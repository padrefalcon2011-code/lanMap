"""Самоописание устройств: UPnP XML, ONVIF, SMB-согласование, имена (DNS, NetBIOS). Только чтение."""
from __future__ import annotations

import concurrent.futures
import re
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree as ET

from lanmap.collectors import USER_AGENT, ScanContext
from lanmap.collectors import dnswire

UPNP_FIELDS = ("friendlyName", "manufacturer", "manufacturerURL", "modelName", "modelNumber",
               "modelDescription", "serialNumber", "deviceType", "presentationURL", "UDN")


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


class _LocalOnlyRedirect(urllib.request.HTTPRedirectHandler):
    """Переходы по редиректам только внутри своей подсети."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not self.ctx.in_scope(urllib.parse.urlparse(newurl).hostname):
            return None
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _opener(ctx: ScanContext):
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _LocalOnlyRedirect(ctx))


def http_get(ctx: ScanContext, url: str, limit: int = 200_000) -> dict:
    """GET только по адресам своей подсети. Для XML — разбор полей UPnP."""
    if not ctx.in_scope(urllib.parse.urlparse(url).hostname):
        return {"url": url, "error": "адрес вне локальной подсети — пропущен"}
    try:
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with _opener(ctx).open(req, timeout=4) as resp:
            raw = resp.read(limit)
            out = {"url": url, "status": resp.status, "headers": dict(resp.headers.items()),
                   "body": raw.decode("utf-8", "replace")}
    except urllib.error.HTTPError as exc:
        return {"url": url, "status": exc.code, "error": str(exc)}
    except Exception as exc:
        return {"url": url, "error": f"{type(exc).__name__}: {exc}"}
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        return out
    fields: dict[str, list[str]] = {}
    for el in root.iter():
        tag = _local(el.tag)
        if tag in UPNP_FIELDS and el.text and el.text.strip():
            fields.setdefault(tag, [])
            if el.text.strip() not in fields[tag]:
                fields[tag].append(el.text.strip())
    out["upnp"] = fields
    return out


def ssdp_locations(ssdp: list[dict]) -> dict[str, str]:
    """URL описаний UPnP из ответов SSDP (только своя подсеть) → IP, приславший ответ."""
    urls: dict[str, str] = {}
    for entry in ssdp:
        match = re.search(r"^location:\s*(\S+)", entry.get("response", ""), re.I | re.M)
        if match:
            urls.setdefault(match[1], entry["ip"])
    return urls


def upnp_descriptions(ctx: ScanContext, ssdp: list[dict]) -> list[dict]:
    urls = {u: ip for u, ip in ssdp_locations(ssdp).items() if ctx.in_scope(urllib.parse.urlparse(u).hostname)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        results = list(pool.map(lambda u: http_get(ctx, u), sorted(urls)))
    for item in results:
        item["ip"] = urls[item["url"]]
    return results


# ---------- ONVIF ----------

_ONVIF_BODY = (b'<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
               b'<s:Body><GetDeviceInformation xmlns="http://www.onvif.org/ver10/device/wsdl"/></s:Body></s:Envelope>')


def onvif_info(ctx: ScanContext, url: str) -> dict:
    """GetDeviceInformation без учётных данных. Многие камеры отвечают анонимно."""
    host = urllib.parse.urlparse(url).hostname
    out: dict = {"ip": host, "url": url, "operation": "GetDeviceInformation (без пароля)"}
    if not ctx.in_scope(host):
        out["error"] = "адрес вне локальной подсети — пропущен"
        return out
    req = urllib.request.Request(url, data=_ONVIF_BODY, headers={
        "Content-Type": 'application/soap+xml; charset=utf-8; action="http://www.onvif.org/ver10/device/wsdl/GetDeviceInformation"',
        "User-Agent": USER_AGENT})
    try:
        with _opener(ctx).open(req, timeout=4) as resp:
            raw = resp.read(65536)
        root = ET.fromstring(raw)
        out["fields"] = {_local(el.tag): (el.text or "").strip() for el in root.iter()
                         if _local(el.tag) in ("Manufacturer", "Model", "FirmwareVersion", "SerialNumber", "HardwareId")}
        out["anonymous"] = True
    except urllib.error.HTTPError as exc:
        out["error"] = f"HTTP {exc.code}"
        out["auth_required"] = exc.code in (400, 401, 403)
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def wsd_xaddrs(wsd: list[dict]) -> list[str]:
    urls = []
    for entry in wsd:
        for block in re.findall(r"<[^>]*XAddrs>([^<]+)<", entry.get("xml", "")):
            urls.extend(block.split())
    return urls


def onvif_targets(ctx: ScanContext, wsd: list[dict], open_ports: dict[str, list[int]]) -> list[str]:
    targets: dict[str, str] = {}
    for url in wsd_xaddrs(wsd):
        host = urllib.parse.urlparse(url).hostname
        if ctx.in_scope(host) and "onvif" in url.lower():
            targets.setdefault(host, url)
    for ip, ports in open_ports.items():
        if ip in targets:
            continue
        if 8899 in ports:
            targets[ip] = f"http://{ip}:8899/onvif/device_service"
        elif 554 in ports and 80 in ports:
            targets[ip] = f"http://{ip}/onvif/device_service"
    return sorted(targets.values())


# ---------- SMB ----------

def smb_negotiate(ctx: ScanContext, ip: str) -> dict:
    """Согласование SMB2/3: диалект и требование подписи. Без входа."""
    out: dict = {"ip": ip}
    try:
        header = struct.pack("<4sHHIHHIIQIIQ16s", b"\xfeSMB", 64, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, b"\0" * 16)
        dialects = (0x202, 0x210, 0x300, 0x302, 0x311)
        body = struct.pack("<HHHHI16sIHH", 36, len(dialects), 1, 0, 0, uuid.uuid4().bytes, 0, 0, 0)
        body += struct.pack(f"<{len(dialects)}H", *dialects)
        payload = header + body
        with socket.create_connection((ip, 445), timeout=3, source_address=(ctx.local_ip, 0)) as sock:
            sock.sendall(struct.pack("!I", len(payload)) + payload)
            data = sock.recv(8192)
        if len(data) >= 74 and data[4:8] == b"\xfeSMB":
            status = struct.unpack_from("<I", data, 12)[0]
            out["status"] = hex(status)
            if status == 0:
                mode, dialect = struct.unpack_from("<HH", data, 70)
                out.update(dialect=hex(dialect), signing_enabled=bool(mode & 1), signing_required=bool(mode & 2))
        else:
            out["response_hex"] = data[:64].hex()
    except Exception as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out


def smb1_request() -> bytes:
    """Согласование SMB1, в котором предложен только диалект NT LM 0.12 (без SMB2). Без входа."""
    header = (b"\xffSMB" + bytes([0x72]) + b"\0" * 4 + bytes([0x18]) + struct.pack("<H", 0xC801)
              + b"\0" * 12 + struct.pack("<HHHH", 0, 0xFEFF, 0, 0))
    dialects = b"\x02NT LM 0.12\x00"
    payload = header + bytes([0]) + struct.pack("<H", len(dialects)) + dialects
    return struct.pack("!I", len(payload)) + payload


def parse_smb1_reply(data: bytes) -> tuple[bool | None, str]:
    """Ответ на smb1_request → (SMB1 принят?, пояснение). Пустой ответ — сервер оборвал соединение: SMB1 нет.
    Непонятный или обрезанный ответ — None: ни «есть», ни «нет»."""
    if not data:
        return False, "оборвал соединение в ответ на SMB1"
    if data[4:8] == b"\xfeSMB":
        return False, "ответил по SMB2"
    if data[4:8] != b"\xffSMB" or len(data) < 39:
        return None, "непонятный ответ"
    status = struct.unpack_from("<I", data, 9)[0]
    words = data[36]
    index = struct.unpack_from("<H", data, 37)[0]
    if status == 0 and words >= 1 and index == 0:
        return True, "согласился на SMB1 (NT LM 0.12)"
    return False, "отказался от SMB1"


def smb1_negotiate(ctx: ScanContext, ip: str) -> dict:
    """Говорит ли устройство по SMB1. smb1: True / False / None (не ответило — неизвестно)."""
    out: dict = {"smb1": None}
    try:
        with socket.create_connection((ip, 445), timeout=3, source_address=(ctx.local_ip, 0)) as sock:
            sock.settimeout(3)
            sock.sendall(smb1_request())
            try:
                data = sock.recv(4096)
            except ConnectionResetError:
                data = b""
        out["smb1"], out["smb1_detail"] = parse_smb1_reply(data)
    except ConnectionRefusedError:
        out["smb1"], out["smb1_detail"], out["port_closed"] = False, "порт 445 закрыт", True
    except Exception as exc:
        out["smb1_detail"] = f"{type(exc).__name__}: {exc}"
    return out


def smb_probe(ctx: ScanContext, ip: str) -> dict:
    """SMB2/3 (диалект, подпись) и SMB1 одним заходом."""
    return {**smb_negotiate(ctx, ip), **smb1_negotiate(ctx, ip)}


# ---------- имена ----------

def reverse_dns(ip: str) -> tuple[str, str | None]:
    try:
        return ip, socket.gethostbyaddr(ip)[0]
    except OSError:
        return ip, None


def gateway_ptr(ctx: ScanContext, ip: str) -> tuple[str, list[str]]:
    """PTR-запрос напрямую к DNS роутера: роутеры часто отдают DHCP-имена клиентов."""
    if not ctx.gateway:
        return ip, []
    packet = dnswire.build_query(dnswire.ptr_name(ip), dnswire.TYPE_PTR, qid=0x4C4D, rd=True)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ctx.local_ip, 0))
    sock.settimeout(1.5)
    try:
        sock.sendto(packet, (ctx.gateway, 53))
        data, _ = sock.recvfrom(8192)
        return ip, [r["value"] for r in dnswire.parse_records(data) if r["type"] == dnswire.TYPE_PTR]
    except (OSError, ValueError, struct.error):
        return ip, []
    finally:
        sock.close()


_NBSTAT = (struct.pack("!6H", 0x4C4D, 0, 1, 0, 0, 0) + b"\x20" + b"CK" + b"A" * 30 + b"\x00"
           + struct.pack("!HH", 0x21, 1))


def netbios_status(ctx: ScanContext, ip: str) -> dict | None:
    """Запрос состояния NetBIOS (UDP 137): имя компьютера и рабочая группа."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ctx.local_ip, 0))
    sock.settimeout(1.0)
    try:
        sock.sendto(_NBSTAT, (ip, 137))
        data, _ = sock.recvfrom(4096)
    except OSError:
        return None
    finally:
        sock.close()
    try:
        offset = 12 + 34 + 10  # заголовок, имя, тип/класс/TTL/длина
        count = data[offset]
        offset += 1
        names = []
        for _ in range(count):
            raw = data[offset:offset + 18]
            name = raw[:15].decode("ascii", "replace").rstrip()
            suffix = raw[15]
            flags = struct.unpack("!H", raw[16:18])[0]
            names.append({"name": name, "suffix": suffix, "group": bool(flags & 0x8000)})
            offset += 18
        mac = data[offset:offset + 6].hex()
    except (IndexError, struct.error):
        return {"ip": ip, "error": "не удалось разобрать ответ"}
    computer = next((n["name"] for n in names if n["suffix"] == 0 and not n["group"]), None)
    group = next((n["name"] for n in names if n["suffix"] == 0 and n["group"]), None)
    return {"ip": ip, "computer": computer, "workgroup": group, "names": names, "mac": mac}
