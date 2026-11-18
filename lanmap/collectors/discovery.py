"""Поиск устройств: ping-проход, таблица соседей, ARP, mDNS, SSDP, WS-Discovery."""
from __future__ import annotations

import concurrent.futures
import ctypes
import json
import re
import socket
import struct
import subprocess
import time
import uuid

from lanmap.collectors import ScanContext
from lanmap.collectors import dnswire
from lanmap.netinfo import run_powershell
from lanmap.util import norm_mac

_TTL = re.compile(rb"TTL=(\d+)", re.I)

MDNS_SERVICES = [
    "_services._dns-sd._udp.local", "_http._tcp.local", "_https._tcp.local", "_smb._tcp.local",
    "_afpovertcp._tcp.local", "_workstation._tcp.local", "_device-info._tcp.local", "_ssh._tcp.local",
    "_googlecast._tcp.local", "_androidtvremote2._tcp.local", "_airplay._tcp.local", "_raop._tcp.local",
    "_companion-link._tcp.local", "_apple-mobdev2._tcp.local", "_ipp._tcp.local", "_ipps._tcp.local",
    "_printer._tcp.local", "_pdl-datastream._tcp.local", "_uscan._tcp.local", "_scanner._tcp.local",
    "_hap._tcp.local", "_hap._udp.local", "_home-assistant._tcp.local", "_yandexio._tcp.local",
    "_spotify-connect._tcp.local", "_miio._udp.local", "_rtsp._tcp.local", "_matter._tcp.local",
    "_amzn-wplay._tcp.local", "_sleep-proxy._udp.local", "_adisk._tcp.local", "_nfs._tcp.local",
]


# ---------- ping ----------

def _ping(ip: str) -> tuple[str, dict]:
    try:
        proc = subprocess.run(["ping", "-n", "1", "-w", "700", ip], capture_output=True, timeout=5)
    except subprocess.TimeoutExpired:
        return ip, {"alive": False}
    match = _TTL.search(proc.stdout)
    return ip, {"alive": proc.returncode == 0 and bool(match), "ttl": int(match[1]) if match else None}


def ping_sweep(ctx: ScanContext, workers: int = 64) -> dict[str, dict]:
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return dict(pool.map(_ping, ctx.hosts()))


# ---------- таблица соседей и ARP ----------

def neighbor_table(ctx: ScanContext) -> list[dict]:
    script = (
        f"Get-NetNeighbor -InterfaceIndex {int(ctx.if_index)} -AddressFamily IPv4 "
        "| Select-Object IPAddress,LinkLayerAddress,@{n='State';e={[string]$_.State}} "
        "| ConvertTo-Json -Compress"
    )
    raw = run_powershell(script)
    try:
        data = json.loads(raw) if raw else []
    except json.JSONDecodeError:
        return []
    data = data if isinstance(data, list) else [data]
    out = []
    for entry in data:
        ip = entry.get("IPAddress")
        mac = norm_mac(entry.get("LinkLayerAddress"))
        if ctx.in_scope(ip) and mac:
            out.append({"ip": ip, "mac": mac, "state": entry.get("State")})
    return out


def _send_arp(args: tuple[str, str]) -> dict:
    ip, source = args
    buf = ctypes.create_string_buffer(8)
    length = ctypes.c_ulong(8)
    dest = struct.unpack("<I", socket.inet_aton(ip))[0]
    src = struct.unpack("<I", socket.inet_aton(source))[0]
    try:
        status = ctypes.windll.iphlpapi.SendARP(dest, src, buf, ctypes.byref(length))
    except Exception as exc:  # не Windows
        return {"ip": ip, "status": None, "error": str(exc), "mac": None}
    mac = norm_mac(buf.raw[:length.value].hex()) if status == 0 else None
    return {"ip": ip, "status": status, "mac": mac}


def arp_query(ctx: ScanContext, ips: list[str], workers: int = 32) -> list[dict]:
    targets = [(ip, ctx.local_ip) for ip in ips if ip != ctx.local_ip and ctx.in_scope(ip)]
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        return list(pool.map(_send_arp, targets))


# ---------- mDNS и SSDP ----------

def multicast(ctx: ScanContext, duration: float = 9.0) -> dict:
    """Один общий проход mDNS (DNS-SD) и SSDP. Ответы только из своей подсети."""
    result: dict = {"ssdp": [], "mdns": [], "errors": []}
    local = ctx.local_ip

    ssdp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ssdp.bind((local, 0))
    ssdp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
    ssdp.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    ssdp.setblocking(False)
    search = (b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\n"
              b"MX: 2\r\nST: ssdp:all\r\n\r\n")

    mdns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    mdns.bind((local, 0))  # эфемерный порт + бит QU: ответы приходят нам напрямую
    mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local))
    mdns.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    mdns.setblocking(False)

    asked: set[str] = set()

    def ask(name: str) -> None:
        if name in asked or len(asked) > 200:
            return
        asked.add(name)
        try:
            mdns.sendto(dnswire.build_query(name, dnswire.TYPE_PTR, unicast_response=True),
                        ("224.0.0.251", 5353))
        except OSError as exc:
            result["errors"].append(f"mdns send {name}: {exc}")

    for _ in range(2):
        try:
            ssdp.sendto(search, ("239.255.255.250", 1900))
        except OSError as exc:
            result["errors"].append(f"ssdp send: {exc}")
    for name in MDNS_SERVICES:
        ask(name)

    seen: set = set()
    resent = False
    end = time.monotonic() + duration
    while time.monotonic() < end:
        if not resent and time.monotonic() > end - duration / 2:
            resent = True
            try:
                ssdp.sendto(search, ("239.255.255.250", 1900))
            except OSError:
                pass
        got = False
        for sock, kind in ((ssdp, "ssdp"), (mdns, "mdns")):
            try:
                data, addr = sock.recvfrom(65535)
            except (BlockingIOError, ConnectionResetError):
                continue
            got = True
            if not ctx.in_scope(addr[0]) or (addr[0], data) in seen:
                continue
            seen.add((addr[0], data))
            if kind == "ssdp":
                result["ssdp"].append({"ip": addr[0], "response": data.decode("utf-8", "replace")})
                continue
            try:
                records = dnswire.parse_records(data)
            except Exception as exc:
                result["errors"].append(f"mdns parse from {addr[0]}: {exc}")
                continue
            result["mdns"].append({"ip": addr[0], "records": records})
            for rec in records:
                if rec["type"] == dnswire.TYPE_PTR and rec["name"] == "_services._dns-sd._udp.local":
                    ask(rec["value"])
        if not got:
            time.sleep(0.02)
    ssdp.close()
    mdns.close()
    result["queried"] = sorted(asked)
    return result


# ---------- WS-Discovery ----------

def ws_discovery(ctx: ScanContext, duration: float = 5.0) -> list[dict]:
    ident = uuid.uuid4()
    probe = (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">'
        f'<e:Header><w:MessageID>uuid:{ident}</w:MessageID>'
        '<w:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action></e:Header>'
        '<e:Body><d:Probe/></e:Body></e:Envelope>'
    ).encode()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((ctx.local_ip, 0))
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ctx.local_ip))
    sock.settimeout(0.5)
    out, seen = [], set()
    try:
        for _ in range(2):
            sock.sendto(probe, ("239.255.255.250", 3702))
        end = time.monotonic() + duration
        while time.monotonic() < end:
            try:
                data, addr = sock.recvfrom(65535)
            except (socket.timeout, ConnectionResetError):
                continue
            if ctx.in_scope(addr[0]) and (addr[0], data) not in seen:
                seen.add((addr[0], data))
                out.append({"ip": addr[0], "xml": data.decode("utf-8", "replace")})
    finally:
        sock.close()
    return out
