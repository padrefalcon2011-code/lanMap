"""Сборка модели «устройство по MAC» из сырых улик среза.

Устройство — это MAC (IP меняется). У одного MAC может быть несколько IP.
Для каждого устройства собираются «факты» (для правил опознания) и «улики» (для объяснения).
"""
from __future__ import annotations

import html
import ipaddress
import re
from pathlib import Path

from lanmap import oui
from lanmap.collectors import dnswire
from lanmap.ports import service_name
from lanmap.util import is_private_mac, read_json

_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_HEADER = re.compile(r"^([A-Za-z0-9-]+):\s*(.*)$", re.M)


def _clean(text: str | None, limit: int = 200) -> str:
    if not text:
        return ""
    text = html.unescape(re.sub(r"\s+", " ", text)).strip()
    return text[:limit]


def parse_http(response: str) -> dict:
    head, _, body = response.partition("\r\n\r\n")
    status_line = head.split("\r\n", 1)[0]
    headers = {k.lower(): v.strip() for k, v in _HEADER.findall(head)}
    title = _TITLE.search(body)
    realm = re.search(r'realm="?([^",]+)', headers.get("www-authenticate", ""), re.I)
    return {
        "status": status_line[:80],
        "server": headers.get("server", ""),
        "title": _clean(title[1]) if title else "",
        "realm": realm[1] if realm else "",
        "location": headers.get("location", ""),
        "body": body[:4000],
    }


def _rtsp_server(response: str) -> str:
    match = re.search(r"^Server:\s*(.+)$", response, re.I | re.M)
    return match[1].strip() if match else ""


def _ssdp_headers(text: str) -> dict:
    return {k.lower(): v.strip() for k, v in _HEADER.findall(text)}


def _wsd_types(xml: str) -> list[str]:
    found = re.findall(r"<[^>]*:?Types>([^<]+)<", xml)
    return sorted({t for block in found for t in block.split()})


class _Dev:
    def __init__(self, key: str, mac: str | None):
        self.key = key
        self.mac = mac
        self.ips: list[str] = []
        self.facts: dict = {
            "ports": set(), "mdns_services": set(), "mdns_txt": {}, "mdns_hosts": set(), "mdns_instances": set(),
            "upnp": {}, "onvif": {}, "http": [], "tls": [], "ssh": [], "rtsp": [], "banners": [],
            "ssdp_server": set(), "ssdp_st": set(), "wsd_types": set(), "netbios": None, "dns": set(),
            "router_names": set(), "smb": None, "ttl": None, "alive": False, "arp": False, "duplicate_mac": False,
        }
        self.evidence: list[dict] = []
        self.services: dict[int, dict] = {}

    def add(self, source: str, text: str, ip: str | None = None, **extra) -> None:
        item = {"source": source, "text": text}
        if ip:
            item["ip"] = ip
        item.update(extra)
        if item not in self.evidence:
            self.evidence.append(item)


def build(snapshot: Path, aliases: dict[str, str] | None = None) -> list[dict]:
    """Сырые улики среза → список устройств. aliases: склейка MAC (вторичный → основной)."""
    aliases = aliases or {}
    raw = snapshot / "raw"
    meta = read_json(snapshot / "meta.json", {})
    iface = meta.get("interface", {})
    local_ip, gateway, local_mac = iface.get("local_ip"), iface.get("gateway"), iface.get("mac")

    pings = read_json(raw / "ping.json", {})
    neighbors = read_json(raw / "neighbors.json", [])
    arp = read_json(raw / "arp.json", [])
    multi = read_json(raw / "multicast.json", {})
    wsd = read_json(raw / "wsd.json", [])
    ports = read_json(raw / "ports.json", {}).get("open", {})
    probes = read_json(raw / "probes.json", [])
    names = read_json(raw / "names.json", {})
    upnp = read_json(raw / "upnp.json", [])
    onvif = read_json(raw / "onvif.json", [])
    smb = read_json(raw / "smb.json", [])

    # 1. IP → MAC: ARP-ответ надёжнее кэша соседей
    ip_mac: dict[str, str] = {}
    for n in neighbors:
        ip_mac[n["ip"]] = n["mac"]
    for a in arp:
        if a.get("mac"):
            ip_mac[a["ip"]] = a["mac"]
    if local_ip and local_mac:
        ip_mac[local_ip] = local_mac

    all_ips = set(ip_mac) | {ip for ip, p in pings.items() if p.get("alive")} | set(ports)
    all_ips |= {e["ip"] for e in multi.get("mdns", []) + multi.get("ssdp", [])} | {e["ip"] for e in wsd}

    # Один MAC на нескольких IP — одно устройство, пока не доказано обратное.
    # Доказательство обратного: разные серийные номера в самоописании (ONVIF, UPnP).
    serial_by_ip: dict[str, str] = {}
    for o in onvif:
        sn = (o.get("fields") or {}).get("SerialNumber")
        if sn and o.get("ip"):
            serial_by_ip[o["ip"]] = sn
    for d in upnp:
        u = d.get("upnp") or {}
        sn = (u.get("serialNumber") or u.get("UDN") or [None])[0]
        if sn and d.get("ip"):
            serial_by_ip.setdefault(d["ip"], sn)
    serials_by_mac: dict[str, set[str]] = {}
    for ip, sn in serial_by_ip.items():
        if ip_mac.get(ip):
            serials_by_mac.setdefault(aliases.get(ip_mac[ip], ip_mac[ip]), set()).add(sn)
    cloned = {mac for mac, sns in serials_by_mac.items() if len(sns) > 1}

    devs: dict[str, _Dev] = {}
    by_ip: dict[str, _Dev] = {}
    for ip in sorted(all_ips, key=ipaddress.ip_address):
        mac = ip_mac.get(ip)
        mac = aliases.get(mac, mac)
        key = mac or f"ip:{ip}"
        if mac in cloned and ip in serial_by_ip:
            key = f"{mac}#{serial_by_ip[ip]}"
        dev = devs.get(key) or devs.setdefault(key, _Dev(key, mac))
        dev.ips.append(ip)
        by_ip[ip] = dev
    for dev in devs.values():
        if dev.mac in cloned:
            dev.facts["duplicate_mac"] = True
            others = sorted(ip for ip, d in by_ip.items() if d.mac == dev.mac and d is not dev)
            dev.add("mac", f"Этот же MAC виден у другого адреса ({', '.join(others)}), но серийные номера разные: "
                    "это два устройства, одно из которых, вероятно, подключено через другое (мост/ретранслятор)")

    # 2. Живость
    neigh_state = {n["ip"]: n.get("state") for n in neighbors}
    for ip, dev in by_ip.items():
        p = pings.get(ip, {})
        if p.get("alive"):
            dev.facts["alive"] = True
            dev.facts["ttl"] = dev.facts["ttl"] or p.get("ttl")
        if any(a["ip"] == ip and a.get("mac") for a in arp):
            dev.facts["arp"] = True
        if ip in ports and ports[ip]:
            dev.facts["alive"] = True
    for dev in devs.values():
        if dev.facts["arp"]:
            dev.facts["alive"] = True

    # 3. Порты и баннеры
    for ip, plist in ports.items():
        dev = by_ip.get(ip)
        if not dev:
            continue
        for port in plist:
            dev.facts["ports"].add(port)
            dev.services.setdefault(port, {"port": port, "name": service_name(port), "ips": []})
            if ip not in dev.services[port]["ips"]:
                dev.services[port]["ips"].append(ip)
    for pr in probes:
        dev = by_ip.get(pr["ip"])
        if not dev or "response" not in pr and "cert" not in pr:
            continue
        port, resp = pr["port"], pr.get("response", "")
        svc = dev.services.setdefault(port, {"port": port, "name": service_name(port), "ips": [pr["ip"]]})
        if pr.get("tls_version"):
            svc["tls"] = pr["tls_version"]
        cert = pr.get("cert") or {}
        if cert.get("subject"):
            subj = cert["subject"]
            dev.facts["tls"].append({"port": port, **cert})
            label = subj.get("commonName") or subj.get("organizationName")
            if label:
                dev.add("tls", f"Сертификат TLS на порту {port}: {label}"
                        + (f", организация {subj['organizationName']}" if subj.get("organizationName") else ""), pr["ip"])
        if pr.get("kind") == "http" and resp.startswith("HTTP/"):
            h = parse_http(resp)
            h["port"] = port
            h["tls"] = bool(pr.get("tls_version"))
            dev.facts["http"].append(h)
            svc["http"] = {k: h[k] for k in ("status", "server", "title", "realm")}
            parts = [f"Server: {h['server']}" if h["server"] else "", f"заголовок «{h['title']}»" if h["title"] else "",
                     f"realm «{h['realm']}»" if h["realm"] else ""]
            parts = [p for p in parts if p]
            if parts:
                dev.add("http", f"HTTP {port}: " + ", ".join(parts), pr["ip"])
        elif pr.get("kind") == "rtsp" and resp:
            server = _rtsp_server(resp)
            dev.facts["rtsp"].append(server or resp[:80])
            svc["banner"] = server or resp.split("\r\n", 1)[0]
            dev.add("rtsp", f"RTSP {port} отвечает" + (f": Server {server}" if server else ""), pr["ip"])
        elif resp.strip():
            banner = _clean(resp, 120)
            svc["banner"] = banner
            if resp.startswith("SSH-"):
                dev.facts["ssh"].append(banner)
                dev.add("ssh", f"SSH-баннер: {banner}", pr["ip"])
            else:
                dev.facts["banners"].append({"port": port, "text": banner})
                dev.add("banner", f"Порт {port} представился: {banner}", pr["ip"])

    # 4. mDNS / DNS-SD
    records = [dict(r, _ip=pkt["ip"]) for pkt in multi.get("mdns", []) for r in pkt["records"]]
    host_ip = {r["name"].lower(): r["value"] for r in records if r["type"] == dnswire.TYPE_A}
    inst_ip: dict[str, str] = {}
    for r in records:
        if r["type"] == dnswire.TYPE_SRV:
            target_ip = host_ip.get(r["value"]["target"].lower()) or r["_ip"]
            inst_ip[r["name"].lower()] = target_ip
    for r in records:
        if r["type"] == dnswire.TYPE_A:
            dev = by_ip.get(r["value"])
            if dev:
                dev.facts["mdns_hosts"].add(r["name"])
        elif r["type"] == dnswire.TYPE_SRV:
            dev = by_ip.get(inst_ip.get(r["name"].lower(), r["_ip"]))
            if dev:
                inst, _, svc_type = r["name"].partition("._")
                svc_type = "_" + svc_type.removesuffix(".local")
                dev.facts["mdns_services"].add(svc_type)
                dev.facts["mdns_instances"].add(inst)
                dev.add("mdns", f"mDNS: служба {svc_type} «{inst}» на порту {r['value']['port']}", r["_ip"])
        elif r["type"] == dnswire.TYPE_TXT:
            dev = by_ip.get(inst_ip.get(r["name"].lower(), r["_ip"]))
            if dev:
                for item in r["value"]:
                    k, sep, v = item.partition("=")
                    if sep and k and v:
                        dev.facts["mdns_txt"].setdefault(k.lower(), v)
        elif r["type"] == dnswire.TYPE_PTR and not r["name"].startswith("_services."):
            # PTR «служба → экземпляр»: тип службы известен, даже если SRV не пришёл
            dev = by_ip.get(inst_ip.get(r["value"].lower(), r["_ip"]))
            if dev and r["name"].startswith("_"):
                dev.facts["mdns_services"].add(r["name"].removesuffix(".local"))
    for dev in devs.values():
        if dev.facts["mdns_hosts"]:
            dev.add("mdns", "mDNS-имя: " + ", ".join(sorted(dev.facts["mdns_hosts"])))
        interesting = {k: v for k, v in dev.facts["mdns_txt"].items()
                       if k in ("md", "model", "ty", "usb_mfg", "usb_mdl", "manufacturer", "fn", "platform",
                                "deviceid", "am", "product", "vendor", "fv", "firmware", "osxvers", "rpmd")}
        if interesting:
            dev.add("mdns", "mDNS TXT: " + ", ".join(f"{k}={v}" for k, v in sorted(interesting.items())))

    # 5. SSDP и UPnP-описания
    for e in multi.get("ssdp", []):
        dev = by_ip.get(e["ip"])
        if dev:
            h = _ssdp_headers(e["response"])
            if h.get("server"):
                dev.facts["ssdp_server"].add(h["server"])
            if h.get("st"):
                dev.facts["ssdp_st"].add(h["st"])
    for dev in devs.values():
        if dev.facts["ssdp_server"]:
            dev.add("ssdp", "SSDP Server: " + "; ".join(sorted(dev.facts["ssdp_server"])))
    for d in upnp:
        dev = by_ip.get(d.get("ip"))
        if not dev or not d.get("upnp"):
            continue
        for field, values in d["upnp"].items():
            bucket = dev.facts["upnp"].setdefault(field, [])
            bucket.extend(v for v in values if v not in bucket)
        u = d["upnp"]
        shown = [f"{k}={u[k][0]}" for k in ("manufacturer", "modelName", "modelNumber", "friendlyName") if u.get(k)]
        if shown:
            dev.add("upnp", "UPnP-описание: " + ", ".join(shown), d["ip"], url=d["url"])

    # 6. WS-Discovery, ONVIF
    for e in wsd:
        dev = by_ip.get(e["ip"])
        if dev:
            types = _wsd_types(e["xml"])
            dev.facts["wsd_types"].update(types)
            if types:
                dev.add("wsd", "WS-Discovery: " + ", ".join(types), e["ip"])
    for o in onvif:
        dev = by_ip.get(o.get("ip"))
        if not dev:
            continue
        if o.get("fields"):
            dev.facts["onvif"] = {**o["fields"], "anonymous": True}
            f = o["fields"]
            dev.add("onvif", "ONVIF без пароля: " + ", ".join(f"{k}={v}" for k, v in f.items() if v), o["ip"])
        elif o.get("auth_required"):
            dev.facts["onvif"] = {"auth_required": True}
            dev.add("onvif", "ONVIF отвечает, но просит пароль", o["ip"])

    # 7. Имена
    for ip, name in (names.get("reverse_dns") or {}).items():
        dev = by_ip.get(ip)
        if dev and name and name != ip:
            dev.facts["dns"].add(name)
    for ip, values in (names.get("gateway_ptr") or {}).items():
        dev = by_ip.get(ip)
        if dev and values:
            dev.facts["router_names"].update(values)
    for nb in names.get("netbios") or []:
        dev = by_ip.get(nb.get("ip"))
        if dev and nb.get("computer"):
            dev.facts["netbios"] = {"computer": nb["computer"], "workgroup": nb.get("workgroup")}
            dev.add("netbios", f"NetBIOS: компьютер {nb['computer']}"
                    + (f", рабочая группа {nb['workgroup']}" if nb.get("workgroup") else ""), nb["ip"])
    for dev in devs.values():
        if dev.facts["router_names"]:
            dev.add("router_dns", "Имя в DNS роутера: " + ", ".join(sorted(dev.facts["router_names"])))
        if dev.facts["dns"] - dev.facts["router_names"]:
            dev.add("dns", "Обратный DNS: " + ", ".join(sorted(dev.facts["dns"] - dev.facts["router_names"])))

    # 8. SMB
    for s in smb:
        dev = by_ip.get(s.get("ip"))
        if dev and s.get("dialect"):
            dev.facts["smb"] = s
            dev.add("smb", f"SMB: диалект {s['dialect']}, подпись "
                    + ("обязательна" if s.get("signing_required") else "не обязательна"), s["ip"])

    # 9. Этот компьютер: имя из системы
    host = meta.get("hostname")
    if local_ip in by_ip and host:
        me = by_ip[local_ip]
        me.facts["netbios"] = me.facts["netbios"] or {"computer": host, "workgroup": None}
        me.add("local", f"Это компьютер, на котором запущен LanMap: {host}", local_ip)

    # 10. OUI, частный MAC, TTL
    result = []
    for dev in devs.values():
        private = is_private_mac(dev.mac)
        vendor = None if private else oui.lookup(dev.mac)
        dev.facts["oui"] = vendor
        dev.facts["private_mac"] = private
        if private:
            dev.add("mac", "Частный (случайный) MAC: производителя по нему не узнать — так делают телефоны, "
                    "планшеты и ноутбуки")
        elif vendor:
            dev.add("oui", f"Производитель сетевого чипа по MAC (IEEE): {vendor}")
        ttl = dev.facts["ttl"]
        if ttl:
            family = "Windows" if 65 <= ttl <= 128 else "Linux/Android/iOS/встроенная система" if ttl <= 64 else "сетевое железо"
            dev.add("ttl", f"TTL={ttl}: похоже на {family}")
        result.append({
            "key": dev.key,
            "mac": dev.mac,
            "private_mac": private,
            "ips": sorted(dev.ips, key=ipaddress.ip_address),
            "is_local": local_ip in dev.ips,
            "is_gateway": gateway in dev.ips if gateway else False,
            "duplicate_mac": bool(dev.facts.get("duplicate_mac")),
            "alive": dev.facts["alive"],
            "in_cache_only": not dev.facts["alive"] and any(neigh_state.get(ip) for ip in dev.ips),
            "services": [dev.services[p] for p in sorted(dev.services)],
            "facts": _jsonable(dev.facts),
            "evidence": dev.evidence,
        })
    return result


def _jsonable(facts: dict) -> dict:
    return {k: sorted(v) if isinstance(v, set) else v for k, v in facts.items()}
