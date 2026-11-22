"""Сборка модели «устройство по MAC» из сырых улик среза.

Устройство — это MAC (IP меняется). У одного MAC может быть несколько IP.
Для каждого устройства собираются «факты» (для правил опознания) и «улики» (для объяснения).
"""
from __future__ import annotations

import datetime as _dt
import html
import ipaddress
import re
import ssl
from pathlib import Path

from lanmap import oui
from lanmap.collectors import dnswire
from lanmap.ports import service_name
from lanmap.util import is_private_mac, norm_mac, read_json

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
            "upnp": {}, "onvif": {}, "onvif_urls": {}, "onvif_leak": None, "http": [], "tls": [], "ssh": [], "rtsp": [], "banners": [],
            "ssdp_server": set(), "ssdp_st": set(), "wsd_types": set(), "netbios": None, "dns": set(),
            "router_names": set(), "smb": None, "smb1": None, "ttl": None, "alive": False, "arp": False, "duplicate_mac": False,
            "router": None, "router_only": False,
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


CERT_SOON = 30  # дней: меньше — сертификат «скоро истекает»


def cert_days(not_after: str | None, at: str | None) -> int | None:
    """Сколько полных дней сертификат ещё действует на момент среза (отрицательное — уже истёк).

    Считаем от даты среза, а не от «сейчас»: отчёт говорит о том, что видел срез, и не меняется при пересборке."""
    if not not_after:
        return None
    try:
        until = ssl.cert_time_to_seconds(not_after)
        when = _dt.datetime.fromisoformat(at).timestamp() if at else _dt.datetime.now().timestamp()
    except (ValueError, TypeError):
        return None
    return int((until - when) // 86400)


SOURCE_NAMES = {"arp": "ARP", "neighbors": "кэш соседей Windows", "router": "роутер"}


def contested_ips(arp: list, neighbors: list, clients: list, aliases: dict | None = None) -> dict[str, list[dict]]:
    """Спорные адреса: один IPv4 — разные MAC → {ip: [{"source", "mac"}]}.

    Источники: свежий ARP-ответ; кэш соседей Windows — только если ARP по адресу не ответил (кэш снят до ARP и
    бывает устаревшим); активные клиенты роутера. Причины разные — два устройства с одним адресом (заводской
    адрес камер), устройство за ретранслятором, устаревшая аренда, — поэтому это подозрение с наблюдениями,
    а не приговор."""
    aliases = aliases or {}

    def mac_of(value):
        m = norm_mac(value)
        return aliases.get(m, m) if m else None

    seen: dict[str, dict[tuple[str, str], None]] = {}
    answered = {a["ip"] for a in arp if a.get("mac") and a.get("ip")}
    for a in arp:
        if a.get("mac") and a.get("ip"):
            seen.setdefault(a["ip"], {})[("arp", mac_of(a["mac"]))] = None
    for n in neighbors:
        if n.get("mac") and n.get("ip") and n["ip"] not in answered and set((mac_of(n["mac"]) or "0").replace(":", "")) != {"0"}:
            seen.setdefault(n["ip"], {})[("neighbors", mac_of(n["mac"]))] = None
    for c in clients:
        if c.get("active") and c.get("ip") and c.get("mac"):
            seen.setdefault(c["ip"], {})[("router", mac_of(c["mac"]))] = None
    out = {}
    for ip, obs in seen.items():
        if len({mac for _, mac in obs}) > 1:
            out[ip] = [{"source": src, "mac": mac} for src, mac in obs]
    return out


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
    onvif_snap = read_json(raw / "onvif_snapshot.json", [])
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
        days = cert_days(cert.get("not_after"), meta.get("started"))
        if days is not None:
            svc["cert"] = {"not_after": cert["not_after"], "days": days}
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
        if o.get("url") and (o.get("fields") or o.get("auth_required")):
            dev.facts["onvif_urls"][o["ip"]] = o["url"]  # для стоп-кадра: служба ONVIF у каждого адреса своя
        if o.get("fields"):
            dev.facts["onvif"] = {**o["fields"], "anonymous": True}
            f = o["fields"]
            dev.add("onvif", "ONVIF без пароля: " + ", ".join(f"{k}={v}" for k, v in f.items() if v), o["ip"])
        elif o.get("auth_required"):
            dev.facts["onvif"] = {"auth_required": True}
            dev.add("onvif", "ONVIF отвечает, но просит пароль", o["ip"])

    # Отдаёт ли камера без пароля адрес кадра со своим паролем: True, если хоть по одному адресу
    for o in onvif_snap or []:
        dev = by_ip.get(o.get("ip"))
        if dev and o.get("leak") is not None and dev.facts["onvif_leak"] is not True:
            dev.facts["onvif_leak"] = bool(o["leak"])
            if o["leak"]:
                dev.add("onvif", "ONVIF без пароля выдаёт адрес кадра с логином и паролем", o["ip"])

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
        if dev and "smb1" in s:  # в старых срезах SMB1 не проверялся — ключа нет
            dev.facts["smb1"] = s["smb1"]
            if s["smb1"]:
                dev.add("smb", "SMB1: " + (s.get("smb1_detail") or "принят"), s["ip"])

    # 9. Этот компьютер: имя из системы
    host = meta.get("hostname")
    if local_ip in by_ip and host:
        me = by_ip[local_ip]
        me.facts["netbios"] = me.facts["netbios"] or {"computer": host, "workgroup": None}
        me.add("local", f"Это компьютер, на котором запущен LanMap: {host}", local_ip)

    # 10. Данные роутера (общий формат модулей): подписи, DHCP-имена, подключение, спящие устройства
    from lanmap import routers
    router = routers.normalize(read_json(raw / "router.json"))
    if router:
        def client_mac(c: dict) -> str | None:
            m = norm_mac(c.get("mac"))
            return aliases.get(m, m) if m else None

        def same_ip(c: dict) -> bool:
            return any(c.get("ip") in d.ips for d in devs.values() if d.mac == client_mac(c))

        # Один MAC у роутера бывает с несколькими адресами: через устройство-мост в сеть выходит другое.
        # Подпись роутера — про владельца MAC, то есть про адрес, выданный этому MAC по DHCP (или закреплённый).
        # У адреса устройства за мостом аренды нет — подпись ему не достаётся.
        reserved = {(norm_mac(r.get("mac")), r.get("ip")) for r in router.get("reservations") or []}
        ips_by_mac: dict[str, set[str]] = {}
        owner_ips: dict[str, set[str]] = {}
        for c in router["clients"]:
            m = client_mac(c)
            if m and c.get("ip"):
                ips_by_mac.setdefault(m, set()).add(c["ip"])
                if c.get("dhcp") or (norm_mac(c.get("mac")), c["ip"]) in reserved:
                    owner_ips.setdefault(m, set()).add(c["ip"])
        bridged = {m: ips - owner_ips[m] for m, ips in ips_by_mac.items() if len(ips) > 1 and owner_ips.get(m)}

        # Сначала — записи, у которых совпали и MAC, и адрес: они точно про это устройство, и запись с чужим
        # адресом их не перезапишет.
        for c in sorted(router["clients"], key=lambda c: not same_ip(c)):
            mac = client_mac(c)
            if not mac:
                continue
            if c.get("ip") in bridged.get(mac, set()):
                c = dict(c, label=None, bridged=True)
            candidates = [d for d in devs.values() if d.mac == mac]
            dev = next((d for d in candidates if c.get("ip") in d.ips), candidates[0] if candidates else None)
            if dev is None:
                dev = devs.setdefault(mac, _Dev(mac, mac))
                dev.facts["router_only"] = True
                if c.get("ip"):
                    dev.ips.append(c["ip"])
            matched_ip = bool(c.get("ip")) and c["ip"] in dev.ips
            if dev.facts.get("router") and dev.facts.get("router_by_ip") and (not matched_ip or c.get("bridged")):
                dev.add("router", f"Роутер видит этот MAC ещё и с адресом {c.get('ip') or '?'}: вероятно, через "
                        "устройство подключено другое (мост)")
                continue
            if dev.facts.get("duplicate_mac") and c.get("label") and not matched_ip:
                # подпись в роутере привязана к MAC, а MAC общий — без совпадения адреса название может быть соседа
                dev.add("router", f"Подпись в роутере «{c['label']}» относится к общему MAC и может принадлежать "
                        "другому устройству — как название не используется")
                c = dict(c, label=None)
            dev.facts["router"] = c
            dev.facts["router_by_ip"] = matched_ip
            if c.get("active"):
                dev.facts["alive"] = True
            if c.get("label"):
                dev.add("router", f"Подпись в роутере: «{c['label']}»")
            if c.get("hostname") and c["hostname"] != c.get("label"):
                dev.add("router", f"Имя, которое устройство сообщило роутеру (DHCP): {c['hostname']}")
            dev.add("router", connection_text(c))

    # 11. Спорные адреса: один IP — разные MAC. Пометка у каждого устройства, чей MAC там замечен
    contested = contested_ips(arp, neighbors, (router or {}).get("clients") or [], aliases)
    for ip, obs in sorted(contested.items()):
        macs = {o["mac"] for o in obs}
        text = "; ".join(f'{SOURCE_NAMES[o["source"]]} — {o["mac"]}' for o in obs)
        for dev in devs.values():
            if dev.mac in macs:
                dev.facts.setdefault("contested", []).append({"ip": ip, "observations": obs})
                dev.add("conflict", f"Спорный адрес {ip}: {text}. Два устройства с одним адресом (например, "
                        "заводской адрес камер), устройство за ретранслятором или устаревшая запись", ip)

    # 12. OUI, частный MAC, TTL
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
            "router": dev.facts.get("router"),
            "router_only": bool(dev.facts.get("router_only")),
            "is_local": local_ip in dev.ips,
            "is_gateway": gateway in dev.ips if gateway else False,
            "duplicate_mac": bool(dev.facts.get("duplicate_mac")),
            "contested": dev.facts.get("contested") or [],
            "alive": dev.facts["alive"],
            "in_cache_only": not dev.facts["alive"] and any(neigh_state.get(ip) for ip in dev.ips),
            "services": [dev.services[p] for p in sorted(dev.services)],
            "facts": _jsonable(dev.facts),
            "evidence": dev.evidence,
        })
    return result


def _ago(seconds) -> str:
    if seconds is None:
        return "?"
    s = int(seconds)
    if s < 120:
        return f"{s} с"
    if s < 7200:
        return f"{s // 60} мин"
    if s < 172800:
        return f"{s // 3600} ч"
    return f"{s // 86400} дн"


def connection_text(c: dict) -> str:
    """«Wi-Fi 5 ГГц «Сеть», сигнал −55 дБм · в сети 3 ч · впервые 12 дн назад» — по данным роутера."""
    parts = []
    if not c.get("active"):
        parts.append("сейчас не в сети" + (f", последний раз {_ago(c['last_seen_s_ago'])} назад"
                                          if c.get("last_seen_s_ago") else ""))
    elif c.get("link") == "wifi":
        wifi = "Wi-Fi" + (f" {c['band']}" if c.get("band") else "") + (f" «{c['ssid']}»" if c.get("ssid") else "")
        if c.get("rssi") is not None:
            wifi += f", сигнал {c['rssi']} дБм"
        if c.get("txrate"):
            wifi += f", {c['txrate']} Мбит/с"
        parts.append(wifi)
    elif c.get("link") == "wired":
        parts.append("кабель" + (f", порт роутера {c['port']}" if c.get("port") is not None else "")
                     + (f", {c['speed']} Мбит/с" if c.get("speed") else ""))
    if c.get("segment"):
        parts.append(f"сегмент «{c['segment']}»")
    if c.get("active") and c.get("uptime_s") is not None:
        parts.append(f"подключено {_ago(c['uptime_s'])} назад")
    if c.get("first_seen_s_ago") is not None:
        parts.append(f"впервые замечено {_ago(c['first_seen_s_ago'])} назад")
    return "Роутер: " + " · ".join(parts)


def _jsonable(facts: dict) -> dict:
    return {k: sorted(v) if isinstance(v, set) else v for k, v in facts.items()}
