"""«Паспорт» неизвестного роутера для заявки на модуль (GitHub issue). Без пароля и только чтение.

Собирает, как роутер представляется сам: заголовки и страница входа веб-интерфейса, UPnP-описание,
открытые служебные порты, производитель по MAC. Результат обезличивается: IP, MAC, серийные номера
и имена сети вырезаются, поэтому текст можно вставить в публичный issue.
"""
from __future__ import annotations

import asyncio
import re

from lanmap import oui
from lanmap.anonymize import anonymize
from lanmap.collectors import ScanContext, discovery, protocols, tcp
from lanmap.devices import parse_http
from lanmap.netinfo import LocalNet

PROBE_PORTS = [22, 23, 53, 80, 161, 443, 1900, 5000, 7547, 8080, 8291, 8443, 8728, 49152, 49000, 37215]
VENDOR_HEADERS = re.compile(r"^(x-[a-z0-9-]+|server|www-authenticate)$", re.I)


async def _ports_and_banners(ctx: ScanContext, host: str) -> tuple[list[int], list[dict]]:
    sem = asyncio.Semaphore(32)
    ports = await tcp.scan_host(ctx, host, PROBE_PORTS, sem, timeout=1.0)
    web = [p for p in ports if p in (80, 443, 5000, 8080, 8443)]
    probes = await asyncio.gather(*(tcp.probe(ctx, host, p, asyncio.Semaphore(4)) for p in web))
    return ports, list(probes)


def probe(net: LocalNet) -> dict:
    ctx = ScanContext(local_ip=net.local_ip, network=net.network, gateway=net.gateway, if_index=net.if_index)
    host = net.gateway
    out: dict = {"ports": [], "web": [], "upnp": {}, "oui": None}
    arp = discovery.arp_query(ctx, [host])
    mac = arp[0].get("mac") if arp else None
    out["oui"] = oui.short_vendor(oui.lookup(mac)) if mac else None
    ports, probes = asyncio.run(_ports_and_banners(ctx, host))
    out["ports"] = ports
    for pr in probes:
        resp = pr.get("response", "")
        if not resp.startswith("HTTP/"):
            continue
        h = parse_http(resp)
        head = resp.partition("\r\n\r\n")[0]
        headers = {k: v.strip() for k, v in re.findall(r"^([A-Za-z0-9-]+):\s*(.*)$", head, re.M) if VENDOR_HEADERS.match(k)}
        out["web"].append({"port": pr["port"], "tls": bool(pr.get("tls_version")), "status": h["status"],
                           "title": h["title"], "headers": headers,
                           "location": re.sub(r"^https?://[^/]+", "", h["location"])})
    multi = discovery.multicast(ctx, duration=4.0)
    multi["ssdp"] = [e for e in multi.get("ssdp", []) if e["ip"] == host]
    for d in protocols.upnp_descriptions(ctx, multi["ssdp"]):
        u = d.get("upnp") or {}
        for field in ("manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType"):
            for value in u.get(field, []):
                out["upnp"].setdefault(field, [])
                if value not in out["upnp"][field]:
                    out["upnp"][field].append(value)
        services = re.findall(r"<serviceType>([^<]+)</serviceType>", d.get("body", ""))
        out["upnp"].setdefault("services", [])
        out["upnp"]["services"] += [s for s in services if s not in out["upnp"]["services"]]
    return out


def to_markdown(info: dict) -> str:
    lines = ["### Паспорт роутера (`python -m lanmap router probe`)", ""]
    lines.append(f"- Производитель сетевого чипа по MAC: {info.get('oui') or 'неизвестно'}")
    lines.append(f"- Открытые порты (из проверенных {len(PROBE_PORTS)}): {', '.join(map(str, info['ports'])) or 'нет'}")
    for w in info["web"]:
        lines.append(f"- Веб {'HTTPS' if w['tls'] else 'HTTP'} {w['port']}: `{w['status']}`"
                     + (f", заголовок «{w['title']}»" if w["title"] else "")
                     + (f", редирект на `{w['location']}`" if w["location"] else ""))
        for k, v in w["headers"].items():
            lines.append(f"  - `{k}: {v}`")
    if info["upnp"]:
        lines.append("- UPnP-описание:")
        for k, v in info["upnp"].items():
            if v:
                lines.append(f"  - {k}: {', '.join(v)}")
    else:
        lines.append("- UPnP-описание: роутер не ответил")
    lines += ["", "_IP, MAC, серийные номера и токены вырезаны автоматически. Проверь текст перед отправкой._"]
    return anonymize("\n".join(lines))
