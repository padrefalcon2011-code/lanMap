"""Точечная перепроверка одной находки: заново собрать только нужные улики и прогнать ту же проверку.

Только чтение и только локальная подсеть, те же сборщики, что у среза. Итог:
- present — находка на месте;
- gone — исчезла. Только если есть доказательство, что устройство на связи и по адресу то же
  устройство (ARP, ответ порта, ping): выключенная приставка не должна выглядеть исправленной;
- unknown — нечем проверить (не ответило, адрес занял другой, нет входа в роутер).
"""
from __future__ import annotations

import concurrent.futures
import copy
import socket
from pathlib import Path

from lanmap import security
from lanmap.collectors import ScanContext
from lanmap.util import read_json

PORTS = {"TELNET_OPEN": [23], "CAMERA_XM_PORT": [34567], "ADB_EXPOSED": [5555],
         "NAS_EXTRA_SERVICES": sorted(security.NAS_EXTRA_PORTS)}
SMB_CHECKS = {"SMB_SIGNING", "SMB1_ENABLED"}
FORWARD_CHECKS = {"UPNP_PORT_MAPPINGS", "STATIC_PORT_FORWARD"}
SUPPORTED = set(PORTS) | SMB_CHECKS | FORWARD_CHECKS | {"CAMERA_ONVIF_ANON"}

GONE = {
    "TELNET_OPEN": "порт 23 закрыт",
    "CAMERA_XM_PORT": "порт 34567 закрыт",
    "ADB_EXPOSED": "порт 5555 закрыт",
    "NAS_EXTRA_SERVICES": "лишние службы закрыты",
    "SMB_SIGNING": "подпись SMB обязательна (или SMB выключен)",
    "SMB1_ENABLED": "SMB1 больше не принимается",
    "CAMERA_ONVIF_ANON": "ONVIF просит пароль или не отвечает",
    "UPNP_PORT_MAPPINGS": "у роутера нет UPnP-пробросов к устройству",
    "STATIC_PORT_FORWARD": "у роутера нет пробросов к устройству",
}


class Probes:
    """Все сетевые вызовы перепроверки. Тесты подставляют свои."""

    def __init__(self, ctx: ScanContext):
        self.ctx = ctx

    def tcp(self, ip: str, port: int) -> str:
        """open — соединился; closed — устройство ответило отказом (значит, на связи); silent — тишина."""
        try:
            with socket.create_connection((ip, port), timeout=1.5, source_address=(self.ctx.local_ip, 0)):
                return "open"
        except ConnectionRefusedError:
            return "closed"
        except OSError:
            return "silent"

    def mac(self, ip: str) -> str | None:
        from lanmap.collectors import discovery
        return discovery._send_arp((ip, self.ctx.local_ip)).get("mac")

    def ping(self, ip: str) -> bool:
        from lanmap.collectors import live
        try:
            return any(live.icmp_echo(ip, 800) for _ in range(2))
        except Exception:  # не Windows
            return False

    def smb(self, ip: str) -> dict:
        from lanmap.collectors import protocols
        return protocols.smb_probe(self.ctx, ip)

    def onvif(self, url: str) -> dict:
        from lanmap.collectors import protocols
        return protocols.onvif_info(self.ctx, url)

    def windows(self) -> dict:
        from lanmap.collectors import windows
        return windows.collect()

    def router(self) -> dict | None:
        from lanmap import routers
        return routers.collect(self.ctx.gateway) if self.ctx.gateway else None

    def igd(self, descriptions: list[dict]) -> dict:
        from lanmap.collectors import igd
        return igd.collect(self.ctx, descriptions)


def _out(result: str, detail: str) -> dict:
    return {"result": result, "detail": detail}


def run(check_id: str, finding: dict, model: dict, snapshot: Path, ctx: ScanContext, probes: Probes | None = None) -> dict:
    """Перепроверить находку последнего среза → {"result": present|gone|unknown, "detail"}."""
    probes = probes or Probes(ctx)
    check = security.BY_ID.get(check_id)
    if check is None or check_id not in SUPPORTED:
        return _out("unknown", "эту проверку пока можно повторить только новым срезом")
    raw = Path(snapshot) / "raw"
    if check_id in FORWARD_CHECKS:
        return _forwards(check, finding, model, raw, probes)

    ips = [x for x in finding.get("ips") or [] if ctx.in_scope(x)]
    if not ips:
        return _out("unknown", "адрес устройства вне локальной подсети")
    dev = next((d for d in model.get("devices") or [] if d["key"] == finding["key"]), None)
    if dev is None:
        return _out("unknown", "устройства нет в последнем срезе")

    local = bool(dev.get("is_local")) or ctx.local_ip in ips
    ip, alive = (ctx.local_ip if ctx.local_ip in ips else ips[0]), local
    if not local:
        # Адресов несколько (у камер Xiongmai заводской адрес бывает общим на несколько камер): берём тот,
        # где по ARP отвечает этот же MAC. Ответил чужой MAC, а своего нет — адрес занял другой
        want = (dev.get("mac") or "").upper()
        answers = [(x, (probes.mac(x) or "").upper()) for x in ips]
        mine = [x for x, mac in answers if mac and (not want or mac == want)]
        if mine:
            ip, alive = mine[0], True
        elif any(mac for _, mac in answers):
            return _out("unknown", "по адресу устройства теперь другое устройство — сделай новый срез")

    fresh = copy.deepcopy(dev)
    fresh["alive"] = True
    facts = fresh.setdefault("facts", {})
    windows = model.get("windows")

    if check_id in PORTS:
        ports = PORTS[check_id]
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(ports)) as pool:
            states = dict(zip(ports, pool.map(lambda p: probes.tcp(ip, p), ports)))
        alive = alive or any(s != "silent" for s in states.values())
        fresh["services"] = ([s for s in fresh.get("services") or [] if s["port"] not in states]
                             + [{"port": p} for p, s in states.items() if s == "open"])
        facts["mdns_services"] = []  # объявления mDNS заново не слушаем: решает порт
    elif check_id in SMB_CHECKS:
        s = probes.smb(ip)
        alive = alive or s.get("smb1") is not None or bool(s.get("status"))
        facts["smb"] = s if s.get("dialect") else None
        facts["smb1"] = s.get("smb1")
        if check_id == "SMB1_ENABLED" and local:
            windows = probes.windows()
        if check_id == "SMB1_ENABLED" and s.get("smb1") is None and not (local and windows):
            return _out("unknown", "устройство не ответило по SMB")
    elif check_id == "CAMERA_ONVIF_ANON":
        known = next((o.get("url") for o in read_json(raw / "onvif.json", []) or [] if o.get("ip") == ip), None)
        o = probes.onvif(known or f"http://{ip}/onvif/device_service")
        if o.get("anonymous"):
            facts["onvif"] = {**(o.get("fields") or {}), "anonymous": True}
        else:
            facts["onvif"] = {"auth_required": True} if o.get("auth_required") else {}
        alive = alive or bool(o.get("anonymous")) or str(o.get("error") or "").startswith("HTTP")

    mini = {"devices": [fresh], "meta": {}, "windows": windows}
    ok, hits = check.detect(security.Ctx(model=mini, raw=raw, tested=None))
    if not ok:
        return _out("unknown", check.needs or "нет нужных данных")
    hit = next((h for h in hits if h["key"] == finding["key"]), None)
    if hit:
        return _out("present", hit["detail"])
    if not alive and not probes.ping(ip):
        return _out("unknown", "устройство не ответило — включено ли оно?")
    return _out("gone", GONE[check_id])


def _forwards(check, finding: dict, model: dict, raw: Path, probes: Probes) -> dict:
    """Пробросы: заново спросить роутер (модуль) и шлюз по UPnP. Устройство само может быть выключено."""
    from lanmap import routers
    from lanmap.collectors import igd
    try:
        router = routers.normalize(probes.router())
    except Exception as exc:
        router = None
        router_error = f"роутер: {exc.__class__.__name__}"
    else:
        router_error = None
    gw = None
    if check.id == "UPNP_PORT_MAPPINGS" and router is None:
        try:
            gw = igd.normalize(probes.igd(read_json(raw / "upnp.json", []) or []))
        except Exception:
            gw = None
    mini = {"devices": model.get("devices") or [], "meta": {}, "router": router, "igd": gw}
    ok, hits = check.detect(security.Ctx(model=mini, raw=raw, tested=None))
    if not ok:
        return _out("unknown", router_error or check.needs or "роутер не ответил")
    ips = set(finding.get("ips") or [])
    hit = next((h for h in hits if h["key"] == finding["key"] or ips & set(h.get("ips") or [])), None)
    if hit:
        return _out("present", hit["detail"])
    return _out("gone", GONE[check.id])
