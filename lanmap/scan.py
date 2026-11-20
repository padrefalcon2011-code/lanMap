"""Срез сети: запуск сборщиков и сохранение сырых улик в новую папку data/snapshots/<время>/."""
from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import re
import time
import urllib.parse
from pathlib import Path

from lanmap import __version__, netinfo
from lanmap.collectors import ScanContext, discovery, igd, protocols, tcp, windows
from lanmap.collectors import dnswire
from lanmap.collectors import onvif as onvif_mod
from lanmap.ports import QUICK
from lanmap.util import data_dir, now_iso, write_json


def snapshots_dir() -> Path:
    path = data_dir() / "snapshots"
    path.mkdir(parents=True, exist_ok=True)
    return path


def new_snapshot_dir() -> Path:
    """Новая папка среза. Существующие никогда не перезаписываются."""
    base = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    path = snapshots_dir() / base
    n = 2
    while path.exists():
        path = snapshots_dir() / f"{base}_{n}"
        n += 1
    (path / "raw").mkdir(parents=True)
    return path


def announced_ports(multi: dict, ctx: ScanContext) -> dict[str, set[int]]:
    """Порты, которые устройства сами объявили в mDNS (SRV) и SSDP (LOCATION)."""
    extra: dict[str, set[int]] = {}
    records = [r for pkt in multi.get("mdns", []) for r in pkt["records"]]
    host_ip = {r["name"].lower(): r["value"] for r in records if r["type"] == dnswire.TYPE_A}
    for r in records:
        if r["type"] == dnswire.TYPE_SRV and r["value"]["port"]:
            ip = host_ip.get(r["value"]["target"].lower())
            if ctx.in_scope(ip):
                extra.setdefault(ip, set()).add(r["value"]["port"])
    for url, ip in protocols.ssdp_locations(multi.get("ssdp", [])).items():
        parsed = urllib.parse.urlparse(url)
        if ctx.in_scope(parsed.hostname):
            extra.setdefault(parsed.hostname, set()).add(parsed.port or 80)
    return extra


class Progress:
    def __init__(self, quiet: bool = False, on_step=None):
        self.quiet = quiet
        self.on_step = on_step  # для веб-интерфейса: показать, на каком этапе срез
        self.t0 = time.monotonic()
        self.stages: list[dict] = []

    def step(self, text: str) -> None:
        elapsed = time.monotonic() - self.t0
        self.stages.append({"at_s": round(elapsed, 1), "stage": text})
        if not self.quiet:
            print(f"[{elapsed:6.1f} с] {text}", flush=True)
        if self.on_step:
            self.on_step(text)


async def _ports_and_probes(ctx: ScanContext, targets: dict[str, list[int]], progress: Progress) -> tuple[dict, list]:
    sem = asyncio.Semaphore(256)
    ips = sorted(targets)
    results = await asyncio.gather(*(tcp.scan_host(ctx, ip, targets[ip], sem) for ip in ips))
    open_ports = dict(zip(ips, results))
    total = sum(len(v) for v in results)
    progress.step(f"Открытых портов: {total}. Снимаю баннеры служб")
    probe_sem = asyncio.Semaphore(24)
    probes = await asyncio.gather(*(tcp.probe(ctx, ip, port, probe_sem)
                                    for ip, ports in open_ports.items() for port in ports))
    return open_ports, list(probes)


def run_scan(net: netinfo.LocalNet, ports: list[int] | None = None, quiet: bool = False, on_step=None) -> Path:
    ports = ports or QUICK
    ctx = ScanContext(local_ip=net.local_ip, network=net.network, gateway=net.gateway,
                      if_index=net.if_index, local_mac=net.mac)
    snap = new_snapshot_dir()
    raw = snap / "raw"
    progress = Progress(quiet, on_step)
    meta = {
        "lanmap_version": __version__,
        "started": now_iso(),
        "admin": netinfo.is_admin(),
        "hostname": netinfo.hostname(),
        "interface": net.to_dict(),
        "ports_mode": "quick" if ports is QUICK else "custom",
        "ports_tested": len(ports),
    }
    write_json(snap / "meta.json", meta)

    progress.step(f"Сеть {ctx.network} через «{net.alias}»: ping-проход, mDNS, SSDP, WS-Discovery")
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
        f_multi = pool.submit(discovery.multicast, ctx)
        f_wsd = pool.submit(discovery.ws_discovery, ctx)
        pings = discovery.ping_sweep(ctx)
        multi, wsd = f_multi.result(), f_wsd.result()
    write_json(raw / "ping.json", pings)
    write_json(raw / "multicast.json", multi)
    write_json(raw / "wsd.json", wsd)

    neighbors = discovery.neighbor_table(ctx)
    write_json(raw / "neighbors.json", neighbors)

    candidates = {ip for ip, p in pings.items() if p.get("alive")}
    candidates |= {n["ip"] for n in neighbors}
    candidates |= {e["ip"] for e in multi.get("mdns", []) + multi.get("ssdp", [])}
    candidates |= {e["ip"] for e in wsd}
    candidates.add(ctx.local_ip)
    candidates = {ip for ip in candidates if ctx.in_scope(ip)}
    progress.step(f"Кандидатов: {len(candidates)}. Уточняю MAC через ARP")
    arp = discovery.arp_query(ctx, sorted(candidates))
    write_json(raw / "arp.json", arp)

    extra = announced_ports(multi, ctx)
    targets = {ip: sorted(set(ports) | extra.get(ip, set())) for ip in candidates}
    progress.step(f"Проверяю {len(ports)} TCP-портов на каждом из {len(targets)} адресов")
    open_ports, probes = asyncio.run(_ports_and_probes(ctx, targets, progress))
    write_json(raw / "ports.json", {"tested": ports, "announced_extra": {k: sorted(v) for k, v in extra.items()},
                                    "open": open_ports})
    write_json(raw / "probes.json", probes)

    if ctx.gateway:
        from lanmap import routers
        progress.step("Роутер: список клиентов и пробросов (только чтение)")
        router = routers.collect(ctx.gateway)
        write_json(raw / "router.json", router)
        if router.get("skipped") or router.get("errors", {}).get("login"):
            progress.step("Данные роутера недоступны: " + (router.get("skipped") or router["errors"]["login"]))

    progress.step("Имена (DNS, роутер, NetBIOS), UPnP-описания, ONVIF, SMB (и SMB1)")
    ips = sorted(candidates)
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        f_rdns = pool.map(protocols.reverse_dns, ips)
        f_ptr = pool.map(lambda ip: protocols.gateway_ptr(ctx, ip), ips)
        f_nb = pool.map(lambda ip: protocols.netbios_status(ctx, ip), ips)
        names = {
            "reverse_dns": dict(f_rdns),
            "gateway_ptr": dict(f_ptr),
            "netbios": [x for x in f_nb if x],
        }
        smb_hosts = [ip for ip, p in open_ports.items() if 445 in p]
        f_smb = pool.map(lambda ip: protocols.smb_probe(ctx, ip), smb_hosts)
        f_onvif = pool.map(lambda url: protocols.onvif_info(ctx, url), protocols.onvif_targets(ctx, wsd, open_ports))
        upnp = protocols.upnp_descriptions(ctx, multi.get("ssdp", []))
        smb, onvif = list(f_smb), list(f_onvif)
        # Отдаёт ли камера без пароля адрес кадра со своим паролем (сам адрес не сохраняется)
        answered = [o for o in onvif if o.get("fields") or o.get("auth_required")]
        snap_leak = list(pool.map(lambda o: onvif_mod.snapshot_leak(ctx, o["ip"], o["url"]), answered))
    write_json(raw / "names.json", names)
    write_json(raw / "upnp.json", upnp)
    progress.step("UPnP-пробросы у шлюза (без пароля, только чтение)")
    write_json(raw / "upnp_igd.json", igd.collect(ctx, upnp))
    write_json(raw / "onvif.json", onvif)
    write_json(raw / "onvif_snapshot.json", snap_leak)
    write_json(raw / "smb.json", smb)
    write_json(raw / "windows.json", windows.collect())

    meta["finished"] = now_iso()
    meta["stages"] = progress.stages
    meta["candidates"] = len(candidates)
    write_json(snap / "meta.json", meta)
    progress.step(f"Сырые улики сохранены: {snap}")
    return snap


def latest_snapshot(complete: bool = False) -> Path | None:
    """Последний срез. complete — только собранный (есть devices.json): прерванный срез оставляет папку без него,
    и отметки владельца не должны уходить туда."""
    need = "devices.json" if complete else "meta.json"
    snaps = sorted(p for p in snapshots_dir().iterdir() if p.is_dir() and (p / need).exists()
                   and re.match(r"\d{4}-\d\d-\d\d_", p.name))
    return snaps[-1] if snaps else None
