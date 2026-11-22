"""Срез сети: запуск сборщиков и сохранение сырых улик в новую папку data/snapshots/<время>/."""
from __future__ import annotations

import asyncio
import concurrent.futures
import datetime as dt
import time
from pathlib import Path

from lanmap import __version__, netinfo, snapshot
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
    """Новая папка среза. Существующие никогда не перезаписываются: имя занимает сам mkdir (exist_ok=False),
    поэтому два среза в одну секунду, даже параллельных, получат …_HHMMSS и …_HHMMSS_2, а не одну папку."""
    base = dt.datetime.now().strftime("%Y-%m-%d_%H%M%S")
    root = snapshots_dir()
    root.mkdir(parents=True, exist_ok=True)
    n = 1
    while True:
        path = root / (base if n == 1 else f"{base}_{n}")
        try:
            path.mkdir()
            break
        except FileExistsError:
            n += 1
    (path / "raw").mkdir()
    return path


def announced_ports(multi: dict, ctx: ScanContext) -> dict[str, set[int]]:
    """Порты, которые устройства сами объявили в mDNS (SRV) и SSDP (LOCATION)."""
    extra: dict[str, set[int]] = {}
    records = [r for pkt in multi.get("mdns", []) for r in pkt.get("records") or [] if isinstance(r, dict)]
    host_ip = {str(r.get("name")).lower(): r.get("value") for r in records if r.get("type") == dnswire.TYPE_A}
    for r in records:
        value = r.get("value")
        if r.get("type") != dnswire.TYPE_SRV or not isinstance(value, dict):
            continue
        port, ip = value.get("port"), host_ip.get(str(value.get("target")).lower())
        if isinstance(port, int) and 1 <= port <= 65535 and isinstance(ip, str) and ctx.in_scope(ip):
            extra.setdefault(ip, set()).add(port)
    for url in protocols.ssdp_locations(multi.get("ssdp", [])):
        target = ctx.url_in_scope(url)  # кривой LOCATION пропускается, срез не обрывается
        if target:
            extra.setdefault(target[0], set()).add(target[1])
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


class Passport:
    """Паспорт полноты среза: исход каждого этапа — ok, partial, skipped, error — и короткое пояснение.

    Обязательные этапы (ping, ARP, порты) при сбое обрывают срез: он остаётся незавершённым. Необязательные идут
    через guard: исключение пишется в паспорт, сырой файл этапа не создаётся, и его проверки честно говорят
    «нечем проверить»."""

    def __init__(self):
        self.items: list[dict] = []

    def add(self, sid: str, status: str, detail: str = "") -> None:
        self.items.append({"id": sid, "status": status, "detail": detail})

    def guard(self, sid: str, fn, default=None):
        """→ (результат, удалось ли)."""
        try:
            return fn(), True
        except Exception as exc:
            self.add(sid, "error", _err(exc))
            return default, False


def _err(exc: BaseException) -> str:
    return f"{type(exc).__name__}: {exc}"[:160]


def _each(fn, fails: list):
    """Опрос одного адреса: сбой на нём не отменяет остальные (pool.map бросил бы исключение на всё сразу)."""
    def call(x):
        try:
            return fn(x)
        except Exception as exc:
            fails.append(type(exc).__name__)
            return None
    return call


def _status(fails: list, done: int) -> str:
    return "ok" if not fails else ("partial" if done else "error")


def _failed(fails: list) -> str:
    return f"; сбоев: {len(fails)} ({', '.join(sorted(set(fails)))})" if fails else ""


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
    passport = Passport()
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
    alive_n = sum(1 for p in pings.values() if p.get("alive"))
    passport.add("discovery", "partial" if multi.get("errors") else "ok",
                 f"ping: ответили {alive_n} из {len(pings)} · mDNS {len(multi.get('mdns', []))} · "
                 f"SSDP {len(multi.get('ssdp', []))} · WS-Discovery {len(wsd)}"
                 + (f"; ошибок мультикаста: {len(multi['errors'])}" if multi.get("errors") else ""))

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
    passport.add("arp", "ok", f"кандидатов {len(candidates)}, MAC по ARP: {sum(1 for a in arp if a.get('mac'))}")

    extra = announced_ports(multi, ctx)
    targets = {ip: sorted(set(ports) | extra.get(ip, set())) for ip in candidates}
    progress.step(f"Проверяю {len(ports)} TCP-портов на каждом из {len(targets)} адресов")
    tcp.sweep_cert_tmp()  # остатки прошлых срезов
    open_ports, probes = asyncio.run(_ports_and_probes(ctx, targets, progress))
    left = tcp.sweep_cert_tmp()
    if left:
        # Во временных PEM — имена и адреса из сертификатов; лежат в data/, но владелец должен знать
        meta["warnings"] = [f"не удалось удалить временные файлы сертификатов в data/{tcp.CERT_TMP}: {len(left)}"]
        progress.step(meta["warnings"][0])
    write_json(raw / "ports.json", {"tested": ports, "announced_extra": {k: sorted(v) for k, v in extra.items()},
                                    "open": open_ports})
    write_json(raw / "probes.json", probes)
    passport.add("ports", "ok", f"{len(ports)} портов на {len(targets)} адресах · открыто "
                                f"{sum(len(v) for v in open_ports.values())} · ответов служб {len(probes)}")

    if ctx.gateway:
        from lanmap import routers
        progress.step("Роутер: список клиентов и пробросов (только чтение)")
        router, ok = passport.guard("router", lambda: routers.collect(ctx.gateway))
        if ok:
            write_json(raw / "router.json", router)
            errors = router.get("errors") or {}
            if router.get("skipped"):
                passport.add("router", "skipped", router["skipped"])
            elif errors.get("login"):
                passport.add("router", "error", errors["login"])
            else:
                passport.add("router", "partial" if errors else "ok",
                             ("не прочитано: " + ", ".join(sorted(errors))) if errors else router.get("product") or "")
            if router.get("skipped") or errors.get("login"):
                progress.step("Данные роутера недоступны: " + (router.get("skipped") or errors["login"]))
    else:
        passport.add("router", "skipped", "у сети нет шлюза")

    progress.step("Имена (DNS, роутер, NetBIOS), UPnP-описания, ONVIF, SMB (и SMB1)")
    ips = sorted(candidates)
    f_names, f_smb, f_onvif, f_leak = [], [], [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=32) as pool:
        f_rdns = pool.map(_each(protocols.reverse_dns, f_names), ips)
        f_ptr = pool.map(_each(lambda ip: protocols.gateway_ptr(ctx, ip), f_names), ips)
        f_nb = pool.map(_each(lambda ip: protocols.netbios_status(ctx, ip), f_names), ips)
        names = {
            "reverse_dns": dict(x for x in f_rdns if x),
            "gateway_ptr": dict(x for x in f_ptr if x),
            "netbios": [x for x in f_nb if x],
        }
        smb_hosts = [ip for ip, p in open_ports.items() if 445 in p]
        f_smb_res = pool.map(_each(lambda ip: protocols.smb_probe(ctx, ip), f_smb), smb_hosts)
        onvif_urls, onvif_ok = passport.guard("onvif", lambda: protocols.onvif_targets(ctx, wsd, open_ports), [])
        f_onvif_res = pool.map(_each(lambda url: protocols.onvif_info(ctx, url), f_onvif), onvif_urls)
        upnp, upnp_ok = passport.guard("upnp", lambda: protocols.upnp_descriptions(ctx, multi.get("ssdp", [])), [])
        smb = [x for x in f_smb_res if x is not None]
        onvif = [x for x in f_onvif_res if x is not None]
        # Отдаёт ли камера без пароля адрес кадра со своим паролем (сам адрес не сохраняется)
        answered = [o for o in onvif if o.get("fields") or o.get("auth_required")]
        snap_leak = [x for x in pool.map(_each(lambda o: onvif_mod.snapshot_leak(ctx, o["ip"], o["url"]), f_leak),
                                         answered) if x is not None]
    write_json(raw / "names.json", names)
    passport.add("names", _status(f_names, len(ips)),
                 f"DNS {sum(1 for v in names['reverse_dns'].values() if v)} · "
                 f"от роутера {sum(1 for v in names['gateway_ptr'].values() if v)} · NetBIOS {len(names['netbios'])}"
                 + _failed(f_names))
    if upnp_ok:
        write_json(raw / "upnp.json", upnp)
        passport.add("upnp", "ok", f"описаний {len(upnp)}")
    progress.step("UPnP-пробросы у шлюза (без пароля, только чтение)")
    gw, ok = passport.guard("igd", lambda: igd.collect(ctx, upnp))
    if ok:
        write_json(raw / "upnp_igd.json", gw)
        n_gw = len((gw or {}).get("gateways") or [])
        # UPnP у шлюза выключен — это хорошо, а не пробел в проверке
        passport.add("igd", "ok", f"шлюзов с UPnP: {n_gw}" if n_gw else "UPnP IGD у шлюза выключен или молчит")
    if onvif_ok:
        write_json(raw / "onvif.json", onvif)
        write_json(raw / "onvif_snapshot.json", snap_leak)
        passport.add("onvif", _status(f_onvif + f_leak, len(onvif)) if onvif_urls else "ok",
                     (f"камер ответило {len(answered)} из {len(onvif_urls)}" if onvif_urls
                      else "камер с ONVIF не видно") + _failed(f_onvif + f_leak))
    write_json(raw / "smb.json", smb)
    passport.add("smb", _status(f_smb, len(smb)) if smb_hosts else "ok",
                 (f"опрошено {len(smb)} из {len(smb_hosts)}" if smb_hosts else "нет устройств с портом 445")
                 + _failed(f_smb))
    win, ok = passport.guard("windows", windows.collect)
    if ok:
        write_json(raw / "windows.json", win)
        if win.get("skipped"):
            passport.add("windows", "skipped", win["skipped"])
        else:
            passport.add("windows", "partial" if win.get("error") else "ok",
                         "реестр: " + ("не прочитан" if win.get("error") else "прочитан (клиент SMB1)"))

    meta["finished"] = now_iso()
    meta["stages"] = progress.stages
    meta["candidates"] = len(candidates)
    meta["passport"] = passport.items
    # Манифест сырых файлов — той же записью, что и finished: завершённый срез без манифеста бывает только старый
    meta["manifest"] = snapshot.manifest(snap)
    write_json(snap / "meta.json", meta)
    progress.step(f"Сырые улики сохранены: {snap}")
    return snap


def latest_snapshot(complete: bool = False) -> Path | None:
    """Последний завершённый срез (snapshot.finished). complete — ещё и собранный (есть devices.json).

    Прерванный срез не берётся никогда: даже пересобранный вручную, он не должен забрать страницу и отметки."""
    snaps = sorted((p for p in snapshots_dir().iterdir() if p.is_dir() and snapshot.is_snapshot_name(p.name)),
                   key=snapshot.order_key, reverse=True)
    return next((p for p in snaps if snapshot.finished(p) and (not complete or (p / "devices.json").exists())), None)
