"""Лёгкий присмотр: опрос присутствия, история по сетям и журнал для трея."""
from __future__ import annotations

import threading
import time
from datetime import datetime
from pathlib import Path

from lanmap import ops, registry, routers, scan, snapshot
from lanmap.collectors import ScanContext, discovery, live
from lanmap.util import UserError, data_dir, norm_mac, read_json, read_state, write_json

INTERVAL = 120
DAY = 86400
RETURN_DAYS = 14
EVENT_LIMIT = 250

TITLES = {"new": "Новое устройство", "return": "Снова в сети", "gap": "Перерыв в наблюдении"}
SOURCES = {"router": "Список активных клиентов роутера", "local": "Ответ на ping в локальной подсети"}


class Poller:
    """Опрос списка клиентов по сохранённой сессии, иначе ping и привязка ответов к MAC."""

    def __init__(self):
        self.router_key = None
        self.router_poll = None
        self.router_changed = threading.Event()

    def __call__(self):
        net = ops.pick_network()
        ctx = ScanContext(net.local_ip, net.network, net.gateway, net.if_index, net.mac)
        if not ctx.in_scope(ctx.gateway):
            raise UserError("Шлюз этой подсети недоступен для присмотра")
        rows = discovery.arp_query(ctx, [ctx.gateway])
        gateway = next((mac for row in rows if (mac := norm_mac(row.get("mac")))), None)
        if not gateway:
            raise UserError("Не удалось подтвердить MAC шлюза")

        network = (ctx.network, gateway)
        router_key = (network, ctx.if_index, ctx.gateway)
        if self.router_changed.is_set() or self.router_key != router_key or self.router_poll is None:
            self.router_changed.clear()
            self.router_key = router_key
            self.router_poll, _ = routers.presence(ctx.gateway)
        if self.router_poll is not None:
            try:
                clients = [c for c in self.router_poll() if c.get("active") is True]
            except Exception:
                self.router_poll = None
                raise UserError("Связь со списком клиентов роутера прервалась") from None
            source = "router"
        else:
            prober = live.Prober(ctx)
            try:
                replies = prober.sweep(ctx.hosts())
            finally:
                prober.close()
            if not any(replies.values()):
                raise UserError("Нет ответов от устройств в локальной подсети")
            clients = discovery.arp_query(ctx, [ip for ip, alive in replies.items() if alive])
            source = "local"
        excluded = {None, norm_mac(ctx.local_mac), gateway}
        clients = [c for c in clients if norm_mac(c.get("mac")) not in excluded]
        return network, source, clients

def baseline(network: tuple[str, str]) -> dict | None:
    """Последний собранный срез этой подсети с тем же MAC шлюза."""
    paths = sorted((p for p in scan.snapshots_dir().iterdir() if p.is_dir()
                    and snapshot.is_snapshot_name(p.name)), key=snapshot.order_key, reverse=True)
    for path in paths:
        meta = snapshot.meta(path)
        if not (path / "devices.json").is_file() or not snapshot.finished(path, meta):
            continue
        identity = snapshot.network_id(path, meta)
        if (identity.get("network"), identity.get("gateway_mac")) != network:
            continue
        model = read_json(path / "devices.json", {})
        at = datetime.fromisoformat(meta["finished"]).timestamp()
        devices = {}
        for dev in model.get("devices", []):
            mac = norm_mac(dev.get("mac"))
            if mac and mac != network[1] and not dev.get("is_local"):
                devices[mac] = {"seen": at if dev.get("alive") else None, "source": None}
        return devices
    return None


def _initial() -> dict:
    return {"version": 1, "return_days": RETURN_DAYS, "paused": False,
            "networks": {}, "events": [], "last_poll": None, "next_id": 1}


def _event(state: dict, kind: str, at: float, **fields) -> dict:
    event = {"id": state["next_id"], "kind": kind, "at": at, **fields}
    state["next_id"] += 1
    state["events"].append(event)
    state["events"] = state["events"][-EVENT_LIMIT:]
    return event


def _gap(state: dict, at: float) -> dict:
    events = state["events"]
    if events and events[-1]["kind"] == "gap" and "end" not in events[-1]:
        return events[-1]
    last = state["last_poll"]
    return _event(state, "gap", min(at, last + INTERVAL) if last is not None else at)


def observe(state: dict, network: tuple[str, str], source: str, clients: list[dict], now: float,
            owner: dict, load_baseline=baseline) -> list[dict]:
    """Обновляет историю удачного опроса и отдаёт события для Windows."""
    events = state["events"]
    if events and events[-1]["kind"] == "gap" and "end" not in events[-1]:
        events[-1]["end"] = now
    elif state["last_poll"] is not None and now - state["last_poll"] > 2 * INTERVAL:
        _gap(state, now)["end"] = now
    state["last_poll"] = now

    net_key = "|".join(network)
    known = state["networks"].get(net_key)
    if known is None:
        known = load_baseline(network)
        quiet = known is None
        known = {} if quiet else known
        state["networks"][net_key] = known
    else:
        quiet = False
    aliases = registry.aliases(owner)
    for mac in known.keys() & aliases.keys():
        previous = known.pop(mac)
        key = aliases[mac]
        if key not in known or (previous["seen"] or 0) > (known[key]["seen"] or 0):
            known[key] = previous

    active = {}
    for client in clients:
        mac = norm_mac(client.get("mac"))
        if mac:
            active.setdefault(aliases.get(mac, mac), (mac, client))
    for key in known.keys() - active.keys():
        entry = known[key]
        if entry["source"] in (None, source):
            entry["absent"] = True

    found = []
    for key, (mac, client) in active.items():
        previous = known.get(key)
        known[key] = {"seen": now, "source": source}
        if quiet:
            continue
        seen = previous["seen"] if previous is not None else None
        if previous is None:
            kind = "new"
        elif previous.get("absent") and seen is not None and now - seen >= state["return_days"] * DAY:
            kind = "return"
        else:
            continue
        signed = registry.entry_for(owner, key) or {}
        name = signed.get("name") or client.get("label") or client.get("hostname")
        found.append(_event(state, kind, now, name=str(name)[:160] if name else None, mac=mac,
                            ip=str(client["ip"])[:40] if client.get("ip") else None,
                            network=network[0], segment=str(client.get("segment") or "")[:80],
                            source=source, seen=seen))
    return found


class Monitor:
    """Один поток опроса. Уведомления уходят после сохранения журнала."""

    def __init__(self, notify, poll=None, path: Path | None = None):
        self.path = path if path is not None else data_dir() / "monitor.json"
        self.notify = notify
        self.poll = poll if poll is not None else Poller()
        self.lock = threading.Lock()
        self.wake = threading.Event()
        self.stop = threading.Event()
        self.source = None
        self.problem = None

    def _load(self) -> dict:
        state = read_state(self.path, _initial())
        if not isinstance(state, dict) or state.get("version") != 1 or not _initial().keys() <= state.keys():
            raise UserError("Неподдерживаемый формат журнала присмотра")
        days = state["return_days"]
        if type(days) is not int or not 1 <= days <= 365 or type(state["paused"]) is not bool:
            raise UserError("Некорректные настройки в журнале присмотра")
        return state

    def status(self) -> dict:
        with self.lock:
            try:
                state = self._load()
            except (OSError, UserError) as exc:
                state = _initial()
                return {**state, "problem": str(exc), "source": None}
            return {**state, "problem": self.problem, "source": self.source}

    def settings(self, fields: dict) -> None:
        days = fields.get("return_days")
        paused = fields.get("paused")
        if not fields or fields.keys() - {"return_days", "paused"}:
            raise UserError("Выбери настройку присмотра")
        if "return_days" in fields and (type(days) is not int or not 1 <= days <= 365):
            raise UserError("Укажи целое число от 1 до 365 дней")
        if "paused" in fields and type(paused) is not bool:
            raise UserError("Укажи, приостановлен ли присмотр")
        with self.lock:
            state = self._load()
            state.update(fields)
            if paused:
                _gap(state, time.time())
            write_json(self.path, state)
        if paused is not None:
            self.wake.set()

    def _tick(self) -> None:
        with self.lock:
            if self._load()["paused"]:
                return
        try:
            network, source, clients = self.poll()
        except Exception as exc:
            with self.lock:
                self.problem = str(exc) if isinstance(exc, UserError) else f"Опрос прерван ({type(exc).__name__})"
                self.source = None
                state = self._load()
                count = state["next_id"]
                _gap(state, time.time())
                if state["next_id"] != count and not self.stop.is_set():
                    write_json(self.path, state)
            return
        with self.lock:
            state = self._load()
            if state["paused"] or self.stop.is_set():
                return
            new = observe(state, network, source, clients, time.time(), registry.load())
            write_json(self.path, state)
            self.problem = None
            self.source = source
        if new:
            self.notify(new)

    def run(self) -> None:
        while not self.stop.is_set():
            self.wake.clear()
            try:
                self._tick()
            except Exception as exc:
                with self.lock:
                    self.source = None
                    self.problem = str(exc) if isinstance(exc, (UserError, OSError)) else f"Ошибка присмотра ({type(exc).__name__})"
            self.wake.wait(INTERVAL)

    def close(self) -> None:
        self.stop.set()
        self.wake.set()

    def refresh_router(self) -> None:
        if isinstance(self.poll, Poller):
            self.poll.router_changed.set()
        self.wake.set()
