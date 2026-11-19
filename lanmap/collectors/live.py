"""«Найти устройство»: живой опрос, кто в сети прямо сейчас. Только чтение и только своя подсеть.

Источники:
- ICMP-эхо через iphlpapi (IcmpSendEcho): без прав администратора и без сотен процессов ping.exe;
- список активных клиентов роутера (если модуль роутера подключён) — для телефонов, которые не отвечают на ping.

Правило: если адрес хоть раз ответил на ping за эту сессию — решает ping (он быстрый в обе стороны);
иначе решает роутер. У MAC-двойников (камеры за мостом) роутер не слушаем: MAC моста активен, пока мост включён.
Пропажа по ping засчитывается после двух промахов подряд, чтобы один потерянный пакет не «гасил» устройство.
"""
from __future__ import annotations

import concurrent.futures
import ctypes
import socket
import struct
import time

from lanmap.collectors import ScanContext
from lanmap.util import norm_mac

MISSES_TO_GONE = 2
MAX_EVENTS = 60


# --- ICMP ------------------------------------------------------------------------------------

class _IpOptions(ctypes.Structure):
    _fields_ = [("Ttl", ctypes.c_ubyte), ("Tos", ctypes.c_ubyte), ("Flags", ctypes.c_ubyte),
                ("OptionsSize", ctypes.c_ubyte), ("OptionsData", ctypes.c_void_p)]


class _EchoReply(ctypes.Structure):
    _fields_ = [("Address", ctypes.c_ulong), ("Status", ctypes.c_ulong), ("RoundTripTime", ctypes.c_ulong),
                ("DataSize", ctypes.c_ushort), ("Reserved", ctypes.c_ushort), ("Data", ctypes.c_void_p),
                ("Options", _IpOptions)]


_PAYLOAD = b"lanmap"


def _ipaddr(ip: str) -> int:
    return struct.unpack("<I", socket.inet_aton(ip))[0]


def icmp_echo(ip: str, timeout_ms: int = 400) -> bool:
    """Ответил ли адрес на эхо. «Узел недоступен» от собственного адреса Windows ответом не считается."""
    api = ctypes.windll.iphlpapi
    api.IcmpCreateFile.restype = ctypes.c_void_p
    api.IcmpSendEcho.argtypes = [ctypes.c_void_p, ctypes.c_ulong, ctypes.c_char_p, ctypes.c_ushort, ctypes.c_void_p,
                                 ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong]
    api.IcmpCloseHandle.argtypes = [ctypes.c_void_p]
    handle = api.IcmpCreateFile()
    if not handle or handle == ctypes.c_void_p(-1).value:
        return False
    try:
        size = ctypes.sizeof(_EchoReply) + len(_PAYLOAD) + 8
        buf = ctypes.create_string_buffer(size)
        dest = _ipaddr(ip)
        got = api.IcmpSendEcho(handle, dest, _PAYLOAD, len(_PAYLOAD), None, buf, size, timeout_ms)
        if not got:
            return False
        reply = _EchoReply.from_buffer(buf)
        return reply.Status == 0 and reply.Address == dest
    finally:
        api.IcmpCloseHandle(handle)


class Prober:
    """Параллельный ICMP-опрос адресов своей подсети."""

    def __init__(self, ctx: ScanContext, workers: int = 128, echo=icmp_echo):
        self.ctx = ctx
        self.echo = echo
        self.pool = concurrent.futures.ThreadPoolExecutor(max_workers=workers, thread_name_prefix="lanmap-icmp")

    def sweep(self, ips: list[str]) -> dict[str, bool]:
        ips = [ip for ip in ips if self.ctx.in_scope(ip) and ip != self.ctx.local_ip]
        return dict(zip(ips, self.pool.map(self.echo, ips)))

    def close(self) -> None:
        self.pool.shutdown(wait=False, cancel_futures=True)


# --- сведение в состояние устройств ----------------------------------------------------------

class Presence:
    """Кто в сети: из ответов ping и списка клиентов роутера → состояние устройств и события."""

    def __init__(self, devices: list[dict], local_ip: str | None = None, mac_of=None):
        self.devices: dict[str, dict] = {}
        self.by_ip: dict[str, str] = {}
        self.by_mac: dict[str, str] = {}
        for d in devices:
            key = d["key"]
            self.devices[key] = {
                "key": key, "title": d.get("title") or key, "mac": d.get("mac"),
                "twin": bool(d.get("duplicate_mac")),
                "fixed": bool(d.get("is_gateway") or d.get("is_local")),  # шлюз и этот ПК — не кандидаты
                "ips": list(d.get("ips") or []), "new": False,
                "alive": None, "change": None, "changed_at": None,
            }
            for ip in d.get("ips") or []:
                self.by_ip.setdefault(ip, key)
            if d.get("mac") and not d.get("duplicate_mac"):
                self.by_mac.setdefault(d["mac"], key)
        self.local_ip = local_ip
        self.mac_of = mac_of                # MAC нового адреса (ARP), спрашивается один раз
        self.answered: set[str] = set()     # адреса, хоть раз ответившие на ping за сессию
        self.misses: dict[str, int] = {}
        self.ip_alive: dict[str, bool] = {}
        self.events: list[dict] = []
        self.cycles = 0

    def known_ips(self) -> list[str]:
        return list(self.by_ip)

    def _new_device(self, key: str, ip: str | None, mac: str | None, title: str) -> dict:
        dev = {"key": key, "title": title, "mac": mac, "twin": False, "fixed": False, "ips": [ip] if ip else [],
               "new": True, "alive": None, "change": None, "changed_at": None}
        self.devices[key] = dev
        if ip:
            self.by_ip[ip] = key
        if mac:
            self.by_mac[mac] = key
        return dev

    def update(self, ping: dict[str, bool], clients: list[dict] | None, now: float,
               name_new=lambda ip, mac: "Новое устройство") -> list[dict]:
        """Один цикл опроса. Возвращает новые события (gone / back / new)."""
        first = self.cycles == 0
        self.cycles += 1
        # роутер: активен ли клиент, и его текущий адрес
        router_ip: dict[str, bool] = {}
        for c in clients or []:
            mac = norm_mac(c.get("mac"))
            ip = c.get("ip")
            key = self.by_mac.get(mac) if mac else None
            if key is None and c.get("active") and (mac or ip):
                if ip and ip in self.by_ip:
                    key = self.by_ip[ip]
                else:
                    key = mac or f"ip:{ip}"
                    if key not in self.devices:
                        title = f"Новое: {c['hostname']}" if c.get("hostname") else name_new(ip, mac)
                        self._new_device(key, ip, mac, title)
            if key and ip:
                dev = self.devices[key]
                if ip not in dev["ips"]:
                    dev["ips"].append(ip)
                self.by_ip.setdefault(ip, key)
            if ip and not (key and self.devices[key]["twin"]):
                router_ip[ip] = router_ip.get(ip, False) or bool(c.get("active"))
        # ping: новые адреса, которых нет ни в срезе, ни у роутера
        for ip, ok in ping.items():
            if ok and ip not in self.by_ip and ip != self.local_ip:
                mac = norm_mac(self.mac_of(ip)) if self.mac_of else None
                key = (self.by_mac.get(mac) or (mac if mac in self.devices else None)) if mac else None
                if key:  # знакомое устройство на новом адресе
                    self.devices[key]["ips"].append(ip)
                    self.by_ip[ip] = key
                else:
                    self._new_device(mac or f"ip:{ip}", ip, mac, name_new(ip, mac))
        # итог по адресам
        for ip, ok in ping.items():
            if ok:
                self.answered.add(ip)
                self.misses[ip] = 0
            else:
                self.misses[ip] = self.misses.get(ip, 0) + 1
        for ip in set(self.by_ip) | set(ping):
            if ip in self.answered:
                alive = self.misses.get(ip, 0) < MISSES_TO_GONE
            elif ip in router_ip:
                alive = router_ip[ip]
            else:
                alive = bool(ping.get(ip))
            self.ip_alive[ip] = alive
        if self.local_ip:
            self.ip_alive[self.local_ip] = True
        # итог по устройствам и события
        events = []
        for dev in self.devices.values():
            states = [self.ip_alive[ip] for ip in dev["ips"] if ip in self.ip_alive]
            alive = any(states) if states else False
            if dev["alive"] is not None and alive != dev["alive"] or (dev["new"] and dev["alive"] is None and not first):
                kind = "new" if dev["new"] and dev["alive"] is None else ("back" if alive else "gone")
                dev["change"], dev["changed_at"] = kind, now
                if not dev["fixed"]:
                    events.append({"t": now, "key": dev["key"], "kind": kind, "title": dev["title"]})
            dev["alive"] = alive
        self.events = (self.events + events)[-MAX_EVENTS:]
        return events

    def state(self) -> dict:
        devs = []
        for d in self.devices.values():
            devs.append({k: d[k] for k in ("key", "title", "mac", "new", "fixed", "alive", "change", "changed_at")}
                        | {"ips": {ip: self.ip_alive.get(ip) for ip in d["ips"]}})
        return {"devices": devs, "events": list(reversed(self.events)), "cycles": self.cycles}
