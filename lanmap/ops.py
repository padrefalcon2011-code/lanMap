"""Действия владельца над последним срезом: подписать устройство, отметить находку или критерий чек-листа.

Общие для командной строки и локального веб-интерфейса. Пишут только в data/ (реестр, findings.json,
checklist.json) и пересобирают отчёт; сеть и устройства не трогают.
"""
from __future__ import annotations

from pathlib import Path

from lanmap import netinfo, registry
from lanmap.util import norm_mac, read_json


class OpError(ValueError):
    """Понятная человеку ошибка действия: командная строка печатает её, сервер отдаёт кодом 400."""


def pick_network(index: int | None = None, allow_large: bool = False) -> netinfo.LocalNet:
    nets = netinfo.list_networks()
    if index is not None:
        chosen = [n for n in nets if n.if_index == index and n.up]
    else:
        chosen = [n for n in nets if n.default_choice]
    if not chosen:
        raise OpError("Не нашёл подходящую сеть. Посмотри список: python -m lanmap interfaces")
    if len(chosen) > 1:
        lines = "\n".join(f"  --interface {n.if_index}  {n.alias}: {n.network}" for n in chosen)
        raise OpError(f"Подходящих сетей несколько, выбери одну:\n{lines}")
    net = chosen[0]
    hosts = netinfo.host_count(net.network)
    if hosts > netinfo.MAX_HOSTS_DEFAULT and not allow_large:
        raise OpError(f"Сеть {net.network} большая ({hosts} адресов). Если точно нужно — добавь --allow-large")
    return net


def latest() -> tuple[Path, dict]:
    """Последний срез и его модель (devices.json)."""
    from lanmap.scan import latest_snapshot
    snap = latest_snapshot(complete=True)
    if not snap:
        raise OpError("Готовых срезов ещё нет. Сначала: python -m lanmap scan")
    return snap, read_json(snap / "devices.json", {}) or {}


def rebuild() -> dict:
    from lanmap.build import build
    return build(latest()[0])


def sign(key: str, fields: dict, also_macs: list[str] | None = None) -> tuple[str, dict]:
    """Подпись устройства (ключ — MAC или MAC#серийник). Пустая строка в поле — стереть поле."""
    bad = [k for k in fields if k not in registry.EDITABLE]
    if bad:
        raise OpError(f"Неизвестные поля реестра: {', '.join(bad)}")
    data = registry.load()
    ips = None
    if "#" in key:  # MAC-двойник: запомнить адрес, по нему подпись найдётся, когда ключ сменится
        try:
            model = latest()[1]
        except OpError:
            model = {}
        ips = next((d["ips"] for d in model.get("devices", []) if d["key"] == key), None)
    try:
        entry = registry.sign(data, key, {k: v for k, v in fields.items() if v != ""}, ips=ips)
    except ValueError as exc:
        raise OpError(str(exc)) from exc
    for k, v in fields.items():
        if v == "":
            entry.pop(k, None)
    if also_macs:
        extra = [m for m in (norm_mac(x) for x in also_macs) if m]
        entry["also_macs"] = sorted(set(entry.get("also_macs", [])) | set(extra))
    registry.save(data)
    return key, entry


def set_finding(check: str, target: str, status: str, reason: str | None = None) -> list[dict]:
    """Отметка находки последнего среза. target — IP, ключ, MAC устройства или all.

    Адреса и сработавшая по каскаду отметка берутся из модели среза, а не от вызывающего."""
    from lanmap import security
    check = check.upper()
    if check not in security.BY_ID:
        raise OpError(f"Нет такой проверки: {check}. Есть: {', '.join(security.BY_ID)}")
    if status not in security.STATUSES:
        raise OpError(f"Нет такого статуса: {status}. Есть: {', '.join(security.STATUSES)}")
    snap, model = latest()
    sec = model.get("security")
    if sec is None:
        raise OpError("В последнем срезе ещё нет проверок. Пересобери: python -m lanmap build")
    mac = norm_mac(target.partition("#")[0])
    targets = [f for f in sec["findings"] if f["id"] == check and (
        target == "all" or target in f["ips"] or f["key"] == target
        or (mac and "#" not in target and f["key"].partition("#")[0] == mac))]
    if not targets:
        raise OpError(f"В последнем срезе нет находки {check} для «{target}». Список: python -m lanmap finding list")
    for f in targets:
        security.set_status(check, f["key"], status, reason or None, ips=f.get("ips"), replace=f.get("status_uid"))
    return targets


def set_check(code: str, status: str, note: str | None = None) -> dict:
    from lanmap import checklist
    try:
        return checklist.set_mark(code, status, note or None)
    except ValueError as exc:
        raise OpError(str(exc)) from exc
