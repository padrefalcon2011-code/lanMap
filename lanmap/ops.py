"""Действия владельца над последним срезом: подписать устройство, отметить находку или критерий чек-листа.

Общие для командной строки и локального веб-интерфейса. Пишут только в data/ (реестр, findings.json,
checklist.json, oui.txt) и пересобирают отчёт; сеть и устройства не трогают. Вход в роутер — только
проверка логина и чтение, пароль уходит в диспетчер учётных данных Windows.
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


def gateway() -> str:
    net = pick_network(allow_large=True)
    if not net.gateway:
        raise OpError("Не найден шлюз (роутер) в выбранной сети")
    return net.gateway


def oui_status() -> dict:
    from lanmap import oui
    return {"available": oui.available(), "count": oui.count()}


def oui_update(source: str | None = None) -> dict:
    """Скачать весь публичный реестр IEEE (MAC-адреса никуда не уходят) и пересобрать отчёт."""
    from lanmap import oui
    try:
        _, count = oui.update(source)
    except (OSError, ValueError) as exc:
        raise OpError(f"Не удалось обновить базу производителей: {exc}") from exc
    try:
        rebuild()
    except OpError:  # срезов ещё нет — пересобирать нечего
        pass
    return {"count": count}


def _router_module(host: str):
    from lanmap import routers
    found = routers.detect(host)
    if not found:
        return None, None
    return routers.MODULES[found[0]], found


def router_status(host: str | None = None) -> dict:
    """Что за роутер и настроен ли вход. Без пароля: роутер только спрашивают, как он представляется."""
    from lanmap import credentials
    host = host or gateway()
    module, found = _router_module(host)
    if not module:
        return {"host": host, "kind": None, "product": None, "login": None}
    saved = credentials.load(module.credential_target(host))
    return {"host": host, "kind": found[0], "product": found[1], "login": saved[0] if saved else None}


def router_test(host: str) -> list[dict]:
    """Какие чтения роутера доступны: имя, путь, ок или ошибка, размер. Без личных данных."""
    module, found = _router_module(host)
    if not module:
        raise OpError("Для этого роутера пока нет модуля")
    result = module.collect(host)
    if "login" in result["errors"]:
        raise OpError(f"Вход: {result['errors']['login']}")
    rows = []
    for name, path in getattr(module, "READS", {}).items():
        if name in result["errors"]:
            rows.append({"name": name, "path": path, "ok": False, "info": result["errors"][name]})
            continue
        value = result["data"].get(name)
        if isinstance(value, dict):
            info = f"ключей: {len(value)}"
        elif isinstance(value, list):
            info = f"записей: {len(value)}"
        else:
            info = repr(value)[:60]
        rows.append({"name": name, "path": path, "ok": True, "info": info})
    return rows


def router_login(username: str, password: str, host: str | None = None) -> dict:
    """Проверить вход и сохранить его в диспетчере учётных данных Windows. Пароль не попадает ни в файлы,
    ни в ответ, ни в текст ошибки."""
    from lanmap import credentials
    host = host or gateway()
    module, found = _router_module(host)
    if not module:
        raise OpError("Для этого роутера пока нет модуля. Собери паспорт роутера и отправь заявку.")
    if not username or not password:
        raise OpError("Нужны логин и пароль")
    try:
        module.check_login(host, username, password)
    except Exception as exc:
        raise OpError(f"Не получилось войти: {exc}") from None
    credentials.save(module.credential_target(host), username, password,
                     comment=f"LanMap: роутер {found[1]} {host}")
    return {"host": host, "kind": found[0], "product": found[1], "login": username,
            "target": "LanMap:" + module.credential_target(host)}


def router_forget(host: str | None = None) -> bool:
    from lanmap import credentials
    host = host or gateway()
    module, _ = _router_module(host)
    target = module.credential_target(host) if module else f"router:{host}"
    return credentials.delete(target)


def router_probe() -> str:
    """Обезличенный паспорт роутера для заявки на модуль (markdown). Без пароля, только чтение."""
    from lanmap.routers import probe
    return probe.to_markdown(probe.probe(pick_network(allow_large=True)))
