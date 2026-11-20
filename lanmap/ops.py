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


class NeedLogin(OpError):
    """Нужен (другой) логин и пароль: страница покажет форму входа."""


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
    _snap, model = latest()
    targets = _findings(model, check, target)
    for f in targets:
        security.set_status(check, f["key"], status, reason or None, ips=f.get("ips"), replace=f.get("status_uid"))
    return targets


def _findings(model: dict, check: str, target: str) -> list[dict]:
    """Находки проверки в модели среза по IP, ключу, MAC устройства или all."""
    sec = model.get("security")
    if sec is None:
        raise OpError("В последнем срезе ещё нет проверок. Пересобери: python -m lanmap build")
    mac = norm_mac(target.partition("#")[0])
    targets = [f for f in sec["findings"] if f["id"] == check and (
        target == "all" or target in f["ips"] or f["key"] == target
        or (mac and "#" not in target and f["key"].partition("#")[0] == mac))]
    if not targets:
        raise OpError(f"В последнем срезе нет находки {check} для «{target}». Список: python -m lanmap finding list")
    return targets


def recheck(check: str, target: str, probes=None) -> list[dict]:
    """Перепроверить находку последнего среза по сети (только чтение, только своя подсеть) и запомнить итог.

    → [{"finding": находка, "result": present|gone|unknown, "detail"}]. Отчёт вызывающий пересобирает сам."""
    from lanmap import recheck as rc
    from lanmap import security
    from lanmap.collectors import ScanContext
    check = check.upper()
    if check not in security.BY_ID:
        raise OpError(f"Нет такой проверки: {check}. Есть: {', '.join(security.BY_ID)}")
    snap, model = latest()
    targets = _findings(model, check, target)
    net = pick_network()
    ctx = ScanContext(local_ip=net.local_ip, network=net.network, gateway=net.gateway, if_index=net.if_index,
                      local_mac=net.mac)
    probes = probes or rc.Probes(ctx)
    out = []
    for f in targets:
        res = rc.run(check, f, model, snap, ctx, probes)
        security.record_recheck(check, f["key"], res["result"], res["detail"], ips=f.get("ips"),
                                replace=f.get("status_uid"))
        out.append({"finding": f, **res})
    return out


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


# --- камеры: стоп-кадр по ONVIF ---------------------------------------------------------------

def camera_target(key: str) -> str:
    return f"camera:{key}"


def _camera_device(target: str) -> dict:
    """Устройство последнего среза по ключу, MAC или IP, если оно отвечает по ONVIF."""
    _snap, model = latest()
    mac = norm_mac(target.partition("#")[0])
    devs = model.get("devices") or []
    dev = (next((d for d in devs if d["key"] == target), None)
           or next((d for d in devs if target in (d.get("ips") or [])), None)
           or (next((d for d in devs if d["key"].partition("#")[0] == mac), None) if mac and "#" not in target else None))
    if not dev:
        raise OpError(f"В последнем срезе нет устройства «{target}»")
    facts = dev.get("facts") or {}
    if not facts.get("onvif") and not facts.get("onvif_urls"):
        raise OpError("Устройство не отвечало по ONVIF — стоп-кадр взять неоткуда")
    return dev


def _camera_address(dev: dict, probes=None) -> tuple:
    """(ScanContext, проверенный IP, адрес службы ONVIF). Пароль уходит только туда, где ARP-ответ даёт MAC
    этой камеры: заводской адрес Xiongmai держат сразу несколько камер. У MAC-двойников (ключ MAC#серийник)
    сверяется и серийный номер из анонимного ONVIF."""
    from lanmap import recheck as rc
    from lanmap.collectors import ScanContext
    net = pick_network()
    ctx = ScanContext(local_ip=net.local_ip, network=net.network, gateway=net.gateway, if_index=net.if_index,
                      local_mac=net.mac)
    probes = probes or rc.Probes(ctx)
    mac, _, serial = dev["key"].partition("#")
    urls = (dev.get("facts") or {}).get("onvif_urls") or {}
    ports = (dev.get("facts") or {}).get("ports") or []
    other = False
    for ip in dev.get("ips") or []:
        if not ctx.in_scope(ip):
            continue
        url = urls.get(ip) or (f"http://{ip}:8899/onvif/device_service" if 8899 in ports
                               else f"http://{ip}/onvif/device_service")
        now = (probes.mac(ip) or "").upper()
        if now != mac.upper():
            other = other or bool(now)
            continue
        if serial and ((probes.onvif(url).get("fields") or {}).get("SerialNumber") or "") != serial:
            other = True
            continue
        return ctx, ip, url
    if other:
        raise OpError("По адресу камеры сейчас отвечает другое устройство — пароль не отправлен. Сделай новый срез")
    raise OpError("Камера не ответила — включена ли она? Пароль не отправлен")


def _camera_snap(dev: dict, user: str, password: str, probes=None, poster=None, fetcher=None) -> bytes:
    from lanmap.collectors import onvif
    ctx, ip, url = _camera_address(dev, probes)
    try:
        return onvif.Camera(ctx, ip, url, user, password, poster, fetcher).snapshot()
    except onvif.AuthError as exc:
        raise NeedLogin(f"Камера: {exc}") from None
    except onvif.OnvifError as exc:
        raise OpError(f"Камера: {exc}") from None


def camera_status(target: str) -> dict:
    from lanmap import credentials
    dev = _camera_device(target)
    saved = credentials.load(camera_target(dev["key"]))
    return {"key": dev["key"], "login": saved[0] if saved else None}


def camera_login(target: str, username: str, password: str, **net) -> tuple[dict, bytes]:
    """Проверить логин и пароль камеры настоящим кадром и сохранить в диспетчере учётных данных Windows.
    Пароль не попадает ни в файлы, ни в ответ, ни в текст ошибки. Кадр — только в памяти."""
    from lanmap import credentials
    if not username or not password:
        raise OpError("Нужны логин и пароль камеры")
    dev = _camera_device(target)
    image = _camera_snap(dev, username, password, **net)
    credentials.save(camera_target(dev["key"]), username, password, comment=f"LanMap: камера {dev.get('title') or ''}".strip())
    return {"key": dev["key"], "login": username, "target": "LanMap:" + camera_target(dev["key"])}, image


def camera_snapshot(target: str, **net) -> bytes:
    """JPEG-кадр с сохранённым паролем владельца. Нет пароля — OpError с просьбой войти."""
    from lanmap import credentials
    dev = _camera_device(target)
    saved = credentials.load(camera_target(dev["key"]))
    if not saved:
        raise NeedLogin("Пароль камеры не сохранён: python -m lanmap camera login " + dev["key"])
    return _camera_snap(dev, *saved, **net)


def camera_forget(target: str) -> bool:
    from lanmap import credentials
    return credentials.delete(camera_target(_camera_device(target)["key"]))
