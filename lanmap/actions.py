"""Действия с устройством: строятся из того, что реально найдено. Только запуск по клику, без паролей.

В файле отчёта это ссылки и команды для копирования. У действия с полем launch в веб-интерфейсе есть
кнопка запуска программы (lanmap/launch.py); kind "launch" — только кнопка, без замены в файле отчёта.
"""
from __future__ import annotations

from lanmap.util import is_private_mac

WEB_HINT_PORTS = {80, 443, 5000, 5001, 8000, 8080, 8443, 8888, 9000, 10000}
# Wake-on-LAN предлагаем тем, кто обычно его умеет: компьютерам и хранилищам
WOL_TYPES = {"computer", "nas"}
WOL_PORTS = {22, 139, 445, 3389, 5900}


def _wol(dev: dict) -> list[dict]:
    mac = dev.get("mac")
    if not mac or is_private_mac(mac):
        return []
    dev_type = ((dev.get("identity") or {}).get("type"))
    ports = {s["port"] for s in dev.get("services") or []}
    if dev_type not in WOL_TYPES and not ports & WOL_PORTS:
        return []
    return [{"kind": "launch", "launch": "wol", "label": "Разбудить",
             "hint": "Wake-on-LAN: волшебный пакет в локальную сеть. Сработает, если пробуждение по сети включено "
                     "в BIOS или настройках устройства"}]


def build(dev: dict) -> list[dict]:
    actions: list[dict] = []
    if not dev["ips"]:
        if dev.get("mac"):
            actions.append({"kind": "copy", "label": "MAC", "value": dev["mac"], "hint": ""})
        return actions + _wol(dev)
    ip = dev["ips"][0]
    seen_urls = set()
    services = {s["port"]: s for s in dev["services"]}

    web = []
    for port, svc in services.items():
        if "http" in svc or (port in WEB_HINT_PORTS and "banner" not in svc):
            tls = bool(svc.get("tls"))
            default = (tls and port == 443) or (not tls and port == 80)
            url = f"{'https' if tls else 'http'}://{ip}{'' if default else f':{port}'}/"
            title = (svc.get("http") or {}).get("title") or ""
            web.append((0 if tls else 1, port, url, title))
    for _rank, port, url, title in sorted(web):
        if url in seen_urls:
            continue
        seen_urls.add(url)
        label = "Веб-панель" + (" (HTTPS)" if url.startswith("https") else "") + (f" :{port}" if port not in (80, 443) else "")
        actions.append({"kind": "link", "label": label, "url": url, "hint": title})

    for port in (554, 8554, 10554):
        if port in services:
            actions.append({"kind": "link", "label": "Видео RTSP (VLC)", "url": f"rtsp://{ip}:{port}/",
                            "hint": "Путь потока зависит от модели; часто нужен логин и пароль камеры",
                            "launch": "vlc", "port": port})
    if 445 in services or 139 in services:
        actions.append({"kind": "copy", "label": "Общие папки", "value": f"\\\\{ip}",
                        "hint": "Вставь в адресную строку Проводника", "launch": "smb"})
    if 22 in services:
        actions.append({"kind": "copy", "label": "SSH", "value": f"ssh {ip}", "hint": "Команда для терминала",
                        "launch": "ssh"})
    if 23 in services:
        actions.append({"kind": "copy", "label": "Telnet ⚠", "value": f"telnet {ip}",
                        "hint": "Незашифрованный канал: пароль идёт открытым текстом. Лучше выключить Telnet",
                        "launch": "telnet"})
    if 3389 in services:
        actions.append({"kind": "copy", "label": "Удалённый рабочий стол", "value": f"mstsc /v:{ip}", "hint": "",
                        "launch": "rdp"})
    if 5900 in services:
        actions.append({"kind": "copy", "label": "VNC", "value": f"{ip}:5900", "hint": "Адрес для VNC-клиента"})
    actions.append({"kind": "copy", "label": "IP", "value": ip, "hint": ""})
    if dev.get("mac"):
        actions.append({"kind": "copy", "label": "MAC", "value": dev["mac"], "hint": ""})
        actions.append({"kind": "copy", "label": "Команда «подписать»",
                        "value": f'python -m lanmap sign {dev["key"]} --name "…"',
                        "hint": "Подписать устройство в реестре", "static_only": True})
    return actions + _wol(dev)
