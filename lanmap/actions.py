"""Действия с устройством: строятся из того, что реально найдено. Только запуск по клику, без паролей.

На этапе статического HTML это ссылки и команды для копирования.
"""
from __future__ import annotations

WEB_HINT_PORTS = {80, 443, 5000, 5001, 8000, 8080, 8443, 8888, 9000, 10000}


def build(dev: dict) -> list[dict]:
    actions: list[dict] = []
    if not dev["ips"]:
        if dev.get("mac"):
            actions.append({"kind": "copy", "label": "MAC", "value": dev["mac"], "hint": ""})
        return actions
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
                            "hint": "Путь потока зависит от модели; часто нужен логин и пароль камеры"})
    if 445 in services or 139 in services:
        actions.append({"kind": "copy", "label": "Общие папки", "value": f"\\\\{ip}",
                        "hint": "Вставь в адресную строку Проводника"})
    if 22 in services:
        actions.append({"kind": "copy", "label": "SSH", "value": f"ssh {ip}", "hint": "Команда для терминала"})
    if 23 in services:
        actions.append({"kind": "copy", "label": "Telnet ⚠", "value": f"telnet {ip}",
                        "hint": "Незашифрованный канал: пароль идёт открытым текстом. Лучше выключить Telnet"})
    if 3389 in services:
        actions.append({"kind": "copy", "label": "Удалённый рабочий стол", "value": f"mstsc /v:{ip}", "hint": ""})
    if 5900 in services:
        actions.append({"kind": "copy", "label": "VNC", "value": f"{ip}:5900", "hint": "Адрес для VNC-клиента"})
    actions.append({"kind": "copy", "label": "IP", "value": ip, "hint": ""})
    if dev.get("mac"):
        actions.append({"kind": "copy", "label": "MAC", "value": dev["mac"], "hint": ""})
        actions.append({"kind": "copy", "label": "Команда «подписать»",
                        "value": f'python -m lanmap sign {dev["key"]} --name "…"',
                        "hint": "Подписать устройство в реестре", "static_only": True})
    return actions
