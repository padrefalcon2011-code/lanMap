"""Модули роутеров. Подключаемые; без модуля программа работает на одном сканировании.

Каждый модуль умеет: узнать свой роутер без пароля (detect), прочитать данные с паролем из
диспетчера учётных данных (collect) и перевести их в ОБЩИЙ формат (normalize). Остальная программа
работает только с общим форматом, поэтому новый роутер = один новый файл-переводчик.

Общий формат:
  {"kind", "model", "firmware",
   "clients": [{"mac", "ip", "label" (подпись владельца в роутере), "hostname" (DHCP-имя),
                "registered", "active", "segment" (домашняя/гостевая сеть), "link" (wifi/wired),
                "ssid", "band", "ap", "rssi", "txrate", "port", "speed",
                "uptime_s", "first_seen_s_ago", "last_seen_s_ago", "access", "via",
                "dhcp" (адрес получен этим MAC по DHCP; устройство за мостом аренды не имеет)}],
   "forwards": [{"kind" (upnp/static), "protocol", "port", "to_ip", "to_port", "description", "interface"}],
   "forward_kinds": ["upnp", "static"] — виды пробросов, прочитанные целиком (чтение не упало); нет ключа — все,
   "reservations": [{"mac", "ip"}] — резервации DHCP (закреплённые адреса) или None, если модуль их не читает,
   "errors": {...}}
"""
from __future__ import annotations

from lanmap import credentials
from lanmap.routers import keenetic

MODULES = {"keenetic": keenetic}


def detect(host: str) -> tuple[str, str] | None:
    """(вид модуля, модель), если для роутера по адресу host есть модуль."""
    product = keenetic.is_keenetic(host)
    if product:
        return "keenetic", product
    return None


def collect(host: str) -> dict:
    """Сырые данные роутера для среза. Без модуля или без входа — объяснение, почему данных нет."""
    found = detect(host)
    if not found:
        return {"host": host, "kind": None, "skipped": "для этого роутера пока нет модуля — работаю на сканировании"}
    kind, product = found
    module = MODULES[kind]
    if not credentials.load(module.credential_target(host)):
        return {"host": host, "kind": kind, "product": product,
                "skipped": "вход в роутер не настроен: python -m lanmap router login"}
    raw = module.collect(host)
    raw["product"] = product
    return raw


def presence(host: str):
    """Для «Найти устройство»: (функция опроса клиентов роутера, None) или (None, почему нельзя).
    Модуль может её не поддерживать — тогда работаем на одном ping."""
    found = detect(host)
    if not found:
        return None, "для роутера нет модуля"
    module = MODULES[found[0]]
    if not hasattr(module, "presence"):
        return None, "модуль роутера не умеет живой опрос"
    if not credentials.load(module.credential_target(host)):
        return None, "вход в роутер не настроен"
    try:
        return module.presence(host), None
    except Exception as exc:
        return None, f"роутер: {exc}"


def normalize(raw: dict | None) -> dict | None:
    if not raw or not raw.get("kind") or raw.get("skipped") or raw.get("errors", {}).get("login"):
        return None
    return MODULES[raw["kind"]].normalize(raw)
