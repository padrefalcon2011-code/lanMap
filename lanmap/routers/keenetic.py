"""Keenetic (KeeneticOS) через RCI — только чтение.

Вход: «вызов — ответ» (X-NDM-Challenge): пароль по сети не передаётся, только хэш.
Клиент умеет делать ТОЛЬКО GET-запросы к /rci/… (плюс POST /auth для входа). Любая запись
невозможна на уровне кода: метода для неё нет. Переадресации (3xx) не выполняются: иначе роутер (или кто-то
на его адресе) мог бы увести запрос — с хэшем пароля и cookie — за пределы локальной подсети.
"""
from __future__ import annotations

import hashlib
import http.cookiejar
import json
import re
import urllib.error
import urllib.request

from lanmap import credentials

USER_AGENT = "LanMap (read-only)"
FORWARD_KINDS = ("upnp", "static")  # какие пробросы модуль умеет читать (routers.normalize)

# Что читаем с роутера: имя в срезе → путь RCI. Всё — чтение (show/… и чтение конфигурации).
READS = {
    "version": "show/version",
    "system": "show/system",
    "hotspot": "show/ip/hotspot",          # клиенты: имя, IP, MAC, Wi-Fi/кабель, сигнал, время
    "known_hosts": "known/host",           # зарегистрированные владельцем устройства (подписи)
    "dhcp_bindings": "show/ip/dhcp/bindings",
    "dhcp_hosts": "ip/dhcp/host",          # резервации DHCP (чтение конфигурации): закреплённые адреса
    "associations": "show/associations",   # Wi-Fi-ассоциации
    "mws": "show/mws/member",              # mesh-узлы (если есть)
    "static_nat": "ip/static",             # пробросы портов (конфигурация)
    "upnp_redirects": "show/upnp/redirect",
    "upnp_config": "upnp",
    "interfaces": "show/interface",
}


class KeeneticError(Exception):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """3xx не выполняется, а приходит как HTTPError: запросы идут только на адрес шлюза."""

    def redirect_request(self, *args, **kwargs):
        return None


def _opener(*handlers) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(), *handlers)


def credential_target(host: str) -> str:
    return f"router:{host}"


def is_keenetic(host: str, timeout: float = 4) -> str | None:
    """Модель (X-NDM-Product), если по адресу отвечает Keenetic. Без входа."""
    opener = _opener()
    try:
        opener.open(urllib.request.Request(f"http://{host}/auth", headers={"User-Agent": USER_AGENT}), timeout=timeout)
    except urllib.error.HTTPError as exc:
        exc.close()
        if exc.headers.get("X-NDM-Challenge"):
            return exc.headers.get("X-NDM-Product") or exc.headers.get("X-NDM-Realm") or "Keenetic"
    except Exception:
        return None
    return None


class KeeneticClient:
    def __init__(self, host: str, timeout: float = 6):
        self.base = f"http://{host}"
        self.timeout = timeout
        self.jar = http.cookiejar.CookieJar()
        self.opener = _opener(urllib.request.HTTPCookieProcessor(self.jar))

    def _request(self, path: str, data: bytes | None = None):
        headers = {"User-Agent": USER_AGENT}
        if data is not None:
            headers["Content-Type"] = "application/json"
        return self.opener.open(urllib.request.Request(self.base + path, data=data, headers=headers), timeout=self.timeout)

    def login(self, username: str, password: str) -> None:
        try:
            self._request("/auth")
            return  # уже авторизованы
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code != 401:
                raise KeeneticError(f"роутер ответил HTTP {exc.code} на /auth")
            realm = exc.headers.get("X-NDM-Realm", "")
            challenge = exc.headers.get("X-NDM-Challenge", "")
        if not challenge:
            raise KeeneticError("роутер не прислал X-NDM-Challenge — это не Keenetic?")
        md5 = hashlib.md5(f"{username}:{realm}:{password}".encode()).hexdigest()
        answer = hashlib.sha256((challenge + md5).encode()).hexdigest()
        body = json.dumps({"login": username, "password": answer}).encode()
        try:
            self._request("/auth", body)
        except urllib.error.HTTPError as exc:
            exc.close()
            if exc.code == 401:
                raise KeeneticError("неверный логин или пароль") from None
            raise KeeneticError(f"вход не удался: HTTP {exc.code}") from None

    def get(self, rci_path: str):
        """Только чтение: GET /rci/<путь>."""
        try:
            with self._request("/rci/" + rci_path.lstrip("/")) as resp:
                return json.loads(resp.read().decode("utf-8", "replace") or "null")
        except urllib.error.HTTPError as exc:
            exc.close()
            raise KeeneticError(f"{rci_path}: HTTP {exc.code}") from None


def check_login(host: str, username: str, password: str) -> None:
    """Проверить логин и пароль входом в роутер (только /auth). Ошибка — KeeneticError без пароля в тексте."""
    KeeneticClient(host).login(username, password)


def connect(host: str) -> KeeneticClient:
    cred = credentials.load(credential_target(host))
    if not cred:
        raise KeeneticError("нет сохранённого входа в роутер: python -m lanmap router login")
    client = KeeneticClient(host)
    client.login(*cred)
    return client


def collect(host: str) -> dict:
    """Все чтения из READS. Ошибки отдельных путей сохраняются, а не роняют срез."""
    out: dict = {"host": host, "kind": "keenetic", "data": {}, "errors": {}}
    try:
        client = connect(host)
    except Exception as exc:
        out["errors"]["login"] = str(exc)
        return out
    for name, path in READS.items():
        try:
            out["data"][name] = client.get(path)
        except Exception as exc:
            out["errors"][name] = str(exc)
    return out


def presence(host: str):
    """Для «Найти устройство»: функция, которая читает только список клиентов (show/ip/hotspot) в общем формате.
    Вход один раз; повторный — только если роутер забыл сессию."""
    client = connect(host)

    def poll() -> list[dict]:
        nonlocal client
        try:
            data = client.get(READS["hotspot"])
        except KeeneticError as exc:
            if "HTTP 401" not in str(exc):
                raise
            client = connect(host)
            data = client.get(READS["hotspot"])
        return normalize({"data": {"hotspot": data}})["clients"]

    return poll


def _list(value):
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


_AUTO_LABEL = re.compile(r"\s+-\s+[^-]*\bnetwork\s+-\s+\d{4}-\d\d-\d\d.*$", re.I)
_MAC_LIKE = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$", re.I)


def clean_label(name: str | None) -> str | None:
    """Keenetic подписывает новые устройства как «<имя> - Home network - <дата>»: оставляем только имя.
    Если вместо имени MAC-адрес — подписи по сути нет."""
    if not name:
        return None
    name = _AUTO_LABEL.sub("", name).strip()
    return None if not name or _MAC_LIKE.match(name) else name


def normalize(raw: dict) -> dict:
    """Ответы Keenetic → общий формат модулей роутеров (см. lanmap.routers.normalize_doc)."""
    data = raw.get("data", {})
    ifaces = data.get("interfaces") or {}
    version = data.get("version") or {}

    def band(ap: str | None) -> str | None:
        if not ap:
            return None
        channel = (ifaces.get(ap.split("/")[0]) or {}).get("channel")
        try:
            return "2,4 ГГц" if int(channel) <= 14 else "5 ГГц"
        except (TypeError, ValueError):
            return None

    clients = []
    for h in _list((data.get("hotspot") or {}).get("host")):
        iface = h.get("interface") or {}
        ap = h.get("ap")
        wifi = bool(ap or h.get("ssid"))
        link = None
        if h.get("active"):
            link = "wifi" if wifi else ("wired" if h.get("port") is not None else None)
        clients.append({
            "mac": h.get("mac"),
            "ip": h.get("ip") if h.get("ip") not in (None, "", "0.0.0.0") else None,
            "label": clean_label(h.get("name")) if h.get("registered") else None,
            "hostname": h.get("hostname") or None,
            "registered": bool(h.get("registered")),
            "active": bool(h.get("active")),
            "segment": iface.get("name") or iface.get("description"),
            "link": link,
            "ssid": h.get("ssid"),
            "band": band(ap),
            "ap": ap,
            "rssi": h.get("rssi"),
            "txrate": h.get("txrate"),
            "port": h.get("port"),
            "speed": h.get("speed"),
            "uptime_s": h.get("uptime"),
            "first_seen_s_ago": h.get("first-seen"),
            "last_seen_s_ago": h.get("last-seen"),
            "access": h.get("access"),
            "via": h.get("via"),
            "dhcp": bool(h.get("dhcp")),   # адрес выдан этому MAC по DHCP (у устройства за мостом аренды нет)
        })

    forwards = []
    for e in _list((data.get("upnp_redirects") or {}).get("entry")):
        forwards.append({"kind": "upnp", "protocol": e.get("protocol"), "port": e.get("port"),
                         "to_ip": e.get("to-address"), "to_port": e.get("to-port"),
                         "description": e.get("description"), "interface": e.get("interface")})
    for e in _list(data.get("static_nat")):
        if isinstance(e, dict):
            forwards.append({"kind": "static", "protocol": e.get("protocol"), "port": e.get("port"),
                             "to_ip": e.get("to-host") or e.get("to-address"), "to_port": e.get("to-port") or e.get("port"),
                             "description": e.get("comment") or e.get("description"), "interface": e.get("interface")})
    # Резервации DHCP. В старых срезах чтения не было (или оно не удалось) — тогда None: «нечем проверить»
    reservations = None
    if "dhcp_hosts" in data and "dhcp_hosts" not in (raw.get("errors") or {}):
        reservations = [{"mac": (h.get("mac") or "").lower(), "ip": h.get("ip")}
                        for h in _list(data.get("dhcp_hosts")) if isinstance(h, dict) and h.get("mac")]
    # Виды пробросов, прочитанные целиком: чтение не упало и секция есть в срезе
    errors = raw.get("errors") or {}
    forward_kinds = [kind for kind, name in (("upnp", "upnp_redirects"), ("static", "static_nat"))
                     if name in data and name not in errors]
    return {
        "kind": "keenetic",
        "model": version.get("model") or version.get("device"),
        "firmware": version.get("title") or version.get("release"),
        "clients": clients,
        "forwards": forwards,
        "forward_kinds": forward_kinds,
        "reservations": reservations,
        "errors": raw.get("errors", {}),
    }
