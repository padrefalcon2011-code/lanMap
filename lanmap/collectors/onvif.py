"""Стоп-кадр (GetSnapshotUri) и адрес видеопотока (GetStreamUri) с камеры по ONVIF. Только чтение,
только локальная подсеть.

Разрешены ровно пять SOAP-действий (READ_ONLY_ACTIONS); любое другое модуль откажется отправлять.
Пароль — только тот, что владелец сам сохранил в диспетчере учётных данных: заводские пароли и пустой
пароль не пробуются никогда (это был бы подбор).

Вход — WS-Security UsernameToken с PasswordDigest (пароль открытым текстом не отправляется). Время в
подписи берётся по часам камеры (GetSystemDateAndTime): у дешёвых камер часы часто сбиты, и подпись
по часам компьютера камера молча отвергает.

Адрес кадра (SnapshotUri) — секрет: камеры Xiongmai вставляют в него логин и пароль. Он не пишется
ни в срез, ни в журнал, ни в текст ошибки и не отдаётся странице. Ходим по нему только на проверенный
адрес камеры (хост из ответа заменяется на него), без переходов на другие хосты. Отдаём только JPEG.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import os
import re
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Callable
from xml.sax.saxutils import escape

from lanmap.collectors import USER_AGENT, ScanContext

DEVICE_NS = "http://www.onvif.org/ver10/device/wsdl"
MEDIA_NS = "http://www.onvif.org/ver10/media/wsdl"
READ_ONLY_ACTIONS = {"GetSystemDateAndTime": DEVICE_NS, "GetCapabilities": DEVICE_NS,
                     "GetProfiles": MEDIA_NS, "GetSnapshotUri": MEDIA_NS, "GetStreamUri": MEDIA_NS}
SCHEMA_NS = "http://www.onvif.org/ver10/schema"
WSSE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd"
WSU = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd"
DIGEST = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordDigest"
B64 = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-soap-message-security-1.0#Base64Binary"
MAX_IMAGE = 5_000_000
AUTH_FAULTS = ("NotAuthorized", "FailedAuthentication", "InvalidSecurityToken")
TIMEOUT = 5

# (url, тело, заголовки) → (HTTP-статус, тело ответа). Подменяется в тестах.
Poster = Callable[[str, bytes, dict], tuple[int, bytes]]
# (url, логин, пароль, предел байт) → (HTTP-статус, тело). Подменяется в тестах.
Fetcher = Callable[[str, str, str, int], tuple[int, bytes]]


class OnvifError(Exception):
    """Понятная ошибка. Текст никогда не содержит пароль и адрес кадра."""


class Refused(OnvifError):
    """Камера ответила, но отказала (SOAP-ошибка или HTTP-код). Не путать с молчанием."""


class AuthError(Refused):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _find(root: ET.Element, name: str) -> ET.Element | None:
    return next((el for el in root.iter() if _local(el.tag) == name), None)


def _text(root: ET.Element, name: str) -> str:
    el = _find(root, name)
    return (el.text or "").strip() if el is not None else ""


def security_header(user: str, password: str, created: dt.datetime, nonce: bytes | None = None) -> str:
    """UsernameToken: Digest = Base64(SHA1(nonce + created + password))."""
    nonce = nonce or os.urandom(16)
    stamp = created.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    digest = base64.b64encode(hashlib.sha1(nonce + stamp.encode() + password.encode("utf-8")).digest()).decode()
    return (f'<s:Header><Security s:mustUnderstand="1" xmlns="{WSSE}"><UsernameToken>'
            f'<Username>{escape(user)}</Username><Password Type="{DIGEST}">{digest}</Password>'
            f'<Nonce EncodingType="{B64}">{base64.b64encode(nonce).decode()}</Nonce>'
            f'<Created xmlns="{WSU}">{stamp}</Created></UsernameToken></Security></s:Header>')


def envelope(action: str, inner: str = "", header: str = "") -> bytes:
    if action not in READ_ONLY_ACTIONS:
        raise PermissionError(f"LanMap только читает: ONVIF-действие {action} запрещено")
    ns = READ_ONLY_ACTIONS[action]
    return (f'<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope">'
            f'{header}<s:Body><{action} xmlns="{ns}">{inner}</{action}></s:Body></s:Envelope>').encode("utf-8")


def _same_host(url: str, ip: str) -> str | None:
    """Адрес из ответа камеры, переписанный на проверенный IP (порт и путь — как у камеры). Только http."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.path and not parts.query:
        return None
    netloc = ip if parts.port is None else f"{ip}:{parts.port}"
    return urllib.parse.urlunsplit((parts.scheme, netloc, parts.path or "/", parts.query, ""))


USER_KEYS = {"user", "username", "usr", "loginuse", "account"}
PASSWORD_KEYS = {"password", "pwd", "pass", "passwd", "loginpas"}


def with_owner_creds(url: str, user: str, password: str) -> str:
    """Логин и пароль в адресе кадра (так у Xiongmai: …?user=…&password=…) — только владельца. Что камера
    вписала туда сама, не используется: это её пароль, выданный без спроса."""
    parts = urllib.parse.urlsplit(url)
    query = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if not query:
        return url
    fixed = [(k, user if k.lower() in USER_KEYS else password if k.lower() in PASSWORD_KEYS else v) for k, v in query]
    return urllib.parse.urlunsplit(parts._replace(query=urllib.parse.urlencode(fixed)))


def leaks_password(uri: str) -> bool:
    """Камера сама вписала непустой пароль в адрес кадра. Значение не читается и не сохраняется."""
    query = urllib.parse.parse_qsl(urllib.parse.urlsplit(uri).query, keep_blank_values=True)
    return any(k.lower() in PASSWORD_KEYS and v for k, v in query)


# Значение логина или пароля в адресе потока: до следующего «ключ=» или конца. Xiongmai пишет их прямо в
# пути и разделяет то «&», то «_»: …/user=admin&password=секрет&channel=1&stream=0.sdp. Ищем по всему, что
# после хоста, одной строкой: «?» и «#» внутри пароля не должны оставить его хвост в query или фрагменте.
_CRED_IN_URL = re.compile(r"(?i)(?<![a-z0-9])(" + "|".join(sorted(USER_KEYS | PASSWORD_KEYS, key=len, reverse=True))
                          + r")=(.*?)(?=[&_;/?#][a-z0-9]+=|$)")
_RTSP = re.compile(r"(?i)^(rtsps?)://([^/?#]*)(.*)$", re.S)


def rtsp_without_creds(uri: str, ip: str) -> tuple[str, bool] | None:
    """Адрес видеопотока без логина и пароля, на проверенном IP. Камера может вписать их в userinfo, в путь
    (Xiongmai) или в query — вырезаются отовсюду. (адрес, были ли там непустые логин или пароль)."""
    m = _RTSP.match(uri.strip())
    if not m:
        return None
    scheme, authority, rest = m.group(1).lower(), m.group(2), m.group(3)
    userinfo, at, hostport = authority.rpartition("@")
    try:
        port = urllib.parse.urlsplit(f"//{hostport}").port
    except ValueError:
        return None
    had = bool(at and userinfo.strip(":"))

    def blank(found: re.Match) -> str:
        nonlocal had
        had = had or bool(found.group(2))
        return found.group(1) + "="
    rest = _CRED_IN_URL.sub(blank, rest).partition("#")[0]
    if not rest.startswith("/"):
        rest = "/" + rest
    return f"{scheme}://{ip if port is None else f'{ip}:{port}'}{rest}", had


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def _post(url: str, body: bytes, headers: dict) -> tuple[int, bytes]:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect())
    try:
        with opener.open(urllib.request.Request(url, data=body, headers=headers), timeout=TIMEOUT) as resp:
            return resp.status, resp.read(1_000_000)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(1_000_000) if exc.fp else b""


def _fetch(url: str, user: str, password: str, limit: int) -> tuple[int, bytes]:
    """GET кадра. Basic/Digest — только если камера сама попросит (401); переходы запрещены."""
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, url, user, password)
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect(),
                                         urllib.request.HTTPDigestAuthHandler(mgr),
                                         urllib.request.HTTPBasicAuthHandler(mgr))
    try:
        with opener.open(urllib.request.Request(url, headers={"User-Agent": USER_AGENT}), timeout=TIMEOUT) as resp:
            return resp.status, resp.read(limit + 1)
    except urllib.error.HTTPError as exc:
        return exc.code, b""


class Camera:
    """Один разговор с камерой по проверенному адресу ip. device_url — служба устройства ONVIF."""

    def __init__(self, ctx: ScanContext, ip: str, device_url: str, user: str, password: str,
                 poster: Poster | None = None, fetcher: Fetcher | None = None):
        if not ctx.in_scope(ip):
            raise OnvifError("адрес камеры вне локальной подсети")
        url = _same_host(device_url, ip)
        if not url:
            raise OnvifError("непонятный адрес службы ONVIF")
        self.ip, self.device_url, self.user, self.password = ip, url, user, password
        self.poster, self.fetcher = poster or _post, fetcher or _fetch
        self.skew = dt.timedelta(0)
        self.sent: list[str] = []  # какие действия ушли (для тестов и журнала)

    def call(self, url: str, action: str, inner: str = "", auth: bool = True) -> ET.Element:
        header = security_header(self.user, self.password, dt.datetime.now(dt.timezone.utc) + self.skew) if auth else ""
        body = envelope(action, inner, header)
        self.sent.append(action)
        try:
            status, raw = self.poster(url, body, {
                "Content-Type": f'application/soap+xml; charset=utf-8; action="{READ_ONLY_ACTIONS[action]}/{action}"',
                "User-Agent": USER_AGENT})
        except Exception as exc:  # только имя класса: в тексте мог оказаться адрес кадра с паролем
            raise OnvifError(f"камера не ответила на {action} ({exc.__class__.__name__})") from None
        try:
            root = ET.fromstring(raw) if raw else None
        except ET.ParseError:
            root = None
        fault = _find(root, "Fault") if root is not None else None
        if status == 401 or (fault is not None and any(w in "".join(fault.itertext()) for w in AUTH_FAULTS)):
            raise AuthError("камера не приняла логин или пароль")
        if fault is not None or status != 200 or root is None:
            raise Refused(f"камера отказала в {action} (HTTP {status})")
        return root

    def sync_clock(self) -> None:
        """Сдвиг часов камеры относительно компьютера. Не ответила — считаем часы верными."""
        try:
            root = self.call(self.device_url, "GetSystemDateAndTime", auth=False)
            utc = _find(root, "UTCDateTime")
            if utc is None:
                return
            date, time = _find(utc, "Date"), _find(utc, "Time")
            cam = dt.datetime(int(_text(date, "Year")), int(_text(date, "Month")), int(_text(date, "Day")),
                              int(_text(time, "Hour")), int(_text(time, "Minute")), int(_text(time, "Second")),
                              tzinfo=dt.timezone.utc)
            self.skew = cam - dt.datetime.now(dt.timezone.utc)
        except (OnvifError, ValueError, TypeError, AttributeError):
            pass

    def media_url(self, auth: bool = True) -> str:
        """Адрес медиа-службы из GetCapabilities, на проверенном IP. Нет ответа — служба устройства."""
        try:
            root = self.call(self.device_url, "GetCapabilities", "<Category>Media</Category>", auth=auth)
        except AuthError:
            raise
        except OnvifError:
            return self.device_url
        media = _find(root, "Media")
        xaddr = _text(media, "XAddr") if media is not None else ""
        return _same_host(xaddr, self.ip) or self.device_url

    def profile(self, media: str, auth: bool = True) -> str:
        root = self.call(media, "GetProfiles", auth=auth)
        for el in root.iter():
            if _local(el.tag) == "Profiles" and el.get("token"):
                return el.get("token")
        raise OnvifError("у камеры нет профилей видео")

    def snapshot(self) -> bytes:
        """JPEG-кадр. Адрес кадра наружу не выходит."""
        self.sync_clock()
        media = self.media_url()
        token = self.profile(media)
        root = self.call(media, "GetSnapshotUri", f"<ProfileToken>{escape(token)}</ProfileToken>")
        url = _same_host(_text(root, "Uri"), self.ip)
        if not url:
            raise OnvifError("камера не дала адрес стоп-кадра")
        url = with_owner_creds(url, self.user, self.password)
        try:
            status, data = self.fetcher(url, self.user, self.password, MAX_IMAGE)
        except Exception as exc:  # только имя класса: в тексте мог оказаться адрес кадра с паролем
            raise OnvifError(f"камера не отдала кадр ({exc.__class__.__name__})") from None
        if status == 401:
            raise AuthError("камера не приняла логин или пароль для кадра")
        if status != 200:
            raise OnvifError(f"камера не отдала кадр (HTTP {status})")
        if len(data) > MAX_IMAGE:
            raise OnvifError("кадр слишком большой")
        if not data.startswith(b"\xff\xd8"):
            # Xiongmai на неверный пароль в адресе кадра отвечает 200 и текстом, а не 401
            raise AuthError("камера не отдала кадр — проверь логин и пароль")
        return data


    def stream_uri(self, auth: bool = True) -> tuple[str, bool]:
        """Адрес RTSP-потока первого профиля без логина и пароля (см. rtsp_without_creds). Сам ответ камеры
        наружу не выходит: в нём бывает её пароль."""
        if auth:
            self.sync_clock()
        media = self.media_url(auth=auth)
        token = self.profile(media, auth=auth)
        setup = (f'<StreamSetup><Stream xmlns="{SCHEMA_NS}">RTP-Unicast</Stream>'
                 f'<Transport xmlns="{SCHEMA_NS}"><Protocol>RTSP</Protocol></Transport></StreamSetup>')
        root = self.call(media, "GetStreamUri", f"{setup}<ProfileToken>{escape(token)}</ProfileToken>", auth=auth)
        clean = rtsp_without_creds(_text(root, "Uri"), self.ip)
        if not clean:
            raise OnvifError("камера не дала адрес видеопотока")
        return clean


def snapshot_leak(ctx: ScanContext, ip: str, device_url: str, poster: Poster | None = None) -> dict:
    """Без пароля спросить адрес кадра и узнать одно: вписала ли камера в него непустой пароль.
    leak: True — вписала; False — адрес без пароля не дала или пароля в нём нет; None — не ответила.
    Ни адрес, ни логин, ни пароль не сохраняются и не читаются дальше этой функции."""
    out: dict = {"ip": ip, "url": device_url, "leak": None}
    try:
        cam = Camera(ctx, ip, device_url, "", "", poster)
        media = cam.media_url(auth=False)
        token = cam.profile(media, auth=False)
        root = cam.call(media, "GetSnapshotUri", f"<ProfileToken>{escape(token)}</ProfileToken>", auth=False)
    except Refused:
        out.update(leak=False, detail="без пароля адрес кадра не даёт")
        return out
    except OnvifError as exc:
        out["detail"] = str(exc)
        return out
    uri = _text(root, "Uri")
    out["leak"] = leaks_password(uri)
    out["detail"] = ("без пароля выдаёт адрес кадра, а в нём — логин и пароль" if out["leak"]
                     else "адрес кадра без пароля выдаёт, но пароля в нём нет" if uri else "адрес кадра не дала")
    return out
