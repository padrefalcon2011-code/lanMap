"""UPnP IGD: пробросы портов, которые роутер раздал по UPnP, — без пароля и без модуля роутера.

Только чтение. Разрешены ровно два SOAP-действия (READ_ONLY_ACTIONS); любое другое сборщик
откажется отправлять. AddPortMapping, DeletePortMapping и прочие изменяющие действия не отправляются
никогда.

Шлюз находится по описаниям UPnP, которые срез уже собрал (raw/upnp.json): в XML ищется служба
WANIPConnection или WANPPPConnection и её controlURL. Записи перебираются GetGenericPortMappingEntry
с индексом 0, 1, 2… до ошибки 713/714 («такой записи нет» — список кончился). Любой другой исход —
список прочитан не полностью: такие данные не считаются проверкой «чисто».
"""
from __future__ import annotations

import ipaddress
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from typing import Callable

from lanmap.collectors import USER_AGENT, ScanContext, url_target

READ_ONLY_ACTIONS = frozenset({"GetGenericPortMappingEntry", "GetExternalIPAddress"})
WAN_SERVICES = ("WANIPConnection", "WANPPPConnection")
END_OF_LIST = {"713", "714"}  # SpecifiedArrayIndexInvalid, NoSuchEntryInArray
MAX_ENTRIES = 256
TIMEOUT = 3
CGNAT = ipaddress.ip_network((0x64400000, 10))  # 100.64.0.0/10: адреса провайдера за его NAT

# Отправка POST: (url, тело, заголовки) → (HTTP-статус, тело ответа). Подменяется в тестах.
Poster = Callable[[str, bytes, dict], tuple[int, bytes]]


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child(el: ET.Element, name: str) -> str:
    for c in el:
        if _local(c.tag) == name:
            return (c.text or "").strip()
    return ""


def wan_services(body: str, desc_url: str) -> list[dict]:
    """Службы WAN*Connection из XML-описания: тип и абсолютный controlURL (с учётом URLBase)."""
    try:
        root = ET.fromstring(body.encode("utf-8") if isinstance(body, str) else body)
    except ET.ParseError:
        return []
    base = _child(root, "URLBase") or desc_url
    out = []
    for el in root.iter():
        if _local(el.tag) != "service":
            continue
        stype = _child(el, "serviceType")
        if any(f":service:{name}:" in stype for name in WAN_SERVICES) and _child(el, "controlURL"):
            try:
                control = urllib.parse.urljoin(base, _child(el, "controlURL"))
            except ValueError:  # кривой URLBase или controlURL — эту службу пропускаем
                continue
            if url_target(control):
                out.append({"service": stype, "control_url": control})
    # WANIPConnection предпочтительнее, затем по версии (2 раньше 1)
    out.sort(key=lambda s: ("WANPPPConnection" in s["service"], -int(s["service"].rsplit(":", 1)[-1] or 0)))
    return out


def envelope(service: str, action: str, args: dict | None = None) -> bytes:
    if action not in READ_ONLY_ACTIONS:
        raise PermissionError(f"LanMap только читает: действие {action} запрещено")
    inner = "".join(f"<{k}>{v}</{k}>" for k, v in (args or {}).items())
    return (f'<?xml version="1.0"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" '
            f's:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/"><s:Body>'
            f'<u:{action} xmlns:u="{service}">{inner}</u:{action}></s:Body></s:Envelope>').encode("utf-8")


def parse_response(status: int, body: bytes) -> dict:
    """Ответ SOAP → {"ok": True, "fields": {...}} или {"ok": False, "code", "description", "status"}."""
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return {"ok": False, "status": status, "code": None, "description": "ответ не XML"}
    tags = {_local(el.tag): (el.text or "").strip() for el in root.iter()}
    if status == 200 and "Fault" not in tags:
        return {"ok": True, "fields": {k: v for k, v in tags.items() if k.startswith("New")}}
    return {"ok": False, "status": status, "code": tags.get("errorCode") or None,
            "description": tags.get("errorDescription") or tags.get("faultstring") or None}


def _http_post(ctx: ScanContext) -> Poster:
    from lanmap.collectors.protocols import _opener

    def post(url: str, data: bytes, headers: dict) -> tuple[int, bytes]:
        req = urllib.request.Request(url, data=data, headers={"User-Agent": USER_AGENT, **headers}, method="POST")
        try:
            with _opener(ctx).open(req, timeout=TIMEOUT) as resp:
                return resp.status, resp.read(65536)
        except urllib.error.HTTPError as exc:  # ошибка UPnP приходит как HTTP 500 с SOAP Fault
            return exc.code, exc.read(65536)
    return post


def call(post: Poster, url: str, service: str, action: str, args: dict | None = None) -> dict:
    data = envelope(service, action, args)  # бросит PermissionError на изменяющем действии
    status, body = post(url, data, {"Content-Type": 'text/xml; charset="utf-8"', "SOAPAction": f'"{service}#{action}"'})
    return parse_response(status, body)


def read_gateway(post: Poster, ip: str, location: str, svc: dict) -> dict:
    """Опрос одной службы WAN*Connection: внешний адрес и все пробросы UPnP."""
    url, service = svc["control_url"], svc["service"]
    out = {"ip": ip, "location": location, "service": service, "control_url": url,
           "external_ip": None, "mappings": [], "complete": False, "termination": None}
    try:
        ext = call(post, url, service, "GetExternalIPAddress")
        if ext["ok"]:
            out["external_ip"] = ext["fields"].get("NewExternalIPAddress") or None
    except Exception as exc:
        out["external_error"] = f"{type(exc).__name__}: {exc}"
    for index in range(MAX_ENTRIES):
        try:
            r = call(post, url, service, "GetGenericPortMappingEntry", {"NewPortMappingIndex": index})
        except Exception as exc:
            out["termination"] = {"index": index, "error": f"{type(exc).__name__}: {exc}"}
            return out
        if not r["ok"]:
            out["termination"] = {"index": index, "status": r.get("status"), "code": r.get("code"),
                                  "description": r.get("description")}
            out["complete"] = r.get("code") in END_OF_LIST
            return out
        out["mappings"].append(r["fields"])
    out["termination"] = {"index": MAX_ENTRIES, "error": f"больше {MAX_ENTRIES} записей — дальше не читаю"}
    return out


def collect(ctx: ScanContext, descriptions: list[dict], post: Poster | None = None) -> dict:
    """Описания UPnP из среза → опрос всех найденных шлюзов IGD своей подсети."""
    post = post or _http_post(ctx)
    gateways, seen = [], set()
    for d in descriptions:
        if not d.get("body"):
            continue
        svcs = [s for s in wan_services(d["body"], d["url"]) if ctx.url_in_scope(s["control_url"])]
        if not svcs or svcs[0]["control_url"] in seen:
            continue
        seen.add(svcs[0]["control_url"])
        gateways.append(read_gateway(post, d.get("ip") or (url_target(d["url"]) or (None,))[0], d["url"], svcs[0]))
    return {"gateways": gateways}


# --- в общий формат ------------------------------------------------------------------------

def external_scope(addr: str | None) -> str | None:
    """public | cgnat | private | None (адреса нет или WAN не поднят)."""
    try:
        ip = ipaddress.ip_address(addr or "")
    except ValueError:
        return None
    if ip.is_unspecified:
        return None
    if ip in CGNAT:
        return "cgnat"
    if ip.is_private:
        return "private"
    return "public"


def _int(value) -> int | str | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return value or None


def normalize(raw: dict | None) -> dict | None:
    """raw/upnp_igd.json → {"gateways": [...], "forwards": [...] (формат как у роутеров), "complete"}.
    None — шлюзов IGD не нашлось (или срез старый, без этого файла)."""
    if not raw or not raw.get("gateways"):
        return None
    forwards, gws = [], []
    for g in raw["gateways"]:
        for m in g.get("mappings") or []:
            if str(m.get("NewEnabled", "1")) == "0":
                continue
            forwards.append({"kind": "upnp", "protocol": (m.get("NewProtocol") or "").lower(),
                             "port": _int(m.get("NewExternalPort")), "to_ip": m.get("NewInternalClient"),
                             "to_port": _int(m.get("NewInternalPort")),
                             "description": m.get("NewPortMappingDescription") or None, "source": "igd"})
        gws.append({"ip": g.get("ip"), "external_scope": external_scope(g.get("external_ip")),
                    "complete": bool(g.get("complete")), "count": len(g.get("mappings") or []),
                    "termination": g.get("termination")})
    return {"gateways": gws, "forwards": forwards, "complete": all(g["complete"] for g in gws),
            "external_scope": next((g["external_scope"] for g in gws if g["external_scope"]), None)}
