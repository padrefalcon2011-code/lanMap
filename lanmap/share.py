"""«Помочь опознать»: обезличенный рассказ об одном устройстве для публичной заявки на GitHub.

Текст собирается по белому списку полей модели устройства, готовые улики (`evidence`) не берутся:
в них подписи владельца, имена экземпляров mDNS, NetBIOS, DNS, SSID и адреса. Поверх списка —
`anonymize()` на случай IP или MAC внутри разрешённой строки (баннер, заголовок).

Вывод LanMap пересчитывается без реестра (`identify.resolve(dev, None)`): в заявку идёт догадка
программы, а не подпись владельца. Значения вывода, в которых сидит имя устройства (правило может
взять модель из DHCP-имени), выбрасываются: имя идёт только под галочкой.

Имя, которое устройство само сообщает сети (DHCP, mDNS), — самая сильная улика для неопознанных
и самое личное поле («iPhone-Masha»). Поэтому оно отдельной строкой: человек сам решает галочкой.
"""
from __future__ import annotations

from lanmap import __version__, identify, oui
from lanmap.anonymize import anonymize

TXT_KEYS = ("md", "model", "ty", "usb_mfg", "usb_mdl", "mfg", "mdl", "manufacturer", "vendor", "product",
            "platform", "am", "rpmd", "fv", "firmware", "osxvers")
UPNP_KEYS = ("manufacturer", "modelName", "modelNumber", "modelDescription", "deviceType")
ONVIF_KEYS = ("Manufacturer", "Model", "FirmwareVersion")
MAX_VALUE = 160


def _v(value) -> str:
    """Одно значение: только печатные символы, без лишних пробелов, не длиннее MAX_VALUE."""
    text = "".join(ch for ch in str(value) if ch.isprintable() and ch != "�")
    text = " ".join(text.split())
    return text if len(text) <= MAX_VALUE else text[:MAX_VALUE - 1] + "…"


def _names(dev: dict) -> set[str]:
    """Все имена устройства и подписи владельца (в нижнем регистре): им не место в выводе LanMap."""
    f = dev.get("facts") or {}
    r = dev.get("router") or f.get("router") or {}
    reg = dev.get("registry") or {}
    found = [r.get("label"), r.get("hostname"), (f.get("netbios") or {}).get("computer"),
             (f.get("mdns_txt") or {}).get("fn"), *((f.get("upnp") or {}).get("friendlyName") or [])]
    found += [h.removesuffix(".local") for h in f.get("mdns_hosts", [])]
    found += list(f.get("mdns_instances", [])) + list(f.get("dns", [])) + list(f.get("router_names", []))
    found += [v for v in reg.values() if isinstance(v, str)]
    return {n.strip().lower() for n in found if n and len(n.strip()) >= 3}


def verdict(dev: dict) -> dict:
    """Вывод LanMap без реестра; производитель, модель, прошивка и система — только если в них нет имени устройства."""
    ident = identify.resolve(dev, None)
    names = _names(dev)
    for key in ("vendor", "model", "firmware", "os"):
        value = str(ident.get(key) or "").lower()
        if value and any(n in value for n in names):
            ident[key] = None
    return ident


def summary(ident: dict) -> str:
    """Что показал LanMap — для поля заявки «Что показал LanMap»."""
    return f"{ident.get('type_label') or 'Неопознанное устройство'} ({ident.get('confidence_label') or 'нет данных'})"


def text(dev: dict, ident: dict | None = None) -> str:
    i, f = ident or verdict(dev), dev.get("facts") or {}
    r = dev.get("router") or f.get("router") or {}
    lines = [f"LanMap {__version__}: {summary(i)}"]
    for key, label in (("vendor", "производитель"), ("model", "модель"), ("firmware", "прошивка"), ("os", "система")):
        if i.get(key):
            lines.append(f"- итог LanMap, {label}: {_v(i[key])}")
    if i.get("rules"):
        lines.append("- сработали правила: " + ", ".join(map(_v, i["rules"])))
    if dev.get("is_gateway"):
        lines.append("- это шлюз сети (роутер)")
    if f.get("private_mac"):
        lines.append("- MAC частный (случайный): производителя по нему не узнать")
    elif f.get("oui"):
        lines.append(f"- производитель сетевого чипа по MAC (OUI): {_v(oui.short_vendor(f['oui']))}")
    if f.get("ttl"):
        lines.append(f"- TTL: {_v(f['ttl'])}")
    if r.get("link") == "wifi":
        lines.append("- подключение: Wi-Fi" + (f" {_v(r['band'])}" if r.get("band") else ""))
    elif r.get("link") == "wired":
        lines.append("- подключение: кабель")
    if f.get("ports"):
        lines.append("- открытые TCP-порты: " + ", ".join(map(_v, f["ports"])))
    for h in f.get("http", []):
        parts = [f"Server: {_v(h['server'])}" if h.get("server") else "",
                 f"заголовок «{_v(h['title'])}»" if h.get("title") else "",
                 f"realm «{_v(h['realm'])}»" if h.get("realm") else ""]
        lines.append(f"- HTTP{'S' if h.get('tls') else ''} {_v(h.get('port'))}: {_v(h.get('status') or '')}"
                     + "".join(", " + p for p in parts if p))
    for c in f.get("tls", []):
        org = (c.get("subject") or {}).get("organizationName")
        if org:
            lines.append(f"- сертификат TLS на порту {_v(c.get('port'))}: организация {_v(org)}")
    lines += [f"- SSH: {_v(s)}" for s in f.get("ssh", [])]
    lines += [f"- RTSP: {_v(s)}" for s in f.get("rtsp", [])]
    lines += [f"- порт {_v(b.get('port'))} представился: {_v(b.get('text'))}" for b in f.get("banners", [])]
    if f.get("mdns_services"):
        lines.append("- mDNS-службы: " + ", ".join(map(_v, f["mdns_services"])))
    txt = {k: v for k, v in (f.get("mdns_txt") or {}).items() if k in TXT_KEYS and v}
    if txt:
        lines.append("- mDNS TXT: " + ", ".join(f"{k}={_v(v)}" for k, v in sorted(txt.items())))
    u = f.get("upnp") or {}
    upnp = [f"{k}={_v(u[k][0])}" for k in UPNP_KEYS if u.get(k)]
    if upnp:
        lines.append("- UPnP: " + ", ".join(upnp))
    lines += [f"- SSDP Server: {_v(s)}" for s in f.get("ssdp_server", [])]
    if f.get("wsd_types"):
        lines.append("- WS-Discovery: " + ", ".join(map(_v, f["wsd_types"])))
    o = f.get("onvif") or {}
    onvif = [f"{k}={_v(o[k])}" for k in ONVIF_KEYS if o.get(k)]
    if onvif:
        lines.append("- ONVIF без пароля: " + ", ".join(onvif))
    elif o.get("auth_required"):
        lines.append("- ONVIF: отвечает, но просит пароль")
    if (f.get("smb") or {}).get("dialect"):
        lines.append(f"- SMB: диалект {_v(f['smb']['dialect'])}")
    if len(lines) == 1:
        lines.append("- улик почти нет: устройство не отвечало на опросы")
    return anonymize("\n".join(lines))


def names_line(dev: dict) -> str:
    """Имена, которые устройство само сообщило сети (DHCP, mDNS). Пусто, если их нет. Подписи владельца — никогда."""
    f = dev.get("facts") or {}
    r = dev.get("router") or f.get("router") or {}
    names = [r.get("hostname")] + [h.removesuffix(".local") for h in f.get("mdns_hosts", [])]
    names = list(dict.fromkeys(_v(n) for n in names if n))
    return anonymize("- имя, которое устройство сообщает сети: " + ", ".join(names)) if names else ""


def payload(dev: dict) -> dict:
    """Данные для кнопки «Помочь опознать» в карточке устройства (атрибут data-share)."""
    ident = verdict(dev)
    return {"lanmap": summary(ident), "text": text(dev, ident), "names": names_line(dev)}
