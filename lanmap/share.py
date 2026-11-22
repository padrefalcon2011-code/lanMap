"""«Помочь опознать»: обезличенный рассказ об одном устройстве для публичной заявки на GitHub.

Текст собирается по белому списку полей модели устройства, готовые улики (`evidence`) не берутся:
в них подписи владельца, имена экземпляров mDNS, NetBIOS, DNS, SSID и адреса. Поверх списка —
`anonymize()` на случай IP или MAC внутри разрешённой строки (баннер, заголовок).

Вывод LanMap пересчитывается без реестра (`identify.resolve(dev, None)`): в заявку идёт догадка
программы, а не подпись владельца. Значения вывода, в которых сидит имя устройства (правило может
взять модель из DHCP-имени), выбрасываются: имя идёт только под галочкой.

Имя, которое устройство само сообщает сети (DHCP, mDNS), — самая сильная улика для неопознанных
и самое личное поле («iPhone-Masha»). Поэтому оно отдельной строкой: человек сам решает галочкой.

Свободный текст устройства — заголовок веб-страницы, realm, организация в сертификате, баннеры портов,
описание UPnP — тоже отдельно (`raw_lines`, своя галочка, по умолчанию выключена): шаблонная очистка
ловит адреса и известные имена, но не любое имя, вписанное в заголовок. В основном тексте — только
структурные поля: модель, производитель, версии ПО, номера портов, типы служб.
"""
from __future__ import annotations

import re

from lanmap import __version__, identify, oui
from lanmap.anonymize import anonymize

TXT_KEYS = ("md", "model", "ty", "usb_mfg", "usb_mdl", "mfg", "mdl", "manufacturer", "vendor", "product",
            "platform", "am", "rpmd", "fv", "firmware", "osxvers")
UPNP_KEYS = ("manufacturer", "modelName", "modelNumber", "deviceType")
UPNP_FREE = ("modelDescription",)  # свободный текст производителя — к сырым строкам
ONVIF_KEYS = ("Manufacturer", "Model", "FirmwareVersion")
MAX_VALUE = 160


def clean_value(value, limit: int = MAX_VALUE) -> str:
    """Одно значение: только печатные символы, без лишних пробелов, не длиннее limit."""
    text = "".join(ch for ch in str(value) if ch.isprintable() and ch != "�")
    text = " ".join(text.split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


_v = clean_value


def _self_described(f: dict) -> list[str]:
    """Как устройство называет себя по стандарту (UPnP, ONVIF, mDNS TXT): модель и производитель, не имя."""
    u, o, t = f.get("upnp") or {}, f.get("onvif") or {}, f.get("mdns_txt") or {}
    texts = [v for k in ("manufacturer", "modelName", "modelNumber") for v in u.get(k) or []]
    texts += [o.get("Manufacturer"), o.get("Model"), f.get("oui")] + [t.get(k) for k in TXT_KEYS]
    return [str(x).lower() for x in texts if x]


def personal_names(dev: dict) -> set[str]:
    """Имена устройства и подписи владельца (в нижнем регистре): им не место в выводе LanMap.

    Имя, которое устройство сообщило о себе и которое целиком входит в его самоописание (принтер объявляет
    в mDNS «EPSON L566 Series» и называет себя «EPSON»), — это модель, а не личное имя: такие не считаются.
    Подписи владельца (реестр, подпись в роутере) личные всегда, даже если совпали с самоописанием.
    """
    f = dev.get("facts") or {}
    r = dev.get("router") or f.get("router") or {}
    reg = dev.get("registry") or {}
    reported = [r.get("hostname"), (f.get("netbios") or {}).get("computer"),
                (f.get("mdns_txt") or {}).get("fn"), *((f.get("upnp") or {}).get("friendlyName") or [])]
    reported += [h.removesuffix(".local") for h in f.get("mdns_hosts", [])]
    reported += list(f.get("mdns_instances", [])) + list(f.get("dns", [])) + list(f.get("router_names", []))
    owner = [r.get("label")] + [reg.get(k) for k in ("name", "place", "owner", "purpose")]  # тип, модель — не имена

    def norm(items):
        return {n.strip().lower() for n in items if isinstance(n, str) and len(n.strip()) >= 3}
    described = _self_described(f)
    return norm(owner) | {n for n in norm(reported) if not any(n in d for d in described)}


def verdict(dev: dict) -> dict:
    """Вывод LanMap без реестра; производитель, модель, прошивка и система — только если в них нет имени устройства."""
    ident = identify.resolve(dev, None)
    names = personal_names(dev)
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
        lines.append(f"- HTTP{'S' if h.get('tls') else ''} {_v(h.get('port'))}: {_v(h.get('status') or '')}"
                     + (f", Server: {_v(h['server'])}" if h.get("server") else ""))
    lines += [f"- SSH: {_v(s)}" for s in f.get("ssh", [])]
    lines += [f"- RTSP: {_v(s)}" for s in f.get("rtsp", [])]
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
    if dev.get("live_only"):
        lines.append("- замечено живым опросом после среза: порты и службы ещё не опрошены")
    elif len(lines) == 1:
        lines.append("- улик почти нет: устройство не отвечало на опросы")
    return anonymize("\n".join(lines))


def raw_lines(dev: dict) -> str:
    """Свободный текст, который устройство отдаёт о себе: заголовки страниц, realm, организация в сертификате,
    баннеры портов, описание UPnP. Хорошая улика, но в нём бывает имя или адрес, — только по галочке."""
    f = dev.get("facts") or {}
    lines = []
    for h in f.get("http", []):
        if h.get("title"):
            lines.append(f"- HTTP{'S' if h.get('tls') else ''} {_v(h.get('port'))}: заголовок «{_v(h['title'])}»")
        if h.get("realm"):
            lines.append(f"- HTTP{'S' if h.get('tls') else ''} {_v(h.get('port'))}: realm «{_v(h['realm'])}»")
    for c in f.get("tls", []):
        org = (c.get("subject") or {}).get("organizationName")
        if org:
            lines.append(f"- сертификат TLS на порту {_v(c.get('port'))}: организация {_v(org)}")
    lines += [f"- порт {_v(b.get('port'))} представился: {_v(b.get('text'))}" for b in f.get("banners", [])]
    u = f.get("upnp") or {}
    lines += [f"- UPnP {k}: {_v(u[k][0])}" for k in UPNP_FREE if u.get(k)]
    if not lines:
        return ""
    text = "\n".join(lines)
    for name in sorted(personal_names(dev), key=len, reverse=True):  # известные имена — даже в сырых строках
        text = re.sub(re.escape(name), "<имя>", text, flags=re.I)
    return anonymize("- сырые строки устройства:\n" + text)


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
    return {"lanmap": summary(ident), "text": text(dev, ident), "names": names_line(dev), "raw": raw_lines(dev)}


def evidence(p: dict, with_names: bool = False, with_raw: bool = False) -> str:
    """Улики из payload: основной текст и, по галочкам, сырые строки и имя. Так же собирает страница."""
    return p["text"] + ("\n" + p["raw"] if with_raw and p.get("raw") else "") + (
        "\n" + p["names"] if with_names and p.get("names") else "")
