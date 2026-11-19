"""«Спросить ИИ»: обезличенный текст всего отчёта для чата с ИИ (ChatGPT, Claude и т. п.).

В отличие от «Помочь опознать» (одно устройство, `share.py`) здесь важны связи: проброс ведёт на
камеру, у камеры открыт Telnet. Поэтому личное не просто вырезается, а заменяется метками, одинаковыми
по всему тексту: устройства — У1, У2… (по порядку, шлюз первым), сегменты роутера — сеть A, B…
Адресов, MAC, имён и подписей в тексте нет совсем; MAC не хэшируется: хэш MAC подбирается перебором.

Каждый блок берёт поля по белому списку. Свободный текст программы (подробности находок, описания
UPnP-пробросов) чистится: известные адреса → метки, имена устройств → «<имя>», затем `anonymize()`.
Не берутся никогда: подписи и имена устройств, реестр (кроме подтверждённых типа/модели), причины
статусов и заметки владельца, описания статических пробросов, имя компьютера, внешний IP.
"""
from __future__ import annotations

import re
from collections import Counter

from lanmap import __version__
from lanmap import forwards as fw_mod
from lanmap import security as sec_mod
from lanmap.anonymize import anonymize
from lanmap.identify import LEVEL_NAMES
from lanmap.share import clean_value as _v
from lanmap.share import personal_names as _names

INTRO = """Ниже — срез моей домашней сети, сделанный программой LanMap {version} ({date}). LanMap только смотрит \
и ничего в сети не меняет. Данные обезличены: устройства обозначены У1, У2…, адреса, MAC-адреса, имена \
и подписи убраны.

Помоги мне разобраться:
1. Какие находки действительно опасны для домашней сети, а какие можно спокойно оставить?
2. Что исправить в первую очередь?
3. Как исправить — по шагам, для моих моделей роутера и устройств; что при этом может сломаться и как вернуть.
Если для ответа не хватает сведений — спроси, что посмотреть."""

STATUS_MARK = {"ok": "✓ выполнен", "fail": "✗ не выполнен", "owner": "? отмечает владелец", "unknown": "? нечем проверить"}
SCOPE = {"cgnat": "из сети провайдера (CGNAT): перед роутером ещё один NAT, снаружи пробросы, скорее всего, не видны",
         "private": "частный: перед роутером ещё один NAT, снаружи пробросы, скорее всего, не видны",
         "public": "публичный: пробросы видны из интернета"}


class _Labels:
    """Метки вместо устройств, адресов, имён и сегментов — одни и те же во всём тексте."""

    def __init__(self, model: dict):
        devs = model.get("devices") or []
        order = sorted(devs, key=lambda d: not d.get("is_gateway"))  # шлюз первым, дальше порядок отчёта
        self.by_key = {d["key"]: f"У{i}" for i, d in enumerate(order, 1)}
        self.by_ip = {ip: self.by_key[d["key"]] for d in devs for ip in d.get("ips") or []}
        names: set[str] = set()
        for d in devs:
            names |= _names(d)  # подписи, имена из DHCP/mDNS/NetBIOS/DNS, реестр; заголовок плитки — из них же
        hostname = (model.get("meta") or {}).get("hostname")
        if hostname:
            names.add(hostname.lower())
        # длинные первыми: «Камера у ворот 2» заменяется целиком, а не по куску «Камера у ворот»
        self.names = sorted(names, key=len, reverse=True)
        self.segments: dict[str, str] = {}

    def segment(self, name: str | None) -> str | None:
        if not name:
            return None
        if name not in self.segments:
            self.segments[name] = "сеть " + "ABCDEFGHIJKLMNOPQRSTUVWXYZ"[min(len(self.segments), 25)]
        return self.segments[name]

    def clean(self, text) -> str:
        """Свободный текст программы: адреса → метки, имена устройств → «<имя>», затем anonymize()."""
        text = _v(text)
        for ip in sorted(self.by_ip, key=len, reverse=True):
            text = re.sub(rf"(?<![\d.]){re.escape(ip)}(?![\d.])", self.by_ip[ip], text)
        for name in self.names:
            text = re.sub(re.escape(name), "<имя>", text, flags=re.I)
        return anonymize(text)


def _what(dev: dict) -> str:
    """Тип, производитель, модель — без имён устройства (правило может взять модель из DHCP-имени)."""
    ident = dev.get("identity") or {}
    names = _names(dev)
    parts = [ident.get("type_label") or "Неопознанное устройство"]
    vendor, model = (ident.get(k) for k in ("vendor", "model"))
    if vendor and model and str(model).lower().startswith(str(vendor).lower()):
        vendor = None  # «EPSON» + «EPSON L566 Series» → только модель
    for value in (vendor, model):
        if value and not any(n in str(value).lower() for n in names) and str(value) not in " ".join(parts):
            parts.append(_v(value))
    return " ".join(parts)


def _device_line(dev: dict, labels: _Labels) -> str:
    ident = dev.get("identity") or {}
    r = dev.get("router") or {}
    bits = [_what(dev)]
    firmware = ident.get("firmware")
    if firmware and not any(n in str(firmware).lower() for n in _names(dev)):
        bits.append(f"прошивка {_v(firmware)}")
    if dev.get("is_gateway"):
        bits.append("шлюз сети")
    if dev.get("is_local"):
        bits.append("компьютер, на котором запущен LanMap")
    if r.get("link") == "wifi":
        bits.append("Wi-Fi" + (f" {_v(r['band'])}" if r.get("band") else ""))
    elif r.get("link") == "wired":
        bits.append("кабель")
    seg = labels.segment(r.get("segment"))
    if seg:
        bits.append(seg)
    if len(dev.get("ips") or []) > 1:
        bits.append(f"{len(dev['ips'])} адреса с одним MAC")
    if dev.get("private_mac") or (dev.get("facts") or {}).get("private_mac"):
        bits.append("частный MAC")
    ports = [f"{s['port']}" + (f" {s['name']}" if s.get("name") else "") for s in dev.get("services") or []]
    bits.append("порты: " + ", ".join(ports) if ports else "открытых TCP-портов нет")
    conf = ident.get("confidence")
    if conf is not None:
        bits.append(f"уверенность: {LEVEL_NAMES.get(min(int(conf), 4), conf)}")
    return f"- {labels.by_key[dev['key']]} — " + "; ".join(bits)


def _network(model: dict, labels: _Labels) -> list[str]:
    meta = model.get("meta") or {}
    iface = meta.get("interface") or {}
    devs = model.get("devices") or []
    alive = [d for d in devs if d.get("alive")]
    lines = ["## Сеть"]
    lines.append(f"- подсеть /{iface['prefix']}" if iface.get("prefix") else "- подсеть: не известна")
    lines.append(f"- устройств: {len(devs)}, сейчас в сети: {len(alive)}")
    router = model.get("router")
    gw = next((d for d in devs if d.get("is_gateway")), None)
    if router:
        what = " ".join(_v(x) for x in ((router.get("kind") or "").capitalize(), router.get("model")) if x)
        lines.append(f"- роутер ({labels.by_key[gw['key']] if gw else 'шлюз'}): {what or 'модель не известна'}"
                     + (f", прошивка {_v(router['firmware'])}" if router.get("firmware") else "")
                     + "; LanMap читает его данные (клиенты, пробросы)")
    else:
        lines.append(f"- роутер ({labels.by_key[gw['key']] if gw else 'шлюз'}): "
                     + (_what(gw) if gw else "не опознан") + "; данных роутера нет, только сканирование")
    scope = (model.get("igd") or {}).get("external_scope")
    if scope in SCOPE:
        lines.append(f"- внешний адрес роутера (сам адрес убран): {SCOPE[scope]}")
    if meta.get("ports_tested"):
        lines.append(f"- проверено TCP-портов на каждом устройстве: {_v(meta['ports_tested'])}")
    return lines


def _checklist(model: dict, labels: _Labels) -> list[str]:
    cl = model.get("checklist")
    if not cl:
        return []
    lines = [f"## Порядок в сети: {cl.get('score', 0)} из {cl.get('total', 0)}"]
    for c in cl.get("criteria") or []:
        line = f"- {STATUS_MARK.get(c.get('status'), c.get('status'))} — {c.get('id')} {_v(c.get('title') or '')}"
        if c.get("why"):
            line += f": {labels.clean(c['why'])}"
        who = [labels.by_key[d["key"]] for d in c.get("devices") or [] if d.get("key") in labels.by_key]
        if who:
            line += f" ({', '.join(who)})"
        segs = [labels.segment(s) for s in c.get("segments") or []]
        if segs:
            line += f"; сети в роутере: {', '.join(segs)}"
        lines.append(line)
    return lines


def _security(model: dict, labels: _Labels, by_key: dict) -> list[str]:
    sec = model.get("security") or {}
    found = sec.get("findings") or []
    if not found:
        return ["## Находки безопасности", "- находок нет" if sec else "- проверки безопасности в срезе нет"]
    live = sum(1 for f in found if f["status"] not in sec_mod.QUIET_STATUSES)
    lines = [f"## Находки безопасности: {live} открыто, {len(found) - live} оставлено владельцем",
             "П1 — самое срочное, П4 — наименее."]
    groups: dict[str, list[dict]] = {}
    for f in found:
        groups.setdefault(f["id"], []).append(f)
    def order(item: tuple[str, list[dict]]) -> tuple:  # открытые выше оставленных, внутри — по срочности
        found_here = item[1]
        return (all(f["status"] in sec_mod.QUIET_STATUSES for f in found_here), min(f["priority"] for f in found_here))

    for cid, items in sorted(groups.items(), key=order):
        check = sec_mod.BY_ID.get(cid)
        prio = min(f["priority"] for f in items)
        lines += ["", f"### П{prio} · {_v(check.title) if check else cid} ({cid})"]
        if check:
            lines.append(f"Чем плохо: {_v(check.risk, 2000)}")
            if check.note:
                lines.append(f"Оговорка: {_v(check.note, 2000)}")
        for f in items:
            dev = by_key.get(f.get("key"))
            who = f"{labels.by_key[dev['key']]} ({_what(dev)})" if dev else "устройство вне среза"
            status = sec_mod.STATUSES.get(f["status"], f["status"])
            lines.append(f"- {who}: {labels.clean(f.get('detail') or '')} — П{f['priority']}, статус: {status}")
    skipped = sec.get("skipped") or {}
    if skipped:
        lines += ["", "Не проверено (нечем): " + "; ".join(
            f"{_v(sec_mod.BY_ID[c].title) if c in sec_mod.BY_ID else c}" for c in skipped)]
    return lines


def _forwards(model: dict, labels: _Labels) -> list[str]:
    fws = fw_mod.merged(model)
    if not fws:
        known = fw_mod.known_kinds(model)
        return ["## Пробросы портов из интернета", "- нет" if known else "- не известны: нет данных роутера и UPnP"]
    lines = ["## Пробросы портов из интернета"]
    for f in fws:
        target = labels.by_ip.get(f.get("to_ip")) or "неизвестный адрес"
        kind = (f.get("kind") or "").upper()
        line = (f"- {kind}: снаружи {(f.get('protocol') or '').upper()} {_v(f.get('port') or '?')} → "
                f"{target}:{_v(f.get('to_port') or '?')}")
        if f.get("kind") == "upnp" and f.get("description"):  # описание даёт программа; у статических — владелец
            line += f", описание «{labels.clean(f['description'])}»"
        lines.append(line)
    return lines


def text(model: dict) -> str:
    labels = _Labels(model)
    devs = model.get("devices") or []
    by_key = {d["key"]: d for d in devs}
    meta = model.get("meta") or {}
    date = (meta.get("started") or "")[:10] or "дата не известна"
    out = [INTRO.format(version=__version__, date=date), ""]
    out += _network(model, labels) + [""]
    out += _checklist(model, labels) + [""] if model.get("checklist") else []
    out += _security(model, labels, by_key) + [""]
    out += _forwards(model, labels) + [""]
    alive = sorted((d for d in devs if d.get("alive")), key=lambda d: int(labels.by_key[d["key"]][1:]))
    out.append(f"## Устройства в сети: {len(alive)}")
    out += [_device_line(d, labels) for d in alive]
    off = [d for d in devs if not d.get("alive")]
    if off:
        kinds = Counter((d.get("identity") or {}).get("type_label") or "Неопознанное устройство" for d in off)
        out += ["", f"## Сейчас не в сети, известны роутеру: {len(off)}",
                "- " + ", ".join(f"{k} — {n}" for k, n in kinds.most_common())]
        mentioned = {d["key"] for d in off} & _mentioned(model)
        out += [_device_line(by_key[k], labels) for k in sorted(mentioned, key=lambda k: int(labels.by_key[k][1:]))]
    return "\n".join(out).strip() + "\n"


def _mentioned(model: dict) -> set[str]:
    """Ключи устройств, на которые ссылаются находки и чек-лист: их строки нужны и вне сети."""
    keys = {f.get("key") for f in (model.get("security") or {}).get("findings") or []}
    for c in (model.get("checklist") or {}).get("criteria") or []:
        keys |= {d.get("key") for d in c.get("devices") or []}
    return {k for k in keys if k}
