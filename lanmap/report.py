"""Статический HTML-отчёт по срезу: показатели, «что изменилось», пробросы, плитки устройств.

Минимум текста: тип — иконкой, состояние — точкой, уверенность — шкалой, изменения — значками.
Подробности (факты, улики, правила) свёрнуты внутри плитки: опознание остаётся объяснимым.
Файл самодостаточный (без внешних скриптов и шрифтов) и лежит в папке среза — данные личные.
"""
from __future__ import annotations

import html
import ipaddress
import json
from collections import Counter

from lanmap import forwards as fw_mod
from lanmap import security as sec_mod
from lanmap.devices import connection_text
from lanmap.identify import GROUPS, LEVEL_NAMES, TYPES
from lanmap.report_assets import CSS, ICONS, JS

SOURCE_NAMES = {
    "registry": "реестр владельца", "upnp": "UPnP", "onvif": "ONVIF", "mdns": "mDNS", "netbios": "NetBIOS",
    "router_dns": "DNS роутера", "dns": "обратный DNS", "oui": "MAC (IEEE)", "http": "HTTP", "tls": "TLS",
    "ssh": "SSH", "rtsp": "RTSP", "ssdp": "SSDP", "wsd": "WS-Discovery", "smb": "SMB", "mac": "MAC",
    "ttl": "TTL", "banner": "баннер", "local": "система", "router": "роутер", "dhcp": "DHCP-имя",
}
FIELD_NAMES = {"type": "Тип", "vendor": "Производитель", "model": "Модель", "firmware": "Прошивка",
               "os": "ОС", "name": "Имя", "group": "Группа"}
OFFLINE_GROUP = "Сейчас не в сети (известны роутеру)"
GROUP_ICONS = {"Сеть": "router", "Компьютеры": "computer", "Хранилища": "nas", "Камеры": "camera",
               "ТВ и приставки": "tv", "Колонки": "speaker", "Печать": "printer", "Умный дом": "iot",
               "Телефоны и планшеты": "phone", "Не опознаны": "unknown", OFFLINE_GROUP: "offline"}
GROUP_SHORT = {OFFLINE_GROUP: "Не в сети"}
# Цвет группы — для узнаваемости вместе с иконкой (смысл не держится на одном цвете). Красный не берём:
# он занят под опасность.
GROUP_COLORS = {"Сеть": "#2a78d6", "Компьютеры": "#6250d6", "Хранилища": "#14a374", "Камеры": "#eb6834",
                "ТВ и приставки": "#d6457f", "Колонки": "#d99400", "Печать": "#0e94b0", "Умный дом": "#3e9a1f",
                "Телефоны и планшеты": "#8a4fd8", "Не опознаны": "#7a8290", OFFLINE_GROUP: "#5b6b82"}


def gstyle(group: str) -> str:
    return f'style="--g:{GROUP_COLORS.get(group, "#7a8290")}"'
# Порты, открытость которых — уже повод насторожиться (подробные проверки — следующий этап)
RISKY_PORTS = {23: "Telnet: пароль идёт открытым текстом", 5555: "ADB: удалённое управление Android без пароля"}
MAX_TILE_PORTS = 6


def e(value) -> str:
    return html.escape(str(value), quote=True)


def icon(name: str, cls: str = "", label: str | None = None) -> str:
    aria = f' role="img" aria-label="{e(label)}"' if label else ' aria-hidden="true"'
    title = f"<title>{e(label)}</title>" if label else ""
    return f'<svg class="i {cls}"{aria}>{title}<use href="#i-{name}"/></svg>'


def live(data: dict) -> str:
    """Данные для кнопки веб-интерфейса (python -m lanmap serve). В статическом отчёте не используются."""
    return e(json.dumps(data, ensure_ascii=False))


def tip(text: str) -> str:
    """Плавающая подсказка (CSS, работает и с клавиатуры) + подпись для экранного диктора."""
    return f'data-tip="{e(text)}" aria-label="{e(text)}"'


def type_icon(dev_type: str | None) -> str:
    return dev_type if dev_type in TYPES else "unknown"


def _source_label(source: str) -> str:
    if source.startswith("rule:"):
        return "правило " + source[5:]
    if source.startswith("registry-draft:"):
        return "черновик реестра (" + source.split(":", 1)[1] + ")"
    return SOURCE_NAMES.get(source, source)


def _short_ips(old: list[str], new: list[str]) -> tuple[str, str]:
    """«·10» вместо «192.0.2.10», если все адреса из одной /24."""
    try:
        nets = {ipaddress.ip_network(f"{ip}/24", strict=False) for ip in old + new}
    except ValueError:
        nets = set()
    if len(nets) == 1:
        return ", ".join("·" + ip.rsplit(".", 1)[1] for ip in old), ", ".join("·" + ip.rsplit(".", 1)[1] for ip in new)
    return ", ".join(old), ", ".join(new)


# --- значки изменений ------------------------------------------------------------------------

def change_chip(item: dict) -> str:
    """Одно изменение → компактный значок. Полный текст — в подсказке и для экранного диктора."""
    what, text = item["what"], e(item["text"])
    attrs = f'title="{text}" aria-label="{text}"'
    if what == "new":
        return f'<span class="pc add" {attrs}>{icon("plus", "s")}новое</span>'
    if what == "gone":
        return f'<span class="pc del" {attrs}>{icon("minus", "s")}пропало</span>'
    if what == "port_open":
        cls = "crit" if item.get("port") in RISKY_PORTS else "add"
        return f'<span class="pc {cls}" {attrs}>+{e(item["port"])}</span>'
    if what == "port_closed":
        return f'<span class="pc del" {attrs}>{icon("minus", "s")}<s>{e(item["port"])}</s></span>'
    if what == "ip":
        old, new = _short_ips(item.get("old") or [], item.get("new") or [])
        return f'<span class="pc trans" {attrs}>IP <s>{e(old)}</s>{icon("arrow", "s")}<span class="to">{e(new)}</span></span>'
    if what == "online":
        return f'<span class="pc trans" {attrs}><i class="dot off"></i>{icon("arrow", "s")}<i class="dot"></i></span>'
    if what == "offline":
        return f'<span class="pc trans del" {attrs}><i class="dot"></i>{icon("arrow", "s")}<i class="dot off"></i></span>'
    if what == "name":
        return f'<span class="pc" {attrs}>{icon("pencil", "s")}{e(item.get("new") or "")}</span>'
    if what == "firmware":
        return f'<span class="pc" {attrs}>{icon("chip", "s")}прошивка</span>'
    if what == "finding":
        return f'<span class="pc p{e(item.get("priority", 2))}" {attrs}>{icon("shield", "s")}находка</span>'
    if what == "serial":
        return f'<span class="pc warn" {attrs}>{icon("barcode", "s")}≠ серийник</span>'
    return f'<span class="pc" {attrs}>{e(item.get("short") or what)}</span>'


# --- плитка устройства -----------------------------------------------------------------------

def _connection(r: dict) -> str:
    if not r or not r.get("active"):
        return ""
    tip = connection_text(r).removeprefix("Роутер: ")
    if r.get("link") == "wifi":
        rssi = r.get("rssi")
        bars = 3 if rssi is None or rssi >= -60 else 2 if rssi >= -72 else 1
        return icon(f"wifi{bars}", "s", "Wi-Fi: " + tip)
    if r.get("link") == "wired":
        return icon("cable", "s", "Кабель: " + tip)
    return ""


def _meter(conf: int) -> str:
    conf = min(conf, 4)
    cells = "".join(f'<i class="{"f" if n < conf else ""}"></i>' for n in range(4))
    label = f"Уверенность опознания: {LEVEL_NAMES[conf]}"
    return f'<span class="meter" title="{e(label)}" role="img" aria-label="{e(label)}">{cells}</span>'


def _port_chip(s: dict, full: bool = False) -> str:
    name = s.get("name") or ""
    tip = " · ".join(x for x in (name, (s.get("http") or {}).get("title"), RISKY_PORTS.get(s["port"])) if x)
    cls = "crit" if s["port"] in RISKY_PORTS else ""
    label = f'{s["port"]}' + (f" {name}" if full and name else "")
    warn = icon("alert", "s") if s["port"] in RISKY_PORTS else ""
    return f'<span class="pc {cls}" title="{e(tip)}">{warn}{e(label)}</span>'


def _flags(dev: dict) -> str:
    out = []
    r = dev.get("router") or {}
    reg = dev.get("registry") or {}
    if reg.get("confirmed"):
        out.append(f'<span class="flag acc">{icon("check", "s", "Подписано владельцем")}</span>')
    if dev["is_local"]:
        out.append(f'<span class="flag acc">{icon("user", "s", "Этот компьютер")}</span>')
    if dev["is_gateway"]:
        out.append(f'<span class="flag acc">{icon("router", "s", "Шлюз (выход в интернет)")}</span>')
    if dev["private_mac"]:
        out.append(f'<span class="flag">{icon("shuffle", "s", "Частный (случайный) MAC телефона или ноутбука")}</span>')
    if dev.get("duplicate_mac"):
        out.append(f'<span class="flag warn">{icon("link", "s", "Общий MAC с другим устройством: мост или ретранслятор")}</span>')
    if r.get("segment") and r["segment"].lower() not in ("home", "домашняя сеть"):
        out.append(f'<span class="pc warn" title="Сегмент сети по данным роутера">{e(r["segment"])}</span>')
    if len(dev["ips"]) > 1:
        out.append(f'<span class="pc warn" title="Один MAC — несколько IP">{len(dev["ips"])} IP</span>')
    return "".join(out)


def _detail(dev: dict, found: list[dict] | None = None) -> str:
    ident, reg, r = dev["identity"], dev.get("registry") or {}, dev.get("router") or {}
    facts = [("IP", ", ".join(dev["ips"]) or "—"), ("MAC", dev["mac"] or "не получен")]
    facts += [(FIELD_NAMES[k], ident[k]) for k in ("vendor", "model", "firmware", "os") if ident.get(k)]
    if r:
        facts.append(("Подключение", connection_text(r).removeprefix("Роутер: ")))
        if r.get("hostname") and r.get("hostname") != dev["title"]:
            facts.append(("DHCP-имя", r["hostname"]))
    facts += [(label, reg[k]) for k, label in (("place", "Место"), ("owner", "Владелец"), ("purpose", "Назначение"))
              if reg.get(k)]
    facts_html = "".join(f'<span>{e(k)}</span><b class="{"mono" if k == "MAC" else ""}">{e(v)}</b>' for k, v in facts)
    ports = "".join(_port_chip(s, full=True) for s in dev["services"]) or '<span class="muted">открытых TCP-портов нет</span>'

    acts = []
    for a in dev["actions"]:
        danger = " danger" if "⚠" in a["label"] else ""
        if a["kind"] == "link":
            acts.append(f'<a class="act{danger}" href="{e(a["url"])}" target="_blank" rel="noopener" title="{e(a.get("hint", ""))}">'
                        f'{icon("open", "s")}<span class="lbl">{e(a["label"])}</span></a>')
        else:
            static = " static-only" if a.get("static_only") else ""  # в веб-интерфейсе вместо неё кнопка
            acts.append(f'<button class="act{danger}{static}" data-copy="{e(a["value"])}" title="{e(a.get("hint", "") or a["value"])}">'
                        f'{icon("copy", "s")}<span class="lbl">{e(a["label"])}</span></button>')
    if dev.get("mac"):
        pre = {"name": reg.get("name") or r.get("label") or "", "place": reg.get("place") or "",
               "owner": reg.get("owner") or ""}
        acts.insert(0, f'<button class="act live-only sign" data-sign="{live({"key": dev["key"], **pre})}" '
                       f'data-id="s|{e(dev["key"])}">{icon("pencil", "s")}<span class="lbl">Подписать</span></button>')

    chosen = "".join(
        f'<li><b>{FIELD_NAMES.get(k, k)}:</b> {e(v["value"] if k != "type" else ident["type_label"])} '
        f'<span class="src">← {e(_source_label(v["source"]))}; {e(v["why"])}</span></li>'
        for k, v in ident["chosen"].items())
    evidence = "".join(
        f'<li><span class="tag">{e(SOURCE_NAMES.get(x["source"], x["source"]))}</span> {e(x["text"])}'
        f'{(" <span class=src>(" + e(x["ip"]) + ")</span>") if x.get("ip") and len(dev["ips"]) > 1 else ""}</li>'
        for x in dev["evidence"])
    problems = "".join(f'<li class="conflict">⚠ {e(c)}</li>' for c in ident["conflicts"])
    problems += "".join(f'<li>ℹ {e(n)}</li>' for n in ident["notes"])
    if reg.get("notes"):
        problems += f'<li>📝 {e(reg["notes"])}</li>'
    why = (f'<details class="why"><summary>Почему так: {e(LEVEL_NAMES[min(ident["confidence"], 4)])}, '
           f'{len(dev["evidence"])} улик</summary>'
           f'<h4>Вывод</h4><ul>{chosen or "<li>ничего не известно</li>"}</ul>'
           f'{"<h4>Внимание</h4><ul>" + problems + "</ul>" if problems else ""}'
           f'<h4>Улики</h4><ul>{evidence or "<li>улик нет</li>"}</ul>'
           f'<p class="src">Правила: {e(", ".join(ident["rules"]) or "нет")}</p></details>')
    slines = "".join(
        f'<div class="sline"><span class="pc p{f["priority"]}">{icon("shield", "s")}П{f["priority"]}</span>'
        f'<a href="#sec-{e(f["id"])}">{e(sec_mod.BY_ID[f["id"]].title)}</a>{_status_chip(f)}</div>'
        for f in found or [])
    return (f'<div class="tdetail" hidden><div class="dgrid"><div class="facts">{facts_html}</div>'
            f'<div class="ports">{ports}</div></div>{slines}<div class="acts">{"".join(acts)}</div>{why}</div>')


def _sec_chip(found: list[dict]) -> str:
    """Один значок на плитке: самый высокий приоритет среди открытых находок устройства и их число."""
    live = [f for f in found if f["status"] not in sec_mod.QUIET_STATUSES]
    if not live:
        return ""
    top = min(f["priority"] for f in live)
    names = "; ".join(sec_mod.BY_ID[f["id"]].title for f in live)
    more = f"·{len(live)}" if len(live) > 1 else ""
    return f'<span class="pc p{top}" title="{e("Находки: " + names)}">{icon("shield", "s")}П{top}{more}</span>'


def _tile(dev: dict, changes: dict | None, found: list[dict] | None = None) -> str:
    ident = dev["identity"]
    conf = ident["confidence"]
    found = found or []
    items = ((changes or {}).get("by_key") or {}).get(dev["key"]) or []
    risky = any(s["port"] in RISKY_PORTS for s in dev["services"]) or any(
        f["priority"] <= 2 and f["status"] not in sec_mod.QUIET_STATUSES for f in found)
    status = "on" if dev["alive"] else "off"
    dot_label = "в сети" if dev["alive"] else "не отвечало"

    ports = dev["services"]
    shown = sorted(ports, key=lambda s: (s["port"] not in RISKY_PORTS, s["port"]))[:MAX_TILE_PORTS]
    port_chips = "".join(_port_chip(s) for s in shown)
    if len(ports) > MAX_TILE_PORTS:
        port_chips += f'<span class="pc" title="ещё портов">+{len(ports) - MAX_TILE_PORTS}</span>'
    chg = "".join(change_chip(x) for x in items)
    marks = (f'{_sec_chip(found)}{chg}{port_chips}{_flags(dev)}')

    search = " ".join([dev["title"], dev["subtitle"], " ".join(dev["ips"]), dev["mac"] or "", ident["type_label"],
                       ident.get("vendor") or "", ident.get("model") or "",
                       " ".join(str(s["port"]) + " " + (s.get("name") or "") for s in dev["services"])]).lower()
    cls = " ".join(x for x in ("tile", "off" if not dev["alive"] else "", "changed" if items else "",
                               "risky" if risky else "") if x)
    ip = ", ".join(dev["ips"]) or (dev["mac"] or "")
    return (f'<article class="{cls}" id="d-{e(dev["key"])}" data-group="{e(ident["group"])}" data-status="{status}" '
            f'data-conf="{conf}" data-changed="{1 if items else 0}" data-search="{e(search)}">'
            f'<button class="thead" aria-expanded="false">'
            f'<span class="ticon" {gstyle(ident["group"])}>{icon(type_icon(ident["type"]), "", ident["type_label"])}'
            f'<i class="dot {"" if dev["alive"] else "off"}" title="{dot_label}"></i></span>'
            f'<span class="tmain"><b>{e(dev["title"])}</b>'
            f'{"<span class=sub>" + e(dev["subtitle"]) + "</span>" if dev["subtitle"] else ""}'
            f'<span class="ip mono">{e(ip)}</span></span>'
            f'<span class="tside">{_meter(conf)}{_connection(dev.get("router") or {})}</span>'
            f'<span class="tmarks">{marks}</span></button>'
            f'{_detail(dev, found)}</article>')


# --- панели ----------------------------------------------------------------------------------

def _who(d: dict, present: set[str]) -> str:
    """Имя устройства с иконкой; если оно есть в этом срезе — кнопка перехода к плитке."""
    color = GROUP_COLORS.get(GROUPS.get(type_icon(d.get("type")), ""), "inherit")
    inner = f'<span style="color:{color};display:inline-flex">{icon(type_icon(d.get("type")))}</span>{e(d["title"])}'
    if d["key"] in present:
        return f'<button class="who" data-goto="{e(d["key"])}" title="Показать плитку">{inner}</button>'
    return f'<span class="who">{inner}</span>'


def _fw_row(f: dict, by_ip: dict, present: set[str], chip: str = "") -> str:
    dev = by_ip.get(f.get("to_ip"))
    target = (_who({"key": dev["key"], "title": dev["title"], "type": dev["identity"]["type"]}, present)
              if dev else f'<span class="who">{icon("unknown", "s")}{e(f.get("to_ip") or "?")}</span>')
    proto = (f.get("protocol") or "").upper()
    kind = (f.get("kind") or "").upper()
    return (f'<div class="door">{chip}<span class="src" title="{e(kind)}: порт снаружи">{icon("globe")}'
            f'{e(proto)} {e(f.get("port") or "")}</span><span class="arr">{icon("arrow")}</span>{target}'
            f'<span class="mono muted">{e(f.get("to_ip") or "")}:{e(f.get("to_port") or "")}</span>'
            f'{"<span class=desc>" + e(f["description"]) + "</span>" if f.get("description") else ""}</div>')


def _changes(model: dict) -> str:
    """Панель «Что изменилось с прошлого среза»."""
    c = model.get("changes")
    if not c:
        return ""
    if c.get("error"):
        return f'<div class="note">{icon("alert", "s")}{e(c["error"])}</div>'
    devs = model["devices"]
    present = {d["key"] for d in devs}
    by_ip = {ip: d for d in devs for ip in d["ips"]}
    when = (c.get("baseline_started") or "")[:16].replace("T", " ") or c.get("baseline")
    p = c.get("private") or {}

    def cnt(n: int, cls: str, ico: str, label: str) -> str:
        return (f'<span class="cnt {cls}{" zero" if not n else ""}" title="{e(label)}" aria-label="{e(label)}: {n}">'
                f'{icon(ico, "s")}{n}</span>')

    counters = (cnt(len(c["new"]), "add", "plus", "Новые устройства") + cnt(len(c["gone"]), "del", "minus", "Пропали")
                + cnt(len(c["changed"]), "", "delta", "Изменились")
                + cnt(len(c["online"]), "", "arrow", "Снова в сети"))
    if c["forwards_added"]:
        counters += cnt(len(c["forwards_added"]), "crit", "globe", "Новые пробросы из интернета")
    if c.get("findings_added"):
        counters += cnt(len(c["findings_added"]), "crit", "shield", "Новые находки безопасности")
    cl = c.get("checklist")
    if cl and cl["old"] != cl["new"]:
        counters += (f'<span class="cnt {"add" if cl["new"] > cl["old"] else "crit"}" title="Порядок в сети: было '
                     f'{cl["old"]}, стало {cl["new"]}">{icon("check", "s")}{cl["old"]}{icon("arrow", "s")}{cl["new"]}</span>')
    head = (f'<summary><h2>{icon("delta")}Изменения</h2><span class="muted">с {e(when)}</span>'
            f'<span class="counters">{counters}</span>{icon("chevron", "chev")}</summary>')
    notes = "".join(f'<div class="note">{icon("info", "s")}<span>{e(n)}</span></div>' for n in c.get("notes") or [])
    if not c.get("total"):
        return (f'<details class="panel" id="changes">{head}<div class="panel-body">'
                f'<div class="note">{icon("check", "s")}Ничего заметного не изменилось.</div>{notes}</div></details>')

    parts = []

    def group(title: str, rows: list[str]) -> None:
        if rows:
            parts.append(f'<div class="cgroup"><h3>{e(title)}</h3>{"".join(rows)}</div>')

    def row(d: dict, chips: str, cls: str = "") -> str:
        ip = f'<span class="ip mono">{e(", ".join(d["ips"]))}</span>' if d.get("ips") else ""
        return f'<div class="crow {cls}">{_who(d, present)}{ip}{chips}</div>'

    group("Новые пробросы из интернета",
          [_fw_row(f, by_ip, present, f'<span class="pc crit">{icon("plus", "s")}</span>') for f in c["forwards_added"]])
    def frow(f: dict, gone: bool = False) -> str:
        chip = (f'<span class="pc del">{icon("check", "s")}нет</span>' if gone else
                f'<span class="pc p{f["priority"]}">{icon("shield", "s")}П{f["priority"]}</span>')
        return row(f, f'{chip}<span>{e(sec_mod.BY_ID[f["id"]].title)}</span>')

    if cl:
        crit = sec_mod.CRITERIA
        group("Порядок в сети",
              [f'<div class="crow"><span class="pc add">{icon("check", "s")}{e(k)}</span><span>выполнен: {e(crit[k])}</span></div>'
               for k in cl["better"]]
              + [f'<div class="crow"><span class="pc crit">{icon("alert", "s")}{e(k)}</span><span>снова не выполнен: '
                 f'{e(crit[k])}</span></div>' for k in cl["worse"]])
    group("Новые находки безопасности", [frow(f) for f in c.get("findings_added") or []])
    group("Находок больше нет", [frow(f, True) for f in c.get("findings_removed") or []])
    group("Новые устройства", [row(d, change_chip({"what": "new", "text": "в прошлом срезе этого устройства не было"}))
                               for d in c["new"]])
    group("Изменились", [row(d, "".join(change_chip(x) for x in d["items"])) for d in c["changed"]])
    group("Пропали", [row(d, change_chip({"what": "gone", "text": "в этом срезе устройства нет"}), "gone") for d in c["gone"]])
    group("Закрытые пробросы",
          [_fw_row(f, by_ip, present, f'<span class="pc del">{icon("minus", "s")}</span>') for f in c["forwards_removed"]])
    group("Роутер", [f'<div class="crow">{icon("router", "s")}<span>{e(t)}</span></div>' for t in c["router"]])
    offline_title = "Вышли из сети (роутер их помнит)" if c.get("has_router") else "Не ответили в этот раз"
    group(offline_title, [row(d, change_chip({"what": "offline", "text": "в прошлый раз отвечало, сейчас нет"}))
                          for d in c["offline"]])
    group("Снова в сети", [row(d, change_chip({"what": "online", "text": "в прошлый раз не отвечало, сейчас в сети"}))
                           for d in c["online"]])
    if p.get("new") or p.get("gone"):
        parts.append(f'<div class="note">{icon("shuffle", "s")}<span>Случайный MAC: '
                     f'+{p.get("new", 0)} / −{p.get("gone", 0)}. Телефоны меняют такой MAC, поштучно не сравниваются.</span></div>')
    return (f'<details class="panel" id="changes" open>{head}<div class="panel-body">{notes}{"".join(parts)}</div></details>')


# --- порядок в сети (чек-лист E1–E9) ------------------------------------------------------------

CRIT_ICONS = {"E1": "barcode", "E2": "globe", "E3": "grid", "E4": "lock", "E5": "power", "E6": "chip",
              "E7": "bot", "E8": "folder", "E9": "link"}
# Исход критерия: (иконка, класс, подсказка)
CRIT_STATES = {"ok": ("check", "ok", "выполнен"), "fail": ("x", "no", "не выполнен"),
               "owner": ("pencil", "own", "отмечаешь ты"), "unknown": ("question", "unk", "нечем проверить")}


def _crit_row(c: dict, present: set[str]) -> str:
    ico, cls, label = CRIT_STATES[c["status"]]
    if c["status"] == "fail" and c.get("likely"):
        label += " (вероятно)"
    bar = ""
    if c.get("total"):
        share = round(100 * c["done"] / c["total"])
        bar = (f'<span class="mini" title="{c["done"]} из {c["total"]}"><i style="width:{share}%"></i></span>'
               f'<span class="frac">{c["done"]}/{c["total"]}</span>')
    body = []
    for g in c.get("findings") or []:
        if g["open"]:
            body.append(f'<a class="pc p{g["priority"]}" href="#sec-{e(g["id"])}" title="К карточке находки">'
                        f'{icon("shield", "s")}П{g["priority"]} · {e(g["title"])}{" ×" + str(g["open"]) if g["open"] > 1 else ""}</a>')
        if g["quiet"]:
            body.append(f'<a class="pc" href="#sec-{e(g["id"])}">{icon("check", "s")}оставлено осознанно · '
                        f'{e(g["title"])}{" ×" + str(g["quiet"]) if g["quiet"] > 1 else ""}</a>')
    devs = c.get("devices") or []
    if devs:
        lead = {"E1": "Незнакомые", "E3": "Камеры и умный дом", "E9": "Без закреплённого адреса"}.get(c["id"], "")
        body.append(f'<div class="edevs"><span class="lbl2">{e(lead)}</span>{"".join(_who(d, present) for d in devs)}</div>')
    if c.get("near"):
        body.append(f'<div class="edevs"><span class="lbl2">в одной сети с ними</span>'
                    f'{"".join(_who(d, present) for d in c["near"])}</div>')
    if c.get("unseen"):
        body.append(f'<div class="enote">{icon("question", "s")}<span>Ещё '
                    f'{plural(c["unseen"], ("устройство", "устройства", "устройств"))}: роутер не сообщил их сеть, '
                    f'проверить нечем.</span></div>')
    hint = {"E1": "Подпиши в роутере или командой python -m lanmap sign <IP> --name «…».",
            "E3": "Камеры и умный дом — в гостевую или отдельную сеть, чтобы из них не было пути к ПК и NAS. "
                  "Изоляцию гостевой сети срез не проверяет.",
            "E9": "На роутере закрепи за ними адреса (резервация DHCP). Если адрес задан на самом устройстве "
                  "вручную, LanMap этого не видит."}.get(c["id"]) if c["status"] == "fail" else None
    if c["status"] in ("owner", "unknown") or c["id"] in ("E6", "E8"):
        hint = c["why"]
    if hint:
        body.append(f'<div class="enote">{icon("info", "s")}<span>{e(hint)}</span></div>')
    if c.get("mark"):
        when = (c["mark"].get("updated") or "")[:10]
        note = f' — {c["mark"]["note"]}' if c["mark"].get("note") else ""
        body.append(f'<div class="enote">{icon("check", "s")}<span>Отмечено {e(when)}{e(note)}</span></div>')
    if c["id"] in ("E6", "E8"):
        cmd = (f'python -m lanmap check set {c["id"]} open' if c["status"] == "ok"
               else f'python -m lanmap check set {c["id"]} done --note "…"')
        mark = {"code": c["id"], "done": c["status"] == "ok", "note": (c.get("mark") or {}).get("note") or ""}
        body.append(f'<div class="cli" data-mark="{live(mark)}" data-id="c|{e(c["id"])}">'
                    f'{"Снять отметку" if c["status"] == "ok" else "Отметить"}: <code>{e(cmd)}</code>'
                    f'<button class="act" data-copy="{e(cmd)}" title="Скопировать команду">{icon("copy", "s")}'
                    f'<span class="lbl">копировать</span></button></div>')
    if c.get("skipped"):
        body.append(f'<div class="enote">{icon("question", "s")}<span>Не проверялось: '
                    f'{e("; ".join(s.lower() for s in c["skipped"]))}</span></div>')
    return (f'<details class="erow {cls}"><summary><span class="est {cls}" title="{e(label)}" aria-label="{e(label)}">'
            f'{icon(ico)}</span><span class="ecode">{e(c["id"])}</span>'
            f'<span class="eico">{icon(CRIT_ICONS.get(c["id"], "info"))}</span><span class="etitle">{e(c["title"][:1].upper() + c["title"][1:])}</span>'
            f'{bar}{icon("chevron", "s chev")}</summary><div class="ebody">{"".join(body)}</div></details>')


def _checklist(model: dict) -> str:
    """Панель «Порядок в сети: X из 9»: строка на критерий, по нажатию — что мешает."""
    cl = model.get("checklist")
    if not cl:
        return ""
    present = {d["key"] for d in model["devices"]}
    share = round(100 * cl["score"] / cl["total"]) if cl["total"] else 0
    diff = (model.get("changes") or {}).get("checklist")
    was = ""
    if diff and diff["old"] != diff["new"]:
        up = diff["new"] > diff["old"]
        was = (f'<span class="cnt {"add" if up else "crit"}" title="С прошлого среза">'
               f'{icon("arrow" if up else "alert", "s")}было {diff["old"]}</span>')
    n = Counter(c["status"] for c in cl["criteria"])
    legend = "".join(f'<span class="est {CRIT_STATES[k][1]} sm" title="{e(CRIT_STATES[k][2])}">{icon(CRIT_STATES[k][0])}</span>'
                     f'<span class="muted">{n[k]}</span>' for k in ("ok", "fail", "owner", "unknown") if n[k])
    head = (f'<summary><h2>{icon("check")}Порядок в сети</h2><span class="score"><b>{cl["score"]}</b> из {cl["total"]}</span>'
            f'<span class="sbar" title="{cl["score"]} из {cl["total"]} критериев"><i style="width:{share}%"></i></span>'
            f'{was}<span class="counters">{legend}</span>{icon("chevron", "chev")}</summary>')
    rows = "".join(_crit_row(c, present) for c in cl["criteria"])
    return f'<details class="panel" id="order" open>{head}<div class="panel-body erows">{rows}</div></details>'


# --- безопасность ----------------------------------------------------------------------------

WHO_ICONS = {"internet": "globe", "lan": "home"}
STAKE_ICONS = {"files": "folder", "video": "eye", "network": "router", "device": "chip", "passwords": "key"}
CONF_ICONS = {"confirmed": "check", "likely": "question", "verify": "search"}
STATUS_CHIPS = {
    "in_progress": ("wrench", "в работе", ""),
    "fixed_pending": ("check", "отмечена исправленной, ждёт нового среза", "good"),
    "regress": ("alert", "исправляли, но вернулась", "crit"),
    "accepted": ("check", "принята осознанно", ""),
    "na": ("minus", "не применимо", ""),
}


# Оговорка к UPnP-карточке по внешнему адресу роутера (его сообщает сам роутер по UPnP)
REACH_NOTES = {
    "public": "Внешний адрес роутера — настоящий, из интернета: двери, скорее всего, видны снаружи. "
              "Сам вход снаружи LanMap не проверял.",
    "cgnat": "Внешний адрес роутера — из сети провайдера (CGNAT): перед роутером ещё один NAT, и снаружи эти двери, "
             "скорее всего, не видны. Но провайдер может выдать «белый» адрес — и они откроются.",
    "private": "Внешний адрес роутера — частный: перед ним ещё один NAT (провайдер или второй роутер), снаружи двери, "
               "скорее всего, не видны. Если наверху тоже включён UPnP — могут открыться и там.",
}


def _status_chip(f: dict) -> str:
    if f["status"] not in STATUS_CHIPS:
        return ""
    ico, text, cls = STATUS_CHIPS[f["status"]]
    reason = f' — {f["reason"]}' if f.get("reason") else ""
    via = STATUS_VIA.get(f.get("status_via") or "")
    if via:
        reason += f" (отметка найдена {via}: ключ устройства сменился)"
    return f'<span class="st {cls}" title="{e(text + reason)}">{icon(ico, "s")}{e(text)}</span>'


STATUS_VIA = {"ip": "по адресу", "serial": "по серийному номеру", "mac": "по MAC"}


def plural(n: int, forms: tuple[str, str, str]) -> str:
    """1 дверь, 2 двери, 5 дверей."""
    k = 0 if n % 10 == 1 and n % 100 != 11 else 1 if 2 <= n % 10 <= 4 and not 12 <= n % 100 <= 14 else 2
    return f"{n} {forms[k]}"


def _dev_node(items: list[dict], sub: str) -> str:
    """Узел схемы «устройства находки»: до трёх — по именам, больше — числом."""
    types = {type_icon(f.get("type")) for f in items}
    ico = types.pop() if len(types) == 1 else "devices"
    color = GROUP_COLORS.get(GROUPS.get(ico, ""), "var(--accent)") if ico != "devices" else "var(--accent)"
    names = (", ".join(f["title"] for f in items) if len(items) <= 3
             else plural(len(items), ("устройство", "устройства", "устройств")))
    return (f'<div class="sn dev" style="--g:{color}"><span class="snc">{icon(ico)}</span><b>{e(names)}</b>'
            f'{"<small>" + e(sub) + "</small>" if sub else ""}</div>')


def _scheme(check, items: list[dict]) -> str:
    """Схема «кто → куда»: узлы и подписанные стрелки."""
    if not check.scheme:
        return ""
    n_fw = sum(len(f.get("forwards") or []) for f in items)
    parts = []
    for i, (ico, label, sub, tone) in enumerate(check.scheme):
        if i:
            text, way = check.links[i - 1] if i - 1 < len(check.links) else ("", "r")
            text = text.replace("{forwards}", plural(n_fw, ("дверь", "двери", "дверей")) if n_fw else "двери")
            parts.append(f'<div class="sl {way} {tone or check.scheme[i - 1][3]}"><small>{e(text)}</small>'
                         f'{icon("arrow")}</div>')
        if ico == "@dev":
            parts.append(_dev_node(items, sub))
        else:
            parts.append(f'<div class="sn {tone}"><span class="snc">{icon(ico)}</span><b>{e(label)}</b>'
                         f'{"<small>" + e(sub) + "</small>" if sub else ""}</div>')
    return f'<div class="scheme" role="img" aria-label="{e(check.risk)}">{"".join(parts)}</div>'


def _dev_row(check, f: dict, present: set[str], rvendor: str | None) -> str:
    """Устройство находки: строка, по нажатию — инструкция именно для него и команда отметки."""
    conf = (f'<span class="conf {f["confidence"]}" title="Степень подтверждения">'
            f'{e(sec_mod.CONFIDENCE_NAMES[f["confidence"]])}</span>')
    ip = f'<span class="ip mono">{e(", ".join(f["ips"]))}</span>' if f.get("ips") else ""
    color = GROUP_COLORS.get(GROUPS.get(type_icon(f.get("type")), ""), "inherit")
    goto = (f'<button class="act goto" data-goto="{e(f["key"])}" title="Показать плитку устройства">'
            f'{icon("open", "s")}</button>' if f["key"] in present else "")
    steps, exact, rname = sec_mod.device_steps(check, f, rvendor)
    ol = "".join(f"<li>{e(s)}</li>" for s in steps) + f'<li class="vfy">{e(check.verify)}</li>'
    kind = (f'<span class="vend">{icon("check", "s")}под {e(f.get("vendor") or "это устройство")}</span>' if exact
            else f'<span class="vend gen">{icon("info", "s")}общая инструкция: названия пунктов у разных '
                 f'производителей отличаются</span>')
    if rname:
        kind += f'<span class="vend">{icon("check", "s")}роутер — под {e(rname.capitalize())}</span>'
    target = f["ips"][0] if f.get("ips") else f["key"]
    cmd = f'python -m lanmap finding set {check.id} {target} accepted --reason "…"'
    quiet = " quiet" if f["status"] in sec_mod.QUIET_STATUSES else ""
    now = {"fixed_pending": "fixed", "regress": "open"}.get(f["status"], f["status"])
    mark = {"check": check.id, "key": f["key"], "status": now, "reason": f.get("reason") or ""}
    return (f'<details class="drow{quiet}"><summary>{icon("chevron", "s chev")}'
            f'<span class="who"><span style="color:{color};display:inline-flex">{icon(type_icon(f.get("type")))}</span>'
            f'{e(f["title"])}</span>{ip}<span class="det">{e(f["detail"])}</span>{conf}{_status_chip(f)}{goto}</summary>'
            f'<div class="dbody">{kind}<ol>{ol}</ol>'
            f'<div class="cli" data-finding="{live(mark)}" data-id="f|{e(check.id)}|{e(f["key"])}">'
            f'Отметить (in_progress, fixed, accepted — оставляю осознанно): <code>{e(cmd)}</code>'
            f'<button class="act" data-copy="{e(cmd)}" title="Скопировать команду">{icon("copy", "s")}'
            f'<span class="lbl">копировать</span></button></div></div></details>')


def _finding_card(check, items: list[dict], present: set[str], rvendor: str | None) -> str:
    """Карточка проверки в виде инфографики: схема, чем грозит, план, устройства с инструкциями."""
    live = [f for f in items if f["status"] not in sec_mod.QUIET_STATUSES]
    prio = min(f["priority"] for f in (live or items))
    who = (f'<span class="facet {"net" if check.who == "internet" else ""}" '
           f'{tip("Кто может воспользоваться: " + sec_mod.WHO_NAMES[check.who])}>{icon(WHO_ICONS[check.who])}</span>')
    stakes = "".join(f'<span class="facet" {tip("Под угрозой: " + sec_mod.STAKE_NAMES[x])}>'
                     f'{icon(STAKE_ICONS[x])}</span>' for x in check.stake)

    threat = f'<span class="tarr">{icon("arrow", "s")}</span>'.join(
        f'<span class="tch">{icon(ico)}{e(text)}</span>' for ico, text in check.threat)
    types = {type_icon(f.get("type")) for f in items}
    dev_ico = types.pop() if len(types) == 1 else "devices"
    todo = "".join(f'<li><span class="nm">{i}</span>{icon(dev_ico if ico == "@dev" else ico)}<span>{e(text)}</span></li>'
                   for i, (ico, text) in enumerate(check.todo, 1))
    rows = "".join(_dev_row(check, f, present, rvendor) for f in items)
    more = (f'<details class="more"><summary>{icon("info", "s")}Подробнее</summary><p class="frisk">{e(check.risk)}</p>'
            f'<div class="hgrid"><div class="hbox"><b>{icon("alert", "s")}Что может сломаться</b>{e(check.breaks)}</div>'
            f'<div class="hbox"><b>{icon("undo", "s")}Как вернуть</b>{e(check.rollback)}</div>'
            f'<div class="hbox"><b>{icon("check", "s")}Как убедиться</b>{e(check.verify)}</div></div></details>')
    note_text = REACH_NOTES.get(next((f.get("reach") for f in items if f.get("reach")), None), check.note)
    note = f'<div class="fnote">{icon("info", "s")}<span>{e(note_text)}</span></div>' if note_text else ""
    return (f'<article class="scard p{prio}{" quiet" if not live else ""}" id="sec-{e(check.id)}">'
            f'<div class="fhead"><span class="fico">{icon(check.icon)}</span><h3>{e(check.title)}</h3>'
            f'<span class="prio">{icon("alert", "s")}{e(sec_mod.PRIORITY_NAMES[prio])}</span>'
            f'<span class="facets">{who}<i class="sep"></i>{stakes}</span></div>'
            f'{_scheme(check, items)}'
            f'{"<div class=threat><span class=lbl2>Чем грозит</span>" + threat + "</div>" if threat else ""}'
            f'{"<ol class=todo>" + todo + "</ol>" if todo else ""}'
            f'<div class="fobjs"><span class="lbl2">{icon("wrench", "s")}Где что нажать — открой устройство</span>{rows}</div>'
            f'{note}{more}</article>')


def _security(model: dict) -> str:
    """Панель «Безопасность»: карточка на проверку, внутри — устройства, риск и свёрнутая инструкция."""
    sec = model.get("security")
    if not sec:
        return ""
    present = {d["key"] for d in model["devices"]}
    by_check: dict[str, list[dict]] = {}
    for f in sec["findings"]:
        by_check.setdefault(f["id"], []).append(f)
    live = sec_mod.open_findings(sec)

    def cnt(p: int) -> str:
        n = sum(1 for f in live if f["priority"] == p)
        label = sec_mod.PRIORITY_NAMES[p]
        return (f'<span class="cnt p{p}{" zero" if not n else ""}" title="{e(label)}" aria-label="{e(label)}: {n}">'
                f'{icon("shield", "s")}П{p} · {n}</span>')

    regress = sum(1 for f in sec["findings"] if f["status"] == "regress")
    counters = cnt(1) + cnt(2) + cnt(3)
    if regress:
        counters += f'<span class="cnt crit" title="Исправленное вернулось">{icon("alert", "s")}вернулось · {regress}</span>'
    top = min((f["priority"] for f in live), default=0)
    head = (f'<summary><h2>{icon("shield")}Безопасность</h2><span class="counters">{counters}</span>'
            f'{icon("chevron", "chev")}</summary>')

    def order(cid: str) -> tuple:
        items = by_check[cid]
        quiet = all(f["status"] in sec_mod.QUIET_STATUSES for f in items)
        return quiet, min(f["priority"] for f in items), list(sec_mod.BY_ID).index(cid)

    rvendor = sec_mod.router_vendor(model)
    cards = "".join(_finding_card(sec_mod.BY_ID[cid], by_check[cid], present, rvendor)
                    for cid in sorted(by_check, key=order))
    if not live:
        cards = f'<div class="ok-big">{icon("check", "l")}Открытых находок нет.</div>' + cards
    skipped = "".join(
        f'<div class="note">{icon("info", "s")}<span>Не проверялось: {e(sec_mod.BY_ID[cid].title.lower())} — {e(why)}</span></div>'
        for cid, why in (sec.get("skipped") or {}).items())
    return (f'<details class="panel{" crit" if top == 1 else ""}" id="security" open>{head}'
            f'<div class="panel-body">{cards}{skipped}</div></details>')


def _forwards(model: dict) -> str:
    fw = fw_mod.merged(model)
    if not fw:
        return ""
    devs = model["devices"]
    present = {d["key"] for d in devs}
    by_ip = {ip: d for d in devs for ip in d["ips"]}
    rows = "".join(_fw_row(f, by_ip, present) for f in fw)
    return (f'<details class="panel crit" id="doors" open><summary><h2>{icon("globe")}Открыто из интернета: {len(fw)}</h2>'
            f'<span class="muted">каждый проброс — дверь снаружи; оставь только осознанные (например, VPN)</span>'
            f'{icon("chevron", "chev")}</summary><div class="panel-body">{rows}</div></details>')


def _pills(model: dict) -> str:
    meta, router = model["meta"], model.get("router")
    pills = []

    def pill(ico: str, short: str, text: str, cls: str = "") -> None:
        pills.append(f'<details class="pill {cls}"><summary>{icon(ico, "s")}{e(short)}</summary><div>{e(text)}</div></details>')

    if router:
        clients = router["clients"]
        pill("router", f'{router.get("model") or "роутер"} · {router.get("firmware") or "?"}',
             f'Роутер {router.get("model") or ""}, прошивка {router.get("firmware") or "?"}: клиентов в списке '
             f'{len(clients)}, сейчас в сети {sum(1 for c in clients if c.get("active"))}. Данные только читаются.')
    elif model.get("router_skipped"):
        pill("router", "роутер недоступен", f'Данные роутера недоступны: {model["router_skipped"]}', "warn")
    if not meta.get("admin"):
        pill("alert", "без админа", "Срез сделан без прав администратора. Часть будущих проверок "
             "(параметры SMB этого компьютера, DISM) будет недоступна.", "warn")
    if not model.get("oui_available"):
        pill("alert", "нет базы IEEE", "Нет базы производителей IEEE (data/oui.txt): производитель по MAC не определяется. "
             "Команда: python -m lanmap oui update", "warn")
    stages = meta.get("stages") or []
    duration = f'{stages[-1]["at_s"]:.0f} с' if stages else "?"
    pill("info", "о срезе", f'Интерфейс «{(meta.get("interface") or {}).get("alias", "?")}», компьютер '
         f'{meta.get("hostname", "?")}, проверено портов: {meta.get("ports_tested", "?")}, длительность {duration}. '
         "Программа только читает сеть и ничего не меняет на устройствах.")
    return f'<div class="pills">{"".join(pills)}</div>'


def _kpis(model: dict) -> str:
    devs = model["devices"]
    alive = [d for d in devs if d["alive"]]
    sure = sum(1 for d in alive if d["identity"]["confidence"] >= 3)
    share = sure / len(alive) if alive else 0
    circ = 2 * 3.14159 * 15
    ring = (f'<svg class="ring" viewBox="0 0 38 38" aria-hidden="true"><circle class="bg" cx="19" cy="19" r="15"/>'
            f'<circle class="fg" cx="19" cy="19" r="15" stroke-dasharray="{circ * share:.1f} {circ:.1f}"/></svg>')
    signed = sum(1 for d in devs if (d.get("registry") or {}).get("confirmed"))
    tiles = [
        f'<button class="kpi" data-kpi="all"><span class="ico">{icon("devices")}</span><span><b>{len(devs)}</b>'
        f'<span class="l">устройств</span></span></button>',
        f'<button class="kpi" data-kpi="online"><span class="ico"><i class="dot"></i></span><span><b>{len(alive)}</b>'
        f'<span class="l">в сети</span></span></button>',
        f'<div class="kpi" title="Опознаны с высокой уверенностью среди отвечавших">{ring}<span><b>{sure}</b>'
        f'<span class="l">опознаны из {len(alive)}</span></span></div>',
        f'<div class="kpi"><span class="ico">{icon("check")}</span><span><b>{signed}</b><span class="l">подписаны</span></span></div>',
    ]
    c = model.get("changes")
    if c and not c.get("error"):
        tiles.append(f'<button class="kpi add" data-kpi="changes"><span class="ico">{icon("delta")}</span>'
                     f'<span><b>{c.get("total", 0)}</b><span class="l">изменений</span></span></button>')
    sec = model.get("security")
    if sec:
        live = sec_mod.open_findings(sec)
        top = min((f["priority"] for f in live), default=0)
        tiles.append(f'<button class="kpi {"crit" if top == 1 else ""}" data-kpi="security"><span class="ico">'
                     f'{icon("shield")}</span><span><b>{len(live)}</b><span class="l">находок безопасности</span></span></button>')
    fw = fw_mod.merged(model)
    if fw_mod.upnp_known(model):
        tiles.append(f'<button class="kpi {"crit" if fw else ""}" data-kpi="doors"><span class="ico">{icon("globe")}</span>'
                     f'<span><b>{len(fw)}</b><span class="l">дверей из интернета</span></span></button>')
    return f'<div class="kpis">{"".join(tiles)}</div>'


def _legend() -> str:
    rows = [
        ('<i class="dot"></i>', "в сети"), ('<i class="dot off"></i>', "не отвечало"),
        (_meter(3), "уверенность опознания (4 деления — точно)"),
        (icon("wifi3", "s") + icon("wifi1", "s"), "Wi-Fi: сильный / слабый сигнал"), (icon("cable", "s"), "кабель"),
        ('<span class="pc add">+80</span>', "порт открылся с прошлого среза"),
        (f'<span class="pc del">{icon("minus", "s")}<s>80</s></span>', "порт закрылся"),
        (f'<span class="pc crit">{icon("alert", "s")}23</span>', "опасный порт (Telnet, ADB)"),
        (f'<span class="pc p1">{icon("shield", "s")}П1</span><span class="pc p2">П2</span><span class="pc p3">П3</span>',
         "находка безопасности: срочно / важно / желательно"),
        (icon("globe", "s") + icon("home", "s"), "кто может воспользоваться: из интернета / изнутри сети"),
        (f'<span class="pc trans">IP <s>·10</s>{icon("arrow", "s")}<span class="to">·20</span></span>', "сменился адрес"),
        (f'<span class="pc warn">{icon("barcode", "s")}≠</span>', "по адресу отвечает другой серийник"),
        (icon("check", "s"), "подписано владельцем"), (icon("user", "s"), "этот компьютер"),
        (icon("shuffle", "s"), "частный (случайный) MAC"), (icon("link", "s"), "общий MAC: мост или ретранслятор"),
    ]
    cells = "".join(f'<div>{a}<span>{e(b)}</span></div>' for a, b in rows)
    return (f'<details class="panel" id="legend"><summary><h2>{icon("question")}Что значат значки</h2>'
            f'{icon("chevron", "chev")}</summary><div class="panel-body legend">{cells}</div></details>')


def render(model: dict) -> str:
    meta = model["meta"]
    iface = meta.get("interface", {})
    devs = model["devices"]
    changes = model.get("changes")
    groups: list[str] = []
    for d in devs:
        if d["identity"]["group"] not in groups:
            groups.append(d["identity"]["group"])
    count = Counter(d["identity"]["group"] for d in devs)
    found_by_key: dict[str, list[dict]] = {}
    for f in (model.get("security") or {}).get("findings") or []:
        found_by_key.setdefault(f["key"], []).append(f)

    gfilters = "".join(
        f'<button class="gf" {gstyle(g)} data-group="{e(g)}" data-tip="{e(GROUP_SHORT.get(g, g))} · {count[g]}" '
        f'aria-label="{e(g)}: {count[g]}">{icon(GROUP_ICONS.get(g, "unknown"))}'
        f'<span class="badge">{count[g]}</span></button>' for g in groups)
    sections = []
    for g in groups:
        tiles = "".join(_tile(d, changes, found_by_key.get(d["key"])) for d in devs if d["identity"]["group"] == g)
        is_open = "" if g == OFFLINE_GROUP else " open"
        sections.append(f'<details class="group" {gstyle(g)}{is_open}><summary>{icon("chevron", "s chev")}'
                        f'<span class="gico">{icon(GROUP_ICONS.get(g, "unknown"))}</span>{e(g)} '
                        f'<span class="n">{count[g]}</span></summary>'
                        f'<div class="grid">{tiles}</div></details>')
    has_changes = any(((changes or {}).get("by_key") or {}).get(d["key"]) for d in devs)
    changed_btn = (f'<button class="iconbtn" id="f-changed" {tip("Только изменившиеся")}>{icon("delta", "s")}</button>'
                   if has_changes else "")
    started = meta.get("started", "")[:16].replace("T", " ")

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LanMap — срез {e(model['snapshot'])}</title>
<style>{CSS}</style></head><body>
{ICONS}
<div class="wrap">
<header>
  <div class="top">
    <h1>{icon("devices", "l")}Сеть {e(iface.get('network', '?'))}</h1>
    <span class="when">{e(started)}</span>
    <span class="spacer"></span>
    <span id="scanst" class="scanst" hidden></span>
    <button class="iconbtn live-only scanbtn" id="scan" {tip("Сделать новый срез сети")}>{icon("refresh", "s")}<span>Срез</span></button>
    <button class="iconbtn tip-l" id="theme" {tip("Светлая / тёмная тема")}>{icon("sun", "s")}{icon("moon", "s")}</button>
  </div>
  {_pills(model)}
  {_kpis(model)}
</header>
{_checklist(model)}
{_security(model)}
{_forwards(model)}
{_changes(model)}
<nav class="gfilters" aria-label="Группы устройств">{gfilters}</nav>
<div class="bar">
  <label class="search">{icon("search", "s")}<input id="q" type="search" placeholder="IP, MAC, имя, порт…" autocomplete="off"></label>
  <span class="seg" role="group" aria-label="Состояние">
    <button data-status="" {tip("Все устройства")}>все</button>
    <button data-status="on" {tip("В сети")}><i class="dot"></i></button>
    <button data-status="off" {tip("Не отвечали")}><i class="dot off"></i></button>
  </span>
  {changed_btn}
  <button class="iconbtn" id="f-low" {tip("Только неуверенно опознанные")}>{icon("question", "s")}</button>
  <span class="seg" role="group" aria-label="Вид">
    <button data-view="tiles" {tip("Плитки")}>{icon("grid", "s")}</button>
    <button data-view="list" {tip("Список")}>{icon("list", "s")}</button>
  </span>
  <button class="iconbtn tip-l" id="expand" {tip("Развернуть / свернуть все")}>{icon("expand", "s")}</button>
</div>
<main>{''.join(sections)}<p id="empty" class="note hidden">{icon("search", "s")}Ничего не найдено.</p></main>
{_legend()}
<footer>LanMap {e(meta.get('lanmap_version', ''))} · только чтение сети · отчёт содержит личные данные, не публикуй его</footer>
</div>
<script>{JS}</script>
</body></html>"""
