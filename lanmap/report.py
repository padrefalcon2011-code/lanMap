"""Статический HTML-отчёт по срезу: карточки устройств, улики, уверенность, ссылки-действия.

Файл самодостаточный (без внешних скриптов и шрифтов) и лежит в папке среза — данные личные.
"""
from __future__ import annotations

import html
from collections import Counter

from lanmap.devices import connection_text
from lanmap.identify import LEVEL_NAMES

SOURCE_NAMES = {
    "registry": "реестр владельца", "upnp": "UPnP", "onvif": "ONVIF", "mdns": "mDNS", "netbios": "NetBIOS",
    "router_dns": "DNS роутера", "dns": "обратный DNS", "oui": "MAC (IEEE)", "http": "HTTP", "tls": "TLS",
    "ssh": "SSH", "rtsp": "RTSP", "ssdp": "SSDP", "wsd": "WS-Discovery", "smb": "SMB", "mac": "MAC",
    "ttl": "TTL", "banner": "баннер", "local": "система", "router": "роутер", "dhcp": "DHCP-имя",
}
FIELD_NAMES = {"type": "Тип", "vendor": "Производитель", "model": "Модель", "firmware": "Прошивка",
               "os": "ОС", "name": "Имя", "group": "Группа"}
CONF_CLASS = {4: "c4", 3: "c3", 2: "c2", 1: "c1", 0: "c0"}


def e(value) -> str:
    return html.escape(str(value), quote=True)


def _source_label(source: str) -> str:
    if source.startswith("rule:"):
        return "правило " + source[5:]
    if source.startswith("registry-draft:"):
        return "черновик реестра (" + source.split(":", 1)[1] + ")"
    return SOURCE_NAMES.get(source, source)


def _card(dev: dict) -> str:
    ident = dev["identity"]
    reg = dev.get("registry") or {}
    conf = ident["confidence"]
    badges = [f'<span class="badge {CONF_CLASS[min(conf, 4)]}" title="Уверенность опознания">{e(LEVEL_NAMES[min(conf, 4)])}</span>']
    if reg.get("confirmed"):
        badges.append('<span class="badge ok">подписано</span>')
    elif reg:
        badges.append(f'<span class="badge draft" title="Черновик реестра, не подтверждён владельцем">предложено: {e(reg.get("source", "импорт"))}</span>')
    if dev["is_local"]:
        badges.append('<span class="badge info">этот компьютер</span>')
    if dev["is_gateway"]:
        badges.append('<span class="badge info">шлюз</span>')
    if dev["private_mac"]:
        badges.append('<span class="badge warn" title="Случайный MAC телефона/планшета/ноутбука">частный MAC</span>')
    if not dev["alive"]:
        badges.append('<span class="badge muted">не отвечало</span>')
    r = dev.get("router") or {}
    if dev.get("router_only"):
        badges.append('<span class="badge muted" title="Сканирование устройство не видело, о нём знает только роутер">только роутер</span>')
    if r.get("segment") and r["segment"].lower() not in ("home", "домашняя сеть"):
        badges.append(f'<span class="badge warn" title="Сегмент сети по данным роутера">{e(r["segment"])}</span>')
    if dev.get("duplicate_mac"):
        badges.append('<span class="badge warn" title="Тот же MAC у другого устройства: мост/ретранслятор или одинаковый MAC">общий MAC</span>')
    if len(dev["ips"]) > 1:
        badges.append(f'<span class="badge warn" title="Один MAC — несколько IP">{len(dev["ips"])} IP</span>')

    facts = []
    facts.append(f'<div><span>IP</span><b>{e(", ".join(dev["ips"]) or "—")}</b></div>')
    facts.append(f'<div><span>MAC</span><b class="mono">{e(dev["mac"] or "не получен")}</b></div>')
    for key in ("vendor", "model", "firmware", "os"):
        if ident.get(key):
            facts.append(f'<div><span>{FIELD_NAMES[key]}</span><b>{e(ident[key])}</b></div>')
    if r:
        facts.append(f'<div><span>Подключение</span><b>{e(connection_text(r).removeprefix("Роутер: "))}</b></div>')
        if r.get("hostname") and r.get("hostname") != dev["title"]:
            facts.append(f'<div><span>DHCP-имя</span><b>{e(r["hostname"])}</b></div>')
    for key in ("place", "owner", "purpose"):
        if reg.get(key):
            label = {"place": "Место", "owner": "Владелец", "purpose": "Назначение"}[key]
            facts.append(f'<div><span>{label}</span><b>{e(reg[key])}</b></div>')

    ports = "".join(
        f'<span class="port" title="{e(s.get("http", {}).get("title") or s.get("banner") or "")}">'
        f'{s["port"]}{(" · " + e(s["name"])) if s.get("name") else ""}</span>'
        for s in dev["services"])
    ports_html = f'<div class="ports">{ports}</div>' if ports else '<div class="ports none">открытых TCP-портов не найдено</div>'

    acts = []
    for a in dev["actions"]:
        if a["kind"] == "link":
            acts.append(f'<a class="act" href="{e(a["url"])}" target="_blank" rel="noopener" title="{e(a.get("hint", ""))}">{e(a["label"])}</a>')
        else:
            acts.append(f'<button class="act copy" data-copy="{e(a["value"])}" title="{e(a.get("hint", "") or a["value"])}">{e(a["label"])}</button>')

    chosen = "".join(
        f'<li><b>{FIELD_NAMES.get(k, k)}:</b> {e(v["value"] if k != "type" else ident["type_label"])} '
        f'<span class="src">← {e(_source_label(v["source"]))}; {e(v["why"])}</span></li>'
        for k, v in ident["chosen"].items())
    evidence = "".join(
        f'<li><span class="tag">{e(SOURCE_NAMES.get(x["source"], x["source"]))}</span> {e(x["text"])}'
        f'{(" <span class=src>(" + e(x["ip"]) + ")</span>") if x.get("ip") and len(dev["ips"]) > 1 else ""}</li>'
        for x in dev["evidence"])
    problems = "".join(f'<li class="conflict">⚠ {e(c)}</li>' for c in ident["conflicts"])
    problems += "".join(f'<li class="note">ℹ {e(n)}</li>' for n in ident["notes"])
    if reg.get("notes"):
        problems += f'<li class="note">📝 {e(reg["notes"])}</li>'
    why = (f'<details><summary>Почему так ({len(dev["evidence"])} улик)</summary>'
           f'<h4>Вывод</h4><ul class="chosen">{chosen or "<li>ничего не известно</li>"}</ul>'
           f'{"<ul class=problems>" + problems + "</ul>" if problems else ""}'
           f'<h4>Улики</h4><ul class="evidence">{evidence or "<li>улик нет</li>"}</ul>'
           f'<p class="src">Сработавшие правила: {e(", ".join(ident["rules"]) or "нет")}</p></details>')

    search = " ".join([dev["title"], dev["subtitle"], " ".join(dev["ips"]), dev["mac"] or "", ident["type_label"],
                       ident.get("vendor") or "", ident.get("model") or "",
                       " ".join(str(s["port"]) + " " + (s.get("name") or "") for s in dev["services"])]).lower()
    return (f'<article class="card" data-group="{e(ident["group"])}" data-conf="{conf}" data-search="{e(search)}">'
            f'<header><h3>{e(dev["title"])}</h3><p class="sub">{e(dev["subtitle"])}</p>'
            f'<div class="badges">{"".join(badges)}</div></header>'
            f'<div class="facts">{"".join(facts)}</div>{ports_html}'
            f'<div class="actions">{"".join(acts)}</div>{why}</article>')


def _forwards(model: dict, devs: list[dict]) -> str:
    router = model.get("router")
    if not router:
        reason = model.get("router_skipped")
        return f'<p class="meta">Данные роутера недоступны{": " + e(reason) if reason else ""}.</p>' if reason else ""
    head = (f'<p class="meta">Роутер {e(router.get("model") or "")}, прошивка {e(router.get("firmware") or "?")}: '
            f'клиентов в списке {len(router["clients"])}, сейчас в сети {sum(1 for c in router["clients"] if c.get("active"))}.</p>')
    fw = router.get("forwards") or []
    if not fw:
        return head + '<p class="meta">Пробросов портов из интернета внутрь сети нет.</p>'
    by_ip = {ip: d for d in devs for ip in d["ips"]}
    rows = "".join(
        f'<tr><td>{e(f["kind"].upper())}</td><td>{e(f.get("protocol") or "")} {e(f.get("port") or "")}</td>'
        f'<td>{e(by_ip[f["to_ip"]]["title"]) if f.get("to_ip") in by_ip else ""} ({e(f.get("to_ip") or "?")}:{e(f.get("to_port") or "")})</td>'
        f'<td>{e(f.get("description") or "")}</td></tr>' for f in fw)
    return (head + f'<div class="forwards"><h3>⚠ Открыто из интернета внутрь сети: {len(fw)}</h3>'
            '<p class="meta">Каждый такой проброс — дверь снаружи. Оставь только осознанные (например, VPN).</p>'
            f'<table><tr><th>Вид</th><th>Порт снаружи</th><th>Куда ведёт</th><th>Описание</th></tr>{rows}</table></div>')


def render(model: dict) -> str:
    meta = model["meta"]
    iface = meta.get("interface", {})
    devs = model["devices"]
    alive = [d for d in devs if d["alive"]]
    conf = Counter(min(d["identity"]["confidence"], 4) for d in alive)
    groups = []
    for d in devs:
        if d["identity"]["group"] not in groups:
            groups.append(d["identity"]["group"])

    warnings = []
    if not meta.get("admin"):
        warnings.append("Срез сделан без прав администратора. Для этапа 0 это почти ничего не меняет, "
                        "но часть будущих проверок (параметры SMB этого компьютера, DISM) будет недоступна.")
    if not model.get("oui_available"):
        warnings.append("Нет базы производителей IEEE (data/oui.txt): производитель по MAC не определяется. "
                        "Команда: python -m lanmap oui update")
    if model.get("registry_drafts"):
        warnings.append(f"В реестре {model['registry_drafts']} черновиков из среза Codex — это предложения, а не факты. "
                        "Подписывать не обязательно сейчас: позже это можно будет сделать кнопкой в интерфейсе.")

    forwards_html = _forwards(model, devs)

    sections = []
    for g in groups:
        cards = "".join(_card(d) for d in devs if d["identity"]["group"] == g)
        n = sum(1 for d in devs if d["identity"]["group"] == g)
        sections.append(f'<section data-section="{e(g)}"><h2>{e(g)} <span class="count">{n}</span></h2>'
                        f'<div class="grid">{cards}</div></section>')

    chips = "".join(f'<button class="chip" data-filter-group="{e(g)}">{e(g)}</button>' for g in groups)
    summary = " · ".join(f'{LEVEL_NAMES[k]}: {conf.get(k, 0)}' for k in (4, 3, 2, 1, 0) if conf.get(k))
    stages = meta.get("stages") or []
    duration = f'{stages[-1]["at_s"]:.0f} с' if stages else "?"
    signed = sum(1 for d in devs if (d.get("registry") or {}).get("confirmed"))

    return f"""<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>LanMap — срез {e(model['snapshot'])}</title>
<style>{CSS}</style></head><body>
<header class="top">
  <h1>Срез сети {e(iface.get('network', '?'))}</h1>
  <p class="meta">{e(meta.get('started', '')[:16].replace('T', ' '))} · интерфейс «{e(iface.get('alias', '?'))}» · компьютер {e(meta.get('hostname', '?'))}
  · проверено портов: {e(meta.get('ports_tested', '?'))} · длительность {e(duration)}</p>
  <div class="kpis">
    <div><b>{len(devs)}</b><span>устройств</span></div>
    <div><b>{len(alive)}</b><span>отвечали</span></div>
    <div><b>{conf.get(4, 0) + conf.get(3, 0)}</b><span>опознаны уверенно</span></div>
    <div><b>{signed}</b><span>подписаны владельцем</span></div>
  </div>
  <p class="meta">Уверенность у отвечавших: {e(summary)}</p>
  {''.join(f'<p class="warning">{e(w)}</p>' for w in warnings)}
  {forwards_html}
  <div class="filters">
    <input id="q" type="search" placeholder="Поиск: IP, MAC, имя, порт, производитель…" autocomplete="off">
    <button class="chip active" data-filter-group="">Все</button>{chips}
    <label class="lowconf"><input type="checkbox" id="low"> только неуверенные</label>
  </div>
</header>
<main>{''.join(sections)}</main>
<footer>LanMap {e(meta.get('lanmap_version', ''))} · программа только читает сеть и ничего не меняет на устройствах · отчёт содержит личные данные сети, не публикуй его</footer>
<script>{JS}</script>
</body></html>"""


CSS = """
:root{--bg:#f6f7f9;--card:#fff;--fg:#1d2330;--muted:#667085;--line:#e3e6eb;--accent:#2f6fde;
--c4:#1a7f37;--c3:#2f6fde;--c2:#b26b00;--c1:#b54708;--c0:#8a8f98;--warnbg:#fff4e5;--chip:#eef1f5}
@media (prefers-color-scheme:dark){:root{--bg:#14171c;--card:#1d2128;--fg:#e6e8eb;--muted:#9aa3ae;--line:#2c323b;
--accent:#6b9cf0;--c4:#4ac26b;--c3:#6b9cf0;--c2:#e0a03a;--c1:#f08a4b;--c0:#8a8f98;--warnbg:#3a2c16;--chip:#262b33}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.45 system-ui,"Segoe UI",sans-serif}
.top{padding:20px 24px 8px;max-width:1400px;margin:auto}h1{margin:0 0 4px;font-size:22px}
.meta{color:var(--muted);margin:2px 0}.kpis{display:flex;gap:12px;flex-wrap:wrap;margin:12px 0}
.kpis div{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:8px 14px;min-width:120px}
.kpis b{display:block;font-size:22px}.kpis span{color:var(--muted);font-size:12px}
.warning{background:var(--warnbg);border-radius:8px;padding:8px 12px;margin:6px 0}
.filters{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin:12px 0 4px}
#q{flex:1 1 280px;padding:8px 10px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--fg)}
.chip{border:1px solid var(--line);background:var(--chip);color:var(--fg);border-radius:999px;padding:5px 11px;cursor:pointer}
.chip.active{background:var(--accent);color:#fff;border-color:var(--accent)}.lowconf{color:var(--muted);margin-left:6px}
main{max-width:1400px;margin:auto;padding:0 24px 24px}h2{font-size:17px;margin:22px 0 10px}.count{color:var(--muted);font-weight:400}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(340px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px;display:flex;flex-direction:column;gap:8px}
.card h3{margin:0;font-size:16px;word-break:break-word}.sub{margin:2px 0 0;color:var(--muted);word-break:break-word}
.badges{display:flex;flex-wrap:wrap;gap:4px;margin-top:6px}
.badge{font-size:11px;border-radius:6px;padding:2px 7px;background:var(--chip);color:var(--fg)}
.badge.c4{background:var(--c4);color:#fff}.badge.c3{background:var(--c3);color:#fff}.badge.c2{background:var(--c2);color:#fff}
.badge.c1{background:var(--c1);color:#fff}.badge.c0{background:var(--c0);color:#fff}
.badge.ok{background:var(--c4);color:#fff}.badge.draft{border:1px dashed var(--c2);background:transparent}
.badge.warn{border:1px solid var(--c2);background:transparent}.badge.info{border:1px solid var(--accent);background:transparent}
.badge.muted{color:var(--muted)}
.facts{display:grid;grid-template-columns:max-content 1fr;gap:2px 10px}.facts div{display:contents}
.facts span{color:var(--muted)}.facts b{font-weight:500;word-break:break-all}.mono{font-family:ui-monospace,Consolas,monospace}
.ports{display:flex;flex-wrap:wrap;gap:4px}.ports.none{color:var(--muted);font-size:12px}
.port{font-size:12px;background:var(--chip);border-radius:6px;padding:1px 6px;font-family:ui-monospace,Consolas,monospace}
.actions{display:flex;flex-wrap:wrap;gap:6px}
.act{font-size:12px;border:1px solid var(--accent);color:var(--accent);background:transparent;border-radius:6px;padding:3px 8px;
text-decoration:none;cursor:pointer}.act:hover{background:var(--accent);color:#fff}
details summary{cursor:pointer;color:var(--accent)}details h4{margin:8px 0 4px;font-size:13px}
details ul{margin:0;padding-left:18px}details li{margin:2px 0}.src{color:var(--muted);font-size:12px}
.tag{font-size:11px;background:var(--chip);border-radius:4px;padding:0 5px}
.problems{list-style:none;padding:0!important;margin:6px 0!important}.conflict{color:var(--c1)}.note{color:var(--muted)}
.forwards{background:var(--warnbg);border-radius:8px;padding:8px 12px;margin:8px 0;overflow-x:auto}
.forwards h3{margin:0 0 4px;font-size:15px}.forwards table{border-collapse:collapse;font-size:13px}
.forwards td,.forwards th{text-align:left;padding:3px 10px 3px 0;vertical-align:top}
footer{color:var(--muted);text-align:center;padding:20px;font-size:12px}
.hidden{display:none!important}
@media (max-width:480px){.top,main{padding-left:12px;padding-right:12px}.grid{grid-template-columns:1fr}}
"""

JS = """
const q=document.getElementById('q'),low=document.getElementById('low');let group='';
function apply(){const t=q.value.trim().toLowerCase();
 document.querySelectorAll('.card').forEach(c=>{const ok=(!group||c.dataset.group===group)&&(!t||c.dataset.search.includes(t))
  &&(!low.checked||+c.dataset.conf<3);c.classList.toggle('hidden',!ok)});
 document.querySelectorAll('section').forEach(s=>s.classList.toggle('hidden',!s.querySelector('.card:not(.hidden)')));}
q.addEventListener('input',apply);low.addEventListener('change',apply);
document.querySelectorAll('[data-filter-group]').forEach(b=>b.addEventListener('click',()=>{group=b.dataset.filterGroup;
 document.querySelectorAll('[data-filter-group]').forEach(x=>x.classList.toggle('active',x===b));apply();}));
document.querySelectorAll('.copy').forEach(b=>b.addEventListener('click',async()=>{const v=b.dataset.copy;
 try{await navigator.clipboard.writeText(v)}catch(e){const a=document.createElement('textarea');a.value=v;document.body.appendChild(a);
 a.select();document.execCommand('copy');a.remove()}const old=b.textContent;b.textContent='Скопировано';setTimeout(()=>b.textContent=old,1200);}));
"""
