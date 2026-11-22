"""Журнал присмотра в том же защищённом локальном веб-интерфейсе."""
from datetime import datetime
from html import escape
import json

from lanmap.monitor import SOURCES, TITLES


def _when(value):
    return datetime.fromtimestamp(value).strftime("%d.%m.%Y %H:%M")


def _card(event: dict, expanded: bool) -> str:
    kind = event["kind"]
    title = TITLES[kind]
    at = _when(event["at"])
    if kind == "gap":
        end = f'до {_when(event["end"])}' if "end" in event else "наблюдение пока не возобновилось"
        return f'<p class="gap"><strong>{title}</strong> · {at} · {end}</p>'
    name = escape(event["name"] or event["mac"])
    details = [("MAC", event["mac"]), ("IP на момент события", event["ip"]),
               ("Подсеть наблюдения", event["network"]), ("Сегмент роутера", event["segment"]),
               ("Подтверждение", SOURCES[event["source"]])]
    if event["seen"] is not None:
        details.append(("Предыдущее наблюдение", _when(event["seen"])))
    rows = "".join(f"<dt>{label}</dt><dd>{escape(value)}</dd>" for label, value in details if value)
    return (f'<details id="event-{event["id"]}"{" open" if expanded else ""}>'
            f'<summary><b>{title}</b> · {name} <time>{at}</time></summary><dl>{rows}</dl></details>')


def render(state: dict, token: str, selected: int | None = None) -> str:
    events = list(reversed(state["events"]))
    event = next((item for item in events if item["id"] == selected and item["kind"] != "gap"), None)
    notice = ""
    if event:
        events.remove(event)
        events.insert(0, event)
    elif selected is not None:
        notice = '<p>Запись уже вышла из журнала. Доступны последние события.</p>'
    cards = "".join(_card(item, item["id"] == selected) for item in events)
    if not cards:
        cards = '<p>Здесь появятся новые и вернувшиеся устройства.</p>'
    if state["paused"]:
        status = "Присмотр на паузе"
    else:
        status = state["problem"] or SOURCES.get(state["source"], "Ожидаю первый опрос")
    if state["last_poll"] is not None:
        status += f' · последний успешный опрос {_when(state["last_poll"])}'
    button = "Продолжить" if state["paused"] else "Пауза"
    return f'''<!doctype html>
<html lang="ru"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Присмотр за сетью · LanMap</title><style>
:root{{color-scheme:light dark}} body{{font:16px/1.5 system-ui,sans-serif;max-width:48rem;margin:2rem auto;padding:0 1rem}}
h1{{line-height:1.15}} .bar{{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center}} form{{display:flex;flex-wrap:wrap;gap:.5rem;align-items:center}}
button,input{{font:inherit}} input{{width:5ch}} details,.gap{{border-block-start:1px solid GrayText;margin:0;padding:.75rem 0}}
summary{{cursor:pointer}} time{{color:GrayText;white-space:nowrap}} dl{{margin:.75rem 0 .25rem 1.1rem}}
dt{{font-weight:600}} dd{{margin:0 0 .4rem;overflow-wrap:anywhere}}
</style></head><body><nav><a href="/">Отчёт LanMap</a></nav><h1>Присмотр за сетью</h1>
<p>{escape(status)}</p><div class="bar"><button type="button" id="toggle">{button}</button>
<form id="settings"><label for="days">Сообщать о возвращении через</label>
<input id="days" type="number" min="1" max="365" value="{state['return_days']}" required> дней
<button>Сохранить</button></form></div><p id="message" role="status"></p>
<h2>Журнал</h2>{notice}{cards}
<script>
const message = document.getElementById('message');
async function save(fields) {{
  try {{
    const response = await fetch('/api/monitor', {{method:'POST', headers:{{'Content-Type':'application/json',
      'X-LanMap-Token':{json.dumps(token)}}}, body:JSON.stringify(fields)}});
    if (!response.ok) throw new Error((await response.json()).error);
    location.reload();
  }} catch (error) {{ message.textContent = error.message || 'Не удалось сохранить настройку'; }}
}}
document.getElementById('toggle').onclick = () => save({{paused:{json.dumps(not state['paused'])}}});
document.getElementById('settings').onsubmit = event => {{
  event.preventDefault();
  save({{return_days:document.getElementById('days').valueAsNumber}});
}};
</script></body></html>'''
