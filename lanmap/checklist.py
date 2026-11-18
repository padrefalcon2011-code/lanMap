"""Чек-лист «экологичной сети» E1–E9 и прогресс «порядок в сети: X из 9». Сеть не трогает: только модель среза.

У критерия четыре исхода:
- ok — выполнен;
- fail — не выполнен (с причинами: находки, устройства);
- owner — проверить нечем, отмечает владелец (E6 прошивки, E8 резервные копии) — `check set E8 done`;
- unknown — нечем проверить в этом срезе (например, нет данных роутера).

Критерии E2, E4, E5, E7 считаются по находкам безопасности (поле criteria у проверки): открытые находки —
не выполнен, «принята осознанно» и «не применимо» не мешают. Отметки владельца — data/checklist.json.
"""
from __future__ import annotations

from pathlib import Path

from lanmap import security as sec_mod
from lanmap.util import data_dir, now_iso, read_json, write_json

OWNER = {"E6", "E8"}
OWNER_HINTS = {
    "E6": "Зайди в настройки каждого важного устройства (роутер, NAS, камеры) и обнови прошивку; устройство без "
          "обновлений — в отдельную сеть или на замену.",
    "E8": "Резервная копия считается проверенной, когда ты хотя бы раз восстановил из неё файл.",
}
# Важные устройства — им нужен постоянный адрес (E9): на них ходят по адресу, пробрасывают порты, пишут видео
IMPORTANT_TYPES = {"nas", "camera", "printer", "network"}
# Кого отделять (E3) и от кого
IOT_TYPES = {"camera", "iot"}
SENSITIVE_TYPES = {"computer", "nas"}
MARK_STATUSES = {"done": "сделано", "open": "не сделано"}


# --- отметки владельца ------------------------------------------------------------------------

def marks_path() -> Path:
    return data_dir() / "checklist.json"


def load_marks() -> dict:
    return (read_json(marks_path(), {}) or {}).get("criteria") or {}


def set_mark(code: str, status: str, note: str | None = None) -> dict:
    code = code.upper()
    if code not in OWNER:
        raise ValueError(f"{code} проверяется по срезу, отмечать его не нужно. Отмечаются: {', '.join(sorted(OWNER))}")
    if status not in MARK_STATUSES:
        raise ValueError(f"Нет такого статуса: {status}. Есть: {', '.join(MARK_STATUSES)}")
    data = read_json(marks_path(), {}) or {}
    items = data.setdefault("criteria", {})
    if status == "open":
        items.pop(code, None)
        entry = {"status": "open"}
    else:
        entry = {"status": status, "updated": now_iso()}
        if note:
            entry["note"] = note
        items[code] = entry
    write_json(marks_path(), data)
    return entry


# --- критерии ---------------------------------------------------------------------------------

def _dev(d: dict) -> dict:
    return {"key": d["key"], "title": d.get("title") or d["key"], "ips": d["ips"],
            "type": (d.get("identity") or {}).get("type") or "unknown"}


def _item(code: str, status: str, why: str = "", done: int | None = None, total: int | None = None, **extra) -> dict:
    return {"id": code, "title": sec_mod.CRITERIA[code], "status": status, "why": why,
            "done": done, "total": total, **extra}


def _e1(model: dict) -> dict:
    alive = [d for d in model["devices"] if d["alive"]]
    if not alive:
        return _item("E1", "unknown", "в срезе нет отвечавших устройств")

    def known(d: dict) -> bool:
        return (d["identity"].get("confidence") or 0) >= 3 or bool((d.get("registry") or {}).get("confirmed")) \
            or bool((d.get("router") or {}).get("label"))

    strangers = [d for d in alive if not known(d)]
    return _item("E1", "fail" if strangers else "ok",
                 f"незнакомых: {len(strangers)}" if strangers else "все отвечавшие устройства опознаны или подписаны",
                 len(alive) - len(strangers), len(alive), devices=[_dev(d) for d in strangers])


def _by_findings(code: str, sec: dict | None) -> dict:
    checks = [c for c in sec_mod.CHECKS if code in c.criteria]
    if not sec:
        return _item(code, "unknown", "в срезе нет проверок безопасности")
    evaluated = sec.get("evaluated") or {}
    ran = [c for c in checks if evaluated.get(c.id)]
    skipped = [c.title for c in checks if not evaluated.get(c.id)]
    if not ran:
        return _item(code, "unknown", "нечем проверить: " + "; ".join(
            (sec.get("skipped") or {}).get(c.id) or c.needs or "нет данных" for c in checks), skipped=skipped)
    ids = {c.id for c in ran}
    found = [f for f in sec.get("findings") or [] if f["id"] in ids]
    groups: dict[str, dict] = {}
    for f in found:
        g = groups.setdefault(f["id"], {"id": f["id"], "title": sec_mod.BY_ID[f["id"]].title,
                                        "priority": 9, "open": 0, "quiet": 0})
        if f["status"] in sec_mod.QUIET_STATUSES:
            g["quiet"] += 1
        else:
            g["open"] += 1
            g["priority"] = min(g["priority"], f["priority"])
    live = sum(g["open"] for g in groups.values())
    order = sorted(groups.values(), key=lambda g: (not g["open"], g["priority"]))
    why = f"открытых находок: {live}" if live else ("оставлено осознанно: " + str(len(found)) if found else "находок нет")
    return _item(code, "fail" if live else "ok", why, len(found) - live if found else None, len(found) or None,
                 findings=order, skipped=skipped)


def _e3(model: dict) -> dict:
    if not model.get("router"):
        return _item("E3", "unknown", "в какой сети (домашней, гостевой) каждое устройство, видно только через роутер")
    alive = [d for d in model["devices"] if d["alive"]]
    seg = {d["key"]: (d.get("router") or {}).get("segment") for d in alive}
    iot = [d for d in alive if d["identity"].get("type") in IOT_TYPES]
    if not iot:
        return _item("E3", "ok", "камер и умного дома в сети нет")
    known = [d for d in iot if seg[d["key"]]]
    if not known:
        return _item("E3", "unknown", "роутер не сообщил, в какой сети камеры и умный дом")
    sensitive = [d for d in alive if d["identity"].get("type") in SENSITIVE_TYPES and seg[d["key"]]]
    shared = {seg[d["key"]] for d in sensitive}
    mixed = [d for d in known if seg[d["key"]] in shared]
    near = [d for d in sensitive if seg[d["key"]] in {seg[m["key"]] for m in mixed}]
    segments = sorted({s for s in seg.values() if s})
    why = (f"в одной сети с ПК и NAS: {len(mixed)}" if mixed
           else "камеры и умный дом в отдельной сети от ПК и NAS")
    return _item("E3", "fail" if mixed else "ok", why, len(known) - len(mixed), len(known),
                 likely=bool(mixed), devices=[_dev(d) for d in mixed], near=[_dev(d) for d in near],
                 segments=segments, unseen=len(iot) - len(known))


def _e9(model: dict) -> dict:
    router = model.get("router")
    if not router or router.get("reservations") is None:
        return _item("E9", "unknown", "закреплённые адреса (резервации DHCP) видны только через модуль роутера"
                     if not router else "в срезе нет списка закреплённых адресов от роутера (старый срез или модуль их не читает)")
    reserved_mac = {(r.get("mac") or "").lower() for r in router["reservations"]}
    reserved_ip = {r.get("ip") for r in router["reservations"] if r.get("ip")}
    imp = [d for d in model["devices"] if d["alive"] and not d["is_gateway"] and not d["is_local"]
           and d["identity"].get("type") in IMPORTANT_TYPES]
    if not imp:
        return _item("E9", "ok", "важных устройств (NAS, камер, принтеров, точек доступа) в сети нет")
    loose = [d for d in imp if (d.get("mac") or "").lower() not in reserved_mac and not set(d["ips"]) & reserved_ip]
    return _item("E9", "fail" if loose else "ok",
                 f"без закреплённого адреса: {len(loose)}" if loose else "у всех важных устройств адрес закреплён",
                 len(imp) - len(loose), len(imp), devices=[_dev(d) for d in loose])


def _owner(code: str, marks: dict) -> dict:
    mark = marks.get(code) or {}
    if mark.get("status") == "done":
        return _item(code, "ok", "отмечено владельцем", mark=mark)
    return _item(code, "owner", OWNER_HINTS[code])


def evaluate(model: dict, marks: dict | None = None) -> dict:
    """Модель среза (с блоком security) → чек-лист для devices.json и отчёта."""
    marks = load_marks() if marks is None else marks
    sec = model.get("security")
    items = [_e1(model), _by_findings("E2", sec), _e3(model), _by_findings("E4", sec), _by_findings("E5", sec),
             _owner("E6", marks), _by_findings("E7", sec), _owner("E8", marks), _e9(model)]
    return {"criteria": items, "score": sum(1 for i in items if i["status"] == "ok"), "total": len(items),
            "unknown": sum(1 for i in items if i["status"] == "unknown")}


def compare(old: dict | None, new: dict | None) -> dict | None:
    """Был X, стал Y. Критерий, который в одном из срезов нечем было проверить, — не улучшение и не регресс."""
    if not old or not new:
        return None
    prev = {i["id"]: i["status"] for i in old["criteria"]}
    better, worse = [], []
    for i in new["criteria"]:
        a, b = prev.get(i["id"]), i["status"]
        if a in (None, "unknown") or b == "unknown" or a == b:
            continue
        if b == "ok":
            better.append(i["id"])
        elif a == "ok":
            worse.append(i["id"])
    return {"old": old["score"], "new": new["score"], "better": better, "worse": worse}
