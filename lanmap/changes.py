"""«Что изменилось»: сравнение двух моделей среза (devices.json) по ключу устройства.

Сеть не трогает. Сопоставление каскадом: точный ключ → серийник (часть ключа после #) →
MAC (если он единственный с обеих сторон) → общий IP у устройства без MAC.
Защиты от ложных изменений:
- в базовом срезе не было данных роутера → его «только роутерные» устройства и пробросы
  не новые, а «впервые увидены через роутер» (и наоборот для пропавших);
- порт «закрылся» только если устройство отвечало в обоих срезах и порт проверялся оба раза;
- устройства с частным (случайным) MAC появляются и пропадают при каждом подключении —
  они считаются одной строкой.
"""
from __future__ import annotations

import ipaddress
import re
from pathlib import Path

from lanmap.util import read_json

_SNAP_RE = re.compile(r"\d{4}-\d\d-\d\d_")
MOBILE_TYPES = {"phone", "wearable"}


def previous_snapshot(snapshot: Path) -> Path | None:
    """Срез, сделанный прямо перед этим (по имени папки), — чтобы пересборка старого среза давала то же сравнение."""
    snapshot = Path(snapshot)
    parent = snapshot.parent
    if not parent.is_dir():
        return None
    older = sorted(p for p in parent.iterdir() if p.is_dir() and _SNAP_RE.match(p.name)
                   and (p / "meta.json").exists() and p.name < snapshot.name)
    return older[-1] if older else None


def tested_ports(snapshot: Path) -> set[int] | None:
    tested = (read_json(Path(snapshot) / "raw" / "ports.json", {}) or {}).get("tested")
    return set(tested) if tested else None


# --- сопоставление -------------------------------------------------------------------------

def _key_serial(dev: dict) -> str | None:
    return dev["key"].partition("#")[2] or None


def _serial(dev: dict) -> str | None:
    """Серийник из ключа или самоописания (ONVIF, UPnP). Может повторяться: камера через соседа отдаёт чужой."""
    facts = dev.get("facts") or {}
    upnp_sn = (facts.get("upnp") or {}).get("serialNumber") or [None]
    return _key_serial(dev) or (facts.get("onvif") or {}).get("SerialNumber") or upnp_sn[0]


def _unique_pairs(old_left: list[dict], new_left: list[dict], attr) -> list[tuple[dict, dict]]:
    """Пары по признаку attr(dev), только когда признак встречается ровно один раз с каждой стороны."""
    def index(devs):
        idx: dict = {}
        for d in devs:
            v = attr(d)
            if v:
                idx.setdefault(v, []).append(d)
        return idx
    o, n = index(old_left), index(new_left)
    return [(o[v][0], n[v][0]) for v in o if v in n and len(o[v]) == 1 and len(n[v]) == 1]


def match(old_devs: list[dict], new_devs: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
    """→ (пары старое/новое, только в старом, только в новом)."""
    pairs: list[tuple[dict, dict]] = []
    old_left, new_left = list(old_devs), list(new_devs)

    def take(found):
        for a, b in found:
            if a in old_left and b in new_left:
                pairs.append((a, b))
                old_left.remove(a)
                new_left.remove(b)

    take(_unique_pairs(old_left, new_left, lambda d: d["key"]))
    take(_unique_pairs(old_left, new_left, _key_serial))
    take(_unique_pairs(old_left, new_left, _serial))
    take(_unique_pairs(old_left, new_left, lambda d: _serial(d) and (_serial(d), tuple(sorted(d["ips"])))))
    take(_unique_pairs(old_left, new_left, lambda d: d.get("mac")))
    # Устройство без MAC (ключ ip:…) — по общему адресу
    for a in [d for d in old_left if d["key"].startswith("ip:")]:
        cands = [b for b in new_left if set(b["ips"]) & set(a["ips"])]
        if len(cands) == 1:
            take([(a, cands[0])])
    for b in [d for d in new_left if d["key"].startswith("ip:")]:
        cands = [a for a in old_left if set(a["ips"]) & set(b["ips"])]
        if len(cands) == 1:
            take([(cands[0], b)])
    return pairs, old_left, new_left


# --- сравнение -----------------------------------------------------------------------------

def _ip_sort(ips):
    return sorted(ips, key=ipaddress.ip_address)


def _brief(dev: dict) -> dict:
    return {"key": dev["key"], "title": dev.get("title") or dev["key"], "subtitle": dev.get("subtitle") or "",
            "ips": _ip_sort(dev["ips"]), "mac": dev.get("mac")}


def _port_text(service: dict) -> str:
    return f'{service["port"]}' + (f' {service["name"]}' if service.get("name") else "")


def _router_names(dev: dict) -> dict:
    r = dev.get("router") or {}
    return {"label": r.get("label"), "hostname": r.get("hostname")}


def _device_changes(old: dict, new: dict, tested_old: set[int] | None, tested_new: set[int] | None) -> list[dict]:
    items: list[dict] = []
    if old["ips"] and new["ips"] and set(old["ips"]) != set(new["ips"]):
        items.append({"what": "ip", "short": "IP",
                      "text": f'IP: {", ".join(_ip_sort(old["ips"]))} → {", ".join(_ip_sort(new["ips"]))}'})

    # Имена сравниваются только из роутера: «имя в сети» в выводе зависит от того, были ли данные роутера
    ro, rn = _router_names(old), _router_names(new)
    for field, label in (("label", "подпись в роутере"), ("hostname", "DHCP-имя")):
        if ro[field] and rn[field] and ro[field] != rn[field]:
            items.append({"what": "name", "short": "имя", "text": f"{label}: «{ro[field]}» → «{rn[field]}»"})

    so, sn = _serial(old), _serial(new)
    other_device = bool(so and sn and so != sn)
    if other_device:
        items.append({"what": "serial", "short": "другой серийник",
                      "text": f"отвечает устройство с другим серийным номером ({so} → {sn}): возможно, это уже другое "
                              "устройство или камера, которая выходит в сеть через соседнюю"})

    of, nf = old["identity"].get("firmware"), new["identity"].get("firmware")
    if of and nf and of != nf and not other_device:
        items.append({"what": "firmware", "short": "прошивка", "text": f"прошивка: {of} → {nf}"})

    if old["alive"] and new["alive"]:
        old_ports = {s["port"]: s for s in old["services"]}
        new_ports = {s["port"]: s for s in new["services"]}
        for port in sorted(set(new_ports) - set(old_ports)):
            # Порт, который в прошлый раз просто не проверяли, — не «открылся»
            if tested_old is not None and port not in tested_old and tested_new is not None and port in tested_new:
                continue
            items.append({"what": "port_open", "short": f"+{port}", "port": port,
                          "text": f"открыт порт {_port_text(new_ports[port])}"})
        # Телефоны и часы закрывают порты при блокировке экрана — закрытие у них не новость (открытие — новость)
        mobile = new.get("private_mac") or new["identity"].get("type") in MOBILE_TYPES
        for port in sorted(set(old_ports) - set(new_ports)):
            if mobile or (tested_new is not None and port not in tested_new):
                continue
            items.append({"what": "port_closed", "short": f"−{port}", "port": port,
                          "text": f"закрыт порт {_port_text(old_ports[port])}"})
    return items


def _fw_key(f: dict) -> tuple:
    return (f.get("kind"), (f.get("protocol") or "").lower(), str(f.get("port") or ""),
            f.get("to_ip"), str(f.get("to_port") or ""))


def compare(old: dict, new: dict, tested_old: set[int] | None = None, tested_new: set[int] | None = None) -> dict:
    """Две модели (как в devices.json) → блок изменений для отчёта."""
    old_router, new_router = old.get("router"), new.get("router")
    pairs, gone_raw, new_raw = match(old["devices"], new["devices"])

    result: dict = {
        "baseline": old.get("snapshot"),
        "baseline_started": (old.get("meta") or {}).get("started"),
        "new": [], "gone": [], "online": [], "offline": [], "changed": [],
        "private": {"new": 0, "gone": 0},
        "first_seen_router": {"devices": 0, "forwards": 0},
        "forwards_added": [], "forwards_removed": [],
        "router": [], "notes": [],
        "has_router": bool(new_router),
        "by_key": {},
    }

    for dev in new_raw:
        if dev.get("router_only") and not old_router:
            result["first_seen_router"]["devices"] += 1
        elif dev.get("private_mac"):
            result["private"]["new"] += 1
        else:
            result["new"].append(_brief(dev))
            result["by_key"][dev["key"]] = [{"what": "new", "short": "новое", "text": "в прошлом срезе этого устройства не было"}]
    for dev in gone_raw:
        if dev.get("router_only") and not new_router:
            continue  # в новом срезе просто нет данных роутера
        if dev.get("private_mac"):
            result["private"]["gone"] += 1
        else:
            result["gone"].append(_brief(dev))

    for a, b in pairs:
        items = _device_changes(a, b, tested_old, tested_new)
        if a["alive"] and not b["alive"]:
            result["offline"].append(_brief(b))
            items.insert(0, {"what": "offline", "short": "ушло из сети", "text": "в прошлый раз отвечало, сейчас нет"})
        elif b["alive"] and not a["alive"]:
            result["online"].append(_brief(b))
            items.insert(0, {"what": "online", "short": "в сети", "text": "в прошлый раз не отвечало, сейчас в сети"})
        real = [x for x in items if x["what"] not in ("online", "offline")]
        if real:
            result["changed"].append({**_brief(b), "items": real})
        if items:
            result["by_key"][b["key"]] = items

    if old_router and new_router:
        of = {_fw_key(f): f for f in old_router.get("forwards") or []}
        nf = {_fw_key(f): f for f in new_router.get("forwards") or []}
        result["forwards_added"] = [nf[k] for k in nf if k not in of]
        result["forwards_removed"] = [of[k] for k in of if k not in nf]
        if old_router.get("firmware") and new_router.get("firmware") and old_router["firmware"] != new_router["firmware"]:
            result["router"].append(f'прошивка роутера: {old_router["firmware"]} → {new_router["firmware"]}')
    elif new_router and not old_router:
        result["first_seen_router"]["forwards"] = len(new_router.get("forwards") or [])

    fs = result["first_seen_router"]
    if fs["devices"] or fs["forwards"]:
        result["notes"].append(
            f'В прошлом срезе не было данных роутера: {fs["devices"]} устройств и {fs["forwards"]} пробросов '
            "увидены через роутер впервые — это не значит, что они новые.")
    elif old_router and not new_router:
        result["notes"].append("В этом срезе нет данных роутера: пробросы и устройства, известные только роутеру, не сравнивались.")
    if tested_old and tested_new and tested_old != tested_new:
        result["notes"].append("Набор проверяемых портов в срезах разный: сравниваются только порты, проверенные оба раза.")

    result["total"] = (len(result["new"]) + len(result["gone"]) + len(result["changed"]) + len(result["online"])
                       + len(result["offline"]) + result["private"]["new"] + result["private"]["gone"]
                       + len(result["forwards_added"]) + len(result["forwards_removed"]) + len(result["router"]))
    return result


def summary(changes: dict) -> str:
    """Одна строка для консоли."""
    parts = [f'новых {len(changes["new"])}', f'пропало {len(changes["gone"])}', f'изменилось {len(changes["changed"])}']
    if changes["forwards_added"] or changes["forwards_removed"]:
        parts.append(f'пробросы +{len(changes["forwards_added"])}/−{len(changes["forwards_removed"])}')
    return f'С прошлого среза ({changes["baseline"]}): ' + ", ".join(parts)
