"""Готовность и целостность папки среза.

Завершённый срез — сбор дошёл до конца: в meta.json есть finished, и на месте основные сырые файлы (CORE_RAW).
Прерванный срез не берётся ни базой сравнения, ни «последним» для build и веб-интерфейса.

Целостность: при завершении в meta.json пишется манифест raw/* (размер и SHA-256) — той же записью, что и
finished, поэтому завершённый срез без манифеста бывает только старый. verify() сверяет файлы с манифестом;
у старых срезов — только наличие основных файлов. SHA-256 ловит случайную порчу и ручную правку,
подлинности он не доказывает.
"""
from __future__ import annotations

import hashlib
import re
from pathlib import Path

from lanmap.util import read_json

# Этапы паспорта полноты (meta.passport, пишет scan.Passport) — в порядке среза
STAGES = {
    "discovery": "Поиск устройств", "arp": "MAC-адреса (ARP)", "ports": "Порты и ответы служб", "router": "Роутер",
    "names": "Имена", "upnp": "UPnP-описания", "igd": "UPnP-пробросы у шлюза", "onvif": "Камеры (ONVIF)",
    "smb": "SMB", "windows": "Этот компьютер",
}
PASS_NAMES = {"ok": "выполнен", "partial": "частично", "skipped": "пропущен", "error": "ошибка"}

# Без них срез не годится: из них строятся устройства и охват портов. Пишутся первыми, есть во всех срезах
CORE_RAW = ("ping.json", "neighbors.json", "arp.json", "ports.json", "probes.json")
NAME_RE = re.compile(r"(\d{4}-\d\d-\d\d_\d{6})(?:_(\d+))?$")


def is_snapshot_name(name: str) -> bool:
    return bool(NAME_RE.match(name))


def order_key(path: Path) -> tuple[str, int]:
    """Порядок срезов: время из имени, затем номер (…_2 раньше …_10)."""
    m = NAME_RE.match(Path(path).name)
    return (m.group(1), int(m.group(2) or 1)) if m else (Path(path).name, 0)


def meta(snap: Path) -> dict:
    try:
        return read_json(Path(snap) / "meta.json", {}) or {}
    except ValueError:
        return {}


def finished(snap: Path, m: dict | None = None) -> bool:
    """Сбор дошёл до конца: finished в meta.json и основные сырые файлы на месте. Без хэшей — дёшево."""
    snap = Path(snap)
    m = meta(snap) if m is None else m
    return bool(m.get("finished")) and all((snap / "raw" / name).is_file() for name in CORE_RAW)


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def manifest(snap: Path) -> dict[str, dict]:
    """Сырые файлы среза → {"raw/имя": {size, sha256}}. devices.json и отчёт — вне raw/, их пересобирают."""
    raw = Path(snap) / "raw"
    out = {}
    for path in sorted(raw.rglob("*")) if raw.is_dir() else []:
        if path.is_file() and not path.name.endswith(".tmp"):
            out[path.relative_to(snap).as_posix()] = {"size": path.stat().st_size, "sha256": _sha256(path)}
    return out


def verify(snap: Path) -> dict:
    """Проверка файлов среза → {finished, manifest, missing, changed, ok}.

    missing — нет основного файла или файла из манифеста; changed — размер или SHA-256 не совпали."""
    snap = Path(snap)
    m = meta(snap)
    listed = m.get("manifest")
    missing = [f"raw/{name}" for name in CORE_RAW if not (snap / "raw" / name).is_file()]
    changed = []
    if isinstance(listed, dict):
        for rel, want in sorted(listed.items()):
            path = snap / rel
            if not path.is_file():
                if rel not in missing:
                    missing.append(rel)
            elif path.stat().st_size != (want or {}).get("size") or _sha256(path) != (want or {}).get("sha256"):
                changed.append(rel)
    out = {"finished": bool(m.get("finished")), "manifest": isinstance(listed, dict), "missing": missing,
           "changed": changed}
    out["ok"] = out["finished"] and not missing and not changed
    return out


def problems(check: dict) -> list[str]:
    """Итог verify() человеческим языком; пустой список — всё в порядке."""
    out = []
    if not check.get("finished"):
        out.append("срез прерван: сбор не дошёл до конца, данные неполные")
    if check.get("missing"):
        out.append("нет файлов среза: " + ", ".join(Path(x).name for x in check["missing"]))
    if check.get("changed"):
        out.append("файлы среза изменены после съёмки: " + ", ".join(Path(x).name for x in check["changed"]))
    return out


def network_id(snap: Path, m: dict | None = None) -> dict:
    """Чья это сеть: подсеть и MAC шлюза (по ARP или таблице соседей среза).

    Одной подсети мало: дома и на даче подсеть часто одинаковая (заводская у роутеров) — различает роутер."""
    snap = Path(snap)
    m = meta(snap) if m is None else m
    iface = m.get("interface") or {}
    gw, mac = iface.get("gateway"), None
    for name in ("arp.json", "neighbors.json"):
        if mac or not gw:
            break
        try:
            rows = read_json(snap / "raw" / name, []) or []
        except ValueError:
            rows = []
        mac = next((r.get("mac") for r in rows if isinstance(r, dict) and r.get("ip") == gw and r.get("mac")), None)
    return {"network": iface.get("network"), "gateway_mac": mac.upper().replace("-", ":") if mac else None}


def model_network_id(model: dict) -> dict:
    """То же для собранной модели (devices.json): MAC шлюза — у устройства is_gateway."""
    gw = next((d for d in model.get("devices") or [] if d.get("is_gateway")), None)
    mac = (gw or {}).get("mac")
    return {"network": ((model.get("meta") or {}).get("interface") or {}).get("network"),
            "gateway_mac": mac.upper() if mac else None}


def network_diff(a: dict, b: dict) -> str | None:
    """Чем различаются сети (network_id) → пояснение или None, если это та же сеть.

    Неизвестное с одной стороны — не повод отказать: старые срезы и сети без шлюза."""
    if a.get("network") and b.get("network") and a["network"] != b["network"]:
        return f'другая подсеть: {a["network"]} и {b["network"]}'
    if a.get("gateway_mac") and b.get("gateway_mac") and a["gateway_mac"] != b["gateway_mac"]:
        return f'другой роутер (MAC шлюза {a["gateway_mac"]} и {b["gateway_mac"]})'
    return None
