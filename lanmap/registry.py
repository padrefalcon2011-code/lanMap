"""Реестр владельца: data/registry.json, ключ — MAC.

Подписанное владельцем (confirmed: true) перекрывает любые выводы программы.
Черновики (импорт из среза Codex и т. п.) показываются как предложение до подтверждения.
"""
from __future__ import annotations

import re
from pathlib import Path

from lanmap.util import data_dir, now_iso, norm_mac, read_json, write_json

EDITABLE = ("name", "group", "type", "vendor", "model", "place", "owner", "purpose", "trust", "notes")
TRUST = ("own", "guest", "unknown")

HELP = ("Реестр устройств LanMap. Ключ — MAC. Поля: name (название, например «Камера над калиткой»), "
        "group, type, vendor, model, place, owner, purpose, trust (own/guest/unknown), notes, "
        "also_macs (другие MAC этого же устройства), confirmed (true — подписано владельцем). "
        "Черновики с confirmed=false программа показывает как предложение.")


def registry_path() -> Path:
    return data_dir() / "registry.json"


def load() -> dict:
    data = read_json(registry_path(), None) or {"version": 1, "devices": {}}
    data.setdefault("devices", {})
    return data


def save(data: dict) -> None:
    data["_help"] = HELP
    data["updated"] = now_iso()
    write_json(registry_path(), data)


def aliases(data: dict) -> dict[str, str]:
    """Склейка MAC: вторичный MAC → основной."""
    out = {}
    for mac, entry in data["devices"].items():
        for other in entry.get("also_macs", []):
            other = norm_mac(other)
            if other and other != mac:
                out[other] = mac
    return out


def entry_for(data: dict, key: str | None, mac: str | None = None) -> dict | None:
    """Запись реестра: сначала по ключу устройства (MAC#серийник для MAC-двойников), потом по MAC."""
    for k in (key, mac):
        if k and k in data["devices"]:
            return data["devices"][k]
    return None


def entry_by_ip(data: dict, ips: list[str], exclude: set[str] = frozenset()) -> tuple[str, dict] | None:
    """Запись MAC-двойника (ключ MAC#серийник) по адресу. У камер за мостом и MAC, и серийник плавают от среза
    к срезу, а закреплённый адрес — нет. Только однозначное совпадение; записи с ключами устройств среза
    (exclude) не берём — они уже нашлись по ключу."""
    found = [(k, e) for k, e in data["devices"].items()
             if "#" in k and k not in exclude and set(e.get("ips") or []) & set(ips or [])]
    return found[0] if len(found) == 1 else None


def sign(data: dict, mac: str, fields: dict, confirm: bool = True, ips: list[str] | None = None) -> dict:
    base, sep, serial = mac.partition("#")
    mac = norm_mac(base)
    if not mac:
        raise ValueError("нужен корректный MAC-адрес")
    mac = f"{mac}#{serial}" if sep else mac
    if sep and ips:
        # MAC-двойник: подпись хранит адрес; если устройство уже подписано под прежним ключом — дополняем её
        if mac not in data["devices"]:
            old = entry_by_ip(data, ips)
            if old:
                mac = old[0]
        data["devices"].setdefault(mac, {})["ips"] = list(ips)
    entry = data["devices"].setdefault(mac, {})
    for key, value in fields.items():
        if key not in EDITABLE:
            raise ValueError(f"неизвестное поле реестра: {key}")
        if key == "trust" and value not in TRUST:
            raise ValueError(f"trust: одно из {', '.join(TRUST)}")
        if value is not None:
            entry[key] = value
    if confirm:
        entry["confirmed"] = True
        entry["confirmed_at"] = now_iso()
        entry.setdefault("source", "owner")
    return entry


# ---------- импорт из среза Codex ----------

_CODEX_TYPES = {
    "Камеры": "camera", "Хранилища": "nas", "Колонки": "speaker", "Печать": "printer",
    "Компьютеры": "computer", "Личные устройства": "phone",
}


def _codex_type(group: str, name: str) -> str | None:
    if group == "Сеть":
        return "router" if re.search(r"keenetic|роутер", name, re.I) else "network"
    if group == "ТВ и приставки":
        return "tv" if name.lower().startswith("телевизор") else "media"
    return _CODEX_TYPES.get(group)


def import_codex(data: dict, legacy_dir: Path) -> tuple[int, int]:
    """Черновики реестра из report-data.json среза Codex. Читается во время работы, в код не попадает.

    Возвращает (добавлено, пропущено). Уже существующие записи не трогаются.
    """
    report = read_json(Path(legacy_dir) / "report-data.json")
    if not report:
        raise FileNotFoundError(f"нет report-data.json в {legacy_dir}")
    source = f"codex-{Path(legacy_dir).name.removeprefix('codex-')}"
    added = skipped = 0
    for dev in report.get("devices", []):
        mac = norm_mac(dev.get("mac"))
        name = (dev.get("name") or "").strip()
        conf = dev.get("confidence") or ""
        if not mac or not name or name.startswith("Неизвестное устройство") or conf in ("Не определено",):
            skipped += 1
            continue
        if mac in data["devices"]:
            existing = data["devices"][mac]
            if existing.get("source") == source and dev.get("ip"):
                note = f"Codex видел этот MAC также на {dev['ip']} ({name})"
                if note not in existing.get("notes", ""):
                    existing["notes"] = (existing.get("notes", "") + "\n" + note).strip()
            skipped += 1
            continue
        entry = {
            "name": name,
            "type": _codex_type(dev.get("group", ""), name),
            "notes": f"Codex ({conf}): {dev.get('evidence', '')}".strip(),
            "last_ip_codex": dev.get("ip"),
            "confirmed": False,
            "source": source,
        }
        data["devices"][mac] = {k: v for k, v in entry.items() if v not in (None, "")}
        added += 1
    return added, skipped
