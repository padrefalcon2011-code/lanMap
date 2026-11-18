"""Мелкие общие функции: JSON, время, MAC-адреса, пути к данным."""
from __future__ import annotations

import datetime as _dt
import json
import os
import re
from pathlib import Path
from typing import Any

PACKAGE_DIR = Path(__file__).resolve().parent
REPO_DIR = PACKAGE_DIR.parent


def data_dir() -> Path:
    """Папка личных данных. По умолчанию `data/` рядом с пакетом, можно переопределить LANMAP_DATA."""
    custom = os.environ.get("LANMAP_DATA")
    path = Path(custom) if custom else REPO_DIR / "data"
    path.mkdir(parents=True, exist_ok=True)
    return path


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(Path(path).read_text("utf-8-sig"))
    except FileNotFoundError:
        return default


def write_json(path: Path, data: Any) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(path)


_HEX = re.compile(r"[0-9A-Fa-f]")


def norm_mac(value: str | None) -> str | None:
    """Приводит MAC к виду AA:BB:CC:DD:EE:FF. Пустые, нулевые и широковещательные — None."""
    if not value:
        return None
    digits = "".join(_HEX.findall(str(value)))
    if len(digits) != 12:
        return None
    digits = digits.upper()
    if digits in ("000000000000", "FFFFFFFFFFFF"):
        return None
    first = int(digits[:2], 16)
    if first & 1:  # групповой (multicast) адрес — не устройство
        return None
    return ":".join(digits[i:i + 2] for i in range(0, 12, 2))


def is_private_mac(mac: str | None) -> bool:
    """Локально назначенный (частный/случайный) MAC: второй бит первого байта равен 1."""
    if not mac:
        return False
    return bool(int(mac[:2], 16) & 2)


def oui_prefix(mac: str | None) -> str | None:
    return mac.replace(":", "")[:6] if mac else None
