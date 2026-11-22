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


_CHOSEN: Path | None = None  # где лежат данные, решается один раз за запуск


def _protected(root: Path) -> bool:
    """Папка программы в Program Files или Windows. Туда пишет только администратор, поэтому от того,
    как запустили программу, зависело бы, куда попадут данные. Такие папки не используем вовсе."""
    for var in ("ProgramFiles", "ProgramW6432", "ProgramFiles(x86)", "windir"):
        base = os.environ.get(var)
        if base and root.resolve().is_relative_to(Path(base).resolve()):
            return True
    return False


def local_data_dir() -> Path:
    base = os.environ.get("LOCALAPPDATA")
    return (Path(base) if base else Path.home() / "AppData" / "Local") / "LanMap" / "data"


def _choose(root: Path) -> Path:
    """`data/` рядом с программой (переезжает вместе с папкой). Если программа лежит в Program Files или
    папку нельзя записать (флешка только для чтения) — %LOCALAPPDATA%/LanMap/data."""
    if _protected(root):
        return local_data_dir()
    path = root / "data"
    try:
        path.mkdir(parents=True, exist_ok=True)
        test = path / ".write-test"
        test.write_bytes(b"")
        test.unlink()
        return path
    except OSError:
        return local_data_dir()


def data_dir() -> Path:
    """Папка личных данных: LANMAP_DATA, иначе `data/` рядом с программой, иначе %LOCALAPPDATA%."""
    global _CHOSEN
    custom = os.environ.get("LANMAP_DATA")
    if custom:
        path = Path(custom)
    else:
        if _CHOSEN is None:
            _CHOSEN = _choose(REPO_DIR)
        path = _CHOSEN
    path.mkdir(parents=True, exist_ok=True)
    return path


def now_iso() -> str:
    return _dt.datetime.now().astimezone().isoformat(timespec="seconds")


class UserError(ValueError):
    """Понятная человеку ошибка: командная строка печатает её, сервер отдаёт кодом 400 (ops.OpError — она же)."""


class BadJSON(UserError):
    """Файл есть, но это не JSON (испорчен, недописан, не UTF-8). В тексте — путь и место ошибки."""

    def __init__(self, path: Path, reason: str, backup: Path | None = None):
        self.path, self.reason, self.backup = Path(path), reason, backup
        text = f"Файл {self.path} повреждён: {reason}."
        if backup:
            text += (f" Копия испорченного файла: {backup}. Исправь файл или удали его — тогда программа начнёт"
                     " с пустого. Пока он повреждён, LanMap его не перезаписывает.")
        super().__init__(text)


def _parse(path: Path) -> Any:
    try:
        return json.loads(path.read_text("utf-8-sig"))
    except UnicodeDecodeError:
        raise BadJSON(path, "это не текст UTF-8") from None
    except json.JSONDecodeError as exc:
        raise BadJSON(path, f"строка {exc.lineno}, столбец {exc.colno}: {exc.msg}") from None


def read_json(path: Path, default: Any = None) -> Any:
    """JSON из файла; нет файла — default. Испорченный файл — BadJSON с путём и местом ошибки."""
    try:
        return _parse(Path(path))
    except FileNotFoundError:
        return default


def _backup(path: Path) -> Path:
    """Копия испорченного файла рядом: <имя>.broken-<время><расширение>. Такая же копия уже есть — её и вернуть."""
    body = path.read_bytes()
    for old in sorted(path.parent.glob(f"{path.stem}.broken-*{path.suffix}")):
        try:
            if old.read_bytes() == body:
                return old
        except OSError:
            continue
    stamp = _dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    out = path.with_name(f"{path.stem}.broken-{stamp}{path.suffix}")
    n = 2
    while out.exists():
        out = path.with_name(f"{path.stem}.broken-{stamp}-{n}{path.suffix}")
        n += 1
    out.write_bytes(body)
    return out


def read_state(path: Path, default: Any = None) -> Any:
    """Состояние владельца (реестр, отметки, свои правила): как read_json, но испорченный файл сначала
    копируется рядом (_backup), а ошибка называет копию. Пустым он не заменяется: все записи состояния
    читают файл перед записью, и ошибка чтения останавливает запись."""
    path = Path(path)
    try:
        return read_json(path, default)
    except BadJSON as exc:
        try:
            backup = _backup(path)
        except OSError:
            raise exc from None
        raise BadJSON(path, exc.reason, backup) from None


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
