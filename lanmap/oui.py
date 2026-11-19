"""Производитель сетевого интерфейса по MAC (база IEEE OUI).

База хранится локально в data/oui.txt. Скачивается только по явной команде (`lanmap oui update` или кнопка
в веб-интерфейсе): MAC-адреса никуда не отправляются, загружается весь публичный реестр целиком. IEEE
отвечает программам кодом 418, поэтому запасной источник — тот же реестр в зеркале Wireshark (файл manuf,
выложен для автоматической загрузки); он переводится в формат IEEE, остальная программа разницы не видит.
"""
from __future__ import annotations

import re
import shutil
import urllib.request
from functools import lru_cache
from pathlib import Path

from lanmap.util import data_dir, oui_prefix

IEEE_URL = "https://standards-oui.ieee.org/oui/oui.txt"
MIRROR_URL = "https://www.wireshark.org/download/automated/data/manuf"
_MANUF_PREFIX = re.compile(r"[0-9A-F]{2}:[0-9A-F]{2}:[0-9A-F]{2}", re.I)  # 24-битный блок; /28 и /36 не подходят
_LINE = re.compile(r"^([0-9A-F]{6})\s+\(base 16\)\s+(.+?)\s*$", re.M)

_SUFFIXES = re.compile(
    r"[,.]?\s*\b(co\.?,?\s*ltd|co\.?|ltd|inc(orporated)?|corp(oration)?|llc|gmbh|limited|technolog(y|ies)|electronics?|"
    r"communications?|telecom|international|industrial|holdings?|group|digital|network(s|ing)?|"
    r"intelligent|information|science|systems?|s\.?a\.?|ag|bv|oy|ab|pte|plc)\b\.?", re.I)


def oui_path() -> Path:
    return data_dir() / "oui.txt"


@lru_cache(maxsize=1)
def _table() -> dict[str, str]:
    path = oui_path()
    if not path.exists():
        return {}
    return dict(_LINE.findall(path.read_text("utf-8", "replace")))


def available() -> bool:
    return bool(_table())


def count() -> int:
    return len(_table())


def lookup(mac: str | None) -> str | None:
    prefix = oui_prefix(mac)
    return _table().get(prefix) if prefix else None


def short_vendor(name: str | None) -> str | None:
    """«TP-LINK TECHNOLOGIES CO.,LTD.» → «TP-LINK». Для сравнения и подписи."""
    if not name:
        return None
    prev = None
    text = name.strip()
    while prev != text:
        prev = text
        text = _SUFFIXES.sub("", text).replace("()", "").strip(" ,.-()")
    return text or name.strip()


def _download(url: str) -> bytes:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler())
    req = urllib.request.Request(url, headers={"User-Agent": "LanMap"})
    with opener.open(req, timeout=60) as resp:
        return resp.read(30_000_000)


def from_manuf(text: str) -> str:
    """Файл manuf Wireshark → строки в формате IEEE oui.txt. Блоки /28 и /36 пропускаются: их таблица не знает."""
    lines = []
    for raw in text.splitlines():
        cols = [c.strip() for c in raw.split("\t")]
        if len(cols) < 2 or not _MANUF_PREFIX.fullmatch(cols[0]):
            continue
        name = cols[2] if len(cols) > 2 and cols[2] else cols[1]  # полное название, иначе короткое
        if name:
            lines.append(f"{cols[0].replace(':', '').upper()}     (base 16)\t\t{name}")
    return "\n".join(lines) + "\n"


def update(source: str | None = None) -> tuple[Path, int]:
    """Обновить базу: из локального файла (source) или скачать весь реестр IEEE."""
    dest = oui_path()
    tmp = dest.with_suffix(".download")
    if source:
        shutil.copyfile(source, tmp)
    else:
        try:
            tmp.write_bytes(_download(IEEE_URL))
        except OSError as first:
            try:
                tmp.write_text(from_manuf(_download(MIRROR_URL).decode("utf-8", "replace")), "utf-8")
            except OSError as second:
                raise OSError(f"IEEE: {first}; зеркало Wireshark: {second}") from None
    count = len(_LINE.findall(tmp.read_text("utf-8", "replace")))
    if count < 1000:
        tmp.unlink(missing_ok=True)
        raise ValueError(f"файл не похож на базу IEEE OUI (записей: {count})")
    tmp.replace(dest)
    _table.cache_clear()
    return dest, count
