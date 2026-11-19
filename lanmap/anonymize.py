"""Вторая линия обезличивания текста для публичных заявок: UUID, MAC, IPv4 и похожие на токены строки.

Первая линия — белый список полей у того, кто собирает текст (`share.py`, `routers/probe.py`).
Эта функция ловит то, что просочилось внутри разрешённых строк (IP в баннере, MAC в имени).
"""
from __future__ import annotations

import re

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-]?[0-9A-Fa-f]{2}){5}\b")
_UUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
# «=» только как хвост base64: иначе «Model=AB123_…» склеивается с ключом и модель принимается за токен
_TOKENISH = re.compile(r"\b(?=[A-Za-z0-9+/_-]*\d)(?=[A-Za-z0-9+/_-]*[A-Za-z])[A-Za-z0-9+/_-]{24,}={0,2}")


def anonymize(text: str) -> str:
    text = _UUID.sub("<uuid>", text)
    text = _MAC.sub("<mac>", text)
    text = _IPV4.sub("<ip>", text)
    return _TOKENISH.sub("<token>", text)
