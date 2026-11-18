"""Пробросы портов из всех источников среза: модуль роутера (главный) и UPnP IGD (без пароля).

Модуль роутера видит и UPnP-, и статические пробросы. IGD — только UPnP, зато без входа в роутер.
Совпадающие записи (ключ — changes._fw_key) не дублируются: остаётся запись роутера.
"""
from __future__ import annotations


def fw_key(f: dict) -> tuple:
    return (f.get("kind"), (f.get("protocol") or "").lower(), str(f.get("port") or ""),
            f.get("to_ip"), str(f.get("to_port") or ""))


def merged(model: dict) -> list[dict]:
    """Все известные пробросы: сначала роутера, потом из IGD, которых у роутера нет."""
    out = list((model.get("router") or {}).get("forwards") or [])
    seen = {fw_key(f) for f in out}
    for f in (model.get("igd") or {}).get("forwards") or []:
        if fw_key(f) not in seen:
            seen.add(fw_key(f))
            out.append(f)
    return out


def upnp_known(model: dict) -> bool:
    """Список UPnP-пробросов известен полностью: есть данные роутера или IGD прочитан до конца."""
    return bool(model.get("router")) or bool((model.get("igd") or {}).get("complete"))


def known_kinds(model: dict) -> set[str]:
    """Какие виды пробросов срез видит целиком (static — только через модуль роутера)."""
    if model.get("router"):
        return {"upnp", "static"}
    return {"upnp"} if upnp_known(model) else set()
