"""Пробросы портов из всех источников среза: модуль роутера (главный) и UPnP IGD (без пароля).

Модуль роутера видит и UPnP-, и статические пробросы. IGD — только UPnP, зато без входа в роутер.
Совпадающие записи (ключ — fw_key ниже; changes берёт его отсюда) не дублируются: остаётся запись роутера.
"""
from __future__ import annotations


def fw_key(f: dict) -> tuple:
    """Ключ проброса: вид, протокол, внешний порт, адрес и порт назначения."""
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


def router_kinds(model: dict) -> set[str]:
    """Виды пробросов, которые модуль роутера прочитал целиком. Упавшее чтение секции не даёт «чисто»."""
    router = model.get("router")
    if not router:
        return set()
    return set(router.get("forward_kinds", ("upnp", "static")))


def upnp_known(model: dict) -> bool:
    """Список UPnP-пробросов известен полностью: роутер прочитал их секцию или IGD прочитан до конца."""
    return "upnp" in router_kinds(model) or bool((model.get("igd") or {}).get("complete"))


def known_kinds(model: dict) -> set[str]:
    """Какие виды пробросов срез видит целиком (static — только через модуль роутера)."""
    return router_kinds(model) | ({"upnp"} if upnp_known(model) else set())
