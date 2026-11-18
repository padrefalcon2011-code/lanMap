"""Из сырых улик среза → модель устройств (devices.json) и HTML-отчёт. Сеть не трогает."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from lanmap import actions, devices, identify, oui, registry
from lanmap.report import render
from lanmap.util import now_iso, read_json, write_json

GROUP_ORDER = ["Сеть", "Компьютеры", "Хранилища", "Камеры", "ТВ и приставки", "Колонки", "Печать",
               "Умный дом", "Телефоны и планшеты", "Не опознаны"]


def _sort_key(dev: dict):
    group = dev["identity"]["group"]
    order = GROUP_ORDER.index(group) if group in GROUP_ORDER else len(GROUP_ORDER)
    return order, ipaddress.ip_address(dev["ips"][0])


def display(dev: dict) -> tuple[str, str]:
    """Заголовок и подзаголовок карточки."""
    ident, reg = dev["identity"], dev.get("registry") or {}
    what = " ".join(x for x in (ident["vendor"], ident["model"]) if x)
    if ident["model"] and ident["vendor"] and ident["vendor"].lower().split(" ")[0] in ident["model"].lower():
        what = ident["model"]
    kind = f"{ident['type_label']} {what}".strip()
    if reg.get("name"):
        return reg["name"], kind
    found_name = ident.get("name")
    return kind, found_name or ""


def build(snapshot: Path) -> dict:
    snapshot = Path(snapshot)
    meta = read_json(snapshot / "meta.json", {})
    reg = registry.load()
    devs = devices.build(snapshot, registry.aliases(reg))
    for dev in devs:
        # У MAC-двойников запись по одному MAC неоднозначна: берём только запись по ключу MAC#серийник
        entry = registry.entry_for(reg, dev["key"], None if dev["duplicate_mac"] else dev["mac"])
        dev["registry"] = entry
        dev["identity"] = identify.resolve(dev, entry)
        dev["actions"] = actions.build(dev)
        dev["title"], dev["subtitle"] = display(dev)
    devs.sort(key=_sort_key)
    model = {
        "built": now_iso(),
        "snapshot": snapshot.name,
        "meta": meta,
        "oui_available": oui.available(),
        "registry_drafts": sum(1 for e in reg["devices"].values() if not e.get("confirmed")),
        "devices": devs,
    }
    write_json(snapshot / "devices.json", model)
    (snapshot / "report.html").write_text(render(model), encoding="utf-8")
    return model
