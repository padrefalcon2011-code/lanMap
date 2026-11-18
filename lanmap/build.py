"""Из сырых улик среза → модель устройств (devices.json) и HTML-отчёт. Сеть не трогает."""
from __future__ import annotations

import ipaddress
from pathlib import Path

from lanmap import actions, changes, checklist, devices, identify, oui, registry, routers, security
from lanmap.collectors import igd
from lanmap.report import render
from lanmap.util import now_iso, read_json, write_json

OFFLINE = "Сейчас не в сети (известны роутеру)"
GROUP_ORDER = ["Сеть", "Компьютеры", "Хранилища", "Камеры", "ТВ и приставки", "Колонки", "Печать",
               "Умный дом", "Телефоны и планшеты", "Не опознаны", OFFLINE]


def _sort_key(dev: dict):
    group = dev["identity"]["group"]
    order = GROUP_ORDER.index(group) if group in GROUP_ORDER else len(GROUP_ORDER)
    first = ipaddress.ip_address(dev["ips"][0]) if dev["ips"] else ipaddress.ip_address("255.255.255.255")
    return order, first, dev["title"].lower()


def display(dev: dict) -> tuple[str, str]:
    """Заголовок и подзаголовок карточки."""
    ident, reg = dev["identity"], dev.get("registry") or {}
    what = " ".join(x for x in (ident["vendor"], ident["model"]) if x)
    if ident["model"] and ident["vendor"] and ident["vendor"].lower().split(" ")[0] in ident["model"].lower():
        what = ident["model"]
    kind = f"{ident['type_label']} {what}".strip()
    if reg.get("name") and (reg.get("confirmed") or not (dev.get("router") or {}).get("label")):
        return reg["name"], kind
    label = (dev.get("router") or {}).get("label")
    if label:
        return label, kind
    found_name = ident.get("name")
    return kind, found_name or ""


def make_model(snapshot: Path, reg: dict | None = None) -> dict:
    """Модель среза по текущим правилам и реестру. Ничего не записывает."""
    snapshot = Path(snapshot)
    meta = read_json(snapshot / "meta.json", {})
    reg = reg if reg is not None else registry.load()
    devs = devices.build(snapshot, registry.aliases(reg))
    keys = {d["key"] for d in devs}
    for dev in devs:
        # У MAC-двойников запись по одному MAC неоднозначна: берём только запись по ключу MAC#серийник,
        # а если ключ сменился — по закреплённому адресу
        entry = registry.entry_for(reg, dev["key"], None if dev["duplicate_mac"] else dev["mac"])
        if entry is None and dev["duplicate_mac"]:
            found = registry.entry_by_ip(reg, dev["ips"], exclude=keys)
            entry = found[1] if found else None
        dev["registry"] = entry
        dev["identity"] = identify.resolve(dev, entry)
        dev["actions"] = actions.build(dev)
        dev["title"], dev["subtitle"] = display(dev)
        if not dev["alive"] and dev.get("router"):
            dev["identity"]["group"] = OFFLINE
    devs.sort(key=_sort_key)
    model = {
        "built": now_iso(),
        "snapshot": snapshot.name,
        "meta": meta,
        "oui_available": oui.available(),
        "registry_drafts": sum(1 for e in reg["devices"].values() if not e.get("confirmed")),
        "router": routers.normalize(read_json(snapshot / "raw" / "router.json")),
        "router_skipped": (read_json(snapshot / "raw" / "router.json") or {}).get("skipped"),
        # UPnP-пробросы, прочитанные у шлюза без пароля (в старых срезах файла нет — тогда None)
        "igd": igd.normalize(read_json(snapshot / "raw" / "upnp_igd.json")),
        "devices": devs,
    }
    model["security"] = security.evaluate(model, snapshot, changes.tested_ports(snapshot))
    model["checklist"] = checklist.evaluate(model)
    return model


def build(snapshot: Path, baseline: Path | None = None) -> dict:
    """Модель + сравнение с прошлым (или указанным) срезом → devices.json и report.html в папке среза."""
    snapshot = Path(snapshot)
    reg = registry.load()
    model = make_model(snapshot, reg)
    baseline = Path(baseline) if baseline else changes.previous_snapshot(snapshot)
    model["changes"] = None
    if baseline and baseline.resolve() != snapshot.resolve():
        try:
            # Старый срез пересобирается текущими правилами: иначе улучшение правил выглядело бы как «изменение» в сети
            old = make_model(baseline, reg)
            model["changes"] = changes.compare(old, model, changes.tested_ports(baseline), changes.tested_ports(snapshot))
        except Exception as exc:  # сравнение — дополнительный блок, отчёт без него всё равно нужен
            model["changes"] = {"error": f"Не удалось сравнить со срезом {baseline.name}: {exc}", "baseline": baseline.name}
    write_json(snapshot / "devices.json", model)
    (snapshot / "report.html").write_text(render(model), encoding="utf-8")
    return model
