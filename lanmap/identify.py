"""Опознание: от улик к выводу «что это за устройство» с уверенностью и объяснением.

Порядок приоритета (концепция, 4.3): реестр владельца → самоописание устройства → правила
по баннерам и портам → производитель по MAC. Противоречия не скрываются, а показываются.
"""
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

from lanmap import oui
from lanmap.util import PACKAGE_DIR, data_dir, read_json, read_state

LEVELS = {"exact": 4, "high": 3, "guess": 2, "weak": 1}
LEVEL_NAMES = {4: "точно", 3: "высокая", 2: "предположение", 1: "слабая догадка", 0: "неизвестно"}

TYPES = {
    "router": "Роутер",
    "network": "Сетевое устройство",
    "camera": "Камера",
    "nas": "Сетевое хранилище",
    "tv": "Телевизор",
    "media": "ТВ-приставка / медиаплеер",
    "speaker": "Умная колонка",
    "printer": "Принтер / МФУ",
    "computer": "Компьютер",
    "phone": "Телефон / планшет",
    "wearable": "Часы / браслет",
    "iot": "Умный дом",
    "unknown": "Неопознанное устройство",
}

GROUPS = {
    "router": "Сеть", "network": "Сеть", "camera": "Камеры", "nas": "Хранилища", "tv": "ТВ и приставки",
    "media": "ТВ и приставки", "speaker": "Колонки", "printer": "Печать", "computer": "Компьютеры",
    "phone": "Телефоны и планшеты", "wearable": "Телефоны и планшеты", "iot": "Умный дом",
    "unknown": "Не опознаны",
}

FIELDS = ("type", "vendor", "model", "firmware", "os", "name")


def rules_files() -> list[Path]:
    """Поставляемая база + пользовательская (data/fingerprints/*.json), если есть."""
    files = sorted((PACKAGE_DIR / "fingerprints").glob("*.json"))
    user = data_dir() / "fingerprints"
    if user.exists():
        files += sorted(user.glob("*.json"))
    return files


@lru_cache(maxsize=1)
def load_rules() -> tuple[dict, ...]:
    rules: list[dict] = []
    for path in rules_files():
        # свои правила владельца — состояние: испорченный файл копируется рядом (util.read_state)
        data = (read_json(path) if path.parent == PACKAGE_DIR / "fingerprints" else read_state(path)) or {}
        for rule in data.get("rules", []):
            rule = dict(rule, _file=path.name)
            rules.append(rule)
    return tuple(rules)


# ---------- проверка условий ----------

def _rx(pattern: str, value) -> bool:
    if value is None:
        return False
    values = value if isinstance(value, (list, tuple, set)) else [value]
    return any(re.search(pattern, str(v)) for v in values if v not in (None, ""))


def _http_texts(facts: dict) -> list[str]:
    out = []
    for h in facts.get("http", []):
        out += [h.get("server", ""), h.get("title", ""), h.get("realm", ""), h.get("body", "")[:4000]]
    for c in facts.get("tls", []):
        out += [str(c.get("subject", "")), str(c.get("issuer", ""))]
    return out


def _cond(key: str, expected, dev: dict) -> bool:
    f = dev["facts"]
    ports = set(f.get("ports", []))
    if key == "is_local":
        return dev.get("is_local") == expected
    if key == "is_gateway":
        return dev.get("is_gateway") == expected
    if key == "private_mac":
        return bool(f.get("private_mac")) == expected
    if key == "no_ports":
        return (not ports) == expected
    if key == "port":
        return bool(ports & set(expected))
    if key == "ports_all":
        return set(expected) <= ports
    if key == "oui":
        return _rx(expected, f.get("oui"))
    if key == "upnp":
        u = f.get("upnp", {})
        return all(_rx(rx, u.get(field)) for field, rx in expected.items())
    if key == "onvif":
        return bool(f.get("onvif", {}).get(expected))
    if key == "mdns_service":
        return _rx(expected, f.get("mdns_services"))
    if key == "mdns_txt":
        t = f.get("mdns_txt", {})
        return all(_rx(rx, t.get(k)) for k, rx in expected.items())
    if key == "http_text":
        return _rx(expected, _http_texts(f))
    if key == "http_server":
        return _rx(expected, [h.get("server") for h in f.get("http", [])])
    if key == "rtsp":
        return _rx(expected, f.get("rtsp"))
    if key == "ssdp_server":
        return _rx(expected, f.get("ssdp_server"))
    if key == "wsd_type":
        return _rx(expected, f.get("wsd_types"))
    if key == "ssh":
        return _rx(expected, f.get("ssh"))
    if key == "hostname":
        nb = (f.get("netbios") or {}).get("computer")
        r = f.get("router") or {}
        return _rx(expected, list(f.get("mdns_hosts", [])) + list(f.get("dns", [])) + list(f.get("router_names", []))
                   + [nb, r.get("hostname"), r.get("label")])
    raise ValueError(f"неизвестное условие в правиле: {key}")


def _all(conds: dict, dev: dict) -> bool:
    return all(_cond(k, v, dev) for k, v in conds.items())


def rule_matches(rule: dict, dev: dict) -> bool:
    if rule.get("if") and not _all(rule["if"], dev):
        return False
    if rule.get("if_any") and not any(_all(c, dev) for c in rule["if_any"]):
        return False
    if rule.get("if_not") and _all(rule["if_not"], dev):
        return False
    return bool(rule.get("if") or rule.get("if_any"))


_TPL = re.compile(r"\{(\w+)\.([\w-]+)\}")


def _render(template: str, facts: dict) -> str | None:
    """«{onvif.Model}» → значение факта. Если факта нет — None (поле не заполняется)."""
    missing = False

    def sub(m: re.Match) -> str:
        nonlocal missing
        section = facts.get(m[1]) or {}
        value = section.get(m[2]) if isinstance(section, dict) else None
        if isinstance(value, list):
            value = value[0] if value else None
        if not value:
            missing = True
            return ""
        return str(value)

    result = _TPL.sub(sub, template).strip()
    return None if missing or not result else result


# ---------- сбор утверждений ----------

def _claim(field: str, value, level: int, source: str, why: str) -> dict:
    return {"field": field, "value": value, "level": level, "source": source, "why": why}


# Заглушки, которые прошивки пишут вместо производителя/модели (например, камеры XM пишут «H264»).
_PLACEHOLDER = re.compile(r"^(h\.?26[45]|ipc(am)?|nvt|onvif|general|generic|manufacturer|model|default|unknown|"
                          r"null|none|n/?a|-+|0+|test|linux|ubuntu|android)$", re.I)
_JUNK_NAMES = re.compile(r"(^|\.)(docker|kubernetes)\.internal$|^localhost$", re.I)


def _meaningful(value) -> bool:
    return bool(value) and not _PLACEHOLDER.match(str(value).strip())


def self_description_claims(dev: dict) -> list[dict]:
    """То, что устройство сообщает о себе само (UPnP, ONVIF, mDNS TXT, NetBIOS, имена)."""
    f = dev["facts"]
    claims = []
    u = f.get("upnp", {})
    first = lambda k: (u.get(k) or [None])[0]  # noqa: E731
    if _meaningful(first("manufacturer")):
        claims.append(_claim("vendor", first("manufacturer"), 4, "upnp", "Производитель из UPnP-описания"))
    if _meaningful(first("modelName")):
        model, number = first("modelName"), first("modelNumber")
        if number and number.startswith(model + " "):
            rest = number[len(model):].strip()
            claims.append(_claim("firmware", rest, 3, "upnp", "Версия из UPnP modelNumber (вероятно, прошивка)"))
        elif number and number not in model and model not in number:
            model = f"{model} {number}"
        claims.append(_claim("model", model, 4, "upnp", "Модель из UPnP-описания"))
    if first("friendlyName"):
        claims.append(_claim("name", first("friendlyName"), 3, "upnp", "Имя из UPnP-описания"))
    o = f.get("onvif", {})
    if _meaningful(o.get("Manufacturer")):
        claims.append(_claim("vendor", o["Manufacturer"], 4, "onvif", "Производитель из ONVIF"))
    if o.get("Model"):
        claims.append(_claim("model", o["Model"], 4, "onvif", "Модель из ONVIF"))
    if o.get("FirmwareVersion"):
        claims.append(_claim("firmware", o["FirmwareVersion"], 4, "onvif", "Прошивка из ONVIF"))
    t = f.get("mdns_txt", {})
    if t.get("usb_mfg"):
        claims.append(_claim("vendor", t["usb_mfg"], 4, "mdns", "Производитель из mDNS (usb_MFG)"))
    for key in ("ty", "usb_mdl", "md", "model"):
        if t.get(key) and not re.fullmatch(r"[0-9A-F]{6,}|Xserve|MacSamba", t[key], re.I):
            claims.append(_claim("model", t[key], 4, "mdns", f"Модель из mDNS ({key})"))
            break
    if t.get("fn"):
        claims.append(_claim("name", t["fn"], 3, "mdns", "Имя из mDNS (fn)"))
    r = f.get("router") or {}
    if r.get("label"):
        claims.append(_claim("name", r["label"], 4, "router", "Подпись владельца в роутере"))
    if r.get("hostname"):
        claims.append(_claim("name", r["hostname"], 2, "dhcp", "Имя, сообщённое роутеру по DHCP"))
    nb = f.get("netbios") or {}
    if nb.get("computer"):
        claims.append(_claim("name", nb["computer"], 3, "netbios", "Имя компьютера NetBIOS"))
    for host in f.get("mdns_hosts", []):
        claims.append(_claim("name", host.removesuffix(".local"), 2, "mdns", "Имя mDNS"))
    for host in f.get("router_names", []):
        claims.append(_claim("name", host, 2, "router_dns", "Имя в DNS роутера"))
    for host in f.get("dns", []):
        if _JUNK_NAMES.search(host):
            continue
        claims.append(_claim("name", host, 1, "dns", "Обратный DNS"))
    for inst in f.get("mdns_instances", []):
        claims.append(_claim("name", inst, 1, "mdns", "Имя экземпляра службы mDNS"))
    return claims


def rule_claims(dev: dict) -> tuple[list[dict], list[str]]:
    claims, matched = [], []
    for rule in load_rules():
        if not rule_matches(rule, dev):
            continue
        matched.append(rule["id"])
        level = LEVELS.get(rule.get("level", "guess"), 2)
        for field, template in (rule.get("then") or {}).items():
            value = _render(template, dev["facts"]) if "{" in template else template
            if value:
                claims.append(_claim(field, value, level, f"rule:{rule['id']}", rule.get("why", "")))
    return claims, matched


def oui_claims(dev: dict) -> list[dict]:
    vendor = dev["facts"].get("oui")
    if not vendor:
        return []
    return [_claim("vendor", oui.short_vendor(vendor), 1, "oui", "Производитель сетевого чипа по MAC (не всегда производитель устройства)")]


def registry_claims(entry: dict | None) -> list[dict]:
    if not entry:
        return []
    confirmed = bool(entry.get("confirmed"))
    level = 5 if confirmed else 2
    source = "registry" if confirmed else f"registry-draft:{entry.get('source', '?')}"
    why = "Подписано владельцем в реестре" if confirmed else f"Черновик реестра ({entry.get('source', 'импорт')}), не подтверждён владельцем"
    return [_claim(f, entry[f], level, source, why) for f in FIELDS if entry.get(f)]


# ---------- итог ----------

def _vendor_key(value: str) -> str:
    short = (oui.short_vendor(value) or value).lower()
    short = re.sub(r"[^a-zа-я0-9]+", " ", short).strip()
    return short.split(" ")[0] if short else ""


def resolve(dev: dict, registry_entry: dict | None = None) -> dict:
    reg = registry_claims(registry_entry)
    self_desc = self_description_claims(dev)
    rules, matched = rule_claims(dev)
    weak = oui_claims(dev)
    claims = reg + self_desc + rules + weak  # порядок = приоритет при равном уровне

    chosen: dict[str, dict] = {}
    for c in claims:
        best = chosen.get(c["field"])
        if best is None or c["level"] > best["level"]:
            chosen[c["field"]] = c

    conflicts, notes = [], []
    vendor = chosen.get("vendor")
    if vendor:
        vkey = _vendor_key(vendor["value"])
        seen = set()
        for c in claims:
            if c["field"] != "vendor" or c is vendor or c["source"].startswith("registry"):
                continue
            ckey = _vendor_key(c["value"])
            if not ckey or ckey in seen or ckey == vkey or ckey in vkey or vkey in ckey:
                continue
            seen.add(ckey)
            text = f"{c['why']}: «{c['value']}», а итог — «{vendor['value']}»"
            if c["source"] == "oui":
                notes.append(text + ". Обычно это сетевой модуль другого производителя.")
            elif c["level"] >= 3 and vendor["level"] >= 3:
                conflicts.append(text)
    dtype = chosen.get("type")
    if dtype:
        rivals = {c["value"]: c for c in claims if c["field"] == "type" and c["value"] != dtype["value"]
                  and c["level"] >= 3 and c["level"] == dtype["level"] and not c["source"].startswith("registry")}
        for c in rivals.values():
            conflicts.append(f"Правила расходятся в типе: «{TYPES.get(c['value'], c['value'])}» ({c['source']}) "
                             f"и «{TYPES.get(dtype['value'], dtype['value'])}» ({dtype['source']})")

    if dev.get("duplicate_mac"):
        conflicts.append("Один MAC у нескольких устройств с разными серийными номерами. Два объяснения: одно устройство "
                         "подключено через другое (Wi-Fi-камеры часто ретранслируют соседей — тогда виден MAC "
                         "ретранслятора), или у них одинаковый MAC. Как различить: выключи одно из них и посмотри, "
                         "пропадёт ли второй адрес или сменится его MAC.")

    type_level = dtype["level"] if dtype else 0
    model_level = chosen["model"]["level"] if chosen.get("model") else 0
    if registry_entry and registry_entry.get("confirmed"):
        confidence = 4
    elif type_level >= 3 and model_level >= 4:
        confidence = 4
    elif type_level >= 3:
        confidence = 3
    elif type_level == 2:
        confidence = 2
    elif type_level == 1 or chosen.get("vendor"):
        confidence = 1
    else:
        confidence = 0

    type_value = dtype["value"] if dtype else "unknown"
    return {
        "type": type_value,
        "type_label": TYPES.get(type_value, type_value),
        "group": (registry_entry or {}).get("group") if (registry_entry or {}).get("confirmed") and registry_entry.get("group")
        else GROUPS.get(type_value, "Не опознаны"),
        "vendor": vendor["value"] if vendor else None,
        "model": chosen["model"]["value"] if chosen.get("model") else None,
        "firmware": chosen["firmware"]["value"] if chosen.get("firmware") else None,
        "os": chosen["os"]["value"] if chosen.get("os") else None,
        "name": chosen["name"]["value"] if chosen.get("name") else None,
        "confidence": confidence,
        "confidence_label": LEVEL_NAMES[min(confidence, 4)],
        "chosen": {k: {"value": v["value"], "source": v["source"], "level": v["level"], "why": v["why"]} for k, v in chosen.items()},
        "rules": matched,
        "conflicts": conflicts,
        "notes": notes,
        "claims": claims,
    }
