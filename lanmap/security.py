"""Проверки безопасности по данным среза. Сеть не трогает: только то, что срез уже собрал.

Проверка — запись в CHECKS: идентификатор, приоритет, критерий E1–E9, «кто может воспользоваться»
(интернет или любой внутри сети), «что под угрозой», риск человеческим языком и инструкция
(шаги, что может сломаться, как вернуть, как убедиться). Функция detect(ctx) возвращает находки.

У проверки три исхода: нашла / чисто / нечем проверить (например, в срезе нет данных роутера).
Третий нужен, чтобы сравнение срезов не выдумывало «появилась» и «исправлена».

Статусы находок (в работе, исправлена, принята осознанно, не применимо) — в data/findings.json
по ключу «проверка|ключ устройства». Если исправленная находка снова видна в срезе, сделанном
после отметки, — это регресс.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Callable

from lanmap import forwards as fw_mod
from lanmap.util import data_dir, now_iso, read_json, write_json

PRIORITY_NAMES = {1: "П1 срочно", 2: "П2 важно", 3: "П3 желательно"}
CONFIDENCE_NAMES = {"confirmed": "подтверждено", "likely": "вероятно", "verify": "требует проверки"}
WHO_NAMES = {"internet": "любой из интернета", "lan": "любой внутри твоей сети"}
STAKE_NAMES = {"files": "файлы", "video": "видео с камер", "network": "вся сеть и интернет в доме",
               "device": "само устройство", "passwords": "пароли"}
CRITERIA = {
    "E1": "все устройства опознаны и подписаны",
    "E2": "снаружи внутрь ничего не открыто",
    "E3": "камеры и умный дом отделены от ПК и NAS",
    "E4": "нет устаревших и небезопасных протоколов",
    "E5": "нет лишних служб",
    "E6": "прошивки актуальны",
    "E7": "отладочные входы выключены",
    "E8": "есть проверенная резервная копия",
    "E9": "адреса важных устройств закреплены",
}
STATUSES = {
    "open": "открыта",
    "in_progress": "в работе",
    "fixed": "исправлена",
    "accepted": "принята осознанно",
    "na": "не применимо",
}
# Находки с такими статусами не считаются «открытыми» (не попадают в счётчик и в красную зону)
QUIET_STATUSES = {"accepted", "na"}

NAS_EXTRA_PORTS = {3306: "MySQL/MariaDB (база данных)", 2049: "NFS (общие папки без учётных записей)",
                   111: "RPC (служба для NFS)", 548: "AFP (общие папки для старых Mac)", 21: "FTP (пароль открытым текстом)"}
CAMERA_TYPES = {"camera"}
SMB_DIALECTS = {"0x202": "2.0.2", "0x210": "2.1", "0x300": "3.0", "0x302": "3.0.2", "0x311": "3.1.1"}


@dataclass
class Ctx:
    """Что известно проверкам: модель среза и сырые файлы."""
    model: dict
    raw: Path
    tested: set[int] | None

    @property
    def devices(self) -> list[dict]:
        return self.model["devices"]

    def raw_exists(self, name: str) -> bool:
        return (self.raw / name).exists()

    def port_checked(self, port: int) -> bool:
        return self.tested is None or port in self.tested


@dataclass
class Check:
    id: str
    title: str          # коротко, для заголовка карточки
    icon: str           # служебная иконка или иконка типа устройства
    priority: int
    criteria: list[str]
    who: str            # internet | lan
    stake: list[str]
    risk: str           # «чем плохо» — одна-две фразы для обычного человека
    steps: list[str]
    breaks: str         # что может сломаться
    rollback: str       # как вернуть
    verify: str         # как убедиться, что исправлено
    detect: Callable[[Ctx], tuple[bool, list[dict]]] = field(repr=False)
    # Инфографика карточки. Узел схемы: (иконка, подпись, пояснение, тон crit|warn|""); иконка "@dev" —
    # место для устройств находки. Стрелка между узлами: (подпись, "r" — вправо | "l" — влево);
    # "{forwards}" в подписи заменяется числом пробросов.
    scheme: list[tuple[str, str, str, str]] = field(default_factory=list)
    links: list[tuple[str, str]] = field(default_factory=list)
    threat: list[tuple[str, str]] = field(default_factory=list)   # (иконка, 2–3 слова): чем кончится
    todo: list[tuple[str, str]] = field(default_factory=list)     # (иконка, коротко): общий план; "@dev" — иконка устройства
    note: str = ""      # мелкая оговорка (чего LanMap не проверял)
    # Инструкция «куда зайти, что нажать» для конкретного устройства: steps — общая, vendor_steps — вместо
    # неё, если производитель устройства содержит ключ. router_steps — добавка про роутер (по марке роутера).
    vendor_steps: dict[str, list[str]] = field(default_factory=dict)
    router_steps: dict[str, list[str]] = field(default_factory=dict)  # ключ "" — общая
    needs: str = ""     # чего не хватает, если проверить нечем


def _hit(dev: dict, detail: str, confidence: str = "confirmed", port: int | None = None, priority: int | None = None,
         extra: dict | None = None) -> dict:
    out = {"key": dev["key"], "ips": dev["ips"], "title": dev.get("title") or dev["key"],
           "type": (dev.get("identity") or {}).get("type") or "unknown",
           "vendor": (dev.get("identity") or {}).get("vendor"),
           "detail": detail, "confidence": confidence}
    if port is not None:
        out["port"] = port
    if priority is not None:
        out["priority"] = priority
    if extra:
        out.update(extra)
    return out


def _ports(dev: dict) -> set[int]:
    return {s["port"] for s in dev.get("services") or []}


def _port_check(port: int, types: set[str] | None = None, confidence: str = "likely"):
    def detect(ctx: Ctx) -> tuple[bool, list[dict]]:
        if not ctx.port_checked(port):
            return False, []
        hits = [_hit(d, f"порт {port} открыт", confidence, port=port) for d in ctx.devices
                if d["alive"] and port in _ports(d) and (types is None or d["identity"].get("type") in types)]
        return True, hits
    return detect


# --- проверки ------------------------------------------------------------------------------

def _upnp(ctx: Ctx) -> tuple[bool, list[dict]]:
    # Источник — модуль роутера или UPnP IGD, прочитанный до конца (неполный список не даёт «чисто»)
    if not fw_mod.upnp_known(ctx.model):
        return False, []
    # Внешний адрес роутера из сети провайдера (или за вторым роутером) — снаружи двери, скорее всего, не видны
    # Тогда находка «вероятно» и П2: срочности нет, но закрыть стоит — провайдер может выдать «белый» адрес
    reach = (ctx.model.get("igd") or {}).get("external_scope")
    behind_nat = reach in ("cgnat", "private")
    by_ip = {ip: d for d in ctx.devices for ip in d["ips"]}
    groups: dict[str, list[dict]] = {}
    for f in fw_mod.merged(ctx.model):
        if f.get("kind") == "upnp":
            groups.setdefault(f.get("to_ip") or "?", []).append(f)
    hits = []
    for ip, fws in groups.items():
        dev = by_ip.get(ip) or {"key": f"ip:{ip}", "ips": [ip], "title": ip, "identity": {"type": "unknown"}}
        ports = ", ".join(f'{f.get("port")}→{f.get("to_port")}' for f in fws)
        hits.append(_hit(dev, f"пробросов из интернета: {len(fws)} ({ports})",
                         "likely" if behind_nat else "confirmed", priority=2 if behind_nat else None,
                         extra={"router_based": True, "reach": reach,
                                "forwards": [f'{(f.get("protocol") or "").upper()} {f.get("port")}→{f.get("to_port")}'
                                             for f in fws]}))
    return True, hits


def _telnet(ctx: Ctx) -> tuple[bool, list[dict]]:
    if not ctx.port_checked(23):
        return False, []
    hits = []
    for d in ctx.devices:
        if d["alive"] and 23 in _ports(d):
            router_like = d["is_gateway"] or d["identity"].get("type") in ("router", "network")
            hits.append(_hit(d, "порт 23 (Telnet) открыт", "confirmed", port=23, priority=1 if router_like else 2))
    return True, hits


def _adb(ctx: Ctx) -> tuple[bool, list[dict]]:
    if not ctx.port_checked(5555):
        return False, []
    hits = []
    for d in ctx.devices:
        if not d["alive"]:
            continue
        mdns = {str(s).lower() for s in (d.get("facts") or {}).get("mdns_services") or []}
        announced = any("_adb" in s for s in mdns)
        if 5555 in _ports(d) or announced:
            hits.append(_hit(d, "порт 5555 (ADB) открыт" + (", устройство само объявляет ADB" if announced else ""),
                             "confirmed" if announced else "likely", port=5555 if 5555 in _ports(d) else None))
    return True, hits


def _onvif_anon(ctx: Ctx) -> tuple[bool, list[dict]]:
    if not ctx.raw_exists("onvif.json"):
        return False, []
    hits = []
    for d in ctx.devices:
        o = (d.get("facts") or {}).get("onvif") or {}
        if d["alive"] and o.get("anonymous"):
            shown = ", ".join(str(o[k]) for k in ("Model", "FirmwareVersion") if o.get(k))
            hits.append(_hit(d, "без пароля выдаёт сведения о себе" + (f": {shown}" if shown else ""), "confirmed"))
    return True, hits


def _nas_extra(ctx: Ctx) -> tuple[bool, list[dict]]:
    checked = [p for p in NAS_EXTRA_PORTS if ctx.port_checked(p)]
    if not checked:
        return False, []
    hits = []
    for d in ctx.devices:
        if d["alive"] and d["identity"].get("type") == "nas":
            found = sorted(p for p in checked if p in _ports(d))
            if found:
                hits.append(_hit(d, "открыто: " + ", ".join(f"{p} {NAS_EXTRA_PORTS[p].split(' (')[0]}" for p in found),
                                 "verify", extra={"ports": found}))
    return True, hits


def _smb_signing(ctx: Ctx) -> tuple[bool, list[dict]]:
    if not ctx.raw_exists("smb.json"):
        return False, []
    hits = []
    for d in ctx.devices:
        s = (d.get("facts") or {}).get("smb") or {}
        if d["alive"] and not d["is_local"] and s.get("status") == "0x0" and s.get("signing_required") is False:
            hits.append(_hit(d, f'SMB {SMB_DIALECTS.get(str(s.get("dialect")), s.get("dialect", "?"))}: подпись {"включена, но " if s.get("signing_enabled") else ""}'
                                "не обязательна", "confirmed"))
    return True, hits


CHECKS: list[Check] = [
    Check(
        id="UPNP_PORT_MAPPINGS", title="Устройство само открыло себе дверь из интернета", icon="globe", priority=1,
        criteria=["E2"], who="internet", stake=["files", "device"],
        risk="Через UPnP устройство попросило роутер пробросить к нему порты, и тебя никто не спросил. Теперь его "
             "страницу входа и службы видно из интернета. Боты круглосуточно перебирают все адреса в мире и ищут как раз "
             "такие двери: подбирают пароли и пробуют известные дыры. У NAS итог обычно один: файлы шифруют и просят выкуп. "
             "Подтверждено правило в роутере; дойдёт ли до него запрос снаружи (у провайдера может быть свой NAT), "
             "LanMap не проверял.",
        scheme=[("globe", "Интернет", "боты ищут двери", "crit"), ("router", "Роутер", "открыл, не спросив", "warn"),
                ("@dev", "", "запрос через UPnP", "")],
        links=[("{forwards}", "r"), ("«открой мне»", "l")],
        threat=[("key", "подберут пароль"), ("lock", "зашифруют файлы"), ("cash", "потребуют выкуп")],
        todo=[("phone", "Нужен доступ вне дома? Сначала VPN или облако"),
              ("@dev", "На устройстве выключи UPnP и удали правила"), ("router", "На роутере выключи UPnP")],
        note="Правило в роутере есть; дойдёт ли запрос снаружи (у провайдера может быть свой NAT) — не проверено.",
        steps=[
            "Нужен доступ снаружи (фото с телефона, синхронизация)? Сначала настрой замену: VPN до дома или облачный "
            "доступ производителя без проброса портов. Проверь его с мобильного интернета.",
            "В настройках устройства найди UPnP (может называться «Автонастройка роутера», «Внешний доступ», "
            "«Проброс портов») и выключи.",
            "Если там есть список созданных правил — удали их.",
        ],
        vendor_steps={
            "synology": [
                "Нужен доступ снаружи? Замена без проброса: QuickConnect (в «Панели управления», обычно в разделе "
                "«Внешний доступ») или пакет VPN Server в «Центре пакетов». Проверь с мобильного интернета.",
                "«Панель управления → Внешний доступ → Конфигурация маршрутизатора»: выдели правила и удали.",
                "Мастер настройки маршрутизатора там же повторно не запускай — он создаст правила заново.",
            ],
        },
        router_steps={
            "": ["На роутере найди UPnP (обычно «Домашняя сеть», «Дополнительно» или «NAT») и выключи. Если "
                 "выключить нельзя — удали правила этого устройства в списке UPnP."],
            "keenetic": ["Роутер Keenetic: UPnP — отдельный компонент прошивки. «Общие настройки → Изменить набор "
                         "компонентов» → сними UPnP и установи (на части прошивок переключатель есть в «Домашней сети»)."],
        },
        breaks="Перестанут работать подключения к устройству из интернета напрямую: приложения на телефоне вне дома, "
               "внешние ссылки на файлы. Некоторые игровые приставки без UPnP хуже находят друзей в сетевой игре.",
        rollback="Включи UPnP обратно на роутере и на устройстве: правила создадутся сами при следующем запуске.",
        verify="В новом срезе нет пробросов к устройству. Доступ снаружи работает только через VPN или облако.",
        detect=_upnp, needs="роутер не ответил по UPnP (или список прочитан не до конца), а входа в роутер нет "
                            "(python -m lanmap router login)",
    ),
    Check(
        id="TELNET_OPEN", title="Управление по Telnet — пароль идёт открытым текстом", icon="key", priority=1,
        criteria=["E4"], who="lan", stake=["network", "passwords"],
        risk="Telnet — старый способ управлять устройством, без шифрования. Пароль администратора можно подсмотреть "
             "или подобрать изнутри сети: с телефона гостя или заражённой умной лампочки. Кто управляет роутером, тот "
             "управляет интернетом в доме: может подсунуть поддельный сайт банка или видеть, куда вы ходите.",
        scheme=[("home", "Кто-то в сети", "гость, умная лампочка", "warn"), ("@dev", "", "Telnet без шифрования", "")],
        links=[("подсмотрит пароль", "r")],
        threat=[("key", "пароль админа"), ("router", "управление сетью"), ("eye", "видят, куда ходишь")],
        todo=[("lock", "Проверь вход в веб-интерфейс"), ("@dev", "Выключи Telnet"), ("key", "Нужна консоль — SSH")],
        steps=[
            "Убедись, что можешь войти в веб-интерфейс устройства (лучше по HTTPS).",
            "Найди в настройках раздел доступа к управлению (Telnet, SSH, командная строка) и выключи Telnet.",
            "Если нужна командная строка — используй SSH вместо Telnet.",
            "Если Telnet выключить нельзя, задай длинный уникальный пароль администратора и закрой доступ к "
            "управлению из гостевой сети и сегмента камер.",
        ],
        vendor_steps={
            "keenetic": [
                "Войди в веб-интерфейс роутера.",
                "«Управление → Пользователи и доступ»: найди Telnet и выключи. Названия пунктов зависят от версии "
                "прошивки — если не нашёл, сверься со справкой Keenetic.",
                "Нужна командная строка — поставь компонент «Сервер SSH» и сузь доступ к управлению.",
            ],
        },
        breaks="Перестанут работать скрипты и программы, которые заходят на устройство по Telnet (обычно их нет).",
        rollback="Включи Telnet обратно в том же разделе настроек.",
        verify="В новом срезе порт 23 закрыт, а вход в веб-интерфейс работает.",
        detect=_telnet,
    ),
    Check(
        id="CAMERA_XM_PORT", title="Служебный вход дешёвых камер (порт 34567)", icon="camera", priority=2,
        criteria=["E7", "E5"], who="lan", stake=["video", "device"],
        risk="Через этот порт работают приложения вроде XMEye и программы видеорегистраторов. У камер на платах "
             "Xiongmai известны заводские пароли и дыры, их массово захватывали в ботнеты. Итог: чужой смотрит "
             "видео, а камера тайком атакует чужие сайты и тормозит тебе сеть.",
        scheme=[("home", "Кто-то в сети", "или заражённый ПК", "warn"), ("@dev", "", "заводские дыры", "")],
        links=[("порт 34567", "r")],
        threat=[("eye", "смотрят видео"), ("bot", "камера в ботнете"), ("network", "тормозит сеть")],
        todo=[("key", "Смени пароль камеры"), ("@dev", "Не нужно облако — выключи"), ("network", "Камеры — в отдельную сеть")],
        steps=[
            "Смени пароль администратора камеры на длинный и уникальный (в веб-интерфейсе или в приложении).",
            "Если смотришь камеры только через регистратор или RTSP, выключи в камере облако (P2P, Cloud) "
            "и лишние службы, если такие пункты есть.",
            "Не пробрасывай этот порт на роутере в интернет.",
            "Лучшее решение — отдельная сеть для камер без выхода в интернет (критерий E3).",
        ],
        breaks="Если закрыть службу, перестанет работать приложение производителя (XMEye и похожие) и "
               "старые программы просмотра.",
        rollback="Включи службу или облако обратно в настройках камеры; старый пароль не возвращай.",
        verify="Пароль сменён; в новом срезе порт закрыт или камера отделена от остальной сети.",
        detect=_port_check(34567, CAMERA_TYPES),
    ),
    Check(
        id="CAMERA_ONVIF_ANON", title="Камера рассказывает о себе без пароля (ONVIF)", icon="camera", priority=2,
        criteria=["E4", "E7"], who="lan", stake=["video"],
        risk="Любой в сети узнаёт модель и прошивку камеры, а значит, и какие дыры к ней подходят. На части камер "
             "без пароля можно получить ещё и видео или управление. Доступ к видео LanMap не проверял: он только "
             "читает и не пробует войти.",
        scheme=[("home", "Любой в сети", "", ""), ("@dev", "", "отвечает без пароля", "")],
        links=[("«кто ты?»", "r")],
        threat=[("search", "узнают модель"), ("key", "подберут дыру"), ("eye", "иногда и видео")],
        todo=[("@dev", "Включи пароль для ONVIF"), ("power", "Не нужен — выключи ONVIF"),
              ("wrench", "Обнови пароль в регистраторе")],
        note="Доступ к видео LanMap не проверял: он только читает и не пробует войти.",
        steps=[
            "В настройках камеры найди ONVIF (бывает в «Сеть → Расширенные» или «Безопасность»).",
            "Включи проверку пароля для ONVIF (Authentication, Digest) и задай отдельного пользователя.",
            "Если ONVIF не нужен (регистратор подключается по своему протоколу), выключи ONVIF совсем.",
            "Перенастрой регистратор или программу просмотра на нового пользователя.",
        ],
        breaks="Регистратор или программа видеонаблюдения могут перестать видеть камеру, пока в них не введёшь "
               "пароль ONVIF.",
        rollback="Выключи проверку пароля ONVIF обратно.",
        verify="В новом срезе камера отвечает «ONVIF просит пароль» или не отвечает по ONVIF вовсе.",
        detect=_onvif_anon, needs="в срезе нет опроса ONVIF",
    ),
    Check(
        id="ADB_EXPOSED", title="Отладка Android по сети включена (ADB)", icon="tv", priority=2,
        criteria=["E7"], who="lan", stake=["device"],
        risk="ADB — служебный вход для разработчиков Android. Через него можно ставить программы, читать данные "
             "и видеть экран приставки или телевизора. На некоторых прошивках он пускает без подтверждения.",
        scheme=[("home", "Любой в сети", "", ""), ("@dev", "", "вход разработчика", "")],
        links=[("порт 5555", "r")],
        threat=[("plus", "ставят программы"), ("eye", "видят экран"), ("folder", "читают данные")],
        todo=[("@dev", "Открой «Для разработчиков»"), ("power", "Выключи отладку"), ("wrench", "Нужна — включай на время")],
        steps=[
            "На устройстве открой «Настройки → Для разработчиков» (иногда «Об устройстве → нажать 7 раз на номер сборки»).",
            "Выключи «Отладка по сети» / «Отладка по USB» / «ADB».",
            "Если отладка нужна, включай её только на время работы.",
        ],
        breaks="Перестанут работать программы, которые управляют приставкой через ADB (некоторые пульты и установщики).",
        rollback="Включи отладку обратно в «Для разработчиков».",
        verify="В новом срезе порт 5555 закрыт.",
        detect=_adb,
    ),
    Check(
        id="NAS_EXTRA_SERVICES", title="На хранилище включены лишние службы", icon="nas", priority=3,
        criteria=["E5"], who="lan", stake=["files"],
        risk="Каждая включённая служба — ещё одна дверь, которую надо запирать. NFS часто пускает к папкам вообще "
             "без пароля, только по адресу компьютера. База данных и старые протоколы — лишние двери, если ими никто "
             "не пользуется.",
        scheme=[("home", "Любой в сети", "", ""), ("@dev", "", "лишние службы", "")],
        links=[("лишние двери", "r")],
        threat=[("folder", "папки без пароля"), ("key", "больше дверей для взлома")],
        todo=[("question", "Кто пользуется службой?"), ("power", "Ненужное выключи"), ("lock", "Нужное ограничь адресами")],
        steps=[
            "Вспомни, кто пользуется службой: NFS — Linux и медиаплееры, AFP — старые Mac, MySQL — сайт или "
            "приложение на NAS.",
            "Ненужное выключи в панели управления NAS (раздел «Файловые службы» или «Пакеты»).",
            "Нужное ограничь: NFS — только конкретным адресам и папкам, базу данных — только своим приложениям.",
        ],
        vendor_steps={
            "synology": [
                "Вспомни, кто пользуется службой: NFS — Linux и медиаплееры, AFP — старые Mac, MariaDB — сайт или "
                "приложение на NAS.",
                "NFS и AFP: «Панель управления → Файловые службы», вкладки NFS и AFP — сними галочку ненужного.",
                "MariaDB: «Центр пакетов» → MariaDB → «Остановить» (или «Удалить», если не нужна).",
                "NFS нужен — «Панель управления → Общая папка → Изменить → Разрешения NFS»: оставь только нужные адреса.",
            ],
        },
        breaks="Перестанут работать устройства и программы, которые ходят через выключенную службу: плеер по NFS, "
               "Time Machine по AFP, сайт на NAS.",
        rollback="Включи службу обратно в том же разделе.",
        verify="В новом срезе лишних портов на хранилище нет.",
        detect=_nas_extra,
    ),
    Check(
        id="SMB_SIGNING", title="Общие папки без обязательной подписи (SMB)", icon="lock", priority=3,
        criteria=["E4"], who="lan", stake=["files"],
        risk="Когда ты копируешь файлы с этого устройства или на него, злоумышленник в сети теоретически может "
             "подменить их по дороге. Дома это маловероятно, поэтому приоритет низкий.",
        scheme=[("computer", "Твой ПК", "", ""), ("home", "Чужой в сети", "подменяет", "warn"),
                ("@dev", "", "общие папки", "")],
        links=[("файлы", "r"), ("файлы", "r")],
        threat=[("shuffle", "подмена файлов"), ("home", "дома маловероятно")],
        todo=[("@dev", "Включи обязательную подпись SMB"), ("lock", "Минимум SMB2 или SMB3"),
              ("computer", "Проверь ПК и сканеры")],
        steps=[
            "В настройках общих папок (SMB) устройства включи обязательную подпись (signing: required / mandatory).",
            "Заодно выставь минимальный протокол SMB2 или SMB3, если есть такой пункт.",
            "Проверь, что все компьютеры, принтеры и сканеры по-прежнему открывают папки.",
        ],
        vendor_steps={
            "synology": [
                "«Панель управления → Файловые службы → SMB → Дополнительные настройки».",
                "Подпись сервера SMB — включи принудительную (названия пункта зависят от версии DSM).",
                "Там же минимальный протокол SMB — SMB2 или выше.",
                "Проверь, что компьютеры, принтеры и сканеры по-прежнему открывают папки.",
            ],
        },
        breaks="Старые устройства (сканеры с «сохранить в папку», старые медиаплееры) могут перестать подключаться. "
               "На слабых NAS копирование может стать чуть медленнее.",
        rollback="Верни подпись SMB в режим «включена» или «авто».",
        verify="В новом срезе SMB этого устройства требует подпись.",
        detect=_smb_signing, needs="в срезе нет опроса SMB",
    ),
]
BY_ID = {c.id: c for c in CHECKS}


# --- статусы ---------------------------------------------------------------------------------

def uid(check_id: str, key: str) -> str:
    return f"{check_id}|{key}"


def statuses_path() -> Path:
    return data_dir() / "findings.json"


def load_statuses() -> dict:
    data = read_json(statuses_path(), {}) or {}
    return data.get("findings") or {}


def set_status(check_id: str, key: str, status: str, reason: str | None = None) -> dict:
    if check_id not in BY_ID:
        raise ValueError(f"Нет такой проверки: {check_id}. Есть: {', '.join(BY_ID)}")
    if status not in STATUSES:
        raise ValueError(f"Нет такого статуса: {status}. Есть: {', '.join(STATUSES)}")
    data = read_json(statuses_path(), {}) or {}
    items = data.setdefault("findings", {})
    u = uid(check_id, key)
    if status == "open":
        items.pop(u, None)
        entry = {"status": "open"}
    else:
        entry = {"status": status, "updated": now_iso()}
        if reason:
            entry["reason"] = reason
        items[u] = entry
    write_json(statuses_path(), data)
    return entry


def _after(a: str | None, b: str | None) -> bool:
    """Момент a позже b (ISO-строки, с часовым поясом или без)."""
    if not a or not b:
        return False
    try:
        da, db = datetime.fromisoformat(a), datetime.fromisoformat(b)
        if (da.tzinfo is None) != (db.tzinfo is None):
            da, db = da.replace(tzinfo=None), db.replace(tzinfo=None)
        return da > db
    except ValueError:
        return a > b


def _effective(saved: dict | None, started: str) -> dict:
    """Статус находки с учётом отметки владельца. Исправленная, но снова видимая находка — регресс."""
    if not saved:
        return {"status": "open"}
    status = saved.get("status", "open")
    out = {"status": status, "updated": saved.get("updated"), "reason": saved.get("reason")}
    if status == "fixed":
        # Срез сделан после отметки «исправлено», а находка на месте — вернулась
        if _after(started, saved.get("updated")):
            out["status"] = "regress"
        else:
            out["status"] = "fixed_pending"  # отмечено, ждёт перепроверки новым срезом
    return out


# --- запуск ----------------------------------------------------------------------------------

def evaluate(model: dict, snapshot: Path, tested: set[int] | None = None, statuses: dict | None = None) -> dict:
    """Все проверки по модели среза → блок security для devices.json и отчёта."""
    ctx = Ctx(model=model, raw=Path(snapshot) / "raw", tested=tested)
    statuses = load_statuses() if statuses is None else statuses
    started = (model.get("meta") or {}).get("started") or ""
    findings, evaluated, skipped = [], {}, {}
    for check in CHECKS:
        try:
            ok, hits = check.detect(ctx)
        except Exception as exc:  # одна сломанная проверка не должна ронять отчёт
            ok, hits = False, []
            skipped[check.id] = f"ошибка проверки: {exc}"
        evaluated[check.id] = ok
        if not ok:
            skipped.setdefault(check.id, check.needs or "в срезе нет нужных данных")
            continue
        for h in hits:
            u = uid(check.id, h["key"])
            findings.append({"id": check.id, "uid": u, "priority": h.pop("priority", check.priority), **h,
                             **_effective(statuses.get(u), started)})
    findings.sort(key=lambda f: (f["status"] in QUIET_STATUSES, f["priority"], f["id"], _ip_key(f["ips"])))
    return {"findings": findings, "evaluated": evaluated, "skipped": skipped}


def _ip_key(ips: list[str]) -> tuple:
    try:
        return (0, ipaddress.ip_address(ips[0])) if ips else (1, ipaddress.ip_address("0.0.0.0"))
    except ValueError:
        return (1, ipaddress.ip_address("0.0.0.0"))


def open_findings(security: dict | None) -> list[dict]:
    return [f for f in (security or {}).get("findings") or [] if f["status"] not in QUIET_STATUSES]


def _pick(options: dict[str, list[str]], vendor: str | None) -> tuple[str | None, list[str]]:
    """Вариант под производителя (ключ — подстрока имени производителя) или общий (ключ "")."""
    low = (vendor or "").lower()
    for name, steps in options.items():
        if name and name in low:
            return name, steps
    return None, options.get("", [])


def device_steps(check: Check, finding: dict, router_vendor: str | None = None) -> tuple[list[str], bool, str | None]:
    """Инструкция «куда зайти, что нажать» для одного устройства находки.
    Возвращает (шаги, подобрана ли часть про устройство под его производителя, марка роутера, если подобрана
    часть про роутер)."""
    name, steps = _pick({"": check.steps, **check.vendor_steps}, finding.get("vendor"))
    rname = None
    if check.router_steps:
        rname, rsteps = _pick(check.router_steps, router_vendor)
        steps = steps + rsteps
    return steps, name is not None, rname


def router_vendor(model: dict) -> str | None:
    """Марка роутера: из модуля роутера, иначе производитель устройства-шлюза."""
    kind = (model.get("router") or {}).get("kind")
    if kind:
        return kind
    for d in model.get("devices") or []:
        if d.get("is_gateway"):
            return (d.get("identity") or {}).get("vendor")
    return None
