"""Командная строка: python -m lanmap <команда>."""
from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from lanmap import __version__, netinfo, oui, registry
from lanmap.util import norm_mac, read_json


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _pick_network(index: int | None, allow_large: bool) -> netinfo.LocalNet:
    nets = netinfo.list_networks()
    if index is not None:
        chosen = [n for n in nets if n.if_index == index and n.up]
    else:
        chosen = [n for n in nets if n.default_choice]
    if not chosen:
        raise SystemExit("Не нашёл подходящую сеть. Посмотри список: python -m lanmap interfaces")
    if len(chosen) > 1:
        lines = "\n".join(f"  --interface {n.if_index}  {n.alias}: {n.network}" for n in chosen)
        raise SystemExit(f"Подходящих сетей несколько, выбери одну:\n{lines}")
    net = chosen[0]
    hosts = netinfo.host_count(net.network)
    if hosts > netinfo.MAX_HOSTS_DEFAULT and not allow_large:
        raise SystemExit(f"Сеть {net.network} большая ({hosts} адресов). Если точно нужно — добавь --allow-large")
    return net


def _snapshot_arg(value: str | None) -> Path:
    from lanmap.scan import latest_snapshot, snapshots_dir
    if value:
        path = Path(value)
        if not path.exists():
            path = snapshots_dir() / value
        if not (path / "meta.json").exists():
            raise SystemExit(f"Не найден срез: {value}")
        return path
    latest = latest_snapshot()
    if not latest:
        raise SystemExit("Срезов ещё нет. Сначала: python -m lanmap scan")
    return latest


def _resolve_mac(target: str) -> str:
    mac = norm_mac(target.partition("#")[0])
    if mac and "." not in target:
        return f"{mac}#{target.partition('#')[2]}" if "#" in target else mac
    from lanmap.scan import latest_snapshot
    snap = latest_snapshot()
    model = read_json(snap / "devices.json", {}) if snap else {}
    for dev in model.get("devices", []):
        if target in dev["ips"] and dev.get("mac"):
            return dev["key"]
    raise SystemExit(f"Не нашёл MAC для «{target}». Укажи MAC (AA:BB:CC:DD:EE:FF) или IP из последнего среза.")


def cmd_interfaces(args) -> int:
    for n in netinfo.list_networks():
        mark = "✓" if n.default_choice else " "
        why = "" if n.default_choice else "  — " + "; ".join(n.reasons_skipped)
        print(f"{mark} [{n.if_index:>3}] {n.alias}: {n.network} (мой IP {n.local_ip}, шлюз {n.gateway or '—'}){why}")
    print(f"\nПрава администратора: {'да' if netinfo.is_admin() else 'нет'}")
    return 0


def cmd_scan(args) -> int:
    from lanmap.build import build
    from lanmap.scan import run_scan
    net = _pick_network(args.interface, args.allow_large)
    if not netinfo.is_admin():
        print("Внимание: запуск без прав администратора — часть будущих проверок будет пропущена.")
    snap = run_scan(net)
    return _finish_build(build, snap, args.open)


def _finish_build(build, snap: Path, open_report: bool, baseline: Path | None = None) -> int:
    from lanmap import changes
    model = build(snap, baseline)
    devs = model["devices"]
    sure = sum(1 for d in devs if d["identity"]["confidence"] >= 3)
    report = snap / "report.html"
    diff = model.get("changes")
    if diff:
        print(diff["error"] if diff.get("error") else changes.summary(diff))
    print(f"Устройств: {len(devs)}, опознаны уверенно: {sure}. Отчёт: {report}")
    if open_report:
        webbrowser.open(report.as_uri())
    return 0


def cmd_build(args) -> int:
    from lanmap.build import build
    baseline = _snapshot_arg(args.compare) if args.compare else None
    return _finish_build(build, _snapshot_arg(args.snapshot), args.open, baseline)


def cmd_oui(args) -> int:
    if args.action == "update":
        if not args.source:
            print(f"Скачиваю весь публичный реестр IEEE ({oui.IEEE_URL}). Твои MAC никуда не отправляются.")
        path, count = oui.update(args.source)
        print(f"База производителей обновлена: {path} ({count} записей)")
    else:
        print(f"{oui.oui_path()}: {'есть' if oui.available() else 'нет'}")
    return 0


def cmd_import_codex(args) -> int:
    data = registry.load()
    added, skipped = registry.import_codex(data, Path(args.path))
    registry.save(data)
    print(f"Черновиков добавлено: {added}, пропущено: {skipped}. Файл: {registry.registry_path()}")
    print("Это предложения, а не факты: проверь и подтверди (python -m lanmap confirm <MAC|IP>).")
    return 0


def cmd_sign(args) -> int:
    data = registry.load()
    mac = _resolve_mac(args.target)
    fields = {k: getattr(args, k) for k in registry.EDITABLE if getattr(args, k, None) is not None}
    entry = registry.sign(data, mac, fields)
    if args.also_mac:
        extra = [m for m in (norm_mac(x) for x in args.also_mac) if m]
        entry["also_macs"] = sorted(set(entry.get("also_macs", [])) | set(extra))
    registry.save(data)
    print(f"Подписано: {mac} → {entry.get('name', '(без названия)')}. Пересобери отчёт: python -m lanmap build")
    return 0


def cmd_confirm(args) -> int:
    data = registry.load()
    for target in args.targets:
        mac = _resolve_mac(target)
        if mac not in data["devices"]:
            print(f"{mac}: в реестре нет записи — используй sign")
            continue
        registry.sign(data, mac, {})
        print(f"Подтверждено: {mac} → {data['devices'][mac].get('name')}")
    registry.save(data)
    return 0


def cmd_finding(args) -> int:
    from lanmap import security
    snap = _snapshot_arg(None)
    model = read_json(snap / "devices.json", {}) or {}
    sec = model.get("security")
    if sec is None:
        raise SystemExit("В последнем срезе ещё нет проверок. Пересобери: python -m lanmap build")
    if args.action == "list":
        if not sec["findings"]:
            print("Находок нет.")
        for f in sec["findings"]:
            status = security.STATUSES.get(f["status"], {"regress": "вернулась", "fixed_pending": "ждёт перепроверки"}
                                           .get(f["status"], f["status"]))
            print(f'П{f["priority"]}  {f["id"]:<20} {", ".join(f["ips"]) or f["key"]:<16} {status:<18} {f["detail"]}')
        for cid, why in sec.get("skipped", {}).items():
            print(f"не проверялось: {cid} — {why}")
        print("\nОтметить: python -m lanmap finding set <ПРОВЕРКА> <IP|MAC|all> <статус> [--reason «почему»]")
        print("Статусы: " + ", ".join(f"{k} ({v})" for k, v in security.STATUSES.items()))
        return 0

    if not args.check or not args.target or not args.status:
        raise SystemExit("Нужно: finding set <ПРОВЕРКА> <IP|MAC|all> <статус>")
    check = args.check.upper()
    if check not in security.BY_ID:
        raise SystemExit(f"Нет такой проверки: {check}. Есть: {', '.join(security.BY_ID)}")
    if args.status not in security.STATUSES:
        raise SystemExit(f"Нет такого статуса: {args.status}. Есть: {', '.join(security.STATUSES)}")
    mac = norm_mac(args.target.partition("#")[0])
    targets = [f for f in sec["findings"] if f["id"] == check and (
        args.target == "all" or args.target in f["ips"] or f["key"] == args.target
        or (mac and f["key"].partition("#")[0] == mac))]
    if not targets:
        raise SystemExit(f"В последнем срезе нет находки {check} для «{args.target}». Список: python -m lanmap finding list")
    for f in targets:
        security.set_status(check, f["key"], args.status, args.reason)
        print(f'{check} · {f["title"]}: {security.STATUSES[args.status]}')
    from lanmap.build import build
    build(snap)
    print(f"Отчёт пересобран: {snap / 'report.html'}")
    return 0


def _gateway() -> str:
    net = _pick_network(None, True)
    if not net.gateway:
        raise SystemExit("Не найден шлюз (роутер) в выбранной сети")
    return net.gateway


def cmd_router(args) -> int:
    import getpass
    from lanmap import credentials
    from lanmap.routers import keenetic
    host = args.host or _gateway()
    target = keenetic.credential_target(host)
    if args.action == "forget":
        print("Удалено." if credentials.delete(target) else "Сохранённого входа не было.")
        return 0
    if args.action == "probe":
        from lanmap.routers import probe
        net = _pick_network(None, True)
        print("Собираю, как роутер представляется (без пароля, только чтение)…", file=sys.stderr)
        text = probe.to_markdown(probe.probe(net))
        print(text, flush=True)
        print("Скопируй текст выше в заявку: https://github.com/padrefalcon2011-code/lanMap/issues/new/choose",
              file=sys.stderr)
        return 0
    product = keenetic.is_keenetic(host)
    if not product:
        raise SystemExit(f"По адресу {host} не отвечает Keenetic. Другие роутеры пока не поддерживаются.")
    if args.action == "login":
        print(f"Роутер {product} ({host}). Лучше отдельный пользователь с правами «Веб-конфигуратор» "
              "и «Запретить сохранять настройки системы».")
        user = input("Логин: ").strip()
        password = getpass.getpass("Пароль (не отображается): ")
        client = keenetic.KeeneticClient(host)
        try:
            client.login(user, password)
        except keenetic.KeeneticError as exc:
            raise SystemExit(f"Не получилось войти: {exc}")
        credentials.save(target, user, password, comment=f"LanMap: роутер {product} {host}")
        print("Вход проверен, пароль сохранён в диспетчере учётных данных Windows "
              f"(запись LanMap:{target}). Проверь доступ: python -m lanmap router test")
        return 0
    # test: какие чтения доступны, без вывода личных данных
    result = keenetic.collect(host)
    if "login" in result["errors"]:
        raise SystemExit(f"Вход: {result['errors']['login']}")
    print(f"Роутер {product} ({host}), вход выполнен. Что доступно для чтения:")
    for name, path in keenetic.READS.items():
        if name in result["errors"]:
            print(f"  ✗ {name:15} {path:25} {result['errors'][name]}")
            continue
        value = result["data"][name]
        if isinstance(value, dict):
            size = f"ключей: {len(value)} ({', '.join(list(value)[:6])}{'…' if len(value) > 6 else ''})"
        elif isinstance(value, list):
            size = f"записей: {len(value)}"
        else:
            size = repr(value)[:60]
        print(f"  ✓ {name:15} {path:25} {size}")
    return 0


def main(argv: list[str] | None = None) -> int:
    _utf8_console()
    parser = argparse.ArgumentParser(prog="lanmap", description="Срез и опознание устройств локальной сети. Только чтение.")
    parser.add_argument("--version", action="version", version=f"LanMap {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("interfaces", help="показать сети компьютера и какая будет сканироваться")
    p.set_defaults(func=cmd_interfaces)

    p = sub.add_parser("scan", help="сделать новый срез сети и отчёт")
    p.add_argument("--interface", type=int, help="номер интерфейса (из команды interfaces)")
    p.add_argument("--allow-large", action="store_true", help="разрешить сеть больше /22")
    p.add_argument("--open", action="store_true", help="открыть отчёт в браузере")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("build", help="пересобрать опознание и отчёт по сохранённому срезу (без сканирования)")
    p.add_argument("snapshot", nargs="?", help="папка среза (по умолчанию последний)")
    p.add_argument("--compare", metavar="СРЕЗ", help="с каким срезом сравнивать (по умолчанию — предыдущий)")
    p.add_argument("--open", action="store_true")
    p.set_defaults(func=cmd_build)

    p = sub.add_parser("oui", help="база производителей по MAC (IEEE)")
    p.add_argument("action", choices=["update", "status"])
    p.add_argument("--from", dest="source", help="взять из локального файла oui.txt вместо скачивания")
    p.set_defaults(func=cmd_oui)

    p = sub.add_parser("import-codex", help="черновики реестра из папки среза Codex")
    p.add_argument("path")
    p.set_defaults(func=cmd_import_codex)

    p = sub.add_parser("sign", help="подписать устройство в реестре (подтверждено владельцем)")
    p.add_argument("target", help="MAC или IP из последнего среза")
    for key in registry.EDITABLE:
        p.add_argument(f"--{key}")
    p.add_argument("--also-mac", action="append", help="другой MAC этого же устройства (склейка)")
    p.set_defaults(func=cmd_sign)

    p = sub.add_parser("confirm", help="подтвердить черновики реестра как есть")
    p.add_argument("targets", nargs="+", help="MAC или IP")
    p.set_defaults(func=cmd_confirm)

    p = sub.add_parser("finding", help="находки безопасности: список и отметки (в работе, исправлена, принята…)")
    p.add_argument("action", choices=["list", "set"])
    p.add_argument("check", nargs="?", help="идентификатор проверки, например TELNET_OPEN")
    p.add_argument("target", nargs="?", help="IP или MAC устройства из последнего среза, или all")
    p.add_argument("status", nargs="?", help="open, in_progress, fixed, accepted, na")
    p.add_argument("--reason", help="почему (для «принята осознанно» и «не применимо»)")
    p.set_defaults(func=cmd_finding)

    p = sub.add_parser("router", help="вход в роутер (только чтение) и проверка доступа")
    p.add_argument("action", choices=["login", "test", "forget", "probe"],
                   help="probe — обезличенный «паспорт» роутера для заявки на модуль")
    p.add_argument("--host", help="адрес роутера (по умолчанию шлюз)")
    p.set_defaults(func=cmd_router)

    args = parser.parse_args(argv)
    if os.name != "nt":
        print("Пока поддерживается только Windows.", file=sys.stderr)
    return args.func(args)
