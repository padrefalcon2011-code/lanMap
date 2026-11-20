"""Командная строка: python -m lanmap <команда>."""
from __future__ import annotations

import argparse
import os
import sys
import webbrowser
from pathlib import Path

from lanmap import __version__, netinfo, oui, registry
from lanmap.util import data_dir, norm_mac, read_json


def _utf8_console() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def _pick_network(index: int | None, allow_large: bool) -> netinfo.LocalNet:
    from lanmap import ops
    try:
        return ops.pick_network(index, allow_large)
    except ops.OpError as exc:
        raise SystemExit(str(exc))


def _snapshot_arg(value: str | None, complete: bool = False) -> Path:
    from lanmap.scan import latest_snapshot, snapshots_dir
    if value:
        path = Path(value)
        if not path.exists():
            path = snapshots_dir() / value
        if not (path / "meta.json").exists():
            raise SystemExit(f"Не найден срез: {value}")
        return path
    latest = latest_snapshot(complete)
    if not latest:
        raise SystemExit("Срезов ещё нет. Сначала: python -m lanmap scan")
    return latest


def _resolve_mac(target: str) -> str:
    mac = norm_mac(target.partition("#")[0])
    if mac and "." not in target:
        return f"{mac}#{target.partition('#')[2]}" if "#" in target else mac
    from lanmap.scan import latest_snapshot
    snap = latest_snapshot(complete=True)
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
        from lanmap import ops
        if not args.source:
            print(f"Скачиваю весь публичный реестр IEEE ({oui.IEEE_URL}). Твои MAC никуда не отправляются.")
        try:
            count = ops.oui_update(args.source)["count"]
        except ops.OpError as exc:
            raise SystemExit(str(exc))
        print(f"База производителей обновлена: {oui.oui_path()} ({count} записей)")
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
    from lanmap import ops
    mac = _resolve_mac(args.target)
    fields = {k: getattr(args, k) for k in registry.EDITABLE if getattr(args, k, None) is not None}
    try:
        _, entry = ops.sign(mac, fields, args.also_mac)
    except ops.OpError as exc:
        raise SystemExit(str(exc))
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
    snap = _snapshot_arg(None, complete=True)
    model = read_json(snap / "devices.json", {}) or {}
    sec = model.get("security")
    if sec is None:
        raise SystemExit("В последнем срезе ещё нет проверок. Пересобери: python -m lanmap build")
    if args.action == "list":
        if not sec["findings"]:
            print("Находок нет.")
        for f in sec["findings"]:
            status = security.EFFECTIVE_NAMES.get(f["status"], f["status"])
            print(f'П{f["priority"]}  {f["id"]:<20} {", ".join(f["ips"]) or f["key"]:<16} {status:<18} {f["detail"]}')
        for cid, why in sec.get("skipped", {}).items():
            print(f"не проверялось: {cid} — {why}")
        print("\nОтметить: python -m lanmap finding set <ПРОВЕРКА> <IP|MAC|all> <статус> [--reason «почему»]")
        print("Перепроверить по сети: python -m lanmap finding recheck <ПРОВЕРКА> <IP|MAC|all>")
        print("Статусы: " + ", ".join(f"{k} ({v})" for k, v in security.STATUSES.items()))
        return 0

    if args.action == "recheck":
        if not args.check or not args.target:
            raise SystemExit("Нужно: finding recheck <ПРОВЕРКА> <IP|MAC|all>")
        from lanmap import ops
        try:
            results = ops.recheck(args.check, args.target)
            ops.rebuild()
        except ops.OpError as exc:
            raise SystemExit(str(exc))
        for r in results:
            f = r["finding"]
            print(f'{f["id"]} · {f["title"]}: {security.RECHECK_NAMES[r["result"]]} — {r["detail"]}')
        print(f"Отчёт пересобран: {snap / 'report.html'}")
        return 0

    if not args.check or not args.target or not args.status:
        raise SystemExit("Нужно: finding set <ПРОВЕРКА> <IP|MAC|all> <статус>")
    from lanmap import ops
    try:
        targets = ops.set_finding(args.check, args.target, args.status, args.reason)
        ops.rebuild()
    except ops.OpError as exc:
        raise SystemExit(str(exc))
    for f in targets:
        print(f'{f["id"]} · {f["title"]}: {security.STATUSES[args.status]}')
    print(f"Отчёт пересобран: {snap / 'report.html'}")
    return 0


def cmd_check(args) -> int:
    from lanmap import checklist
    snap = _snapshot_arg(None, complete=True)
    if args.action == "list":
        model = read_json(snap / "devices.json", {}) or {}
        cl = model.get("checklist")
        if cl is None:
            raise SystemExit("В последнем срезе ещё нет чек-листа. Пересобери: python -m lanmap build")
        names = {"ok": "выполнен", "fail": "не выполнен", "owner": "отмечаешь ты", "unknown": "нечем проверить"}
        print(f'Порядок в сети: {cl["score"]} из {cl["total"]}')
        for c in cl["criteria"]:
            frac = f' {c["done"]}/{c["total"]}' if c.get("total") else ""
            print(f'{c["id"]}  {names[c["status"]]:<16}{frac:<7} {c["title"]} — {c["why"]}')
        print("\nОтметить (E6, E8): python -m lanmap check set E8 done [--note «что сделал»]; снять — open")
        return 0
    if not args.code or not args.status:
        raise SystemExit("Нужно: check set <E6|E8> <done|open> [--note «…»]")
    from lanmap import ops
    try:
        ops.set_check(args.code, args.status, args.note)
        ops.rebuild()
    except ops.OpError as exc:
        raise SystemExit(str(exc))
    print(f'{args.code.upper()}: {checklist.MARK_STATUSES[args.status]}')
    print(f"Отчёт пересобран: {snap / 'report.html'}")
    return 0


def cmd_serve(args) -> int:
    from lanmap import server
    from lanmap.scan import latest_snapshot
    snap = latest_snapshot(complete=True)
    if snap:
        print("Пересобираю отчёт последнего среза текущими правилами…")
        ops_build(snap)
    httpd = server.make_server(args.port)
    url = server.url_for(httpd)
    print(f"LanMap: {url}")
    print(f"Данные: {data_dir()}")
    print("Ссылка с ключом доступа действует, пока открыто это окно. Остановить — Ctrl+C.")
    if not netinfo.is_admin():
        print("Внимание: без прав администратора срез из интерфейса пропустит часть проверок.")
    if not args.no_open:
        webbrowser.open(url)
    try:
        httpd.serve_forever()
        print("Выключено из интерфейса.")
    except KeyboardInterrupt:
        print("Остановлено.")
    finally:
        httpd.server_close()
    return 0


def ops_build(snap: Path) -> None:
    from lanmap.build import build
    try:
        build(snap)
    except Exception as exc:  # старый отчёт всё равно можно показать
        print(f"Не удалось пересобрать: {exc}")


def cmd_router(args) -> int:
    import getpass
    from lanmap import ops
    try:
        if args.action == "probe":
            print("Собираю, как роутер представляется (без пароля, только чтение)…", file=sys.stderr)
            print(ops.router_probe(), flush=True)
            print("Скопируй текст выше в заявку: https://github.com/padrefalcon2011-code/lanMap/issues/new/choose",
                  file=sys.stderr)
            return 0
        host = args.host or ops.gateway()
        if args.action == "forget":
            print("Удалено." if ops.router_forget(host) else "Сохранённого входа не было.")
            return 0
        status = ops.router_status(host)
        if not status["kind"]:
            raise SystemExit(f"Для роутера {host} пока нет модуля. Паспорт для заявки: python -m lanmap router probe")
        product = status["product"]
        if args.action == "login":
            print(f"Роутер {product} ({host}). Лучше отдельный пользователь с правами «Веб-конфигуратор» "
                  "и «Запретить сохранять настройки системы».")
            user = input("Логин: ").strip()
            password = getpass.getpass("Пароль (не отображается): ")
            saved = ops.router_login(user, password, host)
            print("Вход проверен, пароль сохранён в диспетчере учётных данных Windows "
                  f"(запись {saved['target']}). Проверь доступ: python -m lanmap router test")
            return 0
        rows = ops.router_test(host)  # test: какие чтения доступны, без вывода личных данных
    except ops.OpError as exc:
        raise SystemExit(str(exc))
    print(f"Роутер {product} ({host}), вход выполнен. Что доступно для чтения:")
    for r in rows:
        print(f"  {'✓' if r['ok'] else '✗'} {r['name']:15} {r['path']:25} {r['info']}")
    return 0


def cmd_camera(args) -> int:
    import getpass
    from lanmap import ops
    try:
        if args.action == "forget":
            print("Удалено." if ops.camera_forget(args.target) else "Сохранённого пароля не было.")
            return 0
        if args.action == "login":
            st = ops.camera_status(args.target)
            print(f"Камера {st['key']}. Пароль проверю настоящим кадром и сохраню в диспетчере учётных данных Windows. "
                  "Лучше отдельный пользователь камеры только для просмотра.")
            user = input("Логин: ").strip()
            password = getpass.getpass("Пароль (не отображается): ")
            saved, image = ops.camera_login(args.target, user, password)
            print(f"Кадр получен ({len(image) // 1024} КБ), пароль сохранён (запись {saved['target']}).")
        else:
            image = ops.camera_snapshot(args.target)
        if args.out:
            Path(args.out).write_bytes(image)
            print(f"Кадр сохранён: {args.out}")
        elif args.action == "snapshot":
            print(f"Кадр получен ({len(image) // 1024} КБ). Чтобы сохранить его, добавь --out кадр.jpg")
    except ops.OpError as exc:
        raise SystemExit(str(exc))
    return 0


def cmd_launch(args) -> int:
    from lanmap import launch, ops
    try:
        print(ops.launch(args.target, args.action, ack=args.ack)["message"])
    except ops.OpError as exc:
        url = getattr(exc, "url", None)
        text = f"{launch.TELNET_WARNING}\nЕсли всё равно нужно: добавь --ack" if getattr(exc, "need_ack", False) else str(exc)
        raise SystemExit(text + (f"\nАдрес потока: {url}" if url else ""))
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
    p.add_argument("action", choices=["list", "set", "recheck"])
    p.add_argument("check", nargs="?", help="идентификатор проверки, например TELNET_OPEN")
    p.add_argument("target", nargs="?", help="IP или MAC устройства из последнего среза, или all")
    p.add_argument("status", nargs="?", help="open, in_progress, fixed, accepted, na")
    p.add_argument("--reason", help="почему (для «принята осознанно» и «не применимо»)")
    p.set_defaults(func=cmd_finding)

    p = sub.add_parser("check", help="чек-лист E1–E9: список и отметки владельца (прошивки, резервные копии)")
    p.add_argument("action", choices=["list", "set"])
    p.add_argument("code", nargs="?", help="критерий: E6 или E8")
    p.add_argument("status", nargs="?", help="done или open")
    p.add_argument("--note", help="что сделано (например, «восстановил файл из копии 18.11»)")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("serve", help="локальный веб-интерфейс: отчёт с кнопками (срез, подписать, отметить)")
    p.add_argument("--port", type=int, default=7480, help="порт (по умолчанию 7480; если занят — любой свободный)")
    p.add_argument("--no-open", action="store_true", help="не открывать браузер")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("router", help="вход в роутер (только чтение) и проверка доступа")
    p.add_argument("action", choices=["login", "test", "forget", "probe"],
                   help="probe — обезличенный «паспорт» роутера для заявки на модуль")
    p.add_argument("--host", help="адрес роутера (по умолчанию шлюз)")
    p.set_defaults(func=cmd_router)

    p = sub.add_parser("camera", help="стоп-кадр с камеры по ONVIF (пароль вводит владелец)")
    p.add_argument("action", choices=["login", "snapshot", "forget"])
    p.add_argument("target", help="ключ, MAC или IP камеры из последнего среза")
    p.add_argument("--out", help="куда сохранить кадр (JPEG); без него кадр только проверяется")
    p.set_defaults(func=cmd_camera)

    p = sub.add_parser("launch", help="открыть программу для устройства: SSH, общие папки, RDP, видео, Telnet, разбудить")
    p.add_argument("target", help="ключ, MAC или IP устройства из последнего среза")
    p.add_argument("action", choices=["ssh", "smb", "rdp", "vlc", "telnet", "wol"])
    p.add_argument("--ack", action="store_true", help="для Telnet: понимаю, что пароль пойдёт открытым текстом")
    p.set_defaults(func=cmd_launch)

    args = parser.parse_args(argv)
    if os.name != "nt":
        print("Пока поддерживается только Windows.", file=sys.stderr)
    return args.func(args)
