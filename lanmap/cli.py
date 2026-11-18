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


def _finish_build(build, snap: Path, open_report: bool) -> int:
    model = build(snap)
    devs = model["devices"]
    sure = sum(1 for d in devs if d["identity"]["confidence"] >= 3)
    report = snap / "report.html"
    print(f"Устройств: {len(devs)}, опознаны уверенно: {sure}. Отчёт: {report}")
    if open_report:
        webbrowser.open(report.as_uri())
    return 0


def cmd_build(args) -> int:
    from lanmap.build import build
    return _finish_build(build, _snapshot_arg(args.snapshot), args.open)


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

    args = parser.parse_args(argv)
    if os.name != "nt":
        print("Пока поддерживается только Windows.", file=sys.stderr)
    return args.func(args)
