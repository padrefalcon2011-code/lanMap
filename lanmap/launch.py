"""Запуск программ по клику в веб-интерфейсе (CONCEPT §5): SSH, Проводник, mstsc, VLC, Telnet, Wake-on-LAN.

Страница присылает только {key, action}. Устройство, адрес и порт берутся из модели последнего среза,
действие должно быть в белом списке ACTIONS и среди действий, построенных для этого устройства
(lanmap/actions.py). Команда собирается здесь: в неё попадают только проверенный IPv4 из локальной
подсети и порт-число — ни строк со страницы, ни имён устройств (их выдаёт сеть, а Windows Terminal
понимает «;» как разделитель команд). Только subprocess со списком аргументов, без shell, программы — по
полному пути из системных папок, а не поиском по PATH и текущей папке.

Пароли не подставляются: программа спросит их сама. В командной строке пароль виден в списке процессов,
поэтому из адреса видеопотока логин и пароль вырезаются (onvif.rtsp_without_creds).

Программы запускаются от того же пользователя, что и LanMap, — обычно с правами администратора.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

ACTIONS = ("ssh", "smb", "rdp", "telnet", "vlc", "wol")
WOL_PORT = 9
TELNET_WARNING = ("Telnet передаёт логин и пароль открытым текстом: их видит любое устройство в сети. "
                  "Лучше выключить Telnet на устройстве и пользоваться SSH или веб-панелью.")


class LaunchError(ValueError):
    """Понятная человеку причина, почему запуск не состоялся."""


@dataclass
class Plan:
    """Что запустить: argv (список, без shell) и нужна ли своя консоль. Для Wake-on-LAN — пакет и адрес."""
    action: str
    argv: list[str] = field(default_factory=list)
    console: bool = False
    packet: bytes = b""
    target: tuple[str, int] | None = None
    source: str | None = None
    message: str = ""


# --- где лежат программы ---------------------------------------------------------------------------

def _windir() -> Path:
    return Path(os.environ.get("SystemRoot") or os.environ.get("windir") or r"C:\Windows")


def _file(path: Path) -> str | None:
    return str(path) if path.is_file() else None


def find_ssh() -> str | None:
    return _file(_windir() / "System32" / "OpenSSH" / "ssh.exe")


def find_telnet() -> str | None:
    return _file(_windir() / "System32" / "telnet.exe")


def find_wt() -> str | None:
    """Windows Terminal: псевдоним приложения в WindowsApps текущего пользователя."""
    local = os.environ.get("LOCALAPPDATA")
    return _file(Path(local, "Microsoft", "WindowsApps", "wt.exe")) if local else None


def find_vlc() -> str | None:
    """VLC: по реестру (64- и 32-битная установка), затем по обычным папкам Program Files."""
    try:
        import winreg
    except ImportError:
        winreg = None
    if winreg:
        for hive in (winreg.HKEY_LOCAL_MACHINE, winreg.HKEY_CURRENT_USER):
            for sub in (r"SOFTWARE\VideoLAN\VLC", r"SOFTWARE\WOW6432Node\VideoLAN\VLC"):
                try:
                    with winreg.OpenKey(hive, sub) as key:
                        for name, as_dir in (("", False), ("InstallDir", True)):
                            try:
                                value = winreg.QueryValueEx(key, name)[0]
                            except OSError:
                                continue
                            if isinstance(value, str) and value:
                                found = _file(Path(value) / "vlc.exe" if as_dir else Path(value))
                                if found:
                                    return found
                except OSError:
                    continue
    for env in ("ProgramFiles", "ProgramFiles(x86)", "ProgramW6432"):
        base = os.environ.get(env)
        if base:
            found = _file(Path(base, "VideoLAN", "VLC", "vlc.exe"))
            if found:
                return found
    return None


@dataclass
class Tools:
    """Найденные программы. Тесты подставляют свои."""
    ssh: str | None = None
    telnet: str | None = None
    wt: str | None = None
    vlc: str | None = None
    explorer: str | None = None
    mstsc: str | None = None

    @classmethod
    def find(cls) -> "Tools":
        win = _windir()
        return cls(ssh=find_ssh(), telnet=find_telnet(), wt=find_wt(), vlc=find_vlc(),
                   explorer=_file(win / "explorer.exe"), mstsc=_file(win / "System32" / "mstsc.exe"))


# --- что можно запустить ---------------------------------------------------------------------------

def available(dev: dict) -> dict[str, dict]:
    """Действия запуска для устройства: пересчитываются из модели, сохранённым строкам не доверяем."""
    from lanmap import actions
    out: dict[str, dict] = {}
    for a in actions.build(dev):
        if a.get("launch") in ACTIONS and a["launch"] not in out:
            out[a["launch"]] = a
    return out


def device_ip(dev: dict, in_scope: Callable[[str], bool]) -> str:
    """Первый IPv4 устройства внутри локальной подсети. Других адресов в командной строке не бывает."""
    for raw in dev.get("ips") or []:
        try:
            ip = ipaddress.IPv4Address(raw)
        except ValueError:
            continue
        if in_scope(str(ip)):
            return str(ip)
    raise LaunchError("У устройства нет адреса в локальной сети — запускать не к чему. Сделай новый срез")


def magic_packet(mac: str) -> bytes:
    digits = mac.replace(":", "").replace("-", "")
    if len(digits) != 12:
        raise LaunchError("Непонятный MAC-адрес")
    raw = bytes.fromhex(digits)
    if raw[0] & 1:
        raise LaunchError("Групповой MAC — это не устройство")
    return b"\xff" * 6 + raw * 16


def plan(dev: dict, action: str, *, ctx, tools: Tools, ack: bool = False,
         stream: Callable[[dict, str, int], tuple[str, str]] | None = None) -> Plan:
    """Собрать команду. ctx — ScanContext текущей локальной сети. stream(dev, ip, port) → (адрес RTSP без
    логина и пароля, пояснение) — для VLC; без него берётся адрес без пути."""
    if action not in ACTIONS:
        raise LaunchError(f"Неизвестное действие: {action}")
    found = available(dev)
    if action not in found:
        raise LaunchError("Для этого устройства такого действия нет: нужный порт не был открыт в последнем срезе")

    if action == "wol":
        from lanmap.util import is_private_mac, norm_mac
        mac = norm_mac(dev.get("mac") or "")
        if not mac or is_private_mac(mac):
            raise LaunchError("Будить можно только устройство с настоящим (не частным) MAC-адресом")
        net = ipaddress.IPv4Network(ctx.network)
        return Plan("wol", packet=magic_packet(mac), target=(str(net.broadcast_address), WOL_PORT),
                    source=ctx.local_ip,
                    message=f"Волшебный пакет отправлен в сеть {net}. Если устройство умеет просыпаться по сети, "
                            "оно включится за минуту")

    ip = device_ip(dev, ctx.in_scope)
    if action == "ssh":
        if not tools.ssh:
            raise LaunchError("Не нашёл клиент SSH Windows (System32\\OpenSSH\\ssh.exe). Его ставят в «Параметры → "
                              "Система → Дополнительные компоненты → Клиент OpenSSH»")
        if tools.wt:  # Windows Terminal; без него — ssh в своём окне консоли
            return Plan("ssh", [tools.wt, "new-tab", "--title", f"SSH {ip}", tools.ssh, ip],
                        message=f"Открыл SSH к {ip} в Windows Terminal. Логин — твой; если не тот: ssh имя@{ip}")
        return Plan("ssh", [tools.ssh, ip], console=True,
                    message=f"Открыл SSH к {ip} в новом окне. Логин — твой; если не тот: ssh имя@{ip}")
    if action == "telnet":
        if not ack:
            raise LaunchError(TELNET_WARNING)
        if not tools.telnet:
            raise LaunchError("Клиент Telnet в Windows не установлен — и это к лучшему. " + TELNET_WARNING)
        return Plan("telnet", [tools.telnet, ip], console=True, message=f"Открыл Telnet к {ip} в новом окне")
    if action == "smb":
        if not tools.explorer:
            raise LaunchError("Не нашёл Проводник Windows")
        return Plan("smb", [tools.explorer, f"\\\\{ip}"], message=f"Открыл общие папки \\\\{ip} в Проводнике")
    if action == "rdp":
        if not tools.mstsc:
            raise LaunchError("Не нашёл «Подключение к удалённому рабочему столу» (mstsc.exe)")
        return Plan("rdp", [tools.mstsc, f"/v:{ip}"], message=f"Открыл удалённый рабочий стол {ip}")
    # vlc
    port = found["vlc"].get("port")
    if not isinstance(port, int) or not 0 < port < 65536:
        raise LaunchError("Непонятный порт видеопотока")
    url, note = stream(dev, ip, port) if stream else (f"rtsp://{ip}:{port}/", "")
    if not tools.vlc:
        err = LaunchError("VLC не установлен (videolan.org). Адрес потока скопирован — его можно открыть в любом "
                          "видеоплеере" + (f". {note}" if note else ""))
        err.url = url
        raise err
    return Plan("vlc", [tools.vlc, url], message="Открыл видео в VLC" + (f". {note}" if note else ""))


# --- запуск -----------------------------------------------------------------------------------------

def _popen(argv: list[str], console: bool) -> None:
    flags = subprocess.CREATE_NEW_CONSOLE if console else 0
    # Без своей консоли ssh и telnet делили бы окно и ввод с сервером LanMap
    subprocess.Popen(argv, shell=False, close_fds=True, creationflags=flags,
                     stdin=None if console else subprocess.DEVNULL,
                     stdout=None if console else subprocess.DEVNULL,
                     stderr=None if console else subprocess.DEVNULL)


def _send_udp(packet: bytes, target: tuple[str, int], source: str | None) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if source:  # с адреса этой сети: пакет уходит в нужный сетевой адаптер
            s.bind((source, 0))
        s.sendto(packet, target)


def execute(p: Plan, popen: Callable[[list[str], bool], None] | None = None,
            send: Callable[[bytes, tuple[str, int], str | None], None] | None = None) -> str:
    if p.action == "wol":
        (send or _send_udp)(p.packet, p.target, p.source)
        return p.message
    try:
        (popen or _popen)(p.argv, p.console)
    except OSError as exc:
        raise LaunchError(f"Не удалось запустить программу ({exc.__class__.__name__})") from None
    return p.message
