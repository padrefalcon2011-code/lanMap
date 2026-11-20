"""Этот компьютер (Windows): настройки, которые по сети не видны. Только чтение реестра.

SMB1 по сети видно лишь со стороны сервера (общих папок этого компьютера) — это проверяет
protocols.smb1_negotiate. Клиент SMB1 (драйвер mrxsmb10: этот компьютер сам ходит к другим по SMB1)
снаружи не виден, поэтому читаем его службу в реестре.
"""
from __future__ import annotations

import sys

SERVICES = r"SYSTEM\CurrentControlSet\Services"
START_NAMES = {0: "boot", 1: "system", 2: "auto", 3: "demand", 4: "disabled"}


def _value(path: str, name: str):
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path) as key:
            return winreg.QueryValueEx(key, name)[0]
    except FileNotFoundError:
        return None


def smb1_client(start) -> bool | None:
    """Клиент SMB1 включён: служба mrxsmb10 есть и не отключена. Нет службы — компонент удалён."""
    if start is None:
        return False
    return start != 4


def collect() -> dict:
    """{platform, smb1_client, mrxsmb10_start, smb1_server_param} или {skipped}: не Windows."""
    if sys.platform != "win32":
        return {"platform": sys.platform, "skipped": "не Windows"}
    out: dict = {"platform": "windows"}
    try:
        start = _value(SERVICES + r"\mrxsmb10", "Start")
        out["mrxsmb10_start"] = START_NAMES.get(start, start)
        out["smb1_client"] = smb1_client(start)
        # Параметр сервера SMB1 (нет — значение по умолчанию, решает компонент Windows; правду скажет сеть)
        out["smb1_server_param"] = _value(SERVICES + r"\LanmanServer\Parameters", "SMB1")
    except OSError as exc:
        out["error"] = f"{type(exc).__name__}: {exc}"
    return out
