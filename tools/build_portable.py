"""Сборка портативного LanMap для Windows: встраиваемый Python с python.org + пакет + LanMap.bat в одном zip.

    python tools/build_portable.py           → dist/LanMap-<версия>-win64.zip (внутри папка LanMap/)
    python tools/build_portable.py --check   → то же и проверка: распаковать в папку с пробелами и кириллицей,
                                               запустить там тесты и команды встроенным Python

Ничего устанавливать не нужно ни здесь, ни у того, кто скачает архив. Встраиваемый Python берётся с
python.org и сверяется по SHA256 со страницы выпуска. В архив попадают только файлы, которые лежат в git
(git ls-files), поэтому data/, legacy/ и __pycache__ туда не попадут, а содержимое ещё раз проверяется на
частные IP и MAC: архив так же публичен, как репозиторий.
"""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import shutil
import subprocess
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DIST = ROOT / "dist"

PY_VERSION = "3.14.10"
PY_URL = f"https://www.python.org/ftp/python/{PY_VERSION}/python-{PY_VERSION}-embed-amd64.zip"
PY_SHA256 = "90905e64a840557d8c1bc4f5b74db3d7ee85e3ffb217611cac1c7813acea4159"  # со страницы выпуска python.org

FILES = ["lanmap", "LanMap.bat", "LICENSE", "README.md"]  # что из репозитория едет в архив
APP = "LanMap"  # папка внутри архива: без версии, чтобы новую версию распаковывали поверх и data/ оставалась

PRIVATE_IP = re.compile(r"\b(?:10\.\d{1,3}|192\.168|172\.(?:1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")
MAC = re.compile(r"\b[0-9A-Fa-f]{2}(?:[:-][0-9A-Fa-f]{2}){5}\b")

README_TXT = """LanMap — карта и порядок в домашней сети. Программа только читает сеть и ничего не меняет на устройствах.

Запуск: двойной щелчок по LanMap.bat. Windows спросит права администратора (можно отказаться — часть
проверок будет пропущена), потом откроется браузер. Python и другие программы устанавливать не нужно.

Если Windows пишет «Система Windows защитила ваш компьютер»: «Подробнее» → «Выполнить в любом случае».
Чтобы предупреждения не было, перед распаковкой: правый щелчок по zip → «Свойства» → «Разблокировать».

Данные (срезы, подписи устройств, отметки) лежат в папке data рядом с программой и переезжают вместе
с ней. Если программа лежит в Program Files — в %LOCALAPPDATA%\\LanMap\\data. Пароль роутера хранится
в диспетчере учётных данных Windows, а не в папке: на другом компьютере вход в роутер нужно сделать заново.

Новая версия: распакуй архив поверх старой папки — data останется на месте.

Описание и исходники: https://github.com/padrefalcon2011-code/lanMap
"""


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, check=True, capture_output=True, text=True,
                          encoding="utf-8").stdout


def version() -> str:
    text = (ROOT / "lanmap" / "__init__.py").read_text("utf-8")
    return re.search(r'__version__\s*=\s*"([^"]+)"', text).group(1)


def embedded_python() -> Path:
    """Архив встраиваемого Python: из кэша dist/cache или с python.org. В любом случае сверка SHA256."""
    cache = DIST / "cache" / PY_URL.rsplit("/", 1)[1]
    if not cache.exists():
        cache.parent.mkdir(parents=True, exist_ok=True)
        print(f"Скачиваю {PY_URL}")
        tmp = cache.with_suffix(".part")
        with urllib.request.urlopen(PY_URL, timeout=120) as resp:
            tmp.write_bytes(resp.read(100_000_000))
        tmp.replace(cache)
    digest = hashlib.sha256(cache.read_bytes()).hexdigest()
    if digest != PY_SHA256:
        cache.unlink()
        raise SystemExit(f"SHA256 встраиваемого Python не совпал ({digest}). Архив удалён, сборка остановлена.")
    return cache


def tracked_files() -> list[str]:
    names = [n for n in git("ls-files", "-z", "--", *FILES).split("\0") if n]
    dirty = git("status", "--porcelain", "--", *FILES).strip()
    if dirty:
        print("Внимание: в архив попадут незакоммиченные правки:\n" + dirty)
    return names


def privacy_check(stage: Path) -> None:
    """Последний рубеж перед публикацией: ни личных папок, ни адресов конкретной сети."""
    for path in stage.rglob("*"):
        rel = path.relative_to(stage)
        if rel.parts[0] == "python" or not path.is_file():
            continue
        if {"data", "legacy", "__pycache__"} & set(rel.parts):
            raise SystemExit(f"В архив попала личная или служебная папка: {rel}")
        if path.suffix not in (".py", ".json", ".md", ".txt", ".bat", ".html"):
            continue
        text = path.read_text("utf-8", "replace").replace("AA:BB:CC:DD:EE:FF", "")
        for rx, what in ((PRIVATE_IP, "частный IP"), (MAC, "MAC-адрес")):
            m = rx.search(text)
            if m:
                raise SystemExit(f"{what} в {rel}: {m.group(0)}")


def build() -> Path:
    stage = DIST / "build" / APP
    shutil.rmtree(stage.parent, ignore_errors=True)
    stage.mkdir(parents=True)

    with zipfile.ZipFile(embedded_python()) as z:
        z.extractall(stage / "python")
    pth = next((stage / "python").glob("python3*._pth"))
    # ._pth задаёт sys.path целиком (PYTHONPATH и чужие Python не мешают); «..» — папка с пакетом lanmap
    lines = [ln for ln in pth.read_text("utf-8").splitlines() if ln.strip() and not ln.startswith("#")]
    pth.write_text("\n".join(lines + [".."]) + "\n", "utf-8")

    for name in tracked_files():
        dest = stage / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    (stage / "README.txt").write_text(README_TXT.replace("\n", "\r\n"), "utf-8-sig")
    privacy_check(stage)

    out = DIST / f"{APP}-{version()}-win64.zip"
    out.unlink(missing_ok=True)
    with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in sorted(stage.rglob("*")):
            if path.is_file():
                z.write(path, (Path(APP) / path.relative_to(stage)).as_posix())
    print(f"Готово: {out} ({out.stat().st_size / 1e6:.1f} МБ)")
    return out


def check(archive: Path) -> None:
    """Распаковать в путь с пробелами и кириллицей и запустить встроенным Python: тесты и команды."""
    base = DIST / "check" / "Мои программы"
    shutil.rmtree(DIST / "check", ignore_errors=True)
    base.mkdir(parents=True)
    with zipfile.ZipFile(archive) as z:
        z.extractall(base)
    app = base / APP
    py = app / "python" / "python.exe"
    env_note = "тесты пишут во временную папку (LANMAP_DATA задают сами)"
    steps = [
        ([str(py), "-B", "-m", "lanmap", "--version"], "версия"),
        ([str(py), "-B", "-c", "import sys, lanmap; print(sys.version); print(lanmap.__file__)"], "откуда пакет"),
        ([str(py), "-B", "-m", "unittest", "discover", "-s", str(ROOT / "tests")], env_note),
        ([str(py), "-B", "-m", "lanmap", "interfaces"], "сети компьютера (только чтение)"),
    ]
    for cmd, what in steps:
        print(f"\n== {what}")
        result = subprocess.run(cmd, cwd=app, text=True, encoding="utf-8", errors="replace", capture_output=True,
                                env={**os.environ, "PYTHONIOENCODING": "utf-8"})
        print((result.stdout + result.stderr).strip()[-3000:])
        if result.returncode:
            raise SystemExit(f"Проверка не прошла: {' '.join(cmd[1:])}")
    if (app / "data").exists():
        shutil.rmtree(app / "data")  # interfaces создаёт пустую data/ — в проверочной папке она не нужна
    print(f"\nПроверка пройдена. Папка для ручной проверки: {app}")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        stream.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(description="Собрать портативный LanMap (zip) для Windows")
    parser.add_argument("--check", action="store_true", help="после сборки распаковать и проверить встроенным Python")
    args = parser.parse_args()
    archive = build()
    if args.check:
        check(archive)
    return 0


if __name__ == "__main__":
    sys.exit(main())
