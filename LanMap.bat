@echo off
chcp 65001 >nul
rem LanMap: веб-интерфейс (python -m lanmap serve) с правами администратора.
rem Двойной щелчок: Windows спросит разрешение, потом откроется браузер с отчётом.
rem Остановить: закрыть это окно или Ctrl+C. Без прав администратора: отказаться в окне Windows.

cd /d "%~dp0"

if defined LANMAP_NO_ADMIN goto run
net session >nul 2>&1
if not errorlevel 1 goto run
echo Запрашиваю права администратора...
powershell -NoProfile -Command "Start-Process -FilePath '%~f0' -Verb RunAs" >nul 2>&1
if not errorlevel 1 exit /b
echo Права не выданы, запускаю без них: часть проверок среза будет пропущена.
set LANMAP_NO_ADMIN=1

:run
set PY=python
where python >nul 2>&1 || set PY=py -3
%PY% -m lanmap serve %*
rem Выключили кнопкой в интерфейсе — окно закрывается само; при ошибке ждёт, чтобы её можно было прочитать
if errorlevel 1 (
  echo.
  echo LanMap остановился с ошибкой. Нужен Python 3.12+: https://www.python.org/downloads/
  pause
)
