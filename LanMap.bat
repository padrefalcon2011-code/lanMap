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
rem Портативная сборка несёт свой Python в папке python, иначе — установленный.
rem Без блоков в скобках: путь вроде «Program Files (x86)» их ломает.
set "PY=%~dp0python\python.exe"
if not exist "%PY%" goto system
"%PY%" -m lanmap serve %*
goto done
:system
set PY=python
where python >nul 2>&1 || set PY=py -3
%PY% -m lanmap serve %*
:done
rem Выключили кнопкой в интерфейсе — окно закрывается само; при ошибке ждёт, чтобы её можно было прочитать
if not errorlevel 1 exit /b 0
echo.
echo LanMap остановился с ошибкой.
if not exist "%~dp0python\python.exe" echo Нужен Python 3.12+ (https://www.python.org/downloads/) или портативная сборка LanMap.
pause
