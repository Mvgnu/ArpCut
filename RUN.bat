@echo off
pushd %~dp0

echo ========================================
echo elmoCut Run Script
echo ========================================
echo.

set "exe=%cd%\exe\"
set "src=%cd%\src\"

echo [1/2] Converting UI files if needed...
REM Try pyuic5 first, fall back to python -m PyQt5.uic.pyuic
where pyuic5 >nul 2>&1
if errorlevel 1 (
    python -m PyQt5.uic.pyuic "%exe%ui_main.ui" -o "%src%ui\ui_main.py" 2>nul
    python -m PyQt5.uic.pyuic "%exe%ui_about.ui" -o "%src%ui\ui_about.py" 2>nul
    python -m PyQt5.uic.pyuic "%exe%ui_device.ui" -o "%src%ui\ui_device.py" 2>nul
    python -m PyQt5.uic.pyuic "%exe%ui_settings.ui" -o "%src%ui\ui_settings.py" 2>nul
    if exist "%exe%ui_traffic.ui" (
        python -m PyQt5.uic.pyuic "%exe%ui_traffic.ui" -o "%src%ui\ui_traffic.py" 2>nul
    )
) else (
    pyuic5 "%exe%ui_main.ui" -o "%src%ui\ui_main.py" 2>nul
    pyuic5 "%exe%ui_about.ui" -o "%src%ui\ui_about.py" 2>nul
    pyuic5 "%exe%ui_device.ui" -o "%src%ui\ui_device.py" 2>nul
    pyuic5 "%exe%ui_settings.ui" -o "%src%ui\ui_settings.py" 2>nul
    if exist "%exe%ui_traffic.ui" (
        pyuic5 "%exe%ui_traffic.ui" -o "%src%ui\ui_traffic.py" 2>nul
    )
)
echo Done.
echo.

echo [2/2] Starting elmoCut...
echo NOTE: For full functionality, run as Administrator!
echo.

python -m src.elmocut

pause
