@echo off
:: Request admin elevation
net session >nul 2>&1
if %errorLevel% == 0 (
    goto :run
) else (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

:run
pushd %~dp0

echo ========================================
echo elmoCut Development Runner (Admin)
echo ========================================
echo Running with Administrator privileges...
echo.

set "exe=%cd%\exe\"
set "src=%cd%\src\"

echo [1/2] Updating UI files...
pyuic5 "%exe%ui_main.ui" -o "%src%ui\ui_main.py"
if errorlevel 1 (
    echo ERROR: pyuic5 not found. Install PyQt5-tools: pip install pyqt5-tools
    pause
    exit /b 1
)
pyuic5 "%exe%ui_about.ui" -o "%src%ui\ui_about.py"
pyuic5 "%exe%ui_device.ui" -o "%src%ui\ui_device.py"
pyuic5 "%exe%ui_settings.ui" -o "%src%ui\ui_settings.py"
echo UI files updated.
echo.

echo [2/2] Running elmoCut with admin privileges...
echo.
python "%src%elmocut.py"
if errorlevel 1 (
    echo.
    echo ERROR: Script failed to run!
    pause
    exit /b 1
)

pause


