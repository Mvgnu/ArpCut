@echo off
pushd %~dp0

echo ========================================
echo elmoCut Build Script
echo ========================================
echo.

set "exe=%cd%\exe\"
set "src=%cd%\src\"

echo [1/4] Checking dependencies...
python -c "import PyQt5" 2>nul
if errorlevel 1 (
    echo Installing PyQt5...
    pip install PyQt5
)
python -c "import pyinstaller" 2>nul
if errorlevel 1 (
    echo Installing PyInstaller...
    pip install pyinstaller
)
echo Dependencies OK.
echo.

echo [2/4] Converting UI files...
REM Try pyuic5 first, fall back to python -m PyQt5.uic.pyuic
where pyuic5 >nul 2>&1
if errorlevel 1 (
    echo pyuic5 not in PATH, using python -m PyQt5.uic.pyuic
    python -m PyQt5.uic.pyuic "%exe%ui_main.ui" -o "%src%ui\ui_main.py"
    python -m PyQt5.uic.pyuic "%exe%ui_about.ui" -o "%src%ui\ui_about.py"
    python -m PyQt5.uic.pyuic "%exe%ui_device.ui" -o "%src%ui\ui_device.py"
    python -m PyQt5.uic.pyuic "%exe%ui_settings.ui" -o "%src%ui\ui_settings.py"
    if exist "%exe%ui_traffic.ui" (
        python -m PyQt5.uic.pyuic "%exe%ui_traffic.ui" -o "%src%ui\ui_traffic.py"
    )
) else (
    pyuic5 "%exe%ui_main.ui" -o "%src%ui\ui_main.py"
    pyuic5 "%exe%ui_about.ui" -o "%src%ui\ui_about.py"
    pyuic5 "%exe%ui_device.ui" -o "%src%ui\ui_device.py"
    pyuic5 "%exe%ui_settings.ui" -o "%src%ui\ui_settings.py"
    if exist "%exe%ui_traffic.ui" (
        pyuic5 "%exe%ui_traffic.ui" -o "%src%ui\ui_traffic.py"
    )
)
if errorlevel 1 (
    echo ERROR: UI conversion failed!
    pause
    exit /b 1
)
echo UI files converted successfully.
echo.

echo [3/4] Building executable...
echo This will create an exe that requests admin privileges.
echo.
python build_auto.py
if errorlevel 1 (
    echo ERROR: Build failed!
    pause
    exit /b 1
)
echo.

echo [4/4] Build complete!
echo.
echo The exe will request administrator privileges on Windows startup.
echo Output location: output\elmoCut\elmoCut.exe
echo.

pause
