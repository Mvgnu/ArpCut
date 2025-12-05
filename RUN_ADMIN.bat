@echo off
:: Run elmoCut with Administrator privileges
:: This script elevates itself to admin

>nul 2>&1 "%SYSTEMROOT%\system32\cacls.exe" "%SYSTEMROOT%\system32\config\system"

if '%errorlevel%' NEQ '0' (
    echo Requesting administrative privileges...
    goto UACPrompt
) else ( goto gotAdmin )

:UACPrompt
    echo Set UAC = CreateObject^("Shell.Application"^) > "%temp%\getadmin.vbs"
    echo UAC.ShellExecute "%~s0", "", "", "runas", 1 >> "%temp%\getadmin.vbs"
    "%temp%\getadmin.vbs"
    exit /B

:gotAdmin
    if exist "%temp%\getadmin.vbs" ( del "%temp%\getadmin.vbs" )
    pushd "%CD%"
    CD /D "%~dp0"

echo ========================================
echo elmoCut (Administrator Mode)
echo ========================================
echo.

set "exe=%cd%\exe\"
set "src=%cd%\src\"

echo Converting UI files...
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

echo Starting elmoCut with admin privileges...
echo.

python -m src.elmocut

pause


