@echo off
echo ========================================
echo elmoCut Dependency Installer
echo ========================================
echo.

echo This will install all required Python packages.
echo.

echo [1/3] Upgrading pip...
python -m pip install --upgrade pip

echo.
echo [2/3] Installing dependencies...
pip install PyQt5 qdarkstyle pyperclip scapy manuf six requests

echo.
echo [3/3] Installing build tools (optional)...
pip install pyinstaller

echo.
echo ========================================
echo Installation complete!
echo ========================================
echo.
echo IMPORTANT: You also need Npcap installed for network features.
echo Download from: https://npcap.com/#download
echo (Select "WinPcap API-compatible Mode" during installation)
echo.
echo To run: Use RUN_ADMIN.bat (recommended) or RUN.bat
echo To build exe: Use BUILD.bat
echo.

pause


