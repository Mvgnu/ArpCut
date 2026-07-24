#!/usr/bin/env python3
"""
Build script for ArpCut.
Run: python build.py           # build for current platform
     python build.py --version  # print version and exit
"""

import subprocess
import sys
import platform
from pathlib import Path
from typing import NoReturn

# Read version from the canonical source
def _read_version() -> str:
    """Parse __version__ from constants.py without importing it."""
    constants_path = Path(__file__).parent / 'src' / 'constants.py'
    for line in constants_path.read_text().splitlines():
        if line.startswith('__version__'):
            return line.split('=', 1)[1].strip().strip("'\"")
    return '0.0.0'

VERSION: str = _read_version()

# All the imports PyInstaller is too dumb to find on its own
HIDDEN_IMPORTS: list[str] = [
    'PySide6',
    'PySide6.QtWidgets',
    'PySide6.QtCore',
    'PySide6.QtGui',
    'PySide6.QtSvg',
    'scapy',
    'scapy.all',
    'scapy.layers.all',
    'manuf',
    # lazily-imported engine/helper modules — bundle them so `--helper` works
    'privilege.helper',
    'privilege.remote',
    'privilege.install',
    'networking.dnsblock',
    'networking.scanner',
    'networking.killer',
    'networking.sniffer',
]

COLLECT_ALL: list[str] = [
    'manuf',
    'scapy',
    'PySide6',
]


def build() -> None:
    """Build ArpCut binary for the current platform."""
    system: str = platform.system()

    # Base command
    cmd: list[str] = ['pyinstaller', '--name', f'ArpCut-{VERSION}']

    # Platform-specific options
    if system == 'Windows':
        cmd.extend(['--onefile', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf;manuf'])
        cmd.extend(['--icon', 'exe/icon.ico'])
        cmd.extend(['--uac-admin'])  # Force admin elevation prompt
    elif system == 'Darwin':  # macOS
        cmd.extend(['--onedir', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf:manuf'])
        cmd.extend(['--icon', 'exe/icon.icns'])  # macOS requires .icns
    else:  # Linux
        cmd.extend(['--onefile'])
        cmd.extend(['--add-data', 'exe/manuf:manuf'])

    # Add hidden imports
    for imp in HIDDEN_IMPORTS:
        cmd.extend(['--hidden-import', imp])

    # Collect all data for these packages
    for pkg in COLLECT_ALL:
        cmd.extend(['--collect-all', pkg])

    # Entry point
    cmd.append('src/elmocut.py')

    print(f"Building for {system}...")
    print(f"Command: {' '.join(cmd)}")
    print()

    result: subprocess.CompletedProcess[bytes] = subprocess.run(cmd)

    if result.returncode == 0:
        print()
        print("Build complete!")
        if system == 'Windows':
            print(f"Output: dist/ArpCut-{VERSION}.exe")
            print("Installer: iscc /DMyAppVersion=%s packaging\\windows\\arpcut.iss" % VERSION)
        elif system == 'Darwin':
            print(f"Output: dist/ArpCut-{VERSION}.app")
            print("Installer: python build.py --dmg   (or packaging/macos/create_dmg.sh)")
        else:
            print(f"Output: dist/ArpCut-{VERSION}")
    else:
        print("Build failed!")
        sys.exit(1)


def package_dmg() -> None:
    """Wrap the built .app into a drag-to-Applications .dmg (macOS only)."""
    if platform.system() != 'Darwin':
        print("--dmg is macOS-only.")
        return
    app = Path('dist') / f'ArpCut-{VERSION}.app'
    script = Path(__file__).parent / 'packaging' / 'macos' / 'create_dmg.sh'
    print(f"Packaging {app} → dmg ...")
    result = subprocess.run(['bash', str(script), str(app)])
    if result.returncode != 0:
        print("DMG packaging failed!")
        sys.exit(1)


if __name__ == '__main__':
    if '--version' in sys.argv:
        print(f'ArpCut {VERSION}')
    elif '--dmg' in sys.argv:
        package_dmg()
    else:
        build()
