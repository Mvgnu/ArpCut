#!/usr/bin/env python3
"""
Build script for ArpCut
Run: python build.py
"""

import subprocess
import sys
import platform

# All the imports PyInstaller is too dumb to find on its own
HIDDEN_IMPORTS = [
    'PyQt5',
    'PyQt5.QtWidgets',
    'PyQt5.QtCore', 
    'PyQt5.QtGui',
    'PyQt5.sip',
    'qdarkstyle',
    'scapy',
    'scapy.all',
    'scapy.layers.all',
    'manuf',
    'pyperclip',
    'requests',
    'six',
]

COLLECT_ALL = [
    'manuf',
    'scapy',
    'qdarkstyle',
]

def build():
    system = platform.system()
    
    # Base command
    cmd = ['pyinstaller', '--name', 'ArpCut']
    
    # Platform-specific options
    if system == 'Windows':
        cmd.extend(['--onefile', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf;manuf'])
        cmd.extend(['--icon', 'exe/icon.ico'])
        cmd.extend(['--uac-admin'])  # Force admin elevation prompt
    elif system == 'Darwin':  # macOS
        cmd.extend(['--onedir', '--windowed'])
        cmd.extend(['--add-data', 'exe/manuf:manuf'])
        cmd.extend(['--icon', 'exe/icon.ico'])
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
    
    result = subprocess.run(cmd)
    
    if result.returncode == 0:
        print()
        print("Build complete!")
        if system == 'Windows':
            print("Output: dist/ArpCut.exe")
        elif system == 'Darwin':
            print("Output: dist/ArpCut.app")
            print("To create zip: cd dist && zip -r ArpCut-macOS.zip ArpCut.app")
        else:
            print("Output: dist/ArpCut")
    else:
        print("Build failed!")
        sys.exit(1)

if __name__ == '__main__':
    build()
