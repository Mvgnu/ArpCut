#!/usr/bin/env python3
"""
Automated build script for elmoCut
Creates a Windows executable with admin elevation
"""

import os
import sys
import shutil
import time
import re

# Configuration
APP_NAME = 'elmoCut'
APP_GUID = '31430AA0-C0A7-4598-991B-E3B2CD961817'
VERSION = '1.1.0'  # Update this for new releases
IS_GUI = True  # False for console app

version_file_template = '''
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers={version_tuple},
    prodvers={version_tuple},
    mask=0x3f,
    flags=0x0,
    OS=0x4,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'elmoiv Apps'),
        StringStruct(u'FileDescription', u'{app_name}'),
        StringStruct(u'FileVersion', u'{version}'),
        StringStruct(u'InternalName', u'{app_name}'),
        StringStruct(u'LegalCopyright', u'Khaled El-Morshedy (elmoiv) 2015-2024'),
        StringStruct(u'OriginalFilename', u'{app_name}.exe'),
        StringStruct(u'ProductName', u'{app_name}'),
        StringStruct(u'ProductVersion', u'{version}')])
      ]), 
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
'''

spec_file_template_windows = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Hidden imports for scapy and networking
hidden_imports = [
    'scapy.all',
    'scapy.layers.l2',
    'scapy.layers.inet',
    'scapy.arch.windows',
    'scapy.arch.windows.native',
    'scapy.modules.six.moves',
    'PyQt5.sip',
    'PyQt5.QtCore',
    'PyQt5.QtGui', 
    'PyQt5.QtWidgets',
]

a = Analysis(['{cur_dir}src\\\\elmocut.py'],
             pathex=['{cur_dir}'],
             binaries=[],
             datas=[
                 ('{cur_dir}exe\\\\manuf', 'manuf'),
             ],
             hiddenimports=hidden_imports,
             hookspath=[],
             runtime_hooks=[],
             excludes={excluded_modules},
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

# Remove unnecessary binaries
excluded_binaries = {excluded_binaries}
a.binaries = TOC([x for x in a.binaries if x[0] not in excluded_binaries])

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='{app_name}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          console={console},
          version='version_info.txt',
          icon='{cur_dir}exe\\\\icon.ico',
          uac_admin=True)

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=False,
               upx_exclude={excluded_upx},
               name='{app_name}')
'''

spec_file_template_unix = '''# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

# Hidden imports for scapy and networking
hidden_imports = [
    'scapy.all',
    'scapy.layers.l2',
    'scapy.layers.inet',
    'scapy.modules.six.moves',
    'PyQt5.sip',
    'PyQt5.QtCore',
    'PyQt5.QtGui', 
    'PyQt5.QtWidgets',
]

a = Analysis(['{cur_dir}src/elmocut.py'],
             pathex=['{cur_dir}'],
             binaries=[],
             datas=[
                 ('{cur_dir}exe/manuf', 'manuf'),
             ],
             hiddenimports=hidden_imports,
             hookspath=[],
             runtime_hooks=[],
             excludes={excluded_modules},
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          [],
          exclude_binaries=True,
          name='{app_name}',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=False,
          console={console},
          icon='{cur_dir}exe/icon.ico')

coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=False,
               name='{app_name}')
'''

# Binaries to exclude (reduce size)
excluded_binaries = [
    'api-ms-win-core-console-l1-1-0.dll',
    'api-ms-win-core-datetime-l1-1-0.dll',
    'api-ms-win-core-debug-l1-1-0.dll',
    'api-ms-win-core-errorhandling-l1-1-0.dll',
    'api-ms-win-core-file-l1-1-0.dll',
    'api-ms-win-core-file-l1-2-0.dll',
    'api-ms-win-core-file-l2-1-0.dll',
    'api-ms-win-core-handle-l1-1-0.dll',
    'api-ms-win-core-heap-l1-1-0.dll',
    'api-ms-win-core-interlocked-l1-1-0.dll',
    'api-ms-win-core-libraryloader-l1-1-0.dll',
    'api-ms-win-core-localization-l1-2-0.dll',
    'api-ms-win-core-memory-l1-1-0.dll',
    'api-ms-win-core-namedpipe-l1-1-0.dll',
    'api-ms-win-core-processenvironment-l1-1-0.dll',
    'api-ms-win-core-processthreads-l1-1-0.dll',
    'api-ms-win-core-processthreads-l1-1-1.dll',
    'api-ms-win-core-profile-l1-1-0.dll',
    'api-ms-win-core-rtlsupport-l1-1-0.dll',
    'api-ms-win-core-string-l1-1-0.dll',
    'api-ms-win-core-synch-l1-1-0.dll',
    'api-ms-win-core-synch-l1-2-0.dll',
    'api-ms-win-core-sysinfo-l1-1-0.dll',
    'api-ms-win-core-timezone-l1-1-0.dll',
    'api-ms-win-core-util-l1-1-0.dll',
    'api-ms-win-crt-conio-l1-1-0.dll',
    'api-ms-win-crt-convert-l1-1-0.dll',
    'api-ms-win-crt-environment-l1-1-0.dll',
    'api-ms-win-crt-filesystem-l1-1-0.dll',
    'api-ms-win-crt-heap-l1-1-0.dll',
    'api-ms-win-crt-locale-l1-1-0.dll',
    'api-ms-win-crt-math-l1-1-0.dll',
    'api-ms-win-crt-multibyte-l1-1-0.dll',
    'api-ms-win-crt-process-l1-1-0.dll',
    'api-ms-win-crt-runtime-l1-1-0.dll',
    'api-ms-win-crt-stdio-l1-1-0.dll',
    'api-ms-win-crt-string-l1-1-0.dll',
    'api-ms-win-crt-time-l1-1-0.dll',
    'api-ms-win-crt-utility-l1-1-0.dll',
    'd3dcompiler_47.dll',
    'libEGL.dll',
    'libGLESv2.dll',
    'opengl32sw.dll',
    'Qt5DBus.dll',
    'Qt5Network.dll',
    'Qt5Qml.dll',
    'Qt5Quick.dll',
    'Qt5Svg.dll',
    'Qt5WebSockets.dll',
    'Qt5QmlModels.dll',
]

excluded_upx = ['qwindows.dll', 'qsvgicon.dll']

excluded_modules = [
    'tk', 'tcl', '_tkinter', 'tkinter', 'Tkinter', 'FixTk',
    'PIL', 'matplotlib', 'IPython', 'scipy', 'eel', 'jedi',
    'numpy', 'pandas', 'notebook', 'jupyter',
]


def version_tuple(version_str):
    """Convert 'x.y.z' to (x, y, z, 0)"""
    parts = [0, 0, 0, 0]
    for i, p in enumerate(version_str.split('.')[:4]):
        try:
            parts[i] = int(p)
        except ValueError:
            pass
    return tuple(parts)


def main():
    print("=" * 50)
    print(f" Building {APP_NAME} v{VERSION}")
    print("=" * 50)
    print(f" Platform: {sys.platform}")
    
    start_time = time.time()
    is_windows = sys.platform.startswith('win')
    
    # Get current directory
    cur_dir = os.path.dirname(os.path.abspath(__file__))
    if cur_dir:
        os.chdir(cur_dir)
        if is_windows:
            cur_dir += '\\'
        else:
            cur_dir += '/'
    else:
        cur_dir = ''
    
    # Update version in main.py
    print("\n[1/5] Updating version in source...")
    main_py_path = os.path.join('src', 'gui', 'main.py')
    if os.path.exists(main_py_path):
        with open(main_py_path, 'r', encoding='utf-8') as f:
            content = f.read()
        
        # Backup
        with open(main_py_path + '.backup', 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Update version
        new_content = re.sub(
            r"self\.version\s*=\s*['\"][\d.]+['\"]",
            f"self.version = '{VERSION}'",
            content
        )
        
        with open(main_py_path, 'w', encoding='utf-8') as f:
            f.write(new_content)
        print(f"    Version set to {VERSION}")
    
    # Create version info file (Windows only)
    print("\n[2/5] Creating version info...")
    if is_windows:
        version_info = version_file_template.format(
            version=VERSION,
            version_tuple=version_tuple(VERSION),
            app_name=APP_NAME
        )
        with open('version_info.txt', 'w') as f:
            f.write(version_info)
    else:
        print("    (Skipped - Windows only)")
    
    # Create spec file
    print("\n[3/5] Creating PyInstaller spec...")
    if is_windows:
        spec_template = spec_file_template_windows
        spec_content = spec_template.format(
            cur_dir=cur_dir.replace('\\', '\\\\'),
            app_name=APP_NAME,
            excluded_binaries=excluded_binaries,
            excluded_upx=excluded_upx,
            excluded_modules=excluded_modules,
            console=not IS_GUI
        )
    else:
        spec_template = spec_file_template_unix
        spec_content = spec_template.format(
            cur_dir=cur_dir,
            app_name=APP_NAME,
            excluded_modules=excluded_modules,
            console=not IS_GUI
        )
    with open('elmocut.spec', 'w') as f:
        f.write(spec_content)
    
    # Run PyInstaller
    print("\n[4/5] Running PyInstaller...")
    result = os.system('pyinstaller elmocut.spec --log-level WARN --noconfirm')
    if result != 0:
        print("ERROR: PyInstaller failed!")
        return 1
    
    # Move output
    print("\n[5/5] Organizing output...")
    output_dir = os.path.join('output', APP_NAME)
    
    # Kill any running instance
    os.system(f'taskkill /f /im {APP_NAME}.exe 2>nul')
    
    # Remove old output
    if os.path.exists(output_dir):
        shutil.rmtree(output_dir)
    
    os.makedirs('output', exist_ok=True)
    
    # Move from dist
    dist_dir = os.path.join('dist', APP_NAME)
    if os.path.exists(dist_dir):
        shutil.move(dist_dir, output_dir)
    else:
        print(f"ERROR: {dist_dir} not found!")
        return 1
    
    # Copy manuf file if not already there
    manuf_dest = os.path.join(output_dir, 'manuf')
    if not os.path.exists(manuf_dest):
        os.makedirs(manuf_dest, exist_ok=True)
    manuf_src = os.path.join('exe', 'manuf')
    if os.path.exists(manuf_src):
        shutil.copy(manuf_src, os.path.join(manuf_dest, 'manuf'))
    
    # Clean up unnecessary Qt files
    platforms_dir = os.path.join(output_dir, 'PyQt5', 'Qt5', 'plugins', 'platforms')
    if not os.path.exists(platforms_dir):
        platforms_dir = os.path.join(output_dir, 'PyQt5', 'Qt', 'plugins', 'platforms')
    
    if os.path.exists(platforms_dir):
        for dll in os.listdir(platforms_dir):
            if 'qwindows' not in dll.lower():
                try:
                    os.remove(os.path.join(platforms_dir, dll))
                except:
                    pass
    
    # Remove unnecessary Qt folders
    for folder in ['translations', 'imageformats', 'iconengines']:
        for qt_path in ['PyQt5/Qt5/plugins', 'PyQt5/Qt/plugins', 'PyQt5/Qt5', 'PyQt5/Qt']:
            folder_path = os.path.join(output_dir, qt_path, folder)
            if os.path.exists(folder_path):
                try:
                    shutil.rmtree(folder_path)
                except:
                    pass
    
    # Clean up build artifacts
    for cleanup in ['dist', 'build', 'version_info.txt', 'elmocut.spec']:
        try:
            if os.path.isdir(cleanup):
                shutil.rmtree(cleanup)
            elif os.path.exists(cleanup):
                os.remove(cleanup)
        except:
            pass
    
    elapsed = time.time() - start_time
    
    print("\n" + "=" * 50)
    print(f" BUILD COMPLETE in {int(elapsed)} seconds")
    print("=" * 50)
    print(f"\nOutput: {os.path.abspath(output_dir)}")
    print(f"Executable: {APP_NAME}.exe")
    print("\nThe exe will automatically request admin privileges.")
    
    return 0


if __name__ == '__main__':
    sys.exit(main())

