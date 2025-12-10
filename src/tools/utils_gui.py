from os import path, makedirs, rename
from json import dump, load, JSONDecodeError
import ctypes
import sys
try:
    import winreg  # Windows only
except Exception:
    winreg = None

from tools.utils import terminal
from constants import *



def is_admin():
    """
    Check if current user is Admin
    """
    if sys.platform.startswith('win'):
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    # On macOS/Linux, assume current user context (no UAC)
    return True

def npcap_exists():
    """
    Check for Npcap driver (Windows only)
    """
    if sys.platform.startswith('win'):
        return path.exists(NPCAP_PATH)
    # macOS/Linux uses libpcap (bundled); always True
    return True

def duplicate_elmocut():
    """
    Check if there is more than 1 instance of ArpCut running
    """
    if sys.platform.startswith('win'):
        try:
            tasklist = terminal('tasklist')
            if not tasklist:
                return False
            # Count actual process entries (each on its own line)
            count = 0
            for line in tasklist.lower().split('\n'):
                if 'arpcut.exe' in line:
                    count += 1
            return count > 1
        except Exception:
            return False
    # TODO: Implement PID/file lock if needed for macOS
    return False

def check_documents_dir():
    """
    Check if documents folder exists in order to store settings
    """
    makedirs(DOCUMENTS_PATH, exist_ok=True)
    if not path.exists(SETTINGS_PATH):
        export_settings()

def import_settings():
    """
    Get stored settings
    """
    check_documents_dir()
    return load(open(SETTINGS_PATH))

def export_settings(values=None):
    """
    Store current settings (or create new)
    """
    keys = SETTINGS_KEYS
    values = values if values else SETTINGS_VALS
    json = dict(zip(keys, values))
    dump(json, open(SETTINGS_PATH, 'w'))

def set_settings(key, value):
    """
    Update certain setting item
    """
    s = import_settings()
    s[key] = value
    export_settings(list(s.values()))

def get_settings(key):
    """
    Get certain setting item by key
    """
    return import_settings()[key]

def repair_settings():
    """
    Rescue elmocut from new settings not found after updates
    """
    original = dict(zip(SETTINGS_KEYS, SETTINGS_VALS))
    
    try:
        s = import_settings()
        for key in s:
            original[key] = s[key]
    except JSONDecodeError:
        pass
        
    export_settings(list(original.values()))

def migrate_settings_file():
    old_exists = path.exists(OLD_SETTINGS_PATH)
    new_exists = path.exists(SETTINGS_PATH)
    if old_exists and not new_exists:
        try:
            makedirs(DOCUMENTS_PATH, exist_ok=True)
            rename(OLD_SETTINGS_PATH, SETTINGS_PATH)
        except Exception as e:
            print(f'Migrating settings error: {e}')
            print('New settings file created instead.')

def add_to_startup(exe_path):
    """
    Add ArpCut to autostart
    """
    if sys.platform.startswith('win') and winreg:
        key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                HKEY_AUTOSTART_PATH,
                0,
                winreg.KEY_SET_VALUE
            )
        winreg.SetValueEx(
            key,
            'arpcut',
            0,
            winreg.REG_SZ, exe_path
        )

def remove_from_startup():
    """
    Remove ArpCut from autostart
    """
    if sys.platform.startswith('win') and winreg:
        key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                HKEY_AUTOSTART_PATH,
                0,
                winreg.KEY_WRITE
            )
        try:
            winreg.DeleteValue(key, 'arpcut')
        except FileNotFoundError:
            pass