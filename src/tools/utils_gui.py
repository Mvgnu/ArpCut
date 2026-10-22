import os
from collections.abc import Mapping
from copy import deepcopy
from os import path, makedirs, rename
from json import dump, load
from tempfile import NamedTemporaryFile
from threading import RLock
from typing import Any, Optional
import ctypes
import sys
try:
    import winreg  # Windows only
except ImportError:
    winreg = None  # Not available on macOS/Linux

from constants import (
    DOCUMENTS_PATH, SETTINGS_PATH, OLD_DOCUMENTS_PATH, OLD_SETTINGS_PATH,
    NPCAP_PATH, HKEY_AUTOSTART_PATH, SETTINGS_KEYS, SETTINGS_VALS,
)

_settings_lock = RLock()


def is_admin() -> bool:
    """Check if the current user has the elevation ArpCut needs.

    On POSIX every core operation (raw/BPF sockets, pfctl/nft, sysctl
    ip-forwarding) requires root, so report the real euid instead of
    assuming True — otherwise root failures are swallowed and the app
    'runs but does nothing'.
    """
    if sys.platform.startswith('win'):
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    return getattr(os, 'geteuid', lambda: 0)() == 0


def npcap_exists() -> bool:
    """Check for Npcap driver (Windows only)."""
    if sys.platform.startswith('win'):
        return path.exists(NPCAP_PATH)
    # macOS/Linux uses libpcap (bundled); always True
    return True


def duplicate_elmocut() -> bool:
    """Check if another instance of ArpCut is already running.
    TODO: Implement via PID file or platform-specific lock."""
    return False


def check_documents_dir() -> None:
    """Ensure config directory exists and settings file is initialized."""
    makedirs(DOCUMENTS_PATH, exist_ok=True)
    if not path.exists(SETTINGS_PATH):
        export_settings()


def import_settings() -> dict[str, Any]:
    """Load stored settings from JSON file."""
    with _settings_lock:
        check_documents_dir()
        with open(SETTINGS_PATH, 'r', encoding='utf-8') as f:
            stored = load(f)
        if not isinstance(stored, dict):
            raise ValueError('Settings must be a JSON object')
        result = deepcopy(dict(zip(SETTINGS_KEYS, SETTINGS_VALS)))
        result.update(stored)
        return result


def export_settings(values: Optional[list[Any] | Mapping[str, Any]] = None) -> None:
    """Atomically save settings by key, retaining the legacy list API."""
    with _settings_lock:
        settings = deepcopy(dict(zip(SETTINGS_KEYS, SETTINGS_VALS)))
        if isinstance(values, Mapping):
            settings.update(values)
        elif values is not None:
            settings.update(zip(SETTINGS_KEYS, values))
        directory = path.dirname(SETTINGS_PATH) or '.'
        makedirs(directory, exist_ok=True)
        temporary = None
        try:
            with NamedTemporaryFile(mode='w', encoding='utf-8', dir=directory,
                                    prefix='.arpcut-', suffix='.json', delete=False) as f:
                temporary = f.name
                dump(settings, f)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temporary, SETTINGS_PATH)
        finally:
            if temporary is not None and path.exists(temporary):
                os.unlink(temporary)


def set_settings(key: str, value: Any) -> None:
    """Update a single setting by key."""
    with _settings_lock:
        s = import_settings()
        s[key] = value
        export_settings(s)


def get_settings(key: str) -> Any:
    """Get a single setting value by key."""
    return import_settings()[key]


def repair_settings() -> None:
    """Merge stored settings with defaults to handle schema upgrades."""
    with _settings_lock:
        try:
            settings = import_settings()
        except (ValueError, UnicodeError):
            settings = None
        export_settings(settings)


def migrate_settings_file() -> None:
    """Migrate settings from old elmoCut path to new ArpCut path."""
    old_exists = path.exists(OLD_SETTINGS_PATH)
    new_exists = path.exists(SETTINGS_PATH)
    if old_exists and not new_exists:
        try:
            makedirs(DOCUMENTS_PATH, exist_ok=True)
            rename(OLD_SETTINGS_PATH, SETTINGS_PATH)
        except OSError as e:
            import logging
            logging.getLogger(__name__).warning('Settings migration failed: %s', e)


def add_to_startup(exe_path: str) -> None:
    """Add ArpCut to OS autostart (Windows only)."""
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


def remove_from_startup() -> None:
    """Remove ArpCut from OS autostart (Windows only)."""
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
