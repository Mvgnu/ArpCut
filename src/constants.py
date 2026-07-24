"""ArpCut global constants — paths, defaults, settings schema."""
from pathlib import Path
from typing import Any
import sys

__version__: str = '2.0.0'

# ---------------------------------------------------------------------------
# Cross-platform settings paths  (migrated from os.path → pathlib)
# ---------------------------------------------------------------------------
if sys.platform.startswith('win'):
    import os
    OLD_DOCUMENTS_PATH: str = str(
        Path(os.environ.get('USERPROFILE', '')) / 'Documents' / 'elmocut'
    )
    DOCUMENTS_PATH: str = str(
        Path(os.environ.get('APPDATA', '')) / 'arpcut'
    )
else:
    import os
    _home = Path(os.environ.get('HOME', ''))
    if sys.platform == 'darwin':
        DOCUMENTS_PATH = str(_home / 'Library' / 'Application Support' / 'arpcut')
    else:
        DOCUMENTS_PATH = str(_home / '.config' / 'arpcut')
    OLD_DOCUMENTS_PATH = (
        str(_home / 'Library' / 'Application Support' / 'elmocut')
        if sys.platform == 'darwin'
        else str(_home / '.config' / 'elmocut')
    )

OLD_SETTINGS_PATH: str = str(Path(OLD_DOCUMENTS_PATH) / 'elmocut.json')
SETTINGS_PATH: str = str(Path(DOCUMENTS_PATH) / 'arpcut.json')

# ---------------------------------------------------------------------------
# UI constants
# ---------------------------------------------------------------------------
TABLE_HEADER_LABELS: list[str] = ['IP Address', 'MAC Address', 'Vendor', 'Type', 'Nickname']

# ---------------------------------------------------------------------------
# Windows-only Npcap details (ignored on macOS/Linux)
# ---------------------------------------------------------------------------
NPCAP_URL: str = 'https://nmap.org/npcap/dist/npcap-1.50.exe'
NPCAP_PATH: str = 'C:\\Windows\\SysWOW64\\Npcap'

# ---------------------------------------------------------------------------
# Network sentinel values
# ---------------------------------------------------------------------------
GLOBAL_MAC: str = 'FF:FF:FF:FF:FF:FF'

DUMMY_ROUTER: dict[str, Any] = {
    'ip': '192.168.1.1',
    'mac': 'FF:FF:FF:FF:FF:FF',
    'vendor': 'NONE',
    'type': 'Router',
    'name': '-',
    'admin': True,
}

DUMMY_IFACE: dict[str, Any] = {
    'name': 'NULL',
    'mac': GLOBAL_MAC,
    'guid': 'NULL',
    'ips': ['0.0.0.0'],
}

# ---------------------------------------------------------------------------
# Windows autostart registry key
# ---------------------------------------------------------------------------
HKEY_AUTOSTART_PATH: str = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'

# ---------------------------------------------------------------------------
# Settings schema — keys and their default values
# ---------------------------------------------------------------------------
SETTINGS_KEYS: list[str] = [
    'dark', 'count', 'autostart', 'minimized', 'remember',
    'killed', 'autoupdate', 'threads', 'iface', 'nicknames',
]

SETTINGS_VALS: list[Any] = [
    True, 255, False, True, False,
    [], True, 12, '', {},
]

# Typed dict mapping for dict-based settings access
SETTINGS_DEFAULTS: dict[str, Any] = dict(zip(SETTINGS_KEYS, SETTINGS_VALS))
