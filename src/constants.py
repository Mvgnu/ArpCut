from os import path, environ
import sys

# Cross-platform settings paths
if sys.platform.startswith('win'):
    OLD_DOCUMENTS_PATH = path.join(environ.get('USERPROFILE', ''), 'Documents', 'elmocut')
    DOCUMENTS_PATH = path.join(environ.get('APPDATA', ''), 'elmocut')
else:
    home = environ.get('HOME', '')
    if sys.platform == 'darwin':
        DOCUMENTS_PATH = path.join(home, 'Library', 'Application Support', 'elmocut')
    else:
        DOCUMENTS_PATH = path.join(home, '.config', 'elmocut')
    OLD_DOCUMENTS_PATH = DOCUMENTS_PATH

OLD_SETTINGS_PATH = path.join(OLD_DOCUMENTS_PATH, 'elmocut.json')
SETTINGS_PATH = path.join(DOCUMENTS_PATH, 'elmocut.json')

TABLE_HEADER_LABELS = ['IP Address', 'MAC Address', 'Vendor', 'Type', 'Nickname']

# Windows-only Npcap details (ignored on macOS/Linux)
NPCAP_URL = 'https://nmap.org/npcap/dist/npcap-1.50.exe'
NPCAP_PATH = 'C:\\Windows\\SysWOW64\\Npcap'

GLOBAL_MAC = 'FF:FF:FF:FF:FF:FF'

DUMMY_ROUTER = {
    'ip': '192.168.1.1',
    'mac': 'FF:FF:FF:FF:FF:FF',
    'vendor': 'NONE',
    'type': 'Router',
    'name': '-',
    'admin': True
}

DUMMY_IFACE = {'name': 'NULL', 'mac': GLOBAL_MAC, 'guid': 'NULL', 'ips': ['0.0.0.0']}

HKEY_AUTOSTART_PATH = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run'

SETTINGS_KEYS = ['dark', 'count', 'autostart', 'minimized', 'remember', 'killed', 'autoupdate', 'threads', 'iface', 'nicknames']

SETTINGS_VALS = [True, 255, False, True, False, [], True, 12, '', {}]
