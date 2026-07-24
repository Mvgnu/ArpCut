"""Root-helper service identity: socket path, LaunchDaemon plist, install glue.

The privileged helper is registered as a LaunchDaemon via ``SMAppService``
(macOS 13+) or the legacy ``SMJobBless``. That registration + notarization is the
deploy step (needs a Developer ID); this module holds the identity and the plist
so the deploy is mechanical, and the running code can locate the socket.
"""
from __future__ import annotations

import sys

HELPER_LABEL = 'com.arpcut.helper'

# Root-created socket, chmod 0666 so the unprivileged GUI can connect.
if sys.platform == 'darwin':
    SOCKET_PATH = '/var/run/com.arpcut.helper.sock'
elif sys.platform.startswith('linux'):
    SOCKET_PATH = '/run/com.arpcut.helper.sock'
else:
    SOCKET_PATH = ''  # Windows elevates the whole process via UAC, no helper daemon


def launchd_plist(program_args: "list[str]") -> str:
    """LaunchDaemon plist XML that runs the helper as root at load."""
    args_xml = '\n'.join(f'        <string>{a}</string>' for a in program_args)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" '
        '"http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
        '<plist version="1.0">\n'
        '<dict>\n'
        f'    <key>Label</key><string>{HELPER_LABEL}</string>\n'
        '    <key>ProgramArguments</key>\n'
        '    <array>\n'
        f'{args_xml}\n'
        '    </array>\n'
        '    <key>RunAtLoad</key><true/>\n'
        '    <key>KeepAlive</key><true/>\n'
        '</dict>\n'
        '</plist>\n'
    )


INSTALL_NOTES = """\
macOS install (one-time; a Developer ID makes it double-clickable):
  1. Bundle the helper in Contents/Library/LaunchDaemons of the .app.
  2. Register with SMAppService.daemon(plistName:) — a single admin auth prompt.
  3. The GUI connects to SOCKET_PATH; if HelperClient.available() is False,
     offer to (re)install/register the daemon.
Uninstall must SMAppService.unregister() and flush firewall rules (clear_anchor).
"""
