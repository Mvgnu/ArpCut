"""Root-helper service identity: socket path, LaunchDaemon plist, install glue.

The current macOS installer authorizes a root-managed LaunchDaemon with the
native administrator prompt and ``launchctl``. Signed ``SMAppService`` /
``SMJobBless`` registration is future deployment work. This module holds the
identity and plist, and lets the running code locate the socket.
"""
from __future__ import annotations

import plistlib
import sys

HELPER_LABEL = 'com.arpcut.helper'
HELPER_UID_ENV = 'ARPCUT_ALLOWED_UID'

# Root-created socket, owned by the authorized GUI user with mode 0600.
if sys.platform == 'darwin':
    SOCKET_PATH = '/var/run/com.arpcut.helper.sock'
elif sys.platform.startswith('linux'):
    SOCKET_PATH = '/run/com.arpcut.helper.sock'
else:
    SOCKET_PATH = ''  # Windows elevates the whole process via UAC, no helper daemon


def launchd_plist(program_args: "list[str]", allowed_uid: int | None = None) -> str:
    """LaunchDaemon plist XML that runs the helper as root at load."""
    data = {'Label': HELPER_LABEL, 'ProgramArguments': list(program_args),
            'RunAtLoad': True, 'KeepAlive': True}
    if allowed_uid is not None:
        if isinstance(allowed_uid, bool) or not isinstance(allowed_uid, int) or allowed_uid < 0:
            raise ValueError('allowed_uid must be a nonnegative integer')
        data['EnvironmentVariables'] = {HELPER_UID_ENV: str(allowed_uid)}
    # plistlib escapes paths and bootstrap strings containing '&', '<', etc.
    return plistlib.dumps(data, sort_keys=False).decode('utf-8')


INSTALL_NOTES = """\
Current macOS install:
  1. Use a packaged app in protected, root-owned paths (including the full bundle).
  2. install.install_helper() authorizes a LaunchDaemon via the native prompt and launchctl.
  3. The socket permits only root and the recorded installing user's peer UID.
Source installs use one-time elevation. Linux has no persistent-helper installer.
Signed SMAppService registration/unregistration remains future deployment work.
"""
