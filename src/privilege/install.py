"""Privilege setup — detect state and grant access without a terminal.

Client-safe (no scapy). Two jobs:

* **`status()`** — is the app privileged right now (root, or a running helper)?
* **grant access** — either relaunch elevated (`elevate()`, works today on every
  OS via the native auth prompt) or install the persistent root **helper daemon**
  (`install_helper()`, the Wireshark/Little-Snitch model). Both surface a native
  password/UAC prompt — no Terminal, no commands to type.

Command/plist construction is kept pure and importable so it is unit-testable
without actually triggering a privilege prompt.
"""
from __future__ import annotations

import os
import shlex
import subprocess
import sys
import tempfile

from privilege.service import HELPER_LABEL, SOCKET_PATH, launchd_plist

DAEMON_PLIST = '/Library/LaunchDaemons/com.arpcut.helper.plist'


def platform_name() -> str:
    if sys.platform == 'darwin':
        return 'macos'
    if sys.platform.startswith('win'):
        return 'windows'
    return 'linux'


def is_root() -> bool:
    return getattr(os, 'geteuid', lambda: 1)() == 0


def helper_available() -> bool:
    if not SOCKET_PATH:
        return False
    try:
        from privilege.client import HelperClient
        return HelperClient().available()
    except Exception:  # noqa: BLE001
        return False


def status() -> dict:
    """Current privilege state, for the setup UI."""
    root = is_root()
    helper = helper_available()
    return {
        'platform': platform_name(),
        'root': root,
        'helper_installed': os.path.exists(DAEMON_PLIST) if platform_name() == 'macos' else False,
        'helper_running': helper,
        'ok': root or helper,
    }


# -- what to run as root -----------------------------------------------------

def _entry_argv() -> list[str]:
    """Argv that (re)launches ArpCut. Frozen bundle → the app binary; dev → the
    interpreter + entry script."""
    if getattr(sys, 'frozen', False):
        return [sys.executable]
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../src
    return [sys.executable, os.path.join(src, 'elmocut.py')]


def helper_argv() -> list[str]:
    """Argv the root daemon runs. Frozen → the app binary itself with ``--helper``
    (it already bundles everything); dev → an interpreter bootstrap that injects
    ``src`` onto ``sys.path`` and runs the daemon."""
    if getattr(sys, 'frozen', False):
        return [sys.executable, '--helper']
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    boot = (f'import sys; sys.path.insert(0, {src!r}); '
            f'from privilege.helper import main; sys.exit(main())')
    return [sys.executable, '-c', boot]


# -- macOS -------------------------------------------------------------------

def macos_daemon_plist() -> str:
    return launchd_plist(helper_argv())


def macos_install_script(plist_src: str) -> str:
    """Shell script (run once as root) that installs + starts the LaunchDaemon."""
    dst = shlex.quote(DAEMON_PLIST)
    src = shlex.quote(plist_src)
    return (
        f'mkdir -p /Library/LaunchDaemons && '
        f'cp {src} {dst} && chown root:wheel {dst} && chmod 644 {dst} && '
        f'(launchctl bootstrap system {dst} 2>/dev/null || launchctl load {dst})'
    )


def macos_uninstall_script() -> str:
    dst = shlex.quote(DAEMON_PLIST)
    return (f'(launchctl bootout system {dst} 2>/dev/null || launchctl unload {dst} 2>/dev/null); '
            f'rm -f {dst}')


def _osa_str(s: str) -> str:
    """Quote a Python string as an AppleScript string literal."""
    return '"' + s.replace('\\', '\\\\').replace('"', '\\"') + '"'


def _run_admin_macos(shell_script: str) -> tuple[bool, str]:
    """Run a shell script once as root via the native admin prompt (osascript)."""
    apple = f'do shell script {_osa_str(shell_script)} with administrator privileges'
    try:
        r = subprocess.run(['osascript', '-e', apple], capture_output=True, text=True)
    except OSError as exc:
        return False, f'Could not launch the authorization prompt: {exc}'
    if r.returncode == 0:
        return True, 'Done.'
    err = (r.stderr or '').strip()
    if 'User canceled' in err or '-128' in err:
        return False, 'Cancelled.'
    return False, err or 'Authorization failed.'


# -- public grant actions ----------------------------------------------------

def install_helper() -> tuple[bool, str]:
    """Install + start the persistent root helper daemon (macOS/Linux)."""
    plat = platform_name()
    if plat == 'macos':
        with tempfile.NamedTemporaryFile('w', suffix='.plist', delete=False) as f:
            f.write(macos_daemon_plist())
            tmp = f.name
        ok, msg = _run_admin_macos(macos_install_script(tmp))
        try:
            os.unlink(tmp)
        except OSError:
            pass
        return (ok, 'Background helper installed — ArpCut now has full access.') if ok else (ok, msg)
    if plat == 'linux':
        return _install_helper_linux()
    return False, 'Windows uses UAC elevation instead of a helper daemon.'


def elevate() -> tuple[bool, str]:
    """Relaunch ArpCut with administrator access (native prompt), then the caller
    should quit this instance. Works today on every platform."""
    plat = platform_name()
    if plat == 'macos':
        inner = ' '.join(shlex.quote(a) for a in _entry_argv()) + ' >/dev/null 2>&1 &'
        return _run_admin_macos(inner)
    if plat == 'windows':
        return _elevate_windows()
    return _elevate_linux()


def _elevate_windows() -> tuple[bool, str]:
    try:
        import ctypes
        argv = _entry_argv()
        params = ' '.join(f'"{a}"' for a in argv[1:])
        rc = ctypes.windll.shell32.ShellExecuteW(None, 'runas', argv[0], params, None, 1)
        return (rc > 32, 'Relaunching with administrator access…' if rc > 32
                else 'Elevation was declined.')
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _elevate_linux() -> tuple[bool, str]:
    if not _which('pkexec'):
        return False, 'Install pkexec (PolicyKit) or run: sudo arpcut'
    try:
        subprocess.Popen(['pkexec'] + _entry_argv())
        return True, 'Relaunching with administrator access…'
    except OSError as exc:
        return False, str(exc)


def _install_helper_linux() -> tuple[bool, str]:
    """Best-effort: grant the interpreter raw-net capabilities via pkexec setcap."""
    if not _which('pkexec') or not _which('setcap'):
        return False, 'Install pkexec + setcap, or run: sudo arpcut'
    target = sys.executable
    try:
        r = subprocess.run(
            ['pkexec', 'setcap', 'cap_net_raw,cap_net_admin+ep', target],
            capture_output=True, text=True)
        return (r.returncode == 0,
                'Network capabilities granted.' if r.returncode == 0
                else (r.stderr.strip() or 'setcap failed.'))
    except OSError as exc:
        return False, str(exc)


def uninstall_helper() -> tuple[bool, str]:
    if platform_name() == 'macos':
        return _run_admin_macos(macos_uninstall_script())
    return True, 'Nothing to uninstall.'


def _which(name: str) -> bool:
    from shutil import which
    return which(name) is not None
