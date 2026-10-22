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
import ctypes
from pathlib import Path
import shlex
import stat
import subprocess
import sys

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
        return [os.path.realpath(sys.executable), '--helper']
    src = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    boot = (f'import sys; sys.path.insert(0, {src!r}); '
            f'from privilege.helper import main; sys.exit(main())')
    return [sys.executable, '-c', boot]


# -- macOS -------------------------------------------------------------------

def _installing_uid() -> int:
    uid = getattr(os, 'getuid', lambda: 0)()
    if uid != 0:
        return uid
    original = os.environ.get('SUDO_UID', '')
    if original.isascii() and original.isdecimal() and 0 < int(original) < 2**32 - 1:
        return int(original)
    if sys.platform == 'darwin':
        uid = os.stat('/dev/console').st_uid
        if uid != 0:
            return uid
    raise ValueError('Could not identify the standard user. Install the helper from a normal ArpCut launch.')


def macos_daemon_plist(allowed_uid: int | None = None) -> str:
    return launchd_plist(helper_argv(), allowed_uid=(
        _installing_uid() if allowed_uid is None else allowed_uid))


def macos_install_script(plist_content: str) -> str:
    """Shell script (run once as root) that installs + starts the LaunchDaemon."""
    dst = shlex.quote(DAEMON_PLIST)
    content = shlex.quote(plist_content)
    return (
        f'mkdir -p /Library/LaunchDaemons && '
        f'(launchctl bootout system {dst} 2>/dev/null || true) && '
        f'rm -f {dst} && umask 022 && printf %s {content} > {dst} && '
        f'chown root:wheel {dst} && chmod 644 {dst} && '
        f'(launchctl bootstrap system {dst} 2>/dev/null || launchctl load {dst})'
    )


def _trusted_helper_bundle() -> tuple[bool, str]:
    """A persistent root service must not load code its GUI user can replace."""
    guidance = ('Persistent helpers require a packaged app in a root-managed '
                'directory, with its bundle and parent paths owned by root and '
                'not writable by other users or governed by extended ACLs. '
                'Use Grant Administrator Access '
                'for this installation.')
    if not getattr(sys, 'frozen', False):
        return False, guidance
    try:
        executable = Path(sys.executable).resolve(strict=True)
        bundle = next((p for p in executable.parents if p.suffix == '.app'), None)
        if bundle is None:
            return False, guidance
        paths = [bundle, *bundle.parents]
        def walk_error(error):
            raise error

        for directory, dirs, files in os.walk(bundle, followlinks=False, onerror=walk_error):
            paths.extend(Path(directory) / name for name in dirs + files)
        for path in paths:
            info = path.lstat()
            if info.st_uid != 0:
                return False, guidance
            if _has_extended_acl(path):
                # Mode bits alone do not rule out access granted to another
                # local account. Persistent services conservatively reject ACLs.
                return False, guidance
            if path.is_symlink():
                # Framework symlinks inside the root-owned bundle are normal;
                # links to a checkout, venv, or other external code are not.
                if not path.resolve(strict=True).is_relative_to(bundle):
                    return False, guidance
            elif not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                return False, guidance
            elif info.st_mode & 0o022:
                return False, guidance
            elif os.geteuid() != 0 and os.access(path, os.W_OK):
                # Also account for an ACL granting the installing user writes.
                return False, guidance
        return True, ''
    except (OSError, RuntimeError, ValueError, AttributeError):
        return False, guidance


def _has_extended_acl(path: Path) -> bool:
    """Fail closed on macOS ACLs; this installer does not interpret ACL policy."""
    if sys.platform != 'darwin':
        return False
    libc = ctypes.CDLL(None, use_errno=True)
    get_acl = libc.acl_get_link_np
    get_acl.argtypes = [ctypes.c_char_p, ctypes.c_int]
    get_acl.restype = ctypes.c_void_p
    get_entry = libc.acl_get_entry
    get_entry.argtypes = [ctypes.c_void_p, ctypes.c_int,
                         ctypes.POINTER(ctypes.c_void_p)]
    get_entry.restype = ctypes.c_int
    free_acl = libc.acl_free
    free_acl.argtypes = [ctypes.c_void_p]
    free_acl.restype = ctypes.c_int
    acl = get_acl(os.fsencode(path), 0x100)  # ACL_TYPE_EXTENDED
    if not acl:
        return True
    try:
        entry = ctypes.c_void_p()
        ctypes.set_errno(0)
        if get_entry(acl, 0, ctypes.byref(entry)) == 0:  # ACL_FIRST_ENTRY
            return True
        import errno
        return ctypes.get_errno() != errno.EINVAL  # EINVAL: empty ACL
    finally:
        free_acl(acl)


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
    """Install + start the persistent root helper daemon on supported macOS apps."""
    plat = platform_name()
    if plat == 'macos':
        trusted, message = _trusted_helper_bundle()
        if not trusted:
            return False, message
        # Embed the reviewed plist in the authorization command. A user-owned
        # temporary file could be replaced while the password prompt is open.
        try:
            plist = macos_daemon_plist()
        except (OSError, ValueError) as exc:
            return False, str(exc)
        ok, msg = _run_admin_macos(macos_install_script(plist))
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
    """Linux has no persistent-helper installer yet; never modify Python caps."""
    return (False, 'Background helper installation is not supported on Linux. '
            'Use Grant Administrator Access (PolicyKit) for this session.')


def uninstall_helper() -> tuple[bool, str]:
    if platform_name() == 'macos':
        return _run_admin_macos(macos_uninstall_script())
    return True, 'Nothing to uninstall.'


def _which(name: str) -> bool:
    from shutil import which
    return which(name) is not None
