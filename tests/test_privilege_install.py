"""Tests for privilege.install — command/plist construction (no execution).

None of these trigger a real privilege prompt; they only assert that the shell
scripts, argv, and plist we would hand to the authorization prompt are correct.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from privilege import install  # noqa: E402
from privilege.service import HELPER_LABEL  # noqa: E402


def test_platform_name_is_known():
    assert install.platform_name() in ('macos', 'windows', 'linux')


def test_status_shape():
    st = install.status()
    assert set(st) >= {'platform', 'root', 'helper_installed', 'helper_running', 'ok'}
    assert isinstance(st['root'], bool)
    assert st['ok'] == (st['root'] or st['helper_running'])


def test_helper_argv_dev_bootstrap():
    argv = install.helper_argv()
    # dev path: interpreter + a self-contained bootstrap that injects src on sys.path
    assert argv[0] == sys.executable
    assert '-c' in argv
    boot = argv[-1]
    assert 'privilege.helper' in boot and 'sys.path.insert' in boot


def test_entry_argv_points_at_launcher():
    argv = install._entry_argv()
    assert argv[0] == sys.executable
    assert argv[-1].endswith('elmocut.py')


def test_macos_daemon_plist_has_label_and_bootstrap():
    plist = install.macos_daemon_plist()
    assert HELPER_LABEL in plist
    assert 'RunAtLoad' in plist and 'KeepAlive' in plist
    assert 'privilege.helper' in plist  # the -c bootstrap is embedded as an arg


def test_macos_install_script_installs_and_starts():
    sc = install.macos_install_script('/tmp/arpcut.plist')
    assert '/tmp/arpcut.plist' in sc
    assert install.DAEMON_PLIST in sc
    assert 'chown root:wheel' in sc and 'chmod 644' in sc
    assert 'launchctl bootstrap system' in sc or 'launchctl load' in sc


def test_macos_uninstall_script_removes():
    sc = install.macos_uninstall_script()
    assert install.DAEMON_PLIST in sc
    assert 'rm -f' in sc
    assert 'bootout' in sc or 'unload' in sc


def test_osa_string_escapes_quotes_and_backslashes():
    assert install._osa_str('a "b" \\c') == '"a \\"b\\" \\\\c"'
