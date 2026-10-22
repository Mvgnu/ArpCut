"""Privilege boundary/lifecycle regressions; mock engine, local socketpairs only."""
import json
import os
import plistlib
import socket
import stat
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from privilege import client, helper, install
from privilege.client import HelperClient, HelperError, HelperSession
from privilege.protocol import MAX_FRAME_BYTES, Request, decode_request, decode_response, validate
from privilege.service import HELPER_UID_ENV, launchd_plist

requires_socket = pytest.mark.skipif(
    sys.platform != 'darwin' and not sys.platform.startswith('linux'),
    reason='helper peer credentials use Linux/macOS Unix sockets',
)


class Engine:
    def __init__(self):
        self.calls = []
        self.cleaned = threading.Event()
        self.on_flows = None

    def kill(self, mac):
        self.calls.append(mac)
        return True

    def cleanup(self):
        self.cleaned.set()
        return True


@pytest.fixture
def loopback():
    sessions, threads, sockets = [], [], []

    def connect(server, timeout=.25):
        a, b = socket.socketpair()
        a.settimeout(timeout)
        sockets.extend([a, b])
        thread = threading.Thread(target=server._serve_and_close, args=(b,), daemon=True)
        thread.start()
        threads.append(thread)
        session = HelperSession(connect=lambda: a, timeout=timeout)
        sessions.append(session)
        return session

    yield connect
    for session in sessions:
        session.close()
    for sock in sockets:
        sock.close()
    for thread in threads:
        thread.join(2)
        assert not thread.is_alive()


@requires_socket
def test_idle_session_remains_connected_and_close_triggers_cleanup(loopback):
    engine = Engine()
    session = loopback(helper.HelperServer(engine), timeout=.05)
    assert session.start()
    assert not engine.cleaned.wait(.15)  # longer than the connection timeout
    assert session.call('ping').result == 'pong'
    session.close()
    assert engine.cleaned.wait(2)


@requires_socket
def test_request_timeout_invalidates_session_instead_of_reusing_late_reply(loopback):
    release = threading.Event()

    class SlowEngine(Engine):
        def kill(self, mac):
            release.wait(2)
            return 'late kill result'

    engine = SlowEngine()
    session = loopback(helper.HelperServer(engine), timeout=.05)
    assert session.start()
    try:
        with pytest.raises(HelperError, match='timed out'):
            session.call('kill', mac='aa:bb:cc:dd:ee:ff')
        assert not session.available()
        with pytest.raises(HelperError, match='not connected'):
            session.call('ping')
    finally:
        release.set()
    assert engine.cleaned.wait(2)


@requires_socket
def test_scan_uses_its_longer_operation_deadline(monkeypatch, loopback):
    class SlowEngine(Engine):
        def scan(self, scan_type):
            threading.Event().wait(.12)
            return ['finished']

    monkeypatch.setitem(client._OPERATION_TIMEOUTS, 'scan', 1.0)
    session = loopback(helper.HelperServer(SlowEngine()), timeout=.05)
    assert session.start()
    assert session.call('scan', type='ping').result == ['finished']
    assert session.available()


@requires_socket
def test_one_owner_and_duplicate_subscribe_cannot_orphan_cleanup(loopback):
    engine = Engine()
    server = helper.HelperServer(engine)
    first = loopback(server)
    second = loopback(server)
    assert first.start()
    assert first.call('subscribe').ok  # idempotent, never duplicates ownership
    assert not second.start()
    assert not engine.cleaned.is_set()
    assert first.call('ping').result == 'pong'
    first.close()
    assert engine.cleaned.wait(2)


@requires_socket
def test_unrelated_uid_is_rejected_before_engine(monkeypatch, loopback):
    monkeypatch.setattr(helper, '_peer_uid', lambda conn: 4243)
    engine = Engine()
    session = loopback(helper.HelperServer(engine, allowed_uid=4242))
    assert not session.start()
    assert engine.calls == []
    assert not engine.cleaned.is_set()


@requires_socket
def test_invalid_subscribe_does_not_claim_session(loopback):
    engine = Engine()
    server = helper.HelperServer(engine)
    session = loopback(server)
    conn = session._connect()
    conn.sendall(b'{"cmd":"subscribe","args":{"unexpected":true}}\n')
    response = decode_response(conn.recv(4096).split(b'\n')[0])
    assert not response.ok
    assert server._session is None
    conn.shutdown(socket.SHUT_RDWR)
    assert not engine.cleaned.is_set()


@requires_socket
def test_oversized_unterminated_request_is_rejected(loopback):
    engine = Engine()
    session = loopback(helper.HelperServer(engine), timeout=2)
    conn = session._connect()
    conn.sendall(b' ' * (MAX_FRAME_BYTES + 1))
    response = decode_response(conn.recv(4096).split(b'\n')[0])
    assert not response.ok and 'too large' in response.error
    assert engine.calls == []


@pytest.mark.parametrize('payload', [[], None, {'cmd': []}, {'cmd': 'ping', 'args': []},
                                    {'cmd': 'ping', 'args': None}, {'cmd': 'ping', 'args': False}])
def test_malformed_request_shapes_are_rejected(payload):
    with pytest.raises(ValueError):
        decode_request(json.dumps(payload).encode())


@pytest.mark.parametrize('payload', [[], None, {'ok': 'false'}, {'ok': 1}, {'ok': True, 'error': []}])
def test_malformed_response_shapes_are_rejected(payload):
    with pytest.raises(ValueError):
        decode_response(json.dumps(payload).encode())


def test_validation_handles_unhashable_commands_and_rejects_trailing_newlines():
    assert validate([], {}) == 'command must be a string'
    assert validate('block_ip', {'ip': '10.0.0.1\n'})
    assert validate('kill', {'mac': 'aa:bb:cc:dd:ee:ff\n'})
    assert validate('set_iface', {'iface': 'en0\n'})


@pytest.mark.parametrize('count,threads', [(1, 12), (256, 12), (255, 0), (255, 65)])
def test_scan_resource_limits_match_the_gui(count, threads):
    assert validate('set_scan_params', {'count': count, 'threads': threads})


def test_launchd_plist_escapes_arguments_and_records_installing_uid():
    argv = ['/path/Arp & Cut.app/helper', 'a < b']
    data = plistlib.loads(launchd_plist(argv, allowed_uid=501).encode())
    assert data['ProgramArguments'] == argv
    assert data['EnvironmentVariables'] == {HELPER_UID_ENV: '501'}


def test_elevated_installer_preserves_original_nonroot_account(monkeypatch):
    monkeypatch.setattr(os, 'getuid', lambda: 0, raising=False)
    monkeypatch.setenv('SUDO_UID', '501')
    data = plistlib.loads(install.macos_daemon_plist().encode())
    assert data['EnvironmentVariables'][HELPER_UID_ENV] == '501'


def test_installer_does_not_persist_root_only_access_when_account_is_unknown(monkeypatch):
    monkeypatch.setattr(os, 'getuid', lambda: 0, raising=False)
    monkeypatch.delenv('SUDO_UID', raising=False)
    monkeypatch.setattr(sys, 'platform', 'linux')  # no macOS console fallback
    with pytest.raises(ValueError, match='standard user'):
        install.macos_daemon_plist()


def test_linux_helper_install_never_grants_capabilities(monkeypatch):
    monkeypatch.setattr(install, 'platform_name', lambda: 'linux')
    monkeypatch.setattr(install.subprocess, 'run', lambda *a, **kw: pytest.fail('must not run setcap'))
    ok, message = install.install_helper()
    assert not ok and 'PolicyKit' in message


def test_macos_source_install_never_persists_user_owned_python(monkeypatch):
    monkeypatch.setattr(install, 'platform_name', lambda: 'macos')
    monkeypatch.setattr(sys, 'frozen', False, raising=False)
    monkeypatch.setattr(install, '_run_admin_macos', lambda *a: pytest.fail('must not install a source daemon'))
    ok, message = install.install_helper()
    assert not ok and 'Grant Administrator Access' in message


@pytest.mark.parametrize('unsafe', ['user_owned_file', 'writable_parent', 'external_symlink', 'acl', None])
def test_macos_bundle_trust_checks_all_loaded_files_and_ancestors(monkeypatch, tmp_path, unsafe):
    bundle = tmp_path / 'ArpCut.app'
    executable = bundle / 'Contents' / 'MacOS' / 'ArpCut'
    executable.parent.mkdir(parents=True)
    executable.write_text('test executable')
    library = bundle / 'Contents' / 'runtime.so'
    library.write_text('test library')
    if unsafe == 'external_symlink':
        external = tmp_path / 'outside.so'
        external.write_text('outside bundle')
        library.unlink()
        try:
            library.symlink_to(external)
        except OSError:
            pytest.skip('test account cannot create symlinks')
    original_stat = Path.lstat

    def fake_stat(path):
        result = original_stat(path)
        mode = stat.S_IFMT(result.st_mode) | 0o755
        uid = 0
        if unsafe == 'user_owned_file' and path == library:
            uid = 501
        if unsafe == 'writable_parent' and path == tmp_path:
            mode |= 0o020
        return SimpleNamespace(st_uid=uid, st_mode=mode)

    monkeypatch.setattr(Path, 'lstat', fake_stat)
    monkeypatch.setattr(sys, 'frozen', True, raising=False)
    monkeypatch.setattr(sys, 'executable', str(executable))
    monkeypatch.setattr(os, 'geteuid', lambda: 501, raising=False)
    monkeypatch.setattr(os, 'access', lambda *a: False)
    monkeypatch.setattr(install, '_has_extended_acl', lambda path: unsafe == 'acl' and path == library)
    trusted, _ = install._trusted_helper_bundle()
    assert trusted is (unsafe is None)


def test_installer_embeds_plist_instead_of_reading_mutable_tempfile():
    script = install.macos_install_script('<plist>\'quoted & content</plist>')
    assert 'printf %s' in script
    assert 'cp ' not in script
    assert 'quoted & content' in script


def test_protected_device_rejected_at_engine_boundary():
    engine = helper.Engine.__new__(helper.Engine)
    engine.scanner = SimpleNamespace(devices=[{'mac': 'aa:bb:cc:dd:ee:ff', 'admin': True}])
    engine.killer = SimpleNamespace(kill=lambda *a: pytest.fail('must not control router'))
    with pytest.raises(ValueError, match='gateway'):
        engine.kill('aa:bb:cc:dd:ee:ff')


def test_restore_uses_original_owned_device_when_scan_lost_it():
    owned = {'mac': 'aa:bb:cc:dd:ee:ff', 'ip': '192.0.2.10'}
    restored = []
    engine = helper.Engine.__new__(helper.Engine)
    engine.scanner = SimpleNamespace(devices=[])
    engine.killer = SimpleNamespace(killed={owned['mac']: owned},
                                    unkill=lambda device: restored.append(device))
    assert engine.unkill(owned['mac'])
    assert restored == [owned]


def test_cleanup_attempts_every_resource_and_reports_failure(monkeypatch):
    calls = []

    def action(name, result=True):
        def run():
            calls.append(name)
            return result
        return run

    engine = helper.Engine.__new__(helper.Engine)
    engine.sniffer = SimpleNamespace(stop=action('capture', False))
    engine._dns = SimpleNamespace(clear=action('dns'))
    engine.killer = SimpleNamespace(unkill_all=action('devices'),
                                    hostblock=SimpleNamespace(clear=action('hosts')))
    monkeypatch.setitem(sys.modules, 'tools.firewall', SimpleNamespace(clear_all_rules=action('firewall')))
    assert engine.cleanup() is False
    assert calls == ['capture', 'dns', 'devices', 'hosts', 'firewall']


def test_interface_switch_aborts_when_old_state_cannot_be_restored(monkeypatch):
    old = SimpleNamespace(name='old')
    new = SimpleNamespace(name='new')
    engine = helper.Engine.__new__(helper.Engine)
    engine.scanner = SimpleNamespace(iface=old)
    engine._state_dirty = True
    engine.cleanup = lambda: False
    monkeypatch.setitem(sys.modules, 'tools.utils', SimpleNamespace(get_iface_by_name=lambda name: new))
    with pytest.raises(RuntimeError, match='restore'):
        engine.set_iface('new')
    assert engine.scanner.iface is old


def test_new_unprivileged_engine_can_select_adapter_without_root_cleanup(monkeypatch):
    new = SimpleNamespace(name='new')
    engine = helper.Engine.__new__(helper.Engine)
    engine._state_dirty = False
    engine.scanner = SimpleNamespace(iface=SimpleNamespace(name='old'), router={},
                                     init=lambda: None, add_me=lambda: None,
                                     add_router=lambda: None)
    engine.killer = SimpleNamespace()
    engine.status = lambda: {'iface': engine.scanner.iface.name}
    engine.cleanup = lambda: pytest.fail('new read-only engine has no root state to clear')
    monkeypatch.setitem(sys.modules, 'tools.utils', SimpleNamespace(get_iface_by_name=lambda name: new))
    monkeypatch.setitem(sys.modules, 'tools.utils_gui', SimpleNamespace(is_admin=lambda: False))
    assert engine.set_iface('new') == {'iface': 'new'}
    assert engine.killer.iface is new


@pytest.mark.parametrize('name,args', [('kill', ['mac']), ('spoof', ['mac']),
                                     ('one_way_kill', ['mac']), ('lag', ['mac', True]),
                                     ('kill_all', [])])
def test_engine_propagates_failed_device_operations(name, args):
    engine = helper.Engine.__new__(helper.Engine)
    engine._device = lambda mac: {'mac': mac}
    engine.scanner = SimpleNamespace(devices=[])
    engine.killer = SimpleNamespace(**{name: lambda *a: False})
    assert getattr(engine, name)(*args) is False
    assert engine._state_dirty  # partial work must still be restored before a switch


def test_disabling_forwarding_does_not_report_a_noop_as_success(monkeypatch):
    engine = helper.Engine.__new__(helper.Engine)
    monkeypatch.setitem(sys.modules, 'networking.killer',
                        SimpleNamespace(enable_ip_forwarding=lambda: pytest.fail('must not enable forwarding')))
    with pytest.raises(ValueError, match='not supported'):
        engine.set_forwarding(False)


def test_flow_snapshot_matches_ui_limit_and_stays_within_frame_budget():
    flows = {('192.0.2.1', port, 'TCP'): {'bytes': port, 'packets': 1}
             for port in range(1, 10001)}
    engine = helper.Engine.__new__(helper.Engine)
    engine.sniffer = SimpleNamespace(get_flows=lambda: flows)
    snapshot = engine.flows()
    assert len(snapshot) == 200
    assert snapshot[0]['port'] == 10000
    assert len(json.dumps({'event': 'flows', 'flows': snapshot}).encode()) < MAX_FRAME_BYTES


@requires_socket
def test_orderly_helper_shutdown_cleans_and_terminates_session(loopback):
    engine = Engine()
    server = helper.HelperServer(engine)
    session = loopback(server)
    assert session.start()
    assert server.close()
    assert engine.cleaned.is_set()
    with pytest.raises(HelperError):
        session.call('kill', mac='aa:bb:cc:dd:ee:ff')
    assert engine.calls == []
