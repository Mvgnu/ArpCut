"""Tests for the privilege-separation layer: protocol, dispatch, client↔server.

A mock engine stands in for the real (scapy/root) engine, so these run anywhere.
"""
import os
import socket
import sys
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from privilege.protocol import (  # noqa: E402
    COMMANDS, Request, Response, encode, decode_request, decode_response, validate,
)
from privilege.helper import HelperServer  # noqa: E402
from privilege.client import HelperClient  # noqa: E402
from privilege.service import launchd_plist, HELPER_LABEL  # noqa: E402


class MockEngine:
    def __init__(self):
        self.calls = []

    def status(self):
        return {'admin': True, 'iface': 'en0'}

    def scan(self, t):
        self.calls.append(('scan', t)); return [{'mac': 'aa:bb:cc:dd:ee:ff'}]

    def devices(self):
        return []

    def kill(self, mac):
        self.calls.append(('kill', mac)); return True

    def unkill(self, mac):
        self.calls.append(('unkill', mac)); return True

    def kill_all(self):
        return True

    def unkill_all(self):
        return True

    def one_way_kill(self, mac):
        self.calls.append(('one_way_kill', mac)); return True

    def block_ip(self, ip, direction='both'):
        self.calls.append(('block_ip', ip, direction)); return True

    def unblock_ip(self, ip):
        return True

    def block_port(self, port, proto='tcp', direction='both', target_ip=None):
        self.calls.append(('block_port', port, proto, target_ip)); return True

    def unblock_port(self, port, proto='tcp'):
        return True

    def block_host(self, target, iface=None):
        self.calls.append(('block_host', target, iface))
        return {'key': 'psn-comms', 'added': ['1.1.1.1'], 'ok': True}

    def unblock_host(self, key):
        return True

    def refresh_hosts(self):
        return {}

    def active_host_blocks(self):
        return {}

    def set_forwarding(self, enabled):
        self.calls.append(('set_forwarding', enabled)); return True


# ---- protocol validation ---------------------------------------------------

def test_validate_ok():
    assert validate('kill', {'mac': 'aa:bb:cc:dd:ee:ff'}) is None
    assert validate('ping', {}) is None
    assert validate('block_ip', {'ip': '10.0.0.5'}) is None  # optional direction


def test_validate_unknown_command():
    assert 'unknown command' in validate('rm_rf', {})


def test_validate_missing_required_arg():
    assert 'missing argument: mac' == validate('kill', {})


def test_validate_bad_mac_rejected():
    assert 'invalid argument: mac' == validate('kill', {'mac': 'not-a-mac'})


def test_validate_bad_ip_rejected():
    assert validate('block_ip', {'ip': '999.1.1.1'}) is not None


def test_validate_unexpected_arg():
    assert 'unexpected argument' in validate('ping', {'sneaky': 1})


def test_no_shell_or_exec_command_exists():
    # The privileged surface is exactly the registry — no arbitrary-exec verb.
    for bad in ('exec', 'shell', 'run', 'system', 'eval'):
        assert bad not in COMMANDS


# ---- wire round-trip -------------------------------------------------------

def test_request_round_trip():
    r = decode_request(encode(Request('kill', {'mac': 'aa:bb:cc:dd:ee:ff'})))
    assert r.cmd == 'kill' and r.args == {'mac': 'aa:bb:cc:dd:ee:ff'}


def test_response_round_trip():
    r = decode_response(encode(Response(ok=True, result={'x': 1})))
    assert r.ok is True and r.result == {'x': 1} and r.error is None


# ---- server dispatch (mock engine) -----------------------------------------

def test_handle_ping():
    s = HelperServer(MockEngine())
    assert s.handle(Request('ping', {})).result == 'pong'


def test_handle_kill_dispatches():
    e = MockEngine(); s = HelperServer(e)
    resp = s.handle(Request('kill', {'mac': 'aa:bb:cc:dd:ee:ff'}))
    assert resp.ok and ('kill', 'aa:bb:cc:dd:ee:ff') in e.calls


def test_handle_invalid_arg_never_reaches_engine():
    e = MockEngine(); s = HelperServer(e)
    resp = s.handle(Request('kill', {'mac': 'bad'}))
    assert not resp.ok and 'invalid argument' in resp.error
    assert e.calls == []  # engine untouched — validated first


def test_handle_unknown_command():
    s = HelperServer(MockEngine())
    resp = s.handle(Request('drop_tables', {}))
    assert not resp.ok and 'unknown command' in resp.error


def test_handle_block_host_returns_dict():
    e = MockEngine(); s = HelperServer(e)
    resp = s.handle(Request('block_host', {'target': 'psn-comms'}))
    assert resp.ok and resp.result['key'] == 'psn-comms'
    assert ('block_host', 'psn-comms', None) in e.calls


def test_handle_engine_error_becomes_error_response():
    class Boom(MockEngine):
        def kill(self, mac):
            raise RuntimeError('no root')
    s = HelperServer(Boom())
    resp = s.handle(Request('kill', {'mac': 'aa:bb:cc:dd:ee:ff'}))
    assert not resp.ok and 'no root' in resp.error


# ---- client ↔ server loopback (real sockets) -------------------------------

def _loopback_call(cmd, **args) -> Response:
    a, b = socket.socketpair()
    engine = MockEngine()
    t = threading.Thread(target=HelperServer(engine).serve_connection,
                         args=(b,), daemon=True)
    t.start()
    try:
        return HelperClient(connect=lambda: a).call(cmd, **args), engine
    finally:
        b.close()


def test_loopback_ping():
    resp, _ = _loopback_call('ping')
    assert resp.ok and resp.result == 'pong'


def test_loopback_block_host_end_to_end():
    resp, engine = _loopback_call('block_host', target='gta-save')
    assert resp.ok and resp.result['key'] == 'psn-comms'  # mock returns fixed key
    assert engine.calls and engine.calls[0][0] == 'block_host'


def test_loopback_bad_request_json():
    a, b = socket.socketpair()
    threading.Thread(target=HelperServer(MockEngine()).serve_connection,
                     args=(b,), daemon=True).start()
    a.sendall(b'not json\n')
    line = a.recv(4096)
    b.close(); a.close()
    assert b'bad request' in line


# ---- service identity ------------------------------------------------------

def test_launchd_plist_contains_label_and_args():
    plist = launchd_plist(['/usr/bin/python3', '-m', 'privilege.helper'])
    assert HELPER_LABEL in plist
    assert '<string>/usr/bin/python3</string>' in plist
    assert 'RunAtLoad' in plist
