"""Controller spoof/block coupling — the new device-routing model.

Drives the Controller against a recording mock ``ops`` (no scapy, no root, no
socket) so it runs on every platform: blockers auto-spoof, un-spoofing clears a
device's blocks, and Restore-all tears everything down.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))
os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')

import pytest
from PySide6.QtWidgets import QApplication

_app = QApplication.instance() or QApplication([])

from gui.controller import Controller

PS5 = 'aa:bb:cc:dd:ee:03'
DEV = {'ip': '192.168.1.42', 'mac': PS5, 'vendor': 'Sony',
       'type': 'User', 'name': 'PS5', 'admin': False}


class MockOps:
    """Records every call; returns truthy defaults."""

    def __init__(self):
        self.calls = []
        self.on_flows = None

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)

        def f(*a, **k):
            self.calls.append((name, a, k))
            if name == 'status':
                return {}
            return True
        return f

    def names(self):
        return [c[0] for c in self.calls]


def _ctrl():
    ops = MockOps()
    c = Controller(ops=ops)
    c._devices = [dict(DEV)]
    c._privileged = True
    c._admin = True
    return c, ops


def test_port_block_autospoofs_and_tracks():
    c, ops = _ctrl()
    c.block_port(3074, 'udp', 'both', '192.168.1.42')   # async; tracks optimistically
    assert 'spoof' in ops.names()               # auto-routed through us
    assert c.is_spoofed(PS5)
    assert c.device_blocks(PS5) == ['1 port block']


def test_unspoof_clears_device_blocks():
    c, ops = _ctrl()
    c.block_port(3074, 'udp', 'both', '192.168.1.42')
    c.toggle_spoof(PS5)                          # user turns routing OFF
    assert not c.is_spoofed(PS5)
    assert c.device_blocks(PS5) == []
    assert 'unblock_port' in ops.names()         # the block was cleared
    assert 'unkill' in ops.names()               # and the spoof dropped


def test_explicit_spoof_toggle_on_off():
    c, ops = _ctrl()
    c.toggle_spoof(PS5)                          # ON
    assert c.is_spoofed(PS5) and 'spoof' in ops.names()
    c.toggle_spoof(PS5)                          # OFF (no blocks → just unspoof)
    assert not c.is_spoofed(PS5)


def test_monitor_uses_spoof_not_kill():
    c, ops = _ctrl()
    c.start_monitor(PS5)
    assert 'spoof' in ops.names()
    assert 'kill' not in ops.names()             # must NOT drop-all when monitoring
    assert 'start_sniff' in ops.names()


def test_lag_uses_spoof_and_lag_not_kill():
    c, ops = _ctrl()
    c.start_lag(PS5, 100, 100, 'both')
    assert 'spoof' in ops.names()
    assert 'kill' not in ops.names()
    assert 'lag' in ops.names()
    c.stop_lag()


def test_restore_all_calls_cleanup():
    c, ops = _ctrl()
    c.block_port(3074, 'udp', 'both', '192.168.1.42')
    c.unkill_all()
    assert 'cleanup' in ops.names()
    assert not c.is_spoofed(PS5)
    assert c._port_blocks == {}
