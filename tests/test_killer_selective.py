"""Killer selective/lag WinDivert state management (Windows-only paths).

These exercise the criteria accumulation/removal logic without a live WinDivert
driver (WINDIVERT_AVAILABLE monkeypatched off, so the rebuild is a no-op) — the
filter strings themselves are validated against the real engine in
test_windivert_forwarder.py. Skipped off Windows, where selective_block is a
deliberate no-op.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest

pytestmark = pytest.mark.skipif(
    not sys.platform.startswith('win'),
    reason='selective WinDivert blocking is a Windows-only kernel path')

from networking import killer as killer_mod
from networking import windivert_forwarder as wd


@pytest.fixture
def k(monkeypatch):
    # Don't touch the registry or the real driver during unit tests.
    monkeypatch.setattr(killer_mod, 'enable_ip_forwarding', lambda: True)
    monkeypatch.setattr(wd, 'WINDIVERT_AVAILABLE', False)
    return killer_mod.Killer()


def test_ports_accumulate(k):
    k.selective_block('192.168.1.42', ports=[443])
    assert k._wd_selective['192.168.1.42']['ports'] == {443}
    k.selective_block('192.168.1.42', ports=[80])
    assert k._wd_selective['192.168.1.42']['ports'] == {443, 80}


def test_dst_scoped(k):
    k.selective_block('192.168.1.42', dst_ips=['8.8.8.8'])
    assert k._wd_selective['192.168.1.42']['dsts'] == {'8.8.8.8'}


def test_unblock_one_port_keeps_others(k):
    k.selective_block('192.168.1.42', ports=[443, 80])
    k.selective_unblock('192.168.1.42', ports=[443])
    assert k._wd_selective['192.168.1.42']['ports'] == {80}


def test_unblock_all_removes_victim(k):
    k.selective_block('192.168.1.42', ports=[443])
    k.selective_unblock('192.168.1.42')
    assert '192.168.1.42' not in k._wd_selective


def test_unblock_port_across_all_victims(k):
    k.selective_block('192.168.1.42', ports=[3074])
    k.selective_block('192.168.1.50', ports=[3074])
    k.selective_unblock_port(3074)
    assert '192.168.1.42' not in k._wd_selective
    assert '192.168.1.50' not in k._wd_selective


def test_selective_block_noop_without_victim_entry(k):
    # unblocking an unknown victim is a harmless no-op
    assert k.selective_unblock('10.0.0.9') is True


def test_global_dst_mirrors_to_spoofed_victims(k):
    # a routed (poisoned) victim
    k.killed['aa:bb:cc:dd:ee:03'] = {'ip': '192.168.1.42', 'mac': 'aa:bb:cc:dd:ee:03'}
    k._apply_global_dst({'203.0.113.5', '198.51.100.9'})
    assert k._global_dst_blocks == {'203.0.113.5', '198.51.100.9'}
    dsts = k._wd_selective['192.168.1.42']['dsts']
    assert '203.0.113.5' in dsts and '198.51.100.9' in dsts


def test_reconcile_removes_stale_global_dst(k):
    k.killed['aa:bb:cc:dd:ee:03'] = {'ip': '192.168.1.42', 'mac': 'aa:bb:cc:dd:ee:03'}
    k._apply_global_dst({'203.0.113.5'})
    # hostblock has nothing active → reconcile drops the mirrored block
    k._reconcile_global_dst()
    assert k._global_dst_blocks == set()
    assert '203.0.113.5' not in k._wd_selective.get('192.168.1.42', {}).get('dsts', set())
