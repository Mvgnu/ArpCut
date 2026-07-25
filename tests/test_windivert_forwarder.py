"""Tests for the Windows WinDivert kernel forwarder.

These run on every platform: the module imports with a guarded ``pydivert``
import, and the filter builder is pure-Python.  When ``pydivert`` *is* present
(Windows dev/CI box) the filter strings are additionally validated against the
real WinDivert engine via ``WinDivert.check_filter`` — no admin required, since
that only compiles the filter in the DLL.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest

from networking import windivert_forwarder as wd
from networking.windivert_forwarder import (
    WinDivertForwarder,
    build_forward_filter,
    validate_filter,
    self_check,
)


# ---------------------------------------------------------------------------
# Filter construction
# ---------------------------------------------------------------------------
def test_default_filter_drops_victim_outbound():
    f = build_forward_filter('192.168.1.42')
    assert f == 'ip and ip.SrcAddr == 192.168.1.42'


def test_both_directions_are_ored():
    f = build_forward_filter('192.168.1.42', drop_from_victim=True, drop_to_victim=True)
    assert f == 'ip and (ip.SrcAddr == 192.168.1.42 or ip.DstAddr == 192.168.1.42)'


def test_inbound_only():
    f = build_forward_filter('10.0.0.5', drop_from_victim=False, drop_to_victim=True)
    assert f == 'ip and ip.DstAddr == 10.0.0.5'


def test_dst_scoped_filter():
    # the victim's traffic TO that destination
    f = build_forward_filter('192.168.1.42', dst_ips=['8.8.8.8'])
    assert f == 'ip and (ip.SrcAddr == 192.168.1.42 and ip.DstAddr == 8.8.8.8)'


def test_multi_dst_filter():
    f = build_forward_filter('192.168.1.42', dst_ips=['1.1.1.1', '8.8.8.8'])
    assert 'ip.DstAddr == 1.1.1.1 or ip.DstAddr == 8.8.8.8' in f


def test_port_filter_covers_both_directions_and_src_dst_port():
    # a port block must catch the port either direction, as src OR dst port
    f = build_forward_filter('192.168.1.42', ports=[443])
    assert f == ('ip and ((ip.SrcAddr == 192.168.1.42 or ip.DstAddr == 192.168.1.42) '
                 'and (tcp.SrcPort == 443 or tcp.DstPort == 443))')


def test_port_filter_udp():
    f = build_forward_filter('192.168.1.42', ports=[3074], proto='udp')
    assert 'udp.SrcPort == 3074 or udp.DstPort == 3074' in f
    assert 'ip.DstAddr == 192.168.1.42' in f      # inbound to the victim too


def test_proto_only_filter():
    f = build_forward_filter('192.168.1.42', proto='udp')
    assert f == 'ip and ip.SrcAddr == 192.168.1.42 and udp'


def test_dst_and_ports_are_ored_not_anded():
    # A victim blocked from an IP AND on a port must drop traffic matching EITHER,
    # not only traffic matching both (the GTA-IP + port-3111 regression).
    f = build_forward_filter('192.168.1.42', dst_ips=['192.81.241.171'],
                             ports=[3111], proto='udp')
    assert f == ('ip and ((ip.SrcAddr == 192.168.1.42 and ip.DstAddr == 192.81.241.171) '
                 'or ((ip.SrcAddr == 192.168.1.42 or ip.DstAddr == 192.168.1.42) '
                 'and (udp.SrcPort == 3111 or udp.DstPort == 3111)))')


def test_no_direction_raises():
    with pytest.raises(ValueError):
        build_forward_filter('192.168.1.42', drop_from_victim=False, drop_to_victim=False)


# ---------------------------------------------------------------------------
# Filters must be accepted by the real WinDivert engine (when present)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize('kwargs', [
    {},
    {'drop_to_victim': True},
    {'drop_from_victim': False, 'drop_to_victim': True},
    {'dst_ips': ['8.8.8.8']},
    {'dst_ips': ['1.1.1.1', '8.8.8.8']},
    {'ports': [443]},
    {'ports': [80, 443]},
    {'ports': [3074], 'proto': 'udp'},
    {'proto': 'tcp'},
    {'dst_ips': ['192.81.241.171'], 'ports': [3111], 'proto': 'udp'},   # combined
    {'dst_ips': ['1.1.1.1', '8.8.8.8'], 'ports': [80, 443]},            # combined multi
])
def test_built_filters_are_engine_valid(kwargs):
    f = build_forward_filter('192.168.1.42', **kwargs)
    ok, msg = validate_filter(f)
    assert ok, f'WinDivert rejected {f!r}: {msg}'


# ---------------------------------------------------------------------------
# Forwarder behaviour without a live driver
# ---------------------------------------------------------------------------
def test_start_returns_false_when_unavailable(monkeypatch):
    monkeypatch.setattr(wd, 'WINDIVERT_AVAILABLE', False)
    fwd = WinDivertForwarder()
    assert fwd.start('192.168.1.42') is False
    assert fwd.running is False


def test_start_rejects_bad_config_without_driver(monkeypatch):
    # Force the "available" flag but keep WinDivert as-is; a no-direction config
    # is rejected before any handle is opened.
    monkeypatch.setattr(wd, 'WINDIVERT_AVAILABLE', True)
    fwd = WinDivertForwarder()
    assert fwd.start('192.168.1.42', drop_from_victim=False, drop_to_victim=False) is False


def test_get_stats_shape():
    fwd = WinDivertForwarder()
    stats = fwd.get_stats()
    assert stats['backend'] == 'windivert'
    assert stats['running'] is False
    for key in ('packets_seen', 'packets_dropped', 'packets_forwarded',
                'drop_from_victim', 'drop_to_victim', 'filter'):
        assert key in stats


def test_stop_is_idempotent():
    fwd = WinDivertForwarder()
    fwd.stop()
    fwd.stop()  # must not raise even though nothing was started


def test_self_check_never_raises_and_reports_keys():
    info = self_check()
    for key in ('available', 'routing_enabled', 'driver_ok', 'error'):
        assert key in info
