"""Tests for firewall hardening: exact-match rule targeting and honest netsh deletes."""
import os
import sys
from subprocess import CompletedProcess

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from tools.firewall import (  # noqa: E402
    _pf_line_targets_ip, _pf_line_targets_port, _netsh_delete_ok, _ErrorState,
)


# ---- exact-match IP targeting (no substring collisions) --------------------

def test_ip_exact_match_hit():
    assert _pf_line_targets_ip('block drop quick on en0 from any to 10.0.0.1', '10.0.0.1')
    assert _pf_line_targets_ip('block drop quick on en0 from 10.0.0.1 to any', '10.0.0.1')


def test_ip_no_prefix_collision():
    # Unblocking 10.0.0.1 must NOT match a rule for 10.0.0.10 / 10.0.0.100.
    line10 = 'block drop quick on en0 from any to 10.0.0.10'
    line100 = 'block drop quick on en0 from any to 10.0.0.100'
    assert not _pf_line_targets_ip(line10, '10.0.0.1')
    assert not _pf_line_targets_ip(line100, '10.0.0.1')


# ---- exact-match port targeting --------------------------------------------

def test_port_exact_match_hit():
    assert _pf_line_targets_port('block drop quick on en0 proto tcp from any to any port 80', 80)


def test_port_no_prefix_collision():
    # Unblocking port 80 must NOT match port 8080.
    assert not _pf_line_targets_port('... to any port 8080', 80)


def test_port_equals_form():
    assert _pf_line_targets_port('block ... port = 443', 443)


# ---- honest netsh delete reporting -----------------------------------------

def test_netsh_delete_success():
    assert _netsh_delete_ok(CompletedProcess([], 0, stdout='Ok.', stderr='')) is True


def test_netsh_delete_no_match_is_success():
    res = CompletedProcess([], 1, stdout='No rules match the specified criteria.', stderr='')
    assert _netsh_delete_ok(res) is True


def test_netsh_delete_real_failure_reported():
    res = CompletedProcess([], 1, stdout='', stderr='The parameter is incorrect.')
    assert _netsh_delete_ok(res) is False


# ---- error state is thread-safe (has a lock, API unchanged) ----------------

def test_error_state_roundtrip():
    e = _ErrorState()
    assert e.get() == ''
    e.set('boom')
    assert e.get() == 'boom'
    e.clear()
    assert e.get() == ''
    assert hasattr(e, '_lock')
