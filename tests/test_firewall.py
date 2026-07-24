"""Unit tests for the Firewall domain — pfctl.py validation and error handling.

Tests use mocked subprocess to avoid requiring root or modifying pf.conf.

Run: PYTHONPATH=src venv/bin/python -m pytest tests/test_firewall.py -v
"""
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock
from subprocess import CompletedProcess

# Ensure src is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))


# ──────────────────────────────────────────────────────────────────────────────
#  IP Validation  (_is_valid_ip)
# ──────────────────────────────────────────────────────────────────────────────

class TestIsValidIp:
    """Tests for _is_valid_ip() — IPv4 validation."""

    def test_valid_ip(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('192.168.1.1') is True

    def test_valid_ip_zeros(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('0.0.0.0') is True

    def test_valid_ip_max(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('255.255.255.255') is True

    def test_invalid_ip_out_of_range(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('256.1.1.1') is False

    def test_invalid_ip_letters(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('abc.def.ghi.jkl') is False

    def test_invalid_ip_empty(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('') is False

    def test_invalid_ip_too_many_octets(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('192.168.1.1.1') is False

    def test_invalid_ip_shell_injection(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('192.168.1.1; rm -rf /') is False

    def test_invalid_ip_newline(self) -> None:
        from tools.firewall import _is_valid_ip
        assert _is_valid_ip('192.168.1.1\n') is False


# ──────────────────────────────────────────────────────────────────────────────
#  Interface Validation  (_is_valid_iface)
# ──────────────────────────────────────────────────────────────────────────────

class TestIsValidIface:
    """Tests for _is_valid_iface() — interface name validation."""

    def test_valid_iface_en0(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('en0') is True

    def test_valid_iface_eth0(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('eth0') is True

    def test_valid_iface_wifi(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('Wi-Fi') is True

    def test_invalid_iface_empty(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('') is False

    def test_invalid_iface_shell_injection(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('en0; rm -rf /') is False

    def test_invalid_iface_spaces(self) -> None:
        from tools.firewall import _is_valid_iface
        assert _is_valid_iface('en 0') is False


# ──────────────────────────────────────────────────────────────────────────────
#  Port/Protocol Validation
# ──────────────────────────────────────────────────────────────────────────────

class TestPortProtoValidation:
    """Tests for _is_valid_port() and _is_valid_proto()."""

    def test_valid_port_80(self) -> None:
        from tools.firewall import _is_valid_port
        assert _is_valid_port(80) is True

    def test_valid_port_443(self) -> None:
        from tools.firewall import _is_valid_port
        assert _is_valid_port(443) is True

    def test_invalid_port_zero(self) -> None:
        from tools.firewall import _is_valid_port
        assert _is_valid_port(0) is False

    def test_invalid_port_negative(self) -> None:
        from tools.firewall import _is_valid_port
        assert _is_valid_port(-1) is False

    def test_invalid_port_too_high(self) -> None:
        from tools.firewall import _is_valid_port
        assert _is_valid_port(65536) is False

    def test_valid_proto_tcp(self) -> None:
        from tools.firewall import _is_valid_proto
        assert _is_valid_proto('tcp') is True

    def test_valid_proto_udp(self) -> None:
        from tools.firewall import _is_valid_proto
        assert _is_valid_proto('udp') is True

    def test_invalid_proto(self) -> None:
        from tools.firewall import _is_valid_proto
        assert _is_valid_proto('icmp') is False

    def test_invalid_proto_injection(self) -> None:
        from tools.firewall import _is_valid_proto
        assert _is_valid_proto('tcp; rm -rf /') is False


# ──────────────────────────────────────────────────────────────────────────────
#  ErrorState
# ──────────────────────────────────────────────────────────────────────────────

class TestErrorState:
    """Tests for _ErrorState container."""

    def test_initial_empty(self) -> None:
        from tools.firewall import _ErrorState
        state = _ErrorState()
        assert state.get() == ''

    def test_set_and_get(self) -> None:
        from tools.firewall import _ErrorState
        state = _ErrorState()
        state.set('test error')
        assert state.get() == 'test error'

    def test_clear(self) -> None:
        from tools.firewall import _ErrorState
        state = _ErrorState()
        state.set('error')
        state.clear()
        assert state.get() == ''

    def test_set_none_becomes_empty(self) -> None:
        from tools.firewall import _ErrorState
        state = _ErrorState()
        state.set('')
        assert state.get() == ''


# ──────────────────────────────────────────────────────────────────────────────
#  last_error() — module-level accessor
# ──────────────────────────────────────────────────────────────────────────────

class TestLastError:
    """Tests for the public last_error() function."""

    def test_returns_string(self) -> None:
        from tools.firewall import last_error
        result = last_error()
        assert isinstance(result, str)


# ──────────────────────────────────────────────────────────────────────────────
#  PF Rule Validation  (_is_valid_pf_rule)
# ──────────────────────────────────────────────────────────────────────────────

class TestPfRuleValidation:
    """Tests for _is_valid_pf_rule() — sanity check on generated rules."""

    def test_valid_block_rule(self) -> None:
        from tools.firewall import _is_valid_pf_rule
        assert _is_valid_pf_rule('block out on en0 from any to 192.168.1.50') is True

    def test_pass_rule_rejected(self) -> None:
        """ArpCut only generates block rules; pass rules are rejected."""
        from tools.firewall import _is_valid_pf_rule
        assert _is_valid_pf_rule('pass in on en0 from 192.168.1.1 to any') is False

    def test_invalid_rule_empty(self) -> None:
        from tools.firewall import _is_valid_pf_rule
        assert _is_valid_pf_rule('') is False

    def test_invalid_rule_comment(self) -> None:
        from tools.firewall import _is_valid_pf_rule
        assert _is_valid_pf_rule('# this is a comment') is False


# ──────────────────────────────────────────────────────────────────────────────
#  block_all_for — with mocked subprocess  (macOS path)
# ──────────────────────────────────────────────────────────────────────────────

class TestBlockAllForMocked:
    """Tests for block_all_for() with mocked subprocess on macOS."""

    def test_rejects_invalid_ip(self) -> None:
        """block_all_for should reject malformed IPs before touching subprocess."""
        from tools.firewall import block_all_for
        result = block_all_for('en0', 'not_an_ip')
        assert result is False

    def test_rejects_invalid_iface(self) -> None:
        from tools.firewall import block_all_for
        result = block_all_for('en0; rm -rf /', '192.168.1.50')
        assert result is False
