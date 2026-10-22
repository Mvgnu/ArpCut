"""Linux nftables path of the firewall module.

Exercises the public firewall functions with ``sys.platform`` patched to linux
and a fake ``nft`` runner, so command construction, idempotency, exact-match
removal, and list parsing are verified without a real Linux host.
"""
import os
import re
import sys
from subprocess import CompletedProcess
from unittest import mock

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import tools.firewall as fw  # noqa: E402


class FakeNft:
    """Models an nft ruleset for list/delete/idempotency checks."""

    def __init__(self) -> None:
        self.rules: list[dict] = []
        self._h = 0
        self.calls: list[list[str]] = []

    def add_rule_count(self) -> int:
        return sum(1 for c in self.calls
                   if len(c) == 2 and c[1].startswith('add rule'))

    def __call__(self, argv):
        self.calls.append(argv)
        rest = argv[1:]
        if len(rest) == 1:
            cmd = rest[0]
            if cmd.startswith('add rule'):
                m = re.search(r'comment "([^"]+)"', cmd)
                self._h += 1
                self.rules.append({'h': self._h, 'text': cmd, 'c': m.group(1) if m else ''})
            return CompletedProcess(argv, 0, '', '')
        if rest[:1] == ['-a']:
            out = '\n'.join(f"{r['text']} # handle {r['h']}" for r in self.rules)
            return CompletedProcess(argv, 0, out, '')
        if rest[:1] == ['delete']:
            h = int(rest[-1])
            self.rules = [r for r in self.rules if r['h'] != h]
            return CompletedProcess(argv, 0, '', '')
        if rest[:1] == ['flush']:
            self.rules = []
            return CompletedProcess(argv, 0, '', '')
        return CompletedProcess(argv, 0, '', '')


@pytest.fixture
def nft():
    fake = FakeNft()
    original = fw._nft
    fw._nft = fw._Nft(runner=fake)
    with mock.patch.object(sys, 'platform', 'linux'):
        yield fake
    fw._nft = original


def comments(fake) -> set:
    return {r['c'] for r in fake.rules}


def test_block_ip_both_creates_two_rules(nft):
    assert fw.block_ip('eth0', '1.2.3.4', 'both') is True
    assert comments(nft) == {'arpcut_ip_1.2.3.4_in', 'arpcut_ip_1.2.3.4_out'}
    assert sorted(fw.list_blocked_ips()) == [('1.2.3.4', 'in'), ('1.2.3.4', 'out')]


def test_block_ip_idempotent(nft):
    fw.block_ip('eth0', '1.2.3.4', 'both')
    n = nft.add_rule_count()
    fw.block_ip('eth0', '1.2.3.4', 'both')
    assert len(nft.rules) == 2 and nft.add_rule_count() == n


def test_unblock_ip_exact_match(nft):
    fw.block_ip('eth0', '1.2.3.4', 'both')
    fw.block_ip('eth0', '1.2.3.40', 'both')     # prefix-colliding neighbour
    fw.unblock_ip('1.2.3.4')
    assert comments(nft) == {'arpcut_ip_1.2.3.40_in', 'arpcut_ip_1.2.3.40_out'}


def test_block_all_for_and_unblock(nft):
    assert fw.block_all_for('eth0', '10.0.0.9') is True
    assert ('10.0.0.9', 'in') in fw.list_blocked_ips()
    fw.unblock_all_for('10.0.0.9')
    assert fw.list_blocked_ips() == []


def test_block_port_both_protos(nft):
    assert fw.block_port('eth0', 3074, 'both') is True
    assert comments(nft) == {'arpcut_port_3074_tcp', 'arpcut_port_3074_udp'}
    assert sorted(fw.list_blocked_ports()) == [(3074, 'tcp', 'both'), (3074, 'udp', 'both')]
    assert fw.is_port_blocked(3074) is True


def test_clear_anchor_flushes(nft):
    fw.block_ip('eth0', '1.2.3.4', 'both')
    fw.clear_anchor()
    assert nft.rules == []


def test_is_blocked_routes_through_nft(nft):
    fw.block_ip('eth0', '5.5.5.5', 'both')
    assert fw.is_blocked('5.5.5.5') is True
    assert fw.is_blocked('6.6.6.6') is False


@pytest.mark.parametrize('args', [
    ('bad;iface', 80, 'tcp', 'both', None),
    ('eth0\n', 80, 'tcp', 'both', None),
    ('eth0', True, 'tcp', 'both', None),
    ('eth0', 80, 'invalid', 'both', None),
    ('eth0', 80, 'tcp', 'invalid', None),
    ('eth0', 80, 'tcp', 'both', 'not-an-ip'),
])
def test_invalid_port_arguments_never_execute_nft(nft, args):
    assert fw.block_port(*args) is False
    assert nft.calls == []


def test_same_port_can_be_tracked_for_distinct_devices(nft):
    assert fw.block_port('eth0', 80, 'tcp', target_ip='192.0.2.1')
    assert fw.block_port('eth0', 80, 'tcp', target_ip='192.0.2.2')
    assert len(nft.rules) == 2
    assert {r['c'] for r in nft.rules} == {
        'arpcut_port_80_tcp_192.0.2.1', 'arpcut_port_80_tcp_192.0.2.2'}
    assert fw.unblock_port(80)
    assert nft.rules == []


def test_nft_reports_permission_failures_for_setup_and_cleanup():
    calls = []

    def denied(argv):
        calls.append(argv)
        return CompletedProcess(argv, 1, '', 'Operation not permitted')

    backend = fw._Nft(denied)
    assert not backend.block_ip('eth0', '192.0.2.1')
    assert len(calls) == 1  # stop before trying to install a rule
    assert not backend.clear()
    assert not backend.unblock_ip('192.0.2.1')
    assert 'Operation not permitted' in fw.last_error()


def test_nft_missing_executable_is_a_reported_failure():
    def missing(argv):
        raise FileNotFoundError('nft is not installed')

    backend = fw._Nft(missing)
    assert not backend.clear()
    assert 'nft is not installed' in fw.last_error()


def test_nft_clear_absent_namespace_is_idempotent():
    def missing_table(argv):
        if argv[1:] == ['list', 'tables']:
            return CompletedProcess(argv, 0, 'table inet unrelated\n', '')
        return CompletedProcess(argv, 1, '', 'No such file or directory')

    backend = fw._Nft(missing_table)
    assert backend.clear()
    assert backend.unblock_ip('192.0.2.1')
