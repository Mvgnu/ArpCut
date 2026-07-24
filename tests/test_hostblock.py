"""Unit tests for the host blocklist (idempotent PSN-domain + GTA-static-IP blocking).

Firewall ops and DNS resolution are faked, so these run anywhere without root
or network.
"""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

from networking.hostblock import (  # noqa: E402
    HostBlocklist, HostPreset, PRESET_HOSTS, PRESETS_BY_KEY,
)


class FakeFirewall:
    """Records block/unblock calls and models a simple rule set."""

    def __init__(self, fail_on: set | None = None) -> None:
        self.blocked: set[str] = set()
        self.block_calls: list[str] = []
        self.unblock_calls: list[str] = []
        self._fail_on = fail_on or set()

    def block_ip(self, iface: str, ip: str, direction: str = 'both') -> bool:
        self.block_calls.append(ip)
        if ip in self._fail_on:
            return False
        self.blocked.add(ip)
        return True

    def unblock_ip(self, ip: str) -> bool:
        self.unblock_calls.append(ip)
        self.blocked.discard(ip)
        return True


def make(resolved: dict[str, set[str]] | None = None, **kw) -> tuple[HostBlocklist, FakeFirewall]:
    fw = FakeFirewall(**kw)
    resolved = resolved or {}
    resolver = lambda domain: set(resolved.get(domain, set()))
    bl = HostBlocklist(fw.block_ip, fw.unblock_ip, resolver=resolver)
    return bl, fw


PSN = 'np.communication.playstation.net'
GTA_IP = '192.81.241.171'


# ---- presets ---------------------------------------------------------------

def test_psn_preset_is_domain_based():
    p = PRESETS_BY_KEY['psn-comms']
    assert PSN in p.domains and not p.ips
    assert p in PRESET_HOSTS


def test_gta_preset_is_verified_static_ip():
    p = PRESETS_BY_KEY['gta-save']
    assert GTA_IP in p.ips and not p.domains


# ---- domain blocking (PSN) -------------------------------------------------

def test_block_resolves_and_blocks():
    bl, fw = make({PSN: {'1.1.1.1', '2.2.2.2'}})
    res = bl.block('psn-comms', 'en0')
    assert res.ok
    assert fw.blocked == {'1.1.1.1', '2.2.2.2'}
    assert bl.active() == {'psn-comms': {'1.1.1.1', '2.2.2.2'}}


def test_block_is_idempotent():
    bl, fw = make({PSN: {'1.1.1.1', '2.2.2.2'}})
    bl.block('psn-comms', 'en0')
    fw.block_calls.clear()
    res2 = bl.block('psn-comms', 'en0')          # second time — nothing new
    assert res2.added == set()
    assert fw.block_calls == []                  # no duplicate firewall calls


def test_unblock_removes_exactly_what_was_added():
    bl, fw = make({PSN: {'1.1.1.1', '2.2.2.2'}})
    bl.block('psn-comms', 'en0')
    assert bl.unblock('psn-comms') is True
    assert fw.blocked == set()
    assert bl.active() == {}


def test_unblock_unknown_key_is_noop_success():
    bl, fw = make()
    assert bl.unblock('nope') is True
    assert fw.unblock_calls == []


def test_refresh_reconciles_rotated_ips():
    resolved = {PSN: {'1.1.1.1', '2.2.2.2'}}
    bl, fw = make(resolved)
    bl.block('psn-comms', 'en0')
    resolved[PSN] = {'1.1.1.1', '3.3.3.3'}       # rotation: 2.2.2.2→3.3.3.3
    r = bl.refresh('en0')['psn-comms']
    assert r.added == {'3.3.3.3'} and r.removed == {'2.2.2.2'}
    assert fw.blocked == {'1.1.1.1', '3.3.3.3'}


# ---- static-IP blocking (GTA) ----------------------------------------------

def test_block_static_ip_preset_without_resolution():
    bl, fw = make()                              # no resolver data needed
    res = bl.block('gta-save', 'en0')
    assert res.ok
    assert fw.blocked == {GTA_IP}
    assert bl.is_active('gta-save')


def test_refresh_keeps_static_ips():
    bl, fw = make()
    bl.block('gta-save', 'en0')
    r = bl.refresh('en0')['gta-save']
    assert r.added == set() and r.removed == set()
    assert fw.blocked == {GTA_IP}


def test_block_bare_ip_string():
    bl, fw = make()
    res = bl.block('9.9.9.9', 'en0')
    assert res.ok and fw.blocked == {'9.9.9.9'}


# ---- mixed + failure -------------------------------------------------------

def test_mixed_domain_and_static_ip_target():
    bl, fw = make({'example.com': {'1.1.1.1'}})
    res = bl.block(['example.com', '9.9.9.9'], 'en0')
    assert res.ok
    assert fw.blocked == {'1.1.1.1', '9.9.9.9'}


def test_block_failure_is_reported_and_not_tracked():
    bl, fw = make({PSN: {'1.1.1.1', '2.2.2.2'}}, fail_on={'2.2.2.2'})
    res = bl.block('psn-comms', 'en0')
    assert res.failed == {'2.2.2.2'} and res.added == {'1.1.1.1'}
    assert bl.active() == {'psn-comms': {'1.1.1.1'}}   # failed IP not tracked
