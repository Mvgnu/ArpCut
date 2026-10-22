"""Discovery identity and cache parsing regressions; all I/O is mocked."""
import sys
import threading
from types import SimpleNamespace

import pytest

from networking import scanner as sm


MAC = '02:11:22:33:44:55'
OTHER_MAC = '02:11:22:33:44:66'


@pytest.fixture
def scanner(monkeypatch):
    result = sm.Scanner.__new__(sm.Scanner)
    result._lock = threading.Lock()
    result.devices = []
    result.old_ips = {}
    result.router_ip, result.router_mac = '192.168.1.254', '02:AA:BB:CC:DD:01'
    result.my_ip, result.my_mac = '192.168.1.100', '02:AA:BB:CC:DD:02'
    result.flushed = []
    monkeypatch.setattr(sm, 'Nicknames', lambda: SimpleNamespace(get_name=lambda mac: 'Known device'))
    monkeypatch.setattr(sm, 'get_vendor', lambda mac: 'Vendor')
    monkeypatch.setattr(result, 'flush_arp', lambda: result.flushed.append(True))
    monkeypatch.setattr(sm, 'terminal', lambda *a, **kw: pytest.fail('unexpected process'))
    return result


@pytest.mark.parametrize('known', [False, True])
def test_repeated_mac_is_published_once(scanner, known):
    if known:
        scanner.old_ips = {MAC: '192.168.1.20'}
    scanner.devices_appender([
        ('192.168.1.20', MAC.lower()),
        ('192.168.1.20', MAC.replace(':', '-')),
        ('192.168.1.20', MAC),
    ])
    users = [d for d in scanner.devices if not d['admin']]
    assert [(d['ip'], d['mac']) for d in users] == [('192.168.1.20', MAC)]
    assert users[0]['name'] == 'Known device'
    assert scanner.old_ips == {MAC: '192.168.1.20'}
    assert scanner.flushed == []


def test_new_mac_with_multiple_addresses_uses_first_sorted_address(scanner):
    scanner.devices_appender([('192.168.1.30', MAC), ('192.168.1.20', MAC)])
    assert scanner.old_ips == {MAC: '192.168.1.20'}
    assert len([d for d in scanner.devices if not d['admin']]) == 1
    assert scanner.flushed == []


@pytest.mark.parametrize('old_ip,new_ip', [
    ('192.168.1.10', '192.168.1.20'),
    ('192.168.1.20', '192.168.1.10'),
])
def test_changed_address_replaces_stale_cache_rows(scanner, old_ip, new_ip):
    scanner.old_ips = {MAC: old_ip}
    scanner.devices_appender([(old_ip, MAC), (new_ip, MAC), (new_ip, MAC)])
    assert scanner.old_ips == {MAC: new_ip}
    assert [(d['ip'], d['mac']) for d in scanner.devices if not d['admin']] == [(new_ip, MAC)]
    assert scanner.flushed == [True]


def test_protected_ips_and_mac_aliases_cannot_become_user_targets(scanner):
    scanner.devices_appender([
        (scanner.router_ip, MAC),
        (scanner.my_ip, OTHER_MAC),
        ('192.168.1.21', scanner.router_mac.lower().replace(':', '-')),
        ('192.168.1.22', scanner.my_mac.lower()),
        ('192.168.1.23', MAC),
    ])
    assert [(d['type'], d['admin']) for d in scanner.devices] == [
        ('Router', True), ('Me', True), ('User', False)]
    assert scanner.old_ips == {MAC: '192.168.1.23'}
    assert scanner.devices[0] is scanner.router
    assert scanner.devices[1] is scanner.me


def test_snapshot_is_not_exposed_during_record_construction(scanner, monkeypatch):
    original = [{'ip': '192.168.1.10', 'mac': OTHER_MAC}]
    scanner.devices = original
    observed = []

    def vendor(mac):
        observed.append(scanner.devices)
        return 'Vendor'

    monkeypatch.setattr(sm, 'get_vendor', vendor)
    scanner.devices_appender([('192.168.1.20', MAC)])
    assert observed and all(snapshot is original for snapshot in observed)
    assert scanner.devices is not original and len(scanner.devices) == 3
    assert original == [{'ip': '192.168.1.10', 'mac': OTHER_MAC}]


@pytest.mark.parametrize('platform', ['win32', 'darwin', 'linux'])
@pytest.mark.parametrize('has_exact_match', [False, True])
def test_arp_probe_requires_exact_address(scanner, monkeypatch, platform, has_exact_match):
    ip = '192.168.1.1'
    if platform == 'win32':
        cache = f'Interface: {ip} --- 0xc\n  192.168.1.10  {OTHER_MAC.replace(":", "-")} dynamic\n'
        if has_exact_match:
            cache += f'  {ip}  {MAC.replace(":", "-")} dynamisch\n'
    else:
        cache = f'? (192.168.1.10) at {OTHER_MAC.lower()} on en0 ifscope [ethernet]\n'
        if has_exact_match:
            cache += f'? ({ip}) at {MAC.lower()} on en0 ifscope [ethernet]\n'
    published = []
    monkeypatch.setattr(sys, 'platform', platform)
    monkeypatch.setattr(sm, 'terminal', lambda *a, **kw: cache)
    monkeypatch.setattr(scanner, 'devices_appender', published.append)
    result = scanner.probe_ip_arp_cache_only(ip)
    assert result == ((ip, MAC) if has_exact_match else None)
    assert published == ([[(ip, MAC)]] if has_exact_match else [])
