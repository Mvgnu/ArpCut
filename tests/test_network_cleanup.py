"""Lifecycle regressions using constructed packets and mocked I/O only."""
import threading
import os
import sys
from types import SimpleNamespace

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from scapy.all import ARP, IP, UDP, Raw

from networking import killer as km
from networking import sniffer as sm


ROUTER = {'ip': '192.0.2.1', 'mac': '02:00:00:00:00:01'}
VICTIM = {'ip': '192.0.2.2', 'mac': '02:00:00:00:00:02'}


@pytest.fixture
def killer(monkeypatch):
    monkeypatch.setattr(km, 'get_default_iface', lambda: SimpleNamespace(
        name='fake0', guid='fake0', mac='02:00:00:00:00:03'))
    monkeypatch.setattr(km, 'sleep', lambda _: None)
    result = km.Killer(dict(ROUTER))
    result.sent = []
    monkeypatch.setattr(result, '_send_packet', lambda p: result.sent.append(p) or True)
    monkeypatch.setattr(result, '_close_socket', lambda: None)
    monkeypatch.setattr(result, '_enforce_windivert_block', lambda *a, **kw: True)
    return result


def test_restore_all_sends_corrective_arp_before_closing(killer, monkeypatch):
    second = {'ip': '192.0.2.4', 'mac': '02:00:00:00:00:04'}
    killer.killed = {v['mac']: v for v in (VICTIM, second)}
    stopped = threading.Event()
    killer._poison_stops[VICTIM['mac']] = stopped
    closed = []
    monkeypatch.setattr(killer, '_close_socket', lambda: closed.append(len(killer.sent)))
    assert killer.unkill_all()
    assert stopped.is_set() and killer.killed == {}
    assert len(killer.sent) == 12 and closed == [12]
    assert {(p[ARP].psrc, p[ARP].hwsrc) for p in killer.sent} == {
        (ROUTER['ip'], ROUTER['mac']),
        (VICTIM['ip'], VICTIM['mac']),
        (second['ip'], second['mac']),
    }


def test_old_poison_session_cannot_resume_after_restore(killer):
    stop = threading.Event()
    killer.killed[VICTIM['mac']] = dict(VICTIM)
    killer._poison_stops[VICTIM['mac']] = stop
    assert killer.unkill(dict(VICTIM))
    assert stop.is_set()
    killer.killed[VICTIM['mac']] = dict(VICTIM)
    killer._poison_stops[VICTIM['mac']] = threading.Event()
    count = len(killer.sent)
    killer._poison_loop(dict(VICTIM), 0, stop)
    assert len(killer.sent) == count


def test_failed_firewall_restore_retains_retry_state(killer, monkeypatch):
    killer.pf_blocks.add(VICTIM['ip'])
    monkeypatch.setattr(km, 'unblock_all_for', lambda ip: False)
    assert killer.unkill_all() is False
    assert killer.pf_blocks == {VICTIM['ip']}
    monkeypatch.setattr(km, 'unblock_all_for', lambda ip: True)
    assert killer.unkill_all() is True
    assert killer.pf_blocks == set()


def test_failed_arp_restore_retains_device_without_restarting_poison(killer, monkeypatch):
    killer.killed[VICTIM['mac']] = dict(VICTIM)
    monkeypatch.setattr(killer, '_send_packet', lambda packet: False)
    assert not killer.unkill_all()
    assert killer.killed == {}
    assert killer._restore_pending == {VICTIM['mac']: VICTIM}
    monkeypatch.setattr(killer, '_send_packet', lambda packet: True)
    assert killer.unkill_all()
    assert killer._restore_pending == {}


@pytest.mark.parametrize('operation', ['spoof', 'one_way_kill'])
def test_forwarding_failure_does_not_redirect_device(killer, monkeypatch, operation):
    monkeypatch.setattr(km, 'enable_ip_forwarding', lambda: False)
    with pytest.raises(RuntimeError, match='forwarding'):
        getattr(killer, operation)(dict(VICTIM))
    assert killer.killed == {} and killer.sent == []


def test_linux_one_way_uses_only_the_outbound_firewall_policy(killer, monkeypatch):
    calls = []
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(km, 'enable_ip_forwarding', lambda: True)
    monkeypatch.setattr(killer, '_poison', lambda *a: None)
    monkeypatch.setattr(km, 'block_ip', lambda *a: calls.append(a) or True)
    monkeypatch.setattr(km, 'block_all_for', lambda *a: pytest.fail('must not block both directions'))
    assert killer.one_way_kill(dict(VICTIM)) is True
    assert calls == [('fake0', VICTIM['ip'], 'out')]


@pytest.mark.parametrize('operation', ['kill', 'one_way_kill', 'lag'])
def test_windows_policy_unavailable_is_reported_without_new_routing(killer, monkeypatch, operation):
    from networking import windivert_forwarder as wd

    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr(km, 'enable_ip_forwarding', lambda: True)
    monkeypatch.setattr(wd, 'WINDIVERT_AVAILABLE', False)
    monkeypatch.setattr(killer, '_enforce_windivert_block',
                        km.Killer._enforce_windivert_block.__get__(killer))
    monkeypatch.setattr(killer, '_poison', lambda *a: pytest.fail('must not start a failed session'))
    args = (dict(VICTIM), True) if operation == 'lag' else (dict(VICTIM),)
    assert getattr(killer, operation)(*args) is False
    assert killer.killed == {} and killer._wd_forwarders == {}


def test_failed_windivert_replacement_keeps_previous_policy(killer, monkeypatch):
    from networking import windivert_forwarder as wd

    old = SimpleNamespace(running=True, drop_from_victim=True, drop_to_victim=False,
                          stop=lambda: pytest.fail('must preserve the existing policy'))
    killer._wd_forwarders[VICTIM['ip']] = old
    closed = []
    monkeypatch.setattr(wd, 'WINDIVERT_AVAILABLE', True)
    monkeypatch.setattr(wd, 'WinDivertForwarder', lambda: SimpleNamespace(
        start=lambda *a, **kw: False, stop=lambda: closed.append(True)))
    assert km.Killer._enforce_windivert_block(
        killer, VICTIM['ip'], drop_to_victim=True) is False
    assert killer._wd_forwarders[VICTIM['ip']] is old
    assert closed == [True]


@pytest.mark.parametrize('operation', ['one_way_kill', 'lag'])
def test_posix_policy_failure_is_reported_without_new_routing(killer, monkeypatch, operation):
    monkeypatch.setattr(sys, 'platform', 'linux')
    monkeypatch.setattr(km, 'enable_ip_forwarding', lambda: True)
    monkeypatch.setattr(km, 'block_ip', lambda *a: False)
    monkeypatch.setattr(km, 'block_all_for', lambda *a: False)
    monkeypatch.setattr(killer, '_poison', lambda *a: pytest.fail('must not start a failed session'))
    args = (dict(VICTIM), True) if operation == 'lag' else (dict(VICTIM),)
    assert getattr(killer, operation)(*args) is False
    assert killer.killed == {} and killer.pf_blocks == set()


def test_one_way_backstop_failure_removes_new_driver_policy(killer, monkeypatch):
    monkeypatch.setattr(sys, 'platform', 'win32')
    monkeypatch.setattr(km, 'enable_ip_forwarding', lambda: True)
    closed = []

    def install(ip, **kwargs):
        killer._wd_forwarders[ip] = SimpleNamespace(stop=lambda: closed.append(True))
        return True

    monkeypatch.setattr(killer, '_enforce_windivert_block', install)
    monkeypatch.setattr(killer, '_enforce_pf_block', lambda ip: False)
    assert killer.one_way_kill(dict(VICTIM)) is False
    assert killer.killed == {} and killer._wd_forwarders == {} and closed == [True]


def test_changed_device_address_is_restored_before_replacement(killer, monkeypatch):
    killer.killed[VICTIM['mac']] = dict(VICTIM)
    stop = threading.Event()
    killer._poison_stops[VICTIM['mac']] = stop
    started = []
    monkeypatch.setattr(killer, '_poison', lambda victim, *a: started.append(dict(victim)))
    updated = dict(VICTIM, ip='192.0.2.20')
    killer.kill(updated)
    assert stop.is_set()
    assert len(killer.sent) == 6
    assert started == [updated]
    assert killer.killed[VICTIM['mac']]['ip'] == '192.0.2.20'


def test_sniffer_stops_without_waiting_for_another_packet(monkeypatch):
    entered = threading.Event()

    def idle_sniff(**kwargs):
        assert 0 < kwargs['timeout'] <= 0.5
        kwargs['started_callback']()
        entered.set()
        # Model an idle capture respecting its bounded timeout, without sockets.
        threading.Event().wait(0.01)

    monkeypatch.setattr(sm, 'sniff', idle_sniff)
    sniffer = sm.TrafficSniffer()
    sniffer.start(VICTIM['ip'], 'fake0')
    thread, cancelled = sniffer._thread, sniffer._stop
    assert entered.wait(1)
    sniffer.stop()
    assert not thread.is_alive() and cancelled.is_set()
    sniffer.start('192.0.2.20', 'fake0')
    assert sniffer._stop is not cancelled and cancelled.is_set()
    sniffer.stop()


def test_sniffer_snapshots_do_not_mutate_and_sessions_do_not_mix(monkeypatch):
    monkeypatch.setattr(sm.TrafficSniffer, '_run', lambda self, stop, ip, iface, ready, state: ready.set())
    sniffer = sm.TrafficSniffer()
    sniffer.start(VICTIM['ip'], 'fake0')
    packet = IP(src=VICTIM['ip'], dst='198.51.100.1') / UDP(dport=53) / Raw(b'hello')
    sniffer._process(packet)
    saved = sniffer.get_flows()
    sniffer._process(packet)
    assert next(iter(saved.values()))['packets'] == 1
    sniffer.start('192.0.2.20', 'fake0')
    assert sniffer.get_flows() == {} and sniffer.get_patterns() == {}
    assert sniffer.get_last_packet_hex() == ''
    sniffer.stop()


def test_sniffer_reports_startup_permission_failure(monkeypatch):
    def denied(**kwargs):
        raise PermissionError('capture denied')

    monkeypatch.setattr(sm, 'sniff', denied)
    sniffer = sm.TrafficSniffer()
    with pytest.raises(RuntimeError, match='capture denied'):
        sniffer.start(VICTIM['ip'], 'fake0')
    assert sniffer._thread is None


def test_dns_stop_during_handle_open_does_not_orphan_handle(monkeypatch):
    from networking.dnsblock import DnsSpoofer

    blocker = DnsSpoofer('fake0')
    closed = []

    class Handle:
        def open(self):
            blocker._wd_stop.set()  # stop while the driver is opening

        def close(self):
            closed.append(True)

        def recv(self):
            pytest.fail('a canceled handle must not receive traffic')

    monkeypatch.setitem(sys.modules, 'pydivert', SimpleNamespace(
        WinDivert=lambda *a, **kw: Handle(), Layer=SimpleNamespace(NETWORK_FORWARD=1)))
    blocker._wd_loop([VICTIM['ip']], blocker._wd_stop)
    assert closed and blocker._wd_handle is None


def test_dns_clear_removes_stale_names(monkeypatch):
    from networking.dnsblock import DnsSpoofer

    blocker = DnsSpoofer('fake0')
    monkeypatch.setattr(blocker, '_restart', lambda: None)
    blocker.block(VICTIM['ip'], ['example.test'])
    blocker.clear()
    assert blocker.active() == {}


def test_windivert_receive_failure_closes_handle():
    from networking.windivert_forwarder import WinDivertForwarder

    closed = []

    class Handle:
        def recv(self):
            raise OSError('driver stopped')

        def close(self):
            closed.append(True)

    forwarder = WinDivertForwarder()
    forwarder.running = True
    forwarder._handle = Handle()
    forwarder._drain()
    assert closed and not forwarder.running and forwarder._handle is None


def test_ping_failure_still_finishes_progress_and_uses_bounded_argv(monkeypatch):
    from networking import scanner as scanner_mod

    scanner = scanner_mod.Scanner.__new__(scanner_mod.Scanner)
    scanner._lock = threading.Lock()
    scanner._Scanner__ping_done = 0
    calls = []

    def failed(command, **kwargs):
        calls.append((command, kwargs))
        raise OSError('ping unavailable')

    monkeypatch.setattr(scanner_mod, 'terminal', failed)
    scanner.ping(VICTIM['ip'])
    assert scanner._Scanner__ping_done == 1
    assert calls[0][0][-1] == VICTIM['ip']
    assert calls[0][1]['timeout'] == 1.0
