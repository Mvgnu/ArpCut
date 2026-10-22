"""GUI failure/teardown regressions with recording engines, never real networking."""
import os
import sys
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

import pytest
from PySide6.QtTest import QTest
from PySide6.QtWidgets import QApplication

from gui.controller import Controller

_app = QApplication.instance() or QApplication([])
MAC = 'aa:bb:cc:dd:ee:03'
OTHER = 'aa:bb:cc:dd:ee:04'
IP = '192.168.1.42'
DEVICES = [
    {'mac': MAC, 'ip': IP, 'type': 'User', 'name': '', 'vendor': '', 'admin': False},
    {'mac': OTHER, 'ip': '192.168.1.43', 'type': 'User', 'name': '', 'vendor': '', 'admin': False},
]


class Ops:
    def __init__(self):
        self.calls = []

    def __getattr__(self, name):
        if name.startswith('__'):
            raise AttributeError(name)

        def call(*args, **kwargs):
            self.calls.append((name, args))
            if name in ('active_host_blocks', 'active_dns_blocks'):
                return {}
            if name == 'devices':
                return [dict(d) for d in DEVICES]
            if name in ('status', 'set_iface'):
                return {'iface': 'eth0', 'admin': True}
            return True
        return call


@pytest.fixture
def controller(monkeypatch):
    import gui.controller as module
    monkeypatch.setattr(module, 'get_settings', lambda key: False if key == 'remember' else [])
    monkeypatch.setattr(module, 'set_settings', lambda *_: None)
    monkeypatch.setattr(module, 'is_admin', lambda: True)
    monkeypatch.setattr(module, 'Nicknames', lambda: type('Names', (), {'get_name': lambda *_: ''})())
    ops = Ops()
    ctrl = Controller(ops=ops)
    ctrl._devices = [dict(d) for d in DEVICES]
    ctrl._privileged = True
    messages = []
    ctrl.status.connect(lambda text, level: messages.append((text, level)))
    yield ctrl, ops, messages
    ctrl.shutdown()
    _app.processEvents()


def test_failed_cut_rolls_back_routing_and_reports_failure(controller):
    ctrl, ops, messages = controller
    ops.block_all_for = lambda _: False
    ctrl.toggle_cut(MAC)
    assert MAC not in ctrl._cut
    assert not ctrl.is_spoofed(MAC)
    assert ('unkill', (MAC,)) in ops.calls
    assert messages[-1][0].startswith('Action failed:')
    assert not any(text.startswith('Cut ') for text, _ in messages)


def test_failed_restore_retains_cut_for_retry(controller):
    ctrl, ops, messages = controller
    ctrl.toggle_cut(MAC)
    messages.clear()
    ops.unblock_all_for = lambda _: False
    ctrl.toggle_cut(MAC)
    assert ctrl._cut == {MAC: IP}
    assert ctrl.is_spoofed(MAC)
    assert not any(text.startswith('Restored ') for text, _ in messages)


@pytest.mark.parametrize('feature', ['dns', 'port', 'explicit', 'monitor'])
def test_restoring_cut_preserves_other_routing_dependencies(controller, feature):
    ctrl, ops, _ = controller
    ctrl.toggle_cut(MAC)
    if feature == 'dns':
        ctrl._dns_blocks[MAC] = IP
    elif feature == 'port':
        ctrl._port_blocks[MAC] = {(443, 'tcp')}
    elif feature == 'explicit':
        ctrl._explicit_spoof.add(MAC)
    else:
        ctrl._monitoring.add(MAC)
    ctrl.toggle_cut(MAC)
    assert MAC not in ctrl._cut
    assert ctrl.is_spoofed(MAC)
    assert ('lag', (MAC, False)) in ops.calls
    assert ('unkill', (MAC,)) not in ops.calls


def test_one_way_restore_preserves_selective_port_block(controller):
    ctrl, ops, _ = controller
    ctrl.toggle_one_way(MAC)
    ctrl._port_blocks[MAC] = {(443, 'tcp')}
    ctrl.toggle_one_way(MAC)
    assert MAC not in ctrl.one_way_kills
    assert ctrl.is_spoofed(MAC)
    assert ('unkill', (MAC,)) not in ops.calls


def test_failed_restore_all_keeps_tracking_for_retry(controller):
    ctrl, ops, messages = controller
    ctrl.toggle_cut(MAC)
    ops.cleanup = lambda: False
    ctrl.unkill_all()
    assert ctrl._cut == {MAC: IP}
    assert not any(text.startswith('Restored all') for text, _ in messages)


def test_failed_dns_start_does_not_leave_phantom_state(controller):
    ctrl, ops, _ = controller
    ops.dns_block = lambda *_: False
    ctrl.dns_block(MAC, ['example.test'])
    assert not ctrl.is_dns_blocked(MAC)
    assert not ctrl.is_spoofed(MAC)


def test_failed_dns_stop_keeps_rule_visible(controller):
    ctrl, ops, _ = controller
    ctrl.dns_block(MAC, ['example.test'])
    ops.dns_unblock = lambda *_: False
    ctrl.dns_unblock(MAC)
    assert ctrl.is_dns_blocked(MAC)
    assert ctrl.is_spoofed(MAC)


def test_failed_monitor_start_rolls_back_automatic_route(controller):
    ctrl, ops, _ = controller
    ops.start_sniff = lambda *_: False
    assert not ctrl.start_monitor(MAC)
    assert not ctrl.is_monitoring(MAC)
    assert not ctrl.is_spoofed(MAC)


def test_monitor_target_switch_restores_previous_device(controller):
    ctrl, ops, _ = controller
    assert ctrl.start_monitor(MAC)
    assert ctrl.start_monitor(OTHER)
    assert not ctrl.is_monitoring(MAC)
    assert not ctrl.is_spoofed(MAC)
    assert ctrl.is_monitoring(OTHER)
    assert ('unkill', (MAC,)) in ops.calls
    calls = list(ops.calls)
    ctrl.stop_monitor(MAC)  # a stale dialog must not stop the new target
    assert ops.calls == calls
    assert ctrl.is_monitoring(OTHER)


def test_restore_all_cancels_queued_mutation(controller, monkeypatch):
    ctrl, ops, messages = controller
    queued = []
    monkeypatch.setattr(ctrl._pool, 'start', queued.append)
    ctrl.block_port(443, 'tcp', target_ip=IP)
    ctrl.unkill_all()
    queued.pop().run()  # delayed worker begins only after Restore All
    _app.processEvents()
    assert not any(name == 'block_port' for name, _ in ops.calls)
    assert ctrl._port_blocks == {}
    assert messages[-1][0] == 'Restored all devices and cleared every block.'


def test_stopping_route_cancels_queued_device_port_block(controller, monkeypatch):
    ctrl, ops, _ = controller
    queued = []
    monkeypatch.setattr(ctrl._pool, 'start', queued.append)
    ctrl.block_port(443, 'tcp', target_ip=IP)
    ctrl.toggle_spoof(MAC)
    queued.pop().run()
    _app.processEvents()
    assert not any(name == 'block_port' for name, _ in ops.calls)
    assert not ctrl.is_spoofed(MAC)


def test_port_completion_cannot_report_success_after_removal(controller, monkeypatch):
    ctrl, _, messages = controller
    queued = []
    monkeypatch.setattr(ctrl._pool, 'start', queued.append)
    ctrl.block_port(443, 'tcp', target_ip=IP)
    queued.pop().run()  # worker finishes; GUI completion is still queued
    ctrl.unblock_port(443, 'tcp')
    _app.processEvents()
    assert messages[-1][0] == 'Unblocked port 443/tcp'
    assert ctrl._port_blocks == {}


def test_restore_all_runs_after_inflight_host_operation(controller):
    ctrl, ops, messages = controller
    entered, release = threading.Event(), threading.Event()
    active = set()

    def block(_):
        entered.set()
        assert release.wait(3)
        active.add('example.test')
        return {'key': 'example.test', 'ok': True, 'added': ['192.0.2.1']}

    def cleanup():
        active.clear()
        return True

    ops.block_host = block
    ops.cleanup = cleanup
    ctrl.block_host('example.test')
    assert entered.wait(3)
    timer = threading.Timer(0.05, release.set)
    timer.start()
    try:
        ctrl.unkill_all()
    finally:
        release.set()
        timer.join()
    ctrl._pool.waitForDone()
    _app.processEvents()
    assert not active
    assert messages[-1][0] == 'Restored all devices and cleared every block.'


def test_stale_scan_completion_does_not_reapply_remembered_cut(controller, monkeypatch):
    ctrl, ops, _ = controller
    monkeypatch.setattr('gui.controller.get_settings', lambda key: [MAC] if key == 'killed' else True)
    ctrl.remember = True
    ctrl._scan.result = [dict(d) for d in DEVICES]
    ctrl.unkill_all()
    ops.calls.clear()
    ctrl._on_scan_done(True)
    assert not any(name in ('kill', 'block_all_for') for name, _ in ops.calls)
    assert not ctrl._cut


def test_scan_address_change_clears_old_rules_before_reapplying_mac_intents(controller):
    ctrl, ops, messages = controller
    ctrl.toggle_cut(MAC)
    ctrl.toggle_one_way(OTHER)
    ctrl._explicit_spoof.add(MAC)
    ctrl._dns_blocks[MAC] = IP
    ctrl._port_blocks[MAC] = {(443, 'tcp')}
    ctrl._monitoring.add(OTHER)
    moved = [dict(d) for d in DEVICES]
    moved[0]['ip'] = '192.168.1.99'
    moved[1]['ip'] = IP  # old IP has been reassigned to a different MAC
    ctrl._scan.result = moved
    ops.calls.clear()
    ctrl._on_scan_done(True)
    assert ops.calls[0] == ('cleanup', ())
    assert ctrl._cut == {MAC: '192.168.1.99'}
    assert ('block_all_for', (IP,)) not in ops.calls
    assert ctrl.one_way_kills == {OTHER}
    assert ctrl._explicit_spoof == {MAC}
    assert not ctrl._dns_blocks and not ctrl._port_blocks and not ctrl._monitoring
    assert 'Addresses changed' in messages[-1][0]


def test_scan_does_not_reapply_after_address_cleanup_failure(controller):
    ctrl, ops, messages = controller
    ctrl.toggle_cut(MAC)
    moved = [dict(d) for d in DEVICES]
    moved[0]['ip'] = '192.168.1.99'
    ctrl._scan.result = moved
    ops.cleanup = lambda: False
    ops.calls.clear()
    ctrl._on_scan_done(True)
    assert ctrl._cut == {MAC: IP}  # retain failed cleanup state for Restore All
    assert not any(name in ('kill', 'one_way_kill', 'block_all_for') for name, _ in ops.calls)
    assert messages[-1][0].startswith('Scan/state refresh failed:')


def test_unchanged_scan_keeps_active_cuts_without_unblocking(controller):
    ctrl, ops, _ = controller
    ctrl.toggle_cut(MAC)
    ctrl.toggle_cut(OTHER)
    ctrl._scan.result = [dict(d) for d in DEVICES]
    ops.calls.clear()
    ctrl._on_scan_done(True)
    assert ctrl._cut == {MAC: IP, OTHER: '192.168.1.43'}
    assert not any(name in ('cleanup', 'kill', 'unblock_all_for', 'block_all_for')
                   for name, _ in ops.calls)


def test_shutdown_joins_scan_before_cleanup(controller):
    ctrl, ops, _ = controller
    entered, release = threading.Event(), threading.Event()
    order = []

    def scan(_):
        entered.set()
        assert release.wait(3)
        order.append('scan finished')
        return [dict(d) for d in DEVICES]

    ops.scan = scan
    ops.cleanup = lambda: order.append('cleanup') or True
    ctrl.scan()
    assert entered.wait(3)
    timer = threading.Timer(0.05, release.set)
    timer.start()
    try:
        ctrl.shutdown()
    finally:
        release.set()
        timer.join()
    assert not ctrl._scan.isRunning()
    assert order == ['scan finished', 'cleanup']
    _app.processEvents()
    assert not ctrl._cut
    ctrl.shutdown()  # application quit and closeEvent may both request teardown
    assert order == ['scan finished', 'cleanup']


def test_old_lag_release_cannot_clear_a_restarted_interval(controller):
    ctrl, ops, _ = controller
    ctrl.start_lag(MAC, 100, 1000, 'both')
    ctrl.stop_lag()
    ctrl.start_lag(MAC, 500, 1000, 'both')
    ops.calls.clear()
    QTest.qWait(150)
    assert ('lag', (MAC, False)) not in ops.calls
    assert ctrl.lag_active_for(MAC)


def test_cut_stops_lag_before_it_can_release_the_new_cut(controller):
    ctrl, ops, _ = controller
    ctrl.start_lag(MAC, 100, 1000, 'both')
    ctrl.toggle_cut(MAC)
    assert not ctrl.lag_active_for(MAC)
    assert MAC in ctrl._cut
    ops.calls.clear()
    QTest.qWait(150)
    assert ('lag', (MAC, False)) not in ops.calls


def test_unprivileged_start_can_still_use_ping_scan(controller, monkeypatch):
    ctrl, ops, _ = controller
    ctrl._privileged = ctrl._admin = False
    ops.status = lambda: {'admin': False, 'iface': 'eth0'}
    ops.cleanup = lambda: False  # cannot change the firewall as a standard user
    started = []
    monkeypatch.setattr(ctrl, 'scan', started.append)
    ctrl.start()
    assert started == [1]


def test_dns_preset_toggle_does_not_claim_or_remove_custom_names(controller):
    from gui.dialogs.blocker_dialog import BlockerDialog
    from networking.hostblock import PRESET_HOSTS

    ctrl, ops, _ = controller
    preset = next(p for p in PRESET_HOSTS if p.method == 'dns')
    domains = {'custom.example.test'}
    ops.active_dns_blocks = lambda: {IP: list(domains)}
    ops.dns_unblock_name = lambda _, name: domains.discard(name) or True
    ctrl._dns_blocks[MAC] = IP
    ctrl._spoofed.add(MAC)
    dialog = BlockerDialog(ctrl)
    dialog.set_target(DEVICES[0])
    assert not dialog._preset_toggles[preset.key].isChecked()
    domains.update(preset.domains)
    dialog._refresh()
    assert dialog._preset_toggles[preset.key].isChecked()
    dialog._toggle_preset(preset, False)
    assert domains == {'custom.example.test'}
    assert ctrl.is_dns_blocked(MAC)
    dialog.close()


def test_rejecting_traffic_dialog_stops_capture(controller):
    from gui.dialogs.traffic_dialog import TrafficDialog

    ctrl, ops, _ = controller
    ops.flows = lambda: []
    dialog = TrafficDialog(ctrl)
    dialog.start(DEVICES[0])
    assert ctrl.is_monitoring(MAC)
    dialog.reject()  # Escape takes this path instead of closeEvent
    assert not ctrl.is_monitoring(MAC)
    assert not ctrl.is_spoofed(MAC)


def test_linux_does_not_offer_persistent_helper_install(controller):
    from gui.dialogs.privilege_dialog import PrivilegeDialog

    ctrl, _, _ = controller
    ctrl.privilege_status = lambda: {
        'platform': 'linux', 'ok': False, 'root': False,
        'helper_installed': False, 'helper_running': False,
    }
    dialog = PrivilegeDialog(ctrl)
    assert dialog._helper_box.isHidden()
    dialog.close()
