"""Controller — the one mediator between the UI and the privileged engine.

The controller owns app *intent* and UI state; the actual privileged work goes
through a swappable ``ops`` backend:

* **root GUI** → ``LocalEngine`` (``privilege.helper.Engine``), in-process.
* **unprivileged GUI + installed helper** → ``RemoteEngine``, every op a request
  to the root daemon over its socket.

Both expose the identical method surface, so the orchestration here (cut = ARP
redirect + firewall drop, one-way, lag, monitor) is written once and runs the
same whether local or remote. The window/widgets are dumb: they call intent
methods and render signals; they never touch a socket, ``pfctl``, or a scanner.
"""
from __future__ import annotations

import functools
import logging
import threading
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, QThread, QThreadPool, QTimer, Qt, Signal, Slot

from networking.nicknames import Nicknames
from tools.utils import get_iface_by_name
from tools.utils_gui import is_admin, get_settings, set_settings

log = logging.getLogger(__name__)

Device = dict


def guarded(fn):
    """Wrap an action so an engine/helper failure becomes a status, not a crash."""
    @functools.wraps(fn)
    def wrap(self, *a, **k):
        try:
            with self._ops_lock:
                if self._closing:
                    return None
                return fn(self, *a, **k)
        except Exception as exc:  # noqa: BLE001
            log.warning('%s failed: %s', fn.__name__, exc)
            self.status.emit(f'Action failed: {exc}', 'danger')
            self.states_changed.emit()
            return None
    return wrap


class ScanWorker(QThread):
    """Runs a (possibly remote) scan off the GUI thread."""

    done = Signal(bool)

    def __init__(self) -> None:
        super().__init__()
        self._fn = None
        self.result = None
        self.error: Optional[str] = None

    def run(self) -> None:
        self.error = None
        self.result = None
        try:
            self.result = self._fn()  # type: ignore[misc]
        except Exception as exc:  # noqa: BLE001
            self.error = str(exc)
            log.warning('scan failed: %s', exc)
        self.done.emit(self.error is None)


class _TaskSignals(QObject):
    done = Signal(object, object)


class _Task(QRunnable):
    def __init__(self, fn, callback, generation) -> None:
        super().__init__()
        self._fn = fn
        self.callback = callback
        self.generation = generation
        self.signals = _TaskSignals()

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001
            result = exc
        self.signals.done.emit(self, result)


class Controller(QObject):
    devices_changed = Signal(list)
    scan_started = Signal(int)
    scan_progress = Signal(int, int)
    scan_finished = Signal(bool)
    states_changed = Signal()
    host_blocks_changed = Signal(dict)
    status = Signal(str, str)
    privilege_changed = Signal(bool, str)
    flows_changed = Signal(list)             # pushed live traffic (no polling)

    def __init__(self, ops=None) -> None:
        super().__init__()
        self._ops_lock = threading.RLock()
        self._generation = 0
        self._closing = False
        self.nicknames = Nicknames()
        self.remember = bool(get_settings('remember'))
        self._applied_remember = False

        # engine backend
        self._remote = False
        self.ops = ops if ops is not None else self._pick_backend()
        # push hook: the engine calls this (from its sniffer / session thread)
        # with fresh flows; the Qt signal marshals it onto the GUI thread.
        try:
            self.ops.on_flows = self._flows_pushed
        except Exception:  # noqa: BLE001
            pass

        # UI-facing state (kept in sync as we drive the backend)
        self._devices: list[Device] = []
        self._iface = 'NULL'
        self._admin = is_admin()
        self._privileged = self._admin or self._remote
        self._spoofed: set[str] = set()      # every ARP-spoofed (routed) mac
        self._explicit_spoof: set[str] = set()   # spoof the user turned on directly
        self._cut: dict[str, str] = {}        # mac -> ip currently firewall-cut
        self.one_way_kills: set[str] = set()
        self._monitoring: set[str] = set()
        self._monitor_spoofed: set[str] = set()
        self._dns_blocks: dict[str, str] = {}    # mac -> ip under DNS-name block (PSN)
        self._dns_spoofed: set[str] = set()
        self._port_blocks: dict[str, set] = {}   # mac -> {(port, proto)} blocked for it

        # lag switch
        self._lag_mac: Optional[str] = None
        self._lag_block_ms = 1500
        self._lag_release_ms = 1500
        self._lag_dir = 'both'
        self._lag_timer = QTimer(self)
        self._lag_timer.timeout.connect(self._lag_cycle)
        self._lag_release_timer = QTimer(self)
        self._lag_release_timer.setSingleShot(True)
        self._lag_release_timer.timeout.connect(self._release_lag)

        self._pool = QThreadPool(self)
        self._pool.setMaxThreadCount(1)
        self._tasks: set[_Task] = set()
        self._scan = ScanWorker()
        self._scan.generation = 0
        self._scan.done.connect(self._on_scan_done)

    def _pick_backend(self):
        """Local engine when root; else the helper if it's running; else local
        (privileged ops will fail and the banner explains why)."""
        if is_admin():
            from privilege.helper import Engine
            return Engine()
        try:
            from privilege.remote import RemoteEngine
            remote = RemoteEngine()
            if remote.available():
                self._remote = True
                return remote
        except Exception as exc:  # noqa: BLE001
            log.info('helper unavailable: %s', exc)
        from privilege.helper import Engine
        return Engine()

    # -- lifecycle -----------------------------------------------------------

    @property
    def full_kills(self) -> set:
        return set(self._cut.values())

    def _flows_pushed(self, flows) -> None:
        if not self._closing:
            self.flows_changed.emit(flows or [])

    def start(self) -> None:
        if self._closing:
            return
        # Clear anything a previous hard-crash could have left blocked.
        try:
            if self._privileged:
                self._require(self.ops.cleanup(), 'Could not clear previous network rules')
            self._require(self.ops.set_scan_params(int(get_settings('count') or 255),
                                                  int(get_settings('threads') or 12)),
                          'Could not configure scanning')
            saved = get_settings('iface')
            if saved:
                self.ops.set_iface(saved)
            st = self.ops.status()
            self._iface = st.get('iface', 'NULL')
            self._admin = bool(st.get('admin'))
            self._devices = self.ops.devices() or []
            self._apply_nicknames()
        except Exception as exc:  # noqa: BLE001
            self.status.emit(f'Engine init failed: {exc}', 'danger')
            self._emit_privilege()
            return
        self._privileged = self._admin or self._remote
        self._emit_privilege()
        self.devices_changed.emit(self._devices)

        if self._remote:
            self.status.emit('Using the background helper for privileged actions.', 'good')
        elif not self._admin:
            self.status.emit('Not running as root — Ping scan only. '
                             'Set Up Access for full power.', 'warn')
        self.scan(0 if self._privileged else 1)

    def shutdown(self) -> None:
        if self._closing:
            return
        self._closing = True
        self._generation += 1
        self._lag_timer.stop()
        self._lag_release_timer.stop()
        self._lag_mac = None
        # Workers may still be changing the engine. Join them before the final
        # cleanup so a late DNS lookup/scan cannot recreate rules after it.
        self._scan.wait()
        self._pool.waitForDone()
        with self._ops_lock:
            if not self._safe(self.ops.cleanup):
                self.status.emit('Could not confirm that every network rule was cleared.', 'danger')
            if hasattr(self.ops, 'close'):
                self._safe(self.ops.close)
        self._tasks.clear()
        self._clear_state()

    def _clear_state(self) -> None:
        self._cut.clear()
        self.one_way_kills.clear()
        self._monitoring.clear()
        self._monitor_spoofed.clear()
        self._spoofed.clear()
        self._explicit_spoof.clear()
        self._dns_blocks.clear()
        self._dns_spoofed.clear()
        self._port_blocks.clear()
        self.flows_changed.emit([])

    def _emit_privilege(self) -> None:
        # "privileged" = we can actually act (root here, or a live helper).
        self.privilege_changed.emit(self._privileged, self._iface)

    def iface_name(self) -> str:
        return self._iface

    # -- privilege setup -----------------------------------------------------

    def privilege_status(self) -> dict:
        from privilege.install import status
        return status()

    def elevate(self) -> tuple:
        from privilege.install import elevate
        ok, msg = elevate()
        self.status.emit(msg, 'good' if ok else 'warn')
        return ok, msg

    def install_helper(self) -> tuple:
        from privilege.install import install_helper
        ok, msg = install_helper()
        self.status.emit(msg, 'good' if ok else 'danger')
        return ok, msg

    # -- scanning ------------------------------------------------------------

    def scan(self, scan_type: int = 0) -> None:
        if self._closing or self._scan.isRunning():
            return
        self.stop_lag()
        kind = 'ping' if scan_type else 'arp'
        generation = self._generation
        self._scan.generation = generation

        def _scan():
            with self._ops_lock:
                if self._closing or generation != self._generation:
                    return None
                return self.ops.scan(kind)

        self._scan._fn = _scan
        self.scan_started.emit(scan_type)
        self.status.emit('Scanning your network…' if scan_type == 0
                         else 'Deep-scanning (ping sweep)…', 'accent')
        self._scan.start()

    def _on_scan_done(self, ok: bool) -> None:
        if self._closing or self._scan.generation != self._generation:
            self.scan_finished.emit(False)
            return
        try:
            with self._ops_lock:
                if self._scan.error:
                    raise RuntimeError(self._scan.error)
                previous_devices = self._devices
                self._devices = self._scan.result or []
                self._apply_nicknames()
                reset = self._reapply_state(previous_devices)
                n = sum(not d['admin'] for d in self._devices)
                message = f'Found {n} device{"s" * (n != 1)} on the network.'
                if reset:
                    message += (' Addresses changed: DNS, port, host and capture rules were cleared. '
                                'Cut, one-way and explicit routing were reapplied to available devices.')
                self.status.emit(message, 'warn' if reset else 'good')
        except Exception as exc:  # noqa: BLE001
            ok = False
            self.status.emit(f'Scan/state refresh failed: {exc}', 'danger')
        self.devices_changed.emit(self._devices)
        self.scan_finished.emit(ok)

    def _reapply_state(self, previous_devices=None) -> bool:
        """Re-assert active cuts/one-way against the fresh device list (IPs may
        have changed) and, on the first scan, any remembered cuts.

        Address-scoped filters cannot safely follow a changed/disappeared MAC:
        that address may now belong to somebody else. Restore before reapplying
        supported MAC-based intents. Unchanged scans leave active rules intact.
        """
        present = {d['mac']: d for d in self._devices if not d['admin']}
        cut_macs = set(self._cut) | self._remembered_once()
        oneway_macs = set(self.one_way_kills)
        explicit_macs = set(self._explicit_spoof)
        previous = {d['mac']: d['ip'] for d in (previous_devices or [])}
        reset = any(mac not in present or previous.get(mac) != present[mac]['ip']
                    for mac in self._spoofed) if previous_devices is not None else False
        if reset:
            self._generation += 1  # queued work still refers to the old addresses
            try:
                self._require(self.ops.cleanup(), 'Could not clear rules for changed network addresses')
            except Exception:
                # Keep the address snapshot associated with the still-tracked
                # rules, so another scan retries this cleanup before reapplying.
                self._devices = previous_devices
                raise
            self._clear_state()
        for mac in cut_macs:
            dev = present.get(mac)
            if dev and self._cut.get(mac) != dev['ip']:
                self._do_cut(mac, dev['ip'])
        for mac in oneway_macs:
            if mac in present and mac not in self.one_way_kills:
                self._require(self.ops.one_way_kill(mac), 'Could not restore one-way mode')
                self._spoofed.add(mac)
                self.one_way_kills.add(mac)
        for mac in explicit_macs:
            if mac in present:
                self._ensure_spoofed(mac)
                self._explicit_spoof.add(mac)
        self._persist_killed()
        if reset:
            self._emit_hosts()
            self.states_changed.emit()
        return reset

    def _remembered_once(self) -> set:
        if self.remember and not self._applied_remember:
            self._applied_remember = True
            return set(get_settings('killed') or [])
        return set()

    # -- kill / restore ------------------------------------------------------

    def device_by_mac(self, mac: str) -> Optional[Device]:
        return next((d for d in self._devices if d['mac'] == mac), None)

    def state_of(self, device: Device) -> dict:
        mac = device['mac']
        return {
            'cut': mac in self._cut,
            'spoof': mac in self._spoofed,
            'one_way': mac in self.one_way_kills,
            'monitor': mac in self._monitoring,
            'dns': mac in self._dns_blocks,
            'lag': self._lag_timer.isActive() and self._lag_mac == mac,
        }

    # -- spoof (route a device through us — the base for blocks) --------------

    def is_spoofed(self, mac: str) -> bool:
        return mac in self._spoofed

    def _ensure_spoofed(self, mac: str) -> None:
        """Route a device through us (idempotent). Base for monitor/lag/blocks."""
        if mac not in self._spoofed:
            self._require(self.ops.spoof(mac), 'Could not route the selected device')
            self._spoofed.add(mac)

    def device_blocks(self, mac: str) -> list[str]:
        """Human labels for everything that would stop if this device is un-spoofed."""
        blocks: list[str] = []
        if mac in self._cut:
            blocks.append('cut')
        if mac in self.one_way_kills:
            blocks.append('one-way kill')
        if mac in self._dns_blocks:
            blocks.append('DNS block')
        if mac in self._monitoring:
            blocks.append('traffic monitor')
        if self.lag_active_for(mac):
            blocks.append('lag switch')
        pb = self._port_blocks.get(mac)
        if pb:
            blocks.append(f'{len(pb)} port block' + ('s' if len(pb) != 1 else ''))
        return blocks

    def _clear_device_blocks(self, mac: str) -> None:
        """Remove every block tied to a device (used when un-spoofing it)."""
        device = self.device_by_mac(mac)
        ip = device['ip'] if device else self._cut.get(mac)
        if self.lag_active_for(mac):
            self.stop_lag()
        if mac in self._monitoring:
            self._require(self.ops.stop_sniff(), 'Could not stop traffic capture')
            self._monitoring.discard(mac)
            self._monitor_spoofed.discard(mac)
        if mac in self._dns_blocks:
            di = self._dns_blocks.get(mac, ip)
            if di:
                self._require(self.ops.dns_unblock(di), 'Could not remove the DNS block')
            self._dns_blocks.pop(mac, None)
            self._dns_spoofed.discard(mac)
        for port, proto in list(self._port_blocks.get(mac, set())):
            self._remove_port(port, proto)
        self._port_blocks.pop(mac, None)
        if mac in self._cut or mac in self.one_way_kills:
            if ip:
                self._require(self.ops.unblock_all_for(ip), 'Could not restore the device')
            self._require(self.ops.lag(mac, False), 'Could not clear the device drop')
            self._cut.pop(mac, None)
        self.one_way_kills.discard(mac)
        self._persist_killed()

    @guarded
    def toggle_spoof(self, mac: str, clear_blocks: bool = True) -> None:
        """Turn routing-through-us on/off for a device.

        Turning it OFF clears every block on the device (the UI warns first);
        pass ``clear_blocks=False`` only if the caller already handled them.
        """
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        if mac in self._spoofed:
            if clear_blocks:
                self._clear_device_blocks(mac)
            self._explicit_spoof.discard(mac)
            self._maybe_unspoof(mac)
            self.status.emit(f'Stopped routing {device["ip"]} through this PC', 'good')
        else:
            self._ensure_spoofed(mac)
            self._explicit_spoof.add(mac)
            self.status.emit(f'Routing {device["ip"]} through this PC — blocks can now apply', 'accent')
        self.states_changed.emit()

    def _maybe_unspoof(self, mac: str) -> None:
        """Drop the ARP spoof only if nothing still needs the device routed."""
        if (mac in self._cut or mac in self.one_way_kills or mac in self._monitoring
                or mac in self._dns_blocks or self.lag_active_for(mac)
                or mac in self._explicit_spoof or self._port_blocks.get(mac)):
            return
        if mac not in self._spoofed:
            return
        self._require(self.ops.unkill(mac), 'Could not stop routing the device')
        self._spoofed.discard(mac)

    def _do_cut(self, mac: str, ip: str) -> None:
        new_spoof = mac not in self._spoofed
        was_one_way = mac in self.one_way_kills
        if new_spoof:
            self._require(self.ops.kill(mac), 'Could not cut the selected device')
            self._spoofed.add(mac)
        else:
            self._require(self.ops.lag(mac, True), 'Could not cut the routed device')
        try:
            self._require(self.ops.block_all_for(ip), 'Could not install the device firewall block')
            self._cut[mac] = ip
            self.one_way_kills.discard(mac)
        except Exception:
            self._safe(lambda: self.ops.lag(mac, False))
            if was_one_way:
                self._safe(lambda: self.ops.one_way_kill(mac))
            if new_spoof:
                self._maybe_unspoof(mac)
            raise

    @guarded
    def toggle_cut(self, mac: str) -> None:
        """Cut a device off the internet reliably: ARP redirect + firewall drop
        (a real cut even while kernel forwarding is on)."""
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        if self.lag_active_for(mac):
            self.stop_lag()
        ip = self._cut.get(mac, device['ip'])
        if mac in self._cut:
            self._require(self.ops.unblock_all_for(ip), 'Could not remove the device firewall block')
            self._require(self.ops.lag(mac, False), 'Could not clear the device drop')
            self._cut.pop(mac, None)
            self.one_way_kills.discard(mac)
            self._maybe_unspoof(mac)
            self.status.emit(f"Restored {ip}'s internet", 'good')
        else:
            self._do_cut(mac, ip)
            self.status.emit(f'Cut {ip} off the internet', 'danger')
        self._persist_killed()
        self.states_changed.emit()

    @guarded
    def kill_all(self) -> None:
        self.stop_lag()
        for device in self._devices:
            if device['admin'] or device['mac'] in self._cut:
                continue
            self._do_cut(device['mac'], device['ip'])
        self._persist_killed()
        self.status.emit('Cut all devices off the internet.', 'danger')
        self.states_changed.emit()

    @guarded
    def unkill_all(self) -> None:
        self._generation += 1
        self.stop_lag()
        # cleanup() is the comprehensive teardown: unkill all + stop sniffer/DNS +
        # clear every firewall rule (port/ip/host) and WinDivert drop. So "Restore
        # all" clears BLOCKS too, not just cuts.
        self._require(self.ops.cleanup(), 'Could not clear every network rule; retry Restore All')
        self._clear_state()
        self._persist_killed()
        self._emit_hosts()
        self.status.emit('Restored all devices and cleared every block.', 'good')
        self.states_changed.emit()

    @guarded
    def toggle_one_way(self, mac: str) -> None:
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        if self.lag_active_for(mac):
            self.stop_lag()
        if mac in self.one_way_kills:
            self._require(self.ops.lag(mac, False), 'Could not clear the one-way drop')
            self._require(self.ops.unblock_all_for(device['ip']), 'Could not clear the one-way rule')
            self.one_way_kills.discard(mac)
            self._maybe_unspoof(mac)
            self.status.emit(f'One-way kill off for {device["ip"]}', 'good')
        else:
            if mac in self._cut:
                self.status.emit('Restore the full cut before enabling one-way mode.', 'warn')
                return
            self._require(self.ops.one_way_kill(mac), 'Could not enable one-way mode')
            self._spoofed.add(mac)
            self.one_way_kills.add(mac)
            self.status.emit(f'One-way kill on for {device["ip"]}', 'warn')
        self.states_changed.emit()

    # -- lag switch ----------------------------------------------------------

    @guarded
    def start_lag(self, mac: str, block_ms: int, release_ms: int, direction: str) -> None:
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        if direction != 'both':
            raise ValueError('Lag switching currently supports both directions only')
        if mac in self._cut or mac in self.one_way_kills:
            raise ValueError('Restore the existing cut before starting a lag switch')
        self.stop_lag()
        self._lag_mac = mac
        self._lag_block_ms, self._lag_release_ms, self._lag_dir = block_ms, release_ms, direction
        self.status.emit(f'Lag switch on: {block_ms}ms lag / {release_ms}ms clear', 'warn')
        self._lag_timer.start(block_ms + release_ms)
        self._lag_cycle()
        self.states_changed.emit()

    @guarded
    def _lag_cycle(self) -> None:
        device = self.device_by_mac(self._lag_mac) if self._lag_mac else None
        if not device:
            self.stop_lag()
            return
        mac = device['mac']
        try:
            self._ensure_spoofed(mac)            # route through us (no permanent drop)
            # Drop everything for one window, then release — a real kernel lag/loss.
            self._require(self.ops.lag(mac, True), 'Could not start the lag interval')
            self._lag_release_timer.start(self._lag_block_ms)
        except Exception:
            self._lag_timer.stop()
            self._lag_release_timer.stop()
            self._lag_mac = None
            self._safe(lambda: self.ops.lag(mac, False))
            self._maybe_unspoof(mac)
            raise

    @guarded
    def _release_lag(self) -> None:
        if self._lag_mac:
            self._require(self.ops.lag(self._lag_mac, False), 'Could not release the lag interval')

    @guarded
    def stop_lag(self) -> None:
        if not self._lag_timer.isActive() and self._lag_mac is None:
            return
        self._lag_timer.stop()
        self._lag_release_timer.stop()
        mac = self._lag_mac
        self._lag_mac = None
        if mac:
            self._require(self.ops.lag(mac, False), 'Could not stop the lag switch')
            self._maybe_unspoof(mac)
        self.status.emit('Lag switch off.', 'good')
        self.states_changed.emit()

    def lag_active_for(self, mac: str) -> bool:
        return self._lag_timer.isActive() and self._lag_mac == mac

    # -- host / port blocking (async — resolves DNS off-thread) --------------

    @guarded
    def block_host(self, target, device_mac: Optional[str] = None) -> None:
        # Route the configured device through us so the destination block actually
        # bites for it (host blocks apply to every spoofed device).
        if device_mac:
            device = self.device_by_mac(device_mac)
            if not device or device['admin']:
                return
            self._ensure_spoofed(device_mac)
            self.states_changed.emit()
        self.status.emit(f'Blocking {target}…', 'accent')
        self._run(lambda: self.ops.block_host(target)
                  if not device_mac or device_mac in self._spoofed else None,
                  lambda result: self._on_host_block(result) if result is not None else None)

    def block_destination(self, target: str, device_mac: Optional[str] = None) -> None:
        """Block a raw destination the user typed — an IP or a domain.

        A **domain** is blocked primarily by DNS interception (NXDOMAIN) so the
        device can't even resolve it — IP-blocking a domain is weak because the
        name still resolves and CDN sites rotate across many IPs. We also
        IP-block its current addresses as a backstop. A raw **IP** is dst-blocked
        directly. Everything is scoped to the routed device you're configuring.
        """
        from networking.hostblock import _looks_like_ipv4
        target = target.strip()
        if not target:
            return
        if not _looks_like_ipv4(target) and device_mac:
            # Domain → DNS NXDOMAIN for this device (the effective block).
            self.dns_block(device_mac, [target])
        # Also IP-block the (resolved) addresses as a backstop / for raw IPs.
        self.block_host(target, device_mac)

    def unblock_host(self, key: str) -> None:
        def _done(result):
            if isinstance(result, Exception) or not result:
                self.status.emit(f'Could not remove host block {key}.', 'danger')
            else:
                self.status.emit(f'Unblocked {key}', 'good')
            self._emit_hosts()

        self._run(lambda: self.ops.unblock_host(key), _done)

    def refresh_hosts(self) -> None:
        self._run(self.ops.refresh_hosts, lambda _: self._emit_hosts())

    def _on_host_block(self, result) -> None:
        if isinstance(result, Exception):
            self.status.emit(f'Host block failed: {result}', 'danger')
        elif isinstance(result, dict) and result.get('ok'):
            self.status.emit(f'Blocked {result["key"]} ({len(result.get("added", []))} IPs)', 'danger')
        else:
            key = result.get('key', '?') if isinstance(result, dict) else '?'
            self.status.emit(f'Nothing blocked for {key} (could not resolve?)', 'warn')
        self._emit_hosts()

    def _emit_hosts(self) -> None:
        self.host_blocks_changed.emit(self.active_host_blocks())

    def active_host_blocks(self) -> dict:
        try:
            return {k: set(v) for k, v in (self.ops.active_host_blocks() or {}).items()}
        except Exception as exc:  # noqa: BLE001
            log.debug('active_host_blocks: %s', exc)
            return {}

    def is_host_active(self, key: str) -> bool:
        return bool(self.active_host_blocks().get(key))

    @guarded
    def block_port(self, port: int, proto: str = 'tcp', direction: str = 'both',
                   target_ip: Optional[str] = None) -> None:
        # A device-scoped port block only bites if that device is routed through
        # us — so auto-spoof it (the block ceases if you later stop spoofing).
        # Run the (blocking) firewall/WinDivert call off the GUI thread so the
        # window never freezes while netsh works.
        mac = None
        if target_ip:
            dev = next((d for d in self._devices if d['ip'] == target_ip and not d['admin']), None)
            if not dev:
                raise ValueError('The selected device is no longer available; scan again')
            mac = dev['mac']
            self._ensure_spoofed(mac)
            # Track optimistically so state (spoof/port list) is consistent
            # immediately; the async call rolls it back if the block fails.
            self._port_blocks.setdefault(mac, set()).add((port, proto))
        self.states_changed.emit()
        self.status.emit(f'Blocking port {port}/{proto}…', 'accent')

        def _done(res):
            if mac and (port, proto) not in self._port_blocks.get(mac, set()):
                return  # removed while the completion was queued
            ok = bool(res) and not isinstance(res, Exception)
            if not ok and mac:
                self._port_blocks.get(mac, set()).discard((port, proto))
                self._maybe_unspoof(mac)
            self.status.emit(f'Blocked port {port}/{proto}' if ok
                             else 'Port block failed (need root / helper?)',
                             'danger' if ok else 'warn')
            self.states_changed.emit()

        self._run(lambda: self.ops.block_port(port, proto, direction, target_ip)
                  if not mac or (port, proto) in self._port_blocks.get(mac, set()) else None,
                  _done)

    def _remove_port(self, port: int, proto: str) -> None:
        self._require(self.ops.unblock_port(port, proto), f'Could not remove port block {port}/{proto}')
        for mac in list(self._port_blocks):
            self._port_blocks[mac].discard((port, proto))
            if not self._port_blocks[mac]:
                self._port_blocks.pop(mac, None)
                self._maybe_unspoof(mac)

    @guarded
    def unblock_port(self, port: int, proto: str = 'tcp') -> None:
        self._remove_port(port, proto)
        self.status.emit(f'Unblocked port {port}/{proto}', 'good')
        self.states_changed.emit()

    def list_blocked_ports(self) -> list:
        try:
            return self.ops.list_blocked_ports() or []
        except Exception:  # noqa: BLE001
            return []

    def list_blocked_ips(self) -> list:
        try:
            return self.ops.list_blocked_ips() or []
        except Exception:  # noqa: BLE001
            return []

    @guarded
    def unblock_ip(self, ip: str) -> None:
        self._require(self.ops.unblock_ip(ip), f'Could not remove IP block {ip}')
        self.status.emit(f'Unblocked {ip}', 'good')

    # -- misc ----------------------------------------------------------------

    def _apply_nicknames(self) -> None:
        for d in self._devices:
            if d.get('type') == 'User':
                d['name'] = self.nicknames.get_name(d['mac'])

    def set_nickname(self, mac: str, name: str) -> None:
        if name.strip():
            self.nicknames.set_name(mac, name.strip())
        else:
            self.nicknames.reset_name(mac)
        self._apply_nicknames()
        self.devices_changed.emit(self._devices)

    def probe(self, ip: str) -> None:
        self.status.emit(f'Probing {ip}…', 'accent')
        self._run(lambda: self.ops.probe(ip), self._on_probe)

    def _on_probe(self, hit) -> None:
        if isinstance(hit, Exception) or not hit:
            self.status.emit('No response from that address.', 'warn')
        else:
            self.status.emit(f'Discovered {hit[0]} · {hit[1]}', 'good')
            self._safe(self._refresh_devices)

    def _refresh_devices(self) -> None:
        self._devices = self.ops.devices() or self._devices
        self._apply_nicknames()
        self.devices_changed.emit(self._devices)

    # -- traffic monitor -----------------------------------------------------

    @guarded
    def start_monitor(self, mac: str) -> bool:
        device = self.device_by_mac(mac)
        if not device or device['admin'] or not self._privileged:
            return False
        # There is one sniffer, so switching targets must retire the previous
        # monitor rather than leaving its device routed and marked capturing.
        for previous in list(self._monitoring - {mac}):
            self._stop_monitor(previous)
        was_spoofed = mac in self._spoofed
        self._ensure_spoofed(mac)          # route through us (no drop) so we can see it
        try:
            self._require(self.ops.start_sniff(device['ip']), 'Could not start traffic capture')
        except Exception:
            if not was_spoofed:
                self._maybe_unspoof(mac)
            raise
        if not was_spoofed:
            self._monitor_spoofed.add(mac)
        self._monitoring.add(mac)
        self.status.emit(
            f'Capturing {device["ip"]} — routed through this Mac.' if self._privileged
            else 'Set Up Access to capture traffic.',
            'accent' if self._privileged else 'warn')
        self.states_changed.emit()
        return self._privileged

    @guarded
    def stop_monitor(self, mac: str) -> None:
        self._stop_monitor(mac)
        self.states_changed.emit()

    def _stop_monitor(self, mac: str) -> None:
        if mac not in self._monitoring:
            return
        self._require(self.ops.stop_sniff(), 'Could not stop traffic capture')
        self._monitoring.discard(mac)
        self._monitor_spoofed.discard(mac)
        self._maybe_unspoof(mac)

    def flows(self) -> list:
        try:
            return self.ops.flows() or []
        except Exception:  # noqa: BLE001
            return []

    def is_monitoring(self, mac: str) -> bool:
        return mac in self._monitoring

    def can_capture(self) -> bool:
        return self._privileged

    # -- DNS-name blocking (PSN) — MITM the device, NXDOMAIN the name --------

    @guarded
    def dns_block(self, mac: str, domains) -> None:
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        ip = device['ip']
        was_spoofed = mac in self._spoofed
        self._ensure_spoofed(mac)                 # DNS must flow through us
        try:
            self._require(self.ops.dns_block(ip, list(domains)), 'Could not install the DNS block')
        except Exception:
            if not was_spoofed:
                self._maybe_unspoof(mac)
            raise
        if not was_spoofed:
            self._dns_spoofed.add(mac)
        self._dns_blocks[mac] = ip
        self.status.emit(f'DNS block active for {ip} (NXDOMAIN on blocked names)', 'danger')
        self.states_changed.emit()

    @guarded
    def dns_unblock(self, mac: str) -> None:
        device = self.device_by_mac(mac)
        ip = self._dns_blocks.get(mac, device['ip'] if device else None)
        if ip:
            self._require(self.ops.dns_unblock(ip), 'Could not remove the DNS block')
        self._dns_blocks.pop(mac, None)
        self._dns_spoofed.discard(mac)
        self._maybe_unspoof(mac)
        self.status.emit('DNS block off.', 'good')
        self.states_changed.emit()

    def stop_dns_block_ip(self, ip: str) -> None:
        mac = next((m for m, i in self._dns_blocks.items() if i == ip), None)
        if mac:
            self.dns_unblock(mac)
        else:
            self._safe(lambda: self.ops.dns_unblock(ip))
            self.states_changed.emit()

    def is_dns_blocked(self, mac: str) -> bool:
        return mac in self._dns_blocks

    @guarded
    def dns_unblock_name(self, mac: str, name: str) -> None:
        """Stop blocking a single DNS/domain name for a device."""
        device = self.device_by_mac(mac)
        ip = self._dns_blocks.get(mac, device['ip'] if device else None)
        if not ip:
            return
        self._require(self.ops.dns_unblock_name(ip, name), f'Could not unblock {name}')
        # A domain typed in the destination field also placed a host IP block under
        # the same key — clear that too so removing the name removes both.
        if name in self.active_host_blocks():
            self._require(self.ops.unblock_host(name), f'Could not remove the destination block for {name}')
        # A failed state read must not be mistaken for an empty DNS blocklist.
        active = self.ops.active_dns_blocks()
        if not isinstance(active, dict):
            raise RuntimeError('Could not read the remaining DNS blocks')
        if not active.get(ip):     # last name for this device
            self._dns_blocks.pop(mac, None)
            self._dns_spoofed.discard(mac)
            self._maybe_unspoof(mac)
        self._emit_hosts()
        self.status.emit(f'Unblocked {name}', 'good')
        self.states_changed.emit()

    def active_blocks(self) -> list:
        """All active blocks as flat, per-item rows built from tracked state.

        In-memory (no netsh enumeration), device-scoped, and one row per name /
        port / host so each can be removed individually.
        """
        items: list[dict] = []
        dns = self.active_dns_blocks()               # {ip: [names]}
        ip_to_mac = {v: k for k, v in self._dns_blocks.items()}
        dns_names: set[str] = set()
        for ip, names in dns.items():
            mac = ip_to_mac.get(ip)
            for name in sorted(names):
                dns_names.add(name)
                items.append({'kind': 'dns', 'mac': mac, 'name': name,
                              'label': f'{name}   ·   DNS + TLS block'})
        mac_to_ip = {d['mac']: d['ip'] for d in self._devices}
        for mac, ports in self._port_blocks.items():
            ip = mac_to_ip.get(mac, '?')
            for port, proto in sorted(ports):
                items.append({'kind': 'port', 'port': port, 'proto': proto,
                              'label': f'port {port}/{proto}   ·   {ip}'})
        for key, ips in self.active_host_blocks().items():
            if key in dns_names:                     # already shown as a domain row
                continue
            items.append({'kind': 'host', 'key': key,
                          'label': f'{key}   ({len(ips)} IP{"s" * (len(ips) != 1)})'})
        return items

    def active_dns_blocks(self) -> dict:
        try:
            res = self.ops.active_dns_blocks()
            return res if isinstance(res, dict) else {}
        except Exception:  # noqa: BLE001
            return {}

    # -- settings ------------------------------------------------------------

    @guarded
    def set_iface(self, name: str) -> None:
        self._generation += 1
        self.stop_lag()
        self._require(self.ops.cleanup(), 'Could not restore the current interface')
        self._clear_state()
        st = self.ops.set_iface(name)
        self._iface = st.get('iface', name) if isinstance(st, dict) else name
        set_settings('iface', name)
        self._devices = self.ops.devices() or []
        self._apply_nicknames()
        self._emit_privilege()
        self.devices_changed.emit(self._devices)
        self._emit_hosts()
        self.states_changed.emit()

    def set_scan_params(self, count: int, threads: int) -> None:
        set_settings('count', count)
        set_settings('threads', threads)
        self._safe(lambda: self.ops.set_scan_params(count, threads))

    def set_remember(self, on: bool) -> None:
        self.remember = on
        set_settings('remember', on)
        self._persist_killed()

    def _persist_killed(self) -> None:
        set_settings('killed', list(self._cut) if self.remember else [])

    # -- plumbing ------------------------------------------------------------

    @staticmethod
    def _require(result, message: str):
        if not result:
            raise RuntimeError(message)
        return result

    def _safe(self, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            log.debug('op failed: %s', exc)
            return None

    def _run(self, fn, callback) -> None:
        if self._closing:
            return
        generation = self._generation

        def _work():
            with self._ops_lock:
                if self._closing or generation != self._generation:
                    return None
                return fn()

        task = _Task(_work, callback, generation)
        task.signals.done.connect(self._finish_task, Qt.QueuedConnection)
        self._tasks.add(task)
        self._pool.start(task)

    @Slot(object, object)
    def _finish_task(self, task, result) -> None:
        self._tasks.discard(task)
        if self._closing or task.generation != self._generation:
            return
        try:
            with self._ops_lock:
                task.callback(result)
        except Exception as exc:  # noqa: BLE001
            log.warning('task completion failed: %s', exc)
            self.status.emit(f'Action failed: {exc}', 'danger')
            self.states_changed.emit()
