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
from typing import Optional

from PySide6.QtCore import QObject, QRunnable, QThread, QThreadPool, QTimer, Signal

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
            return fn(self, *a, **k)
        except Exception as exc:  # noqa: BLE001
            log.warning('%s failed: %s', fn.__name__, exc)
            self.status.emit('Action failed — is the helper still running?', 'danger')
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
    done = Signal(object)


class _Task(QRunnable):
    def __init__(self, fn) -> None:
        super().__init__()
        self._fn = fn
        self.signals = _TaskSignals()

    def run(self) -> None:
        try:
            result = self._fn()
        except Exception as exc:  # noqa: BLE001
            result = exc
        self.signals.done.emit(result)


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

        self._pool = QThreadPool.globalInstance()
        self._tasks: set[_Task] = set()
        self._scan = ScanWorker()
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
        self.flows_changed.emit(flows or [])

    def start(self) -> None:
        # Clear anything a previous hard-crash could have left blocked.
        self._safe(self.ops.cleanup)
        self.ops.set_scan_params(int(get_settings('count') or 255),
                                 int(get_settings('threads') or 12))
        saved = get_settings('iface')
        try:
            if saved:
                self.ops.set_iface(saved)
            st = self.ops.status()
            self._iface = st.get('iface', 'NULL')
            self._admin = bool(st.get('admin'))
            self._devices = self.ops.devices() or []
            self._apply_nicknames()
        except Exception as exc:  # noqa: BLE001
            self.status.emit(f'Engine init failed: {exc}', 'danger')
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
        self.stop_lag()
        self._safe(self.ops.cleanup)          # restore everything now…
        if hasattr(self.ops, 'close'):
            self._safe(self.ops.close)        # …and drop the session (helper also
                                              # auto-restores on the disconnect)
        self._cut.clear()
        self.one_way_kills.clear()
        self._monitoring.clear()
        self._spoofed.clear()
        self._dns_blocks.clear()
        self._dns_spoofed.clear()

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
        if self._scan.isRunning():
            return
        self.stop_lag()
        kind = 'ping' if scan_type else 'arp'
        self._scan._fn = lambda: self.ops.scan(kind)
        self.scan_started.emit(scan_type)
        self.status.emit('Scanning your network…' if scan_type == 0
                         else 'Deep-scanning (ping sweep)…', 'accent')
        self._scan.start()

    def _on_scan_done(self, ok: bool) -> None:
        if self._scan.error:
            self.status.emit(f'Scan failed: {self._scan.error}', 'danger')
        else:
            self._devices = self._scan.result or []
            self._apply_nicknames()
            self._reapply_state()
            n = max(0, len(self._devices) - 2)
            self.status.emit(f'Found {n} device{"s" * (n != 1)} on the network.', 'good')
        self.devices_changed.emit(self._devices)
        self.scan_finished.emit(ok)

    def _reapply_state(self) -> None:
        """Re-assert active cuts/one-way against the fresh device list (IPs may
        have changed) and, on the first scan, any remembered cuts."""
        present = {d['mac']: d for d in self._devices if not d['admin']}
        cut_macs = set(self._cut) | self._remembered_once()
        oneway_macs = set(self.one_way_kills)
        for ip in list(self._cut.values()):
            self._safe(lambda ip=ip: self.ops.unblock_all_for(ip))
        self._cut.clear()
        self.one_way_kills.clear()
        for mac in cut_macs:
            dev = present.get(mac)
            if dev:
                self._do_cut(mac, dev['ip'])
        for mac in oneway_macs:
            if mac in present:
                self._safe(lambda mac=mac: self.ops.one_way_kill(mac))
                self._spoofed.add(mac)
                self.one_way_kills.add(mac)
        self._persist_killed()

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
            self.ops.spoof(mac)
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
            self._safe(lambda: self.ops.stop_sniff())
            self._monitoring.discard(mac)
            self._monitor_spoofed.discard(mac)
        if mac in self._dns_blocks:
            di = self._dns_blocks.pop(mac, ip)
            if di:
                self._safe(lambda: self.ops.dns_unblock(di))
            self._dns_spoofed.discard(mac)
        for port, proto in list(self._port_blocks.get(mac, set())):
            self._safe(lambda p=port, pr=proto: self.ops.unblock_port(p, pr))
        self._port_blocks.pop(mac, None)
        if mac in self._cut:
            if ip:
                self._safe(lambda: self.ops.unblock_all_for(ip))
            self._cut.pop(mac, None)
        self.one_way_kills.discard(mac)

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
            self.ops.spoof(mac)
            self._spoofed.add(mac)
            self._explicit_spoof.add(mac)
            self.status.emit(f'Routing {device["ip"]} through this PC — blocks can now apply', 'accent')
        self.states_changed.emit()

    def _maybe_unspoof(self, mac: str) -> None:
        """Drop the ARP spoof only if nothing still needs the device routed."""
        if (mac in self._cut or mac in self.one_way_kills or mac in self._monitoring
                or mac in self._dns_blocks or self.lag_active_for(mac)
                or mac in self._explicit_spoof or self._port_blocks.get(mac)):
            return
        self._safe(lambda: self.ops.unkill(mac))
        self._spoofed.discard(mac)

    def _do_cut(self, mac: str, ip: str) -> None:
        if mac not in self._spoofed:
            self.ops.kill(mac)
            self._spoofed.add(mac)
        if self.ops.block_all_for(ip):
            self._cut[mac] = ip

    @guarded
    def toggle_cut(self, mac: str) -> None:
        """Cut a device off the internet reliably: ARP redirect + firewall drop
        (a real cut even while kernel forwarding is on)."""
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        ip = device['ip']
        if mac in self._cut:
            self.ops.unblock_all_for(ip)
            self._cut.pop(mac, None)
            self.one_way_kills.discard(mac)
            if mac not in self._monitoring:
                self.ops.unkill(mac)
                self._spoofed.discard(mac)
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
        self.stop_lag()
        # cleanup() is the comprehensive teardown: unkill all + stop sniffer/DNS +
        # clear every firewall rule (port/ip/host) and WinDivert drop. So "Restore
        # all" clears BLOCKS too, not just cuts.
        self._safe(self.ops.cleanup)
        self._cut.clear()
        self.one_way_kills.clear()
        self._spoofed.clear()
        self._explicit_spoof.clear()
        self._monitoring.clear()
        self._monitor_spoofed.clear()
        self._dns_blocks.clear()
        self._dns_spoofed.clear()
        self._port_blocks.clear()
        self._persist_killed()
        self._emit_hosts()
        self.status.emit('Restored all devices and cleared every block.', 'good')
        self.states_changed.emit()

    @guarded
    def toggle_one_way(self, mac: str) -> None:
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        if mac in self.one_way_kills:
            self.ops.unkill(mac)
            self._spoofed.discard(mac)
            self.one_way_kills.discard(mac)
            self.status.emit(f'One-way kill off for {device["ip"]}', 'good')
        else:
            self.ops.one_way_kill(mac)
            self._spoofed.add(mac)
            self.one_way_kills.add(mac)
            self.status.emit(f'One-way kill on for {device["ip"]}', 'warn')
        self.states_changed.emit()

    # -- lag switch ----------------------------------------------------------

    def start_lag(self, mac: str, block_ms: int, release_ms: int, direction: str) -> None:
        device = self.device_by_mac(mac)
        if not device or device['admin']:
            return
        self.stop_lag()
        self._lag_mac = mac
        self._lag_block_ms, self._lag_release_ms, self._lag_dir = block_ms, release_ms, direction
        self.status.emit(f'Lag switch on: {block_ms}ms lag / {release_ms}ms clear', 'warn')
        self._lag_cycle()
        self._lag_timer.start(block_ms + release_ms)
        self.states_changed.emit()

    @guarded
    def _lag_cycle(self) -> None:
        device = self.device_by_mac(self._lag_mac) if self._lag_mac else None
        if not device:
            self.stop_lag()
            return
        mac = device['mac']
        self._ensure_spoofed(mac)            # route through us (no permanent drop)
        # Drop everything for one window, then release — a real kernel lag/loss.
        self.ops.lag(mac, True)
        QTimer.singleShot(self._lag_block_ms,
                          lambda m=mac: self._safe(lambda: self.ops.lag(m, False)))

    @guarded
    def stop_lag(self) -> None:
        if not self._lag_timer.isActive() and self._lag_mac is None:
            return
        self._lag_timer.stop()
        mac = self._lag_mac
        if mac:
            self._safe(lambda: self.ops.lag(mac, False))
            self._maybe_unspoof(mac)
        self._lag_mac = None
        self.status.emit('Lag switch off.', 'good')
        self.states_changed.emit()

    def lag_active_for(self, mac: str) -> bool:
        return self._lag_timer.isActive() and self._lag_mac == mac

    # -- host / port blocking (async — resolves DNS off-thread) --------------

    def block_host(self, target, device_mac: Optional[str] = None) -> None:
        # Route the configured device through us so the destination block actually
        # bites for it (host blocks apply to every spoofed device).
        if device_mac:
            self._ensure_spoofed(device_mac)
            self.states_changed.emit()
        self.status.emit(f'Blocking {target}…', 'accent')
        self._run(lambda: self.ops.block_host(target), self._on_host_block)

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
        self._run(lambda: self.ops.unblock_host(key), lambda _: self._emit_hosts())

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

    def block_port(self, port: int, proto: str = 'tcp', direction: str = 'both',
                   target_ip: Optional[str] = None) -> None:
        # A device-scoped port block only bites if that device is routed through
        # us — so auto-spoof it (the block ceases if you later stop spoofing).
        # Run the (blocking) firewall/WinDivert call off the GUI thread so the
        # window never freezes while netsh works.
        mac = None
        if target_ip:
            dev = next((d for d in self._devices if d['ip'] == target_ip and not d['admin']), None)
            if dev:
                mac = dev['mac']
                self._ensure_spoofed(mac)
                # Track optimistically so state (spoof/port list) is consistent
                # immediately; the async call rolls it back if the block fails.
                self._port_blocks.setdefault(mac, set()).add((port, proto))
        self.states_changed.emit()
        self.status.emit(f'Blocking port {port}/{proto}…', 'accent')

        def _done(res):
            ok = bool(res) and not isinstance(res, Exception)
            if not ok and mac:
                self._port_blocks.get(mac, set()).discard((port, proto))
                self._maybe_unspoof(mac)
            self.status.emit(f'Blocked port {port}/{proto}' if ok
                             else 'Port block failed (need root / helper?)',
                             'danger' if ok else 'warn')
            self.states_changed.emit()

        self._run(lambda: self.ops.block_port(port, proto, direction, target_ip), _done)

    def unblock_port(self, port: int, proto: str = 'tcp') -> None:
        self._safe(lambda: self.ops.unblock_port(port, proto))
        for mac in list(self._port_blocks):
            self._port_blocks[mac].discard((port, proto))
            if not self._port_blocks[mac]:
                self._port_blocks.pop(mac, None)
                self._maybe_unspoof(mac)
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

    def unblock_ip(self, ip: str) -> None:
        self._safe(lambda: self.ops.unblock_all_for(ip))
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
        if not device or device['admin']:
            return False
        was_spoofed = mac in self._spoofed
        self._ensure_spoofed(mac)          # route through us (no drop) so we can see it
        if not was_spoofed:
            self._monitor_spoofed.add(mac)
        self._monitoring.add(mac)
        self.ops.start_sniff(device['ip'])
        self.status.emit(
            f'Capturing {device["ip"]} — routed through this Mac.' if self._privileged
            else 'Set Up Access to capture traffic.',
            'accent' if self._privileged else 'warn')
        self.states_changed.emit()
        return self._privileged

    @guarded
    def stop_monitor(self, mac: str) -> None:
        self.ops.stop_sniff()
        self._monitoring.discard(mac)
        self._monitor_spoofed.discard(mac)
        self._maybe_unspoof(mac)
        self.states_changed.emit()

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
        if not was_spoofed:
            self._dns_spoofed.add(mac)
        self.ops.dns_block(ip, list(domains))
        self._dns_blocks[mac] = ip
        self.status.emit(f'DNS block active for {ip} (NXDOMAIN on blocked names)', 'danger')
        self.states_changed.emit()

    @guarded
    def dns_unblock(self, mac: str) -> None:
        device = self.device_by_mac(mac)
        ip = self._dns_blocks.pop(mac, device['ip'] if device else None)
        if ip:
            self.ops.dns_unblock(ip)
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

    def active_dns_blocks(self) -> dict:
        try:
            return self.ops.active_dns_blocks() or {}
        except Exception:  # noqa: BLE001
            return {}

    # -- settings ------------------------------------------------------------

    @guarded
    def set_iface(self, name: str) -> None:
        self.stop_lag()
        self.ops.unkill_all()
        self._cut.clear()
        self.one_way_kills.clear()
        self._spoofed.clear()
        st = self.ops.set_iface(name)
        self._iface = st.get('iface', name) if isinstance(st, dict) else name
        set_settings('iface', name)
        self._devices = self.ops.devices() or []
        self._apply_nicknames()
        self._emit_privilege()
        self.devices_changed.emit(self._devices)

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

    def _safe(self, fn):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            log.debug('op failed: %s', exc)
            return None

    def _run(self, fn, callback) -> None:
        task = _Task(fn)

        def _finish(result, t=task):
            self._tasks.discard(t)
            callback(result)

        task.signals.done.connect(_finish)
        self._tasks.add(task)
        self._pool.start(task)
