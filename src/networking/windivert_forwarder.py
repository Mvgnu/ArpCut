"""Windows kernel-speed selective forwarder using WinDivert.

On macOS/Linux, ARP-MITM'd traffic is forwarded by the kernel the moment
``enable_ip_forwarding()`` flips the routing sysctl, and pf/nft drop the
filtered flows — no Python touches the packet hot path. Windows has no sysctl
equivalent for L2-diverted traffic, which is why the old user-space scapy
``MitmForwarder`` had to rewrite every frame in Python (the slow path). This
module closes that gap with WinDivert (the kernel packet-diversion driver that
ships with the ``pydivert`` dependency):

* :func:`enable_windows_routing` sets the ``IPEnableRouter`` registry flag — the
  Windows analogue of the forwarding sysctl — so the stack routes the diverted
  packets at native speed.
* :class:`WinDivertForwarder` opens a WinDivert handle on the
  ``NETWORK_FORWARD`` layer whose filter matches **only the flows we want to
  drop**.  In the default (``Flag.DROP``) mode the driver discards those packets
  in the kernel and everything else is forwarded untouched — there is no Python
  in the allowed-traffic hot path.  A counting mode (recv loop) is available when
  the traffic monitor wants live drop stats.

So a Windows one-way cut / port / host block becomes: ARP-poison to steer the
traffic through us → the kernel forwards it at native speed → WinDivert drops
exactly the filtered flows.  This mirrors the mac/linux ``sysctl`` + ``pf``/``nft``
design and replaces the broken ``netsh`` selective path (which filtered the
*attacker's* host, not the victim's forwarded traffic).

The ``pydivert`` import is guarded so this module loads on every platform; the
engine only instantiates the forwarder on Windows and only when
:data:`WINDIVERT_AVAILABLE` is true.
"""
from __future__ import annotations

import logging
import sys
import threading
from typing import Optional

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Guarded pydivert / WinDivert import
# ---------------------------------------------------------------------------
try:  # pragma: no cover - import guard is platform dependent
    from pydivert import WinDivert, Layer, Flag  # type: ignore

    WINDIVERT_AVAILABLE: bool = sys.platform.startswith('win')
except Exception as _e:  # noqa: BLE001 - any import failure means "not available"
    WinDivert = None  # type: ignore
    Layer = None  # type: ignore
    Flag = None  # type: ignore
    WINDIVERT_AVAILABLE = False
    log.debug('pydivert/WinDivert unavailable: %s', _e)


# ---------------------------------------------------------------------------
# Windows kernel routing (the IPEnableRouter analogue of the forwarding sysctl)
# ---------------------------------------------------------------------------
_TCPIP_PARAMS = r'SYSTEM\CurrentControlSet\Services\Tcpip\Parameters'


def windows_routing_enabled() -> bool:
    """Return True if the ``IPEnableRouter`` registry flag is currently set."""
    if not sys.platform.startswith('win'):
        return False
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _TCPIP_PARAMS) as key:
            val, _ = winreg.QueryValueEx(key, 'IPEnableRouter')
            return int(val) == 1
    except (OSError, ValueError):
        return False


def enable_windows_routing() -> bool:
    """Enable Windows IP routing so ARP-MITM'd traffic is forwarded in-kernel.

    Sets ``HKLM\\...\\Tcpip\\Parameters\\IPEnableRouter = 1`` (needs admin) and
    best-effort nudges the Routing/RemoteAccess service so the change takes
    effect without a reboot.  Returns True when the flag is set.

    This is the Windows counterpart to ``sysctl net.ipv4.ip_forward=1`` /
    ``net.inet.ip.forwarding=1``.  A full guarantee that routing is live may
    still require the ``RemoteAccess`` service (or a reboot) on some SKUs; the
    WinDivert forward handle keeps working regardless, and callers treat a
    ``False`` return as "kernel routing not available — fall back / warn".
    """
    if not sys.platform.startswith('win'):
        return False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _TCPIP_PARAMS, 0,
            winreg.KEY_SET_VALUE | winreg.KEY_QUERY_VALUE,
        ) as key:
            winreg.SetValueEx(key, 'IPEnableRouter', 0, winreg.REG_DWORD, 1)
    except (OSError, PermissionError) as e:
        log.warning('Could not set IPEnableRouter (admin required): %s', e)
        return False
    _refresh_routing_service()
    log.debug('IPEnableRouter set to 1')
    return True


def disable_windows_routing() -> bool:
    """Reset ``IPEnableRouter`` to 0 (best effort). Returns True on success."""
    if not sys.platform.startswith('win'):
        return False
    try:
        import winreg
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, _TCPIP_PARAMS, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, 'IPEnableRouter', 0, winreg.REG_DWORD, 0)
        return True
    except (OSError, PermissionError) as e:
        log.debug('Could not reset IPEnableRouter: %s', e)
        return False


def _refresh_routing_service() -> None:
    """Best-effort: apply the routing table change without a reboot.

    ``RemoteAccess`` is the service that actually programs the routing flag on
    client SKUs.  We only try to (re)start it if it exists; failures are
    non-fatal because the WinDivert forward handle does not depend on it.
    """
    import subprocess
    no_window = 0x08000000  # CREATE_NO_WINDOW — don't flash a console window
    try:
        subprocess.run(['sc', 'config', 'RemoteAccess', 'start=', 'demand'],
                       capture_output=True, check=False, timeout=10,
                       creationflags=no_window)
        subprocess.run(['sc', 'start', 'RemoteAccess'],
                       capture_output=True, check=False, timeout=15,
                       creationflags=no_window)
    except (OSError, subprocess.SubprocessError) as e:
        log.debug('RemoteAccess service refresh skipped: %s', e)


# ---------------------------------------------------------------------------
# Filter construction (validated by tests via WinDivert.check_filter)
# ---------------------------------------------------------------------------
def build_forward_filter(
    victim_ip: str,
    *,
    drop_from_victim: bool = True,
    drop_to_victim: bool = False,
    dst_ips: Optional[list[str]] = None,
    ports: Optional[list[int]] = None,
    proto: Optional[str] = None,
) -> str:
    """Build a WinDivert ``NETWORK_FORWARD`` filter matching the flows to DROP.

    The filter deliberately matches *only* the traffic we want to discard, so
    everything else stays on the kernel forward fast-path.  Direction is
    expressed with ``ip.SrcAddr`` / ``ip.DstAddr`` because the ``inbound`` /
    ``outbound`` tokens are not valid on the ``NETWORK_FORWARD`` layer.

    - ``drop_from_victim`` matches ``ip.SrcAddr == victim`` (victim → internet).
    - ``drop_to_victim`` matches ``ip.DstAddr == victim`` (internet → victim).
    - ``dst_ips`` narrows the drop to specific destinations (host blocking).
    - ``ports`` + ``proto`` narrow it to specific ports (port blocking).

    Raises ``ValueError`` if neither direction is selected.
    """
    dirs: list[str] = []
    if drop_from_victim:
        dirs.append(f'ip.SrcAddr == {victim_ip}')
    if drop_to_victim:
        dirs.append(f'ip.DstAddr == {victim_ip}')
    if not dirs:
        raise ValueError('build_forward_filter: at least one direction required')

    clauses: list[str] = ['ip']
    # victim direction(s)
    clauses.append(dirs[0] if len(dirs) == 1 else '(' + ' or '.join(dirs) + ')')

    if dst_ips:
        if len(dst_ips) == 1:
            clauses.append(f'ip.DstAddr == {dst_ips[0]}')
        else:
            clauses.append('(' + ' or '.join(f'ip.DstAddr == {d}' for d in dst_ips) + ')')

    proto_kw = (proto or '').lower()
    if ports:
        pk = proto_kw if proto_kw in ('tcp', 'udp') else 'tcp'
        if len(ports) == 1:
            clauses.append(f'{pk}.DstPort == {ports[0]}')
        else:
            clauses.append('(' + ' or '.join(f'{pk}.DstPort == {p}' for p in ports) + ')')
    elif proto_kw in ('tcp', 'udp'):
        clauses.append(proto_kw)

    return ' and '.join(clauses)


def validate_filter(filter_str: str) -> tuple[bool, str]:
    """Validate a filter against the real WinDivert engine (no driver load).

    Returns ``(ok, message)``.  Works without administrator rights because it
    only compiles the filter string in the DLL.  Returns ``(True, '')`` when
    WinDivert is unavailable (nothing to validate against).
    """
    if not WINDIVERT_AVAILABLE or WinDivert is None:
        return True, ''
    res, pos, msg = WinDivert.check_filter(filter_str, Layer.NETWORK_FORWARD)
    return bool(res), ('' if res else f'{msg} @ {pos}')


# ---------------------------------------------------------------------------
# The forwarder
# ---------------------------------------------------------------------------
class WinDivertForwarder:
    """Kernel-level selective forwarder for a single victim on Windows.

    Public surface intentionally mirrors :class:`networking.forwarder.MitmForwarder`
    (``running``, ``start``/``stop``, ``get_stats``) so callers can pick the
    kernel path on Windows and the user-space path elsewhere without branching
    on the object's shape.

    Two modes:

    * **drop mode** (default, ``count=False``) — opens the handle with
      ``Flag.DROP``; the driver discards matched packets in the kernel with zero
      Python per-packet work.  Stats report ``packets_dropped`` as unknown (-1).
    * **count mode** (``count=True``) — a recv loop tallies each dropped packet
      for the traffic monitor.  Slightly slower but still far cheaper than the
      scapy forwarder because only the *dropped* subset is diverted.
    """

    def __init__(self, debug: bool = False) -> None:
        self.running: bool = False
        self.victim_ip: Optional[str] = None
        self.drop_from_victim: bool = False
        self.drop_to_victim: bool = False
        self._filter: Optional[str] = None
        self._handle: object = None
        self._thread: Optional[threading.Thread] = None
        self._count_mode: bool = False
        self._pkt_count: int = 0
        self._drop_count: int = 0
        self._debug: bool = debug
        self._lock = threading.Lock()

    def start(
        self,
        victim_ip: str,
        *,
        drop_from_victim: bool = True,
        drop_to_victim: bool = False,
        dst_ips: Optional[list[str]] = None,
        ports: Optional[list[int]] = None,
        proto: Optional[str] = None,
        count: bool = False,
    ) -> bool:
        """Start dropping the selected victim flows in-kernel. Returns success.

        Allowed traffic is not diverted — it rides the kernel forward path
        enabled by :func:`enable_windows_routing`.  Returns ``False`` (and logs)
        when WinDivert is unavailable, the filter is invalid, or the driver
        cannot be opened (e.g. not elevated).
        """
        self.stop()
        if not WINDIVERT_AVAILABLE or WinDivert is None:
            log.warning('WinDivert unavailable; cannot start kernel forwarder')
            return False

        try:
            self._filter = build_forward_filter(
                victim_ip,
                drop_from_victim=drop_from_victim,
                drop_to_victim=drop_to_victim,
                dst_ips=dst_ips,
                ports=ports,
                proto=proto,
            )
        except ValueError as e:
            log.error('Invalid forwarder configuration: %s', e)
            return False

        ok, msg = validate_filter(self._filter)
        if not ok:
            log.error('WinDivert rejected filter %r: %s', self._filter, msg)
            return False

        self.victim_ip = victim_ip
        self.drop_from_victim = drop_from_victim
        self.drop_to_victim = drop_to_victim
        self._count_mode = count
        self._pkt_count = 0
        self._drop_count = 0

        flags = Flag.RECV_ONLY if count else Flag.DROP
        try:
            self._handle = WinDivert(self._filter, layer=Layer.NETWORK_FORWARD, flags=flags)
            self._handle.open()
        except Exception as e:  # noqa: BLE001 - surface driver/permission errors as a clean False
            log.warning('Failed to open WinDivert handle (%s): %s', self._filter, e)
            self._handle = None
            return False

        self.running = True
        log.debug('WinDivert forwarder started: filter=%r count=%s', self._filter, count)
        if count:
            self._thread = threading.Thread(target=self._drain, name='windivert-fwd', daemon=True)
            self._thread.start()
        return True

    def _drain(self) -> None:
        """Count-mode loop: receive matched (to-drop) packets and discard them.

        Not re-injecting a received packet is what drops it.  Only the filtered
        subset reaches here; the allowed traffic never leaves the kernel.
        """
        handle = self._handle
        while self.running and handle is not None:
            try:
                handle.recv()  # matched == to-drop; we simply never send() it
            except Exception as e:  # noqa: BLE001 - handle closed / shutdown races
                if self.running:
                    log.debug('WinDivert recv ended: %s', e)
                break
            with self._lock:
                self._pkt_count += 1
                self._drop_count += 1

    def stop(self) -> None:
        """Stop dropping and close the handle (traffic returns to normal)."""
        self.running = False
        handle, self._handle = self._handle, None
        if handle is not None:
            try:
                handle.close()
            except Exception as e:  # noqa: BLE001
                log.debug('WinDivert close error (ignoring): %s', e)
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def get_stats(self) -> dict[str, object]:
        """Return current statistics (mirrors MitmForwarder.get_stats)."""
        with self._lock:
            return {
                'backend': 'windivert',
                'running': self.running,
                'filter': self._filter,
                'packets_seen': self._pkt_count if self._count_mode else -1,
                'packets_dropped': self._drop_count if self._count_mode else -1,
                'packets_forwarded': -1,  # forwarded in-kernel; not counted here
                'drop_from_victim': self.drop_from_victim,
                'drop_to_victim': self.drop_to_victim,
            }

    def __del__(self) -> None:  # pragma: no cover - best effort finaliser
        try:
            self.stop()
        except Exception:  # noqa: BLE001
            pass


def self_check() -> dict[str, object]:
    """Report WinDivert readiness for diagnostics / privilege banner.

    Attempts to open a no-op handle (``false`` filter) — success proves the
    driver loads and we are elevated.  Never raises.
    """
    info: dict[str, object] = {
        'available': WINDIVERT_AVAILABLE,
        'routing_enabled': windows_routing_enabled(),
        'driver_ok': False,
        'error': '',
    }
    if not WINDIVERT_AVAILABLE or WinDivert is None:
        info['error'] = 'pydivert/WinDivert not available on this platform'
        return info
    try:
        h = WinDivert('false', layer=Layer.NETWORK_FORWARD, flags=Flag.RECV_ONLY)
        h.open()
        h.close()
        info['driver_ok'] = True
    except Exception as e:  # noqa: BLE001 - typically PermissionError when not elevated
        info['error'] = f'{type(e).__name__}: {e}'
    return info
