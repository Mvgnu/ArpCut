"""Root helper daemon — owns the privileged engine, serves the command protocol.

This component runs as **root** (installed as a macOS LaunchDaemon through the
native administrator prompt and ``launchctl`` — see ``install.py``). It listens on a Unix-domain socket and
executes the fixed command set from ``protocol.py`` against the real engine
(``Scanner`` / ``Killer`` / firewall / sniffer). The GUI is a thin, unprivileged
client (``client.py`` → ``RemoteEngine`` in ``remote.py``); it never opens a raw
socket or shells out itself.

The very same ``Engine`` class is what the GUI uses **in-process** when it already
has root (``LocalOps``). So one implementation serves both paths — the only
difference is whether the controller talks to it directly or over the socket.

``HelperServer.handle()`` is a pure function of ``(engine, request)`` so it is
unit-tested with a mock engine — no scapy, no root.
"""
from __future__ import annotations

import json
import logging
import os
import socket
import struct
import sys
import threading
from functools import wraps

from privilege.protocol import (
    COMMANDS, MAX_FRAME_BYTES, Request, Response, decode_request, encode, validate,
)

log = logging.getLogger(__name__)

_READ_ONLY = {
    'ping', 'status', 'get_devices', 'list_blocked_ports', 'list_blocked_ips',
    'active_host_blocks', 'active_dns_blocks', 'flows',
}
_SESSION_COMMANDS = set(COMMANDS) - _READ_ONLY - {'subscribe'}


def _peer_uid(conn) -> int:
    """Get credentials supplied by the kernel, never by the client request."""
    if sys.platform.startswith('linux'):
        creds = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                struct.calcsize('iII'))
        return struct.unpack('iII', creds)[1]
    if sys.platform == 'darwin':
        import ctypes
        libc = ctypes.CDLL(None, use_errno=True)
        uid, gid = ctypes.c_uint(), ctypes.c_uint()
        getpeereid = libc.getpeereid
        getpeereid.argtypes = [ctypes.c_int, ctypes.POINTER(ctypes.c_uint),
                              ctypes.POINTER(ctypes.c_uint)]
        getpeereid.restype = ctypes.c_int
        if getpeereid(conn.fileno(), ctypes.byref(uid), ctypes.byref(gid)) != 0:
            raise OSError(ctypes.get_errno(), 'could not verify helper peer')
        return uid.value
    raise OSError('peer credentials are not supported on this platform')


def _allowed_uid() -> int:
    """Installed daemons name their user; manual sudo runs preserve the caller."""
    from privilege.service import HELPER_UID_ENV
    value = os.environ.get(HELPER_UID_ENV, os.environ.get('SUDO_UID'))
    if value is not None:
        if not value.isascii() or not value.isdecimal():
            raise ValueError('invalid authorized helper UID')
        return int(value)
    if sys.platform == 'darwin':
        return os.stat('/dev/console').st_uid
    return 0  # fail closed; never fall back to world access


def _stateful(method):
    """Remember attempted privileged changes until a complete cleanup succeeds."""
    @wraps(method)
    def call(self, *args, **kwargs):
        self._state_dirty = True
        return method(self, *args, **kwargs)
    return call


class Engine:
    """The privileged engine: discovery, kill/restore, blocking, capture.

    Used in-process by a root GUI (``LocalOps``) or inside the root helper.
    Heavy imports are lazy so constructing it is cheap where scapy/root exist.
    """

    def __init__(self) -> None:
        from networking.scanner import Scanner
        from networking.killer import Killer
        from networking.sniffer import TrafficSniffer
        self.scanner = Scanner()
        self.scanner.init()
        self.scanner.add_me()
        self.scanner.add_router()
        self.killer = Killer(router=self.scanner.router)
        self.sniffer = TrafficSniffer()
        self.on_flows = None       # push hook: called with the flow list on updates
        self._last_flow_push = 0.0
        self._dns = None           # lazy DnsSpoofer (root-side DNS-name blocking)
        self._state_dirty = False

    def _device(self, mac: str, allow_protected: bool = False) -> dict:
        for d in self.scanner.devices:
            if d.get('mac') == mac:
                if not allow_protected and d.get('admin'):
                    raise ValueError('the local device and gateway cannot be controlled')
                return d
        raise ValueError(f'unknown device: {mac}')

    # -- discovery -----------------------------------------------------------

    def status(self) -> dict:
        from tools.utils_gui import is_admin
        return {
            'admin': is_admin(),
            'iface': self.scanner.iface.name,
            'my_ip': getattr(self.scanner, 'my_ip', None),
            'gateway_ip': self.scanner.router.get('ip') if self.scanner.router else None,
            'gateway_mac': self.scanner.router.get('mac') if self.scanner.router else None,
            'device_count': len(self.scanner.devices),
        }

    def set_iface(self, name: str) -> dict:
        from tools.utils import get_iface_by_name
        from tools.utils_gui import is_admin
        iface = get_iface_by_name(name)
        # A new unprivileged local engine still supports adapter selection and
        # ping discovery. It has nothing privileged to restore. Once any stateful
        # operation was attempted, require cleanup even if privileges were lost.
        if (is_admin() or getattr(self, '_state_dirty', False)) and not self.cleanup():
            raise RuntimeError('Could not restore the current interface; retry cleanup before switching.')
        self._dns = None  # its capture interface belongs to the old adapter
        self.scanner.iface = iface
        self.scanner.init()
        self.scanner.add_me()
        self.scanner.add_router()
        self.killer.iface = self.scanner.iface
        self.killer.router = self.scanner.router
        return self.status()

    def set_scan_params(self, count: int, threads: int) -> bool:
        err = validate('set_scan_params', {'count': count, 'threads': threads})
        if err:
            raise ValueError(err)
        self.scanner.device_count = count
        self.scanner.max_threads = threads
        return True

    def scan(self, scan_type: str) -> list:
        if scan_type == 'ping':
            if self.scanner.ping_scan():
                self.scanner.arping_cache()
        else:
            self.scanner.arp_scan()
        self.killer.router = self.scanner.router
        return self.scanner.devices

    def devices(self) -> list:
        return self.scanner.devices

    def probe(self, ip: str):
        hit = self.scanner.probe_ip(ip)
        return list(hit) if hit else None

    # -- kill / restore ------------------------------------------------------

    @_stateful
    def kill(self, mac: str) -> bool:
        return self.killer.kill(self._device(mac)) is not False

    @_stateful
    def unkill(self, mac: str) -> bool:
        # A scan may no longer see an offline device. Its previously owned
        # routing state still must be restored using the original address.
        device = (getattr(self.killer, '_restore_pending', {}).get(mac)
                  or self.killer.killed.get(mac)
                  or self._device(mac, allow_protected=True))
        return self.killer.unkill(device) is not False

    @_stateful
    def kill_all(self) -> bool:
        return self.killer.kill_all(self.scanner.devices) is not False

    @_stateful
    def unkill_all(self) -> bool:
        return self.killer.unkill_all() is not False

    @_stateful
    def one_way_kill(self, mac: str) -> bool:
        return self.killer.one_way_kill(self._device(mac)) is not False

    @_stateful
    def spoof(self, mac: str) -> bool:
        """Route the device through us (no drop) — base for monitor/lag/blocks."""
        return self.killer.spoof(self._device(mac)) is not False

    @_stateful
    def lag(self, mac: str, on: bool) -> bool:
        """Toggle a full kernel drop of a (spoofed) device for the lag switch."""
        return self.killer.lag(self._device(mac), bool(on)) is not False

    # -- firewall primitives -------------------------------------------------

    @_stateful
    def block_all_for(self, ip: str) -> bool:
        from tools.firewall import ensure_pf_enabled, install_anchor, block_all_for
        return bool(ensure_pf_enabled() and install_anchor()
                    and block_all_for(self.scanner.iface.name, ip))

    @_stateful
    def unblock_all_for(self, ip: str) -> bool:
        from tools.firewall import unblock_all_for
        return unblock_all_for(ip)

    @_stateful
    def block_ip(self, ip: str, direction: str = 'both') -> bool:
        from tools.firewall import block_ip
        return block_ip(self.scanner.iface.name, ip, direction)

    @_stateful
    def unblock_ip(self, ip: str) -> bool:
        from tools.firewall import unblock_ip
        return unblock_ip(ip)

    @_stateful
    def block_port(self, port: int, proto: str = 'tcp', direction: str = 'both',
                   target_ip=None) -> bool:
        # Windows + a victim IP: drop that port for the *victim's forwarded*
        # traffic via WinDivert. Do NOT add a netsh rule — that filters only THIS
        # host's port (blocks the attacker, does nothing for the victim).
        if sys.platform.startswith('win') and target_ip:
            return bool(self.killer.selective_block(target_ip, ports=[port], proto=proto))
        from tools.firewall import block_port
        return block_port(self.scanner.iface.name, port, proto, direction, target_ip)

    @_stateful
    def unblock_port(self, port: int, proto: str = 'tcp') -> bool:
        from tools.firewall import unblock_port
        ok = unblock_port(port, proto)
        if sys.platform.startswith('win'):
            self.killer.selective_unblock_port(port)
        return ok

    def list_blocked_ports(self) -> list:
        from tools.firewall import list_blocked_ports
        return [list(t) for t in list_blocked_ports()]

    def list_blocked_ips(self) -> list:
        from tools.firewall import list_blocked_ips
        return [list(t) for t in list_blocked_ips()]

    # -- host / domain blocking ----------------------------------------------

    @_stateful
    def block_host(self, target, iface=None) -> dict:
        r = self.killer.block_host(target, iface)
        return {'key': r.key, 'desired': sorted(r.desired), 'added': sorted(r.added),
                'removed': sorted(r.removed), 'failed': sorted(r.failed), 'ok': r.ok}

    @_stateful
    def unblock_host(self, key: str) -> bool:
        return self.killer.unblock_host(key)

    @_stateful
    def refresh_hosts(self) -> dict:
        results = self.killer.refresh_hosts()
        return {k: {'added': sorted(v.added), 'removed': sorted(v.removed)}
                for k, v in results.items()}

    def active_host_blocks(self) -> dict:
        return {k: sorted(v) for k, v in self.killer.active_host_blocks().items()}

    @_stateful
    def set_forwarding(self, enabled: bool) -> bool:
        from networking.killer import enable_ip_forwarding
        if not enabled:
            raise ValueError('Restoring system-wide forwarding is not supported; its previous state is not tracked.')
        return enable_ip_forwarding()

    # -- traffic capture (root-side sniffer, push-driven) --------------------

    @_stateful
    def start_sniff(self, ip: str) -> bool:
        self._last_flow_push = 0.0
        return self.sniffer.start(ip, self._scapy_iface(), on_update=self._flow_update) is not False

    def _scapy_iface(self) -> str:
        """The pcap/scapy interface id — guid on Windows, name elsewhere.

        Passing the friendly name to scapy fails to capture on Windows (npcap
        wants the ``\\Device\\NPF_{...}`` guid), which silently broke DNS blocking
        and traffic capture on this box.
        """
        ifc = self.scanner.iface
        return ifc.guid or ifc.name

    @_stateful
    def stop_sniff(self) -> bool:
        self.sniffer.stop()
        return True

    def flows(self) -> list:
        out = []
        # The traffic dialog displays the 200 largest flows. Bound the snapshot
        # here as well so a long capture never exceeds the IPC frame budget.
        flows = sorted(self.sniffer.get_flows().items(),
                       key=lambda item: item[1]['bytes'], reverse=True)[:200]
        for (dst, port, proto), st in flows:
            out.append({'dst': dst, 'port': int(port), 'proto': proto,
                        'bytes': int(st['bytes']), 'packets': int(st['packets'])})
        return out

    def _flow_update(self) -> None:
        """Sniffer per-packet callback → push flows, throttled to ~2 Hz."""
        if not self.on_flows:
            return
        import time
        now = time.time()
        if now - self._last_flow_push < 0.5:
            return
        self._last_flow_push = now
        try:
            self.on_flows(self.flows())
        except Exception:  # noqa: BLE001
            pass

    # -- DNS-name blocking (RPZ-style, for no-A-record names like PSN) --------

    @_stateful
    def dns_block(self, ip: str, domains: list) -> bool:
        if self._dns is None:
            from networking.dnsblock import DnsSpoofer
            self._dns = DnsSpoofer(self._scapy_iface())
        self._dns.block(ip, domains)
        return True

    @_stateful
    def dns_unblock(self, ip: str) -> bool:
        if self._dns:
            self._dns.unblock(ip)
        return True

    @_stateful
    def dns_unblock_name(self, ip: str, name: str) -> bool:
        if self._dns:
            self._dns.unblock_name(ip, name)
        return True

    def active_dns_blocks(self) -> dict:
        return self._dns.active() if self._dns else {}

    # -- teardown ------------------------------------------------------------

    def cleanup(self) -> bool:
        """Restore everything — the anti-orphan guarantee. Called on GUI session
        drop (quit/crash) and at GUI start (clears any hard-crash leftovers)."""
        failures = []

        def attempt(name, operation):
            try:
                if operation() is False:
                    failures.append(name)
            except Exception as exc:  # continue restoring independent resources
                failures.append(name)
                log.warning('%s cleanup failed: %s', name, exc)

        attempt('capture', self.sniffer.stop)
        if self._dns:
            attempt('DNS rules', self._dns.clear)
        attempt('devices', self.killer.unkill_all)
        attempt('host rules', self.killer.hostblock.clear)
        from tools.firewall import clear_all_rules
        attempt('firewall rules', clear_all_rules)
        if failures:
            self._state_dirty = True
            log.warning('cleanup incomplete: %s', ', '.join(failures))
        else:
            self._state_dirty = False
        return not failures


class HelperServer:
    """Validates + dispatches commands, pushes events to the GUI session, and
    restores everything when that session drops (the anti-orphan guarantee)."""

    def __init__(self, engine, allowed_uid: int | None = None) -> None:
        self.engine = engine
        self.allowed_uid = getattr(os, 'getuid', lambda: 0)() if allowed_uid is None else allowed_uid
        self._session = None
        self._closed = False
        self._engine_lock = threading.RLock()
        self._send_lock = threading.Lock()

    def handle(self, req: Request) -> Response:
        """Pure: validate a request and dispatch it, returning a Response."""
        err = validate(req.cmd, req.args)
        if err:
            return Response(ok=False, error=err)
        if req.cmd == 'ping':
            return Response(ok=True, result='pong')
        try:
            with self._engine_lock:
                return Response(ok=True, result=self._dispatch(req.cmd, req.args))
        except Exception as exc:  # engine errors become a clean error response
            log.debug('command %s failed: %s', req.cmd, exc)
            return Response(ok=False, error=str(exc))

    def _dispatch(self, cmd: str, args: dict):
        e = self.engine
        a = args
        # Every entry is a thunk so building the table never touches the engine
        # for a command that wasn't requested (keeps mock engines minimal).
        table = {
            'ping': lambda: 'pong',
            'status': lambda: e.status(),
            'set_iface': lambda: e.set_iface(a['iface']),
            'set_scan_params': lambda: e.set_scan_params(a['count'], a['threads']),
            'scan': lambda: e.scan(a['type']),
            'get_devices': lambda: e.devices(),
            'probe': lambda: e.probe(a['ip']),
            'kill': lambda: e.kill(a['mac']),
            'unkill': lambda: e.unkill(a['mac']),
            'kill_all': lambda: e.kill_all(),
            'unkill_all': lambda: e.unkill_all(),
            'one_way_kill': lambda: e.one_way_kill(a['mac']),
            'spoof': lambda: e.spoof(a['mac']),
            'lag': lambda: e.lag(a['mac'], a['on']),
            'dns_unblock_name': lambda: e.dns_unblock_name(a['ip'], a['name']),
            'block_all_for': lambda: e.block_all_for(a['ip']),
            'unblock_all_for': lambda: e.unblock_all_for(a['ip']),
            'block_ip': lambda: e.block_ip(a['ip'], a.get('direction', 'both')),
            'unblock_ip': lambda: e.unblock_ip(a['ip']),
            'block_port': lambda: e.block_port(a['port'], a.get('proto', 'tcp'),
                                               a.get('direction', 'both'), a.get('target_ip')),
            'unblock_port': lambda: e.unblock_port(a['port'], a.get('proto', 'tcp')),
            'list_blocked_ports': lambda: e.list_blocked_ports(),
            'list_blocked_ips': lambda: e.list_blocked_ips(),
            'block_host': lambda: e.block_host(a['target'], a.get('iface')),
            'unblock_host': lambda: e.unblock_host(a['key']),
            'refresh_hosts': lambda: e.refresh_hosts(),
            'active_host_blocks': lambda: e.active_host_blocks(),
            'set_forwarding': lambda: e.set_forwarding(a['enabled']),
            'start_sniff': lambda: e.start_sniff(a['ip']),
            'stop_sniff': lambda: e.stop_sniff(),
            'flows': lambda: e.flows(),
            'dns_block': lambda: e.dns_block(a['ip'], a['domains']),
            'dns_unblock': lambda: e.dns_unblock(a['ip']),
            'active_dns_blocks': lambda: e.active_dns_blocks(),
            'cleanup': lambda: e.cleanup(),
        }
        return table[cmd]()

    # -- push ----------------------------------------------------------------

    def _push(self, event: dict) -> None:
        """Send an unsolicited event frame only to the owning GUI session."""
        frame = (json.dumps(event) + '\n').encode('utf-8')
        with self._send_lock:
            conn = self._session
            if conn is not None:
                try:
                    conn.sendall(frame)
                except OSError:
                    pass

    def _send(self, conn, resp: Response) -> None:
        with self._send_lock:
            conn.sendall(encode(resp))

    # -- socket serving ------------------------------------------------------

    def _handle_connection_request(self, conn, req) -> Response:
        err = validate(req.cmd, req.args)
        if err:
            return Response(ok=False, error=err)
        if req.cmd == 'ping':
            return self.handle(req)  # health probes do not wait behind a scan
        with self._engine_lock:
            if self._closed:
                return Response(ok=False, error='helper is shutting down')
            if req.cmd == 'subscribe':
                if self._session is not None and self._session is not conn:
                    return Response(ok=False, error='another GUI session already owns the helper')
                self._session = conn
                self.engine.on_flows = lambda flows: self._push(
                    {'event': 'flows', 'flows': flows})
                conn.settimeout(None)
                return Response(ok=True, result='subscribed')
            if req.cmd in _SESSION_COMMANDS and self._session is not conn:
                return Response(ok=False, error='a subscribed GUI session is required')
            return self.handle(req)

    def serve_connection(self, conn) -> None:
        """Serve one connection. A ``subscribe`` marks it as the GUI session:
        it then receives pushed events and, when it drops, triggers a full
        restore so no device is left blocked after the app is gone."""
        buf = b''
        try:
            if _peer_uid(conn) not in (0, self.allowed_uid):
                self._send(conn, Response(ok=False, error='helper access denied'))
                return
            # A probe cannot hold an idle reader forever; subscribed GUIs can.
            conn.settimeout(5.0)
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if len(line) > MAX_FRAME_BYTES:
                        self._send(conn, Response(ok=False, error='request frame is too large'))
                        return
                    if not line.strip():
                        continue
                    try:
                        req = decode_request(line)
                    except Exception as exc:
                        self._send(conn, Response(ok=False, error=f'bad request: {exc}'))
                        continue
                    self._send(conn, self._handle_connection_request(conn, req))
                if len(buf) > MAX_FRAME_BYTES:
                    self._send(conn, Response(ok=False, error='request frame is too large'))
                    return
        except OSError as exc:  # peer closed / socket torn down — a normal end
            log.debug('helper connection closed: %s', exc)
        finally:
            with self._engine_lock:
                if self._session is conn:
                    self._session = None
                    self.engine.on_flows = None
                    try:
                        if self.engine.cleanup() is False:
                            log.warning('session dropped — cleanup incomplete')
                        else:
                            log.info('session dropped — restored all devices')
                    except Exception as exc:  # noqa: BLE001
                        log.warning('cleanup on disconnect failed: %s', exc)

    def serve_forever(self, sock) -> None:
        # One thread per connection so a held GUI session doesn't block probes.
        while True:
            conn, _ = sock.accept()
            threading.Thread(target=self._serve_and_close, args=(conn,), daemon=True).start()

    def _serve_and_close(self, conn) -> None:
        try:
            self.serve_connection(conn)
        finally:
            conn.close()

    def close(self) -> bool:
        """Stop accepting work and restore state on an orderly daemon shutdown."""
        with self._engine_lock:
            self._closed = True
            conn, self._session = self._session, None
            self.engine.on_flows = None
            if conn is not None:
                try:
                    conn.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            return self.engine.cleanup() is not False


def main() -> int:
    """Entry point for the root helper daemon."""
    if getattr(os, 'geteuid', lambda: 0)() != 0:
        print('arpcut helper must run as root', file=sys.stderr)
        return 1

    from privilege.service import SOCKET_PATH
    import signal

    if not SOCKET_PATH:
        print('the root helper is supported only on macOS and Linux', file=sys.stderr)
        return 1

    try:
        allowed_uid = _allowed_uid()
    except (OSError, ValueError) as exc:
        print(f'Cannot identify the authorized helper user: {exc}', file=sys.stderr)
        return 1
    engine = Engine()
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old_umask = os.umask(0o177)
    try:
        sock.bind(SOCKET_PATH)
    finally:
        os.umask(old_umask)
    os.chown(SOCKET_PATH, allowed_uid, 0)
    os.chmod(SOCKET_PATH, 0o600)
    sock.listen(5)
    log.info('arpcut helper listening on %s', SOCKET_PATH)
    server = HelperServer(engine, allowed_uid=allowed_uid)
    previous_sigterm = signal.getsignal(signal.SIGTERM)

    def terminate(signum, frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, terminate)
    try:
        server.serve_forever(sock)
    finally:
        sock.close()
        try:
            server.close()
        finally:
            signal.signal(signal.SIGTERM, previous_sigterm)
            if os.path.exists(SOCKET_PATH):
                os.unlink(SOCKET_PATH)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
