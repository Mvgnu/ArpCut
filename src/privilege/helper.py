"""Root helper daemon — owns the privileged engine, serves the command protocol.

This is the component that runs as **root** (installed as a LaunchDaemon via
``SMAppService`` — see ``service.py``). It listens on a Unix-domain socket and
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
import sys
import threading

from privilege.protocol import (
    Request, Response, decode_request, encode, validate,
)

log = logging.getLogger(__name__)

_MUTATING = {
    'set_iface', 'scan', 'kill', 'unkill', 'kill_all', 'unkill_all', 'one_way_kill',
    'spoof', 'lag',
    'block_all_for', 'unblock_all_for', 'block_ip', 'unblock_ip', 'block_port',
    'unblock_port', 'block_host', 'unblock_host', 'refresh_hosts', 'cleanup',
    'dns_block', 'dns_unblock',
}


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

    def _device(self, mac: str) -> dict:
        for d in self.scanner.devices:
            if d.get('mac') == mac:
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
        self.scanner.iface = get_iface_by_name(name)
        self.scanner.init()
        self.scanner.add_me()
        self.scanner.add_router()
        self.killer.iface = self.scanner.iface
        self.killer.router = self.scanner.router
        return self.status()

    def set_scan_params(self, count: int, threads: int) -> bool:
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

    def kill(self, mac: str) -> bool:
        self.killer.kill(self._device(mac))
        return True

    def unkill(self, mac: str) -> bool:
        self.killer.unkill(self._device(mac))
        return True

    def kill_all(self) -> bool:
        self.killer.kill_all(self.scanner.devices)
        return True

    def unkill_all(self) -> bool:
        self.killer.unkill_all()
        return True

    def one_way_kill(self, mac: str) -> bool:
        self.killer.one_way_kill(self._device(mac))
        return True

    def spoof(self, mac: str) -> bool:
        """Route the device through us (no drop) — base for monitor/lag/blocks."""
        self.killer.spoof(self._device(mac))
        return True

    def lag(self, mac: str, on: bool) -> bool:
        """Toggle a full kernel drop of a (spoofed) device for the lag switch."""
        self.killer.lag(self._device(mac), bool(on))
        return True

    # -- firewall primitives -------------------------------------------------

    def block_all_for(self, ip: str) -> bool:
        from tools.firewall import ensure_pf_enabled, install_anchor, block_all_for
        return bool(ensure_pf_enabled() and install_anchor()
                    and block_all_for(self.scanner.iface.name, ip))

    def unblock_all_for(self, ip: str) -> bool:
        from tools.firewall import unblock_all_for
        unblock_all_for(ip)
        return True

    def block_ip(self, ip: str, direction: str = 'both') -> bool:
        from tools.firewall import block_ip
        return block_ip(self.scanner.iface.name, ip, direction)

    def unblock_ip(self, ip: str) -> bool:
        from tools.firewall import unblock_ip
        return unblock_ip(ip)

    def block_port(self, port: int, proto: str = 'tcp', direction: str = 'both',
                   target_ip=None) -> bool:
        # Windows + a victim IP: drop that port for the *victim's forwarded*
        # traffic via WinDivert. Do NOT add a netsh rule — that filters only THIS
        # host's port (blocks the attacker, does nothing for the victim).
        if sys.platform.startswith('win') and target_ip:
            return bool(self.killer.selective_block(target_ip, ports=[port], proto=proto))
        from tools.firewall import block_port
        return block_port(self.scanner.iface.name, port, proto, direction, target_ip)

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

    def block_host(self, target, iface=None) -> dict:
        r = self.killer.block_host(target, iface)
        return {'key': r.key, 'desired': sorted(r.desired), 'added': sorted(r.added),
                'removed': sorted(r.removed), 'failed': sorted(r.failed), 'ok': r.ok}

    def unblock_host(self, key: str) -> bool:
        return self.killer.unblock_host(key)

    def refresh_hosts(self) -> dict:
        results = self.killer.refresh_hosts()
        return {k: {'added': sorted(v.added), 'removed': sorted(v.removed)}
                for k, v in results.items()}

    def active_host_blocks(self) -> dict:
        return {k: sorted(v) for k, v in self.killer.active_host_blocks().items()}

    def set_forwarding(self, enabled: bool) -> bool:
        from networking.killer import enable_ip_forwarding
        return enable_ip_forwarding() if enabled else True

    # -- traffic capture (root-side sniffer, push-driven) --------------------

    def start_sniff(self, ip: str) -> bool:
        self._last_flow_push = 0.0
        self.sniffer.start(ip, self._scapy_iface(), on_update=self._flow_update)
        return True

    def _scapy_iface(self) -> str:
        """The pcap/scapy interface id — guid on Windows, name elsewhere.

        Passing the friendly name to scapy fails to capture on Windows (npcap
        wants the ``\\Device\\NPF_{...}`` guid), which silently broke DNS blocking
        and traffic capture on this box.
        """
        ifc = self.scanner.iface
        return ifc.guid or ifc.name

    def stop_sniff(self) -> bool:
        self.sniffer.stop()
        return True

    def flows(self) -> list:
        out = []
        for (dst, port, proto), st in self.sniffer.get_flows().items():
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

    def dns_block(self, ip: str, domains: list) -> bool:
        if self._dns is None:
            from networking.dnsblock import DnsSpoofer
            self._dns = DnsSpoofer(self._scapy_iface())
        self._dns.block(ip, domains)
        return True

    def dns_unblock(self, ip: str) -> bool:
        if self._dns:
            self._dns.unblock(ip)
        return True

    def active_dns_blocks(self) -> dict:
        return self._dns.active() if self._dns else {}

    # -- teardown ------------------------------------------------------------

    def cleanup(self) -> bool:
        """Restore everything — the anti-orphan guarantee. Called on GUI session
        drop (quit/crash) and at GUI start (clears any hard-crash leftovers)."""
        try:
            self.sniffer.stop()
        except Exception:  # noqa: BLE001
            pass
        if self._dns:
            try:
                self._dns.stop()
            except Exception:  # noqa: BLE001
                pass
        try:
            self.killer.unkill_all()
        except Exception:  # noqa: BLE001
            pass
        from tools.firewall import (
            list_blocked_ips, unblock_ip, list_blocked_ports, unblock_port,
            clear_all_port_blocks, clear_anchor,
        )
        for ip, _ in list_blocked_ips():
            unblock_ip(ip)
        for port, proto, _ in list_blocked_ports():
            unblock_port(port, proto)
        clear_all_port_blocks()
        clear_anchor()
        return True


class HelperServer:
    """Validates + dispatches commands, pushes events to the GUI session, and
    restores everything when that session drops (the anti-orphan guarantee)."""

    def __init__(self, engine) -> None:
        self.engine = engine
        self._subs: list = []
        self._send_lock = threading.Lock()

    def handle(self, req: Request) -> Response:
        """Pure: validate a request and dispatch it, returning a Response."""
        err = validate(req.cmd, req.args)
        if err:
            return Response(ok=False, error=err)
        try:
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
        """Send an unsolicited event frame to every subscribed session."""
        frame = (json.dumps(event) + '\n').encode('utf-8')
        with self._send_lock:
            for conn in list(self._subs):
                try:
                    conn.sendall(frame)
                except OSError:
                    pass

    def _send(self, conn, resp: Response) -> None:
        with self._send_lock:
            conn.sendall(encode(resp))

    # -- socket serving ------------------------------------------------------

    def serve_connection(self, conn) -> None:
        """Serve one connection. A ``subscribe`` marks it as the GUI session:
        it then receives pushed events and, when it drops, triggers a full
        restore so no device is left blocked after the app is gone."""
        buf = b''
        subscribed = False
        try:
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b'\n' in buf:
                    line, buf = buf.split(b'\n', 1)
                    if not line.strip():
                        continue
                    try:
                        req = decode_request(line)
                    except Exception as exc:
                        self._send(conn, Response(ok=False, error=f'bad request: {exc}'))
                        continue
                    if req.cmd == 'subscribe':
                        subscribed = True
                        self._subs.append(conn)
                        self.engine.on_flows = lambda flows: self._push(
                            {'event': 'flows', 'flows': flows})
                        self._send(conn, Response(ok=True, result='subscribed'))
                        continue
                    self._send(conn, self.handle(req))
        except OSError as exc:  # peer closed / socket torn down — a normal end
            log.debug('helper connection closed: %s', exc)
        finally:
            if subscribed:
                if conn in self._subs:
                    self._subs.remove(conn)
                if not self._subs:
                    self.engine.on_flows = None
                    try:
                        self.engine.cleanup()  # GUI gone → free every device
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


def main() -> int:
    """Entry point for the root helper daemon."""
    import os
    import socket
    import sys

    if getattr(os, 'geteuid', lambda: 0)() != 0:
        print('arpcut helper must run as root', file=sys.stderr)
        return 1

    from privilege.service import SOCKET_PATH

    engine = Engine()
    if os.path.exists(SOCKET_PATH):
        os.unlink(SOCKET_PATH)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(SOCKET_PATH)
    os.chmod(SOCKET_PATH, 0o666)  # let the unprivileged GUI user connect
    sock.listen(5)
    log.info('arpcut helper listening on %s', SOCKET_PATH)
    try:
        HelperServer(engine).serve_forever(sock)
    finally:
        sock.close()
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
