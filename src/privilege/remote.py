"""RemoteEngine — the unprivileged GUI's view of the root helper's engine.

Mirrors ``helper.Engine``'s method surface, but every call is a request to the
root daemon over the Unix socket (``HelperClient``). The controller uses this as
its ``ops`` backend when the GUI isn't root but the helper is installed — so the
GUI drives real privileged operations while holding no privilege itself.

No scapy, no root: safe to import and construct from the GUI process.
"""
from __future__ import annotations

from privilege.client import HelperError, HelperSession
from privilege.service import SOCKET_PATH


class RemoteEngine:
    def __init__(self, session: HelperSession = None, sock_path: str = SOCKET_PATH) -> None:
        self.on_flows = None  # push hook the controller sets; fed by 'flows' events
        self._session = session or HelperSession(sock_path=sock_path, on_event=self._on_event)
        self._session.on_event = self._on_event

    def available(self) -> bool:
        return self._session.available() or self._session.start()

    def close(self) -> None:
        self._session.close()

    def cleanup(self) -> bool:
        return self._call('cleanup')

    def _on_event(self, frame: dict) -> None:
        if frame.get('event') == 'flows' and self.on_flows:
            self.on_flows(frame.get('flows') or [])

    def _call(self, cmd: str, **args):
        resp = self._session.call(cmd, **args)
        if not resp.ok:
            raise HelperError(resp.error or f'{cmd} failed')
        return resp.result

    # -- discovery -----------------------------------------------------------
    def status(self) -> dict:
        return self._call('status')

    def set_iface(self, name: str) -> dict:
        return self._call('set_iface', iface=name)

    def set_scan_params(self, count: int, threads: int) -> bool:
        return self._call('set_scan_params', count=count, threads=threads)

    def scan(self, scan_type: str) -> list:
        return self._call('scan', type=scan_type)

    def devices(self) -> list:
        return self._call('get_devices')

    def probe(self, ip: str):
        return self._call('probe', ip=ip)

    # -- kill / restore ------------------------------------------------------
    def kill(self, mac: str) -> bool:
        return self._call('kill', mac=mac)

    def unkill(self, mac: str) -> bool:
        return self._call('unkill', mac=mac)

    def kill_all(self) -> bool:
        return self._call('kill_all')

    def unkill_all(self) -> bool:
        return self._call('unkill_all')

    def one_way_kill(self, mac: str) -> bool:
        return self._call('one_way_kill', mac=mac)

    # -- firewall primitives -------------------------------------------------
    def block_all_for(self, ip: str) -> bool:
        return self._call('block_all_for', ip=ip)

    def unblock_all_for(self, ip: str) -> bool:
        return self._call('unblock_all_for', ip=ip)

    def block_ip(self, ip: str, direction: str = 'both') -> bool:
        return self._call('block_ip', ip=ip, direction=direction)

    def unblock_ip(self, ip: str) -> bool:
        return self._call('unblock_ip', ip=ip)

    def block_port(self, port: int, proto: str = 'tcp', direction: str = 'both',
                   target_ip=None) -> bool:
        args = {'port': port, 'proto': proto, 'direction': direction}
        if target_ip:
            args['target_ip'] = target_ip
        return self._call('block_port', **args)

    def unblock_port(self, port: int, proto: str = 'tcp') -> bool:
        return self._call('unblock_port', port=port, proto=proto)

    def list_blocked_ports(self) -> list:
        return self._call('list_blocked_ports') or []

    def list_blocked_ips(self) -> list:
        return self._call('list_blocked_ips') or []

    # -- host / domain blocking ----------------------------------------------
    def block_host(self, target, iface=None) -> dict:
        args = {'target': target}
        if iface:
            args['iface'] = iface
        return self._call('block_host', **args)

    def unblock_host(self, key: str) -> bool:
        return self._call('unblock_host', key=key)

    def refresh_hosts(self) -> dict:
        return self._call('refresh_hosts') or {}

    def active_host_blocks(self) -> dict:
        return self._call('active_host_blocks') or {}

    def set_forwarding(self, enabled: bool) -> bool:
        return self._call('set_forwarding', enabled=enabled)

    # -- traffic capture -----------------------------------------------------
    def start_sniff(self, ip: str) -> bool:
        return self._call('start_sniff', ip=ip)

    def stop_sniff(self) -> bool:
        return self._call('stop_sniff')

    def flows(self) -> list:
        return self._call('flows') or []

    # -- DNS-name blocking ---------------------------------------------------
    def dns_block(self, ip: str, domains: list) -> bool:
        return self._call('dns_block', ip=ip, domains=list(domains))

    def dns_unblock(self, ip: str) -> bool:
        return self._call('dns_unblock', ip=ip)

    def active_dns_blocks(self) -> dict:
        return self._call('active_dns_blocks') or {}
