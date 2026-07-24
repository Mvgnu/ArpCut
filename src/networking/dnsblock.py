"""DNS-name blocking for MITM'd devices — the on-host equivalent of a router RPZ.

Some block targets (notably the PSN comms name ``np.communication.playstation.net``)
have **no A record**, so there is no IP to firewall. The way to stop a device from
reaching such a name is the way the router-side Bind9/RPZ recipe in ``psn code.txt``
does it: intercept the device's DNS query for that name and answer it with
``NXDOMAIN``.

Because ArpCut is already the man-in-the-middle for a cut/monitored device (ARP
spoof + kernel forwarding), that device's DNS queries pass through this host. This
sniffer watches those queries (UDP/53) and, for a blocked name, forges an
``NXDOMAIN`` reply that appears to come from the device's resolver — racing (and
usually beating) the real answer. DNS is low-volume, so the per-packet Python cost
is negligible.

Root-only (needs raw capture + send); scapy is imported lazily so importing this
module stays cheap.
"""
from __future__ import annotations

import logging
import threading

log = logging.getLogger(__name__)


def _name_blocked(qname: str, domains: "set[str]") -> bool:
    qname = qname.rstrip('.').lower()
    return any(qname == d or qname.endswith('.' + d) for d in domains)


class DnsSpoofer:
    """Blackhole DNS names for specific MITM'd targets by forging NXDOMAIN."""

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._targets: dict[str, set[str]] = {}   # target_ip -> blocked domain suffixes
        self._sniffer = None
        self._lock = threading.Lock()

    # -- control -------------------------------------------------------------

    def block(self, target_ip: str, domains) -> None:
        clean = {d.rstrip('.').lower() for d in domains if d}
        if not clean:
            return
        with self._lock:
            self._targets.setdefault(target_ip, set()).update(clean)
        self._restart()

    def unblock(self, target_ip: str) -> None:
        with self._lock:
            self._targets.pop(target_ip, None)
            empty = not self._targets
        if empty:
            self.stop()
        else:
            self._restart()

    def active(self) -> dict:
        with self._lock:
            return {ip: sorted(doms) for ip, doms in self._targets.items()}

    def stop(self) -> None:
        sniffer, self._sniffer = self._sniffer, None
        if sniffer is not None:
            try:
                sniffer.stop()
            except Exception as exc:  # noqa: BLE001
                log.debug('dns sniffer stop: %s', exc)

    # -- capture -------------------------------------------------------------

    def _restart(self) -> None:
        self.stop()
        with self._lock:
            ips = list(self._targets)
        if not ips:
            return
        try:
            from scapy.all import AsyncSniffer
        except ImportError:
            log.warning('scapy unavailable — DNS blocking disabled')
            return
        bpf = 'udp port 53 and (' + ' or '.join(f'src host {ip}' for ip in ips) + ')'
        self._sniffer = AsyncSniffer(iface=self.iface, filter=bpf, store=False,
                                     prn=self._process)
        try:
            self._sniffer.start()
            log.info('DNS blocking active on %s for %s', self.iface, ips)
        except Exception as exc:  # noqa: BLE001
            log.warning('could not start DNS sniffer: %s', exc)
            self._sniffer = None

    def _process(self, pkt) -> None:
        from scapy.all import DNS, IP, UDP
        if not (pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:            # only client queries
            return
        src = pkt[IP].src
        with self._lock:
            domains = set(self._targets.get(src, ()))
        if not domains:
            return
        try:
            qname = pkt[DNS].qd.qname.decode('utf-8', 'ignore')
        except Exception:  # noqa: BLE001
            return
        if _name_blocked(qname, domains):
            self._send_nxdomain(pkt)

    def _send_nxdomain(self, pkt) -> None:
        """Forge an NXDOMAIN reply that looks like it came from the resolver."""
        from scapy.all import DNS, Ether, IP, UDP, sendp
        try:
            reply = (
                Ether(dst=pkt[Ether].src, src=pkt[Ether].dst) /
                IP(src=pkt[IP].dst, dst=pkt[IP].src) /
                UDP(sport=53, dport=pkt[UDP].sport) /
                DNS(id=pkt[DNS].id, qr=1, aa=1, rd=pkt[DNS].rd, ra=1,
                    rcode=3, qd=pkt[DNS].qd)     # rcode 3 = NXDOMAIN
            )
            sendp(reply, iface=self.iface, verbose=0)
        except Exception as exc:  # noqa: BLE001
            log.debug('nxdomain send failed: %s', exc)
