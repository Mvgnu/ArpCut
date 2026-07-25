"""DNS-name blocking for MITM'd devices — the on-host equivalent of a router RPZ.

Some block targets (notably the PSN comms name ``np.communication.playstation.net``)
have **no A record**, so there is no IP to firewall. The way to stop a device from
reaching such a name is the way the router-side Bind9/RPZ recipe in ``psn code.txt``
does it: intercept the device's DNS query for that name and answer it with
``NXDOMAIN``.

Because ArpCut is already the man-in-the-middle for a spoofed device (ARP spoof +
kernel forwarding), that device's DNS queries pass through this host. Two things
happen for a blocked name:

1. **Forge** — a scapy sniffer on UDP/53 forges an ``NXDOMAIN`` reply that appears
   to come from the device's resolver and sends it straight back to the device.
2. **Drop the real query** — on Windows the forwarded query is *dropped in-kernel*
   with WinDivert so the real resolver never answers. Without this the forge is a
   race the LAN resolver usually wins; with it, the device only ever sees the
   forged NXDOMAIN (or, if the forge misses, nothing — still blocked). On mac/linux
   the forge's head start is the mechanism today.

Root-only (needs raw capture + send); scapy and pydivert are imported lazily so
importing this module stays cheap and cross-platform.
"""
from __future__ import annotations

import logging
import sys
import threading

log = logging.getLogger(__name__)


def _name_blocked(qname: str, domains: "set[str]") -> bool:
    qname = qname.rstrip('.').lower()
    return any(qname == d or qname.endswith('.' + d) for d in domains)


def parse_tls_sni(payload: bytes) -> "str | None":
    """Extract the SNI host from a TLS ClientHello, or None.

    Blocking by SNI is the reliable way to block a domain for a MITM'd device:
    it's independent of DNS (cache/DoH) and of the destination IP (CDN rotation) —
    we just drop the handshake whose ClientHello names the blocked host. Bounds-
    checked and never raises; returns None for anything that isn't a ClientHello
    carrying a server_name extension.
    """
    try:
        b = payload
        n = len(b)
        # TLS record: content_type(0x16 handshake) + version(2) + length(2)
        if n < 43 or b[0] != 0x16:
            return None
        p = 5
        if b[p] != 0x01:                 # handshake type 1 = ClientHello
            return None
        p += 4                           # handshake type(1) + length(3)
        p += 2 + 32                      # client_version(2) + random(32)
        if p + 1 > n:
            return None
        p += 1 + b[p]                    # session_id: len(1) + id
        if p + 2 > n:
            return None
        p += 2 + int.from_bytes(b[p:p + 2], 'big')   # cipher_suites: len(2) + data
        if p + 1 > n:
            return None
        p += 1 + b[p]                    # compression: len(1) + data
        if p + 2 > n:
            return None
        ext_end = min(n, p + 2 + int.from_bytes(b[p:p + 2], 'big'))
        p += 2
        while p + 4 <= ext_end:
            etype = int.from_bytes(b[p:p + 2], 'big')
            elen = int.from_bytes(b[p + 2:p + 4], 'big')
            p += 4
            if etype == 0x0000:          # server_name extension
                q = p + 2                # skip server_name_list length(2)
                if q + 3 > n:
                    return None
                name_type = b[q]
                name_len = int.from_bytes(b[q + 1:q + 3], 'big')
                q += 3
                if name_type == 0 and q + name_len <= n:
                    return b[q:q + name_len].decode('ascii', 'ignore').lower()
                return None
            p += elen
        return None
    except Exception:  # noqa: BLE001 - never raise into the packet loop
        return None


class DnsSpoofer:
    """Blackhole DNS names for specific MITM'd targets by forging NXDOMAIN and
    (on Windows) dropping the real forwarded query so it can't be answered."""

    def __init__(self, iface: str) -> None:
        self.iface = iface
        self._targets: dict[str, set[str]] = {}   # target_ip -> blocked domain suffixes
        self._sniffer = None
        self._lock = threading.Lock()
        # Windows in-kernel query dropper.
        self._wd_handle = None
        self._wd_thread = None
        self._wd_running = False

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
        self._stop_windivert()

    def _is_blocked(self, src_ip: str, qname: str) -> bool:
        with self._lock:
            domains = set(self._targets.get(src_ip, ()))
        return bool(domains) and _name_blocked(qname, domains)

    def _should_drop_query(self, src_ip: str, payload: bytes) -> bool:
        """Decide whether a forwarded UDP/53 payload is a blocked query to drop.

        Fail-safe: returns True only when the payload positively parses as a DNS
        *query* (qr=0) for a blocked name from a targeted source. Any parse error
        or non-query returns False, so the packet is forwarded normally.
        """
        if not payload:
            return False
        try:
            from scapy.all import DNS
            dns = DNS(payload)
            if dns.qr != 0 or dns.qd is None:
                return False
            qname = dns.qd.qname.decode('utf-8', 'ignore')
            return self._is_blocked(src_ip, qname)
        except Exception:  # noqa: BLE001 - never drop on uncertainty
            return False

    def _should_drop_sni(self, src_ip: str, payload: bytes) -> bool:
        """Decide whether a forwarded TCP/443 payload is a blocked-SNI ClientHello.

        Fail-safe: only a positively-parsed ClientHello whose SNI matches a blocked
        name for the source is dropped; everything else forwards normally.
        """
        sni = parse_tls_sni(payload)
        return bool(sni) and self._is_blocked(src_ip, sni)

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
            log.info('DNS forge active on %s for %s', self.iface, ips)
        except Exception as exc:  # noqa: BLE001
            log.warning('could not start DNS sniffer: %s', exc)
            self._sniffer = None
        self._start_windivert(ips)

    def _process(self, pkt) -> None:
        from scapy.all import DNS, IP, UDP
        if not (pkt.haslayer(DNS) and pkt.haslayer(IP) and pkt.haslayer(UDP)):
            return
        dns = pkt[DNS]
        if dns.qr != 0 or not dns.qd:            # only client queries
            return
        try:
            qname = pkt[DNS].qd.qname.decode('utf-8', 'ignore')
        except Exception:  # noqa: BLE001
            return
        if self._is_blocked(pkt[IP].src, qname):
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

    # -- Windows in-kernel query drop (WinDivert) ----------------------------

    def _start_windivert(self, ips: "list[str]") -> None:
        if not sys.platform.startswith('win'):
            return
        try:
            from pydivert import WinDivert, Layer  # noqa: F401
        except Exception:  # noqa: BLE001
            log.debug('pydivert unavailable — DNS drop falls back to forge-only')
            return
        self._wd_running = True
        self._wd_thread = threading.Thread(target=self._wd_loop, args=(list(ips),),
                                           name='dns-windivert', daemon=True)
        self._wd_thread.start()

    def _stop_windivert(self) -> None:
        self._wd_running = False
        handle, self._wd_handle = self._wd_handle, None
        if handle is not None:
            try:
                handle.close()
            except Exception:  # noqa: BLE001
                pass
        thread, self._wd_thread = self._wd_thread, None
        if thread is not None:
            thread.join(timeout=2)

    def _wd_loop(self, ips: "list[str]") -> None:
        """Forward-path loop: drop blocked DNS queries, re-inject everything else.

        Fail-safe by construction — the default action is *re-inject* (forward
        normally); a packet is only dropped when we positively parse a blocked
        query for a targeted source. Any parse/where error re-injects, so a bug
        here can never black-hole the victim's DNS wholesale.
        """
        from pydivert import WinDivert, Layer
        srcs = '(' + ' or '.join(f'ip.SrcAddr == {ip}' for ip in ips) + ')'
        # DNS queries (UDP/53) for the NXDOMAIN drop, plus TLS ClientHellos
        # (TCP/443 with a payload) for SNI-based domain blocking.
        filt = (f'({srcs}) and (udp.DstPort == 53 or '
                f'(tcp.DstPort == 443 and tcp.PayloadLength > 0))')
        try:
            handle = WinDivert(filt, layer=Layer.NETWORK_FORWARD)
            handle.open()
        except Exception as exc:  # noqa: BLE001 - typically not elevated
            log.warning('DNS WinDivert drop unavailable (%s); forge-only', exc)
            return
        self._wd_handle = handle
        log.info('DNS in-kernel query drop active for %s', ips)
        while self._wd_running:
            try:
                pkt = handle.recv()
            except Exception:  # noqa: BLE001 - handle closed on stop
                break
            payload = bytes(pkt.payload) if pkt.payload else b''
            src = str(pkt.src_addr)
            if pkt.udp is not None and pkt.dst_port == 53:
                drop = self._should_drop_query(src, payload)
            elif pkt.tcp is not None and pkt.dst_port == 443:
                drop = self._should_drop_sni(src, payload)
            else:
                drop = False
            if not drop:
                try:
                    handle.send(pkt)           # forward normally
                except Exception:  # noqa: BLE001
                    pass
            # else: blocked — DNS query dies (no answer) / TLS handshake dies.
