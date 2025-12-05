from collections import defaultdict
from threading import Thread, Event
from time import time
import sys

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except Exception:
    sniff = None


class TrafficSniffer:
    def __init__(self):
        self._thread = None
        self._stop = Event()
        self._flows = defaultdict(lambda: {
            'bytes': 0,
            'packets': 0,
            'last_seen': 0.0,
            'proto': ''
        })
        self._patterns = defaultdict(lambda: {
            'bytes': 0,
            'packets': 0,
        })
        self._pattern_samples = defaultdict(list)
        self._callback = None
        self._iface = None
        self._victim_ip = None
        self._last_pkt = None

    def get_flows(self):
        return dict(self._flows)

    def get_last_packet_hex(self):
        if self._last_pkt is None:
            return ''
        raw = bytes(self._last_pkt)[:512]
        return ' '.join(f'{b:02x}' for b in raw)

    def get_last_packet_layers(self):
        if self._last_pkt is None:
            return {}
        pkt = self._last_pkt
        info = {}
        if IP in pkt:
            ip = pkt[IP]
            info['ip'] = {
                'src': ip.src,
                'dst': ip.dst,
                'ttl': ip.ttl,
                'len': ip.len
            }
        if TCP in pkt:
            t = pkt[TCP]
            info['tcp'] = {
                'sport': int(t.sport),
                'dport': int(t.dport),
                'flags': str(t.flags)
            }
        if UDP in pkt:
            u = pkt[UDP]
            info['udp'] = {
                'sport': int(u.sport),
                'dport': int(u.dport),
                'len': int(u.len)
            }
        if Raw in pkt:
            payload = bytes(pkt[Raw].load)
            try:
                printable = payload.decode('utf-8', errors='ignore')
            except Exception:
                printable = ''
            info['payload'] = {
                'length': len(payload),
                'text': printable[:512]
            }
        return info

    def get_patterns(self):
        return dict(self._patterns)

    def start(self, victim_ip: str, iface: str, on_update=None):
        self.stop()
        self._victim_ip = victim_ip
        self._iface = iface
        self._callback = on_update
        self._stop.clear()
        self._thread = Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        if self._thread and self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=1.0)
        self._thread = None

    def _run(self):
        if sniff is None:
            return
        # BPF filter: traffic to/from victim
        bpf = f"host {self._victim_ip}"
        try:
            sniff(prn=self._process,
                  filter=bpf,
                  store=False,
                  iface=self._iface,
                  stop_filter=lambda p: self._stop.is_set())
        except PermissionError:
            # Non-root on macOS: no sniffing; ignore
            pass
        except Exception:
            # Best-effort; do not crash UI
            pass

    def _process(self, pkt):
        now = time()
        if IP not in pkt:
            return
        self._last_pkt = pkt
        ip = pkt[IP]
        proto = 'TCP' if TCP in pkt else 'UDP' if UDP in pkt else str(ip.proto)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        if ip.src == self._victim_ip:
            key = (ip.dst, int(dport), proto)
        elif ip.dst == self._victim_ip:
            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
            key = (ip.src, int(sport), proto)
        else:
            return

        size = len(bytes(pkt))
        flow = self._flows[key]
        flow['bytes'] += size
        flow['packets'] += 1
        flow['last_seen'] = now
        flow['proto'] = proto
        # Pattern key: (proto, dst_port, payload_len_bucket)
        try:
            from scapy.all import Raw
            payload_len = len(bytes(pkt[Raw].load)) if Raw in pkt else 0
        except Exception:
            payload_len = 0
        bucket = (payload_len // 32) * 32
        pkey = (proto, int(dport), bucket)
        pat = self._patterns[pkey]
        pat['bytes'] += size
        pat['packets'] += 1
        # Store up to N samples per pattern
        if len(self._pattern_samples[pkey]) < 50:
            from datetime import datetime
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            preview = ''
            try:
                from scapy.all import Raw
                payload = bytes(pkt[Raw].load) if Raw in pkt else b''
                preview = payload[:64].hex()
            except Exception:
                pass
            dst = ip.dst if ip.src == self._victim_ip else ip.src
            self._pattern_samples[pkey].append({
                'time': ts,
                'dst': dst,
                'length': size,
                'preview': preview,
            })
        if self._callback:
            try:
                self._callback()
            except Exception:
                pass

    def get_pattern_samples(self, key):
        return list(self._pattern_samples.get(key, []))


