"""Real-time traffic sniffer for per-device flow and pattern analysis."""
import logging
from collections import defaultdict
from datetime import datetime
from threading import Thread, Event, RLock, current_thread
from time import time
import sys
from typing import Optional, Callable, Any

log = logging.getLogger(__name__)

try:
    from scapy.all import sniff, IP, TCP, UDP, Raw
except ImportError:
    sniff = None  # type: ignore[assignment]
    log.warning('scapy not available — traffic sniffing disabled')


class TrafficSniffer:
    def __init__(self) -> None:
        self._thread = None
        self._stop = Event()
        self._lock = RLock()
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
        self._callback: Optional[Callable[[], None]] = None
        self._iface: Optional[str] = None
        self._victim_ip: Optional[str] = None
        self._last_pkt: object = None

    def get_flows(self) -> dict[tuple[str, int, str], dict[str, Any]]:
        with self._lock:
            return {key: dict(value) for key, value in self._flows.items()}

    def get_last_packet_hex(self) -> str:
        if self._last_pkt is None:
            return ''
        raw = bytes(self._last_pkt)[:512]
        return ' '.join(f'{b:02x}' for b in raw)

    def get_last_packet_layers(self) -> dict[str, dict[str, Any]]:
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
            except (UnicodeDecodeError, ValueError):
                printable = ''
            info['payload'] = {
                'length': len(payload),
                'text': printable[:512]
            }
        return info

    def get_patterns(self) -> dict[tuple[str, int, int], dict[str, int]]:
        with self._lock:
            return {key: dict(value) for key, value in self._patterns.items()}

    def start(self, victim_ip: str, iface: str, on_update: Optional[Callable[[], None]] = None) -> bool:
        self.stop()
        with self._lock:
            self._victim_ip = victim_ip
            self._iface = iface
            self._callback = on_update
            self._flows.clear()
            self._patterns.clear()
            self._pattern_samples.clear()
            self._last_pkt = None
        # Never reuse a cancellation event: a stopped worker must stay stopped.
        self._stop = Event()
        ready = Event()
        startup = {'error': None}
        self._thread = Thread(target=self._run,
                              args=(self._stop, victim_ip, iface, ready, startup), daemon=True)
        self._thread.start()
        if not ready.wait(2.0):
            self.stop()
            raise RuntimeError('Traffic capture did not start in time')
        if startup['error']:
            self.stop()
            raise RuntimeError(startup['error'])
        return True

    def stop(self) -> None:
        self._stop.set()
        if self._thread and self._thread.is_alive():
            if self._thread is current_thread():
                return
            self._thread.join(timeout=2.0)
            if self._thread.is_alive():
                raise RuntimeError('Traffic capture has not stopped yet')
        self._thread = None

    def _run(self, stop: Event, victim_ip: str, iface: str,
             ready: Event, startup: dict) -> None:
        if sniff is None:
            startup['error'] = 'Scapy is unavailable for traffic capture'
            ready.set()
            return
        # BPF filter: traffic to/from victim
        bpf = f"host {victim_ip}"
        try:
            # stop_filter only runs when a packet arrives. A bounded capture
            # timeout also releases idle captures, allowing stop/join to finish.
            while not stop.is_set():
                sniff(prn=lambda pkt: None if stop.is_set() else self._process(pkt),
                      filter=bpf, store=False, iface=iface, timeout=0.5,
                      stop_filter=lambda p: stop.is_set(), started_callback=ready.set)
        except Exception as e:  # scapy wraps BPF-open denial in Scapy_Exception, not OSError
            startup['error'] = str(e) or type(e).__name__
            log.warning('Sniffer stopped on %s: %s', self._iface, e)
        finally:
            ready.set()

    def _process(self, pkt: object) -> None:
        with self._lock:
            self._process_locked(pkt)

    def _process_locked(self, pkt: object) -> None:
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
            payload_len = len(bytes(pkt[Raw].load)) if Raw in pkt else 0
        except (AttributeError, IndexError):
            payload_len = 0
        bucket = (payload_len // 32) * 32
        pkey = (proto, int(dport), bucket)
        pat = self._patterns[pkey]
        pat['bytes'] += size
        pat['packets'] += 1
        # Store up to N samples per pattern
        if len(self._pattern_samples[pkey]) < 50:
            ts = datetime.now().strftime('%H:%M:%S.%f')[:-3]
            preview = ''
            try:
                payload = bytes(pkt[Raw].load) if Raw in pkt else b''
                preview = payload[:64].hex()
            except (AttributeError, IndexError):
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
            except Exception as e:
                log.debug('Sniffer callback error: %s', e)

    def get_pattern_samples(self, key: tuple[str, int, int]) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(sample) for sample in self._pattern_samples.get(key, [])]


