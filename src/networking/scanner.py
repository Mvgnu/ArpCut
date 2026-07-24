"""ARP and ICMP network scanning with device discovery."""
import logging
from concurrent.futures.thread import ThreadPoolExecutor
from scapy.all import Ether, arping, conf, get_if_addr
from time import sleep
from re import findall
import sys
import threading
from typing import Optional, TypedDict, Callable

log = logging.getLogger(__name__)

from networking.nicknames import Nicknames
from networking.ifaces import NetFace
from tools.utils import (terminal, threaded, get_vendor, good_mac,
                         get_my_ip, get_gateway_ip, get_gateway_mac,
                         get_default_iface, get_iface_by_name)
from constants import GLOBAL_MAC


class DeviceInfo(TypedDict):
    """Canonical device record used throughout ArpCut."""
    ip: str
    mac: str
    vendor: str
    type: str  # 'Me' | 'Router' | 'User'
    name: str
    admin: bool


class Scanner():
    def __init__(self) -> None:
        self.iface: NetFace = get_default_iface()
        self.device_count: int = 25
        self.max_threads: int = 8
        self._lock: threading.Lock = threading.Lock()
        self.__ping_done: int = 0
        self.devices: list[DeviceInfo] = []
        self.old_ips: dict[str, str] = {}  # mac → ip
        self.router: DeviceInfo = {}  # type: ignore[typeddict-item]
        self.ips: list[str] = []
        self.me: DeviceInfo = {}  # type: ignore[typeddict-item]
        self.perfix: Optional[str] = None
        self.qt_progress_signal: Callable[[int], object] = int
        self.qt_log_signal: Callable[..., object] = print
        self.qt_cancel_flag: Callable[[], bool] = lambda: False
    
    def generate_ips(self) -> None:        self.ips = [f'{self.perfix}.{i}' for i in range(1, self.device_count)]

    def init(self) -> None:
        """
        Intializing Scanner
        """
        self.iface = get_iface_by_name(self.iface.name)
        self.devices = []

        # Use iface.guid (Scapy/pcap name) for network operations, not iface.name
        self.router_ip = get_gateway_ip(self.iface.guid)
        self.router_mac = get_gateway_mac(self.iface.ip, self.router_ip)

        self.my_ip = get_my_ip(self.iface.guid)
        self.my_mac = good_mac(self.iface.mac)
        
        self.perfix = self.my_ip.rsplit(".", 1)[0]
        self.generate_ips()
    
    def flush_arp(self) -> None:
        """
        Flush ARP cache
        """
        if sys.platform.startswith('win'):
            arp_cmd = terminal('arp -d *')
            if arp_cmd and 'The parameter is incorrect' in arp_cmd:
                terminal('netsh interface ip delete arpcache')
        elif sys.platform == 'darwin':
            # Best-effort flush of the whole ARP cache (needs root).
            terminal('arp -d -a')
        else:  # Linux
            terminal('ip -s -s neigh flush all')

    def add_me(self) -> None:
        """
        Get My info and append to self.devices
        """
        self.me = {
            'ip':       self.my_ip,
            'mac':      self.my_mac,
            'vendor':   get_vendor(self.my_mac),
            'type':     'Me',
            'name':     '',
            'admin':    True
        }
        
        self.devices.insert(0, self.me)

    def add_router(self) -> None:
        """
        Get Gateway info and append to self.devices
        """
        self.router = {
            'ip':       self.router_ip,
            'mac':      self.router_mac,
            'vendor':   get_vendor(self.router_mac),
            'type':     'Router',
            'name':     '',
            'admin':    True
        }

        self.devices.insert(0, self.router)

    def devices_appender(self, scan_result: list[tuple[str, str]]) -> None:
        """
        Append scan results to self.devices.
        Thread-safe: acquires ``_lock`` before mutating ``self.devices``.
        """
        nicknames = Nicknames()

        self.devices = []
        unique = []

        # Sort by last part of ip xxx.xxx.x.y
        scan_result = sorted(
            scan_result,
            key=lambda i:int(i[0].split('.')[-1])
        )
        
        for ip, mac in scan_result:
            mac = good_mac(mac)

            # Skip me or router and duplicated devices
            if ip in [self.router_ip, self.my_ip] or mac in unique:
                continue
            
            # update same device with new ip
            if self.old_ips.get(mac, ip) != ip:
                self.old_ips[mac] = ip
                unique.append(mac)

            self.devices.append(
                {
                    'ip':     ip,
                    'mac':    mac,
                    'vendor': get_vendor(mac),
                    'type':   'User',
                    'name':   nicknames.get_name(mac),
                    'admin':  False
                }
            )
        
        # Remove device with old ip
        for device in self.devices[:]:
            mac, ip = device['mac'], device['ip']
            if self.old_ips.get(mac, ip) != ip:
                self.devices.remove(device)
        
        # Re-create devices old ips dict
        self.old_ips = {d['mac']: d['ip'] for d in self.devices}

        self.add_me()
        self.add_router()

        # Clear arp cache to avoid duplicates next time
        if unique:
            self.flush_arp()
    
    def arping_cache(self) -> None:
        """
        Showing system arp cache after pinging
        """
        # Correct scan result when working with specific interface
        if sys.platform.startswith('win'):
            # Windows: get ARP table for the interface
            if self.my_ip and self.my_ip != '127.0.0.1':
                scan_result = terminal(f'arp -a -N {self.my_ip}')
            else:
                # Fallback: get all ARP entries
                scan_result = terminal('arp -a')
            
            if scan_result:
                # Filter for dynamic entries
                lines = [l for l in scan_result.split('\n') if 'dynamic' in l.lower() or 'static' in l.lower()]
                scan_result = '\n'.join(lines)
        else:
            scan_result = terminal('arp -an')
        
        if not scan_result:
            log.warning('ARP cache parse returned empty — no devices found')
            self.devices_appender([])
            return

        if sys.platform.startswith('win'):
            # Windows ARP format: "  IP_ADDRESS      MAC_ADDRESS      TYPE"
            clean_result = []
            for line in scan_result.split('\n'):
                line = line.strip()
                if not line or 'Interface:' in line:
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip = parts[0]
                    # MAC might be in format 00-11-22 or 00:11:22
                    mac_candidate = parts[1].replace('-', ':')
                    # Validate IP format
                    if '.' in ip and ip.count('.') == 3:
                        try:
                            # Quick IP validation
                            nums = ip.split('.')
                            if all(0 <= int(n) <= 255 for n in nums):
                                mac = good_mac(mac_candidate)
                                if mac and mac != GLOBAL_MAC:
                                    clean_result.append((ip, mac))
                        except (ValueError, IndexError):
                            continue
        else:
            # macOS/Linux: parse lines like "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ..."
            lines = [l for l in scan_result.split('\n') if l.strip()]
            clean_result = []
            for line in lines:
                try:
                    ip = findall(r'\(([^)]+)\)', line)[0]
                    macs = findall(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                    if macs:
                        clean_result.append((ip, macs[0]))
                except (ValueError, IndexError):
                    continue
        self.devices_appender(clean_result)
    
    def arp_scan(self) -> None:
        """
        Scan using Scapy arping method 
        """
        self.init()

        self.generate_ips()
        scan_result = arping(
            f"{self.router_ip}/24",
            iface=self.iface.guid,  # Use guid (Scapy/pcap name), not name
            verbose=0,
            timeout=1
        )
        clean_result = [(i[1].psrc, i[1].src) for i in scan_result[0]]

        self.devices_appender(clean_result)

    def ping_scan(self) -> bool:
        """
        Ping all devices at once [CPU Killing function]
           (All Threads will run at the same tine)
        """
        self.init()
        self.__ping_done = 0
        
        self.generate_ips()
        self.ping_thread_pool()
        
        while self.__ping_done < self.device_count - 1:
            # Cooperative cancellation — bridge layer can request abort
            if self.qt_cancel_flag():
                log.info('Ping scan cancelled at %d/%d', self.__ping_done, self.device_count - 1)
                return False
            # Add a sleep to overcome High CPU usage
            sleep(.01)
            self.qt_progress_signal(self.__ping_done)
        
        return True
    
    @threaded
    def ping_thread_pool(self) -> None:
        """
        Control maximum threads running at once
        """
        with ThreadPoolExecutor(self.max_threads) as executor:
            for ip in self.ips:
                executor.submit(self.ping, ip)

    def ping(self, ip: str) -> None:
        """
        Ping a specific ip with native command "ping -n"
        """
        if sys.platform.startswith('win'):
            terminal(f'ping -n 1 {ip}', decode=False)
        else:
            # macOS: -W is millis for some ping variants; use higher timeout via -t if available
            terminal(f'ping -c 1 {ip}', decode=False)
        with self._lock:
            self.__ping_done += 1

    def probe_ip(self, ip: str) -> Optional[tuple]:
        """
        Probe a specific IP using multiple methods; return (ip, mac) if discovered.
        Adds to ARP cache when possible. Best-effort cross-platform.
        """
        # Ensure scanner is initialized
        if not hasattr(self, 'my_ip') or not self.my_ip or self.my_ip == '127.0.0.1':
            try:
                self.init()
            except (OSError, AttributeError) as e:
                log.warning('Scanner init failed in probe_ip: %s', e)
        
        # Validate interface
        if self.iface.name == 'NULL':
            log.warning('Invalid interface for probe_ip(%s)', ip)
            # Try to reinitialize interface
            try:
                self.iface = get_default_iface()
                self.init()
            except (OSError, AttributeError) as e:
                log.debug('Interface reinit failed in probe_ip: %s', e)
        
        try:
            # 1) Try scapy arping to /32 (requires admin on Windows)
            if self.iface.name != 'NULL':
                ans = arping(f"{ip}/32", iface=self.iface.guid, timeout=1, verbose=0)  # Use guid (Scapy/pcap name)
                hits = [(r[1].psrc, r[1].src) for r in ans[0]]
                if hits:
                    self.devices_appender(hits)
                    return hits[0]
        except OSError as e:
            log.debug('Scapy arping failed for %s (fallback to ping): %s', ip, e)

        # 2) ICMP ping fallback to populate ARP
        try:
            self.ping(ip)
        except OSError as e:
            log.warning('Ping failed for %s: %s', ip, e)
        
        # Small delay to let ARP cache update (longer for Windows)
        from time import sleep
        sleep(0.3)
        
        # 3) Parse ARP cache
        result = self.probe_ip_arp_cache_only(ip)
        if result:
            return result

        # 4) TCP SYN to common ports to stimulate ARP (gaming/HTTP/HTTPS/DNS)
        try:
            from scapy.all import IP, TCP, sr1
            for port in [53, 80, 443, 3074, 500, 88, 123]:
                sr1(IP(dst=ip)/TCP(dport=port, flags='S'), timeout=0.5, verbose=0, iface=self.iface.guid)  # Use guid (Scapy/pcap name)
        except OSError as e:
            log.debug('TCP SYN probe failed for %s: %s', ip, e)

        # Re-check ARP cache
        return self.probe_ip_arp_cache_only(ip)

    def probe_ip_arp_cache_only(self, ip: str) -> Optional[tuple]:
        if sys.platform.startswith('win'):
            # Windows ARP format: "  IP_ADDRESS      MAC_ADDRESS      TYPE"
            # Try with interface IP first
            if self.my_ip and self.my_ip != '127.0.0.1':
                cache = terminal(f'arp -a {ip} -N {self.my_ip}') or ''
            else:
                # Fallback: query all ARP entries
                cache = terminal(f'arp -a {ip}') or ''
            
            if cache:
                # Windows ARP output format:
                # " 192.168.1.1          00-11-22-33-44-55     dynamic"
                # or "Interface: 192.168.1.100 --- 0x3\n  192.168.1.1          00-11-22-33-44-55     dynamic"
                for line in cache.split('\n'):
                    line = line.strip()
                    if not line or 'Interface:' in line:
                        continue
                    # Look for IP and MAC in the line
                    parts = line.split()
                    if len(parts) >= 2:
                        # Check if first part is the IP we're looking for
                        if parts[0] == ip:
                            # Second part should be MAC (might be in format 00-11-22 or 00:11:22)
                            mac_candidate = parts[1].replace('-', ':')
                            mac = good_mac(mac_candidate)
                            if mac and mac != GLOBAL_MAC:
                                self.devices_appender([(ip, mac)])
                                return (ip, mac)
                        # Also check if IP appears anywhere in the line
                        elif ip in line:
                            # Extract MAC using regex
                            macs = findall(r'([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})', line)
                            if macs:
                                mac = good_mac(macs[0])
                                if mac and mac != GLOBAL_MAC:
                                    self.devices_appender([(ip, mac)])
                                    return (ip, mac)
        else:
            cache = terminal('arp -an') or ''
            for line in cache.split('\n'):
                if ip in line:
                    macs = findall(r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})', line)
                    if macs:
                        mac = good_mac(macs[0])
                        self.devices_appender([(ip, mac)])
                        return (ip, mac)
        return None