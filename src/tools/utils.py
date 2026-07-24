"""Cross-platform utilities — network interface detection, shell commands, MAC helpers.

This module is the main platform abstraction layer in ArpCut.  It wraps scapy,
system commands, and OUI lookups behind a common interface.
"""
import logging
import re
import shlex
import subprocess
import sys
import webbrowser
from socket import socket
from subprocess import CalledProcessError, check_output
from threading import Thread
from typing import Any, Callable, Generator, Optional

from manuf import manuf
from scapy.all import conf, get_if_list

from constants import GLOBAL_MAC, DUMMY_IFACE
from networking.ifaces import NetFace

log = logging.getLogger(__name__)
p: manuf.MacParser = manuf.MacParser()


# ---------------------------------------------------------------------------
# Shell / process helpers
# ---------------------------------------------------------------------------

def terminal(command, decode: bool = True) -> Optional[str]:
    """Run a command WITHOUT a shell and return stdout, or None on failure.

    ``command`` may be an argv list or a string (split with ``shlex``). Running
    without a shell means values interpolated into commands (IPs parsed from OS
    output) can't be reinterpreted as shell syntax — this closes the old
    ``shell=True`` injection surface. Commands that genuinely needed a pipe are
    rewritten to filter their output in Python instead.
    """
    args = shlex.split(command, posix=not sys.platform.startswith('win')) \
        if isinstance(command, str) else command
    try:
        out = check_output(args, stderr=subprocess.STDOUT)
        return out.decode('utf-8', errors='replace') if decode else None
    except CalledProcessError as e:
        if getattr(e, 'output', None):
            try:
                return e.output.decode('utf-8', errors='replace') if decode else None
            except (UnicodeDecodeError, AttributeError):
                pass
        return None
    except (OSError, ValueError) as e:  # ValueError: shlex on malformed quoting
        log.debug('terminal() command failed: %s', e)
        return None


def threaded(fn: Callable[..., Any]) -> Callable[..., Thread]:
    """Decorator to run a function in a daemon Thread."""
    def run(*k: Any, **kw: Any) -> Thread:
        t = Thread(target=fn, args=k, kwargs=kw)
        t.start()
        return t
    return run


# ---------------------------------------------------------------------------
# MAC / Vendor helpers
# ---------------------------------------------------------------------------

def get_vendor(mac: str) -> str:
    """Get vendor from manuf wireshark MAC database."""
    return p.get_manuf(mac) or 'None'


def good_mac(mac: str) -> str:
    """Normalize MAC to uppercase colon-separated format."""
    return mac.upper().replace('-', ':')


# ---------------------------------------------------------------------------
# IP / Gateway resolution
# ---------------------------------------------------------------------------

def get_my_ip(iface_name: Optional[str]) -> str:
    """Get interface IP address (cross-platform).

    ``iface_name`` must be the Scapy/pcap name.
    """
    try:
        conf.route.resync()
    except OSError as e:
        log.debug('Route resync failed: %s', e)

    invalid_ips = ('0.0.0.0', '127.0.0.1', None)
    iface_name = iface_name or str(conf.iface)

    # Preferred: walk the scapy route table for the specific interface
    try:
        for entry in conf.route.routes:
            if len(entry) >= 5:
                dst, mask, gw, iface, src_ip = entry[:5]
                if iface == iface_name and src_ip not in invalid_ips:
                    return src_ip
    except (OSError, AttributeError) as e:
        log.debug('Route table walk failed: %s', e)

    # Fallback: use the default route
    try:
        route_result = conf.route.route("0.0.0.0")
        if len(route_result) >= 2 and route_result[1] not in invalid_ips:
            return route_result[1]
    except (OSError, AttributeError) as e:
        log.debug('Default route lookup failed: %s', e)

    return '127.0.0.1'


def get_gateway_ip(iface_name: Optional[str]) -> str:
    """Get default gateway IP (cross-platform)."""
    try:
        conf.route.resync()
    except OSError as e:
        log.debug('Route resync failed: %s', e)

    invalid_gws = ('0.0.0.0', None)
    iface_name = iface_name or str(conf.iface)
    chosen_gw = None

    try:
        for entry in conf.route.routes:
            if len(entry) >= 5:
                dst, mask, gw, iface, src_ip = entry[:5]
                if iface_name and iface != iface_name:
                    continue
                if gw in invalid_gws:
                    continue
                if dst == 0 and mask == 0:
                    return gw
                if not chosen_gw:
                    chosen_gw = gw
    except (OSError, AttributeError) as e:
        log.debug('Route table walk failed: %s', e)

    if not chosen_gw:
        try:
            result = conf.route.route("0.0.0.0")
            if len(result) >= 3 and result[2] and result[2] not in invalid_gws:
                chosen_gw = result[2]
        except (OSError, AttributeError) as e:
            log.debug('Fallback gateway lookup failed: %s', e)

    return chosen_gw or '0.0.0.0'


def get_gateway_mac(iface_ip: Optional[str], router_ip: str) -> str:
    """Resolve the MAC address of the default gateway."""
    if sys.platform.startswith('win'):
        if iface_ip and iface_ip != '127.0.0.1':
            response = terminal(f'arp -a {router_ip} -N {iface_ip}')
        else:
            response = terminal(f'arp -a {router_ip}')

        if response:
            for line in response.split('\n'):
                line = line.strip()
                if not line or 'Interface:' in line:
                    continue
                parts = line.split()
                if len(parts) >= 2 and parts[0] == router_ip:
                    mac_candidate = parts[1].replace('-', ':')
                    mac = good_mac(mac_candidate)
                    if mac and mac != GLOBAL_MAC:
                        return mac
    else:
        response = terminal(f'arp -n {router_ip}')
        if response:
            # Match a real MAC (six colon-separated hex groups), not any token
            # containing a colon (which could be IPv6 / ifscope noise).
            m = re.search(r'([0-9a-fA-F]{1,2}(?::[0-9a-fA-F]{1,2}){5})', response)
            if m:
                return good_mac(m.group(1))

    # Fallback: actively resolve via scapy
    try:
        from scapy.all import getmacbyip
        mac = getmacbyip(router_ip)
        if mac:
            return good_mac(mac)
    except OSError as e:
        log.debug('scapy getmacbyip failed for %s: %s', router_ip, e)
    return GLOBAL_MAC


# ---------------------------------------------------------------------------
# Misc utilities
# ---------------------------------------------------------------------------

def goto(url: str) -> None:
    """Open url in default browser (cross-platform)."""
    try:
        webbrowser.open(url)
    except OSError as e:
        log.warning('Failed to open browser for %s: %s', url, e)


def check_connection(func: Callable[..., Any]) -> Callable[..., Any]:
    """Decorator that only runs the wrapped function when connected."""
    def wrapper(*args: Any, **kargs: Any) -> Any:
        if is_connected():
            return func(args[0])
    return wrapper


# ---------------------------------------------------------------------------
# Interface detection — split by platform
# ---------------------------------------------------------------------------

_GUID_RE = re.compile(r'([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-'
                      r'[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})')
_IPV4_RE = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}$')


def _get_ifaces_windows() -> Generator[NetFace, None, None]:
    """Detect network interfaces on Windows via scapy's structured NIC list.

    Replaces ~170 lines of ``ipconfig``/``netsh`` text parsing: scapy already
    enumerates adapters with name/guid/mac/ips, so we map that onto ``NetFace``
    and match it to the pcap-style socket name (``\\Device\\NPF_{guid}``) that
    scapy needs for L2 sockets. Falls back to the route table for a missing IP.

    NOTE: behavior-preserving simplification; runtime-verify on a Windows host.
    """
    from scapy.all import get_if_list, get_if_hwaddr
    try:
        from scapy.arch.windows import get_windows_if_list
        win_ifaces = get_windows_if_list()
    except ImportError:
        win_ifaces = []

    # Index scapy's structured data by GUID (braces stripped, upper-cased).
    by_guid: dict[str, dict[str, Any]] = {}
    for entry in win_ifaces:
        g = (entry.get('guid') or '').strip('{}').upper()
        if g:
            by_guid[g] = entry

    for pcap_name in get_if_list():
        m = _GUID_RE.search(pcap_name)
        guid = m.group(1).upper() if m else None
        info = by_guid.get(guid or '', {})

        ipv4s = [ip for ip in info.get('ips', []) if _IPV4_RE.match(ip)]
        ip = next((i for i in ipv4s if i not in ('0.0.0.0', '127.0.0.1')), '0.0.0.0')
        if ip == '127.0.0.1':
            continue

        mac = good_mac(info.get('mac') or '') or GLOBAL_MAC
        if mac == GLOBAL_MAC:
            try:
                hw = get_if_hwaddr(pcap_name)
                if hw and hw != '00:00:00:00:00:00':
                    mac = good_mac(hw)
            except OSError:
                pass

        if ip == '0.0.0.0':  # route-table fallback for the interface's src IP
            fallback = get_my_ip(pcap_name)
            if fallback not in ('0.0.0.0', '127.0.0.1'):
                ip = fallback

        name = info.get('name') or info.get('description') or (guid or pcap_name)
        yield NetFace({
            'name': name,
            'guid': pcap_name,   # pcap/socket name scapy needs
            'mac': mac,
            'ips': [ip],
            'win_guid': guid,
        })


def _get_ifaces_unix() -> Generator[NetFace, None, None]:
    """Detect network interfaces on macOS and Linux.

    Uses scapy's route table for IPs and ``get_if_hwaddr`` for MACs.
    """
    from scapy.all import get_if_hwaddr

    # Build iface → src_ip map from route table
    iface_ips: dict[str, str] = {}
    try:
        for entry in conf.route.routes:
            if len(entry) >= 5:
                dst, mask, gw, iface, src_ip = entry[:5]
                if src_ip and src_ip not in ('0.0.0.0', '127.0.0.1'):
                    if iface not in iface_ips:
                        iface_ips[iface] = src_ip
    except (OSError, AttributeError) as e:
        log.debug('Route table walk failed: %s', e)

    for name in get_if_list():
        ip = iface_ips.get(name, '0.0.0.0')
        try:
            mac = get_if_hwaddr(name)
        except OSError:
            mac = GLOBAL_MAC
        iface_dict: dict[str, Any] = {'name': name, 'guid': name, 'mac': mac, 'ips': [ip]}
        yield NetFace(iface_dict)


def get_ifaces() -> Generator[NetFace, None, None]:
    """Get current working interfaces (cross-platform dispatcher)."""
    conf.route.resync()
    if sys.platform.startswith('win'):
        yield from _get_ifaces_windows()
    else:
        yield from _get_ifaces_unix()


# ---------------------------------------------------------------------------
# Interface selection
# ---------------------------------------------------------------------------

def get_default_iface() -> NetFace:
    """Get default pcap interface (cross-platform)."""
    ifaces_list = list(get_ifaces())
    if not ifaces_list:
        return NetFace(DUMMY_IFACE)

    # Try to match with scapy's default interface
    for iface in ifaces_list:
        if iface.guid in str(conf.iface) or iface.name in str(conf.iface):
            return iface

    # Fallback: return first non-loopback interface
    for iface in ifaces_list:
        if iface.ip and iface.ip != '127.0.0.1' and iface.ip != '0.0.0.0':
            return iface

    return ifaces_list[0] if ifaces_list else NetFace(DUMMY_IFACE)


def get_iface_by_name(name: str) -> NetFace:
    """Return interface given its name."""
    for iface in get_ifaces():
        if iface.name == name:
            return iface
    return get_default_iface()


# ---------------------------------------------------------------------------
# Connectivity check
# ---------------------------------------------------------------------------

def is_connected(current_iface: Optional[NetFace] = None) -> bool:
    """Check if there is active network connectivity."""
    if current_iface is None:
        current_iface = get_default_iface()

    if current_iface.name == 'NULL':
        current_iface = get_default_iface()
        if current_iface.name == 'NULL':
            try:
                s = socket()
                try:
                    s.settimeout(1)
                    s.connect(('8.8.8.8', 53))
                    return True
                finally:
                    s.close()
            except OSError:
                return False

    if sys.platform.startswith('win'):
        ipconfig_output = terminal('ipconfig')
        if ipconfig_output:
            gw_lines = [ln for ln in ipconfig_output.splitlines() if 'gateway' in ln.lower()]
            if any(any(c.isdigit() for c in ln) for ln in gw_lines):
                return True
        if current_iface.ip and current_iface.ip not in ('0.0.0.0', '127.0.0.1'):
            return True

    # Fallback: socket connectivity test
    try:
        s = socket()
        try:
            s.settimeout(1)
            s.connect(('8.8.8.8', 53))
            return True
        finally:
            s.close()
    except OSError:
        pass

    return False
