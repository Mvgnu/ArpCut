from scapy.all import conf, get_if_list
from subprocess import check_output, CalledProcessError
import subprocess
from socket import socket
from threading import Thread
from manuf import manuf
import sys
import webbrowser
import re

from networking.ifaces import NetFace
from constants import *

p = manuf.MacParser()

def terminal(command, shell=True, decode=True):
    """
    Terminal commands via Subprocess (cross-platform)
    """
    try:
        cmd = check_output(command, shell=shell, stderr=subprocess.STDOUT)
        return cmd.decode('utf-8', errors='replace') if decode else None
    except CalledProcessError as e:
        # Return error output if available for debugging
        if hasattr(e, 'output') and e.output:
            try:
                return e.output.decode('utf-8', errors='replace') if decode else None
            except:
                pass
        return None
    except UnicodeDecodeError:
        try:
            return cmd.decode('utf-8', errors='replace') if decode else None
        except:
            return str(cmd) if decode else None
    except Exception:
        return None

def threaded(fn):
    """
    Thread wrapper function (decorator)
    """
    def run(*k, **kw):
        t = Thread(target=fn, args=k, kwargs=kw)
        t.start()
        return t
    return run

def get_vendor(mac):
    """
    Get vendor from manuf wireshark mac database
    """
    return p.get_manuf(mac) or 'None'

def good_mac(mac):
    """
    Convert dash separated MAC to colon separated
    """
    return mac.upper().replace('-', ':')

def get_my_ip(iface_name):
    """
    Get interface IP address (cross-platform)
    iface_name must be the Scapy/pcap name (e.g., \\Device\\NPF_{GUID} on Windows, en0 on macOS)
    """
    try:
        conf.route.resync()
    except Exception:
        pass

    invalid_ips = ('0.0.0.0', '127.0.0.1', None)
    iface_name = iface_name or str(conf.iface)

    # Preferred: walk the scapy route table for the specific interface
    try:
        for entry in conf.route.routes:
            if len(entry) >= 5:
                dst, mask, gw, iface, src_ip = entry[:5]
                if iface == iface_name and src_ip not in invalid_ips:
                    return src_ip
    except Exception:
        pass

    # Fallback: use the default route (first non-loopback source IP)
    try:
        route_result = conf.route.route("0.0.0.0")
        if len(route_result) >= 2 and route_result[1] not in invalid_ips:
            return route_result[1]
    except Exception:
        pass

    # Last resort
    return '127.0.0.1'

def get_gateway_ip(iface_name):
    """
    Get default gateway IP (cross-platform)
    iface_name must be the Scapy/pcap name (e.g., \\Device\\NPF_{GUID} on Windows, en0 on macOS)
    """
    try:
        conf.route.resync()
    except Exception:
        pass

    invalid_gws = ('0.0.0.0', None)
    iface_name = iface_name or str(conf.iface)
    chosen_gw = None

    try:
        for entry in conf.route.routes:
            if len(entry) >= 5:
                dst, mask, gw, iface, src_ip = entry[:5]
                # Prefer matches for our interface
                if iface_name and iface != iface_name:
                    continue
                if gw in invalid_gws:
                    continue
                # Default route (dst == 0 and mask == 0) is ideal
                if dst == 0 and mask == 0:
                    return gw
                if not chosen_gw:
                    chosen_gw = gw
    except Exception:
        pass

    # Fallback: use the gateway from the default route (no iface filter)
    if not chosen_gw:
        try:
            result = conf.route.route("0.0.0.0")
            if len(result) >= 3 and result[2] and result[2] not in invalid_gws:
                chosen_gw = result[2]
        except Exception:
            pass

    return chosen_gw or '0.0.0.0'

def get_gateway_mac(iface_ip, router_ip):
    if sys.platform.startswith('win'):
        # Windows: try ARP table lookup
        if iface_ip and iface_ip != '127.0.0.1':
            response = terminal(f'arp -a {router_ip} -N {iface_ip}')
        else:
            response = terminal(f'arp -a {router_ip}')
        
        if response:
            # Parse Windows ARP output: "  IP_ADDRESS      MAC_ADDRESS      TYPE"
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
        # macOS/Linux: query ARP table
        response = terminal(f'arp -n {router_ip}')
        if response:
            parts = response.split()
            for token in parts:
                if ':' in token and len(token) >= 17:
                    return good_mac(token)
    # Fallback: actively resolve via scapy
    try:
        from scapy.all import getmacbyip
        mac = getmacbyip(router_ip)
        if mac:
            return good_mac(mac)
    except Exception:
        pass
    return GLOBAL_MAC

def goto(url):
    """
    Open url in default browser (cross-platform)
    """
    try:
        webbrowser.open(url)
    except Exception:
        pass

def check_connection(func):
    """
    Connection checker decorator
    """
    def wrapper(*args, **kargs):
        if is_connected():
            # args[0] == "self" in ElmoCut class
            return func(args[0])
    return wrapper

def get_ifaces():
    """
    Get current working interfaces (cross-platform)
    """
    conf.route.resync()
    if sys.platform.startswith('win'):
        # Windows: Scapy returns GUIDs like \\Device\\NPF_{GUID}
        # We need to map these to friendly names and get IPs
        
        # Step 1: Get interface info from ipconfig to map friendly names to IPs
        ipconfig_output = terminal('ipconfig /all')
        interface_map = {}  # friendly_name -> {ip, mac, guid}
        current_adapter = None
        
        if ipconfig_output:
            for line in ipconfig_output.split('\n'):
                line = line.strip()
                if not line:
                    continue
                # Look for adapter name: "Ethernet adapter Ethernet:" (works for localized outputs too)
                if 'adapter' in line.lower() and ':' in line:
                    # Extract adapter name (text before the colon)
                    adapter_name = line.split(':', 1)[0].split()[-1]
                    if adapter_name:
                        current_adapter = line.split(':', 1)[0].split('adapter')[-1].strip(' :')
                        if not current_adapter:
                            current_adapter = adapter_name
                        interface_map[current_adapter] = {'ip': '0.0.0.0', 'mac': GLOBAL_MAC, 'guid': None}
                elif current_adapter:
                    # Look for IPv4 address with a regex to handle "(Preferred)" or localized text
                    ip_match = re.search(r'(\d{1,3}(?:\.\d{1,3}){3})', line)
                    if ip_match:
                        ip = ip_match.group(1)
                        try:
                            nums = ip.split('.')
                            if all(0 <= int(n) <= 255 for n in nums) and ip != '0.0.0.0':
                                interface_map[current_adapter]['ip'] = ip
                        except ValueError:
                            pass
                    # Look for Physical Address (MAC) using regex for locale-agnostic parsing
                    mac_match = re.search(r'([0-9A-Fa-f]{2}(?:[-:][0-9A-Fa-f]{2}){5})', line)
                    if mac_match:
                        interface_map[current_adapter]['mac'] = good_mac(mac_match.group(1))
        
        # Step 2: Get GUID mapping from netsh (may be localized - best effort)
        netsh_output = terminal('netsh interface show interface')
        guid_to_friendly = {}  # guid -> friendly_name
        if netsh_output:
            for line in netsh_output.split('\n'):
                line = line.strip()
                if not line or '---' in line:
                    continue
                # Try to extract GUID in braces if present
                if '{' in line and '}' in line:
                    guid_start = line.find('{')
                    guid_end = line.find('}', guid_start)
                    if guid_start >= 0 and guid_end > guid_start:
                        guid = line[guid_start+1:guid_end]
                        friendly = line[:guid_start].strip()
                        # Take the last token as interface name (works for many locales)
                        friendly_parts = friendly.split()
                        if friendly_parts:
                            friendly = friendly_parts[-1]
                        guid_to_friendly[guid] = friendly
        
        # Step 3: Get Scapy interfaces and match with our map
        from scapy.all import get_if_hwaddr
        scapy_ifaces = get_if_list()
        
        for scapy_name in scapy_ifaces:
            # Extract GUID from Scapy name: \\Device\\NPF_{GUID}
            guid = None
            if 'NPF_' in scapy_name:
                # Extract GUID: \\Device\\NPF_{20AB37B7-7002-4A4E-9F8C-3B6C95FC709D}
                guid_part = scapy_name.split('NPF_')[-1]
                # Remove braces - GUID is between { and }
                if '{' in guid_part:
                    guid_start = guid_part.find('{')
                    guid_end = guid_part.find('}', guid_start)
                    if guid_end > guid_start:
                        guid = guid_part[guid_start+1:guid_end]
                    else:
                        # Fallback: just strip braces
                        guid = guid_part.strip('{}').split('}')[0].split('\\')[0]
                else:
                    guid = guid_part.strip('{}').split('}')[0].split('\\')[0]
            
            # Try to find matching friendly name
            friendly_name = None
            if guid and guid in guid_to_friendly:
                friendly_name = guid_to_friendly[guid]
            else:
                # Try to match by checking if GUID appears in interface_map keys
                for key in interface_map.keys():
                    if guid and guid.lower() in key.lower():
                        friendly_name = key
                        break
            
            # Get IP and MAC
            ip = '0.0.0.0'
            mac = GLOBAL_MAC
            found_ip = False
            
            if friendly_name and friendly_name in interface_map:
                ip = interface_map[friendly_name]['ip']
                mac = interface_map[friendly_name]['mac']
                if ip != '0.0.0.0' and ip != '127.0.0.1':
                    found_ip = True
            
            # Try to get MAC from scapy (always try this)
            try:
                scapy_mac = get_if_hwaddr(scapy_name)
                if scapy_mac and scapy_mac != '00:00:00:00:00:00':
                    mac = scapy_mac
            except Exception:
                scapy_mac = None

            # If we have a MAC, attempt to match friendly names from ipconfig
            if not friendly_name and scapy_mac:
                for friendly, info in interface_map.items():
                    if info['mac'] != GLOBAL_MAC and good_mac(info['mac']) == good_mac(scapy_mac):
                        friendly_name = friendly
                        if info['ip'] not in ('0.0.0.0', '127.0.0.1'):
                            ip = info['ip']
                            found_ip = True
                        break
            
            # Fallback: try to get IP from scapy route table (always try this as fallback)
            if not found_ip:
                # Method 1: Try default route for this iface (ignore TypeError on newer scapy)
                try:
                    route_result = conf.route.route("0.0.0.0", iface=scapy_name)
                    if route_result and len(route_result) > 1:
                        potential_ip = route_result[1]
                        if potential_ip and potential_ip not in ('0.0.0.0', '127.0.0.1'):
                            ip = potential_ip
                            found_ip = True
                except TypeError:
                    # Newer scapy versions do not accept iface kwarg
                    pass
                except Exception:
                    pass

                # Method 2: Check all routes for this interface
                if not found_ip:
                    try:
                        for route in conf.route.routes:
                            # Route format: (dst, mask, gw, iface, ip)
                            if len(route) >= 5 and route[3] == scapy_name:
                                route_ip = route[4]
                                if route_ip and route_ip not in ('0.0.0.0', '127.0.0.1'):
                                    ip = route_ip
                                    found_ip = True
                                    break
                    except Exception:
                        pass
            
            # Skip only loopback interfaces, but include interfaces even if IP is 0.0.0.0
            # (they might be valid interfaces that just don't have an IP assigned)
            if ip == '127.0.0.1':
                continue
            
            # Final fallback: use get_my_ip with the Scapy name directly
            if not found_ip or ip == '0.0.0.0':
                try:
                    potential_ip = get_my_ip(scapy_name)
                    if potential_ip and potential_ip != '0.0.0.0' and potential_ip != '127.0.0.1':
                        ip = potential_ip
                        found_ip = True
                except Exception:
                    pass
            
            # Use friendly name if available, otherwise use Scapy name (cleaned up)
            if friendly_name:
                display_name = friendly_name
            else:
                # Clean up Scapy name for display
                display_name = scapy_name.replace('\\Device\\NPF_', '').strip('{}')
                # If still looks like a GUID, use a simpler name
                if '{' in display_name or len(display_name) > 50:
                    display_name = f"Interface-{scapy_ifaces.index(scapy_name)+1}"
            
            # Always yield the interface, even if IP is 0.0.0.0 (might be valid but unconfigured)
            # Only skip if it's explicitly loopback
            # KEY FIX: guid must be the Scapy/pcap name, not just the Windows GUID
            iface = {
                'name': display_name,        # nice human name (or cleaned up)
                'guid': scapy_name,         # scapy / pcap name (\\Device\\NPF_{...})
                'mac': mac,
                'ips': [ip],
                'win_guid': guid,            # optional: keep Windows GUID if needed
            }
            yield NetFace(iface)
    else:
        # macOS/Linux: Build iface dicts similar to Windows structure
        # name, guid=name, mac via scapy, ips via route table
        
        # Build a map of iface -> src_ip from route table
        iface_ips = {}
        try:
            for entry in conf.route.routes:
                if len(entry) >= 5:
                    dst, mask, gw, iface, src_ip = entry[:5]
                    if src_ip and src_ip not in ('0.0.0.0', '127.0.0.1'):
                        if iface not in iface_ips:
                            iface_ips[iface] = src_ip
        except Exception:
            pass
        
        for name in get_if_list():
            ip = iface_ips.get(name, '0.0.0.0')
            try:
                from scapy.all import get_if_hwaddr
                mac = get_if_hwaddr(name)
            except Exception:
                mac = GLOBAL_MAC
            iface = {'name': name, 'guid': name, 'mac': mac, 'ips': [ip]}
            yield NetFace(iface)

def get_default_iface():
    """
    Get default pcap interface (cross-platform)
    """
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
    
    # Last resort: return first interface
    return ifaces_list[0] if ifaces_list else NetFace(DUMMY_IFACE)

def get_iface_by_name(name):
    """
    Return interface given its name
    """
    for iface in get_ifaces():
        if iface.name == name:
            return iface
    return get_default_iface()

def is_connected(current_iface=None):
    """
    Checks if there are any IPs in Default Gateway sections
    """
    if current_iface is None:
        current_iface = get_default_iface()
    
    if current_iface.name == 'NULL':
        # Try to get a valid interface
        current_iface = get_default_iface()
        if current_iface.name == 'NULL':
            # Last resort: check if we have any network connectivity
            try:
                socket().connect(('8.8.8.8', 53))
                return True
            except Exception:
                return False

    if sys.platform.startswith('win'):
        # Windows: check for default gateway via ipconfig
        ipconfig_output = terminal('ipconfig | findstr /i gateway')
        if ipconfig_output and ipconfig_output.strip():
            # Check if output contains IP addresses (digits with dots)
            if any(c.isdigit() for c in ipconfig_output):
                return True
        # Fallback: check if interface has a valid IP
        if current_iface.ip and current_iface.ip != '0.0.0.0' and current_iface.ip != '127.0.0.1':
            return True

    # Fallback: try socket connection test
    try:
        s = socket()
        s.settimeout(1)
        s.connect(('8.8.8.8', 53))
        s.close()
        return True
    except Exception:
        pass
    
    return False
