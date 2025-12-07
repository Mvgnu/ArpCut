#!/usr/bin/env python3
"""
Deep diagnostic for Windows interface detection issues
Analyzes the three-layer naming problem: Scapy name, Windows GUID, Friendly name
"""
import sys
import os
import re
sys.path.append(os.path.join(os.getcwd(), 'src'))

def section(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

print("="*60)
print(" WINDOWS INTERFACE DETECTION DEBUG")
print("="*60)
print(f"Platform: {sys.platform}")

if not sys.platform.startswith('win'):
    print("\n⚠ This diagnostic is designed for Windows.")
    print("  Running anyway for comparison...\n")

from tools.utils import terminal, good_mac

# Layer 1: ipconfig /all - Get friendly names, IPs, MACs
section("Layer 1: ipconfig /all (Friendly Names)")
ipconfig_output = terminal('ipconfig /all')
interface_map = {}  # friendly_name -> {ip, mac}

if ipconfig_output:
    print(f"Output length: {len(ipconfig_output)} chars\n")
    current_adapter = None
    
    for line in ipconfig_output.split('\n'):
        line_stripped = line.strip()
        if not line_stripped:
            continue
            
        # Detect adapter headers
        if 'adapter' in line.lower() and ':' in line:
            # Format: "Ethernet adapter Ethernet:" or "Wireless LAN adapter Wi-Fi:"
            match = re.search(r'adapter\s+(.+?):', line, re.IGNORECASE)
            if match:
                current_adapter = match.group(1).strip()
                interface_map[current_adapter] = {'ip': '0.0.0.0', 'mac': 'FF:FF:FF:FF:FF:FF'}
                print(f"  Found adapter: '{current_adapter}'")
        elif current_adapter:
            # Look for IPv4
            if 'ipv4' in line_stripped.lower() or ('ip address' in line_stripped.lower() and 'ipv6' not in line_stripped.lower()):
                match = re.search(r':\s*([\d.]+)', line_stripped)
                if match:
                    ip = match.group(1)
                    if ip.count('.') == 3 and ip != '0.0.0.0':
                        interface_map[current_adapter]['ip'] = ip
                        print(f"    -> IP: {ip}")
            # Look for Physical Address
            elif 'physical address' in line_stripped.lower():
                match = re.search(r':\s*([0-9A-Fa-f-]+)', line_stripped)
                if match:
                    mac = good_mac(match.group(1))
                    interface_map[current_adapter]['mac'] = mac
                    print(f"    -> MAC: {mac}")
    
    print(f"\n  Total adapters found: {len(interface_map)}")
else:
    print("  ✗ No ipconfig output!")

# Layer 2: netsh - Get connection status (no GUIDs here usually)
section("Layer 2: netsh interface show interface")
netsh_output = terminal('netsh interface show interface')
connected_ifaces = set()

if netsh_output:
    print(f"Output:\n{netsh_output}\n")
    for line in netsh_output.split('\n'):
        if 'Connected' in line:
            parts = line.split()
            if len(parts) >= 4:
                # Last part is usually the interface name
                iface_name = parts[-1]
                connected_ifaces.add(iface_name)
                print(f"  Connected: {iface_name}")
else:
    print("  ✗ No netsh output!")

# Layer 3: Scapy interfaces
section("Layer 3: Scapy Interfaces (NPF names)")
try:
    from scapy.all import get_if_list, get_if_hwaddr, conf
    scapy_ifaces = get_if_list()
    print(f"Scapy found {len(scapy_ifaces)} interfaces:\n")
    
    for scapy_name in scapy_ifaces:
        print(f"  Scapy name: {scapy_name}")
        
        # Extract GUID from NPF name
        guid = None
        if 'NPF_' in scapy_name:
            match = re.search(r'NPF_\{?([A-Fa-f0-9-]+)\}?', scapy_name)
            if match:
                guid = match.group(1).upper()
                print(f"    GUID: {guid}")
        
        # Try to get MAC via Scapy
        try:
            mac = get_if_hwaddr(scapy_name)
            print(f"    Scapy MAC: {mac}")
        except Exception as e:
            print(f"    Scapy MAC: error - {e}")
        
        print()
except Exception as e:
    print(f"  ✗ Scapy error: {e}")

# Matching Analysis
section("Matching Analysis")
print("Attempting to match Scapy interfaces to friendly names...\n")

try:
    from scapy.all import get_if_list, get_if_hwaddr
    
    for scapy_name in get_if_list():
        print(f"Scapy: {scapy_name[:50]}...")
        
        # Get Scapy's MAC for this interface
        try:
            scapy_mac = good_mac(get_if_hwaddr(scapy_name))
        except:
            scapy_mac = None
        
        # Try to match by MAC
        matched = None
        if scapy_mac and scapy_mac != 'FF:FF:FF:FF:FF:FF':
            for friendly, info in interface_map.items():
                if info['mac'] == scapy_mac:
                    matched = friendly
                    break
        
        if matched:
            info = interface_map[matched]
            print(f"  ✓ Matched to: {matched}")
            print(f"    IP: {info['ip']}, MAC: {info['mac']}")
        else:
            print(f"  ✗ No match found (Scapy MAC: {scapy_mac})")
        print()
except Exception as e:
    print(f"  ✗ Matching failed: {e}")

# Route Table Analysis
section("Scapy Route Table")
try:
    from scapy.all import conf
    print(f"Total routes: {len(conf.route.routes)}\n")
    print("Default routes (gw != 0.0.0.0):")
    
    for entry in conf.route.routes:
        if len(entry) >= 5:
            dst, mask, gw, iface, src = entry[:5]
            if gw and gw != '0.0.0.0':
                print(f"  gw={gw} src={src} iface={iface[:40]}")
except Exception as e:
    print(f"  ✗ Route table error: {e}")

# Final Summary
section("SUMMARY")
print("Interface Map (from ipconfig):")
for name, info in interface_map.items():
    status = "✓" if info['ip'] not in ('0.0.0.0', '127.0.0.1') else "✗"
    print(f"  {status} {name}: IP={info['ip']}, MAC={info['mac']}")

print("\nConnected interfaces (from netsh):")
for name in connected_ifaces:
    print(f"  • {name}")

print("\n" + "="*60)
print("If interfaces aren't matching, check:")
print("1. MAC addresses should match between ipconfig and Scapy")
print("2. Scapy names are \\\\Device\\\\NPF_{GUID} format")
print("3. Use the GUID to correlate with registry if needed")
print("="*60)
