#!/usr/bin/env python3
"""
Comprehensive diagnostic for Kill and One-Way Kill functionality
Tests: Interface detection, ARP spoofing, packet forwarding, firewall rules
Run as Administrator on Windows / sudo on macOS
"""
import sys
import os
import time
import json
from datetime import datetime

sys.path.append(os.path.join(os.getcwd(), 'src'))

def section(title):
    print(f"\n{'='*60}")
    print(f" {title}")
    print('='*60)

def ok(msg):
    print(f"  ✓ {msg}")

def warn(msg):
    print(f"  ⚠ {msg}")

def fail(msg):
    print(f"  ✗ {msg}")

def info(msg):
    print(f"    {msg}")

results = {
    'timestamp': datetime.now().isoformat(),
    'platform': sys.platform,
    'python': sys.version,
    'tests': {},
    'critical_issues': []
}

print("="*60)
print(" ELMOCUT KILL FUNCTIONALITY DIAGNOSTIC")
print("="*60)
print(f"Platform: {sys.platform}")
print(f"Python: {sys.version}")
print(f"Time: {results['timestamp']}")

# Check if running as admin/root
section("0. Privilege Check")
is_admin = False
if sys.platform.startswith('win'):
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        pass
else:
    is_admin = os.geteuid() == 0

if is_admin:
    ok("Running with admin/root privileges")
    results['tests']['admin'] = True
else:
    fail("NOT running as admin/root - some tests will fail!")
    results['tests']['admin'] = False
    results['critical_issues'].append("Not running as admin/root")

# Test 1: Core Imports
section("1. Core Imports")
try:
    from tools.utils import get_ifaces, get_default_iface, get_my_ip, get_gateway_ip, get_gateway_mac
    from networking.ifaces import NetFace
    from networking.killer import Killer
    from networking.scanner import Scanner
    from networking.forwarder import MitmForwarder
    from tools.pfctl import pf_self_check, block_all_for, unblock_all_for, ensure_pf_enabled, install_anchor
    from scapy.all import conf, get_if_list, ARP, Ether, sendp, sr1, AsyncSniffer
    ok("All modules imported successfully")
    results['tests']['imports'] = 'pass'
except Exception as e:
    fail(f"Import failed: {e}")
    results['tests']['imports'] = f'fail: {e}'
    results['critical_issues'].append(f"Import failed: {e}")

# Test 2: Interface Detection
section("2. Interface Detection")
try:
    default = get_default_iface()
    results['tests']['interface'] = {
        'name': default.name,
        'guid': default.guid[:60] if len(default.guid) > 60 else default.guid,
        'ip': default.ip,
        'mac': default.mac
    }
    
    if default.name == 'NULL':
        fail("Default interface is NULL!")
        results['critical_issues'].append("Default interface is NULL")
    else:
        ok(f"Name: {default.name}")
        
    # Check guid format on Windows
    if sys.platform.startswith('win'):
        if default.guid.startswith('\\Device\\NPF_'):
            ok(f"GUID format correct: {default.guid[:50]}...")
        else:
            fail(f"GUID format WRONG - expected \\Device\\NPF_... got: {default.guid[:40]}")
            results['critical_issues'].append("GUID format incorrect - Scapy operations will fail")
    else:
        ok(f"GUID: {default.guid}")
    
    if default.ip and default.ip not in ('0.0.0.0', '127.0.0.1'):
        ok(f"IP: {default.ip}")
    else:
        fail(f"IP: {default.ip} (invalid!)")
        results['critical_issues'].append(f"Invalid IP: {default.ip}")
        
    if default.mac and default.mac != 'FF:FF:FF:FF:FF:FF':
        ok(f"MAC: {default.mac}")
    else:
        fail(f"MAC: {default.mac} (invalid!)")
        results['critical_issues'].append(f"Invalid MAC: {default.mac}")
        
except Exception as e:
    fail(f"Interface detection failed: {e}")
    results['tests']['interface'] = f'fail: {e}'
    results['critical_issues'].append(f"Interface detection failed: {e}")

# Test 3: Gateway Detection
section("3. Gateway Detection")
try:
    default = get_default_iface()
    gw_ip = get_gateway_ip(default.guid)
    results['tests']['gateway_ip'] = gw_ip
    
    if gw_ip and gw_ip != '0.0.0.0':
        ok(f"Gateway IP: {gw_ip}")
        
        my_ip = get_my_ip(default.guid)
        gw_mac = get_gateway_mac(my_ip, gw_ip)
        results['tests']['gateway_mac'] = gw_mac
        
        if gw_mac and gw_mac != 'FF:FF:FF:FF:FF:FF':
            ok(f"Gateway MAC: {gw_mac}")
        else:
            fail(f"Gateway MAC resolution failed: {gw_mac}")
            results['critical_issues'].append("Cannot resolve gateway MAC - ARP spoofing will fail")
    else:
        fail(f"Gateway IP detection failed: {gw_ip}")
        results['critical_issues'].append("Gateway IP detection failed")
except Exception as e:
    fail(f"Gateway detection failed: {e}")
    results['tests']['gateway'] = f'fail: {e}'
    results['critical_issues'].append(f"Gateway detection failed: {e}")

# Test 4: Scanner Initialization
section("4. Scanner Initialization")
try:
    scanner = Scanner()
    scanner.init()
    
    results['tests']['scanner'] = {
        'my_ip': scanner.my_ip,
        'router_ip': scanner.router_ip,
        'router_mac': scanner.router_mac,
        'iface_name': scanner.iface.name,
        'iface_guid': scanner.iface.guid[:50] if len(scanner.iface.guid) > 50 else scanner.iface.guid
    }
    
    if scanner.my_ip and scanner.my_ip not in ('0.0.0.0', '127.0.0.1'):
        ok(f"Scanner my_ip: {scanner.my_ip}")
    else:
        fail(f"Scanner my_ip: {scanner.my_ip} (invalid!)")
        results['critical_issues'].append("Scanner cannot detect local IP")
        
    if scanner.router_ip and scanner.router_ip != '0.0.0.0':
        ok(f"Scanner router_ip: {scanner.router_ip}")
    else:
        fail(f"Scanner router_ip: {scanner.router_ip} (invalid!)")
        results['critical_issues'].append("Scanner cannot detect router IP")
        
    if scanner.router_mac and scanner.router_mac != 'FF:FF:FF:FF:FF:FF':
        ok(f"Scanner router_mac: {scanner.router_mac}")
    else:
        fail(f"Scanner router_mac: {scanner.router_mac} (invalid!)")
        results['critical_issues'].append("Scanner cannot detect router MAC")
        
except Exception as e:
    fail(f"Scanner init failed: {e}")
    import traceback
    traceback.print_exc()
    results['tests']['scanner'] = f'fail: {e}'
    results['critical_issues'].append(f"Scanner init failed: {e}")

# Test 5: Killer Initialization
section("5. Killer Initialization")
try:
    killer = Killer()
    
    results['tests']['killer'] = {
        'iface_name': killer.iface.name,
        'iface_guid': killer.iface.guid[:50] if len(killer.iface.guid) > 50 else killer.iface.guid,
        'iface_mac': killer.iface.mac,
        'router': killer.router
    }
    
    ok(f"Killer initialized on: {killer.iface.name}")
    ok(f"Killer iface.guid: {killer.iface.guid[:50]}...")
    
    # Check conf.iface
    conf_iface = str(conf.iface)
    results['tests']['conf_iface'] = conf_iface[:50]
    
    if sys.platform.startswith('win'):
        if conf_iface.startswith('\\Device\\NPF_'):
            ok(f"conf.iface correctly set: {conf_iface[:50]}...")
        else:
            fail(f"conf.iface WRONG format: {conf_iface[:40]}")
            results['critical_issues'].append("conf.iface not set to Scapy name - sendp will fail")
    else:
        ok(f"conf.iface: {conf_iface}")
        
except Exception as e:
    fail(f"Killer init failed: {e}")
    import traceback
    traceback.print_exc()
    results['tests']['killer'] = f'fail: {e}'
    results['critical_issues'].append(f"Killer init failed: {e}")

# Test 6: ARP Packet Construction
section("6. ARP Packet Construction")
try:
    default = get_default_iface()
    gw_ip = get_gateway_ip(default.guid)
    my_ip = get_my_ip(default.guid)
    gw_mac = get_gateway_mac(my_ip, gw_ip)
    
    # Construct a test ARP packet (don't send)
    test_pkt = Ether(dst=gw_mac)/ARP(
        op=2,
        psrc=my_ip,
        hwsrc=default.mac,
        pdst=gw_ip,
        hwdst=gw_mac
    )
    
    ok(f"ARP packet constructed successfully")
    info(f"Ether.dst: {test_pkt[Ether].dst}")
    info(f"ARP.psrc: {test_pkt[ARP].psrc}")
    info(f"ARP.hwsrc: {test_pkt[ARP].hwsrc}")
    info(f"ARP.pdst: {test_pkt[ARP].pdst}")
    info(f"ARP.hwdst: {test_pkt[ARP].hwdst}")
    results['tests']['arp_construction'] = 'pass'
    
except Exception as e:
    fail(f"ARP construction failed: {e}")
    results['tests']['arp_construction'] = f'fail: {e}'
    results['critical_issues'].append(f"ARP construction failed: {e}")

# Test 7: Scapy sendp Test (requires admin)
section("7. Scapy sendp Test")
if is_admin:
    try:
        default = get_default_iface()
        iface_to_use = default.guid
        
        # Send a harmless ARP request to ourselves
        test_pkt = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(
            op=1,  # ARP request
            pdst=get_my_ip(default.guid)
        )
        
        sendp(test_pkt, iface=iface_to_use, verbose=0, count=1)
        ok(f"sendp() succeeded on {iface_to_use[:40]}...")
        results['tests']['sendp'] = 'pass'
        
    except Exception as e:
        fail(f"sendp() failed: {e}")
        import traceback
        traceback.print_exc()
        results['tests']['sendp'] = f'fail: {e}'
        results['critical_issues'].append(f"sendp failed: {e} - Kill will not work")
else:
    warn("Skipped - requires admin privileges")
    results['tests']['sendp'] = 'skipped'

# Test 8: AsyncSniffer Test (requires admin)
section("8. AsyncSniffer Test")
if is_admin:
    try:
        default = get_default_iface()
        iface_to_use = default.guid
        
        packets_seen = []
        def packet_callback(pkt):
            packets_seen.append(1)
        
        sniffer = AsyncSniffer(
            iface=iface_to_use,
            filter="arp",
            prn=packet_callback,
            store=False,
            count=5
        )
        sniffer.start()
        time.sleep(0.5)
        sniffer.stop()
        
        ok(f"AsyncSniffer works on {iface_to_use[:40]}...")
        info(f"Captured {len(packets_seen)} ARP packets in 0.5s")
        results['tests']['sniffer'] = 'pass'
        
    except Exception as e:
        fail(f"AsyncSniffer failed: {e}")
        import traceback
        traceback.print_exc()
        results['tests']['sniffer'] = f'fail: {e}'
        results['critical_issues'].append(f"AsyncSniffer failed: {e} - Forwarder will not work")
else:
    warn("Skipped - requires admin privileges")
    results['tests']['sniffer'] = 'skipped'

# Test 9: Firewall Access
section("9. Firewall Access")
try:
    if sys.platform.startswith('win'):
        from tools.utils import terminal
        result = terminal('netsh advfirewall show allprofiles state')
        if result and 'ON' in result:
            ok("Windows Firewall accessible")
            results['tests']['firewall'] = 'accessible'
        else:
            warn("Windows Firewall may not be accessible")
            results['tests']['firewall'] = 'limited'
    else:
        if is_admin:
            pf_ok = ensure_pf_enabled()
            anchor_ok = install_anchor()
            if pf_ok and anchor_ok:
                ok("pf enabled and anchor installed")
                results['tests']['firewall'] = 'accessible'
            else:
                warn(f"pf: {pf_ok}, anchor: {anchor_ok}")
                results['tests']['firewall'] = 'limited'
        else:
            warn("Skipped - requires root")
            results['tests']['firewall'] = 'skipped'
except Exception as e:
    fail(f"Firewall check failed: {e}")
    results['tests']['firewall'] = f'fail: {e}'

# Test 10: MitmForwarder Configuration Check
section("10. MitmForwarder Configuration")
try:
    forwarder = MitmForwarder()
    
    # Check that drop flags are properly initialized
    if hasattr(forwarder, 'drop_from_victim') and hasattr(forwarder, 'drop_to_victim'):
        ok("MitmForwarder has drop_from_victim and drop_to_victim flags")
        info(f"Initial drop_from_victim: {forwarder.drop_from_victim}")
        info(f"Initial drop_to_victim: {forwarder.drop_to_victim}")
        results['tests']['forwarder_config'] = 'pass'
    else:
        fail("MitmForwarder missing drop flags!")
        results['critical_issues'].append("MitmForwarder missing drop flags - One-Way Kill will not work")
        results['tests']['forwarder_config'] = 'fail'
        
except Exception as e:
    fail(f"MitmForwarder check failed: {e}")
    results['tests']['forwarder_config'] = f'fail: {e}'

# Test 11: One-Way Kill Logic Check
section("11. One-Way Kill Logic Check")
try:
    # Check that Killer has the one_way_kill method
    killer = Killer()
    
    if hasattr(killer, 'one_way_kill'):
        ok("Killer.one_way_kill() method exists")
    else:
        fail("Killer.one_way_kill() method MISSING!")
        results['critical_issues'].append("one_way_kill method missing")
        
    if hasattr(killer, '_start_one_way_forwarder'):
        ok("Killer._start_one_way_forwarder() method exists")
    else:
        fail("Killer._start_one_way_forwarder() method MISSING!")
        results['critical_issues'].append("_start_one_way_forwarder method missing")
        
    if hasattr(killer, '_enforce_pf_block'):
        ok("Killer._enforce_pf_block() method exists")
    else:
        fail("Killer._enforce_pf_block() method MISSING!")
        results['critical_issues'].append("_enforce_pf_block method missing")
        
    if hasattr(killer, 'forwarders'):
        ok("Killer.forwarders dict exists")
    else:
        fail("Killer.forwarders dict MISSING!")
        results['critical_issues'].append("forwarders dict missing")
        
    results['tests']['one_way_kill_logic'] = 'pass'
    
except Exception as e:
    fail(f"One-Way Kill logic check failed: {e}")
    results['tests']['one_way_kill_logic'] = f'fail: {e}'

# Test 12: Network Scan Test
section("12. Network Scan Test")
if is_admin:
    try:
        scanner = Scanner()
        scanner.init()
        
        # Try ARP scan with short timeout
        info("Attempting quick ARP scan...")
        from scapy.all import arping
        
        scan_result = arping(
            f"{scanner.router_ip}/24",
            iface=scanner.iface.guid,
            verbose=0,
            timeout=2
        )
        
        devices_found = len(scan_result[0])
        ok(f"ARP scan found {devices_found} devices")
        results['tests']['arp_scan'] = devices_found
        
        if devices_found == 0:
            warn("No devices found - this may indicate a problem")
            results['critical_issues'].append("ARP scan found 0 devices")
        else:
            for i, (sent, recv) in enumerate(scan_result[0][:5]):
                info(f"  {recv.psrc} -> {recv.src}")
                
    except Exception as e:
        fail(f"ARP scan failed: {e}")
        import traceback
        traceback.print_exc()
        results['tests']['arp_scan'] = f'fail: {e}'
        results['critical_issues'].append(f"ARP scan failed: {e}")
else:
    warn("Skipped - requires admin privileges")
    results['tests']['arp_scan'] = 'skipped'

# Summary
section("SUMMARY")
print(f"\n  Platform: {sys.platform}")
print(f"  Admin/Root: {'Yes' if is_admin else 'No'}")

passed = sum(1 for v in results['tests'].values() if v == 'pass' or v == 'accessible' or (isinstance(v, int) and v > 0))
total = len(results['tests'])
print(f"  Tests: {passed}/{total} passed")

if results['critical_issues']:
    print(f"\n  CRITICAL ISSUES ({len(results['critical_issues'])}):")
    for issue in results['critical_issues']:
        print(f"    ✗ {issue}")
else:
    print("\n  ✓ No critical issues found")

# Diagnosis
section("DIAGNOSIS")
if not is_admin:
    print("  Run this test as Administrator (Windows) or with sudo (macOS/Linux)")
    print("  Many features require elevated privileges to work.")
elif results['critical_issues']:
    print("  Issues detected that will prevent Kill/One-Way Kill from working:")
    for issue in results['critical_issues']:
        print(f"    → {issue}")
    print("\n  Common fixes:")
    print("    - Ensure Npcap is installed (Windows)")
    print("    - Check network interface is connected")
    print("    - Verify firewall isn't blocking the app")
else:
    print("  ✓ All systems appear operational")
    print("  If Kill/One-Way Kill still doesn't work, the issue may be:")
    print("    - Target device not responding to ARP")
    print("    - Network isolation/AP isolation enabled")
    print("    - VLAN separation between devices")

# Save results
try:
    with open('kill_diagnostic_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved to: kill_diagnostic_results.json")
except Exception:
    pass

print("\n" + "="*60)


