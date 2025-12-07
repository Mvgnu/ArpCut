#!/usr/bin/env python3
"""
Comprehensive network diagnostic for Windows
Run as Administrator for full functionality
"""
import sys
import os
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
    'tests': {}
}

print("="*60)
print(" ELMOCUT NETWORK DIAGNOSTIC")
print("="*60)
print(f"Platform: {sys.platform}")
print(f"Python: {sys.version}")
print(f"Time: {results['timestamp']}")

# Test 1: Imports
section("1. Module Imports")
try:
    from tools.utils import terminal, get_ifaces, get_default_iface, get_my_ip, get_gateway_ip, get_gateway_mac
    from networking.ifaces import NetFace
    ok("Core utils imported")
    results['tests']['imports_utils'] = 'pass'
except Exception as e:
    fail(f"Utils import failed: {e}")
    results['tests']['imports_utils'] = f'fail: {e}'

try:
    from networking.killer import Killer
    from networking.scanner import Scanner
    ok("Killer and Scanner imported")
    results['tests']['imports_networking'] = 'pass'
except Exception as e:
    fail(f"Networking import failed: {e}")
    results['tests']['imports_networking'] = f'fail: {e}'

try:
    from tools.pfctl import pf_self_check, block_all_for, unblock_all_for
    ok("Firewall module imported")
    results['tests']['imports_firewall'] = 'pass'
except Exception as e:
    fail(f"Firewall import failed: {e}")
    results['tests']['imports_firewall'] = f'fail: {e}'

try:
    from scapy.all import conf, get_if_list, get_if_hwaddr, ARP, Ether, sendp
    ok("Scapy imported")
    results['tests']['imports_scapy'] = 'pass'
except Exception as e:
    fail(f"Scapy import failed: {e}")
    results['tests']['imports_scapy'] = f'fail: {e}'

# Test 2: Interface Detection
section("2. Interface Detection")
try:
    ifaces = list(get_ifaces())
    results['tests']['iface_count'] = len(ifaces)
    if ifaces:
        ok(f"Found {len(ifaces)} interfaces")
        for iface in ifaces:
            status = []
            if iface.ip and iface.ip not in ('0.0.0.0', '127.0.0.1'):
                status.append(f"IP={iface.ip}")
            else:
                status.append("no IP")
            if iface.mac and iface.mac != 'FF:FF:FF:FF:FF:FF':
                status.append(f"MAC={iface.mac}")
            else:
                status.append("no MAC")
            info(f"{iface.name}: {', '.join(status)}")
    else:
        fail("No interfaces found!")
except Exception as e:
    fail(f"Interface detection failed: {e}")
    results['tests']['iface_detection'] = f'fail: {e}'

# Test 3: Default Interface
section("3. Default Interface")
try:
    default = get_default_iface()
    results['tests']['default_iface'] = {
        'name': default.name,
        'guid': default.guid[:50] if len(default.guid) > 50 else default.guid,
        'ip': default.ip,
        'mac': default.mac
    }
    if default.name == 'NULL':
        fail("Default interface is NULL!")
    else:
        ok(f"Name: {default.name}")
        info(f"GUID: {default.guid[:60]}..." if len(default.guid) > 60 else f"GUID: {default.guid}")
        if default.ip and default.ip not in ('0.0.0.0', '127.0.0.1'):
            ok(f"IP: {default.ip}")
        else:
            warn(f"IP: {default.ip} (invalid)")
        if default.mac and default.mac != 'FF:FF:FF:FF:FF:FF':
            ok(f"MAC: {default.mac}")
        else:
            warn(f"MAC: {default.mac} (invalid)")
except Exception as e:
    fail(f"Default interface failed: {e}")
    results['tests']['default_iface'] = f'fail: {e}'

# Test 4: IP Detection
section("4. IP Detection")
try:
    default = get_default_iface()
    if default.name != 'NULL':
        my_ip = get_my_ip(default.guid)
        results['tests']['my_ip'] = my_ip
        if my_ip and my_ip not in ('127.0.0.1', '0.0.0.0'):
            ok(f"My IP: {my_ip}")
        else:
            fail(f"My IP: {my_ip} (detection failed)")
    else:
        fail("Cannot test - no valid interface")
        results['tests']['my_ip'] = 'skipped'
except Exception as e:
    fail(f"IP detection failed: {e}")
    results['tests']['my_ip'] = f'fail: {e}'

# Test 5: Gateway Detection
section("5. Gateway Detection")
try:
    default = get_default_iface()
    if default.name != 'NULL':
        gw_ip = get_gateway_ip(default.guid)
        results['tests']['gateway_ip'] = gw_ip
        if gw_ip and gw_ip != '0.0.0.0':
            ok(f"Gateway IP: {gw_ip}")
            # Try to get gateway MAC
            my_ip = get_my_ip(default.guid)
            gw_mac = get_gateway_mac(my_ip, gw_ip)
            results['tests']['gateway_mac'] = gw_mac
            if gw_mac and gw_mac != 'FF:FF:FF:FF:FF:FF':
                ok(f"Gateway MAC: {gw_mac}")
            else:
                warn(f"Gateway MAC: {gw_mac} (resolution failed)")
        else:
            fail(f"Gateway IP: {gw_ip} (detection failed)")
    else:
        fail("Cannot test - no valid interface")
        results['tests']['gateway_ip'] = 'skipped'
except Exception as e:
    fail(f"Gateway detection failed: {e}")
    results['tests']['gateway_ip'] = f'fail: {e}'

# Test 6: Scapy Route Table
section("6. Scapy Route Table")
try:
    routes = conf.route.routes[:10]  # First 10 routes
    results['tests']['route_count'] = len(conf.route.routes)
    ok(f"Route table has {len(conf.route.routes)} entries")
    for r in routes[:5]:
        if len(r) >= 5:
            dst, mask, gw, iface, src = r[:5]
            if gw and gw != '0.0.0.0':
                info(f"dst={dst} gw={gw} iface={iface[:30]} src={src}")
except Exception as e:
    fail(f"Route table failed: {e}")
    results['tests']['route_table'] = f'fail: {e}'

# Test 7: Scapy Interface Operations
section("7. Scapy Interface Operations")
try:
    scapy_ifaces = get_if_list()
    results['tests']['scapy_iface_count'] = len(scapy_ifaces)
    ok(f"Scapy sees {len(scapy_ifaces)} interfaces")
    for iface in scapy_ifaces[:5]:
        try:
            mac = get_if_hwaddr(iface)
            info(f"{iface[:40]}: MAC={mac}")
        except Exception as e:
            info(f"{iface[:40]}: MAC error - {e}")
except Exception as e:
    fail(f"Scapy interface ops failed: {e}")
    results['tests']['scapy_ifaces'] = f'fail: {e}'

# Test 8: Terminal Commands
section("8. Terminal Commands")
test_cmds = {
    'ipconfig': 'ipconfig',
    'arp': 'arp -a',
    'netsh': 'netsh interface show interface',
}
for name, cmd in test_cmds.items():
    try:
        output = terminal(cmd)
        if output:
            ok(f"{name}: {len(output)} chars")
            results['tests'][f'terminal_{name}'] = len(output)
        else:
            warn(f"{name}: no output")
            results['tests'][f'terminal_{name}'] = 0
    except Exception as e:
        fail(f"{name}: {e}")
        results['tests'][f'terminal_{name}'] = f'fail: {e}'

# Test 9: Firewall Check
section("9. Firewall Access")
try:
    fw_ok = pf_self_check()
    results['tests']['firewall'] = 'accessible' if fw_ok else 'not accessible'
    if fw_ok:
        ok("Firewall is accessible")
    else:
        warn("Firewall not accessible (may need admin)")
except Exception as e:
    fail(f"Firewall check failed: {e}")
    results['tests']['firewall'] = f'fail: {e}'

# Test 10: ARP Cache
section("10. ARP Cache")
try:
    default = get_default_iface()
    my_ip = get_my_ip(default.guid) if default.name != 'NULL' else None
    if my_ip and my_ip not in ('127.0.0.1', '0.0.0.0'):
        if sys.platform.startswith('win'):
            arp_output = terminal(f'arp -a -N {my_ip}')
        else:
            arp_output = terminal('arp -an')
        if arp_output:
            lines = [l.strip() for l in arp_output.split('\n') if l.strip()]
            ok(f"ARP cache has {len(lines)} lines")
            results['tests']['arp_cache'] = len(lines)
            for line in lines[:5]:
                info(line[:70])
        else:
            warn("ARP cache empty or inaccessible")
            results['tests']['arp_cache'] = 0
    else:
        warn("Cannot test - no valid IP")
        results['tests']['arp_cache'] = 'skipped'
except Exception as e:
    fail(f"ARP cache failed: {e}")
    results['tests']['arp_cache'] = f'fail: {e}'

# Summary
section("SUMMARY")
passed = sum(1 for v in results['tests'].values() if v == 'pass' or (isinstance(v, (int, dict)) and v))
total = len(results['tests'])
print(f"\n  Tests: {passed}/{total} passed")

critical_checks = ['my_ip', 'gateway_ip', 'gateway_mac', 'default_iface']
critical_ok = True
for check in critical_checks:
    val = results['tests'].get(check)
    if isinstance(val, str) and ('fail' in val or val in ('0.0.0.0', '127.0.0.1', 'skipped')):
        critical_ok = False
    elif isinstance(val, dict) and val.get('ip') in ('0.0.0.0', '127.0.0.1', 'NULL'):
        critical_ok = False

if critical_ok:
    print("\n  ✓ All critical checks passed - Kill/One-Way Kill should work")
else:
    print("\n  ✗ Critical checks failed - networking features may not work")
    print("    Check: IP detection, Gateway detection, Interface detection")

# Save results
try:
    with open('diagnostic_results.json', 'w') as f:
        json.dump(results, f, indent=2, default=str)
    print(f"\n  Results saved to: diagnostic_results.json")
except Exception:
    pass

print("\n" + "="*60)
