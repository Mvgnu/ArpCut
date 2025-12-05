#!/usr/bin/env python3
"""
Windows compatibility test - verifies all code paths work
Run on Windows or with: python test_windows_compat.py
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

def section(title):
    print(f"\n{'='*50}")
    print(f" {title}")
    print('='*50)

def ok(msg):
    print(f"  ✓ {msg}")

def fail(msg):
    print(f"  ✗ {msg}")

all_passed = True

print("="*50)
print(" ELMOCUT COMPATIBILITY TEST")
print("="*50)
print(f"Platform: {sys.platform}")
print(f"Python: {sys.version}")

# Test 1: Core Imports
section("1. Core Module Imports")
modules = [
    ('tools.utils', 'Utility functions'),
    ('tools.pfctl', 'Firewall control'),
    ('networking.killer', 'Kill functionality'),
    ('networking.scanner', 'Network scanner'),
    ('networking.forwarder', 'Traffic forwarder'),
    ('networking.ifaces', 'Interface handling'),
    ('networking.sniffer', 'Traffic sniffer'),
]

for mod_name, desc in modules:
    try:
        __import__(mod_name)
        ok(f"{desc} ({mod_name})")
    except Exception as e:
        fail(f"{desc} ({mod_name}): {e}")
        all_passed = False

# Test 2: GUI Imports (may fail without display)
section("2. GUI Module Imports")
gui_modules = [
    ('gui.main', 'Main window'),
    ('gui.traffic', 'Traffic window'),
]

for mod_name, desc in gui_modules:
    try:
        __import__(mod_name)
        ok(f"{desc} ({mod_name})")
    except ImportError as e:
        if 'PyQt5' in str(e) or 'display' in str(e).lower():
            print(f"  ⚠ {desc}: PyQt5/display not available (expected in headless)")
        else:
            fail(f"{desc}: {e}")
            all_passed = False
    except Exception as e:
        fail(f"{desc}: {e}")
        all_passed = False

# Test 3: Key Functions Exist
section("3. Key Function Availability")
try:
    from tools.utils import (
        get_ifaces, get_default_iface, get_my_ip, get_gateway_ip,
        get_gateway_mac, terminal, good_mac, is_connected
    )
    ok("All utility functions available")
except ImportError as e:
    fail(f"Missing utility function: {e}")
    all_passed = False

try:
    from tools.pfctl import (
        ensure_pf_enabled, install_anchor, block_all_for,
        unblock_all_for, pf_self_check
    )
    ok("All firewall functions available")
except ImportError as e:
    fail(f"Missing firewall function: {e}")
    all_passed = False

try:
    from networking.killer import Killer
    k = Killer.__init__  # Check class exists
    ok("Killer class available")
except Exception as e:
    fail(f"Killer class: {e}")
    all_passed = False

try:
    from networking.scanner import Scanner
    s = Scanner.__init__
    ok("Scanner class available")
except Exception as e:
    fail(f"Scanner class: {e}")
    all_passed = False

try:
    from networking.forwarder import MitmForwarder
    f = MitmForwarder.__init__
    ok("MitmForwarder class available")
except Exception as e:
    fail(f"MitmForwarder class: {e}")
    all_passed = False

# Test 4: Platform-specific code paths
section("4. Platform-Specific Code")
try:
    from tools.utils import get_ifaces
    # Just verify it doesn't crash
    ifaces = list(get_ifaces())
    ok(f"get_ifaces() returned {len(ifaces)} interfaces")
except Exception as e:
    fail(f"get_ifaces() failed: {e}")
    all_passed = False

try:
    from tools.utils import get_default_iface
    default = get_default_iface()
    if default.name != 'NULL':
        ok(f"get_default_iface() name: {default.name}")
        guid_display = default.guid[:50] + "..." if len(default.guid) > 50 else default.guid
        ok(f"get_default_iface() guid: {guid_display}")
        # Verify guid is the full Scapy name on Windows
        if sys.platform.startswith('win') and not default.guid.startswith('\\\\Device\\\\NPF_'):
            fail(f"GUID should start with \\\\Device\\\\NPF_ but got: {default.guid[:30]}")
            all_passed = False
    else:
        print(f"  ⚠ get_default_iface() returned NULL (may be normal)")
except Exception as e:
    fail(f"get_default_iface() failed: {e}")
    all_passed = False

# Test 5: Firewall functions (platform-aware)
section("5. Firewall Functions")
try:
    from tools.pfctl import pf_self_check
    result = pf_self_check()
    if result:
        ok("Firewall accessible")
    else:
        print("  ⚠ Firewall not accessible (may need admin)")
except Exception as e:
    fail(f"Firewall check failed: {e}")
    all_passed = False

# Test 6: Scapy Integration
section("6. Scapy Integration")
try:
    from scapy.all import conf, get_if_list, ARP, Ether
    ok("Scapy core imports work")
except Exception as e:
    fail(f"Scapy import failed: {e}")
    all_passed = False

try:
    from scapy.all import get_if_list
    ifaces = get_if_list()
    ok(f"Scapy sees {len(ifaces)} interfaces")
except Exception as e:
    fail(f"Scapy interface list failed: {e}")
    all_passed = False

try:
    from scapy.all import conf
    routes = len(conf.route.routes)
    ok(f"Scapy route table has {routes} entries")
except Exception as e:
    fail(f"Scapy route table failed: {e}")
    all_passed = False

# Test 7: Constants
section("7. Constants and Config")
try:
    from constants import DOCUMENTS_PATH, GLOBAL_MAC, DUMMY_IFACE
    ok(f"DOCUMENTS_PATH: {DOCUMENTS_PATH}")
    ok(f"GLOBAL_MAC: {GLOBAL_MAC}")
except Exception as e:
    fail(f"Constants failed: {e}")
    all_passed = False

# Summary
section("SUMMARY")
if all_passed:
    print("\n  ✓ All compatibility tests passed!")
    print("  The application should work on this platform.")
    sys.exit(0)
else:
    print("\n  ✗ Some tests failed")
    print("  Check the errors above for details.")
    sys.exit(1)
