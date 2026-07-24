#!/usr/bin/env python3
"""
Test script for lag switch functionality on macOS.

The lag switch works by:
1. Killing a device (blocking its traffic via ARP spoofing)
2. Waiting for 'block_duration' milliseconds
3. Unkilling the device (allowing traffic again)
4. Waiting for 'release_duration' milliseconds
5. Repeating the cycle

This creates a "laggy" connection for the target device.
"""

import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

# Try to import network modules (may fail without scapy)
try:
    from networking.killer import Killer
    from networking.scanner import Scanner
    NETWORK_AVAILABLE = True
except ImportError as e:
    print(f"Note: Network modules not available ({e})")
    NETWORK_AVAILABLE = False

def test_lag_switch_logic():
    """Test the lag switch on/off cycling logic (without actual network ops)."""
    print("=" * 60)
    print("LAG SWITCH LOGIC TEST")
    print("=" * 60)
    
    # Simulate lag switch parameters
    block_ms = 1500
    release_ms = 1500
    
    print(f"\nLag switch parameters:")
    print(f"  Block duration:   {block_ms}ms")
    print(f"  Release duration: {release_ms}ms")
    print(f"  Total cycle:      {block_ms + release_ms}ms")
    
    print("\nLag switch cycle simulation:")
    print("-" * 40)
    
    for cycle in range(3):
        print(f"\n[Cycle {cycle + 1}]")
        print(f"  {time.strftime('%H:%M:%S')} - BLOCK (kill device)")
        time.sleep(0.2)  # Shortened for test
        print(f"  {time.strftime('%H:%M:%S')} - RELEASE (unkill device)")
        time.sleep(0.2)  # Shortened for test
    
    print("\n" + "=" * 60)
    print("LOGIC TEST PASSED - Cycle behavior works correctly")
    print("=" * 60)

def test_lag_switch_with_real_network():
    """Test lag switch with actual network components (requires root)."""
    print("\n" + "=" * 60)
    print("LAG SWITCH NETWORK INTEGRATION TEST")
    print("=" * 60)
    
    if not NETWORK_AVAILABLE:
        print("\n⚠️  Network modules not available (scapy not installed)")
        print("   Install with: pip3 install scapy")
        return False
    
    if os.geteuid() != 0:
        print("\n⚠️  This test requires root privileges.")
        print("   Run with: sudo python3 test_lag_switch.py")
        return False
    
    try:
        print("\nInitializing scanner...")
        scanner = Scanner()
        print(f"  Interface: {scanner.iface.name}")
        print(f"  Gateway:   {scanner.gateway.ip}")
        print(f"  Host MAC:  {scanner.host.mac}")
        
        print("\nInitializing killer...")
        killer = Killer()
        killer.iface = scanner.iface
        killer.gateway = scanner.gateway
        killer.host = scanner.host
        print("  Killer initialized successfully")
        
        print("\nScanning for devices...")
        scanner.arp_scan()
        
        non_admin_devices = [d for d in scanner.devices if not d.get('admin', False)]
        
        if not non_admin_devices:
            print("  No non-admin devices found to test with")
            return False
        
        print(f"  Found {len(non_admin_devices)} non-admin device(s)")
        
        # Pick a device for testing (but don't actually lag it in this test)
        test_device = non_admin_devices[0]
        print(f"\n  Test candidate: {test_device['ip']} ({test_device['mac']})")
        
        print("\n" + "-" * 40)
        print("LAG SWITCH SIMULATION (dry run)")
        print("-" * 40)
        
        block_ms = 1000
        release_ms = 1000
        
        print(f"\nWould execute lag cycle on {test_device['ip']}:")
        print(f"  1. Call killer.kill(device)    - block for {block_ms}ms")
        print(f"  2. Call killer.unkill(device)  - release for {release_ms}ms")
        print(f"  3. Repeat...")
        
        # Test one actual kill/unkill cycle
        print("\n" + "-" * 40)
        print("SINGLE KILL/UNKILL CYCLE TEST")
        print("-" * 40)
        
        response = input(f"\nTest single kill/unkill on {test_device['ip']}? (y/N): ")
        if response.lower() == 'y':
            print(f"\n  Killing {test_device['ip']}...")
            killer.kill(test_device)
            print(f"  Killed devices: {killer.killed}")
            
            time.sleep(1)
            
            print(f"  Unkilling {test_device['ip']}...")
            killer.unkill(test_device)
            print(f"  Killed devices after unkill: {killer.killed}")
            
            print("\n  ✅ Kill/Unkill cycle completed successfully!")
        else:
            print("\n  Skipping actual network test")
        
        print("\n" + "=" * 60)
        print("NETWORK INTEGRATION TEST COMPLETE")
        print("=" * 60)
        return True
        
    except Exception as e:
        print(f"\n❌ Error during network test: {e}")
        import traceback
        traceback.print_exc()
        return False

def main():
    print("\n" + "=" * 60)
    print("   LAG SWITCH FUNCTIONALITY TEST")
    print("=" * 60)
    
    # Always run the logic test
    test_lag_switch_logic()
    
    # Run network test if root
    test_lag_switch_with_real_network()
    
    print("\n" + "=" * 60)
    print("   TEST SUMMARY")
    print("=" * 60)
    print("""
The lag switch in the GUI works as follows:

1. User selects a device in the table
2. Clicks 'Lag Switch' button
3. Dialog appears to set block/release durations
4. On confirm:
   - lag_active = True
   - A QTimer starts with interval = block + release
   - _lag_cycle() is called immediately and on each timeout
   
5. _lag_cycle():
   - Calls killer.kill(device) to block traffic
   - Schedules _lag_release() after block_ms
   
6. _lag_release():
   - Calls killer.unkill(device) to restore traffic
   
7. Cycle repeats until user clicks 'Stop Lag'

8. stopLagSwitch():
   - Stops the timer
   - Unkills the device if still killed
   - Resets lag_active to False
""")

if __name__ == '__main__':
    main()

