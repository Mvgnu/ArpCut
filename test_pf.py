#!/usr/bin/env python3
"""Test pf blocking - run with sudo"""
import sys
import os
from subprocess import run, PIPE
import shutil

def cmd(c):
    print(f"$ {c}")
    r = run(c, shell=True, stdout=PIPE, stderr=PIPE, text=True)
    if r.stdout.strip():
        print(r.stdout.strip())
    if r.stderr.strip():
        for line in r.stderr.strip().split('\n'):
            if 'ALTQ' not in line and 'flushing' not in line.lower():
                print(f"  [err] {line}")
    return r

def main():
    print("=" * 60)
    print("PF DIRECT BLOCK TEST (no anchor)")
    print("=" * 60)
    
    # Backup current pf.conf
    print("\n[1] Backing up pf.conf...")
    shutil.copy('/etc/pf.conf', '/tmp/pf.conf.backup')
    print("  Saved to /tmp/pf.conf.backup")
    
    # Read current pf.conf
    with open('/etc/pf.conf', 'r') as f:
        original = f.read()
    
    # Create new pf.conf with block rule at the TOP
    print("\n[2] Adding block rule to TOP of pf.conf...")
    block_rule = "block drop quick on en0 from any to 8.8.8.8\n"
    with open('/etc/pf.conf', 'w') as f:
        f.write(block_rule)
        f.write(original)
    
    # Reload pf
    print("\n[3] Reloading pf...")
    cmd("pfctl -f /etc/pf.conf")
    
    # Show rules
    print("\n[4] Current rules (should see block at top):")
    cmd("pfctl -s rules | head -10")
    
    # Test ping
    print("\n[5] Testing if 8.8.8.8 is blocked:")
    r = cmd("ping -c 1 -t 2 8.8.8.8")
    if r.returncode != 0:
        print("  ✓ BLOCKED - pf works when rule is in main config!")
    else:
        print("  ✗ NOT BLOCKED - something else is wrong")
    
    # Restore original
    print("\n[6] Restoring original pf.conf...")
    shutil.copy('/tmp/pf.conf.backup', '/etc/pf.conf')
    cmd("pfctl -f /etc/pf.conf")
    print("  Restored!")
    
    print("\n" + "=" * 60)
    print("CONCLUSION:")
    print("If [5] showed BLOCKED, anchors are the problem.")
    print("We need to add rules to main pf.conf, not anchors.")
    print("=" * 60)

if __name__ == '__main__':
    if os.geteuid() != 0:
        print("Run with: sudo python3 test_pf.py")
        sys.exit(1)
    main()

