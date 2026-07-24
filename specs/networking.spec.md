---
name: networking
description: "Core network engine: scanning, ARP spoofing, kernel/user-space forwarding, traffic sniffing"
status: active
paths:
  scanner: src/networking/scanner.py
  killer: src/networking/killer.py
  forwarder: src/networking/forwarder.py       # user-space fallback (traffic monitor)
  sniffer: src/networking/sniffer.py
  ifaces: src/networking/ifaces.py
  nicknames: src/networking/nicknames.py
  tests: tests/
exports:
  - Scanner
  - Killer
  - MitmForwarder
  - TrafficSniffer
  - NetFace
  - Nicknames
  - DeviceInfo
  - enable_ip_forwarding
consumes:
  - platform.get_default_iface
  - platform.get_iface_by_name
  - platform.get_my_ip
  - platform.get_gateway_ip
  - platform.get_gateway_mac
  - platform.get_vendor
  - platform.good_mac
  - platform.threaded
  - platform.terminal
  - firewall.block_all_for
  - firewall.unblock_all_for
verification:
  test: "python -m pytest tests/ -v"
  smoke: "PYTHONPATH=src python -c 'from networking.scanner import Scanner; Scanner().init()'"
---

# Networking Domain

The Qt-free core of ArpCut. Confirmed: no module here imports PyQt — the whole
domain is reusable behind the new controller and (later) the privileged helper.

## Components

### Scanner (`scanner.py`)
Discovers devices via ARP scan (one scapy `arping /24`) or threaded Ping scan
(`ThreadPoolExecutor`, `max_threads=8`, native `ping` per host), with a
`probe_ip()` escalation (arping /32 → ping → TCP-SYN to common ports → re-read
ARP cache). Device record is the canonical `DeviceInfo` TypedDict
(`ip, mac, vendor, type, name, admin`). Vendor via `manuf`; name via `Nicknames`.

### Killer (`killer.py`)
ARP-spoof engine: `kill`/`unkill` (re-poison every 2s — safe vs 30–120s cache),
`kill_all`/`unkill_all`, `one_way_kill`, `store`/`rekill_stored`. Holds a
persistent L2 socket to avoid Windows socket exhaustion. `enable_ip_forwarding()`
lives here and toggles the kernel forwarding sysctl (mac/linux only today).

### MitmForwarder (`forwarder.py`) — Windows fallback only
User-space forwarder (scapy `AsyncSniffer`, per-packet MAC rewrite + checksum
recompute). **The slow path — never the default.** `Killer` holds **no** forwarder
state anymore: the dead per-victim `forwarders` dict, `_start_one_way_forwarder`,
`_stop_forwarder` and `get_forwarder_stats` are removed. The only remaining user is
the traffic monitor's optional "forward mode", which is **redundant on mac/linux**
(the kernel forwards once `enable_ip_forwarding()` is on) and matters only on
Windows until WinDivert replaces it — at which point `forwarder.py` can be deleted.

### TrafficSniffer (`sniffer.py`)
Live per-device monitoring: flows, patterns, hex/last-packet inspection.

### NetFace (`ifaces.py`) / Nicknames (`nicknames.py`)
Interface data class (`name`, `guid`, `mac`, `ip`) and JSON-backed nickname store.

## Kernel-level forwarding (target)

Selective blocking forwards allowed traffic and drops the rest. Move forwarding
into the kernel everywhere:

- **macOS**: `sysctl net.inet.ip.forwarding=1` + `pf` filter (works today; harden).
- **Linux**: `sysctl net.ipv4.ip_forward=1` + **`nftables`** filter (add backend).
- **Windows**: **WinDivert** kernel path (or WFP + registry `IPEnableRouter`).
  This replaces the dead user-space path.

`one_way_kill` / lag / port / host blocks then become: ARP-poison to steer
traffic through us → kernel forwards at native speed → firewall backend drops the
specific flows. No Python in the packet hot path.

**Status**: mac/linux kernel forwarding is a real `enable_ip_forwarding()` sysctl
in `killer.py` (called once in `Killer.__init__`). Windows has no sysctl
equivalent for ARP-MITM'd traffic — that path will be **WinDivert**, written and
validated on Windows (Phase 2). We do not ship an empty Windows forwarder shell in
the meantime.

## Confirmed bugs (fix in Phase 0/2)

1. ~~`Scanner()` raised `NameError`~~ — **fixed**: `get_default_iface` /
   `get_iface_by_name` now imported at top of `scanner.py`. (Redundant local
   import at ~L302 can be removed.)
2. **Windows selective-block is non-functional** (the "Windows desync/lag"): no
   kernel forwarding on Windows and the `netsh` rule filters the *attacker's* host
   not the victim's forwarded traffic. Progress: dead `_start_one_way_forwarder`
   **removed**. **Remaining (Phase 2)**: implement the WinDivert kernel forwarder on
   Windows (intercept + re-inject, dropping filtered flows), replacing the broken
   netsh selective path.
3. **`conf.iface` global mutation** in `Killer.__init__` (`killer.py:43`) —
   process-global side effect; scope it or restore it.
4. **`devices_appender` race**: rebuilds `self.devices` without holding `_lock`
   despite the docstring claim; races GUI reads.
5. ~~**`flush_arp` (unix)** `arp -a > /dev/null | cat` no-op~~ — **fixed**: now
   `arp -d -a` (macOS) / `ip -s -s neigh flush all` (Linux), best-effort.
6. **`get_gateway_mac` (unix)** token scan can match non-MAC/IPv6 tokens.
7. **Silent privilege failures**: L2 socket / BPF errors are swallowed; pair with
   the `privilege` domain's honest `is_admin` + banner.

## Data model

`DeviceInfo(TypedDict)` is canonical (`scanner.py`). Router/Me are the same shape.
`DUMMY_ROUTER` uses `192.168.1.1` / broadcast MAC as a sentinel — real router is
resolved by the scanner; do not block against the dummy.

## Tasks

- [x] Fix `Scanner()` import `NameError`.
- [x] Remove dead `_start_one_way_forwarder`; route selective block through the
      `Firewall` abstraction; add platform-aware `forwarding` package.
- [x] Fix `flush_arp` unix no-op; remove redundant scanner import.
- [ ] Implement the WinDivert kernel forwarder on Windows — Phase 2.
- [ ] Validate the Linux nft forward-hook chain end-to-end on a real Linux host.
- [ ] Lock `devices` rebuild; scope `conf.iface`; fix `get_gateway_mac` heuristic.
- [ ] Unit tests with mocked scapy (scan parsing, kill packet construction).
