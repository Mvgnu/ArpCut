---
name: networking
description: "Core network engine: scanning, ARP spoofing, kernel/user-space forwarding, traffic sniffing"
status: active
paths:
  scanner: src/networking/scanner.py
  killer: src/networking/killer.py
  forwarder: src/networking/forwarder.py       # user-space fallback (traffic monitor)
  windivert: src/networking/windivert_forwarder.py  # Windows kernel forwarder (WinDivert)
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

The Qt-free core of ArpCut. Networking modules are shared by the GUI controller
through the local or remote privileged engine.

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
uses the macOS/Linux routing sysctl or Windows routing configuration.

### MitmForwarder (`forwarder.py`) — Windows fallback only
User-space forwarder (scapy `AsyncSniffer`, per-packet MAC rewrite + checksum
recompute). **The slow path — never the default.** `Killer` holds **no** forwarder
state for this class anymore: the dead per-victim `forwarders` dict, `_start_one_way_forwarder`,
`_stop_forwarder` and `get_forwarder_stats` are removed. The only remaining user is
the traffic monitor's optional "forward mode", which is **redundant on mac/linux**
(the kernel forwards once `enable_ip_forwarding()` is on). Windows now uses
WinDivert for the default policy path; this legacy class remains optional.

### TrafficSniffer (`sniffer.py`)
Live per-device monitoring: flows, patterns, hex/last-packet inspection.

### NetFace (`ifaces.py`) / Nicknames (`nicknames.py`)
Interface data class (`name`, `guid`, `mac`, `ip`) and JSON-backed nickname store.

## Kernel-level forwarding

Selective blocking uses platform forwarding and filtering facilities:

- **macOS**: `sysctl net.inet.ip.forwarding=1` and the ArpCut PF anchor.
- **Linux**: `sysctl net.ipv4.ip_forward=1` and a dedicated nftables table.
- **Windows**: `IPEnableRouter` routing configuration and WinDivert
  `NETWORK_FORWARD` filters.

`one_way_kill` / lag / port / host blocks then become: ARP-poison to steer
traffic through us → kernel forwards at native speed → firewall backend drops the
specific flows. No Python in the packet hot path.

**Status**: `enable_ip_forwarding()` is called by modes that require forwarding,
such as spoof, one-way, and selective blocking; construction alone does not
enable it. Windows has a corresponding configuration path:
`enable_ip_forwarding()` sets the `IPEnableRouter` registry flag (the sysctl
analogue) and `one_way_kill` starts a **WinDivert** `NETWORK_FORWARD` drop for the
victim's outbound (`windivert_forwarder.py`). The filter matches only the flows to
drop, so allowed traffic rides the kernel forward fast-path — no Python in the hot
path. WinDivert (driver + DLL) ships with the `pydivert` dep (Windows-only) and is
bundled by `build.py`/the installer. Filter construction is unit-tested against the
real WinDivert engine (`WinDivert.check_filter`, no admin needed); live packet-drop
validation needs an elevated run against a real victim.

## Confirmed bugs (fix in Phase 0/2)

1. ~~`Scanner()` raised `NameError`~~ — **fixed**: `get_default_iface` /
   `get_iface_by_name` now imported at top of `scanner.py`. (Redundant local
   import at ~L302 can be removed.)
2. ~~**Windows selective-block is non-functional**~~ — **fixed (Phase 2)**: the
   WinDivert kernel forwarder (`windivert_forwarder.py`) drops the victim's
   forwarded flows in-kernel while `IPEnableRouter` lets the stack forward the
   rest, replacing the broken `netsh` selective path (which filtered the
   *attacker's* host, not the victim's forwarded traffic). The netsh block is kept
   as a portable backstop. Live-traffic validation against a real victim is still
   recommended before the next Windows release.
3. ~~**`conf.iface` global mutation** in `Killer.__init__`~~ — **fixed**:
   sockets and sends use their explicit instance interface without changing the
   process-global Scapy default.
4. ~~**`devices_appender` published a partially rebuilt list**~~ — **fixed**:
   complete snapshots are built locally and published under `_lock`.
5. ~~**`flush_arp` (unix)** `arp -a > /dev/null | cat` no-op~~ — **fixed**: now
   `arp -d -a` (macOS) / `ip -s -s neigh flush all` (Linux), best-effort.
6. ~~**`get_gateway_mac` (unix)** scanned arbitrary colon-containing tokens~~ —
   **fixed**: it matches six hexadecimal MAC-address groups and normalizes them.
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
- [x] Implement the WinDivert kernel forwarder on Windows — Phase 2
      (`windivert_forwarder.py`; `IPEnableRouter` + `NETWORK_FORWARD` drop; wired
      into `enable_ip_forwarding`/`one_way_kill`; unit-tested filter builder).
- [x] Full/regular kill on Windows drops the victim in-kernel (WinDivert drop-all,
      both directions) instead of relying on ARP-poison alone; **removed** the
      `enable_ip_forwarding()` from `Killer.__init__` (it enabled `IPEnableRouter`
      globally and made full kills *leak* — the kernel routed the poisoned traffic).
      Forwarding is now enabled only by `one_way_kill`/selective blocks that need it.
- [x] Selective per-victim drops (`selective_block`/`selective_unblock`/`lag`) via
      scoped WinDivert filters; port blocking with a target IP routes through them
      (`helper.Engine.block_port`). `block_all_for` (Windows) now blocks both directions.
- [x] Lag switch and host/dst/domain blocks route through the WinDivert selective
      path on Windows: `lag()` toggles a kernel drop of a spoofed victim, and host
      blocks mirror their destination IPs into every spoofed victim's WinDivert
      drop (`_apply_global_dst`/`_reconcile_global_dst`). mac/linux already catch
      these via forward-chain pf/nft rules. Live e2e validation still recommended.
- [x] Locale-robust netsh: firewall state via registry (not the localized 'ON'),
      rule readback via the `arpcut_*` token (not the localized 'Rule Name:').
- [ ] Validate the Linux nft forward-hook chain end-to-end on a real Linux host.
- [x] Scope interfaces to each operation and use MAC-aware gateway parsing.
- [x] Publish complete scan snapshots under the scanner lock.
- [x] Add mocked packet construction, restoration, and policy failure tests.

## Lifecycle audit (2026-10-22)

- `unkill` and `unkill_all` synchronously stop the corresponding poison sessions
  and send corrective ARP mappings before closing their L2 socket. Restore All
  batches the three repetitions across all devices. Canceled poison workers use
  separate events and cannot revive when the same MAC is routed again.
- Failed restoration keeps the captured device in `_restore_pending` for retry,
  without leaving poisoning enabled. Firewall deletion failures retain their
  bookkeeping too. An address change restores the old device mapping before
  creating the new routing session.
- Spoof/one-way setup verifies forwarding before redirecting traffic, so a
  failed sysctl/registry operation does not silently disconnect the device.
- Policy setup returns its actual result through `kill`, `kill_all`,
  `one_way_kill`, and `lag`. A missing Windows driver or rejected one-way policy
  does not create a new routing session. WinDivert policy replacement leaves
  the old handle active until its replacement has started successfully.
- POSIX one-way mode requests an outbound-only rule. In particular, Linux no
  longer installs the two-direction whole-device policy for that mode.
- `TrafficSniffer.start` waits for capture readiness and reports startup errors.
  Captures use a bounded timeout even on an idle interface; stop joins the worker
  before restart. Each session receives a fresh cancellation event and empty
  flow state. Public flow/pattern snapshots are independent copies.
- DNS capture and WinDivert workers close handles on startup/stop races and
  receive failures. `DnsSpoofer.clear()` additionally forgets the session's names.
- Deep scan uses one-packet pings capped at one second per child, with progress
  completion in `finally`. The helper validates count/thread limits and supplies
  a separate long-running scan deadline.
- Scan results deduplicate normalized MAC addresses, reject local/router MAC
  aliases, and publish complete snapshots. Probe cache parsing matches exact IP
  addresses instead of treating an address prefix as a match. Mocked scanner
  regressions are in `tests/test_scanner_regressions.py`.
- Mocked regressions are in `tests/test_network_cleanup.py`; they send no packets
  and alter no host firewall or routing state.

Global forwarding changes are still persistent OS configuration. Cleanup restores
devices/rules but does not guess whether another application depends on forwarding
and must not blindly disable it.
