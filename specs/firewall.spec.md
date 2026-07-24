---
name: firewall
description: "The one firewall module (pf / netsh / nft) plus the host-domain blocklist"
status: active
paths:
  firewall: src/tools/firewall.py         # one module, platform branches, private _Nft
  hostblock: src/networking/hostblock.py  # domain/IP blocklist (PSN, GTA)
  tests: tests/test_firewall.py tests/test_firewall_hardening.py tests/test_firewall_linux.py tests/test_hostblock.py
exports:
  - block_ip
  - unblock_ip
  - list_blocked_ips
  - block_port
  - unblock_port
  - list_blocked_ports
  - block_all_for
  - unblock_all_for
  - block_dst
  - unblock_dst
  - is_blocked
  - clear_anchor
  - clear_all_port_blocks
  - last_error
  - HostBlocklist
  - PRESET_HOSTS
consumes: []
verification:
  test: "python -m pytest tests/test_firewall.py tests/test_firewall_hardening.py tests/test_firewall_linux.py tests/test_hostblock.py -v"
  lint: "python -m pyflakes src/tools/firewall.py"
---

# Firewall Domain

**One module, `src/tools/firewall.py`.** Each public function branches on
`sys.platform` and applies rules through the native tool: `pfctl` anchor (macOS),
`netsh advfirewall` (Windows), `nftables` (Linux). No `Firewall` interface, no
`get_firewall()` dispatcher, no per-OS adapter classes, no legacy `pfctl.py` — an
earlier attempt added those on top of the old module and it was pure cladding;
it's gone.

## Layout

- Free functions are the public API (`block_ip`, `block_all_for`, `block_port`,
  their unblock/list counterparts, `clear_anchor`, `is_blocked`, `last_error`).
- macOS pf: anchor file `/etc/pf.anchors/com.arpcut`, referenced idempotently from
  `/etc/pf.conf`, reloaded via `pfctl -a`.
- Windows netsh: rules named `arpcut_*`.
- Linux: a small private `_Nft` helper at the bottom of the file (dedicated
  `inet arpcut` table, comment-tagged rules, arg-list runner — no shell). The
  `linux` branch of each public function delegates to the module singleton `_nft`.
  This is the only place a class earns its keep (it holds the runner for testing).

`enable_ip_forwarding()` lives in `killer.py` (a real sysctl toggle for mac/linux,
not a wrapper); Windows forwarding is deferred to WinDivert (Phase 2).

## Bugs fixed (Phase 0/1)

- **Substring-match removal** — `unblock_ip`/`unblock_dst`/`is_blocked` and the
  port equivalents now match exact tokens (`_pf_line_targets_ip` /
  `_pf_line_targets_port`), so unblocking `10.0.0.1` / port `80` no longer strips
  `10.0.0.10` / port `8080`.
- **Silent Windows leaks** — `_netsh_delete_ok()` reports real failures and treats
  "No rules match" as an idempotent no-op success; the always-`return True`
  branches are gone.
- **Non-idempotent writes** — macOS `_write_pf_rules` dedupes; Linux nft skips a
  rule whose comment already exists.
- **`_err` thread-safety** — `_ErrorState` guards its message with a lock.

## Host-domain blocklist (`hostblock.py`)

Blocks services by **domain** (resolves live) or **verified IP**, replacing the
old single hardcoded `COMMON_IPS`. Firewall ops are injected (default
`tools.firewall.block_ip`/`unblock_ip`) so it's unit-testable.

`PRESET_HOSTS` (curated, correct — no guessed IPs):
- **`psn-comms`** — domain `np.communication.playstation.net`; PSN party /
  host-migration. On-host equivalent of the router-side Bind9/RPZ recipe in
  `psn code.txt` — no separate DNS/proxy server.
- **`gta-save`** — verified static Rockstar save-server IP `192.81.241.171`;
  GTA Online save block.

`HostBlocklist.block/unblock/refresh` reconcile idempotently and track exactly
which IPs each preset installed, so `unblock` removes only its own rules and
`refresh` follows IP rotation. Reachable from `Killer.block_host` /
`unblock_host` / `refresh_hosts`.

**Xbox = one-way kill** — a device action (relabeled in the Phase-4 UI), not a
host preset; uses the existing `one_way_kill` path.

## Remaining tasks

- [ ] `nft` end-to-end validation on a real Linux host (root + `nft`); the
      command construction is unit-tested but the driver path is not.
- [ ] Linux `block_dst`/`unblock_dst` (traffic-monitor per-destination) — currently
      macOS/Windows only.
- [ ] `shell=True` in `_exec`: privileged calls move behind the macOS helper's
      typed protocol (see `privilege.spec.md`); `_exec` inputs are IP/port/proto
      validated today.
- [ ] Auto-clear anchor + remove the `/etc/pf.conf` reference on uninstall — Phase 5.
- [ ] Wire the Port Blocker UI to `HostBlocklist`, drop `COMMON_IPS` — Phase 4.
