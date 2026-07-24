---
name: overview
description: "ArpCut north-star architecture, locked decisions, domain map, and phased roadmap"
status: active
supersedes: "the Rust-port framing and Løp/biolab governance in the prior specs"
---

# ArpCut — Overview & Roadmap

ArpCut is a cross-platform desktop tool for controlling local-network traffic:
device discovery, ARP-based blocking (kill), selective blocking (one-way / lag /
port / host), and live traffic monitoring. It targets Windows, macOS, and Linux.

This document is the **single source of truth for direction**. The per-domain
specs (`platform`, `privilege`, `networking`, `firewall`, `gui`, `build`) describe
their own slice; this file records the cross-cutting architecture and the order
we build in.

## Locked decisions (confirmed 2026-07-24)

1. **Language: Python stays; no Rust rewrite.** The desync/lag is not "Python is
   slow" — it is that packet forwarding runs in Python user-space (or, on Windows,
   nowhere). We fix it by moving forwarding into the **kernel on every platform**,
   not by rewriting in Rust. A native core is revisited only if a specific
   bottleneck survives kernel forwarding.
2. **UI: full rewrite on PySide6** (Qt6, LGPL) with a custom frosted-glass theme.
   **Done** — the elmoCut-derived PyQt5 interface, generated `src/ui/*.py`, base64
   `assets.py`, `bridge.py`, `qtools.py`, and raster icons are deleted; a
   device-centric window + controller + SVG iconography replace them. The
   networking/firewall engine (which has **zero Qt imports**) is reused unchanged
   behind the controller. See `gui.spec.md`.
3. **Privilege: split architecture.** An unprivileged GUI talks to a privileged
   engine. On macOS that engine is a **root helper daemon** (SMAppService /
   SMJobBless), installed once with an admin prompt — the same model as Wireshark
   and Little Snitch. This is what makes a double-clicked, signed app actually
   work. See `privilege.spec.md`.

## Why the app doesn't "work out of the box" today

The core capability (raw ARP frames, pf/netsh rules, IP-forwarding toggle)
**inherently requires elevated privilege on every OS**. There is no sandbox-safe
path — this can never ship on the Mac App Store.

- **macOS**: `/dev/bpf*` is `root:wheel 0600`. A double-clicked GUI runs as the
  user and cannot open it, so scapy fails silently. Signing/notarization only
  gets you past Gatekeeper to *launch*; the app then dies the moment it touches
  BPF. The fix is privilege separation (helper daemon), not a packaging format.
- **Windows**: already elevates via the UAC manifest, but needs the **Npcap**
  driver, which is not bundled — the user must install it separately.
- **Linux**: needs root or `CAP_NET_RAW`/`CAP_NET_ADMIN`; today it just fails.

## Target architecture

```
┌────────────────────────────┐        ┌─────────────────────────────────┐
│  GUI  (unprivileged)       │        │  Engine  (privileged)           │
│  PySide6 + controller      │  IPC   │  scanner · killer · forwarder   │
│  no raw sockets, no pfctl  │◄──────►│  firewall backends · sysctl     │
│                            │        │  (root helper on mac; elevated  │
│                            │        │   process on win/linux)         │
└────────────────────────────┘        └─────────────────────────────────┘
```

- **GUI** owns presentation and user intent only. It never opens a raw socket or
  shells `pfctl`/`netsh` directly (today it does — that is the coupling we remove).
- **Controller** (in-process, Qt-aware) mediates GUI events → engine calls, runs
  long operations off the UI thread, and holds no packet logic.
- **Engine** is the existing Qt-free core, elevated. On macOS it is reached
  through the helper daemon over XPC/local socket; on Windows/Linux it runs in the
  elevated app process (Phase 1) and may be split into a helper later.

## Kernel-level forwarding (the desync fix)

A **kill** is pure ARP-poison blackhole and is already fine. The problem is
**selective** blocking (one-way / lag / port / host), which must forward the
*allowed* traffic while dropping the rest.

| OS | Forwarding today | Target |
|----|------------------|--------|
| macOS | `sysctl net.inet.ip.forwarding=1` + `pf` filter | keep; harden `pf` rules |
| Linux | `sysctl net.ipv4.ip_forward=1` (+ firewall stub) | add `nftables` filter backend |
| Windows | **none** — falls back to dead/slow user-space forwarder | **WinDivert** (or WFP + `IPEnableRouter`) kernel path |

The Python `MitmForwarder` (scapy `AsyncSniffer`, per-packet Python + checksum
recompute) becomes a **last-resort fallback**, never the default path. On Windows
it is currently *dead code with no callers* and the `netsh` selective-block rule
targets the attacker host, not the victim — so Windows selective blocking is
effectively non-functional today.

## Domain map

| Spec | Owns | Key change |
|------|------|-----------|
| `overview` | direction, roadmap | this file |
| `platform` | ifaces, settings, constants, subprocess | drop Rust notes; fix `is_admin`; harden `terminal()` |
| `privilege` | root helper daemon + typed command protocol + client | **built** (deploy pending) |
| `networking` | scanner, killer, forwarder, sniffer | kernel forwarding; bug fixes; forwarder demoted |
| `firewall` | one `tools/firewall.py` (pf/netsh/nft) + host blocklist | Linux nft; PSN/GTA presets; bug fixes; no adapter/legacy |
| `gui` | PySide6 frosted-glass UI + controller + SVG icons | **built**; legacy `ui/*`/`assets.py`/`bridge.py`/`qtools.py` deleted |
| `build` | packaging, installers, signing, CI | `.dmg`+helper, NSIS+Npcap, AppImage; sign/notarize |

## Phased roadmap

**Phase 0 — Stabilize (done).** App-breaking bugs fixed: `Scanner()` `NameError`,
`is_admin()` on POSIX (honest euid), substring-match `unblock_ip`/`unblock_port`,
silent Windows unblock reporting, `flush_arp` no-op, dead `_start_one_way_forwarder`
removed, `_err` thread-safety. Keep the PyQt5 UI alive as a reference.

**Phase 1 — One firewall module + host blocklist (done).** Consolidated to a
single `tools/firewall.py` (pf / netsh / nft via platform branches; no interface,
no adapter, no legacy `pfctl.py`), with the substring-unblock, silent-Windows-leak,
non-idempotent-write and `_err` thread-safety bugs fixed. **Host blocklist**
shipped: `psn-comms` (domain, resolves live) + `gta-save` (verified Rockstar IP),
idempotent, reachable from `Killer.block_host`. Remaining: on-box Linux `nft`
validation, UI wiring (Phase 4). See `firewall.spec.md`.

**Phase 2 — Windows kernel forwarding (WinDivert).** mac/linux already forward via
the `enable_ip_forwarding()` sysctl + firewall drop rules. Windows needs a
WinDivert kernel forwarder (intercept + re-inject, dropping filtered flows),
written and validated on Windows — the real fix for the desync. Ties into driver
bundling (installer) and privilege.

**Phase 3 — Privilege separation (built; deploy pending).** `src/privilege/`: a
typed command protocol (fixed registry, per-arg validation, no arbitrary-exec
verb), a root helper daemon (`Engine` + `HelperServer`) that owns the engine, and
an unprivileged `HelperClient` — the Phase-4 GUI becomes the thin client. Remaining
is the deploy only: `SMAppService` registration + `.app` bundling + signing (Dev ID
available). Windows keeps UAC + bundles Npcap; Linux uses `setcap`/polkit. See
`privilege.spec.md`.

**Phase 4 — PySide6 UI rewrite (done).** A frosted-glass, device-centric UI on
PySide6: `gui/app.py` (bootstrap), `gui/window.py` (presentation only),
`gui/controller.py` (engine mediator + off-thread scan/tasks, absorbing
`bridge.py`), `gui/theme.py` (one QSS + live dark/light proxy), `gui/icons.py`
(SVG set + logo), `gui/widgets/*` (glass chrome, title bar, controls, device card)
and six `gui/dialogs/*` (settings, blocker, traffic, lag, device, about). All
legacy UI (`gui/*` PyQt5, `ui/*`, `assets.py`, `bridge.py`, `qtools.py`) and raster
icons are deleted; `requirements.txt`/`build.py` moved to PySide6. Remaining: wire
to `HelperClient` after the Phase-3 deploy; event streaming; full runtime theme
repaint. See `gui.spec.md`.

**Phase 5 — Installers.** Signed+notarized `.dmg` (with helper install), Windows
NSIS/Inno installer bundling Npcap, Linux AppImage/`.deb`. CI drives `build.py`;
release artifacts are installers, not raw binaries. The CI workflow
(`build-release.yml`) still lists PyQt5/qdarkstyle hidden-imports — swap to PySide6
here.

## Working conventions (kept from prior guidance, de-ceremonied)

- **Spec-first**: update the relevant spec when behavior/interfaces change.
- **No silent unfinished work**: mark partial work with `TODO` comments in code.
- **Verify before done**: run the domain's tests / a smoke import before claiming
  completion.
- Dropped: the Løp "bubble-agent write-gate" and Prisma/Zod rules — they are from
  an unrelated TS monorepo and do not apply here.
