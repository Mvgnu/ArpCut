---
name: overview
description: "ArpCut architecture, locked decisions, domain map, and remaining delivery work"
status: active
supersedes: "the Rust-port framing and Løp/biolab governance in the prior specs"
---

# ArpCut — Overview & Roadmap

ArpCut is a Python/PySide6 desktop tool for local-network device discovery,
ARP-based traffic control, selective blocking, and live traffic monitoring. It
targets Windows, macOS, and Linux. This document records cross-domain direction;
the domain specs describe the corresponding implementation contracts.

## Locked decisions

- **Python stays.** No Rust rewrite is planned. Address measured bottlenecks in
  the existing architecture before proposing a new native core.
- **PySide6 is the GUI.** The earlier PyQt5/generated UI was replaced by
  `gui/window.py`, `gui/controller.py`, dialogs, widgets, and SVG assets. Networking
  and firewall modules remain independent of Qt.
- **Privileged operations belong to one engine.** The controller uses
  `privilege.helper.Engine` in an elevated process, or `RemoteEngine` over a
  persistent Unix socket to a root helper. Both expose the same operations.
- **Forwarding and filtering use platform facilities.** macOS/Linux use the
  routing sysctl with PF/nftables. Windows uses routing configuration and
  WinDivert's `NETWORK_FORWARD` drop filters. Npcap supplies Windows packet
  capture/ARP access and is a separate dependency.

## Current architecture (2026-10-22)

The GUI displays user intent and engine results. The controller serializes
operations, runs scans and background tasks off the UI thread, and discards
queued results after restore, interface changes, or shutdown. A failed operation
must remain visible instead of being presented as a successful state change.

The engine owns scanner, ARP sessions, capture, DNS-name filters, host blocks,
and firewall changes. Device-control operations reject the local host and
router independently of the GUI. Restore first stops poison workers, then sends
corrective ARP mappings and tears down rules. Failed state remains available for
retry. Cleanup attempts independent stages even when one stage fails.

The root helper accepts one controlling subscribed GUI session, authenticates
its peer UID, and restricts its socket to the installing user. Health/status
probes do not acquire ownership. Losing the owning session triggers cleanup;
malformed frames and expired requests cannot be reused as another request's
response. Orderly application/helper shutdown also cleans up. Force-killing
both the GUI and helper, killing an elevated local process, or losing power
cannot guarantee an in-process restore; the next privileged startup and
`--flush-firewall` clear ArpCut's firewall rules.

### Privilege and installation

| Platform | Implemented path | Delivery limits |
|----------|------------------|-----------------|
| macOS | Administrator relaunch; persistent LaunchDaemon installed with an authorization prompt and `launchctl` | Persistent installation requires a frozen, root-owned protected app bundle and protected parent paths. Source/user-writable installations use one-time elevation. Signed SMAppService registration and notarization remain future work. |
| Windows | Elevated application via UAC; WinDivert packaged through `pydivert` | Npcap is installed separately in normal releases. Explicit OEM bundling requires the appropriately licensed installer. |
| Linux | Elevated application through PolicyKit (`pkexec`) or a direct root launch | Persistent-helper installation is not implemented. Never grant capabilities to a shared Python interpreter. |

Unprivileged local operation is limited to discovery that does not require raw
packet access. Capture, ARP control, forwarding, and firewall changes require
administrator access. Packaged-app signing is separate from those privileges.

### Forwarding and firewall scope

| Platform | Forwarding | Filtering |
|----------|------------|-----------|
| macOS | `net.inet.ip.forwarding` | ArpCut PF anchor |
| Linux | `net.ipv4.ip_forward` | Dedicated nftables table |
| Windows | `IPEnableRouter` and service configuration | WinDivert for forwarded target traffic; named `arpcut_*` Windows Firewall rules where applicable |

The Windows default drop mode filters in the driver; its optional counting mode
uses a receive loop. Actual routing readiness depends on the host configuration
and needs native smoke testing. The old `MitmForwarder` remains legacy code and
is not the default forwarding path.

Cleanup removes ArpCut-owned rules. It does not disable global forwarding:
ownership of the previous system setting is not tracked, and another program
may require it. Destination-IP host rules currently apply to all routed devices;
port removal is also shared by port/protocol. The UI must describe those scopes
accurately until narrower backend APIs exist.

## Domain map

| Spec | Responsibility |
|------|----------------|
| `platform.spec.md` | Interface discovery, settings, constants, subprocess handling |
| `privilege.spec.md` | Engine boundary, command validation, socket/session lifecycle, helper installation |
| `networking.spec.md` | Scanning, ARP sessions, forwarding, DNS filters, capture |
| `firewall.spec.md` | PF/nftables/Windows rule operations and host-block ownership |
| `gui.spec.md` | Controller state, asynchronous work, dialogs and user-visible failures |
| `build.spec.md` | Build paths, packaging, dependencies, release and test workflows |

## Verification and remaining delivery work

Pull requests and pushes to `main` run unit/local-IPC tests on Linux, Windows,
and macOS. Release builds have a test gate and package a Windows launcher and
Inno installer, a macOS ZIP and DMG, and a Linux standalone binary. Existing
v2.0.1 assets predate the DMG workflow change. Linux AppImage/deb packages are
planned, not current release artifacts.

Mocked tests cover rule construction, failure propagation, restoration order,
worker cancellation, settings persistence, controller races, helper ownership,
and install-command construction. These tests do not establish native driver,
packet-routing, privileged installer, signing, or notarization behavior. Before
a release, validate native capture/control/restore on each supported OS in a
controlled network and test installation/uninstallation using the built assets.

Remaining engineering work includes ownership-aware global-forwarding restore,
subnet-aware scanning beyond the current `/24` model, capture-history retention
for long sessions, finer per-device rule-removal APIs, signed macOS helper
registration, and Linux distribution packages. Keep these limits explicit;
completion of the audit does not imply that future platform work is delivered.

## Working conventions

- **Spec-first:** update the relevant spec when behavior or interfaces change.
- **No silent unfinished work:** document remaining behavior limits and partial
  implementations rather than presenting them as complete.
- **Verify before done:** run relevant tests and report platform checks that
  could not be performed.
- The older Løp/biolab write gates and Prisma/Zod rules describe an unrelated
  TypeScript monorepo and do not apply here.
