---
name: privilege
description: "Privilege separation — unprivileged GUI ↔ root helper daemon, typed command protocol"
status: active
paths:
  package: src/privilege/
  protocol: src/privilege/protocol.py
  helper: src/privilege/helper.py
  client: src/privilege/client.py
  service: src/privilege/service.py
  is_admin: src/tools/utils_gui.py
  tests: tests/test_privilege.py
exports:
  - HelperClient
  - HelperServer
  - Engine
  - COMMANDS
  - Request
  - Response
  - validate
  - SOCKET_PATH
  - HELPER_LABEL
  - launchd_plist
consumes:
  - networking.Scanner
  - networking.Killer
  - firewall.*
  - platform.is_admin
---

# Privilege Domain

## Audit hardening (2026-10-22)

- The daemon socket is private (`0600`) to the installing user, and the helper
  verifies the peer UID before serving requests. The LaunchDaemon records that
  UID explicitly; manual `sudo` launches use `SUDO_UID`, with the macOS console
  user as a fallback. If no user is identified, access remains root-only.
- Exactly one subscribed GUI session owns privileged state. Mutating operations,
  scans, and captures require that session. Read-only health/status probes remain
  available without subscribing. Requests and disconnect cleanup are serialized;
  a second session cannot inherit or clear a live session's rules.
- Persistent sessions have no idle read timeout. Explicit close shuts down the
  socket to wake both readers, and a request timeout invalidates the connection
  so a late reply cannot be mistaken for the next request's response. Scans have
  a 300-second deadline (2–255 addresses, 1–64 workers); host resolution and
  cleanup use explicit 60/120-second deadlines. Health probes stay responsive
  during long operations.
- JSON frames and argument types are checked before dispatch, including subscribe.
  Frames are bounded to 1 MiB. Cleanup attempts every stage and reports failures;
  switching interfaces first restores the old interface's state. SIGTERM runs
  orderly helper cleanup; hard termination/power loss still needs a later cleanup
  run. The engine also rejects device-control actions against protected gateway
  and local-host records, independently of the GUI.
- Persistent macOS installation requires a frozen application bundle whose files
  and parent paths are root-owned and not group/world-writable, with no extended
  ACLs or links outside the bundle. Source checkouts
  use one-time elevation; the installer never persists a user-writable Python
  interpreter or checkout as a root service. Generated plist content is embedded
  in the authorized install command, avoiding a temporary-plist replacement race.
- Linux uses one-time PolicyKit elevation. Persistent-helper installation is not
  implemented, and must never grant capabilities to a shared Python interpreter.
- `set_forwarding(False)` explicitly reports that restoration is unsupported;
  the previous global forwarding state is not yet tracked.

ArpCut cannot function without root on macOS/Linux (raw/BPF sockets, `pfctl`/`nft`,
`sysctl` forwarding all require it), and a double-clicked GUI runs as the user. The
fix — the same one Wireshark/Little Snitch use — is **privilege separation**: a
small root **helper daemon** does the privileged work; the GUI is an unprivileged
**client**. There is no sandbox-safe path, so the Mac App Store is out of scope.

## What is built (unit-tested, no scapy/root needed for the tests)

`src/privilege/` — a clean client/daemon split:

- **`protocol.py`** — the wire protocol. Newline-delimited JSON; a **fixed command
  registry** (`COMMANDS`) with per-argument validators. `validate(cmd, args)` runs
  before anything executes. There is **no arbitrary-exec verb** — the entire
  privileged surface is this enum, so the old `shell=True` injection surface is
  gone. Commands: `ping`, `status`, `scan`, `get_devices`, `kill`/`unkill`,
  `kill_all`/`unkill_all`, `one_way_kill`, `block_ip`/`unblock_ip`,
  `block_port`/`unblock_port`, `block_host`/`unblock_host`, `refresh_hosts`,
  `active_host_blocks`, `set_forwarding`.
- **`helper.py`** — `Engine` (adapter over `Scanner`/`Killer`/firewall, returning
  JSON-friendly data; scapy imported lazily) and `HelperServer`. `handle(req)` is a
  pure validate-then-dispatch function (unit-tested with a mock engine);
  `serve_connection` / `serve_forever` run the Unix-socket loop. `main()` refuses to
  start unless `euid == 0`, binds `SOCKET_PATH` privately (`0600`, installing-user
  ownership), verifies peer credentials, and serves.
- **`client.py`** — `HelperClient.call(cmd, **args) -> Response` for read-only
  probes over the Unix socket; `available()` pings the helper. `connect` is injectable (tests wire a
  `socketpair` for a real client↔server loopback). No scapy, no privilege — safe to
  import from the GUI.
- **`remote.py`** — `RemoteEngine`: the unprivileged GUI's view of the engine,
  mirroring `Engine`'s method surface but sending each call as a request over
  `HelperClient`. The **same `Engine` class** is used in-process by a root GUI
  (`LocalOps`) and inside the root helper, so orchestration is written once.

## GUI wiring (done)

`gui.Controller` picks its `ops` backend at startup: **root GUI → `Engine`**
(in-process); **unprivileged GUI + running helper → `RemoteEngine`**; otherwise
local (privileged ops fail and the "Set Up Access" banner explains why). All
controller orchestration (cut = ARP + firewall drop, one-way, lag, monitor) runs
through `ops.*`, so the unprivileged path drives the root helper over IPC with the
GUI holding no privilege.

### Persistent session — push + anti-orphan (done)

The remote backend holds **one persistent connection** (`HelperSession`), not a
call-per-connection. This buys two things that prevent real user pain:

- **Disconnect cleanup.** The session is `subscribe`d; when it drops — GUI quit
  *or* crash — the helper runs `Engine.cleanup()` (unkill all + clear every
  firewall rule), reporting/logging failures that need a retry. The GUI
  also calls `cleanup()` on start (clears hard-crash leftovers) and on clean
  shutdown. Non-session (one-shot) connections never trigger cleanup.
- **Push, not poll.** The root-side sniffer's per-packet callback pushes throttled
  `flows` events over the session; the controller re-emits them as
  `flows_changed`, and the Traffic dialog renders on push (a slow timer is only a
  fallback). `serve_forever` is thread-per-connection so the held session and any
  probe coexist.

Verified without root by a real AF_UNIX loopback: every command round-trips
(`RemoteEngine → HelperServer → engine`), a pushed `flows` event arrives on the
session, and **dropping the session triggers `cleanup()`** — plus a
controller-with-mock-ops suite (`tests/test_engine_backend.py`, 8 tests).
- **`service.py`** — identity: `HELPER_LABEL = com.arpcut.helper`, `SOCKET_PATH`
  (`/var/run/...` on macOS, `/run/...` on Linux, empty on Windows), a
  `launchd_plist()` generator, and `INSTALL_NOTES`.

Also fixed earlier: **`is_admin()` is honest on POSIX** (`euid == 0`), so the app
reports missing privilege instead of failing silently.

## Deploy step (gated on Developer ID — you have one)

Building the helper is **not** blocked by signing; only shipping it double-click is:
1. Bundle the helper in `Contents/Library/LaunchDaemons` of the `.app`.
2. Register via `SMAppService.daemon(plistName:)` (macOS 13+) / `SMJobBless` — one
   admin auth prompt. The GUI offers this when `HelperClient.available()` is False.
3. Sign both app + helper with the same Developer ID team; notarize + staple.
4. Uninstall must `SMAppService.unregister()` and flush firewall rules
   (`clear_anchor`).

## Windows / Linux

- **Windows**: elevate the whole process via the existing UAC manifest; bundle Npcap
  in the installer. No separate helper daemon for v1 (`SOCKET_PATH` is empty).
- **Linux**: session elevation through PolicyKit; there is no persistent-helper
  installer. Never grant capabilities to the shared Python interpreter. The same
  helper protocol supports manually managed daemons over
  `/run/com.arpcut.helper.sock`, with an explicitly authorized user.

## Remaining

- [x] Wire the PySide6 GUI to the helper — `gui.Controller` uses `RemoteEngine`
      when unprivileged + helper available (see GUI wiring above).
- [x] Persistent session with pushed `flows` events (traffic no longer polls).
- [x] Anti-orphan cleanup: helper restores everything when the GUI session drops.
- [ ] Push device-list / state snapshots too (scan still blocks in a worker;
      cut/one-way state is still controller-mirrored, accurate within a session).
- [ ] SMAppService registration code + `.app` bundling (deploy).
- [x] Private socket permissions, peer UID verification, and exclusive session ownership.
