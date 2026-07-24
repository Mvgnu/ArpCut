---
name: platform
description: "Cross-platform glue — interface detection, IP/MAC resolution, settings, subprocess"
status: active
paths:
  utils: src/tools/utils.py
  utils_gui: src/tools/utils_gui.py
  qtools: src/tools/qtools.py          # PyQt5 today → PySide6 in the UI rewrite
  constants: src/constants.py
exports:
  - terminal
  - threaded
  - get_vendor
  - good_mac
  - get_my_ip
  - get_gateway_ip
  - get_gateway_mac
  - get_ifaces
  - get_default_iface
  - get_iface_by_name
  - is_connected
  - is_admin
  - npcap_exists
  - get_settings
  - set_settings
  - import_settings
  - export_settings
  - repair_settings
  - migrate_settings_file
  - add_to_startup
  - remove_from_startup
  - DOCUMENTS_PATH
  - SETTINGS_PATH
  - SETTINGS_DEFAULTS
  - DUMMY_ROUTER
  - DUMMY_IFACE
consumes: []
verification:
  test: "python -m pytest tests/test_platform.py -v"
  lint: "python -m pyflakes src/tools/ src/constants.py"
---

# Platform Domain

Handles OS differences for interface detection, IP/MAC resolution, settings, and
subprocess. Settings are already dict-based (`SETTINGS_DEFAULTS`) and paths use
`pathlib`; the elmocut→arpcut migration is in place (`migrate_settings_file`).

## Components

- **`utils.py`** — `get_ifaces()` dispatches to `_get_ifaces_windows()` (parses
  `ipconfig /all` + `netsh` GUID mapping, cross-refs scapy `NPF_{guid}`) and
  `_get_ifaces_unix()` (route table + `get_if_hwaddr`). Plus `get_my_ip`,
  `get_gateway_ip/mac`, `get_vendor` (manuf OUI), `good_mac`, `terminal`,
  `threaded`, `check_connection`.
- **`utils_gui.py`** — `is_admin`, `npcap_exists`, settings I/O, Windows autostart.
- **`qtools.py`** — Qt helpers (`Buttons`, `MsgType`, `MsgIcon`, `msg_box`,
  `colored_item`, `clickable`). Migrates PyQt5 → PySide6 with the UI rewrite.
- **`constants.py`** — paths, settings schema, sentinels, Npcap constants.

## Issues to fix

1. **`is_admin()` lies on POSIX** — returns `True` unconditionally; must check
   `os.geteuid() == 0`. Owned jointly with `privilege.spec.md` (Phase 0).
2. **`_get_ifaces_windows()` is locale-fragile** — splits on the English literal
   `adapter` and matches GUID substrings; breaks on non-English Windows. Prefer
   scapy's `get_windows_if_list()` / WMI as the primary source, `ipconfig` only for
   the friendly-name label.
3. **`terminal()` uses `shell=True`** with f-string interpolation of values parsed
   from OS output (ARP/ipconfig) — low practical risk but unquoted. Move to
   arg-list `subprocess.run` (no shell) where possible; privileged commands go
   through the helper's typed protocol, not shell.
4. **`get_gateway_mac` (unix)** token heuristic can match IPv6/non-MAC tokens.
5. **Hardcoded `en0`** fallbacks appear across GUI/port-blocker — replace with
   `get_default_iface()` so non-macOS and non-`en0` setups work.

## Notes

- The friendly `NetFace.name` vs pcap `NetFace.guid` distinction matters: scapy
  must receive `guid` (`\Device\NPF_{...}` on Windows; `en0` on macOS where they
  coincide). Passing `.name` to scapy fails on Windows — keep the split.
- Rust-port notes from the old spec are removed (no Rust rewrite — see
  `overview.spec.md`).

## Tasks

- [x] Fix `is_admin()` POSIX (honest `euid`). `PrivilegeState`/banner: still pending
      (privilege domain).
- [x] **De-shell**: `terminal()` and firewall `_exec` no longer use `shell=True`
      (argv via `shlex`); the one `is_connected` shell pipe is filtered in Python;
      `test -f` replaced by `os.path.exists`. Only `settings.py os.system('start …
      restart.exe')` remains (legacy Windows GUI restart — Phase 4). Verified on
      macOS (string + argv forms run correctly).
- [x] Fix `get_gateway_mac` unix heuristic — proper MAC regex (six hex groups),
      not "any colon token" (verified against live `arp -a`).
- [ ] Simplify `get_ifaces()` Windows `ipconfig`/`netsh` parsing (behavior-preserving;
      runtime-verify on Windows).
- [ ] Replace hardcoded `en0` fallbacks with `get_default_iface()`.
- [ ] Unit tests: settings round-trip, MAC normalization, vendor lookup.
