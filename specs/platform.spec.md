---
name: platform
description: "Cross-platform interface detection, settings persistence, subprocess helpers"
status: active
paths:
  utils: src/tools/utils.py
  utils_gui: src/tools/utils_gui.py
  constants: src/constants.py
verification:
  test: "python -m pytest tests/test_platform.py tests/test_platform_regressions.py -q"
---

# Platform Domain

The application stays in Python. `utils.py` provides interface discovery and
process helpers; `utils_gui.py` provides privilege detection, Npcap detection,
settings, and Windows autostart. GUI presentation lives in `gui/` (PySide6).

## Interface and process contracts

- Windows interfaces come from Scapy's structured interface list, matched by
  GUID. `NetFace.name` is a friendly label; raw capture uses `NetFace.guid`.
- POSIX interface discovery uses Scapy's interface and route information.
- `is_admin()` uses Windows administrator status or POSIX effective UID.
- `terminal()` executes argv without a shell. Malformed quoting, a nonzero
  process exit, a missing executable, or a timeout returns `None`; diagnostic
  stdout from a failed process is not a success result.
- Commands have a 30-second default deadline. Callers such as ping scanning can
  request a shorter deadline through the keyword-only `timeout` argument.
- `threaded()` creates daemon threads and retains wrapped-function metadata.
  Callers that must finish cleanup must join their workers explicitly.
- Npcap installation guidance uses the official download page, not an old
  hardcoded binary URL. Driver redistributability belongs to the build domain.

## Settings persistence

Settings live under the platform's ArpCut configuration directory. The legacy
elmoCut path is migrated when appropriate.

- Keys identify values. JSON object order and unknown future keys must never
  shift values into another setting.
- Reads merge stored objects with independent default values. Non-object JSON is
  invalid; startup repair recovers defaults from malformed or non-object data.
- `export_settings()` accepts a mapping; the legacy ordered-list API remains
  supported for compatibility.
- Saves serialize to a private temporary file in the destination directory,
  flush it, then atomically replace the settings file. Failed serialization or
  replacement preserves the last valid file and removes the temporary file.
- A re-entrant process-local lock serializes read/modify/write operations. This
  is not a multi-process settings database; simultaneous app instances should
  not be treated as independent writers.

## Verification

Tests cover existing defaults and migration-compatible serialization, reordered
JSON fields, unknown keys, corrupt/non-object JSON, failed writes, invalid
command quoting, nonzero process exits, and command deadlines. Tests use
isolated temporary settings files and mocked subprocesses.
