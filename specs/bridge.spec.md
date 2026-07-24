---
name: bridge
description: "Background task execution — absorbed into gui.Controller; bridge.py deleted"
status: done
supersededBy: gui
paths:
  controller: src/gui/controller.py   # scanning + async tasks now live here
consumes:
  - networking.Scanner
---

# Bridge Domain — absorbed into `gui.Controller` (complete)

`src/bridge.py` (the old `ScanThread` / `UpdateThread` QThread wrappers) is
**deleted**. Its one live responsibility — running scans off the GUI thread —
moved into the controller:

- **Scanning** runs on `ScanWorker(QThread)` inside `gui/controller.py`, emitting
  `scan_progress(done, total)` and `scan_finished(bool)`. The cancellation
  contract is preserved: the worker sets `scanner.qt_progress_signal` /
  `scanner.qt_cancel_flag`, exactly what `Scanner.ping_scan` already reads.
- **DNS-resolving host blocks** and **IP probes** run as `QThreadPool` tasks
  (`Controller._run`), re-emitting typed result signals. The GUI thread never
  blocks.
- **`UpdateThread`** (GitHub release check) was dead in the fork and is dropped;
  a future update check can live behind a controller task pointed at
  `Mvgnu/ArpCut`.

Nothing further to do here — see `gui.spec.md`.
