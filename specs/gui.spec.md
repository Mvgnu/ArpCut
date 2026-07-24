---
name: gui
description: "PySide6 frosted-glass UI — controller layer, device-centric window, centralized theme, SVG icons"
status: active
paths:
  entry: src/elmocut.py            # bootstrap → gui.app.main
  app: src/gui/app.py              # QApplication bootstrap (theme + controller + window)
  window: src/gui/window.py        # MainWindow — presentation only
  controller: src/gui/controller.py  # mediates GUI ↔ engine, off-thread ops (absorbs bridge.py)
  theme: src/gui/theme.py          # one palette + one QSS (dark/light), live-swappable proxy
  icons: src/gui/icons.py          # SVG icon set + bespoke app logo (replaces base64 assets.py)
  widgets: src/gui/widgets/        # glass chrome, title bar, controls, device row
  dialogs: src/gui/dialogs/        # settings, about, blocker, traffic, lag, device
consumes:
  - networking.Scanner
  - networking.Killer
  - networking.TrafficSniffer
  - networking.Nicknames
  - networking.HostBlocklist   # via Killer.block_host
  - firewall.*                 # via Controller only
  - platform.is_admin / get_ifaces / is_connected
exports:
  - Controller
  - MainWindow
  - gui.app.main
---

# GUI Domain — PySide6 frosted-glass rewrite (built)

The elmoCut-derived PyQt5 UI is **gone**: `gui/main.py` (the ~910-line god object),
`gui/{about,device,settings,traffic,lag_switch,port_blocker}.py`, the generated
`ui/*.py`, the base64 `assets.py`, `bridge.py`, `tools/qtools.py`, and the legacy
raster icons in `assets/` are all deleted. The networking/firewall engine (zero Qt
imports) is reused unchanged behind a new controller.

## Stack

- **PySide6** (Qt6, LGPL). No `qdarkstyle`, no `PyQt5`, no `pyperclip`.
- One **`theme.py`**: a palette (dark + light) + one global QSS. `THEME` is a live
  proxy so `from gui.theme import THEME` reads stay correct across a theme switch
  (a plain rebind would strand every captured reference). Painted chrome follows
  the active theme immediately; inline-styled labels reflect it on next build.
- **`icons.py`**: Feather-style SVG line icons rendered to theme-colored, Retina
  pixmaps on demand, plus a bespoke `app_logo()`. No image files shipped.
- Frosted glass = frameless + translucent top-levels, a drop-shadowed rounded
  `GlassRoot` that paints a translucent fill + top sheen + hairline border, custom
  traffic-light title bar, native drag/resize via `startSystemMove/Resize`.

## Architecture: Controller layer

```
MainWindow / dialogs (presentation) ──intent──▶ Controller ──▶ engine
        ▲                                          │  (Scanner/Killer/Sniffer/firewall)
        └──────────── Qt signals ──────────────────┘  (scan on QThread, DNS/probe on QThreadPool)
```

- **`Controller`** (a `QObject`) owns the `Scanner`/`Killer`/`TrafficSniffer`/
  `Nicknames` and all app state (killed set, one-way set, full-kill set, lag timer,
  host blocks). It exposes intent methods (`scan`, `toggle_cut`, `kill_all`,
  `toggle_one_way`, `toggle_full_kill`, `start_lag`/`stop_lag`, `block_host`,
  `block_port`, `set_iface`, `probe`, …) and emits result signals
  (`devices_changed`, `scan_progress`, `states_changed`, `host_blocks_changed`,
  `status`, `privilege_changed`). No widget touches a socket, `pfctl`, or the
  scanner directly.
- Long ops run off the GUI thread: scanning on a `ScanWorker(QThread)` (this
  absorbs the old `bridge.py`), DNS-resolving host blocks and IP probes on a
  `QThreadPool`. The UI never blocks.
- The controller is the natural seam for the **privileged helper**: each engine
  call behind it can later become a `HelperClient` call unchanged.

## Design language

- **Device-centric card list**, not a table. Each card: tinted vendor/type badge,
  display name (nickname → vendor → "Unknown device"), IP · MAC (muted), live
  state chips (Cut / One-way / Full / Lag), and a primary **Cut / Restore** toggle.
  Admin devices (Me / Router) show a YOU / GATEWAY tag instead of a Cut button.
- **One primary action** per card; advanced actions live in a **selection-driven
  action bar** (One-way, Lag, Full, Blocker, Traffic, Info) that appears for the
  selected non-admin device.
- **Status is obvious**: a persistent privilege/interface banner (from
  `privilege_changed`) replaces silent failure; scanning shows an inline progress
  strip; a status line reports the last action in an accent color.
- **Dark-first**, theme-aware, macOS system accent palette, generous spacing.
- **Menu-bar tray** with Show / Cut All / Restore All / Quit; close minimizes to
  tray when the `minimized` setting is on.

## Dialogs (frosted-glass, signal-driven)

- **Settings**: interface picker, theme segment, scan count/threads, behavior
  toggles — emits to the controller / persists settings; never mutates the window.
- **Blocker** (Ports & Hosts): curated **host presets** (PSN comms, GTA save) as
  toggles over `HostBlocklist`, quick IP/domain block, quick port block (proto +
  "only this device"), and a live list of active blocks (hosts/ports/IPs) with
  per-item removal. Replaces the old static `COMMON_IPS`.
- **Traffic**: live per-device flows from `TrafficSniffer`, polled on a timer.
- **Lag switch**: block/clear intervals + direction; returns values to the controller.
- **Device**: details + nickname editor (→ `Nicknames`).
- **About**: app mark, version, credits (elmoCut), GitHub link.

## Done

- [x] `Controller` extracting all inline logic from the old `ElmoCut`.
- [x] `theme.py` centralizing every style (one QSS, live proxy, dark+light).
- [x] `MainWindow` + device-card widget + selection action bar + tray.
- [x] Every dialog rebuilt as a signal-driven frosted-glass widget.
- [x] Legacy UI, `ui/*`, `assets.py`, `bridge.py`, `qtools.py`, raster icons deleted.
- [x] SVG icon set + bespoke logo replace the base64 blobs.
- [x] Verified: 102 engine tests still green; window + all dialogs build & render
      offscreen; both themes render correctly.

## Remaining (later phases)

- [ ] Wire the controller to `HelperClient` once the macOS helper is deployed
      (Phase 3 deploy) — today it calls the in-process engine directly.
- [ ] Live event streaming (scan/device/traffic push) instead of polling.
- [ ] Full runtime theme repaint without relaunch (rebuild inline-styled widgets).
- [ ] `.icns`/packaging polish (Phase 5).
