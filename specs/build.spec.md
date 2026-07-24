---
name: build
description: "Packaging, signed/notarized installers, driver bundling, and CI"
status: active
paths:
  build: build.py
  spec: ArpCut.spec
  requirements: requirements.txt
  installers: packaging/            # new — dmg/, windows/, linux/ (Phase 5)
  github: .github/
  exe: exe/
exports: []
consumes:
  - privilege.helper                 # macOS helper is bundled + registered by the installer
verification:
  build: "python build.py"
---

# Build Domain

Turn ArpCut into installers that work on double-click. Today the release is raw,
unsigned artifacts (`ArpCut.exe`, `ArpCut-macOS.zip`, `ArpCut` binary) — none of
which install cleanly or acquire the privilege the app needs.

## Current state

- `build.py` runs PyInstaller per platform (Windows `--onefile --windowed
  --uac-admin`; macOS `--onedir --windowed` → `.app`; Linux `--onefile`). Version
  is read from `constants.py __version__`.
- CI (`.github/workflows/build-release.yml`) **duplicates** the PyInstaller
  command instead of calling `build.py` — drift risk; make CI call `build.py`.
- Icon is `.ico` even for macOS (should be `.icns`). No signing/notarization. No
  Npcap bundling. No installer packaging.

## Target: per-platform installers

### macOS — signed, notarized `.dmg` + helper
- Build the `.app` (PySide6), sign the app **and** the `com.arpcut.helper` with a
  **Developer ID** identity, enable the **Hardened Runtime** (does not block BPF),
  then **notarize** + staple.
- Package a `.dmg` (or `.pkg` if the helper is easier to install via pkg
  scripts). First launch registers the helper via `SMAppService` (one admin
  prompt). Uninstall unregisters the daemon and flushes pf rules.
- Requires an Apple Developer account; document the identity/entitlements. Without
  signing, the app can still run from Terminal for developers (documented).

### Windows — installer that bundles Npcap
- Wrap the `--uac-admin` exe in an **NSIS or Inno Setup** installer that bundles
  and silently installs **Npcap** (WinPcap-compatible mode) if absent, creates
  Start-menu/shortcut, and registers uninstall (which flushes `arpcut_*` netsh
  rules). Ship WinDivert's driver alongside once kernel forwarding lands.
- Code-sign the exe + installer to reduce SmartScreen/AV friction (network tools
  trigger false positives — keep the VirusTotal links in the README).

### Linux — AppImage / `.deb`
- **AppImage** (self-contained) as the primary artifact; document
  `setcap cap_net_raw,cap_net_admin+ep` or a polkit action for privilege. Provide
  a `.deb` with a post-install `setcap` step for Debian/Ubuntu.

## Dependencies

`requirements.txt` moves PyQt5 → **PySide6**; drops `qdarkstyle` (custom theme).
Adds `WinDivert` bindings (Windows-only extra) in Phase 2. `manuf`, `scapy`,
`pyperclip` stay. Update PyInstaller hidden-imports/`collect_all` accordingly.

## CI

- One reusable job matrix (win/mac/linux) that calls `build.py`, then a
  packaging step per OS, then a signing/notarization step (secrets: Apple API
  key, Windows cert), then `softprops/action-gh-release` uploading **installers**
  (not raw binaries). Add a `pytest` job gating releases.

## Authored (this pass) — see `packaging/`

The install-wizard scaffolding is built; what's left is signing + the actual
per-OS build runs (need a Windows box / Developer ID).

- **`packaging/macos/create_dmg.sh`** — drag-to-Applications `.dmg` builder
  (runnable on macOS); wired into `build.py --dmg`.
- **`packaging/macos/entitlements.plist`** — Hardened-Runtime entitlements for
  Developer-ID signing (BPF is gated by root, not the runtime).
- **`packaging/windows/arpcut.iss`** — Inno Setup wizard: installs to Program
  Files, **silently installs Npcap** if the `npcap` service is absent, admin
  manifest, shortcuts, and an uninstall step that runs `ArpCut.exe
  --flush-firewall`.
- **`packaging/linux/arpcut.desktop`** + README AppImage/`.deb` recipe.
- **`packaging/README.md`** — the end-to-end per-OS install story.
- **First-run privilege flow** is in the app: `Set Up Access` (banner button +
  onboarding dialog) drives `privilege.install` (relaunch-elevated **or** install
  the root helper). Packaged app auto-opens it on first unprivileged launch.
- **Helper is bundled with no second binary**: the app binary doubles as the root
  daemon (`elmocut.py --helper` → `privilege.helper.main()`); `helper_argv` frozen =
  `[sys.executable, '--helper']`, so the LaunchDaemon runs the app binary as root.
- **`.icns` icon** generated from the SVG app mark (`gui.icons.app_logo` → iconutil).
- **`elmocut.py --flush-firewall`** — headless full firewall cleanup for uninstallers.
- `requirements.txt` + `build.py` moved to **PySide6** (PyQt5/qdarkstyle dropped).

## Remaining (deploy-gated)

- [ ] CI (`build-release.yml`) calls `build.py`; swap PyQt5→PySide6 hidden-imports;
      add a `pytest` gate.
- [ ] macOS: `.icns`, Developer-ID sign + notarize the `.app` and `.dmg`; bundle
      `arpcut-helper` + register via `SMAppService` (turns Set Up Access into one prompt).
- [ ] Windows: run the Inno build on a Windows box; drop `vendor/npcap.exe`; code-sign.
- [ ] Linux: produce the AppImage + `.deb` (with `setcap` postinst).
