---
name: build
description: "Packaging, dependency installation, CI and release artifacts"
status: active
paths:
  build: build.py
  requirements: requirements.txt
  development_requirements: requirements-dev.txt
  installers: packaging/
  github: .github/workflows/
verification:
  unit: "python -m pytest tests/test_build.py tests/test_cli_cleanup.py tests/test_pf_diagnostic.py -q"
  build: "python build.py"
---

# Build Domain

## Current build contract

`build.py` reads the version from `src/constants.py` without importing the app.
It invokes PyInstaller through the current interpreter, with its working
directory fixed to the repository root. This also supports invoking the script
from a different directory.

| OS | Build output | Packaging |
|----|--------------|-----------|
| Windows | `dist/ArpCut-<version>.exe` | Inno Setup `ArpCut-<version>-Setup.exe` |
| macOS | `dist/ArpCut-<version>.app` | ZIP and `python build.py --dmg` |
| Linux | `dist/ArpCut-<version>` | Standalone binary |

The macOS DMG script defaults to the versioned app bundle. PySide6, Scapy, manuf,
and lazily imported helper/engine modules are bundled; Windows also bundles
pydivert's WinDivert runtime. The packaged entry point supports `--helper` and
`--flush-firewall` without starting the GUI.

## Windows capture-driver handling

Default builds do not bundle Npcap and CI does not download its public installer.
The application directs users without the driver to `https://npcap.com/#download`.
Npcap's public installer is not redistributable, and silent `/S` installation is
an OEM feature. References: [OEM rights](https://npcap.com/oem/) and
[installer options](https://npcap.com/guide/npcap-users-guide.html).

A builder with an OEM redistribution license can provide
`packaging/windows/vendor/npcap-oem.exe` and compile with `/DBundleNpcapOEM`.
The explicit flag fails if the OEM file is missing. Vendor binaries are ignored
by Git. The Windows uninstaller invokes `--flush-firewall`; its exit status now
reflects whether all ArpCut rules could be cleared.

## Tests and CI

`requirements-dev.txt` installs application requirements, pytest, and
cryptography for the Scapy TLS ClientHello test fixtures. Runtime TLS name parsing
does not depend on cryptography.

`pytest.ini` selects `tests/` and adds `src` to the Python path. Manual diagnostics
are excluded from default test discovery. Tests mock packet transmission and
firewall mutation; helper tests use real local Unix sockets on supported OSes.

- `tests.yml` runs on pull requests, pushes to `main`, and manual dispatch.
- Its matrix covers Linux, Windows, and macOS on Python 3.11 plus Linux 3.12.
- `build-release.yml` retains its Linux test gate, uses `build.py` on all three
  platforms, and uploads the declared outputs before tag-triggered publication.
- Default workflow permissions are read-only; only the release job can publish.

## Manual diagnostics

Diagnostic scripts resolve `src` relative to their own repository location.
The compatibility diagnostic imports the current PySide6 modules.
`test_pf.py` is a manual macOS-only command that temporarily modifies the system
firewall configuration. It keeps a uniquely named private recovery copy,
restores configuration in `finally` (including Ctrl+C), and retains the recovery
copy if restoration fails. Unit tests inject a temporary config and mock every
command; the diagnostic is never executed against the host firewall by CI.

## Outstanding platform work

- Developer ID signing/notarization and SMAppService registration are not
  implemented. The current macOS helper installer requires a protected,
  root-managed packaged app; see `privilege.spec.md`.
- Windows code signing and licensed OEM driver provisioning are separate release
  tasks. Default installers require users to install Npcap themselves.
- AppImage and Debian packaging are not implemented. Linux uses an elevated
  standalone executable; the installer does not assign capabilities to Python.
- Unit/IPC checks do not replace testing Npcap, WinDivert, pf, or nftables against
  a real authorized network on their native operating systems.
