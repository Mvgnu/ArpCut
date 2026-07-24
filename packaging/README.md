# ArpCut packaging — installers for non-technical users

The goal: a user double-clicks one file, installs, launches, and clicks **Set Up
Access** once — no Terminal, no commands. Each OS gets a native installer; the
in-app privilege flow (`Set Up Access`) handles elevation on first run.

| OS | Artifact | Driver | Privilege on first run |
|----|----------|--------|------------------------|
| macOS | `ArpCut-<ver>.dmg` (drag → Applications) | libpcap (built in) | native password prompt → relaunch as admin, **or** install background helper |
| Windows | `ArpCut-<ver>-Setup.exe` (Inno Setup) | **Npcap** bundled + silent-installed | UAC (installer + app manifest) |
| Linux | AppImage / `.deb` | libpcap | PolicyKit (`pkexec`) or `setcap` |

The build itself is `python build.py` (PyInstaller). Packaging wraps its output.

---

## macOS — `.dmg`

```bash
python build.py                       # → dist/ArpCut-<ver>.app
# (optional, needs a Developer ID — see Signing below)
packaging/macos/create_dmg.sh         # → dist/ArpCut-<ver>.dmg
```

`create_dmg.sh` stages the app next to an `/Applications` symlink and builds a
compressed UDZO image — the familiar "drag to Applications" installer.

**Privilege.** ArpCut can't touch `/dev/bpf*` as a normal user. First launch shows
**Set Up Access**:
- **Grant Administrator Access** → one macOS password prompt, ArpCut relaunches with
  root (works immediately, unsigned).
- **Install Background Helper** → installs `com.arpcut.helper` as a LaunchDaemon
  (root), the Wireshark/Little-Snitch model, so it just works every launch.

**Signing / notarization (optional, for zero Gatekeeper friction).** Requires an
Apple Developer ID. The Hardened Runtime does **not** block BPF.
```bash
codesign --deep --force --options runtime \
  --entitlements packaging/macos/entitlements.plist \
  --sign "Developer ID Application: <you>" dist/ArpCut-<ver>.app
xcrun notarytool submit dist/ArpCut-<ver>.dmg --keychain-profile <profile> --wait
xcrun stapler staple dist/ArpCut-<ver>.dmg
```
The signed release should bundle a `arpcut-helper` executable and register it via
`SMAppService` — that turns "Set Up Access" into a single system prompt.

---

## Windows — `Setup.exe`

```bat
python build.py                                  :: → dist\ArpCut-<ver>.exe
:: put the Npcap installer here first (https://npcap.com):
::   packaging\windows\vendor\npcap.exe
iscc /DMyAppVersion=<ver> packaging\windows\arpcut.iss   :: → dist\ArpCut-<ver>-Setup.exe
```

`arpcut.iss` (Inno Setup 6):
- installs to Program Files, creates Start-menu / optional desktop shortcuts,
- **silently installs Npcap** (`/S /winpcap_mode=yes`) only if the `npcap` service
  is absent,
- requests admin (`PrivilegesRequired=admin`; the app exe also carries a
  `--uac-admin` manifest from `build.py`),
- on uninstall runs `ArpCut.exe --flush-firewall` to remove leftover `arpcut_*`
  rules.

Code-sign `ArpCut.exe` and the Setup with an EV/OV cert to avoid SmartScreen/AV
false positives (network tools trip them — keep VirusTotal links in the README).

---

## Linux — AppImage / `.deb`

Build the binary with `python build.py` (→ `dist/ArpCut`). Ship it as an AppImage
(via `linuxdeploy`) or a `.deb`. Install `packaging/linux/arpcut.desktop` and an
`arpcut` icon into the standard paths.

**Privilege.** First launch → **Set Up Access**:
- **Grant Administrator Access** → `pkexec` relaunch, or
- **Install Background Helper** → `pkexec setcap cap_net_raw,cap_net_admin+ep` on the
  interpreter/binary.

A `.deb` may run the `setcap` step in `postinst`.

---

## Uninstall hygiene (every OS)

`ArpCut.exe --flush-firewall` (works headless on all platforms) removes every
ArpCut firewall rule: unblocks tracked IPs/ports, clears port blocks, and clears
the pf anchor. The Windows uninstaller calls it automatically; document the macOS
helper removal (`launchctl bootout` + delete the LaunchDaemon plist — see
`privilege.install.macos_uninstall_script`).
