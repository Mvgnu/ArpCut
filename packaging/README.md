# ArpCut packaging — installers for non-technical users

The goal: a user double-clicks one file, installs, launches, and clicks **Set Up
Access** once — no Terminal, no commands. Each OS gets a native installer; the
in-app privilege flow (`Set Up Access`) handles elevation on first run.

| OS | Artifact | Driver | Privilege on first run |
|----|----------|--------|------------------------|
| macOS | `ArpCut-<ver>.dmg` (drag → Applications) | libpcap (built in) | native password prompt → relaunch as admin, **or** install background helper |
| Windows | `ArpCut-<ver>-Setup.exe` (Inno Setup) | **Npcap** installed separately by default | UAC (installer + app manifest) |
| Linux | `ArpCut-<ver>` standalone binary | libpcap | PolicyKit (`pkexec`) |

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
  (root). This requires a packaged `.app` whose bundle and parent directories are
  root-owned and not writable by other users. Source checkouts and user-writable
  app bundles are rejected; use administrator relaunch for development. The
  daemon authorizes the installing user's UID and accepts one controlling GUI
  session at a time.

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
iscc /DMyAppVersion=<ver> packaging\windows\arpcut.iss   :: → dist\ArpCut-<ver>-Setup.exe
```

`arpcut.iss` (Inno Setup 6):
- installs to Program Files, creates Start-menu / optional desktop shortcuts,
- leaves Npcap installation to the user by default, through the
  [official download page](https://npcap.com/#download),
- requests admin (`PrivilegesRequired=admin`; the app exe also carries a
  `--uac-admin` manifest from `build.py`),
- on uninstall runs `ArpCut.exe --flush-firewall` to remove leftover `arpcut_*`
  rules.

Npcap's public installer cannot be redistributed, and its `/S` silent-install
option is available only with OEM. See the
[Npcap OEM documentation](https://npcap.com/oem/) and
[installer options](https://npcap.com/guide/npcap-users-guide.html).
CI therefore does not download or bundle a public Npcap installer. If you hold an
OEM redistribution license, provide `packaging/windows/vendor/npcap-oem.exe` and
compile with `/DBundleNpcapOEM`; this explicitly enables the optional silent
installation when the `npcap` service is absent. Vendor installers are not tracked
in Git.

Code-sign `ArpCut.exe` and the Setup with an EV/OV cert to avoid SmartScreen/AV
false positives (network tools trip them — keep VirusTotal links in the README).

---

## Linux — standalone binary

Build the binary with `python build.py` (→ `dist/ArpCut-<ver>`). AppImage and `.deb`
targets remain unimplemented. A future package can install
`packaging/linux/arpcut.desktop` and an `arpcut` icon into the standard paths.

**Privilege.** First launch → **Set Up Access**:
- **Grant Administrator Access** → `pkexec` relaunch.
- Persistent helper installation is unavailable on Linux. Capabilities on a
  Python interpreter authorize unrelated scripts and are not a supported setup
  path. The app also needs privileged firewall/forwarding commands beyond raw
  socket access.

---

## Uninstall hygiene (every OS)

`ArpCut.exe --flush-firewall` (works headless on all platforms) removes every
ArpCut firewall rule: unblocks tracked IPs/ports, clears port blocks, and clears
the pf anchor. The Windows uninstaller calls it automatically; document the macOS
helper removal (`launchctl bootout` + delete the LaunchDaemon plist — see
`privilege.install.macos_uninstall_script`).
