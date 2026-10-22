# Building ArpCut

## Prerequisites

### All Platforms
- Python 3.10+
- PyInstaller 5.x+
- `pip install -r requirements.txt pyinstaller`

### Windows
- **Npcap** — download from [nmap.org/npcap](https://nmap.org/npcap/) (required for raw packet capture)
- Visual Studio Build Tools (only if compiling `restart.c`)
- Admin privileges for testing (ARP spoofing requires it)

### macOS
- **libpcap** (bundled with macOS)
- Xcode command line tools: `xcode-select --install`
- The `.app` build uses the bundled `exe/icon.icns`
- Run with `sudo` for full functionality (BPF access)

### Linux
- **libpcap-dev**: `sudo apt install libpcap-dev` (Debian/Ubuntu)
- Run with `sudo` for raw socket access

## Building

```bash
# Install dependencies
pip install -r requirements.txt pyinstaller

# Build for current platform
python build.py
```

## Output

| Platform | Output | Notes |
|----------|--------|-------|
| Windows | `dist/ArpCut-<version>.exe` | Single-file, UAC admin prompt |
| macOS | `dist/ArpCut-<version>.app` | App bundle directory; `python build.py --dmg` packages it |
| Linux | `dist/ArpCut-<version>` | Single-file binary; no AppImage / `.deb` target yet |

Build paths are resolved relative to `build.py`, so invoking the script from
another working directory uses the same sources and output directory. Windows
installer and driver requirements are documented in `packaging/README.md`.

## Tests

```bash
pip install -r requirements-dev.txt
QT_QPA_PLATFORM=offscreen python -m pytest -q
```

The development requirements include `cryptography` for Scapy's TLS test fixtures.
On Windows, set the environment variable separately before running pytest.

## Version Bumping

The version string lives in `src/constants.py` as `__version__`.
Update it there before building a release:

```python
__version__: str = '2.0.0'  # ← bump this
```

`build.py` reads this constant and injects it into the PyInstaller build.
