# Building ArpCut

## Prerequisites

### All Platforms
- Python 3.10+
- PyInstaller 5.x+
- `pip install -r requirements.txt`

### Windows
- **Npcap** — download from [nmap.org/npcap](https://nmap.org/npcap/) (required for raw packet capture)
- Visual Studio Build Tools (only if compiling `restart.c`)
- Admin privileges for testing (ARP spoofing requires it)

### macOS
- **libpcap** (bundled with macOS)
- Xcode command line tools: `xcode-select --install`
- For `.app` bundle: convert `exe/icon.ico` to `.icns` using `iconutil`
- Run with `sudo` for full functionality (BPF access)

### Linux
- **libpcap-dev**: `sudo apt install libpcap-dev` (Debian/Ubuntu)
- Run with `sudo` for raw socket access

## Building

```bash
# Install dependencies
pip install -r requirements.txt

# Build for current platform
python build.py
```

## Output

| Platform | Output | Notes |
|----------|--------|-------|
| Windows | `dist/ArpCut.exe` | Single-file, UAC admin prompt |
| macOS | `dist/ArpCut.app` | App bundle directory |
| Linux | `dist/ArpCut` | Single-file binary |

## Version Bumping

The version string lives in `src/constants.py` as `__version__`.
Update it there before building a release:

```python
__version__: str = '2.0.0'  # ← bump this
```

`build.py` reads this constant and injects it into the PyInstaller build.
