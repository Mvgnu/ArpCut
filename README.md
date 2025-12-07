# ArpCut

Cross-platform network control tool for ARP spoofing. Works on Windows and macOS.

Based on [elmoCut](https://github.com/elmoiv/elmocut) by Khaled El-Morshedy (elmoiv).

**Author:** Mvgnus (Magnus Ohle)

---

## Download

Pre-built binaries are available in [Releases](https://github.com/Mvgnu/ArpCut/releases).

| Platform | File | Notes |
|----------|------|-------|
| Windows | `ArpCut.exe` | Requires [Npcap](https://npcap.com/) |
| macOS | `ArpCut-macOS.zip` | Unzip and run |
| Linux | `ArpCut` | Experimental |

**Requirements:** Administrator/root privileges required.

If the pre-built binaries don't work on your machine, build from source (see below).

---

## Features

**Scanning**
- ARP Scan - Fast device discovery
- Ping Scan - Thorough scan, finds all devices

**Device Control**
- Kill / Unkill - Block or restore individual device access
- Kill All / Unkill All - Mass control
- Full Kill - Complete traffic block via system firewall
- One-Way Kill - Block outgoing only

**Advanced**
- Lag Switch - Intermittent blocking with configurable timing and direction (incoming/outgoing/both)
- Port Blocker - Block specific ports with instant toggle, preset gaming ports included
- Traffic Monitor - Real-time bandwidth per device

**Other**
- Dark theme
- System tray
- Device nicknames
- Remember killed devices

---

## Installation from Source

### Windows

1. Install Python 3.8+ from [python.org](https://python.org/downloads) - check "Add to PATH"
2. Install [Npcap](https://npcap.com/) - check "WinPcap API-compatible Mode"
3. Clone and run:

```cmd
git clone https://github.com/Mvgnu/ArpCut.git
cd ArpCut
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python src\elmocut.py
```

Run as Administrator.

### macOS

1. Install Python:
```bash
brew install python@3.11
```

2. Clone and run:
```bash
git clone https://github.com/Mvgnu/ArpCut.git
cd ArpCut
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
sudo python3 src/elmocut.py
```

---

## Building

Install PyInstaller, then run the build script:

```bash
pip install pyinstaller pillow
python build.py
```

That's it. Works on Windows, macOS, and Linux.

Output:
- Windows: `dist/ArpCut.exe`
- macOS: `dist/ArpCut.app`
- Linux: `dist/ArpCut`

---

## Button Reference

| Button | Action |
|--------|--------|
| ARP Scan | Fast network scan |
| Ping Scan | Thorough scan |
| Kill | Block selected device |
| Unkill | Restore selected device |
| Kill All | Block all devices |
| Unkill All | Restore all devices |
| Lag Switch | Toggle intermittent blocking |
| Full Kill | Complete firewall block |
| One-Way Kill | Block outgoing only |
| Port Blocker | Block specific ports |

---

## VirusTotal

Network tools often trigger antivirus false positives. The code is open source and auditable.

<!-- Add VirusTotal link after uploading release binary -->
[Windows](https://www.virustotal.com/gui/file/0d7db182f64251f0c22952192894b66b96cd2a87f9a143767bd07bbdcad4eb14)
[Macos](https://www.virustotal.com/gui/file/948666b8fad8db4d3870123c794bad28453de5c3265d2cf0be94a1d79e086d46)
[Linux](https://www.virustotal.com/gui/file/15e91b6b6099b6271f74577c1f44070d2983121199d280d28250bec130be84c5)

---

## Disclaimer

This software is for educational and authorized network administration purposes only.

Only use on networks you own or have explicit permission to test. Unauthorized use may violate computer crime laws.

---

## Credits

- [elmoCut](https://github.com/elmoiv/elmocut) by elmoiv (Khaled El-Morshedy)
- Mvgnus (Magnus Ohle)

---

## License

GNU General Public License v3.0 - see [LICENSE](LICENSE)
