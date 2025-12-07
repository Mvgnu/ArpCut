<p align="center">
  <img src="assets/logo.png" alt="ArpCut Logo" width="200">
</p>

<h1 align="center">ArpCut</h1>
<p align="center"><strong>Open-source network control tool for Windows & macOS</strong></p>

<p align="center">
  <a href="https://github.com/Mvgnu/ArpCut/releases/latest"><img src="https://img.shields.io/github/v/release/Mvgnu/ArpCut?style=flat-square" alt="Release"></a>
  <a href="https://github.com/Mvgnu/ArpCut/releases"><img src="https://img.shields.io/github/downloads/Mvgnu/ArpCut/total?style=flat-square" alt="Downloads"></a>
  <a href="LICENSE"><img src="https://img.shields.io/github/license/Mvgnu/ArpCut?style=flat-square" alt="License"></a>
  <a href="#virustotal"><img src="https://img.shields.io/badge/VirusTotal-Clean-brightgreen?style=flat-square" alt="VirusTotal"></a>
</p>

<p align="center">
  <a href="#-download">Download</a> •
  <a href="#-why-use-this">Why Use This?</a> •
  <a href="#-features">Features</a> •
  <a href="#-screenshots">Screenshots</a> •
  <a href="#-installation">Installation</a> •
  <a href="#-building">Building</a>
</p>

---

## 📥 Download

**Just want the app? Grab the latest release:**

| Platform | Download | Notes |
|----------|----------|-------|
| **Windows** | [ArpCut-Setup.exe](https://github.com/Mvgnu/ArpCut/releases/latest) | Run installer, requires [Npcap](https://npcap.com/) |
| **Windows Portable** | [ArpCut.exe](https://github.com/Mvgnu/ArpCut/releases/latest) | No install needed |
| **macOS** | [ArpCut.dmg](https://github.com/Mvgnu/ArpCut/releases/latest) | Drag to Applications |

> ⚠️ **Requires Administrator/Root privileges** to run (network packet manipulation needs elevated access)

---

## 🤔 Why Use This?

| Feature | ArpCut | NetCut | Other Tools |
|---------|--------|--------|-------------|
| **Price** | ✅ Free forever | ❌ Subscription | Varies |
| **Open Source** | ✅ Fully auditable | ❌ Closed source | Rarely |
| **No Ads** | ✅ Zero ads | ❌ Ad-supported | Varies |
| **Cross-Platform** | ✅ Windows + macOS | ❌ Windows only | Usually single |
| **Lag Switch** | ✅ Built-in | ❌ Not available | Rare |
| **Port Blocking** | ✅ Per-port control | ❌ Limited | Rare |

**ArpCut is the open-source alternative to NetCut.** No subscriptions, no ads, no telemetry. Every line of code is auditable.

### Perfect For:
- 🎮 **Gamers** - Lag switch for online games, port blocking for specific traffic
- 🔧 **Network Admins** - Manage device access on your network
- 🔒 **Security Testing** - Test network resilience (on networks you own!)
- 📚 **Learning** - Understand how ARP spoofing works

---

## ✨ Features

### Core Features
- **ARP Scanning** - Fast device discovery
- **Ping Scanning** - Thorough network scan
- **Kill/Unkill** - Block or restore individual device access
- **Kill All** - One-click network control

### Advanced Features
- **🎮 Lag Switch** - Create artificial lag with customizable timing
  - Incoming only / Outgoing only / Both directions
  - Preset timings (Fast/Medium/Heavy)
- **🔒 Full Kill** - Complete traffic block using system firewall
- **📡 One-Way Kill** - Block outgoing only (can receive but not send)
- **🚪 Port Blocker** - Block specific ports instantly
  - Common gaming ports preset
  - TCP/UDP selection
  - Instant toggle on/off
- **📊 Traffic Monitor** - Real-time bandwidth per device

### Quality of Life
- Dark theme UI with tooltips
- System tray integration
- Device nicknames
- Remember killed devices
- Cross-platform (Windows + macOS)

---

## 📸 Screenshots

<!-- TODO: Add actual screenshots -->

### Main Window
![Main Window](assets/screenshots/main.png)
*Main interface showing scanned devices and control buttons*

### Lag Switch
![Lag Switch](assets/screenshots/lagswitch.png)
*Lag switch configuration with directional options*

### Port Blocker
![Port Blocker](assets/screenshots/portblocker.png)
*Port blocking interface with common gaming ports*

### In Action
![Demo GIF](assets/screenshots/demo.gif)
*ArpCut in action - scanning and blocking a device*

> 📷 **Screenshots needed!** If you have good screenshots, please contribute!

---

## 🛡️ VirusTotal

Network tools often trigger false positives in antivirus software because they interact with network adapters at a low level.

**[View VirusTotal Scan Results](https://www.virustotal.com/gui/file/YOUR_HASH_HERE)**

<!-- TODO: Upload release binary to VirusTotal and replace link above -->

If you're concerned, you can:
1. Review the [source code](https://github.com/Mvgnu/ArpCut) yourself
2. Build from source (instructions below)
3. Check the VirusTotal link above

---

## 💻 Installation

### Windows (Easy Way)

1. Download [ArpCut-Setup.exe](https://github.com/Mvgnu/ArpCut/releases/latest)
2. Install [Npcap](https://npcap.com/#download) (check "WinPcap API-compatible Mode")
3. Run ArpCut as Administrator

### macOS (Easy Way)

1. Download [ArpCut.dmg](https://github.com/Mvgnu/ArpCut/releases/latest)
2. Drag to Applications
3. Right-click → Open (first time, due to Gatekeeper)
4. Run with: `sudo /Applications/ArpCut.app/Contents/MacOS/ArpCut`

### From Source (Both Platforms)

<details>
<summary><strong>Windows</strong></summary>

```powershell
# 1. Install Python 3.8+ from python.org (check "Add to PATH")
# 2. Install Npcap from npcap.com

# 3. Clone and setup
git clone https://github.com/Mvgnu/ArpCut.git
cd ArpCut
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt

# 4. Run as Administrator
python src\elmocut.py
```
</details>

<details>
<summary><strong>macOS</strong></summary>

```bash
# 1. Install Python (via Homebrew recommended)
brew install python@3.11

# 2. Clone and setup
git clone https://github.com/Mvgnu/ArpCut.git
cd ArpCut
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3. Run with root
sudo python3 src/elmocut.py
```
</details>

---

## 🔨 Building

### Automated Builds (GitHub Actions)

Every release automatically builds binaries for:
- Windows (.exe installer + portable)
- macOS (.dmg)

Just create a new release tag and binaries will be attached automatically.

### Manual Build

<details>
<summary><strong>Windows EXE</strong></summary>

```powershell
pip install pyinstaller
python build.py
# Output: dist/ArpCut.exe
```
</details>

<details>
<summary><strong>macOS DMG</strong></summary>

```bash
pip install pyinstaller
brew install create-dmg

pyinstaller --onefile --windowed --name ArpCut \
    --add-data "exe/manuf:manuf" \
    --icon exe/icon.ico \
    src/elmocut.py

create-dmg --volname "ArpCut" "ArpCut.dmg" "dist/ArpCut.app"
```
</details>

---

## 🎮 Usage Guide

### Basic Usage
1. **Launch** ArpCut with admin/root privileges
2. **Scan** using ARP (fast) or Ping (thorough)
3. **Select** a device from the list
4. **Control** using the action buttons

### Button Reference

| Button | What It Does |
|--------|--------------|
| 🔍 ARP Scan | Fast scan using ARP requests |
| 🔍 Ping Scan | Thorough scan using ICMP |
| ❌ Kill | Block selected device |
| ✅ Unkill | Restore selected device |
| ❌❌ Kill All | Block all devices |
| ✅✅ Unkill All | Restore all devices |
| **Lag Switch** | Toggle artificial lag (configurable) |
| **Full Kill** | Complete firewall block |
| **One-Way Kill** | Block outgoing only |
| **Port Blocker** | Block specific ports |

### Right-Click Menu
Right-click any device for:
- Copy IP/MAC
- Set nickname
- Traffic monitor
- Quick kill/unkill

---

## ⚠️ Disclaimer

**This software is for educational and authorized network administration only.**

- Only use on networks you **own** or have **explicit written permission** to test
- Unauthorized use may violate computer crime laws
- You are solely responsible for how you use this tool

---

## 🙏 Credits

- **Author:** [Mvgnus](https://github.com/Mvgnu) (Magnus Ohle)
- **Based on:** [elmoCut](https://github.com/elmoiv/elmocut) by [elmoiv](https://github.com/elmoiv) (Khaled El-Morshedy)

### Connect
- 🐙 GitHub: [@Mvgnu](https://github.com/Mvgnu)
- 𝕏 Twitter: [@YOUR_TWITTER](https://twitter.com/YOUR_TWITTER)
- 💬 Discord: [YOUR_DISCORD](https://discord.gg/YOUR_DISCORD)

---

## 📄 License

GNU General Public License v3.0 - see [LICENSE](LICENSE)

You are free to use, modify, and distribute this software.

<p align="center">
  <a href="https://www.gnu.org/licenses/gpl-3.0.en.html">
    <img src="https://www.gnu.org/graphics/gplv3-127x51.png" alt="GPL v3">
  </a>
</p>
