# ArpCut

**A cross-platform network control tool for ARP spoofing**

*Based on [elmoCut](https://github.com/elmoiv/elmocut) by Khaled El-Morshedy (elmoiv)*

**Author:** Mvgnus (Magnus Ohle)

---

## Table of Contents

- [About](#about)
- [Features](#features)
- [Pre-built Binaries](#pre-built-binaries)
- [Installation from Source](#installation-from-source)
  - [macOS](#macos-installation)
  - [Windows](#windows-installation)
- [Building Executables](#building-executables)
- [Usage](#usage)
- [Button Reference](#button-reference)
- [Disclaimer](#disclaimer)
- [License](#license)

---

## About

ArpCut is a fork of elmoCut, adapted to work on both **macOS** and **Windows**. It provides network control capabilities through ARP spoofing, allowing you to manage network access for devices on your local network.

## Features

- **ARP Scanning** - Fast network device discovery using ARP requests
- **Ping Scanning** - Thorough network device discovery using ICMP
- **Kill/Unkill** - Block or restore individual device network access
- **Kill All/Unkill All** - Mass network control for all devices
- **Full Kill** - Complete traffic blocking using system firewall (macOS: pf, Windows: ARP)
- **One-Way Kill** - Asymmetric traffic blocking (block outgoing only)
- **Lag Switch** - Intermittent connection blocking with configurable timing
- **Traffic Monitor** - Real-time bandwidth monitoring per device
- Clean, dark-themed UI with helpful tooltips
- System tray integration
- Device nicknames
- Remember killed devices across sessions

---

## Pre-built Binaries

Pre-built executables are available in the **Releases** section:

| Platform | File | Notes |
|----------|------|-------|
| macOS | `ArpCut.dmg` | Mount and drag to Applications |
| Windows | `ArpCut-Setup.exe` | Run installer |
| Windows | `ArpCut.exe` | Portable executable |

### ⚠️ Important Notes on Pre-built Binaries

- **macOS**: You may need to right-click → Open the first time due to Gatekeeper
- **Windows**: Requires [Npcap](https://npcap.com/) to be installed
- **Both platforms require administrator/root privileges**

If the pre-built binaries don't work on your machine (architecture mismatch, missing dependencies, security restrictions), please [build from source](#building-executables).

---

## Installation from Source

### macOS Installation

#### 1. Install Python 3.8+

**Option A: Using Homebrew (Recommended)**
```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Python
brew install python@3.11
```

**Option B: Download from python.org**
1. Go to [python.org/downloads](https://www.python.org/downloads/)
2. Download the latest Python 3.x installer for macOS
3. Run the installer

#### 2. Clone the Repository
```bash
git clone https://github.com/YOUR_USERNAME/arpcut.git
cd arpcut
```

#### 3. Create Virtual Environment (Recommended)
```bash
python3 -m venv venv
source venv/bin/activate
```

#### 4. Install Dependencies
```bash
pip install -r requirements.txt
```

#### 5. Run ArpCut
```bash
# Must run as root for network packet manipulation
sudo python3 src/elmocut.py
```

---

### Windows Installation

#### 1. Install Python 3.8+

1. Go to [python.org/downloads](https://www.python.org/downloads/windows/)
2. Download the latest Python 3.x installer (64-bit recommended)
3. **IMPORTANT**: Check "Add Python to PATH" during installation
4. Click "Install Now"

Verify installation:
```cmd
python --version
pip --version
```

#### 2. Install Npcap

Npcap is required for packet capture on Windows:

1. Download from [npcap.com](https://npcap.com/#download)
2. Run the installer
3. **IMPORTANT**: Check "Install Npcap in WinPcap API-compatible Mode"
4. Complete the installation

#### 3. Install Visual C++ Redistributable

If you encounter DLL errors, install the Visual C++ Redistributable:
- Download from [Microsoft](https://aka.ms/vs/17/release/vc_redist.x64.exe)

#### 4. Clone the Repository
```cmd
git clone https://github.com/YOUR_USERNAME/arpcut.git
cd arpcut
```

Or download and extract the ZIP file.

#### 5. Create Virtual Environment (Recommended)
```cmd
python -m venv venv
venv\Scripts\activate
```

#### 6. Install Dependencies
```cmd
pip install -r requirements.txt
```

#### 7. Run ArpCut
```cmd
# Run as Administrator (right-click Command Prompt → Run as Administrator)
python src\elmocut.py
```

---

## Building Executables

### Building on macOS (DMG)

#### Prerequisites
```bash
pip install pyinstaller
brew install create-dmg  # Optional, for creating DMG
```

#### Build
```bash
# Activate virtual environment if using one
source venv/bin/activate

# Build with PyInstaller
pyinstaller --onefile --windowed --name ArpCut \
    --add-data "exe/manuf:manuf" \
    --icon exe/icon.ico \
    src/elmocut.py

# The app will be in dist/ArpCut.app
```

#### Create DMG (Optional)
```bash
create-dmg \
    --volname "ArpCut" \
    --window-size 600 400 \
    --icon-size 100 \
    --icon "ArpCut.app" 150 200 \
    --app-drop-link 450 200 \
    "ArpCut.dmg" \
    "dist/ArpCut.app"
```

### Building on Windows (EXE)

#### Prerequisites
```cmd
pip install pyinstaller
```

#### Build
```cmd
REM Activate virtual environment if using one
venv\Scripts\activate

REM Use the included build script
python build.py

REM Or build manually
pyinstaller --onefile --windowed --name ArpCut ^
    --add-data "exe\manuf;manuf" ^
    --icon exe\icon.ico ^
    src\elmocut.py
```

The executable will be in `dist\ArpCut.exe`

---

## Usage

1. **Launch ArpCut** with administrator/root privileges
2. **Scan the network** using ARP Scan (fast) or Ping Scan (thorough)
3. **Select a device** from the discovered devices list
4. **Apply controls** using the action buttons

### Right-Click Context Menu

Right-click on any device in the table for additional options:
- Copy IP/MAC address
- Set device nickname
- Open Traffic Monitor
- Quick kill/unkill

---

## Button Reference

| Button | Action | Description |
|--------|--------|-------------|
| 🔍 ARP Scan | `btnScanEasy` | Fast network scan using ARP requests. May miss some devices. |
| 🔍 Ping Scan | `btnScanHard` | Thorough scan using ICMP ping. Slower but finds all devices. |
| ❌ Kill | `btnKill` | Block internet access for the selected device. |
| ✅ Unkill | `btnUnkill` | Restore internet access for the selected device. |
| ❌❌ Kill All | `btnKillAll` | Block internet access for ALL devices on the network. |
| ✅✅ Unkill All | `btnUnkillAll` | Restore internet access for all blocked devices. |
| ⚙️ Settings | `btnSettings` | Configure scan options, interface, and appearance. |
| ℹ️ About | `btnAbout` | View credits and version info. |
| **Lag Switch** | Text button | Create intermittent connectivity by cycling block/unblock. |
| **Full Kill** | Text button | Complete traffic block using system firewall. |
| **One-Way Kill** | Text button | Block only outgoing traffic from the device. |

---

## Disclaimer

**⚠️ This software is provided for educational and authorized network administration purposes only.**

The use of this software is done at your own discretion and risk. You are solely responsible for any damage or unauthorized access that may result from its use. 

**Only use ArpCut on networks you own or have explicit written permission to test.**

Unauthorized use of ARP spoofing tools may violate computer crime laws in your jurisdiction.

---

## Credits

- Original [elmoCut](https://github.com/elmoiv/elmocut) by [elmoiv](https://github.com/elmoiv) (Khaled El-Morshedy)
- macOS/Windows adaptation by Mvgnus (Magnus Ohle)

---

## License

This project is licensed under the **GNU General Public License v3.0**.

You are free to use, study, share, and improve this software. See [LICENSE](LICENSE) for details.

[![GNU GPLv3](https://www.gnu.org/graphics/gplv3-127x51.png)](https://www.gnu.org/licenses/gpl-3.0.en.html)
