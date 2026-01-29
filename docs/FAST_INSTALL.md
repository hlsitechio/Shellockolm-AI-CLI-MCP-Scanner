# ⚡ Ultra-Fast Install - Copy & Paste

**No cloning, no downloads - just one line and you're scanning.**

---

## 🪟 Windows

### PowerShell (Recommended)
```powershell
iex (irm https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.ps1)
```

### Download & Double-Click (No Terminal)
1. [Download ZIP](https://github.com/hlsitechio/shellockolm/archive/refs/heads/main.zip)
2. Extract anywhere
3. Double-click **`setup.bat`**
4. Done ✅

---

## 🐧 Linux

### Ubuntu / Debian / Mint / Pop!_OS
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install-debian.sh | bash
```

**What it does:**
- Auto-installs Python 3.10+ if missing (via apt)
- Auto-installs pip and git
- Clones repo to `~/shellockolm`
- Installs dependencies
- Creates `shellockolm` command

---

### Arch / Manjaro / EndeavourOS
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install-arch.sh | bash
```

**What it does:**
- Auto-installs Python if missing (via pacman)
- Auto-installs pip and git
- Clones repo to `~/shellockolm`
- Installs dependencies
- Creates `shellockolm` command

---

### Fedora / RHEL / CentOS
```bash
# Install Python first
sudo dnf install python3 python3-pip git

# Then run generic installer
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.sh | bash
```

---

## 🍎 macOS

### One-Line Install
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.sh | bash
```

**Requirements:** Python 3.10+ (install via [Homebrew](https://brew.sh/))
```bash
brew install python@3.11
```

---

## 🚀 After Install

### Run Your First Scan
```bash
# From install directory
cd ~/shellockolm
python src/cli.py scan .
```

**Or if you added to PATH:**
```bash
shellockolm scan /path/to/your/project
```

### Launch Interactive Shell
```bash
python src/cli.py
# or
shellockolm
```

---

## ⏱️ Installation Time

| System | Time | What Gets Installed |
|--------|------|---------------------|
| **Windows** | ~60 sec | Python deps (~15 MB) |
| **Ubuntu/Debian** | ~90 sec | Python 3.10+, pip, git, deps |
| **Arch** | ~45 sec | Python, pip, git, deps |
| **macOS** | ~60 sec | Python deps (~15 MB) |

**All installers:**
- ✅ Verify Python 3.10+
- ✅ Auto-install missing dependencies
- ✅ Test installation before completing
- ✅ Optional: Add global `shellockolm` command
- ✅ Optional: Create desktop shortcut (Windows)

---

## 🔍 What Each Installer Does

### Windows (`install.ps1`)
1. Check Python 3.10+ *(shows download link if missing)*
2. Check/install pip
3. Clone repo (if remote install)
4. Install 8 Python packages from `requirements.txt`
5. Verify imports work
6. **Optional:** Create desktop shortcut
7. **Optional:** Add `shellockolm.bat` to PATH
8. **Optional:** Run first scan immediately

### Ubuntu/Debian (`install-debian.sh`)
1. Update apt package list
2. Auto-install Python 3.10+ via apt *(or deadsnakes PPA)*
3. Auto-install pip and git
4. Clone repo to `~/shellockolm`
5. Install Python dependencies
6. Verify installation
7. **Optional:** Add alias to shell config
8. **Optional:** Run first scan immediately

### Arch (`install-arch.sh`)
1. Update pacman database
2. Auto-install Python via pacman
3. Auto-install pip and git
4. Clone repo to `~/shellockolm`
5. Install Python dependencies
6. Verify installation
7. **Optional:** Add alias to shell config
8. **Optional:** Run first scan immediately

### Generic (`install.sh`)
1. Detect Python 3.10+ *(error if missing)*
2. Detect pip *(install via ensurepip if missing)*
3. Clone repo to `~/shellockolm`
4. Install Python dependencies
5. Verify installation
6. **Optional:** Add alias to shell config
7. **Optional:** Run first scan immediately

---

## 🛟 Troubleshooting

### "Python not found" (Windows)
1. Download from https://www.python.org/downloads/
2. **Important:** Check "Add Python to PATH" during install
3. Restart PowerShell
4. Run installer again

### "Permission denied" (Windows)
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "Python version too old" (Linux)
The distro-specific installers (`install-debian.sh`, `install-arch.sh`) automatically install Python 3.10+.

If using generic `install.sh`:
```bash
# Ubuntu/Debian
sudo add-apt-repository ppa:deadsnakes/ppa
sudo apt update
sudo apt install python3.11 python3.11-venv python3-pip

# Arch
sudo pacman -S python
```

### Already installed? Update it:
```bash
cd ~/shellockolm  # or %USERPROFILE%\shellockolm on Windows
git pull origin main
pip install -r requirements.txt --upgrade
```

---

## 🎯 Quick Commands After Install

```bash
# Full scan current directory
shellockolm scan .

# Scan specific project
shellockolm scan ~/my-react-app

# Scan with specific scanner
shellockolm scan . --scanner react

# Interactive shell (60+ commands)
shellockolm

# List all 32 tracked CVEs
shellockolm cves

# Export to JSON
shellockolm scan . -o report.json

# Live probe a URL
shellockolm live https://example.com
```

---

**Total install time: 45-90 seconds depending on system** ⚡

**Zero configuration required** ✅

**Works offline after install** 🔒
