# 🚀 Installation Guide

Multiple ways to install Shellockolm - choose what works best for you.

---

## ⚡ One-Line Install (Recommended for Windows)

### Method 1: Remote Install (from anywhere)
```powershell
iex (irm https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.ps1)
```

This will:
- Clone the repository to `%USERPROFILE%\shellockolm`
- Install Python dependencies
- Verify installation
- Optionally create desktop shortcut
- Optionally add to PATH for global `shellockolm` command

### Method 2: Local Install (if already cloned)
```powershell
cd shellockolm
.\install.ps1
```

### Method 3: Double-Click Install (easiest)
1. Download or clone this repository
2. Double-click `setup.bat`
3. Follow the prompts

---

## 🐧 Linux/Mac Install

### One-Liner
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/install.sh | bash
```

### Manual Install
```bash
git clone https://github.com/hlsitechio/shellockolm.git
cd shellockolm
pip install -r requirements.txt
python src/cli.py
```

---

## 📦 What Gets Installed

**Python packages** (from `requirements.txt`):
- `rich` - Terminal formatting
- `typer` - CLI framework
- `requests` - HTTP requests
- `packaging` - Version parsing
- `semver` - Semantic versioning
- `pydantic` - Data validation
- `mcp` - MCP server support
- `aiofiles` - Async file operations

**Total size:** ~15 MB

---

## ✅ Verify Installation

After installation, verify everything works:

```bash
python src/cli.py --version
```

Or run a quick test:
```bash
python src/cli.py scan --help
```

---

## 🎯 Quick Start After Install

### 1. Scan your current project
```bash
python src/cli.py scan .
```

### 2. Launch interactive shell
```bash
python src/cli.py
```

### 3. Scan a specific project
```bash
python src/cli.py scan /path/to/your/app
```

---

## 🔧 Troubleshooting

### "Python not found"
**Windows:**
1. Download from https://www.python.org/downloads/
2. **Important:** Check "Add Python to PATH" during installation
3. Restart terminal/PowerShell

**Linux/Mac:**
```bash
# Ubuntu/Debian
sudo apt install python3 python3-pip

# macOS
brew install python3
```

### "pip not found"
```bash
python -m ensurepip --default-pip
python -m pip install --upgrade pip
```

### "Permission denied" on Windows
Run PowerShell as Administrator:
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### "ModuleNotFoundError" after install
Reinstall dependencies:
```bash
pip install -r requirements.txt --force-reinstall
```

### Dependencies won't install
Try upgrading pip first:
```bash
python -m pip install --upgrade pip
pip install -r requirements.txt
```

---

## 🌐 Global Command (Optional)

To use `shellockolm` from anywhere:

**Windows:**
The installer offers to add to PATH automatically. Or manually:
1. Add repository directory to your PATH
2. Use the `shellockolm.bat` wrapper created during install

**Linux/Mac:**
```bash
# Add to ~/.bashrc or ~/.zshrc
alias shellockolm='python /path/to/shellockolm/src/cli.py'

# Or create a symlink
sudo ln -s /path/to/shellockolm/src/cli.py /usr/local/bin/shellockolm
```

---

## 🔄 Update Shellockolm

### If installed via one-liner
```bash
cd %USERPROFILE%\shellockolm  # Windows
cd ~/shellockolm              # Linux/Mac

git pull origin main
pip install -r requirements.txt --upgrade
```

### If using PATH command
Just run the installer again - it will update in place.

---

## 🗑️ Uninstall

### Remove Python packages
```bash
pip uninstall -r requirements.txt -y
```

### Remove repository
**Windows:**
```powershell
Remove-Item -Recurse -Force $env:USERPROFILE\shellockolm
```

**Linux/Mac:**
```bash
rm -rf ~/shellockolm
```

### Remove from PATH
**Windows:** 
1. System Properties → Environment Variables
2. Edit "Path" under "User variables"
3. Remove Shellockolm entry

**Linux/Mac:**
Remove the alias/symlink from your shell config.

---

## 🆘 Still Having Issues?

- [Open an issue](https://github.com/hlsitechio/shellockolm/issues)
- [Check existing issues](https://github.com/hlsitechio/shellockolm/issues)
- [Discussions](https://github.com/hlsitechio/shellockolm/discussions)

---

## 🎓 Next Steps

After installation:
1. Read the [Quick Start Guide](docs/QUICK_START.md)
2. Try the [interactive shell](#quick-start-after-install)
3. Scan your first project
4. ⭐ Star the repo if it helped!
