# 🚀 Quick Start - From Zero to Scanning in 60 Seconds

## Windows Users (Easiest)

### Option 1: Double-Click Install (No Terminal Needed)
1. **Download this repository** 
   - Click the green "Code" button → Download ZIP
   - Extract anywhere (e.g., Downloads folder)

2. **Double-click `setup.bat`**
   - Windows will ask "Do you want to allow this app to make changes?" → Click **Yes**
   - The installer will automatically:
     - ✅ Check Python installation
     - ✅ Install all dependencies
     - ✅ Create desktop shortcut (optional)
     - ✅ Add to PATH for global `shellockolm` command (optional)

3. **Start scanning**
   - Double-click the desktop shortcut **OR**
   - Open PowerShell anywhere and type: `shellockolm scan .`

**Total time:** ~60 seconds

---

### Option 2: One-Line PowerShell (For Advanced Users)
```powershell
iex (irm https://raw.githubusercontent.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/main/scripts/install.ps1)
```

Installs everything from scratch without downloading manually.

---

## Mac/Linux Users

### One-Line Terminal Install
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/main/scripts/install.sh | bash
```

Or manual:
```bash
git clone https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner.git
cd shellockolm
pip3 install -r requirements.txt
python3 src/cli.py
```

---

## First Scan in 3 Commands

After installation:

```bash
# 1. Navigate to your project
cd C:\Users\YourName\my-react-app

# 2. Run the scan
python src/cli.py scan .

# Or if you added to PATH:
shellockolm scan .

# 3. See results instantly
```

**Example output:**
```
╔═══════════════════════════════════════════════════════════╗
║  Scan Complete - Found 3 vulnerabilities                  ║
╠═══════════════════════════════════════════════════════════╣
║  🔴 CRITICAL: React Server Components RCE (CVE-2025-55182)║
║  🟡 HIGH: Next.js middleware bypass (CVE-2025-29927)      ║
║  🟠 MEDIUM: API key exposed in .env                        ║
╚═══════════════════════════════════════════════════════════╝
```

---

## Interactive Shell

For the full experience with 60+ commands:

```bash
python src/cli.py
```

**You'll see:**
```
┌─────────────────────────────────────────────────────────────┐
│  Shellockolm - Security Detective v1.0                      │
├─────────────────────────────────────────────────────────────┤
│  1   Full Scan           → All 7 scanners, 32 CVEs          │
│  2   React Scanner       → Server Components RCE            │
│  17  Deep Malware Scan   → Detect backdoors & cryptominers  │
│  23  Scan for Secrets    → Find leaked API keys             │
│  X   QuickFix            → Auto-patch vulnerabilities       │
│  Q   Quit                                                    │
└─────────────────────────────────────────────────────────────┘

Enter command: _
```

Type a number (e.g., `1`) and press Enter to run any command.

---

## Common First Scans

### Scan your React app
```bash
shellockolm scan /path/to/my-react-app --scanner react
```

### Scan before installing a suspicious npm package
```bash
# Launch interactive shell
python src/cli.py

# Choose: 1b (Pre-Download Check)
# Enter package name: suspicious-package-name
# It will install to temp, scan, and delete automatically
```

### Full security audit (all scanners)
```bash
shellockolm scan . -o security-report.json
```

---

## Troubleshooting

### "Python not found"
**You need Python 3.10+ installed first:**
1. Go to https://www.python.org/downloads/
2. Download Python 3.10 or newer
3. **IMPORTANT:** Check "Add Python to PATH" during installation
4. Restart your terminal
5. Try again

### "Permission denied" (Windows)
Run PowerShell as Administrator:
1. Right-click PowerShell → "Run as Administrator"
2. Run: `Set-ExecutionPolicy RemoteSigned -Scope CurrentUser`
3. Try installation again

### Still stuck?
- [Installation Guide](INSTALL.md) - Full troubleshooting
- [Open an Issue](https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/issues)

---

## What Happens During Install?

The installer (`setup.bat` or `install.ps1`) does this:

1. ✅ **Checks Python** - Verifies Python 3.10+ is installed
2. ✅ **Checks pip** - Python's package manager
3. ✅ **Installs 8 dependencies** - Takes ~10 seconds
   - rich (terminal formatting)
   - typer (CLI framework)
   - requests (HTTP)
   - packaging, semver (version parsing)
   - pydantic (validation)
   - mcp (server protocol)
   - aiofiles (async I/O)
4. ✅ **Verifies installation** - Test imports
5. ✅ **Creates shortcuts** (optional)
6. ✅ **Adds to PATH** (optional) - Use `shellockolm` globally

**Total install size:** ~15 MB  
**Total time:** ~60 seconds on average internet

---

## Next Steps

After your first scan:

1. 📖 **Read the full [README](README.md)** to see all 60+ commands
2. 🎯 **Try different scanners** - React, Next.js, malware, secrets
3. 🔧 **Use auto-fix** - Type `X` in interactive shell to patch vulnerabilities
4. ⭐ **Star the repo** if it helped you!

---

**You're ready to scan! 🔍**
