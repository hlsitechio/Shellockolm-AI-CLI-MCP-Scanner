# Quick Start - 2 Minutes to Security

## Choose Your Path

### Path 1: Scan Local Projects (Fastest)

```bash
# 1. Clone the repo
git clone https://github.com/hlsitechio/shellockolm
cd shellockolm

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run auto-fix
python src/auto_fix.py /your/projects

# Done! Check the report
```

**What happens:**
- ✅ Scans all your local projects
- ✅ Finds vulnerable React versions
- ✅ Creates backups
- ✅ Patches automatically
- ✅ Verifies everything worked

---

### Path 2: Scan GitHub Repositories

```bash
# 1. Install GitHub CLI (one-time)
# Windows: winget install GitHub.cli
# Mac: brew install gh
# Linux: sudo apt install gh

# 2. Authenticate
gh auth login

# 3. Scan all your repos
python src/github_scanner.py

# That's it!
```

**What happens:**
- ✅ Lists all your GitHub repositories
- ✅ Checks package.json files via API
- ✅ No cloning required
- ✅ Works with private repos
- ✅ Generates detailed report

---

### Path 3: Use with AI Assistant

```bash
# 1. Start the MCP server
python src/server.py

# 2. In Claude Desktop/Cursor, ask:
# "Scan my projects for CVE-2025-55182"

# Done! AI handles the rest
```

---

## What You'll See

### Successful Scan Output

```
======================================================================
CVE-2025-55182 Auto-Fix Tool
======================================================================

[STEP 1] Initial Vulnerability Scan
[INFO] Scanning: /your/projects
[INFO] Found 15 projects with package.json
[VULNERABLE] project-1: React 19.0.0
[VULNERABLE] project-2: React 19.1.0
[SAFE] project-3: React 18.2.0

[STEP 2] Patching Vulnerable Projects
[PATCH] project-1: 19.0.0 → 19.0.1
  ✓ Backup created
  ✓ package.json updated
  ✓ package-lock.json updated
[PATCH] project-2: 19.1.0 → 19.1.2
  ✓ Backup created
  ✓ package.json updated
  ✓ package-lock.json updated

[STEP 3] Verification Scan
[VERIFY] Scanning all projects again...
[OK] No vulnerabilities found!

========== SUMMARY ==========
Total Projects:     15
Vulnerable:         2
Patched:            2/2 (100%)
Failed:             0
Status:             SECURE ✓
```

---

## Next Steps

1. **Run npm install** in patched projects
2. **Test your applications** to ensure compatibility
3. **Commit the changes** to version control
4. **Share with your team**

---

## Common Questions

**Q: Will this break my app?**
A: No! We only update React versions within the same major version (e.g., 19.0.0 → 19.0.1). These are security patches, not breaking changes.

**Q: What if something goes wrong?**
A: We create timestamped backups before any changes. You can always roll back.

**Q: Can I scan without patching?**
A: Yes! Use the `scanner.py` tool for read-only scanning.

---

## Need Help?

- 📖 [Full Documentation](../README.md)
- 🔍 [GitHub Scanner Guide](GITHUB_SCANNER.md)
- 🐛 [Report Issues](https://github.com/hlsitechio/shellockolm/issues)
- 💬 [Ask Questions](https://github.com/hlsitechio/shellockolm/discussions)
