# Privacy & Security Guide

## 🔒 Your Data Privacy is Critical

This tool is **100% local** and **never uploads your code or project information** to any external servers. However, it creates local files that contain sensitive information about your projects. This guide helps you protect that data.

---

## ⚠️ What Information This Tool Collects Locally

The scanner creates local files containing:

### Sensitive Information
- **Project paths** (absolute file paths to your projects)
- **Project names** (directory names)
- **Package versions** (React, Next.js, npm package versions)
- **Vulnerability details** (which projects are vulnerable)
- **GitHub repository names** (when using GitHub scanner)

### Files Created by This Tool

| File Pattern | Contains | Risk Level |
|--------------|----------|------------|
| `*_report*.json` | Project paths, versions, vulnerabilities | **HIGH** |
| `*_scan*.json` | Project paths, scan results | **HIGH** |
| `github_scan_report.json` | GitHub repo names, vulnerabilities | **CRITICAL** |
| `malware_scan_report_*.json` | Project paths, potential malware findings | **HIGH** |
| `*.backup` | Original package.json files | **MEDIUM** |
| `mcp_server.log` | Scanned paths, MCP requests | **MEDIUM** |

---

## 🛡️ How Your Data is Protected

### 1. **.gitignore Protection** ✅

The `.gitignore` file automatically prevents these sensitive files from being committed to git:

```gitignore
# All scan reports are blocked
*_report*.json
*_scan*.json
github_scan_report.json
malware_scan_report_*.json

# Backup files are blocked
*.backup
*.backup_*
package.json.backup*

# Output directories are blocked
scan_output/
reports/
vulnerability_reports/
```

### 2. **Local-Only Operation** ✅

- ✅ **No internet required** (except for GitHub CLI when scanning GitHub repos)
- ✅ **No telemetry or tracking**
- ✅ **No cloud uploads**
- ✅ **No API calls** (except to GitHub API via `gh` CLI for GitHub scanning)

### 3. **Open Source & Auditable** ✅

- ✅ All code is open source
- ✅ You can audit exactly what the tool does
- ✅ No obfuscated or compiled code

---

## ⚠️ Security Best Practices

### DO ✅

1. **Keep scan reports local only**
   - Review reports locally
   - Delete reports when no longer needed
   - Store reports in encrypted folders if needed

2. **Check before committing**
   ```bash
   git status
   git diff
   # Make sure no *_report*.json files are staged
   ```

3. **Use on trusted machines only**
   - Only run scans on your own computer
   - Avoid running on shared or public machines

4. **Review the .gitignore**
   - Make sure `.gitignore` is working
   - Add project-specific patterns if needed

### DON'T ❌

1. **Never commit scan reports**
   - They contain your project structure
   - They reveal what you're working on
   - They show your vulnerabilities

2. **Never share reports publicly**
   - Don't post on GitHub issues
   - Don't share in public Slack/Discord
   - Don't include in pull requests

3. **Never run on untrusted code**
   - Don't scan projects you don't trust
   - Malicious code could read scan results

---

## 🔍 What Information is NOT Collected

This tool **NEVER** collects:

- ❌ Your source code
- ❌ Environment variables or secrets
- ❌ Authentication tokens
- ❌ Personal information
- ❌ Telemetry or analytics
- ❌ Error reports (unless you explicitly share them)

---

## 📝 Data You Might Share (If You Choose)

### Safe to Share:
- ✅ Total number of projects scanned
- ✅ Total number of vulnerabilities found
- ✅ React/Next.js version numbers (without project names)
- ✅ Anonymous statistics

### NEVER Share:
- ❌ Full scan reports
- ❌ Project paths
- ❌ Project names
- ❌ GitHub repository names (unless you want to disclose them)

---

## 🚨 If You Accidentally Commit Sensitive Data

### If you committed a scan report:

1. **Remove from git history immediately:**
   ```bash
   # Remove the file
   git rm --cached github_scan_report.json
   git commit -m "Remove sensitive scan report"

   # If already pushed, use git filter-branch or BFG Repo-Cleaner
   ```

2. **Consider the data exposed:**
   - If it contained private repo names, assume they're now public
   - If it contained project paths, review what information that reveals
   - Rotate any secrets that might have been exposed indirectly

3. **Update .gitignore** to prevent future accidents

---

## 🔐 Additional Security Measures

### For Extra Security:

1. **Encrypt scan results:**
   ```bash
   # Encrypt reports before storing
   gpg -c github_scan_report.json
   rm github_scan_report.json  # Delete unencrypted version
   ```

2. **Use a separate scan directory:**
   ```bash
   # Keep all reports in one secure location
   mkdir ~/secure-scans
   python src/auto_fix.py /your/projects > ~/secure-scans/report.json
   ```

3. **Auto-delete old reports:**
   ```bash
   # Add to your cleanup script
   find . -name "*_report*.json" -mtime +7 -delete
   ```

---

## 📞 Questions?

If you have security concerns or questions:

1. **Check the code** - It's all open source
2. **Review the .gitignore** - Make sure it's protecting your files
3. **Open an issue** - If you find a security problem, please report it responsibly

---

## 📜 Privacy Summary

| Aspect | Status |
|--------|--------|
| **Data Collection** | Local only |
| **Internet Access** | Only for GitHub CLI (optional) |
| **Code Upload** | Never |
| **Telemetry** | None |
| **Third-party Services** | None (except GitHub API via CLI) |
| **Open Source** | Yes - fully auditable |

---

**Remember: This tool is a security scanner. Protect its output as you would protect a security audit report.**

Stay safe! 🔒
