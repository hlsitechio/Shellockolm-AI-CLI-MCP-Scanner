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

---

## 🛡️ Enhanced Privacy Protections (v2.0.0+)

### Additional .gitignore Patterns

Shellockolm v2.0.0 includes **enhanced privacy protection** with over 350 .gitignore patterns to prevent accidental data exposure:

#### Protected File Types
- ✅ **All scan outputs**: `*_scan*.json`, `*_report*.csv`, etc.
- ✅ **Database files**: `*.db`, `*.sqlite`, `scan_cache.db`
- ✅ **API keys/tokens**: `*.key`, `*.token`, `.secrets`
- ✅ **Debug logs**: `debug*.log`, `trace*.log`, `error*.log`
- ✅ **Screenshots**: `screenshot*.png`, `capture*.png` (may show paths)
- ✅ **Archives**: `*_scan*.zip`, `*_report*.tar.gz`
- ✅ **CSV exports**: `*_results*.csv`, `vulnerability*.csv`
- ✅ **Local configs**: `config.local.json`, `settings.local.json`
- ✅ **User notes**: `NOTES.md`, `TODO.md`, `TASKS.md`

#### Protected Directories
- ✅ `.cache/`, `.scan_cache/`, `.vulnerability_cache/`
- ✅ `scan_output/`, `reports/`, `vulnerability_reports/`
- ✅ `test_data/`, `fixtures/`, `sample_projects/`
- ✅ `.local/`, `local/`, `my_*/`
- ✅ `generated/`, `auto_generated/`

### .gitattributes Protection

Binary and sensitive files are marked to:
- Never show diffs (protects against accidental viewing)
- Marked as `linguist-generated` (excluded from code reviews)
- Treated as binary (prevents text comparison)

### Verification Commands

Check your protection status:

```bash
# Verify .gitignore is working
git status --ignored

# Check for sensitive files
git ls-files | grep -E "(report|scan|secret|key|token)"

# Verify nothing sensitive is staged
git diff --cached --name-only
```

### Protection Checklist

Before committing:
- [ ] Run `git status --ignored` to verify sensitive files are ignored
- [ ] Check `git diff --cached` for any project paths or sensitive data
- [ ] Ensure no `*_report*.json` or `*_scan*.json` files are staged
- [ ] Verify no `.env`, `*.key`, or `*.token` files are included
- [ ] Review PR diffs carefully before submitting

---

## 🔒 Additional Security Recommendations

### 1. Use Global .gitignore

Create `~/.gitignore_global` for system-wide protection:

```bash
# Create global gitignore
cat > ~/.gitignore_global << 'EOF'
# Scan results
*_scan*.json
*_report*.json
*_results*.csv

# Secrets
*.key
*.token
.secrets
.env.local

# Screenshots
screenshot*.png
capture*.png
EOF

# Enable it globally
git config --global core.excludesfile ~/.gitignore_global
```

### 2. Pre-commit Hook

Add this pre-commit hook to `.git/hooks/pre-commit`:

```bash
#!/bin/bash
# Pre-commit hook to prevent sensitive data commits

SENSITIVE_PATTERNS=(
  "*_report*.json"
  "*_scan*.json"
  "*.key"
  "*.token"
  ".secrets"
  "*_results*.csv"
)

for pattern in "${SENSITIVE_PATTERNS[@]}"; do
  if git diff --cached --name-only | grep -q "$pattern"; then
    echo "❌ ERROR: Attempting to commit sensitive file matching: $pattern"
    echo "Please remove it from staging area"
    exit 1
  fi
done

echo "✅ Pre-commit check passed"
```

### 3. Scan Your Repo

Check if you've accidentally committed sensitive data:

```bash
# Search entire git history for sensitive patterns
git log --all --full-history --source -- "*_report*.json"
git log --all --full-history --source -- "*_scan*.json"

# Search for potential secrets
git grep -E "(api[_-]?key|secret|token|password)" $(git rev-list --all)
```

### 4. Remove Accidentally Committed Files

If you accidentally committed sensitive data:

```bash
# Remove from current commit (not yet pushed)
git reset HEAD path/to/sensitive_file.json
git commit --amend

# Remove from history (if already pushed - DANGEROUS)
git filter-branch --force --index-filter \
  "git rm --cached --ignore-unmatch path/to/sensitive_file.json" \
  --prune-empty --tag-name-filter cat -- --all

# Force push (coordinate with team first!)
git push --force --all
```

---

## 📋 Privacy Audit Checklist

Run this monthly audit:

- [ ] **Check .gitignore coverage**: `git ls-files | wc -l` (should be minimal)
- [ ] **Verify ignored files**: `git status --ignored | wc -l` (should be high)
- [ ] **Scan commit history**: No sensitive files in `git log --all --name-only`
- [ ] **Review recent commits**: `git log -10 --stat` (no reports/scans)
- [ ] **Check remote**: Ensure fork/clones don't have sensitive data
- [ ] **Audit GitHub**: Review repo file list on GitHub web interface

---

## 🆘 Incident Response

### If Sensitive Data is Exposed

1. **Immediate Actions**:
   - Remove the file from repository
   - Rotate any exposed credentials
   - Notify affected parties
   - Document the incident

2. **Clean History**:
   - Use `git filter-branch` or `BFG Repo-Cleaner`
   - Force push cleaned history
   - Ask collaborators to re-clone

3. **Prevention**:
   - Add missing patterns to `.gitignore`
   - Install pre-commit hooks
   - Train team members
   - Regular audits

---

## 📞 Privacy Questions?

- 📖 Check `.gitignore` file for full list of protected patterns
- 🐛 Report privacy concerns: https://github.com/hlsitechio/shellockolm/security
- 📧 Email: hlarosesurprenant@gmail.com

**Remember: Your security is our priority. When in doubt, don't commit it!**

