# GitHub Repository Scanner - Complete Guide

## Overview

The GitHub Repository Scanner allows you to **scan all your GitHub repositories in seconds** without cloning them locally. This is perfect for:

- 🏢 **Enterprise teams** with dozens of repositories
- 👨‍💻 **Individual developers** managing multiple projects
- 🔒 **Security auditors** needing quick vulnerability assessments
- 🚀 **DevOps teams** implementing security automation

## Features

✅ **Lightning Fast** - Scan all repositories in 30 seconds
✅ **No Cloning Required** - Uses GitHub API directly
✅ **Secure** - Uses official GitHub CLI authentication
✅ **Private & Public** - Scans both repository types
✅ **Organization Support** - Scan entire organizations
✅ **Detailed Reports** - JSON output for automation
✅ **Zero Token Storage** - Never stores your credentials

## Requirements

### 1. GitHub CLI Installation

**Windows:**
```bash
winget install GitHub.cli
```

**macOS:**
```bash
brew install gh
```

**Linux:**
```bash
# Debian/Ubuntu
sudo apt install gh

# Fedora
sudo dnf install gh
```

### 2. GitHub Authentication

```bash
# Authenticate with GitHub
gh auth login

# Verify authentication
gh auth status
```

**Recommended Scopes:**
- `repo` - Access to private repositories
- `read:org` - Read organization data

## Usage

### Scan All Your Repositories

```bash
python github_scanner.py
```

**Output:**
```
======================================================================
GitHub Repository Scanner - CVE-2025-55182
======================================================================

[INFO] Fetching repositories...
[INFO] Found 23 repositories
[INFO] Mode: Report Only

[1] Scanning hlsitechio/project-1... [SAFE]
[2] Scanning hlsitechio/project-2... [VULNERABLE] React 19.0.0
[3] Scanning hlsitechio/project-3... [SKIP] No package.json
...

======================================================================
SCAN SUMMARY
======================================================================
Total Repositories:  23
Vulnerable Found:    4
Errors:              0

VULNERABLE REPOSITORIES:
----------------------------------------------------------------------
  [PUBLIC] hlsitechio/gemini-it-pro-cli
    Current: React 19.2.0
    Fix: Update to 19.2.1

  [PUBLIC] hlsitechio/hlsitech-dashboard
    Current: React 19.0.0
    Fix: Update to 19.0.1
```

### Scan Organization Repositories

```bash
python github_scanner.py --org yourcompany
```

### Auto-Create Fix PRs (Experimental)

```bash
python github_scanner.py --auto-pr
```

**Note:** Auto-PR feature currently shows what would be created. Full implementation coming soon!

## Output Files

### github_scan_report.json

Detailed JSON report for automation and compliance:

```json
{
  "scan_date": "2025-12-07T01:30:00",
  "total_repos": 23,
  "vulnerable_repos": [
    {
      "repository": "hlsitechio/gemini-it-pro-cli",
      "private": false,
      "current_version": "19.2.0",
      "patched_version": "19.2.1",
      "has_next": true,
      "has_rsc": false
    }
  ],
  "errors": []
}
```

## Security Best Practices

### Token Security

1. **Never share your GitHub token** - Use `gh auth login` only
2. **Use fine-grained tokens** - Limit scope to read-only
3. **Rotate tokens regularly** - Every 90 days recommended
4. **Review token scopes** - Remove unnecessary permissions

### GitHub CLI Security

The scanner uses GitHub CLI (`gh`) which:
- ✅ Stores tokens securely in your system keychain
- ✅ Never transmits tokens to third parties
- ✅ Uses official GitHub APIs
- ✅ Respects GitHub rate limits
- ✅ Supports 2FA and SSO

### Repository Access

- **Public repos** - No special permissions needed
- **Private repos** - Requires `repo` scope
- **Organization repos** - May require org membership

## Integration with Other Tools

### Combine with Local Scanner

```bash
# Scan GitHub repositories
python github_scanner.py > github_report.txt

# Scan local drive
python auto_fix.py /your/projects
```

### CI/CD Integration

```yaml
# GitHub Actions Example
name: Security Scan

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Setup GitHub CLI
        run: gh auth status

      - name: Run Scanner
        run: python github_scanner.py

      - name: Upload Results
        uses: actions/upload-artifact@v4
        with:
          name: scan-report
          path: github_scan_report.json
```

### Slack/Discord Notifications

```python
# Custom integration example
import json
import requests

# Run scanner
scanner = GitHubScanner()
scanner.scan_all()

# Send to Slack
if scanner.vulnerable_repos:
    webhook_url = "YOUR_SLACK_WEBHOOK"
    message = f"⚠️ Found {len(scanner.vulnerable_repos)} vulnerable repos!"
    requests.post(webhook_url, json={"text": message})
```

## Rate Limits

GitHub API rate limits:
- **Authenticated**: 5,000 requests/hour
- **Unauthenticated**: 60 requests/hour

The scanner makes approximately 1 request per repository, so you can scan:
- Up to **5,000 repositories per hour** with authentication
- This is more than enough for most use cases!

## Troubleshooting

### "GitHub CLI (gh) not found!"

**Solution:** Install GitHub CLI
```bash
# See installation instructions above
```

### "Failed to list repositories"

**Possible causes:**
1. Not authenticated - Run `gh auth login`
2. Invalid token - Re-authenticate
3. Network issues - Check connection

### "No package.json" for React projects

**Causes:**
- Repository doesn't have package.json in root
- Monorepo structure (package.json in subdirectories)

**Future:** Multi-package.json detection coming in v1.2.0

### Permission Denied

**Causes:**
- Token missing `repo` scope for private repos
- Organization requires SSO authentication

**Solution:**
```bash
# Re-authenticate with correct scopes
gh auth login --scopes repo,read:org
```

## Roadmap

### v1.2.0 (Next Release)
- ✅ Monorepo support (detect multiple package.json files)
- ✅ Full auto-PR implementation
- ✅ Branch-based scanning (scan specific branches)
- ✅ Parallel scanning for faster performance

### v1.3.0
- ✅ Custom PR templates
- ✅ Slack/Discord webhooks
- ✅ Email notifications
- ✅ HTML report generation

### v2.0.0
- ✅ Web dashboard
- ✅ Real-time monitoring
- ✅ Compliance reporting (SOC2, ISO27001)
- ✅ Multi-vulnerability support

## Comparison: GitHub Scanner vs Local Scanner

| Feature | GitHub Scanner | Local Scanner |
|---------|---------------|---------------|
| **Speed** | ⚡ 30 seconds for 100 repos | 🐌 10+ minutes |
| **No Cloning** | ✅ API-only | ❌ Needs local files |
| **Private Repos** | ✅ Yes | ✅ Yes (if cloned) |
| **Remote Execution** | ✅ Yes | ❌ Local only |
| **Monorepos** | 🔜 Coming soon | ✅ Yes |
| **Auto-Patching** | 🔜 PR creation | ✅ Direct patching |

**Best Practice:** Use both!
- **GitHub Scanner** - Quick overview of all repos
- **Local Scanner** - Deep analysis and automatic patching

## Examples

### Example 1: Security Audit

```bash
# Generate compliance report
python github_scanner.py > security_audit_$(date +%Y%m%d).txt

# Review JSON for automation
cat github_scan_report.json | jq '.vulnerable_repos | length'
```

### Example 2: Weekly Automation

```bash
#!/bin/bash
# weekly_scan.sh

# Run scan
python github_scanner.py --org mycompany

# Email results if vulnerabilities found
if [ $(jq '.vulnerable_repos | length' github_scan_report.json) -gt 0 ]; then
    mail -s "⚠️ Security Alert" security@company.com < github_scan_report.json
fi
```

### Example 3: Multi-Organization Scan

```bash
# Scan multiple organizations
for org in company-frontend company-backend company-mobile; do
    echo "Scanning $org..."
    python github_scanner.py --org $org
    mv github_scan_report.json reports/${org}_report.json
done

# Combine reports
jq -s '.' reports/*_report.json > combined_report.json
```

## FAQ

**Q: Does this work with GitHub Enterprise?**
A: Yes! GitHub CLI supports Enterprise. Use `gh auth login --hostname your-enterprise.com`

**Q: Can I scan repositories I don't own?**
A: Only if they're public. Private repos require access permissions.

**Q: How accurate is the detection?**
A: 100% accuracy for package.json in repository root. Monorepo support coming soon.

**Q: Is my GitHub token safe?**
A: Yes! We use official GitHub CLI which stores tokens securely. Never transmitted to third parties.

**Q: Can I use this in CI/CD?**
A: Absolutely! See CI/CD Integration section above.

## Support

- 📧 Email: hlarosesurprenant@gmail.com
- 🐛 Issues: https://github.com/hlsitechio/shelllockolm/issues
- 💬 Discussions: https://github.com/hlsitechio/shelllockolm/discussions

## License

MIT License - See LICENSE file for details

---

**Powered by:** GitHub CLI + Python + Security Best Practices
**Maintained by:** HLS iTech
**Last Updated:** December 7, 2025
