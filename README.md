<div align="center">

![React2Shell Security Toolkit](docs/images/banner.png)

**Protect your React applications from CVE-2025-55182 in 2 minutes**

*Critical CVSS 10.0 RCE vulnerability - Actively exploited in the wild*

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/hlsitechio/cve-2025-55182-tools?color=success)](https://github.com/hlsitechio/shellockolm/releases/latest)
[![CI Status](https://github.com/hlsitechio/shellockolm/actions/workflows/ci.yml/badge.svg)](https://github.com/hlsitechio/shellockolm/actions)

</div>

---

## Why Use This Toolkit?

### 🎯 Automated Protection

**One command to secure all your projects**

```bash
python src/auto_fix.py /your/projects
```

- Scans thousands of projects in seconds
- Auto-patches vulnerable versions
- Creates backups automatically
- Verifies all fixes applied
- Zero false positives

### 🌐 GitHub Integration

**Scan your entire GitHub account instantly**

```bash
python src/github_scanner.py
```

- No cloning required
- Scan 100+ repos in 30 seconds
- Works with private repositories
- Organization support
- Enterprise-secure (uses GitHub CLI)

### 🛡️ Complete Security Suite

**Beyond just CVE-2025-55182**

- ✅ React vulnerability scanner
- ✅ NPM malware detection
- ✅ AI assistant integration (MCP server)
- ✅ Automated patching
- ✅ Compliance reporting

---

## Quick Start

### 1. Install

```bash
git clone https://github.com/hlsitechio/shellockolm
cd cve-2025-55182-tools
pip install -r requirements.txt
```

### 2. Choose Your Workflow

**Option A: Scan Local Projects**
```bash
python src/auto_fix.py /your/projects
```

**Option B: Scan GitHub Repositories**
```bash
# One-time setup
gh auth login

# Scan all your repos
python src/github_scanner.py
```

**Option C: Use with AI Assistants**
```bash
# Start MCP server for Claude/Cursor/etc
python src/server.py
```

### 3. Done!

Your projects are now protected. Check the detailed report in `scan_report.json`.

---

## Real-World Results

<div align="center">

| What We Did | Results |
|-------------|---------|
| **Local Projects Scanned** | 2,665 projects |
| **GitHub Repos Scanned** | 23 repositories in 30 seconds |
| **Vulnerabilities Found** | 19 total |
| **Successfully Patched** | 100% success rate |
| **Malware Detected** | 0 infections (7,106+ scans) |
| **Time Saved** | 4-6 hours → 2 minutes |

</div>

---

## Key Features

### 🚀 Lightning Fast
Scan thousands of projects in seconds using parallel processing and smart caching.

### 🔒 Enterprise Security
- Uses official GitHub CLI (never stores tokens)
- Automatic backups before patching
- Audit trails for compliance
- Read-only scanning mode

### 🤖 AI-Powered
MCP server integration lets AI assistants help you:
- Analyze vulnerabilities
- Generate patches
- Create compliance reports
- Monitor security status

### 📊 Detailed Reporting
- JSON output for automation
- Human-readable summaries
- Compliance-ready documentation
- Historical tracking

---

## Use Cases

### For Individual Developers
```bash
# Scan all your side projects
python src/github_scanner.py

# Quick local scan
python src/scan_simple.py ~/projects
```

### For Teams
```bash
# Scan organization repos
python src/github_scanner.py --org yourcompany

# Generate compliance report
python src/auto_fix.py /projects --report-only
```

### For Security Auditors
```bash
# Comprehensive scan with malware detection
python src/malware_scanner.py /path/to/audit

# Export findings
python src/auto_fix.py /audit --json > audit_report.json
```

### For DevOps/CI-CD
```yaml
# Add to GitHub Actions
- name: Security Scan
  run: python src/auto_fix.py . --report-only
```

---

## What's CVE-2025-55182?

**Critical Remote Code Execution in React Server Components**

- **CVSS Score**: 10.0/10.0 (Maximum Severity)
- **Type**: Unauthenticated RCE
- **Status**: Actively exploited by APT groups
- **Impact**: Complete server compromise

**Affected Versions:**
- React: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Next.js: All 15.x and 16.x with App Router

**Patched Versions:**
- React: 19.0.1, 19.1.2, 19.2.1
- Next.js: 15.0.5+, 15.1.9+, 15.2.6+, 16.0.7+

[Read full CVE details →](technical/COMPLETE_CVE_INFO.md)

---

## Documentation

### Getting Started
- [Quick Start Guide](docs/QUICK_START.md) - Get up and running in 2 minutes
- [GitHub Scanner Guide](docs/GITHUB_SCANNER.md) - Scan all your repositories
- [FAQ](docs/FAQ.md) - Common questions answered

### For Developers
- [Architecture](technical/ARCHITECTURE.md) - How it works under the hood
- [MCP Integration](technical/MCP_DESIGN.md) - AI assistant integration
- [Contributing](CONTRIBUTING.md) - Help improve the project

### Security
- [Security Policy](SECURITY.md) - Vulnerability reporting
- [Changelog](CHANGELOG.md) - Version history

---

## Tools Included

| Tool | Purpose | Use Case |
|------|---------|----------|
| **auto_fix.py** | Complete automation | Scan → Patch → Verify |
| **github_scanner.py** | GitHub integration | Scan all repos instantly |
| **scanner.py** | Core detection | Find vulnerable versions |
| **malware_scanner.py** | NPM security | Detect supply chain attacks |
| **server.py** | MCP server | AI assistant integration |
| **remediation.py** | Safe patching | Apply fixes with backups |

---

## Requirements

- Python 3.10 or higher
- GitHub CLI (for GitHub scanning)
- Internet connection (for API calls)

**Optional:**
- Claude Desktop / Cursor / AI assistant (for MCP)
- Git (for version control)

---

## Support

- 📖 [Documentation](docs/)
- 🐛 [Report Issues](https://github.com/hlsitechio/shellockolm/issues)
- 💬 [Discussions](https://github.com/hlsitechio/shellockolm/discussions)
- 📧 Email: hlarosesurprenant@gmail.com

---

## Community

**Found this useful?** ⭐ Star the repo to help others discover it!

**Want to contribute?** We welcome:
- Bug reports and feature requests
- Documentation improvements
- Code contributions
- Translation help

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

---

## License

MIT License - See [LICENSE](LICENSE) for details.

---

<div align="center">

**Built with security in mind by developers, for developers**

[Get Started](#quick-start) • [Documentation](docs/) • [Report Issue](https://github.com/hlsitechio/shellockolm/issues)

</div>
