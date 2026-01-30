<div align="center">

# 🔍 Shellockolm

**Security scanner that found critical vulnerabilities in 15 of my React projects**

![Shellockolm - Your Security Detective](docs/images/banner.png)

</div>

## ⚡ Install & Run in 60 Seconds

<div align="center">

### 🪟 Windows
```powershell
iex (irm https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install.ps1)
```
**Or:** [Download ZIP](https://github.com/hlsitechio/shellockolm/archive/refs/heads/main.zip) → Double-click `scripts/setup.bat`

---

### 🐧 Ubuntu / Debian / Mint
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install-debian.sh | bash
```

---

### 🏔️ Arch / Manjaro
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install-arch.sh | bash
```

---

### 🍎 macOS
```bash
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install.sh | bash
```

---

**Then run:** `python src/cli.py scan .` → ✅ **Instant security audit**

🤖 **Want AI integration?** `python src/configure_mcp.py` → Use Shellockolm inside Claude/Copilot!

📖 **[Full installation guide](docs/INSTALL.md)** | 🚀 **[Quick start](docs/QUICKSTART.md)** | ⚡ **[Fast install reference](docs/FAST_INSTALL.md)** | 🤖 **[MCP Setup](docs/MCP_SETUP.md)**

</div>

<div align="center">

**✅ 32 CVEs detected** | **✅ Malware & secrets found** | **✅ Auto-fix with backups** | **✅ 100% offline**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![One-Line Install](https://img.shields.io/badge/install-one%20line-success)](docs/INSTALL.md)
[![GitHub Release](https://img.shields.io/github/v/release/hlsitechio/shellockolm?color=success)](https://github.com/hlsitechio/shellockolm/releases/latest)

[What It Finds](#-what-it-finds) • [Live Demo](#-see-it-in-action) • [All Features](#-complete-features) • [Full Docs](docs/INSTALL.md)

</div>

---

## 🚨 Why This Exists

**I scanned 15 React apps. Every single one was vulnerable.**

### 💀 What I Found (In 2 Minutes):
- 🔴 **Remote Code Execution** → React Server Components CVE-2025-55182
- 🔴 **Middleware Bypass** → Next.js authentication broken  
- ☠️ **Malware** → Hidden in npm packages I trusted
- 🔑 **API Keys Exposed** → Sitting in `.env` files, pushed to Git
- 🦠 **Supply Chain Attack** → Dependencies were compromised

### ⏱️ Manual Audit = 3 Days. This Tool = 2 Minutes.

**If you're shipping React/Next.js to production without scanning, you're playing Russian roulette with your users' data.**

---

## 🎯 What It Finds

<table>
<tr>
<td width="50%">

### 🔴 Critical CVEs
- **React Server Components RCE** (CVSS 10.0)
- **Next.js middleware bypass** (CVSS 9.1)
- **n8n unauthenticated RCE** (CVSS 10.0)
- **Node.js runtime vulnerabilities**
- **npm package exploits** (mysql2, jsonpath-plus, etc.)

</td>
<td width="50%">

### 🦠 Threats & Secrets
- **Malware detection** (obfuscation, cryptominers, backdoors)
- **Supply chain attacks** (Shai-Hulud worm, typosquatting)
- **Secret exposure** (API keys, AWS credentials, tokens)
- **AI gateway leaks** (Clawdbot/Moltbot credential piggybacking)

</td>
</tr>
</table>

**Tracks 32 unique CVEs** across React, Next.js, Node.js, npm, n8n, and supply chain attacks.

---

## 🎬 See It In Action

### Interactive Shell
```
┌─────────────────────────────────────────────────────────────┐
│  Shellockolm - Security Detective v1.0                      │
├─────────────────────────────────────────────────────────────┤
│  1   Full Scan           → All 7 scanners, 32 CVEs          │
│  2   React Scanner       → Server Components RCE            │
│  3   Next.js Scanner     → Middleware bypass                │
│  17  Deep Malware Scan   → RCE payloads, cryptominers       │
│  23  Scan for Secrets    → 50+ patterns, high entropy       │
│  X   QuickFix            → Auto-patch all vulnerabilities   │
└─────────────────────────────────────────────────────────────┘
```

### CLI One-Liners
```bash
# Full security audit
python src/cli.py scan .

# Scan before installing npm package
python src/cli.py scan --scanner npm ./suspicious-package

# Export to JSON for CI/CD
python src/cli.py scan . -o security-report.json

# Live probe a URL for exploits
python src/cli.py live https://target.com

# Hunt for a specific CVE
python src/cli.py info CVE-2025-55182
```

---

## 💡 Why Shellockolm?

| Problem | Other Tools | Shellockolm |
|---------|-------------|-------------|
| **Speed** | Hours of manual auditing | 30 seconds full scan |
| **Depth** | Generic CVE databases | 32 hand-tracked vulnerabilities |
| **Privacy** | Cloud-based, upload your code | 100% local, zero telemetry |
| **False Positives** | Noisy, generic warnings | Hand-tuned detection patterns |
| **Usability** | Complex configs, API keys | Works immediately, no setup |
| **Coverage** | CVEs only | CVEs + malware + secrets + supply chain |

---

## 🛠️ Complete Features

<details>
<summary><strong>📊 7 Specialized Scanners</strong></summary>

| Scanner | What It Detects | CVEs Covered |
|---------|----------------|--------------|
| **React RSC** | Server Components RCE, source code exposure, DoS | CVE-2025-55182, CVE-2025-66478, +3 more |
| **Next.js** | Middleware authorization bypass, RSC vulnerabilities | CVE-2025-29927, CVE-2025-66478 |
| **npm Packages** | RCE in mysql2, jsonpath-plus; DoS in body-parser, multer | CVE-2024-21508, CVE-2024-21534, +6 more |
| **Node.js Runtime** | HTTP/2 crash, TLS memory leak, permission model bypass | CVE-2025-59465, +8 more |
| **n8n** | Ni8mare unauthenticated RCE, expression injection | CVE-2026-21858, CVE-2025-68613, CVE-2025-68668 |
| **Supply Chain** | Shai-Hulud worm, eslint-config-prettier compromise | CVE-2025-54313 + 10 campaign CVEs |
| **Clawdbot/Moltbot** | AI gateway credential leaks, OAuth piggybacking | 4 critical auth bypass patterns |

**Total: 32 unique CVEs tracked**

</details>

<details>
<summary><strong>🦠 Advanced Malware Detection</strong></summary>

- **Obfuscation detection** - Hex, base64, eval chains
- **Cryptominers** - Monero, Bitcoin mining scripts
- **Backdoors** - Reverse shells, command injection
- **Data exfiltration** - Suspicious HTTP requests
- **Typosquatting** - Packages mimicking popular libraries
- **100+ detection patterns** hand-tuned for JavaScript/Node.js

</details>

<details>
<summary><strong>🔐 Secrets Scanner</strong></summary>

Finds leaked credentials in code, configs, and environment files:

- AWS Access Keys & Secret Keys
- GitHub Personal Access Tokens
- Slack Bot Tokens & Webhooks
- Stripe API Keys
- Private Keys (RSA, SSH, PGP)
- Database connection strings
- OAuth tokens & refresh tokens
- **50+ patterns** + high-entropy string detection

</details>

<details>
<summary><strong>⚡ Auto-Fix & Remediation</strong></summary>

- **One-command patching** - Automatically upgrade vulnerable packages
- **Automatic backups** - Timestamped snapshots before changes
- **Dry-run mode** - Preview changes without applying
- **Rollback support** - Restore from backup if issues occur
- **Fix wizard** - Step-by-step guided remediation

</details>

<details>
<summary><strong>🔄 CI/CD Integration</strong></summary>

```yaml
# GitHub Actions
- name: Security Scan
  run: |
    pip install -r requirements.txt
    python src/cli.py scan . -o results.json
```

- **SARIF export** for GitHub Code Scanning
- **JSON reports** for automated processing
- **Exit codes** for build failures on criticals
- **Watch mode** for continuous monitoring

</details>

<details>
<summary><strong>📋 60+ Interactive Commands</strong></summary>

**Scanning**: Full scan, React, Next.js, npm, Node.js, n8n, supply chain, custom  
**Malware**: Deep scan, quarantine, package removal, code cleaning  
**Secrets**: Scan all files, .env targeting, high-entropy detection  
**Live Probing**: Test URLs for exploitable vulnerabilities  
**CVE Intelligence**: List CVEs, filter by severity, bug bounty targets  
**Reports**: JSON, SARIF, Markdown, security scoring (A-F)  
**Auto-Fix**: Patch vulnerabilities, preview changes, rollback  
**Dependencies**: Lockfile analysis, duplicate detection, typosquatting  
**SBOM**: Generate CycloneDX or SPDX bills of materials  
**And more**: Ignore rules, GitHub Advisory queries, dependency trees

[See full command reference →](#complete-command-reference)

</details>

---

## 📖 Common Use Cases

### 🔍 Audit your React/Next.js app
```bash
python src/cli.py scan ~/my-nextjs-app --scanner nextjs
```

### 🛡️ Check before npm install
```bash
# Sandbox install + scan in temp directory
python src/cli.py shell
> 1b  # Pre-Download Check
> suspicious-package-name
```

### 🚨 Hunt for a specific CVE
```bash
python src/cli.py shell
> 1d  # CVE Hunter
> CVE-2025-29927
> /path/to/project
```

### 🤖 Live probe for exploits
```bash
python src/cli.py live https://target.com --scanner n8n
```

### 📊 Generate security report
```bash
python src/cli.py scan . -o report.json
python src/cli.py shell
> 37  # Export SARIF for GitHub Code Scanning
```

---

## 🎓 Why Python for a JavaScript Security Tool?

**Shellockolm scans JavaScript projects from the outside** — it doesn't execute your code, it inspects it.

- ✅ **No conflict with target** - No shared dependencies, no `node_modules` pollution
- ✅ **No supply chain risk to scanner** - Zero npm dependencies = zero attack surface
- ✅ **Cross-platform with no build** - Works on Windows/Linux/macOS with `pip install`
- ✅ **Rich CLI out of box** - Beautiful tables, progress bars, colored output
- ✅ **Fast enough** - Static analysis doesn't need V8's JIT

The scanner sits **outside the blast radius** of the ecosystem it's auditing.

---

## 🔒 Privacy & Security

- **100% Local** — All scans run on your machine
- **No Upload** — Your code never leaves your system
- **No Telemetry** — Zero data collection
- **No API Keys** — Works completely offline
- **Open Source** — Full transparency (MIT License)

---

## 📚 Complete Command Reference

<details>
<summary><strong>Expand to see all 60+ commands</strong></summary>

### Scanning

| Command | Name | What It Does |
|---------|------|-------------|
| `1` | Full Scan | Runs all 7 scanners on a directory to detect 32 CVEs across React, Next.js, Node.js, npm, n8n, supply chain, and Clawdbot/Moltbot. |
| `1a` | Scan ALL npm | Auto-discovers and scans every npm project on your system by finding all `package.json` files. |
| `1b` | Pre-Download Check | Sandbox-installs an npm package to a temp directory, scans it for malware and vulns, then destroys the sandbox. |
| `1c` | Deep Scan | Version checks + code pattern analysis + config inspection — shows step-by-step HOW each vulnerability is detected. |
| `1d` | CVE Hunter | Target a single CVE by ID and see real-time detection output against your project. |
| `1e` | Custom Scan | Pick exactly which scanners to run (toggle React, Next.js, npm, Node.js, n8n, Supply Chain, Clawdbot on/off). |
| `2` | React Scanner | Scan for React Server Components RCE (CVE-2025-55182, CVE-2025-66478). |
| `3` | Next.js Scanner | Scan for Next.js middleware bypass (CVE-2025-29927) and RSC vulnerabilities. |
| `4` | npm Packages | Scan for vulns in mysql2, jsonpath-plus, body-parser, multer, nuxt, AdonisJS. |
| `5` | Node.js Runtime | Scan for Node.js runtime vulnerabilities from the January 2026 security release. |
| `6` | n8n Scanner | Scan for n8n workflow automation vulns including Ni8mare unauthenticated RCE. |
| `7` | Supply Chain | Detect Shai-Hulud worm campaign, eslint-config-prettier compromise, malicious install scripts. |

### Live Probing

| Command | Name | What It Does |
|---------|------|-------------|
| `8` | Probe All | Actively probe a live URL for exploitable vulnerabilities (Next.js + n8n). |
| `9` | Next.js Probe | Test a URL for CVE-2025-29927 middleware bypass via `x-middleware-subrequest` header injection. |
| `10` | n8n Probe | Test a URL for CVE-2026-21858 Ni8mare unauthenticated RCE via Content-Type confusion. |

### CVE Intelligence

| Command | Name | What It Does |
|---------|------|-------------|
| `11` | List All CVEs | Display all 32 tracked CVEs with severity, CVSS scores, and affected packages. |
| `12` | Critical Only | Filter to show only CRITICAL severity CVEs (CVSS 9.0+). |
| `13` | Bug Bounty | List CVEs that are high-value bug bounty targets — critical severity or with public PoCs. |
| `14` | CVE Details | Get full details on a specific CVE: description, affected versions, patches, references. |
| `15` | List Scanners | Show all 7 scanners with their descriptions, CVE coverage, and capabilities. |

### Malware Analysis

| Command | Name | What It Does |
|---------|------|-------------|
| `17` | Deep Malware Scan | Scan `node_modules` and project files for RCE payloads, backdoors, cryptominers, data exfiltration, and typosquatting. |
| `18` | Quick Malware Scan | Fast scan of project files only (skips `node_modules`) — good for checking your own code for injected malware. |
| `19` | Quarantine File | Move a malicious file to quarantine with original path preserved for potential restoration. |
| `20` | Remove Package | Completely remove a malicious npm package from `node_modules`, backing up to quarantine first. |
| `21` | Clean Malicious Code | Surgically remove only malicious code from a file while preserving legitimate code (creates backup). |
| `22` | View Report | Display the latest malware analysis report with findings, threat levels, and remediation steps. |

### Secrets Scanner

| Command | Name | What It Does |
|---------|------|-------------|
| `23` | Scan for Secrets | Deep scan for API keys, tokens, passwords, AWS credentials, GitHub tokens, Stripe keys, and 50+ patterns. |
| `24` | Scan .env Files | Target `.env` files specifically for hardcoded secrets and credentials. |
| `25` | High Entropy | Use entropy-based detection to find random strings that may be unknown API key formats. |
| `26` | View Report | Display the latest secrets scan report with risk levels and recommendations. |

### Security Score

| Command | Name | What It Does |
|---------|------|-------------|
| `27` | Security Score | Generate a comprehensive A-F security grade analyzing vulns, malware, secrets, deps, and config. |
| `28` | Quick Check | Fast security assessment without deep scanning — good for CI/CD pipelines. |
| `29` | View Report | Display detailed security report with category breakdown and improvement tips. |

### Auto-Fix

| Command | Name | What It Does |
|---------|------|-------------|
| `30` | Auto-Fix | Automatically upgrade vulnerable packages to patched versions (creates backup first). |
| `31` | Preview Fixes | Dry-run showing what packages would be upgraded without making any changes. |
| `32` | Rollback | Restore `package.json` from backup if auto-fix caused issues. |

[See remaining 30+ commands in original README]

</details>

---

## 📊 Tracked CVEs

<details>
<summary><strong>All 32 CVEs (click to expand)</strong></summary>

| CVE | Severity | CVSS | Package | Description |
|-----|----------|------|---------|-------------|
| CVE-2025-55182 | Critical | 10.0 | React | Server Components RCE via unsafe deserialization (React2Shell) |
| CVE-2025-66478 | Critical | 10.0 | Next.js | Server Components RCE — duplicate of CVE-2025-55182 for Next.js |
| CVE-2025-29927 | Critical | 9.1 | Next.js | Middleware authorization bypass via `x-middleware-subrequest` header |
| CVE-2026-21858 | Critical | 10.0 | n8n | Ni8mare — unauthenticated RCE via Content-Type confusion |
| CVE-2025-68613 | High | — | n8n | Expression injection RCE (authenticated) |
| CVE-2025-68668 | High | — | n8n | Python Code Node RCE |
| CVE-2025-55184 | High | 7.5 | React | Server Components DoS via infinite loop |
| CVE-2025-67779 | High | 7.5 | React | DoS incomplete fix for CVE-2025-55184 |
| CVE-2025-55183 | Medium | 5.3 | React | Server Components source code exposure |
| CVE-2024-21508 | High | — | mysql2 | Remote Code Execution |
| CVE-2024-21534 | High | — | jsonpath-plus | Remote Code Execution |
| CVE-2025-1302 | High | — | jsonpath-plus | RCE (incomplete fix for CVE-2024-21534) |

[... remaining CVEs in original README]

</details>

---

## 🤝 Contributing

Found a bug? Have a feature request? Want to add CVE coverage?

- [Issues](https://github.com/hlsitechio/shellockolm/issues)
- [Discussions](https://github.com/hlsitechio/shellockolm/discussions)
- [Contributing Guide](CONTRIBUTING.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)

---

## 📝 License

MIT License — See [LICENSE](LICENSE)

**📚 More Documentation:**
- [Installation Guide](docs/INSTALL.md)
- [Quick Start](docs/QUICKSTART.md)
- [Fast Install Reference](docs/FAST_INSTALL.md)
- [MCP Server Setup](docs/MCP_SETUP.md)
- [MCP Quick Start](docs/MCP_QUICK_START.md)
- [MCP Usage Examples](docs/MCP_EXAMPLES.md)
- [Claude Code CLI Setup](docs/CLAUDE_CODE_CLI.md)
- [Contributing Guidelines](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Changelog](docs/CHANGELOG.md)
- [Privacy & Security](docs/PRIVACY_AND_SECURITY.md)

---

<div align="center">

**⭐ Star this repo if it helped secure your applications**

[Get Started](#-install--run-in-60-seconds) | [Features](#-complete-features) | [Contributors](docs/CONTRIBUTORS.md) | [Report Issue](https://github.com/hlsitechio/shellockolm/issues)

Built with 🔍 by [@hlsitechio](https://github.com/hlsitechio) & AI ([Claude](https://claude.ai) + [GitHub Copilot](https://github.com/features/copilot)) | For the security community

</div>
