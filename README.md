<div align="center">

![Shellockolm - Your Security Detective](docs/images/banner.png)

# Shellockolm

**Security Detective for React, Next.js, Node.js & npm**

*Elementary, my dear developer!* Detect CVEs, malware, secrets, and supply chain attacks in seconds.

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/downloads/)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![GitHub Release](https://img.shields.io/github/v/release/hlsitechio/shellockolm?color=success)](https://github.com/hlsitechio/shellockolm/releases/latest)

</div>

---

## Quick Install

```bash
# Clone and run (recommended)
git clone https://github.com/hlsitechio/shellockolm.git
cd shellockolm
pip install -r requirements.txt
python src/cli.py shell
```

**One-liner:**
```bash
git clone https://github.com/hlsitechio/shellockolm.git && cd shellockolm && pip install -r requirements.txt && python src/cli.py shell
```

---

## What It Does

| Scanner | Detects | Coverage |
|---------|---------|----------|
| **CVE Scanner** | Known vulnerabilities | 28+ CVEs (React, Next.js, Node.js, n8n) |
| **Malware Scanner** | npm malware, backdoors, cryptominers | 100+ patterns |
| **Secrets Scanner** | API keys, tokens, credentials | AWS, GitHub, Slack, etc. |
| **Supply Chain** | Typosquatting, dependency confusion | npm ecosystem |
| **SBOM Generator** | Software bill of materials | CycloneDX, SPDX |

---

## Usage

### Interactive Shell (Recommended)

```bash
python src/cli.py shell
```

Opens a full-featured menu with 60+ commands:

| SCAN | CVE | MALWARE | SECRETS | REMEDIATION |
|------|-----|---------|---------|-------------|
| `1` Full | `11` List | `17` Deep | `23` Scan | `27` Risk Score |
| `1a` ALL npm | `12` Critical | `18` Quick | `24` .env | `30` Auto-fix |
| `1b` Pre-Check | `13` Bounty | `19` Quarantine | `25` Entropy | `31` Preview |
| `1c` Deep | `14` Details | `20` Remove | `26` Report | `32` Rollback |
| `1d` CVE Hunter | `15` By Pkg | `22` Report | | `X` QuickFix |
| `1e` Custom | `16` Export | | | `F` FixWizard |

| LIVE | DEPS | GITHUB | SBOM | CI/CD |
|------|------|--------|------|-------|
| `8` Probe All | `33` Lockfile | `40` Query GHSA | `48` Generate | `58` Workflow |
| `9` Next.js | `34` Duplicates | `41` Check Pkg | `49` CycloneDX | `59` Basic |
| `10` n8n | `35` Typosquat | `44` npm Audit | `50` SPDX | `60` Full |
| | `36` Report | `45` Auto-fix | `37` SARIF | `61` Watch |

### CLI Commands

```bash
# Scan a directory
python src/cli.py scan /path/to/project

# Scan with specific scanner
python src/cli.py scan /path --scanner nextjs

# Live probe a URL
python src/cli.py live https://example.com

# List all tracked CVEs
python src/cli.py cves

# Get CVE details
python src/cli.py info CVE-2025-29927

# List scanners
python src/cli.py scanners
```

---

## Key Features

### [1] Full Scan
Runs all scanners (Next.js, React, npm, Node.js, n8n, Supply Chain) on your project.

### [1c] Deep Scan
Version checks + Code pattern analysis + Config inspection. Shows exactly HOW each vulnerability is detected.

### [1d] CVE Hunter
Target a specific CVE (e.g., `CVE-2025-29927`). Shows step-by-step detection with verbose output.

### [X] QuickFix
One-click fix for all detected vulnerabilities. Updates package.json with safe versions.

### [F] FixWizard
Interactive wizard that walks you through each fix with explanations.

### [17] Malware Deep Scan
Comprehensive malware detection:
- Obfuscated code patterns
- Suspicious network calls
- Cryptominer signatures
- Data exfiltration attempts
- Reverse shells

### [23-26] Secrets Scanner
Detect exposed secrets:
- AWS keys
- GitHub/GitLab tokens
- Slack webhooks
- Database credentials
- Private keys
- High-entropy strings

### [48-50] SBOM Generator
Generate Software Bill of Materials:
- CycloneDX format
- SPDX format
- JSON export

### [37-39] SARIF Export
Export results for:
- GitHub Code Scanning
- VS Code SARIF Viewer
- CI/CD pipelines

---

## Tracked CVEs

| CVE | Severity | Package | Description |
|-----|----------|---------|-------------|
| CVE-2025-29927 | Critical | Next.js | Middleware bypass via x-middleware-subrequest |
| CVE-2025-55182 | High | Next.js | Image cache poisoning |
| CVE-2024-34351 | High | Next.js | Server Actions SSRF |
| CVE-2024-47831 | High | Next.js | Image optimization DoS |
| CVE-2024-46982 | Medium | Next.js | Cache poisoning |
| CVE-2024-56332 | Medium | Next.js | Denial of Service |
| + 22 more | Various | React, Node.js, n8n | [Full list](docs/CVE_DATABASE.md) |

---

## Full Command Reference

<details>
<summary><b>Click to expand all 60+ commands</b></summary>

### Scanning (`1-7`)
`1` Full scan | `1a` ALL npm | `1b` Pre-check | `1c` Deep | `1d` CVE Hunter | `1e` Custom | `2` React | `3` Next.js | `4` npm | `5` Node.js | `6` n8n | `7` Supply chain

### Live Probing (`8-10`)
`8` Probe all | `9` Next.js | `10` n8n

### CVE Database (`11-16`)
`11` List all | `12` Critical only | `13` Bounty | `14` Details | `15` By package | `16` Export

### Malware (`17-22`)
`17` Deep scan | `18` Quick scan | `19` Quarantine | `20` Remove | `21` Cleanup | `22` Report

### Secrets (`23-26`)
`23` Full scan | `24` .env files | `25` Entropy | `26` Report

### Remediation (`27-32`)
`27` Risk score | `28` Quick score | `29` Fix report | `30` Auto-fix | `31` Preview | `32` Rollback

### Dependencies (`33-36`)
`33` Lockfile | `34` Duplicates | `35` Typosquat | `36` Report

### SARIF (`37-39`)
`37` Export | `38` View | `39` Convert

### GitHub Advisory (`40-43`)
`40` Query GHSA | `41` Check pkg | `42` Scan | `43` Report

### npm Audit (`44-47`)
`44` Audit | `45` Auto-fix | `46` Recommendations | `47` History

### SBOM (`48-50`)
`48` Generate | `49` CycloneDX | `50` SPDX

### Dependency Tree (`51-54`)
`51` View | `52` Find pkg | `53` Stats | `54` Export

### Ignore & CI/CD (`55-61`)
`55` Create rules | `56` View rules | `57` Test | `58` Workflow | `59` Basic | `60` Full CI/CD | `61` Watch

### Quick Actions
`X` QuickFix | `F` FixWizard | `R` Report | `P` PoC | `U` Update | `M` Menu | `Q` Quit

</details>

---

## Requirements

- Python 3.10+
- pip

**Dependencies (auto-installed):**
```
rich>=13.0.0
typer>=0.9.0
packaging>=21.0
requests>=2.28.0
```

---

## Privacy

- **100% Local**: All scans run on your machine
- **No Upload**: Code never leaves your system
- **No Telemetry**: Zero data collection
- **Open Source**: Full transparency

---

## Examples

### Scan a Next.js project
```bash
python src/cli.py scan ~/myapp --scanner nextjs
```

### Hunt for CVE-2025-29927
```bash
python src/cli.py shell
> 1d
> CVE-2025-29927
> /path/to/project
```

### Generate SBOM
```bash
python src/cli.py shell
> 48
> /path/to/project
```

### Quick security check
```bash
python src/cli.py shell
> 1
> /path/to/project
> X  # QuickFix if vulnerabilities found
```

---

## CI/CD Integration

### GitHub Actions
```yaml
- name: Security Scan
  run: |
    pip install -r requirements.txt
    python src/cli.py scan . --json > results.json
```

### Pre-commit Hook
```bash
#!/bin/bash
python src/cli.py scan . --scanner npm
```

---

## Documentation

- [Quick Start](docs/QUICK_START.md)
- [CVE Database](docs/CVE_DATABASE.md)
- [GitHub Scanner](docs/GITHUB_SCANNER.md)
- [Privacy & Security](PRIVACY_AND_SECURITY.md)
- [Contributing](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)

---

## Support

- [Issues](https://github.com/hlsitechio/shellockolm/issues)
- [Discussions](https://github.com/hlsitechio/shellockolm/discussions)

---

## License

MIT License - See [LICENSE](LICENSE)

---

<div align="center">

**Security scanning made simple.**

[Get Started](#quick-install) | [Documentation](#documentation) | [Report Issue](https://github.com/hlsitechio/shellockolm/issues)

</div>
