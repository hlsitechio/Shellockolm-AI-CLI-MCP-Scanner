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

```
╭─────────────────────────────────────────────────────────────────╮
│ SCAN           │ LIVE          │ CVE           │ MALWARE       │
├─────────────────────────────────────────────────────────────────┤
│ [ 1] Full Scan │ [ 8] Probe    │ [11] List All │ [17] Deep     │
│ [1a] ALL npm   │ [ 9] Next.js  │ [12] Critical │ [18] Quick    │
│ [1b] Pre-Check │ [10] n8n      │ [13] Bounty   │ [19] Quarantine│
│ [1c] Deep Scan │               │ [14] Details  │ [20] Remove   │
│ [1d] CVE Hunter│               │ [15] By Pkg   │ [21] Cleanup  │
│ [1e] Custom    │               │ [16] Export   │ [22] Report   │
│ [ 2] React     │               │               │               │
│ [ 3] Next.js   │               │               │               │
│ [ 4] npm Pkgs  │               │               │               │
╰─────────────────────────────────────────────────────────────────╯
```

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

## Menu Reference

### Scanning
| Command | Description |
|---------|-------------|
| `1` | Full scan (all scanners) |
| `1a` | Scan ALL npm packages system-wide |
| `1b` | Pre-install check (sandbox test) |
| `1c` | Deep scan with verbose detection |
| `1d` | Hunt for specific CVE |
| `1e` | Custom scanner selection |
| `2` | React scanner only |
| `3` | Next.js scanner only |
| `4` | npm packages only |
| `5` | Node.js scanner only |
| `6` | n8n scanner only |
| `7` | Supply chain scanner |

### Live Probing
| Command | Description |
|---------|-------------|
| `8` | Probe all endpoints |
| `9` | Next.js live probe |
| `10` | n8n live probe |

### CVE Database
| Command | Description |
|---------|-------------|
| `11` | List all CVEs |
| `12` | Show critical only |
| `13` | Bug bounty relevant |
| `14` | CVE details |
| `15` | CVEs by package |
| `16` | Export database |

### Malware
| Command | Description |
|---------|-------------|
| `17` | Deep malware scan |
| `18` | Quick malware scan |
| `19` | Quarantine threats |
| `20` | Remove malware |
| `21` | Cleanup quarantine |
| `22` | Malware report |

### Secrets
| Command | Description |
|---------|-------------|
| `23` | Full secrets scan |
| `24` | Scan .env files |
| `25` | Entropy analysis |
| `26` | Secrets report |

### Remediation
| Command | Description |
|---------|-------------|
| `27` | Risk score analysis |
| `28` | Quick score |
| `29` | Fix report |
| `30` | Auto-fix all |
| `31` | Preview fixes |
| `32` | Rollback changes |

### Dependencies
| Command | Description |
|---------|-------------|
| `33` | Lockfile analysis |
| `34` | Find duplicates |
| `35` | Typosquat check |
| `36` | Dependency report |

### SARIF
| Command | Description |
|---------|-------------|
| `37` | Export SARIF |
| `38` | View SARIF |
| `39` | Convert to SARIF |

### GitHub Advisory
| Command | Description |
|---------|-------------|
| `40` | Query GHSA |
| `41` | Check package |
| `42` | Scan project |
| `43` | Advisory report |

### npm Audit
| Command | Description |
|---------|-------------|
| `44` | Run audit |
| `45` | Auto-fix audit |
| `46` | Recommendations |
| `47` | Audit history |

### SBOM
| Command | Description |
|---------|-------------|
| `48` | Generate SBOM |
| `49` | CycloneDX format |
| `50` | SPDX format |

### Dependency Tree
| Command | Description |
|---------|-------------|
| `51` | View tree |
| `52` | Find package |
| `53` | Tree stats |
| `54` | Export tree |

### Ignore Rules
| Command | Description |
|---------|-------------|
| `55` | Create rules |
| `56` | View rules |
| `57` | Test path |

### CI/CD
| Command | Description |
|---------|-------------|
| `58` | Generate workflow |
| `59` | Basic config |
| `60` | Full CI/CD |
| `61` | Watch mode |

### Quick Actions
| Key | Action |
|-----|--------|
| `X` | QuickFix all vulnerabilities |
| `F` | FixWizard (interactive) |
| `R` | Generate report |
| `P` | Fetch PoC |
| `U` | Update CVE database |
| `M` | Back to menu |
| `Q` | Quit |

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
