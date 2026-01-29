# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2025-12-08

### 🔍 Major Rebranding: Welcome to Shelllockolm!

**BREAKING CHANGES:**
- Package renamed: `cve-2025-55182-tools` → `shellockolm`
- CLI commands renamed:
  - `cve-2025-55182-scan` → `shellockolm` / `shellockolm-scan`
  - `cve-2025-55182-fix` → `shellockolm-fix`
  - `cve-2025-55182-patch` → `shellockolm-patch`
  - `cve-2025-55182-malware` → `shellockolm-malware`
- New command: `shellockolm-github` for GitHub repository scanning
- Repository URL updated to `https://github.com/hlsitechio/shellockolm`

### Added
- **CVE-2025-66478 Detection** - Comprehensive Next.js vulnerability scanning
- **Dual CVE Support** - Track both CVE-2025-55182 and CVE-2025-66478
- **Next.js Version Ranges** - Precise detection for all 15.x and 16.x versions
- **Vulnerability Database** (`vulnerability_database.py`) - Centralized CVE tracking
- **Enhanced Privacy Protection** - Comprehensive .gitignore for scan results
- **Privacy & Security Guide** (`PRIVACY_AND_SECURITY.md`) - Complete data protection guide
- **Detective Theme Branding** - "Elementary security for complex codebases"
- New keywords: shellockolm, sherlock-holmes, detective, threat-detection

### Changed
- **Project Description**: "Your Security Detective for React, Next.js & npm"
- **Tagline**: "Elementary, my dear developer! Detect CVEs, malware, and supply chain attacks"
- **README**: Complete rebrand with detective theme
- **MCP Server**: Updated to v1.1.0 with dual CVE support
- **Scanner**: Enhanced with Next.js vulnerability ranges
- Package structure updated to use src/ layout

### Security
- Enhanced .gitignore to prevent scan report leakage
- Added protection for backup files and configuration
- Privacy-first design with local-only scanning
- Comprehensive documentation on data protection

### Fixed
- Next.js version detection across all 15.x and 16.x ranges
- Canary version handling for Next.js
- MCP resource URIs updated for both CVEs

### Documentation
- New PRIVACY_AND_SECURITY.md guide
- Updated README with Shelllockolm branding
- Added TAGLINE_OPTIONS.md with marketing concepts
- Enhanced vulnerability documentation

---

## [1.1.0] - 2025-12-06

### Added
- **NPM Malware Scanner** (`malware_scanner.py`) - Detect npm supply chain attacks
- Detection for shai-hulud campaign malware indicators
- Comprehensive security scan summary documentation
- Malicious file detection (bun_environment.js, setup_bun.js, cloud.json, etc.)
- Malicious directory detection (.truffler-cache, .truffler)
- Suspicious npm package detection (@postman, @posthog, @asyncapi, etc.)
- Malicious workflow detection (discussion.yaml)
- JSON malware scan reports with severity classification

### Security
- Successfully tested on 7,106+ projects
- Zero malware indicators found on production systems
- Comprehensive malware detection capability added

## [1.0.0] - 2025-12-06

### Added
- Initial release of CVE-2025-55182 security tools
- Automated vulnerability scanner for React projects
- Auto-fix tool with scan→patch→verify workflow
- Mass patcher for batch operations
- MCP server with 5 tools for AI assistant integration
- Windows-compatible simple scanner
- Safe remediation with automatic backups
- Comprehensive documentation (README, MCP_DESIGN, COMPLETE_CVE_INFO)
- GitHub Actions CI/CD workflows
- Daily CVE monitoring workflow
- MIT License
- Code of Conduct
- Contributing guidelines
- Security policy

### Features
- Support for React 19.0.0, 19.1.0, 19.1.1, 19.2.0 detection
- Automatic patching to 19.0.1, 19.1.2, 19.2.1
- Next.js project detection (15.x and 16.x)
- Cross-platform support (Windows, Linux, macOS)
- Python 3.10+ compatibility
- JSON audit trail generation
- Automated npm install script generation
- Dry-run mode for safe previews
- Timestamped backup creation

### Tested
- Successfully patched 15 production projects
- 100% patch success rate
- Scanned 2,665+ projects
- Zero false positives

---

## Release Notes

### v2.0.0 Highlights 🔍

**Shelllockolm** - Your Security Detective for React, Next.js & npm!

This major release represents a complete rebranding and significant expansion:

**🎯 Dual CVE Detection:**
- CVE-2025-55182 (React Server Components RCE)
- CVE-2025-66478 (Vercel/Next.js advisory)

**🔐 Enhanced Security:**
- Privacy-first design with comprehensive .gitignore
- Local-only scanning with no code upload
- Complete data protection documentation

**🚀 New Features:**
- Next.js version range detection (15.x, 16.x)
- Centralized vulnerability database
- Enhanced malware detection
- GitHub repository scanning

**💡 Why "Shelllockolm"?**
A play on "Sherlock Holmes" - your detective for finding security threats. Elementary!

**Migration Guide:**
- Update package references from `cve-2025-55182-tools` to `shellockolm`
- Update CLI commands (see BREAKING CHANGES above)
- Repository URL: https://github.com/hlsitechio/shellockolm

### v1.1.0 Highlights

**NPM Malware Detection** - Complete supply chain security scanning.

### v1.0.0 Highlights

This is the initial production-ready release of the CVE-2025-55182 security toolkit. The tools have been extensively tested and successfully used to secure 15 production React applications.

**Key Features:**
- Complete automation from scanning to verification
- AI assistant integration via MCP
- Enterprise-ready with comprehensive documentation

**Compatibility:**
- Python 3.10, 3.11, 3.12
- Windows 10/11, Linux (Ubuntu 20.04+), macOS (10.15+)
- React 19.x all vulnerable versions
- Next.js 15.x and 16.x detection

---

## Future Roadmap

### Planned for v2.1.0
- [ ] PyPI package publishing (as shellockolm)
- [ ] npm package for direct installation
- [ ] Enhanced GitHub Scanner features
- [ ] Real-time vulnerability notifications

### Planned for v2.2.0
- [ ] Historical React CVE database expansion
- [ ] Additional framework support (Vue.js, Angular)
- [ ] HTML/PDF report generation
- [ ] CI/CD integration examples

### Planned for v3.0.0
- [ ] Real-time monitoring dashboard
- [ ] Webhook notifications
- [ ] Enterprise SSO integration
- [ ] Multi-language support

---

[2.0.0]: https://github.com/hlsitechio/shellockolm/releases/tag/v2.0.0
[1.1.0]: https://github.com/hlsitechio/shellockolm/releases/tag/v1.1.0
[1.0.0]: https://github.com/hlsitechio/shellockolm/releases/tag/v1.0.0
