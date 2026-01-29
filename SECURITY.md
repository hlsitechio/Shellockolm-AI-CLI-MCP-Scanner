# Security Policy

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please follow these guidelines:

### Where to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **GitHub Security Advisories**: Use the "Security" tab in this repository (preferred)
2. **Email**: Contact via GitHub profile
3. **Private disclosure**: Open a discussion marked as private

### What to Include

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact and severity
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Proof of Concept**: If possible, provide a PoC (without exploiting real systems)
- **Suggested Fix**: If you have ideas for fixing the issue
- **Your Contact Information**: So we can follow up with you

### Response Timeline

We will acknowledge your report within **48 hours** and provide:

- Confirmation that we received your report
- Initial assessment of the vulnerability
- Estimated timeline for a fix

We aim to:

- **Confirm** the issue within 7 days
- **Release a patch** within 30 days (depending on severity)
- **Publicly disclose** after a patch is available (coordinated disclosure)

### Our Commitment

- We will keep you informed about our progress
- We will credit you in the security advisory (unless you prefer to remain anonymous)
- We will not take legal action against security researchers who:
  - Follow responsible disclosure practices
  - Do not exploit vulnerabilities beyond demonstration
  - Do not access, modify, or delete user data
  - Comply with all applicable laws

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

## Security Best Practices

When using this tool:

1. **Use official installers** - Run our verified one-line installers from the official repository
2. **Always backup** your files before running auto-fix or patchers
3. **Test in development** before deploying to production
4. **Verify patches** after application
5. **Keep dependencies updated** - run `pip install -U -r requirements.txt`
6. **Review code changes** - especially from automated tools
7. **Monitor logs** - check for unexpected behavior

### Installation Security

Our installers are designed with security in mind:

- ✅ **Verified downloads** - Installers only download from official GitHub repository
- ✅ **No sudo for dependencies** - Python packages installed to user directory (`--user`)
- ✅ **Transparent operations** - All actions are displayed during installation
- ✅ **Optional components** - PATH integration and shortcuts are opt-in
- ✅ **Verification checks** - Installation is verified before completion

**Windows users:** The PowerShell installer requires execution policy changes. Review `install.ps1` before running if concerned.

## Known Security Considerations

### This Tool

- **File Modification**: This tool modifies `package.json` files. Always use backups.
- **No Authentication**: The MCP server does not require authentication. Use in trusted environments only.
- **Local Operations**: All operations are local; no data is sent to external servers.
- **Backup Files**: Backup files contain the same sensitive data as original files.

### CVEs We Detect

This tool detects **32 critical CVEs** including:

**CVE-2025-55182 (React2Shell)**:
- CVSS Score: 10.0 (CRITICAL)
- Remote Code Execution in React Server Components
- Actively exploited in the wild

**CVE-2025-29927**:
- CVSS Score: 9.1 (CRITICAL)
- Next.js middleware authorization bypass

**CVE-2026-21858 (Ni8mare)**:
- CVSS Score: 10.0 (CRITICAL)
- n8n unauthenticated RCE

See **[full CVE list in README](README.md#-tracked-cves)** for all 32 vulnerabilities tracked.

## Security Updates

We will publish security advisories for:

- Vulnerabilities in this tool
- New React/Next.js CVEs we add support for
- Critical bugs that could affect security

Subscribe to this repository to receive notifications.

## Bug Bounty

We currently do not have a bug bounty program, but we greatly appreciate security research and will acknowledge all valid reports.

## Responsible Disclosure

We support responsible disclosure and will:

1. Work with you to understand and validate the issue
2. Keep you updated on our progress
3. Coordinate the public disclosure timing with you
4. Give you credit for the discovery (if desired)

## Legal

This security policy does not create any legal obligations. We reserve the right to modify this policy at any time.

## Quick Install (Secure & Verified)

Get started securely with our official installers:

**Windows:**
```powershell
iex (irm https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install.ps1)
```

**Linux/macOS:**
```bash
# Ubuntu/Debian
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install-debian.sh | bash

# Arch Linux
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install-arch.sh | bash

# macOS
curl -fsSL https://raw.githubusercontent.com/hlsitechio/shellockolm/main/scripts/install.sh | bash
```

All installers:
- Download only from official GitHub repository
- Display all actions before execution
- Include verification checks
- Support offline operation after install

---

**Last Updated**: January 29, 2026

Thank you for helping keep our project and users safe! 🛡️
