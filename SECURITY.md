# Security Policy

## Reporting a Vulnerability

We take the security of this project seriously. If you discover a security vulnerability, please follow these guidelines:

### Where to Report

**Please DO NOT report security vulnerabilities through public GitHub issues.**

Instead, please report them via:

1. **Email**: [Your security email] (preferred)
2. **GitHub Security Advisories**: Use the "Security" tab in this repository
3. **Private vulnerability disclosure**: Contact the maintainers directly

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

1. **Always backup** your files before running patchers
2. **Test in development** before deploying to production
3. **Verify patches** after application
4. **Keep dependencies updated** - run `pip install -U -r requirements.txt`
5. **Review code changes** - especially from automated tools
6. **Use virtual environments** - isolate dependencies
7. **Monitor logs** - check for unexpected behavior

## Known Security Considerations

### This Tool

- **File Modification**: This tool modifies `package.json` files. Always use backups.
- **No Authentication**: The MCP server does not require authentication. Use in trusted environments only.
- **Local Operations**: All operations are local; no data is sent to external servers.
- **Backup Files**: Backup files contain the same sensitive data as original files.

### The CVE We're Fixing

**CVE-2025-55182 (React2Shell)**:
- CVSS Score: 10.0 (CRITICAL)
- Remote Code Execution in React Server Components
- Actively exploited in the wild
- **Patch immediately** if you use React 19.x with Server Components

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

---

**Last Updated**: December 6, 2025

Thank you for helping keep our project and users safe! 🛡️
