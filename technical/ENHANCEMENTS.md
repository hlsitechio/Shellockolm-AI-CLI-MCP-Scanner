# Planned Enhancements

This document tracks potential enhancements and features for the CVE-2025-55182 security tools based on community feedback and security research.

## High Priority Enhancements

### 1. Additional Framework Detection

**Status**: Planned for v1.1.0

Based on research, CVE-2025-55182 affects multiple React-based frameworks beyond Next.js:

- **React Router** (with RSC APIs)
- **Waku** (React framework)
- **Expo** (React Native framework with RSC)
- **RedwoodJS** (rwsdk)
- **@parcel/rsc** (Parcel bundler RSC plugin)
- **@vitejs/plugin-rsc** (Vite bundler RSC plugin)

**Implementation Plan**:
```python
AFFECTED_FRAMEWORKS = {
    'react-router': {
        'package_names': ['react-router', '@react-router/serve'],
        'rsc_indicator': 'use server',
        'min_version': '7.0.0'
    },
    'waku': {
        'package_names': ['waku'],
        'all_versions_affected': True
    },
    'expo-router': {
        'package_names': ['expo-router'],
        'rsc_indicator': 'app directory'
    },
    'redwood': {
        'package_names': ['@redwoodjs/vite', '@redwoodjs/web'],
        'rsc_indicator': 'RSCWebpackPlugin'
    }
}
```

### 2. Lock File Support

**Status**: Planned for v1.1.0

Currently only scans `package.json`. Should also check:

- `pnpm-lock.yaml` - pnpm package manager
- `yarn.lock` - Yarn package manager
- `bun.lockb` - Bun package manager
- `package-lock.json` - npm (already partially supported)

**Benefits**:
- Detect indirect/transitive dependencies
- More accurate version resolution
- Find hidden vulnerabilities

**Implementation**:
```python
def scan_lock_files(project_path):
    """Scan lock files for React versions"""
    lock_files = {
        'package-lock.json': parse_npm_lock,
        'yarn.lock': parse_yarn_lock,
        'pnpm-lock.yaml': parse_pnpm_lock,
        'bun.lockb': parse_bun_lock
    }

    for filename, parser in lock_files.items():
        lock_path = project_path / filename
        if lock_path.exists():
            return parser(lock_path)

    return None
```

### 3. Canary Release Detection

**Status**: Planned for v1.1.0

Next.js canary releases 14.3.0-canary.77 and later are vulnerable but not detected by current version matching.

**Implementation**:
```python
def is_canary_vulnerable(version):
    """Check if canary release is vulnerable"""
    if 'canary' in version:
        # Extract canary number: 14.3.0-canary.77
        match = re.match(r'(\d+\.\d+\.\d+)-canary\.(\d+)', version)
        if match:
            base_version, canary_num = match.groups()
            if base_version.startswith('14.3.') and int(canary_num) >= 77:
                return True
    return False
```

### 4. Server Components Usage Detection

**Status**: Planned for v1.2.0

Not all React 19 projects use Server Components. Add detection for actual RSC usage:

**Indicators**:
- `"use server"` directive in files
- `server-only` package dependency
- Next.js App Router (app/ directory)
- React Server DOM packages in dependencies

**Implementation**:
```python
def detect_rsc_usage(project_path):
    """Detect if project actually uses React Server Components"""
    indicators = []

    # Check for "use server" in files
    if find_in_files(project_path, '"use server"'):
        indicators.append('use_server_directive')

    # Check for server-only package
    if has_dependency(project_path, 'server-only'):
        indicators.append('server_only_package')

    # Check for App Router
    if (project_path / 'app').exists():
        indicators.append('nextjs_app_router')

    return indicators
```

## Medium Priority Enhancements

### 5. CI/CD Integration

**Status**: Planned for v1.2.0

**GitHub Actions Integration**:
```yaml
name: CVE-2025-55182 Check
on: [push, pull_request]
jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
      - name: Scan for CVE-2025-55182
        run: |
          pip install -r requirements.txt
          python scan_simple.py . --fail-on-vulnerable
```

**GitLab CI**:
```yaml
cve-scan:
  script:
    - python scan_simple.py . --fail-on-vulnerable
  only:
    - merge_requests
    - main
```

### 6. Enhanced Reporting

**Status**: Planned for v1.2.0

**Output Formats**:
- HTML reports with charts
- PDF executive summaries
- SARIF format for GitHub Code Scanning
- CSV for spreadsheet analysis
- Markdown for documentation

**Implementation**:
```python
def generate_report(scan_results, format='json'):
    """Generate report in multiple formats"""
    generators = {
        'json': generate_json_report,
        'html': generate_html_report,
        'pdf': generate_pdf_report,
        'sarif': generate_sarif_report,
        'csv': generate_csv_report,
        'markdown': generate_markdown_report
    }

    return generators[format](scan_results)
```

### 7. Dependency Tree Analysis

**Status**: Planned for v1.3.0

Show full dependency tree to understand where React comes from:

```
myapp
├── next@15.3.3
│   └── react@19.0.0 (VULNERABLE)
└── react-router@7.1.0
    └── react@19.0.0 (VULNERABLE)
```

### 8. Auto-Update Feature

**Status**: Planned for v1.3.0

Automatically update package.json AND run npm install:

```bash
python auto_fix.py /projects --install --test
```

**Flags**:
- `--install` - Run npm install after patching
- `--test` - Run npm test to verify nothing broke
- `--build` - Run npm build to ensure builds succeed

### 9. IDE Extensions

**Status**: Planned for v2.0.0

- **VS Code Extension** - Real-time vulnerability highlighting
- **JetBrains Plugin** - IntelliJ, WebStorm support
- **Vim Plugin** - CLI integration

### 10. Web Dashboard

**Status**: Planned for v2.0.0

Web-based dashboard for:
- Multiple project monitoring
- Historical tracking
- Team collaboration
- Scheduled scans

## Low Priority / Nice to Have

### 11. Docker Support

**Status**: Planned for v2.0.0

```dockerfile
FROM python:3.11-slim
COPY . /app
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "/app/scan_simple.py"]
```

Usage:
```bash
docker run cve-2025-55182-scanner /projects
```

### 12. Webhook Notifications

**Status**: Planned for v2.0.0

Send notifications when vulnerabilities found:
- Slack
- Discord
- Microsoft Teams
- Email
- PagerDuty

### 13. Database Integration

**Status**: Planned for v2.1.0

Store scan history in database:
- PostgreSQL
- MongoDB
- SQLite

Track trends over time and generate metrics.

### 14. Multi-CVE Support

**Status**: Planned for v2.0.0

Expand to detect multiple CVEs:
- React vulnerabilities (all versions)
- Vue.js vulnerabilities
- Angular vulnerabilities
- General npm vulnerabilities via Snyk/OSSINDEX integration

## Community Requested Features

### 15. Rollback Capability

**Status**: Under consideration

Ability to roll back patches if they break the application:

```bash
python auto_fix.py /project --rollback
```

### 16. Monorepo Support

**Status**: Under consideration

Better handling of monorepos (Nx, Turborepo, Lerna):
- Detect workspace structure
- Patch all packages in workspace
- Handle shared dependencies

### 17. Configuration File

**Status**: Under consideration

`.cve-scanner.yml` configuration file:
```yaml
scan:
  exclude:
    - node_modules
    - dist
    - build
  include:
    - src
    - packages

alerts:
  slack_webhook: https://...
  email: security@company.com

auto_patch:
  enabled: true
  create_pr: true
  run_tests: true
```

## Contributing

Want to implement one of these features? Check out [CONTRIBUTING.md](CONTRIBUTING.md)!

Priority features marked for v1.1.0 are accepting pull requests now.

---

**Last Updated**: December 6, 2025
**Next Review**: January 2026
