# Shellockolm Enhancement Plan
## User-Controlled, Transparent Security Scanning

### Philosophy
- Every action = User initiated
- Every process = Visible to user
- Every result = Explained clearly
- No background/hidden operations

---

## Phase 1: Enhanced Scan Controls (Menu Options)

### [1c] Deep Scan Mode
- Quick Scan: Version checks only (fast)
- Deep Scan: Version + Code patterns + Config analysis + Behavior
- User chooses depth before scan

### [1d] Single CVE Hunter
- User enters CVE ID (e.g., CVE-2025-29927)
- Scanner shows step-by-step detection process
- Explains exactly what it's checking and why

### [1e] Selective Scanner
- Checkbox-style selection:
  ```
  Select scanners to run:
  [x] Next.js Scanner (5 CVEs)
  [x] npm Package Scanner (12 CVEs)
  [ ] React Scanner (4 CVEs)
  [ ] n8n Scanner (3 CVEs)
  [x] Supply Chain Scanner
  ```

---

## Phase 2: Transparent Detection

### Verbose Detection Log
For each file/package scanned, show:
```
[SCAN] package.json
  ├─ Found: next@14.1.0
  ├─ Checking: CVE-2025-29927 (middleware bypass)
  │   ├─ Version match: 14.1.0 in range [11.1.4-14.2.24] ✓
  │   ├─ Checking middleware config...
  │   └─ VULNERABLE: Pattern matched
  └─ Checking: CVE-2025-55182 (cache poisoning)
      ├─ Version match: 14.1.0 in range ✓
      └─ NOT VULNERABLE: No route handlers found
```

### Scan Progress Dashboard
```
🔍 Scanning: /path/to/project
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Progress: [████████████░░░░░░░░] 62%
Files:    247/398
Packages: 89 checked
Found:    3 vulnerabilities (1 critical)
Time:     12.3s elapsed
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Currently: node_modules/next/package.json
```

### Detection Explainer
For each finding, show three sections:
1. **WHY vulnerable**: Technical explanation
2. **WHAT attacker can do**: Impact/exploit scenario
3. **HOW we detected it**: Our detection method

---

## Phase 3: User-Initiated Updates

### [U] CVE Database Refresh
```
Refreshing CVE Database...

[1/4] Fetching GitHub Advisory Database...
      └─ Found 3 new advisories for npm ecosystem

[2/4] Checking NVD for Node.js CVEs...
      └─ Found 1 new CVE: CVE-2025-XXXXX

[3/4] Updating scanner rules...
      └─ Added detection for CVE-2025-XXXXX

[4/4] Verifying database integrity...
      └─ Total: 32 CVEs tracked

✓ Database updated! Run a scan to check your projects.
```

### [P] PoC Fetcher
User requests PoC for specific CVE:
```
Fetching PoC for CVE-2025-29927...

Sources checked:
  ├─ GitHub: Found 3 repositories
  ├─ ExploitDB: Found 1 entry
  └─ Nuclei Templates: Found 1 template

[1] zhero/CVE-2025-29927-PoC (★ 234)
    "Next.js middleware bypass proof of concept"

[2] projectdiscovery/nuclei-templates
    "next-middleware-bypass.yaml"

Select to view [1-2] or [D]ownload all:
```

---

## Phase 4: Reports & Remediation

### Interactive Report Builder
```
╭─── Report Builder ───╮
│                      │
│ Include findings:    │
│ [x] CVE-2025-29927   │
│ [x] CVE-2025-55182   │
│ [ ] CVE-2024-34351   │
│                      │
│ Format:              │
│ (•) Markdown         │
│ ( ) JSON             │
│ ( ) HackerOne        │
│ ( ) PDF              │
│                      │
│ Include:             │
│ [x] PoC code         │
│ [x] Remediation      │
│ [x] CVSS scores      │
│ [ ] Full scan log    │
│                      │
│ [Generate Report]    │
╰──────────────────────╯
```

### Remediation Wizard
```
╭─── Remediation Wizard ───╮
│                          │
│ Fixing: CVE-2025-29927   │
│ Package: next@14.1.0     │
│                          │
│ Step 1 of 3:             │
│ Update package.json      │
│                          │
│ Current:  "next": "14.1.0"
│ Fixed:    "next": "14.2.25"
│                          │
│ Apply this change? [y/N] │
╰──────────────────────────╯
```

---

## New Menu Structure

```
╭─────────────────────────────────────────╮
│ SCAN                                    │
├─────────────────────────────────────────┤
│ [ 1] Full Scan      (all scanners)      │
│ [1a] ALL npm        (system-wide)       │
│ [1b] Pre-Check      (sandbox install)   │
│ [1c] Deep Scan      (code + config)     │
│ [1d] CVE Hunter     (target one CVE)    │
│ [1e] Custom Scan    (pick scanners)     │
╰─────────────────────────────────────────╯

Quick Actions (below banner):
[Q] Exit  [H] Help  [S] Star  [U] Update CVEs  [P] Get PoC
```

---

## Implementation Order

1. **Phase 1** - New scan modes (1c, 1d, 1e)
2. **Phase 2** - Verbose output & progress
3. **Phase 3** - Update & PoC fetcher
4. **Phase 4** - Report builder & wizard

Each phase builds on the previous, maintaining stability.
