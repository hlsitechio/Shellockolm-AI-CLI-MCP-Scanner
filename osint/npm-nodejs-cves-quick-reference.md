# NPM/NODE.JS CVE QUICK REFERENCE GUIDE

**Last Updated:** 2026-01-23  
**Total CVEs:** 30+  
**Severity:** CRITICAL and HIGH only (CVSS 7.0+)

---

## CRITICAL SEVERITY (CVSS 9.0-10.0)

| CVE ID | Package/System | CVSS | Type | Status |
|--------|---------------|------|------|--------|
| CVE-2025-55182 | React Server Components | 10.0 | RCE | Active Exploitation |
| CVE-2026-21858 | n8n workflow | 10.0 | Unauth RCE | Public PoC |
| CVE-2025-68613 | n8n workflow | 9.9 | Auth RCE | Public PoC |
| CVE-2024-21534 | jsonpath-plus | 9.8 | RCE | Public PoC |
| CVE-2024-21508 | mysql2 | 9.8 | RCE | Patched |
| CVE-2025-29927 | Next.js | 9.1 | Auth Bypass | Patched |
| CVE-2026-21440 | AdonisJS bodyparser | 9.2 | Path Traversal | Patched |

---

## HIGH SEVERITY (CVSS 7.0-8.9)

| CVE ID | Package/System | CVSS | Type | Status |
|--------|---------------|------|------|--------|
| CVE-2024-21891 | Node.js | 8.8 | Permission Bypass | Patched |
| CVE-2025-55184 | React Server Components | 7.5 | DoS | Patched |
| CVE-2025-67779 | React Server Components | 7.5 | DoS (incomplete fix) | Patched |
| CVE-2024-45590 | body-parser | 7.5 | DoS | Patched |
| CVE-2025-54313 | eslint-config-prettier | 7.5 | Supply Chain | Deprecated |
| CVE-2025-27210 | Node.js (Windows) | ~7.0+ | Path Traversal | Patched |
| CVE-2025-55130 | Node.js | High | Permission Bypass | Patched |
| CVE-2025-68668 | @n8n/config | High | RCE | Patched |
| CVE-2024-34344 | Nuxt.js | High | RCE | Patched |
| CVE-2024-13059 | AnythingLLM | High | Path Traversal → RCE | Patched |
| CVE-2025-59465 | Node.js | High | HTTP/2 DoS | Patched |
| CVE-2025-48997 | multer | Critical | DoS | Patched |
| CVE-2025-47944 | multer | High | Multiple Issues | Patched |

---

## REACT/NEXT.JS ECOSYSTEM

### React Server Components
- **CVE-2025-55182** (10.0) - RCE via unsafe deserialization - **ACTIVE EXPLOITATION**
- **CVE-2025-55183** (5.3) - Source code exposure
- **CVE-2025-55184** (7.5) - DoS via infinite loop
- **CVE-2025-67779** (7.5) - DoS (incomplete fix for 55184)

**Affected Versions:** React 19.0.0-19.2.2  
**Patched Versions:** 19.0.3+, 19.1.4+, 19.2.3+

### Next.js
- **CVE-2025-29927** (9.1) - Middleware authorization bypass
- **CVE-2025-66478** (10.0) - REJECTED (duplicate of CVE-2025-55182)

**Affected Versions:** 11.1.4-15.2.2  
**Patched Versions:** 13.5.7+, 14.2.25+, 15.2.3+

---

## NODE.JS RUNTIME

### December 2025 / January 2026 Security Release
- **CVE-2025-59465** (High) - HTTP/2 server crash with malformed HEADERS
- **CVE-2025-59464** (Medium) - TLS client cert memory leak
- **CVE-2025-59466** (Medium) - async_hooks uncatchable error

### Permission Model Bypasses
- **CVE-2025-55130** (High) - Symlink bypass for --allow-fs-read/write
- **CVE-2026-21636** (Medium) - Unix Domain Socket bypass for --allow-net
- **CVE-2025-55132** (Low) - fs.futimes() bypass
- **CVE-2024-21891** (8.8) - Path normalization bypass

### Path Traversal (Windows)
- **CVE-2025-27210** (High) - Device names (CON, PRN, AUX) bypass
- **CVE-2025-23084** (5.6) - Drive name handling flaw

**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

---

## N8N WORKFLOW AUTOMATION

- **CVE-2026-21858** (10.0) - Unauthenticated RCE via webhook ("Ni8mare")
- **CVE-2025-68613** (9.9) - Authenticated expression injection RCE
- **CVE-2025-68668** (High) - Python Code Node RCE

**Affected Versions:** Various versions < 1.121.0  
**Patched Versions:** 1.120.4+, 1.121.1+, 1.122.0+

---

## NPM PACKAGES

### Code Execution
- **CVE-2024-21534** (9.8) - jsonpath-plus RCE
- **CVE-2025-1302** - jsonpath-plus RCE (incomplete fix)
- **CVE-2024-21508** (9.8) - mysql2 RCE
- **CVE-2024-34344** (High) - Nuxt.js test mode RCE

### Denial of Service
- **CVE-2024-45590** (7.5) - body-parser DoS
- **CVE-2025-48997** (Critical) - multer DoS
- **CVE-2025-47944** (High) - multer vulnerabilities

### Path Traversal
- **CVE-2024-13059** (High) - AnythingLLM path traversal → RCE
- **CVE-2026-21440** (9.2) - AdonisJS bodyparser path traversal

---

## SUPPLY CHAIN ATTACKS

### eslint-config-prettier Compromise (July 2025)
- **CVE-2025-54313** (7.5)
- **Malicious Versions:** 8.10.1, 9.1.1, 10.1.6, 10.1.7
- **Safe Versions:** 8.10.2+, 9.1.2+, 10.1.8+
- **Impact:** 30M+ weekly downloads, Windows malware ("Scavenger")

### Shai-Hulud Worm Campaign (November 2025)
- **No CVE assigned**
- **Scope:** 25,000+ repos, 350+ users compromised
- **Impact:** Self-replicating npm malware, credential theft

---

## AFFECTED BUNDLERS (via CVE-2025-55182)

All bundlers implementing React Server Components:
- **webpack** (react-server-dom-webpack)
- **Turbopack** (react-server-dom-turbopack)
- **Parcel** (react-server-dom-parcel, @parcel/rsc)
- **Vite** (@vitejs/plugin-rsc)

---

## ACTIVE EXPLOITATION CONFIRMED

- **CVE-2025-55182** - Nation-state actors (PRC-linked), coin miners, backdoors
  - Added to CISA KEV: December 5, 2025
  - First exploitation: December 5, 2025 (2 days after disclosure)
  - Attack tools: SNOWLIGHT, VShell trojans

---

## PATCH PRIORITY MATRIX

### EMERGENCY (Patch Immediately)
1. CVE-2025-55182 - React/Next.js RCE
2. CVE-2026-21858 - n8n unauth RCE
3. CVE-2025-68613 - n8n auth RCE
4. CVE-2024-21534 - jsonpath-plus RCE
5. CVE-2025-29927 - Next.js auth bypass

### HIGH PRIORITY (Patch This Week)
1. All Node.js runtime CVEs (2025-59465, 55130, 27210, etc.)
2. CVE-2024-21508 - mysql2 RCE
3. CVE-2025-54313 - eslint-config-prettier supply chain
4. CVE-2024-45590 - body-parser DoS
5. CVE-2025-48997 - multer DoS

### MEDIUM PRIORITY (Patch This Month)
1. CVE-2024-34344 - Nuxt.js test RCE
2. CVE-2024-13059 - AnythingLLM path traversal
3. CVE-2025-55183 - React source code exposure
4. Node.js medium severity issues

---

## VERSION COMPATIBILITY MATRIX

### React Server Components
| Version Range | CVE-2025-55182 | CVE-2025-55184 | CVE-2025-67779 | Safe Version |
|---------------|----------------|----------------|----------------|--------------|
| 19.0.0-19.0.1 | ✓ | ✓ | - | 19.0.3+ |
| 19.0.2 | ✓ | - | ✓ | 19.0.3+ |
| 19.1.0-19.1.1 | ✓ | ✓ | - | 19.1.4+ |
| 19.1.2-19.1.3 | ✓ | - | ✓ | 19.1.4+ |
| 19.2.0-19.2.1 | ✓ | ✓ | - | 19.2.3+ |
| 19.2.2 | ✓ | - | ✓ | 19.2.3+ |

### Next.js
| Version Range | CVE-2025-55182 | CVE-2025-29927 | Safe Version |
|---------------|----------------|----------------|--------------|
| 11.1.4-13.5.6 | - | ✓ | 13.5.7+ |
| 14.0.0-14.2.24 | - | ✓ | 14.2.25+ |
| 15.0.0-15.0.4 | ✓ | ✓ | 15.2.3+ |
| 15.1.0-15.2.2 | ✓ | ✓ | 15.2.3+ |
| 16.0.0-16.0.6 | ✓ | - | Latest |

### Node.js
| Version | Dec 2025/Jan 2026 CVEs | Safe Version |
|---------|------------------------|--------------|
| 18.x | Legacy | EOL |
| 20.x | ✓ | 20.20.0+ |
| 22.x | ✓ | 22.22.0+ |
| 24.x | ✓ | 24.13.0+ |
| 25.x | ✓ | 25.3.0+ |

---

## EXPLOITATION DIFFICULTY

### Trivial (Public PoCs Available)
- CVE-2025-55182 (React2Shell)
- CVE-2026-21858 (n8n Ni8mare)
- CVE-2025-68613 (n8n expression injection)
- CVE-2024-21534 (jsonpath-plus)

### Easy (Well-Documented)
- CVE-2025-29927 (Next.js middleware bypass)
- CVE-2024-45590 (body-parser DoS)
- CVE-2025-27210 (Node.js path traversal)

### Moderate (Requires Specific Conditions)
- CVE-2024-34344 (Nuxt.js test mode)
- CVE-2024-21891 (Node.js permission model)
- CVE-2024-13059 (AnythingLLM)

---

## RECON DETECTION SIGNATURES

### Identifying Vulnerable Applications

**React Server Components:**
```
HTTP Header: "rsc: 1"
HTTP Header: "Next-Router-State-Tree"
Content-Type: text/x-component
```

**Next.js Detection:**
```
/_next/static/
X-Powered-By: Next.js
```

**n8n Detection:**
```
/webhook/
/webhook-test/
/form/
X-n8n-webhook-id
```

**Node.js Version:**
```
HTTP Header: X-Powered-By: Express
Server: Node.js
```

---

## IMPACT SUMMARY BY ATTACK TYPE

### Remote Code Execution (RCE)
- CVE-2025-55182 (React) - Unauthenticated
- CVE-2026-21858 (n8n) - Unauthenticated
- CVE-2025-68613 (n8n) - Authenticated
- CVE-2024-21534 (jsonpath-plus)
- CVE-2024-21508 (mysql2)
- CVE-2024-34344 (Nuxt.js)
- CVE-2024-13059 (AnythingLLM)
- CVE-2025-68668 (n8n Python)

### Authorization/Authentication Bypass
- CVE-2025-29927 (Next.js middleware)
- CVE-2024-21891 (Node.js permissions)
- CVE-2025-55130 (Node.js symlink)
- CVE-2026-21636 (Node.js UDS)

### Path Traversal
- CVE-2025-27210 (Node.js Windows)
- CVE-2025-23084 (Node.js Windows)
- CVE-2026-21440 (AdonisJS)
- CVE-2024-13059 (AnythingLLM)

### Denial of Service
- CVE-2025-55184/67779 (React)
- CVE-2024-45590 (body-parser)
- CVE-2025-48997 (multer)
- CVE-2025-59465 (Node.js HTTP/2)

### Information Disclosure
- CVE-2025-55183 (React source code)

### Supply Chain
- CVE-2025-54313 (eslint-config-prettier)
- Shai-Hulud worm campaign

---

## THREAT ACTOR ACTIVITY

### Nation-State (Confirmed)
- **CVE-2025-55182** - PRC-linked initial access broker (CL-STA-1015)
  - Payloads: SNOWLIGHT, VShell trojans
  - Activity: December 5, 2025 onwards

### Cybercriminal (Confirmed)
- **CVE-2025-55182** - Coin miners, credential harvesters
- **Shai-Hulud** - Automated credential theft worm

### Red Team / Security Research
- Most CVEs have public PoCs from security researchers
- Active scanning detected for CVE-2025-55182 within 12 hours of disclosure

---

## BUG BOUNTY HUNTING TIPS

### High-Value Scenarios
1. **Next.js apps with custom middleware** - Test CVE-2025-29927
2. **React 19 apps with Server Components** - Check for CVE-2025-55182
3. **Self-hosted n8n instances** - CVE-2026-21858 (webhooks)
4. **Windows Node.js deployments** - Path traversal CVEs
5. **Apps using outdated npm packages** - Dependency scanning

### Quick Wins
1. Check package.json for vulnerable versions (if exposed)
2. Test custom headers on Next.js middleware routes
3. Probe n8n form webhooks with malicious Content-Type
4. Windows path manipulation in file upload features
5. Source code exposure via React Server Function .toString()

### Tools & Commands
```bash
# Check React version
curl -I https://target.com | grep -i rsc

# Next.js middleware bypass
curl -H "x-middleware-subrequest: 1" https://target.com/api/admin

# n8n webhook detection
curl https://target.com/webhook/test

# Node.js version detection
curl -I https://target.com | grep -i "x-powered-by"
```

---

## ADDITIONAL RESOURCES

- **NVD Database:** https://nvd.nist.gov/
- **GitHub Security Advisories:** https://github.com/advisories
- **Snyk Vulnerability DB:** https://security.snyk.io/
- **CISA KEV Catalog:** https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **React Security:** https://react.dev/blog
- **Next.js Security:** https://nextjs.org/blog
- **Node.js Security:** https://nodejs.org/en/blog/vulnerability/

---

**Generated by:** Gatherer-OSINT Agent  
**For:** Rainkode Bug Bounty Operations  
**Classification:** OSINT - Public Information  
**Maintain Operational Security:** Do not disclose hunting targets or active research
