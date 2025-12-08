# Complete CVE Information - React2Shell

## Primary Vulnerabilities

### CVE-2025-55182 (React Server Components)
- **CVSS Score**: 10.0 (CRITICAL - Maximum Severity)
- **Type**: Unauthenticated Remote Code Execution (RCE)
- **CWE**: CWE-502 (Deserialization of Untrusted Data)
- **Nickname**: "React2Shell"
- **Disclosure Date**: December 3, 2025
- **Discovered By**: Lachlan Davidson (November 29, 2025)

#### Affected Packages
| Package | Vulnerable Versions | Patched Versions |
|---------|---------------------|------------------|
| react-server-dom-webpack | 19.0.0, 19.1.0-19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 |
| react-server-dom-parcel | 19.0.0, 19.1.0-19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 |
| react-server-dom-turbopack | 19.0.0, 19.1.0-19.1.1, 19.2.0 | 19.0.1, 19.1.2, 19.2.1 |

### CVE-2025-66478 (Next.js - REJECTED AS DUPLICATE)
- **Status**: REJECTED - This CVE was rejected as a duplicate of CVE-2025-55182
- **CVSS Score**: 10.0 (initially rated, now merged with CVE-2025-55182)
- **Type**: Downstream impact of CVE-2025-55182 on Next.js
- **Note**: All Next.js vulnerabilities are now tracked under CVE-2025-55182

#### Affected Next.js Versions
| Version Range | Status | Patched Versions |
|---------------|--------|------------------|
| Next.js 16.x (all minor versions) | VULNERABLE | 16.0.7 |
| Next.js 15.5.x | VULNERABLE | 15.5.7 |
| Next.js 15.4.x | VULNERABLE | 15.4.8 |
| Next.js 15.3.x | VULNERABLE | 15.3.6 |
| Next.js 15.2.x | VULNERABLE | 15.2.6 |
| Next.js 15.1.x | VULNERABLE | 15.1.9 |
| Next.js 15.0.x | VULNERABLE | 15.0.5 |
| Next.js 14.3.0-canary.77+ | VULNERABLE | Upgrade to 15.x patched |
| Next.js 14.x stable | SAFE | No patch needed |
| Next.js 13.x | SAFE | No patch needed |

**Important**: Only Next.js apps using App Router with React Server Components are affected. Pages Router apps are NOT vulnerable.

---

## Technical Details

### Root Cause
The vulnerable code unsafely deserializes payloads from HTTP requests to Server Function endpoints in the React Server Components "Flight" protocol.

### Attack Vector
- **Network-based**: Exploitable remotely
- **No authentication required**: Unauthenticated RCE
- **No user interaction needed**: Fully automated exploitation
- **Default configurations vulnerable**: Standard `create-next-app` apps are exploitable

### Exploitation

**Active Exploitation Confirmed!**
Within hours of public disclosure, multiple China state-nexus threat groups began exploiting this vulnerability:
- **Earth Lamia**
- **Jackpot Panda**

**Public PoC Available**: Working RCE exploit code is publicly available

**EPSS Score**: 13.814% (94th percentile) - High probability of exploitation within 30 days

---

## Affected Frameworks

The following React frameworks & bundlers are affected:
1. **Next.js** (15.x, 16.x with App Router)
2. **React Router** (with RSC)
3. **Waku**
4. **@parcel/rsc**
5. **@vitejs/plugin-rsc** (Vite RSC plugin)
6. **rwsdk** (Redwood SDK)

---

## Remediation

### React Projects

```bash
# For React 19.0.0:
npm install react@19.0.1 react-dom@19.0.1

# For React 19.1.0 or 19.1.1:
npm install react@19.1.2 react-dom@19.1.2

# For React 19.2.0:
npm install react@19.2.1 react-dom@19.2.1
```

### Next.js Projects

```bash
# Upgrade to appropriate patched version:
npm install next@16.0.7      # For Next.js 16.x
npm install next@15.5.7      # For Next.js 15.5.x
npm install next@15.4.8      # For Next.js 15.4.x
npm install next@15.3.6      # For Next.js 15.3.x
npm install next@15.2.6      # For Next.js 15.2.x
npm install next@15.1.9      # For Next.js 15.1.x
npm install next@15.0.5      # For Next.js 15.0.x
```

### Post-Patch Steps

```bash
npm install           # Install new versions
npm run build        # Rebuild application
# Test thoroughly before deploying
```

**Important**: There is NO configuration option to disable the vulnerable code path. You MUST upgrade.

---

## References

### Official Advisories
- [React Security Blog](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [Next.js Security Advisory](https://nextjs.org/blog/CVE-2025-66478)
- [GitHub Advisory GHSA-fv66-9v8q-g76r](https://github.com/advisories/GHSA-fv66-9v8q-g76r)
- [Vercel Changelog](https://vercel.com/changelog/cve-2025-55182)

### Technical Analysis
- [React2Shell.com](https://react2shell.com/) - Dedicated vulnerability tracker
- [Wiz Security Analysis](https://www.wiz.io/blog/critical-vulnerability-in-react-cve-2025-55182)
- [Unit42 Analysis](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- [Praetorian Exploit Analysis](https://www.praetorian.com/blog/critical-advisory-remote-code-execution-in-next-js-cve-2025-66478-with-working-exploit/)
- [Datadog Security Labs](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)

### Threat Intelligence
- [AWS Security - China-nexus Exploitation](https://aws.amazon.com/blogs/security/china-nexus-cyber-threat-groups-rapidly-exploit-react2shell-vulnerability-cve-2025-55182/)

### Fix Details
- [GitHub PR #35277](https://github.com/facebook/react/pull/35277)
- [Fix Commit](https://github.com/facebook/react/commit/7dc903cd29dac55efb4424853fd0442fef3a8700)
- [OSS Security Mailing List](http://www.openwall.com/lists/oss-security/2025/12/03/4)

### National Cyber Security Centers
- [Singapore CSA Alert](https://www.csa.gov.sg/alerts-and-advisories/alerts/al-2025-112/)

### CVE Databases
- [NVD CVE-2025-55182](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [MITRE CVE-2025-55182](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2025-55182)

---

## Detection & Scanning

Use the React CVE Scanner MCP to automatically detect vulnerable projects:

```bash
python scan.py /path/to/projects
```

The scanner will identify:
- Vulnerable React versions (19.0.0, 19.1.0, 19.1.1, 19.2.0)
- Vulnerable Next.js versions (15.x, 16.x with App Router)
- React Server Components usage
- Recommended patched versions

---

## Risk Assessment

### Severity Factors
- ✅ **Maximum CVSS Score** (10.0/10.0)
- ✅ **Active Exploitation** (State-sponsored APTs)
- ✅ **Public PoC Available**
- ✅ **No Workarounds** (Must patch)
- ✅ **Default Config Vulnerable**
- ✅ **Widespread Usage** (React/Next.js popularity)

### Business Impact
- Complete server compromise
- Data exfiltration
- Ransomware deployment
- Lateral movement in infrastructure
- Supply chain attacks

---

## Timeline

| Date | Event |
|------|-------|
| Nov 29, 2025 | Lachlan Davidson responsibly discloses to Meta |
| Dec 3, 2025 | Public disclosure by React team |
| Dec 3, 2025 | Patches released (19.0.1, 19.1.2, 19.2.1) |
| Dec 3, 2025 | Next.js patches released (15.0.5+, 16.0.7) |
| Dec 3, 2025 | Active exploitation begins (China APTs) |
| Dec 4, 2025 | Public PoC exploit released |
| Dec 6, 2025 | Widespread scanning and exploitation observed |

---

**Last Updated**: 2025-12-06
**Status**: ACTIVELY EXPLOITED - PATCH IMMEDIATELY
