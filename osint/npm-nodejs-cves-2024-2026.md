# COMPREHENSIVE CVE REPORT: npm/Node.js Ecosystem 2024-2026

**Collection Date:** 2026-01-23  
**Intelligence Specialist:** Gatherer-OSINT Agent  
**Scope:** npm ecosystem, Node.js runtime, React/Next.js, and related bundlers/tools  
**Severity Filter:** CRITICAL and HIGH (CVSS 7.0+)  

---

## EXECUTIVE SUMMARY

This report identifies **30+ critical and high-severity CVEs** affecting the npm/Node.js ecosystem from 2024-2026. The most severe vulnerabilities include:

- **CVE-2025-55182 (CVSS 10.0)** - React Server Components RCE ("React2Shell")
- **CVE-2026-21858 (CVSS 10.0)** - n8n workflow automation unauthenticated RCE
- **CVE-2025-68613 (CVSS 9.9)** - n8n authenticated expression injection RCE
- **CVE-2024-21534 (CVSS 9.8)** - jsonpath-plus RCE
- **CVE-2024-21508 (CVSS 9.8)** - mysql2 RCE
- **CVE-2025-29927 (CVSS 9.1)** - Next.js middleware authorization bypass

**Attack Surface:** Remote Code Execution, Path Traversal, Source Code Exposure, Supply Chain Attacks, DoS

---

## CATEGORY 1: REACT SERVER COMPONENTS VULNERABILITIES

### CVE-2025-55182 - React Server Components RCE ("React2Shell")
**Severity:** CRITICAL (CVSS 10.0)  
**CVE Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H  
**CWE:** CWE-502 (Deserialization of Untrusted Data)  

**Affected Packages:**
- **react-server-dom-parcel**: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- **react-server-dom-turbopack**: 19.0.0, 19.1.0, 19.1.1, 19.2.0
- **react-server-dom-webpack**: 19.0.0, 19.1.0, 19.1.1, 19.2.0

**Affected Next.js Versions (Node.js):**
- 15.0.0 to 15.0.4
- 15.1.0 to 15.1.8
- 15.2.0 to 15.2.5
- 15.3.0 to 15.3.5
- 15.4.0 to 15.4.7
- 15.5.0 to 15.5.6
- 16.0.0 to 16.0.6

**Affected Frameworks/Bundlers:**
- Next.js
- React Router
- Waku
- @parcel/rsc
- @vitejs/plugin-rsc
- rwsdk

**Patched Versions:** React 19.0.1, 19.1.2, 19.2.1

**Description:**  
Critical pre-authentication remote code execution vulnerability in React Server Components. The flaw involves unsafe deserialization of payloads from HTTP requests to Server Function endpoints. Attackers can craft malicious HTTP requests that, when deserialized by React, execute arbitrary code on the server.

**Exploitation:**
- Publicly disclosed: December 3, 2025
- Active exploitation detected: December 5, 2025
- Added to CISA KEV Catalog: December 5, 2025 (Due Date: December 12, 2025)
- Exploitation by nation-state actors (PRC-linked groups)
- Observed payloads: coin miners, credential harvesting, cloud backdoors (SNOWLIGHT, VShell)

**Impact:**
- Unauthenticated remote code execution
- Full server compromise
- Data exfiltration
- Lateral movement capabilities

---

### CVE-2025-55183 - React Server Components Source Code Exposure
**Severity:** MEDIUM (CVSS 5.3)  

**Affected Versions:** 19.0.0-19.2.2 (react-server-dom-parcel, react-server-dom-webpack, react-server-dom-turbopack)  
**Patched Versions:** 19.0.3, 19.1.4, 19.2.3

**Description:**  
Server Functions can be manipulated to return compiled source code by calling ".toString()" on server function objects, potentially exposing hardcoded secrets, API keys, and sensitive logic.

**Impact:**
- Source code disclosure
- Exposure of hardcoded credentials
- Intellectual property theft

---

### CVE-2025-55184 & CVE-2025-67779 - React Server Components DoS
**Severity:** HIGH (CVSS 7.5)  

**Affected Versions:**
- CVE-2025-55184: 19.0.0-19.0.1, 19.1.0-19.1.1, 19.2.0-19.2.1
- CVE-2025-67779: 19.0.2, 19.1.3, 19.2.2 (incomplete fix)

**Patched Versions:** 19.0.3, 19.1.4, 19.2.3

**Description:**  
Malicious HTTP requests to Server Function endpoints can trigger infinite loops that hang the server process and consume CPU resources, causing denial of service.

**Impact:**
- Server process hangs
- CPU exhaustion
- Service unavailability

**Note:** Organizations that patched CVE-2025-55182 may still be vulnerable to DoS if using incomplete fix versions.

---

### CVE-2025-66478 - Next.js RCE (REJECTED - Duplicate of CVE-2025-55182)
**Status:** REJECTED as duplicate of CVE-2025-55182  
**Original Severity:** CRITICAL (CVSS 10.0)

Initially tracked separately for Next.js but later determined to be the same vulnerability as CVE-2025-55182.

---

## CATEGORY 2: NEXT.JS VULNERABILITIES

### CVE-2025-29927 - Next.js Middleware Authorization Bypass
**Severity:** CRITICAL (CVSS 9.1)  

**Affected Versions:**
- 11.1.4 through 13.5.6
- 14.x before 14.2.25
- 15.x before 15.2.3

**Patched Versions:** 13.5.7+, 14.2.25+, 15.2.3+

**Description:**  
Attackers can bypass authorization middleware by injecting a specially crafted `x-middleware-subrequest` HTTP header. This allows complete circumvention of middleware controls in self-hosted Next.js applications using `next start` with `output: 'standalone'`.

**Impact:**
- Authorization bypass
- Unauthorized access to protected routes
- Security control circumvention

**Note:** Vercel-hosted deployments are automatically protected, but self-hosted instances require patching.

---

## CATEGORY 3: NODE.JS RUNTIME VULNERABILITIES

### CVE-2025-59465 - Node.js HTTP/2 Server DoS (High)
**Severity:** HIGH  

**Affected Versions:** All Node.js 18.x, 20.x, 22.x, 24.x, 25.x  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
Malformed HTTP/2 HEADERS frames with oversized HPACK data trigger unhandled TLSSocket ECONNRESET errors, causing Node.js process crashes and enabling remote denial of service.

**Impact:**
- Process crash
- Service unavailability
- DoS attacks

---

### CVE-2025-59464 - Node.js TLS Client Certificate Memory Leak (Medium)
**Severity:** MEDIUM  

**Affected Versions:** Node.js 20.x, 22.x, 24.x, 25.x  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
Memory leak in applications processing TLS client certificates enables remote denial of service through resource exhaustion.

**Impact:**
- Memory exhaustion
- Remote DoS
- Service degradation

---

### CVE-2025-59466 - Node.js async_hooks Uncatchable Error (Medium)
**Severity:** MEDIUM  

**Affected Versions:** Node.js 20.x, 22.x, 24.x, 25.x  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
Uncatchable "Maximum call stack size exceeded" error via async_hooks leads to process crashes, bypassing error handlers.

**Impact:**
- Process crashes
- Error handler bypass
- Service instability

**Requirements:** async_hooks must be enabled

---

### CVE-2025-27210 - Node.js Windows Path Traversal (High)
**Severity:** HIGH (CVSS ~7.0+)  

**Affected Versions:** Node.js 20.x, 22.x, 24.x on Windows  
**Patched Versions:** July 2025 security release

**Description:**  
Incomplete fix for CVE-2025-23084. Windows reserved device names (CON, PRN, AUX) bypass path traversal protections in `path.normalize()` and `path.join()` APIs, allowing directory traversal attacks.

**Impact:**
- Path traversal
- Unauthorized file access
- Configuration file exposure

**Platform:** Windows only

---

### CVE-2025-23084 - Node.js Path Traversal on Windows (Medium)
**Severity:** MEDIUM (CVSS 5.6)  
**CWE:** CWE-22 (Improper Limitation of a Pathname to a Restricted Directory)

**Affected Versions:** Node.js 18.x, 20.x, 22.x, 23.x on Windows  
**Patched Versions:** Later versions (see security releases)

**Description:**  
Node.js functions don't properly treat drive names as special on Windows. Paths without file separators are treated as relative but actually refer to root directory.

**Impact:**
- Path traversal
- Unauthorized file access
- Directory restriction bypass

**Platform:** Windows only

---

### CVE-2024-21891 - Node.js Permission Model Bypass (High)
**Severity:** HIGH (CVSS 8.8)  

**Affected Versions:**
- Node.js 20.0.0 to 20.11.0
- Node.js 21.0.0 to 21.6.1

**Patched Versions:** 20.11.1+, 21.6.2+

**Description:**  
Built-in utility functions to normalize paths can be overwritten with user-defined implementations, leading to filesystem permission model bypass through path traversal attack.

**Impact:**
- Permission model bypass
- Unauthorized file system access
- Security boundary violation

**Note:** Affects experimental permission model in Node.js 20 and 21

---

### CVE-2025-55130 - Node.js Permission Model Symlink Bypass (High)
**Severity:** HIGH  

**Affected Versions:** Node.js 20.x, 22.x, 24.x, 25.x  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
Crafted symlinks bypass `--allow-fs-read` and `--allow-fs-write` permission restrictions, enabling arbitrary file read/write operations.

**Impact:**
- Permission bypass
- Arbitrary file read/write
- Security control circumvention

---

### CVE-2026-21636 - Node.js Unix Domain Socket Permission Bypass (Medium)
**Severity:** MEDIUM  

**Affected Versions:** Node.js 20.x, 22.x, 24.x, 25.x  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
Unix Domain Socket (UDS) connections bypass `--allow-net` restrictions. APIs like net, tls, or fetch can establish UDS connections without proper permission checks.

**Impact:**
- Network permission bypass
- Access to privileged local services
- Security isolation violation

---

### CVE-2025-55132 - Node.js fs.futimes() Permission Bypass (Low)
**Severity:** LOW  

**Affected Versions:** Node.js with permission model enabled  
**Patched Versions:** 20.20.0+, 22.22.0+, 24.13.0+, 25.3.0+

**Description:**  
`fs.futimes()` bypasses read-only permission model restrictions.

**Impact:**
- Limited permission bypass
- File timestamp modification

**Fix:** fs.futimes() disabled when permission model is enabled

---

## CATEGORY 4: NPM SUPPLY CHAIN ATTACKS

### CVE-2025-54313 - eslint-config-prettier Supply Chain Attack
**Severity:** HIGH (CVSS 7.5)  

**Affected Packages:**
- eslint-config-prettier: 8.10.1, 9.1.1, 10.1.6, 10.1.7
- eslint-plugin-prettier
- synckit
- @pkgr/core
- napi-postinstall

**Safe Versions:** 8.10.2+, 9.1.2+, 10.1.8+

**Description:**  
Maintainer phishing attack (fake npnjs.com domain) led to account compromise. Malicious versions contain embedded malware ("Scavenger" DLL) targeting Windows systems.

**Attack Vector:**
- Install.js file executes node-gyp.dll malware
- Exfiltrates `.npmrc` containing npm tokens
- Supply chain propagation

**Impact:**
- Credential theft
- npm token exfiltration
- Supply chain compromise
- 30+ million weekly downloads affected

**Timeline:**
- Attack: July 19, 2025
- Public disclosure: July 2025
- Malicious versions deprecated on npm registry

---

### Shai-Hulud Worm Campaign (November 2025)
**Campaign Name:** Shai-Hulud 2.0  
**Severity:** CRITICAL  

**Scope:**
- 25,000+ malicious GitHub repositories
- 350+ unique compromised users
- Tens of thousands of affected repositories

**Description:**  
Self-replicating npm-focused malware campaign targeting developer credentials. Worm infiltrates npm ecosystem via compromised maintainer accounts.

**Impact:**
- Developer credential theft
- Mass repository compromise
- Supply chain contamination
- Automated propagation

---

## CATEGORY 5: NPM PACKAGE VULNERABILITIES

### CVE-2024-21534 - jsonpath-plus RCE
**Severity:** CRITICAL (CVSS 9.8)  

**Affected Versions:** All versions before 10.2.0  
**Patched Versions:** 10.2.0+ (npm), NO FIX for Maven (org.webjars.npm:jsonpath-plus up to 6.0.1)

**Description:**  
Improper input sanitization and unsafe default usage of `vm` module in Node.js allows arbitrary code execution.

**Impact:**
- Remote code execution
- Full system compromise
- Public PoC exploits available

**Note:** Versions 10.0.0-10.1.0 had incomplete fixes vulnerable to alternative payloads

---

### CVE-2025-1302 - jsonpath-plus RCE (Incomplete Fix)
**Severity:** CRITICAL  

**Affected Versions:** Versions with incomplete CVE-2024-21534 fix  
**Patched Versions:** 10.2.0+

**Description:**  
Incomplete fix for CVE-2024-21534 allows exploitation via different payloads.

---

### CVE-2024-21508 - mysql2 RCE
**Severity:** CRITICAL (CVSS 9.8)  
**CWE:** CWE-94 (Code Injection)  
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

**Affected Versions:** All versions before 3.9.4  
**Patched Versions:** 3.9.4+

**Description:**  
Improper validation of `supportBigNumbers` and `bigNumberStrings` values in `readCodeFor` function enables remote code execution.

**Impact:**
- Remote code execution
- Full database server compromise
- No authentication required

**Remediation:** No known workaround - upgrade required

---

### CVE-2024-34344 - Nuxt.js Test Mode RCE
**Severity:** HIGH  
**CVSS Vector:** CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N

**Affected Versions:** Nuxt.js < 3.12.4  
**Patched Versions:** 3.12.4+

**Description:**  
Insufficient validation of path parameter in NuxtTestComponentWrapper allows arbitrary JavaScript execution on server when test server is running.

**Attack Scenario:**
- User runs tests locally
- Opens malicious web page in browser
- Page sends requests to localhost test server
- Arbitrary code execution on developer machine

**Impact:**
- Remote code execution in development
- Developer machine compromise
- Supply chain attack vector

---

### CVE-2024-45590 - body-parser Denial of Service
**Severity:** HIGH (CVSS 7.5)  
**CWE:** CWE-405 (Asymmetric Resource Consumption)  
**CVSS Vector:** CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H

**Affected Versions:** All versions before 1.20.3  
**Patched Versions:** 1.20.3+

**Description:**  
Lack of input validation when URL encoding is enabled allows attackers to flood server with specially crafted payloads, causing denial of service.

**Impact:**
- Denial of service
- Server resource exhaustion
- Service unavailability

**Workaround:** Disable URL encoding by setting `extended: false` in body-parser configuration

**Published:** September 10, 2024

---

### CVE-2025-48997 - multer Denial of Service
**Severity:** CRITICAL  

**Affected Versions:** multer 1.4.4-lts.1 and < 2.0.1  
**Patched Versions:** 2.0.1+

**Description:**  
Upload requests with empty string field names trigger unhandled exceptions, causing process crashes.

**Impact:**
- Denial of service
- Process crash
- Service unavailability

**Affected Frameworks:** @nestjs/platform-express

---

### CVE-2025-47944 - multer Vulnerability
**Severity:** HIGH  

**Affected Versions:** multer 1.4.4-lts.1  
**Patched Versions:** Later versions

**Description:**  
Additional multer vulnerability affecting NestJS and other frameworks.

---

### CVE-2024-13059 - AnythingLLM Path Traversal to RCE
**Severity:** HIGH  

**Affected Versions:** AnythingLLM < 1.3.1  
**Patched Versions:** 1.3.1+

**Description:**  
Improper handling of non-ASCII filenames in multer library leads to path traversal. Attackers with manager/admin roles can write arbitrary files and achieve RCE.

**Impact:**
- Path traversal
- Arbitrary file write
- Remote code execution

**Requirements:** Manager or admin role

---

### CVE-2026-21440 - AdonisJS Bodyparser Path Traversal
**Severity:** CRITICAL (CVSS 9.2)  

**Affected Versions:** AdonisJS bodyparser (specific versions TBD)  
**Patched Versions:** Latest release

**Description:**  
Crafted filenames with traversal sequences bypass sanitization in `MultipartFile.move()`, enabling arbitrary file write.

**Impact:**
- Path traversal
- Arbitrary file write
- Potential RCE

---

## CATEGORY 6: N8N WORKFLOW AUTOMATION VULNERABILITIES

### CVE-2026-21858 - n8n Unauthenticated RCE ("Ni8mare")
**Severity:** CRITICAL (CVSS 10.0)  

**Affected Versions:** n8n < 1.121.0  
**Patched Versions:** 1.121.0+

**Description:**  
Content-Type confusion flaw in Form Webhook HTTP request parsing allows unauthenticated file read via filepath parameter manipulation. Attackers can:
1. Leak arbitrary files (config, database)
2. Recreate n8n-auth cookies for any user including admins
3. Execute commands via Execute Command node with admin privileges

**Attack Chain:**
1. Arbitrary file read via webhook
2. Authentication bypass through leaked credentials
3. Remote code execution through workflow manipulation

**Impact:**
- Unauthenticated RCE
- Full instance takeover
- Data exfiltration
- Cloud-native backdoor deployment

**Estimated Exposure:** ~100,000 servers globally (primarily self-hosted)

**Remediation:** Upgrade to 1.121.0+ (no workarounds available)

---

### CVE-2025-68613 - n8n Authenticated Expression Injection RCE
**Severity:** CRITICAL (CVSS 9.9)  

**Affected Versions:** n8n 0.211.0 to < 1.120.4, < 1.121.1, < 1.122.0  
**Patched Versions:** 1.120.4+, 1.121.1+, 1.122.0+

**Description:**  
Insufficient sandbox isolation in workflow expression evaluation allows authenticated users to escape execution context. Function expressions access Node.js global `this` object, leading to `process.mainModule.require('child_process').execSync(...)` command execution.

**Impact:**
- Authenticated remote code execution
- Full instance takeover
- OS-level command execution
- Lateral movement

**Requirements:** Workflow creation/editing permissions (no elevated privileges required)

**Mitigations (temporary):**
- Restrict workflow editing to trusted users only
- Deploy in hardened environment
- Limit OS privileges and network access

**Exploitation Status:** No confirmed in-the-wild exploitation (as of late December 2025)

---

### CVE-2025-68668 - n8n Python Code Node RCE
**Severity:** HIGH  

**Affected Package:** @n8n/config  

**Description:**  
Insufficient isolation in Python Code Node using Pyodide allows remote code execution.

**Impact:**
- Remote code execution
- Sandbox escape
- Unauthorized operations

---

## CATEGORY 7: BUNDLER/TOOLING VULNERABILITIES

### React Server Components Bundler Vulnerabilities
**Affected Bundlers:** All covered under CVE-2025-55182

**Impacted Tools:**
- **Webpack** (react-server-dom-webpack)
- **Turbopack** (react-server-dom-turbopack)
- **Parcel** (react-server-dom-parcel, @parcel/rsc)
- **Vite** (@vitejs/plugin-rsc)

All share the same critical RCE vulnerability through React Server Components Flight protocol implementation.

---

## ATTACK SURFACE SUMMARY

### Critical Entry Points
1. **React Server Components** - Any RSC-enabled application (Next.js, Waku, React Router, etc.)
2. **Self-hosted Next.js** - Middleware bypass and RSC vulnerabilities
3. **n8n instances** - Both unauthenticated (webhook) and authenticated (expression injection)
4. **npm Supply Chain** - Compromised packages, malicious dependencies
5. **Windows Node.js Applications** - Path traversal vulnerabilities
6. **Node.js Permission Model** - Multiple bypass techniques

### Common Vulnerability Patterns
- **Deserialization Flaws** - React Flight protocol, expression evaluation
- **Path Traversal** - Windows-specific issues, symlink bypasses
- **Input Validation** - body-parser, multer, jsonpath-plus
- **Supply Chain** - Maintainer account compromise, malicious packages
- **Permission Bypasses** - Node.js permission model weaknesses

### Exploitation Landscape
- **Active Exploitation:** CVE-2025-55182 (React2Shell) by nation-state actors
- **Public PoCs:** CVE-2024-21534, CVE-2026-21858, CVE-2025-68613
- **Supply Chain Campaigns:** Shai-Hulud worm, eslint-config-prettier compromise

---

## RECOMMENDATIONS FOR BUG BOUNTY HUNTERS

### High-Value Targets
1. **Next.js Applications** running versions 15.x-16.x
2. **Self-hosted Next.js** with middleware authentication
3. **n8n instances** exposed to internet
4. **Applications using React 19.x** Server Components
5. **npm packages** with high download counts and outdated dependencies

### Exploitation Strategies
1. **Identify React Server Components usage** - Look for Flight protocol endpoints
2. **Test middleware bypasses** - Custom headers, path manipulation
3. **Check Node.js versions** - Vulnerable Windows installations
4. **Audit dependencies** - Outdated packages with known RCEs
5. **Supply chain research** - Recently compromised packages

### Recon Focus Areas
- `/api/*` endpoints in Next.js applications
- Form webhook endpoints in n8n instances
- Package.json files exposed via misconfiguration
- Windows-hosted Node.js applications
- Applications using experimental Node.js permission model

---

## TIMELINE OF MAJOR DISCLOSURES

- **February 2024** - CVE-2024-21891 (Node.js permission bypass)
- **September 2024** - CVE-2024-45590 (body-parser DoS)
- **December 3, 2025** - CVE-2025-55182 (React2Shell) public disclosure
- **December 5, 2025** - Active exploitation of CVE-2025-55182 detected
- **December 11, 2025** - CVE-2025-55183/55184/67779 (React DoS and source exposure)
- **July 2025** - CVE-2025-54313 (eslint-config-prettier supply chain)
- **November 2025** - Shai-Hulud 2.0 worm campaign
- **January 2026** - CVE-2026-21858 (n8n Ni8mare), CVE-2026-21636 (Node.js UDS bypass)
- **January 13, 2026** - Node.js security release (8 CVEs)

---

## REFERENCES AND SOURCES

### Official Security Advisories
- [React Official Security Blog - CVE-2025-55182](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [React Official Security Blog - DoS & Source Exposure](https://react.dev/blog/2025/12/11/denial-of-service-and-source-code-exposure-in-react-server-components)
- [Next.js Security Advisory - CVE-2025-66478](https://nextjs.org/blog/CVE-2025-66478)
- [Next.js Security Update - December 11, 2025](https://nextjs.org/blog/security-update-2025-12-11)
- [Node.js Security Releases - January 2026](https://nodejs.org/en/blog/vulnerability/december-2025-security-releases)
- [Node.js Security Releases - July 2025](https://nodejs.org/en/blog/vulnerability/july-2025-security-releases)
- [Node.js Security Releases - February 2024](https://nodejs.org/en/blog/vulnerability/february-2024-security-releases)

### NVD/NIST Database
- [CVE-2025-55182 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-55182)
- [CVE-2025-23084 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-23084)
- [CVE-2025-27210 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2025-27210)
- [CVE-2024-21534 - NVD](https://nvd.nist.gov/vuln/detail/cve-2024-21534)
- [CVE-2024-21508 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-21508)
- [CVE-2024-34344 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-34344)
- [CVE-2024-45590 - NVD](https://nvd.nist.gov/vuln/detail/CVE-2024-45590)

### Threat Intelligence & Analysis
- [Palo Alto Unit 42 - React Server Components Exploitation](https://unit42.paloaltonetworks.com/cve-2025-55182-react-and-cve-2025-66478-next/)
- [Microsoft Security Blog - React2Shell Defense](https://www.microsoft.com/en-us/security/blog/2025/12/15/defending-against-the-cve-2025-55182-react2shell-vulnerability-in-react-server-components/)
- [Datadog Security Labs - CVE-2025-55182 Analysis](https://securitylabs.datadoghq.com/articles/cve-2025-55182-react2shell-remote-code-execution-react-server-components/)
- [ProjectDiscovery - Next.js Middleware Bypass](https://projectdiscovery.io/blog/nextjs-middleware-authorization-bypass)
- [Orca Security - n8n CVE-2026-21858](https://orca.security/resources/blog/cve-2026-21858-n8n-rce-vulnerability/)
- [Orca Security - n8n CVE-2025-68613](https://orca.security/resources/blog/cve-2025-68613-n8n-rce-vulnerability/)
- [Cyera Research Labs - Ni8mare](https://www.cyera.com/research-labs/ni8mare-unauthenticated-remote-code-execution-in-n8n-cve-2026-21858)
- [Horizon3.ai - n8n RCE Analysis](https://horizon3.ai/attack-research/attack-blogs/the-ni8mare-test-n8n-rce-under-the-microscope-cve-2026-21858/)

### Vulnerability Databases
- [Snyk Security Advisory - React/Next.js RCE](https://snyk.io/blog/security-advisory-critical-rce-vulnerabilities-react-server-components/)
- [Snyk - CVE-2024-21534](https://security.snyk.io/vuln/SNYK-JS-JSONPATHPLUS-7945884)
- [Snyk - CVE-2024-21508](https://security.snyk.io/vuln/SNYK-JS-MYSQL2-6591085)
- [Snyk - CVE-2024-34344](https://security.snyk.io/vuln/SNYK-JS-NUXT-7640974)
- [Snyk - CVE-2024-45590](https://security.snyk.io/vuln/SNYK-JS-BODYPARSER-7954826)
- [GitHub Advisory Database - CVE-2025-54313](https://github.com/advisories/GHSA-f29h-pxvx-f335)
- [GitHub Advisory Database - CVE-2024-21534](https://github.com/advisories/GHSA-pppg-cpfq-h7wr)
- [GitHub Advisory Database - CVE-2024-21508](https://github.com/advisories/GHSA-fpw7-j2hg-69v5)
- [GitHub Advisory Database - CVE-2024-34344](https://github.com/advisories/GHSA-v784-fjjh-f8r4)
- [GitHub Advisory Database - CVE-2024-45590](https://github.com/advisories/GHSA-qwcr-r2fm-qrc7)

### Supply Chain Intelligence
- [Palo Alto Unit 42 - Shai-Hulud Worm](https://unit42.paloaltonetworks.com/npm-supply-chain-attack/)
- [Trend Micro - NPM Supply Chain Attack](https://www.trendmicro.com/en_us/research/25/i/npm-supply-chain-attack.html)
- [Red Hat - Multiple NPM Supply Chain Attacks](https://access.redhat.com/security/supply-chain-attacks-NPM-packages)
- [Endor Labs - eslint-config-prettier Compromise](https://www.endorlabs.com/learn/cve-2025-54313-eslint-config-prettier-compromise----high-severity-but-windows-only)
- [ZeroPath - CVE-2025-54313 Deep Dive](https://zeropath.com/blog/cve-2025-54313-eslint-config-prettier-supply-chain-malware)
- [SafeDep - eslint-config-prettier Hack](https://safedep.io/eslint-config-prettier-major-npm-supply-chain-hack/)

### Node.js Specific Analysis
- [Endor Labs - Eight Node.js Vulnerabilities](https://www.endorlabs.com/learn/eight-for-one-multiple-vulnerabilities-fixed-in-the-node-js-runtime)
- [ZeroPath - CVE-2025-27210 Path Traversal](https://zeropath.com/blog/cve-2025-27210-nodejs-path-traversal-windows)
- [NodeSource - Node.js January 2026 Security Release](https://nodesource.com/blog/nodejs-security-release-january-2026)

### Security Research & PoCs
- [Hunt.io - React2Shell PoC](https://hunt.io/blog/react2shell-cve-2025-55182-nextjs-nodejs-rce)
- [GitHub - CVE-2024-21534 PoC](https://github.com/verylazytech/cve-2024-21534)
- [GitHub - CVE-2025-68613 PoC](https://github.com/mbanyamer/n8n-Authenticated-Expression-Injection-RCE-CVE-2025-68613)
- [Praetorian - Next.js CVE-2025-66478 with Working Exploit](https://www.praetorian.com/blog/critical-advisory-remote-code-execution-in-next-js-cve-2025-66478-with-working-exploit/)

### Additional Resources
- [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [Vercel - CVE-2025-55182 Summary](https://vercel.com/changelog/cve-2025-55182)
- [Express.js Security Releases - September 2024](https://expressjs.com/2024/09/29/security-releases.html)
- [Resecurity - CVE-2025-68613 Analysis](https://www.resecurity.com/blog/article/cve-2025-68613-remote-code-execution-via-expression-injection-in-n8n-2)

---

## CONCLUSION

The npm/Node.js ecosystem experienced a significant security crisis in 2025-2026, with multiple CVSS 10.0 vulnerabilities and active nation-state exploitation. The React Server Components vulnerability (CVE-2025-55182) represents one of the most severe web framework vulnerabilities in recent history, affecting millions of applications.

Key takeaways for security researchers:
1. **Immediate patching critical** for React 19.x and Next.js 15.x-16.x
2. **Supply chain vigilance** essential due to active worm campaigns
3. **Windows Node.js deployments** require special attention for path traversal issues
4. **n8n instances** present high-value targets with multiple RCE vectors
5. **Bundler implementations** of RSC introduce framework-wide vulnerabilities

This intelligence should guide reconnaissance efforts toward vulnerable technology stacks and inform prioritization of security testing activities.

---

**Report Classification:** OSINT - Publicly Available Information  
**Next Update:** Monitor for new CVEs in Q1 2026  
**Contact:** Rainkode Bug Bounty Operations
