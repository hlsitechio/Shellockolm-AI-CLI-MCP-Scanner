# AI Gateway Security Research - OSINT Report
**Date:** 2026-01-27
**Classification:** UNCLASSIFIED - Security Research

## EXECUTIVE SUMMARY

Researched 15 AI coding assistants and gateways that act as proxies to AI APIs. Found multiple critical vulnerabilities including exposed credentials, RCE, SSRF, and privilege escalation issues.

## QUICK REFERENCE TABLE

| # | Tool | GitHub URL | Stars | CVEs | Risk Level | Default Ports |
|---|------|-----------|-------|------|------------|---------------|
| 1 | Moltbot (Clawdbot) | github.com/moltbot/moltbot | ~5k | None assigned (Auth Bypass, Shodan exposure) | CRITICAL | 18789, 18791, 22 |
| 2 | Aider | github.com/Aider-AI/aider | 34.3k | None | MEDIUM | N/A (CLI) |
| 3 | Continue.dev | github.com/continuedev/continue | 31.1k | None | MEDIUM | N/A (IDE) |
| 4 | Open Interpreter | github.com/openinterpreter/open-interpreter | 61.8k | None (CWE-94 fixed) | MEDIUM-HIGH | 1337 |
| 5 | Sweep AI | github.com/sweepai/sweep | 7.6k | None | LOW | N/A (IDE) |
| 6 | Cline (Claude Dev) | github.com/project-copilot/claude-dev | ~20k | None | MEDIUM | N/A (IDE) |
| 7 | GPT Engineer | github.com/AntonOsika/gpt-engineer | ~52k | None | MEDIUM | N/A (CLI) |
| 8 | GPT-Pilot | github.com/Pythagora-io/gpt-pilot | ~30k | None | MEDIUM | N/A (CLI) |
| 9 | Tabby | github.com/TabbyML/tabby | 32.8k | None | LOW | N/A |
| 10 | jan.ai | github.com/janhq/jan | 40.1k | None | LOW | 1337 |
| 11 | LocalAI | github.com/mudler/LocalAI | 35.8k | None | LOW | 8080 |
| 12 | Open WebUI | github.com/open-webui/open-webui | ~50k | CVE-2025-64496 (RCE) | HIGH | Varies |
| 13 | LiteLLM | github.com/BerriAI/litellm | ~15k | 4 CVEs (Key leak, Priv Esc) | HIGH | 4000 |
| 14 | LobeChat | github.com/lobehub/lobehub | ~40k | CVE-2026-23733 (XSS to RCE) | MEDIUM-HIGH | Varies |
| 15 | NextChat | github.com/ChatGPTNextWeb/NextChat | 87.1k | CVE-2023-49785 (SSRF) | HIGH | 3000 |
| 16 | LibreChat | github.com/danny-avila/LibreChat | ~20k | 3 CVEs (Auth Bypass) | MEDIUM-HIGH | Varies |

## CRITICAL VULNERABILITIES FOUND

### 1. MOLTBOT/CLAWDBOT - CREDENTIAL EXPOSURE
**No CVE Assigned**
- **Shodan Discovery:** Search "Clawdbot Control" exposes hundreds of instances
- **Exposed Data:** API keys, OAuth secrets, conversation histories, command execution
- **Authentication Bypass:** Auto-approves localhost without auth when behind reverse proxy
- **Scale:** 1,000+ exposed servers
- **Ports:** 18789 (gateway), 18791 (browser control), 22 (SSH)
- **Credential Storage:** ~/.clawdbot/credentials
- **Demonstration:** Researcher sent prompt injection via email, AI forwarded 5 emails to attacker in 5 minutes

### 2. LITELLM - MULTIPLE CVEs
**CVE-2025-0330** (CVSS 7.5 - HIGH)
- Langfuse API key leakage in proxy_server.py
- Exposes langfuse_secret and langfuse_public_key
- Full project access to all requests

**CVE-2025-0628** (HIGH)
- Privilege escalation: 'internal_user_viewer' role gets admin API key
- Access to /users/list and /users/get_users endpoints
- Escalate to PROXY ADMIN

**CVE-2024-9606** (FIXED in 1.44.12)
- API key masking only masks first 5 characters
- Leaks almost entire key in logs

**Additional:** SQL injection in /key/block, CVE-2024-6825 RCE

### 3. OPEN WEBUI - RCE VIA DIRECT CONNECTIONS
**CVE-2025-64496** (CVSS 7.3-8.0 - HIGH)
- Affects versions up to 0.6.34, patched in 0.6.35
- Code injection via Server-Sent Events (SSE) from Direct Connections
- Arbitrary JavaScript execution via new Function()
- Enables RCE, account takeover, network pivots

**Related Ollama CVEs:**
- CVE-2025-63389 (CRITICAL): Authentication bypass in API endpoints (Ollama ≤v0.12.3)
- CVE-2025-51471 (MEDIUM): Cross-domain token exposure (Ollama 0.6.7)

### 4. NEXTCHAT - CRITICAL SSRF
**CVE-2023-49785** (CVSS 9.1 - CRITICAL)
- Affects versions ≤2.11.2, patched in 2.12.2+
- /api/cors endpoint acts as open proxy
- Unauthenticated SSRF and reflected XSS
- Full read/write access to internal HTTP endpoints
- **Shodan Exposure:** 7,500+ instances (query: title:NextChat,"ChatGPT Next Web")
- Mostly in China and US

### 5. LOBECHAT - XSS TO RCE
**CVE-2026-23733** (CRITICAL)
- Affects versions before 2.0.0-next.180
- Stored XSS in Mermaid artifact renderer
- Escalates to RCE via electronAPI IPC bridge
- Execute arbitrary system commands

### 6. LIBRECHAT - AUTHORIZATION BYPASS
**CVE-2025-6088** (v0.7.8, fixed in v0.7.9-rc1)
- Unauthorized access to conversations via /api/share/conversationID
- No authorization checks

**CVE-2025-69220** (v0.8.1-rc2, fixed in v0.8.2-rc2)
- File upload access control bypass for agents
- Change agent behavior without permissions

**CVE-2024-52787**
- Directory traversal in upload_documents

## HANDLES API KEYS/CREDENTIALS

**Gateway/Proxy Tools (HIGH RISK):**
- ✅ Moltbot/Clawdbot - Claude credentials (CRITICAL - Shodan exposure)
- ✅ LiteLLM - 100+ LLM providers (HIGH - Multiple CVEs)
- ✅ Open WebUI - OpenAI, Anthropic, etc. (HIGH - RCE)
- ✅ NextChat - OpenAI (HIGH - SSRF, 7,500+ exposed)
- ✅ LibreChat - Multiple providers with AES encryption (MEDIUM - Auth bypass)
- ✅ LobeChat - Multiple providers (MEDIUM - XSS to RCE)

**Self-Hosted (LOWER RISK):**
- ❌ LocalAI - Self-hosted, generates own tokens
- ❌ Tabby - Self-hosted, no external APIs
- ⚠️ jan.ai - Optional cloud connection (100% offline capable)

**IDE/CLI Tools (MEDIUM RISK):**
- ✅ Aider - Stores API keys locally
- ✅ Continue.dev - IDE config storage
- ✅ Open Interpreter - Environment vars
- ✅ Cline - VS Code settings
- ✅ Sweep - Platform-managed
- ✅ GPT Engineer/Pilot - Environment vars

## MCP (MODEL CONTEXT PROTOCOL) SUPPORT

**Confirmed MCP Integration:**
1. ✅ Jan.ai - Acts as MCP host
2. ✅ LocalAI - Full MCP support
3. ✅ Continue.dev - YAML configuration
4. ✅ LibreChat - MCP enabled
5. ✅ LobeChat - Claude Artifacts (MCP-based)

**Not Confirmed:**
- Moltbot, LiteLLM, Aider, Open Interpreter, Tabby, Cline, Sweep, GPT Engineer/Pilot
- Open WebUI likely supports via Ollama

## ATTACK SURFACE - KEY FINDINGS

### Credential Leakage Vectors:
1. **Shodan Discovery** - Moltbot (18789), NextChat instances
2. **Log Exposure** - LiteLLM CVE-2024-9606
3. **Auth Bypass** - Moltbot localhost, LibreChat endpoints
4. **Proxy Abuse** - NextChat /api/cors SSRF

### Code Execution Vectors:
1. **XSS to RCE** - LobeChat Mermaid → electronAPI
2. **SSE Injection** - Open WebUI Direct Connections
3. **Inherent Design** - Open Interpreter executes LLM code
4. **RCE** - LiteLLM CVE-2024-6825

### Privilege Escalation:
1. **Role Bypass** - LiteLLM 'internal_user_viewer' → admin
2. **Agent Control** - LibreChat file upload bypass

### Information Disclosure:
1. **Conversation Leak** - LibreChat sharing endpoint
2. **API Key Masking** - LiteLLM partial masking
3. **Full Credential Dump** - Moltbot Shodan exposure

## BUG BOUNTY TARGETING GUIDE

### HIGH-VALUE RECONNAISSANCE:

**1. Shodan/Censys Searches:**
- "Clawdbot Control" (port 18789)
- title:NextChat,"ChatGPT Next Web" (port 3000)
- LiteLLM on port 4000
- LocalAI on port 8080
- jan.ai on port 1337

**2. Port Scanning Targets:**
- 18789, 18791 - Moltbot gateway and browser control
- 4000 - LiteLLM proxy
- 3000 - NextChat
- 8080 - LocalAI
- 1337 - jan.ai API server

**3. Endpoint Testing:**
- `/api/cors` - NextChat SSRF
- `/api/share/conversationID` - LibreChat auth bypass
- `/users/list`, `/users/get_users` - LiteLLM privilege escalation
- `/key/block` - LiteLLM SQL injection
- Direct Connections - Open WebUI SSE injection

### TESTING METHODOLOGY:

**Phase 1: Discovery**
- Shodan/ZoomEye/Censys enumeration
- Port scanning for defaults
- Technology fingerprinting
- Version detection

**Phase 2: Authentication**
- Localhost bypass attempts (Moltbot pattern)
- Token leakage testing
- Credential file exposure (~/.clawdbot/credentials)
- Log analysis for key leaks

**Phase 3: Authorization**
- Role-based access bypass (LiteLLM)
- Conversation sharing auth (LibreChat)
- Agent access control (LibreChat)
- File upload restrictions

**Phase 4: Injection**
- SSRF via proxy endpoints (NextChat /api/cors)
- SSE code injection (Open WebUI)
- XSS in renderers (LobeChat Mermaid)
- SQL injection (LiteLLM)
- Prompt injection (Moltbot email demo)

**Phase 5: RCE Chain**
- XSS → electronAPI → system commands (LobeChat)
- SSE → JavaScript execution (Open WebUI)
- Malicious AI server → Direct Connection (Open WebUI)

## PATCHING STATUS

**Patched:**
- Open WebUI CVE-2025-64496: Upgrade to ≥0.6.35
- LiteLLM CVE-2025-0330: Fixed
- LiteLLM CVE-2024-9606: Fixed in ≥1.44.12
- NextChat CVE-2023-49785: Upgrade to ≥2.12.2
- LobeChat CVE-2026-23733: Upgrade to ≥2.0.0-next.180
- LibreChat CVE-2025-6088: Fixed in v0.7.9-rc1
- LibreChat CVE-2025-69220: Fixed in v0.8.2-rc2
- Ollama CVE-2025-51471: Fixed in PR #10750

**Needs Verification:**
- LiteLLM CVE-2025-0628 status
- Ollama CVE-2025-63389 (affects ≤v0.12.3)

**No CVE Assigned (Critical):**
- Moltbot/Clawdbot authentication bypass and credential exposure
- Open Interpreter code injection (CWE-94 fixed in PR #1643 but no CVE)

## RECOMMENDED SEARCH QUERIES

### For Exposed Instances:
```
Shodan: "Clawdbot Control"
Shodan: title:NextChat,"ChatGPT Next Web"
Censys: services.port:18789
Censys: services.port:4000 product:litellm
```

### For Version Detection:
```
Check /api/version endpoints
Look for X-Powered-By headers
JavaScript bundle comments
README or docs endpoints
```

## SOURCES

All information gathered from public sources including:
- GitHub repositories and security advisories
- CVE databases (NVD, CVEDetails, OpenCVE)
- Security blogs (The Register, Bitdefender, Vicarius, Miggo)
- Official documentation sites
- Shodan/security research reports

## DISCLAIMER

**FOR SECURITY RESEARCH AND BUG BOUNTY PURPOSES ONLY**

This report contains OSINT (Open Source Intelligence) gathered from publicly available sources. Information is provided for:
- Security research
- Authorized bug bounty programs
- Defensive security measures
- Responsible disclosure

**DO NOT:**
- Use for unauthorized access or testing
- Exploit vulnerabilities without permission
- Access systems you don't own or have explicit authorization to test

Always follow responsible disclosure practices and respect bug bounty program rules.

---

**Report Location:** /mnt/bounty/Bounty_New/Github/Shellockolm/shellockolm/AI_GATEWAY_SECURITY_REPORT.md
**Generated:** 2026-01-27
**Classification:** UNCLASSIFIED

