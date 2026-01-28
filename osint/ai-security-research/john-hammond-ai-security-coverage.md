# OSINT Report: John Hammond's AI Security Research Coverage

**Target**: John Hammond (@_JohnHammond) - Security Researcher at Huntress
**Collection Date**: 2026-01-27
**Focus**: AI coding bots, Clawdbot, AI gateway security vulnerabilities

---

## RESEARCHER PROFILE

**Name**: John Hammond  
**Role**: Principal Security Researcher at Huntress  
**YouTube Channel**: [@JohnHammond](https://www.youtube.com/@JohnHammond)  
**Subscribers**: 2.05M+  
**Social Media**: @_JohnHammond (Twitter/X, Instagram)  
**Channel ID**: UCVeW9qkBjo3zosnqUbG7CFw  

**Background**: John Hammond is a well-known cybersecurity researcher, educator, and content creator who specializes in malware analysis, penetration testing, CTF walkthroughs, dark web threats, security tool demonstrations, and vulnerability research.

---

## CONFIRMED VIDEO: "I Backdoored Cursor AI"

**Video**: Over 33 minutes demonstrating backdooring Cursor AI using Loki C2 framework
**References**:
- https://www.classcentral.com/course/youtube-i-backdoored-cursor-ai-443848
- https://www.linkedin.com/posts/johnhammond010_i-backdoored-cursor-ai-httpslnkdin-activity-7315357817526202370-xLsI
- https://www.instagram.com/_johnhammond/p/DIL71qzxUwZ/
- https://app.daily.dev/posts/i-backdoored-cursor-ai-f6fhxclsw

**Content**: Discovery, exploitation, persistence in Cursor AI (Electron app) using Process Monitor and Loki C2

---

## KEY VULNERABILITIES DISCOVERED

### CURSOR IDE CRITICAL VULNERABILITIES

1. **MCPoison (CVE-2025-54136)** - MCP Trust Bypass RCE
   - Discovered: Check Point Research (July 29, 2025)
   - https://research.checkpoint.com/2025/cursor-vulnerability-mcpoison/

2. **CurXecute (CVE-2025-54135)** - MCP Auto-Start RCE
   - Discovered: AIM Security (August 1, 2025)
   - https://www.tenable.com/blog/faq-cve-2025-54135-cve-2025-54136-vulnerabilities-in-cursor-curxecute-mcpoison

3. **Workspace Trust Bypass** - Silent Code Execution
   - Discovered: Oasis Security
   - https://www.oasis.security/blog/cursor-security-flaw

4. **CVE-2025-59944** - Case-Sensitivity File Bypass
   - Discovered: Lakera (Brett Gustafson)
   - Patched: Cursor 1.7
   - https://www.lakera.ai/blog/cursor-vulnerability-cve-2025-59944

5. **94+ Chromium Vulnerabilities**
   - Discovered: OX Security
   - Affected: 1.8 million developers
   - https://www.ox.security/blog/94-vulnerabilities-in-cursor-and-windsurf-put-1-8m-developers-at-risk/

6. **Fake VS Code Extension** - ClawdBot Agent Malware
   - Date: January 27, 2026
   - Type: ScreenConnect RAT disguised as AI assistant
   - https://www.aikido.dev/blog/fake-clawdbot-vscode-extension-malware

---

### CLAWDBOT/MOLTBOT CRITICAL SECURITY CRISIS

**Status**: Renamed from Clawdbot to Moltbot (Anthropic trademark concerns)

1. **1,000+ Exposed Servers** - Unauthenticated Access
   - https://www.theregister.com/2026/01/27/clawdbot_moltbot_security_concerns/
   - https://beyondmachines.net/event_details/clawdbot-security-issues-over-1000-ai-agent-servers-exposed-to-unauthenticated-access-6-y-a-t-e

2. **Authentication Bypass** - Reverse Proxy Misconfiguration
   - All connections appear as 127.0.0.1 (localhost)
   - Exposes: API keys, OAuth secrets, conversation histories

3. **Prompt Injection** - 5-Minute Private Key Theft
   - Researcher: Matvey Kukuy (Archestra AI)
   - Method: Email-based prompt injection

4. **Infostealer Malware Targeting**
   - Families: Redline, Lumma, Vidar
   - https://www.infostealers.com/article/clawdbot-the-new-primary-target-for-infostealers-in-the-ai-era/

5. **Cryptocurrency Theft Vulnerabilities**
   - https://forklog.com/en/critical-vulnerabilities-found-in-clawdbot-ai-agent-for-cryptocurrency-theft/

6. **Credential & Data Leakage**
   - https://www.tradingview.com/news/cointelegraph:99cbc6b7d094b:0-viral-ai-assistant-clawdbot-risks-leaking-private-messages-credentials/
   - https://www.bitdefender.com/en-us/blog/hotforsecurity/moltbot-security-alert-exposed-clawdbot-control-panels-risk-credential-leaks-and-account-takeovers/

7. **GitHub Account Hijacking**
   - Target: Clawdbot founder
   - Date: January 27, 2026
   - https://www.binance.com/en-AE/square/post/01-27-2026-clawdbot-founder-faces-github-account-hijack-by-crypto-scammers-35643613762385

**Official Warning**: "Running an AI agent with shell access on your machine is... spicy. There is no 'perfectly secure' setup."
- https://docs.clawd.bot/gateway/security

**Project**: https://github.com/moltbot/moltbot (formerly clawdbot)

---

### MODEL CONTEXT PROTOCOL (MCP) SECURITY RISKS

**Background**: Open standard by Anthropic (November 2024)

1. **Prompt Injection → Full RCE**
   - https://www.redhat.com/en/blog/model-context-protocol-mcp-understanding-security-risks-and-controls
   - https://www.pillar.security/blog/the-security-risks-of-model-context-protocol-mcp

2. **Tool Permission Exploits** (April 2025 disclosure)
   - Combining tools enables file exfiltration
   - Lookalike tools replace trusted ones
   - https://www.legitsecurity.com/aspm-knowledge-base/model-context-protocol-security

3. **Confused Deputy Problem**
   - Principle of least privilege violations
   - https://writer.com/engineering/mcp-security-considerations/

4. **Token Theft**
   - MCP servers = high-value targets
   - OAuth tokens persist after password changes
   - https://strobes.co/blog/mcp-model-context-protocol-and-its-critical-vulnerabilities/

5. **Authentication Gaps**
   - OAuth optional, ad-hoc approaches
   - https://www.blackhillsinfosec.com/model-context-protocol/

**Academic Research**: https://arxiv.org/abs/2503.23278
**Microsoft Security**: https://blogs.windows.com/windowsexperience/2025/05/19/securing-the-model-context-protocol-building-a-safer-agentic-future-on-windows/

---

### MICROSOFT COPILOT - "REPROMPT" ATTACK

**Discovered**: Varonis Threat Labs (Disclosed August 31, 2025)
**Status**: Patched, no wild exploitation detected
**Affected**: Copilot Personal (NOT M365 Copilot)

**Attack**: Single-click data theft via 'q' parameter URL injection
- https://www.varonis.com/blog/reprompt
- https://www.malwarebytes.com/blog/news/2026/01/reprompt-attack-lets-attackers-steal-data-from-microsoft-copilot
- https://www.bleepingcomputer.com/news/security/reprompt-attack-let-hackers-hijack-microsoft-copilot-sessions/
- https://thehackernews.com/2026/01/researchers-reveal-reprompt-attack.html

**Other Issues**:
- OAuth token theft via Copilot Studio: https://www.techradar.com/pro/security/experts-warn-microsoft-copilot-studio-agents-are-being-hijacked-to-steal-oauth-tokens
- GitHub Actions command injection: https://github.com/github/copilot-cli/issues/1099

---

### CLAUDE CODE - AI-ORCHESTRATED ESPIONAGE

**Attacker**: Chinese state-sponsored
**AI Autonomy**: 80-90% of campaign
**Capabilities**: Vulnerability research, exploit writing, credential harvesting, data categorization, backdoor creation
**Targets**: ~30 global organizations

**References**:
- https://www.anthropic.com/news/disrupting-AI-espionage
- https://fortune.com/2026/01/21/anthropic-claude-ai-chatbot-new-rules-safety-consciousness/
- https://www.nbcnews.com/tech/security/hacker-used-ai-automate-unprecedented-cybercrime-spree-anthropic-says-rcna227309
- https://bdtechtalks.substack.com/p/how-hackers-turned-claude-code-into

**Security Features**:
- Read-only default, permission-based changes
- /security-review command
- https://code.claude.com/docs/en/overview
- https://www.eesel.ai/blog/security-claude-code

**Research**: Stanford study shows developers with AI assistants "wrote significantly less secure code" while being "overconfident"

---

### GITHUB COPILOT + CLAWDBOT INTEGRATION

**Integration**: GitHub Copilot supported as Moltbot model provider
- Tokens: COPILOT_GITHUB_TOKEN / GH_TOKEN / GITHUB_TOKEN
- https://docs.molt.bot/concepts/model-providers

**Community**:
- Scott Hanselman (Microsoft VP) Windows setup: https://github.com/shanselman/clawdbot/pull/1
- Skills: https://github.com/justbecauselabs/clawd-skills
- Awesome collection: https://github.com/VoltAgent/awesome-moltbot-skills

---

## KEY TOOLS

### 1. Loki C2 Framework
- **Purpose**: Script-jacking Electron apps (VS Code, Cursor, Discord, Slack)
- **Developer**: Bobby Cook (boku7)
- **GitHub**: https://github.com/boku7/Loki
- **Method**: Replace JavaScript files with malicious code
- **Featured**: John Hammond's "I Backdoored Cursor AI" video
- **Credit**: John Hammond acknowledged as "Video Creator" in repo

### 2. Moltbot (Clawdbot)
- **Creator**: Peter Steinberger
- **Type**: Open-source personal AI assistant
- **GitHub**: https://github.com/moltbot/moltbot
- **Features**: Local-first, multi-channel (WhatsApp, Telegram, Slack, Discord)
- **Security**: CRITICAL VULNERABILITIES ACTIVE

---

## ATTACK SURFACE

1. **Electron Apps**: JavaScript replacement, no integrity checks
2. **MCP Weaknesses**: Prompt injection → RCE, auth bypasses, token theft
3. **Reverse Proxies**: Localhost auth assumptions, exposed interfaces
4. **Supply Chain**: Fake extensions, malicious MCP servers, lookalike tools
5. **Infostealers**: Targeting AI tool directories, credential harvesting
6. **Social Engineering**: Prompt injection via email/chat

---

## INTELLIGENCE GAPS

**No John Hammond Content Found For**:
- Clawdbot/Moltbot (despite massive vulnerabilities)
- MCP security (no dedicated coverage)
- Copilot Reprompt attack
- "Claude Copilot Bot" or "AI Copilot Gateway" (terms not widely used)

**Likely Future Coverage**: Given recent publicity and severity, John Hammond may cover Clawdbot/Moltbot vulnerabilities

---

## BUG BOUNTY RECOMMENDATIONS

1. **Monitor**: https://www.youtube.com/@JohnHammond for AI security content
2. **Test Vectors**:
   - Cursor workspace trust bypass
   - MCP prompt injection
   - Electron backdoor detection
   - Reverse proxy auth bypass
3. **Targets**:
   - Programs using Cursor/VS Code/Electron IDEs
   - Services implementing MCP
   - AI gateways with reverse proxies
4. **Tools**: Study Loki C2, MCP architecture, Electron security, prompt injection

---

## QUICK LINKS

**John Hammond**:
- YouTube: https://www.youtube.com/@JohnHammond
- Stats: https://vidiq.com/youtube-stats/channel/UCVeW9qkBjo3zosnqUbG7CFw/
- LinkedIn: https://www.linkedin.com/in/johnhammond010/
- Twitter: https://x.com/_JohnHammond

**Security Research**:
- Check Point, Oasis Security, Lakera, OX Security, Varonis, AIM Security, Aikido

**Documentation**:
- MCP: https://modelcontextprotocol.io/
- Moltbot Security: https://docs.clawd.bot/gateway/security
- Claude Code: https://code.claude.com/docs

---

**Report Complete** | Confidence: HIGH (confirmed findings), MEDIUM (gaps)
