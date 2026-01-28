# OSINT REPORT: AI Gateway and Coding Assistant Security Research

**TARGET:** AI Coding Bots/Gateways with Known Security Issues  
**COLLECTION_DATE:** 2026-01-27  
**INTELLIGENCE TYPE:** Open Source Intelligence (OSINT)  
**CLASSIFICATION:** UNCLASSIFIED

---

## EXECUTIVE SUMMARY

This report identifies 15 AI coding assistants and gateways with known security vulnerabilities. The most critical finding is **Moltbot/Clawdbot** with hundreds of exposed instances discoverable via Shodan, followed by multiple CVEs in **LiteLLM**, **Open WebUI**, and **NextChat**.

**HIGH-RISK TARGETS:**
1. Moltbot/Clawdbot - Hundreds of exposed instances with leaked credentials
2. LiteLLM - Multiple CVEs including API key leakage (CVE-2025-0330)
3. Open WebUI - Critical RCE vulnerability (CVE-2025-64496)
4. NextChat - Critical SSRF vulnerability (CVE-2023-49785, 7,500+ exposed instances)
5. LibreChat - Multiple authorization bypass CVEs

See full detailed report below.
