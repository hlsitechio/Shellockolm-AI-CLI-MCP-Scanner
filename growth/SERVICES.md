# Shellockolm Security Services

> Draft asset — review, edit pricing/identity, then publish (e.g. as a GitHub Pages
> site, a Notion page, or a section in the README). Nothing here is published yet.

**React / Next.js / npm supply-chain security audits — by the maintainer of Shellockolm.**

You ran the free scanner and it found something. These services are the human
follow-through: verifying findings, fixing them safely, and hardening the rest of
your stack against the next event-stream / xz-style supply-chain hit.

---

## Packages

### 1. Express Audit — $1,500 (fixed scope, ~3 days)
For a single app / repo.
- Full Shellockolm scan (CVEs, malware patterns, secrets, supply chain) + manual triage
- False-positive filtering — you get a report you can act on, not noise
- Prioritized findings with exploitability + business impact, not just CVSS
- 1-hour walkthrough call
- **Deliverable:** a clear remediation plan ranked by risk

### 2. Audit + Remediation — $4,500 (fixed scope, ~2 weeks)
Express Audit, plus we fix it:
- Dependency upgrades / patching with verified builds (no broken `package.json`)
- Secrets rotation guidance + leak cleanup
- CI integration so regressions get caught on every PR
- Re-scan + sign-off report (useful as vendor/customer evidence)

### 3. Hardening Retainer — $1,500/mo
Ongoing coverage for teams shipping fast:
- Monthly scan + report
- New-CVE watch on the dependencies you actually use
- Up to 4 hrs/mo of remediation or advisory
- 48-hour response on critical findings

> Price anchors only — adjust to your market and experience. Fixed-scope beats
> hourly: it sells the outcome, caps the client's risk, and protects your margin.

---

## Why this maintainer
- Built and maintains Shellockolm (CLI + MCP scanner) — deep, current knowledge of
  the React/Next.js/Node/npm/n8n threat landscape
- Focus on the JS/TS supply chain specifically — not a generalist
- Findings are explained (why it's vulnerable, what an attacker does, how to fix),
  not dumped

## What I do NOT claim
- No "zero false positives" or "100% success" guarantees — security doesn't work
  that way, and any consultant who promises it is selling you something.

---

## Book it
Email **hlarosesurprenant@gmail.com** with your repo/stack and what prompted the
scan. First reply within 48 hours.

---

### CLI footer CTA (paste into the scan summary output)
Suggested one-liner to print after a scan that finds ≥1 high/critical issue:

```
Found criticals you want fixed fast? Security audits & remediation:
hlarosesurprenant@gmail.com  ·  see growth/SERVICES.md
```
