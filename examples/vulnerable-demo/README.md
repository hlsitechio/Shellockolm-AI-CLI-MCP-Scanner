# `vulnerable-demo` — intentionally vulnerable demo project

> ⚠️ **This project is deliberately insecure. Do not deploy it or copy its
> dependencies into a real app.** It exists only so the Shellockolm
> [60-second quickstart](../../README.md#-install--run-in-60-seconds) has a
> target that produces a real, reproducible finding.

It is a minimal Next.js `package.json` pinned to **`next@15.2.2`**, a version
affected by **[CVE-2025-29927](https://github.com/advisories/GHSA-f82v-jwr5-mffw)**
(Next.js middleware authorization bypass, CVSS 9.1, CRITICAL).

Scan it from the repo root:

```bash
shellockolm scan examples/vulnerable-demo
```

Shellockolm reports the bypass and exits non-zero (findings gate the build):

```
🚨 VULNERABILITIES DETECTED

┌─ CVE-2025-29927: Next.js Middleware Authorization Bypass
│  File: examples/vulnerable-demo/package.json
│  Package: next @ 15.2.2
│  Fix: 15.2.3
│  CVSS: 9.1 | Difficulty: Trivial
│  Production code - ACTION REQUIRED
└─ Upgrade next to 15.2.3
```

Bumping `next` to `15.2.3` (or later) removes the finding — that is the fix the
scanner recommends, and the way to confirm the scanner stops flagging a patched
project.

This directory is **not** an AI-agent artifact (no `SKILL.md`, `mcp.json`,
`CLAUDE.md`, hooks, …), so the repo's agent-only self-scan CI gate
(`scan -s agent --fail-on high`) does not flag it.
