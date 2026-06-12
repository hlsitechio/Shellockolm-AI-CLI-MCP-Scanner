# Build-Loop Task Backlog (50 tasks)

Consumed by the autonomous `shellockolm-build-loop` scheduled task. Rules:

- Work **top-down within the highest unfinished tier**; one task per run.
- Mark a task done by checking it off and appending the commit hash.
- Every scanner/detection task ships with fixtures + tests (positive cases AND a
  benign zero-false-positive baseline). Every CLI/MCP task ships with a test or a
  recorded verification command. Website tasks must pass `npm run build`.
- Guardrails from the scheduled task always apply (no deploys, no Stripe, no main).

Status legend: `[ ]` open · `[x] (hash)` done · `[~]` blocked (note why).

---

## Tier 1 — Detection engine depth (the product IS the detections)

1. [x] **AGENT-PI-011: Homoglyph/confusable spoofing** — detect mixed-script confusables (Cyrillic а/е/о inside ASCII words) in skill/instruction files used to evade keyword review. Use a small confusable map, not a full UTS#39 table. _(commit 99aa1f1)_
2. [x] **AGENT-PI-012: Markdown link/text mismatch** — link text says one domain, href is another (`[github.com/x](https://evil.tld)`) in agent artifacts; classic lure for agent auto-fetch. _(commit c2a6c57)_
3. [x] **AGENT-PI-013: HTML-comment-hidden instructions** — imperative instructions hidden inside `<!-- ... -->` blocks in skills/instruction files (invisible in rendered view, read by model). Flags a comment only when its body carries a directive cue (override/jailbreak, AI-addressed command, "note to the AI", covert "don't tell the user", exfil/execute, "from now on"); descriptive/tooling comments never trip it. Verified zero FP across 1344 real skill/instruction files. _(commit 35aecaf)_
4. [x] **AGENT-PI-014: Frontmatter abuse in SKILL.md** — structurally parses the leading YAML frontmatter and flags permission/safety-bypass flags baked into it: `bypassPermissions`, `--dangerously-skip-permissions` (anywhere in the block, incl. args lists), truthy safety toggles (`auto-approve`/`yolo`/`disable-safety`/`skip-permissions`/`no-confirm`…), and `permission-mode: bypassPermissions`-style modes. Structured parse means a `description` that only *mentions* a flag never trips it. Wildcard `allowed-tools: "*"` was deliberately NOT flagged — calibration showed it's used legitimately by tool-adaptive skills (the `model:` key likewise is legitimate and not flagged). Verified zero FP across 2728 real skill/instruction files via the live scanner. _(commit 6f4e4e3)_
5. [x] **AGENT-PI-015: Memory/persistence poisoning** — flags self-propagating injection: an artifact instructing the agent to write a directive into its own persistent standing-context store (CLAUDE.md / AGENTS.md / a memory file / .cursorrules / settings.json / "your memory/config") so it auto-loads every future session — a one-shot inject rewritten into config to become a persistent backdoor. Fires only when a "persist <self-reference> into <memory/config target>" action co-occurs (within a ~420-char window) with a self-propagation payload cue (covert "don't tell the user", an instruction override, or a "from now on always…" coercion); a notes/memory skill that merely saves user-chosen facts carries no such cue and is not flagged. Verified zero FP across ~3017 real skill/instruction artifacts via the live Pro scanner. _(commit 365fe17)_
6. [x] **AGENT-MCP-004: Suspicious env exfil in MCP config** — structurally inspects each MCP server's `env` block and flags a broad ambient host credential (AWS_ACCESS_KEY_ID/SECRET/SESSION, GITHUB/GH_TOKEN + PAT, GITLAB token, SSH_AUTH_SOCK/SSH_PRIVATE_KEY, GOOGLE_APPLICATION_CREDENTIALS/GCP/GCLOUD creds, AZURE client secret, KUBECONFIG, NPM/NODE_AUTH token, DOCKER password, CLOUDFLARE/DO/VERCEL/NETLIFY/HEROKU/HF tokens) forwarded to a server whose name/command/args/package does not relate to that credential's service. Identifies the credential by the env KEY *or* by a `${VAR}`/`$VAR`/`${env:VAR}` interpolation in the value (catches a cred renamed to an innocuous key), and uses delimited-token service association so the official integration (aws-* server ← AWS creds, github server ← GITHUB_TOKEN) is never flagged. Non-secret config (AWS_REGION, NODE_ENV) and app-scoped keys (BRAVE_API_KEY) are not in the credential map. Verified zero FP across 94 real MCP configs (27 with env blocks; correctly suppressed a real github-server ← GITHUB_TOKEN case) via the live Pro scanner; 7 new tests (3 positive incl. renamed-via-value + KUBECONFIG in desktop config, 4 benign baselines). _(commit b25a8cc)_
7. [x] **AGENT-MCP-005: MCP server from raw URL / gist** — structurally inspects each MCP server's launch path (command + args, not the env block and not a remote server's `url` transport field) and flags a URL whose host is a dedicated raw-code / paste / gist service (raw.githubusercontent.com, gist.githubusercontent.com/gist.github.com, raw/rawcdn.githack.com, pastebin.com, paste.ee, hastebin, dpaste, rentry, 0bin, ghostbin, controlc, bpa.st, ix.io, sprunge.us, paste.rs, termbin) OR a routable **public** IP literal. The code that runs is then fetched unversioned and attacker-mutable at launch (`deno run <url>`, `npx <tarball-url>`, `bunx <url>`, `uvx --from git+<rawhost>`) — a supply-chain RCE / rug-pull channel distinct from the curl|bash pipe form (AGENT-MCP-001). Public-IP detection uses `ipaddress.is_global`, so loopback / private (RFC1918) / link-local / CGNAT / documentation IPs (local dev) are excluded; the host suffix match is `.`-anchored so a lookalike (`raw.githubusercontent.com.evil.com`) is never mistaken for the trusted host; and an ordinary vendor endpoint (`https://api.vendor.com/mcp` passed to a proxy) is never flagged. Verified ZERO FP across 100 real MCP configs (190 servers; the 2 URL-bearing servers — a 127.0.0.1 loopback and a *.netlify.app vendor endpoint — correctly passed) via the live Pro scanner; 9 new tests (5 positive incl. git+https raw + public-IP literal, 4 benign baselines). _(commit 060021c)_
8. [x] **AGENT-N8N-002: n8n credential-node exfil pairing** — structurally parses the exported workflow's node list and fires on a tight credential-exfil pairing, not on mere co-occurrence (almost every real workflow uses credentials AND calls external APIs). Two zero-FP conditions: **(A) PAIRING** — a credential read (a node's `credentials` binding, or params referencing `$credentials` / `getCredentials(` / `$secrets.` / a secret-named `$env` var / a hardcoded key) co-occurs with a POST to a known out-of-band / request-capture / paste sink (webhook.site, `*.ngrok.*`, `*.oast.*`, interact.sh, burpcollaborator, dnslog, `*.requestcatcher.com`, pastebin/hastebin/paste.ee); Slack/Discord **incoming webhooks** and pipedream are deliberately excluded as legitimate notification destinations. **(B) DIRECT EMBED** — a single node ships a hardcoded high-entropy key literal (AKIA…/ghp_…/sk-…/AIza…/xox…) to a routable external host in the request itself (new coverage beyond the env-ref-only AGENT-EXFIL-003); loopback/private/`.local` destinations are excluded via `ipaddress.is_global`. Verified ZERO FP across a 15-workflow benign corpus (Stripe/GitHub/OpenAI/SendGrid/Airtable/Notion/HubSpot/Sheets credentialed API calls, DB-read + Slack & Discord incoming webhooks, pipedream, secret-named `$env` to a real API, non-secret `$env` in URL, code transforms, webhook trigger/respond) while catching all 4 malicious shapes; 8 new tests (4 positive incl. direct-embed + env-secret/oast, 4 benign baselines). _(commit 49f3060)_
9. [x] **AGENT-PI-016: Cross-file staged payload** — flags an artifact that sends the agent to a companion file and tells it to FOLLOW/OBEY the instructions inside (an obey-verb + instruction-noun pointing into the file, a bare obey-pronoun right after a read of it — "read … and follow it" — or "do what it says"). Calibration on the real corpus found the plain in-bundle form ("read forms.md and follow its instructions") is the OFFICIAL skill progressive-disclosure pattern (Anthropic's pdf / skill-creator skills), so a GATE limits firing to the exploitable subset: a SUSPICIOUS target path (parent traversal `../`, absolute / home `~` / UNC, or a hidden dot-directory) OR a covert/instruction-override cue framing the indirection (reuses the PI-015 payload cue). Data reads ("parse the apiUrl"), doc pointers ("see ./docs/setup.md for the steps"), "run it" on a script, "follow the steps below", and a suspicious path read for *data* (no obey cue) are all not flagged. Verified ZERO FP end-to-end through the live Pro scanner across 2962 skills + 62 instruction files (the 6 prior progressive-disclosure hits are now correctly suppressed); 12 new tests (7 positive incl. traversal/hidden/absolute/UNC + covert/override framing, 5 benign baselines incl. the official in-bundle pattern). _(commit 5e6cfd8)_
10. [x] **Hook/command scanning** — extends the agent scanner to two new artifact classes. **(A) `.claude/settings.json` / `settings.local.json` `hooks`** — shell commands the agent auto-runs on lifecycle events with no per-invocation prompt (a zero-click RCE/exfil channel in a cloned repo). Hook commands are extracted STRUCTURALLY (only string values under a `command` key, so `matcher`/`type`/event metadata is never misread) and only unambiguously dangerous shapes fire — never a plain prettier/eslint/pytest/git hook: `AGENT-HOOK-001` (CRITICAL) download-and-execute (curl|bash, PowerShell Net.WebClient/DownloadString+iex cradle, certutil/bitsadmin LOLBIN), `AGENT-HOOK-002` (HIGH) obfuscated exec (encoded PowerShell `-enc`/`-ec`, base64-decode|shell, atob/FromBase64String→eval), `AGENT-HOOK-003` (HIGH) out-of-band exfil (webhook.site/`*.ngrok.*`/`*.oast.*`/interact.sh/pastebin), plus reused `AGENT-DESTRUCT-001` for auto-running destructive hooks. Scoped to files inside a `.claude` tree so `.vscode/settings.json` etc. are ignored. **(B) `.claude/commands/**/*.md` slash commands** — a command body becomes a prompt the agent runs, so it gets the full high-precision structural/stealth suite + unambiguous malicious-content rules, but EXCLUDES the broad NL heuristics (PI-002/PI-006/PRO-001/PRO-002/DESTRUCT) that legit command prose trips. Skills/instructions/commands now share one `_scan_text_artifact` path. Verified ZERO FP across 916 real marketplace command files (incl. official Anthropic commands) + 35 real `.claude` settings files via the live Pro scanner; 36 new tests (positive hook/command shapes, structural-extraction, `.claude`-scoping, benign baselines for every calibrated-out case), full suite 185 green. _(commit ff78be7)_
11. [ ] **AGENT-SECRET-002: broaden secret patterns** — add Stripe (sk_live_), Supabase service_role JWT shape, OpenAI sk-, Telegram bot tokens, Discord bot tokens, with redaction in findings.
12. [ ] **Severity-context boost** — raise severity one notch when a PI finding co-occurs with an exfil sink in the same file (composite scoring in finalize step).
13. [ ] **AGENT-PI-017: Tool-output injection markers** — fake `<tool_result>`/`<function_results>`/`<system-reminder>` blocks embedded in artifacts to spoof harness output.
14. [ ] **Allowlist/ignore support for agent-scan** — respect `.shellockolmignore` rule IDs per path so teams can suppress accepted findings (reuse ignore_handler).
15. [ ] **Confidence field on findings** — add `confidence: high|medium|low` to AgentRule + ScanFinding, surface in output, let `--min-confidence` filter.

## Tier 2 — CLI tool experience

16. [ ] **`shellockolm agent-scan --json`** — stable machine-readable JSON output (schema documented in README) for CI pipelines.
17. [ ] **SARIF output for agent-scan** — wire agent findings into the existing sarif_output.py so GitHub code scanning can ingest them.
18. [ ] **Exit-code contract** — documented exit codes (0 clean, 1 findings, 2 error) + `--fail-on critical|high|...` threshold flag; tests for each.
19. [ ] **`--diff` mode** — scan only files changed in git (staged or vs a ref) for fast pre-commit use.
20. [ ] **Pre-commit hook integration** — ship a `.pre-commit-hooks.yaml` so `pre-commit` users can add shellockolm in one block; document it.
21. [ ] **GitHub Action** — `action.yml` wrapping the scanner (checkout → scan → SARIF upload), with README usage snippet.
22. [ ] **Rich/terminal table output polish** — group findings by file, color by severity, summary footer; degrade gracefully when not a TTY.
23. [ ] **`shellockolm rules list`** — command that prints all rule IDs, severity, tier (free/pro), and one-line description; doubles as docs.
24. [ ] **`--explain RULE-ID`** — print full description, example attack, remediation for any rule.
25. [ ] **Baseline file support** — `--baseline baseline.json` writes/compares findings so CI only fails on NEW findings.
26. [ ] **Quick benchmark + perf guard** — script timing a scan over a large fixture tree; precompile/regex-pass optimization if >2s; record numbers in docs (real, measured).
27. [ ] **Windows path/encoding hardening pass** — fixtures with UTF-16/BOM files, long paths, reparse points; assert no crashes (errors collected, scan continues).
28. [ ] **`shellockolm doctor`** — environment self-check (python version, db freshness, license status, write perms) with actionable output.
29. [ ] **Config file** — support `shellockolm.toml` (or `[tool.shellockolm]` in pyproject) for default paths, ignores, thresholds.
30. [ ] **Progress + summary stats** — file/scanner counts and elapsed time in scan footer (already partially in stats; surface it consistently).

## Tier 3 — MCP server tooling (agent-native distribution)

31. [ ] **MCP tool: `scan_agent_artifacts`** — expose agent-scan through the MCP server with path arg + structured findings; this is the flagship "agents scanning agents" feature.
32. [ ] **MCP tool: `explain_finding`** — given a rule ID or finding, return the why/impact/remediation explainer.
33. [ ] **MCP tool: `scan_text`** — scan a raw string (e.g., a skill the agent is about to install) without touching disk.
34. [ ] **MCP server self-test** — pytest that spins the MCP server over stdio and exercises each tool end-to-end (no live network).
35. [ ] **MCP install docs** — one-paste configs for Claude Code, Claude Desktop, Cursor, Windsurf in README + website.
36. [ ] **MCP tool: `check_mcp_config`** — scan the caller's own mcp.json paths (well-known locations per OS) on request.
37. [ ] **Pro gating in MCP** — Pro rules respected identically through MCP path; test that free tier still returns free findings.
38. [ ] **MCP rate/size safety** — cap scan_text input size, bound directory walk time, return partial-result warnings instead of hanging.

## Tier 4 — Quality, trust, and tests

39. [ ] **Fixture corpus** — `tests/fixtures/` tree of real-shaped malicious + benign artifacts (skills, mcp.json variants, n8n exports, CLAUDE.md) used by all detection tests; include README explaining each.
40. [ ] **False-positive regression suite** — scan a vendored set of popular legit skills/configs (anthropic skills repo samples) and assert zero CRITICAL/HIGH findings.
41. [ ] **Coverage gate** — add pytest-cov threshold (start at current %, ratchet up); wire into CI.
42. [ ] **CI workflow** — GitHub Actions: lint (ruff), tests on 3.10–3.14, Windows + Linux matrix.
43. [ ] **Self-scan in CI** — run shellockolm against its own repo every CI run; fail on new HIGH+ (dogfooding badge material — only claim it once true).
44. [ ] **Property tests for redaction** — hypothesis tests asserting secrets never appear unredacted in finding output.
45. [ ] **Type-check pass** — mypy (or pyright) clean on src/scanners + licensing; add to CI.

## Tier 5 — Docs & revenue-readiness (no fabricated claims)

46. [ ] **RULES.md** — auto-generated rule reference (from `rules list`) committed to repo and linked from README/website.
47. [ ] **Threat-model doc** — one page: the agentic supply-chain threat model and exactly which rule covers which attack class (maps to marketing honestly).
48. [ ] **Pro tier page accuracy pass** — website Pro feature list matches actually-shipped Pro rules/features; remove/flag anything not yet real.
49. [ ] **Quickstart GIF/asciinema + 60-second README path** — install → scan → finding in three commands; verify commands actually work as written.
50. [ ] **CHANGELOG.md + version bump discipline** — backfill changelog from git history, adopt keep-a-changelog format, bump version with each batch.

---

Completed prior to this backlog (context): AGENT-PI-001…010, MCP structured scan,
webhook/paste exfil, server-authoritative licensing, CLI menu/README agent-scan surfacing.
