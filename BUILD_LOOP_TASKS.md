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
4. [ ] **AGENT-PI-014: Frontmatter abuse in SKILL.md** — YAML frontmatter keys that auto-broaden agent behavior (`allowed-tools: *`, hidden `model:`/`bypassPermissions` style flags, suspicious `metadata` blobs).
5. [ ] **AGENT-PI-015: Memory/persistence poisoning** — instructions telling the agent to write itself into CLAUDE.md / memory files / settings.json ("add this rule to your memory/config") — self-propagation.
6. [ ] **AGENT-MCP-004: Suspicious env exfil in MCP config** — `env` block forwarding broad host secrets (AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK) to an unknown third-party server package.
7. [ ] **AGENT-MCP-005: MCP server from raw URL / gist** — command launches code from raw.githubusercontent.com, gist, pastebin, or an IP-literal URL.
8. [ ] **AGENT-N8N-002: n8n credential-node exfil pairing** — workflow that reads a credential node and posts to an external webhook in the same workflow.
9. [ ] **AGENT-PI-016: Cross-file staged payload** — skill references a companion file (`read ./helpers/notes.txt and follow it`) — flag instruction-following indirection to sibling files.
10. [ ] **Hook/command scanning** — extend scanner to `.claude/settings.json` hooks and `commands/*.md`: flag hooks that run network fetch/eval, and commands with PI rules.
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
