# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Older history (2.0.0 and earlier) lives in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## [Unreleased]

### Fixed

- **`AGENT-PI-002` false positives on a skill's own activation docs** — the
  low-confidence hidden-conditional-trigger heuristic no longer fires when its
  "when the user does X" match sits where a skill legitimately *advertises* when
  it applies: the YAML `description:` field (the official format's activation
  contract, incl. documented `description:` examples shown inside a ```yaml
  fence) or a "When to use" section. A genuine covert trigger in ordinary body
  prose still fires, and a malicious description's action clause is still caught
  by the high-confidence rules (PI-001/PI-003/PI-006/EXFIL/DESTRUCT). Drops the
  legit-corpus PI-002 false-positive count from 13 to 0.

## [3.1.0] - 2026-06-22

The first open-core feature batch since the 3.0.0 packaging fix — additive
throughout: the OSS core stays free and MIT, and Pro remains a strictly
additive, license-gated detection rule pack. Highlights:

- **Detection depth** — the agent supply-chain scanner gained new
  prompt-injection, MCP, n8n, hook, and secret rules, plus a `confidence` axis
  and composite-severity scoring (see `RULES.md` / `THREAT_MODEL.md`).
- **CI-grade CLI** — `--json`, `--sarif`, a documented `--fail-on` exit-code
  contract, `--diff`, `--baseline`, `--table`, a discoverable `shellockolm.toml`
  config file, and new `rules list|explain` + `doctor` commands, plus a
  pre-commit hook and a GitHub Action.
- **Agent-native MCP** — four new tools (`scan_agent_artifacts`, `scan_text`,
  `explain_finding`, `check_mcp_config`), a real stdio self-test, and per-tier
  Pro gating + input rate/size safety.
- **Trust hardening** — a fixture + false-positive regression corpus, a
  ratcheting coverage floor, build-blocking ruff and strict-mypy gates, a
  dogfooding self-scan in CI, and generated, drift-checked docs.

### Added
- **60-second quickstart with a real, reproducible finding.** A bundled,
  intentionally-vulnerable demo project (`examples/vulnerable-demo/`, a Next.js
  `package.json` pinned to `next@15.2.2`) gives the quickstart a target that
  deterministically reports **CVE-2025-29927** (middleware authorization bypass,
  CVSS 9.1) and exits non-zero — so the README's *install → scan → finding in
  three commands* path (`pip install -e .` → `shellockolm scan
  examples/vulnerable-demo` → `shellockolm info CVE-2025-29927`) produces a real
  result, not a placeholder. The demo is not an agent artifact, so the agent-only
  self-scan CI gate still passes. An asciinema recording of the session
  (`docs/quickstart.cast`) is generated drift-proof by
  `scripts/generate_quickstart_cast.py` (with a `--check` CI gate), and
  `tests/test_quickstart.py` (14 tests) runs the documented commands through the
  real CLI to prove they work exactly as written.

### Changed
- **README + `docs/QUICKSTART.md` quickstart now uses the installed `shellockolm`
  console script** (not `python src/cli.py`) and shows the **real** scanner output.
  The old QUICKSTART "example output" was fabricated — it invented "3
  vulnerabilities" and mislabelled CVE-2025-29927 as *HIGH* when the tool reports
  it *CRITICAL (CVSS 9.1)*; it's replaced with the verified finding text.

### Fixed
- **Three latent `UnboundLocalError`/`NameError` crashes in the interactive CLI menu,
  surfaced by the new ruff lint gate.** In the large interactive-menu function, a
  module-level name was shadowed by a redundant *local* re-import/assignment further down
  the same scope, which makes Python treat the name as local throughout — so the earlier
  use raised `UnboundLocalError` whenever that menu path ran: `re` (a redundant local
  `import re`), `Panel` (a redundant local `from rich.panel import Panel`), and the
  `scanners` command (a local `scanners = get_all_scanners()` that shadowed the command
  function called earlier). The redundant locals were removed and the shadowing variable
  renamed; all three now resolve to their module-level definition. Also fixed a missing
  `Dict` import (`cli.py` annotated four functions with `Dict[...]` without importing it —
  a `NameError` under `typing.get_type_hints()`).
- **MCP resource reads no longer error over the real transport.** The server's
  `read_resource` callback was typed `uri: str` and called string-only methods
  (`uri.startswith("cve://")`, `uri.replace(...)`), but the MCP framework hands that
  callback a parsed pydantic **`AnyUrl`** when a client reads a resource over stdio — so
  every transport-level `cve://…` read failed with `'AnyUrl' object has no attribute
  'startswith'`. (The internal `get_cve_info` tool was unaffected because it calls the
  handler with a plain string.) The handler now coerces `uri` to `str` up front, so both
  callers work. Surfaced by the new MCP server self-test, which is the first thing to
  exercise the resource path through the genuine client⇆server transport.
- **Packaging: pure CLI-helper modules are now installed.** `diff_scan`, `baseline`, and `doctor`
  (added in earlier build-loop tasks) were imported by `cli` but missing from `[tool.setuptools]`
  `py-modules`, so a `pip install` would build a package whose `shellockolm` console script fails to
  import (`ModuleNotFoundError`). All three — plus the new `config_file` — are now listed, and added
  to the smoke-import test net. (In-tree test runs were unaffected because `conftest.py` puts `src/`
  on `sys.path`; the gap only bit an installed package.)
- **Windows path/encoding hardening — UTF-16/BOM artifacts no longer evade the agent
  scanner, and a benign BOM no longer false-positives.** Skills, MCP configs, and
  instruction files were read as UTF-8 with `errors="ignore"`, so a malicious artifact
  saved as **UTF-16** (routine from Windows Notepad's "Unicode" save or PowerShell
  `Out-File`/`>`) decoded to garbled, NUL-interleaved text that matched **no** rule —
  a complete detection bypass (confirmed: a UTF-16 instruction-override skill scored
  0 findings vs. 2 in UTF-8). Conversely a benign **UTF-8-BOM** file leaked a leading
  `U+FEFF` that the invisible-character rule (AGENT-PI-005) flagged as smuggling — a
  false positive. A new `_decode_bytes` now detects the byte-order mark (UTF-8/16/32,
  longest match first), strips it, and decodes with the right codec, with a NUL-density
  heuristic for BOM-less UTF-16; detections now fire identically across UTF-8/UTF-16
  LE+BE/UTF-32/BOM, and the BOM false positive is gone. Verified a **strict no-op on
  the real `~/.claude/skills` corpus** (187 findings, byte-identical; 0 read errors).
- **Unreadable artifacts are collected, not silently swallowed; the scan always
  continues.** A long path, locked file, reparse-point, or permission error during
  read is now recorded in `result.errors` (capped at 50) instead of being dropped, so
  a skipped file is visible rather than masquerading as clean. A missing scan path
  already reported an error; this extends the same contract per-file.
- **Directory reparse-point loop protection (symlinks *and* Windows junctions).** The
  walker now skips directory reparse points, which could otherwise loop back into the
  tree and report the same finding repeatedly (a self-referential junction inflated one
  skill's findings 5×) or escape the scan root. `Path.is_symlink()` alone misses
  Windows junctions, so the check also inspects the lstat reparse-point attribute. File
  symlinks are still followed. 28 new tests (`tests/test_windows_hardening.py`: per-BOM
  decode units, malicious detected in every encoding, benign zero-FP in every encoding,
  the AGENT-PI-005 BOM regression, read-error collection + cap, and a real
  junction/symlink loop that completes without crashing and counts the finding once);
  full suite **484 green** (was 456).

### Added
- **CI: mypy static type-check gate over the detection-critical core.** A dedicated,
  **build-blocking** `typecheck` job in `.github/workflows/ci.yml` runs `mypy` on every CI
  run, and the checked surface — the modular scanners (`src/scanners`, where the agent
  supply-chain rules live) and the server-authoritative licensing client
  (`src/licensing.py`) — is now **clean at strict settings** (`disallow_untyped_defs`,
  `warn_return_any`). Scope, import resolution, and strictness are the single source of
  truth in `[tool.mypy]` in `pyproject.toml` (`mypy_path = "src"` resolves the project's
  flat imports from the repo root; `follow_imports = "silent"` keeps the gate scoped to the
  target files), so CI and a local bare `mypy` enforce exactly the same gate. Like the
  ruff/coverage gates, the checked surface is a **ratchet** — widened over time, never
  narrowed. Getting to clean fixed **65 real type errors** with genuine fixes (no blanket
  `# type: ignore`): widening `create_finding(file_path=…)` to `str | Path` (it already
  `str()`-converts internally), annotating the per-scanner vulnerability tables
  (`PACKAGE_VULNERABILITIES`/`COMPROMISED_PACKAGES`/`VULNS`) so their entries stop typing as
  `object`, restoring the `quick_mode` parameter on three subclass `scan_directory`
  overrides that had dropped it (an LSP break), widening `ScanResult.stats` to the
  free-form `Dict[str, Any]` it actually is (it holds string metadata like `min_confidence`
  alongside int counts), making `parse_package_json` return `None` for a non-object
  top-level JSON, and rewriting an `object`-typed dedup that used `set.add()`'s return value
  in a comprehension. Behaviour is unchanged (full suite green before and after). A 7-test
  contract suite (`tests/test_type_check.py`, stdlib-only config/workflow parsing so it
  collects on every supported Python) asserts the wiring can't silently rot — mypy is a dev
  dependency, the core scope + `mypy_path` + strictness flags are present, the `typecheck`
  job is build-blocking — and, the real proof, that the committed core passes its own gate
  **and** that the gate has teeth (an int/str return mismatch fails under the repo config).
  Full suite **870 green** (was 863).
- **CI: self-scan (dogfooding) gate — shellockolm scans its own repo.** A dedicated,
  **build-blocking** `self-scan` job in `.github/workflows/ci.yml` runs the flagship agent
  supply-chain scanner against this repository on every CI run and fails the build on any
  **HIGH/CRITICAL** finding in a real agent artifact (`shellockolm scan -s agent --fail-on
  high .`), writing a JSON + SARIF report as an artifact. A committed `shellockolm.toml`
  excludes ONLY the deliberate detection corpus under `tests/fixtures/` (intentionally
  malicious/benign test data the detection suite asserts on, not real threats) — and only
  `ignore`, so a contributor's plain `shellockolm scan .` is never silently narrowed; the
  excluded count is always announced. The gate is currently green: a self-scan reports
  **zero** HIGH+ findings across the repo's real artifacts (42 agent items scanned, 36
  fixture findings correctly excluded), so the "we scan ourselves" claim is true before
  it's made. Agent-only keeps the gate deterministic and fully offline (bundled rules, no
  live CVE feed), so a red build always means a genuine regression. A 9-test suite
  (`tests/test_self_scan.py`) asserts the job wiring (agent scanner, build-blocking,
  `--fail-on high` ∈ the CLI's accepted choices), the config excludes the fixtures without
  pinning `scanner`/`fail_on`, and — the real proof — that the repo is clean at HIGH+ today
  **and** that the exclusion is load-bearing (without it the fixtures trip HIGH+ → exit 1,
  so the gate is never vacuously green). Full suite **856 green** (was 847).
- **CI: ruff lint gate + Python 3.10–3.14 test matrix.** The test job now runs across
  the full supported interpreter range (`3.10`, `3.11`, `3.12`, `3.13`, `3.14`) on the
  existing Windows + Linux matrix. A dedicated, **build-blocking** `lint` job runs
  `ruff check src`, replacing the prior non-blocking flake8 + black steps. The rule
  selection and the deferred-backlog `ignore` list live in exactly one place —
  `[tool.ruff.lint]` in `pyproject.toml` (shared by CI and a local `ruff check src`) — so
  the gate can't drift. It enforces the high-signal correctness families (`E`/`F`/`W`)
  clean; the genuine-bug codes (undefined names `F821`/`F823`, redefinitions, syntax
  errors) are never ignored, while a pre-existing cosmetic backlog (line length,
  whitespace, placeholder-less f-strings, unused imports, the CLI's intentional deferred
  imports) is explicitly deferred and ratcheted down over time — never up. `ruff` is now
  a `dev` dependency and the 3.13/3.14 classifiers were added. A 9-test contract suite
  (`tests/test_ci_workflow.py`) asserts the matrix coverage, the blocking ruff job, the
  single-source-of-truth config, that the enforced bug codes stay un-ignored, and (when
  ruff is installed) that the committed `src/` passes its own gate.
- **Coverage gate wired into CI.** A non-regression floor on line coverage over `src/`,
  enforced by a dedicated, build-blocking `coverage` job in `.github/workflows/ci.yml`
  (`pytest tests/ --cov=src --cov-report=term-missing --cov-report=xml`). The threshold
  lives in exactly one place — `[tool.coverage.report] fail_under` in `pyproject.toml`
  (read by both CI and local `pytest --cov=src` runs) — so it can't drift. Current
  measured coverage is **30.2%** across the suite; the floor starts at **28%** (a small
  cushion below the measured value to absorb platform/interpreter variance — a handful of
  tests are Windows-only and skip on the Linux coverage job) and is ratcheted **up** as
  real coverage grows, never down. The legacy CLI/GUI/scanner-shim modules dominate the
  denominator and are largely untested; the agent detection engine and the CLI-helper
  modules it ships already sit at 93–100%. `coverage` is intentionally kept **out** of the
  default pytest `addopts`, so the suite still runs with `pytest-cov` absent. A new
  `tests/test_coverage_gate.py` contract suite (7 tests, stdlib-only file parsing so it
  collects on every supported Python) asserts the wiring stays intact — the `fail_under`
  threshold is declared and not gutted below the established floor, CI runs `--cov=src` in
  a step that can actually fail the build (no `continue-on-error`), and `pytest-cov`
  genuinely enforces `fail_under` here (an isolated subprocess proves an unreachable floor
  exits non-zero). **Also added `pyyaml` to the `dev` extras**: the existing workflow
  contract tests (`test_github_action.py`, `test_pre_commit_hooks.py`) import `yaml`
  unguarded, but PyYAML was never declared, so a clean `pip install .[dev]` left the suite
  unable to collect — declaring it makes the gate (and the rest of the suite) reproducibly
  green in CI. (Full suite **838 green**, was 831.)
- **Committed detection-test fixture corpus** (`tests/fixtures/`). A tree of real-shaped,
  defanged agent artifacts — skills, MCP configs, n8n exports, `CLAUDE.md` instruction files,
  `.claude` slash commands, and Claude Code `settings.json` — each labelled `malicious` or
  `benign` in a machine-readable `manifest.json` (schema_version 1.0). A new
  `tests/test_fixture_corpus.py` consumes the manifest and enforces the corpus contract per
  fixture: malicious fixtures must trip every rule ID they declare (a *subset* check), benign
  fixtures must produce **zero** findings at **both** the free and Pro tier, and the manifest
  stays in sync with the on-disk tree (no undocumented files). The corpus doubles as a living,
  self-describing regression net — a calibration change that breaks a detection or introduces a
  false positive now fails a named test. `.gitignore`'s blanket `fixtures/` rule is narrowed so
  this corpus under `tests/` is tracked while ad-hoc local `fixtures/` dirs stay ignored. A
  README documents the layout and every fixture. (64 new tests; full suite 778 green, was 714.)
- **MCP rate/size safety — a hostile or accidental giant input can no longer hang an agent's
  tool call.** Two complementary caps, both surfacing **partial-scan warnings** instead of blocking:
  (1) `scan_text` (and every in-memory caller) now bounds its input at `MAX_TEXT_CHARS`
  (1,000,000 chars); a larger string is truncated to the cap — the head, where frontmatter and the
  opening injection prose live, is still scanned — and the cut is announced, never silent. (2)
  `scan_directory` gained an optional `time_budget` (seconds): the directory walk is now iterated
  **lazily** (the previous eager `list(...)` materialization was itself the hang on a huge tree) and
  the deadline is checked before each candidate file, so a pathological/looping tree stops at the
  budget with a partial result rather than blocking. The `scan_agent_artifacts` MCP tool applies a
  **120 s default** budget (override per-call; `0` = unbounded for a deliberate full local scan);
  the CLI default stays unbounded (`time_budget=None`), so existing behavior is unchanged. A new
  `ScanResult.warnings` channel (distinct from per-file read `errors`) carries the notices through to
  the structured payload (`summary.partial` / `summary.warnings`) and the human-readable tool output.
  28 new tests (`tests/test_mcp_rate_size_safety.py`: truncation + head-still-scanned, the
  zero-false-partial baseline on a normal input, lazy-walk timeout via a deterministic fake clock,
  `time_budget` boundary validation, and the `partial`/`warnings` contract end-to-end through both
  agent MCP tools).
- **Pro-gating regression suite for the MCP path — the open-core invariant is now CI-locked.**
  A new `tests/test_mcp_pro_gating.py` proves that Pro rules are gated identically through the MCP
  server as on the CLI: the agentic tools (`scan_agent_artifacts`, `scan_text`, `check_mcp_config`)
  construct `AgentSupplyChainScanner()` with **no** `pro=` argument, so the active license alone
  decides — and the headline guarantee, **the free tier still returns every free finding**, holds
  regardless. The 11 tests drive the real async `handle_call_tool` entry point (where the scanner is
  built internally, not handed an explicit tier) over a single artifact that trips exactly one FREE
  rule (a smuggled `AGENT-PI-007`) and one PRO rule (`AGENT-PRO-003` context exfiltration), and
  assert: free → only the free finding (Pro rule absent, `scan.pro=false`); Pro → free **plus** the
  Pro rule (`scan.pro=true`, finding `tier="pro"`); Pro gating is **strictly additive** (the free id
  set is a proper subset of the Pro set, the only delta being genuine pro-tier rules — Pro never
  drops or rewrites a free finding); the MCP handler's finding set is **byte-identical** to a
  directly license-pinned `AgentSupplyChainScanner(pro=…)` at both tiers; and no free-tier scan
  across any of the three tools ever leaks a `tier="pro"` finding. The license is forced offline by
  replacing `licensing.LicenseManager` with a fake (the scanner re-reads that module attribute on
  each construction), so the result never depends on the host's real license file, env var, or
  network. Full suite **695 green** (was 684).
- **MCP tool `check_mcp_config` — audit the agent's OWN installed MCP configs (the 12th tool).**
  Scans the well-known MCP-server config locations per OS — Claude Desktop
  (`%APPDATA%\Claude\…` / `~/Library/Application Support/Claude/…` / `~/.config/Claude/…`),
  Claude Code (`~/.claude.json`), Cursor (`~/.cursor/mcp.json`), Windsurf
  (`~/.codeium/windsurf/mcp_config.json`), VS Code (`…/Code/User/mcp.json`), plus this project's
  `.mcp.json` / `mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` — for a poisoned server entry:
  code fetched from a raw-paste URL or public IP (AGENT-MCP-005), a broad host credential forwarded
  to an unrelated server (AGENT-MCP-004), a `curl|bash` launcher (AGENT-MCP-001), an unpinned remote
  package (AGENT-MCP-002), or a hardcoded secret. Reports which configs exist, which were scanned,
  and any structured findings + a stable `schema_version` 1.0 JSON document (the same per-finding
  shape as `scan_agent_artifacts`). Each existing file is routed through the agent scanner's
  structured MCP path regardless of its actual filename, so a config not literally named `mcp.json`
  (`~/.claude.json`, Windsurf's `mcp_config.json`) is still parsed for `mcpServers` entries. It is
  **read-only** (never modifies a config), bounds each read at 5 MB (a runaway `~/.claude.json` is
  marked `skipped`, never a silent gap), and any matched secret is redacted in the output. The
  candidate-location enumeration lives in a pure, exhaustively-tested `src/mcp_config_locations.py`
  (mirrors the `diff_scan`/`baseline`/`doctor`/`config_file` split — no filesystem access, fully
  parameterized by `system`/`home`/`env`/`project_root`). Pro rules are gated by the active license
  exactly as on the CLI. Args: `path` (project root, default cwd), `include_user`, `include_project`,
  `min_confidence`. Verified live against the real machine's configs (correctly surfaced a CRITICAL
  secret-in-URL and HIGH hardcoded credentials, both redacted). 26 new tests
  (`tests/test_mcp_check_config.py`: per-OS location enumeration incl. APPDATA fallback + de-dup, the
  disk-probing scan incl. absent/oversize/forced-mcp-path, the payload contract + CRITICAL→INFO
  ordering, the markdown/JSON formatter, tool registration, and every e2e error path) + the live
  stdio self-test now exercises it as the 12th tool. Full suite **684 green** (was 656).
- **MCP server self-test — the client⇆server stdio transport is now covered by CI.** A new
  `tests/test_mcp_server_selftest.py` launches `src/mcp_server.py` as a **subprocess** and drives it
  through the genuine MCP JSON-RPC **stdio** transport exactly as an AI client would (Claude Code /
  Desktop / Cursor / Windsurf): `initialize` → `list_tools` → `call_tool` for **all 11 tools** →
  `list_resources` / `read_resource`. This is the pytest-native promotion of the previously manual
  `tests/mcp_live_check.py` script, so the full handshake — not just the in-process handler functions —
  is exercised on every run. It is offline by construction: each scanning tool runs against a tiny
  **local** temp fixture (a vulnerable `package.json` and a malicious/benign `SKILL.md`), and `scan_live`
  is probed with a `127.0.0.1` loopback URL that the SSRF guard rejects *before* any socket opens. The
  server is spawned once (a module-scoped fixture captures every response); 18 granular tests assert
  per-tool behavior — CVE detection (`quick_scan`→CVE-2024-21508, `scan_directory`→CVE-2025-29927, both
  scanner-pinned for determinism), agent supply-chain detection + a zero-finding benign baseline,
  `explain_finding` resolving both a rule id and a CVE id, the SSRF block, and the exact 11-tool surface.
  Full suite **656 green** (was 638). _(This is also what surfaced the `read_resource` AnyUrl fix above.)_
- **MCP tool `scan_text` — vet a raw artifact string in-memory, no disk I/O.** The in-memory sibling
  of `scan_agent_artifacts`: pass the raw **text** of an artifact the agent is *about to install or
  paste* — a skill / `SKILL.md`, an `mcp.json` config, an instruction file
  (`CLAUDE.md`/`AGENTS.md`/`.cursorrules`), an n8n workflow export, a `settings.json` hooks block, or a
  slash command — and get back the same **structured findings** (rule id, severity, confidence, attack
  class, line, remediation) + stable `schema_version` 1.0 JSON document, *before the content ever
  touches disk*. The new `AgentSupplyChainScanner.scan_text()` routes the string to the right detection
  path; `artifact_type` selects it explicitly (`skill`/`instructions`/`command`/`mcp`/`n8n`/`settings`)
  while the default `auto` infers it from an optional `filename` hint, then from the content shape
  (valid JSON with `mcpServers` → mcp, with `nodes`+`connections` → n8n, otherwise prose → skill).
  Composite-severity boosting and the `min_confidence` filter run exactly as in `scan_directory`;
  rule-ID `.shellockolmignore` suppression is intentionally skipped (there is no on-disk ignore tree
  for a string). It reuses the flagship `build_agent_scan_payload` so `scan_text` and
  `scan_agent_artifacts` share one contract (plus an additive `scan.artifact_type` showing what `auto`
  resolved to); a missing/blank `text`, an unknown `artifact_type`, and an invalid `min_confidence` are
  clear errors, never a silently-wrong scan. Verified end-to-end over the real stdio transport
  (`tests/mcp_live_check.py` now also vets a smuggled skill string in-memory) and with 24 new tests
  (`tests/test_mcp_scan_text.py`: per-kind routing, `auto` classification by filename + content, bytes
  input, the no-disk-I/O guarantee, the `min_confidence` filter, the ValueError boundary, tool
  registration, and end-to-end handler runs for malicious skill/MCP text, a benign baseline, and every
  error path). Full suite **638 green** (was 614).
- **MCP tool `scan_agent_artifacts` — the flagship "agents scanning agents" feature.** The agent
  supply-chain scanner is now exposed directly through the MCP server as a dedicated tool, so an AI
  agent can vet a skill, MCP server, or repo mid-session — *before* installing or trusting it — and
  get back **structured findings**: each finding carries the `AGENT-*` rule id, severity, confidence,
  **attack class** (prompt-injection / mcp / n8n / hooks / secrets / …), **tier** (free/pro),
  `cvss_score`, the `file:line` locator, and remediation, plus a stable `schema_version` 1.0 JSON
  document (`build_agent_scan_payload`) that mirrors the CLI's `scan --json` shape. Covers every
  agent artifact class the CLI does — `SKILL.md` skills, `mcp.json` configs, n8n workflow exports,
  slash commands, `settings.json` hooks, and `CLAUDE.md`/`AGENTS.md`/`.cursorrules` instruction
  files — and accepts `recursive`, `max_depth`, `min_confidence` (`low|medium|high`), and
  `quick_mode` arguments. Pro rules are gated by the active license through the MCP path exactly as
  on the CLI (free tier still returns every free finding); invalid `min_confidence`/`max_depth` and a
  missing path are clear errors, never a silently-wrong scan; the embedded JSON is `ensure_ascii` so
  an invisible-Unicode injection payload stays pipe-safe. Verified end-to-end over the real stdio
  transport (`tests/mcp_live_check.py` now also exercises it) and with 16 new tests
  (`tests/test_mcp_agent_scan.py`: payload shape + CRITICAL→INFO ordering + zero-FP benign baseline +
  ASCII-safety, the markdown/JSON formatter, tool registration, and end-to-end handler runs for a
  malicious skill, a raw-URL MCP config, a single-file path, and every error path). Full suite
  **593 green** (was 577).
- **MCP tool `explain_finding` — the why/impact/remediation explainer over MCP.** The companion to
  `scan_agent_artifacts`: given a rule ID (`AGENT-PI-013`, `AGENT-MCP-004` — from an agent-artifact
  scan) **or** a tracked CVE ID (`CVE-2025-29927` — from a dependency/malware scan), it returns the
  full explainer — severity/tier/confidence/attack-class/CVSS, the description, a concrete **example
  attack**, and the remediation — plus a stable `schema_version` 1.0 JSON document
  (`build_explain_payload`). It is the MCP analog of the `shellockolm rules explain <id>` CLI command,
  and a single entry point for both finding families the scanner emits: agent rules resolve through
  the shared `agent_rule_explain` catalog (no drift between MCP and CLI), CVEs through the bundled
  vulnerability database. The ID is case-insensitive and whitespace-tolerant; a missing/blank id and
  an unknown id are clear errors (never a silently-empty explainer); the embedded JSON is
  `ensure_ascii` so unicode-heavy rule prose stays pipe-safe. Verified end-to-end over the real stdio
  transport (`tests/mcp_live_check.py` now resolves both a rule and a CVE) and with 21 new tests
  (`tests/test_mcp_explain_finding.py`: resolver shape for rules + CVEs, case-insensitivity,
  every-rule-resolves coverage, unknown/boundary → None, the markdown/JSON formatter, ASCII-safety,
  tool registration, and end-to-end handler runs incl. every error path).
- **Scan-volume stats in the footer — items scanned + scanners run, surfaced consistently.**
  The per-scanner artifact/unit counts (`skills_scanned`, `mcp_configs_scanned`, `packages_scanned`,
  `files_scanned`, …) and the scanner count were already tracked on each `ScanResult` but never
  surfaced together. The human `INVESTIGATION SUMMARY` footer now reports **Items scanned** and
  **Scanners run** alongside the existing duration, and the `--json` `summary` block gains matching
  `items_scanned` / `scanners_run` keys (additive — the documented `schema_version` 1.0 contract only
  ever grows). A single pure helper `aggregate_scan_stats()` is the source of truth for both paths: it
  sums every integer stat whose key ends in `_scanned`, so a new scanner that follows the naming
  convention is counted with no further changes (bools and the `min_confidence` string are excluded).
  10 new tests (`tests/test_scan_stats.py`: suffix summation, scanner count, duration rounding,
  non-count-stat exclusion, empty-results zero case, JSON propagation parity, e2e human-footer +
  `--json` over a real benign-skill fixture); full suite **577 green** (was 567).
- **Config file (`shellockolm.toml` / `[tool.shellockolm]`) — pin scan defaults.** A project
  can commit its scan settings so every contributor and CI runs the same scan without retyping
  flags. The CLI reads the **nearest** `shellockolm.toml` (top-level keys or a `[tool.shellockolm]`
  table) or `pyproject.toml` `[tool.shellockolm]` table at or above the scan path (walking up like
  `.gitignore`); a dedicated `shellockolm.toml` is preferred over a `pyproject.toml`, and a
  `pyproject.toml` without our table is left alone. Supported keys: `path`, `scanner`, `recursive`,
  `max_depth` (alias `depth`), `min_confidence`, `fail_on`, and `ignore` (a list of rule/CVE IDs
  and/or gitignore-style path globs). Config supplies a **default** only for a flag the user did not
  pass — **an explicit flag always wins** (detected via Click's parameter-source, compared by member
  name so Typer's bundled-Click copy doesn't break the check). `ignore` is applied as a pure,
  scanner-agnostic post-filter alongside `--diff`/`--baseline`; the hidden count is announced and
  surfaced as `summary.findings_config_ignored` in `--json`. `--config <path>` targets a specific
  file (missing/invalid → exit `2`) and `--no-config` disables discovery; a malformed config (bad
  value/type, invalid TOML) is a usage error (exit `2`), never a silently-wrong scan. Backed by a
  pure, testable `src/config_file.py` (mirrors `diff_scan.py` / `baseline.py` / `doctor.py`); 56 new
  tests (`tests/test_config_file.py`: discovery + precedence, table extraction, full validation of
  every key + every error path, ignore rule-ID/glob matching, anti-drift parity with the CLI's
  `_FAIL_ON_CHOICES`, and e2e subprocess proving config defaults apply, an explicit flag overrides,
  `--no-config` disables, an `ignore` entry hides a finding, a `pyproject` table is discovered, and
  missing/invalid configs exit 2); full suite **567 green** (was 508).
- **`shellockolm doctor` — environment self-check with actionable output.** A new
  command that verifies Shellockolm can scan on the current machine before you depend
  on it: the Python runtime meets the supported floor (`>=3.10`), the bundled CVE
  database and the agent supply-chain rule catalog import and are populated, the
  config (`~/.shellockolm`, where the Pro license lives) and session/log directories
  are writable, the optional `git` dependency (used by `scan --diff` and the
  pre-commit hook) is on `PATH`, and the active license tier resolves. Each check is
  `ok` / `warn` / `fail` / `info`; only a hard `fail` (old Python, a corrupt install)
  makes the command exit non-zero — a missing `git` or an unwritable log dir is a
  `warn` that still passes. Exit codes mirror the scan contract (**0** healthy /
  **1** one or more checks failed), and `--json` emits one stable `schema_version`
  1.0 document (pure stdout, no banner) for CI. Runs **fully offline** unless a
  license key is configured (the license probe only contacts the server when a key
  is present). Backed by a pure, testable `src/doctor.py` (mirrors `diff_scan.py` /
  `baseline.py`); 23 new tests (`tests/test_doctor.py`: per-check units incl. the
  Python-floor boundary, writable-probe success/failure + cleanup, git/license
  probes, `DoctorReport` health/counts/serialization, the CLI exit-code mapping, and
  e2e subprocess proving pure-JSON stdout + a healthy machine exits 0); full suite
  **507 green** (was 484).
- **Benchmark script + perf guard for the agent scanner.** A new
  `scripts/benchmark_scan.py` generates a deterministic, self-contained corpus of
  agent artifacts (skills, MCP configs, n8n exports, instruction files, `.claude/`
  settings + slash-commands; ≈5 % carrying a known malicious shape), scans it, and
  reports wall-clock + throughput (and gates on a `--budget`). The corpus
  generator is shared with the new `tests/test_perf_guard.py` so the benchmark and
  the CI regression tripwire agree. Real measured numbers are documented in
  [docs/PERFORMANCE.md](docs/PERFORMANCE.md): ~960–1,080 artifacts/s (~1 ms/artifact)
  on the synthetic tree, and the real `~/.claude/skills` corpus (1,335 skills).

### Changed
- **Faster non-ASCII stealth scans (regex-pass optimization).** The per-character
  Unicode-Tags-smuggling, Trojan-Source bidi, and confusable/homoglyph checks used
  to iterate every character of every artifact (and, for confusables, regex over
  every word). Every code point they look for lives above U+007F, so a single
  C-level character-class search (`_STEALTH_CHARS_RE`, built from the same
  constants the checks consume so it cannot drift) now lets a pure-ASCII artifact
  skip all three Python loops. **1,333 of 1,335 real skills are pure ASCII**, so
  the fast path applies almost everywhere: **−14.2 %** wall-clock on the real
  corpus (18.65 s → 16.01 s) and −10.3 % on a 2,000-artifact synthetic tree, with
  findings **byte-identical** both ways (a strict superset guard — any artifact
  with a real stealth char still runs the full slow-path scan). 15 new perf-guard
  tests assert the guard never drifts, fast-paths benign ASCII *and* benign
  non-ASCII (emoji/curly-quotes/CJK), and still detects every smuggling attack;
  full suite 456 green (was 441).

- **Baseline support (`--baseline` / `--write-baseline`) — fail CI only on NEW
  findings.** Adopt the scanner on a codebase that already has findings without
  drowning CI in pre-existing noise. `scan --write-baseline baseline.json`
  snapshots every current finding into a file (a report-only run that never fails
  the build) so you can accept the existing findings and commit it;
  `scan --baseline baseline.json` then drops every finding already in the baseline
  and reports only NEW ones, which gate the exit code per `--fail-on`. A
  finding's identity is a SHA-256 over `id | repo-relative path | package |
  version`, deliberately **excluding the line number and severity** — so editing a
  file (shifting a finding's line) or a later composite-severity boost never makes
  a known finding look new and spuriously fail the build. The hidden count is
  announced (never silent) and surfaced as `summary.findings_baselined` in
  `--json`; a missing/corrupt baseline is a usage error (exit `2`, never a silent
  pass); `--baseline` and `--write-baseline` together is a usage error. New
  self-contained `src/baseline.py` module (mirrors `diff_scan.py`: pure, tested
  identity + filtering split from the file I/O). The baseline file is a documented
  `schema_version` 1.0 JSON document (deduped + sorted, so it diffs cleanly across
  regenerations). 25 new tests (`tests/test_baseline.py`: fingerprint stability
  across line-shift + severity-change, per-axis distinctness, build/load/filter
  round-trip, every load error path, and e2e subprocess runs proving
  write→exit 0, known-hidden→exit 0, new-finding→exit 1 with only the new file
  reported, missing→exit 2, and the conflict→exit 2); full suite 441 green
  (was 416).
- **`rules explain <RULE-ID>` — a full per-rule explainer with an example
  attack.** The deep-dive companion to `rules list`: `shellockolm rules explain
  AGENT-PI-013` prints one rule's severity, tier, confidence, attack class and
  CVSS, then the full description, a concrete **example attack**, and the
  remediation. The rule ID is case-insensitive; an unknown ID is a usage error
  (exit `2`, message to stderr so `--json` stdout stays empty); `--json` emits
  one stable document (`schema_version` 1.0, `rule` object) for docs/CI. Backing
  it, a canonical per-rule example-attack catalog (`_RULE_ATTACK_EXAMPLES` +
  `agent_rule_example()` / `agent_rule_explain()` in
  `scanners/agent_supply_chain.py`) carries one short, illustrative example for
  **every** rule the scanner can emit — completeness is test-enforced so it can't
  drift behind a newly-added rule, and every embedded credential is an obvious
  non-live placeholder. The human render escapes authored prose, so an example
  containing markdown-link brackets (`[docs.github.com](…)`) can't be mis-parsed
  as console markup. 11 new tests (example-catalog completeness + case-insensitive
  /unknown-safe lookup, explainer-matches-catalog + every-rule coverage, and e2e
  subprocess runs for the human render, `--json` document, case-insensitivity,
  the exit-2 unknown-rule path, and markup-safety); full suite 416 green (was 405).
- **`rules list` — the agent rule catalog as a command (and docs).** A new
  `shellockolm rules list` prints every agent supply-chain detection rule — ID,
  severity, **tier** (free / Pro), confidence, attack class, and a one-line
  description — so you can see exactly what the agent scanner looks for without
  reading source. Filters: `--tier free|pro`, `--severity critical|…|info`;
  `--json` emits one stable JSON document (`schema_version` 1.0) that feeds the
  forthcoming `RULES.md` and CI tooling — pure JSON on stdout (usage errors to
  stderr, exit `2` on an unknown filter value). Backing it, every detection rule
  is now exposed through a single canonical catalog (`agent_rule_catalog()` /
  `ALL_AGENT_RULES` in `scanners/agent_supply_chain.py`): the 11 structural /
  stealth-channel rules that were inline `AgentRule` literals (invisible chars,
  Unicode-Tags, bidi, homoglyph, link/href mismatch, HTML comment, frontmatter,
  memory poisoning, cross-file, tool-output spoof, base64 blob) were promoted to
  named module constants and are now enumerable without running a scan — a
  behaviour-preserving refactor (the full pre-existing agent suite stays green).
  22 new tests (`tests/test_rules_catalog.py`: catalog completeness incl. all
  structural rules, tier/attack-class classification, de-dup + ordering, valid
  enums, a behaviour-preservation check that a promoted rule still emits its
  catalog metadata, and e2e subprocess runs for `rules list` JSON/filters/exit-2
  /human table); full suite 405 green (was 383).
- **`scan --table` — polished findings table grouped by file.** A new opt-in
  human-output mode: one compact Rich table per artifact (rows colored by
  severity, with rule ID, line, CVSS and detection confidence), closed by a
  severity-tally summary footer. It **degrades gracefully when stdout is not a
  TTY** — a piped/redirected stream gets an ASCII box (no Unicode frame glyphs),
  no ANSI color, and the bare severity word instead of an emoji — so it stays
  clean in a log capture. Grouping reuses `diff_scan.bare_path`, so a file's
  findings collapse together across the `:<line>` / `» server:<name>` location
  suffixes. `--json` (CI mode) suppresses the table; stdout stays a single JSON
  document. Rendering helpers (`group_findings_by_file`, `build_findings_table`,
  `build_severity_footer`, `render_findings_table`) are pure/testable, and finding
  text is wrapped in `rich.text.Text` so a bracket in a path or title can't be
  mis-parsed as console markup. 19 new tests (`tests/test_cli_table_output.py`:
  grouping/ordering units, TTY-vs-non-TTY degradation, tallies, markup-safety, and
  e2e subprocess runs proving the table renders, the piped stream is ASCII, and
  `--json` still emits only JSON); full suite 383 green (was 364).
- **GitHub Action (`action.yml`) — checkout → scan → SARIF upload.** A composite
  action consumers add in one workflow step. It runs the scan in stable `--json`
  mode, writes a JSON report and a SARIF 2.1.0 document, and uploads the SARIF to
  GitHub code scanning (Security tab) via `github/codeql-action/upload-sarif`.
  Inputs: `path`, `scanner` (empty = all), `fail-on`, `min-confidence`, `output`,
  `sarif`, `upload-sarif`, `quick`, `python-version`; outputs: `report`, `sarif`,
  `findings`, `exit-code`. The build fails per the documented exit-code contract
  (`--fail-on`, wired through to the step's exit). A 20-test contract suite
  (`tests/test_github_action.py`) validates the action shape, that the scan step
  wires `--json`/`--fail-on`/`--sarif`/`-o`, that the SARIF upload step exists and
  is gated, and that the `scripts/action_summary.py` helper prints only the finding
  count to stdout (degrading to `0` on a missing report).

### Fixed
- **GitHub Action no longer passes the invalid `-s all`.** The previous stub
  `action.yml` defaulted `scanner` to `all` and passed `-s all`, which `scan`
  rejects (exit `2`) — so it failed every run. The scanner default is now empty
  (= run every scanner) and `-s` is only passed when a scanner is named; the
  `fail-on` input is now actually wired to the exit code (it was a no-op), and the
  `findings` output is populated.

- **Pre-commit hook integration (`.pre-commit-hooks.yaml`).** Ships two
  [pre-commit](https://pre-commit.com) hooks so any repo can vet every commit in
  one `.pre-commit-config.yaml` block: `shellockolm-agent` (AI agent
  supply-chain scan, the recommended default — triggers only when a `SKILL.md` /
  `mcp.json` / `.claude/` / `CLAUDE.md` / `AGENTS.md` artifact is staged) and
  `shellockolm` (full deps + secrets + malware + agent scan). Both scan only the
  **staged** set via `scan --diff` (so they flag what the commit introduces and
  exit `0` instantly when nothing relevant is staged), block the commit on HIGH+
  by default, and keep `--diff` in `entry` so it survives an `args:` gate
  override. `pass_filenames: false` (the `scan` CLI takes one PATH, not a
  filename list). Documented in the README; an 11-test contract suite
  (`tests/test_pre_commit_hooks.py`) validates the YAML shape, that the `entry`
  console script is declared in `pyproject` `[project.scripts]`, that the default
  `--fail-on` gate is a value the live CLI accepts, and that the agent hook's
  `files` trigger regex matches real agent artifacts while ignoring ordinary
  source files.
- **`scan --diff` / `--diff-ref` — git-diff scoping for pre-commit & CI.** Reports
  findings only for files **changed in git**: `--diff` scans the staged set
  (`git diff --cached`, the pre-commit content) and `--diff-ref <ref>` scans
  everything that differs from a ref (e.g. `origin/main`). Findings on unchanged
  files are dropped (count announced, never silent; surfaced as
  `summary.findings_diff_filtered` in `--json`); an empty changed set exits `0`
  immediately. Path-matching is exact and case-insensitive on Windows — it strips a
  finding's `:<line>` / ` » server:<name>` suffix and resolves relative paths, never
  a fuzzy basename match. A path outside a git work tree (or an unknown ref) is a
  usage error (exit `2`). Composes with `--json`/`--sarif`/`--fail-on`/
  `--min-confidence`. New `src/diff_scan.py` with a 28-test suite
  (`tests/test_diff_scan.py`): pure matching units, real-temp-repo integration, and
  e2e proving an unchanged malicious skill is hidden while a staged one is reported.
- **`scan` exit-code contract + `--fail-on` gate.** Exit codes are now documented
  and stable — `0` clean, `1` findings, `2` usage/operational error — and
  `--fail-on critical|high|medium|low|info` gates the build on severity (exit `1`
  only when a finding at or above that level is present), with `--fail-on none` for
  report-only runs. A finding below the gate is announced rather than silently
  passed. Usage errors (bad path, unknown scanner, unknown flag value) now exit `2`
  instead of `1`, so a flag typo can't masquerade as a clean run. Documented in the
  README with an 18-test suite (`tests/test_cli_exit_codes.py`).

## [3.0.0] - 2026-06-10

A correctness, security, and packaging hardening pass. The headline fix:
`pip install .` now actually works — previously it produced broken console
scripts and silently omitted the `scanners` subpackage.

### Added
- **Real test suite** under `tests/` (pytest): vulnerability database, modular
  scanners, secrets scanner, ignore-file matching, and a smoke test that imports
  every `src/` module to catch import-time errors.
- **`shellockolm-mcp` console script** wired to `mcp_server:run` for launching
  the MCP server directly.
- **Root `CHANGELOG.md`** (this file) in Keep a Changelog format.
- **Modular scanner architecture** (`src/scanners/`) covering React/RSC,
  Next.js, npm packages, Node.js, n8n, supply-chain, and Clawdbot/Moltbot.

### Fixed
- **Packaging — `pip install .` is no longer broken.** Replaced the bogus
  `packages = ["shellockolm"]` / `package-dir = {"shellockolm" = "src"}` mapping
  (which produced unimportable console scripts and dropped the `scanners`
  subpackage) with a flat install from `src/`: `package-dir = {"" = "src"}`,
  an explicit `py-modules` list of all 29 top-level modules, and
  `packages.find` to pick up the `scanners` package. Flat imports
  (`import cli`, `from scanners import ...`, `from vulnerability_database import ...`)
  and all entry points now resolve from the installed distribution.
- **`requirements.txt` now matches reality.** Added the missing-but-required
  `requests` and `prompt_toolkit`, removed the dead `semver` dependency (never
  imported), and moved `pytest`/`pytest-asyncio` out of runtime deps into the
  packaging `dev` extra. Installer shell scripts that verify `import requests`
  after `pip install -r requirements.txt` now succeed.
- **Single source of truth for packaging.** Deleted the conflicting `setup.py`
  (different package name, phantom modules, pytest shipped as a runtime dep,
  a missing entry point); `pyproject.toml` is now authoritative.
- **Clawdbot/Moltbot CVEs are reachable** through `get_all_vulnerabilities()`
  and the lookup API.
- **Secrets scanner false positive:** a bare `0x` + 64-hex string (EVM
  transaction hash / keccak digest) is no longer misreported as a CRITICAL
  Ethereum private key; a private-key context keyword is now required.
- **`gui.py` import crash** from a missing `io` import.
- **`.shellockolmignore` glob matching** for patterns like `*.min.js` and
  `*.log`.

### Changed
- **CI is real now** (`.github/workflows/ci.yml`): runs `pip install .`,
  asserts the `shellockolm` console script works, and runs `pytest` as a
  blocking step. Smoke import/scan steps no longer swallow failures. Matrix
  trimmed to Ubuntu + Windows on Python 3.10/3.12.
- **Coverage** is no longer forced in the default pytest `addopts` (so the suite
  runs without `pytest-cov`); run `pytest --cov=src` explicitly for coverage.
- **Package data** no longer ships internal docs (`ENHANCEMENT_PLAN.md`);
  restricted to `*.txt` data files.

### Security
- **CVE-monitor workflow** (`.github/workflows/cve-monitor.yml`) declares a
  least-privilege `permissions:` block (`issues: write`, `contents: read`).
- Removed the dependency on the previously-compromised `tj-actions` org for
  Bandit; the security scan now runs `bandit` from pip directly.

---

For the 2.0.0 (2025-12-08), 1.1.0, and earlier releases, see
[docs/CHANGELOG.md](docs/CHANGELOG.md).
