# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Older history (2.0.0 and earlier) lives in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## [Unreleased]

### Added
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
