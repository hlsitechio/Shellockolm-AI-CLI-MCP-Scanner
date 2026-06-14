# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Older history (2.0.0 and earlier) lives in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## [Unreleased]

### Added
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
