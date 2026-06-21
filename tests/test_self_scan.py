"""Contract + mechanism tests for the CI self-scan / dogfooding gate (task #43).

Task #43 asks shellockolm to run against its OWN repo on every CI run and fail
on HIGH+ findings — "dogfooding badge material — only claim it once true". That
contract lives in two committed files:

* ``.github/workflows/ci.yml`` — a dedicated, build-blocking ``self-scan`` job
  that runs ``shellockolm scan -s agent --fail-on high .``.
* ``shellockolm.toml`` — excludes ONLY the deliberate detection corpus under
  ``tests/fixtures/`` (intentionally malicious/benign test data the detection
  suite asserts on), so the gate measures real agent artifacts, not test data.

Two layers of assertion:

1. **Contract** (stdlib text/TOML parsing — collects on every supported Python):
   the job exists, runs the agent scanner, is build-blocking, gates on a valid
   ``--fail-on`` level, and the config excludes the fixtures while NOT silently
   narrowing a contributor's plain ``shellockolm scan``.
2. **Mechanism** (runs the real scanner in a subprocess): the repo is genuinely
   clean at HIGH+ today (exit 0) AND the exclusion is load-bearing — without it
   the deliberate fixtures trip HIGH+ (exit 1). This is the "only claim it once
   true" proof, and it guards against the gate being vacuously green.
"""

import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

CLI_PY = SRC / "cli.py"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SHELLOCKOLM_TOML = REPO_ROOT / "shellockolm.toml"

# The deliberate detection corpus the self-scan config must exclude.
FIXTURES_DIR_TOKEN = "tests/fixtures/"


def _read(path: Path) -> str:
    assert path.exists(), f"expected file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _job_block(ci_text: str, job: str) -> str:
    """Slice one job's body out of ci.yml: from ``  <job>:`` to the next job.

    Pure text slicing so the assertions stay scoped to the self-scan job and
    can't be satisfied by an unrelated job elsewhere in the workflow.
    """
    lines = ci_text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(rf"^\s{{2}}{re.escape(job)}:\s*$", line):
            start = i
            break
    assert start is not None, f"no '{job}' job found in ci.yml"
    body = [lines[start]]
    for line in lines[start + 1:]:
        if re.match(r"^\s{2}\S", line):  # next top-level job header (2-space indent)
            break
        body.append(line)
    return "\n".join(body)


# --------------------------------------------------------------------------
# Contract — the committed shellockolm.toml excludes the fixtures (only)
# --------------------------------------------------------------------------
def test_repo_ships_a_shellockolm_toml():
    assert SHELLOCKOLM_TOML.is_file(), (
        "the self-scan job depends on a committed shellockolm.toml at the repo "
        "root to exclude the deliberate detection corpus"
    )


def test_config_excludes_the_fixtures_corpus():
    """The committed config must actually parse and exclude tests/fixtures/."""
    import config_file

    cfg = config_file.load_config_from_file(str(SHELLOCKOLM_TOML))
    assert any(
        entry.rstrip("/").replace("\\", "/") == FIXTURES_DIR_TOKEN.rstrip("/")
        or entry.replace("\\", "/").startswith(FIXTURES_DIR_TOKEN)
        for entry in cfg.ignore
    ), (
        "shellockolm.toml must ignore the deliberate detection corpus under "
        f"{FIXTURES_DIR_TOKEN}; got ignore={cfg.ignore!r}"
    )


def test_config_does_not_silently_narrow_a_plain_scan():
    """The config sets ONLY `ignore` — pinning `scanner`/`fail_on` would change a
    contributor's plain `shellockolm scan .` behavior, which the design forbids."""
    import config_file

    cfg = config_file.load_config_from_file(str(SHELLOCKOLM_TOML))
    assert cfg.scanner is None, (
        "shellockolm.toml must not pin `scanner` (it would narrow a plain "
        "`shellockolm scan .` for every contributor)"
    )
    assert cfg.fail_on is None, (
        "shellockolm.toml must not pin `fail_on` (the self-scan job passes "
        "--fail-on explicitly; pinning it would change interactive scans)"
    )


# --------------------------------------------------------------------------
# Contract — the CI self-scan job is wired and build-blocking
# --------------------------------------------------------------------------
def test_ci_has_dedicated_self_scan_job():
    block = _job_block(_read(CI_WORKFLOW), "self-scan")
    # Runs the flagship agent supply-chain scanner against this repo.
    assert "-s agent" in block, "the self-scan job must run the agent scanner (`-s agent`)"
    assert "shellockolm scan" in block, "the self-scan job must invoke `shellockolm scan`"


def test_self_scan_gates_on_high_plus():
    block = _job_block(_read(CI_WORKFLOW), "self-scan")
    m = re.search(r"--fail-on\s+(\S+)", block)
    assert m, "the self-scan job must pass --fail-on to gate the exit code"
    assert m.group(1) == "high", (
        f"the self-scan dogfood gate must fail on HIGH+ (got --fail-on {m.group(1)})"
    )


def test_self_scan_fail_on_value_is_a_valid_cli_choice():
    """Anti-drift: the level the job gates on must be one the CLI accepts, so a
    typo can't silently turn the gate into a usage error (exit 2)."""
    import cli

    block = _job_block(_read(CI_WORKFLOW), "self-scan")
    m = re.search(r"--fail-on\s+(\S+)", block)
    assert m and m.group(1) in cli._FAIL_ON_CHOICES, (
        f"--fail-on {m.group(1) if m else '?'} is not in the CLI's accepted "
        f"choices {sorted(cli._FAIL_ON_CHOICES)}"
    )


def test_self_scan_step_is_build_blocking():
    """The scan step must be able to fail the build — no continue-on-error may
    decorate the job (otherwise a real HIGH+ regression would not gate)."""
    block = _job_block(_read(CI_WORKFLOW), "self-scan")
    assert "continue-on-error: true" not in block, (
        "the self-scan job must block the build (no continue-on-error)"
    )


# --------------------------------------------------------------------------
# Mechanism — the gate is genuinely green here AND has teeth (the real proof)
# --------------------------------------------------------------------------
def _run_self_scan(*extra_args):
    """Run the exact self-scan gate from the repo root; return (rc, json|None)."""
    args = ["scan", "-s", "agent", "--fail-on", "high", *extra_args, "."]
    proc = subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        cwd=str(REPO_ROOT), capture_output=True, text=True, encoding="utf-8",
    )
    report = None
    if "--json" in extra_args:
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            report = None
    return proc.returncode, report


def test_repo_is_clean_at_high_plus_today():
    """Dogfooding claim: a self-scan of this repo (fixtures excluded via the
    committed config) reports ZERO HIGH/CRITICAL findings and exits 0."""
    rc, report = _run_self_scan("--json")
    assert report is not None, "self-scan did not emit a JSON report"
    by_sev = report["summary"].get("by_severity", {})
    assert by_sev.get("high", 0) == 0 and by_sev.get("critical", 0) == 0, (
        f"self-scan found HIGH+ findings in real artifacts: {by_sev}"
    )
    # Non-vacuous: it really walked agent artifacts (not green because nothing
    # was scanned), and the fixtures were scanned-then-excluded (not skipped).
    assert report["summary"].get("items_scanned", 0) > 0, (
        "self-scan scanned nothing — a green gate here would be meaningless"
    )
    assert report["summary"].get("findings_config_ignored", 0) > 0, (
        "the deliberate fixtures should have been scanned then excluded by "
        "config; a zero count means they were never reached (vacuous gate)"
    )
    assert rc == 0, "the self-scan gate must exit 0 on a clean repo"


def test_exclusion_is_load_bearing_and_gate_has_teeth():
    """Without the fixtures exclusion the deliberate malicious corpus trips
    HIGH+ and the gate fails — proving the exclusion does real work and the
    --fail-on gate genuinely blocks the build."""
    rc_no_config, _ = _run_self_scan("--no-config")
    assert rc_no_config == 1, (
        "scanning the repo WITHOUT the fixtures exclusion must exit 1 (the "
        "deliberate malicious fixtures trip HIGH+) — the gate would otherwise "
        "be vacuous"
    )
    rc_with_config, _ = _run_self_scan()
    assert rc_with_config == 0, (
        "the same scan WITH the committed config must exit 0 (clean repo)"
    )
