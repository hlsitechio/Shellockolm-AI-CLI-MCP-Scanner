"""Contract tests for the coverage gate (build-loop task #41).

The coverage gate is a *contract* spread across two committed files:

* ``pyproject.toml`` — declares the coverage configuration and the
  ``fail_under`` threshold (the single source of truth for the floor).
* ``.github/workflows/ci.yml`` — runs ``pytest --cov=src`` in a dedicated,
  build-blocking job that enforces that threshold on every push / PR.

These tests assert the wiring stays intact (so the gate can't be silently
removed or gutted) and that the underlying ``pytest-cov`` mechanism actually
enforces ``fail_under`` in this environment. Everything here is parsed from
file *text* with the stdlib only, so the tests collect on every supported
Python (3.10+) with no extra parser dependency.
"""

import re
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# The established floor. The gate ratchets UP over time; it must never be
# quietly lowered below this meaningful level (a 1% gate is not a gate).
MIN_EXPECTED_FLOOR = 25


def _read(path: Path) -> str:
    assert path.exists(), f"expected file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _toml_table(text: str, header: str) -> str:
    """Return the body of a TOML table from its ``[header]`` line up to the
    next table header (or EOF). Pure text slicing — no TOML parser needed."""
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if line.strip() == f"[{header}]":
            start = i + 1
            break
    assert start is not None, f"[{header}] table not found in pyproject.toml"
    body = []
    for line in lines[start:]:
        if re.match(r"^\s*\[", line):  # next table header
            break
        body.append(line)
    return "\n".join(body)


def _dev_extras(text: str) -> str:
    """Return the body of the ``dev = [ ... ]`` optional-dependencies array.

    Read line-by-line until the array's closing ``]`` (a line that is just
    ``]``), so a ``]`` appearing inside a comment (e.g. ``pip install .[dev]``)
    does not prematurely terminate the slice.
    """
    lines = text.splitlines()
    start = None
    for i, line in enumerate(lines):
        if re.match(r"^\s*dev\s*=\s*\[", line):
            start = i + 1
            break
    assert start is not None, "dev optional-dependencies array not found"
    body = []
    for line in lines[start:]:
        if line.strip() == "]":
            break
        body.append(line)
    return "\n".join(body)


# --------------------------------------------------------------------------
# pyproject.toml — the threshold and coverage config
# --------------------------------------------------------------------------
def test_coverage_run_section_targets_src():
    run = _toml_table(_read(PYPROJECT), "tool.coverage.run")
    assert re.search(r'source\s*=\s*\[[^\]]*"src"', run), (
        "[tool.coverage.run] must measure the src/ tree"
    )


def test_coverage_report_declares_fail_under():
    report = _toml_table(_read(PYPROJECT), "tool.coverage.report")
    m = re.search(r"^\s*fail_under\s*=\s*([0-9]+)", report, re.MULTILINE)
    assert m, "[tool.coverage.report] must declare a fail_under threshold"
    value = int(m.group(1))
    assert 1 <= value <= 100, f"fail_under={value} out of range"
    assert value >= MIN_EXPECTED_FLOOR, (
        f"coverage gate gutted: fail_under={value} is below the established "
        f"floor of {MIN_EXPECTED_FLOOR}% (the gate only ratchets up)"
    )


def test_fail_under_threshold_value():
    """The current floor — bump this in lockstep when ratcheting the gate up."""
    report = _toml_table(_read(PYPROJECT), "tool.coverage.report")
    m = re.search(r"^\s*fail_under\s*=\s*([0-9]+)", report, re.MULTILINE)
    assert m and int(m.group(1)) == 28


def test_dev_extras_include_coverage_tooling():
    extras = _dev_extras(_read(PYPROJECT))
    assert "pytest-cov" in extras, "pytest-cov must be a dev dependency"
    # PyYAML is required for the workflow/contract tests to collect under a
    # clean `pip install .[dev]`; without it the whole suite (and thus the
    # coverage gate job) fails at import time.
    assert re.search(r"pyyaml", extras, re.IGNORECASE), (
        "pyyaml must be a dev dependency so the suite collects in CI"
    )


# --------------------------------------------------------------------------
# CI workflow — the gate actually runs and blocks the build
# --------------------------------------------------------------------------
def test_ci_runs_coverage_over_src():
    ci = _read(CI_WORKFLOW)
    assert "--cov=src" in ci, (
        "CI must run the suite under coverage (--cov=src) to enforce the gate"
    )


def test_ci_has_dedicated_coverage_job():
    ci = _read(CI_WORKFLOW)
    assert re.search(r"^\s{2}coverage:", ci, re.MULTILINE), (
        "expected a dedicated 'coverage' job in ci.yml"
    )
    # The gating step must be able to fail the build: no continue-on-error may
    # decorate the step that runs the coverage invocation.
    cov_idx = ci.index("--cov=src")
    step_block = ci[max(0, cov_idx - 400):cov_idx + 200]
    assert "continue-on-error: true" not in step_block, (
        "the coverage gate step must block the build (no continue-on-error)"
    )


# --------------------------------------------------------------------------
# Mechanism — pytest-cov really enforces fail_under (skips if cov absent)
# --------------------------------------------------------------------------
def test_pytest_cov_enforces_fail_under(tmp_path):
    """An impossible threshold makes pytest exit non-zero — proving the gate
    mechanism the CI job relies on is installed and active here."""
    pytest.importorskip(
        "pytest_cov", reason="coverage gate mechanism needs pytest-cov"
    )
    (tmp_path / "covtarget.py").write_text(
        "def used():\n    return 1\n\n\ndef never_called():\n    return 2\n",
        encoding="utf-8",
    )
    (tmp_path / "test_covtarget.py").write_text(
        "import covtarget\n\n\ndef test_used():\n    assert covtarget.used() == 1\n",
        encoding="utf-8",
    )
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "test_covtarget.py",
            "-p", "no:cacheprovider",
            "-o", "addopts=",
            "-q",
            "--cov=covtarget",
            "--cov-report=",
            "--cov-fail-under=100",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "pytest-cov did not fail the run on an unreachable coverage floor:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert "Required test coverage" in (result.stdout + result.stderr)
