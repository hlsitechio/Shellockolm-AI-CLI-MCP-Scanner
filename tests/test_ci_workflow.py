"""Contract tests for the CI workflow + ruff lint gate (build-loop task #42).

Task #42 asks for a CI workflow that runs **lint (ruff)**, tests across
**Python 3.10–3.14**, on a **Windows + Linux** matrix. That contract is spread
across two committed files:

* ``.github/workflows/ci.yml`` — the test matrix (OS x Python) and a dedicated,
  build-blocking ``lint`` job that runs ``ruff check src tests scripts``. The
  ``tests`` path was added by build-loop follow-up F25: the test tree is where
  every detection claim in the backlog is actually pinned, and while it sat
  outside the gate it drifted (13 violations the day it was folded in).
  ``scripts`` followed in F26 — ``action_summary.py`` runs inside the shipped
  GitHub Action and ``benchmark_scan.py`` is imported by the perf tripwire, so
  it is shipped CI surface, not inert tooling. The gate paths are parsed back
  out of the workflow here and re-run, so the tree CI lints and the tree these
  tests prove clean can never diverge.
* ``pyproject.toml`` — declares ``ruff`` as a dev dependency and the single
  source of truth for the lint rule selection / deferred-backlog ignore list in
  ``[tool.ruff.lint]`` (shared by CI and a local ``ruff check``).

These tests assert the wiring stays intact (so the gate can't be silently
removed, un-blocked, or gutted) and — when ruff is installed — that the
committed source actually passes its own gate and that the gate mechanism
genuinely flags a real bug. Everything is parsed from file *text* with the
stdlib only, so the assertions collect on every supported Python (3.10+) with
no extra parser dependency; the mechanism tests skip cleanly when ruff is
absent (ruff is in the ``dev`` extras, so CI always has it).
"""

import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"

# The Python versions the matrix must cover, end to end.
EXPECTED_PY_VERSIONS = ["3.10", "3.11", "3.12", "3.13", "3.14"]
EXPECTED_OSES = ["ubuntu-latest", "windows-latest"]

# Crash-class rule codes that surfaced real bugs and must STAY enforced — they
# may never be added to the deferred-backlog ignore list.
ENFORCED_BUG_CODES = ["F821", "F823", "F811", "E9"]

# Hygiene codes the cleanups fixed rather than silenced: E741/E702 in the test
# tree (F25), E401 in the scripts tree (F26), and E722 (bare-except) in the CLI's
# sandbox deep-install check (F27) — the rule-family half of the ratchet, where a
# swallowed exception in a security scanner silently becomes "no findings". They
# must stay enforced — silencing them in the ignore list is the cheap way to
# "fix" a future failure, which would quietly re-open the drift this gate exists
# to close.
LINT_HYGIENE_CODES = ["E741", "E702", "E401", "E722"]

# Trees the CI lint gate must cover. `src` is the shipped package; `tests` is
# where the detection claims are pinned; `scripts` holds tooling that runs in
# shipped CI surface (action_summary.py inside the GitHub Action,
# benchmark_scan.py's corpus generator imported by the perf tripwire).
REQUIRED_LINT_PATHS = ["src", "tests", "scripts"]


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
    """Return the body of the ``dev = [ ... ]`` optional-dependencies array."""
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


def _ci_ruff_paths(ci: str) -> list:
    """Return the path arguments of the workflow's ``ruff check`` invocation.

    Parsed straight out of ci.yml so the paths asserted (and re-linted) here are
    literally the ones CI runs — a path added to or dropped from the gate shows
    up in these tests instead of drifting silently.
    """
    m = re.search(r"^\s*run:\s*ruff check\s+(.+)$", ci, re.MULTILINE)
    assert m, "no `run: ruff check ...` step found in ci.yml"
    # Keep positional paths only; a future flag (e.g. --output-format) is not one.
    return [tok for tok in m.group(1).split() if not tok.startswith("-")]


def _ruff_argv():
    """Best-effort ruff invocation, or None when ruff is not installed."""
    candidates = []
    exe = shutil.which("ruff")
    if exe:
        candidates.append([exe])
    candidates.append([sys.executable, "-m", "ruff"])
    for argv in candidates:
        try:
            probe = subprocess.run(
                argv + ["--version"], capture_output=True, text=True
            )
        except (OSError, ValueError):
            continue
        if probe.returncode == 0:
            return argv
    return None


# --------------------------------------------------------------------------
# pyproject.toml — ruff is a dev dependency and configured as the gate
# --------------------------------------------------------------------------
def test_ruff_is_a_dev_dependency():
    extras = _dev_extras(_read(PYPROJECT))
    assert re.search(r"^\s*[\"']ruff", extras, re.MULTILINE), (
        "ruff must be a dev dependency so `pip install .[dev]` provides the "
        "linter in CI"
    )


def test_ruff_lint_selects_correctness_families():
    lint = _toml_table(_read(PYPROJECT), "tool.ruff.lint")
    m = re.search(r"select\s*=\s*\[([^\]]*)\]", lint)
    assert m, "[tool.ruff.lint] must declare a `select` rule set"
    selected = m.group(1)
    for fam in ('"E"', '"F"', '"W"'):
        assert fam in selected, (
            f"ruff lint must enable the {fam} correctness family; got: {selected}"
        )


def test_enforced_bug_codes_are_not_ignored():
    """The crash-class codes this gate first surfaced (undefined name/local,
    redefinition, syntax) must never be silenced via the ignore list."""
    lint = _toml_table(_read(PYPROJECT), "tool.ruff.lint")
    m = re.search(r"ignore\s*=\s*\[(.*?)\]", lint, re.DOTALL)
    ignore_body = m.group(1) if m else ""
    for code in ENFORCED_BUG_CODES:
        assert f'"{code}"' not in ignore_body, (
            f"{code} is a genuine-bug rule and must stay enforced — it may not "
            f"be added to [tool.ruff.lint] ignore"
        )


def test_hygiene_codes_cleaned_from_tests_stay_enforced():
    """E741/E702 were the drift that folding `tests` into the gate exposed. They
    must not be silenced into the ignore list instead of being fixed."""
    lint = _toml_table(_read(PYPROJECT), "tool.ruff.lint")
    m = re.search(r"ignore\s*=\s*\[(.*?)\]", lint, re.DOTALL)
    ignore_body = m.group(1) if m else ""
    for code in LINT_HYGIENE_CODES:
        assert f'"{code}"' not in ignore_body, (
            f"{code} was fixed in the test tree, not ignored — it may not be "
            f"added to [tool.ruff.lint] ignore"
        )


def test_requires_python_floor_matches_lowest_matrix_version():
    text = _read(PYPROJECT)
    m = re.search(r'requires-python\s*=\s*">=\s*([0-9]+\.[0-9]+)"', text)
    assert m, "requires-python floor not found"
    assert m.group(1) == EXPECTED_PY_VERSIONS[0], (
        "the lowest CI matrix Python must equal the requires-python floor"
    )


# --------------------------------------------------------------------------
# CI workflow — matrix coverage + a dedicated, blocking ruff lint job
# --------------------------------------------------------------------------
def test_ci_matrix_covers_windows_and_linux():
    ci = _read(CI_WORKFLOW)
    m = re.search(r"os:\s*\[([^\]]*)\]", ci)
    assert m, "no `os:` matrix found in ci.yml"
    os_list = m.group(1)
    for os_name in EXPECTED_OSES:
        assert os_name in os_list, f"CI matrix must include {os_name}"


def test_ci_matrix_covers_python_310_through_314():
    ci = _read(CI_WORKFLOW)
    m = re.search(r"python-version:\s*\[([^\]]*)\]", ci)
    assert m, "no `python-version:` matrix found in ci.yml"
    versions = m.group(1)
    for ver in EXPECTED_PY_VERSIONS:
        assert f"'{ver}'" in versions or f'"{ver}"' in versions, (
            f"CI Python matrix must include {ver}; got: {versions}"
        )


def test_ci_has_dedicated_blocking_ruff_lint_job():
    ci = _read(CI_WORKFLOW)
    assert re.search(r"^\s{2}lint:", ci, re.MULTILINE), (
        "expected a dedicated 'lint' job in ci.yml"
    )
    assert "ruff check" in ci, "the lint job must run `ruff check`"
    # The ruff step must be able to fail the build: no continue-on-error may
    # decorate the step that runs the lint invocation.
    idx = ci.index("ruff check")
    step_block = ci[max(0, idx - 500):idx + 100]
    assert "continue-on-error: true" not in step_block, (
        "the ruff lint step must block the build (no continue-on-error)"
    )


def test_ci_ruff_gate_covers_required_trees():
    """The gate must lint every tree that can break something: the shipped
    package, the test tree that pins the detection claims (it sat outside and
    drifted — F25), and the scripts tree that runs in shipped CI surface (F26)."""
    paths = _ci_ruff_paths(_read(CI_WORKFLOW))
    for required in REQUIRED_LINT_PATHS:
        assert required in paths, (
            f"the CI ruff gate must lint `{required}`; it currently covers "
            f"{paths}"
        )


# --------------------------------------------------------------------------
# Mechanism — ruff is installed here and the gate really works (skips if absent)
# --------------------------------------------------------------------------
def test_repo_source_passes_its_own_ruff_gate():
    """The committed src/ tree must pass `ruff check src` under the repo config
    — i.e. the gate CI runs is currently green here."""
    argv = _ruff_argv()
    if argv is None:
        pytest.skip("ruff not installed; gate mechanism is exercised in CI")
    result = subprocess.run(
        argv + ["check", "src"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "the committed src/ tree fails its own ruff gate:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_repo_tests_tree_passes_its_own_ruff_gate():
    """The committed tests/ tree must pass `ruff check tests` — the half of the
    gate F25 added, and the half that had drifted."""
    argv = _ruff_argv()
    if argv is None:
        pytest.skip("ruff not installed; gate mechanism is exercised in CI")
    result = subprocess.run(
        argv + ["check", "tests"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "the committed tests/ tree fails its own ruff gate:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_repo_scripts_tree_passes_its_own_ruff_gate():
    """The committed scripts/ tree must pass `ruff check scripts` — the tree F26
    added. It is not inert: `action_summary.py` runs inside the shipped GitHub
    Action and `benchmark_scan.py` is imported by the perf tripwire."""
    argv = _ruff_argv()
    if argv is None:
        pytest.skip("ruff not installed; gate mechanism is exercised in CI")
    result = subprocess.run(
        argv + ["check", "scripts"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "the committed scripts/ tree fails its own ruff gate:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_repo_passes_the_exact_ci_ruff_invocation():
    """Run ruff over the paths parsed out of ci.yml itself. If the gate is later
    widened to another tree, this test lints that tree too — the CI command and
    the locally-proven-clean surface cannot drift apart."""
    argv = _ruff_argv()
    if argv is None:
        pytest.skip("ruff not installed; gate mechanism is exercised in CI")
    paths = _ci_ruff_paths(_read(CI_WORKFLOW))
    result = subprocess.run(
        argv + ["check"] + paths,
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"the repo fails the exact CI ruff gate (`ruff check {' '.join(paths)}`):\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_ruff_gate_flags_a_real_undefined_name(tmp_path):
    """An undefined-name (F821) — exactly the bug class this gate exists to
    catch — must make ruff exit non-zero under the enforced selection."""
    argv = _ruff_argv()
    if argv is None:
        pytest.skip("ruff not installed; gate mechanism is exercised in CI")
    target = tmp_path / "boom.py"
    # References a name that was never defined/imported -> F821.
    target.write_text("def f():\n    return TotallyUndefinedName\n", encoding="utf-8")
    result = subprocess.run(
        argv + ["check", "--select", "F821", str(target)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "ruff did not flag an undefined name — the gate mechanism is broken:\n"
        f"{result.stdout}\n{result.stderr}"
    )
    assert "F821" in (result.stdout + result.stderr)
