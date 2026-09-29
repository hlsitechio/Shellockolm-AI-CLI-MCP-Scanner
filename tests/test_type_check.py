"""Contract tests for the mypy type-check gate (build-loop task #45).

Task #45 asks for a static type-check pass that is **clean on the
detection-critical core** — the modular scanners (``src/scanners``, where the
agent supply-chain rules live) and the server-authoritative licensing client
(``src/licensing.py``) — and **wired into CI** as a build-blocking gate. That
contract spans two committed files:

* ``pyproject.toml`` — declares ``mypy`` as a dev dependency and is the single
  source of truth for the checked scope + strictness in ``[tool.mypy]``
  (``files``, ``mypy_path``, ``follow_imports``, ``disallow_untyped_defs``),
  shared by CI and a local bare ``mypy``.
* ``.github/workflows/ci.yml`` — a dedicated, build-blocking ``typecheck`` job
  that runs ``mypy``.

Like the ruff/coverage gates, the checked surface is a **ratchet**: it starts at
the core and is widened over time, never narrowed. These tests assert the wiring
stays intact (so the gate can't be silently removed, un-blocked, narrowed below
the core, or have its strictness gutted) and — when mypy is installed — that the
committed source actually passes its own gate and that the gate mechanism
genuinely flags a real type error. The config/workflow assertions parse file
*text* with the stdlib only, so they collect on every supported Python (3.10+)
with no extra parser dependency; the mechanism tests skip cleanly when mypy is
absent (mypy is in the ``dev`` extras, so CI always has it).
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

# The core surface the gate must check today (the ratchet floor — paths may be
# ADDED over time but these two must always remain in scope).
REQUIRED_SCOPE = ["src/scanners", "src/licensing.py"]

# Strictness flags whose removal would gut the gate (turn it into a no-op that
# accepts untyped code). They must stay enabled in [tool.mypy].
REQUIRED_STRICTNESS = ["disallow_untyped_defs", "warn_return_any"]


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


def _mypy_argv():
    """Best-effort mypy invocation, or None when mypy is not installed."""
    candidates = []
    exe = shutil.which("mypy")
    if exe:
        candidates.append([exe])
    candidates.append([sys.executable, "-m", "mypy"])
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
# pyproject.toml — mypy is a dev dependency and configured as the gate
# --------------------------------------------------------------------------
def test_mypy_is_a_dev_dependency():
    extras = _dev_extras(_read(PYPROJECT))
    assert re.search(r"^\s*[\"']mypy", extras, re.MULTILINE), (
        "mypy must be a dev dependency so `pip install .[dev]` provides the "
        "type checker in CI"
    )


def test_mypy_checks_the_core_scope():
    """The detection-critical core (scanners + licensing) must be in the
    checked `files` set — the ratchet floor that may grow but never shrink."""
    cfg = _toml_table(_read(PYPROJECT), "tool.mypy")
    m = re.search(r"files\s*=\s*\[(.*?)\]", cfg, re.DOTALL)
    assert m, "[tool.mypy] must declare a `files` scope"
    files_body = m.group(1)
    for path in REQUIRED_SCOPE:
        assert path in files_body, (
            f"[tool.mypy] files must include {path!r} (the gate's ratchet "
            f"floor); got: {files_body}"
        )


def test_mypy_resolves_flat_imports_via_mypy_path():
    """The project uses flat imports (e.g. `from vulnerability_database import
    ...`); `mypy_path = "src"` is what lets the gate resolve them from the repo
    root, so CI and a local bare `mypy` behave identically."""
    cfg = _toml_table(_read(PYPROJECT), "tool.mypy")
    assert re.search(r'mypy_path\s*=\s*"src"', cfg), (
        '[tool.mypy] must set mypy_path = "src" to resolve the project\'s flat '
        "imports from the repo root"
    )


def test_mypy_strictness_is_not_gutted():
    """The flags that make the gate meaningful (reject untyped defs / Any
    returns) must stay enabled — otherwise the gate would pass on untyped code."""
    cfg = _toml_table(_read(PYPROJECT), "tool.mypy")
    for flag in REQUIRED_STRICTNESS:
        assert re.search(rf"^\s*{flag}\s*=\s*true", cfg, re.MULTILINE), (
            f"[tool.mypy] must keep {flag} = true so the gate actually rejects "
            "untyped/loosely-typed code"
        )


# --------------------------------------------------------------------------
# CI workflow — a dedicated, build-blocking mypy typecheck job
# --------------------------------------------------------------------------
def test_ci_has_dedicated_blocking_typecheck_job():
    ci = _read(CI_WORKFLOW)
    assert re.search(r"^\s{2}typecheck:", ci, re.MULTILINE), (
        "expected a dedicated 'typecheck' job in ci.yml"
    )
    # The job must actually invoke mypy.
    m = re.search(r"^\s*run:\s*mypy\s*$", ci, re.MULTILINE)
    assert m, "the typecheck job must run `mypy` (uses the [tool.mypy] config)"
    # The mypy step must be able to fail the build: no continue-on-error may
    # decorate the step that runs the type checker.
    idx = m.start()
    step_block = ci[max(0, idx - 500):idx + 100]
    assert "continue-on-error: true" not in step_block, (
        "the mypy typecheck step must block the build (no continue-on-error)"
    )


# --------------------------------------------------------------------------
# Mechanism — mypy is installed here and the gate really works (skips if absent)
# --------------------------------------------------------------------------
def test_repo_core_passes_its_own_mypy_gate():
    """The committed scanners + licensing surface must pass `mypy` under the
    repo config — i.e. the gate CI runs is currently green here."""
    argv = _mypy_argv()
    if argv is None:
        pytest.skip("mypy not installed; gate mechanism is exercised in CI")
    result = subprocess.run(
        argv,  # bare: scope + config come from [tool.mypy]
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "the committed core fails its own mypy gate:\n"
        f"{result.stdout}\n{result.stderr}"
    )


def test_mypy_gate_flags_a_real_type_error(tmp_path):
    """A genuine type error (returning str from an int-typed function) — the
    bug class this gate exists to catch — must make mypy exit non-zero under the
    repo config."""
    argv = _mypy_argv()
    if argv is None:
        pytest.skip("mypy not installed; gate mechanism is exercised in CI")
    target = tmp_path / "boom.py"
    # Annotated to return int but returns a str -> [return-value]. This proves
    # real type analysis (not just annotation presence) under the repo config.
    target.write_text(
        "def f() -> int:\n    return 'not an int'\n", encoding="utf-8"
    )
    result = subprocess.run(
        argv + ["--config-file", str(PYPROJECT), str(target)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0, (
        "mypy did not flag an int/str return mismatch — the gate mechanism is "
        f"broken:\n{result.stdout}\n{result.stderr}"
    )
    assert "error:" in (result.stdout + result.stderr)
