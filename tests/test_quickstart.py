"""Tests for the 60-second quickstart (build-loop task #49).

The quickstart is a documentation promise — *install → scan → finding in three
commands* — so this suite is the regression net that keeps the promise true and
stops the docs from drifting away from real behaviour:

* **Demo integrity** — ``examples/vulnerable-demo`` pins ``next`` to a version the
  Next.js scanner actually flags (and a one-bump-higher version it does NOT), so
  the demo can neither silently go safe nor have its "upgrade to fix" claim rot.
* **CI safety** — the demo is not an agent artifact, so the repo's agent-only
  self-scan gate (task #43) never flags it.
* **Commands work as written** — the exact documented ``shellockolm scan`` /
  ``info`` commands run through the real CLI process and produce the documented
  finding + exit code.
* **Docs in sync** — the README + QUICKSTART carry the canonical commands and the
  real (not fabricated) finding output, and ``docs/quickstart.cast`` is a valid
  asciinema v2 recording that stays byte-identical to its generator.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC = REPO_ROOT / "src"
SCRIPTS = REPO_ROOT / "scripts"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from scanners.nextjs import NextJSScanner  # noqa: E402
from scanners.agent_supply_chain import AgentSupplyChainScanner  # noqa: E402
import generate_quickstart_cast as cast_gen  # noqa: E402

CLI_PY = SRC / "cli.py"
DEMO_DIR = REPO_ROOT / "examples" / "vulnerable-demo"
DEMO_PKG = DEMO_DIR / "package.json"
CAST_PATH = REPO_ROOT / "docs" / "quickstart.cast"
README = REPO_ROOT / "README.md"
QUICKSTART = REPO_ROOT / "docs" / "QUICKSTART.md"

# The CVE the demo is built to surface.
DEMO_CVE = "CVE-2025-29927"
# The exact vulnerable version the demo pins, and the patched one that fixes it.
DEMO_VULN_VERSION = "15.2.2"
DEMO_FIXED_VERSION = "15.2.3"


def _run_cli(*args):
    """Run the real CLI from the repo root; return the CompletedProcess."""
    return subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
    )


# ──────────────────────────────────────────────────────────────────────────
# Demo project integrity
# ──────────────────────────────────────────────────────────────────────────
def test_demo_files_exist():
    assert DEMO_PKG.is_file(), "quickstart demo package.json is missing"
    assert (DEMO_DIR / "README.md").is_file(), "demo README is missing"


def test_demo_pins_the_vulnerable_version():
    data = json.loads(DEMO_PKG.read_text(encoding="utf-8"))
    assert data.get("dependencies", {}).get("next") == DEMO_VULN_VERSION


def test_pinned_version_is_actually_flagged_but_the_fix_is_not():
    """The demo can't silently go safe, and 'upgrade to 15.2.3 fixes it' holds."""
    scanner = NextJSScanner()
    assert scanner._is_middleware_bypass_vulnerable(DEMO_VULN_VERSION) is True
    assert scanner._is_middleware_bypass_vulnerable(DEMO_FIXED_VERSION) is False


def test_demo_is_not_an_agent_artifact():
    """The agent-only self-scan CI gate must never flag the demo (task #43)."""
    result = AgentSupplyChainScanner(pro=True).scan_directory(str(DEMO_DIR))
    assert result.findings == [], "demo must produce zero agent-scanner findings"


# ──────────────────────────────────────────────────────────────────────────
# The documented commands work exactly as written
# ──────────────────────────────────────────────────────────────────────────
def test_documented_scan_reports_the_cve_and_exits_one():
    """`shellockolm scan examples/vulnerable-demo` → CVE + exit 1 (the README path)."""
    proc = _run_cli("scan", "examples/vulnerable-demo")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert DEMO_CVE in proc.stdout


def test_scoped_nextjs_scan_is_a_clean_single_critical():
    """`-s nextjs` is deterministic + machine-independent: exactly the demo CVE."""
    proc = _run_cli("scan", "-s", "nextjs", "examples/vulnerable-demo")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert DEMO_CVE in proc.stdout
    assert "Next.js Middleware Authorization Bypass" in proc.stdout


def test_documented_info_command_explains_the_cve():
    """`shellockolm info CVE-2025-29927` → CRITICAL/CVSS 9.1 detail, exit 0."""
    proc = _run_cli("info", DEMO_CVE)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert DEMO_CVE in proc.stdout
    assert "9.1" in proc.stdout


# ──────────────────────────────────────────────────────────────────────────
# Docs carry the canonical commands and honest output
# ──────────────────────────────────────────────────────────────────────────
def test_readme_documents_the_three_commands():
    text = README.read_text(encoding="utf-8")
    assert "pip install -e ." in text
    assert "shellockolm scan examples/vulnerable-demo" in text
    assert f"shellockolm info {DEMO_CVE}" in text


def test_readme_shows_the_real_finding_not_a_fabricated_one():
    text = README.read_text(encoding="utf-8")
    assert DEMO_CVE in text
    assert "Next.js Middleware Authorization Bypass" in text


def test_quickstart_doc_dropped_the_fabricated_output():
    """The old QUICKSTART box invented '3 vulnerabilities' and mislabelled the CVE
    as HIGH (it is CRITICAL/9.1) — that fabrication must be gone."""
    text = QUICKSTART.read_text(encoding="utf-8")
    assert "Scan Complete - Found 3 vulnerabilities" not in text
    assert "🟡 HIGH: Next.js middleware bypass" not in text
    assert "shellockolm scan examples/vulnerable-demo" in text


# ──────────────────────────────────────────────────────────────────────────
# The asciinema cast is valid and in sync with its generator
# ──────────────────────────────────────────────────────────────────────────
def test_cast_exists_and_is_in_sync_with_generator():
    """`generate_quickstart_cast.py --check` is a CI drift gate — prove it's clean."""
    assert CAST_PATH.is_file()
    assert CAST_PATH.read_text(encoding="utf-8") == cast_gen.render()


def test_cast_is_valid_asciinema_v2():
    lines = CAST_PATH.read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[0])
    assert header["version"] == 2
    assert isinstance(header["width"], int) and isinstance(header["height"], int)
    # Every subsequent line is an output event: [time(float), "o", data(str)].
    for line in lines[1:]:
        evt = json.loads(line)
        assert isinstance(evt, list) and len(evt) == 3
        assert isinstance(evt[0], (int, float))
        assert evt[1] == "o"
        assert isinstance(evt[2], str)


def test_cast_actually_shows_the_finding():
    """The recording's terminal stream must contain the real finding."""
    lines = CAST_PATH.read_text(encoding="utf-8").splitlines()
    stream = "".join(json.loads(line)[2] for line in lines[1:])
    assert DEMO_CVE in stream
    assert "shellockolm scan examples/vulnerable-demo" in stream


def test_cast_check_mode_has_teeth(tmp_path, monkeypatch):
    """A perturbed committed cast must make --check fail (the gate isn't vacuous)."""
    bogus = tmp_path / "quickstart.cast"
    bogus.write_text(cast_gen.render() + "tampered\n", encoding="utf-8")
    monkeypatch.setattr(cast_gen, "CAST_PATH", bogus)
    assert cast_gen.main(["--check"]) == 1
