"""Tests for the ``F841`` (unused-variable) closure — follow-up F28.

F28 closed the last genuine-bug family left in the ruff ignore list. An
assigned-but-unused variable is often a *dropped result*, and reviewing all 20
sites individually surfaced several real defects, all of the same shape F27
closed for the sandbox path: **something that did not happen is reported as
though it did.**

The behaviour-bearing fixes pinned here:

* ``mcp_server`` read the documented ``exclude_node_modules`` tool input and
  threw it away. Every registered scanner excludes ``node_modules``
  unconditionally (``BaseScanner.EXCLUDE_DIRS``), so a caller passing ``false``
  — asking for the installed dependency tree, exactly where a supply-chain
  payload lands — got a scan that never looked there and no indication of it.
  The scan now always states its real scope and says plainly when the request
  was not honored.
* ``MalwareAnalyzer.scan_file`` / ``scan_package_json`` and
  ``MalwareScanner._scan_project`` swallowed read/parse failures, so an
  unreadable file returned zero matches — indistinguishable from clean. The
  skip is now recorded and surfaced on the report.
* The three ``MalwareAnalyzer`` remediation paths returned ``False`` but
  discarded *why*, so a permission error looked like a vanished file.
* ``SarifGenerator.from_malware_report`` computed the analyzer's malware
  classification and dropped it before writing SARIF.

:func:`test_src_tree_has_no_unused_locals` is the mechanism guard: it re-runs
the rule over the shipped tree so the family cannot quietly reopen.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

import mcp_server
from malware_analyzer import AnalysisReport, MalwareAnalyzer
from malware_scanner import MalwareScanner
from sarif_output import SarifGenerator


# --------------------------------------------------------------------------
# mcp_server: the discarded exclude_node_modules input
# --------------------------------------------------------------------------

@pytest.mark.parametrize("raw,expected", [
    (True, True),
    (False, False),
    (None, True),          # absent -> the scanners' real behaviour
    ("false", False),
    ("FALSE", False),
    (" no ", False),
    ("0", False),
    ("off", False),
    ("", True),            # unparseable -> never claim more coverage
    ("true", True),
    ("yes", True),
    (object(), True),
])
def test_normalize_exclude_node_modules(raw, expected):
    assert mcp_server.normalize_exclude_node_modules(raw) is expected


def test_scope_note_states_exclusion_by_default():
    note = mcp_server.node_modules_scope_note(True)
    assert "node_modules" in note
    assert "excluded" in note.lower()


def test_scope_note_says_the_request_was_not_honored():
    """The whole point: a false input must not silently narrow the scan."""
    note = mcp_server.node_modules_scope_note(False)
    assert "NOT honored" in note
    assert "did **not**" in note
    # It must not leave the reader thinking dependencies were cleared.
    assert "not evidence" in note


def test_scope_note_never_claims_node_modules_was_scanned():
    for value in (True, False):
        note = mcp_server.node_modules_scope_note(value)
        assert "scanned node_modules" not in note.lower()


@pytest.mark.parametrize("tool", ["quick_scan", "scan_directory"])
def test_tool_schema_documents_the_unconditional_exclusion(tool):
    """The advertised description must match what the scanner actually does."""
    import asyncio

    tools = asyncio.run(mcp_server.handle_list_tools())
    spec = next(t for t in tools if t.name == tool)
    desc = spec.inputSchema["properties"]["exclude_node_modules"]["description"]
    assert "unconditionally" in desc


@pytest.mark.parametrize("tool", ["quick_scan", "scan_directory"])
def test_scan_output_carries_the_scope_note(tmp_path, tool):
    """End to end: the caller sees the scope caveat in the tool result."""
    import asyncio

    (tmp_path / "package.json").write_text(
        json.dumps({"name": "benign", "version": "1.0.0", "dependencies": {}}),
        encoding="utf-8",
    )

    out = asyncio.run(mcp_server.handle_call_tool(
        tool, {"path": str(tmp_path), "exclude_node_modules": False}
    ))
    text = "".join(block.text for block in out)
    assert "NOT honored" in text

    out_default = asyncio.run(mcp_server.handle_call_tool(
        tool, {"path": str(tmp_path)}
    ))
    text_default = "".join(block.text for block in out_default)
    assert "NOT honored" not in text_default
    assert "node_modules" in text_default


# --------------------------------------------------------------------------
# malware_analyzer: a skipped file is not a clean file
# --------------------------------------------------------------------------

def test_unreadable_file_is_recorded_not_silently_clean(tmp_path, monkeypatch):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    target = tmp_path / "app.js"
    target.write_text("console.log(1)", encoding="utf-8")

    def boom(*args, **kwargs):
        raise OSError("device busy")

    monkeypatch.setattr(Path, "read_text", boom)

    matches = analyzer.scan_file(target)

    assert matches == []                      # looks clean...
    assert len(analyzer.read_errors) == 1     # ...but the skip is visible
    assert "app.js" in analyzer.read_errors[0]
    assert "OSError" in analyzer.read_errors[0]


def test_unparseable_package_json_is_recorded(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    pkg = tmp_path / "package.json"
    pkg.write_text("{ not valid json", encoding="utf-8")

    matches = analyzer.scan_package_json(pkg)

    assert matches == []
    assert len(analyzer.read_errors) == 1
    assert "package.json" in analyzer.read_errors[0]


def test_read_errors_are_capped_but_the_overflow_is_counted(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    for i in range(analyzer.MAX_RECORDED_ERRORS + 7):
        analyzer._record_read_error(f"f{i}.js", OSError("nope"))

    assert len(analyzer.read_errors) == analyzer.MAX_RECORDED_ERRORS
    assert analyzer.read_errors_suppressed == 7


def test_scan_directory_surfaces_errors_on_the_report(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    (tmp_path / "package.json").write_text("{ broken", encoding="utf-8")

    report = analyzer.scan_directory(str(tmp_path))

    assert report.matches == []
    assert report.errors, "an unparseable package.json must not read as clean"


def test_scan_directory_resets_errors_between_scans(tmp_path):
    """One scan's skipped files must not be attributed to the next."""
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    dirty = tmp_path / "dirty"
    dirty.mkdir()
    (dirty / "package.json").write_text("{ broken", encoding="utf-8")

    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "package.json").write_text(
        json.dumps({"name": "ok", "version": "1.0.0"}), encoding="utf-8"
    )

    assert analyzer.scan_directory(str(dirty)).errors
    assert analyzer.scan_directory(str(clean)).errors == []


def test_clean_scan_reports_no_errors(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "benign", "version": "1.0.0"}), encoding="utf-8"
    )
    (tmp_path / "index.js").write_text("export const x = 1;\n", encoding="utf-8")

    report = analyzer.scan_directory(str(tmp_path))

    assert report.errors == []
    assert report.matches == []


# --------------------------------------------------------------------------
# malware_analyzer: remediation failures keep their reason
# --------------------------------------------------------------------------

def test_quarantine_failure_records_the_reason(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    report = AnalysisReport(scan_id="abc123")

    # A directory where a file is expected: the move fails inside the try.
    victim = tmp_path / "notafile"
    victim.mkdir()

    assert analyzer.quarantine_file(str(victim), report) is False
    assert report.errors
    assert "quarantine failed" in report.errors[0]


def test_clean_failure_records_the_reason(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    report = AnalysisReport(scan_id="abc123")

    # Exists (so it clears the missing-file guard) but cannot be read as text.
    victim = tmp_path / "adirectory.js"
    victim.mkdir()

    assert analyzer.clean_malicious_code(str(victim), [], report) is False
    assert report.errors
    assert "clean failed" in report.errors[0]


def test_clean_missing_file_is_a_guard_not_an_error(tmp_path):
    """The early missing-file return is a legitimate guard, not a failure."""
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    report = AnalysisReport(scan_id="abc123")

    assert analyzer.clean_malicious_code(str(tmp_path / "gone.js"), [], report) is False
    assert report.errors == []


def test_remove_package_failure_records_the_reason(tmp_path):
    analyzer = MalwareAnalyzer(quarantine_dir=str(tmp_path / "q"))
    report = AnalysisReport(scan_id="abc123")

    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text("{ not json", encoding="utf-8")

    assert analyzer.remove_package("evil-pkg", str(project), report) is False
    assert report.errors
    assert "package removal failed" in report.errors[0]
    assert "evil-pkg" not in report.removed_packages


def test_analysis_report_errors_defaults_empty():
    assert AnalysisReport().errors == []


# --------------------------------------------------------------------------
# malware_scanner: an unparseable project is not a clean project
# --------------------------------------------------------------------------

def test_npm_scanner_records_unparseable_package_json(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text("{ broken", encoding="utf-8")

    scanner = MalwareScanner()
    report = scanner.scan_directory(str(tmp_path))

    assert report["errors"], "an unparseable package.json must be reported"
    assert "package.json" in report["errors"][0]


def test_npm_scanner_clean_project_has_no_errors(tmp_path):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "package.json").write_text(
        json.dumps({"name": "ok", "version": "1.0.0", "dependencies": {}}),
        encoding="utf-8",
    )

    scanner = MalwareScanner()
    report = scanner.scan_directory(str(tmp_path))

    assert report["errors"] == []
    assert report["infected_projects"] == 0


# --------------------------------------------------------------------------
# sarif_output: the malware classification survives into SARIF
# --------------------------------------------------------------------------

def test_malware_type_becomes_a_rule_tag():
    gen = SarifGenerator()
    gen.add_malware_finding(
        pattern_id="P1",
        pattern_name="Credential Stealer",
        file_path="a.js",
        line_number=3,
        message="steals creds",
        severity="critical",
        malware_type="CREDENTIAL_THEFT",
    )
    rule = gen.rules["MALWARE-P1"]
    assert "credential_theft" in rule.tags
    assert "malware" in rule.tags


def test_malware_finding_without_type_is_unchanged():
    """Existing callers must serialize byte-identically."""
    gen = SarifGenerator()
    gen.add_malware_finding(
        pattern_id="P1",
        pattern_name="Generic",
        file_path="a.js",
        line_number=1,
        message="m",
    )
    assert gen.rules["MALWARE-P1"].tags == ["security", "malware"]


# --------------------------------------------------------------------------
# mechanism guard
# --------------------------------------------------------------------------

def test_src_tree_has_no_unused_locals():
    """F841 must stay closed across the shipped tree.

    An assigned-but-unused local is how a computed result gets dropped on the
    floor; this pass found one in the MCP surface that silently narrowed a
    security scan. Re-running the rule directly means the guard holds even if
    the ruff ignore list is edited.
    """
    proc = subprocess.run(
        [sys.executable, "-m", "ruff", "check", "src", "tests", "scripts",
         "--isolated", "--select", "F841", "--output-format", "concise"],
        cwd=REPO_ROOT, capture_output=True, text=True,
    )
    assert proc.returncode == 0, (
        "F841 (unused-variable) reappeared — an assigned-but-unused local is "
        "often a dropped result, not dead weight. Review the site rather than "
        f"silencing the rule:\n{proc.stdout}{proc.stderr}"
    )
