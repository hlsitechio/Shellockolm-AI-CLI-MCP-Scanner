"""Tests for scan-volume stats in the scan footer (build-loop task #30).

The per-scanner artifact/unit counts (``skills_scanned``, ``packages_scanned``,
…) and the scanner count + elapsed time were already tracked on each
``ScanResult`` but were not surfaced consistently. ``aggregate_scan_stats`` rolls
them up, and both the human ``INVESTIGATION SUMMARY`` footer and the ``--json``
``summary`` block now report them.

Two layers:

* Unit tests on the pure :func:`cli.aggregate_scan_stats` helper — the
  ``_scanned``-suffix summation, scanner count, duration rounding, and the
  exclusion of non-count stats (flags, strings, finding tallies).
* End-to-end subprocess tests driving the real CLI over benign skill fixtures,
  asserting the human footer shows the new lines and the ``--json`` summary
  carries the matching counts.
"""

import json
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import cli  # noqa: E402
from scanners.base import FindingSeverity, ScanFinding, ScanResult  # noqa: E402

CLI_PY = SRC / "cli.py"


# ──────────────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────────────
def _result(scanner_name, *, stats=None, secs=0.5, findings=None):
    start = datetime(2026, 1, 1, 12, 0, 0)
    return ScanResult(
        scanner_name=scanner_name,
        scan_type="local",
        target="./skills",
        start_time=start,
        end_time=start + timedelta(seconds=secs),
        findings=list(findings or []),
        stats=dict(stats or {}),
    )


def _finding(cve_id="AGENT-PI-007", severity="HIGH"):
    return ScanFinding(
        cve_id=cve_id,
        title=f"{cve_id} title",
        severity=FindingSeverity[severity],
        cvss_score=7.5,
        package="agent-skill",
        version="n/a",
        patched_version=None,
        file_path="SKILL.md:1",
        description="desc",
        remediation="fix it",
    )


def _run_cli(*args):
    proc = subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return proc.returncode, proc.stdout, proc.stderr


# ──────────────────────────────────────────────────────────────────────────
# Unit: aggregate_scan_stats
# ──────────────────────────────────────────────────────────────────────────
def test_sums_scanned_suffix_keys_across_results():
    agg = cli.aggregate_scan_stats([
        _result("agent", stats={
            "skills_scanned": 12,
            "mcp_configs_scanned": 3,
            "n8n_workflows_scanned": 1,
            "instruction_files_scanned": 2,
        }),
        _result("npm", stats={"packages_scanned": 40}),
    ])
    assert agg["items_scanned"] == 12 + 3 + 1 + 2 + 40
    assert agg["scanners_run"] == 2


def test_scanners_run_counts_every_result():
    agg = cli.aggregate_scan_stats([_result("a"), _result("b"), _result("c")])
    assert agg["scanners_run"] == 3


def test_duration_is_summed_and_rounded():
    agg = cli.aggregate_scan_stats([
        _result("a", secs=0.51),
        _result("b", secs=1.25),
    ])
    assert agg["duration_seconds"] == 1.76


def test_excludes_non_count_stats():
    # Only keys ending in ``_scanned`` contribute. Finding tallies, the
    # confidence string, and detection flags must NOT inflate the item count.
    agg = cli.aggregate_scan_stats([
        _result("agent", stats={
            "skills_scanned": 5,
            "total_findings": 99,       # finalize() tally — not a scanned-unit count
            "critical": 7,
            "findings_suppressed": 4,
            "min_confidence": "low",    # string value
            "nextjs_detected": True,    # bool is an int subclass — must be ignored
            "detected_version": "14.0",
        }),
    ])
    assert agg["items_scanned"] == 5


def test_empty_results_are_all_zero():
    agg = cli.aggregate_scan_stats([])
    assert agg == {"items_scanned": 0, "scanners_run": 0, "duration_seconds": 0.0}


def test_result_without_scanned_stats_contributes_zero_items_but_counts_as_scanner():
    # A scanner that records no ``*_scanned`` key (e.g. only flags) still counts
    # toward scanners_run; it just adds nothing to items_scanned.
    agg = cli.aggregate_scan_stats([_result("flags-only", stats={"n8n_detected": False})])
    assert agg["items_scanned"] == 0
    assert agg["scanners_run"] == 1


# ──────────────────────────────────────────────────────────────────────────
# Unit: build_json_report propagation
# ──────────────────────────────────────────────────────────────────────────
def test_json_summary_carries_scan_volume():
    results = [
        _result("agent", stats={"skills_scanned": 8}, findings=[_finding()]),
        _result("npm", stats={"packages_scanned": 16}),
    ]
    report = cli.build_json_report(results, target="/tmp/x", scanners=["agent", "npm"])
    summary = report["summary"]
    assert summary["items_scanned"] == 24
    assert summary["scanners_run"] == 2
    # The summary count agrees with the standalone helper (single source of truth).
    agg = cli.aggregate_scan_stats(results)
    assert summary["items_scanned"] == agg["items_scanned"]
    assert summary["scanners_run"] == agg["scanners_run"]


def test_json_summary_keys_are_additive_only():
    # The new keys join the existing summary contract without dropping any.
    report = cli.build_json_report([_result("agent", stats={"skills_scanned": 1})],
                                   target="/tmp/x")
    assert {"items_scanned", "scanners_run"} <= set(report["summary"])
    assert {"total_findings", "by_severity", "findings_suppressed"} <= set(report["summary"])


# ──────────────────────────────────────────────────────────────────────────
# End-to-end: the real CLI footer
# ──────────────────────────────────────────────────────────────────────────
def _make_benign_skills(tmp_path, n):
    root = tmp_path / "skills"
    root.mkdir()
    for i in range(n):
        d = root / f"skill_{i}"
        d.mkdir()
        (d / "SKILL.md").write_text(
            f"# Tool {i}\n\nFormats your code nicely and reports versions.\n",
            encoding="utf-8",
        )
    return root


def test_human_footer_shows_scan_volume(tmp_path):
    root = _make_benign_skills(tmp_path, 3)
    code, out, _ = _run_cli("scan", "-s", "agent", str(root))
    assert "INVESTIGATION SUMMARY" in out
    assert "Items scanned" in out
    assert "Scanners run" in out
    assert code == 0  # benign → clean


def test_json_summary_reports_real_scan_volume(tmp_path):
    root = _make_benign_skills(tmp_path, 3)
    _, out, _ = _run_cli("scan", "-s", "agent", "--json", str(root))
    doc = json.loads(out)
    # Three skill artifacts were scanned by exactly one scanner.
    assert doc["summary"]["items_scanned"] >= 3
    assert doc["summary"]["scanners_run"] == 1
