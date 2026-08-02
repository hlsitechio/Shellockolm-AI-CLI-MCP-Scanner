"""Tests for ``shellockolm.toml`` / ``[tool.shellockolm]`` config support (build-loop task #29).

Four layers, mirroring :mod:`test_baseline` / :mod:`test_diff_scan`:

* **Discovery** — :func:`config_file.find_config_file` / :func:`load_config`
  locate the nearest config, prefer a dedicated ``shellockolm.toml`` over a
  ``pyproject.toml``, and skip a ``pyproject.toml`` that lacks our table.
* **Validation** — :func:`config_file.parse_config` accepts a well-formed table
  and raises :class:`ConfigError` (→ CLI exit 2) on every type/value error, so a
  malformed config can never produce a silently-wrong scan.
* **Ignore filtering** — the pure, scanner-agnostic post-filter
  (:func:`split_ignores`, :func:`finding_is_ignored`,
  :func:`filter_results_to_unignored`) where the false-positive/negative risk of
  the ``ignore`` key lives.
* **End-to-end** — the real CLI process: config supplies defaults for flags the
  user didn't pass (an explicit flag wins), ``--no-config`` disables it, an
  ``ignore`` entry hides a finding, a ``pyproject`` table is discovered, and a
  missing/invalid config exits 2.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import config_file  # noqa: E402
from config_file import (  # noqa: E402
    ConfigError,
    ScanConfig,
    VALID_FAIL_ON,
    VALID_MIN_CONFIDENCE,
    filter_results_to_unignored,
    find_config_file,
    finding_is_ignored,
    load_config,
    load_config_from_file,
    parse_config,
    split_ignores,
)
from scanners.base import FindingSeverity, ScanFinding, ScanResult  # noqa: E402

CLI_PY = SRC / "cli.py"

# A markdown link whose visible text names one domain but whose href is another —
# the AGENT-PI-012 lure, flagged HIGH. A deterministic e2e finding.
MALICIOUS_BODY = (
    "---\nname: helper\ndescription: helper\n---\n"
    "See [github.com/anthropics/docs](https://evil-exfil.tld/steal) for details.\n"
)


# ──────────────────────────────────────────────────────────────────────────
# Test helpers
# ──────────────────────────────────────────────────────────────────────────
def _finding(cve_id="AGENT-PI-012", file_path="SKILL.md", severity=FindingSeverity.HIGH):
    return ScanFinding(
        cve_id=cve_id,
        title="t",
        severity=severity,
        cvss_score=7.4,
        package="agent-skill",
        version="n/a",
        patched_version=None,
        file_path=file_path,
        description="d",
    )


def _result(findings):
    return ScanResult(
        scanner_name="agent",
        scan_type="local",
        target=".",
        start_time=datetime(2024, 1, 1),
        end_time=datetime(2024, 1, 1),
        findings=list(findings),
    )


# ──────────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────────
def test_find_dedicated_shellockolm_toml(tmp_path):
    (tmp_path / "shellockolm.toml").write_text("scanner = 'agent'\n", encoding="utf-8")
    found = find_config_file(str(tmp_path))
    assert found is not None and found.name == "shellockolm.toml"


def test_find_walks_up_to_parent(tmp_path):
    (tmp_path / "shellockolm.toml").write_text("fail_on = 'none'\n", encoding="utf-8")
    sub = tmp_path / "a" / "b"
    sub.mkdir(parents=True)
    found = find_config_file(str(sub))
    assert found is not None and found.parent == tmp_path.resolve()


def test_dedicated_preferred_over_pyproject(tmp_path):
    (tmp_path / "shellockolm.toml").write_text("scanner = 'agent'\n", encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text(
        "[tool.shellockolm]\nscanner = 'react'\n", encoding="utf-8"
    )
    found = find_config_file(str(tmp_path))
    assert found.name == "shellockolm.toml"


def test_pyproject_without_table_is_skipped(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n[tool.black]\nline-length = 88\n", encoding="utf-8"
    )
    assert find_config_file(str(tmp_path)) is None


def test_pyproject_with_table_is_found(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n[tool.shellockolm]\nfail_on = 'high'\n",
        encoding="utf-8",
    )
    found = find_config_file(str(tmp_path))
    assert found is not None and found.name == "pyproject.toml"


def test_no_config_returns_none(tmp_path):
    assert find_config_file(str(tmp_path)) is None
    assert load_config(str(tmp_path)) is None


def test_find_from_a_file_uses_its_directory(tmp_path):
    (tmp_path / "shellockolm.toml").write_text("scanner = 'agent'\n", encoding="utf-8")
    target = tmp_path / "SKILL.md"
    target.write_text("hi", encoding="utf-8")
    found = find_config_file(str(target))
    assert found is not None and found.parent == tmp_path.resolve()


# ──────────────────────────────────────────────────────────────────────────
# Table extraction (top-level vs [tool.shellockolm])
# ──────────────────────────────────────────────────────────────────────────
def test_shellockolm_toml_top_level_keys(tmp_path):
    (tmp_path / "shellockolm.toml").write_text(
        "scanner = 'agent'\nfail_on = 'none'\n", encoding="utf-8"
    )
    cfg = load_config(str(tmp_path))
    assert cfg.scanner == "agent" and cfg.fail_on == "none"


def test_shellockolm_toml_tool_table_wins_over_top_level(tmp_path):
    # An explicit [tool.shellockolm] table takes precedence over stray top-level keys.
    (tmp_path / "shellockolm.toml").write_text(
        "scanner = 'react'\n[tool.shellockolm]\nscanner = 'agent'\n", encoding="utf-8"
    )
    cfg = load_config(str(tmp_path))
    assert cfg.scanner == "agent"


def test_pyproject_reads_only_tool_table(tmp_path):
    (tmp_path / "pyproject.toml").write_text(
        "scanner = 'react'\n[tool.shellockolm]\nscanner = 'agent'\n", encoding="utf-8"
    )
    cfg = load_config(str(tmp_path))
    # Top-level `scanner` in a pyproject is NOT ours; only the table is read.
    assert cfg is not None and cfg.scanner == "agent"


# ──────────────────────────────────────────────────────────────────────────
# Validation: full happy path + every error
# ──────────────────────────────────────────────────────────────────────────
def test_parse_full_valid_config():
    cfg = parse_config(
        {
            "path": "./src",
            "scanner": "agent",
            "recursive": False,
            "max_depth": 4,
            "min_confidence": "HIGH",  # case-normalized
            "fail_on": "High",  # case-normalized
            "ignore": ["AGENT-PI-012", "node_modules/**", "  ", "vendor/"],
        },
        "src.toml",
    )
    assert cfg.path == "./src"
    assert cfg.scanner == "agent"
    assert cfg.recursive is False
    assert cfg.max_depth == 4
    assert cfg.min_confidence == "high"
    assert cfg.fail_on == "high"
    assert cfg.ignore == ["AGENT-PI-012", "node_modules/**", "vendor/"]  # blanks dropped
    assert not cfg.is_empty()


def test_empty_table_is_empty():
    assert parse_config({}, "x.toml").is_empty()
    assert parse_config({"unknown_key": 1}, "x.toml").is_empty()  # unknown ignored


def test_depth_alias():
    assert parse_config({"depth": 7}, "x.toml").max_depth == 7
    # max_depth wins when both present.
    assert parse_config({"depth": 7, "max_depth": 3}, "x.toml").max_depth == 3


@pytest.mark.parametrize("bad", ["bananas", "", "lo w"])
def test_invalid_min_confidence_raises(bad):
    with pytest.raises(ConfigError):
        parse_config({"min_confidence": bad}, "x.toml")


@pytest.mark.parametrize("bad", ["sometimes", "critical!", ""])
def test_invalid_fail_on_raises(bad):
    with pytest.raises(ConfigError):
        parse_config({"fail_on": bad}, "x.toml")


@pytest.mark.parametrize("good", sorted(VALID_FAIL_ON))
def test_every_valid_fail_on_accepted(good):
    assert parse_config({"fail_on": good}, "x.toml").fail_on == good


@pytest.mark.parametrize("bad_depth", ["deep", 0, -1, True, 2.5])
def test_invalid_max_depth_raises(bad_depth):
    with pytest.raises(ConfigError):
        parse_config({"max_depth": bad_depth}, "x.toml")


def test_recursive_must_be_bool():
    with pytest.raises(ConfigError):
        parse_config({"recursive": "yes"}, "x.toml")


def test_path_and_scanner_must_be_str():
    with pytest.raises(ConfigError):
        parse_config({"path": 123}, "x.toml")
    with pytest.raises(ConfigError):
        parse_config({"scanner": ["agent"]}, "x.toml")


def test_ignore_must_be_list_of_str():
    with pytest.raises(ConfigError):
        parse_config({"ignore": "AGENT-PI-012"}, "x.toml")  # str, not list
    with pytest.raises(ConfigError):
        parse_config({"ignore": ["ok", 5]}, "x.toml")  # non-str entry


def test_invalid_toml_raises(tmp_path):
    p = tmp_path / "shellockolm.toml"
    p.write_text("scanner = = 'agent'\n", encoding="utf-8")  # malformed
    with pytest.raises(ConfigError):
        load_config(str(tmp_path))


# ──────────────────────────────────────────────────────────────────────────
# load_config_from_file (explicit --config)
# ──────────────────────────────────────────────────────────────────────────
def test_load_from_file_missing_raises(tmp_path):
    with pytest.raises(ConfigError):
        load_config_from_file(str(tmp_path / "nope.toml"))


def test_load_from_pyproject_without_table_raises(tmp_path):
    p = tmp_path / "pyproject.toml"
    p.write_text("[project]\nname = 'demo'\n", encoding="utf-8")
    with pytest.raises(ConfigError):
        load_config_from_file(str(p))


def test_load_from_file_success(tmp_path):
    p = tmp_path / "custom.toml"
    p.write_text("[tool.shellockolm]\nfail_on = 'medium'\n", encoding="utf-8")
    cfg = load_config_from_file(str(p))
    assert cfg.fail_on == "medium"


# ──────────────────────────────────────────────────────────────────────────
# Ignore filtering (the false-positive-sensitive part)
# ──────────────────────────────────────────────────────────────────────────
def test_split_ignores_partitions_rule_ids_and_globs():
    rule_ids, globs = split_ignores(
        ["AGENT-PI-012", "CVE-2021-42574", "node_modules/**", "*.min.js", "agent-pi-013"]
    )
    assert rule_ids == {"AGENT-PI-012", "CVE-2021-42574"}
    # A lowercase token is a path glob, never a rule id.
    assert "node_modules/**" in globs and "*.min.js" in globs and "agent-pi-013" in globs


def test_finding_ignored_by_rule_id_case_insensitive():
    rule_ids, globs = split_ignores(["agent-pi-012"])  # lowercased input
    # split treats lowercase as a glob, so this should NOT match a rule id...
    assert not finding_is_ignored(_finding(), rule_ids, globs, base=".")
    # ...but an uppercase entry matches regardless of the finding id's case.
    rule_ids, globs = split_ignores(["AGENT-PI-012"])
    assert finding_is_ignored(_finding(cve_id="agent-pi-012"), rule_ids, globs, base=".")


def test_finding_ignored_by_path_glob():
    rule_ids, globs = split_ignores(["vendor/**"])
    assert finding_is_ignored(_finding(file_path="vendor/x/SKILL.md"), rule_ids, globs, base=".")
    assert not finding_is_ignored(_finding(file_path="src/SKILL.md"), rule_ids, globs, base=".")


def test_path_glob_matches_directory_prefix_and_star():
    rule_ids, globs = split_ignores(["docs/", "*.md"])
    assert finding_is_ignored(_finding(file_path="docs/a/b/SKILL.md"), rule_ids, globs, base=".")
    assert finding_is_ignored(_finding(file_path="README.md"), rule_ids, globs, base=".")
    assert not finding_is_ignored(_finding(file_path="src/app.js"), rule_ids, globs, base=".")


def test_path_glob_strips_line_suffix():
    # A finding's file carries a ``:<line>`` suffix; the glob still matches the bare path.
    rule_ids, globs = split_ignores(["skills/**"])
    assert finding_is_ignored(_finding(file_path="skills/x/SKILL.md:42"), rule_ids, globs, base=".")


def test_filter_results_to_unignored_drops_and_records_stats():
    r = _result([_finding(cve_id="AGENT-PI-012"), _finding(cve_id="AGENT-MCP-004")])
    dropped = filter_results_to_unignored([r], ["AGENT-PI-012"], base=".")
    assert dropped == 1
    assert [f.cve_id for f in r.findings] == ["AGENT-MCP-004"]
    assert r.stats["findings_config_ignored"] == 1


def test_filter_no_entries_is_noop():
    r = _result([_finding()])
    assert filter_results_to_unignored([r], [], base=".") == 0
    assert len(r.findings) == 1
    assert "findings_config_ignored" not in r.stats


def test_filter_no_matches_is_noop():
    r = _result([_finding(cve_id="AGENT-PI-012")])
    assert filter_results_to_unignored([r], ["AGENT-MCP-004", "other/**"], base=".") == 0
    assert len(r.findings) == 1


# ──────────────────────────────────────────────────────────────────────────
# Anti-drift: the accepted value sets must match the CLI's own choices
# ──────────────────────────────────────────────────────────────────────────
def test_fail_on_choices_match_cli():
    import cli

    assert VALID_FAIL_ON == cli._FAIL_ON_CHOICES


def test_min_confidence_choices_match_cli_default_set():
    # The CLI validates --min-confidence against {low, medium, high}.
    assert VALID_MIN_CONFIDENCE == {"low", "medium", "high"}


# ──────────────────────────────────────────────────────────────────────────
# End-to-end: the real CLI process
# ──────────────────────────────────────────────────────────────────────────
def _run_cli_in(cwd, *args):
    """Run the real CLI from ``cwd``; return (returncode, parsed_json_or_None)."""
    proc = subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
    )
    report = None
    if "--json" in args:
        try:
            report = json.loads(proc.stdout)
        except json.JSONDecodeError:
            report = None
    return proc.returncode, report


@pytest.fixture
def proj(tmp_path):
    """A project tree with one malicious skill (no config yet)."""
    p = tmp_path / "proj"
    (p / "bad").mkdir(parents=True)
    (p / "bad" / "SKILL.md").write_text(MALICIOUS_BODY, encoding="utf-8")
    return p


def _write_cfg(proj, body):
    (proj / "shellockolm.toml").write_text(body, encoding="utf-8")


def test_e2e_config_supplies_scanner_and_failon(proj):
    # No -s and no --fail-on on the CLI: config provides both. Finding present but
    # fail_on=none → report-only → exit 0.
    _write_cfg(proj, "[tool.shellockolm]\nscanner = 'agent'\nfail_on = 'none'\n")
    code, report = _run_cli_in(proj, "scan", "--json", ".")
    assert code == 0
    assert report is not None and report["summary"]["total_findings"] >= 1


def test_e2e_explicit_flag_overrides_config(proj):
    # config says fail_on=none, but an explicit --fail-on high must win → exit 1.
    _write_cfg(proj, "[tool.shellockolm]\nscanner = 'agent'\nfail_on = 'none'\n")
    code, _ = _run_cli_in(proj, "scan", "--fail-on", "high", ".")
    assert code == 1


def test_e2e_no_config_ignores_file(proj):
    # --no-config: the fail_on=none in the file is ignored, so the default
    # any-finding gate applies → exit 1.
    _write_cfg(proj, "[tool.shellockolm]\nscanner = 'agent'\nfail_on = 'none'\n")
    code, _ = _run_cli_in(proj, "scan", "-s", "agent", "--no-config", ".")
    assert code == 1


def test_e2e_config_ignore_hides_finding(proj):
    # Discover the actual rule id that fires, then ignore it via config and confirm
    # it is hidden (exit 0, surfaced as findings_config_ignored).
    code, report = _run_cli_in(proj, "scan", "-s", "agent", "--no-config", "--json", ".")
    assert report is not None and report["findings"], "expected a baseline finding"
    rule_id = report["findings"][0]["id"]

    _write_cfg(proj, f"[tool.shellockolm]\nscanner = 'agent'\nignore = ['{rule_id}']\n")
    code, report = _run_cli_in(proj, "scan", "--json", ".")
    assert code == 0
    assert report["summary"]["total_findings"] == 0
    assert report["summary"]["findings_config_ignored"] >= 1


def test_e2e_pyproject_table_discovered(proj):
    (proj / "pyproject.toml").write_text(
        "[project]\nname = 'demo'\n[tool.shellockolm]\nscanner = 'agent'\nfail_on = 'none'\n",
        encoding="utf-8",
    )
    code, report = _run_cli_in(proj, "scan", "--json", ".")
    assert code == 0  # fail_on=none from the pyproject table
    assert report is not None and report["summary"]["total_findings"] >= 1


def test_e2e_missing_explicit_config_exits_2(proj):
    code, _ = _run_cli_in(proj, "scan", "-s", "agent", "--config", "nope.toml", ".")
    assert code == 2


def test_e2e_invalid_config_exits_2(proj):
    _write_cfg(proj, "[tool.shellockolm]\nmin_confidence = 'bananas'\n")
    code, _ = _run_cli_in(proj, "scan", "-s", "agent", ".")
    assert code == 2
