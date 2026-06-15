"""Tests for ``shellockolm doctor`` — environment self-check (build-loop task #28).

Three layers:

* **Unit** — the pure, exception-safe check functions in :mod:`doctor`
  (Python floor, detection-database / agent-rule-catalog population, the
  writable probe, the git/license probes) plus the :class:`DoctorReport`
  health/counts/serialization logic, where the real risk lives.
* **Exit-code mapping** — the CLI ``doctor`` command maps ``report.healthy`` to
  exit 0 (healthy) / 1 (a FAILED check), driven in-process with
  :func:`doctor.run_checks` monkeypatched so a FAIL is deterministic without a
  broken interpreter.
* **End-to-end** — the real CLI process: ``doctor`` exits 0 on this (healthy)
  machine, and ``doctor --json`` emits ONE pure JSON document on stdout (no
  banner leakage) with the documented schema.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import typer

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import cli  # noqa: E402
import doctor  # noqa: E402
from doctor import (  # noqa: E402
    FAIL,
    INFO,
    OK,
    WARN,
    Check,
    DoctorReport,
    check_agent_rules,
    check_config_writable,
    check_detection_database,
    check_git,
    check_license,
    check_python,
    check_temp_writable,
    run_checks,
)

CLI_PY = SRC / "cli.py"


def _run_cli(*args):
    """Run the real CLI in a subprocess; return (exit_code, stdout, stderr)."""
    proc = subprocess.run(
        [sys.executable, str(CLI_PY), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return proc.returncode, proc.stdout, proc.stderr


# ──────────────────────────────────────────────────────────────────────────
# Unit — Python runtime floor
# ──────────────────────────────────────────────────────────────────────────
def test_python_check_ok_for_current_interpreter():
    c = check_python()
    assert c.status == OK
    assert c.hint is None


def test_python_check_ok_at_exact_floor():
    c = check_python(version_info=(3, 10, 0))
    assert c.status == OK


def test_python_check_fails_below_floor():
    c = check_python(version_info=(3, 9, 18))
    assert c.status == FAIL
    assert "3.9.18" in c.detail
    assert c.hint and "3.10" in c.hint


def test_python_check_ok_for_future_major():
    assert check_python(version_info=(4, 0, 0)).status == OK


# ──────────────────────────────────────────────────────────────────────────
# Unit — install integrity (detection DB + agent rules)
# ──────────────────────────────────────────────────────────────────────────
def test_detection_database_loads_and_is_populated():
    c = check_detection_database()
    assert c.status == OK
    assert "CVE" in c.detail
    # The number reported must match the real bundled database.
    from vulnerability_database import VulnerabilityDatabase

    assert str(len(VulnerabilityDatabase.get_all_vulnerabilities())) in c.detail


def test_agent_rules_load_and_report_tier_split():
    c = check_agent_rules()
    assert c.status == OK
    from scanners.agent_supply_chain import agent_rule_catalog

    cat = agent_rule_catalog()
    assert str(len(cat)) in c.detail
    assert "free" in c.detail and "Pro" in c.detail


# ──────────────────────────────────────────────────────────────────────────
# Unit — writable probes
# ──────────────────────────────────────────────────────────────────────────
def test_config_writable_ok_on_temp_home(tmp_path):
    c = check_config_writable(home=tmp_path)
    assert c.status == OK
    assert ".shellockolm" in c.detail
    # The probe file must be cleaned up (no leftover artifacts).
    assert list((tmp_path / ".shellockolm").glob("*.tmp")) == []


def test_config_writable_warns_when_uncreatable(tmp_path):
    # A regular file standing where the parent dir must be → mkdir fails.
    blocker = tmp_path / "blocker"
    blocker.write_text("i am a file", encoding="utf-8")
    c = check_config_writable(home=blocker)
    assert c.status == WARN
    assert c.hint  # actionable
    # A perms problem must NOT make the install unhealthy.
    assert DoctorReport(checks=[c]).healthy is True


def test_temp_writable_ok(tmp_path):
    c = check_temp_writable(tmp_root=tmp_path / "logs")
    assert c.status == OK


def test_temp_writable_warns_when_uncreatable(tmp_path):
    blocker = tmp_path / "f"
    blocker.write_text("x", encoding="utf-8")
    c = check_temp_writable(tmp_root=blocker / "sub")
    assert c.status == WARN


# ──────────────────────────────────────────────────────────────────────────
# Unit — git + license probes
# ──────────────────────────────────────────────────────────────────────────
def test_git_check_ok_when_found():
    c = check_git(which=lambda _: "/usr/bin/git")
    assert c.status == OK
    assert "/usr/bin/git" in c.detail


def test_git_check_warns_when_missing():
    c = check_git(which=lambda _: None)
    assert c.status == WARN
    assert c.hint and "--diff" in c.hint
    # git missing is a degradation, never a hard failure.
    assert DoctorReport(checks=[c]).healthy is True


def test_license_check_is_informational_and_never_fails(monkeypatch, tmp_path):
    # Hermetic: no key in env and a throwaway home with no license.json → FREE,
    # zero network calls (LicenseManager only calls out when a key is present).
    monkeypatch.delenv("SHELLOCKOLM_LICENSE", raising=False)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    c = check_license()
    assert c.name == "License"
    assert c.status in (INFO, WARN)  # never FAIL — Pro state must not block scanning


# ──────────────────────────────────────────────────────────────────────────
# Unit — DoctorReport: health, counts, serialization
# ──────────────────────────────────────────────────────────────────────────
def test_report_healthy_only_when_no_fail():
    assert DoctorReport(checks=[Check("a", OK, "x")]).healthy is True
    assert DoctorReport(checks=[Check("a", WARN, "x"), Check("b", INFO, "y")]).healthy is True
    assert DoctorReport(checks=[Check("a", OK, "x"), Check("b", FAIL, "boom")]).healthy is False


def test_report_counts_tally_every_status():
    rep = DoctorReport(checks=[
        Check("a", OK, "x"), Check("b", OK, "y"),
        Check("c", WARN, "z"), Check("d", FAIL, "f"), Check("e", INFO, "i"),
    ])
    assert rep.counts() == {"ok": 2, "warn": 1, "fail": 1, "info": 1}


def test_report_to_dict_schema_and_hint_optionality():
    rep = DoctorReport(checks=[
        Check("ok-check", OK, "fine"),
        Check("bad-check", FAIL, "broke", hint="fix it"),
    ])
    d = rep.to_dict()
    assert d["schema_version"] == "1.0"
    assert d["tool"] == "shellockolm"
    assert d["report"] == "doctor"
    assert d["healthy"] is False
    assert d["summary"] == {"ok": 1, "warn": 0, "fail": 1, "info": 0}
    assert [c["name"] for c in d["checks"]] == ["ok-check", "bad-check"]
    # hint only serialized when present.
    assert "hint" not in d["checks"][0]
    assert d["checks"][1]["hint"] == "fix it"


def test_run_checks_returns_expected_checks_in_order():
    rep = run_checks()
    names = [c.name for c in rep.checks]
    assert names == [
        "Python runtime",
        "Detection database",
        "Agent rule catalog",
        "Config directory",
        "Session/log directory",
        "git (for --diff / pre-commit)",
        "License",
    ]
    # Every check carries a valid status.
    assert all(c.status in (OK, WARN, FAIL, INFO) for c in rep.checks)


def test_run_checks_healthy_on_this_machine():
    # The dev/CI environment must pass its own doctor.
    assert run_checks().healthy is True


# ──────────────────────────────────────────────────────────────────────────
# CLI exit-code mapping (in-process, deterministic via monkeypatch)
# ──────────────────────────────────────────────────────────────────────────
def test_cli_doctor_exits_zero_when_healthy(monkeypatch, capsys):
    healthy = DoctorReport(checks=[Check("x", OK, "fine")])
    monkeypatch.setattr(doctor, "run_checks", lambda: healthy)
    with pytest.raises(typer.Exit) as exc:
        cli.doctor(output_json=True, _from_menu=True)
    assert exc.value.exit_code == cli.EXIT_OK


def test_cli_doctor_exits_one_when_unhealthy(monkeypatch, capsys):
    unhealthy = DoctorReport(checks=[Check("x", FAIL, "boom", hint="fix")])
    monkeypatch.setattr(doctor, "run_checks", lambda: unhealthy)
    with pytest.raises(typer.Exit) as exc:
        cli.doctor(output_json=True, _from_menu=True)
    assert exc.value.exit_code == cli.EXIT_FINDINGS


def test_cli_doctor_human_mode_renders_fail_without_crashing(monkeypatch):
    # A FAIL with a '[' in the detail must not break Rich markup parsing.
    unhealthy = DoctorReport(checks=[
        Check("weird", FAIL, "path C:\\x [v1.2] is bad", hint="do [thing]"),
    ])
    monkeypatch.setattr(doctor, "run_checks", lambda: unhealthy)
    with pytest.raises(typer.Exit) as exc:
        cli.doctor(output_json=False, _from_menu=True)
    assert exc.value.exit_code == cli.EXIT_FINDINGS


# ──────────────────────────────────────────────────────────────────────────
# End-to-end subprocess — the real CLI process
# ──────────────────────────────────────────────────────────────────────────
def test_e2e_doctor_human_exits_zero_on_healthy_machine():
    code, out, _err = _run_cli("doctor")
    assert code == 0
    assert "Shellockolm Doctor" in out


def test_e2e_doctor_json_is_pure_and_well_formed():
    code, out, _err = _run_cli("doctor", "--json")
    assert code == 0
    # Pure JSON: stdout parses as one document with no banner/text leakage.
    doc = json.loads(out)
    assert out.lstrip().startswith("{")
    assert "_____" not in out  # the ASCII banner never leaks into --json stdout
    assert doc["schema_version"] == "1.0"
    assert doc["report"] == "doctor"
    assert doc["healthy"] is True
    assert len(doc["checks"]) == 7
    assert {c["name"] for c in doc["checks"]} >= {"Python runtime", "License"}
