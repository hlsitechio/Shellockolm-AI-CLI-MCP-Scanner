"""Tests for the shipped ``action.yml`` GitHub Action (build-loop task #21).

`action.yml` is a *contract* consumed by other people's workflows: a wrong input
default, an unwired gate, a scan invocation that the CLI rejects, or a missing
SARIF-upload step all silently break the integration for every downstream user.
There is no GitHub runner here, so we validate the contract structurally:

* the document parses and has the composite-action shape (name/description/runs);
* the scan step actually wires the documented flags (``--json``, ``--fail-on``,
  ``--sarif``, ``-o``) so findings are gated and SARIF is produced;
* a regression guard for the original bug — the action MUST NOT pass ``-s all``
  (``scan`` rejects it; only an *empty* scanner means "run all"), and ``-s`` is
  gated behind a non-empty check;
* every default the action feeds the CLI is one the live CLI accepts
  (``--fail-on`` ∈ ``_FAIL_ON_CHOICES``, ``--min-confidence`` ∈ low/medium/high);
* a SARIF upload step using ``github/codeql-action/upload-sarif`` exists; and
* the ``scripts/action_summary.py`` helper prints ONLY the finding count to stdout
  and degrades to ``0`` on a missing/malformed report.
"""

import json
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
ACTION_FILE = REPO_ROOT / "action.yml"
SUMMARY_SCRIPT = REPO_ROOT / "scripts" / "action_summary.py"

SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

SCRIPTS = REPO_ROOT / "scripts"
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))


@pytest.fixture(scope="module")
def action():
    assert ACTION_FILE.is_file(), f"missing {ACTION_FILE}"
    data = yaml.safe_load(ACTION_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict), "action.yml must be a mapping"
    return data


@pytest.fixture(scope="module")
def steps(action):
    runs = action.get("runs", {})
    assert runs.get("using") == "composite", "must be a composite action"
    s = runs.get("steps")
    assert isinstance(s, list) and s, "composite action needs a non-empty steps list"
    return s


@pytest.fixture(scope="module")
def scan_step(steps):
    for st in steps:
        if st.get("id") == "scan":
            return st
    pytest.fail("no step with id: scan")


# --------------------------------------------------------------------------- #
# Document-level contract
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("key", ["name", "description", "runs", "inputs", "outputs"])
def test_required_top_level_keys(action, key):
    assert action.get(key), f"action.yml missing {key!r}"


def test_has_branding(action):
    branding = action.get("branding", {})
    assert branding.get("icon") and branding.get("color"), "marketplace branding required"


def test_expected_inputs_present(action):
    inputs = action["inputs"]
    expected = {
        "path", "scanner", "fail-on", "min-confidence",
        "output", "sarif", "upload-sarif", "quick",
    }
    assert expected <= set(inputs), f"missing inputs: {expected - set(inputs)}"


def test_expected_outputs_present(action):
    outputs = action["outputs"]
    assert {"report", "sarif", "findings"} <= set(outputs)
    # Every output must wire to a real step output expression.
    for name, spec in outputs.items():
        assert "steps.scan.outputs" in str(spec.get("value", "")), name


# --------------------------------------------------------------------------- #
# Defaults the action feeds the CLI must be values the live CLI accepts
# --------------------------------------------------------------------------- #

def test_default_fail_on_is_accepted_by_cli(action):
    from cli import _FAIL_ON_CHOICES  # noqa: E402

    assert action["inputs"]["fail-on"]["default"] in _FAIL_ON_CHOICES


def test_default_min_confidence_is_valid(action):
    assert action["inputs"]["min-confidence"]["default"] in {"low", "medium", "high"}


def test_scanner_default_is_empty_not_all(action):
    # Regression guard: the scan CLI rejects "-s all" (that is the `live` command's
    # default). An EMPTY scanner means "run every scanner", so the default must be
    # the empty string — never the literal "all".
    default = action["inputs"]["scanner"]["default"]
    assert default == "", f"scanner default must be empty, got {default!r}"


# --------------------------------------------------------------------------- #
# The scan step wires the gate + SARIF and does not reintroduce the -s all bug
# --------------------------------------------------------------------------- #

def test_scan_step_wires_documented_flags(scan_step):
    run = scan_step.get("run", "")
    for flag in ("--json", "--fail-on", "--sarif", "-o"):
        assert flag in run, f"scan step must pass {flag}"
    # The gate input must actually be threaded through (not hardcoded).
    assert "inputs.fail-on" in run
    assert "inputs.sarif" in run


def test_scan_step_does_not_pass_s_all(scan_step):
    run = scan_step.get("run", "")
    # Inspect only the executable shell — strip comment lines so the guard checks
    # what actually reaches argv, not the explanatory comments.
    code = "\n".join(
        ln for ln in run.splitlines() if not ln.lstrip().startswith("#")
    )
    # The original action shipped a hardcoded `-s all` / `-s ${{ inputs.scanner }}`
    # with an "all" default, which `scan` rejects (exit 2 on every run). Ensure the
    # scanner flag is gated behind a non-empty check and "all" never reaches argv.
    assert "-s all" not in code, "must not pass the invalid '-s all'"
    assert "-s ${{ inputs.scanner }}" not in code, "scanner flag must be conditional"
    assert "inputs.scanner" in code and "-n " in code, "-s must be gated by a non-empty test"


def test_scan_step_propagates_exit_code(scan_step):
    run = scan_step.get("run", "")
    # The captured scan exit code must be re-raised so the build actually fails.
    assert "exit $code" in run
    # Outputs the rest of the action depends on must be set.
    for out in ("exit-code=", "report=", "sarif=", "findings="):
        assert out in run, f"scan step must set {out} output"


def test_has_sarif_upload_step(steps):
    uploads = [
        st for st in steps
        if "github/codeql-action/upload-sarif" in str(st.get("uses", ""))
    ]
    assert uploads, "an upload-sarif step is required for Security-tab integration"
    up = uploads[0]
    # Gated on the upload-sarif input and only when a SARIF file exists.
    cond = str(up.get("if", ""))
    assert "upload-sarif" in cond and "hashFiles" in cond
    assert up.get("with", {}).get("sarif_file"), "must pass sarif_file"


# --------------------------------------------------------------------------- #
# The action_summary.py helper: stdout = count only, robust to bad input
# --------------------------------------------------------------------------- #

def test_summary_script_exists():
    assert SUMMARY_SCRIPT.is_file()


def test_summary_prints_count_to_stdout(tmp_path, capsys):
    import action_summary

    report = tmp_path / "report.json"
    report.write_text(json.dumps({
        "summary": {
            "total_findings": 3,
            "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        },
        "findings": [
            {"id": "AGENT-PI-001", "severity": "critical", "file_path": "SKILL.md:4"},
            {"id": "AGENT-HOOK-001", "severity": "high", "file_path": ".claude/settings.json"},
            {"id": "AGENT-MCP-005", "severity": "high", "file_path": "mcp.json » server:x"},
        ],
    }), encoding="utf-8")

    rc = action_summary.main([str(report)])
    assert rc == 0
    out = capsys.readouterr()
    # stdout is ONLY the integer count (consumed by the action's `findings` output).
    assert out.out.strip() == "3"
    # The readable breakdown + per-finding lines go to stderr (the Actions log).
    assert "3 finding(s)" in out.err
    assert "AGENT-HOOK-001" in out.err


def test_summary_handles_missing_report(tmp_path, capsys):
    import action_summary

    rc = action_summary.main([str(tmp_path / "does-not-exist.json")])
    assert rc == 0
    out = capsys.readouterr()
    assert out.out.strip() == "0"  # never crashes; count degrades to 0


def test_summary_handles_no_args(capsys):
    import action_summary

    rc = action_summary.main([])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "0"


def test_summary_clean_report_prints_zero(tmp_path, capsys):
    import action_summary

    report = tmp_path / "clean.json"
    report.write_text(json.dumps({
        "summary": {"total_findings": 0, "by_severity": {}},
        "findings": [],
    }), encoding="utf-8")

    rc = action_summary.main([str(report)])
    assert rc == 0
    out = capsys.readouterr()
    assert out.out.strip() == "0"
    assert "no findings" in out.err.lower()
