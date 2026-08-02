"""Pure phase logic for the interactive ``sandbox <pkg>`` deep-install check
(build-loop follow-up F29).

The ``sandbox <pkg>`` command installs an npm package into a throwaway directory
**with install scripts enabled** and then decides whether to tell the user
"APPEARS SAFE TO DOWNLOAD". F27 extracted the snapshot/diff half into
:mod:`sandbox_snapshot`; the phases that *consume* it — the expected-location
filter, the install-script analysis, the malware-pattern pass, the CVE
classification, the typosquat check and the final verdict — still lived inside a
~450-line block in ``interactive_shell()``, unreachable from a test because the
function needs a TTY. Their correctness was held by review and ruff's ``F821``
alone. This module is that logic, as pure functions over plain data.

Design rules, all of which the tests pin:

* **A blind phase is never a pass.** Every phase that could not run (an
  unreadable snapshot path, an unreadable installed file, a crashed CVE scanner,
  a failed install, metadata that could not be fetched) calls
  :meth:`SandboxFindings.mark_blind`. The verdict table then renders
  :data:`Verdict.INCONCLUSIVE` — never "APPEARS SAFE" — because absence of
  findings from a check that did not run is not evidence of absence.
* **One source of truth for danger.** The inline version carried both an
  ``is_safe`` flag and a ``dangers`` list and had to keep them in sync by hand;
  one site already appended a danger without clearing the flag. The verdict now
  derives from ``dangers`` alone, so they cannot diverge.
* **A capability is not a verdict.** The malware-pattern table is calibrated
  the way the ``AGENT-*`` rules are (F31): a pattern that also describes
  ordinary library code — running a subprocess, building a function at runtime —
  is a warning, and becomes a danger only when the same file carries an attacker
  context signal. The uncalibrated table condemned lodash, chalk, axios,
  typescript, webpack, eslint, commander and bluebird; the current one produces
  zero dangers across a real install of 480 packages.

  F37 applied the same rule to the **install-hook** table, which was still a
  flat substring list where every hit was a full DANGER — so a hook that echoed
  a documentation URL scored exactly like one that piped ``curl`` to ``sh``.
  That was tolerable while it ran against one package the user had named; F34
  applies it across the whole dependency tree, and F36 made a git-sourced
  package's ``prepare`` genuinely execute — and the canonical ``prepare`` body
  is a *build* step. Re-measured over 175,127 installed manifests (1,761 unique
  hook bodies across 761 packages), the flat table produced **six** DANGER lines
  and **all six were build scripts**: ``rm -rf dist && npm run build``,
  ``rm -rf lib && tsc``, ``faiss-node``'s source build (reported as "External
  URL"), and ``phenomenon``'s ``$npm_execpath run test``, which matched
  ``exec`` *inside a variable name*. The table now has two tiers: composite
  attacks (a downloader wired to a shell, a decoded payload run, a shell wired
  to a socket) are dangers; the twenty original substrings are warnings, none
  removed. Same corpus after tiering: **zero** dangers, zero coverage lost.

  The danger tier was then stress-tested against a much wider set of real
  command lines — **104,467 unique ``scripts`` bodies over 6,207 packages and
  5,450 distinct script names**, i.e. every build, test and release script in
  the same trees, not just the four install hooks. The flat table calls
  **3,434 of them (3.3%)** a DANGER. The tiered one flags **one** — the genuine
  ``curl -Ls https://coverage.codacy.com/get.sh | bash`` in ``diff2html``'s
  ``coverage:push``. (Those scripts never auto-run, so this is a precision
  measurement of the patterns, not of the production surface; the install-hook
  corpus above is that.)
* **The expected-location filter is anchored.** The inline filter asked
  ``any(pattern in path for pattern in expected)``, an unanchored substring test:
  a payload written to ``evil-package.json`` matched ``package.json`` and a
  payload at ``.ssh/node_modules/authorized_keys`` matched ``node_modules/``, so
  both were silently dropped from a security filter. Matching is now by path
  segment.

Pure and unit-testable, mirroring ``sandbox_snapshot`` / ``diff_scan`` /
``baseline`` / ``doctor``: no filesystem, no subprocess, no console.
"""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Iterable, List, Mapping, Sequence, Tuple

# ---------------------------------------------------------------------------
# Verdict
# ---------------------------------------------------------------------------


class Verdict(str, Enum):
    """Outcome of a sandbox deep-install check."""

    SAFE = "safe"
    INCONCLUSIVE = "inconclusive"
    DANGER = "danger"


#: ``next_step_type`` the interactive shell reports per verdict. INCONCLUSIVE
#: gets its own value: labelling a blind run "sandbox_safe" was the same
#: overclaim in a different field.
NEXT_STEP_TYPES: Dict[Verdict, str] = {
    Verdict.SAFE: "sandbox_safe",
    Verdict.INCONCLUSIVE: "sandbox_inconclusive",
    Verdict.DANGER: "sandbox_danger",
}


def decide_verdict(has_dangers: bool, analysis_incomplete: bool) -> Verdict:
    """The verdict table, in one place.

    A danger outranks everything (an incomplete analysis that still found a
    payload is a DANGER, not an INCONCLUSIVE). With no danger, the deciding
    question is whether every phase actually ran.
    """
    if has_dangers:
        return Verdict.DANGER
    if analysis_incomplete:
        return Verdict.INCONCLUSIVE
    return Verdict.SAFE


@dataclass
class SandboxFindings:
    """Accumulated result of the sandbox phases.

    ``blind_phases`` is the whole point: it holds ``(phase, reason)`` for every
    check that could not see what it was supposed to see, and it is what turns a
    finding-free run into :data:`Verdict.INCONCLUSIVE`.
    """

    dangers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    info: List[str] = field(default_factory=list)
    blind_phases: List[Tuple[str, str]] = field(default_factory=list)

    def add_danger(self, message: str) -> None:
        self.dangers.append(message)

    def add_warning(self, message: str) -> None:
        self.warnings.append(message)

    def add_info(self, message: str) -> None:
        self.info.append(message)

    def mark_blind(self, phase: str, reason: str) -> None:
        """Record that ``phase`` could not complete, and why.

        Also surfaced as a warning so the reason is visible in the summary — a
        downgraded verdict with no stated cause is not actionable.
        """
        self.blind_phases.append((phase, reason))
        self.add_warning(f"{phase} incomplete: {reason}")

    @property
    def analysis_incomplete(self) -> bool:
        return bool(self.blind_phases)

    @property
    def verdict(self) -> Verdict:
        return decide_verdict(bool(self.dangers), self.analysis_incomplete)

    @property
    def next_step_type(self) -> str:
        return NEXT_STEP_TYPES[self.verdict]

    def extend(self, dangers: Iterable[str] = (), warnings: Iterable[str] = ()) -> None:
        """Merge a phase helper's classified output."""
        self.dangers.extend(dangers)
        self.warnings.extend(warnings)


# ---------------------------------------------------------------------------
# Package spec handling
# ---------------------------------------------------------------------------

# The menu prompt offers "npm package name or URL", but the raw value went
# straight to `npm view`, which cannot resolve a registry URL — the advertised
# input always failed. Normalizing here makes it work and keeps it testable.
_NPM_URL_RE = re.compile(
    r"^https?://(?:www\.)?(?:npmjs\.com|npmjs\.org|registry\.npmjs\.org)/"
    r"(?:package/)?(?P<name>@[^/@\s]+/[^/@\s]+|[^/@\s]+)",
    re.IGNORECASE,
)


def normalize_package_spec(raw: str) -> str:
    """Reduce user input to something ``npm view``/``npm install`` accepts.

    Accepts a bare name, a scoped name, a name with a version spec, or an
    npmjs.com package URL. Anything unrecognized is returned stripped, so an
    unusual-but-valid spec is passed through rather than mangled.
    """
    spec = (raw or "").strip().strip("'\"")
    if not spec:
        return ""
    match = _NPM_URL_RE.match(spec)
    if match:
        return match.group("name")
    return spec.rstrip("/")


def installed_package_dirname(pkg_spec: str) -> str:
    """Directory under ``node_modules/`` that ``pkg_spec`` installs into.

    Strips a version spec and preserves the full scoped path, so a scoped
    package's own directory is scanned rather than the whole scope directory
    (``node_modules/@scope/pkg``, not ``node_modules/@scope``) and a spec like
    ``lodash@4.17.21`` does not point at a directory that never exists — which
    silently skipped the entire code-analysis phase.
    """
    name = normalize_package_spec(pkg_spec)
    if not name:
        return ""
    if name.startswith("@"):
        scope, _, rest = name.partition("/")
        if not rest:
            return scope
        base = rest.split("@", 1)[0]
        return f"{scope}/{base}" if base else scope
    return name.split("@", 1)[0] or name


# ---------------------------------------------------------------------------
# Phase 1 — install-script analysis
# ---------------------------------------------------------------------------

#: npm lifecycle hooks that run automatically on `npm install`.
INSTALL_SCRIPT_HOOKS: Tuple[str, ...] = ("preinstall", "install", "postinstall", "prepare")

class HookSeverity(str, Enum):
    """How much a single install-hook pattern is allowed to claim.

    :data:`DANGER` blocks the install on its own; :data:`WARNING` is reported
    and shown, but never decides the verdict by itself.
    """

    DANGER = "danger"
    WARNING = "warning"


@dataclass(frozen=True)
class InstallScriptPattern:
    """One row of the install-hook table: what to look for, and how loudly."""

    regex: str
    description: str
    severity: HookSeverity
    ignore_case: bool = True


# --- the DANGER tier -------------------------------------------------------
#
# Composite shapes only: a downloader *wired to* an execution sink, a payload
# that is decoded and then run, or a shell wired to a socket. Each is a
# complete attack in one command line, and none of them has a reading in which
# an ordinary package is merely building itself.

#: The commands that pull bytes off the network inside a hook body.
_HOOK_DOWNLOADER = r"(?:curl|wget)"

#: A shell being asked to interpret something, with or without an absolute path.
_HOOK_SHELL = r"(?:sudo\s+)?(?:/(?:usr/)?bin/)?(?:ba|z|k|da)?sh\b"

#: PowerShell's download primitives, which take the place of curl on Windows.
_HOOK_PS_DOWNLOAD = r"(?:Invoke-WebRequest|Invoke-RestMethod|\biwr\b|Net\.WebClient|DownloadString|DownloadFile)"


# --- the WARNING tier ------------------------------------------------------
#
# The original flat table, unchanged in coverage and demoted in severity. Every
# one of these describes a *capability*: fetching a file, running a subprocess,
# deleting a directory. Real install hooks do all of it — `node-gyp` shells
# out, `prebuild-install` downloads a binary, and the canonical `prepare` body
# is `rm -rf dist && npm run build`. Whether that is an attack is decided by
# what the capability is wired to, which is what the DANGER tier asks.
#
# Seven entries are word-anchored rather than raw substrings, each because the
# substring form matched across a word boundary: `"nc "` matched `npm run
# sync foo`, `".bat"` matched `.batch`, `"eval"` matched `retrieval`, `"curl"`
# matched `curly`, `"wget"` matched `widget`, `"exec"` matched `$npm_execpath`,
# and `"rm -rf"` missed `rm -fr` and `rm -r` entirely. The rest stay literal:
# over-matching costs a warning line, and narrowing them would be a coverage
# loss for no gain.
#
# `exec` was the one F37 measured and deliberately left, on the reasoning that
# a stray warning line is cheap. F42 asked whether the F34 tree-wide sweep
# multiplies that cost — `socket` inside `websocket`, `base64` inside a
# filename, several lines per hooked package, all of it compressed by a summary
# that shows ten and then says "... and N more" — and told this pass not to
# guess the number. Measured over **301 real `node_modules` trees / 54,656
# installed manifests**: the four lifecycle hooks hold **229 unique bodies**, of
# which **48** are in the auto-run set the F34 sweep actually classifies, and
# the entire twenty-row warning tier fires **once** across them (`https://` in
# `faiss-node`'s source build). The declared ceiling — every hook, as if each
# package were git-sourced and its `prepare` ran — is **4 lines across 4
# packages**, one line each. No package produces two, so there is nothing for a
# summary to group and the display cap hides nothing.
#
# Exactly **one** of those four is a cross-word match, and it is this row:
# `exec` inside `phenomenon`'s real `prepare` body, `$npm_execpath run test`.
# `socket`/`websocket` and `base64`-in-a-filename, the two the task expected to
# find, do not occur in the corpus at all. So the calibration is a one-character
# fix and the summary regrouping is unwarranted. The anchor is left-side only,
# exactly like `\beval`: `execSync`, `execFile` and `execa` all still fire,
# while `npm_execpath` and `preexec` no longer do.

#: The install-hook table, ordered DANGER-first so a report leads with the
#: strongest thing it found.
INSTALL_SCRIPT_PATTERN_TABLE: Tuple[InstallScriptPattern, ...] = (
    # curl … | sh — the crypto-miner dropper, and the shape every writeup opens
    # with. On Windows the same thing is `DownloadString(...) | iex`.
    InstallScriptPattern(
        rf"{_HOOK_DOWNLOADER}\b[^\n]{{0,200}}\|\s*{_HOOK_SHELL}"
        rf"|{_HOOK_PS_DOWNLOAD}[^\n]{{0,200}}(?:\biex\b|Invoke-Expression)"
        # `IEX (New-Object Net.WebClient).DownloadString(…)` is the same command
        # with the two halves swapped, and is the form every writeup quotes.
        rf"|(?:\biex\b|Invoke-Expression)[^\n]{{0,200}}{_HOOK_PS_DOWNLOAD}",
        "downloaded content piped to a shell",
        HookSeverity.DANGER,
    ),
    # The two-statement form of the same attack: fetch to disk, then run it.
    #
    # The naive spelling — a downloader followed by any `./something` — reads
    # `curl -o deps.tgz … && ./scripts/unpack.sh` as an attack, and that is a
    # real build hook. So the executed path has to be *the file the downloader
    # just wrote*, matched by back-reference. `chmod +x` after a download needs
    # no back-reference: marking anything executable in the same breath as
    # fetching it is the shape, whatever it is named.
    InstallScriptPattern(
        rf"{_HOOK_DOWNLOADER}\b[^\n]{{0,200}}?"
        r"(?:--output-document=?|--output|-o|-O|>)\s*['\"]?([\w./\\-]+)['\"]?"
        rf"[^\n]{{0,200}}(?:;|&&|\|\||\|)\s*(?:sudo\s+)?"
        rf"(?:{_HOOK_SHELL}\s+|\./|chmod\s+[+0-7ugoa]*x\s+)['\"]?\1\b"
        rf"|{_HOOK_DOWNLOADER}\b[^\n]{{0,200}}(?:;|&&|\|\|)\s*"
        r"(?:sudo\s+)?chmod\s+[+0-7ugoa]*x\b",
        "downloaded file executed",
        HookSeverity.DANGER,
    ),
    # Decoding base64 is ordinary data handling; decoding it *into an
    # interpreter* is the dropper cradle. `powershell -enc <blob>` is the same
    # move with the encoding built into the flag.
    InstallScriptPattern(
        r"base64\s+-{1,2}[a-z]*d[a-z]*\b[^\n]{0,120}\|\s*" + _HOOK_SHELL
        + r"|\|\s*base64\s+-{1,2}[a-z]*d[a-z]*\b[^\n]{0,120}\|\s*" + _HOOK_SHELL
        + r"|(?:eval|exec|execSync|spawnSync|new\s+Function)\s*\(\s*[^;\n]{0,80}?"
        r"(?:Buffer\.from\s*\([^)\n]*['\"]base64['\"]|\batob\s*\()"
        r"|powershell[^\n]{0,60}?\s-e(?:nc(?:odedcommand)?)?\s+['\"]?[A-Za-z0-9+/]{20,}",
        "encoded payload executed",
        HookSeverity.DANGER,
    ),
    # A shell wired to a socket. `/dev/tcp` has no other use; `nc -e`, `ncat
    # --exec` and `socat … EXEC:` are the same instruction spelled three ways.
    InstallScriptPattern(
        r"/dev/(?:tcp|udp)/"
        r"|\bnc(?:\.exe)?\s+[^\n]{0,80}?-[a-zA-Z]*e[a-zA-Z]*\s"
        r"|\bncat\b[^\n]{0,80}--(?:exec|sh-exec|lua-exec)"
        r"|\bsocat\b[^\n]{0,120}(?:EXEC|SYSTEM):"
        r"|(?:ba|z|k)?sh\s+-i\b[^\n]{0,80}(?:>&|<>|2>&1)",
        "reverse shell",
        HookSeverity.DANGER,
    ),
    # The exfil hook: an upload flag on a downloader, carrying the output of a
    # command substitution or an environment read. This is how a dependency-
    # confusion payload ships `$(env | base64)` or `$(whoami)` to its collector.
    # Every part has to be on one line, so a multi-line build script that
    # happens to use all three does not add up to a finding.
    #
    # Anchored to line starts (``(?m)^``) rather than left to float. Three
    # unanchored ``[^\n]*`` lookaheads are retried at every character, and each
    # one rescans to the end of the line — quadratic in the body length, which
    # a hostile package controls. Anchoring makes it one attempt per line and
    # changes nothing about what it matches, since every lookahead already
    # scanned the whole line from wherever it started.
    InstallScriptPattern(
        r"(?m)^(?=[^\n]*(?:curl|wget|Invoke-RestMethod|Invoke-WebRequest))"
        r"(?=[^\n]*(?:\s-d\b|--data\b|--data-binary\b|\s-F\b|--form\b|\s-T\b"
        r"|--upload-file\b|-Method\s+Post))"
        r"(?=[^\n]*(?:\$\(|\$\{?(?:HOME|USER|PWD|HOSTNAME|PATH|NPM_TOKEN)\b"
        r"|%USERPROFILE%|%USERNAME%|process\.env))",
        "local data sent to a remote endpoint",
        HookSeverity.DANGER,
    ),
    InstallScriptPattern(r"\bcurl\b", "Downloads external content", HookSeverity.WARNING),
    InstallScriptPattern(r"\bwget\b", "Downloads external content", HookSeverity.WARNING),
    InstallScriptPattern(r"\beval", "Dynamic code execution", HookSeverity.WARNING),
    InstallScriptPattern(r"\bexec", "Command execution", HookSeverity.WARNING),
    InstallScriptPattern(r"child_process", "Spawns processes", HookSeverity.WARNING),
    InstallScriptPattern(
        r"\brm\s+-[a-zA-Z]*[rf]\b", "Destructive file operation", HookSeverity.WARNING
    ),
    InstallScriptPattern(r"base64", "Encoded payload", HookSeverity.WARNING),
    InstallScriptPattern(r"/dev/tcp", "Network backdoor", HookSeverity.WARNING),
    InstallScriptPattern(r"powershell", "PowerShell execution", HookSeverity.WARNING),
    InstallScriptPattern(r"cmd\.exe", "Windows command execution", HookSeverity.WARNING),
    InstallScriptPattern(r"\.bat\b", "Batch script execution", HookSeverity.WARNING),
    InstallScriptPattern(r"\bnc\s", "Netcat - reverse shell", HookSeverity.WARNING),
    InstallScriptPattern(r"netcat", "Netcat - reverse shell", HookSeverity.WARNING),
    InstallScriptPattern(r"/bin/sh", "Shell execution", HookSeverity.WARNING),
    InstallScriptPattern(r"/bin/bash", "Bash execution", HookSeverity.WARNING),
    InstallScriptPattern(r"socket", "Network socket", HookSeverity.WARNING),
    InstallScriptPattern(r"XMLHttpRequest", "HTTP request", HookSeverity.WARNING),
    InstallScriptPattern(r"fetch\(", "HTTP fetch", HookSeverity.WARNING),
    InstallScriptPattern(r"https://", "External URL", HookSeverity.WARNING),
    InstallScriptPattern(r"http://", "External URL (insecure)", HookSeverity.WARNING),
)

#: Backwards-compatible ``(pattern, description)`` views, one per tier. The
#: single flat ``INSTALL_SCRIPT_DANGER_PATTERNS`` used to hold both, which is
#: exactly the conflation F37 removes: "prints a documentation URL" scored the
#: same as "pipes curl to sh".
INSTALL_SCRIPT_DANGER_PATTERNS: Tuple[Tuple[str, str], ...] = tuple(
    (entry.regex, entry.description)
    for entry in INSTALL_SCRIPT_PATTERN_TABLE
    if entry.severity is HookSeverity.DANGER
)
INSTALL_SCRIPT_WARNING_PATTERNS: Tuple[Tuple[str, str], ...] = tuple(
    (entry.regex, entry.description)
    for entry in INSTALL_SCRIPT_PATTERN_TABLE
    if entry.severity is HookSeverity.WARNING
)

_COMPILED_INSTALL_SCRIPT_PATTERNS: Tuple[Tuple[Any, InstallScriptPattern], ...] = tuple(
    (
        re.compile(entry.regex, re.IGNORECASE if entry.ignore_case else 0),
        entry,
    )
    for entry in INSTALL_SCRIPT_PATTERN_TABLE
)


#: How much of a matched hook fragment a finding line quotes.
HOOK_SNIPPET_LIMIT = 80

#: How much of a hook body the pattern table reads.
#:
#: The table is regexes now, and several carry a bounded ``[^\n]{0,200}`` window
#: that the engine retries at every start position — linear work per character,
#: so quadratic in a body whose length a hostile package chooses. Measured: a
#: 43 KB hook body took **38 seconds**, which is a denial of service against the
#: scanner rather than a scan. The limit bounds that.
#:
#: 4,000 is ~7.5x the longest install hook in the corpus F37 measured: over
#: 1,761 unique hook bodies from 175,127 installed manifests the maximum was
#: **532** characters (``stacktrace-gps``), p99 was 102, and the median 15. No
#: real package is truncated by this; a body that exceeds it is itself unusual,
#: which is why exceeding it is reported rather than passed over.
HOOK_BODY_SCAN_LIMIT = 4000


def _matched_snippet(match: Any) -> str:
    """The text a hook pattern actually matched, trimmed for one console line.

    The old table quoted the *pattern* (``"rm -rf"``), which worked only
    because every pattern was a literal substring. Quoting the match instead
    stays readable now that the entries are regexes, and says more: it names
    the fragment in *this* hook rather than the rule that fired.

    A pure-lookahead pattern matches the empty string, so the head of the hook
    body stands in — a finding whose evidence line is blank is not a finding.
    """
    text = " ".join((match.group(0) or "").split())
    if not text:
        text = " ".join((match.string or "").split())
    if len(text) > HOOK_SNIPPET_LIMIT:
        text = text[: HOOK_SNIPPET_LIMIT - 1].rstrip() + "…"
    return text


@dataclass
class InstallScriptReport:
    """Which lifecycle hooks a package declares, and what they contain.

    ``dangers`` and ``warnings`` are the two tiers of
    :data:`INSTALL_SCRIPT_PATTERN_TABLE`. Only ``dangers`` reaches
    :meth:`SandboxFindings.verdict`; a warning is reported and never blocks.
    """

    hooks: List[str] = field(default_factory=list)
    bodies: Dict[str, str] = field(default_factory=dict)
    dangers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    #: Hooks whose body was longer than :data:`HOOK_BODY_SCAN_LIMIT`, so only
    #: its head was matched against the table. Carried separately so a caller
    #: can mark the phase blind: "we read the first 4,000 characters and found
    #: nothing" is not the same claim as "this hook is clean".
    truncated_hooks: List[str] = field(default_factory=list)

    @property
    def has_hooks(self) -> bool:
        return bool(self.hooks)

    @property
    def has_findings(self) -> bool:
        """Whether the hooks matched anything at all, at either severity."""
        return bool(self.dangers or self.warnings)


def analyze_install_scripts(scripts: Any) -> InstallScriptReport:
    """Classify a package's ``scripts`` block.

    Tolerant of whatever ``npm view --json`` returns: a non-mapping ``scripts``
    value, or a hook whose body is not a string, yields an empty report instead
    of raising inside the scan.
    """
    report = InstallScriptReport()
    if not isinstance(scripts, Mapping):
        return report

    for hook in INSTALL_SCRIPT_HOOKS:
        if hook not in scripts:
            continue
        body = scripts.get(hook)
        if not isinstance(body, str):
            body = "" if body is None else str(body)
        report.hooks.append(hook)
        report.bodies[hook] = body
        scanned = body
        if len(body) > HOOK_BODY_SCAN_LIMIT:
            scanned = body[:HOOK_BODY_SCAN_LIMIT]
            report.truncated_hooks.append(hook)
            report.warnings.append(
                f"⚠️ {hook} script: body is {len(body)} characters - only the "
                f"first {HOOK_BODY_SCAN_LIMIT} were analysed"
            )
        for compiled, entry in _COMPILED_INSTALL_SCRIPT_PATTERNS:
            match = compiled.search(scanned)
            if match is None:
                continue
            line = f"{hook} script: {entry.description} ({_matched_snippet(match)})"
            if entry.severity is HookSeverity.DANGER:
                report.dangers.append(f"🚨 {line}")
            else:
                report.warnings.append(f"⚠️ {line}")
    return report


# ---------------------------------------------------------------------------
# Phase 4 — expected-location filter over new files
# ---------------------------------------------------------------------------

#: Directories whose contents `npm install` legitimately creates in the sandbox.
#: `.npm` is included because the check redirects ``HOME`` into the sandbox, so
#: npm's own state directory is an artifact of *our* isolation, not the package.
EXPECTED_INSTALL_DIRS: Tuple[str, ...] = ("node_modules", ".npm-cache", ".npm")

#: Exact files npm writes at the sandbox root.
EXPECTED_INSTALL_FILES: Tuple[str, ...] = (
    "package.json",
    "package-lock.json",
    ".package-lock.json",
)


def _relative_sandbox_path(path: str) -> str:
    """Normalize a snapshot key to a forward-slashed, root-relative path."""
    normalized = (path or "").replace("\\", "/")
    # Strip a leading "./" only. `lstrip("./")` would strip a CHARACTER SET and
    # turn ".npm-cache/x" into "npm-cache/x", so npm's own cache stopped being
    # recognized and every cached file was reported as a dropped payload.
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.lstrip("/")


def is_npm_owned_directory_path(path: str) -> bool:
    """True when ``path`` lives inside a directory npm manages end-to-end.

    npm creates, rewrites and prunes everything under ``node_modules/`` and its
    cache directories, so churn there is npm's own bookkeeping. Root *files*
    are deliberately excluded: see :func:`filter_unexpected_deletions`.
    """
    normalized = _relative_sandbox_path(path)
    if not normalized:
        return False
    return normalized.split("/", 1)[0] in EXPECTED_INSTALL_DIRS


def is_expected_install_path(path: str) -> bool:
    """True when ``path`` is an artifact npm itself creates in the sandbox.

    Matching is by **path segment**, not substring. The inline version used
    ``'package.json' in path`` / ``'node_modules/' in path``, so a dropped
    payload named ``evil-package.json`` — or hidden at
    ``.ssh/node_modules/authorized_keys`` — was quietly treated as expected and
    never reported.
    """
    normalized = _relative_sandbox_path(path)
    if not normalized:
        return False
    if normalized in EXPECTED_INSTALL_FILES:
        return True
    return is_npm_owned_directory_path(normalized)


def filter_suspicious_new_files(new_files: Iterable[str]) -> List[str]:
    """New files that npm did not put there — i.e. what the install wrote."""
    return [path for path in new_files if not is_expected_install_path(path)]


def filter_unexpected_modifications(modified_files: Iterable[str]) -> List[str]:
    """Pre-existing files the install **rewrote** and npm does not own.

    ``compare_snapshots`` has always returned this set and phase 4 has always
    dropped it, so an install that appended to or truncated a file that already
    existed was invisible to a check that only ever answered "what was
    created" (follow-up F40).

    The same expected-artifact filter the new-file check uses applies here:
    since F36 keeps the lockfile, npm legitimately rewrites the sandbox
    ``package.json`` on *every* run, so an unfiltered set would report npm's
    own write as a finding every time.
    """
    return [path for path in modified_files if not is_expected_install_path(path)]


def filter_unexpected_deletions(deleted_files: Iterable[str]) -> List[str]:
    """Pre-existing files the install **removed**, minus npm's own churn.

    Deletion is filtered more narrowly than modification, and the asymmetry is
    the point: npm rewrites ``package.json`` and writes ``package-lock.json``,
    but it never *removes* the manifest of the project it is installing into.
    So a root file that existed before the install and is gone afterwards is
    the install's doing, while a file vanishing from ``node_modules/`` or a
    cache directory is npm pruning a tree it owns.
    """
    return [path for path in deleted_files if not is_npm_owned_directory_path(path)]


def count_paths_under(paths: Iterable[str], directory: str) -> int:
    """Count paths inside ``directory`` (segment-anchored, for the stats line)."""
    prefix = directory.rstrip("/") + "/"
    return sum(1 for path in paths if path.replace("\\", "/").startswith(prefix))


# ---------------------------------------------------------------------------
# Phase 5 — malware patterns in installed code
# ---------------------------------------------------------------------------

#: How many consecutive escape sequences make an encoded *blob*. A single
#: ``'\\xc0'`` in a character table is ordinary library code (lodash ships
#: several); a run is the shape of an obfuscated payload string.
ENCODED_RUN_LENGTH = 6


@dataclass(frozen=True)
class MalwarePattern:
    """One calibrated malware-pattern rule.

    ``ignore_case`` exists because JavaScript is case-sensitive and the original
    table compiled everything with ``re.IGNORECASE``: ``Function\\s*\\(`` then
    matched every anonymous ``function(a, b)`` in the language (193 hits on
    lodash alone). ``requires`` names a co-occurrence gate that must also be
    present in the same file — the discipline the ``AGENT-*`` rules already use.
    """

    regex: str
    description: str
    ignore_case: bool = True
    requires: str = ""


#: A file only gets credit for a command-execution hit when it actually binds
#: ``child_process``. Without this gate ``\.exec\s*\(`` matched JavaScript's
#: ``RegExp.prototype.exec`` (``reTrimStart.exec(string)``), which is why a plain
#: ``npm install lodash`` produced a **DO NOT INSTALL** verdict. Module names are
#: lowercase, so the gate is deliberately case-sensitive.
_CO_OCCURRENCE_GATES: Dict[str, Any] = {
    "child_process": re.compile(
        r"""require\s*\(\s*['"](?:node:)?child_process['"]\s*\)"""
        r"""|from\s+['"](?:node:)?child_process['"]"""
        r"""|import\s*\(?\s*['"](?:node:)?child_process['"]"""
        r"""|process\.binding\s*\(\s*['"]spawn_sync['"]"""
    ),
}

#: How far apart a network call and an execution sink may sit and still count as
#: *wired together* (F35). Sized to span a request call and its response
#: callback body — the dropper's whole shape — without reaching across the
#: unrelated statements of a minified bundle. Measured at zero hits over 736
#: real installed packages; the same window at 120 catches the same droppers, so
#: 240 is the loose end of a range that is empty of benign code either way.
NETWORK_EXEC_WINDOW = 240

#: An outbound network call.
#:
#: ``cache.fetch(key)`` and ``store.request(id)`` are ordinary method calls, and
#: counting them as network I/O is the same imprecision F35 exists to remove. The
#: obvious guard — a ``(?<![.\w$])`` lookbehind — turned out to cost 6x: a
#: lookbehind *inside an alternation* defeats CPython's prefix-charset
#: optimisation, so the branch is tried at every offset instead of skipping to
#: the next candidate character (measured over 19 MB of real bundles:
#: 0.42s -> 2.62s for this pattern alone). The guard is therefore semantic
#: rather than syntactic: the ambiguous names must be handed something
#: URL-shaped. ``https.get`` / ``axios`` / ``XMLHttpRequest`` name the transport
#: outright and need no such restriction, so the node-native dropper forms stay
#: fully covered; the narrowing costs only a global ``fetch(x)`` whose argument
#: is an opaque local name.
_NETWORK_CALL = (
    r"(?:\bhttps?\.(?:get|request)\s*\("
    r"|\bfetch\s*\(\s*(?:['\"`]https?://"
    r"|[\w.]*(?:url|Url|URL|uri|Uri|URI|endpoint|Endpoint|host|Host)\b)"
    r"|\baxios\s*(?:\.\s*(?:get|post|put|patch|delete)\s*)?\("
    r"|\brequest\s*\(\s*['\"`]https?://"
    r"|\bnew\s+XMLHttpRequest\b)"
)

#: Building and running code from a string.
_DYNAMIC_CODE_SINK = r"(?:\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`])"

#: Running an OS command. Deliberately NOT the capability table's broad
#: ``(?:\.|\b)exec\s*\(``: the one benign shape that sits closest to a dropper is
#: ``RE.exec(await response.text())`` — parsing a fetched string with a regular
#: expression, which is ordinary code and lands well inside the window. So the
#: exec-family names a ``RegExp`` never has (``execSync``, ``execFile``,
#: ``spawn``…) match anywhere, while plain ``exec`` matches only in the two forms
#: a command runner takes: on a child_process-shaped receiver (``cp.exec(cmd)``)
#: or destructured at the head of a statement (``; exec(cmd)``, ``=> exec(cmd)``).
_COMMAND_EXEC_SINK = (
    r"(?:\b(?:execSync|execFile|execFileSync|spawn|spawnSync)\s*\("
    r"|\b(?:child_process|childProcess|child|cp|proc|subprocess)\s*\.\s*exec\s*\("
    r"|[;{}>]\s*exec\s*\()"
)


def _wired_within(first: str, second: str) -> str:
    """Regex matching ``first`` and ``second`` within :data:`NETWORK_EXEC_WINDOW`.

    Both orders match, because both are attacker shapes and only the direction
    differs: fetch-then-execute is a dropper, execute-then-send is exfiltration.
    """
    gap = r"[\s\S]{0,%d}?" % NETWORK_EXEC_WINDOW
    return f"(?:{first}{gap}{second})|(?:{second}{gap}{first})"


#: How far along a spawn call's command line the shell-payload check reads. The
#: bound is a *line*, not a character window over the file, so the check cannot
#: run off the end of the call into an unrelated statement — a command line is
#: written on one line even in a minified bundle.
SHELL_COMMAND_WINDOW = 200

#: The call forms that start a process, up to and including the opening quote of
#: their first argument. The three shell shapes below share this prefix and are
#: spelled as ONE branch after it rather than three whole patterns: repeating the
#: prefix made the pattern **4x** slower over 23.5 MB of real bundles
#: (1.09s -> 4.24s), because the engine re-scans the file per alternative.
#: ``(?:\.|\b)`` is likewise dropped for a plain ``\b`` — the two are equivalent
#: here (``.`` is a non-word character, so a boundary already sits before the
#: ``e`` of ``cp.exec``) and the alternation cost 0.26s of the remainder.
_PROCESS_CALL = r"\b(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*['\"`]"

#: A raw shell binary, spelled the way a spawn call spells it. The leading
#: ``(?:/(?:usr/)?bin/)|\b`` is one alternation rather than a plain ``\b``
#: because there is no word boundary between a quote and the ``/`` of an
#: absolute path; without the boundary, the bare ``sh`` alternative matches
#: inside ``npm publish``.
_SHELL_BINARY = (
    r"(?:(?:/(?:usr/)?bin/)|\b)(?:sh|bash|zsh|dash|ash)\b"
    r"|\bcmd(?:\.exe)?\b|\bpowershell(?:\.exe)?\b|\bpwsh(?:\.exe)?\b"
)

#: PowerShell, which gets its own arm because its encoded-payload flags are
#: ambiguous outside it.
_POWERSHELL = r"(?:powershell(?:\.exe)?|pwsh(?:\.exe)?)"

#: What makes a shell command line a delivery mechanism: it fetches the payload
#: (``curl``, ``certutil``, a ``/dev/tcp`` socket) or decodes one it carries.
_SHELL_PAYLOAD = (
    r"\bcurl\b|\bwget\b|Invoke-WebRequest|\biwr\b|Net\.WebClient|DownloadString"
    r"|DownloadFile|\bcertutil\b|\bbitsadmin\b|/dev/tcp|\bnc\s+-e|\bbase64\s+-d\b"
)

#: PowerShell's encoded-payload spellings. Kept PowerShell-only, and NOT folded
#: into :data:`_SHELL_PAYLOAD`, because ``-ec`` and ``-e`` are also POSIX shell
#: flags: ``bash -ec "npm run build"`` is a real build idiom.
_POWERSHELL_ENCODED = r"-(?:enc|ec|e)\b|EncodedCommand|FromBase64String"

#: How far from a weak input-capture noun (``keystrokes``, ``keylog``) the
#: corroborating verb may sit. A line bound, like every other window here, and
#: the value the ``keystrokes`` arm has always used — reused rather than picked
#: again so the two arms cannot drift apart.
KEYLOG_VERB_WINDOW = 40

#: What turns a bare ``keylog`` into a keylogger: a theft verb following it —
#: the same vocabulary the ``credential theft`` pattern below already uses,
#: deliberately reused rather than invented.
#:
#: The obvious wider set is wrong, and measurably so. ``captur`` and ``record``
#: read as *packet* capture right next to this token: "run with
#: ``--tls-keylog`` to decrypt the capture in Wireshark" is the documented
#: workflow the option exists for, and it put the rule straight back on benign
#: prose. ``logg`` is absent for the same reason the reverse holds — "keylog …
#: logging" corroborates nothing and re-opens a config key named ``keylog``
#: beside a ``logger`` call. Stealing, exfiltrating, harvesting and siphoning
#: have no such second reading.
_KEYLOG_THEFT_VERB = r"steal|exfiltrat|harvest|siphon"

#: The calibrated pattern table applied to each installed ``.js`` file.
#:
#: Calibration rules (build-loop follow-up F31), each pinned by a test over real
#: mainstream-package code:
#:
#: * command execution is **gated** on a ``child_process`` binding — and, being
#:   gated, is then free to match the destructured form (``const {exec} =
#:   require('child_process'); exec(cmd)``) that the dot-anchored pattern missed;
#: * ``eval`` / ``Function`` are case-sensitive and shape-anchored, so
#:   ``retrieval(x)`` and ``function (a, b)`` no longer count as dynamic code;
#: * an encoding escape only counts as a **run** of consecutive escapes (the
#:   obfuscated-payload shape), not a lone ``\\xc0`` in a string table;
#: * "credential theft" requires a theft verb, not the word ``credentials``
#:   (which alone made axios a DO-NOT-INSTALL).
MALWARE_PATTERN_TABLE: Tuple[MalwarePattern, ...] = (
    MalwarePattern(r"\beval\s*\(", "eval() - dynamic code execution", ignore_case=False),
    MalwarePattern(
        r"\bnew\s+Function\s*\(|\bFunction\s*\(\s*['\"`]",
        "Function constructor - dynamic code",
        ignore_case=False,
    ),
    MalwarePattern(r"child_process", "child_process - command execution"),
    MalwarePattern(
        r"(?:\.|\b)(?:exec|execSync|execFile|execFileSync)\s*\(",
        "exec() - command execution",
        requires="child_process",
    ),
    MalwarePattern(
        r"(?:\.|\b)(?:spawn|spawnSync)\s*\(",
        "spawn() - process spawning",
        requires="child_process",
    ),
    MalwarePattern(r"require\s*\(\s*['\"]fs['\"]\s*\)", "filesystem access"),
    MalwarePattern(r"require\s*\(\s*['\"]net['\"]\s*\)", "network access"),
    MalwarePattern(r"require\s*\(\s*['\"]http['\"]\s*\)", "HTTP client"),
    MalwarePattern(r"require\s*\(\s*['\"]https['\"]\s*\)", "HTTPS client"),
    MalwarePattern(r"process\.env", "environment variable access"),
    MalwarePattern(
        r"Buffer\.from\([^)]+,\s*['\"]base64['\"]", "base64 decoding"
    ),
    MalwarePattern(r"\batob\s*\(", "base64 decoding (atob)"),
    # Only escapes in the PRINTABLE ASCII range (\x20-\x7f) count. Writing
    # readable text as `\x63\x75\x72\x6c` ("curl") has no purpose except to hide
    # it from a reader, whereas an arbitrary-byte run is embedded binary data:
    # pdf-parse's PDF worker and sass's dist both carry a long `\xNN` run of
    # font/CMap bytes, and the unrestricted pattern made them corroborating
    # evidence of obfuscation (F33).
    MalwarePattern(
        r"(?:\\x[2-7][0-9a-fA-F]){%d,}" % ENCODED_RUN_LENGTH,
        "hex-encoded string blob (possible obfuscation)",
    ),
    MalwarePattern(
        r"(?:\\u[0-9a-fA-F]{4}){%d,}" % ENCODED_RUN_LENGTH,
        "unicode-encoded string blob (possible obfuscation)",
    ),
    MalwarePattern(
        r"\b(?:cryptocurrency|bitcoin|monero|wallet)\b",
        "cryptocurrency references",
    ),
    # Three arms, because only one of the three spellings is unambiguous.
    #
    # ``keylogger`` / ``keylogging`` name the thing and have no benign twin, so
    # they fire alone. The bare token ``keylog`` does have one, and it is in the
    # standard library: ``keylog`` is Node's TLS session-key event
    # (``tlsSocket.on('keylog', line => …)``, ``--tls-keylog=<file>``), which
    # writes an NSS keylog file so *you* can decrypt *your own* traffic in
    # Wireshark. Nothing to do with keystrokes (F39).
    #
    # Measured over 1,372 unique installed packages / 56,282 scanned source
    # files, every hit this rule produced was that event: 8 files, all of them
    # ``@types/node``'s ``tls.d.ts`` and ``https.d.ts``. Because the rule is
    # always-dangerous, one hit is a verdict — and those 8 files made
    # ``@types/node``, a package containing no runtime code at all, DO NOT
    # INSTALL, which was **4 of the 7** danger verdicts the whole phase produced
    # over that corpus.
    #
    # So ``keylog`` now needs a :data:`_KEYLOG_THEFT_VERB` within
    # :data:`KEYLOG_VERB_WINDOW` **after** it on the same line — exactly the
    # corroboration the equally-weak ``keystrokes`` arm has always required.
    #
    # Narrowing the pattern rather than skipping ``.d.ts`` is what makes this
    # hold for code as well as declarations: the runtime form
    # ``socket.on('keylog', …)`` in a real ``.js`` file was condemned by the same
    # arm, and a file-selection fix would have left that untouched.
    #
    # The reverse phrasing ("harvest the keylog") is a KNOWN, measured miss, not
    # an oversight. Every arm here starts with the literal ``key``, so CPython
    # skips to the next ``k`` instead of trying the branch at every offset; an
    # arm led by the verbs instead starts on s/e/h and destroys that. Measured
    # over 25.7 MB of real bundle text: 0.60s before this task, 0.64s as
    # written, **1.04s** with the reverse arm added — 63% of the pattern's whole
    # runtime, spent on a shape with zero true positives in the 1,372-package
    # corpus. A test pins the miss so it stays a decision rather than a bug.
    MalwarePattern(
        r"\bkey(?:logger|logging)\b"
        r"|\bkeylog\b[^\n]{0,%d}\b(?:%s)" % (KEYLOG_VERB_WINDOW, _KEYLOG_THEFT_VERB)
        + r"|\bkeystrokes?\b[^\n]{0,%d}\b(?:captur|logg|record|steal)"
        % KEYLOG_VERB_WINDOW,
        "keylogger indicators",
    ),
    MalwarePattern(
        r"\bscreenshot\b|\bscreen[\s._-]?captur\w*", "screen capture"
    ),
    MalwarePattern(
        r"\b(?:steal|exfiltrat|harvest|siphon|dump)\w*[^\n]{0,40}"
        r"\b(?:credential|password|secret)s?\b"
        r"|\b(?:credential|password)s?\b[^\n]{0,40}"
        r"\b(?:steal|exfiltrat|harvest|siphon)\w*",
        "credential theft",
    ),
    MalwarePattern(
        r"reverse[\s._-]?shell|bind[\s._-]?shell", "shell backdoor"
    ),
    # A shell spawned for one of the two reasons an attacker spawns one.
    #
    # F31 introduced this as "spawning a raw shell binary, as opposed to
    # spawning `git` or `node`" and measured it at zero hits over 480 packages.
    # A wider sweep — 2,080 unique installed packages, 82,677 scanned files —
    # falsifies that: invoking an interpreter to *query the OS* or hand a path
    # to a Windows helper is what every cross-platform tool does. All four hits
    # it produced are support code. `vite` runs `execSync('powershell -NoProfile
    # -Command "[Console]::OutputEncoding=…"')`, `app-builder-lib` runs
    # `exec("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
    # "Get-Command pwsh.exe"])`, and `next`'s dev overlay runs
    # `spawn("cmd.exe", ["/C", editor].concat(args))` to open your editor. The
    # old pattern called all three DO NOT INSTALL — worse, since it is
    # always-dangerous AND a context signal, one hit both condemned the package
    # and escalated every capability in the file with it (F38).
    #
    # Narrowed to the two shapes with no benign twin:
    #
    # * the shell is handed **no command at all** — an interactive shell whose
    #   stdio the caller then wires somewhere, i.e. the reverse shell. Support
    #   code always passes a command (`sh -c "npm run build"`, `powershell
    #   -Command …`), so an absent or **empty** argv is what separates them —
    #   empty, not short, because `next` passes a two-element one;
    # * the command line carries a **payload**: a downloader (`cmd.exe /c curl …
    #   && a.exe`) or, for PowerShell only, an encoded one (`-enc`,
    #   `FromBase64String`). Reading past the first string literal to the rest of
    #   the line is what catches `execFile('cmd.exe', ['/c', 'curl …'])`, which
    #   the old first-literal-only pattern could not see.
    #
    # The union fires on zero of those 2,080 packages and on every malicious
    # fixture, and costs nothing: 0.88s vs the old 1.07s over 23.5 MB of real
    # bundles (see :data:`_PROCESS_CALL` for why the spelling matters).
    MalwarePattern(
        _PROCESS_CALL + r"(?:"
        # the shell IS the whole argument: no command, empty or absent argv
        r"\s*(?:" + _SHELL_BINARY + r")\s*['\"`]\s*(?:\)|,\s*\[\s*\]\s*[,)])"
        # or the command line carries a payload
        r"|[^\n]{0,%d}?(?:" % SHELL_COMMAND_WINDOW
        + r"(?:" + _SHELL_BINARY + r")[^\n]{0,%d}?(?:" % SHELL_COMMAND_WINDOW
        + _SHELL_PAYLOAD + r")"
        r"|" + _POWERSHELL + r"[^\n]{0,%d}?(?:" % SHELL_COMMAND_WINDOW
        + _POWERSHELL_ENCODED + r")"
        r")"
        r")",
        "shell process spawned",
    ),
    # A command string that fetches and immediately executes. The install-script
    # phase already flags this shape in a lifecycle hook; installed code can run
    # it too (a destructured `exec('curl … | sh')` carries no other signal).
    # Also measured at zero hits across the 480-package corpus.
    MalwarePattern(
        r"(?:curl|wget)\b[^\n'\"`]{0,120}\|\s*(?:sudo\s+)?(?:ba)?sh\b"
        r"|(?:Invoke-WebRequest|Net\.WebClient|DownloadString)[^\n]{0,120}"
        r"(?:iex|Invoke-Expression)",
        "download piped to shell",
    ),
    # The classic npm dropper cradle. Decoding base64 is ordinary data handling
    # (typescript decodes an IPC response that way), so plain "base64 decoding"
    # is not corroboration on its own — but *executing* what was decoded, in the
    # call itself, has no benign reading.
    MalwarePattern(
        r"\b(?:eval|new\s+Function|Function|execSync|exec|spawnSync|spawn)\s*\(\s*"
        r"[^;\n]{0,80}?(?:Buffer\.from\s*\([^)\n]*['\"]base64['\"]|\batob\s*\()",
        "decoded payload executed (base64 -> eval/exec)",
        ignore_case=False,
    ),
    # F35: what `require('https')` was *meant* to stand for, stated directly.
    # A network call and an execution sink close enough together to be one
    # operation is the dropper (fetch, then run what came back) and the
    # exfiltrator (run, then send the output out). A build tool does both
    # things — that is why the import alone condemned vite and esbuild — but it
    # does not wire them to each other.
    MalwarePattern(
        _wired_within(_NETWORK_CALL, _DYNAMIC_CODE_SINK),
        "network I/O wired to dynamic code execution",
        ignore_case=False,
    ),
    MalwarePattern(
        _wired_within(_NETWORK_CALL, _COMMAND_EXEC_SINK),
        "network I/O wired to command execution",
        ignore_case=False,
        requires="child_process",
    ),
)

#: Backwards-compatible ``(regex, description)`` view of the table.
MALWARE_PATTERNS: Tuple[Tuple[str, str], ...] = tuple(
    (pattern.regex, pattern.description) for pattern in MALWARE_PATTERN_TABLE
)

#: Descriptions that are malicious on their own — no benign reading, so they
#: are dangers wherever they appear.
ALWAYS_DANGEROUS_DESCRIPTIONS: frozenset = frozenset(
    {
        "keylogger indicators",
        "credential theft",
        "shell backdoor",
        "shell process spawned",
        "download piped to shell",
        "decoded payload executed (base64 -> eval/exec)",
        "network I/O wired to dynamic code execution",
        "network I/O wired to command execution",
    }
)

#: Descriptions that are a *capability*, not evidence of malice. Running a
#: subprocess or building a function at runtime is what build tooling does:
#: typescript, webpack, eslint, commander and bluebird all do it, and the
#: keyword classifier called every one of them DO NOT INSTALL. A capability is
#: escalated to a danger only when the SAME file also carries an attacker
#: context signal — the composite discipline the ``AGENT-*`` rules already use.
CAPABILITY_DESCRIPTIONS: frozenset = frozenset(
    {
        "child_process - command execution",
        "exec() - command execution",
        "spawn() - process spawning",
        "eval() - dynamic code execution",
        "Function constructor - dynamic code",
    }
)

#: Attacker context: egress channels, obfuscation and shell spawning. Each
#: member was measured against a real install of 480 packages (the top-N plus
#: their transitive tree) and pairs with a capability in **zero** files there.
#:
#: The exclusions are the calibration, and each one is a package this set would
#: otherwise have condemned:
#:
#: * ``filesystem access`` / ``environment variable access`` — ordinary in any
#:   package that also shells out;
#: * ``base64 decoding`` — typescript decodes an IPC response that way; the
#:   decode-and-*execute* cradle has its own always-dangerous pattern instead;
#: * ``network access`` (``require('net')``) — a local-daemon socket client
#:   (fb-watchman, a jest dependency) spawns its daemon and talks to it over a
#:   socket; the reverse-shell shape it was meant to catch is covered by
#:   ``shell process spawned`` and ``shell backdoor``;
#: * ``unicode-encoded string blob`` — json5, terser and @vue all embed Unicode
#:   identifier range tables as long ``\\uXXXX`` runs. The hex form stays in the
#:   set, but F33 narrowed the *pattern* to printable-ASCII escapes so embedded
#:   binary (a PDF worker's font tables, sass's dist) is no longer read as
#:   obfuscation — F31's claim that hex "has no benign twin" held only for its
#:   480-package corpus.
#:
#: One further exclusion came from F33, which widened the phase's file selection
#: past ``*.js`` and so read a much larger slice of real installed code.
#: Re-measured over **995 publishable installed packages** (vs F31's 480):
#:
#: * ``screen capture`` — pairs with ``child_process`` in every package that
#:   renders or visually tests something; ``pdf-parse``'s own CLI test spawns a
#:   process and talks about screenshots, and puppeteer / playwright /
#:   jest-image-snapshot are that same shape. "Spawns a process and mentions
#:   screenshots" describes a testing tool, not spyware. It remains a
#:   warning-level pattern; only its power to promote a capability to a danger
#:   is removed.
#:
#: F35 then removed the two signals the set was built around. ``HTTP client`` and
#: ``HTTPS client`` match ``require('http')`` / ``require('https')`` — an
#: **import**, which says nothing about what the file does with it. Re-measured
#: over 736 installed packages they escalated 17 capabilities across 5 packages
#: and every one was false: ``vite``'s two hits are inside a JSDoc comment
#: (``* var connect = require('connect'), http = require('http')``), all three
#: ``@agent-tars`` hits are webpack's bundled module map (``http: function
#: (module) { module.exports = require("http") }``), and ``esbuild``'s is a real
#: import used to download its own platform binary from the npm registry. F31
#: measured this pairing at zero over 480 packages; the wider corpus falsifies
#: that, and narrowing an *import* pattern cannot separate "downloads and then
#: executes" from "is a build tool" — at the import the two are the same code.
#: The shape the set actually wanted is now stated directly by the two
#: ``network I/O wired to …`` patterns, which require the network call and the
#: execution sink to be within :data:`NETWORK_EXEC_WINDOW` of each other. Both
#: import patterns remain in the table, as warnings.
CONTEXT_DESCRIPTIONS: frozenset = frozenset(
    {
        "hex-encoded string blob (possible obfuscation)",
        "cryptocurrency references",
        "shell process spawned",
        "network I/O wired to dynamic code execution",
        "network I/O wired to command execution",
    }
)

_COMPILED_MALWARE_PATTERNS: Tuple[Tuple[Any, MalwarePattern], ...] = tuple(
    (
        re.compile(pattern.regex, re.IGNORECASE if pattern.ignore_case else 0),
        pattern,
    )
    for pattern in MALWARE_PATTERN_TABLE
)


def _gate_is_open(name: str, content: str, cache: Dict[str, bool]) -> bool:
    """Whether co-occurrence gate ``name`` is satisfied by ``content``.

    Cached per file: a gate is checked at most once no matter how many patterns
    depend on it.
    """
    if name not in cache:
        gate = _CO_OCCURRENCE_GATES.get(name)
        # An unknown gate name would silently disable its patterns, so treat it
        # as closed only when it is genuinely absent from the registry — the
        # anti-drift test asserts every `requires` resolves.
        cache[name] = bool(gate.search(content)) if gate is not None else False
    return cache[name]


def scan_text_for_malware_patterns(content: str) -> List[str]:
    """Descriptions of every malware pattern present in ``content``.

    Order follows :data:`MALWARE_PATTERN_TABLE` so a report is deterministic.
    """
    if not content:
        return []
    gates: Dict[str, bool] = {}
    return [
        pattern.description
        for compiled, pattern in _COMPILED_MALWARE_PATTERNS
        if (not pattern.requires or _gate_is_open(pattern.requires, content, gates))
        and compiled.search(content)
    ]


@dataclass
class MalwareClassification:
    """Malware-pattern hits split into dangers and warnings."""

    counts: Dict[str, int] = field(default_factory=dict)
    dangers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    #: Capability descriptions escalated to dangers because some file carried
    #: them alongside an attacker context signal. Surfaced so the report can say
    #: WHY a capability became a danger instead of asserting it.
    corroborated: List[str] = field(default_factory=list)

    @property
    def total_hits(self) -> int:
        return sum(self.counts.values())


def is_dangerous_hit(description: str) -> bool:
    """Whether ``description`` is malicious on its own, ignoring context.

    Capability descriptions deliberately return ``False`` here: they only
    become dangers through :func:`corroborated_capabilities`.
    """
    return description in ALWAYS_DANGEROUS_DESCRIPTIONS


def corroborated_capabilities(hits: Sequence[Tuple[str, str]]) -> List[str]:
    """Capability descriptions that share a FILE with an attacker context signal.

    Grouping is per file, never per package: "some file runs subprocesses and
    some other file speaks HTTP" describes most build tools, and treating that
    as corroboration is how the keyword classifier ended up condemning them.
    """
    per_file: Dict[str, set] = {}
    for path, description in hits:
        per_file.setdefault(path, set()).add(description)

    escalated: set = set()
    for descriptions in per_file.values():
        if descriptions & CONTEXT_DESCRIPTIONS:
            escalated |= descriptions & CAPABILITY_DESCRIPTIONS
    return sorted(escalated)


def classify_malware_hits(
    hits: Sequence[Tuple[str, str]],
) -> MalwareClassification:
    """Group ``(file, description)`` hits by description and rank them.

    Insertion order is preserved so the report is deterministic for a given
    walk rather than dependent on hash ordering.
    """
    result = MalwareClassification()
    for _path, description in hits:
        result.counts[description] = result.counts.get(description, 0) + 1

    escalated = set(corroborated_capabilities(hits))
    result.corroborated = sorted(escalated)

    for description, count in result.counts.items():
        line = f"{description}: {count} occurrences"
        if is_dangerous_hit(description):
            result.dangers.append(f"🚨 {line}")
        elif description in escalated:
            result.dangers.append(
                f"🚨 {line} (in a file that also shows network/obfuscation indicators)"
            )
        else:
            result.warnings.append(f"⚠️ {line}")
    return result


# ---------------------------------------------------------------------------
# Phase 6 — CVE findings
# ---------------------------------------------------------------------------

#: Severities that block the install; anything else is reported as a warning.
BLOCKING_SEVERITIES = frozenset({"CRITICAL", "HIGH"})


@dataclass
class CveClassification:
    """CVE findings split by severity."""

    dangers: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    @property
    def found_any(self) -> bool:
        return bool(self.dangers or self.warnings)


def _severity_name(severity: Any) -> str:
    """Severity as an upper-case string, whether it is an enum or a str."""
    value = getattr(severity, "value", severity)
    return str(value).upper()


def classify_cve_findings(findings: Iterable[Any]) -> CveClassification:
    """Split scanner findings into blocking dangers and informational warnings.

    Duck-typed over ``severity`` / ``cve_id`` / ``title`` so it works with any
    scanner's finding object (and with test doubles) without importing the
    scanner package.
    """
    result = CveClassification()
    for finding in findings or []:
        severity = _severity_name(getattr(finding, "severity", ""))
        cve_id = getattr(finding, "cve_id", None) or "UNKNOWN"
        title = getattr(finding, "title", "") or ""
        if severity in BLOCKING_SEVERITIES:
            result.dangers.append(f"🔴 {cve_id}: {title}")
        else:
            result.warnings.append(f"🟡 {cve_id}: {title}")
    return result


# ---------------------------------------------------------------------------
# Phase 7 — typosquatting
# ---------------------------------------------------------------------------

POPULAR_PACKAGES: Tuple[str, ...] = (
    "react", "lodash", "express", "axios", "moment", "jquery",
    "vue", "angular", "webpack", "babel", "typescript", "eslint",
    "prettier", "jest", "mocha", "chai", "underscore", "async",
    "request", "bluebird", "chalk", "commander", "inquirer",
    "debug", "uuid", "dotenv", "cors", "body-parser", "mongoose",
    "sequelize", "redux", "next", "gatsby", "nuxt", "svelte",
)

TYPOSQUAT_THRESHOLD = 0.75


def typosquat_matches(
    pkg_spec: str,
    popular: Sequence[str] = POPULAR_PACKAGES,
    threshold: float = TYPOSQUAT_THRESHOLD,
) -> List[Tuple[str, float]]:
    """Popular packages this name is suspiciously close to, most similar first.

    An exact match scores 1.0 and is excluded — ``lodash`` is not a typosquat of
    ``lodash``. The comparison uses the bare package name, so a scope or version
    spec cannot dilute the ratio.
    """
    name = installed_package_dirname(pkg_spec).lower().split("/")[-1]
    if not name:
        return []
    matches: List[Tuple[str, float]] = []
    for candidate in popular:
        if name == candidate:
            continue
        ratio = difflib.SequenceMatcher(None, candidate, name).ratio()
        if threshold < ratio < 1.0:
            matches.append((candidate, ratio))
    matches.sort(key=lambda item: (-item[1], item[0]))
    return matches


# ---------------------------------------------------------------------------
# Final verdict rendering
# ---------------------------------------------------------------------------


def _escape_markup(text: str) -> str:
    """Neutralize Rich console markup in interpolated user input.

    The package name comes straight from a prompt; an unescaped ``[`` in it
    would be parsed as a style tag and could blank out or recolor the verdict.
    """
    return (text or "").replace("[", r"\[")


@dataclass
class VerdictSummary:
    """Everything the CLI needs to render the final panel."""

    verdict: Verdict
    title: str
    body: str
    border_style: str
    next_step_type: str


def build_verdict_summary(
    verdict: Verdict, pkg_name: str, danger_count: int = 0
) -> VerdictSummary:
    """Render the verdict panel content.

    Kept here, not in the CLI, so the tests can assert what the user is
    actually told — specifically that an INCONCLUSIVE run never renders the
    "APPEARS SAFE" language.
    """
    safe_name = _escape_markup(pkg_name)

    if verdict is Verdict.DANGER:
        body = (
            f"[danger]🚫 DO NOT INSTALL[/danger]\n\n"
            f"Package '{safe_name}' has [bright_red]{danger_count}[/bright_red] "
            f"security issue(s)!\n\n"
            f"[bright_yellow]Recommendations:[/bright_yellow]\n"
            f"• Search for alternative packages\n"
            f"• Report to npm if malicious\n"
            f"• Check package on snyk.io or socket.dev"
        )
        border = "bright_red"
    elif verdict is Verdict.INCONCLUSIVE:
        body = (
            f"[warning]⚠️ INCONCLUSIVE - ANALYSIS WAS INCOMPLETE[/warning]\n\n"
            f"No security issue was found in package '{safe_name}', but parts of\n"
            f"the analysis could not run (see WARNINGS above).\n"
            f"[dim]Absence of findings here is NOT a clean bill of health.[/dim]\n\n"
            f"Re-run the check, or review the package manually before installing."
        )
        border = "bright_yellow"
    else:
        body = (
            f"[success]✅ APPEARS SAFE TO DOWNLOAD[/success]\n\n"
            f"Package '{safe_name}' passed security analysis.\n"
            f"[dim]Note: No automated scan is 100% - review code if handling "
            f"sensitive data[/dim]\n\n"
            f"Install with: [bright_white]npm install {safe_name}[/bright_white]"
        )
        border = "bright_green"

    return VerdictSummary(
        verdict=verdict,
        title="🛡️ VERDICT",
        body=body,
        border_style=border,
        next_step_type=NEXT_STEP_TYPES[verdict],
    )
