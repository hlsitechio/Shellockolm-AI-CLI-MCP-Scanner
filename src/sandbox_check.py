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

#: (substring, human description) pairs treated as dangerous inside a hook.
INSTALL_SCRIPT_DANGER_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("curl", "Downloads external content"),
    ("wget", "Downloads external content"),
    ("eval", "Dynamic code execution"),
    ("exec", "Command execution"),
    ("child_process", "Spawns processes"),
    ("rm -rf", "Destructive file operation"),
    ("base64", "Encoded payload"),
    ("/dev/tcp", "Network backdoor"),
    ("powershell", "PowerShell execution"),
    ("cmd.exe", "Windows command execution"),
    (".bat", "Batch script execution"),
    ("nc ", "Netcat - reverse shell"),
    ("netcat", "Netcat - reverse shell"),
    ("/bin/sh", "Shell execution"),
    ("/bin/bash", "Bash execution"),
    ("socket", "Network socket"),
    ("XMLHttpRequest", "HTTP request"),
    ("fetch(", "HTTP fetch"),
    ("https://", "External URL"),
    ("http://", "External URL (insecure)"),
)


@dataclass
class InstallScriptReport:
    """Which lifecycle hooks a package declares, and what they contain."""

    hooks: List[str] = field(default_factory=list)
    bodies: Dict[str, str] = field(default_factory=dict)
    dangers: List[str] = field(default_factory=list)

    @property
    def has_hooks(self) -> bool:
        return bool(self.hooks)


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
        lowered = body.lower()
        for pattern, description in INSTALL_SCRIPT_DANGER_PATTERNS:
            if pattern.lower() in lowered:
                report.dangers.append(f"🚨 {hook} script: {description} ({pattern})")
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


def is_expected_install_path(path: str) -> bool:
    """True when ``path`` is an artifact npm itself creates in the sandbox.

    Matching is by **path segment**, not substring. The inline version used
    ``'package.json' in path`` / ``'node_modules/' in path``, so a dropped
    payload named ``evil-package.json`` — or hidden at
    ``.ssh/node_modules/authorized_keys`` — was quietly treated as expected and
    never reported.
    """
    normalized = (path or "").replace("\\", "/")
    # Strip a leading "./" only. `lstrip("./")` would strip a CHARACTER SET and
    # turn ".npm-cache/x" into "npm-cache/x", so npm's own cache stopped being
    # recognized and every cached file was reported as a dropped payload.
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    if not normalized:
        return False
    if normalized in EXPECTED_INSTALL_FILES:
        return True
    head = normalized.split("/", 1)[0]
    return head in EXPECTED_INSTALL_DIRS


def filter_suspicious_new_files(new_files: Iterable[str]) -> List[str]:
    """New files that npm did not put there — i.e. what the install wrote."""
    return [path for path in new_files if not is_expected_install_path(path)]


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
    MalwarePattern(
        r"\bkey(?:logger|logging)\b|\bkeylog\b"
        r"|\bkeystrokes?\b[^\n]{0,40}\b(?:captur|logg|record|steal)",
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
    # Spawning a raw shell binary, as opposed to spawning `git` or `node`.
    # Measured at zero hits across 480 installed real packages, which is why
    # this one is trusted on its own where bare `spawn()` is not.
    MalwarePattern(
        r"(?:\.|\b)(?:exec|execSync|execFile|execFileSync|spawn|spawnSync)\s*\(\s*"
        r"['\"`][^'\"`\n]*(?:/bin/(?:sh|bash|zsh)|cmd\.exe|powershell)",
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
CONTEXT_DESCRIPTIONS: frozenset = frozenset(
    {
        "HTTP client",
        "HTTPS client",
        "hex-encoded string blob (possible obfuscation)",
        "cryptocurrency references",
        "shell process spawned",
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
