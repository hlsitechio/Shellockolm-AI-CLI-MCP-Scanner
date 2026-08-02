"""Phase 5 file selection and deep-code walk for ``sandbox <pkg>``
(build-loop follow-up F33).

The deep-code-analysis phase of the interactive ``sandbox <pkg>`` check was a
single line inside ``interactive_shell()``::

    for js_file in node_modules.rglob("*.js"):

so the malware pass read **only** ``.js``. A package whose entry point is
``.cjs`` / ``.mjs`` — increasingly the default now that ESM-only packages ship
dual builds — or that ships TypeScript source, a ``bin/`` script with no
extension, or an ``install.sh`` / ``install.ps1`` invoked from a lifecycle hook,
had **zero** files read by the phase. Worse, unlike an unreadable file (which
F29 taught the phase to count and report), scanning nothing was indistinguishable
from scanning everything and finding nothing: the run printed
"✓ No obvious malware patterns" and contributed an ``info`` finding over a phase
that had not looked at a single byte, and the package could reach
"APPEARS SAFE TO DOWNLOAD" on it.

This module is that phase's file selection and walk, as functions over a
directory:

* :func:`is_scannable_code_path` decides — by path segment and extension, never
  by substring — which installed files are executable source. It is the whole
  fix to the coverage half, and it is pure.
* :func:`scan_installed_package_code` walks the installed package and returns a
  :class:`DeepCodeScanReport` that reports its own coverage:
  :meth:`DeepCodeScanReport.blind_reason` is non-``None`` whenever the phase did
  not actually see the package's code, so the caller marks the phase blind
  (``SandboxFindings.mark_blind``) instead of printing a pass — the F29 rule
  that **a blind phase is never a pass**, applied to the case F29 itself missed.

The directory walk records — rather than swallows — a directory it could not
read, mirroring :mod:`sandbox_snapshot`: a tree that half-failed must not read
as a clean tree.

Filesystem-touching but console-free and unit-testable, mirroring
``sandbox_snapshot``; the pattern table and the danger/warning classification
stay in the pure :mod:`sandbox_check`.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Optional, Sequence, Tuple

from sandbox_check import scan_text_for_malware_patterns

# ---------------------------------------------------------------------------
# What counts as executable source
# ---------------------------------------------------------------------------

#: Extensions the deep-code pass reads, lower-cased and dot-prefixed.
#:
#: Scope rule: an extension belongs here when a published npm package can get
#: the file *executed* — by node, by a ``bin`` entry, or by a lifecycle hook.
#:
#: Deliberately absent:
#:
#: * ``.json`` — data, not code, and counting it would defeat the blind check
#:   this task adds: every npm package ships a ``package.json``, so no package
#:   could ever report "nothing scannable found". A nested package's lifecycle
#:   *hooks* are a real gap, but they want the structured
#:   ``analyze_install_scripts`` pass, not the free-text malware table (F34).
#: * ``.map`` — a source map is generated data; it also never matched the old
#:   ``*.js`` glob, so excluding it is not a regression.
#: * ``.node`` / ``.wasm`` — compiled binaries. The pattern table is a text
#:   scan; pretending to have scanned them is exactly the overclaim this
#:   module exists to stop, so a package that ships only those is reported
#:   blind.
SCANNABLE_CODE_EXTENSIONS: frozenset = frozenset(
    {
        # JavaScript, in every form npm actually publishes an entry point as.
        ".js",
        ".cjs",
        ".mjs",
        ".jsx",
        # TypeScript source, shipped unbuilt by a growing number of packages
        # and run directly by node >= 22, bun, deno and ts-node.
        ".ts",
        ".cts",
        ".mts",
        ".tsx",
        # Scripts a lifecycle hook or a `bin` entry invokes.
        ".sh",
        ".bash",
        ".zsh",
        ".ps1",
        ".psm1",
        ".bat",
        ".cmd",
        ".py",
    }
)

#: Directories whose extension-less entries are executables. ``bin/`` is npm's
#: own convention for a package's command (``"bin": {"tool": "bin/cli"}``), and
#: such a file is routinely shipped with a shebang and no extension — the exact
#: shape the ``*.js`` glob could never see.
EXECUTABLE_SCRIPT_DIRS: frozenset = frozenset({"bin", ".bin"})

#: How many unreadable paths are kept as examples for the console line.
MAX_UNREADABLE_EXAMPLES = 3


def is_scannable_code_path(path: str) -> bool:
    """Whether ``path`` (relative to the installed package) is executable source.

    Matching is by **extension** and by **path segment**, never by substring, so
    a data file called ``notes.js.txt`` is not scanned and a temp directory that
    merely contains the letters ``bin`` does not make every extension-less file
    in the tree look like an executable — pass a package-relative path and the
    ``bin/`` rule means npm's ``bin`` directory specifically.
    """
    normalized = (path or "").replace("\\", "/").strip("/")
    if not normalized:
        return False

    segments = normalized.split("/")
    name = segments[-1]
    if not name:
        return False

    # `rfind` (not `partition`) so `.eslintrc.js` and `index.d.ts` resolve to
    # their real trailing extension; index 0 means a dotfile with no extension
    # at all (`.npmrc`), not an empty-named file with one.
    dot = name.rfind(".")
    if dot > 0:
        return name[dot:].lower() in SCANNABLE_CODE_EXTENSIONS

    return any(segment.lower() in EXECUTABLE_SCRIPT_DIRS for segment in segments[:-1])


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


@dataclass
class DeepCodeScanReport:
    """Result of the deep-code pass, including how much of it actually ran.

    ``files_scanned`` counts files whose bytes were read and matched. An
    unreadable file is deliberately NOT counted: inflating the coverage number
    behind a "no malware" claim is the failure this whole phase guards against.
    """

    files_scanned: int = 0
    files_unreadable: int = 0
    dir_errors: int = 0
    #: ``(relative path, error text)`` for the first few unreadable files.
    unreadable_examples: List[Tuple[str, str]] = field(default_factory=list)
    #: ``(relative path, pattern description)`` for every malware-pattern hit.
    hits: List[Tuple[str, str]] = field(default_factory=list)
    #: Count of scanned files per extension (``""`` for extension-less ones),
    #: so the report can say what it read rather than claiming "JavaScript".
    scanned_by_extension: Dict[str, int] = field(default_factory=dict)

    @property
    def scanned_anything(self) -> bool:
        return self.files_scanned > 0

    @property
    def coverage_complete(self) -> bool:
        """Every candidate file was read, and there was at least one."""
        return self.scanned_anything and not self.files_unreadable and not self.dir_errors

    def blind_reason(self, package_dir: str = "") -> Optional[str]:
        """Why this phase could not see the package's code, or ``None``.

        A non-``None`` value must reach ``SandboxFindings.mark_blind``: it means
        the malware pass has no conclusion to offer, and "no findings" from it is
        the absence of evidence rather than evidence of absence.
        """
        location = f"node_modules/{package_dir}" if package_dir else "the package"

        if self.files_unreadable or self.dir_errors:
            parts = []
            if self.files_unreadable:
                parts.append(f"{self.files_unreadable} installed file(s) unreadable")
            if self.dir_errors:
                parts.append(f"{self.dir_errors} directory(s) could not be listed")
            detail = " and ".join(parts)
            if not self.scanned_anything:
                return f"{detail} - the package code was NOT analyzed"
            return f"{detail} - code analysis is partial"

        if not self.scanned_anything:
            return (
                f"no scannable source file found under {location} "
                f"- the package code was NOT analyzed"
            )
        return None


def collect_scannable_files(root: Path) -> Tuple[List[Path], int]:
    """Every executable-source file under ``root``, plus a directory-error count.

    Returned sorted so a report is deterministic rather than dependent on the
    order the filesystem hands back. A directory that cannot be listed is
    counted, not swallowed — the caller turns that into a blind phase.
    """
    files: List[Path] = []
    dir_errors = 0

    def on_error(_error: OSError) -> None:
        nonlocal dir_errors
        dir_errors += 1

    for dirpath, _dirnames, filenames in os.walk(root, onerror=on_error):
        current = Path(dirpath)
        for filename in filenames:
            candidate = current / filename
            try:
                relative = candidate.relative_to(root).as_posix()
            except ValueError:  # pragma: no cover - defensive
                continue
            if is_scannable_code_path(relative):
                files.append(candidate)

    files.sort()
    return files, dir_errors


def read_code_file(path: Path) -> str:
    """Read one installed source file.

    A named module-level function (mirroring ``sandbox_snapshot.hash_file``) so
    a test can inject a read failure without needing a genuinely unreadable file
    — which is not portably creatable on Windows.
    """
    return path.read_text(errors="ignore")


def _extension_of(relative_path: str) -> str:
    name = relative_path.replace("\\", "/").rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def scan_installed_package_code(
    root: Path,
    patterns_for: Callable[[str], List[str]] = scan_text_for_malware_patterns,
) -> DeepCodeScanReport:
    """Run the malware-pattern pass over every executable source file in ``root``.

    ``patterns_for`` is injectable purely so a test can drive the walk without
    depending on the calibrated table; production always uses
    :func:`sandbox_check.scan_text_for_malware_patterns`.
    """
    report = DeepCodeScanReport()
    files, report.dir_errors = collect_scannable_files(root)

    for code_file in files:
        relative = code_file.relative_to(root).as_posix()
        try:
            content = read_code_file(code_file)
        except OSError as read_err:
            # An unreadable file is NOT a scanned file: counting it would
            # inflate the coverage number behind a "no malware" claim.
            report.files_unreadable += 1
            if len(report.unreadable_examples) < MAX_UNREADABLE_EXAMPLES:
                report.unreadable_examples.append((relative, str(read_err)))
            continue

        report.files_scanned += 1
        extension = _extension_of(relative)
        report.scanned_by_extension[extension] = (
            report.scanned_by_extension.get(extension, 0) + 1
        )
        for description in patterns_for(content):
            report.hits.append((relative, description))

    return report


def describe_scanned_extensions(counts: Dict[str, int], limit: int = 4) -> str:
    """Human summary of what the pass actually read, e.g. ``".js" x12, "bin" x1``.

    Used by the console line so it reports the files it read instead of the
    hard-coded "JavaScript files" the ``*.js`` glob era printed.
    """
    if not counts:
        return "nothing"
    ordered: Sequence[Tuple[str, int]] = sorted(
        counts.items(), key=lambda item: (-item[1], item[0])
    )
    shown = [
        f"{extension or 'no extension'} x{count}" for extension, count in ordered[:limit]
    ]
    remaining = len(ordered) - limit
    if remaining > 0:
        shown.append(f"+{remaining} more")
    return ", ".join(shown)
