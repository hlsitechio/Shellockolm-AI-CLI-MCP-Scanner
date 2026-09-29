"""Git-diff scoping for ``shellockolm scan --diff`` (build-loop task #19).

Lets pre-commit / CI runs report findings only for the files changed in git —
either the **staged** set (``--diff``: ``git diff --cached``, the exact content a
commit will introduce) or everything that differs from a **ref** (``--diff-ref
<ref>``: ``git diff <ref>``, e.g. ``origin/main`` in CI). Findings on files you
did not touch are dropped, so the signal is scoped to your change.

Two concerns live here, split so the risky part is pure and unit-testable:

* ``resolve_changed_files`` shells out to git to produce the changed-file set
  (absolute, normalized keys). It raises :class:`DiffScanError` — which the CLI
  maps to exit code 2 — when the scope can't be resolved (not a repo, git
  missing, bad ref).
* ``path_matches_changed`` / ``filter_results_to_changed`` decide whether a
  finding belongs to a changed file. This is the part with real
  false-positive/negative risk (a finding's ``file_path`` may carry a trailing
  ``:<line>`` or a ``» server:<name>`` structured suffix, may be absolute or
  relative-to-cwd, and matching must be case-insensitive on Windows). It is pure
  and exhaustively tested.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path
from typing import List, Optional, Set, Tuple


class DiffScanError(RuntimeError):
    """Raised when the changed-file set cannot be resolved.

    Cases: the path is not inside a git work tree, the ``git`` executable is
    missing, a git command failed (e.g. an unknown ref), or a malformed ref was
    supplied. The CLI surfaces the message and exits with the usage/operational
    error code (2), never the findings code.
    """


# Only Added / Copied / Modified / Renamed files still exist on disk and are
# worth scanning; Deleted (D) files have nothing left to read.
_DIFF_FILTER = "ACMR"

# A finding's ``file_path`` ends with a structured suffix for the agent scanner's
# structured rules: ``<path> » server:<name>`` / ``» node:<name>``.
_STRUCTURED_SEP = " » "
# ...and text rules append the line number as ``<path>:<line>``.
_TRAILING_LINE_RE = re.compile(r":(\d+)$")


def _normkey(path: str) -> str:
    """Normalized, case-folded absolute key for cross-platform path comparison.

    ``abspath`` normalizes separators and collapses ``.``/``..``; ``normcase``
    lower-cases the drive + path on Windows (so ``G:\\Repo`` and ``g:\\repo``
    compare equal) and is a no-op on POSIX.
    """
    return os.path.normcase(os.path.abspath(path))


def bare_path(file_path: str) -> str:
    """Strip a finding's structured ``» …`` suffix and trailing ``:<line>``.

    Returns the bare artifact path. A Windows drive colon (``G:\\…``) is preserved
    because :data:`_TRAILING_LINE_RE` is anchored to end-of-string (only a
    *trailing* ``:<digits>`` is the line number). Mirrors the SARIF generator's
    ``_split_location`` so both surfaces agree on what a finding's file is.
    """
    s = (file_path or "").split(_STRUCTURED_SEP, 1)[0].strip()
    m = _TRAILING_LINE_RE.search(s)
    if m:
        s = s[: m.start()]
    return s.strip()


def path_matches_changed(file_path: str, changed_keys: Set[str], *, base: str) -> bool:
    """True if a finding's ``file_path`` resolves to a member of ``changed_keys``.

    ``changed_keys`` is a set of :func:`_normkey` keys (absolute, normalized).
    A relative finding path is resolved against ``base`` (the scan's working
    directory) before comparison; an absolute path is used as-is. Both sides go
    through :func:`_normkey`, so the match is exact and case-insensitive on
    Windows — never a fuzzy basename match (two ``SKILL.md`` in different dirs
    stay distinct).
    """
    bare = bare_path(file_path)
    if not bare:
        return False
    resolved = bare if os.path.isabs(bare) else os.path.join(base, bare)
    return _normkey(resolved) in changed_keys


def filter_results_to_changed(results, changed_keys: Set[str], *, base: str) -> int:
    """Drop findings outside ``changed_keys`` in-place; return how many were dropped.

    Each :class:`ScanResult` keeps only findings whose file is in the changed set
    and records the per-scanner drop count under ``stats['findings_diff_filtered']``
    so the suppression is auditable and never silent.
    """
    total_dropped = 0
    for r in results:
        before = len(r.findings)
        r.findings = [
            f for f in r.findings
            if path_matches_changed(f.file_path, changed_keys, base=base)
        ]
        dropped = before - len(r.findings)
        if dropped:
            r.stats["findings_diff_filtered"] = (
                r.stats.get("findings_diff_filtered", 0) + dropped
            )
            total_dropped += dropped
    return total_dropped


def _run_git(args: List[str], *, cwd: str) -> str:
    """Run ``git <args>`` in ``cwd`` and return stdout, or raise DiffScanError."""
    try:
        proc = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
        )
    except FileNotFoundError:
        raise DiffScanError("git executable not found on PATH")
    except OSError as e:  # pragma: no cover - environment-specific
        raise DiffScanError(f"could not run git: {e}")
    if proc.returncode != 0:
        err = (proc.stderr or "").strip() or f"git exited {proc.returncode}"
        if "not a git repository" in err.lower():
            raise DiffScanError("not a git repository (no work tree here)")
        raise DiffScanError(err)
    return proc.stdout


def git_diff_args(ref: Optional[str] = None) -> List[str]:
    """Build the ``git diff`` argv for staged mode (ref=None) or ref mode.

    Staged: ``diff --cached --name-only --diff-filter=ACMR`` (the pre-commit set).
    Ref:    ``diff --name-only --diff-filter=ACMR <ref>`` (working tree vs ref).

    The ref is passed as its own argv token (never a shell string) and a leading
    ``-`` is rejected, so a value like ``--output`` can't be smuggled in as a git
    option.
    """
    if ref is not None:
        ref = ref.strip()
        if not ref or ref.startswith("-"):
            raise DiffScanError(f"invalid git ref: {ref!r}")
        return ["diff", "--name-only", f"--diff-filter={_DIFF_FILTER}", ref]
    return ["diff", "--cached", "--name-only", f"--diff-filter={_DIFF_FILTER}"]


def _git_toplevel(scan_path: str) -> str:
    """Absolute path to the git work-tree root containing ``scan_path``."""
    p = Path(scan_path)
    cwd = str(p if p.is_dir() else p.parent)
    top = _run_git(["rev-parse", "--show-toplevel"], cwd=cwd).strip()
    if not top:
        raise DiffScanError("not a git repository (no work tree here)")
    return top


def resolve_changed_files(scan_path: str, *, ref: Optional[str] = None) -> Tuple[str, Set[str]]:
    """Resolve the changed-file scope for ``scan_path``.

    Returns ``(toplevel, changed_keys)`` where ``toplevel`` is the git work-tree
    root and ``changed_keys`` is a set of :func:`_normkey` keys for every changed
    file. git is run with ``cwd=toplevel`` so its ``--name-only`` output is
    relative to the root; each name is joined back onto the root to form an
    absolute key. Raises :class:`DiffScanError` on any git failure.
    """
    toplevel = _git_toplevel(scan_path)
    out = _run_git(git_diff_args(ref), cwd=toplevel)
    keys: Set[str] = set()
    for line in out.splitlines():
        name = line.strip()
        if name:
            keys.add(_normkey(os.path.join(toplevel, name)))
    return toplevel, keys
