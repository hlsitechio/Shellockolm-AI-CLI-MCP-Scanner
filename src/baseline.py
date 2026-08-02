"""Baseline support for ``shellockolm scan`` (build-loop task #25).

Lets CI fail **only on NEW findings**. You snapshot the findings you currently
accept into a baseline file, commit it, and from then on only findings that are
*not* in the baseline gate the build:

* ``scan --write-baseline baseline.json`` — run a scan and write every current
  finding into ``baseline.json`` (a report-only run that never fails the build).
  Commit that file. This is how you "accept" the existing findings.
* ``scan --baseline baseline.json`` — run a scan and drop every finding already
  in the baseline; only NEW findings are reported and can gate the exit code
  (composes with ``--fail-on``). A missing/corrupt baseline is a usage error
  (CLI exit 2), never a silent pass.

Two concerns live here, split so the risky part is pure and unit-testable,
mirroring :mod:`diff_scan`:

* :func:`load_baseline` reads/parses the baseline file and raises
  :class:`BaselineError` (→ CLI exit 2) on any problem.
* :func:`finding_fingerprint` / :func:`filter_results_to_new` /
  :func:`build_baseline_document` are the pure identity + filtering logic where
  the real false-positive/negative risk lives, and are exhaustively tested.

**Fingerprint design.** A finding's identity is a SHA-256 over
``id | repo-relative-path | package | version`` — deliberately EXCLUDING the
line number and the severity. Excluding the line number means editing a file
(shifting a finding up or down) does NOT make an old finding look "new" and
spuriously fail the build — the property that matters most for a baseline.
Excluding severity means a later composite-severity boost of the same detection
is still recognised as the same finding. The trade-off (two findings of the same
rule on the same file/package collapse to one key) favours not-spuriously-failing
CI, the whole point of a baseline; refresh the baseline after a large refactor.
The path is stored repo-relative, forward-slashed and case-folded, so a baseline
written on one machine matches a scan on another that runs from the same root.
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime
from pathlib import Path
from typing import List, Set

from diff_scan import bare_path

# The baseline file format version. Within a major version, fields are only
# ADDED, never renamed or removed (same contract as the --json report).
BASELINE_SCHEMA_VERSION = "1.0"


class BaselineError(RuntimeError):
    """Raised when the baseline file cannot be read or parsed.

    Cases: the file does not exist, is unreadable, is not valid JSON, or does
    not have the expected shape (a JSON object with a ``findings`` array). The
    CLI surfaces the message and exits with the usage/operational error code
    (2), never the findings code — so a typo'd or corrupt baseline can never
    masquerade as a clean run.
    """


def _severity_str(finding) -> str:
    """Normalize a finding's severity to an UPPERCASE string (enum or str)."""
    sev = getattr(finding, "severity", "")
    return (sev.value if hasattr(sev, "value") else str(sev)).upper()


def rel_key(file_path: str, base: str) -> str:
    """Stable, portable key for a finding's file: repo-relative, ``/``, case-folded.

    Strips the structured ``» …`` / trailing ``:<line>`` suffix via
    :func:`diff_scan.bare_path`, resolves a relative path against ``base`` (the
    scan's working directory) to an absolute path, then re-expresses it relative
    to ``base``. The result is ``normcase``-folded (lower-cases the drive/path on
    Windows, a no-op on POSIX) and forward-slashed, so the same artifact yields
    the same key regardless of OS path separator or invocation directory.
    """
    bare = bare_path(file_path)
    if not bare:
        return ""
    abs_path = bare if os.path.isabs(bare) else os.path.join(base, bare)
    try:
        rel = os.path.relpath(abs_path, base)
    except ValueError:
        # Different drive on Windows — no relative path exists; fall back to the
        # absolute path so the key is still deterministic.
        rel = abs_path
    return os.path.normcase(rel).replace("\\", "/")


def _raw_fingerprint(id_: str, rel_path: str, package: str, version: str) -> str:
    """SHA-256 over the stable identity tuple. ``rel_path`` is already normalized."""
    raw = "|".join([id_ or "", rel_path or "", package or "", version or ""])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def finding_fingerprint(finding, *, base: str) -> str:
    """Stable identity hash for a live :class:`ScanFinding` (see module docstring)."""
    return _raw_fingerprint(
        getattr(finding, "cve_id", "") or "",
        rel_key(getattr(finding, "file_path", "") or "", base),
        getattr(finding, "package", "") or "",
        getattr(finding, "version", "") or "",
    )


def build_baseline_document(results, *, target: str, base: str, tool_version: str = "") -> dict:
    """Assemble the baseline document from scan results.

    Each finding contributes a self-describing entry: its ``fingerprint`` (the
    key compared on later runs) plus human-readable metadata (id / severity /
    scanner / file / package / version / title) so the committed file is
    auditable in review. Entries are de-duplicated by fingerprint and sorted, so
    the file is deterministic and produces clean diffs across regenerations.
    """
    entries = []
    for r in results:
        for f in r.findings:
            fp = finding_fingerprint(f, base=base)
            entries.append({
                "fingerprint": fp,
                "id": getattr(f, "cve_id", "") or "",
                "severity": _severity_str(f),
                "scanner": getattr(r, "scanner_name", "") or "",
                "file": rel_key(getattr(f, "file_path", "") or "", base),
                "package": getattr(f, "package", "") or "",
                "version": getattr(f, "version", "") or "",
                "title": getattr(f, "title", "") or "",
            })

    seen: Set[str] = set()
    unique: List[dict] = []
    for e in sorted(entries, key=lambda e: (e["fingerprint"], e["id"], e["file"])):
        if e["fingerprint"] in seen:
            continue
        seen.add(e["fingerprint"])
        unique.append(e)

    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "tool": {"name": "shellockolm", "version": tool_version},
        "generated": datetime.now().isoformat(),
        "target": target,
        "findings": unique,
    }


def load_baseline(path: str) -> Set[str]:
    """Read a baseline file and return its set of finding fingerprints.

    Raises :class:`BaselineError` (→ CLI exit 2) if the file is missing,
    unreadable, not valid JSON, or not the expected shape. An entry missing a
    ``fingerprint`` is tolerated (older / hand-edited baselines): its key is
    recomputed from the stored ``id``/``file``/``package``/``version`` fields,
    which are already in normalized form.
    """
    p = Path(path)
    if not p.exists():
        raise BaselineError(f"baseline file not found: {path}")
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise BaselineError(f"could not read baseline {path}: {e}")
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise BaselineError(f"baseline file is not valid JSON ({path}): {e}")
    if not isinstance(doc, dict) or not isinstance(doc.get("findings"), list):
        raise BaselineError(
            f"unrecognized baseline format in {path} "
            "(expected a JSON object with a 'findings' array)"
        )

    fingerprints: Set[str] = set()
    for entry in doc["findings"]:
        if not isinstance(entry, dict):
            continue
        fp = entry.get("fingerprint")
        if isinstance(fp, str) and fp:
            fingerprints.add(fp)
        else:
            fingerprints.add(_raw_fingerprint(
                str(entry.get("id", "") or ""),
                str(entry.get("file", "") or ""),
                str(entry.get("package", "") or ""),
                str(entry.get("version", "") or ""),
            ))
    return fingerprints


def filter_results_to_new(results, baseline_fingerprints: Set[str], *, base: str) -> int:
    """Drop findings already in the baseline in-place; return how many were dropped.

    Each :class:`ScanResult` keeps only findings whose fingerprint is NOT in
    ``baseline_fingerprints`` and records the per-scanner drop count under
    ``stats['findings_baselined']`` so the suppression is auditable and never
    silent. Mirrors :func:`diff_scan.filter_results_to_changed`.
    """
    total_dropped = 0
    for r in results:
        before = len(r.findings)
        r.findings = [
            f for f in r.findings
            if finding_fingerprint(f, base=base) not in baseline_fingerprints
        ]
        dropped = before - len(r.findings)
        if dropped:
            r.stats["findings_baselined"] = (
                r.stats.get("findings_baselined", 0) + dropped
            )
            total_dropped += dropped
    return total_dropped
