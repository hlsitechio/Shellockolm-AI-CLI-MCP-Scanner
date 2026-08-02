#!/usr/bin/env python3
"""Render a Shellockolm ``scan --json`` report for the GitHub Action log and emit
the total finding count (build-loop task #21).

The composite action (``action.yml``) runs ``scan --json -o <report> ...`` and then
invokes this helper with the report path. Contract:

* **stdout** carries ONLY the integer total finding count, so the action can do
  ``findings=$(python scripts/action_summary.py report.json)`` and expose it as a
  step output. Nothing else is ever written to stdout.
* **stderr** carries a readable severity breakdown + per-finding lines, which show
  up in the Actions log without polluting the captured count.
* A missing or malformed report (e.g. the scan hit an operational error and exited
  2 before writing the document) is non-fatal: stdout gets ``0`` and stderr a note.
  The action still fails the build on the scan's own exit code.

This file deliberately has no third-party imports so it runs on the bare runner
Python before any ``pip install`` of the package.
"""
from __future__ import annotations

import json
import sys
from typing import Optional, Sequence

_SEV_ORDER = ("critical", "high", "medium", "low", "info")


def _load(path: str):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if not args:
        print(0)
        print("action_summary: no report path given", file=sys.stderr)
        return 0

    report = _load(args[0])
    if not isinstance(report, dict):
        print(0)
        print(
            f"action_summary: no readable JSON report at {args[0]} "
            "(scan likely exited with an operational error before writing one)",
            file=sys.stderr,
        )
        return 0

    summary = report.get("summary") or {}
    total = summary.get("total_findings", 0) or 0
    by_sev = summary.get("by_severity") or {}
    findings = report.get("findings") or []

    # stdout: ONLY the count (consumed by the action's `findings` output).
    print(total)

    # stderr: the readable report for the Actions log.
    if not total:
        print("Shellockolm: no findings.", file=sys.stderr)
        return 0

    breakdown = ", ".join(
        f"{sev}={by_sev.get(sev, 0)}" for sev in _SEV_ORDER if by_sev.get(sev)
    )
    header = f"Shellockolm: {total} finding(s)"
    if breakdown:
        header += f" - {breakdown}"
    print(header, file=sys.stderr)
    for f in findings:
        if not isinstance(f, dict):
            continue
        sev = str(f.get("severity", "?")).upper()
        fid = f.get("id", "?")
        loc = f.get("file_path", "?")
        print(f"  [{sev}] {fid}  {loc}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
