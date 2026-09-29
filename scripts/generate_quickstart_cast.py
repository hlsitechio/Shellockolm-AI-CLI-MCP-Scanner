#!/usr/bin/env python3
"""Generate ``docs/quickstart.cast`` — the asciinema recording of the 60-second
quickstart (build-loop task #49).

The cast is rendered from a single in-file source of truth: the three quickstart
commands and their **real, lightly-normalized** terminal output (the decorative
per-user welcome banner and machine-specific timestamps are removed so the
recording is reproducible; the finding text itself is exactly what
``shellockolm scan examples/vulnerable-demo`` and ``shellockolm info
CVE-2025-29927`` print). The output is a valid `asciinema v2
<https://docs.asciinema.org/manual/asciicast/v2/>`_ cast.

The render is fully deterministic (fixed timestamp, fixed pacing, LF newlines),
so the committed file is byte-stable and ``--check`` doubles as a CI drift gate
(exit 1 on mismatch) — the same pattern used by ``generate_rules_md.py`` and
``generate_threat_model.py``.

Usage::

    python scripts/generate_quickstart_cast.py            # write docs/quickstart.cast
    python scripts/generate_quickstart_cast.py --check    # exit 1 if out of sync
    python scripts/generate_quickstart_cast.py --stdout   # print, write nothing
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
CAST_PATH = REPO_ROOT / "docs" / "quickstart.cast"

WIDTH = 88
HEIGHT = 26
PROMPT = "$ "

# Deterministic pacing (seconds). These only drive the playback animation; the
# terminal *content* below is the real tool output.
DELAY_AFTER_PROMPT = 0.6   # pause after a command is "typed", before its output
DELAY_AFTER_OUTPUT = 1.4   # pause to read the output before the next command

# The three quickstart steps. Each ``output`` block is the real (normalized)
# terminal output of the command above it. Keep these in sync with the README
# quickstart and docs/QUICKSTART.md (tests/test_quickstart.py enforces it).
STEPS = [
    (
        "pip install -e .",
        "Successfully installed shellockolm-3.0.0\n"
        "# the `shellockolm` command is now on your PATH\n",
    ),
    (
        "shellockolm scan examples/vulnerable-demo",
        "Target: examples/vulnerable-demo\n"
        "\n"
        "\U0001f6a8 VULNERABILITIES DETECTED\n"
        "\n"
        "┌─ CVE-2025-29927: Next.js Middleware Authorization Bypass\n"
        "│  File: examples/vulnerable-demo/package.json\n"
        "│  Package: next @ 15.2.2\n"
        "│  Fix: 15.2.3\n"
        "│  CVSS: 9.1 | Difficulty: Trivial\n"
        "│  Production code - ACTION REQUIRED\n"
        "└─ Upgrade next to 15.2.3\n"
        "\n"
        "═══ INVESTIGATION SUMMARY ═══\n"
        "  \U0001f4ca Total findings:  1\n"
        "  \U0001f534 Critical:        1\n"
        "  (exit code 1 — findings gate the build)\n",
    ),
    (
        "shellockolm info CVE-2025-29927",
        "\U0001f50d CVE-2025-29927 — Next.js Middleware Authorization Bypass\n"
        "   Severity: CRITICAL (CVSS 9.1)\n"
        "   Packages: next\n"
        "   Fixed in: 12.x→12.3.5, 13.x→13.5.7, 14.x→14.2.25, 15.x→15.2.3\n",
    ),
]


def build_events() -> list:
    """Build the asciinema v2 output-event stream (list of [time, 'o', data])."""
    events = []
    t = 0.0
    for command, output in STEPS:
        # The prompt + the "typed" command, then a newline as if Enter was pressed.
        events.append([round(t, 3), "o", f"{PROMPT}{command}\r\n"])
        t += DELAY_AFTER_PROMPT
        # The command's real output, terminal-newline normalized.
        events.append([round(t, 3), "o", output.replace("\n", "\r\n")])
        t += DELAY_AFTER_OUTPUT
    # A trailing prompt so the recording ends on a clean ready line.
    events.append([round(t, 3), "o", PROMPT])
    return events


def render() -> str:
    """Render the full cast document (header line + one JSON array per event)."""
    header = {
        "version": 2,
        "width": WIDTH,
        "height": HEIGHT,
        # Fixed timestamp keeps the render byte-stable (no wall-clock).
        "timestamp": 0,
        "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
        "title": "Shellockolm — 60-second quickstart",
    }
    lines = [json.dumps(header, ensure_ascii=False, sort_keys=True)]
    for event in build_events():
        lines.append(json.dumps(event, ensure_ascii=False))
    return "\n".join(lines) + "\n"


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit 1 if docs/quickstart.cast is out of sync (CI drift gate)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="print the cast to stdout and write nothing",
    )
    args = parser.parse_args(argv)

    content = render()

    if args.stdout:
        sys.stdout.write(content)
        return 0

    if args.check:
        if not CAST_PATH.exists():
            print(f"[drift] {CAST_PATH} does not exist; run the generator.", file=sys.stderr)
            return 1
        current = CAST_PATH.read_text(encoding="utf-8")
        if current != content:
            print(
                f"[drift] {CAST_PATH} is out of sync with the generator; "
                f"run: python scripts/generate_quickstart_cast.py",
                file=sys.stderr,
            )
            return 1
        print(f"[ok] {CAST_PATH} is in sync.")
        return 0

    CAST_PATH.write_text(content, encoding="utf-8", newline="\n")
    print(f"[ok] wrote {CAST_PATH} ({len(content)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
