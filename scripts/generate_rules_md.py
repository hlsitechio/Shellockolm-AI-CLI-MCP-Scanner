#!/usr/bin/env python3
"""Generate ``RULES.md`` — the agent supply-chain rule reference (build-loop task #46).

``RULES.md`` is the committed, human-readable catalog of every ``AGENT-*`` detection
rule the scanner can emit. It is **generated** from the single source of truth
(:func:`scanners.agent_supply_chain.agent_rule_catalog` +
:func:`agent_rule_example`) — the exact same data behind ``shellockolm rules list``
and ``rules explain`` — so the doc can never drift from the code.

The render is fully deterministic (no timestamps, no randomness; rules are emitted
in the catalog's stable id order), so the output is byte-stable and a ``--check``
run can act as a CI drift gate.

Usage::

    python scripts/generate_rules_md.py            # write RULES.md at the repo root
    python scripts/generate_rules_md.py --check    # verify the committed file is in
                                                   #   sync (exit 1 on drift; CI guard)
    python scripts/generate_rules_md.py --stdout   # print to stdout, write nothing

``tests/test_rules_md.py`` enforces the same in-sync contract in the test suite.
This file imports only the stdlib plus the in-repo catalog.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

# Flat import layout: the source modules import each other bare (e.g.
# `from scanners import ...`), so put src/ on the path before importing.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from scanners.agent_supply_chain import (  # noqa: E402  (after sys.path tweak)
    agent_rule_catalog,
    agent_rule_example,
)

# Path to the committed reference doc (repo root).
RULES_MD_PATH = _REPO_ROOT / "RULES.md"

# Confidence axis legend (mirrors the `confidence` field on every rule).
_CONFIDENCE_LEGEND = [
    ("high", "Structural / signature / decoded-secret match — a deterministic true "
             "positive. These are the rules behind the `--min-confidence high` CI gate."),
    ("medium", "A natural-language phrasing heuristic that matches the real attack "
               "shape but can also fire on benign prose."),
    ("low", "The broadest conditional heuristic (\"when the user does X…\"); useful "
            "for triage, noisiest for gating."),
]


def _anchor(rule_id: str) -> str:
    """GitHub heading anchor for a rule-id-only heading (`#### AGENT-PI-013`)."""
    return rule_id.strip().lower()


def _fence_for(text: str) -> str:
    """Smallest backtick fence (>=3) that does not collide with the content."""
    fence = "```"
    while fence in text:
        fence += "`"
    return fence


def _example_block(example: str) -> List[str]:
    """Render a rule's example-attack string as a fenced code block."""
    body = example.rstrip("\n")
    fence = _fence_for(body)
    return [f"{fence}text", body, fence]


def _summary_counts(catalog: List[Dict[str, Any]]) -> Dict[str, int]:
    free = sum(1 for r in catalog if r["tier"] == "free")
    pro = sum(1 for r in catalog if r["tier"] == "pro")
    return {"total": len(catalog), "free": free, "pro": pro}


def render_rules_md() -> str:
    """Render the full ``RULES.md`` document as a string (the single source of truth).

    Deterministic: rules come from the id-sorted catalog and attack-class groups are
    emitted in alphabetical order, so repeated runs are byte-identical.
    """
    catalog = agent_rule_catalog()
    counts = _summary_counts(catalog)

    lines: List[str] = []
    lines.append("# Shellockolm — Agent Supply-Chain Rule Reference")
    lines.append("")
    lines.append(
        "> **This file is auto-generated. Do not edit it by hand.** It is rendered "
        "from the rule catalog in `src/scanners/agent_supply_chain.py` by "
        "`scripts/generate_rules_md.py` — the same source of truth behind "
        "`shellockolm rules list` and `rules explain`. Regenerate with "
        "`python scripts/generate_rules_md.py`."
    )
    lines.append("")
    lines.append(
        "These are the **agent supply-chain** detection rules Shellockolm applies to "
        "AI-agent coding artifacts — Claude/agent **skills** (`SKILL.md`), **MCP "
        "configs** (`mcp.json`, `.mcp.json`, `claude_desktop_config.json`), **n8n** "
        "workflow exports, AI **instruction files** (`CLAUDE.md` / `AGENTS.md` / "
        "`.cursorrules` / Copilot instructions), `.claude/` **settings hooks**, and "
        "`.claude/commands/` **slash commands**. They detect prompt injection, secret "
        "exfiltration, tool poisoning, auto-running hook RCE, and other agentic-era "
        "supply-chain attacks."
    )
    lines.append("")
    lines.append(
        f"**{counts['total']} rules** — **{counts['free']} free** (always on, MIT/OSS) "
        f"and **{counts['pro']} Pro** (run only with an active Shellockolm Pro "
        "license; listed here for reference)."
    )
    lines.append("")

    # Confidence legend.
    lines.append("**Confidence axis** (independent of severity):")
    lines.append("")
    for level, desc in _CONFIDENCE_LEGEND:
        lines.append(f"- **{level}** — {desc}")
    lines.append("")

    # Index table (all rules, catalog/id order).
    lines.append("## Index")
    lines.append("")
    lines.append("| Rule | Severity | Tier | Confidence | Attack class | What it catches |")
    lines.append("|------|----------|------|------------|--------------|-----------------|")
    for r in catalog:
        tier = "Pro" if r["tier"] == "pro" else "free"
        title = r["title"].replace("|", "\\|")
        lines.append(
            f"| [`{r['id']}`](#{_anchor(r['id'])}) | {r['severity']} | {tier} | "
            f"{r['confidence']} | {r['attack_class']} | {title} |"
        )
    lines.append("")

    # Detailed sections grouped by attack class (classes alphabetical; rules keep
    # the catalog's id order within each class).
    lines.append("## Rules by attack class")
    lines.append("")
    classes = sorted({r["attack_class"] for r in catalog})
    for cls in classes:
        cls_rules = [r for r in catalog if r["attack_class"] == cls]
        lines.append(f"### {cls}")
        lines.append("")
        for r in cls_rules:
            tier = "Pro" if r["tier"] == "pro" else "free"
            lines.append(f"#### {r['id']}")
            lines.append("")
            lines.append(f"**{r['title']}**")
            lines.append("")
            lines.append(
                f"- **Severity:** {r['severity']} &nbsp;·&nbsp; "
                f"**Tier:** {tier} &nbsp;·&nbsp; "
                f"**Confidence:** {r['confidence']} &nbsp;·&nbsp; "
                f"**CVSS:** {r['cvss']} &nbsp;·&nbsp; "
                f"**Attack class:** {r['attack_class']}"
            )
            lines.append("")
            lines.append(r["description"])
            lines.append("")
            example = agent_rule_example(r["id"])
            if example.strip():
                lines.append("**Example attack**")
                lines.append("")
                lines.extend(_example_block(example))
                lines.append("")
            lines.append(f"**Remediation:** {r['remediation']}")
            lines.append("")

    # Footer pointer back to the live CLI.
    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by `scripts/generate_rules_md.py` from the live rule catalog. "
        "For the machine-readable form, run `shellockolm rules list --json`; for a "
        "single rule's full explainer, `shellockolm rules explain <RULE-ID>`."
    )
    lines.append("")

    return "\n".join(lines)


def _read_committed() -> str:
    try:
        return RULES_MD_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")
    except OSError:
        return ""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the RULES.md rule reference.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check", action="store_true",
        help="Verify the committed RULES.md matches the catalog (exit 1 on drift).")
    group.add_argument(
        "--stdout", action="store_true",
        help="Print the rendered document to stdout; write nothing.")
    args = parser.parse_args(argv)

    rendered = render_rules_md()

    if args.stdout:
        sys.stdout.write(rendered)
        return 0

    if args.check:
        committed = _read_committed()
        if committed == rendered:
            print(f"RULES.md is in sync ({rendered.count(chr(10))} lines).")
            return 0
        print(
            "RULES.md is OUT OF SYNC with the rule catalog. "
            "Run: python scripts/generate_rules_md.py",
            file=sys.stderr,
        )
        return 1

    # Default: write the file (force LF so the doc is byte-stable cross-platform).
    with open(RULES_MD_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(rendered)
    print(f"Wrote {RULES_MD_PATH} ({rendered.count(chr(10))} lines).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
