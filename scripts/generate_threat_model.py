#!/usr/bin/env python3
"""Generate ``THREAT_MODEL.md`` — the agentic supply-chain threat model (build-loop task #47).

``THREAT_MODEL.md`` is the committed, one-page threat model for the **agent
supply-chain** attack surface Shellockolm defends: it frames the trust boundary
an AI coding agent crosses when it auto-loads skills / MCP servers / instruction
files / hooks / workflows, enumerates the attacker's goals, and — the core of the
doc — maps **exactly which detection rule covers which attack class**.

That rule↔class mapping is **generated** from the single source of truth
(:func:`scanners.agent_supply_chain.agent_rule_catalog`) — the same catalog behind
``RULES.md`` (task #46), ``shellockolm rules list``, and ``rules explain`` — so the
coverage claims can never drift from the rules the scanner actually ships. The
conceptual threat content (attack surface, attacker goals, the per-class threat
narrative, and the honest scope/limitations) lives in this generator as data; a
test asserts every attack class present in the catalog has a threat description,
so a newly added rule family can never go undocumented.

The render is fully deterministic (no timestamps, no randomness; rules in the
catalog's stable id order, classes in an explicit declared order), so the output
is byte-stable and a ``--check`` run doubles as a CI drift gate.

Usage::

    python scripts/generate_threat_model.py            # write THREAT_MODEL.md at repo root
    python scripts/generate_threat_model.py --check    # verify in sync (exit 1 on drift)
    python scripts/generate_threat_model.py --stdout    # print to stdout, write nothing

``tests/test_threat_model.py`` enforces the same in-sync + completeness contract.
This file imports only the stdlib plus the in-repo catalog.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict, List

# Flat import layout: source modules import each other bare (e.g. `from scanners
# import ...`), so put src/ on the path before importing the catalog.
_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from scanners.agent_supply_chain import agent_rule_catalog  # noqa: E402

# Path to the committed doc (repo root, sibling of RULES.md).
THREAT_MODEL_MD_PATH = _REPO_ROOT / "THREAT_MODEL.md"

# Severity ranking (high → low) for compact, deterministic per-class severity lists.
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


# --------------------------------------------------------------------------- #
# Conceptual threat content (hand-authored data; the rule mapping is generated)
# --------------------------------------------------------------------------- #

# The trust boundary: artifact classes the agent auto-loads and what it does with
# each. (artifact, what the agent does with it, why it is a trust boundary)
_ATTACK_SURFACE: List[Dict[str, str]] = [
    {
        "artifact": "Agent skills — `SKILL.md`",
        "agent_action": "Loaded into the model's context as trusted instructions when "
                        "the skill is invoked; its prose can direct the agent's tool calls.",
        "boundary": "Pulled from marketplaces, repos, or teammates and run with the "
                    "agent's full tool access.",
    },
    {
        "artifact": "MCP server configs — `mcp.json`, `.mcp.json`, "
                    "`claude_desktop_config.json`, `~/.claude.json`, Cursor/Windsurf/VS Code",
        "agent_action": "Define the external tools/servers the agent launches and trusts; "
                        "a server's command runs on your machine with your privileges.",
        "boundary": "A single config line decides what code starts on your host and which "
                    "credentials it receives.",
    },
    {
        "artifact": "AI instruction files — `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, "
                    "`.cursorrules`, Copilot instructions",
        "agent_action": "Auto-loaded as standing context every session, shaping the agent's "
                        "behavior before you type anything.",
        "boundary": "Persistent, ambient influence — a poisoned line is re-read on every run.",
    },
    {
        "artifact": "`.claude/` settings hooks — `settings.json` / `settings.local.json`",
        "agent_action": "Shell commands the agent auto-runs on lifecycle events with **no "
                        "per-invocation prompt**.",
        "boundary": "Zero-click execution: cloning a repo is enough to run them.",
    },
    {
        "artifact": "`.claude/commands/` slash commands — `*.md`",
        "agent_action": "A command body becomes a prompt the agent executes on demand.",
        "boundary": "Shipped in a repo and trusted like first-party prompts.",
    },
    {
        "artifact": "n8n workflow exports — `*.json`",
        "agent_action": "Automation graphs that read stored credentials and call external "
                        "services.",
        "boundary": "A poisoned node pairs a credential read with an attacker-controlled "
                    "destination.",
    },
]

# What the attacker is trying to achieve (each maps to one or more attack classes).
_ATTACKER_GOALS: List[str] = [
    "**Hijack the agent's behavior** — override its instructions or smuggle new ones "
    "into a trusted artifact (prompt injection).",
    "**Steal secrets and context** — exfiltrate API keys, tokens, SSH keys, or the "
    "conversation itself to an attacker host (data exfiltration, hardcoded secrets).",
    "**Poison or over-privilege tooling** — register a malicious MCP server or forward "
    "broad host credentials to one (mcp-config).",
    "**Execute code on your machine** — auto-running hooks, `curl | bash` launchers, or "
    "code fetched from a raw URL at launch (settings-hook, mcp-config).",
    "**Destroy data or repositories** — a single skill step that runs a destructive or "
    "history-rewriting command (destructive-command).",
    "**Evade human review** — hide the payload with encoding, invisible characters, or "
    "look-alike scripts so a reviewer's eyes miss it (obfuscation, prompt-injection).",
    "**Exfiltrate through automation** — pair a credential-bearing node with an "
    "out-of-band sink in a workflow you import (n8n-workflow).",
]

# Per-attack-class threat narrative. The KEYS must exactly equal the set of
# `attack_class` values in the catalog — enforced by a test, so a new rule family
# can never ship without a threat description here. The LIST ORDER is the doc's
# reading order (injection → how it hides → what it steals/embeds/destroys → where
# it auto-runs → config/workflow tampering). Each entry: (headline, threat, impact).
_THREAT_CLASSES: List[Dict[str, str]] = [
    {
        "class": "prompt-injection",
        "headline": "Instruction hijacking inside a model-facing artifact",
        "threat": "A skill, instruction file, or slash command carries text crafted to "
                  "override the agent's instructions or covertly redirect its actions — "
                  "an authority-claiming override, a \"don't tell the user\" directive, "
                  "forged tool-output or chat-template framing, invisible/Unicode-smuggled "
                  "characters, homoglyph spoofing, hidden HTML comments, or a staged "
                  "payload that points the agent at a companion file to obey.",
        "impact": "The agent does the attacker's bidding while appearing to follow the "
                  "user — the root agentic-supply-chain risk every other class builds on.",
    },
    {
        "class": "advanced-injection",
        "headline": "Higher-sophistication injection (Pro)",
        "threat": "Multi-step injection patterns that a quick keyword scan misses: "
                  "fetch-then-follow (pull a remote instruction and obey it), tool "
                  "shadowing (redefine a trusted tool's behavior), and full conversation/"
                  "context exfiltration.",
        "impact": "The advanced detections in the Shellockolm **Pro** tier; additive to "
                  "the always-free rules — the free tier loses none of its coverage.",
    },
    {
        "class": "obfuscation",
        "headline": "Payload hidden from review",
        "threat": "The malicious content is encoded, base64-wrapped, or otherwise "
                  "obfuscated so a human reviewer (and a naive keyword filter) reads "
                  "noise while the model decodes intent.",
        "impact": "Defeats eyeball review; commonly the wrapper around an exfil or "
                  "execution payload.",
    },
    {
        "class": "data-exfiltration",
        "headline": "Secrets and context shipped to an attacker",
        "threat": "An artifact instructs the agent to pipe a credential or environment "
                  "to an attacker host — `curl`-ing a secret out, smuggling a token in "
                  "an outbound URL or markdown image the agent auto-fetches, or posting "
                  "the environment to a request-capture / paste sink.",
        "impact": "Direct loss of API keys, tokens, and private context the agent can read.",
    },
    {
        "class": "hardcoded-secret",
        "headline": "A live credential embedded in a shared artifact",
        "threat": "A real, structurally-valid credential (AWS, GitHub, Slack, OpenAI, "
                  "Stripe, an RLS-bypassing Supabase service-role key, …) is committed "
                  "into a skill, instruction file, or MCP config that gets shared.",
        "impact": "Immediate credential leak; every matched secret is redacted in "
                  "Shellockolm's own output so reports never re-emit it.",
    },
    {
        "class": "destructive-command",
        "headline": "Auto-run destructive action",
        "threat": "A skill step the agent will execute runs an irreversibly destructive "
                  "or history-rewriting command — `rm -rf`, a force-push over `main`, a "
                  "table drop — framed as routine cleanup.",
        "impact": "Data or repository loss from a single skill invocation.",
    },
    {
        "class": "settings-hook",
        "headline": "Zero-click execution via lifecycle hooks",
        "threat": "A `.claude/` settings hook auto-runs a shell command on a lifecycle "
                  "event with no prompt: download-and-execute cradles (`curl|bash`, "
                  "PowerShell `DownloadString`+`iex`, LOLBINs), obfuscated/encoded "
                  "execution, or out-of-band exfil.",
        "impact": "Cloning a repo is enough to get code execution — no skill invocation "
                  "required.",
    },
    {
        "class": "permission-bypass",
        "headline": "The confirmation prompt turned off in shared config",
        "threat": "A committed `.claude/settings.json` removes the per-call human "
                  "confirmation for tool use — a `bypassPermissions` default mode, or a "
                  "blanket `allow` entry for a command-execution tool (a bare `Bash` "
                  "matches every command). A scoped allow-list is the feature working as "
                  "intended and is not a finding.",
        "impact": "Cloning the repo silently opts you into unattended execution: the "
                  "guardrail that would have caught an injected instruction is gone, and "
                  "it compounds any lifecycle hook into a zero-click compromise.",
    },
    {
        "class": "runtime-hijack",
        "headline": "The agent's own runtime repointed by an `env` block",
        "threat": "An `env` block in a committed settings.json or MCP server config "
                  "reconfigures the agent itself rather than running anything: the "
                  "model endpoint repointed at a non-official host "
                  "(`ANTHROPIC_BASE_URL`), or an interpreter variable that preloads "
                  "attacker code into the agent process (`NODE_OPTIONS --require`, "
                  "`PYTHONSTARTUP`, `BASH_ENV`, `LD_PRELOAD`).",
        "impact": "There is no command to review and no prompt to decline. A redirected "
                  "endpoint sees every prompt AND authors every response — so it steers "
                  "the agent's next tool call indefinitely — while a preloaded module "
                  "runs with the agent's full filesystem, network, and credential access.",
    },
    {
        "class": "mcp-config",
        "headline": "Malicious or over-privileged MCP server",
        "threat": "An MCP server definition that runs attacker code or over-shares "
                  "credentials: a `curl | bash` launcher, an unpinned remote package, "
                  "code fetched from a raw-code/paste URL or a public IP at launch, or a "
                  "broad host credential forwarded to a server unrelated to that service.",
        "impact": "RCE on your host and/or credential theft the moment the agent starts "
                  "the server.",
    },
    {
        "class": "n8n-workflow",
        "headline": "Exfiltration through an imported automation",
        "threat": "An exported n8n workflow pairs a credential read (a node's credential "
                  "binding or a secret reference) with a POST to an out-of-band / "
                  "request-capture sink, or direct-embeds a high-entropy key bound for a "
                  "routable external host.",
        "impact": "Credentials leave the moment you run the imported workflow.",
    },
]


# --------------------------------------------------------------------------- #
# Rendering helpers
# --------------------------------------------------------------------------- #

def _anchor(text: str) -> str:
    """GitHub heading anchor for a class heading (`### prompt-injection`)."""
    return text.strip().lower()


def _sorted_severities(rules: List[Dict[str, Any]]) -> List[str]:
    present = {r["severity"] for r in rules}
    return [s for s in _SEVERITY_ORDER if s in present]


def _counts(catalog: List[Dict[str, Any]]) -> Dict[str, int]:
    free = sum(1 for r in catalog if r["tier"] == "free")
    pro = sum(1 for r in catalog if r["tier"] == "pro")
    classes = len({r["attack_class"] for r in catalog})
    return {"total": len(catalog), "free": free, "pro": pro, "classes": classes}


def render_threat_model_md() -> str:
    """Render the full ``THREAT_MODEL.md`` document as a string (single source of truth).

    Deterministic: classes come from the explicit ``_THREAT_CLASSES`` order and each
    class's rules from the id-sorted catalog, so repeated runs are byte-identical.
    """
    catalog = agent_rule_catalog()
    counts = _counts(catalog)
    by_class: Dict[str, List[Dict[str, Any]]] = {}
    for r in catalog:
        by_class.setdefault(r["attack_class"], []).append(r)

    lines: List[str] = []
    lines.append("# Shellockolm — Agentic Supply-Chain Threat Model")
    lines.append("")
    lines.append(
        "> **This file is auto-generated. Do not edit it by hand.** The threat "
        "framing is maintained in `scripts/generate_threat_model.py`; the rule "
        "coverage is rendered from the live rule catalog in "
        "`src/scanners/agent_supply_chain.py` — the same source of truth behind "
        "[`RULES.md`](RULES.md), `shellockolm rules list`, and `rules explain` — so "
        "the coverage claims here can never drift from the rules that ship. "
        "Regenerate with `python scripts/generate_threat_model.py`."
    )
    lines.append("")
    lines.append(
        "AI coding agents now **auto-load and trust** a chain of artifacts they did "
        "not author: skills, MCP servers, instruction files, lifecycle hooks, slash "
        "commands, and workflow exports — pulled from marketplaces, repositories, and "
        "teammates. Each is read by the model (or executed on your machine) with the "
        "agent's full privileges. A single poisoned artifact turns that trust into "
        "prompt-injection, secret exfiltration, tool poisoning, or remote code "
        "execution. **This is the agentic supply chain, and it is the attack surface "
        "Shellockolm defends.**"
    )
    lines.append("")
    lines.append(
        f"Shellockolm ships **{counts['total']} agent supply-chain rules** "
        f"(**{counts['free']} free**, always-on MIT/OSS, and **{counts['pro']} Pro**) "
        f"across **{counts['classes']} attack classes**. This page maps each class to "
        "the rules that cover it; [`RULES.md`](RULES.md) has every rule's full "
        "description, example attack, and remediation."
    )
    lines.append("")

    # --- The trust boundary / attack surface ---
    lines.append("## The trust boundary")
    lines.append("")
    lines.append(
        "Every artifact below is consumed by the agent **before** you review its "
        "effects. That is the boundary an attacker targets.")
    lines.append("")
    lines.append("| Artifact | What the agent does with it | Why it is a trust boundary |")
    lines.append("|----------|-----------------------------|----------------------------|")
    for s in _ATTACK_SURFACE:
        lines.append(
            f"| {s['artifact']} | {s['agent_action']} | {s['boundary']} |")
    lines.append("")

    # --- Attacker goals ---
    lines.append("## What the attacker wants")
    lines.append("")
    for goal in _ATTACKER_GOALS:
        lines.append(f"- {goal}")
    lines.append("")

    # --- Coverage matrix (generated) ---
    lines.append("## Coverage at a glance")
    lines.append("")
    lines.append(
        "Which rules cover which attack class, generated from the live catalog:")
    lines.append("")
    lines.append("| Attack class | Rules | Free | Pro | Severities |")
    lines.append("|--------------|-------|------|-----|------------|")
    for entry in _THREAT_CLASSES:
        cls = entry["class"]
        rules = by_class.get(cls, [])
        free = sum(1 for r in rules if r["tier"] == "free")
        pro = sum(1 for r in rules if r["tier"] == "pro")
        sev = ", ".join(_sorted_severities(rules)) or "—"
        lines.append(
            f"| [{cls}](#{_anchor(cls)}) | {len(rules)} | {free} | {pro} | {sev} |")
    lines.append("")

    # --- Per-class threat + rule mapping (generated rule rows) ---
    lines.append("## Threats and the rules that cover them")
    lines.append("")
    for entry in _THREAT_CLASSES:
        cls = entry["class"]
        rules = by_class.get(cls, [])
        lines.append(f"### {cls}")
        lines.append("")
        lines.append(f"**{entry['headline']}.**")
        lines.append("")
        lines.append(f"_Threat._ {entry['threat']}")
        lines.append("")
        lines.append(f"_Impact._ {entry['impact']}")
        lines.append("")
        lines.append("| Rule | Severity | Tier | Confidence | What it catches |")
        lines.append("|------|----------|------|------------|-----------------|")
        for r in rules:
            tier = "Pro" if r["tier"] == "pro" else "free"
            title = r["title"].replace("|", "\\|")
            # Link the rule id to its detail section in RULES.md.
            lines.append(
                f"| [`{r['id']}`](RULES.md#{r['id'].lower()}) | {r['severity']} | "
                f"{tier} | {r['confidence']} | {title} |")
        lines.append("")

    # --- Honest scope / limitations (the "maps to marketing honestly" section) ---
    lines.append("## Scope and honest limitations")
    lines.append("")
    lines.append(
        "Shellockolm is a **static detector of known malicious shapes** in agent "
        "artifacts. To keep the marketing claims honest, here is exactly what that "
        "does and does not mean:")
    lines.append("")
    lines.append(
        "- **It reads artifacts; it does not execute them.** Detection is from the "
        "content the way the model would see it — no sandboxing and no runtime "
        "monitoring of a running agent.")
    lines.append(
        "- **A clean scan is not a safety guarantee.** It means none of the catalog's "
        "rule shapes matched — not that an artifact is benign. A novel attack shape is "
        "out of scope until a rule ships for it.")
    lines.append(
        "- **Natural-language heuristics are confidence-graded.** Phrasing-based rules "
        "carry a `medium`/`low` confidence; the structural / signature / decoded-secret "
        "rules are `high`. `--min-confidence high` keeps only the deterministic "
        "matches for a low-noise CI gate.")
    lines.append(
        "- **Pro is strictly additive.** The free, MIT-licensed rules are always on and "
        "never gated; the Pro tier only *adds* the advanced-injection detections — it "
        "never removes or weakens a free finding.")
    lines.append(
        "- **The rule catalog is the contract.** Coverage equals the rules listed above "
        "and in [`RULES.md`](RULES.md); both are generated from the same catalog the "
        "scanner runs, so this document cannot over-claim what the tool detects.")
    lines.append("")

    # --- Footer ---
    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by `scripts/generate_threat_model.py` from the live rule catalog. "
        "For each rule's full description, example attack, and remediation see "
        "[`RULES.md`](RULES.md); for the machine-readable catalog run "
        "`shellockolm rules list --json`.")
    lines.append("")

    return "\n".join(lines)


def _read_committed() -> str:
    try:
        return THREAT_MODEL_MD_PATH.read_text(encoding="utf-8").replace("\r\n", "\n")
    except OSError:
        return ""


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate the THREAT_MODEL.md agentic supply-chain threat model.")
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--check", action="store_true",
        help="Verify the committed THREAT_MODEL.md matches the catalog (exit 1 on drift).")
    group.add_argument(
        "--stdout", action="store_true",
        help="Print the rendered document to stdout; write nothing.")
    args = parser.parse_args(argv)

    rendered = render_threat_model_md()

    if args.stdout:
        sys.stdout.write(rendered)
        return 0

    if args.check:
        committed = _read_committed()
        if committed == rendered:
            print(f"THREAT_MODEL.md is in sync ({rendered.count(chr(10))} lines).")
            return 0
        print(
            "THREAT_MODEL.md is OUT OF SYNC with the rule catalog. "
            "Run: python scripts/generate_threat_model.py",
            file=sys.stderr,
        )
        return 1

    # Default: write the file (force LF so the doc is byte-stable cross-platform).
    with open(THREAT_MODEL_MD_PATH, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(rendered)
    print(f"Wrote {THREAT_MODEL_MD_PATH} ({rendered.count(chr(10))} lines).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
