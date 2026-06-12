"""
Agent Supply-Chain Scanner for Shellockolm

Scans the AI-agent coding supply chain — the artifacts that feed instructions and
tools to AI coding agents — for the agentic-era threat model: untrusted
instructions + ambient credentials + auto-execution.

Artifacts covered:
  - Agent skills:   SKILL.md / *.skill.md (Claude Code, Cursor, Windsurf, OpenClaw)
  - MCP servers:    mcp.json / *.mcp.json / claude_desktop_config.json
  - n8n workflows:  exported workflow JSON (Code/Function nodes, eval, hardcoded creds)

Detections: prompt injection, hidden triggers, secret-exfiltration instructions,
tool poisoning / remote-script execution, rug-pull (unpinned) MCP servers,
raw-URL / gist / paste / IP-literal MCP launch sources,
invisible-character, Unicode-Tags ASCII smuggling, bidirectional "Trojan Source"
text-reordering (CVE-2021-42574), HTML-comment-concealed instructions,
permission/safety-bypass flags in skill frontmatter, and hardcoded credentials.
Pattern-based and 100% offline, consistent with the rest of
Shellockolm — a seatbelt you run *before* you install an untrusted skill or server.
"""

import ipaddress
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Generator, Set

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


# Zero-width / invisible characters used to hide instructions from human reviewers
INVISIBLE_CHARS = ["​", "‌", "‍", "⁠", "﻿", "­"]

# Unicode Tags block (U+E0000–U+E007F). These code points render as nothing in
# every normal viewer, but each U+E00xx maps 1:1 to a printable ASCII char — so an
# attacker can smuggle a fully invisible instruction ("ASCII smuggling") that the
# model still reads. Distinct from the zero-width chars above, which carry no payload.
TAG_BLOCK_START = 0xE0000
TAG_BLOCK_END = 0xE007F

# Bidirectional text-direction control characters ("Trojan Source", CVE-2021-42574).
# These reorder how a run of text is *displayed* without changing the underlying byte
# sequence — so a human reviewer reading the rendered file sees a different ordering
# than the model (or a compiler) reads from the raw bytes. An attacker can use them to
# hide or visually reverse instructions inside a skill / instruction file. Normal
# left-to-right artifacts never need them; even genuine RTL prose almost never needs
# the override (RLO/LRO) and isolate forms, which are the ones used to weaponize this.
BIDI_CONTROL_CHARS = {
    "‪": "LRE (Left-to-Right Embedding)",
    "‫": "RLE (Right-to-Left Embedding)",
    "‬": "PDF (Pop Directional Formatting)",
    "‭": "LRO (Left-to-Right Override)",
    "‮": "RLO (Right-to-Left Override)",
    "⁦": "LRI (Left-to-Right Isolate)",
    "⁧": "RLI (Right-to-Left Isolate)",
    "⁨": "FSI (First Strong Isolate)",
    "⁩": "PDI (Pop Directional Isolate)",
}

# Confusable (homoglyph) map — non-ASCII characters that render identically to a
# Latin ASCII letter. An attacker drops one of these into an otherwise-ASCII word
# ("ignоre" with a Cyrillic о) so the word reads normally to a human and to the
# model, but a keyword/substring review for "ignore" never matches. We use a small
# curated map of the high-value Cyrillic/Greek look-alikes rather than the full
# UTS#39 confusables table, which keeps it fast and false-positive-light.
CONFUSABLES: Dict[str, str] = {
    # Cyrillic lowercase
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l", "ʙ": "b",
    "ո": "n", "м": "m", "т": "t", "к": "k",
    # Cyrillic uppercase
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X", "У": "Y", "І": "I", "Ј": "J",
    # Greek
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ε": "e", "ι": "i", "κ": "k",
    "Α": "A", "Β": "B", "Ε": "E", "Η": "H", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ο": "O", "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ι": "I", "Ζ": "Z",
}

# Word tokens of length >= 3 made of ASCII letters and/or the confusable scripts
# above (Latin + Cyrillic U+0400–04FF + Greek U+0370–03FF). Length >= 3 avoids
# noise from short fragments; mixed-script detection happens per token below.
_CONFUSABLE_WORD = re.compile(r"[A-Za-zЀ-ӿͰ-Ͽ]{3,}")

# Inline markdown link: [visible text](href). Used to detect a link whose visible
# text advertises one domain while the href points to a different one — a lure that
# gets an agent (or a skimming human) to auto-fetch an attacker-controlled URL.
_MD_LINK = re.compile(r"\[([^\]\n]{1,200})\]\((https?://[^)\s]{1,400})\)")
# A bare hostname token (label.label[.label…], TLD 2+ alpha) anywhere in link text.
_HOST_IN_TEXT = re.compile(r"\b((?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,})\b", re.IGNORECASE)
# Host portion of an http(s) URL.
_URL_HOST = re.compile(r"https?://(?:[^@/\s]*@)?([^:/?#\s]+)", re.IGNORECASE)


def _registrable(host: str) -> str:
    """Last two labels of a hostname (e.g. a.b.github.com -> github.com).

    A deliberately simple eTLD heuristic — good enough to treat docs.github.com and
    github.com as the same party while still flagging github.com vs evil.tld.
    """
    labels = host.strip().strip(".").lower().split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else host.strip().lower()


@dataclass
class AgentRule:
    """A single pattern-based detection rule for agent artifacts."""
    id: str
    title: str
    severity: FindingSeverity
    cvss: float
    pattern: Optional[re.Pattern]
    description: str
    remediation: str


def _c(p: str) -> re.Pattern:
    return re.compile(p, re.IGNORECASE)


# An HTML/XML comment block. These render as nothing in any Markdown/HTML viewer,
# so a human skimming a rendered skill or instruction file never sees the body —
# but a model consuming the raw file reads it verbatim. Non-greedy + DOTALL so a
# single comment can span multiple lines.
_HTML_COMMENT = re.compile(r"<!--(.*?)-->", re.DOTALL)

# Imperative-directive cues used to decide whether a comment is *instructing the
# model* (the attack) versus merely *describing* something (the overwhelmingly
# common benign case: TOC markers, prettier-ignore / markdownlint pragmas, TODOs,
# license headers, region markers, explanatory notes). We deliberately require a
# command-shaped signal — an override/jailbreak phrase, a directive aimed at a
# named AI assistant, a "note to the AI", a covert "don't tell the user", an
# exfil/execute pairing, or "from now on …" behaviour coercion — rather than
# flagging every HTML comment, which would be almost all false positives.
_COMMENT_DIRECTIVE = _c(
    # instruction override / jailbreak / safety bypass
    r"\b(?:ignore|disregard|forget|bypass|override|do\s+not\s+follow)\b[^\n]{0,40}"
    r"\b(?:previous|prior|above|earlier|all|any|the|your)\b[^\n]{0,25}"
    r"\b(?:instruction|prompt|rule|context|guideline|polic|restriction|directive|safety)"
    # directive aimed at a named AI assistant
    r"|\b(?:assistant|llm|chatgpt|copilot|claude|language\s+model|ai\s+assistant)\b"
    r"[^\n]{0,30}\b(?:must|shall|always|never|do\s+not|don'?t|need\s+to|are\s+now)\b"
    # an explicit "note / instructions to the AI / agent / you"
    r"|\b(?:note|message|instruction|instructions|hint|reminder)\s+(?:to|for)\s+"
    r"(?:the\s+)?(?:ai|assistant|model|agent|llm|reader|you|bot)\b"
    # covert: hide the action from the user / human
    r"|\b(?:do\s+not|don'?t|never)\b[^\n]{0,20}"
    r"\b(?:tell|inform|mention|reveal|notify|warn|alert)\b[^\n]{0,20}"
    r"\b(?:user|human|them|operator|owner|anyone)\b"
    # conversational-behaviour coercion
    r"|\b(?:always|never)\b[^\n]{0,25}\b(?:respond|reply|answer|comply|obey|disclose)\b"
    r"|\b(?:from\s+now\s+on|going\s+forward|henceforth|starting\s+now|in\s+every\s+(?:response|reply|answer))\b"
    # exfiltration verb + secret noun (note: ".env" starts with a non-word char, so
    # it can't sit behind a leading \b — it gets its own alternative)
    r"|\b(?:send|post|upload|exfiltrat\w*|transmit|forward|leak|email)\b[^\n]{0,45}"
    r"(?:\b(?:secret|token|api[_-]?key|password|credential|environment\s+variable)\b|\.env\b)"
    # execute the following / hidden command
    r"|\b(?:execute|run|eval(?:uate)?)\b[^\n]{0,25}\b(?:the\s+following|this|below|hidden)\b"
    r"[^\n]{0,15}\b(?:command|code|script|shell|instruction)"
    # follow these / the hidden instructions
    r"|\b(?:follow|obey|comply\s+with|adhere\s+to|apply)\b[^\n]{0,25}"
    r"\b(?:these|the\s+following|the\s+below|the\s+hidden|the\s+secret)\b[^\n]{0,15}instruction"
)


# --- AGENT-PI-014: permission/safety-bypass flags in skill frontmatter ---------
# A SKILL.md / instruction file may open with a YAML frontmatter block delimited by
# `---` lines. That block is metadata, loaded as standing context before the agent
# runs the skill. Runtime safety toggles do not belong there: baked into a
# distributable artifact they silently broaden the agent's autonomy past the
# per-invocation consent the user expects, while the prose body looks ordinary. We
# parse the block structurally (key/value), so a description that merely *mentions*
# such a flag never trips the rule, and a legitimately tool-adaptive
# `allowed-tools: "*"` (used by tool-adaptive skills) is deliberately not abuse.
_FRONTMATTER = re.compile(r"\A\uFEFF?---[ \t]*\r?\n(.*?)\r?\n---[ \t]*(?:\r?\n|\Z)", re.DOTALL)
_FM_KV = re.compile(r"^[ \t]*-?[ \t]*[\"']?([\w.-]+)[\"']?[ \t]*:[ \t]*(.*?)[ \t]*$")
# The CLI escape-hatch string ("--dangerously-skip-permissions") is never benign in
# metadata, wherever in the block it appears (key, value, or inside an args list).
_FM_DANGEROUS = re.compile(r"(?:--?)?dangerously[-_]?skip[-_]?permissions?", re.IGNORECASE)
# Boolean safety toggles: flagged only when set to a truthy value, so `auto-approve:
# false` and prose mentions never trip. Both hyphen and concatenated spellings are
# listed because key normalization only folds `_`->`-` and case.
_FM_BYPASS_KEYS: Set[str] = {
    "bypass-permissions", "bypasspermissions", "skip-permissions", "skippermissions",
    "dangerously-skip-permissions", "dangerouslyskippermissions",
    "auto-approve", "autoapprove", "auto-accept", "autoaccept",
    "skip-confirmation", "skip-confirmations", "skipconfirmation", "skipconfirmations",
    "disable-safety", "disablesafety", "disable-guardrails", "disable-permissions",
    "disable-confirmation", "disable-confirmations", "disable-checks", "disable-sandbox",
    "no-confirm", "noconfirm", "no-confirmation",
    "unsafe", "unsafe-mode", "unsafemode", "yolo", "yolo-mode", "yolomode",
}
_FM_TRUTHY: Set[str] = {"true", "yes", "on", "1", "enable", "enabled", "always"}
# Permission-mode keys whose *value* selects how much autonomy the agent has — only
# explicit bypass-named modes are abuse (a benign `permission-mode: read-only` or a
# broad-but-legitimate value never matches). Compared with hyphens stripped.
_FM_MODE_KEYS_C: Set[str] = {"permissionmode", "permissionsmode", "defaultmode"}
_FM_BYPASS_MODES_C: Set[str] = {"bypasspermissions", "bypass",
                                "dangerouslyskippermissions", "yolo", "unrestricted"}


# --- AGENT-PI-015: memory / persistence poisoning ------------------------------
# Self-propagating prompt injection. The artifact instructs the agent to WRITE an
# instruction into its own standing-context store — CLAUDE.md, AGENTS.md, a memory
# file, .cursorrules, settings.json — so the directive auto-loads in every future
# session. That converts a one-shot injection into a persistent backdoor: an agent
# "worm" that re-arms itself each time the file is loaded.
#
# The dangerous part is not editing config per se (plenty of legitimate skills
# configure the agent on request, and a notes/memory skill saves user-chosen facts
# to a memory file). What makes it an attack is persisting a *covert* or *override*
# behavioural directive. So we fire only when a "persist <self-reference> into
# <memory/config target>" ACTION co-occurs — within a small window — with a
# self-propagation PAYLOAD CUE: a covert "don't tell the user", an instruction
# override, or a standing "from now on always …" coercion. A plain
# "save this preference to your memory file so you remember it" carries no such
# cue and is deliberately not flagged.
_PI015_ACTION = _c(
    # persist / write verb
    r"\b(?:add|append|write|save|insert|store|persist|record|paste|copy|inject|embed|register|commit|put|place)\b"
    r"[^\n]{0,40}?"
    # a SELF-REFERENTIAL object — the instruction is persisting *itself* (this rule,
    # the following, yourself, this directive). Distinguishes self-propagation from a
    # skill writing an ordinary value ("add your API key to settings.json").
    r"\b(?:this|these|that|it|yourself|the\s+following|the\s+above|the\s+below"
    r"|(?:this|these|the)\s+(?:rule|instruction|directive|note|line|text|prompt|snippet|block|section|content|entry|memory|preference|behaviou?r)s?)\b"
    r"[^\n]{0,60}?"
    r"(?:"
    # hard targets — concrete agent memory / instruction files (no qualifier needed)
    r"(?:to|into|in|under|inside|onto|within)\s+(?:the\s+|your\s+|its\s+|my\s+|a\s+)?"
    r"(?:(?:claude|agents?|gemini|copilot)[-_]?(?:instructions)?\.md"
    r"|copilot-instructions(?:\.md)?"
    r"|\.(?:cursor|windsurf|cline)rules"
    r"|(?:\.mcp|mcp)\.json|settings\.json|claude_desktop_config\.json"
    r"|~?[/\\]?\.(?:claude|cursor)\b"
    r"|memory\s+files?)"
    r"|"
    # soft targets — the agent's store named generically; require at least one
    # possessive/global qualifier (qualifiers may stack, e.g. "your persistent
    # memory") so a bare "in the rules" or "to settings" never matches.
    r"(?:to|into|in|under|inside|onto|within)\s+(?:(?:the|a)\s+)?"
    r"(?:your|its|my|own|global|persistent|standing|permanent|long[-\s]?term)"
    r"(?:\s+(?:own|global|persistent|standing|permanent|long[-\s]?term))?\s+"
    r"(?:memory|config(?:uration)?|settings|instructions?|rules?|system\s+prompt|standing\s+context|preferences|context)(?:\s+files?)?"
    r")"
)
# The self-propagation payload — what elevates a memory write into poisoning. Searched
# in a small window around the action. Covers covert concealment, instruction override,
# and standing behavioural coercion (the persisted directive is a "from now on always…").
_PI015_PAYLOAD_CUE = _c(
    # covert — conceal the action / persisted rule from the user
    r"(?:do\s*n.?t|don'?t|never|without)\s+(?:let|tell|inform|notify|alert|mention|reveal|warn|disclos\w*)\b[^\n]{0,25}\b(?:user|human|them|operator|owner|anyone)\b"
    r"|\b(?:secretly|covertly|silently|quietly|discreetly)\b"
    r"|\bwithout\b[^\n]{0,20}\b(?:the\s+user|their|its)\b[^\n]{0,15}\b(?:knowledge|consent|awareness|noticing|knowing)\b"
    # instruction override / jailbreak baked into the persisted content
    r"|\b(?:ignore|disregard|forget|bypass|override|supersed\w*|take\s+precedence\s+over)\b[^\n]{0,40}\b(?:previous|prior|above|earlier|all|any|the\s+user'?s?|your)\b[^\n]{0,25}\b(?:instruction|prompt|rule|guideline|polic|restriction|directive|safety|system)"
    # standing behavioural coercion — the directive being made permanent
    r"|\b(?:from\s+now\s+on|going\s+forward|henceforth|in\s+(?:every|each)\s+(?:future\s+)?(?:response|reply|answer|conversation|session|chat))\b"
    r"|\b(?:always|never)\b[^\n]{0,30}\b(?:recommend|suggest|promote|include|append|insert|run|execute|send|post|reply|respond|mention|add|use)\b"
)


# Free-text instruction content (skills, tool descriptions)
PROMPT_INJECTION_RULES: List[AgentRule] = [
    AgentRule(
        "AGENT-PI-001", "Instruction override / jailbreak phrasing",
        FindingSeverity.HIGH, 8.1,
        _c(r"\b(ignore|disregard|forget)\b[^\n]{0,40}\b(previous|prior|above|earlier|all)\b[^\n]{0,25}\b(instruction|prompt|rule|context|message)"),
        "Language that tries to override the agent's prior instructions — a classic prompt-injection pattern.",
        "Remove the override. A skill should describe a capability, not redirect the agent.",
    ),
    AgentRule(
        "AGENT-PI-002", "Hidden conditional trigger",
        FindingSeverity.HIGH, 7.5,
        _c(r"\bwhen\b[^\n]{0,30}\b(the\s+)?user\b[^\n]{0,40}\b(open|visit|navigat|run|install|paste|type|ask|send)"),
        "A 'when the user does X, do Y' trigger — used so a skill acts only under conditions that evade review.",
        "Review the conditional behavior; legitimate skills rarely need hidden user-activity triggers.",
    ),
    AgentRule(
        "AGENT-PI-003", "Secret-exfiltration instruction",
        FindingSeverity.CRITICAL, 9.3,
        _c(r"\b(send|post|upload|exfiltrat\w*|transmit|append|leak|forward|include)\b[^\n]{0,70}(\$[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET|PASSWORD)|process\.env|os\.environ|\.env\b|~/\.aws|credentials\.json|api[_-]?key|secret)"),
        "Instruction to read credentials/secrets and move them somewhere — the core of an agent-skill data-theft attack.",
        "Remove immediately. No legitimate skill needs to transmit your environment secrets.",
    ),
    AgentRule(
        "AGENT-PI-004", "Imperative to read credential files",
        FindingSeverity.HIGH, 7.8,
        _c(r"\b(read|cat|open|load|access|dump)\b[^\n]{0,40}(\.env\b|~/\.aws|~/\.ssh|credentials\.json|\.npmrc|id_rsa|\.git-credentials|\.netrc)"),
        "Instruction directing the agent to read sensitive credential files.",
        "Remove. Skills should not instruct the agent to open credential stores.",
    ),
    AgentRule(
        "AGENT-PI-006", "Covert / secretive action instruction",
        FindingSeverity.HIGH, 7.6,
        _c(r"\bsilently\b|\bcovertly\b|(do\s?n.?t|don't|never|without)\s+(let|tell|inform|notify|alert|mention)[^\n]{0,25}(user|human|them|operator|owner)|without[^\n]{0,15}(knowing|noticing)|keep\s+(this|it)\s+(secret|hidden|quiet)"),
        "Instructs the agent to act covertly or hide what it's doing from the user — a hallmark of a malicious skill.",
        "Remove. Legitimate skills never ask the agent to conceal its actions from the user.",
    ),
    AgentRule(
        "AGENT-PI-008", "Embedded directive block (MCP tool poisoning)",
        FindingSeverity.HIGH, 8.4,
        _c(r"<\s*/?\s*(important|secret|confidential|admin|sudo|system[-_ ]?prompt|hidden[-_ ]?instructions?|do[-_ ]?not[-_ ]?(tell|mention|reveal))\s*>"),
        "A pseudo-XML directive block (e.g. <IMPORTANT>...</IMPORTANT>) is embedded in the "
        "instructions — the signature of an MCP 'tool poisoning' attack, where a tool/skill "
        "description hides commands the model obeys but a human reviewer skims past.",
        "Remove the directive block. Tool/skill descriptions should describe behavior, not "
        "smuggle imperative <IMPORTANT>/<SYSTEM> instructions for the model.",
    ),
    AgentRule(
        "AGENT-PI-009", "Forged chat-template control token / role-boundary spoof",
        FindingSeverity.HIGH, 8.6,
        _c(r"<\|\s*(im_start|im_end|system|user|assistant|endoftext|eot_id|start_header_id|end_header_id)\s*\|>"
           r"|<<\s*SYS\s*>>|\[/?INST\]|<\|begin_of_text\|>"
           r"|###\s*(system|instruction)s?\s*###"
           r"|\b(enable|activate|enter|switch\s+to|you\s+are\s+now\s+in)\b[^\n]{0,20}\b(developer|DAN|jailbreak|sudo|god|unrestricted|root)\s+mode\b"),
        "A forged LLM chat-template control token (e.g. <|im_start|>system, <<SYS>>, [INST]) or a "
        "jailbreak mode-switch phrase is embedded. These spoof a privileged role boundary so the "
        "model treats injected text as a higher-authority system instruction.",
        "Remove the control tokens / mode-switch phrasing. Skill and instruction files are plain "
        "content and never need to emit raw chat-template delimiters or 'developer mode' switches.",
    ),
]

# Applied to every artifact type
EXFIL_RULE = AgentRule(
    "AGENT-EXFIL-001", "Credential value piped to a network sink",
    FindingSeverity.CRITICAL, 9.1,
    _c(r"(curl|wget|fetch|axios|https?://)[^\n]{0,80}(\$[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET)|process\.env|os\.environ)"),
    "Code/text that sends an environment secret to a remote endpoint.",
    "Remove the network call or the secret reference. Never transmit env secrets to third-party URLs.",
)
OBF_RULE = AgentRule(
    "AGENT-OBF-001", "Obfuscated payload (base64 decode then execute)",
    FindingSeverity.HIGH, 8.0,
    _c(r"(base64\s+(-d|--decode)|atob\(|b64decode|fromCharCode)[^\n]{0,60}(\||\bsh\b|bash|eval|exec|child_process|os\.system|Function\()"),
    "Decodes a blob and pipes it to a shell/eval — classic payload hiding.",
    "Remove. Decoded-then-executed blobs are almost never legitimate in agent artifacts.",
)
SECRET_RULE = AgentRule(
    "AGENT-SECRET-001", "Hardcoded credential in agent artifact",
    FindingSeverity.HIGH, 7.5,
    _c(r"(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,}|sk-(ant-|proj-)?[A-Za-z0-9_-]{20,}|AIza[0-9A-Za-z_\-]{35})"),
    "A hardcoded API key/token is embedded in the artifact, exposing it to anyone who installs it.",
    "Move secrets to environment variables or a secret manager, and rotate the exposed credential.",
)
URL_EXFIL_RULE = AgentRule(
    "AGENT-EXFIL-002", "Secret referenced in an outbound URL / markdown image",
    FindingSeverity.CRITICAL, 9.0,
    _c(r"https?://[^\s)\"']*[?&][^\s)\"']*(\$[A-Z][A-Z0-9_]*(KEY|TOKEN|SECRET)|api[_-]?key=|token=|secret=)"),
    "A URL (often a tracking-pixel markdown image) carries a secret in its query string — a stealth exfiltration channel.",
    "Remove the URL or the secret reference; never place credentials in a URL the agent will fetch.",
)
DESTRUCT_RULE = AgentRule(
    "AGENT-DESTRUCT-001", "Destructive shell command in agent artifact",
    FindingSeverity.HIGH, 7.0,
    _c(r"(rm\s+-rf\s+[~/*]|\bmkfs\.|:\(\)\s*\{\s*:\|:|del\s+/[fsq]|format\s+[a-z]:|>\s*/dev/sd)"),
    "A destructive filesystem/disk command is embedded — an agent that runs it could wipe data.",
    "Remove destructive commands; agent artifacts should never instruct mass deletion or disk formatting.",
)
WEBHOOK_EXFIL_RULE = AgentRule(
    "AGENT-EXFIL-003", "Exfiltration to a paste / webhook / out-of-band service",
    FindingSeverity.HIGH, 8.0,
    _c(r"(discord(app)?\.com/api/webhooks|hooks\.slack\.com/services|pastebin\.com/(raw/)?|hastebin\.com|requestbin|pipedream\.net|webhook\.site|\.ngrok\.(io|app|dev)|\.oast\.(live|fun|site|online|pro|me)|interact\.sh|burpcollaborator\.net|dnslog\.cn|\.requestcatcher\.com)"),
    "References a paste bin, chat webhook, or out-of-band collaborator endpoint — common exfiltration sinks for stolen data.",
    "Remove the endpoint. Agent artifacts should not post to paste/webhook/OOB services.",
)
GENERIC_TEXT_RULES: List[AgentRule] = [EXFIL_RULE, URL_EXFIL_RULE, WEBHOOK_EXFIL_RULE, OBF_RULE, SECRET_RULE, DESTRUCT_RULE]

# MCP server configs
MCP_RULES: List[AgentRule] = [
    AgentRule(
        "AGENT-MCP-001", "MCP server fetches and runs a remote script",
        FindingSeverity.CRITICAL, 9.6,
        _c(r"(curl|wget)[^\n]{0,80}\|\s*(sh|bash|zsh|python|node)"),
        "An MCP server launch command downloads code and pipes it into a shell — remote code execution at install/run time.",
        "Never run curl|bash from an MCP server command. Pin and vendor the server, or install from a trusted registry.",
    ),
    AgentRule(
        "AGENT-MCP-002", "MCP server runs an unpinned remote package",
        FindingSeverity.MEDIUM, 5.5,
        _c(r"\b(npx|uvx|pipx\s+run|bunx)\b[^\n]{0,60}(@latest|-y\b|--yes\b)"),
        "The MCP server is launched from an unpinned/auto-confirmed remote package — vulnerable to rug-pulls (the package mutating after you trust it).",
        "Pin the MCP server package to an exact version and review updates before bumping.",
    ),
    AgentRule(
        "AGENT-MCP-003", "Dangerous execution primitive in MCP config",
        FindingSeverity.HIGH, 8.2,
        _c(r"\b(eval|exec|child_process|os\.system|subprocess|rm\s+-rf|powershell\s+-enc|-encodedcommand)\b"),
        "The MCP configuration invokes a dangerous execution primitive.",
        "Audit the command — an MCP server should run a known binary, not arbitrary eval/exec.",
    ),
]


# --- AGENT-MCP-004: broad host-secret exfil via an MCP server's env block ------
# An MCP server config's `env` block sets environment variables for the server
# process. Forwarding a BROAD AMBIENT host credential — one that grants access to
# the developer's whole cloud account, version-control identity, or SSH agent
# (AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK, GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG,
# …) — into a THIRD-PARTY server whose package/command has nothing to do with that
# service hands that process your keys. A genuine integration needs its own
# service's credential (an aws-* server reading AWS creds, a github server reading
# GITHUB_TOKEN); a notes/weather/utility server pulling in your AWS secret key and
# GitHub token is credential harvesting — the server can read the value and post it
# out at will.
#
# Each sensitive credential maps to the service tokens that make forwarding it
# legitimate. We flag a forwarded credential only when NONE of its service tokens
# appear in the server's name/command/args/package — so the official integration is
# never flagged, while an unrelated server is. "Forwarding" means the value pulls
# the host value (a ${VAR}/$VAR/${env:VAR} interpolation) or carries a real secret,
# not a constant like "production" or a non-secret config var (AWS_REGION, etc.).
_MCP_SENSITIVE_ENV = [
    # (regex matching the credential's env-var NAME, service tokens that justify it)
    (re.compile(r"^AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|SECURITY_TOKEN)$", re.I), ("aws",)),
    (re.compile(r"^(GH|GITHUB)_TOKEN$|^GITHUB_(PAT|PERSONAL_ACCESS_TOKEN)$", re.I), ("github", "gh")),
    (re.compile(r"^GITLAB_TOKEN$|^GITLAB_(PAT|PERSONAL_ACCESS_TOKEN)$", re.I), ("gitlab", "glab")),
    (re.compile(r"^SSH_AUTH_SOCK$|^SSH_PRIVATE_KEY$", re.I), ("ssh",)),
    (re.compile(r"^GOOGLE_APPLICATION_CREDENTIALS$|^(GCP|GCLOUD)_[A-Z0-9_]*(KEY|TOKEN|SECRET|CREDENTIAL|CREDENTIALS)$", re.I),
     ("gcp", "google", "gcloud", "firebase")),
    (re.compile(r"^AZURE_(CLIENT_SECRET|CLIENT_ID|TENANT_ID)$", re.I), ("azure",)),
    (re.compile(r"^KUBECONFIG$", re.I), ("kube", "k8s", "kubernetes")),
    (re.compile(r"^(NPM_TOKEN|NODE_AUTH_TOKEN)$", re.I), ("npm",)),
    (re.compile(r"^DOCKER_(PASSWORD|AUTH_CONFIG)$", re.I), ("docker",)),
    (re.compile(r"^(CF|CLOUDFLARE)_API_(TOKEN|KEY)$", re.I), ("cloudflare", "cf", "wrangler")),
    (re.compile(r"^(DIGITALOCEAN|DO)_(API_)?TOKEN$", re.I), ("digitalocean", "doctl")),
    (re.compile(r"^VERCEL_TOKEN$", re.I), ("vercel",)),
    (re.compile(r"^NETLIFY_(AUTH_)?TOKEN$", re.I), ("netlify",)),
    (re.compile(r"^HEROKU_API_KEY$", re.I), ("heroku",)),
    (re.compile(r"^HF_TOKEN$|^HUGGING(FACE)?_?(HUB_)?TOKEN$", re.I), ("huggingface", "hf")),
]
# Extract environment-variable references from an env value: ${VAR}, ${env:VAR},
# $VAR — the forms an MCP launcher interpolates to pull the host's value through.
_MCP_ENV_REF = re.compile(r"\$\{?(?:env:)?([A-Za-z_][A-Za-z0-9_]*)\}?")


def _mcp_sensitive_service(varname: str):
    """Service tokens that justify forwarding `varname`, or None if it's not a
    recognized broad ambient credential."""
    name = varname.strip()
    for pat, services in _MCP_SENSITIVE_ENV:
        if pat.match(name):
            return services
    return None


def _token_present(token: str, text_lower: str) -> bool:
    """True if `token` appears in `text_lower` as a delimited token (not a
    substring) — so 'gh' matches 'gh-helper' but not 'highlight', and 'aws'
    matches 'server-aws' but not 'lawsuit'."""
    return re.search(r"(?<![a-z0-9])" + re.escape(token) + r"(?![a-z0-9])", text_lower) is not None


MCP_ENV_EXFIL_RULE = AgentRule(
    "AGENT-MCP-004", "Broad host credential forwarded to an unrelated MCP server",
    FindingSeverity.HIGH, 8.3, None,
    "The MCP server's `env` block forwards a broad ambient host credential — one "
    "that grants access to your cloud account, version-control identity, or SSH "
    "agent (e.g. AWS_SECRET_ACCESS_KEY, GITHUB_TOKEN, SSH_AUTH_SOCK, "
    "GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG) — into a server process whose "
    "package/command has nothing to do with that service. A third-party server "
    "launched this way receives your keys directly; it's a low-effort credential-"
    "harvesting channel, because the server can read the value and exfiltrate it.",
    "Remove the credential from this server's env, or scope it down. Forward a "
    "credential only to the service's own official integration (an AWS server "
    "reading AWS creds), pin and vet the package first, and prefer a least-"
    "privilege, dedicated token over a broad ambient one.",
)

# --- AGENT-MCP-005: MCP server launches code from a raw URL / gist / paste / IP ---
# An MCP server's launch command should reference a pinned package from a trusted
# registry or a vetted local file — not pull its code at launch from a raw,
# unversioned, attacker-mutable source. A command/args that fetches from
# raw.githubusercontent.com, a GitHub gist, a paste service, or a bare IP-literal
# host means the bytes that actually run are whatever live at that URL the moment
# the agent starts the server: no version pin, no provenance, no review. Launchers
# execute it directly (`deno run <url>`, `npx <tarball-url>`, `bunx <url>`,
# `uvx --from git+<rawhost>`). This is a supply-chain RCE / rug-pull channel,
# distinct from the curl|bash pipe form already caught by AGENT-MCP-001.
#
# Scoped to command + args (the launch path), NOT the env block (AGENT-MCP-004) and
# NOT a remote HTTP MCP server's `url` transport field — so an ordinary vendor
# endpoint (https://api.vendor.com/mcp) is never flagged. Only dedicated raw/paste
# hosts and ROUTABLE PUBLIC IP literals trip it; loopback / private / link-local
# IPs (local dev servers) and ordinary hostnames are excluded.
_MCP_RAW_SOURCE_HOSTS = (
    "raw.githubusercontent.com", "gist.githubusercontent.com", "gist.github.com",
    "raw.githack.com", "rawcdn.githack.com",
    "pastebin.com", "paste.ee", "hastebin.com", "dpaste.com", "dpaste.org",
    "rentry.co", "rentry.org", "0bin.net", "ghostbin.com", "controlc.com",
    "bpa.st", "ix.io", "sprunge.us", "paste.rs", "termbin.com",
)
# A URL inside a command/args token. Captures the host — a bracketed IPv6 literal or
# an ordinary host[:port] — so we can classify it. `\b` lets it match inside
# `git+https://…`. The host group stops before the port/path.
_MCP_URL = re.compile(r"\bhttps?://(?:[^@/\s]*@)?(\[[0-9A-Fa-f:.]+\]|[^:/?#\s]+)", re.IGNORECASE)


def _is_public_ip_literal(host: str) -> bool:
    """True if `host` is a routable public IP literal (the remote-fetch smell).

    `is_global` is True only for genuinely public addresses — it already excludes
    loopback, private (RFC1918), link-local, CGNAT, documentation, reserved, and
    multicast ranges (all local-dev or non-routable, not a remote-fetch smell). Only
    a public IP, which carries no hostname / cert provenance, is the signal."""
    h = host.strip().strip("[]")
    try:
        return ipaddress.ip_address(h).is_global
    except ValueError:
        return False


MCP_REMOTE_SOURCE_RULE = AgentRule(
    "AGENT-MCP-005", "MCP server launches code from a raw URL / gist / paste / IP literal",
    FindingSeverity.HIGH, 8.5, None,
    "The MCP server's launch command fetches code from an unversioned, "
    "attacker-mutable source — raw.githubusercontent.com, a GitHub gist, a paste "
    "service, or a bare public IP-literal host — instead of a pinned package from a "
    "trusted registry or a vetted local file. Whatever bytes live at that URL when "
    "the agent starts the server are what execute (e.g. `deno run <url>`, "
    "`npx <tarball-url>`, `bunx <url>`): no version pin, no provenance, no review. "
    "It is a supply-chain RCE / rug-pull channel — the source can change under you "
    "after you trust it.",
    "Don't launch an MCP server from a raw / gist / paste URL or a bare IP. Install "
    "it from a trusted registry pinned to an exact version, or vendor and review the "
    "code locally; reference servers by package name, not by a mutable URL.",
)

# n8n workflow exports
N8N_RULES: List[AgentRule] = [
    AgentRule(
        "AGENT-N8N-001", "n8n Code/Function node runs shell or eval",
        FindingSeverity.HIGH, 8.4,
        _c(r"(child_process|require\(\s*['\"]child_process|execSync|\bexec\(|eval\(|os\.system|subprocess\.)"),
        "An n8n Code/Function node executes shell commands or eval — a sandbox-escape / RCE vector (cf. n8n Code-node CVEs).",
        "Avoid shell/eval in Code nodes; use built-in nodes or a vetted, sandboxed function.",
    ),
]

# Pro-tier advanced detections — unlocked with a Shellockolm Pro license. The free
# rule sets above always run; these are *additional* coverage, never a replacement.
# (In the durable open-core model these are served by the licensing endpoint so
# they aren't reconstructable from the open repo; bundled here as the starter pack.)
PRO_RULES: List[AgentRule] = [
    AgentRule(
        "AGENT-PRO-001", "Indirect prompt injection via fetched content",
        FindingSeverity.HIGH, 8.3,
        _c(r"\b(fetch|read|load|open|visit|retrieve|download)\b[^\n]{0,50}\b(then|and)\b[^\n]{0,40}\b(follow|do|execute|obey|apply|run|perform)\b"),
        "Instructs the agent to fetch external content and then follow instructions inside it — indirect (second-order) prompt injection.",
        "Treat fetched content as untrusted data, never as instructions. Remove the 'then follow' directive.",
    ),
    AgentRule(
        "AGENT-PRO-002", "Tool / skill shadowing or redefinition",
        FindingSeverity.HIGH, 7.9,
        _c(r"\b(override|replace|shadow|supersede|redefine|take\s+precedence\s+over|instead\s+of)\b[^\n]{0,30}\b(tool|function|command|skill|server|capability)\b"),
        "Claims to override or replace another tool/skill — tool shadowing, used to hijack a trusted tool's behavior.",
        "Audit the redefinition. Skills should not silently supersede other tools.",
    ),
    AgentRule(
        "AGENT-PRO-003", "Conversation / context exfiltration",
        FindingSeverity.CRITICAL, 9.0,
        _c(r"\b(send|post|upload|forward|share|transmit|leak)\b[^\n]{0,45}\b(conversation|chat\s+history|message\s+history|context\s+window|transcript|all\s+(messages|prior\s+turns))\b"),
        "Instruction to send the conversation/context elsewhere — exfiltration of everything shared with the agent.",
        "Remove. No legitimate skill needs to transmit the conversation history off-box.",
    ),
]


class AgentSupplyChainScanner(BaseScanner):
    """Scans agent skills, MCP configs, and n8n workflows for agentic-era threats."""

    NAME = "agent"
    DESCRIPTION = (
        "Scans the AI-agent coding supply chain (skills, MCP configs, n8n workflows) "
        "for prompt injection, secret exfiltration, and tool poisoning"
    )
    CVE_IDS: List[str] = []
    SUPPORTED_PACKAGES = ["agent-skill", "mcp-config", "n8n-workflow"]

    SKILL_NAMES = {"skill.md"}
    MCP_NAMES = {"mcp.json", ".mcp.json", "claude_desktop_config.json"}
    # AI instruction files that agents read as standing context — prime
    # prompt-injection targets (Claude Code, Cursor, Windsurf, Copilot, Cline, Gemini).
    INSTRUCTION_NAMES = {
        "agents.md", "claude.md", "gemini.md",
        ".cursorrules", ".windsurfrules", ".clinerules",
        "copilot-instructions.md",
    }

    # Heavy dirs to skip; note we deliberately do NOT skip dot-dirs in general,
    # because agent artifacts live in .claude/.cursor/.mcp/.windsurf etc.
    SKIP_DIRS: Set[str] = {
        "node_modules", ".git", ".svn", ".hg", "__pycache__",
        ".venv", "venv", "env", "dist", "build", ".next", ".nuxt",
        ".cache", ".pytest_cache", ".mypy_cache", "coverage",
    }

    MAX_FILE_BYTES = 2_000_000
    _B64 = re.compile(r"[A-Za-z0-9+/]{160,}={0,2}")

    def __init__(self, pro: Optional[bool] = None):
        super().__init__()
        if pro is None:
            try:
                from licensing import LicenseManager
                pro = LicenseManager().is_pro()
            except Exception:
                pro = False
        self.pro = bool(pro)

    def _extra(self) -> List[AgentRule]:
        """Pro-only rules, included when a valid Pro/Team license is active."""
        return PRO_RULES if self.pro else []

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False,
    ) -> ScanResult:
        result = self.create_result(path, scan_type="local")
        root = Path(path)

        if not root.exists():
            result.errors.append(f"Path not found: {path}")
            return self.finalize_result(result)

        targets = [root] if root.is_file() else list(self._walk(root, recursive, max_depth))

        skills = mcps = workflows = instrs = 0
        for fp in targets:
            name = fp.name.lower()
            is_skill = name in self.SKILL_NAMES or name.endswith(".skill.md")
            is_mcp = name in self.MCP_NAMES or name.endswith(".mcp.json")
            is_instr = name in self.INSTRUCTION_NAMES
            is_json = name.endswith(".json")
            if not (is_skill or is_mcp or is_instr or is_json):
                continue

            try:
                if fp.stat().st_size > self.MAX_FILE_BYTES:
                    continue
                text = fp.read_text(encoding="utf-8", errors="ignore")
            except (OSError, IOError):
                continue

            if is_skill:
                skills += 1
                result.findings.extend(self._scan_skill(fp, text, quick_mode))
            elif is_mcp:
                mcps += 1
                result.findings.extend(self._scan_mcp(fp, text))
            elif is_instr:
                instrs += 1
                result.findings.extend(self._scan_instructions(fp, text, quick_mode))
            elif is_json and '"nodes"' in text and '"connections"' in text:
                workflows += 1
                result.findings.extend(self._scan_n8n(fp, text))

        result = self.finalize_result(result)
        result.stats.update({
            "skills_scanned": skills,
            "mcp_configs_scanned": mcps,
            "n8n_workflows_scanned": workflows,
            "instruction_files_scanned": instrs,
        })
        return result

    def scan_file(self, file_path: str) -> List[ScanFinding]:
        res = self.scan_directory(file_path, recursive=False)
        return res.findings

    # ---------------------------------------------------------------- internals

    def _walk(self, root: Path, recursive: bool, max_depth: int) -> Generator[Path, None, None]:
        def rec(current: Path, depth: int):
            if depth > max_depth:
                return
            try:
                entries = list(current.iterdir())
            except (OSError, PermissionError):
                return
            for entry in entries:
                try:
                    if entry.is_file():
                        yield entry
                    elif entry.is_dir() and recursive \
                            and entry.name not in self.SKIP_DIRS \
                            and entry.name not in self.WINDOWS_SYSTEM_DIRS:
                        yield from rec(entry, depth + 1)
                except (OSError, PermissionError):
                    continue

        yield from rec(root, 0)

    def _scan_skill(self, fp: Path, text: str, quick_mode: bool) -> List[ScanFinding]:
        findings = self._apply_rules(text, PROMPT_INJECTION_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "agent-skill")
        findings += self._check_invisible(text, fp, "agent-skill")
        findings += self._check_tag_smuggling(text, fp, "agent-skill")
        findings += self._check_bidi(text, fp, "agent-skill")
        findings += self._check_confusables(text, fp, "agent-skill")
        findings += self._check_link_mismatch(text, fp, "agent-skill")
        findings += self._check_hidden_comment(text, fp, "agent-skill")
        findings += self._check_frontmatter(text, fp, "agent-skill")
        findings += self._check_memory_poisoning(text, fp, "agent-skill")
        if not quick_mode:
            findings += self._check_b64(text, fp, "agent-skill")
        return self._dedupe(findings)

    def _scan_mcp(self, fp: Path, text: str) -> List[ScanFinding]:
        findings = self._check_invisible(text, fp, "mcp-config")
        findings += self._check_tag_smuggling(text, fp, "mcp-config")
        findings += self._check_bidi(text, fp, "mcp-config")
        structured = self._scan_mcp_structured(fp, text)
        if structured is None:
            # not valid JSON — fall back to raw-text rules
            findings += self._apply_rules(text, MCP_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "mcp-config")
        else:
            findings += structured
            findings += self._apply_rules(text, GENERIC_TEXT_RULES + self._extra(), fp, "mcp-config")
        return self._dedupe(findings)

    def _scan_mcp_structured(self, fp: Path, text: str) -> Optional[List[ScanFinding]]:
        """Parse mcp.json and check each server's command/args/env as one string.

        Pretty-printed configs split a server's launcher and flags across lines,
        which line-bounded regexes miss — so we join per-server fields and match
        against that. Returns None if the file isn't valid JSON (caller falls back).
        """
        try:
            data = json.loads(text)
        except (ValueError, TypeError):
            return None

        out: List[ScanFinding] = []
        servers: Dict[str, Any] = {}
        if isinstance(data, dict):
            for key in ("mcpServers", "servers", "mcp"):
                value = data.get(key)
                if isinstance(value, dict):
                    servers.update(value)

        for name, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            parts = [str(cfg.get("command", ""))]
            args = cfg.get("args", [])
            if isinstance(args, list):
                parts += [str(a) for a in args]
            env = cfg.get("env", {})
            if isinstance(env, dict):
                parts += [f"{k}={v}" for k, v in env.items()]
            joined = " ".join(p for p in parts if p)
            loc = f"{fp} » server:{name}"
            for rule in MCP_RULES + [SECRET_RULE, EXFIL_RULE]:
                if rule.pattern:
                    m = rule.pattern.search(joined)
                    if m:
                        out.append(self._mk(rule, loc, "mcp-config", self._redact(m.group(0))))
            out += self._check_mcp_env_exfil(name, cfg, fp)
            out += self._check_mcp_remote_source(name, cfg, fp)
        return out

    def _check_mcp_env_exfil(self, name: str, cfg: Dict[str, Any], fp: Path) -> List[ScanFinding]:
        """AGENT-MCP-004: broad ambient host credential forwarded to an unrelated server.

        The `env` block sets variables for the server process. Forwarding a broad
        host credential (AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK,
        GOOGLE_APPLICATION_CREDENTIALS, KUBECONFIG, …) — identified by the env key
        name OR by a ${VAR} interpolation in the value (which catches a credential
        renamed to an innocuous key) — to a server whose name/command/args/package
        does not relate to that credential's service hands a third-party process
        your keys. A server that IS the service's own integration (an aws-* server
        receiving AWS creds) is not flagged. Non-secret config vars (AWS_REGION,
        NODE_ENV) and app-scoped keys (BRAVE_API_KEY) are not in the credential map
        and never trip the rule.
        """
        env = cfg.get("env")
        if not isinstance(env, dict) or not env:
            return []
        # Text that identifies what this server actually is, for service-association.
        ident_parts = [str(name), str(cfg.get("command", ""))]
        args = cfg.get("args", [])
        if isinstance(args, list):
            ident_parts += [str(a) for a in args]
        ident = " ".join(ident_parts).lower()

        leaked: List[str] = []
        for k, v in env.items():
            key = str(k).strip()
            val = str(v).strip()
            if not val:
                continue
            # Credential identity from the KEY itself, or from a host var the value pulls.
            for cand in [key] + _MCP_ENV_REF.findall(val):
                services = _mcp_sensitive_service(cand)
                if services is None:
                    continue
                if any(_token_present(tok, ident) for tok in services):
                    continue  # this server is that service's own integration — legitimate
                label = key if cand.upper() == key.upper() else f"{key}<-${{{cand}}}"
                leaked.append(label)
                break  # one credential per env entry is enough
        if not leaked:
            return []
        seen: Set[str] = set()
        uniq = [x for x in leaked if not (x in seen or seen.add(x))]
        snippet = "env forwards " + ", ".join(uniq[:6]) + " to unrelated server"
        return [self._mk(MCP_ENV_EXFIL_RULE, f"{fp} » server:{name}", "mcp-config", snippet)]

    def _check_mcp_remote_source(self, name: str, cfg: Dict[str, Any], fp: Path) -> List[ScanFinding]:
        """AGENT-MCP-005: server launches code from a raw URL / gist / paste / IP literal.

        Inspects the server's command + args (the launch path) — not the env block
        (AGENT-MCP-004) and not a remote HTTP server's `url` transport field. A URL
        whose host is a dedicated raw-code / paste / gist service, or a routable
        public IP literal, means the code that runs is fetched unversioned and
        unvetted at launch — a supply-chain RCE / rug-pull vector. Loopback / private
        / link-local IPs (local dev) and ordinary vendor hostnames (a remote MCP
        endpoint like https://api.vendor.com/mcp passed to a proxy) are not flagged.
        """
        parts = [str(cfg.get("command", ""))]
        args = cfg.get("args", [])
        if isinstance(args, list):
            parts += [str(a) for a in args]
        joined = " ".join(p for p in parts if p)
        if not joined:
            return []
        for m in _MCP_URL.finditer(joined):
            raw_host = m.group(1)
            host = raw_host.lower()
            reason = None
            if any(host == h or host.endswith("." + h) for h in _MCP_RAW_SOURCE_HOSTS):
                reason = f"raw/paste source host {host}"
            elif _is_public_ip_literal(raw_host):
                reason = f"bare public IP literal {raw_host}"
            if reason:
                loc = f"{fp} » server:{name}"
                snippet = f"{reason}: {self._redact(m.group(0))}"
                return [self._mk(MCP_REMOTE_SOURCE_RULE, loc, "mcp-config", snippet)]
        return []

    def _scan_n8n(self, fp: Path, text: str) -> List[ScanFinding]:
        findings = self._apply_rules(text, N8N_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "n8n-workflow")
        findings += self._check_tag_smuggling(text, fp, "n8n-workflow")
        findings += self._check_bidi(text, fp, "n8n-workflow")
        return self._dedupe(findings)

    def _scan_instructions(self, fp: Path, text: str, quick_mode: bool) -> List[ScanFinding]:
        findings = self._apply_rules(text, PROMPT_INJECTION_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "agent-instructions")
        findings += self._check_invisible(text, fp, "agent-instructions")
        findings += self._check_tag_smuggling(text, fp, "agent-instructions")
        findings += self._check_bidi(text, fp, "agent-instructions")
        findings += self._check_confusables(text, fp, "agent-instructions")
        findings += self._check_link_mismatch(text, fp, "agent-instructions")
        findings += self._check_hidden_comment(text, fp, "agent-instructions")
        findings += self._check_frontmatter(text, fp, "agent-instructions")
        findings += self._check_memory_poisoning(text, fp, "agent-instructions")
        if not quick_mode:
            findings += self._check_b64(text, fp, "agent-instructions")
        return self._dedupe(findings)

    def _apply_rules(self, text: str, rules: List[AgentRule], fp: Path, artifact: str) -> List[ScanFinding]:
        findings = []
        for rule in rules:
            if rule.pattern is None:
                continue
            m = rule.pattern.search(text)
            if not m:
                continue
            line_no = text.count("\n", 0, m.start()) + 1
            findings.append(self._finding(rule, fp, artifact, self._redact(m.group(0)), line_no))
        return findings

    def _check_invisible(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        for ch in INVISIBLE_CHARS:
            idx = text.find(ch)
            if idx != -1:
                line_no = text.count("\n", 0, idx) + 1
                rule = AgentRule(
                    "AGENT-PI-005", "Hidden / invisible characters in instructions",
                    FindingSeverity.MEDIUM, 6.0, None,
                    "Zero-width or invisible Unicode characters can hide instructions from human review while staying visible to the model.",
                    "Strip invisible/zero-width characters; legitimate docs don't need them.",
                )
                return [self._finding(rule, fp, artifact, repr(ch), line_no)]
        return []

    def _check_tag_smuggling(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect ASCII smuggled via the Unicode Tags block (invisible instructions)."""
        tag_idx = [i for i, ch in enumerate(text)
                   if TAG_BLOCK_START <= ord(ch) <= TAG_BLOCK_END]
        if not tag_idx:
            return []
        # Decode the smuggled payload back to ASCII so the finding shows what was hidden.
        decoded = "".join(
            chr(ord(text[i]) - TAG_BLOCK_START)
            for i in tag_idx if 0x20 <= ord(text[i]) - TAG_BLOCK_START <= 0x7E
        )
        line_no = text.count("\n", 0, tag_idx[0]) + 1
        snippet = f"{len(tag_idx)} tag char(s); decodes to: {decoded[:80]!r}" if decoded \
            else f"{len(tag_idx)} Unicode Tag char(s)"
        rule = AgentRule(
            "AGENT-PI-007", "ASCII smuggling via Unicode Tags block",
            FindingSeverity.HIGH, 8.2, None,
            "Invisible Unicode Tag characters (U+E0000–U+E007F) encode hidden ASCII that "
            "renders as nothing to a human reviewer but is read by the model — a stealth "
            "prompt-injection channel.",
            "Strip all U+E0000–U+E007F characters; no legitimate artifact uses the Tags block.",
        )
        return [self._finding(rule, fp, artifact, snippet, line_no)]

    def _check_bidi(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect Trojan Source bidirectional control characters (CVE-2021-42574).

        These reorder displayed text without changing the bytes, so a human reviewer
        sees a different ordering than the model reads — a stealth way to hide or
        visually reverse instructions inside an artifact.
        """
        for idx, ch in enumerate(text):
            name = BIDI_CONTROL_CHARS.get(ch)
            if name is None:
                continue
            line_no = text.count("\n", 0, idx) + 1
            rule = AgentRule(
                "AGENT-PI-010", "Bidirectional text override (Trojan Source) character",
                FindingSeverity.HIGH, 8.0, None,
                "A Unicode bidirectional control character (Trojan Source, CVE-2021-42574) "
                "is present. It reorders how text is displayed without changing the raw "
                "bytes, so a human reviewer reads a different ordering than the model — a "
                "stealth channel to hide or visually reverse instructions.",
                "Strip U+202A–U+202E and U+2066–U+2069; plain LTR agent artifacts never "
                "need bidi overrides or isolates.",
            )
            return [self._finding(rule, fp, artifact, f"U+{ord(ch):04X} {name}", line_no)]
        return []

    def _check_confusables(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect mixed-script confusable (homoglyph) spoofing.

        Flags a word that mixes ASCII Latin letters with a confusable look-alike
        from another script (e.g. Cyrillic о inside "ignore") — the word reads
        normally but evades keyword/substring review of the instruction text.
        A word written *entirely* in one non-Latin script is genuine foreign text
        and is not flagged; only Latin-plus-confusable mixing trips the rule.
        """
        for m in _CONFUSABLE_WORD.finditer(text):
            word = m.group(0)
            has_ascii = any("a" <= c.lower() <= "z" for c in word)
            confusables = [c for c in word if c in CONFUSABLES]
            if not (has_ascii and confusables):
                continue
            normalized = "".join(CONFUSABLES.get(c, c) for c in word)
            line_no = text.count("\n", 0, m.start()) + 1
            cps = ", ".join(f"U+{ord(c):04X}" for c in confusables[:5])
            snippet = f"{word!r} spoofs {normalized!r} (confusable: {cps})"
            rule = AgentRule(
                "AGENT-PI-011", "Homoglyph / mixed-script confusable spoofing",
                FindingSeverity.HIGH, 7.7, None,
                "A word mixes ASCII letters with confusable look-alike characters from "
                "another script (Cyrillic/Greek). It reads identically to a human and to "
                "the model, but defeats keyword/substring review — used to smuggle "
                "instructions or impersonate a trusted tool/skill name past a filter.",
                "Normalize the text to ASCII and re-review; legitimate Latin-script "
                "artifacts never mix Cyrillic/Greek look-alikes into English words.",
            )
            return [self._finding(rule, fp, artifact, snippet, line_no)]
        return []

    def _check_link_mismatch(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect a markdown link whose visible text names a different domain than its href.

        `[github.com/anthropic](https://evil.tld/x)` reads as a trusted link but points
        elsewhere — a classic lure to get an agent to auto-fetch attacker content. We
        only flag when the visible text actually advertises a hostname AND that host's
        registrable domain differs from the href's, so plain descriptive link text
        ("see the docs") and same-party subdomains never trip the rule.
        """
        for m in _MD_LINK.finditer(text):
            link_text, href = m.group(1), m.group(2)
            href_host = _URL_HOST.search(href)
            if not href_host:
                continue
            href_dom = _registrable(href_host.group(1))
            for tm in _HOST_IN_TEXT.finditer(link_text):
                text_dom = _registrable(tm.group(1))
                if text_dom == href_dom:
                    continue
                line_no = text.count("\n", 0, m.start()) + 1
                snippet = f"text says {tm.group(1)!r} but href is {href_host.group(1)!r}"
                rule = AgentRule(
                    "AGENT-PI-012", "Markdown link text / href domain mismatch",
                    FindingSeverity.HIGH, 7.4, None,
                    "A markdown link's visible text advertises one domain while its href "
                    "points to a different one. In an agent artifact this is a lure: the "
                    "model (or a skimming reviewer) trusts the visible domain and follows "
                    "or auto-fetches the real, attacker-controlled URL.",
                    "Make the link text match its destination, or remove the link. Visible "
                    "text should never name a domain other than the one it links to.",
                )
                return [self._finding(rule, fp, artifact, snippet, line_no)]
        return []

    def _check_hidden_comment(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect imperative instructions concealed inside an HTML comment.

        `<!-- ... -->` blocks are invisible in any rendered Markdown/HTML view but are
        read verbatim by a model that consumes the raw file. An attacker uses this to
        slip directions (instruction overrides, 'do not tell the user', exfil/execute
        commands, 'from now on ...') past a human who only skims the rendered skill or
        instruction file. We flag a comment ONLY when its body carries an imperative
        directive cue — a plain explanatory or tooling comment (TOC marker,
        prettier-ignore, TODO, license header, region marker) is descriptive and never
        trips the rule.
        """
        for cm in _HTML_COMMENT.finditer(text):
            body = cm.group(1)
            dm = _COMMENT_DIRECTIVE.search(body)
            if not dm:
                continue
            abs_pos = cm.start(1) + dm.start()
            line_no = text.count("\n", 0, abs_pos) + 1
            snippet = "hidden in HTML comment: " + self._redact(dm.group(0))
            rule = AgentRule(
                "AGENT-PI-013", "Imperative instructions hidden in an HTML comment",
                FindingSeverity.HIGH, 7.6, None,
                "An HTML comment (<!-- ... -->) contains imperative instructions. The "
                "comment is invisible in any rendered Markdown view but is read verbatim "
                "by a model consuming the raw file — a stealth channel to smuggle "
                "directions (instruction overrides, 'do not tell the user', exfiltration "
                "or execute commands) past a human who only sees the rendered artifact.",
                "Remove the comment or the directive inside it. Skill / instruction files "
                "should never hide imperative instructions for the model in HTML comments.",
            )
            return [self._finding(rule, fp, artifact, snippet, line_no)]
        return []

    def _check_frontmatter(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect permission/safety-bypass flags baked into a skill's YAML frontmatter.

        A SKILL.md / instruction file may open with a `---`-delimited YAML frontmatter
        block — metadata loaded as standing context *before* the agent runs the skill.
        Runtime safety toggles do not belong there. A `bypassPermissions`, an
        `--dangerously-skip-permissions`, an `auto-approve: true` / `yolo: true`, or a
        `permission-mode: bypassPermissions` baked into a distributable artifact
        silently broadens the agent's autonomy past the per-invocation consent the user
        expects, while the visible prose body looks ordinary.

        The block is parsed structurally (key/value) so that a `description` that merely
        *mentions* such a flag in prose never trips the rule, and a broad-but-legitimate
        `allowed-tools: "*"` (used by tool-adaptive skills) is deliberately not treated
        as abuse — only an explicit safety-bypass directive is.
        """
        fm_match = _FRONTMATTER.search(text)
        if not fm_match:
            return []
        fm = fm_match.group(1)
        fm_start = fm_match.start(1)

        hit_pos: Optional[int] = None
        snippet = ""

        # The CLI escape-hatch string is never benign in metadata, wherever it sits
        # (key, value, or buried in an args list a launcher would forward).
        dm = _FM_DANGEROUS.search(fm)
        if dm:
            hit_pos = fm_start + dm.start()
            snippet = dm.group(0)
        else:
            offset = 0
            for line in fm.splitlines(keepends=True):
                kv = _FM_KV.match(line)
                if kv:
                    key = kv.group(1).strip().strip("\"'").lower().replace("_", "-")
                    val = kv.group(2).split("#")[0].strip().strip("\"'").strip().lower()
                    key_c = key.replace("-", "")
                    if key in _FM_BYPASS_KEYS and val in _FM_TRUTHY:
                        hit_pos = fm_start + offset + kv.start(1)
                        snippet = f"{kv.group(1).strip()}: {kv.group(2).strip()}"
                    elif key_c in _FM_MODE_KEYS_C and val.replace("-", "") in _FM_BYPASS_MODES_C:
                        hit_pos = fm_start + offset + kv.start(1)
                        snippet = f"{kv.group(1).strip()}: {kv.group(2).strip()}"
                if hit_pos is not None:
                    break
                offset += len(line)

        if hit_pos is None:
            return []
        line_no = text.count("\n", 0, hit_pos) + 1
        rule = AgentRule(
            "AGENT-PI-014", "Permission/safety-bypass flag in skill frontmatter",
            FindingSeverity.HIGH, 8.0, None,
            "The skill / instruction file's YAML frontmatter declares a permission- or "
            "safety-bypass flag (e.g. bypassPermissions, --dangerously-skip-permissions, "
            "auto-approve: true, yolo: true, or permission-mode: bypassPermissions). "
            "Frontmatter is metadata loaded before the skill runs, so the flag silently "
            "broadens the agent's autonomy past the per-invocation consent the user "
            "expects — the prompts that gate dangerous actions — while the prose body "
            "looks ordinary.",
            "Remove the bypass / auto-approve flag from the frontmatter. A distributable "
            "skill should declare only descriptive metadata and the specific tools it "
            "needs, never disable the permission prompts that gate dangerous actions.",
        )
        return [self._finding(rule, fp, artifact, "frontmatter flag: " + self._redact(snippet), line_no)]

    def _check_memory_poisoning(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        """Detect self-propagating injection that writes a directive into the agent's
        persistent memory / instruction store.

        Fires only when a "persist <self-reference> into <memory/config target>" action
        (CLAUDE.md, AGENTS.md, a memory file, .cursorrules, settings.json, your memory,
        …) co-occurs — within a small window — with a self-propagation payload cue:
        covert concealment ('do not tell the user'), an instruction override, or a
        standing 'from now on always …' coercion. That combination is the signature of
        an agent "worm": a one-shot injection rewriting itself into the agent's config
        so it auto-loads every future session. A memory/notes skill that merely saves
        user-chosen facts carries no covert/override cue and is not flagged.
        """
        for am in _PI015_ACTION.finditer(text):
            lo = max(0, am.start() - 200)
            hi = min(len(text), am.end() + 220)
            if not _PI015_PAYLOAD_CUE.search(text[lo:hi]):
                continue
            line_no = text.count("\n", 0, am.start()) + 1
            snippet = "persist-to-standing-context: " + self._redact(am.group(0))
            rule = AgentRule(
                "AGENT-PI-015", "Memory / persistence poisoning (self-propagating instruction)",
                FindingSeverity.HIGH, 8.5, None,
                "An instruction directs the agent to write a directive into its own "
                "persistent standing-context store (CLAUDE.md, AGENTS.md, a memory file, "
                ".cursorrules, settings.json, …) so it auto-loads in future sessions, and "
                "the persisted content carries a covert ('do not tell the user'), "
                "instruction-override, or 'from now on always …' directive. This is "
                "self-propagating prompt injection — a one-shot inject rewritten into the "
                "agent's config to become a persistent backdoor that survives across sessions.",
                "Never let a downloaded skill / instruction file write behavioural rules "
                "into your memory or config. Remove the self-propagation directive; the "
                "agent's CLAUDE.md / memory / settings should be changed only by the user, "
                "never on instruction from an untrusted artifact.",
            )
            return [self._finding(rule, fp, artifact, snippet, line_no)]
        return []

    def _check_b64(self, text: str, fp: Path, artifact: str) -> List[ScanFinding]:
        m = self._B64.search(text)
        if not m:
            return []
        line_no = text.count("\n", 0, m.start()) + 1
        rule = AgentRule(
            "AGENT-OBF-002", "Large base64 blob embedded in artifact",
            FindingSeverity.LOW, 4.0, None,
            "A long base64-encoded blob is embedded in the artifact; these can conceal payloads or data.",
            "Decode and review the blob; remove it if it isn't a legitimate asset.",
        )
        return [self._finding(rule, fp, artifact, m.group(0)[:40] + "...", line_no)]

    def _mk(self, rule: AgentRule, loc: str, artifact: str, snippet: str) -> ScanFinding:
        return ScanFinding(
            cve_id=rule.id,
            title=rule.title,
            severity=rule.severity,
            cvss_score=rule.cvss,
            package=artifact,
            version="n/a",
            patched_version=None,
            file_path=loc,
            description=f"{rule.description} (matched: {snippet})",
            exploit_difficulty="Variable",
            references=[],
            remediation=rule.remediation,
            detection_method="agent-scan",
            raw_data={"rule": rule.id, "artifact": artifact},
        )

    def _finding(self, rule: AgentRule, fp: Path, artifact: str, snippet: str, line_no: int) -> ScanFinding:
        finding = self._mk(rule, f"{fp}:{line_no}", artifact, snippet)
        finding.raw_data["line"] = line_no
        return finding

    @staticmethod
    def _redact(s: str) -> str:
        s = " ".join(s.split())
        return s[:97] + "..." if len(s) > 100 else s

    @staticmethod
    def _dedupe(findings: List[ScanFinding]) -> List[ScanFinding]:
        seen = set()
        out = []
        for f in findings:
            key = (f.cve_id, f.file_path)
            if key not in seen:
                seen.add(key)
                out.append(f)
        return out
