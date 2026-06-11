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
tool poisoning / remote-script execution, rug-pull (unpinned) MCP servers, and
hardcoded credentials. Pattern-based and 100% offline, consistent with the rest of
Shellockolm — a seatbelt you run *before* you install an untrusted skill or server.
"""

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Dict, Any, Generator, Set

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


# Zero-width / invisible characters used to hide instructions from human reviewers
INVISIBLE_CHARS = ["​", "‌", "‍", "⁠", "﻿", "­"]


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
GENERIC_TEXT_RULES: List[AgentRule] = [EXFIL_RULE, URL_EXFIL_RULE, OBF_RULE, SECRET_RULE, DESTRUCT_RULE]

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
        if not quick_mode:
            findings += self._check_b64(text, fp, "agent-skill")
        return self._dedupe(findings)

    def _scan_mcp(self, fp: Path, text: str) -> List[ScanFinding]:
        findings = self._check_invisible(text, fp, "mcp-config")
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
        return out

    def _scan_n8n(self, fp: Path, text: str) -> List[ScanFinding]:
        findings = self._apply_rules(text, N8N_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "n8n-workflow")
        return self._dedupe(findings)

    def _scan_instructions(self, fp: Path, text: str, quick_mode: bool) -> List[ScanFinding]:
        findings = self._apply_rules(text, PROMPT_INJECTION_RULES + GENERIC_TEXT_RULES + self._extra(), fp, "agent-instructions")
        findings += self._check_invisible(text, fp, "agent-instructions")
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
