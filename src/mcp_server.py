"""
Shellockolm MCP Server v3.0 - FAST & SMART
Model Context Protocol server for comprehensive CVE detection and remediation

NEW in v3.0:
- find_packages: Lightning-fast package discovery (~0.1s, excludes node_modules by default)
- quick_scan: Fast CVE-only scanning (2-3min, no deep analysis)
- scan_directory: Deep security scan (10+ min, all threats)

Smart defaults for speed:
- Excludes node_modules by default (40x faster)
- Max depth limits (prevents infinite recursion)
- Clear tool descriptions (AI picks the right tool)

Covers 32 CVEs across:
- React Server Components
- Next.js
- Node.js
- npm packages (mysql2, jsonpath-plus, body-parser, multer, etc.)
- n8n workflow automation
- Supply chain attacks (Shai-Hulud campaign)
"""

import asyncio
import inspect
import ipaddress
import json
import os
import socket
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional
from datetime import datetime
from urllib.parse import urlparse

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from mcp.server.models import InitializationOptions
from mcp.server import NotificationOptions, Server
from mcp.server.stdio import stdio_server
import mcp.types as types

from scanners import (
    SCANNER_REGISTRY,
    get_all_scanners,
    get_scanner,
    ScanResult,
    ScanFinding,
)
from vulnerability_database import VulnerabilityDatabase, Severity


# Create MCP server instance
server = Server("shellockolm")

# Initialize database
db = VulnerabilityDatabase()


def format_finding(finding: ScanFinding) -> str:
    """Format a finding for text output"""
    sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    return f"""### {finding.cve_id}: {finding.title}
- **Severity**: {sev} (CVSS {finding.cvss_score})
- **Package**: {finding.package} @ {finding.version}
- **File**: {finding.file_path}
- **Fix**: {finding.patched_version or 'See remediation'}
- **Difficulty**: {finding.exploit_difficulty}

{finding.description}

**Remediation**: {finding.remediation}
"""


def format_scan_results(results: List[ScanResult]) -> str:
    """Format multiple scan results"""
    total_findings = sum(len(r.findings) for r in results)
    critical = sum(1 for r in results for f in r.findings
                   if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "CRITICAL")
    high = sum(1 for r in results for f in r.findings
               if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "HIGH")

    output = f"""# Shellockolm Scan Results

## Summary
- **Total Findings**: {total_findings}
- **Critical**: {critical}
- **High**: {high}
- **Duration**: {sum(r.duration_seconds for r in results):.2f}s

"""

    if total_findings == 0:
        output += "✅ **No vulnerabilities detected!**\n"
        return output

    output += "## Findings\n\n"

    # Sort by severity
    all_findings = [(r, f) for r in results for f in r.findings]
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda x: severity_order.get(
        (x[1].severity.value if hasattr(x[1].severity, 'value') else str(x[1].severity)).upper(),
        4
    ))

    for result, finding in all_findings:
        output += format_finding(finding) + "\n---\n\n"

    return output


# ─────────────────────────────────────────────────────────────────
# AGENT SUPPLY-CHAIN SCAN — structured payload (the "agents scanning agents" tool)
# ─────────────────────────────────────────────────────────────────

# Stable contract version for the scan_agent_artifacts structured document. Within a
# major version, fields are only ADDED — never renamed or removed. Mirrors the CLI's
# build_json_report schema so an MCP client and `scan --json` agree on shape.
AGENT_SCAN_SCHEMA_VERSION = "1.0"

# UPPERCASE severity ranking for deterministic CRITICAL→INFO ordering.
_AGENT_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Accepted detection-certainty thresholds for the min_confidence argument.
_VALID_CONFIDENCE = {"low", "medium", "high"}

# Default wall-clock budget (seconds) for the scan_agent_artifacts directory walk, so a
# pathological or hostile tree can never hang an interactive agent's tool call. The walk
# stops at the budget and returns PARTIAL results with a warning rather than blocking.
# Callers can override per-call (0 = unbounded for a deliberate full local scan).
DEFAULT_AGENT_SCAN_TIME_BUDGET = 120.0


def normalize_exclude_node_modules(raw: Any) -> bool:
    """Coerce the ``exclude_node_modules`` tool input to a bool.

    Only an explicitly false-y value counts as "please scan inside
    node_modules". Anything unrecognized falls back to ``True``, which is what
    the scanners actually do — so an odd input can never make the scope note
    claim more coverage than the scan delivered.
    """
    if isinstance(raw, bool):
        return raw
    if raw is None:
        return True
    if isinstance(raw, str):
        return raw.strip().lower() not in {"false", "0", "no", "off"}
    return bool(raw)


def node_modules_scope_note(exclude_node_modules: bool) -> str:
    """Report what the scan actually covered w.r.t. ``node_modules``.

    Every registered scanner excludes ``node_modules`` unconditionally
    (``BaseScanner.EXCLUDE_DIRS``), so this tool input can only be honored in
    its default ``True`` direction. A caller passing ``False`` is asking for the
    installed dependency tree to be scanned — exactly where a supply-chain
    payload lands — and silently ignoring that request would present a scan as
    complete when it never looked there. Say so instead of quietly narrowing.
    """
    if exclude_node_modules:
        return (
            "**Scope**: `node_modules/` excluded — project sources only, "
            "not installed dependencies.\n\n"
        )
    return (
        "> ⚠️ **`exclude_node_modules=false` was NOT honored.** Every scanner in this "
        "server excludes `node_modules/` unconditionally, so this scan did **not** "
        "inspect installed dependencies. Treat the result as covering project sources "
        "only — it is not evidence that your dependency tree is clean.\n\n"
    )


def _finding_severity(finding) -> str:
    """Normalize a finding's severity to an UPPERCASE string (enum or str safe)."""
    sev = finding.severity
    return (sev.value if hasattr(sev, "value") else str(sev)).upper()


def _agent_finding_dict(finding) -> Dict[str, Any]:
    """Serialize one agent-scanner ``ScanFinding`` to the stable per-finding dict shape.

    Shared by ``build_agent_scan_payload`` (scan_agent_artifacts / scan_text) and
    ``build_mcp_config_payload`` (check_mcp_config) so every agentic tool emits the
    SAME finding shape: rule id, severity, confidence, attack class, tier, file:line,
    remediation. The agent scanner stores the ``AGENT-*`` rule id in ``cve_id``.
    """
    from scanners.agent_supply_chain import agent_rule_class, agent_rule_tier

    rule_id = finding.cve_id
    return {
        "id": rule_id,
        "title": finding.title,
        "severity": _finding_severity(finding),
        "confidence": getattr(finding, "confidence", "high"),
        "attack_class": agent_rule_class(rule_id),
        "tier": agent_rule_tier(rule_id),
        "cvss_score": finding.cvss_score,
        # file_path carries the ``<path>:<line>`` / ``<path> » server:<name>`` locator
        # exactly as the scanner emits it, so callers can resolve the artifact + line.
        "file_path": finding.file_path,
        "description": finding.description,
        "remediation": finding.remediation,
    }


def build_agent_scan_payload(
    result: ScanResult,
    *,
    target: str,
    min_confidence: str = "low",
    pro: bool = False,
) -> Dict[str, Any]:
    """Assemble the stable, structured agent-scan document from the agent scanner's
    ``ScanResult``.

    Agent-scoped sibling of the CLI's ``build_json_report`` (same ``schema_version``
    1.0 shape) that ADDS per-finding ``attack_class`` and ``tier`` (free/pro) so an
    MCP client gets the full agentic-supply-chain context without a second call.
    Findings are sorted CRITICAL→INFO for deterministic output, and ``ensure_ascii``
    JSON serialization keeps an invisible-Unicode injection payload pipe-safe.
    """
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings: List[Dict[str, Any]] = []
    for f in result.findings:
        sev = _finding_severity(f)
        key = sev.lower()
        if key in by_severity:
            by_severity[key] += 1
        findings.append(_agent_finding_dict(f))

    findings.sort(key=lambda d: _AGENT_SEVERITY_ORDER.get(d["severity"], 5))

    stats = result.stats or {}
    # Sum every integer ``*_scanned`` stat (bools excluded), matching the CLI's
    # aggregate_scan_stats convention so a new artifact class is counted for free.
    items_scanned = sum(
        v for k, v in stats.items()
        if k.endswith("_scanned") and isinstance(v, int) and not isinstance(v, bool)
    )

    mc = str(min_confidence).strip().lower()
    if mc not in _VALID_CONFIDENCE:
        mc = "low"

    # Partial-scan notices (input truncated to the size cap, or the directory walk
    # stopped at its time budget) — distinct from per-file read `errors`. `partial`
    # is the at-a-glance flag a client checks before trusting "0 findings" as clean.
    warnings = [str(w) for w in getattr(result, "warnings", [])]

    return {
        "schema_version": AGENT_SCAN_SCHEMA_VERSION,
        "tool": {"name": "shellockolm", "scanner": "agent"},
        "scan": {
            "time": datetime.now().isoformat(),
            "target": target,
            "min_confidence": mc,
            "pro": bool(pro),
            "duration_seconds": round(result.duration_seconds, 4),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "items_scanned": items_scanned,
            # Findings removed by a .shellockolmignore rule allowlist.
            "findings_suppressed": stats.get("findings_suppressed", 0),
            # Findings hidden by the min_confidence threshold.
            "findings_below_confidence": stats.get("findings_below_confidence", 0),
            # True when coverage was bounded (size cap / time budget) — results partial.
            "partial": bool(warnings),
            "warnings": warnings,
        },
        "findings": findings,
        "errors": [str(e) for e in result.errors],
    }


def format_agent_scan_results(payload: Dict[str, Any]) -> str:
    """Render the agent-scan payload as a markdown summary + an embedded JSON block.

    The markdown is for a human reading the tool output; the fenced ``json`` block is
    the machine-readable structured document for programmatic consumers.
    """
    scan = payload["scan"]
    s = payload["summary"]
    bs = s["by_severity"]
    tier = "Pro" if scan.get("pro") else "Free"

    lines = [
        "# Agent Supply-Chain Scan",
        "",
        f"**Target**: {scan['target']}",
        (
            f"**Tier**: {tier}  |  **Min confidence**: {scan['min_confidence']}  |  "
            f"**Items scanned**: {s['items_scanned']}  |  **Duration**: {scan['duration_seconds']}s"
        ),
        (
            f"**Total findings**: {s['total_findings']}  "
            f"(CRITICAL {bs['critical']}, HIGH {bs['high']}, MEDIUM {bs['medium']}, "
            f"LOW {bs['low']}, INFO {bs['info']})"
        ),
        "",
    ]

    if s["total_findings"] == 0:
        lines.append("✅ **No agentic-supply-chain threats detected.**")
    else:
        lines.append("## Findings")
        lines.append("")
        for f in payload["findings"]:
            conf = f.get("confidence", "high")
            conf_note = "" if conf == "high" else f" · confidence: {conf}"
            lines.append(
                f"- **[{f['severity']}] {f['id']}** "
                f"({f['attack_class']}, {f['tier']}{conf_note}) — {f['title']}\n"
                f"  `{f['file_path']}`\n"
                f"  _Fix_: {f['remediation']}"
            )

    if s.get("warnings"):
        lines.append("")
        lines.append("## ⚠️ Partial scan (coverage was bounded)")
        for w in s["warnings"]:
            lines.append(f"- {w}")

    if payload["errors"]:
        lines.append("")
        lines.append("## Errors (files skipped, scan continued)")
        for e in payload["errors"]:
            lines.append(f"- {e}")

    lines.append("")
    lines.append("## Structured findings (JSON)")
    lines.append("```json")
    lines.append(json.dumps(payload, indent=2, ensure_ascii=True))
    lines.append("```")
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# CHECK MCP CONFIG — scan the caller's OWN installed MCP configs (well-known paths)
# ─────────────────────────────────────────────────────────────────

# Stable contract version for the check_mcp_config structured document. Within a major
# version, fields are only ADDED. Reuses the same per-finding shape as the agent scan.
MCP_CONFIG_SCHEMA_VERSION = "1.0"

# Skip a config file larger than this (a runaway ~/.claude.json can carry MBs of
# project history); recorded as "skipped" so it is never a silent gap.
MAX_MCP_CONFIG_BYTES = 5_000_000


def scan_known_mcp_configs(
    locations,
    *,
    min_confidence: str = "low",
    quick_mode: bool = False,
):
    """Probe each candidate MCP-config location and scan the ones that exist.

    Takes the PURE candidate list from
    :func:`mcp_config_locations.known_mcp_config_locations` and turns it into per-location
    records: an absent file is ``"absent"`` (skipped), an oversize one ``"skipped"``, an
    unreadable one ``"unreadable"`` (note kept), and an existing readable one ``"scanned"``
    with its findings. Each file is routed through the agent scanner's structured MCP path
    (``artifact_type="mcp"``) regardless of its actual filename, so a config that is not
    literally named ``mcp.json`` (``~/.claude.json``, Windsurf's ``mcp_config.json``) is
    still parsed for ``mcpServers`` / ``servers`` entries.

    Returns ``(records, pro)`` where ``pro`` reflects the active license (Pro rules are
    gated exactly as on the CLI). The scanner is constructed once and reused.
    """
    from scanners.agent_supply_chain import AgentSupplyChainScanner

    scanner = AgentSupplyChainScanner()
    records: List[Dict[str, Any]] = []

    for loc in locations:
        record: Dict[str, Any] = {
            "client": loc.client,
            "scope": loc.scope,
            "path": str(loc.path),
            "status": "absent",
            "note": None,
            "findings": [],
        }
        try:
            if not loc.path.is_file():
                records.append(record)
                continue
            if loc.path.stat().st_size > MAX_MCP_CONFIG_BYTES:
                record["status"] = "skipped"
                record["note"] = (
                    f"file larger than {MAX_MCP_CONFIG_BYTES} bytes — not scanned"
                )
                records.append(record)
                continue
            raw = loc.path.read_bytes()
        except OSError as exc:
            record["status"] = "unreadable"
            record["note"] = f"{type(exc).__name__}: {exc}"
            records.append(record)
            continue

        try:
            result = scanner.scan_text(
                raw,
                artifact_type="mcp",
                filename=str(loc.path),
                quick_mode=bool(quick_mode),
                min_confidence=str(min_confidence),
            )
        except Exception as exc:  # defensive: a rule bug must never crash the tool
            record["status"] = "unreadable"
            record["note"] = f"scan error: {type(exc).__name__}: {exc}"
            records.append(record)
            continue

        record["status"] = "scanned"
        record["findings"] = list(result.findings)
        records.append(record)

    return records, scanner.pro


def build_mcp_config_payload(
    records: List[Dict[str, Any]],
    *,
    system: str,
    min_confidence: str = "low",
    pro: bool = False,
) -> Dict[str, Any]:
    """Assemble the stable check_mcp_config document from per-location scan records.

    Surfaces a ``locations`` array (which well-known config each client uses, whether it
    is present, and how many findings it carried) plus a flat ``findings`` list sorted
    CRITICAL→INFO using the SAME per-finding shape as ``scan_agent_artifacts`` — so a
    client gets both "where are my MCP configs" and "what's wrong in them" in one call.
    """
    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings: List[Dict[str, Any]] = []
    location_entries: List[Dict[str, Any]] = []

    present = scanned = 0
    for rec in records:
        status = rec["status"]
        if status != "absent":
            present += 1
        if status == "scanned":
            scanned += 1
        rec_findings = rec.get("findings", []) if status == "scanned" else []
        for f in rec_findings:
            sev = _finding_severity(f)
            key = sev.lower()
            if key in by_severity:
                by_severity[key] += 1
            findings.append(_agent_finding_dict(f))

        entry = {
            "client": rec["client"],
            "scope": rec["scope"],
            "path": rec["path"],
            "status": status,
            "findings": len(rec_findings),
        }
        if rec.get("note"):
            entry["note"] = rec["note"]
        location_entries.append(entry)

    findings.sort(key=lambda d: _AGENT_SEVERITY_ORDER.get(d["severity"], 5))

    mc = str(min_confidence).strip().lower()
    if mc not in _VALID_CONFIDENCE:
        mc = "low"

    return {
        "schema_version": MCP_CONFIG_SCHEMA_VERSION,
        "tool": {"name": "shellockolm", "scanner": "agent", "mode": "check_mcp_config"},
        "scan": {
            "time": datetime.now().isoformat(),
            "system": system,
            "min_confidence": mc,
            "pro": bool(pro),
        },
        "summary": {
            "total_findings": len(findings),
            "by_severity": by_severity,
            "locations_checked": len(records),
            "locations_present": present,
            "locations_scanned": scanned,
        },
        "locations": location_entries,
        "findings": findings,
    }


# Per-status glyph for the human summary line.
_MCP_STATUS_GLYPH = {
    "scanned": "•",
    "absent": "·",
    "skipped": "⚠",
    "unreadable": "⚠",
}


def format_mcp_config_results(payload: Dict[str, Any]) -> str:
    """Render the check_mcp_config payload as a markdown summary + an embedded JSON block."""
    scan = payload["scan"]
    s = payload["summary"]
    bs = s["by_severity"]
    tier = "Pro" if scan.get("pro") else "Free"

    lines = [
        "# MCP Config Audit",
        "",
        (
            f"**System**: {scan['system']}  |  **Tier**: {tier}  |  "
            f"**Min confidence**: {scan['min_confidence']}"
        ),
        (
            f"**Configs**: {s['locations_present']} present / "
            f"{s['locations_checked']} known locations checked "
            f"({s['locations_scanned']} scanned)"
        ),
        (
            f"**Total findings**: {s['total_findings']}  "
            f"(CRITICAL {bs['critical']}, HIGH {bs['high']}, MEDIUM {bs['medium']}, "
            f"LOW {bs['low']}, INFO {bs['info']})"
        ),
        "",
        "## Locations",
    ]
    for loc in payload["locations"]:
        glyph = _MCP_STATUS_GLYPH.get(loc["status"], "·")
        if loc["status"] == "scanned":
            detail = (
                f"{loc['findings']} finding(s)"
                if loc["findings"]
                else "clean"
            )
        elif loc["status"] == "absent":
            detail = "not present"
        else:
            detail = f"{loc['status']}: {loc.get('note', '')}".strip().rstrip(":")
        lines.append(
            f"- {glyph} **{loc['client']}** ({loc['scope']}) — {detail}\n"
            f"  `{loc['path']}`"
        )

    if s["total_findings"] == 0:
        present_note = (
            "✅ **No threats in your installed MCP configs.**"
            if s["locations_present"]
            else "ℹ️ **No MCP config files found in the well-known locations.**"
        )
        lines += ["", present_note]
    else:
        lines += ["", "## Findings", ""]
        for f in payload["findings"]:
            conf = f.get("confidence", "high")
            conf_note = "" if conf == "high" else f" · confidence: {conf}"
            lines.append(
                f"- **[{f['severity']}] {f['id']}** "
                f"({f['attack_class']}, {f['tier']}{conf_note}) — {f['title']}\n"
                f"  `{f['file_path']}`\n"
                f"  _Fix_: {f['remediation']}"
            )

    lines += [
        "",
        "## Structured findings (JSON)",
        "```json",
        json.dumps(payload, indent=2, ensure_ascii=True),
        "```",
    ]
    return "\n".join(lines)


# ─────────────────────────────────────────────────────────────────
# EXPLAIN FINDING — the why / impact / remediation explainer (rule ID or CVE ID)
# ─────────────────────────────────────────────────────────────────

# Stable contract version for the explain_finding structured document. Mirrors the
# CLI's `rules explain --json` schema_version so an MCP client and the CLI agree.
EXPLAIN_SCHEMA_VERSION = "1.0"


def _cve_explain_dict(vuln) -> Dict[str, Any]:
    """JSON-safe explainer dict for a bundled CVE database entry.

    Defensive: enum-or-str fields are normalized via ``.value`` when present, and
    every optional list/flag is fetched with ``getattr`` so a future schema tweak
    can't make the explainer raise mid-call.
    """
    def _val(x) -> str:
        return (x.value if hasattr(x, "value") else str(x)) if x is not None else ""

    patched = dict(getattr(vuln, "patched_versions", {}) or {})
    if patched:
        remediation = (
            "Upgrade affected package(s) to a patched version: "
            + ", ".join(f"{k} -> {v}" for k, v in patched.items())
        )
    else:
        remediation = "Upgrade affected package(s) to a patched version."

    return {
        "id": vuln.cve_id,
        "title": vuln.title,
        "severity": _val(vuln.severity).upper(),
        "cvss": vuln.cvss_score,
        "vuln_type": _val(getattr(vuln, "vuln_type", None)),
        "exploit_difficulty": _val(getattr(vuln, "exploit_difficulty", None)),
        "packages": list(getattr(vuln, "packages", []) or []),
        "affected_versions": list(getattr(vuln, "affected_versions", []) or []),
        "patched_versions": patched,
        "description": vuln.description,
        "remediation": remediation,
        "references": list(getattr(vuln, "references", []) or []),
        "cisa_kev": bool(getattr(vuln, "cisa_kev", False)),
        "public_poc": bool(getattr(vuln, "public_poc", False)),
        "active_exploitation": bool(getattr(vuln, "active_exploitation", False)),
    }


def build_explain_payload(finding_id: str) -> Optional[Dict[str, Any]]:
    """Resolve a rule ID or CVE ID to a stable explainer document, or None if unknown.

    Single entry point that explains any Shellockolm finding: an agent supply-chain
    rule (``AGENT-*``, from ``scan_agent_artifacts``) via the shared
    ``agent_rule_explain`` catalog, or a bundled CVE (``CVE-*``) via the
    vulnerability database. Returns ``None`` when the ID matches neither — a clear
    "unknown" at the boundary, never a silently-empty explainer. Lookup is
    case-insensitive and whitespace-tolerant.
    """
    rid = (finding_id or "").strip()
    if not rid:
        return None

    # Agent supply-chain rule first (the flagship tool's findings); the catalog
    # lookup is itself case-insensitive and carries the example_attack deep-dive.
    from scanners.agent_supply_chain import agent_rule_explain

    rule = agent_rule_explain(rid)
    if rule is not None:
        return {
            "schema_version": EXPLAIN_SCHEMA_VERSION,
            "tool": "shellockolm",
            "kind": "agent-rule",
            "rule": rule,
        }

    # Fall back to the bundled CVE database (dependency / malware findings carry CVE ids).
    vuln = db.get_by_cve(rid.upper())
    if vuln is not None:
        return {
            "schema_version": EXPLAIN_SCHEMA_VERSION,
            "tool": "shellockolm",
            "kind": "cve",
            "cve": _cve_explain_dict(vuln),
        }

    return None


def format_explain_payload(payload: Dict[str, Any]) -> str:
    """Render an explainer payload as a markdown why/impact/remediation write-up plus
    an embedded JSON block (the machine-readable structured document)."""
    kind = payload.get("kind")
    lines: List[str] = []

    if kind == "agent-rule":
        r = payload["rule"]
        lines += [
            f"# {r['id']} — {r['title']}",
            "",
            (
                f"**Severity**: {r['severity']}  |  **Tier**: {r['tier']}  |  "
                f"**Confidence**: {r['confidence']}  |  **CVSS**: {r['cvss']}  |  "
                f"**Attack class**: {r['attack_class']}"
            ),
            "",
            "## Why it's flagged (impact)",
            r["description"],
        ]
        if r.get("example_attack"):
            lines += ["", "## Example attack", "```", r["example_attack"], "```"]
        lines += ["", "## Remediation", r["remediation"]]

    elif kind == "cve":
        c = payload["cve"]
        lines += [
            f"# {c['id']} — {c['title']}",
            "",
            (
                f"**Severity**: {c['severity']}  |  **CVSS**: {c['cvss']}  |  "
                f"**Type**: {c['vuln_type']}  |  **Exploit difficulty**: {c['exploit_difficulty']}"
            ),
            "",
            "## Why it's flagged (impact)",
            c["description"],
        ]
        if c["packages"]:
            lines += ["", f"**Affected packages**: {', '.join(c['packages'])}"]
        if c["patched_versions"]:
            patched = ", ".join(f"{k} -> {v}" for k, v in c["patched_versions"].items())
            lines += [f"**Patched**: {patched}"]
        flags = []
        if c["cisa_kev"]:
            flags.append("⚠️ CISA Known Exploited Vulnerability")
        if c["public_poc"]:
            flags.append("🔴 Public PoC available — exploitation is trivial")
        if c["active_exploitation"]:
            flags.append("🚨 Active exploitation in the wild")
        if flags:
            lines += ["", *[f"- {fl}" for fl in flags]]
        lines += ["", "## Remediation", c["remediation"]]
        if c["references"]:
            lines += ["", "## References", *[f"- {ref}" for ref in c["references"]]]

    lines += [
        "",
        "## Structured explanation (JSON)",
        "```json",
        json.dumps(payload, indent=2, ensure_ascii=True),
        "```",
    ]
    return "\n".join(lines)


def _is_blocked_ip(ip_str: str) -> bool:
    """Return True if an IP address is loopback, private, link-local, or otherwise
    not safe to fetch (SSRF protection)."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        # Not a parseable IP — treat as unsafe (can't validate it)
        return True

    return (
        ip.is_loopback        # 127.0.0.0/8, ::1
        or ip.is_private      # 10/8, 172.16/12, 192.168/16, fc00::/7, etc.
        or ip.is_link_local   # 169.254.0.0/16 (incl. 169.254.169.254 metadata), fe80::/10
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified  # 0.0.0.0, ::
    )


def check_ssrf_safety(url: str) -> Optional[str]:
    """Validate a URL against SSRF attacks.

    Rejects loopback, RFC1918 private ranges, and link-local addresses
    (including the cloud metadata IP 169.254.169.254). Resolves the hostname
    and checks the resolved IP too.

    Returns an error message string if the URL is unsafe, or None if it's allowed.
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return f"Error: could not parse URL '{url}'"

    hostname = parsed.hostname
    if not hostname:
        return f"Error: URL '{url}' has no host component"

    # Block obvious loopback hostnames before resolution
    if hostname.lower() in {"localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"}:
        return (
            f"Error: URL '{url}' is blocked for SSRF safety "
            "(loopback/localhost addresses are not allowed)."
        )

    # If the hostname is itself a literal IP, check it directly
    try:
        ipaddress.ip_address(hostname)
        if _is_blocked_ip(hostname):
            return (
                f"Error: URL '{url}' is blocked for SSRF safety "
                "(loopback/private/link-local address)."
            )
        return None
    except ValueError:
        pass  # Not a literal IP — resolve the hostname below

    # Resolve the hostname and validate the resolved IP
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        return f"Error: could not resolve host '{hostname}' for URL '{url}'."

    if _is_blocked_ip(resolved_ip):
        return (
            f"Error: URL '{url}' is blocked for SSRF safety. "
            f"Host '{hostname}' resolves to a loopback/private/link-local "
            f"address ({resolved_ip})."
        )

    return None


# ─────────────────────────────────────────────────────────────────
# RESOURCES
# ─────────────────────────────────────────────────────────────────

@server.list_resources()
async def handle_list_resources() -> list[types.Resource]:
    """List available CVE resources"""
    resources = []

    # Add CVE resources for all tracked vulnerabilities
    for vuln in db.get_all_vulnerabilities()[:20]:  # Limit to top 20 for readability
        resources.append(types.Resource(
            uri=f"cve://{vuln.cve_id.lower()}",
            name=f"{vuln.cve_id} - {vuln.title[:50]}",
            description=vuln.description[:100] + "...",
            mimeType="text/plain"
        ))

    return resources


@server.read_resource()
async def handle_read_resource(uri: str) -> str:
    """Read CVE details"""
    # The MCP framework hands this callback a parsed pydantic ``AnyUrl`` over the real
    # transport (string-only methods like .startswith/.replace fail on it), whereas the
    # internal ``get_cve_info`` path calls it with a plain ``str``. Coerce to ``str``
    # up front so both callers work — without this, every transport-level resource read
    # errored with "'AnyUrl' object has no attribute 'startswith'".
    uri = str(uri)
    if uri.startswith("cve://"):
        cve_id = uri.replace("cve://", "").upper()
        vuln = db.get_by_cve(cve_id)

        if not vuln:
            raise ValueError(f"Unknown CVE: {cve_id}")

        patched_str = ", ".join(f"{k}→{v}" for k, v in vuln.patched_versions.items())
        packages_str = ", ".join(vuln.packages)

        output = f"""# {vuln.cve_id}: {vuln.title}

**Severity**: {vuln.severity.value} (CVSS {vuln.cvss_score})
**Type**: {vuln.vuln_type.value}
**Packages**: {packages_str}
**Exploit Difficulty**: {vuln.exploit_difficulty.value}

## Description
{vuln.description}

## Affected Versions
{', '.join(vuln.affected_versions)}

## Patched Versions
{patched_str}

## Remediation
Upgrade affected packages to patched versions.

"""
        if vuln.references:
            output += "## References\n"
            for ref in vuln.references:
                output += f"- {ref}\n"

        if vuln.cisa_kev:
            output += f"\n⚠️ **CISA Known Exploited Vulnerability** (Added: {vuln.cisa_kev_date})\n"

        if vuln.public_poc:
            output += "\n🔴 **Public PoC Available** - Exploitation is trivial\n"

        if vuln.active_exploitation:
            output += "\n🚨 **Active Exploitation in the Wild**\n"

        return output

    raise ValueError(f"Unknown resource: {uri}")


# ─────────────────────────────────────────────────────────────────
# TOOLS
# ─────────────────────────────────────────────────────────────────

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List available scanning tools"""
    return [
        types.Tool(
            name="scan_agent_artifacts",
            description=(
                "FLAGSHIP — agents scanning agents: scan the AI-agent coding supply "
                "chain for agentic-era threats (prompt injection, secret exfiltration, "
                "tool poisoning, MCP/n8n abuse, auto-running hook RCE) across Claude / "
                "Cursor / Windsurf skills & SKILL.md, MCP configs (mcp.json), n8n workflow "
                "exports, slash commands, subagent definitions (.claude/agents/*.md), "
                "settings.json hooks, and CLAUDE.md / AGENTS.md / "
                ".cursorrules instruction files. Returns STRUCTURED findings (rule id, "
                "severity, confidence, attack class, file:line, remediation) plus a JSON "
                "document. Use this to vet a skill, MCP server, or agent repo BEFORE "
                "installing or trusting it."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory or single file path to scan for agent artifacts"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recursively scan subdirectories",
                        "default": True
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory depth to walk (prevents runaway/looping trees)",
                        "default": 10
                    },
                    "min_confidence": {
                        "type": "string",
                        "description": "Drop findings below this detection certainty: low | medium | high (default low keeps everything; high = structural/signature/secret only)",
                        "default": "low"
                    },
                    "quick_mode": {
                        "type": "boolean",
                        "description": "Skip the most expensive heuristics for a faster pass",
                        "default": False
                    },
                    "time_budget": {
                        "type": "number",
                        "description": "Wall-clock cap in seconds for the directory walk so a huge/hostile tree can't hang the call; on timeout it returns PARTIAL results with a warning (default 120; 0 = unbounded full scan)",
                        "default": 120
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="explain_finding",
            description=(
                "Explain ONE Shellockolm finding in depth — the why / impact / "
                "remediation companion to scan_agent_artifacts. Given a rule ID "
                "(e.g. AGENT-PI-013, AGENT-MCP-004 — from an agent-artifact scan) OR "
                "a CVE ID (e.g. CVE-2025-29927 — from a dependency/malware scan), "
                "returns the severity/tier/confidence/attack-class, the full "
                "description, a concrete EXAMPLE ATTACK, and the remediation, plus a "
                "stable JSON document. The ID is case-insensitive. Use this to "
                "understand a finding before acting on it."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "finding_id": {
                        "type": "string",
                        "description": (
                            "A rule ID (e.g. AGENT-PI-013) or a tracked CVE ID "
                            "(e.g. CVE-2025-29927) to explain"
                        )
                    }
                },
                "required": ["finding_id"]
            }
        ),
        types.Tool(
            name="scan_text",
            description=(
                "Scan a raw STRING for agentic-supply-chain threats WITHOUT touching "
                "disk — the in-memory sibling of scan_agent_artifacts. Pass the text "
                "of a skill / SKILL.md, MCP config (mcp.json), AI instruction file "
                "(CLAUDE.md / AGENTS.md / .cursorrules), n8n workflow export, "
                "settings.json hooks block, slash command, or subagent definition the "
                "agent is ABOUT to install or paste, and get back the same STRUCTURED findings (rule id, "
                "severity, confidence, attack class, line, remediation) + JSON "
                "document — before the content ever lands on disk. 'artifact_type' "
                "selects the detection path; the default 'auto' infers it from an "
                "optional 'filename' hint then the content shape. Pro rules respected "
                "as on the CLI."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "text": {
                        "type": "string",
                        "description": "The raw artifact content to scan (skill / MCP config / instruction / n8n / command text)"
                    },
                    "artifact_type": {
                        "type": "string",
                        "description": "Detection path: auto | skill | instructions | command | mcp | n8n | settings (default auto = infer from filename/content)",
                        "default": "auto"
                    },
                    "filename": {
                        "type": "string",
                        "description": "Optional virtual filename (e.g. SKILL.md, mcp.json) used to classify the text and label finding locations"
                    },
                    "min_confidence": {
                        "type": "string",
                        "description": "Drop findings below this detection certainty: low | medium | high (default low keeps everything)",
                        "default": "low"
                    },
                    "quick_mode": {
                        "type": "boolean",
                        "description": "Skip the most expensive heuristics for a faster pass",
                        "default": False
                    }
                },
                "required": ["text"]
            }
        ),
        types.Tool(
            name="check_mcp_config",
            description=(
                "Audit the CALLER'S OWN installed MCP server configs — scan the "
                "well-known mcp.json / config locations per OS (Claude Desktop, Claude "
                "Code's ~/.claude.json, Cursor, Windsurf, VS Code; plus this project's "
                ".mcp.json / .cursor/mcp.json / .vscode/mcp.json) for a poisoned server "
                "entry: code fetched from a raw-paste URL or public IP, a broad host "
                "credential forwarded to an unrelated server, or a curl|bash launcher. "
                "Reports which configs exist, which were scanned, and any STRUCTURED "
                "findings (rule id, severity, attack class, file, remediation) + a JSON "
                "document. Read-only; never modifies a config. Use this to check whether "
                "the agent's own MCP setup has been tampered with."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Project root for the project-scoped configs (.mcp.json, .cursor/mcp.json, .vscode/mcp.json). Defaults to the current working directory."
                    },
                    "include_user": {
                        "type": "boolean",
                        "description": "Check the per-user install configs under the home dir (Claude Desktop/Code, Cursor, Windsurf, VS Code)",
                        "default": True
                    },
                    "include_project": {
                        "type": "boolean",
                        "description": "Check the project-scoped configs under 'path'",
                        "default": True
                    },
                    "min_confidence": {
                        "type": "string",
                        "description": "Drop findings below this detection certainty: low | medium | high (default low keeps everything)",
                        "default": "low"
                    }
                }
            }
        ),
        types.Tool(
            name="find_packages",
            description="FAST: Find npm packages (package.json files) in a directory. By default excludes node_modules (40x faster). Returns list in ~0.1 seconds. Use this when user asks to 'find' or 'list' packages.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to search"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Search subdirectories recursively",
                        "default": True
                    },
                    "include_node_modules": {
                        "type": "boolean",
                        "description": "Include node_modules folders (WARNING: Very slow, searches 1000s of dependency files. Usually not needed.)",
                        "default": False
                    },
                    "max_depth": {
                        "type": "integer",
                        "description": "Maximum directory depth to search (prevents infinite recursion)",
                        "default": 3
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="quick_scan",
            description="MEDIUM SPEED: Quick CVE scan of npm packages (2-3 minutes). Only checks package.json/lock files against CVE database. Skips deep file analysis, malware detection, and secrets scanning. Use when user wants fast vulnerability check.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to scan"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recursively scan subdirectories",
                        "default": True
                    },
                    "exclude_node_modules": {
                        "type": "boolean",
                        "description": (
                            "Skip node_modules folders (scans projects only, not dependencies). "
                            "Always applied: the scanners exclude node_modules unconditionally, "
                            "so passing false does not widen the scan — the result says so."
                        ),
                        "default": True
                    },
                    "scanner": {
                        "type": "string",
                        "description": f"Specific scanner to use (optional): {', '.join(SCANNER_REGISTRY.keys())}",
                        "default": None
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="scan_directory",
            description="SLOW BUT THOROUGH: Deep security scan (10+ minutes for large codebases). Scans for CVEs, malware, secrets, obfuscation, backdoors. Use only when user explicitly asks for 'deep scan', 'full scan', or 'complete security audit'.",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory path to scan"
                    },
                    "recursive": {
                        "type": "boolean",
                        "description": "Recursively scan subdirectories",
                        "default": True
                    },
                    "scanner": {
                        "type": "string",
                        "description": f"Specific scanner to use (optional): {', '.join(SCANNER_REGISTRY.keys())}",
                        "default": None
                    },
                    "exclude_node_modules": {
                        "type": "boolean",
                        "description": (
                            "Skip node_modules folders. Always applied: the scanners exclude "
                            "node_modules unconditionally, so passing false does not widen the "
                            "scan — the result says so."
                        ),
                        "default": True
                    }
                },
                "required": ["path"]
            }
        ),
        types.Tool(
            name="scan_live",
            description="Live probe a URL for exploitable vulnerabilities (Next.js middleware bypass, n8n RCE)",
            inputSchema={
                "type": "object",
                "properties": {
                    "url": {
                        "type": "string",
                        "description": "URL to probe"
                    },
                    "scanner": {
                        "type": "string",
                        "description": "Scanner to use: nextjs, n8n, or all",
                        "default": "all"
                    },
                    "timeout": {
                        "type": "integer",
                        "description": "Request timeout in seconds",
                        "default": 10
                    }
                },
                "required": ["url"]
            }
        ),
        types.Tool(
            name="get_cve_info",
            description="Get detailed information about a specific CVE",
            inputSchema={
                "type": "object",
                "properties": {
                    "cve_id": {
                        "type": "string",
                        "description": "CVE ID (e.g., CVE-2025-29927)"
                    }
                },
                "required": ["cve_id"]
            }
        ),
        types.Tool(
            name="list_cves",
            description="List all tracked CVEs with optional filtering",
            inputSchema={
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "description": "Filter by severity: critical, high, medium, low",
                        "default": None
                    },
                    "category": {
                        "type": "string",
                        "description": "Filter by category: react, nextjs, nodejs, npm, n8n, supply-chain",
                        "default": None
                    }
                }
            }
        ),
        types.Tool(
            name="list_scanners",
            description="List all available vulnerability scanners and their coverage",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        ),
        types.Tool(
            name="generate_report",
            description="Generate a comprehensive JSON vulnerability report",
            inputSchema={
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "Directory to scan"
                    },
                    "output_path": {
                        "type": "string",
                        "description": "Path to save JSON report (optional)"
                    }
                },
                "required": ["path"]
            }
        ),
    ]


@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Handle tool execution"""

    # Guard against clients sending null params (e.g. JSON-RPC params: null)
    arguments = arguments or {}

    if name == "scan_agent_artifacts":
        path = arguments.get("path", ".")
        recursive = arguments.get("recursive", True)
        min_confidence = arguments.get("min_confidence", "low")
        quick_mode = arguments.get("quick_mode", False)

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        # Validate min_confidence at the boundary so a typo is a clear error, never a
        # silently-wrong scan (mirrors the CLI's --min-confidence handling).
        if str(min_confidence).strip().lower() not in _VALID_CONFIDENCE:
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Invalid min_confidence: {min_confidence!r}. "
                    "Use one of: low, medium, high."
                )
            )]

        # max_depth may arrive as a string from a loose client; coerce defensively.
        try:
            max_depth = int(arguments.get("max_depth", 10))
        except (TypeError, ValueError):
            return [types.TextContent(
                type="text",
                text=f"❌ Invalid max_depth: {arguments.get('max_depth')!r}. Must be an integer."
            )]

        # Rate/size safety: bound the walk so a pathological/hostile tree can't hang the
        # call. Defaults to DEFAULT_AGENT_SCAN_TIME_BUDGET; a client may raise it or pass
        # 0 for an unbounded full scan. A non-numeric value is a clear boundary error.
        try:
            time_budget = float(arguments.get("time_budget", DEFAULT_AGENT_SCAN_TIME_BUDGET))
        except (TypeError, ValueError):
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Invalid time_budget: {arguments.get('time_budget')!r}. "
                    "Must be a number of seconds (0 = unbounded)."
                )
            )]
        # 0 / negative → unbounded (explicit opt-out of the cap).
        time_budget = time_budget if time_budget > 0 else None

        from scanners.agent_supply_chain import AgentSupplyChainScanner

        # Pro rules are gated by the active license, resolved inside the scanner's
        # __init__ exactly as the CLI does — free tier still gets every free rule.
        scanner = AgentSupplyChainScanner()
        try:
            result = scanner.scan_directory(
                path,
                recursive=bool(recursive),
                max_depth=max_depth,
                quick_mode=bool(quick_mode),
                min_confidence=str(min_confidence),
                time_budget=time_budget,
            )
        except Exception as e:
            return [types.TextContent(type="text", text=f"❌ Error scanning agent artifacts: {e}")]

        payload = build_agent_scan_payload(
            result,
            target=str(Path(path).resolve()),
            min_confidence=str(min_confidence),
            pro=scanner.pro,
        )
        return [types.TextContent(type="text", text=format_agent_scan_results(payload))]

    if name == "explain_finding":
        finding_id = arguments.get("finding_id", "")

        # Validate the required field at the boundary so a missing/blank id is a
        # clear error, never a silently-empty explainer.
        if not isinstance(finding_id, str) or not finding_id.strip():
            return [types.TextContent(
                type="text",
                text=(
                    "❌ Error: 'finding_id' is required (a rule ID like "
                    "AGENT-PI-013 or a CVE ID like CVE-2025-29927)."
                )
            )]

        payload = build_explain_payload(finding_id)
        if payload is None:
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Unknown finding ID: {finding_id!r}. Expected an agent rule "
                    "ID (AGENT-*) or a tracked CVE ID (CVE-*). Use list_cves or run "
                    "'shellockolm rules list' to see valid IDs."
                )
            )]

        return [types.TextContent(type="text", text=format_explain_payload(payload))]

    if name == "scan_text":
        text = arguments.get("text")
        artifact_type = arguments.get("artifact_type", "auto")
        filename = arguments.get("filename")
        min_confidence = arguments.get("min_confidence", "low")
        quick_mode = arguments.get("quick_mode", False)

        # The raw artifact string is the one required field — a missing/blank value is
        # a clear error, never a silently-empty scan.
        if not isinstance(text, str) or not text.strip():
            return [types.TextContent(
                type="text",
                text="❌ Error: 'text' is required (the raw artifact string to scan)."
            )]

        from scanners.agent_supply_chain import AgentSupplyChainScanner

        # Validate the selector at the boundary so a typo is a clear error.
        valid_types = AgentSupplyChainScanner.TEXT_ARTIFACT_TYPES
        at = str(artifact_type).strip().lower()
        if at not in valid_types:
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Invalid artifact_type: {artifact_type!r}. "
                    f"Use one of: {', '.join(sorted(valid_types))}."
                )
            )]

        if str(min_confidence).strip().lower() not in _VALID_CONFIDENCE:
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Invalid min_confidence: {min_confidence!r}. "
                    "Use one of: low, medium, high."
                )
            )]

        if filename is not None and not isinstance(filename, str):
            return [types.TextContent(
                type="text",
                text=f"❌ Invalid filename: {filename!r}. Must be a string."
            )]

        # Pro rules gated by the active license inside __init__, exactly as the CLI.
        scanner = AgentSupplyChainScanner()
        try:
            result = scanner.scan_text(
                text,
                artifact_type=at,
                filename=filename,
                quick_mode=bool(quick_mode),
                min_confidence=str(min_confidence),
            )
        except Exception as e:
            return [types.TextContent(type="text", text=f"❌ Error scanning text: {e}")]

        # Reuse the flagship structured payload so scan_text and scan_agent_artifacts
        # share one contract; label the target by filename or the resolved kind.
        resolved = result.stats.get("artifact_type", at)
        target = filename if filename else f"<text:{resolved}>"
        payload = build_agent_scan_payload(
            result, target=target, min_confidence=str(min_confidence), pro=scanner.pro
        )
        # Additive field (schema 1.0 only grows): surface what "auto" resolved to.
        payload["scan"]["artifact_type"] = resolved
        return [types.TextContent(type="text", text=format_agent_scan_results(payload))]

    if name == "check_mcp_config":
        include_user = arguments.get("include_user", True)
        include_project = arguments.get("include_project", True)
        min_confidence = arguments.get("min_confidence", "low")
        path = arguments.get("path")

        # Validate min_confidence at the boundary (mirrors the other agent tools).
        if str(min_confidence).strip().lower() not in _VALID_CONFIDENCE:
            return [types.TextContent(
                type="text",
                text=(
                    f"❌ Invalid min_confidence: {min_confidence!r}. "
                    "Use one of: low, medium, high."
                )
            )]

        # The project root for project-scoped configs; default to the server's cwd.
        if path is not None and not isinstance(path, str):
            return [types.TextContent(
                type="text",
                text=f"❌ Invalid path: {path!r}. Must be a string."
            )]
        project_root = Path(path) if path else Path.cwd()

        import platform as _platform
        from mcp_config_locations import known_mcp_config_locations

        locations = known_mcp_config_locations(
            project_root=project_root,
            include_user=bool(include_user),
            include_project=bool(include_project),
        )

        try:
            records, pro = scan_known_mcp_configs(
                locations, min_confidence=str(min_confidence)
            )
        except Exception as e:
            return [types.TextContent(type="text", text=f"❌ Error checking MCP configs: {e}")]

        payload = build_mcp_config_payload(
            records,
            system=_platform.system(),
            min_confidence=str(min_confidence),
            pro=pro,
        )
        return [types.TextContent(type="text", text=format_mcp_config_results(payload))]

    if name == "find_packages":
        path = arguments.get("path", ".")
        recursive = arguments.get("recursive", True)
        include_node_modules = arguments.get("include_node_modules", False)
        max_depth = arguments.get("max_depth", 3)

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        start_time = datetime.now()

        # Caps to keep the tool fast and bounded
        MAX_RESULTS = 500
        MAX_PACKAGE_JSON_BYTES = 1_000_000  # skip reading package.json files > 1MB

        # Directories to prune during the walk (cross-platform, no shell)
        prune_dirs = {".git", ".svn", ".hg", "__pycache__", "dist", "build",
                      ".next", ".nuxt"}
        if not include_node_modules:
            prune_dirs.add("node_modules")

        root = Path(path).resolve()
        root_depth = len(root.parts)

        packages: List[str] = []
        truncated = False

        try:
            for dirpath, dirnames, filenames in os.walk(root):
                # Enforce max_depth relative to the root
                current_depth = len(Path(dirpath).parts) - root_depth
                if current_depth >= max_depth:
                    # Don't descend any deeper
                    dirnames[:] = []
                elif not recursive:
                    # Non-recursive: only inspect the top-level directory
                    dirnames[:] = []

                # Prune excluded directories in-place so os.walk skips them
                dirnames[:] = [d for d in dirnames if d not in prune_dirs]

                if "package.json" in filenames:
                    packages.append(str(Path(dirpath) / "package.json"))
                    if len(packages) >= MAX_RESULTS:
                        truncated = True
                        break
        except Exception as e:
            return [types.TextContent(type="text", text=f"❌ Error finding packages: {e}")]

        duration = (datetime.now() - start_time).total_seconds()

        # Extract package info (cap individual reads)
        package_list = []
        for pkg_path in packages:
            try:
                if os.path.getsize(pkg_path) > MAX_PACKAGE_JSON_BYTES:
                    package_list.append({
                        "name": "unknown (file too large)",
                        "version": "unknown",
                        "path": pkg_path
                    })
                    continue
                with open(pkg_path, 'r', encoding='utf-8', errors='ignore') as f:
                    data = json.load(f)
                    package_list.append({
                        "name": data.get("name", "unknown"),
                        "version": data.get("version", "unknown"),
                        "path": pkg_path
                    })
            except Exception:
                package_list.append({
                    "name": "unknown",
                    "version": "unknown",
                    "path": pkg_path
                })

        output = f"""# Package Discovery Results

## Summary
- **Total packages found**: {len(packages)}{' (capped)' if truncated else ''}
- **Search time**: {duration:.2f}s
- **Excluded node_modules**: {not include_node_modules}
- **Max depth**: {max_depth}

## Packages
"""

        for pkg in package_list:
            output += f"\n- **{pkg['name']}** @ {pkg['version']}\n  `{pkg['path']}`"

        if truncated:
            output += f"\n\n... result list capped at {MAX_RESULTS} packages. Narrow the path or reduce max_depth to see more."

        return [types.TextContent(type="text", text=output)]

    elif name == "quick_scan":
        path = arguments.get("path", ".")
        recursive = arguments.get("recursive", True)
        exclude_node_modules = normalize_exclude_node_modules(
            arguments.get("exclude_node_modules", True)
        )
        scanner_name = arguments.get("scanner")

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        output = "# Quick CVE Scan Results\n\n"
        output += node_modules_scope_note(exclude_node_modules)
        output += "**Mode**: Quick scan (package.json + lock files only)\n"
        output += "**Speed**: Skipping deep file analysis, malware detection, and secrets scanning\n\n"
        
        # Get scanners
        results: List[ScanResult] = []
        
        if scanner_name:
            if scanner_name not in SCANNER_REGISTRY:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Unknown scanner: {scanner_name}\nAvailable: {', '.join(SCANNER_REGISTRY.keys())}"
                )]
            scanners = [get_scanner(scanner_name)]
        else:
            scanners = get_all_scanners()
        
        # Quick scan mode: Pass quick_mode=True only to scanners that accept it.
        # Use an explicit signature check rather than catching TypeError so that
        # genuine TypeErrors raised *inside* a scanner propagate instead of being
        # masked by a silent full re-scan.
        for s in scanners:
            try:
                sig = inspect.signature(s.scan_directory)
                supports_quick = "quick_mode" in sig.parameters
            except (TypeError, ValueError):
                supports_quick = False

            if supports_quick:
                result = s.scan_directory(path, recursive=recursive, quick_mode=True)
            else:
                result = s.scan_directory(path, recursive=recursive)
            results.append(result)
        
        output += format_scan_results(results)
        
        return [types.TextContent(type="text", text=output)]

    elif name == "scan_directory":
        path = arguments.get("path", ".")
        recursive = arguments.get("recursive", True)
        scanner_name = arguments.get("scanner")
        exclude_node_modules = normalize_exclude_node_modules(
            arguments.get("exclude_node_modules", True)
        )

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        output = "# Deep Security Scan\n\n"
        output += node_modules_scope_note(exclude_node_modules)
        output += "**Note**: Deep scan mode - analyzing all files for CVEs, malware, secrets, and backdoors.\n"
        output += "This may take 10+ minutes for large codebases.\n\n"
        
        results: List[ScanResult] = []

        if scanner_name:
            if scanner_name not in SCANNER_REGISTRY:
                return [types.TextContent(
                    type="text",
                    text=f"❌ Unknown scanner: {scanner_name}\nAvailable: {', '.join(SCANNER_REGISTRY.keys())}"
                )]
            scanners = [get_scanner(scanner_name)]
        else:
            scanners = get_all_scanners()

        for s in scanners:
            result = s.scan_directory(path, recursive=recursive)
            results.append(result)

        output += format_scan_results(results)
        return [types.TextContent(type="text", text=output)]

    elif name == "scan_live":
        url = arguments.get("url")
        scanner_name = arguments.get("scanner", "all")
        timeout = arguments.get("timeout", 10)

        # Validate required field before using it (avoid AttributeError on None)
        if not url or not isinstance(url, str):
            return [types.TextContent(type="text", text="❌ Error: 'url' is required")]

        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        # SSRF guard: reject loopback / private / link-local (cloud metadata) targets
        ssrf_error = check_ssrf_safety(url)
        if ssrf_error:
            return [types.TextContent(type="text", text=f"❌ {ssrf_error}")]

        results: List[ScanResult] = []
        output = f"# Live Probe Results for {url}\n\n"

        if scanner_name in ["nextjs", "all"]:
            try:
                from scanners.nextjs import NextJSScanner
                s = NextJSScanner()
                result = s.scan_live(url, timeout=timeout)
                results.append(result)

                if result.stats.get("nextjs_detected"):
                    output += f"✓ **Next.js detected** (v{result.stats.get('detected_version', 'unknown')})\n"
                else:
                    output += "• Next.js not detected\n"
            except Exception as e:
                output += f"✗ Next.js probe failed: {e}\n"

        if scanner_name in ["n8n", "all"]:
            try:
                from scanners.n8n import N8NScanner
                s = N8NScanner()
                result = s.scan_live(url, timeout=timeout)
                results.append(result)

                if result.stats.get("n8n_detected"):
                    output += f"✓ **n8n detected** (v{result.stats.get('detected_version', 'unknown')})\n"
                else:
                    output += "• n8n not detected\n"
            except Exception as e:
                output += f"✗ n8n probe failed: {e}\n"

        output += "\n"
        output += format_scan_results(results)
        return [types.TextContent(type="text", text=output)]

    elif name == "get_cve_info":
        cve_id = arguments.get("cve_id", "").upper()
        vuln = db.get_by_cve(cve_id)

        if not vuln:
            return [types.TextContent(
                type="text",
                text=f"❌ CVE not found: {cve_id}\n\nUse list_cves to see all tracked CVEs."
            )]

        # Return the resource content
        return [types.TextContent(
            type="text",
            text=await handle_read_resource(f"cve://{cve_id.lower()}")
        )]

    elif name == "list_cves":
        severity = arguments.get("severity")
        category = arguments.get("category")

        vulns = db.get_all_vulnerabilities()

        # Apply filters
        if severity:
            sev_upper = severity.upper()
            vulns = [v for v in vulns if v.severity.value.upper() == sev_upper]

        if category:
            cat_map = {
                "react": db.REACT_RSC_VULNERABILITIES,
                "nextjs": db.NEXTJS_VULNERABILITIES,
                "nodejs": db.NODEJS_VULNERABILITIES,
                "npm": db.NPM_PACKAGE_VULNERABILITIES,
                "n8n": db.N8N_VULNERABILITIES,
                "supply-chain": db.SUPPLY_CHAIN_VULNERABILITIES,
            }
            if category in cat_map:
                vulns = cat_map[category]

        output = "# Shellockolm CVE Database\n\n"
        output += f"**Total CVEs**: {len(vulns)}\n\n"
        output += "| CVE ID | Severity | CVSS | Package | Title |\n"
        output += "|--------|----------|------|---------|-------|\n"

        for v in vulns:
            pkg = ", ".join(v.packages[:2])
            if len(v.packages) > 2:
                pkg += "..."
            title = v.title[:40] + "..." if len(v.title) > 40 else v.title
            output += f"| {v.cve_id} | {v.severity.value} | {v.cvss_score} | {pkg} | {title} |\n"

        return [types.TextContent(type="text", text=output)]

    elif name == "list_scanners":
        output = "# Shellockolm Scanners\n\n"
        output += "| Scanner | Description | CVEs | Live Scan |\n"
        output += "|---------|-------------|------|----------|\n"

        total_cves = 0
        for name, scanner_class in SCANNER_REGISTRY.items():
            s = scanner_class()
            has_live = hasattr(s, 'scan_live')
            total_cves += len(s.CVE_IDS)
            output += f"| {name} | {s.DESCRIPTION} | {len(s.CVE_IDS)} | {'✓' if has_live else ''} |\n"

        output += f"\n**Total**: {len(SCANNER_REGISTRY)} scanners covering {total_cves} CVEs\n"
        return [types.TextContent(type="text", text=output)]

    elif name == "generate_report":
        path = arguments.get("path", ".")
        output_path = arguments.get("output_path")

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        results: List[ScanResult] = []
        for s in get_all_scanners():
            result = s.scan_directory(path, recursive=True)
            results.append(result)

        # Build JSON report
        report = {
            "scan_time": datetime.now().isoformat(),
            "target": str(Path(path).resolve()),
            "total_findings": sum(len(r.findings) for r in results),
            "summary": {
                "critical": sum(1 for r in results for f in r.findings
                               if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "CRITICAL"),
                "high": sum(1 for r in results for f in r.findings
                           if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "HIGH"),
                "medium": sum(1 for r in results for f in r.findings
                             if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "MEDIUM"),
                "low": sum(1 for r in results for f in r.findings
                          if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "LOW"),
            },
            "results": []
        }

        for r in results:
            result_dict = {
                "scanner": r.scanner_name,
                "target": r.target,
                "findings": [
                    {
                        "cve_id": f.cve_id,
                        "title": f.title,
                        "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                        "cvss_score": f.cvss_score,
                        "package": f.package,
                        "version": f.version,
                        "patched_version": f.patched_version,
                        "file_path": f.file_path,
                        "description": f.description,
                        "remediation": f.remediation,
                        "exploit_difficulty": f.exploit_difficulty,
                        "references": f.references or [],
                    }
                    for f in r.findings
                ],
                "stats": r.stats,
                "errors": r.errors,
            }
            report["results"].append(result_dict)

        json_output = json.dumps(report, indent=2)

        # Build a compact summary so we never blow up the context with a full dump.
        summary_text = (
            f"## Report Summary\n"
            f"- **Target**: {report['target']}\n"
            f"- **Scan time**: {report['scan_time']}\n"
            f"- **Total findings**: {report['total_findings']}\n"
            f"- **Critical**: {report['summary']['critical']}\n"
            f"- **High**: {report['summary']['high']}\n"
            f"- **Medium**: {report['summary']['medium']}\n"
            f"- **Low**: {report['summary']['low']}\n"
        )

        # Resolve the destination. Default to a temp reports dir rather than
        # trusting a model-supplied write-anywhere path. If output_path is given,
        # resolve it (so relative/.. paths are normalized) before writing.
        reports_dir = Path(tempfile.gettempdir()) / "shellockolm" / "reports"
        if output_path:
            dest = Path(output_path).expanduser().resolve()
        else:
            reports_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = reports_dir / f"shellockolm_report_{timestamp}.json"

        try:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(json_output, encoding="utf-8")
        except OSError as e:
            # If we can't write the requested path, fall back to the temp reports dir.
            reports_dir.mkdir(parents=True, exist_ok=True)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            dest = reports_dir / f"shellockolm_report_{timestamp}.json"
            dest.write_text(json_output, encoding="utf-8")
            summary_text += f"\n⚠️ Could not write to requested path ({e}); saved to temp dir instead.\n"

        return [types.TextContent(
            type="text",
            text=(
                f"✅ Report saved to: {dest}\n\n"
                f"{summary_text}\n"
                f"_Full JSON written to file above. Inline preview (truncated):_\n\n"
                f"```json\n{json_output[:2000]}{'...' if len(json_output) > 2000 else ''}\n```"
            )
        )]

    raise ValueError(f"Unknown tool: {name}")


async def main():
    """Main entry point for the MCP server"""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="shellockolm",
                server_version="3.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


def run():
    """Console-script entry point (e.g. `shellockolm-mcp`). Launches the server."""
    asyncio.run(main())


if __name__ == "__main__":
    run()
