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


def _finding_severity(finding) -> str:
    """Normalize a finding's severity to an UPPERCASE string (enum or str safe)."""
    sev = finding.severity
    return (sev.value if hasattr(sev, "value") else str(sev)).upper()


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
    # Imported lazily so the module's import surface stays light and the helper is
    # patchable in tests; the scanner package is already a hard dependency.
    from scanners.agent_supply_chain import agent_rule_class, agent_rule_tier

    by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    findings: List[Dict[str, Any]] = []
    for f in result.findings:
        sev = _finding_severity(f)
        key = sev.lower()
        if key in by_severity:
            by_severity[key] += 1
        # For the agent scanner the finding's ``cve_id`` field carries the AGENT-* rule id.
        rule_id = f.cve_id
        findings.append({
            "id": rule_id,
            "title": f.title,
            "severity": sev,
            "confidence": getattr(f, "confidence", "high"),
            "attack_class": agent_rule_class(rule_id),
            "tier": agent_rule_tier(rule_id),
            "cvss_score": f.cvss_score,
            # file_path carries the ``<path>:<line>`` / ``<path> » server:<name>`` locator
            # exactly as the CLI emits it, so callers can resolve the artifact + line.
            "file_path": f.file_path,
            "description": f.description,
            "remediation": f.remediation,
        })

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
                "exports, slash commands, settings.json hooks, and CLAUDE.md / AGENTS.md / "
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
                    }
                },
                "required": ["path"]
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
                        "description": "Skip node_modules folders (scans projects only, not dependencies)",
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
                        "description": "Skip node_modules folders",
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
        exclude_node_modules = arguments.get("exclude_node_modules", True)
        scanner_name = arguments.get("scanner")
        
        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]
        
        output = "# Quick CVE Scan Results\n\n"
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
        exclude_node_modules = arguments.get("exclude_node_modules", True)

        if not Path(path).exists():
            return [types.TextContent(type="text", text=f"❌ Path does not exist: {path}")]

        output = "# Deep Security Scan\n\n"
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
                server_version="3.0.0",
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
