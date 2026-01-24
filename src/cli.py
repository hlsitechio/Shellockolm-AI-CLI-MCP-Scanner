#!/usr/bin/env python3
"""
Shellockolm - Security Detective CLI
Unified command-line interface for all CVE scanners

Usage:
    shellockolm scan [PATH]                 # Run all scanners
    shellockolm scan --scanner react [PATH] # Run specific scanner
    shellockolm live URL                    # Live probe a URL
    shellockolm cves                        # List all CVEs
    shellockolm info CVE-ID                 # Get CVE details
"""

import sys
import json
import os
from pathlib import Path
from typing import Optional, List
from datetime import datetime
from io import StringIO

try:
    import typer
except ImportError:
    print("Error: typer not installed. Run: pip install typer[all]")
    sys.exit(1)

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.theme import Theme
from rich.progress import Progress, SpinnerColumn, TextColumn

# Import scanners
from scanners import (
    SCANNER_REGISTRY,
    get_all_scanners,
    get_scanner,
    ScanResult,
    ScanFinding,
)
from vulnerability_database import VulnerabilityDatabase, Severity
from malware_analyzer import MalwareAnalyzer, ThreatLevel
from secrets_scanner import SecretsScanner
from security_score import SecurityScoreCalculator
from auto_fix import AutoFixer
from lockfile_analyzer import LockfileAnalyzer
from sarif_output import SarifGenerator, SarifResult
from github_advisory import GitHubAdvisoryDB, AdvisorySeverity
from npm_audit import NpmAuditWrapper, NpmAuditSeverity
from sbom_generator import SBOMGenerator, SBOMFormat
from dependency_tree import DependencyTreeVisualizer, OutputFormat as TreeOutputFormat
from ignore_handler import IgnoreHandler
from github_actions import GitHubActionsGenerator, WorkflowConfig, ScanLevel, TriggerType
from watch_mode import WatchMode, WatchConfig
from context_intelligence import (
    analyze_finding as analyze_finding_context,
    detect_path_context,
    PathContext,
    format_actionable_tips,
    get_quick_fix_summary,
)

# ─────────────────────────────────────────────────────────────────
# SESSION LOGGING
# ─────────────────────────────────────────────────────────────────
class SessionLogger:
    """Logs all scans and recon operations to session files"""

    LOG_DIR = Path("/tmp/shellockolm/sessions")

    def __init__(self):
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.log_dir = self.LOG_DIR
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_file = self.log_dir / f"session_{self.session_id}.log"
        self.findings_file = self.log_dir / f"findings_{self.session_id}.json"
        self.all_findings = []
        self._init_session()

    def _init_session(self):
        """Initialize session log file"""
        header = f"""
================================================================================
SHELLOCKOLM SESSION LOG
================================================================================
Session ID:  {self.session_id}
Started:     {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
Log File:    {self.log_file}
Findings:    {self.findings_file}
================================================================================

"""
        self.log_file.write_text(header)

    def log(self, message: str, level: str = "INFO"):
        """Log a message with timestamp"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        entry = f"[{timestamp}] [{level}] {message}\n"
        with open(self.log_file, "a") as f:
            f.write(entry)

    def log_command(self, command: str, description: str = ""):
        """Log a command execution"""
        self.log(f"COMMAND: {command}", "CMD")
        if description:
            self.log(f"  Description: {description}", "CMD")
        self.log("-" * 60, "CMD")

    def log_scan_start(self, scanner: str, target: str):
        """Log scan start"""
        self.log(f"SCAN START: {scanner} -> {target}", "SCAN")

    def log_scan_result(self, scanner: str, findings_count: int, duration: float):
        """Log scan completion"""
        self.log(f"SCAN COMPLETE: {scanner} | Findings: {findings_count} | Duration: {duration:.2f}s", "SCAN")

    def log_finding(self, finding: dict):
        """Log a vulnerability finding"""
        self.all_findings.append(finding)
        self.log(f"FINDING: {finding.get('cve_id', 'N/A')} | {finding.get('severity', 'N/A')} | {finding.get('title', 'N/A')}", "VULN")
        self.log(f"  File: {finding.get('file_path', 'N/A')}", "VULN")
        self.log(f"  Package: {finding.get('package', 'N/A')} @ {finding.get('version', 'N/A')}", "VULN")
        # Update findings JSON
        self._save_findings()

    def log_live_probe(self, url: str, scanner: str):
        """Log live recon probe"""
        self.log(f"LIVE PROBE: {scanner} -> {url}", "RECON")

    def log_summary(self, total_findings: int, critical: int, high: int, duration: float):
        """Log scan summary"""
        summary = f"""
================================================================================
SESSION SUMMARY
================================================================================
Total Findings: {total_findings}
Critical:       {critical}
High:           {high}
Duration:       {duration:.2f}s
================================================================================
"""
        with open(self.log_file, "a") as f:
            f.write(summary)

    def _save_findings(self):
        """Save findings to JSON file"""
        output = {
            "session_id": self.session_id,
            "timestamp": datetime.now().isoformat(),
            "total_findings": len(self.all_findings),
            "findings": self.all_findings
        }
        with open(self.findings_file, "w") as f:
            json.dump(output, f, indent=2)

    def get_log_path(self) -> str:
        return str(self.log_file)

    def get_findings_path(self) -> str:
        return str(self.findings_file)


# Global session logger (initialized in interactive_shell)
session_logger: Optional[SessionLogger] = None


# Dark theme for Shellockolm
dark_theme = Theme({
    "info": "bright_cyan",
    "warning": "bright_yellow",
    "danger": "bright_red bold",
    "success": "bright_green",
    "highlight": "bright_magenta",
    "path": "bright_blue",
    "command": "bright_green italic",
    "title": "bold bright_white",
    "subtitle": "bright_cyan italic",
    "detective": "bright_yellow bold",
    "critical": "bold bright_red on dark_red",
    "high": "bright_red",
    "medium": "bright_yellow",
    "low": "bright_blue",
})

console = Console(theme=dark_theme)
app = typer.Typer(
    name="shellockolm",
    help="Security Detective for React, Next.js, Node.js & npm CVEs",
    no_args_is_help=True,
    rich_markup_mode="rich",
)


def get_username():
    """Get current username"""
    import getpass
    return getpass.getuser().capitalize()


def get_random_tip():
    """Get a random security tip"""
    import random
    tips = [
        "Use 'shellockolm scan .' to scan current directory",
        "Try '--bounty' flag to see bug bounty targets",
        "Live probe URLs with 'shellockolm live URL'",
        "Export findings to JSON with '-o report.json'",
        "Press 'l' in menu to view session logs",
        "CVE-2025-29927 is a critical Next.js bypass",
        "Check for supply chain attacks with scanner #7",
        "Use '-s react' to scan only React CVEs",
        "Session logs saved in /tmp/shellockolm/",
        "Run 'shellockolm cves -s critical' for high priority",
        "Use [17] Deep Scan to find malware in node_modules",
        "Quarantine suspicious files before investigating",
        "Shai-Hulud worm spreads via npm install hooks",
        "Check for typosquatting attacks: recat vs react",
        "Use [23] Secrets Scan to find exposed API keys",
        "Calculate your security grade with [27] Score",
        "Auto-fix vulnerable packages with [30] Fix Vulns",
        "Preview fixes before applying with [31] Preview",
        "[25] Entropy scan finds unknown secret formats",
        "Check .env files for exposed secrets with [24]",
    ]
    return random.choice(tips)


def print_banner(show_full: bool = True):
    """Print Shellockolm banner with detective ASCII art"""
    username = get_username()
    now = datetime.now()
    date_str = now.strftime("%a %b %d, %Y")
    time_str = now.strftime("%H:%M:%S")

    if show_full:
        # Shellockolm ASCII title
        banner_art = """
[bold bright_yellow]     _____ __         ____            __         __
    / ___// /_  ___  / / /___  _____/ /______  / /___ ___
    \\__ \\/ __ \\/ _ \\/ / / __ \\/ ___/ //_/ __ \\/ / __ `__ \\
   ___/ / / / /  __/ / / /_/ / /__/ ,< / /_/ / / / / / / /
  /____/_/ /_/\\___/_/_/\\____/\\___/_/|_|\\____/_/_/ /_/ /_/[/bold bright_yellow]
[dim]              ═══ Security Detective for npm/Node.js ═══[/dim]
"""
        console.print(banner_art)

    # Info box using Rich Panel for proper alignment
    tip = get_random_tip()

    # Add session info if available
    session_line = ""
    if session_logger:
        session_line = f"\n[dim]📝 Session: {session_logger.session_id} | Log: /tmp/shellockolm/sessions/[/dim]"

    info_content = f"""[bold bright_white]Welcome back, {username}![/bold bright_white]
[dim]{date_str} • {time_str}[/dim]

[bright_cyan]AI MCP Tool & Python CVE Scanner[/bright_cyan]
[dim]React • Next.js • Node.js • n8n • npm • Supply Chain[/dim]

[bright_green]✓ 29 CVEs  ✓ 6 Scanners  ✓ Malware  ✓ Secrets  ✓ Auto-Fix[/bright_green]
[link=https://github.com/hlsitechio/shellockolm][bright_blue]🔗 github.com/hlsitechio/shellockolm[/bright_blue][/link]
────────────────────────────────────────────────────────────────────
[bright_yellow]💡 Tip:[/bright_yellow] {tip}{session_line}"""

    console.print(Panel(
        info_content,
        border_style="bright_cyan",
        padding=(0, 2),
    ))


def severity_style(severity: str) -> str:
    """Get style for severity level"""
    styles = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "MEDIUM": "medium",
        "LOW": "low",
    }
    return styles.get(severity.upper(), "info")


def print_finding(finding: ScanFinding, verbose: bool = False, show_context: bool = True):
    """Print a single finding with context intelligence"""
    sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
    style = severity_style(sev)

    # Get context intelligence
    ctx = None
    if show_context:
        ctx = analyze_finding_context(
            file_path=finding.file_path,
            package=finding.package,
            current_version=finding.version,
            fixed_version=finding.patched_version or "",
            severity=sev,
            cve_id=finding.cve_id
        )

    # Skip non-actionable findings in brief mode (exploit data, research, etc.)
    if ctx and not ctx.is_actionable and not verbose:
        # Show condensed version for non-actionable
        console.print(f"\n[dim]┌─ {finding.cve_id} in {finding.package} @ {finding.version}[/dim]")
        console.print(f"[dim]│  {finding.file_path}[/dim]")
        console.print(f"[dim]└─ {ctx.message} (skipped)[/dim]")
        return

    # Header with context indicator
    header = f"[{style}]┌─ {finding.cve_id}: {finding.title}[/{style}]"
    if ctx and not ctx.is_actionable:
        header += f" [dim](non-production)[/dim]"
    console.print(f"\n{header}")

    console.print(f"[path]│  File: {finding.file_path}[/path]")
    console.print(f"[info]│  Package: {finding.package} @ {finding.version}[/info]")
    console.print(f"[success]│  Fix: {finding.patched_version or 'See remediation'}[/success]")
    console.print(f"[warning]│  CVSS: {finding.cvss_score} | Difficulty: {finding.exploit_difficulty}[/warning]")

    # Show context message
    if ctx and ctx.message:
        console.print(f"│  {ctx.message}")

    if verbose:
        console.print(f"[subtitle]│  {finding.description}[/subtitle]")
        if finding.references:
            console.print(f"[path]│  Refs: {', '.join(finding.references[:2])}[/path]")

    # Show actionable fix command
    if ctx and ctx.fix_command and ctx.is_actionable:
        # Clean multiline commands for display
        cmd = ctx.fix_command.strip().split('\n')[0] if '\n' in ctx.fix_command else ctx.fix_command
        if "nvm" not in cmd:  # Skip long Node.js upgrade instructions
            console.print(f"[bright_green]│  💡 Quick fix: [command]{cmd}[/command][/bright_green]")
        else:
            console.print(f"[bright_green]│  💡 Upgrade Node.js to fix[/bright_green]")
        console.print(f"[command]└─ {finding.remediation}[/command]")
    else:
        console.print(f"[command]└─ {finding.remediation}[/command]")


def print_summary(results: List[ScanResult], output_json: Optional[str] = None):
    """Print scan summary with actionable tips"""
    total_findings = sum(len(r.findings) for r in results)
    critical = sum(1 for r in results for f in r.findings
                   if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "CRITICAL")
    high = sum(1 for r in results for f in r.findings
               if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "HIGH")

    # Count actionable vs non-actionable findings
    actionable = 0
    non_actionable = 0
    for r in results:
        for f in r.findings:
            ctx = analyze_finding_context(
                file_path=f.file_path,
                package=f.package,
                current_version=f.version,
                fixed_version=f.patched_version or "",
                severity=f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                cve_id=f.cve_id
            )
            if ctx.is_actionable:
                actionable += 1
            else:
                non_actionable += 1

    console.print("\n[title]═══ INVESTIGATION SUMMARY ═══[/title]")
    console.print(f"  📊 Total findings:  [danger]{total_findings}[/danger]")
    console.print(f"  🔴 Critical:        [critical]{critical}[/critical]")
    console.print(f"  🟠 High:            [high]{high}[/high]")
    console.print(f"  ⏱️  Duration:        [info]{sum(r.duration_seconds for r in results):.2f}s[/info]")

    # Show actionable breakdown
    if non_actionable > 0:
        console.print(f"\n  [bright_green]✓ Actionable:        {actionable}[/bright_green]")
        console.print(f"  [dim]○ Non-production:    {non_actionable} (exploit data, research, etc.)[/dim]")

    # Generate and show quick fix tips
    if actionable > 0:
        all_findings = []
        for r in results:
            for f in r.findings:
                all_findings.append({
                    "file_path": f.file_path,
                    "package": f.package,
                    "version": f.version,
                    "patched_version": f.patched_version,
                    "severity": f.severity.value if hasattr(f.severity, 'value') else str(f.severity),
                    "cve_id": f.cve_id,
                })

        tips = format_actionable_tips(all_findings)
        if tips:
            console.print(tips)

    console.print("────────────────────────────────────────────────────────────")

    if output_json:
        # Export to JSON
        output = {
            "scan_time": datetime.now().isoformat(),
            "total_findings": total_findings,
            "results": []
        }
        for r in results:
            result_dict = {
                "target": r.target,
                "scanner": r.scanner_name,
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
                    }
                    for f in r.findings
                ],
                "stats": r.stats,
                "errors": r.errors,
            }
            output["results"].append(result_dict)

        with open(output_json, 'w') as f:
            json.dump(output, f, indent=2)
        console.print(f"\n[success]📋 Report saved to: {output_json}[/success]")


# ─────────────────────────────────────────────────────────────────
# SCAN COMMAND
# ─────────────────────────────────────────────────────────────────
@app.command()
def scan(
    path: str = typer.Argument(".", help="Path to scan (default: current directory)"),
    scanner: Optional[str] = typer.Option(
        None, "--scanner", "-s",
        help=f"Specific scanner to use: {', '.join(SCANNER_REGISTRY.keys())}"
    ),
    recursive: bool = typer.Option(True, "--recursive/--no-recursive", "-r", help="Scan recursively"),
    max_depth: int = typer.Option(10, "--depth", "-d", help="Maximum directory depth"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show detailed findings"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report to file"),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="Minimal output"),
):
    """
    Scan directory for npm/Node.js/React/Next.js CVEs

    Examples:
        shellockolm scan                        # Scan current directory
        shellockolm scan /path/to/project       # Scan specific path
        shellockolm scan -s react ./            # Use only React scanner
        shellockolm scan -o report.json ./      # Export to JSON
    """
    if not quiet:
        print_banner()
        console.print(f"[title]Target:[/title] [path]{Path(path).resolve()}[/path]")

    # Validate path
    if not Path(path).exists():
        console.print(f"[danger]Error: Path does not exist: {path}[/danger]")
        raise typer.Exit(1)

    results: List[ScanResult] = []

    # Get scanners to run
    if scanner:
        if scanner not in SCANNER_REGISTRY:
            console.print(f"[danger]Unknown scanner: {scanner}[/danger]")
            console.print(f"[info]Available: {', '.join(SCANNER_REGISTRY.keys())}[/info]")
            raise typer.Exit(1)
        scanners = [get_scanner(scanner)]
    else:
        scanners = get_all_scanners()

    # Run scans
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
        disable=quiet,
    ) as progress:
        for s in scanners:
            # Log scan start
            if session_logger:
                session_logger.log_scan_start(s.NAME, str(Path(path).resolve()))

            task = progress.add_task(f"[info]Running {s.NAME} scanner...", total=None)
            result = s.scan_directory(path, recursive=recursive, max_depth=max_depth)
            results.append(result)
            progress.remove_task(task)

            # Log scan result
            if session_logger:
                session_logger.log_scan_result(s.NAME, len(result.findings), result.duration_seconds)

            if not quiet and result.findings:
                console.print(f"[warning]  {s.NAME}: {len(result.findings)} findings[/warning]")

    # Print findings
    all_findings = [f for r in results for f in r.findings]

    if all_findings:
        if not quiet:
            console.print("\n[danger]🚨 VULNERABILITIES DETECTED[/danger]")

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        sorted_findings = sorted(
            all_findings,
            key=lambda f: severity_order.get(
                (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper(),
                4
            )
        )

        for finding in sorted_findings:
            print_finding(finding, verbose)
            # Log each finding to session
            if session_logger:
                session_logger.log_finding({
                    "cve_id": finding.cve_id,
                    "title": finding.title,
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "cvss_score": finding.cvss_score,
                    "package": finding.package,
                    "version": finding.version,
                    "patched_version": finding.patched_version,
                    "file_path": finding.file_path,
                    "remediation": finding.remediation,
                })
    else:
        if not quiet:
            console.print(Panel(
                "[success]✅ No vulnerabilities detected![/success]\n\n"
                "🔍 Investigation complete. Your projects appear secure.\n"
                "[subtitle]Elementary, my dear developer![/subtitle]",
                title="🎉 Status: SECURE",
                border_style="bright_green",
            ))

    print_summary(results, output)

    # Log summary to session
    if session_logger:
        total_findings = len(all_findings)
        critical = sum(1 for f in all_findings
                       if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "CRITICAL")
        high = sum(1 for f in all_findings
                   if (f.severity.value if hasattr(f.severity, 'value') else str(f.severity)).upper() == "HIGH")
        duration = sum(r.duration_seconds for r in results)
        session_logger.log_summary(total_findings, critical, high, duration)

    # Exit with error if vulnerabilities found
    if all_findings:
        raise typer.Exit(1)


# ─────────────────────────────────────────────────────────────────
# LIVE COMMAND - Active URL probing
# ─────────────────────────────────────────────────────────────────
@app.command()
def live(
    url: str = typer.Argument(..., help="URL to probe"),
    scanner: str = typer.Option(
        "all", "--scanner", "-s",
        help="Scanner to use: nextjs, n8n, or all"
    ),
    timeout: int = typer.Option(10, "--timeout", "-t", help="Request timeout in seconds"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save JSON report"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Verbose output"),
):
    """
    Live probe a URL for vulnerabilities

    Tests for:
      - CVE-2025-29927: Next.js middleware bypass
      - CVE-2026-21858: n8n unauthenticated RCE

    Examples:
        shellockolm live https://target.com
        shellockolm live -s nextjs https://target.com
        shellockolm live -s n8n https://n8n.target.com
    """
    print_banner()
    console.print(f"[title]Live Probe:[/title] [path]{url}[/path]")
    console.print("[warning]Testing for exploitable vulnerabilities...[/warning]\n")

    results: List[ScanResult] = []

    # Validate URL
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"

    # Log live probe
    if session_logger:
        session_logger.log_live_probe(url, scanner)

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        if scanner in ["nextjs", "all"]:
            task = progress.add_task("[info]Probing for Next.js vulnerabilities...", total=None)
            try:
                from scanners.nextjs import NextJSScanner
                s = NextJSScanner()
                result = s.scan_live(url, timeout=timeout)
                results.append(result)

                if result.stats.get("nextjs_detected"):
                    console.print(f"[success]  ✓ Next.js detected (v{result.stats.get('detected_version', 'unknown')})[/success]")
                else:
                    console.print("[info]  • Next.js not detected[/info]")
            except Exception as e:
                console.print(f"[danger]  ✗ Next.js probe failed: {e}[/danger]")
            finally:
                progress.remove_task(task)

        if scanner in ["n8n", "all"]:
            task = progress.add_task("[info]Probing for n8n vulnerabilities...", total=None)
            try:
                from scanners.n8n import N8NScanner
                s = N8NScanner()
                result = s.scan_live(url, timeout=timeout)
                results.append(result)

                if result.stats.get("n8n_detected"):
                    console.print(f"[success]  ✓ n8n detected (v{result.stats.get('detected_version', 'unknown')})[/success]")
                else:
                    console.print("[info]  • n8n not detected[/info]")
            except Exception as e:
                console.print(f"[danger]  ✗ n8n probe failed: {e}[/danger]")
            finally:
                progress.remove_task(task)

    # Print findings
    all_findings = [f for r in results for f in r.findings]

    if all_findings:
        console.print("\n[danger]🚨 LIVE VULNERABILITIES CONFIRMED[/danger]")
        for finding in all_findings:
            print_finding(finding, verbose)
            # Log live finding to session
            if session_logger:
                session_logger.log_finding({
                    "cve_id": finding.cve_id,
                    "title": finding.title,
                    "severity": finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity),
                    "cvss_score": finding.cvss_score,
                    "package": finding.package,
                    "version": finding.version,
                    "file_path": url,  # For live probes, use URL as file path
                    "remediation": finding.remediation,
                    "type": "live_probe",
                })
    else:
        console.print("\n[success]No exploitable vulnerabilities detected at this URL[/success]")
        if session_logger:
            session_logger.log(f"Live probe complete - No vulnerabilities at {url}", "RECON")

    print_summary(results, output)


# ─────────────────────────────────────────────────────────────────
# CVES COMMAND - List all CVEs
# ─────────────────────────────────────────────────────────────────
@app.command()
def cves(
    category: Optional[str] = typer.Option(
        None, "--category", "-c",
        help="Filter by category: react, nextjs, nodejs, npm, n8n, supply-chain"
    ),
    severity: Optional[str] = typer.Option(
        None, "--severity", "-s",
        help="Filter by severity: critical, high, medium, low"
    ),
    bounty: bool = typer.Option(False, "--bounty", "-b", help="Show only bug bounty worthy CVEs"),
):
    """
    List all tracked CVEs

    Examples:
        shellockolm cves                      # List all CVEs
        shellockolm cves -c react             # React CVEs only
        shellockolm cves -s critical          # Critical severity only
        shellockolm cves --bounty             # Bug bounty targets
    """
    print_banner()

    db = VulnerabilityDatabase()
    all_vulns = db.get_all_vulnerabilities()

    # Apply filters
    filtered = all_vulns

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
            filtered = cat_map[category]
        else:
            console.print(f"[danger]Unknown category: {category}[/danger]")
            console.print(f"[info]Available: {', '.join(cat_map.keys())}[/info]")
            raise typer.Exit(1)

    if severity:
        sev_upper = severity.upper()
        filtered = [v for v in filtered if v.severity.value.upper() == sev_upper]

    if bounty:
        # Bug bounty worthy = CRITICAL severity or public PoC or active exploitation
        filtered = [v for v in filtered if v.severity == Severity.CRITICAL or getattr(v, 'public_poc', False) or getattr(v, 'active_exploitation', False)]

    # Build table
    table = Table(
        title="🔍 Shellockolm CVE Database",
        box=box.ROUNDED,
        border_style="bright_cyan",
    )
    table.add_column("CVE ID", style="highlight", no_wrap=True)
    table.add_column("Severity", justify="center")
    table.add_column("CVSS", justify="center", style="warning")
    table.add_column("Package", style="info")
    table.add_column("Title", style="path")
    table.add_column("Bounty", justify="center")

    for v in filtered:
        sev = v.severity.value.upper()
        sev_styled = f"[{severity_style(sev)}]{sev}[/{severity_style(sev)}]"
        # Bug bounty worthy = CRITICAL severity or public PoC
        is_bounty = v.severity == Severity.CRITICAL or getattr(v, 'public_poc', False)
        bounty_icon = "💰" if is_bounty else ""

        table.add_row(
            v.cve_id,
            sev_styled,
            str(v.cvss_score),
            ", ".join(v.packages[:2]) + ("..." if len(v.packages) > 2 else ""),
            v.title[:40] + "..." if len(v.title) > 40 else v.title,
            bounty_icon,
        )

    console.print(table)
    console.print(f"\n[info]Total: {len(filtered)} CVEs[/info]")


# ─────────────────────────────────────────────────────────────────
# INFO COMMAND - CVE details
# ─────────────────────────────────────────────────────────────────
@app.command()
def info(
    cve_id: str = typer.Argument(..., help="CVE ID (e.g., CVE-2025-29927)"),
):
    """
    Get detailed information about a specific CVE

    Example:
        shellockolm info CVE-2025-29927
    """
    db = VulnerabilityDatabase()
    vuln = db.get_by_cve(cve_id.upper())

    if not vuln:
        console.print(f"[danger]CVE not found: {cve_id}[/danger]")
        console.print("[info]Use 'shellockolm cves' to see all tracked CVEs[/info]")
        raise typer.Exit(1)

    sev = vuln.severity.value.upper()
    is_bounty = vuln.severity == Severity.CRITICAL or getattr(vuln, 'public_poc', False)
    patched_str = ", ".join(f"{k}→{v}" for k, v in vuln.patched_versions.items()) if vuln.patched_versions else "See advisory"
    packages_str = ", ".join(vuln.packages)

    panel_content = f"""[title]{vuln.title}[/title]

[{severity_style(sev)}]Severity: {sev} (CVSS {vuln.cvss_score})[/{severity_style(sev)}]
[info]Packages: {packages_str}[/info]
[success]Fixed in: {patched_str}[/success]
[warning]Exploit Difficulty: {vuln.exploit_difficulty.value}[/warning]
[highlight]Bug Bounty Worthy: {'Yes 💰' if is_bounty else 'Maybe'}[/highlight]

[subtitle]Description:[/subtitle]
{vuln.description}

[subtitle]Remediation:[/subtitle]
Upgrade affected packages to patched versions.
"""

    if vuln.references:
        panel_content += "\n[subtitle]References:[/subtitle]\n"
        for ref in vuln.references[:5]:
            panel_content += f"  • [path]{ref}[/path]\n"

    console.print(Panel(
        panel_content,
        title=f"🔍 {cve_id}",
        border_style="bright_cyan",
    ))


# ─────────────────────────────────────────────────────────────────
# SCANNERS COMMAND - List available scanners
# ─────────────────────────────────────────────────────────────────
@app.command()
def scanners():
    """List all available scanners and their CVE coverage"""
    print_banner()

    table = Table(
        title="🔍 Available Scanners",
        box=box.ROUNDED,
        border_style="bright_cyan",
    )
    table.add_column("Scanner", style="highlight")
    table.add_column("Description", style="info")
    table.add_column("CVEs", justify="center", style="warning")
    table.add_column("Live Scan", justify="center")

    for name, scanner_class in SCANNER_REGISTRY.items():
        s = scanner_class()
        has_live = hasattr(s, 'scan_live')
        table.add_row(
            name,
            s.DESCRIPTION,
            str(len(s.CVE_IDS)),
            "✓" if has_live else "",
        )

    console.print(table)

    total_cves = sum(len(scanner_class().CVE_IDS) for scanner_class in SCANNER_REGISTRY.values())
    console.print(f"\n[info]Total: {len(SCANNER_REGISTRY)} scanners covering {total_cves} CVEs[/info]")


# ─────────────────────────────────────────────────────────────────
# VERSION COMMAND
# ─────────────────────────────────────────────────────────────────
@app.command()
def version():
    """Show version information"""
    console.print("[title]Shellockolm v2.0.0[/title]")
    console.print("[subtitle]Security Detective for React, Next.js, Node.js & npm[/subtitle]")
    console.print("[info]https://github.com/hlsitechio/shellockolm[/info]")


def main():
    """Main entry point"""
    app()


# ─────────────────────────────────────────────────────────────────
# INTERACTIVE MENU SYSTEM
# ─────────────────────────────────────────────────────────────────

# Menu structure with categories
MENU_CATEGORIES = {
    "scanning": {
        "title": "🔍 SCANNING",
        "commands": [
            {
                "id": "1",
                "name": "Full Scan",
                "description": "Run ALL 6 scanners on a directory to detect 29 CVEs across React, Next.js, Node.js, npm packages, n8n, and supply chain attacks.",
                "action": "scan",
                "requires_input": "path",
                "input_prompt": "Enter path to scan (or . for current dir): ",
            },
            {
                "id": "1a",
                "name": "Scan ALL npm",
                "description": "Auto-detect and scan ALL npm projects on your system (home dir, npm cache, common locations). Finds all package.json/lockfiles.",
                "action": "scan-all-npm",
                "requires_input": None,
            },
            {
                "id": "1b",
                "name": "Pre-Download Check",
                "description": "🛡️ SANDBOX: Check npm package BEFORE downloading. Downloads to temp sandbox, analyzes for malware/vulnerabilities, then destroys. Safe way to verify packages!",
                "action": "sandbox-check",
                "requires_input": "npm_package",
                "input_prompt": "Enter npm package name or URL (e.g., 'lodash' or 'https://npmjs.com/package/lodash'): ",
            },
            {
                "id": "2",
                "name": "React Scanner",
                "description": "Scan for React Server Components RCE vulnerabilities (CVE-2025-55182, CVE-2025-66478). Detects vulnerable react, react-server-dom-webpack packages.",
                "action": "scan -s react",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "3",
                "name": "Next.js Scanner",
                "description": "Scan for Next.js middleware bypass (CVE-2025-29927) and RSC vulnerabilities. Checks for middleware.ts/js files.",
                "action": "scan -s nextjs",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "4",
                "name": "npm Packages Scanner",
                "description": "Scan for vulnerabilities in popular npm packages: mysql2 (RCE), jsonpath-plus (RCE), body-parser (DoS), multer (DoS), nuxt, AdonisJS.",
                "action": "scan -s npm",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "5",
                "name": "Node.js Runtime Scanner",
                "description": "Scan for Node.js runtime vulnerabilities from January 2026 security release. Checks system Node.js version and project requirements.",
                "action": "scan -s nodejs",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "6",
                "name": "n8n Scanner",
                "description": "Scan for n8n workflow automation vulnerabilities including Ni8mare unauthenticated RCE (CVE-2026-21858).",
                "action": "scan -s n8n",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "7",
                "name": "Supply Chain Scanner",
                "description": "Detect supply chain attacks: Shai-Hulud worm campaign, eslint-config-prettier compromise, malicious install scripts, npm token exposure.",
                "action": "scan -s supply-chain",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
        ]
    },
    "live_recon": {
        "title": "🌐 LIVE RECON",
        "commands": [
            {
                "id": "8",
                "name": "Live Probe (All)",
                "description": "Actively probe a URL for exploitable vulnerabilities. Tests for Next.js middleware bypass and n8n unauthenticated RCE.",
                "action": "live",
                "requires_input": "url",
                "input_prompt": "Enter target URL (e.g., https://target.com): ",
            },
            {
                "id": "9",
                "name": "Next.js Probe",
                "description": "Test URL for CVE-2025-29927 - Next.js middleware authorization bypass via x-middleware-subrequest header injection.",
                "action": "live -s nextjs",
                "requires_input": "url",
                "input_prompt": "Enter target URL: ",
            },
            {
                "id": "10",
                "name": "n8n Probe",
                "description": "Test URL for CVE-2026-21858 - n8n Ni8mare unauthenticated RCE via Content-Type confusion in Form Webhooks.",
                "action": "live -s n8n",
                "requires_input": "url",
                "input_prompt": "Enter n8n URL (e.g., https://n8n.target.com): ",
            },
        ]
    },
    "intelligence": {
        "title": "📊 CVE INTELLIGENCE",
        "commands": [
            {
                "id": "11",
                "name": "List All CVEs",
                "description": "Display all 28 tracked CVEs with severity, CVSS scores, affected packages, and titles.",
                "action": "cves",
                "requires_input": None,
            },
            {
                "id": "12",
                "name": "Critical CVEs Only",
                "description": "Show only CRITICAL severity CVEs (CVSS 9.0+). These are the highest priority vulnerabilities.",
                "action": "cves --severity critical",
                "requires_input": None,
            },
            {
                "id": "13",
                "name": "Bug Bounty Targets",
                "description": "List CVEs that are high-value bug bounty targets - CRITICAL severity or with public PoCs.",
                "action": "cves --bounty",
                "requires_input": None,
            },
            {
                "id": "14",
                "name": "CVE Details",
                "description": "Get detailed information about a specific CVE including description, affected versions, patches, and references.",
                "action": "info",
                "requires_input": "cve",
                "input_prompt": "Enter CVE ID (e.g., CVE-2025-29927): ",
            },
            {
                "id": "15",
                "name": "List Scanners",
                "description": "Show all 6 available scanners with their descriptions, CVE coverage, and live scan capability.",
                "action": "scanners",
                "requires_input": None,
            },
        ]
    },
    "reports": {
        "title": "📋 REPORTS",
        "commands": [
            {
                "id": "16",
                "name": "Generate JSON Report",
                "description": "Run full scan and export results to a JSON file for documentation or integration with other tools.",
                "action": "scan -o",
                "requires_input": "path_and_output",
                "input_prompt": "Enter path to scan: ",
                "input_prompt2": "Enter output filename (e.g., report.json): ",
            },
        ]
    },
    "malware": {
        "title": "🦠 MALWARE ANALYSIS",
        "commands": [
            {
                "id": "17",
                "name": "Deep Malware Scan",
                "description": "Deep scan node_modules and project for malicious code patterns. Detects RCE payloads, data exfiltration, backdoors, crypto miners, supply chain attacks (Shai-Hulud worm), and typosquatting.",
                "action": "malware-scan --deep",
                "requires_input": "path",
                "input_prompt": "Enter project path to deep scan: ",
            },
            {
                "id": "18",
                "name": "Quick Malware Scan",
                "description": "Fast scan of project files only (excludes node_modules). Good for checking your own code for injected malware.",
                "action": "malware-scan --quick",
                "requires_input": "path",
                "input_prompt": "Enter project path to scan: ",
            },
            {
                "id": "19",
                "name": "Quarantine File",
                "description": "Move a malicious file to quarantine. Preserves original path info for potential restoration. File is renamed with .quarantine extension.",
                "action": "malware-quarantine",
                "requires_input": "file_path",
                "input_prompt": "Enter path to file to quarantine: ",
            },
            {
                "id": "20",
                "name": "Remove Package",
                "description": "Completely remove a malicious npm package from node_modules. Backs up to quarantine before deletion.",
                "action": "malware-remove",
                "requires_input": "package_info",
                "input_prompt": "Enter malicious package name: ",
                "input_prompt2": "Enter project path: ",
            },
            {
                "id": "21",
                "name": "Clean Malicious Code",
                "description": "Surgically remove only malicious code from a file while preserving legitimate code. Creates backup before modification.",
                "action": "malware-clean",
                "requires_input": "file_path",
                "input_prompt": "Enter path to file to clean: ",
            },
            {
                "id": "22",
                "name": "View Malware Report",
                "description": "View the latest malware analysis report with detailed findings, threat levels, and remediation steps.",
                "action": "malware-report",
                "requires_input": None,
            },
        ]
    },
    "secrets": {
        "title": "🔐 SECRETS SCANNER",
        "commands": [
            {
                "id": "23",
                "name": "Scan for Secrets",
                "description": "Deep scan for exposed secrets: API keys, tokens, passwords, AWS credentials, GitHub tokens, Stripe keys, and 50+ patterns.",
                "action": "secrets-scan",
                "requires_input": "path",
                "input_prompt": "Enter path to scan for secrets: ",
            },
            {
                "id": "24",
                "name": "Scan .env Files",
                "description": "Specifically scan .env files for exposed secrets and credentials. Checks for hardcoded API keys and sensitive values.",
                "action": "secrets-env",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "25",
                "name": "High Entropy Scan",
                "description": "Use entropy-based detection to find random strings that may be secrets. Catches unknown API key formats.",
                "action": "secrets-entropy",
                "requires_input": "path",
                "input_prompt": "Enter path to scan: ",
            },
            {
                "id": "26",
                "name": "View Secrets Report",
                "description": "View the latest secrets scan report with findings, risk levels, and recommendations.",
                "action": "secrets-report",
                "requires_input": None,
            },
        ]
    },
    "security": {
        "title": "📊 SECURITY SCORE",
        "commands": [
            {
                "id": "27",
                "name": "Calculate Security Score",
                "description": "Generate comprehensive A-F security grade for your project. Analyzes vulnerabilities, malware, secrets, dependencies, and configuration.",
                "action": "security-score",
                "requires_input": "path",
                "input_prompt": "Enter project path to analyze: ",
            },
            {
                "id": "28",
                "name": "Quick Security Check",
                "description": "Fast security assessment without deep scanning. Good for CI/CD pipelines and quick checks.",
                "action": "security-quick",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "29",
                "name": "View Security Report",
                "description": "View detailed security report with breakdown by category, recommendations, and improvement tips.",
                "action": "security-report",
                "requires_input": None,
            },
        ]
    },
    "autofix": {
        "title": "🔧 AUTO-FIX",
        "commands": [
            {
                "id": "30",
                "name": "Auto-Fix Vulnerabilities",
                "description": "Automatically upgrade vulnerable packages to patched versions. Creates backup before modifications.",
                "action": "autofix-scan",
                "requires_input": "path",
                "input_prompt": "Enter project path to fix: ",
            },
            {
                "id": "31",
                "name": "Preview Fixes",
                "description": "Show what packages would be upgraded without making changes. Safe dry-run mode.",
                "action": "autofix-preview",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "32",
                "name": "Rollback Changes",
                "description": "Restore package.json from backup if auto-fix caused issues.",
                "action": "autofix-rollback",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
        ]
    },
    "deps": {
        "title": "📦 DEPENDENCY ANALYSIS",
        "commands": [
            {
                "id": "33",
                "name": "Analyze Lockfile",
                "description": "Analyze package-lock.json, yarn.lock, or pnpm-lock.yaml for vulnerabilities, duplicates, and issues.",
                "action": "lockfile-analyze",
                "requires_input": "path",
                "input_prompt": "Enter path to lockfile (or project dir): ",
            },
            {
                "id": "34",
                "name": "Find Duplicates",
                "description": "Find duplicate packages with multiple versions in your lockfile. Helps reduce bundle size.",
                "action": "lockfile-duplicates",
                "requires_input": "path",
                "input_prompt": "Enter path to lockfile: ",
            },
            {
                "id": "35",
                "name": "Check Typosquatting",
                "description": "Check for potential typosquatting packages (malicious packages with similar names).",
                "action": "lockfile-typosquat",
                "requires_input": "path",
                "input_prompt": "Enter path to lockfile: ",
            },
            {
                "id": "36",
                "name": "View Lockfile Report",
                "description": "View detailed lockfile analysis report with all issues and recommendations.",
                "action": "lockfile-report",
                "requires_input": None,
            },
        ]
    },
    "exports": {
        "title": "📤 CI/CD EXPORTS",
        "commands": [
            {
                "id": "37",
                "name": "Export SARIF",
                "description": "Export scan results to SARIF format for GitHub Code Scanning, VS Code, and CI/CD pipeline integration.",
                "action": "sarif-export",
                "requires_input": "path",
                "input_prompt": "Enter project path to scan: ",
            },
            {
                "id": "38",
                "name": "View SARIF Report",
                "description": "View the most recent SARIF report or convert existing scan results to SARIF.",
                "action": "sarif-view",
                "requires_input": None,
            },
            {
                "id": "39",
                "name": "SARIF from Last Scan",
                "description": "Convert the most recent scan results to SARIF format (no new scan required).",
                "action": "sarif-convert",
                "requires_input": None,
            },
        ]
    },
    "github": {
        "title": "🐙 GITHUB ADVISORY",
        "commands": [
            {
                "id": "40",
                "name": "Query Package",
                "description": "Query GitHub Advisory Database for vulnerabilities in a specific npm package.",
                "action": "ghsa-query",
                "requires_input": "package",
                "input_prompt": "Enter npm package name: ",
            },
            {
                "id": "41",
                "name": "Check Version",
                "description": "Check if a specific package version is vulnerable using GitHub Advisory Database.",
                "action": "ghsa-check",
                "requires_input": "package_version",
                "input_prompt": "Enter package@version (e.g., lodash@4.17.0): ",
            },
            {
                "id": "42",
                "name": "Scan Project",
                "description": "Scan package.json dependencies against GitHub Advisory Database.",
                "action": "ghsa-scan",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "43",
                "name": "View Report",
                "description": "View the most recent GitHub Advisory scan report.",
                "action": "ghsa-report",
                "requires_input": None,
            },
        ]
    },
    "npm_audit": {
        "title": "📦 NPM AUDIT",
        "commands": [
            {
                "id": "44",
                "name": "Run npm audit",
                "description": "Run npm audit with enhanced output and beautiful formatting.",
                "action": "npm-audit",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "45",
                "name": "npm audit fix",
                "description": "Run npm audit fix to automatically patch vulnerabilities.",
                "action": "npm-fix",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "46",
                "name": "Fix Recommendations",
                "description": "Get detailed fix recommendations for npm vulnerabilities.",
                "action": "npm-recommend",
                "requires_input": None,
            },
            {
                "id": "47",
                "name": "Audit History",
                "description": "View history of previous npm audit scans.",
                "action": "npm-history",
                "requires_input": None,
            },
        ]
    },
    "sbom": {
        "title": "📋 SBOM",
        "commands": [
            {
                "id": "48",
                "name": "Generate SBOM",
                "description": "Generate Software Bill of Materials in CycloneDX or SPDX format.",
                "action": "sbom-generate",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "49",
                "name": "CycloneDX SBOM",
                "description": "Generate SBOM in CycloneDX 1.4 JSON format (industry standard).",
                "action": "sbom-cyclonedx",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "50",
                "name": "SPDX SBOM",
                "description": "Generate SBOM in SPDX 2.3 JSON format (Linux Foundation standard).",
                "action": "sbom-spdx",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
        ]
    },
    "deptree": {
        "title": "🌳 DEP TREE",
        "commands": [
            {
                "id": "51",
                "name": "View Tree",
                "description": "Display dependency tree with beautiful Rich formatting.",
                "action": "tree-view",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "52",
                "name": "Find Package",
                "description": "Find all instances of a package in the dependency tree.",
                "action": "tree-find",
                "requires_input": "package",
                "input_prompt": "Enter package name to find: ",
            },
            {
                "id": "53",
                "name": "Tree Stats",
                "description": "Show dependency tree statistics (duplicates, depth, circular refs).",
                "action": "tree-stats",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "54",
                "name": "Export Tree",
                "description": "Export dependency tree to file (JSON, DOT, ASCII formats).",
                "action": "tree-export",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
        ]
    },
    "ignore": {
        "title": "🚫 IGNORE",
        "commands": [
            {
                "id": "55",
                "name": "Create .shellockolmignore",
                "description": "Create a new .shellockolmignore file with recommended patterns.",
                "action": "ignore-create",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "56",
                "name": "View Patterns",
                "description": "View all loaded ignore patterns (defaults + project + global).",
                "action": "ignore-view",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "57",
                "name": "Test Path",
                "description": "Test if a specific path would be ignored by current patterns.",
                "action": "ignore-test",
                "requires_input": "path",
                "input_prompt": "Enter path to test: ",
            },
        ]
    },
    "cicd": {
        "title": "⚙️ CI/CD",
        "commands": [
            {
                "id": "58",
                "name": "Generate Workflow",
                "description": "Create GitHub Actions workflow for automated security scanning.",
                "action": "gha-generate",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "59",
                "name": "Basic Workflow",
                "description": "Generate minimal workflow for quick CI/CD setup.",
                "action": "gha-basic",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "60",
                "name": "Full Workflow",
                "description": "Generate comprehensive workflow with all features.",
                "action": "gha-full",
                "requires_input": "path",
                "input_prompt": "Enter project path: ",
            },
            {
                "id": "61",
                "name": "Watch Mode",
                "description": "Start continuous scanning - monitors files for changes.",
                "action": "watch-start",
                "requires_input": "path",
                "input_prompt": "Enter path to watch: ",
            },
        ]
    },
}


def show_main_menu():
    """Display the main menu using 4-column table layout"""

    console.print()
    # Row 1: SCAN, LIVE, CVE, MALWARE
    t1 = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True, padding=(0, 1))
    t1.add_column("[cyan]SCAN[/cyan]", width=17)
    t1.add_column("[green]LIVE[/green]", width=15)
    t1.add_column("[yellow]CVE[/yellow]", width=15)
    t1.add_column("[red]MALWARE[/red]", width=15)
    t1.add_row("[cyan][ 1][/cyan] Full Scan", "[green][ 8][/green] Probe All", "[yellow][11][/yellow] List All", "[red][17][/red] Deep Scan")
    t1.add_row("[cyan][1a][/cyan] ALL npm", "[green][ 9][/green] Next.js", "[yellow][12][/yellow] Critical", "[red][18][/red] Quick")
    t1.add_row("[cyan][1b][/cyan] Pre-Check", "[green][10][/green] n8n", "[yellow][13][/yellow] Bounty", "[red][19][/red] Quarantine")
    t1.add_row("[cyan][ 2][/cyan] React", "", "[yellow][14][/yellow] Details", "[red][20][/red] Remove")
    t1.add_row("[cyan][ 3][/cyan] Next.js", "", "[yellow][15][/yellow] By Pkg", "[red][21][/red] Cleanup")
    t1.add_row("[cyan][ 4][/cyan] npm Pkgs", "", "[yellow][16][/yellow] Export", "[red][22][/red] Report")
    t1.add_row("[cyan][ 5][/cyan] Node.js", "", "", "")
    t1.add_row("[cyan][ 6][/cyan] n8n", "", "", "")
    t1.add_row("[cyan][ 7][/cyan] Chain", "", "", "")
    console.print(t1)

    # Row 2: SECRETS, FIX, DEPS, SARIF
    t2 = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True, padding=(0, 1))
    t2.add_column("[magenta]SECRETS[/magenta]", width=17)
    t2.add_column("[blue]REMEDIATION[/blue]", width=15)
    t2.add_column("[white]DEPS[/white]", width=15)
    t2.add_column("[yellow]SARIF[/yellow]", width=15)
    t2.add_row("[magenta][23][/magenta] Sec Scan", "[blue][27][/blue] Risk Score", "[white][33][/white] Lockfile", "[yellow][37][/yellow] Export")
    t2.add_row("[magenta][24][/magenta] .env Scan", "[blue][28][/blue] Quick Score", "[white][34][/white] Dupes", "[yellow][38][/yellow] View")
    t2.add_row("[magenta][25][/magenta] Entropy", "[blue][29][/blue] Fix Report", "[white][35][/white] Typosquat", "[yellow][39][/yellow] Convert")
    t2.add_row("[magenta][26][/magenta] Report", "[blue][30][/blue] Auto Fix", "[white][36][/white] Report", "")
    t2.add_row("", "[blue][31][/blue] Preview", "", "")
    t2.add_row("", "[blue][32][/blue] Rollback", "", "")
    console.print(t2)

    # Row 3: GITHUB, NPM, SBOM, TREE
    t3 = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True, padding=(0, 1))
    t3.add_column("[green]GITHUB[/green]", width=17)
    t3.add_column("[cyan]NPM AUDIT[/cyan]", width=15)
    t3.add_column("[magenta]SBOM[/magenta]", width=15)
    t3.add_column("[yellow]DEP TREE[/yellow]", width=15)
    t3.add_row("[green][40][/green] Query GHSA", "[cyan][44][/cyan] Audit", "[magenta][48][/magenta] Generate", "[yellow][51][/yellow] View")
    t3.add_row("[green][41][/green] Check", "[cyan][45][/cyan] Auto Fix", "[magenta][49][/magenta] CycloneDX", "[yellow][52][/yellow] Find Pkg")
    t3.add_row("[green][42][/green] Scan", "[cyan][46][/cyan] Recs", "[magenta][50][/magenta] SPDX", "[yellow][53][/yellow] Stats")
    t3.add_row("[green][43][/green] Report", "[cyan][47][/cyan] History", "", "[yellow][54][/yellow] Export")
    console.print(t3)

    # Row 4: IGNORE, CI/CD
    t4 = Table(box=box.ROUNDED, border_style="bright_cyan", show_header=True, padding=(0, 1))
    t4.add_column("[red]IGNORE[/red]", width=17)
    t4.add_column("[blue]CI/CD[/blue]", width=15)
    t4.add_column("", width=15)
    t4.add_column("", width=15)
    t4.add_row("[red][55][/red] Create", "[blue][58][/blue] Generate", "", "")
    t4.add_row("[red][56][/red] View", "[blue][59][/blue] Basic", "", "")
    t4.add_row("[red][57][/red] Test Path", "[blue][60][/blue] Full CI/CD", "", "")
    t4.add_row("", "[blue][61][/blue] Watch", "", "")
    console.print(t4)

    console.print()
    console.print("  [bright_red][0][/bright_red] Exit   [bright_cyan][h][/bright_cyan] Help   [bright_green][c][/bright_green] Clear   [bright_yellow][l][/bright_yellow] Logs   [bright_magenta][?][/bright_magenta] Command Info")
    console.print()


def get_command_by_id(cmd_id: str):
    """Get command info by ID"""
    for category in MENU_CATEGORIES.values():
        for cmd in category["commands"]:
            if cmd["id"] == cmd_id:
                return cmd
    return None


def show_next_steps(cmd_type: str, context: dict = None):
    """Show contextual next steps after a command completes"""
    context = context or {}

    steps = {
        "scan": [
            ("[14]", "View CVE details for any finding"),
            ("[16]", "Export results to JSON report"),
            ("[12]", "List only Critical CVEs"),
            ("[8]", "Live probe a target URL"),
        ],
        "scan_clean": [
            ("[1]", "Run full scan on another path"),
            ("[8]", "Try live probe on a URL"),
            ("[11]", "Browse all tracked CVEs"),
        ],
        "cves": [
            ("[14]", "Get details on a specific CVE"),
            ("[1]", "Scan a project for these CVEs"),
            ("[13]", "View bug bounty targets"),
        ],
        "cve_detail": [
            ("[1]", "Scan for this vulnerability"),
            ("[11]", "View all CVEs"),
            ("[8]", "Live probe a target"),
        ],
        "live": [
            ("[1]", "Run full local scan"),
            ("[16]", "Export findings to JSON"),
            ("[14]", "Get CVE details"),
        ],
        "live_clean": [
            ("[8]", "Probe another URL"),
            ("[1]", "Run local scan instead"),
            ("[11]", "Browse CVE database"),
        ],
        "scanners": [
            ("[1]", "Run full scan (all scanners)"),
            ("[2-7]", "Run a specific scanner"),
            ("[11]", "View CVE database"),
        ],
        "malware_scan": [
            ("[19]", "Quarantine malicious file"),
            ("[20]", "Remove malicious package"),
            ("[21]", "Clean malicious code from file"),
            ("[22]", "View full malware report"),
        ],
        "malware_clean_result": [
            ("[17]", "Run deep scan with node_modules"),
            ("[1]", "Run CVE vulnerability scan"),
            ("[7]", "Check for supply chain attacks"),
        ],
        "malware_action": [
            ("[17]", "Run another malware scan"),
            ("[22]", "View malware report"),
            ("[1]", "Run CVE vulnerability scan"),
        ],
        "malware_report": [
            ("[17]", "Run new deep scan"),
            ("[19]", "Quarantine a file"),
            ("[20]", "Remove malicious package"),
        ],
        "secrets_scan": [
            ("[24]", "Scan .env files specifically"),
            ("[25]", "Try high entropy detection"),
            ("[26]", "View secrets report"),
            ("[27]", "Calculate security score"),
        ],
        "secrets_clean": [
            ("[23]", "Run another secrets scan"),
            ("[17]", "Run malware deep scan"),
            ("[1]", "Run CVE vulnerability scan"),
        ],
        "secrets_report": [
            ("[23]", "Run new secrets scan"),
            ("[27]", "Calculate security score"),
            ("[30]", "Auto-fix vulnerabilities"),
        ],
        "security_score": [
            ("[30]", "Auto-fix vulnerabilities"),
            ("[23]", "Scan for exposed secrets"),
            ("[17]", "Run malware deep scan"),
            ("[1]", "Run full CVE scan"),
        ],
        "security_clean": [
            ("[27]", "Calculate score for another project"),
            ("[1]", "Run vulnerability scan"),
            ("[8]", "Live probe a URL"),
        ],
        "security_report": [
            ("[27]", "Calculate new security score"),
            ("[30]", "Auto-fix vulnerabilities"),
            ("[23]", "Scan for secrets"),
        ],
        "autofix_scan": [
            ("[31]", "Preview fixes first"),
            ("[32]", "Rollback changes"),
            ("[27]", "Recalculate security score"),
            ("[1]", "Verify with CVE scan"),
        ],
        "autofix_preview": [
            ("[30]", "Apply fixes"),
            ("[27]", "Calculate security score"),
            ("[1]", "Run vulnerability scan"),
        ],
        "autofix_rollback": [
            ("[30]", "Try auto-fix again"),
            ("[31]", "Preview changes first"),
            ("[1]", "Run CVE scan"),
        ],
        "lockfile_scan": [
            ("[34]", "View duplicate packages"),
            ("[35]", "Check typosquatting"),
            ("[36]", "View full lockfile report"),
            ("[30]", "Auto-fix vulnerabilities"),
        ],
        "lockfile_clean": [
            ("[33]", "Analyze another lockfile"),
            ("[1]", "Run CVE vulnerability scan"),
            ("[27]", "Calculate security score"),
        ],
        "lockfile_report": [
            ("[33]", "Run new lockfile analysis"),
            ("[30]", "Auto-fix vulnerabilities"),
            ("[1]", "Run CVE scan"),
        ],
        "sarif_export": [
            ("[38]", "View SARIF report"),
            ("[39]", "Convert another scan to SARIF"),
            ("[1]", "Run new CVE scan"),
            ("[17]", "Run malware scan"),
        ],
        "sarif_view": [
            ("[37]", "Export new SARIF scan"),
            ("[1]", "Run vulnerability scan"),
            ("[33]", "Analyze lockfile"),
        ],
        "ghsa_query": [
            ("[42]", "Scan full project"),
            ("[41]", "Check specific version"),
            ("[30]", "Auto-fix vulnerabilities"),
        ],
        "ghsa_scan": [
            ("[43]", "View full report"),
            ("[30]", "Auto-fix vulnerabilities"),
            ("[37]", "Export to SARIF"),
        ],
        "ghsa_report": [
            ("[42]", "Run new GHSA scan"),
            ("[40]", "Query specific package"),
            ("[1]", "Run CVE scan"),
        ],
        "npm_audit": [
            ("[45]", "Auto-fix vulnerabilities"),
            ("[46]", "View fix recommendations"),
            ("[47]", "View audit history"),
        ],
        "npm_fix": [
            ("[44]", "Run new audit"),
            ("[27]", "Calculate security score"),
            ("[1]", "Run CVE scan"),
        ],
        "npm_history": [
            ("[44]", "Run new audit"),
            ("[37]", "Export to SARIF"),
        ],
        "sbom_generate": [
            ("[49]", "View CycloneDX format"),
            ("[50]", "View SPDX format"),
            ("[27]", "Calculate security score"),
            ("[1]", "Scan for vulnerabilities"),
        ],
        "sbom_cyclonedx": [
            ("[50]", "Generate SPDX format"),
            ("[37]", "Export to SARIF"),
            ("[40]", "Check GitHub Advisory"),
        ],
        "sbom_spdx": [
            ("[49]", "Generate CycloneDX format"),
            ("[37]", "Export to SARIF"),
            ("[40]", "Check GitHub Advisory"),
        ],
        "tree_view": [
            ("[52]", "Find specific package"),
            ("[53]", "View tree statistics"),
            ("[54]", "Export tree to file"),
            ("[1]", "Run CVE scan"),
        ],
        "tree_find": [
            ("[51]", "View full tree"),
            ("[40]", "Check GitHub Advisory for package"),
            ("[14]", "Get CVE info"),
        ],
        "tree_stats": [
            ("[51]", "View dependency tree"),
            ("[33]", "Analyze lockfile"),
            ("[48]", "Generate SBOM"),
        ],
        "tree_export": [
            ("[51]", "View tree"),
            ("[48]", "Generate SBOM"),
            ("[37]", "Export to SARIF"),
        ],
        "ignore_create": [
            ("[56]", "View loaded patterns"),
            ("[57]", "Test a path"),
            ("[1]", "Run scan with ignore file"),
        ],
        "ignore_view": [
            ("[55]", "Create new ignore file"),
            ("[57]", "Test a specific path"),
            ("[1]", "Run scan"),
        ],
        "ignore_test": [
            ("[55]", "Create ignore file"),
            ("[56]", "View all patterns"),
            ("[1]", "Run scan"),
        ],
        "gha_generate": [
            ("[59]", "Generate basic workflow"),
            ("[60]", "Generate full workflow"),
            ("[1]", "Run local scan first"),
        ],
        "gha_basic": [
            ("[60]", "Upgrade to full workflow"),
            ("[37]", "Test SARIF export locally"),
            ("[1]", "Run scan"),
        ],
        "gha_full": [
            ("[48]", "Generate SBOM locally"),
            ("[40]", "Test GitHub Advisory locally"),
            ("[1]", "Run full scan"),
        ],
        "watch_stop": [
            ("[1]", "Run one-time scan"),
            ("[61]", "Start watch mode again"),
            ("[58]", "Generate CI/CD workflow"),
        ],
    }

    suggestions = steps.get(cmd_type, [])
    if not suggestions:
        return

    console.print("\n[bold bright_cyan]📌 Next Steps:[/bold bright_cyan]")
    for key, desc in suggestions:
        console.print(f"   [white]{key}[/white] {desc}")
    console.print()


def show_command_details(cmd: dict) -> bool:
    """Show command details and ask for confirmation. Returns True if user confirms."""
    console.print(f"\n[title]━━━ {cmd['name'].upper()} ━━━[/title]")
    console.print(f"\n[subtitle]Description:[/subtitle]")
    console.print(f"  {cmd['description']}")
    console.print(f"\n[info]Command: {cmd['action']}[/info]")
    console.print()

    console.print("[bold]Run this command?[/bold]  [bright_green][Y]es[/bright_green]  /  [bright_red][N]o[/bright_red]")
    confirm = console.input(">>> ").strip().lower()
    return confirm in ['', 'y', 'yes']


def interactive_shell():
    """Interactive menu-driven shell"""
    global session_logger
    from prompt_toolkit import prompt
    from prompt_toolkit.history import FileHistory
    import shlex

    # Initialize session logger
    session_logger = SessionLogger()

    # Clear screen and show full banner
    console.clear()
    print_banner(show_full=True)

    session_logger.log("Session started - Interactive mode", "INFO")

    history_file = Path.home() / ".shellockolm_history"
    show_menu = True  # Flag to control menu display

    while True:
        try:
            if show_menu:
                show_main_menu()
            show_menu = True  # Reset for next iteration

            choice = prompt(
                "Select option: ",
                history=FileHistory(str(history_file)),
            ).strip().lower()

            # Handle special options
            if choice in ['0', 'q', 'quit', 'exit']:
                if session_logger:
                    session_logger.log("Session ended by user", "INFO")
                    console.print(f"\n[info]📝 Session log saved: {session_logger.get_log_path()}[/info]")
                    if session_logger.all_findings:
                        console.print(f"[warning]📋 Findings JSON: {session_logger.get_findings_path()}[/warning]")
                console.print("[info]👋 Goodbye! Stay secure.[/info]")
                break

            if choice in ['l', 'log', 'logs']:
                if session_logger:
                    console.print(f"\n[title]Session Log Location:[/title]")
                    console.print(f"  [path]{session_logger.get_log_path()}[/path]")
                    console.print(f"  [path]{session_logger.get_findings_path()}[/path]\n")
                    # Show last 20 lines of log
                    try:
                        with open(session_logger.log_file, "r") as f:
                            lines = f.readlines()[-20:]
                        console.print("[subtitle]Last 20 log entries:[/subtitle]")
                        console.print("".join(lines))
                    except Exception:
                        pass
                console.input("\n[subtitle]Press Enter to continue...[/subtitle]")
                # Menu will show on next iteration (show_menu = True by default)
                continue

            if choice in ['h', 'help']:
                console.print(Panel(
                    "[title]Shellockolm v2.0[/title]\n\n"
                    "Security Detective for React, Next.js, Node.js & npm\n\n"
                    "[highlight]Coverage:[/highlight]\n"
                    "  • 28 CVEs tracked (2024-2026)\n"
                    "  • 6 specialized scanners\n"
                    "  • Live URL probing\n"
                    "  • Supply chain attack detection\n\n"
                    "[highlight]Bug Bounty Ready:[/highlight]\n"
                    "  • 10 Critical CVEs\n"
                    "  • Public PoCs available\n"
                    "  • JSON report export\n\n"
                    "[info]https://github.com/hlsitechio/shellockolm[/info]",
                    title="About",
                    border_style="bright_cyan",
                ))
                console.input("\n[subtitle]Press Enter to continue...[/subtitle]")
                # Menu will show on next iteration (show_menu = True by default)
                continue

            if choice in ['c', 'clear']:
                console.clear()
                print_banner(show_full=False)
                continue

            # Get command by ID
            cmd = get_command_by_id(choice)
            if not cmd:
                console.print(f"[danger]Invalid option: {choice}[/danger]")
                show_menu = False  # Don't reshow menu for invalid input
                continue

            # Show details and confirm
            if not show_command_details(cmd):
                # User cancelled - clear and return to clean menu state
                console.clear()
                print_banner(show_full=False)
                continue

            # Get required input
            action = cmd["action"]

            if cmd.get("requires_input") == "path":
                path_input = prompt(cmd["input_prompt"]).strip() or "."
                # Resolve the path to show user what will actually be scanned
                resolved_path = Path(path_input).resolve()

                # Check for dangerous paths (home, root, or very large dirs)
                home_dir = Path.home()
                dangerous_paths = [home_dir, Path("/"), Path("/home"), Path("/Users")]

                if resolved_path in dangerous_paths or resolved_path == home_dir:
                    console.print(f"\n[warning]⚠️  Path resolves to: {resolved_path}[/warning]")
                    console.print("[warning]This would scan your entire home/root directory![/warning]")
                    console.print("[info]Enter a specific project path instead (e.g., /home/user/myproject)[/info]")
                    confirm = console.input("\n[bold]Scan anyway? [y/N]: [/bold]").strip().lower()
                    if confirm not in ['y', 'yes']:
                        console.print("[info]Cancelled. Enter a more specific path.[/info]")
                        show_menu = False
                        continue
                else:
                    # Show resolved path for clarity
                    console.print(f"[dim]Resolved: {resolved_path}[/dim]")

                # Use the resolved path
                path = str(resolved_path)
                action = f"{action} {path}"

            elif cmd.get("requires_input") == "url":
                url = prompt(cmd["input_prompt"]).strip()
                if not url:
                    console.print("[danger]URL is required.[/danger]")
                    show_menu = False
                    continue
                action = f"{action} {url}"

            elif cmd.get("requires_input") == "cve":
                cve_id = prompt(cmd["input_prompt"]).strip().upper()
                if not cve_id:
                    console.print("[danger]CVE ID is required.[/danger]")
                    show_menu = False
                    continue
                action = f"{action} {cve_id}"

            elif cmd.get("requires_input") == "path_and_output":
                path_input = prompt(cmd["input_prompt"]).strip() or "."
                resolved_path = Path(path_input).resolve()
                home_dir = Path.home()
                dangerous_paths = [home_dir, Path("/"), Path("/home"), Path("/Users")]
                if resolved_path in dangerous_paths or resolved_path == home_dir:
                    console.print(f"\n[warning]⚠️  Path resolves to: {resolved_path}[/warning]")
                    console.print("[warning]This would scan your entire home/root directory![/warning]")
                    confirm = console.input("\n[bold]Scan anyway? [y/N]: [/bold]").strip().lower()
                    if confirm not in ['y', 'yes']:
                        console.print("[info]Cancelled.[/info]")
                        show_menu = False
                        continue
                else:
                    console.print(f"[dim]Resolved: {resolved_path}[/dim]")
                output = prompt(cmd["input_prompt2"]).strip() or "report.json"
                action = f"scan {resolved_path} -o {output}"

            elif cmd.get("requires_input") == "file_path":
                file_path = prompt(cmd["input_prompt"]).strip()
                if not file_path:
                    console.print("[danger]File path is required.[/danger]")
                    show_menu = False
                    continue
                action = f"{action} {file_path}"

            elif cmd.get("requires_input") == "package_info":
                pkg_name = prompt(cmd["input_prompt"]).strip()
                if not pkg_name:
                    console.print("[danger]Package name is required.[/danger]")
                    show_menu = False
                    continue
                project_path = prompt(cmd["input_prompt2"]).strip() or "."
                action = f"{action} {pkg_name} {project_path}"

            elif cmd.get("requires_input") == "npm_package":
                pkg_input = prompt(cmd["input_prompt"]).strip()
                if not pkg_input:
                    console.print("[danger]Package name or URL is required.[/danger]")
                    show_menu = False
                    continue
                # Extract package name from URL if needed
                if "npmjs.com/package/" in pkg_input:
                    # Extract package name from URL like https://www.npmjs.com/package/lodash
                    pkg_name = pkg_input.split("/package/")[-1].split("?")[0].split("/")[0]
                else:
                    pkg_name = pkg_input
                cmd["input_value"] = pkg_name
                action = f"{action} {pkg_name}"

            # Execute command
            console.print(f"\n[info]Running: {action}[/info]\n")
            console.print("─" * 60)

            # Log the command
            if session_logger:
                session_logger.log_command(action, cmd.get("description", ""))

            next_step_type = None  # Track command type for next steps
            had_findings = False   # Track if findings were found

            try:
                args = shlex.split(action)
                cmd_name = args[0]
                cmd_args = args[1:] if len(args) > 1 else []

                # Direct function dispatch
                if cmd_name == "scan":
                    path = "."
                    scanner_name = None
                    output_file = None
                    i = 0
                    while i < len(cmd_args):
                        if cmd_args[i] in ["-s", "--scanner"] and i + 1 < len(cmd_args):
                            scanner_name = cmd_args[i + 1]
                            i += 2
                        elif cmd_args[i] in ["-o", "--output"] and i + 1 < len(cmd_args):
                            output_file = cmd_args[i + 1]
                            i += 2
                        elif not cmd_args[i].startswith("-"):
                            path = cmd_args[i]
                            i += 1
                        else:
                            i += 1
                    scan(path=path, scanner=scanner_name, output=output_file, recursive=True, max_depth=10, verbose=False, quiet=False)
                    next_step_type = "scan_clean"  # Will be updated if exit code 1

                elif cmd_name == "scan-all-npm":
                    # Auto-detect and scan all npm projects on the system
                    console.print(f"\n[title]🔍 Scanning ALL npm Projects on System[/title]\n")

                    home_dir = Path.home()
                    search_paths = [
                        home_dir / ".npm",                    # npm cache
                        home_dir / "node_modules",            # global node_modules
                        home_dir / "projects",                # common project folder
                        home_dir / "code",                    # another common folder
                        home_dir / "dev",                     # dev folder
                        Path("/mnt"),                         # mounted drives
                        Path("/opt"),                         # opt folder
                    ]

                    # Find all package.json files
                    console.print("[info]Searching for npm projects...[/info]")
                    found_projects = set()

                    for search_path in search_paths:
                        if search_path.exists():
                            console.print(f"  [dim]Checking {search_path}...[/dim]")
                            try:
                                import subprocess
                                result = subprocess.run(
                                    ["find", str(search_path), "-maxdepth", "6", "-name", "package.json", "-type", "f"],
                                    capture_output=True, text=True, timeout=30
                                )
                                for line in result.stdout.strip().split("\n"):
                                    if line and "node_modules" not in line:
                                        project_dir = str(Path(line).parent)
                                        found_projects.add(project_dir)
                            except Exception as e:
                                console.print(f"  [dim]Skipped {search_path}: {e}[/dim]")

                    if not found_projects:
                        console.print("[warning]No npm projects found on system.[/warning]")
                    else:
                        console.print(f"\n[success]Found {len(found_projects)} npm projects![/success]\n")

                        total_findings = 0
                        for i, project in enumerate(sorted(found_projects)[:20], 1):  # Limit to 20
                            console.print(f"[info]({i}/{min(len(found_projects), 20)}) Scanning: {project}[/info]")
                            try:
                                # Run scan quietly and count findings
                                from scanners import get_all_scanners
                                for scanner_obj in get_all_scanners():
                                    result = scanner_obj.scan_directory(project, recursive=True, max_depth=5)
                                    if result.findings:
                                        total_findings += len(result.findings)
                                        for finding in result.findings:
                                            print_finding(finding, verbose=False)
                            except Exception as e:
                                console.print(f"  [dim]Error: {e}[/dim]")

                        console.print(f"\n[title]═══ SYSTEM-WIDE SCAN COMPLETE ═══[/title]")
                        console.print(f"  📁 Projects scanned: {min(len(found_projects), 20)}")
                        console.print(f"  📊 Total findings: {total_findings}")

                        if total_findings > 0:
                            next_step_type = "scan"
                        else:
                            next_step_type = "scan_clean"

                elif cmd_name == "sandbox-check":
                    # ENHANCED Sandbox pre-download npm package checker
                    # Actually INSTALLS the package to detect post-install malware
                    pkg_name = cmd_args[0] if cmd_args else cmd.get("input_value", "")
                    if not pkg_name:
                        console.print("[danger]Package name is required.[/danger]")
                        continue

                    import tempfile
                    import shutil
                    import subprocess
                    import tarfile
                    import json
                    import hashlib
                    import difflib

                    console.print(f"\n[title]🛡️ SANDBOX DEEP INSTALL CHECK[/title]")
                    console.print(f"[info]Package: {pkg_name}[/info]")
                    console.print(f"[dim]This will INSTALL the package in isolation to detect post-install malware[/dim]\n")

                    sandbox_dir = None
                    is_safe = True
                    warnings = []
                    dangers = []
                    info_items = []

                    def get_dir_snapshot(path: Path) -> dict:
                        """Get snapshot of all files with hashes"""
                        snapshot = {}
                        try:
                            for f in path.rglob("*"):
                                if f.is_file():
                                    rel = str(f.relative_to(path))
                                    try:
                                        with open(f, 'rb') as fh:
                                            snapshot[rel] = {
                                                'hash': hashlib.md5(fh.read()).hexdigest(),
                                                'size': f.stat().st_size
                                            }
                                    except:
                                        snapshot[rel] = {'hash': 'unreadable', 'size': 0}
                        except:
                            pass
                        return snapshot

                    def compare_snapshots(before: dict, after: dict) -> tuple:
                        """Compare before/after snapshots"""
                        new_files = []
                        modified_files = []
                        deleted_files = []

                        for f, info in after.items():
                            if f not in before:
                                new_files.append(f)
                            elif before[f]['hash'] != info['hash']:
                                modified_files.append(f)

                        for f in before:
                            if f not in after:
                                deleted_files.append(f)

                        return new_files, modified_files, deleted_files

                    try:
                        # Create isolated sandbox project
                        sandbox_dir = tempfile.mkdtemp(prefix="shellockolm_sandbox_")
                        console.print(f"[dim]📦 Created sandbox: {sandbox_dir}[/dim]")

                        # Create minimal package.json for the sandbox project
                        sandbox_pkg = {
                            "name": "shellockolm-sandbox",
                            "version": "1.0.0",
                            "private": True,
                            "description": "Isolated sandbox for security analysis"
                        }
                        with open(Path(sandbox_dir) / "package.json", 'w') as f:
                            json.dump(sandbox_pkg, f)

                        # PHASE 1: Get package info first (without install)
                        console.print(f"\n[bright_cyan]━━━ PHASE 1: Package Metadata Analysis ━━━[/bright_cyan]")
                        console.print(f"[info]📋 Fetching package info...[/info]")

                        npm_view = subprocess.run(
                            ["npm", "view", pkg_name, "--json"],
                            capture_output=True, text=True, timeout=30
                        )

                        pkg_data = {}
                        if npm_view.returncode == 0:
                            try:
                                pkg_data = json.loads(npm_view.stdout)
                                pkg_version = pkg_data.get('version', 'unknown')
                                pkg_desc = pkg_data.get('description', 'N/A')[:60]
                                maintainers = pkg_data.get('maintainers', [])
                                last_publish = pkg_data.get('time', {}).get(pkg_version, 'unknown')

                                console.print(f"  [bright_white]Name:[/bright_white] {pkg_data.get('name', pkg_name)}")
                                console.print(f"  [bright_white]Version:[/bright_white] {pkg_version}")
                                console.print(f"  [bright_white]Description:[/bright_white] {pkg_desc}...")
                                console.print(f"  [bright_white]Last Published:[/bright_white] {last_publish[:10] if last_publish != 'unknown' else 'unknown'}")

                                # Check for install scripts in metadata
                                scripts = pkg_data.get('scripts', {})
                                install_scripts = []
                                for script_name in ['preinstall', 'install', 'postinstall', 'prepare']:
                                    if script_name in scripts:
                                        install_scripts.append(script_name)
                                        script_content = scripts[script_name]

                                        # Analyze script content
                                        danger_patterns = [
                                            ('curl', 'Downloads external content'),
                                            ('wget', 'Downloads external content'),
                                            ('eval', 'Dynamic code execution'),
                                            ('exec', 'Command execution'),
                                            ('child_process', 'Spawns processes'),
                                            ('rm -rf', 'Destructive file operation'),
                                            ('base64', 'Encoded payload'),
                                            ('/dev/tcp', 'Network backdoor'),
                                            ('powershell', 'PowerShell execution'),
                                            ('cmd.exe', 'Windows command execution'),
                                            ('.bat', 'Batch script execution'),
                                            ('nc ', 'Netcat - reverse shell'),
                                            ('netcat', 'Netcat - reverse shell'),
                                            ('/bin/sh', 'Shell execution'),
                                            ('/bin/bash', 'Bash execution'),
                                            ('socket', 'Network socket'),
                                            ('XMLHttpRequest', 'HTTP request'),
                                            ('fetch(', 'HTTP fetch'),
                                            ('https://', 'External URL'),
                                            ('http://', 'External URL (insecure)'),
                                        ]

                                        for pattern, desc in danger_patterns:
                                            if pattern.lower() in script_content.lower():
                                                dangers.append(f"🚨 {script_name} script: {desc} ({pattern})")
                                                is_safe = False

                                if install_scripts:
                                    console.print(f"  [bright_yellow]⚠️ Has install scripts:[/bright_yellow] {', '.join(install_scripts)}")
                                    for sn in install_scripts:
                                        sc = scripts.get(sn, '')[:100]
                                        console.print(f"    [dim]{sn}: {sc}...[/dim]")
                                else:
                                    console.print(f"  [bright_green]✓ No install scripts[/bright_green]")
                                    info_items.append("No install scripts detected")

                            except json.JSONDecodeError:
                                warnings.append("Could not parse package metadata")
                        else:
                            warnings.append(f"Could not fetch package info: {npm_view.stderr[:100]}")

                        # PHASE 2: Take BEFORE snapshot
                        console.print(f"\n[bright_cyan]━━━ PHASE 2: Pre-Install Snapshot ━━━[/bright_cyan]")
                        before_snapshot = get_dir_snapshot(Path(sandbox_dir))
                        console.print(f"[success]✓ Captured baseline ({len(before_snapshot)} files)[/success]")

                        # PHASE 3: INSTALL the package (this runs install scripts!)
                        console.print(f"\n[bright_cyan]━━━ PHASE 3: Installing Package (DANGEROUS ZONE) ━━━[/bright_cyan]")
                        console.print(f"[warning]⚡ Running npm install - install scripts WILL execute[/warning]")

                        # Use --ignore-scripts=false to ensure scripts run (default behavior)
                        # Set HOME to sandbox to prevent credential theft
                        install_env = os.environ.copy()
                        install_env['HOME'] = sandbox_dir
                        install_env['NPM_CONFIG_CACHE'] = str(Path(sandbox_dir) / '.npm-cache')

                        install_result = subprocess.run(
                            ["npm", "install", pkg_name, "--no-save", "--prefix", sandbox_dir],
                            capture_output=True, text=True, cwd=sandbox_dir,
                            timeout=120, env=install_env
                        )

                        if install_result.returncode != 0:
                            console.print(f"[danger]❌ Install failed: {install_result.stderr[:200]}[/danger]")
                            # Check if failure was due to malicious script
                            if 'ELIFECYCLE' in install_result.stderr:
                                dangers.append("Install script failed - possibly malicious or broken")
                            else:
                                warnings.append(f"Install failed: {install_result.stderr[:100]}")
                        else:
                            console.print(f"[success]✓ Package installed[/success]")

                        # PHASE 4: Take AFTER snapshot and compare
                        console.print(f"\n[bright_cyan]━━━ PHASE 4: Post-Install Analysis ━━━[/bright_cyan]")
                        after_snapshot = get_dir_snapshot(Path(sandbox_dir))
                        console.print(f"[info]Captured post-install state ({len(after_snapshot)} files)[/info]")

                        new_files, modified_files, deleted_files = compare_snapshots(before_snapshot, after_snapshot)

                        # Expected file patterns (not suspicious)
                        expected_patterns = [
                            'node_modules/',      # Package files
                            '.npm-cache/',        # npm cache (we set NPM_CONFIG_CACHE)
                            'package-lock.json',  # Lock file created by npm
                            'package.json',       # May be modified by npm
                        ]

                        # Filter for truly suspicious files
                        suspicious_new = []
                        for f in new_files:
                            # Skip expected files
                            is_expected = any(pattern in f for pattern in expected_patterns)
                            if is_expected:
                                continue
                            # Flag files created in unexpected locations
                            suspicious_new.append(f)

                        if suspicious_new:
                            console.print(f"[danger]🚨 Suspicious files created OUTSIDE expected locations:[/danger]")
                            for sf in suspicious_new[:10]:
                                console.print(f"  [danger]+ {sf}[/danger]")
                                dangers.append(f"Suspicious file created: {sf}")
                                is_safe = False
                        else:
                            console.print(f"  [bright_green]✓ No suspicious files created outside node_modules[/bright_green]")

                        # Count installed files
                        node_modules_files = [f for f in new_files if 'node_modules/' in f]
                        npm_cache_files = [f for f in new_files if '.npm-cache/' in f]
                        console.print(f"  [dim]Installed {len(node_modules_files)} package files, {len(npm_cache_files)} cache files[/dim]")

                        # PHASE 5: Deep scan installed code
                        console.print(f"\n[bright_cyan]━━━ PHASE 5: Deep Code Analysis ━━━[/bright_cyan]")

                        node_modules = Path(sandbox_dir) / "node_modules" / pkg_name.split('/')[0] if '/' in pkg_name else Path(sandbox_dir) / "node_modules" / pkg_name

                        if node_modules.exists():
                            # Scan for malicious patterns in installed code
                            console.print(f"[info]🔍 Scanning installed code for malware patterns...[/info]")

                            malware_patterns = [
                                (r'eval\s*\(', 'eval() - dynamic code execution'),
                                (r'Function\s*\(', 'Function constructor - dynamic code'),
                                (r'child_process', 'child_process - command execution'),
                                (r'\.exec\s*\(', 'exec() - command execution'),
                                (r'\.spawn\s*\(', 'spawn() - process spawning'),
                                (r'require\s*\(\s*[\'"]fs[\'"]\s*\)', 'filesystem access'),
                                (r'require\s*\(\s*[\'"]net[\'"]\s*\)', 'network access'),
                                (r'require\s*\(\s*[\'"]http[\'"]\s*\)', 'HTTP client'),
                                (r'require\s*\(\s*[\'"]https[\'"]\s*\)', 'HTTPS client'),
                                (r'process\.env', 'environment variable access'),
                                (r'Buffer\.from\([^)]+,\s*[\'"]base64[\'"]', 'base64 decoding'),
                                (r'atob\s*\(', 'base64 decoding (atob)'),
                                (r'\\x[0-9a-fA-F]{2}', 'hex-encoded strings'),
                                (r'\\u[0-9a-fA-F]{4}', 'unicode-encoded strings'),
                                (r'cryptocurrency|bitcoin|monero|wallet', 'cryptocurrency references'),
                                (r'keylog|keystroke', 'keylogger indicators'),
                                (r'screenshot|screen.capture', 'screen capture'),
                                (r'credential|password.*steal', 'credential theft'),
                                (r'reverse.shell|bind.shell', 'shell backdoor'),
                            ]

                            import re
                            files_scanned = 0
                            malware_hits = []

                            for js_file in node_modules.rglob("*.js"):
                                files_scanned += 1
                                try:
                                    content = js_file.read_text(errors='ignore')
                                    for pattern, desc in malware_patterns:
                                        if re.search(pattern, content, re.IGNORECASE):
                                            rel_path = str(js_file.relative_to(node_modules))
                                            malware_hits.append((rel_path, desc))
                                except:
                                    pass

                            console.print(f"  [dim]Scanned {files_scanned} JavaScript files[/dim]")

                            # Group and report malware hits
                            if malware_hits:
                                # Count by type
                                hit_types = {}
                                for _, desc in malware_hits:
                                    hit_types[desc] = hit_types.get(desc, 0) + 1

                                # Dangerous patterns
                                dangerous_types = ['eval', 'child_process', 'exec', 'spawn', 'reverse', 'backdoor', 'keylog', 'credential']
                                for hit_type, count in hit_types.items():
                                    is_dangerous = any(d in hit_type.lower() for d in dangerous_types)
                                    if is_dangerous:
                                        dangers.append(f"🚨 {hit_type}: {count} occurrences")
                                        is_safe = False
                                    else:
                                        # Common patterns like fs/http are warnings not dangers
                                        warnings.append(f"⚠️ {hit_type}: {count} occurrences")

                            else:
                                console.print(f"  [bright_green]✓ No obvious malware patterns[/bright_green]")
                                info_items.append("No malware patterns detected in code")

                        # PHASE 6: Check for known CVEs
                        console.print(f"\n[bright_cyan]━━━ PHASE 6: CVE Database Check ━━━[/bright_cyan]")
                        try:
                            from scanners import get_all_scanners
                            cve_found = False
                            for scanner_obj in get_all_scanners():
                                try:
                                    scan_result = scanner_obj.scan_directory(str(Path(sandbox_dir) / "node_modules"), recursive=True, max_depth=3)
                                    if scan_result and scan_result.findings:
                                        cve_found = True
                                        for finding in scan_result.findings:
                                            sev = finding.severity.value if hasattr(finding.severity, 'value') else str(finding.severity)
                                            if sev.upper() in ["CRITICAL", "HIGH"]:
                                                is_safe = False
                                                dangers.append(f"🔴 {finding.cve_id}: {finding.title}")
                                            else:
                                                warnings.append(f"🟡 {finding.cve_id}: {finding.title}")
                                except:
                                    pass
                            if not cve_found:
                                console.print(f"  [bright_green]✓ No known CVEs found[/bright_green]")
                                info_items.append("No known CVEs")
                        except Exception as e:
                            console.print(f"  [dim]CVE check skipped: {e}[/dim]")

                        # PHASE 7: Typosquatting check
                        console.print(f"\n[bright_cyan]━━━ PHASE 7: Typosquatting Analysis ━━━[/bright_cyan]")
                        popular_packages = [
                            "react", "lodash", "express", "axios", "moment", "jquery",
                            "vue", "angular", "webpack", "babel", "typescript", "eslint",
                            "prettier", "jest", "mocha", "chai", "underscore", "async",
                            "request", "bluebird", "chalk", "commander", "inquirer",
                            "debug", "uuid", "dotenv", "cors", "body-parser", "mongoose",
                            "sequelize", "redux", "next", "gatsby", "nuxt", "svelte"
                        ]

                        pkg_lower = pkg_name.lower().split('/')[-1]  # Handle scoped packages
                        for popular in popular_packages:
                            if pkg_lower != popular:
                                similarity = difflib.SequenceMatcher(None, popular, pkg_lower).ratio()
                                if similarity > 0.75 and similarity < 1.0:
                                    warnings.append(f"⚠️ Similar to '{popular}' ({similarity:.0%}) - typosquat risk?")
                                    console.print(f"  [warning]Name '{pkg_lower}' is {similarity:.0%} similar to '{popular}'[/warning]")

                        if not any('typosquat' in w.lower() for w in warnings):
                            console.print(f"  [bright_green]✓ No typosquatting detected[/bright_green]")

                    except subprocess.TimeoutExpired:
                        console.print("[danger]❌ Install timed out (>120s)[/danger]")
                        dangers.append("Install timed out - suspicious long-running scripts")
                        is_safe = False
                    except Exception as e:
                        console.print(f"[danger]❌ Error: {e}[/danger]")
                        dangers.append(f"Analysis error: {str(e)}")
                        is_safe = False
                    finally:
                        # ALWAYS destroy sandbox completely
                        if sandbox_dir and Path(sandbox_dir).exists():
                            console.print(f"\n[bright_cyan]━━━ CLEANUP ━━━[/bright_cyan]")
                            console.print(f"[dim]🗑️  Destroying sandbox...[/dim]")
                            try:
                                shutil.rmtree(sandbox_dir, ignore_errors=True)
                                console.print(f"[success]✓ Sandbox destroyed - no traces remain[/success]")
                            except:
                                console.print(f"[warning]Cleanup may be incomplete - manually remove: {sandbox_dir}[/warning]")

                    # FINAL VERDICT
                    console.print(f"\n{'═' * 60}")
                    console.print(f"[title]📊 ANALYSIS SUMMARY[/title]")
                    console.print(f"{'═' * 60}")

                    if dangers:
                        console.print(f"\n[danger]🚫 DANGERS ({len(dangers)}):[/danger]")
                        for d in dangers[:10]:  # Limit display
                            console.print(f"  [danger]{d}[/danger]")
                        if len(dangers) > 10:
                            console.print(f"  [dim]... and {len(dangers) - 10} more[/dim]")

                    if warnings:
                        console.print(f"\n[warning]⚠️  WARNINGS ({len(warnings)}):[/warning]")
                        for w in warnings[:10]:
                            console.print(f"  [warning]{w}[/warning]")
                        if len(warnings) > 10:
                            console.print(f"  [dim]... and {len(warnings) - 10} more[/dim]")

                    if info_items and not dangers:
                        console.print(f"\n[success]✓ PASSED CHECKS:[/success]")
                        for item in info_items:
                            console.print(f"  [success]✓ {item}[/success]")

                    console.print(f"\n{'═' * 60}")

                    if is_safe and not dangers:
                        console.print(Panel(
                            f"[success]✅ APPEARS SAFE TO DOWNLOAD[/success]\n\n"
                            f"Package '{pkg_name}' passed security analysis.\n"
                            f"[dim]Note: No automated scan is 100% - review code if handling sensitive data[/dim]\n\n"
                            f"Install with: [bright_white]npm install {pkg_name}[/bright_white]",
                            title="🛡️ VERDICT",
                            border_style="bright_green"
                        ))
                        next_step_type = "sandbox_safe"
                    else:
                        console.print(Panel(
                            f"[danger]🚫 DO NOT INSTALL[/danger]\n\n"
                            f"Package '{pkg_name}' has [bright_red]{len(dangers)}[/bright_red] security issue(s)!\n\n"
                            f"[bright_yellow]Recommendations:[/bright_yellow]\n"
                            f"• Search for alternative packages\n"
                            f"• Report to npm if malicious\n"
                            f"• Check package on snyk.io or socket.dev",
                            title="🛡️ VERDICT",
                            border_style="bright_red"
                        ))
                        next_step_type = "sandbox_danger"

                elif cmd_name == "live":
                    url = cmd_args[-1] if cmd_args else ""
                    scanner_name = "all"
                    for i, arg in enumerate(cmd_args):
                        if arg in ["-s", "--scanner"] and i + 1 < len(cmd_args):
                            scanner_name = cmd_args[i + 1]
                    live(url=url, scanner=scanner_name, timeout=10, output=None, verbose=False)
                    next_step_type = "live_clean"

                elif cmd_name == "cves":
                    sev = None
                    cat = None
                    bounty_flag = False
                    for i, arg in enumerate(cmd_args):
                        if arg in ["--severity", "-s"] and i + 1 < len(cmd_args):
                            sev = cmd_args[i + 1]
                        elif arg in ["--category", "-c"] and i + 1 < len(cmd_args):
                            cat = cmd_args[i + 1]
                        elif arg in ["--bounty", "-b"]:
                            bounty_flag = True
                    cves(severity=sev, category=cat, bounty=bounty_flag)
                    next_step_type = "cves"

                elif cmd_name == "info":
                    cve_id = cmd_args[0] if cmd_args else ""
                    info(cve_id=cve_id)
                    next_step_type = "cve_detail"

                elif cmd_name == "scanners":
                    scanners()
                    next_step_type = "scanners"

                elif cmd_name == "version":
                    version()

                elif cmd_name == "malware-scan":
                    # Deep or quick malware scan
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."
                    deep = "--deep" in cmd_args
                    scan_node_modules = deep  # Deep scan includes node_modules

                    console.print(f"\n[title]🦠 Malware Analysis {'(Deep)' if deep else '(Quick)'}[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]")
                    console.print(f"[info]Scanning node_modules: {'Yes' if scan_node_modules else 'No'}[/info]\n")

                    analyzer = MalwareAnalyzer()
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Scanning for malicious code...", total=None)
                        report = analyzer.scan_directory(
                            path,
                            recursive=True,
                            max_depth=15 if deep else 5,
                            scan_node_modules=scan_node_modules
                        )
                        progress.remove_task(task)

                    # Display results
                    if report.matches:
                        console.print(f"\n[danger]🚨 MALICIOUS CODE DETECTED![/danger]")
                        console.print(f"[warning]Found {len(report.matches)} malicious patterns in {report.files_scanned} files[/warning]\n")

                        # Group by threat level
                        critical = [m for m in report.matches if m.threat_level == ThreatLevel.CRITICAL]
                        high = [m for m in report.matches if m.threat_level == ThreatLevel.HIGH]
                        medium = [m for m in report.matches if m.threat_level == ThreatLevel.MEDIUM]

                        if critical:
                            console.print(f"[critical]  🔴 CRITICAL: {len(critical)}[/critical]")
                        if high:
                            console.print(f"[high]  🟠 HIGH: {len(high)}[/high]")
                        if medium:
                            console.print(f"[medium]  🟡 MEDIUM: {len(medium)}[/medium]")

                        console.print()

                        # Show top findings
                        for match in report.matches[:10]:
                            sev = match.threat_level.value
                            style = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else "warning"
                            console.print(f"[{style}]┌─ {match.pattern_name} ({sev})[/{style}]")
                            console.print(f"[path]│  File: {match.file_path}:{match.line_number}[/path]")
                            console.print(f"[info]│  Type: {match.malware_type.value}[/info]")
                            if match.cve_ids:
                                console.print(f"[warning]│  CVEs: {', '.join(match.cve_ids)}[/warning]")
                            console.print(f"[subtitle]│  {match.explanation[:80]}...[/subtitle]")
                            console.print(f"[success]└─ {match.remediation}[/success]\n")

                        if len(report.matches) > 10:
                            console.print(f"[dim]... and {len(report.matches) - 10} more findings[/dim]")

                        # Save report
                        report_path = Path("/tmp/shellockolm/malware_report.json")
                        analyzer.generate_report(report, str(report_path))
                        console.print(f"\n[info]📋 Full report saved: {report_path}[/info]")

                        had_findings = True
                        next_step_type = "malware_scan"
                    else:
                        console.print(Panel(
                            "[success]✅ No malicious code detected![/success]\n\n"
                            f"🔍 Scanned {report.files_scanned} files\n"
                            f"⏱️  Duration: {report.duration:.2f}s\n"
                            "[subtitle]Your project appears clean![/subtitle]",
                            title="🎉 Status: CLEAN",
                            border_style="bright_green",
                        ))
                        next_step_type = "malware_clean_result"

                elif cmd_name == "malware-quarantine":
                    file_path = cmd_args[0] if cmd_args else ""
                    if not file_path or not Path(file_path).exists():
                        console.print(f"[danger]File not found: {file_path}[/danger]")
                    else:
                        analyzer = MalwareAnalyzer()
                        # First scan the file to get matches
                        matches = analyzer.scan_file(file_path)
                        if matches:
                            from malware_analyzer import AnalysisReport
                            report = AnalysisReport()
                            report.matches = matches
                            if analyzer.quarantine_file(file_path, report):
                                console.print(f"[success]✅ File quarantined successfully![/success]")
                                console.print(f"[path]Original: {file_path}[/path]")
                                console.print(f"[warning]Quarantine: /tmp/shellockolm/quarantine/[/warning]")
                            else:
                                console.print(f"[danger]Failed to quarantine file[/danger]")
                        else:
                            console.print(f"[warning]No malicious code detected in file. Quarantine anyway? (y/n)[/warning]")
                            if prompt(">>> ").strip().lower() in ['y', 'yes']:
                                from malware_analyzer import AnalysisReport
                                report = AnalysisReport()
                                if analyzer.quarantine_file(file_path, report):
                                    console.print(f"[success]✅ File quarantined[/success]")
                    next_step_type = "malware_action"

                elif cmd_name == "malware-remove":
                    if len(cmd_args) >= 2:
                        pkg_name = cmd_args[0]
                        project_path = cmd_args[1]
                    else:
                        console.print("[danger]Usage: malware-remove <package-name> <project-path>[/danger]")
                        show_menu = False
                        continue

                    analyzer = MalwareAnalyzer()
                    from malware_analyzer import AnalysisReport
                    report = AnalysisReport()

                    console.print(f"[warning]⚠️  This will REMOVE package '{pkg_name}' from {project_path}[/warning]")
                    console.print("[bold]Are you sure? [Y]es / [N]o[/bold]")
                    if prompt(">>> ").strip().lower() in ['y', 'yes']:
                        if analyzer.remove_package(pkg_name, project_path, report):
                            console.print(f"[success]✅ Package '{pkg_name}' removed![/success]")
                            console.print(f"[info]Backup saved to quarantine folder[/info]")
                        else:
                            console.print(f"[danger]Failed to remove package[/danger]")
                    else:
                        console.print("[info]Operation cancelled[/info]")
                    next_step_type = "malware_action"

                elif cmd_name == "malware-clean":
                    file_path = cmd_args[0] if cmd_args else ""
                    if not file_path or not Path(file_path).exists():
                        console.print(f"[danger]File not found: {file_path}[/danger]")
                    else:
                        analyzer = MalwareAnalyzer()
                        matches = analyzer.scan_file(file_path)
                        if matches:
                            console.print(f"[warning]Found {len(matches)} malicious patterns in file[/warning]")
                            for m in matches:
                                console.print(f"  [danger]• {m.pattern_name}[/danger] at line {m.line_number}")

                            console.print("\n[bold]Clean malicious code? [Y]es / [N]o[/bold]")
                            if prompt(">>> ").strip().lower() in ['y', 'yes']:
                                from malware_analyzer import AnalysisReport
                                report = AnalysisReport()
                                if analyzer.clean_malicious_code(file_path, matches, report):
                                    console.print(f"[success]✅ Malicious code removed![/success]")
                                    console.print(f"[info]Backup saved with .backup extension[/info]")
                                else:
                                    console.print(f"[danger]Failed to clean file[/danger]")
                            else:
                                console.print("[info]Operation cancelled[/info]")
                        else:
                            console.print(f"[success]No malicious code detected in file[/success]")
                    next_step_type = "malware_action"

                elif cmd_name == "malware-report":
                    report_path = Path("/tmp/shellockolm/malware_report.json")
                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)

                        console.print(Panel(
                            f"[title]Malware Analysis Report[/title]\n\n"
                            f"[info]Scan Time:[/info] {report_data.get('scan_time', 'N/A')}\n"
                            f"[info]Target:[/info] {report_data.get('target_path', 'N/A')}\n"
                            f"[info]Files Scanned:[/info] {report_data.get('files_scanned', 0)}\n"
                            f"[info]Duration:[/info] {report_data.get('duration', 0):.2f}s\n\n"
                            f"[danger]Total Findings:[/danger] {report_data.get('total_matches', 0)}\n"
                            f"[critical]Critical:[/critical] {report_data.get('critical_count', 0)}\n"
                            f"[high]High:[/high] {report_data.get('high_count', 0)}\n"
                            f"[medium]Medium:[/medium] {report_data.get('medium_count', 0)}",
                            title="🦠 Latest Malware Report",
                            border_style="bright_red",
                        ))

                        # Show findings summary
                        findings = report_data.get('matches', [])
                        if findings:
                            console.print("\n[title]Top Findings:[/title]")
                            for f in findings[:5]:
                                console.print(f"  [{f.get('threat_level', 'unknown').lower()}]• {f.get('pattern_name')}[/{f.get('threat_level', 'unknown').lower()}]")
                                console.print(f"    [path]{f.get('file_path')}:{f.get('line_number')}[/path]")
                    else:
                        console.print("[warning]No malware report found. Run a malware scan first.[/warning]")
                    next_step_type = "malware_report"

                # ─────────────────────────────────────────────────────────
                # SECRETS SCANNER COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name in ["secrets-scan", "secrets-env", "secrets-entropy"]:
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."
                    env_only = cmd_name == "secrets-env"
                    entropy_mode = cmd_name == "secrets-entropy"

                    console.print(f"\n[title]🔐 Secrets Scanner{' (.env)' if env_only else ' (Entropy)' if entropy_mode else ''}[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    scanner = SecretsScanner()
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Scanning for exposed secrets...", total=None)
                        # Scan directory for secrets
                        report = scanner.scan_directory(path)
                        progress.remove_task(task)

                    # Display results
                    if report.matches:
                        console.print(f"\n[danger]🚨 EXPOSED SECRETS DETECTED![/danger]")
                        console.print(f"[warning]Found {len(report.matches)} exposed secrets in {report.files_scanned} files[/warning]\n")

                        # Group by severity using pattern's severity enum
                        from secrets_scanner import SecretSeverity
                        critical = [m for m in report.matches if m.pattern.severity == SecretSeverity.CRITICAL]
                        high = [m for m in report.matches if m.pattern.severity == SecretSeverity.HIGH]
                        medium = [m for m in report.matches if m.pattern.severity == SecretSeverity.MEDIUM]

                        if critical:
                            console.print(f"[critical]  🔴 CRITICAL: {len(critical)}[/critical]")
                        if high:
                            console.print(f"[high]  🟠 HIGH: {len(high)}[/high]")
                        if medium:
                            console.print(f"[medium]  🟡 MEDIUM: {len(medium)}[/medium]")

                        console.print()

                        # Show top findings
                        for match in report.matches[:10]:
                            sev = match.pattern.severity.value
                            style = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else "warning"
                            console.print(f"[{style}]┌─ {match.pattern.name} ({sev})[/{style}]")
                            console.print(f"[path]│  File: {match.file_path}:{match.line_number}[/path]")
                            console.print(f"[info]│  Type: {match.pattern.secret_type.value}[/info]")
                            console.print(f"[warning]│  Value: {match.masked_value}[/warning]")
                            console.print(f"[success]└─ {match.pattern.remediation}[/success]\n")

                        if len(report.matches) > 10:
                            console.print(f"[dim]... and {len(report.matches) - 10} more findings[/dim]")

                        # Save report
                        report_path = Path("/tmp/shellockolm/secrets_report.json")
                        scanner.generate_report(report, str(report_path))
                        console.print(f"\n[info]📋 Full report saved: {report_path}[/info]")

                        had_findings = True
                        next_step_type = "secrets_scan"
                    else:
                        console.print(Panel(
                            "[success]✅ No exposed secrets detected![/success]\n\n"
                            f"🔍 Scanned {report.files_scanned} files\n"
                            f"⏱️  Duration: {report.duration:.2f}s\n"
                            "[subtitle]Your secrets appear safe![/subtitle]",
                            title="🎉 Status: CLEAN",
                            border_style="bright_green",
                        ))
                        next_step_type = "secrets_clean"

                elif cmd_name == "secrets-report":
                    report_path = Path("/tmp/shellockolm/secrets_report.json")
                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)

                        console.print(Panel(
                            f"[title]Secrets Scan Report[/title]\n\n"
                            f"[info]Scan Time:[/info] {report_data.get('scan_time', 'N/A')}\n"
                            f"[info]Target:[/info] {report_data.get('target_path', 'N/A')}\n"
                            f"[info]Files Scanned:[/info] {report_data.get('files_scanned', 0)}\n"
                            f"[info]Duration:[/info] {report_data.get('duration', 0):.2f}s\n\n"
                            f"[danger]Total Secrets:[/danger] {report_data.get('total_matches', 0)}\n"
                            f"[critical]Critical:[/critical] {report_data.get('critical_count', 0)}\n"
                            f"[high]High:[/high] {report_data.get('high_count', 0)}\n"
                            f"[medium]Medium:[/medium] {report_data.get('medium_count', 0)}",
                            title="🔐 Latest Secrets Report",
                            border_style="bright_magenta",
                        ))

                        findings = report_data.get('matches', [])
                        if findings:
                            console.print("\n[title]Top Findings:[/title]")
                            for f in findings[:5]:
                                console.print(f"  [danger]• {f.get('pattern_name')}[/danger]")
                                console.print(f"    [path]{f.get('file_path')}:{f.get('line_number')}[/path]")
                    else:
                        console.print("[warning]No secrets report found. Run a secrets scan first.[/warning]")
                    next_step_type = "secrets_report"

                # ─────────────────────────────────────────────────────────
                # SECURITY SCORE COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name in ["security-score", "security-quick"]:
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."
                    quick_mode = cmd_name == "security-quick"

                    console.print(f"\n[title]📊 Security Score Calculator{' (Quick)' if quick_mode else ''}[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    calculator = SecurityScoreCalculator()
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Analyzing security posture...", total=None)
                        report = calculator.calculate_score(path)
                        progress.remove_task(task)

                    # Display grade with big ASCII art
                    grade_value = report.grade.value  # Get string from enum
                    grade_letter = grade_value[0]  # Get first letter for color lookup
                    grade_colors = {
                        "A": "bright_green", "B": "green", "C": "bright_yellow",
                        "D": "yellow", "F": "bright_red"
                    }
                    grade_color = grade_colors.get(grade_letter, "white")

                    # Grade summaries
                    grade_summaries = {
                        "A+": "Excellent security posture!",
                        "A": "Very good security!",
                        "B": "Good, but room for improvement",
                        "C": "Needs attention",
                        "D": "Poor security - action required",
                        "F": "Critical issues detected!"
                    }
                    summary = grade_summaries.get(grade_value, "Review needed")

                    grade_art = f"""
[{grade_color}]
   ██████╗ ██████╗  █████╗ ██████╗ ███████╗
  ██╔════╝ ██╔══██╗██╔══██╗██╔══██╗██╔════╝
  ██║  ███╗██████╔╝███████║██║  ██║█████╗
  ██║   ██║██╔══██╗██╔══██║██║  ██║██╔══╝
  ╚██████╔╝██║  ██║██║  ██║██████╔╝███████╗
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝ ╚══════╝
                    {grade_value}
[/{grade_color}]"""
                    console.print(grade_art)

                    console.print(f"[{grade_color}]Overall Score: {report.score}/100[/{grade_color}]")
                    console.print(f"[info]Grade: {grade_value} - {summary}[/info]\n")

                    # Show breakdown - ScoreBreakdown is a dataclass with numeric attributes
                    console.print("[title]Category Breakdown:[/title]")
                    breakdown_items = [
                        ("Vulnerabilities", report.breakdown.vulnerabilities),
                        ("Malware", report.breakdown.malware),
                        ("Secrets", report.breakdown.secrets),
                        ("Dependencies", report.breakdown.dependencies),
                        ("Configuration", report.breakdown.configuration),
                    ]
                    for cat_name, cat_score in breakdown_items:
                        cat_grade = calculator.score_to_grade(cat_score).value
                        cat_color = grade_colors.get(cat_grade[0], "white")
                        console.print(f"  [{cat_color}]{cat_name}: {cat_score}/100 ({cat_grade})[/{cat_color}]")

                    console.print()

                    # Show recommendations
                    if report.recommendations:
                        console.print("[title]Top Recommendations:[/title]")
                        for rec in report.recommendations[:5]:
                            console.print(f"  [warning]• {rec}[/warning]")

                    # Save report
                    report_path = Path("/tmp/shellockolm/security_report.json")
                    calculator.generate_report(report, str(report_path))
                    console.print(f"\n[info]📋 Full report saved: {report_path}[/info]")

                    next_step_type = "security_score" if report.score < 80 else "security_clean"

                elif cmd_name == "security-report":
                    report_path = Path("/tmp/shellockolm/security_report.json")
                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)

                        grade = report_data.get('grade', 'F')
                        score = report_data.get('score', 0)
                        grade_colors = {"A": "bright_green", "B": "green", "C": "bright_yellow", "D": "yellow", "F": "bright_red"}

                        console.print(Panel(
                            f"[title]Security Score Report[/title]\n\n"
                            f"[info]Scan Time:[/info] {report_data.get('scan_time', 'N/A')}\n"
                            f"[info]Target:[/info] {report_data.get('target_path', 'N/A')}\n\n"
                            f"[{grade_colors.get(grade, 'white')}]Grade: {grade} ({score}/100)[/{grade_colors.get(grade, 'white')}]\n"
                            f"[info]{report_data.get('summary', '')}[/info]",
                            title="📊 Latest Security Report",
                            border_style="bright_blue",
                        ))

                        breakdown = report_data.get('breakdown', {})
                        if breakdown:
                            console.print("\n[title]Category Breakdown:[/title]")
                            for cat, data in breakdown.items():
                                console.print(f"  {cat}: {data.get('score', 0)}/100 ({data.get('grade', 'F')})")
                    else:
                        console.print("[warning]No security report found. Run a security score first.[/warning]")
                    next_step_type = "security_report"

                # ─────────────────────────────────────────────────────────
                # AUTO-FIX COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name in ["autofix-scan", "autofix-preview"]:
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."
                    preview_only = cmd_name == "autofix-preview"

                    console.print(f"\n[title]🔧 Auto-Fix{' (Preview)' if preview_only else ''}[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    fixer = AutoFixer()
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Scanning for vulnerable packages...", total=None)
                        # scan_project returns List[VulnerableDependency]
                        vulns = fixer.scan_project(path)
                        progress.remove_task(task)

                    if vulns:
                        console.print(f"[warning]Found {len(vulns)} vulnerable packages:[/warning]\n")

                        for pkg in vulns:
                            console.print(f"[danger]┌─ {pkg.name} @ {pkg.current_version}[/danger]")
                            console.print(f"[success]│  Fix: Upgrade to {pkg.patched_version or 'latest'}[/success]")
                            if pkg.cve_ids:
                                console.print(f"[warning]│  CVEs: {', '.join(pkg.cve_ids)}[/warning]")
                            console.print(f"[info]└─ Severity: {pkg.severity.value}[/info]\n")

                        if preview_only:
                            console.print("[info]Preview mode - no changes made[/info]")
                            next_step_type = "autofix_preview"
                        else:
                            console.print("[bold]Apply fixes? [Y]es / [N]o[/bold]")
                            if prompt(">>> ").strip().lower() in ['y', 'yes']:
                                with Progress(
                                    SpinnerColumn(),
                                    TextColumn("[progress.description]{task.description}"),
                                    console=console,
                                ) as progress:
                                    task = progress.add_task("[success]Applying fixes...", total=None)
                                    # fix_all does scan + fix, returns FixReport
                                    fix_report = fixer.fix_all(path, dry_run=False)
                                    progress.remove_task(task)

                                console.print(f"[success]✅ Fixed {fix_report.fixed} packages![/success]")
                                if fix_report.failed > 0:
                                    console.print(f"[warning]⚠️  Failed: {fix_report.failed}[/warning]")
                                if fix_report.manual_required > 0:
                                    console.print(f"[info]ℹ️  Manual fix required: {fix_report.manual_required}[/info]")
                                if fix_report.backup_dir:
                                    console.print(f"[info]Backup saved: {fix_report.backup_dir}[/info]")
                            else:
                                console.print("[info]Operation cancelled[/info]")
                            next_step_type = "autofix_scan"
                    else:
                        console.print(Panel(
                            "[success]✅ No vulnerable packages found![/success]\n\n"
                            "All dependencies are up to date with security patches.\n"
                            "[subtitle]Great job keeping your project secure![/subtitle]",
                            title="🎉 Status: SECURE",
                            border_style="bright_green",
                        ))
                        next_step_type = "autofix_preview"

                elif cmd_name == "autofix-rollback":
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."

                    console.print(f"\n[title]🔧 Auto-Fix Rollback[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    fixer = AutoFixer()
                    # Look for backup in the default backup directory
                    backup_dir = Path("/tmp/shellockolm/backups")

                    # Find most recent backup for this project
                    backups = sorted(backup_dir.glob("*"), reverse=True) if backup_dir.exists() else []
                    if backups:
                        latest_backup = backups[0]
                        console.print(f"[warning]Found backup: {latest_backup}[/warning]")
                        console.print("[bold]Restore from backup? [Y]es / [N]o[/bold]")
                        if prompt(">>> ").strip().lower() in ['y', 'yes']:
                            if fixer.rollback(str(latest_backup), path):
                                console.print(f"[success]✅ Restored package.json from backup![/success]")
                            else:
                                console.print(f"[danger]Failed to restore backup[/danger]")
                        else:
                            console.print("[info]Operation cancelled[/info]")
                    else:
                        console.print("[warning]No backup found. Nothing to rollback.[/warning]")
                    next_step_type = "autofix_rollback"

                # ─────────────────────────────────────────────────────────
                # LOCKFILE ANALYZER COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name in ["lockfile-analyze", "lockfile-duplicates", "lockfile-typosquat"]:
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."

                    # Find lockfile
                    lockfile_path = Path(path)
                    if lockfile_path.is_dir():
                        # Look for lockfile in directory
                        for lf in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
                            if (lockfile_path / lf).exists():
                                lockfile_path = lockfile_path / lf
                                break

                    console.print(f"\n[title]📦 Lockfile Analyzer[/title]")
                    console.print(f"[path]File: {lockfile_path}[/path]\n")

                    if not lockfile_path.exists():
                        console.print(f"[danger]Lockfile not found: {lockfile_path}[/danger]")
                        next_step_type = None
                        continue

                    analyzer = LockfileAnalyzer()
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Analyzing lockfile...", total=None)
                        report = analyzer.analyze(str(lockfile_path))
                        progress.remove_task(task)

                    # Display results
                    console.print(f"[info]Lockfile Type: {report.lockfile_type.value}[/info]")
                    console.print(f"[info]Total Packages: {report.total_packages}[/info]")
                    console.print(f"[info]Duration: {report.duration:.2f}s[/info]\n")

                    if report.issues:
                        console.print(f"[danger]🚨 Found {report.total_issues} issues![/danger]\n")

                        if report.critical:
                            console.print(f"[critical]  🔴 CRITICAL: {report.critical}[/critical]")
                        if report.high:
                            console.print(f"[high]  🟠 HIGH: {report.high}[/high]")
                        if report.medium:
                            console.print(f"[medium]  🟡 MEDIUM: {report.medium}[/medium]")
                        if report.low:
                            console.print(f"[low]  🔵 LOW: {report.low}[/low]")
                        if report.info:
                            console.print(f"[info]  ℹ️  INFO: {report.info}[/info]")

                        console.print()

                        # Show top issues based on mode
                        if cmd_name == "lockfile-duplicates":
                            issues_to_show = [i for i in report.issues if i.issue_type.value == "duplicate_package"]
                        elif cmd_name == "lockfile-typosquat":
                            issues_to_show = [i for i in report.issues if i.issue_type.value == "typosquatting"]
                        else:
                            issues_to_show = report.issues

                        for issue in issues_to_show[:10]:
                            sev = issue.severity.value
                            style = "critical" if sev == "CRITICAL" else "high" if sev == "HIGH" else "medium" if sev == "MEDIUM" else "info"
                            console.print(f"[{style}]┌─ {issue.title} ({sev})[/{style}]")
                            console.print(f"[path]│  Package: {issue.package_name}@{issue.current_version}[/path]")
                            if issue.cve_ids:
                                console.print(f"[warning]│  CVEs: {', '.join(issue.cve_ids)}[/warning]")
                            console.print(f"[success]└─ {issue.remediation}[/success]\n")

                        if len(issues_to_show) > 10:
                            console.print(f"[dim]... and {len(issues_to_show) - 10} more issues[/dim]")

                        # Save report
                        report_path = Path("/tmp/shellockolm/lockfile_report.json")
                        analyzer.generate_report(report, str(report_path))
                        console.print(f"\n[info]📋 Full report saved: {report_path}[/info]")

                        had_findings = True
                        next_step_type = "lockfile_scan"
                    else:
                        console.print(Panel(
                            "[success]✅ No lockfile issues detected![/success]\n\n"
                            f"🔍 Analyzed {report.total_packages} packages\n"
                            f"⏱️  Duration: {report.duration:.2f}s\n"
                            "[subtitle]Your lockfile looks healthy![/subtitle]",
                            title="🎉 Status: HEALTHY",
                            border_style="bright_green",
                        ))
                        next_step_type = "lockfile_clean"

                elif cmd_name == "lockfile-report":
                    report_path = Path("/tmp/shellockolm/lockfile_report.json")
                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)

                        summary = report_data.get("summary", {})
                        console.print(Panel(
                            f"[title]Lockfile Analysis Report[/title]\n\n"
                            f"[info]File:[/info] {report_data.get('file_path', 'N/A')}\n"
                            f"[info]Type:[/info] {report_data.get('lockfile_type', 'N/A')}\n"
                            f"[info]Scan Time:[/info] {report_data.get('scan_time', 'N/A')}\n\n"
                            f"[info]Total Packages:[/info] {summary.get('total_packages', 0)}\n"
                            f"[danger]Total Issues:[/danger] {summary.get('total_issues', 0)}\n"
                            f"[critical]Critical:[/critical] {summary.get('critical', 0)}\n"
                            f"[high]High:[/high] {summary.get('high', 0)}\n"
                            f"[medium]Medium:[/medium] {summary.get('medium', 0)}\n"
                            f"[info]Duplicates:[/info] {summary.get('duplicates', 0)}",
                            title="📦 Latest Lockfile Report",
                            border_style="bright_blue",
                        ))

                        issues = report_data.get('issues', [])
                        if issues:
                            console.print("\n[title]Top Issues:[/title]")
                            for issue in issues[:5]:
                                console.print(f"  [{issue.get('severity', 'info').lower()}]• {issue.get('title')}[/{issue.get('severity', 'info').lower()}]")
                    else:
                        console.print("[warning]No lockfile report found. Run a lockfile analysis first.[/warning]")
                    next_step_type = "lockfile_report"

                # ─────────────────────────────────────────────────────────
                # SARIF EXPORT COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name == "sarif-export":
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."

                    console.print(f"\n[title]📤 SARIF Export (CI/CD Integration)[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    sarif_gen = SarifGenerator()
                    total_findings = 0

                    # Run all scanners and collect results
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        # 1. CVE Scan
                        task = progress.add_task("[warning]Running CVE scan...", total=None)
                        try:
                            scanners = get_all_scanners()
                            for scanner in scanners:
                                result = scanner.scan(path)
                                if result.findings:
                                    sarif_gen.from_scan_results(result.findings)
                                    total_findings += len(result.findings)
                        except Exception as e:
                            console.print(f"[warning]CVE scan error: {e}[/warning]")
                        progress.remove_task(task)

                        # 2. Malware Scan
                        task = progress.add_task("[warning]Running malware scan...", total=None)
                        try:
                            malware = MalwareAnalyzer()
                            malware_report = malware.analyze_project(path)
                            if malware_report.matches:
                                sarif_gen.from_malware_report(malware_report)
                                total_findings += len(malware_report.matches)
                        except Exception as e:
                            console.print(f"[warning]Malware scan error: {e}[/warning]")
                        progress.remove_task(task)

                        # 3. Secrets Scan
                        task = progress.add_task("[warning]Running secrets scan...", total=None)
                        try:
                            secrets = SecretsScanner()
                            secrets_report = secrets.scan(path)
                            if secrets_report.matches:
                                sarif_gen.from_secrets_report(secrets_report)
                                total_findings += len(secrets_report.matches)
                        except Exception as e:
                            console.print(f"[warning]Secrets scan error: {e}[/warning]")
                        progress.remove_task(task)

                        # 4. Lockfile Scan
                        task = progress.add_task("[warning]Running lockfile scan...", total=None)
                        try:
                            lockfile = LockfileAnalyzer()
                            proj_path = Path(path)
                            for lf in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
                                lf_path = proj_path / lf if proj_path.is_dir() else proj_path
                                if lf_path.exists():
                                    lockfile_report = lockfile.analyze(str(lf_path))
                                    if lockfile_report.issues:
                                        sarif_gen.from_lockfile_report(lockfile_report)
                                        total_findings += len(lockfile_report.issues)
                                    break
                        except Exception as e:
                            console.print(f"[warning]Lockfile scan error: {e}[/warning]")
                        progress.remove_task(task)

                        # 5. Generate SARIF
                        task = progress.add_task("[warning]Generating SARIF report...", total=None)
                        sarif_path = Path("/tmp/shellockolm/sarif-report.sarif")
                        sarif_output = sarif_gen.generate(str(sarif_path))
                        progress.remove_task(task)

                    # Display results
                    console.print(Panel(
                        f"[title]SARIF Report Generated[/title]\n\n"
                        f"[info]Total Findings:[/info] {total_findings}\n"
                        f"[info]Rules Defined:[/info] {len(sarif_gen.rules)}\n"
                        f"[info]SARIF Version:[/info] 2.1.0\n\n"
                        f"[success]Output File:[/success] {sarif_path}\n\n"
                        f"[subtitle]Use this file with:[/subtitle]\n"
                        f"  • GitHub Code Scanning\n"
                        f"  • VS Code SARIF Viewer\n"
                        f"  • Any SARIF-compatible CI/CD tool",
                        title="📤 SARIF Export Complete",
                        border_style="bright_green" if total_findings == 0 else "bright_yellow",
                    ))

                    if total_findings > 0:
                        had_findings = True
                        console.print(f"\n[warning]🚨 Found {total_findings} issues![/warning]")
                    else:
                        console.print(f"\n[success]✅ No security issues found![/success]")

                    next_step_type = "sarif_export"

                elif cmd_name in ["sarif-view", "sarif-convert"]:
                    sarif_path = Path("/tmp/shellockolm/sarif-report.sarif")

                    if cmd_name == "sarif-convert":
                        console.print(f"\n[title]📤 SARIF Converter[/title]")
                        console.print(f"[subtitle]Converting last scan results to SARIF format...[/subtitle]\n")

                        sarif_gen = SarifGenerator()
                        total_findings = 0

                        # Try to load and convert existing reports
                        with Progress(
                            SpinnerColumn(),
                            TextColumn("[progress.description]{task.description}"),
                            console=console,
                        ) as progress:
                            # Load scan results JSON if exists
                            task = progress.add_task("[warning]Converting scan results...", total=None)
                            scan_report = Path("/tmp/shellockolm/sessions")
                            if scan_report.exists():
                                # Get most recent findings file
                                findings_files = sorted(scan_report.glob("findings_*.json"), reverse=True)
                                if findings_files:
                                    try:
                                        with open(findings_files[0]) as f:
                                            findings = json.load(f)
                                            for finding in findings:
                                                if "cve_id" in finding:
                                                    sarif_gen.add_cve_finding(
                                                        cve_id=finding.get("cve_id", "UNKNOWN"),
                                                        file_path=finding.get("file_path", "unknown"),
                                                        line_number=finding.get("line_number", 1),
                                                        message=finding.get("description", "No description"),
                                                        severity=finding.get("severity", "medium")
                                                    )
                                                    total_findings += 1
                                    except Exception:
                                        pass
                            progress.remove_task(task)

                            # Load malware report if exists
                            task = progress.add_task("[warning]Converting malware results...", total=None)
                            malware_report = Path("/tmp/shellockolm/malware_report.json")
                            if malware_report.exists():
                                try:
                                    with open(malware_report) as f:
                                        report = json.load(f)
                                        for match in report.get("matches", []):
                                            sarif_gen.add_malware_finding(
                                                pattern_id=match.get("pattern_id", "UNKNOWN"),
                                                pattern_name=match.get("pattern_name", "Unknown Pattern"),
                                                file_path=match.get("file_path", "unknown"),
                                                line_number=match.get("line_number", 1),
                                                message=match.get("explanation", "No explanation"),
                                                severity=match.get("threat_level", "medium")
                                            )
                                            total_findings += 1
                                except Exception:
                                    pass
                            progress.remove_task(task)

                            # Load lockfile report if exists
                            task = progress.add_task("[warning]Converting lockfile results...", total=None)
                            lockfile_report = Path("/tmp/shellockolm/lockfile_report.json")
                            if lockfile_report.exists():
                                try:
                                    with open(lockfile_report) as f:
                                        report = json.load(f)
                                        for issue in report.get("issues", []):
                                            rule_id = f"DEP-{issue.get('issue_type', 'unknown').upper()}"
                                            sarif_gen.add_result(SarifResult(
                                                rule_id=rule_id,
                                                message=f"{issue.get('title', 'Issue')}: {issue.get('description', '')}",
                                                file_path=report.get("file_path", "unknown"),
                                                start_line=issue.get("line_number", 1) or 1,
                                                level="warning"
                                            ))
                                            total_findings += 1
                                except Exception:
                                    pass
                            progress.remove_task(task)

                            # Generate SARIF
                            task = progress.add_task("[warning]Generating SARIF...", total=None)
                            sarif_gen.generate(str(sarif_path))
                            progress.remove_task(task)

                        console.print(Panel(
                            f"[title]SARIF Conversion Complete[/title]\n\n"
                            f"[info]Total Findings Converted:[/info] {total_findings}\n"
                            f"[success]Output File:[/success] {sarif_path}",
                            title="📤 Conversion Complete",
                            border_style="bright_green",
                        ))

                    else:  # sarif-view
                        console.print(f"\n[title]📤 SARIF Report Viewer[/title]\n")

                        if sarif_path.exists():
                            with open(sarif_path) as f:
                                sarif_data = json.load(f)

                            runs = sarif_data.get("runs", [])
                            if runs:
                                run = runs[0]
                                results = run.get("results", [])
                                rules = {r["id"]: r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}

                                console.print(Panel(
                                    f"[info]SARIF Version:[/info] {sarif_data.get('version', 'N/A')}\n"
                                    f"[info]Tool:[/info] {run.get('tool', {}).get('driver', {}).get('name', 'N/A')}\n"
                                    f"[info]Total Results:[/info] {len(results)}\n"
                                    f"[info]Rules Defined:[/info] {len(rules)}",
                                    title="📋 SARIF Report Summary",
                                    border_style="bright_blue",
                                ))

                                if results:
                                    console.print("\n[title]Findings:[/title]")
                                    for i, result in enumerate(results[:15], 1):
                                        rule_id = result.get("ruleId", "UNKNOWN")
                                        level = result.get("level", "warning")
                                        message = result.get("message", {}).get("text", "No message")[:80]
                                        loc = result.get("locations", [{}])[0].get("physicalLocation", {})
                                        file_path = loc.get("artifactLocation", {}).get("uri", "unknown")
                                        line = loc.get("region", {}).get("startLine", 1)

                                        level_style = {"error": "danger", "warning": "warning", "note": "info"}.get(level, "info")
                                        console.print(f"  [{level_style}]{i}. [{rule_id}][/{level_style}] {file_path}:{line}")
                                        console.print(f"     {message}")

                                    if len(results) > 15:
                                        console.print(f"\n  [subtitle]... and {len(results) - 15} more findings[/subtitle]")

                                console.print(f"\n[info]Full report: {sarif_path}[/info]")
                        else:
                            console.print("[warning]No SARIF report found. Run [37] SARIF Export first.[/warning]")

                    next_step_type = "sarif_view"

                # ─────────────────────────────────────────────────────────
                # GITHUB ADVISORY DATABASE COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name == "ghsa-query":
                    package_name = cmd_args[-1] if cmd_args else ""
                    if not package_name:
                        console.print("[danger]Please specify a package name[/danger]")
                        continue

                    console.print(f"\n[title]🐙 GitHub Advisory Database Query[/title]")
                    console.print(f"[path]Package: {package_name}[/path]\n")

                    ghsa_db = GitHubAdvisoryDB()

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Querying GitHub Advisory Database...", total=None)
                        result = ghsa_db.query_package(package_name)
                        progress.remove_task(task)

                    console.print(f"[info]From Cache:[/info] {'Yes' if result.from_cache else 'No'}")
                    console.print(f"[info]Advisories Found:[/info] {len(result.advisories)}\n")

                    if result.advisories:
                        had_findings = True
                        console.print(f"[danger]🚨 Found {len(result.advisories)} security advisories![/danger]\n")

                        for advisory in result.advisories[:10]:
                            severity_style = {
                                AdvisorySeverity.CRITICAL: "critical",
                                AdvisorySeverity.HIGH: "high",
                                AdvisorySeverity.MODERATE: "medium",
                                AdvisorySeverity.LOW: "low",
                            }.get(advisory.severity, "info")

                            console.print(f"[{severity_style}]● [{advisory.severity.value.upper()}] {advisory.ghsa_id}[/{severity_style}]")
                            if advisory.cve_id:
                                console.print(f"    CVE: {advisory.cve_id}")
                            console.print(f"    Summary: {advisory.summary[:70]}...")
                            if advisory.patched_versions:
                                patches = ", ".join(f"{k}@{v}" for k, v in advisory.patched_versions.items())
                                console.print(f"    [success]Patched in:[/success] {patches}")
                            console.print()

                        if len(result.advisories) > 10:
                            console.print(f"[subtitle]... and {len(result.advisories) - 10} more advisories[/subtitle]")

                        # Save report
                        report_path = Path("/tmp/shellockolm/ghsa_report.json")
                        ghsa_db.generate_report([package_name], str(report_path))
                        console.print(f"\n[info]📋 Full report: {report_path}[/info]")
                    else:
                        console.print(Panel(
                            f"[success]✅ No known vulnerabilities found for {package_name}![/success]\n\n"
                            "[subtitle]Package appears to be safe according to GitHub Advisory Database.[/subtitle]",
                            title="🎉 All Clear",
                            border_style="bright_green",
                        ))

                    next_step_type = "ghsa_query"

                elif cmd_name == "ghsa-check":
                    pkg_version = cmd_args[-1] if cmd_args else ""
                    if "@" not in pkg_version:
                        console.print("[danger]Please specify package@version (e.g., lodash@4.17.0)[/danger]")
                        continue

                    package_name, version = pkg_version.rsplit("@", 1)

                    console.print(f"\n[title]🐙 GitHub Advisory Version Check[/title]")
                    console.print(f"[path]Package: {package_name}@{version}[/path]\n")

                    ghsa_db = GitHubAdvisoryDB()

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Checking version...", total=None)
                        affected = ghsa_db.check_package_version(package_name, version)
                        progress.remove_task(task)

                    if affected:
                        had_findings = True
                        console.print(f"[danger]🚨 Version {version} is VULNERABLE![/danger]\n")
                        console.print(f"Affected by {len(affected)} advisories:\n")

                        for advisory in affected:
                            severity_style = {
                                AdvisorySeverity.CRITICAL: "critical",
                                AdvisorySeverity.HIGH: "high",
                            }.get(advisory.severity, "warning")

                            console.print(f"  [{severity_style}]● {advisory.ghsa_id}[/{severity_style}]")
                            if advisory.cve_id:
                                console.print(f"    CVE: {advisory.cve_id}")
                            if advisory.patched_versions:
                                patches = ", ".join(f"{v}" for v in advisory.patched_versions.values())
                                console.print(f"    [success]Update to:[/success] {patches}")
                            console.print()
                    else:
                        console.print(Panel(
                            f"[success]✅ {package_name}@{version} has no known vulnerabilities![/success]",
                            title="🎉 Version Safe",
                            border_style="bright_green",
                        ))

                    next_step_type = "ghsa_query"

                elif cmd_name == "ghsa-scan":
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."

                    console.print(f"\n[title]🐙 GitHub Advisory Project Scan[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    # Find package.json
                    project_path = Path(path)
                    pkg_json_path = project_path / "package.json" if project_path.is_dir() else project_path

                    if not pkg_json_path.exists():
                        console.print(f"[danger]package.json not found at {pkg_json_path}[/danger]")
                        continue

                    # Load dependencies
                    with open(pkg_json_path) as f:
                        pkg_data = json.load(f)

                    deps = list(pkg_data.get("dependencies", {}).keys())
                    dev_deps = list(pkg_data.get("devDependencies", {}).keys())
                    all_deps = deps + dev_deps

                    console.print(f"[info]Found {len(deps)} dependencies, {len(dev_deps)} dev dependencies[/info]\n")

                    ghsa_db = GitHubAdvisoryDB()
                    all_advisories = []
                    vulnerable_packages = []

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task(f"[warning]Checking {len(all_deps)} packages...", total=len(all_deps))

                        for i, dep in enumerate(all_deps):
                            progress.update(task, description=f"[warning]Checking {dep}...")
                            result = ghsa_db.query_package(dep)
                            if result.advisories:
                                vulnerable_packages.append(dep)
                                all_advisories.extend(result.advisories)
                            progress.advance(task)

                        progress.remove_task(task)

                    console.print(f"\n[info]Packages Scanned:[/info] {len(all_deps)}")
                    console.print(f"[info]Vulnerable Packages:[/info] {len(vulnerable_packages)}")
                    console.print(f"[info]Total Advisories:[/info] {len(all_advisories)}\n")

                    if all_advisories:
                        had_findings = True
                        console.print(f"[danger]🚨 Found {len(all_advisories)} security advisories![/danger]\n")

                        # Group by severity
                        by_severity = {"critical": [], "high": [], "moderate": [], "low": []}
                        for advisory in all_advisories:
                            by_severity[advisory.severity.value].append(advisory)

                        for sev, advs in by_severity.items():
                            if advs:
                                style = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}[sev]
                                console.print(f"[{style}]{sev.upper()}: {len(advs)}[/{style}]")

                        console.print("\n[title]Vulnerable Packages:[/title]")
                        for pkg in vulnerable_packages[:15]:
                            console.print(f"  [warning]• {pkg}[/warning]")

                        # Save report
                        report_path = Path("/tmp/shellockolm/ghsa_report.json")
                        ghsa_db.generate_report(all_deps, str(report_path))
                        console.print(f"\n[info]📋 Full report: {report_path}[/info]")
                    else:
                        console.print(Panel(
                            f"[success]✅ No known vulnerabilities in {len(all_deps)} packages![/success]\n\n"
                            "[subtitle]All dependencies appear safe according to GitHub Advisory Database.[/subtitle]",
                            title="🎉 Project Secure",
                            border_style="bright_green",
                        ))

                    next_step_type = "ghsa_scan"

                elif cmd_name == "ghsa-report":
                    report_path = Path("/tmp/shellockolm/ghsa_report.json")

                    if report_path.exists():
                        with open(report_path) as f:
                            report_data = json.load(f)

                        console.print(Panel(
                            f"[title]GitHub Advisory Report[/title]\n\n"
                            f"[info]Report Time:[/info] {report_data.get('report_time', 'N/A')}\n"
                            f"[info]Total Packages:[/info] {report_data.get('total_packages', 0)}\n"
                            f"[info]Total Advisories:[/info] {report_data.get('total_advisories', 0)}\n\n"
                            f"[title]Severity Breakdown:[/title]\n"
                            f"[critical]Critical:[/critical] {report_data.get('severity_breakdown', {}).get('critical', 0)}\n"
                            f"[high]High:[/high] {report_data.get('severity_breakdown', {}).get('high', 0)}\n"
                            f"[medium]Moderate:[/medium] {report_data.get('severity_breakdown', {}).get('moderate', 0)}\n"
                            f"[low]Low:[/low] {report_data.get('severity_breakdown', {}).get('low', 0)}",
                            title="🐙 GitHub Advisory Database Report",
                            border_style="bright_blue",
                        ))

                        advisories = report_data.get('advisories', [])
                        if advisories:
                            console.print("\n[title]Top Advisories:[/title]")
                            for adv in advisories[:10]:
                                severity = adv.get('severity', 'unknown')
                                style = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low"}.get(severity, "info")
                                console.print(f"  [{style}]● [{severity.upper()}] {adv.get('ghsa_id')}[/{style}]")
                                if adv.get('cve_id'):
                                    console.print(f"    CVE: {adv.get('cve_id')}")
                                console.print(f"    {adv.get('summary', '')[:60]}...")
                    else:
                        console.print("[warning]No GitHub Advisory report found. Run [42] GHSA Scan first.[/warning]")

                    next_step_type = "ghsa_report"

                # ─────────────────────────────────────────────────────────
                # NPM AUDIT COMMANDS
                # ─────────────────────────────────────────────────────────
                elif cmd_name == "npm-audit":
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."

                    console.print(f"\n[title]📦 npm Audit (Enhanced)[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    npm_wrapper = NpmAuditWrapper()

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Running npm audit...", total=None)
                        report = npm_wrapper.run_audit(path)
                        progress.remove_task(task)

                    if report.error:
                        console.print(f"[danger]Error: {report.error}[/danger]")
                        continue

                    console.print(f"[info]npm Version:[/info] {report.npm_version}")
                    console.print(f"[info]Node Version:[/info] {report.node_version}")
                    console.print(f"[info]Dependencies:[/info] {report.total_dependencies} ({report.total_dev_dependencies} dev)\n")

                    if report.vulnerabilities:
                        had_findings = True
                        console.print(f"[danger]🚨 Found {report.total_vulnerabilities} vulnerabilities![/danger]\n")

                        # Severity breakdown
                        console.print("[title]Severity Breakdown:[/title]")
                        if report.severity_counts.get("critical", 0):
                            console.print(f"  [critical]Critical:[/critical] {report.severity_counts['critical']}")
                        if report.severity_counts.get("high", 0):
                            console.print(f"  [high]High:[/high] {report.severity_counts['high']}")
                        if report.severity_counts.get("moderate", 0):
                            console.print(f"  [medium]Moderate:[/medium] {report.severity_counts['moderate']}")
                        if report.severity_counts.get("low", 0):
                            console.print(f"  [low]Low:[/low] {report.severity_counts['low']}")

                        console.print(f"\n[success]Fixable:[/success] {report.fixable_count} of {report.total_vulnerabilities}")

                        console.print("\n[title]Vulnerabilities:[/title]")
                        for vuln in report.vulnerabilities[:15]:
                            severity_style = {
                                NpmAuditSeverity.CRITICAL: "critical",
                                NpmAuditSeverity.HIGH: "high",
                                NpmAuditSeverity.MODERATE: "medium",
                                NpmAuditSeverity.LOW: "low",
                            }.get(vuln.severity, "info")

                            fix_badge = "[success]✓[/success]" if vuln.fix_available else "[warning]✗[/warning]"
                            console.print(f"  [{severity_style}]● [{vuln.severity.value.upper()}] {vuln.name}[/{severity_style}] {fix_badge}")
                            if vuln.title:
                                console.print(f"    {vuln.title[:60]}...")
                            if vuln.via and vuln.via != [vuln.name]:
                                console.print(f"    via: {', '.join(vuln.via[:3])}")

                        if len(report.vulnerabilities) > 15:
                            console.print(f"\n  [subtitle]... and {len(report.vulnerabilities) - 15} more[/subtitle]")

                        # Save report
                        save_path = npm_wrapper.save_report(report)
                        console.print(f"\n[info]📋 Report saved: {save_path}[/info]")
                    else:
                        console.print(Panel(
                            f"[success]✅ No vulnerabilities found![/success]\n\n"
                            f"Scanned {report.total_dependencies} dependencies\n"
                            f"(+ {report.total_dev_dependencies} dev dependencies)",
                            title="🎉 All Clear",
                            border_style="bright_green",
                        ))

                    next_step_type = "npm_audit"

                elif cmd_name == "npm-fix":
                    path = cmd_args[-1] if cmd_args and not cmd_args[-1].startswith("-") else "."
                    force = "--force" in cmd_args

                    console.print(f"\n[title]📦 npm audit fix{'--force' if force else ''}[/title]")
                    console.print(f"[path]Target: {Path(path).resolve()}[/path]\n")

                    if force:
                        console.print("[warning]⚠️  Using --force flag - this may install breaking changes![/warning]\n")

                    npm_wrapper = NpmAuditWrapper()

                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        console=console,
                    ) as progress:
                        task = progress.add_task("[warning]Running npm audit fix...", total=None)
                        success, output = npm_wrapper.run_fix(path, force=force)
                        progress.remove_task(task)

                    if success:
                        console.print(Panel(
                            f"[success]✅ npm audit fix completed successfully![/success]\n\n"
                            f"[subtitle]Run [44] to see remaining vulnerabilities.[/subtitle]",
                            title="🔧 Fix Applied",
                            border_style="bright_green",
                        ))
                    else:
                        console.print(f"[danger]npm audit fix failed:[/danger]")
                        console.print(output[:500] if output else "Unknown error")

                    next_step_type = "npm_fix"

                elif cmd_name == "npm-recommend":
                    console.print(f"\n[title]📦 npm Fix Recommendations[/title]\n")

                    # Load the most recent audit report
                    npm_wrapper = NpmAuditWrapper()
                    history = npm_wrapper.get_history(limit=1)

                    if not history:
                        console.print("[warning]No audit history found. Run [44] npm audit first.[/warning]")
                        continue

                    # Load the full report
                    try:
                        with open(history[0]["file"]) as f:
                            report_data = json.load(f)

                        # Create a minimal report object for recommendations
                        # We need to reconstruct vulnerabilities from the saved data
                        console.print(f"[info]Based on audit from: {report_data.get('audit_time', 'N/A')}[/info]\n")

                        vulns_data = report_data.get("vulnerabilities", [])
                        total = len(vulns_data)
                        fixable = sum(1 for v in vulns_data if v.get("fix_available"))
                        unfixable = total - fixable

                        console.print(f"[info]Total Vulnerabilities:[/info] {total}")
                        console.print(f"[success]Auto-fixable:[/success] {fixable}")
                        console.print(f"[warning]Manual required:[/warning] {unfixable}\n")

                        if fixable > 0:
                            console.print(Panel(
                                f"[success]Run: npm audit fix[/success]\n\n"
                                f"This will automatically update {fixable} packages to secure versions.\n"
                                f"Use [45] in Shellockolm or run manually in terminal.",
                                title="💡 Recommended Fix",
                                border_style="bright_green",
                            ))

                        if unfixable > 0:
                            console.print("\n[title]Manual Action Required:[/title]")
                            for vuln in vulns_data:
                                if not vuln.get("fix_available"):
                                    console.print(f"  [warning]• {vuln.get('name')}[/warning]")
                                    console.print(f"    Severity: {vuln.get('severity', 'unknown')}")
                                    console.print(f"    Consider: Replace with alternative package")
                                    console.print()

                    except Exception as e:
                        console.print(f"[danger]Error loading report: {e}[/danger]")

                    next_step_type = "npm_audit"

                elif cmd_name == "npm-history":
                    console.print(f"\n[title]📦 npm Audit History[/title]\n")

                    npm_wrapper = NpmAuditWrapper()
                    history = npm_wrapper.get_history(limit=10)

                    if not history:
                        console.print("[warning]No audit history found. Run [44] npm audit first.[/warning]")
                        continue

                    console.print(f"[info]Found {len(history)} previous audits:[/info]\n")

                    for i, report in enumerate(history, 1):
                        sev = report.get("severity_counts", {})
                        total = report.get("total_vulnerabilities", 0)
                        critical = sev.get("critical", 0)
                        high = sev.get("high", 0)

                        status_style = "success" if total == 0 else "danger" if critical > 0 else "warning"
                        console.print(f"[{status_style}]{i}. {report.get('audit_time', 'N/A')[:19]}[/{status_style}]")
                        console.print(f"   Project: {report.get('project_path', 'N/A')}")
                        console.print(f"   Vulns: {total} (Critical: {critical}, High: {high})")
                        console.print()

                    next_step_type = "npm_history"

                # ─────────────────────────────────────────────────────────────
                # SBOM COMMANDS
                # ─────────────────────────────────────────────────────────────
                elif cmd_name == "sbom-generate":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📋 Generate SBOM[/title]\n")
                    console.print(f"[info]Analyzing project: {project_path}[/info]\n")

                    try:
                        generator = SBOMGenerator()
                        sbom = generator.generate(project_path)

                        console.print(f"[success]✅ SBOM generated successfully![/success]\n")
                        console.print(f"[info]Project: {sbom.metadata.name}[/info]")
                        console.print(f"[info]Version: {sbom.metadata.version}[/info]")
                        console.print(f"[info]Components: {len(sbom.components)}[/info]\n")

                        # Show format options
                        console.print("[subtitle]Available formats:[/subtitle]")
                        console.print("  [49] CycloneDX 1.4 (industry standard)")
                        console.print("  [50] SPDX 2.3 (Linux Foundation)")

                        # Export both formats
                        output_dir = Path(project_path) / "sbom"
                        output_dir.mkdir(exist_ok=True)

                        cdx_path = generator.export(sbom, str(output_dir / "sbom-cyclonedx.json"))
                        spdx_path = generator.export(sbom, str(output_dir / "sbom-spdx.json"), SBOMFormat.SPDX)

                        console.print(f"\n[success]📄 Exported to:[/success]")
                        console.print(f"   CycloneDX: {cdx_path}")
                        console.print(f"   SPDX: {spdx_path}")

                        next_step_type = "sbom_generate"

                    except Exception as e:
                        console.print(f"[danger]Error generating SBOM: {e}[/danger]")

                elif cmd_name == "sbom-cyclonedx":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📋 CycloneDX SBOM[/title]\n")
                    console.print(f"[info]Generating CycloneDX 1.4 format...[/info]\n")

                    try:
                        generator = SBOMGenerator()
                        sbom = generator.generate(project_path)

                        # Convert to CycloneDX
                        cdx_data = generator.to_cyclonedx(sbom)

                        # Display summary
                        console.print(f"[success]✅ CycloneDX SBOM generated![/success]\n")
                        console.print(f"[info]Spec Version: {cdx_data.get('specVersion', 'N/A')}[/info]")
                        console.print(f"[info]Serial: {cdx_data.get('serialNumber', 'N/A')[:50]}...[/info]")
                        console.print(f"[info]Components: {len(cdx_data.get('components', []))}[/info]\n")

                        # Show component table
                        if cdx_data.get("components"):
                            comp_table = Table(
                                title="[bold]Top 10 Components[/bold]",
                                box=box.ROUNDED,
                                border_style="bright_cyan"
                            )
                            comp_table.add_column("Name", style="bright_white")
                            comp_table.add_column("Version", style="bright_green")
                            comp_table.add_column("Type", style="bright_yellow")
                            comp_table.add_column("License", style="bright_magenta")

                            for comp in cdx_data["components"][:10]:
                                licenses = comp.get("licenses", [])
                                license_str = licenses[0].get("license", {}).get("id", "N/A") if licenses else "N/A"
                                comp_table.add_row(
                                    comp.get("name", "N/A"),
                                    comp.get("version", "N/A"),
                                    comp.get("type", "N/A"),
                                    license_str
                                )

                            console.print(comp_table)

                        # Export
                        output_dir = Path(project_path) / "sbom"
                        output_dir.mkdir(exist_ok=True)
                        output_path = output_dir / "sbom-cyclonedx.json"

                        with open(output_path, "w") as f:
                            json.dump(cdx_data, f, indent=2)

                        console.print(f"\n[success]📄 Exported to: {output_path}[/success]")
                        next_step_type = "sbom_cyclonedx"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "sbom-spdx":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📋 SPDX SBOM[/title]\n")
                    console.print(f"[info]Generating SPDX 2.3 format...[/info]\n")

                    try:
                        generator = SBOMGenerator()
                        sbom = generator.generate(project_path)

                        # Convert to SPDX
                        spdx_data = generator.to_spdx(sbom)

                        # Display summary
                        console.print(f"[success]✅ SPDX SBOM generated![/success]\n")
                        console.print(f"[info]SPDX Version: {spdx_data.get('spdxVersion', 'N/A')}[/info]")
                        console.print(f"[info]Document: {spdx_data.get('name', 'N/A')}[/info]")
                        console.print(f"[info]Packages: {len(spdx_data.get('packages', []))}[/info]\n")

                        # Show package table
                        if spdx_data.get("packages"):
                            pkg_table = Table(
                                title="[bold]Top 10 Packages[/bold]",
                                box=box.ROUNDED,
                                border_style="bright_green"
                            )
                            pkg_table.add_column("Name", style="bright_white")
                            pkg_table.add_column("Version", style="bright_green")
                            pkg_table.add_column("License", style="bright_yellow")
                            pkg_table.add_column("Download", style="dim")

                            for pkg in spdx_data["packages"][:10]:
                                pkg_table.add_row(
                                    pkg.get("name", "N/A"),
                                    pkg.get("versionInfo", "N/A"),
                                    pkg.get("licenseConcluded", "NOASSERTION"),
                                    pkg.get("downloadLocation", "N/A")[:40]
                                )

                            console.print(pkg_table)

                        # Export
                        output_dir = Path(project_path) / "sbom"
                        output_dir.mkdir(exist_ok=True)
                        output_path = output_dir / "sbom-spdx.json"

                        with open(output_path, "w") as f:
                            json.dump(spdx_data, f, indent=2)

                        console.print(f"\n[success]📄 Exported to: {output_path}[/success]")
                        next_step_type = "sbom_spdx"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                # ─────────────────────────────────────────────────────────────
                # DEPENDENCY TREE COMMANDS
                # ─────────────────────────────────────────────────────────────
                elif cmd_name == "tree-view":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]🌳 Dependency Tree[/title]\n")
                    console.print(f"[info]Analyzing: {project_path}[/info]\n")

                    try:
                        visualizer = DependencyTreeVisualizer(console)
                        output = visualizer.visualize(project_path, max_depth=6)
                        console.print(output)
                        console.print()
                        visualizer.display_stats()
                        next_step_type = "tree_view"

                    except FileNotFoundError as e:
                        console.print(f"[danger]Error: {e}[/danger]")
                        console.print("[info]No lockfile found. Run 'npm install' first.[/info]")
                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "tree-find":
                    package_name = cmd.get("input_value", "")
                    console.print(f"\n[title]🔍 Find Package: {package_name}[/title]\n")

                    # Need to get project path too
                    project_path = console.input("[info]Enter project path: [/info]").strip() or "."

                    try:
                        visualizer = DependencyTreeVisualizer(console)
                        results = visualizer.find_package(project_path, package_name)

                        if not results:
                            console.print(f"[warning]No matches found for '{package_name}'[/warning]")
                        else:
                            console.print(f"[success]Found {len(results)} matches:[/success]\n")

                            for i, (path, node) in enumerate(results[:20], 1):
                                style = "bright_white"
                                if node.dev:
                                    style = "bright_magenta"
                                elif node.circular_ref:
                                    style = "yellow"

                                console.print(f"[{style}]{i}. {node.name}@{node.version}[/{style}]")
                                console.print(f"   [dim]{path}[/dim]\n")

                            if len(results) > 20:
                                console.print(f"[info]... and {len(results) - 20} more[/info]")

                        next_step_type = "tree_find"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "tree-stats":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📊 Dependency Statistics[/title]\n")

                    try:
                        visualizer = DependencyTreeVisualizer(console)
                        # Parse to gather stats
                        _ = visualizer.visualize(project_path, max_depth=100)
                        visualizer.display_stats()

                        stats = visualizer.get_stats()

                        # Additional insights
                        console.print("\n[subtitle]Insights:[/subtitle]")

                        if stats["duplicate_count"] > 10:
                            console.print(f"  [warning]⚠ High duplicate count ({stats['duplicate_count']}). Consider deduplication.[/warning]")

                        if stats["max_depth"] > 10:
                            console.print(f"  [warning]⚠ Deep dependency tree (depth={stats['max_depth']}). May affect install time.[/warning]")

                        if stats["circular_references"]:
                            console.print(f"  [danger]❌ Circular references detected! This may cause issues.[/danger]")

                        if stats["duplicate_count"] == 0 and stats["max_depth"] < 8:
                            console.print(f"  [success]✅ Healthy dependency tree![/success]")

                        next_step_type = "tree_stats"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "tree-export":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📤 Export Dependency Tree[/title]\n")

                    # Show format options
                    console.print("[subtitle]Available formats:[/subtitle]")
                    console.print("  1. JSON - Structured JSON tree")
                    console.print("  2. DOT - GraphViz format (can visualize with dot)")
                    console.print("  3. ASCII - Plain text tree")
                    console.print()

                    format_choice = console.input("[info]Select format [1-3]: [/info]").strip() or "1"

                    format_map = {
                        "1": (TreeOutputFormat.JSON, "tree.json"),
                        "2": (TreeOutputFormat.DOT, "tree.dot"),
                        "3": (TreeOutputFormat.ASCII, "tree.txt"),
                    }

                    fmt, filename = format_map.get(format_choice, (TreeOutputFormat.JSON, "tree.json"))

                    try:
                        visualizer = DependencyTreeVisualizer(console)
                        output_dir = Path(project_path) / "reports"
                        output_dir.mkdir(exist_ok=True)
                        output_path = str(output_dir / filename)

                        result_path = visualizer.export_to_file(
                            project_path,
                            output_path,
                            output_format=fmt,
                            max_depth=50
                        )

                        console.print(f"\n[success]✅ Exported to: {result_path}[/success]")

                        if fmt == TreeOutputFormat.DOT:
                            console.print("[info]Tip: Generate image with: dot -Tpng tree.dot -o tree.png[/info]")

                        next_step_type = "tree_export"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                # ─────────────────────────────────────────────────────────────
                # IGNORE FILE COMMANDS
                # ─────────────────────────────────────────────────────────────
                elif cmd_name == "ignore-create":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]🚫 Create .shellockolmignore[/title]\n")

                    ignore_file = Path(project_path) / ".shellockolmignore"
                    if ignore_file.exists():
                        console.print(f"[warning]File already exists: {ignore_file}[/warning]")
                        overwrite = console.input("[info]Overwrite? (y/N): [/info]").strip().lower()
                        if overwrite != "y":
                            console.print("[info]Skipped.[/info]")
                            continue

                    try:
                        handler = IgnoreHandler(console)
                        created_path = handler.create_ignore_file(project_path)

                        console.print(f"[success]✅ Created: {created_path}[/success]\n")
                        console.print("[subtitle]Default patterns included:[/subtitle]")
                        console.print("  • node_modules/, dist/, build/")
                        console.print("  • coverage/, __tests__/, *.test.js")
                        console.print("  • *.config.js, *.min.js, vendor/")
                        console.print("\n[info]Edit the file to customize patterns.[/info]")

                        next_step_type = "ignore_create"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "ignore-view":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]📋 Loaded Ignore Patterns[/title]\n")

                    try:
                        handler = IgnoreHandler(console)
                        handler.load_global_ignore()
                        handler.load_project_ignores(project_path)

                        handler.display_patterns()

                        stats = handler.get_stats()
                        console.print(f"\n[subtitle]Summary:[/subtitle]")
                        console.print(f"  Default patterns: {stats['default_patterns']}")
                        console.print(f"  Global patterns: {stats['global_patterns']}")
                        console.print(f"  Project patterns: {stats['project_patterns']}")
                        console.print(f"  [bright_white]Total: {stats['total_patterns']}[/bright_white]")

                        next_step_type = "ignore_view"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "ignore-test":
                    test_path = cmd.get("input_value", "")
                    console.print(f"\n[title]🧪 Test Ignore Pattern[/title]\n")

                    project_path = console.input("[info]Enter project path: [/info]").strip() or "."

                    try:
                        handler = IgnoreHandler(console)
                        handler.load_global_ignore()
                        handler.load_project_ignores(project_path)

                        # Test the path
                        is_dir = test_path.endswith("/") or os.path.isdir(test_path) if test_path else False
                        ignored, reason = handler.should_ignore(test_path, is_dir)

                        console.print(f"\n[info]Testing: {test_path}[/info]")
                        console.print(f"[info]Type: {'directory' if is_dir else 'file'}[/info]\n")

                        if ignored:
                            console.print(f"[red]❌ IGNORED[/red]")
                            console.print(f"[dim]Reason: {reason}[/dim]")
                        else:
                            console.print(f"[green]✅ NOT IGNORED[/green]")
                            console.print("[dim]This path would be scanned.[/dim]")

                        next_step_type = "ignore_test"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                # ─────────────────────────────────────────────────────────────
                # GITHUB ACTIONS COMMANDS
                # ─────────────────────────────────────────────────────────────
                elif cmd_name == "gha-generate":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]⚙️ Generate GitHub Actions Workflow[/title]\n")

                    try:
                        generator = GitHubActionsGenerator(console)

                        # Ask for options
                        console.print("[subtitle]Select workflow type:[/subtitle]")
                        console.print("  1. Basic - Quick scan on push/PR")
                        console.print("  2. Standard - Default with SARIF upload")
                        console.print("  3. Comprehensive - All features")
                        console.print()

                        choice = console.input("[info]Select [1-3]: [/info]").strip() or "2"

                        config = WorkflowConfig()
                        if choice == "1":
                            config.scan_level = ScanLevel.BASIC
                            config.upload_sarif = False
                        elif choice == "3":
                            config.scan_level = ScanLevel.COMPREHENSIVE
                            config.triggers = [TriggerType.PUSH, TriggerType.PULL_REQUEST, TriggerType.SCHEDULE, TriggerType.WORKFLOW_DISPATCH]
                            config.create_issues = True

                        workflow_path = generator.create_workflow_file(project_path, config)
                        console.print(f"\n[success]✅ Created: {workflow_path}[/success]")

                        console.print("\n[subtitle]Workflow features:[/subtitle]")
                        console.print(f"  • Scan level: {config.scan_level.value}")
                        console.print(f"  • SARIF upload: {'Yes' if config.upload_sarif else 'No'}")
                        console.print(f"  • Fail on critical: {'Yes' if config.fail_on_critical else 'No'}")

                        console.print("\n[info]Commit and push to activate the workflow.[/info]")
                        next_step_type = "gha_generate"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "gha-basic":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]⚙️ Create Basic Workflow[/title]\n")

                    try:
                        generator = GitHubActionsGenerator(console)

                        # Create with basic config
                        config = WorkflowConfig()
                        config.scan_level = ScanLevel.BASIC
                        config.upload_sarif = True
                        config.create_issues = False

                        workflow_path = generator.create_workflow_file(project_path, config)

                        console.print(f"[success]✅ Created: {workflow_path}[/success]\n")
                        console.print("[subtitle]Basic workflow includes:[/subtitle]")
                        console.print("  • Trigger on push/PR to main")
                        console.print("  • Python + Node.js setup")
                        console.print("  • Security scan")
                        console.print("  • SARIF upload to GitHub Security")

                        # Show preview
                        console.print("\n[info]Preview first 20 lines:[/info]")
                        with open(workflow_path, "r") as f:
                            for i, line in enumerate(f):
                                if i >= 20:
                                    console.print("[dim]...[/dim]")
                                    break
                                console.print(f"[dim]{line.rstrip()}[/dim]")

                        next_step_type = "gha_basic"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                elif cmd_name == "gha-full":
                    project_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]⚙️ Create Comprehensive Workflow[/title]\n")

                    try:
                        generator = GitHubActionsGenerator(console)

                        # Write comprehensive workflow
                        workflow_dir = Path(project_path) / ".github/workflows"
                        workflow_dir.mkdir(parents=True, exist_ok=True)
                        workflow_path = workflow_dir / "shellockolm-security.yml"

                        content = generator.generate_comprehensive_workflow()
                        with open(workflow_path, "w") as f:
                            f.write(content)

                        console.print(f"[success]✅ Created: {workflow_path}[/success]\n")
                        console.print("[subtitle]Comprehensive workflow includes:[/subtitle]")
                        console.print("  • Triggers: push, PR, weekly schedule, manual")
                        console.print("  • Full CVE scan")
                        console.print("  • npm audit integration")
                        console.print("  • GitHub Advisory check")
                        console.print("  • SBOM generation")
                        console.print("  • SARIF upload")
                        console.print("  • Auto-create issues for failures")
                        console.print("  • Artifact upload")

                        console.print("\n[info]Commit and push to activate.[/info]")
                        next_step_type = "gha_full"

                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                # ─────────────────────────────────────────────────────────────
                # WATCH MODE COMMANDS
                # ─────────────────────────────────────────────────────────────
                elif cmd_name == "watch-start":
                    watch_path = cmd.get("input_value", ".")
                    console.print(f"\n[title]👁️ Watch Mode[/title]\n")

                    console.print("[subtitle]Watch options:[/subtitle]")
                    console.print("  1. Standard watch (scan on changes)")
                    console.print("  2. Watch + desktop notifications")
                    console.print("  3. Watch + clear screen between scans")
                    console.print()

                    choice = console.input("[info]Select [1-3]: [/info]").strip() or "1"

                    try:
                        watch = WatchMode(console)

                        notifications = choice in ["2"]
                        clear_screen = choice in ["3"]

                        console.print()
                        console.print("[warning]Press Ctrl+C to stop watching[/warning]\n")

                        # This will block until Ctrl+C
                        watch.start(
                            watch_path,
                            scan_on_start=True,
                            clear_screen=clear_screen,
                            notifications=notifications
                        )

                        # After stopping
                        next_step_type = "watch_stop"

                    except KeyboardInterrupt:
                        console.print("\n[info]Watch mode stopped.[/info]")
                        next_step_type = "watch_stop"
                    except Exception as e:
                        console.print(f"[danger]Error: {e}[/danger]")

                else:
                    console.print(f"[danger]Unknown command: {cmd_name}[/danger]")

            except typer.Exit as e:
                # Expected: scan() raises Exit(1) when vulnerabilities found
                if e.exit_code != 0:
                    had_findings = True
                    if cmd_name == "scan":
                        next_step_type = "scan"  # Findings found
                    elif cmd_name == "live":
                        next_step_type = "live"  # Findings found
            except SystemExit:
                pass  # Handle any other sys.exit calls
            except Exception as e:
                console.print(f"[danger]Error: {e}[/danger]")

            console.print("─" * 60)

            # Show contextual next steps
            if next_step_type:
                show_next_steps(next_step_type)

            console.input("[subtitle]Press Enter to continue...[/subtitle]")

        except KeyboardInterrupt:
            console.print("\n[warning]Press 0 or 'quit' to exit[/warning]")
        except EOFError:
            console.print("\n[info]👋 Goodbye![/info]")
            break


@app.command()
def shell():
    """Start interactive shell mode"""
    try:
        interactive_shell()
    except ImportError as e:
        console.print(f"[danger]Interactive mode requires prompt_toolkit: {e}[/danger]")
        console.print("[info]Install with: pip install prompt_toolkit[/info]")
        raise typer.Exit(1)


if __name__ == "__main__":
    # If no args, start interactive shell
    if len(sys.argv) == 1:
        try:
            interactive_shell()
        except ImportError:
            # Fallback to showing help
            main()
    else:
        main()
