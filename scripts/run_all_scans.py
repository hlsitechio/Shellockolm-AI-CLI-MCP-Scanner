#!/usr/bin/env python3
"""
Shellockolm - Run ALL Scans & Generate Full Report
Executes every non-destructive, non-interactive scan command
and writes consolidated output to full_report.txt
"""
import sys, os

# Fix Windows encoding
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

os.chdir(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "src"))

# Suppress prompt_toolkit import (not needed for batch)
from io import StringIO
from datetime import datetime
from pathlib import Path

# Target path for scans
SCAN_TARGET = str(Path.home())
REPORT_FILE = os.path.join(os.path.dirname(__file__), "full_report.txt")

output_lines = []

def log(msg):
    print(msg)
    output_lines.append(msg)

def section(title):
    log(f"\n{'='*80}")
    log(f"  {title}")
    log(f"{'='*80}\n")

def run_safe(label, func, *args, **kwargs):
    """Run a function safely, catching all errors"""
    try:
        log(f"--- {label} ---")
        result = func(*args, **kwargs)
        if result is not None:
            log(str(result))
        log(f"[OK] {label} completed\n")
        return result
    except Exception as e:
        log(f"[ERROR] {label}: {type(e).__name__}: {e}\n")
        return None

# ==========================================
# IMPORTS
# ==========================================
log(f"Shellockolm Full Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log(f"Target: {SCAN_TARGET}")
log(f"Python: {sys.version}")

try:
    import compat
except Exception:
    pass

from rich.console import Console
console = Console(file=StringIO(), force_terminal=False, width=120)

def capture_rich(func, *a, **kw):
    """Capture Rich console output to string"""
    buf = StringIO()
    c = Console(file=buf, force_terminal=False, width=120, highlight=False)
    old_console = None
    # Try to monkey-patch the module's console
    import cli as cli_module
    old_console = cli_module.console
    cli_module.console = c
    try:
        func(*a, **kw)
    except SystemExit:
        pass
    finally:
        cli_module.console = old_console
    return buf.getvalue()

# ==========================================
# 1. VERSION
# ==========================================
section("1. VERSION INFO")
try:
    from cli import app
    log("Shellockolm v2.0.0 - Security Detective for React, Next.js, Node.js & npm")
except Exception as e:
    log(f"Import error: {e}")

# ==========================================
# 2. SCANNER REGISTRY
# ==========================================
section("2. AVAILABLE SCANNERS")
try:
    from scanners import get_all_scanners, SCANNER_REGISTRY
    for scanner_obj in get_all_scanners():
        name = getattr(scanner_obj, 'NAME', 'unknown')
        desc = getattr(scanner_obj, 'DESCRIPTION', '')
        cve_db = getattr(scanner_obj, 'CVE_DATABASE', {})
        log(f"  Scanner: {name}")
        log(f"    Description: {desc}")
        log(f"    CVEs tracked: {len(cve_db)}")
        for cve_id in sorted(cve_db.keys()):
            info = cve_db[cve_id]
            sev = info.get('severity', 'UNKNOWN')
            title = info.get('title', info.get('description', '')[:60])
            log(f"      {cve_id} [{sev}] - {title}")
        log("")
except Exception as e:
    log(f"Error loading scanners: {e}")

# ==========================================
# 3. VULNERABILITY DATABASE
# ==========================================
section("3. FULL CVE DATABASE")
try:
    from vulnerability_database import VulnerabilityDatabase
    db = VulnerabilityDatabase()
    all_vulns = db.get_all_vulnerabilities()
    log(f"Total vulnerabilities in database: {len(all_vulns)}")
    for v in all_vulns:
        cve = getattr(v, 'cve_id', str(v))
        sev = getattr(v, 'severity', 'N/A')
        cvss = getattr(v, 'cvss_score', 'N/A')
        title = getattr(v, 'title', 'N/A')
        pkg = getattr(v, 'affected_packages', [])
        fixed = getattr(v, 'fixed_version', 'N/A')
        bounty = getattr(v, 'bounty_target', False)
        log(f"  {cve} | {sev} | CVSS {cvss} | {title}")
        log(f"    Packages: {pkg} | Fixed: {fixed} | Bounty: {'YES' if bounty else 'no'}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 4. FULL SCAN (all scanners)
# ==========================================
section("4. FULL SCAN - ALL SCANNERS")
try:
    from scanners import get_all_scanners
    for scanner_obj in get_all_scanners():
        name = getattr(scanner_obj, 'NAME', 'unknown')
        log(f"\n  >> Running scanner: {name}")
        try:
            result = scanner_obj.scan(SCAN_TARGET)
            if result:
                findings = getattr(result, 'findings', [])
                log(f"     Findings: {len(findings)}")
                for f in findings[:20]:
                    sev = getattr(f, 'severity', 'N/A')
                    title = getattr(f, 'title', str(f)[:80])
                    file_path = getattr(f, 'file_path', '')
                    log(f"       [{sev}] {title}")
                    if file_path:
                        log(f"         File: {file_path}")
                if len(findings) > 20:
                    log(f"       ... and {len(findings) - 20} more findings")
            else:
                log(f"     No results returned")
        except Exception as e:
            log(f"     Scanner error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 5. MALWARE ANALYSIS
# ==========================================
section("5. MALWARE ANALYSIS")
try:
    from malware_analyzer import MalwareAnalyzer
    analyzer = MalwareAnalyzer()
    log(f"  Malware patterns loaded: {len(getattr(analyzer, 'patterns', getattr(analyzer, 'PATTERNS', [])))}")
    log(f"  Running quick malware scan on: {SCAN_TARGET}")
    try:
        results = analyzer.scan(SCAN_TARGET, deep=False)
        if results:
            threats = getattr(results, 'threats', results) if not isinstance(results, list) else results
            if isinstance(threats, list):
                log(f"  Threats found: {len(threats)}")
                for t in threats[:15]:
                    log(f"    {t}")
            else:
                log(f"  Result: {str(results)[:500]}")
        else:
            log(f"  No malware threats detected")
    except Exception as e:
        log(f"  Scan error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 6. SECRETS SCANNER
# ==========================================
section("6. SECRETS SCANNER")
try:
    from secrets_scanner import SecretsScanner
    scanner = SecretsScanner()
    log(f"  Secret patterns loaded: {len(getattr(scanner, 'patterns', getattr(scanner, 'PATTERNS', [])))}")
    log(f"  Scanning: {SCAN_TARGET}")
    try:
        results = scanner.scan(SCAN_TARGET)
        if results:
            findings = results if isinstance(results, list) else getattr(results, 'findings', [results])
            log(f"  Secrets found: {len(findings)}")
            for f in findings[:15]:
                log(f"    {f}")
        else:
            log(f"  No exposed secrets detected")
    except Exception as e:
        log(f"  Scan error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 7. SECURITY SCORE
# ==========================================
section("7. SECURITY SCORE")
try:
    from security_score import SecurityScoreCalculator
    calc = SecurityScoreCalculator()
    log(f"  Calculating security score for: {SCAN_TARGET}")
    try:
        score = calc.calculate(SCAN_TARGET)
        if score:
            grade = getattr(score, 'grade', 'N/A')
            total = getattr(score, 'score', getattr(score, 'total_score', 'N/A'))
            log(f"  Grade: {grade}")
            log(f"  Score: {total}")
            breakdown = getattr(score, 'breakdown', getattr(score, 'categories', None))
            if breakdown:
                if isinstance(breakdown, dict):
                    for k, v in breakdown.items():
                        log(f"    {k}: {v}")
                else:
                    log(f"    {breakdown}")
        else:
            log(f"  No score returned")
    except Exception as e:
        log(f"  Score error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 8. LOCKFILE ANALYZER
# ==========================================
section("8. LOCKFILE ANALYSIS")
try:
    from lockfile_analyzer import LockfileAnalyzer
    la = LockfileAnalyzer()
    lockfile_path = os.path.join(SCAN_TARGET, "package-lock.json")
    if os.path.exists(lockfile_path):
        log(f"  Analyzing: {lockfile_path}")
        try:
            result = la.analyze(lockfile_path)
            if result:
                log(f"  Result: {str(result)[:1000]}")
        except Exception as e:
            log(f"  Error: {type(e).__name__}: {e}")
    else:
        log(f"  No package-lock.json found at {SCAN_TARGET}")
        # Try yarn.lock
        yarn_lock = os.path.join(SCAN_TARGET, "yarn.lock")
        if os.path.exists(yarn_lock):
            log(f"  Found yarn.lock, analyzing...")
            try:
                result = la.analyze(yarn_lock)
                log(f"  Result: {str(result)[:1000]}")
            except Exception as e:
                log(f"  Error: {e}")
        else:
            log(f"  No lockfiles found")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 9. SBOM GENERATOR
# ==========================================
section("9. SBOM GENERATION")
try:
    from sbom_generator import SBOMGenerator, SBOMFormat
    gen = SBOMGenerator()
    log(f"  Generating CycloneDX SBOM for: {SCAN_TARGET}")
    try:
        sbom = gen.generate(SCAN_TARGET, format=SBOMFormat.CYCLONEDX)
        if sbom:
            if isinstance(sbom, dict):
                components = sbom.get('components', [])
                log(f"  Components: {len(components)}")
                for c in components[:10]:
                    log(f"    {c.get('name', '?')}@{c.get('version', '?')}")
                if len(components) > 10:
                    log(f"    ... and {len(components) - 10} more")
            else:
                log(f"  SBOM: {str(sbom)[:1000]}")
        else:
            log(f"  No SBOM generated (no package.json found?)")
    except Exception as e:
        log(f"  Error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 10. SARIF OUTPUT
# ==========================================
section("10. SARIF EXPORT")
try:
    from sarif_output import SarifGenerator
    sg = SarifGenerator()
    log(f"  SARIF generator loaded")
    log(f"  Tool: {getattr(sg, 'tool_name', 'shellockolm')}")
    log(f"  Version: {getattr(sg, 'version', '2.0.0')}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 11. GITHUB ADVISORY DB
# ==========================================
section("11. GITHUB ADVISORY DATABASE")
try:
    from github_advisory import GitHubAdvisoryDB
    ghsa = GitHubAdvisoryDB()
    test_packages = ["react", "next", "express", "lodash", "mysql2", "jsonpath-plus", "body-parser", "multer"]
    for pkg in test_packages:
        log(f"  Checking {pkg}...")
        try:
            advisories = ghsa.query(pkg)
            if advisories:
                count = len(advisories) if isinstance(advisories, list) else 1
                log(f"    Found {count} advisories")
                if isinstance(advisories, list):
                    for a in advisories[:3]:
                        log(f"      {a}")
            else:
                log(f"    No advisories found")
        except Exception as e:
            log(f"    Error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 12. DEPENDENCY TREE
# ==========================================
section("12. DEPENDENCY TREE")
try:
    from dependency_tree import DependencyTreeVisualizer
    dtv = DependencyTreeVisualizer()
    pkg_json = os.path.join(SCAN_TARGET, "package.json")
    if os.path.exists(pkg_json):
        log(f"  Analyzing dependency tree: {pkg_json}")
        try:
            tree = dtv.build_tree(SCAN_TARGET)
            if tree:
                stats = dtv.get_stats() if hasattr(dtv, 'get_stats') else None
                if stats:
                    log(f"  Stats: {stats}")
                log(f"  Tree: {str(tree)[:1000]}")
        except Exception as e:
            log(f"  Error: {type(e).__name__}: {e}")
    else:
        log(f"  No package.json at target root")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 13. AUTO-FIX (PREVIEW ONLY)
# ==========================================
section("13. AUTO-FIX PREVIEW (dry run)")
try:
    from auto_fix import AutoFixer
    fixer = AutoFixer()
    log(f"  Previewing fixes for: {SCAN_TARGET}")
    try:
        preview = fixer.preview(SCAN_TARGET) if hasattr(fixer, 'preview') else fixer.scan(SCAN_TARGET)
        if preview:
            log(f"  Preview: {str(preview)[:1000]}")
        else:
            log(f"  No fixes needed or no vulnerable packages found")
    except Exception as e:
        log(f"  Error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 14. GITHUB ACTIONS GENERATOR
# ==========================================
section("14. GITHUB ACTIONS WORKFLOW")
try:
    from github_actions import GitHubActionsGenerator, WorkflowConfig, ScanLevel, TriggerType
    gha = GitHubActionsGenerator()
    log(f"  Generating basic workflow config...")
    try:
        config = WorkflowConfig(scan_level=ScanLevel.BASIC, triggers=[TriggerType.PUSH, TriggerType.PR])
        workflow = gha.generate(config)
        if workflow:
            log(f"  Workflow YAML ({len(workflow)} chars):")
            for line in workflow.split('\n')[:30]:
                log(f"    {line}")
            if workflow.count('\n') > 30:
                log(f"    ... ({workflow.count(chr(10)) - 30} more lines)")
    except Exception as e:
        log(f"  Error: {type(e).__name__}: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 15. IGNORE HANDLER
# ==========================================
section("15. IGNORE HANDLER")
try:
    from ignore_handler import IgnoreHandler
    ih = IgnoreHandler()
    log(f"  Default ignore patterns loaded")
    patterns = getattr(ih, 'patterns', getattr(ih, 'default_patterns', []))
    if patterns:
        log(f"  Patterns ({len(patterns)}):")
        for p in patterns[:20]:
            log(f"    {p}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 16. CONTEXT INTELLIGENCE
# ==========================================
section("16. CONTEXT INTELLIGENCE")
try:
    from context_intelligence import detect_path_context, PathContext
    test_paths = [
        os.path.join(SCAN_TARGET, "node_modules"),
        os.path.join(SCAN_TARGET, ".env"),
        os.path.join(SCAN_TARGET, "package.json"),
    ]
    for tp in test_paths:
        log(f"  Context for: {tp}")
        try:
            ctx = detect_path_context(tp)
            log(f"    Result: {ctx}")
        except Exception as e:
            log(f"    Error: {e}")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 17. CLAWDBOT SCANNER
# ==========================================
section("17. CLAWDBOT / MOLTBOT SCANNER")
try:
    from scanners import get_scanner
    clawdbot = get_scanner("clawdbot")
    if clawdbot:
        log(f"  Scanner: {clawdbot.NAME}")
        log(f"  Description: {clawdbot.DESCRIPTION}")
        log(f"  CVEs: {len(getattr(clawdbot, 'CVE_DATABASE', {}))}")
        log(f"  Running Clawdbot scan...")
        try:
            result = clawdbot.scan(SCAN_TARGET)
            if result:
                findings = getattr(result, 'findings', [])
                log(f"  Findings: {len(findings)}")
                for f in findings[:20]:
                    sev = getattr(f, 'severity', 'N/A')
                    title = getattr(f, 'title', str(f)[:80])
                    log(f"    [{sev}] {title}")
            else:
                log(f"  No Clawdbot threats detected")
        except Exception as e:
            log(f"  Error: {type(e).__name__}: {e}")
    else:
        log(f"  Clawdbot scanner not found in registry")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 18. NPM AUDIT WRAPPER
# ==========================================
section("18. NPM AUDIT")
try:
    from npm_audit import NpmAuditWrapper
    npm = NpmAuditWrapper()
    log(f"  NPM Audit wrapper loaded")
    pkg_json = os.path.join(SCAN_TARGET, "package.json")
    if os.path.exists(pkg_json):
        log(f"  Running npm audit on: {SCAN_TARGET}")
        try:
            result = npm.audit(SCAN_TARGET)
            if result:
                log(f"  Result: {str(result)[:1000]}")
        except Exception as e:
            log(f"  Error: {type(e).__name__}: {e}")
    else:
        log(f"  No package.json found")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# 19. WATCH MODE CONFIG
# ==========================================
section("19. WATCH MODE CONFIG")
try:
    from watch_mode import WatchMode, WatchConfig
    config = WatchConfig(path=SCAN_TARGET, interval=60)
    log(f"  Watch config: path={config.path}, interval={config.interval}s")
    log(f"  (Not starting watch mode - batch report only)")
except Exception as e:
    log(f"Error: {e}")

# ==========================================
# SUMMARY
# ==========================================
section("REPORT COMPLETE")
log(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
log(f"Sections run: 19")
log(f"Report saved to: {REPORT_FILE}")

# Write report
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    f.write("\n".join(output_lines))

print(f"\n>>> Full report saved to: {REPORT_FILE}")
