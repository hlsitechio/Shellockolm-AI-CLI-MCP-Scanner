#!/usr/bin/env python3
"""
Shellockolm npm Audit Wrapper
Enhanced npm audit with beautiful output and advanced features

Features:
- Runs npm audit and parses JSON output
- Beautiful Rich terminal output
- Filters by severity
- Shows fix recommendations
- Exports to multiple formats
- Tracks audit history
"""

import json
import subprocess
import shutil
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum


class NpmAuditSeverity(Enum):
    """npm audit severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    INFO = "info"


@dataclass
class NpmVulnerability:
    """A vulnerability from npm audit"""
    name: str
    severity: NpmAuditSeverity
    via: List[str]  # packages through which this is vulnerable
    effects: List[str]  # packages affected
    range_affected: str  # vulnerable version range
    nodes: List[str]  # paths in dependency tree
    fix_available: bool
    direct: bool  # is it a direct dependency?
    cwe: List[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    ghsa_id: Optional[str]
    url: Optional[str]
    title: str
    recommendation: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "severity": self.severity.value,
            "via": self.via,
            "effects": self.effects,
            "range_affected": self.range_affected,
            "nodes": self.nodes,
            "fix_available": self.fix_available,
            "direct": self.direct,
            "cwe": self.cwe,
            "cvss_score": self.cvss_score,
            "ghsa_id": self.ghsa_id,
            "url": self.url,
            "title": self.title,
            "recommendation": self.recommendation,
        }


@dataclass
class NpmAuditReport:
    """Complete npm audit report"""
    project_path: str
    audit_time: datetime
    total_dependencies: int
    total_dev_dependencies: int
    vulnerabilities: List[NpmVulnerability]
    severity_counts: Dict[str, int]
    fix_available_count: int
    npm_version: str
    node_version: str
    audit_level: str  # npm audit --audit-level setting
    raw_output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)

    @property
    def critical_count(self) -> int:
        return self.severity_counts.get("critical", 0)

    @property
    def high_count(self) -> int:
        return self.severity_counts.get("high", 0)

    @property
    def fixable_count(self) -> int:
        return sum(1 for v in self.vulnerabilities if v.fix_available)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "project_path": self.project_path,
            "audit_time": self.audit_time.isoformat(),
            "total_dependencies": self.total_dependencies,
            "total_dev_dependencies": self.total_dev_dependencies,
            "total_vulnerabilities": self.total_vulnerabilities,
            "severity_counts": self.severity_counts,
            "fix_available_count": self.fix_available_count,
            "npm_version": self.npm_version,
            "node_version": self.node_version,
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "error": self.error,
        }


class NpmAuditWrapper:
    """
    Enhanced npm audit wrapper with beautiful output
    """

    # Use the platform temp dir so this resolves correctly on Windows
    # (the old hardcoded "/tmp/..." mapped onto the current drive root).
    HISTORY_DIR = Path(tempfile.gettempdir()) / "shellockolm" / "npm_audit_history"

    def __init__(self):
        # mkdir is deferred until we actually write history (see save_report),
        # so merely constructing the wrapper does not create directories.
        self.history_dir = self.HISTORY_DIR

    def _get_npm_version(self) -> str:
        """Get npm version"""
        try:
            result = subprocess.run(
                ["npm", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def _get_node_version(self) -> str:
        """Get Node.js version"""
        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            return result.stdout.strip()
        except Exception:
            return "unknown"

    def _check_npm_available(self) -> bool:
        """Check if npm is available"""
        return shutil.which("npm") is not None

    def run_audit(self, project_path: str, production_only: bool = False,
                  audit_level: str = "low", include_dev: bool = True) -> NpmAuditReport:
        """
        Run npm audit on a project

        Args:
            project_path: Path to npm project
            production_only: Only audit production dependencies
            audit_level: Minimum severity level (low, moderate, high, critical)
            include_dev: Include devDependencies in audit

        Returns:
            NpmAuditReport with all findings
        """
        project = Path(project_path).resolve()

        # Check for package.json
        pkg_json_path = project / "package.json"
        if not pkg_json_path.exists():
            return NpmAuditReport(
                project_path=str(project),
                audit_time=datetime.now(),
                total_dependencies=0,
                total_dev_dependencies=0,
                vulnerabilities=[],
                severity_counts={},
                fix_available_count=0,
                npm_version=self._get_npm_version(),
                node_version=self._get_node_version(),
                audit_level=audit_level,
                error="package.json not found"
            )

        # Read package.json to get dependency counts
        try:
            with open(pkg_json_path) as f:
                pkg_data = json.load(f)
            total_deps = len(pkg_data.get("dependencies", {}))
            total_dev_deps = len(pkg_data.get("devDependencies", {}))
        except Exception:
            total_deps = 0
            total_dev_deps = 0

        # Check if npm is available
        if not self._check_npm_available():
            return NpmAuditReport(
                project_path=str(project),
                audit_time=datetime.now(),
                total_dependencies=total_deps,
                total_dev_dependencies=total_dev_deps,
                vulnerabilities=[],
                severity_counts={},
                fix_available_count=0,
                npm_version="not found",
                node_version=self._get_node_version(),
                audit_level=audit_level,
                error="npm not found in PATH"
            )

        # Build npm audit command
        cmd = ["npm", "audit", "--json"]

        if production_only:
            cmd.append("--production")

        if not include_dev:
            cmd.append("--omit=dev")

        cmd.extend(["--audit-level", audit_level])

        # Run npm audit
        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=120
            )

            # npm audit exits with non-zero when vulnerabilities found
            # so we can't use returncode to check for errors
            output = result.stdout
            stderr = result.stderr

            # Check for actual errors (not just vulnerabilities)
            if result.returncode != 0 and not output:
                return NpmAuditReport(
                    project_path=str(project),
                    audit_time=datetime.now(),
                    total_dependencies=total_deps,
                    total_dev_dependencies=total_dev_deps,
                    vulnerabilities=[],
                    severity_counts={},
                    fix_available_count=0,
                    npm_version=self._get_npm_version(),
                    node_version=self._get_node_version(),
                    audit_level=audit_level,
                    error=stderr or "npm audit failed"
                )

            # Parse JSON output
            audit_data = json.loads(output) if output else {}

        except subprocess.TimeoutExpired:
            return NpmAuditReport(
                project_path=str(project),
                audit_time=datetime.now(),
                total_dependencies=total_deps,
                total_dev_dependencies=total_dev_deps,
                vulnerabilities=[],
                severity_counts={},
                fix_available_count=0,
                npm_version=self._get_npm_version(),
                node_version=self._get_node_version(),
                audit_level=audit_level,
                error="npm audit timed out after 120 seconds"
            )
        except json.JSONDecodeError as e:
            return NpmAuditReport(
                project_path=str(project),
                audit_time=datetime.now(),
                total_dependencies=total_deps,
                total_dev_dependencies=total_dev_deps,
                vulnerabilities=[],
                severity_counts={},
                fix_available_count=0,
                npm_version=self._get_npm_version(),
                node_version=self._get_node_version(),
                audit_level=audit_level,
                error=f"Failed to parse npm audit output: {e}"
            )
        except Exception as e:
            return NpmAuditReport(
                project_path=str(project),
                audit_time=datetime.now(),
                total_dependencies=total_deps,
                total_dev_dependencies=total_dev_deps,
                vulnerabilities=[],
                severity_counts={},
                fix_available_count=0,
                npm_version=self._get_npm_version(),
                node_version=self._get_node_version(),
                audit_level=audit_level,
                error=str(e)
            )

        # Parse vulnerabilities from npm audit output
        vulnerabilities = self._parse_audit_output(audit_data)

        # Count by severity
        severity_counts = {"critical": 0, "high": 0, "moderate": 0, "low": 0, "info": 0}
        fix_available_count = 0

        for vuln in vulnerabilities:
            severity_counts[vuln.severity.value] = severity_counts.get(vuln.severity.value, 0) + 1
            if vuln.fix_available:
                fix_available_count += 1

        return NpmAuditReport(
            project_path=str(project),
            audit_time=datetime.now(),
            total_dependencies=total_deps,
            total_dev_dependencies=total_dev_deps,
            vulnerabilities=vulnerabilities,
            severity_counts=severity_counts,
            fix_available_count=fix_available_count,
            npm_version=self._get_npm_version(),
            node_version=self._get_node_version(),
            audit_level=audit_level,
            raw_output=audit_data
        )

    def _parse_audit_output(self, audit_data: Dict[str, Any]) -> List[NpmVulnerability]:
        """Parse npm audit JSON output into vulnerability list"""
        vulnerabilities = []

        # Handle different npm audit output formats (npm 6 vs npm 7+)
        vulns_data = audit_data.get("vulnerabilities", {})

        if not vulns_data:
            # Try npm 6 format
            advisories = audit_data.get("advisories", {})
            for adv_id, advisory in advisories.items():
                severity_map = {
                    "critical": NpmAuditSeverity.CRITICAL,
                    "high": NpmAuditSeverity.HIGH,
                    "moderate": NpmAuditSeverity.MODERATE,
                    "low": NpmAuditSeverity.LOW,
                    "info": NpmAuditSeverity.INFO,
                }

                vuln = NpmVulnerability(
                    name=advisory.get("module_name", "unknown"),
                    severity=severity_map.get(advisory.get("severity", "low"), NpmAuditSeverity.LOW),
                    via=[],
                    effects=[],
                    range_affected=advisory.get("vulnerable_versions", "*"),
                    nodes=[f.get("path", "") for f in advisory.get("findings", [])],
                    fix_available=bool(advisory.get("patched_versions")),
                    direct=any(f.get("dev") == False for f in advisory.get("findings", [])),
                    cwe=[advisory.get("cwe", "")],
                    cvss_score=advisory.get("cvss", {}).get("score"),
                    cvss_vector=advisory.get("cvss", {}).get("vectorString"),
                    ghsa_id=advisory.get("github_advisory_id"),
                    url=advisory.get("url"),
                    title=advisory.get("title", ""),
                    recommendation=advisory.get("recommendation", "Update to patched version")
                )
                vulnerabilities.append(vuln)
        else:
            # npm 7+ format
            for pkg_name, vuln_info in vulns_data.items():
                severity_map = {
                    "critical": NpmAuditSeverity.CRITICAL,
                    "high": NpmAuditSeverity.HIGH,
                    "moderate": NpmAuditSeverity.MODERATE,
                    "low": NpmAuditSeverity.LOW,
                    "info": NpmAuditSeverity.INFO,
                }

                # Handle 'via' - can be strings or objects
                via = []
                via_data = vuln_info.get("via", [])
                for v in via_data:
                    if isinstance(v, str):
                        via.append(v)
                    elif isinstance(v, dict):
                        via.append(v.get("name", ""))

                # Extract advisory info from 'via' objects
                ghsa_id = None
                url = None
                title = ""
                cwe = []
                cvss_score = None
                recommendation = ""

                for v in via_data:
                    if isinstance(v, dict):
                        ghsa_id = ghsa_id or v.get("github_advisory_id")
                        url = url or v.get("url")
                        title = title or v.get("title", "")
                        cwe.extend(v.get("cwe", []))
                        cvss_score = cvss_score or v.get("cvss", {}).get("score")

                vuln = NpmVulnerability(
                    name=pkg_name,
                    severity=severity_map.get(vuln_info.get("severity", "low"), NpmAuditSeverity.LOW),
                    via=via,
                    effects=vuln_info.get("effects", []),
                    range_affected=vuln_info.get("range", "*"),
                    nodes=vuln_info.get("nodes", []),
                    fix_available=vuln_info.get("fixAvailable", False),
                    direct=vuln_info.get("isDirect", False),
                    cwe=cwe,
                    cvss_score=cvss_score,
                    cvss_vector=None,
                    ghsa_id=ghsa_id,
                    url=url,
                    title=title,
                    recommendation=recommendation or "Run npm audit fix"
                )
                vulnerabilities.append(vuln)

        # Sort by severity
        severity_order = {
            NpmAuditSeverity.CRITICAL: 0,
            NpmAuditSeverity.HIGH: 1,
            NpmAuditSeverity.MODERATE: 2,
            NpmAuditSeverity.LOW: 3,
            NpmAuditSeverity.INFO: 4,
        }
        vulnerabilities.sort(key=lambda v: severity_order.get(v.severity, 5))

        return vulnerabilities

    def run_fix(self, project_path: str, force: bool = False) -> Tuple[bool, str]:
        """
        Run npm audit fix

        Args:
            project_path: Path to npm project
            force: Use --force flag (may install breaking changes)

        Returns:
            Tuple of (success, output message)
        """
        project = Path(project_path).resolve()

        if not self._check_npm_available():
            return False, "npm not found in PATH"

        cmd = ["npm", "audit", "fix"]
        if force:
            cmd.append("--force")

        try:
            result = subprocess.run(
                cmd,
                cwd=str(project),
                capture_output=True,
                text=True,
                timeout=300
            )

            output = result.stdout + "\n" + result.stderr
            return result.returncode == 0, output.strip()

        except subprocess.TimeoutExpired:
            return False, "npm audit fix timed out after 5 minutes"
        except Exception as e:
            return False, str(e)

    def get_fix_recommendations(self, report: NpmAuditReport) -> List[Dict[str, Any]]:
        """
        Get fix recommendations from audit report

        Returns:
            List of fix recommendations with commands
        """
        recommendations = []

        fixable = [v for v in report.vulnerabilities if v.fix_available]
        unfixable = [v for v in report.vulnerabilities if not v.fix_available]

        if fixable:
            # Group by whether they can be auto-fixed
            direct_fixable = [v for v in fixable if v.direct]
            transitive_fixable = [v for v in fixable if not v.direct]

            if direct_fixable:
                recommendations.append({
                    "type": "auto_fix",
                    "description": f"Auto-fix {len(direct_fixable)} direct dependency vulnerabilities",
                    "command": "npm audit fix",
                    "packages": [v.name for v in direct_fixable],
                    "severity_breakdown": {
                        "critical": sum(1 for v in direct_fixable if v.severity == NpmAuditSeverity.CRITICAL),
                        "high": sum(1 for v in direct_fixable if v.severity == NpmAuditSeverity.HIGH),
                        "moderate": sum(1 for v in direct_fixable if v.severity == NpmAuditSeverity.MODERATE),
                        "low": sum(1 for v in direct_fixable if v.severity == NpmAuditSeverity.LOW),
                    }
                })

            if transitive_fixable:
                recommendations.append({
                    "type": "force_fix",
                    "description": f"Force fix {len(transitive_fixable)} transitive dependency vulnerabilities (may break)",
                    "command": "npm audit fix --force",
                    "packages": [v.name for v in transitive_fixable],
                    "warning": "This may install breaking changes. Review changes carefully."
                })

        if unfixable:
            for vuln in unfixable:
                recommendations.append({
                    "type": "manual",
                    "description": f"Manual action required for {vuln.name}",
                    "package": vuln.name,
                    "severity": vuln.severity.value,
                    "reason": "No automatic fix available",
                    "suggestion": f"Consider replacing {vuln.name} with an alternative package"
                })

        return recommendations

    def save_report(self, report: NpmAuditReport, output_path: Optional[str] = None) -> str:
        """
        Save audit report to file

        Args:
            report: The audit report to save
            output_path: Optional custom path (defaults to history dir)

        Returns:
            Path to saved report
        """
        if output_path:
            save_path = Path(output_path)
        else:
            timestamp = report.audit_time.strftime("%Y%m%d_%H%M%S")
            save_path = self.history_dir / f"npm_audit_{timestamp}.json"

        save_path.parent.mkdir(parents=True, exist_ok=True)

        with open(save_path, "w") as f:
            json.dump(report.to_dict(), f, indent=2)

        return str(save_path)

    def get_history(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Get audit history

        Args:
            limit: Maximum number of reports to return

        Returns:
            List of historical report summaries
        """
        reports = []

        history_files = sorted(
            self.history_dir.glob("npm_audit_*.json"),
            reverse=True
        )[:limit]

        for report_file in history_files:
            try:
                with open(report_file) as f:
                    data = json.load(f)
                    reports.append({
                        "file": str(report_file),
                        "project_path": data.get("project_path"),
                        "audit_time": data.get("audit_time"),
                        "total_vulnerabilities": data.get("total_vulnerabilities", 0),
                        "severity_counts": data.get("severity_counts", {}),
                    })
            except Exception:
                continue

        return reports

    def compare_reports(self, report1: NpmAuditReport, report2: NpmAuditReport) -> Dict[str, Any]:
        """
        Compare two audit reports

        Returns:
            Comparison showing new, fixed, and unchanged vulnerabilities
        """
        vulns1 = {v.name: v for v in report1.vulnerabilities}
        vulns2 = {v.name: v for v in report2.vulnerabilities}

        new_vulns = [vulns2[n] for n in vulns2 if n not in vulns1]
        fixed_vulns = [vulns1[n] for n in vulns1 if n not in vulns2]
        unchanged = [vulns2[n] for n in vulns2 if n in vulns1]

        return {
            "report1_time": report1.audit_time.isoformat(),
            "report2_time": report2.audit_time.isoformat(),
            "new_vulnerabilities": len(new_vulns),
            "fixed_vulnerabilities": len(fixed_vulns),
            "unchanged_vulnerabilities": len(unchanged),
            "new_details": [v.to_dict() for v in new_vulns],
            "fixed_details": [v.to_dict() for v in fixed_vulns],
        }


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for testing"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python npm_audit.py <project-path>")
        sys.exit(1)

    project_path = sys.argv[1]

    print(f"Running npm audit on: {project_path}")
    print("-" * 50)

    wrapper = NpmAuditWrapper()
    report = wrapper.run_audit(project_path)

    if report.error:
        print(f"Error: {report.error}")
        sys.exit(1)

    print(f"npm version: {report.npm_version}")
    print(f"Node version: {report.node_version}")
    print(f"Dependencies: {report.total_dependencies}")
    print(f"Dev Dependencies: {report.total_dev_dependencies}")
    print()
    print(f"Vulnerabilities found: {report.total_vulnerabilities}")
    print(f"  Critical: {report.severity_counts.get('critical', 0)}")
    print(f"  High: {report.severity_counts.get('high', 0)}")
    print(f"  Moderate: {report.severity_counts.get('moderate', 0)}")
    print(f"  Low: {report.severity_counts.get('low', 0)}")
    print()

    if report.vulnerabilities:
        print("Top vulnerabilities:")
        for vuln in report.vulnerabilities[:5]:
            print(f"  [{vuln.severity.value.upper()}] {vuln.name}")
            if vuln.title:
                print(f"    {vuln.title[:60]}...")
            if vuln.fix_available:
                print(f"    Fix available: Yes")
        print()

    # Save report
    save_path = wrapper.save_report(report)
    print(f"Report saved: {save_path}")


if __name__ == "__main__":
    main()
