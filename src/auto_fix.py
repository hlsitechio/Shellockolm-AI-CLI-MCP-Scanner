#!/usr/bin/env python3
"""
Shellockolm Auto-Fix Engine
Automatically patches vulnerable npm packages to secure versions

Features:
- Detects vulnerable package versions
- Looks up patched versions from vulnerability database
- Creates backups before modifications
- Updates package.json and lockfiles
- Supports bulk fixes and rollback
"""

import json
import shutil
import subprocess
import re
import tempfile
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

from vulnerability_database import VulnerabilityDatabase, Severity


class FixStatus(Enum):
    """Status of a fix operation"""
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    MANUAL_REQUIRED = "manual_required"
    ALREADY_FIXED = "already_fixed"


@dataclass
class VulnerableDependency:
    """A vulnerable dependency found in a project"""
    name: str
    current_version: str
    cve_ids: List[str]
    severity: Severity
    patched_version: Optional[str]
    is_dev_dep: bool = False
    file_path: str = ""


@dataclass
class FixResult:
    """Result of attempting to fix a vulnerability"""
    dependency: VulnerableDependency
    status: FixStatus
    message: str
    old_version: str
    new_version: Optional[str] = None
    backup_path: Optional[str] = None


@dataclass
class FixReport:
    """Complete report of fix operations"""
    project_path: str
    scan_time: datetime
    total_vulnerabilities: int
    fixed: int
    failed: int
    skipped: int
    manual_required: int
    results: List[FixResult] = field(default_factory=list)
    backup_dir: str = ""


class AutoFixer:
    """
    Automatic vulnerability fixer for npm projects
    """

    # Version patterns for semver
    SEMVER_PATTERN = re.compile(r'^[\^~]?(\d+)\.(\d+)\.(\d+)(?:-[a-zA-Z0-9.]+)?$')

    # Package version constraints
    VERSION_PREFIXES = ('^', '~', '>=', '>', '<=', '<', '=')

    def __init__(self, backup_dir: Optional[str] = None):
        self.vuln_db = VulnerabilityDatabase()
        if backup_dir is None:
            backup_dir = str(Path(tempfile.gettempdir()) / "shellockolm" / "backups")
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)

    def scan_project(self, project_path: str) -> List[VulnerableDependency]:
        """Scan a project for vulnerable dependencies"""
        vulnerabilities = []
        project = Path(project_path)

        # Read package.json
        pkg_json_path = project / "package.json"
        if not pkg_json_path.exists():
            return vulnerabilities

        try:
            pkg_data = json.loads(pkg_json_path.read_text())
        except json.JSONDecodeError:
            return vulnerabilities

        # Check all dependencies
        deps = pkg_data.get("dependencies", {})
        dev_deps = pkg_data.get("devDependencies", {})

        # Get all vulnerabilities from our database
        all_vulns = self.vuln_db.get_all_vulnerabilities()

        # Create lookup by package name
        vuln_lookup: Dict[str, List[Any]] = {}
        for vuln in all_vulns:
            for pkg in vuln.packages:
                if pkg not in vuln_lookup:
                    vuln_lookup[pkg] = []
                vuln_lookup[pkg].append(vuln)

        # Check regular dependencies
        for dep_name, dep_version in deps.items():
            if dep_name in vuln_lookup:
                for vuln in vuln_lookup[dep_name]:
                    if self._is_vulnerable(dep_version, vuln):
                        patched = vuln.patched_versions.get(dep_name)
                        vulnerabilities.append(VulnerableDependency(
                            name=dep_name,
                            current_version=dep_version,
                            cve_ids=[vuln.cve_id],
                            severity=vuln.severity,
                            patched_version=patched,
                            is_dev_dep=False,
                            file_path=str(pkg_json_path),
                        ))

        # Check dev dependencies
        for dep_name, dep_version in dev_deps.items():
            if dep_name in vuln_lookup:
                for vuln in vuln_lookup[dep_name]:
                    if self._is_vulnerable(dep_version, vuln):
                        patched = vuln.patched_versions.get(dep_name)
                        vulnerabilities.append(VulnerableDependency(
                            name=dep_name,
                            current_version=dep_version,
                            cve_ids=[vuln.cve_id],
                            severity=vuln.severity,
                            patched_version=patched,
                            is_dev_dep=True,
                            file_path=str(pkg_json_path),
                        ))

        return vulnerabilities

    def _is_vulnerable(self, installed_version: str, vuln) -> bool:
        """Check if installed version is vulnerable"""
        spec = installed_version.strip()

        # Fail SAFE for non-pinned / non-semver specifiers we cannot reason
        # about. Rewriting these would either break the project or be wrong, so
        # leave them untouched (return False) rather than assuming vulnerable.
        #   *, x, latest, ""            -> floating tags
        #   workspace:, npm:, file:,    -> protocol specs
        #   link:, git/url, github short
        lowered = spec.lower()
        if (
            spec in ("", "*", "x", "X")
            or lowered in ("latest", "next", "*")
            or lowered.startswith(("workspace:", "npm:", "file:", "link:", "portal:"))
            or "://" in lowered  # git+https://, https://, etc.
            or lowered.startswith(("git@", "git+"))
            or re.match(r'^[\w.-]+/[\w.-]+(#.*)?$', spec)  # github user/repo shorthand
        ):
            return False

        # Strip version prefix
        version = spec.lstrip('^~>=<')

        # Parse version components
        match = self.SEMVER_PATTERN.match(version)
        if not match:
            # Genuinely ambiguous but pinned-ish (e.g. odd pre-release tags):
            # stay conservative and treat as vulnerable.
            return True

        major, minor, patch = int(match.group(1)), int(match.group(2)), int(match.group(3))

        # Check against affected versions
        for affected in vuln.affected_versions:
            if self._version_matches_range(major, minor, patch, affected):
                return True

        return False

    def _version_matches_range(self, major: int, minor: int, patch: int, range_str: str) -> bool:
        """Check if version matches a version range"""
        # Handle common range patterns
        range_str = range_str.strip()

        if range_str.startswith('<'):
            # Less than
            target = range_str.lstrip('<= ')
            target_match = self.SEMVER_PATTERN.match(target)
            if target_match:
                t_major, t_minor, t_patch = int(target_match.group(1)), int(target_match.group(2)), int(target_match.group(3))
                return (major, minor, patch) < (t_major, t_minor, t_patch)
        elif range_str.startswith('>'):
            # Greater than
            target = range_str.lstrip('>= ')
            target_match = self.SEMVER_PATTERN.match(target)
            if target_match:
                t_major, t_minor, t_patch = int(target_match.group(1)), int(target_match.group(2)), int(target_match.group(3))
                return (major, minor, patch) > (t_major, t_minor, t_patch)
        elif '-' in range_str:
            # Range like "1.0.0 - 2.0.0"
            parts = range_str.split('-')
            if len(parts) == 2:
                low = parts[0].strip()
                high = parts[1].strip()
                low_match = self.SEMVER_PATTERN.match(low)
                high_match = self.SEMVER_PATTERN.match(high)
                if low_match and high_match:
                    l_major, l_minor, l_patch = int(low_match.group(1)), int(low_match.group(2)), int(low_match.group(3))
                    h_major, h_minor, h_patch = int(high_match.group(1)), int(high_match.group(2)), int(high_match.group(3))
                    return (l_major, l_minor, l_patch) <= (major, minor, patch) <= (h_major, h_minor, h_patch)
        else:
            # Exact version or wildcard
            if '*' in range_str or 'x' in range_str.lower():
                return True
            target_match = self.SEMVER_PATTERN.match(range_str)
            if target_match:
                t_major, t_minor, t_patch = int(target_match.group(1)), int(target_match.group(2)), int(target_match.group(3))
                return (major, minor, patch) == (t_major, t_minor, t_patch)

        return False

    def create_backup(self, project_path: str) -> str:
        """Create a backup of package.json and lockfiles"""
        project = Path(project_path)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_subdir = self.backup_dir / f"backup_{timestamp}"
        backup_subdir.mkdir(parents=True, exist_ok=True)

        # Backup package.json
        pkg_json = project / "package.json"
        if pkg_json.exists():
            shutil.copy2(pkg_json, backup_subdir / "package.json")

        # Backup package-lock.json
        pkg_lock = project / "package-lock.json"
        if pkg_lock.exists():
            shutil.copy2(pkg_lock, backup_subdir / "package-lock.json")

        # Backup yarn.lock
        yarn_lock = project / "yarn.lock"
        if yarn_lock.exists():
            shutil.copy2(yarn_lock, backup_subdir / "yarn.lock")

        # Backup pnpm-lock.yaml
        pnpm_lock = project / "pnpm-lock.yaml"
        if pnpm_lock.exists():
            shutil.copy2(pnpm_lock, backup_subdir / "pnpm-lock.yaml")

        # Save metadata
        metadata = {
            "project_path": str(project),
            "backup_time": datetime.now().isoformat(),
            "files_backed_up": [f.name for f in backup_subdir.iterdir()],
        }
        (backup_subdir / "metadata.json").write_text(json.dumps(metadata, indent=2))

        return str(backup_subdir)

    def fix_vulnerability(self, project_path: str, vuln: VulnerableDependency,
                          dry_run: bool = False) -> FixResult:
        """Fix a single vulnerability by updating package version"""
        project = Path(project_path)
        pkg_json_path = project / "package.json"

        if not vuln.patched_version:
            return FixResult(
                dependency=vuln,
                status=FixStatus.MANUAL_REQUIRED,
                message=f"No patched version available for {vuln.name}",
                old_version=vuln.current_version,
            )

        try:
            pkg_data = json.loads(pkg_json_path.read_text())
        except Exception as e:
            return FixResult(
                dependency=vuln,
                status=FixStatus.FAILED,
                message=f"Failed to read package.json: {e}",
                old_version=vuln.current_version,
            )

        # Determine which dependency section
        dep_key = "devDependencies" if vuln.is_dev_dep else "dependencies"

        if dep_key not in pkg_data or vuln.name not in pkg_data[dep_key]:
            return FixResult(
                dependency=vuln,
                status=FixStatus.SKIPPED,
                message=f"Package {vuln.name} not found in {dep_key}",
                old_version=vuln.current_version,
            )

        old_version = pkg_data[dep_key][vuln.name]

        # Preserve version prefix (^, ~, etc.)
        prefix = ""
        for p in self.VERSION_PREFIXES:
            if old_version.startswith(p):
                prefix = p
                break

        new_version = f"{prefix}{vuln.patched_version}"

        if dry_run:
            return FixResult(
                dependency=vuln,
                status=FixStatus.SUCCESS,
                message=f"[DRY RUN] Would update {vuln.name}: {old_version} -> {new_version}",
                old_version=old_version,
                new_version=new_version,
            )

        # Update package.json
        pkg_data[dep_key][vuln.name] = new_version

        try:
            pkg_json_path.write_text(json.dumps(pkg_data, indent=2) + "\n")
        except Exception as e:
            return FixResult(
                dependency=vuln,
                status=FixStatus.FAILED,
                message=f"Failed to write package.json: {e}",
                old_version=old_version,
            )

        return FixResult(
            dependency=vuln,
            status=FixStatus.SUCCESS,
            message=f"Updated {vuln.name}: {old_version} -> {new_version}",
            old_version=old_version,
            new_version=new_version,
        )

    def fix_all(self, project_path: str, dry_run: bool = False,
                severity_threshold: Optional[Severity] = None,
                create_backup: bool = True) -> FixReport:
        """Fix all vulnerabilities in a project"""
        project = Path(project_path)

        # Scan for vulnerabilities
        vulnerabilities = self.scan_project(str(project))

        # Filter by severity if threshold specified
        if severity_threshold:
            severity_order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]
            threshold_idx = severity_order.index(severity_threshold)
            vulnerabilities = [v for v in vulnerabilities
                            if severity_order.index(v.severity) <= threshold_idx]

        # Create backup
        backup_path = ""
        if create_backup and not dry_run:
            backup_path = self.create_backup(str(project))

        # Fix each vulnerability
        results = []
        fixed = 0
        failed = 0
        skipped = 0
        manual_required = 0

        for vuln in vulnerabilities:
            result = self.fix_vulnerability(str(project), vuln, dry_run=dry_run)
            results.append(result)

            if result.status == FixStatus.SUCCESS:
                fixed += 1
            elif result.status == FixStatus.FAILED:
                failed += 1
            elif result.status == FixStatus.SKIPPED:
                skipped += 1
            elif result.status == FixStatus.MANUAL_REQUIRED:
                manual_required += 1

        return FixReport(
            project_path=str(project),
            scan_time=datetime.now(),
            total_vulnerabilities=len(vulnerabilities),
            fixed=fixed,
            failed=failed,
            skipped=skipped,
            manual_required=manual_required,
            results=results,
            backup_dir=backup_path,
        )

    def rollback(self, backup_path: str, project_path: str) -> bool:
        """Rollback to a previous backup"""
        backup = Path(backup_path)
        project = Path(project_path)

        if not backup.exists():
            return False

        try:
            # Restore package.json
            backup_pkg = backup / "package.json"
            if backup_pkg.exists():
                shutil.copy2(backup_pkg, project / "package.json")

            # Restore lockfiles
            for lockfile in ["package-lock.json", "yarn.lock", "pnpm-lock.yaml"]:
                backup_lock = backup / lockfile
                if backup_lock.exists():
                    shutil.copy2(backup_lock, project / lockfile)

            return True
        except Exception:
            return False

    def generate_report(self, report: FixReport, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate a detailed fix report"""
        output = {
            "project_path": report.project_path,
            "scan_time": report.scan_time.isoformat(),
            "backup_dir": report.backup_dir,
            "summary": {
                "total_vulnerabilities": report.total_vulnerabilities,
                "fixed": report.fixed,
                "failed": report.failed,
                "skipped": report.skipped,
                "manual_required": report.manual_required,
            },
            "fixes": [],
        }

        for result in report.results:
            fix = {
                "package": result.dependency.name,
                "cve_ids": result.dependency.cve_ids,
                "severity": result.dependency.severity.value,
                "status": result.status.value,
                "message": result.message,
                "old_version": result.old_version,
                "new_version": result.new_version,
            }
            output["fixes"].append(fix)

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(json.dumps(output, indent=2))

        return output


# ─────────────────────────────────────────────────────────────────
# CLI INTEGRATION
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for auto-fix"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: shellockolm-fix <project-path> [--dry-run] [--critical-only]")
        sys.exit(1)

    project_path = sys.argv[1]
    dry_run = "--dry-run" in sys.argv
    critical_only = "--critical-only" in sys.argv

    fixer = AutoFixer()

    threshold = Severity.CRITICAL if critical_only else None
    report = fixer.fix_all(project_path, dry_run=dry_run, severity_threshold=threshold)

    # Print results
    print(f"\n{'[DRY RUN] ' if dry_run else ''}Auto-Fix Report")
    print("=" * 50)
    print(f"Project: {report.project_path}")
    print(f"Total vulnerabilities: {report.total_vulnerabilities}")
    print(f"Fixed: {report.fixed}")
    print(f"Failed: {report.failed}")
    print(f"Manual required: {report.manual_required}")

    if report.backup_dir:
        print(f"Backup: {report.backup_dir}")

    print("\nDetails:")
    for result in report.results:
        status_icon = "✓" if result.status == FixStatus.SUCCESS else "✗" if result.status == FixStatus.FAILED else "⚠"
        print(f"  {status_icon} {result.dependency.name}: {result.message}")


if __name__ == "__main__":
    main()
