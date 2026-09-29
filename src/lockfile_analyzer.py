#!/usr/bin/env python3
"""
Shellockolm Lockfile Analyzer
Analyzes package-lock.json, yarn.lock, and pnpm-lock.yaml for security issues

Features:
- Detects outdated transitive dependencies
- Identifies duplicate packages
- Finds integrity hash mismatches
- Checks for known vulnerable versions
- Detects dependency confusion attacks
"""

import json
import re
import hashlib
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum

try:
    from vulnerability_database import VulnerabilityDatabase, Severity
except ImportError:
    pass


class LockfileType(Enum):
    """Types of supported lockfiles"""
    NPM = "package-lock.json"
    YARN = "yarn.lock"
    YARN_BERRY = "yarn.lock (berry)"
    PNPM = "pnpm-lock.yaml"
    UNKNOWN = "unknown"


class IssueType(Enum):
    """Types of lockfile issues"""
    VULNERABLE_VERSION = "vulnerable_version"
    OUTDATED_DEPENDENCY = "outdated_dependency"
    DUPLICATE_PACKAGE = "duplicate_package"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    MISSING_INTEGRITY = "missing_integrity"
    DEPENDENCY_CONFUSION = "dependency_confusion"
    TYPOSQUATTING = "typosquatting"
    UNPINNED_VERSION = "unpinned_version"
    PRIVATE_REGISTRY = "private_registry"
    GIT_DEPENDENCY = "git_dependency"
    LOCAL_DEPENDENCY = "local_dependency"


class IssueSeverity(Enum):
    """Severity of lockfile issues"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class LockfileIssue:
    """An issue found in a lockfile"""
    issue_type: IssueType
    severity: IssueSeverity
    package_name: str
    current_version: str
    title: str
    description: str
    remediation: str
    cve_ids: List[str] = field(default_factory=list)
    safe_version: Optional[str] = None
    line_number: int = 0


@dataclass
class PackageInfo:
    """Information about a package in the lockfile"""
    name: str
    version: str
    resolved_url: Optional[str] = None
    integrity: Optional[str] = None
    dependencies: Dict[str, str] = field(default_factory=dict)
    dev_dependency: bool = False
    optional: bool = False


@dataclass
class LockfileReport:
    """Report of lockfile analysis"""
    file_path: str
    lockfile_type: LockfileType
    scan_time: datetime
    total_packages: int
    total_issues: int
    critical: int
    high: int
    medium: int
    low: int
    info: int
    issues: List[LockfileIssue] = field(default_factory=list)
    packages: Dict[str, PackageInfo] = field(default_factory=dict)
    duplicates: Dict[str, List[str]] = field(default_factory=dict)
    duration: float = 0.0


# Known typosquatting packages
TYPOSQUATTING_PACKAGES = {
    # Common typos of popular packages
    "lodahs": "lodash",
    "lodashs": "lodash",
    "loadsh": "lodash",
    "axois": "axios",
    "axio": "axios",
    "expresss": "express",
    "expres": "express",
    "recat": "react",
    "recact": "react",
    "raect": "react",
    "angualr": "angular",
    "agular": "angular",
    "momnet": "moment",
    "momment": "moment",
    "underscroe": "underscore",
    "undersore": "underscore",
    "jqeury": "jquery",
    "jqurey": "jquery",
    "webapck": "webpack",
    "wepback": "webpack",
    "bable": "babel",
    "babael": "babel",
    "eslnt": "eslint",
    "esllint": "eslint",
    "typescirpt": "typescript",
    "typescrpt": "typescript",
}


class LockfileAnalyzer:
    """
    Analyzes npm/yarn/pnpm lockfiles for security issues
    """

    def __init__(self):
        try:
            self.vuln_db = VulnerabilityDatabase()
        except Exception:
            self.vuln_db = None

    def detect_lockfile_type(self, file_path: Path) -> LockfileType:
        """Detect the type of lockfile"""
        name = file_path.name.lower()
        
        if name == "package-lock.json":
            return LockfileType.NPM
        elif name == "yarn.lock":
            # Check if it's Yarn Berry (v2+) or classic
            content = file_path.read_text()
            if content.startswith("__metadata:") or "resolution:" in content:
                return LockfileType.YARN_BERRY
            return LockfileType.YARN
        elif name in ["pnpm-lock.yaml", "pnpm-lock.yml"]:
            return LockfileType.PNPM
        
        return LockfileType.UNKNOWN

    def parse_npm_lockfile(self, file_path: Path) -> Dict[str, PackageInfo]:
        """Parse package-lock.json"""
        packages = {}
        
        try:
            data = json.loads(file_path.read_text())
            lockfile_version = data.get("lockfileVersion", 1)
            
            if lockfile_version >= 2:
                # npm v7+ format with "packages" key
                for pkg_path, pkg_data in data.get("packages", {}).items():
                    if not pkg_path or pkg_path == "":
                        continue  # Skip root package
                    
                    # Extract package name from path (node_modules/...)
                    name = pkg_path.replace("node_modules/", "").split("/")[-1]
                    if not name:
                        continue
                    
                    version = pkg_data.get("version", "unknown")
                    packages[f"{name}@{version}"] = PackageInfo(
                        name=name,
                        version=version,
                        resolved_url=pkg_data.get("resolved"),
                        integrity=pkg_data.get("integrity"),
                        dependencies=pkg_data.get("dependencies", {}),
                        dev_dependency=pkg_data.get("dev", False),
                        optional=pkg_data.get("optional", False),
                    )
            else:
                # npm v6 format with "dependencies" key
                def parse_deps(deps: Dict, dev: bool = False):
                    for name, pkg_data in deps.items():
                        if isinstance(pkg_data, dict):
                            version = pkg_data.get("version", "unknown")
                            packages[f"{name}@{version}"] = PackageInfo(
                                name=name,
                                version=version,
                                resolved_url=pkg_data.get("resolved"),
                                integrity=pkg_data.get("integrity"),
                                dependencies=pkg_data.get("requires", {}),
                                dev_dependency=dev,
                            )
                            # Recurse into nested dependencies
                            if "dependencies" in pkg_data:
                                parse_deps(pkg_data["dependencies"])
                
                parse_deps(data.get("dependencies", {}))
                
        except Exception as e:
            print(f"Error parsing npm lockfile: {e}")
        
        return packages

    def parse_yarn_lockfile(self, file_path: Path) -> Dict[str, PackageInfo]:
        """Parse yarn.lock (classic v1)"""
        packages = {}
        
        try:
            content = file_path.read_text()
            
            # Parse yarn.lock format
            current_pkg = None
            current_data = {}
            
            for line in content.split("\n"):
                # Package header line (e.g., "lodash@^4.17.0:")
                if line and not line.startswith(" ") and not line.startswith("#"):
                    if current_pkg and current_data:
                        packages[current_pkg] = PackageInfo(**current_data)
                    
                    # Parse package specifier
                    match = re.match(r'^"?([^@]+)@', line.rstrip(":"))
                    if match:
                        current_pkg = None
                        current_data = {}
                        pkg_name = match.group(1).strip('"')
                        current_data["name"] = pkg_name
                        current_data["dependencies"] = {}
                    continue
                
                # Property lines
                if line.startswith("  "):
                    key_value = line.strip()
                    if key_value.startswith("version "):
                        version = key_value.replace("version ", "").strip('"')
                        current_data["version"] = version
                        current_pkg = f"{current_data.get('name', 'unknown')}@{version}"
                    elif key_value.startswith("resolved "):
                        current_data["resolved_url"] = key_value.replace("resolved ", "").strip('"')
                    elif key_value.startswith("integrity "):
                        current_data["integrity"] = key_value.replace("integrity ", "").strip()
            
            # Don't forget the last package
            if current_pkg and current_data:
                packages[current_pkg] = PackageInfo(**current_data)
                
        except Exception as e:
            print(f"Error parsing yarn lockfile: {e}")
        
        return packages

    def parse_pnpm_lockfile(self, file_path: Path) -> Dict[str, PackageInfo]:
        """Parse pnpm-lock.yaml"""
        packages = {}
        
        try:
            # Simple YAML parsing without external dependency
            content = file_path.read_text()
            
            # Very basic YAML parsing for pnpm-lock
            in_packages = False
            current_pkg = None
            current_version = None
            
            for line in content.split("\n"):
                if line.strip() == "packages:":
                    in_packages = True
                    continue
                
                if in_packages:
                    # Package entry like "  /@babel/core@7.23.0:"
                    if line.startswith("  /") or line.startswith("  '@"):
                        match = re.match(r'^\s+[\'"]?/?(@?[^@]+)@([^:\'\"]+)', line)
                        if match:
                            current_pkg = match.group(1)
                            current_version = match.group(2)
                            packages[f"{current_pkg}@{current_version}"] = PackageInfo(
                                name=current_pkg,
                                version=current_version,
                            )
                    elif line.startswith("    resolution:"):
                        if current_pkg and current_version:
                            key = f"{current_pkg}@{current_version}"
                            if key in packages:
                                match = re.search(r'integrity:\s*(\S+)', line)
                                if match:
                                    packages[key].integrity = match.group(1)
                                    
        except Exception as e:
            print(f"Error parsing pnpm lockfile: {e}")
        
        return packages

    def find_duplicates(self, packages: Dict[str, PackageInfo]) -> Dict[str, List[str]]:
        """Find duplicate packages (same name, different versions)"""
        by_name: Dict[str, List[str]] = {}
        
        for key, pkg in packages.items():
            if pkg.name not in by_name:
                by_name[pkg.name] = []
            by_name[pkg.name].append(pkg.version)
        
        # Return only packages with multiple versions
        return {name: versions for name, versions in by_name.items() if len(versions) > 1}

    def check_typosquatting(self, packages: Dict[str, PackageInfo]) -> List[LockfileIssue]:
        """Check for potential typosquatting packages"""
        issues = []
        
        for key, pkg in packages.items():
            name_lower = pkg.name.lower()
            
            if name_lower in TYPOSQUATTING_PACKAGES:
                intended = TYPOSQUATTING_PACKAGES[name_lower]
                issues.append(LockfileIssue(
                    issue_type=IssueType.TYPOSQUATTING,
                    severity=IssueSeverity.CRITICAL,
                    package_name=pkg.name,
                    current_version=pkg.version,
                    title=f"Potential typosquatting: {pkg.name}",
                    description=f"Package '{pkg.name}' looks like a typosquat of '{intended}'. "
                                "This could be a malicious package trying to intercept installations.",
                    remediation=f"Remove '{pkg.name}' and install '{intended}' instead.",
                ))
        
        return issues

    def check_dependency_confusion(self, packages: Dict[str, PackageInfo]) -> List[LockfileIssue]:
        """Check for potential dependency confusion attacks"""
        issues = []
        
        for key, pkg in packages.items():
            if pkg.resolved_url:
                # Check for private registry URLs
                if any(registry in pkg.resolved_url for registry in [
                    "registry.npmjs.org",
                    "registry.yarnpkg.com",
                ]):
                    continue  # Public registry, OK
                
                # Check if it's a scoped package from private registry
                if pkg.name.startswith("@"):
                    # Scoped packages from private registries could be vulnerable
                    # if the scope isn't properly reserved on npm
                    issues.append(LockfileIssue(
                        issue_type=IssueType.DEPENDENCY_CONFUSION,
                        severity=IssueSeverity.MEDIUM,
                        package_name=pkg.name,
                        current_version=pkg.version,
                        title=f"Private registry dependency: {pkg.name}",
                        description=f"Package '{pkg.name}' is resolved from a private registry. "
                                    "Ensure the scope is reserved on npm to prevent dependency confusion.",
                        remediation="Reserve the scope on npm registry or use .npmrc to enforce private registry.",
                    ))
        
        return issues

    def check_vulnerabilities(self, packages: Dict[str, PackageInfo]) -> List[LockfileIssue]:
        """Check packages against vulnerability database"""
        issues = []
        
        if not self.vuln_db:
            return issues
        
        for key, pkg in packages.items():
            # Check each CVE in the database
            for vuln in self.vuln_db.get_all_vulnerabilities():
                if pkg.name in vuln.packages:
                    # affected_versions is a List[str] of exact versions and
                    # range specs (e.g. "<3.9.4", "19.0.0-19.2.2", "20.x").
                    if self._is_version_affected(pkg.version, vuln.affected_versions):
                        patched = self._resolve_patched_version(pkg, vuln)

                        issues.append(LockfileIssue(
                            issue_type=IssueType.VULNERABLE_VERSION,
                            severity=IssueSeverity[vuln.severity.value],
                            package_name=pkg.name,
                            current_version=pkg.version,
                            title=f"Vulnerable package: {pkg.name}@{pkg.version}",
                            description=f"{vuln.cve_id}: {vuln.title}",
                            remediation=f"Upgrade to {patched}",
                            cve_ids=[vuln.cve_id],
                            safe_version=patched,
                        ))
        
        return issues

    def _is_version_affected(self, version: str, affected_versions: List[str]) -> bool:
        """Check if a concrete version is in the affected_versions list.

        affected_versions is a List[str] of exact versions ("19.0.0") and range
        specs ("<3.9.4", "19.0.0-19.2.2", "20.x"). Prefer the vulnerability
        database's range helpers when available, falling back to the local
        comparator otherwise.
        """
        if not version or not affected_versions:
            return False

        clean_version = version.lstrip("^~>=<").split()[0].strip()

        # Exact match against any listed version
        if clean_version in affected_versions:
            return True

        # Range matching - reuse the database helper if we have it
        db_in_range = getattr(self.vuln_db, "_version_in_range", None)
        for affected in affected_versions:
            if db_in_range is not None:
                try:
                    if db_in_range(clean_version, affected):
                        return True
                    continue
                except Exception:
                    pass
            # Fallback to the local single-range comparator
            if self._version_in_range(clean_version, [affected]):
                return True

        return False

    def _resolve_patched_version(self, pkg: "PackageInfo", vuln) -> str:
        """Resolve the recommended patched version for a vulnerable package.

        patched_versions is keyed by version-range (e.g. "15.0.x", "<3.9.4"),
        NOT by package name. Delegate to the database resolver when possible.
        """
        get_patched = getattr(self.vuln_db, "get_patched_version", None)
        if get_patched is not None:
            try:
                resolved = get_patched(pkg.name, pkg.version, vuln.cve_id)
                if resolved:
                    return resolved
            except Exception:
                pass

        # Fallback: first patched value listed, else "latest"
        patched_map = getattr(vuln, "patched_versions", None) or {}
        for value in patched_map.values():
            if value:
                return value
        return "latest"

    def _version_in_range(self, version: str, ranges: List[str]) -> bool:
        """Check if a version falls within any of the affected ranges"""
        if not ranges:
            return False
        
        for range_str in ranges:
            # Simple range checking (should use semver library for production)
            if range_str == "*":
                return True
            
            if range_str.startswith("<"):
                # Less than comparison
                try:
                    target = range_str[1:].strip()
                    if self._version_compare(version, target) < 0:
                        return True
                except Exception:
                    pass
            
            if range_str.startswith(">=") and "<" in range_str:
                # Range like >=1.0.0 <2.0.0
                try:
                    parts = range_str.split("<")
                    min_ver = parts[0].replace(">=", "").strip()
                    max_ver = parts[1].strip()
                    if self._version_compare(version, min_ver) >= 0 and \
                       self._version_compare(version, max_ver) < 0:
                        return True
                except Exception:
                    pass
        
        return False

    def _version_compare(self, v1: str, v2: str) -> int:
        """Compare two semver versions"""
        def parse_version(v):
            # Extract just the numeric parts
            match = re.match(r'(\d+)\.(\d+)\.(\d+)', v)
            if match:
                return tuple(int(x) for x in match.groups())
            return (0, 0, 0)
        
        p1, p2 = parse_version(v1), parse_version(v2)
        
        if p1 < p2:
            return -1
        elif p1 > p2:
            return 1
        return 0

    def check_integrity(self, packages: Dict[str, PackageInfo]) -> List[LockfileIssue]:
        """Check for missing or invalid integrity hashes"""
        issues = []
        
        for key, pkg in packages.items():
            if not pkg.integrity:
                issues.append(LockfileIssue(
                    issue_type=IssueType.MISSING_INTEGRITY,
                    severity=IssueSeverity.LOW,
                    package_name=pkg.name,
                    current_version=pkg.version,
                    title=f"Missing integrity hash: {pkg.name}",
                    description=f"Package '{pkg.name}@{pkg.version}' has no integrity hash. "
                                "This makes it harder to detect tampering.",
                    remediation="Run 'npm install' or 'yarn install' to regenerate lockfile with integrity hashes.",
                ))
        
        return issues

    def check_git_dependencies(self, packages: Dict[str, PackageInfo]) -> List[LockfileIssue]:
        """Check for git dependencies (potentially risky)"""
        issues = []
        
        for key, pkg in packages.items():
            if pkg.resolved_url and any(x in pkg.resolved_url for x in ["github.com", "gitlab.com", "bitbucket.org", ".git"]):
                issues.append(LockfileIssue(
                    issue_type=IssueType.GIT_DEPENDENCY,
                    severity=IssueSeverity.INFO,
                    package_name=pkg.name,
                    current_version=pkg.version,
                    title=f"Git dependency: {pkg.name}",
                    description=f"Package '{pkg.name}' is resolved from a git repository. "
                                "Git dependencies can change without version updates.",
                    remediation="Pin to a specific commit hash or use a published npm version.",
                ))
        
        return issues

    def analyze(self, file_path: str) -> LockfileReport:
        """Analyze a lockfile for security issues"""
        import time
        start_time = time.time()
        
        path = Path(file_path)
        if not path.exists():
            return LockfileReport(
                file_path=file_path,
                lockfile_type=LockfileType.UNKNOWN,
                scan_time=datetime.now(),
                total_packages=0,
                total_issues=0,
                critical=0,
                high=0,
                medium=0,
                low=0,
                info=0,
            )
        
        # Detect lockfile type
        lockfile_type = self.detect_lockfile_type(path)
        
        # Parse lockfile
        packages = {}
        if lockfile_type == LockfileType.NPM:
            packages = self.parse_npm_lockfile(path)
        elif lockfile_type in [LockfileType.YARN, LockfileType.YARN_BERRY]:
            packages = self.parse_yarn_lockfile(path)
        elif lockfile_type == LockfileType.PNPM:
            packages = self.parse_pnpm_lockfile(path)
        
        # Find duplicates
        duplicates = self.find_duplicates(packages)
        
        # Run all checks
        issues = []
        issues.extend(self.check_typosquatting(packages))
        issues.extend(self.check_dependency_confusion(packages))
        issues.extend(self.check_vulnerabilities(packages))
        issues.extend(self.check_integrity(packages))
        issues.extend(self.check_git_dependencies(packages))
        
        # Add duplicate issues
        for name, versions in duplicates.items():
            if len(versions) > 2:  # Only flag if more than 2 versions
                issues.append(LockfileIssue(
                    issue_type=IssueType.DUPLICATE_PACKAGE,
                    severity=IssueSeverity.INFO,
                    package_name=name,
                    current_version=", ".join(versions),
                    title=f"Multiple versions: {name}",
                    description=f"Package '{name}' has {len(versions)} different versions installed. "
                                f"This increases bundle size and could cause conflicts.",
                    remediation="Run 'npm dedupe' or 'yarn dedupe' to consolidate versions.",
                ))
        
        # Count severities
        critical = sum(1 for i in issues if i.severity == IssueSeverity.CRITICAL)
        high = sum(1 for i in issues if i.severity == IssueSeverity.HIGH)
        medium = sum(1 for i in issues if i.severity == IssueSeverity.MEDIUM)
        low = sum(1 for i in issues if i.severity == IssueSeverity.LOW)
        info = sum(1 for i in issues if i.severity == IssueSeverity.INFO)
        
        duration = time.time() - start_time
        
        return LockfileReport(
            file_path=file_path,
            lockfile_type=lockfile_type,
            scan_time=datetime.now(),
            total_packages=len(packages),
            total_issues=len(issues),
            critical=critical,
            high=high,
            medium=medium,
            low=low,
            info=info,
            issues=issues,
            packages=packages,
            duplicates=duplicates,
            duration=duration,
        )

    def generate_report(self, report: LockfileReport, output_path: Optional[str] = None) -> Dict[str, Any]:
        """Generate a detailed lockfile analysis report"""
        output = {
            "file_path": report.file_path,
            "lockfile_type": report.lockfile_type.value,
            "scan_time": report.scan_time.isoformat(),
            "duration": report.duration,
            "summary": {
                "total_packages": report.total_packages,
                "total_issues": report.total_issues,
                "critical": report.critical,
                "high": report.high,
                "medium": report.medium,
                "low": report.low,
                "info": report.info,
                "duplicates": len(report.duplicates),
            },
            "issues": [
                {
                    "type": issue.issue_type.value,
                    "severity": issue.severity.value,
                    "package": issue.package_name,
                    "version": issue.current_version,
                    "title": issue.title,
                    "description": issue.description,
                    "remediation": issue.remediation,
                    "cve_ids": issue.cve_ids,
                    "safe_version": issue.safe_version,
                }
                for issue in report.issues
            ],
            "duplicates": report.duplicates,
        }
        
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(output, f, indent=2)
        
        return output


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT (for standalone use)
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point"""
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python lockfile_analyzer.py <path-to-lockfile>")
        sys.exit(1)
    
    analyzer = LockfileAnalyzer()
    report = analyzer.analyze(sys.argv[1])
    
    print(f"\n=== Lockfile Analysis: {report.file_path} ===")
    print(f"Type: {report.lockfile_type.value}")
    print(f"Packages: {report.total_packages}")
    print(f"Issues: {report.total_issues}")
    print(f"  Critical: {report.critical}")
    print(f"  High: {report.high}")
    print(f"  Medium: {report.medium}")
    print(f"  Low: {report.low}")
    print(f"  Info: {report.info}")
    
    if report.issues:
        print("\n=== Issues ===")
        for issue in report.issues[:10]:
            print(f"\n[{issue.severity.value}] {issue.title}")
            print(f"  {issue.description}")
            print(f"  Fix: {issue.remediation}")
    
    if report.duplicates:
        print(f"\n=== Duplicates ({len(report.duplicates)}) ===")
        for name, versions in list(report.duplicates.items())[:5]:
            print(f"  {name}: {len(versions)} versions")


if __name__ == "__main__":
    main()
