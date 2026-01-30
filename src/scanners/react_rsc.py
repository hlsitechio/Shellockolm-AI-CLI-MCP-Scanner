"""
React Server Components Scanner
Detects CVE-2025-55182, CVE-2025-66478, and related RSC vulnerabilities
"""

from pathlib import Path
from typing import List, Set
from datetime import datetime

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class ReactRSCScanner(BaseScanner):
    """Scanner for React Server Components vulnerabilities"""

    NAME = "react-rsc"
    DESCRIPTION = "Scans for React Server Components RCE and related vulnerabilities"
    CVE_IDS = [
        "CVE-2025-55182",  # React2Shell RCE
        "CVE-2025-66478",  # Next.js duplicate
        "CVE-2025-55183",  # Source code exposure
        "CVE-2025-55184",  # DoS infinite loop
        "CVE-2025-67779",  # DoS incomplete fix
    ]
    SUPPORTED_PACKAGES = [
        "react",
        "react-dom",
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack",
        "next",
    ]

    # Vulnerable React 19.x versions
    VULNERABLE_REACT_VERSIONS = {
        "19.0.0", "19.0.1", "19.0.2",
        "19.1.0", "19.1.1", "19.1.2", "19.1.3",
        "19.2.0", "19.2.1", "19.2.2",
    }

    # RSC indicator packages
    RSC_PACKAGES = {
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack",
        "@parcel/rsc",
        "@vitejs/plugin-rsc",
    }

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """
        Scan directory for React RSC vulnerabilities
        
        Args:
            quick_mode: If True, only checks package.json versions (FAST)
                       If False, includes deep file analysis (SLOW)
        """
        result = self.create_result(path)

        packages_scanned = 0
        vulnerable_projects = 0

        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            
            if quick_mode:
                # QUICK MODE: Only check package.json versions
                findings = self._scan_package_quick(package_json)
            else:
                # DEEP MODE: Full analysis
                findings = self._scan_package(package_json)

            if findings:
                vulnerable_projects += 1
                result.findings.extend(findings)

        result.stats["packages_scanned"] = packages_scanned
        result.stats["vulnerable_projects"] = vulnerable_projects
        result.stats["quick_mode"] = quick_mode

        return self.finalize_result(result)

    def _scan_package_quick(self, package_json: Path) -> List[ScanFinding]:
        """
        QUICK SCAN: Only check package.json versions against CVE database
        Skips deep file analysis, RSC detection, etc.
        """
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)

        # Check React version against database (FAST)
        for pkg in ["react", "react-dom"]:
            if pkg in deps:
                version = self.extract_version(deps[pkg])
                vulns = self.check_package_vulnerability(pkg, version)

                for vuln in vulns:
                    # In quick mode, report ALL React CVEs
                    # (we skip the RSC usage check for speed)
                    finding = self.create_finding(vuln, pkg, version, package_json)
                    finding.raw_data["quick_scan"] = True
                    findings.append(finding)

        return findings

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a single package.json for React RSC vulnerabilities"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)
        project_dir = package_json.parent

        # Check if project uses React Server Components
        uses_rsc = self._check_uses_rsc(deps, project_dir)

        # Check React version
        for pkg in ["react", "react-dom"]:
            if pkg in deps:
                version = self.extract_version(deps[pkg])
                vulns = self.check_package_vulnerability(pkg, version)

                for vuln in vulns:
                    # RSC vulns only apply if actually using RSC
                    if vuln.cve_id in ["CVE-2025-55182", "CVE-2025-55183", "CVE-2025-55184", "CVE-2025-67779"]:
                        if uses_rsc:
                            finding = self.create_finding(vuln, pkg, version, package_json)
                            finding.raw_data["uses_rsc"] = True
                            findings.append(finding)
                    else:
                        findings.append(self.create_finding(vuln, pkg, version, package_json))

        # Check RSC-specific packages
        for pkg in self.RSC_PACKAGES:
            if pkg in deps:
                version = self.extract_version(deps[pkg])
                vulns = self.check_package_vulnerability(pkg, version)
                for vuln in vulns:
                    findings.append(self.create_finding(vuln, pkg, version, package_json))

        # Check Next.js (inherits React RSC vulns)
        if "next" in deps:
            version = self.extract_version(deps["next"])
            vulns = self.check_package_vulnerability("next", version)
            for vuln in vulns:
                # Only include RSC-related Next.js CVEs here
                if vuln.cve_id in ["CVE-2025-66478"]:
                    findings.append(self.create_finding(vuln, "next", version, package_json))

        # Also check lockfiles for more accurate versions
        lockfile_findings = self._check_lockfiles(project_dir, package_json)
        findings.extend(lockfile_findings)

        return findings

    def _check_uses_rsc(self, deps: dict, project_dir: Path) -> bool:
        """Check if project uses React Server Components"""
        # Check for RSC packages in dependencies
        for pkg in self.RSC_PACKAGES:
            if pkg in deps:
                return True

        # Check for Next.js app router (uses RSC by default in v13+)
        if "next" in deps:
            version = self.extract_version(deps["next"])
            try:
                major = int(version.split(".")[0])
                if major >= 13:
                    # Check for app directory (Next.js App Router)
                    app_dir = project_dir / "app"
                    src_app_dir = project_dir / "src" / "app"
                    if app_dir.exists() or src_app_dir.exists():
                        return True
            except (ValueError, IndexError):
                pass

        # Check for 'use server' directive in any .js/.jsx/.ts/.tsx files
        # (This is a heuristic - could be expensive for large projects)
        try:
            for ext in ["js", "jsx", "ts", "tsx"]:
                for f in project_dir.glob(f"**/*.{ext}"):
                    if "node_modules" in str(f):
                        continue
                    try:
                        with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
                            content = fp.read(2000)  # Only check first 2KB
                            if "'use server'" in content or '"use server"' in content:
                                return True
                    except:
                        pass
        except:
            pass

        return False

    def _check_lockfiles(self, project_dir: Path, package_json: Path) -> List[ScanFinding]:
        """Check lockfiles for accurate version information"""
        findings = []
        lockfiles = self.find_lockfiles(project_dir)

        for lockfile_name, lockfile_path in lockfiles.items():
            packages = {}

            if lockfile_name == "package-lock.json":
                lock_data = self.parse_package_lock(lockfile_path)
                if lock_data:
                    # npm v3+ format
                    if "packages" in lock_data:
                        for pkg_path, pkg_info in lock_data.get("packages", {}).items():
                            if pkg_path and "version" in pkg_info:
                                name = pkg_path.split("node_modules/")[-1]
                                if name:
                                    packages[name] = pkg_info["version"]
                    # npm v2 format
                    elif "dependencies" in lock_data:
                        for name, info in lock_data.get("dependencies", {}).items():
                            if "version" in info:
                                packages[name] = info["version"]

            elif lockfile_name == "yarn.lock":
                packages = self.parse_yarn_lock(lockfile_path)

            elif lockfile_name == "pnpm-lock.yaml":
                packages = self.parse_pnpm_lock(lockfile_path)

            # Check packages for vulnerabilities
            for pkg in self.SUPPORTED_PACKAGES:
                if pkg in packages:
                    version = packages[pkg]
                    vulns = self.check_package_vulnerability(pkg, version)
                    for vuln in vulns:
                        finding = self.create_finding(
                            vuln, pkg, version, package_json,
                            detection_method=f"lockfile:{lockfile_name}"
                        )
                        # Avoid duplicates
                        if not any(f.cve_id == finding.cve_id and f.package == finding.package
                                   for f in findings):
                            findings.append(finding)

        return findings

    def is_vulnerable_react_version(self, version: str) -> bool:
        """Quick check if React version is vulnerable"""
        clean_version = self.extract_version(version)
        return clean_version in self.VULNERABLE_REACT_VERSIONS
