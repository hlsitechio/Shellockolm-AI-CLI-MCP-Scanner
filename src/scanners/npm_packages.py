"""
NPM Package Scanner
Detects vulnerabilities in popular npm packages:
- mysql2 (CVE-2024-21508)
- jsonpath-plus (CVE-2024-21534, CVE-2025-1302)
- body-parser (CVE-2024-45590)
- multer (CVE-2025-48997, CVE-2025-47944)
- nuxt (CVE-2024-34344)
- @adonisjs/bodyparser (CVE-2026-21440)
"""

from pathlib import Path
from typing import List, Set
from datetime import datetime

from .base import BaseScanner, ScanResult, ScanFinding


class NPMPackageScanner(BaseScanner):
    """Scanner for common NPM package vulnerabilities"""

    NAME = "npm-packages"
    DESCRIPTION = "Scans for vulnerabilities in popular npm packages"
    CVE_IDS = [
        "CVE-2024-21508",   # mysql2 RCE
        "CVE-2024-21534",   # jsonpath-plus RCE
        "CVE-2025-1302",    # jsonpath-plus RCE (incomplete fix)
        "CVE-2024-45590",   # body-parser DoS
        "CVE-2025-48997",   # multer DoS
        "CVE-2025-47944",   # multer multiple issues
        "CVE-2024-34344",   # Nuxt.js test mode RCE
        "CVE-2024-13059",   # AnythingLLM path traversal
        "CVE-2026-21440",   # AdonisJS bodyparser path traversal
    ]

    # Package name -> CVE mapping with version checks
    PACKAGE_VULNERABILITIES = {
        "mysql2": {
            "cves": ["CVE-2024-21508"],
            "vulnerable_below": "3.9.4",
        },
        "jsonpath-plus": {
            "cves": ["CVE-2024-21534", "CVE-2025-1302"],
            "vulnerable_below": "10.2.0",
        },
        "body-parser": {
            "cves": ["CVE-2024-45590"],
            "vulnerable_below": "1.20.3",
        },
        "multer": {
            "cves": ["CVE-2025-48997", "CVE-2025-47944"],
            "vulnerable_below": "2.0.1",
        },
        "nuxt": {
            "cves": ["CVE-2024-34344"],
            "vulnerable_below": "3.12.4",
        },
        "@adonisjs/bodyparser": {
            "cves": ["CVE-2026-21440"],
            "vulnerable_below": "9.0.0",
        },
        "@nestjs/platform-express": {
            "cves": ["CVE-2025-47944"],
            "vulnerable_versions": ["1.4.4-lts.1"],  # Specific version
        },
    }

    SUPPORTED_PACKAGES = list(PACKAGE_VULNERABILITIES.keys())

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """Scan directory for npm package vulnerabilities"""
        result = self.create_result(path)

        packages_scanned = 0
        vulnerable_projects = 0

        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            findings = self._scan_package(package_json)

            if findings:
                vulnerable_projects += 1
                result.findings.extend(findings)

        result.stats["packages_scanned"] = packages_scanned
        result.stats["vulnerable_projects"] = vulnerable_projects

        return self.finalize_result(result)

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a single package.json for npm package vulnerabilities"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)
        project_dir = package_json.parent

        # Check each tracked package
        for package, vuln_info in self.PACKAGE_VULNERABILITIES.items():
            if package in deps:
                version = self.extract_version(deps[package])
                is_vulnerable = False

                # Check if below vulnerable threshold
                if "vulnerable_below" in vuln_info:
                    is_vulnerable = self._is_version_below(version, vuln_info["vulnerable_below"])

                # Check specific vulnerable versions
                if "vulnerable_versions" in vuln_info:
                    if version in vuln_info["vulnerable_versions"]:
                        is_vulnerable = True

                if is_vulnerable:
                    for cve_id in vuln_info["cves"]:
                        vuln = self.db.get_by_cve(cve_id)
                        if vuln:
                            finding = self.create_finding(vuln, package, version, package_json)
                            findings.append(finding)

        # Also check lockfiles for accurate versions
        lockfile_findings = self._check_lockfiles(project_dir, package_json)

        # Deduplicate findings
        existing = {(f.cve_id, f.package) for f in findings}
        for f in lockfile_findings:
            if (f.cve_id, f.package) not in existing:
                findings.append(f)

        return findings

    def _is_version_below(self, version: str, threshold: str) -> bool:
        """Check if version is below a threshold"""
        try:
            from packaging.version import Version
            return Version(version) < Version(threshold)
        except Exception:
            # If parsing fails, be conservative and report it
            return True

    def _check_lockfiles(self, project_dir: Path, package_json: Path) -> List[ScanFinding]:
        """Check lockfiles for accurate version information"""
        findings = []
        lockfiles = self.find_lockfiles(project_dir)

        for lockfile_name, lockfile_path in lockfiles.items():
            packages = {}

            if lockfile_name == "package-lock.json":
                lock_data = self.parse_package_lock(lockfile_path)
                if lock_data:
                    if "packages" in lock_data:
                        for pkg_path, pkg_info in lock_data.get("packages", {}).items():
                            if pkg_path and "version" in pkg_info:
                                name = pkg_path.split("node_modules/")[-1]
                                if name:
                                    packages[name] = pkg_info["version"]
                    elif "dependencies" in lock_data:
                        for name, info in lock_data.get("dependencies", {}).items():
                            if "version" in info:
                                packages[name] = info["version"]

            elif lockfile_name == "yarn.lock":
                packages = self.parse_yarn_lock(lockfile_path)

            elif lockfile_name == "pnpm-lock.yaml":
                packages = self.parse_pnpm_lock(lockfile_path)

            # Check packages
            for package, vuln_info in self.PACKAGE_VULNERABILITIES.items():
                if package in packages:
                    version = packages[package]
                    is_vulnerable = False

                    if "vulnerable_below" in vuln_info:
                        is_vulnerable = self._is_version_below(version, vuln_info["vulnerable_below"])

                    if "vulnerable_versions" in vuln_info:
                        if version in vuln_info["vulnerable_versions"]:
                            is_vulnerable = True

                    if is_vulnerable:
                        for cve_id in vuln_info["cves"]:
                            vuln = self.db.get_by_cve(cve_id)
                            if vuln:
                                finding = self.create_finding(
                                    vuln, package, version, package_json,
                                    detection_method=f"lockfile:{lockfile_name}"
                                )
                                findings.append(finding)

        return findings
