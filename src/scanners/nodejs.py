"""
Node.js Runtime Scanner
Detects Node.js runtime vulnerabilities from version in package.json engines
Also checks for platform-specific vulnerabilities (Windows path traversal, etc.)
"""

import platform
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple
from datetime import datetime

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class NodeJSScanner(BaseScanner):
    """Scanner for Node.js runtime vulnerabilities"""

    NAME = "nodejs"
    DESCRIPTION = "Scans for Node.js runtime vulnerabilities"
    CVE_IDS = [
        "CVE-2025-59465",   # HTTP/2 crash
        "CVE-2025-59464",   # TLS memory leak
        "CVE-2025-59466",   # async_hooks stack exhaustion
        "CVE-2025-27210",   # Windows path traversal (device names)
        "CVE-2025-23084",   # Windows path traversal (drive names)
        "CVE-2024-21891",   # Permission model bypass
        "CVE-2025-55130",   # Symlink permission bypass
        "CVE-2026-21636",   # Unix socket permission bypass
        "CVE-2025-55132",   # fs.futimes bypass
    ]
    SUPPORTED_PACKAGES = ["node"]

    # Node.js version -> vulnerabilities mapping
    # Format: major_version: [(cve_id, min_affected, fixed_version)]
    VERSION_VULNERABILITIES = {
        20: [
            ("CVE-2025-59465", "20.0.0", "20.20.0"),
            ("CVE-2025-59464", "20.0.0", "20.20.0"),
            ("CVE-2025-59466", "20.0.0", "20.20.0"),
            ("CVE-2025-55130", "20.0.0", "20.20.0"),
            ("CVE-2026-21636", "20.0.0", "20.20.0"),
            ("CVE-2025-55132", "20.0.0", "20.20.0"),
            ("CVE-2024-21891", "20.0.0", "20.11.1"),
        ],
        22: [
            ("CVE-2025-59465", "22.0.0", "22.22.0"),
            ("CVE-2025-59464", "22.0.0", "22.22.0"),
            ("CVE-2025-59466", "22.0.0", "22.22.0"),
            ("CVE-2025-55130", "22.0.0", "22.22.0"),
            ("CVE-2026-21636", "22.0.0", "22.22.0"),
            ("CVE-2025-55132", "22.0.0", "22.22.0"),
        ],
        24: [
            ("CVE-2025-59465", "24.0.0", "24.13.0"),
            ("CVE-2025-59464", "24.0.0", "24.13.0"),
            ("CVE-2025-59466", "24.0.0", "24.13.0"),
            ("CVE-2025-55130", "24.0.0", "24.13.0"),
            ("CVE-2026-21636", "24.0.0", "24.13.0"),
            ("CVE-2025-55132", "24.0.0", "24.13.0"),
        ],
        25: [
            ("CVE-2025-59465", "25.0.0", "25.3.0"),
            ("CVE-2025-59464", "25.0.0", "25.3.0"),
            ("CVE-2025-59466", "25.0.0", "25.3.0"),
            ("CVE-2025-55130", "25.0.0", "25.3.0"),
            ("CVE-2026-21636", "25.0.0", "25.3.0"),
            ("CVE-2025-55132", "25.0.0", "25.3.0"),
        ],
    }

    # Windows-specific CVEs
    WINDOWS_CVES = ["CVE-2025-27210", "CVE-2025-23084"]

    # Linux-specific CVEs
    LINUX_CVES = ["CVE-2026-21636"]

    def __init__(self):
        super().__init__()
        self.current_platform = platform.system()
        self.system_node_version = self._get_system_node_version()

    def _get_system_node_version(self) -> Optional[str]:
        """Get the Node.js version installed on the system"""
        try:
            result = subprocess.run(
                ["node", "--version"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                version = result.stdout.strip().lstrip("v")
                return version
        except Exception:
            pass
        return None

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """Scan directory for Node.js runtime vulnerabilities"""
        result = self.create_result(path)

        packages_scanned = 0
        vulnerable_projects = 0

        # First, check system Node.js version
        if self.system_node_version:
            system_findings = self._check_node_version(
                self.system_node_version,
                "system",
                "system"
            )
            if system_findings:
                result.findings.extend(system_findings)
                result.stats["system_node_vulnerable"] = True

        # Then scan projects
        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            findings = self._scan_package(package_json)

            if findings:
                vulnerable_projects += 1
                result.findings.extend(findings)

        result.stats["packages_scanned"] = packages_scanned
        result.stats["vulnerable_projects"] = vulnerable_projects
        result.stats["system_node_version"] = self.system_node_version
        result.stats["platform"] = self.current_platform

        return self.finalize_result(result)

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a package.json for Node.js version requirements"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        # Check engines.node field
        engines = data.get("engines", {})
        node_requirement = engines.get("node")

        if node_requirement:
            # Parse version requirement and check against vulnerabilities
            min_version, max_version = self._parse_node_requirement(node_requirement)

            if min_version:
                version_findings = self._check_node_version(
                    min_version,
                    str(package_json),
                    f"package.json engines.node: {node_requirement}"
                )
                findings.extend(version_findings)

        # Check for .nvmrc, .node-version files
        project_dir = package_json.parent
        version_files = [".nvmrc", ".node-version", ".tool-versions"]

        for vf in version_files:
            vf_path = project_dir / vf
            if vf_path.exists():
                try:
                    with open(vf_path, 'r') as f:
                        content = f.read().strip()
                        # Extract version from content
                        version = self._extract_version_from_file(content, vf)
                        if version:
                            version_findings = self._check_node_version(
                                version,
                                str(package_json),
                                f"{vf}: {version}"
                            )
                            findings.extend(version_findings)
                except Exception:
                    pass

        return findings

    def _check_node_version(
        self,
        version: str,
        file_path: str,
        context: str
    ) -> List[ScanFinding]:
        """Check a Node.js version for vulnerabilities"""
        findings = []

        try:
            clean_version = version.lstrip("v").split()[0]
            parts = clean_version.split(".")
            major = int(parts[0])

            if major not in self.VERSION_VULNERABILITIES:
                return findings

            from packaging.version import Version
            v = Version(clean_version)

            for cve_id, min_affected, fixed in self.VERSION_VULNERABILITIES[major]:
                # Skip platform-specific CVEs if not applicable
                if cve_id in self.WINDOWS_CVES and self.current_platform != "Windows":
                    continue
                if cve_id in self.LINUX_CVES and self.current_platform not in ["Linux", "Darwin"]:
                    continue

                min_v = Version(min_affected)
                fixed_v = Version(fixed)

                if min_v <= v < fixed_v:
                    vuln = self.db.get_by_cve(cve_id)
                    if vuln:
                        finding = ScanFinding(
                            cve_id=cve_id,
                            title=vuln.title,
                            severity=FindingSeverity[vuln.severity.value],
                            cvss_score=vuln.cvss_score,
                            package="node",
                            version=clean_version,
                            patched_version=fixed,
                            file_path=file_path,
                            description=vuln.description,
                            exploit_difficulty=vuln.exploit_difficulty.value,
                            references=vuln.references,
                            remediation=f"Upgrade Node.js to {fixed}+",
                            detection_method=f"version_check:{context}",
                        )
                        findings.append(finding)

        except Exception:
            pass

        return findings

    def _parse_node_requirement(self, requirement: str) -> Tuple[Optional[str], Optional[str]]:
        """Parse a Node.js version requirement string"""
        # Handle formats like: ">=18.0.0", "^20.0.0", "20.x", "18 || 20", etc.
        import re

        # Extract first version number we can find
        match = re.search(r'(\d+)\.?(\d+)?\.?(\d+)?', requirement)
        if match:
            major = match.group(1)
            minor = match.group(2) or "0"
            patch = match.group(3) or "0"
            min_version = f"{major}.{minor}.{patch}"
            return min_version, None

        return None, None

    def _extract_version_from_file(self, content: str, filename: str) -> Optional[str]:
        """Extract Node.js version from version file content"""
        import re

        if filename == ".tool-versions":
            # Format: "nodejs 20.10.0"
            match = re.search(r'nodejs\s+(\d+\.\d+\.\d+)', content)
            if match:
                return match.group(1)
        else:
            # .nvmrc, .node-version: just the version or "v20.10.0"
            match = re.search(r'v?(\d+\.\d+\.\d+)', content)
            if match:
                return match.group(1)
            # Also handle "20" or "lts/*" style
            match = re.search(r'^(\d+)$', content.strip())
            if match:
                return f"{match.group(1)}.0.0"

        return None

    def check_system_node(self) -> List[ScanFinding]:
        """Check the system Node.js installation for vulnerabilities"""
        if not self.system_node_version:
            return []

        return self._check_node_version(
            self.system_node_version,
            "system",
            "system Node.js installation"
        )
