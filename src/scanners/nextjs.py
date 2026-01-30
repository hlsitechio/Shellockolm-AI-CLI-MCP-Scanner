"""
Next.js Scanner
Detects CVE-2025-29927 (Middleware Auth Bypass) and other Next.js CVEs
"""

import re
from pathlib import Path
from typing import List, Optional, Dict, Any
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class NextJSScanner(BaseScanner):
    """Scanner for Next.js specific vulnerabilities"""

    NAME = "nextjs"
    DESCRIPTION = "Scans for Next.js middleware bypass and other vulnerabilities"
    CVE_IDS = [
        "CVE-2025-29927",  # Middleware authorization bypass
        "CVE-2025-66478",  # RSC RCE (via React)
    ]
    SUPPORTED_PACKAGES = ["next"]

    # Version ranges affected by CVE-2025-29927
    MIDDLEWARE_BYPASS_AFFECTED = {
        # Major version: (min_affected, max_affected, patched)
        11: ("11.1.4", "11.999.999", None),  # No patch for v11
        12: ("12.0.0", "12.3.4", "12.3.5"),
        13: ("13.0.0", "13.5.6", "13.5.7"),
        14: ("14.0.0", "14.2.24", "14.2.25"),
        15: ("15.0.0", "15.2.2", "15.2.3"),
    }

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """
        Scan directory for Next.js vulnerabilities
        
        Args:
            quick_mode: If True, only checks package.json versions (FAST)
        """
        result = self.create_result(path)

        packages_scanned = 0
        vulnerable_projects = 0

        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            
            if quick_mode:
                # QUICK MODE: Only check versions
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
        """QUICK SCAN: Only check package.json version"""
        findings = []
        
        data = self.parse_package_json(package_json)
        if not data:
            return findings
        
        deps = self.get_dependencies(data)
        
        if "next" in deps:
            version = self.extract_version(deps["next"])
            vulns = self.check_package_vulnerability("next", version)
            
            for vuln in vulns:
                finding = self.create_finding(vuln, "next", version, package_json)
                finding.raw_data["quick_scan"] = True
                findings.append(finding)
        
        return findings

    def scan_live(self, url: str, timeout: int = 10) -> ScanResult:
        """
        Scan a live Next.js application for CVE-2025-29927
        Tests the x-middleware-subrequest header bypass
        """
        if not HAS_REQUESTS:
            result = self.create_result(url, scan_type="live")
            result.errors.append("requests library not installed - live scanning unavailable")
            return self.finalize_result(result)

        result = self.create_result(url, scan_type="live")

        try:
            # First, detect if it's Next.js
            nextjs_detected, version = self._detect_nextjs(url, timeout)

            if not nextjs_detected:
                result.stats["nextjs_detected"] = False
                return self.finalize_result(result)

            result.stats["nextjs_detected"] = True
            result.stats["detected_version"] = version

            # Test for middleware bypass
            is_vulnerable = self._test_middleware_bypass(url, timeout)

            if is_vulnerable:
                vuln = self.db.get_by_cve("CVE-2025-29927")
                if vuln:
                    finding = ScanFinding(
                        cve_id="CVE-2025-29927",
                        title="Next.js Middleware Authorization Bypass",
                        severity=FindingSeverity.CRITICAL,
                        cvss_score=9.1,
                        package="next",
                        version=version or "unknown",
                        patched_version=self._get_patched_version(version) if version else "15.2.3+",
                        file_path=url,
                        description="x-middleware-subrequest header bypasses middleware authorization",
                        exploit_difficulty="Trivial",
                        references=vuln.references,
                        remediation="Upgrade Next.js or block x-middleware-subrequest header at reverse proxy",
                        detection_method="live",
                    )
                    result.findings.append(finding)

        except Exception as e:
            result.errors.append(f"Live scan error: {str(e)}")

        return self.finalize_result(result)

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a single package.json for Next.js vulnerabilities"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)
        project_dir = package_json.parent

        if "next" not in deps:
            return findings

        version = self.extract_version(deps["next"])

        # Check for middleware bypass vulnerability
        if self._is_middleware_bypass_vulnerable(version):
            # Check if project uses middleware
            uses_middleware = self._check_uses_middleware(project_dir)

            vuln = self.db.get_by_cve("CVE-2025-29927")
            if vuln:
                finding = self.create_finding(vuln, "next", version, package_json)
                finding.raw_data["uses_middleware"] = uses_middleware
                if not uses_middleware:
                    finding.raw_data["note"] = "Middleware not detected - may not be exploitable"
                findings.append(finding)

        # Check for RSC RCE (CVE-2025-66478) if using App Router
        if self._check_uses_app_router(project_dir):
            vulns = self.check_package_vulnerability("next", version)
            for vuln in vulns:
                if vuln.cve_id == "CVE-2025-66478":
                    finding = self.create_finding(vuln, "next", version, package_json)
                    finding.raw_data["uses_app_router"] = True
                    findings.append(finding)

        return findings

    def _is_middleware_bypass_vulnerable(self, version: str) -> bool:
        """Check if version is vulnerable to CVE-2025-29927"""
        try:
            parts = version.split(".")
            major = int(parts[0])

            if major not in self.MIDDLEWARE_BYPASS_AFFECTED:
                return False

            min_affected, max_affected, patched = self.MIDDLEWARE_BYPASS_AFFECTED[major]

            from packaging.version import Version
            v = Version(version)
            min_v = Version(min_affected)
            max_v = Version(max_affected)

            if v < min_v:
                return False

            if patched:
                patched_v = Version(patched)
                return v < patched_v
            else:
                return v <= max_v

        except Exception:
            # If we can't parse, assume vulnerable for safety
            return True

    def _check_uses_middleware(self, project_dir: Path) -> bool:
        """Check if project uses Next.js middleware"""
        middleware_files = [
            "middleware.ts",
            "middleware.js",
            "src/middleware.ts",
            "src/middleware.js",
        ]

        for mw_file in middleware_files:
            if (project_dir / mw_file).exists():
                return True

        return False

    def _check_uses_app_router(self, project_dir: Path) -> bool:
        """Check if project uses Next.js App Router"""
        app_dirs = [
            project_dir / "app",
            project_dir / "src" / "app",
        ]

        for app_dir in app_dirs:
            if app_dir.exists() and app_dir.is_dir():
                # Check for layout.tsx/js which indicates App Router
                for ext in ["tsx", "ts", "jsx", "js"]:
                    if (app_dir / f"layout.{ext}").exists():
                        return True
                    if (app_dir / f"page.{ext}").exists():
                        return True

        return False

    def _detect_nextjs(self, url: str, timeout: int) -> tuple:
        """Detect if a URL is running Next.js and try to get version"""
        try:
            resp = requests.get(url, timeout=timeout, allow_redirects=True)

            # Check X-Powered-By header
            powered_by = resp.headers.get("X-Powered-By", "")
            if "Next.js" in powered_by:
                # Try to extract version from header
                match = re.search(r'Next\.js\s*([\d.]+)?', powered_by)
                version = match.group(1) if match and match.group(1) else None
                return True, version

            # Check for Next.js indicators in HTML
            if "/_next/" in resp.text or "__NEXT_DATA__" in resp.text:
                return True, None

            # Check for _next/static path
            resp2 = requests.get(f"{url.rstrip('/')}/_next/static/", timeout=timeout)
            if resp2.status_code != 404:
                return True, None

        except Exception:
            pass

        return False, None

    def _test_middleware_bypass(self, url: str, timeout: int) -> bool:
        """Test for CVE-2025-29927 middleware bypass"""
        try:
            # Make a request with the bypass header
            headers = {"x-middleware-subrequest": "1"}

            # Test on common protected paths
            test_paths = [
                "/api/admin",
                "/admin",
                "/dashboard",
                "/api/private",
                "/settings",
            ]

            for path in test_paths:
                test_url = f"{url.rstrip('/')}{path}"

                # First request without bypass header
                resp1 = requests.get(test_url, timeout=timeout, allow_redirects=False)

                # If it returns 401/403/302, try with bypass header
                if resp1.status_code in [401, 403, 302, 307]:
                    resp2 = requests.get(test_url, headers=headers, timeout=timeout, allow_redirects=False)

                    # If status code changes to 200 or different redirect, likely vulnerable
                    if resp2.status_code == 200 and resp1.status_code != 200:
                        return True
                    if resp1.status_code in [302, 307] and resp2.status_code not in [302, 307]:
                        return True

        except Exception:
            pass

        return False

    def _get_patched_version(self, version: str) -> Optional[str]:
        """Get the patched version for a vulnerable Next.js version"""
        try:
            major = int(version.split(".")[0])
            if major in self.MIDDLEWARE_BYPASS_AFFECTED:
                _, _, patched = self.MIDDLEWARE_BYPASS_AFFECTED[major]
                return patched
        except Exception:
            pass
        return None
