"""
n8n Workflow Automation Scanner
Detects CVE-2026-21858 (Ni8mare - Unauth RCE) and CVE-2025-68613 (Auth RCE)
"""

import re
from pathlib import Path
from typing import List, Optional
from datetime import datetime

try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class N8NScanner(BaseScanner):
    """Scanner for n8n workflow automation vulnerabilities"""

    NAME = "n8n"
    DESCRIPTION = "Scans for n8n workflow automation vulnerabilities"
    CVE_IDS = [
        "CVE-2026-21858",  # Ni8mare - Unauthenticated RCE
        "CVE-2025-68613",  # Expression injection RCE (authenticated)
        "CVE-2025-68668",  # Python Code Node RCE
    ]
    SUPPORTED_PACKAGES = ["n8n", "n8n-workflow", "@n8n/config"]

    # Version thresholds
    VULNS = {
        "CVE-2026-21858": {
            "package": "n8n",
            "fixed": "1.121.0",
            "auth_required": False,
        },
        "CVE-2025-68613": {
            "package": "n8n",
            "fixed": "1.120.4",
            "alt_fixed": ["1.121.1", "1.122.0"],
            "auth_required": True,
        },
        "CVE-2025-68668": {
            "package": "n8n",
            "fixed": "1.120.0",
            "auth_required": True,
        },
    }

    # Detection signatures for live scanning
    N8N_PATHS = [
        "/webhook/",
        "/webhook-test/",
        "/form/",
        "/rest/",
        "/api/",
    ]

    N8N_HEADERS = [
        "X-n8n-webhook-id",
        "X-n8n-Version",
    ]

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10
    ) -> ScanResult:
        """Scan directory for n8n installations"""
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

    def scan_live(self, url: str, timeout: int = 10) -> ScanResult:
        """
        Scan a live n8n instance for vulnerabilities
        Tests for CVE-2026-21858 (Ni8mare) unauthenticated RCE
        """
        if not HAS_REQUESTS:
            result = self.create_result(url, scan_type="live")
            result.errors.append("requests library not installed - live scanning unavailable")
            return self.finalize_result(result)

        result = self.create_result(url, scan_type="live")

        try:
            # Detect if it's n8n
            n8n_detected, version = self._detect_n8n(url, timeout)

            if not n8n_detected:
                result.stats["n8n_detected"] = False
                return self.finalize_result(result)

            result.stats["n8n_detected"] = True
            result.stats["detected_version"] = version

            # Check for unauthenticated endpoints (CVE-2026-21858)
            unauth_vulnerable = self._test_unauth_vulnerability(url, timeout)

            if unauth_vulnerable:
                vuln = self.db.get_by_cve("CVE-2026-21858")
                if vuln:
                    finding = ScanFinding(
                        cve_id="CVE-2026-21858",
                        title="n8n Unauthenticated RCE (Ni8mare)",
                        severity=FindingSeverity.CRITICAL,
                        cvss_score=10.0,
                        package="n8n",
                        version=version or "unknown",
                        patched_version="1.121.0+",
                        file_path=url,
                        description="Content-Type confusion in Form Webhooks enables unauthenticated RCE",
                        exploit_difficulty="Trivial",
                        references=vuln.references,
                        remediation="Upgrade n8n to 1.121.0 or later immediately",
                        detection_method="live",
                    )
                    result.findings.append(finding)

            # Version-based checks
            if version:
                version_findings = self._check_version_vulns(version, url)
                result.findings.extend(version_findings)

        except Exception as e:
            result.errors.append(f"Live scan error: {str(e)}")

        return self.finalize_result(result)

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a package.json for n8n dependencies"""
        findings = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)

        # Check n8n packages
        for package in self.SUPPORTED_PACKAGES:
            if package in deps:
                version = self.extract_version(deps[package])
                pkg_findings = self._check_version_vulns(version, str(package_json))
                findings.extend(pkg_findings)

        # Check if this IS an n8n installation (check name field)
        if data.get("name") == "n8n":
            version = data.get("version", "")
            if version:
                findings.extend(self._check_version_vulns(version, str(package_json)))

        return findings

    def _check_version_vulns(self, version: str, file_path: str) -> List[ScanFinding]:
        """Check n8n version for known vulnerabilities"""
        findings = []

        try:
            from packaging.version import Version
            v = Version(version)

            for cve_id, info in self.VULNS.items():
                # A CVE may be fixed across several release branches. Build the
                # full list of fix versions (primary + alternates) so we can
                # evaluate the branch that matches this version's minor line.
                fix_versions = [Version(info["fixed"])]
                fix_versions.extend(Version(alt) for alt in info.get("alt_fixed", []))

                # Find fix branches on the SAME minor line (major.minor) as the
                # installed version. A version is vulnerable if it is below the
                # fix for its own branch.
                same_branch_fixes = [
                    fv for fv in fix_versions
                    if (fv.major, fv.minor) == (v.major, v.minor)
                ]

                is_vulnerable = False
                if same_branch_fixes:
                    # Vulnerable if below the fix for its branch.
                    is_vulnerable = v < max(same_branch_fixes)
                else:
                    # No fix on this exact branch. The version is vulnerable if
                    # it sits below the lowest fix branch (older, unpatched
                    # minor line). Versions on or above all fix branches that
                    # have no matching branch fix are treated as patched.
                    is_vulnerable = v < min(fix_versions)

                # The vulnerability data may also explicitly enumerate affected
                # versions/ranges (e.g. a single odd release like 1.121.0 that
                # is >= the primary fix but still listed as affected). Honor it.
                if not is_vulnerable:
                    is_vulnerable = self._version_explicitly_affected(cve_id, version)

                if is_vulnerable:
                    vuln = self.db.get_by_cve(cve_id)
                    if vuln:
                        finding = ScanFinding(
                            cve_id=cve_id,
                            title=vuln.title,
                            severity=FindingSeverity[vuln.severity.value],
                            cvss_score=vuln.cvss_score,
                            package=info["package"],
                            version=version,
                            patched_version=info["fixed"],
                            file_path=file_path,
                            description=vuln.description,
                            exploit_difficulty=vuln.exploit_difficulty.value,
                            references=vuln.references,
                            remediation=f"Upgrade n8n to {info['fixed']}+",
                            detection_method="version_check",
                            raw_data={"auth_required": info.get("auth_required", False)},
                        )
                        findings.append(finding)

        except Exception:
            pass

        return findings

    def _version_explicitly_affected(self, cve_id: str, version: str) -> bool:
        """Check the vulnerability DB's affected_versions list for this version.

        Handles exact versions ("1.121.0") and range specs ("0.211.0-1.120.3").
        Used to catch versions that are >= the primary fix but still explicitly
        listed as affected.
        """
        try:
            vuln = self.db.get_by_cve(cve_id)
            if not vuln:
                return False

            from packaging.version import Version
            v = Version(version)

            for spec in vuln.affected_versions:
                spec = spec.strip()
                # Range like "0.211.0-1.120.3"
                if "-" in spec and not spec.startswith("<") and not spec.startswith(">"):
                    parts = spec.split("-")
                    if len(parts) == 2:
                        try:
                            low, high = Version(parts[0].strip()), Version(parts[1].strip())
                            if low <= v <= high:
                                return True
                            continue
                        except Exception:
                            # Not a clean version range (e.g. "1.122.0-RC"); fall
                            # back to an exact string match below.
                            pass
                if "<" in spec:
                    try:
                        if v < Version(spec.lstrip("<").strip()):
                            return True
                        continue
                    except Exception:
                        pass
                # Exact version match
                try:
                    if v == Version(spec):
                        return True
                except Exception:
                    if spec == version:
                        return True
        except Exception:
            pass

        return False

    def _detect_n8n(self, url: str, timeout: int) -> tuple:
        """Detect if URL is an n8n instance and try to get version"""
        try:
            # Try common n8n endpoints
            for path in ["/", "/rest/settings"]:
                resp = requests.get(
                    f"{url.rstrip('/')}{path}",
                    timeout=timeout,
                    allow_redirects=True
                )

                # Check for n8n headers
                for header in self.N8N_HEADERS:
                    if header.lower() in [h.lower() for h in resp.headers]:
                        version = resp.headers.get("X-n8n-Version")
                        return True, version

                # Check for n8n indicators in response
                if "n8n" in resp.text.lower():
                    # Try to extract version
                    match = re.search(r'"version":\s*"(\d+\.\d+\.\d+)"', resp.text)
                    version = match.group(1) if match else None
                    return True, version

            # Try webhook endpoint
            resp = requests.get(
                f"{url.rstrip('/')}/webhook-test/",
                timeout=timeout
            )
            if resp.status_code != 404:
                return True, None

        except Exception:
            pass

        return False, None

    def _test_unauth_vulnerability(self, url: str, timeout: int) -> bool:
        """
        Test for CVE-2026-21858 unauthenticated vulnerability
        This is a passive check - it tests if form webhooks are accessible
        """
        try:
            # Test if form webhook endpoints are accessible without auth
            test_endpoints = [
                "/form/",
                "/webhook/",
                "/webhook-test/",
            ]

            for endpoint in test_endpoints:
                resp = requests.get(
                    f"{url.rstrip('/')}{endpoint}",
                    timeout=timeout,
                    allow_redirects=False
                )

                # If we get anything other than 401/403, it might be vulnerable
                # Form endpoints in vulnerable versions don't require auth
                if resp.status_code in [200, 404, 405]:
                    # This indicates the endpoint exists and doesn't require auth
                    # For a more accurate test, you'd need to send actual exploit payloads
                    # but that's out of scope for a scanner
                    return True

        except Exception:
            pass

        return False
