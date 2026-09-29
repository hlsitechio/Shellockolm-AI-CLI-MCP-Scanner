"""
Supply Chain Scanner
Detects supply chain attacks and compromised packages:
- Shai-Hulud campaign
- eslint-config-prettier compromise (CVE-2025-54313)
- Suspicious install scripts
"""

import re
import os
from pathlib import Path
from typing import List, Set, Dict, Any
from datetime import datetime

from .base import BaseScanner, ScanResult, ScanFinding, FindingSeverity


class SupplyChainScanner(BaseScanner):
    """Scanner for supply chain attacks and malware"""

    NAME = "supply-chain"
    DESCRIPTION = "Scans for supply chain attacks, malware indicators, and compromised packages"
    CVE_IDS = ["CVE-2025-54313"]  # eslint-config-prettier
    SUPPORTED_PACKAGES = []  # Dynamic - checks known compromised packages

    # Known compromised packages and versions
    COMPROMISED_PACKAGES: Dict[str, Dict[str, Any]] = {
        # eslint-config-prettier supply chain attack
        "eslint-config-prettier": {
            "malicious_versions": ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
            "safe_versions": ["8.10.2", "9.1.2", "10.1.8"],
            "cve": "CVE-2025-54313",
            "severity": FindingSeverity.HIGH,
            "description": "Maintainer phishing attack - malicious DLL payload (Scavenger)",
            "platform": "Windows",
        },
        "eslint-plugin-prettier": {
            "malicious_versions": [],  # Related but versions unclear
            "cve": "CVE-2025-54313",
            "severity": FindingSeverity.MEDIUM,
            "description": "Related to eslint-config-prettier compromise - verify versions",
        },
        "synckit": {
            "malicious_versions": [],
            "cve": "CVE-2025-54313",
            "severity": FindingSeverity.MEDIUM,
            "description": "Related to eslint-config-prettier compromise",
        },
        # Shai-Hulud campaign packages
        "@postman/security-helpers": {
            "cve": None,
            "severity": FindingSeverity.CRITICAL,
            "description": "Shai-Hulud worm campaign - credential stealing malware",
            "campaign": "Shai-Hulud",
        },
        "@posthog/plugin-geoip": {
            "cve": None,
            "severity": FindingSeverity.CRITICAL,
            "description": "Shai-Hulud worm campaign - credential stealing malware",
            "campaign": "Shai-Hulud",
        },
        "@asyncapi/openapi-schema-parser": {
            "cve": None,
            "severity": FindingSeverity.CRITICAL,
            "description": "Shai-Hulud worm campaign - credential stealing malware",
            "campaign": "Shai-Hulud",
        },
        "@ensdomains/content-hash": {
            "cve": None,
            "severity": FindingSeverity.CRITICAL,
            "description": "Shai-Hulud worm campaign - credential stealing malware",
            "campaign": "Shai-Hulud",
        },
        "@zapier/secret-scrubber": {
            "cve": None,
            "severity": FindingSeverity.CRITICAL,
            "description": "Shai-Hulud worm campaign - credential stealing malware",
            "campaign": "Shai-Hulud",
        },
    }

    # Shai-Hulud indicator files
    MALWARE_INDICATORS = [
        "bun_environment.js",
        "setup_bun.js",
        "cloud.json",
        "truffleSecrets.json",
        ".truffler-cache",
        ".truffler",
        "trufflehog",
    ]

    # Suspicious script patterns in package.json
    SUSPICIOUS_SCRIPT_PATTERNS = [
        (r"preinstall.*curl.*\|.*sh", "Suspicious preinstall with curl pipe to shell"),
        (r"postinstall.*wget", "Suspicious postinstall with wget"),
        (r"preinstall.*base64.*-d", "Suspicious preinstall with base64 decode"),
        (r"install.*eval.*\$\(", "Suspicious install with eval"),
        (r"npm.*token", "Potential npm token access"),
        (r"github\.com.*Shai-Hulud", "Direct Shai-Hulud campaign indicator"),
        (r"preinstall.*--ignore-scripts=false", "Forcing script execution"),
        (r"node\s+-e\s+['\"].*require.*child_process", "Inline child_process execution"),
        (r"require\(['\"]child_process['\"]\)", "Child process in scripts"),
        (r"\\x[0-9a-fA-F]{2}", "Hex-encoded strings (potential obfuscation)"),
        (r"Buffer\.from\([^)]+,\s*['\"]base64", "Base64 decoding (potential obfuscation)"),
        (r"https?://[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}", "IP address URL (suspicious)"),
    ]

    def scan_directory(
        self,
        path: str,
        recursive: bool = True,
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """Scan directory for supply chain attacks and malware"""
        result = self.create_result(path)

        packages_scanned = 0
        malware_indicators_found = 0
        compromised_packages_found = 0

        # Check for malware indicator files
        indicator_findings = self._scan_for_indicators(Path(path))
        if indicator_findings:
            malware_indicators_found = len(indicator_findings)
            result.findings.extend(indicator_findings)

        # Scan packages
        for package_json in self.find_package_json_files(path, recursive, max_depth):
            packages_scanned += 1
            findings = self._scan_package(package_json)

            if findings:
                compromised_packages_found += len([f for f in findings if "compromised" in f.detection_method])
                result.findings.extend(findings)

        result.stats["packages_scanned"] = packages_scanned
        result.stats["malware_indicators_found"] = malware_indicators_found
        result.stats["compromised_packages_found"] = compromised_packages_found

        return self.finalize_result(result)

    def _scan_package(self, package_json: Path) -> List[ScanFinding]:
        """Scan a package.json for supply chain issues"""
        findings: List[ScanFinding] = []

        data = self.parse_package_json(package_json)
        if not data:
            return findings

        deps = self.get_dependencies(data)

        # Check for known compromised packages
        for package, info in self.COMPROMISED_PACKAGES.items():
            if package in deps:
                version = self.extract_version(deps[package])

                # Check if it's a known malicious version
                is_malicious = False
                if "malicious_versions" in info and info["malicious_versions"]:
                    is_malicious = version in info["malicious_versions"]
                else:
                    # If no specific versions known, flag presence of package
                    if "campaign" in info:
                        is_malicious = True

                if is_malicious:
                    cve_id = info.get("cve") or "NO-CVE"
                    safe_version = info.get("safe_versions", ["latest"])[0] if info.get("safe_versions") else "latest"

                    finding = ScanFinding(
                        cve_id=cve_id,
                        title=f"Compromised Package: {package}",
                        severity=info.get("severity", FindingSeverity.CRITICAL),
                        cvss_score=9.0 if info.get("severity") == FindingSeverity.CRITICAL else 7.5,
                        package=package,
                        version=version,
                        patched_version=safe_version,
                        file_path=str(package_json),
                        description=info.get("description", "Known compromised package"),
                        exploit_difficulty="Trivial",
                        remediation=f"Remove {package} or upgrade to {safe_version}",
                        detection_method="compromised_package",
                        raw_data={"campaign": info.get("campaign")},
                    )
                    findings.append(finding)

        # Check for suspicious install scripts
        scripts = data.get("scripts", {})
        for script_name, script_content in scripts.items():
            if script_name in ["preinstall", "postinstall", "install", "prepare"]:
                for pattern, description in self.SUSPICIOUS_SCRIPT_PATTERNS:
                    if re.search(pattern, script_content, re.IGNORECASE):
                        finding = ScanFinding(
                            cve_id="SUSPICIOUS-SCRIPT",
                            title=f"Suspicious {script_name} Script",
                            severity=FindingSeverity.HIGH,
                            cvss_score=7.0,
                            package=data.get("name", "unknown"),
                            version=data.get("version", "unknown"),
                            patched_version=None,
                            file_path=str(package_json),
                            description=description,
                            exploit_difficulty="Easy",
                            remediation="Review script content and remove if malicious",
                            detection_method="script_analysis",
                            raw_data={
                                "script_name": script_name,
                                "script_content": script_content[:500],
                                "matched_pattern": pattern,
                            },
                        )
                        findings.append(finding)
                        break  # Only report once per script

        return findings

    def _scan_for_indicators(self, root_path: Path) -> List[ScanFinding]:
        """Scan for malware indicator files"""
        findings: List[ScanFinding] = []

        if not root_path.exists():
            return findings

        for indicator in self.MALWARE_INDICATORS:
            # Search in root and common locations
            search_paths = [
                root_path / indicator,
                root_path / "node_modules" / indicator,
            ]

            # Also check inside node_modules subdirectories
            node_modules = root_path / "node_modules"
            if node_modules.exists():
                try:
                    for pkg_dir in node_modules.iterdir():
                        if pkg_dir.is_dir():
                            indicator_path = pkg_dir / indicator
                            if indicator_path.exists():
                                search_paths.append(indicator_path)
                except PermissionError:
                    pass

            for indicator_path in search_paths:
                if indicator_path.exists():
                    finding = ScanFinding(
                        cve_id="MALWARE-INDICATOR",
                        title=f"Shai-Hulud Malware Indicator: {indicator}",
                        severity=FindingSeverity.CRITICAL,
                        cvss_score=10.0,
                        package="unknown",
                        version="unknown",
                        patched_version=None,
                        file_path=str(indicator_path),
                        description=f"Found Shai-Hulud campaign indicator file: {indicator}",
                        exploit_difficulty="Trivial",
                        remediation="Immediately investigate and remove. Check for credential theft.",
                        detection_method="indicator_file",
                        raw_data={"indicator": indicator},
                    )
                    findings.append(finding)

        return findings

    def scan_npm_token_exposure(self, path: str) -> List[ScanFinding]:
        """Check for exposed npm tokens"""
        findings = []
        root = Path(path)

        # Files that might contain npm tokens
        sensitive_files = [
            ".npmrc",
            ".yarnrc",
            ".yarnrc.yml",
            ".env",
            ".env.local",
            ".env.production",
        ]

        for sf in sensitive_files:
            sf_path = root / sf
            if sf_path.exists():
                try:
                    with open(sf_path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read()

                    # Check for npm tokens
                    if re.search(r'//registry\.npmjs\.org/:_authToken=', content):
                        finding = ScanFinding(
                            cve_id="NPM-TOKEN-EXPOSURE",
                            title="Exposed npm Authentication Token",
                            severity=FindingSeverity.CRITICAL,
                            cvss_score=9.0,
                            package="npm",
                            version="N/A",
                            patched_version=None,
                            file_path=str(sf_path),
                            description="npm authentication token found in file. May be targeted by supply chain attacks.",
                            exploit_difficulty="Trivial",
                            remediation="Rotate npm token immediately and add file to .gitignore",
                            detection_method="token_scan",
                        )
                        findings.append(finding)

                except Exception:
                    pass

        return findings
