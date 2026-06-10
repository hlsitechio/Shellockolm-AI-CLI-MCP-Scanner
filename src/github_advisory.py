#!/usr/bin/env python3
"""
Shellockolm GitHub Advisory Database Integration
Fetches CVE data from GitHub's Advisory Database for npm packages

Features:
- Query GitHub Advisory Database API
- Cache advisories locally for offline use
- Enrich existing vulnerability database
- Support for GHSA IDs and CVE cross-references
"""

import json
import hashlib
import subprocess
import tempfile
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
import re
import urllib.request
import urllib.error
import ssl


class AdvisorySeverity(Enum):
    """GitHub Advisory severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class GitHubAdvisory:
    """A GitHub Security Advisory"""
    ghsa_id: str  # e.g., GHSA-xxxx-xxxx-xxxx
    cve_id: Optional[str]  # e.g., CVE-2025-12345
    severity: AdvisorySeverity
    summary: str
    description: str
    affected_packages: List[Dict[str, Any]]  # [{name, ecosystem, vulnerable_versions}]
    patched_versions: Dict[str, str]  # {package_name: patched_version}
    cwes: List[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str]
    published_at: str
    updated_at: str
    references: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        return {
            "ghsa_id": self.ghsa_id,
            "cve_id": self.cve_id,
            "severity": self.severity.value,
            "summary": self.summary,
            "description": self.description,
            "affected_packages": self.affected_packages,
            "patched_versions": self.patched_versions,
            "cwes": self.cwes,
            "cvss_score": self.cvss_score,
            "cvss_vector": self.cvss_vector,
            "published_at": self.published_at,
            "updated_at": self.updated_at,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GitHubAdvisory":
        """Create from dictionary"""
        return cls(
            ghsa_id=data.get("ghsa_id", ""),
            cve_id=data.get("cve_id"),
            severity=AdvisorySeverity(data.get("severity", "unknown")),
            summary=data.get("summary", ""),
            description=data.get("description", ""),
            affected_packages=data.get("affected_packages", []),
            patched_versions=data.get("patched_versions", {}),
            cwes=data.get("cwes", []),
            cvss_score=data.get("cvss_score"),
            cvss_vector=data.get("cvss_vector"),
            published_at=data.get("published_at", ""),
            updated_at=data.get("updated_at", ""),
            references=data.get("references", []),
        )


@dataclass
class AdvisoryQueryResult:
    """Result of querying the GitHub Advisory Database"""
    package_name: str
    advisories: List[GitHubAdvisory]
    query_time: datetime
    from_cache: bool


class GitHubAdvisoryDB:
    """
    GitHub Advisory Database Integration

    Uses the GitHub Advisory Database GraphQL API to fetch security advisories
    for npm packages. Supports caching and offline use.
    """

    GRAPHQL_ENDPOINT = "https://api.github.com/graphql"
    REST_ENDPOINT = "https://api.github.com/advisories"
    CACHE_DIR = Path(tempfile.gettempdir()) / "shellockolm" / "github_advisory_cache"
    CACHE_TTL_HOURS = 24  # Cache validity in hours

    # GraphQL query for security advisories
    ADVISORY_QUERY = """
    query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!, $first: Int!) {
        securityVulnerabilities(
            ecosystem: $ecosystem,
            package: $package,
            first: $first
        ) {
            nodes {
                advisory {
                    ghsaId
                    summary
                    description
                    severity
                    cvss {
                        score
                        vectorString
                    }
                    cwes(first: 5) {
                        nodes {
                            cweId
                        }
                    }
                    identifiers {
                        type
                        value
                    }
                    publishedAt
                    updatedAt
                    references {
                        url
                    }
                }
                package {
                    name
                    ecosystem
                }
                vulnerableVersionRange
                firstPatchedVersion {
                    identifier
                }
            }
        }
    }
    """

    def __init__(self, github_token: Optional[str] = None):
        """
        Initialize the GitHub Advisory Database client

        Args:
            github_token: GitHub Personal Access Token (optional, but recommended for higher rate limits)
        """
        self.github_token = github_token or self._get_token_from_env()
        self.cache_dir = self.CACHE_DIR
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self._advisories_by_cve: Dict[str, GitHubAdvisory] = {}
        self._advisories_by_ghsa: Dict[str, GitHubAdvisory] = {}

    def _get_token_from_env(self) -> Optional[str]:
        """Try to get GitHub token from environment"""
        import os
        for var in ["GITHUB_TOKEN", "GH_TOKEN", "GITHUB_API_TOKEN"]:
            token = os.environ.get(var)
            if token:
                return token
        return None

    def _cache_key(self, package_name: str) -> str:
        """Generate cache key for a package"""
        return hashlib.sha256(f"npm:{package_name}".encode()).hexdigest()[:16]

    def _get_cache_path(self, package_name: str) -> Path:
        """Get cache file path for a package"""
        return self.cache_dir / f"{self._cache_key(package_name)}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache is still valid"""
        if not cache_path.exists():
            return False

        try:
            with open(cache_path) as f:
                cache_data = json.load(f)

            cached_time = datetime.fromisoformat(cache_data.get("cached_at", ""))
            return datetime.now() - cached_time < timedelta(hours=self.CACHE_TTL_HOURS)
        except Exception:
            return False

    def _load_from_cache(self, package_name: str) -> Optional[List[GitHubAdvisory]]:
        """Load advisories from cache"""
        cache_path = self._get_cache_path(package_name)
        if not self._is_cache_valid(cache_path):
            return None

        try:
            with open(cache_path) as f:
                cache_data = json.load(f)

            return [GitHubAdvisory.from_dict(a) for a in cache_data.get("advisories", [])]
        except Exception:
            return None

    def _save_to_cache(self, package_name: str, advisories: List[GitHubAdvisory]):
        """Save advisories to cache"""
        cache_path = self._get_cache_path(package_name)
        cache_data = {
            "package_name": package_name,
            "cached_at": datetime.now().isoformat(),
            "advisories": [a.to_dict() for a in advisories],
        }

        try:
            with open(cache_path, "w") as f:
                json.dump(cache_data, f, indent=2)
        except Exception:
            pass  # Caching failure is not critical

    def _make_graphql_request(self, query: str, variables: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Make a GraphQL request to GitHub API"""
        if not self.github_token:
            return None

        headers = {
            "Authorization": f"Bearer {self.github_token}",
            "Content-Type": "application/json",
            "Accept": "application/vnd.github+json",
        }

        payload = json.dumps({"query": query, "variables": variables}).encode()

        try:
            # Create SSL context
            ctx = ssl.create_default_context()

            req = urllib.request.Request(
                self.GRAPHQL_ENDPOINT,
                data=payload,
                headers=headers,
                method="POST"
            )

            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
                return json.loads(response.read().decode())
        except Exception as e:
            return None

    def _make_rest_request(self, endpoint: str) -> Optional[Dict[str, Any]]:
        """Make a REST request to GitHub API"""
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        if self.github_token:
            headers["Authorization"] = f"Bearer {self.github_token}"

        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(endpoint, headers=headers)

            with urllib.request.urlopen(req, context=ctx, timeout=30) as response:
                return json.loads(response.read().decode())
        except Exception:
            return None

    def query_package(self, package_name: str, use_cache: bool = True) -> AdvisoryQueryResult:
        """
        Query advisories for a specific npm package

        Args:
            package_name: The npm package name to query
            use_cache: Whether to use cached results if available

        Returns:
            AdvisoryQueryResult with all found advisories
        """
        # Try cache first
        if use_cache:
            cached = self._load_from_cache(package_name)
            if cached is not None:
                return AdvisoryQueryResult(
                    package_name=package_name,
                    advisories=cached,
                    query_time=datetime.now(),
                    from_cache=True
                )

        advisories = []

        # Try GraphQL API (requires token)
        if self.github_token:
            variables = {
                "ecosystem": "NPM",
                "package": package_name,
                "first": 100
            }

            result = self._make_graphql_request(self.ADVISORY_QUERY, variables)

            if result and "data" in result:
                vulns = result["data"].get("securityVulnerabilities", {}).get("nodes", [])

                for vuln in vulns:
                    advisory_data = vuln.get("advisory", {})

                    # Extract CVE ID
                    cve_id = None
                    for identifier in advisory_data.get("identifiers", []):
                        if identifier.get("type") == "CVE":
                            cve_id = identifier.get("value")
                            break

                    # Map severity
                    severity_map = {
                        "CRITICAL": AdvisorySeverity.CRITICAL,
                        "HIGH": AdvisorySeverity.HIGH,
                        "MODERATE": AdvisorySeverity.MODERATE,
                        "LOW": AdvisorySeverity.LOW,
                    }
                    severity = severity_map.get(
                        advisory_data.get("severity", "").upper(),
                        AdvisorySeverity.UNKNOWN
                    )

                    # Extract CWEs
                    cwes = [
                        cwe.get("cweId", "")
                        for cwe in advisory_data.get("cwes", {}).get("nodes", [])
                    ]

                    # Extract patched version
                    patched_versions = {}
                    first_patched = vuln.get("firstPatchedVersion")
                    if first_patched and first_patched.get("identifier"):
                        pkg_name = vuln.get("package", {}).get("name", package_name)
                        patched_versions[pkg_name] = first_patched["identifier"]

                    # Build advisory
                    advisory = GitHubAdvisory(
                        ghsa_id=advisory_data.get("ghsaId", ""),
                        cve_id=cve_id,
                        severity=severity,
                        summary=advisory_data.get("summary", ""),
                        description=advisory_data.get("description", ""),
                        affected_packages=[{
                            "name": vuln.get("package", {}).get("name", ""),
                            "ecosystem": vuln.get("package", {}).get("ecosystem", ""),
                            "vulnerable_versions": vuln.get("vulnerableVersionRange", ""),
                        }],
                        patched_versions=patched_versions,
                        cwes=cwes,
                        cvss_score=advisory_data.get("cvss", {}).get("score"),
                        cvss_vector=advisory_data.get("cvss", {}).get("vectorString"),
                        published_at=advisory_data.get("publishedAt", ""),
                        updated_at=advisory_data.get("updatedAt", ""),
                        references=[
                            ref.get("url", "")
                            for ref in advisory_data.get("references", [])
                        ],
                    )

                    advisories.append(advisory)

                    # Index by CVE and GHSA
                    if advisory.cve_id:
                        self._advisories_by_cve[advisory.cve_id] = advisory
                    self._advisories_by_ghsa[advisory.ghsa_id] = advisory

        # Cache the results
        if advisories:
            self._save_to_cache(package_name, advisories)

        return AdvisoryQueryResult(
            package_name=package_name,
            advisories=advisories,
            query_time=datetime.now(),
            from_cache=False
        )

    def query_multiple_packages(self, packages: List[str], use_cache: bool = True) -> Dict[str, AdvisoryQueryResult]:
        """
        Query advisories for multiple packages

        Args:
            packages: List of npm package names
            use_cache: Whether to use cached results

        Returns:
            Dictionary mapping package name to AdvisoryQueryResult
        """
        results = {}
        for package in packages:
            results[package] = self.query_package(package, use_cache)
        return results

    def get_advisory_by_cve(self, cve_id: str) -> Optional[GitHubAdvisory]:
        """Get advisory by CVE ID (from cache/memory only)"""
        return self._advisories_by_cve.get(cve_id)

    def get_advisory_by_ghsa(self, ghsa_id: str) -> Optional[GitHubAdvisory]:
        """Get advisory by GHSA ID (from cache/memory only)"""
        return self._advisories_by_ghsa.get(ghsa_id)

    def check_package_version(self, package_name: str, version: str, use_cache: bool = True) -> List[GitHubAdvisory]:
        """
        Check if a specific package version is vulnerable

        Args:
            package_name: The npm package name
            version: The version to check
            use_cache: Whether to use cached results

        Returns:
            List of advisories affecting this version
        """
        result = self.query_package(package_name, use_cache)

        affected = []
        for advisory in result.advisories:
            for pkg in advisory.affected_packages:
                if pkg.get("name") == package_name:
                    vulnerable_range = pkg.get("vulnerable_versions", "")
                    if self._version_in_range(version, vulnerable_range):
                        affected.append(advisory)
                        break

        return affected

    def _version_in_range(self, version: str, range_str: str) -> bool:
        """
        Check if version is in vulnerable range
        Supports npm semver range syntax
        """
        if not range_str:
            return False

        # Strip version prefix
        version = version.lstrip("^~>=<")

        # Parse version
        version_match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
        if not version_match:
            return True  # Assume vulnerable if can't parse

        v_major, v_minor, v_patch = int(version_match.group(1)), int(version_match.group(2)), int(version_match.group(3))
        version_tuple = (v_major, v_minor, v_patch)

        # Parse range - npm semver syntax
        # Examples: "< 1.0.0", ">= 1.0.0, < 2.0.0", "> 1.0.0 < 2.0.0"

        # Handle "< X.Y.Z" pattern
        lt_match = re.search(r"<\s*(\d+)\.(\d+)\.(\d+)", range_str)
        gte_match = re.search(r">=\s*(\d+)\.(\d+)\.(\d+)", range_str)
        gt_match = re.search(r">\s*(\d+)\.(\d+)\.(\d+)", range_str)

        if lt_match:
            lt_tuple = (int(lt_match.group(1)), int(lt_match.group(2)), int(lt_match.group(3)))
            if version_tuple >= lt_tuple:
                return False  # Version is not less than upper bound

        if gte_match:
            gte_tuple = (int(gte_match.group(1)), int(gte_match.group(2)), int(gte_match.group(3)))
            if version_tuple < gte_tuple:
                return False  # Version is less than lower bound

        if gt_match and not gte_match:
            gt_tuple = (int(gt_match.group(1)), int(gt_match.group(2)), int(gt_match.group(3)))
            if version_tuple <= gt_tuple:
                return False  # Version is not greater than lower bound

        return True

    def export_to_vuln_db_format(self, advisories: List[GitHubAdvisory]) -> List[Dict[str, Any]]:
        """
        Export advisories to Shellockolm vulnerability database format

        Args:
            advisories: List of GitHub advisories

        Returns:
            List of vulnerability records in internal format
        """
        vulns = []

        for advisory in advisories:
            # Map severity
            severity_map = {
                AdvisorySeverity.CRITICAL: "critical",
                AdvisorySeverity.HIGH: "high",
                AdvisorySeverity.MODERATE: "medium",
                AdvisorySeverity.LOW: "low",
                AdvisorySeverity.UNKNOWN: "medium",
            }

            # Build affected versions list
            affected_versions = []
            packages = []
            for pkg in advisory.affected_packages:
                packages.append(pkg.get("name", ""))
                vuln_range = pkg.get("vulnerable_versions", "")
                if vuln_range:
                    affected_versions.append(vuln_range)

            vuln = {
                "cve_id": advisory.cve_id or advisory.ghsa_id,
                "ghsa_id": advisory.ghsa_id,
                "title": advisory.summary,
                "description": advisory.description,
                "severity": severity_map.get(advisory.severity, "medium"),
                "cvss_score": advisory.cvss_score,
                "cvss_vector": advisory.cvss_vector,
                "packages": packages,
                "affected_versions": affected_versions,
                "patched_versions": advisory.patched_versions,
                "cwes": advisory.cwes,
                "references": advisory.references,
                "published_at": advisory.published_at,
                "updated_at": advisory.updated_at,
                "source": "github_advisory_database",
            }

            vulns.append(vuln)

        return vulns

    def generate_report(self, packages: List[str], output_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Generate a comprehensive report of all advisories for given packages

        Args:
            packages: List of package names to check
            output_path: Optional path to save the report

        Returns:
            Report dictionary
        """
        all_advisories = []
        package_results = {}

        for package in packages:
            result = self.query_package(package)
            package_results[package] = {
                "advisory_count": len(result.advisories),
                "from_cache": result.from_cache,
                "advisories": [a.ghsa_id for a in result.advisories],
            }
            all_advisories.extend(result.advisories)

        # Count by severity
        severity_counts = {
            "critical": 0,
            "high": 0,
            "moderate": 0,
            "low": 0,
            "unknown": 0,
        }

        for advisory in all_advisories:
            severity_counts[advisory.severity.value] += 1

        report = {
            "report_time": datetime.now().isoformat(),
            "total_packages": len(packages),
            "total_advisories": len(all_advisories),
            "severity_breakdown": severity_counts,
            "packages": package_results,
            "advisories": [a.to_dict() for a in all_advisories],
        }

        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, "w") as f:
                json.dump(report, f, indent=2)

        return report

    def clear_cache(self):
        """Clear all cached advisories"""
        for cache_file in self.cache_dir.glob("*.json"):
            try:
                cache_file.unlink()
            except Exception:
                pass


# ─────────────────────────────────────────────────────────────────
# CLI ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    """CLI entry point for testing"""
    import sys

    if len(sys.argv) < 2:
        print("Usage: python github_advisory.py <package-name>")
        print("Example: python github_advisory.py lodash")
        sys.exit(1)

    package_name = sys.argv[1]

    print(f"Querying GitHub Advisory Database for: {package_name}")
    print("-" * 50)

    db = GitHubAdvisoryDB()
    result = db.query_package(package_name)

    print(f"From cache: {result.from_cache}")
    print(f"Found {len(result.advisories)} advisories")
    print()

    for advisory in result.advisories:
        print(f"  [{advisory.severity.value.upper()}] {advisory.ghsa_id}")
        if advisory.cve_id:
            print(f"    CVE: {advisory.cve_id}")
        print(f"    Summary: {advisory.summary[:80]}...")
        if advisory.patched_versions:
            print(f"    Patched: {advisory.patched_versions}")
        print()


if __name__ == "__main__":
    main()
