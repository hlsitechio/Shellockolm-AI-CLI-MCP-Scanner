#!/usr/bin/env python3
"""
GitHub Repository Scanner for CVE-2025-55182
Scans all your GitHub repositories for vulnerable React versions
"""

import os
import sys
import json
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional
import subprocess


class GitHubScanner:
    """Scanner that uses GitHub CLI to scan repositories for CVE-2025-55182"""

    VULNERABLE_VERSIONS = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]
    PATCHED_VERSIONS = {
        "19.0.0": "19.0.1",
        "19.1.0": "19.1.2",
        "19.1.1": "19.1.2",
        "19.2.0": "19.2.1",
    }

    def __init__(self, auto_pr: bool = False, report_only: bool = True):
        self.auto_pr = auto_pr
        self.report_only = report_only
        self.vulnerable_repos = []
        self.scanned_count = 0
        self.results = {
            "scan_date": datetime.now().isoformat(),
            "total_repos": 0,
            "vulnerable_repos": [],
            "errors": [],
        }

    def check_gh_cli(self) -> bool:
        """Check if GitHub CLI is installed and authenticated"""
        try:
            result = subprocess.run(
                ["gh", "auth", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0
        except FileNotFoundError:
            print("[ERROR] GitHub CLI (gh) not found!")
            print("Install: https://cli.github.com/")
            return False
        except Exception as e:
            print(f"[ERROR] Failed to check GitHub CLI: {e}")
            return False

    def get_repositories(self, org: Optional[str] = None) -> List[Dict]:
        """Get list of repositories using GitHub CLI"""
        try:
            if org:
                cmd = ["gh", "repo", "list", org, "--json", "name,nameWithOwner,isPrivate", "--limit", "1000"]
            else:
                cmd = ["gh", "repo", "list", "--json", "name,nameWithOwner,isPrivate", "--limit", "1000"]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                print(f"[ERROR] Failed to list repositories: {result.stderr}")
                return []

            repos = json.loads(result.stdout)
            return repos

        except Exception as e:
            print(f"[ERROR] Failed to get repositories: {e}")
            return []

    def get_package_json(self, repo_full_name: str) -> Optional[Dict]:
        """Get package.json content from a repository"""
        try:
            # Try to get package.json from root
            result = subprocess.run(
                ["gh", "api", f"repos/{repo_full_name}/contents/package.json"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            content_data = json.loads(result.stdout)

            # GitHub API returns base64 encoded content
            import base64
            content = base64.b64decode(content_data.get("content", "")).decode("utf-8")
            return json.loads(content)

        except json.JSONDecodeError:
            return None
        except Exception:
            return None

    def check_vulnerability(self, package_json: Dict) -> Optional[Dict]:
        """Check if package.json contains vulnerable React version"""
        dependencies = {
            **package_json.get("dependencies", {}),
            **package_json.get("devDependencies", {}),
        }

        react_version = dependencies.get("react", "")

        # Strip version prefixes
        react_version = react_version.lstrip("^~>=<")

        if react_version in self.VULNERABLE_VERSIONS:
            return {
                "current_version": react_version,
                "patched_version": self.PATCHED_VERSIONS.get(react_version),
                "has_next": "next" in dependencies,
                "has_rsc": "react-server-dom-webpack" in dependencies,
            }

        return None

    def create_fix_pr(self, repo_full_name: str, vulnerability: Dict) -> bool:
        """Create a pull request with the fix"""
        try:
            current = vulnerability["current_version"]
            patched = vulnerability["patched_version"]

            print(f"  [AUTO-PR] Creating pull request...")

            # This would create a PR using GitHub CLI
            # For now, we'll return the command that would be used
            pr_title = f"Security: Fix CVE-2025-55182 - Update React {current} to {patched}"
            pr_body = f"""## Security Patch: CVE-2025-55182

This PR updates React from `{current}` to `{patched}` to fix a critical Remote Code Execution vulnerability.

**CVE Details:**
- CVE ID: CVE-2025-55182
- CVSS Score: 10.0 (Critical)
- Affected: React Server Components
- Impact: Unauthenticated Remote Code Execution

**Changes:**
- Update `react` from `{current}` to `{patched}`
- Update `react-dom` from `{current}` to `{patched}`

**References:**
- https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components
- https://www.cve.org/CVERecord?id=CVE-2025-55182

---
Auto-generated by react2shell-autopatcher
"""

            print(f"  [INFO] PR would be created with title: {pr_title}")
            print(f"  [INFO] Use 'gh pr create' to create PRs manually")

            return True

        except Exception as e:
            print(f"  [ERROR] Failed to create PR: {e}")
            return False

    def scan_repository(self, repo: Dict) -> None:
        """Scan a single repository"""
        repo_name = repo["nameWithOwner"]
        self.scanned_count += 1

        print(f"[{self.scanned_count}] Scanning {repo_name}...", end=" ")

        try:
            package_json = self.get_package_json(repo_name)

            if not package_json:
                print("[SKIP] No package.json")
                return

            vulnerability = self.check_vulnerability(package_json)

            if vulnerability:
                print(f"[VULNERABLE] React {vulnerability['current_version']}")

                vuln_info = {
                    "repository": repo_name,
                    "private": repo.get("isPrivate", False),
                    **vulnerability,
                }

                self.vulnerable_repos.append(vuln_info)
                self.results["vulnerable_repos"].append(vuln_info)

                if self.auto_pr and not self.report_only:
                    self.create_fix_pr(repo_name, vulnerability)
            else:
                print("[SAFE]")

        except Exception as e:
            print(f"[ERROR] {str(e)}")
            self.results["errors"].append({
                "repository": repo_name,
                "error": str(e),
            })

    def scan_all(self, org: Optional[str] = None) -> None:
        """Scan all repositories"""
        print("=" * 70)
        print("GitHub Repository Scanner - CVE-2025-55182")
        print("=" * 70)
        print()

        if not self.check_gh_cli():
            print("[ERROR] Please install and authenticate GitHub CLI")
            print("Visit: https://cli.github.com/")
            sys.exit(1)

        print("[INFO] Fetching repositories...")
        repos = self.get_repositories(org)

        if not repos:
            print("[ERROR] No repositories found")
            sys.exit(1)

        self.results["total_repos"] = len(repos)

        print(f"[INFO] Found {len(repos)} repositories")
        print(f"[INFO] Mode: {'Auto-PR' if self.auto_pr else 'Report Only'}")
        print()

        for repo in repos:
            self.scan_repository(repo)

        self.print_summary()
        self.save_report()

    def print_summary(self) -> None:
        """Print scan summary"""
        print()
        print("=" * 70)
        print("SCAN SUMMARY")
        print("=" * 70)
        print(f"Total Repositories:  {self.results['total_repos']}")
        print(f"Vulnerable Found:    {len(self.vulnerable_repos)}")
        print(f"Errors:              {len(self.results['errors'])}")
        print()

        if self.vulnerable_repos:
            print("VULNERABLE REPOSITORIES:")
            print("-" * 70)
            for vuln in self.vulnerable_repos:
                visibility = "[PRIVATE]" if vuln["private"] else "[PUBLIC]"
                print(f"  {visibility} {vuln['repository']}")
                print(f"    Current: React {vuln['current_version']}")
                print(f"    Fix: Update to {vuln['patched_version']}")
                print()

    def save_report(self) -> None:
        """Save detailed report to JSON"""
        report_file = Path("github_scan_report.json")

        with open(report_file, "w", encoding="utf-8") as f:
            json.dump(self.results, f, indent=2)

        print(f"[INFO] Detailed report saved to: {report_file}")


def main():
    parser = argparse.ArgumentParser(
        description="Scan GitHub repositories for CVE-2025-55182",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Scan all your repositories (report only)
  python github_scanner.py

  # Scan organization repositories
  python github_scanner.py --org yourcompany

  # Scan and create fix PRs (coming soon)
  python github_scanner.py --auto-pr

Security:
  This tool uses GitHub CLI (gh) for authentication.
  Your GitHub token is never stored or transmitted.
  All API calls use official GitHub CLI.

Requirements:
  - GitHub CLI (gh) installed and authenticated
  - Read access to repositories
  - 'repo' scope for private repositories
""",
    )

    parser.add_argument(
        "--org",
        help="Organization name to scan",
        type=str,
    )

    parser.add_argument(
        "--auto-pr",
        help="Automatically create pull requests for fixes (experimental)",
        action="store_true",
    )

    args = parser.parse_args()

    scanner = GitHubScanner(
        auto_pr=args.auto_pr,
        report_only=not args.auto_pr,
    )

    try:
        scanner.scan_all(org=args.org)
    except KeyboardInterrupt:
        print("\n\n[INFO] Scan interrupted by user")
        scanner.save_report()
        sys.exit(0)


if __name__ == "__main__":
    main()
