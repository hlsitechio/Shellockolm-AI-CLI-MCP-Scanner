"""
CVE-2025-55182 & CVE-2025-66478 Scanner Module
Scans directories for vulnerable React Server Components
These are duplicate CVEs for the same vulnerability
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Optional
from dataclasses import dataclass, field
from packaging import version


@dataclass
class VulnerableProject:
    """Represents a project with CVE-2025-55182/CVE-2025-66478 vulnerability"""
    path: str
    react_version: str
    recommended_version: str
    risk_level: str
    cve_ids: List[str] = field(default_factory=lambda: ["CVE-2025-55182", "CVE-2025-66478"])
    next_js_version: Optional[str] = None
    next_js_vulnerable: bool = False
    next_js_recommended: Optional[str] = None
    uses_server_components: bool = False
    vulnerable_packages: List[str] = field(default_factory=list)
    affected_frameworks: List[str] = field(default_factory=list)
    found_in_lockfiles: List[str] = field(default_factory=list)
    vulnerable_packages_in_lockfiles: List[str] = field(default_factory=list)


class CVEScanner:
    """Scanner for CVE-2025-55182 & CVE-2025-66478 vulnerability"""

    # CVE Information
    CVE_IDS = ["CVE-2025-55182", "CVE-2025-66478"]

    # Vulnerable React versions
    VULNERABLE_VERSIONS = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]

    # Patched versions mapping
    PATCHED_VERSIONS = {
        "19.0.0": "19.0.1",
        "19.1.0": "19.1.2",
        "19.1.1": "19.1.2",
        "19.2.0": "19.2.1",
    }

    # Next.js vulnerable versions and patches (based on CVE-2025-66478 / GHSA-9qr9-h5gf-34mp)
    NEXTJS_VULNERABLE_RANGES = {
        "15.0": {"min": "15.0.0", "max": "15.0.4", "patch": "15.0.5"},
        "15.1": {"min": "15.1.0", "max": "15.1.8", "patch": "15.1.9"},
        "15.2": {"min": "15.2.0", "max": "15.2.5", "patch": "15.2.6"},
        "15.3": {"min": "15.3.0", "max": "15.3.5", "patch": "15.3.6"},
        "15.4": {"min": "15.4.0", "max": "15.4.7", "patch": "15.4.8"},
        "15.5": {"min": "15.5.0", "max": "15.5.6", "patch": "15.5.7"},
        "16.0": {"min": "16.0.0", "max": "16.0.6", "patch": "16.0.7"},
    }

    # Next.js canary versions are also affected
    NEXTJS_CANARY_SAFE_MIN = "14.3.0-canary.77"

    # React Server Components packages
    SERVER_COMPONENT_PACKAGES = [
        "react-server-dom-webpack",
        "react-server-dom-parcel",
        "react-server-dom-turbopack"
    ]

    # Affected frameworks and bundlers (from official CVE advisory)
    AFFECTED_FRAMEWORKS = [
        "next",
        "react-router",
        "waku",
        "@parcel/rsc",
        "@vitejs/plugin-rsc",
        "rwsdk"
    ]

    # Lockfile patterns to scan
    LOCKFILE_PATTERNS = [
        "package-lock.json",  # npm
        "yarn.lock",          # yarn
        "pnpm-lock.yaml",     # pnpm
        "bun.lockb",          # bun (binary format - harder to parse)
        "npm-shrinkwrap.json" # npm shrinkwrap
    ]

    def __init__(self, exclude_patterns: Optional[List[str]] = None):
        """
        Initialize scanner

        Args:
            exclude_patterns: List of directory patterns to exclude
        """
        self.exclude_patterns = exclude_patterns or [
            # Development folders
            "node_modules",
            ".git",
            "dist",
            "build",
            ".next",
            "out",
            ".cache",
            "coverage",
            ".npm",
            ".bun",
            # Windows system folders (MASSIVE speed boost)
            "Windows",
            "Program Files",
            "Program Files (x86)",
            "ProgramData",
            "$Recycle.Bin",
            "System Volume Information",
            "$WINDOWS.~BT",
            "Recovery",
            "PerfLogs",
            "AppData",
            "Backups",
            # Common large folders
            "Downloads",
            "Videos",
            "Music",
            "Pictures",
            "Documents",
            # Python/Node package caches
            ".venv",
            "venv",
            "env",
            "__pycache__",
            ".pytest_cache",
            # IDE folders
            ".vscode",
            ".idea",
            ".vs"
        ]

    def should_exclude(self, path: Path) -> bool:
        """Check if a path should be excluded from scanning"""
        path_str = str(path).lower()
        return any(pattern.lower() in path_str for pattern in self.exclude_patterns)

    def find_package_json_files(self, root_path: str, recursive: bool = True, max_depth: int = 5) -> List[Path]:
        """
        Find all package.json files in a directory (OPTIMIZED FOR SPEED)

        Args:
            root_path: Root directory to scan
            recursive: Whether to scan subdirectories
            max_depth: Maximum directory depth to scan (default 5 for speed)

        Returns:
            List of Path objects pointing to package.json files
        """
        root = Path(root_path)
        package_files = []

        if not root.exists():
            return package_files

        if recursive:
            # Use os.walk for speed - it allows early exclusion
            import os
            for dirpath, dirnames, filenames in os.walk(root):
                current_path = Path(dirpath)

                # Calculate depth
                try:
                    depth = len(current_path.relative_to(root).parts)
                except ValueError:
                    depth = 0

                # Stop if too deep
                if depth > max_depth:
                    dirnames.clear()  # Don't recurse further
                    continue

                # Remove excluded directories IN-PLACE (prevents walking into them)
                dirnames[:] = [d for d in dirnames if not self.should_exclude(current_path / d)]

                # Check for package.json in current directory
                if "package.json" in filenames:
                    pkg_path = current_path / "package.json"
                    if not self.should_exclude(current_path):
                        package_files.append(pkg_path)
        else:
            package_json = root / "package.json"
            if package_json.exists():
                package_files.append(package_json)

        return package_files

    def find_lockfiles(self, root_path: str, recursive: bool = True, max_depth: int = 5) -> Dict[str, List[Path]]:
        """
        Find all lockfiles in a directory (OPTIMIZED FOR SPEED)

        Args:
            root_path: Root directory to scan
            recursive: Whether to scan subdirectories
            max_depth: Maximum directory depth to scan (default 5 for speed)

        Returns:
            Dictionary mapping lockfile types to lists of Path objects
        """
        root = Path(root_path)
        lockfiles = {pattern: [] for pattern in self.LOCKFILE_PATTERNS}

        if not root.exists():
            return lockfiles

        if recursive:
            import os
            for dirpath, dirnames, filenames in os.walk(root):
                current_path = Path(dirpath)

                # Calculate depth
                try:
                    depth = len(current_path.relative_to(root).parts)
                except ValueError:
                    depth = 0

                # Stop if too deep
                if depth > max_depth:
                    dirnames.clear()
                    continue

                # Remove excluded directories IN-PLACE
                dirnames[:] = [d for d in dirnames if not self.should_exclude(current_path / d)]

                # Check for lockfiles in current directory
                if not self.should_exclude(current_path):
                    for lockfile_pattern in self.LOCKFILE_PATTERNS:
                        if lockfile_pattern in filenames:
                            lockfile_path = current_path / lockfile_pattern
                            lockfiles[lockfile_pattern].append(lockfile_path)
        else:
            for lockfile_pattern in self.LOCKFILE_PATTERNS:
                lockfile_path = root / lockfile_pattern
                if lockfile_path.exists():
                    lockfiles[lockfile_pattern].append(lockfile_path)

        return lockfiles

    def parse_package_json(self, package_path: Path) -> Optional[Dict]:
        """
        Parse a package.json file

        Args:
            package_path: Path to package.json file

        Returns:
            Parsed JSON as dictionary, or None if parsing fails
        """
        try:
            with open(package_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Warning: Could not parse {package_path}: {e}")
            return None

    def parse_package_lock_json(self, lockfile_path: Path) -> Optional[Dict]:
        """
        Parse package-lock.json or npm-shrinkwrap.json

        Args:
            lockfile_path: Path to lockfile

        Returns:
            Dictionary of package@version found in lockfile
        """
        try:
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                packages = {}

                # package-lock.json v2/v3 format
                if "packages" in data:
                    for pkg_path, pkg_info in data.get("packages", {}).items():
                        if pkg_path.startswith("node_modules/"):
                            pkg_name = pkg_path.replace("node_modules/", "")
                            if "version" in pkg_info:
                                packages[pkg_name] = pkg_info["version"]

                # package-lock.json v1 format
                if "dependencies" in data:
                    def extract_deps(deps_dict):
                        for pkg_name, pkg_info in deps_dict.items():
                            if "version" in pkg_info:
                                packages[pkg_name] = pkg_info["version"]
                            if "dependencies" in pkg_info:
                                extract_deps(pkg_info["dependencies"])

                    extract_deps(data.get("dependencies", {}))

                return packages
        except (json.JSONDecodeError, FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Warning: Could not parse {lockfile_path}: {e}")
            return None

    def parse_yarn_lock(self, lockfile_path: Path) -> Optional[Dict]:
        """
        Parse yarn.lock file

        Args:
            lockfile_path: Path to yarn.lock

        Returns:
            Dictionary of package@version found in lockfile
        """
        try:
            packages = {}
            with open(lockfile_path, 'r', encoding='utf-8') as f:
                current_package = None
                for line in f:
                    line = line.strip()

                    # Package declaration (starts with package name)
                    if line and not line.startswith("#") and not line.startswith(" "):
                        # Extract package name from line like: "react@^19.0.0", react@^19.0.0:
                        if "@" in line and (line.endswith(":") or "," in line):
                            # Handle multiple package specs on one line
                            parts = line.replace(":", "").replace('"', '').split(",")
                            for part in parts:
                                part = part.strip()
                                if "@" in part:
                                    pkg_name = part.split("@")[0].strip()
                                    if pkg_name:
                                        current_package = pkg_name

                    # Version line
                    elif current_package and line.startswith("version"):
                        version = line.split('"')[1] if '"' in line else line.split()[1]
                        packages[current_package] = version
                        current_package = None

            return packages
        except (FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Warning: Could not parse {lockfile_path}: {e}")
            return None

    def parse_pnpm_lock(self, lockfile_path: Path) -> Optional[Dict]:
        """
        Parse pnpm-lock.yaml file

        Args:
            lockfile_path: Path to pnpm-lock.yaml

        Returns:
            Dictionary of package@version found in lockfile
        """
        try:
            # Try to use PyYAML if available
            try:
                import yaml
                with open(lockfile_path, 'r', encoding='utf-8') as f:
                    data = yaml.safe_load(f)
                    packages = {}

                    # pnpm v6+ format
                    if "packages" in data:
                        for pkg_spec, pkg_info in data.get("packages", {}).items():
                            # Extract package name and version from spec like "/react/19.0.0"
                            parts = pkg_spec.strip("/").split("/")
                            if len(parts) >= 2:
                                pkg_name = "/".join(parts[:-1])
                                version = parts[-1]
                                packages[pkg_name] = version

                    return packages
            except ImportError:
                # Fallback: basic text parsing
                packages = {}
                with open(lockfile_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        # Look for patterns like "  /react/19.0.0:"
                        if line.strip().startswith("/") and ":" in line:
                            spec = line.strip().replace(":", "")
                            parts = spec.strip("/").split("/")
                            if len(parts) >= 2:
                                pkg_name = "/".join(parts[:-1])
                                version = parts[-1]
                                packages[pkg_name] = version

                return packages
        except (FileNotFoundError, UnicodeDecodeError) as e:
            print(f"Warning: Could not parse {lockfile_path}: {e}")
            return None

    def check_lockfiles_for_vulnerabilities(self, project_dir: Path) -> Dict:
        """
        Check all lockfiles in a project directory for vulnerable packages

        Args:
            project_dir: Project directory path

        Returns:
            Dictionary with lockfile vulnerability information
        """
        vulnerabilities = {
            "found_in_lockfiles": [],
            "vulnerable_packages_in_lockfiles": []
        }

        # Check each lockfile type
        lockfile_parsers = {
            "package-lock.json": self.parse_package_lock_json,
            "npm-shrinkwrap.json": self.parse_package_lock_json,
            "yarn.lock": self.parse_yarn_lock,
            "pnpm-lock.yaml": self.parse_pnpm_lock,
        }

        for lockfile_name, parser in lockfile_parsers.items():
            lockfile_path = project_dir / lockfile_name
            if lockfile_path.exists():
                print(f"  📄 Checking {lockfile_name}...")
                packages = parser(lockfile_path)
                if packages:
                    # Check for vulnerable React versions
                    for pkg_name, pkg_version in packages.items():
                        if pkg_name == "react" and pkg_version in self.VULNERABLE_VERSIONS:
                            vulnerabilities["found_in_lockfiles"].append(lockfile_name)
                            vulnerabilities["vulnerable_packages_in_lockfiles"].append(
                                f"{pkg_name}@{pkg_version} in {lockfile_name}"
                            )

                        # Check for vulnerable server component packages
                        if pkg_name in self.SERVER_COMPONENT_PACKAGES and pkg_version in self.VULNERABLE_VERSIONS:
                            vulnerabilities["found_in_lockfiles"].append(lockfile_name)
                            vulnerabilities["vulnerable_packages_in_lockfiles"].append(
                                f"{pkg_name}@{pkg_version} in {lockfile_name}"
                            )

                        # Check for vulnerable Next.js versions
                        if pkg_name == "next":
                            is_vuln, _ = self.is_nextjs_vulnerable(pkg_version)
                            if is_vuln:
                                vulnerabilities["found_in_lockfiles"].append(lockfile_name)
                                vulnerabilities["vulnerable_packages_in_lockfiles"].append(
                                    f"{pkg_name}@{pkg_version} in {lockfile_name}"
                                )

        # Deduplicate
        vulnerabilities["found_in_lockfiles"] = list(set(vulnerabilities["found_in_lockfiles"]))
        vulnerabilities["vulnerable_packages_in_lockfiles"] = list(set(vulnerabilities["vulnerable_packages_in_lockfiles"]))

        return vulnerabilities

    def extract_version(self, version_str: str) -> str:
        """
        Extract clean version number from version string

        Args:
            version_str: Version string (e.g., "^19.0.0", "~19.1.0")

        Returns:
            Clean version number (e.g., "19.0.0")
        """
        # Remove common prefixes
        cleaned = version_str.lstrip("^~>=<")
        # Handle version ranges (take the first version)
        if " " in cleaned:
            cleaned = cleaned.split()[0]
        return cleaned

    def is_vulnerable_version(self, react_version: str) -> bool:
        """
        Check if a React version is vulnerable to CVE-2025-55182/CVE-2025-66478

        Args:
            react_version: React version string

        Returns:
            True if vulnerable, False otherwise
        """
        try:
            clean_version = self.extract_version(react_version)
            return clean_version in self.VULNERABLE_VERSIONS
        except Exception:
            return False

    def is_nextjs_vulnerable(self, next_version: str) -> tuple[bool, Optional[str]]:
        """
        Check if a Next.js version is vulnerable to CVE-2025-66478

        Args:
            next_version: Next.js version string

        Returns:
            Tuple of (is_vulnerable, recommended_patch_version)
        """
        try:
            clean_version = self.extract_version(next_version)

            # Handle canary versions
            if "canary" in clean_version:
                # Versions before 14.3.0-canary.77 are vulnerable
                # This is a simplified check
                return (True, "15.6.0-canary.58 or 16.1.0-canary.12+")

            # Parse major.minor version
            parts = clean_version.split(".")
            if len(parts) < 2:
                return (False, None)

            major_minor = f"{parts[0]}.{parts[1]}"

            # Check if version falls in vulnerable range
            if major_minor in self.NEXTJS_VULNERABLE_RANGES:
                range_info = self.NEXTJS_VULNERABLE_RANGES[major_minor]
                try:
                    v = version.parse(clean_version)
                    v_min = version.parse(range_info["min"])
                    v_max = version.parse(range_info["max"])

                    if v_min <= v <= v_max:
                        return (True, range_info["patch"])
                except Exception:
                    # If version parsing fails, assume vulnerable for this range
                    return (True, range_info["patch"])

            return (False, None)
        except Exception:
            return (False, None)

    def get_recommended_version(self, current_version: str) -> str:
        """
        Get the recommended patched version

        Args:
            current_version: Current vulnerable version

        Returns:
            Recommended patched version
        """
        clean_version = self.extract_version(current_version)
        return self.PATCHED_VERSIONS.get(clean_version, "19.1.2")

    def check_server_components(self, package_data: Dict) -> tuple[bool, List[str], List[str]]:
        """
        Check if project uses React Server Components and affected frameworks

        Args:
            package_data: Parsed package.json data

        Returns:
            Tuple of (uses_server_components, list of vulnerable packages, list of affected frameworks)
        """
        vulnerable_packages = []
        affected_frameworks = []
        dependencies = {**package_data.get("dependencies", {}),
                       **package_data.get("devDependencies", {})}

        # Check for vulnerable React Server Component packages
        for pkg in self.SERVER_COMPONENT_PACKAGES:
            if pkg in dependencies:
                pkg_version = self.extract_version(dependencies[pkg])
                if pkg_version in self.VULNERABLE_VERSIONS:
                    vulnerable_packages.append(f"{pkg}@{pkg_version}")

        # Check for affected frameworks (from official CVE advisory)
        for framework in self.AFFECTED_FRAMEWORKS:
            if framework in dependencies:
                affected_frameworks.append(f"{framework}@{self.extract_version(dependencies[framework])}")

        # Check if using Next.js (which includes server components)
        has_nextjs = "next" in dependencies
        has_server_components = len(vulnerable_packages) > 0 or has_nextjs

        return (has_server_components, vulnerable_packages, affected_frameworks)

    def analyze_project(self, package_path: Path) -> Optional[VulnerableProject]:
        """
        Analyze a single project for vulnerability (including lockfiles)

        Args:
            package_path: Path to package.json file

        Returns:
            VulnerableProject object if vulnerable, None otherwise
        """
        package_data = self.parse_package_json(package_path)
        if not package_data:
            return None

        dependencies = package_data.get("dependencies", {})
        dev_dependencies = package_data.get("devDependencies", {})
        all_deps = {**dependencies, **dev_dependencies}

        # Check React version
        react_version = all_deps.get("react")
        if not react_version:
            return None

        if not self.is_vulnerable_version(react_version):
            return None

        # Get Next.js version if present and check if vulnerable
        next_version = all_deps.get("next")
        next_js_vulnerable = False
        next_js_recommended = None

        if next_version:
            next_js_vulnerable, next_js_recommended = self.is_nextjs_vulnerable(next_version)

        # Check for server components and affected frameworks
        uses_sc, vulnerable_pkgs, affected_fws = self.check_server_components(package_data)

        # Check lockfiles for additional vulnerability confirmation
        lockfile_vulns = self.check_lockfiles_for_vulnerabilities(package_path.parent)

        return VulnerableProject(
            path=str(package_path.parent),
            react_version=self.extract_version(react_version),
            recommended_version=self.get_recommended_version(react_version),
            risk_level="CRITICAL",
            cve_ids=self.CVE_IDS,
            next_js_version=self.extract_version(next_version) if next_version else None,
            next_js_vulnerable=next_js_vulnerable,
            next_js_recommended=next_js_recommended,
            uses_server_components=uses_sc,
            vulnerable_packages=vulnerable_pkgs,
            affected_frameworks=affected_fws,
            found_in_lockfiles=lockfile_vulns["found_in_lockfiles"],
            vulnerable_packages_in_lockfiles=lockfile_vulns["vulnerable_packages_in_lockfiles"]
        )

    def scan_directory(self, root_path: str, recursive: bool = True) -> Dict:
        """
        Scan a directory for vulnerable projects

        Args:
            root_path: Root directory to scan
            recursive: Whether to scan subdirectories

        Returns:
            Dictionary with scan results
        """
        package_files = self.find_package_json_files(root_path, recursive)
        vulnerable_projects = []
        safe_projects = []

        for package_path in package_files:
            result = self.analyze_project(package_path)
            if result:
                vulnerable_projects.append(result)
            else:
                safe_projects.append(str(package_path.parent))

        return {
            "summary": {
                "total_projects": len(package_files),
                "vulnerable_projects": len(vulnerable_projects),
                "safe_projects": len(safe_projects),
                "cve_ids": self.CVE_IDS
            },
            "vulnerable_projects": [
                {
                    "path": vp.path,
                    "react_version": vp.react_version,
                    "recommended_version": vp.recommended_version,
                    "risk_level": vp.risk_level,
                    "cve_ids": vp.cve_ids,
                    "next_js_version": vp.next_js_version,
                    "next_js_vulnerable": vp.next_js_vulnerable,
                    "next_js_recommended": vp.next_js_recommended,
                    "uses_server_components": vp.uses_server_components,
                    "vulnerable_packages": vp.vulnerable_packages,
                    "affected_frameworks": vp.affected_frameworks,
                    "found_in_lockfiles": vp.found_in_lockfiles,
                    "vulnerable_packages_in_lockfiles": vp.vulnerable_packages_in_lockfiles
                }
                for vp in vulnerable_projects
            ],
            "safe_projects": safe_projects
        }


if __name__ == "__main__":
    # Example usage
    scanner = CVEScanner()
    results = scanner.scan_directory(".", recursive=True)

    print(f"Scanning for {', '.join(scanner.CVE_IDS)}")
    print(f"Scanned {results['summary']['total_projects']} projects")
    print(f"Found {results['summary']['vulnerable_projects']} vulnerable projects")

    for vp in results['vulnerable_projects']:
        print(f"\n[VULNERABLE] {vp['path']}")
        print(f"  CVEs: {', '.join(vp['cve_ids'])}")
        print(f"  React {vp['react_version']} → {vp['recommended_version']}")
        if vp['next_js_version']:
            print(f"  Next.js: {vp['next_js_version']}", end="")
            if vp['next_js_vulnerable']:
                print(f" → {vp['next_js_recommended']} (VULNERABLE)")
            else:
                print(" (OK)")
