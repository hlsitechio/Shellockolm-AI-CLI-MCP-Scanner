"""
Base Scanner Class for Shellockolm
All scanners inherit from this and implement the scan methods
"""

import json
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict, Any, Set, Generator

# Import vulnerability database
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))
from vulnerability_database import (
    VulnerabilityDatabase,
    Vulnerability,
    Severity,
    VulnType,
    ExploitDifficulty
)


class FindingSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class ScanFinding:
    """Represents a single vulnerability finding"""
    cve_id: str
    title: str
    severity: FindingSeverity
    cvss_score: float
    package: str
    version: str
    patched_version: Optional[str]
    file_path: str
    description: str
    exploit_difficulty: str = "Unknown"
    references: List[str] = field(default_factory=list)
    remediation: Optional[str] = None
    detection_method: str = "lockfile"  # lockfile, live, manifest
    raw_data: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """Result of a scan operation"""
    scanner_name: str
    scan_type: str  # local, live, github
    target: str
    start_time: datetime
    end_time: Optional[datetime] = None
    findings: List[ScanFinding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    stats: Dict[str, int] = field(default_factory=dict)

    @property
    def duration_seconds(self) -> float:
        if self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return 0.0

    @property
    def critical_count(self) -> int:
        return len([f for f in self.findings if f.severity == FindingSeverity.CRITICAL])

    @property
    def high_count(self) -> int:
        return len([f for f in self.findings if f.severity == FindingSeverity.HIGH])

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner_name,
            "scan_type": self.scan_type,
            "target": self.target,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_seconds": self.duration_seconds,
            "summary": {
                "total": self.total_findings,
                "critical": self.critical_count,
                "high": self.high_count,
            },
            "findings": [
                {
                    "cve_id": f.cve_id,
                    "title": f.title,
                    "severity": f.severity.value,
                    "cvss_score": f.cvss_score,
                    "package": f.package,
                    "version": f.version,
                    "patched_version": f.patched_version,
                    "file_path": f.file_path,
                    "description": f.description,
                    "exploit_difficulty": f.exploit_difficulty,
                    "remediation": f.remediation,
                }
                for f in self.findings
            ],
            "errors": self.errors,
            "stats": self.stats,
        }

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


class BaseScanner(ABC):
    """
    Abstract base class for all Shellockolm scanners
    """

    # Scanner metadata - override in subclasses
    NAME: str = "base"
    DESCRIPTION: str = "Base scanner"
    CVE_IDS: List[str] = []
    SUPPORTED_PACKAGES: List[str] = []

    # Exclusion patterns for directory traversal
    EXCLUDE_DIRS: Set[str] = {
        "node_modules",
        ".git",
        ".svn",
        ".hg",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        "dist",
        "build",
        ".next",
        ".nuxt",
        "coverage",
        ".vscode",
        ".idea",
        "venv",
        ".venv",
        "env",
    }

    # Windows system folders to skip
    WINDOWS_SYSTEM_DIRS: Set[str] = {
        "Windows",
        "Program Files",
        "Program Files (x86)",
        "ProgramData",
        "$Recycle.Bin",
        "System Volume Information",
    }

    def __init__(self):
        self.db = VulnerabilityDatabase

    @abstractmethod
    def scan_directory(
        self, 
        path: str, 
        recursive: bool = True, 
        max_depth: int = 10,
        quick_mode: bool = False
    ) -> ScanResult:
        """
        Scan a local directory for vulnerabilities
        
        Args:
            path: Directory path to scan
            recursive: Recursively scan subdirectories
            max_depth: Maximum directory depth to traverse
            quick_mode: If True, only check package.json/lock files (FAST)
                       If False, deep scan including file content analysis (SLOW)
        
        Quick Mode (2-3 minutes):
            - Only reads package.json and lock files
            - Checks versions against CVE database
            - Skips deep file content analysis
            - Skips malware detection
            - Skips secrets scanning
        
        Deep Mode (10+ minutes):
            - Full file content analysis
            - Malware pattern detection
            - Secrets scanning
            - Complete security audit
        """
        pass

    def scan_file(self, file_path: str) -> List[ScanFinding]:
        """Scan a single file - override if scanner needs custom file handling"""
        return []

    def scan_live(self, url: str) -> ScanResult:
        """Scan a live URL/endpoint - override for network-capable scanners"""
        raise NotImplementedError(f"{self.NAME} does not support live scanning")

    # =========================================================================
    # HELPER METHODS
    # =========================================================================

    def find_package_json_files(
        self,
        root_path: str,
        recursive: bool = True,
        max_depth: int = 10
    ) -> Generator[Path, None, None]:
        """Find all package.json files in a directory tree"""
        root = Path(root_path)

        if not root.exists():
            return

        if not root.is_dir():
            if root.name == "package.json":
                yield root
            return

        def should_exclude(path: Path) -> bool:
            name = path.name
            return (
                name in self.EXCLUDE_DIRS or
                name in self.WINDOWS_SYSTEM_DIRS or
                name.startswith(".")
            )

        def walk_dir(current: Path, depth: int):
            if depth > max_depth:
                return

            try:
                for entry in current.iterdir():
                    if entry.is_file() and entry.name == "package.json":
                        yield entry
                    elif entry.is_dir() and recursive and not should_exclude(entry):
                        yield from walk_dir(entry, depth + 1)
            except PermissionError:
                pass
            except OSError:
                pass

        yield from walk_dir(root, 0)

    def find_lockfiles(self, directory: Path) -> Dict[str, Path]:
        """Find all lockfiles in a directory"""
        lockfiles = {}
        lockfile_names = [
            "package-lock.json",
            "yarn.lock",
            "pnpm-lock.yaml",
            "npm-shrinkwrap.json",
            "bun.lockb",
        ]

        for name in lockfile_names:
            lockfile = directory / name
            if lockfile.exists():
                lockfiles[name] = lockfile

        return lockfiles

    def parse_package_json(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a package.json file"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return None

    def parse_package_lock(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """Parse a package-lock.json file"""
        return self.parse_package_json(file_path)

    def parse_yarn_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse a yarn.lock file and extract package versions"""
        packages = {}

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()

            # Simple regex to extract package@version pairs
            # Handles formats like: "react@^19.0.0", react@19.0.0:
            pattern = r'^"?(@?[^@\s"]+)@[^":\s]+["\s]*:?\s*\n\s+version\s+"?([^"\s]+)"?'
            matches = re.findall(pattern, content, re.MULTILINE)

            for name, version in matches:
                packages[name] = version

        except IOError:
            pass

        return packages

    def parse_pnpm_lock(self, file_path: Path) -> Dict[str, str]:
        """Parse a pnpm-lock.yaml file"""
        packages = {}

        try:
            # Try to use PyYAML if available
            import yaml
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if data and 'packages' in data:
                for pkg_path, pkg_info in data['packages'].items():
                    # pnpm format: /package-name@version or /@scope/package@version
                    if '@' in pkg_path:
                        parts = pkg_path.rsplit('@', 1)
                        if len(parts) == 2:
                            name = parts[0].lstrip('/')
                            version = parts[1].split('(')[0]  # Remove peer deps
                            packages[name] = version

        except ImportError:
            # Fallback regex parsing without yaml library
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()

                pattern = r'/(@?[^@\s]+)@(\d+\.\d+\.\d+[^:\s]*)'
                matches = re.findall(pattern, content)
                for name, version in matches:
                    packages[name] = version.split('(')[0]
            except IOError:
                pass
        except Exception:
            pass

        return packages

    def extract_version(self, version_spec: str) -> str:
        """Extract clean version from a version specifier"""
        # Remove prefixes like ^, ~, >=, etc.
        clean = re.sub(r'^[\^~>=<\s]+', '', version_spec)
        # Take only the version part (not ranges)
        clean = clean.split()[0] if ' ' in clean else clean
        clean = clean.split('||')[0].strip() if '||' in clean else clean
        return clean

    def get_dependencies(self, package_data: Dict[str, Any]) -> Dict[str, str]:
        """Extract all dependencies from package.json"""
        deps = {}

        for key in ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']:
            if key in package_data and isinstance(package_data[key], dict):
                deps.update(package_data[key])

        return deps

    def check_package_vulnerability(
        self,
        package: str,
        version: str
    ) -> List[Vulnerability]:
        """Check if a package version is vulnerable"""
        return self.db.check_version(package, version)

    def create_finding(
        self,
        vuln: Vulnerability,
        package: str,
        version: str,
        file_path: str,
        detection_method: str = "lockfile"
    ) -> ScanFinding:
        """Create a ScanFinding from a Vulnerability"""
        patched = self.db.get_patched_version(package, version, vuln.cve_id)

        return ScanFinding(
            cve_id=vuln.cve_id,
            title=vuln.title,
            severity=FindingSeverity[vuln.severity.value],
            cvss_score=vuln.cvss_score,
            package=package,
            version=version,
            patched_version=patched,
            file_path=str(file_path),
            description=vuln.description,
            exploit_difficulty=vuln.exploit_difficulty.value,
            references=vuln.references,
            remediation=f"Upgrade {package} to {patched}" if patched else "Check vendor advisory",
            detection_method=detection_method,
        )

    def create_result(self, target: str, scan_type: str = "local") -> ScanResult:
        """Create a new ScanResult"""
        return ScanResult(
            scanner_name=self.NAME,
            scan_type=scan_type,
            target=target,
            start_time=datetime.now(),
        )

    def finalize_result(self, result: ScanResult) -> ScanResult:
        """Finalize a ScanResult with end time and stats"""
        result.end_time = datetime.now()
        result.stats = {
            "total_findings": result.total_findings,
            "critical": result.critical_count,
            "high": result.high_count,
        }
        return result
