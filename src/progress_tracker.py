#!/usr/bin/env python3
"""
Progress Tracker for Shellockolm
Real-time scan progress dashboard with live updates
"""

import time
import threading
from pathlib import Path
from typing import Dict, List, Optional, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import (
        Progress,
        SpinnerColumn,
        TextColumn,
        BarColumn,
        TaskProgressColumn,
        TimeElapsedColumn,
        TimeRemainingColumn
    )
    from rich.table import Table
    from rich.live import Live
    from rich.layout import Layout
    from rich import box
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    raise


class ScanPhase(Enum):
    """Phases of scanning"""
    INIT = "Initializing"
    DISCOVERY = "Discovering files"
    SCANNING = "Scanning for CVEs"
    ANALYZING = "Analyzing results"
    COMPLETE = "Complete"


@dataclass
class ScanStats:
    """Statistics for current scan"""
    total_files: int = 0
    scanned_files: int = 0
    total_packages: int = 0
    checked_packages: int = 0
    vulnerabilities_found: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    start_time: float = field(default_factory=time.time)
    current_file: str = ""
    current_scanner: str = ""
    current_cve: str = ""
    phase: ScanPhase = ScanPhase.INIT


class ProgressTracker:
    """
    Real-time progress tracker with live dashboard
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.stats = ScanStats()
        self._lock = threading.Lock()
        self._live: Optional[Live] = None
        self._progress: Optional[Progress] = None
        self._task_id = None
        self._active = False

    def _generate_dashboard(self) -> Panel:
        """Generate the progress dashboard display"""
        with self._lock:
            elapsed = time.time() - self.stats.start_time

            # Progress bar section
            if self.stats.total_files > 0:
                pct = (self.stats.scanned_files / self.stats.total_files) * 100
            else:
                pct = 0

            bar_width = 40
            filled = int(bar_width * pct / 100)
            bar = "█" * filled + "░" * (bar_width - filled)

            # Build dashboard content
            lines = [
                f"[bold bright_cyan]🔍 {self.stats.phase.value}[/bold bright_cyan]",
                "",
                f"Progress: [{bar}] {pct:.1f}%",
                f"Files:    {self.stats.scanned_files}/{self.stats.total_files}",
                f"Packages: {self.stats.checked_packages} checked",
                "",
            ]

            # Vulnerability counts with colors
            if self.stats.vulnerabilities_found > 0:
                vuln_line = f"Found:    [bold]{self.stats.vulnerabilities_found}[/bold] vulnerabilities ("
                parts = []
                if self.stats.critical_count > 0:
                    parts.append(f"[bright_red]{self.stats.critical_count} critical[/bright_red]")
                if self.stats.high_count > 0:
                    parts.append(f"[red]{self.stats.high_count} high[/red]")
                if self.stats.medium_count > 0:
                    parts.append(f"[yellow]{self.stats.medium_count} medium[/yellow]")
                if self.stats.low_count > 0:
                    parts.append(f"[blue]{self.stats.low_count} low[/blue]")
                vuln_line += ", ".join(parts) + ")"
                lines.append(vuln_line)
            else:
                lines.append(f"Found:    [dim]0 vulnerabilities[/dim]")

            lines.append(f"Time:     {elapsed:.1f}s elapsed")
            lines.append("")

            # Current activity
            if self.stats.current_scanner:
                lines.append(f"[dim]Scanner: {self.stats.current_scanner}[/dim]")
            if self.stats.current_cve:
                lines.append(f"[dim]Checking: {self.stats.current_cve}[/dim]")
            if self.stats.current_file:
                # Truncate long paths
                file_display = self.stats.current_file
                if len(file_display) > 50:
                    file_display = "..." + file_display[-47:]
                lines.append(f"[dim]File: {file_display}[/dim]")

            content = "\n".join(lines)

            # Determine border color based on findings
            if self.stats.critical_count > 0:
                border_style = "bright_red"
            elif self.stats.vulnerabilities_found > 0:
                border_style = "yellow"
            else:
                border_style = "bright_cyan"

            return Panel(
                content,
                title="[bold]Scan Progress[/bold]",
                border_style=border_style,
                box=box.ROUNDED
            )

    def start(self, total_files: int = 0):
        """Start the progress tracker"""
        self.stats = ScanStats()
        self.stats.total_files = total_files
        self.stats.phase = ScanPhase.DISCOVERY
        self._active = True

        # Start live display
        self._live = Live(
            self._generate_dashboard(),
            console=self.console,
            refresh_per_second=4,
            transient=True
        )
        self._live.start()

    def stop(self):
        """Stop the progress tracker"""
        self._active = False
        self.stats.phase = ScanPhase.COMPLETE

        if self._live:
            self._live.update(self._generate_dashboard())
            self._live.stop()
            self._live = None

    def update(
        self,
        scanned_files: Optional[int] = None,
        total_files: Optional[int] = None,
        checked_packages: Optional[int] = None,
        current_file: Optional[str] = None,
        current_scanner: Optional[str] = None,
        current_cve: Optional[str] = None,
        phase: Optional[ScanPhase] = None
    ):
        """Update progress stats"""
        with self._lock:
            if scanned_files is not None:
                self.stats.scanned_files = scanned_files
            if total_files is not None:
                self.stats.total_files = total_files
            if checked_packages is not None:
                self.stats.checked_packages = checked_packages
            if current_file is not None:
                self.stats.current_file = current_file
            if current_scanner is not None:
                self.stats.current_scanner = current_scanner
            if current_cve is not None:
                self.stats.current_cve = current_cve
            if phase is not None:
                self.stats.phase = phase

        if self._live:
            self._live.update(self._generate_dashboard())

    def add_finding(self, severity: str):
        """Record a vulnerability finding"""
        with self._lock:
            self.stats.vulnerabilities_found += 1
            severity_lower = severity.lower()
            if severity_lower == "critical":
                self.stats.critical_count += 1
            elif severity_lower == "high":
                self.stats.high_count += 1
            elif severity_lower == "medium":
                self.stats.medium_count += 1
            else:
                self.stats.low_count += 1

        if self._live:
            self._live.update(self._generate_dashboard())

    def increment_files(self):
        """Increment scanned files count"""
        with self._lock:
            self.stats.scanned_files += 1
        if self._live:
            self._live.update(self._generate_dashboard())

    def increment_packages(self):
        """Increment checked packages count"""
        with self._lock:
            self.stats.checked_packages += 1
        if self._live:
            self._live.update(self._generate_dashboard())

    def get_summary(self) -> Dict[str, Any]:
        """Get final scan summary"""
        elapsed = time.time() - self.stats.start_time
        return {
            "total_files": self.stats.total_files,
            "scanned_files": self.stats.scanned_files,
            "packages_checked": self.stats.checked_packages,
            "vulnerabilities": self.stats.vulnerabilities_found,
            "critical": self.stats.critical_count,
            "high": self.stats.high_count,
            "medium": self.stats.medium_count,
            "low": self.stats.low_count,
            "elapsed_seconds": elapsed,
        }


class VerboseDetectionLog:
    """
    Verbose detection logging - shows HOW each CVE is detected
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.detections: List[Dict] = []

    def log_check(
        self,
        file_path: str,
        package: str,
        version: str,
        cve_id: str,
        check_type: str,
        result: bool,
        details: str = ""
    ):
        """Log a detection check"""
        detection = {
            "file": file_path,
            "package": package,
            "version": version,
            "cve": cve_id,
            "check": check_type,
            "vulnerable": result,
            "details": details,
            "timestamp": datetime.now()
        }
        self.detections.append(detection)

        # Display verbose output
        file_display = Path(file_path).name

        self.console.print(f"[SCAN] {file_display}")
        self.console.print(f"  ├─ Found: {package}@{version}")
        self.console.print(f"  ├─ Checking: {cve_id} ({check_type})")

        if result:
            self.console.print(f"  │   ├─ {details}")
            self.console.print(f"  │   └─ [bold bright_red]VULNERABLE[/bold bright_red]: Pattern matched")
        else:
            self.console.print(f"  │   └─ [green]NOT VULNERABLE[/green]: {details}")

    def log_version_check(
        self,
        file_path: str,
        package: str,
        found_version: str,
        vulnerable_range: str,
        cve_id: str,
        is_vulnerable: bool
    ):
        """Log a version range check"""
        check_symbol = "✓" if is_vulnerable else "✗"

        self.console.print(f"  ├─ Checking: {cve_id}")
        self.console.print(f"  │   ├─ Version {found_version} in range [{vulnerable_range}] {check_symbol}")

        if is_vulnerable:
            self.console.print(f"  │   └─ [bold bright_red]VULNERABLE[/bold bright_red]")
        else:
            self.console.print(f"  │   └─ [green]Safe[/green]")

    def get_summary(self) -> Dict:
        """Get detection summary"""
        vulnerable = [d for d in self.detections if d["vulnerable"]]
        return {
            "total_checks": len(self.detections),
            "vulnerable_findings": len(vulnerable),
            "detections": self.detections
        }


class DetectionExplainer:
    """
    Explains WHY something is vulnerable, WHAT an attacker can do,
    and HOW we detected it
    """

    # CVE explanations database
    CVE_EXPLANATIONS = {
        "CVE-2025-29927": {
            "why": "Next.js middleware can be bypassed using the x-middleware-subrequest header. Internal implementation headers are not stripped from external requests.",
            "what": "Attacker can bypass authentication, authorization, and security middleware. Access protected routes, bypass rate limiting, skip CSRF checks.",
            "how": "We check: 1) Next.js version in vulnerable range (11.1.4-14.2.24), 2) Presence of middleware.ts/js files, 3) Auth patterns in middleware code.",
            "affected": "next",
            "versions": "11.1.4 - 14.2.24, 15.0.0 - 15.2.2"
        },
        "CVE-2025-55182": {
            "why": "Next.js Image component improperly handles certain image URLs, allowing cache poisoning through URL manipulation.",
            "what": "Attacker can poison CDN/browser cache with malicious content, potentially serving XSS payloads or redirecting users.",
            "how": "We check: 1) Next.js version in range, 2) Use of next/image component, 3) External image domains in config.",
            "affected": "next",
            "versions": "14.0.0 - 14.2.24"
        },
        "CVE-2024-34351": {
            "why": "Server Actions in Next.js allow SSRF through Host header manipulation in redirects.",
            "what": "Attacker can access internal services, read sensitive data, perform internal port scans.",
            "how": "We check: 1) Next.js version, 2) Server Actions usage (use server directive), 3) Redirect patterns.",
            "affected": "next",
            "versions": "13.4.0 - 14.1.0"
        },
        "CVE-2024-47831": {
            "why": "Image optimization endpoint in Next.js is vulnerable to DoS through malformed image requests.",
            "what": "Attacker can cause server resource exhaustion, crash Node.js process, denial of service.",
            "how": "We check: 1) Next.js version, 2) Image optimization config, 3) External image sources allowed.",
            "affected": "next",
            "versions": "10.0.0 - 14.2.6"
        },
    }

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()

    def explain(self, cve_id: str, finding_context: Optional[Dict] = None):
        """Provide detailed explanation for a CVE finding"""
        explanation = self.CVE_EXPLANATIONS.get(cve_id, {})

        if not explanation:
            self.console.print(f"\n[dim]No detailed explanation available for {cve_id}[/dim]")
            return

        # Build explanation panel
        content = []

        # WHY vulnerable
        content.append("[bold bright_red]WHY VULNERABLE:[/bold bright_red]")
        content.append(f"  {explanation.get('why', 'Unknown')}")
        content.append("")

        # WHAT attacker can do
        content.append("[bold yellow]WHAT ATTACKER CAN DO:[/bold yellow]")
        content.append(f"  {explanation.get('what', 'Unknown')}")
        content.append("")

        # HOW we detected it
        content.append("[bold bright_cyan]HOW WE DETECTED IT:[/bold bright_cyan]")
        content.append(f"  {explanation.get('how', 'Unknown')}")
        content.append("")

        # Affected versions
        content.append("[bold]AFFECTED VERSIONS:[/bold]")
        content.append(f"  Package: {explanation.get('affected', 'Unknown')}")
        content.append(f"  Versions: {explanation.get('versions', 'Unknown')}")

        # Finding context if provided
        if finding_context:
            content.append("")
            content.append("[bold]YOUR FINDING:[/bold]")
            content.append(f"  File: {finding_context.get('file', 'N/A')}")
            content.append(f"  Version: {finding_context.get('version', 'N/A')}")

        self.console.print(Panel(
            "\n".join(content),
            title=f"[bold]{cve_id} Explained[/bold]",
            border_style="bright_red",
            box=box.DOUBLE
        ))

    def get_explanation(self, cve_id: str) -> Optional[Dict]:
        """Get explanation data for a CVE"""
        return self.CVE_EXPLANATIONS.get(cve_id)

    def has_explanation(self, cve_id: str) -> bool:
        """Check if we have explanation for a CVE"""
        return cve_id in self.CVE_EXPLANATIONS


# Convenience functions
def create_progress_tracker(console: Optional[Console] = None) -> ProgressTracker:
    """Create a new progress tracker"""
    return ProgressTracker(console)


def create_verbose_log(console: Optional[Console] = None) -> VerboseDetectionLog:
    """Create a verbose detection logger"""
    return VerboseDetectionLog(console)


def create_explainer(console: Optional[Console] = None) -> DetectionExplainer:
    """Create a detection explainer"""
    return DetectionExplainer(console)


# Test when run directly
if __name__ == "__main__":
    import time

    console = Console()

    # Test progress tracker
    console.print("\n[bold]Testing Progress Tracker...[/bold]\n")

    tracker = ProgressTracker(console)
    tracker.start(total_files=100)

    for i in range(100):
        tracker.update(
            scanned_files=i+1,
            current_file=f"/path/to/file_{i}.js",
            current_scanner="Next.js Scanner",
            current_cve=f"CVE-2025-{29927 + (i % 5)}"
        )
        if i % 20 == 0:
            tracker.add_finding("critical" if i < 40 else "high")
        tracker.increment_packages()
        time.sleep(0.05)

    tracker.stop()

    # Print summary
    summary = tracker.get_summary()
    console.print(f"\n[bold]Summary:[/bold] {summary}")

    # Test explainer
    console.print("\n[bold]Testing Detection Explainer...[/bold]\n")

    explainer = DetectionExplainer(console)
    explainer.explain("CVE-2025-29927", {
        "file": "/app/middleware.ts",
        "version": "14.1.0"
    })
