#!/usr/bin/env python3
"""
Watch Mode for Shellockolm
Monitors file changes and triggers automatic security scans
"""

import os
import sys
import time
import hashlib
import threading
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.live import Live
    from rich.table import Table
    from rich.text import Text
    from rich import box
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    raise


class WatchEvent(Enum):
    """Types of file system events"""
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"


@dataclass
class FileChange:
    """Represents a file change event"""
    path: str
    event: WatchEvent
    timestamp: datetime
    hash: Optional[str] = None


@dataclass
class WatchConfig:
    """Configuration for watch mode"""
    # Paths to watch
    include_patterns: List[str] = field(default_factory=lambda: [
        "*.js", "*.ts", "*.jsx", "*.tsx",
        "*.json", "*.mjs", "*.cjs",
        "package.json", "package-lock.json", "yarn.lock"
    ])
    # Paths to ignore
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "node_modules/*", ".git/*", "dist/*", "build/*",
        "coverage/*", "*.min.js", "*.map"
    ])
    # Debounce time in seconds
    debounce_seconds: float = 2.0
    # Maximum events before forced scan
    max_pending_events: int = 10
    # Scan on start
    scan_on_start: bool = True
    # Clear screen between scans
    clear_screen: bool = False
    # Show desktop notifications
    notifications: bool = False


class FileWatcher:
    """
    Simple file watcher using polling (no external dependencies)
    """

    def __init__(
        self,
        root_path: str,
        config: WatchConfig,
        on_change: Callable[[List[FileChange]], None]
    ):
        self.root_path = Path(root_path).resolve()
        self.config = config
        self.on_change = on_change
        self._running = False
        self._file_hashes: Dict[str, str] = {}
        self._pending_changes: List[FileChange] = []
        self._last_scan_time: float = 0
        self._lock = threading.Lock()

    def _should_watch(self, path: Path) -> bool:
        """Check if path should be watched based on patterns"""
        rel_path = str(path.relative_to(self.root_path))

        # Check excludes first
        for pattern in self.config.exclude_patterns:
            if self._matches_pattern(rel_path, pattern):
                return False

        # Check includes
        for pattern in self.config.include_patterns:
            if self._matches_pattern(rel_path, pattern):
                return True

        return False

    def _matches_pattern(self, path: str, pattern: str) -> bool:
        """Simple glob-like pattern matching"""
        import fnmatch
        return fnmatch.fnmatch(path, pattern) or fnmatch.fnmatch(os.path.basename(path), pattern)

    def _get_file_hash(self, path: Path) -> Optional[str]:
        """Calculate file hash for change detection"""
        try:
            with open(path, "rb") as f:
                return hashlib.md5(f.read()).hexdigest()
        except (IOError, PermissionError):
            return None

    def _scan_directory(self) -> Dict[str, str]:
        """Scan directory and return file hashes"""
        hashes = {}

        for root, dirs, files in os.walk(self.root_path):
            # Skip ignored directories
            dirs[:] = [d for d in dirs if not any(
                self._matches_pattern(d, p) for p in self.config.exclude_patterns
            )]

            for file in files:
                path = Path(root) / file
                if self._should_watch(path):
                    file_hash = self._get_file_hash(path)
                    if file_hash:
                        hashes[str(path)] = file_hash

        return hashes

    def _detect_changes(self) -> List[FileChange]:
        """Detect file changes since last scan"""
        changes = []
        current_hashes = self._scan_directory()

        # Check for new and modified files
        for path, hash_val in current_hashes.items():
            if path not in self._file_hashes:
                changes.append(FileChange(
                    path=path,
                    event=WatchEvent.CREATED,
                    timestamp=datetime.now(),
                    hash=hash_val
                ))
            elif self._file_hashes[path] != hash_val:
                changes.append(FileChange(
                    path=path,
                    event=WatchEvent.MODIFIED,
                    timestamp=datetime.now(),
                    hash=hash_val
                ))

        # Check for deleted files
        for path in self._file_hashes:
            if path not in current_hashes:
                changes.append(FileChange(
                    path=path,
                    event=WatchEvent.DELETED,
                    timestamp=datetime.now()
                ))

        # Update stored hashes
        self._file_hashes = current_hashes

        return changes

    def start(self, poll_interval: float = 1.0):
        """Start watching for changes"""
        self._running = True
        self._file_hashes = self._scan_directory()

        while self._running:
            time.sleep(poll_interval)

            changes = self._detect_changes()
            if changes:
                with self._lock:
                    self._pending_changes.extend(changes)

                # Check if we should trigger scan
                current_time = time.time()
                time_since_last = current_time - self._last_scan_time

                should_scan = (
                    time_since_last >= self.config.debounce_seconds or
                    len(self._pending_changes) >= self.config.max_pending_events
                )

                if should_scan:
                    with self._lock:
                        if self._pending_changes:
                            self.on_change(self._pending_changes.copy())
                            self._pending_changes.clear()
                            self._last_scan_time = current_time

    def stop(self):
        """Stop watching"""
        self._running = False


class WatchMode:
    """
    Interactive watch mode for continuous security scanning
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.config = WatchConfig()
        self.watcher: Optional[FileWatcher] = None
        self._scan_count = 0
        self._last_findings: List[Dict] = []
        self._last_scan_time: Optional[datetime] = None
        self._watch_thread: Optional[threading.Thread] = None

    def _on_changes_detected(self, changes: List[FileChange]):
        """Callback when file changes are detected"""
        # Group changes by type
        created = [c for c in changes if c.event == WatchEvent.CREATED]
        modified = [c for c in changes if c.event == WatchEvent.MODIFIED]
        deleted = [c for c in changes if c.event == WatchEvent.DELETED]

        self.console.print()
        self.console.print(Panel(
            f"[bold]Detected {len(changes)} changes[/bold]\n"
            f"  Created: {len(created)}\n"
            f"  Modified: {len(modified)}\n"
            f"  Deleted: {len(deleted)}",
            title="File Changes",
            border_style="bright_yellow"
        ))

        # Show changed files (limited)
        if len(changes) <= 5:
            for change in changes:
                icon = {"created": "➕", "modified": "📝", "deleted": "❌"}
                self.console.print(f"  {icon.get(change.event.value, '•')} {Path(change.path).name}")

        # Trigger scan
        self._run_scan()

    def _run_scan(self):
        """Run security scan"""
        self._scan_count += 1
        self._last_scan_time = datetime.now()

        if self.config.clear_screen:
            self.console.clear()

        self.console.print()
        self.console.print(Panel(
            f"[bold bright_cyan]Running security scan #{self._scan_count}[/bold bright_cyan]",
            border_style="bright_cyan"
        ))

        # Import and run scanner
        try:
            from scanners import get_all_scanners, ScanResult

            findings = []
            for scanner in get_all_scanners():
                try:
                    result = scanner.scan_directory(str(self.watcher.root_path), quick_mode=True)
                    if result and result.findings:
                        for finding in result.findings:
                            findings.append({
                                "scanner": scanner.NAME,
                                "cve": finding.cve_id,
                                "severity": finding.severity.value,
                                "file": finding.file_path,
                                "line": getattr(finding, "line_number", 0),
                                "message": finding.description
                            })
                except Exception as e:
                    self.console.print(f"[dim]Scanner {scanner.NAME} error: {e}[/dim]")

            self._last_findings = findings

            # Display results
            self._display_results(findings)

        except ImportError as e:
            self.console.print(f"[danger]Error importing scanners: {e}[/danger]")
        except Exception as e:
            self.console.print(f"[danger]Scan error: {e}[/danger]")

    def _display_results(self, findings: List[Dict]):
        """Display scan results"""
        if not findings:
            self.console.print(Panel(
                "[bold bright_green]✅ No vulnerabilities found![/bold bright_green]",
                border_style="bright_green"
            ))
            return

        # Count by severity
        severity_counts = {}
        for f in findings:
            sev = f.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        # Create summary table
        table = Table(
            title=f"[bold]Found {len(findings)} Issues[/bold]",
            box=box.ROUNDED,
            border_style="bright_red" if severity_counts.get("critical", 0) > 0 else "bright_yellow"
        )
        table.add_column("Severity", style="bold")
        table.add_column("Count", justify="right")

        severity_order = ["critical", "high", "medium", "low", "info"]
        severity_colors = {
            "critical": "bright_red",
            "high": "red",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }

        for sev in severity_order:
            count = severity_counts.get(sev, 0)
            if count > 0:
                color = severity_colors.get(sev, "white")
                table.add_row(f"[{color}]{sev.upper()}[/{color}]", str(count))

        self.console.print(table)

        # Show top findings
        if len(findings) <= 5:
            self.console.print("\n[subtitle]Findings:[/subtitle]")
            for f in findings:
                sev_color = severity_colors.get(f.get("severity", ""), "white")
                self.console.print(f"  [{sev_color}]{f.get('cve', 'N/A')}[/{sev_color}] - {f.get('message', '')[:50]}")
                self.console.print(f"    [dim]{f.get('file', 'N/A')}:{f.get('line', 'N/A')}[/dim]")

        # Desktop notification
        if self.config.notifications:
            self._send_notification(len(findings), severity_counts)

    def _send_notification(self, count: int, severity_counts: Dict):
        """Send desktop notification (platform-specific)"""
        try:
            critical = severity_counts.get("critical", 0)
            high = severity_counts.get("high", 0)

            title = "Shellockolm Security Alert"
            if critical > 0:
                message = f"🚨 {critical} critical vulnerabilities found!"
            elif high > 0:
                message = f"⚠️ {high} high severity issues found!"
            else:
                message = f"Found {count} security issues"

            # Try different notification methods
            if sys.platform == "darwin":
                os.system(f'osascript -e \'display notification "{message}" with title "{title}"\'')
            elif sys.platform == "linux":
                os.system(f'notify-send "{title}" "{message}"')
        except Exception:
            pass  # Notifications are optional

    def start(
        self,
        root_path: str,
        scan_on_start: bool = True,
        clear_screen: bool = False,
        notifications: bool = False
    ):
        """Start watch mode"""
        self.config.scan_on_start = scan_on_start
        self.config.clear_screen = clear_screen
        self.config.notifications = notifications

        root = Path(root_path).resolve()

        # Display header
        self.console.print(Panel(
            f"[bold bright_cyan]Watch Mode Active[/bold bright_cyan]\n\n"
            f"Monitoring: [bright_white]{root}[/bright_white]\n"
            f"Patterns: [dim]{', '.join(self.config.include_patterns[:5])}...[/dim]\n\n"
            f"[dim]Press Ctrl+C to stop[/dim]",
            title="🔍 Shellockolm Watch Mode",
            border_style="bright_cyan"
        ))

        # Create watcher
        self.watcher = FileWatcher(
            root_path=str(root),
            config=self.config,
            on_change=self._on_changes_detected
        )

        # Initial scan
        if scan_on_start:
            self.console.print("\n[info]Running initial scan...[/info]")
            self._run_scan()

        # Start watching in background
        try:
            self.console.print("\n[info]Watching for changes...[/info]\n")
            self.watcher.start()
        except KeyboardInterrupt:
            self.stop()

    def stop(self):
        """Stop watch mode"""
        if self.watcher:
            self.watcher.stop()

        self.console.print()
        self.console.print(Panel(
            f"[bold]Watch mode stopped[/bold]\n\n"
            f"Total scans: {self._scan_count}\n"
            f"Last scan: {self._last_scan_time.strftime('%H:%M:%S') if self._last_scan_time else 'N/A'}\n"
            f"Last findings: {len(self._last_findings)}",
            title="Session Summary",
            border_style="bright_cyan"
        ))

    def get_status(self) -> Dict[str, Any]:
        """Get current watch status"""
        return {
            "running": self.watcher._running if self.watcher else False,
            "scan_count": self._scan_count,
            "last_scan_time": self._last_scan_time,
            "last_findings_count": len(self._last_findings),
            "watched_files": len(self.watcher._file_hashes) if self.watcher else 0
        }


def start_watch_mode(root_path: str, **kwargs):
    """Helper function to start watch mode"""
    console = Console()
    watch = WatchMode(console)
    watch.start(root_path, **kwargs)


# CLI interface for standalone testing
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Shellockolm Watch Mode")
    parser.add_argument("path", nargs="?", default=".", help="Path to watch")
    parser.add_argument("--no-initial", action="store_true", help="Skip initial scan")
    parser.add_argument("--clear", action="store_true", help="Clear screen between scans")
    parser.add_argument("--notify", action="store_true", help="Enable desktop notifications")

    args = parser.parse_args()

    start_watch_mode(
        args.path,
        scan_on_start=not args.no_initial,
        clear_screen=args.clear,
        notifications=args.notify
    )
