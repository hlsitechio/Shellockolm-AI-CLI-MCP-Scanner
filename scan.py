#!/usr/bin/env python3
"""
Quick CLI tool to scan for CVE-2025-55182 vulnerabilities
Usage: python scan.py [path]
"""

import sys
import json
from pathlib import Path
from scanner import CVEScanner
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()


def print_banner():
    """Print banner"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║           CVE-2025-55182 VULNERABILITY SCANNER            ║
║        React Server Components RCE Detection Tool         ║
║                    CVSS 10.0 CRITICAL                     ║
╚═══════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="bold red")


def main():
    print_banner()

    # Get path from argument or use current directory
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "."

    console.print(f"\n[bold cyan]Scanning:[/bold cyan] {Path(scan_path).resolve()}")
    console.print("[yellow]This may take a few minutes for large directories...[/yellow]\n")

    # Initialize scanner
    scanner = CVEScanner()

    # Perform scan
    with console.status("[bold green]Scanning projects..."):
        results = scanner.scan_directory(scan_path, recursive=True)

    # Print summary
    summary = results['summary']
    console.print("\n[bold]SCAN SUMMARY[/bold]")
    console.print(f"  Total projects scanned: [cyan]{summary['total_projects']}[/cyan]")
    console.print(f"  Vulnerable projects:    [red]{summary['vulnerable_projects']}[/red]")
    console.print(f"  Safe projects:          [green]{summary['safe_projects']}[/green]\n")

    # Print vulnerable projects in a table
    if results['vulnerable_projects']:
        console.print("[bold red]⚠️  CRITICAL VULNERABILITIES DETECTED![/bold red]\n")

        table = Table(title="Vulnerable Projects", box=box.ROUNDED)
        table.add_column("Path", style="cyan", no_wrap=False)
        table.add_column("React Version", style="red")
        table.add_column("Fix Version", style="green")
        table.add_column("Next.js", style="yellow")
        table.add_column("Server Components", style="magenta")

        for vp in results['vulnerable_projects']:
            table.add_row(
                vp['path'],
                vp['react_version'],
                vp['recommended_version'],
                vp['next_js_version'] or "N/A",
                "✓" if vp['uses_server_components'] else "✗"
            )

        console.print(table)
        console.print()

        # Print remediation steps
        console.print("[bold]REMEDIATION STEPS:[/bold]")
        for i, vp in enumerate(results['vulnerable_projects'], 1):
            console.print(f"\n[bold cyan]{i}. {vp['path']}[/bold cyan]")
            console.print(f"   [yellow]cd {vp['path']}[/yellow]")
            console.print(f"   [green]npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}[/green]")
            console.print(f"   [green]npm run build[/green]")

        console.print()
        console.print("[bold red]⚠️  IMMEDIATE ACTION REQUIRED - CVSS 10.0 RCE VULNERABILITY[/bold red]")

        # Save detailed report
        report_path = Path("cve_2025_55182_scan_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[bold]Detailed report saved to:[/bold] {report_path.resolve()}")

    else:
        console.print(Panel(
            "[bold green]✓ All projects are safe![/bold green]\n\n"
            "No vulnerable React versions detected.\n"
            "Your projects are not affected by CVE-2025-55182.",
            title="Security Status",
            border_style="green"
        ))

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[bold red]Error:[/bold red] {e}")
        sys.exit(1)
