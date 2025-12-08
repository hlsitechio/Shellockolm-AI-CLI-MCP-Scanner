#!/usr/bin/env python3
"""
Quick CLI tool to scan for CVE-2025-55182 vulnerabilities
Usage: python scan.py [path]

🔍 Shellockolm - Dark Theme Edition
"""

import sys
import io
import json
from pathlib import Path
from scanner import CVEScanner
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.theme import Theme

# Fix UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')

# 🎨 DARK THEME CONFIGURATION
dark_theme = Theme({
    "info": "bright_cyan",
    "warning": "bright_yellow",
    "danger": "bright_red bold",
    "success": "bright_green",
    "highlight": "bright_magenta",
    "path": "bright_blue",
    "command": "bright_green italic",
    "title": "bold bright_white",
    "subtitle": "bright_cyan italic",
    "detective": "bright_yellow bold"  # Sherlock theme!
})

console = Console(theme=dark_theme)


def print_banner():
    """Print Shellockolm banner with dark theme"""
    banner = """
╔═══════════════════════════════════════════════════════════╗
║          🔍 SHELLOCKOLM - SECURITY DETECTIVE              ║
║        CVE-2025-55182 & CVE-2025-66478 Scanner           ║
║                    CVSS 10.0 CRITICAL                     ║
╚═══════════════════════════════════════════════════════════╝
"""
    console.print(banner, style="detective")
    console.print("[subtitle]Elementary security for complex codebases[/subtitle]\n")


def main():
    print_banner()

    # Get path from argument or use current directory
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "."

    console.print(f"[title]Scanning:[/title] [path]{Path(scan_path).resolve()}[/path]")
    console.print("[warning]This may take a few minutes for large directories...[/warning]\n")

    # Initialize scanner
    scanner = CVEScanner()

    # Perform scan with detective theme
    with console.status("[success]🔍 Investigating projects for vulnerabilities..."):
        results = scanner.scan_directory(scan_path, recursive=True)

    # Print summary
    summary = results['summary']
    console.print("\n[title]═══ INVESTIGATION SUMMARY ═══[/title]")
    console.print(f"  📂 Total projects scanned: [info]{summary['total_projects']}[/info]")
    console.print(f"  ⚠️  Vulnerable projects:    [danger]{summary['vulnerable_projects']}[/danger]")
    console.print(f"  ✅ Safe projects:          [success]{summary['safe_projects']}[/success]\n")

    # Print vulnerable projects in a table
    if results['vulnerable_projects']:
        console.print("[danger]🚨 CRITICAL VULNERABILITIES DETECTED![/danger]\n")

        table = Table(
            title="🔍 Vulnerable Projects Detected",
            box=box.DOUBLE_EDGE,
            border_style="bright_red"
        )
        table.add_column("📁 Path", style="path", no_wrap=False)
        table.add_column("⚠️ React Version", style="danger")
        table.add_column("✅ Fix Version", style="success")
        table.add_column("🌐 Next.js", style="warning")
        table.add_column("🔧 Server Components", style="highlight")

        for vp in results['vulnerable_projects']:
            next_js_status = vp['next_js_version'] or "N/A"
            if vp['next_js_vulnerable']:
                next_js_status += " ⚠️"

            table.add_row(
                vp['path'],
                vp['react_version'],
                vp['recommended_version'],
                next_js_status,
                "✅ Yes" if vp['uses_server_components'] else "❌ No"
            )

        console.print(table)
        console.print()

        # Print remediation steps
        console.print("[title]🔧 REMEDIATION STEPS:[/title]")
        console.print("[subtitle]Elementary fixes for detected vulnerabilities[/subtitle]\n")

        for i, vp in enumerate(results['vulnerable_projects'], 1):
            console.print(f"[info]┌─ Case #{i}: {vp['path']}[/info]")
            console.print(f"[path]│  cd {vp['path']}[/path]")
            console.print(f"[command]│  npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}[/command]")

            # Show Next.js fix if needed
            if vp['next_js_vulnerable'] and vp['next_js_recommended']:
                console.print(f"[command]│  npm install next@{vp['next_js_recommended']}[/command]")

            console.print(f"[command]│  npm run build[/command]")
            console.print(f"[info]└─ ✓ Case resolved[/info]\n")

        console.print()
        console.print("[danger]⚠️  IMMEDIATE ACTION REQUIRED - CVSS 10.0 RCE VULNERABILITY[/danger]")

        # Save detailed report
        report_path = Path("cve_2025_55182_scan_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"\n[title]📋 Detailed report saved to:[/title] [path]{report_path.resolve()}[/path]")

    else:
        console.print(Panel(
            "[success]✅ All projects are secure![/success]\n\n"
            "🔍 Investigation complete: No vulnerable React versions detected.\n"
            "🛡️  Your projects are protected from CVE-2025-55182 & CVE-2025-66478.\n\n"
            "[subtitle]Elementary, my dear developer![/subtitle]",
            title="🎉 Security Status: SAFE",
            border_style="bright_green",
            box=box.DOUBLE
        ))

    console.print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[warning]⚠️  Investigation interrupted by user[/warning]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[danger]❌ Error:[/danger] {e}")
        sys.exit(1)
