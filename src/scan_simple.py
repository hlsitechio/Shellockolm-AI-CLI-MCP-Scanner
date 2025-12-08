#!/usr/bin/env python3
"""
Simple CVE-2025-55182 Scanner (Windows Compatible) - Dark Theme
Scans for vulnerable React and Next.js versions

🔍 Shellockolm - Elementary security for complex codebases
"""

import sys
import io
import json
from pathlib import Path
from scanner import CVEScanner

# Fix UTF-8 encoding for Windows console
if sys.platform == 'win32':
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding='utf-8')


# 🎨 DARK THEME ANSI COLORS (Windows Compatible)
class Colors:
    """ANSI color codes optimized for dark terminals"""
    # Bright colors for dark backgrounds
    DETECTIVE = '\033[1;93m'     # Bright Yellow Bold (Sherlock theme)
    TITLE = '\033[1;97m'         # Bright White Bold
    INFO = '\033[96m'            # Bright Cyan
    SUCCESS = '\033[92m'         # Bright Green
    WARNING = '\033[93m'         # Bright Yellow
    DANGER = '\033[1;91m'        # Bright Red Bold
    HIGHLIGHT = '\033[95m'       # Bright Magenta
    PATH = '\033[94m'            # Bright Blue
    COMMAND = '\033[3;92m'       # Bright Green Italic
    SUBTITLE = '\033[3;96m'      # Bright Cyan Italic
    RESET = '\033[0m'            # Reset
    BOLD = '\033[1m'             # Bold

# Enable colors on Windows
try:
    import colorama
    colorama.init()
except ImportError:
    pass


def print_banner():
    """Print Shellockolm banner"""
    print(f"{Colors.DETECTIVE}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.DETECTIVE}{'':^20}🔍 SHELLOCKOLM - SECURITY DETECTIVE{Colors.RESET}")
    print(f"{Colors.TITLE}{'':^15}CVE-2025-55182 & CVE-2025-66478 Scanner{Colors.RESET}")
    print(f"{Colors.DANGER}{'':^22}CVSS 10.0 CRITICAL{Colors.RESET}")
    print(f"{Colors.DETECTIVE}{'=' * 70}{Colors.RESET}")
    print(f"{Colors.SUBTITLE}{'':^15}Elementary security for complex codebases{Colors.RESET}\n")


def main():
    print_banner()

    # Get path from argument or use current directory
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "."

    print(f"{Colors.TITLE}🔍 Scanning:{Colors.RESET} {Colors.PATH}{Path(scan_path).resolve()}{Colors.RESET}")
    print(f"{Colors.WARNING}⏳ Please wait, this may take a few minutes...{Colors.RESET}\n")

    # Initialize scanner
    scanner = CVEScanner()

    # Perform scan
    print(f"{Colors.INFO}🔎 Investigating projects for vulnerabilities...{Colors.RESET}")
    results = scanner.scan_directory(scan_path, recursive=True)

    # Print summary
    summary = results['summary']
    print(f"\n{Colors.TITLE}{'═' * 70}{Colors.RESET}")
    print(f"{Colors.TITLE}═══ INVESTIGATION SUMMARY ═══{Colors.RESET}")
    print(f"{Colors.TITLE}{'═' * 70}{Colors.RESET}")
    print(f"  📂 Total projects scanned: {Colors.INFO}{summary['total_projects']}{Colors.RESET}")
    print(f"  ⚠️  Vulnerable projects:    {Colors.DANGER}{summary['vulnerable_projects']}{Colors.RESET}")
    print(f"  ✅ Safe projects:          {Colors.SUCCESS}{summary['safe_projects']}{Colors.RESET}")
    print()

    # Print vulnerable projects
    if results['vulnerable_projects']:
        print(f"{Colors.DANGER}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.DANGER}🚨 CRITICAL VULNERABILITIES DETECTED!{Colors.RESET}")
        print(f"{Colors.DANGER}{'=' * 70}{Colors.RESET}")
        print()

        for i, vp in enumerate(results['vulnerable_projects'], 1):
            print(f"{Colors.INFO}┌─ Case #{i}:{Colors.RESET} {Colors.PATH}{vp['path']}{Colors.RESET}")
            print(f"{Colors.INFO}│{Colors.RESET}  ⚠️  React Version:       {Colors.DANGER}{vp['react_version']}{Colors.RESET}")
            print(f"{Colors.INFO}│{Colors.RESET}  ✅ Recommended Version: {Colors.SUCCESS}{vp['recommended_version']}{Colors.RESET}")

            if vp['next_js_version']:
                status = f"{Colors.DANGER}{vp['next_js_version']} ⚠️{Colors.RESET}" if vp['next_js_vulnerable'] else f"{Colors.SUCCESS}{vp['next_js_version']}{Colors.RESET}"
                print(f"{Colors.INFO}│{Colors.RESET}  🌐 Next.js Version:     {status}")

            if vp['next_js_vulnerable'] and vp['next_js_recommended']:
                print(f"{Colors.INFO}│{Colors.RESET}  ✅ Next.js Recommended: {Colors.SUCCESS}{vp['next_js_recommended']}{Colors.RESET}")

            if vp['uses_server_components']:
                print(f"{Colors.INFO}│{Colors.RESET}  🔧 Server Components:   {Colors.HIGHLIGHT}✅ Detected{Colors.RESET}")

            if vp['vulnerable_packages']:
                print(f"{Colors.INFO}│{Colors.RESET}  📦 Vulnerable Packages: {Colors.WARNING}{', '.join(vp['vulnerable_packages'])}{Colors.RESET}")

            print(f"{Colors.INFO}└─{Colors.RESET}")
            print()

        # Print remediation
        print(f"{Colors.TITLE}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.TITLE}🔧 REMEDIATION STEPS{Colors.RESET}")
        print(f"{Colors.TITLE}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.SUBTITLE}Elementary fixes for detected vulnerabilities{Colors.RESET}\n")

        for i, vp in enumerate(results['vulnerable_projects'], 1):
            print(f"{Colors.INFO}┌─ Case #{i}: {vp['path']}{Colors.RESET}")
            print(f"{Colors.PATH}│  cd {vp['path']}{Colors.RESET}")
            print(f"{Colors.COMMAND}│  npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}{Colors.RESET}")

            if vp['next_js_vulnerable'] and vp['next_js_recommended']:
                print(f"{Colors.COMMAND}│  npm install next@{vp['next_js_recommended']}{Colors.RESET}")

            print(f"{Colors.COMMAND}│  npm run build{Colors.RESET}")
            print(f"{Colors.INFO}└─ ✓ Case resolved{Colors.RESET}\n")

        print(f"{Colors.DANGER}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.DANGER}⚠️  IMMEDIATE ACTION REQUIRED{Colors.RESET}")
        print(f"{Colors.DANGER}CVSS 10.0 RCE - ACTIVELY EXPLOITED{Colors.RESET}")
        print(f"{Colors.DANGER}{'=' * 70}{Colors.RESET}")

        # Save report
        report_path = Path("cve_2025_55182_scan_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\n{Colors.TITLE}📋 Detailed report saved to:{Colors.RESET} {Colors.PATH}{report_path.resolve()}{Colors.RESET}")

    else:
        print(f"{Colors.SUCCESS}{'=' * 70}{Colors.RESET}")
        print(f"{Colors.SUCCESS}🎉 ALL PROJECTS ARE SECURE!{Colors.RESET}")
        print(f"{Colors.SUCCESS}{'=' * 70}{Colors.RESET}")
        print(f"\n{Colors.SUCCESS}✅ Investigation complete: No vulnerable React versions detected.{Colors.RESET}")
        print(f"{Colors.SUCCESS}🛡️  Your projects are protected from CVE-2025-55182 & CVE-2025-66478.{Colors.RESET}\n")
        print(f"{Colors.SUBTITLE}Elementary, my dear developer!{Colors.RESET}")

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}⚠️  Investigation interrupted by user{Colors.RESET}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Colors.DANGER}❌ Error:{Colors.RESET} {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
