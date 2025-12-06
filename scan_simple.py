#!/usr/bin/env python3
"""
Simple CVE-2025-55182 Scanner (Windows Compatible)
Scans for vulnerable React and Next.js versions
"""

import sys
import json
from pathlib import Path
from scanner import CVEScanner


def main():
    print("=" * 70)
    print("CVE-2025-55182 VULNERABILITY SCANNER")
    print("React Server Components RCE Detection Tool")
    print("CVSS 10.0 CRITICAL - ACTIVELY EXPLOITED")
    print("=" * 70)

    # Get path from argument or use current directory
    if len(sys.argv) > 1:
        scan_path = sys.argv[1]
    else:
        scan_path = "."

    print(f"\nScanning: {Path(scan_path).resolve()}")
    print("Please wait, this may take a few minutes...\n")

    # Initialize scanner
    scanner = CVEScanner()

    # Perform scan
    print("Scanning projects...")
    results = scanner.scan_directory(scan_path, recursive=True)

    # Print summary
    summary = results['summary']
    print("\n" + "=" * 70)
    print("SCAN SUMMARY")
    print("=" * 70)
    print(f"Total projects scanned: {summary['total_projects']}")
    print(f"Vulnerable projects:    {summary['vulnerable_projects']}")
    print(f"Safe projects:          {summary['safe_projects']}")
    print()

    # Print vulnerable projects
    if results['vulnerable_projects']:
        print("=" * 70)
        print("!!! CRITICAL VULNERABILITIES DETECTED !!!")
        print("=" * 70)
        print()

        for i, vp in enumerate(results['vulnerable_projects'], 1):
            print(f"{i}. {vp['path']}")
            print(f"   React Version:       {vp['react_version']}")
            print(f"   Recommended Version: {vp['recommended_version']}")
            if vp['next_js_version']:
                print(f"   Next.js Version:     {vp['next_js_version']}")
            if vp['vulnerable_packages']:
                print(f"   Vulnerable Packages: {', '.join(vp['vulnerable_packages'])}")
            print()

        # Print remediation
        print("=" * 70)
        print("REMEDIATION STEPS")
        print("=" * 70)
        for i, vp in enumerate(results['vulnerable_projects'], 1):
            print(f"\n{i}. {vp['path']}")
            print(f"   cd {vp['path']}")
            print(f"   npm install react@{vp['recommended_version']} react-dom@{vp['recommended_version']}")
            if vp['next_js_version']:
                # Determine Next.js patch version
                next_ver = vp['next_js_version']
                if next_ver.startswith('16.'):
                    patch = '16.0.7'
                elif next_ver.startswith('15.5.'):
                    patch = '15.5.7'
                elif next_ver.startswith('15.4.'):
                    patch = '15.4.8'
                elif next_ver.startswith('15.3.'):
                    patch = '15.3.6'
                elif next_ver.startswith('15.2.'):
                    patch = '15.2.6'
                elif next_ver.startswith('15.1.'):
                    patch = '15.1.9'
                elif next_ver.startswith('15.0.'):
                    patch = '15.0.5'
                else:
                    patch = '15.5.7'  # Default to latest 15.x
                print(f"   npm install next@{patch}")
            print(f"   npm run build")

        print()
        print("=" * 70)
        print("!!! IMMEDIATE ACTION REQUIRED !!!")
        print("CVSS 10.0 RCE - ACTIVELY EXPLOITED BY STATE ACTORS")
        print("=" * 70)

        # Save report
        report_path = Path("cve_2025_55182_scan_report.json")
        with open(report_path, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nDetailed report saved to: {report_path.resolve()}")

    else:
        print("=" * 70)
        print("ALL PROJECTS ARE SAFE!")
        print("=" * 70)
        print("\nNo vulnerable React versions detected.")
        print("Your projects are not affected by CVE-2025-55182.")

    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
