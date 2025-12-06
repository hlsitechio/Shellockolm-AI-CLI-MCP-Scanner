#!/usr/bin/env python3
"""
CVE-2025-55182 Auto-Fix Tool
Automated workflow: Scan → Patch → Verify
"""

import sys
import json
from pathlib import Path
from datetime import datetime
from scanner import CVEScanner
from remediation import Remediator


class AutoFixer:
    """Automated scan, patch, and verify workflow"""

    NEXTJS_PATCHES = {
        '16.': '16.0.7',
        '15.5.': '15.5.7',
        '15.4.': '15.4.8',
        '15.3.': '15.3.6',
        '15.2.': '15.2.6',
        '15.1.': '15.1.9',
        '15.0.': '15.0.5',
    }

    def __init__(self, scan_path: str, backup: bool = True):
        self.scan_path = scan_path
        self.backup = backup
        self.scanner = CVEScanner()
        self.remediator = Remediator()
        self.results = {
            'initial_scan': None,
            'patched': [],
            'failed': [],
            'verification_scan': None
        }

    def get_nextjs_patch(self, version: str) -> str:
        """Get Next.js patch version"""
        for prefix, patch in self.NEXTJS_PATCHES.items():
            if version.startswith(prefix):
                return patch
        return '15.5.7'

    def step1_initial_scan(self):
        """Step 1: Initial vulnerability scan"""
        print("\n" + "=" * 70)
        print("STEP 1: INITIAL VULNERABILITY SCAN")
        print("=" * 70)
        print(f"Scanning: {self.scan_path}")
        print()

        results = self.scanner.scan_directory(self.scan_path, recursive=True)
        self.results['initial_scan'] = results

        summary = results['summary']
        print(f"Total projects: {summary['total_projects']}")
        print(f"Vulnerable:     {summary['vulnerable_projects']}")
        print(f"Safe:           {summary['safe_projects']}")

        if summary['vulnerable_projects'] == 0:
            print("\n[OK] No vulnerable projects found!")
            return False

        print(f"\n[!] Found {summary['vulnerable_projects']} vulnerable projects")
        return True

    def step2_patch_all(self):
        """Step 2: Patch all vulnerable projects"""
        print("\n" + "=" * 70)
        print("STEP 2: PATCHING VULNERABLE PROJECTS")
        print("=" * 70)
        print(f"Backup enabled: {self.backup}")
        print()

        vulnerable = self.results['initial_scan']['vulnerable_projects']
        total = len(vulnerable)

        for i, vp in enumerate(vulnerable, 1):
            project_path = vp['path']
            package_json = Path(project_path) / "package.json"

            print(f"[{i}/{total}] {project_path}")
            print(f"  Current: React {vp['react_version']}", end='')
            if vp['next_js_version']:
                print(f", Next.js {vp['next_js_version']}")
            else:
                print()

            try:
                # Patch React
                result = self.remediator.patch_package_json(
                    package_json,
                    vp['recommended_version'],
                    dry_run=False,
                    backup=self.backup
                )

                if result['success']:
                    self.results['patched'].append({
                        'project': project_path,
                        'changes': result['changes_made'],
                        'backup': result.get('backup_location')
                    })
                    print(f"  [OK] Patched!")
                    for change in result['changes_made']:
                        print(f"    - {change}")
                else:
                    self.results['failed'].append({
                        'project': project_path,
                        'error': result.get('errors', ['Unknown error'])
                    })
                    print(f"  [FAIL] Patch failed")

            except Exception as e:
                self.results['failed'].append({
                    'project': project_path,
                    'error': str(e)
                })
                print(f"  [FAIL] Error: {e}")

            print()

        print(f"Successfully patched: {len(self.results['patched'])}")
        print(f"Failed: {len(self.results['failed'])}")

    def step3_verify(self):
        """Step 3: Verify all patches applied"""
        print("\n" + "=" * 70)
        print("STEP 3: VERIFICATION SCAN")
        print("=" * 70)
        print("Re-scanning to verify all vulnerabilities are fixed...")
        print()

        results = self.scanner.scan_directory(self.scan_path, recursive=True)
        self.results['verification_scan'] = results

        summary = results['summary']
        print(f"Total projects: {summary['total_projects']}")
        print(f"Vulnerable:     {summary['vulnerable_projects']}")
        print(f"Safe:           {summary['safe_projects']}")

        if summary['vulnerable_projects'] == 0:
            print("\n" + "=" * 70)
            print("[SUCCESS] ALL PROJECTS PATCHED SUCCESSFULLY!")
            print("=" * 70)
            return True
        else:
            print("\n" + "=" * 70)
            print(f"[WARNING] {summary['vulnerable_projects']} projects still vulnerable")
            print("=" * 70)

            # Show which projects are still vulnerable
            print("\nStill vulnerable:")
            for vp in results['vulnerable_projects']:
                print(f"  - {vp['path']}: React {vp['react_version']}")

            return False

    def generate_install_script(self):
        """Generate npm install script"""
        if not self.results['patched']:
            return

        script_file = "install_patches.sh"
        lines = [
            "#!/bin/bash",
            "# Auto-generated npm install script for patched projects",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "set -e",
            "echo 'Installing patched dependencies...'",
            ""
        ]

        for i, result in enumerate(self.results['patched'], 1):
            lines.extend([
                f"# Project {i}: {result['project']}",
                f"echo '[{i}/{len(self.results['patched'])}] {result['project']}'",
                f"cd '{result['project']}'",
                "npm install",
                "echo ''",
                ""
            ])

        lines.extend([
            "echo 'All dependencies installed!'",
            "echo 'Next: Run npm run build for each project'",
            ""
        ])

        with open(script_file, 'w') as f:
            f.write('\n'.join(lines))

        print(f"\nGenerated install script: {script_file}")
        return script_file

    def save_report(self):
        """Save detailed report"""
        report_file = f"auto_fix_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"

        report = {
            'timestamp': datetime.now().isoformat(),
            'scan_path': self.scan_path,
            'backup_enabled': self.backup,
            'initial_scan': {
                'total': self.results['initial_scan']['summary']['total_projects'],
                'vulnerable': self.results['initial_scan']['summary']['vulnerable_projects'],
                'safe': self.results['initial_scan']['summary']['safe_projects']
            },
            'patching': {
                'patched': len(self.results['patched']),
                'failed': len(self.results['failed']),
                'details': self.results['patched'],
                'failures': self.results['failed']
            },
            'verification': {
                'total': self.results['verification_scan']['summary']['total_projects'],
                'vulnerable': self.results['verification_scan']['summary']['vulnerable_projects'],
                'safe': self.results['verification_scan']['summary']['safe_projects'],
                'remaining_vulnerabilities': self.results['verification_scan']['vulnerable_projects']
            }
        }

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2)

        print(f"Detailed report saved: {report_file}")
        return report_file

    def run(self):
        """Run complete auto-fix workflow"""
        print("=" * 70)
        print("CVE-2025-55182 AUTO-FIX TOOL")
        print("Automated: Scan > Patch > Verify")
        print("=" * 70)

        # Step 1: Initial scan
        has_vulnerabilities = self.step1_initial_scan()
        if not has_vulnerabilities:
            return

        # Step 2: Patch all
        self.step2_patch_all()

        # Step 3: Verify
        all_fixed = self.step3_verify()

        # Generate install script
        script_file = self.generate_install_script()

        # Save report
        report_file = self.save_report()

        # Final summary
        print("\n" + "=" * 70)
        print("AUTO-FIX SUMMARY")
        print("=" * 70)
        print(f"Projects scanned:      {self.results['initial_scan']['summary']['total_projects']}")
        print(f"Initially vulnerable:  {self.results['initial_scan']['summary']['vulnerable_projects']}")
        print(f"Successfully patched:  {len(self.results['patched'])}")
        print(f"Failed to patch:       {len(self.results['failed'])}")
        print(f"Still vulnerable:      {self.results['verification_scan']['summary']['vulnerable_projects']}")
        print()

        if all_fixed:
            print("[SUCCESS] All vulnerabilities fixed!")
        else:
            print("[WARNING] Some projects still vulnerable - check report")

        print(f"\nNext steps:")
        print(f"  1. Run: bash {script_file}")
        print(f"  2. Build each project: npm run build")
        print(f"  3. Test thoroughly before deploying")
        print(f"\nReport: {report_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Auto-fix CVE-2025-55182 vulnerabilities (scan-patch-verify)'
    )
    parser.add_argument(
        'path',
        help='Path to scan and patch'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip creating backups (not recommended)'
    )

    args = parser.parse_args()

    fixer = AutoFixer(args.path, backup=not args.no_backup)
    fixer.run()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nAuto-fix interrupted")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
