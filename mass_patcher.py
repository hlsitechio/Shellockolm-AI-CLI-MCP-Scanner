#!/usr/bin/env python3
"""
CVE-2025-55182 Mass Patcher
Automatically patches ALL vulnerable projects with safety features
"""

import sys
import json
import shutil
from pathlib import Path
from datetime import datetime
from scanner import CVEScanner
from remediation import Remediator


class MassPatcher:
    """Automated mass patching for CVE-2025-55182"""

    # Next.js version mapping for patches
    NEXTJS_PATCHES = {
        '16.': '16.0.7',
        '15.5.': '15.5.7',
        '15.4.': '15.4.8',
        '15.3.': '15.3.6',
        '15.2.': '15.2.6',
        '15.1.': '15.1.9',
        '15.0.': '15.0.5',
    }

    def __init__(self, backup=True, dry_run=True):
        self.scanner = CVEScanner()
        self.remediator = Remediator()
        self.backup = backup
        self.dry_run = dry_run
        self.results = {
            'patched': [],
            'failed': [],
            'skipped': []
        }

    def get_nextjs_patch_version(self, version: str) -> str:
        """Determine appropriate Next.js patch version"""
        for prefix, patch in self.NEXTJS_PATCHES.items():
            if version.startswith(prefix):
                return patch
        return '15.5.7'  # Default to latest 15.x

    def patch_project(self, project_path: str, target_react_version: str,
                      target_nextjs_version: str = None) -> dict:
        """
        Patch a single project

        Args:
            project_path: Path to project
            target_react_version: Target React version
            target_nextjs_version: Target Next.js version (optional)

        Returns:
            Dictionary with patch results
        """
        package_json = Path(project_path) / "package.json"

        result = {
            'project': project_path,
            'success': False,
            'changes': [],
            'backup': None,
            'error': None
        }

        try:
            # Patch package.json
            patch_result = self.remediator.patch_package_json(
                package_json,
                target_react_version,
                dry_run=self.dry_run,
                backup=self.backup
            )

            if patch_result['success']:
                result['success'] = True
                result['changes'] = patch_result['changes_made']
                result['backup'] = patch_result.get('backup_location')

                # If Next.js is present, add that to changes
                if target_nextjs_version:
                    result['changes'].append(
                        f"Next.js should be updated to {target_nextjs_version}"
                    )

        except Exception as e:
            result['error'] = str(e)

        return result

    def patch_all_projects(self, scan_results: dict, filter_priority: str = 'all'):
        """
        Patch all vulnerable projects

        Args:
            scan_results: Results from scanner
            filter_priority: 'all', 'high' (Next.js projects only), or 'medium'

        Returns:
            Summary of patching results
        """
        vulnerable_projects = scan_results['vulnerable_projects']
        total = len(vulnerable_projects)

        print(f"\n{'=' * 70}")
        print(f"MASS PATCHING - {'DRY RUN' if self.dry_run else 'LIVE MODE'}")
        print(f"{'=' * 70}")
        print(f"Total vulnerable projects: {total}")
        print(f"Filter: {filter_priority}")
        print(f"Backup enabled: {self.backup}")
        print()

        for i, vp in enumerate(vulnerable_projects, 1):
            # Apply filter
            if filter_priority == 'high' and not vp['next_js_version']:
                self.results['skipped'].append({
                    'project': vp['path'],
                    'reason': 'Not high priority (no Next.js)'
                })
                continue
            elif filter_priority == 'medium' and vp['next_js_version']:
                self.results['skipped'].append({
                    'project': vp['path'],
                    'reason': 'Not medium priority (has Next.js)'
                })
                continue

            print(f"[{i}/{total}] Patching: {vp['path']}")
            print(f"  Current: React {vp['react_version']}", end='')
            if vp['next_js_version']:
                print(f", Next.js {vp['next_js_version']}")
            else:
                print()

            # Determine patch versions
            react_patch = vp['recommended_version']
            nextjs_patch = None
            if vp['next_js_version']:
                nextjs_patch = self.get_nextjs_patch_version(vp['next_js_version'])

            # Patch the project
            result = self.patch_project(vp['path'], react_patch, nextjs_patch)

            if result['success']:
                self.results['patched'].append(result)
                print(f"  [OK] Success!")
                for change in result['changes']:
                    print(f"    - {change}")
                if result['backup']:
                    print(f"    Backup: {result['backup']}")
            else:
                self.results['failed'].append(result)
                print(f"  [FAIL] Failed: {result.get('error', 'Unknown error')}")

            print()

        return self.get_summary()

    def get_summary(self) -> dict:
        """Get patching summary"""
        return {
            'total_processed': len(self.results['patched']) + len(self.results['failed']),
            'successfully_patched': len(self.results['patched']),
            'failed': len(self.results['failed']),
            'skipped': len(self.results['skipped']),
            'details': self.results
        }

    def print_summary(self):
        """Print patching summary"""
        summary = self.get_summary()

        print(f"\n{'=' * 70}")
        print("PATCHING SUMMARY")
        print(f"{'=' * 70}")
        print(f"Total processed:        {summary['total_processed']}")
        print(f"Successfully patched:   {summary['successfully_patched']}")
        print(f"Failed:                 {summary['failed']}")
        print(f"Skipped:                {summary['skipped']}")
        print()

        if self.results['failed']:
            print("FAILED PATCHES:")
            for failure in self.results['failed']:
                print(f"  - {failure['project']}: {failure['error']}")
            print()

        if self.dry_run:
            print("=" * 70)
            print("DRY RUN MODE - No changes were made")
            print("Run with --apply to actually patch the projects")
            print("=" * 70)
        else:
            print("=" * 70)
            print("NEXT STEPS:")
            print("=" * 70)
            print("For each patched project, run:")
            print("  cd <project-path>")
            print("  npm install")
            print("  npm run build")
            print("  # Test thoroughly")
            print()

    def generate_npm_install_script(self, output_file: str = "install_patches.sh"):
        """Generate a shell script to run npm install on all patched projects"""
        if not self.results['patched']:
            print("No projects to generate script for")
            return

        script_lines = [
            "#!/bin/bash",
            "# Auto-generated script to install patches for CVE-2025-55182",
            f"# Generated: {datetime.now().isoformat()}",
            "",
            "set -e  # Exit on error",
            "",
            "echo 'Installing patches for CVE-2025-55182...'",
            "echo ''"
        ]

        for i, result in enumerate(self.results['patched'], 1):
            project_path = result['project']
            script_lines.extend([
                f"# Project {i}: {project_path}",
                f"echo '[{i}/{len(self.results['patched'])}] Installing: {project_path}'",
                f"cd '{project_path}'",
                "npm install",
                "echo 'Done!'",
                "echo ''",
                ""
            ])

        script_lines.extend([
            "echo 'All patches installed successfully!'",
            "echo ''",
            "echo 'NEXT: Run npm run build for each project and test thoroughly'",
            ""
        ])

        with open(output_file, 'w') as f:
            f.write('\n'.join(script_lines))

        print(f"\nGenerated install script: {output_file}")
        print(f"Run: bash {output_file}")


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Mass patcher for CVE-2025-55182 vulnerabilities'
    )
    parser.add_argument(
        'scan_path',
        help='Path to scan for vulnerable projects'
    )
    parser.add_argument(
        '--apply',
        action='store_true',
        help='Actually apply patches (default is dry-run)'
    )
    parser.add_argument(
        '--no-backup',
        action='store_true',
        help='Skip creating backups (not recommended)'
    )
    parser.add_argument(
        '--priority',
        choices=['all', 'high', 'medium'],
        default='all',
        help='Filter by priority: high (Next.js projects), medium (React only), or all'
    )
    parser.add_argument(
        '--generate-script',
        action='store_true',
        help='Generate npm install script for patched projects'
    )

    args = parser.parse_args()

    print("=" * 70)
    print("CVE-2025-55182 MASS PATCHER")
    print("=" * 70)
    print(f"Scan path: {args.scan_path}")
    print(f"Mode: {'APPLY' if args.apply else 'DRY RUN'}")
    print(f"Backup: {'No' if args.no_backup else 'Yes'}")
    print(f"Priority filter: {args.priority}")
    print()

    # Scan for vulnerabilities
    print("Step 1: Scanning for vulnerable projects...")
    scanner = CVEScanner()
    scan_results = scanner.scan_directory(args.scan_path, recursive=True)

    total = scan_results['summary']['total_projects']
    vulnerable = scan_results['summary']['vulnerable_projects']

    print(f"Found {vulnerable} vulnerable projects out of {total} scanned")

    if vulnerable == 0:
        print("\n✓ No vulnerable projects found. All projects are safe!")
        return

    # Ask for confirmation if applying
    if args.apply:
        print("\n" + "!" * 70)
        print("WARNING: You are about to modify package.json files!")
        print("!" * 70)
        response = input("\nType 'YES' to continue: ")
        if response != 'YES':
            print("Aborted.")
            return

    # Patch projects
    print("\nStep 2: Patching vulnerable projects...")
    patcher = MassPatcher(
        backup=not args.no_backup,
        dry_run=not args.apply
    )

    patcher.patch_all_projects(scan_results, filter_priority=args.priority)
    patcher.print_summary()

    # Generate install script if requested
    if args.generate_script and args.apply:
        patcher.generate_npm_install_script()

    # Save results
    results_file = "mass_patch_results.json"
    with open(results_file, 'w') as f:
        json.dump(patcher.get_summary(), f, indent=2)
    print(f"\nDetailed results saved to: {results_file}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nPatching interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
