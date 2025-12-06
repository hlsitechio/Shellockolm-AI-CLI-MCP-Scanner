"""
Remediation Module for CVE-2025-55182
Handles patching of vulnerable projects
"""

import json
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional


class Remediator:
    """Handles patching of vulnerable React projects"""

    def __init__(self):
        self.backup_suffix = ".backup"

    def create_backup(self, file_path: Path) -> Path:
        """
        Create a backup of a file

        Args:
            file_path: Path to file to backup

        Returns:
            Path to backup file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = file_path.with_suffix(f"{file_path.suffix}{self.backup_suffix}_{timestamp}")
        shutil.copy2(file_path, backup_path)
        return backup_path

    def patch_package_json(
        self,
        package_path: Path,
        target_react_version: str,
        dry_run: bool = True,
        backup: bool = True
    ) -> Dict:
        """
        Patch a package.json file to use patched React version

        Args:
            package_path: Path to package.json
            target_react_version: Target React version to update to
            dry_run: If True, only preview changes without applying
            backup: If True, create backup before modifying

        Returns:
            Dictionary with patch results
        """
        result = {
            "success": False,
            "changes_made": [],
            "backup_location": None,
            "next_steps": [],
            "errors": []
        }

        try:
            # Read package.json
            with open(package_path, 'r', encoding='utf-8') as f:
                content = f.read()
                package_data = json.loads(content)

            original_data = package_data.copy()
            changes = []

            # Update React version
            if "dependencies" in package_data and "react" in package_data["dependencies"]:
                old_version = package_data["dependencies"]["react"]
                # Preserve version prefix (^, ~, etc.)
                prefix = ""
                if old_version.startswith(("^", "~", ">=", ">")):
                    prefix = old_version[0] if old_version[0] in "^~" else old_version[:2]

                new_version = f"{prefix}{target_react_version}"
                package_data["dependencies"]["react"] = new_version
                changes.append(f"Updated react from {old_version} to {new_version}")

            # Update React DOM version
            if "dependencies" in package_data and "react-dom" in package_data["dependencies"]:
                old_version = package_data["dependencies"]["react-dom"]
                prefix = ""
                if old_version.startswith(("^", "~", ">=", ">")):
                    prefix = old_version[0] if old_version[0] in "^~" else old_version[:2]

                new_version = f"{prefix}{target_react_version}"
                package_data["dependencies"]["react-dom"] = new_version
                changes.append(f"Updated react-dom from {old_version} to {new_version}")

            # Update React Server Components packages if present
            rsc_packages = [
                "react-server-dom-webpack",
                "react-server-dom-parcel",
                "react-server-dom-turbopack"
            ]

            for pkg in rsc_packages:
                if "dependencies" in package_data and pkg in package_data["dependencies"]:
                    old_version = package_data["dependencies"][pkg]
                    prefix = ""
                    if old_version.startswith(("^", "~", ">=", ">")):
                        prefix = old_version[0] if old_version[0] in "^~" else old_version[:2]

                    new_version = f"{prefix}{target_react_version}"
                    package_data["dependencies"][pkg] = new_version
                    changes.append(f"Updated {pkg} from {old_version} to {new_version}")

            if not changes:
                result["errors"].append("No React dependencies found to update")
                return result

            result["changes_made"] = changes

            if not dry_run:
                # Create backup if requested
                if backup:
                    backup_path = self.create_backup(package_path)
                    result["backup_location"] = str(backup_path)

                # Write updated package.json
                with open(package_path, 'w', encoding='utf-8') as f:
                    json.dump(package_data, f, indent=2, ensure_ascii=False)
                    f.write("\n")  # Add trailing newline

                result["success"] = True
                result["next_steps"] = [
                    "Run: npm install",
                    "Run: npm run build",
                    "Test your application thoroughly",
                    "Deploy to production after testing"
                ]
            else:
                result["success"] = True
                result["next_steps"] = [
                    "Review changes above",
                    "Run patch_package_json with dry_run=False to apply"
                ]

        except FileNotFoundError:
            result["errors"].append(f"File not found: {package_path}")
        except json.JSONDecodeError as e:
            result["errors"].append(f"Invalid JSON in {package_path}: {e}")
        except Exception as e:
            result["errors"].append(f"Unexpected error: {e}")

        return result

    def verify_fix(self, package_path: Path, expected_version: str) -> Dict:
        """
        Verify that a fix was applied correctly

        Args:
            package_path: Path to package.json
            expected_version: Expected React version after patch

        Returns:
            Dictionary with verification results
        """
        result = {
            "verified": False,
            "react_version": None,
            "react_dom_version": None,
            "still_vulnerable": True,
            "message": ""
        }

        try:
            with open(package_path, 'r', encoding='utf-8') as f:
                package_data = json.load(f)

            # Check React version
            react_version = package_data.get("dependencies", {}).get("react")
            react_dom_version = package_data.get("dependencies", {}).get("react-dom")

            if not react_version:
                result["message"] = "React dependency not found"
                return result

            # Extract clean version
            clean_version = react_version.lstrip("^~>=<").split()[0]

            result["react_version"] = clean_version
            result["react_dom_version"] = react_dom_version.lstrip("^~>=<").split()[0] if react_dom_version else None

            # Check if still vulnerable
            vulnerable_versions = ["19.0.0", "19.1.0", "19.1.1", "19.2.0"]
            result["still_vulnerable"] = clean_version in vulnerable_versions

            if not result["still_vulnerable"]:
                result["verified"] = True
                result["message"] = f"Project successfully patched to React {clean_version}"
            else:
                result["message"] = f"Project still vulnerable: React {clean_version}"

        except Exception as e:
            result["message"] = f"Verification failed: {e}"

        return result

    def generate_update_command(self, current_version: str, target_version: str) -> str:
        """
        Generate npm/yarn update command

        Args:
            current_version: Current React version
            target_version: Target React version

        Returns:
            Update command string
        """
        return f"npm install react@{target_version} react-dom@{target_version}"

    def rollback(self, package_path: Path, backup_path: Path) -> Dict:
        """
        Rollback a patch by restoring from backup

        Args:
            package_path: Path to package.json
            backup_path: Path to backup file

        Returns:
            Dictionary with rollback results
        """
        result = {
            "success": False,
            "message": ""
        }

        try:
            if not backup_path.exists():
                result["message"] = f"Backup file not found: {backup_path}"
                return result

            shutil.copy2(backup_path, package_path)
            result["success"] = True
            result["message"] = f"Successfully rolled back to backup: {backup_path}"

        except Exception as e:
            result["message"] = f"Rollback failed: {e}"

        return result


if __name__ == "__main__":
    # Example usage
    remediator = Remediator()

    # Dry run example
    result = remediator.patch_package_json(
        Path("./package.json"),
        target_react_version="19.1.2",
        dry_run=True
    )

    print("Dry Run Results:")
    for change in result["changes_made"]:
        print(f"  - {change}")
