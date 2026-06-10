#!/usr/bin/env python3
"""
Ignore File Handler for Shellockolm
Supports .shellockolmignore files similar to .gitignore format
"""

import os
import fnmatch
import re
from pathlib import Path
from typing import List, Set, Optional, Tuple
from dataclasses import dataclass, field

try:
    from rich.console import Console
    from rich.table import Table
    from rich import box
except ImportError:
    pass


@dataclass
class IgnorePattern:
    """Represents a single ignore pattern"""
    pattern: str
    is_negation: bool = False
    is_directory_only: bool = False
    is_rooted: bool = False
    regex: Optional[re.Pattern] = None

    def __post_init__(self):
        """Compile pattern to regex for efficient matching"""
        self.regex = self._compile_pattern()

    def _compile_pattern(self) -> re.Pattern:
        """Convert gitignore-style pattern to regex"""
        pattern = self.pattern

        # Handle negation (patterns starting with !)
        if pattern.startswith("!"):
            self.is_negation = True
            pattern = pattern[1:]

        # Handle directory-only patterns (ending with /)
        if pattern.endswith("/"):
            self.is_directory_only = True
            pattern = pattern[:-1]

        # Handle rooted patterns (starting with /)
        if pattern.startswith("/"):
            self.is_rooted = True
            pattern = pattern[1:]

        # Convert the gitignore glob into a regex.
        #
        # The glob metacharacters (**, *, ?) must NOT be passed through
        # re.escape, while every other character must be escaped exactly once
        # so it is treated as a literal. We split the pattern on the glob
        # tokens, re.escape each literal segment, then substitute the glob
        # tokens with their regex equivalents.
        #   **  ->  .*        (matches across directory separators)
        #   *   ->  [^/]*     (matches anything except a separator)
        #   ?   ->  [^/]      (matches a single non-separator character)
        token_regex = re.compile(r"\*\*|\*|\?")
        out_parts = []
        last_end = 0
        for m in token_regex.finditer(pattern):
            # Escape the literal text preceding this glob token.
            out_parts.append(re.escape(pattern[last_end:m.start()]))
            token = m.group(0)
            if token == "**":
                out_parts.append(".*")
            elif token == "*":
                out_parts.append("[^/]*")
            else:  # "?"
                out_parts.append("[^/]")
            last_end = m.end()
        # Escape the trailing literal text.
        out_parts.append(re.escape(pattern[last_end:]))
        pattern = "".join(out_parts)

        # Add anchors based on pattern type
        if self.is_rooted:
            pattern = "^" + pattern
        else:
            pattern = "(^|/)" + pattern

        if self.is_directory_only:
            pattern = pattern + "(/|$)"
        else:
            pattern = pattern + "($|/)"

        return re.compile(pattern)

    def matches(self, path: str, is_directory: bool = False) -> bool:
        """Check if path matches this pattern"""
        # Directory-only patterns should only match directories
        if self.is_directory_only and not is_directory:
            return False

        # Normalize path separators
        path = path.replace("\\", "/")

        # Try to match
        return self.regex.search(path) is not None


@dataclass
class IgnoreFile:
    """Represents a loaded ignore file"""
    path: Path
    patterns: List[IgnorePattern] = field(default_factory=list)
    base_dir: Path = field(default_factory=Path)

    def __post_init__(self):
        if self.path and self.path.exists():
            self.base_dir = self.path.parent
            self._load()

    def _load(self):
        """Load and parse the ignore file"""
        with open(self.path, "r") as f:
            for line in f:
                line = line.rstrip("\n\r")

                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Skip lines that are only whitespace
                if not line.strip():
                    continue

                self.patterns.append(IgnorePattern(line))

    def should_ignore(self, path: str, is_directory: bool = False) -> bool:
        """Check if a path should be ignored"""
        # Make path relative to base_dir
        try:
            rel_path = Path(path).relative_to(self.base_dir)
            rel_path_str = str(rel_path).replace("\\", "/")
        except ValueError:
            rel_path_str = str(path).replace("\\", "/")

        # Check patterns in order (last matching pattern wins)
        ignored = False
        for pattern in self.patterns:
            if pattern.matches(rel_path_str, is_directory):
                ignored = not pattern.is_negation

        return ignored


class IgnoreHandler:
    """
    Handles .shellockolmignore files and path filtering
    """

    IGNORE_FILENAME = ".shellockolmignore"

    # Default patterns to always ignore
    DEFAULT_IGNORES = [
        # Dependencies
        "node_modules/",
        "vendor/",
        "bower_components/",
        ".pnpm/",
        ".yarn/",

        # Build outputs
        "dist/",
        "build/",
        "out/",
        ".next/",
        ".nuxt/",
        ".output/",

        # Cache
        ".cache/",
        ".parcel-cache/",
        ".turbo/",

        # IDE
        ".idea/",
        ".vscode/",
        "*.swp",
        "*.swo",
        "*~",

        # Version control
        ".git/",
        ".svn/",
        ".hg/",

        # Test coverage
        "coverage/",
        ".nyc_output/",

        # Logs
        "*.log",
        "npm-debug.log*",
        "yarn-debug.log*",
        "yarn-error.log*",

        # OS files
        ".DS_Store",
        "Thumbs.db",

        # Misc
        "*.min.js",
        "*.min.css",
        "*.map",
    ]

    def __init__(self, console: Optional[Console] = None):
        self.console = console
        self.ignore_files: List[IgnoreFile] = []
        self.global_ignore: Optional[IgnoreFile] = None
        self.use_defaults = True
        self.default_patterns: List[IgnorePattern] = []

        # Compile default patterns
        self._load_defaults()

    def _load_defaults(self):
        """Load default ignore patterns"""
        for pattern in self.DEFAULT_IGNORES:
            self.default_patterns.append(IgnorePattern(pattern))

    def load_global_ignore(self):
        """Load global ignore file from home directory"""
        home = Path.home()
        global_path = home / self.IGNORE_FILENAME

        if global_path.exists():
            self.global_ignore = IgnoreFile(global_path)
            return True
        return False

    def find_ignore_files(self, root_path: str) -> List[Path]:
        """Find all .shellockolmignore files in directory tree"""
        root = Path(root_path)
        ignore_files = []

        # Check root
        root_ignore = root / self.IGNORE_FILENAME
        if root_ignore.exists():
            ignore_files.append(root_ignore)

        # Walk subdirectories (but not into ignored directories)
        for dirpath, dirnames, filenames in os.walk(root):
            # Check for ignore file
            if self.IGNORE_FILENAME in filenames:
                ignore_path = Path(dirpath) / self.IGNORE_FILENAME
                if ignore_path not in ignore_files:
                    ignore_files.append(ignore_path)

            # Skip ignored directories
            dirnames[:] = [d for d in dirnames if not self._is_always_ignored(d)]

        return ignore_files

    def _is_always_ignored(self, dirname: str) -> bool:
        """Check if directory should always be ignored"""
        always_ignore = {
            "node_modules", ".git", ".svn", ".hg", "vendor",
            "bower_components", ".pnpm", ".yarn", ".next", ".nuxt",
            "dist", "build", "coverage", ".cache"
        }
        return dirname in always_ignore

    def load_project_ignores(self, root_path: str):
        """Load all ignore files for a project"""
        ignore_paths = self.find_ignore_files(root_path)

        for path in ignore_paths:
            self.ignore_files.append(IgnoreFile(path))

    def should_ignore(self, path: str, is_directory: bool = False) -> Tuple[bool, str]:
        """
        Check if a path should be ignored

        Returns:
            (should_ignore, reason)
        """
        # Check default patterns
        if self.use_defaults:
            for pattern in self.default_patterns:
                if pattern.matches(path, is_directory):
                    return (True, f"default pattern: {pattern.pattern}")

        # Check global ignore
        if self.global_ignore and self.global_ignore.should_ignore(path, is_directory):
            return (True, f"global ignore file")

        # Check project ignore files (from most specific to least)
        for ignore_file in reversed(self.ignore_files):
            if ignore_file.should_ignore(path, is_directory):
                return (True, f"ignore file: {ignore_file.path}")

        return (False, "")

    def filter_paths(self, paths: List[str], base_path: str = "") -> List[str]:
        """Filter a list of paths, removing ignored ones"""
        result = []

        for path in paths:
            full_path = os.path.join(base_path, path) if base_path else path
            is_dir = os.path.isdir(full_path) if os.path.exists(full_path) else path.endswith("/")

            ignored, _ = self.should_ignore(path, is_dir)
            if not ignored:
                result.append(path)

        return result

    def create_ignore_file(self, path: str, patterns: Optional[List[str]] = None) -> str:
        """Create a new .shellockolmignore file"""
        ignore_path = Path(path) / self.IGNORE_FILENAME

        content_lines = [
            "# Shellockolm Ignore File",
            "# Patterns follow .gitignore syntax",
            "#",
            "# Examples:",
            "#   node_modules/     - Ignore directory",
            "#   *.log             - Ignore by extension",
            "#   /config.local.js  - Ignore specific file at root",
            "#   !important.js     - Don't ignore this file",
            "#",
            "",
        ]

        if patterns:
            content_lines.append("# Custom patterns")
            content_lines.extend(patterns)
        else:
            # Add recommended patterns
            content_lines.append("# Recommended patterns")
            content_lines.extend([
                "",
                "# Dependencies",
                "node_modules/",
                "",
                "# Build outputs",
                "dist/",
                "build/",
                ".next/",
                "",
                "# Test & Coverage",
                "coverage/",
                "__tests__/",
                "*.test.js",
                "*.spec.js",
                "",
                "# Config files (often don't need scanning)",
                "*.config.js",
                "*.config.ts",
                "",
                "# Minified files",
                "*.min.js",
                "*.min.css",
                "",
                "# Vendor/third-party",
                "vendor/",
                "public/vendor/",
            ])

        content = "\n".join(content_lines)

        with open(ignore_path, "w") as f:
            f.write(content)

        return str(ignore_path)

    def display_patterns(self):
        """Display all loaded patterns in a table"""
        if not self.console:
            return

        table = Table(
            title="Loaded Ignore Patterns",
            box=box.ROUNDED,
            border_style="bright_cyan"
        )
        table.add_column("Source", style="bright_cyan")
        table.add_column("Pattern", style="bright_white")
        table.add_column("Type", style="dim")

        # Default patterns (summarized)
        table.add_row(
            "[dim]defaults[/dim]",
            f"[dim]{len(self.default_patterns)} patterns[/dim]",
            "[dim]built-in[/dim]"
        )

        # Global ignore
        if self.global_ignore:
            for pattern in self.global_ignore.patterns:
                ptype = "negation" if pattern.is_negation else "dir" if pattern.is_directory_only else "file"
                table.add_row(
                    "[bright_yellow]~/.shellockolmignore[/bright_yellow]",
                    pattern.pattern,
                    ptype
                )

        # Project ignores
        for ignore_file in self.ignore_files:
            for pattern in ignore_file.patterns:
                ptype = "negation" if pattern.is_negation else "dir" if pattern.is_directory_only else "file"
                table.add_row(
                    str(ignore_file.path.relative_to(ignore_file.base_dir.parent)),
                    pattern.pattern,
                    ptype
                )

        self.console.print(table)

    def get_stats(self) -> dict:
        """Get statistics about loaded patterns"""
        total_patterns = len(self.default_patterns)
        project_patterns = sum(len(f.patterns) for f in self.ignore_files)
        global_patterns = len(self.global_ignore.patterns) if self.global_ignore else 0

        return {
            "default_patterns": len(self.default_patterns),
            "global_patterns": global_patterns,
            "project_patterns": project_patterns,
            "total_patterns": total_patterns + project_patterns + global_patterns,
            "ignore_files": len(self.ignore_files),
            "has_global": self.global_ignore is not None,
        }


def create_default_ignore(path: str) -> str:
    """Create a default .shellockolmignore file"""
    handler = IgnoreHandler()
    return handler.create_ignore_file(path)


# CLI interface for standalone testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python ignore_handler.py <project_path> [path_to_check]")
        sys.exit(1)

    project = sys.argv[1]
    check_path = sys.argv[2] if len(sys.argv) > 2 else None

    console = Console()
    handler = IgnoreHandler(console)

    # Load ignore files
    handler.load_global_ignore()
    handler.load_project_ignores(project)

    # Display loaded patterns
    handler.display_patterns()

    # Check specific path if provided
    if check_path:
        console.print(f"\n[info]Checking: {check_path}[/info]")
        ignored, reason = handler.should_ignore(check_path)
        if ignored:
            console.print(f"[red]IGNORED[/red] - {reason}")
        else:
            console.print("[green]NOT IGNORED[/green]")

    # Show stats
    stats = handler.get_stats()
    console.print(f"\n[dim]Total patterns loaded: {stats['total_patterns']}[/dim]")
