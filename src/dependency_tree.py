#!/usr/bin/env python3
"""
Dependency Tree Visualizer for Shellockolm
Displays beautiful ASCII/Unicode trees of npm package dependencies
"""

import json
import os
from collections import deque
from pathlib import Path
from typing import Dict, FrozenSet, List, Optional, Set, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

try:
    from rich.console import Console
    from rich.tree import Tree
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from rich.text import Text
except ImportError:
    print("Error: rich not installed. Run: pip install rich")
    raise


class OutputFormat(Enum):
    """Output format options"""
    TREE = "tree"
    JSON = "json"
    DOT = "dot"  # GraphViz format
    ASCII = "ascii"


# A hoisted lockfile is a DAG, not a tree: the same package is reachable through
# many parents, so a naive full expansion is exponential. npm's own `npm ls`
# sidesteps this by printing a repeat occurrence as "deduped" instead of
# re-expanding it, which is what `_expanded` below does. These two constants are
# the backstops for pathological graphs so a scan can never hang or blow the
# interpreter's recursion limit.
MAX_TREE_NODES = 50000
MAX_TREE_DEPTH = 200

# Sections of a `packages` entry that declare real installed edges. Peer
# dependencies are included because npm resolves them to an actually-installed
# package (`npm ls --all` lists them as edges), so a vulnerable peer is genuinely
# reachable from the parent; a peer that was NOT installed simply fails to
# resolve and is skipped. Matching npm's own edge set is what the tree is
# checked against.
_EDGE_SECTIONS = ("dependencies", "optionalDependencies", "peerDependencies")
_ROOT_EDGE_SECTIONS = (
    "dependencies",
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
)


@dataclass
class DependencyNode:
    """Represents a dependency in the tree"""
    name: str
    version: str
    resolved: str = ""
    integrity: str = ""
    dev: bool = False
    optional: bool = False
    peer: bool = False
    bundled: bool = False
    dependencies: Dict[str, 'DependencyNode'] = field(default_factory=dict)
    depth: int = 0
    circular_ref: bool = False
    duplicate: bool = False
    has_vulnerabilities: bool = False
    vulnerability_count: int = 0


class DependencyTreeVisualizer:
    """
    Visualizes npm dependency trees with rich formatting
    """

    def __init__(self, console: Optional[Console] = None):
        self.console = console or Console()
        self.all_packages: Dict[str, List[str]] = {}  # name -> versions
        self.circular_refs: List[Tuple[str, str]] = []  # (parent, child)
        self.max_depth: int = 0
        self.total_packages: int = 0
        self.duplicate_count: int = 0
        self.truncated: bool = False
        # Package identities already expanded somewhere in the tree. A repeat is
        # emitted as a leaf marked `duplicate` (npm's "deduped") rather than
        # re-walked, which keeps a hoisted DAG linear in the number of edges.
        self._expanded: Set[str] = set()

    def _reset(self) -> None:
        """Clear per-parse accumulators so re-parsing on one instance is idempotent."""
        self.all_packages = {}
        self.circular_refs = []
        self.max_depth = 0
        self.total_packages = 0
        self.duplicate_count = 0
        self.truncated = False
        self._expanded = set()

    def _track_version(self, name: str, version: str) -> None:
        """Record that `name` exists at `version` (drives the multi-version report)."""
        versions = self.all_packages.setdefault(name, [])
        if version not in versions:
            versions.append(version)

    @staticmethod
    def _package_name_from_path(pkg_path: str) -> str:
        """Package name for a `packages` key such as `node_modules/a/node_modules/@s/b`.

        The name is what follows the LAST `node_modules/` segment — a nested
        install belongs to the nested package, not to its host. Returns "" for a
        workspace entry (a key with no `node_modules/` segment at all), which is
        a local link rather than a resolved dependency.
        """
        marker = "node_modules/"
        idx = pkg_path.rfind(marker)
        if idx == -1:
            return ""
        parts = pkg_path[idx + len(marker):].split("/")
        if parts[0].startswith("@") and len(parts) > 1:
            return f"{parts[0]}/{parts[1]}"
        return parts[0]

    @staticmethod
    def _resolve_pkg_path(packages: Dict[str, Dict], from_path: str, name: str) -> Optional[str]:
        """Resolve `name` as required BY the package installed at `from_path`.

        Mirrors node's own lookup: try the requiring package's own
        `node_modules`, then each ancestor's, ending at the top level — which is
        where npm hoists nearly everything on a modern lockfile. Returns None
        when the dependency is not installed (an unmet optional dep).
        """
        prefix = from_path
        while True:
            candidate = f"{prefix}/node_modules/{name}" if prefix else f"node_modules/{name}"
            if candidate in packages:
                return candidate
            if not prefix:
                return None
            idx = prefix.rfind("/node_modules/")
            prefix = prefix[:idx] if idx != -1 else ""

    def parse_package_lock(self, lock_path: str) -> Dict[str, DependencyNode]:
        """Parse package-lock.json and build dependency tree"""
        with open(lock_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        self._reset()
        root_deps: Dict[str, DependencyNode] = {}
        lock_version = data.get("lockfileVersion", 1)

        if lock_version >= 2:
            # npm v7+ format with packages
            packages = data.get("packages", {})

            # Track every version present in the lockfile
            for pkg_path, pkg_info in packages.items():
                if pkg_path == "":
                    # Root package
                    continue
                name = self._package_name_from_path(pkg_path)
                if not name:
                    continue  # workspace link, not an installed dependency
                self._track_version(name, pkg_info.get("version", "0.0.0"))

            if packages:
                # `packages` is the authoritative edge source for npm v7+: every
                # install is hoisted into it and lockfileVersion 3 drops the
                # legacy `dependencies` mirror entirely, so reading only that
                # mirror yields an EMPTY tree on a modern lockfile.
                root_deps = self._build_tree_from_packages(packages)
            else:
                for name, dep_info in data.get("dependencies", {}).items():
                    root_deps[name] = self._build_node_v2(
                        name, dep_info, set(), 1, data.get("dependencies", {})
                    )

        else:
            # npm v6 format
            legacy = data.get("dependencies", {})
            for name, dep_info in legacy.items():
                root_deps[name] = self._build_node_v1(name, dep_info, set(), 1, legacy)

        return root_deps

    def _new_node(self, name: str, info: Dict, depth: int, circular: bool) -> DependencyNode:
        """Build a node and fold it into the running counters."""
        node = DependencyNode(
            name=name,
            version=info.get("version", "0.0.0"),
            resolved=info.get("resolved", ""),
            integrity=info.get("integrity", ""),
            dev=info.get("dev", False),
            optional=info.get("optional", False),
            peer=info.get("peer", False),
            bundled=info.get("bundled", False),
            depth=depth,
            circular_ref=circular,
        )
        self._track_version(name, node.version)
        self.total_packages += 1
        self.max_depth = max(self.max_depth, depth)
        return node

    def _should_expand(self, node: DependencyNode, identity: str, depth: int) -> bool:
        """Whether to walk `node`'s children, marking why not when we don't."""
        if node.circular_ref:
            return False
        if identity in self._expanded:
            # Already rendered in full elsewhere in the tree — npm calls this
            # "deduped". Re-expanding it would duplicate a whole subtree.
            node.duplicate = True
            self.duplicate_count += 1
            return False
        if depth >= MAX_TREE_DEPTH or self.total_packages >= MAX_TREE_NODES:
            self.truncated = True
            return False
        self._expanded.add(identity)
        return True

    @staticmethod
    def _packages_entry(packages: Dict[str, Dict], pkg_path: str) -> Dict:
        """The metadata for `pkg_path`, following a workspace link to its real entry."""
        info = packages.get(pkg_path, {})
        if info.get("link") and info.get("resolved") in packages:
            return packages[info["resolved"]]
        return info

    def _build_tree_from_packages(self, packages: Dict[str, Dict]) -> Dict[str, DependencyNode]:
        """Build the tree from an npm v7+ `packages` map (lockfileVersion 2 and 3).

        Breadth-first, so a package reachable by several routes is expanded at
        its SHALLOWEST occurrence and deduped deeper — the same choice `npm ls`
        makes, and the reason a direct dependency is never demoted to a
        "deduped" leaf just because some transitive peer happened to reach it
        first.
        """
        root_info = packages.get("", {})
        root_deps: Dict[str, DependencyNode] = {}
        queue: deque = deque()

        def enqueue(name: str, pkg_path: str, seen: FrozenSet[str], depth: int, parent: str):
            circular = pkg_path in seen
            if circular:
                self.circular_refs.append((parent, name))
            node = self._new_node(name, self._packages_entry(packages, pkg_path), depth, circular)
            queue.append((node, pkg_path, seen, depth))
            return node

        for section in _ROOT_EDGE_SECTIONS:
            for name in root_info.get(section, {}):
                if name in root_deps:
                    continue
                dep_path = self._resolve_pkg_path(packages, "", name)
                if dep_path is None:
                    continue  # declared but not installed (unmet optional dep)
                root_deps[name] = enqueue(name, dep_path, frozenset(), 1, "root")

        while queue:
            node, pkg_path, seen, depth = queue.popleft()
            if not self._should_expand(node, pkg_path, depth):
                continue

            info = self._packages_entry(packages, pkg_path)
            child_seen = seen | {pkg_path}
            for section in _EDGE_SECTIONS:
                for child_name in info.get(section, {}):
                    if child_name in node.dependencies:
                        continue
                    child_path = self._resolve_pkg_path(packages, pkg_path, child_name)
                    if child_path is None:
                        continue  # not installed (unmet optional dep)
                    node.dependencies[child_name] = enqueue(
                        child_name, child_path, child_seen, depth + 1, node.name
                    )

        return root_deps

    @staticmethod
    def _legacy_children(info: Dict, hoisted: Optional[Dict]) -> Dict[str, Dict]:
        """Children of a legacy (`dependencies`-mirror) entry.

        An entry's NESTED `dependencies` object holds only the deps npm could
        not hoist; everything else it declares lives in `requires` and was
        hoisted to the lockfile's top level. Walking the nested object alone
        therefore misses nearly every real edge. A nested copy wins over the
        hoisted one — it is the version actually installed for this parent.
        """
        nested = info.get("dependencies")
        children: Dict[str, Dict] = dict(nested) if isinstance(nested, dict) else {}

        requires = info.get("requires")
        if isinstance(requires, dict):  # old npm also writes `"requires": true`
            for req_name in requires:
                if req_name in children:
                    continue
                hoisted_info = (hoisted or {}).get(req_name)
                if isinstance(hoisted_info, dict):
                    children[req_name] = hoisted_info

        return children

    def _build_node_v1(
        self,
        name: str,
        info: Dict,
        seen: Set[str],
        depth: int = 1,
        hoisted: Optional[Dict] = None,
    ) -> DependencyNode:
        """Build node for npm v6 lockfile format"""
        pkg_key = f"{name}@{info.get('version', '0.0.0')}"
        node = self._new_node(name, info, depth, circular=pkg_key in seen)

        if self._should_expand(node, pkg_key, depth):
            child_seen = seen | {pkg_key}
            for sub_name, sub_info in self._legacy_children(info, hoisted).items():
                node.dependencies[sub_name] = self._build_node_v1(
                    sub_name, sub_info, child_seen, depth + 1, hoisted
                )

        return node

    def _build_node_v2(
        self,
        name: str,
        info: Dict,
        seen: Set[str],
        depth: int = 1,
        hoisted: Optional[Dict] = None,
    ) -> DependencyNode:
        """Build node for a legacy `dependencies` mirror in an npm v7+ lockfile"""
        pkg_key = f"{name}@{info.get('version', '0.0.0')}"
        circular = pkg_key in seen
        if circular:
            self.circular_refs.append((list(seen)[-1] if seen else "root", name))

        node = self._new_node(name, info, depth, circular)

        if self._should_expand(node, pkg_key, depth):
            child_seen = seen | {pkg_key}
            for sub_name, sub_info in self._legacy_children(info, hoisted).items():
                node.dependencies[sub_name] = self._build_node_v2(
                    sub_name, sub_info, child_seen, depth + 1, hoisted
                )

        return node

    def parse_yarn_lock(self, lock_path: str) -> Dict[str, DependencyNode]:
        """Parse yarn.lock and build dependency tree"""
        with open(lock_path, "r", encoding="utf-8") as f:
            content = f.read()

        self._reset()
        root_deps = {}
        current_pkg = None
        current_info = {}

        lines = content.split("\n")
        for line in lines:
            if not line or line.startswith("#"):
                continue

            # Package header line (not indented)
            if not line.startswith(" ") and not line.startswith("\t"):
                # Save previous package
                if current_pkg and current_info:
                    name = current_pkg.split("@")[0]
                    if name.startswith("@"):
                        # Scoped package
                        parts = current_pkg.split("@")
                        name = f"@{parts[1]}"

                    if name not in root_deps:
                        root_deps[name] = DependencyNode(
                            name=name,
                            version=current_info.get("version", "0.0.0"),
                            resolved=current_info.get("resolved", ""),
                            integrity=current_info.get("integrity", ""),
                            depth=1
                        )
                        self.total_packages += 1

                        if name not in self.all_packages:
                            self.all_packages[name] = []
                        if root_deps[name].version not in self.all_packages[name]:
                            self.all_packages[name].append(root_deps[name].version)

                # Start new package
                current_pkg = line.rstrip(":").strip('"')
                current_info = {}

            elif line.strip():
                # Property line
                line = line.strip()
                if line.startswith("version"):
                    current_info["version"] = line.split('"')[1] if '"' in line else line.split()[-1]
                elif line.startswith("resolved"):
                    current_info["resolved"] = line.split('"')[1] if '"' in line else ""
                elif line.startswith("integrity"):
                    current_info["integrity"] = line.split()[-1]

        # Don't forget last package
        if current_pkg and current_info:
            name = current_pkg.split("@")[0]
            if name.startswith("@"):
                parts = current_pkg.split("@")
                name = f"@{parts[1]}"

            if name not in root_deps:
                root_deps[name] = DependencyNode(
                    name=name,
                    version=current_info.get("version", "0.0.0"),
                    resolved=current_info.get("resolved", ""),
                    integrity=current_info.get("integrity", ""),
                    depth=1
                )
                self.total_packages += 1

        return root_deps

    def visualize(
        self,
        project_path: str,
        max_depth: int = 10,
        show_dev: bool = True,
        show_optional: bool = False,
        filter_name: Optional[str] = None,
        output_format: OutputFormat = OutputFormat.TREE
    ) -> str:
        """
        Visualize the dependency tree

        Args:
            project_path: Path to the project
            max_depth: Maximum depth to display
            show_dev: Include dev dependencies
            show_optional: Include optional dependencies
            filter_name: Filter to specific package
            output_format: Output format

        Returns:
            Visualization string
        """
        project = Path(project_path)

        # Find lockfile
        package_lock = project / "package-lock.json"
        yarn_lock = project / "yarn.lock"

        deps = {}
        if package_lock.exists():
            deps = self.parse_package_lock(str(package_lock))
        elif yarn_lock.exists():
            deps = self.parse_yarn_lock(str(yarn_lock))
        else:
            raise FileNotFoundError("No package-lock.json or yarn.lock found")

        # Filter if needed
        if filter_name:
            deps = {k: v for k, v in deps.items() if filter_name.lower() in k.lower()}

        # Filter dev/optional
        if not show_dev:
            deps = {k: v for k, v in deps.items() if not v.dev}
        if not show_optional:
            deps = {k: v for k, v in deps.items() if not v.optional}

        # Generate output
        if output_format == OutputFormat.TREE:
            return self._render_rich_tree(deps, project_path, max_depth)
        elif output_format == OutputFormat.ASCII:
            return self._render_ascii_tree(deps, max_depth)
        elif output_format == OutputFormat.JSON:
            return self._render_json(deps)
        elif output_format == OutputFormat.DOT:
            return self._render_graphviz(deps, project_path)

        return ""

    def _render_rich_tree(self, deps: Dict[str, DependencyNode], project_path: str, max_depth: int) -> str:
        """Render as Rich tree"""
        # Get project name
        pkg_json = Path(project_path) / "package.json"
        project_name = "project"
        if pkg_json.exists():
            with open(pkg_json) as f:
                data = json.load(f)
                project_name = data.get("name", "project")

        # Create root tree
        tree = Tree(
            f"[bold bright_cyan]{project_name}[/bold bright_cyan]",
            guide_style="bright_black"
        )

        # Add dependencies
        for name, node in sorted(deps.items()):
            self._add_tree_node(tree, node, 1, max_depth)

        # Render to string
        from io import StringIO
        string_io = StringIO()
        temp_console = Console(file=string_io, force_terminal=True, width=120)
        temp_console.print(tree)
        return string_io.getvalue()

    def _add_tree_node(self, parent: Tree, node: DependencyNode, depth: int, max_depth: int):
        """Recursively add tree nodes"""
        if depth > max_depth:
            parent.add("[dim]...[/dim]")
            return

        # Build label
        label_parts = []

        # Package name with version
        if node.circular_ref:
            label_parts.append(f"[yellow]{node.name}@{node.version}[/yellow] [red](circular)[/red]")
        elif node.duplicate:
            label_parts.append(f"[dim]{node.name}@{node.version}[/dim] [dim](dup)[/dim]")
        elif node.dev:
            label_parts.append(f"[bright_magenta]{node.name}@{node.version}[/bright_magenta] [dim](dev)[/dim]")
        elif node.optional:
            label_parts.append(f"[bright_blue]{node.name}@{node.version}[/bright_blue] [dim](opt)[/dim]")
        elif node.peer:
            label_parts.append(f"[bright_yellow]{node.name}@{node.version}[/bright_yellow] [dim](peer)[/dim]")
        elif node.has_vulnerabilities:
            label_parts.append(f"[bold red]{node.name}@{node.version}[/bold red] [red](!{node.vulnerability_count})[/red]")
        else:
            label_parts.append(f"[bright_white]{node.name}[/bright_white]@[bright_green]{node.version}[/bright_green]")

        label = " ".join(label_parts)
        branch = parent.add(label)

        # Add sub-dependencies (don't recurse into circular refs)
        if not node.circular_ref:
            for sub_name, sub_node in sorted(node.dependencies.items()):
                self._add_tree_node(branch, sub_node, depth + 1, max_depth)

    def _render_ascii_tree(self, deps: Dict[str, DependencyNode], max_depth: int) -> str:
        """Render as plain ASCII tree"""
        lines = []

        def add_node(node: DependencyNode, prefix: str, is_last: bool, depth: int):
            if depth > max_depth:
                lines.append(f"{prefix}{'`-- ' if is_last else '|-- '}...")
                return

            # Current node
            marker = "`-- " if is_last else "|-- "
            suffix = ""
            if node.circular_ref:
                suffix = " (circular)"
            elif node.dev:
                suffix = " (dev)"
            elif node.optional:
                suffix = " (optional)"

            lines.append(f"{prefix}{marker}{node.name}@{node.version}{suffix}")

            # Children
            children = list(node.dependencies.items())
            for i, (name, child) in enumerate(sorted(children)):
                is_child_last = (i == len(children) - 1)
                child_prefix = prefix + ("    " if is_last else "|   ")
                add_node(child, child_prefix, is_child_last, depth + 1)

        # Root dependencies
        items = list(deps.items())
        for i, (name, node) in enumerate(sorted(items)):
            is_last = (i == len(items) - 1)
            add_node(node, "", is_last, 1)

        return "\n".join(lines)

    def _render_json(self, deps: Dict[str, DependencyNode]) -> str:
        """Render as JSON"""
        def node_to_dict(node: DependencyNode) -> Dict:
            return {
                "name": node.name,
                "version": node.version,
                "dev": node.dev,
                "optional": node.optional,
                "peer": node.peer,
                "circular": node.circular_ref,
                "duplicate": node.duplicate,
                "depth": node.depth,
                "dependencies": {
                    k: node_to_dict(v) for k, v in node.dependencies.items()
                }
            }

        data = {k: node_to_dict(v) for k, v in deps.items()}
        return json.dumps(data, indent=2)

    def _render_graphviz(self, deps: Dict[str, DependencyNode], project_path: str) -> str:
        """Render as GraphViz DOT format"""
        pkg_json = Path(project_path) / "package.json"
        project_name = "project"
        if pkg_json.exists():
            with open(pkg_json) as f:
                data = json.load(f)
                project_name = data.get("name", "project")

        lines = [
            "digraph dependencies {",
            "    rankdir=TB;",
            "    node [shape=box, style=filled];",
            f'    "{project_name}" [fillcolor=lightblue];',
        ]

        added_edges = set()

        def add_edges(node: DependencyNode, parent: str):
            node_id = f"{node.name}@{node.version}"
            edge = f"{parent} -> {node_id}"

            if edge not in added_edges:
                added_edges.add(edge)

                # Style based on type
                color = "white"
                if node.circular_ref:
                    color = "yellow"
                elif node.dev:
                    color = "lightpink"
                elif node.optional:
                    color = "lightgray"
                elif node.has_vulnerabilities:
                    color = "red"

                lines.append(f'    "{node_id}" [fillcolor={color}];')
                lines.append(f'    "{parent}" -> "{node_id}";')

                for name, child in node.dependencies.items():
                    add_edges(child, node_id)

        for name, node in deps.items():
            add_edges(node, project_name)

        lines.append("}")
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get dependency tree statistics"""
        duplicates = [
            name for name, versions in self.all_packages.items()
            if len(versions) > 1
        ]

        return {
            "total_packages": self.total_packages,
            "unique_packages": len(self.all_packages),
            "max_depth": self.max_depth,
            "duplicate_packages": duplicates,
            "duplicate_count": len(duplicates),
            "deduped_nodes": self.duplicate_count,
            "truncated": self.truncated,
            "circular_references": self.circular_refs,
            "multi_version_packages": {
                name: versions
                for name, versions in self.all_packages.items()
                if len(versions) > 1
            }
        }

    def display_stats(self):
        """Display statistics in a Rich panel"""
        stats = self.get_stats()

        table = Table(title="Dependency Tree Statistics", box=box.ROUNDED)
        table.add_column("Metric", style="bright_cyan")
        table.add_column("Value", style="bright_white")

        table.add_row("Total Packages", str(stats["total_packages"]))
        table.add_row("Unique Packages", str(stats["unique_packages"]))
        table.add_row("Max Depth", str(stats["max_depth"]))
        table.add_row("Duplicate Packages", str(stats["duplicate_count"]))
        table.add_row("Deduped Nodes", str(stats["deduped_nodes"]))
        table.add_row("Circular References", str(len(stats["circular_references"])))

        self.console.print(table)

        if stats["truncated"]:
            self.console.print(
                f"\n[yellow]Tree truncated at {MAX_TREE_NODES} nodes / depth "
                f"{MAX_TREE_DEPTH}; some edges are not shown.[/yellow]"
            )

        # Show duplicates if any
        if stats["multi_version_packages"]:
            self.console.print("\n[bold yellow]Multi-Version Packages:[/bold yellow]")
            for name, versions in stats["multi_version_packages"].items():
                self.console.print(f"  [bright_white]{name}[/bright_white]: {', '.join(versions)}")

        # Show circular refs if any
        if stats["circular_references"]:
            self.console.print("\n[bold red]Circular References:[/bold red]")
            for parent, child in stats["circular_references"]:
                self.console.print(f"  [bright_white]{parent}[/bright_white] -> [yellow]{child}[/yellow]")

    def find_package(self, project_path: str, package_name: str) -> List[Tuple[str, DependencyNode]]:
        """Find all instances of a package in the tree"""
        project = Path(project_path)

        # Find and parse lockfile
        package_lock = project / "package-lock.json"
        yarn_lock = project / "yarn.lock"

        if package_lock.exists():
            deps = self.parse_package_lock(str(package_lock))
        elif yarn_lock.exists():
            deps = self.parse_yarn_lock(str(yarn_lock))
        else:
            return []

        results = []

        def search_tree(node: DependencyNode, path: List[str]):
            current_path = path + [f"{node.name}@{node.version}"]

            if package_name.lower() in node.name.lower():
                results.append((" -> ".join(current_path), node))

            for child in node.dependencies.values():
                search_tree(child, current_path)

        for name, node in deps.items():
            search_tree(node, [])

        return results

    def export_to_file(
        self,
        project_path: str,
        output_path: str,
        output_format: OutputFormat = OutputFormat.TREE,
        max_depth: int = 10
    ) -> str:
        """Export dependency tree to file"""
        content = self.visualize(
            project_path,
            max_depth=max_depth,
            output_format=output_format
        )

        with open(output_path, "w") as f:
            f.write(content)

        return output_path


# CLI interface for standalone testing
if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: python dependency_tree.py <project_path> [max_depth]")
        sys.exit(1)

    project = sys.argv[1]
    depth = int(sys.argv[2]) if len(sys.argv) > 2 else 5

    console = Console()
    visualizer = DependencyTreeVisualizer(console)

    try:
        output = visualizer.visualize(project, max_depth=depth)
        console.print(output)
        console.print()
        visualizer.display_stats()
    except FileNotFoundError as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(1)
