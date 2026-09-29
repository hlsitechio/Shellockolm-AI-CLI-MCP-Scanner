"""Well-known MCP-config file locations, enumerated per OS (task #36 support module).

The ``check_mcp_config`` MCP tool vets the *caller's own* installed MCP server configs
— the files that tell Claude Desktop / Claude Code / Cursor / Windsurf / VS Code which
MCP servers to launch. A poisoned entry there (a server fetched from a raw-paste URL, a
broad host credential forwarded to an unrelated server, a curl|bash launcher) is a
zero-click supply-chain foothold, so an agent should be able to scan these on request.

This module is the **pure, side-effect-free** half: it computes the candidate file
paths for a given OS / home dir / project root WITHOUT touching the filesystem, mirroring
the ``diff_scan`` / ``baseline`` / ``doctor`` / ``config_file`` split the rest of the
codebase uses. The MCP server does the ``.exists()`` probing and the actual scanning, so
this part is exhaustively unit-testable by feeding it a synthetic ``system`` / ``home`` /
``env`` / ``project_root`` with no machine dependence.

Only canonical, stable MCP-server config files are listed. Each location is scanned via
the agent scanner's structured MCP path, which fires only when the file actually declares
servers (``mcpServers`` / ``servers`` / ``mcp`` keys) — so a listed-but-unrelated config
simply yields no findings rather than a false positive.
"""

from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from typing import List, Mapping, Optional


@dataclass(frozen=True)
class McpConfigLocation:
    """One well-known MCP-config file path and which client/scope it belongs to.

    ``path`` is a candidate only — the caller checks whether it actually exists on
    disk before scanning. ``scope`` is ``"user"`` (a per-user install config under the
    home dir) or ``"project"`` (a repo-local config under the scanned project root).
    """

    client: str
    scope: str  # "user" | "project"
    path: Path


def _appdata_dir(home: Path, env: Mapping[str, str]) -> Path:
    """Windows roaming AppData dir (``%APPDATA%``), falling back to the default path."""
    appdata = env.get("APPDATA")
    if appdata:
        return Path(appdata)
    return home / "AppData" / "Roaming"


def _claude_desktop_dir(system: str, home: Path, env: Mapping[str, str]) -> Path:
    """Per-OS Claude Desktop config directory."""
    if system == "Windows":
        return _appdata_dir(home, env) / "Claude"
    if system == "Darwin":
        return home / "Library" / "Application Support" / "Claude"
    return home / ".config" / "Claude"


def _vscode_user_dir(system: str, home: Path, env: Mapping[str, str]) -> Path:
    """Per-OS VS Code user-settings directory (where a user-level ``mcp.json`` lives)."""
    if system == "Windows":
        return _appdata_dir(home, env) / "Code" / "User"
    if system == "Darwin":
        return home / "Library" / "Application Support" / "Code" / "User"
    return home / ".config" / "Code" / "User"


def _dedupe(locations: List[McpConfigLocation]) -> List[McpConfigLocation]:
    """Drop later entries whose path collides with an earlier one (case-insensitive,
    normalized), preserving the first (most specific) client label and order."""
    seen = set()
    out: List[McpConfigLocation] = []
    for loc in locations:
        key = os.path.normcase(os.path.normpath(str(loc.path)))
        if key in seen:
            continue
        seen.add(key)
        out.append(loc)
    return out


def known_mcp_config_locations(
    *,
    system: Optional[str] = None,
    home: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
    project_root: Optional[Path] = None,
    include_user: bool = True,
    include_project: bool = True,
) -> List[McpConfigLocation]:
    """Enumerate candidate MCP-config file paths for the given environment — PURE.

    Performs **no** filesystem access; every input is parameterized so the result is
    deterministic and testable. Unspecified inputs default to the live environment
    (``platform.system()`` / ``Path.home()`` / ``os.environ`` / ``Path.cwd()``).

    * ``include_user`` adds the per-user install configs (Claude Desktop, Claude Code,
      Cursor, Windsurf, VS Code) under the home dir.
    * ``include_project`` adds the repo-local configs (``.mcp.json``, ``mcp.json``,
      ``.cursor/mcp.json``, ``.vscode/mcp.json``) under ``project_root``.

    Paths that resolve to the same file (e.g. a project run at the home dir) are
    de-duplicated, keeping the first/most-specific client label.
    """
    system = system if system is not None else platform.system()
    home = Path(home) if home is not None else Path.home()
    env = env if env is not None else os.environ
    project_root = Path(project_root) if project_root is not None else Path.cwd()

    locations: List[McpConfigLocation] = []

    if include_user:
        cd = _claude_desktop_dir(system, home, env)
        vs = _vscode_user_dir(system, home, env)
        locations += [
            # Claude Desktop — `mcpServers` object.
            McpConfigLocation("Claude Desktop", "user", cd / "claude_desktop_config.json"),
            # Claude Code (CLI) — user-scope servers live in ~/.claude.json.
            McpConfigLocation("Claude Code", "user", home / ".claude.json"),
            # Cursor — global config.
            McpConfigLocation("Cursor", "user", home / ".cursor" / "mcp.json"),
            # Windsurf (Codeium) — global config.
            McpConfigLocation(
                "Windsurf", "user", home / ".codeium" / "windsurf" / "mcp_config.json"
            ),
            # VS Code (native MCP / Copilot) — user-level config.
            McpConfigLocation("VS Code", "user", vs / "mcp.json"),
        ]

    if include_project:
        root = project_root
        locations += [
            # Claude Code project scope.
            McpConfigLocation("Claude Code", "project", root / ".mcp.json"),
            # Generic project root config (some tools read a bare mcp.json).
            McpConfigLocation("Generic", "project", root / "mcp.json"),
            # Cursor project scope.
            McpConfigLocation("Cursor", "project", root / ".cursor" / "mcp.json"),
            # VS Code workspace scope.
            McpConfigLocation("VS Code", "project", root / ".vscode" / "mcp.json"),
        ]

    return _dedupe(locations)
