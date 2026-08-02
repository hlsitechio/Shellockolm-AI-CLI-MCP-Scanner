"""Config file support for ``shellockolm scan`` (build-loop task #29).

Lets a project pin its scan defaults in a committed file so every contributor
(and CI) runs the same scan without retyping flags. Two equivalent sources are
supported, discovered by walking up from the scan target to the filesystem root
(the **nearest** wins, like ``.gitignore`` / ``pyproject.toml`` discovery):

* a dedicated ``shellockolm.toml`` — keys live either at the top level or under a
  ``[tool.shellockolm]`` table (the table wins if both are present), or
* a ``pyproject.toml`` with a ``[tool.shellockolm]`` table (the standard place
  for tool config in a Python project).

A ``shellockolm.toml`` is preferred over a ``pyproject.toml`` in the same
directory. A ``pyproject.toml`` **without** a ``[tool.shellockolm]`` table is
skipped (it's not ours to read), and discovery keeps walking up.

Supported keys (every key is optional; an unknown key is ignored so the file is
forward-compatible):

* ``path``           — default scan target (str)
* ``scanner``        — default scanner name (str; validated by the CLI registry)
* ``recursive``      — recurse into subdirectories (bool)
* ``max_depth`` / ``depth`` — directory-walk depth cap (int >= 1)
* ``min_confidence`` — agent-scan confidence floor: ``low|medium|high`` (str)
* ``fail_on``        — exit-code severity gate: ``critical|high|medium|low|info|none`` (str)
* ``ignore``         — list of rule IDs and/or path globs to drop from results

**Config is a *default*, never an override.** The CLI applies a config value only
for a flag the user did not pass on the command line (detected via Click's
``get_parameter_source``), so an explicit flag always wins. This mirrors how every
other tool treats config-vs-flag precedence.

Design mirrors :mod:`diff_scan` / :mod:`baseline` / :mod:`doctor`: the risky,
high-value logic (discovery, parsing, validation, ignore matching) is pure and
exhaustively unit-testable, separated from Typer/CLI rendering. A malformed file
raises :class:`ConfigError` (→ CLI exit 2), never a silent wrong-config scan.
"""

from __future__ import annotations

import fnmatch
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple

from diff_scan import bare_path

# The candidate filenames, in the priority order they are checked within a single
# directory. A dedicated config wins over a borrowed pyproject table.
CONFIG_FILENAMES = ("shellockolm.toml", "pyproject.toml")

# The table key under which config lives in a pyproject.toml (or, optionally, in a
# dedicated shellockolm.toml). Mirrors the PEP 518 ``[tool.<name>]`` convention.
TOOL_TABLE = "shellockolm"

# Accepted values for the threshold keys. Defined here (not imported from cli) so
# this module stays import-light and pure; a CLI test asserts parity with the
# CLI's own ``_FAIL_ON_CHOICES`` / ``--min-confidence`` choices so they can't drift.
VALID_MIN_CONFIDENCE = {"low", "medium", "high"}
VALID_FAIL_ON = {"critical", "high", "medium", "low", "info", "none", "never", "off"}

# A rule/finding identifier in an ``ignore`` entry — same shape as the
# `.shellockolmignore` rule-suppression token (and a finding's ``cve_id``):
# uppercase, hyphen-segmented (AGENT-PI-013, CVE-2021-42574). Requiring all-upper
# segments keeps an ordinary lowercase path glob (``node_modules/**``, ``*.min.js``)
# from ever being mistaken for a rule ID, so the two ignore kinds never collide.
_RULE_ID_RE = re.compile(r"^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+$")

# Keys that hold a single string value (case-normalized at validation time).
_STR_KEYS = ("path", "scanner", "min_confidence", "fail_on")


class ConfigError(RuntimeError):
    """Raised when a config file cannot be read, parsed, or validated.

    The CLI surfaces the message and exits with the usage/operational error code
    (2), never the findings code — so a typo'd or malformed config can never
    masquerade as a clean (or a spuriously failed) run.
    """


@dataclass
class ScanConfig:
    """Validated scan defaults loaded from a config file.

    Every field is ``None`` / empty when the corresponding key is absent, so the
    CLI can tell "configured" from "not configured" and only fill in the gaps a
    user left on the command line.
    """

    path: Optional[str] = None
    scanner: Optional[str] = None
    recursive: Optional[bool] = None
    max_depth: Optional[int] = None
    min_confidence: Optional[str] = None
    fail_on: Optional[str] = None
    ignore: List[str] = field(default_factory=list)
    source: Optional[str] = None  # absolute path of the file this came from

    def is_empty(self) -> bool:
        """True if no recognized key was set (an empty or all-unknown table)."""
        return (
            self.path is None
            and self.scanner is None
            and self.recursive is None
            and self.max_depth is None
            and self.min_confidence is None
            and self.fail_on is None
            and not self.ignore
        )


# ──────────────────────────────────────────────────────────────────────────
# TOML loading (stdlib tomllib on 3.11+, tomli fallback on 3.10)
# ──────────────────────────────────────────────────────────────────────────
def _load_toml(path: Path) -> dict:
    """Read and parse a TOML file into a dict, or raise :class:`ConfigError`."""
    try:
        import tomllib as _toml  # Python 3.11+
    except ModuleNotFoundError:  # pragma: no cover - only on 3.10
        try:
            import tomli as _toml  # type: ignore
        except ModuleNotFoundError:
            raise ConfigError(
                "reading TOML config requires Python 3.11+ (for the stdlib "
                "tomllib) or the 'tomli' package on 3.10 — install tomli or "
                "upgrade Python"
            )
    try:
        with open(path, "rb") as fh:  # tomllib requires a binary handle
            return _toml.load(fh)
    except OSError as e:
        raise ConfigError(f"could not read config {path}: {e}")
    except _toml.TOMLDecodeError as e:
        raise ConfigError(f"config file is not valid TOML ({path}): {e}")


# ──────────────────────────────────────────────────────────────────────────
# Discovery
# ──────────────────────────────────────────────────────────────────────────
def _extract_table(doc: dict, filename: str) -> Optional[dict]:
    """Return the shellockolm config table from a parsed TOML document, or None.

    * ``pyproject.toml``  — only ``[tool.shellockolm]`` (the file isn't ours to
      read otherwise); returns None when that table is absent.
    * ``shellockolm.toml`` — a ``[tool.shellockolm]`` table if present (wins),
      else the top-level keys (a dedicated file needs no namespacing). A file
      that is *only* a ``[tool.shellockolm]`` table is read via that table.
    """
    tool = doc.get("tool")
    tool_tbl = tool.get(TOOL_TABLE) if isinstance(tool, dict) else None

    if Path(filename).name == "pyproject.toml":
        return tool_tbl if isinstance(tool_tbl, dict) else None

    # Dedicated shellockolm.toml: prefer the explicit table, else top-level keys.
    if isinstance(tool_tbl, dict):
        return tool_tbl
    return doc


def find_config_file(start: str) -> Optional[Path]:
    """Locate the nearest config file at or above ``start``.

    Walks from ``start`` (a file or directory) up to the filesystem root. In each
    directory a ``shellockolm.toml`` is preferred over a ``pyproject.toml``; a
    ``pyproject.toml`` only counts when it actually carries a
    ``[tool.shellockolm]`` table (otherwise discovery keeps walking). Returns the
    first match's absolute path, or None if none is found.

    A parse error while *probing* a pyproject's table is swallowed here (it is not
    necessarily our file); the real load via :func:`load_config` surfaces errors
    for the file it ultimately selects.
    """
    p = Path(start)
    try:
        base = p if p.is_dir() else p.parent
        base = base.resolve()
    except OSError:  # pragma: no cover - exotic path errors
        return None

    for directory in (base, *base.parents):
        for name in CONFIG_FILENAMES:
            candidate = directory / name
            if not candidate.is_file():
                continue
            if name == "pyproject.toml":
                # Only adopt a pyproject when it has our table; ignore parse
                # errors during probing so an unrelated broken pyproject up the
                # tree doesn't abort discovery.
                try:
                    doc = _load_toml(candidate)
                except ConfigError:
                    continue
                if _extract_table(doc, name) is None:
                    continue
            return candidate.resolve()
    return None


# ──────────────────────────────────────────────────────────────────────────
# Validation
# ──────────────────────────────────────────────────────────────────────────
def _require_str(value, key: str, source: str) -> str:
    if not isinstance(value, str):
        raise ConfigError(
            f"config key '{key}' in {source} must be a string, got "
            f"{type(value).__name__}"
        )
    return value.strip()


def _validate_ignore(value, source: str) -> List[str]:
    """Validate the ``ignore`` key into a clean list of non-empty strings."""
    if not isinstance(value, list):
        raise ConfigError(
            f"config key 'ignore' in {source} must be a list of strings, got "
            f"{type(value).__name__}"
        )
    out: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ConfigError(
                f"every 'ignore' entry in {source} must be a string, got "
                f"{type(item).__name__}"
            )
        item = item.strip()
        if item:
            out.append(item)
    return out


def parse_config(table: dict, source: str) -> ScanConfig:
    """Validate a raw config table into a :class:`ScanConfig`.

    Type/value errors raise :class:`ConfigError` (→ exit 2). Unknown keys are
    ignored (forward-compatible). String threshold keys are lower-cased and
    checked against their accepted value sets.
    """
    if not isinstance(table, dict):
        raise ConfigError(
            f"the [tool.{TOOL_TABLE}] config in {source} must be a table/section"
        )

    cfg = ScanConfig(source=source)

    if "path" in table:
        cfg.path = _require_str(table["path"], "path", source) or None
    if "scanner" in table:
        cfg.scanner = (_require_str(table["scanner"], "scanner", source) or None)

    if "recursive" in table:
        val = table["recursive"]
        if not isinstance(val, bool):
            raise ConfigError(
                f"config key 'recursive' in {source} must be true/false, got "
                f"{type(val).__name__}"
            )
        cfg.recursive = val

    # ``max_depth`` (preferred) or its ``depth`` alias (matches the CLI's -d/--depth).
    depth_key = "max_depth" if "max_depth" in table else ("depth" if "depth" in table else None)
    if depth_key is not None:
        val = table[depth_key]
        # bool is an int subclass — reject it explicitly so `max_depth = true`
        # isn't silently read as depth 1.
        if isinstance(val, bool) or not isinstance(val, int):
            raise ConfigError(
                f"config key '{depth_key}' in {source} must be an integer, got "
                f"{type(val).__name__}"
            )
        if val < 1:
            raise ConfigError(
                f"config key '{depth_key}' in {source} must be >= 1, got {val}"
            )
        cfg.max_depth = val

    if "min_confidence" in table:
        mc = _require_str(table["min_confidence"], "min_confidence", source).lower()
        if mc not in VALID_MIN_CONFIDENCE:
            raise ConfigError(
                f"config key 'min_confidence' in {source} must be one of "
                f"{sorted(VALID_MIN_CONFIDENCE)}, got '{mc}'"
            )
        cfg.min_confidence = mc

    if "fail_on" in table:
        fo = _require_str(table["fail_on"], "fail_on", source).lower()
        if fo not in VALID_FAIL_ON:
            raise ConfigError(
                f"config key 'fail_on' in {source} must be one of "
                f"{sorted(VALID_FAIL_ON)}, got '{fo}'"
            )
        cfg.fail_on = fo

    if "ignore" in table:
        cfg.ignore = _validate_ignore(table["ignore"], source)

    return cfg


def load_config(start: str) -> Optional[ScanConfig]:
    """Discover, load, and validate the nearest config file at/above ``start``.

    Returns the parsed :class:`ScanConfig` (with ``source`` set), or None when no
    config file exists. Raises :class:`ConfigError` if a discovered file is
    unreadable, not valid TOML, or fails validation.
    """
    found = find_config_file(start)
    if found is None:
        return None
    doc = _load_toml(found)
    table = _extract_table(doc, found.name)
    if table is None:
        # A selected pyproject lost its table between probe and load (race), or a
        # dedicated file is genuinely empty — treat as no config.
        return None
    cfg = parse_config(table, str(found))
    return cfg


def load_config_from_file(path: str) -> ScanConfig:
    """Load and validate a specific config file (no discovery). Always validates.

    Used by ``--config <path>``: an explicitly named file that is missing or the
    wrong shape is a usage error, not a silently-skipped probe.
    """
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {path}")
    doc = _load_toml(p)
    table = _extract_table(doc, p.name)
    if table is None:
        raise ConfigError(
            f"no [tool.{TOOL_TABLE}] config found in {path} "
            "(expected a [tool.shellockolm] table or shellockolm.toml keys)"
        )
    return parse_config(table, str(p.resolve()))


# ──────────────────────────────────────────────────────────────────────────
# Ignore application (a pure, scanner-agnostic CLI-level post-filter)
# ──────────────────────────────────────────────────────────────────────────
def split_ignores(entries: Iterable[str]) -> Tuple[Set[str], List[str]]:
    """Partition ``ignore`` entries into (rule-ID set, path-glob list).

    An entry whose token matches :data:`_RULE_ID_RE` (uppercase, hyphen-segmented)
    is a rule/finding-ID suppression; anything else is treated as a gitignore-style
    path glob matched against a finding's file. Rule IDs are upper-cased so a
    case-insensitive match is possible; globs are kept verbatim.
    """
    rule_ids: Set[str] = set()
    globs: List[str] = []
    for raw in entries:
        token = (raw or "").strip()
        if not token:
            continue
        if _RULE_ID_RE.match(token):
            rule_ids.add(token.upper())
        else:
            globs.append(token)
    return rule_ids, globs


def _rel_for_glob(file_path: str, base: str) -> str:
    """A finding's file as a base-relative, forward-slashed path for glob matching.

    Strips the structured ``» …`` / trailing ``:<line>`` suffix (via
    :func:`diff_scan.bare_path`), resolves a relative path against ``base``, then
    re-expresses it relative to ``base`` with ``/`` separators so a config glob
    written ``docs/skills/**`` matches regardless of OS separator or scan cwd.
    """
    bare = bare_path(file_path)
    if not bare:
        return ""
    abs_path = bare if os.path.isabs(bare) else os.path.join(base, bare)
    try:
        rel = os.path.relpath(abs_path, base)
    except ValueError:  # different drive on Windows — no relative form
        rel = abs_path
    return rel.replace("\\", "/")


def _path_matches_any_glob(rel_path: str, globs: List[str]) -> bool:
    """True if ``rel_path`` matches any glob.

    A trailing-``/`` directory glob (``vendor/``) and a bare directory name match
    anything beneath it; ``fnmatch`` handles ``*``/``?``/``[...]`` and ``**`` is
    accepted as "any depth" by also trying the pattern with ``/**`` stripped.
    """
    if not rel_path:
        return False
    candidates = [rel_path]
    for pat in globs:
        pat = pat.rstrip()
        if not pat:
            continue
        # Directory-style pattern: match the dir itself and everything under it.
        if pat.endswith("/"):
            dir_pat = pat.rstrip("/")
            if rel_path == dir_pat or rel_path.startswith(dir_pat + "/"):
                return True
            continue
        for cand in candidates:
            if fnmatch.fnmatch(cand, pat):
                return True
            # Treat ``dir/**`` as also matching ``dir/`` prefixes regardless of
            # fnmatch's literal handling of ``**``.
            if pat.endswith("/**"):
                prefix = pat[:-3]
                if cand == prefix or cand.startswith(prefix + "/"):
                    return True
    return False


def finding_is_ignored(finding, rule_ids: Set[str], globs: List[str], *, base: str) -> bool:
    """True if a finding matches a config ``ignore`` rule-ID or path glob."""
    fid = (getattr(finding, "cve_id", "") or "").strip().upper()
    if fid and fid in rule_ids:
        return True
    if globs:
        rel = _rel_for_glob(getattr(finding, "file_path", "") or "", base)
        if _path_matches_any_glob(rel, globs):
            return True
    return False


def filter_results_to_unignored(results, entries: Iterable[str], *, base: str) -> int:
    """Drop findings matched by config ``ignore`` entries in-place; return the count.

    Each :class:`ScanResult` keeps only findings NOT matched by a config rule-ID or
    path glob and records the per-scanner drop count under
    ``stats['findings_config_ignored']`` so the suppression is auditable and never
    silent. Mirrors :func:`diff_scan.filter_results_to_changed` /
    :func:`baseline.filter_results_to_new`. A no-op (no entries / no matches)
    leaves results untouched and returns 0.
    """
    rule_ids, globs = split_ignores(entries)
    if not rule_ids and not globs:
        return 0
    total_dropped = 0
    for r in results:
        before = len(r.findings)
        r.findings = [
            f for f in r.findings
            if not finding_is_ignored(f, rule_ids, globs, base=base)
        ]
        dropped = before - len(r.findings)
        if dropped:
            r.stats["findings_config_ignored"] = (
                r.stats.get("findings_config_ignored", 0) + dropped
            )
            total_dropped += dropped
    return total_dropped
