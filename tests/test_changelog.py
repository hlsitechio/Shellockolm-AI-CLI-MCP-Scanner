"""Version-bump discipline gate (build-loop task #50).

This is the build-blocking teeth behind the "bump the version with each batch"
practice. The project version is declared in several in-tree sources that all
mean *the version of this build* — they must stay single-valued, and a version
bump must always land together with a `CHANGELOG.md` entry. A future change that
bumps `pyproject.toml` without updating the CLI fallback / MCP server / `mcp.json`
(or without adding a CHANGELOG release) turns this suite red.

The gated sources are the code/manifest versions only:

* ``pyproject.toml``           — the canonical packaging version.
* ``src/cli.py`` ``__version__``— the `importlib.metadata` fallback (used in the
  banner and the ``scan --json`` / ``--sarif`` ``tool.version`` field).
* ``src/mcp_server.py`` ``server_version`` — advertised over the MCP handshake.
* ``mcp.json`` ``version``      — the MCP manifest.
* the top ``## [x.y.z]`` heading in ``CHANGELOG.md``.

The README version badge and the pre-commit ``rev:`` example are deliberately
NOT gated: they reference the latest *published* git tag, which legitimately
lags the in-development source version until a release is actually tagged.

Everything here is parsed from file *text* with the stdlib only (no ``tomllib``,
which is 3.11+), so the module collects on every supported Python (3.10+).
"""

import datetime as _dt
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]

_SEMVER = r"\d+\.\d+\.\d+"
# `## [x.y.z] - YYYY-MM-DD` — a released section. `## [Unreleased]` has no
# semver in the brackets and is intentionally not matched.
_VERSIONED_HEADING = re.compile(
    r"^## \[(" + _SEMVER + r")\] - (\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE
)


def _read(rel: str) -> str:
    path = REPO_ROOT / rel
    assert path.exists(), f"expected file is missing: {path}"
    return path.read_text(encoding="utf-8")


def _search(pattern: str, rel: str, label: str) -> str:
    m = re.search(pattern, _read(rel))
    assert m, f"could not find {label} in {rel}"
    return m.group(1)


def _pyproject_version() -> str:
    # `^version = "x.y.z"` at line start. The other `*-version`/`*_version`
    # keys (target-version, python_version) don't match the `^version` anchor.
    return _search(
        r'(?m)^version\s*=\s*"(' + _SEMVER + r')"',
        "pyproject.toml",
        "[project] version",
    )


def _cli_fallback_version() -> str:
    # The semver-anchored value skips the `_pkg_version("shellockolm")` line.
    return _search(
        r'__version__\s*=\s*"(' + _SEMVER + r')"',
        "src/cli.py",
        "__version__ fallback literal",
    )


def _mcp_server_version() -> str:
    return _search(
        r'server_version\s*=\s*"(' + _SEMVER + r')"',
        "src/mcp_server.py",
        "server_version",
    )


def _mcp_manifest_version() -> str:
    return _search(
        r'"version"\s*:\s*"(' + _SEMVER + r')"',
        "mcp.json",
        "manifest version",
    )


def _changelog_releases():
    """Versioned CHANGELOG sections as ``[(version, date), ...]``, top-first."""
    return _VERSIONED_HEADING.findall(_read("CHANGELOG.md"))


# ── version-source consistency ──────────────────────────────────────────────


def test_pyproject_version_is_semver():
    assert re.fullmatch(_SEMVER, _pyproject_version()), _pyproject_version()


def test_all_code_version_sources_agree():
    """One version across pyproject / CLI / MCP server / manifest."""
    canonical = _pyproject_version()
    sources = {
        "pyproject.toml version": canonical,
        "src/cli.py __version__": _cli_fallback_version(),
        "src/mcp_server.py server_version": _mcp_server_version(),
        "mcp.json version": _mcp_manifest_version(),
    }
    mismatched = {k: v for k, v in sources.items() if v != canonical}
    assert not mismatched, (
        f"version sources disagree with pyproject ({canonical}): {mismatched} "
        "— bump every source together"
    )


# ── CHANGELOG structure + bump discipline ───────────────────────────────────


def test_changelog_has_keep_a_changelog_skeleton():
    text = _read("CHANGELOG.md")
    assert text.lstrip().startswith("# Changelog")
    assert "Keep a Changelog" in text
    assert "Semantic Versioning" in text
    unreleased = text.find("## [Unreleased]")
    assert unreleased != -1, "missing '## [Unreleased]' section"
    first_release = _VERSIONED_HEADING.search(text)
    assert first_release is not None, "CHANGELOG.md has no released sections"
    assert unreleased < first_release.start(), (
        "'## [Unreleased]' must come before every released section"
    )


def test_current_version_has_a_changelog_release():
    """The package version must be the TOP released CHANGELOG entry.

    This is the discipline: you cannot bump the version without also writing
    its changelog entry (and vice-versa, you cannot leave the bump behind).
    """
    releases = _changelog_releases()
    assert releases, "CHANGELOG.md has no versioned sections"
    top_version, _top_date = releases[0]
    assert top_version == _pyproject_version(), (
        f"CHANGELOG top release is {top_version} but the package version is "
        f"{_pyproject_version()} — bump the version *and* add a CHANGELOG entry"
    )


def test_changelog_releases_are_unique_and_descending():
    releases = _changelog_releases()
    versions = [tuple(int(p) for p in v.split(".")) for v, _ in releases]
    assert len(versions) == len(set(versions)), (
        f"duplicate release version in CHANGELOG.md: {[v for v, _ in releases]}"
    )
    assert versions == sorted(versions, reverse=True), (
        f"CHANGELOG releases must be newest-first: {[v for v, _ in releases]}"
    )


def test_changelog_release_dates_are_valid_and_newest_first():
    releases = _changelog_releases()
    assert releases, "CHANGELOG.md has no versioned sections"
    dates = [_dt.date.fromisoformat(ds) for _v, ds in releases]  # raises if malformed
    assert dates == sorted(dates, reverse=True), (
        "CHANGELOG release dates must be newest-first: "
        f"{[(v, str(d)) for (v, _), d in zip(releases, dates)]}"
    )
