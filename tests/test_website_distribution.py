"""The marketing site must actually build from a fresh clone.

This repo's ``.gitignore`` started life as the standard *Python* template, and
its unanchored ``lib/`` rule matches at ANY depth — so it silently swallowed
``website/src/lib/``, the site's own source directory. The file was present on
the author's disk (so ``npm run build`` passed locally and every prior
website task looked green) while being absent from every clone: ``tsc`` fails
with ``TS2307: Cannot find module '@/lib/scanEngine'`` for anyone else. Exactly
the same class of bug the ``!tests/fixtures/`` negation at the bottom of
``.gitignore`` already had to undo for the detection corpus.

"It builds on my machine" cannot catch this, because the local tree has the
file. So these tests ask git, not the filesystem:

* the Python ``lib/``/``lib64/`` rules stay root-anchored (the literal
  regression guard);
* no file under ``website/src/`` is ignored, and every one is tracked;
* every first-party import in the site's sources (``@/…`` and relative)
  resolves to a **git-tracked** file — the "a clone can build the site" teeth.

Everything is derived from ``git ls-files``/``git check-ignore``, so a new
component that imports a newly-ignored module fails here rather than in a
downstream user's clone.

The second half covers *what a clone installs*. Shipping the sources is only
half the guarantee: ``website/package-lock.json`` was untracked, so every clone
ran ``npm install`` and re-resolved 17 caret-ranged direct dependencies (179
packages) fresh from the registry — the site a contributor or CI builds was not
the site the author built. For a scanner whose own ``AGENT-MCP-002`` rule flags
unpinned remote packages, that is the bug we sell the cure for. Meanwhile
``node_modules/`` matched no ignore rule at all (only ``node_modules_cache/``),
so a ``git add -A`` would stage the entire installed dependency tree.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
GITIGNORE = REPO_ROOT / ".gitignore"
WEBSITE = REPO_ROOT / "website"
WEBSITE_SRC = WEBSITE / "src"
PACKAGE_JSON = WEBSITE / "package.json"
LOCKFILE = WEBSITE / "package-lock.json"

# A concrete, fully-resolved version: "18.3.1", "7.18.1", "1.0.0-beta.2".
# Anything carrying a range operator (^ ~ * >= ||) is not pinned.
_CONCRETE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$")

# Suffixes that are real site sources (an import must land on one of these).
SOURCE_SUFFIXES = (".ts", ".tsx", ".js", ".jsx", ".css")

# `import … from "x"` / `export … from "x"` / bare `import "x"`.
_IMPORT_RE = re.compile(
    r"""(?:from|import)\s+["']([^"']+)["']""",
    re.MULTILINE,
)

# Resolution order mirrors the bundler: exact path, then extensions, then
# a directory's index file. `@/*` maps to website/src/* in BOTH tsconfig.json
# ("paths") and vite.config.ts ("resolve.alias"), which the site's build uses.
_RESOLVE_SUFFIXES = ("", *SOURCE_SUFFIXES)
_INDEX_NAMES = tuple(f"index{s}" for s in SOURCE_SUFFIXES)


def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
    )


@pytest.fixture(scope="module", autouse=True)
def _requires_git_repo():
    """These tests assert on git state; skip where there is none."""
    if shutil.which("git") is None:
        pytest.skip("git not on PATH")
    if _git("rev-parse", "--is-inside-work-tree").returncode != 0:
        pytest.skip("not inside a git work tree")


@pytest.fixture(scope="module")
def website_files() -> list[Path]:
    assert WEBSITE_SRC.is_dir(), f"missing {WEBSITE_SRC}"
    files = sorted(p for p in WEBSITE_SRC.rglob("*") if p.is_file())
    assert files, "website/src is empty"
    return files


@pytest.fixture(scope="module")
def tracked_paths() -> set[str]:
    """Every path git actually ships, as repo-relative POSIX strings."""
    proc = _git("ls-files")
    assert proc.returncode == 0, f"git ls-files failed: {proc.stderr}"
    return {line.strip() for line in proc.stdout.splitlines() if line.strip()}


def _rel(path: Path) -> str:
    return path.resolve().relative_to(REPO_ROOT).as_posix()


# ── The literal regression guard ──────────────────────────────────────────────


def test_python_lib_ignore_rules_are_root_anchored():
    """`lib/` unanchored matches website/src/lib/ — it must stay `/lib/`."""
    lines = [
        line.strip()
        for line in GITIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    for unanchored in ("lib/", "lib64/"):
        assert unanchored not in lines, (
            f"'{unanchored}' in .gitignore is unanchored and matches at any "
            f"depth, which swallows website/src/lib/. Use '/{unanchored}'."
        )
    assert "/lib/" in lines, "the root-anchored Python /lib/ rule went missing"


# ── git must not be hiding the site's own sources ─────────────────────────────


def test_no_website_source_file_is_gitignored(website_files):
    """`git check-ignore` is the authority — the filesystem always has them."""
    rels = [_rel(p) for p in website_files]
    proc = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(rels),
        capture_output=True,
        text=True,
        check=False,
    )
    # exit 0 => at least one path IS ignored (and is echoed on stdout);
    # exit 1 => none ignored; anything else is a real git failure.
    assert proc.returncode in (0, 1), f"git check-ignore failed: {proc.stderr}"
    ignored = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert not ignored, (
        "these website sources are gitignored, so they are missing from every "
        f"clone: {ignored}"
    )


def test_every_website_source_file_is_tracked(website_files, tracked_paths):
    untracked = [_rel(p) for p in website_files if _rel(p) not in tracked_paths]
    assert not untracked, (
        f"website sources present locally but absent from a clone: {untracked}"
    )


def test_scan_engine_module_is_tracked(tracked_paths):
    """Pin the exact file the unanchored `lib/` rule hid."""
    assert "website/src/lib/scanEngine.ts" in tracked_paths


# ── the teeth: every first-party import resolves to a tracked file ────────────


def _resolve_import(spec: str, importer: Path) -> Path | None:
    """Resolve a first-party import the way tsconfig/vite do. None if 3rd-party."""
    if spec.startswith("@/"):
        base = WEBSITE_SRC / spec[2:]
    elif spec.startswith("."):
        base = (importer.parent / spec).resolve()
    else:
        return None  # bare package specifier (react, lucide-react, …)

    for suffix in _RESOLVE_SUFFIXES:
        candidate = Path(str(base) + suffix)
        if candidate.is_file():
            return candidate
    for index in _INDEX_NAMES:
        candidate = base / index
        if candidate.is_file():
            return candidate
    return None


def _first_party_imports(path: Path) -> list[str]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return [
        spec
        for spec in _IMPORT_RE.findall(text)
        if spec.startswith("@/") or spec.startswith(".")
    ]


def test_first_party_imports_resolve_on_disk(website_files):
    """A broken alias/path would make the tracked-file check below vacuous."""
    unresolved: list[str] = []
    for path in website_files:
        if path.suffix not in (".ts", ".tsx"):
            continue
        for spec in _first_party_imports(path):
            if _resolve_import(spec, path) is None:
                unresolved.append(f"{_rel(path)} -> {spec}")
    assert not unresolved, f"imports that resolve to no file: {unresolved}"


def test_first_party_imports_resolve_to_tracked_files(website_files, tracked_paths):
    """The clone-can-build guarantee: no import may land on an untracked file."""
    checked = 0
    broken: list[str] = []
    for path in website_files:
        if path.suffix not in (".ts", ".tsx"):
            continue
        for spec in _first_party_imports(path):
            target = _resolve_import(spec, path)
            if target is None:
                continue
            checked += 1
            rel = _rel(target)
            if rel not in tracked_paths:
                broken.append(f"{_rel(path)} -> {spec} ({rel} is not tracked)")
    assert checked, "no first-party imports were checked — the guard is vacuous"
    assert not broken, (
        "these imports resolve to files git does not ship, so `npm run build` "
        f"fails in a fresh clone: {broken}"
    )


def test_package_scanner_section_imports_the_scan_engine(website_files):
    """Anti-vacuity: the component that exposed the bug still imports it."""
    section = WEBSITE_SRC / "components" / "PackageScannerSection.tsx"
    assert section.is_file(), "PackageScannerSection.tsx is missing"
    assert "@/lib/scanEngine" in _first_party_imports(section)


# ── a clone must install the SAME dependency tree ─────────────────────────────


@pytest.fixture(scope="module")
def manifest() -> dict:
    assert PACKAGE_JSON.is_file(), f"missing {PACKAGE_JSON}"
    return json.loads(PACKAGE_JSON.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def lockfile() -> dict:
    assert LOCKFILE.is_file(), f"missing {LOCKFILE}"
    return json.loads(LOCKFILE.read_text(encoding="utf-8"))


def test_website_lockfile_is_tracked(tracked_paths):
    """Untracked => every clone re-resolves the caret ranges from scratch."""
    assert "website/package-lock.json" in tracked_paths, (
        "website/package-lock.json is not tracked, so a clone runs `npm install` "
        "and floats every transitive dependency instead of `npm ci` installing "
        "the exact tree this repo was built and audited against"
    )


def test_website_lockfile_is_not_gitignored():
    """Guard the other direction: an ignore rule would silently unpin the site."""
    proc = _git("check-ignore", "website/package-lock.json")
    assert proc.returncode == 1, (
        "a .gitignore rule matches website/package-lock.json "
        f"({proc.stdout.strip()}) — that removes dependency pinning from clones"
    )


def test_lockfile_root_entry_matches_package_json(manifest, lockfile):
    """A stale lockfile is worse than none: `npm ci` aborts the build."""
    root = lockfile["packages"][""]
    for field in ("dependencies", "devDependencies"):
        assert root.get(field, {}) == manifest.get(field, {}), (
            f"package-lock.json is out of sync with package.json ({field}); "
            "`npm ci` will fail. Run `npm install` and commit the lockfile."
        )


def test_lockfile_pins_every_declared_dependency(manifest, lockfile):
    """Each declared range must resolve to one concrete version in the lock."""
    declared = {
        **manifest.get("dependencies", {}),
        **manifest.get("devDependencies", {}),
    }
    assert declared, "package.json declares no dependencies — guard is vacuous"

    packages = lockfile["packages"]
    unpinned: list[str] = []
    for name, spec in declared.items():
        entry = packages.get(f"node_modules/{name}")
        if entry is None:
            unpinned.append(f"{name} ({spec}): absent from the lockfile")
            continue
        version = entry.get("version", "")
        if not _CONCRETE_VERSION_RE.match(version):
            unpinned.append(f"{name} ({spec}): locked to {version!r}, not exact")
    assert not unpinned, f"dependencies a clone would not pin: {unpinned}"


def test_every_locked_package_has_an_integrity_hash(lockfile):
    """Tamper-evidence — the reason a lockfile is worth committing at all."""
    packages = lockfile["packages"]
    resolved = {
        name: entry
        for name, entry in packages.items()
        if name and not entry.get("link")
    }
    assert len(resolved) > 50, (
        f"only {len(resolved)} locked packages — the guard looks vacuous"
    )
    missing = [name for name, entry in resolved.items() if not entry.get("integrity")]
    assert not missing, (
        "locked packages without a subresource-integrity hash, so a swapped "
        f"tarball would install silently: {missing}"
    )


# ── the installed tree must never be committable ──────────────────────────────


def test_node_modules_is_gitignored():
    """`node_modules_cache/` does NOT match `node_modules/` — that was the gap."""
    # Works whether or not the tree is installed: check-ignore is pattern-only.
    for path in ("website/node_modules", "website/node_modules/react/package.json"):
        proc = _git("check-ignore", path)
        assert proc.returncode == 0, (
            f"{path} is not gitignored — `git add -A` would stage the whole "
            "installed dependency tree into a security scanner's repo"
        )


def test_claude_ignore_rule_stays_anchored_to_website():
    """A blanket `.claude/` would swallow the tracked detection corpus."""
    lines = [
        line.strip()
        for line in GITIGNORE.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert ".claude/" not in lines, (
        "'.claude/' in .gitignore is unanchored and matches at any depth, which "
        "hides the tests/fixtures/**/.claude/ detection corpus from clones. "
        "Anchor it (e.g. 'website/.claude/')."
    )


def test_tracked_claude_fixture_corpus_is_not_ignored(tracked_paths):
    """The teeth for the rule above: ask git about the real corpus files."""
    corpus = sorted(p for p in tracked_paths if "/.claude/" in p)
    assert corpus, "no tracked .claude fixtures found — the guard is vacuous"
    proc = subprocess.run(
        ["git", "check-ignore", "--stdin"],
        cwd=REPO_ROOT,
        input="\n".join(corpus),
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode in (0, 1), f"git check-ignore failed: {proc.stderr}"
    ignored = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    assert not ignored, (
        f"detection-corpus fixtures hidden from every clone: {ignored}"
    )
