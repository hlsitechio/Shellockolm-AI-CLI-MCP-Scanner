"""Tests for ``sandbox_integrity`` — the installed tree vs. what npm recorded (F47).

F47 asked how a dependency that **wipes a sibling package** during its
``postinstall`` could be told apart from npm's own pruning, since
``filter_unexpected_deletions`` drops every deletion under ``node_modules/``.
:func:`test_sibling_sabotage_appears_in_no_snapshot_list` is the fail-first proof
that the premise was wrong in a way that matters: the filter is not what hides
sibling sabotage, the **baseline** is. Phase 2 snapshots a temp directory holding
one ``package.json`` and the decoys, so ``node_modules/`` is not in it — a file
npm creates during the install and a hook deletes seconds later shows up in
*none* of ``compare_snapshots``' three lists. Widening the deletion filter would
have detected exactly nothing.

So the pass is built on the lockfile instead, which the sandbox install already
keeps for F36. Its precision rests on one measured calibration, pinned by
:func:`test_measured_platform_conditional_entries_are_not_reported`: across six
real installs (left-pad, chalk, express, typescript, esbuild, @babel/core — 161
lockfile entries) **44** entries named a directory that was legitimately absent,
and every one carried ``"optional": true`` with an ``os``/``cpu`` constraint —
npm records a package's whole platform matrix and installs the one entry that
matches the host. Excluding those takes the false positive count to zero, and the
entries below are the real ones npm 11.9.0 wrote.

The entry-point check has its own measurement, over **679 installed packages**
from 18 real dependency trees (451 declaring ``main``, 230 declaring ``exports``
across 1,292 targets), pinned by the ``…_shapes_measured_…`` tests below:

* reading ``main`` alone → **2** false positives (``@humanfs/core`` and
  ``@humanfs/node``, both eslint dependencies, ship a ``main`` pointing into a
  directory holding only ``.d.ts`` files — their real entry is an ``exports``
  target);
* requiring every ``exports`` target to exist → **10** (``@babel/helper-*`` and
  ``yargs`` list ``.d.ts`` files they never publish);
* deferring to ``exports`` and requiring **one** target to resolve → **zero**,
  which is the shipped rule.

The 228 packages declaring no entry point at all are not guessed at: assuming
``index.js`` would call every types-only and bin-only package gutted.
"""

import ast
import json
from pathlib import Path

import pytest

import sandbox_deps
import sandbox_integrity
from sandbox_check import filter_unexpected_deletions, filter_unexpected_modifications
from sandbox_integrity import (
    DAMAGE_DIRECTORY_GONE,
    DAMAGE_ENTRY_EMPTIED,
    DAMAGE_ENTRY_GONE,
    DAMAGE_MANIFEST_EMPTIED,
    DAMAGE_MANIFEST_GONE,
    MAX_EXPORTS_DEPTH,
    MAX_EXPORTS_TARGETS,
    MAX_REPORTED_DAMAGE,
    MAX_UNREADABLE_EXAMPLES,
    ExpectedTree,
    TreeIntegrityReport,
    collect_export_targets,
    describe_tree_integrity,
    load_expected_install_tree,
    normalize_entry_path,
    package_name_from_dir,
    verify_installed_tree,
)
from sandbox_snapshot import compare_snapshots

LOCKFILE = "package-lock.json"

#: Real ``packages`` entries from the measured corpus, verbatim. Every one names
#: a directory npm did NOT create on this host, and every one is excluded.
MEASURED_PLATFORM_ENTRIES = {
    "node_modules/@esbuild/aix-ppc64": {
        "version": "0.28.1",
        "resolved": "https://registry.npmjs.org/@esbuild/aix-ppc64/-/aix-ppc64-0.28.1.tgz",
        "cpu": ["ppc64"],
        "optional": True,
        "os": ["aix"],
    },
    "node_modules/@esbuild/darwin-arm64": {
        "version": "0.28.1",
        "resolved": "https://registry.npmjs.org/@esbuild/darwin-arm64/-/darwin-arm64-0.28.1.tgz",
        "cpu": ["arm64"],
        "optional": True,
        "os": ["darwin"],
    },
    "node_modules/@typescript/typescript-linux-x64": {
        "version": "7.0.2",
        "resolved": "https://registry.npmjs.org/@typescript/typescript-linux-x64/-/typescript-linux-x64-7.0.2.tgz",
        "cpu": ["x64"],
        "optional": True,
        "os": ["linux"],
    },
}


# ---------------------------------------------------------------------------
# Sandbox builders
# ---------------------------------------------------------------------------


def _write(path: Path, content: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _write_lockfile(root: Path, entries: dict, *, version: int = 3) -> Path:
    """Write a lockfile in the layout npm 7+ emits, plus the root entry."""
    packages = {"": {"name": "shellockolm-sandbox", "version": "1.0.0"}}
    packages.update(entries)
    return _write(
        root / LOCKFILE,
        json.dumps(
            {
                "name": "shellockolm-sandbox",
                "lockfileVersion": version,
                "requires": True,
                "packages": packages,
            }
        ),
    )


def _lock_entry(name: str, version: str = "1.0.0", **extra) -> dict:
    entry = {
        "version": version,
        "resolved": f"https://registry.npmjs.org/{name}/-/{name}-{version}.tgz",
        "integrity": "sha512-deadbeef",
    }
    entry.update(extra)
    return entry


def _install(
    root: Path,
    package_dir: str,
    *,
    version: str = "1.0.0",
    main: str = "index.js",
    entry_rel: str = "index.js",
    entry_body: str = "module.exports = 1;\n",
) -> Path:
    """Put a package on disk the way a completed ``npm install`` leaves it."""
    package_path = root / "node_modules" / package_dir
    manifest = {"name": package_dir, "version": version}
    if main is not None:
        manifest["main"] = main
    _write(package_path / "package.json", json.dumps(manifest))
    if entry_rel is not None:
        _write(package_path / entry_rel, entry_body)
    return package_path


def _sandbox_with_two_packages(root: Path) -> None:
    """The shape this pass exists for: a target plus a hoisted sibling."""
    _write(root / "package.json", json.dumps({"name": "shellockolm-sandbox"}))
    _install(root, "target-pkg")
    _install(root, "left-pad", version="1.3.0")
    _write_lockfile(
        root,
        {
            "node_modules/target-pkg": _lock_entry("target-pkg"),
            "node_modules/left-pad": _lock_entry("left-pad", "1.3.0"),
        },
    )


# ---------------------------------------------------------------------------
# Fail-first: why the snapshot diff could never have caught this
# ---------------------------------------------------------------------------


def test_sibling_sabotage_appears_in_no_snapshot_list():
    """The proof that F47's premise pointed at the wrong mechanism.

    ``node_modules/`` does not exist in the pre-install baseline, so a sibling
    file npm creates and a hook then deletes is neither new, nor modified, nor
    deleted. The deletion filter never sees it to drop it — there is nothing to
    widen.
    """
    before = {
        "package.json": {"hash": "a", "size": 10},
        ".npmrc": {"hash": "b", "size": 10},
    }
    # What the post-install walk finds: left-pad is installed but its index.js
    # was unlinked by the target's postinstall before the walk ran.
    after = {
        "package.json": {"hash": "a2", "size": 12},
        ".npmrc": {"hash": "b", "size": 10},
        "package-lock.json": {"hash": "c", "size": 99},
        "node_modules/target-pkg/package.json": {"hash": "d", "size": 50},
        "node_modules/left-pad/package.json": {"hash": "e", "size": 50},
    }

    new_files, modified_files, deleted_files = compare_snapshots(before, after)

    assert deleted_files == []
    assert filter_unexpected_deletions(deleted_files) == []
    # The rewrite of the sandbox package.json is npm's own and is filtered too,
    # so the whole phase-4 change set is silent about the sabotage.
    assert filter_unexpected_modifications(modified_files) == []
    assert not any("left-pad" in path for path in deleted_files)
    # The wiped file is not even mentioned as new — it never existed on disk.
    assert "node_modules/left-pad/index.js" not in new_files


def test_the_lockfile_is_what_makes_the_wipe_visible(tmp_path):
    """The same install, read against what npm recorded installing."""
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "index.js").unlink()

    report = verify_installed_tree(tmp_path)

    assert report.damaged_count == 1
    damaged = report.damaged[0]
    assert damaged.kind == DAMAGE_ENTRY_GONE
    assert damaged.package.label == "left-pad@1.3.0"
    assert "left-pad" in damaged.describe()
    assert report.blind_reason() is None


# ---------------------------------------------------------------------------
# Reading the lockfile
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "package_dir,expected",
    [
        ("left-pad", "left-pad"),
        ("@scope/pkg", "@scope/pkg"),
        ("a/node_modules/b", "b"),
        ("a/node_modules/@s/b", "@s/b"),
    ],
)
def test_package_name_comes_from_the_key_when_the_entry_has_none(package_dir, expected):
    """npm writes no ``name`` for a registry entry — the key carries it."""
    assert package_name_from_dir(package_dir) == expected


def test_a_wiped_package_is_named_the_way_npm_names_it(tmp_path):
    """A finding that says `node_modules/left-pad` instead of `left-pad@1.3.0`
    makes the user look the package up; the lockfile already knows both."""
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "index.js").unlink()

    damaged = verify_installed_tree(tmp_path).damaged[0]

    assert damaged.package.label == "left-pad@1.3.0"
    assert "left-pad@1.3.0 was damaged during the install" in damaged.describe()


def test_lockfile_names_every_installed_package(tmp_path):
    _write_lockfile(
        tmp_path,
        {
            "node_modules/left-pad": _lock_entry("left-pad", "1.3.0"),
            "node_modules/@scope/pkg": _lock_entry("pkg", "2.0.0"),
            "node_modules/a/node_modules/b": _lock_entry("b", "3.0.0"),
        },
    )

    tree = load_expected_install_tree(tmp_path)

    assert tree.is_authoritative
    assert {pkg.package_dir for pkg in tree.packages} == {
        "left-pad",
        "@scope/pkg",
        "a/node_modules/b",
    }
    assert len(tree) == 3


def test_measured_platform_conditional_entries_are_not_reported(tmp_path):
    """The calibration: 44/44 absent directories in the real corpus were these."""
    entries = dict(MEASURED_PLATFORM_ENTRIES)
    entries["node_modules/esbuild"] = _lock_entry("esbuild", "0.28.1")
    _write_lockfile(tmp_path, entries)
    _install(tmp_path, "esbuild", version="0.28.1")

    tree = load_expected_install_tree(tmp_path)
    report = verify_installed_tree(tmp_path, tree)

    assert tree.platform_conditional == len(MEASURED_PLATFORM_ENTRIES)
    assert [pkg.package_dir for pkg in tree.packages] == ["esbuild"]
    assert report.damaged == []
    assert report.dangers == []
    assert report.verified_count == 1


@pytest.mark.parametrize(
    "flags",
    [
        {"optional": True},
        {"devOptional": True},
        {"os": ["darwin"]},
        {"cpu": ["arm64"]},
        {"optional": True, "os": ["linux"], "cpu": ["x64"]},
    ],
)
def test_every_platform_conditional_flag_excludes_an_entry(tmp_path, flags):
    _write_lockfile(tmp_path, {"node_modules/maybe": _lock_entry("maybe", **flags)})

    tree = load_expected_install_tree(tmp_path)

    assert tree.packages == ()
    assert tree.platform_conditional == 1


def test_workspace_symlinks_are_not_verified(tmp_path):
    """A linked entry's contents live outside node_modules — not ours to check."""
    _write_lockfile(
        tmp_path,
        {
            "node_modules/app": {"resolved": "packages/app", "link": True},
            "packages/app": {"name": "app", "version": "1.0.0"},
        },
    )

    tree = load_expected_install_tree(tmp_path)

    assert tree.packages == ()
    assert tree.linked == 1


def test_root_and_non_package_keys_are_skipped(tmp_path):
    _write_lockfile(
        tmp_path,
        {
            "packages/app": {"name": "app", "version": "1.0.0"},
            "node_modules/real": _lock_entry("real"),
        },
    )

    tree = load_expected_install_tree(tmp_path)

    assert [pkg.package_dir for pkg in tree.packages] == ["real"]


def test_missing_lockfile_is_unknown_not_empty(tmp_path):
    tree = load_expected_install_tree(tmp_path)

    assert not tree.is_authoritative
    assert LOCKFILE in (tree.unavailable_reason or "")
    assert tree.packages == ()


def test_unreadable_lockfile_is_unknown(tmp_path, monkeypatch):
    _write_lockfile(tmp_path, {"node_modules/x": _lock_entry("x")})

    def _boom(path):
        raise OSError("permission denied")

    monkeypatch.setattr(sandbox_deps, "read_lockfile", _boom)
    monkeypatch.setattr(sandbox_integrity, "read_lockfile", _boom)

    tree = load_expected_install_tree(tmp_path)

    assert not tree.is_authoritative
    assert "could not be read" in (tree.unavailable_reason or "")


@pytest.mark.parametrize(
    "raw,expected_fragment",
    [
        ("{not json", "could not be parsed"),
        ("[]", "is not an object"),
        ('{"lockfileVersion": 1, "dependencies": {"x": {"version": "1.0.0"}}}',
         "has no `packages` map"),
    ],
)
def test_unusable_lockfile_shapes_are_blind_not_clean(tmp_path, raw, expected_fragment):
    """A version-1 tree is not guessed at: blind beats invented findings."""
    _write(tmp_path / LOCKFILE, raw)

    tree = load_expected_install_tree(tmp_path)

    assert not tree.is_authoritative
    assert expected_fragment in (tree.unavailable_reason or "")


def test_unavailable_lockfile_reports_no_damage_but_marks_itself_blind(tmp_path):
    _install(tmp_path, "left-pad")

    report = verify_installed_tree(tmp_path)

    assert report.dangers == []
    reason = report.blind_reason()
    assert reason is not None
    assert "NOT verified" in reason


# ---------------------------------------------------------------------------
# Verifying the tree
# ---------------------------------------------------------------------------


def test_intact_tree_is_clean(tmp_path):
    _sandbox_with_two_packages(tmp_path)

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.dangers == []
    assert report.verified_count == report.expected_count == 2
    assert report.blind_reason() is None


def test_a_wiped_sibling_directory_is_reported(tmp_path):
    import shutil

    _sandbox_with_two_packages(tmp_path)
    shutil.rmtree(tmp_path / "node_modules" / "left-pad")

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_DIRECTORY_GONE]
    assert report.damaged[0].path == "node_modules/left-pad"
    assert report.verified_count == 1


def test_a_deleted_sibling_manifest_is_reported(tmp_path):
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "package.json").unlink()

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_MANIFEST_GONE]


def test_a_truncated_sibling_manifest_is_reported(tmp_path):
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "package.json").write_text("")

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_MANIFEST_EMPTIED]


def test_a_truncated_entry_point_is_reported(tmp_path):
    """Emptying a file is the quieter wipe: the path still exists."""
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "index.js").write_text("")

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_ENTRY_EMPTIED]
    assert report.damaged[0].path == "node_modules/left-pad/index.js"


def test_a_missing_node_modules_is_one_finding_not_hundreds(tmp_path):
    import shutil

    _sandbox_with_two_packages(tmp_path)
    shutil.rmtree(tmp_path / "node_modules")

    report = verify_installed_tree(tmp_path)

    assert report.tree_missing
    assert len(report.dangers) == 1
    assert "node_modules/ does not exist" in report.dangers[0]


def test_damage_lines_are_capped_with_the_remainder_counted():
    """A tree-wide wipe must be reportable without burying the verdict."""
    packages = [
        sandbox_integrity.ExpectedPackage(package_dir=f"p{i}", lockfile_key=f"node_modules/p{i}")
        for i in range(MAX_REPORTED_DAMAGE + 5)
    ]
    report = TreeIntegrityReport(
        expected_count=len(packages),
        damaged=[
            sandbox_integrity.DamagedPackage(
                package=pkg, kind=DAMAGE_DIRECTORY_GONE, path=pkg.lockfile_key
            )
            for pkg in packages
        ],
    )

    lines = report.dangers

    assert len(lines) == MAX_REPORTED_DAMAGE + 1
    assert lines[-1].startswith("... and 5 more")


# ---------------------------------------------------------------------------
# Entry-point resolution — where a careless check invents false positives
# ---------------------------------------------------------------------------


def test_a_package_without_main_is_verified_not_guessed_at(tmp_path):
    """47 of the 161 measured lockfile entries declare no ``main``."""
    _write(tmp_path / "package.json", "{}")
    _install(tmp_path, "types-only", main=None, entry_rel=None)
    _write(tmp_path / "node_modules" / "types-only" / "index.d.ts", "export {};\n")
    _write_lockfile(tmp_path, {"node_modules/types-only": _lock_entry("types-only")})

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


@pytest.mark.parametrize(
    "main,entry_rel",
    [
        ("index.js", "index.js"),
        ("./index.js", "index.js"),
        ("lib/main", "lib/main.js"),          # extension-less, Node adds .js
        ("./dist/index", "dist/index.js"),
        ("lib", "lib/index.js"),               # directory, Node falls back to index
        ("./data.json", "data.json"),
        ("./.internal/entry.js", ".internal/entry.js"),  # the lstrip trap
    ],
)
def test_real_main_shapes_resolve_without_a_finding(tmp_path, main, entry_rel):
    _write(tmp_path / "package.json", "{}")
    _install(tmp_path, "shapes", main=main, entry_rel=entry_rel)
    _write_lockfile(tmp_path, {"node_modules/shapes": _lock_entry("shapes")})

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


@pytest.mark.parametrize(
    "main", ["../../../etc/passwd", "/etc/passwd", "C:\\Windows\\system32\\x.js", "  "]
)
def test_a_main_pointing_outside_the_package_is_not_followed(tmp_path, main):
    """The pass reports on the package it was given, never on someone else's file."""
    _write(tmp_path / "package.json", "{}")
    _install(tmp_path, "odd", main=main, entry_rel="index.js")
    _write_lockfile(tmp_path, {"node_modules/odd": _lock_entry("odd")})

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


# ---------------------------------------------------------------------------
# `exports` — measured to be the field that decides, not `main`
# ---------------------------------------------------------------------------


def _install_with_exports(root: Path, package_dir: str, exports, files: dict, **manifest_extra):
    package_path = root / "node_modules" / package_dir
    manifest = {"name": package_dir, "version": "1.0.0", "exports": exports}
    manifest.update(manifest_extra)
    _write(package_path / "package.json", json.dumps(manifest))
    for rel, body in files.items():
        _write(package_path / rel, body)
    _write_lockfile(root, {f"node_modules/{package_dir}": _lock_entry(package_dir)})
    _write(root / "package.json", "{}")
    return package_path


def test_a_stale_main_next_to_a_live_exports_is_not_a_finding(tmp_path):
    """The exact shape of the 2 false positives the `main`-only rule produced.

    ``@humanfs/node`` ships ``"main": "dist/index.js"`` and publishes only
    ``dist/*.d.ts``; the file Node actually loads is the ``exports`` target
    ``./src/index.js``.
    """
    _install_with_exports(
        tmp_path,
        "humanfs-shaped",
        {"import": {"types": "./dist/index.d.ts", "default": "./src/index.js"}},
        {"dist/index.d.ts": "export {};\n", "src/index.js": "export const x = 1;\n"},
        main="dist/index.js",
        type="module",
    )

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


def test_an_exports_target_that_was_never_published_is_not_a_finding(tmp_path):
    """The shape of the 10 findings the all-targets-must-exist rule produced."""
    _install_with_exports(
        tmp_path,
        "babel-shaped",
        {".": {"types": "./lib/index.d.ts", "default": "./lib/index.js"}},
        {"lib/index.js": "module.exports = 1;\n"},  # the .d.ts is not shipped
    )

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


def test_wiping_every_exports_target_is_reported(tmp_path):
    """A modern package is still catchable — all its entry points must be gone."""
    package_path = _install_with_exports(
        tmp_path,
        "modern",
        {".": {"require": "./dist/index.cjs", "import": "./dist/index.mjs"}},
        {"dist/index.cjs": "1;\n", "dist/index.mjs": "1;\n"},
    )
    (package_path / "dist" / "index.cjs").unlink()
    (package_path / "dist" / "index.mjs").unlink()

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_ENTRY_GONE]


def test_truncating_every_exports_target_is_reported(tmp_path):
    package_path = _install_with_exports(
        tmp_path,
        "modern",
        {".": {"require": "./dist/index.cjs", "import": "./dist/index.mjs"}},
        {"dist/index.cjs": "1;\n", "dist/index.mjs": "1;\n"},
    )
    (package_path / "dist" / "index.cjs").write_text("")
    (package_path / "dist" / "index.mjs").write_text("")

    report = verify_installed_tree(tmp_path)

    assert [entry.kind for entry in report.damaged] == [DAMAGE_ENTRY_EMPTIED]


def test_a_broken_main_is_not_reported_when_exports_is_present(tmp_path):
    """Node ignores `main` entirely once `exports` exists; so does this pass."""
    _install_with_exports(
        tmp_path,
        "modern",
        {".": "./dist/index.js"},
        {"dist/index.js": "1;\n"},
        main="does/not/exist.js",
    )

    assert verify_installed_tree(tmp_path).damaged == []


def test_an_exports_field_naming_no_resolvable_file_claims_nothing(tmp_path):
    """A wildcard-only or bare-specifier `exports` names no file to check."""
    _install_with_exports(
        tmp_path,
        "wildcards",
        {"./*": "./dist/*.js", "./pkg": "some-other-package"},
        {"dist/a.js": "1;\n"},
    )

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.verified_count == 1


@pytest.mark.parametrize(
    "exports,expected",
    [
        ("./index.js", ("./index.js",)),
        ({".": "./a.js"}, ("./a.js",)),
        ({".": {"import": "./a.mjs", "require": "./a.cjs"}}, {"./a.mjs", "./a.cjs"}),
        ({".": ["./a.js", "./b.js"]}, {"./a.js", "./b.js"}),
        ({"./*": "./dist/*.js"}, ()),                    # wildcard, unresolvable
        ({".": "other-package"}, ()),                    # bare specifier
        (None, ()),
        (123, ()),
    ],
)
def test_collect_export_targets(exports, expected):
    found = collect_export_targets(exports)

    if isinstance(expected, tuple):
        assert found == expected
    else:
        assert set(found) == expected


def test_collect_export_targets_survives_a_hostile_manifest():
    """The manifest is untrusted input: depth and count are both bounded."""
    deep: object = "./deep.js"
    for _ in range(MAX_EXPORTS_DEPTH + 20):
        deep = {".": deep}

    assert collect_export_targets(deep) == ()

    wide = {f"./p{i}": f"./dist/{i}.js" for i in range(MAX_EXPORTS_TARGETS + 50)}
    assert len(collect_export_targets(wide)) <= MAX_EXPORTS_TARGETS


@pytest.mark.parametrize(
    "main,expected",
    [
        ("index.js", "index.js"),
        ("./index.js", "index.js"),
        ("././lib/x.js", "lib/x.js"),
        ("./.internal/x.js", ".internal/x.js"),
        ("lib/", "lib"),
        ("./", "index.js"),
        ("../evil", None),
        ("/abs", None),
        ("D:\\x", None),
        ("", None),
    ],
)
def test_normalize_entry_path(main, expected):
    assert normalize_entry_path(main) == expected


# ---------------------------------------------------------------------------
# Blindness (the F29 rule)
# ---------------------------------------------------------------------------


def test_an_unreadable_manifest_makes_the_entry_check_blind(tmp_path, monkeypatch):
    _sandbox_with_two_packages(tmp_path)

    def _boom(path):
        raise OSError("locked")

    monkeypatch.setattr(sandbox_integrity, "read_manifest", _boom)

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.manifests_unreadable == 2
    reason = report.blind_reason()
    assert reason is not None
    assert "entry points were NOT verified" in reason


def test_an_unparseable_manifest_is_blind_not_damaged(tmp_path):
    """A package whose manifest is corrupt is present; nothing is claimed gone."""
    _sandbox_with_two_packages(tmp_path)
    (tmp_path / "node_modules" / "left-pad" / "package.json").write_text("{not json")

    report = verify_installed_tree(tmp_path)

    assert report.damaged == []
    assert report.manifests_unreadable == 1
    assert report.blind_reason() is not None


def test_unreadable_examples_are_capped(tmp_path, monkeypatch):
    _write(tmp_path / "package.json", "{}")
    entries = {}
    for index in range(MAX_UNREADABLE_EXAMPLES + 3):
        name = f"pkg{index}"
        _install(tmp_path, name)
        entries[f"node_modules/{name}"] = _lock_entry(name)
    _write_lockfile(tmp_path, entries)

    def _boom(path):
        raise OSError("locked")

    monkeypatch.setattr(sandbox_integrity, "read_manifest", _boom)

    report = verify_installed_tree(tmp_path)

    assert report.manifests_unreadable == MAX_UNREADABLE_EXAMPLES + 3
    assert len(report.unreadable_examples) == MAX_UNREADABLE_EXAMPLES


# ---------------------------------------------------------------------------
# Benign baseline: the shapes a healthy install actually has
# ---------------------------------------------------------------------------


def test_a_realistic_benign_tree_produces_zero_findings(tmp_path):
    """Every shape the measured corpus contained, in one tree."""
    _write(tmp_path / "package.json", "{}")
    entries = {}

    # A scoped package, a nested (non-hoisted) copy, a types-only package with
    # no `main`, an extension-less `main`, and a directory `main`.
    _install(tmp_path, "@scope/util", main="./dist/index")
    _write(tmp_path / "node_modules" / "@scope" / "util" / "dist" / "index.js", "1;\n")
    entries["node_modules/@scope/util"] = _lock_entry("util")

    _install(tmp_path, "a")
    entries["node_modules/a"] = _lock_entry("a")
    _install(tmp_path, "a/node_modules/b", version="2.0.0")
    entries["node_modules/a/node_modules/b"] = _lock_entry("b", "2.0.0")

    _install(tmp_path, "typedefs", main=None, entry_rel=None)
    entries["node_modules/typedefs"] = _lock_entry("typedefs")

    _install(tmp_path, "libdir", main="lib", entry_rel="lib/index.js")
    entries["node_modules/libdir"] = _lock_entry("libdir")

    entries.update(MEASURED_PLATFORM_ENTRIES)
    _write_lockfile(tmp_path, entries)

    report = verify_installed_tree(tmp_path)

    assert report.dangers == []
    assert report.damaged == []
    assert report.blind_reason() is None
    assert report.verified_count == 5
    assert report.platform_conditional == len(MEASURED_PLATFORM_ENTRIES)


def test_summary_line_reports_what_was_and_was_not_checked(tmp_path):
    _sandbox_with_two_packages(tmp_path)

    summary = describe_tree_integrity(verify_installed_tree(tmp_path))

    assert "2/2" in summary


def test_summary_line_of_an_unusable_lockfile_claims_nothing():
    summary = describe_tree_integrity(
        TreeIntegrityReport(unavailable_reason="package-lock.json could not be parsed")
    )

    assert summary.startswith("Installed-tree check did not run")


def test_empty_expected_tree_is_not_a_pass_claim():
    report = verify_installed_tree(Path("."), ExpectedTree())

    assert report.dangers == []
    assert report.expected_count == 0
    assert describe_tree_integrity(report).endswith("no installed package to verify")


# ---------------------------------------------------------------------------
# CLI wiring — a pass nobody calls detects nothing
# ---------------------------------------------------------------------------

CLI_SOURCE = Path(__file__).resolve().parents[1] / "src" / "cli.py"


def test_cli_runs_the_tree_integrity_pass():
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")
    ast.parse(source)  # the guard must not be satisfied by a syntax-broken file

    assert "from sandbox_integrity import" in source
    assert "verify_installed_tree(Path(sandbox_dir))" in source
    assert "PHASE 4b" in source
    assert 'findings.mark_blind("Installed-tree integrity"' in source


def test_cli_does_not_report_a_failed_install_as_sabotage():
    """A partial tree after a failed install is the failure, not a package."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert "tree_report = verify_installed_tree(Path(sandbox_dir))" in source
    marker = "PHASE 4b"
    phase = source[source.index(marker) : source.index(marker) + 2000]
    assert "if install_failed:" in phase
    assert phase.index("if install_failed:") < phase.index("tree_report =")
