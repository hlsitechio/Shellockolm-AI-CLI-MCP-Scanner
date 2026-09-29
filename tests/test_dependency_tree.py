"""Tests for the npm dependency-tree builder (build-loop follow-up F30).

The bug F30 tracked was that the tree walked only an entry's NESTED
``dependencies`` and ignored the edges npm hoists. On a modern lockfile that is
not an under-report but a total failure:

* **lockfileVersion 3** has no legacy ``dependencies`` mirror at all, so the
  builder read an absent key and returned an EMPTY tree (0 nodes, depth 0) for
  every npm v7+ project.
* **lockfileVersion 2** keeps the mirror, but nearly every edge lives in an
  entry's ``requires`` map pointing at a top-level (hoisted) sibling, so only
  the handful of conflict-nested installs were ever walked.

Coverage here is three layers:

* **Unit** — the two pure resolution primitives where the correctness risk
  lives: ``_package_name_from_path`` (the name is what follows the LAST
  ``node_modules/`` segment) and ``_resolve_pkg_path`` (node's own
  nearest-``node_modules`` walk, so a nested copy shadows the hoisted one).
* **Graph shape** — hoisted-only edges, a nested override of a hoisted dep, and
  a cycle, exercised through BOTH the ``packages`` path (v2/v3) and the legacy
  ``requires`` mirror, plus the dedupe/budget guards that keep a hoisted DAG
  from expanding exponentially.
* **No fabricated edges** — a property over the repo's own real lockfile: every
  parent→child edge the tree emits must be declared by that parent in the
  lockfile. This is the invariant that would catch an over-eager resolver.
"""

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import dependency_tree  # noqa: E402
from dependency_tree import DependencyTreeVisualizer  # noqa: E402

REPO_ROOT = Path(__file__).resolve().parents[1]
REAL_LOCKFILE = REPO_ROOT / "website" / "package-lock.json"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def write_lock(tmp_path: Path, data: dict) -> str:
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def pkg(version="1.0.0", **extra) -> dict:
    entry = {"version": version, "resolved": f"https://registry.npmjs.org/x/-/x-{version}.tgz"}
    entry.update(extra)
    return entry


def edges(deps: dict) -> set:
    """Every parent→child name pair in a built tree ('' is the root)."""
    found = set()

    def walk(node, parent):
        found.add((parent, node.name))
        for child in node.dependencies.values():
            walk(child, node.name)

    for node in deps.values():
        walk(node, "")
    return found


def find(deps: dict, path: list):
    """Descend a tree by a list of package names."""
    node = deps[path[0]]
    for name in path[1:]:
        node = node.dependencies[name]
    return node


# ---------------------------------------------------------------------------
# unit: _package_name_from_path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "pkg_path,expected",
    [
        ("node_modules/left-pad", "left-pad"),
        ("node_modules/@scope/pkg", "@scope/pkg"),
        # The name is the LAST segment: a nested install belongs to the nested
        # package, not to its host. The old code stripped EVERY "node_modules/"
        # occurrence and so attributed this to "a".
        ("node_modules/a/node_modules/b", "b"),
        ("node_modules/a/node_modules/@scope/b", "@scope/b"),
        ("node_modules/@s/a/node_modules/b", "b"),
        # A workspace entry is a local link, not a resolved dependency.
        ("packages/my-app", ""),
        ("", ""),
    ],
)
def test_package_name_from_path(pkg_path, expected):
    assert DependencyTreeVisualizer._package_name_from_path(pkg_path) == expected


# ---------------------------------------------------------------------------
# unit: _resolve_pkg_path
# ---------------------------------------------------------------------------

def test_resolve_pkg_path_finds_hoisted_from_root():
    packages = {"": {}, "node_modules/a": {}, "node_modules/b": {}}
    assert DependencyTreeVisualizer._resolve_pkg_path(packages, "", "b") == "node_modules/b"


def test_resolve_pkg_path_nested_shadows_hoisted():
    """A package's own node_modules wins over the hoisted copy."""
    packages = {
        "": {},
        "node_modules/a": {},
        "node_modules/b": {},
        "node_modules/a/node_modules/b": {},
    }
    resolved = DependencyTreeVisualizer._resolve_pkg_path(packages, "node_modules/a", "b")
    assert resolved == "node_modules/a/node_modules/b"


def test_resolve_pkg_path_walks_up_to_ancestor_then_top_level():
    packages = {"": {}, "node_modules/a": {}, "node_modules/a/node_modules/b": {}, "node_modules/c": {}}
    # From deep inside a/b, `c` is only at the top level.
    resolved = DependencyTreeVisualizer._resolve_pkg_path(
        packages, "node_modules/a/node_modules/b", "c"
    )
    assert resolved == "node_modules/c"


def test_resolve_pkg_path_unresolvable_returns_none():
    packages = {"": {}, "node_modules/a": {}}
    assert DependencyTreeVisualizer._resolve_pkg_path(packages, "", "ghost") is None
    assert DependencyTreeVisualizer._resolve_pkg_path(packages, "node_modules/a", "ghost") is None


# ---------------------------------------------------------------------------
# packages map (lockfileVersion 2 / 3) — the F30 core
# ---------------------------------------------------------------------------

def test_v3_lockfile_builds_a_tree_at_all(tmp_path):
    """Regression guard: a v3 lockfile has NO `dependencies` mirror.

    Reading only that absent key returned an empty tree for every npm v7+
    project — the flagship symptom F30 describes.
    """
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^2.0.0"}),
            "node_modules/b": pkg("2.0.0"),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    assert set(deps) == {"a"}
    assert v.get_stats()["total_packages"] == 2
    assert v.get_stats()["max_depth"] == 2


def test_hoisted_only_edge_is_followed(tmp_path):
    """`a` depends on `b`, and npm hoisted `b` to the top level."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^2.0.0"}),
            "node_modules/b": pkg("2.0.0", dependencies={"c": "^3.0.0"}),
            "node_modules/c": pkg("3.0.0"),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    assert edges(deps) == {("", "a"), ("a", "b"), ("b", "c")}
    assert find(deps, ["a", "b", "c"]).version == "3.0.0"
    assert v.get_stats()["max_depth"] == 3


def test_nested_install_overrides_hoisted_version(tmp_path):
    """`a` pins b@1 in its own node_modules while b@2 is hoisted for the root."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0", "b": "^2.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^1.0.0"}),
            "node_modules/a/node_modules/b": pkg("1.9.9"),
            "node_modules/b": pkg("2.0.0"),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    assert find(deps, ["a", "b"]).version == "1.9.9"  # the nested pin
    assert find(deps, ["b"]).version == "2.0.0"       # the hoisted copy
    stats = v.get_stats()
    assert stats["multi_version_packages"] == {"b": ["1.9.9", "2.0.0"]}
    assert stats["duplicate_count"] == 1  # one name at multiple versions


def test_cycle_terminates_and_is_recorded(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^1.0.0"}),
            "node_modules/b": pkg("1.0.0", dependencies={"a": "^1.0.0"}),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    looped = find(deps, ["a", "b", "a"])
    assert looped.circular_ref is True
    assert looped.dependencies == {}          # the walk stopped
    assert ("b", "a") in v.get_stats()["circular_references"]


def test_repeat_occurrence_is_deduped_not_re_expanded(tmp_path):
    """Diamond: root→a→shared and root→b→shared.

    A hoisted lockfile is a DAG; expanding every path is exponential. The second
    occurrence is a leaf marked `duplicate` (npm's "deduped"), so `shared`'s own
    subtree is rendered exactly once.
    """
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"shared": "^1.0.0"}),
            "node_modules/b": pkg("1.0.0", dependencies={"shared": "^1.0.0"}),
            "node_modules/shared": pkg("1.0.0", dependencies={"deep": "^1.0.0"}),
            "node_modules/deep": pkg("1.0.0"),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    first = find(deps, ["a", "shared"])
    second = find(deps, ["b", "shared"])
    assert first.duplicate is False and "deep" in first.dependencies
    assert second.duplicate is True and second.dependencies == {}
    assert v.get_stats()["deduped_nodes"] == 1


def test_dev_optional_and_peer_edges(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"d": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", peerDependencies={"p": "^1.0.0"},
                                  optionalDependencies={"o": "^1.0.0"}),
            "node_modules/d": pkg("1.0.0", dev=True),
            "node_modules/p": pkg("1.0.0", peer=True),
            "node_modules/o": pkg("1.0.0", optional=True),
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    assert deps["d"].dev is True
    assert find(deps, ["a", "p"]).peer is True
    assert find(deps, ["a", "o"]).optional is True


def test_declared_but_uninstalled_dep_is_skipped(tmp_path):
    """An unmet optional/peer dep has no `packages` entry — there is nothing to point at."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", optionalDependencies={"never-installed": "^1.0.0"}),
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert deps["a"].dependencies == {}


def test_platform_specific_optional_deps_recorded_in_the_lockfile_are_included(tmp_path):
    """The lockfile, not this machine, is the source of truth.

    npm records EVERY platform variant of an optional binary dep (esbuild's
    per-arch binaries and friends) in `packages`, but installs only the matching
    one — so `npm ls` on Windows hides the linux binary that CI will pull. A
    scanner reading the lockfile must report what any platform would install.
    """
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"bundler": "^1.0.0"}},
            "node_modules/bundler": pkg("1.0.0", optionalDependencies={
                "@bin/linux-x64": "1.0.0", "@bin/win32-x64": "1.0.0",
            }),
            "node_modules/@bin/linux-x64": pkg("1.0.0", optional=True, os=["linux"]),
            "node_modules/@bin/win32-x64": pkg("1.0.0", optional=True, os=["win32"]),
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert set(deps["bundler"].dependencies) == {"@bin/linux-x64", "@bin/win32-x64"}


def test_shallowest_occurrence_expands_so_a_root_dep_is_never_a_deduped_leaf(tmp_path):
    """`shared` is a direct dep AND a transitive peer of `a`.

    Depth-first expansion reached it through `a` first and demoted the ROOT
    entry to a bare "deduped" leaf. Breadth-first gives the shallowest
    occurrence the full subtree, matching `npm ls`.
    """
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0", "shared": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"shared": "^1.0.0"}),
            "node_modules/shared": pkg("1.0.0", dependencies={"deep": "^1.0.0"}),
            "node_modules/deep": pkg("1.0.0"),
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)

    assert deps["shared"].duplicate is False
    assert "deep" in deps["shared"].dependencies
    assert find(deps, ["a", "shared"]).duplicate is True


def test_workspace_link_is_followed_to_its_real_entry(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"my-lib": "workspace:*"}},
            "node_modules/my-lib": {"resolved": "packages/my-lib", "link": True},
            "packages/my-lib": {"version": "4.2.0", "dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0"),
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)

    assert deps["my-lib"].version == "4.2.0"
    assert "a" in deps["my-lib"].dependencies


def test_v2_lockfile_prefers_packages_over_legacy_mirror(tmp_path):
    """v2 carries BOTH sections; `packages` is the authoritative one.

    The legacy mirror lists every hoisted package at its top level, so reading it
    as the root's direct deps makes every transitive package a root child.
    """
    lock = write_lock(tmp_path, {
        "lockfileVersion": 2,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^1.0.0"}),
            "node_modules/b": pkg("1.0.0"),
        },
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^1.0.0"}},
            "b": {"version": "1.0.0"},
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)

    assert set(deps) == {"a"}          # only the real root dep
    assert set(deps["a"].dependencies) == {"b"}


# ---------------------------------------------------------------------------
# legacy `requires` mirror (v1, and v2 with no `packages` section)
# ---------------------------------------------------------------------------

def test_v1_requires_resolves_against_hoisted_top_level(tmp_path):
    """The literal F30 fix: `requires` names live at the lockfile's top level."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^2.0.0"}},
            "b": {"version": "2.0.0", "requires": {"c": "^3.0.0"}},
            "c": {"version": "3.0.0"},
        },
    })
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(lock)

    assert find(deps, ["a", "b", "c"]).version == "3.0.0"
    assert v.get_stats()["max_depth"] == 3


def test_v1_nested_copy_wins_over_hoisted(tmp_path):
    """A nested entry is the version actually installed for that parent."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {
                "version": "1.0.0",
                "requires": {"b": "^1.0.0"},
                "dependencies": {"b": {"version": "1.9.9"}},
            },
            "b": {"version": "2.0.0"},
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert find(deps, ["a", "b"]).version == "1.9.9"


def test_v1_requires_cycle_terminates(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^1.0.0"}},
            "b": {"version": "1.0.0", "requires": {"a": "^1.0.0"}},
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    looped = find(deps, ["a", "b", "a"])
    assert looped.circular_ref is True
    assert looped.dependencies == {}


def test_legacy_requires_true_is_not_treated_as_a_map(tmp_path):
    """Old npm writes `"requires": true`; iterating that would crash."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "requires": True}},
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert deps["a"].dependencies == {}


def test_v2_falls_back_to_legacy_mirror_when_packages_absent(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 2,
        "dependencies": {
            "a": {"version": "1.0.0", "requires": {"b": "^2.0.0"}},
            "b": {"version": "2.0.0"},
        },
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert find(deps, ["a", "b"]).version == "2.0.0"


def test_legacy_unresolvable_require_is_skipped(tmp_path):
    lock = write_lock(tmp_path, {
        "lockfileVersion": 1,
        "dependencies": {"a": {"version": "1.0.0", "requires": {"ghost": "^1.0.0"}}},
    })
    deps = DependencyTreeVisualizer().parse_package_lock(lock)
    assert deps["a"].dependencies == {}


# ---------------------------------------------------------------------------
# guards
# ---------------------------------------------------------------------------

def test_reparsing_on_one_instance_is_idempotent(tmp_path):
    """`find_package` parses again on the same visualizer — counters must not accrue."""
    lock = write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^1.0.0"}),
            "node_modules/b": pkg("1.0.0"),
        },
    })
    v = DependencyTreeVisualizer()
    v.parse_package_lock(lock)
    first = v.get_stats()
    v.parse_package_lock(lock)
    assert v.get_stats() == first


def test_depth_budget_truncates_instead_of_recursing_forever(tmp_path, monkeypatch):
    packages = {"": {"dependencies": {"p0": "^1.0.0"}}}
    for i in range(12):
        packages[f"node_modules/p{i}"] = pkg("1.0.0", dependencies={f"p{i + 1}": "^1.0.0"})
    packages["node_modules/p12"] = pkg("1.0.0")
    lock = write_lock(tmp_path, {"lockfileVersion": 3, "packages": packages})

    monkeypatch.setattr(dependency_tree, "MAX_TREE_DEPTH", 4)
    v = DependencyTreeVisualizer()
    v.parse_package_lock(lock)

    assert v.get_stats()["truncated"] is True
    assert v.get_stats()["max_depth"] <= 5


def test_node_budget_truncates(tmp_path, monkeypatch):
    packages = {"": {"dependencies": {f"p{i}": "^1.0.0" for i in range(20)}}}
    for i in range(20):
        packages[f"node_modules/p{i}"] = pkg("1.0.0")
    lock = write_lock(tmp_path, {"lockfileVersion": 3, "packages": packages})

    monkeypatch.setattr(dependency_tree, "MAX_TREE_NODES", 5)
    v = DependencyTreeVisualizer()
    v.parse_package_lock(lock)
    assert v.get_stats()["truncated"] is True


def test_renderers_accept_the_expanded_tree(tmp_path):
    """The hoisted tree must survive every output format."""
    write_lock(tmp_path, {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"a": "^1.0.0"}},
            "node_modules/a": pkg("1.0.0", dependencies={"b": "^1.0.0"}),
            "node_modules/b": pkg("1.0.0", dependencies={"a": "^1.0.0"}),
        },
    })
    (tmp_path / "package.json").write_text(json.dumps({"name": "demo"}), encoding="utf-8")

    v = DependencyTreeVisualizer()
    ascii_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.ASCII)
    json_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.JSON)
    dot_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.DOT)

    assert "a@1.0.0" in ascii_out and "b@1.0.0" in ascii_out
    assert json.loads(json_out)["a"]["dependencies"]["b"]["name"] == "b"
    assert "digraph dependencies" in dot_out and '"demo" -> "a@1.0.0"' in dot_out


# ---------------------------------------------------------------------------
# real lockfile: the tree must be non-empty AND invent no edges
# ---------------------------------------------------------------------------

@pytest.mark.skipif(not REAL_LOCKFILE.exists(), reason="website lockfile not present")
def test_real_lockfile_tree_is_populated_and_matches_package_json():
    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(str(REAL_LOCKFILE))

    manifest = json.loads((REAL_LOCKFILE.parent / "package.json").read_text(encoding="utf-8"))
    declared = set(manifest.get("dependencies", {})) | set(manifest.get("devDependencies", {}))

    # Before the fix this lockfile (v3) produced ZERO nodes.
    assert set(deps) == declared
    stats = v.get_stats()
    assert stats["total_packages"] > len(declared)
    assert stats["max_depth"] > 1
    assert stats["truncated"] is False


@pytest.mark.skipif(not REAL_LOCKFILE.exists(), reason="website lockfile not present")
def test_real_lockfile_tree_invents_no_edges():
    """Every emitted edge must be declared by its parent in the lockfile.

    This is the invariant an over-eager resolver would break — the tree may
    under-report, but it must never claim a dependency npm does not record.
    """
    data = json.loads(REAL_LOCKFILE.read_text(encoding="utf-8"))
    packages = data["packages"]

    declared_by = {}
    for path, info in packages.items():
        name = DependencyTreeVisualizer._package_name_from_path(path) or ""
        names = set()
        for section in ("dependencies", "devDependencies", "optionalDependencies",
                        "peerDependencies"):
            names |= set(info.get(section, {}))
        declared_by.setdefault(name, set()).update(names)

    v = DependencyTreeVisualizer()
    deps = v.parse_package_lock(str(REAL_LOCKFILE))

    for parent, child in edges(deps):
        assert child in declared_by.get(parent, set()), f"{parent} does not declare {child}"
