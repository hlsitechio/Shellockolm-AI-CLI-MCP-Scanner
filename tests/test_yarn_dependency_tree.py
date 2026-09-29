"""Tests for the yarn dependency-tree builder (build-loop follow-up F32).

F30 fixed this class of bug for npm; F32 is the same bug still open for yarn.
``parse_yarn_lock`` read only each block's ``version`` / ``resolved`` /
``integrity`` properties and never looked at its ``dependencies:`` sub-block, so:

* **no node ever got a child** — every installed package was emitted as a
  ``depth=1`` root and the "tree" was an alphabetical list. Measured on the
  vendored fixture: 84 roots, **0 edges**, ``max_depth`` 0.
* **two versions of one package collapsed** — entries were keyed by bare name
  (``if name not in root_deps``), so a project with ``ms@2.0.0`` *and*
  ``ms@2.1.3`` installed reported only whichever block was parsed first.
* **the root's real direct dependencies were never distinguished** from
  transitive ones. They live in ``package.json``, not the lockfile.

Coverage here mirrors the F30 layout:

* **Unit** — the two pure primitives where the correctness risk lives:
  ``_split_yarn_descriptor`` (split at the FIRST ``@`` after index 0, so a scope
  keeps its leading ``@`` and an npm alias is not turned into a package called
  ``foo@npm:bar``) and ``_split_yarn_line`` (one grammar covering v1's
  space-separated form and berry's colon form).
* **Graph shape** — hand-written lockfiles exercising multi-version resolution,
  optional/dev marking, cycles, dedupe, the peer-is-not-an-edge rule, the
  unresolvable-edge rule, both root-seeding paths and the budget guards.
* **Ground truth** — the vendored real project in
  ``tests/fixtures/yarn-tree/``: every edge the tree emits must be one yarn
  itself reports, and every ``(name, version)`` it claims must exist in the real
  ``node_modules``. This is the invariant an over-eager resolver would break.
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

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "yarn-tree"


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def write_project(tmp_path: Path, lock: str, manifest: dict | None = None) -> str:
    """Write a yarn project and return its lockfile path."""
    (tmp_path / "yarn.lock").write_text(lock, encoding="utf-8")
    if manifest is not None:
        (tmp_path / "package.json").write_text(json.dumps(manifest), encoding="utf-8")
    return str(tmp_path / "yarn.lock")


def block(descriptors: str, version: str, body: str = "") -> str:
    """One yarn v1 lockfile block."""
    lines = [
        f"{descriptors}:",
        f'  version "{version}"',
        f'  resolved "https://registry.yarnpkg.com/x/-/x-{version}.tgz#abc"',
        f"  integrity sha512-{version.replace('.', '')}==",
    ]
    if body:
        lines.append(body.rstrip("\n"))
    return "\n".join(lines) + "\n"


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


def nodes(deps: dict) -> set:
    """Every (name, version) pair the tree claims is installed."""
    found = set()

    def walk(node):
        found.add((node.name, node.version))
        for child in node.dependencies.values():
            walk(child)

    for node in deps.values():
        walk(node)
    return found


def find(deps: dict, path: list):
    """Descend a tree by a list of package names."""
    node = deps[path[0]]
    for name in path[1:]:
        node = node.dependencies[name]
    return node


# --------------------------------------------------------------------------- #
# unit: _split_yarn_descriptor
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "descriptor,expected",
    [
        ("lodash@^4.17.0", ("lodash", "^4.17.0")),
        ("lodash@4.17.21", ("lodash", "4.17.21")),
        # A scope's own '@' is at index 0 and is never the separator.
        ("@babel/core@^7.0.0", ("@babel/core", "^7.0.0")),
        # An npm alias carries a SECOND '@' inside its range. Splitting at the
        # last one would invent a package called "foo@npm:bar".
        ("foo@npm:bar@^1.0.0", ("foo", "npm:bar@^1.0.0")),
        ("@scope/foo@npm:bar@^1.0.0", ("@scope/foo", "npm:bar@^1.0.0")),
        # Berry writes the protocol into the descriptor.
        ("lodash@npm:^4.17.0", ("lodash", "npm:^4.17.0")),
        # A range can carry spaces and comparators.
        ("semver@>=1.0.0 <2.0.0", ("semver", ">=1.0.0 <2.0.0")),
        # Degenerate input must not raise.
        ("lodash", ("lodash", "")),
        ("@scope/pkg", ("@scope/pkg", "")),
        ("", ("", "")),
    ],
)
def test_split_yarn_descriptor(descriptor, expected):
    assert DependencyTreeVisualizer._split_yarn_descriptor(descriptor) == expected


# --------------------------------------------------------------------------- #
# unit: _split_yarn_line
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize(
    "line,expected",
    [
        # yarn v1 property lines
        ('  version "7.12.13"', ("version", "7.12.13")),
        ('  resolved "https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz#5608ae"',
         ("resolved", "https://registry.yarnpkg.com/ms/-/ms-2.0.0.tgz#5608ae")),
        ("  integrity sha512-Tpp60P6IUJ==", ("integrity", "sha512-Tpp60P6IUJ==")),
        # yarn v1 dependency lines
        ('    lodash "^4.17.0"', ("lodash", "^4.17.0")),
        ('    "@babel/highlight" "^7.12.13"', ("@babel/highlight", "^7.12.13")),
        ('    semver ">=1.0.0 <2.0.0"', ("semver", ">=1.0.0 <2.0.0")),
        # berry colon forms
        ("  version: 4.17.21", ("version", "4.17.21")),
        ('  resolution: "lodash@npm:4.17.21"', ("resolution", "lodash@npm:4.17.21")),
        ('    "@babel/highlight": ^7.12.13', ("@babel/highlight", "^7.12.13")),
        ("    lodash: ^4.17.0", ("lodash", "^4.17.0")),
        ("  linkType: hard", ("linkType", "hard")),
        # a key with no value still parses
        ("  dependencies:", ("dependencies", "")),
        # nothing to read
        ("   ", None),
        ("", None),
    ],
)
def test_split_yarn_line(line, expected):
    assert DependencyTreeVisualizer._split_yarn_line(line) == expected


def test_split_yarn_line_unterminated_quote_is_not_a_crash():
    assert DependencyTreeVisualizer._split_yarn_line('  "@babel/core') is None


# --------------------------------------------------------------------------- #
# the core regression: a tree, not a flat list
# --------------------------------------------------------------------------- #

LOCK_CHAIN = (
    "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
    "# yarn lockfile v1\n\n\n"
    + block("a@^1.0.0", "1.0.0", '  dependencies:\n    b "^1.0.0"\n')
    + "\n"
    + block("b@^1.0.0", "1.0.0", '  dependencies:\n    c "^1.0.0"\n')
    + "\n"
    + block("c@^1.0.0", "1.0.0")
)


def test_lockfile_builds_a_tree_at_all(tmp_path):
    """Before the fix this produced 3 roots, 0 edges and max_depth 0."""
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert set(deps) == {"a"}
    assert edges(deps) == {("", "a"), ("a", "b"), ("b", "c")}
    assert v.get_stats()["max_depth"] == 3
    assert find(deps, ["a", "b", "c"]).version == "1.0.0"


def test_roots_come_from_the_manifest_not_from_every_entry(tmp_path):
    """A transitive package is never reported as a direct dependency."""
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert set(deps) == {"a"}
    assert "b" not in deps and "c" not in deps


def test_dev_and_optional_root_sections_are_marked(tmp_path):
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0") + "\n" + block("d@^1.0.0", "1.0.0")
        + "\n" + block("o@^1.0.0", "1.0.0"),
        {
            "dependencies": {"a": "^1.0.0"},
            "devDependencies": {"d": "^1.0.0"},
            "optionalDependencies": {"o": "^1.0.0"},
        },
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert (deps["a"].dev, deps["a"].optional) == (False, False)
    assert (deps["d"].dev, deps["d"].optional) == (True, False)
    assert (deps["o"].dev, deps["o"].optional) == (False, True)


def test_root_section_precedence_matches_declaration_order(tmp_path):
    """A package declared in two sections is claimed by the first one."""
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0"),
        {"dependencies": {"a": "^1.0.0"}, "devDependencies": {"a": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps["a"].dev is False


# --------------------------------------------------------------------------- #
# multi-version resolution: the collapse bug
# --------------------------------------------------------------------------- #

LOCK_TWO_VERSIONS = (
    block("chalk@^2.0.0", "2.4.2") + "\n"
    + block("chalk@^4.0.0", "4.1.2") + "\n"
    + block("old@^1.0.0", "1.0.0", '  dependencies:\n    chalk "^2.0.0"\n')
)


def test_two_versions_of_one_package_do_not_collapse(tmp_path):
    """Each parent gets the copy ITS range resolves to, not the first block."""
    lock = write_project(
        tmp_path,
        LOCK_TWO_VERSIONS,
        {"dependencies": {"chalk": "^4.0.0", "old": "^1.0.0"}},
    )
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert deps["chalk"].version == "4.1.2"
    assert find(deps, ["old", "chalk"]).version == "2.4.2"
    assert v.get_stats()["multi_version_packages"] == {"chalk": ["2.4.2", "4.1.2"]}


def test_multi_version_report_covers_unreachable_entries_too(tmp_path):
    """Every version in the lockfile is reported, reachable or not.

    Mirrors the npm v7+ path, which tallies the whole ``packages`` map before it
    walks anything — a stale second copy in the lockfile is worth surfacing even
    when nothing in the current manifest reaches it.
    """
    lock = write_project(
        tmp_path, LOCK_TWO_VERSIONS, {"dependencies": {"chalk": "^4.0.0"}}
    )
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert set(deps) == {"chalk"}  # `old` is not reachable
    assert v.get_stats()["multi_version_packages"] == {"chalk": ["2.4.2", "4.1.2"]}


def test_scoped_package_name_survives_the_round_trip(tmp_path):
    lock = write_project(
        tmp_path,
        block('"@babel/code-frame@^7.0.0", "@babel/code-frame@^7.10.4"', "7.12.13",
              '  dependencies:\n    "@babel/highlight" "^7.12.13"\n')
        + "\n" + block('"@babel/highlight@^7.12.13"', "7.12.13"),
        {"dependencies": {"@babel/code-frame": "^7.10.4"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert set(deps) == {"@babel/code-frame"}
    assert find(deps, ["@babel/code-frame", "@babel/highlight"]).version == "7.12.13"


def test_multi_descriptor_header_indexes_every_descriptor(tmp_path):
    """`"a@^1.0.0", "a@^1.2.0":` must resolve BOTH ranges to the one copy."""
    lock = write_project(
        tmp_path,
        block('"a@^1.0.0", "a@^1.2.0"', "1.5.0") + "\n"
        + block("p@^1.0.0", "1.0.0", '  dependencies:\n    a "^1.2.0"\n'),
        {"dependencies": {"a": "^1.0.0", "p": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps["a"].version == "1.5.0"
    assert find(deps, ["p", "a"]).version == "1.5.0"


# --------------------------------------------------------------------------- #
# edges the tree must NOT draw
# --------------------------------------------------------------------------- #

def test_peer_dependency_is_not_an_edge(tmp_path):
    """Yarn classic does not install peers, so a peer is not this parent's copy."""
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  peerDependencies:\n    react "^17.0.0"\n')
        + "\n" + block("react@^17.0.0", "17.0.2"),
        {"dependencies": {"a": "^1.0.0", "react": "^17.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps["a"].dependencies == {}
    assert ("a", "react") not in edges(deps)


def test_declared_but_uninstalled_optional_dep_is_skipped(tmp_path):
    """A platform-specific optional dep yarn skipped has no entry to point at."""
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  optionalDependencies:\n    fsevents "^2.3.2"\n'),
        {"dependencies": {"a": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps["a"].dependencies == {}


def test_optional_dependency_edge_is_marked_optional(tmp_path):
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  optionalDependencies:\n    fsevents "^2.3.2"\n')
        + "\n" + block("fsevents@^2.3.2", "2.3.2"),
        {"dependencies": {"a": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert find(deps, ["a", "fsevents"]).optional is True


def test_ambiguous_unresolvable_range_is_dropped_not_guessed(tmp_path):
    """Two copies installed + a range matching no descriptor ⇒ no edge.

    Guessing would attribute a copy yarn installed for somebody else to this
    parent, which is the fabricated edge the tree must never claim.
    """
    lock = write_project(
        tmp_path,
        block("chalk@^2.0.0", "2.4.2") + "\n"
        + block("chalk@^4.0.0", "4.1.2") + "\n"
        + block("p@^1.0.0", "1.0.0", '  dependencies:\n    chalk "^9.9.9"\n'),
        {"dependencies": {"p": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps["p"].dependencies == {}


def test_single_installed_copy_resolves_a_descriptor_format_miss(tmp_path):
    """With exactly one copy installed, the declared range must be satisfied by it."""
    lock = write_project(
        tmp_path,
        block("chalk@^4.0.0", "4.1.2") + "\n"
        + block("p@^1.0.0", "1.0.0", '  dependencies:\n    chalk "npm:^4.0.0"\n'),
        {"dependencies": {"p": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert find(deps, ["p", "chalk"]).version == "4.1.2"


def test_unknown_sub_blocks_are_not_read_as_edges(tmp_path):
    """berry's `bin:` / `peerDependenciesMeta:` bodies are not installed edges."""
    lock = write_project(
        tmp_path,
        block(
            "a@^1.0.0",
            "1.0.0",
            '  bin:\n'
            '    acorn "bin/acorn"\n'
            "  peerDependenciesMeta:\n"
            '    "@babel/core":\n'
            "      optional: true\n"
            "  dependencies:\n"
            '    b "^1.0.0"\n',
        )
        + "\n" + block("b@^1.0.0", "1.0.0") + "\n" + block("acorn@^8.0.0", "8.0.0")
        + "\n" + block('"@babel/core@^7.0.0"', "7.0.0"),
        {"dependencies": {"a": "^1.0.0"}},
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert set(deps["a"].dependencies) == {"b"}


# --------------------------------------------------------------------------- #
# DAG guards inherited from the F30 machinery
# --------------------------------------------------------------------------- #

def test_cycle_terminates_and_is_recorded(tmp_path):
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  dependencies:\n    b "^1.0.0"\n') + "\n"
        + block("b@^1.0.0", "1.0.0", '  dependencies:\n    a "^1.0.0"\n'),
        {"dependencies": {"a": "^1.0.0"}},
    )
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert find(deps, ["a", "b", "a"]).circular_ref is True
    assert ("b", "a") in v.get_stats()["circular_references"]


def test_repeat_occurrence_is_deduped_not_re_expanded(tmp_path):
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  dependencies:\n    shared "^1.0.0"\n') + "\n"
        + block("b@^1.0.0", "1.0.0", '  dependencies:\n    shared "^1.0.0"\n') + "\n"
        + block("shared@^1.0.0", "1.0.0", '  dependencies:\n    leaf "^1.0.0"\n') + "\n"
        + block("leaf@^1.0.0", "1.0.0"),
        {"dependencies": {"a": "^1.0.0", "b": "^1.0.0"}},
    )
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    first = find(deps, ["a", "shared"])
    second = find(deps, ["b", "shared"])
    assert set(first.dependencies) == {"leaf"}
    assert second.duplicate is True and second.dependencies == {}
    assert v.get_stats()["deduped_nodes"] == 1


def test_depth_budget_truncates_instead_of_recursing_forever(tmp_path, monkeypatch):
    monkeypatch.setattr(dependency_tree, "MAX_TREE_DEPTH", 2)
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    v.parse_yarn_lock(lock)
    assert v.get_stats()["truncated"] is True


def test_node_budget_truncates(tmp_path, monkeypatch):
    monkeypatch.setattr(dependency_tree, "MAX_TREE_NODES", 2)
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    v.parse_yarn_lock(lock)
    assert v.get_stats()["truncated"] is True


def test_reparsing_on_one_instance_is_idempotent(tmp_path):
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    first = v.parse_yarn_lock(lock)
    first_stats = v.get_stats()
    second = v.parse_yarn_lock(lock)
    assert edges(first) == edges(second)
    assert v.get_stats() == first_stats


# --------------------------------------------------------------------------- #
# root seeding without a manifest
# --------------------------------------------------------------------------- #

def test_without_a_manifest_roots_fall_back_to_unreferenced_entries(tmp_path):
    """No package.json ⇒ the entries nothing else depends on are the best roots."""
    lock = write_project(tmp_path, LOCK_CHAIN, manifest=None)
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert set(deps) == {"a"}
    assert edges(deps) == {("", "a"), ("a", "b"), ("b", "c")}


def test_without_a_manifest_an_all_cycle_lockfile_is_still_non_empty(tmp_path):
    """Nothing is unreferenced inside one cycle; the tree must not come back empty."""
    lock = write_project(
        tmp_path,
        block("a@^1.0.0", "1.0.0", '  dependencies:\n    b "^1.0.0"\n') + "\n"
        + block("b@^1.0.0", "1.0.0", '  dependencies:\n    a "^1.0.0"\n'),
        manifest=None,
    )
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert set(deps) == {"a", "b"}


def test_a_manifest_with_no_installed_deps_does_not_fall_back(tmp_path):
    """A real manifest whose deps are all unmet reports nothing, not transitives.

    Falling through to the in-degree fallback here would silently promote
    transitive packages to direct dependencies.
    """
    lock = write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"absent": "^1.0.0"}})
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert deps == {}


def test_unreadable_manifest_falls_back_rather_than_raising(tmp_path):
    (tmp_path / "package.json").write_text("{not json", encoding="utf-8")
    lock = write_project(tmp_path, LOCK_CHAIN)
    deps = DependencyTreeVisualizer().parse_yarn_lock(lock)
    assert set(deps) == {"a"}


# --------------------------------------------------------------------------- #
# berry (yarn 2+) lockfiles
# --------------------------------------------------------------------------- #

BERRY_LOCK = """\
# This file is generated by running "yarn install" inside your project.
__metadata:
  version: 6
  cacheKey: 8

"a@npm:^1.0.0":
  version: 1.0.0
  resolution: "a@npm:1.0.0"
  dependencies:
    "@scope/b": ^2.0.0
  checksum: 1111
  languageName: node
  linkType: hard

"@scope/b@npm:^2.0.0":
  version: 2.0.0
  resolution: "@scope/b@npm:2.0.0"
  checksum: 2222
  languageName: node
  linkType: hard
"""


def test_berry_lockfile_builds_a_tree(tmp_path):
    """Berry's colon syntax and `npm:` descriptors resolve like v1's."""
    lock = write_project(tmp_path, BERRY_LOCK, {"dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(lock)

    assert set(deps) == {"a"}
    assert deps["a"].version == "1.0.0"
    assert find(deps, ["a", "@scope/b"]).version == "2.0.0"
    # __metadata is a header block, not a package.
    assert "__metadata" not in {n for n, _ in nodes(deps)}


# --------------------------------------------------------------------------- #
# consumers of the tree
# --------------------------------------------------------------------------- #

def test_renderers_accept_the_yarn_tree(tmp_path):
    write_project(tmp_path, LOCK_CHAIN, {"name": "demo", "dependencies": {"a": "^1.0.0"}})
    v = DependencyTreeVisualizer()
    ascii_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.ASCII)
    json_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.JSON)
    dot_out = v.visualize(str(tmp_path), output_format=dependency_tree.OutputFormat.DOT)

    assert "a@1.0.0" in ascii_out and "c@1.0.0" in ascii_out
    assert json.loads(json_out)["a"]["dependencies"]["b"]["dependencies"]["c"]["name"] == "c"
    assert "digraph dependencies" in dot_out and '"demo" -> "a@1.0.0"' in dot_out


def test_find_package_reports_the_path_through_the_tree(tmp_path):
    """Before the fix every hit was a bare root; now the real path is reported."""
    write_project(tmp_path, LOCK_CHAIN, {"dependencies": {"a": "^1.0.0"}})
    hits = DependencyTreeVisualizer().find_package(str(tmp_path), "c")
    assert [path for path, _ in hits] == ["a@1.0.0 -> b@1.0.0 -> c@1.0.0"]


# --------------------------------------------------------------------------- #
# ground truth: the vendored real project
# --------------------------------------------------------------------------- #

GROUND_TRUTH = FIXTURE / "ground-truth.json"


@pytest.fixture(scope="module")
def real_tree():
    v = DependencyTreeVisualizer()
    deps = v.parse_yarn_lock(str(FIXTURE / "yarn.lock"))
    return v, deps


@pytest.fixture(scope="module")
def ground_truth():
    return json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))


def test_real_project_roots_are_exactly_the_declared_dependencies(real_tree):
    _, deps = real_tree
    manifest = json.loads((FIXTURE / "package.json").read_text(encoding="utf-8"))
    declared = set(manifest.get("dependencies", {})) | set(manifest.get("devDependencies", {}))
    # Before the fix: 84 roots — every installed package.
    assert set(deps) == declared


def test_real_project_tree_has_real_depth(real_tree):
    v, _ = real_tree
    stats = v.get_stats()
    assert stats["max_depth"] > 1, "the tree is a flat list again"
    assert stats["truncated"] is False


def test_real_project_invents_no_edges(real_tree, ground_truth):
    """Every emitted edge must be one `yarn list` itself reports."""
    expected = {tuple(e.split("|", 1)) for e in ground_truth["edges"]}
    emitted = {(p, c) for p, c in edges(real_tree[1]) if p}
    assert not (emitted - expected), "fabricated edges"


def test_real_project_misses_no_edges(real_tree, ground_truth):
    expected = {tuple(e.split("|", 1)) for e in ground_truth["edges"]}
    emitted = {(p, c) for p, c in edges(real_tree[1]) if p}
    assert not (expected - emitted), "edges yarn reports that the tree dropped"


def test_real_project_claims_only_packages_that_exist_on_disk(real_tree, ground_truth):
    """The version on every node must be one yarn actually installed."""
    installed = {tuple(p.rsplit("@", 1)) for p in ground_truth["installed_on_disk"]}
    assert not (nodes(real_tree[1]) - installed)


def test_real_project_reaches_every_listed_package(real_tree, ground_truth):
    listed = {tuple(p.rsplit("@", 1)) for p in ground_truth["listed_packages"]}
    assert not (listed - nodes(real_tree[1]))


def test_real_project_resolves_each_parent_to_its_own_copy(real_tree, ground_truth):
    """`ms` is installed twice; each parent must get the copy node resolves for it.

    This is the collapse bug in one assertion — keyed by bare name, both parents
    got whichever `ms` block was parsed first.
    """
    _, deps = real_tree
    found: dict[str, set] = {}

    def walk(node):
        for child_name, child in node.dependencies.items():
            found.setdefault(f"{node.name}|{child_name}", set()).add(child.version)
            walk(child)

    for node in deps.values():
        walk(node)

    for edge, expected in ground_truth["nested_resolutions"].items():
        assert found.get(edge) == {expected}, f"{edge} resolved to {found.get(edge)}"
