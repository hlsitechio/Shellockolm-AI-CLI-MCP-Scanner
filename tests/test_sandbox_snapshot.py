"""Tests for ``sandbox_snapshot`` and the no-bare-except gate (follow-up F27).

F27 closed the ``E722`` (bare-except) family — the only genuine-bug rule left in
the ruff ignore list. All five sites lived in the interactive shell's ``sandbox
<pkg>`` deep-install check, where a swallowed exception silently becomes "no
findings": a snapshot walk that died on one unreadable path returned a partial
map that the caller reported as "No suspicious files created", and a crashing
CVE scanner produced "✓ No known CVEs found".

Two of those sites were closures inside ``interactive_shell()`` (untestable in
place); they now live in :mod:`sandbox_snapshot` and are exercised here:

* a read failure is **recorded**, not swallowed — the file is kept with an
  ``unreadable`` hash and the snapshot reports ``is_complete == False``;
* the walk **continues** past a failure instead of aborting the whole tree;
* ``KeyboardInterrupt`` is no longer caught (a bare ``except`` swallowed Ctrl-C
  during a multi-thousand-file walk);
* keys are forward-slashed, so the caller's ``'node_modules/' in path``
  classification behaves the same on Windows as on POSIX.

:func:`test_src_tree_has_no_bare_except` is the mechanism guard for the three
sites that stayed inline: an AST walk over ``src/`` that fails if any bare
``except:`` reappears anywhere in the shipped package.
"""

import ast
from pathlib import Path

import pytest

import sandbox_snapshot
from sandbox_snapshot import (
    MAX_RECORDED_ERRORS,
    UNREADABLE,
    DirectorySnapshot,
    compare_snapshots,
    hash_file,
    snapshot_directory,
)

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"


def _write(root: Path, rel: str, content: str = "x") -> Path:
    target = root / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


# --------------------------------------------------------------------------
# snapshot_directory — the happy path
# --------------------------------------------------------------------------
def test_snapshot_captures_every_file_with_a_hash_and_size(tmp_path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "node_modules/left-pad/index.js", "module.exports = 1;")

    snap = snapshot_directory(tmp_path)

    assert set(snap.files) == {"package.json", "node_modules/left-pad/index.js"}
    entry = snap.files["node_modules/left-pad/index.js"]
    assert entry["size"] == len("module.exports = 1;")
    assert entry["hash"] not in ("", UNREADABLE)
    assert snap.is_complete
    assert len(snap) == 2


def test_snapshot_keys_are_forward_slashed_on_every_platform(tmp_path):
    """The caller classifies with ``'node_modules/' in path``. With native
    separators that test is always False on Windows, so every installed file
    looked like it had been created OUTSIDE node_modules (a benign package
    reported as dangerous)."""
    _write(tmp_path, "node_modules/pkg/lib/deep/file.js", "1")

    snap = snapshot_directory(tmp_path)

    key = next(iter(snap.files))
    assert "\\" not in key
    assert key == "node_modules/pkg/lib/deep/file.js"
    assert any("node_modules/" in k for k in snap.files)


def test_identical_content_hashes_equal_and_a_change_is_detected(tmp_path):
    target = _write(tmp_path, "a.js", "before")
    first = snapshot_directory(tmp_path)
    target.write_text("after", encoding="utf-8")
    second = snapshot_directory(tmp_path)

    assert first.files["a.js"]["hash"] != second.files["a.js"]["hash"]

    unchanged = snapshot_directory(tmp_path)
    assert unchanged.files["a.js"]["hash"] == second.files["a.js"]["hash"]


def test_hash_is_sha256_not_md5(tmp_path):
    """The hash is a tamper check in a security verdict path; MD5 collisions are
    cheap enough to hide a modified file behind its pre-install hash."""
    import hashlib

    target = _write(tmp_path, "a.js", "payload")
    digest = hash_file(target)

    assert len(digest) == 64
    assert digest == hashlib.sha256(b"payload").hexdigest()


def test_empty_directory_snapshots_clean(tmp_path):
    snap = snapshot_directory(tmp_path)
    assert snap.files == {}
    assert snap.is_complete


# --------------------------------------------------------------------------
# snapshot_directory — failures are RECORDED, never swallowed
# --------------------------------------------------------------------------
def test_unreadable_file_is_recorded_and_marks_the_snapshot_incomplete(
    tmp_path, monkeypatch
):
    """The bug F27 closed: a read failure used to be ``except: pass``-ed into an
    ``unreadable`` entry with no way for the caller to know it was blind."""
    _write(tmp_path, "readable.js", "ok")
    _write(tmp_path, "locked.js", "secret")

    real_hash = sandbox_snapshot.hash_file

    def fake_hash(path):
        if path.name == "locked.js":
            raise PermissionError(13, "Permission denied")
        return real_hash(path)

    monkeypatch.setattr(sandbox_snapshot, "hash_file", fake_hash)

    snap = snapshot_directory(tmp_path)

    assert snap.files["locked.js"]["hash"] == UNREADABLE
    assert snap.unreadable == 1
    assert not snap.is_complete
    assert snap.error_count == 1
    assert any("locked.js" in err for err in snap.errors)
    # ...and the readable file was still captured: the walk CONTINUED.
    assert snap.files["readable.js"]["hash"] != UNREADABLE


def test_walk_continues_past_a_failure_instead_of_aborting_the_tree(
    tmp_path, monkeypatch
):
    """The outer bare except aborted the whole walk on the first error, so a
    single bad path could silently truncate the snapshot to a prefix."""
    for i in range(6):
        _write(tmp_path, f"dir{i}/file{i}.js", f"content-{i}")

    real_hash = sandbox_snapshot.hash_file

    def fake_hash(path):
        if path.name in ("file0.js", "file3.js"):
            raise OSError(5, "I/O error")
        return real_hash(path)

    monkeypatch.setattr(sandbox_snapshot, "hash_file", fake_hash)

    snap = snapshot_directory(tmp_path)

    assert len(snap.files) == 6, "every entry must still be present"
    assert snap.unreadable == 2
    assert len([k for k, v in snap.files.items() if v["hash"] != UNREADABLE]) == 4
    assert not snap.is_complete


def test_keyboard_interrupt_is_not_swallowed(tmp_path, monkeypatch):
    """A bare ``except`` also caught KeyboardInterrupt, so Ctrl-C during a walk
    of thousands of node_modules files was silently discarded."""
    _write(tmp_path, "a.js", "1")

    def interrupting_hash(path):
        raise KeyboardInterrupt

    monkeypatch.setattr(sandbox_snapshot, "hash_file", interrupting_hash)

    with pytest.raises(KeyboardInterrupt):
        snapshot_directory(tmp_path)


def test_missing_root_is_recorded_not_raised(tmp_path):
    snap = snapshot_directory(tmp_path / "does-not-exist")

    assert snap.files == {}
    assert not snap.is_complete
    assert snap.error_count == 1


def test_a_file_as_root_is_recorded_not_raised(tmp_path):
    target = _write(tmp_path, "a.js", "1")
    snap = snapshot_directory(target)

    assert snap.files == {}
    assert not snap.is_complete


def test_error_recording_is_capped_but_still_counted():
    snap = DirectorySnapshot()
    for i in range(MAX_RECORDED_ERRORS + 7):
        snap.record_error(f"boom {i}")

    assert len(snap.errors) == MAX_RECORDED_ERRORS
    assert snap.errors_omitted == 7
    assert snap.error_count == MAX_RECORDED_ERRORS + 7
    assert not snap.is_complete, "overflow must not make a snapshot look complete"


def test_error_summary_reports_state():
    clean = DirectorySnapshot()
    assert clean.error_summary() == "complete"

    blind = DirectorySnapshot()
    blind.record_error("x")
    assert "1 path(s)" in blind.error_summary()


# --------------------------------------------------------------------------
# compare_snapshots — pure diff
# --------------------------------------------------------------------------
def test_compare_reports_new_modified_and_deleted():
    before = {
        "keep.js": {"hash": "a", "size": 1},
        "gone.js": {"hash": "b", "size": 1},
        "changed.js": {"hash": "c", "size": 1},
    }
    after = {
        "keep.js": {"hash": "a", "size": 1},
        "changed.js": {"hash": "c2", "size": 2},
        "dropped-payload.sh": {"hash": "d", "size": 9},
    }

    new_files, modified, deleted = compare_snapshots(before, after)

    assert new_files == ["dropped-payload.sh"]
    assert modified == ["changed.js"]
    assert deleted == ["gone.js"]


def test_compare_accepts_snapshot_objects(tmp_path):
    before = snapshot_directory(tmp_path)
    _write(tmp_path, "node_modules/pkg/index.js", "1")
    _write(tmp_path, "evil.sh", "curl x | sh")
    after = snapshot_directory(tmp_path)

    new_files, modified, deleted = compare_snapshots(before, after)

    assert sorted(new_files) == ["evil.sh", "node_modules/pkg/index.js"]
    assert modified == []
    assert deleted == []
    # The caller's expected-location filter must see the installed file as
    # expected and the dropped script as suspicious.
    suspicious = [f for f in new_files if "node_modules/" not in f]
    assert suspicious == ["evil.sh"]


def test_compare_of_identical_snapshots_is_empty(tmp_path):
    _write(tmp_path, "a.js", "1")
    snap = snapshot_directory(tmp_path)

    assert compare_snapshots(snap, snap) == ([], [], [])


def test_unreadable_on_both_sides_is_not_reported_as_modified():
    """Two ``unreadable`` entries compare equal — the caller can only learn the
    file was never actually read from ``is_complete``, which is why the CLI
    downgrades an incomplete run to INCONCLUSIVE instead of clean."""
    before = {"x.js": {"hash": UNREADABLE, "size": 0}}
    after = {"x.js": {"hash": UNREADABLE, "size": 0}}

    assert compare_snapshots(before, after) == ([], [], [])


# --------------------------------------------------------------------------
# Mechanism — no bare `except:` may reappear anywhere in the shipped package
# --------------------------------------------------------------------------
def test_src_tree_has_no_bare_except():
    """AST guard for the whole of ``src/``.

    ruff's E722 enforces this in CI, but this test states the *reason* and keeps
    holding even if the lint config is edited: in a security scanner a bare
    ``except`` turns a crashed check into a clean report, and it swallows
    ``KeyboardInterrupt``/``SystemExit`` besides.
    """
    offenders = []
    for path in sorted(SRC_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and node.type is None:
                offenders.append(f"{path.relative_to(REPO_ROOT)}:{node.lineno}")

    assert not offenders, (
        "bare `except:` found in src/ — catch the real exception (and record it "
        "where a scan must continue) instead:\n  " + "\n  ".join(offenders)
    )


def test_the_bare_except_guard_actually_detects_one(tmp_path):
    """Fail-first check: the AST walk above must really flag a bare except."""
    source = "try:\n    pass\nexcept:\n    pass\n"
    tree = ast.parse(source)
    bare = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ExceptHandler) and node.type is None
    ]
    assert len(bare) == 1

    typed = ast.parse("try:\n    pass\nexcept OSError:\n    pass\n")
    assert not [
        node
        for node in ast.walk(typed)
        if isinstance(node, ast.ExceptHandler) and node.type is None
    ]
