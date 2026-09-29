"""Filesystem snapshot/diff for the interactive ``sandbox`` deep-install check
(build-loop follow-up F27).

The interactive shell's ``sandbox <pkg>`` command installs an npm package into a
throwaway directory **with install scripts enabled**, then decides whether the
package "APPEARS SAFE" partly from what the install wrote to disk: it snapshots
the sandbox before and after ``npm install`` and treats a file created outside
``node_modules/`` as a danger.

That verdict is only as trustworthy as the snapshot. The original implementation
lived as a closure inside ``interactive_shell()`` and swallowed every failure
with a bare ``except: pass``, so a walk that died on one unreadable path returned
a *partial* snapshot the caller could not distinguish from a complete one — an
install that dropped a payload could then be reported as "No suspicious files
created", i.e. a security check that reads clean because it crashed. This module
makes the failure visible instead:

* a per-file read error is recorded and the file is kept with an
  :data:`UNREADABLE` hash, so the walk continues; ``os.walk``'s ``onerror`` hook
  means one bad directory no longer aborts the rest of the tree;
* :attr:`DirectorySnapshot.is_complete` tells the caller the snapshot is blind
  somewhere, so an empty diff can be reported as *inconclusive* rather than
  clean;
* only ``OSError`` is caught, so ``KeyboardInterrupt`` during a
  multi-thousand-file walk actually interrupts it instead of being swallowed.

Two further corrections came with the extraction:

* keys are **forward-slashed** relative paths. The caller classifies paths with
  ``'node_modules/' in path``; with native separators that test was always False
  on Windows, so every installed file looked like it had been created *outside*
  ``node_modules`` and a benign package could be reported as dangerous.
* content is hashed with **SHA-256**, not MD5. The hash is a tamper check in a
  security verdict path, and MD5 collisions are cheap to construct — a modified
  file could be made to hash-match its pre-install self.

Pure and unit-testable, mirroring ``diff_scan`` / ``baseline`` / ``doctor``.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Mapping, Tuple, Union

# Cap on recorded error strings, mirroring the agent scanner's error collection
# (task #27B): a pathological tree must not build an unbounded list, but the
# overflow is counted so the snapshot still reports itself incomplete.
MAX_RECORDED_ERRORS = 50

#: Hash placeholder for a file that exists but whose bytes could not be read.
UNREADABLE = "unreadable"

# Files are hashed in chunks so a large binary in node_modules can't blow memory.
_CHUNK_BYTES = 1024 * 1024

FileEntry = Dict[str, object]


@dataclass
class DirectorySnapshot:
    """Content snapshot of a directory tree, plus what it could not see.

    ``files`` maps a forward-slashed relative path to ``{"hash": ..., "size":
    ...}``. ``errors`` holds human-readable read/walk failures (capped at
    :data:`MAX_RECORDED_ERRORS`, with the overflow counted in
    ``errors_omitted``), and ``unreadable`` counts files present in ``files``
    whose content could not be hashed.
    """

    files: Dict[str, FileEntry] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    unreadable: int = 0
    errors_omitted: int = 0

    @property
    def is_complete(self) -> bool:
        """True when the whole tree was walked and every file was read.

        A caller must not report "nothing suspicious" from an incomplete
        snapshot — that is the exact failure this module exists to prevent.
        """
        return not self.errors and self.errors_omitted == 0

    @property
    def error_count(self) -> int:
        """Total failures, including any beyond the recording cap."""
        return len(self.errors) + self.errors_omitted

    def __len__(self) -> int:
        return len(self.files)

    def record_error(self, message: str) -> None:
        if len(self.errors) < MAX_RECORDED_ERRORS:
            self.errors.append(message)
        else:
            self.errors_omitted += 1

    def error_summary(self) -> str:
        """One-line description for the CLI warning line."""
        if self.is_complete:
            return "complete"
        return f"{self.error_count} path(s) could not be read"


def _relative_key(root: Path, path: Path) -> str:
    """Forward-slashed path of ``path`` relative to ``root``.

    Falls back to the absolute string if the path escapes the root (a symlinked
    file resolved elsewhere), so an entry is never dropped silently.
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return str(path).replace("\\", "/")
    return rel.as_posix()


def hash_file(path: Path) -> str:
    """SHA-256 of a file's contents, read in chunks.

    Raises ``OSError`` — the caller decides how to record it. Kept public so
    tests can substitute a failing reader without touching the filesystem's
    permission model (which differs sharply between Windows and POSIX).
    """
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while True:
            chunk = handle.read(_CHUNK_BYTES)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def snapshot_directory(root: Union[str, Path]) -> DirectorySnapshot:
    """Snapshot every file under ``root``, recording what could not be read.

    Never raises: a missing root, an unwalkable directory and an unreadable file
    are all recorded on the returned snapshot (which then reports
    ``is_complete == False``) so the caller can downgrade its verdict instead of
    mistaking a blind scan for a clean one.
    """
    root_path = Path(root)
    snapshot = DirectorySnapshot()

    if not root_path.is_dir():
        snapshot.record_error(f"{root_path}: not a directory")
        return snapshot

    def _on_walk_error(exc: OSError) -> None:
        target = getattr(exc, "filename", None) or root_path
        snapshot.record_error(f"{target}: {exc}")

    # followlinks stays False: a directory symlink/junction could otherwise loop
    # back into the tree (the reparse-point hazard closed in task #27C).
    for dirpath, _dirnames, filenames in os.walk(root_path, onerror=_on_walk_error):
        for name in filenames:
            file_path = Path(dirpath) / name
            key = _relative_key(root_path, file_path)
            try:
                size = file_path.stat().st_size
                digest = hash_file(file_path)
            except OSError as exc:
                snapshot.files[key] = {"hash": UNREADABLE, "size": 0}
                snapshot.unreadable += 1
                snapshot.record_error(f"{key}: {exc}")
                continue
            snapshot.files[key] = {"hash": digest, "size": size}

    return snapshot


def _as_files(
    snapshot: Union[DirectorySnapshot, Mapping[str, FileEntry]],
) -> Mapping[str, FileEntry]:
    """Accept either a :class:`DirectorySnapshot` or a bare files mapping."""
    if isinstance(snapshot, DirectorySnapshot):
        return snapshot.files
    return snapshot


def compare_snapshots(
    before: Union[DirectorySnapshot, Mapping[str, FileEntry]],
    after: Union[DirectorySnapshot, Mapping[str, FileEntry]],
) -> Tuple[List[str], List[str], List[str]]:
    """Return ``(new_files, modified_files, deleted_files)`` between snapshots.

    Pure set/hash comparison over the two mappings; ordering follows ``after``
    then ``before`` so output is deterministic for a given pair of walks.
    """
    before_files = _as_files(before)
    after_files = _as_files(after)

    new_files: List[str] = []
    modified_files: List[str] = []
    deleted_files: List[str] = []

    for key, info in after_files.items():
        if key not in before_files:
            new_files.append(key)
        elif before_files[key].get("hash") != info.get("hash"):
            modified_files.append(key)

    for key in before_files:
        if key not in after_files:
            deleted_files.append(key)

    return new_files, modified_files, deleted_files
