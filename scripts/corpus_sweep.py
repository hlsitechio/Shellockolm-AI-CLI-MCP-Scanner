#!/usr/bin/env python3
"""Re-runnable malware-pattern sweep over installed npm packages (follow-up F59).

Every calibration pass in this repo cites a number — "measured over 480
packages", "re-measured over 995", "2,080 packages, zero false dangers" — and
every pass has had to re-earn that number with an ad-hoc script written from
scratch. F43 could not earn it at all: two full sweeps over the 7,576 packages
installed on this machine failed, one on ``MemoryError`` reading an >8 MB
bundle, one on I/O starvation (~11s of CPU across 40 minutes of wall clock).
A measurement that cannot be reproduced is a claim, not evidence.

This is that sweep as a checked-in command, built around the three things that
broke it:

* **A per-file size cap** (``--max-file-bytes``). One pathological bundle can no
  longer kill a 40-minute run. An oversize file is *counted and named* in the
  report, never silently dropped — the cap is a property of this measurement
  harness, NOT of the shipped scanner, and a report that hid it would overstate
  coverage. The same rule covers a file whose scan raises: a failed file is not
  a scanned file.
* **A persisted inventory** (``inventory``). The walk is the expensive half on a
  spinning/contended disk, and it is also the half that does not change between
  two runs of the same corpus. Walk once, sweep as often as you like.
* **Resumable, streaming sweeps** (``--resume``). Results are written per package
  as they are produced, so an interrupted sweep costs only the package it was on,
  and progress goes to stderr while stdout/the report file stay machine-readable.

And the point of it all: ``diff`` turns two reports into a machine-readable
old-vs-new delta, so "this narrowing removed 17 false dangers and added none" is
a command anyone can re-run rather than a number a pass asserts.

Usage::

    # Walk once, persist the inventory (the slow half).
    python scripts/corpus_sweep.py inventory --root G:/ -o corpus.inv.jsonl

    # Sweep it (fast, resumable) — before a change, and again after.
    python scripts/corpus_sweep.py sweep -i corpus.inv.jsonl -o before.jsonl
    python scripts/corpus_sweep.py sweep -i corpus.inv.jsonl -o after.jsonl --resume

    # What actually changed.
    python scripts/corpus_sweep.py diff before.jsonl after.jsonl --fail-on-new-dangers

Both file formats are JSONL with a header line and a **trailer line**: a reader
that reaches EOF without the trailer knows the file was truncated and refuses it
rather than reporting a short corpus as a complete one.

Exit codes: 0 on success; 1 when ``diff --fail-on-new-dangers`` finds a package
that gained a danger; 2 on a usage/IO error.
"""

from __future__ import annotations

import argparse
import itertools
import json
import os
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, Sequence, Tuple

# Flat import layout: the source modules import each other bare, so put src/ on
# the path before importing (same preamble as scripts/benchmark_scan.py).
_SRC = Path(__file__).resolve().parents[1] / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from sandbox_check import (  # noqa: E402
    classify_malware_hits,
    is_dangerous_hit,
    scan_text_for_malware_patterns,
)
from sandbox_codescan import is_scannable_code_path  # noqa: E402

INVENTORY_SCHEMA = "shellockolm.corpus-inventory/1"
REPORT_SCHEMA = "shellockolm.corpus-report/1"
DIFF_SCHEMA = "shellockolm.corpus-diff/1"

#: Default per-file cap. Comfortably above real package source (the largest file
#: in a typical install is a few hundred KB) and below the multi-MB generated
#: bundles that are neither hand-written code nor readable evidence.
DEFAULT_MAX_FILE_BYTES = 2 * 1024 * 1024

#: How many oversize/failed paths a package record keeps as examples. The
#: *counts* are always exact; only the example list is bounded.
MAX_EXAMPLES = 5


# --------------------------------------------------------------------------- #
# Package attribution (pure)
# --------------------------------------------------------------------------- #


def resolve_package(
    relative: str, root_is_package: bool = False
) -> Optional[Tuple[str, str, str]]:
    """Attribute one root-relative path to its installed package.

    Returns ``(package path relative to the root, package name, path within the
    package)``, or ``None`` when the path belongs to no package. The third
    element is ``""`` when ``relative`` IS the package directory — callers that
    want a file must check it, and the directory case is what lets the walk
    register a package that ships no scannable code at all (a declarations-only
    package is part of the corpus, and hiding it would flatter the coverage).

    The owning package is the one named by the **last** ``node_modules`` segment,
    which is what makes nesting work without a second walk: a file under
    ``a/node_modules/b/node_modules/c/index.js`` belongs to ``c``, not to ``a``,
    so a nested dependency is measured once as itself rather than twice as part
    of its parent.

    ``.bin`` and other dotted entries directly under ``node_modules`` are npm's
    own bookkeeping, not packages, and are excluded.
    """
    segments = [segment for segment in relative.replace("\\", "/").split("/") if segment]
    last = -1
    for index, segment in enumerate(segments):
        if segment == "node_modules":
            last = index

    if last < 0:
        if root_is_package:
            return "", "", "/".join(segments)
        return None

    rest = segments[last + 1 :]
    if not rest:
        return None
    if rest[0].startswith("@"):
        # A scope directory is not itself a package; it needs `@scope/name`.
        if len(rest) < 2:
            return None
        depth = 2
    else:
        if rest[0].startswith("."):
            return None
        depth = 1

    package_path = "/".join(segments[: last + 1 + depth])
    name = "/".join(rest[:depth])
    return package_path, name, "/".join(rest[depth:])


# --------------------------------------------------------------------------- #
# The walk
# --------------------------------------------------------------------------- #


@dataclass
class PackageInventory:
    """Every scannable file in one installed package, with its size."""

    key: str
    name: str
    root: str
    #: ``(path within the package, size in bytes)``, sorted.
    files: List[Tuple[str, int]] = field(default_factory=list)
    dir_errors: int = 0

    @property
    def total_bytes(self) -> int:
        return sum(size for _path, size in self.files)

    def to_json(self) -> Dict[str, Any]:
        return {
            "kind": "package",
            "key": self.key,
            "name": self.name,
            "root": self.root,
            "files": [[path, size] for path, size in self.files],
            "dir_errors": self.dir_errors,
        }

    @classmethod
    def from_json(cls, record: Dict[str, Any]) -> "PackageInventory":
        return cls(
            key=record["key"],
            name=record.get("name", ""),
            root=record.get("root", ""),
            files=[(str(path), int(size)) for path, size in record.get("files", [])],
            dir_errors=int(record.get("dir_errors", 0)),
        )


#: ``os.path.isjunction`` is 3.12+; on older Pythons a junction is simply not
#: distinguished here and the symlink check carries what it can.
_IS_JUNCTION = getattr(os.path, "isjunction", None)


@dataclass
class WalkStep:
    """One directory visited by :func:`_scandir_walk`."""

    path: Path
    #: Path relative to the walk root, ``""`` at the root itself. Carried
    #: through the walk rather than recovered by string-prefix arithmetic — a
    #: drive root (``G:/``) already ends in a separator, and stripping it back
    #: off a child path is exactly the kind of off-by-one that produced keys
    #: like ``G://G:/...`` the first time this ran for real.
    relative: str
    subdirs: List[str] = field(default_factory=list)
    files: List[Tuple[str, int]] = field(default_factory=list)
    errors: int = 0
    links: int = 0


def _scandir_walk(root: Path) -> Iterator[WalkStep]:
    """Depth-first, alphabetical walk of ``root``.

    ``os.scandir`` rather than ``os.walk`` because the size comes from the
    directory entry the walk already read: on Windows that is the difference
    between one syscall per directory and one extra ``stat`` per file, and the
    stat storm is half of why the ad-hoc sweeps starved. Entries are sorted so a
    second run over an unchanged tree produces a byte-identical inventory — and
    so ``--start/--limit`` addresses the same slice every time.

    A directory that cannot be listed is *counted*, never swallowed: a tree that
    half-failed must not read as a complete tree (the ``sandbox_snapshot`` rule).

    Symlinked and junctioned directories are not descended into — pnpm's virtual
    store is built out of them, and on Windows a junction is not an
    ``os.walk``-visible symlink, so following them is an unbounded walk rather
    than a bigger one. They are counted too.
    """
    stack: List[Tuple[Path, str]] = [(root, "")]
    while stack:
        current, relative = stack.pop()
        step = WalkStep(path=current, relative=relative)
        try:
            with os.scandir(current) as entries:
                listing = sorted(entries, key=lambda entry: entry.name)
        except OSError:
            step.errors = 1
            yield step
            continue

        for entry in listing:
            try:
                if entry.is_dir(follow_symlinks=False):
                    if entry.is_symlink() or (
                        _IS_JUNCTION is not None and _IS_JUNCTION(entry.path)
                    ):
                        step.links += 1
                        continue
                    step.subdirs.append(entry.name)
                elif entry.is_file(follow_symlinks=False):
                    step.files.append(
                        (entry.name, entry.stat(follow_symlinks=False).st_size)
                    )
            except OSError:
                step.errors += 1

        yield step
        # Reversed: `stack.pop()` takes the last item, so pushing in reverse
        # order keeps the traversal alphabetical.
        for name in reversed(step.subdirs):
            stack.append((current / name, _join(relative, name)))


def build_inventory(
    roots: Sequence[Path],
    on_progress: Optional[Any] = None,
    on_links: Optional[Any] = None,
) -> Iterator[PackageInventory]:
    """Yield one :class:`PackageInventory` per installed package under ``roots``.

    Packages are flushed as the walk leaves them rather than accumulated, so the
    memory cost is the current ``node_modules`` nesting depth (a handful of
    records) instead of the whole corpus — the second reason the ad-hoc sweeps
    fell over on a 7,576-package tree.
    """
    for root in roots:
        root = root.resolve()
        root_posix = root.as_posix()
        root_is_package = (root / "package.json").is_file()
        open_packages: Dict[str, PackageInventory] = {}
        directories = 0

        for step in _scandir_walk(root):
            directories += 1
            if step.links and on_links is not None:
                on_links(step.links)

            # Flush every package the walk has left. A package whose relative
            # directory is not a prefix of where the walk now is, is finished.
            for key in sorted(open_packages):
                if key and not (
                    step.relative == key or step.relative.startswith(key + "/")
                ):
                    yield _finish(open_packages.pop(key))

            # Register the owning package from the DIRECTORY, not only from a
            # scannable file in it: a package that ships nothing this phase can
            # read is still part of the corpus, and it is precisely the package
            # a coverage claim must not quietly omit.
            owner = resolve_package(step.relative, root_is_package)
            if owner is not None:
                package = _ensure_open(
                    open_packages, owner[0], owner[1], root, root_posix
                )
                package.dir_errors += step.errors

            for filename, size in step.files:
                owner = resolve_package(_join(step.relative, filename), root_is_package)
                if owner is None:
                    continue
                package_path, name, within = owner
                if not within or not is_scannable_code_path(within):
                    continue
                package = _ensure_open(
                    open_packages, package_path, name, root, root_posix
                )
                package.files.append((within, size))

            if on_progress is not None:
                on_progress(directories)

        for key in sorted(open_packages):
            yield _finish(open_packages.pop(key))


def _finish(package: PackageInventory) -> PackageInventory:
    """Sort a package's files before it leaves the walk.

    Here rather than in the CLI so *every* consumer gets the same order: a
    sweep sliced with ``--start/--limit`` must address the same files each run,
    and two inventories of an unchanged tree must be byte-identical.
    """
    package.files.sort()
    return package


def _join(left: str, right: str) -> str:
    return f"{left}/{right}" if left else right


def _ensure_open(
    open_packages: Dict[str, PackageInventory],
    package_path: str,
    name: str,
    root: Path,
    root_posix: str,
) -> PackageInventory:
    package = open_packages.get(package_path)
    if package is None:
        # `root / relative` rather than string concatenation, so a drive root
        # ("G:/") joins to "G:/node_modules/x" and not "G://G:/node_modules/x".
        directory = root / package_path if package_path else root
        package = PackageInventory(
            key=directory.as_posix(),
            name=name or directory.name,
            root=root_posix,
        )
        open_packages[package_path] = package
    return package


# --------------------------------------------------------------------------- #
# JSONL with a trailer (a truncated file is detectable, not silently short)
# --------------------------------------------------------------------------- #


class TruncatedReport(RuntimeError):
    """A JSONL corpus file that ends without its trailer line."""


def _write_line(handle: Any, record: Dict[str, Any]) -> None:
    handle.write(json.dumps(record, sort_keys=True))
    handle.write("\n")


#: How far back from EOF to look for the trailer line. A trailer is a few
#: hundred bytes; this is slack, not a guess at the record size.
_TRAILER_SEEK_BYTES = 64 * 1024


def _last_line(path: Path) -> str:
    """The final non-empty line of ``path``, read from the end.

    Reading the tail rather than the file: an inventory of a real machine is
    ~170 MB, and a sweep must be able to reject a truncated one in milliseconds
    instead of after parsing every record of it.
    """
    with path.open("rb") as handle:
        handle.seek(0, os.SEEK_END)
        size = handle.tell()
        handle.seek(max(0, size - _TRAILER_SEEK_BYTES))
        tail = handle.read().decode("utf-8", errors="ignore")
    for line in reversed(tail.splitlines()):
        if line.strip():
            return line.strip()
    return ""


def verify_bounds(path: Path, schema: str) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Validate a corpus file's header and trailer without reading the middle.

    A file that ends without its trailer was interrupted, and measuring on it
    would silently report a short corpus as a complete one — so it is refused
    here, before the expensive part starts rather than after.
    """
    with path.open("r", encoding="utf-8") as handle:
        first = handle.readline().strip()
    try:
        header = json.loads(first) if first else {}
    except json.JSONDecodeError:
        header = {}
    if header.get("kind") != "header":
        raise TruncatedReport(f"{path}: no header line — not a corpus_sweep file")
    if header.get("schema") != schema:
        raise TruncatedReport(
            f"{path}: schema is {header.get('schema')!r}, expected {schema!r}"
        )

    last = _last_line(path)
    try:
        trailer = json.loads(last) if last else {}
    except json.JSONDecodeError:
        trailer = {}
    if trailer.get("kind") != "trailer":
        raise TruncatedReport(
            f"{path}: no trailer line — the run was interrupted, so this file "
            f"holds an unknown fraction of its corpus. Re-run it (sweeps take "
            f"--resume) rather than measuring on a partial corpus."
        )
    return header, trailer


def iter_records(path: Path) -> Iterator[Dict[str, Any]]:
    """Stream the package records of a corpus file, one at a time.

    A generator, not a list: the inventory of this machine holds 143,010
    package records across 168 MB, and materialising them was itself a
    ``MemoryError`` — the very failure this harness exists to remove, found by
    running it for real.
    """
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("kind") not in ("header", "trailer"):
                yield record


def read_jsonl(
    path: Path, schema: str
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any]]:
    """Header, every record, and trailer — for callers that need the whole file.

    ``diff`` genuinely needs both reports at once (it is a join), and a report
    record carries no file list so it is a fraction of an inventory's size. The
    sweep must NOT use this; it streams via :func:`iter_records`.
    """
    header, trailer = verify_bounds(path, schema)
    return header, list(iter_records(path)), trailer


# --------------------------------------------------------------------------- #
# The sweep
# --------------------------------------------------------------------------- #


@dataclass
class PackageResult:
    """One package's malware-pattern hits, and how much of it was read."""

    key: str
    name: str
    dangers: Dict[str, int] = field(default_factory=dict)
    warnings: Dict[str, int] = field(default_factory=dict)
    corroborated: List[str] = field(default_factory=list)
    files_scanned: int = 0
    bytes_scanned: int = 0
    files_oversize: int = 0
    files_failed: int = 0
    dir_errors: int = 0
    oversize_examples: List[Tuple[str, int]] = field(default_factory=list)
    failed_examples: List[Tuple[str, str]] = field(default_factory=list)

    @property
    def complete(self) -> bool:
        """Whether every candidate file in the package was actually read."""
        return not (self.files_oversize or self.files_failed or self.dir_errors)

    def to_json(self) -> Dict[str, Any]:
        return {
            "kind": "package",
            "key": self.key,
            "name": self.name,
            "dangers": self.dangers,
            "warnings": self.warnings,
            "corroborated": self.corroborated,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "files_oversize": self.files_oversize,
            "files_failed": self.files_failed,
            "dir_errors": self.dir_errors,
            "oversize_examples": [[p, s] for p, s in self.oversize_examples],
            "failed_examples": [[p, r] for p, r in self.failed_examples],
            "complete": self.complete,
        }


def read_capped(path: Path, max_bytes: int) -> Tuple[Optional[str], int]:
    """Read at most ``max_bytes`` of ``path``; ``(None, size)`` when it is over.

    Reads ``max_bytes + 1`` so a file that grew past the cap since the inventory
    was taken is still caught here rather than silently truncated into a scan —
    a partial read of a bundle would produce a *coverage* claim the bytes do not
    support.
    """
    with path.open("rb") as handle:
        blob = handle.read(max_bytes + 1)
    if len(blob) > max_bytes:
        return None, len(blob)
    return blob.decode("utf-8", errors="ignore"), len(blob)


def sweep_package(
    package: PackageInventory, max_file_bytes: int
) -> PackageResult:
    """Run the shipped malware-pattern table over one inventoried package."""
    result = PackageResult(
        key=package.key, name=package.name, dir_errors=package.dir_errors
    )
    package_dir = Path(package.key)
    hits: List[Tuple[str, str]] = []

    for within, size in package.files:
        if size > max_file_bytes:
            result.files_oversize += 1
            if len(result.oversize_examples) < MAX_EXAMPLES:
                result.oversize_examples.append((within, size))
            continue
        try:
            content, actual = read_capped(package_dir / within, max_file_bytes)
        except (OSError, MemoryError) as read_error:
            # MemoryError belongs here, not only around the scan: measured on a
            # real 3,000-package sweep, the allocation that failed was the
            # 2 MB *read*, under machine-wide memory pressure. A sweep that
            # dies on one file is the failure this harness replaces, so the
            # file is counted and named and the run continues.
            result.files_failed += 1
            if len(result.failed_examples) < MAX_EXAMPLES:
                result.failed_examples.append(
                    (within, str(read_error) or type(read_error).__name__)
                )
            continue
        if content is None:
            result.files_oversize += 1
            if len(result.oversize_examples) < MAX_EXAMPLES:
                result.oversize_examples.append((within, actual))
            continue

        try:
            descriptions = scan_text_for_malware_patterns(content)
        except (MemoryError, RecursionError) as scan_error:
            # One pathological file must not end a 40-minute sweep, and it must
            # not be counted as scanned either.
            result.files_failed += 1
            if len(result.failed_examples) < MAX_EXAMPLES:
                result.failed_examples.append((within, type(scan_error).__name__))
            continue

        result.files_scanned += 1
        result.bytes_scanned += actual
        for description in descriptions:
            hits.append((within, description))

    classification = classify_malware_hits(hits)
    escalated = set(classification.corroborated)
    result.corroborated = sorted(escalated)
    for description, count in classification.counts.items():
        if is_dangerous_hit(description) or description in escalated:
            result.dangers[description] = count
        else:
            result.warnings[description] = count
    return result


# --------------------------------------------------------------------------- #
# Aggregation + diff
# --------------------------------------------------------------------------- #


class Totals:
    """Corpus-level totals, accumulated one package at a time.

    Incremental so a sweep never holds its results: a full-machine report is
    143,010 records, and the point of this harness is that the big numbers stop
    costing big memory.
    """

    def __init__(self) -> None:
        self.data: Dict[str, int] = {
            "packages": 0,
            "packages_with_dangers": 0,
            "packages_incomplete": 0,
            # A package whose bytes were never read has no verdict to
            # contribute. Counted separately so "N packages, zero false
            # dangers" cannot quietly include packages nothing looked at.
            "packages_unscanned": 0,
            "files_scanned": 0,
            "bytes_scanned": 0,
            "files_oversize": 0,
            "files_failed": 0,
            "dir_errors": 0,
            "danger_occurrences": 0,
            "warning_occurrences": 0,
        }

    def add(self, record: Dict[str, Any]) -> None:
        totals = self.data
        dangers = record.get("dangers", {})
        warnings = record.get("warnings", {})
        totals["packages"] += 1
        if dangers:
            totals["packages_with_dangers"] += 1
        if not record.get("complete", True):
            totals["packages_incomplete"] += 1
        if not int(record.get("files_scanned", 0)):
            totals["packages_unscanned"] += 1
        totals["files_scanned"] += int(record.get("files_scanned", 0))
        totals["bytes_scanned"] += int(record.get("bytes_scanned", 0))
        totals["files_oversize"] += int(record.get("files_oversize", 0))
        totals["files_failed"] += int(record.get("files_failed", 0))
        totals["dir_errors"] += int(record.get("dir_errors", 0))
        totals["danger_occurrences"] += sum(dangers.values())
        totals["warning_occurrences"] += sum(warnings.values())


def aggregate(results: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Corpus-level totals from per-package records."""
    totals = Totals()
    for record in results:
        totals.add(record)
    return totals.data


def _by_description(records: Sequence[Dict[str, Any]]) -> Dict[str, Dict[str, int]]:
    table: Dict[str, Dict[str, int]] = {}

    def bump(description: str, field_name: str, count: int) -> None:
        entry = table.setdefault(
            description,
            {"danger_packages": 0, "warning_packages": 0, "occurrences": 0},
        )
        entry[field_name] += 1
        entry["occurrences"] += count

    for record in records:
        for description, count in record.get("dangers", {}).items():
            bump(description, "danger_packages", int(count))
        for description, count in record.get("warnings", {}).items():
            bump(description, "warning_packages", int(count))
    return table


def diff_reports(
    old: Sequence[Dict[str, Any]], new: Sequence[Dict[str, Any]]
) -> Dict[str, Any]:
    """Machine-readable old-vs-new delta over two sweeps of the same corpus."""
    old_by_key = {record["key"]: record for record in old}
    new_by_key = {record["key"]: record for record in new}

    gained: List[Dict[str, Any]] = []
    lost: List[Dict[str, Any]] = []
    for key in sorted(set(old_by_key) & set(new_by_key)):
        before = set(old_by_key[key].get("dangers", {}))
        after = set(new_by_key[key].get("dangers", {}))
        if after - before:
            gained.append(
                {
                    "key": key,
                    "name": new_by_key[key].get("name", ""),
                    "descriptions": sorted(after - before),
                }
            )
        if before - after:
            lost.append(
                {
                    "key": key,
                    "name": old_by_key[key].get("name", ""),
                    "descriptions": sorted(before - after),
                }
            )

    old_totals = aggregate(old)
    new_totals = aggregate(new)
    old_descriptions = _by_description(old)
    new_descriptions = _by_description(new)

    description_delta: Dict[str, Any] = {}
    for description in sorted(set(old_descriptions) | set(new_descriptions)):
        before_entry = old_descriptions.get(
            description, {"danger_packages": 0, "warning_packages": 0, "occurrences": 0}
        )
        after_entry = new_descriptions.get(
            description, {"danger_packages": 0, "warning_packages": 0, "occurrences": 0}
        )
        if before_entry == after_entry:
            continue
        description_delta[description] = {
            "old": before_entry,
            "new": after_entry,
            "delta": {
                name: after_entry[name] - before_entry[name] for name in before_entry
            },
        }

    return {
        "schema": DIFF_SCHEMA,
        "totals": {
            "old": old_totals,
            "new": new_totals,
            "delta": {
                name: new_totals[name] - old_totals[name] for name in old_totals
            },
        },
        "packages_gained_dangers": gained,
        "packages_lost_dangers": lost,
        "packages_only_in_old": sorted(set(old_by_key) - set(new_by_key)),
        "packages_only_in_new": sorted(set(new_by_key) - set(old_by_key)),
        "descriptions": description_delta,
    }


# --------------------------------------------------------------------------- #
# Progress (stderr only — stdout stays machine-readable)
# --------------------------------------------------------------------------- #


class Progress:
    """Throttled stderr progress. Silent when ``--quiet``."""

    def __init__(self, enabled: bool = True, every_seconds: float = 2.0) -> None:
        self.enabled = enabled
        self.every_seconds = every_seconds
        self._last = 0.0
        self._started = time.time()

    def update(self, message: str, force: bool = False) -> None:
        if not self.enabled:
            return
        now = time.time()
        if not force and now - self._last < self.every_seconds:
            return
        self._last = now
        elapsed = now - self._started
        print(f"[{elapsed:7.1f}s] {message}", file=sys.stderr, flush=True)

    def note(self, message: str) -> None:
        if self.enabled:
            print(message, file=sys.stderr, flush=True)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #


def command_inventory(args: argparse.Namespace) -> int:
    roots = [Path(root) for root in args.root]
    missing = [str(root) for root in roots if not root.exists()]
    if missing:
        print(f"error: root(s) do not exist: {', '.join(missing)}", file=sys.stderr)
        return 2

    progress = Progress(enabled=not args.quiet)
    output = Path(args.output)
    packages = 0
    packages_with_files = 0
    files = 0
    total_bytes = 0
    dir_errors = 0
    directories = 0
    links = 0

    def on_directory(count: int) -> None:
        nonlocal directories
        directories = count
        progress.update(
            f"walking: {directories} dirs, {packages} packages, {files} files"
        )

    def on_links(count: int) -> None:
        nonlocal links
        links += count

    with output.open("w", encoding="utf-8") as handle:
        _write_line(
            handle,
            {
                "kind": "header",
                "schema": INVENTORY_SCHEMA,
                "roots": [str(root.resolve()) for root in roots],
            },
        )
        for package in build_inventory(
            roots, on_progress=on_directory, on_links=on_links
        ):
            packages += 1
            if package.files:
                packages_with_files += 1
            files += len(package.files)
            total_bytes += package.total_bytes
            dir_errors += package.dir_errors
            _write_line(handle, package.to_json())
        _write_line(
            handle,
            {
                "kind": "trailer",
                "totals": {
                    "packages": packages,
                    "packages_with_files": packages_with_files,
                    "files": files,
                    "bytes": total_bytes,
                    "dir_errors": dir_errors,
                    "directories": directories,
                    "linked_dirs_skipped": links,
                },
            },
        )

    progress.update(
        f"inventory complete: {packages} packages "
        f"({packages_with_files} with scannable code), {files} files, "
        f"{total_bytes / 1e6:.1f} MB, {dir_errors} unreadable dirs, "
        f"{links} linked dirs not descended",
        force=True,
    )
    print(str(output))
    return 0


def _load_resume(path: Path) -> Dict[str, Dict[str, Any]]:
    """Per-package records already written to a report, keyed by package.

    Deliberately tolerant of a missing trailer: resuming is exactly the case
    where the previous run was interrupted, and the whole point is to keep the
    packages it did finish.
    """
    if not path.exists():
        return {}
    done: Dict[str, Dict[str, Any]] = {}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                # A half-written final line from a hard kill: everything before
                # it is still good.
                break
            if record.get("kind") == "package":
                done[record["key"]] = record
    return done


def command_sweep(args: argparse.Namespace) -> int:
    inventory_path = Path(args.inventory)
    if not inventory_path.exists():
        print(f"error: inventory not found: {inventory_path}", file=sys.stderr)
        return 2
    try:
        # Bounds first, and cheaply: a truncated inventory must be rejected in
        # milliseconds rather than after an hour of sweeping it.
        header, trailer = verify_bounds(inventory_path, INVENTORY_SCHEMA)
    except (TruncatedReport, json.JSONDecodeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    output = Path(args.output)
    progress = Progress(enabled=not args.quiet)
    resume = _load_resume(output) if args.resume else {}
    # A resume APPENDS to the report it is resuming. Rewriting it would mean a
    # second interruption throws away the work the first one survived — and the
    # reason to resume at all is that this sweep takes 25 minutes over 3,000
    # packages on a real disk.
    resuming = bool(args.resume and output.exists())
    if resume:
        progress.note(f"resuming: {len(resume)} package(s) already swept")

    available = int(trailer.get("totals", {}).get("packages", 0))
    end = None if args.limit is None else args.start + args.limit
    if args.start or end is not None:
        # Never a silent cap: a sliced sweep that reported like a full one would
        # be the same overclaim the size cap is reported for.
        progress.note(
            f"NOTE: sweeping a slice — skipping {args.start} package(s) before "
            f"the start"
            + (f" and everything past #{end}" if end is not None else "")
            + f"; the inventory holds {available}"
        )

    swept = 0
    reused = 0
    totals = Totals()
    started = time.time()
    # Streamed, never materialised: `--resume` reading its own output is the
    # only place this command holds per-package state.
    stream = itertools.islice(iter_records(inventory_path), args.start, end)

    with output.open("a" if resuming else "w", encoding="utf-8") as handle:
        if not resuming:
            _write_line(
                handle,
                {
                    "kind": "header",
                    "schema": REPORT_SCHEMA,
                    "inventory": str(inventory_path),
                    "inventory_roots": header.get("roots", []),
                    "inventory_totals": trailer.get("totals", {}),
                    "max_file_bytes": args.max_file_bytes,
                    "slice": {
                        "start": args.start,
                        "limit": args.limit,
                        "available": available,
                    },
                },
            )
        for record in stream:
            cached = resume.get(record["key"])
            if cached is not None:
                # Already on disk from the interrupted run: count it, do not
                # rewrite it.
                totals.add(cached)
                reused += 1
                continue
            package = PackageInventory.from_json(record)
            result = sweep_package(package, args.max_file_bytes).to_json()
            swept += 1
            totals.add(result)
            _write_line(handle, result)
            handle.flush()
            done = swept + reused
            progress.update(
                f"sweeping: {done} packages "
                f"({done / max(time.time() - started, 1e-9):.0f}/s), "
                f"{totals.data['files_scanned']} files, "
                f"{totals.data['packages_with_dangers']} with dangers"
            )
        _write_line(handle, {"kind": "trailer", "totals": totals.data})

    summary = totals.data
    progress.update(
        f"sweep complete: {summary['packages']} packages "
        f"({reused} reused), {summary['files_scanned']} files, "
        f"{summary['packages_with_dangers']} with dangers, "
        f"{summary['files_oversize']} over the {args.max_file_bytes} B cap, "
        f"{summary['files_failed']} unreadable",
        force=True,
    )
    if args.summary:
        json.dump(summary, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(str(output))
    return 0


def command_diff(args: argparse.Namespace) -> int:
    try:
        _, old_records, _ = read_jsonl(Path(args.old), REPORT_SCHEMA)
        _, new_records, _ = read_jsonl(Path(args.new), REPORT_SCHEMA)
    except (TruncatedReport, json.JSONDecodeError, OSError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    report = diff_reports(old_records, new_records)
    report["old"] = str(args.old)
    report["new"] = str(args.new)

    if args.output:
        Path(args.output).write_text(
            json.dumps(report, indent=2, sort_keys=True), encoding="utf-8"
        )
    else:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")

    gained = report["packages_gained_dangers"]
    if not args.quiet:
        delta = report["totals"]["delta"]
        print(
            f"packages gaining dangers: {len(gained)}; "
            f"losing dangers: {len(report['packages_lost_dangers'])}; "
            f"danger-occurrence delta: {delta['danger_occurrences']:+d}; "
            f"warning-occurrence delta: {delta['warning_occurrences']:+d}",
            file=sys.stderr,
        )
    if args.fail_on_new_dangers and gained:
        return 1
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="corpus_sweep.py",
        description=(
            "Re-runnable malware-pattern sweep over installed npm packages: "
            "walk once, sweep repeatedly, diff two sweeps."
        ),
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    inventory = subparsers.add_parser(
        "inventory", help="walk the roots once and persist the scannable-file list"
    )
    inventory.add_argument(
        "--root",
        action="append",
        required=True,
        help="a directory to walk (repeatable); node_modules trees are found inside it",
    )
    inventory.add_argument("-o", "--output", required=True, help="inventory JSONL path")
    inventory.add_argument("-q", "--quiet", action="store_true")
    inventory.set_defaults(func=command_inventory)

    sweep = subparsers.add_parser(
        "sweep", help="scan an inventory and write a per-package report"
    )
    sweep.add_argument("-i", "--inventory", required=True)
    sweep.add_argument("-o", "--output", required=True, help="report JSONL path")
    sweep.add_argument(
        "--max-file-bytes",
        type=int,
        default=DEFAULT_MAX_FILE_BYTES,
        help=(
            "per-file read cap; a larger file is counted and named as oversize "
            f"rather than scanned (default {DEFAULT_MAX_FILE_BYTES})"
        ),
    )
    sweep.add_argument(
        "--resume",
        action="store_true",
        help="reuse per-package results already present in the output file",
    )
    sweep.add_argument("--start", type=int, default=0, help="skip the first N packages")
    sweep.add_argument("--limit", type=int, default=None, help="sweep at most N packages")
    sweep.add_argument(
        "--summary",
        action="store_true",
        help="print the corpus totals as JSON on stdout instead of the report path",
    )
    sweep.add_argument("-q", "--quiet", action="store_true")
    sweep.set_defaults(func=command_sweep)

    diff = subparsers.add_parser("diff", help="compare two reports over the same corpus")
    diff.add_argument("old")
    diff.add_argument("new")
    diff.add_argument("-o", "--output", default=None, help="write the diff JSON here")
    diff.add_argument(
        "--fail-on-new-dangers",
        action="store_true",
        help="exit 1 when any package gained a danger (a CI-usable calibration gate)",
    )
    diff.add_argument("-q", "--quiet", action="store_true")
    diff.set_defaults(func=command_diff)

    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
