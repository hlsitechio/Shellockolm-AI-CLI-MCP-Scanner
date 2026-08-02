"""Lockfile-vs-disk verification of the tree ``npm install`` left behind
(build-loop follow-up F47).

F47 asked whether a dependency that **wipes a sibling package** during its
``postinstall`` could be told apart from npm's own pruning, given that
``sandbox_check.filter_unexpected_deletions`` drops every deletion under
``node_modules/``. Measuring the phase-4 diff first answered a different and
more useful question: that filter is not what hides sibling sabotage — the
**baseline** is. The pre-install snapshot is taken of a temp directory holding
one ``package.json`` and the decoy files, so ``node_modules/`` does not exist in
it. A file npm creates during the install and a hook deletes seconds later was
never in the baseline and is not in the post-install walk, so it appears in
*none* of ``compare_snapshots``' three lists. Widening the deletion filter would
have changed nothing: there is no deletion to filter.

Seeing intra-install churn needs a record of what npm *intended* to leave
behind, which is exactly the lockfile F36 already keeps (the sandbox install
deliberately omits ``--no-save``). This module reads
``package-lock.json`` as that source of truth and checks each package it names
against the disk:

* the package directory exists;
* it still has a ``package.json``, non-empty;
* the entry point the manifest's ``main`` declares still resolves, non-empty.

What that catches is a dependency **removed or gutted** after npm put it there.
What it does not catch is stated rather than implied: a sibling file that is
neither the manifest nor the entry point can be deleted invisibly, and a
sibling *rewritten* with attacker code passes every check here (the file
exists and is non-empty). Both need a per-file record of the reified tree,
which this pass does not have.

Both calibrations are measured against real installs, not assumed, because a
check that reports a healthy tree as sabotaged is worse than no check at all.

*Which lockfile entries are expected on disk*: across six real installs
(left-pad, chalk, express, typescript, esbuild, @babel/core — 161 lockfile
entries), **44** entries named a directory that was legitimately absent, and
every single one carried ``"optional": true`` together with an ``os``/``cpu``
constraint. npm records the whole platform matrix of a package like
``@esbuild/*`` in the lockfile and installs the one entry that matches the host,
so :func:`_is_platform_conditional` excludes them — taking that corpus to zero
false positives.

*What counts as an intact entry point*: measured over **679 installed packages**
from 18 real dependency trees, of which 451 declare ``main`` and 230 declare
``exports`` (1,292 concrete targets). Reading ``main`` alone reports **2**
healthy packages as gutted — ``@humanfs/core`` and ``@humanfs/node``, both
dependencies of eslint, ship ``"main": "dist/index.js"`` with only ``.d.ts``
files in that directory, because their real entry point is the ``exports``
target ``./src/index.js``. Requiring *every* ``exports`` target to exist is worse
(**10** findings: ``@babel/helper-*`` and ``yargs`` list ``.d.ts`` files they do
not publish). Deferring to ``exports`` when it is present and requiring **one**
target to resolve reports **zero**. The 228 packages that declare no entry point
at all are not guessed at: assuming ``index.js`` would call every types-only and
bin-only package gutted.

Filesystem-touching but console-free and unit-testable, mirroring
:mod:`sandbox_deps` and :mod:`sandbox_codescan`.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from sandbox_deps import (
    LOCKFILE_NAME,
    MANIFEST_NAME,
    NESTED_MODULES_DIR,
    lockfile_key_to_package_dir,
    read_lockfile,
    read_manifest,
)

#: Lockfile flags that mean "npm may legitimately not have installed this".
#: ``optional``/``devOptional`` mark a dependency reached only through
#: ``optionalDependencies``, and ``os``/``cpu`` a build published for a platform
#: that is not this one. Measured over six real installs, these three account for
#: **every** absent directory (44/44) — see the module docstring.
PLATFORM_CONDITIONAL_FLAGS: Tuple[str, ...] = ("optional", "devOptional")
PLATFORM_CONSTRAINT_FIELDS: Tuple[str, ...] = ("os", "cpu")

#: A lockfile entry that is a symlink to a workspace rather than an installed
#: copy. Its contents live outside ``node_modules`` and are not this pass's to
#: verify.
LINK_FLAG = "link"

#: Suffixes Node tries when resolving a ``main`` that is not an exact file, and
#: the index files it falls back to for a directory. Mirroring the resolver
#: matters: ``"main": "./lib/index"`` is a real published shape, and treating it
#: as a missing file would report a healthy package as gutted.
ENTRY_SUFFIXES: Tuple[str, ...] = (".js", ".json", ".node")
ENTRY_INDEX_NAMES: Tuple[str, ...] = ("index.js", "index.json", "index.node")

#: How deep the ``exports`` walk descends, and how many targets it collects.
#: The manifest is untrusted input: a self-referential structure must not be able
#: to exhaust the stack, and a generated one must not build an unbounded list.
MAX_EXPORTS_DEPTH = 8
MAX_EXPORTS_TARGETS = 256

#: How many damaged packages are reported individually before the rest are
#: summarised. A tree-wide wipe must not produce a hundred findings.
MAX_REPORTED_DAMAGE = 10

#: How many unreadable manifests are kept as examples for the console line.
MAX_UNREADABLE_EXAMPLES = 3

# Damage kinds, phrased as the sentence that reaches the user.
DAMAGE_DIRECTORY_GONE = "its directory is gone"
DAMAGE_MANIFEST_GONE = f"its {MANIFEST_NAME} is gone"
DAMAGE_MANIFEST_EMPTIED = f"its {MANIFEST_NAME} was emptied"
DAMAGE_ENTRY_GONE = "the entry point its manifest declares is gone"
DAMAGE_ENTRY_EMPTIED = "the entry point its manifest declares was emptied"


@dataclass(frozen=True)
class ExpectedPackage:
    """One package ``package-lock.json`` says npm installed."""

    #: Path under ``node_modules/``, e.g. ``left-pad`` or ``a/node_modules/b``.
    package_dir: str
    #: The lockfile key it came from, kept for the finding line.
    lockfile_key: str
    name: str = ""
    version: str = ""

    @property
    def label(self) -> str:
        """How this package is named in a finding.

        Falls back to the installed directory when neither the lockfile entry nor
        the key yields a name — a package that is gone cannot be re-read for one.
        """
        if self.name and self.version:
            return f"{self.name}@{self.version}"
        return self.name or self.package_dir


@dataclass(frozen=True)
class ExpectedTree:
    """What the lockfile claims the install left on disk.

    ``unavailable_reason`` is the honest third state, matching
    :class:`sandbox_deps.InstallSourceIndex`: not "the install placed nothing"
    but "the lockfile could not answer". A caller holding one of those cannot
    report an intact tree, so it marks the phase blind instead.
    """

    packages: Tuple[ExpectedPackage, ...] = ()
    #: Entries skipped because npm installs them only on a matching platform.
    platform_conditional: int = 0
    #: Entries skipped because they are workspace symlinks, not installed copies.
    linked: int = 0
    unavailable_reason: Optional[str] = None

    @property
    def is_authoritative(self) -> bool:
        """Whether this tree can be used to call a package missing."""
        return self.unavailable_reason is None

    def __len__(self) -> int:
        return len(self.packages)


@dataclass(frozen=True)
class DamagedPackage:
    """One package the lockfile names that is not intact on disk."""

    package: ExpectedPackage
    #: One of the ``DAMAGE_*`` constants.
    kind: str
    #: The path that is missing or empty, relative to the sandbox root.
    path: str

    def describe(self) -> str:
        """The finding line, naming the package, the damage and the path."""
        return (
            f"Installed dependency {self.package.label} was damaged during the "
            f"install: {self.kind} ({self.path}), but package-lock.json records "
            f"npm installing it"
        )


@dataclass
class TreeIntegrityReport:
    """Result of the lockfile-vs-disk pass, including how much of it ran."""

    expected_count: int = 0
    verified_count: int = 0
    platform_conditional: int = 0
    linked: int = 0
    #: Every package that failed a check, in lockfile order.
    damaged: List[DamagedPackage] = field(default_factory=list)
    #: ``(package dir, error text)`` for manifests that could not be read or
    #: parsed. The directory and manifest were still verified to exist; only the
    #: entry-point check could not run, so the blindness is narrow.
    unreadable_examples: List[Tuple[str, str]] = field(default_factory=list)
    manifests_unreadable: int = 0
    #: Set when ``node_modules/`` itself is absent while the lockfile names
    #: packages — reported as one finding rather than one per package.
    tree_missing: bool = False
    #: Why the lockfile could not be used, or ``None`` when it could.
    unavailable_reason: Optional[str] = None

    @property
    def damaged_count(self) -> int:
        return len(self.damaged)

    @property
    def dangers(self) -> List[str]:
        """Finding lines for ``SandboxFindings``, capped with a summary line.

        A postinstall that deletes the whole tree would otherwise emit one
        finding per package; the cap keeps the verdict readable without hiding
        the scale, which the summary line carries.
        """
        if self.tree_missing:
            return [
                f"The installed tree is gone after the install: "
                f"{NESTED_MODULES_DIR}/ does not exist, but package-lock.json "
                f"records npm installing {self.expected_count} package(s)"
            ]
        lines = [entry.describe() for entry in self.damaged[:MAX_REPORTED_DAMAGE]]
        remaining = self.damaged_count - len(lines)
        if remaining > 0:
            lines.append(
                f"... and {remaining} more installed dependency(s) damaged during "
                f"the install"
            )
        return lines

    def blind_reason(self) -> Optional[str]:
        """Why this pass could not verify the tree, or ``None``.

        A non-``None`` value must reach ``SandboxFindings.mark_blind``: it means
        "the installed tree is intact" would be the absence of evidence rather
        than evidence of absence (the F29 rule).
        """
        if self.unavailable_reason:
            return (
                f"{self.unavailable_reason} - the installed tree was NOT verified "
                f"against what npm recorded installing"
            )
        if self.manifests_unreadable:
            return (
                f"{self.manifests_unreadable} installed manifest(s) could not be "
                f"read - their entry points were NOT verified"
            )
        return None


def package_name_from_dir(package_dir: str) -> str:
    """The package name a ``node_modules`` path denotes.

    npm does **not** write a ``name`` field for a registry entry in a version-3
    lockfile — the key carries it — so a finding built from the entry alone would
    name a wiped package by its directory instead of its name. The trailing
    segment after any nested ``node_modules`` is that name, scope included::

        left-pad                 -> left-pad
        @scope/pkg               -> @scope/pkg
        a/node_modules/@s/b      -> @s/b
    """
    separator = f"/{NESTED_MODULES_DIR}/"
    tail = package_dir.rsplit(separator, 1)[-1]
    return tail.strip("/")


def _is_platform_conditional(entry: dict) -> bool:
    """Whether npm installs this entry only on a matching platform."""
    if any(entry.get(flag) for flag in PLATFORM_CONDITIONAL_FLAGS):
        return True
    return any(entry.get(field_name) for field_name in PLATFORM_CONSTRAINT_FIELDS)


def _expected_from_v3(packages: object) -> ExpectedTree:
    """Build the expected tree from a ``lockfileVersion`` 2/3 ``packages`` map."""
    found: List[ExpectedPackage] = []
    platform_conditional = 0
    linked = 0

    if not isinstance(packages, dict):
        return ExpectedTree(
            unavailable_reason=f"{LOCKFILE_NAME} has no `packages` map"
        )

    for key, entry in packages.items():
        if not isinstance(key, str) or not isinstance(entry, dict):
            continue
        package_dir = lockfile_key_to_package_dir(key)
        if package_dir is None:
            # The root project (""), a workspace directory, or a malformed
            # chain — none of which is a package npm unpacked into the tree.
            continue
        if entry.get(LINK_FLAG):
            linked += 1
            continue
        if _is_platform_conditional(entry):
            platform_conditional += 1
            continue
        name = entry.get("name")
        version = entry.get("version")
        found.append(
            ExpectedPackage(
                package_dir=package_dir,
                lockfile_key=key,
                name=(
                    name if isinstance(name, str) and name
                    else package_name_from_dir(package_dir)
                ),
                version=version if isinstance(version, str) else "",
            )
        )

    return ExpectedTree(
        packages=tuple(found),
        platform_conditional=platform_conditional,
        linked=linked,
    )


def load_expected_install_tree(project_root: Path) -> ExpectedTree:
    """Read ``project_root/package-lock.json`` as the record of what npm installed.

    Only the flat ``packages`` map of ``lockfileVersion`` 2/3 is used. A version-1
    lockfile yields an ``unavailable_reason`` rather than a guess: its nested
    ``dependencies`` tree predates the hoisting layout this pass has to resolve
    against, and claiming a package is missing from a layout that was never
    measured would invent findings. Blind is the honest state, and npm has
    written version 2 or 3 since npm 7 (2020).

    A lockfile that is missing, unreadable, unparseable or not an object is the
    same third state, for the same reason.
    """
    path = project_root / LOCKFILE_NAME

    try:
        raw = read_lockfile(path)
    except OSError as read_err:
        return ExpectedTree(
            unavailable_reason=f"{LOCKFILE_NAME} could not be read ({read_err})"
        )

    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return ExpectedTree(unavailable_reason=f"{LOCKFILE_NAME} could not be parsed")
    if not isinstance(data, dict):
        return ExpectedTree(unavailable_reason=f"{LOCKFILE_NAME} is not an object")

    return _expected_from_v3(data.get("packages"))


def _file_size(path: Path) -> Optional[int]:
    """Size of ``path`` if it is a readable regular file, else ``None``."""
    try:
        if not path.is_file():
            return None
        return path.stat().st_size
    except OSError:
        return None


def normalize_entry_path(main: str) -> Optional[str]:
    """A manifest's ``main`` as a package-relative path, or ``None`` to skip it.

    ``None`` means the value is not one this pass resolves: an absolute path, or
    one climbing out with ``..``. Following those would have it stat — and report
    on — a file belonging to something else.

    The leading ``./`` is stripped in a loop rather than with ``lstrip("./")``,
    which takes a CHARACTER SET: that call turns ``"./.internal/x"`` into
    ``"internal/x"`` and would report a healthy package's entry point as gone.
    """
    normalized = main.replace("\\", "/").strip()
    if not normalized or normalized.startswith("/"):
        return None
    if len(normalized) > 1 and normalized[1] == ":":  # C:\... on Windows
        return None
    if ".." in normalized.split("/"):
        return None
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized.rstrip("/") or "index.js"


def _resolve_entry_point(package_path: Path, main: str) -> Tuple[Optional[Path], bool]:
    """Resolve a manifest's ``main`` the way Node does.

    Returns ``(resolved path or None, whether any candidate was checked)``. The
    second value distinguishes "``main`` names a file that is gone" from "``main``
    was not a value this pass resolves", so only the former is ever reported.
    """
    relative = normalize_entry_path(main)
    if relative is None:
        return None, False

    base = package_path / relative

    candidates = [base]
    candidates.extend(package_path / f"{relative}{suffix}" for suffix in ENTRY_SUFFIXES)
    candidates.extend(base / index_name for index_name in ENTRY_INDEX_NAMES)

    for candidate in candidates:
        if _file_size(candidate) is not None:
            return candidate, True
    return None, True


def collect_export_targets(exports: object) -> Tuple[str, ...]:
    """Every concrete file target in a manifest's ``exports`` field.

    ``exports`` is a tree of condition maps, subpath maps, arrays and strings;
    only the strings are targets. Wildcard targets (``"./*": "./dist/*.js"``)
    are dropped because they name no file without a subpath to substitute, and
    anything not starting with ``.`` is a bare specifier that resolves through
    another package rather than this one's files.

    The walk is iterative with a depth bound: a manifest is untrusted input.
    """
    found: List[str] = []
    pending: List[Tuple[object, int]] = [(exports, 0)]

    while pending and len(found) < MAX_EXPORTS_TARGETS:
        node, depth = pending.pop()
        if depth > MAX_EXPORTS_DEPTH:
            continue
        if isinstance(node, str):
            if node.startswith(".") and "*" not in node:
                found.append(node)
        elif isinstance(node, list):
            pending.extend((item, depth + 1) for item in node)
        elif isinstance(node, dict):
            # Keys are subpaths and conditions; only the values are targets.
            pending.extend((value, depth + 1) for value in node.values())

    return tuple(found)


def _check_export_entries(
    package_path: Path, targets: Tuple[str, ...]
) -> Optional[str]:
    """Damage kind for a package whose entry points come from ``exports``.

    Returns ``None`` when the entry surface is intact, an unresolvable target set
    means there is nothing to claim, or the manifest names no file this pass can
    stat.

    The rule is **at least one target must resolve**, and it is measured rather
    than chosen: over **679 real installed packages** (18 dependency trees, 230
    of them declaring ``exports`` across 1,292 targets), requiring *every* target
    to exist produced **10** findings on packages that are perfectly healthy —
    ``@babel/helper-*`` and ``yargs`` list ``.d.ts`` files they do not publish,
    and ``expect`` lists build outputs it does not ship. Requiring one produced
    **zero**. A package whose every entry point is gone is still caught, which is
    the shape this pass is for.
    """
    resolvable = [
        normalized
        for normalized in (normalize_entry_path(target) for target in targets)
        if normalized
    ]
    if not resolvable:
        return None

    sizes = [
        size
        for size in (_file_size(package_path / relative) for relative in resolvable)
        if size is not None
    ]
    if not sizes:
        return DAMAGE_ENTRY_GONE
    if all(size == 0 for size in sizes):
        return DAMAGE_ENTRY_EMPTIED
    return None


def _relative_to_root(project_root: Path, path: Path) -> str:
    """Forward-slashed sandbox-relative path for a finding line."""
    try:
        return path.relative_to(project_root).as_posix()
    except ValueError:
        return path.as_posix()


def verify_installed_tree(
    project_root: Path, expected: Optional[ExpectedTree] = None
) -> TreeIntegrityReport:
    """Check every package the lockfile names against what is on disk.

    ``expected`` is accepted so a caller that already loaded the tree does not
    read the lockfile twice; it is loaded here when omitted.
    """
    if expected is None:
        expected = load_expected_install_tree(project_root)

    report = TreeIntegrityReport(
        expected_count=len(expected),
        platform_conditional=expected.platform_conditional,
        linked=expected.linked,
        unavailable_reason=expected.unavailable_reason,
    )
    if not expected.is_authoritative or not expected.packages:
        return report

    modules_root = project_root / NESTED_MODULES_DIR
    if not modules_root.is_dir():
        # One finding, not one per package: the whole tree is the thing missing.
        report.tree_missing = True
        return report

    for package in expected.packages:
        package_path = modules_root / package.package_dir
        if not package_path.is_dir():
            report.damaged.append(
                DamagedPackage(
                    package=package,
                    kind=DAMAGE_DIRECTORY_GONE,
                    path=_relative_to_root(project_root, package_path),
                )
            )
            continue

        manifest_path = package_path / MANIFEST_NAME
        manifest_size = _file_size(manifest_path)
        manifest_rel = _relative_to_root(project_root, manifest_path)
        if manifest_size is None:
            report.damaged.append(
                DamagedPackage(
                    package=package, kind=DAMAGE_MANIFEST_GONE, path=manifest_rel
                )
            )
            continue
        if manifest_size == 0:
            report.damaged.append(
                DamagedPackage(
                    package=package, kind=DAMAGE_MANIFEST_EMPTIED, path=manifest_rel
                )
            )
            continue

        try:
            manifest = json.loads(read_manifest(manifest_path))
        except (OSError, ValueError, RecursionError) as manifest_err:
            # The package is present; only its entry point stays unverified.
            report.manifests_unreadable += 1
            if len(report.unreadable_examples) < MAX_UNREADABLE_EXAMPLES:
                report.unreadable_examples.append(
                    (package.package_dir, str(manifest_err))
                )
            continue

        exports = manifest.get("exports") if isinstance(manifest, dict) else None
        if exports is not None:
            # `exports` REPLACES `main` in Node's resolver, so a package that has
            # one is verified through it and `main` is not consulted. Measured:
            # `@humanfs/node` ships `"main": "dist/index.js"` with only
            # `dist/*.d.ts` in that directory — its real entry point is the
            # `exports` target `./src/index.js`. Reading `main` there reported a
            # healthy dependency of eslint as gutted.
            damage = _check_export_entries(package_path, collect_export_targets(exports))
            if damage is None:
                report.verified_count += 1
                continue
            report.damaged.append(
                DamagedPackage(
                    package=package,
                    kind=damage,
                    path=_relative_to_root(project_root, package_path),
                )
            )
            continue

        main = manifest.get("main") if isinstance(manifest, dict) else None
        if not isinstance(main, str) or not main.strip():
            # No declared entry point to verify. Guessing `index.js` here would
            # report every types-only or bin-only package as gutted: 228 of the
            # 679 measured packages declare no `main`.
            report.verified_count += 1
            continue

        resolved, checked = _resolve_entry_point(package_path, main)
        if not checked:
            report.verified_count += 1
            continue
        if resolved is None:
            report.damaged.append(
                DamagedPackage(
                    package=package,
                    kind=DAMAGE_ENTRY_GONE,
                    path=f"{_relative_to_root(project_root, package_path)}/{main}",
                )
            )
            continue
        if _file_size(resolved) == 0:
            report.damaged.append(
                DamagedPackage(
                    package=package,
                    kind=DAMAGE_ENTRY_EMPTIED,
                    path=_relative_to_root(project_root, resolved),
                )
            )
            continue

        report.verified_count += 1

    return report


def describe_tree_integrity(report: TreeIntegrityReport) -> str:
    """One-line summary of how much of the tree was verified, for the console."""
    if report.unavailable_reason:
        return f"Installed-tree check did not run: {report.unavailable_reason}"
    if not report.expected_count:
        return "package-lock.json records no installed package to verify"
    skipped = report.platform_conditional + report.linked
    suffix = (
        f" ({skipped} platform-conditional or linked entry(s) not applicable)"
        if skipped
        else ""
    )
    return (
        f"Verified {report.verified_count}/{report.expected_count} package(s) "
        f"npm recorded installing{suffix}"
    )
