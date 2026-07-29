"""Installed-dependency lifecycle-hook analysis for ``sandbox <pkg>``
(build-loop follow-up F34).

Phase 1 of the sandbox check runs :func:`sandbox_check.analyze_install_scripts`
over the **target** package's ``scripts`` block, as returned by ``npm view``.
Phase 5 reads the installed code but deliberately does not treat
``package.json`` as scannable source (it is data, and counting it would defeat
F33's blind check, since every package ships one).

Between the two, nothing looked at the ``preinstall`` / ``install`` /
``postinstall`` / ``prepare`` hooks of the **transitive** packages npm just
installed — every one of which already executed during phase 3, and which is
where a compromised indirect dependency actually lands. The user was shown
"✓ No install scripts" for the package they named while a dependency four levels
down ran ``curl … | sh`` on their machine.

This module closes that: it walks the installed tree and runs the existing
structured ``analyze_install_scripts`` over each installed manifest, reported
per package.

Two things make it precise rather than noisy:

* :func:`is_installed_package_manifest` is the rule for what npm actually
  *installed*, expressed structurally: a manifest counts only when its directory
  chain is ``<name>`` / ``@scope/<name>``, optionally repeated through a nested
  ``node_modules``. A ``package.json`` sitting in a package's own test fixtures
  or examples is **not** an installed package and its hooks never run, so it is
  never reported. The same predicate gates the traversal, so the walk descends
  only where npm places packages instead of reading a whole source tree.
* :meth:`DependencyScriptReport.blind_reason` applies the F29 rule — an
  unreadable manifest, an unparseable one, or a directory that could not be
  listed means the pass has no conclusion to offer, so the caller marks it blind
  rather than printing a pass.

Filesystem-touching but console-free and unit-testable, mirroring
:mod:`sandbox_codescan` and :mod:`sandbox_snapshot`; the hook table and the
danger classification stay in the pure :mod:`sandbox_check`.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import FrozenSet, List, Optional, Tuple

from sandbox_check import analyze_install_scripts

#: The manifest filename npm reads a package's lifecycle hooks from.
MANIFEST_NAME = "package.json"

#: The directory name that separates one package from its nested dependencies.
NESTED_MODULES_DIR = "node_modules"

#: How many unreadable manifests are kept as examples for the console line.
MAX_UNREADABLE_EXAMPLES = 3

#: Danger lines from ``analyze_install_scripts`` start with this marker.
DANGER_PREFIX = "🚨 "

#: The lifecycle hooks npm actually runs for a package installed as a
#: **dependency** from a registry tarball — i.e. the ones that already executed
#: during phase 3, on the user's machine, without a prompt.
#:
#: ``prepare`` is deliberately absent. npm runs it for the *root* project, for a
#: dependency given as a **git** URL, and before ``npm publish`` — never for a
#: registry tarball. Treating it as executed is a measured false positive: over
#: 44,980 real installed packages the only two danger lines this pass produced
#: were ``faiss-node``'s ``install`` hook (a true positive — it clones and builds
#: from GitHub) and ``remix-island``'s ``prepare`` hook, whose ``rm -rf dist &&
#: npm run build`` is the package's own build cleanup and never ran on any
#: consumer's machine. A declared ``prepare`` is still surfaced, but as a
#: conditional hook rather than as something that executed.
AUTO_RUN_DEPENDENCY_HOOKS: Tuple[str, ...] = ("preinstall", "install", "postinstall")


# ---------------------------------------------------------------------------
# What counts as an installed package
# ---------------------------------------------------------------------------


def _is_package_name_segment(segment: str) -> bool:
    """Whether one path segment can be an npm package name.

    Rejects npm's own bookkeeping directories (``.bin``, ``.cache``, ``.pnpm``)
    — a package name may not begin with a dot — a bare scope marker, and the
    literal ``node_modules``, so a malformed directory chain can never be read
    as a package.
    """
    if not segment or segment.startswith(".") or segment.startswith("@"):
        return False
    return segment != NESTED_MODULES_DIR


def is_installed_package_manifest(relative_path: str) -> bool:
    """Whether ``relative_path`` (relative to a ``node_modules`` root) is a
    manifest npm will run lifecycle hooks from.

    The accepted shape is ``PKG`` optionally repeated through nested module
    directories, where ``PKG`` is ``<name>`` or ``@scope/<name>``::

        lodash/package.json                        -> True
        @babel/core/package.json                   -> True
        foo/node_modules/bar/package.json          -> True
        @a/b/node_modules/@c/d/package.json        -> True

    Everything else is not an installed package. In particular a manifest inside
    a package's own source tree is rejected::

        foo/test/fixtures/package.json             -> False
        foo/examples/demo/package.json             -> False
        .bin/package.json                          -> False
        foo/node_modules/package.json              -> False

    That distinction is the whole precision of this pass: npm never runs the
    hooks in a fixture manifest, so reporting one would be a false positive on
    every package that ships integration tests.
    """
    normalized = (relative_path or "").replace("\\", "/").strip("/")
    if not normalized:
        return False

    segments = normalized.split("/")
    if segments[-1] != MANIFEST_NAME:
        return False

    directory = segments[:-1]
    total = len(directory)
    if not total:
        return False

    index = 0
    while index < total:
        segment = directory[index]
        if segment.startswith("@"):
            # A scope directory is not itself a package: npm always places the
            # package's own name directly beneath it.
            if len(segment) == 1 or index + 1 >= total:
                return False
            if not _is_package_name_segment(directory[index + 1]):
                return False
            index += 2
        else:
            if not _is_package_name_segment(segment):
                return False
            index += 1

        if index == total:
            return True

        # The only thing that may follow a package directory is a NESTED
        # node_modules. Anything else means we are inside the package's own
        # source tree, whose manifests npm never executes.
        if directory[index] != NESTED_MODULES_DIR:
            return False
        index += 1

    # A chain ending in a bare `node_modules` names no package.
    return False


# ---------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------


def collect_installed_manifests(
    node_modules_root: Path,
) -> Tuple[List[Tuple[str, Path]], int]:
    """Every installed package manifest under ``node_modules_root``.

    Returns ``([(package dir relative to the root, manifest path)], dir_errors)``,
    sorted so a report is deterministic rather than dependent on the order the
    filesystem hands back. A directory that cannot be listed is counted, not
    swallowed — the caller turns that into a blind phase.

    The descent follows npm's layout (a package directory, a scope directory, a
    nested ``node_modules``) and is gated by
    :func:`is_installed_package_manifest`, so it never walks a package's source
    tree. Already-visited real paths are tracked, so a symlinked or junctioned
    ``node_modules`` — which npm workspaces and ``npm link`` both create — cannot
    send the walk round a cycle.
    """
    manifests: List[Tuple[str, Path]] = []
    dir_errors = 0
    seen: set = set()
    pending: List[Tuple[Path, str]] = [(node_modules_root, "")]

    while pending:
        modules_dir, prefix = pending.pop()
        try:
            real = os.path.realpath(modules_dir)
        except OSError:  # pragma: no cover - defensive
            real = str(modules_dir)
        if real in seen:
            continue
        seen.add(real)

        try:
            entries = sorted(os.listdir(modules_dir))
        except OSError:
            dir_errors += 1
            continue

        for entry in entries:
            entry_path = modules_dir / entry
            if not entry_path.is_dir():
                continue

            if entry.startswith("@"):
                try:
                    scoped = sorted(os.listdir(entry_path))
                except OSError:
                    dir_errors += 1
                    continue
                candidates = [
                    (f"{entry}/{name}", entry_path / name)
                    for name in scoped
                    if (entry_path / name).is_dir()
                ]
            else:
                candidates = [(entry, entry_path)]

            for relative_dir, package_dir in candidates:
                package_key = f"{prefix}{relative_dir}"
                if not is_installed_package_manifest(f"{package_key}/{MANIFEST_NAME}"):
                    continue

                manifest = package_dir / MANIFEST_NAME
                if manifest.is_file():
                    manifests.append((package_key, manifest))

                nested = package_dir / NESTED_MODULES_DIR
                if nested.is_dir():
                    pending.append((nested, f"{package_key}/{NESTED_MODULES_DIR}/"))

    manifests.sort()
    return manifests, dir_errors


def read_manifest(path: Path) -> str:
    """Read one installed ``package.json``.

    A named module-level function (mirroring ``sandbox_codescan.read_code_file``)
    so a test can inject a read failure without needing a genuinely unreadable
    file — which is not portably creatable on Windows.
    """
    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


@dataclass
class InstalledPackageScripts:
    """One installed package that declares at least one lifecycle hook."""

    package_dir: str
    name: str = ""
    version: str = ""
    #: Every lifecycle hook the manifest declares, in npm's own order.
    hooks: List[str] = field(default_factory=list)
    #: The subset of ``hooks`` that npm actually ran during the install (see
    #: :data:`AUTO_RUN_DEPENDENCY_HOOKS`). Empty means the package declares only
    #: conditional hooks, which did not execute here.
    auto_run_hooks: List[str] = field(default_factory=list)
    #: Package-qualified danger lines (see :func:`qualify_dependency_danger`).
    #: Only ever derived from :attr:`auto_run_hooks`.
    dangers: List[str] = field(default_factory=list)

    @property
    def executed(self) -> bool:
        """Whether any of this package's hooks ran during the install."""
        return bool(self.auto_run_hooks)

    @property
    def label(self) -> str:
        """How this package is named in a finding.

        Falls back to the installed directory when the manifest has no usable
        ``name`` — a package that hides its identity still has to be reportable.
        """
        if self.name and self.version:
            return f"{self.name}@{self.version}"
        return self.name or self.package_dir


@dataclass
class DependencyScriptReport:
    """Result of the dependency-hook pass, including how much of it ran.

    ``packages_found`` counts every installed manifest the walk located,
    ``packages_scanned`` only those actually parsed and analysed. The two differ
    when a manifest is excluded (the target package, already covered by phase 1)
    or could not be read — and keeping them apart is what lets
    :meth:`blind_reason` tell "there were no dependencies" apart from "the
    dependencies were not looked at".
    """

    packages_found: int = 0
    packages_scanned: int = 0
    packages_excluded: int = 0
    manifests_unreadable: int = 0
    manifests_invalid: int = 0
    dir_errors: int = 0
    #: ``(package dir, error text)`` for the first few unreadable manifests.
    unreadable_examples: List[Tuple[str, str]] = field(default_factory=list)
    #: Every scanned package that declares a lifecycle hook, in walk order.
    with_hooks: List[InstalledPackageScripts] = field(default_factory=list)

    @property
    def scanned_anything(self) -> bool:
        return self.packages_scanned > 0

    @property
    def hooked_count(self) -> int:
        """Packages declaring any lifecycle hook, executed or conditional."""
        return len(self.with_hooks)

    @property
    def executed_count(self) -> int:
        """Packages that actually ran code during the install.

        This is the number the console leads with: it is the size of the
        install-time execution surface the user just accepted, as opposed to
        hooks that merely exist in a manifest.
        """
        return sum(1 for entry in self.with_hooks if entry.executed)

    @property
    def dangers(self) -> List[str]:
        """Every package-qualified danger line, flattened for ``SandboxFindings``."""
        return [danger for entry in self.with_hooks for danger in entry.dangers]

    def blind_reason(self) -> Optional[str]:
        """Why this pass could not see the installed dependencies, or ``None``.

        A non-``None`` value must reach ``SandboxFindings.mark_blind``: it means
        "no dangerous dependency hooks" is the absence of evidence rather than
        evidence of absence.

        Note that a run where every manifest was *excluded* is NOT blind: the
        walk saw the tree, the target simply had no transitive dependencies.
        """
        parts = []
        if self.manifests_unreadable:
            parts.append(f"{self.manifests_unreadable} dependency manifest(s) unreadable")
        if self.manifests_invalid:
            parts.append(
                f"{self.manifests_invalid} dependency manifest(s) could not be parsed"
            )
        if self.dir_errors:
            parts.append(f"{self.dir_errors} directory(s) could not be listed")

        if parts:
            detail = " and ".join(parts)
            if not self.scanned_anything:
                return f"{detail} - dependency lifecycle hooks were NOT analyzed"
            return f"{detail} - dependency lifecycle-hook analysis is partial"

        if self.packages_found == 0:
            return (
                "no installed package manifest found under node_modules "
                "- dependency lifecycle hooks were NOT analyzed"
            )
        return None


def qualify_dependency_danger(label: str, danger: str) -> str:
    """Name the dependency in a danger line lifted from ``analyze_install_scripts``.

    Phase 1's danger lines describe the package the user asked about, so an
    unqualified ``"postinstall script: …"`` in the same summary would read as if
    the *target* declared it. Every line from this pass names the transitive
    dependency instead.
    """
    body = danger[len(DANGER_PREFIX) :] if danger.startswith(DANGER_PREFIX) else danger
    return f"{DANGER_PREFIX}dependency {label}: {body}"


def scan_installed_dependency_scripts(
    node_modules_root: Path,
    exclude_dirs: FrozenSet[str] = frozenset(),
) -> DependencyScriptReport:
    """Analyse the lifecycle hooks of every package installed under ``node_modules``.

    ``exclude_dirs`` holds package directories (relative to the root, e.g.
    ``"lodash"`` or ``"@scope/pkg"``) that another phase already covered — in
    practice the target package itself, whose hooks phase 1 reads from the
    registry metadata. An excluded package still counts toward
    ``packages_found``, so excluding the only installed package does not make the
    pass look blind.
    """
    report = DependencyScriptReport()
    manifests, report.dir_errors = collect_installed_manifests(node_modules_root)
    report.packages_found = len(manifests)

    excluded = {
        (name or "").replace("\\", "/").strip("/") for name in exclude_dirs
    } - {""}

    for package_dir, manifest_path in manifests:
        if package_dir in excluded:
            report.packages_excluded += 1
            continue

        try:
            raw = read_manifest(manifest_path)
        except OSError as read_err:
            # An unreadable manifest is NOT a scanned package: counting it would
            # inflate the coverage number behind a "no dangerous hooks" claim.
            report.manifests_unreadable += 1
            if len(report.unreadable_examples) < MAX_UNREADABLE_EXAMPLES:
                report.unreadable_examples.append((package_dir, str(read_err)))
            continue

        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            report.manifests_invalid += 1
            continue
        if not isinstance(data, dict):
            report.manifests_invalid += 1
            continue

        report.packages_scanned += 1
        declared = analyze_install_scripts(data.get("scripts"))
        if not declared.has_hooks:
            continue

        # Classify twice rather than string-matching the hook name back out of a
        # rendered danger line: the second pass sees only the hooks that npm
        # actually ran here, so a conditional `prepare` can never contribute a
        # danger for something that did not execute.
        executed = analyze_install_scripts(
            {
                hook: body
                for hook, body in declared.bodies.items()
                if hook in AUTO_RUN_DEPENDENCY_HOOKS
            }
        )

        name = data.get("name")
        version = data.get("version")
        entry = InstalledPackageScripts(
            package_dir=package_dir,
            name=name if isinstance(name, str) else "",
            version=version if isinstance(version, str) else "",
            hooks=list(declared.hooks),
            auto_run_hooks=list(executed.hooks),
        )
        entry.dangers = [
            qualify_dependency_danger(entry.label, danger) for danger in executed.dangers
        ]
        report.with_hooks.append(entry)

    return report


def format_hooked_package_line(entry: InstalledPackageScripts) -> str:
    """One console line for a dependency that runs code at install time.

    Shows the installed directory whenever it differs from the package name, so
    a nested copy (``foo/node_modules/bar``) is distinguishable from the
    top-level one, and marks a package whose only hooks are conditional — it did
    not run here, and saying otherwise would overstate what happened.
    """
    hooks = ", ".join(entry.hooks) if entry.hooks else "no hooks"
    location = ""
    if entry.package_dir and entry.package_dir != entry.name:
        location = f" [{entry.package_dir}]"
    suffix = "" if entry.executed else " (not run for a registry install)"
    return f"{entry.label}{location}: {hooks}{suffix}"
