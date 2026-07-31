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

Three things make it precise rather than noisy:

* :func:`is_installed_package_manifest` is the rule for what npm actually
  *installed*, expressed structurally: a manifest counts only when its directory
  chain is ``<name>`` / ``@scope/<name>``, optionally repeated through a nested
  ``node_modules``. A ``package.json`` sitting in a package's own test fixtures
  or examples is **not** an installed package and its hooks never run, so it is
  never reported. The same predicate gates the traversal, so the walk descends
  only where npm places packages instead of reading a whole source tree.
* :func:`load_install_source_index` reads ``package-lock.json`` so the pass can
  tell a **registry tarball** from a dependency npm **built from source**. npm
  runs ``prepare`` for the latter and not the former, and the manifest alone
  records nothing about where the package came from (build-loop follow-up F36).
  Without the lockfile a malicious ``prepare`` in a git dependency executes and
  is then reported as "not run for a registry install".
* :meth:`DependencyScriptReport.blind_reason` applies the F29 rule — an
  unreadable manifest, an unparseable one, a directory that could not be listed,
  or a ``prepare`` hook whose install source could not be determined means the
  pass has no conclusion to offer, so the caller marks it blind rather than
  printing a pass.

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

#: The lockfile npm writes at the project root. It is the only record of *where*
#: each installed package came from; the installed manifest has none.
LOCKFILE_NAME = "package-lock.json"

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
#:
#: The one shape that calibration was blind to is closed by
#: :data:`GIT_SOURCE_HOOK` below.
AUTO_RUN_DEPENDENCY_HOOKS: Tuple[str, ...] = ("preinstall", "install", "postinstall")

#: The hook npm runs *in addition* for a dependency it had to build from source
#: — i.e. one given as a git URL rather than fetched as a registry tarball
#: (build-loop follow-up F36). For those packages ``prepare`` genuinely executed
#: on the user's machine during phase 3, so excluding it unconditionally reported
#: a hook that ran as one that did not.
GIT_SOURCE_HOOK = "prepare"

#: How npm records a git dependency's origin in ``package-lock.json``. Measured
#: over **559 real lockfiles** on a development machine: 19 of them carry a git
#: dependency, for 25 git-sourced entries in total, and every one is
#: ``git+ssh://git@host/owner/repo.git#<sha>``. ``git+https://``, ``git+file://``
#: (what a locally cloned dependency resolves to — the shape the F36 fixture
#: installs) and the bare ``git://`` scheme are the other forms npm normalizes
#: to, so the ``git+`` family and ``git://`` are all accepted. A registry
#: tarball's ``resolved`` is an ``https://registry.npmjs.org/…`` URL and never
#: matches, which is what keeps the F34 calibration intact.
GIT_SOURCE_PREFIXES: Tuple[str, ...] = ("git+", "git://")

#: Lockfile fields that can carry the origin. The same measurement found the git
#: URL in ``resolved`` 20 times and in ``version`` 5 times — the latter is the
#: ``lockfileVersion`` 1 layout, which is not a legacy curiosity: 114 of those
#: 559 lockfiles are still v1 (280 v3, 165 v2), so both readers below earn their
#: place. ``from`` is v1's third spelling of the same fact.
GIT_SOURCE_FIELDS: Tuple[str, ...] = ("resolved", "version", "from")

#: Bound on the v1 dependency tree walk. A lockfile is untrusted input; a
#: pathologically nested one must not be able to make the walk unbounded.
MAX_LOCKFILE_DEPTH = 64


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


def read_lockfile(path: Path) -> str:
    """Read the project's ``package-lock.json``.

    Separate from :func:`read_manifest` so a test can fail one without the other,
    and so a lockfile failure is never miscounted as an unreadable manifest.
    """
    return path.read_text(encoding="utf-8", errors="ignore")


# ---------------------------------------------------------------------------
# Where each package came from (F36)
# ---------------------------------------------------------------------------


def _is_git_source(value: object) -> bool:
    """Whether a lockfile origin field names a git checkout.

    ``git+ssh://``, ``git+https://`` and ``git://`` are git; a registry
    tarball's plain ``https://registry.npmjs.org/…`` URL is not.
    """
    return isinstance(value, str) and value.startswith(GIT_SOURCE_PREFIXES)


def _entry_is_git_sourced(entry: object) -> bool:
    """Whether one lockfile entry records a git origin in any known field."""
    if not isinstance(entry, dict):
        return False
    return any(_is_git_source(entry.get(field)) for field in GIT_SOURCE_FIELDS)


def lockfile_key_to_package_dir(key: str) -> Optional[str]:
    """The installed package directory a ``lockfileVersion`` 2/3 key refers to.

    Lockfile keys are paths from the project root, so they carry a leading
    ``node_modules/`` that the walk's keys do not::

        node_modules/lodash                        -> lodash
        node_modules/a/node_modules/b              -> a/node_modules/b
        node_modules/@scope/pkg                    -> @scope/pkg

    Returns ``None`` for anything that is not an installed package: the root
    project (``""``), a workspace directory (``packages/app``), or a malformed
    chain. Reusing :func:`is_installed_package_manifest` here means the lockfile
    side and the filesystem side agree on what a package is by construction,
    rather than by two hand-written path rules that can drift apart.
    """
    normalized = (key or "").replace("\\", "/").strip("/")
    prefix = f"{NESTED_MODULES_DIR}/"
    if not normalized.startswith(prefix):
        return None
    package_dir = normalized[len(prefix) :]
    if not is_installed_package_manifest(f"{package_dir}/{MANIFEST_NAME}"):
        return None
    return package_dir


def _git_packages_from_v3(packages: object) -> List[str]:
    """Git-sourced package directories from a ``lockfileVersion`` 2/3 map."""
    found: List[str] = []
    if not isinstance(packages, dict):
        return found
    for key, entry in packages.items():
        if not isinstance(key, str) or not _entry_is_git_sourced(entry):
            continue
        package_dir = lockfile_key_to_package_dir(key)
        if package_dir:
            found.append(package_dir)
    return found


def _git_packages_from_v1(dependencies: object) -> List[str]:
    """Git-sourced package directories from a ``lockfileVersion`` 1 tree.

    Iterative rather than recursive: the lockfile is untrusted input and a deeply
    nested ``dependencies`` chain must not be able to exhaust the stack.
    """
    found: List[str] = []
    pending: List[Tuple[object, str, int]] = [(dependencies, "", 0)]

    while pending:
        node, prefix, depth = pending.pop()
        if not isinstance(node, dict) or depth > MAX_LOCKFILE_DEPTH:
            continue
        for name, entry in node.items():
            if not isinstance(name, str) or not isinstance(entry, dict):
                continue
            package_dir = f"{prefix}{name}"
            if _entry_is_git_sourced(entry) and is_installed_package_manifest(
                f"{package_dir}/{MANIFEST_NAME}"
            ):
                found.append(package_dir)
            nested = entry.get("dependencies")
            if isinstance(nested, dict):
                pending.append(
                    (nested, f"{package_dir}/{NESTED_MODULES_DIR}/", depth + 1)
                )

    return found


@dataclass(frozen=True)
class InstallSourceIndex:
    """Which installed packages npm built from source, per the lockfile.

    ``unavailable_reason`` is the honest third state: not "no git dependencies"
    but "the lockfile could not answer". A pass holding one of those cannot claim
    a declared ``prepare`` did not run, so the caller turns it into a blind
    phase — see :meth:`DependencyScriptReport.blind_reason`.
    """

    git_sourced: FrozenSet[str] = frozenset()
    unavailable_reason: Optional[str] = None

    @property
    def is_authoritative(self) -> bool:
        """Whether this index can be used to rule a hook out as well as in."""
        return self.unavailable_reason is None

    def auto_run_hooks(self, package_dir: str) -> Tuple[str, ...]:
        """The hooks npm ran for ``package_dir`` during the install.

        A git-sourced package gets :data:`GIT_SOURCE_HOOK` on top of the registry
        set, because npm builds it from source and therefore runs ``prepare``.
        """
        if package_dir in self.git_sourced:
            return AUTO_RUN_DEPENDENCY_HOOKS + (GIT_SOURCE_HOOK,)
        return AUTO_RUN_DEPENDENCY_HOOKS


def load_install_source_index(project_root: Path) -> InstallSourceIndex:
    """Read ``project_root/package-lock.json`` and index the git-sourced packages.

    Handles both lockfile layouts npm has written: the flat ``packages`` map of
    ``lockfileVersion`` 2/3, keyed by path from the project root, and the nested
    ``dependencies`` tree of version 1. A lockfile that is missing, unreadable,
    unparseable, or not an object yields an index with an
    ``unavailable_reason`` rather than an empty one — the difference between "no
    git dependencies" and "unknown".
    """
    path = project_root / LOCKFILE_NAME

    try:
        raw = read_lockfile(path)
    except OSError as read_err:
        return InstallSourceIndex(
            unavailable_reason=f"{LOCKFILE_NAME} could not be read ({read_err})"
        )

    try:
        data = json.loads(raw)
    except (ValueError, RecursionError):
        return InstallSourceIndex(
            unavailable_reason=f"{LOCKFILE_NAME} could not be parsed"
        )
    if not isinstance(data, dict):
        return InstallSourceIndex(unavailable_reason=f"{LOCKFILE_NAME} is not an object")

    found = _git_packages_from_v3(data.get("packages"))
    # v1 had no `packages` map at all; v2 carries both and the flat map is
    # authoritative, so the tree is only consulted when the map is absent.
    if not isinstance(data.get("packages"), dict):
        found.extend(_git_packages_from_v1(data.get("dependencies")))

    return InstallSourceIndex(git_sourced=frozenset(found))


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
    #: Whether the lockfile records this package as built from a git checkout, in
    #: which case npm also ran :data:`GIT_SOURCE_HOOK`.
    git_sourced: bool = False
    #: Whether this package declares :data:`GIT_SOURCE_HOOK` while the lockfile
    #: could not say where it came from. The hook is neither reported as run nor
    #: ruled out — it makes the phase blind instead.
    source_unverified: bool = False

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
    #: Why the lockfile could not say where the packages came from, or ``None``
    #: when it did (see :class:`InstallSourceIndex`).
    source_unknown_reason: Optional[str] = None

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
    def git_sourced_count(self) -> int:
        """Hook-declaring packages npm built from a git checkout."""
        return sum(1 for entry in self.with_hooks if entry.git_sourced)

    @property
    def source_unverified_count(self) -> int:
        """Packages whose ``prepare`` may or may not have run, unknowably."""
        return sum(1 for entry in self.with_hooks if entry.source_unverified)

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

        # Narrow by design: a lockfile the pass could not read only costs it the
        # ability to rule a `prepare` hook in or out, so it is only blind when
        # some package actually declares one. Reporting every scan as blind
        # because a lockfile was absent would spend the verdict on nothing.
        unverified = self.source_unverified_count
        if unverified:
            detail = self.source_unknown_reason or "the install source is unknown"
            return (
                f"{unverified} dependency(s) declare a `{GIT_SOURCE_HOOK}` hook and "
                f"{detail} - whether npm ran it was NOT determined"
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
    install_sources: Optional[InstallSourceIndex] = None,
) -> DependencyScriptReport:
    """Analyse the lifecycle hooks of every package installed under ``node_modules``.

    ``exclude_dirs`` holds package directories (relative to the root, e.g.
    ``"lodash"`` or ``"@scope/pkg"``) that another phase already covered — in
    practice the target package itself, whose hooks phase 1 reads from the
    registry metadata. An excluded package still counts toward
    ``packages_found``, so excluding the only installed package does not make the
    pass look blind.

    ``install_sources`` says which packages npm built from source (F36). Omitting
    it means the provenance is *unknown*, not registry: a declared ``prepare`` is
    then neither reported as executed nor ruled out, and the pass marks itself
    blind. Callers get the authoritative answer from
    :func:`load_install_source_index`.
    """
    sources = install_sources or InstallSourceIndex(
        unavailable_reason=f"no {LOCKFILE_NAME} was supplied to the pass"
    )
    report = DependencyScriptReport(source_unknown_reason=sources.unavailable_reason)
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
        auto_run = sources.auto_run_hooks(package_dir)
        executed = analyze_install_scripts(
            {
                hook: body
                for hook, body in declared.bodies.items()
                if hook in auto_run
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
            git_sourced=package_dir in sources.git_sourced,
            # Only a declared `prepare` is at stake: every other hook runs for a
            # registry install too, so an unreadable lockfile costs nothing there.
            source_unverified=(
                not sources.is_authoritative and GIT_SOURCE_HOOK in declared.hooks
            ),
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

    Three suffixes, one per state the provenance check can be in: built from a
    git checkout (``prepare`` ran), a registry tarball (it did not), or a lockfile
    that could not say (unknown — never presented as either).
    """
    hooks = ", ".join(entry.hooks) if entry.hooks else "no hooks"
    location = ""
    if entry.package_dir and entry.package_dir != entry.name:
        location = f" [{entry.package_dir}]"

    if entry.git_sourced:
        suffix = " (built from a git checkout)"
    elif entry.source_unverified:
        suffix = f" (install source unverified - `{GIT_SOURCE_HOOK}` may have run)"
    elif entry.executed:
        suffix = ""
    else:
        suffix = " (not run for a registry install)"
    return f"{entry.label}{location}: {hooks}{suffix}"
