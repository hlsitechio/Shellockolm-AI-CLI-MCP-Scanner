"""Resolve what an install hook actually *runs*, and scan that file
(build-loop follow-up F41).

Phase 1 reads a package's ``preinstall`` / ``install`` / ``postinstall`` /
``prepare`` **string** and matches it against the two-tier table F37 built. That
is a narrower surface than it looks, and the writeups are the evidence:

* ``eslint-scope`` (2018) shipped ``postinstall: "node ./lib/build.js"``
* ``ua-parser-js`` (2021) shipped ``preinstall: "start /B node preinstall.js & node preinstall.js"``
* ``coa`` and ``rc`` (2021) shipped ``node compile.js``

Not one of those hook bodies contains a pattern from either tier, and every one
of them stole credentials. The payload was in the **referenced file**.

Phase 5 does read that file — but only as one entry in a whole-package sweep,
so a hit there is one malware-pattern line among hundreds rather than *the code
the install executed*. And it does not always read it: phase 5 selects files by
extension, and ``node scripts/postinstall`` (extension-less, outside ``bin/``)
is a real shape in the corpus below that no phase read at all.

This module closes the link. :func:`resolve_hook_targets` is a pure parser over
a hook body; :func:`scan_hook_reachable_scripts` resolves each target against
the installed package and runs the malware table over it.

What it is calibrated against
-----------------------------

Measured over **1,976 installed manifests that declare a ``scripts`` block**
across eight real dependency trees: 42 unique install-hook bodies, 173
occurrences. Their shapes, and how this module treats each:

* **A script path via an interpreter** — ``node install.js``,
  ``node ./scripts/transpile-to-esm.js``, ``bash ./scripts/fixup.sh``,
  ``node scripts/postinstall`` (no extension). 20 of the 42. **Resolved and
  scanned.**
* **An npm-script indirection** — ``npm run build`` (the single most common
  body), ``npm run compile``, ``yarn build``, ``run-s compile``. **Followed**
  into the same manifest's ``scripts`` block, so the file at the end of the
  chain is still reached.
* **A command with no script operand** — ``tshy``, ``husky``, ``tsc``,
  ``patch-package``, ``node-gyp rebuild``, ``prebuild-install``, ``wireit``.
  Roughly half of all occurrences. These run a *dependency's* binary out of
  ``node_modules/.bin``; there is no file in this package to scan, and calling
  that "blind" would downgrade half of all hooked packages to INCONCLUSIVE for
  nothing. Recorded as :data:`UNRESOLVED_NOT_A_FILE`, which is **not** blind.
* **Inline code** — ``node -e "…"``. The body is already the thing phase 1
  matched, so there is nothing further to read. Also not blind.

Blindness is therefore narrow and deliberate: the hook **names a script** and we
could not read it — a computed path (``node $SCRIPT``), a path that escapes the
package, a file that is not there, or an ``npm run`` naming a script the
manifest does not define. Those are exactly the cases that must not print a
pass, and over the hooks npm actually runs they occur **zero** times in the
corpus above.

The qualifier in that sentence is the second measured calibration, and it is
not a detail. Following all four lifecycle hooks makes **27 of 169** hooked
packages blind — 16%, which would downgrade a sixth of every real dependency
tree to INCONCLUSIVE. Every one of the 27 is a ``prepare`` hook, and every one
fails the same way: ``rollup``'s ``scripts/check-release.js``, ``lru-cache``'s
``fixup.sh``, ``undici``'s ``./scripts/platform-shell.js`` all exist in the
repository and are excluded from the published tarball, because ``prepare`` is
a *repository* build step. F36 already established that npm does not run
``prepare`` for a registry tarball at all — so those files are not missing, they
are irrelevant, and the pass follows :data:`AUTO_RUN_HOOKS` by default. A caller
that knows a package was built from a git checkout (F36's install-source index)
passes ``prepare`` in explicitly, because there it genuinely ran.

Honest scoping, restated from the task: this makes the entry point *visible*
and closes one coverage hole; it does not make a payload detectable. A clean
hook body means very little, and so does a clean hook target — the same
calibrated table that reads the rest of the package reads this file too. What
changes is that a hit in it is attributed to the code that ran.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from sandbox_check import scan_text_for_malware_patterns

# ---------------------------------------------------------------------------
# Bounds (a hook body is attacker-controlled input)
# ---------------------------------------------------------------------------

#: How many commands one hook body is parsed into. The longest real body in the
#: corpus is 190 characters and holds four commands; this is far above it, and
#: exists so a generated body cannot turn parsing into the denial of service
#: ``HOOK_BODY_SCAN_LIMIT`` already guards the pattern table against.
MAX_COMMANDS_PER_HOOK = 32

#: How many distinct target files one hook may resolve to.
MAX_TARGETS_PER_HOOK = 8

#: How deep an ``npm run`` chain is followed. ``prepare -> npm run build ->
#: npm run build:esm -> node scripts/build.js`` is three links; a manifest whose
#: scripts reference each other in a cycle is bounded by the seen-set as well.
MAX_SCRIPT_INDIRECTION_DEPTH = 8

#: Bytes read from one resolved target. The malware table is a text scan and a
#: hook target is source, not a bundle; a file above this is truncated and the
#: target is marked partially read rather than silently half-scanned.
MAX_TARGET_READ_BYTES = 512_000

#: The lifecycle hooks this pass follows by default: the ones npm runs for a
#: package installed from the registry. Mirrors
#: :data:`sandbox_deps.AUTO_RUN_DEPENDENCY_HOOKS` — kept as its own name rather
#: than imported so this module stays free of that dependency, and duplicated
#: deliberately: they are the same list for the same reason (F36), and if one
#: ever changes the other must be revisited rather than silently follow.
#:
#: ``prepare`` is absent. See the module docstring: including it makes 16% of
#: real hooked packages blind on files that were never published because the
#: hook never runs.
AUTO_RUN_HOOKS: Tuple[str, ...] = ("preinstall", "install", "postinstall")


# ---------------------------------------------------------------------------
# Command vocabulary
# ---------------------------------------------------------------------------

#: Interpreters that take a **script path** as their first non-flag operand and
#: resolve an extension-less path the way node does.
NODE_INTERPRETERS: frozenset = frozenset({"node", "nodejs", "bun", "ts-node", "tsx"})

#: Shells and other interpreters that take a script path, but resolve it
#: literally — ``sh build`` does not try ``build.sh``.
SCRIPT_INTERPRETERS: frozenset = frozenset(
    {"sh", "bash", "zsh", "ksh", "dash", "python", "python3", "py", "ruby", "perl"}
)

#: PowerShell, whose script operand is behind a flag rather than positional.
POWERSHELL_COMMANDS: frozenset = frozenset({"powershell", "pwsh"})

#: Flags that mean "the code is right here", so there is no file to resolve.
INLINE_CODE_FLAGS: frozenset = frozenset(
    {
        "-e",
        "--eval",
        "-p",
        "--print",
        "-c",
        "--command",
        "-encodedcommand",
        "-enc",
    }
)

#: Flags taking a value that is **not** the script (so the value is skipped).
_VALUE_FLAGS: frozenset = frozenset(
    {"-r", "--require", "--import", "--loader", "--experimental-loader", "--conditions"}
)

#: Package managers whose ``run <name>`` re-enters the same manifest.
PACKAGE_MANAGERS: frozenset = frozenset({"npm", "pnpm", "yarn", "npx", "bun"})

#: ``npm-run-all`` and its two aliases: every operand is a script name.
SCRIPT_RUNNERS: frozenset = frozenset({"run-s", "run-p", "npm-run-all"})

#: Command words that prefix another command and are stepped over.
_PREFIX_COMMANDS: frozenset = frozenset({"sudo", "exec", "command", "nice", "time"})

#: Extensions ``node <path>`` will try when the reference has none, in node's
#: own order. ``package.json`` inside a directory is not followed: a hook that
#: runs a directory is vanishingly rare and following it would mean resolving a
#: nested manifest's ``main``, which is a resolver, not a parser.
NODE_EXTENSION_CANDIDATES: Tuple[str, ...] = (".js", ".cjs", ".mjs", ".json")

#: Extensions that make a bare first token (``./build.sh``, ``scripts/x.js``)
#: read as a file to execute rather than a command on ``PATH``.
DIRECT_SCRIPT_EXTENSIONS: frozenset = frozenset(
    {".js", ".cjs", ".mjs", ".sh", ".bash", ".zsh", ".ps1", ".py", ".rb", ".pl", ".bat", ".cmd"}
)

#: Why a named script could not be read. The first is **not** blind — it means
#: the hook never named a file in this package; the rest are.
UNRESOLVED_NOT_A_FILE = "not a file reference"
UNRESOLVED_INLINE = "code is inline in the hook body"
UNRESOLVED_COMPUTED = "path is computed at run time"
UNRESOLVED_ESCAPES = "path points outside the package"
UNRESOLVED_MISSING = "file is not present in the installed package"
UNRESOLVED_UNREADABLE = "file could not be read"
UNRESOLVED_NO_SUCH_SCRIPT = "no such script in the manifest"

#: The reasons that make the phase blind: the hook names something to run and we
#: could not read it. :data:`UNRESOLVED_NOT_A_FILE` and :data:`UNRESOLVED_INLINE`
#: are deliberately absent — see the module docstring's calibration note.
BLINDING_REASONS: frozenset = frozenset(
    {
        UNRESOLVED_COMPUTED,
        UNRESOLVED_ESCAPES,
        UNRESOLVED_MISSING,
        UNRESOLVED_UNREADABLE,
        UNRESOLVED_NO_SUCH_SCRIPT,
    }
)

#: Shell metacharacters that mean the reference is not a literal path.
_COMPUTED_REFERENCE_RE = re.compile(r"[$`*?]|%[A-Za-z_][A-Za-z0-9_]*%|^~")

#: A leading ``NAME=value`` environment assignment (``BABEL_ENV=publish babel …``
#: is in the corpus), which is stepped over to reach the real command word.
_ENV_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")


# ---------------------------------------------------------------------------
# Splitting a hook body into commands, and a command into tokens
# ---------------------------------------------------------------------------


def split_hook_commands(body: str) -> List[str]:
    """Split a hook body into individual commands on shell separators.

    Splits on ``&&``, ``||``, ``;``, ``|``, ``&`` and newlines, honouring single
    and double quotes so ``node -e "a && b"`` stays one command. Written as a
    scan rather than ``re.split`` for exactly that reason: the separator inside
    a quoted string is data, and splitting on it invents a command that never
    runs — which is how ``ua-parser-js``'s ``start /B node preinstall.js & node
    preinstall.js`` has to read as two, while an inline payload holding ``;``
    reads as one.
    """
    commands: List[str] = []
    current: List[str] = []
    quote: str = ""
    index = 0
    length = len(body or "")

    while index < length:
        char = body[index]
        if quote:
            current.append(char)
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in "\"'":
            quote = char
            current.append(char)
            index += 1
            continue
        if char in "\n\r;&|":
            # Consume a doubled operator (`&&`, `||`) as one separator.
            if char in "&|" and index + 1 < length and body[index + 1] == char:
                index += 1
            commands.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1

    commands.append("".join(current))
    return [command.strip() for command in commands if command.strip()][:MAX_COMMANDS_PER_HOOK]


def tokenize_command(command: str) -> List[str]:
    """Split one command into tokens, respecting quotes.

    Deliberately not :func:`shlex.split`: in POSIX mode it treats a backslash as
    an escape, so ``node scripts\\build.js`` — a real Windows-authored hook —
    loses its separator and becomes ``scriptsbuild.js``. Here a backslash is an
    ordinary character, which is what a path needs.
    """
    tokens: List[str] = []
    current: List[str] = []
    quote = ""
    has_content = False

    for char in command or "":
        if quote:
            if char == quote:
                quote = ""
            else:
                current.append(char)
            continue
        if char in "\"'":
            quote = char
            has_content = True
            continue
        if char.isspace():
            if current or has_content:
                tokens.append("".join(current))
                current = []
                has_content = False
            continue
        current.append(char)

    if current or has_content:
        tokens.append("".join(current))
    return tokens


def _command_word(token: str) -> str:
    """The bare command name from ``token``: no directory, no ``.exe``/``.cmd``."""
    name = (token or "").replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _extension_of(reference: str) -> str:
    name = (reference or "").replace("\\", "/").rsplit("/", 1)[-1]
    dot = name.rfind(".")
    return name[dot:].lower() if dot > 0 else ""


def _looks_like_path(token: str) -> bool:
    """Whether a bare first token is a file this package ships, not a binary.

    ``./install.sh`` and ``scripts/build.js`` are files; ``tshy`` and ``husky``
    are commands resolved out of ``node_modules/.bin``. The distinction is a
    leading relative marker or a recognized script extension — never "contains a
    slash", which would read ``node-gyp rebuild``'s sibling forms as paths.
    """
    normalized = (token or "").replace("\\", "/")
    if not normalized:
        return False
    if normalized.startswith(("./", "../", "/")):
        return True
    return _extension_of(normalized) in DIRECT_SCRIPT_EXTENSIONS


# ---------------------------------------------------------------------------
# What one command references
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HookReference:
    """One thing a hook command runs, before it is resolved on disk.

    ``kind`` is ``"file"`` (``reference`` is a package-relative path),
    ``"script"`` (``reference`` names another entry in the manifest's
    ``scripts``) or ``"none"`` (nothing in this package to read, with
    ``reason`` saying which of the benign shapes it was).
    """

    kind: str
    reference: str = ""
    reason: str = ""
    #: True when the interpreter resolves an extension-less path the way node
    #: does, so ``scripts/postinstall`` may be ``scripts/postinstall.js``.
    node_resolution: bool = False


_NO_FILE = HookReference(kind="none", reason=UNRESOLVED_NOT_A_FILE)
_INLINE = HookReference(kind="none", reason=UNRESOLVED_INLINE)


def _first_operand(tokens: Sequence[str], node_style: bool) -> HookReference:
    """The script operand of an interpreter invocation, or why there is none."""
    index = 0
    while index < len(tokens):
        token = tokens[index]
        lowered = token.lower()
        if lowered in INLINE_CODE_FLAGS:
            return _INLINE
        if lowered in _VALUE_FLAGS:
            index += 2
            continue
        if token == "-":
            # Reading the script from stdin: there is no path to follow.
            return _INLINE
        if token.startswith("-"):
            index += 1
            continue
        return HookReference(kind="file", reference=token, node_resolution=node_style)
    return _NO_FILE


def _powershell_operand(tokens: Sequence[str]) -> HookReference:
    """PowerShell's ``-File <path>``; ``-Command``/``-EncodedCommand`` is inline."""
    index = 0
    while index < len(tokens):
        lowered = tokens[index].lower()
        if lowered in INLINE_CODE_FLAGS or lowered.startswith("-command"):
            return _INLINE
        if lowered in ("-file", "-f"):
            if index + 1 < len(tokens):
                return HookReference(kind="file", reference=tokens[index + 1])
            return _NO_FILE
        index += 1
    return _NO_FILE


def _package_manager_scripts(command: str, tokens: Sequence[str]) -> List[HookReference]:
    """Script names an ``npm run`` / ``yarn build`` style invocation re-enters.

    ``yarn <name>`` with no ``run`` is yarn 1's shorthand and is accepted, but
    only when ``<name>`` is not one of yarn's own subcommands — otherwise
    ``yarn install`` would be read as "run the ``install`` script", which is a
    different thing entirely.
    """
    operands = [token for token in tokens if not token.startswith("-")]
    if not operands:
        return []
    if operands[0] in ("run", "run-script"):
        names = operands[1:2]
    elif command in ("yarn", "bun") and operands[0] not in _MANAGER_SUBCOMMANDS:
        names = operands[:1]
    else:
        return []
    return [HookReference(kind="script", reference=name) for name in names if name]


#: Subcommands of ``yarn``/``bun`` that are the tool's own, not a script name.
_MANAGER_SUBCOMMANDS: frozenset = frozenset(
    {
        "install",
        "add",
        "remove",
        "up",
        "upgrade",
        "link",
        "unlink",
        "pack",
        "publish",
        "info",
        "why",
        "workspace",
        "workspaces",
        "dlx",
        "exec",
        "node",
        "init",
        "cache",
        "config",
        "audit",
        "outdated",
        "create",
        "x",
    }
)


def references_in_command(command: str) -> List[HookReference]:
    """Every file or script one command runs.

    Returns an empty list when the command is not an execution at all (``cd ..``
    is in the corpus), and a single :data:`UNRESOLVED_NOT_A_FILE` reference when
    it runs a binary that takes no script operand.
    """
    tokens = tokenize_command(command)
    index = 0
    while index < len(tokens) and (
        _ENV_ASSIGNMENT_RE.match(tokens[index]) or _command_word(tokens[index]) in _PREFIX_COMMANDS
    ):
        index += 1
    tokens = tokens[index:]
    if not tokens:
        return []

    word = _command_word(tokens[0])
    operands = tokens[1:]

    if word in ("cd", "pushd", "popd", "echo", "true", "false", "set", "export"):
        return []
    if word in NODE_INTERPRETERS:
        return [_first_operand(operands, node_style=True)]
    if word in SCRIPT_INTERPRETERS:
        return [_first_operand(operands, node_style=False)]
    if word in POWERSHELL_COMMANDS:
        return [_powershell_operand(operands)]
    if word in SCRIPT_RUNNERS:
        return [
            HookReference(kind="script", reference=token)
            for token in operands
            if not token.startswith("-")
        ]
    if word in PACKAGE_MANAGERS:
        found = _package_manager_scripts(word, operands)
        return found if found else [_NO_FILE]
    if _looks_like_path(tokens[0]):
        return [HookReference(kind="file", reference=tokens[0])]
    return [_NO_FILE]


def resolve_hook_targets(
    body: str,
    scripts: Optional[Mapping[str, str]] = None,
    _depth: int = 0,
    _seen: Optional[set] = None,
) -> List[HookReference]:
    """Every file a hook body reaches, following ``npm run`` indirection.

    ``scripts`` is the manifest's whole ``scripts`` block, which is what makes
    ``postinstall: "npm run build"`` — the most common body in the corpus —
    resolvable rather than opaque. A script name the block does not define is
    returned as an unresolved reference rather than dropped: a hook that runs a
    script which is not there is precisely the case that must not read as clean.
    """
    seen = _seen if _seen is not None else set()
    results: List[HookReference] = []

    for command in split_hook_commands(body):
        for reference in references_in_command(command):
            if reference.kind != "script":
                results.append(reference)
                continue
            name = reference.reference
            if not isinstance(scripts, Mapping) or name not in scripts:
                results.append(
                    HookReference(kind="none", reference=name, reason=UNRESOLVED_NO_SUCH_SCRIPT)
                )
                continue
            if name in seen or _depth >= MAX_SCRIPT_INDIRECTION_DEPTH:
                # A cycle or a chain past the bound: stop without claiming the
                # end of it was read.
                results.append(
                    HookReference(kind="none", reference=name, reason=UNRESOLVED_COMPUTED)
                )
                continue
            nested = scripts.get(name)
            if not isinstance(nested, str):
                results.append(
                    HookReference(kind="none", reference=name, reason=UNRESOLVED_NO_SUCH_SCRIPT)
                )
                continue
            results.extend(
                resolve_hook_targets(nested, scripts, _depth + 1, seen | {name})
            )

    return results[:MAX_TARGETS_PER_HOOK]


# ---------------------------------------------------------------------------
# Resolving a reference against the installed package
# ---------------------------------------------------------------------------


def resolve_reference_path(root: Path, reference: str, node_resolution: bool) -> Tuple[Optional[Path], str]:
    """Locate ``reference`` inside ``root``; return ``(path, unresolved reason)``.

    Refuses anything that leaves the package — an absolute path, a drive letter
    or a ``..`` that climbs out — because reading it would take the scan outside
    the sandboxed install, and because a hook whose target is outside the
    package is itself the finding.
    """
    raw = (reference or "").strip().strip("\"'")
    if not raw:
        return None, UNRESOLVED_NOT_A_FILE
    if _COMPUTED_REFERENCE_RE.search(raw):
        return None, UNRESOLVED_COMPUTED

    normalized = raw.replace("\\", "/")
    if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized):
        return None, UNRESOLVED_ESCAPES

    segments = [segment for segment in normalized.split("/") if segment not in ("", ".")]
    depth = 0
    for segment in segments:
        if segment == "..":
            depth -= 1
            if depth < 0:
                return None, UNRESOLVED_ESCAPES
        else:
            depth += 1
    if not segments:
        return None, UNRESOLVED_NOT_A_FILE

    candidates = ["/".join(segments)]
    if node_resolution and not _extension_of(candidates[0]):
        candidates.extend(candidates[0] + extension for extension in NODE_EXTENSION_CANDIDATES)

    for candidate in candidates:
        path = root / candidate
        try:
            if path.is_file():
                return path, ""
        except OSError:
            return None, UNRESOLVED_UNREADABLE
    return None, UNRESOLVED_MISSING


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------


@dataclass
class HookScriptTarget:
    """One file (or unresolvable reference) an install hook runs."""

    hook: str
    reference: str
    #: Package-relative path of the file that was read, ``""`` when unresolved.
    relative_path: str = ""
    #: Empty when the target was read; otherwise one of the ``UNRESOLVED_*``
    #: constants.
    unresolved_reason: str = ""
    #: Malware-table descriptions found in the target, in table order.
    descriptions: List[str] = field(default_factory=list)
    #: True when the file was longer than :data:`MAX_TARGET_READ_BYTES`.
    truncated: bool = False

    @property
    def resolved(self) -> bool:
        return not self.unresolved_reason

    @property
    def blinding(self) -> bool:
        """Whether this target leaves the phase unable to claim a pass."""
        return self.unresolved_reason in BLINDING_REASONS or self.truncated

    @property
    def label(self) -> str:
        """How this target reads on one console line."""
        if self.resolved:
            return f"{self.hook} -> {self.relative_path}"
        return f"{self.hook} -> {self.reference or '?'} ({self.unresolved_reason})"


@dataclass
class HookReachableReport:
    """What the install hooks execute, and what the table found in it."""

    targets: List[HookScriptTarget] = field(default_factory=list)
    #: Manifest read failure, when the pass had to load ``package.json`` itself.
    manifest_error: str = ""

    @property
    def resolved_targets(self) -> List[HookScriptTarget]:
        return [target for target in self.targets if target.resolved]

    @property
    def unresolved_targets(self) -> List[HookScriptTarget]:
        return [target for target in self.targets if not target.resolved]

    @property
    def files_scanned(self) -> int:
        return len(self.resolved_targets)

    @property
    def hits(self) -> List[Tuple[str, str]]:
        """``(relative path, description)`` pairs, in :func:`classify_malware_hits` shape."""
        return [
            (target.relative_path, description)
            for target in self.resolved_targets
            for description in target.descriptions
        ]

    def blind_reason(self) -> Optional[str]:
        """Why the hook-reachable pass could not see what the hooks run.

        ``None`` when every hook either resolved to a file that was read in
        full, or named nothing in this package to read (a dependency binary,
        inline code) — see the module docstring on why the latter is not blind.
        """
        if self.manifest_error:
            return self.manifest_error
        blinding = [target for target in self.targets if target.blinding]
        if not blinding:
            return None
        shown = ", ".join(target.label for target in blinding[:3])
        if len(blinding) > 3:
            shown += f", +{len(blinding) - 3} more"
        return f"install hook code was NOT analyzed: {shown}"


def read_target_file(path: Path) -> Tuple[str, bool]:
    """Read one hook target; returns ``(content, truncated)``.

    A named module-level function so a test can inject a read failure without
    needing a genuinely unreadable file, mirroring
    :func:`sandbox_codescan.read_code_file`.
    """
    with path.open("r", encoding="utf-8", errors="ignore") as handle:
        content = handle.read(MAX_TARGET_READ_BYTES + 1)
    if len(content) > MAX_TARGET_READ_BYTES:
        return content[:MAX_TARGET_READ_BYTES], True
    return content, False


def scan_hook_reachable_scripts(
    package_root: Path,
    scripts: Optional[Mapping[str, str]] = None,
    hooks: Sequence[str] = (),
    patterns_for: Callable[[str], List[str]] = scan_text_for_malware_patterns,
) -> HookReachableReport:
    """Resolve and scan the code every declared install hook executes.

    ``scripts`` is the installed manifest's ``scripts`` block; ``hooks`` names
    the lifecycle entries to follow, defaulting to :data:`AUTO_RUN_HOOKS` — the
    ones npm actually runs for a registry install. Pass
    ``hooks=AUTO_RUN_HOOKS + ("prepare",)`` for a package the lockfile records
    as built from a git checkout, where ``prepare`` ran too.

    ``patterns_for`` is injectable only so a test can drive the walk without
    depending on the calibrated table.
    """
    report = HookReachableReport()
    lifecycle = tuple(hooks) or AUTO_RUN_HOOKS
    if not isinstance(scripts, Mapping):
        return report

    seen_paths: Dict[str, HookScriptTarget] = {}

    for hook in lifecycle:
        body = scripts.get(hook)
        if not isinstance(body, str) or not body.strip():
            continue
        for reference in resolve_hook_targets(body, scripts):
            if reference.kind != "file":
                if reference.reason in BLINDING_REASONS:
                    report.targets.append(
                        HookScriptTarget(
                            hook=hook,
                            reference=reference.reference,
                            unresolved_reason=reference.reason,
                        )
                    )
                continue

            path, reason = resolve_reference_path(
                package_root, reference.reference, reference.node_resolution
            )
            if path is None:
                report.targets.append(
                    HookScriptTarget(
                        hook=hook,
                        reference=reference.reference,
                        unresolved_reason=reason,
                    )
                )
                continue

            relative = path.relative_to(package_root).as_posix()
            existing = seen_paths.get(relative)
            if existing is not None:
                # The same file reached from a second hook: report the link
                # without reading and re-matching it.
                report.targets.append(
                    HookScriptTarget(
                        hook=hook,
                        reference=reference.reference,
                        relative_path=relative,
                        descriptions=list(existing.descriptions),
                        truncated=existing.truncated,
                    )
                )
                continue

            try:
                content, truncated = read_target_file(path)
            except OSError:
                report.targets.append(
                    HookScriptTarget(
                        hook=hook,
                        reference=reference.reference,
                        unresolved_reason=UNRESOLVED_UNREADABLE,
                    )
                )
                continue

            target = HookScriptTarget(
                hook=hook,
                reference=reference.reference,
                relative_path=relative,
                descriptions=list(patterns_for(content)),
                truncated=truncated,
            )
            seen_paths[relative] = target
            report.targets.append(target)

    return report


def classify_hook_reachable_hits(report: HookReachableReport) -> Tuple[List[str], List[str]]:
    """``(dangers, info)`` lines attributing table hits to the code that ran.

    The severity rule is phase 5's, reused rather than reinvented: a description
    that is malicious on its own (:func:`sandbox_check.is_dangerous_hit`) is a
    danger, and a *capability* becomes one only when the same file also carries
    an attacker context signal (:func:`sandbox_check.corroborated_capabilities`)
    — the composite discipline F31 established.

    Reusing it here rather than falling back to the standalone set is a measured
    choice: over the **263 hook-target files** this pass reads across the corpus,
    the corroboration rule adds **zero** dangers, so it costs nothing and it is
    what separates ``esbuild``'s installer (downloads a tarball in one function,
    unpacks it in another) from a stager that pipes an HTTP response straight
    into ``execSync`` — the shape a hook-reachable file is most likely to hold.

    An uncorroborated capability is reported as info, not as a warning: 20 of
    the 42 real install-hook bodies run a build script that spawns processes and
    speaks HTTP, and calling that a finding is how a keyword classifier ends up
    condemning the whole ecosystem. "Here is what your install actually runs"
    is information, and information is where it belongs.
    """
    from sandbox_check import corroborated_capabilities, is_dangerous_hit

    escalated = set(corroborated_capabilities(report.hits))
    dangers: List[str] = []
    info: List[str] = []
    for target in report.resolved_targets:
        capabilities = []
        for description in target.descriptions:
            if is_dangerous_hit(description) or description in escalated:
                dangers.append(
                    f"🚨 {target.hook} hook executes {target.relative_path}: {description}"
                )
            else:
                capabilities.append(description)
        if capabilities:
            info.append(
                f"{target.hook} hook executes {target.relative_path} "
                f"({', '.join(capabilities)})"
            )
        else:
            info.append(f"{target.hook} hook executes {target.relative_path}")
    return dangers, info
