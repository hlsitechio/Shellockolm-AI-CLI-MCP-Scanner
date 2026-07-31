"""Decoy credentials and canary observation for the ``sandbox`` deep-install
check (build-loop follow-up F46).

F40 made *rewrites* and *deletions* of pre-existing sandbox files reportable,
and immediately ran into the limit F46 records: the baseline contained exactly
one file we wrote (``package.json``), so there was almost nothing for the new
check to be about. The check redirects ``HOME`` into the sandbox precisely so a
credential thief cannot reach the real one — which also means the sandbox
``HOME`` is empty, and an install script that reads ``~/.aws/credentials``,
``~/.npmrc`` or ``~/.ssh/id_rsa`` finds nothing, does nothing, and looks
identical to a package that never tried.

This module seeds that empty ``HOME`` with obviously-fake credential files, each
carrying a per-run **canary token**, and then observes the two places where a
package that read one would show its hand.

Scope, stated honestly, because F46 asked for it:

* This does **not** watch the network. A payload that reads a decoy and POSTs it
  to an attacker is invisible here, exactly as it was before.
* What *is* observable is the value arriving somewhere we already look: the
  install's own captured stdout/stderr (the "postinstall dumps the environment"
  shape), and any file the install wrote into the sandbox outside npm's own
  directories (the staging-file shape). Both are direct evidence a decoy was
  read, because the token exists nowhere else on the machine. Both routes were
  verified against real ``npm install`` runs of purpose-built stealers, and the
  stdout one only works because the caller passes ``--foreground-scripts``:
  npm 7+ buffers and discards lifecycle output unless the script fails, so
  without that flag the payload's own print never reaches the captured stream.
* One route is measured and deliberately **not** covered: a postinstall's
  working directory is its own installed package directory, so a stager that
  writes loot beside its own files lands under ``node_modules/``, which the
  phase-4 filter excludes as npm's territory. Reading that tree instead is not
  free — the target package's own directory holds 10 files for ``express`` and
  **8,094** for ``next`` — so it needs a budget decision rather than a wider
  default (backlog F48).
* Tampering is observable for free: nothing in ``npm install`` legitimately
  rewrites or removes ``~/.aws/credentials``, so a decoy showing up in F40's
  change set is unambiguous.

Two constraints the decoys are built to respect:

* **They must be obviously fake.** Every file carries
  :data:`DECOY_MARKER` and a "not a real credential" notice in-band, so no
  verdict, log line or leaked copy can be mistaken for a real secret — including
  by the attacker who steals one.
* **They must not change the install's behaviour.** ``$HOME/.npmrc`` is npm's
  own user config, so a decoy auth token there would be sent to the registry.
  :data:`NPM_USERCONFIG_ENV` / :func:`inert_userconfig_path` give the caller the
  one-line neutralizer: point ``npm_config_userconfig`` at an unused path inside
  the sandbox, and npm reads that (nonexistent, therefore empty) file instead of
  the decoy — the same empty config it had before this module existed. The
  ``.config/gh/hosts.yml`` decoy needs the mirror-image treatment: it creates a
  ``.config/`` directory in the sandbox HOME, which is where npm looks on Linux,
  so :data:`XDG_ENV_VARS` are redirected at ``.npm/`` (already an expected
  install directory) rather than left to land somewhere phase 4 would report.

Pure-ish and unit-testable, mirroring ``sandbox_snapshot`` / ``sandbox_check``:
:func:`seed_decoys` and :func:`scan_files_for_canary` touch the filesystem and
never raise, everything else is a pure function over plain data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Mapping, Sequence, Tuple, Union

#: Substring stamped into every decoy file. Present so that a stolen or logged
#: copy identifies itself as bait rather than as a credential.
DECOY_MARKER = "SHELLOCKOLM-DECOY"

#: Prefix of the per-run canary value. The full token is this plus a run id, so
#: the string is unique to one sandbox run and cannot collide with real content.
CANARY_PREFIX = "SHELLOCKOLM-CANARY"

#: In-band notice repeated in each decoy body.
DECOY_NOTICE = (
    "This is a fake credential planted by the Shellockolm sandbox check. "
    "It grants no access to anything."
)

#: Environment variable npm reads instead of ``$HOME/.npmrc`` when set.
NPM_USERCONFIG_ENV = "npm_config_userconfig"

#: Filename used for the (deliberately absent) inert user config.
INERT_USERCONFIG_NAME = ".npm-userconfig"

#: Directory the XDG variables are pointed at. Already in
#: ``sandbox_check.EXPECTED_INSTALL_DIRS``, so anything npm writes there is
#: recognized as npm's own state rather than reported as a dropped payload.
XDG_REDIRECT_DIR = ".npm"

#: XDG variables redirected alongside the user config. One decoy lives at
#: ``.config/gh/hosts.yml``, which puts a ``.config/`` directory in the sandbox
#: HOME — and npm consults ``$XDG_CONFIG_HOME``/``$XDG_CACHE_HOME`` on Linux, so
#: without this a benign install could write ``.config/npm/...`` and phase 4
#: would report it as a file created outside the expected locations.
XDG_ENV_VARS: Tuple[str, ...] = ("XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_STATE_HOME")

#: Hard cap on bytes read from any one candidate file when hunting the canary.
#: A staged exfil file is small; this stops a multi-gigabyte artifact from being
#: pulled into memory by a check that only needs to find a 40-character string.
CANARY_SCAN_BYTE_LIMIT = 2 * 1024 * 1024

#: Hard cap on how many candidate files the canary scan opens. The caller feeds
#: it the *unexpected* new files, which is normally an empty list; the cap keeps
#: a pathological install from turning the check into a full-tree read.
CANARY_SCAN_FILE_LIMIT = 200


def build_canary_token(run_id: str) -> str:
    """The value planted in every decoy for one sandbox run.

    ``run_id`` is caller-supplied (the CLI passes random hex) so the token is
    unique per run and tests can pin it. Uppercased and stripped of separators
    so a token that survives a round-trip through a shell, JSON or a log line is
    still one searchable literal.
    """
    cleaned = "".join(ch for ch in str(run_id) if ch.isalnum()).upper()
    if not cleaned:
        cleaned = "0"
    return f"{CANARY_PREFIX}-{cleaned}"


def decoy_files(token: str) -> Dict[str, str]:
    """Relative path → file body for every decoy planted in the sandbox HOME.

    The paths are the ones real npm credential stealers have gone after
    (``.npmrc``, ``.aws/credentials``, ``.ssh/id_rsa``, ``.config/gh/hosts.yml``
    in the writeups behind AGENT-PI and the 2021-2024 npm incidents). Forward
    slashes, relative to HOME, so the keys line up with
    :mod:`sandbox_snapshot`'s snapshot keys without translation.
    """
    return {
        ".npmrc": (
            f"; {DECOY_MARKER}: {DECOY_NOTICE}\n"
            f"//registry.npmjs.org/:_authToken={token}\n"
        ),
        ".aws/credentials": (
            f"# {DECOY_MARKER}: {DECOY_NOTICE}\n"
            "[default]\n"
            f"aws_access_key_id = {token}\n"
            f"aws_secret_access_key = {token}\n"
        ),
        ".ssh/id_rsa": (
            f"# {DECOY_MARKER}: {DECOY_NOTICE}\n"
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            f"{token}\n"
            "-----END OPENSSH PRIVATE KEY-----\n"
        ),
        ".config/gh/hosts.yml": (
            f"# {DECOY_MARKER}: {DECOY_NOTICE}\n"
            "github.com:\n"
            f"    oauth_token: {token}\n"
        ),
    }


def decoy_relative_paths(token: str = "x") -> Tuple[str, ...]:
    """Every decoy path, in a stable order. Content-independent."""
    return tuple(decoy_files(token).keys())


def is_decoy_path(path: str) -> bool:
    """True when a snapshot key names one of the planted decoys.

    Matches the exact relative path, so a package that drops its *own*
    ``.npmrc`` inside ``node_modules/evil/.npmrc`` is not mistaken for the
    decoy — that file is a new file and phase 4 already owns it.
    """
    normalized = (path or "").replace("\\", "/")
    # Same order as ``sandbox_check._relative_sandbox_path``: strip a leading
    # "./" as a UNIT, never with ``lstrip("./")``, which strips a character set
    # and would turn ".ssh/id_rsa" into "ssh/id_rsa".
    while normalized.startswith("./"):
        normalized = normalized[2:]
    normalized = normalized.lstrip("/")
    return normalized in set(decoy_relative_paths())


def split_decoy_changes(paths: Iterable[str]) -> Tuple[List[str], List[str]]:
    """Partition a change list into ``(decoy_paths, other_paths)``.

    Lets the caller report a tampered decoy at a different severity from the
    ordinary "a pre-existing file changed" line F40 added, while keeping one
    pass over the data.
    """
    decoys: List[str] = []
    others: List[str] = []
    for path in paths:
        (decoys if is_decoy_path(path) else others).append(path)
    return decoys, others


def inert_userconfig_path(home: Union[str, Path]) -> str:
    """Path to point ``npm_config_userconfig`` at so the decoy ``.npmrc`` is inert.

    Deliberately a file that is never created: npm treats a missing user config
    as empty, which is exactly the state the sandbox had before decoys existed.
    """
    return str(Path(home) / INERT_USERCONFIG_NAME)


def npm_env_overrides(home: Union[str, Path]) -> Dict[str, str]:
    """Environment additions that keep the decoys out of npm's own config.

    Both user-config spellings are set because npm accepts either case and a
    stray ``NPM_CONFIG_USERCONFIG`` already in the inherited environment would
    otherwise win over the lowercase one on a case-sensitive platform.

    The XDG variables are redirected for the mirror-image reason: the decoys put
    a ``.config/`` directory in the sandbox HOME, and npm reads
    ``$XDG_CONFIG_HOME`` there on Linux — so a benign install writing
    ``.config/npm/...`` would be reported as a payload dropped outside the
    expected locations. Pointing them at ``.npm/`` (already an expected install
    directory) makes that deterministic instead of platform-dependent.
    """
    path = inert_userconfig_path(home)
    overrides = {NPM_USERCONFIG_ENV: path, NPM_USERCONFIG_ENV.upper(): path}
    xdg_root = str(Path(home) / XDG_REDIRECT_DIR)
    for name in XDG_ENV_VARS:
        overrides[name] = xdg_root
    return overrides


@dataclass
class DecoySeeding:
    """What was planted, and what could not be.

    ``is_complete`` is False when any decoy failed to write. The caller must
    then mark the phase blind rather than report the read-side check as clean:
    a decoy that was never planted cannot be stolen, so its silence proves
    nothing.
    """

    token: str = ""
    paths: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def is_complete(self) -> bool:
        return not self.errors and bool(self.paths)

    def error_summary(self) -> str:
        if self.is_complete:
            return "complete"
        if not self.paths:
            return "no decoy could be planted"
        return f"{len(self.errors)} decoy file(s) could not be planted"


def seed_decoys(home: Union[str, Path], token: str) -> DecoySeeding:
    """Write the decoy credential files under ``home``.

    Never raises: a directory that cannot be created and a file that cannot be
    written are both recorded on the result, which then reports
    ``is_complete == False``.
    """
    home_path = Path(home)
    seeding = DecoySeeding(token=token)

    for relative, body in decoy_files(token).items():
        target = home_path / relative
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(body, encoding="utf-8")
        except OSError as exc:
            seeding.errors.append(f"{relative}: {exc}")
            continue
        seeding.paths.append(relative)

    return seeding


@dataclass
class CanaryExposure:
    """Places the canary token turned up after the install.

    ``sources`` names each one (a stream name, or a sandbox-relative file path).
    ``errors`` records candidates that could not be read — the same blind-is-not
    -a-pass rule the rest of the check follows.
    """

    token: str = ""
    sources: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def found(self) -> bool:
        return bool(self.sources)

    @property
    def is_complete(self) -> bool:
        return not self.errors

    def describe(self) -> List[str]:
        """One finding line per exposure, in the report's voice."""
        return [
            f"Sandbox decoy credential was read and its value reached {source} "
            f"- the install exfiltrated a planted secret"
            for source in self.sources
        ]


def _contains_token(text: str, token: str) -> bool:
    """Case-insensitive literal search, tolerant of the token being re-cased.

    No regex: the token is a fixed literal and a payload that base64s it is out
    of scope (and stated as such in the module docstring).
    """
    if not token or not text:
        return False
    return token.lower() in text.lower()


def find_canary_in_streams(
    token: str, streams: Mapping[str, str]
) -> CanaryExposure:
    """Look for the canary in captured process output.

    ``streams`` maps a human-readable name ("install stdout") to its text.
    """
    exposure = CanaryExposure(token=token)
    for name, text in streams.items():
        if _contains_token(text or "", token):
            exposure.sources.append(name)
    return exposure


def scan_files_for_canary(
    root: Union[str, Path],
    token: str,
    candidates: Sequence[str],
    file_limit: int = CANARY_SCAN_FILE_LIMIT,
    byte_limit: int = CANARY_SCAN_BYTE_LIMIT,
) -> CanaryExposure:
    """Look for the canary inside files the install created.

    ``candidates`` are sandbox-relative paths — the caller passes the
    *unexpected* new files, i.e. what the install wrote outside npm's own
    directories. Decoy paths themselves are skipped: they contain the token by
    construction, and finding it there means nothing.

    Never raises. A candidate that cannot be read is recorded in ``errors`` so
    an empty result can be reported as inconclusive rather than clean. Files
    beyond ``file_limit`` are recorded as unexamined for the same reason.
    """
    root_path = Path(root)
    exposure = CanaryExposure(token=token)

    scannable = [path for path in candidates if not is_decoy_path(path)]
    if len(scannable) > file_limit:
        exposure.errors.append(
            f"{len(scannable) - file_limit} created file(s) beyond the "
            f"{file_limit}-file scan cap were NOT searched for the canary"
        )
        scannable = scannable[:file_limit]

    for relative in scannable:
        target = root_path / relative
        try:
            with open(target, "rb") as handle:
                blob = handle.read(byte_limit)
            oversized = target.stat().st_size > byte_limit
        except OSError as exc:
            exposure.errors.append(f"{relative}: {exc}")
            continue
        text = blob.decode("utf-8", errors="ignore")
        if _contains_token(text, token):
            exposure.sources.append(relative)
        elif oversized:
            exposure.errors.append(
                f"{relative}: only the first {byte_limit} bytes were searched"
            )

    return exposure


def merge_exposures(*exposures: CanaryExposure) -> CanaryExposure:
    """Combine several :class:`CanaryExposure` results into one."""
    merged = CanaryExposure()
    for exposure in exposures:
        merged.token = merged.token or exposure.token
        merged.sources.extend(exposure.sources)
        merged.errors.extend(exposure.errors)
    return merged


def describe_decoy_tampering(paths: Iterable[str], action: str) -> List[str]:
    """Finding lines for decoys the install rewrote or removed.

    ``npm install`` never touches ``~/.aws/credentials`` or ``~/.ssh/id_rsa``,
    so unlike the general F40 change set this needs no calibration: a decoy in
    the change set is the install having gone after credentials.
    """
    return [
        f"Sandbox decoy credential {action} by the install: {path} "
        f"- nothing in a normal npm install touches this file"
        for path in paths
    ]


def environment_with_decoy_isolation(
    base_env: Mapping[str, str], home: Union[str, Path]
) -> Dict[str, str]:
    """``base_env`` plus the overrides that keep npm off the decoy ``.npmrc``.

    Kept here rather than inline in the CLI so the pairing of "plant a decoy
    npmrc" with "make sure npm does not read it" is one testable unit — the
    behaviour-change constraint F46 set is easy to satisfy once and lose later.
    """
    merged = dict(base_env)
    merged.update(npm_env_overrides(home))
    return merged


__all__ = [
    "CANARY_PREFIX",
    "CANARY_SCAN_BYTE_LIMIT",
    "CANARY_SCAN_FILE_LIMIT",
    "CanaryExposure",
    "DECOY_MARKER",
    "DECOY_NOTICE",
    "DecoySeeding",
    "INERT_USERCONFIG_NAME",
    "NPM_USERCONFIG_ENV",
    "XDG_ENV_VARS",
    "XDG_REDIRECT_DIR",
    "build_canary_token",
    "decoy_files",
    "decoy_relative_paths",
    "describe_decoy_tampering",
    "environment_with_decoy_isolation",
    "find_canary_in_streams",
    "inert_userconfig_path",
    "is_decoy_path",
    "merge_exposures",
    "npm_env_overrides",
    "scan_files_for_canary",
    "seed_decoys",
    "split_decoy_changes",
]
