"""Tests for ``sandbox_canary`` — decoy credentials and canary observation
(build-loop follow-up F46).

F40 made rewrites and deletions of pre-existing sandbox files reportable and
then had almost nothing to be about: the baseline held the one ``package.json``
the check writes, because ``HOME`` is redirected into an empty throwaway
directory. F46 fills that HOME with obviously-fake credential files and watches
the two places a stolen value can land where this check can still see it.

What these tests pin, in the order the module's claims appear:

* **The decoys are unmistakably fake.** Every body carries ``SHELLOCKOLM-DECOY``
  and an in-band "grants no access" notice, so neither a report line nor a
  thief's copy can be read as a real credential.
* **They do not change the install.** ``$HOME/.npmrc`` is npm's own user config,
  so a decoy auth token there would be sent to the registry;
  :func:`environment_with_decoy_isolation` redirects ``npm_config_userconfig``
  at an unused sandbox path, and the test asserts both the redirect and that
  nothing else in the environment is disturbed.
* **A hit is real and a miss is honest.** The canary is found in captured output
  and in a file the install created, and is NOT found across a benign-install
  baseline (real npm output, a realistic new-file list, ordinary file bodies) —
  zero false positives. A candidate that could not be read, or one past the scan
  cap, is recorded as an error so the caller marks the phase blind instead of
  reporting clean.
* **It composes with what phase 4 already does.** The end-to-end test runs the
  real ``sandbox_snapshot`` walk and the real ``sandbox_check`` filters over a
  simulated install, and asserts the credential-stealing shape produces findings
  while the benign one produces none.
"""

from pathlib import Path

import pytest

from sandbox_canary import (
    CANARY_PREFIX,
    DECOY_MARKER,
    DECOY_NOTICE,
    INERT_USERCONFIG_NAME,
    NPM_USERCONFIG_ENV,
    XDG_ENV_VARS,
    XDG_REDIRECT_DIR,
    CanaryExposure,
    build_canary_token,
    decoy_files,
    decoy_relative_paths,
    describe_decoy_tampering,
    environment_with_decoy_isolation,
    find_canary_in_streams,
    inert_userconfig_path,
    is_decoy_path,
    merge_exposures,
    npm_env_overrides,
    scan_files_for_canary,
    seed_decoys,
    split_decoy_changes,
)
from sandbox_check import (
    filter_suspicious_new_files,
    filter_unexpected_deletions,
    filter_unexpected_modifications,
    is_expected_install_path,
)
from sandbox_snapshot import compare_snapshots, snapshot_directory

TOKEN = build_canary_token("deadbeef")


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------


def test_token_carries_the_canary_prefix():
    assert TOKEN.startswith(CANARY_PREFIX)
    assert "DEADBEEF" in TOKEN


def test_token_is_deterministic_for_a_run_id():
    assert build_canary_token("abc123") == build_canary_token("abc123")


def test_token_differs_between_runs():
    assert build_canary_token("aaaa") != build_canary_token("bbbb")


def test_token_strips_separators_so_it_survives_a_round_trip():
    """A token containing quotes or slashes would break when echoed through a
    shell or embedded in JSON, and the search is a literal one."""
    token = build_canary_token("a-b/c d\"e'")
    assert token == f"{CANARY_PREFIX}-ABCDE"


def test_empty_run_id_still_produces_a_searchable_token():
    assert build_canary_token("") == f"{CANARY_PREFIX}-0"


# ---------------------------------------------------------------------------
# Decoy content — obviously fake, by construction
# ---------------------------------------------------------------------------


def test_every_decoy_is_marked_as_a_decoy():
    for path, body in decoy_files(TOKEN).items():
        assert DECOY_MARKER in body, path
        assert DECOY_NOTICE in body, path


def test_every_decoy_carries_the_canary():
    for path, body in decoy_files(TOKEN).items():
        assert TOKEN in body, path


def test_decoys_cover_the_paths_real_stealers_read():
    paths = set(decoy_relative_paths())
    assert {".npmrc", ".aws/credentials", ".ssh/id_rsa"} <= paths


def test_decoy_paths_are_forward_slashed_and_relative():
    for path in decoy_relative_paths():
        assert not path.startswith("/")
        assert "\\" not in path


# ---------------------------------------------------------------------------
# Decoy path classification
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("path", decoy_relative_paths())
def test_is_decoy_path_matches_each_planted_file(path):
    assert is_decoy_path(path) is True


@pytest.mark.parametrize(
    "path",
    [".aws\\credentials", "./.npmrc", "/.ssh/id_rsa", ".config\\gh\\hosts.yml"],
)
def test_is_decoy_path_normalizes_separators_and_prefixes(path):
    """Windows snapshot keys arrive backslashed, and a "./" prefix must be
    stripped as a unit — `lstrip("./")` strips a character SET and would turn
    ".ssh/id_rsa" into "ssh/id_rsa" (the bug F27 fixed for ".npm-cache")."""
    assert is_decoy_path(path) is True


@pytest.mark.parametrize(
    "path",
    [
        "node_modules/evil/.npmrc",
        "node_modules/pkg/.ssh/id_rsa",
        "package.json",
        "evil.npmrc",
        "",
    ],
)
def test_is_decoy_path_rejects_lookalikes(path):
    """A package that ships its OWN .npmrc is a new file phase 4 already owns —
    treating it as the decoy would attribute someone else's file to us."""
    assert is_decoy_path(path) is False


def test_decoys_are_not_expected_install_paths():
    """The F40 change filters must keep decoys, or tampering is invisible."""
    for path in decoy_relative_paths():
        assert is_expected_install_path(path) is False


def test_split_decoy_changes_partitions_without_loss():
    changed = [".npmrc", "notes.txt", ".aws/credentials", "package.json"]
    decoys, others = split_decoy_changes(changed)
    assert decoys == [".npmrc", ".aws/credentials"]
    assert others == ["notes.txt", "package.json"]


def test_split_decoy_changes_on_an_empty_set():
    assert split_decoy_changes([]) == ([], [])


# ---------------------------------------------------------------------------
# Seeding
# ---------------------------------------------------------------------------


def test_seed_decoys_writes_every_file(tmp_path):
    seeding = seed_decoys(tmp_path, TOKEN)

    assert seeding.is_complete
    assert sorted(seeding.paths) == sorted(decoy_relative_paths())
    for path in decoy_relative_paths():
        assert (tmp_path / path).is_file()


def test_seeded_content_matches_the_declared_bodies(tmp_path):
    seed_decoys(tmp_path, TOKEN)
    for path, body in decoy_files(TOKEN).items():
        assert (tmp_path / path).read_text(encoding="utf-8") == body


def test_seed_decoys_records_failure_instead_of_raising(tmp_path):
    """A HOME that is a file, not a directory: every write fails and the result
    reports itself incomplete rather than blowing up the sandbox run."""
    blocked = tmp_path / "home-is-a-file"
    blocked.write_text("not a directory", encoding="utf-8")

    seeding = seed_decoys(blocked, TOKEN)

    assert seeding.is_complete is False
    assert seeding.paths == []
    assert seeding.errors
    assert seeding.error_summary() == "no decoy could be planted"


def test_partial_seeding_is_incomplete(tmp_path):
    """One decoy blocked by an existing file at its directory path."""
    (tmp_path / ".aws").write_text("blocking file", encoding="utf-8")

    seeding = seed_decoys(tmp_path, TOKEN)

    assert seeding.paths  # the others still landed
    assert seeding.is_complete is False
    assert "decoy file(s) could not be planted" in seeding.error_summary()


def test_complete_seeding_summary_says_complete(tmp_path):
    assert seed_decoys(tmp_path, TOKEN).error_summary() == "complete"


# ---------------------------------------------------------------------------
# npm isolation — the decoys must not change the install
# ---------------------------------------------------------------------------


def test_userconfig_is_redirected_into_the_sandbox(tmp_path):
    overrides = npm_env_overrides(tmp_path)
    assert overrides[NPM_USERCONFIG_ENV] == str(tmp_path / INERT_USERCONFIG_NAME)


def test_both_case_spellings_are_set(tmp_path):
    """An inherited NPM_CONFIG_USERCONFIG would otherwise beat the lowercase one
    on a case-sensitive platform, and npm would read the decoy .npmrc."""
    overrides = npm_env_overrides(tmp_path)
    assert overrides[NPM_USERCONFIG_ENV.upper()] == overrides[NPM_USERCONFIG_ENV]


def test_the_inert_userconfig_is_never_created(tmp_path):
    """npm treats a missing user config as empty — the same state the sandbox
    had before decoys existed."""
    seed_decoys(tmp_path, TOKEN)
    assert not Path(inert_userconfig_path(tmp_path)).exists()


def test_xdg_is_redirected_into_an_expected_install_directory(tmp_path):
    """The `.config/gh/hosts.yml` decoy puts a `.config/` directory in the
    sandbox HOME, and npm reads `$XDG_CONFIG_HOME` there on Linux — so a benign
    install writing `.config/npm/...` would be reported as a dropped payload.
    Redirecting XDG at `.npm/` makes it npm's own recognized state instead."""
    overrides = npm_env_overrides(tmp_path)

    for name in XDG_ENV_VARS:
        assert overrides[name] == str(tmp_path / XDG_REDIRECT_DIR)
    # The redirect target must be a directory phase 4 already expects, or the
    # fix would just move the false positive.
    assert is_expected_install_path(f"{XDG_REDIRECT_DIR}/npm/npmrc") is True


def test_xdg_redirect_does_not_collide_with_a_decoy(tmp_path):
    """`.npm/` must not be where a decoy lives, or npm's own writes would look
    like credential tampering."""
    assert not any(
        path.startswith(f"{XDG_REDIRECT_DIR}/") for path in decoy_relative_paths()
    )


def test_isolation_preserves_the_rest_of_the_environment(tmp_path):
    base = {"HOME": str(tmp_path), "NPM_CONFIG_CACHE": "cache", "PATH": "/usr/bin"}

    merged = environment_with_decoy_isolation(base, tmp_path)

    assert merged["HOME"] == str(tmp_path)
    assert merged["NPM_CONFIG_CACHE"] == "cache"
    assert merged["PATH"] == "/usr/bin"
    assert merged[NPM_USERCONFIG_ENV] == inert_userconfig_path(tmp_path)


def test_isolation_does_not_mutate_the_caller_environment(tmp_path):
    base = {"PATH": "/usr/bin"}
    environment_with_decoy_isolation(base, tmp_path)
    assert base == {"PATH": "/usr/bin"}


def test_isolation_overrides_an_inherited_userconfig(tmp_path):
    base = {NPM_USERCONFIG_ENV: "/home/real-user/.npmrc"}
    merged = environment_with_decoy_isolation(base, tmp_path)
    assert merged[NPM_USERCONFIG_ENV] == inert_userconfig_path(tmp_path)


# ---------------------------------------------------------------------------
# Read side — streams
# ---------------------------------------------------------------------------


def test_canary_found_in_install_stdout():
    exposure = find_canary_in_streams(
        TOKEN, {"the install's stdout": f"token={TOKEN}\n"}
    )
    assert exposure.found
    assert exposure.sources == ["the install's stdout"]


def test_canary_found_when_the_payload_recases_it():
    exposure = find_canary_in_streams(
        TOKEN, {"the install's stderr": TOKEN.lower()}
    )
    assert exposure.found


def test_canary_reported_per_stream():
    exposure = find_canary_in_streams(
        TOKEN, {"stdout": TOKEN, "stderr": TOKEN, "quiet": "nothing"}
    )
    assert exposure.sources == ["stdout", "stderr"]


BENIGN_NPM_OUTPUT = """
added 482 packages, and audited 483 packages in 12s

61 packages are looking for funding
  run `npm fund` for details

found 0 vulnerabilities
npm notice New minor version of npm available! 10.2.4 -> 10.5.0
npm warn deprecated inflight@1.0.6: This module is not supported
"""


def test_benign_npm_output_produces_no_exposure():
    exposure = find_canary_in_streams(
        TOKEN,
        {"the install's stdout": BENIGN_NPM_OUTPUT, "the install's stderr": ""},
    )
    assert exposure.found is False
    assert exposure.is_complete


def test_empty_streams_are_not_an_exposure():
    assert find_canary_in_streams(TOKEN, {"stdout": "", "stderr": ""}).found is False


def test_an_empty_token_never_matches():
    """Defensive: a token that failed to build must not match every string."""
    assert find_canary_in_streams("", {"stdout": "anything"}).found is False


# ---------------------------------------------------------------------------
# Read side — files the install created
# ---------------------------------------------------------------------------


def test_canary_found_in_a_staged_exfil_file(tmp_path):
    (tmp_path / "stolen.json").write_text(
        '{"npmrc": "' + TOKEN + '"}', encoding="utf-8"
    )

    exposure = scan_files_for_canary(tmp_path, TOKEN, ["stolen.json"])

    assert exposure.sources == ["stolen.json"]
    assert exposure.is_complete


def test_the_decoys_themselves_are_skipped(tmp_path):
    """They contain the token by construction; a hit there means nothing."""
    seed_decoys(tmp_path, TOKEN)

    exposure = scan_files_for_canary(tmp_path, TOKEN, list(decoy_relative_paths()))

    assert exposure.found is False
    assert exposure.is_complete


def test_binary_file_does_not_break_the_scan(tmp_path):
    (tmp_path / "blob.bin").write_bytes(b"\x00\xff\xfe" + TOKEN.encode() + b"\x00")

    exposure = scan_files_for_canary(tmp_path, TOKEN, ["blob.bin"])

    assert exposure.sources == ["blob.bin"]


def test_unreadable_candidate_is_recorded_not_swallowed(tmp_path):
    exposure = scan_files_for_canary(tmp_path, TOKEN, ["gone.txt"])

    assert exposure.found is False
    assert exposure.is_complete is False
    assert "gone.txt" in exposure.errors[0]


def test_scan_cap_is_reported_rather_than_silently_truncating(tmp_path):
    for index in range(5):
        (tmp_path / f"f{index}.txt").write_text("benign", encoding="utf-8")

    exposure = scan_files_for_canary(
        tmp_path, TOKEN, [f"f{i}.txt" for i in range(5)], file_limit=2
    )

    assert exposure.found is False
    assert exposure.is_complete is False
    assert "3 created file(s) beyond the 2-file scan cap" in exposure.errors[0]


def test_oversized_file_is_read_in_part_and_says_so(tmp_path):
    (tmp_path / "big.log").write_text("a" * 5000, encoding="utf-8")

    exposure = scan_files_for_canary(
        tmp_path, TOKEN, ["big.log"], byte_limit=100
    )

    assert exposure.found is False
    assert exposure.is_complete is False
    assert "only the first 100 bytes" in exposure.errors[0]


def test_oversized_file_that_hits_early_is_still_a_clean_finding(tmp_path):
    (tmp_path / "big.log").write_text(TOKEN + "a" * 5000, encoding="utf-8")

    exposure = scan_files_for_canary(
        tmp_path, TOKEN, ["big.log"], byte_limit=200
    )

    assert exposure.sources == ["big.log"]
    assert exposure.is_complete


BENIGN_CREATED_FILES = {
    "README.md": "# my-lib\n\nInstall with `npm i my-lib`.\n",
    "index.js": "module.exports = require('./lib/main.js');\n",
    "config.json": '{"registry": "https://registry.npmjs.org/"}\n',
    ".gitignore": "node_modules/\n",
    "build/out.js": "console.log('built');\n",
}


def test_benign_created_files_produce_no_exposure(tmp_path):
    for name, body in BENIGN_CREATED_FILES.items():
        target = tmp_path / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body, encoding="utf-8")

    exposure = scan_files_for_canary(
        tmp_path, TOKEN, list(BENIGN_CREATED_FILES)
    )

    assert exposure.found is False
    assert exposure.is_complete


def test_no_candidates_is_complete_and_empty(tmp_path):
    exposure = scan_files_for_canary(tmp_path, TOKEN, [])
    assert exposure.found is False
    assert exposure.is_complete


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------


def test_exposure_lines_name_the_source_and_the_act():
    exposure = CanaryExposure(token=TOKEN, sources=["the install's stdout"])
    (line,) = exposure.describe()
    assert "the install's stdout" in line
    assert "exfiltrated" in line


def test_exposure_lines_never_print_the_token():
    """The token is bait, but a report is copied into issues and chat logs —
    the line describes the event, it does not echo the value."""
    exposure = CanaryExposure(token=TOKEN, sources=["stolen.json"])
    assert all(TOKEN not in line for line in exposure.describe())


def test_no_sources_describes_nothing():
    assert CanaryExposure(token=TOKEN).describe() == []


def test_tampering_lines_state_why_it_is_unambiguous():
    (line,) = describe_decoy_tampering([".aws/credentials"], "deleted")
    assert ".aws/credentials" in line
    assert "deleted" in line
    assert "normal npm install" in line


def test_merge_exposures_combines_sources_and_errors():
    merged = merge_exposures(
        CanaryExposure(token=TOKEN, sources=["stdout"]),
        CanaryExposure(token=TOKEN, sources=["a.txt"], errors=["b.txt: boom"]),
    )
    assert merged.token == TOKEN
    assert merged.sources == ["stdout", "a.txt"]
    assert merged.errors == ["b.txt: boom"]
    assert merged.is_complete is False


def test_merge_of_nothing_is_clean():
    assert merge_exposures().found is False
    assert merge_exposures().is_complete


# ---------------------------------------------------------------------------
# End to end over the real snapshot/filter pipeline
# ---------------------------------------------------------------------------


def _sandbox_with_decoys(tmp_path):
    """A sandbox in the state phase 2 snapshots it: manifest plus decoys."""
    (tmp_path / "package.json").write_text('{"name":"shellockolm-sandbox"}', encoding="utf-8")
    seeding = seed_decoys(tmp_path, TOKEN)
    assert seeding.is_complete
    return snapshot_directory(tmp_path)


def _phase_four(before, after):
    new_files, modified, deleted = compare_snapshots(before, after)
    return (
        filter_suspicious_new_files(new_files),
        filter_unexpected_modifications(modified),
        filter_unexpected_deletions(deleted),
    )


def test_benign_install_produces_no_finding_of_any_kind(tmp_path):
    """The zero-false-positive baseline: an install that writes only what npm
    writes leaves the decoys untouched and the canary unseen."""
    before = _sandbox_with_decoys(tmp_path)

    # What npm itself does: a lockfile, a rewritten manifest, a package tree.
    (tmp_path / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"shellockolm-sandbox","dependencies":{}}', encoding="utf-8")
    installed = tmp_path / "node_modules" / "left-pad"
    installed.mkdir(parents=True)
    (installed / "index.js").write_text("module.exports = () => {};", encoding="utf-8")
    (tmp_path / ".npm-cache").mkdir()
    (tmp_path / ".npm-cache" / "index-v5").write_text("cache", encoding="utf-8")

    after = snapshot_directory(tmp_path)
    suspicious, changed, removed = _phase_four(before, after)

    assert suspicious == []
    assert split_decoy_changes(changed) == ([], [])
    assert split_decoy_changes(removed) == ([], [])

    exposure = merge_exposures(
        find_canary_in_streams(
            TOKEN,
            {"the install's stdout": BENIGN_NPM_OUTPUT, "the install's stderr": ""},
        ),
        scan_files_for_canary(tmp_path, TOKEN, suspicious),
    )
    assert exposure.found is False
    assert exposure.is_complete


def test_credential_stealer_that_stages_the_value_is_caught(tmp_path):
    """The shape F46 exists for: a postinstall reads ~/.aws/credentials and
    writes it somewhere before sending it."""
    before = _sandbox_with_decoys(tmp_path)

    stolen = (tmp_path / ".aws" / "credentials").read_text(encoding="utf-8")
    (tmp_path / ".cache-tmp.json").write_text(
        '{"payload":"' + stolen.strip().replace("\n", " ") + '"}', encoding="utf-8"
    )

    after = snapshot_directory(tmp_path)
    suspicious, _changed, _removed = _phase_four(before, after)

    assert ".cache-tmp.json" in suspicious

    exposure = scan_files_for_canary(tmp_path, TOKEN, suspicious)
    assert exposure.sources == [".cache-tmp.json"]


def test_credential_stealer_that_prints_the_value_is_caught(tmp_path):
    """`postinstall: cat ~/.npmrc` — the value never touches disk, but it is in
    the output the check already captures."""
    _sandbox_with_decoys(tmp_path)
    printed = (tmp_path / ".npmrc").read_text(encoding="utf-8")

    exposure = find_canary_in_streams(TOKEN, {"the install's stdout": printed})

    assert exposure.found


def test_install_that_wipes_the_ssh_key_is_caught(tmp_path):
    """Tampering needs no read-side signal at all: npm never deletes ~/.ssh."""
    before = _sandbox_with_decoys(tmp_path)

    (tmp_path / ".ssh" / "id_rsa").unlink()

    after = snapshot_directory(tmp_path)
    _suspicious, _changed, removed = _phase_four(before, after)

    wiped, others = split_decoy_changes(removed)
    assert wiped == [".ssh/id_rsa"]
    assert others == []
    assert describe_decoy_tampering(wiped, "deleted")


def test_cli_asks_npm_for_foreground_scripts():
    """Mechanism guard for the stdout route.

    npm 7+ buffers and DISCARDS lifecycle-script output unless the script
    fails, so without ``--foreground-scripts`` a payload's own print never
    reaches ``install_result.stdout`` and the canary stream check is looking at
    a stream nothing can arrive on. Measured against a real install both ways:
    with the flag the canary is exposed, without it the same install reports
    clean. Losing the flag would silently kill the check, so assert it at the
    call site.
    """
    source = (Path(__file__).resolve().parents[1] / "src" / "cli.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    install_calls = [
        line for line in source.splitlines()
        if '"npm", "install", pkg_name' in line
    ]
    assert install_calls, "sandbox install call not found - test needs updating"
    window = source.split('"npm", "install", pkg_name', 1)[1][:200]
    assert "--foreground-scripts" in window


def test_cli_isolates_npm_from_the_decoy_npmrc():
    """The decoy .npmrc must never become npm's real user config."""
    source = (Path(__file__).resolve().parents[1] / "src" / "cli.py").read_text(
        encoding="utf-8", errors="ignore"
    )
    assert "environment_with_decoy_isolation" in source
    assert "seed_decoys" in source


def test_install_that_rewrites_the_npmrc_is_caught(tmp_path):
    before = _sandbox_with_decoys(tmp_path)

    (tmp_path / ".npmrc").write_text("//evil.tld/:_authToken=x\n", encoding="utf-8")

    after = snapshot_directory(tmp_path)
    _suspicious, changed, _removed = _phase_four(before, after)

    tampered, others = split_decoy_changes(changed)
    assert tampered == [".npmrc"]
    assert others == []
