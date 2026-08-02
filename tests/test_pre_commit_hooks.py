"""Tests for the shipped ``.pre-commit-hooks.yaml`` (build-loop task #20).

A `.pre-commit-hooks.yaml` is a *contract* consumed by the `pre-commit`
framework in OTHER people's repos: a typo in `id`, a missing `pass_filenames`,
an `entry` that names a console script we do not actually install, or a default
``--fail-on`` value the CLI rejects all silently break the integration for every
downstream user. There is no network/`pre-commit` install here, so we validate
the contract structurally:

* the document parses and is a list of hook mappings with the required keys;
* every hook is ``language: python``, ``pass_filenames: false`` (our `scan` CLI
  takes a single PATH, not a filename list) and scopes to git via ``--diff``;
* the ``entry`` console script is actually declared in ``pyproject.toml``
  ``[project.scripts]`` (so `pre-commit` can resolve it after install);
* every default ``--fail-on`` value is one the live CLI accepts; and
* the agent hook's ``files`` trigger is a valid regex that matches real agent
  artifacts and ignores ordinary source files.
"""

import re
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]
HOOKS_FILE = REPO_ROOT / ".pre-commit-hooks.yaml"
PYPROJECT = REPO_ROOT / "pyproject.toml"

SRC = REPO_ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))


@pytest.fixture(scope="module")
def hooks():
    assert HOOKS_FILE.is_file(), f"missing {HOOKS_FILE}"
    data = yaml.safe_load(HOOKS_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, list) and data, "hooks file must be a non-empty list"
    return data


@pytest.fixture(scope="module")
def by_id(hooks):
    return {h["id"]: h for h in hooks}


# --------------------------------------------------------------------------- #
# Document-level contract
# --------------------------------------------------------------------------- #

def test_expected_hook_ids_present(by_id):
    # Both advertised ids exist; no accidental duplicates.
    assert {"shellockolm", "shellockolm-agent"} <= set(by_id)
    assert len(by_id) == 2, "unexpected/duplicate hook ids"


@pytest.mark.parametrize("key", ["id", "name", "entry", "language"])
def test_every_hook_has_required_keys(hooks, key):
    for h in hooks:
        assert key in h and h[key], f"hook {h.get('id')!r} missing {key!r}"


def test_every_hook_is_python_serial_and_no_filenames(hooks):
    for h in hooks:
        # language: python → pre-commit builds an isolated venv and `pip install`s
        # this repo, exposing the console scripts.
        assert h["language"] == "python", h["id"]
        # `scan` takes ONE path, so passing the staged filename list would break it;
        # `--diff` does the scoping instead.
        assert h.get("pass_filenames") is False, h["id"]
        assert h.get("require_serial") is True, h["id"]


def test_every_entry_is_a_diff_scoped_scan(hooks):
    for h in hooks:
        parts = h["entry"].split()
        assert parts[0] == "shellockolm", h["id"]
        assert parts[1] == "scan", h["id"]
        # --diff must live in entry (survives an args: override) so a hook never
        # silently scans the whole tree on commit.
        assert "--diff" in parts, f"{h['id']} entry must include --diff"


# --------------------------------------------------------------------------- #
# Cross-file contract: entry script + default gate must be real
# --------------------------------------------------------------------------- #

def test_entry_console_script_is_declared_in_pyproject(hooks):
    text = PYPROJECT.read_text(encoding="utf-8")
    block = text.split("[project.scripts]", 1)[1].split("[", 1)[0]
    declared = set(re.findall(r"^([A-Za-z0-9_-]+)\s*=", block, re.MULTILINE))
    assert "shellockolm" in declared, "console entry not declared"
    for h in hooks:
        assert h["entry"].split()[0] in declared, h["id"]


def test_default_fail_on_values_are_accepted_by_cli(hooks):
    from cli import _FAIL_ON_CHOICES  # noqa: E402

    for h in hooks:
        args = h.get("args", [])
        assert isinstance(args, list) and all(isinstance(a, str) for a in args)
        if "--fail-on" in args:
            value = args[args.index("--fail-on") + 1]
            assert value in _FAIL_ON_CHOICES, f"{h['id']}: bad --fail-on {value}"


# --------------------------------------------------------------------------- #
# Agent hook specifics + the files: trigger regex
# --------------------------------------------------------------------------- #

def test_agent_hook_targets_agent_scanner(by_id):
    assert "-s agent" in by_id["shellockolm-agent"]["entry"]
    # The full-scan hook must NOT pin a single scanner.
    assert "-s " not in by_id["shellockolm"]["entry"]


def test_agent_files_regex_matches_real_artifacts(by_id):
    pattern = by_id["shellockolm-agent"]["files"]
    rx = re.compile(pattern)  # must compile
    should_match = [
        "SKILL.md",
        "skills/my-skill/SKILL.md",
        "mcp.json",
        ".mcp.json",
        "claude_desktop_config.json",
        "claude_desktop_config_EXAMPLE.json",
        ".claude/settings.json",
        ".claude/commands/deploy.md",
        "CLAUDE.md",
        "sub/AGENTS.md",
        "GEMINI.md",
        ".cursorrules",
        ".github/copilot-instructions.md",
    ]
    for p in should_match:
        assert rx.search(p), f"expected agent-artifact match: {p}"

    should_not_match = [
        "src/app.js",
        "README.md",
        "package.json",
        "docs/skill-guide.md",   # not literally SKILL.md
        "notes/claude.md.bak",
    ]
    for p in should_not_match:
        assert not rx.search(p), f"unexpected match on ordinary file: {p}"
