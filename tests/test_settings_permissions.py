"""Tests for AGENT-PERM-001 — Claude Code settings that disable the confirmation prompt.

A `.claude/settings.json` `permissions` block decides which tool calls run WITHOUT
asking the human. That per-call confirmation is the primary guardrail between a prompt
injection the agent just read and arbitrary execution on the machine, so a committed
settings.json that turns it off is a standing zero-click execution channel — the Claude
Code analogue of a blanket MCP auto-approval (AGENT-MCP-007).

A scoped allow-list is the feature working as intended and is the overwhelmingly common
real shape, so the rule fires ONLY on the two documented BLANKET forms:
  (A) `permissions.defaultMode: "bypassPermissions"` — documented as skipping prompts;
  (B) a blanket `permissions.allow` entry for a command-EXECUTION tool — a bare `Bash`
      (documented: matches every Bash command) or the equivalent `Bash(*)`.

The zero-FP baselines below each encode a DOCUMENTED semantic — flagging any of them
would be a false positive, not a conservative choice:
  * `auto` / `dontAsk` are documented as SAFER, not prompt-skipping (`auto` gates on a
    classifier and honors `ask` rules; `dontAsk` auto-DENIES anything not pre-approved);
    `acceptEdits` runs no commands; `plan` / `default` (alias `manual`) are normal.
  * an unanchored `allow` glob (`"*"`, `"B*"`, `"mcp__*"`) is documented as "skipped
    with a warning" and auto-approves NOTHING — it is not a vector.
  * a blanket entry in `deny` / `ask` is a RESTRICTION; flagging it would be backwards.
  * bare READ-ONLY tools (Read/Glob/Grep/WebSearch) and exact MCP tool names grant no
    command execution — and are what real configs actually contain (calibration over 34
    real settings.json files: 478 scoped allow entries, ZERO blanket execution grants).
"""

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanners.agent_supply_chain import (  # noqa: E402
    AgentSupplyChainScanner,
    SETTINGS_PERMISSION_BYPASS_RULE,
    ALL_AGENT_RULES,
    agent_rule_catalog,
    agent_rule_example,
    agent_rule_class,
    agent_rule_tier,
    _perm_blanket_exec_allow,
    _perm_findings,
)

RULE = "AGENT-PERM-001"


@pytest.fixture
def scanner():
    # Pro is the strictest surface; PERM-001 is a free rule, so it must fire at both
    # tiers — running Pro here also proves it isn't accidentally Pro-gated.
    return AgentSupplyChainScanner(pro=True)


def _write_settings(tmp_path: Path, data, name: str = "settings.json") -> Path:
    d = tmp_path / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    fp = d / name
    fp.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return fp


def _rule_ids(result):
    return [f.cve_id for f in result.findings]


# --------------------------------------------------------------- helper units

@pytest.mark.parametrize("entry,tool", [
    ("Bash", "Bash"),
    ("Bash(*)", "Bash"),
    ("Bash( * )", "Bash"),
    ("  Bash  ", "Bash"),
    ("bash", "bash"),
    ("PowerShell", "PowerShell"),
    ("PowerShell(*)", "PowerShell"),
])
def test_blanket_exec_allow_detects_blanket_forms(entry, tool):
    """A bare execution-tool name — or its documented `Tool(*)` equivalent — is blanket."""
    assert _perm_blanket_exec_allow(entry) == tool


@pytest.mark.parametrize("entry", [
    # scoped Bash rules — the feature working as intended
    "Bash(npm run test:*)", "Bash(npm run lint)", "Bash(git status)",
    "Bash(ls *)", "Bash(ls:*)", "Bash(**)", "Bash(*extra)",
    # non-execution tools: blanket, but they run no commands
    "Read", "Glob", "Grep", "WebSearch", "WebFetch", "Write", "Edit",
    # unanchored allow globs: documented as skipped-with-a-warning, grant nothing
    "*", "B*", "mcp__*",
    # the sanctioned per-server MCP form + an exact MCP tool name
    "mcp__puppeteer__*", "mcp__supabase__execute_sql",
    # degenerate input
    "", "   ",
])
def test_blanket_exec_allow_ignores_benign_entries(entry):
    assert _perm_blanket_exec_allow(entry) is None


def test_blanket_exec_allow_never_raises_on_odd_input():
    for bad in ["", "   ", "((", "Bash(", "Bash()"]:
        _perm_blanket_exec_allow(bad)


def test_perm_findings_requires_a_real_permissions_shape():
    """An unrelated JSON that merely has a `permissions` field is not a settings file."""
    assert _perm_findings({"permissions": {"role": "admin", "scopes": ["read"]}}) == []


@pytest.mark.parametrize("data", [
    "not-a-dict",
    ["nope"],
    {"permissions": "all"},
    {"permissions": None},
    {"hooks": {}},
    {},
])
def test_perm_findings_tolerates_non_settings_input(data):
    assert _perm_findings(data) == []


# ------------------------------------------------------------------ positives

def test_bypass_permissions_mode_fires(tmp_path, scanner):
    fp = _write_settings(tmp_path, {"permissions": {"defaultMode": "bypassPermissions"}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


def test_blanket_bash_allow_fires(tmp_path, scanner):
    fp = _write_settings(tmp_path, {"permissions": {"allow": ["Bash"]}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


def test_blanket_bash_wildcard_allow_fires(tmp_path, scanner):
    """`Bash(*)` is documented as equivalent to a bare `Bash`."""
    _write_settings(tmp_path, {"permissions": {"allow": ["Bash(*)"]}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


def test_blanket_powershell_allow_fires(tmp_path, scanner):
    """PowerShell rules use the same shape as Bash rules — also command execution."""
    _write_settings(tmp_path, {"permissions": {"allow": ["PowerShell"]}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


def test_both_blanket_forms_report_separately(tmp_path, scanner):
    """A config that bypasses AND blanket-allows reports each distinct grant."""
    _write_settings(tmp_path, {
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"]}
    })
    result = scanner.scan_directory(str(tmp_path))
    perm = [f for f in result.findings if f.cve_id == RULE]
    assert len(perm) == 2
    locs = " ".join(f.file_path for f in perm)
    assert "permissions.defaultMode" in locs and "permissions.allow" in locs


def test_fires_in_settings_local_json(tmp_path, scanner):
    _write_settings(tmp_path, {"permissions": {"allow": ["Bash"]}}, name="settings.local.json")
    result = scanner.scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


def test_finding_metadata_is_medium_and_high_confidence(tmp_path, scanner):
    _write_settings(tmp_path, {"permissions": {"defaultMode": "bypassPermissions"}})
    result = scanner.scan_directory(str(tmp_path))
    f = next(f for f in result.findings if f.cve_id == RULE)
    assert f.severity.value == "MEDIUM"
    assert f.confidence == "high"
    assert f.package == "claude-settings"
    assert "bypassPermissions" in f.description


def test_fires_at_free_tier_too(tmp_path):
    """PERM-001 is a free/OSS rule — it must not be accidentally Pro-gated."""
    _write_settings(tmp_path, {"permissions": {"allow": ["Bash"]}})
    result = AgentSupplyChainScanner(pro=False).scan_directory(str(tmp_path))
    assert RULE in _rule_ids(result)


# ------------------------------------------------- negatives (zero-FP baselines)

@pytest.mark.parametrize("mode", ["auto", "dontAsk", "acceptEdits", "plan", "default", "manual"])
def test_non_bypass_modes_do_not_fire(tmp_path, scanner, mode):
    """Only `bypassPermissions` skips prompts; `auto`/`dontAsk` are documented as safer."""
    _write_settings(tmp_path, {"permissions": {"defaultMode": mode, "allow": ["Bash(npm test)"]}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_scoped_allow_list_does_not_fire(tmp_path, scanner):
    _write_settings(tmp_path, {"permissions": {
        "defaultMode": "acceptEdits",
        "allow": ["Bash(npm run test:*)", "Bash(git status)", "Read", "Glob",
                  "Grep", "WebSearch", "mcp__supabase__list_tables"],
    }})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_unanchored_allow_glob_does_not_fire(tmp_path, scanner):
    """`*` / `B*` / `mcp__*` in allow are skipped with a warning and grant nothing."""
    _write_settings(tmp_path, {"permissions": {"allow": ["*", "B*", "mcp__*"]}})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_blanket_deny_and_ask_are_restrictions_not_risks(tmp_path, scanner):
    """A blanket entry in deny/ask RESTRICTS the agent — flagging it would be backwards."""
    _write_settings(tmp_path, {"permissions": {
        "deny": ["Bash", "*", "PowerShell"],
        "ask": ["Bash"],
    }})
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_empty_and_missing_permissions_do_not_fire(tmp_path, scanner):
    _write_settings(tmp_path, {"permissions": {"allow": [], "deny": []}})
    _write_settings(tmp_path, {"hooks": {}}, name="settings.local.json")
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_scoped_permissions_fixture_is_clean(scanner):
    """The committed benign fixture must stay zero-finding at the strictest tier."""
    fixture = Path(__file__).parent / "fixtures" / "settings" / "scoped-permissions"
    result = scanner.scan_directory(str(fixture))
    assert result.findings == [], [f.cve_id for f in result.findings]


def test_permission_bypass_fixture_fires(scanner):
    fixture = Path(__file__).parent / "fixtures" / "settings" / "permission-bypass"
    result = scanner.scan_directory(str(fixture))
    assert RULE in _rule_ids(result)


def test_non_claude_settings_json_is_ignored(tmp_path, scanner):
    """A .vscode/settings.json is not agent config — the `.claude` scoping still holds."""
    d = tmp_path / ".vscode"
    d.mkdir(parents=True)
    (d / "settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash"]}}),
        encoding="utf-8",
    )
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_malformed_settings_json_does_not_crash(tmp_path, scanner):
    d = tmp_path / ".claude"
    d.mkdir(parents=True)
    (d / "settings.json").write_text('{"permissions": {"allow": ["Bash"', encoding="utf-8")
    result = scanner.scan_directory(str(tmp_path))
    assert RULE not in _rule_ids(result)


def test_existing_hook_fixtures_unaffected(scanner):
    """The prior hook fixtures must keep their exact behaviour (no new PERM findings)."""
    base = Path(__file__).parent / "fixtures" / "settings"
    benign = scanner.scan_directory(str(base / "benign"))
    assert benign.findings == []
    malicious = scanner.scan_directory(str(base / "malicious"))
    ids = [f.cve_id for f in malicious.findings]
    assert "AGENT-HOOK-001" in ids
    assert RULE not in ids


# ------------------------------------------------------- scan_text integration

def test_scan_text_auto_detects_permissions_only_settings(scanner):
    """A permissions-only settings.json has no `hooks` key — auto-detection must still
    route it to the settings path rather than silently under-scanning it as prose."""
    text = json.dumps({"permissions": {"defaultMode": "bypassPermissions"}})
    result = scanner.scan_text(text)
    assert result.stats["artifact_type"] == "settings"
    assert RULE in _rule_ids(result)


def test_scan_text_with_filename_hint(scanner):
    text = json.dumps({"permissions": {"allow": ["Bash"]}})
    result = scanner.scan_text(text, filename=".claude/settings.json")
    assert RULE in _rule_ids(result)


def test_scan_text_unrelated_permissions_json_not_settings(scanner):
    """A JSON that merely has a `permissions` field must not be misrouted to settings."""
    text = json.dumps({"permissions": {"role": "admin", "scopes": ["read"]}})
    result = scanner.scan_text(text)
    assert result.stats["artifact_type"] != "settings"


def test_scan_text_explicit_settings_type(scanner):
    text = json.dumps({"permissions": {"allow": ["Bash(*)"]}})
    result = scanner.scan_text(text, artifact_type="settings")
    assert RULE in _rule_ids(result)


# ------------------------------------------------------ catalog / docs wiring

def test_rule_is_in_the_catalog():
    entry = next((e for e in agent_rule_catalog() if e["id"] == RULE), None)
    assert entry is not None
    assert entry["severity"] == "MEDIUM"
    assert entry["confidence"] == "high"
    assert entry["tier"] == "free"
    assert entry["attack_class"] == "permission-bypass"


def test_rule_object_is_registered():
    assert SETTINGS_PERMISSION_BYPASS_RULE in ALL_AGENT_RULES
    assert SETTINGS_PERMISSION_BYPASS_RULE.id == RULE


def test_attack_class_and_tier_helpers():
    assert agent_rule_class(RULE) == "permission-bypass"
    assert agent_rule_tier(RULE) == "free"


def test_example_attack_exists_and_shows_the_safe_form():
    example = agent_rule_example(RULE)
    assert "bypassPermissions" in example
    # the example must also teach the scoped alternative, so a reader sees the fix
    assert "Bash(npm run test:*)" in example
