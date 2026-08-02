"""Tests for AGENT-MCP-007 — MCP server that blanket-auto-approves every tool call.

Several MCP clients (Cline, Roo Code, Cursor, Windsurf) let a per-server config
pre-approve tool calls so the agent runs them WITHOUT the usual per-call human
confirmation. A scoped named allow-list (`alwaysAllow: ["read_file"]`) is the user's
deliberate, safe choice. What removes all oversight is a BLANKET approval — a
wildcard (`"*"`) or a boolean `true` — which auto-approves every tool the server
exposes, including tools a later server update silently adds (a rug-pull). This rule
fires ONLY on the blanket form, so an explicit named allow-list never trips it.

Contract asserted here:
* positive: wildcard list / wildcard scalar / boolean-true / spelling variants
  (`always_allow`, `auto-approve`, `autoApproved`, …) fire AGENT-MCP-007 at MEDIUM,
  at both free and Pro tier, redacted;
* negative (zero-FP): a scoped named allow-list, an empty list, `false`, `"false"`,
  a falsey scalar, and a server with no auto-approve field — none fire;
* the helper `_mcp_blanket_autoapprove` classification units;
* catalog / example wiring so RULES.md / `rules explain` never drift.
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
    MCP_AUTOAPPROVE_RULE,
    ALL_AGENT_RULES,
    agent_rule_catalog,
    agent_rule_example,
    agent_rule_class,
    agent_rule_tier,
    _mcp_blanket_autoapprove,
)

RULE = "AGENT-MCP-007"


@pytest.fixture
def scanner():
    # Pro tier is the strictest surface; MCP-007 is a free rule, so it must fire at
    # both tiers — running Pro here also proves it isn't accidentally Pro-gated.
    return AgentSupplyChainScanner(pro=True)


def _write_mcp(tmp_path: Path, config: dict, filename: str = "mcp.json") -> str:
    (tmp_path / filename).write_text(json.dumps(config, indent=2), encoding="utf-8")
    return str(tmp_path)


def _ids(tmp_path: Path, config: dict, filename: str = "mcp.json") -> set:
    result = AgentSupplyChainScanner(pro=True).scan_directory(_write_mcp(tmp_path, config, filename))
    return {f.cve_id for f in result.findings}


# --------------------------------------------------------------------------- #
# Positive detections
# --------------------------------------------------------------------------- #

def test_wildcard_list_flagged(scanner, tmp_path):
    config = {"mcpServers": {"helper": {
        "command": "npx", "args": ["unvetted-mcp"], "alwaysAllow": ["*"],
    }}}
    result = scanner.scan_directory(_write_mcp(tmp_path, config))
    findings = [f for f in result.findings if f.cve_id == RULE]
    assert findings, f"expected {RULE}, got {[f.cve_id for f in result.findings]}"
    f = findings[0]
    assert f.severity.name == "MEDIUM"
    assert "server:helper" in f.file_path
    assert "auto-approval" in f.description.lower()


def test_boolean_true_flagged(tmp_path):
    config = {"mcpServers": {"notes": {"command": "node", "args": ["s.js"], "autoApprove": True}}}
    assert RULE in _ids(tmp_path, config)


def test_wildcard_scalar_star_flagged(tmp_path):
    config = {"mcpServers": {"svc": {"autoApprove": "*"}}}
    assert RULE in _ids(tmp_path, config)


@pytest.mark.parametrize("scalar", ["*", "all", "any", "true", "yes", "on", "always"])
def test_approve_all_scalars_flagged(tmp_path, scalar):
    config = {"mcpServers": {"svc": {"alwaysAllow": scalar}}}
    assert RULE in _ids(tmp_path, config), f"scalar {scalar!r} should flag as blanket approval"


@pytest.mark.parametrize("key", [
    "alwaysAllow", "always_allow", "always-allow",
    "autoApprove", "auto_approve", "auto-approve", "autoApproved",
    "autoAllow", "autoAccept", "autoExecute", "autoRun",
])
def test_field_key_spelling_variants_flagged(tmp_path, key):
    config = {"mcpServers": {"svc": {key: True}}}
    assert RULE in _ids(tmp_path, config), f"key {key!r} should be recognized as an auto-approve field"


def test_gemini_trust_true_flagged(tmp_path):
    # Gemini CLI's `trust: true` bypasses ALL tool-call confirmations for the server —
    # semantically identical to a blanket `autoApprove: true`, so it must fire MCP-007.
    config = {"mcpServers": {"gem": {"command": "npx", "args": ["srv"], "trust": True}}}
    assert RULE in _ids(tmp_path, config)


def test_flagged_in_claude_code_named_config(tmp_path):
    # A config not literally named mcp.json is still routed through the structured path.
    config = {"mcpServers": {"remote": {"command": "npx", "args": ["x"], "alwaysAllow": ["*"]}}}
    assert RULE in _ids(tmp_path, config, "claude_desktop_config.json")


def test_fires_at_free_tier_too(tmp_path):
    # MCP-007 is a FREE rule — it must fire without a Pro license.
    config = {"mcpServers": {"svc": {"autoApprove": True}}}
    result = AgentSupplyChainScanner(pro=False).scan_directory(_write_mcp(tmp_path, config))
    assert any(f.cve_id == RULE for f in result.findings)


def test_one_finding_per_blanket_server(scanner, tmp_path):
    # Two blanket-approving servers → exactly two MCP-007 findings (one per server).
    config = {"mcpServers": {
        "a": {"alwaysAllow": ["*"]},
        "b": {"autoApprove": True},
    }}
    result = scanner.scan_directory(_write_mcp(tmp_path, config))
    hits = [f for f in result.findings if f.cve_id == RULE]
    assert len(hits) == 2
    assert {"server:a" in f.file_path or "server:b" in f.file_path for f in hits} == {True}


# --------------------------------------------------------------------------- #
# Negative baselines (zero false positives)
# --------------------------------------------------------------------------- #

def test_scoped_named_allowlist_not_flagged(tmp_path):
    # The intentional, safe use of the feature — a specific named allow-list.
    config = {"mcpServers": {"fs": {
        "command": "npx", "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"],
        "alwaysAllow": ["read_file", "list_directory"],
    }}}
    assert RULE not in _ids(tmp_path, config)


def test_scoped_autoapprove_list_not_flagged(tmp_path):
    config = {"mcpServers": {"search": {"autoApprove": ["web_search", "fetch_url"]}}}
    assert RULE not in _ids(tmp_path, config)


@pytest.mark.parametrize("val", [[], False, "false", "no", "off", "0", "disabled"])
def test_falsey_or_empty_not_flagged(tmp_path, val):
    config = {"mcpServers": {"svc": {"autoApprove": val}}}
    assert RULE not in _ids(tmp_path, config), f"value {val!r} must not be flagged"


def test_no_autoapprove_field_not_flagged(tmp_path):
    config = {"mcpServers": {"fs": {"command": "npx", "args": ["server-filesystem@1.0.0"]}}}
    assert RULE not in _ids(tmp_path, config)


def test_gemini_trust_false_not_flagged(tmp_path):
    # The Gemini CLI default (`trust: false`) keeps per-call confirmations on — not an
    # attack, must not fire. Guards against the `trust` field over-firing on the
    # common falsey value.
    config = {"mcpServers": {"gem": {"command": "npx", "args": ["srv"], "trust": False}}}
    assert RULE not in _ids(tmp_path, config)


def test_named_tool_called_all_is_not_a_wildcard_scalar(tmp_path):
    # A *list* element must be exactly a wildcard token; a plausible real tool name
    # like "all_files" is not "all" and stays a scoped, non-blanket approval.
    config = {"mcpServers": {"svc": {"alwaysAllow": ["all_files", "read_note"]}}}
    assert RULE not in _ids(tmp_path, config)


def test_integer_one_not_treated_as_blanket(tmp_path):
    # A bare JSON number 1 is deliberately not read as "approve all" (avoid a numeric
    # false read); only boolean true / wildcard string / wildcard list element fire.
    config = {"mcpServers": {"svc": {"autoApprove": 1}}}
    assert RULE not in _ids(tmp_path, config)


# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("cfg,expect_key", [
    ({"alwaysAllow": ["*"]}, "alwaysAllow"),
    ({"autoApprove": True}, "autoApprove"),
    ({"auto_approve": "all"}, "auto_approve"),
    ({"autoRun": "any"}, "autoRun"),
    ({"trust": True}, "trust"),  # Gemini CLI blanket-trust form
])
def test_helper_detects_blanket(cfg, expect_key):
    hit = _mcp_blanket_autoapprove(cfg)
    assert hit is not None
    assert hit[0] == expect_key


@pytest.mark.parametrize("cfg", [
    {"alwaysAllow": ["read_file"]},
    {"alwaysAllow": []},
    {"autoApprove": False},
    {"autoApprove": "false"},
    {"command": "npx", "args": ["srv"]},
    {"autoApprove": 1},
    {"alwaysAllow": ["all_tools"]},
    {"trust": False},  # Gemini CLI default — confirmations stay on
])
def test_helper_returns_none_for_non_blanket(cfg):
    assert _mcp_blanket_autoapprove(cfg) is None


# --------------------------------------------------------------------------- #
# Does not hijack the other MCP rules
# --------------------------------------------------------------------------- #

def test_composes_with_raw_url_launcher(tmp_path):
    # A server that BOTH launches from a raw URL (MCP-005) AND blanket-approves
    # (MCP-007) yields both findings — the checks are independent.
    config = {"mcpServers": {"x": {
        "command": "deno",
        "args": ["run", "-A", "https://raw.githubusercontent.com/e/v/s.ts"],
        "alwaysAllow": ["*"],
    }}}
    ids = _ids(tmp_path, config)
    assert RULE in ids
    assert "AGENT-MCP-005" in ids


# --------------------------------------------------------------------------- #
# Catalog / example wiring (drift guards)
# --------------------------------------------------------------------------- #

def test_rule_in_catalog_with_expected_metadata():
    cat = {c["id"]: c for c in agent_rule_catalog()}
    assert RULE in cat
    entry = cat[RULE]
    assert entry["severity"] == "MEDIUM"
    assert entry["tier"] == "free"
    assert entry["attack_class"] == "mcp-config"
    assert entry["confidence"] == "high"


def test_rule_object_is_enumerable():
    assert MCP_AUTOAPPROVE_RULE.id == RULE
    assert any(r.id == RULE for r in ALL_AGENT_RULES)
    assert agent_rule_tier(RULE) == "free"
    assert agent_rule_class(RULE) == "mcp-config"


def test_rule_has_example_attack():
    ex = agent_rule_example(RULE)
    assert ex and ("alwaysAllow" in ex or "autoApprove" in ex)
