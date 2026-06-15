"""Tests for the MCP server's ``explain_finding`` tool (task #32).

Covers the pure resolver (`build_explain_payload`) and the markdown formatter
(`format_explain_payload`), plus end-to-end exercise of the async
`handle_call_tool` / `handle_list_tools` handlers exactly as an MCP client invokes
them — for both finding families the scanner emits (agent ``AGENT-*`` rules and
bundled ``CVE-*`` entries), case-insensitive lookup, and every error path
(missing/blank id, unknown id).
"""

import asyncio
import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import mcp_server as m  # noqa: E402
from scanners.agent_supply_chain import ALL_AGENT_RULES, agent_rule_explain  # noqa: E402


# ─────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────

def _call(name: str, args):
    """Invoke an MCP tool handler synchronously and return its text payload."""
    res = asyncio.run(m.handle_call_tool(name, args))
    assert res and hasattr(res[0], "text")
    return res[0].text


def _embedded_json(text: str) -> dict:
    """Extract and parse the structured JSON document from the tool's markdown output."""
    block = text.split("```json", 1)[1].split("```", 1)[0]
    return json.loads(block)


def _a_known_cve_id() -> str:
    """A real CVE id from the bundled database (the canonical Next.js middleware bypass)."""
    return "CVE-2025-29927"


# ─────────────────────────────────────────────────────────────────
# build_explain_payload — agent rules
# ─────────────────────────────────────────────────────────────────

def test_payload_agent_rule_shape():
    payload = m.build_explain_payload("AGENT-PI-013")
    assert payload is not None
    assert payload["schema_version"] == m.EXPLAIN_SCHEMA_VERSION
    assert payload["tool"] == "shellockolm"
    assert payload["kind"] == "agent-rule"
    rule = payload["rule"]
    # The why/impact/remediation explainer + the example-attack deep-dive.
    for key in ("id", "title", "severity", "tier", "confidence", "cvss",
                "attack_class", "description", "remediation", "example_attack"):
        assert key in rule, key
    assert rule["id"] == "AGENT-PI-013"
    assert rule["example_attack"]  # PI-013 has a concrete example
    # Matches the canonical catalog explainer (no drift between MCP and CLI).
    assert rule == agent_rule_explain("AGENT-PI-013")


def test_payload_agent_rule_case_insensitive():
    upper = m.build_explain_payload("AGENT-MCP-004")
    lower = m.build_explain_payload("  agent-mcp-004  ")
    assert upper is not None and lower is not None
    assert upper["rule"]["id"] == lower["rule"]["id"] == "AGENT-MCP-004"


def test_payload_every_agent_rule_resolves():
    """Every rule the scanner can emit is explainable through the MCP path."""
    for r in ALL_AGENT_RULES:
        payload = m.build_explain_payload(r.id)
        assert payload is not None, r.id
        assert payload["kind"] == "agent-rule"
        assert payload["rule"]["id"] == r.id
        # example_attack completeness is enforced upstream; assert it surfaces here.
        assert payload["rule"]["example_attack"], r.id


# ─────────────────────────────────────────────────────────────────
# build_explain_payload — CVEs
# ─────────────────────────────────────────────────────────────────

def test_payload_cve_shape():
    cve_id = _a_known_cve_id()
    payload = m.build_explain_payload(cve_id)
    assert payload is not None
    assert payload["kind"] == "cve"
    c = payload["cve"]
    for key in ("id", "title", "severity", "cvss", "vuln_type",
                "exploit_difficulty", "packages", "affected_versions",
                "patched_versions", "description", "remediation", "references",
                "cisa_kev", "public_poc", "active_exploitation"):
        assert key in c, key
    assert c["id"] == cve_id
    assert isinstance(c["packages"], list)
    assert isinstance(c["patched_versions"], dict)
    assert isinstance(c["cisa_kev"], bool)


def test_payload_cve_case_insensitive():
    cve_id = _a_known_cve_id()
    payload = m.build_explain_payload(cve_id.lower())
    assert payload is not None and payload["kind"] == "cve"
    assert payload["cve"]["id"] == cve_id


# ─────────────────────────────────────────────────────────────────
# build_explain_payload — unknown / boundary
# ─────────────────────────────────────────────────────────────────

@pytest.mark.parametrize("bad", ["", "   ", None, "NOT-A-RULE", "CVE-9999-00000",
                                 "AGENT-PI-999"])
def test_payload_unknown_returns_none(bad):
    assert m.build_explain_payload(bad) is None


# ─────────────────────────────────────────────────────────────────
# format_explain_payload
# ─────────────────────────────────────────────────────────────────

def test_formatter_agent_rule_markdown_and_json():
    payload = m.build_explain_payload("AGENT-PI-013")
    text = m.format_explain_payload(payload)
    assert "AGENT-PI-013" in text
    assert "## Why it's flagged (impact)" in text
    assert "## Example attack" in text
    assert "## Remediation" in text
    # Embedded JSON round-trips to the same document.
    assert _embedded_json(text)["rule"]["id"] == "AGENT-PI-013"


def test_formatter_cve_markdown_and_json():
    payload = m.build_explain_payload(_a_known_cve_id())
    text = m.format_explain_payload(payload)
    assert _a_known_cve_id() in text
    assert "## Why it's flagged (impact)" in text
    assert "## Remediation" in text
    assert _embedded_json(text)["cve"]["id"] == _a_known_cve_id()


def test_formatter_json_is_ascii_safe():
    """Rule prose carries en-dashes/ellipses — the embedded JSON must stay pipe-safe."""
    payload = m.build_explain_payload("AGENT-PI-005")  # invisible-char rule, unicode-heavy prose
    text = m.format_explain_payload(payload)
    blob = json.dumps(_embedded_json(text), ensure_ascii=True)
    assert blob.isascii()


# ─────────────────────────────────────────────────────────────────
# Tool registration
# ─────────────────────────────────────────────────────────────────

def test_tool_is_listed_with_required_schema():
    tools = asyncio.run(m.handle_list_tools())
    by_name = {t.name: t for t in tools}
    assert "explain_finding" in by_name
    tool = by_name["explain_finding"]
    assert tool.inputSchema["required"] == ["finding_id"]
    assert "finding_id" in tool.inputSchema["properties"]
    assert "explain" in tool.description.lower()


# ─────────────────────────────────────────────────────────────────
# handle_call_tool — end-to-end
# ─────────────────────────────────────────────────────────────────

def test_e2e_explain_agent_rule():
    text = _call("explain_finding", {"finding_id": "agent-pi-013"})
    doc = _embedded_json(text)
    assert doc["kind"] == "agent-rule"
    assert doc["rule"]["id"] == "AGENT-PI-013"


def test_e2e_explain_cve():
    text = _call("explain_finding", {"finding_id": _a_known_cve_id()})
    doc = _embedded_json(text)
    assert doc["kind"] == "cve"
    assert doc["cve"]["id"] == _a_known_cve_id()


def test_e2e_unknown_id_errors():
    text = _call("explain_finding", {"finding_id": "NOT-A-RULE"})
    assert "Unknown finding ID" in text


def test_e2e_missing_id_errors():
    text = _call("explain_finding", {})
    assert "'finding_id' is required" in text


def test_e2e_blank_id_errors():
    text = _call("explain_finding", {"finding_id": "   "})
    assert "'finding_id' is required" in text


def test_e2e_null_arguments_safe():
    # A JSON-RPC client sending params: null must not crash the handler.
    res = asyncio.run(m.handle_call_tool("explain_finding", None))
    assert res and "'finding_id' is required" in res[0].text
