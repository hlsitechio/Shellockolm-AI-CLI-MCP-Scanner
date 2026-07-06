"""Tests for AGENT-MCP-006 — remote MCP server over cleartext http:// / ws:// transport.

A remote MCP server configured with a transport URL (`url` / `serverUrl` /
`endpoint`) reached over an unencrypted scheme (http:// or ws://) to a PUBLIC host
sends its JSON-RPC traffic in the clear: an on-path attacker can read the auth token
AND inject forged tool results/definitions the agent trusts. AGENT-MCP-005
deliberately ignores the url transport field (it inspects the *launch command*), so
this rule closes that gap.

Contract asserted here:
* positive: cleartext (http/ws) transport to a public host / public IP fires
  AGENT-MCP-006 at every supported url field key, at MEDIUM severity, redacted;
* negative (zero-FP): https/wss, and cleartext to localhost / 127.0.0.1 / [::1] /
  private / link-local / mDNS (.local/.internal) / host.docker.internal / a stdio
  server with no url — none fire;
* the helper `_is_local_or_private_host` classification units;
* catalog/example wiring so RULES.md / `rules explain` never drift.
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
    MCP_CLEARTEXT_RULE,
    ALL_AGENT_RULES,
    agent_rule_catalog,
    agent_rule_example,
    agent_rule_class,
    agent_rule_tier,
    _is_local_or_private_host,
)

RULE = "AGENT-MCP-006"


@pytest.fixture
def scanner():
    # Pro tier is the strictest surface; MCP-006 is a free rule, so it must fire at
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

def test_cleartext_http_remote_host_flagged(scanner, tmp_path):
    config = {"mcpServers": {"remote": {"type": "sse", "url": "http://mcp.example.com:8080/sse"}}}
    result = scanner.scan_directory(_write_mcp(tmp_path, config))
    findings = [f for f in result.findings if f.cve_id == RULE]
    assert findings, f"expected {RULE}, got {[f.cve_id for f in result.findings]}"
    f = findings[0]
    assert f.severity.name == "MEDIUM"
    assert "mcp.example.com" in f.description
    assert "server:remote" in f.file_path


def test_cleartext_ws_public_ip_flagged(tmp_path):
    # ws:// (WebSocket) is cleartext too; a genuinely global IP has no cert provenance.
    config = {"servers": {"sock": {"serverUrl": "ws://8.8.8.8/rpc"}}}
    assert RULE in _ids(tmp_path, config)


def test_cleartext_http_public_ip_flagged(tmp_path):
    config = {"mcpServers": {"svc": {"url": "http://93.184.216.34:8080/mcp"}}}
    assert RULE in _ids(tmp_path, config)


def test_endpoint_field_key_flagged(tmp_path):
    # The `endpoint` alias for the transport URL is covered, not only `url`.
    config = {"mcpServers": {"svc": {"endpoint": "http://tools.vendor.net/mcp"}}}
    assert RULE in _ids(tmp_path, config)


def test_serverurl_field_key_flagged(tmp_path):
    config = {"mcpServers": {"svc": {"serverUrl": "http://api.thirdparty.io/sse"}}}
    assert RULE in _ids(tmp_path, config)


def test_flagged_in_claude_desktop_named_config(tmp_path):
    # A config not literally named mcp.json is still routed through the structured path.
    config = {"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}}
    assert RULE in _ids(tmp_path, config, "claude_desktop_config.json")


def test_finding_redacts_the_url(scanner, tmp_path):
    # The rendered evidence must not echo a raw embedded credential in the URL.
    config = {"mcpServers": {"r": {"url": "http://user:s3cr3t-token@mcp.example.com/sse"}}}
    result = scanner.scan_directory(_write_mcp(tmp_path, config))
    findings = [f for f in result.findings if f.cve_id == RULE]
    assert findings
    assert "s3cr3t-token" not in findings[0].description


def test_fires_at_free_tier_too(tmp_path):
    # MCP-006 is a FREE rule — it must fire without a Pro license.
    config = {"mcpServers": {"remote": {"url": "http://mcp.example.com/sse"}}}
    result = AgentSupplyChainScanner(pro=False).scan_directory(_write_mcp(tmp_path, config))
    assert any(f.cve_id == RULE for f in result.findings)


# --------------------------------------------------------------------------- #
# Negative baselines (zero false positives)
# --------------------------------------------------------------------------- #

def test_https_remote_not_flagged(tmp_path):
    config = {"mcpServers": {"remote": {"type": "http", "url": "https://api.example.com/mcp"}}}
    assert RULE not in _ids(tmp_path, config)


def test_wss_remote_not_flagged(tmp_path):
    config = {"mcpServers": {"remote": {"serverUrl": "wss://mcp.vendor.io/sse"}}}
    assert RULE not in _ids(tmp_path, config)


@pytest.mark.parametrize("url", [
    "http://localhost:3000/sse",
    "http://localhost/sse",
    "http://127.0.0.1:9000/mcp",
    "http://[::1]:8080/mcp",
    "http://192.168.1.50:8080/mcp",      # RFC1918 private
    "http://10.0.0.5/mcp",               # RFC1918 private
    "http://172.16.0.9/mcp",             # RFC1918 private
    "http://169.254.10.10/mcp",          # link-local
    "http://dev.local/rpc",              # mDNS
    "http://svc.internal/rpc",           # reserved private-use TLD
    "http://box.lan/rpc",                # home-network TLD
    "http://host.docker.internal:7000/sse",
])
def test_local_and_private_cleartext_not_flagged(tmp_path, url):
    config = {"mcpServers": {"local": {"url": url}}}
    assert RULE not in _ids(tmp_path, config), f"local/dev endpoint {url} must not be flagged"


def test_stdio_server_has_no_url_not_flagged(tmp_path):
    # An ordinary stdio server (command/args, no url field) is unaffected.
    config = {"mcpServers": {"fs": {
        "command": "npx",
        "args": ["@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"],
    }}}
    assert RULE not in _ids(tmp_path, config)


def test_does_not_hijack_the_mcp005_launcher_path(tmp_path):
    # A raw-URL *launcher* (args) is MCP-005's job; MCP-006 must not also claim it
    # (it only reads the transport url field, not command/args).
    config = {"mcpServers": {"helper": {
        "command": "deno",
        "args": ["run", "-A", "http://185.199.108.153/server.ts"],
    }}}
    ids = _ids(tmp_path, config)
    assert "AGENT-MCP-005" in ids
    assert RULE not in ids


# --------------------------------------------------------------------------- #
# Helper unit tests
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("host", [
    "localhost", "LocalHost", "app.localhost", "dev.local", "svc.internal",
    "box.lan", "host.docker.internal", "127.0.0.1", "::1", "[::1]",
    "192.168.0.1", "10.1.2.3", "172.31.255.1", "169.254.1.1", "",
])
def test_is_local_or_private_host_true(host):
    assert _is_local_or_private_host(host) is True


@pytest.mark.parametrize("host", [
    "mcp.example.com", "api.vendor.io", "8.8.8.8", "93.184.216.34",
    "1.1.1.1", "example.org",
])
def test_is_local_or_private_host_false(host):
    assert _is_local_or_private_host(host) is False


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
    assert MCP_CLEARTEXT_RULE.id == RULE
    assert any(r.id == RULE for r in ALL_AGENT_RULES)
    assert agent_rule_tier(RULE) == "free"
    assert agent_rule_class(RULE) == "mcp-config"


def test_rule_has_example_attack():
    ex = agent_rule_example(RULE)
    assert ex and "http://" in ex
