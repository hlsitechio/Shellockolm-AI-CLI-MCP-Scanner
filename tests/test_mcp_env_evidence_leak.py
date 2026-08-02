"""AGENT-MCP-002 scoping, and the credential leak its mis-scoping caused.

Surfaced by `test_mcp_env_secret_never_unredacted` (a Hypothesis property test) finding
the example `xoxb-0000000000-Y`. Pre-existing — reproduced identically against the
committed HEAD, independent of the routing work in `test_mcp_config_routing.py`.

`_scan_mcp_structured` matches most rules against a join of the server's
`command + args + env`, and scopes the ones that assert "this config AUTO-EXECUTES
code" to the LAUNCH PATH alone, because an env entry is data handed to the process, not
a command line the agent runs. AGENT-MCP-002 ("runs an unpinned remote package") is that
kind of assertion — a package is pinned or not by its command line — but was matched
against the env join. Two defects followed:

* **False positive.** The rule's terminator is `-y\\b`, compiled case-insensitively, so
  ANY env value ending in `-Y` supplies it. A Slack bot token does:

      npx some-mcp API_KEY=xoxb-0000000000-Y

  fires "unpinned remote package" even though `npx some-mcp` carries no `-y` and no
  `@latest` at all. The credential, not the launcher, produced the finding.

* **Credential leak.** Evidence is `m.group(0)`, and the match now spans from `npx` to
  the `-Y` at the end of the secret — so the raw token is embedded in the finding text,
  which `to_dict()` copies into `--json` and SARIF. The scanner's report became a second
  copy of the credential it was reporting.

Fixed at the root: AGENT-MCP-002 joins `_LAUNCH_PATH_ONLY_RULES`, so env never reaches
it. `_scrub_secrets` is the second line of defence for the rules that legitimately DO
read env (the exfil/secret set) — a generic rule's span can still swallow a neighbouring
credential there, and masking the evidence with the secret rules' own patterns keeps
that unrepresentable regardless of which rule matched.

Costs nothing: a genuinely unpinned launcher always lives in command+args, and on 5,344
real agent artifacts the finding set is unchanged (no corpus AGENT-MCP-002 was
env-driven).
"""

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanners.agent_supply_chain import (  # noqa: E402
    _LAUNCH_PATH_ONLY_RULES,
    AgentSupplyChainScanner,
)

# Real credential shapes whose tail satisfies the rule's `-y` terminator. Each must be
# a token the secret rules actually recognize, or the test would pass vacuously — the
# `ghp_` body is exactly the 36 chars `AGENT-SECRET-001` requires.
TRAILING_Y_SECRETS = [
    "xoxb-0000000000-Y",                       # the Hypothesis falsifying example
    "xoxp-1111111111-2222222222-abcdefgY",
    "ghp_" + "0" * 35 + "Y",
]


@pytest.fixture
def scanner():
    return AgentSupplyChainScanner(pro=True)


def _scan(scanner, tmp_path: Path, cfg):
    (tmp_path / "mcp.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return scanner.scan_directory(tmp_path)


def _blob(result) -> str:
    """The canonical serialization every downstream report derives its text from."""
    return json.dumps(result.to_dict(), ensure_ascii=False, default=str)


@pytest.mark.parametrize("secret", TRAILING_Y_SECRETS)
def test_env_secret_never_appears_in_serialized_output(scanner, tmp_path, secret):
    result = _scan(scanner, tmp_path, {"mcpServers": {"svc": {
        "command": "npx", "args": ["some-mcp"], "env": {"API_KEY": secret}}}})
    assert secret not in _blob(result)


@pytest.mark.parametrize("secret", TRAILING_Y_SECRETS)
def test_env_secret_does_not_fabricate_an_unpinned_launcher(scanner, tmp_path, secret):
    """The launcher here is pinned-by-omission: no `-y`, no `--yes`, no `@latest`."""
    result = _scan(scanner, tmp_path, {"mcpServers": {"svc": {
        "command": "npx", "args": ["some-mcp"], "env": {"API_KEY": secret}}}})
    assert "AGENT-MCP-002" not in {f.cve_id for f in result.findings}


@pytest.mark.parametrize("secret", TRAILING_Y_SECRETS)
def test_the_secret_itself_is_still_detected(scanner, tmp_path, secret):
    """Scoping the launcher rule must not cost the credential finding — the leak is
    fixed by masking the evidence, never by going quiet about the secret."""
    result = _scan(scanner, tmp_path, {"mcpServers": {"svc": {
        "command": "npx", "args": ["some-mcp"], "env": {"API_KEY": secret}}}})
    assert any(f.cve_id.startswith("AGENT-SECRET") for f in result.findings)


@pytest.mark.parametrize("args", [
    ["-y", "some-mcp"],
    ["--yes", "some-mcp"],
    ["some-mcp@latest"],
])
def test_real_unpinned_launchers_still_fire(scanner, tmp_path, args):
    """The narrowing is to the launch path, not to nothing."""
    result = _scan(scanner, tmp_path, {"mcpServers": {"svc": {
        "command": "npx", "args": args}}})
    assert "AGENT-MCP-002" in {f.cve_id for f in result.findings}


def test_unpinned_launcher_still_fires_alongside_an_env_secret(scanner, tmp_path):
    """Both findings coexist — and the evidence for neither carries the raw token."""
    secret = "xoxb-0000000000-Y"
    result = _scan(scanner, tmp_path, {"mcpServers": {"svc": {
        "command": "npx", "args": ["-y", "some-mcp"], "env": {"API_KEY": secret}}}})
    ids = {f.cve_id for f in result.findings}
    assert "AGENT-MCP-002" in ids
    assert any(i.startswith("AGENT-SECRET") for i in ids)
    assert secret not in _blob(result)


def test_mcp_002_is_scoped_to_the_launch_path():
    assert "AGENT-MCP-002" in _LAUNCH_PATH_ONLY_RULES


@pytest.mark.parametrize("secret", TRAILING_Y_SECRETS)
def test_scrub_masks_a_credential_embedded_in_any_evidence(scanner, secret):
    """The defence-in-depth half, exercised directly: whatever rule produced the span,
    a credential inside it is masked rather than echoed."""
    scrubbed = scanner._scrub_secrets(f"npx some-mcp API_KEY={secret}")
    assert secret not in scrubbed
    assert "[redacted" in scrubbed


def test_scrub_leaves_ordinary_evidence_alone(scanner):
    for text in ["npx -y some-mcp", "curl https://example.com/x.sh | bash",
                 "AWS_REGION=us-east-1", "", "node --version"]:
        assert scanner._scrub_secrets(text) == text
