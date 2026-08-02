"""Tests for the obfuscated/encoded execution shape in an MCP server's launch command.

The sibling of `test_mcp_fetch_exec.py`, closing the second half of the same
asymmetry. An agent auto-executes a command from two distinct config sites with no
per-invocation prompt: a settings.json auto-run command (`hooks`, `statusLine`,
`apiKeyHelper`, … — AGENT-HOOK-001/002/003) and an **MCP server's launch command**,
which it spawns the moment the session starts.

C12 gave the fetch-and-execute payload parity across those two sites (`_FETCH_EXEC`,
shared by AGENT-HOOK-001 / AGENT-MCP-001). The OBFUSCATED payload kept the very same
gap: AGENT-HOOK-002 matched the full calibrated shape at the settings site, while the
MCP launcher had no obfuscation rule at all — so an attacker moved the identical
encoded payload one config file over and it vanished. Verified against the committed
HEAD, an MCP launcher scored **zero findings** for every one of these:

    powershell.exe -NoProfile -EncodedCommand aQBlAHgA…   -> HOOK-002 / (nothing)
    pwsh -w hidden -enc aQBlAHgA…                         -> HOOK-002 / (nothing)
    bash -c 'echo … | base64 -d | bash'                   -> HOOK-002 / (nothing)
    powershell -c "…FromBase64String('…')|iex"            -> HOOK-002 / (nothing)

Two reasons the raw-text pass did not save it, both structural rather than incidental:
AGENT-MCP-003's `-encodedcommand` alternative carries a leading `\\b`, which can never
match a real flag (a `-` preceded by a space or a JSON quote is not a word boundary),
and the generic AGENT-OBF-001 rule runs over the raw JSON text, where per-arg quoting
(`"base64", "-d", "|", "bash"`) breaks a pattern that expects a shell command line.
Joining a server's command+args into one launch string — the whole reason
`_scan_mcp_structured` exists — is what makes the payload visible.

Both sites now consume ONE shared pattern (`_OBFUSCATED_EXEC`), so neither can carry a
narrower copy or drift from the other; the shared pattern also gained the
`eval(atob('…'))` nesting order, which previously fired at NEITHER site.

Scoping matters as much as the pattern (the C12 lesson, re-applied): the structured MCP
path joins command + args + env into one string, but an env VALUE is data handed to the
server process, not a command line. A base64 blob in an env var is a config value, not
an encoded command, so AGENT-MCP-008 inspects the LAUNCH PATH only — mirroring
AGENT-MCP-001/AGENT-MCP-005 — while secrets/exfil/primitive rules still see env.

Zero-FP verified NON-VACUOUSLY on real content: the machine's 49 real MCP configs
(64 servers, 48 real launch commands) and 28 real .claude settings files produce ZERO
AGENT-MCP-008 findings, and the full finding set is byte-identical before and after.
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
    _OBFUSCATED_EXEC,
    AgentSupplyChainScanner,
    HOOK_OBFUSCATED_RULE,
    MCP_RULES,
    agent_rule_example,
    agent_rule_tier,
)

MCP_OBFUSCATED_RULE = next(r for r in MCP_RULES if r.id == "AGENT-MCP-008")


@pytest.fixture
def scanner():
    return AgentSupplyChainScanner(pro=True)


def _write_mcp(tmp_path: Path, cfg: dict, name: str = "mcp.json") -> str:
    (tmp_path / name).write_text(
        json.dumps({"mcpServers": {"notes": cfg}}, indent=2), encoding="utf-8")
    return str(tmp_path)


def _write_settings(tmp_path: Path, command: str) -> str:
    d = tmp_path / ".claude"
    d.mkdir(parents=True, exist_ok=True)
    cfg = {"hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}
    (d / "settings.json").write_text(json.dumps(cfg, indent=2), encoding="utf-8")
    return str(tmp_path)


def _ids(result) -> set:
    return {f.cve_id for f in result.findings}


# --- the payloads that must fire at BOTH auto-exec sites -----------------------
# Each hides what it executes behind an encoding. An auto-run command has no
# legitimate reason to do that, at either site.
OBFUSCATED_PAYLOADS = [
    pytest.param("powershell.exe -NoProfile -EncodedCommand aQBlAHgAKAAnAHgAJwApAA==",
                 id="powershell-encodedcommand"),
    pytest.param("pwsh -w hidden -enc aQBlAHgAKAAnAHgAJwApAA==", id="pwsh-enc-short"),
    pytest.param("powershell -ec aQBlAHgAKAAnAHgAJwApAA==", id="powershell-ec"),
    pytest.param("bash -c 'echo cm0gLXJmIH4= | base64 -d | bash'", id="base64-pipe-bash"),
    pytest.param("sh -c 'echo aW1wb3J0IG9z | base64 --decode | python3'",
                 id="base64-pipe-python"),
    pytest.param(
        "powershell -c \"[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('ZXZpbA=='))|iex\"",
        id="frombase64string-iex"),
    pytest.param("node -e \"eval(atob('Y29uc29sZS5sb2coMSk='))\"", id="eval-wraps-atob"),
    pytest.param("node -e \"const p=atob('Y29k'); child_process.exec(p)\"",
                 id="atob-then-exec"),
    pytest.param("python3 -c \"exec(b64decode('cHJpbnQoMSk='))\"", id="exec-wraps-b64decode"),
]


@pytest.mark.parametrize("payload", OBFUSCATED_PAYLOADS)
def test_obfuscated_exec_detected_in_mcp_launcher(scanner, tmp_path, payload):
    """Every obfuscated shape is caught in an MCP server's launch command."""
    result = scanner.scan_directory(
        _write_mcp(tmp_path, {"command": "sh", "args": ["-c", payload]}))
    assert "AGENT-MCP-008" in _ids(result), \
        f"MCP launcher payload not detected: {payload!r} -> {_ids(result)}"


@pytest.mark.parametrize("payload", OBFUSCATED_PAYLOADS)
def test_hook_and_mcp_launcher_parity(scanner, tmp_path, payload):
    """THE REGRESSION GUARD: the same payload is caught at BOTH auto-exec sites.

    This is the exact evasion that existed — HIGH under a settings hook, ZERO findings
    in an MCP launcher. Moving a payload between auto-exec sites must never change
    whether it is detected.
    """
    hook_dir = tmp_path / "hook"
    mcp_dir = tmp_path / "mcp"
    hook_dir.mkdir()
    mcp_dir.mkdir()

    hook_res = scanner.scan_directory(_write_settings(hook_dir, payload))
    mcp_res = scanner.scan_directory(
        _write_mcp(mcp_dir, {"command": "sh", "args": ["-c", payload]}))

    assert "AGENT-HOOK-002" in _ids(hook_res), f"hook site regressed for {payload!r}"
    assert "AGENT-MCP-008" in _ids(mcp_res), (
        f"EVASION: {payload!r} is HIGH as a settings hook but invisible as an "
        f"MCP launcher -> {_ids(mcp_res)}")


def test_encoded_payload_split_across_args(scanner, tmp_path):
    """The launcher is caught when the flag and blob are SEPARATE argv entries.

    This is the realistic config shape, and the one the raw-JSON text pass misses:
    per-arg quoting (`"powershell.exe", "-EncodedCommand", "…"`) breaks any pattern
    expecting a command line. Joining command+args is what makes it visible.
    """
    result = scanner.scan_directory(_write_mcp(tmp_path, {
        "command": "powershell.exe",
        "args": ["-NoProfile", "-w", "hidden", "-EncodedCommand", "aQBlAHgAKAAnAHgAJwApAA=="],
    }))
    assert "AGENT-MCP-008" in _ids(result)


def test_bare_command_no_args(scanner, tmp_path):
    """A payload written entirely in `command`, with no args list at all."""
    result = scanner.scan_directory(_write_mcp(
        tmp_path, {"command": "powershell -enc aQBlAHgAKAAnAHgAJwApAA=="}))
    assert "AGENT-MCP-008" in _ids(result)


def test_mcp_obfuscated_finding_is_high_and_located(scanner, tmp_path):
    result = scanner.scan_directory(_write_mcp(
        tmp_path, {"command": "pwsh", "args": ["-enc", "aQBlAHgAKAAnAHgAJwApAA=="]}))
    f = next(f for f in result.findings if f.cve_id == "AGENT-MCP-008")
    assert f.severity.name == "HIGH"
    assert f.confidence == "high"
    assert "server:notes" in f.file_path


def test_detected_in_free_tier(tmp_path):
    """The rule is free-tier: the OSS scanner catches it without a Pro license."""
    free = AgentSupplyChainScanner(pro=False)
    result = free.scan_directory(_write_mcp(
        tmp_path, {"command": "powershell", "args": ["-enc", "aQBlAHgAKAAnAHgAJwApAA=="]}))
    assert "AGENT-MCP-008" in _ids(result)
    assert agent_rule_tier("AGENT-MCP-008") == "free"


# --- anti-drift: one shared pattern, two sites --------------------------------

def test_both_sites_share_the_same_compiled_pattern():
    """Neither auto-exec site may keep a narrower copy of the obfuscation pattern.

    Identity, not equality: if someone edits one site's pattern in place, this fails.
    """
    assert MCP_OBFUSCATED_RULE.pattern is _OBFUSCATED_EXEC
    assert HOOK_OBFUSCATED_RULE.pattern is _OBFUSCATED_EXEC
    assert MCP_OBFUSCATED_RULE.pattern is HOOK_OBFUSCATED_RULE.pattern


def test_launch_path_only_scoping_declared():
    """AGENT-MCP-008 asserts auto-execution, so it reads the launch path, not env."""
    assert "AGENT-MCP-008" in _LAUNCH_PATH_ONLY_RULES
    assert "AGENT-MCP-001" in _LAUNCH_PATH_ONLY_RULES


def test_rule_metadata_preserved():
    assert MCP_OBFUSCATED_RULE.severity.name == "HIGH"
    assert MCP_OBFUSCATED_RULE.confidence == "high"
    assert agent_rule_example("AGENT-MCP-008")


# --- zero false positives ------------------------------------------------------
# Real launcher shapes taken from actual MCP configs on this machine. None of these
# may fire: the rule must be free for the ordinary way servers are launched.
BENIGN_LAUNCHERS = [
    pytest.param({"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"]},
                 id="npx-github"),
    pytest.param({"command": "uvx", "args": ["mcp-server-fetch"]}, id="uvx-fetch"),
    pytest.param({"command": "node", "args": ["dist/server.js"]}, id="node-dist"),
    pytest.param({"command": "docker", "args": ["run", "-i", "--rm", "mcp/postgres"]},
                 id="docker-run"),
    pytest.param({"command": "python", "args": ["-m", "my_mcp.server"]}, id="python-module"),
    pytest.param({"command": "bash", "args": ["-c", "cd /srv && ./server"]}, id="bash-c-plain"),
    pytest.param({"command": "powershell", "args": ["-NoProfile", "-File", "server.ps1"]},
                 id="powershell-file-not-encoded"),
    pytest.param({"command": "powershell", "args": ["-ExecutionPolicy", "Bypass",
                                                    "-Command", "./server.ps1"]},
                 id="powershell-command-not-encoded"),
    pytest.param({"command": "deno", "args": ["run", "-A", "./local/server.ts"]}, id="deno-local"),
    pytest.param({"command": "/usr/local/bin/my-server", "args": ["--port", "8080"]},
                 id="absolute-binary"),
]


@pytest.mark.parametrize("cfg", BENIGN_LAUNCHERS)
def test_benign_launcher_no_false_positive(scanner, tmp_path, cfg):
    result = scanner.scan_directory(_write_mcp(tmp_path, cfg))
    assert "AGENT-MCP-008" not in _ids(result), \
        f"FALSE POSITIVE on a real launcher shape: {cfg} -> {_ids(result)}"


def test_powershell_execution_policy_flags_are_not_encoded_commands(scanner, tmp_path):
    """`-ExecutionPolicy` / `-Command` / `-File` must never read as `-enc`.

    The pattern requires the ENCODED form specifically; these are the common benign
    PowerShell flags that a looser `-e` prefix match would swallow.
    """
    result = scanner.scan_directory(_write_mcp(tmp_path, {
        "command": "powershell.exe",
        "args": ["-ExecutionPolicy", "Bypass", "-NoProfile", "-File", "C:\\srv\\run.ps1"],
    }))
    assert "AGENT-MCP-008" not in _ids(result)


def test_base64_blob_in_env_is_data_not_a_command(scanner, tmp_path):
    """THE SCOPING LOCK (the C12 FP class, re-applied).

    An env VALUE is data handed to the server process, not a command line. A server
    that legitimately receives a base64-encoded config blob — or any env var whose
    value merely contains such text — must not read as an encoded launcher.
    """
    result = scanner.scan_directory(_write_mcp(tmp_path, {
        "command": "node",
        "args": ["server.js"],
        "env": {
            "CONFIG_B64": "ZXhhbXBsZSBjb25maWcgdmFsdWU=",
            "DECODE_HINT": "base64 -d | sh",
            "PS_SNIPPET": "FromBase64String",
        },
    }))
    assert "AGENT-MCP-008" not in _ids(result), \
        "env is DATA, not a launch command — matching an exec shape there is a FP"


def test_env_is_still_scanned_by_other_rules(scanner, tmp_path):
    """Launch-path scoping must not blind the rules that SHOULD read env.

    Guards against 'fixing' the FP above by dropping env from the subject entirely.
    """
    result = scanner.scan_directory(_write_mcp(tmp_path, {
        "command": "node",
        "args": ["server.js"],
        "env": {"OPENAI_API_KEY": "sk-proj-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
    }))
    assert "AGENT-SECRET-001" in _ids(result)


def test_benign_settings_hook_no_false_positive(scanner, tmp_path):
    """The shared pattern's new nesting branch must not fire on ordinary hooks."""
    result = scanner.scan_directory(_write_settings(
        tmp_path, "npx prettier --write $CLAUDE_FILE_PATHS"))
    assert "AGENT-HOOK-002" not in _ids(result)
