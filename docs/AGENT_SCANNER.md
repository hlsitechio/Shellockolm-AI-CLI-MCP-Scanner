# 🤖 Agent Supply-Chain Scanner — Complete Guide

## Overview

Traditional security scanners check **your dependencies** — the npm packages, runtimes, and
frameworks your app ships. The **Agent Supply-Chain Scanner** checks a different, newer attack
surface: the artifacts that feed **instructions and tools to your AI coding agent**.

In the agentic era, the threat model is **untrusted instructions + ambient credentials +
auto-execution**. When you install a community "skill", wire up an MCP server, or import an n8n
workflow, you are running someone else's instructions inside an agent that already holds your API
keys, your shell, and your repo. A malicious or compromised artifact can quietly tell the agent to
read `~/.aws/credentials` and POST it to a webhook — and you would never see it in a normal diff,
because the payload can be hidden in characters that render as nothing.

This scanner is the **seatbelt you run *before* you install an untrusted skill or server.** It is
100% offline and pattern-based, consistent with the rest of Shellockolm.

> **Free & open source.** The agent scanner is part of the MIT-licensed core — not a paid add-on.

## What it scans

| Artifact | Files matched | Why it's a target |
|----------|---------------|-------------------|
| **Agent skills** | `SKILL.md`, `*.skill.md` | Free-text instructions executed by Claude Code, Cursor, Windsurf, OpenClaw |
| **MCP servers** | `mcp.json`, `*.mcp.json`, `claude_desktop_config.json` | Define commands/servers the agent will launch — a remote-code vector |
| **n8n workflows** | exported workflow `*.json` | Code/Function nodes run `eval`-style logic and often embed credentials |

## What it detects

Pattern-based detections across three buckets:

### Prompt injection & hidden instructions
- `AGENT-PI-001` — Instruction override / jailbreak phrasing
- `AGENT-PI-002` — Hidden conditional trigger ("when the user does X, do Y")
- `AGENT-PI-004` — Imperative to read credential files
- `AGENT-PI-006` — Covert / secretive action instruction
- `AGENT-PI-005` — Hidden / invisible (zero-width) characters in instructions
- `AGENT-PI-007` — **ASCII smuggling via the Unicode Tags block** (renders as nothing, model still reads it)
- `AGENT-PRO-001` — Indirect prompt injection via fetched content
- `AGENT-PRO-002` — Tool / skill shadowing or redefinition

### Secret exfiltration & data theft
- `AGENT-PI-003` — Secret-exfiltration instruction (read a secret, send it somewhere)
- `AGENT-EXFIL-001` — Credential value piped to a network sink
- `AGENT-EXFIL-002` — Secret referenced in an outbound URL / markdown image
- `AGENT-EXFIL-003` — Exfiltration to a paste / webhook / out-of-band service
- `AGENT-PRO-003` — Conversation / context exfiltration
- `AGENT-SECRET-001` — Hardcoded credential in an agent artifact

### Tool poisoning, execution & obfuscation
- `AGENT-MCP-001` — MCP server fetches and runs a remote script
- `AGENT-MCP-002` — MCP server runs an **unpinned remote package** (rug-pull risk)
- `AGENT-MCP-003` — Dangerous execution primitive in an MCP config
- `AGENT-DESTRUCT-001` — Destructive shell command in an agent artifact
- `AGENT-OBF-001` — Obfuscated payload (base64 decode then execute)
- `AGENT-OBF-002` — Large base64 blob embedded in artifact

## Usage

### CLI

```bash
# Vet a single skill file before you install it
python src/cli.py scan -s agent ./some-skill/SKILL.md

# Vet an MCP / Claude Desktop config
python src/cli.py scan -s agent ./claude_desktop_config.json

# Scan a whole directory of skills / workflows
python src/cli.py scan -s agent ./my-skills/
```

The agent scanner also runs automatically as part of a **Full Scan** (`scan` with no `-s`).

### Interactive shell

```
python src/cli.py shell
> 7a       # Agent Supply-Chain Scanner
> ./some-skill/SKILL.md
```

### MCP tool

The agent scanner is reachable through the `scan` MCP tool — pass `scanner: "agent"`. This lets an
AI agent **vet a skill or MCP server mid-session, before installing it**, using the same offline
engine:

```jsonc
{
  "name": "scan",
  "arguments": { "path": "./some-skill/SKILL.md", "scanner": "agent" }
}
```

## Why offline & pattern-based

Like the rest of Shellockolm, this scanner never sends your files anywhere. The artifacts it
inspects frequently *contain* the very secrets and instructions you're worried about — uploading
them to a cloud service would defeat the purpose. Detection is deterministic and explainable: every
finding maps to a rule ID above with a description and remediation.

## See also

- [README — Complete Features](../README.md#-complete-features)
- [MCP Quick Start](MCP_QUICK_START.md)
- Source: [`src/scanners/agent_supply_chain.py`](../src/scanners/agent_supply_chain.py)
