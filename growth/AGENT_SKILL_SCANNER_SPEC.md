# Spec: Agent Supply-Chain Scanner (the moat play)

> Draft spec for the highest-upside OSS pivot: scanning the **AI-agent supply chain**.
> This is the niche with a real first-mover moat and a proven exit (Snyk acquired
> mcp-scan / Invariant Labs in 2025). Shellockolm already has an MCP server, so the
> agent surface is half-built.

## Why this, why now
- New, thin, contested space. Snyk's "ToxicSkills" research found prompt injection in
  **36%** of tested agent skills; publishing a skill needs only a `SKILL.md` and a
  week-old GitHub account — no signing, no review, no sandbox.
- The same threat model spans three artifacts the big SCA players don't yet cover well:
  **MCP server configs**, **Claude/agent `SKILL.md` files**, and **n8n workflows**.
  All three are "untrusted instructions + ambient credentials + auto-execution."
- Owning "scan my whole agentic stack" is defensible while incumbents bolt AI scanning
  onto legacy dependency scanners.

## MVP scope (ship small, ship free)
A new subcommand: `shellockolm agent-scan <path>` that scans:

1. **Agent skills** — `SKILL.md` / skill bundles (Claude Code, Cursor, Windsurf, OpenClaw formats)
2. **MCP configs** — `mcp.json`, `.mcp/`, client config blocks
3. **n8n workflows** — exported workflow JSON

Output: same report/SARIF pipeline Shellockolm already has.

## Detection rules (v1)

### Prompt-injection / hidden-trigger
- Hidden or conditional instructions: "when the user opens any URL…", "ignore previous
  instructions", "before responding, …", instructions inside HTML comments / zero-width
  chars / base64 blobs in a skill body
- Tool descriptions that instruct the agent to take actions unrelated to the tool's name
  (tool poisoning)

### Secret exfiltration
- Instructions to read env vars / credential files and send them out:
  `$ANTHROPIC_API_KEY`, `$OPENAI_API_KEY`, `~/.aws/credentials`, `.env`, then a network
  sink (`curl`, `fetch`, webhook URL, image markdown with a query string)
- Reuse Shellockolm's existing 50 secret patterns to flag hardcoded creds in the artifact itself

### Tool poisoning / rug-pull (MCP)
- Tool/skill definition that changed after install (pin + hash tool descriptions; flag drift)
- Tool shadowing (a new tool redefining a trusted tool's behavior)
- Cross-origin escalation (a tool referencing another server's auth/scope)

### n8n-specific
- Risky `Code` nodes (raw JS/Python eval), sandbox-escape patterns
- Hardcoded credentials in workflow JSON
- Dangerous `Merge` node SQL mode; version pin to a vulnerable n8n release
  (you already track CVE-2026-21858 / Ni8mare)

## Implementation notes
- Lives in `src/scanners/agent_supply_chain.py`, extends `BaseScanner` like the others
- Reuse: secret patterns, SARIF output, report builder, severity exit codes
- Keep it 100% offline + pattern-based at first (consistent with the tool's stance);
  add hashing/pinning for rug-pull detection in v2
- Add an MCP tool wrapper so an agent can scan a skill **before installing it**

## Positioning
"Scan your Claude skills + MCP servers + n8n workflows for prompt injection, secret
exfiltration, and tool poisoning — before you install them." Keep it free and
well-maintained: in this niche, stars and mindshare ARE the asset that triggers an
acquisition.
