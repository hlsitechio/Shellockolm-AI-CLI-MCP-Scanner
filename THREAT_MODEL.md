# Shellockolm — Agentic Supply-Chain Threat Model

> **This file is auto-generated. Do not edit it by hand.** The threat framing is maintained in `scripts/generate_threat_model.py`; the rule coverage is rendered from the live rule catalog in `src/scanners/agent_supply_chain.py` — the same source of truth behind [`RULES.md`](RULES.md), `shellockolm rules list`, and `rules explain` — so the coverage claims here can never drift from the rules that ship. Regenerate with `python scripts/generate_threat_model.py`.

AI coding agents now **auto-load and trust** a chain of artifacts they did not author: skills, MCP servers, instruction files, lifecycle hooks, slash commands, and workflow exports — pulled from marketplaces, repositories, and teammates. Each is read by the model (or executed on your machine) with the agent's full privileges. A single poisoned artifact turns that trust into prompt-injection, secret exfiltration, tool poisoning, or remote code execution. **This is the agentic supply chain, and it is the attack surface Shellockolm defends.**

Shellockolm ships **41 agent supply-chain rules** (**38 free**, always-on MIT/OSS, and **3 Pro**) across **10 attack classes**. This page maps each class to the rules that cover it; [`RULES.md`](RULES.md) has every rule's full description, example attack, and remediation.

## The trust boundary

Every artifact below is consumed by the agent **before** you review its effects. That is the boundary an attacker targets.

| Artifact | What the agent does with it | Why it is a trust boundary |
|----------|-----------------------------|----------------------------|
| Agent skills — `SKILL.md` | Loaded into the model's context as trusted instructions when the skill is invoked; its prose can direct the agent's tool calls. | Pulled from marketplaces, repos, or teammates and run with the agent's full tool access. |
| MCP server configs — `mcp.json`, `.mcp.json`, `claude_desktop_config.json`, `~/.claude.json`, Cursor/Windsurf/VS Code | Define the external tools/servers the agent launches and trusts; a server's command runs on your machine with your privileges. | A single config line decides what code starts on your host and which credentials it receives. |
| AI instruction files — `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`, Copilot instructions | Auto-loaded as standing context every session, shaping the agent's behavior before you type anything. | Persistent, ambient influence — a poisoned line is re-read on every run. |
| `.claude/` settings hooks — `settings.json` / `settings.local.json` | Shell commands the agent auto-runs on lifecycle events with **no per-invocation prompt**. | Zero-click execution: cloning a repo is enough to run them. |
| `.claude/commands/` slash commands — `*.md` | A command body becomes a prompt the agent executes on demand. | Shipped in a repo and trusted like first-party prompts. |
| n8n workflow exports — `*.json` | Automation graphs that read stored credentials and call external services. | A poisoned node pairs a credential read with an attacker-controlled destination. |

## What the attacker wants

- **Hijack the agent's behavior** — override its instructions or smuggle new ones into a trusted artifact (prompt injection).
- **Steal secrets and context** — exfiltrate API keys, tokens, SSH keys, or the conversation itself to an attacker host (data exfiltration, hardcoded secrets).
- **Poison or over-privilege tooling** — register a malicious MCP server or forward broad host credentials to one (mcp-config).
- **Execute code on your machine** — auto-running hooks, `curl | bash` launchers, or code fetched from a raw URL at launch (settings-hook, mcp-config).
- **Destroy data or repositories** — a single skill step that runs a destructive or history-rewriting command (destructive-command).
- **Evade human review** — hide the payload with encoding, invisible characters, or look-alike scripts so a reviewer's eyes miss it (obfuscation, prompt-injection).
- **Exfiltrate through automation** — pair a credential-bearing node with an out-of-band sink in a workflow you import (n8n-workflow).

## Coverage at a glance

Which rules cover which attack class, generated from the live catalog:

| Attack class | Rules | Free | Pro | Severities |
|--------------|-------|------|-----|------------|
| [prompt-injection](#prompt-injection) | 17 | 17 | 0 | CRITICAL, HIGH, MEDIUM |
| [advanced-injection](#advanced-injection) | 3 | 0 | 3 | CRITICAL, HIGH |
| [obfuscation](#obfuscation) | 2 | 2 | 0 | HIGH, LOW |
| [data-exfiltration](#data-exfiltration) | 3 | 3 | 0 | CRITICAL, HIGH |
| [hardcoded-secret](#hardcoded-secret) | 2 | 2 | 0 | HIGH |
| [destructive-command](#destructive-command) | 1 | 1 | 0 | HIGH |
| [settings-hook](#settings-hook) | 3 | 3 | 0 | CRITICAL, HIGH |
| [permission-bypass](#permission-bypass) | 1 | 1 | 0 | MEDIUM |
| [mcp-config](#mcp-config) | 7 | 7 | 0 | CRITICAL, HIGH, MEDIUM |
| [n8n-workflow](#n8n-workflow) | 2 | 2 | 0 | HIGH |

## Threats and the rules that cover them

### prompt-injection

**Instruction hijacking inside a model-facing artifact.**

_Threat._ A skill, instruction file, or slash command carries text crafted to override the agent's instructions or covertly redirect its actions — an authority-claiming override, a "don't tell the user" directive, forged tool-output or chat-template framing, invisible/Unicode-smuggled characters, homoglyph spoofing, hidden HTML comments, or a staged payload that points the agent at a companion file to obey.

_Impact._ The agent does the attacker's bidding while appearing to follow the user — the root agentic-supply-chain risk every other class builds on.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-PI-001`](RULES.md#agent-pi-001) | HIGH | free | medium | Instruction override / jailbreak phrasing |
| [`AGENT-PI-002`](RULES.md#agent-pi-002) | HIGH | free | low | Hidden conditional trigger |
| [`AGENT-PI-003`](RULES.md#agent-pi-003) | CRITICAL | free | high | Secret-exfiltration instruction |
| [`AGENT-PI-004`](RULES.md#agent-pi-004) | HIGH | free | high | Imperative to read credential files |
| [`AGENT-PI-005`](RULES.md#agent-pi-005) | MEDIUM | free | high | Hidden / invisible characters in instructions |
| [`AGENT-PI-006`](RULES.md#agent-pi-006) | HIGH | free | medium | Covert / secretive action instruction |
| [`AGENT-PI-007`](RULES.md#agent-pi-007) | HIGH | free | high | ASCII smuggling via Unicode Tags block |
| [`AGENT-PI-008`](RULES.md#agent-pi-008) | HIGH | free | high | Embedded directive block (MCP tool poisoning) |
| [`AGENT-PI-009`](RULES.md#agent-pi-009) | HIGH | free | high | Forged chat-template control token / role-boundary spoof |
| [`AGENT-PI-010`](RULES.md#agent-pi-010) | HIGH | free | high | Bidirectional text override (Trojan Source) character |
| [`AGENT-PI-011`](RULES.md#agent-pi-011) | HIGH | free | high | Homoglyph / mixed-script confusable spoofing |
| [`AGENT-PI-012`](RULES.md#agent-pi-012) | HIGH | free | high | Markdown link text / href domain mismatch |
| [`AGENT-PI-013`](RULES.md#agent-pi-013) | HIGH | free | high | Imperative instructions hidden in an HTML comment |
| [`AGENT-PI-014`](RULES.md#agent-pi-014) | HIGH | free | high | Permission/safety-bypass flag in skill frontmatter |
| [`AGENT-PI-015`](RULES.md#agent-pi-015) | HIGH | free | high | Memory / persistence poisoning (self-propagating instruction) |
| [`AGENT-PI-016`](RULES.md#agent-pi-016) | HIGH | free | high | Cross-file staged payload (instruction-following indirection) |
| [`AGENT-PI-017`](RULES.md#agent-pi-017) | HIGH | free | high | Spoofed harness tool-output / system-reminder marker |

### advanced-injection

**Higher-sophistication injection (Pro).**

_Threat._ Multi-step injection patterns that a quick keyword scan misses: fetch-then-follow (pull a remote instruction and obey it), tool shadowing (redefine a trusted tool's behavior), and full conversation/context exfiltration.

_Impact._ The advanced detections in the Shellockolm **Pro** tier; additive to the always-free rules — the free tier loses none of its coverage.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-PRO-001`](RULES.md#agent-pro-001) | HIGH | Pro | medium | Indirect prompt injection via fetched content |
| [`AGENT-PRO-002`](RULES.md#agent-pro-002) | HIGH | Pro | medium | Tool / skill shadowing or redefinition |
| [`AGENT-PRO-003`](RULES.md#agent-pro-003) | CRITICAL | Pro | high | Conversation / context exfiltration |

### obfuscation

**Payload hidden from review.**

_Threat._ The malicious content is encoded, base64-wrapped, or otherwise obfuscated so a human reviewer (and a naive keyword filter) reads noise while the model decodes intent.

_Impact._ Defeats eyeball review; commonly the wrapper around an exfil or execution payload.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-OBF-001`](RULES.md#agent-obf-001) | HIGH | free | high | Obfuscated payload (base64 decode then execute) |
| [`AGENT-OBF-002`](RULES.md#agent-obf-002) | LOW | free | high | Large base64 blob embedded in artifact |

### data-exfiltration

**Secrets and context shipped to an attacker.**

_Threat._ An artifact instructs the agent to pipe a credential or environment to an attacker host — `curl`-ing a secret out, smuggling a token in an outbound URL or markdown image the agent auto-fetches, or posting the environment to a request-capture / paste sink.

_Impact._ Direct loss of API keys, tokens, and private context the agent can read.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-EXFIL-001`](RULES.md#agent-exfil-001) | CRITICAL | free | medium | Credential value piped to a network sink |
| [`AGENT-EXFIL-002`](RULES.md#agent-exfil-002) | CRITICAL | free | high | Secret referenced in an outbound URL / markdown image |
| [`AGENT-EXFIL-003`](RULES.md#agent-exfil-003) | HIGH | free | high | Exfiltration to a paste / webhook / out-of-band service |

### hardcoded-secret

**A live credential embedded in a shared artifact.**

_Threat._ A real, structurally-valid credential (AWS, GitHub, Slack, OpenAI, Stripe, an RLS-bypassing Supabase service-role key, …) is committed into a skill, instruction file, or MCP config that gets shared.

_Impact._ Immediate credential leak; every matched secret is redacted in Shellockolm's own output so reports never re-emit it.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-SECRET-001`](RULES.md#agent-secret-001) | HIGH | free | high | Hardcoded credential in agent artifact |
| [`AGENT-SECRET-002`](RULES.md#agent-secret-002) | HIGH | free | high | Hardcoded high-value credential in agent artifact |

### destructive-command

**Auto-run destructive action.**

_Threat._ A skill step the agent will execute runs an irreversibly destructive or history-rewriting command — `rm -rf`, a force-push over `main`, a table drop — framed as routine cleanup.

_Impact._ Data or repository loss from a single skill invocation.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-DESTRUCT-001`](RULES.md#agent-destruct-001) | HIGH | free | medium | Destructive shell command in agent artifact |

### settings-hook

**Zero-click execution via lifecycle hooks.**

_Threat._ A `.claude/` settings hook auto-runs a shell command on a lifecycle event with no prompt: download-and-execute cradles (`curl|bash`, PowerShell `DownloadString`+`iex`, LOLBINs), obfuscated/encoded execution, or out-of-band exfil.

_Impact._ Cloning a repo is enough to get code execution — no skill invocation required.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-HOOK-001`](RULES.md#agent-hook-001) | CRITICAL | free | high | Claude Code auto-run settings command downloads and executes remote code |
| [`AGENT-HOOK-002`](RULES.md#agent-hook-002) | HIGH | free | high | Claude Code auto-run settings command runs an obfuscated / encoded payload |
| [`AGENT-HOOK-003`](RULES.md#agent-hook-003) | HIGH | free | high | Claude Code auto-run settings command exfiltrates to an out-of-band sink |

### permission-bypass

**The confirmation prompt turned off in shared config.**

_Threat._ A committed `.claude/settings.json` removes the per-call human confirmation for tool use — a `bypassPermissions` default mode, or a blanket `allow` entry for a command-execution tool (a bare `Bash` matches every command). A scoped allow-list is the feature working as intended and is not a finding.

_Impact._ Cloning the repo silently opts you into unattended execution: the guardrail that would have caught an injected instruction is gone, and it compounds any lifecycle hook into a zero-click compromise.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-PERM-001`](RULES.md#agent-perm-001) | MEDIUM | free | high | Claude Code settings disable the tool-call confirmation prompt |

### mcp-config

**Malicious or over-privileged MCP server.**

_Threat._ An MCP server definition that runs attacker code or over-shares credentials: a `curl | bash` launcher, an unpinned remote package, code fetched from a raw-code/paste URL or a public IP at launch, or a broad host credential forwarded to a server unrelated to that service.

_Impact._ RCE on your host and/or credential theft the moment the agent starts the server.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-MCP-001`](RULES.md#agent-mcp-001) | CRITICAL | free | high | MCP server fetches and runs a remote script |
| [`AGENT-MCP-002`](RULES.md#agent-mcp-002) | MEDIUM | free | medium | MCP server runs an unpinned remote package |
| [`AGENT-MCP-003`](RULES.md#agent-mcp-003) | HIGH | free | medium | Dangerous execution primitive in MCP config |
| [`AGENT-MCP-004`](RULES.md#agent-mcp-004) | HIGH | free | high | Broad host credential forwarded to an unrelated MCP server |
| [`AGENT-MCP-005`](RULES.md#agent-mcp-005) | HIGH | free | high | MCP server launches code from a raw URL / gist / paste / IP literal |
| [`AGENT-MCP-006`](RULES.md#agent-mcp-006) | MEDIUM | free | high | Remote MCP server uses cleartext http:// transport |
| [`AGENT-MCP-007`](RULES.md#agent-mcp-007) | MEDIUM | free | high | MCP server blanket-auto-approves every tool call |

### n8n-workflow

**Exfiltration through an imported automation.**

_Threat._ An exported n8n workflow pairs a credential read (a node's credential binding or a secret reference) with a POST to an out-of-band / request-capture sink, or direct-embeds a high-entropy key bound for a routable external host.

_Impact._ Credentials leave the moment you run the imported workflow.

| Rule | Severity | Tier | Confidence | What it catches |
|------|----------|------|------------|-----------------|
| [`AGENT-N8N-001`](RULES.md#agent-n8n-001) | HIGH | free | high | n8n Code/Function node runs shell or eval |
| [`AGENT-N8N-002`](RULES.md#agent-n8n-002) | HIGH | free | high | n8n workflow pairs a credential read with an external exfil sink |

## Scope and honest limitations

Shellockolm is a **static detector of known malicious shapes** in agent artifacts. To keep the marketing claims honest, here is exactly what that does and does not mean:

- **It reads artifacts; it does not execute them.** Detection is from the content the way the model would see it — no sandboxing and no runtime monitoring of a running agent.
- **A clean scan is not a safety guarantee.** It means none of the catalog's rule shapes matched — not that an artifact is benign. A novel attack shape is out of scope until a rule ships for it.
- **Natural-language heuristics are confidence-graded.** Phrasing-based rules carry a `medium`/`low` confidence; the structural / signature / decoded-secret rules are `high`. `--min-confidence high` keeps only the deterministic matches for a low-noise CI gate.
- **Pro is strictly additive.** The free, MIT-licensed rules are always on and never gated; the Pro tier only *adds* the advanced-injection detections — it never removes or weakens a free finding.
- **The rule catalog is the contract.** Coverage equals the rules listed above and in [`RULES.md`](RULES.md); both are generated from the same catalog the scanner runs, so this document cannot over-claim what the tool detects.

---

Generated by `scripts/generate_threat_model.py` from the live rule catalog. For each rule's full description, example attack, and remediation see [`RULES.md`](RULES.md); for the machine-readable catalog run `shellockolm rules list --json`.
