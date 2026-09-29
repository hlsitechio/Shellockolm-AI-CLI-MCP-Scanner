# 🤖 MCP Server Setup - Use Shellockolm in AI Tools

**Shellockolm MCP Server** lets AI assistants (Claude, Copilot, Codex) scan your code for vulnerabilities directly.

---

## 🎯 What You Get

AI assistants can now:
- ✅ **Vet agent artifacts** (skills, `mcp.json`, n8n workflows, `CLAUDE.md`) for prompt injection, tool poisoning & secret exfiltration **before** you trust them
- ✅ **Scan raw text** in-memory before you paste or install it (no disk I/O)
- ✅ **Scan projects** for 32 tracked CVEs (React/Next/Node/npm) plus malware & secrets
- ✅ **Live probe** URLs for exploitable vulnerabilities
- ✅ **Explain any finding** (an `AGENT-*` rule or a `CVE-*`) with impact & remediation

---

## ⚡ Quick Setup

**Prerequisite:** install the package so the `shellockolm-mcp` command is on your `PATH`:

```bash
pip install -e .          # from a clone of this repo
# or
pipx install shellockolm  # isolated global install
```

Every client below uses the **same** one-paste server block — no clone path, no `PYTHONPATH`:

```json
{
  "mcpServers": {
    "shellockolm": {
      "command": "shellockolm-mcp"
    }
  }
}
```

---

### 1️⃣ For Claude Code

One command — no file editing:

```bash
claude mcp add shellockolm -- shellockolm-mcp                # this project
claude mcp add --scope user shellockolm -- shellockolm-mcp   # all your projects
```

…or commit a `.mcp.json` at the repo root containing the server block above so the whole team
gets it automatically. Verify with `claude mcp list`.

---

### 2️⃣ For Claude Desktop (Anthropic)

1. Open Claude Desktop → **Settings → Developer → Edit Config**.
2. Paste the server block into the config file:
   - **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
   - **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Restart Claude Desktop.

A ready-to-copy `claude_desktop_config_EXAMPLE.json` ships in the repo root.

---

### 3️⃣ For Cursor IDE

Add the server block to **`~/.cursor/mcp.json`** (global) or **`.cursor/mcp.json`** (this project),
then enable **shellockolm** under **Settings → MCP**.

**Usage:**
```
# In Cursor chat
@shellockolm scan this directory for CVEs
@shellockolm scan this SKILL.md before I install it
@shellockolm explain AGENT-PI-013
```

---

### 4️⃣ For Windsurf

Add the server block to **`~/.codeium/windsurf/mcp_config.json`** (or **Settings → Cascade → Add
Server** → paste), then hit the refresh button so Cascade picks up the new server.

---

### 5️⃣ For Any MCP-Compatible Client

**Generic stdio configuration** (after `pip install`):
```json
{
  "command": "shellockolm-mcp",
  "args": []
}
```

**Without a global install** — point at the server script directly:
```json
{
  "command": "python",
  "args": ["/absolute/path/to/Shellockolm-Scanner/src/mcp_server.py"]
}
```

---

## 🧪 Test Your Setup

The MCP server speaks JSON-RPC over **stdio** — launched directly it stays silent and waits for a
client, so there is no banner to look for. Confirm the install with the bundled self-check instead:

```bash
shellockolm doctor   # verifies Python, the CVE database, the rule catalog, git, and license
```

**Claude Code:** `claude mcp list` should show `shellockolm` connected.

### Inspect interactively (optional)
```bash
npx @modelcontextprotocol/inspector shellockolm-mcp
```

---

## 🛠️ Available MCP Tools

The server exposes **12 tools**. Run `shellockolm rules list` / `list_cves` for the full catalogs.

### Agent supply-chain (the differentiator)

#### **scan_agent_artifacts**
Scan a path of agent artifacts (skills, `mcp.json`, n8n exports, `CLAUDE.md`/`AGENTS.md`,
`.claude/` hooks & commands) for prompt injection, tool poisoning, and secret exfiltration.

```
Use shellockolm to scan ./my-skill before I install it
```

**Parameters:** `path` (required), `recursive`, `max_depth`, `min_confidence` (low|medium|high), `quick_mode`

#### **scan_text**
Scan a **raw artifact string in-memory** — no disk I/O — for content you're about to paste/install.

**Parameters:** `text` (required), `artifact_type` (auto|skill|instructions|command|mcp|n8n|settings), `min_confidence`, `filename`

#### **explain_finding**
Explain any finding — an `AGENT-*` rule **or** a tracked `CVE-*` — with severity, impact, an
example attack, and remediation.

**Parameters:** `finding_id` (required)

#### **check_mcp_config**
Audit the agent's **own** installed MCP configs — the well-known per-OS locations (Claude Desktop,
Claude Code's `~/.claude.json`, Cursor, Windsurf, VS Code; plus this project's `.mcp.json` /
`.cursor/mcp.json` / `.vscode/mcp.json`) — for a poisoned server entry (raw-URL/IP launcher, a host
credential forwarded to an unrelated server, `curl|bash`). Read-only; secrets are redacted.

```
Use shellockolm to check my MCP config for tampering
```

**Parameters:** `path` (project root, optional), `include_user`, `include_project`, `min_confidence`

### CVEs, malware & secrets

#### **scan_directory**
Deep scan of a directory for tracked CVEs, malware, secrets, **and** agent rules.
**Parameters:** `path` (required), `recursive`, `scanner` (react, nextjs, npm, …).

#### **quick_scan**
Fast CVE scan of `package.json` only. **Parameters:** `path` (required).

#### **find_packages**
Fast (~0.1s) discovery of npm packages in a tree. **Parameters:** `path` (required).

#### **scan_live**
Probe a live URL for exploitable vulnerabilities (Next.js, n8n).
**Parameters:** `url` (required), `scanner` (default `all`), `timeout` (default 10).

#### **get_cve_info**
Details for a specific CVE. **Parameters:** `cve_id` (required).

#### **list_cves**
List the 32 tracked CVEs with filters. **Parameters:** `severity`, `package`, `exploitable` (all optional).

#### **list_scanners**
List the available vulnerability scanners and their CVE coverage.

#### **generate_report**
Generate a comprehensive JSON vulnerability report. **Parameters:** `path` (required).

---

## 🔧 Troubleshooting

### MCP Server Won't Start

**Check Python path:**
```bash
which python  # Should show Python 3.10+
python --version
```

**Check dependencies:**
```bash
pip install -r requirements.txt
```

**Test imports:**
```bash
cd /path/to/shellockolm
python -c "import sys; sys.path.insert(0, 'src'); from mcp_server import server; print('OK')"
```

### AI Tool Can't Find Server

**Verify config path:**
- Claude Desktop: `%APPDATA%\Claude\claude_desktop_config.json` (Windows)
- Claude Desktop: `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS)
- Confirm `shellockolm-mcp` runs from a normal shell (`pip install -e .` if the command isn't found)

**Check logs:**
- Claude Desktop: Help → Show Logs
- Look for MCP connection errors

### Tools Don't Respond

**Test with MCP Inspector:**
```bash
npx @modelcontextprotocol/inspector shellockolm-mcp
# Try calling scan_directory from the inspector
```

**Enable debug logging:**
```bash
export SHELLOCKOLM_LOG_LEVEL=DEBUG
python src/mcp_server.py
```

---

## 📚 Examples

### Example 1: Scan a React Project
**Prompt to AI:**
```
Use shellockolm to scan my React project at ~/code/my-app
```

**AI Response:**
```
Scanning ~/code/my-app...

Found 3 vulnerabilities:
- CVE-2025-55182 (CRITICAL): React Server Components RCE
- CVE-2025-55130 (HIGH): Node.js permission bypass
- CLAWDBOT-PLAINTEXT-CREDS (HIGH): Exposed API tokens

Would you like me to fix these?
```

### Example 2: Check a Specific CVE
**Prompt:**
```
What is CVE-2025-55182 and am I affected?
```

**AI Response:**
```
CVE-2025-55182: React Server Components Remote Code Execution
- CVSS: 10.0 (CRITICAL)
- Affects: React 19.0.0, 19.1.0, 19.1.1, 19.2.0
- Fix: Upgrade to React 19.3.0+

Checking your project... [scans automatically]
✅ Not vulnerable - you're using React 18.2.0
```

### Example 3: Live Probe a URL
**Prompt:**
```
Is my Next.js app vulnerable? https://myapp.vercel.app
```

**AI Response:**
```
Probing https://myapp.vercel.app...

⚠️ VULNERABLE: Next.js middleware bypass detected
- CVE-2025-55128 (CVSS 9.1)
- Authentication can be bypassed
- Fix: Upgrade Next.js to 15.2.0+
```

---

## 🚀 Advanced Usage

### Custom Scan Workflows
Create AI workflows that automatically:
1. Scan on every commit
2. Auto-fix low-risk CVEs
3. Create GitHub issues for critical findings
4. Generate security reports

### Integration with CI/CD
Use MCP tools in AI-powered CI/CD:
```
Ask AI: "Scan this PR for security issues using shellockolm"
→ AI uses MCP to scan
→ AI comments on PR with findings
→ AI can auto-fix if you approve
```

---

## 📖 Learn More

- **MCP Protocol:** https://modelcontextprotocol.io
- **Shellockolm Docs:** https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner
- **Report Issues:** https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner/issues

---

**Built with 🔍 by @hlsitechio & AI (Claude + GitHub Copilot)**
