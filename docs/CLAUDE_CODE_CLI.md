# Claude Code CLI - MCP Setup Guide

**Using Shellockolm inside Claude Code CLI (terminal assistant)**

---

## ⚠️ Important: Claude Code CLI ≠ Claude Desktop

**These are two different products:**

| Product | Type | Config File |
|---------|------|-------------|
| Claude Desktop | GUI App | `%APPDATA%\Claude\claude_desktop_config.json` |
| Claude Code CLI | Terminal | `~/.claude.json` |

**This guide is for Claude Code CLI only.**

---

## 🚀 Quick Setup

### Option 1: Automatic (Recommended)

```bash
cd /path/to/shellockolm
python src/configure_mcp.py
# Select: Claude Code CLI
```

### Option 2: Manual Setup

**1. Find your config file:**
```bash
# Windows
C:\Users\[USERNAME]\.claude.json

# macOS/Linux
~/.claude.json
```

**2. Open it in your editor:**
```bash
# Windows
notepad C:\Users\[USERNAME]\.claude.json

# macOS/Linux
nano ~/.claude.json
```

**3. Find your project's `mcpServers` section:**

The config is organized by project path. Find your current project:

```json
{
  "projects": {
    "C:/Users/yourname": {
      "mcpServers": {
        "memory-sync": { ... }
      }
    }
  }
}
```

**4. Add shellockolm** (note `"type": "stdio"` - this is required!):

```json
"mcpServers": {
  "memory-sync": { ... },
  "shellockolm": {
    "type": "stdio",
    "command": "python",
    "args": ["G:\\shellockholm\\src\\mcp_server.py"],
    "env": {
      "PYTHONPATH": "G:\\shellockholm\\src"
    }
  }
}
```

**Windows users:** Use double backslashes `\\` in paths!

**5. Save the file**

**6. Restart Claude Code CLI:**
```bash
# Exit current session
exit

# Start fresh
claude
```

---

## ✅ Verify It's Working

### 1. Check MCP Servers Menu

```bash
$ claude
# Type /mcp or access MCP menu
```

You should see:
```
Local MCPs (C:\Users\[user]\.claude.json)
memory-sync · ✘ failed
shellockolm · ✔ connected  ← NEW!
```

### 2. Test a Command

```bash
❯ Use shellockolm to list available scanners
```

**Expected response:**
```
● Using shellockolm to list scanners...

  shellockolm - list_scanners (MCP)

7 scanners available:
- react: React Server Components
- nextjs: Next.js vulnerabilities
- npm: npm packages
- nodejs: Node.js runtime
- n8n: n8n automation
- supply-chain: Supply chain attacks
- clawdbot: AI gateway security
```

---

## 🎯 Usage Examples

### Scan a Directory
```bash
❯ Use shellockolm to scan G:\myproject for vulnerabilities
```

**What happens:**
```
● I'll scan G:\myproject using shellockolm...

  shellockolm - scan_directory (MCP)
  ├─ path: "G:\\myproject"
  └─ recursive: true

[Scanning...]

● Found 3 vulnerabilities:
  - CVE-2025-55182 (CRITICAL) - React Server Components RCE
  - CVE-2025-55130 (HIGH) - Node.js permission bypass
  - Exposed API token in .env file

Would you like me to explain how to fix these?
```

---

### Check a Specific CVE
```bash
❯ What is CVE-2025-55182? Am I vulnerable?
```

**Claude Code CLI will:**
1. Use `get_cve_info` to get CVE details
2. Use `scan_directory` to check your project
3. Tell you if you're affected

---

### Live Probe a URL
```bash
❯ Use shellockolm to check if https://myapp.com is vulnerable
```

**What happens:**
```
● I'll probe https://myapp.com using shellockolm...

  shellockolm - scan_live (MCP)
  ├─ url: "https://myapp.com"
  └─ scanner: "all"

⚠️ VULNERABILITY FOUND:
CVE-2025-55128: Next.js Middleware Authentication Bypass
- CVSS: 9.1 (CRITICAL)
- Your Next.js version is vulnerable
```

---

### List All CVEs
```bash
❯ Show me all critical React CVEs
```

**What happens:**
```
● Using shellockolm to list critical React CVEs...

  shellockolm - list_cves (MCP)
  ├─ severity: "critical"
  └─ category: "react"

2 critical React CVEs:
- CVE-2025-55182 (CVSS 10.0) - React RSC RCE
- CVE-2025-55184 (CVSS 9.8) - Client-side XSS
```

---

### Generate Report
```bash
❯ Generate a full security report for this project
```

**What happens:**
```
● Generating comprehensive security report...

  shellockolm - generate_report (MCP)
  ├─ path: "."
  └─ output_path: "security-report.json"

✅ Report generated: security-report.json
Summary:
- 8 findings
- 2 critical
- 4 high
- 2 medium
```

---

## 🔧 Available Commands

Claude Code CLI can use all 6 MCP tools:

| Tool | What It Does | Example |
|------|--------------|---------|
| `scan_directory` | Scan files for CVEs | *"Scan this folder"* |
| `scan_live` | Probe live URLs | *"Check if myapp.com is hackable"* |
| `get_cve_info` | Get CVE details | *"What is CVE-2025-55182?"* |
| `list_cves` | List all CVEs | *"Show critical React CVEs"* |
| `list_scanners` | Show scanners | *"What can you scan for?"* |
| `generate_report` | JSON report | *"Generate security report"* |

---

## 💡 Pro Tips

### 1. Natural Language Works
You don't need to say "use shellockolm" every time:

✅ **Good:**
```
"Scan this project for vulnerabilities"
"Is my React app secure?"
"Check for CVEs in package.json"
```

❌ **Not needed:**
```
"Use shellockolm MCP tool to execute scan_directory on current path"
```

Claude is smart enough to use the right tool!

### 2. Be Specific About Paths
```
✅ "Scan G:\myproject for vulnerabilities"
❌ "Scan my project" (which one?)
```

### 3. Ask Follow-Up Questions
```
You: "Scan this directory"
Claude: [Shows 5 vulnerabilities]
You: "How do I fix the critical one?"
Claude: [Explains CVE-2025-55182 remediation]
```

### 4. Chain Commands
```
"Scan G:\myproject, then show only critical issues, then explain how to fix them"
```

---

## 🐛 Troubleshooting

### "shellockolm not found in MCP servers"

**Fix:**
1. Check config file has shellockolm entry
2. Verify path to `mcp_server.py` is correct (use absolute path)
3. Restart Claude Code CLI completely
4. Check `type: "stdio"` is set (required for local servers)

### "Server failed to connect"

**Test MCP server manually:**
```bash
cd /path/to/shellockolm
python src/mcp_server.py
# Should start without errors
# Ctrl+C to stop
```

**If errors:**
- Check Python version (need 3.10+)
- Install dependencies: `pip install -r requirements.txt`
- Verify PYTHONPATH in config

### "Permission denied" errors

**Windows:**
```json
"env": {
  "PYTHONPATH": "G:\\shellockholm\\src"
}
```
Use double backslashes!

**macOS/Linux:**
```json
"env": {
  "PYTHONPATH": "/absolute/path/to/shellockholm/src"
}
```
Use absolute paths, not `~`

### Config not loading

**Make sure you edited the right project!**

Your config has multiple projects:
```json
{
  "projects": {
    "C:/Users/hlaro": { ... },      ← This one
    "G:/myproject": { ... },        ← Or this one?
  }
}
```

Add shellockolm to **the project you're working in**.

---

## 📚 More Resources

- **[MCP Quick Start](MCP_QUICK_START.md)** - All AI tools
- **[MCP Examples](MCP_EXAMPLES.md)** - Real conversations
- **[Main README](../README.md)** - Full documentation

---

**Built with 🔍 by @hlsitechio & AI (Claude + GitHub Copilot)**
