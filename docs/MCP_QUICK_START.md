# 🎯 Quick Start - Using Shellockolm in AI Tools

**Get security scanning INSIDE your AI assistant in 60 seconds.**

---

## ⚠️ IMPORTANT: Two Different Claude Products

**Claude Desktop** (GUI app) and **Claude Code CLI** (terminal) are **separate products** with **different configs**.

| Product | Type | Config File |
|---------|------|-------------|
| **Claude Desktop** | GUI app | `%APPDATA%\Claude\claude_desktop_config.json` |
| **Claude Code CLI** | Terminal | `~/.claude.json` or `C:\Users\[user]\.claude.json` |

**Make sure you configure the right one!**

---

## ⚡ One-Command Setup

```bash
cd /path/to/shellockolm
python src/configure_mcp.py
```

**What it does:**
1. Detects your installed AI tools (Claude Desktop, Claude Code CLI, Copilot, Cursor, etc.)
2. Automatically writes config files
3. That's it!

---

## 🟣 Claude Desktop (GUI App)

### Setup
```bash
python src/configure_mcp.py
# Select: [1] Claude Desktop
```

**Config location:**
- Windows: `%APPDATA%\Claude\claude_desktop_config.json`
- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`

### Restart Claude Desktop
1. **Close** Claude Desktop completely
2. **Wait** 5 seconds  
3. **Reopen** Claude Desktop

### Test It
Open Claude Desktop and ask:
```
"What MCP tools do you have?"
```

You should see `shellockolm` listed with 6 tools.

### Example Usage
```
You: "Scan this project for vulnerabilities"

Claude: "I'll scan this directory using shellockolm..."
[Uses scan_directory tool automatically]

Claude: "Found 3 vulnerabilities:
- CVE-2025-55182 (CRITICAL) in React 19.0.0
- CVE-2025-55130 (HIGH) in Node.js
- Exposed API key in .env file

Would you like me to help fix these?"
```

**More examples:**
- *"Check if I'm vulnerable to CVE-2025-55182"*
- *"Scan G:\myproject for React CVEs"*
- *"Is https://myapp.com hackable?"*
- *"Generate a security report"*

---

## 💻 Claude Code CLI (Terminal Tool)

### ⚠️ Different Config File!

**Claude Code CLI uses:** `~/.claude.json` (or `C:\Users\[user]\.claude.json` on Windows)

This is **NOT** the same as Claude Desktop!

### Setup

**Option 1: Automatic**
```bash
python src/configure_mcp.py
# Select: Claude Code CLI
```

**Option 2: Manual**

1. **Find your project in the config:**
   ```bash
   # Windows
   notepad C:\Users\[USERNAME]\.claude.json
   
   # macOS/Linux
   nano ~/.claude.json
   ```

2. **Find your project's `mcpServers` section:**
   ```json
   "projects": {
     "C:/Users/hlaro": {
       "mcpServers": {
         "memory-sync": { ... }
       }
     }
   }
   ```

3. **Add shellockolm** (note the `"type": "stdio"`):
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

4. **Save and restart Claude Code CLI**

### Verify It Works

1. **Start Claude Code CLI:**
   ```bash
   claude
   ```

2. **Check MCP servers:**
   - Look for the MCP menu
   - Should see `shellockolm` listed
   - Status should be ✔ connected

3. **Test it:**
   ```bash
   # In Claude Code CLI chat:
   "Use shellockolm to scan this directory for vulnerabilities"
   "List available scanners"
   "What CVEs does shellockolm track?"
   ```

### Example Session
```bash
$ claude

❯ Use shellockolm to scan G:\ for vulnerabilities

● I'll scan your G:\ drive for vulnerabilities using shellockolm.

  shellockolm - scan_directory (MCP)
  ├─ path: "G:\\"
  └─ recursive: true

[Scan runs automatically]

● Found 5 vulnerabilities:
  - CVE-2025-55182 (CRITICAL) - React Server Components RCE
  - CVE-2025-55130 (HIGH) - Node.js permission bypass
  - CLAWDBOT-CREDS (HIGH) - Exposed API tokens
  ...

Would you like me to explain how to fix these?
```

---

## 💚 GitHub Copilot CLI

### Setup
```bash
# Install Copilot CLI if needed
gh extension install github/gh-copilot

# Configure MCP
python src/configure_mcp.py
# Select: [2] GitHub Copilot CLI
```

**Manual config (if auto-config fails):**
Edit `~/.config/github-copilot/mcp.json`:
```json
{
  "servers": {
    "shellockolm": {
      "command": "python",
      "args": ["src/mcp_server.py"],
      "cwd": "/absolute/path/to/shellockolm",
      "env": {
        "PYTHONPATH": "/absolute/path/to/shellockolm/src"
      }
    }
  }
}
```

### Usage
```bash
# Suggest mode
gh copilot suggest "scan this directory for CVEs"

# Chat mode
gh copilot chat
> Use shellockolm to scan for vulnerabilities
> What React CVEs are tracked?
> Check if my Next.js app is vulnerable
```

### Verify
```bash
gh copilot chat
> What tools can you use?
# Should list shellockolm
```

---

## 🔵 Gemini CLI

### Setup
```bash
# Install Gemini CLI
npm install -g @google/generative-ai-cli

# Configure
mkdir -p ~/.gemini
cat > ~/.gemini/mcp-config.json << 'EOF'
{
  "mcpServers": {
    "shellockolm": {
      "command": "python",
      "args": ["src/mcp_server.py"],
      "cwd": "/absolute/path/to/shellockolm",
      "env": {
        "PYTHONPATH": "/absolute/path/to/shellockolm/src"
      }
    }
  }
}
EOF
```

### Usage
```bash
gemini chat
> Scan this project for security vulnerabilities
> What CVEs does shellockolm track?
> Check my app for exploits
```

---

## ⚫ Cursor IDE

### Setup (GUI)
1. Open Cursor
2. Press `Cmd/Ctrl + ,` (Settings)
3. Search: **"MCP Servers"**
4. Click **"Add MCP Server"**
5. Fill in:
   ```
   Name: shellockolm
   Command: python
   Args: ["src/mcp_server.py"]
   Working Directory: /absolute/path/to/shellockolm
   ```
6. Click **Save**
7. Restart Cursor

### Usage
```
@shellockolm scan this directory
@shellockolm check CVE-2025-55182
@shellockolm what scanners do you have?
```

---

## 🔧 Continue.dev (VS Code Extension)

### Setup
Edit `~/.continue/config.json`:
```json
{
  "mcpServers": [
    {
      "name": "shellockolm",
      "command": "python",
      "args": ["src/mcp_server.py"],
      "cwd": "/absolute/path/to/shellockolm"
    }
  ]
}
```

Reload VS Code window: `Cmd/Ctrl + Shift + P` → "Reload Window"

### Usage
Same as Cursor - tag with `@shellockolm` or just ask naturally.

---

## 🛠️ What You Can Ask

### Scanning
```
"Scan this project for vulnerabilities"
"Check G:\myproject for CVEs"
"Find security issues in my React app"
"Scan all subdirectories for exploits"
```

### Live Testing
```
"Is https://myapp.com vulnerable?"
"Check if my website is hackable"
"Test myapp.com for Next.js exploits"
"Probe this URL for vulnerabilities"
```

### Information
```
"What is CVE-2025-55182?"
"Show all React CVEs"
"List critical vulnerabilities"
"What CVEs do you track?"
"What scanners are available?"
```

### Reporting
```
"Generate a security report"
"Create JSON report for this directory"
"Show me all findings in detail"
```

---

## ✅ Verify It's Working

### Test Command
In any AI tool:
```
"What MCP tools do you have access to?"
```

**✅ Working:** AI lists `shellockolm` with tools  
**❌ Not Working:** AI says "I don't have access to MCP tools"

### Quick Functional Test
```
"Use shellockolm to list available scanners"
```

**✅ Working:** Returns table with 7 scanners  
**❌ Not Working:** Error or "I can't do that"

---

## 🐛 Troubleshooting

### "MCP server not found"
1. Check config file location
2. Use **absolute paths** (not relative)
3. Restart AI tool completely

### "Python command not found"
Update config to use full Python path:
```json
"command": "/usr/bin/python3"  // macOS/Linux
"command": "C:\\Python312\\python.exe"  // Windows
```

### "Module not found" errors
Check `PYTHONPATH` in config:
```json
"env": {
  "PYTHONPATH": "/absolute/path/to/shellockolm/src"
}
```

### Still not working?
1. Test MCP server manually:
   ```bash
   cd /path/to/shellockolm
   python src/mcp_server.py
   # Should start without errors
   ```

2. Check AI tool logs:
   - Claude Desktop: Help → Show Logs
   - Copilot: `gh copilot --debug`
   - Cursor: View → Output → MCP

3. See full guide: [MCP_SETUP.md](MCP_SETUP.md)

---

## 📚 More Resources

- **[Complete MCP Setup Guide](MCP_SETUP.md)** - All details
- **[README](../README.md)** - Main documentation  
- **[GitHub Issues](https://github.com/hlsitechio/shellockolm/issues)** - Report problems

---

**Built with 🔍 by @hlsitechio & AI (Claude + GitHub Copilot)**
