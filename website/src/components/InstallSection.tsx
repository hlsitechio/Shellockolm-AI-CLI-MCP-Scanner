import { Copy, Check, Terminal, Github, Bot, Plug, AppWindow, MousePointer2, Wind } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/button";

const InstallSection = () => {
  const [copied, setCopied] = useState<string | null>(null);

  const copyToClipboard = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  };

  const installCommands = [
    {
      id: "clone",
      icon: Github,
      title: "Clone & Install",
      commands: [
        "git clone https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner.git",
        "cd Shellockolm-AI-CLI-MCP-Scanner",
        "pip install -e .",
      ],
    },
  ];

  const useCases = [
    {
      id: "local",
      icon: Terminal,
      title: "Local Projects",
      command: "python src/auto_fix.py ~/projects",
      description: "Scan all local projects recursively",
    },
    {
      id: "github",
      icon: Github,
      title: "GitHub Repos",
      command: "python src/github_scanner.py",
      description: "Scan entire GitHub account (no cloning)",
    },
    {
      id: "mcp",
      icon: Bot,
      title: "AI Assistant",
      command: "shellockolm-mcp",
      description: "MCP server for Claude, Cursor, Windsurf",
    },
  ];

  const mcpConfig = `{
  "mcpServers": {
    "shellockolm": {
      "command": "shellockolm-mcp"
    }
  }
}`;

  const mcpClients = [
    {
      id: "claude-code",
      icon: Terminal,
      title: "Claude Code",
      detail: "One command, no file editing:",
      command: "claude mcp add shellockolm -- shellockolm-mcp",
    },
    {
      id: "claude-desktop",
      icon: AppWindow,
      title: "Claude Desktop",
      detail: "Settings → Developer → Edit Config, then paste the block into:",
      command: "%APPDATA%\\Claude\\claude_desktop_config.json",
    },
    {
      id: "cursor",
      icon: MousePointer2,
      title: "Cursor",
      detail: "Paste the block, then enable shellockolm under Settings → MCP:",
      command: "~/.cursor/mcp.json",
    },
    {
      id: "windsurf",
      icon: Wind,
      title: "Windsurf",
      detail: "Paste the block (or Settings → Cascade → Add Server), then refresh:",
      command: "~/.codeium/windsurf/mcp_config.json",
    },
  ];

  return (
    <section aria-label="Installation" className="relative py-28 overflow-hidden">
      <div className="absolute inset-0 bg-navy" aria-hidden="true" />
      <div
        className="absolute inset-0"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 80% 50% at 20% 80%, hsl(var(--gold) / 0.08), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Section header */}
        <div className="text-center mb-16">
          <span className="badge-detective mb-6 inline-flex">
            <Terminal className="w-4 h-4" aria-hidden="true" />
            Quick Start
          </span>
          <h2 className="font-display text-4xl sm:text-5xl lg:text-6xl font-bold mb-6">
            Start{" "}
            <span className="text-gradient-gold">Investigating</span>
          </h2>
          <p className="text-base sm:text-lg text-muted-foreground max-w-xl mx-auto leading-relaxed">
            Get up and running in under a minute. No complex configuration required.
          </p>
        </div>

        <div className="max-w-3xl mx-auto space-y-10">
          {/* Step 1 — Installation */}
          <div>
            <h3 className="font-display text-lg sm:text-xl font-semibold mb-4 flex items-center gap-3">
              <span
                className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold shrink-0"
                aria-hidden="true"
              >
                1
              </span>
              Installation
            </h3>
            {installCommands.map((item) => (
              <div key={item.id} className="terminal-window">
                <div className="terminal-header">
                  <div className="terminal-dot bg-danger" aria-hidden="true" />
                  <div className="terminal-dot bg-gold" aria-hidden="true" />
                  <div className="terminal-dot bg-success" aria-hidden="true" />
                  <span className="ml-4 text-sm text-muted-foreground font-mono flex items-center gap-2">
                    <item.icon className="w-4 h-4" aria-hidden="true" />
                    {item.title}
                  </span>
                </div>
                <div className="terminal-body">
                  {item.commands.map((cmd, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between group mb-2 last:mb-0"
                    >
                      <code className="text-foreground text-sm overflow-x-auto">
                        <span className="text-muted-foreground select-none">$ </span>
                        {cmd}
                      </code>
                      <button
                        onClick={() => copyToClipboard(cmd, `${item.id}-${idx}`)}
                        className="opacity-0 group-hover:opacity-100 focus-visible:opacity-100 transition-opacity p-1.5 hover:bg-secondary rounded ml-3 shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                        aria-label={`Copy command: ${cmd}`}
                      >
                        {copied === `${item.id}-${idx}` ? (
                          <Check className="w-4 h-4 text-success" aria-hidden="true" />
                        ) : (
                          <Copy className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          {/* Step 2 — Choose approach */}
          <div>
            <h3 className="font-display text-lg sm:text-xl font-semibold mb-4 flex items-center gap-3">
              <span
                className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold shrink-0"
                aria-hidden="true"
              >
                2
              </span>
              Choose Your Approach
            </h3>
            <div className="grid sm:grid-cols-3 gap-4">
              {useCases.map((useCase) => (
                <div key={useCase.id} className="card-noir p-5 flex flex-col gap-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 text-primary shrink-0">
                      <useCase.icon className="w-5 h-5" aria-hidden="true" />
                    </div>
                    <h4 className="font-semibold text-foreground text-sm">
                      {useCase.title}
                    </h4>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {useCase.description}
                  </p>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/60 font-mono text-xs mt-auto">
                    <code className="text-primary truncate">{useCase.command}</code>
                    <button
                      onClick={() => copyToClipboard(useCase.command, useCase.id)}
                      className="ml-2 p-1.5 hover:bg-secondary rounded shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-1 focus-visible:ring-offset-secondary"
                      aria-label={`Copy command: ${useCase.command}`}
                    >
                      {copied === useCase.id ? (
                        <Check className="w-3 h-3 text-success" aria-hidden="true" />
                      ) : (
                        <Copy className="w-3 h-3 text-muted-foreground" aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Step 3 — Add to your AI agent (MCP) */}
          <div>
            <h3 className="font-display text-lg sm:text-xl font-semibold mb-4 flex items-center gap-3">
              <span
                className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold shrink-0"
                aria-hidden="true"
              >
                3
              </span>
              Add to Your AI Agent (MCP)
            </h3>
            <p className="text-sm text-muted-foreground mb-4 leading-relaxed">
              After installing, your agent can call all 11 security tools over the{" "}
              <a
                href="https://modelcontextprotocol.io"
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                Model Context Protocol
              </a>
              . Every client below uses the{" "}
              <span className="text-foreground font-medium">same</span> one-paste server block:
            </p>

            {/* One-paste config block */}
            <div className="terminal-window mb-5">
              <div className="terminal-header">
                <div className="terminal-dot bg-danger" aria-hidden="true" />
                <div className="terminal-dot bg-gold" aria-hidden="true" />
                <div className="terminal-dot bg-success" aria-hidden="true" />
                <span className="ml-4 text-sm text-muted-foreground font-mono flex items-center gap-2">
                  <Plug className="w-4 h-4" aria-hidden="true" />
                  mcp config
                </span>
                <button
                  onClick={() => copyToClipboard(mcpConfig, "mcp-config")}
                  className="ml-auto p-1.5 hover:bg-secondary rounded shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary"
                  aria-label="Copy MCP server config"
                >
                  {copied === "mcp-config" ? (
                    <Check className="w-4 h-4 text-success" aria-hidden="true" />
                  ) : (
                    <Copy className="w-4 h-4 text-muted-foreground" aria-hidden="true" />
                  )}
                </button>
              </div>
              <div className="terminal-body">
                <pre className="text-foreground text-xs sm:text-sm overflow-x-auto leading-relaxed">
                  <code>{mcpConfig}</code>
                </pre>
              </div>
            </div>

            {/* Per-client grid */}
            <div className="grid sm:grid-cols-2 gap-4">
              {mcpClients.map((client) => (
                <div key={client.id} className="card-noir p-5 flex flex-col gap-3">
                  <div className="flex items-center gap-3">
                    <div className="p-2 rounded-lg bg-primary/10 text-primary shrink-0">
                      <client.icon className="w-5 h-5" aria-hidden="true" />
                    </div>
                    <h4 className="font-semibold text-foreground text-sm">{client.title}</h4>
                  </div>
                  <p className="text-xs text-muted-foreground leading-relaxed">
                    {client.detail}
                  </p>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/60 font-mono text-xs mt-auto">
                    <code className="text-primary truncate">{client.command}</code>
                    <button
                      onClick={() => copyToClipboard(client.command, client.id)}
                      className="ml-2 p-1.5 hover:bg-secondary rounded shrink-0 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary focus-visible:ring-offset-1 focus-visible:ring-offset-secondary"
                      aria-label={`Copy: ${client.command}`}
                    >
                      {copied === client.id ? (
                        <Check className="w-3 h-3 text-success" aria-hidden="true" />
                      ) : (
                        <Copy className="w-3 h-3 text-muted-foreground" aria-hidden="true" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* CTA */}
          <div className="pt-4 text-center flex flex-col sm:flex-row items-center justify-center gap-4">
            <Button
              size="lg"
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-base font-semibold glow-ultramarine w-full sm:w-auto"
              onClick={() =>
                window.open(
                  "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                  "_blank",
                  "noopener noreferrer"
                )
              }
              aria-label="View Shellockolm source code on GitHub"
            >
              <Github className="w-5 h-5 mr-2" aria-hidden="true" />
              View on GitHub
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="border-border hover:border-primary/50 px-8 py-6 text-base w-full sm:w-auto"
              onClick={() =>
                document.getElementById("services")?.scrollIntoView({ behavior: "smooth" })
              }
              aria-label="See professional services section"
            >
              Need expert help?
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InstallSection;
