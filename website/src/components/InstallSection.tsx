import { Copy, Check, Terminal, Github, Bot } from "lucide-react";
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
        "git clone https://github.com/hlsitechio/shellockolm.git",
        "cd shellockolm",
        "pip install -r requirements.txt"
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
      command: "python src/server.py",
      description: "MCP server for Claude, Cursor, etc.",
    },
  ];

  return (
    <section className="relative py-32 overflow-hidden">
      <div className="absolute inset-0 bg-navy" />
      <div 
        className="absolute inset-0"
        style={{
          backgroundImage: `radial-gradient(ellipse 80% 50% at 20% 80%, hsl(var(--gold) / 0.1), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-6">
        <div className="text-center mb-16">
          <span className="badge-detective mb-6 inline-flex">
            <Terminal className="w-4 h-4" />
            Quick Start
          </span>
          <h2 className="font-display text-4xl md:text-5xl lg:text-6xl font-bold mb-6">
            Start <span className="text-gradient-gold">Investigating</span>
          </h2>
          <p className="text-lg text-muted-foreground max-w-2xl mx-auto">
            Get up and running in under a minute. No complex configuration required.
          </p>
        </div>

        <div className="max-w-4xl mx-auto">
          <div className="mb-12">
            <h3 className="font-display text-xl font-semibold mb-4 flex items-center gap-2">
              <span className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold">1</span>
              Installation
            </h3>
            {installCommands.map((item) => (
              <div key={item.id} className="terminal-window">
                <div className="terminal-header">
                  <div className="terminal-dot bg-danger" />
                  <div className="terminal-dot bg-primary" />
                  <div className="terminal-dot bg-success" />
                  <span className="ml-4 text-sm text-muted-foreground font-mono flex items-center gap-2">
                    <item.icon className="w-4 h-4" />
                    {item.title}
                  </span>
                </div>
                <div className="terminal-body">
                  {item.commands.map((cmd, idx) => (
                    <div key={idx} className="flex items-center justify-between group mb-2 last:mb-0">
                      <code className="text-foreground">
                        <span className="text-muted-foreground">$ </span>{cmd}
                      </code>
                      <button
                        onClick={() => copyToClipboard(cmd, `${item.id}-${idx}`)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity p-1 hover:bg-secondary rounded"
                      >
                        {copied === `${item.id}-${idx}` ? (
                          <Check className="w-4 h-4 text-success" />
                        ) : (
                          <Copy className="w-4 h-4 text-muted-foreground" />
                        )}
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </div>

          <div>
            <h3 className="font-display text-xl font-semibold mb-4 flex items-center gap-2">
              <span className="w-8 h-8 rounded-full bg-primary text-primary-foreground flex items-center justify-center text-sm font-bold">2</span>
              Choose Your Approach
            </h3>
            <div className="grid md:grid-cols-3 gap-4">
              {useCases.map((useCase) => (
                <div key={useCase.id} className="card-noir p-6">
                  <div className="flex items-center gap-3 mb-4">
                    <div className="p-2 rounded-lg bg-primary/10 text-primary">
                      <useCase.icon className="w-5 h-5" />
                    </div>
                    <h4 className="font-semibold text-foreground">{useCase.title}</h4>
                  </div>
                  <p className="text-sm text-muted-foreground mb-4">{useCase.description}</p>
                  <div className="flex items-center justify-between p-3 rounded-lg bg-secondary/50 font-mono text-xs">
                    <code className="text-primary truncate">{useCase.command}</code>
                    <button
                      onClick={() => copyToClipboard(useCase.command, useCase.id)}
                      className="ml-2 p-1 hover:bg-secondary rounded shrink-0"
                    >
                      {copied === useCase.id ? (
                        <Check className="w-3 h-3 text-success" />
                      ) : (
                        <Copy className="w-3 h-3 text-muted-foreground" />
                      )}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div className="mt-12 text-center">
            <Button 
              size="lg"
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-lg font-semibold glow-gold"
              onClick={() => window.open('https://github.com/hlsitechio/shellockolm', '_blank')}
            >
              <Github className="w-5 h-5 mr-2" />
              View on GitHub
            </Button>
          </div>
        </div>
      </div>
    </section>
  );
};

export default InstallSection;
