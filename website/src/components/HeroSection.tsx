import { Shield, ArrowRight, Bot, Eye } from "lucide-react";
import { Button } from "@/components/ui/button";

const HeroSection = () => {
  return (
    <section
      aria-label="Hero"
      className="relative min-h-screen flex items-center overflow-hidden pt-16"
    >
      {/* Background layers */}
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-40"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 80% 50% at 50% -20%, hsl(var(--ultramarine) / 0.2), transparent)`,
        }}
      />
      <div
        className="absolute inset-0 opacity-15"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 40% 30% at 80% 80%, hsl(var(--gold) / 0.3), transparent)`,
        }}
      />
      <div
        className="absolute inset-0 opacity-5"
        aria-hidden="true"
        style={{
          backgroundImage: `linear-gradient(hsl(var(--ultramarine)) 1px, transparent 1px),
                           linear-gradient(90deg, hsl(var(--ultramarine)) 1px, transparent 1px)`,
          backgroundSize: "50px 50px",
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        <div className="max-w-4xl mx-auto text-center">
          {/* Badge */}
          <div className="animate-fade-up-delay-1 mb-8">
            <span className="badge-detective" role="note">
              <Shield className="w-4 h-4" aria-hidden="true" />
              AI-Agent Supply Chain · CVEs · Secrets · 100% Offline
            </span>
          </div>

          {/* Headline */}
          <h1 className="animate-fade-up-delay-1 font-display text-5xl sm:text-6xl lg:text-7xl font-bold mb-5 leading-tight tracking-tight">
            <span className="text-gradient-ultramarine glow-text">Shellockolm</span>
          </h1>

          {/* Tagline */}
          <p className="animate-fade-up-delay-2 font-display text-xl sm:text-2xl text-foreground/90 mb-5 italic">
            "Elementary, my dear developer!"
          </p>

          {/* Sub-copy — specific, no buzzwords */}
          <p className="animate-fade-up-delay-2 text-base sm:text-lg text-muted-foreground max-w-2xl mx-auto mb-4 leading-relaxed">
            Scans the <strong className="text-foreground/80 font-medium">AI-agent coding supply chain</strong> —
            Claude/agent skills, MCP servers, and n8n workflows — for{" "}
            <strong className="text-foreground/80 font-medium">prompt injection</strong>,{" "}
            <strong className="text-foreground/80 font-medium">secret exfiltration</strong>, and{" "}
            <strong className="text-foreground/80 font-medium">tool poisoning</strong>.
            Plus React, Next.js, Node.js, and npm CVEs.
          </p>

          {/* Concrete threat list */}
          <div className="animate-fade-up-delay-2 flex flex-wrap justify-center gap-x-5 gap-y-2 mb-10 text-xs font-mono text-muted-foreground/70">
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" aria-hidden="true" />
              Prompt-injected SKILL.md
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-amber-500 inline-block" aria-hidden="true" />
              curl|bash MCP servers
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" aria-hidden="true" />
              CVE-2025-29927 Next.js auth bypass
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-red-500 inline-block" aria-hidden="true" />
              CVE-2026-21858 n8n Ni8mare RCE
            </span>
          </div>

          {/* CTA buttons */}
          <div className="animate-fade-up-delay-3 flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              size="lg"
              className="group relative overflow-hidden bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-base sm:text-lg font-semibold glow-ultramarine animate-glow-pulse"
              onClick={() =>
                document.getElementById("demo")?.scrollIntoView({ behavior: "smooth" })
              }
              aria-label="See live demo of Shellockolm catching real threats"
            >
              <Eye className="w-5 h-5 mr-2" aria-hidden="true" />
              See It Catch a Threat
              <ArrowRight
                className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-1"
                aria-hidden="true"
              />
            </Button>
            <Button
              size="lg"
              variant="outline"
              className="border-border hover:bg-secondary hover:border-primary/50 px-8 py-6 text-base sm:text-lg"
              onClick={() =>
                window.open(
                  "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                  "_blank",
                  "noopener noreferrer"
                )
              }
              aria-label="Get Shellockolm on GitHub — free and open source"
            >
              <Bot className="w-5 h-5 mr-2" aria-hidden="true" />
              Get It Free
            </Button>
          </div>

          {/* Trust strip */}
          <p className="animate-fade-up-delay-3 mt-6 text-xs text-muted-foreground/60">
            Open source · MIT License · No telemetry · No cloud · Runs entirely on your machine
          </p>
        </div>

        {/* Divider */}
        <div
          className="my-16 lg:my-20 flex items-center justify-center"
          aria-hidden="true"
        >
          <div className="h-px w-full max-w-4xl bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
        </div>

        {/* Hero terminal — quick-scan preview */}
        <div className="animate-fade-up-delay-3 max-w-3xl mx-auto">
          <p className="text-center text-xs text-muted-foreground/60 font-mono mb-3 uppercase tracking-widest">
            What it finds
          </p>
          <div
            className="terminal-window"
            role="img"
            aria-label="Terminal output showing Shellockolm catching a poisoned Claude skill and two CVEs"
          >
            <div className="terminal-header">
              <div className="terminal-dot bg-danger" aria-hidden="true" />
              <div className="terminal-dot bg-gold" aria-hidden="true" />
              <div className="terminal-dot bg-success" aria-hidden="true" />
              <span className="ml-4 text-sm text-muted-foreground font-mono select-none">
                shellockolm — scan output
              </span>
            </div>
            <div className="terminal-body text-left space-y-1.5">
              <p className="text-muted-foreground text-sm">
                <span aria-hidden="true">$ </span>python src/scan.py --mode ai-agent ./skills/
              </p>
              <p className="text-primary text-sm mt-2">
                › Scanning AI-agent supply chain…
              </p>
              <p className="text-red-400 text-sm">
                &nbsp;&nbsp;[CRITICAL] AGENT-PI-003 &nbsp;SKILL.md:3 — Secret-exfiltration instruction
              </p>
              <p className="text-amber-400 text-sm">
                &nbsp;&nbsp;[HIGH]&nbsp;&nbsp;&nbsp;&nbsp; AGENT-PI-001 &nbsp;SKILL.md:2 — Instruction override / jailbreak phrasing
              </p>
              <p className="text-amber-400 text-sm">
                &nbsp;&nbsp;[HIGH]&nbsp;&nbsp;&nbsp;&nbsp; AGENT-MCP-001 mcp.json » server:bad — curl|bash remote execution
              </p>
              <p className="text-red-400 text-sm">
                &nbsp;&nbsp;[CRITICAL] CVE-2025-29927 &nbsp;package.json — Next.js middleware auth bypass (CVSS 9.1)
              </p>
              <p className="text-success text-sm mt-2">✓ Scan complete — 4 findings. Elementary!</p>
            </div>
          </div>
          <p className="text-center text-xs text-muted-foreground/40 font-mono mt-3">
            Interactive demo with expandable explanations ↓
          </p>
        </div>
      </div>

      {/* Bottom fade */}
      <div
        className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-background to-transparent"
        aria-hidden="true"
      />
    </section>
  );
};

export default HeroSection;
