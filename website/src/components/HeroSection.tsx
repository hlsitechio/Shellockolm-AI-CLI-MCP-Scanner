import { Shield, Zap, ArrowRight } from "lucide-react";
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
              60+ Commands &nbsp;·&nbsp; Zero Config &nbsp;·&nbsp; 100% Local
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

          {/* Sub-copy */}
          <p className="animate-fade-up-delay-2 text-base sm:text-lg text-muted-foreground max-w-2xl mx-auto mb-10 leading-relaxed">
            Security scanner for <strong className="text-foreground/80 font-medium">React</strong>,{" "}
            <strong className="text-foreground/80 font-medium">Next.js</strong>,{" "}
            <strong className="text-foreground/80 font-medium">Node.js</strong>, and{" "}
            <strong className="text-foreground/80 font-medium">npm</strong> — detects 32 CVEs
            across 7 specialised scanners. Scans, patches, and generates SBOMs without
            leaving your machine.
          </p>

          {/* CTA buttons */}
          <div className="animate-fade-up-delay-3 flex flex-col sm:flex-row gap-4 justify-center">
            <Button
              size="lg"
              className="group relative overflow-hidden bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-base sm:text-lg font-semibold glow-ultramarine animate-glow-pulse"
              onClick={() =>
                window.open(
                  "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                  "_blank",
                  "noopener noreferrer"
                )
              }
              aria-label="Get started — open Shellockolm on GitHub"
            >
              <Shield className="w-5 h-5 mr-2" aria-hidden="true" />
              Get Started Free
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
                document.getElementById("features")?.scrollIntoView({ behavior: "smooth" })
              }
              aria-label="See features section"
            >
              <Zap className="w-5 h-5 mr-2" aria-hidden="true" />
              See Features
            </Button>
          </div>

          {/* Trust strip */}
          <p className="animate-fade-up-delay-3 mt-6 text-xs text-muted-foreground/60">
            Open source · MIT License · No telemetry · Runs entirely on your machine
          </p>
        </div>

        {/* Divider */}
        <div
          className="my-16 lg:my-24 flex items-center justify-center"
          aria-hidden="true"
        >
          <div className="h-px w-full max-w-4xl bg-gradient-to-r from-transparent via-primary/50 to-transparent" />
        </div>

        {/* Terminal demo */}
        <div className="animate-fade-up-delay-3 max-w-3xl mx-auto">
          <p className="text-center text-xs text-muted-foreground/60 font-mono mb-3 uppercase tracking-widest">
            Live example
          </p>
          <div className="terminal-window" role="img" aria-label="Terminal showing Shellockolm scanning and patching vulnerabilities">
            <div className="terminal-header">
              <div className="terminal-dot bg-danger" aria-hidden="true" />
              <div className="terminal-dot bg-gold" aria-hidden="true" />
              <div className="terminal-dot bg-success" aria-hidden="true" />
              <span className="ml-4 text-sm text-muted-foreground font-mono select-none">
                shellockolm — terminal
              </span>
            </div>
            <div className="terminal-body text-left space-y-1">
              <p className="text-muted-foreground">
                <span aria-hidden="true">$ </span>python src/auto_fix.py ~/projects
              </p>
              <p className="text-primary mt-2">
                🔍 Scanning 32 CVEs across 7 scanners…
              </p>
              <p className="text-foreground">
                &nbsp;&nbsp;&nbsp;→ React 19.0.0&nbsp;&nbsp;&nbsp;CVE-2025-55182 (CVSS 10.0)
              </p>
              <p className="text-foreground">
                &nbsp;&nbsp;&nbsp;→ Next.js 15.0.0&nbsp;CVE-2025-66478 (CVSS 10.0)
              </p>
              <p className="text-foreground">
                &nbsp;&nbsp;&nbsp;→ n8n 1.76.1&nbsp;&nbsp;&nbsp;&nbsp;CVE-2026-21858 (Ni8mare RCE)
              </p>
              <p className="text-success mt-2">✓ All vulnerabilities patched. Elementary!</p>
            </div>
          </div>
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
