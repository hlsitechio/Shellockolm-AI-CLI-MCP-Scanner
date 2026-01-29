import { Shield, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";

const HeroSection = () => {
  return (
    <section className="relative min-h-screen flex items-center overflow-hidden pt-20">
      <div className="absolute inset-0 bg-gradient-dark" />
      <div 
        className="absolute inset-0 opacity-40"
        style={{
          backgroundImage: `radial-gradient(ellipse 80% 50% at 50% -20%, hsl(var(--ultramarine) / 0.2), transparent)`,
        }}
      />
      <div 
        className="absolute inset-0 opacity-15"
        style={{
          backgroundImage: `radial-gradient(ellipse 40% 30% at 80% 80%, hsl(var(--gold) / 0.3), transparent)`,
        }}
      />

      <div 
        className="absolute inset-0 opacity-5"
        style={{
          backgroundImage: `linear-gradient(hsl(var(--ultramarine)) 1px, transparent 1px),
                           linear-gradient(90deg, hsl(var(--ultramarine)) 1px, transparent 1px)`,
          backgroundSize: '50px 50px',
        }}
      />

      <div className="relative z-10 container mx-auto px-6">
        <div className="max-w-4xl mx-auto text-center">
          <div className="animate-fade-up-delay-1 mb-6">
            <span className="badge-detective">
              <Shield className="w-4 h-4" />
              60+ Commands. Zero Config.
            </span>
          </div>

          <h1 className="animate-fade-up-delay-1 font-display text-5xl md:text-6xl lg:text-7xl font-bold mb-4 leading-tight">
            <span className="text-gradient-ultramarine glow-text">Shellockolm</span>
          </h1>

          <p className="animate-fade-up-delay-2 font-display text-xl md:text-2xl text-foreground/90 mb-4 italic">
            "Elementary, my dear developer!"
          </p>

          <p className="animate-fade-up-delay-2 text-base md:text-lg text-muted-foreground max-w-2xl mx-auto mb-8">
            Security scanner for React, Next.js, Node.js, and npm. 32 CVEs. 60+ commands. Zero config.
          </p>

          <div className="animate-fade-up-delay-3 flex flex-col sm:flex-row gap-4 justify-center">
            <Button 
              size="lg" 
              className="group relative overflow-hidden bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-lg font-semibold glow-ultramarine animate-glow-pulse"
              onClick={() => window.open('https://github.com/hlsitechio/shellockolm', '_blank')}
            >
              <Shield className="w-5 h-5 mr-2" />
              Get Started
            </Button>
            <Button 
              size="lg" 
              variant="outline"
              className="border-border hover:bg-secondary hover:border-primary/50 px-8 py-6 text-lg"
              onClick={() => document.getElementById('features')?.scrollIntoView({ behavior: 'smooth' })}
            >
              <Zap className="w-5 h-5 mr-2" />
              See Features
            </Button>
          </div>
        </div>

        <div className="my-20 lg:my-28 flex items-center justify-center">
          <div className="h-px w-full max-w-4xl bg-gradient-to-r from-transparent via-primary to-transparent" />
        </div>

        <div className="animate-fade-up-delay-3 max-w-4xl mx-auto">
          <div className="terminal-window">
            <div className="terminal-header">
              <div className="terminal-dot bg-danger" />
              <div className="terminal-dot bg-primary" />
              <div className="terminal-dot bg-success" />
              <span className="ml-4 text-sm text-muted-foreground font-mono">terminal</span>
            </div>
            <div className="terminal-body text-left">
              <p className="text-muted-foreground">$ python src/auto_fix.py ~/projects</p>
              <p className="text-primary mt-2">🔍 Scanning 32 CVEs across 7 scanners...</p>
              <p className="text-foreground mt-1">   → React 19.0.0 → CVE-2025-55182 (CVSS 10.0)</p>
              <p className="text-foreground">   → Next.js 15.0.0 → CVE-2025-66478 (CVSS 10.0)</p>
              <p className="text-foreground">   → n8n 1.76.1 → CVE-2026-21858 (Ni8mare RCE)</p>
              <p className="text-success mt-2">✓ All vulnerabilities patched. Elementary!</p>
            </div>
          </div>
        </div>
      </div>

      <div className="absolute bottom-0 left-0 right-0 h-32 bg-gradient-to-t from-background to-transparent" />
    </section>
  );
};

export default HeroSection;
