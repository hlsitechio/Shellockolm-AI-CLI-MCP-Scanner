import {
  Search,
  Shield,
  Github,
  Bot,
  Lock,
  FileCode,
} from "lucide-react";
import FlipCard from "./FlipCard";

const features = [
  {
    icon: Search,
    title: "CVE Detection",
    description: "Detects 32 CVEs including critical RCEs in React, Next.js, Node.js, and n8n.",
    highlight: "32 CVEs",
    terminalLines: [
      "$ python src/scan.py ./project",
      "🔍 Scanning 7 specialized scanners...",
      "→ React: CVE-2025-55182 (CVSS 10.0)",
      "→ Next.js: CVE-2025-66478 (CVSS 10.0)",
      "→ n8n: CVE-2026-21858 (Ni8mare RCE)",
      "→ Node.js: 9 runtime vulnerabilities",
      "✓ 32 CVEs tracked",
    ],
  },
  {
    icon: Shield,
    title: "Auto-Patching",
    description: "Scan, detect, patch, verify. One command fixes everything.",
    highlight: "One Command",
    terminalLines: [
      "$ python src/auto_fix.py ~/projects",
      "🔍 Scanning...",
      "→ Found 3 vulnerable packages",
      "→ Patching react: 19.0.0 → 19.0.1",
      "→ Patching next: 15.0.0 → 15.0.5",
      "→ Verified all patches",
      "✓ Done. Backed up originals.",
    ],
  },
  {
    icon: Lock,
    title: "Secrets Scanner",
    description: "Finds API keys, tokens, and credentials. 50+ patterns.",
    highlight: "50+ Patterns",
    terminalLines: [
      "$ python src/secrets_scanner.py ./",
      "🔍 Scanning for secrets...",
      "→ 50+ detection patterns",
      "→ AWS keys, tokens, passwords",
      "⚠ Found: .env.local (3 secrets)",
      "⚠ Found: config.js (API key)",
      "✓ Report: secrets_report.json",
    ],
  },
  {
    icon: FileCode,
    title: "SBOM Generator",
    description: "Creates CycloneDX or SPDX bills of materials for compliance.",
    highlight: "CycloneDX/SPDX",
    terminalLines: [
      "$ python src/sbom.py --format cyclonedx",
      "🔍 Generating SBOM...",
      "→ Reading package.json",
      "→ Analyzing dependencies",
      "→ Format: CycloneDX 1.5",
      "→ Components: 247 found",
      "✓ sbom.json created",
    ],
  },
  {
    icon: Github,
    title: "GitHub Scanner",
    description: "Scan your repos via API. No cloning needed.",
    highlight: "No Cloning",
    terminalLines: [
      "$ python src/github_scanner.py username",
      "🔍 Fetching repositories...",
      "→ Found 12 repos",
      "→ Scanning via GitHub API",
      "→ repo-1: ✓ Clean",
      "→ repo-2: ⚠ 2 CVEs found",
      "✓ Complete (no cloning)",
    ],
  },
  {
    icon: Bot,
    title: "AI Integration",
    description: "MCP server for Claude, Cursor, and any AI assistant.",
    highlight: "MCP Server",
    terminalLines: [
      "$ python src/server.py",
      "🔍 Starting MCP server...",
      "→ Protocol: stdio",
      "→ Tools: scan, patch, sbom",
      "✓ Connected to Claude",
      "✓ Ready for AI commands",
    ],
  },
];

const FeaturesSection = () => {
  return (
    <section className="relative py-24 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-dark" />
      <div 
        className="absolute inset-0 opacity-25"
        style={{
          backgroundImage: `radial-gradient(ellipse 60% 40% at 50% 50%, hsl(var(--ultramarine) / 0.15), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-6">
        <div className="text-center mb-16">
          <h2 className="font-display text-4xl md:text-5xl font-bold mb-4">
            <span className="text-gradient-ultramarine">6</span> Core Tools
          </h2>
          <p className="text-muted-foreground max-w-lg mx-auto">
            Everything you need to secure React, Next.js, and Node.js apps.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto">
          {features.map((feature, index) => (
            <FlipCard
              key={feature.title}
              icon={feature.icon}
              title={feature.title}
              description={feature.description}
              highlight={feature.highlight}
              terminalLines={feature.terminalLines}
              index={index}
            />
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
