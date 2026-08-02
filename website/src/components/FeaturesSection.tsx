import {
  Search,
  Shield,
  Github,
  Bot,
  Lock,
  FileCode,
  Zap,
} from "lucide-react";
import FlipCard from "./FlipCard";
import { useEffect, useRef, useState } from "react";

const features = [
  {
    icon: Bot,
    title: "AI-Agent Scanner",
    description:
      "Detects prompt injection, secret exfiltration, and tool poisoning in Claude skills (SKILL.md), MCP server configs (mcp.json), and n8n workflows.",
    highlight: "Agent supply chain",
    terminalLines: [
      "$ python src/scan.py --mode ai-agent ./skills/",
      "› Loading AI-agent scanner…",
      "→ [CRITICAL] AGENT-PI-003 SKILL.md:3",
      "   Secret-exfiltration instruction",
      "→ [HIGH]     AGENT-PI-001 SKILL.md:2",
      "   Instruction override / jailbreak",
      "✓ Skill quarantined. Elementary!",
    ],
  },
  {
    icon: Shield,
    title: "MCP Server Audit",
    description:
      "Catches curl|bash remote-execution in MCP server startup commands, unpinned package versions (rug-pull risk), and prompt injection in tool descriptions.",
    highlight: "curl|bash detection",
    terminalLines: [
      "$ python src/scan.py --mode mcp ./mcp.json",
      "› Parsing MCP server definitions…",
      "→ [CRITICAL] AGENT-MCP-001",
      "   server:bad fetches & runs remote script",
      "→ [MEDIUM]   AGENT-MCP-002",
      "   Unpinned package — rug-pull risk",
      "✓ 2 findings. Remediation guide attached.",
    ],
  },
  {
    icon: Search,
    title: "CVE Detection",
    description:
      "Detects 32 CVEs including CVSS 10.0 RCEs in React, Next.js, Node.js, and n8n. CVE-2025-29927 Next.js auth bypass. CVE-2026-21858 Ni8mare RCE.",
    highlight: "32 CVEs · CVSS 10.0",
    terminalLines: [
      "$ python src/scan.py --mode cve ./package.json",
      "› Checking 32 CVE signatures…",
      "→ [CRITICAL] CVE-2025-55182 react@19.0.0",
      "   RCE via Server Components (CVSS 10.0)",
      "→ [CRITICAL] CVE-2025-29927 next@15.0.0",
      "   Middleware auth bypass (CVSS 9.1)",
      "✓ Patches: react→19.0.1, next→15.2.3",
    ],
  },
  {
    icon: Lock,
    title: "Secrets Scanner",
    description:
      "Finds API keys, tokens, and hardcoded credentials embedded in skill files, config, and source. 50+ detection patterns covering AWS, Stripe, GitHub, and more.",
    highlight: "50+ patterns",
    terminalLines: [
      "$ python src/secrets_scanner.py ./",
      "› 50+ detection patterns active…",
      "→ SKILL.md:4   Hardcoded API key",
      "   Pattern: sk-[a-zA-Z0-9]{48}",
      "⚠ .env.local (3 secrets found)",
      "⚠ config.js   (GitHub token)",
      "✓ Report: secrets_report.json",
    ],
  },
  {
    icon: FileCode,
    title: "SBOM Generator",
    description:
      "Creates CycloneDX or SPDX software bills of materials for compliance. Covers npm, pip, and mixed stacks. Feeds directly into your CI pipeline.",
    highlight: "CycloneDX / SPDX",
    terminalLines: [
      "$ python src/sbom.py --format cyclonedx",
      "› Generating SBOM…",
      "→ Reading package.json + requirements.txt",
      "→ Components: 247 identified",
      "→ Format: CycloneDX 1.5",
      "→ CVE cross-reference: 32 signatures",
      "✓ sbom.json — ready for compliance",
    ],
  },
  {
    icon: Github,
    title: "GitHub Scanner",
    description:
      "Scan your entire GitHub account via API — no cloning required. Spots vulnerable deps and exposed secrets across all repos in one pass.",
    highlight: "No cloning needed",
    terminalLines: [
      "$ python src/github_scanner.py username",
      "› Fetching repositories via API…",
      "→ 12 repos found",
      "→ repo-frontend: CVE-2025-29927 (HIGH)",
      "→ repo-api:      3 secrets exposed",
      "→ repo-n8n:      CVE-2026-21858 (CRITICAL)",
      "✓ Full report — no clone required",
    ],
  },
];

function useScrollReveal(threshold = 0.15) {
  const ref = useRef<HTMLDivElement>(null);
  const [visible, setVisible] = useState(false);

  useEffect(() => {
    const el = ref.current;
    if (!el) return;

    // Respect prefers-reduced-motion — show immediately
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setVisible(true);
      return;
    }

    const observer = new IntersectionObserver(
      ([entry]) => {
        if (entry.isIntersecting) {
          setVisible(true);
          observer.disconnect();
        }
      },
      { threshold }
    );
    observer.observe(el);
    return () => observer.disconnect();
  }, [threshold]);

  return { ref, visible };
}

const FeaturesSection = () => {
  const { ref: headerRef, visible: headerVisible } = useScrollReveal(0.3);
  const { ref: gridRef, visible: gridVisible } = useScrollReveal(0.1);

  return (
    <section aria-label="Features" className="relative py-24 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-25"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 60% 40% at 50% 50%, hsl(var(--ultramarine) / 0.15), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Section header */}
        <div
          ref={headerRef}
          className={`text-center mb-16 max-w-2xl mx-auto transition-all duration-700 ${
            headerVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-6"
          }`}
        >
          <span className="badge-detective mb-6 inline-flex">
            <Zap className="w-4 h-4" aria-hidden="true" />
            What It Scans
          </span>
          <h2 className="font-display text-4xl sm:text-5xl font-bold mb-4">
            From{" "}
            <span className="text-gradient-ultramarine">poisoned skills</span>
            {" "}to CVSS 10 RCEs
          </h2>
          <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
            Six specialised scanners. One tool. Covers the threats that matter
            right now — AI-agent supply chain attacks and critical web CVEs.
            Flip a card to see each scanner in action.
          </p>
        </div>

        {/* Feature grid */}
        <div
          ref={gridRef}
          className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6 max-w-5xl mx-auto"
          role="list"
          aria-label="Feature cards — click any card to see a live terminal example"
        >
          {features.map((feature, index) => (
            <div
              key={feature.title}
              role="listitem"
              className={`transition-all duration-500 ${
                gridVisible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-8"
              }`}
              style={{ transitionDelay: `${index * 80}ms` }}
            >
              <FlipCard
                icon={feature.icon}
                title={feature.title}
                description={feature.description}
                highlight={feature.highlight}
                terminalLines={feature.terminalLines}
                index={index}
              />
            </div>
          ))}
        </div>
      </div>
    </section>
  );
};

export default FeaturesSection;
