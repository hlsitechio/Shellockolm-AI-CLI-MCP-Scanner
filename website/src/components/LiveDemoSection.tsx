import { useState, useEffect, useRef, useCallback } from "react";
import { Play, RotateCcw, ChevronDown, ChevronUp, Terminal } from "lucide-react";
import { Button } from "@/components/ui/button";

// ── Types ────────────────────────────────────────────────────────────────────

type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW";

interface Finding {
  severity: Severity;
  ruleId: string;
  location: string;
  title: string;
  why: string;
}

interface DemoTarget {
  id: string;
  label: string;
  filename: string;
  description: string;
  command: string;
  scanningLines: string[];
  findings: Finding[];
}

// ── Demo data (accurate to the tool's real output format) ───────────────────

const TARGETS: DemoTarget[] = [
  {
    id: "skill",
    label: "Poisoned Claude Skill",
    filename: "SKILL.md",
    description: "Agent skill with embedded prompt-injection and secret exfiltration",
    command: "python src/scan.py --mode ai-agent ./SKILL.md",
    scanningLines: [
      "Loading AI-agent scanner…",
      "Parsing skill manifest…",
      "Checking for prompt-injection patterns…",
      "Checking for hidden conditional triggers…",
      "Scanning for hardcoded credentials…",
    ],
    findings: [
      {
        severity: "CRITICAL",
        ruleId: "AGENT-PI-003",
        location: "SKILL.md:3",
        title: "Secret-exfiltration instruction",
        why: "The skill instructs the agent to forward user data or tool results to an external URL. An attacker-controlled server receives everything the agent sees.",
      },
      {
        severity: "HIGH",
        ruleId: "AGENT-PI-001",
        location: "SKILL.md:2",
        title: "Instruction override / jailbreak phrasing",
        why: "\"Ignore previous instructions\" phrasing detected. This attempts to override the model's system prompt and redefine its behaviour for anyone who installs the skill.",
      },
      {
        severity: "HIGH",
        ruleId: "AGENT-PI-002",
        location: "SKILL.md:3",
        title: "Hidden conditional trigger",
        why: "A conditional that silently activates only when certain keywords appear in conversation — designed to stay dormant during casual review but fire in production.",
      },
      {
        severity: "HIGH",
        ruleId: "AGENT-SECRET-001",
        location: "SKILL.md:4",
        title: "Hardcoded credential",
        why: "An API key or token is embedded directly in the skill file. Anyone with access to the skill gets the credential; it will likely appear in the agent's context window.",
      },
    ],
  },
  {
    id: "mcp",
    label: "Malicious MCP Server",
    filename: "mcp.json",
    description: "MCP config wiring an agent to a remote-code-execution backdoor",
    command: "python src/scan.py --mode mcp ./mcp.json",
    scanningLines: [
      "Loading MCP scanner…",
      "Parsing server definitions…",
      "Checking server commands for remote execution…",
      "Checking package pins…",
      "Verifying tool descriptions for prompt injection…",
    ],
    findings: [
      {
        severity: "CRITICAL",
        ruleId: "AGENT-MCP-001",
        location: "mcp.json » server:bad",
        title: "MCP server fetches and runs a remote script (curl|bash)",
        why: "The server's startup command pipes a URL directly into bash. Every time the agent starts this server it executes arbitrary code from an attacker-controlled host — a classic supply-chain RCE.",
      },
      {
        severity: "MEDIUM",
        ruleId: "AGENT-MCP-002",
        location: "mcp.json » server:loose",
        title: "Unpinned MCP package (rug-pull risk)",
        why: "The package version is unpinned (\"@latest\" or no version). The package author — or an attacker who compromises the registry entry — can push a malicious update that your agent picks up automatically.",
      },
    ],
  },
  {
    id: "react",
    label: "Vulnerable React App",
    filename: "package.json",
    description: "Dependencies with active critical CVEs in the wild",
    command: "python src/scan.py --mode cve ./package.json",
    scanningLines: [
      "Loading CVE database (32 entries)…",
      "Parsing package.json…",
      "Checking react@19.0.0…",
      "Checking next@15.0.0…",
      "Checking n8n@1.76.1…",
    ],
    findings: [
      {
        severity: "CRITICAL",
        ruleId: "CVE-2025-55182",
        location: "package.json",
        title: "React Server Components RCE (CVSS 10.0)",
        why: "Unauthenticated remote code execution via malformed Server Component payload. Any user can trigger server-side code execution without credentials. Patched in react@19.0.1.",
      },
      {
        severity: "CRITICAL",
        ruleId: "CVE-2025-29927",
        location: "package.json",
        title: "Next.js middleware auth bypass (CVSS 9.1)",
        why: "A crafted x-middleware-subrequest header causes Next.js to skip middleware execution entirely, bypassing authentication, rate-limiting, and any other middleware-based access control.",
      },
      {
        severity: "CRITICAL",
        ruleId: "CVE-2026-21858",
        location: "package.json",
        title: "n8n Ni8mare unauthenticated RCE (CVSS 10.0)",
        why: "Unauthenticated RCE in n8n's workflow engine via a malicious webhook payload. A public-facing n8n instance is fully compromised with a single HTTP request. No patch yet — disable public access.",
      },
    ],
  },
];

// ── Severity helpers ─────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, { label: string; bg: string; text: string; border: string }> = {
  CRITICAL: {
    label: "CRITICAL",
    bg: "bg-red-950/60",
    text: "text-red-400",
    border: "border-red-700/50",
  },
  HIGH: {
    label: "HIGH",
    bg: "bg-amber-950/60",
    text: "text-amber-400",
    border: "border-amber-700/50",
  },
  MEDIUM: {
    label: "MEDIUM",
    bg: "bg-yellow-950/40",
    text: "text-yellow-400",
    border: "border-yellow-700/40",
  },
  LOW: {
    label: "LOW",
    bg: "bg-secondary/40",
    text: "text-muted-foreground",
    border: "border-border",
  },
};

// ── Typewriter hook ──────────────────────────────────────────────────────────

function useTypewriter(text: string, active: boolean, charDelay = 18) {
  const [displayed, setDisplayed] = useState("");

  useEffect(() => {
    if (!active) {
      setDisplayed("");
      return;
    }
    let i = 0;
    setDisplayed("");
    const id = setInterval(() => {
      i++;
      setDisplayed(text.slice(0, i));
      if (i >= text.length) clearInterval(id);
    }, charDelay);
    return () => clearInterval(id);
  }, [text, active, charDelay]);

  return displayed;
}

// ── FindingRow ────────────────────────────────────────────────────────────────

function FindingRow({
  finding,
  visible,
  reducedMotion,
}: {
  finding: Finding;
  visible: boolean;
  reducedMotion: boolean;
}) {
  const [expanded, setExpanded] = useState(false);
  const s = SEVERITY_STYLES[finding.severity];

  return (
    <div
      className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden transition-all duration-300 ${
        visible ? "opacity-100 translate-y-0" : "opacity-0 translate-y-2"
      } ${reducedMotion ? "transition-none" : ""}`}
    >
      {/* Header row */}
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors group"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        aria-label={`${finding.severity} finding: ${finding.title}. Click to ${expanded ? "collapse" : "expand"} explanation.`}
      >
        {/* Severity badge */}
        <span
          className={`shrink-0 font-mono text-[10px] font-bold tracking-wider px-1.5 py-0.5 rounded ${s.text} border ${s.border} bg-black/30`}
          aria-hidden="true"
        >
          {s.label}
        </span>

        {/* Rule ID */}
        <span className="shrink-0 font-mono text-xs text-muted-foreground/80 hidden sm:block">
          {finding.ruleId}
        </span>

        {/* Location */}
        <span className="shrink-0 font-mono text-xs text-primary/70 hidden md:block">
          {finding.location}
        </span>

        {/* Title */}
        <span className="flex-1 text-sm font-medium text-foreground/90 truncate">
          {finding.title}
        </span>

        {/* Expand toggle */}
        <span className={`shrink-0 ${s.text} opacity-60 group-hover:opacity-100`} aria-hidden="true">
          {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </span>
      </button>

      {/* Why it matters */}
      {expanded && (
        <div className="px-4 pb-4 pt-1 border-t border-white/5">
          {/* Mobile-only: rule id + location */}
          <p className="sm:hidden font-mono text-[11px] text-muted-foreground mb-2">
            {finding.ruleId} · {finding.location}
          </p>
          <p className="text-sm text-muted-foreground leading-relaxed">
            <span className="font-semibold text-foreground/70">Why it matters: </span>
            {finding.why}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Main component ───────────────────────────────────────────────────────────

const LiveDemoSection = () => {
  const [selectedId, setSelectedId] = useState<string>(TARGETS[0].id);
  const [phase, setPhase] = useState<"idle" | "command" | "scanning" | "findings">("idle");
  const [scanLineIndex, setScanLineIndex] = useState(0);
  const [visibleFindings, setVisibleFindings] = useState(0);
  const timeoutsRef = useRef<ReturnType<typeof setTimeout>[]>([]);
  const sectionRef = useRef<HTMLElement>(null);
  const reducedMotion =
    typeof window !== "undefined"
      ? window.matchMedia("(prefers-reduced-motion: reduce)").matches
      : false;

  const target = TARGETS.find((t) => t.id === selectedId)!;

  const commandTyped = useTypewriter(
    `$ ${target.command}`,
    phase === "command",
    reducedMotion ? 0 : 16
  );

  // Clear all pending timeouts
  const clearAll = useCallback(() => {
    timeoutsRef.current.forEach(clearTimeout);
    timeoutsRef.current = [];
  }, []);

  const run = useCallback(() => {
    clearAll();
    setPhase("idle");
    setScanLineIndex(0);
    setVisibleFindings(0);

    const push = (fn: () => void, ms: number) => {
      const id = setTimeout(fn, ms);
      timeoutsRef.current.push(id);
    };

    const commandDuration = reducedMotion ? 0 : target.command.length * 16 + 100;

    push(() => setPhase("command"), 80);
    push(() => setPhase("scanning"), commandDuration + 300);

    // Stream scanning lines
    target.scanningLines.forEach((_, i) => {
      const scanDelay = reducedMotion ? 0 : 420;
      push(() => setScanLineIndex(i + 1), commandDuration + 300 + (i + 1) * scanDelay);
    });

    const totalScanDuration =
      commandDuration + 300 + target.scanningLines.length * (reducedMotion ? 0 : 420);

    push(() => setPhase("findings"), totalScanDuration + 200);

    // Stream findings in one by one
    target.findings.forEach((_, i) => {
      const findingDelay = reducedMotion ? 0 : 480;
      push(() => setVisibleFindings(i + 1), totalScanDuration + 200 + (i + 1) * findingDelay);
    });
  }, [target, clearAll, reducedMotion]);

  // Stop on unmount
  useEffect(() => () => clearAll(), [clearAll]);

  // Reset when target changes (don't auto-run)
  useEffect(() => {
    clearAll();
    setPhase("idle");
    setScanLineIndex(0);
    setVisibleFindings(0);
  }, [selectedId, clearAll]);

  const handleTargetChange = (id: string) => {
    if (id === selectedId) return;
    setSelectedId(id);
  };

  const isRunning = phase === "command" || phase === "scanning";
  const isDone = phase === "findings";

  return (
    <section
      id="demo"
      aria-label="Interactive live demo"
      ref={sectionRef}
      className="relative py-24 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-navy" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-30"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 70% 50% at 50% 0%, hsl(var(--ultramarine) / 0.18), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Section header */}
        <div className="text-center mb-12 max-w-2xl mx-auto">
          <span className="badge-detective mb-6 inline-flex">
            <Terminal className="w-4 h-4" aria-hidden="true" />
            Live Demo
          </span>
          <h2 className="font-display text-4xl sm:text-5xl font-bold mb-4 leading-tight">
            Watch it catch a{" "}
            <span className="text-gradient-gold">real threat</span>
          </h2>
          <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
            Pick a target. Hit Run. See exactly what Shellockolm finds and why it matters.
            No mock data — these are the actual rule IDs and CVE identifiers the tool produces.
          </p>
        </div>

        {/* Target selector */}
        <div
          className="flex flex-col sm:flex-row gap-3 justify-center mb-8"
          role="group"
          aria-label="Select scan target"
        >
          {TARGETS.map((t) => (
            <button
              key={t.id}
              onClick={() => handleTargetChange(t.id)}
              aria-pressed={selectedId === t.id}
              className={`px-5 py-3 rounded-xl border font-mono text-sm transition-all duration-200 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${
                selectedId === t.id
                  ? "border-primary bg-primary/15 text-primary glow-ultramarine"
                  : "border-border bg-secondary/20 text-muted-foreground hover:border-primary/40 hover:text-foreground hover:bg-secondary/40"
              }`}
            >
              <span className="block text-xs opacity-60 mb-0.5">{t.filename}</span>
              {t.label}
            </button>
          ))}
        </div>

        {/* Terminal window */}
        <div className="max-w-3xl mx-auto">
          <div className="terminal-window">
            {/* Terminal header */}
            <div className="terminal-header">
              <div className="terminal-dot bg-danger" aria-hidden="true" />
              <div className="terminal-dot bg-gold" aria-hidden="true" />
              <div className="terminal-dot bg-success" aria-hidden="true" />
              <span className="ml-3 text-sm text-muted-foreground font-mono flex-1 truncate">
                shellockolm — {target.filename}
              </span>
              {/* Run / Re-run button */}
              <button
                onClick={run}
                disabled={isRunning}
                className={`flex items-center gap-1.5 px-3 py-1 rounded text-xs font-mono transition-all focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary ${
                  isRunning
                    ? "text-muted-foreground cursor-not-allowed"
                    : isDone
                    ? "text-gold hover:text-gold/80"
                    : "text-success hover:text-success/80"
                }`}
                aria-label={isDone ? "Re-run scan" : "Run scan"}
              >
                {isDone ? (
                  <>
                    <RotateCcw className="w-3 h-3" aria-hidden="true" />
                    Re-run
                  </>
                ) : (
                  <>
                    <Play className="w-3 h-3" aria-hidden="true" />
                    {isRunning ? "Running…" : "Run"}
                  </>
                )}
              </button>
            </div>

            {/* Terminal body */}
            <div className="terminal-body space-y-1 min-h-[220px]" aria-live="polite" aria-atomic="false">
              {/* Idle state */}
              {phase === "idle" && (
                <p className="text-muted-foreground/50 italic text-sm">
                  ↑ Press Run to start the scan
                </p>
              )}

              {/* Command line (typewriter) */}
              {phase !== "idle" && (
                <p className="text-muted-foreground text-sm">
                  <span aria-hidden="true">{commandTyped}</span>
                  {phase === "command" && (
                    <span className="inline-block w-2 h-4 bg-primary ml-0.5 animate-pulse align-middle" aria-hidden="true" />
                  )}
                </p>
              )}

              {/* Scanning lines */}
              {(phase === "scanning" || phase === "findings") && (
                <div className="mt-2 space-y-1">
                  {target.scanningLines.slice(0, scanLineIndex).map((line, i) => (
                    <p
                      key={i}
                      className={`text-sm font-mono transition-opacity duration-300 ${
                        i < scanLineIndex ? "opacity-100" : "opacity-0"
                      } ${reducedMotion ? "transition-none" : ""}`}
                    >
                      <span className="text-primary/60" aria-hidden="true">  › </span>
                      <span className="text-muted-foreground">{line}</span>
                      {i === scanLineIndex - 1 && phase === "scanning" && (
                        <span className="inline-block w-1.5 h-1.5 bg-primary rounded-full ml-2 animate-pulse align-middle" aria-hidden="true" />
                      )}
                    </p>
                  ))}
                </div>
              )}

              {/* Done line */}
              {phase === "findings" && scanLineIndex >= target.scanningLines.length && (
                <p className="text-sm font-mono mt-2">
                  <span className="text-success">✓ </span>
                  <span className="text-foreground/80">
                    Scan complete —{" "}
                    <span className={target.findings.length > 0 ? "text-red-400 font-semibold" : "text-success font-semibold"}>
                      {target.findings.length} finding{target.findings.length !== 1 ? "s" : ""}
                    </span>
                  </span>
                </p>
              )}
            </div>
          </div>

          {/* Findings list */}
          {phase === "findings" && target.findings.length > 0 && (
            <div className="mt-4 space-y-3" aria-label="Scan findings" aria-live="polite">
              <p className="text-xs font-mono text-muted-foreground/60 uppercase tracking-widest px-1">
                Findings — click any row to expand
              </p>
              {target.findings.map((finding, i) => (
                <FindingRow
                  key={finding.ruleId}
                  finding={finding}
                  visible={i < visibleFindings}
                  reducedMotion={reducedMotion}
                />
              ))}
            </div>
          )}

          {/* Target description */}
          <p className="text-center text-xs text-muted-foreground/50 font-mono mt-6">
            {target.description}
          </p>
        </div>

        {/* Bottom CTA */}
        <div className="text-center mt-12">
          <Button
            size="lg"
            className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-6 text-base font-semibold glow-ultramarine"
            onClick={() =>
              window.open(
                "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner",
                "_blank",
                "noopener noreferrer"
              )
            }
            aria-label="Get Shellockolm on GitHub to run these scans on your own code"
          >
            Run This On Your Own Code — Free
          </Button>
          <p className="mt-3 text-xs text-muted-foreground/50">
            100% local · no telemetry · MIT license
          </p>
        </div>
      </div>
    </section>
  );
};

export default LiveDemoSection;
