import {
  Check,
  Github,
  ArrowRight,
  Lock,
  Zap,
  ShieldAlert,
  Infinity,
  Download,
  Sparkles,
  RefreshCw,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";

// ── Stripe Pro Payment Link ──────────────────────────────────────────────────
// This is a hosted Stripe Payment Link — no secret key touches the frontend.
const STRIPE_PRO_LINK = "https://buy.stripe.com/00wcN68161FLfX78JU3Je05";
const GITHUB_REPO = "https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner";

// ── Feature lists ────────────────────────────────────────────────────────────
const freeFeatures: { label: string; detail?: string }[] = [
  {
    label: "Complete CVE scanner",
    detail: "React / Next.js / Node.js / npm — 32+ rules including CVSS 10.0 RCEs",
  },
  {
    label: "Agent supply-chain scanner",
    detail:
      "Claude skills (SKILL.md), MCP server configs, n8n workflows — prompt injection, secret exfil, tool poisoning",
  },
  {
    label: "Malware & secrets detection",
    detail: "Obfuscated payloads, hard-coded credentials, environment variable leaks",
  },
  { label: "CLI + MCP server", detail: "Run locally or pipe into any MCP-compatible agent" },
  { label: "SARIF & SBOM export", detail: "Drop-in for GitHub Advanced Security, Semgrep, etc." },
  { label: "100% offline — zero telemetry", detail: "Your code never leaves your machine" },
  { label: "MIT licence", detail: "Fork it. Embed it. Ship it. No strings." },
];

const proFeatures: { label: string; detail?: string }[] = [
  {
    label: "Everything in Free — forever",
    detail: "The open-source repo is never paywalled; Pro adds on top",
  },
  {
    label: "Advanced agent supply-chain Pro rule packs",
    detail:
      "Indirect & second-order prompt injection, tool/skill shadowing, conversation-context exfiltration",
  },
  {
    label: "Premium report formats",
    detail: "Executive PDF summaries, compliance-ready JSON, Jira/Linear ticket export",
  },
  {
    label: "Continuous monitoring",
    detail:
      "Server-delivered scan runs on a schedule; new findings land in your inbox automatically",
  },
  {
    label: "Early access to new detections",
    detail: "Pro rule packs ship ahead of open-source merges",
  },
  {
    label: "Priority issue tracker access",
    detail: "Bug reports and rule requests jump the queue",
  },
];

// ── Sub-components ────────────────────────────────────────────────────────────

interface FeatureRowProps {
  label: string;
  detail?: string;
  iconColor?: string;
}

const FeatureRow = ({ label, detail, iconColor = "text-success" }: FeatureRowProps) => (
  <li className="flex items-start gap-3 text-sm">
    <Check
      className={`w-4 h-4 shrink-0 mt-0.5 ${iconColor}`}
      aria-hidden="true"
    />
    <span>
      <span className="text-foreground font-medium">{label}</span>
      {detail && (
        <>
          <span className="text-muted-foreground/70 mx-1">—</span>
          <span className="text-muted-foreground">{detail}</span>
        </>
      )}
    </span>
  </li>
);

// ── Main component ────────────────────────────────────────────────────────────

const ProTierSection = () => {
  return (
    <section
      id="pro"
      aria-label="Free vs Pro open-core tiers"
      className="relative py-28 overflow-hidden"
    >
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-20"
        aria-hidden="true"
        style={{
          backgroundImage:
            "radial-gradient(ellipse 70% 50% at 30% 60%, hsl(var(--gold) / 0.12), transparent), radial-gradient(ellipse 50% 40% at 70% 30%, hsl(var(--ultramarine) / 0.12), transparent)",
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Section header */}
        <div className="text-center mb-16 max-w-2xl mx-auto">
          <span className="badge-detective mb-6 inline-flex">
            <Infinity className="w-4 h-4" aria-hidden="true" />
            Open-Core Pricing
          </span>
          <h2 className="font-display text-4xl sm:text-5xl font-bold mb-5 leading-tight">
            The scanner stays{" "}
            <span className="text-gradient-gold">free. Always.</span>
          </h2>
          <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
            Shellockolm is MIT-licensed and fully downloadable — no feature ever moves
            behind a paywall. Pro is an additive upgrade that delivers server-side rule
            packs and automation on top of the open-source core.
          </p>
        </div>

        {/* Two-column tier grid */}
        <div
          className="grid grid-cols-1 lg:grid-cols-2 gap-6 max-w-5xl mx-auto items-start"
          role="list"
          aria-label="Open-core subscription tiers"
        >
          {/* ── FREE TIER ──────────────────────────────────────────────── */}
          <div
            role="listitem"
            className="card-noir flex flex-col p-8 border-border hover:border-primary/40 transition-colors duration-300"
          >
            {/* Tier header */}
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-secondary text-success" aria-hidden="true">
                <Download className="w-6 h-6" />
              </div>
              <h3 className="font-display text-2xl font-bold">Free</h3>
            </div>

            {/* Price */}
            <div className="mb-1">
              <span className="text-4xl font-bold text-foreground">$0</span>
              <span className="text-muted-foreground text-sm ml-2">forever · MIT</span>
            </div>
            <p className="text-sm text-muted-foreground mb-6 font-mono">
              Clone it. Use it. Fork it. No account. No telemetry.
            </p>

            {/* Open-core guarantee callout */}
            <div
              className="rounded-xl border border-success/25 bg-success/5 px-4 py-3 mb-6 flex items-start gap-2.5 text-sm"
              role="note"
              aria-label="Open-source guarantee"
            >
              <Lock className="w-4 h-4 text-success shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-success/90 leading-relaxed">
                <strong className="font-semibold">Open-core guarantee:</strong> the full scanner
                — including the AI-agent rule engine — is MIT-licensed and will remain
                freely downloadable forever. Pro never locks the repo.
              </p>
            </div>

            {/* Feature list */}
            <ul className="space-y-4 mb-8 flex-1" aria-label="Free tier features">
              {freeFeatures.map((f) => (
                <FeatureRow key={f.label} label={f.label} detail={f.detail} />
              ))}
            </ul>

            {/* CTA */}
            <Button
              size="lg"
              variant="outline"
              className="w-full group border-primary/40 hover:border-primary hover:bg-primary/10 text-primary gap-2"
              onClick={() => window.open(GITHUB_REPO, "_blank", "noopener noreferrer")}
              aria-label="Clone Shellockolm on GitHub — it's free forever"
            >
              <Github className="w-5 h-5" aria-hidden="true" />
              Clone it — it's yours
              <ArrowRight
                className="w-4 h-4 ml-auto transition-transform group-hover:translate-x-0.5"
                aria-hidden="true"
              />
            </Button>
          </div>

          {/* ── PRO TIER ───────────────────────────────────────────────── */}
          <div
            role="listitem"
            className="card-noir relative flex flex-col p-8 border-primary glow-ultramarine"
          >
            {/* "Most value" badge */}
            <span
              className="absolute -top-3.5 left-1/2 -translate-x-1/2 badge-detective text-xs whitespace-nowrap"
              aria-label="Pro — most value"
            >
              <Sparkles className="w-3 h-3" aria-hidden="true" />
              Early access · additive upgrade
            </span>

            {/* Tier header */}
            <div className="flex items-center gap-3 mb-2">
              <div className="p-2.5 rounded-xl bg-primary/20 text-primary" aria-hidden="true">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <h3 className="font-display text-2xl font-bold">Pro</h3>
            </div>

            {/* Price */}
            <div className="mb-1">
              <span className="text-4xl font-bold text-gradient-ultramarine">$29</span>
              <span className="text-muted-foreground text-sm ml-2">/month</span>
            </div>
            <p className="text-sm text-muted-foreground mb-6 font-mono">
              Additive upgrade — the free scanner is always included.
            </p>

            {/* What Pro adds callout */}
            <div
              className="rounded-xl border border-primary/25 bg-primary/5 px-4 py-3 mb-6 flex items-start gap-2.5 text-sm"
              role="note"
              aria-label="What Pro adds"
            >
              <Zap className="w-4 h-4 text-primary shrink-0 mt-0.5" aria-hidden="true" />
              <p className="text-primary/90 leading-relaxed">
                <strong className="font-semibold">Pro adds server-delivered features</strong>{" "}
                on top of the open-source core. Nothing is removed from the repo.
                The MIT licence stays.
              </p>
            </div>

            {/* Feature list */}
            <ul className="space-y-4 mb-6 flex-1" aria-label="Pro tier features">
              {proFeatures.map((f) => (
                <FeatureRow
                  key={f.label}
                  label={f.label}
                  detail={f.detail}
                  iconColor={f.label === "Everything in Free — forever" ? "text-gold" : "text-primary"}
                />
              ))}
            </ul>

            {/* CTA */}
            <Button
              size="lg"
              className="w-full group bg-primary text-primary-foreground hover:bg-primary/90 glow-ultramarine gap-2 mb-3"
              onClick={() => window.open(STRIPE_PRO_LINK, "_blank", "noopener noreferrer")}
              aria-label="Subscribe to Shellockolm Pro — $29 per month"
            >
              <RefreshCw className="w-5 h-5" aria-hidden="true" />
              Go Pro — $29/mo
              <ArrowRight
                className="w-4 h-4 ml-auto transition-transform group-hover:translate-x-0.5"
                aria-hidden="true"
              />
            </Button>

            {/* Small print */}
            <p className="text-xs text-muted-foreground/60 text-center leading-relaxed flex items-start gap-1.5 justify-center">
              <FileText className="w-3 h-3 shrink-0 mt-0.5" aria-hidden="true" />
              <span>
                License key emailed after checkout (manual within 24 h during early access).
              </span>
            </p>
          </div>
        </div>

        {/* Bottom open-source reinforcement */}
        <div className="mt-14 text-center max-w-xl mx-auto">
          <p className="text-sm text-muted-foreground/70 leading-relaxed">
            Prefer pure open-source?{" "}
            <button
              className="text-primary underline underline-offset-4 hover:text-primary/80 transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-primary rounded-sm"
              onClick={() => window.open(GITHUB_REPO, "_blank", "noopener noreferrer")}
            >
              The full scanner is on GitHub
            </button>
            {" "}and always will be. Pro is opt-in, not a gate.
          </p>
        </div>
      </div>
    </section>
  );
};

export default ProTierSection;
