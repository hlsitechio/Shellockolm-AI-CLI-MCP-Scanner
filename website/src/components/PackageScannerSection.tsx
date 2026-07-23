import { useState, useRef, useEffect, useCallback, FormEvent } from "react";
import {
  Search,
  ShieldCheck,
  ShieldAlert,
  Loader2,
  ChevronDown,
  ChevronUp,
  ExternalLink,
  Package,
  Download,
  Scale,
  Users,
  Clock,
  Fingerprint,
  GitBranch,
  Globe,
  BadgeCheck,
  History,
  TrendingUp,
  TrendingDown,
  Minus,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  scanPackage,
  type ScanReport,
  type Finding,
  type Severity,
  type Provenance,
  type VersionTrend,
} from "@/lib/scanEngine";

// ── Severity + grade styling ──────────────────────────────────────────────────

const SEVERITY_STYLES: Record<Severity, { text: string; bg: string; border: string }> = {
  CRITICAL: { text: "text-red-400", bg: "bg-red-950/60", border: "border-red-700/50" },
  HIGH: { text: "text-amber-400", bg: "bg-amber-950/60", border: "border-amber-700/50" },
  MEDIUM: { text: "text-yellow-400", bg: "bg-yellow-950/40", border: "border-yellow-700/40" },
  LOW: { text: "text-sky-300", bg: "bg-sky-950/30", border: "border-sky-800/40" },
  INFO: { text: "text-muted-foreground", bg: "bg-secondary/40", border: "border-border" },
};

// Grade → colour band. A/A+ green, B gold, C amber, D/F red.
function gradeStyle(grade: string): { text: string; ring: string; glow: string } {
  if (grade.startsWith("A")) return { text: "text-success", ring: "border-success/50", glow: "shadow-[0_0_40px_hsl(var(--success)/0.35)]" };
  if (grade === "B") return { text: "text-gold", ring: "border-gold/50", glow: "glow-gold" };
  if (grade === "C") return { text: "text-amber-400", ring: "border-amber-500/50", glow: "shadow-[0_0_40px_hsl(38_90%_55%/0.3)]" };
  return { text: "text-red-400", ring: "border-red-600/50", glow: "shadow-[0_0_40px_hsl(0_72%_55%/0.35)]" };
}

// Grade → the fill colour used by score/version bars.
function gradeBar(grade: string): string {
  if (grade.startsWith("A")) return "bg-success";
  if (grade === "B") return "bg-gold";
  if (grade === "C") return "bg-amber-400";
  return "bg-red-500";
}

// Each step names WHAT it does + the threat it's trying to catch — a peek at the
// engine's coverage without dumping the whole rubric.
const SCAN_LINES: { step: string; catch: string }[] = [
  { step: "Resolving package on the npm registry", catch: "unpublished or pulled malicious releases" },
  { step: "Querying OSV.dev for known CVEs", catch: "published CVE / GHSA advisories on this exact version" },
  { step: "Matching the supply-chain campaign list", catch: "Shai-Hulud worm & maintainer-compromise malware CVEs miss" },
  { step: "Inspecting install hooks", catch: "pre / post-install scripts — the #1 RCE vector" },
  { step: "Comparing the name to popular packages", catch: "typosquats one keystroke from the real thing" },
  { step: "Auditing package health", catch: "deprecated, abandoned & single-maintainer risk" },
  { step: "Verifying provenance", catch: "repo ↔ npm ↔ signed build, and homepage mismatches" },
  { step: "Scoring the last 5 versions", catch: "security improving or sliding release-over-release" },
  { step: "Grading on the Shellockolm rubric", catch: "one weighted A+→F score" },
];

const EXAMPLES = ["react", "lodash@4.17.11", "eslint-config-prettier@10.1.7", "left-pad"];

// ── Finding row (expandable) ──────────────────────────────────────────────────

function FindingRow({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const s = SEVERITY_STYLES[finding.severity];
  return (
    <div className={`rounded-lg border ${s.border} ${s.bg} overflow-hidden`}>
      <button
        className="w-full flex items-center gap-3 px-4 py-3 text-left hover:bg-white/5 transition-colors group"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
      >
        <span className={`shrink-0 font-mono text-[10px] font-bold tracking-wider px-1.5 py-0.5 rounded ${s.text} border ${s.border} bg-black/30`}>
          {finding.severity}
        </span>
        <span className="shrink-0 font-mono text-xs text-muted-foreground/80 hidden sm:block">{finding.ruleId}</span>
        <span className="flex-1 text-sm font-medium text-foreground/90 truncate">{finding.title}</span>
        <span className={`shrink-0 ${s.text} opacity-60 group-hover:opacity-100`}>
          {open ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
        </span>
      </button>
      {open && (
        <div className="px-4 pb-4 pt-1 border-t border-white/5">
          <p className="sm:hidden font-mono text-[11px] text-muted-foreground mb-2">{finding.ruleId}</p>
          <p className="text-sm text-muted-foreground leading-relaxed">{finding.detail}</p>
          {finding.ref && (
            <a
              href={finding.ref}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1 mt-2 text-xs font-mono text-primary hover:text-primary/80"
            >
              Advisory <ExternalLink className="w-3 h-3" />
            </a>
          )}
        </div>
      )}
    </div>
  );
}

// ── Metadata chip ─────────────────────────────────────────────────────────────

function MetaChip({ icon: Icon, label, value }: { icon: any; label: string; value: string }) {
  return (
    <div className="flex items-center gap-2 rounded-lg border border-border bg-secondary/20 px-3 py-2">
      <Icon className="w-4 h-4 text-primary/70 shrink-0" aria-hidden="true" />
      <div className="min-w-0">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 leading-none mb-0.5">{label}</p>
        <p className="text-sm font-mono text-foreground/90 truncate">{value}</p>
      </div>
    </div>
  );
}

// ── Provenance ────────────────────────────────────────────────────────────────

function ProvRow({
  icon: Icon,
  label,
  value,
  href,
  sub,
  tone = "ok",
}: {
  icon: any;
  label: string;
  value: string;
  href?: string | null;
  sub?: string;
  tone?: "ok" | "warn" | "muted";
}) {
  const valueColor = tone === "warn" ? "text-amber-300" : tone === "muted" ? "text-muted-foreground/70" : "text-foreground/90";
  const iconColor = tone === "warn" ? "text-amber-400" : "text-primary/70";
  const inner = (
    <div
      className={`flex items-center gap-2.5 rounded-lg border border-border bg-secondary/20 px-3 py-2 h-full ${
        href ? "hover:border-primary/40 transition-colors" : ""
      }`}
    >
      <Icon className={`w-4 h-4 shrink-0 ${iconColor}`} aria-hidden="true" />
      <div className="min-w-0 flex-1">
        <p className="text-[10px] uppercase tracking-wider text-muted-foreground/60 leading-none mb-0.5">{label}</p>
        <p className={`text-sm font-mono truncate ${valueColor}`}>{value}</p>
        {sub && <p className="text-[10px] font-mono text-muted-foreground/50 truncate">{sub}</p>}
      </div>
      {href && <ExternalLink className="w-3.5 h-3.5 text-muted-foreground/50 shrink-0" aria-hidden="true" />}
    </div>
  );
  return href ? (
    <a href={href} target="_blank" rel="noopener noreferrer" className="block">
      {inner}
    </a>
  ) : (
    inner
  );
}

function ProvenanceCard({ name, prov }: { name: string; prov: Provenance }) {
  const repo = prov.repo;
  return (
    <div className="card-noir p-4 sm:p-5 border border-border space-y-3">
      <div className="flex items-center gap-2">
        <Fingerprint className="w-4 h-4 text-primary/80" aria-hidden="true" />
        <h4 className="font-mono text-xs uppercase tracking-widest text-muted-foreground/70">
          Provenance — where this really comes from
        </h4>
      </div>

      <div className="grid sm:grid-cols-2 gap-2">
        {/* Official npm page */}
        <ProvRow icon={Package} label="Official npm page" value={`npmjs.com/package/${name}`} href={prov.npmUrl} />

        {/* Source repository */}
        {repo.url ? (
          <ProvRow
            icon={GitBranch}
            label={`Source repo${repo.host && repo.host !== "other" ? ` · ${repo.host}` : ""}`}
            value={repo.owner && repo.name ? `${repo.owner}/${repo.name}` : repo.url.replace(/^https?:\/\//, "")}
            href={repo.url}
            sub={repo.directory ? `↳ ${repo.directory}` : undefined}
          />
        ) : (
          <ProvRow icon={GitBranch} label="Source repo" value="none declared" tone="warn" />
        )}

        {/* Signed build provenance */}
        {prov.signedProvenance ? (
          <ProvRow
            icon={BadgeCheck}
            label="Build provenance"
            value="Signed · Sigstore / SLSA"
            href={prov.attestationUrl || undefined}
          />
        ) : (
          <ProvRow icon={BadgeCheck} label="Build provenance" value="Not signed" tone="muted" />
        )}

        {/* Homepage */}
        {prov.homepage && (
          <ProvRow
            icon={Globe}
            label="Homepage"
            value={prov.homepage.replace(/^https?:\/\//, "").replace(/\/$/, "")}
            href={prov.homepage}
          />
        )}
      </div>

      {prov.homepageRepoMismatch && (
        <p className="text-xs text-amber-300/90 flex items-start gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden="true" />
          Homepage points at a different GitHub repo than the declared source — confirm which one is authoritative before
          trusting its install instructions.
        </p>
      )}
      {!repo.url && (
        <p className="text-xs text-muted-foreground/70 flex items-start gap-1.5">
          <ShieldAlert className="w-3.5 h-3.5 mt-0.5 shrink-0 text-amber-400" aria-hidden="true" />
          No public source repo is declared, so the published code can’t be diffed against reviewable source.
        </p>
      )}
    </div>
  );
}

// ── Version trend ─────────────────────────────────────────────────────────────

function VersionTrendCard({ trend }: { trend: VersionTrend }) {
  const pts = trend.points;
  const DirIcon = trend.direction === "improving" ? TrendingUp : trend.direction === "declining" ? TrendingDown : Minus;
  const dirColor =
    trend.direction === "improving"
      ? "text-success border-success/40 bg-success/10"
      : trend.direction === "declining"
      ? "text-red-400 border-red-600/40 bg-red-950/40"
      : "text-muted-foreground border-border bg-secondary/30";

  return (
    <div className="card-noir p-4 sm:p-5 border border-border space-y-4">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div className="flex items-center gap-2">
          <History className="w-4 h-4 text-primary/80" aria-hidden="true" />
          <h4 className="font-mono text-xs uppercase tracking-widest text-muted-foreground/70">
            Security score across recent versions
          </h4>
        </div>
        {trend.delta != null && (
          <span className={`inline-flex items-center gap-1 font-mono text-xs px-2 py-0.5 rounded-full border ${dirColor}`}>
            <DirIcon className="w-3.5 h-3.5" aria-hidden="true" />
            {trend.delta > 0 ? "+" : ""}
            {trend.delta} over {pts.length} versions
          </span>
        )}
      </div>

      {/* Bars — one per version, oldest → newest */}
      <div className="flex items-end justify-between gap-2 sm:gap-3">
        {pts.map((p, i) => {
          const g = gradeStyle(p.grade);
          const newest = i === pts.length - 1;
          return (
            <div key={p.version} className="flex-1 flex flex-col items-center gap-1.5 min-w-0">
              <span className={`text-[11px] font-mono ${newest ? g.text : "text-muted-foreground/70"}`}>{p.score}</span>
              <div className="w-full flex items-end h-20 bg-black/30 rounded-md overflow-hidden">
                <div
                  className={`w-full rounded-md transition-all duration-700 ${gradeBar(p.grade)} ${newest ? "" : "opacity-70"}`}
                  style={{ height: `${Math.max(6, p.score)}%` }}
                  title={`${p.version}: ${p.grade} (${p.score}/100)${p.cveCount ? ` · ${p.cveCount} CVE${p.cveCount === 1 ? "" : "s"}` : ""}`}
                />
              </div>
              <span className={`text-[10px] font-mono truncate max-w-full ${newest ? "text-foreground/90" : "text-muted-foreground/70"}`}>
                {p.version}
              </span>
              {p.cveCount > 0 ? (
                <span className="text-[9px] font-mono text-red-400/80 leading-none">{p.cveCount} CVE</span>
              ) : (
                <span className="text-[9px] font-mono text-muted-foreground/30 leading-none">clean</span>
              )}
            </div>
          );
        })}
      </div>

      {/* Trajectory narrative — oldest → newest across the shown window */}
      {(trend.improved.length > 0 || trend.declined.length > 0) && (
        <p className="text-xs text-muted-foreground leading-relaxed">
          <span className="text-muted-foreground/60">
            {pts[0].version} → {pts[pts.length - 1].version}:{" "}
          </span>
          {trend.improved.length > 0 && <span className="text-success">↑ improved {trend.improved.join(", ")}</span>}
          {trend.improved.length > 0 && trend.declined.length > 0 && <span className="text-muted-foreground/40"> · </span>}
          {trend.declined.length > 0 && <span className="text-red-400">↓ declined {trend.declined.join(", ")}</span>}
        </p>
      )}
      {trend.improved.length === 0 && trend.declined.length === 0 && (
        <p className="text-xs text-muted-foreground/70">Scored signals held steady across the last {pts.length} versions.</p>
      )}
    </div>
  );
}

// ── Report card ───────────────────────────────────────────────────────────────

function ReportCard({ report }: { report: ScanReport }) {
  const g = gradeStyle(report.grade);
  const counts = report.findings.reduce<Record<string, number>>((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
  const clean = report.findings.length === 0;
  const dl = report.meta.weeklyDownloads;

  return (
    <div className="mt-6 space-y-4 animate-fade-up">
      {/* Grade banner */}
      <div className={`card-noir p-6 flex flex-col sm:flex-row items-center gap-6 border ${g.ring} ${g.glow}`}>
        <div className={`shrink-0 w-24 h-24 rounded-2xl border-2 ${g.ring} bg-black/40 flex flex-col items-center justify-center`}>
          <span className={`font-display text-5xl font-bold ${g.text} leading-none`}>{report.grade}</span>
          <span className="text-[10px] font-mono text-muted-foreground/60 mt-1">GRADE</span>
        </div>
        <div className="flex-1 text-center sm:text-left">
          <div className="flex items-center justify-center sm:justify-start gap-2 mb-1">
            {clean ? (
              <ShieldCheck className="w-5 h-5 text-success" />
            ) : (
              <ShieldAlert className={`w-5 h-5 ${g.text}`} />
            )}
            <h3 className="font-mono text-lg text-foreground">
              {report.name}
              <span className="text-muted-foreground/70">@{report.meta.version}</span>
            </h3>
          </div>
          <p className="text-sm text-muted-foreground mb-3 max-w-xl">
            {clean
              ? "No known vulnerabilities or supply-chain red flags on this version."
              : `${report.findings.length} finding${report.findings.length === 1 ? "" : "s"}: ` +
                (["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[])
                  .filter((s) => counts[s])
                  .map((s) => `${counts[s]} ${s.toLowerCase()}`)
                  .join(" · ")}
          </p>
          {/* Score bar */}
          <div className="flex items-center gap-3">
            <div className="flex-1 h-2 rounded-full bg-black/40 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all duration-700 ${gradeBar(report.grade)}`}
                style={{ width: `${report.score}%` }}
              />
            </div>
            <span className="font-mono text-sm text-foreground/80 w-16 text-right">{report.score}/100</span>
          </div>
        </div>
      </div>

      {/* Metadata grid */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
        <MetaChip
          icon={Download}
          label="Downloads/wk"
          value={
            dl == null
              ? "—"
              : dl >= 1_000_000
              ? `${(dl / 1_000_000).toFixed(dl >= 10_000_000 ? 0 : 1)}M`
              : dl >= 1000
              ? `${Math.round(dl / 1000)}k`
              : String(dl)
          }
        />
        <MetaChip icon={Scale} label="License" value={report.meta.license || "none"} />
        <MetaChip icon={Users} label="Maintainers" value={String(report.meta.maintainers || "—")} />
        <MetaChip
          icon={Clock}
          label="Last release"
          value={
            report.meta.lastActivityDays == null
              ? "—"
              : report.meta.lastActivityDays < 1
              ? "today"
              : report.meta.lastActivityDays < 60
              ? `${report.meta.lastActivityDays}d ago`
              : `${Math.round(report.meta.lastActivityDays / 30)}mo ago`
          }
        />
      </div>

      {/* Provenance — where the package really comes from */}
      {report.provenance && <ProvenanceCard name={report.name} prov={report.provenance} />}

      {/* Version-over-version security trend */}
      {report.versionTrend && report.versionTrend.points.length >= 2 && (
        <VersionTrendCard trend={report.versionTrend} />
      )}

      {/* Findings */}
      {clean ? (
        <div className="rounded-lg border border-success/30 bg-success/5 px-4 py-6 text-center">
          <ShieldCheck className="w-8 h-8 text-success mx-auto mb-2" />
          <p className="text-sm text-foreground/80">Clean bill of health on this version — nothing flagged.</p>
        </div>
      ) : (
        <div className="space-y-2">
          <p className="text-xs font-mono text-muted-foreground/60 uppercase tracking-widest px-1">
            Findings — click any row to expand
          </p>
          {report.findings.map((f, i) => (
            <FindingRow key={`${f.ruleId}-${i}`} finding={f} />
          ))}
        </div>
      )}

      {/* Disclaimer + CTA */}
      <p className="text-center text-xs text-muted-foreground/50 leading-relaxed pt-1">
        Free single-package check using live OSV data + the Shellockolm rubric. For full lockfile, transitive
        dependency, secrets and AI-agent scanning, run the CLI on your own project.
      </p>
    </div>
  );
}

// ── Main section ──────────────────────────────────────────────────────────────

const PackageScannerSection = () => {
  const [spec, setSpec] = useState("");
  const [status, setStatus] = useState<"idle" | "scanning" | "done" | "error">("idle");
  const [report, setReport] = useState<ScanReport | null>(null);
  const [errorMsg, setErrorMsg] = useState("");
  const [lineIdx, setLineIdx] = useState(0);
  const tickRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopTicker = useCallback(() => {
    if (tickRef.current) clearInterval(tickRef.current);
    tickRef.current = null;
  }, []);

  useEffect(() => () => stopTicker(), [stopTicker]);

  const runScan = useCallback(
    async (raw: string) => {
      const query = raw.trim();
      if (!query || status === "scanning") return;

      setStatus("scanning");
      setReport(null);
      setErrorMsg("");
      setLineIdx(0);

      // Animate scanning lines while the network work happens.
      stopTicker();
      tickRef.current = setInterval(() => {
        setLineIdx((i) => (i < SCAN_LINES.length - 1 ? i + 1 : i));
      }, 360);

      const started = Date.now();
      let result: ScanReport;
      try {
        result = await scanPackage(query);
      } catch (e: any) {
        stopTicker();
        setErrorMsg(e?.message || "Scan failed. Please try again.");
        setStatus("error");
        return;
      }

      // Keep the animation on screen for at least ~1.3s so it never flickers.
      const elapsed = Date.now() - started;
      const wait = Math.max(0, 1500 - elapsed);
      setTimeout(() => {
        stopTicker();
        if (!result.ok) {
          setErrorMsg(result.error || "Package not found.");
          setStatus("error");
        } else {
          setReport(result);
          setStatus("done");
        }
      }, wait);
    },
    [status, stopTicker],
  );

  const onSubmit = (e: FormEvent) => {
    e.preventDefault();
    runScan(spec);
  };

  return (
    <section id="scan" aria-label="Free npm package scanner" className="relative py-24 overflow-hidden">
      {/* Background */}
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-30"
        aria-hidden="true"
        style={{ backgroundImage: `radial-gradient(ellipse 70% 50% at 50% 0%, hsl(var(--gold) / 0.12), transparent)` }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Header */}
        <div className="text-center mb-10 max-w-2xl mx-auto">
          <span className="badge-detective mb-6 inline-flex">
            <Search className="w-4 h-4" aria-hidden="true" />
            Free Package Scanner
          </span>
          <h2 className="font-display text-4xl sm:text-5xl font-bold mb-4 leading-tight">
            Worried about a package? <span className="text-gradient-gold">Scan it free.</span>
          </h2>
          <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
            Type any npm package — get an instant security report: known CVEs, supply-chain red flags, install-script
            risk and an A–F grade. No sign-up, no install, nothing leaves your browser except the package name.
          </p>
        </div>

        {/* Search box */}
        <div className="max-w-2xl mx-auto">
          <form onSubmit={onSubmit} className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Package className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground/60" aria-hidden="true" />
              <input
                type="text"
                value={spec}
                onChange={(e) => setSpec(e.target.value)}
                placeholder="e.g. express  or  lodash@4.17.20"
                aria-label="npm package name"
                autoCapitalize="off"
                autoCorrect="off"
                spellCheck={false}
                className="w-full pl-12 pr-4 py-4 rounded-xl bg-secondary/30 border border-border font-mono text-sm text-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-2 focus:ring-primary focus:border-primary transition-all"
              />
            </div>
            <Button
              type="submit"
              size="lg"
              disabled={status === "scanning" || !spec.trim()}
              className="bg-primary text-primary-foreground hover:bg-primary/90 px-8 py-4 h-auto text-base font-semibold glow-ultramarine shrink-0"
            >
              {status === "scanning" ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" /> Scanning…
                </>
              ) : (
                <>
                  <Search className="w-4 h-4" /> Scan
                </>
              )}
            </Button>
          </form>

          {/* Example chips */}
          <div className="flex flex-wrap items-center justify-center gap-2 mt-4">
            <span className="text-xs text-muted-foreground/50 font-mono">try:</span>
            {EXAMPLES.map((ex) => (
              <button
                key={ex}
                onClick={() => {
                  setSpec(ex);
                  runScan(ex);
                }}
                disabled={status === "scanning"}
                className="px-3 py-1 rounded-full border border-border bg-secondary/20 font-mono text-xs text-muted-foreground hover:border-primary/40 hover:text-foreground transition-colors disabled:opacity-50"
              >
                {ex}
              </button>
            ))}
          </div>

          {/* Scanning terminal */}
          {status === "scanning" && (
            <div className="terminal-window mt-6" aria-live="polite">
              <div className="terminal-header">
                <div className="terminal-dot bg-danger" aria-hidden="true" />
                <div className="terminal-dot bg-gold" aria-hidden="true" />
                <div className="terminal-dot bg-success" aria-hidden="true" />
                <span className="ml-3 text-sm text-muted-foreground font-mono truncate">shellockolm — scanning {spec.trim()}</span>
              </div>
              <div className="terminal-body space-y-1.5 min-h-[200px]">
                <p className="text-muted-foreground text-sm">$ shellockolm scan {spec.trim()}</p>
                {SCAN_LINES.slice(0, lineIdx + 1).map((line, i) => {
                  const active = i === lineIdx;
                  return (
                    <div key={i} className="text-sm font-mono leading-snug">
                      <p>
                        <span className="text-primary/60" aria-hidden="true">  › </span>
                        <span className={active ? "text-foreground/90" : "text-muted-foreground"}>{line.step}</span>
                        {active ? (
                          <span className="inline-block w-1.5 h-1.5 bg-primary rounded-full ml-2 animate-pulse align-middle" aria-hidden="true" />
                        ) : (
                          <span className="text-success/70 ml-1.5" aria-hidden="true">✓</span>
                        )}
                      </p>
                      <p className="pl-6 text-[11px] text-muted-foreground/45">
                        <span aria-hidden="true">↳ </span>catching {line.catch}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Error */}
          {status === "error" && (
            <div className="mt-6 rounded-xl border border-red-700/50 bg-red-950/40 px-4 py-4 text-center" role="alert">
              <ShieldAlert className="w-6 h-6 text-red-400 mx-auto mb-2" />
              <p className="text-sm text-red-200/90">{errorMsg}</p>
            </div>
          )}

          {/* Report */}
          {status === "done" && report && <ReportCard report={report} />}
        </div>

        {/* CTA */}
        <div className="text-center mt-12">
          <Button
            size="lg"
            variant="outline"
            className="border-primary/50 hover:bg-primary/10 text-primary hover:text-primary px-8 py-6 text-base font-semibold"
            onClick={() =>
              window.open("https://github.com/hlsitechio/Shellockolm-AI-CLI-MCP-Scanner", "_blank", "noopener noreferrer")
            }
          >
            Scan your whole project with the CLI — Free
          </Button>
          <p className="mt-3 text-xs text-muted-foreground/50">Powered by OSV.dev + the Shellockolm engine · no key, no telemetry</p>
        </div>
      </div>
    </section>
  );
};

export default PackageScannerSection;
