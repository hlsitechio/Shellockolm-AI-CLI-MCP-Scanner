// ── Shellockolm free NPM package scanner — browser engine ─────────────────────
//
// Runs entirely client-side ($0, no backend). It combines LIVE vulnerability data
// with the same heuristic categories the Shellockolm CLI/MCP scanner uses:
//
//   • OSV.dev            → every known CVE/GHSA for the exact package + version
//   • Supply-chain list  → known-compromised packages OSV won't flag as CVEs
//                          (Shai-Hulud worm campaign, eslint-config-prettier, …)
//   • Install-script     → pre/post-install RCE surface (top supply-chain vector)
//   • Typosquat          → Levenshtein-1 against the most-installed packages
//   • Package health     → deprecated, unmaintained, single-maintainer, brand-new
//   • Weighted A+→F grade → mirrors src/security_score.py
//
// Data sources are all public + CORS-enabled: registry.npmjs.org, api.npmjs.org,
// and api.osv.dev. No API keys, no telemetry.

// ── Types ─────────────────────────────────────────────────────────────────────

export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export interface Finding {
  severity: Severity;
  ruleId: string;
  title: string;
  detail: string;
  ref?: string; // optional URL for more info (CVE/GHSA/advisory)
}

export interface ScanMeta {
  description: string;
  license: string;
  version: string; // resolved version that was scanned
  latest: string;
  requested: string; // exactly what the user typed
  publishedAt: string | null; // ISO date the scanned version was published
  lastActivityDays: number | null; // days since the newest publish (staleness)
  ageDays: number | null; // days since first release
  maintainers: number;
  weeklyDownloads: number | null;
  deprecated: string | null;
  repository: string | null;
  homepage: string | null;
}

export type RepoHost = "github" | "gitlab" | "bitbucket" | "other" | null;

// Where does this package REALLY come from? Everything here is derived from the
// same registry packument we already fetch — no extra network calls.
export interface Provenance {
  npmUrl: string; // canonical npm page for this exact name
  repo: {
    url: string | null; // normalized https URL to the source repo
    host: RepoHost;
    owner: string | null; // e.g. "dcastil"
    name: string | null; // e.g. "tailwind-merge"
    directory: string | null; // monorepo subpath, if declared
  };
  homepage: string | null;
  signedProvenance: boolean; // npm published with --provenance (Sigstore/SLSA attestation)
  attestationUrl: string | null; // link to the signed attestation bundle
  homepageRepoMismatch: boolean; // homepage points at a DIFFERENT github repo than the source
}

export interface ScoreBreakdown {
  vulnerabilities: number;
  malware: number;
  health: number;
  dependencies: number;
  configuration: number;
}

// Human labels for each score bucket — used when narrating what moved between
// versions ("Vulnerabilities improved", "Dependencies declined").
export const BUCKET_LABELS: Record<keyof ScoreBreakdown, string> = {
  vulnerabilities: "Vulnerabilities",
  malware: "Supply chain",
  health: "Maintenance",
  dependencies: "Dependencies",
  configuration: "Metadata",
};

// One graded point in the version-history trend.
export interface VersionScore {
  version: string;
  publishedAt: string | null;
  score: number; // 0..100
  grade: string;
  cveCount: number; // known CVEs affecting this exact version
  worst: Severity | null; // worst severity among those CVEs
  buckets: ScoreBreakdown;
}

// How the security score has moved across the most recent published versions —
// mirrors what Socket.dev surfaces as "N metric improved / N decreased".
export interface VersionTrend {
  points: VersionScore[]; // oldest → newest (natural left-to-right)
  delta: number | null; // newest.score − previous.score
  improved: string[]; // bucket labels that got better newest-vs-previous
  declined: string[]; // bucket labels that got worse
  direction: "improving" | "declining" | "stable";
}

export interface ScanReport {
  ok: boolean;
  name: string;
  grade: string; // A+ .. F
  score: number; // 0 .. 100
  breakdown: ScoreBreakdown;
  findings: Finding[];
  meta: ScanMeta;
  provenance?: Provenance; // where the package really comes from
  versionTrend?: VersionTrend | null; // score across recent versions
  scannedAt: string;
  error?: string;
}

// ── Shellockolm supply-chain intelligence (ported from src/scanners) ──────────
// Known-compromised packages. OSV/CVE feeds frequently miss active malware
// campaigns, so this curated list is the scanner's differentiator.

interface CompromisedEntry {
  maliciousVersions: string[] | "ALL"; // "ALL" = every published version is tainted
  severity: Severity;
  campaign?: string;
  cve?: string;
  description: string;
}

const COMPROMISED_PACKAGES: Record<string, CompromisedEntry> = {
  "eslint-config-prettier": {
    maliciousVersions: ["8.10.1", "9.1.1", "10.1.6", "10.1.7"],
    severity: "HIGH",
    cve: "CVE-2025-54313",
    description:
      "Maintainer phishing attack pushed a malicious 'Scavenger' DLL payload in these versions. Upgrade to 8.10.2 / 9.1.2 / 10.1.8 or later.",
  },
  "eslint-plugin-prettier": {
    maliciousVersions: "ALL",
    severity: "MEDIUM",
    cve: "CVE-2025-54313",
    description:
      "Package related to the eslint-config-prettier maintainer compromise — verify the exact version you pin against the advisory.",
  },
  synckit: {
    maliciousVersions: "ALL",
    severity: "MEDIUM",
    cve: "CVE-2025-54313",
    description:
      "Package linked to the eslint-config-prettier compromise chain — verify your pinned version against the advisory.",
  },
  "@postman/security-helpers": {
    maliciousVersions: "ALL",
    severity: "CRITICAL",
    campaign: "Shai-Hulud",
    description: "Shai-Hulud worm campaign — credential-stealing malware. Do not install.",
  },
  "@posthog/plugin-geoip": {
    maliciousVersions: "ALL",
    severity: "CRITICAL",
    campaign: "Shai-Hulud",
    description: "Shai-Hulud worm campaign — credential-stealing malware. Do not install.",
  },
  "@asyncapi/openapi-schema-parser": {
    maliciousVersions: "ALL",
    severity: "CRITICAL",
    campaign: "Shai-Hulud",
    description: "Shai-Hulud worm campaign — credential-stealing malware. Do not install.",
  },
  "@ensdomains/content-hash": {
    maliciousVersions: "ALL",
    severity: "CRITICAL",
    campaign: "Shai-Hulud",
    description: "Shai-Hulud worm campaign — credential-stealing malware. Do not install.",
  },
  "@zapier/secret-scrubber": {
    maliciousVersions: "ALL",
    severity: "CRITICAL",
    campaign: "Shai-Hulud",
    description: "Shai-Hulud worm campaign — credential-stealing malware. Do not install.",
  },
};

// Most-installed packages — targets that typosquatters imitate. A user-supplied
// name that is exactly one edit away from one of these (but not equal to it) is
// a likely typosquat.
const POPULAR_PACKAGES = [
  "react", "react-dom", "next", "vue", "angular", "svelte", "express", "koa",
  "fastify", "lodash", "underscore", "axios", "node-fetch", "got", "request",
  "chalk", "commander", "yargs", "inquirer", "debug", "moment", "dayjs",
  "date-fns", "webpack", "vite", "rollup", "esbuild", "babel", "typescript",
  "eslint", "prettier", "jest", "mocha", "chai", "vitest", "dotenv", "cors",
  "body-parser", "mongoose", "sequelize", "prisma", "pg", "mysql", "mysql2",
  "redis", "ioredis", "socket.io", "ws", "redux", "zustand", "rxjs", "three",
  "uuid", "nanoid", "async", "bluebird", "jquery", "bootstrap", "tailwindcss",
  "rimraf", "glob", "semver", "cross-env", "nodemon", "concurrently", "zod",
  "yup", "joi", "passport", "jsonwebtoken", "bcrypt", "helmet", "winston",
  "pino", "sharp", "puppeteer", "playwright", "cheerio", "handlebars", "ejs",
];

// ── Small helpers ─────────────────────────────────────────────────────────────

const DAY = 86_400_000;

function daysSince(iso: string | null): number | null {
  if (!iso) return null;
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return null;
  return Math.max(0, Math.round((Date.now() - t) / DAY));
}

// Classic Levenshtein edit distance (small strings, fine to run in the loop).
function levenshtein(a: string, b: string): number {
  if (a === b) return 0;
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    const cur = [i];
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
    }
    prev = cur;
  }
  return prev[n];
}

function clamp(n: number, lo = 0, hi = 100): number {
  return Math.max(lo, Math.min(hi, n));
}

// Parse "name", "name@version", "@scope/name", "@scope/name@version".
export function parseSpec(raw: string): { name: string; version: string | null } {
  const input = raw.trim();
  if (!input) return { name: "", version: null };
  const at = input.lastIndexOf("@");
  // No version, or the only "@" is the scope marker at position 0.
  if (at <= 0) return { name: input, version: null };
  return { name: input.slice(0, at), version: input.slice(at + 1) || null };
}

// Basic sanity check on a package name before hitting the network.
export function isValidName(name: string): boolean {
  if (!name || name.length > 214) return false;
  return /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/.test(name);
}

// ── Network layer ─────────────────────────────────────────────────────────────

async function fetchJSON(url: string, opts?: RequestInit, timeoutMs = 12_000): Promise<any> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    const res = await fetch(url, { ...opts, signal: ctrl.signal });
    if (!res.ok) {
      const err: any = new Error(`HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

// npm registry needs the "/" in a scoped name percent-encoded.
function registryUrl(name: string): string {
  return `https://registry.npmjs.org/${name.replace(/\//g, "%2F")}`;
}

async function fetchWeeklyDownloads(name: string): Promise<number | null> {
  try {
    const d = await fetchJSON(`https://api.npmjs.org/downloads/point/last-week/${name}`);
    return typeof d?.downloads === "number" ? d.downloads : null;
  } catch {
    return null; // downloads are best-effort; never fail the scan over them
  }
}

interface OsvVuln {
  id: string;
  summary?: string;
  details?: string;
  aliases?: string[];
  severity?: Array<{ type: string; score: string }>;
  database_specific?: { severity?: string };
  references?: Array<{ type?: string; url: string }>;
}

async function fetchOsv(name: string, version: string | null): Promise<OsvVuln[]> {
  try {
    const body: any = { package: { name, ecosystem: "npm" } };
    if (version) body.version = version;
    const d = await fetchJSON("https://api.osv.dev/v1/query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    return Array.isArray(d?.vulns) ? d.vulns : [];
  } catch {
    return []; // if OSV is unreachable we still return heuristic findings
  }
}

// Map an OSV record to our severity scale.
function osvSeverity(v: OsvVuln): Severity {
  const raw = (v.database_specific?.severity || "").toUpperCase();
  if (raw === "CRITICAL") return "CRITICAL";
  if (raw === "HIGH") return "HIGH";
  if (raw === "MODERATE" || raw === "MEDIUM") return "MEDIUM";
  if (raw === "LOW") return "LOW";

  // Fall back to a CVSS base score parsed from the vector string, if any.
  const cvss = v.severity?.find((s) => s.type?.startsWith("CVSS"));
  if (cvss) {
    const m = cvss.score.match(/\/?(\d{1,2}(?:\.\d)?)$/);
    const score = m ? parseFloat(m[1]) : NaN;
    if (!Number.isNaN(score)) {
      if (score >= 9) return "CRITICAL";
      if (score >= 7) return "HIGH";
      if (score >= 4) return "MEDIUM";
      return "LOW";
    }
  }
  return "MEDIUM";
}

function bestRef(v: OsvVuln): string {
  const adv = v.references?.find((r) => r.type === "ADVISORY");
  return adv?.url || v.references?.[0]?.url || `https://osv.dev/vulnerability/${v.id}`;
}

// Prefer a CVE alias over an internal OSV/GHSA id for display.
function displayId(v: OsvVuln): string {
  const cve = v.aliases?.find((a) => a.startsWith("CVE-"));
  return cve || v.id;
}

// ── Scoring (weights ported from src/security_score.py) ───────────────────────

const VULN_IMPACT: Record<Severity, number> = { CRITICAL: 15, HIGH: 10, MEDIUM: 5, LOW: 2, INFO: 0 };

const GRADES: Array<[number, string]> = [
  [95, "A+"],
  [90, "A"],
  [80, "B"],
  [70, "C"],
  [60, "D"],
  [0, "F"],
];

function gradeFor(score: number): string {
  for (const [floor, g] of GRADES) if (score >= floor) return g;
  return "F";
}

const SEV_ORDER: Record<Severity, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };

// ── Provenance ────────────────────────────────────────────────────────────────
// "Is this the REAL package?" — derive the canonical npm page, the true source
// repo (owner/name), and whether the build carries a signed Sigstore/SLSA
// attestation. All from the packument we already fetched — no extra requests.

// Pull "owner/repo" out of any GitHub URL, lowercased, for comparison.
function githubSlug(url: string | null): string | null {
  if (!url) return null;
  const m = String(url).match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#?]|$)/i);
  return m ? `${m[1].toLowerCase()}/${m[2].toLowerCase()}` : null;
}

// Normalize the many shapes an npm `repository` field can take into a clean
// https URL plus structured host/owner/name. Handles: git+https, git://,
// ssh/scp (git@github.com:owner/repo), and shorthands (github:owner/repo,
// owner/repo).
function normalizeRepo(raw: string | null, directory: string | null): Provenance["repo"] {
  const empty: Provenance["repo"] = { url: null, host: null, owner: null, name: null, directory: directory || null };
  if (!raw) return empty;
  let s = String(raw).trim().replace(/^git\+/, "");

  const HOSTS: Record<string, { host: RepoHost; base: string }> = {
    github: { host: "github", base: "https://github.com" },
    gitlab: { host: "gitlab", base: "https://gitlab.com" },
    bitbucket: { host: "bitbucket", base: "https://bitbucket.org" },
  };

  // Shorthand "github:owner/repo" / "gitlab:owner/repo" / "bitbucket:owner/repo".
  const short = s.match(/^(github|gitlab|bitbucket):(.+)$/i);
  if (short) {
    const { host, base } = HOSTS[short[1].toLowerCase()];
    const [owner, name] = short[2].replace(/\.git$/, "").split("/");
    return {
      url: owner && name ? `${base}/${owner}/${name}` : null,
      host, owner: owner || null, name: name || null, directory: directory || null,
    };
  }

  // Bare "owner/repo" — npm treats this as GitHub.
  if (/^[\w.-]+\/[\w.-]+$/.test(s)) {
    const [owner, name] = s.replace(/\.git$/, "").split("/");
    return { url: `https://github.com/${owner}/${name}`, host: "github", owner, name, directory: directory || null };
  }

  // Full URL forms — coerce ssh/scp/git into https so URL() can parse them.
  s = s.replace(/^git@([^:]+):/, "https://$1/").replace(/^ssh:\/\/git@/, "https://").replace(/^git:\/\//, "https://");
  try {
    const u = new URL(s);
    const hostname = u.hostname.toLowerCase().replace(/^www\./, "");
    const host: RepoHost = hostname.endsWith("github.com")
      ? "github"
      : hostname.endsWith("gitlab.com")
      ? "gitlab"
      : hostname.endsWith("bitbucket.org")
      ? "bitbucket"
      : "other";
    const parts = u.pathname.replace(/^\/+/, "").replace(/\.git$/, "").split("/").filter(Boolean);
    const owner = parts[0] || null;
    const name = parts[1] || null;
    const url =
      host !== "other" && owner && name
        ? `https://${hostname}/${owner}/${name}`
        : `${u.protocol}//${hostname}${u.pathname.replace(/\.git$/, "")}`.replace(/\/+$/, "");
    return { url, host, owner, name, directory: directory || null };
  } catch {
    return empty;
  }
}

function computeProvenance(name: string, vdoc: any, packument: any): Provenance {
  const repoField = vdoc.repository ?? packument.repository ?? null;
  const repoRaw = typeof repoField === "string" ? repoField : repoField?.url ?? null;
  const directory = (repoField && typeof repoField === "object" && repoField.directory) || null;
  const repo = normalizeRepo(repoRaw, directory);
  const homepage = vdoc.homepage || packument.homepage || null;

  // npm --provenance publishes a Sigstore bundle; the registry advertises it on
  // the version's dist object as `dist.attestations = { url, provenance }`.
  const att = vdoc.dist?.attestations;
  const signedProvenance = !!(att && att.provenance);
  const attestationUrl = (att && att.url) || null;

  // Does the homepage quietly point at a DIFFERENT github repo than the source?
  const repoSlug = repo.host === "github" && repo.owner && repo.name ? `${repo.owner.toLowerCase()}/${repo.name.toLowerCase()}` : null;
  const homeSlug = githubSlug(homepage);
  const homepageRepoMismatch = !!(repoSlug && homeSlug && repoSlug !== homeSlug);

  return {
    npmUrl: `https://www.npmjs.com/package/${name}`,
    repo,
    homepage,
    signedProvenance,
    attestationUrl,
    homepageRepoMismatch,
  };
}

// ── Version trend ─────────────────────────────────────────────────────────────
// Score the last few published versions with the same rubric so you can see the
// security trajectory — did a release patch a CVE, or bolt on an install hook?

// Lightweight per-version scorer. Uses only signals present on the version doc
// (+ that version's OSV hits), so every point is comparable across the history.
function scoreVersion(
  name: string,
  version: string,
  vdoc: any,
  osv: OsvVuln[],
  maintainerCount: number,
  publishedAt: string | null,
): VersionScore {
  const b: ScoreBreakdown = { vulnerabilities: 100, malware: 100, health: 100, dependencies: 100, configuration: 100 };

  // Vulnerabilities — dedupe by CVE id, keep the worst severity per id.
  const deduped = new Map<string, OsvVuln>();
  for (const v of osv) {
    const key = displayId(v);
    const ex = deduped.get(key);
    if (!ex || VULN_IMPACT[osvSeverity(v)] > VULN_IMPACT[osvSeverity(ex)]) deduped.set(key, v);
  }
  let worst: Severity | null = null;
  for (const v of deduped.values()) {
    const sev = osvSeverity(v);
    b.vulnerabilities -= VULN_IMPACT[sev];
    if (worst === null || SEV_ORDER[sev] < SEV_ORDER[worst]) worst = sev;
  }

  // Supply chain — known-compromised (version-specific) + install hooks.
  const comp = COMPROMISED_PACKAGES[name];
  if (comp && (comp.maliciousVersions === "ALL" || (comp.maliciousVersions as string[]).includes(version))) {
    b.malware -= comp.severity === "CRITICAL" ? 100 : comp.severity === "HIGH" ? 60 : 30;
  }
  const scripts = vdoc.scripts || {};
  if (["preinstall", "install", "postinstall"].some((h) => scripts[h])) b.malware -= 12;

  // Maintenance — deprecated flag (per-version) + bus factor (package-level).
  if (vdoc.deprecated) b.health -= 15;
  if (maintainerCount === 1) b.health -= 6;

  // Dependencies + metadata hygiene.
  if (Object.keys(vdoc.dependencies || {}).length > 40) b.dependencies -= 12;
  const lic = typeof vdoc.license === "string" ? vdoc.license : vdoc.license?.type;
  if (!lic) b.configuration -= 15;
  const repo = typeof vdoc.repository === "string" ? vdoc.repository : vdoc.repository?.url;
  if (!repo) b.configuration -= 8;

  for (const k of Object.keys(b) as (keyof ScoreBreakdown)[]) b[k] = clamp(b[k]);
  const score = Math.round(
    b.vulnerabilities * 0.3 + b.malware * 0.25 + b.health * 0.2 + b.dependencies * 0.15 + b.configuration * 0.1,
  );
  return { version, publishedAt, score, grade: gradeFor(score), cveCount: deduped.size, worst, buckets: b };
}

// Compare two dotted versions numerically (pre-releases are filtered out before
// this runs, so "3.10.0" > "3.9.0" sorts correctly, unlike a string compare).
function cmpSemver(a: string, b: string): number {
  const pa = a.split(".");
  const pb = b.split(".");
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (parseInt(pa[i], 10) || 0) - (parseInt(pb[i], 10) || 0);
    if (d) return d;
  }
  return 0;
}

async function computeVersionTrend(
  name: string,
  packument: any,
  seed: Record<string, OsvVuln[]>,
  maintainerCount: number,
): Promise<VersionTrend | null> {
  const time = packument.time || {};
  const versions = packument.versions || {};
  // Stable releases only (skip pre-releases). Order by SEMVER, not publish time,
  // so a version back-ported to an old line can't scramble the axis — the trend
  // reads cleanly low → high left-to-right.
  const stable = Object.keys(versions)
    .filter((v) => !v.includes("-") && time[v])
    .sort(cmpSemver);
  if (stable.length < 2) return null;
  const recent = stable.slice(-5); // the 5 highest versions, ascending

  // Fetch OSV for the versions we don't already hold, in parallel.
  const osvByVersion: Record<string, OsvVuln[]> = {};
  await Promise.all(
    recent.map(async (v) => {
      osvByVersion[v] = seed[v] ?? (await fetchOsv(name, v));
    }),
  );

  const points = recent.map((v) => scoreVersion(name, v, versions[v] || {}, osvByVersion[v] || [], maintainerCount, time[v] || null));

  // Trajectory across the whole shown window: oldest → newest. This is what
  // captures the real story ("3 CVEs patched over these releases"), which a
  // newest-vs-immediately-previous diff would miss.
  const oldest = points[0];
  const newest = points[points.length - 1];
  const delta = newest.score - oldest.score;
  const improved: string[] = [];
  const declined: string[] = [];
  for (const k of Object.keys(newest.buckets) as (keyof ScoreBreakdown)[]) {
    const d = newest.buckets[k] - oldest.buckets[k];
    if (d > 0) improved.push(BUCKET_LABELS[k]);
    else if (d < 0) declined.push(BUCKET_LABELS[k]);
  }
  const direction = Math.abs(delta) < 1 ? "stable" : delta > 0 ? "improving" : "declining";
  return { points, delta, improved, declined, direction };
}

// ── The scan ──────────────────────────────────────────────────────────────────

export async function scanPackage(rawSpec: string): Promise<ScanReport> {
  const { name, version: requestedVersion } = parseSpec(rawSpec);
  const scannedAt = new Date().toISOString();

  const emptyMeta: ScanMeta = {
    description: "",
    license: "",
    version: "",
    latest: "",
    requested: rawSpec.trim(),
    publishedAt: null,
    lastActivityDays: null,
    ageDays: null,
    maintainers: 0,
    weeklyDownloads: null,
    deprecated: null,
    repository: null,
    homepage: null,
  };

  if (!isValidName(name)) {
    return {
      ok: false,
      name,
      grade: "—",
      score: 0,
      breakdown: { vulnerabilities: 0, malware: 0, health: 0, dependencies: 0, configuration: 0 },
      findings: [],
      meta: emptyMeta,
      scannedAt,
      error: `"${rawSpec.trim() || "(empty)"}" is not a valid npm package name.`,
    };
  }

  // 1) Registry metadata — the backbone of the scan.
  let packument: any;
  try {
    packument = await fetchJSON(registryUrl(name));
  } catch (e: any) {
    const notFound = e?.status === 404;
    return {
      ok: false,
      name,
      grade: "—",
      score: 0,
      breakdown: { vulnerabilities: 0, malware: 0, health: 0, dependencies: 0, configuration: 0 },
      findings: [],
      meta: emptyMeta,
      scannedAt,
      error: notFound
        ? `Package "${name}" was not found on the npm registry.`
        : `Could not reach the npm registry (${e?.message || "network error"}). Try again.`,
    };
  }

  const latest: string = packument["dist-tags"]?.latest || "";

  // Resolve the version to scan. A requested version may be an exact match, a
  // dist-tag (e.g. "next"), or missing entirely — a version that was unpublished
  // is itself a signal (npm pulls malicious releases), so we keep track of it.
  let version = latest;
  let unresolvedRequest: string | null = null;
  if (requestedVersion) {
    if (packument.versions?.[requestedVersion]) version = requestedVersion;
    else if (packument["dist-tags"]?.[requestedVersion]) version = packument["dist-tags"][requestedVersion];
    else unresolvedRequest = requestedVersion;
  }
  const vdoc = packument.versions?.[version] || {};
  const time = packument.time || {};

  // Resolve display/meta fields.
  const licenseRaw = vdoc.license || packument.license;
  const license = typeof licenseRaw === "string" ? licenseRaw : licenseRaw?.type || "";
  const maintainers: any[] = packument.maintainers || vdoc.maintainers || [];
  const repository =
    (typeof vdoc.repository === "string" ? vdoc.repository : vdoc.repository?.url) ||
    (typeof packument.repository === "string" ? packument.repository : packument.repository?.url) ||
    null;
  const deprecated = vdoc.deprecated || null;
  const publishedAt = time[version] || null;
  const firstReleaseAt = time.created || null;
  const newestPublish = (latest && time[latest]) || time.modified || null;

  const weeklyDownloads = await fetchWeeklyDownloads(name);

  const meta: ScanMeta = {
    description: vdoc.description || packument.description || "",
    license: license || "",
    version,
    latest,
    requested: rawSpec.trim(),
    publishedAt,
    lastActivityDays: daysSince(newestPublish),
    ageDays: daysSince(firstReleaseAt),
    maintainers: maintainers.length,
    weeklyDownloads,
    deprecated,
    repository: repository ? String(repository).replace(/^git\+/, "").replace(/\.git$/, "") : null,
    homepage: packument.homepage || null,
  };

  // 2) Live CVEs from OSV.
  const osvVulns = await fetchOsv(name, version);

  // ── Build findings + category subscores ──────────────────────────────────
  const findings: Finding[] = [];
  const breakdown: ScoreBreakdown = {
    vulnerabilities: 100,
    malware: 100,
    health: 100,
    dependencies: 100,
    configuration: 100,
  };

  // Dedupe OSV records that share a CVE id — OSV returns one record per GHSA
  // advisory, and several GHSA can alias the same CVE. Collapse to the highest-
  // severity record per id so a single CVE is neither listed nor scored twice.
  const dedupedVulns = new Map<string, OsvVuln>();
  for (const v of osvVulns) {
    const key = displayId(v);
    const existing = dedupedVulns.get(key);
    if (!existing || VULN_IMPACT[osvSeverity(v)] > VULN_IMPACT[osvSeverity(existing)]) {
      dedupedVulns.set(key, v);
    }
  }

  // Known CVEs (vulnerabilities bucket)
  for (const v of dedupedVulns.values()) {
    const sev = osvSeverity(v);
    breakdown.vulnerabilities -= VULN_IMPACT[sev];
    findings.push({
      severity: sev,
      ruleId: displayId(v),
      title: v.summary || "Known vulnerability",
      detail:
        (v.details ? v.details.slice(0, 280).trim() + (v.details.length > 280 ? "…" : "") : "") ||
        "This version is affected by a published security advisory.",
      ref: bestRef(v),
    });
  }

  // If the user asked about a version that no longer exists, say so — npm pulls
  // malicious releases, so an unpublished pin is worth surfacing on its own.
  if (unresolvedRequest) {
    findings.push({
      severity: "INFO",
      ruleId: "META-VERSION-001",
      title: `Version ${unresolvedRequest} not on the registry — scanned ${version} instead`,
      detail:
        `The exact version you entered (${unresolvedRequest}) isn't published. It may never have existed, or it was unpublished — npm removes versions that are found to be malicious. Supply-chain findings below still evaluate the version you asked about.`,
    });
  }

  // Known-compromised / supply-chain campaign (malware bucket). Match against both
  // the resolved version AND the exact version the user typed, so a pulled bad
  // release is still caught even though the registry no longer serves it.
  const comp = COMPROMISED_PACKAGES[name];
  if (comp) {
    const candidates = [version, requestedVersion].filter(Boolean) as string[];
    const hit = comp.maliciousVersions === "ALL" || candidates.some((c) => (comp.maliciousVersions as string[]).includes(c));
    if (hit) {
      breakdown.malware -= comp.severity === "CRITICAL" ? 100 : comp.severity === "HIGH" ? 60 : 30;
      findings.push({
        severity: comp.severity,
        ruleId: comp.cve || (comp.campaign ? `SUPPLY-CHAIN/${comp.campaign}` : "SUPPLY-CHAIN"),
        title: comp.campaign
          ? `Known-compromised package (${comp.campaign} campaign)`
          : "Known-compromised package version",
        detail: comp.description,
        ref: comp.cve ? `https://osv.dev/vulnerability/${comp.cve}` : undefined,
      });
    }
  }

  // Install scripts (malware/supply-chain surface)
  const scripts = vdoc.scripts || {};
  const installHooks = ["preinstall", "install", "postinstall"].filter((h) => scripts[h]);
  if (installHooks.length) {
    breakdown.malware -= 12;
    findings.push({
      severity: "MEDIUM",
      ruleId: "SUPPLY-INSTALL-001",
      title: `Runs code on install (${installHooks.join(", ")})`,
      detail:
        "This package executes a script during `npm install`. Install hooks are the #1 supply-chain RCE vector — a compromised release runs on your machine and CI before you ever import the code. Review the script or install with --ignore-scripts.",
    });
  }

  // Typosquat check (malware bucket) — only for unscoped names not already flagged.
  if (!name.includes("/") && !comp) {
    for (const popular of POPULAR_PACKAGES) {
      if (name !== popular && Math.abs(name.length - popular.length) <= 1 && levenshtein(name, popular) === 1) {
        breakdown.malware -= 40;
        findings.push({
          severity: "HIGH",
          ruleId: "SUPPLY-TYPOSQUAT-001",
          title: `Possible typosquat of "${popular}"`,
          detail: `The name is a single character away from "${popular}", a very popular package. Typosquatters publish look-alike names to catch install typos and ship malware. Confirm this is the package you actually meant.`,
        });
        break;
      }
    }
  }

  // Deprecated (health bucket)
  if (deprecated) {
    breakdown.health -= 15;
    findings.push({
      severity: "MEDIUM",
      ruleId: "HEALTH-DEPRECATED-001",
      title: "Package version is deprecated",
      detail: `The maintainer flagged this version as deprecated: "${String(deprecated).slice(0, 200)}". Deprecated packages stop getting security fixes.`,
    });
  }

  // Unmaintained (health bucket)
  if (meta.lastActivityDays !== null && meta.lastActivityDays > 730) {
    breakdown.health -= 12;
    const years = (meta.lastActivityDays / 365).toFixed(1);
    findings.push({
      severity: "LOW",
      ruleId: "HEALTH-STALE-001",
      title: `No release in ${years} years`,
      detail:
        "The package hasn't published in over two years. Abandoned dependencies accumulate unpatched vulnerabilities and are prime targets for maintainer-account takeover.",
    });
  }

  // Single maintainer (health bucket)
  if (meta.maintainers === 1) {
    breakdown.health -= 6;
    findings.push({
      severity: "LOW",
      ruleId: "HEALTH-BUSFACTOR-001",
      title: "Single maintainer",
      detail:
        "Only one maintainer account controls this package. A single compromised or phished account is enough to push a malicious release to every consumer.",
    });
  }

  // Brand-new package (health bucket)
  if (meta.ageDays !== null && meta.ageDays < 30) {
    breakdown.health -= 8;
    findings.push({
      severity: "LOW",
      ruleId: "HEALTH-NEW-001",
      title: `Very new package (${meta.ageDays} day${meta.ageDays === 1 ? "" : "s"} old)`,
      detail:
        "This package was first published less than 30 days ago. New packages have little community scrutiny and are a common vehicle for typosquat and dependency-confusion attacks.",
    });
  }

  // Dependency surface (dependencies bucket)
  const deps = Object.keys(vdoc.dependencies || {});
  if (deps.length > 40) {
    breakdown.dependencies -= 12;
    findings.push({
      severity: "INFO",
      ruleId: "DEPS-SURFACE-001",
      title: `Large dependency surface (${deps.length} direct dependencies)`,
      detail:
        "A high number of direct dependencies widens the supply-chain attack surface — every one is transitive code you now trust. Consider lighter alternatives.",
    });
  }

  // Configuration hygiene (configuration bucket)
  if (!license) {
    breakdown.configuration -= 15;
    findings.push({
      severity: "LOW",
      ruleId: "CONFIG-LICENSE-001",
      title: "No license declared",
      detail:
        "The package publishes no license field. Beyond legal risk, a missing license is a mild signal of a low-effort or hastily-published package.",
    });
  }
  if (!repository) {
    breakdown.configuration -= 8;
    findings.push({
      severity: "INFO",
      ruleId: "CONFIG-REPO-001",
      title: "No source repository linked",
      detail:
        "No public repository is declared, so the published code can't be diffed against reviewable source. Legitimate popular packages almost always link their repo.",
    });
  }

  // Clamp buckets and compute the weighted total (same weights as the CLI).
  for (const k of Object.keys(breakdown) as (keyof ScoreBreakdown)[]) breakdown[k] = clamp(breakdown[k]);
  const score = Math.round(
    breakdown.vulnerabilities * 0.3 +
      breakdown.malware * 0.25 +
      breakdown.health * 0.2 +
      breakdown.dependencies * 0.15 +
      breakdown.configuration * 0.1,
  );

  // Sort findings by severity for display.
  findings.sort((a, b) => SEV_ORDER[a.severity] - SEV_ORDER[b.severity]);

  // Provenance is derived from the packument we already have (no extra calls).
  const provenance = computeProvenance(name, vdoc, packument);

  // Version trend reuses the OSV result for the scanned version as a seed, so it
  // only fetches the handful of other recent versions.
  const versionTrend = await computeVersionTrend(name, packument, { [version]: osvVulns }, maintainers.length);

  return {
    ok: true,
    name,
    grade: gradeFor(score),
    score,
    breakdown,
    findings,
    meta,
    provenance,
    versionTrend,
    scannedAt,
  };
}
