import { Check, ShieldCheck, Wrench, RefreshCw, Mail, ArrowRight } from "lucide-react";
import { Button } from "@/components/ui/button";

// ── Stripe Payment Links ─────────────────────────────────────────────
// Paste your hosted Stripe Payment Link URLs here (create them in the
// Stripe dashboard → Payment Links). They look like:
//   https://buy.stripe.com/xxxxxxxxxxxxxxxx
// NEVER put a secret key (sk_live_...) in this file or anywhere in the
// frontend — Payment Links need no keys at all. If a link is left blank,
// the button falls back to an email enquiry.
const PAYMENT_LINKS = {
  express: "https://buy.stripe.com/aFadRaa9efwBdOZ4tE3Je02",
  auditFix: "https://buy.stripe.com/eVq28s1CI4RXdOZ1hs3Je03",
  retainer: "https://buy.stripe.com/28EcN66X2acheT35xI3Je04",
};

const CONTACT_EMAIL = "hlarosesurprenant@gmail.com";

type Plan = {
  icon: typeof ShieldCheck;
  name: string;
  price: string;
  cadence: string;
  blurb: string;
  features: string[];
  link: string;
  featured?: boolean;
};

const plans: Plan[] = [
  {
    icon: ShieldCheck,
    name: "Express Audit",
    price: "$2,000",
    cadence: "fixed scope · ~3 days",
    blurb: "A scan, triaged by a human, for one app or repo.",
    features: [
      "Full Shellockolm scan + manual triage",
      "False-positive filtering — signal, not noise",
      "Findings ranked by real exploitability",
      "1-hour walkthrough call",
      "Prioritized remediation plan",
    ],
    link: PAYMENT_LINKS.express,
  },
  {
    icon: Wrench,
    name: "Audit + Remediation",
    price: "$6,000",
    cadence: "fixed scope · ~2 weeks",
    blurb: "Everything in Express Audit — and I fix it with you.",
    features: [
      "Dependency upgrades with verified builds",
      "Secrets rotation + leak cleanup",
      "CI integration so regressions get caught",
      "Re-scan + sign-off report for your records",
    ],
    link: PAYMENT_LINKS.auditFix,
    featured: true,
  },
  {
    icon: RefreshCw,
    name: "Hardening Retainer",
    price: "$1,500",
    cadence: "per month",
    blurb: "Ongoing coverage for teams shipping fast.",
    features: [
      "Monthly scan + report",
      "New-CVE watch on the deps you actually use",
      "Up to 4 hrs/mo remediation or advisory",
      "48-hour response on critical findings",
    ],
    link: PAYMENT_LINKS.retainer,
  },
];

const PricingSection = () => {
  const book = (plan: Plan) => {
    if (plan.link) {
      window.open(plan.link, "_blank", "noopener noreferrer");
      return;
    }
    const subject = encodeURIComponent(`Shellockolm: ${plan.name}`);
    const body = encodeURIComponent(
      `Hi — I'd like to book the ${plan.name} (${plan.price}).\n\nMy stack / repo:\nWhat prompted this:\n`
    );
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`;
  };

  return (
    <section aria-label="Professional services and pricing" className="relative py-28 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-dark" aria-hidden="true" />
      <div
        className="absolute inset-0 opacity-25"
        aria-hidden="true"
        style={{
          backgroundImage: `radial-gradient(ellipse 60% 40% at 50% 30%, hsl(var(--ultramarine) / 0.15), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-4 sm:px-6">
        {/* Section header */}
        <div className="text-center mb-16 max-w-2xl mx-auto">
          <span className="badge-detective mb-6 inline-flex">
            <ShieldCheck className="w-4 h-4" aria-hidden="true" />
            Human Services
          </span>
          <h2 className="font-display text-4xl sm:text-5xl font-bold mb-5 leading-tight">
            The tool is free.{" "}
            <span className="text-gradient-ultramarine">Your time isn't.</span>
          </h2>
          <p className="text-muted-foreground text-base sm:text-lg leading-relaxed">
            Ran the scanner and it found something real? These are the human
            services that verify it, fix it, and harden the rest of your stack.
          </p>
        </div>

        {/* Pricing cards */}
        <div
          className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto items-stretch"
          role="list"
          aria-label="Service plans"
        >
          {plans.map((plan) => {
            const Icon = plan.icon;
            return (
              <div
                key={plan.name}
                role="listitem"
                className={`relative flex flex-col rounded-xl border backdrop-blur-sm p-7 sm:p-8 transition-all duration-300 ${
                  plan.featured
                    ? "border-primary glow-ultramarine bg-secondary/30 scale-[1.02] md:scale-105"
                    : "border-border hover:border-primary/50 bg-secondary/15 hover:bg-secondary/20"
                }`}
              >
                {/* Featured badge */}
                {plan.featured && (
                  <span
                    className="absolute -top-3.5 left-1/2 -translate-x-1/2 badge-detective text-xs whitespace-nowrap"
                    aria-label="Most popular plan"
                  >
                    Most popular
                  </span>
                )}

                {/* Icon + name */}
                <div className="flex items-center gap-3 mb-5">
                  <div
                    className={`p-2.5 rounded-xl ${
                      plan.featured ? "bg-primary/20 text-primary" : "bg-secondary text-primary"
                    }`}
                  >
                    <Icon className="w-6 h-6" aria-hidden="true" />
                  </div>
                  <h3 className="font-display text-xl font-bold">{plan.name}</h3>
                </div>

                {/* Price */}
                <div className="mb-1">
                  <span className="text-4xl font-bold text-gradient-ultramarine">
                    {plan.price}
                  </span>
                </div>
                <p className="text-xs text-muted-foreground mb-4 font-mono">{plan.cadence}</p>

                {/* Blurb */}
                <p className="text-sm text-foreground/90 mb-6 leading-relaxed border-b border-border/50 pb-6">
                  {plan.blurb}
                </p>

                {/* Feature list */}
                <ul className="space-y-3 mb-8 flex-1" aria-label={`${plan.name} features`}>
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-2.5 text-sm text-muted-foreground">
                      <Check
                        className="w-4 h-4 text-success shrink-0 mt-0.5"
                        aria-hidden="true"
                      />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>

                {/* CTA */}
                <Button
                  size="lg"
                  variant={plan.featured ? "default" : "outline"}
                  className={`w-full group ${
                    plan.featured
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 glow-ultramarine"
                      : "border-border hover:border-primary/50 hover:bg-secondary/50"
                  }`}
                  onClick={() => book(plan)}
                  aria-label={`Book ${plan.name} — ${plan.price}`}
                >
                  Book {plan.name}
                  <ArrowRight
                    className="w-4 h-4 ml-1 transition-transform group-hover:translate-x-0.5"
                    aria-hidden="true"
                  />
                </Button>
              </div>
            );
          })}
        </div>

        {/* Footer actions */}
        <div className="text-center mt-14 max-w-xl mx-auto space-y-5">
          <Button
            variant="ghost"
            className="text-muted-foreground hover:text-foreground gap-2"
            onClick={() => {
              window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(
                "Shellockolm: custom security work"
              )}`;
            }}
            aria-label="Email for custom security work enquiry"
          >
            <Mail className="w-4 h-4" aria-hidden="true" />
            Need something custom? Email me
          </Button>
          <p className="text-xs text-muted-foreground/60 leading-relaxed">
            No "zero false positives" or "100% success" guarantees — security
            doesn't work that way. You get honest findings and real fixes.
          </p>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
