import { Check, ShieldCheck, Wrench, RefreshCw, Mail } from "lucide-react";
import { Button } from "@/components/ui/button";

// ── Stripe Payment Links ─────────────────────────────────────────────
// Paste your hosted Stripe Payment Link URLs here (create them in the
// Stripe dashboard → Payment Links). They look like:
//   https://buy.stripe.com/xxxxxxxxxxxxxxxx
// NEVER put a secret key (sk_live_...) in this file or anywhere in the
// frontend — Payment Links need no keys at all. If a link is left blank,
// the button falls back to an email enquiry.
const PAYMENT_LINKS = {
  express: "",
  auditFix: "",
  retainer: "",
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
    price: "$1,500",
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
    price: "$4,500",
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
      window.open(plan.link, "_blank");
      return;
    }
    const subject = encodeURIComponent(`Shellockolm: ${plan.name}`);
    const body = encodeURIComponent(
      `Hi — I'd like to book the ${plan.name} (${plan.price}).\n\nMy stack / repo:\nWhat prompted this:\n`
    );
    window.location.href = `mailto:${CONTACT_EMAIL}?subject=${subject}&body=${body}`;
  };

  return (
    <section className="relative py-24 overflow-hidden">
      <div className="absolute inset-0 bg-gradient-dark" />
      <div
        className="absolute inset-0 opacity-25"
        style={{
          backgroundImage: `radial-gradient(ellipse 60% 40% at 50% 30%, hsl(var(--ultramarine) / 0.15), transparent)`,
        }}
      />

      <div className="relative z-10 container mx-auto px-6">
        <div className="text-center mb-16 max-w-2xl mx-auto">
          <h2 className="font-display text-4xl md:text-5xl font-bold mb-4">
            The tool is free. <span className="text-gradient-ultramarine">Your time isn't.</span>
          </h2>
          <p className="text-muted-foreground">
            Ran the scanner and it found something real? These are the human
            services that verify it, fix it, and harden the rest of your stack.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6 max-w-5xl mx-auto items-stretch">
          {plans.map((plan) => {
            const Icon = plan.icon;
            return (
              <div
                key={plan.name}
                className={`relative flex flex-col rounded-xl border bg-secondary/20 backdrop-blur-sm p-8 transition-all ${
                  plan.featured
                    ? "border-primary glow-ultramarine"
                    : "border-border hover:border-primary/50"
                }`}
              >
                {plan.featured && (
                  <span className="absolute -top-3 left-1/2 -translate-x-1/2 badge-detective text-xs">
                    Most popular
                  </span>
                )}

                <Icon className="w-8 h-8 text-primary mb-4" />
                <h3 className="font-display text-xl font-bold mb-1">{plan.name}</h3>
                <div className="flex items-baseline gap-2 mb-1">
                  <span className="text-3xl font-bold text-gradient-ultramarine">{plan.price}</span>
                </div>
                <p className="text-xs text-muted-foreground mb-4">{plan.cadence}</p>
                <p className="text-sm text-foreground/90 mb-6">{plan.blurb}</p>

                <ul className="space-y-3 mb-8 flex-1">
                  {plan.features.map((f) => (
                    <li key={f} className="flex items-start gap-2 text-sm text-muted-foreground">
                      <Check className="w-4 h-4 text-success shrink-0 mt-0.5" />
                      <span>{f}</span>
                    </li>
                  ))}
                </ul>

                <Button
                  size="lg"
                  variant={plan.featured ? "default" : "outline"}
                  className={
                    plan.featured
                      ? "bg-primary text-primary-foreground hover:bg-primary/90 glow-ultramarine"
                      : "border-border hover:border-primary/50"
                  }
                  onClick={() => book(plan)}
                >
                  Book {plan.name}
                </Button>
              </div>
            );
          })}
        </div>

        <div className="text-center mt-12 max-w-2xl mx-auto">
          <Button
            variant="ghost"
            className="text-muted-foreground hover:text-foreground"
            onClick={() => {
              window.location.href = `mailto:${CONTACT_EMAIL}?subject=${encodeURIComponent(
                "Shellockolm: custom security work"
              )}`;
            }}
          >
            <Mail className="w-4 h-4 mr-2" />
            Need something custom? Email me
          </Button>
          <p className="text-xs text-muted-foreground/70 mt-6">
            No "zero false positives" or "100% success" guarantees — security
            doesn't work that way. You get honest findings and real fixes.
          </p>
        </div>
      </div>
    </section>
  );
};

export default PricingSection;
