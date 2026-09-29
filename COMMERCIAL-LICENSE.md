# Shellockolm — Commercial License

Copyright © 2025–2026 HLS iTech (Hubert Larose-Surprenant). All rights reserved.

Shellockolm is **source-available, not open source**. The source code is published
under the [PolyForm Strict License 1.0.0](LICENSE). That license permits **personal
and noncommercial use only** and **forbids copying, redistribution, forking,
modification, and derivative works**.

**Any commercial or business use requires a paid commercial license from HLS iTech.**

---

## Do I need a commercial license?

You need a commercial license if you use Shellockolm in **any** of these contexts:

- Inside a company, startup, agency, or any for-profit organization
- As part of a product, SaaS, or paid service you offer to others
- In a paid consulting, contracting, or security-audit engagement
- In any CI/CD pipeline that builds or ships commercial software
- Any other use with an anticipated commercial application

You do **not** need a commercial license for genuinely personal, hobby, academic,
research, or nonprofit use — those are already permitted, free of charge, by the
PolyForm Strict License.

> If you are unsure which side of the line you are on, assume you need a commercial
> license and reach out. Enforcement is friendly-first: see the "Violations"
> section of the PolyForm Strict License (32-day cure period on written notice).

---

## What a commercial license grants

A commercial license is a separate, paid agreement that grants your organization
the right to **use** Shellockolm for commercial purposes. It is:

- **Per-organization / per-seat**, term-based (annual), and non-transferable
- **Non-exclusive** and **non-sublicensable**
- Still **not** a grant to redistribute, resell, republish, or open-source the code

Purchasing a commercial license also provisions a **license key** that unlocks the
Pro / Team feature tiers (advanced rule packs, premium reports, continuous
monitoring) via the server-authoritative validator in `src/licensing.py`.

| Tier | Who it's for | Key required | How to get it |
|------|--------------|--------------|---------------|
| **Free / Noncommercial** | Individuals, hobby, research, nonprofit | No | Just use it (PolyForm Strict) |
| **Pro** | A commercial developer / small team | Yes | Purchase — key emailed after checkout |
| **Team** | A whole organization | Yes | Purchase — key emailed after checkout |

Pricing and current tiers are listed on the website. Pricing is deliberately
positioned as a **serious-tool filter**, not a mass-market price.

---

## How to buy

- **Web:** https://shellockolm.netlify.app
- **Email:** hlarosesurprenant@gmail.com

During early access, keys are issued manually within 24 hours of purchase. A row is
added to the authoritative `licenses` table; the key is delivered by email and
activated by setting `SHELLOCKOLM_LICENSE` or writing `~/.shellockolm/license.json`.

---

## Why source-available instead of MIT?

Shellockolm is a **defensive security tool**. Its source stays readable so that
customers, reviewers, and the security community can **audit exactly what it does**
— no hidden telemetry, no black box. But readable is not the same as free-to-take:
the PolyForm Strict License makes copying, reselling, or forking the code an act of
**infringement**, while a paid commercial license is what grants the right to use
it in business. Transparency for trust; a real license for protection.

---

*This document summarizes the commercial licensing model. The binding legal terms
are the [PolyForm Strict License](LICENSE) for the source, plus the individual
commercial license agreement issued to you on purchase.*
