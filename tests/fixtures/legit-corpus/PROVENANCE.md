# Legitimate-skills false-positive regression corpus

A vendored set of **real, popular, legitimate** agent skills used as a
false-positive regression net. The rule is simple and load-bearing for an
open-core security product: **a high-confidence (deterministic) rule must never
fire on real, well-known, benign content, and no legitimate skill may ever be
rated CRITICAL.** If a calibration change breaks that, a named test here goes red.

Consumed by [`tests/test_false_positive_regression.py`](../../test_false_positive_regression.py).

## Source & license

Every `SKILL.md` under `skills/` is an **unmodified** copy of an Anthropic-authored
skill from the official Claude Code plugin directory:

- **Repository:** <https://github.com/anthropics/claude-plugins-official>
- **Path upstream:** `plugins/<plugin>/skills/<skill>/SKILL.md` — the directory the
  marketplace README documents as *"Internal plugins developed and maintained by
  Anthropic"* (i.e. not the third-party `external_plugins/` tree).
- **License:** Apache License 2.0 (see the `LICENSE` file in that repository).
- **Vendored:** the `SKILL.md` instruction artifact only (the model-facing prose that
  is the prompt-injection surface). Supporting scripts/reference files are not copied,
  so the corpus on disk equals exactly the set of artifacts the scanner reads.

These are redistributed here under their original Apache-2.0 license, solely as test
fixtures, with attribution. They are **not** Shellockolm's own work.

## What it asserts

The corpus is scanned at the **Pro tier** (the strictest — every rule active). The
contract the tests enforce:

1. **Zero CRITICAL findings at any confidence.** No legitimate skill may be rated
   CRITICAL by any rule, heuristic or structural.
2. **Zero CRITICAL/HIGH findings at `high` confidence.** The deterministic rules
   (structural parse / signature / decoded-secret) are zero-false-positive by design;
   this proves it on real, popular content. Equivalently: the `--min-confidence high`
   CI gate is clean on this corpus.

## Why some HIGH findings are *expected* (and allowed)

A handful of **low/medium-confidence** natural-language heuristics (e.g. `AGENT-PI-002`
"when the user does X", `AGENT-PRO-001/002`, `AGENT-DESTRUCT-001`) do match the prose of
some legitimate skills — for example a skill whose frontmatter `description:` reads
*"Use when the user asks to …"*. These are advisory by construction, which is exactly
why the `confidence` axis and the `--min-confidence high` gate exist. The regression
suite therefore does **not** require zero findings overall; it requires zero
*high-confidence* CRITICAL/HIGH and zero CRITICAL. Tightening those low/medium
heuristics is tracked separately as detection-calibration work, not a corpus failure.

## Updating

Re-vendoring (new upstream versions, more skills) is fine — drop unmodified `SKILL.md`
files under `skills/<skill>/`. Keep this file's attribution accurate. If a freshly
vendored skill trips the high-confidence gate, that is either a genuine detection bug
to fix or a skill that genuinely is not benign — investigate, don't just delete it.
