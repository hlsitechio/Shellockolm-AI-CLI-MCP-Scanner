# ⚡ Performance — Agent Supply-Chain Scanner

Real, measured numbers for the `AGENT-*` supply-chain scanner (`shellockolm scan -s agent`),
plus the benchmark you can run yourself. All figures below are **measured**, not estimated.

> Reproduce locally:
> ```bash
> python scripts/benchmark_scan.py            # default ~1500-artifact synthetic tree
> python scripts/benchmark_scan.py -n 4000    # larger tree
> python scripts/benchmark_scan.py --json     # machine-readable result
> ```
> The benchmark generates a deterministic, self-contained corpus of skills, MCP
> configs, n8n exports, instruction files, and `.claude/` settings + slash-commands
> (≈5 % carrying a known malicious shape) in a temp dir, scans it, and reports
> wall-clock + throughput. The corpus generator is shared with the perf-guard test
> (`tests/test_perf_guard.py`), so the benchmark and the CI tripwire agree.

## Synthetic benchmark

Deterministic tree of small, uniform artifacts — a clean *throughput* baseline.
Measured on Windows 11 / Python 3.14, best of 5 runs, warm file cache:

| Tree size (artifacts) | Wall-clock | Throughput      | Per-artifact |
|----------------------:|-----------:|----------------:|-------------:|
| 1,000                 | ~1.0 s     | ~980 artifacts/s| ~1.0 ms      |
| 1,500 (default)       | ~1.5 s     | ~960 artifacts/s| ~1.0 ms      |
| 4,000                 | ~3.7 s     | ~1,080 artifacts/s | ~0.9 ms   |

## Real-world corpus

A real `~/.claude/skills` tree (1,335 skills) — larger, varied files, the honest
upper bound on per-artifact cost:

| Corpus                | Artifacts | Wall-clock | Throughput     | Per-artifact |
|-----------------------|----------:|-----------:|---------------:|-------------:|
| `~/.claude/skills`    | 1,335     | ~16 s      | ~83 artifacts/s| ~12 ms       |

Real skills are larger and prose-heavier than the synthetic ones, so per-artifact
cost is higher. The remaining hot path is the regex detection pass (see *Known
hot path* below) — file I/O is a small fraction of the total.

## Optimization: non-ASCII stealth-scan fast path

The per-character stealth scans — Unicode-Tags smuggling (`AGENT-PI-007`),
Trojan-Source bidi (`AGENT-PI-008`-class), and confusable/homoglyph spoofing
(`AGENT-PI-011`) — used to iterate **every character** of **every** artifact
(plus, for confusables, a regex over every word). But every code point those
checks look for lives above U+007F, so a single C-level character-class search
(`_STEALTH_CHARS_RE`, built from the same constants the checks consume so it can
never drift) lets a pure-ASCII artifact skip all three Python loops entirely.

**1,333 of 1,335 real skills are pure ASCII**, so the fast path applies almost
everywhere. Measured impact (interleaved on/off in one process to cancel machine
noise; findings byte-identical both ways):

| Corpus                       | Before  | After   | Speedup |
|------------------------------|--------:|--------:|--------:|
| `~/.claude/skills` (1,335)   | 18.65 s | 16.01 s | **−14.2 %** |
| synthetic, 2,000 artifacts   | 2.28 s  | 2.04 s  | −10.3 % |

The optimization is **behavior-preserving**: the fast path is a strict superset
guard, so any artifact containing a real stealth character still runs the full
slow-path scan. `tests/test_perf_guard.py` asserts the guard matches every
constituent character (anti-drift), fast-paths benign ASCII *and* benign
non-ASCII (emoji, curly quotes, accents, CJK), and still detects every smuggling
attack while staying clean on benign prose.

## Cost of statement scoping on generated content

Scanning a minified line statement by statement (F22 — so a payload run through a
bundler is still detected) is **free on everything that is not minified**, which
is almost everything: the split is lazy and keyed by line, so a file with no line
of 2,000+ characters never performs one, and a file that has one pays only when a
rule actually matches on it. Measured on `~/.claude/plugins` (1,144 bundled
scripts, 65 of them carrying a generated line, best of two runs each):

| Build                        | Wall-clock | Findings |
|------------------------------|-----------:|---------:|
| before                       | 59.33 s    | 187      |
| statement scoping            | 59.48 s    | 196      |

The +9 findings are real detections the length guard had been hiding, not new
false positives — see the CHANGELOG entry.

The first implementation ran each rule with `finditer` **per statement region**,
which is the obvious reading of "run the rules per statement" and cost **97.7 s
(+65 %)**: a 70,000-character line becomes thousands of regions, and the
per-call overhead dominates. Scanning the text once and re-tokenising only around
a match that crosses a statement boundary gives the identical results — the same
25-suppressed / 9-fired split and the same 65/65 planted-payload detection — at
no measurable cost.

### Carrying quote state across lines (F23)

Splitting a line that *continues* a multi-line template literal needs the quote
state the previous line left open, which means the walk to that line has to run.
It stays free for the same reason the split does — laziness plus a fast path:

* the walk happens only when a rule matches on a generated line, so the 1,749 of
  1,814 bundled scripts with no generated line never start one;
* it is forward-only and memoised, so a file is walked at most once per rule
  rather than once per line; and
* a line containing **no backtick** can neither open nor close the only delimiter
  that survives a newline, so its exit state *is* its entry state and the
  tokenizer is skipped entirely. That is nearly every line of a hand-written
  script.

Measured on `~/.claude/plugins` (5,231 items scanned):

| Build                        | Wall-clock | Findings |
|------------------------------|-----------:|---------:|
| statement scoping (F22)      | 57.66 s    | 190      |
| + quote carry (F23)          | 57.85 s    | 190      |

The finding **set** is identical, not just the count. What changes is coverage of
the generated lines themselves: zero-boundary lines fall from **70 of 384 to 19**,
and a payload planted after a continued literal goes from 32/64 detected to 64/64.

## Perf-guard test

`tests/test_perf_guard.py::test_scan_throughput_regression_guard` scans a
generated corpus and asserts the scanner stays far above a floor (ceiling of
20 ms/artifact with a 6 s floor — ~20× headroom over measured ~1 ms/artifact). It
is a regression tripwire: ordinary CI variance never trips it, but removing the
fast path or introducing an O(n²) path does.

## Known hot path (follow-up)

On the real corpus the dominant cost is the regex detection pass — `re.search`
(~11.7 s) and `_check_staged_payload` (`AGENT-PI-016`, ~4.8 s), which iterates
every file-reference match in each artifact. A cheap whole-text gate does **not**
help here (the obey-verbs `run`/`execute`/`apply` are too common to short-circuit
on), so a deeper loop-inversion is tracked as a separate, independently-tested
change.
