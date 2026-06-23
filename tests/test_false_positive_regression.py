"""False-positive regression suite over a vendored corpus of real, legit skills.

``tests/fixtures/legit-corpus/`` holds **unmodified** copies of Anthropic-authored
``SKILL.md`` files from the official ``anthropics/claude-plugins-official`` plugin
directory (Apache-2.0; see ``legit-corpus/PROVENANCE.md``). They are popular,
genuinely benign agent artifacts — so they are the right material to prove the
scanner does not cry wolf on real content.

The load-bearing invariant for an open-core security product: **a deterministic
(high-confidence) rule must never fire on real, well-known, benign content, and no
legitimate skill may ever be rated CRITICAL.** The corpus is scanned at the Pro tier
(strictest — every rule active) and the suite asserts:

* zero CRITICAL findings at any confidence, and
* zero CRITICAL/HIGH findings at ``high`` confidence (== the ``--min-confidence high``
  CI gate is clean).

It deliberately does NOT require zero findings overall: a few low/medium-confidence
natural-language heuristics (``AGENT-PI-006``, ``AGENT-DESTRUCT-001``) legitimately match
the prose of some real skills — that is what the ``confidence`` axis and the high-confidence
gate exist to handle. Tightening those is ongoing calibration work, not a corpus failure.

``AGENT-PI-002`` (the hidden-conditional-trigger heuristic) HAS now been calibrated:
every one of its former hits on this corpus was a skill documenting its own activation
conditions (the ``description:`` field or a "When to use" section), which the scanner
suppresses — so the suite below also locks in ``AGENT-PI-002 == 0`` on the corpus.

``AGENT-PRO-002`` (tool/skill shadowing) has likewise been calibrated: its former hits
matched the bare comparative preposition "instead of" in benign instructional prose, so
it now only fires on "instead of" when a *qualified existing/trusted* tool is the target
(the genuine hijack shape) — the suite locks in ``AGENT-PRO-002 == 0`` on the corpus too.

``AGENT-PRO-001`` (indirect injection via fetched content) has likewise been calibrated:
its former hit was the official skill-creator instruction to read the skill's own bundled
``SKILL.md`` and follow it — a *local* read, not the remote fetch the rule names — so it now
fires only on a genuine *external* fetch (remote verb or a URL/web/link/remote indicator),
leaving local read-and-follow to ``AGENT-PI-016``; the suite locks in ``AGENT-PRO-001 == 0``.
"""

import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanners.agent_supply_chain import AgentSupplyChainScanner  # noqa: E402
from scanners.base import FindingSeverity  # noqa: E402

CORPUS = Path(__file__).resolve().parent / "fixtures" / "legit-corpus"

# A floor so the suite can never pass *vacuously* (e.g. the corpus dir is emptied or a
# path typo makes the glob match nothing). We currently vendor 23 skills.
_MIN_CORPUS_SIZE = 20

_BLOCKING = (FindingSeverity.CRITICAL, FindingSeverity.HIGH)


def _skill_files() -> list[Path]:
    """Every scanned artifact vendored into the corpus (SKILL.md / *.skill.md)."""
    return sorted(
        p
        for p in CORPUS.rglob("*")
        if p.is_file() and (p.name.lower() == "skill.md" or p.name.lower().endswith(".skill.md"))
    )


def _rel(path: Path) -> str:
    return str(path.relative_to(CORPUS))


def _fmt(findings) -> str:
    return ", ".join(
        f"{f.cve_id}[{f.severity.value}/{f.confidence}] @ {f.file_path}" for f in findings
    )


# --------------------------------------------------------------------------- #
# Corpus hygiene — the suite must not pass vacuously
# --------------------------------------------------------------------------- #

def test_corpus_dir_exists():
    assert CORPUS.is_dir(), f"legit-corpus directory missing: {CORPUS}"
    assert (CORPUS / "PROVENANCE.md").is_file(), "legit-corpus must document its provenance"


def test_corpus_is_populated():
    files = _skill_files()
    assert len(files) >= _MIN_CORPUS_SIZE, (
        f"legit-corpus has only {len(files)} skill artifact(s); "
        f"expected at least {_MIN_CORPUS_SIZE}. A shrinking FP corpus is a regression."
    )


def test_corpus_is_actually_scanned():
    """Guard against a silent skip: the scanner must read every vendored artifact."""
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    assert result.stats.get("skills_scanned", 0) == len(_skill_files()), (
        f"scanner read {result.stats.get('skills_scanned')} skills but "
        f"{len(_skill_files())} are vendored — a corpus file is being skipped."
    )
    assert not result.errors, f"unexpected scan errors over legit corpus: {result.errors}"


# --------------------------------------------------------------------------- #
# The regression contract (whole corpus, Pro tier)
# --------------------------------------------------------------------------- #

def test_no_critical_findings_any_confidence():
    """No legitimate, popular skill may EVER be rated CRITICAL by any rule."""
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    crit = [f for f in result.findings if f.severity == FindingSeverity.CRITICAL]
    assert not crit, f"CRITICAL false positive(s) on legit skills: {_fmt(crit)}"


def test_no_high_confidence_blocking_findings():
    """Deterministic (high-confidence) rules must never fire CRITICAL/HIGH on legit content.

    The headline invariant: structural / signature / decoded-secret rules are
    zero-false-positive by design — this proves it on real, popular skills.
    """
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    offenders = [
        f
        for f in result.findings
        if f.severity in _BLOCKING and f.confidence == "high"
    ]
    assert not offenders, (
        "high-confidence CRITICAL/HIGH false positive(s) on legit skills "
        f"(a deterministic rule fired on benign content): {_fmt(offenders)}"
    )


def test_pi002_calibrated_out_on_legit_corpus():
    """AGENT-PI-002 no longer false-positives on the legit corpus.

    Every former PI-002 hit here was a skill documenting its own activation conditions
    (the ``description:`` frontmatter field or a "When to use" section) — exactly where
    the official skill format expects "use when the user asks to …" phrasing. The PI-002
    calibration suppresses those activation-doc contexts while still firing on a covert
    trigger in ordinary body prose, so the corpus is now clean of PI-002. Locks the win.
    """
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    pi002 = [f for f in result.findings if f.cve_id == "AGENT-PI-002"]
    assert not pi002, f"AGENT-PI-002 false positive(s) on legit skills: {_fmt(pi002)}"


def test_pro002_calibrated_out_on_legit_corpus():
    """AGENT-PRO-002 (tool/skill shadowing) no longer false-positives on the legit corpus.

    Both former hits matched the weak comparative preposition "instead of" in ordinary
    instructional prose — "write a standalone HTML file instead of starting a server"
    and 'say "This skill should be used when…" instead of "Use this skill when…"' — not a
    claim to displace a real tool. The rule now only fires on "instead of" when it targets
    a *qualified existing/trusted* tool ("instead of the built-in/official/real … tool"),
    so the corpus is clean of PRO-002 while genuine shadowing still trips it. Locks the win.
    """
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    pro002 = [f for f in result.findings if f.cve_id == "AGENT-PRO-002"]
    assert not pro002, f"AGENT-PRO-002 false positive(s) on legit skills: {_fmt(pro002)}"


def test_pro001_calibrated_out_on_legit_corpus():
    """AGENT-PRO-001 (indirect injection via fetched content) no longer false-positives
    on the legit corpus.

    The former hit was the official skill-creator *test-running* instruction — "for each
    test case, read the skill's SKILL.md, then follow its instructions" — which reads a
    file already in the trusted bundle, not the remote/attacker-controlled page the rule
    names. PRO-001 now fires only on a genuine *external* fetch (a remote verb, or a URL/
    web/link/remote indicator in the window); a local read-and-follow is left to PI-016
    (the staged-payload rule, gated on a suspicious path or covert framing). The corpus is
    now clean of PRO-001 while genuine remote fetch-then-follow still trips it. Locks the win.
    """
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS))
    pro001 = [f for f in result.findings if f.cve_id == "AGENT-PRO-001"]
    assert not pro001, f"AGENT-PRO-001 false positive(s) on legit skills: {_fmt(pro001)}"


def test_min_confidence_high_gate_is_clean():
    """End-to-end proof that the ``--min-confidence high`` CI gate is clean here.

    Scanning with ``min_confidence='high'`` filters out the advisory low/medium
    heuristics exactly as the CLI flag does; what survives must contain no
    CRITICAL/HIGH finding.
    """
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(CORPUS), min_confidence="high")
    blocking = [f for f in result.findings if f.severity in _BLOCKING]
    assert not blocking, (
        "--min-confidence high gate is not clean on legit skills: " + _fmt(blocking)
    )


def test_free_tier_also_clean_at_high_confidence():
    """The free tier is a subset of Pro, but assert the gate explicitly so a free-only
    regression is still caught."""
    scanner = AgentSupplyChainScanner(pro=False)
    result = scanner.scan_directory(str(CORPUS), min_confidence="high")
    blocking = [f for f in result.findings if f.severity in _BLOCKING]
    assert not blocking, (
        "--min-confidence high gate is not clean on legit skills (free tier): " + _fmt(blocking)
    )


# --------------------------------------------------------------------------- #
# Per-file pinpointing — a regression names the exact offending skill
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("skill", _skill_files(), ids=_rel)
def test_each_legit_skill_passes_high_confidence_gate(skill):
    """Each vendored skill, scanned individually, must pass the high-confidence gate
    at the Pro tier — so a regression points at one named file, not the whole corpus."""
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(skill), min_confidence="high")
    blocking = [f for f in result.findings if f.severity in _BLOCKING]
    assert not blocking, f"{_rel(skill)}: high-confidence false positive(s): {_fmt(blocking)}"


@pytest.mark.parametrize("skill", _skill_files(), ids=_rel)
def test_each_legit_skill_never_critical(skill):
    scanner = AgentSupplyChainScanner(pro=True)
    result = scanner.scan_directory(str(skill))
    crit = [f for f in result.findings if f.severity == FindingSeverity.CRITICAL]
    assert not crit, f"{_rel(skill)}: CRITICAL false positive(s): {_fmt(crit)}"
