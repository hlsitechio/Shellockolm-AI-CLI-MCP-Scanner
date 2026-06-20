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
natural-language heuristics (``AGENT-PI-002`` etc.) legitimately match the prose of
some real skills — that is what the ``confidence`` axis and the high-confidence gate
exist to handle. Tightening those is separate calibration work, not a corpus failure.
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
