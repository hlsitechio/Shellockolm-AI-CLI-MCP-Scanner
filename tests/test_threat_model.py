"""Tests for the generated ``THREAT_MODEL.md`` (build-loop task #47).

``THREAT_MODEL.md`` is the committed, one-page agentic supply-chain threat model.
Its rule↔attack-class coverage is **generated** from the single source of truth
(`scanners.agent_supply_chain.agent_rule_catalog`) by
`scripts/generate_threat_model.py` — the same catalog behind ``RULES.md`` — so the
coverage claims can never drift from the rules that ship.

This suite enforces that contract:

* the committed ``THREAT_MODEL.md`` is byte-identical to a fresh render (the
  in-sync gate, the same one `generate_threat_model.py --check` runs in CI),
* the render is deterministic and "has teeth" (a perturbation is detected),
* **every attack class in the catalog has a hand-authored threat description** and
  every rule appears under its class — coverage cannot silently go undocumented,
* the at-a-glance matrix counts match the catalog, Pro rules are labelled Pro,
* the honest scope/limitations section is present (the "maps to marketing
  honestly" requirement), and README + the website footer both link to the doc.
"""

import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_SCRIPTS = _REPO_ROOT / "scripts"
for _p in (_SRC, _SCRIPTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import generate_threat_model as gen  # noqa: E402
from scanners.agent_supply_chain import agent_rule_catalog  # noqa: E402

THREAT_MD = _REPO_ROOT / "THREAT_MODEL.md"


def _committed() -> str:
    return THREAT_MD.read_text(encoding="utf-8").replace("\r\n", "\n")


# --------------------------------------------------------------------------- #
# In-sync contract
# --------------------------------------------------------------------------- #

def test_threat_model_exists_and_nonempty():
    assert THREAT_MD.is_file(), "THREAT_MODEL.md must be committed at the repo root"
    assert len(_committed()) > 1000, "THREAT_MODEL.md looks empty/truncated"


def test_committed_matches_fresh_render():
    """The committed file equals a fresh render — the core anti-drift guard."""
    assert _committed() == gen.render_threat_model_md(), (
        "THREAT_MODEL.md is out of sync with the rule catalog. "
        "Run: python scripts/generate_threat_model.py"
    )


def test_check_mode_passes_on_committed_file():
    """`generate_threat_model.py --check` exits 0 against the committed file."""
    assert gen.main(["--check"]) == 0


def test_render_is_deterministic():
    assert gen.render_threat_model_md() == gen.render_threat_model_md()


def test_check_has_teeth(monkeypatch):
    """A perturbed render must make the in-sync comparison fail (exit 1)."""
    real = gen.render_threat_model_md()
    monkeypatch.setattr(
        gen, "render_threat_model_md", lambda: real + "\n<!-- drift -->\n")
    assert gen.main(["--check"]) == 1


# --------------------------------------------------------------------------- #
# Completeness — every attack class is modelled, every rule mapped
# --------------------------------------------------------------------------- #

def test_threat_classes_exactly_match_catalog():
    """Every catalog attack class has a threat description and vice-versa.

    This is the anti-drift gate for the *narrative*: add a new rule family and the
    generator (hence the doc) fails until a threat description is written for it.
    """
    catalog_classes = {r["attack_class"] for r in agent_rule_catalog()}
    described_classes = {e["class"] for e in gen._THREAT_CLASSES}
    assert described_classes == catalog_classes, (
        "Threat descriptions out of sync with the catalog's attack classes. "
        f"Missing a description: {catalog_classes - described_classes}; "
        f"described but not in catalog: {described_classes - catalog_classes}"
    )


def test_threat_class_descriptions_are_substantive():
    """Each class carries a non-trivial headline + threat + impact (no stubs)."""
    for e in gen._THREAT_CLASSES:
        for field in ("headline", "threat", "impact"):
            assert len(e[field].strip()) > 20, (
                f"{e['class']} has an empty/stub {field}")


def test_every_class_has_a_section_and_matrix_row():
    doc = _committed()
    for e in gen._THREAT_CLASSES:
        cls = e["class"]
        assert f"### {cls}\n" in doc, f"{cls} missing its threat section heading"
        # Coverage-matrix row links to the class anchor.
        assert f"[{cls}](#{cls.lower()})" in doc, f"{cls} missing from the coverage matrix"


def test_every_rule_appears_under_its_class():
    """Every catalog rule is mapped (id link to its RULES.md anchor + title)."""
    doc = _committed()
    catalog = agent_rule_catalog()
    assert catalog, "catalog must not be empty"
    for r in catalog:
        rid = r["id"]
        # The rule id links to its detail section in RULES.md.
        assert f"[`{rid}`](RULES.md#{rid.lower()})" in doc, (
            f"{rid} not mapped in THREAT_MODEL.md")
        assert r["title"] in doc, f"{rid} title not rendered"


def test_header_counts_match_catalog():
    doc = _committed()
    catalog = agent_rule_catalog()
    total = len(catalog)
    free = sum(1 for r in catalog if r["tier"] == "free")
    pro = sum(1 for r in catalog if r["tier"] == "pro")
    classes = len({r["attack_class"] for r in catalog})
    assert f"**{total} agent supply-chain rules**" in doc
    assert f"**{free} free**" in doc
    assert f"**{pro} Pro**" in doc
    assert f"**{classes} attack classes**" in doc


def test_coverage_matrix_counts_are_correct():
    """Each matrix row's rule/free/pro counts equal the catalog's per-class tally."""
    doc_lines = _committed().splitlines()
    catalog = agent_rule_catalog()
    for e in gen._THREAT_CLASSES:
        cls = e["class"]
        rules = [r for r in catalog if r["attack_class"] == cls]
        free = sum(1 for r in rules if r["tier"] == "free")
        pro = sum(1 for r in rules if r["tier"] == "pro")
        row = next(ln for ln in doc_lines if ln.startswith(f"| [{cls}](#{cls.lower()})"))
        # | [cls](#cls) | total | free | pro | severities |
        cells = [c.strip() for c in row.strip("|").split("|")]
        assert cells[1] == str(len(rules)), f"{cls} rule count wrong: {row}"
        assert cells[2] == str(free), f"{cls} free count wrong: {row}"
        assert cells[3] == str(pro), f"{cls} pro count wrong: {row}"


def test_pro_rules_labelled_pro():
    doc_lines = _committed().splitlines()
    for r in agent_rule_catalog():
        if r["tier"] == "pro":
            row = next(ln for ln in doc_lines
                       if ln.startswith(f"| [`{r['id']}`]"))
            assert "| Pro |" in row, f"{r['id']} not labelled Pro"


# --------------------------------------------------------------------------- #
# Honest-marketing scope section
# --------------------------------------------------------------------------- #

def test_scope_and_limitations_section_present():
    """The honest scope/limitations section is the 'maps to marketing' requirement."""
    doc = _committed()
    assert "## Scope and honest limitations" in doc
    # Key honest caveats must be stated, not just the heading.
    assert "clean scan is not a safety guarantee" in doc.lower() \
        or "not a safety guarantee" in doc.lower()
    assert "additive" in doc.lower(), "Pro-is-additive caveat missing"


# --------------------------------------------------------------------------- #
# Links from README + website
# --------------------------------------------------------------------------- #

def test_readme_links_to_threat_model():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "(THREAT_MODEL.md)" in readme, "README must link to THREAT_MODEL.md"


def test_website_footer_links_to_threat_model():
    footer = (_REPO_ROOT / "website" / "src" / "components" / "Footer.tsx").read_text(
        encoding="utf-8")
    assert "/blob/main/THREAT_MODEL.md" in footer, (
        "Website footer must link to THREAT_MODEL.md")


# --------------------------------------------------------------------------- #
# Generator hygiene
# --------------------------------------------------------------------------- #

def test_no_unclosed_code_fence():
    """Even count of ```-fence lines (balanced, if any are present)."""
    fences = [ln for ln in _committed().splitlines() if ln.startswith("```")]
    assert len(fences) % 2 == 0, "THREAT_MODEL.md has an unbalanced code fence"


def test_stdout_mode_writes_nothing_to_disk(capsys, monkeypatch, tmp_path):
    """`--stdout` prints the doc and never touches THREAT_MODEL.md."""
    sentinel = tmp_path / "THREAT_MODEL.md"
    sentinel.write_text("UNTOUCHED", encoding="utf-8")
    monkeypatch.setattr(gen, "THREAT_MODEL_MD_PATH", sentinel)
    rc = gen.main(["--stdout"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# Shellockolm")
    assert sentinel.read_text(encoding="utf-8") == "UNTOUCHED"
