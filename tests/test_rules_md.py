"""Tests for the generated ``RULES.md`` rule reference (build-loop task #46).

``RULES.md`` is the committed, human-readable catalog of every ``AGENT-*`` rule the
scanner emits. It is **generated** from the single source of truth
(`scanners.agent_supply_chain.agent_rule_catalog` + `agent_rule_example`) by
`scripts/generate_rules_md.py`, so the doc can never drift from the code.

This suite enforces that contract:

* the committed ``RULES.md`` is byte-identical to a fresh render (the in-sync gate,
  the same one `generate_rules_md.py --check` runs in CI),
* the render is deterministic and "has teeth" (a perturbation is detected),
* every catalog rule is documented — index row + detail section + counts,
* README and the marketing-site footer both link to ``RULES.md``.
"""

import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
_SRC = _REPO_ROOT / "src"
_SCRIPTS = _REPO_ROOT / "scripts"
for _p in (_SRC, _SCRIPTS):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

import generate_rules_md as gen  # noqa: E402
from scanners.agent_supply_chain import (  # noqa: E402
    agent_rule_catalog,
    agent_rule_example,
)

RULES_MD = _REPO_ROOT / "RULES.md"


def _committed() -> str:
    return RULES_MD.read_text(encoding="utf-8").replace("\r\n", "\n")


# --------------------------------------------------------------------------- #
# In-sync contract
# --------------------------------------------------------------------------- #

def test_rules_md_exists_and_nonempty():
    assert RULES_MD.is_file(), "RULES.md must be committed at the repo root"
    assert len(_committed()) > 1000, "RULES.md looks empty/truncated"


def test_committed_matches_fresh_render():
    """The committed file equals a fresh render — the core anti-drift guard."""
    assert _committed() == gen.render_rules_md(), (
        "RULES.md is out of sync with the rule catalog. "
        "Run: python scripts/generate_rules_md.py"
    )


def test_check_mode_passes_on_committed_file():
    """`generate_rules_md.py --check` exits 0 against the committed file."""
    assert gen.main(["--check"]) == 0


def test_render_is_deterministic():
    assert gen.render_rules_md() == gen.render_rules_md()


def test_check_has_teeth(monkeypatch):
    """A perturbed render must make the in-sync comparison fail (exit 1)."""
    real = gen.render_rules_md()
    monkeypatch.setattr(gen, "render_rules_md", lambda: real + "\n<!-- drift -->\n")
    assert gen.main(["--check"]) == 1


# --------------------------------------------------------------------------- #
# Completeness — every rule is documented
# --------------------------------------------------------------------------- #

def test_every_rule_has_index_row_and_detail_section():
    doc = _committed()
    catalog = agent_rule_catalog()
    assert catalog, "catalog must not be empty"
    for r in catalog:
        rid = r["id"]
        # Index row links to the rule's anchor.
        assert f"[`{rid}`](#{rid.lower()})" in doc, f"{rid} missing from the index table"
        # Detail section heading (anchor target).
        assert f"#### {rid}\n" in doc, f"{rid} missing its detail section"
        # The one-line title shows up in the body.
        assert r["title"] in doc, f"{rid} title not rendered"


def test_every_rule_example_attack_is_rendered():
    doc = _committed()
    for r in agent_rule_catalog():
        example = agent_rule_example(r["id"]).strip()
        assert example, f"{r['id']} has no example attack (catalog drift)"
        # The example's first line is a stable, content-bearing anchor to match on.
        first_line = example.splitlines()[0].strip()
        assert first_line in doc, f"{r['id']} example attack not rendered in RULES.md"


def test_header_counts_match_catalog():
    doc = _committed()
    catalog = agent_rule_catalog()
    total = len(catalog)
    free = sum(1 for r in catalog if r["tier"] == "free")
    pro = sum(1 for r in catalog if r["tier"] == "pro")
    assert f"**{total} rules**" in doc
    assert f"**{free} free**" in doc
    assert f"**{pro} Pro**" in doc


def test_pro_rules_labelled_pro_in_index():
    doc = _committed()
    for r in agent_rule_catalog():
        if r["tier"] == "pro":
            # The index row for a Pro rule carries the "Pro" tier cell.
            line = next(ln for ln in doc.splitlines()
                        if ln.startswith(f"| [`{r['id']}`]"))
            assert "| Pro |" in line, f"{r['id']} not labelled Pro in the index"


# --------------------------------------------------------------------------- #
# Links from README + website
# --------------------------------------------------------------------------- #

def test_readme_links_to_rules_md():
    readme = (_REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "(RULES.md)" in readme, "README must link to RULES.md"


def test_website_footer_links_to_rules_md():
    footer = (_REPO_ROOT / "website" / "src" / "components" / "Footer.tsx").read_text(
        encoding="utf-8")
    assert "/blob/main/RULES.md" in footer, "Website footer must link to RULES.md"


# --------------------------------------------------------------------------- #
# Generator hygiene
# --------------------------------------------------------------------------- #

def test_no_unclosed_code_fence():
    """Even count of ```-fence lines (the example blocks are balanced)."""
    fences = [ln for ln in _committed().splitlines() if ln.startswith("```")]
    assert len(fences) % 2 == 0, "RULES.md has an unbalanced code fence"


def test_stdout_mode_writes_nothing_to_disk(capsys, monkeypatch, tmp_path):
    """`--stdout` prints the doc and never touches RULES.md."""
    sentinel = tmp_path / "RULES.md"
    sentinel.write_text("UNTOUCHED", encoding="utf-8")
    monkeypatch.setattr(gen, "RULES_MD_PATH", sentinel)
    rc = gen.main(["--stdout"])
    out = capsys.readouterr().out
    assert rc == 0
    assert out.startswith("# Shellockolm")
    assert sentinel.read_text(encoding="utf-8") == "UNTOUCHED"
