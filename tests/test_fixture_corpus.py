"""Manifest-driven detection tests over the committed fixture corpus.

The corpus lives in ``tests/fixtures/`` and is described by ``manifest.json``:
a tree of real-shaped agent artifacts (skills, MCP configs, n8n exports,
instruction files, slash commands, Claude Code settings) each labelled
``malicious`` or ``benign``.

Contract enforced here:

* **malicious** fixtures must trip every rule ID in their ``expected_rules``
  (a *subset* check — broader detection by other rules is fine).
* **benign** fixtures must produce **zero** findings at BOTH the free and the
  Pro tier (the zero-false-positive baseline).
* the manifest and the on-disk tree stay in sync — every declared fixture
  exists, and every fixture file on disk is declared (no silent orphans).

This is the single corpus the manifest points at, so the fixtures double as a
living regression net: a calibration change that breaks a detection or
introduces a false positive fails a named, self-describing test here.
"""

import json
import sys
from pathlib import Path

import pytest

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanners.agent_supply_chain import AgentSupplyChainScanner  # noqa: E402

FIXTURES = Path(__file__).resolve().parent / "fixtures"
MANIFEST_PATH = FIXTURES / "manifest.json"

_VALID_CLASSIFICATIONS = {"malicious", "benign"}


def _load_manifest() -> dict:
    return json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))


def _fixtures() -> list[dict]:
    return _load_manifest()["fixtures"]


def _scan_ids(path: Path, *, pro: bool) -> set[str]:
    """Return the set of rule/CVE IDs the agent scanner reports for ``path``."""
    scanner = AgentSupplyChainScanner(pro=pro)
    result = scanner.scan_directory(str(path))
    return {f.cve_id for f in result.findings}


def _ids(entry: dict) -> str:
    return entry["path"]


# --------------------------------------------------------------------------- #
# Manifest hygiene
# --------------------------------------------------------------------------- #

def test_manifest_exists_and_has_schema_version():
    manifest = _load_manifest()
    assert manifest.get("schema_version") == "1.0"
    assert isinstance(manifest.get("fixtures"), list)
    assert manifest["fixtures"], "fixture corpus must not be empty"


def test_manifest_has_both_malicious_and_benign():
    classes = {e["classification"] for e in _fixtures()}
    assert "malicious" in classes
    assert "benign" in classes


@pytest.mark.parametrize("entry", _fixtures(), ids=_ids)
def test_manifest_entry_is_well_formed(entry):
    assert entry["classification"] in _VALID_CLASSIFICATIONS
    assert entry.get("path"), "fixture entry needs a path"
    assert entry.get("description"), "fixture entry needs a description"
    expected = entry.get("expected_rules", [])
    assert isinstance(expected, list)
    if entry["classification"] == "malicious":
        # A malicious fixture without a declared signature rule proves nothing.
        assert expected, f"{entry['path']} (malicious) must declare expected_rules"
    else:
        # A benign fixture must not claim to trip anything.
        assert expected == [], f"{entry['path']} (benign) must declare no expected_rules"


@pytest.mark.parametrize("entry", _fixtures(), ids=_ids)
def test_declared_fixture_exists_on_disk(entry):
    assert (FIXTURES / entry["path"]).is_file(), f"missing fixture file: {entry['path']}"


def test_no_undocumented_fixture_files():
    """Every artifact file under tests/fixtures/ must be declared in the manifest.

    Guards against a fixture being added (or a benign baseline quietly dropped)
    without a manifest entry describing what it is and what it must (not) trip.
    """
    declared = {(FIXTURES / e["path"]).resolve() for e in _fixtures()}
    # Docs/metadata that are not themselves scanned artifacts.
    allowed_extra = {
        (FIXTURES / "manifest.json").resolve(),
        (FIXTURES / "README.md").resolve(),
    }
    on_disk = {
        p.resolve()
        for p in FIXTURES.rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    }
    orphans = on_disk - declared - allowed_extra
    assert not orphans, "undocumented fixture files (add them to manifest.json): " + ", ".join(
        str(p.relative_to(FIXTURES)) for p in sorted(orphans)
    )


# --------------------------------------------------------------------------- #
# Detection contract
# --------------------------------------------------------------------------- #

_MALICIOUS = [e for e in _fixtures() if e["classification"] == "malicious"]
_BENIGN = [e for e in _fixtures() if e["classification"] == "benign"]


@pytest.mark.parametrize("entry", _MALICIOUS, ids=_ids)
def test_malicious_fixture_trips_expected_rules(entry):
    """Each malicious fixture must trip every rule it declares (subset check)."""
    found = _scan_ids(FIXTURES / entry["path"], pro=True)
    expected = set(entry["expected_rules"])
    missing = expected - found
    assert not missing, (
        f"{entry['path']}: expected rules not detected: {sorted(missing)} "
        f"(found: {sorted(found)})"
    )


@pytest.mark.parametrize("entry", _BENIGN, ids=_ids)
def test_benign_fixture_is_clean_free_tier(entry):
    found = _scan_ids(FIXTURES / entry["path"], pro=False)
    assert not found, f"{entry['path']}: benign fixture flagged (free tier): {sorted(found)}"


@pytest.mark.parametrize("entry", _BENIGN, ids=_ids)
def test_benign_fixture_is_clean_pro_tier(entry):
    """Zero false positives must hold at the Pro tier too (more rules active)."""
    found = _scan_ids(FIXTURES / entry["path"], pro=True)
    assert not found, f"{entry['path']}: benign fixture flagged (Pro tier): {sorted(found)}"
