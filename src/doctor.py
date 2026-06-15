"""
Shellockolm doctor — environment self-check (build-loop task #28).

Pure, offline diagnostics that confirm a Shellockolm install is healthy *before*
a scan: the Python runtime meets the supported floor, the bundled detection
database and agent supply-chain rule catalog import and are populated, the config
and session directories are writable, the optional ``git`` dependency (needed by
``scan --diff`` and the pre-commit hook) is present, and the current license tier.

The check logic lives here, separated from CLI rendering (mirrors
:mod:`diff_scan` / :mod:`baseline`), so every check is unit-testable without
Typer. Running doctor makes **zero network calls** unless a license key is already
configured — :class:`licensing.LicenseManager` only contacts the server when a key
is present — preserving the "free tier is fully offline" guarantee.

Each check yields a :class:`Check` with one of four statuses:

* ``ok``   — healthy.
* ``warn`` — degraded but not fatal (e.g. ``git`` missing → ``--diff`` unavailable,
  a non-writable log dir → scans still run but aren't logged).
* ``fail`` — a real problem that stops scanning (old Python, a corrupt install);
  any FAIL makes doctor exit non-zero.
* ``info`` — neutral context (the license tier); never affects the exit code.

:func:`run_checks` returns a :class:`DoctorReport`; ``report.healthy`` is ``False``
iff any check FAILED. The CLI maps that to its exit code (0 healthy / 1 problems).
Every individual check catches its own exceptions, so one broken probe degrades to
a single FAIL/WARN row instead of aborting the whole self-check.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

# Minimum supported Python — mirrors pyproject `requires-python = ">=3.10"`.
MIN_PYTHON: Tuple[int, int] = (3, 10)

# Check statuses.
OK = "ok"
WARN = "warn"
FAIL = "fail"
INFO = "info"

_STATUSES = (OK, WARN, FAIL, INFO)


@dataclass
class Check:
    """One environment probe and its verdict."""

    name: str
    status: str
    detail: str
    hint: Optional[str] = None  # actionable remediation; only set when not OK

    def to_dict(self) -> dict:
        d = {"name": self.name, "status": self.status, "detail": self.detail}
        if self.hint:
            d["hint"] = self.hint
        return d


@dataclass
class DoctorReport:
    """The full set of checks plus a derived health verdict."""

    checks: List[Check] = field(default_factory=list)

    @property
    def healthy(self) -> bool:
        """True iff no check FAILED (warnings/info never make the env unhealthy)."""
        return not any(c.status == FAIL for c in self.checks)

    def counts(self) -> dict:
        return {s: sum(1 for c in self.checks if c.status == s) for s in _STATUSES}

    def to_dict(self) -> dict:
        return {
            "schema_version": "1.0",
            "tool": "shellockolm",
            "report": "doctor",
            "healthy": self.healthy,
            "summary": self.counts(),
            "checks": [c.to_dict() for c in self.checks],
        }


# ──────────────────────────────────────────────────────────────────────────
# Individual checks (each self-contained and exception-safe)
# ──────────────────────────────────────────────────────────────────────────
def check_python(version_info=None) -> Check:
    """Verify the running interpreter meets the supported floor."""
    v = version_info or sys.version_info
    cur = f"{v[0]}.{v[1]}.{v[2]}" if len(v) >= 3 else f"{v[0]}.{v[1]}"
    floor = ".".join(str(p) for p in MIN_PYTHON)
    if (v[0], v[1]) >= MIN_PYTHON:
        return Check("Python runtime", OK, f"Python {cur} (>= {floor} required)")
    return Check(
        "Python runtime",
        FAIL,
        f"Python {cur} is below the supported floor {floor}",
        hint=f"Install Python {floor}+ and re-run — Shellockolm uses {floor}+ syntax.",
    )


def check_detection_database() -> Check:
    """Verify the bundled CVE database imports and is populated."""
    try:
        from vulnerability_database import VulnerabilityDatabase

        n = len(VulnerabilityDatabase.get_all_vulnerabilities())
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch in tests
        return Check(
            "Detection database",
            FAIL,
            f"Failed to load the CVE database: {exc.__class__.__name__}: {exc}",
            hint="Reinstall Shellockolm — the bundled vulnerability database is missing or corrupt.",
        )
    if n == 0:
        return Check(
            "Detection database",
            FAIL,
            "The CVE database loaded but is empty.",
            hint="Reinstall Shellockolm — the bundled vulnerability database is corrupt.",
        )
    return Check("Detection database", OK, f"{n} bundled CVEs loaded")


def check_agent_rules() -> Check:
    """Verify the agent supply-chain rule catalog imports and is populated."""
    try:
        from scanners.agent_supply_chain import agent_rule_catalog

        rules = agent_rule_catalog()
        n = len(rules)
    except Exception as exc:  # pragma: no cover - exercised via monkeypatch in tests
        return Check(
            "Agent rule catalog",
            FAIL,
            f"Failed to load the agent supply-chain rules: {exc.__class__.__name__}: {exc}",
            hint="Reinstall Shellockolm — the agent scanner module is missing or corrupt.",
        )
    if n == 0:
        return Check(
            "Agent rule catalog",
            FAIL,
            "The agent rule catalog loaded but is empty.",
            hint="Reinstall Shellockolm — the agent scanner module is corrupt.",
        )
    free = sum(1 for r in rules if r.get("tier") == "free")
    pro = sum(1 for r in rules if r.get("tier") == "pro")
    return Check("Agent rule catalog", OK, f"{n} agent rules loaded ({free} free, {pro} Pro)")


def _probe_writable(directory: Path) -> Tuple[bool, str]:
    """Create ``directory`` if needed, write+delete a probe file under it.

    Returns ``(True, "")`` on success or ``(False, reason)`` on any failure.
    Never raises — a permission/long-path error becomes a reason string.
    """
    try:
        directory.mkdir(parents=True, exist_ok=True)
        # PID-stamped so two concurrent doctor runs don't collide on the probe.
        probe = directory / f".shellockolm-doctor-{os.getpid()}.tmp"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink()
        return True, ""
    except Exception as exc:
        return False, f"{exc.__class__.__name__}: {exc}"


def check_config_writable(home: Optional[Path] = None) -> Check:
    """Verify the ``~/.shellockolm`` config dir (license storage) is writable."""
    base = (Path(home) if home is not None else Path.home()) / ".shellockolm"
    ok, reason = _probe_writable(base)
    if ok:
        return Check("Config directory", OK, f"Writable: {base}")
    return Check(
        "Config directory",
        WARN,
        f"Not writable: {base} ({reason})",
        hint=f"Grant write access to {base} — the Pro license file (license.json) is stored there.",
    )


def check_temp_writable(tmp_root: Optional[Path] = None) -> Check:
    """Verify the session/log temp dir is writable (scans still run without it)."""
    base = Path(tmp_root) if tmp_root is not None else (Path(tempfile.gettempdir()) / "shellockolm")
    ok, reason = _probe_writable(base)
    if ok:
        return Check("Session/log directory", OK, f"Writable: {base}")
    return Check(
        "Session/log directory",
        WARN,
        f"Not writable: {base} ({reason})",
        hint="Session logs and temp scan artifacts can't be written; scans still run but won't be logged.",
    )


def check_git(which=shutil.which) -> Check:
    """Report whether ``git`` is on PATH (required by ``--diff`` / pre-commit)."""
    found = which("git")
    if found:
        return Check("git (for --diff / pre-commit)", OK, f"Found: {found}")
    return Check(
        "git (for --diff / pre-commit)",
        WARN,
        "git not found on PATH",
        hint="Install git to use `scan --diff` / `--diff-ref` and the pre-commit hook; full scans are unaffected.",
    )


def check_license() -> Check:
    """Report the active license tier (offline unless a key is configured)."""
    try:
        from licensing import LicenseManager

        mgr = LicenseManager()
        return Check("License", INFO, mgr.status_line())
    except Exception as exc:
        return Check(
            "License",
            WARN,
            f"Could not resolve license: {exc.__class__.__name__}: {exc}",
            hint="Free scanning is unaffected; Pro features require a valid license.",
        )


def run_checks() -> DoctorReport:
    """Run every check in order and return the assembled report."""
    return DoctorReport(
        checks=[
            check_python(),
            check_detection_database(),
            check_agent_rules(),
            check_config_writable(),
            check_temp_writable(),
            check_git(),
            check_license(),
        ]
    )
