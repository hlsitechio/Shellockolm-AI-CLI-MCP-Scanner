"""
Tests for the modular scanners, focused on the Next.js middleware-bypass
detection (CVE-2025-29927).

A vulnerable package.json (next 14.1.5) must produce a finding that references
the CVE; a patched package.json (next 15.2.3) must NOT produce a middleware
bypass finding.
"""

import json

from scanners import NextJSScanner


def _write_package_json(directory, deps):
    pkg = {"name": "fixture-project", "version": "1.0.0", "dependencies": deps}
    (directory / "package.json").write_text(json.dumps(pkg, indent=2), encoding="utf-8")


def test_vulnerable_next_version_flags_cve(tmp_path):
    _write_package_json(tmp_path, {"next": "14.1.5"})

    scanner = NextJSScanner()
    result = scanner.scan_directory(str(tmp_path), recursive=True)

    cve_ids = {f.cve_id for f in result.findings}
    assert "CVE-2025-29927" in cve_ids, (
        f"Expected CVE-2025-29927 for next@14.1.5, got findings: {cve_ids}"
    )


def test_patched_next_version_has_no_middleware_bypass(tmp_path):
    _write_package_json(tmp_path, {"next": "15.2.3"})

    scanner = NextJSScanner()
    result = scanner.scan_directory(str(tmp_path), recursive=True)

    cve_ids = {f.cve_id for f in result.findings}
    assert "CVE-2025-29927" not in cve_ids, (
        f"next@15.2.3 is patched and must not flag the middleware bypass; "
        f"got findings: {cve_ids}"
    )


def test_scan_result_shape(tmp_path):
    """scan_directory must return a ScanResult-like object with a findings list."""
    _write_package_json(tmp_path, {"next": "14.1.5"})

    scanner = NextJSScanner()
    result = scanner.scan_directory(str(tmp_path), recursive=True)

    assert hasattr(result, "findings")
    assert isinstance(result.findings, list)
    # finalize_result() populates stats with the finding counts.
    assert result.stats.get("total_findings", 0) >= 1
    assert result.total_findings == len(result.findings)
