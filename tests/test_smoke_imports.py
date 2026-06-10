"""
Smoke test: import every top-level src module to catch import-time errors.

This would have caught the historical `gui.py` missing-`io` import bug and any
similar NameError/ImportError that only surfaces at module load time.

`gui` is skipped when tkinter is unavailable (common on headless CI), since its
import-time failure would then be about the environment, not the code.
"""

import importlib

import pytest

# Every loose module under src/ (mirrors pyproject's py-modules list).
SRC_MODULES = [
    "cli",
    "compat",
    "scanner",
    "server",
    "vulnerability_database",
    "scan",
    "scan_simple",
    "auto_fix",
    "mass_patcher",
    "malware_analyzer",
    "malware_scanner",
    "secrets_scanner",
    "security_score",
    "remediation",
    "github_actions",
    "github_advisory",
    "github_scanner",
    "ignore_handler",
    "watch_mode",
    "progress_tracker",
    "context_intelligence",
    "sarif_output",
    "sbom_generator",
    "configure_mcp",
    "dependency_tree",
    "lockfile_analyzer",
    "npm_audit",
    "mcp_server",
    "gui",
]


@pytest.mark.parametrize("module_name", SRC_MODULES)
def test_module_imports(module_name):
    if module_name == "gui":
        # gui depends on tkinter; skip cleanly if the GUI toolkit is absent.
        try:
            import tkinter  # noqa: F401
        except ImportError:
            pytest.skip("tkinter not available; skipping gui import")

    importlib.import_module(module_name)


def test_scanners_package_imports():
    """The scanners subpackage (with __init__.py) must import as a unit."""
    import scanners  # noqa: F401

    assert hasattr(scanners, "SCANNER_REGISTRY")
    assert hasattr(scanners, "get_all_scanners")
