"""
Platform compatibility helpers for Shellockolm.

Import this module early (before any Unicode output) to ensure
stdout/stderr are configured for UTF-8 on Windows.

    import compat  # noqa: F401  — side-effect import
"""

import sys
import os

_configured = False


def ensure_utf8_stdio():
    """Reconfigure stdout/stderr to UTF-8 on Windows.

    Safe to call multiple times — only acts once.
    On non-Windows platforms this is a no-op.
    """
    global _configured
    if _configured:
        return
    _configured = True

    if sys.platform != "win32":
        return

    try:
        # Enable VT100 escape sequences (colors/Rich markup) on Win10+
        os.system("")
        if hasattr(sys.stdout, "reconfigure"):
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stderr, "reconfigure"):
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        # Fallback for older Python or frozen executables
        os.environ.setdefault("PYTHONIOENCODING", "utf-8")


# Auto-configure on import so callers just need:  import compat
ensure_utf8_stdio()
