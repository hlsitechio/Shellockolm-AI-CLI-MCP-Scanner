"""
Tests for the .shellockolmignore pattern handler.

Verifies glob patterns compile and match correctly:
  *.min.js  -> app.min.js
  *.log     -> error.log
both at the low level (IgnorePattern) and via the high-level IgnoreHandler,
which ships these as default ignore patterns.
"""

from ignore_handler import IgnorePattern, IgnoreHandler


def test_ignore_pattern_matches_min_js():
    pattern = IgnorePattern("*.min.js")
    assert pattern.matches("app.min.js") is True
    assert pattern.matches("vendor/app.min.js") is True
    # A non-matching extension must not match.
    assert pattern.matches("app.js") is False


def test_ignore_pattern_matches_log():
    pattern = IgnorePattern("*.log")
    assert pattern.matches("error.log") is True
    assert pattern.matches("logs/error.log") is True
    assert pattern.matches("error.txt") is False


def test_handler_default_patterns_ignore_min_js_and_log():
    handler = IgnoreHandler()

    ignored_min, _ = handler.should_ignore("app.min.js")
    assert ignored_min is True

    ignored_log, _ = handler.should_ignore("error.log")
    assert ignored_log is True

    # A regular source file should not be ignored by the defaults.
    ignored_src, _ = handler.should_ignore("index.js")
    assert ignored_src is False
