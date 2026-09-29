"""
Tests for the .shellockolmignore pattern handler.

Verifies glob patterns compile and match correctly:
  *.min.js  -> app.min.js
  *.log     -> error.log
both at the low level (IgnorePattern) and via the high-level IgnoreHandler,
which ships these as default ignore patterns.
"""

from ignore_handler import (
    IgnorePattern,
    IgnoreHandler,
    IgnoreFile,
    _parse_rule_suppression,
)


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


# --------------------------------------------------------------------------- #
# Rule-ID suppression (.shellockolmignore allowlist for agent-scan findings)
# --------------------------------------------------------------------------- #


def test_parse_rule_suppression_global():
    sups = _parse_rule_suppression("AGENT-PI-013")
    assert sups is not None and len(sups) == 1
    assert sups[0].rule_id == "AGENT-PI-013"
    assert sups[0].path_pattern is None


def test_parse_rule_suppression_path_scoped():
    sups = _parse_rule_suppression("AGENT-PI-016 docs/skills/**")
    assert sups is not None and len(sups) == 1
    assert sups[0].rule_id == "AGENT-PI-016"
    assert sups[0].path_pattern is not None


def test_parse_rule_suppression_comma_list():
    sups = _parse_rule_suppression("AGENT-PI-013,AGENT-MCP-004 vendor/**")
    assert sups is not None
    assert {s.rule_id for s in sups} == {"AGENT-PI-013", "AGENT-MCP-004"}
    # The single shared path scope is applied to every rule in the list.
    assert all(s.path_pattern is not None for s in sups)


def test_parse_rule_suppression_rejects_path_patterns():
    # Ordinary path patterns must NOT be mistaken for rule IDs.
    for line in ["*.min.js", "node_modules/", "important-notes", "/config.local.js",
                 "MY-DIR/", "a,b.js"]:
        assert _parse_rule_suppression(line) is None, line


def _write_ignore(tmp_path, body):
    p = tmp_path / IgnoreHandler.IGNORE_FILENAME
    p.write_text(body, encoding="utf-8")
    return p


def test_ignore_file_separates_rules_from_paths(tmp_path):
    _write_ignore(tmp_path, "node_modules/\n*.log\nAGENT-PI-013\n")
    igf = IgnoreFile(tmp_path / IgnoreHandler.IGNORE_FILENAME)
    # Path patterns and rule suppressions are parsed into their own buckets.
    assert len(igf.patterns) == 2
    assert len(igf.rule_suppressions) == 1
    assert igf.rule_suppressions[0].rule_id == "AGENT-PI-013"


def test_ignore_file_rule_should_ignore_global(tmp_path):
    _write_ignore(tmp_path, "AGENT-PI-013\n")
    igf = IgnoreFile(tmp_path / IgnoreHandler.IGNORE_FILENAME)
    assert igf.rule_should_ignore("AGENT-PI-013", str(tmp_path / "any" / "SKILL.md"))
    # A different rule is never suppressed by it.
    assert not igf.rule_should_ignore("AGENT-PI-099", str(tmp_path / "any" / "SKILL.md"))


def test_ignore_file_rule_path_scoped(tmp_path):
    _write_ignore(tmp_path, "AGENT-PI-016 vendored/**\n")
    igf = IgnoreFile(tmp_path / IgnoreHandler.IGNORE_FILENAME)
    assert igf.rule_should_ignore("AGENT-PI-016", str(tmp_path / "vendored" / "SKILL.md"))
    # Same rule outside the scoped path is NOT suppressed.
    assert not igf.rule_should_ignore("AGENT-PI-016", str(tmp_path / "app" / "SKILL.md"))


def test_handler_is_rule_suppressed(tmp_path):
    _write_ignore(tmp_path, "AGENT-MCP-004 config/**\n")
    handler = IgnoreHandler()
    handler.load_project_ignores(str(tmp_path))
    assert handler.get_stats()["rule_suppressions"] == 1

    suppressed, reason = handler.is_rule_suppressed(
        "AGENT-MCP-004", str(tmp_path / "config" / "mcp.json"))
    assert suppressed is True and reason

    suppressed, _ = handler.is_rule_suppressed(
        "AGENT-MCP-004", str(tmp_path / "src" / "mcp.json"))
    assert suppressed is False
