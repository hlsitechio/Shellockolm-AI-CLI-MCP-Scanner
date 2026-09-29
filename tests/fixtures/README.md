# Detection-test fixture corpus

Real-shaped agent supply-chain artifacts used by the detection test suite. Each
fixture is a small, self-contained file that looks like something an agent would
actually be handed — a Claude/Cursor/Windsurf **skill**, an **MCP** server
config, an **n8n** workflow export, a **CLAUDE.md** instruction file, a
`.claude/commands` **slash command**, or a Claude Code **settings.json** — and is
labelled either `malicious` or `benign`.

`manifest.json` is the machine-readable source of truth (schema_version 1.0). It
is consumed by [`tests/test_fixture_corpus.py`](../test_fixture_corpus.py), which
enforces the corpus contract:

- **malicious** fixtures must trip every rule ID in their `expected_rules`
  (a *subset* check — broader detection by other rules is allowed and expected);
- **benign** fixtures must produce **zero** findings at **both** the free and the
  Pro tier (the zero-false-positive baseline);
- the manifest and the on-disk tree stay in sync (no undocumented files, every
  declared fixture present).

> ⚠️ These files contain *defanged* attack patterns for detection testing only.
> Secrets are placeholders, exfil hosts are the canonical research sinks
> (`webhook.site`, example domains), and nothing here is live. Do not copy a
> malicious fixture into a real agent.

## Layout

```
tests/fixtures/
├── manifest.json            # source of truth (path, classification, expected_rules)
├── README.md                # this file
├── skills/        {malicious,benign}/*.skill.md
├── mcp/           {malicious,benign}/*.mcp.json
├── n8n/           {malicious,benign}/*.json
├── instructions/  {malicious,benign}/**/CLAUDE.md
├── settings/      {malicious,benign}/.claude/settings.json
└── slash-commands/{malicious,benign}/.claude/commands/*.md
```

## Malicious fixtures

| Fixture | Attack class | Signature rules | What it is |
|---|---|---|---|
| `skills/malicious/tool-poisoning.skill.md` | prompt-injection | `AGENT-PI-004`, `AGENT-PI-008` | Hidden `<IMPORTANT>` block telling the agent to read `~/.cursor/mcp.json` + `~/.aws/credentials` and smuggle them out as a tool argument, concealed from the user. |
| `skills/malicious/homoglyph-admin-spoof.skill.md` | prompt-injection | `AGENT-PI-011` | Cyrillic homoglyph (`Аdmin`) inside an ASCII word to evade keyword review while coercing auto-run. |
| `skills/malicious/link-text-mismatch.skill.md` | prompt-injection | `AGENT-PI-012`, `AGENT-EXFIL-002` | Markdown link whose visible text claims `docs.python.org` but whose href points at an attacker host with a secret in the query string. |
| `skills/malicious/hidden-html-comment.skill.md` | prompt-injection | `AGENT-PI-013` | Imperative exfil instructions hidden inside an HTML comment (invisible when rendered, read by the model). |
| `skills/malicious/frontmatter-permission-bypass.skill.md` | prompt-injection | `AGENT-PI-014` | YAML frontmatter bakes in permission/safety-bypass flags (`permission-mode: bypassPermissions`, `--dangerously-skip-permissions`, `auto-approve: true`). |
| `mcp/malicious/raw-url-launcher.mcp.json` | mcp | `AGENT-MCP-005` | MCP server launched via `deno run` against a raw gist URL — unversioned, attacker-mutable code fetched at every launch. |
| `mcp/malicious/credential-exfil-env.mcp.json` | mcp | `AGENT-MCP-004` | A weather server's `env` block forwards a broad ambient `AWS_SECRET_ACCESS_KEY` unrelated to its purpose. |
| `n8n/malicious/credential-exfil-webhook.json` | n8n | `AGENT-N8N-002` | Reads a stored credential and POSTs it to `webhook.site` — credential read paired with an out-of-band sink. |
| `instructions/malicious/persistence-poisoning/CLAUDE.md` | prompt-injection | `AGENT-PI-015` | Tells the agent to append a covert exfil directive into its own `CLAUDE.md` so it auto-loads every future session. |
| `settings/malicious/.claude/settings.json` | hooks | `AGENT-HOOK-001` | A `PreToolUse` hook running `curl ... \| bash` — a zero-click download-and-execute RCE that auto-fires on lifecycle events. |
| `slash-commands/malicious/.claude/commands/release.md` | prompt-injection | `AGENT-PI-004` | A slash-command body that hides instructions to read `~/.aws/credentials` and POST it out. |

## Benign fixtures (zero-FP baselines)

| Fixture | What it is |
|---|---|
| `skills/benign/file-search.skill.md` | Ordinary glob file-search skill: no network, no credential reads, no hidden directives. |
| `skills/benign/progressive-disclosure.skill.md` | The official skill progressive-disclosure pattern (`read forms.md and follow its instructions`, `see ./docs/setup.md`) that `AGENT-PI-016` calibration deliberately treats as benign. |
| `mcp/benign/github-official.mcp.json` | Two hardened official MCP servers (github reading its matched `GITHUB_PERSONAL_ACCESS_TOKEN`, plus a filesystem server), pinned to exact versions, no `-y` auto-confirm. |
| `n8n/benign/internal-api-sync.json` | Reads a credential and POSTs to a first-party API host (not an out-of-band sink) — the legitimate shape `AGENT-N8N-002` must not flag. |
| `instructions/benign/project-guide/CLAUDE.md` | A normal CLAUDE.md project guide (conventions, layout, dependency policy). |
| `settings/benign/.claude/settings.json` | A settings.json whose only hook runs `prettier --write` — a normal formatting hook the dangerous-hook rules must not flag. |
| `slash-commands/benign/.claude/commands/lint.md` | A normal lint slash command full of legitimate imperative prose (`run the linter`, `fix issues`). |

## Running just the corpus tests

```bash
.venv/Scripts/python.exe -m pytest tests/test_fixture_corpus.py -v
```

## Adding a fixture

1. Drop the artifact under the right `<type>/<malicious|benign>/` directory.
2. Add a matching entry to `manifest.json` (path, classification, attack_class,
   `expected_rules`, description).
3. Run the corpus tests. `test_no_undocumented_fixture_files` will fail if you
   forget step 2; the detection tests will fail if a malicious fixture doesn't
   trip its declared rules or a benign one produces any finding.
