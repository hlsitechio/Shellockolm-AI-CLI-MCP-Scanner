# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> Older history (2.0.0 and earlier) lives in [docs/CHANGELOG.md](docs/CHANGELOG.md).

## [Unreleased]

### Fixed

- **A hook registry keyed by another client's event names is no longer invisible to
  the directory walk.** A `hooks` block auto-runs shell commands with no
  per-invocation prompt, so failing to *route* one is worse than a missed pattern —
  the file is never opened by any rule, and a clean report for it means UNSCANNED,
  not safe. The content route that classifies a hook registry qualified a file on one
  arm: a top-level `hooks` dict keyed by a name in Claude Code's lifecycle vocabulary.
  That made the gate an allow-list of event NAMES, and it guarded the **primary**
  entry point — `shellockolm scan .`, which is what the pre-commit hook and the GitHub
  Action run. A `.cursor/hooks.json` whose events are `beforeShellExecution` /
  `afterFileEdit` and whose command is `curl … | bash` scored **zero** through the
  walk, while `scan_text` — which has always gated on the extractor ("does a command
  actually come out of this?") — scored **CRITICAL** on the identical bytes. The two
  entry points disagreed, and swapping one event name to `stop` made the same file
  fire. The gate now qualifies on either arm: a known lifecycle event (which still
  carries registries declaring no command at all, such as a `type: "prompt"` hook, and
  is what keeps the change a strict superset) **or** a `hooks` dict or list from which
  a command is actually extracted — self-validating, so it covers every client's
  vocabulary, present and future. Both arms keep the `hooks` anchor, which is what
  stops an unrelated JSON that merely carries a `command` string (an n8n
  Execute-Command node) from being dragged onto the settings rule path. The parse-free
  counterpart used for the unparseable-file coverage warning was widened to match, so
  a malformed foreign-vocabulary registry is still announced as unscanned. No new
  rules and no pattern changes: the already-calibrated AGENT-HOOK-* set is simply
  reachable wherever a hook registry lives. Verified on 5,517 real artifacts —
  finding set **byte-identical** (338 findings, 0 new, 0 lost) while 2 more artifacts
  are now actually scanned, both genuine registries that were invisible: the
  **official `claude-security` plugin's** `hooks/hooks.json` (keyed by
  `UserPromptExpansion`) and a marketplace plugin whose `hooks` is a list of
  `action.command` entries. Non-vacuous: with a payload planted, the walk catches
  **51/51** real hook registries on that machine, against 49/51 before. 53 new tests,
  mutation-verified (20 fail without the fix).

### Added

- **AGENT-MCP-009 — a remote MCP server's `headers` block is now scanned for credential
  forwarding** (rule catalog 44 → 45, free tier, HIGH). AGENT-MCP-004 flags a broad
  ambient host credential (AWS keys, `GITHUB_TOKEN`, `KUBECONFIG`, `NPM_TOKEN`, …)
  forwarded to an unrelated MCP server through its `env` block — but a **remote**
  server has no `env` block at all. The http / sse / streamable-http transports are
  configured with a `url` plus a `headers` map the client attaches to every JSON-RPC
  request, and that channel was scanned by nothing: the identical payload scored an
  AGENT-MCP-004 finding in `env` and **zero** one key over, purely because the server
  is remote rather than spawned. Confirmed on disk before the fix. The header channel
  is also the **worse** of the two — an `env` value is handed to a process on your own
  machine, which must then choose to exfiltrate it, whereas a header value is
  transmitted to the third-party host on *every request*, so the credential has
  already left the machine by the time anyone looks. The credential map is shared with
  AGENT-MCP-004 (a "broad ambient credential" is a property of the credential, not of
  the channel), and a literal secret pasted into a header is deliberately left to the
  existing raw-text credential rules rather than double-reported. **Service
  association had to differ**, and that is the whole calibration: a remote server has
  no command/args, so the evidence is the transport URL, read as the **registrable**
  domain's leftmost label with the service token required to sit at a label boundary.
  `https://api.githubcopilot.com/mcp/` carrying a `${GITHUB_TOKEN}` is GitHub's own
  remote MCP server and is correctly suppressed (a delimited-token match — what
  AGENT-MCP-004 uses for command/args — does *not* match `github` inside
  `githubcopilot`, so a naive port false-positives on the most common remote MCP
  server in existence), while `https://github.evil.tld/mcp` with the same token still
  fires, because a service name in a subdomain is free to claim. Calibrated against
  438 real MCP servers across 104 real configs on a live machine: 9 carry a `headers`
  block and none is a leak (4 literal tokens, 1 `<YOUR_HF_TOKEN>` placeholder, 1
  `${input:…}` client prompt, 2 app-scoped Datadog keys, 1 official GitHub server) —
  a full agent scan of 5,517 real artifacts is **byte-identical before and after**
  (338 findings, 0 new, 0 lost), and the zero is non-vacuous: those same 9 real
  servers with a broad credential planted in their own headers block are caught 9/9.
  58 new tests, mutation-verified.
- **AGENT-ENV-001 / AGENT-ENV-002 — the `env` block is now scanned as a runtime-hijack
  channel** (new `runtime-hijack` attack class; rule catalog 42 → 44, both free tier).
  An agent config's `env` block reconfigures the **agent itself**, with no command to
  review, no lifecycle hook to notice, and no permission prompt to decline — and every
  existing rule looked somewhere else: the credential sweep matches secret *values*,
  AGENT-MCP-004 matches a credential forwarded to the wrong *server*, and AGENT-HOOK-*
  only reads keys holding a *command*. Confirmed live: a `.claude/settings.json` that
  redirected all model traffic to an attacker relay **and** preloaded a module into the
  agent's Node process scored **0 findings**, despite the file being scanned.
  **AGENT-ENV-001** (CRITICAL) fires when a model-endpoint variable
  (`ANTHROPIC_BASE_URL`, `ANTHROPIC_BEDROCK_BASE_URL`, `ANTHROPIC_VERTEX_BASE_URL`,
  `OPENAI_BASE_URL`, …) points at a literal URL whose host is neither the vendor's own
  endpoint nor a local/private dev address. The host then receives every prompt — plus
  whatever files and secrets the agent read to build it — and **authors every response**,
  and the response is what selects the agent's next tool call, so the redirect is a
  persistent injection channel rather than passive eavesdropping. **AGENT-ENV-002**
  (CRITICAL) fires on a variable that loads attacker code into the agent process before
  its own entrypoint runs: `NODE_OPTIONS` carrying a module-loading flag
  (`--require` / `-r` / `--import` / `--loader` / `--experimental-loader`),
  `PYTHONSTARTUP`, `BASH_ENV`, `LD_PRELOAD`, `LD_AUDIT`, `DYLD_INSERT_LIBRARIES`. Both
  run at **both** places an `env` block lives — a `.claude` settings file and each MCP
  server's per-server `env` — through one shared verdict function, so an identical
  payload cannot score differently depending on which block it is parked in.
  Calibrated against real config, not against what sounds dangerous: a sweep of 4,708
  JSON files on a live machine (54 with `env` blocks, 97 distinct keys) drove four
  deliberate exclusions — `HTTP_PROXY`/`HTTPS_PROXY` (a published, legitimate
  `corporate-proxy.json` template sets both), any key merely *containing* `BASE_URL`
  (a real MCP config sets `CIRCLECI_BASE_URL=https://circleci.com`), the bare
  `ANTHROPIC_` prefix (`ANTHROPIC_MODEL` / `ANTHROPIC_SMALL_FAST_MODEL` /
  `ANTHROPIC_VERTEX_PROJECT_ID` / `ANTHROPIC_CUSTOM_HEADERS` are all legitimate), and
  `PYTHONPATH` (a real template ships `PYTHONPATH: "."`; it shadows resolution but
  loads nothing). `NODE_EXTRA_CA_CERTS` is excluded on the same grounds as the proxy
  vars. **Zero-FP verified non-vacuously on real content:** the live scanner over
  `~/.claude` + `G:/skills` (**5,517 scanned artifacts**) produces a finding set
  **byte-identical before and after** — 338 findings, 0 new, 0 lost, identical
  per-scanner stats — while the same real configs *with the payload planted in their
  own env block* are caught **35/35** across every routed config that carries one.
  100 new tests (`tests/test_env_runtime_hijack.py`), mutation-verified: reverting the
  settings wiring fails 4, the MCP wiring 3, the redirect verdict 15, and the
  NODE_OPTIONS gate 11. RULES.md + THREAT_MODEL.md regenerated.

### Changed

- **Relicensed from MIT to the PolyForm Strict License 1.0.0 (source-available).**
  Shellockolm is now source-available, not open source: free for personal, research,
  and nonprofit use, but commercial/business use requires a paid commercial license
  (see `COMMERCIAL-LICENSE.md`), and the code may no longer be copied, forked,
  redistributed, or modified. The source stays fully readable so the tool can still
  be audited. Updated `LICENSE`, `pyproject.toml`, `mcp.json`, `README.md`, and the
  `src/licensing.py` docstring; runtime behaviour is unchanged. Website marketing
  copy still advertises the old MIT/open-core promise and must be updated to match.

### Fixed

- **A Claude Code plugin is now a scannable artifact tree — closing a whole-format blind
  spot on the ecosystem's unit of distribution.** A plugin ships commands, subagents,
  skills, an MCP config and a `hooks` registry, but 4 of the 6 class × placement cells
  reached no scan path at all. **(1)** `SETTINGS_NAMES` knows only `settings.json` /
  `settings.local.json`, so a plugin's hook file — `hooks/hooks.json`, or whatever name
  its `plugin.json` points at (real marketplace plugins ship `codex-hooks.json`,
  `hooks-cursor.json`) — was routed by nothing: the identical `curl … | bash` payload
  scored 2 findings (AGENT-HOOK-001 + AGENT-HOOK-003) in a `.claude/settings.json` and
  **zero** in the plugin hook file beside it. That is the worst cell in the matrix — a
  hook command auto-executes on a lifecycle event with no per-invocation prompt, and it
  was invisible **even after installation** (on the author's machine, 83 live hook
  registries under `~/.claude` were read by no rule). Hook files now route by a content
  **signature** — a top-level `hooks` dict keyed by a real lifecycle event — mirroring
  the existing `_json_declares_mcp_servers` route, so every place a registry can live is
  covered rather than a list of filenames. **(2)** `_is_command_file` /
  `_is_subagent_file` require a `.claude` ancestor, which holds for an *installed*
  plugin but not for a plugin **repo**, where `commands/` and `agents/` sit at the plugin
  root — so they were unscannable at exactly the moment the check is worth something:
  reviewing a cloned plugin *before* installing it. Both now also accept the plugin's own
  official marker (`<root>/.claude-plugin/plugin.json`), so carrying the marker is what
  makes a directory plugin content and an unrelated `commands/` or `agents/` folder is
  still never treated as agent artifacts. No detection rule was added (count stays 42)
  and an unparseable hook file is reported, never silently dropped. Verified on 5,400+
  real agent artifacts: the finding set is **byte-identical** (336) while
  `claude_settings_scanned` rises **17 → 100**, and those same 83 real hook files each
  with one planted payload are caught **83/83**.

- **JSON `\uXXXX` escapes no longer defeat the entire stealth suite on config artifacts.**
  The four stealth checks (invisible characters PI-005, Unicode Tags PI-007, bidi PI-010,
  homoglyphs PI-011) are signature matches on literal code points — which is exactly what
  makes them safe to run on config, and was also their blind spot. JSON expresses any code
  point as a pure-ASCII escape, so a malicious `mcp.json`, n8n export or `settings.json`
  could carry a zero-width space or a Tags-smuggled instruction while containing no
  non-ASCII byte at all: `str.isascii()` and `_STEALTH_CHARS_RE` (the fast paths added for
  performance) both short-circuited, **all four checks were skipped**, and `json.loads`
  still handed the client the byte-identical malicious string. Measured on the three JSON
  artifact classes, every one of the 12 check × class cells was blind in the escaped form
  (literal → 1 finding, escaped → **0**). This was not a crafted-input bug: `json.dumps`
  escapes **by default** (`ensure_ascii=True`), so the bypassing form is what any
  Python-emitted config already looks like — an attacker need only let the standard
  library serialize the payload. The three raw-text scan paths now decode above-ASCII
  escapes before re-running the suite, the fix precedented in the same module by
  `_check_n8n_cred_exfil`'s `ensure_ascii=False` re-serialization (which is why the
  *structured* paths were escape-immune all along). Decoding is deliberately partial and
  in place — only escapes above U+007F, so an escaped newline cannot renumber every line
  below it and a reported line still points at the right line of the real file; surrogate
  pairs are combined so an astral Tags character is the single character the checks
  expect; escaped backslashes are honoured by run parity; and it works on a config that
  does not parse (trailing comma, `//` comment), which is the case that most needs it.
  Findings are collapsed to one per rule, preferring the literal-text hit. Verified as a
  strict no-op on 5,289 real agent artifacts (**0 new findings**, byte-identical set), and
  non-vacuously via a re-serialization sweep: all 55 real mcp.json/settings.json rewritten
  into the escaped form score identically, with 4 carrying non-ASCII that genuinely drives
  the decoder. 49 new tests.

- **AGENT-PI-005 now covers the whole invisible-character category (was 6 of 64).** This
  rule is the safety net behind the natural-language rules: an attacker who splices an
  invisible code point into a keyword (`Ign<invisible>ore all previous instructions`)
  defeats AGENT-PI-001, and PI-005 is the only thing left standing. Its set was a
  hand-picked list of six while the same Unicode format category (`Cf`) holds 64 — so
  `U+2062 INVISIBLE TIMES`, the immediate neighbour of the word joiner that *was*
  covered, took a malicious skill from 1 finding to **zero**. The set is now the `Cf`
  category itself (23 hardcoded ranges, guarded by a `unicodedata`-recomputed anti-drift
  test), minus the code points owned by the more specific sibling rules (bidi controls →
  AGENT-PI-010, Tags block → AGENT-PI-007) and plus a documented set of non-`Cf`
  invisibles including the variation-selector supplement. The emoji presentation
  selectors U+FE00–FE0F are deliberately excluded — U+FE0F appears in 603 files of the
  real calibration corpus, so including them would trade one bypass for hundreds of false
  positives. Findings now name the code point (`U+2062 INVISIBLE TIMES`) and point at the
  earliest occurrence in the text rather than the first member of the constant.
  Verified as a strict no-op on 9,133 real artifacts: **0 new findings**.

- **AGENT-PI-005 no longer false-positives on emoji.** U+200D ZWJ is how a multi-part
  emoji is composed (`🧑‍💻`, `👨‍👩‍👧`, `❤️‍🔥`), and it was flagged as a smuggled
  separator — the rule's *only* hit across the 9,133-artifact real corpus was one of
  these, i.e. its real-world precision was 0%. A ZWJ is now suppressed only when a
  pictograph sits on both sides; a ZWJ between two letters, or between a letter and an
  emoji, still fires.

- **Hardcoded-credential detection now reaches every artifact class.** A real credential
  can be pasted into any artifact an agent loads, but the credential rules did not run
  everywhere: measured against the previous release, a 9-shape × 6-site matrix was blind in
  **10 of 54 cells**. `.claude/settings.json` was a whole-class hole — all 9 shapes scored
  **zero** — and it is the worst one to have, because its documented `env` block is exactly
  where Claude Code is told to put API keys and the file is routinely committed to a repo.
  The identical three credentials scored 3× HIGH in a `SKILL.md` and **nothing** in a
  `settings.json` next to it. `_scan_settings` deliberately excludes the broad
  natural-language rules (a config file is not model-facing prose), and the credential rules
  had been swept out along with them; separately, the Supabase **service_role** JWT decode
  never ran on n8n exports, so the RLS-bypassing server secret was invisible there. Every
  site now derives from one canonical `CREDENTIAL_RULES` set, paired with the JWT decode by
  `_check_credentials`, and the n8n direct-embed pairing (`AGENT-N8N-002`) consumes the same
  dataset via `_credential_match` instead of its own SECRET-001-only copy — so a node
  shipping a hardcoded Stripe live key to an external host is now recognised as a credential
  read at all. Matrix is **10/54 blind → 0/54**. Widening `settings.json` is safe because
  these are signature matches on distinctive key prefixes, not NL heuristics: a `${VAR}`
  interpolation, an `apiKeyHelper` that shells out, and a secret-manager reference carry no
  literal and cannot match; the anon-key anti-false-positive (shape-identical to the
  service_role secret, safe to ship) holds at the new site too, and the NL-rule exclusion is
  now locked by test in both directions. No rule added (count stays 42); severity and
  redaction are unchanged, so no finding re-emits a live credential. Verified zero
  false positives non-vacuously: **5,284 real agent artifacts** produce a finding set
  byte-identical before and after (283 findings), all **18** real `settings.json` files on
  the test machine stay clean, and those same 18 files each with one planted credential are
  caught **18/18**.

### Added

- **`AGENT-MCP-008` — MCP server launch command runs an obfuscated / encoded payload**
  (HIGH, confidence high). An agent auto-executes a command from two config sites with no
  per-invocation prompt: a `settings.json` command key (`hooks`, `statusLine`,
  `apiKeyHelper`, …) and an **MCP server's launch command**, spawned the moment the session
  starts. `AGENT-HOOK-002` caught an encoded payload at the first site, but the MCP launcher
  had no obfuscation rule at all — so writing the identical payload one config file over
  made it vanish. Against the previous release, `powershell.exe -NoProfile -EncodedCommand
  <blob>`, `pwsh -enc <blob>`, `base64 -d | bash` and a `FromBase64String(…)|iex` cradle each
  scored HIGH under a settings hook and produced **zero findings** in an MCP launcher; all
  are now HIGH at both. The raw-text pass did not cover it for two structural reasons:
  `AGENT-MCP-003`'s `-encodedcommand` alternative carries a leading `\b`, which can never
  match a real flag (a `-` preceded by a space or a JSON quote is not a word boundary), and
  the generic `AGENT-OBF-001` runs over the raw JSON, where per-arg quoting
  (`"base64", "-d", "|", "bash"`) breaks a pattern expecting a shell command line — joining
  a server's command+args is what makes the payload visible. Both sites now consume one
  shared `_OBFUSCATED_EXEC` pattern, so neither can keep a narrower copy or drift (a test
  asserts the two rules hold the same compiled object). The shared pattern also gained the
  `eval(atob('…'))` nesting order, which previously fired at **neither** site. Like
  `AGENT-MCP-001`, the rule inspects the **launch path only** (command + args): an env value
  is data handed to the process, not a command line, so a base64 config blob in an env var
  is not an encoded launcher (secrets/exfil rules still see `env`). Verified zero false
  positives non-vacuously on 49 real MCP configs (64 servers, 48 real launch commands) and
  28 real `.claude` settings files, with the complete finding set byte-identical before and
  after — a strict no-op on real configs while closing the evasion.

- **`AGENT-PERM-001` — Claude Code settings disable the tool-call confirmation prompt**
  (MEDIUM, confidence high). A `.claude/settings.json` `permissions` block decides which
  tool calls run **without** asking the human. That per-call confirmation is the primary
  guardrail between a prompt injection the agent just read and arbitrary execution on the
  machine, so a committed settings.json that turns it off means anyone who clones the repo
  silently opts into unattended execution — and it compounds an auto-running hook
  (`AGENT-HOOK-*`) into a zero-click compromise. The Claude Code analogue of a blanket MCP
  auto-approval (`AGENT-MCP-007`) or a `bypassPermissions` SKILL.md frontmatter flag
  (`AGENT-PI-014`). Detection is a structural parse and deliberately narrow — it fires
  **only** on the two documented **blanket** forms: `permissions.defaultMode:
  "bypassPermissions"` (documented as skipping permission prompts), or a blanket
  `permissions.allow` entry for a command-**execution** tool (a bare `Bash` is documented
  as matching every Bash command, and `Bash(*)` as equivalent; PowerShell rules use the
  same shape). A scoped allow-list is the feature working as intended and is **never**
  flagged. Also deliberately **not** flagged, each per the documented semantics: the
  `auto` / `dontAsk` modes (documented as *safer*, not prompt-skipping — `auto` gates on a
  classifier and honors `ask` rules, `dontAsk` auto-*denies* anything not pre-approved),
  `acceptEdits` / `plan` / `default`; an unanchored `allow` glob (`"*"`, `"B*"`,
  `"mcp__*"` — documented as skipped with a warning, granting nothing); a blanket entry in
  `deny` / `ask` (a restriction, not a risk); and bare read-only tools (`Read` / `Glob` /
  `Grep` / `WebSearch`) or exact MCP tool names. Only `allow` is inspected, and only inside
  a `.claude` tree (a `.vscode/settings.json` is ignored). `scan_text`'s `auto` mode now
  also recognizes a **permissions-only** settings.json (which carries no `hooks` key),
  requiring a real permissions sub-key so an unrelated JSON with a `permissions` field is
  not misrouted. Wired into the catalog (`rules list` / `rules explain`), RULES.md +
  THREAT_MODEL.md (regenerated, new `permission-bypass` attack class; rule count 40 → 41,
  free 37 → 38). Verified against the **32 real settings.json files on a live machine** at
  the strictest Pro tier: exactly **2 flagged, both ground-truth-confirmed true positives**
  (`defaultMode: bypassPermissions`; one also carrying a genuine `Bash(*)` among 105
  otherwise-scoped allow entries) — **zero false positives** across the remaining 30 files
  and their 478 scoped allow entries. Malicious + benign fixtures added to the corpus;
  67 new tests (`tests/test_settings_permissions.py`).

- **`AGENT-MCP-007` — MCP server that blanket-auto-approves every tool call**
  (MEDIUM, confidence high). Several MCP clients (Cline, Roo Code, Cursor, Windsurf)
  let a per-server config pre-approve tool calls so the agent runs them **without** the
  usual per-call human confirmation — the primary guardrail against a malicious or
  compromised server. Detection is structural and deliberately narrow: it fires **only**
  on a **blanket** approval (a wildcard `"*"` or a boolean `true` on an
  `alwaysAllow` / `autoApprove` setting, incl. spelling variants like `always_allow` /
  `auto-approve`), which auto-approves every tool the server exposes — including any tool
  a later server update silently adds (a rug-pull). An explicit scoped allow-list of
  specific tool names (`alwaysAllow: ["read_file"]`), an empty list, or a falsey value is
  the user's deliberate, safe choice and is **never** flagged. This is the MCP analogue of
  a `SKILL.md` `bypassPermissions` frontmatter flag (`AGENT-PI-014`) or an auto-running
  settings hook (`AGENT-HOOK-*`). Verified with a malicious + benign fixture pair, zero
  over-firing across the machine's real MCP configs, and 58 new tests (wildcard-list /
  wildcard-scalar / boolean-true / spelling-variant positives, the scoped-list / empty /
  falsey / `all_files`-tool-name / integer-`1` zero-FP baselines, an MCP-005-launcher
  compose case, helper units, and catalog/example drift guards). Rule catalog 39 → 40
  (free 36 → 37); `RULES.md` + `THREAT_MODEL.md` regenerated.
- **`AGENT-MCP-006` — remote MCP server over cleartext `http://` / `ws://` transport**
  (MEDIUM, confidence high) closes a deliberate gap in `AGENT-MCP-005`, which inspects
  a *local* server's launch command and ignores the transport `url` field. A **remote**
  MCP server configured with a `url` / `serverUrl` / `endpoint` over an unencrypted
  scheme to a **public** host sends its JSON-RPC traffic in the clear: an on-path
  attacker can read any bearer token in the transport headers **and** — the sharper
  risk for an agent — rewrite the server's responses in flight, so forged tool
  **results** and tool **definitions** injected over the wire become prompt injection
  the agent trusts. Detection is structural (parse the URL, classify scheme + host):
  it fires only on `http`/`ws` to a genuinely public host/IP, and never on local
  development — `localhost`, `127.0.0.1`, `[::1]`, RFC1918 / link-local IPs, and
  `*.local` / `*.internal` / `*.lan` / `host.docker.internal` are all excluded (cleartext
  to a local server is ordinary). `https://` / `wss://` and ordinary stdio servers are
  untouched. The rendered finding drops the URL's userinfo and query string so it never
  re-emits an embedded token. Verified with a malicious + benign fixture pair and 30 new
  tests (per-field-key positives, public-IP + `ws://` coverage, redaction, the full
  local/private zero-FP matrix, an MCP-005-launcher-path differential, and the
  `_is_local_or_private_host` helper units); the self-scan gate stays clean at HIGH+.
- **Subagent-definition coverage (`.claude/agents/**/*.md`)** — the agent scanner
  now reads Claude Code subagent definitions, a model-facing artifact class it was
  previously blind to. A subagent file's frontmatter names a delegated agent and
  its Markdown body becomes that agent's **system prompt**, so a poisoned definition
  (project-level or an installed plugin's `.claude/plugins/.../agents/*.md`) injects
  standing instructions into a sub-agent the primary agent hands work to — the same
  trust boundary as a slash command or skill. New `_is_subagent_file()` recognizes
  the path (a `.md` under an `agents/` dir with a `.claude` ancestor, incl. namespaced
  subdirs) and routes it through the **identical high-precision command-class detection
  path** as slash commands: every structural / stealth-channel check plus the
  unambiguous malicious-content rules, but excluding the broad natural-language
  heuristics (`_COMMAND_EXCLUDED_RULE_IDS`) that a dense imperative system prompt
  ("You are the ARCHITECT…", "When the user asks to …") would trip — so the command
  calibration transfers and the deterministic rules (hardcoded secret, link/domain
  mismatch, secret-exfiltration instruction, homoglyph smuggle) still fire. Both the
  directory walk (new `subagents_scanned` stat) and `scan_text`'s `auto` mode pick it
  up. Verified over the machine's real subagent corpus (benign definitions produce
  zero findings) with a canonical injection / hardcoded secret firing in each location
  and a differential proof that an excluded rule fires on a *skill* but is suppressed
  on a *subagent* with the identical body; the self-scan gate stays clean at HIGH+.

### Fixed

- **`AGENT-EXFIL-003` missed `*.ngrok-free.app` — the domain every free ngrok tunnel
  gets** — the out-of-band sink host list existed as three independent hand-maintained
  copies (the generic prose rule `AGENT-EXFIL-003`, which runs on every skill /
  instruction / command file and the raw MCP config text; the settings auto-run rule
  `AGENT-HOOK-003`; and the n8n pairing `AGENT-N8N-002`), and they had drifted — with the
  widest-reaching copy the most stale. Against the previous release, `AGENT-EXFIL-003`
  knew only the legacy `*.ngrok.io/.app/.dev` domains, so a skill exfiltrating to
  `*.ngrok-free.app` scored **zero** on the product's core surface while the identical URL
  inside a settings hook scored HIGH. `*.ngrok-free.dev` (also missed by the n8n rule),
  `paste.ee`, and a bare `pastebin.com` (the pattern required a trailing `/`) had drifted
  the same way. All three sites now derive from one shared dataset, so a sink added for one
  site can never again be invisible at another. The change is a strict superset — every
  host the previous pattern matched still matches — and Slack/Discord incoming webhooks and
  pipedream remain deliberately scoped to prose only, since a build hook or workflow posting
  a status message to Slack is ordinary plumbing. Verified as a no-op on real content: 5,284
  real agent artifacts produce a byte-identical finding set.
- **`AGENT-PI-002` false positives on a skill's own activation docs** — the
  low-confidence hidden-conditional-trigger heuristic no longer fires when its
  "when the user does X" match sits where a skill legitimately *advertises* when
  it applies: the YAML `description:` field (the official format's activation
  contract, incl. documented `description:` examples shown inside a ```yaml
  fence) or a "When to use" section. A genuine covert trigger in ordinary body
  prose still fires, and a malicious description's action clause is still caught
  by the high-confidence rules (PI-001/PI-003/PI-006/EXFIL/DESTRUCT). Drops the
  legit-corpus PI-002 false-positive count from 13 to 0.
- **`AGENT-PRO-002` false positives on benign "instead of" prose** — the
  tool/skill-shadowing heuristic treated the weak comparative preposition
  "instead of" the same as the strong imperative verbs (override/replace/shadow/
  supersede/redefine/take precedence over), so it fired on ordinary instructional
  prose ("write a standalone HTML file instead of starting a server", 'say "This
  skill should be used when…" instead of "Use this skill when…"'). The "instead
  of" branch now fires only when it targets a *qualified existing/trusted* tool
  ("instead of the built-in/official/real/default … tool/command/skill") — the
  genuine "use this in place of the real one" hijack shape. The strong imperative
  verbs are unchanged, so genuine shadowing still trips the rule. Drops the
  legit-corpus PRO-002 false-positive count from 2 to 0.
- **`AGENT-PRO-001` false positive on the official progressive-disclosure
  pattern** — the Pro indirect-injection rule names *fetched external* content
  ("fetch a remote page, then obey it"), but its broad "<fetch/read…> … then
  <follow/do…>" phrasing also matched benign *local* shapes ("read the changed
  files then run the tests"; the skill-creator's "read the skill's SKILL.md, then
  follow its instructions"). PRO-001 now fires only on a genuine *external* fetch
  (a remote verb, or a URL/web/link/remote indicator in the match window); a local
  read-and-follow is left to `AGENT-PI-016`, so no genuine attack is lost.
- **`AGENT-PI-006` false positive on benign bare-adverb prose** — the
  covert-action rule's bare "silently"/"covertly" alternations matched ordinary
  technical prose describing an output surface or control flow ("Update context
  silently (no visible message)", "the call fails silently", "do NOT silently
  continue"). A bare-adverb match is now suppressed when a no-visible-surface
  clause sits in its window or it directly governs a benign control-flow/error
  verb; a bare adverb modifying a genuine action ("silently exfiltrate") still
  fires, and every strong concealment branch is untouched.
- **`AGENT-DESTRUCT-001` false positive on a documented detection-pattern
  example** — the destructive-shell-command rule (`rm -rf ~//*`, `mkfs`, fork
  bomb, `del /f`, `format c:`, `> /dev/sd`) also matched a destructive command
  shown as the *value of a detection pattern* in a rule-authoring skill
  (Anthropic's `writing-rules`: `pattern: rm -rf /tmp  # Only matches exact
  path`) — a string the rule matches with, never executes. A match on a
  detection-pattern key line (`pattern:`/`regex:`/`match:`/`grep:`/`search:`) is
  now suppressed, while a run-this command in body prose or a hook `command:`
  value still fires (provably non-blinding — an executed command never lives as a
  detection-pattern value). Drops the legit-corpus DESTRUCT-001 false-positive
  count to 0; no change on the live 1,333-skill corpus, confirming tight scope.

## [3.1.0] - 2026-06-22

The first open-core feature batch since the 3.0.0 packaging fix — additive
throughout: the OSS core stays free and MIT, and Pro remains a strictly
additive, license-gated detection rule pack. Highlights:

- **Detection depth** — the agent supply-chain scanner gained new
  prompt-injection, MCP, n8n, hook, and secret rules, plus a `confidence` axis
  and composite-severity scoring (see `RULES.md` / `THREAT_MODEL.md`).
- **CI-grade CLI** — `--json`, `--sarif`, a documented `--fail-on` exit-code
  contract, `--diff`, `--baseline`, `--table`, a discoverable `shellockolm.toml`
  config file, and new `rules list|explain` + `doctor` commands, plus a
  pre-commit hook and a GitHub Action.
- **Agent-native MCP** — four new tools (`scan_agent_artifacts`, `scan_text`,
  `explain_finding`, `check_mcp_config`), a real stdio self-test, and per-tier
  Pro gating + input rate/size safety.
- **Trust hardening** — a fixture + false-positive regression corpus, a
  ratcheting coverage floor, build-blocking ruff and strict-mypy gates, a
  dogfooding self-scan in CI, and generated, drift-checked docs.

### Added
- **60-second quickstart with a real, reproducible finding.** A bundled,
  intentionally-vulnerable demo project (`examples/vulnerable-demo/`, a Next.js
  `package.json` pinned to `next@15.2.2`) gives the quickstart a target that
  deterministically reports **CVE-2025-29927** (middleware authorization bypass,
  CVSS 9.1) and exits non-zero — so the README's *install → scan → finding in
  three commands* path (`pip install -e .` → `shellockolm scan
  examples/vulnerable-demo` → `shellockolm info CVE-2025-29927`) produces a real
  result, not a placeholder. The demo is not an agent artifact, so the agent-only
  self-scan CI gate still passes. An asciinema recording of the session
  (`docs/quickstart.cast`) is generated drift-proof by
  `scripts/generate_quickstart_cast.py` (with a `--check` CI gate), and
  `tests/test_quickstart.py` (14 tests) runs the documented commands through the
  real CLI to prove they work exactly as written.

### Changed
- **README + `docs/QUICKSTART.md` quickstart now uses the installed `shellockolm`
  console script** (not `python src/cli.py`) and shows the **real** scanner output.
  The old QUICKSTART "example output" was fabricated — it invented "3
  vulnerabilities" and mislabelled CVE-2025-29927 as *HIGH* when the tool reports
  it *CRITICAL (CVSS 9.1)*; it's replaced with the verified finding text.

### Fixed
- **Three latent `UnboundLocalError`/`NameError` crashes in the interactive CLI menu,
  surfaced by the new ruff lint gate.** In the large interactive-menu function, a
  module-level name was shadowed by a redundant *local* re-import/assignment further down
  the same scope, which makes Python treat the name as local throughout — so the earlier
  use raised `UnboundLocalError` whenever that menu path ran: `re` (a redundant local
  `import re`), `Panel` (a redundant local `from rich.panel import Panel`), and the
  `scanners` command (a local `scanners = get_all_scanners()` that shadowed the command
  function called earlier). The redundant locals were removed and the shadowing variable
  renamed; all three now resolve to their module-level definition. Also fixed a missing
  `Dict` import (`cli.py` annotated four functions with `Dict[...]` without importing it —
  a `NameError` under `typing.get_type_hints()`).
- **MCP resource reads no longer error over the real transport.** The server's
  `read_resource` callback was typed `uri: str` and called string-only methods
  (`uri.startswith("cve://")`, `uri.replace(...)`), but the MCP framework hands that
  callback a parsed pydantic **`AnyUrl`** when a client reads a resource over stdio — so
  every transport-level `cve://…` read failed with `'AnyUrl' object has no attribute
  'startswith'`. (The internal `get_cve_info` tool was unaffected because it calls the
  handler with a plain string.) The handler now coerces `uri` to `str` up front, so both
  callers work. Surfaced by the new MCP server self-test, which is the first thing to
  exercise the resource path through the genuine client⇆server transport.
- **Packaging: pure CLI-helper modules are now installed.** `diff_scan`, `baseline`, and `doctor`
  (added in earlier build-loop tasks) were imported by `cli` but missing from `[tool.setuptools]`
  `py-modules`, so a `pip install` would build a package whose `shellockolm` console script fails to
  import (`ModuleNotFoundError`). All three — plus the new `config_file` — are now listed, and added
  to the smoke-import test net. (In-tree test runs were unaffected because `conftest.py` puts `src/`
  on `sys.path`; the gap only bit an installed package.)
- **Windows path/encoding hardening — UTF-16/BOM artifacts no longer evade the agent
  scanner, and a benign BOM no longer false-positives.** Skills, MCP configs, and
  instruction files were read as UTF-8 with `errors="ignore"`, so a malicious artifact
  saved as **UTF-16** (routine from Windows Notepad's "Unicode" save or PowerShell
  `Out-File`/`>`) decoded to garbled, NUL-interleaved text that matched **no** rule —
  a complete detection bypass (confirmed: a UTF-16 instruction-override skill scored
  0 findings vs. 2 in UTF-8). Conversely a benign **UTF-8-BOM** file leaked a leading
  `U+FEFF` that the invisible-character rule (AGENT-PI-005) flagged as smuggling — a
  false positive. A new `_decode_bytes` now detects the byte-order mark (UTF-8/16/32,
  longest match first), strips it, and decodes with the right codec, with a NUL-density
  heuristic for BOM-less UTF-16; detections now fire identically across UTF-8/UTF-16
  LE+BE/UTF-32/BOM, and the BOM false positive is gone. Verified a **strict no-op on
  the real `~/.claude/skills` corpus** (187 findings, byte-identical; 0 read errors).
- **Unreadable artifacts are collected, not silently swallowed; the scan always
  continues.** A long path, locked file, reparse-point, or permission error during
  read is now recorded in `result.errors` (capped at 50) instead of being dropped, so
  a skipped file is visible rather than masquerading as clean. A missing scan path
  already reported an error; this extends the same contract per-file.
- **Directory reparse-point loop protection (symlinks *and* Windows junctions).** The
  walker now skips directory reparse points, which could otherwise loop back into the
  tree and report the same finding repeatedly (a self-referential junction inflated one
  skill's findings 5×) or escape the scan root. `Path.is_symlink()` alone misses
  Windows junctions, so the check also inspects the lstat reparse-point attribute. File
  symlinks are still followed. 28 new tests (`tests/test_windows_hardening.py`: per-BOM
  decode units, malicious detected in every encoding, benign zero-FP in every encoding,
  the AGENT-PI-005 BOM regression, read-error collection + cap, and a real
  junction/symlink loop that completes without crashing and counts the finding once);
  full suite **484 green** (was 456).

### Added
- **CI: mypy static type-check gate over the detection-critical core.** A dedicated,
  **build-blocking** `typecheck` job in `.github/workflows/ci.yml` runs `mypy` on every CI
  run, and the checked surface — the modular scanners (`src/scanners`, where the agent
  supply-chain rules live) and the server-authoritative licensing client
  (`src/licensing.py`) — is now **clean at strict settings** (`disallow_untyped_defs`,
  `warn_return_any`). Scope, import resolution, and strictness are the single source of
  truth in `[tool.mypy]` in `pyproject.toml` (`mypy_path = "src"` resolves the project's
  flat imports from the repo root; `follow_imports = "silent"` keeps the gate scoped to the
  target files), so CI and a local bare `mypy` enforce exactly the same gate. Like the
  ruff/coverage gates, the checked surface is a **ratchet** — widened over time, never
  narrowed. Getting to clean fixed **65 real type errors** with genuine fixes (no blanket
  `# type: ignore`): widening `create_finding(file_path=…)` to `str | Path` (it already
  `str()`-converts internally), annotating the per-scanner vulnerability tables
  (`PACKAGE_VULNERABILITIES`/`COMPROMISED_PACKAGES`/`VULNS`) so their entries stop typing as
  `object`, restoring the `quick_mode` parameter on three subclass `scan_directory`
  overrides that had dropped it (an LSP break), widening `ScanResult.stats` to the
  free-form `Dict[str, Any]` it actually is (it holds string metadata like `min_confidence`
  alongside int counts), making `parse_package_json` return `None` for a non-object
  top-level JSON, and rewriting an `object`-typed dedup that used `set.add()`'s return value
  in a comprehension. Behaviour is unchanged (full suite green before and after). A 7-test
  contract suite (`tests/test_type_check.py`, stdlib-only config/workflow parsing so it
  collects on every supported Python) asserts the wiring can't silently rot — mypy is a dev
  dependency, the core scope + `mypy_path` + strictness flags are present, the `typecheck`
  job is build-blocking — and, the real proof, that the committed core passes its own gate
  **and** that the gate has teeth (an int/str return mismatch fails under the repo config).
  Full suite **870 green** (was 863).
- **CI: self-scan (dogfooding) gate — shellockolm scans its own repo.** A dedicated,
  **build-blocking** `self-scan` job in `.github/workflows/ci.yml` runs the flagship agent
  supply-chain scanner against this repository on every CI run and fails the build on any
  **HIGH/CRITICAL** finding in a real agent artifact (`shellockolm scan -s agent --fail-on
  high .`), writing a JSON + SARIF report as an artifact. A committed `shellockolm.toml`
  excludes ONLY the deliberate detection corpus under `tests/fixtures/` (intentionally
  malicious/benign test data the detection suite asserts on, not real threats) — and only
  `ignore`, so a contributor's plain `shellockolm scan .` is never silently narrowed; the
  excluded count is always announced. The gate is currently green: a self-scan reports
  **zero** HIGH+ findings across the repo's real artifacts (42 agent items scanned, 36
  fixture findings correctly excluded), so the "we scan ourselves" claim is true before
  it's made. Agent-only keeps the gate deterministic and fully offline (bundled rules, no
  live CVE feed), so a red build always means a genuine regression. A 9-test suite
  (`tests/test_self_scan.py`) asserts the job wiring (agent scanner, build-blocking,
  `--fail-on high` ∈ the CLI's accepted choices), the config excludes the fixtures without
  pinning `scanner`/`fail_on`, and — the real proof — that the repo is clean at HIGH+ today
  **and** that the exclusion is load-bearing (without it the fixtures trip HIGH+ → exit 1,
  so the gate is never vacuously green). Full suite **856 green** (was 847).
- **CI: ruff lint gate + Python 3.10–3.14 test matrix.** The test job now runs across
  the full supported interpreter range (`3.10`, `3.11`, `3.12`, `3.13`, `3.14`) on the
  existing Windows + Linux matrix. A dedicated, **build-blocking** `lint` job runs
  `ruff check src`, replacing the prior non-blocking flake8 + black steps. The rule
  selection and the deferred-backlog `ignore` list live in exactly one place —
  `[tool.ruff.lint]` in `pyproject.toml` (shared by CI and a local `ruff check src`) — so
  the gate can't drift. It enforces the high-signal correctness families (`E`/`F`/`W`)
  clean; the genuine-bug codes (undefined names `F821`/`F823`, redefinitions, syntax
  errors) are never ignored, while a pre-existing cosmetic backlog (line length,
  whitespace, placeholder-less f-strings, unused imports, the CLI's intentional deferred
  imports) is explicitly deferred and ratcheted down over time — never up. `ruff` is now
  a `dev` dependency and the 3.13/3.14 classifiers were added. A 9-test contract suite
  (`tests/test_ci_workflow.py`) asserts the matrix coverage, the blocking ruff job, the
  single-source-of-truth config, that the enforced bug codes stay un-ignored, and (when
  ruff is installed) that the committed `src/` passes its own gate.
- **Coverage gate wired into CI.** A non-regression floor on line coverage over `src/`,
  enforced by a dedicated, build-blocking `coverage` job in `.github/workflows/ci.yml`
  (`pytest tests/ --cov=src --cov-report=term-missing --cov-report=xml`). The threshold
  lives in exactly one place — `[tool.coverage.report] fail_under` in `pyproject.toml`
  (read by both CI and local `pytest --cov=src` runs) — so it can't drift. Current
  measured coverage is **30.2%** across the suite; the floor starts at **28%** (a small
  cushion below the measured value to absorb platform/interpreter variance — a handful of
  tests are Windows-only and skip on the Linux coverage job) and is ratcheted **up** as
  real coverage grows, never down. The legacy CLI/GUI/scanner-shim modules dominate the
  denominator and are largely untested; the agent detection engine and the CLI-helper
  modules it ships already sit at 93–100%. `coverage` is intentionally kept **out** of the
  default pytest `addopts`, so the suite still runs with `pytest-cov` absent. A new
  `tests/test_coverage_gate.py` contract suite (7 tests, stdlib-only file parsing so it
  collects on every supported Python) asserts the wiring stays intact — the `fail_under`
  threshold is declared and not gutted below the established floor, CI runs `--cov=src` in
  a step that can actually fail the build (no `continue-on-error`), and `pytest-cov`
  genuinely enforces `fail_under` here (an isolated subprocess proves an unreachable floor
  exits non-zero). **Also added `pyyaml` to the `dev` extras**: the existing workflow
  contract tests (`test_github_action.py`, `test_pre_commit_hooks.py`) import `yaml`
  unguarded, but PyYAML was never declared, so a clean `pip install .[dev]` left the suite
  unable to collect — declaring it makes the gate (and the rest of the suite) reproducibly
  green in CI. (Full suite **838 green**, was 831.)
- **Committed detection-test fixture corpus** (`tests/fixtures/`). A tree of real-shaped,
  defanged agent artifacts — skills, MCP configs, n8n exports, `CLAUDE.md` instruction files,
  `.claude` slash commands, and Claude Code `settings.json` — each labelled `malicious` or
  `benign` in a machine-readable `manifest.json` (schema_version 1.0). A new
  `tests/test_fixture_corpus.py` consumes the manifest and enforces the corpus contract per
  fixture: malicious fixtures must trip every rule ID they declare (a *subset* check), benign
  fixtures must produce **zero** findings at **both** the free and Pro tier, and the manifest
  stays in sync with the on-disk tree (no undocumented files). The corpus doubles as a living,
  self-describing regression net — a calibration change that breaks a detection or introduces a
  false positive now fails a named test. `.gitignore`'s blanket `fixtures/` rule is narrowed so
  this corpus under `tests/` is tracked while ad-hoc local `fixtures/` dirs stay ignored. A
  README documents the layout and every fixture. (64 new tests; full suite 778 green, was 714.)
- **MCP rate/size safety — a hostile or accidental giant input can no longer hang an agent's
  tool call.** Two complementary caps, both surfacing **partial-scan warnings** instead of blocking:
  (1) `scan_text` (and every in-memory caller) now bounds its input at `MAX_TEXT_CHARS`
  (1,000,000 chars); a larger string is truncated to the cap — the head, where frontmatter and the
  opening injection prose live, is still scanned — and the cut is announced, never silent. (2)
  `scan_directory` gained an optional `time_budget` (seconds): the directory walk is now iterated
  **lazily** (the previous eager `list(...)` materialization was itself the hang on a huge tree) and
  the deadline is checked before each candidate file, so a pathological/looping tree stops at the
  budget with a partial result rather than blocking. The `scan_agent_artifacts` MCP tool applies a
  **120 s default** budget (override per-call; `0` = unbounded for a deliberate full local scan);
  the CLI default stays unbounded (`time_budget=None`), so existing behavior is unchanged. A new
  `ScanResult.warnings` channel (distinct from per-file read `errors`) carries the notices through to
  the structured payload (`summary.partial` / `summary.warnings`) and the human-readable tool output.
  28 new tests (`tests/test_mcp_rate_size_safety.py`: truncation + head-still-scanned, the
  zero-false-partial baseline on a normal input, lazy-walk timeout via a deterministic fake clock,
  `time_budget` boundary validation, and the `partial`/`warnings` contract end-to-end through both
  agent MCP tools).
- **Pro-gating regression suite for the MCP path — the open-core invariant is now CI-locked.**
  A new `tests/test_mcp_pro_gating.py` proves that Pro rules are gated identically through the MCP
  server as on the CLI: the agentic tools (`scan_agent_artifacts`, `scan_text`, `check_mcp_config`)
  construct `AgentSupplyChainScanner()` with **no** `pro=` argument, so the active license alone
  decides — and the headline guarantee, **the free tier still returns every free finding**, holds
  regardless. The 11 tests drive the real async `handle_call_tool` entry point (where the scanner is
  built internally, not handed an explicit tier) over a single artifact that trips exactly one FREE
  rule (a smuggled `AGENT-PI-007`) and one PRO rule (`AGENT-PRO-003` context exfiltration), and
  assert: free → only the free finding (Pro rule absent, `scan.pro=false`); Pro → free **plus** the
  Pro rule (`scan.pro=true`, finding `tier="pro"`); Pro gating is **strictly additive** (the free id
  set is a proper subset of the Pro set, the only delta being genuine pro-tier rules — Pro never
  drops or rewrites a free finding); the MCP handler's finding set is **byte-identical** to a
  directly license-pinned `AgentSupplyChainScanner(pro=…)` at both tiers; and no free-tier scan
  across any of the three tools ever leaks a `tier="pro"` finding. The license is forced offline by
  replacing `licensing.LicenseManager` with a fake (the scanner re-reads that module attribute on
  each construction), so the result never depends on the host's real license file, env var, or
  network. Full suite **695 green** (was 684).
- **MCP tool `check_mcp_config` — audit the agent's OWN installed MCP configs (the 12th tool).**
  Scans the well-known MCP-server config locations per OS — Claude Desktop
  (`%APPDATA%\Claude\…` / `~/Library/Application Support/Claude/…` / `~/.config/Claude/…`),
  Claude Code (`~/.claude.json`), Cursor (`~/.cursor/mcp.json`), Windsurf
  (`~/.codeium/windsurf/mcp_config.json`), VS Code (`…/Code/User/mcp.json`), plus this project's
  `.mcp.json` / `mcp.json` / `.cursor/mcp.json` / `.vscode/mcp.json` — for a poisoned server entry:
  code fetched from a raw-paste URL or public IP (AGENT-MCP-005), a broad host credential forwarded
  to an unrelated server (AGENT-MCP-004), a `curl|bash` launcher (AGENT-MCP-001), an unpinned remote
  package (AGENT-MCP-002), or a hardcoded secret. Reports which configs exist, which were scanned,
  and any structured findings + a stable `schema_version` 1.0 JSON document (the same per-finding
  shape as `scan_agent_artifacts`). Each existing file is routed through the agent scanner's
  structured MCP path regardless of its actual filename, so a config not literally named `mcp.json`
  (`~/.claude.json`, Windsurf's `mcp_config.json`) is still parsed for `mcpServers` entries. It is
  **read-only** (never modifies a config), bounds each read at 5 MB (a runaway `~/.claude.json` is
  marked `skipped`, never a silent gap), and any matched secret is redacted in the output. The
  candidate-location enumeration lives in a pure, exhaustively-tested `src/mcp_config_locations.py`
  (mirrors the `diff_scan`/`baseline`/`doctor`/`config_file` split — no filesystem access, fully
  parameterized by `system`/`home`/`env`/`project_root`). Pro rules are gated by the active license
  exactly as on the CLI. Args: `path` (project root, default cwd), `include_user`, `include_project`,
  `min_confidence`. Verified live against the real machine's configs (correctly surfaced a CRITICAL
  secret-in-URL and HIGH hardcoded credentials, both redacted). 26 new tests
  (`tests/test_mcp_check_config.py`: per-OS location enumeration incl. APPDATA fallback + de-dup, the
  disk-probing scan incl. absent/oversize/forced-mcp-path, the payload contract + CRITICAL→INFO
  ordering, the markdown/JSON formatter, tool registration, and every e2e error path) + the live
  stdio self-test now exercises it as the 12th tool. Full suite **684 green** (was 656).
- **MCP server self-test — the client⇆server stdio transport is now covered by CI.** A new
  `tests/test_mcp_server_selftest.py` launches `src/mcp_server.py` as a **subprocess** and drives it
  through the genuine MCP JSON-RPC **stdio** transport exactly as an AI client would (Claude Code /
  Desktop / Cursor / Windsurf): `initialize` → `list_tools` → `call_tool` for **all 11 tools** →
  `list_resources` / `read_resource`. This is the pytest-native promotion of the previously manual
  `tests/mcp_live_check.py` script, so the full handshake — not just the in-process handler functions —
  is exercised on every run. It is offline by construction: each scanning tool runs against a tiny
  **local** temp fixture (a vulnerable `package.json` and a malicious/benign `SKILL.md`), and `scan_live`
  is probed with a `127.0.0.1` loopback URL that the SSRF guard rejects *before* any socket opens. The
  server is spawned once (a module-scoped fixture captures every response); 18 granular tests assert
  per-tool behavior — CVE detection (`quick_scan`→CVE-2024-21508, `scan_directory`→CVE-2025-29927, both
  scanner-pinned for determinism), agent supply-chain detection + a zero-finding benign baseline,
  `explain_finding` resolving both a rule id and a CVE id, the SSRF block, and the exact 11-tool surface.
  Full suite **656 green** (was 638). _(This is also what surfaced the `read_resource` AnyUrl fix above.)_
- **MCP tool `scan_text` — vet a raw artifact string in-memory, no disk I/O.** The in-memory sibling
  of `scan_agent_artifacts`: pass the raw **text** of an artifact the agent is *about to install or
  paste* — a skill / `SKILL.md`, an `mcp.json` config, an instruction file
  (`CLAUDE.md`/`AGENTS.md`/`.cursorrules`), an n8n workflow export, a `settings.json` hooks block, or a
  slash command — and get back the same **structured findings** (rule id, severity, confidence, attack
  class, line, remediation) + stable `schema_version` 1.0 JSON document, *before the content ever
  touches disk*. The new `AgentSupplyChainScanner.scan_text()` routes the string to the right detection
  path; `artifact_type` selects it explicitly (`skill`/`instructions`/`command`/`mcp`/`n8n`/`settings`)
  while the default `auto` infers it from an optional `filename` hint, then from the content shape
  (valid JSON with `mcpServers` → mcp, with `nodes`+`connections` → n8n, otherwise prose → skill).
  Composite-severity boosting and the `min_confidence` filter run exactly as in `scan_directory`;
  rule-ID `.shellockolmignore` suppression is intentionally skipped (there is no on-disk ignore tree
  for a string). It reuses the flagship `build_agent_scan_payload` so `scan_text` and
  `scan_agent_artifacts` share one contract (plus an additive `scan.artifact_type` showing what `auto`
  resolved to); a missing/blank `text`, an unknown `artifact_type`, and an invalid `min_confidence` are
  clear errors, never a silently-wrong scan. Verified end-to-end over the real stdio transport
  (`tests/mcp_live_check.py` now also vets a smuggled skill string in-memory) and with 24 new tests
  (`tests/test_mcp_scan_text.py`: per-kind routing, `auto` classification by filename + content, bytes
  input, the no-disk-I/O guarantee, the `min_confidence` filter, the ValueError boundary, tool
  registration, and end-to-end handler runs for malicious skill/MCP text, a benign baseline, and every
  error path). Full suite **638 green** (was 614).
- **MCP tool `scan_agent_artifacts` — the flagship "agents scanning agents" feature.** The agent
  supply-chain scanner is now exposed directly through the MCP server as a dedicated tool, so an AI
  agent can vet a skill, MCP server, or repo mid-session — *before* installing or trusting it — and
  get back **structured findings**: each finding carries the `AGENT-*` rule id, severity, confidence,
  **attack class** (prompt-injection / mcp / n8n / hooks / secrets / …), **tier** (free/pro),
  `cvss_score`, the `file:line` locator, and remediation, plus a stable `schema_version` 1.0 JSON
  document (`build_agent_scan_payload`) that mirrors the CLI's `scan --json` shape. Covers every
  agent artifact class the CLI does — `SKILL.md` skills, `mcp.json` configs, n8n workflow exports,
  slash commands, `settings.json` hooks, and `CLAUDE.md`/`AGENTS.md`/`.cursorrules` instruction
  files — and accepts `recursive`, `max_depth`, `min_confidence` (`low|medium|high`), and
  `quick_mode` arguments. Pro rules are gated by the active license through the MCP path exactly as
  on the CLI (free tier still returns every free finding); invalid `min_confidence`/`max_depth` and a
  missing path are clear errors, never a silently-wrong scan; the embedded JSON is `ensure_ascii` so
  an invisible-Unicode injection payload stays pipe-safe. Verified end-to-end over the real stdio
  transport (`tests/mcp_live_check.py` now also exercises it) and with 16 new tests
  (`tests/test_mcp_agent_scan.py`: payload shape + CRITICAL→INFO ordering + zero-FP benign baseline +
  ASCII-safety, the markdown/JSON formatter, tool registration, and end-to-end handler runs for a
  malicious skill, a raw-URL MCP config, a single-file path, and every error path). Full suite
  **593 green** (was 577).
- **MCP tool `explain_finding` — the why/impact/remediation explainer over MCP.** The companion to
  `scan_agent_artifacts`: given a rule ID (`AGENT-PI-013`, `AGENT-MCP-004` — from an agent-artifact
  scan) **or** a tracked CVE ID (`CVE-2025-29927` — from a dependency/malware scan), it returns the
  full explainer — severity/tier/confidence/attack-class/CVSS, the description, a concrete **example
  attack**, and the remediation — plus a stable `schema_version` 1.0 JSON document
  (`build_explain_payload`). It is the MCP analog of the `shellockolm rules explain <id>` CLI command,
  and a single entry point for both finding families the scanner emits: agent rules resolve through
  the shared `agent_rule_explain` catalog (no drift between MCP and CLI), CVEs through the bundled
  vulnerability database. The ID is case-insensitive and whitespace-tolerant; a missing/blank id and
  an unknown id are clear errors (never a silently-empty explainer); the embedded JSON is
  `ensure_ascii` so unicode-heavy rule prose stays pipe-safe. Verified end-to-end over the real stdio
  transport (`tests/mcp_live_check.py` now resolves both a rule and a CVE) and with 21 new tests
  (`tests/test_mcp_explain_finding.py`: resolver shape for rules + CVEs, case-insensitivity,
  every-rule-resolves coverage, unknown/boundary → None, the markdown/JSON formatter, ASCII-safety,
  tool registration, and end-to-end handler runs incl. every error path).
- **Scan-volume stats in the footer — items scanned + scanners run, surfaced consistently.**
  The per-scanner artifact/unit counts (`skills_scanned`, `mcp_configs_scanned`, `packages_scanned`,
  `files_scanned`, …) and the scanner count were already tracked on each `ScanResult` but never
  surfaced together. The human `INVESTIGATION SUMMARY` footer now reports **Items scanned** and
  **Scanners run** alongside the existing duration, and the `--json` `summary` block gains matching
  `items_scanned` / `scanners_run` keys (additive — the documented `schema_version` 1.0 contract only
  ever grows). A single pure helper `aggregate_scan_stats()` is the source of truth for both paths: it
  sums every integer stat whose key ends in `_scanned`, so a new scanner that follows the naming
  convention is counted with no further changes (bools and the `min_confidence` string are excluded).
  10 new tests (`tests/test_scan_stats.py`: suffix summation, scanner count, duration rounding,
  non-count-stat exclusion, empty-results zero case, JSON propagation parity, e2e human-footer +
  `--json` over a real benign-skill fixture); full suite **577 green** (was 567).
- **Config file (`shellockolm.toml` / `[tool.shellockolm]`) — pin scan defaults.** A project
  can commit its scan settings so every contributor and CI runs the same scan without retyping
  flags. The CLI reads the **nearest** `shellockolm.toml` (top-level keys or a `[tool.shellockolm]`
  table) or `pyproject.toml` `[tool.shellockolm]` table at or above the scan path (walking up like
  `.gitignore`); a dedicated `shellockolm.toml` is preferred over a `pyproject.toml`, and a
  `pyproject.toml` without our table is left alone. Supported keys: `path`, `scanner`, `recursive`,
  `max_depth` (alias `depth`), `min_confidence`, `fail_on`, and `ignore` (a list of rule/CVE IDs
  and/or gitignore-style path globs). Config supplies a **default** only for a flag the user did not
  pass — **an explicit flag always wins** (detected via Click's parameter-source, compared by member
  name so Typer's bundled-Click copy doesn't break the check). `ignore` is applied as a pure,
  scanner-agnostic post-filter alongside `--diff`/`--baseline`; the hidden count is announced and
  surfaced as `summary.findings_config_ignored` in `--json`. `--config <path>` targets a specific
  file (missing/invalid → exit `2`) and `--no-config` disables discovery; a malformed config (bad
  value/type, invalid TOML) is a usage error (exit `2`), never a silently-wrong scan. Backed by a
  pure, testable `src/config_file.py` (mirrors `diff_scan.py` / `baseline.py` / `doctor.py`); 56 new
  tests (`tests/test_config_file.py`: discovery + precedence, table extraction, full validation of
  every key + every error path, ignore rule-ID/glob matching, anti-drift parity with the CLI's
  `_FAIL_ON_CHOICES`, and e2e subprocess proving config defaults apply, an explicit flag overrides,
  `--no-config` disables, an `ignore` entry hides a finding, a `pyproject` table is discovered, and
  missing/invalid configs exit 2); full suite **567 green** (was 508).
- **`shellockolm doctor` — environment self-check with actionable output.** A new
  command that verifies Shellockolm can scan on the current machine before you depend
  on it: the Python runtime meets the supported floor (`>=3.10`), the bundled CVE
  database and the agent supply-chain rule catalog import and are populated, the
  config (`~/.shellockolm`, where the Pro license lives) and session/log directories
  are writable, the optional `git` dependency (used by `scan --diff` and the
  pre-commit hook) is on `PATH`, and the active license tier resolves. Each check is
  `ok` / `warn` / `fail` / `info`; only a hard `fail` (old Python, a corrupt install)
  makes the command exit non-zero — a missing `git` or an unwritable log dir is a
  `warn` that still passes. Exit codes mirror the scan contract (**0** healthy /
  **1** one or more checks failed), and `--json` emits one stable `schema_version`
  1.0 document (pure stdout, no banner) for CI. Runs **fully offline** unless a
  license key is configured (the license probe only contacts the server when a key
  is present). Backed by a pure, testable `src/doctor.py` (mirrors `diff_scan.py` /
  `baseline.py`); 23 new tests (`tests/test_doctor.py`: per-check units incl. the
  Python-floor boundary, writable-probe success/failure + cleanup, git/license
  probes, `DoctorReport` health/counts/serialization, the CLI exit-code mapping, and
  e2e subprocess proving pure-JSON stdout + a healthy machine exits 0); full suite
  **507 green** (was 484).
- **Benchmark script + perf guard for the agent scanner.** A new
  `scripts/benchmark_scan.py` generates a deterministic, self-contained corpus of
  agent artifacts (skills, MCP configs, n8n exports, instruction files, `.claude/`
  settings + slash-commands; ≈5 % carrying a known malicious shape), scans it, and
  reports wall-clock + throughput (and gates on a `--budget`). The corpus
  generator is shared with the new `tests/test_perf_guard.py` so the benchmark and
  the CI regression tripwire agree. Real measured numbers are documented in
  [docs/PERFORMANCE.md](docs/PERFORMANCE.md): ~960–1,080 artifacts/s (~1 ms/artifact)
  on the synthetic tree, and the real `~/.claude/skills` corpus (1,335 skills).

### Changed
- **Faster non-ASCII stealth scans (regex-pass optimization).** The per-character
  Unicode-Tags-smuggling, Trojan-Source bidi, and confusable/homoglyph checks used
  to iterate every character of every artifact (and, for confusables, regex over
  every word). Every code point they look for lives above U+007F, so a single
  C-level character-class search (`_STEALTH_CHARS_RE`, built from the same
  constants the checks consume so it cannot drift) now lets a pure-ASCII artifact
  skip all three Python loops. **1,333 of 1,335 real skills are pure ASCII**, so
  the fast path applies almost everywhere: **−14.2 %** wall-clock on the real
  corpus (18.65 s → 16.01 s) and −10.3 % on a 2,000-artifact synthetic tree, with
  findings **byte-identical** both ways (a strict superset guard — any artifact
  with a real stealth char still runs the full slow-path scan). 15 new perf-guard
  tests assert the guard never drifts, fast-paths benign ASCII *and* benign
  non-ASCII (emoji/curly-quotes/CJK), and still detects every smuggling attack;
  full suite 456 green (was 441).

- **Baseline support (`--baseline` / `--write-baseline`) — fail CI only on NEW
  findings.** Adopt the scanner on a codebase that already has findings without
  drowning CI in pre-existing noise. `scan --write-baseline baseline.json`
  snapshots every current finding into a file (a report-only run that never fails
  the build) so you can accept the existing findings and commit it;
  `scan --baseline baseline.json` then drops every finding already in the baseline
  and reports only NEW ones, which gate the exit code per `--fail-on`. A
  finding's identity is a SHA-256 over `id | repo-relative path | package |
  version`, deliberately **excluding the line number and severity** — so editing a
  file (shifting a finding's line) or a later composite-severity boost never makes
  a known finding look new and spuriously fail the build. The hidden count is
  announced (never silent) and surfaced as `summary.findings_baselined` in
  `--json`; a missing/corrupt baseline is a usage error (exit `2`, never a silent
  pass); `--baseline` and `--write-baseline` together is a usage error. New
  self-contained `src/baseline.py` module (mirrors `diff_scan.py`: pure, tested
  identity + filtering split from the file I/O). The baseline file is a documented
  `schema_version` 1.0 JSON document (deduped + sorted, so it diffs cleanly across
  regenerations). 25 new tests (`tests/test_baseline.py`: fingerprint stability
  across line-shift + severity-change, per-axis distinctness, build/load/filter
  round-trip, every load error path, and e2e subprocess runs proving
  write→exit 0, known-hidden→exit 0, new-finding→exit 1 with only the new file
  reported, missing→exit 2, and the conflict→exit 2); full suite 441 green
  (was 416).
- **`rules explain <RULE-ID>` — a full per-rule explainer with an example
  attack.** The deep-dive companion to `rules list`: `shellockolm rules explain
  AGENT-PI-013` prints one rule's severity, tier, confidence, attack class and
  CVSS, then the full description, a concrete **example attack**, and the
  remediation. The rule ID is case-insensitive; an unknown ID is a usage error
  (exit `2`, message to stderr so `--json` stdout stays empty); `--json` emits
  one stable document (`schema_version` 1.0, `rule` object) for docs/CI. Backing
  it, a canonical per-rule example-attack catalog (`_RULE_ATTACK_EXAMPLES` +
  `agent_rule_example()` / `agent_rule_explain()` in
  `scanners/agent_supply_chain.py`) carries one short, illustrative example for
  **every** rule the scanner can emit — completeness is test-enforced so it can't
  drift behind a newly-added rule, and every embedded credential is an obvious
  non-live placeholder. The human render escapes authored prose, so an example
  containing markdown-link brackets (`[docs.github.com](…)`) can't be mis-parsed
  as console markup. 11 new tests (example-catalog completeness + case-insensitive
  /unknown-safe lookup, explainer-matches-catalog + every-rule coverage, and e2e
  subprocess runs for the human render, `--json` document, case-insensitivity,
  the exit-2 unknown-rule path, and markup-safety); full suite 416 green (was 405).
- **`rules list` — the agent rule catalog as a command (and docs).** A new
  `shellockolm rules list` prints every agent supply-chain detection rule — ID,
  severity, **tier** (free / Pro), confidence, attack class, and a one-line
  description — so you can see exactly what the agent scanner looks for without
  reading source. Filters: `--tier free|pro`, `--severity critical|…|info`;
  `--json` emits one stable JSON document (`schema_version` 1.0) that feeds the
  forthcoming `RULES.md` and CI tooling — pure JSON on stdout (usage errors to
  stderr, exit `2` on an unknown filter value). Backing it, every detection rule
  is now exposed through a single canonical catalog (`agent_rule_catalog()` /
  `ALL_AGENT_RULES` in `scanners/agent_supply_chain.py`): the 11 structural /
  stealth-channel rules that were inline `AgentRule` literals (invisible chars,
  Unicode-Tags, bidi, homoglyph, link/href mismatch, HTML comment, frontmatter,
  memory poisoning, cross-file, tool-output spoof, base64 blob) were promoted to
  named module constants and are now enumerable without running a scan — a
  behaviour-preserving refactor (the full pre-existing agent suite stays green).
  22 new tests (`tests/test_rules_catalog.py`: catalog completeness incl. all
  structural rules, tier/attack-class classification, de-dup + ordering, valid
  enums, a behaviour-preservation check that a promoted rule still emits its
  catalog metadata, and e2e subprocess runs for `rules list` JSON/filters/exit-2
  /human table); full suite 405 green (was 383).
- **`scan --table` — polished findings table grouped by file.** A new opt-in
  human-output mode: one compact Rich table per artifact (rows colored by
  severity, with rule ID, line, CVSS and detection confidence), closed by a
  severity-tally summary footer. It **degrades gracefully when stdout is not a
  TTY** — a piped/redirected stream gets an ASCII box (no Unicode frame glyphs),
  no ANSI color, and the bare severity word instead of an emoji — so it stays
  clean in a log capture. Grouping reuses `diff_scan.bare_path`, so a file's
  findings collapse together across the `:<line>` / `» server:<name>` location
  suffixes. `--json` (CI mode) suppresses the table; stdout stays a single JSON
  document. Rendering helpers (`group_findings_by_file`, `build_findings_table`,
  `build_severity_footer`, `render_findings_table`) are pure/testable, and finding
  text is wrapped in `rich.text.Text` so a bracket in a path or title can't be
  mis-parsed as console markup. 19 new tests (`tests/test_cli_table_output.py`:
  grouping/ordering units, TTY-vs-non-TTY degradation, tallies, markup-safety, and
  e2e subprocess runs proving the table renders, the piped stream is ASCII, and
  `--json` still emits only JSON); full suite 383 green (was 364).
- **GitHub Action (`action.yml`) — checkout → scan → SARIF upload.** A composite
  action consumers add in one workflow step. It runs the scan in stable `--json`
  mode, writes a JSON report and a SARIF 2.1.0 document, and uploads the SARIF to
  GitHub code scanning (Security tab) via `github/codeql-action/upload-sarif`.
  Inputs: `path`, `scanner` (empty = all), `fail-on`, `min-confidence`, `output`,
  `sarif`, `upload-sarif`, `quick`, `python-version`; outputs: `report`, `sarif`,
  `findings`, `exit-code`. The build fails per the documented exit-code contract
  (`--fail-on`, wired through to the step's exit). A 20-test contract suite
  (`tests/test_github_action.py`) validates the action shape, that the scan step
  wires `--json`/`--fail-on`/`--sarif`/`-o`, that the SARIF upload step exists and
  is gated, and that the `scripts/action_summary.py` helper prints only the finding
  count to stdout (degrading to `0` on a missing report).

### Fixed
- **GitHub Action no longer passes the invalid `-s all`.** The previous stub
  `action.yml` defaulted `scanner` to `all` and passed `-s all`, which `scan`
  rejects (exit `2`) — so it failed every run. The scanner default is now empty
  (= run every scanner) and `-s` is only passed when a scanner is named; the
  `fail-on` input is now actually wired to the exit code (it was a no-op), and the
  `findings` output is populated.

- **Pre-commit hook integration (`.pre-commit-hooks.yaml`).** Ships two
  [pre-commit](https://pre-commit.com) hooks so any repo can vet every commit in
  one `.pre-commit-config.yaml` block: `shellockolm-agent` (AI agent
  supply-chain scan, the recommended default — triggers only when a `SKILL.md` /
  `mcp.json` / `.claude/` / `CLAUDE.md` / `AGENTS.md` artifact is staged) and
  `shellockolm` (full deps + secrets + malware + agent scan). Both scan only the
  **staged** set via `scan --diff` (so they flag what the commit introduces and
  exit `0` instantly when nothing relevant is staged), block the commit on HIGH+
  by default, and keep `--diff` in `entry` so it survives an `args:` gate
  override. `pass_filenames: false` (the `scan` CLI takes one PATH, not a
  filename list). Documented in the README; an 11-test contract suite
  (`tests/test_pre_commit_hooks.py`) validates the YAML shape, that the `entry`
  console script is declared in `pyproject` `[project.scripts]`, that the default
  `--fail-on` gate is a value the live CLI accepts, and that the agent hook's
  `files` trigger regex matches real agent artifacts while ignoring ordinary
  source files.
- **`scan --diff` / `--diff-ref` — git-diff scoping for pre-commit & CI.** Reports
  findings only for files **changed in git**: `--diff` scans the staged set
  (`git diff --cached`, the pre-commit content) and `--diff-ref <ref>` scans
  everything that differs from a ref (e.g. `origin/main`). Findings on unchanged
  files are dropped (count announced, never silent; surfaced as
  `summary.findings_diff_filtered` in `--json`); an empty changed set exits `0`
  immediately. Path-matching is exact and case-insensitive on Windows — it strips a
  finding's `:<line>` / ` » server:<name>` suffix and resolves relative paths, never
  a fuzzy basename match. A path outside a git work tree (or an unknown ref) is a
  usage error (exit `2`). Composes with `--json`/`--sarif`/`--fail-on`/
  `--min-confidence`. New `src/diff_scan.py` with a 28-test suite
  (`tests/test_diff_scan.py`): pure matching units, real-temp-repo integration, and
  e2e proving an unchanged malicious skill is hidden while a staged one is reported.
- **`scan` exit-code contract + `--fail-on` gate.** Exit codes are now documented
  and stable — `0` clean, `1` findings, `2` usage/operational error — and
  `--fail-on critical|high|medium|low|info` gates the build on severity (exit `1`
  only when a finding at or above that level is present), with `--fail-on none` for
  report-only runs. A finding below the gate is announced rather than silently
  passed. Usage errors (bad path, unknown scanner, unknown flag value) now exit `2`
  instead of `1`, so a flag typo can't masquerade as a clean run. Documented in the
  README with an 18-test suite (`tests/test_cli_exit_codes.py`).

## [3.0.0] - 2026-06-10

A correctness, security, and packaging hardening pass. The headline fix:
`pip install .` now actually works — previously it produced broken console
scripts and silently omitted the `scanners` subpackage.

### Added
- **Real test suite** under `tests/` (pytest): vulnerability database, modular
  scanners, secrets scanner, ignore-file matching, and a smoke test that imports
  every `src/` module to catch import-time errors.
- **`shellockolm-mcp` console script** wired to `mcp_server:run` for launching
  the MCP server directly.
- **Root `CHANGELOG.md`** (this file) in Keep a Changelog format.
- **Modular scanner architecture** (`src/scanners/`) covering React/RSC,
  Next.js, npm packages, Node.js, n8n, supply-chain, and Clawdbot/Moltbot.

### Fixed
- **Packaging — `pip install .` is no longer broken.** Replaced the bogus
  `packages = ["shellockolm"]` / `package-dir = {"shellockolm" = "src"}` mapping
  (which produced unimportable console scripts and dropped the `scanners`
  subpackage) with a flat install from `src/`: `package-dir = {"" = "src"}`,
  an explicit `py-modules` list of all 29 top-level modules, and
  `packages.find` to pick up the `scanners` package. Flat imports
  (`import cli`, `from scanners import ...`, `from vulnerability_database import ...`)
  and all entry points now resolve from the installed distribution.
- **`requirements.txt` now matches reality.** Added the missing-but-required
  `requests` and `prompt_toolkit`, removed the dead `semver` dependency (never
  imported), and moved `pytest`/`pytest-asyncio` out of runtime deps into the
  packaging `dev` extra. Installer shell scripts that verify `import requests`
  after `pip install -r requirements.txt` now succeed.
- **Single source of truth for packaging.** Deleted the conflicting `setup.py`
  (different package name, phantom modules, pytest shipped as a runtime dep,
  a missing entry point); `pyproject.toml` is now authoritative.
- **Clawdbot/Moltbot CVEs are reachable** through `get_all_vulnerabilities()`
  and the lookup API.
- **Secrets scanner false positive:** a bare `0x` + 64-hex string (EVM
  transaction hash / keccak digest) is no longer misreported as a CRITICAL
  Ethereum private key; a private-key context keyword is now required.
- **`gui.py` import crash** from a missing `io` import.
- **`.shellockolmignore` glob matching** for patterns like `*.min.js` and
  `*.log`.

### Changed
- **CI is real now** (`.github/workflows/ci.yml`): runs `pip install .`,
  asserts the `shellockolm` console script works, and runs `pytest` as a
  blocking step. Smoke import/scan steps no longer swallow failures. Matrix
  trimmed to Ubuntu + Windows on Python 3.10/3.12.
- **Coverage** is no longer forced in the default pytest `addopts` (so the suite
  runs without `pytest-cov`); run `pytest --cov=src` explicitly for coverage.
- **Package data** no longer ships internal docs (`ENHANCEMENT_PLAN.md`);
  restricted to `*.txt` data files.

### Security
- **CVE-monitor workflow** (`.github/workflows/cve-monitor.yml`) declares a
  least-privilege `permissions:` block (`issues: write`, `contents: read`).
- Removed the dependency on the previously-compromised `tj-actions` org for
  Bandit; the security scan now runs `bandit` from pip directly.

---

For the 2.0.0 (2025-12-08), 1.1.0, and earlier releases, see
[docs/CHANGELOG.md](docs/CHANGELOG.md).
