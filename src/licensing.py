"""
Shellockolm licensing — open-core.

The scanner is free and MIT-licensed; the repository stays fully downloadable and
the free feature set NEVER requires a key. A license only UNLOCKS extra Pro
features (advanced rule packs, premium report formats, continuous monitoring).
Nothing that is free today is taken away.

License resolution order:
  1. env  SHELLOCKOLM_LICENSE          (the key string)
  2. file ~/.shellockolm/license.json  ({"key": "..."} )

Validation:
  - Offline (default): keys are SHLK-<TIER>-<NONCE>-<CHECK> tokens, verified with a
    bundled keyed checksum. IMPORTANT: because that check ships in an open-source
    repo, it is *tamper-evident*, not forgery-proof. It exists for convenience and
    typo-protection, not as the paywall.
  - Online (authoritative): if SHELLOCKOLM_LICENSE_API is set, the key is POSTed
    there for the real verdict — revocation, expiry, and seat limits live server
    side, and that same endpoint is where premium *content* (Pro rule packs, CVE
    intel) is delivered. That is the durable enforcement path: it cannot be
    reconstructed by reading the open repo.

This module is intentionally dependency-free (stdlib only).
"""

import hashlib
import hmac
import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

# Tamper-evident (NOT forgery-proof) offline check secret. Real enforcement is remote.
_OFFLINE_SECRET = b"shellockolm-offline-keycheck-v1"
_PREFIX = "SHLK"


class Tier(str, Enum):
    FREE = "free"
    PRO = "pro"
    TEAM = "team"


@dataclass
class License:
    tier: Tier = Tier.FREE
    key: Optional[str] = None
    email: Optional[str] = None
    valid: bool = False
    source: str = "none"  # none | offline | remote | invalid


def _checksum(body: str) -> str:
    return hmac.new(_OFFLINE_SECRET, body.encode(), hashlib.sha256).hexdigest()[:10]


def issue_key(tier: Tier, nonce: str) -> str:
    """Issue an offline key. (The authoritative issuer is the licensing server;
    this helper exists for tests and local Pro keys.)"""
    body = f"{_PREFIX}-{tier.value.upper()}-{nonce}"
    return f"{body}-{_checksum(body)}"


def _parse_offline(key: str) -> Optional[License]:
    parts = key.strip().split("-")
    if len(parts) != 4 or parts[0] != _PREFIX:
        return None
    prefix, tier_s, nonce, check = parts
    body = f"{prefix}-{tier_s}-{nonce}"
    if not hmac.compare_digest(check, _checksum(body)):
        return None
    try:
        tier = Tier(tier_s.lower())
    except ValueError:
        return None
    return License(tier=tier, key=key, valid=True, source="offline")


class LicenseManager:
    """Resolves the active license and answers tier/feature questions."""

    def __init__(self, key: Optional[str] = None, api_url: Optional[str] = None):
        self.api_url = api_url or os.environ.get("SHELLOCKOLM_LICENSE_API")
        self._license = self._resolve(key)

    def _resolve(self, key: Optional[str]) -> License:
        key = key or os.environ.get("SHELLOCKOLM_LICENSE")
        if not key:
            path = Path.home() / ".shellockolm" / "license.json"
            if path.exists():
                try:
                    key = json.loads(path.read_text(encoding="utf-8")).get("key")
                except (OSError, ValueError):
                    key = None
        if not key:
            return License()

        # Authoritative online check first (if configured); fall back to offline on
        # network failure so a transient outage doesn't disable a paid user.
        if self.api_url:
            remote = self._verify_remote(key)
            if remote is not None:
                return remote

        return _parse_offline(key) or License(key=key, valid=False, source="invalid")

    def _verify_remote(self, key: str) -> Optional[License]:
        try:
            import urllib.request
            req = urllib.request.Request(
                self.api_url,
                data=json.dumps({"key": key}).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "shellockolm"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                data = json.loads(resp.read().decode())
            if data.get("valid"):
                tier = Tier(str(data.get("tier", "pro")).lower())
                return License(tier=tier, key=key, email=data.get("email"),
                               valid=True, source="remote")
            return License(key=key, valid=False, source="remote")
        except Exception:
            return None  # network/endpoint failure → caller falls back to offline

    @property
    def license(self) -> License:
        return self._license

    def tier(self) -> Tier:
        return self._license.tier if self._license.valid else Tier.FREE

    def is_pro(self) -> bool:
        return self._license.valid and self._license.tier in (Tier.PRO, Tier.TEAM)

    def status_line(self) -> str:
        if self.is_pro():
            who = f" ({self._license.email})" if self._license.email else ""
            return f"Shellockolm {self.tier().value.upper()}{who} — Pro features unlocked"
        return "Shellockolm FREE — core scanning (upgrade for Pro rule packs & reports)"
