"""
Shellockolm licensing — open-core.

The scanner is free and MIT-licensed; the repository stays fully downloadable and
the free feature set NEVER requires a key. A license only UNLOCKS extra Pro features
(advanced rule packs, premium reports, continuous monitoring). Nothing free is
ever taken away.

License resolution order:
  1. env  SHELLOCKOLM_LICENSE          (the key string)
  2. file ~/.shellockolm/license.json  ({"key": "..."} )

Validation is **server-authoritative only**. A key is POSTed to the licensing
endpoint (Supabase Edge Function), which is the sole source of truth — revocation,
expiry, and the customer record all live server-side, in a private table the open
repo cannot read. There is deliberately NO offline secret or client-side key
checker in this module: shipping one in a public repo would let anyone forge keys.

Behaviour:
  - No key  -> FREE, and ZERO network calls (the tool stays 100% offline).
  - Key + server says valid   -> PRO/TEAM.
  - Key + server says invalid -> FREE.
  - Key + server unreachable  -> FREE for this run (fail-closed for Pro only; every
    free feature still works fully offline). Pro re-activates as soon as the
    validator is reachable again.

Fulfilment: add a row to the `licenses` table on the licensing project (manually
today, via the Stripe webhook once that ships). This module is stdlib-only.
"""

import json
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Optional

# Authoritative validation endpoint (public URL; only called when a key is present,
# so free users make zero network calls). Override with SHELLOCKOLM_LICENSE_API.
DEFAULT_LICENSE_API = "https://rqwwmucfqmvqfjhxbzrt.supabase.co/functions/v1/validate-license"


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
    source: str = "none"  # none | remote | invalid | unreachable


class LicenseManager:
    """Resolves the active license against the authoritative server."""

    def __init__(self, key: Optional[str] = None, api_url: Optional[str] = None):
        self.api_url = api_url or os.environ.get("SHELLOCKOLM_LICENSE_API") or DEFAULT_LICENSE_API
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
            return License()  # FREE — no key, no network call

        verdict = self._verify_remote(key)
        if verdict is not None:
            return verdict
        # Validator unreachable: fail closed for Pro (free features unaffected).
        return License(key=key, valid=False, source="unreachable")

    def _verify_remote(self, key: str) -> Optional[License]:
        """Returns a License on a definite verdict, or None if the server is
        unreachable (network error / timeout)."""
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
        except Exception:
            return None  # unreachable → caller fails closed for Pro

        if data.get("valid"):
            try:
                tier = Tier(str(data.get("tier", "pro")).lower())
            except ValueError:
                tier = Tier.PRO
            return License(tier=tier, key=key, email=data.get("email"), valid=True, source="remote")
        return License(key=key, valid=False, source="invalid")

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
        if self._license.source == "unreachable":
            return "Shellockolm FREE — license server unreachable; Pro re-activates when online"
        return "Shellockolm FREE — core scanning (upgrade for Pro rule packs & reports)"
