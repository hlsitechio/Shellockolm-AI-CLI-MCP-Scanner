# Shellockolm License Server

The authoritative validation API for **Shellockolm Pro** — the non-bypassable side of
the open-core paywall. The OSS scanner stays free and fully downloadable; this Cloudflare
Worker is what makes Pro real: it validates Pro license keys and (once wired) issues them
on Stripe checkout.

The client is [`src/licensing.py`](../src/licensing.py) (`LicenseManager`), which POSTs
`{key}` to `/validate` when `SHELLOCKOLM_LICENSE_API` is set.

## Endpoints
- `POST /validate` → `{key}` → `{valid, tier, email, source}` — KV-authoritative with an
  offline HMAC fallback (so manually-issued `SHLK-` keys validate before the webhook flow).
- `POST /stripe/webhook` → on `checkout.session.completed`, issue + store a key, email it.
  (Handler is stubbed until `STRIPE_WEBHOOK_SECRET` is set — see worker.js.)
- `GET /` → health check.

## Deploy (supervised — needs secrets, do not automate)
```bash
cd license-server
npm i -g wrangler          # or: npx wrangler
wrangler kv namespace create LICENSES   # put the id in wrangler.toml
wrangler secret put LICENSE_SECRET       # MUST match src/licensing.py _OFFLINE_SECRET
wrangler secret put STRIPE_SECRET        # optional
wrangler secret put STRIPE_WEBHOOK_SECRET
wrangler deploy
```
Then point the client at it:
```bash
export SHELLOCKOLM_LICENSE_API="https://shellockolm-license.<your-subdomain>.workers.dev/validate"
```
And add the same URL to the Stripe webhook (`checkout.session.completed`).

## Manual fulfillment (today, before the webhook is wired)
A Pro subscriber can be served immediately:
```python
from licensing import issue_key, Tier
print(issue_key(Tier.PRO, "customer-nonce"))   # email this SHLK-PRO-... key to them
```
The scanner validates it offline and unlocks the Pro rule pack.

## Test
`node ../_license_server_test.mjs` (or see the committed test) — covers offline-key
validation, bad keys, KV records, and revocation/expiry.
