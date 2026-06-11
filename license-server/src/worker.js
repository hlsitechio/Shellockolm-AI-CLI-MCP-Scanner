// Shellockolm license validation Worker (Cloudflare)
//
// The authoritative, non-bypassable side of the open-core paywall. The OSS repo
// stays free and fully downloadable; this endpoint is what makes Pro real:
//   - POST /validate  {key}  -> {valid, tier, email}   (KV-backed, offline fallback)
//   - POST /stripe/webhook   -> issues + stores a Pro key on checkout.completed
//   - GET  /                 -> health check
//
// The client is src/licensing.py (LicenseManager), which POSTs {key} to /validate
// when SHELLOCKOLM_LICENSE_API is set. KV is authoritative (revocation/expiry/email);
// the offline HMAC fallback also accepts manually-issued SHLK- keys so first Pro
// customers can be served before the Stripe webhook flow is wired.

const PREFIX = "SHLK";
const enc = new TextEncoder();

async function hmac10(secret, body) {
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(body));
  const hex = [...new Uint8Array(sig)].map((b) => b.toString(16).padStart(2, "0")).join("");
  return hex.slice(0, 10);
}

function timingSafeEq(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let r = 0;
  for (let i = 0; i < a.length; i++) r |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return r === 0;
}

// Issue an offline key. Must use the SAME secret as src/licensing.py (_OFFLINE_SECRET)
// for keys to be cross-compatible between the Python issuer and this validator.
export async function genKey(secret, tier, nonce) {
  const body = `${PREFIX}-${tier.toUpperCase()}-${nonce}`;
  return `${body}-${await hmac10(secret, body)}`;
}

// Validate a license key. `store` is a KV-like object with async get(key, "json").
export async function validateKey(key, { secret, store } = {}) {
  if (!key || typeof key !== "string") return { valid: false };

  // 1) Authoritative KV record (revocation, expiry, email, seat) — set by the webhook.
  if (store) {
    let rec = null;
    try { rec = await store.get(key, "json"); } catch { rec = null; }
    if (rec) {
      if (rec.revoked) return { valid: false, reason: "revoked" };
      if (rec.expires && Date.now() > rec.expires) return { valid: false, reason: "expired" };
      return { valid: true, tier: rec.tier || "pro", email: rec.email || null, source: "kv" };
    }
  }

  // 2) Offline HMAC fallback — accepts manually-issued SHLK-<TIER>-<nonce>-<check> keys.
  const parts = key.trim().split("-");
  if (parts.length === 4 && parts[0] === PREFIX && secret) {
    const [p, t, n, chk] = parts;
    const expect = await hmac10(secret, `${p}-${t}-${n}`);
    if (timingSafeEq(chk, expect)) return { valid: true, tier: t.toLowerCase(), source: "offline" };
  }

  return { valid: false };
}

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "POST, GET, OPTIONS",
  "access-control-allow-headers": "content-type, stripe-signature",
};
const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json", ...CORS } });

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { headers: CORS });
    if (url.pathname === "/") return json({ ok: true, service: "shellockolm-license" });

    if (url.pathname === "/validate" && request.method === "POST") {
      const body = await request.json().catch(() => ({}));
      const res = await validateKey(body.key, { secret: env.LICENSE_SECRET, store: env.LICENSES });
      return json(res);
    }

    if (url.pathname === "/stripe/webhook" && request.method === "POST") {
      // TODO (supervised deploy step): verify the Stripe-Signature header with
      // env.STRIPE_WEBHOOK_SECRET, then on `checkout.session.completed` generate a key
      // (genKey(env.LICENSE_SECRET, "pro", crypto.randomUUID())), store it in KV
      // (env.LICENSES.put(key, JSON.stringify({tier:"pro", email, created:Date.now()}))),
      // and email it to the customer. Stubbed until secrets are configured.
      return json({ received: true, note: "webhook handler stubbed pending STRIPE_WEBHOOK_SECRET" });
    }

    return json({ error: "not_found" }, 404);
  },
};
