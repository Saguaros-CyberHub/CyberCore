/**
 * HMAC-signed URL helpers for /vuln-assets/ short-lived downloads.
 *
 * Requires env var VULN_ASSETS_SECRET (any long random string — generate with
 * `openssl rand -hex 32`). If unset, falls back to a dev-only static value
 * and logs a warning so prod mistakes are loud.
 */

const crypto = require('crypto');

const DEFAULT_TTL_SECONDS = 15 * 60;   // 15 min — enough headroom for slow pulls
const SIG_ENCODING = 'hex';

function getSecret() {
  const s = process.env.VULN_ASSETS_SECRET;
  if (!s || s.length < 16) {
    if (process.env.NODE_ENV === 'production') {
      throw new Error('[signed-url] VULN_ASSETS_SECRET is missing or too short — refusing to sign URLs with a predictable key in production. Generate one with `openssl rand -hex 32`.');
    }
    if (!global.__vuln_assets_secret_warned__) {
      console.warn('[signed-url] VULN_ASSETS_SECRET is missing or too short. Using insecure fallback — set it in .env for production.');
      global.__vuln_assets_secret_warned__ = true;
    }
    return 'DEV-ONLY-INSECURE-SECRET-SET-VULN_ASSETS_SECRET-IN-ENV';
  }
  return s;
}

function sign(filename, exp) {
  return crypto
    .createHmac('sha256', getSecret())
    .update(`${filename}|${exp}`)
    .digest(SIG_ENCODING);
}

/**
 * Build a `?token=…&exp=…` query string for a given filename, valid for ttlSeconds.
 * Returns just the query string (no leading `?`), ready to append.
 */
function buildSignedQuery(filename, ttlSeconds = DEFAULT_TTL_SECONDS) {
  const exp = Math.floor(Date.now() / 1000) + ttlSeconds;
  const token = sign(filename, exp);
  return `exp=${exp}&token=${token}`;
}

/**
 * Build a full download URL including the signed query.
 */
function buildSignedUrl(baseUrl, filename, ttlSeconds = DEFAULT_TTL_SECONDS) {
  const base = baseUrl.replace(/\/+$/, '');
  return `${base}/vuln-assets/${encodeURIComponent(filename)}?${buildSignedQuery(filename, ttlSeconds)}`;
}

/**
 * Verify a signed URL request. Returns { ok, reason }.
 *  - filename: the filename from the URL path (decoded, no leading slash)
 *  - expRaw:   req.query.exp
 *  - tokenRaw: req.query.token
 */
function verifySignedUrl(filename, expRaw, tokenRaw) {
  if (!expRaw || !tokenRaw)  return { ok: false, reason: 'missing token' };
  const exp = Number(expRaw);
  if (!Number.isFinite(exp)) return { ok: false, reason: 'bad exp' };
  if (exp < Math.floor(Date.now() / 1000)) return { ok: false, reason: 'expired' };

  const expected = sign(filename, exp);
  // Constant-time compare — avoid timing-leak side channel on the token.
  const a = Buffer.from(expected, SIG_ENCODING);
  const b = Buffer.from(String(tokenRaw), SIG_ENCODING);
  if (a.length !== b.length) return { ok: false, reason: 'bad token' };
  if (!crypto.timingSafeEqual(a, b)) return { ok: false, reason: 'bad token' };

  return { ok: true };
}

module.exports = { buildSignedQuery, buildSignedUrl, verifySignedUrl };
