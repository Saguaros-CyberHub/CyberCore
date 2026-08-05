/**
 * ============================================================================
 * GUACAMOLE API HELPER
 * Shared utility for communicating with the Apache Guacamole API
 * ============================================================================
 */

const { randomBytes } = require('crypto');

const GUAC_URL = process.env.GUAC_API_URL || 'http://100.100.70.10:8080/guacamole';
const GUAC_DS = process.env.GUAC_DATASOURCE || 'postgresql';

// Cache the Guac auth token (they last ~60 min)
let guacTokenCache = { token: null, expires: 0 };

/**
 * Authenticate as the service account and return Guacamole's full token
 * payload. Deliberately NOT cached: every call opens a NEW Guacamole session.
 *
 * This is what a browser handoff must use. Guacamole keeps its tokens in
 * memory and destroys one the moment its holder logs out (the web client sends
 * DELETE /api/tokens/<token>), so a browser handed the token THIS process is
 * caching can end that session for the whole orchestrator — after which every
 * server-side call fails with 403 PERMISSION_DENIED until the cache turns over.
 * Mint a separate one for the client and let it own its own session.
 */
async function mintGuacToken() {
  const username = process.env.GUAC_ADMIN_USER || 'cactus-admin';
  const password = process.env.GUAC_ADMIN_PASSWORD;
  if (!password) throw new Error('GUAC_ADMIN_PASSWORD not set in .env');

  const resp = await fetch(`${GUAC_URL}/api/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
  });

  if (!resp.ok) {
    const text = await resp.text();
    throw new Error(`Guacamole auth failed (${resp.status}): ${text}`);
  }
  return resp.json(); // { authToken, username, dataSource, availableDataSources }
}

/**
 * Drop the cached token so the next call re-authenticates.
 *
 * A Guacamole token can die long before the cache expires — the server was
 * restarted (tokens live in memory), the session idled out, or somebody logged
 * the session out. Nothing about that is visible until a call fails, so every
 * 401/403 clears the cache; see guacAPI.
 */
function invalidateGuacToken() {
  guacTokenCache = { token: null, expires: 0 };
}

async function getGuacToken() {
  // Return cached token if still valid (with 5-min buffer)
  if (guacTokenCache.token && Date.now() < guacTokenCache.expires - 300000) {
    return guacTokenCache.token;
  }

  const data = await mintGuacToken();
  guacTokenCache = {
    token: data.authToken,
    expires: Date.now() + 55 * 60 * 1000 // ~55 min
  };
  return data.authToken;
}

/**
 * Generic Guac API call helper.
 *
 * A dead session answers with 403 PERMISSION_DENIED — indistinguishable, at the
 * status code, from a real authorization failure. Since the token is cached for
 * up to ~50 minutes, believing it would leave the whole orchestrator locked out
 * of Guacamole for that long: no console provisioning, and every lane teardown
 * failing its Guac cleanup (which is enough to leave lanes stuck in 'error').
 * So the first 401/403 discards the cached token and retries ONCE with a fresh
 * one. A genuine permission error simply fails twice.
 */
async function guacAPI(method, path, body = null, _retried = false) {
  const token = await getGuacToken();
  const url = `${GUAC_URL}/api/session/data/${GUAC_DS}${path}?token=${token}`;

  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  };
  if (body) opts.body = JSON.stringify(body);

  const resp = await fetch(url, opts);

  // Some DELETE calls return 204 with no body
  if (resp.status === 204) return null;

  const text = await resp.text();
  if (!resp.ok) {
    if ((resp.status === 403 || resp.status === 401) && !_retried) {
      console.warn(`[Guac] ${method} ${path} returned ${resp.status} — re-authenticating and retrying once`);
      invalidateGuacToken();
      return guacAPI(method, path, body, true);
    }
    throw new Error(`Guac API ${method} ${path} failed (${resp.status}): ${text}`);
  }

  try { return JSON.parse(text); } catch { return text; }
}

/**
 * Ensure a Guacamole user account exists for `username` (a CyberCore email),
 * RESETTING its password if it already exists, so the caller always receives a
 * known credential.
 *
 * This rotates a live credential. Only call it where that is the intent — an
 * explicit "reset this user's console password" action. A deploy or a lookup
 * that merely needs the account to exist must use ensureGuacUserExists(), or it
 * will silently invalidate every console the user already has open.
 *
 * Returns the plaintext password on success, or null if Guac is unreachable.
 */
async function ensureGuacAccount(username) {
  const password = randomBytes(24).toString('hex');
  try {
    await guacAPI('POST', '/users', { username, password, attributes: {} });
    return password;
  } catch (_createErr) {
    // User already exists — reset the password so the caller gets a known value.
    try {
      await guacAPI('PUT', `/users/${encodeURIComponent(username)}`, {
        username,
        password,
        attributes: {},
      });
      return password;
    } catch (_resetErr) {
      return null;
    }
  }
}

/**
 * Ensure the account exists WITHOUT touching an existing one.
 *
 * Deploy paths need the account to be present before they can grant it
 * connection permissions, but must never rotate its password — the student may
 * already be holding that credential, and `attributes: {}` on a PUT also wipes
 * whatever timezone/expiry the account was created with.
 *
 * @returns {Promise<{existed: boolean, password: string|null}>} `password` is
 *   non-null only when this call created the account.
 */
async function ensureGuacUserExists(username) {
  try {
    await guacAPI('GET', `/users/${encodeURIComponent(username)}`);
    return { existed: true, password: null };
  } catch (_notFound) {
    // Fall through and create. A Guac outage surfaces on the create attempt.
  }
  const password = randomBytes(24).toString('hex');
  try {
    await guacAPI('POST', '/users', { username, password, attributes: {} });
    return { existed: false, password };
  } catch (createErr) {
    // Lost a race with a concurrent create — the account exists, which is all
    // the caller asked for.
    if (/already exists/i.test(createErr.message)) return { existed: true, password: null };
    throw createErr;
  }
}

module.exports = {
  guacAPI,
  getGuacToken,
  mintGuacToken,
  invalidateGuacToken,
  ensureGuacAccount,
  ensureGuacUserExists,
  GUAC_URL,
  GUAC_DS,
};
