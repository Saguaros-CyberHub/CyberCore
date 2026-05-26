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

async function getGuacToken() {
  // Return cached token if still valid (with 5-min buffer)
  if (guacTokenCache.token && Date.now() < guacTokenCache.expires - 300000) {
    return guacTokenCache.token;
  }

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

  const data = await resp.json();
  guacTokenCache = {
    token: data.authToken,
    expires: Date.now() + 55 * 60 * 1000 // ~55 min
  };
  return data.authToken;
}

// Generic Guac API call helper
async function guacAPI(method, path, body = null) {
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
    throw new Error(`Guac API ${method} ${path} failed (${resp.status}): ${text}`);
  }

  try { return JSON.parse(text); } catch { return text; }
}

/**
 * Ensure a Guacamole user account exists for `username` (a CyberCore email).
 * Creates the account if it doesn't exist, or resets the password if it does,
 * so the caller always receives a known credential.
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

module.exports = { guacAPI, getGuacToken, ensureGuacAccount, GUAC_URL, GUAC_DS };
