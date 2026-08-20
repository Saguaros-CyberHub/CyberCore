/**
 * ============================================================================
 * GUACAMOLE API HELPER
 * Shared utility for communicating with the Apache Guacamole API
 * ============================================================================
 */

const { randomBytes } = require('crypto');

const GUAC_URL = process.env.GUAC_API_URL || 'http://100.100.70.10:8080/guacamole';
const GUAC_DS = process.env.GUAC_DATASOURCE || 'postgresql';

/**
 * Hard deadline for ONE Guacamole HTTP call.
 *
 * Guacamole 1.5.5 shares its Postgres container with CyberCore, so when it
 * blocks on that database — or on guacd — it still completes the TCP handshake
 * and then simply never sends response headers. A bare fetch() waits that out
 * for undici's default 300s headersTimeout and logs nothing, so a single
 * stalled console call pins the request (and whatever deploy is awaiting it)
 * for five minutes and looks, from outside, like the orchestrator has hung.
 * 10s is two orders of magnitude above a healthy Guac round trip and well
 * under any caller's patience.
 */
const GUAC_TIMEOUT_MS = Number(process.env.GUAC_HTTP_TIMEOUT_MS) || 10000;

/**
 * Ceiling for one logical guacAPI() call, which can cost up to four round trips
 * (mint a token, make the call, then re-auth and call again on a 401/403).
 * Capping each fetch on its own would still add up to 4 x GUAC_TIMEOUT_MS, so
 * every fetch inside one call shares this single budget instead and the worst
 * case stays at two round trips no matter how the retry falls.
 */
const GUAC_TOTAL_TIMEOUT_MS = GUAC_TIMEOUT_MS * 2;

// Cache the Guac auth token (they last ~60 min)
let guacTokenCache = { token: null, expires: 0 };

/**
 * The error every timed-out Guacamole call throws.
 *
 * Named deliberately: an aborted fetch reports "This operation was aborted",
 * which names neither the host nor the call and reads like a generic network
 * blip, and that is exactly what made these stalls unreadable in the log.
 */
function guacTimeoutError(operation, ms, wholeBudget = false) {
  const secs = Math.round(ms / 100) / 10;
  const err = new Error(wholeBudget
    ? `Guacamole did not respond within the ${secs}s budget for this call — ${operation} at ${GUAC_URL}`
    : `Guacamole did not respond in ${secs}s — ${operation} at ${GUAC_URL}`);
  // Tagged so a caller that must swallow the failure (see getUserGuacToken in
  // routes/guac-sessions.js) can still tell an outage from a bad password.
  err.code = 'GUAC_TIMEOUT';
  return err;
}

/**
 * One Guacamole HTTP call with a hard deadline, flattened to
 * `{ status, ok, text }`.
 *
 * Every fetch that talks to Guacamole goes through here — see GUAC_TIMEOUT_MS
 * for why none of them may be a bare fetch().
 *
 * @param {string} operation Human-readable label ("GET /connections/7") used in
 *   the timeout message.
 * @param {number} [deadline] Absolute Date.now() stamp shared by every call in
 *   one logical operation, so a re-auth + retry cannot multiply the worst case.
 *   0 means "this call only", i.e. the full GUAC_TIMEOUT_MS.
 */
async function guacFetchText(url, opts, operation, deadline = 0) {
  const budget = deadline ? Math.min(GUAC_TIMEOUT_MS, deadline - Date.now()) : GUAC_TIMEOUT_MS;
  // Trimmed means an earlier round trip in this same logical call already spent
  // most of the shared budget, so the honest number to report on a timeout is
  // the whole budget rather than this last thin slice of it — "did not respond
  // in 0.2s" would read like we expected an answer in 0.2s.
  const trimmed = budget < GUAC_TIMEOUT_MS;
  // Shared budget already spent by earlier round trips: fail now rather than
  // open a request that is guaranteed to be aborted before it can answer.
  if (budget <= 0) throw guacTimeoutError(operation, GUAC_TOTAL_TIMEOUT_MS, true);

  try {
    const resp = await fetch(url, { ...opts, signal: AbortSignal.timeout(budget) });
    // The signal stays armed across the body read on purpose: a Guacamole that
    // stalls AFTER sending headers hangs resp.text() in exactly the same way,
    // and the caller wants the body either way (error text, or the payload).
    const text = resp.status === 204 ? '' : await resp.text();
    return { status: resp.status, ok: resp.ok, text };
  } catch (err) {
    // AbortSignal.timeout rejects the fetch with a TimeoutError DOMException;
    // undici surfaces an aborted body read as an AbortError. Both mean the same
    // thing here — no answer inside the budget.
    if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
      throw guacTimeoutError(operation, trimmed ? GUAC_TOTAL_TIMEOUT_MS : budget, trimmed);
    }
    throw err;
  }
}

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
 *
 * @param {number} [deadline] Optional shared budget stamp — see guacFetchText.
 *   External callers omit it and get the plain per-call GUAC_TIMEOUT_MS.
 */
async function mintGuacToken(deadline = 0) {
  const username = process.env.GUAC_ADMIN_USER || 'cactus-admin';
  const password = process.env.GUAC_ADMIN_PASSWORD;
  if (!password) throw new Error('GUAC_ADMIN_PASSWORD not set in .env');

  // Logging in is the call most likely to stall: it is the one that always hits
  // Guacamole's Postgres, which is the container that gets blocked.
  const { status, ok, text } = await guacFetchText(`${GUAC_URL}/api/tokens`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`
  }, 'POST /api/tokens (service-account login)', deadline);

  if (!ok) {
    throw new Error(`Guacamole auth failed (${status}): ${text}`);
  }
  return JSON.parse(text); // { authToken, username, dataSource, availableDataSources }
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

async function getGuacToken(deadline = 0) {
  // Return cached token if still valid (with 5-min buffer)
  if (guacTokenCache.token && Date.now() < guacTokenCache.expires - 300000) {
    return guacTokenCache.token;
  }

  // Pass the budget down: on a cache miss this login is the first of the round
  // trips guacAPI is bounding, not a free one.
  const data = await mintGuacToken(deadline);
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
 *
 * That retry is also why this call carries a deadline rather than just a
 * per-fetch timeout: it can cost four round trips (login, call, login, call),
 * and four independent 10s waits is a 40s stall, not a bounded one. All four
 * share GUAC_TOTAL_TIMEOUT_MS, and _retried keeps the recursion to one extra
 * attempt no matter what.
 */
async function guacAPI(method, path, body = null, _retried = false, _deadline = 0) {
  // Set on the first attempt only; the retry inherits it (see below) so it
  // spends what is LEFT of the budget instead of opening a fresh one.
  const deadline = _deadline || Date.now() + GUAC_TOTAL_TIMEOUT_MS;

  const token = await getGuacToken(deadline);
  const url = `${GUAC_URL}/api/session/data/${GUAC_DS}${path}?token=${token}`;

  const opts = {
    method,
    headers: { 'Content-Type': 'application/json' }
  };
  if (body) opts.body = JSON.stringify(body);

  const { status, ok, text } = await guacFetchText(url, opts, `${method} ${path}`, deadline);

  // Some DELETE calls return 204 with no body
  if (status === 204) return null;

  if (!ok) {
    if ((status === 403 || status === 401) && !_retried) {
      console.warn(`[Guac] ${method} ${path} returned ${status} — re-authenticating and retrying once`);
      invalidateGuacToken();
      // _retried = true makes this the last attempt; the shared deadline makes
      // it a cheap one if the first attempt already burned most of the budget.
      return guacAPI(method, path, body, true, deadline);
    }
    throw new Error(`Guac API ${method} ${path} failed (${status}): ${text}`);
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
  guacFetchText,
  getGuacToken,
  mintGuacToken,
  invalidateGuacToken,
  ensureGuacAccount,
  ensureGuacUserExists,
  GUAC_URL,
  GUAC_DS,
};
