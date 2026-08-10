/**
 * ============================================================================
 * ACTIVATION TOKENS
 * ============================================================================
 * Single-use, time-bounded links that let a newly-imported student set their
 * own password without a credential ever existing in their mailbox.
 *
 * Why a link rather than a temporary password: an emailed password is a working
 * credential that sits in an inbox indefinitely, readable by anyone who later
 * gains access to that mailbox, and it survives being "used" because nothing
 * forces it to stop working. A token is consumed on first use and dies on a
 * clock, so the window is bounded by construction rather than by policy.
 *
 * Only the SHA-256 of the token is stored. A read of this table — via adminer,
 * a backup, or a dump — must not yield a usable link.
 */

const crypto = require('crypto');
const { cybercoreQuery } = require('./cybercore-db');

// 32 bytes -> 64 hex chars. Far beyond guessing, and still a tolerable URL.
const TOKEN_BYTES = 32;

const DEFAULT_TTL_HOURS = Number(process.env.ACTIVATION_TTL_HOURS) > 0
  ? Number(process.env.ACTIVATION_TTL_HOURS)
  : 72;

const VALID_PURPOSES = ['activate', 'reset'];

function httpError(status, message) {
  const err = new Error(message);
  err.status = status;
  return err;
}

/**
 * SHA-256, not bcrypt.
 *
 * Deliberate, and the opposite of the right answer for passwords. A token is
 * 256 bits of uniform randomness, so there is no dictionary to slow down — the
 * only thing a work factor would buy is a slower lookup on every activation.
 * Bcrypt would also make the hash unsearchable, since it salts per row and we
 * need an indexed equality match to find the token at all.
 */
function hashToken(token) {
  return crypto.createHash('sha256').update(String(token)).digest('hex');
}

/**
 * Mint a token for a user. Returns the plaintext EXACTLY once — it is never
 * recoverable afterwards, by design.
 *
 * Any outstanding token for the same purpose is revoked first: if an instructor
 * resends an invitation, the older link in the older email must stop working,
 * or "resend" would quietly widen the window instead of replacing it.
 *
 * @param {string} userId
 * @param {{purpose?: string, ttlHours?: number, createdBy?: string, context?: object}} [opts]
 * @returns {Promise<{token: string, expiresAt: Date, tokenId: string}>}
 */
async function issueActivationToken(userId, opts = {}) {
  const purpose = opts.purpose || 'activate';
  if (!VALID_PURPOSES.includes(purpose)) {
    throw httpError(400, `invalid activation purpose "${purpose}"`);
  }

  const ttlHours = Number(opts.ttlHours) > 0 ? Number(opts.ttlHours) : DEFAULT_TTL_HOURS;
  const expiresAt = new Date(Date.now() + ttlHours * 3600 * 1000);

  await revokeActivationTokens(userId, purpose);

  const token = crypto.randomBytes(TOKEN_BYTES).toString('hex');
  const result = await cybercoreQuery(
    `INSERT INTO cybercore_activation_token
       (user_id, token_hash, purpose, expires_at, created_by, context)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb)
     RETURNING token_id`,
    [userId, hashToken(token), purpose, expiresAt, opts.createdBy || null,
     JSON.stringify(opts.context || {})]
  );

  return { token, expiresAt, tokenId: result.rows[0].token_id };
}

/**
 * Redeem a token, atomically and exactly once.
 *
 * The single UPDATE is the whole point: checking "is it unconsumed?" and then
 * separately marking it consumed would let two concurrent requests both pass
 * the check. Here the database decides, and the loser gets rowCount 0.
 *
 * Every failure mode — unknown, expired, already used — returns the same error,
 * so a caller cannot use this endpoint to learn which tokens ever existed.
 *
 * @returns {Promise<{userId: string, purpose: string, context: object, tokenId: string}>}
 */
async function consumeActivationToken(token) {
  if (typeof token !== 'string' || token.length < 32) {
    throw httpError(400, 'This link is not valid. Ask your instructor to send a new one.');
  }

  const result = await cybercoreQuery(
    `UPDATE cybercore_activation_token
        SET consumed_at = NOW()
      WHERE token_hash = $1
        AND consumed_at IS NULL
        AND expires_at > NOW()
      RETURNING token_id, user_id, purpose, context`,
    [hashToken(token)]
  );

  if (result.rows.length === 0) {
    throw httpError(400, 'This link has expired or has already been used. Ask your instructor to send a new one.');
  }

  const row = result.rows[0];
  return {
    tokenId: row.token_id,
    userId: row.user_id,
    purpose: row.purpose,
    context: row.context || {},
  };
}

/**
 * Invalidate a user's outstanding tokens. Called before issuing a replacement,
 * and worth calling whenever an account's credentials change by another route.
 *
 * @returns {Promise<number>} how many were revoked
 */
async function revokeActivationTokens(userId, purpose = 'activate') {
  const result = await cybercoreQuery(
    `UPDATE cybercore_activation_token
        SET consumed_at = NOW()
      WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`,
    [userId, purpose]
  );
  return result.rowCount || 0;
}

/**
 * Whether a user has a live, unredeemed invitation — so a roster can show
 * "invited, not yet activated" rather than leaving an instructor guessing.
 */
async function pendingActivationFor(userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return {};
  const result = await cybercoreQuery(
    `SELECT user_id, MAX(expires_at) AS expires_at
       FROM cybercore_activation_token
      WHERE user_id = ANY($1::uuid[])
        AND purpose = 'activate'
        AND consumed_at IS NULL
        AND expires_at > NOW()
      GROUP BY user_id`,
    [userIds]
  );
  const out = {};
  result.rows.forEach(r => { out[r.user_id] = r.expires_at; });
  return out;
}

/** Build the link that goes in the email. */
function activationUrl(token, baseUrl) {
  const base = String(baseUrl || process.env.MAIL_PUBLIC_URL || '').replace(/\/+$/, '');
  return `${base}/activate?token=${encodeURIComponent(token)}`;
}

/**
 * Idempotent boot DDL. Mirrors ensureMfaColumns() in server.js — the
 * config/postgres scripts only run on a fresh volume. Keep in sync with
 * front-end/migrations/028_activation_tokens.sql.
 */
async function ensureActivationTokens() {
  try {
    await cybercoreQuery(`
      CREATE TABLE IF NOT EXISTS cybercore_activation_token (
        token_id     UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        user_id      UUID NOT NULL,
        token_hash   TEXT NOT NULL UNIQUE,
        purpose      TEXT NOT NULL DEFAULT 'activate'
                     CHECK (purpose IN ('activate','reset')),
        expires_at   TIMESTAMPTZ NOT NULL,
        consumed_at  TIMESTAMPTZ,
        created_by   UUID,
        context      JSONB NOT NULL DEFAULT '{}'::jsonb,
        created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
      )
    `);
    await cybercoreQuery(`
      CREATE INDEX IF NOT EXISTS idx_activation_token_user
        ON cybercore_activation_token (user_id) WHERE consumed_at IS NULL
    `);
    console.log('✅ Activation token table ensured');
  } catch (err) {
    console.warn('⚠️  Could not ensure activation token table:', err.message);
  }
}

/**
 * Drop tokens that are long dead. Consumed and expired rows have no purpose
 * beyond a short audit tail, and this table would otherwise grow one row per
 * student per import forever.
 */
async function pruneActivationTokens(retentionDays = 30) {
  try {
    const result = await cybercoreQuery(
      `DELETE FROM cybercore_activation_token
        WHERE (consumed_at IS NOT NULL AND consumed_at < NOW() - ($1 || ' days')::interval)
           OR (expires_at < NOW() - ($1 || ' days')::interval)`,
      [String(retentionDays)]
    );
    return result.rowCount || 0;
  } catch (err) {
    console.warn('⚠️  Could not prune activation tokens:', err.message);
    return 0;
  }
}

module.exports = {
  TOKEN_BYTES, DEFAULT_TTL_HOURS,
  hashToken,
  issueActivationToken,
  consumeActivationToken,
  revokeActivationTokens,
  pendingActivationFor,
  activationUrl,
  ensureActivationTokens,
  pruneActivationTokens,
};
