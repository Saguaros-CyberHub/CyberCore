/**
 * ============================================================================
 * GUACAMOLE CREDENTIAL ACCESS
 * ----------------------------------------------------------------------------
 * One place to read (and rotate) the Guacamole password CyberCore holds for a
 * user, so staff can hand a student their console login back when they lose it.
 *
 * Storage: cybercore_user.guac_password, encrypted at rest with pgcrypto
 * (pgp_sym_encrypt). The key is GUAC_ENCRYPT_KEY in the app environment and is
 * never stored in the database — without it nothing here can decrypt, which is
 * reported as `available: false` rather than as an empty password.
 *
 * This is the same get-or-mint sequence lane-deployer.resolveGuacPassword,
 * routes/workstations.js, routes/auth.js and routes/admin/guac.js each grew
 * their own copy of. They now share this one, so a password minted by any of
 * them is the password every other path reports.
 *
 * Callers are responsible for authorization. Every route that exposes these
 * values must be staff-gated AND must log the disclosure — a Guacamole password
 * reaches every console that user owns.
 * ============================================================================
 */

const { cybercoreQuery } = require('./cybercore-db');
const { ensureGuacAccount } = require('./guacamole');

const LOG = '[GuacCreds]';

/** The pgcrypto key, or null when the deployment has not configured one. */
function encryptKey() {
  return process.env.GUAC_ENCRYPT_KEY || null;
}

/** Decrypt the stored password for a user, or null. */
async function readStoredPassword(userId) {
  const key = encryptKey();
  if (!key) return null;
  const r = await cybercoreQuery(
    `SELECT CASE WHEN guac_password IS NOT NULL
                 THEN pgp_sym_decrypt(guac_password, $2)::text END AS pw
       FROM cybercore_user WHERE user_id = $1`,
    [userId, key]
  ).catch((e) => {
    // A wrong key raises "Wrong key or corrupt data" rather than returning null.
    console.warn(`${LOG} Could not decrypt guac_password for ${userId}: ${e.message}`);
    return { rows: [] };
  });
  return r.rows[0]?.pw || null;
}

/** Encrypt and persist a password. No-op (logged) when no key is configured. */
async function storePassword(userId, password) {
  const key = encryptKey();
  if (!key) {
    console.warn(`${LOG} GUAC_ENCRYPT_KEY is not set — not persisting the password for ${userId}`);
    return false;
  }
  await cybercoreQuery(
    `UPDATE cybercore_user SET guac_password = pgp_sym_encrypt($1, $2) WHERE user_id = $3`,
    [password, key, userId]
  );
  return true;
}

/**
 * A password recorded on one of the user's VM instances. Deploys before the
 * user-level column existed wrote it there; migrating it forward means an old
 * lane's credential is still recoverable.
 */
async function readLegacyVmPassword(userId) {
  const r = await cybercoreQuery(
    `SELECT vi.metadata->>'guac_password' AS pw
       FROM cybercore_vm_instance vi
       JOIN cybercore_resource r ON r.resource_id = vi.resource_id
       JOIN cybercore_allocation a ON a.resource_id = r.resource_id AND a.user_id = $1
      WHERE vi.metadata->>'guac_password' IS NOT NULL
        AND vi.destroyed_at IS NULL
      LIMIT 1`,
    [userId]
  ).catch(() => ({ rows: [] }));
  return r.rows[0]?.pw || null;
}

/**
 * The Guacamole login for a user, creating the account on first use.
 *
 * @param {string}  userId
 * @param {object}  [opts]
 * @param {boolean} [opts.create=true]  mint + persist a password when none is
 *   stored. Set false for a read-only peek that must not change anything.
 * @returns {Promise<{username, password, available, source, reason?}>}
 *   `source` is 'stored' | 'migrated' | 'created' | 'none'.
 */
async function getGuacCredential(userId, { create = true } = {}) {
  const u = await cybercoreQuery(
    `SELECT user_id, email, username, first_name, last_name FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  if (u.rows.length === 0) {
    const err = new Error('User not found');
    err.status = 404;
    throw err;
  }
  const user = u.rows[0];
  // Guacamole accounts are email-keyed everywhere in this codebase.
  const username = user.email || user.username;

  if (!encryptKey()) {
    return {
      username, password: null, available: false, source: 'none',
      reason: 'GUAC_ENCRYPT_KEY is not configured on this server, so stored console passwords cannot be decrypted.',
    };
  }

  const stored = await readStoredPassword(userId);
  if (stored) return { username, password: stored, available: true, source: 'stored' };

  if (!create) {
    return {
      username, password: null, available: false, source: 'none',
      reason: 'No console password is recorded for this user yet.',
    };
  }

  const legacy = await readLegacyVmPassword(userId);
  if (legacy) {
    await storePassword(userId, legacy).catch(() => {});
    return { username, password: legacy, available: true, source: 'migrated' };
  }

  if (!username) {
    return {
      username: null, password: null, available: false, source: 'none',
      reason: 'This account has no email address, so it cannot have a Guacamole login.',
    };
  }

  // Nothing recorded: create (or reset) the Guacamole account so the caller
  // walks away with a credential that actually works.
  const minted = await ensureGuacAccount(username).catch((e) => {
    console.warn(`${LOG} ensureGuacAccount failed for ${username}: ${e.message}`);
    return null;
  });
  if (!minted) {
    return {
      username, password: null, available: false, source: 'none',
      reason: 'Guacamole is unreachable, so a console password could not be issued.',
    };
  }
  await storePassword(userId, minted).catch(() => {});
  return { username, password: minted, available: true, source: 'created' };
}

/**
 * Rotate a user's Guacamole password: reset it in Guacamole and re-encrypt the
 * new value. Existing Guacamole sessions survive; the next login needs the new
 * password.
 */
async function resetGuacCredential(userId) {
  const u = await cybercoreQuery(
    `SELECT email, username FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  if (u.rows.length === 0) {
    const err = new Error('User not found');
    err.status = 404;
    throw err;
  }
  const username = u.rows[0].email || u.rows[0].username;
  if (!username) {
    const err = new Error('This account has no email address, so it cannot have a Guacamole login.');
    err.status = 409;
    throw err;
  }

  const password = await ensureGuacAccount(username);
  if (!password) {
    const err = new Error('Guacamole is unreachable, so the password could not be reset.');
    err.status = 502;
    throw err;
  }
  const persisted = await storePassword(userId, password);
  return {
    username,
    password,
    available: true,
    source: 'created',
    ...(persisted ? {} : {
      warning: 'GUAC_ENCRYPT_KEY is not configured, so this password was NOT saved — record it now.',
    }),
  };
}

/**
 * Credentials for many users at once, read-only (never mints). Powers the
 * instructor's cohort view, where issuing N Guacamole accounts as a side effect
 * of opening a page would be wrong.
 *
 * @returns {Promise<Object.<string, {username, password, available}>>} by user_id
 */
async function getGuacCredentialsForUsers(userIds) {
  if (!Array.isArray(userIds) || userIds.length === 0) return {};
  const key = encryptKey();

  const r = await cybercoreQuery(
    key
      ? `SELECT user_id, email, username,
                CASE WHEN guac_password IS NOT NULL
                     THEN pgp_sym_decrypt(guac_password, $2)::text END AS pw
           FROM cybercore_user WHERE user_id = ANY($1::uuid[])`
      : `SELECT user_id, email, username, NULL::text AS pw
           FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    key ? [userIds, key] : [userIds]
  ).catch((e) => {
    console.warn(`${LOG} Bulk credential read failed: ${e.message}`);
    return { rows: [] };
  });

  const out = {};
  for (const row of r.rows) {
    out[row.user_id] = {
      username: row.email || row.username,
      password: row.pw || null,
      available: !!row.pw,
    };
  }
  return out;
}

module.exports = {
  getGuacCredential,
  getGuacCredentialsForUsers,
  resetGuacCredential,
  readStoredPassword,
  storePassword,
};
