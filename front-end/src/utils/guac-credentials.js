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
const { ensureGuacAccount, ensureGuacUserExists } = require('./guacamole');

const LOG = '[GuacCreds]';

/** The pgcrypto key, or null when the deployment has not configured one. */
function encryptKey() {
  return process.env.GUAC_ENCRYPT_KEY || null;
}

/**
 * Read the stored password for a user.
 *
 * Returns `{ password, decryptFailed }`. The two failure modes MUST stay
 * distinguishable: "nothing is stored" is recoverable by issuing a new
 * credential, but "stored ciphertext would not decrypt" (a rotated or mistyped
 * GUAC_ENCRYPT_KEY, a row written under an older key, corrupt bytes) is NOT —
 * treating it as "nothing stored" and minting turns a read into a rotation that
 * kills every live console for that user AND overwrites the only ciphertext
 * that a corrected key could still have recovered.
 */
async function readStoredPassword(userId) {
  const key = encryptKey();
  if (!key) return { password: null, decryptFailed: false };
  try {
    const r = await cybercoreQuery(
      `SELECT CASE WHEN guac_password IS NOT NULL
                   THEN pgp_sym_decrypt(guac_password, $2)::text END AS pw
         FROM cybercore_user WHERE user_id = $1`,
      [userId, key]
    );
    return { password: r.rows[0]?.pw || null, decryptFailed: false };
  } catch (e) {
    // pgp_sym_decrypt raises "Wrong key or corrupt data" — it does not return null.
    console.warn(`${LOG} Could not decrypt guac_password for ${userId}: ${e.message}`);
    return { password: null, decryptFailed: true };
  }
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

/** The user row every entry point here needs, or a 404-shaped throw. */
async function loadUser(userId) {
  const u = await cybercoreQuery(
    `SELECT user_id, email, username, role FROM cybercore_user WHERE user_id = $1`,
    [userId]
  );
  if (u.rows.length === 0) {
    const err = new Error('User not found');
    err.status = 404;
    throw err;
  }
  return u.rows[0];
}

/**
 * Make sure the user HAS a Guacamole account, without disturbing it if it
 * already exists. This is what deploy paths need: they grant connection
 * permissions to the account by name, and a PATCH against a nonexistent user
 * fails, leaving the owner with a console they cannot see.
 *
 * Deliberately never rotates. A deploy that reset the password would invalidate
 * the credential the student is already holding — including the one the admin
 * group deploy prints for the class moments earlier.
 *
 * Works with GUAC_ENCRYPT_KEY unset: the account is still created (only the
 * at-rest copy of its password is skipped), because otherwise every console
 * permission grant on such a deployment fails silently.
 *
 * @returns {Promise<boolean>} whether the account is now present.
 */
async function ensureGuacUser(userId, email) {
  const username = email || (await loadUser(userId).catch(() => null))?.email;
  if (!username) {
    console.warn(`${LOG} Cannot ensure a Guacamole account for ${userId}: no email on the account`);
    return false;
  }
  try {
    const { existed, password } = await ensureGuacUserExists(username);
    // Only a freshly created account has a password we know; record it so staff
    // can hand it back later.
    if (!existed && password) await storePassword(userId, password).catch(() => {});
    return true;
  } catch (e) {
    console.warn(`${LOG} Could not ensure a Guacamole account for ${username}: ${e.message}`);
    return false;
  }
}

/**
 * The Guacamole login recorded for a user.
 *
 * @param {string}  userId
 * @param {object}  [opts]
 * @param {boolean} [opts.create=true]  when nothing is recorded, create the
 *   account and store its password. This only ever mints for an account that
 *   does NOT already exist in Guacamole — an existing account whose password we
 *   have lost is reported, not silently rotated, because rotating would break
 *   every console that user currently has.
 * @returns {Promise<{username, password, available, source, reason?}>}
 *   `source` is 'stored' | 'migrated' | 'created' | 'undecryptable' |
 *   'unrecoverable' | 'none'.
 */
async function getGuacCredential(userId, { create = true } = {}) {
  const user = await loadUser(userId);
  // Guacamole accounts are email-keyed everywhere in this codebase.
  const username = user.email || user.username;

  if (!encryptKey()) {
    return {
      username, password: null, available: false, source: 'none',
      reason: 'GUAC_ENCRYPT_KEY is not configured on this server, so console passwords are not stored and cannot be recovered. Use Reset to issue a new one.',
    };
  }

  const { password: stored, decryptFailed } = await readStoredPassword(userId);
  if (decryptFailed) {
    // Never mint here: doing so would overwrite ciphertext that the correct key
    // could still decrypt, and rotate a password that is very likely still live.
    return {
      username, password: null, available: false, source: 'undecryptable',
      reason: 'A password is stored for this user but could not be decrypted — GUAC_ENCRYPT_KEY may have changed since it was written. Restore the original key to recover it, or use Reset to issue a new one.',
    };
  }
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

  // Nothing recorded. Create the account if it genuinely does not exist — but if
  // it does, its password is simply unknown to us, and resetting it behind the
  // caller's back would kill their live sessions. Say so and let them choose.
  let created;
  try {
    created = await ensureGuacUserExists(username);
  } catch (e) {
    console.warn(`${LOG} Guacamole unreachable for ${username}: ${e.message}`);
    return {
      username, password: null, available: false, source: 'none',
      reason: 'Guacamole is unreachable, so a console password could not be issued.',
    };
  }

  if (created.existed) {
    return {
      username, password: null, available: false, source: 'unrecoverable',
      reason: 'This user has a Guacamole account but no password on record. Use Reset to issue a new one — that will end any console sessions they currently have open.',
    };
  }

  const persisted = await storePassword(userId, created.password).catch(() => false);
  return {
    username, password: created.password, available: true, source: 'created',
    ...(persisted ? {} : {
      warning: 'This password could not be saved, so it cannot be looked up again — record it now.',
    }),
  };
}

/**
 * Rotate a user's Guacamole password: reset it in Guacamole and re-encrypt the
 * new value. Existing Guacamole sessions survive; the next login needs the new
 * password.
 */
async function resetGuacCredential(userId) {
  const user = await loadUser(userId);
  const username = user.email || user.username;
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
async function getGuacCredentialsForUsers(userIds, caller = null) {
  if (!Array.isArray(userIds) || userIds.length === 0) return {};
  const key = encryptKey();

  // Roles first, so a non-admin caller never gets an instructor's or admin's
  // password in a cohort listing (see assertDisclosable).
  const roles = await cybercoreQuery(
    `SELECT user_id, email, username, role FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    [userIds]
  ).catch((e) => {
    console.warn(`${LOG} Bulk role read failed: ${e.message}`);
    return { rows: [] };
  });

  const out = {};
  const readable = [];
  for (const row of roles.rows) {
    const base = { username: row.email || row.username, password: null, available: false };
    try {
      assertDisclosable(row, caller);
      readable.push(row.user_id);
      out[row.user_id] = base;
    } catch (err) {
      out[row.user_id] = { ...base, source: 'withheld', reason: err.message };
    }
  }
  if (!key || readable.length === 0) {
    if (!key) for (const id of readable) out[id].reason = 'GUAC_ENCRYPT_KEY is not configured on this server.';
    return out;
  }

  // Decrypt per row: one bad ciphertext must not fail the whole cohort read, and
  // "undecryptable" has to stay distinguishable from "nothing stored".
  const pw = await cybercoreQuery(
    `SELECT user_id,
            CASE WHEN guac_password IS NOT NULL
                 THEN pgp_sym_decrypt(guac_password, $2)::text END AS pw
       FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    [readable, key]
  ).catch(async (e) => {
    console.warn(`${LOG} Bulk decrypt failed (${e.message}) — falling back to per-user reads`);
    const rows = [];
    for (const id of readable) {
      const one = await readStoredPassword(id);
      rows.push({ user_id: id, pw: one.password, _decryptFailed: one.decryptFailed });
    }
    return { rows };
  });

  for (const row of pw.rows) {
    const entry = out[row.user_id];
    if (!entry) continue;
    if (row._decryptFailed) {
      entry.source = 'undecryptable';
      entry.reason = 'Stored password could not be decrypted — GUAC_ENCRYPT_KEY may have changed.';
      continue;
    }
    entry.password = row.pw || null;
    entry.available = !!row.pw;
  }
  return out;
}

/**
 * Guard for the staff-facing disclosure endpoints.
 *
 * Reading a Guacamole password hands over that account's entire Guacamole
 * session — every connection it holds READ on. For an admin that is the whole
 * cluster's consoles. Course membership is NOT sufficient authority for that:
 * an instructor can enroll an arbitrary email address in their own course, so
 * without this check "manages the course AND target is enrolled" is a two-step
 * path from instructor to admin.
 *
 * Admins may look up anyone. Everyone else is limited to student-tier accounts.
 */
function assertDisclosable(targetUser, caller) {
  if (caller?.role === 'admin') return;
  const targetRole = String(targetUser.role || 'student').toLowerCase();
  if (targetRole !== 'student') {
    const err = new Error(
      `Console passwords can only be looked up for student accounts (this account is '${targetRole}'). ` +
      `An administrator can retrieve it if needed.`
    );
    err.status = 403;
    throw err;
  }
}

/** Load a user and assert the caller may see their credential. Returns the row. */
async function assertCanDiscloseFor(userId, caller) {
  const user = await loadUser(userId);
  assertDisclosable(user, caller);
  return user;
}

module.exports = {
  ensureGuacUser,
  getGuacCredential,
  getGuacCredentialsForUsers,
  resetGuacCredential,
  readStoredPassword,
  storePassword,
  assertDisclosable,
  assertCanDiscloseFor,
};
