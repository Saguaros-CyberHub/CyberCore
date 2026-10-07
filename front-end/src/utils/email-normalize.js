/**
 * ============================================================================
 * EMAIL NORMALIZATION
 * ============================================================================
 * One definition of "the same address", shared by the write path (account
 * creation) and the read path (login lookup). The two MUST agree: an address
 * stored in one form and looked up in another is an account nobody can sign
 * into, which is the bug this module exists to fix.
 *
 * The bug, concretely: POST /api/admin/users/batch stored the roster's email
 * verbatim, while POST /api/auth/login ran express-validator's .normalizeEmail()
 * over what the user typed and then matched it with `WHERE email = $1`. A roster
 * row of `Jane.Doe@university.edu` was therefore stored capitalized and looked
 * up lowercased — a permanently unusable account.
 */

const validator = require('validator');

/**
 * Canonical form: trim + lowercase, and nothing else.
 *
 * Deliberately more conservative than validator's normalizeEmail(), whose
 * defaults also strip dots and +subaddresses for Gmail/Outlook/Yahoo/iCloud.
 * Those rewrites turn the address into something the roster never contained —
 * `first.last@gmail.com` becomes `firstlast@gmail.com` — which surprises users
 * and makes "the address I gave you" stop being "the address I sign in with".
 *
 * Lowercasing alone is enough to make lookups stable, and it is exactly what
 * ux_cybercore_user_email_lower already indexes.
 *
 * @param {string} email
 * @returns {string|null} normalized address, or null if there was nothing usable
 */
function normalizeEmail(email) {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim().toLowerCase();
  return trimmed.length > 0 ? trimmed : null;
}

/**
 * The aggressive normalization this codebase applied at registration until
 * Phase 0 — i.e. validator.normalizeEmail() with its defaults, which is what
 * express-validator's .normalizeEmail() called under the hood.
 *
 * Accounts created before that change are STORED in this form, so the login
 * lookup falls back to it once before giving up. Without the fallback, a user
 * who self-registered as `first.last@gmail.com` (stored as `firstlast@gmail.com`)
 * would be locked out the moment login stopped stripping dots.
 *
 * New code must never write this form — it is a compatibility shim for reads.
 *
 * @param {string} email
 * @returns {string|null}
 */
function legacyNormalizeEmail(email) {
  if (typeof email !== 'string') return null;
  const trimmed = email.trim();
  if (!trimmed) return null;

  // validator.normalizeEmail does NOT validate — it splits on '@' and rewrites
  // the halves. Handed a bare username it happily returns '@bob'. Since the
  // login field now accepts usernames as well as addresses, gate on shape first
  // so the caller never runs a second lookup against a nonsense string.
  if (!isEmailShaped(trimmed)) return null;

  const normalized = validator.normalizeEmail(trimmed);
  return normalized === false ? null : normalized;
}

/**
 * True when `email` looks like an address at all. Kept here so the roster
 * import and the auth routes apply the same test rather than two regexes that
 * drift apart. Mirrors the check at admin/settings.js:690.
 */
function isEmailShaped(email) {
  return typeof email === 'string' && /^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email.trim());
}

module.exports = { normalizeEmail, legacyNormalizeEmail, isEmailShaped };
