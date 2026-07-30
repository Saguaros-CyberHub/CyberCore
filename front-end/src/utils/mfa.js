/**
 * ============================================================================
 * MFA (TOTP) HELPERS
 * ----------------------------------------------------------------------------
 * Authenticator-app TOTP via otplib, plus one-time recovery codes.
 *
 * Secrets themselves are encrypted at rest with pgcrypto (pgp_sym_encrypt) in
 * the SQL layer — see auth.js. This module is DB-agnostic: it only generates
 * and verifies secrets/codes. The encryption key lives in MFA_ENCRYPT_KEY
 * (falls back to GUAC_ENCRYPT_KEY) and is exposed here as mfaKey() so callers
 * pass it as a query parameter.
 * ============================================================================
 */

const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const otp = require('otplib');
const QRCode = require('qrcode');

const ISSUER = process.env.MFA_ISSUER || 'CyberHub';
const RECOVERY_CODE_COUNT = 10;

// Allow ±1 time-step (±30s) of clock drift between server and authenticator.
// otplib 13 dropped the configurable `authenticator` singleton, so tolerance is
// passed per verify() call in seconds rather than set once as `window: 1`.
const EPOCH_TOLERANCE_SECONDS = 30;

// otplib 13 rejects secrets shorter than 16 bytes, but otplib 12 — which
// enrolled every existing user — generated 10-byte (16-char base32) secrets.
// Verifying under the stock guardrail would lock out every already-enrolled
// account, so verification accepts the legacy length. This is not a weakening
// relative to the previous behaviour: otplib 12 both minted and accepted these.
// New enrollments are unaffected and get otplib 13's stronger 20-byte default,
// so the short secrets disappear as users re-enroll.
const LEGACY_SECRET_GUARDRAILS = otp.createGuardrails({ MIN_SECRET_BYTES: 10 });

/** Symmetric key for pgcrypto encryption of the stored secret. */
function mfaKey() {
  return process.env.MFA_ENCRYPT_KEY || process.env.GUAC_ENCRYPT_KEY || null;
}

/** Generate a new base32 TOTP secret. */
function generateSecret() {
  return otp.generateSecret();
}

/** Build the otpauth:// URI an authenticator app imports (also encoded in the QR). */
function keyUri(accountName, secret) {
  return otp.generateURI({ issuer: ISSUER, label: accountName, secret });
}

/** Render an otpauth URI to a PNG data URL for inline <img src>. */
async function qrDataUrl(otpauthUri) {
  return QRCode.toDataURL(otpauthUri, { margin: 1, width: 220 });
}

/**
 * Verify a 6-digit TOTP code against a secret. Returns boolean, never throws.
 * The try/catch is load-bearing: otplib throws on a token that isn't exactly 6
 * digits and on a secret that isn't valid base32, so bad input must not escape.
 */
function verifyTotp(token, secret) {
  if (!token || !secret) return false;
  try {
    const result = otp.verifySync({
      token: String(token).trim(),
      secret,
      epochTolerance: EPOCH_TOLERANCE_SECONDS,
      guardrails: LEGACY_SECRET_GUARDRAILS,
    });
    return result.valid === true;
  } catch {
    return false;
  }
}

/**
 * Generate recovery codes. Returns { plain, stored } where:
 *   plain  — human-readable codes shown to the user ONCE (e.g. "a1b2-c3d4-e5f6")
 *   stored — JSON-serializable [{ hash, used:false }] persisted in the DB
 */
function makeRecoveryCodes(count = RECOVERY_CODE_COUNT) {
  const plain = [];
  const stored = [];
  for (let i = 0; i < count; i++) {
    const raw = crypto.randomBytes(6).toString('hex'); // 12 hex chars
    const code = `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`;
    plain.push(code);
    stored.push({ hash: bcrypt.hashSync(normalizeRecoveryCode(code), 10), used: false });
  }
  return { plain, stored };
}

/** Strip spaces/dashes and lowercase so display formatting doesn't matter on input. */
function normalizeRecoveryCode(code) {
  return String(code || '').replace(/[\s-]/g, '').toLowerCase();
}

/**
 * Check a submitted recovery code against the stored list. Returns the index of
 * the matching, unused code or -1. Caller is responsible for marking it used.
 */
function matchRecoveryCode(code, stored) {
  const norm = normalizeRecoveryCode(code);
  if (!norm || !Array.isArray(stored)) return -1;
  for (let i = 0; i < stored.length; i++) {
    const entry = stored[i];
    if (entry && !entry.used && bcrypt.compareSync(norm, entry.hash)) return i;
  }
  return -1;
}

module.exports = {
  ISSUER,
  RECOVERY_CODE_COUNT,
  mfaKey,
  generateSecret,
  keyUri,
  qrDataUrl,
  verifyTotp,
  makeRecoveryCodes,
  normalizeRecoveryCode,
  matchRecoveryCode,
};
