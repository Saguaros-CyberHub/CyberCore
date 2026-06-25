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
const { authenticator } = require('otplib');
const QRCode = require('qrcode');

// Allow ±1 time-step (±30s) of clock drift between server and authenticator.
authenticator.options = { window: 1 };

const ISSUER = process.env.MFA_ISSUER || 'CyberHub';
const RECOVERY_CODE_COUNT = 10;

/** Symmetric key for pgcrypto encryption of the stored secret. */
function mfaKey() {
  return process.env.MFA_ENCRYPT_KEY || process.env.GUAC_ENCRYPT_KEY || null;
}

/** Generate a new base32 TOTP secret. */
function generateSecret() {
  return authenticator.generateSecret();
}

/** Build the otpauth:// URI an authenticator app imports (also encoded in the QR). */
function keyUri(accountName, secret) {
  return authenticator.keyuri(accountName, ISSUER, secret);
}

/** Render an otpauth URI to a PNG data URL for inline <img src>. */
async function qrDataUrl(otpauthUri) {
  return QRCode.toDataURL(otpauthUri, { margin: 1, width: 220 });
}

/** Verify a 6-digit TOTP code against a secret. Returns boolean, never throws. */
function verifyTotp(token, secret) {
  if (!token || !secret) return false;
  try {
    return authenticator.verify({ token: String(token).trim(), secret });
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
