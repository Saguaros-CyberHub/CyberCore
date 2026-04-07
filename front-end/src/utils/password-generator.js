/**
 * ============================================================================
 * PASSWORD GENERATOR
 * Generates random passwords for group-deployed accounts
 * ============================================================================
 */

const crypto = require('crypto');

const UPPER = 'ABCDEFGHJKLMNPQRSTUVWXYZ';     // no I, O (ambiguous)
const LOWER = 'abcdefghjkmnpqrstuvwxyz';       // no i, l, o (ambiguous)
const DIGITS = '23456789';                       // no 0, 1 (ambiguous)
const SYMBOLS = '!@#$%&*';

/**
 * Generate a random password that meets the app's password policy:
 * - Min 12 chars
 * - At least 1 uppercase, 1 lowercase, 1 digit, 1 symbol
 * @param {number} length - Password length (default 14)
 * @returns {string}
 */
function generatePassword(length = 14) {
  const all = UPPER + LOWER + DIGITS + SYMBOLS;

  // Guarantee at least one of each required character class
  const required = [
    UPPER[crypto.randomInt(UPPER.length)],
    LOWER[crypto.randomInt(LOWER.length)],
    DIGITS[crypto.randomInt(DIGITS.length)],
    SYMBOLS[crypto.randomInt(SYMBOLS.length)]
  ];

  // Fill remaining length with random chars from the full set
  const remaining = length - required.length;
  for (let i = 0; i < remaining; i++) {
    required.push(all[crypto.randomInt(all.length)]);
  }

  // Shuffle using Fisher-Yates
  for (let i = required.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    [required[i], required[j]] = [required[j], required[i]];
  }

  return required.join('');
}

module.exports = { generatePassword };
