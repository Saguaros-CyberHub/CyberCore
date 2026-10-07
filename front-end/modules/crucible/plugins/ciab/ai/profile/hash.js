/**
 * ai/profile/hash.js — deterministic per-run randomness.
 * ============================================================================
 * Extracted from prompts.js so org-sizing.js can hash without requiring
 * prompts.js (which requires org-sizing.js — that would be a cycle).
 *
 * Everything downstream of a profile MUST be reproducible from run_id alone.
 * Before this module existed, `pickEmployeeCount` and the public IP used
 * Math.random() while every other dimension was hashed, so regenerating a
 * profile from the same seed produced a different company. That made
 * paper-vs-lane parity impossible to assert by regeneration.
 *
 * Rule: no Math.random() and no Date.now() anywhere in the generation path.
 */

/** FNV-ish 32-bit string hash. Stable across processes and Node versions. */
function hashStr(s, salt = '') {
  const x = String(s || '') + '|' + salt;
  let h = 0;
  for (let i = 0; i < x.length; i++) h = ((h * 31) + x.charCodeAt(i)) >>> 0;
  return h;
}

/** Deterministic float in [0,1) for this run + salt. */
function hashFloat(runId, salt) {
  return hashStr(runId, salt) / 4294967296;
}

/** Deterministic integer in [min,max] inclusive. */
function hashInt(runId, salt, min, max) {
  if (max <= min) return min;
  return min + (hashStr(runId, salt) % (max - min + 1));
}

/**
 * Deterministic LOG-uniform integer in [min,max].
 *
 * Real organization sizes are log-skewed — most orgs sit near the low end of
 * any band. A uniform draw over e.g. [25,200] puts the median at 112, which is
 * a mid-market company, not the small org this course is about. Log-uniform
 * puts it near 70 and makes genuinely small orgs common.
 */
function hashLogInt(runId, salt, min, max) {
  const lo = Math.max(1, min);
  const hi = Math.max(lo, max);
  if (hi === lo) return lo;
  const t = hashFloat(runId, salt);
  return Math.round(Math.exp(Math.log(lo) + t * (Math.log(hi) - Math.log(lo))));
}

/** Deterministic weighted coin. `pct` is the chance of true, 0-100. */
function hashCoin(runId, salt, pct) {
  return (hashStr(runId, 'coin:' + salt) % 100) < pct;
}

/** Deterministic pick from an array. */
function hashPick(runId, salt, list) {
  if (!Array.isArray(list) || list.length === 0) return undefined;
  return list[hashStr(runId, salt) % list.length];
}

module.exports = { hashStr, hashFloat, hashInt, hashLogInt, hashCoin, hashPick };
