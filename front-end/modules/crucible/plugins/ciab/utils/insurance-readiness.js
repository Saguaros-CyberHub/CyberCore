/**
 * insurance-readiness.js — Cyber-insurance underwriting scorecard.
 *
 * Mirrors the 12-control questionnaire that modern cyber-insurance
 * carriers (Coalition, At-Bay, Cowbell, Resilience) use during
 * underwriting. Each control: yes / partial / no / unknown.
 *
 * Score: weighted points (max 100). Tier mapping:
 *   ≥85  → Insurable      (standard market)
 *   65-84 → Conditional   (sub-standard / restricted coverage)
 *   45-64 → Restricted    (only specialist carriers)
 *    <45 → Uninsurable    (carrier declination expected)
 */

// Weight per control (sums to 100).
// MFA controls dominate because they're the single largest predictor of
// loss-event frequency in real underwriting data (Coalition Cyber Claims
// Report 2024 cites MFA as preventing 67% of would-be incidents).
const WEIGHTS = {
  mfa_email:           12,
  mfa_remote:          12,
  mfa_privileged:      14,
  mfa_cloud:           10,
  edr_coverage_pct:    10,    // graded 0-100% on its own scale
  immutable_backups:    8,
  tested_restore_12mo:  6,
  ir_plan_written:      6,
  tabletop_12mo:        5,
  pam_in_place:         6,
  security_training:    6,
  vuln_scanning:        5
};

const TOTAL_WEIGHT = Object.values(WEIGHTS).reduce((s, v) => s + v, 0); // sanity: 100

function fractionFor(value) {
  if (value === 'yes')     return 1.0;
  if (value === 'partial') return 0.5;
  if (value === 'no')      return 0.0;
  return 0.0; // 'unknown' treated as 'no' by underwriters
}

function tierFor(score) {
  if (score >= 85) return 'Insurable';
  if (score >= 65) return 'Conditional';
  if (score >= 45) return 'Restricted';
  return 'Uninsurable';
}

function scoreReadiness(row) {
  let score = 0;
  // 11 simple yes/partial/no items
  for (const k of Object.keys(WEIGHTS)) {
    if (k === 'edr_coverage_pct') continue;
    score += WEIGHTS[k] * fractionFor(row[k]);
  }
  // EDR coverage is graded on the percentage
  const edrPct = Math.max(0, Math.min(100, Number(row.edr_coverage_pct) || 0));
  score += WEIGHTS.edr_coverage_pct * (edrPct / 100);
  const rounded = Math.round(score);
  return {
    score: rounded,
    tier: tierFor(rounded),
    breakdown: Object.fromEntries(Object.keys(WEIGHTS).map(k => [k, {
      value: k === 'edr_coverage_pct' ? edrPct : row[k],
      weight: WEIGHTS[k],
      points: k === 'edr_coverage_pct'
        ? Math.round(WEIGHTS[k] * (edrPct / 100))
        : Math.round(WEIGHTS[k] * fractionFor(row[k]))
    }]))
  };
}

/**
 * Derive an answer-key readiness scorecard from an AI profile.
 * Maps declared IT controls onto the underwriting questionnaire.
 */
function deriveReadinessFromProfile(ctx) {
  const it = ctx.it || {};
  const ra = it.remote_access || {};
  const ep = it.endpoint_protection || {};
  const bk = it.backups || {};

  // MFA mapping — based on declared remote_access.mfa
  let mfaAll = 'no';
  if (ra.mfa === 'All') mfaAll = 'yes';
  else if (ra.mfa === 'ExecOnly') mfaAll = 'partial';

  return {
    mfa_email:        mfaAll,
    mfa_remote:       mfaAll,
    mfa_privileged:   mfaAll,
    mfa_cloud:        mfaAll,
    edr_coverage_pct: Number(ep.coverage_percent || 0),
    immutable_backups:   bk.immutability ? 'yes' : 'no',
    tested_restore_12mo: (() => {
      const rt = String(bk.restore_tests || '').toLowerCase();
      if (rt.includes('quarterly') || rt.includes('monthly')) return 'yes';
      if (rt.includes('annual'))  return 'partial';
      return 'no';
    })(),
    // The rest aren't declared in the profile — assume sensible defaults
    // for an answer-key based on the posture archetype (caller may override)
    ir_plan_written:   'no',     // most SMBs don't have one
    tabletop_12mo:     'no',
    pam_in_place:      'no',
    security_training: 'partial',
    vuln_scanning:     'partial'
  };
}

module.exports = {
  WEIGHTS, TOTAL_WEIGHT,
  scoreReadiness, tierFor,
  deriveReadinessFromProfile
};
