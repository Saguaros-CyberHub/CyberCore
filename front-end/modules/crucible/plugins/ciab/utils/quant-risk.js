/**
 * quant-risk.js — Quantitative risk helpers for student training.
 *
 * Provides:
 *   - FAIR-lite Monte Carlo simulation (Loss Event Frequency × Loss Magnitude
 *     with triangular distributions, configurable iterations).
 *   - ALE / SLE / ARO calculator (the formula students will see on
 *     Security+ / CISSP / CRISC).
 *   - OWASP Risk Rating Methodology factor rollup.
 *
 * All pure functions — no DB, no IO. Server-side so we can pre-compute
 * answer-key results and store the LEC chart data in the finding row.
 */

// ─── Triangular distribution sample ─────────────────────────────────────
// Standard inverse-CDF sampling from a triangular distribution.
// Min, mode, max — the three numbers an SME provides without statistical
// training. Returns one random sample.
function triangular(min, mode, max) {
  if (max <= min) return min;
  if (mode < min) mode = min;
  if (mode > max) mode = max;
  const u = Math.random();
  const fc = (mode - min) / (max - min);
  if (u < fc) {
    return min + Math.sqrt(u * (max - min) * (mode - min));
  } else {
    return max - Math.sqrt((1 - u) * (max - min) * (max - mode));
  }
}

// ─── FAIR-lite Monte Carlo ──────────────────────────────────────────────
/**
 * Run N iterations of LEF × LM and return the loss distribution.
 *
 * @param {object} input
 *   lef: { min, mode, max }      Loss Event Frequency — events per year
 *   lm:  { min, mode, max }      Loss Magnitude per event — dollars
 *   iterations: 5000             (default — sufficient for SMB illustration)
 *
 * @returns {object}
 *   ale_mean: average annual loss
 *   ale_p10, ale_median, ale_p90: percentile values
 *   lec_data: [{ loss_threshold_usd, probability_exceeding }] for the
 *             Loss Exceedance Curve chart.
 */
function fairMonteCarlo({ lef, lm, iterations = 5000 }) {
  if (!lef || !lm) return null;
  if (lef.max <= 0 || lm.max <= 0) return null;

  const annualLosses = [];
  for (let i = 0; i < iterations; i++) {
    // Sample frequency (events/year, can be fractional)
    const freq = triangular(lef.min, lef.mode, lef.max);
    // Sample one magnitude per event (we use a single sample per year — for
    // a more rigorous model you'd sample N events and sum, but this is the
    // standard FAIR-lite shortcut that retains the distribution shape).
    const mag = triangular(lm.min, lm.mode, lm.max);
    annualLosses.push(freq * mag);
  }
  annualLosses.sort((a, b) => a - b);

  const mean   = annualLosses.reduce((s, v) => s + v, 0) / iterations;
  const pctile = p => annualLosses[Math.min(iterations - 1, Math.floor(iterations * p))];
  const p10    = pctile(0.10);
  const median = pctile(0.50);
  const p90    = pctile(0.90);
  const max    = annualLosses[iterations - 1];

  // Loss Exceedance Curve: for each loss threshold, what fraction of
  // iterations exceeded it? Generate ~30 logarithmic threshold steps.
  const lec = [];
  const minThreshold = Math.max(1, p10);
  const maxThreshold = Math.max(p90 * 1.2, max);
  const steps = 30;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    const threshold = Math.exp(Math.log(minThreshold) + t * (Math.log(maxThreshold) - Math.log(minThreshold)));
    const exceeded = annualLosses.filter(v => v >= threshold).length;
    lec.push({
      loss_threshold_usd: Math.round(threshold),
      probability_exceeding: exceeded / iterations
    });
  }

  return {
    ale_mean:   Math.round(mean),
    ale_p10:    Math.round(p10),
    ale_median: Math.round(median),
    ale_p90:    Math.round(p90),
    ale_max:    Math.round(max),
    iterations,
    inputs: { lef, lm },
    lec_data: lec
  };
}

// ─── Classic ALE/SLE/ARO ───────────────────────────────────────────────
/**
 * Single Loss Expectancy = Asset Value × Exposure Factor
 * Annualized Loss Expectancy = SLE × Annualized Rate of Occurrence
 *
 * This is the formula tested on Security+ / CISSP / CISA.
 *
 * @param {object} input
 *   asset_value_usd: dollar value of the asset
 *   exposure_factor: 0.0 - 1.0 (fraction of asset value lost in one event)
 *   aro: events per year (can be fractional, e.g. 0.25 = once every 4 years)
 *
 * @returns {object} { sle, ale, breakdown }
 */
function classicAleSleAro({ asset_value_usd, exposure_factor, aro }) {
  const av  = Number(asset_value_usd) || 0;
  const ef  = Math.max(0, Math.min(1, Number(exposure_factor) || 0));
  const aroN = Math.max(0, Number(aro) || 0);
  const sle = av * ef;
  const ale = sle * aroN;
  return {
    sle: Math.round(sle),
    ale: Math.round(ale),
    breakdown: {
      asset_value_usd: av,
      exposure_factor: ef,
      aro: aroN,
      formula_sle: 'SLE = AV × EF',
      formula_ale: 'ALE = SLE × ARO'
    }
  };
}

// ─── OWASP Risk Rating Methodology ──────────────────────────────────────
// Each factor is 0-9. Likelihood and Impact each have 8 factors. The
// methodology averages the 8 within each side, then maps to LOW/MEDIUM/
// HIGH/CRITICAL via a 4x4 matrix.

const OWASP_LIKELIHOOD_FACTORS = [
  'skill_level',          // 1=security pros, 3=network/programming, 5=advanced computer user, 6=some technical, 9=no technical skills
  'motive',               // 1=low/no reward, 4=possible reward, 9=high reward
  'opportunity',          // 0=full access/expensive resources required, 4=special access/resources required, 7=some access/resources required, 9=no access/resources required
  'size',                 // 2=developers/sysadmins, 4=intranet users, 5=partners, 6=authenticated users, 9=anonymous internet users
  'ease_of_discovery',    // 1=practically impossible, 3=difficult, 7=easy, 9=automated tools available
  'ease_of_exploit',      // 1=theoretical, 3=difficult, 5=easy, 9=automated tools available
  'awareness',            // 1=unknown, 4=hidden, 6=obvious, 9=public knowledge
  'intrusion_detection'   // 1=active detection in app, 3=logged and reviewed, 8=logged without review, 9=not logged
];

const OWASP_IMPACT_FACTORS = [
  'loss_of_confidentiality',  // 2=minimal non-sensitive, 6=minimal critical/extensive non-sensitive, 7=extensive critical, 9=all data
  'loss_of_integrity',         // 1=minimal slightly corrupt, 5=extensive slightly/minimal seriously, 7=extensive seriously, 9=all data totally
  'loss_of_availability',      // 1=minimal secondary services, 5=minimal primary/extensive secondary, 7=extensive primary, 9=all services lost
  'loss_of_accountability',    // 1=fully traceable, 7=possibly traceable, 9=completely anonymous
  'financial_damage',          // 1=less than cost to fix, 3=minor effect on annual profit, 7=significant effect, 9=bankruptcy
  'reputation_damage',         // 1=minimal damage, 4=loss of major accounts, 5=loss of goodwill, 9=brand damage
  'non_compliance',            // 2=minor violation, 5=clear violation, 7=high profile violation, 9=jail/major penalty
  'privacy_violation'          // 3=one individual, 5=hundreds, 7=thousands, 9=millions
];

function owaspAvg(factors, fieldList) {
  if (!factors) return null;
  let sum = 0; let n = 0;
  for (const f of fieldList) {
    const v = Number(factors[f]);
    if (!Number.isFinite(v)) continue;
    sum += v; n++;
  }
  return n > 0 ? (sum / n) : null;
}

function owaspBand(score) {
  if (score == null) return null;
  if (score < 3) return 'LOW';
  if (score < 6) return 'MEDIUM';
  if (score < 9) return 'HIGH';
  return 'CRITICAL';
}

// 4x4 OWASP combined-severity matrix
const OWASP_MATRIX = {
  'LOW-LOW':       'NOTE',
  'LOW-MEDIUM':    'LOW',
  'LOW-HIGH':      'MEDIUM',
  'LOW-CRITICAL':  'HIGH',
  'MEDIUM-LOW':    'LOW',
  'MEDIUM-MEDIUM': 'MEDIUM',
  'MEDIUM-HIGH':   'HIGH',
  'MEDIUM-CRITICAL':'CRITICAL',
  'HIGH-LOW':      'MEDIUM',
  'HIGH-MEDIUM':   'HIGH',
  'HIGH-HIGH':     'CRITICAL',
  'HIGH-CRITICAL': 'CRITICAL',
  'CRITICAL-LOW':       'HIGH',
  'CRITICAL-MEDIUM':    'CRITICAL',
  'CRITICAL-HIGH':      'CRITICAL',
  'CRITICAL-CRITICAL':  'CRITICAL'
};

/**
 * Compute the OWASP severity rating from decomposed factors.
 * @param {object} factors — { skill_level, motive, ..., privacy_violation }
 * @returns {object} { likelihood_score, impact_score, likelihood_band,
 *                     impact_band, severity }
 */
function owaspRollup(factors) {
  const lScore = owaspAvg(factors, OWASP_LIKELIHOOD_FACTORS);
  const iScore = owaspAvg(factors, OWASP_IMPACT_FACTORS);
  const lBand = owaspBand(lScore);
  const iBand = owaspBand(iScore);
  return {
    likelihood_score:   lScore == null ? null : Math.round(lScore * 10) / 10,
    impact_score:       iScore == null ? null : Math.round(iScore * 10) / 10,
    likelihood_band:    lBand,
    impact_band:        iBand,
    severity:           (lBand && iBand) ? OWASP_MATRIX[`${lBand}-${iBand}`] : null
  };
}

module.exports = {
  triangular,
  fairMonteCarlo,
  classicAleSleAro,
  owaspRollup,
  OWASP_LIKELIHOOD_FACTORS,
  OWASP_IMPACT_FACTORS
};
