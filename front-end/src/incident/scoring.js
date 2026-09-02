/**
 * ============================================================================
 * INCIDENT SCORING — pure, re-runnable, and it never touches the database
 * ============================================================================
 * Takes the run's answer key and the student's banked claims; returns a verdict
 * per claim and one roll-up. Persisting any of that is src/incident/board.js's
 * job, and keeping the two apart is what makes this file testable without a
 * Postgres, a lane, or a clock.
 *
 * IDEMPOTENT BY CONSTRUCTION. Same key + same findings = same output, every
 * time. That is not a nicety: the scorer is re-run whenever a key is recompiled
 * or a bug is fixed, and a scorer that drifts between runs turns "regrade the
 * class" into "regrade the class and then defend thirty changed numbers".
 *
 * THE FOUR RULES, AND THE ONE THAT IS EASY TO GET WRONG
 * ----------------------------------------------------------------------------
 *   technique hit      +1.0   the id is in the key
 *   IOC hit            +0.5   case-insensitive EXACT match on the value
 *   false positive     -0.5   claimed, in neither the key nor the floor
 *   DEFENSIBLE MISS     0.0   claimed, and it IS in the floor's benign tagged
 *                             set — verdict 'partial', WITH A NOTE
 *
 * The defensible miss is the one that matters, and it is not generosity. The
 * benign floor deliberately tags 4-20% of its own ordinary events with real
 * MITRE technique ids, precisely so that "has a MITRE tag" is not itself the
 * answer key (test/loggen-playbooks.test.js enforces that band). A student who
 * reports T1110 because they found brute-force-shaped traffic in the floor
 * found EXACTLY WHAT WAS PLANTED FOR THEM. Penalising that teaches them not to
 * look, which is the opposite of the exercise — and it would make the floor's
 * whole design self-defeating. So: zero points, no penalty, and the reason is
 * returned to the student in `auto_note` rather than left in a comment here.
 *
 * The run total is FLOORED AT 0. Without it, a student who guessed widely and
 * then found something real ends below a student who submitted nothing, and the
 * gradebook says the second student did better.
 *
 * TIME TO DETECT — the thing that is broken and must not be used
 * ----------------------------------------------------------------------------
 * TTD is min(submitted_at of a HIT) - run.scheduled_start_at, clamped at 0.
 *
 * NEVER a document's `@timestamp`, and this is not a style preference: cc-emit
 * writes its own `timestamp` field, the ndjson parser lands it as
 * `loggen.timestamp`, the Kibana data view keys on `@timestamp` — which is
 * INGEST time — and there is no timestamp processor anywhere in the agent
 * config. Backdating does not work in this stack. A TTD measured against a
 * document clock would look plausible and be meaningless.
 *
 * `observed_at` is the student's own assertion about when the activity
 * happened. It orders the timeline; it is not evidence of when they detected
 * anything, and a student who back-dates it would otherwise score a negative
 * TTD.
 *
 * TIMELINE — Kendall tau, over the CORRECT claims only
 * ----------------------------------------------------------------------------
 * Rank correlation between the order the student asserts and the order the key
 * records. Computed over the subset of their timeline entries whose technique
 * IS in the key: an uncorrelated entry is EXCLUDED rather than counted as an
 * inversion, because it has already been penalised once as a false positive and
 * charging it again to the ordering score is double jeopardy for one mistake.
 *
 * Fewer than two correlated entries gives NULL, not zero. A rank correlation
 * over one point is undefined, and 0 reads as "ordered no better than chance" —
 * a claim about a student nobody measured.
 *
 * NO ANSWER KEY IS NOT A ZERO
 * ----------------------------------------------------------------------------
 * A run with an empty key (a Caldera run, or one whose compile failed) grades
 * every claim 'unscored' and says so. The tempting alternative — treat an empty
 * key as "nothing was in the attack" — marks every correct answer a false
 * positive and hands the class negative scores for a server-side bug.
 * ============================================================================
 */

'use strict';

const { ANSWER_KEY_VERSION } = require('./answer-key');

/** The point values. One place, so the tests and the UI can both read them. */
const POINTS = Object.freeze({
  TECHNIQUE_HIT: 1.0,
  IOC_HIT: 0.5,
  FALSE_POSITIVE: -0.5,
  PARTIAL: 0,
  UNSCORED: 0,
});

/** Student-facing. This text is the whole point of the defensible-miss rule. */
const DEFENSIBLE_MISS_NOTE =
  'That label also occurs in ordinary traffic on this network, so finding it is '
  + 'not a mistake — it just is not part of this incident. No points either way.';

const NO_KEY_NOTE =
  'This run has no compiled answer key, so nothing was auto-graded. '
  + 'Your instructor scores it by hand.';

const DUPLICATE_NOTE = 'Already claimed on this run — counted once.';

/**
 * Thrown when the stored key was written by a NEWER build than this one.
 *
 * Refusing is the safe direction. A shape this build does not understand read
 * with this build's rules produces numbers that look fine and are wrong, and
 * the only place that surfaces is a student's grade.
 */
class AnswerKeyVersionError extends Error {
  constructor(found) {
    super(
      `incident answer key version ${found} is newer than this build understands `
      + `(${ANSWER_KEY_VERSION}). Refusing to score rather than grade against a shape `
      + 'whose meaning may have changed.'
    );
    this.name = 'AnswerKeyVersionError';
    this.code = 'ANSWER_KEY_VERSION';
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const normTechnique = (v) => String(v == null ? '' : v).trim().toUpperCase();
const normValue = (v) => String(v == null ? '' : v).trim().toLowerCase();

/** Milliseconds since epoch for a Date, an ISO string or null. */
function ms(v) {
  if (!v) return null;
  const t = v instanceof Date ? v.getTime() : Date.parse(String(v));
  return Number.isFinite(t) ? t : null;
}

/** Round to 2dp so a float sum never renders as 1.4000000000000001. */
const round2 = (n) => Math.round(Number(n) * 100) / 100;

/**
 * Kendall tau-a between two rankings of the same items.
 *
 * @param {string[]} claimed the student's order
 * @param {string[]} truth   the key's order; every element of `claimed` must be
 *                           present, which the caller guarantees by filtering
 * @returns {number|null} tau in [-1, 1], or null for fewer than two items
 */
function kendallTau(claimed, truth) {
  const n = claimed.length;
  if (n < 2) return null;
  const rank = new Map();
  truth.forEach((id, i) => rank.set(id, i));
  let concordant = 0;
  let discordant = 0;
  for (let i = 0; i < n; i += 1) {
    for (let j = i + 1; j < n; j += 1) {
      const a = rank.get(claimed[i]);
      const b = rank.get(claimed[j]);
      // Ties in the KEY (two techniques whose first event lands on the same
      // second) are neither concordant nor discordant. Counting them either way
      // would make the score depend on a tie-break the student cannot see.
      if (a === b) continue;
      if (a < b) concordant += 1; else discordant += 1;
    }
  }
  const pairs = concordant + discordant;
  if (pairs === 0) return null;
  return (concordant - discordant) / pairs;
}

/** Points an OVERRIDE verdict is worth, which depends on what was claimed. */
function verdictPoints(kind, verdict) {
  switch (verdict) {
    case 'hit':
    case 'true_positive':
      return kind === 'ioc' ? POINTS.IOC_HIT : POINTS.TECHNIQUE_HIT;
    case 'false_positive':
      return POINTS.FALSE_POSITIVE;
    case 'partial':
    case 'benign_true_positive':
      return POINTS.PARTIAL;
    default:
      return POINTS.UNSCORED;
  }
}

/**
 * The verdict and points that actually count, once an instructor has had their
 * say. Precedence, most specific first:
 *
 *   1. override_points  an explicit number beats everything, including its own
 *                       verdict — "this is worth 0.25" is a thing an instructor
 *                       says, and it must not be silently rounded to a bucket.
 *   2. override_verdict re-buckets the claim; points follow from the bucket.
 *   3. auto_*           the scorer's own answer.
 */
function effective(finding, auto) {
  const verdict = finding.override_verdict || auto.auto_verdict;
  let points;
  if (finding.override_points != null && finding.override_points !== '') {
    points = Number(finding.override_points);
  } else if (finding.override_verdict) {
    points = verdictPoints(finding.kind, finding.override_verdict);
  } else {
    points = Number(auto.auto_points || 0);
  }
  return { verdict, points: Number.isFinite(points) ? points : 0 };
}

// ---------------------------------------------------------------------------
// The scorer
// ---------------------------------------------------------------------------

/**
 * Grade one student's board for one run.
 *
 * @param {object}   opts
 * @param {object}   opts.run        needs `scheduled_start_at` and nothing else
 * @param {object}   opts.answerKey  from src/incident/answer-key.js; {} is legal
 * @param {object[]} opts.findings   cybercore_incident_finding rows for ONE user
 * @param {number|null} [opts.runOverridePoints] a whole-run instructor total
 * @returns {{graded: boolean, findings: object[], score: object}}
 *   `findings[]` carries ONLY the scorer-owned columns plus finding_id, so a
 *   caller cannot accidentally write an override_* back through this path.
 */
function scoreRun(opts) {
  const o = opts || {};
  const run = o.run || {};
  const key = o.answerKey || {};
  const rows = Array.isArray(o.findings) ? o.findings.slice() : [];

  if (Number(key.version) > ANSWER_KEY_VERSION) throw new AnswerKeyVersionError(key.version);

  const keyTechniques = Array.isArray(key.techniques) ? key.techniques : [];
  const keyIocs = Array.isArray(key.iocs) ? key.iocs : [];
  const graded = keyTechniques.length > 0 || keyIocs.length > 0;

  const techniqueSet = new Set(keyTechniques.map((t) => normTechnique(t.id)));
  // The KEY's order, which is the truth the timeline is correlated against.
  const techniqueOrder = keyTechniques.map((t) => normTechnique(t.id));
  const floorTechniques = new Set((key.floor_techniques || []).map(normTechnique));
  const iocByValue = new Map();
  for (const ioc of keyIocs) iocByValue.set(normValue(ioc.value), ioc);
  const floorValues = new Set((key.floor_values || []).map(normValue));

  // Deterministic order, so "which duplicate scored" never depends on the row
  // order Postgres felt like returning. submitted_at first because the earliest
  // claim is the one the student actually made; finding_id breaks exact ties.
  rows.sort((a, b) => {
    const d = (ms(a.submitted_at) || 0) - (ms(b.submitted_at) || 0);
    return d || String(a.finding_id).localeCompare(String(b.finding_id));
  });

  const seenTechniques = new Set();
  const seenIocs = new Set();
  const scored = [];

  for (const f of rows) {
    const out = {
      finding_id: f.finding_id,
      auto_verdict: 'unscored',
      auto_points: POINTS.UNSCORED,
      auto_matched_key: null,
      auto_note: null,
    };

    if (f.withdrawn_at) {
      out.auto_note = 'Withdrawn — not scored.';
      scored.push(out);
      continue;
    }

    if (!graded) {
      out.auto_note = NO_KEY_NOTE;
      scored.push(out);
      continue;
    }

    if (f.kind === 'timeline') {
      // Deliberately worth nothing on its own. A timeline entry names a
      // technique the student has usually ALSO banked as a finding, and paying
      // for both would be +2.0 for one correct answer. Its contribution is the
      // ordering score below.
      out.auto_note = 'Ordering claim — contributes to the timeline score, not to points.';
      scored.push(out);
      continue;
    }

    if (f.kind === 'ioc') {
      const value = normValue(f.ioc_value);
      if (!value) {
        out.auto_note = 'No indicator value — nothing to match.';
      } else if (seenIocs.has(value)) {
        out.auto_note = DUPLICATE_NOTE;
      } else if (iocByValue.has(value)) {
        const hit = iocByValue.get(value);
        seenIocs.add(value);
        out.auto_verdict = 'hit';
        out.auto_points = POINTS.IOC_HIT;
        out.auto_matched_key = `${hit.type}:${hit.value}`;
      } else if (floorValues.has(value)) {
        seenIocs.add(value);
        out.auto_verdict = 'partial';
        out.auto_note = DEFENSIBLE_MISS_NOTE;
      } else {
        seenIocs.add(value);
        out.auto_verdict = 'false_positive';
        out.auto_points = POINTS.FALSE_POSITIVE;
      }
      scored.push(out);
      continue;
    }

    // 'finding' and 'alert' are both technique claims. An alert carries a
    // detection rule's own id as well, but what is GRADED is the technique the
    // student concluded from it.
    const id = normTechnique(f.technique_id);
    if (!id) {
      out.auto_note = 'No technique claimed — narrative only.';
    } else if (seenTechniques.has(id)) {
      out.auto_note = DUPLICATE_NOTE;
    } else if (techniqueSet.has(id)) {
      seenTechniques.add(id);
      out.auto_verdict = 'hit';
      out.auto_points = POINTS.TECHNIQUE_HIT;
      out.auto_matched_key = id;
    } else if (floorTechniques.has(id)) {
      seenTechniques.add(id);
      out.auto_verdict = 'partial';
      out.auto_note = DEFENSIBLE_MISS_NOTE;
    } else {
      seenTechniques.add(id);
      out.auto_verdict = 'false_positive';
      out.auto_points = POINTS.FALSE_POSITIVE;
    }
    scored.push(out);
  }

  // ── Roll-up, over EFFECTIVE verdicts so an override moves the totals ──────
  const byId = new Map(scored.map((s) => [s.finding_id, s]));
  const foundTechniques = new Set();
  const foundIocs = new Set();
  let falsePositives = 0;
  let autoSum = 0;
  let effectiveSum = 0;
  let firstHitMs = null;

  for (const f of rows) {
    const auto = byId.get(f.finding_id);
    if (!auto) continue;
    autoSum += Number(auto.auto_points || 0);
    if (f.withdrawn_at) continue;

    const eff = effective(f, auto);
    effectiveSum += eff.points;

    if (eff.verdict === 'hit' || eff.verdict === 'true_positive') {
      if (f.kind === 'ioc') foundIocs.add(normValue(f.ioc_value));
      else if (f.kind !== 'timeline') foundTechniques.add(normTechnique(f.technique_id));
      // TTD is measured from SUBMISSION, never from observed_at. See header.
      const at = ms(f.submitted_at);
      if (at != null && (firstHitMs == null || at < firstHitMs)) firstHitMs = at;
    } else if (eff.verdict === 'false_positive') {
      falsePositives += 1;
    }
  }

  // ── Timeline ─────────────────────────────────────────────────────────────
  const timelineClaims = rows
    .filter((f) => f.kind === 'timeline' && !f.withdrawn_at)
    .filter((f) => techniqueSet.has(normTechnique(f.technique_id)))
    .sort((a, b) => {
      // The student's ASSERTED order: when they say it happened, falling back
      // to when they wrote it down.
      const av = ms(a.observed_at) != null ? ms(a.observed_at) : ms(a.submitted_at);
      const bv = ms(b.observed_at) != null ? ms(b.observed_at) : ms(b.submitted_at);
      return (av || 0) - (bv || 0)
        || String(a.finding_id).localeCompare(String(b.finding_id));
    });
  const claimedOrder = [];
  for (const f of timelineClaims) {
    const id = normTechnique(f.technique_id);
    if (!claimedOrder.includes(id)) claimedOrder.push(id);
  }
  const timelineScore = kendallTau(claimedOrder, techniqueOrder);

  // ── TTD ──────────────────────────────────────────────────────────────────
  const startMs = ms(run.scheduled_start_at);
  let ttdSeconds = null;
  if (firstHitMs != null && startMs != null) {
    // Clamped at 0. A negative TTD is not a fast student, it is a clock — a
    // lane whose RTC Proxmox never resynced, or a run whose scheduled start was
    // pushed back after the fact.
    ttdSeconds = Math.max(0, Math.round((firstHitMs - startMs) / 1000));
  }

  const autoPoints = Math.max(0, round2(autoSum));
  const runOverride = o.runOverridePoints;
  const hasRunOverride = runOverride != null && runOverride !== '' && Number.isFinite(Number(runOverride));

  return {
    graded,
    findings: scored,
    score: {
      techniques_total: keyTechniques.length,
      techniques_found: foundTechniques.size,
      techniques_missed: Math.max(0, keyTechniques.length - foundTechniques.size),
      iocs_total: keyIocs.length,
      iocs_found: foundIocs.size,
      false_positives: falsePositives,
      timeline_score: timelineScore == null ? null : Math.round(timelineScore * 10000) / 10000,
      first_detection_at: firstHitMs == null ? null : new Date(firstHitMs).toISOString(),
      ttd_seconds: ttdSeconds,
      auto_points: autoPoints,
      override_points: hasRunOverride ? round2(runOverride) : null,
      // A run-level override REPLACES the total outright; that is what an
      // instructor typing a number into the gradebook means. Otherwise the
      // total is the sum of effective per-finding points, floored at 0 for the
      // reason in the header.
      final_points: hasRunOverride ? round2(runOverride) : Math.max(0, round2(effectiveSum)),
    },
  };
}

module.exports = {
  POINTS,
  DEFENSIBLE_MISS_NOTE,
  NO_KEY_NOTE,
  DUPLICATE_NOTE,
  AnswerKeyVersionError,
  kendallTau,
  verdictPoints,
  effective,
  scoreRun,
};
