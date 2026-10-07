/**
 * ============================================================================
 * INCIDENT PROJECTION — the three layers that keep the key off the student page
 * ============================================================================
 * A `cybercore_incident_run` row contains, in plain columns, everything the
 * exercise is asking the student to work out: which technique fired
 * (`technique_id`), which tactic (`tactic_id`), which scripted chain
 * (`chain_key`), which client scenario (`scenario_id`, `scenario_ref`), the
 * compiled attack itself (`playbook`), and the graded truth (`answer_key`).
 *
 * One `SELECT *` on a student route ends the exercise for the whole class, in
 * one request, with no error and no log line. So there are three independent
 * layers, and each of them is enough on its own:
 *
 *   1. THIS FILE — a WHITELIST. Every student-facing object is BUILT NEW from a
 *      fixed key list. It is never a copy of the row with the dangerous fields
 *      deleted, because `delete row.answer_key` is correct exactly until
 *      somebody adds a twelfth private column and does not think to delete that
 *      one too. A whitelist fails CLOSED on a schema change; a blacklist fails
 *      open, silently, at exactly the moment the schema grows.
 *
 *   2. COLUMN-LIST SELECTS — `STUDENT_RUN_COLUMNS` below, the
 *      `utils/tickets.js` TICKET_COLUMNS precedent. The private columns never
 *      leave Postgres on a student path at all, so a projection bug is not a
 *      disclosure, it is a missing field.
 *
 *   3. THE RELEASE GATE — until an instructor releases a run, a student sees
 *      only their own submissions: no verdicts, no points, and NO TECHNIQUE
 *      COUNT. The count is the non-obvious one. "There are six" is a hint, and
 *      a good one: it tells a student when to stop hunting, which is most of
 *      the skill being taught.
 *
 * And a fourth, procedural: test/incident-answer-key-leak.test.js is a
 * source-text gate over the student-facing handlers.
 *
 * WHY `catalog_version` IS PRIVATE, since it looks harmless
 * ----------------------------------------------------------------------------
 * It names the exact log-generator build the images run. cle/routes/attacks.js
 * already treats the catalog as private for that reason ("Static for the life
 * of the process, but private"). A student who can read it can diff two runs,
 * and can look up the build to enumerate what it is capable of emitting.
 *
 * 404, NEVER 403, ON SOMEONE ELSE'S RUN
 * ----------------------------------------------------------------------------
 * Every student route resolves a run through "your lane's scope only" and
 * returns the SAME 404 for "no such run" and "not your run". A 403 confirms the
 * run exists, which across a class of thirty is an enumerable oracle for how
 * many exercises are running and when. cle/routes/attacks.js documents the same
 * rule for its own :runId handlers.
 * ============================================================================
 */

'use strict';

/**
 * THE WHITELIST. Eight keys, and everything absent is absent on purpose:
 *
 *   technique_id, tactic_id, chain_key   the selection — literally the answer
 *   scenario_id, scenario_ref            same, for the CiAB arm, plus the
 *                                        client's own threat-scenario text
 *   playbook                             the compiled attack, verbatim
 *   answer_key                           the graded truth
 *   catalog_version                      see the header
 *   launched_by, error, event_group_id   staff operational detail
 *   duration_seconds, speed, lead_seconds
 *                                        how long and how fast — a student who
 *                                        knows the run is 30 minutes long knows
 *                                        when to stop looking
 *
 * `status` and `scheduled_start_at` ARE included: a student has to know whether
 * the incident has happened yet, and "it started at 10:05" is the premise of
 * the exercise, not a hint about its content.
 */
const STUDENT_RUN_KEYS = Object.freeze([
  'run_id',
  'scope_type',
  'scope_id',
  'status',
  'mode',
  'scheduled_start_at',
  'finished_at',
  'engine',
]);

/**
 * Layer 2, the SQL half. Mirrors STUDENT_RUN_KEYS exactly.
 *
 * This is the ONLY column list in this file, and that is deliberate. The staff
 * lists live beside the queries that use them, in src/incident/board.js,
 * because they necessarily NAME the private columns — and
 * test/incident-answer-key-leak.test.js gates those names out of every
 * student-facing file, this one included. A file that holds both lists cannot
 * be gated at all.
 *
 * The `r.` prefix is deliberate and so is the absence of `r.*` anywhere in this
 * file: the leak gate greps for that string, and a column list that starts
 * agreeing with a star select is a column list that stopped doing anything.
 */
const STUDENT_RUN_COLUMNS = `
  r.run_id, r.scope_type, r.scope_id, r.status, r.mode,
  r.scheduled_start_at, r.finished_at, r.engine
`;

/**
 * A run, as a student may see it.
 *
 * Builds a NEW object. Never mutates, never deletes, never spreads the row.
 * `undefined` for an absent key rather than throwing, so a caller that passes a
 * partial row (a JOIN that selected fewer columns) gets a smaller object rather
 * than a 500 — the failure mode of this function must be "less data", always.
 */
function projectRunForStudent(row) {
  if (!row) return null;
  const out = {};
  for (const key of STUDENT_RUN_KEYS) out[key] = row[key];
  return out;
}

/** Same discipline, applied to a list. */
function projectRunsForStudent(rows) {
  return (rows || []).map(projectRunForStudent);
}

/**
 * One of the student's own findings.
 *
 * PRE-RELEASE this returns their submission and nothing else — `verdict` and
 * `points` are null, not absent, so the page renders "submitted" rather than
 * an empty cell it has to guess the meaning of.
 *
 * POST-RELEASE it adds the EFFECTIVE verdict (an instructor override beats the
 * scorer) and `auto_note`, which is where the defensible-miss explanation
 * lives and is written to be read by the student.
 *
 * `override_note` is NEVER included, at either stage. It is the
 * ciab_module.instructor_notes precedent: a field staff write in the
 * expectation that the student cannot read it.
 */
function projectFindingForStudent(row, opts) {
  if (!row) return null;
  const released = !!(opts && opts.released);
  const out = {
    finding_id: row.finding_id,
    run_id: row.run_id,
    kind: row.kind,
    technique_id: row.technique_id,
    observed_at: row.observed_at,
    ioc_type: row.ioc_type,
    ioc_value: row.ioc_value,
    title: row.title,
    narrative: row.narrative,
    evidence: row.evidence,
    source_stack: row.source_stack,
    alert_rule_id: row.alert_rule_id,
    alert_doc_id: row.alert_doc_id,
    submitted_at: row.submitted_at,
    withdrawn_at: row.withdrawn_at,
    verdict: null,
    points: null,
    matched_key: null,
    note: null,
    released,
  };
  if (!released) return out;
  out.verdict = row.override_verdict || row.auto_verdict || null;
  out.points = row.override_points != null
    ? Number(row.override_points)
    : (row.auto_points != null ? Number(row.auto_points) : null);
  out.matched_key = row.auto_matched_key || null;
  out.note = row.auto_note || null;
  return out;
}

/** A finding for staff: the row as it is, minus nothing. */
function projectFindingForStaff(row) {
  return row || null;
}

/**
 * The score, gated.
 *
 * UNRELEASED returns counts of what the student has SUBMITTED and nothing
 * derived from the key. Note what is missing and why: `techniques_total`. It is
 * the single most valuable leak on this page — a student who knows the answer
 * is six stops at six — so it does not appear until release even though it
 * reveals no technique id at all.
 *
 * @param {object|null} row  a cybercore_incident_score row, or null if never scored
 * @param {{findings:number, iocs:number, timeline:number}} submitted
 */
function projectScoreForStudent(row, submitted) {
  const counts = submitted || { findings: 0, iocs: 0, timeline: 0 };
  if (!row || row.released !== true) {
    return {
      released: false,
      submitted: {
        findings: counts.findings || 0,
        iocs: counts.iocs || 0,
        timeline: counts.timeline || 0,
      },
    };
  }
  return {
    released: true,
    released_at: row.released_at,
    submitted: {
      findings: counts.findings || 0,
      iocs: counts.iocs || 0,
      timeline: counts.timeline || 0,
    },
    techniques_total: row.techniques_total,
    techniques_found: row.techniques_found,
    techniques_missed: row.techniques_missed,
    iocs_total: row.iocs_total,
    iocs_found: row.iocs_found,
    false_positives: row.false_positives,
    timeline_score: row.timeline_score == null ? null : Number(row.timeline_score),
    first_detection_at: row.first_detection_at,
    ttd_seconds: row.ttd_seconds,
    // The student sees the FINAL number only. `auto_points` beside it would
    // expose every instructor adjustment as a subtraction to argue about, and
    // an override is a judgement, not a correction to be audited by its subject.
    points: row.final_points == null ? null : Number(row.final_points),
  };
}

module.exports = {
  STUDENT_RUN_KEYS,
  STUDENT_RUN_COLUMNS,
  projectRunForStudent,
  projectRunsForStudent,
  projectFindingForStudent,
  projectFindingForStaff,
  projectScoreForStudent,
};
