/**
 * ============================================================================
 * INCIDENT BOARD — one implementation, two callers
 * ============================================================================
 * Everything the blue-team board DOES: read a run within a scope, take a
 * student's claims, run the scorer, apply an instructor's override, release.
 *
 * The two route files — cle/routes/incidents.js and ciab/routes/incidents.js —
 * are deliberately thin. They resolve WHO is asking and WHICH scope they are
 * asking about, then delegate here. That split is not tidiness: the two plugins
 * have different databases, different enrollment models and different words for
 * everything, and the one thing they must not have is two blue-team boards that
 * agree today and drift by the second bug fix. cle_attack_run's NOT NULL FK to
 * cle_course is what that drift looks like when it has finished happening.
 *
 * SCOPE POLYMORPHISM, AND THE 404
 * ----------------------------------------------------------------------------
 * A run is addressed by (scope_type, scope_id, run_id) — never by run_id alone.
 * Every read below takes the pair, so "a run in another course" and "a run that
 * does not exist" produce the same null, which the routes render as the same
 * 404. A 403 would confirm the run exists, and across a class that is an
 * enumerable oracle for how many exercises are running and when.
 *
 * WHAT A STUDENT WRITE MAY CONTAIN
 * ----------------------------------------------------------------------------
 * A whitelist, in FINDING_INPUT_KEYS, and an INSERT that names its columns. The
 * scorer-owned `auto_*` and instructor-owned `override_*` columns are not in
 * either, so a student POSTing `{auto_verdict:'hit', auto_points:99}` writes
 * nothing at all rather than grading themselves. That is a test
 * (test/incident-board-routes.test.js), not a hope.
 *
 * RE-SCORING IS NON-DESTRUCTIVE, ALWAYS
 * ----------------------------------------------------------------------------
 * scoreRun() writes exactly five columns per finding — the four `auto_*` and
 * `scored_at` — in ONE statement, and upserts the score row without touching
 * `released`, `released_at` or `released_by`. So "re-score the class after the
 * key was recompiled" cannot erase an instructor's adjudication and cannot
 * un-release a run that students are already reading.
 * ============================================================================
 */

'use strict';

const { cybercoreQuery } = require('../utils/cybercore-db');
const projection = require('./projection');
const scoring = require('./scoring');

const { STUDENT_RUN_COLUMNS } = projection;

// ---------------------------------------------------------------------------
// THE STAFF COLUMN LISTS LIVE HERE, NOT IN projection.js
//
// They necessarily NAME the private columns, and
// test/incident-answer-key-leak.test.js gates those names out of every
// student-facing file -- projection.js included, because it is required by both
// route files. A module holding both the student list and the staff list cannot
// be gated at all, so the split is what makes the gate meaningful rather than
// decorative. They stay explicit lists rather than a star for the reason
// utils/tickets.js keeps TICKET_COLUMNS: two readers that disagree about which
// columns exist is how a field ends up rendered on one page and undefined on
// the other.
// ---------------------------------------------------------------------------

/**
 * The staff read. Still an explicit list rather than a star, for the same
 * reason tickets.js keeps one: two readers that disagree about which columns
 * exist is how a field ends up rendered on one page and undefined on the other.
 *
 * The two private JSONB columns are NOT here. They are large, they are needed
 * by exactly one caller (the scorer), and a staff list endpoint that ships a
 * compiled playbook per row for thirty runs is a megabyte of response nobody
 * asked for. board.js reads them by name, one run at a time.
 */
const STAFF_RUN_COLUMNS = `
  r.run_id, r.scope_type, r.scope_id, r.scope_label, r.engine, r.launched_by,
  r.mode, r.technique_id, r.tactic_id, r.chain_key, r.scenario_id, r.scenario_ref,
  r.duration_seconds, r.speed, r.catalog_version, r.lead_seconds,
  r.scheduled_start_at, r.status, r.event_group_id, r.error,
  r.created_at, r.finished_at
`;

/** Every column of a finding. Staff see all of it; students see a projection. */
const FINDING_COLUMNS = `
  f.finding_id, f.run_id, f.target_id, f.user_id, f.kind,
  f.technique_id, f.observed_at, f.ioc_type, f.ioc_value,
  f.title, f.narrative, f.evidence,
  f.source_stack, f.alert_rule_id, f.alert_doc_id,
  f.submitted_at, f.withdrawn_at,
  f.auto_verdict, f.auto_points, f.auto_matched_key, f.auto_note, f.scored_at,
  f.override_verdict, f.override_points, f.override_note, f.override_by, f.override_at,
  f.created_at, f.updated_at
`;

const SCORE_COLUMNS = `
  s.run_id, s.user_id, s.techniques_total, s.techniques_found, s.techniques_missed,
  s.iocs_total, s.iocs_found, s.false_positives, s.timeline_score,
  s.first_detection_at, s.ttd_seconds,
  s.auto_points, s.override_points, s.final_points,
  s.released, s.released_at, s.released_by, s.scored_at
`;


const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * The same column list as FINDING_COLUMNS, unaliased, for RETURNING clauses —
 * which have no FROM and therefore no `f`. Derived rather than restated so the
 * two can never drift into disagreeing about which columns a write returns.
 */
const FINDING_RETURNING = FINDING_COLUMNS.replace(/f\./g, '');

/** Scope types the run table's CHECK allows. Rejected here rather than by pg. */
const SCOPE_TYPES = Object.freeze(['course', 'engagement']);

/**
 * The lane-ownership predicate, borrowed from the engine rather than restated.
 *
 * E2's runner.scopeLanePredicate() already decides which lanes belong to a
 * course and which to an engagement, and the two arms are NOT symmetric — the
 * engagement arm also requires `config->>'ciab' = 'true'`, because an
 * engagement id alone does not distinguish a CiAB lane from anything else that
 * might one day carry that key. A second copy here would be correct on the day
 * it was written and wrong the first time either arm changed, and the symptom
 * would be a student who owns a lane being told their run does not exist.
 * test/incident-scope.test.js pins the arms; this borrows them.
 *
 * REQUIRED LAZILY. runner.js pulls in the Proxmox client and the script
 * executor at module scope, and this module is required by two plugin route
 * files at boot — a student reading their own board should not drag the
 * dispatcher into the process to do it. One property lookup per call.
 */
let _runner = null;
function scopeLanePredicate(scopeType) {
  if (!_runner) _runner = require('./runner');
  return _runner.scopeLanePredicate(scopeType);
}

/**
 * Fields a student may set on a finding. Everything absent is absent because a
 * student setting it would be grading themselves; see the header.
 */
const FINDING_INPUT_KEYS = Object.freeze([
  'kind',
  'technique_id',
  'observed_at',
  'ioc_type',
  'ioc_value',
  'title',
  'narrative',
  'evidence',
  'source_stack',
  'alert_rule_id',
  'alert_doc_id',
]);

const FINDING_KINDS = Object.freeze(['finding', 'ioc', 'timeline', 'alert']);
const IOC_TYPES = Object.freeze(['host', 'user', 'ip', 'path', 'process', 'domain', 'hash', 'port']);
const SOURCE_STACKS = Object.freeze(['elastic', 'wazuh', 'other']);
const OVERRIDE_VERDICTS = Object.freeze([
  'hit', 'partial', 'false_positive', 'unscored', 'true_positive', 'benign_true_positive',
]);

/** A 4xx the routes render directly. Anything else is a 500 and a log line. */
class BoardError extends Error {
  constructor(status, code, message) {
    super(message);
    this.name = 'BoardError';
    this.status = status;
    this.code = code;
  }
}

const bad = (code, message) => new BoardError(400, code, message);

function assertScope(scope) {
  const type = scope && scope.scopeType;
  const id = scope && scope.scopeId;
  if (!SCOPE_TYPES.includes(type)) throw bad('BAD_SCOPE', `unknown scope type ${JSON.stringify(type)}`);
  if (!UUID_RE.test(String(id || ''))) throw bad('BAD_SCOPE', 'scope id must be a uuid');
  return { type, id: String(id) };
}

/** Trim to a length, or null. Keeps a runaway paste out of a TEXT column. */
function text(v, max) {
  if (v == null) return null;
  const s = String(v).trim();
  if (!s) return null;
  return s.length > max ? s.slice(0, max) : s;
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/**
 * One run, student-safe columns only, scoped.
 *
 * The column list is layer 2 of the projection defence: `answer_key`,
 * `playbook` and the selection columns never leave Postgres on this path, so a
 * projection bug downstream is a missing field rather than a disclosure.
 */
async function readRunForStudent(runId, scope) {
  const s = assertScope(scope);
  if (!UUID_RE.test(String(runId || ''))) return null;
  const r = await cybercoreQuery(
    `SELECT ${STUDENT_RUN_COLUMNS}
       FROM cybercore_incident_run r
      WHERE r.run_id = $1 AND r.scope_type = $2 AND r.scope_id = $3`,
    [runId, s.type, s.id]
  );
  return r.rows[0] || null;
}

/** One run, staff columns, scoped. The two large JSONB columns are not here. */
async function readRunForStaff(runId, scope) {
  const s = assertScope(scope);
  if (!UUID_RE.test(String(runId || ''))) return null;
  const r = await cybercoreQuery(
    `SELECT ${STAFF_RUN_COLUMNS}
       FROM cybercore_incident_run r
      WHERE r.run_id = $1 AND r.scope_type = $2 AND r.scope_id = $3`,
    [runId, s.type, s.id]
  );
  return r.rows[0] || null;
}

/**
 * Runs in a scope, newest first.
 *
 * `tier` picks the COLUMN LIST, not just the projection. A student list read
 * with the staff columns and projected afterwards would be correct today and a
 * disclosure the first time someone forgets the projection — so the private
 * columns do not leave Postgres on a student path at all.
 */
async function listRunsForScope(scope, opts) {
  const s = assertScope(scope);
  const limit = Math.min(200, Math.max(1, Number((opts && opts.limit) || 50)));
  const columns = (opts && opts.tier === 'student') ? STUDENT_RUN_COLUMNS : STAFF_RUN_COLUMNS;
  const r = await cybercoreQuery(
    `SELECT ${columns}
       FROM cybercore_incident_run r
      WHERE r.scope_type = $1 AND r.scope_id = $2
      ORDER BY r.created_at DESC
      LIMIT ${limit}`,
    [s.type, s.id]
  );
  return r.rows;
}

/**
 * Does this user hold an active lane in this scope?
 *
 * The "your lane's scope only" resolution the plan requires, and the reason a
 * student route never trusts a scope id from the URL on its own: a course id or
 * an engagement id is guessable, and enrollment alone does not prove a lane.
 */
async function studentHasScopeLane(userId, scope) {
  const s = assertScope(scope);
  if (!UUID_RE.test(String(userId || ''))) return false;
  // The predicate binds the scope id as $1 (see runner.scopeLanesSql), so the
  // user id is $2 here. Neither is ever interpolated.
  const r = await cybercoreQuery(
    `SELECT 1
       FROM cybercore_lane l
      WHERE ${scopeLanePredicate(s.type)}
        AND l.user_id = $2
        AND l.status = 'active'
      LIMIT 1`,
    [s.id, userId]
  );
  return r.rows.length > 0;
}

/** The student's target row for a run, so a finding records which lane it came from. */
async function targetIdFor(runId, userId) {
  const r = await cybercoreQuery(
    `SELECT target_id FROM cybercore_incident_target
      WHERE run_id = $1 AND user_id = $2
      ORDER BY created_at DESC LIMIT 1`,
    [runId, userId]
  );
  return r.rows.length ? r.rows[0].target_id : null;
}

async function readFindings(runId, userId) {
  const params = userId ? [runId, userId] : [runId];
  const where = userId ? 'f.run_id = $1 AND f.user_id = $2' : 'f.run_id = $1';
  const r = await cybercoreQuery(
    `SELECT ${FINDING_COLUMNS}
       FROM cybercore_incident_finding f
      WHERE ${where}
      ORDER BY f.submitted_at, f.finding_id`,
    params
  );
  return r.rows;
}

async function readScores(runId, userId) {
  const params = userId ? [runId, userId] : [runId];
  const where = userId ? 's.run_id = $1 AND s.user_id = $2' : 's.run_id = $1';
  const r = await cybercoreQuery(
    `SELECT ${SCORE_COLUMNS}
       FROM cybercore_incident_score s
      WHERE ${where}`,
    params
  );
  return r.rows;
}

/**
 * The student's whole board for one run.
 *
 * Every object leaving here has been through projection.js. The run is built
 * from the eight-key whitelist, the findings are the student's OWN and carry no
 * override_note, and the score is withheld entirely until release — including
 * the technique count. See projection.js for why the count is the dangerous one.
 */
async function getStudentBoard(run, userId) {
  const findings = await readFindings(run.run_id, userId);
  const scores = await readScores(run.run_id, userId);
  const scoreRow = scores[0] || null;
  const released = !!(scoreRow && scoreRow.released === true);

  const active = findings.filter((f) => !f.withdrawn_at);
  const submitted = {
    findings: active.filter((f) => f.kind === 'finding' || f.kind === 'alert').length,
    iocs: active.filter((f) => f.kind === 'ioc').length,
    timeline: active.filter((f) => f.kind === 'timeline').length,
  };

  return {
    run: projection.projectRunForStudent(run),
    findings: findings.map((f) => projection.projectFindingForStudent(f, { released })),
    score: projection.projectScoreForStudent(scoreRow, submitted),
  };
}

/** The instructor's grading view: every student's work, unprojected. */
async function getStaffBoard(run) {
  const [findings, scores] = await Promise.all([
    readFindings(run.run_id, null),
    readScores(run.run_id, null),
  ]);
  // projectFindingForStaff is the identity today, and it is called anyway: it
  // is the single place a future "even staff do not see X" rule would go, and a
  // rule added to a function nobody calls is a rule that does not exist.
  return { run, findings: findings.map(projection.projectFindingForStaff), scores };
}

// ---------------------------------------------------------------------------
// Student writes
// ---------------------------------------------------------------------------

/**
 * Coerce a request body into the columns a student may set.
 *
 * Reads only FINDING_INPUT_KEYS and returns a NEW object, so an `auto_points`
 * or `override_verdict` in the body is not rejected loudly — it simply is not
 * carried, which is the behaviour that survives someone later adding a column.
 */
function sanitizeFindingInput(body) {
  const raw = (body && typeof body === 'object' && !Array.isArray(body)) ? body : {};
  const picked = {};
  for (const key of FINDING_INPUT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, key)) picked[key] = raw[key];
  }

  const kind = String(picked.kind || 'finding');
  if (!FINDING_KINDS.includes(kind)) throw bad('BAD_KIND', `kind must be one of ${FINDING_KINDS.join(', ')}`);

  const out = {
    kind,
    technique_id: text(picked.technique_id, 16),
    observed_at: null,
    ioc_type: null,
    ioc_value: null,
    title: text(picked.title, 200),
    narrative: text(picked.narrative, 8000),
    evidence: {},
    source_stack: null,
    alert_rule_id: text(picked.alert_rule_id, 200),
    alert_doc_id: text(picked.alert_doc_id, 200),
  };

  if (out.technique_id && !/^T\d{4}(\.\d{3})?$/i.test(out.technique_id)) {
    throw bad('BAD_TECHNIQUE', 'technique_id must look like T1110 or T1110.001');
  }
  if (out.technique_id) out.technique_id = out.technique_id.toUpperCase();

  if (picked.observed_at != null && picked.observed_at !== '') {
    const t = Date.parse(String(picked.observed_at));
    if (!Number.isFinite(t)) throw bad('BAD_OBSERVED_AT', 'observed_at must be a timestamp');
    out.observed_at = new Date(t).toISOString();
  }

  if (picked.source_stack != null && picked.source_stack !== '') {
    const st = String(picked.source_stack);
    if (!SOURCE_STACKS.includes(st)) throw bad('BAD_SOURCE_STACK', `source_stack must be one of ${SOURCE_STACKS.join(', ')}`);
    out.source_stack = st;
  }

  if (kind === 'ioc') {
    const t = String(picked.ioc_type || '');
    if (!IOC_TYPES.includes(t)) throw bad('BAD_IOC_TYPE', `ioc_type must be one of ${IOC_TYPES.join(', ')}`);
    const v = text(picked.ioc_value, 500);
    if (!v) throw bad('BAD_IOC_VALUE', 'an indicator needs a value');
    out.ioc_type = t;
    out.ioc_value = v;
  }

  if (kind === 'timeline' && !out.technique_id) {
    throw bad('BAD_TIMELINE', 'a timeline entry names the technique it orders');
  }

  // Evidence is free-form by design — it carries whatever query the student
  // ran, in whichever console — but it is bounded, and it is an OBJECT. An
  // array or a string here would land in JSONB and then break every reader that
  // expects `evidence.query`.
  const ev = picked.evidence;
  if (ev && typeof ev === 'object' && !Array.isArray(ev)) {
    out.evidence = {
      query: text(ev.query, 4000),
      note: text(ev.note, 2000),
      doc_ids: Array.isArray(ev.doc_ids)
        ? ev.doc_ids.slice(0, 50).map((d) => text(d, 200)).filter(Boolean)
        : [],
    };
  }

  return out;
}

/**
 * Bank one claim.
 *
 * Refuses once the run has been RELEASED to this student: the answers are on
 * their screen at that point, so a submission after release is not a finding,
 * it is a transcription. 409 rather than 403 because the resource exists and
 * the state is what refuses.
 */
async function submitFinding(run, userId, body) {
  const input = sanitizeFindingInput(body);

  const scores = await readScores(run.run_id, userId);
  if (scores[0] && scores[0].released === true) {
    throw new BoardError(409, 'BOARD_RELEASED',
      'This run has been released — its answers are visible, so the board is closed to new submissions.');
  }

  const targetId = await targetIdFor(run.run_id, userId);

  try {
    const r = await cybercoreQuery(
      `INSERT INTO cybercore_incident_finding
         (run_id, target_id, user_id, kind, technique_id, observed_at,
          ioc_type, ioc_value, title, narrative, evidence,
          source_stack, alert_rule_id, alert_doc_id)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12,$13,$14)
       RETURNING ${FINDING_RETURNING}`,
      [
        run.run_id, targetId, userId, input.kind, input.technique_id, input.observed_at,
        input.ioc_type, input.ioc_value, input.title, input.narrative,
        JSON.stringify(input.evidence),
        input.source_stack, input.alert_rule_id, input.alert_doc_id,
      ]
    );
    return r.rows[0];
  } catch (err) {
    // 23505 is the partial unique index doing its job: the same technique or
    // the same indicator, twice. That is a duplicate, not an error the student
    // can act on by retrying, so it gets its own status and its own words.
    if (err && err.code === '23505') {
      throw new BoardError(409, 'ALREADY_CLAIMED', 'You have already recorded that on this run.');
    }
    throw err;
  }
}

/**
 * Withdraw a claim. A TIMESTAMP, never a DELETE — see the schema comment: a
 * hard delete would let a student launder a false positive out of the record
 * after seeing their score.
 */
async function withdrawFinding(run, userId, findingId) {
  if (!UUID_RE.test(String(findingId || ''))) return null;
  const r = await cybercoreQuery(
    `UPDATE cybercore_incident_finding
        SET withdrawn_at = now(), updated_at = now()
      WHERE finding_id = $1 AND run_id = $2 AND user_id = $3 AND withdrawn_at IS NULL
      RETURNING ${FINDING_RETURNING}`,
    [findingId, run.run_id, userId]
  );
  return r.rows[0] || null;
}

// ---------------------------------------------------------------------------
// Staff writes
// ---------------------------------------------------------------------------

/**
 * An instructor's adjudication on one finding.
 *
 * Writes ONLY the override_* block. It never touches auto_*, which is what
 * makes "re-run the scorer" safe to do at any time — and it is the reason the
 * two blocks are separate columns rather than one mutable verdict.
 */
async function overrideFinding(run, findingId, staffUserId, patch) {
  if (!UUID_RE.test(String(findingId || ''))) return null;
  const p = (patch && typeof patch === 'object') ? patch : {};

  let verdict = null;
  if (p.override_verdict != null && p.override_verdict !== '') {
    verdict = String(p.override_verdict);
    if (!OVERRIDE_VERDICTS.includes(verdict)) {
      throw bad('BAD_VERDICT', `override_verdict must be one of ${OVERRIDE_VERDICTS.join(', ')}`);
    }
  }
  let points = null;
  if (p.override_points != null && p.override_points !== '') {
    points = Number(p.override_points);
    if (!Number.isFinite(points) || points < -100 || points > 100) {
      throw bad('BAD_POINTS', 'override_points must be a number between -100 and 100');
    }
  }
  const note = text(p.override_note, 4000);

  // "Did the instructor say anything at all?" is decided HERE, in JS, and sent
  // as one boolean -- rather than as `CASE WHEN $1 IS NULL AND $2 IS NULL ...`
  // over the three value parameters. Postgres cannot infer a parameter's type
  // from a bare NULL test, so that form fails to PARSE, which is a 500 on a
  // route that looked fine in review. test/sql-param-typing.test.js is the
  // repo-wide gate on exactly this, and it caught this statement.
  //
  // Clearing all three is how an override is UNDONE, and override_at must go
  // back to NULL with them or the row reads as adjudicated forever.
  const cleared = verdict === null && points === null && note === null;

  const r = await cybercoreQuery(
    `UPDATE cybercore_incident_finding
        SET override_verdict = $1,
            override_points  = $2,
            override_note    = $3,
            override_by      = CASE WHEN $5::boolean THEN NULL ELSE $4 END,
            override_at      = CASE WHEN $5::boolean THEN NULL ELSE now() END,
            updated_at       = now()
      WHERE finding_id = $6 AND run_id = $7
      RETURNING ${FINDING_RETURNING}`,
    [verdict, points, note, staffUserId, cleared, findingId, run.run_id]
  );
  return r.rows[0] || null;
}

/**
 * The run's compiled key. Read on its own, by name, one run at a time — it is
 * the only thing in this file that reads a private column, and it exists as a
 * separate function so that "who can reach the answer key" is one call site.
 */
async function readAnswerKey(runId) {
  const r = await cybercoreQuery(
    `SELECT r.run_id, r.engine, r.scheduled_start_at, r.answer_key
       FROM cybercore_incident_run r
      WHERE r.run_id = $1`,
    [runId]
  );
  return r.rows[0] || null;
}

/**
 * Re-grade every student on a run.
 *
 * Idempotent: same key + same findings gives the same numbers, so this is safe
 * to run on a timer, after a key recompile, or twice by accident.
 *
 * @returns {{users:number, findings:number, graded:boolean}}
 */
async function scoreRun(run) {
  const keyRow = await readAnswerKey(run.run_id);
  if (!keyRow) throw new BoardError(404, 'NO_RUN', 'run not found');

  const key = keyRow.answer_key || {};
  const findings = await readFindings(run.run_id, null);
  const existing = await readScores(run.run_id, null);
  const overrideByUser = new Map(existing.map((s) => [String(s.user_id), s.override_points]));

  // Every user who has a finding OR an existing score row. The second half
  // matters: a student who withdrew everything must have their score recomputed
  // to zero rather than left showing yesterday's total.
  const users = new Set([
    ...findings.map((f) => String(f.user_id)),
    ...existing.map((s) => String(s.user_id)),
  ]);

  const ids = [];
  const verdicts = [];
  const points = [];
  const matched = [];
  const notes = [];
  let graded = false;

  for (const userId of users) {
    const mine = findings.filter((f) => String(f.user_id) === userId);
    const result = scoring.scoreRun({
      run: { scheduled_start_at: keyRow.scheduled_start_at },
      answerKey: key,
      findings: mine,
      runOverridePoints: overrideByUser.get(userId),
    });
    graded = graded || result.graded;

    for (const s of result.findings) {
      ids.push(s.finding_id);
      verdicts.push(s.auto_verdict);
      points.push(String(s.auto_points));
      matched.push(s.auto_matched_key);
      notes.push(s.auto_note);
    }

    const sc = result.score;
    // The upsert does NOT list released / released_at / released_by. Adding
    // them here is how a re-score would silently un-release a run students are
    // already reading, or re-release one an instructor pulled back.
    await cybercoreQuery(
      `INSERT INTO cybercore_incident_score
         (run_id, user_id, techniques_total, techniques_found, techniques_missed,
          iocs_total, iocs_found, false_positives, timeline_score,
          first_detection_at, ttd_seconds, auto_points, final_points, scored_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13, now())
       ON CONFLICT (run_id, user_id) DO UPDATE SET
         techniques_total   = EXCLUDED.techniques_total,
         techniques_found   = EXCLUDED.techniques_found,
         techniques_missed  = EXCLUDED.techniques_missed,
         iocs_total         = EXCLUDED.iocs_total,
         iocs_found         = EXCLUDED.iocs_found,
         false_positives    = EXCLUDED.false_positives,
         timeline_score     = EXCLUDED.timeline_score,
         first_detection_at = EXCLUDED.first_detection_at,
         ttd_seconds        = EXCLUDED.ttd_seconds,
         auto_points        = EXCLUDED.auto_points,
         final_points       = EXCLUDED.final_points,
         scored_at          = now()`,
      [
        run.run_id, userId, sc.techniques_total, sc.techniques_found, sc.techniques_missed,
        sc.iocs_total, sc.iocs_found, sc.false_positives, sc.timeline_score,
        sc.first_detection_at, sc.ttd_seconds, sc.auto_points, sc.final_points,
      ]
    );
  }

  if (ids.length) {
    // ONE statement, five columns. See the header: this is the shape that makes
    // a re-score incapable of touching an override.
    await cybercoreQuery(
      `UPDATE cybercore_incident_finding f
          SET auto_verdict     = v.auto_verdict,
              auto_points      = v.auto_points,
              auto_matched_key = v.auto_matched_key,
              auto_note        = v.auto_note,
              scored_at        = now(),
              updated_at       = now()
         FROM (
           SELECT t.finding_id, t.auto_verdict, t.auto_points, t.auto_matched_key, t.auto_note
             FROM unnest($1::uuid[], $2::text[], $3::numeric[], $4::text[], $5::text[])
               AS t(finding_id, auto_verdict, auto_points, auto_matched_key, auto_note)
         ) v
        WHERE f.finding_id = v.finding_id`,
      [ids, verdicts, points, matched, notes]
    );
  }

  return { users: users.size, findings: ids.length, graded };
}

/**
 * Release (or retract) a run's scores.
 *
 * Per-run by default, optionally per-student. Retraction exists because the
 * first release of a semester is usually a mistake, and the alternative to an
 * un-release is a support ticket.
 */
async function setRelease(run, released, staffUserId, studentUserId) {
  const on = released === true;
  const params = [run.run_id, on, on ? staffUserId : null];
  let where = 's.run_id = $1';
  if (studentUserId) {
    if (!UUID_RE.test(String(studentUserId))) throw bad('BAD_USER', 'user_id must be a uuid');
    params.push(studentUserId);
    where += ' AND s.user_id = $4';
  }
  const r = await cybercoreQuery(
    `UPDATE cybercore_incident_score s
        SET released    = $2,
            released_at = CASE WHEN $2 THEN now() ELSE NULL END,
            released_by = $3
      WHERE ${where}
      RETURNING s.run_id, s.user_id, s.released, s.released_at`,
    params
  );
  return r.rows;
}

module.exports = {
  BoardError,
  SCOPE_TYPES,
  scopeLanePredicate,
  FINDING_INPUT_KEYS,
  FINDING_KINDS,
  IOC_TYPES,
  SOURCE_STACKS,
  OVERRIDE_VERDICTS,
  sanitizeFindingInput,
  readRunForStudent,
  readRunForStaff,
  listRunsForScope,
  studentHasScopeLane,
  readFindings,
  readScores,
  getStudentBoard,
  getStaffBoard,
  submitFinding,
  withdrawFinding,
  overrideFinding,
  readAnswerKey,
  scoreRun,
  setRelease,
};
