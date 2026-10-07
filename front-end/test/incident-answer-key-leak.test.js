/**
 * incident-answer-key-leak.test.js — Track E, phase E5: the key never reaches a
 * student.
 *
 * A `cybercore_incident_run` row contains, in plain columns, the entire answer
 * to the exercise: `technique_id`, `tactic_id`, `chain_key`, `scenario_id`,
 * `scenario_ref`, the compiled `playbook` and the graded `answer_key`. One
 * `SELECT *` on a student route ends the exercise for a whole class, in one
 * request, with no error, no log line and nothing on screen that looks wrong.
 *
 * THAT IS WHY THIS FILE IS A SOURCE-TEXT GATE AND NOT ONLY A BEHAVIOURAL TEST.
 * A runtime test proves the handlers that EXIST do not leak. It cannot see the
 * handler somebody adds next month, reasonably, with a `SELECT *` in it. The
 * property being defended — "no student-facing code path can name these
 * columns" — is exactly the kind that gets reintroduced by a small, sensible
 * change, and the blunt instrument is the right one for it.
 *
 * COMMENTS ARE STRIPPED FIRST, and that is load-bearing here for the same
 * reason it is in ciab-deploy-parity.test.js and incident-engine-locality.test.js:
 * this codebase documents its traps at length, and the traps are named after
 * exactly the identifiers forbidden below. projection.js's header is a page of
 * prose about `answer_key` and `override_note`; without stripping, the comment
 * that exists to prevent the leak would itself fail the test.
 *
 * Sections 5-8 then EXECUTE the projection, because a scan cannot see a
 * whitelist that is right and a spread that is applied after it.
 *
 * Run: node --test test/incident-answer-key-leak.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/** Borrowed wholesale from incident-engine-locality.test.js. See the header. */
function codeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('#');
    })
    .join('\n');
}

/**
 * THE FORBIDDEN FIVE.
 *
 *   'SELECT *'        the whole row, including both JSONB columns
 *   'r.*'             the same thing wearing the run table's alias
 *   'answer_key'      the graded truth
 *   'playbook'        the compiled attack, verbatim
 *   'override_note'   STAFF ONLY — the ciab_module.instructor_notes precedent
 */
const FORBIDDEN = [
  { needle: 'SELECT *', why: 'a star select reaches every private column at once' },
  { needle: 'r.*', why: 'the same star, wearing the run table alias' },
  { needle: 'answer_key', why: 'the graded truth' },
  { needle: 'playbook', why: 'the compiled attack, verbatim' },
  { needle: 'override_note', why: 'an instructor writes it expecting the student cannot read it' },
];

/** Every file a student's browser or a student's request can reach. */
const STUDENT_FACING = [
  'modules/crucible/plugins/cle/routes/incidents.js',
  'modules/crucible/plugins/ciab/routes/incidents.js',
  'public/js/blueteam/blueteam-api.js',
  'public/js/blueteam/blueteam-board.js',
  'public/js/blueteam/blueteam-score.js',
  'public/js/blueteam/blueteam-timeline.js',
  'src/incident/projection.js',
];

// ---------------------------------------------------------------------------
// §1 The gate
// ---------------------------------------------------------------------------

test('E5-L1: no student-facing incident handler names the answer key', () => {
  for (const rel of STUDENT_FACING) {
    const code = codeOnly(read(rel));
    for (const { needle, why } of FORBIDDEN) {
      assert.ok(!code.includes(needle),
        `${rel} contains ${JSON.stringify(needle)} — ${why}.\n`
        + '  Student reads go through src/incident/projection.js and its column lists.');
    }
  }
});

test('E5-L2: the board reads no star select either, at any tier', () => {
  // board.js DOES read the key — that is its job, for the scorer — so it is not
  // in the list above. What it must never do is read a whole row: a star select
  // there would put the key into the same object the student projection is
  // built from, and the whitelist is then the only thing between them.
  const code = codeOnly(read('src/incident/board.js'));
  assert.ok(!code.includes('SELECT *'), 'src/incident/board.js contains a star select');
  assert.ok(!code.includes('r.*'), 'src/incident/board.js contains r.*');
});

test('E5-L3: the student read is the STUDENT column list, in SQL', () => {
  // Layer 2. The private columns must not leave Postgres on a student path at
  // all, so that a projection bug downstream is a MISSING FIELD rather than a
  // disclosure. Read off the function body, so a later edit that swaps the
  // constant is caught even though both constants exist in the file.
  const src = read('src/incident/board.js');
  const body = (name) => {
    const start = src.indexOf(`async function ${name}(`);
    assert.ok(start >= 0, `${name}() is missing from board.js`);
    const end = src.indexOf('\n}', start);
    return src.slice(start, end);
  };

  const student = body('readRunForStudent');
  assert.ok(student.includes('${STUDENT_RUN_COLUMNS}'), 'readRunForStudent must use STUDENT_RUN_COLUMNS');
  assert.ok(!student.includes('STAFF_RUN_COLUMNS'), 'readRunForStudent must not reach the staff list');
  for (const { needle } of FORBIDDEN) {
    assert.ok(!codeOnly(student).includes(needle), `readRunForStudent names ${needle}`);
  }

  // And the scope pair is on the WHERE, so "another course's run" and "no such
  // run" produce the same null and therefore the same 404.
  assert.match(student, /r\.run_id = \$1 AND r\.scope_type = \$2 AND r\.scope_id = \$3/);
});

// ---------------------------------------------------------------------------
// §2 The whitelist itself
// ---------------------------------------------------------------------------

test('E5-L4: the run whitelist is exactly eight keys, and the SQL mirrors it', () => {
  const projection = require('../src/incident/projection');
  assert.deepStrictEqual(projection.STUDENT_RUN_KEYS.slice().sort(), [
    'engine', 'finished_at', 'mode', 'run_id',
    'scheduled_start_at', 'scope_id', 'scope_type', 'status',
  ]);
  // The SQL column list and the JS key list have to agree, or the projection
  // silently emits `undefined` for a column the query never selected.
  const sqlKeys = projection.STUDENT_RUN_COLUMNS
    .split(',').map((c) => c.trim().replace(/^r\./, '')).filter(Boolean).sort();
  assert.deepStrictEqual(sqlKeys, projection.STUDENT_RUN_KEYS.slice().sort());
});

// ---------------------------------------------------------------------------
// §3 The projection, executed
// ---------------------------------------------------------------------------

/** A run row with EVERY column populated, including the two that end exercises. */
function fullRunRow() {
  return {
    run_id: 'r1', scope_type: 'course', scope_id: 'c1', scope_label: 'CYBR400-01',
    engine: 'synthetic', launched_by: 'u9',
    mode: 'chain', technique_id: 'T1110.001', tactic_id: 'TA0006',
    chain_key: 'ransomware-ryuk', scenario_id: 'sc-1',
    scenario_ref: { profile_id: 'p1', name: 'Ransomware at Acme' },
    playbook: { steps: [{ message: 'the whole attack' }] },
    answer_key: { techniques: [{ id: 'T1486' }], iocs: [{ value: '203.0.113.11' }] },
    duration_seconds: 1800, speed: '1.00', catalog_version: 'loggen-2026.02',
    lead_seconds: 60, scheduled_start_at: '2026-03-01T10:00:00.000Z',
    status: 'completed', event_group_id: 'g1', error: null,
    created_at: '2026-03-01T09:00:00.000Z', finished_at: '2026-03-01T10:30:00.000Z',
  };
}

test('E5-L5: projectRunForStudent BUILDS a new object and drops everything else', () => {
  const projection = require('../src/incident/projection');
  const row = fullRunRow();
  const out = projection.projectRunForStudent(row);

  assert.deepStrictEqual(Object.keys(out).sort(), projection.STUDENT_RUN_KEYS.slice().sort());

  // Nothing private survived, by NAME or by VALUE. The value check is the one
  // that catches a nested spread.
  const asText = JSON.stringify(out);
  for (const needle of ['answer_key', 'playbook', 'technique_id', 'tactic_id', 'chain_key',
    'scenario_id', 'scenario_ref', 'catalog_version', 'launched_by', 'duration_seconds',
    'T1110.001', 'TA0006', 'ransomware-ryuk', 'T1486', '203.0.113.11', 'loggen-2026.02']) {
    assert.ok(!asText.includes(needle), `${needle} survived the run projection`);
  }

  // It is a NEW object: the source row is untouched, so a caller that also
  // renders a staff view of the same row still has one.
  assert.ok(row.answer_key, 'the projection must not mutate its input');
  assert.ok(row.playbook, 'the projection must not mutate its input');

  // A partial row (a query that selected fewer columns) yields a smaller
  // object, never a throw. The failure mode of this function is "less data".
  const partial = projection.projectRunForStudent({ run_id: 'r1' });
  assert.strictEqual(partial.run_id, 'r1');
  assert.strictEqual(partial.status, undefined);
  assert.strictEqual(projection.projectRunForStudent(null), null);
});

test('E5-L6: a finding projection never carries the instructor note, released or not', () => {
  const projection = require('../src/incident/projection');
  const row = {
    finding_id: 'f1', run_id: 'r1', user_id: 'u1', kind: 'finding',
    technique_id: 'T1110', title: 'brute force', narrative: 'saw a spray',
    evidence: { query: 'loggen.metadata.outcome : "failure"' },
    submitted_at: '2026-03-01T10:05:00.000Z', withdrawn_at: null,
    auto_verdict: 'hit', auto_points: '1.00', auto_matched_key: 'T1110',
    auto_note: null, scored_at: '2026-03-01T11:00:00.000Z',
    override_verdict: 'partial', override_points: '0.50',
    override_note: 'PRIVATE-INSTRUCTOR-TEXT', override_by: 'u9',
    override_at: '2026-03-01T11:05:00.000Z',
  };

  for (const released of [false, true]) {
    const out = projection.projectFindingForStudent(row, { released });
    const asText = JSON.stringify(out);
    assert.ok(!asText.includes('PRIVATE-INSTRUCTOR-TEXT'),
      `override_note leaked at released=${released}`);
    assert.ok(!Object.prototype.hasOwnProperty.call(out, 'override_note'));
    assert.ok(!Object.prototype.hasOwnProperty.call(out, 'user_id'),
      'a student page has no use for a user id and it is somebody else\'s on the staff board');
  }

  // PRE-RELEASE: submitted, and nothing derived from the key.
  const before = projection.projectFindingForStudent(row, { released: false });
  assert.strictEqual(before.verdict, null);
  assert.strictEqual(before.points, null);
  assert.strictEqual(before.note, null);
  assert.strictEqual(before.matched_key, null);
  // The claim itself is still theirs to see — it is what they typed.
  assert.strictEqual(before.technique_id, 'T1110');

  // POST-RELEASE: the EFFECTIVE verdict, so an override is what the student
  // sees rather than the scorer's superseded answer.
  const after = projection.projectFindingForStudent(row, { released: true });
  assert.strictEqual(after.verdict, 'partial');
  assert.strictEqual(after.points, 0.5);
});

test('E5-L7: pre-release, a student is not told HOW MANY techniques there are', () => {
  const projection = require('../src/incident/projection');
  const scoreRow = {
    run_id: 'r1', user_id: 'u1',
    techniques_total: 6, techniques_found: 2, techniques_missed: 4,
    iocs_total: 3, iocs_found: 1, false_positives: 1,
    timeline_score: '0.6667', first_detection_at: '2026-03-01T10:09:00.000Z',
    ttd_seconds: 540, auto_points: '2.50', override_points: null, final_points: '2.50',
    released: false, released_at: null, released_by: null,
  };
  const submitted = { findings: 2, iocs: 1, timeline: 3 };

  const before = projection.projectScoreForStudent(scoreRow, submitted);
  assert.strictEqual(before.released, false);
  assert.deepStrictEqual(before.submitted, submitted);
  // THE COUNT IS THE HINT. "There are six" tells a student when to stop
  // hunting, which is most of the skill the exercise is teaching — so it is
  // withheld even though it names no technique at all.
  assert.ok(!Object.prototype.hasOwnProperty.call(before, 'techniques_total'));
  assert.ok(!Object.prototype.hasOwnProperty.call(before, 'techniques_found'));
  assert.ok(!Object.prototype.hasOwnProperty.call(before, 'points'));
  assert.ok(!Object.prototype.hasOwnProperty.call(before, 'ttd_seconds'));

  // A student who has never been scored at all gets the same shape, not a null
  // the page has to guess the meaning of.
  const never = projection.projectScoreForStudent(null, submitted);
  assert.strictEqual(never.released, false);
  assert.deepStrictEqual(never.submitted, submitted);

  const after = projection.projectScoreForStudent(
    Object.assign({}, scoreRow, { released: true }), submitted
  );
  assert.strictEqual(after.released, true);
  assert.strictEqual(after.techniques_total, 6);
  assert.strictEqual(after.points, 2.5);
  // The FINAL number only. auto_points beside it would expose every instructor
  // adjustment as a subtraction to argue about.
  assert.ok(!Object.prototype.hasOwnProperty.call(after, 'auto_points'));
  assert.ok(!Object.prototype.hasOwnProperty.call(after, 'override_points'));
});

// ---------------------------------------------------------------------------
// §4 The client cannot rebuild what the server withheld
// ---------------------------------------------------------------------------

test('E5-L8: the board UI does not reconstruct a technique total client-side', () => {
  // The release gate is server-side and complete: the counts are simply not in
  // the payload before release. The one way to defeat it from the browser is to
  // count the findings list and render "2 of ?" — which is why the score
  // renderer takes the SERVER's numbers and nothing else.
  const code = codeOnly(read('public/js/blueteam/blueteam-score.js'));
  assert.ok(!/techniques_total\s*[=:]\s*[^s]/.test(code.replace(/s\.techniques_total/g, '')),
    'blueteam-score.js computes a technique total instead of rendering the server\'s');
  assert.ok(code.includes('s.released !== true'),
    'blueteam-score.js must branch on the SERVER\'s released flag');
});
