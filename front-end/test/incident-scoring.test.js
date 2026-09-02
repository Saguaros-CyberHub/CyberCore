/**
 * incident-scoring.test.js — Track E, phase E5: the auto-scorer.
 *
 * The scorer is the only part of this feature whose bugs land in a GRADE. A
 * wrong number here does not crash, does not log, and is not visible to anyone
 * except the student it was wrong about — so the rules are pinned as a table
 * rather than left to review.
 *
 * WHAT EACH SECTION DEFENDS
 *
 *   §1  THE FOUR VERDICTS. Hit, false positive, defensible miss, duplicate.
 *   §2  THE DEFENSIBLE MISS, on its own, because it is the rule most likely to
 *       be "simplified" away by someone who has not read why the benign floor
 *       tags 4-20% of its own events with real MITRE ids. Deleting it turns
 *       every student who correctly notices the floor into a penalised one, and
 *       makes the floor's whole design self-defeating.
 *   §3  THE FLOOR AT ZERO. Without it, guessing widely and then finding
 *       something real scores BELOW submitting nothing.
 *   §4  TIME TO DETECT. Measured from the run's scheduled start, from a
 *       SUBMISSION time, clamped at 0 — never from observed_at (the student's
 *       own assertion) and never from a document @timestamp (which is ingest
 *       time in this stack; backdating does not work).
 *   §5  KENDALL TAU, including the two edges that are wrong by default: one
 *       entry is NULL and not zero, and an uncorrelated entry is EXCLUDED
 *       rather than counted as an inversion — it has already been charged once
 *       as a false positive.
 *   §6  OVERRIDE PRECEDENCE. Points beat verdict beat auto; a run-level total
 *       replaces the sum outright.
 *   §7  IDEMPOTENCE. Byte-identical on re-run. This is what makes "re-score the
 *       class" a safe thing to press.
 *   §8  NO KEY IS NOT A ZERO. The tempting shortcut — treat an empty key as
 *       "nothing was in the attack" — marks every correct answer a false
 *       positive and hands the class negative scores for a server-side bug.
 *
 * Pure: no database, no clock, no lane. Run: node --test test/incident-scoring.test.js
 */
'use strict';

const { test } = require('node:test');
const assert = require('assert');

const scoring = require('../src/incident/scoring');
const { ANSWER_KEY_VERSION } = require('../src/incident/answer-key');

const START = '2026-03-01T10:00:00.000Z';
const at = (seconds) => new Date(Date.parse(START) + seconds * 1000).toISOString();

/** A small, explicit key. Real keys come from answer-key.js; this pins rules. */
const KEY = Object.freeze({
  version: ANSWER_KEY_VERSION,
  engine: 'synthetic',
  techniques: [
    { id: 'T1566.001', tactic: 'TA0001', first_offset_s: 10, event_count: 30 },
    { id: 'T1059.003', tactic: 'TA0002', first_offset_s: 60, event_count: 20 },
    { id: 'T1003.001', tactic: 'TA0006', first_offset_s: 120, event_count: 10 },
  ],
  iocs: [
    { type: 'ip', value: '203.0.113.11', technique_ids: ['T1566.001'], event_count: 12 },
    { type: 'process', value: 'ryuk.exe', technique_ids: ['T1003.001'], event_count: 4 },
  ],
  timeline: [],
  // The floor's own MITRE tags — the defensible-miss set.
  floor_techniques: ['T1110', 'T1082'],
  // Lowercased, as answer-key.js emits them.
  floor_values: ['web-01', 'jsmith', '10.20.30.14'],
  floor_truncated: false,
  totals: { events: 60, techniques: 3, iocs: 2 },
});

let seq = 0;
/** A finding row, with the columns the scorer reads and sane defaults. */
function finding(over) {
  seq += 1;
  return Object.assign({
    finding_id: `00000000-0000-0000-0000-${String(seq).padStart(12, '0')}`,
    user_id: 'u1',
    kind: 'finding',
    technique_id: null,
    ioc_type: null,
    ioc_value: null,
    observed_at: null,
    submitted_at: at(300),
    withdrawn_at: null,
    override_verdict: null,
    override_points: null,
  }, over || {});
}

const run = { scheduled_start_at: START };
const score = (findings, extra) => scoring.scoreRun(
  Object.assign({ run, answerKey: KEY, findings }, extra || {})
);
const verdictOf = (result, i) => result.findings[i].auto_verdict;
const pointsOf = (result, i) => result.findings[i].auto_points;

// ---------------------------------------------------------------------------
// §1 The four verdicts
// ---------------------------------------------------------------------------

test('E5-S1: every verdict the scorer can reach, in one table', () => {
  const cases = [
    {
      name: 'a technique in the key is a hit worth +1.0',
      f: finding({ technique_id: 'T1566.001' }),
      verdict: 'hit', points: 1.0, matched: 'T1566.001',
    },
    {
      name: 'case and whitespace do not decide a grade',
      f: finding({ technique_id: '  t1566.001 ' }),
      verdict: 'hit', points: 1.0, matched: 'T1566.001',
    },
    {
      name: 'a technique in neither the key nor the floor is -0.5',
      f: finding({ technique_id: 'T1486' }),
      verdict: 'false_positive', points: -0.5,
    },
    {
      name: 'a technique the FLOOR tags is a defensible miss: 0, never negative',
      f: finding({ technique_id: 'T1110' }),
      verdict: 'partial', points: 0,
    },
    {
      name: 'an IOC in the key is +0.5, matched case-insensitively',
      f: finding({ kind: 'ioc', ioc_type: 'process', ioc_value: 'RYUK.EXE' }),
      verdict: 'hit', points: 0.5, matched: 'process:ryuk.exe',
    },
    {
      name: 'an ordinary value the floor also emits is a defensible miss, not a penalty',
      f: finding({ kind: 'ioc', ioc_type: 'host', ioc_value: 'WEB-01' }),
      verdict: 'partial', points: 0,
    },
    {
      name: 'a value in neither is -0.5',
      f: finding({ kind: 'ioc', ioc_type: 'ip', ioc_value: '198.51.100.9' }),
      verdict: 'false_positive', points: -0.5,
    },
    {
      name: 'a narrative with no technique is unscored, not a false positive',
      f: finding({ technique_id: null, title: 'something looked odd' }),
      verdict: 'unscored', points: 0,
    },
    {
      name: 'a timeline entry is worth nothing on its own — it is scored as ORDER',
      f: finding({ kind: 'timeline', technique_id: 'T1566.001' }),
      verdict: 'unscored', points: 0,
    },
    {
      name: 'a withdrawn claim scores nothing, whatever it claimed',
      f: finding({ technique_id: 'T1566.001', withdrawn_at: at(400) }),
      verdict: 'unscored', points: 0,
    },
  ];

  for (const c of cases) {
    const r = score([c.f]);
    assert.strictEqual(verdictOf(r, 0), c.verdict, c.name);
    assert.strictEqual(pointsOf(r, 0), c.points, `${c.name} (points)`);
    if (c.matched) assert.strictEqual(r.findings[0].auto_matched_key, c.matched, `${c.name} (matched)`);
  }
});

test('E5-S2: the same technique claimed twice banks once', () => {
  // The partial unique index in schema.js is the FIRST line of defence and it
  // is the one that survives two concurrent POSTs. This is the second: a
  // duplicate that reaches the scorer anyway is 'unscored', not a second +1.0.
  const r = score([
    finding({ technique_id: 'T1566.001', submitted_at: at(100) }),
    finding({ technique_id: 'T1566.001', submitted_at: at(200) }),
  ]);
  assert.strictEqual(verdictOf(r, 0), 'hit');
  assert.strictEqual(verdictOf(r, 1), 'unscored');
  assert.strictEqual(r.score.auto_points, 1);
  assert.strictEqual(r.score.techniques_found, 1);

  // And the EARLIER submission is the one that banks, regardless of row order.
  const reversed = score([
    finding({ technique_id: 'T1059.003', submitted_at: at(200) }),
    finding({ technique_id: 'T1059.003', submitted_at: at(100) }),
  ]);
  const hit = reversed.findings.find((f) => f.auto_verdict === 'hit');
  const dup = reversed.findings.find((f) => f.auto_verdict === 'unscored');
  assert.ok(hit && dup, 'exactly one of the pair banks');
});

// ---------------------------------------------------------------------------
// §2 The defensible miss, on its own
// ---------------------------------------------------------------------------

test('E5-S3: a defensible miss carries the EXPLANATION, not just a zero', () => {
  // The note is the point of the rule. A student who reports T1110 because the
  // floor is full of failed logons found exactly what the floor planted for
  // them; "0 points" with no words reads as "wrong". The text is student-facing
  // and travels in auto_note, which projection.js passes through on release.
  const r = score([finding({ technique_id: 'T1082' })]);
  assert.strictEqual(verdictOf(r, 0), 'partial');
  assert.strictEqual(r.findings[0].auto_note, scoring.DEFENSIBLE_MISS_NOTE);
  assert.match(r.findings[0].auto_note, /ordinary traffic/i);
  // It is NOT counted against them anywhere else either.
  assert.strictEqual(r.score.false_positives, 0);
  assert.strictEqual(r.score.auto_points, 0);
});

// ---------------------------------------------------------------------------
// §3 The floor at zero
// ---------------------------------------------------------------------------

test('E5-S4: the run total is floored at 0, so guessing never beats silence', () => {
  const wild = score([
    finding({ technique_id: 'T1486' }),
    finding({ technique_id: 'T1021.001' }),
    finding({ technique_id: 'T1547.001' }),
    finding({ technique_id: 'T1566.001' }),   // one real hit, +1.0
  ]);
  // Raw sum is 1.0 - 1.5 = -0.5.
  assert.strictEqual(wild.score.auto_points, 0, 'floored, not negative');
  assert.strictEqual(wild.score.final_points, 0);
  assert.strictEqual(wild.score.false_positives, 3);

  const silent = score([]);
  assert.strictEqual(silent.score.final_points, 0);
  assert.ok(wild.score.final_points >= silent.score.final_points,
    'a student who found something real never scores below one who submitted nothing');
});

// ---------------------------------------------------------------------------
// §4 Time to detect
// ---------------------------------------------------------------------------

test('E5-S5: TTD is measured from the scheduled start, on submissions, clamped at 0', () => {
  const normal = score([
    finding({ technique_id: 'T1059.003', submitted_at: at(540) }),
    finding({ technique_id: 'T1566.001', submitted_at: at(900) }),
  ]);
  assert.strictEqual(normal.score.ttd_seconds, 540, 'the EARLIEST hit sets it');
  assert.strictEqual(normal.score.first_detection_at, at(540));

  // A clock, not a fast student. Proxmox only syncs a guest RTC on resume, and
  // a scheduled start can be moved after the fact — either produces a negative
  // interval, and a negative TTD in a gradebook is worse than none.
  const early = score([finding({ technique_id: 'T1566.001', submitted_at: at(-600) })]);
  assert.strictEqual(early.score.ttd_seconds, 0);

  // observed_at is the student's OWN ASSERTION about when the activity
  // happened. Measuring detection against it would let a student back-date
  // their way to a TTD of zero.
  const backdated = score([finding({
    technique_id: 'T1566.001', submitted_at: at(3600), observed_at: at(1),
  })]);
  assert.strictEqual(backdated.score.ttd_seconds, 3600, 'submission time, not observed_at');

  // Nothing correct, nothing detected.
  const missed = score([finding({ technique_id: 'T1486' })]);
  assert.strictEqual(missed.score.ttd_seconds, null);
  assert.strictEqual(missed.score.first_detection_at, null);

  // No scheduled start (a run that never dispatched) is null, not NaN and not 0.
  const noStart = scoring.scoreRun({
    run: {}, answerKey: KEY, findings: [finding({ technique_id: 'T1566.001' })],
  });
  assert.strictEqual(noStart.score.ttd_seconds, null);
});

// ---------------------------------------------------------------------------
// §5 Kendall tau
// ---------------------------------------------------------------------------

test('E5-S6: kendallTau is the textbook statistic, with the right null', () => {
  const truth = ['A', 'B', 'C', 'D'];
  assert.strictEqual(scoring.kendallTau(['A', 'B', 'C', 'D'], truth), 1);
  assert.strictEqual(scoring.kendallTau(['D', 'C', 'B', 'A'], truth), -1);
  // One swap out of six pairs: (6-1-1)/6 -> 4/6.
  assert.ok(Math.abs(scoring.kendallTau(['B', 'A', 'C', 'D'], truth) - (4 / 6)) < 1e-9);
  // UNDEFINED, not zero. Zero would read as "ordered no better than chance",
  // which is a claim about a student nobody measured.
  assert.strictEqual(scoring.kendallTau(['A'], truth), null);
  assert.strictEqual(scoring.kendallTau([], truth), null);
});

test('E5-S7: the timeline score covers CORRECT claims only, and excludes the rest', () => {
  // Perfect order.
  const good = score([
    finding({ kind: 'timeline', technique_id: 'T1566.001', observed_at: at(10) }),
    finding({ kind: 'timeline', technique_id: 'T1059.003', observed_at: at(60) }),
    finding({ kind: 'timeline', technique_id: 'T1003.001', observed_at: at(120) }),
  ]);
  assert.strictEqual(good.score.timeline_score, 1);

  // Backwards.
  const bad = score([
    finding({ kind: 'timeline', technique_id: 'T1003.001', observed_at: at(10) }),
    finding({ kind: 'timeline', technique_id: 'T1059.003', observed_at: at(60) }),
    finding({ kind: 'timeline', technique_id: 'T1566.001', observed_at: at(120) }),
  ]);
  assert.strictEqual(bad.score.timeline_score, -1);

  // AN UNCORRELATED ENTRY IS EXCLUDED, NOT COUNTED AS AN INVERSION. T1486 is
  // not in the key, so it has already been charged as a false positive if the
  // student also banked it as a finding. Counting it here as well is double
  // jeopardy for one mistake — and, mechanically, there is no rank to compare
  // it against, so any treatment other than exclusion is invented.
  const withNoise = score([
    finding({ kind: 'timeline', technique_id: 'T1566.001', observed_at: at(10) }),
    finding({ kind: 'timeline', technique_id: 'T1486', observed_at: at(30) }),
    finding({ kind: 'timeline', technique_id: 'T1059.003', observed_at: at(60) }),
    finding({ kind: 'timeline', technique_id: 'T1003.001', observed_at: at(120) }),
  ]);
  assert.strictEqual(withNoise.score.timeline_score, 1,
    'the two correct pairs are still perfectly ordered');

  // One correlated entry is null, for the same reason kendallTau returns null.
  const single = score([finding({ kind: 'timeline', technique_id: 'T1566.001' })]);
  assert.strictEqual(single.score.timeline_score, null);

  // A withdrawn ordering claim is out of the correlation entirely.
  const withdrawn = score([
    finding({ kind: 'timeline', technique_id: 'T1003.001', observed_at: at(10) }),
    finding({ kind: 'timeline', technique_id: 'T1566.001', observed_at: at(20), withdrawn_at: at(30) }),
    finding({ kind: 'timeline', technique_id: 'T1059.003', observed_at: at(60) }),
  ]);
  assert.strictEqual(withdrawn.score.timeline_score, -1, 'C before B, and B is gone');
});

// ---------------------------------------------------------------------------
// §6 Override precedence
// ---------------------------------------------------------------------------

test('E5-S8: an instructor override beats the scorer, and points beat verdict', () => {
  const rows = [
    // The scorer said false positive; the instructor says it was right.
    finding({ technique_id: 'T1486', override_verdict: 'hit' }),
    // The scorer said hit; the instructor gives partial credit by NUMBER, which
    // must not be rounded into the verdict's bucket.
    finding({ technique_id: 'T1566.001', override_verdict: 'hit', override_points: 0.25 }),
  ];
  const r = score(rows);

  // auto_* is untouched by the override — that is what makes a re-score safe.
  assert.strictEqual(verdictOf(r, 0), 'false_positive');
  assert.strictEqual(pointsOf(r, 0), -0.5);
  assert.strictEqual(verdictOf(r, 1), 'hit');
  assert.strictEqual(pointsOf(r, 1), 1.0);

  // The TOTAL uses the effective values: 1.0 + 0.25.
  assert.strictEqual(r.score.final_points, 1.25);
  assert.strictEqual(r.score.false_positives, 0, 'the overridden FP no longer counts as one');
  assert.strictEqual(r.score.techniques_found, 2);

  // auto_points is still the scorer's own answer, floored: 1.0 - 0.5 = 0.5.
  assert.strictEqual(r.score.auto_points, 0.5);

  // A run-level total REPLACES the sum outright — that is what typing a number
  // into a gradebook means.
  const overridden = score(rows, { runOverridePoints: 7 });
  assert.strictEqual(overridden.score.final_points, 7);
  assert.strictEqual(overridden.score.override_points, 7);
  // And it does not disturb the diagnostics beside it.
  assert.strictEqual(overridden.score.techniques_found, 2);
});

// ---------------------------------------------------------------------------
// §7 Idempotence
// ---------------------------------------------------------------------------

test('E5-S9: re-scoring is byte-identical, so it is safe to press twice', () => {
  const rows = [
    finding({ technique_id: 'T1566.001', submitted_at: at(120) }),
    finding({ technique_id: 'T1110', submitted_at: at(200) }),
    finding({ technique_id: 'T1486', submitted_at: at(240) }),
    finding({ kind: 'ioc', ioc_type: 'ip', ioc_value: '203.0.113.11', submitted_at: at(260) }),
    finding({ kind: 'timeline', technique_id: 'T1566.001', observed_at: at(10) }),
    finding({ kind: 'timeline', technique_id: 'T1003.001', observed_at: at(120) }),
  ];
  const a = JSON.stringify(score(rows));
  const b = JSON.stringify(score(rows.slice().reverse()));
  assert.strictEqual(a, b, 'row order must not change a single number');

  const parsed = JSON.parse(a);
  // 1.0 (T1566.001) + 0 (T1110 partial) - 0.5 (T1486) + 0.5 (the IOC) = 1.0
  assert.strictEqual(parsed.score.final_points, 1);
  assert.strictEqual(parsed.score.techniques_total, 3);
  assert.strictEqual(parsed.score.techniques_found, 1);
  assert.strictEqual(parsed.score.techniques_missed, 2);
  assert.strictEqual(parsed.score.iocs_total, 2);
  assert.strictEqual(parsed.score.iocs_found, 1);
});

// ---------------------------------------------------------------------------
// §8 No key is not a zero
// ---------------------------------------------------------------------------

test('E5-S10: an empty answer key grades NOTHING rather than everything wrong', () => {
  // A Caldera run, or one whose compile failed. Treating {} as "the attack
  // contained nothing" would mark every correct answer a false positive and
  // hand the class negative scores for a server-side bug.
  const r = scoring.scoreRun({
    run,
    answerKey: {},
    findings: [
      finding({ technique_id: 'T1566.001' }),
      finding({ kind: 'ioc', ioc_type: 'ip', ioc_value: '203.0.113.11' }),
    ],
  });
  assert.strictEqual(r.graded, false);
  assert.deepStrictEqual(r.findings.map((f) => f.auto_verdict), ['unscored', 'unscored']);
  assert.strictEqual(r.score.false_positives, 0);
  assert.strictEqual(r.score.final_points, 0);
  assert.match(r.findings[0].auto_note, /no compiled answer key/i);
});

test('E5-S11: a key from a NEWER build is refused, not reinterpreted', () => {
  // A rolling deploy or a rollback. Reading a shape this build does not
  // understand with this build's rules produces numbers that look fine and are
  // wrong, and the only place that surfaces is a student's grade.
  assert.throws(
    () => scoring.scoreRun({
      run,
      answerKey: Object.assign({}, KEY, { version: ANSWER_KEY_VERSION + 1 }),
      findings: [],
    }),
    (err) => {
      assert.strictEqual(err.name, 'AnswerKeyVersionError');
      assert.strictEqual(err.code, 'ANSWER_KEY_VERSION');
      return true;
    }
  );
});
