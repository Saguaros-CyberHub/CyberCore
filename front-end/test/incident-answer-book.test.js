'use strict';

const test = require('node:test');
const assert = require('node:assert');

const runner = require('../src/incident/runner');
const book = require('../src/incident/answer-book');

const RUN_ID = '3f2a1c88-9d4e-4b7a-8c11-55e6a1b0d7f2';

function bookFor(technique, seconds = 1800, runId = RUN_ID) {
  const selection = runner.resolveSelection({
    mode: 'technique', technique_id: technique, duration_seconds: seconds,
  });
  return book.buildAnswerBook(
    { run_id: runId, duration_seconds: seconds, mode: 'technique', technique_id: technique },
    { playbook: runner.playbookFor(selection) }
  );
}

test('the book describes the same attack every lane received', () => {
  // The whole premise. cc-emit seeds from the run id, so the book is only worth
  // marking against if recompiling it reproduces what the guests ran. If this
  // ever drifts, an instructor marks against an attack that never happened and
  // every correct student answer reads as a false positive -- with no symptom
  // short of someone noticing the numbers disagree.
  const a = bookFor('T1110.001');
  const b = bookFor('T1110.001');
  assert.deepEqual(a.activity, b.activity);
  assert.deepEqual(a.adversary, b.adversary);
  assert.equal(a.totals.events_per_lane, b.totals.events_per_lane);

  const other = bookFor('T1110.001', 1800, '8c4d0e11-2f6b-4a33-9e77-0b1c2d3e4f55');
  assert.notDeepEqual(other.adversary, a.adversary,
    'a different run id must produce a different adversary, or every week is the same attack');
});

test('every event is accounted for in the activity groups', () => {
  // An instructor reading "2,940 events" and seeing groups that sum to 2,100
  // cannot tell which 840 are missing or whether the book is simply wrong. The
  // projection has to be total or it is not evidence.
  for (const tech of ['T1110.001', 'T1005', 'T1018']) {
    const b = bookFor(tech);
    const summed = b.activity.reduce((n, a) => n + a.event_count, 0);
    assert.equal(summed, b.totals.events_per_lane, `${tech}: groups do not sum to the total`);
  }
});

test('messages collapse to the sentences the attack actually says', () => {
  // Ports, pids and byte counts are random per event, so a raw frequency table
  // over messages is thousands of rows of one. Collapsing the variable parts is
  // what makes the book readable at all.
  assert.equal(
    book.patternOf('Failed password for jsmith from 203.0.113.4 port 54611 ssh2'),
    book.patternOf('Failed password for jsmith from 203.0.113.4 port 40421 ssh2')
  );

  // Addresses are replaced as a UNIT, and before bare digits. Two addresses in
  // the same sentence ARE one message shape and should group -- what matters is
  // that the token stays readable. Digit-first replacement renders every address
  // as '#.#.#.#', which tells a reader nothing about what varied.
  assert.equal(book.patternOf('from 203.0.113.4 port 1'), 'from <addr> port #');
  assert.ok(!book.patternOf('from 203.0.113.4 port 1').includes('#.#'),
    'an address was eaten one component at a time');

  const b = bookFor('T1110.001');
  const patterns = b.activity.reduce((n, a) => n + a.messages.length, 0);
  assert.ok(patterns < 30, `${patterns} distinct message shapes is not a readable book`);
  for (const a of b.activity) {
    for (const m of a.messages) {
      assert.ok(m.examples.length > 0, 'a pattern with no worked example is not evidence');
      assert.ok(!/\{\{/.test(m.examples[0]), 'an unexpanded token reached the book');
    }
  }
});

test('every query is exact, and says how many events it must return', () => {
  // The count is the point: it turns "did this lane ingest the attack" from a
  // judgement into a check the instructor makes in one paste.
  const b = bookFor('T1110.001');
  assert.ok(b.queries.length, 'no queries at all leaves the instructor guessing');
  for (const q of b.queries) {
    assert.ok(q.kql.includes('loggen.'), 'a query must name the indexed field path');
    assert.ok(Number.isInteger(q.expect_events) && q.expect_events > 0,
      `query "${q.kql}" promises ${q.expect_events} events`);
  }
});

test('the queries are keyed on indicators, never on an oracle field', () => {
  // log.file.path and data_stream.dataset were removed from the index on
  // purpose: each separated attack from benign in one click. A query here that
  // leaned on one would work perfectly and quietly re-document the oracle the
  // telemetry design exists to close.
  const b = bookFor('T1005');
  for (const q of b.queries) {
    for (const banned of ['log.file.path', 'data_stream.dataset', 'loggen.mitre']) {
      assert.ok(!q.kql.includes(banned), `answer-book query leans on the ${banned} oracle`);
    }
  }
});

test('benign look-alikes travel with the book', () => {
  // The floor emits from the same (type, name) pairs as the attacks and tags
  // some of its own events with real technique ids. An instructor who does not
  // know which ones marks a defensible answer wrong.
  const b = bookFor('T1110.001');
  assert.ok(b.look_alikes.length, 'no look-alikes for a technique the floor also emits');
  assert.ok(b.look_alikes.some((l) => l.technique),
    'the floor tags benign events; the book must say which');
});

test('a KQL phrase cannot be broken by the value inside it', () => {
  // Built from char codes so the assertion says exactly what it means and does
  // not depend on how this file was written to disk.
  const BS = String.fromCharCode(92);
  const QT = String.fromCharCode(34);
  assert.equal(book.kqlValue('a' + QT + 'b'), 'a' + BS + QT + 'b');
  assert.equal(book.kqlValue('C:' + BS + 'Windows'), 'C:' + BS + BS + 'Windows');
});

test('chains produce a book too, spanning several techniques', () => {
  // Chains are keyed WITHOUT the 'chain-' filename prefix in the catalog; the
  // playbook file is chain-ransomware-ryuk.json.
  const selection = runner.resolveSelection({ mode: 'chain', chain_key: 'ransomware-ryuk' });
  const pb = runner.playbookFor(selection);
  assert.ok(pb, 'the ransomware chain playbook did not resolve');
  const b = book.buildAnswerBook(
    { run_id: RUN_ID, duration_seconds: null, mode: 'chain', chain_key: 'ransomware-ryuk' },
    { playbook: pb }
  );
  assert.ok(b.totals.events_per_lane > 0);
  assert.ok(b.techniques.length > 1, 'a chain reporting one technique is not a chain');
});
