/**
 * llm-json-repair.test.js — the repair pipeline, pinned against real failures.
 *
 * WHY THIS FILE EXISTS
 * Every CIAB generation flow asks Claude for JSON and parses the reply. When the
 * model emits JSON that is a character away from valid, the whole generation is
 * lost: profile generation throws "Organization branch failed", the caller gets a
 * 500, and the tokens already spent are gone. One observed run burned 82 seconds
 * and returned nothing because of a single missing comma.
 *
 * repairAndParseJson exists for exactly that, but it only ever handled the
 * failures someone had already seen. This file pins each one, so a future edit
 * to the repair chain cannot quietly drop a case that has cost a real run.
 *
 * THE PRODUCTION FAILURE THIS FILE WAS OPENED FOR
 *   2026-09-04 [clinic-api /generate] Organization branch failed:
 *   JSON parse failed after repair: Expected ',' or ']' after array element
 *   at position 9184
 * with the tail:
 *       "PCI scope and card-processing workflow"
 *       "History of attempted wire fraud incidents"]}]}
 *
 * The obvious reading — "the model dropped a comma" — was WRONG, and worth
 * recording because it is the reading anyone will reach for first. The model's
 * output was fine apart from being cut short. THE REPAIR DELETED THAT COMMA:
 * closeUnbalancedStructures tracked the last non-space character in a way that
 * skipped every character inside a string, so it mistook the comma before the
 * final element for a trailing one and removed it, then closed the brackets.
 * The `]}]}` in that log line is the repair's own handiwork.
 *
 * A repair that corrupts valid input is worse than no repair at all, because it
 * converts a recoverable document into an unrecoverable one and reports the
 * failure as the model's. Both halves are pinned below: the root-cause fix, and
 * the missing-comma strategy that genuinely was absent from the chain.
 *
 * Run: node --test front-end/test/llm-json-repair.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const llm = require(path.join(__dirname, '..', 'src', 'utils', 'llm-client.js'));
const { repairAndParseJson } = llm;

// ── The failure that opened this file ───────────────────────────────────────

test('a comma missing between two array elements is repaired', () => {
  const broken = [
    '{"organization":{"company_name":"Brandywine Mercantile",',
    '"asks":["Financial system access details",',
    '"List of staff with bank portal access",',
    '"PCI scope and card-processing workflow"',      // <- comma missing here
    '"History of attempted wire fraud incidents"]}}',
  ].join('\n');
  const out = repairAndParseJson(broken);
  assert.strictEqual(out.organization.asks.length, 4);
  assert.strictEqual(out.organization.asks[3], 'History of attempted wire fraud incidents');
});

test('a comma missing between two object members is repaired', () => {
  const out = repairAndParseJson('{"a":1\n"b":2}');
  assert.deepStrictEqual(out, { a: 1, b: 2 });
});

test('a comma missing before a nested object is repaired', () => {
  const out = repairAndParseJson('{"x":[{"a":1}\n{"b":2}]}');
  assert.deepStrictEqual(out, { x: [{ a: 1 }, { b: 2 }] });
});

test('commas missing around numbers and literals are repaired', () => {
  const out = repairAndParseJson('{"a":1\n"b":true\n"c":null\n"d":-2.5}');
  assert.deepStrictEqual(out, { a: 1, b: true, c: null, d: -2.5 });
});

// ── The repair must not be over-eager ───────────────────────────────────────
// A repair that inserts a comma where one does not belong turns a recoverable
// document into an unrecoverable one, which is strictly worse than not trying.

test('valid JSON is returned unchanged', () => {
  const src = { a: [1, 2, 3], b: { c: 'd' }, e: null, f: false };
  assert.deepStrictEqual(repairAndParseJson(JSON.stringify(src)), src);
});

test('a key/value colon is not mistaken for a value boundary', () => {
  assert.deepStrictEqual(repairAndParseJson('{"key" : "value"}'), { key: 'value' });
});

test('quotes and separators INSIDE a string are left alone', () => {
  // The state machine must not treat string contents as structure. A naive
  // regex would insert a comma inside the sentence below.
  const src = '{"note":"he said \\"one\\" then \\"two\\" and left"}';
  assert.strictEqual(repairAndParseJson(src).note, 'he said "one" then "two" and left');
});

test('a string containing a bracketed list is left alone', () => {
  const src = '{"note":"see [a] [b] for detail"}';
  assert.strictEqual(repairAndParseJson(src).note, 'see [a] [b] for detail');
});

test('an empty array or object is not given a spurious comma', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a":[],"b":{}}'), { a: [], b: {} });
});

// ── The pre-existing strategies still work ──────────────────────────────────

test('code fences are stripped', () => {
  assert.deepStrictEqual(repairAndParseJson('```json\n{"a":1}\n```'), { a: 1 });
});

test('trailing commas are dropped', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a":[1,2,],}'), { a: [1, 2] });
});

test('raw newlines inside a string are escaped', () => {
  const out = repairAndParseJson('{"a":"line one\nline two"}');
  assert.strictEqual(out.a, 'line one\nline two');
});

test('a truncated document is closed', () => {
  const out = repairAndParseJson('{"a":{"b":["one","two"');
  assert.deepStrictEqual(out.a.b, ['one', 'two']);
});

test('leading prose before the JSON is stripped', () => {
  assert.deepStrictEqual(repairAndParseJson('Here you go:\n{"a":1}'), { a: 1 });
});

// ── The root cause: a repair that CORRUPTED valid input ─────────────────

test('a truncated document does not lose a legitimate trailing-element comma', () => {
  // THE production bug. closeUnbalancedStructures updated lastNonSpace at the
  // BOTTOM of its loop, after every string branch had already continued — so no
  // character inside a string, including the quote that CLOSES one, ever moved
  // it. lastNonSpace therefore pointed at the comma BEFORE the final string,
  // and the "truly trailing comma" branch deleted it.
  //
  // The input below is valid JSON that was merely cut short. Before the fix the
  // repair returned it a comma poorer and unparseable — which is exactly the
  // tail the 2026-09-04 log showed.
  const truncated = '{"asks":["PCI scope and card-processing workflow",\n'
    + '"History of attempted wire fraud incidents"';
  const out = repairAndParseJson(truncated);
  assert.deepStrictEqual(out.asks, [
    'PCI scope and card-processing workflow',
    'History of attempted wire fraud incidents',
  ]);
});

test('a genuinely trailing comma is still dropped', () => {
  // The branch that caused the bug is still needed; it just has to fire on a
  // real trailing comma rather than on the one before the last element.
  assert.deepStrictEqual(repairAndParseJson('{"a":[1,2,'), { a: [1, 2] });
  assert.deepStrictEqual(repairAndParseJson('{"a":["x","y",'), { a: ['x', 'y'] });
});

// ── The strategies must compose ─────────────────────────────────────────────

test('a fenced, comma-missing, truncated document is still recovered', () => {
  // Each strategy handles one defect; the value is in them composing, because a
  // model that drops a comma is also the model that fences and runs long.
  const out = repairAndParseJson('```json\n{"a":["one"\n"two"\n"three"');
  assert.deepStrictEqual(out.a, ['one', 'two', 'three']);
});
