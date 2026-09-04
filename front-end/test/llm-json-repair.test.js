/**
 * llm-json-repair.test.js — the repair pipeline, pinned against real failures.
 *
 * WHY THIS FILE EXISTS
 * Every CIAB generation flow asks Claude for JSON and parses the reply. When the
 * reply is a character away from valid, the whole generation is lost: profile
 * generation throws "Organization branch failed", the caller gets a 500, and the
 * ~80 seconds of tokens already spent are gone.
 *
 * TWO PRODUCTION FAILURES, ONE DAY APART, AND WHAT THEY TAUGHT
 *
 * 1) 2026-09-04 01:00 — "Expected ',' or ']' after array element at position 9184",
 *    tail: "PCI scope and card-processing workflow"
 *          "History of attempted wire fraud incidents"]}]}
 *
 *    The obvious reading is "the model dropped a comma". It is WRONG, and worth
 *    recording because it is the reading anyone reaches for first. The model's
 *    output was fine apart from being cut short. THE REPAIR DELETED THAT COMMA:
 *    closeUnbalancedStructures updated `lastNonSpace` at the bottom of its loop,
 *    after both string branches had already `continue`d, so no character inside a
 *    string — including the quote that CLOSES one — ever moved it. It therefore
 *    pointed at the comma before the final element, and the "trailing comma"
 *    branch removed it. The `]}]}` in that log is the repair's own handiwork.
 *
 * 2) 2026-09-04 01:39 — "Expected double-quoted property name at position 260".
 *
 *    Caused by the FIX for (1): a speculative "insert a missing comma" strategy
 *    added in the same change. It treated every digit as a complete value, so
 *    `{"employee_count": 45}` became `{"employee_count": 4,5}` and every profile
 *    with a multi-digit number failed. It was removed; see the note above
 *    closeUnbalancedStructures in llm-client.js.
 *
 * THE LESSON BOTH TAUGHT, which is why this file is thorough about the negative
 * cases: a repair that corrupts valid input is worse than no repair. It turns a
 * recoverable document into an unrecoverable one and blames the model. Every
 * strategy here must therefore be tested on input it should NOT touch, not only
 * on the input it is meant to fix.
 *
 * Run: node --test front-end/test/llm-json-repair.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const llm = require(path.join(__dirname, '..', 'src', 'utils', 'llm-client.js'));
const { repairAndParseJson } = llm;

// ── Failure 1: the repair must not delete a comma that is doing work ────────

test('a truncated document keeps its legitimate trailing-element comma', () => {
  // Valid JSON, merely cut short. Before the fix this came back a comma poorer
  // and unparseable — exactly the 01:00 log.
  const truncated = '{"asks":["PCI scope and card-processing workflow",\n'
    + '"History of attempted wire fraud incidents"';
  assert.deepStrictEqual(repairAndParseJson(truncated).asks, [
    'PCI scope and card-processing workflow',
    'History of attempted wire fraud incidents',
  ]);
});

test('a genuinely trailing comma is still dropped', () => {
  // The branch that caused failure 1 is still needed — it just has to fire on a
  // real trailing comma rather than the one before the last element.
  assert.deepStrictEqual(repairAndParseJson('{"a":[1,2,'), { a: [1, 2] });
  assert.deepStrictEqual(repairAndParseJson('{"a":["x","y",'), { a: ['x', 'y'] });
  assert.deepStrictEqual(repairAndParseJson('{"a":[1,2,],}'), { a: [1, 2] });
});

// ── Failure 2: numbers must survive the pipeline intact ─────────────────────
// These are the cases whose absence let the digit-splitting bug ship. A single
// -2.5 and a single 1 both passed; 45 did not exist in the suite.

test('multi-digit numbers survive intact', () => {
  assert.deepStrictEqual(repairAndParseJson('{"employee_count": 45}'), { employee_count: 45 });
  assert.deepStrictEqual(repairAndParseJson('{"a": 1234567}'), { a: 1234567 });
  assert.deepStrictEqual(repairAndParseJson('{"a": 10, "b": 20, "c": 300}'),
    { a: 10, b: 20, c: 300 });
});

test('decimals, negatives and exponents survive intact', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a": -2.5, "b": 1.25, "c": 1e3, "d": -1.5e-2}'),
    { a: -2.5, b: 1.25, c: 1e3, d: -1.5e-2 });
});

test('literals survive intact', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a": true, "b": false, "c": null}'),
    { a: true, b: false, c: null });
});

test('a realistic org branch payload round-trips', () => {
  // The shape that actually failed at 01:39.
  const src = '{"organization":{"company_name":"Mesquite Holdings",'
    + '"employee_count":45,"naics_hint":"541990","revenue_usd":12500000,'
    + '"sites":[{"city":"Tucson","staff":30},{"city":"Phoenix","staff":15}]}}';
  const out = repairAndParseJson(src);
  assert.strictEqual(out.organization.employee_count, 45);
  assert.strictEqual(out.organization.revenue_usd, 12500000);
  assert.strictEqual(out.organization.sites[1].staff, 15);
});

// ── Valid input must come back untouched ────────────────────────────────────

test('valid JSON is returned unchanged', () => {
  const src = { a: [1, 2, 3], b: { c: 'd' }, e: null, f: false, g: 45, h: -2.5 };
  assert.deepStrictEqual(repairAndParseJson(JSON.stringify(src)), src);
});

test('structure characters INSIDE strings are left alone', () => {
  const src = '{"note":"he said \\"one\\" then \\"two\\", see [a] {b} 1,2 and left"}';
  assert.strictEqual(repairAndParseJson(src).note,
    'he said "one" then "two", see [a] {b} 1,2 and left');
});

test('empty containers are left alone', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a":[],"b":{}}'), { a: [], b: {} });
});

// ── The strategies that were always here ────────────────────────────────────

test('code fences are stripped', () => {
  assert.deepStrictEqual(repairAndParseJson('```json\n{"a":1}\n```'), { a: 1 });
});

test('raw newlines inside a string are escaped', () => {
  assert.strictEqual(repairAndParseJson('{"a":"line one\nline two"}').a, 'line one\nline two');
});

test('leading prose before the JSON is stripped', () => {
  assert.deepStrictEqual(repairAndParseJson('Here you go:\n{"a":1}'), { a: 1 });
});

test('a document truncated mid-string is closed', () => {
  // The 01:39 payload was cut mid-word ("unadd" for "unaddressed").
  const out = repairAndParseJson(
    '{"gaps":["Shadow IT tools are unknown to IT leadership and unadd');
  assert.strictEqual(out.gaps.length, 1);
  assert.ok(out.gaps[0].endsWith('unadd'));
});

test('a truncated nested document is closed', () => {
  assert.deepStrictEqual(repairAndParseJson('{"a":{"b":["one","two"').a.b, ['one', 'two']);
});

// ── The guard that keeps this file honest ───────────────────────────────────

test('no repair strategy rewrites a number', () => {
  // A blunt property check across the whole chain: for a range of numeric
  // payloads, whatever comes out must equal what went in. This is the assertion
  // whose absence let the digit-splitting bug reach production.
  for (const n of [0, 1, 7, 45, 100, 1234, 999999, 12500000, -3, -45, 0.5, -2.5, 1e3]) {
    const src = `{"v":${JSON.stringify(n)}}`;
    assert.deepStrictEqual(repairAndParseJson(src), { v: n },
      `repair chain altered ${src}`);
  }
});
