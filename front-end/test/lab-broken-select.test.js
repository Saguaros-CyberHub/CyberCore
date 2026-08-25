/**
 * Tests for "Select N broken" on the Environments tab
 * (cle/public/pages/courses.html)
 *
 * The VM tab's equivalent keys on one field, `lane_status === 'error'`. An
 * environment can be broken in three distinct ways, and the third is the one
 * that matters most and is easiest to miss:
 *
 *   lane_status 'error' — the deploy itself failed.
 *   _failed             — a PREVIOUS redeploy failed. Persisted in
 *                         cle_course_material.content.redeploy_errors, so it
 *                         outlives the hour-long progress entry and a restart.
 *   _detached           — torn down and never rebuilt. There is NO deployment
 *                         row for these students; before this change they were
 *                         rendered as a read-only footnote with no checkbox, so
 *                         the students with literally nothing were the only ones
 *                         who could not be fixed in bulk.
 *
 * The other thing pinned here: the quick-select reads the row STATE, not the
 * DOM. A "select all broken" that quietly skipped the rows an active search was
 * hiding would be a trap — the bar's count would disagree with what the button
 * just did.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const PAGE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'public', 'pages', 'courses.html'
);
const src = fs.readFileSync(PAGE, 'utf8');

function extractFn(name) {
  const start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in courses.html — renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}

// eslint-disable-next-line no-new-func
const { _labRowBroken, _labSelectable } = new Function(
  `${extractFn('_labRowBroken')}
   ${extractFn('_labSelectable')}
   return { _labRowBroken, _labSelectable };`
)();

const row = (over = {}) => ({ user_id: 'u1', lane_status: 'active', ...over });

// ── what counts as broken ───────────────────────────────────────────────────

test('a healthy deployment is not broken', () => {
  assert.strictEqual(_labRowBroken(row()), false);
});

test('a failed deploy is broken', () => {
  assert.strictEqual(_labRowBroken(row({ lane_status: 'error' })), true);
});

test('a previously-failed redeploy is broken even though the lane looks active', () => {
  // The lane row can be perfectly healthy while the student is missing machines
  // a redeploy never rebuilt. redeploy_errors is the only record of that, and it
  // is persisted precisely so it survives the progress entry ageing out.
  assert.strictEqual(_labRowBroken(row({ lane_status: 'active', _failed: true })), true);
});

test('a student torn down and never rebuilt is broken', () => {
  // The most broken state there is — they have nothing — and the one with no
  // deployment row of its own.
  assert.strictEqual(_labRowBroken(row({ _detached: true, lane_status: null })), true);
});

// ── what may be acted on ────────────────────────────────────────────────────

test('a detached row is selectable, so it can be fixed in bulk', () => {
  // The whole point of collecting these into _labRowsByLab. Rebuilding twenty of
  // them one at a time is exactly the problem the bulk bar exists to solve.
  assert.strictEqual(_labSelectable(row({ _detached: true, lane_status: null })), true);
});

test('anything already working is excluded from both sides', () => {
  // Tearing down mid-rebuild races the deployer; rebuilding something already
  // being built is nonsense.
  assert.strictEqual(_labSelectable(row({ _busy: true, lane_status: 'error' })), false);
  assert.strictEqual(_labSelectable(row({ lane_status: 'deploying' })), false);
});

test('a row with no user id is never selectable', () => {
  assert.strictEqual(_labSelectable(row({ user_id: null })), false);
});

// ── the quick-select itself ─────────────────────────────────────────────────

test('the quick-select reads row state, not the rendered checkboxes', () => {
  // Reading the DOM would silently skip every broken row an active search is
  // hiding, so the button would disagree with the count beside it.
  const fn = extractFn('selectBrokenLabRows');
  assert.match(fn, /_labRowsByLab\[labId\]/,
    'must read the fetched rows, not document.querySelectorAll');
  assert.ok(!/querySelectorAll/.test(fn),
    'reading the DOM would skip rows hidden by the search');
});

test('the quick-select is additive and never clears a hand-built selection', () => {
  // "I hand-picked two, now add all the broken ones" is the real flow.
  const fn = extractFn('selectBrokenLabRows');
  assert.match(fn, /_labSelected\.add\(/);
  assert.ok(!/_labSelected\.clear\(\)/.test(fn), 'it must not wipe the existing selection');
  assert.ok(!/\.delete\(/.test(fn), 'it only ever adds');
});

test('the quick-select only picks rows that are both broken AND actionable', () => {
  const fn = extractFn('selectBrokenLabRows');
  assert.match(fn, /_labSelectable\(d\) && _labRowBroken\(d\)/);
});

test('detached rows are collected into the selectable set at fetch time', () => {
  // If they only existed in the render, _selectedLabRows could not return them
  // and a bulk action would silently drop them.
  const load = extractFn('loadVulnerableLabs');
  assert.match(load, /_detached: true/);
  assert.match(load, /if \(haveRow\.has\(uid\) \|\| inFlight\[uid\]\) return;/,
    'a student who already has a row, or is mid-flight, must not be duplicated');
});
