/**
 * deploy-student-picker.test.js -- the "Deploy to" roster in Deploy Environment.
 *
 * The picker answers one question: who still needs this? On a 30-student roster
 * that used to mean reading names, so each row now carries what that student
 * already has, and the list can be searched and filtered to exactly the gap.
 *
 * THE HAZARD, and why this file exists
 * A search sitting on top of a multi-select whose button DEPLOYS is the same
 * shape as the VM/Environments bulk bars, and test/roster-search.test.js already
 * pins the contract for those:
 *
 *   1. Filtering changes what is RENDERED, never what is SELECTED. A row ticked
 *      then filtered out is still acted on -- so the UI has to SAY so.
 *   2. Select-all is scoped to what is on screen.
 *   3. Clear really clears.
 *
 * This picker adds a fourth of its own, and it is the one with teeth:
 *
 *   4. A student who already holds the selection renders `checked disabled` so
 *      the row reads as covered. `:checked` MATCHES a disabled box, so any DOM
 *      query for the selection would silently include every already-covered
 *      student in the deploy. Selection must come from state.
 *
 * Source assertions plus the real coverage function, lifted out of the page --
 * the same idiom roster-search.test.js and provision-slots.test.js use.
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
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
// LF-normalised: git checks this page out as CRLF on Windows, and every
// brace-match below would stop matching without saying why.
const src = fs.readFileSync(PAGE, 'utf8').split(CRLF).join(LF);

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

/**
 * envStudentStatus reads four page globals. Injecting them is what lets the real
 * function be exercised against made-up rosters instead of a copy of its rules.
 */
function statusFn({ wsOnly = false, template = null, vms = [], labs = [] } = {}) {
  // eslint-disable-next-line no-new-func
  return new Function(
    'isWorkstationOnly', 'selectedVulnTemplate', '_provisionExistingVMs', '_envLabDeployments',
    `${extractFn('envStudentStatus')} return envStudentStatus;`
  )(() => wsOnly, () => template, vms, labs);
}

const ENV = { template_id: 'env-cybr400' };
const STUDENT = { user_id: 'u1', email: 'a@x.edu' };

// -- rule 4: coverage is relative to the CURRENT selection -------------------

test('a student with nothing is never covered', () => {
  const st = statusFn({ template: ENV })(STUDENT);
  assert.strictEqual(st.covered, false);
  assert.strictEqual(st.tag, null);
});

test('holding THIS environment covers them', () => {
  const st = statusFn({
    template: ENV,
    labs: [{ template_id: 'env-cybr400', user_id: 'u1', lane_status: 'active' }],
  })(STUDENT);
  assert.strictEqual(st.covered, true);
  assert.match(st.tag, /already has this/);
});

test('holding a DIFFERENT environment does NOT cover them', () => {
  // The whole point of the picker is finding who needs THIS one. Treating any
  // environment as coverage would hide exactly the people who need deploying.
  const st = statusFn({
    template: ENV,
    labs: [{ template_id: 'env-other', user_id: 'u1', lane_status: 'active' }],
  })(STUDENT);
  assert.strictEqual(st.covered, false);
  assert.match(st.tag, /another environment/);
});

test('a workstation does not cover an environment, but is still worth saying', () => {
  const st = statusFn({
    template: ENV,
    vms: [{ user_id: 'u1', lane_status: 'active' }],
  })(STUDENT);
  assert.strictEqual(st.covered, false);
  assert.match(st.tag, /workstation/);
});

test('an environment does not cover a WORKSTATION-only deploy', () => {
  const st = statusFn({
    wsOnly: true,
    labs: [{ template_id: 'env-cybr400', user_id: 'u1', lane_status: 'active' }],
  })(STUDENT);
  assert.strictEqual(st.covered, false);
});

test('a workstation covers a workstation-only deploy', () => {
  const st = statusFn({ wsOnly: true, vms: [{ user_id: 'u1', lane_status: 'active' }] })(STUDENT);
  assert.strictEqual(st.covered, true);
});

// -- a FAILED deploy is not coverage ----------------------------------------

test('THE TRAP: a failed lane reads as needing one, not as covered', () => {
  // Covered rows are checked-disabled and hidden by the "Needs one" filter. A
  // failed deploy counted as coverage would make the ONE student whose deploy
  // broke the single person the instructor cannot select to retry.
  const st = statusFn({
    template: ENV,
    labs: [{ template_id: 'env-cybr400', user_id: 'u1', lane_status: 'error' }],
  })(STUDENT);
  assert.strictEqual(st.covered, false);
  assert.match(st.tag, /failed/);
});

test('a failed workstation likewise reads as needing one', () => {
  const st = statusFn({ wsOnly: true, vms: [{ user_id: 'u1', lane_status: 'error' }] })(STUDENT);
  assert.strictEqual(st.covered, false);
  assert.match(st.tag, /failed/);
});

// -- rule 4, at the source level --------------------------------------------

test('the selection is read from STATE, never from a DOM :checked query', () => {
  // `:checked` matches a disabled box. A DOM query would deploy to everyone who
  // already has it.
  const fn = extractFn('selectedEnvStudentIds');
  assert.ok(/_envStudents\s*$/m.test(fn) || fn.includes('_envStudents'),
    'selection must come from the roster state');
  assert.ok(fn.includes('_envSelected.has'), 'and from the selection Set');
  assert.ok(fn.includes('envStudentStatus'),
    'covered students must be filtered out even if they were ticked before the switch');
  assert.ok(!/querySelectorAll/.test(fn), 'must not read the DOM for the selection');
});

test('no deploy path reads the selection out of the DOM', () => {
  const queries = src.match(/querySelectorAll\([^)]*modal-student-select[^)]*\)/g) || [];
  for (const q of queries) {
    assert.ok(!q.includes(':checked'),
      `a :checked query would include covered-and-disabled students: ${q}`);
  }
});

test('both deploy paths go through the same resolver', () => {
  for (const fn of ['readDeployEnvForm', 'provisionVMs']) {
    assert.ok(extractFn(fn).includes('selectedEnvStudentIds()'),
      `${fn} must resolve targets through selectedEnvStudentIds`);
  }
});

// -- rules 1-3: the house search contract -----------------------------------

test('filtering never mutates the selection', () => {
  const fn = extractFn('renderEnvStudents');
  assert.ok(!/_envSelected\.(add|delete|clear)/.test(fn),
    'render must not add to or remove from the selection Set');
});

test('a selection hidden by the search is disclosed, not silently carried', () => {
  // Rule 1. Same `(N hidden by search)` note the VM and Environments bulk bars
  // carry, so the three read alike.
  const fn = extractFn('renderEnvStudents');
  assert.ok(fn.includes('hidden by search'), 'the summary must report hidden selections');
  assert.ok(fn.includes('bulk-hidden-note'), 'and use the page-wide style for it');
});

test('select-all is scoped to what is on screen', () => {
  // Rule 2.
  const fn = extractFn('toggleEnvSelectAll');
  assert.ok(fn.includes('#deployEnvStudents'), 'scoped to this container');
  assert.ok(fn.includes(':not(:disabled)'), 'and never reaches covered rows');
});

test('clear really clears', () => {
  // Rule 3.
  const fn = extractFn('clearEnvStudentSearch');
  assert.ok(fn.includes("value = ''"));
  assert.ok(fn.includes('onEnvStudentSearch'), 'and re-renders through the same path as typing');
});

test('the picker reuses the page-wide search component', () => {
  const modal = src.slice(src.indexOf('id="deployEnvModal"'), src.indexOf('id="deployEnvStudents"'));
  assert.ok(modal.includes('class="roster-search"'),
    'so the three student searches on this page look and behave alike');
  assert.ok(modal.includes('roster-search-clear'), 'including the clear affordance');
});

// -- the counts answer the right question -----------------------------------

test('the summary counts the whole roster, not the filtered view', () => {
  // "How many still need one" must not change as the instructor types.
  const fn = extractFn('renderEnvStudents');
  assert.ok(/const needs = rows\.filter/.test(fn),
    'needs-count must derive from rows (everyone), not visible (the filtered view)');
});

test('staff rows are excluded from the needs count', () => {
  // The instructor is not a student who is missing a machine.
  assert.ok(/needs = rows\.filter\(r => !r\.status\.covered && !staffRow\(r\)\)/.test(
    extractFn('renderEnvStudents')));
});
