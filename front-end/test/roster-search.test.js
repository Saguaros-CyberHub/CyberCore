/**
 * Tests for the student search on the VM Management and Environments tabs
 * (cle/public/pages/courses.html)
 *
 * A search that merely hides rows is harmless. A search sitting on top of a
 * multi-select whose buttons are Delete and Tear down is not, and the hazard is
 * specific: filter, tick some rows, change the filter, press Delete. Whatever
 * the number in the confirm says had better be what actually gets destroyed.
 *
 * The design these pin:
 *
 *   1. Filtering changes what is RENDERED, never what is SELECTED. A row ticked
 *      and then filtered out is still in the Set and is still acted on — because
 *      ticking it was a deliberate act and silently discarding it would be worse
 *      — so the bulk bar has to report it. Both bars add a "(N hidden by search)"
 *      note for exactly this.
 *
 *   2. Select-all is scoped to what is on screen. Ticking it under an active
 *      search must never reach the rows the search hid.
 *
 *   3. Clear really clears. clearLabSelection is per-environment and used to
 *      delete only the keys with a checkbox in the DOM, which under a search
 *      left the hidden ones selected — so the bar still read "3 selected"
 *      straight after Clear and the next Tear down would have taken them.
 *
 *   4. The search box lives OUTSIDE the re-rendered container. Both tables
 *      rebuild their innerHTML every 8s while anything is deploying; an input
 *      inside that would lose its value and caret mid-keystroke.
 *
 *   5. The poll re-arms on the UNFILTERED set, so a search cannot freeze a table
 *      that is still changing.
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
  return src.slice(start, open) + src.slice(open, i + 1);
}

// eslint-disable-next-line no-new-func
const _matchesSearch = new Function(`${extractFn('_matchesSearch')} return _matchesSearch;`)();

const ROW = ['Jacob', 'Williams', 'jacoblwilliams@arizona.edu', 'Windows 11 Base Template', 'vxlan 10582'];

// ── the matcher ─────────────────────────────────────────────────────────────

test('an empty search matches everything', () => {
  assert.strictEqual(_matchesSearch(ROW, ''), true);
  assert.strictEqual(_matchesSearch(ROW, null), true);
  assert.strictEqual(_matchesSearch([], ''), true);
});

test('matching is case-insensitive across every field', () => {
  assert.strictEqual(_matchesSearch(ROW, 'JACOB'), true);
  assert.strictEqual(_matchesSearch(ROW, 'williams'), true);
  assert.strictEqual(_matchesSearch(ROW, 'ARIZONA.EDU'), true);
  assert.strictEqual(_matchesSearch(ROW, 'windows 11'), true);
  assert.strictEqual(_matchesSearch(ROW, '10582'), true);
});

test('multiple terms narrow rather than widen, in any order', () => {
  // AND, not OR: "jacob wil" must not start matching every Williams in the class.
  assert.strictEqual(_matchesSearch(ROW, 'jacob wil'), true);
  assert.strictEqual(_matchesSearch(ROW, 'wil jacob'), true, 'term order must not matter');
  assert.strictEqual(_matchesSearch(ROW, 'jacob smith'), false);
});

test('a term never matches ACROSS two fields', () => {
  // Fields are joined with a space, so the end of one and the start of the next
  // do not form a match — "williamsjacob" is not a real substring of anything.
  assert.strictEqual(_matchesSearch(['Jacob', 'Williams'], 'jacobwilliams'), false);
});

test('extra whitespace is ignored', () => {
  assert.strictEqual(_matchesSearch(ROW, '   jacob    williams   '), true);
  assert.strictEqual(_matchesSearch(ROW, '   '), true, 'blank input is not a filter');
});

test('null and undefined fields are skipped, not stringified', () => {
  // A row with no VXLAN would otherwise contain the literal text "null" and
  // match a search for it.
  assert.strictEqual(_matchesSearch(['a@x.edu', null, undefined], 'null'), false);
  assert.strictEqual(_matchesSearch(['a@x.edu', null], 'a@x'), true);
});

// ── selection safety, at the source level ───────────────────────────────────

function fn(name) { return extractFn(name); }

test('both bulk bars report selected rows the search is hiding', () => {
  // Without this the instructor reads "3 selected", presses Delete, and destroys
  // five lanes.
  for (const name of ['_syncVMBulkBar', '_syncLabBulkBar']) {
    const body = fn(name);
    assert.match(body, /hidden/i, `${name} must account for hidden-but-selected rows`);
    assert.match(body, /bulk-hidden-note/, `${name} must surface the hidden count`);
  }
});

test('both select-alls are scoped to the visible rows', () => {
  // They compute their checked/indeterminate state from `visible`, never from
  // the total selection — ticking select-all under a search must not reach the
  // rows the search hid.
  for (const name of ['_syncVMBulkBar', '_syncLabBulkBar']) {
    const body = fn(name);
    assert.match(body, /all\.checked = total > 0 && visible === total/,
      `${name}'s select-all must key on the visible count`);
    assert.match(body, /all\.indeterminate = visible > 0 && visible < total/);
  }
});

test('the actions read the UNFILTERED row list, so a hidden selection is honoured', () => {
  // _selectedVMRows / _selectedLabRows filter the full fetched set by the Set —
  // never the rendered DOM — so a deliberate tick survives a filter change.
  assert.match(fn('_selectedVMRows'), /_vmRows\.filter/);
  assert.match(fn('_selectedLabRows'), /_labRowsByLab\[labId\]/);
});

test('Clear drops hidden selections too', () => {
  // The bug this pins: clearLabSelection used to delete only the keys with a
  // checkbox on screen, leaving hidden rows selected after Clear.
  const lab = fn('clearLabSelection');
  assert.match(lab, /_labSelected\]\.forEach/,
    'clearLabSelection must sweep the Set, not just the rendered checkboxes');
  assert.match(lab, /startsWith\(prefix\)/, 'and it must stay scoped to one environment');
  // The VM tab has a single table, so clearing the whole Set is correct there.
  assert.match(fn('clearVMSelection'), /_vmSelected\.clear\(\)/);
});

// ── render plumbing ─────────────────────────────────────────────────────────

test('both search inputs live outside the re-rendered container', () => {
  // Both tables replace their innerHTML every 8s while anything is deploying. An
  // input inside that would lose its value and caret mid-keystroke.
  for (const [inputId, containerId] of [['vmSearch', 'vmManagementContent'], ['labSearch', 'vulnerableLabsContent']]) {
    const inputAt = src.indexOf(`id="${inputId}"`);
    const containerAt = src.indexOf(`<div id="${containerId}">`);
    assert.notStrictEqual(inputAt, -1, `${inputId} not found`);
    assert.notStrictEqual(containerAt, -1, `${containerId} not found`);
    assert.ok(inputAt < containerAt,
      `${inputId} must be rendered before (outside) #${containerId}`);
  }
});

test('typing filters without refetching', () => {
  // The whole point of the fetch/render split: a keystroke must not hit the API.
  for (const [handler, renderer] of [['onVMSearch', 'renderVMManagement'], ['onLabSearch', 'renderVulnerableLabs']]) {
    const body = fn(handler);
    assert.match(body, new RegExp(renderer + '\\(\\)'), `${handler} must re-render`);
    assert.ok(!/\bapi\(/.test(body), `${handler} must not call the API`);
    assert.ok(!/load(VMManagement|VulnerableLabs)\(/.test(body),
      `${handler} must not trigger a fetch`);
  }
});

test('the auto-refresh re-arms on the unfiltered set', () => {
  // A search must never stop a table that is still changing from updating.
  const vmLoad = fn('loadVMManagement');
  assert.match(vmLoad, /vms\.some\(v => v\.lane_status === 'deploying'\)/);
  assert.ok(!/renderVMManagement[\s\S]*_vmSearch[\s\S]*setTimeout/.test(vmLoad),
    'the re-arm must not be gated on the filtered rows');

  const labLoad = fn('loadVulnerableLabs');
  assert.match(labLoad, /labs\.some\(l => l\.in_progress\)/);
});

test('an empty result tells you which kind of empty it is', () => {
  // "Nothing matches your search" and "nothing is deployed" are different facts,
  // and showing the second when the first is true reads as data loss.
  assert.match(fn('renderVMManagement'), /No students match/);
  assert.match(fn('renderVMManagement'), /No workstation VMs provisioned yet/);
  assert.match(fn('renderVulnerableLabs'), /No students match/);
  assert.match(fn('renderVulnerableLabs'), /No environments deployed yet/);
});
