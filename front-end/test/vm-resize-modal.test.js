/**
 * vm-resize-modal.test.js -- the Resize Machines screen's contract.
 *
 * courses.html is a 4000-line page with no build step, so the rules most likely
 * to rot silently are asserted against the source itself -- the same approach
 * deploy-env-modal.test.js takes, and for the same reason: standing the page up
 * needs a browser, and what matters here is visible in the text.
 *
 * Four things this pins, each of which fails quietly rather than loudly:
 *
 *   1. THE ADMIN GATE. The resize button must be behind _canResize(). The
 *      server is the real gate, but an instructor handed a button that always
 *      403s is a bug report, and the check is one easy line to drop in a
 *      refactor.
 *
 *   2. NO DISK INPUT. Proxmox cannot shrink a volume, and growing one enlarges
 *      the block device without enlarging the filesystem inside it. A live disk
 *      field would let an admin ask for something the platform silently will not
 *      do.
 *
 *   3. THE COPY LEADS WITH WHAT IS KEPT. This dialog sits next to Redeploy,
 *      whose copy says "Anything saved inside the machines is lost." If the two
 *      read alike, nobody will trust the safe one -- and the entire point of the
 *      feature is that it is safe.
 *
 *   4. A SEPARATE POLL TIMER that re-reads its banner. #provisionProgressBanner
 *      lives inside #vmManagementContent, which loadVMManagement() replaces on
 *      its own 8s poll, so a cached element reference goes stale and the
 *      progress display stops updating with nothing to indicate why.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PAGE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'public', 'pages', 'courses.html'
);
// LF-normalised: git checks this page out as CRLF on Windows, and the slice
// assertions below would stop matching without saying why.
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
const src = fs.readFileSync(PAGE, 'utf8').split(CRLF).join(LF);

/** The body of a named function, by brace-matching. */
function fnBody(name) {
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in courses.html`);
  let depth = 0, i = src.indexOf('{', start);
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}

/** The resize modal's markup, from its overlay div to the next modal overlay. */
function resizeModalMarkup() {
  const start = src.indexOf('id="vmResizeModal"');
  assert.notStrictEqual(start, -1, 'vmResizeModal is not on the page');
  const next = src.indexOf('class="modal-overlay"', start + 1);
  return src.slice(start, next === -1 ? src.length : next);
}

// -- the admin gate ---------------------------------------------------------

test('the resize button is rendered only for an admin', () => {
  // Anchored to the render function, not to a slice between two markup strings:
  // `<table class="students-table">` appears five times in this page and the
  // first is well ABOVE the bulk bar, which silently produced an empty slice
  // and a test that passed on nothing.
  const bar = fnBody('renderVMManagement');
  assert.ok(bar.includes('vmBulkResizeBtn'), 'the bulk bar has no resize button');
  assert.ok(/_canResize\(\)\s*\?[\s\S]{0,200}vmBulkResizeBtn/.test(bar),
    'the resize button is not behind _canResize()');
});

test('_canResize reads the bare Auth binding, not window.Auth', () => {
  // THE BUG THAT HID THE BUTTON. app.js declares `const Auth = {...}` at the top
  // level of a classic script. Per spec, top-level let/const/class go into the
  // global DECLARATIVE environment record, not onto the global object — only
  // `var` and function declarations become properties of `window`. So `Auth`
  // resolves by name from this page and `window.Auth` is undefined, and a gate
  // written `window.Auth && Auth.user && ...` is false for everyone including
  // admins. The control then never renders, with nothing in the console.
  // Comments stripped first: the fix documents the trap by naming it, so a raw
  // substring check would match the warning rather than the code.
  const body = fnBody('_canResize').replace(/\/\/[^\n]*/g, '');
  assert.ok(!/window\.Auth/.test(body),
    'window.Auth is always undefined — this gate would hide the button from admins');
  assert.match(body, /typeof Auth !== 'undefined'/,
    'guard the bare binding with typeof, so the page cannot throw if app.js is absent');
});

test('_canResize tests for the admin role specifically', () => {
  const body = fnBody('_canResize');
  assert.match(body, /Auth\.user\.role === 'admin'/,
    'the gate must be the admin role, not merely "logged in"');
  assert.doesNotMatch(body, /instructor/,
    'instructors must NOT pass this gate — the server route is requireRole(admin)');
});

test('the entry point re-checks the gate rather than trusting the hidden button', () => {
  assert.match(fnBody('bulkResizeLanes'), /_canResize\(\)/);
});

test('the button is not styled as destructive', () => {
  const bar = fnBody('renderVMManagement');
  const from = bar.indexOf('vmBulkResizeBtn');
  const to = bar.indexOf('vmBulkRedeployBtn');
  assert.ok(from !== -1 && to > from, 'could not isolate the resize button markup');
  const btn = bar.slice(from, to);
  assert.ok(!btn.includes('#e53e3e') && !btn.includes('btn-danger'),
    'a resize destroys nothing and must not be coloured like Delete');
});

// -- no disk ----------------------------------------------------------------

test('the resize form offers cores and memory only', () => {
  const body = fnBody('_renderVMResizeFields');
  assert.match(body, /\['cores', 'memory_mb'\]/,
    'the field list must be exactly cores and memory_mb');
  assert.ok(!/'disk_gb'/.test(body.split('disabled')[0]),
    'disk_gb must not be an editable field');
});

test('the disk field is present but disabled, so its absence reads as deliberate', () => {
  const body = fnBody('_renderVMResizeFields');
  assert.match(body, /disabled/, 'show a disabled disk field rather than a gap');
  assert.match(body, /cannot be changed after deployment/i);
});

test('the request body can never carry disk_gb', () => {
  const body = fnBody('_vmResizeBody');
  assert.ok(!body.includes('disk_gb'), 'the wire format must not mention disk');
});

test('the modal explains WHY disk is excluded, not just that it is', () => {
  const modal = resizeModalMarkup();
  assert.match(modal, /shrink a disk/i);
  assert.match(modal, /filesystem/i);
});

// -- the copy ---------------------------------------------------------------

test('the dialog leads with what survives, because Redeploy next door does not', () => {
  const modal = resizeModalMarkup();
  assert.match(modal, /Nothing on these machines is lost/i);
  assert.match(modal, /files, installed software and configuration/i);
  // And the cost, stated rather than buried.
  assert.match(modal, /restarts?/i);
});

test('the running-machine warning names the reboot cost in full', () => {
  const body = fnBody('_syncVMResizePicker');
  assert.match(body, /will restart/i);
  assert.match(body, /disconnected/i);
  assert.match(body, /same details/i, 'connection details survive — say so, or nobody believes it');
  assert.match(body, /unsaved/i, 'the one thing that CAN be lost must be stated');
});

// -- two-step preview -------------------------------------------------------

test('the first submit only previews — confirm is a second, separate call', () => {
  assert.match(fnBody('submitVMResize'), /_vmResizeBody\(false\)/);
  assert.match(fnBody('_applyVMResize'), /_vmResizeBody\(true\)/);
});

test('editing a field invalidates a preview already on screen', () => {
  // Otherwise an admin previews 8 GB, types 64, and commits against a capacity
  // check that was run for a different number.
  assert.match(fnBody('setVMResizeField'), /_resetVMResizeButton\(\)/);
  assert.match(fnBody('_resetVMResizeButton'), /vmResizePreview/);
});

test('changing the SELECTION also invalidates a preview already on screen', () => {
  // The preview approved a specific set of machines, and the commit button is
  // gated on its verdict. Untick the Windows group after a preview that
  // approved them and a live "Resize 42 machines" button would still be backed
  // by a capacity check for machines no longer selected.
  const body = fnBody('_syncVMResizePicker');
  assert.match(body, /vmResizePreview/);
  assert.match(body, /pv\.innerHTML = ''/);
  assert.match(body, /Check capacity/, 'the button must fall back to the preview step');
  // Inline, because _resetVMResizeButton calls back into this function.
  assert.ok(!/_resetVMResizeButton\(\)/.test(body),
    'calling the reset helper from here recurses');
});


test('the commit is refused while the preview says it cannot proceed', () => {
  assert.match(fnBody('submitVMResize'), /res\.canProceed/);
});

// -- selection and slot semantics -------------------------------------------

test('a partial selection is sent as explicit machines, never as slot numbers', () => {
  // `slots: [0]` means "slot 0 on every selected lane", which equals "these
  // machines" only while an image sits at the same slot on every lane. One lane
  // rebuilt with its machines the other way round turns "resize the Windows
  // boxes" into "resize that student's Linux sensor" — silently, and on someone
  // else's machine.
  const body = fnBody('_vmResizeBody');
  assert.match(body, /body\.machines = machines\.map/);
  assert.match(body, /lane_id: m\._laneId, slot: m\.slot/);
  assert.ok(!/body\.slots/.test(body), 'slot numbers are too coarse for a partial selection');
});

test('the machine list is omitted when everything is ticked, so "all" is the wire default', () => {
  const body = fnBody('_vmResizeBody');
  assert.match(body, /allTicked/);
  assert.match(body, /if \(!allTicked\) body\.machines/);
});

test('the picker reads state, not :checked, when resolving machines', () => {
  // The same trap selectedEnvStudentIds documents: :checked also matches
  // disabled boxes.
  assert.match(fnBody('_selectedVMResizeMachines'), /_vmResizeMachines\.filter/);
});

test('pre-fill only happens when the selected machines agree on a size', () => {
  // A disagreeing selection must leave the field blank rather than propose one
  // machine's size for all of them.
  assert.match(fnBody('_commonResources'), /vals\.length === 1/);
});

test('the size fields follow the selection until the admin types something', () => {
  // The group workflow depends on this: open on a mixed selection and the
  // fields are blank because the two kinds disagree; untick the sensors and
  // they fill with the Windows boxes' real size — the number to edit, rather
  // than one to re-enter from scratch.
  assert.match(fnBody('_syncVMResizeSpecFromSelection'), /if \(_vmResizeUserEdited\) return/,
    'a typed value must never be silently overwritten by a re-derived one');
  assert.match(fnBody('_syncVMResizePicker'), /_syncVMResizeSpecFromSelection\(\)/);
  assert.match(fnBody('setVMResizeField'), /_vmResizeUserEdited = true/);
  assert.match(fnBody('showVMResizeModal'), /_vmResizeUserEdited = false/,
    'a fresh open must start tracking again');
});

// -- grouping by machine type -----------------------------------------------

test('machines are grouped by TEMPLATE, not by slot', () => {
  // Slot is a position, not a type. It correlates with the image on a course
  // deployed in one pass and stops correlating the moment one lane is rebuilt
  // with its machines in the other order — at which point a slot-keyed group
  // silently mixes the two images together.
  const body = fnBody('_vmResizeGroups');
  assert.match(body, /m\.template_id \?/, 'group on template_id first');
  assert.match(body, /m\.slot/, 'fall back to slot only when there is no template');
  assert.match(body, /m\.template_name/, 'the label is the template name');
});

test('the group heading carries a checkbox, so one kind is one click', () => {
  const body = fnBody('_vmResizeGroupBlock');
  assert.match(body, /vm-resize-group-box/);
  assert.match(body, /toggleVMResizeGroup\(this\)/);
});

test('the heading shows the count and the shared size, not just a name', () => {
  // An admin picking "the Windows ones" is really picking "the 32 GB ones".
  const body = fnBody('_vmResizeGroupBlock');
  assert.match(body, /_commonResources\(g\.machines\)/);
  assert.match(body, /g\.machines\.length/);
  assert.match(body, /mixed sizes/, 'a group whose machines disagree must say so');
});

test('a group toggle moves only its own machines', () => {
  const body = fnBody('toggleVMResizeGroup');
  assert.match(body, /CSS\.escape\(key\)/,
    'scope the query to the group, and escape the key — template ids reach the selector');
  assert.match(body, /data-group=/);
});

test('group headings get the tri-state, so a partial group cannot read as full', () => {
  const body = fnBody('_syncVMResizePicker');
  assert.match(body, /vm-resize-group-box/);
  assert.match(body, /head\.indeterminate = on > 0 && on < mine\.length/);
});

test('the selection summary names the KIND, not just a count', () => {
  // "42 of 84" does not tell an admin whether they have the Windows boxes or
  // the sensors.
  const body = fnBody('_syncVMResizePicker');
  assert.match(body, /template_name/);
  assert.match(body, /kindLabel/);
});

test('the "untick a heading" hint appears only when there is a choice to make', () => {
  assert.match(fnBody('showVMResizeModal'), /groups\.length > 1 \? 'block' : 'none'/);
});

test('the dialog resets before it is shown, every time', () => {
  const body = fnBody('showVMResizeModal');
  const reset = body.indexOf('_vmResizeSpec = { cores: null, memory_mb: null }');
  const show = body.indexOf("showModal('vmResizeModal')");
  assert.ok(reset !== -1 && show !== -1 && reset < show,
    'state must be cleared BEFORE the modal opens, or it acts on a previous selection');
});

// -- progress ---------------------------------------------------------------

test('the resize poller is its own timer, distinct from provision and rebuild', () => {
  assert.ok(src.includes('_vmResizeProgressTimer'), 'no dedicated resize timer');
  assert.ok(src.includes('_vmRebuildProgressTimer'), 'the rebuild timer should still exist');
  assert.notStrictEqual(
    src.indexOf('_vmResizeProgressTimer'), src.indexOf('_vmRebuildProgressTimer'));
});

test('the poller re-reads its banner on every tick', () => {
  // #provisionProgressBanner is inside #vmManagementContent, which
  // loadVMManagement() replaces on its own 8s poll. A cached reference detaches.
  const body = fnBody('pollResizeProgress');
  assert.match(body, /getElementById\('provisionProgressBanner'\)/);
  assert.match(body, /setTimeout\(\(\) => pollResizeProgress\(url\), 5000\)/,
    'recursive setTimeout, not a setInterval holding a stale element');
});

test('the in-flight lanes are dimmed before the server admits it', () => {
  // On a 24-lane job the gap between the 202 and the next table poll is several
  // seconds of live buttons aimed at machines that are already rebooting.
  assert.match(fnBody('_applyVMResize'), /_vmBusyLanes\.add/);
});

test('the loading state is cleared BEFORE the reload that detaches the button', () => {
  const body = fnBody('_applyVMResize');
  const clear = body.indexOf('Utils.setBtnLoading(btn, false)');
  const reload = body.indexOf('loadVMManagement()');
  assert.ok(clear !== -1 && reload !== -1 && clear < reload,
    'loadVMManagement replaces innerHTML and detaches btn');
});

test('skipped lanes are surfaced rather than swallowed', () => {
  assert.match(fnBody('_applyVMResize'), /res\.skipped/);
});
