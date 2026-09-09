/**
 * vm-restart-ui.test.js -- the Restart controls' contract in courses.html.
 *
 * Source assertions, like deploy-env-modal.test.js and vm-resize-modal.test.js:
 * standing the page up needs a browser, and what matters here is in the text.
 *
 * Three things this pins:
 *
 *   1. THE BUTTON IS NOT ADMIN-GATED. Restart is instructor-visible on purpose:
 *      it destroys nothing and commits no cluster resources, unlike Resize.
 *      Someone copying the Resize button as a template would inherit
 *      _canResize() and quietly lock instructors out of unsticking their own
 *      class.
 *
 *   2. THE COPY SAYS THE GATEWAY IS SPARED. "Will this break the links I sent
 *      my students" is the first thing an instructor thinks, and the answer is
 *      no. A dialog that does not say so gets cancelled.
 *
 *   3. IT IS A TWO-STEP. The counts in the dialog have to be real -- "restart 84
 *      machines" and "restart 84, 3 of which are off" are different things to
 *      agree to, and only the server knows which.
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
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
const src = fs.readFileSync(PAGE, 'utf8').split(CRLF).join(LF);

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

// -- placement and permission ------------------------------------------------

test('both bulk bars carry a Restart button', () => {
  assert.ok(fnBody('renderVMManagement').includes('vmBulkRestartBtn'),
    'the VM Management bulk bar has no Restart button');
  assert.ok(src.includes('bulkRestartStudentLabs(this)'),
    'the Environments bulk bar has no Restart button');
});

test('Restart is NOT behind the admin gate, unlike Resize', () => {
  const bar = fnBody('renderVMManagement');
  const at = bar.indexOf('vmBulkRestartBtn');
  const gate = bar.indexOf('_canResize()');
  assert.ok(at !== -1);
  // The resize gate sits AFTER the restart button in the markup; if the restart
  // button had been wrapped in it, the gate would come first.
  assert.ok(gate > at,
    'Restart must not inherit _canResize() -- it is instructor-visible on purpose');
  assert.ok(!/_canResize\(\)/.test(fnBody('bulkRestartLanes')),
    'the entry point must not gate on admin either');
});

test('the restart button is enabled and disabled with the rest of the bar', () => {
  assert.match(fnBody('_syncVMBulkBar'), /vmBulkRestartBtn/);
});

test('neither Restart button is styled as destructive', () => {
  const bar = fnBody('renderVMManagement');
  const from = bar.indexOf('vmBulkRestartBtn');
  const to = bar.indexOf('vmBulkResizeBtn');
  assert.ok(from !== -1 && to > from);
  const btn = bar.slice(from, to);
  assert.ok(!btn.includes('#e53e3e') && !btn.includes('btn-danger'),
    'a restart destroys nothing and must not be coloured like Tear down');
});

// -- the copy ----------------------------------------------------------------

test('the confirm says the gateway is left running', () => {
  // The first question an instructor has is whether the console links they
  // handed out will still work.
  const body = fnBody('_restartConfirmBody');
  assert.match(body, /gateway is NOT restarted/i);
  assert.match(body, /console address/i);
});

test('the confirm leads with what is NOT destroyed', () => {
  // This button sits next to Redeploy and Tear down, whose copy says work is
  // lost. If the three read alike nobody will trust the safe one.
  const body = fnBody('_restartConfirmBody');
  assert.match(body, /Nothing is deleted and nothing is rebuilt/i);
  assert.match(body, /flags are untouched/i);
});

test('the confirm still states the real cost', () => {
  const body = fnBody('_restartConfirmBody');
  assert.match(body, /disconnected/i);
  assert.match(body, /unsaved/i, 'the one thing that CAN be lost must be stated');
});

test('the environment restart says the student workstation is spared', () => {
  assert.match(fnBody('bulkRestartStudentLabs'), /workstation is left alone/i);
});

// -- the start-stopped decision ----------------------------------------------

test('the checkbox appears only when something is actually off', () => {
  const body = fnBody('_restartCheckbox');
  assert.match(body, /if \(!stopped\) return null/,
    'do not ask a question that has no subject');
  assert.match(body, /checked: true/, 'starting them is the default');
});

test('both callers read the checkbox rather than assuming', () => {
  for (const fn of ['bulkRestartLanes', 'bulkRestartStudentLabs']) {
    assert.match(fnBody(fn), /s\.stopped \? !!r\.checked : true/,
      `${fn} must honour the checkbox, and default true when it was not shown`);
  }
});

// -- two-step ----------------------------------------------------------------

test('the first call previews and the second commits', () => {
  for (const fn of ['bulkRestartLanes', 'bulkRestartStudentLabs']) {
    const body = fnBody(fn);
    const preview = body.indexOf('restart`, {');
    const commit = body.indexOf('confirm: true');
    assert.ok(preview !== -1 && commit > preview,
      `${fn} must preview before it commits`);
  }
});

test('skipped rows are surfaced rather than swallowed', () => {
  for (const fn of ['bulkRestartLanes', 'bulkRestartStudentLabs']) {
    assert.match(fnBody(fn), /res\.skipped/);
  }
});

test('the loading state is cleared BEFORE the reload that detaches the button', () => {
  for (const fn of ['bulkRestartLanes', 'bulkRestartStudentLabs']) {
    const body = fnBody(fn);
    const clear = body.lastIndexOf('Utils.setBtnLoading(btn, false)');
    const reload = body.lastIndexOf('load');
    assert.ok(clear !== -1 && reload > clear, `${fn} detaches btn before clearing it`);
  }
});

// -- progress ----------------------------------------------------------------

test('the restart poller is its own timer, distinct from the other three', () => {
  for (const t of ['_vmRestartProgressTimer', '_vmResizeProgressTimer', '_vmRebuildProgressTimer']) {
    assert.ok(src.includes(t), `missing timer ${t}`);
  }
});

test('the poller re-reads its banner on every tick', () => {
  // #provisionProgressBanner lives inside #vmManagementContent, which
  // loadVMManagement() replaces on its own 8s poll; a cached reference detaches.
  const body = fnBody('pollRestartProgress');
  assert.match(body, /getElementById\('provisionProgressBanner'\)/);
  assert.match(body, /setTimeout\(\(\) => pollRestartProgress\(url\), 5000\)/);
});
