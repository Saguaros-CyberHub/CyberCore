/**
 * deploy-env-modal.test.js -- the Deploy Environment screen's contract.
 *
 * courses.html is a 3000-line page with no build step, so the parts most likely
 * to rot silently are asserted against the source itself: the script tags the
 * topology preview needs, the scoped student query, and the re-read guard that
 * stands between a preview and a commit.
 *
 * These are source assertions, not behaviour -- the same approach
 * provision-slots.test.js takes for the provision route, and for the same
 * reason: standing up the page needs a browser, and the rules worth pinning are
 * visible in the text.
 *
 * Run: node front-end/test/deploy-env-modal.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const PAGE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'public', 'pages', 'courses.html'
);
// LF-normalised: git checks this page out as CRLF on Windows, and the
// index/slice assertions below would stop matching without saying why.
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
const src = fs.readFileSync(PAGE, 'utf8').split(CRLF).join(LF);

// -- the assets the live topology needs -------------------------------------

test('the page loads exactly the five topology files the preview needs', () => {
  // specToGraph resolves CyberCoreTopologyEditor at CALL time, so topology-seed
  // alone is not enough -- the editor has to be on the page even though its
  // mount() is never used here.
  for (const f of ['/vendor/cytoscape.min.js', '/js/topology/topology-icons.js',
                   '/js/topology/topology-render.js', '/js/topology/topology-editor.js',
                   '/js/topology/topology-seed.js']) {
    assert.ok(src.includes(`<script src="${f}"></script>`), `missing script tag: ${f}`);
  }
});

test('edit-mode-only assets stay off the page', () => {
  // edgehandles and its lodash dependency are reachable only behind
  // mode === 'edit'. An instructor authors nothing here, and both are large.
  assert.ok(!src.includes('cytoscape-edgehandles.js'), 'edgehandles is edit-mode only');
  assert.ok(!src.includes('/vendor/lodash.min.js'), 'lodash is only needed by edgehandles');
});

// -- the merge actually happened --------------------------------------------

test('the two old modals are gone and one replaces them', () => {
  assert.ok(!src.includes('id="provisionVMModal"'), 'the old workstation modal should be removed');
  assert.ok(!src.includes('id="deployVulnerableModal"'), 'the old lab modal should be removed');
  assert.ok(src.includes('id="deployEnvModal"'), 'the merged modal should exist');
});

test('both entry points open the same merged screen', () => {
  assert.ok(/const showDeployVulnerableModal = showDeployEnvModal/.test(src));
  assert.ok(/const showProvisionVMModal = \(\) => showDeployEnvModal\(\)/.test(src));
});

test('the workstation-only path survives the merge as an explicit option', () => {
  assert.ok(src.includes("const WORKSTATION_ONLY = '__workstation_only__'"));
  assert.ok(src.includes(`<option value="${'${WORKSTATION_ONLY}'}"`),
    'the picker should offer the workstation-only row');
});

// -- the hazards the old code carried comments about ------------------------

test('the student query stays scoped to this modal', () => {
  // `.modal-student-select` is shared with the other pickers on this page; a
  // global query was picking those up too.
  const globals = src.match(/querySelectorAll\('[^']*\.modal-student-select[^']*'\)/g) || [];
  assert.ok(globals.length > 0, 'the student query should exist');
  for (const q of globals) {
    assert.ok(/#\w+/.test(q), `student query is not scoped to a container: ${q}`);
  }
});

test('Cytoscape is mounted only after the modal is visible', () => {
  // It measures its container at init; a hidden one yields a 0x0 graph that
  // never recovers.
  const show = src.indexOf("showModal('deployEnvModal')");
  const mount = src.indexOf('mountEnvTopology()', show);
  assert.ok(show > -1 && mount > show, 'showModal must precede mountEnvTopology');
});

test('closing the modal destroys the renderer', () => {
  // destroy() is what disconnects the theme MutationObserver; skipping it leaks
  // one observer per open.
  const fn = src.slice(src.indexOf('function closeDeployEnvModal()'));
  assert.ok(fn.slice(0, 300).includes('destroyEnvTopology()'));
  assert.ok(src.includes('_deployEnvTopo.destroy()'));
});

// -- preview -> confirm ------------------------------------------------------

test('the confirm step re-reads the form and compares every field it can change', () => {
  // The preview stays on screen while the student list, machine list and console
  // pick are all still editable. Committing the snapshot would deploy something
  // other than what is on screen.
  const guard = src.slice(src.indexOf('const changed = now.templateId'), src.indexOf('if (changed) {'));
  for (const field of ['mode', 'attackBox', 'consoleVm', 'extraWorkstations', 'studentIds']) {
    assert.ok(guard.includes(`now.${field}`), `the changed-guard ignores ${field}`);
  }
});

test('the deploy body carries the new fields', () => {
  const body = src.slice(src.indexOf('function deployEnvBody(form)'));
  for (const key of ['attack_box:', 'console_vm:', 'extra_workstations:']) {
    assert.ok(body.slice(0, 500).includes(key), `deployEnvBody omits ${key}`);
  }
});

// -- sizing ------------------------------------------------------------------

test('per-machine sizing is sent as an ARRAY, never as one scalar for every slot', () => {
  // A scalar spec applied to every slot is what cloned a 4 GB sensor at a SIEM
  // box's 16 GB, times the cohort. See provision-slots.test.js.
  const fn = src.slice(src.indexOf('async function provisionVMs()'));
  assert.ok(fn.slice(0, 2000).includes('resources: slots.map(a => compactResources(a.resources))'),
    'provisionVMs must send one resources entry per slot');
});

test('the console machine is placed at slot 0 on the workstation path', () => {
  // Slot 0 takes the lane .50 and the gateway's baked console port, so ordering
  // IS how that path expresses "the machine the student opens".
  const fn = src.slice(src.indexOf('function workstationSlotOrder()'));
  assert.ok(fn.slice(0, 600).includes('consoleRef'), 'slot order must consider the console pick');
});
