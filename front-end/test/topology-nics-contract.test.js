/**
 * topology-nics-contract.test.js — what an EMPTY nics list means, pinned across
 * all four layers that used to disagree about it.
 *
 * ── The bug this file describes ─────────────────────────────────────────────
 * Detaching a machine on the Topology Designer canvas did NOTHING. Four layers,
 * each locally reasonable, composing into a silent lie:
 *
 *   1. canvas detach                  ->  node.segments = []
 *   2. syncFromCanvas                 ->  '' !== 'lan', so it writes vm.nics = []
 *      (topology-editor.js:184-188)
 *   3. buildSpecVm / normaliseNics    ->  `return out.length ? out : null`, so
 *      (challenge-spec.js)                the key is OMITTED from the spec
 *   4. resolveVmSegments              ->  explicit.length is 0, so it falls
 *      (lane-networking.js)               through to the derivation -> ['lan']
 *
 * The machine deploys ATTACHED while the canvas draws it floating, and nothing
 * anywhere says so.
 *
 * ── The decision, and why it is not "make [] mean detached" ─────────────────
 * A VM with no network in this platform is useless: no DHCP lease, no Guacamole
 * target, no vuln scripts. So a machine must always have at least one NIC.
 *
 * "Omit means derive" STAYS the spec contract — that is exactly what keeps every
 * pre-canvas spec byte-identical, and changing it would rewrite the placement of
 * every legacy challenge. Since an absent key and `[]` are indistinguishable
 * everywhere downstream, `[]` cannot be made to also mean "isolated" without
 * making one value mean two things. An author-intended detach is therefore
 * refused at the EDITOR, and a spec that nonetheless arrives with zero segments
 * (an import, an older editor, a hand-edited spec) is caught LOUDLY by
 * validateTopology's `no-nic` error.
 *
 * This file asserts the whole round trip, including the part that is still a
 * re-attach — so that the re-attach can never again be SILENT.
 *
 * Run: node front-end/test/topology-nics-contract.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
const { buildSpecVm, normaliseNics } = require(path.join(UTILS, 'challenge-spec'));
const { resolveVmSegments } = require(path.join(UTILS, 'lane-networking'));
const { validateTopology } = require(path.join(UTILS, 'topology-validate'));

const EDITOR_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'js', 'topology', 'topology-editor.js'), 'utf8');

// topology-editor.js only needs `window` at load time; everything DOM-facing
// lives inside mount(), which this file never calls. Same loader
// topology-editor-derive.test.js uses.
function loadEditor() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(EDITOR_SRC, sandbox, { filename: 'topology-editor.js' });
  return sandbox.CyberCoreTopologyEditor;
}
const Editor = loadEditor();

/**
 * syncFromCanvas' NIC rule, transcribed from topology-editor.js:184-188.
 *
 * It lives inside mount() and is not exported, so it cannot be called directly.
 * Transcribing it is the same technique challenge-spec-create.test.js uses for
 * the pre-refactor literal — and the source-text guard below is what stops the
 * transcription drifting away from the original.
 */
function syncNics(specVm, canvasSegments, scheme, isGoadVm = false) {
  const out = { ...specVm };
  const derived = Editor.deriveSegments({ role: out.role, type: out.type }, scheme, isGoadVm);
  const current = canvasSegments || [];
  if (current.join('|') === derived.join('|')) delete out.nics;
  else out.nics = current.map(s => ({ segment: s }));
  return out;
}

test('the transcribed sync rule still matches topology-editor.js', () => {
  // If this fails, syncNics() above is describing code that no longer exists and
  // every conclusion in this file is about the wrong program.
  assert.match(EDITOR_SRC, /var derived = deriveSegments\(\{ role: vm\.role, type: vm\.type \}, scheme, isGoadVm\(vm\)\);/);
  assert.match(EDITOR_SRC, /var current = n\.segments \|\| \[\];/);
  assert.match(EDITOR_SRC, /if \(current\.join\('\|'\) === derived\.join\('\|'\)\) delete vm\.nics;/);
  assert.match(EDITOR_SRC, /else vm\.nics = current\.map\(function \(s\) \{ return \{ segment: s \}; \}\);/);
});

// ── 1. the four layers, one at a time ────────────────────────────────────────

test('layer 2: a canvas detach produces nics: [] — not a deleted key', () => {
  // This is the step that makes the whole thing possible: '' !== 'lan', so the
  // "only write nics when it differs from the derivation" shortcut takes the
  // ELSE branch and writes an empty array.
  const synced = syncNics({ name: 'DC01', role: '', type: 'qemu' }, [], 'v2');
  assert.deepStrictEqual(synced.nics, [], 'detach writes an empty array');
});

test('layer 3: normaliseNics([]) is null, so buildSpecVm omits the key', () => {
  assert.strictEqual(normaliseNics([]), null);
  assert.strictEqual(normaliseNics([{}, null, { segment: '' }]), null,
    'entries with no usable segment are the same case');

  const built = buildSpecVm({ name: 'DC01', template_vmid: 1004, type: 'qemu', nics: [] }, 0, 'k');
  assert.ok(!('nics' in built),
    'omitting is what keeps every legacy spec byte-identical — it is NOT the bug');
});

test('layer 4: an omitted nics key derives, which is the documented contract', () => {
  assert.deepStrictEqual(resolveVmSegments({ name: 'DC01', type: 'qemu' }, { subnetScheme: 'v2' }), ['lan']);
  assert.deepStrictEqual(resolveVmSegments({ name: 'DC01', type: 'qemu', nics: [] }, { subnetScheme: 'v2' }), ['lan'],
    'an EMPTY array and an ABSENT key mean the same thing here, on purpose');
});

// ── 2. the full round trip ───────────────────────────────────────────────────

for (const scheme of ['v1', 'v2', 'v3']) {
  test(`the round trip re-attaches on ${scheme} — and that is now a LOUD outcome`, () => {
    const authored = { name: 'DC01', role: '', type: 'qemu', template_vmid: 1004, vm_offset: 600000 };

    // 1 + 2. The author detaches the machine on the canvas.
    const synced = syncNics(authored, [], scheme);
    assert.deepStrictEqual(synced.nics, []);

    // 3. POST /api/admin/create-lab.
    const stored = buildSpecVm(synced, 0, 'k');
    assert.ok(!('nics' in stored));

    // 4. Deploy time. The machine comes up ATTACHED. This assertion is the bug
    //    stated as behaviour, not a wish: it is what the platform does and what
    //    it must keep doing, because every legacy spec relies on the same rule.
    const expected = scheme === 'v3' ? ['ext'] : ['lan'];
    assert.deepStrictEqual(
      resolveVmSegments(stored, { subnetScheme: scheme }), expected,
      'omit-means-derive is the contract; the detach cannot be encoded here');

    // THE POINT OF THE PHASE. The spec the editor is holding — before
    // buildSpecVm flattens it — is refused by the validator, which is what the
    // canvas paints live. So the author is told, rather than discovering it in a
    // deployed lane.
    const result = validateTopology({ subnetScheme: scheme, specVms: [synced] });
    const finding = result.errors.find(f => f.code === 'no-nic');
    assert.ok(finding, `no-nic must be raised on ${scheme}: ${JSON.stringify(result.findings)}`);
    assert.strictEqual(finding.vm, 'DC01');
    assert.match(finding.message, /silently deploy attached/,
      'the message must name the consequence, not just the condition');
  });
}

test('the re-attach is never SILENT — a detached spec always carries an error', () => {
  // The one invariant worth stating on its own: for every scheme, and for both
  // shapes of "zero segments", validateTopology refuses. If this ever passes
  // clean, the bug is back in exactly the form it had before.
  for (const scheme of ['v1', 'v2', 'v3']) {
    for (const nics of [[], [{}], [null], [{ segment: '' }]]) {
      const r = validateTopology({
        subnetScheme: scheme,
        specVms: [{ name: 'DC01', type: 'qemu', template_vmid: 1004, nics }],
      });
      assert.ok(r.errors.some(f => f.code === 'no-nic'),
        `no-nic missing for ${scheme} / ${JSON.stringify(nics)}`);
    }
  }
});

// ── 3. everything that must NOT change ───────────────────────────────────────

test('an attached machine is clean — no-nic is not a permanent badge', () => {
  // A finding that fires on every topology trains authors to ignore findings.
  for (const [scheme, seg] of [['v2', 'lan'], ['v3', 'ext'], ['v3', 'int']]) {
    const r = validateTopology({
      subnetScheme: scheme,
      specVms: [{ name: 'DC01', type: 'qemu', template_vmid: 1004, nics: [{ segment: seg }] }],
    });
    assert.ok(!r.findings.some(f => f.code === 'no-nic'), `${scheme}/${seg}`);
  }
});

test('a machine with NO nics key at all is clean — omit is not a detach', () => {
  // Every pre-canvas challenge in the database is this shape. Flagging them
  // would put an error on every legacy spec the moment the canvas opens it.
  const r = validateTopology({
    subnetScheme: 'v2',
    specVms: [{ name: 'web01', type: 'qemu', template_vmid: 1601 }],
  });
  assert.ok(!r.findings.some(f => f.code === 'no-nic'), JSON.stringify(r.findings));
});

test('a canvas move that matches the derivation still deletes the key', () => {
  // The back-compat shortcut in syncFromCanvas: dragging a machine onto the
  // segment it would have derived anyway must not start writing nics[] into a
  // spec that never had one.
  const synced = syncNics({ name: 'web01', role: '', type: 'qemu', nics: [{ segment: 'lan' }] }, ['lan'], 'v2');
  assert.ok(!('nics' in synced));
});

test('a real re-attachment still round-trips as an explicit nics list', () => {
  const synced = syncNics({ name: 'DC01', role: '', type: 'qemu' }, ['int'], 'v3');
  const stored = buildSpecVm({ ...synced, template_vmid: 1004 }, 0, 'k');
  assert.deepStrictEqual(stored.nics, [{ segment: 'int' }]);
  assert.deepStrictEqual(resolveVmSegments(stored, { subnetScheme: 'v3' }), ['int']);
  assert.ok(!validateTopology({ subnetScheme: 'v3', specVms: [stored] })
    .findings.some(f => f.code === 'no-nic'));
});

// ── 4. the contract is documented where it is implemented ────────────────────

test('both halves of the contract carry the explanation', () => {
  // This bug survived because each function was individually defensible and the
  // interaction was written down nowhere. The comments ARE the fix for the next
  // reader; losing one of them re-creates the conditions exactly.
  for (const file of ['challenge-spec.js', 'lane-networking.js']) {
    const src = fs.readFileSync(path.join(UTILS, file), 'utf8');
    assert.match(src, /EMPTY-NICS CONTRACT/,
      `${file} must explain that an empty nics list and an absent one mean the same thing`);
  }
});
