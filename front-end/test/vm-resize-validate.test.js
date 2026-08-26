/**
 * Tests for resize request validation and target resolution
 * (cle/routes/vms.js) plus the sizing write-back mirror
 * (src/utils/lane-deployer.js)
 *
 * What these protect:
 *
 *   parseResizeSpec — DISK MUST BE REFUSED LOUDLY. Silently dropping disk_gb is
 *     the worst available option: an admin who types a new disk size, watches
 *     the machines reboot and sees the row still say 128 GB concludes the whole
 *     feature is broken. Proxmox cannot shrink a volume at all, and growing one
 *     enlarges the block device without enlarging the filesystem inside it —
 *     there is no growpart/Resize-Partition step anywhere in this app, because
 *     every other resize happens before a guest's first boot where cloud-init
 *     does that work.
 *
 *   resolveResizeTargets — this is the function that decides which of a
 *     student's machines get power-cycled. It deliberately allows `slots`
 *     across MANY lanes, unlike parseRedeployRequest which refuses them beyond
 *     one. That asymmetry is the thing most likely to be "fixed" by someone who
 *     assumes it was an oversight, so it is pinned here: a redeploy DESTROYS a
 *     machine, so a slot number meaning different things on different lanes is
 *     a data-loss bug; a resize destroys nothing, and "give every student's
 *     slot-1 sensor more RAM" is the main thing anyone wants from it.
 *
 *     An ineligible lane must be SKIPPED, never silently dropped and never
 *     fatal to the batch — the table polls every 8s, so one lane a co-instructor
 *     touched three seconds ago must not fail the other twenty-nine.
 *
 *   flatResourceMirrorPatch — the flat slot-0 mirror, narrowed. Reusing
 *     flatMirrorPatch here would be a bug rather than an inefficiency: that one
 *     also mirrors ip, console_*, guac_connection_id and the workstation
 *     credentials, none of which a resize touches, and copying a slot-3 record
 *     over slot 0's would hand a student the wrong machine's login.
 *
 * Lifted from the route source by brace-matching rather than requiring the
 * route, which pulls in the Proxmox client and the CLE pool at require time —
 * the technique vm-redeploy-validate.test.js and provision-slots.test.js use.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'vms.js'
);
const DEPLOYER = path.join(__dirname, '..', 'src', 'utils', 'lane-deployer.js');

function extractFn(src, name, file) {
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in ${file} — did it get renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}

const routeSrc = fs.readFileSync(ROUTE, 'utf8');
const deployerSrc = fs.readFileSync(DEPLOYER, 'utf8');

// The real validator, so the bounds under test are the ones the app enforces.
const normalizeResourceSpec = new Function(
  `${extractFn(deployerSrc, 'normalizeResourceSpec', 'lane-deployer.js')}
   const RESOURCE_LIMITS = {
     cores:     { min: 1,    max: 32     },
     memory_mb: { min: 1024, max: 131072 },
     disk_gb:   { min: 8,    max: 2048   },
   };
   return normalizeResourceSpec;`
)();

const flatResourceMirrorPatch = new Function(
  `${extractFn(deployerSrc, 'flatResourceMirrorPatch', 'lane-deployer.js')}
   return flatResourceMirrorPatch;`
)();

const WORKSTATION_MAX_SLOTS = 30;
const MAX_RESIZE_TARGETS = 200;

// laneWorkstationRecords is stubbed to the simple case — the legacy-lane
// synthesis it performs is already covered by lane-deployer-slots.test.js, and
// pulling it in whole would drag the octet/mac helpers along with it.
const { parseResizeSpec, resolveResizeTargets } = new Function(
  'normalizeResourceSpec', 'WORKSTATION_MAX_SLOTS', 'MAX_RESIZE_TARGETS', 'laneDeployer',
  `${extractFn(routeSrc, 'parseResizeSpec', 'vms.js')}
   ${extractFn(routeSrc, 'resolveResizeTargets', 'vms.js')}
   return { parseResizeSpec, resolveResizeTargets };`
)(normalizeResourceSpec, WORKSTATION_MAX_SLOTS, MAX_RESIZE_TARGETS, {
  laneWorkstationRecords: (lane) => {
    const ws = (lane.config || {}).workstations || [];
    return ws.filter(w => w && w.slot != null).slice().sort((a, b) => a.slot - b.slot);
  },
});

const lane = (over = {}) => ({
  lane_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  name: 'cle-cybv454-10003',
  status: 'active',
  student_email: 'a@example.edu',
  user_id: 'u1',
  config: {
    workstations: [
      { slot: 0, vmid: 610003, template_id: 'win11', provider_type: 'qemu', hostname: 'ws0' },
      { slot: 1, vmid: 310221, template_id: 'sensor', provider_type: 'qemu', hostname: 'ws1' },
    ],
  },
  ...over,
});

const spec = (over = {}) => ({ resources: { cores: 8, memory_mb: 16384 }, ...over });
const threw = (fn) => { try { fn(); return null; } catch (e) { return e; } };

// ── parseResizeSpec ─────────────────────────────────────────────────────────

test('a normal cores + memory request validates', () => {
  assert.deepStrictEqual(parseResizeSpec(spec()), { cores: 8, memory_mb: 16384 });
});

test('either field alone is enough', () => {
  assert.deepStrictEqual(parseResizeSpec({ resources: { cores: 8 } }), { cores: 8 });
  assert.deepStrictEqual(parseResizeSpec({ resources: { memory_mb: 4096 } }), { memory_mb: 4096 });
});

test('disk_gb is REFUSED, with an explanation rather than a bare rejection', () => {
  const e = threw(() => parseResizeSpec({ resources: { cores: 8, disk_gb: 256 } }));
  assert.ok(e, 'disk_gb was accepted');
  assert.strictEqual(e.status, 400);
  assert.match(e.message, /cannot be changed/i);
  assert.match(e.message, /shrink/i);
  assert.match(e.message, /filesystem/i, 'the message must say WHY growing is not enough');
});

test('a disk_gb of 0, null or empty string is not a disk request', () => {
  // Only a real value is a request; a form that posts an empty field must not
  // be told off for it.
  assert.deepStrictEqual(parseResizeSpec({ resources: { cores: 8, disk_gb: null } }), { cores: 8 });
  assert.deepStrictEqual(parseResizeSpec({ resources: { cores: 8, disk_gb: '' } }), { cores: 8 });
});

test('an empty or missing resources object is rejected', () => {
  assert.strictEqual(threw(() => parseResizeSpec({})).status, 400);
  assert.strictEqual(threw(() => parseResizeSpec({ resources: {} })).status, 400);
  assert.strictEqual(threw(() => parseResizeSpec({ resources: [] })).status, 400);
  assert.strictEqual(threw(() => parseResizeSpec({ resources: 'big' })).status, 400);
});

test('out-of-range sizings are rejected by the shared bounds, not re-invented here', () => {
  assert.strictEqual(threw(() => parseResizeSpec({ resources: { cores: 999 } })).status, 400);
  assert.strictEqual(threw(() => parseResizeSpec({ resources: { memory_mb: 4 } })).status, 400);
  assert.strictEqual(threw(() => parseResizeSpec({ resources: { cores: 2.5 } })).status, 400);
});

// ── resolveResizeTargets ────────────────────────────────────────────────────

test('with no slots, every machine on every lane is a target', () => {
  const { targets, skipped } = resolveResizeTargets({}, [lane()]);
  assert.deepStrictEqual(targets.map(t => t.slot), [0, 1]);
  assert.deepStrictEqual(skipped, []);
});

test('slots apply across MANY lanes — the divergence from parseRedeployRequest', () => {
  // parseRedeployRequest 400s here because a mis-aimed rebuild destroys a
  // machine. A resize destroys nothing, and this is its main use case.
  const lanes = [
    lane({ lane_id: 'a'.repeat(36) }),
    lane({ lane_id: 'b'.repeat(36) }),
    lane({ lane_id: 'c'.repeat(36) }),
  ];
  const { targets } = resolveResizeTargets({ slots: [1] }, lanes);
  assert.strictEqual(targets.length, 3);
  assert.ok(targets.every(t => t.slot === 1));
  assert.strictEqual(new Set(targets.map(t => t.lane_id)).size, 3);
});

test('a lane that lacks the requested slot is SKIPPED, not fatal to the batch', () => {
  const lanes = [
    lane({ lane_id: 'a'.repeat(36) }),
    lane({
      lane_id: 'b'.repeat(36),
      config: { workstations: [{ slot: 0, vmid: 610004, provider_type: 'qemu' }] },
    }),
  ];
  const { targets, skipped } = resolveResizeTargets({ slots: [1] }, lanes);
  assert.strictEqual(targets.length, 1);
  assert.strictEqual(skipped.length, 1);
  assert.match(skipped[0].reason, /none of the selected slots/i);
});

test('a malformed slot is a 400 rather than a silent slot 0', () => {
  // Number(null), Number('') and Number([]) are all 0 — the one machine holding
  // the student's console. A bad body must never resolve to it by accident.
  for (const bad of [null, '', [], {}, 'two', -1, WORKSTATION_MAX_SLOTS]) {
    const e = threw(() => resolveResizeTargets({ slots: [bad] }, [lane()]));
    assert.ok(e, `slots:[${JSON.stringify(bad)}] was accepted`);
    assert.strictEqual(e.status, 400);
  }
});

test('numeric strings are accepted, because form fields post strings', () => {
  const { targets } = resolveResizeTargets({ slots: ['1'] }, [lane()]);
  assert.deepStrictEqual(targets.map(t => t.slot), [1]);
});

test('duplicate slots are de-duped, so a machine is not power-cycled twice', () => {
  const { targets } = resolveResizeTargets({ slots: [1, 1, '1'] }, [lane()]);
  assert.strictEqual(targets.length, 1);
});

test('an empty slots array is a 400, not "all machines"', () => {
  assert.strictEqual(threw(() => resolveResizeTargets({ slots: [] }, [lane()])).status, 400);
});

test('a non-active lane is skipped with a reason the instructor can act on', () => {
  const { targets, skipped } = resolveResizeTargets({}, [
    lane({ lane_id: 'a'.repeat(36), status: 'deploying' }),
    lane({ lane_id: 'b'.repeat(36), status: 'error' }),
  ]);
  assert.strictEqual(targets.length, 0);
  assert.match(skipped[0].reason, /already running/i);
  assert.match(skipped[1].reason, /error state/i);
});

test('a lane that records no machines is skipped', () => {
  const { targets, skipped } = resolveResizeTargets({}, [lane({ config: { workstations: [] } })]);
  assert.strictEqual(targets.length, 0);
  assert.match(skipped[0].reason, /no machines/i);
});

// ── template scope: the screenshot's case ───────────────────────────────────

test('template scope selects only the machines cloned from that template', () => {
  const { targets } = resolveResizeTargets(
    { scope: 'template', template_id: 'win11' }, [lane()]);
  assert.deepStrictEqual(targets.map(t => t.slot), [0]);
  assert.strictEqual(targets[0].template_id, 'win11');
});

test('template scope skips a lane with no machine from that template', () => {
  const { targets, skipped } = resolveResizeTargets(
    { scope: 'template', template_id: 'nothing-uses-this' }, [lane()]);
  assert.strictEqual(targets.length, 0);
  assert.match(skipped[0].reason, /from that template/i);
});

test('template scope without a template_id is a 400', () => {
  assert.strictEqual(
    threw(() => resolveResizeTargets({ scope: 'template' }, [lane()])).status, 400);
});

test('slots and template scope compose', () => {
  const { targets } = resolveResizeTargets(
    { scope: 'template', template_id: 'sensor', slots: [1] }, [lane()]);
  assert.deepStrictEqual(targets.map(t => t.slot), [1]);
});

// ── the cap ─────────────────────────────────────────────────────────────────

test('over the cap is a hard 400 naming the count, never a silent truncation', () => {
  // An admin who selected 300 machines and saw 200 resized has no way to know
  // which hundred were skipped.
  const many = Array.from({ length: 120 }, (_, i) =>
    lane({ lane_id: String(i).padStart(36, '0') }));   // 2 machines each = 240
  const e = threw(() => resolveResizeTargets({}, many));
  assert.ok(e, 'the cap did not fire');
  assert.strictEqual(e.status, 400);
  assert.match(e.message, /at most 200/);
  assert.match(e.message, /got 240/);
});

test('the cap is well above a normal cohort, so a 60-student course still works', () => {
  const many = Array.from({ length: 60 }, (_, i) =>
    lane({ lane_id: String(i).padStart(36, '0') }));
  assert.strictEqual(resolveResizeTargets({}, many).targets.length, 120);
});

// ── flatResourceMirrorPatch ─────────────────────────────────────────────────

test('the flat mirror is written ONLY when slot 0 was actually resized', () => {
  // The rule flatMirrorPatch's docblock exists to protect. On a slots:[3]
  // operation, records[0] is slot 3 — mirroring it would overwrite slot 0's
  // flat keys with a different machine's.
  assert.deepStrictEqual(
    flatResourceMirrorPatch([{ slot: 3, resources: { cores: 8 } }]), {});
  assert.deepStrictEqual(
    flatResourceMirrorPatch([{ slot: 1, resources: { cores: 8 } }, { slot: 2, resources: { cores: 2 } }]), {});
});

test('when slot 0 is present its sizing is mirrored, wherever it sits in the array', () => {
  const patch = flatResourceMirrorPatch([
    { slot: 2, resources: { cores: 2 } },
    { slot: 0, resources: { cores: 8, memory_mb: 16384 }, resource_warnings: ['x'] },
  ]);
  assert.deepStrictEqual(patch.resources, { cores: 8, memory_mb: 16384 });
  assert.deepStrictEqual(patch.resource_warnings, ['x']);
});

test('the mirror carries SIZING ONLY — never console details or credentials', () => {
  // Reusing flatMirrorPatch here would hand a student the wrong machine's login.
  const patch = flatResourceMirrorPatch([{
    slot: 0,
    resources: { cores: 8 },
    ip: '10.0.0.50',
    console_port: 3389,
    guac_connection_id: 42,
    workstation_user: 'student',
    workstation_pass: 'hunter2',
  }]);
  assert.deepStrictEqual(Object.keys(patch), ['resources']);
});

test('an empty or missing record set mirrors nothing', () => {
  assert.deepStrictEqual(flatResourceMirrorPatch([]), {});
  assert.deepStrictEqual(flatResourceMirrorPatch(null), {});
});
