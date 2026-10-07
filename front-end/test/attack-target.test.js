/**
 * attack-target.test.js — picking the right VM to attack.
 *
 * A wrong answer here does not fail loudly: it fires log-generator at whatever
 * VM it chose. In a CYBR 400 lane the other machine is the student's ELK stack,
 * so guessing means attacking the SIEM instead of the sensor. The resolver
 * therefore has to return null rather than a best guess whenever more than one
 * candidate survives, and that is most of what these tests pin.
 *
 * resolveLoggenTarget() is pure over injected lookups (catalog row, challenge
 * spec, probe fn), so the whole ladder runs here with no database and no
 * Proxmox.
 *
 * Run: node front-end/test/attack-target.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

// E1 moved the engine into shared core and left a re-export shim at the old
// cle/utils/ path; E2 deleted the shim. This is the one home it has.
const target = require(path.join(__dirname, '..', 'src', 'incident', 'target.js'));

const TEMPLATE = { id: 'tmpl-uuid-1', template_vmid: 1006, template_key: 'cybr400-loggen-template' };

/** A challenge lane: gateway LXC + Kali + two QEMU VMs, the shape v3 produces. */
function challengeLane(extra = {}) {
  return {
    lane_id: 'lane-1', module_key: 'crucible',
    config: {
      node: 'cyberhub-node-2',
      challenge_key: 'cybr400',
      gateway_vm_id: 100042,
      attack_box_vm_id: 700042,
      vms: [
        { vm_id: 600042, name: 'elk', proxmox_name: 'elk-s1', type: 'qemu', node: 'cyberhub-node-2' },
        { vm_id: 600043, name: 'sensor', proxmox_name: 'sensor-s1', type: 'qemu', node: 'cyberhub-node-2' },
      ],
      ...extra,
    },
  };
}

/** A workstation lane, which unlike the above DOES carry template_id. */
function workstationLane(extra = {}) {
  return {
    lane_id: 'lane-2', module_key: 'crucible',
    config: {
      node: 'cyberhub-node-3',
      gateway_vmid: 100043,
      workstations: [
        { slot: 0, vmid: 600100, hostname: 'elk', provider_type: 'qemu', template_id: 'tmpl-uuid-win' },
        { slot: 1, vmid: 600101, hostname: 'sensor', provider_type: 'qemu', template_id: 'tmpl-uuid-1' },
      ],
      ...extra,
    },
  };
}

const SPEC_TEMPLATED = [
  { name: 'elk', template_vmid: 1004, os: 'windows' },
  { name: 'sensor', template_vmid: 1006, os: 'rocky' },
];

test('rung 1: a challenge lane resolves through the spec to the catalog template', async () => {
  const r = await target.resolveLoggenTarget(challengeLane(), { template: TEMPLATE, specVms: SPEC_TEMPLATED });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.vm_name, 'sensor');
  assert.strictEqual(r.resolved_by, 'template');
  assert.strictEqual(r.node, 'cyberhub-node-2');
});

test('rung 1: a workstation lane matches template_id directly, with no spec at all', async () => {
  const r = await target.resolveLoggenTarget(workstationLane(), { template: TEMPLATE, specVms: [] });
  assert.strictEqual(r.vmid, 600101);
  assert.strictEqual(r.resolved_by, 'template');
});

test('rung 2: an explicit spec role wins when no template is registered', async () => {
  const spec = [
    { name: 'elk', os: 'windows' },
    { name: 'sensor', os: 'linux', role: 'loggen' },
  ];
  const r = await target.resolveLoggenTarget(challengeLane(), { template: null, specVms: spec });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.resolved_by, 'spec_role');
});

test('rung 3: one Windows box and one Linux box resolves with zero configuration', async () => {
  // This is the CYBR 400 case, and the reason the feature needs no setup: no
  // catalog tag, no role, just elimination.
  const spec = [{ name: 'elk', os: 'windows' }, { name: 'sensor', os: 'rocky' }];
  const r = await target.resolveLoggenTarget(challengeLane(), { template: null, specVms: spec });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.resolved_by, 'sole_linux');
});

test('rung 3 does NOT fire when a VM cannot be classified', async () => {
  // normalizeOs returns null for 'Unknown' and for human strings it cannot
  // parse. An unclassifiable VM must stay a candidate and make the answer
  // ambiguous, never be silently treated as not-Linux.
  const spec = [{ name: 'elk', os: 'Unknown' }, { name: 'sensor', os: 'rocky' }];
  const r = await target.resolveLoggenTarget(challengeLane(), { template: null, specVms: spec });
  assert.strictEqual(r.vmid, null);
  assert.match(r.reason, /could not identify/);
});

test('two Linux VMs and no tag returns null with a reason, never a guess', async () => {
  const spec = [{ name: 'elk', os: 'linux' }, { name: 'sensor', os: 'linux' }];
  const r = await target.resolveLoggenTarget(challengeLane(), { template: null, specVms: spec });
  assert.strictEqual(r.vmid, null);
  assert.match(r.reason, /2 Linux VMs/);
});

test('rung 4: the guest probe breaks a tie the metadata could not', async () => {
  const spec = [{ name: 'elk', os: 'linux' }, { name: 'sensor', os: 'linux' }];
  const probed = [];
  const r = await target.resolveLoggenTarget(challengeLane(), {
    template: null, specVms: spec,
    probe: async ({ vmid }) => { probed.push(vmid); return vmid === 600043; },
  });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.resolved_by, 'probe');
  assert.ok(probed.length >= 1);
});

test('a probe that throws is not a match and not a crash', async () => {
  const spec = [{ name: 'elk', os: 'linux' }, { name: 'sensor', os: 'linux' }];
  const r = await target.resolveLoggenTarget(challengeLane(), {
    template: null, specVms: spec,
    probe: async () => { throw new Error('guest agent unreachable'); },
  });
  assert.strictEqual(r.vmid, null);
});

test('rung 0: a cached target short-circuits the ladder', async () => {
  const lane = challengeLane({ loggen: { vmid: 600043, node: 'cyberhub-node-2', vm_name: 'sensor' } });
  const r = await target.resolveLoggenTarget(lane, { template: null, specVms: [] });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.resolved_by, 'cache');
});

test('a stale cache pointing at a VM the lane no longer has is ignored', async () => {
  // A redeploy reuses lane_id while replacing every vmid. Trusting the cache
  // blindly would aim at a VM that is gone, or at a recycled id owned by
  // something else entirely.
  const lane = challengeLane({ loggen: { vmid: 999999, node: 'cyberhub-node-2', vm_name: 'ghost' } });
  const spec = [{ name: 'elk', os: 'windows' }, { name: 'sensor', os: 'rocky' }];
  const r = await target.resolveLoggenTarget(lane, { template: null, specVms: spec });
  assert.strictEqual(r.vmid, 600043);
  assert.strictEqual(r.resolved_by, 'sole_linux');
});

test('lane infrastructure is never a candidate', () => {
  // The gateway and the Kali attack box would otherwise survive to rung 3 and
  // make every lane ambiguous. The gateway is also an LXC, which has no
  // guest-agent exec API at all.
  const cands = target.laneCandidates(challengeLane().config);
  const ids = cands.map((c) => c.vmid);
  assert.ok(!ids.includes(100042), 'gateway must be excluded');
  assert.ok(!ids.includes(700042), 'attack box must be excluded');
  assert.deepStrictEqual(ids.sort(), [600042, 600043]);
});

test('non-QEMU VMs are dropped, because guest-agent exec is QEMU-only', () => {
  const cfg = {
    node: 'n1',
    vms: [
      { vm_id: 1, name: 'a', type: 'lxc' },
      { vm_id: 2, name: 'b', type: 'qemu' },
    ],
  };
  assert.deepStrictEqual(target.laneCandidates(cfg).map((c) => c.vmid), [2]);
});

test('attached-module VMs are candidates too', () => {
  const cfg = {
    node: 'n1',
    vms: [{ vm_id: 600042, name: 'elk', type: 'qemu' }],
    attached_modules: [{ vms: [{ vm_id: 800042, name: 'sensor', type: 'qemu' }] }],
  };
  assert.deepStrictEqual(target.laneCandidates(cfg).map((c) => c.vmid).sort(), [600042, 800042]);
});

test('a lane with no node is refused rather than dispatched blindly', async () => {
  const lane = { lane_id: 'x', config: { vms: [{ vm_id: 1, name: 'a', type: 'qemu' }] } };
  const r = await target.resolveLoggenTarget(lane, {});
  assert.strictEqual(r.vmid, null);
  assert.match(r.reason, /no Proxmox node/);
});

test('the cache write is a single jsonb_set, never a read-modify-write', () => {
  // src/utils/script-executor.js updateScriptStatus() SELECTs a JSONB column,
  // edits it in Node and UPDATEs the whole thing, so two concurrent writers
  // lose one edit. A dispatch resolves every lane at once, which is exactly
  // that workload. Pinning the shape stops the pattern being reintroduced.
  const src = target.cacheLoggenTarget.toString();
  assert.match(src, /jsonb_set/, 'must write through jsonb_set');
  assert.ok(!/SELECT/i.test(src), 'must not read the config back first');
  const inv = target.invalidateLoggenCache.toString();
  assert.ok(!/SELECT/i.test(inv), 'invalidation must not read config back either');
});

// ════════════════════════════════════════════════════════════════════════════
// E2 — the CiAB arm
// ════════════════════════════════════════════════════════════════════════════
//
// A CiAB lane reaches this resolver through the same ladder as a CYBR 400 lane,
// but it arrives with three differences that each independently decide whether
// the sensor is found:
//
//   module_key   'ciab', not 'crucible' — so the spec lookup's derived table
//                name is `ciab_challenge`, which HAS NEVER EXISTED
//   config       carries `loggen` already, stamped at deploy time by the
//                blueteam post-deploy hook rather than by a previous run
//   spec.vms[]   carries role: 'sensor', which LOGGEN_ROLES already contains
//
// The tests below pin one each. They matter in that order: rung 0 is what fires
// on a healthy lane, and rung 2 is the recovery path when the stamp is lost to a
// redeploy — which is exactly when nobody is watching.

/**
 * The lane shape CiAB's profile deploy produces: a gateway LXC, a Kali attack
 * box, the synthetic vuln-app VM, and the sensor.
 *
 * TWO Linux VMs survive as candidates here (the vuln app and the sensor), which
 * is deliberate — it is what makes rung 3 ambiguous and forces the lane to
 * resolve on rung 0 or rung 2. A fixture with only one Linux box would pass
 * every assertion below for the wrong reason.
 */
function ciabLane(extra = {}) {
  return {
    lane_id: 'lane-ciab-1',
    module_key: 'ciab',
    config: {
      node: 'cyberhub-node-4',
      ciab: true,
      engagement_id: '3f1d0c9a-1111-4222-8333-444455556666',
      challenge_key: 'ciab-acme-dental',
      gateway_vm_id: 100077,
      attack_box_vm_id: 700077,
      vms: [
        { vm_id: 600077, name: 'web', proxmox_name: 'web-s1', type: 'qemu', node: 'cyberhub-node-4' },
        { vm_id: 600078, name: 'sensor', proxmox_name: 'sensor-s1', type: 'qemu', node: 'cyberhub-node-4' },
      ],
      ...extra,
    },
  };
}

/**
 * Swap src/utils/cybercore-db for a stub and hand back a freshly-required
 * target.js bound to it.
 *
 * loadSpecVms is the one function in this file that is NOT pure over injected
 * lookups — it issues the query itself — so there is no seam to inject through
 * and the module cache is the seam that exists. Restored in a finally, always:
 * leaking a stubbed pool into the next test file in the run would be a failure
 * nobody could trace back to here.
 */
function withStubbedPool(cybercoreQuery, body) {
  const Module = require('module');
  const dbPath = require.resolve('../src/utils/cybercore-db.js');
  const targetPath = require.resolve('../src/incident/target.js');
  const savedDb = require.cache[dbPath];
  const savedTarget = require.cache[targetPath];

  const stub = new Module(dbPath, null);
  stub.filename = dbPath;
  stub.loaded = true;
  stub.exports = { cybercoreQuery };
  require.cache[dbPath] = stub;
  delete require.cache[targetPath];

  const restore = () => {
    if (savedDb) require.cache[dbPath] = savedDb; else delete require.cache[dbPath];
    if (savedTarget) require.cache[targetPath] = savedTarget; else delete require.cache[targetPath];
  };
  return Promise.resolve()
    .then(() => body(require('../src/incident/target.js')))
    .finally(restore);
}

test('rung 0: a CiAB lane stamped at deploy time resolves with no spec and no catalog', async () => {
  // blueteam-postdeploy.js calls cacheLoggenTarget() the moment the sensor VM
  // exists, writing config.loggen with resolved_by:'postdeploy'. That is rung 0
  // populated BEFORE the first run, so the very first dispatch costs no ladder
  // at all — no catalog read, no spec read, and no guest probe.
  //
  // resolveLoggenTarget reports 'cache', not 'postdeploy': the stamp is a rung-0
  // VALUE, not a rung of its own. 'postdeploy' only ever reaches
  // cybercore_incident_target.resolved_by, whose column is VARCHAR(24) with no
  // CHECK — which is why the sixth vocabulary word needed no DDL.
  const lane = ciabLane({
    loggen: {
      vmid: 600078, node: 'cyberhub-node-4', vm_name: 'sensor',
      resolved_by: 'postdeploy', at: new Date().toISOString(),
    },
  });
  const r = await target.resolveLoggenTarget(lane, { template: null, specVms: [] });
  assert.strictEqual(r.vmid, 600078);
  assert.strictEqual(r.vm_name, 'sensor');
  assert.strictEqual(r.node, 'cyberhub-node-4');
  assert.strictEqual(r.resolved_by, 'cache');
});

test("rung 2: spec role 'sensor' resolves a CiAB lane the ladder could not otherwise call", async () => {
  // The recovery path. A redeploy reuses lane_id while replacing every vmid, so
  // the post-deploy stamp is stale and rung 0 correctly refuses it. Without the
  // spec this lane is unresolvable — the vuln-app VM and the sensor are both
  // Linux, so rung 3 is ambiguous by construction and rung 4 would probe a
  // student's application server first.
  //
  // 'sensor' is already in LOGGEN_ROLES, so E2 changed no role set. What E2
  // changed is that a CiAB lane can now LOAD a spec at all — see the
  // crucible_challenge fallback test below.
  const spec = [
    { name: 'web', role: 'target', os: 'linux' },
    { name: 'sensor', role: 'sensor', os: 'linux' },
  ];
  const lane = ciabLane({
    loggen: { vmid: 999999, node: 'cyberhub-node-4', vm_name: 'ghost' },  // stale
  });
  const r = await target.resolveLoggenTarget(lane, { template: null, specVms: spec });
  assert.strictEqual(r.vmid, 600078);
  assert.strictEqual(r.resolved_by, 'spec_role');
  assert.ok(target.LOGGEN_ROLES.has('sensor'),
    "'sensor' must stay in LOGGEN_ROLES — it is the role CiAB's synthesizer emits");
});

test('without the spec, the same CiAB lane is refused rather than guessed at', async () => {
  // The mirror of the test above, and the reason the crucible_challenge fallback
  // is a correctness fix rather than an optimisation. Two Linux VMs and no spec
  // is not "resolve to the likely one" — the other candidate is the student's
  // vulnerable application, and firing log-generator at it would look like a
  // successful run that produced nothing anyone could hunt.
  const r = await target.resolveLoggenTarget(ciabLane(), { template: null, specVms: [] });
  assert.strictEqual(r.vmid, null);
  assert.match(r.reason, /could not identify/);
});

test('loadSpecVms falls back to crucible_challenge when the module has no table', async () => {
  // THE FIX, exercised against a stubbed pool.
  //
  // `${module_key}_challenge` is a convention, not a guarantee. It holds on the
  // CLE side (module_key 'crucible' -> crucible_challenge, which is ALSO the
  // shared table, so the two coincided and nothing looked wrong). It does not
  // hold for CiAB: its lanes carry module_key 'ciab' while their specs live in
  // the shared crucible_challenge, and ciab_challenge has never existed.
  //
  // The old single-table version therefore threw "relation ciab_challenge does
  // not exist" on every CiAB lane, swallowed it, and returned [] — so rung 2
  // could never fire no matter how the spec was tagged.
  const asked = [];
  await withStubbedPool(async (text, params) => {
    asked.push({ text: String(text).replace(/\s+/g, ' ').trim(), params });
    // Exactly how Postgres answers a missing relation: an error, not an empty
    // result. Returning [] here would let a broken implementation pass.
    if (/FROM ciab_challenge\b/.test(text)) {
      const err = new Error('relation "ciab_challenge" does not exist');
      err.code = '42P01';
      throw err;
    }
    if (/FROM crucible_challenge\b/.test(text)) {
      return { rows: [{ spec: { vms: [{ name: 'sensor', role: 'sensor', os: 'linux' }] } }], rowCount: 1 };
    }
    return { rows: [], rowCount: 0 };
  }, async (fresh) => {
    const lane = ciabLane();
    const vms = await fresh.loadSpecVms(lane, lane.config);

    assert.deepStrictEqual(vms, [{ name: 'sensor', role: 'sensor', os: 'linux' }]);
    assert.strictEqual(asked.length, 2, 'the module table is tried FIRST, then the shared one');
    assert.match(asked[0].text, /FROM ciab_challenge/);
    assert.match(asked[1].text, new RegExp(`FROM ${fresh.SHARED_CHALLENGE_TABLE}`));
    // The lookup key is bound, never interpolated, on both attempts.
    for (const q of asked) assert.deepStrictEqual(q.params, ['ciab-acme-dental']);
  });
});

test('a spec found in the module table is authoritative — no second query', async () => {
  // A HIT stops the ladder even when it declares no vms. An environment really
  // can be a bare workstation pair, and falling through to crucible_challenge on
  // "found it, but it was empty" would silently prefer some unrelated row that
  // happened to share the challenge_key.
  const asked = [];
  await withStubbedPool(async (text) => {
    asked.push(String(text).replace(/\s+/g, ' ').trim());
    return { rows: [{ spec: {} }], rowCount: 1 };
  }, async (fresh) => {
    const lane = ciabLane();
    assert.deepStrictEqual(await fresh.loadSpecVms(lane, lane.config), []);
    assert.strictEqual(asked.length, 1);
    assert.match(asked[0], /FROM ciab_challenge/);
  });
});

test('a CLE lane still asks exactly one table, because the two coincide', async () => {
  // The no-regression half. module_key 'crucible' derives crucible_challenge,
  // which IS the shared table — so the fallback must dedupe rather than issue
  // the identical query twice on every lane of every dispatch.
  const asked = [];
  await withStubbedPool(async (text) => {
    asked.push(String(text).replace(/\s+/g, ' ').trim());
    return { rows: [{ spec: { vms: [{ name: 'sensor', os: 'rocky' }] } }], rowCount: 1 };
  }, async (fresh) => {
    const lane = challengeLane();
    lane.module_key = 'crucible';
    const vms = await fresh.loadSpecVms(lane, lane.config);
    assert.strictEqual(vms.length, 1);
    assert.strictEqual(asked.length, 1, 'crucible_challenge must not be queried twice');
    assert.match(asked[0], /FROM crucible_challenge/);
  });
});

test('a lane with no challenge_key never touches the database', async () => {
  // Workstation lanes have no challenge at all. Preserved from before E2, and
  // worth pinning: the fallback added a second table to try, and "try both on
  // every lane" would put two pointless round trips in front of every rung-1
  // resolution in CYBR 400 — the most common path in the product.
  let calls = 0;
  await withStubbedPool(async () => { calls += 1; return { rows: [], rowCount: 0 }; },
    async (fresh) => {
      const lane = workstationLane();
      assert.deepStrictEqual(await fresh.loadSpecVms(lane, lane.config), []);
      assert.strictEqual(calls, 0);
    });
});
