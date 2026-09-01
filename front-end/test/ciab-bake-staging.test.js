/**
 * ciab-bake-staging.test.js — Track G5/S3: the two bake phases that touch the
 * cluster, asserted with no cluster.
 *
 * WHY THIS FILE EXISTS
 * bake-orchestrator's own tests prove the SEQUENCE is durable: the row moves,
 * the detached worker never throws, a missing phase fails rather than skips.
 * They prove nothing about the two phases that actually build and freeze
 * machines, because until now those phases refused by construction.
 *
 * Every property below is one that source text cannot check and a real run
 * cannot check either — the cheapest reproduction of a bake is ninety minutes
 * of Ansible on hardware, and the failures being guarded against are the ones
 * that report success:
 *
 *   1. ONE LANE, NOT A CLASS SET. deployChallengeLanes deploys one lane per
 *      user, so the length of `users` IS the lane count. A bake that passed two
 *      would pay for the chain twice and capture one of them, and nothing
 *      anywhere would say so.
 *
 *   2. THE IDS REACH THE ROW BEFORE THE DEPLOY RETURNS. staging_lane_id is the
 *      only handle anything will ever have on the lane a bake is building —
 *      teardownStagingLane says outright that a VMID with no lane row cannot be
 *      destroyed because nothing knows its node. The deployer returns ninety
 *      minutes after it inserts the row, so recording only its return value
 *      leaves the entire chain running against a lane the row cannot name.
 *
 *   3. CAPTURE NEVER SYSPREPS. This is the reflex answer for "make a template"
 *      and it destroys the domain the bake just spent ninety minutes building.
 *      Asserted DIRECTLY, against every call the phase makes: no guest-agent
 *      exec at all, and nothing anywhere carrying the string.
 *
 *   4. A HALF-CAPTURED LANE IS REFUSED, NOT FINISHED. Capture is the point of no
 *      return: a converted VM cannot be un-converted, so a retry that lands on a
 *      partially converted lane would assemble a golden set out of two separate
 *      runs of the chain, with a probe report that describes neither half.
 *
 *   5. A FAILURE LANDS ON THE ROW. Both phases run inside a detached bake that
 *      must never throw out of its own top level. Driven through the REAL
 *      bakeProfile, because that is the contract being relied on.
 *
 * OFFLINE BY CONSTRUCTION. bake-staging.js has no top-level requires — every
 * edge to Proxmox, to cybercore_db and to the shared deployer is behind
 * defaultDeps(), which builds closures that require one level down. So the
 * module under test loads with nothing stubbed, and a test that injects `deps`
 * never loads challenge-lane-deployer (which reads a gitignored config/site.json
 * at import) or cybercore-db (which builds a pg pool at import) at all.
 * ciab/utils/db.js IS stubbed through require.cache, completely, for the §5
 * tests that drive the real orchestrator.
 *
 * Run: node --test front-end/test/ciab-bake-staging.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const UTILS = path.join(ROOT, 'src', 'utils');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ── the orchestrator's database, stubbed COMPLETELY ─────────────────────────
// A partial stub leaves the real module loaded for whichever export was
// omitted, and that one builds a pg pool. Same shape as
// ciab-bake-orchestrator.test.js.
let dbLog = [];
stub(path.join(CIAB, 'utils', 'db.js'), {
  query: async (text, params) => {
    dbLog.push({ sql: String(text).replace(/\s+/g, ' ').trim(), params: params || [] });
    return { rows: [], rowCount: 0 };
  },
  getPool: () => null,
  setPool: () => {},
  pool: null,
});

const staging = require(path.join(CIAB, 'utils', 'bake-staging.js'));
const orch = require(path.join(CIAB, 'utils', 'bake-orchestrator.js'));

// ── fixtures ────────────────────────────────────────────────────────────────

const BAKE_ID = '22222222-2222-4222-8222-222222222222';
const PROFILE_ID = '11111111-1111-4111-8111-111111111111';
const ACTOR = '99999999-9999-4999-8999-999999999999';
const LANE_ID = '33333333-3333-4333-8333-333333333333';
const VXLAN = 10007;
const FIXED = { int: '10.39.16', ext: '10.39.17' };

function spec(over = {}) {
  return {
    subnet_scheme: 'v3',
    vxlan_block: { start: 10000, end: 10009 },
    vms: [{ name: 'DC01', template_vmid: 9001 }, { name: 'SRV02', template_vmid: 9002 }],
    ...over,
    goad: {
      enabled: true,
      version: 'CIAB-a1b2c3d4',
      fixed_subnet: { ...FIXED },
      lab: { forestRoot: 'clinic.local' },
      ...(over.goad || {}),
    },
  };
}

function bakeRow(over = {}) {
  return {
    bake_id: BAKE_ID,
    profile_id: PROFILE_ID,
    lab_hash: 'a1b2c3d4e5f6',
    lab_name: 'CIAB-a1b2c3d4',
    spec: spec(),
    staging_lane_id: null,
    staging_vxlan_id: null,
    controller_vmid: null,
    status: 'provisioning',
    golden_vmids: null,
    created_by: ACTOR,
    ...over,
  };
}

/** The lane row deployChallengeLanes would have inserted and then filled in. */
function laneRow(over = {}) {
  return {
    lane_id: LANE_ID,
    vxlan_id: VXLAN,
    status: 'active',
    config: {
      ciab_bake_id: BAKE_ID,
      node: 'pve1',
      gateway_vm_id: 100000 + VXLAN,
      attack_box_vm_id: 400000 + VXLAN,
      lane_subnet_base: FIXED.ext,
      lane_subnet_internal: FIXED.int,
      vms: [
        { vm_id: 500000 + VXLAN, name: 'DC01', type: 'qemu', node: 'pve1' },
        { vm_id: 500001 + VXLAN, name: 'SRV02', type: 'qemu', node: 'pve1' },
        { vm_id: 400000 + VXLAN, name: 'kali', type: 'qemu', node: 'pve1' },
        { vm_id: 100000 + VXLAN, name: 'gateway', type: 'lxc', node: 'pve1' },
      ],
      goad: {
        controller_vmid: 200000 + VXLAN,
        status: 'provisioned',
        probe: {
          ran: true, passed: true, reason: null, error: null,
          summary: { ok: 12, total: 12, failed: 0 }, errors: [], failed_checks: [],
        },
      },
      ...(over.config || {}),
    },
    ...(() => { const o = { ...over }; delete o.config; return o; })(),
  };
}

/** A step-args harness: records everything the phase writes back. */
function harness(bake) {
  const recorded = [];
  const details = [];
  return {
    recorded,
    details,
    args: {
      bake,
      phase: 'provisioning',
      step: 'provision',
      setDetail: async (d) => { details.push(String(d)); return true; },
      record: async (fields) => {
        // The REAL whitelist, so a phase that invents a column fails here rather
        // than having its value silently dropped.
        orch.assertStepPatch(fields, 'the test phase');
        recorded.push(fields);
        Object.assign(bake, fields);
        return true;
      },
    },
  };
}

/** cybercoreQuery over a fixed lane row and a fixed owner. */
function makeQuery({ lane = null, owner = { id: ACTOR, email: 'admin@clinic.local' } } = {}) {
  const calls = [];
  const fn = async (text, params) => {
    const sql = String(text).replace(/\s+/g, ' ').trim();
    calls.push({ sql, params });
    if (/FROM cybercore_user/.test(sql)) {
      return { rows: owner ? [owner] : [] };
    }
    if (/FROM cybercore_lane/.test(sql)) {
      return { rows: lane ? [lane] : [] };
    }
    return { rows: [] };
  };
  fn.calls = calls;
  return fn;
}

/**
 * A fake Proxmox holding a handful of QEMU guests.
 *
 * Every call the capture phase makes passes through here, which is what makes
 * the sysprep assertion TOTAL rather than a sample.
 */
function makeCluster(vms, { shutdownWorks = true } = {}) {
  const calls = [];
  const state = {};
  for (const vm of vms) state[String(vm.vmid)] = { ...vm };

  const find = (p) => {
    const m = /\/nodes\/([^/]+)\/qemu\/(\d+)/.exec(p);
    return m ? state[m[2]] : null;
  };

  const proxmoxAPI = async (method, p, body) => {
    calls.push({ method, path: p, body: body || null });
    const vm = find(p);
    if (!vm) throw new Error(`VM not found: ${p}`);
    if (method === 'GET' && /\/config$/.test(p)) {
      return { ...vm.config, ...(vm.template ? { template: 1 } : {}) };
    }
    if (method === 'GET' && /\/status\/current$/.test(p)) {
      return { status: vm.power, ...(vm.template ? { template: 1 } : {}) };
    }
    if (method === 'POST' && /\/status\/shutdown$/.test(p)) {
      if (shutdownWorks) vm.power = 'stopped';
      return 'UPID:pve1:shutdown';
    }
    if (method === 'PUT' && /\/config$/.test(p)) {
      if (body && body.delete) delete vm.config[body.delete];
      return null;
    }
    if (method === 'POST' && /\/template$/.test(p)) {
      vm.template = true;
      return 'UPID:pve1:template';
    }
    throw new Error(`unexpected call ${method} ${p}`);
  };

  return {
    calls,
    state,
    deps: {
      proxmoxAPI,
      waitForTask: async () => ({ exitstatus: 'OK' }),
      waitForPowerState: async (node, vmid, type, want) => {
        const vm = state[String(vmid)];
        if (vm && vm.power === want) return want;
        throw new Error(`VM ${vmid} never reached ${want}`);
      },
      sleep: async () => {},
    },
  };
}

function guest(vmid, over = {}) {
  return {
    vmid,
    node: 'pve1',
    power: 'running',
    template: false,
    config: { name: `vm-${vmid}`, ide2: 'local-lvm:vm-1-cloudinit,media=cdrom', scsi0: 'local-lvm:vm-1-disk-0' },
    ...over,
  };
}

// ═══════════════════════════════════════════════════════════════════════════
// 1. PROVISION — one lane, through the shared deployer
// ═══════════════════════════════════════════════════════════════════════════

test('provision drives the SHARED deployer for exactly one lane', async () => {
  let handed = null;
  const bake = bakeRow();
  const h = harness(bake);

  await staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 0,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      deployChallengeLanes: async (a) => {
        handed = a;
        return { provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN, node: 'pve1' }], failed: [], lanes: [] };
      },
    },
  });

  assert.ok(handed, 'the phase must go through deployChallengeLanes, not a private clone loop');
  assert.strictEqual(handed.users.length, 1,
    'deployChallengeLanes deploys ONE LANE PER USER, so the length of this array is the lane count — '
    + 'two users is two ninety-minute chains and one of them captured');
  assert.strictEqual(handed.users[0].id, ACTOR,
    'the lane belongs to the person who pressed Bake: cybercore_lane.user_id is not optional, and '
    + 'the gates require somebody to walk the solve path on this exact lane');
  assert.strictEqual(handed.moduleKey, 'ciab');
  assert.strictEqual(handed.challenge.subnet_scheme, 'v3');
  assert.strictEqual(handed.pinAllVms, true,
    'these machines become the templates the profile’s lanes clone — an address pinned at bake time '
    + 'and drawn from a pool at deploy time is a machine whose baked identity and lane address disagree');
  assert.strictEqual(handed.laneConfig.ciab_bake_id, BAKE_ID,
    'the ONLY thing that connects a cybercore_lane row to the bake that made it');
  assert.ok(!handed.laneConfig.profile_lane_group,
    'a staging lane must not carry the flag that puts a lane in the student panel — nobody has '
    + 'signed it off yet');
});

test('provision records the three ids recovery needs, and controller_vmid is derived, not guessed', async () => {
  const bake = bakeRow();
  const h = harness(bake);

  const patch = await staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 0,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      deployChallengeLanes: async () => ({
        provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [],
      }),
    },
  });

  assert.strictEqual(patch.staging_lane_id, LANE_ID);
  assert.strictEqual(patch.staging_vxlan_id, VXLAN);
  assert.strictEqual(patch.controller_vmid, 200000 + VXLAN);
  assert.ok(h.recorded.some((r) => r.staging_lane_id === LANE_ID),
    'and they are RECORDED, not merely returned — a bake that crashes between the two leaks the lane');
});

test('the controller VMID this file derives is the one goad-deploy actually creates', () => {
  // The one coupling here that behaviour cannot keep honest: goad-deploy does
  // not export its offset, and a bake that recorded the wrong controller VMID
  // would leave the real one running with nothing pointing at it.
  const src = fs.readFileSync(path.join(UTILS, 'goad-deploy.js'), 'utf8');
  assert.match(src, /const controllerVmId = 200000 \+ vxlanId;/,
    'bake-staging.CONTROLLER_VMID_OFFSET mirrors goad-deploy.deployController; if that derivation '
    + 'moves, the bake row starts naming a VM that does not exist');
  assert.strictEqual(staging.CONTROLLER_VMID_OFFSET, 200000);
  assert.strictEqual(staging.controllerVmidFor(VXLAN), 200000 + VXLAN);
  assert.strictEqual(staging.controllerVmidFor(0), null, 'a bad vxlan id must not become VMID 200000');
});

test('the lane ids reach the row BEFORE the ninety-minute deploy returns', async () => {
  // THE PROPERTY THE WATCHER EXISTS FOR. deployChallengeLanes inserts the lane
  // row minutes in and returns ninety minutes later; a bake that recorded only
  // its return value would run the whole chain against a lane the row cannot
  // name, and a crash in that window leaks a lane plus a controller VM that
  // nothing can enumerate.
  const bake = bakeRow();
  const h = harness(bake);
  let recordedDuringDeploy = false;

  await staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 1,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      deployChallengeLanes: async () => {
        // Stand in for the chain: give the watcher a few ticks to find the row
        // the deployer would already have inserted.
        for (let i = 0; i < 50 && !recordedDuringDeploy; i += 1) {
          await new Promise((r) => setTimeout(r, 2));
          recordedDuringDeploy = h.recorded.some((x) => x.staging_lane_id === LANE_ID);
        }
        return { provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [] };
      },
    },
  });

  assert.ok(recordedDuringDeploy,
    'staging_lane_id must be written while the chain is still running, not after it finishes');
});

test('a deploy that throws still leaves the lane findable, then fails', async () => {
  const bake = bakeRow();
  const h = harness(bake);

  await assert.rejects(() => staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 0,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow({ status: 'error' }) }),
      deployChallengeLanes: async () => { throw new Error('gateway clone failed'); },
    },
  }), /gateway clone failed/);

  assert.ok(h.recorded.some((r) => r.staging_lane_id === LANE_ID),
    'deployChallengeLanes marks the row it inserted "error" and rethrows — the lane is still there, '
    + 'and it is exactly the one somebody has to clean up');
});

test('provision hands the verify phase a report, and says so when there is none', async () => {
  const bake = bakeRow();
  const h = harness(bake);
  const patch = await staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 0,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      deployChallengeLanes: async () => ({
        provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [],
      }),
    },
  });
  assert.strictEqual(orch.gradeVerifyReport(patch.verify_report).ok, true,
    'a clean probe on the lane must grade clean in the verify phase');

  // And the absence of a report is a REFUSAL upstream, never an absence the
  // verify phase could mistake for a pass.
  const none = staging.verifyReportFromLane({ lane_id: LANE_ID, vxlan_id: VXLAN, config: {} });
  assert.strictEqual(none.ran, false);
  const verdict = orch.gradeVerifyReport(none);
  assert.strictEqual(verdict.ok, false);
  assert.match(verdict.detail, /did not run|no post-condition report/);
});

test('provision refuses a spec it cannot bake, before anything is allocated', async () => {
  const cases = [
    [{ goad: { enabled: false } }, /goad\.enabled/],
    [{ goad: { prebaked: true } }, /prebaked/],
    [{ vxlan_block: null }, /reserved VXLAN block/],
    [{ goad: { fixed_subnet: null } }, /fixed_subnet/],
  ];
  for (const [over, re] of cases) {
    const bake = bakeRow();
    const h = harness(bake);
    let deployed = false;
    await assert.rejects(() => staging.provisionStagingLane({
      ...h.args,
      spec: spec(over),
      watchIntervalMs: 0,
      deps: {
        cybercoreQuery: makeQuery({ lane: null }),
        findProfileChallenge: async () => null,
        deployChallengeLanes: async () => { deployed = true; return { provisioned: [], failed: [] }; },
      },
    }), re);
    assert.strictEqual(deployed, false,
      'the refusal has to land BEFORE the deployer allocates a VXLAN, a WAN address and a lane row');
  }
});

test('the staging lane draws from the CLIENT’s reservation, and never creates its own', async () => {
  // A bake's spec carries the compiled lab and nothing about networking. A bake
  // that reserved its own single-lane block would have it torn down and resized
  // by the client's first real deploy — teardownLabNetwork deletes the whole SDN
  // zone — with the ninety-minute chain still running on it.
  let handed = null;
  const bake = bakeRow();
  const h = harness(bake);
  const noBlock = spec({ vxlan_block: null });

  await staging.provisionStagingLane({
    ...h.args, spec: noBlock, watchIntervalMs: 0,
    deps: {
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      findProfileChallenge: async (id) => {
        assert.strictEqual(id, PROFILE_ID);
        return { challenge_id: 'chal-1', vxlan_block: { start: 10000, end: 10019 } };
      },
      deployChallengeLanes: async (a) => {
        handed = a;
        return { provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [] };
      },
    },
  });

  assert.deepStrictEqual(handed.challenge.spec.vxlan_block, { start: 10000, end: 10019 });
  assert.strictEqual(handed.challenge.challenge_id, null,
    'and the lane is NOT filed under the client’s reservation id: nothing enumerating the deploy '
    + 'group should find a lane nobody has signed off');
});

test('provision refuses a bake with no owner rather than inventing one', async () => {
  const bake = bakeRow({ created_by: null });
  const h = harness(bake);
  await assert.rejects(() => staging.provisionStagingLane({
    ...h.args, spec: spec(), watchIntervalMs: 0,
    deps: { cybercoreQuery: makeQuery({}), deployChallengeLanes: async () => ({ provisioned: [] }) },
  }), /created_by|owner/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. CAPTURE — the pinned subnet, and the sysprep that must never happen
// ═══════════════════════════════════════════════════════════════════════════

test('capture REFUSES without spec.goad.fixed_subnet, and names it', async () => {
  // The whole design rests on this. A provisioned forest writes its own
  // addresses into its DNS zone, its SYSVOL referrals and every SPN; clone it
  // onto a different base and each of those names an address the lane does not
  // have, while the lane reports `active` and nothing fails until a student
  // tries to authenticate.
  const missing = [
    [undefined, 'no fixed_subnet at all'],
    [{ int: '10.39.16' }, 'only the internal base'],
    [{ ext: '10.39.17' }, 'only the external base'],
    [{ int: ' ', ext: '10.39.17' }, 'a blank base, which applyFixedSubnet ignores silently'],
  ];

  for (const [fixed, why] of missing) {
    const bake = bakeRow({ staging_lane_id: LANE_ID });
    const h = harness(bake);
    const cluster = makeCluster([]);
    const err = await staging.captureGolden({
      ...h.args,
      spec: spec({ goad: { fixed_subnet: fixed } }),
      deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
    }).then(() => null, (e) => e);

    assert.ok(err, `capture must refuse with ${why}`);
    assert.strictEqual(err.code, 'BAKE_CAPTURE_NO_FIXED_SUBNET');
    assert.match(err.message, /spec\.goad\.fixed_subnet/,
      'the refusal names the field an operator has to set, not just that something is missing');
    assert.strictEqual(cluster.calls.length, 0,
      'and it refuses before it reads — let alone converts — a single machine');
  }
});

test('capture refuses a partial fixed_subnet spelled as a whole address', () => {
  assert.throws(() => staging.assertFixedSubnet(spec({ goad: { fixed_subnet: { int: '10.39.16.0/24', ext: '10.39.17' } } })),
    /not a \/24 base/);
});

test('capture NEVER issues a sysprep — asserted against every call it makes', async () => {
  // THE REFLEX ANSWER, AND IT IS WRONG HERE. Sysprep /generalize resets the
  // machine SID and the computer account password; on a domain controller that
  // is the directory itself, and Microsoft does not support it. The design
  // relies on atomic clone + cloud-init strip + a pinned subnet instead, so the
  // baked hostname, IP and machine password stay valid on every clone.
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([guest(500000 + VXLAN), guest(500001 + VXLAN)]);

  await staging.captureGolden({
    ...h.args,
    spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  });

  assert.ok(cluster.calls.length > 0, 'an empty call list would make this assertion vacuous');

  for (const call of cluster.calls) {
    const blob = `${call.method} ${call.path} ${JSON.stringify(call.body)}`;
    assert.ok(!/sysprep/i.test(blob), `capture issued a sysprep-shaped call: ${blob}`);
    assert.ok(!/\/agent\b/.test(call.path),
      'sysprep can only be run INSIDE the guest, so the phase must make no guest-agent call at all: '
      + `${blob}`);
    assert.ok(!/unattend|generalize|oobe/i.test(blob), `capture issued a generalisation call: ${blob}`);
  }

  // The positive half: it did the three things it is supposed to do instead.
  const paths = cluster.calls.map((c) => `${c.method} ${c.path}`);
  assert.ok(paths.some((p) => /POST .*\/status\/shutdown$/.test(p)), 'a clean ACPI shutdown');
  assert.ok(cluster.calls.some((c) => c.method === 'PUT' && /\/config$/.test(c.path) && c.body && c.body.delete === 'ide2'),
    'the cloud-init drive is stripped — without it cloudbase-init’s SetHostNamePlugin renames the '
    + 'clone to the Proxmox VM name and a member’s baked AD account no longer matches its host');
  assert.ok(paths.some((p) => /POST .*\/template$/.test(p)), 'and the VM becomes a template');
});

test('capture stops guests cleanly and never force-stops one', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([guest(500000 + VXLAN), guest(500001 + VXLAN)]);

  await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  });

  assert.ok(!cluster.calls.some((c) => /\/status\/stop$/.test(c.path)),
    'a hard stop is a power cut: it freezes NTDS.dit and SYSVOL mid-write, and every lane cloned '
    + 'from that template inherits the damage and still boots');
});

test('a guest that will not shut down cleanly refuses the capture instead of being killed', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([guest(500000 + VXLAN), guest(500001 + VXLAN)], { shutdownWorks: false });

  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  }).then(() => null, (e) => e);

  assert.ok(err);
  assert.strictEqual(err.code, 'BAKE_CAPTURE_STOP_FAILED');
  assert.ok(!cluster.calls.some((c) => /\/status\/stop$/.test(c.path)),
    'refusing is the point — forcing it off is what would produce a silently damaged golden set');
  assert.ok(!cluster.calls.some((c) => /\/template$/.test(c.path)),
    'and nothing was converted, so the lane is still exactly what it was');
});

// ═══════════════════════════════════════════════════════════════════════════
// 3. CAPTURE — idempotence at the point of no return
// ═══════════════════════════════════════════════════════════════════════════

test('a HALF-CAPTURED lane is refused rather than finished', async () => {
  // The retry case. One machine converted, one not: finishing would assemble a
  // golden set out of two runs of a ninety-minute chain, and the probe report
  // that passed describes neither half.
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([
    guest(500000 + VXLAN, { template: true, power: 'stopped' }),
    guest(500001 + VXLAN),
  ]);

  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  }).then(() => null, (e) => e);

  assert.ok(err, 'a partial capture must refuse');
  assert.strictEqual(err.code, 'BAKE_CAPTURE_PARTIAL');
  assert.match(err.message, /HALF CAPTURED/);
  assert.match(err.message, /DC01/, 'and it names which machines are on which side');
  assert.strictEqual(h.recorded.length, 0,
    'HALF-RECORDED IS THE FAILURE: golden_vmids naming one of two machines is a bake that reads '
    + "'ready' while every lane clones an incomplete forest");
  assert.ok(!cluster.calls.some((c) => /\/template$/.test(c.path)),
    'and nothing further was converted');
});

test('a lane whose machines cannot be read is refused, not captured around', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  // Only one of the two spec machines exists on the cluster.
  const cluster = makeCluster([guest(500000 + VXLAN)]);

  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  }).then(() => null, (e) => e);

  assert.strictEqual(err && err.code, 'BAKE_CAPTURE_VM_UNREADABLE');
  assert.strictEqual(h.recorded.length, 0);
});

test('a retry after a COMPLETE capture is a no-op that records what is there', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([
    guest(500000 + VXLAN, { template: true, power: 'stopped' }),
    guest(500001 + VXLAN, { template: true, power: 'stopped' }),
  ]);

  const patch = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  });

  assert.deepStrictEqual(Object.keys(patch.golden_vmids).sort(), ['DC01', 'SRV02']);
  assert.ok(!cluster.calls.some((c) => /\/template$/.test(c.path)),
    'a template cannot be un-converted, so re-converting is not idempotence — recording is');
});

test('classifyCapture is the whole rule, and it is pure', () => {
  const t = (over) => ({ name: 'X', vmid: 1, node: 'n', exists: true, isTemplate: false, ...over });
  assert.strictEqual(staging.classifyCapture([t({}), t({ name: 'Y', vmid: 2 })]).mode, 'capture');
  assert.strictEqual(
    staging.classifyCapture([t({ isTemplate: true }), t({ name: 'Y', vmid: 2, isTemplate: true })]).mode,
    'already_captured');
  assert.throws(() => staging.classifyCapture([t({}), t({ name: 'Y', vmid: 2, isTemplate: true })]),
    (e) => e.code === 'BAKE_CAPTURE_PARTIAL');
  assert.throws(() => staging.classifyCapture([t({ exists: false, error: 'gone' })]),
    (e) => e.code === 'BAKE_CAPTURE_VM_UNREADABLE');
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. CAPTURE — what becomes golden, and what must not
// ═══════════════════════════════════════════════════════════════════════════

test('golden_vmids is populated on success, and written after EVERY machine', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const cluster = makeCluster([guest(500000 + VXLAN), guest(500001 + VXLAN)]);

  const patch = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: laneRow() }) },
  });

  assert.deepStrictEqual(Object.keys(patch.golden_vmids).sort(), ['DC01', 'SRV02']);
  assert.strictEqual(patch.golden_vmids.DC01.vmid, 500000 + VXLAN);
  assert.strictEqual(patch.golden_vmids.DC01.node, 'pve1');

  const goldenWrites = h.recorded.filter((r) => r.golden_vmids);
  assert.strictEqual(goldenWrites.length, 2,
    'recorded after EVERY conversion, not at the end — a crash halfway leaves templates that only '
    + 'golden_vmids can name, and teardownStagingLane destroys exactly what it is told about');
  assert.deepStrictEqual(Object.keys(goldenWrites[0].golden_vmids), ['DC01'],
    'the first write names the first machine, which is the whole point of writing early');

  // The shape the orchestrator's teardown enumerator actually reads.
  assert.deepStrictEqual(orch.vmidsFromGolden(patch.golden_vmids).sort(),
    [500000 + VXLAN, 500001 + VXLAN].sort(),
    'a shape teardown cannot enumerate is a silent leak: it reports success and destroys nothing');
});

test('the gateway, Kali and the ansible controller are never captured', () => {
  const targets = staging.captureTargets({
    bake: bakeRow({ controller_vmid: 200000 + VXLAN }),
    lane: laneRow(),
  });
  assert.deepStrictEqual(targets.map((t) => t.name).sort(), ['DC01', 'SRV02']);

  // Each exclusion breaks something specific if it is dropped:
  //   gateway     an LXC whose whole config derives from the lane's vxlan id
  //   kali        carries a per-lane generated password
  //   controller  the ansible box; a pre-baked lane runs no chain at all
  const ids = targets.map((t) => t.vmid);
  assert.ok(!ids.includes(100000 + VXLAN), 'the gateway must not become a template');
  assert.ok(!ids.includes(400000 + VXLAN), 'a captured Kali hands every student the staging credential');
  assert.ok(!ids.includes(200000 + VXLAN), 'the controller exists to run the chain once');
});

test('a lane with nothing capturable is a refusal, not an empty success', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const bare = laneRow();
  bare.config.vms = [{ vm_id: 100000 + VXLAN, name: 'gateway', type: 'lxc', node: 'pve1' }];
  const cluster = makeCluster([]);

  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: bare }) },
  }).then(() => null, (e) => e);

  assert.strictEqual(err && err.code, 'BAKE_CAPTURE_NO_TARGETS',
    "a bake that reached 'ready' here would leave every lane cloning from nothing");
});

test('capture refuses a lane built on a different subnet than the profile pins', async () => {
  const bake = bakeRow({ staging_lane_id: LANE_ID });
  const h = harness(bake);
  const drifted = laneRow();
  drifted.config.lane_subnet_internal = '10.44.9';
  const cluster = makeCluster([guest(500000 + VXLAN), guest(500001 + VXLAN)]);

  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...cluster.deps, cybercoreQuery: makeQuery({ lane: drifted }) },
  }).then(() => null, (e) => e);

  assert.strictEqual(err && err.code, 'BAKE_CAPTURE_SUBNET_MISMATCH');
  assert.strictEqual(cluster.calls.length, 0, 'and nothing was touched');

  // "Could not check" is not "no drift" — the same rule assertBakeDeployable
  // applies to toolchain drift, for the same reason.
  const blind = laneRow();
  delete blind.config.lane_subnet_base;
  delete blind.config.lane_subnet_internal;
  assert.throws(() => staging.assertSubnetMatch(FIXED, blind),
    (e) => e.code === 'BAKE_CAPTURE_SUBNET_UNKNOWN');
});

test('capture refuses when provision recorded no staging lane', async () => {
  const bake = bakeRow({ staging_lane_id: null });
  const h = harness(bake);
  const err = await staging.captureGolden({
    ...h.args, spec: spec(),
    deps: { ...makeCluster([]).deps, cybercoreQuery: makeQuery({ lane: null }) },
  }).then(() => null, (e) => e);
  assert.strictEqual(err && err.code, 'BAKE_CAPTURE_NO_LANE');
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. WIRING — the orchestrator runs these, and a failure lands on the ROW
// ═══════════════════════════════════════════════════════════════════════════

test('buildBakeSteps binds provision and capture to bake-staging, not to a refusal', async () => {
  const seen = [];
  const steps = orch.buildBakeSteps({
    compileLab: async () => ({
      name: 'CIAB-a1b2c3d4',
      files: { 'data/config.json': '{}', 'data/inventory': '[all]\n' },
      chain: ['build.yml'],
    }),
    staging: {
      provisionStagingLane: async (a) => { seen.push(['provision', a.spec]); return { staging_lane_id: LANE_ID }; },
      captureGolden: async (a) => { seen.push(['capture', a.spec]); return { golden_vmids: { DC01: { vmid: 1 } } }; },
    },
  });

  const bake = bakeRow({ spec: spec() });
  const h = harness(bake);
  await steps.compile(h.args);
  await steps.push(h.args);
  const provisionPatch = await steps.provision(h.args);
  const capturePatch = await steps.capture(h.args);

  assert.deepStrictEqual(seen.map((s) => s[0]), ['provision', 'capture']);
  assert.strictEqual(provisionPatch.staging_lane_id, LANE_ID);
  assert.deepStrictEqual(capturePatch, { golden_vmids: { DC01: { vmid: 1 } } });
  assert.strictEqual(seen[0][1].goad.version, 'CIAB-a1b2c3d4',
    'both phases receive the spec the PUSH phase prepared, not the row’s untouched one — otherwise '
    + 'the staging lane deploys a lab the controller was never given');
  assert.strictEqual(seen[1][1].goad.fixed_subnet.int, FIXED.int,
    'and the pinned subnet survives that rewrite, or capture refuses a spec that was fine');
});

test('a failure in either phase is RECORDED on the row, never thrown out of the bake', async () => {
  // bakeProfile is detached: nothing awaits it, so a rejection out of its top
  // level lands on an unhandled-rejection handler instead of in the row, where
  // it is the only thing an operator can see.
  for (const [failing, message] of [['provision', 'no VXLAN capacity'], ['capture', 'half captured']]) {
    dbLog = [];
    const impl = {
      compileLab: async () => ({
        name: 'CIAB-a1b2c3d4',
        files: { 'data/config.json': '{}', 'data/inventory': '[all]\n' },
        chain: ['build.yml'],
      }),
      staging: {
        provisionStagingLane: async () => {
          if (failing === 'provision') throw new Error(message);
          return {
            verify_report: {
              ran: true, passed: true,
              report: { passed: true, summary: { ok: 1, total: 1 }, checks: [], errors: [] },
            },
          };
        },
        captureGolden: async () => { throw new Error(message); },
      },
    };

    const result = await orch.bakeProfile(bakeRow({ spec: spec() }), {
      steps: orch.buildBakeSteps(impl), heartbeatMs: 0,
    });

    assert.strictEqual(result.status, 'failed', `${failing} must fail the bake, not the process`);
    assert.match(result.error, new RegExp(message));
    const failWrite = dbLog.find((q) => /SET status = 'failed'/.test(q.sql));
    assert.ok(failWrite, 'and the failure reaches the ROW');
    assert.ok(String(failWrite.params[1]).includes(message),
      'carrying the reason, because phase_detail still holds where it happened and the error holds why');
  }
});

test('a phase that returns a column nobody wired up fails the bake rather than losing it', async () => {
  // The orchestrator's whitelist, exercised through the real steps: a capture
  // that recorded golden VMIDs under some other key would have them silently
  // dropped, and the bake would reach 'ready' with lanes cloning from nothing.
  const steps = orch.buildBakeSteps({
    compileLab: async () => ({ name: 'L', files: { 'data/x': '1' }, chain: ['a.yml'] }),
    staging: {
      provisionStagingLane: async () => ({ golden_vm_ids: [1] }),
      captureGolden: async () => ({}),
    },
  });
  const h = harness(bakeRow({ spec: spec() }));
  await steps.compile(h.args);
  const patch = await steps.provision(h.args);
  assert.throws(() => orch.assertStepPatch(patch, "the 'provision' phase"), /unknown column/);
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. THE COMPANY WEBSITE — the curated cc_web role, actually invoked
//
// The role in infrastructure/ansible/cc-web has always been able to build the
// DMZ web tier the paper describes, and nothing has ever called it: every bake
// produced a forest with no company in front of it. These tests drive the REAL
// provision phase and assert what it does to the REAL controller — which role
// files it stages, what variables it derives, what argv it launches — because
// "the role exists and its own tests pass" is exactly the shape of failure this
// track keeps producing.
//
// The controller and the DMZ host are a fake that interprets the handful of
// shell commands the phase issues, so the assertions are about the bytes that
// would really land on the machines rather than about a mock's call log.
// ═══════════════════════════════════════════════════════════════════════════

const compileMod = require(path.join(CIAB, 'utils', 'goad-lab-compile.js'));
const contentMod = require(path.join(CIAB, 'utils', 'goad-lab-content.js'));

const WEB_VM = 'web01';
const WEB_VMID = 700000 + VXLAN;

const WEB_CLIENT = Object.freeze({
  // PINNED, and pinned for its chain shape: RUN_BAKE_WEB_7 designs a
  // 'web_credential' entry, whose foothold the chain plants ON THE WEBSITE. That
  // is the case the seam tests below are about — for an AD-side entry the site
  // deliberately publishes an inert account instead, which is its own test in
  // ciab-goad-lab-content.test.js.
  runId: 'RUN_BAKE_WEB_7',
  company: 'Ridgeline Dental Group',
  domain: 'ridgelinedental.com',
  employees: 46,
  city: 'Boise, ID',
  departments: { Clinical: 18, Administration: 9, Finance: 5, IT: 3 },
  stakeholders: [
    { name: 'Alice Kwan', role: 'Practice Principal', department: 'Clinical' },
    { name: 'Tom Iverson', role: 'Practice Manager', department: 'Administration' },
    { name: 'Nadia Farouk', role: 'Head of Nursing', department: 'Clinical' },
  ],
});

function webProfile(o) {
  return {
    json_data: {
      student_view: {
        meta: { run_id: o.runId, client_type: 'SMB', difficulty: 'intermediate' },
        quick: { company_name: o.company, employees_total: o.employees },
        raw: {
          threats: {
            organization: {
              company_name: o.company, domain_public: o.domain, employees_total: o.employees,
              hq_city: o.city, industry: 'Healthcare', department_breakdown: o.departments,
            },
            it_environment: { delivery: 'Hybrid' },
          },
        },
        stakeholders: o.stakeholders,
      },
    },
  };
}

let webLabCache = null;
/** A real compiled client, and the website the generator authors for it. */
function webLab() {
  if (!webLabCache) {
    const compiled = compileMod.compileLabWithChain(webProfile(WEB_CLIENT));
    const lab = JSON.parse(compiled.files['data/config.json']).lab;
    webLabCache = {
      ir: compiled.ir,
      lab,
      // Deterministic, so regenerating it here is a legitimate way to know what
      // the phase is about to derive — and an implicit assertion that it is.
      site: contentMod.generateSiteContent(compiled.ir, { runId: compiled.run_id }),
    };
  }
  return webLabCache;
}

/** A spec that carries a real compiled lab and a dual-homed DMZ machine. */
function webSpec(over = {}) {
  const { ir } = webLab();
  return spec({
    vms: [
      { name: 'DC01', template_vmid: 9001 },
      { name: 'SRV02', template_vmid: 9002 },
      {
        name: WEB_VM,
        template_vmid: 1005,
        // The v3 pivot: two segments, which is what makes it .240 on both and
        // the one machine that can bridge the engagement.
        nics: [{ segment: 'ext' }, { segment: 'int' }],
      },
    ],
    ...over,
    goad: { lab: ir, ...(over.goad || {}) },
  });
}

/** The lane row the deployer would have written for that spec. */
function webLaneRow(over = {}) {
  const row = laneRow(over);
  row.config.vms = row.config.vms.concat([
    { vm_id: WEB_VMID, name: WEB_VM, type: 'qemu', node: 'pve1' },
  ]);
  return row;
}

/** What cc_web's verify.yml would publish for a site it built correctly. */
function observedFor(site, mutate) {
  const out = {
    product: 'apache',
    version: site.web_facts.version,
    ports: site.web_facts.ports.slice(),
    tls: {
      enabled: site.web_facts.tls.enabled,
      port: site.web_facts.tls.port,
      // The role publishes its own normalised spellings, not the ones it was
      // handed — which is exactly why both sides go through readWebFacts.
      protocols: site.web_facts.tls.protocols.map((p) => p.toLowerCase().replace(/[^a-z0-9.]/g, '')),
    },
    paths: site.web_facts.paths.slice(),
    server_name: site.server_name,
    docroot: site.docroot,
    pivot_credential_path: site.pivot.path,
    verified_at: '2026-01-01T00:00:00Z',
  };
  return mutate ? mutate(out) : out;
}

/**
 * A controller and a DMZ host that interpret the commands the phase sends.
 *
 * Small on purpose: it understands the chunked base64 write, ssh-keygen, the
 * authorized_keys append, the detached launch and the `[ -f ] && cat` read, and
 * nothing else. Anything the phase learns to do that is not one of those shows
 * up here as an unhandled command rather than as a silently green test.
 */
function fakeControllerCluster({ observed = null, exitCode = 0 } = {}) {
  const calls = [];
  const files = {};
  const at = (vmId) => (files[vmId] = files[vmId] || {});
  const pending = new Map();
  let pid = 0;
  let launched = null;
  const unhandled = [];

  const run = (vmId, argv) => {
    calls.push({ vmId, argv });
    const script = String(argv[2] || '');
    const ok = (stdout) => ({ exited: true, exitcode: 0, stdout: stdout || '', stderr: '' });

    let m = script.match(/printf '%s' '([A-Za-z0-9+/=]*)' (>>?) '([^']+)'/);
    if (m) {
      const store = at(vmId);
      store[m[3]] = m[2] === '>>' ? `${store[m[3]] || ''}${m[1]}` : m[1];
      return ok();
    }
    m = script.match(/base64 -d < '([^']+)' > '([^']+)'/);
    if (m) {
      const store = at(vmId);
      store[m[2]] = Buffer.from(store[m[1]] || '', 'base64').toString('utf8');
      delete store[m[1]];
      return ok();
    }
    m = script.match(/ssh-keygen[\s\S]*cat '([^']+)\.pub'/);
    if (m) {
      at(vmId)[m[1]] = 'PRIVATE KEY';
      return ok('ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTheBake cc-web-bake\n');
    }
    if (/getent passwd/.test(script)) {
      const store = at(vmId);
      store.__authorized_keys = `${store.__authorized_keys || ''}ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeKeyForTheBake cc-web-bake\n`;
      return ok();
    }
    m = script.match(/nohup setsid sh -c "([\s\S]+)" <\/dev\/null/);
    if (m) {
      launched = m[1];
      const store = at(vmId);
      const done = m[1].match(/echo \\?\$\? > '([^']+)'/);
      const log = m[1].match(/> '([^']+)' 2>&1/);
      const vars = Object.keys(store).filter((p) => /cc-web-vars\.yml$/.test(p))[0];
      const dest = vars && (store[vars].match(/^cc_web_observed_dest: "(.+)"$/m) || [])[1];
      if (log) store[log[1]] = 'PLAY RECAP\nweb01 : ok=31 changed=12 unreachable=0 failed=0\n';
      if (dest && observed) store[dest] = `${JSON.stringify(observed, null, 2)}\n`;
      if (done) store[done[1]] = `${exitCode}\n`;
      return ok();
    }
    m = script.match(/^\[ -f '([^']+)' \] && cat/);
    if (m) return ok(files[vmId] && files[vmId][m[1]] != null ? files[vmId][m[1]] : '__MISSING__');

    unhandled.push({ vmId, script });
    return { exited: true, exitcode: 127, stdout: '', stderr: 'unhandled command' };
  };

  return {
    calls,
    files,
    unhandled,
    launched: () => launched,
    controller: () => files[200000 + VXLAN] || {},
    dmz: () => files[WEB_VMID] || {},
    deps: {
      agentExecArgv: async (node, vmId, argv) => {
        pid += 1;
        pending.set(pid, run(vmId, argv));
        return { pid };
      },
      pollExecStatus: async (node, vmId, p) => pending.get(p)
        || { exited: true, exitcode: 0, stdout: '', stderr: '' },
      sleep: async () => {},
    },
  };
}

/** Drive the REAL provision phase with a real lab, a real lane and the fake. */
async function provisionWithWeb({ observed, exitCode, specOver, laneOver, plainLane } = {}) {
  const bake = bakeRow({ spec: webSpec(specOver) });
  const h = harness(bake);
  const cluster = fakeControllerCluster({ observed, exitCode });
  const lane = plainLane ? laneRow(laneOver) : webLaneRow(laneOver);
  let error = null;
  let patch = null;
  try {
    patch = await staging.provisionStagingLane({
      ...h.args,
      spec: bake.spec,
      watchIntervalMs: 0,
      deps: {
        ...cluster.deps,
        cybercoreQuery: makeQuery({ lane }),
        deployChallengeLanes: async () => ({
          provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [],
        }),
      },
    });
  } catch (err) { error = err; }
  return { bake, h, cluster, patch, error };
}

test('the staging bake INVOKES cc_web against the DMZ host, with the real role tree', async () => {
  const { site } = webLab();
  const { error, patch, cluster } = await provisionWithWeb({ observed: observedFor(site) });

  assert.strictEqual(error, null, error && error.message);
  assert.deepStrictEqual(cluster.unhandled, [],
    'the phase issued a command this fake does not model, so the test proved less than it looks like');

  // 1. the ROLE, verbatim out of the repository — not a copy pasted into JS.
  const staged = cluster.controller();
  const disk = staging.readCcWebTree();
  const stagedRole = Object.keys(staged).filter((p) => /\/cc-web\/roles\/cc_web\//.test(p));
  assert.ok(stagedRole.length >= 10, `only ${stagedRole.length} role files reached the controller`);
  for (const [rel, body] of Object.entries(disk)) {
    const landed = Object.keys(staged).find((p) => p.endsWith(`/cc-web/${rel}`));
    assert.ok(landed, `${rel} was never staged on the controller`);
    assert.strictEqual(staged[landed], body, `${rel} did not arrive byte for byte`);
  }
  assert.ok(disk['roles/cc_web/tasks/main.yml'].indexOf('verify.yml') !== -1,
    'the staged tree is the curated role, verification pass and all');

  // 2. the PLAY that applies it, run with this tree's own ansible.cfg so ./roles
  //    resolves ahead of upstream GOAD's read-only role library.
  const launched = cluster.launched();
  assert.ok(/cd '[^']*\/cc-web' && ANSIBLE_CONFIG=\.\/ansible\.cfg /.test(launched),
    `the run does not cd into the staged tree with its own ansible.cfg: ${launched}`);
  assert.ok(/'ansible-playbook'/.test(launched) && /'cc-web\.yml'/.test(launched),
    'cc-web.yml is THE play that applies the role; the bake must run it rather than re-declaring it');

  // 3. against the DMZ host, at the address the deployer pins it to.
  const inv = Object.keys(staged).filter((p) => /inventory$/.test(p))[0];
  assert.ok(inv, 'no inventory was written');
  assert.ok(/^\[cc_web\]$/m.test(staged[inv]),
    "cc-web.yml's inventory contract is one group named cc_web holding exactly the DMZ host");
  assert.ok(staged[inv].indexOf(`ansible_host=${FIXED.ext}.${staging.CC_WEB_DMZ_OCTET}`) !== -1,
    `the DMZ host is pinned to .${staging.CC_WEB_DMZ_OCTET} on both segments; the inventory must `
    + `name that address: ${staged[inv]}`);
  assert.ok(staged[inv].indexOf('DC01') === -1 && staged[inv].indexOf('SRV02') === -1,
    'the cc_web group must not overlap a GOAD inventory group');

  // 4. and it is RECORDED as having happened.
  assert.strictEqual(patch.verify_report.cc_web.passed, true, patch.verify_report.cc_web.reason);
  assert.strictEqual(patch.verify_report.cc_web.host, WEB_VM);
  assert.strictEqual(patch.verify_report.cc_web.server_name, site.server_name);
  assert.strictEqual(patch.verify_report.passed, true,
    'the GOAD half of the report has to survive the web half being added to it');
});

test('the cc_web variables are DERIVED FROM THE LAB, not literals', async () => {
  const { site, ir } = webLab();
  const { cluster, error } = await provisionWithWeb({ observed: observedFor(site) });
  assert.strictEqual(error, null, error && error.message);

  const staged = cluster.controller();
  const varsPath = Object.keys(staged).filter((p) => /cc-web-vars\.yml$/.test(p))[0];
  assert.ok(varsPath, 'no variables file was written');
  const vars = staged[varsPath];

  // The identity every one of these is derived from.
  const publicDomain = ir.domains[0].fqdn.replace(/^corp\./, '');
  assert.ok(vars.indexOf(`cc_web_server_name: "www.${publicDomain}"`) !== -1,
    `the vhost ServerName is the CLIENT's public domain: ${vars.split('\n').filter((l) => /server_name/.test(l))}`);
  assert.ok(vars.indexOf('cc_web_facts:') !== -1 && vars.indexOf('product: "apache"') !== -1);
  for (const port of site.web_facts.ports) {
    assert.ok(new RegExp(`^\\s+- ${port}$`, 'm').test(vars), `port ${port} is not in the declared set`);
  }
  for (const declared of site.web_facts.paths) {
    assert.ok(vars.indexOf(`"${declared}"`) !== -1, `declared path ${declared} never reached the role`);
  }
  // The staff on the About page are the accounts the forest creates.
  for (const person of site.staff) {
    assert.ok(vars.indexOf(person.name) !== -1, `${person.name} is on the site and not in the vars`);
    assert.ok(ir.principals.users.some((u) => u.sam === person.sam));
  }
  // Nothing in the phase names a company. If it did, this client's own name
  // would not be the only one in the file.
  assert.ok(vars.indexOf('example.com') === -1 && vars.indexOf('acme') === -1,
    'a placeholder identity reached the role');
});

test('the credential the role plants is the one the IR declares, and never an argument', async () => {
  const { site, ir } = webLab();
  const { cluster, error, patch } = await provisionWithWeb({ observed: observedFor(site) });
  assert.strictEqual(error, null, error && error.message);

  const staged = cluster.controller();
  const varsPath = Object.keys(staged).filter((p) => /cc-web-vars\.yml$/.test(p))[0];
  const vars = staged[varsPath];
  const cred = ir.foothold_credential;

  assert.ok(vars.indexOf(`username: "${cred.sam}"`) !== -1,
    'the account in the app config is the account the chain starts at');
  assert.ok(vars.indexOf(`password: "${cred.password}"`) !== -1,
    'the website must plant the exact string the forest is built with; anything else is a lab whose '
    + 'second act never starts');
  const user = ir.principals.users.filter((u) => u.sam === cred.sam)[0];
  assert.strictEqual(user.password, cred.password, 'and AD honours it');

  // THE PASSWORD IS NEVER ON A COMMAND LINE. It would be visible in `ps`, in the
  // ansible task banner and in the job log an instructor can read.
  for (const call of cluster.calls) {
    const flat = call.argv.join(' ');
    assert.ok(flat.indexOf(cred.password) === -1,
      `the pivot password reached a command line: ${flat.slice(0, 200)}`);
  }
  assert.ok(cluster.launched().indexOf(cred.password) === -1);
  // Nor into the report an instructor reads.
  assert.strictEqual(JSON.stringify(patch.verify_report.cc_web).indexOf(cred.password), -1,
    'the bake row carries the pivot ACCOUNT so a grader can name it, never the password');
  assert.ok(patch.verify_report.cc_web.pivot_account.indexOf(cred.sam) !== -1);
});

test('route content is tagged !unsafe, because ansible would otherwise evaluate it', async () => {
  const { site } = webLab();
  const { cluster, error } = await provisionWithWeb({ observed: observedFor(site) });
  assert.strictEqual(error, null, error && error.message);
  const staged = cluster.controller();
  const vars = staged[Object.keys(staged).filter((p) => /cc-web-vars\.yml$/.test(p))[0]];
  const tagged = vars.split('\n').filter((l) => /^\s+content: !unsafe "/.test(l));
  assert.strictEqual(tagged.length, site.routes.length,
    'every page has to be tagged: ansible renders a variable value recursively, and roles/cc_web/'
    + 'tasks/content.yml says outright that the role cannot defend against it — the caller must');
});

test('a host that does not serve what the paper claims REFUSES the bake', async () => {
  const { site } = webLab();
  // The listener came up offering only a modern protocol while the report says
  // the lane is vulnerable to a weak one. Everything is green: apache started,
  // the port is open, and the student's sslscan finds nothing to find.
  const { error, bake } = await provisionWithWeb({
    observed: observedFor(site, (o) => Object.assign(o, { tls: { ...o.tls, protocols: ['tlsv1.2'] } })),
  });
  assert.ok(error, 'a lane whose TLS does not match the report must not reach the gates');
  assert.strictEqual(error.code, 'BAKE_PROVISION_WEB_FAILED');
  assert.ok(/TLS protocols/.test(error.message), error.message);

  // RECORDED BEFORE IT THREW: the row is the only place an operator can read why.
  const recorded = bake.verify_report;
  assert.ok(recorded && recorded.cc_web, 'the failure has to reach the bake row');
  assert.strictEqual(recorded.cc_web.passed, false);
  assert.ok(recorded.cc_web.differences.some((d) => /TLS protocols/.test(d)));
  assert.deepStrictEqual(recorded.cc_web.declared_facts, site.web_facts);
});

test('a role that reports success and publishes nothing is not a pass', async () => {
  const { error, bake } = await provisionWithWeb({ observed: null, exitCode: 0 });
  assert.ok(error, '"it said green" is not evidence — that is why the role writes an observed file');
  assert.ok(/published no observed facts/.test(bake.verify_report.cc_web.reason),
    bake.verify_report.cc_web.reason);
});

test('a role that refuses is reported with the tail of its own run', async () => {
  const { site } = webLab();
  const { error, bake } = await provisionWithWeb({ observed: observedFor(site), exitCode: 2 });
  assert.ok(error);
  assert.strictEqual(bake.verify_report.cc_web.passed, false);
  assert.ok(/exited 2/.test(bake.verify_report.cc_web.reason));
  assert.ok(/PLAY RECAP/.test(bake.verify_report.cc_web.log_tail),
    'the operator reading this is not the person who wrote the role, so the run has to come back with it');
});

test('a lane with no dual-homed DMZ host is a REFUSAL that names what would fix it', async () => {
  const { site } = webLab();
  const { error } = await provisionWithWeb({
    observed: observedFor(site),
    specOver: { vms: [{ name: 'DC01', template_vmid: 9001 }] },
    plainLane: true,
  });
  assert.ok(error, 'the website is half of what an external engagement is');
  assert.strictEqual(error.code, 'BAKE_PROVISION_NO_DMZ_HOST');
  assert.ok(/spec\.cc_web\.host/.test(error.message) && /cc_web\.enabled = false/.test(error.message),
    'a refusal an operator cannot act on is only marginally better than the silence it replaces');
});

test('an AD-only environment is a DECLARATION on the spec, never a silence', async () => {
  const { patch, error, cluster } = await provisionWithWeb({
    specOver: { cc_web: { enabled: false }, vms: [{ name: 'DC01', template_vmid: 9001 }] },
    plainLane: true,
  });
  assert.strictEqual(error, null, error && error.message);
  assert.strictEqual(patch.verify_report.cc_web.applicable, false);
  assert.ok(/AD-only/.test(patch.verify_report.cc_web.reason));
  assert.strictEqual(cluster.calls.length, 0, 'nothing was staged for an environment with no website');
});

test('a bake carrying no compiled lab says so rather than inventing a company', async () => {
  // The pre-existing fixture: spec.goad.lab names a forest and nothing else.
  const bake = bakeRow();
  const h = harness(bake);
  const cluster = fakeControllerCluster();
  const patch = await staging.provisionStagingLane({
    ...h.args,
    spec: spec(),
    watchIntervalMs: 0,
    deps: {
      ...cluster.deps,
      cybercoreQuery: makeQuery({ lane: laneRow() }),
      deployChallengeLanes: async () => ({
        provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [],
      }),
    },
  });
  assert.strictEqual(patch.verify_report.cc_web.applicable, false);
  assert.ok(/no compiled lab/.test(patch.verify_report.cc_web.reason));
});

test('the observed facts are compared through the SCAN DOCUMENTS\' own reader', () => {
  const { site } = webLab();
  const clean = staging.compareWebFacts(site.web_facts, observedFor(site));
  assert.strictEqual(clean.match, true, clean.differences.join('; '));

  // A spelling difference the report would not trip over must not fail it: the
  // role publishes 'tlsv1.0' and a compiler writes 'TLSv1.0'.
  const spelt = staging.compareWebFacts(
    { ...site.web_facts, tls: { ...site.web_facts.tls, protocols: ['TLS 1.0', 'tls1.2'] } },
    observedFor(site, (o) => Object.assign(o, { tls: { ...o.tls, protocols: ['tlsv1.0', 'tlsv1.2'] } }))
  );
  assert.strictEqual(spelt.match, true, spelt.differences.join('; '));

  // A real difference must.
  for (const [mutate, needle] of [
    [(o) => Object.assign(o, { product: 'nginx' }), /product/],
    [(o) => Object.assign(o, { version: '2.4.99' }), /version/],
    // NOT `[80]`: readWebFacts folds a declared TLS listener's port back into
    // the set, so dropping 443 alone is a difference the contract itself says is
    // not one. A port the host binds and the paper never mentions is.
    [(o) => Object.assign(o, { ports: [8081] }), /ports/],
    [(o) => Object.assign(o, { paths: ['/'] }), /paths/],
    [(o) => Object.assign(o, { tls: { ...o.tls, enabled: false } }), /TLS/],
  ]) {
    const bad = staging.compareWebFacts(site.web_facts, observedFor(site, mutate));
    assert.strictEqual(bad.match, false);
    assert.ok(bad.differences.some((d) => needle.test(d)), bad.differences.join('; '));
  }
});

test('the variables file is YAML the role can read, and quotes what must stay a string', () => {
  const yaml = staging.toVarsYaml({
    cc_web_facts: { product: 'apache', ports: [80, 443], tls: { enabled: true, protocols: ['TLSv1.0'] } },
    cc_web_routes: [{ path: '/', file: 'index.html', content: staging.unsafeScalar('<p>hi "there"</p>\n') }],
    cc_web_pivot: { mode: '0640', allow_in_docroot: true, extra: {} },
  });
  assert.strictEqual(yaml, [
    '---',
    'cc_web_facts:',
    '  product: "apache"',
    '  ports:',
    '    - 80',
    '    - 443',
    '  tls:',
    '    enabled: true',
    '    protocols:',
    '      - "TLSv1.0"',
    'cc_web_routes:',
    '  - path: "/"',
    '    file: "index.html"',
    '    content: !unsafe "<p>hi \\"there\\"</p>\\n"',
    'cc_web_pivot:',
    // QUOTED. YAML 1.1 reads an unquoted 0640 as the integer 640, and the role
    // then applies mode 0o1200 — a credential file the exercise cannot read.
    '  mode: "0640"',
    '  allow_in_docroot: true',
    '  extra: {}',
    '',
  ].join('\n'));
});

test('the cc_web role itself carries NO company literal, for any client', () => {
  // The role is variable-driven or it is not reusable. Checked against two real
  // generated clients rather than against a list of words somebody remembered.
  const tree = staging.readCcWebTree();
  const body = Object.values(tree).join('\n');
  const { site, ir } = webLab();
  const forbidden = [
    site.org, site.public_domain, site.server_name, ir.domains[0].fqdn,
    site.portal_path, site.admin_path, site.pivot.username, site.pivot.password,
    WEB_CLIENT.city, WEB_CLIENT.company,
  ].concat(site.staff.map((s) => s.name)).concat(site.staff.map((s) => s.sam));

  for (const literal of forbidden) {
    assert.ok(String(literal).length > 2, `refusing to search for '${literal}'`);
    const hit = Object.keys(tree).find((p) => tree[p].indexOf(literal) !== -1);
    assert.ok(!hit, `the role names '${literal}' in ${hit}. The AI writes the site; the role installs `
      + 'whatever it was handed, and an identity in the role is a role that can build exactly one '
      + "client's website");
  }
  // And the identity-bearing variables really are empty in defaults/.
  const defaults = tree['roles/cc_web/defaults/main.yml'];
  assert.ok(/cc_web_server_name: ""/.test(defaults));
  assert.ok(/cc_web_routes: \[\]/.test(defaults));
  assert.ok(/cc_web_pivot: \{\}/.test(defaults),
    'a password with a default is a password that ships');
  assert.ok(body.indexOf('cc_web_facts') !== -1, 'the role still reads the web-facts contract');
});

test('the REAL bake steps object reaches the role, not just this module export', async () => {
  // THE BAR THIS PROJECT KEEPS FAILING is not "the code is written", it is
  // "something drives it". buildBakeSteps() is the ONE place the five phases are
  // bound to the code that performs them, so this drives the phase through that
  // object with only the cluster faked, and asserts the curated role really
  // arrived on the controller and really got run.
  const { site } = webLab();
  const cluster = fakeControllerCluster({ observed: observedFor(site) });
  const steps = orch.buildBakeSteps({
    compileLab: async () => ({
      name: 'CIAB-a1b2c3d4',
      files: { 'data/config.json': '{}', 'data/inventory': '[all]\n' },
      chain: ['build.yml'],
    }),
    stagingDeps: {
      ...cluster.deps,
      cybercoreQuery: makeQuery({ lane: webLaneRow() }),
      deployChallengeLanes: async () => ({
        provisioned: [{ lane_id: LANE_ID, vxlan_id: VXLAN }], failed: [], lanes: [],
      }),
    },
  });

  const bake = bakeRow({ spec: webSpec() });
  const h = harness(bake);
  await steps.compile(h.args);
  await steps.push(h.args);
  const patch = await steps.provision(h.args);

  assert.strictEqual(patch.verify_report.cc_web.passed, true, patch.verify_report.cc_web.reason);
  const staged = cluster.controller();
  assert.ok(Object.keys(staged).some((p) => p.endsWith('/cc-web/roles/cc_web/tasks/main.yml')),
    'the bake steps object ran the phase and the cc_web role never reached the controller');
  assert.ok(/'ansible-playbook'/.test(cluster.launched()));
  // And the verify phase, which is what decides whether the bake is ready, still
  // grades the GOAD half correctly with the web half attached to the same report.
  h.args.bake.verify_report = patch.verify_report;
  await steps.verify(h.args);
});
