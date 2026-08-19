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

const P = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils');
const target = require(path.join(P, 'attack-target.js'));

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
