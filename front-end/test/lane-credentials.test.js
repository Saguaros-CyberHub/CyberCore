/**
 * lane-credentials.test.js — which login a lane workstation card shows.
 *
 * The bug this pins: a lane's credentials live in TWO shapes in the same JSONB
 * column, written by two different deployers.
 *
 *   utils/lane-deployer.js       → config.workstations[] (one entry per slot),
 *                                  AND slot 0 flattened onto config.workstation_*
 *   utils/challenge-lane-deployer.js → the flattened keys ONLY
 *
 * Read the flattened keys first and every slot of a multi-machine lane reports
 * slot 0's password — which is a WORKING credential for the wrong machine, so it
 * does not read as a bug to whoever is holding it. It reads as "the password
 * doesn't work on ws02", and the lane looks broken.
 *
 * The second thing worth pinning is that `credentials_source` is not decoration.
 * 'template' means the password is the image's own built-in account, identical on
 * every classmate's machine — migrations 025/026 exist because that field once
 * held Packer's WinRM build secrets and was rendered to students as if personal.
 * A caller that cannot tell the two apart cannot warn anyone.
 *
 * Run: node --test front-end/test/lane-credentials.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

// The module opens a Postgres pool at require time.
const dbPath = require.resolve(path.join(UTILS, 'cybercore-db.js'));
require.cache[dbPath] = {
  id: dbPath, filename: dbPath, loaded: true,
  exports: { cybercoreQuery: async () => ({ rows: [] }) },
};

const { resolveLaneWorkstationCredential } = require(path.join(UTILS, 'lane-credentials.js'));

/** A two-slot lane as lane-deployer actually writes it. */
function twoSlotLane() {
  return {
    workstations: [
      { slot: 0, vmid: 10581, hostname: 'ws01',
        workstation_user: 'cactus-user', workstation_pass: 'SLOT-ZERO-PW',
        credentials_source: 'cloudinit' },
      { slot: 1, vmid: 10582, hostname: 'ws02',
        workstation_user: 'sensor', workstation_pass: 'SLOT-ONE-PW',
        credentials_source: 'cloudinit' },
    ],
    // deployLaneWorkstations flattens slot 0 onto these, for the readers that
    // predate multi-slot lanes.
    workstation_user: 'cactus-user',
    workstation_pass: 'SLOT-ZERO-PW',
    credentials_source: 'cloudinit',
  };
}

// ── slot selection ───────────────────────────────────────────────────────────

test('the per-slot entry wins over the flattened slot-0 keys', () => {
  const c = resolveLaneWorkstationCredential(twoSlotLane(), '10582');
  assert.strictEqual(c.username, 'sensor');
  assert.strictEqual(c.password, 'SLOT-ONE-PW');
  assert.strictEqual(c.available, true);
});

test('provider_vmid is matched as a STRING against a numeric config vmid', () => {
  // provider_vmid is TEXT in the database (the deployers write String(vmid)),
  // config.workstations[].vmid is a number. A === between them is false for
  // every row in the table, which silently demotes every lane to slot 0.
  const asText = resolveLaneWorkstationCredential(twoSlotLane(), '10582');
  const asNumber = resolveLaneWorkstationCredential(twoSlotLane(), 10582);
  assert.deepStrictEqual(asText, asNumber);
  assert.strictEqual(asNumber.password, 'SLOT-ONE-PW');
});

test('slot 0 resolves to slot 0, not by accident of the fallback', () => {
  const c = resolveLaneWorkstationCredential(twoSlotLane(), '10581');
  assert.strictEqual(c.password, 'SLOT-ZERO-PW');
});

test('a vmid belonging to no slot does not borrow another slot password', () => {
  // The gateway, a lane target VM, a stale VMID — none of them are workstations,
  // and handing back slot 0's credential for one would be a working password for
  // a machine the caller did not ask about.
  const lane = { workstations: twoSlotLane().workstations };   // no flattened keys
  const c = resolveLaneWorkstationCredential(lane, '99999');
  assert.strictEqual(c.available, false);
  assert.strictEqual(c.password, null);
});

// ── the flattened-only shape (challenge lanes) ───────────────────────────────

test('a challenge lane, which has no workstations[] at all, still resolves', () => {
  // challenge-lane-deployer writes config.vms[] and the flattened keys only.
  const lane = {
    vms: [{ vm_id: 'x', name: 'target' }],
    workstation_user: 'ada',
    workstation_pass: 'KALI-PW',
    credentials_source: 'cloudinit',
  };
  const c = resolveLaneWorkstationCredential(lane, '20001');
  assert.strictEqual(c.username, 'ada');
  assert.strictEqual(c.password, 'KALI-PW');
  assert.strictEqual(c.available, true);
});

test('a null vmid falls through to the flattened keys rather than throwing', () => {
  const lane = { workstation_user: 'ada', workstation_pass: 'PW', credentials_source: 'cloudinit' };
  const c = resolveLaneWorkstationCredential(lane, null);
  assert.strictEqual(c.password, 'PW');
});

// ── source semantics ─────────────────────────────────────────────────────────

test("source 'template' is flagged shared — it is the image's own account", () => {
  const c = resolveLaneWorkstationCredential({
    workstation_user: 'Admin',
    workstation_pass: 'BAKED-IN',
    credentials_source: 'template',
  }, null);
  assert.strictEqual(c.available, true);
  assert.strictEqual(c.shared, true, 'a static template password must not pass as personal');
});

test("source 'cloudinit' is NOT shared", () => {
  const c = resolveLaneWorkstationCredential(twoSlotLane(), '10582');
  assert.strictEqual(c.shared, false);
});

test("source 'baked' reports why there is no password, rather than an empty one", () => {
  // LXC, or a clone with no cloud-init drive: nothing was injected and nothing
  // recorded. An empty string here would render as a password of length zero.
  const c = resolveLaneWorkstationCredential({
    workstations: [{ slot: 0, vmid: 7, credentials_source: 'baked' }],
  }, 7);
  assert.strictEqual(c.available, false);
  assert.strictEqual(c.password, null);
  assert.match(c.reason, /cloud-init/i);
});

test('a username with no password reports the account and withholds availability', () => {
  // metadata.default_rdp_pass is genuinely optional: the image ships a stable
  // account whose password the deployer never knew. The name is still useful.
  const c = resolveLaneWorkstationCredential({
    workstation_user: 'Admin',
    credentials_source: 'template',
  }, null);
  assert.strictEqual(c.username, 'Admin');
  assert.strictEqual(c.password, null);
  assert.strictEqual(c.available, false);
  assert.ok(c.reason);
});

// ── degenerate input ─────────────────────────────────────────────────────────

test('a lane still deploying, with an empty config, is unavailable not undefined', () => {
  for (const cfg of [null, undefined, {}, { workstations: [] }]) {
    const c = resolveLaneWorkstationCredential(cfg, '1');
    assert.strictEqual(c.available, false, `config ${JSON.stringify(cfg)}`);
    assert.strictEqual(c.username, null);
    assert.strictEqual(c.password, null);
    assert.ok(c.reason, 'an unavailable credential must say why');
  }
});

test('a non-array workstations value does not throw', () => {
  // config is free-form JSONB written by several deployers; a shape change
  // upstream must degrade to "no credential", never to a 500 on the card.
  const c = resolveLaneWorkstationCredential({ workstations: 'not-an-array' }, '1');
  assert.strictEqual(c.available, false);
});

test('the resolver never returns a password without available:true', () => {
  const cases = [
    twoSlotLane(),
    { workstation_user: 'a', credentials_source: 'template' },
    { workstations: [{ vmid: 1, credentials_source: 'baked' }] },
    {},
    null,
  ];
  for (const cfg of cases) {
    const c = resolveLaneWorkstationCredential(cfg, 1);
    if (c.password) {
      assert.strictEqual(c.available, true, 'a password was returned with available:false');
    }
  }
});
