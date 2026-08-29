/**
 * ciab-reservation.test.js — one CIAB client, several engagements, one shared
 * network provisioner.
 *
 * WHY THIS FILE EXISTS
 * ciab-deploy-parity.test.js pins the DESTINATION as source text: no private SDN
 * provisioner, no profile-only reservation key. Source text cannot tell you
 * whether the replacement actually behaves, and the two things most likely to go
 * wrong here are invisible to it:
 *
 *   1. Continuity. Every CIAB VNet already on the cluster sits in the Proxmox SDN
 *      zone 'ciabprof', because the old code derived the zone from the challenge
 *      key through sanitizeZoneAbbrev — which truncates to 8 characters, so every
 *      'ciab-profile-<anything>' collapsed to the same name. Changing the key
 *      format must not change that, and the reservations already in cybercore_db
 *      have no spec.zone.abbrev for the shared teardown to read.
 *
 *   2. Aliasing. The headline requirement of the whole program is "client A wants
 *      an internal test, client B wants external". Both are engagements against a
 *      profile, and a profile-keyed reservation makes the second silently adopt
 *      the first's VXLAN block — after which tearing either down takes the
 *      other's live lanes with it.
 *
 * WHAT THIS FILE IS
 * A runtime test of the real reservation code against a fake cybercore_db and a
 * fake Proxmox. src/utils/lab-network-provision.js is NOT stubbed: the point is
 * to exercise the seam CIAB now depends on, including that the shared teardown
 * refuses to re-carve a block that still has lanes in it.
 *
 * Run: node --test front-end/test/ciab-reservation.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

// Required BEFORE the stubs so the fake below can assert against the real
// predicate rather than a copy of it that can drift.
const { claimsSql, RELEASED_STATUSES } = require(path.join(UTILS, 'lane-claims.js'));

function stub(abs, exports) {
  const p = require.resolve(abs);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}
const stubUtil = (rel, exports) => stub(path.join(UTILS, rel), exports);

// ── Fake cybercore_db ───────────────────────────────────────────────────────
// Just enough of crucible_challenge + cybercore_lane to run the reservation
// paths. Routing is by query shape, and anything unrecognised throws rather than
// returning an empty result — a silent {rows: []} would turn a broken query into
// a passing test.

let challenges = [];   // { challenge_id, challenge_key, name, description, difficulty, spec, status, subnet_scheme, challenge_type, module_key, created_at }
let lanes = [];        // { vxlan_id, status }
let nextId = 1;
const uuid = () => `0000000${nextId++}-0000-4000-8000-000000000000`.slice(0, 36);

function mergeZoneAbbrev(spec, abbrev) {
  const zone = { ...((spec && spec.zone) || {}), abbrev };
  return { ...(spec || {}), zone };
}

async function fakeCybercoreQuery(sql, params = []) {
  const q = sql.replace(/\s+/g, ' ').trim();

  if (/^SELECT .*FROM crucible_challenge WHERE challenge_key = \$1$/.test(q)) {
    return { rows: challenges.filter(c => c.challenge_key === params[0]).map(c => ({ ...c })) };
  }
  if (/FROM crucible_challenge WHERE challenge_key = \$1 OR challenge_key LIKE \$1 \|\| '-%'/.test(q)) {
    const prefix = params[0];
    return {
      rows: challenges
        .filter(c => c.challenge_key === prefix || c.challenge_key.startsWith(`${prefix}-`))
        .sort((a, b) => a.challenge_key.localeCompare(b.challenge_key))
        .map(c => ({ ...c })),
    };
  }
  if (/^SELECT .*FROM crucible_challenge WHERE challenge_id = \$1$/.test(q)) {
    return { rows: challenges.filter(c => c.challenge_id === params[0]).map(c => ({ ...c })) };
  }
  if (/^SELECT \(spec->'vxlan_block'->>'end'\)::int AS vxlan_end FROM crucible_challenge/.test(q)) {
    return {
      rows: challenges
        .filter(c => c.spec && c.spec.vxlan_block && c.spec.vxlan_block.end != null)
        .map(c => ({ vxlan_end: c.spec.vxlan_block.end })),
    };
  }
  if (/^UPDATE crucible_challenge SET spec = COALESCE/.test(q)) {
    const row = challenges.find(c => c.challenge_id === params[0]);
    if (!row || (row.spec && row.spec.zone && row.spec.zone.abbrev)) return { rows: [] };
    row.spec = mergeZoneAbbrev(row.spec, params[1]);
    return { rows: [{ spec: row.spec }] };
  }
  if (/^UPDATE crucible_challenge SET challenge_key = \$1 WHERE challenge_id = \$2 AND challenge_key = \$3/.test(q)) {
    const [newKey, id, oldKey] = params;
    if (challenges.some(c => c.challenge_key === newKey)) {
      throw Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' });
    }
    const row = challenges.find(c => c.challenge_id === id && c.challenge_key === oldKey);
    if (!row) return { rows: [] };
    row.challenge_key = newKey;
    return { rows: [{ ...row }] };
  }
  if (/^UPDATE crucible_challenge SET spec = \$1::jsonb WHERE challenge_id = \$2$/.test(q)) {
    const row = challenges.find(c => c.challenge_id === params[1]);
    if (row) row.spec = JSON.parse(params[0]);
    return { rows: [] };
  }
  if (/^INSERT INTO crucible_challenge \(/.test(q)) {
    const cols = q.match(/^INSERT INTO crucible_challenge \(([^)]*)\)/)[1].split(',').map(s => s.trim());
    const row = { challenge_id: uuid(), created_at: new Date().toISOString() };
    cols.forEach((c, i) => { row[c] = c === 'spec' ? JSON.parse(params[i]) : params[i]; });
    if (challenges.some(c => c.challenge_key === row.challenge_key)) {
      throw Object.assign(new Error('duplicate key value violates unique constraint'), { code: '23505' });
    }
    challenges.push(row);
    return { rows: [{ challenge_id: row.challenge_id, challenge_key: row.challenge_key }] };
  }
  if (/^DELETE FROM crucible_challenge WHERE challenge_id = \$1$/.test(q)) {
    challenges = challenges.filter(c => c.challenge_id !== params[0]);
    return { rows: [] };
  }
  if (/^SELECT COUNT\(\*\)::int AS cnt FROM cybercore_lane WHERE vxlan_id BETWEEN \$1 AND \$2/.test(q)) {
    // The regex above stops at $2, so the predicate that decides what counts as a
    // claim is NOT matched by it. Assert it explicitly and filter from the shared
    // status list, or this fake would happily substitute its own opinion and the
    // "suspended lane blocks a re-carve" test below would pass against the exact
    // status IN ('active','deploying') bug lab-network-provision.js:99 documents.
    assert.ok(q.includes(claimsSql()),
      `countActiveLanesInBlock no longer uses the shared claim predicate: ${q}`);
    const [start, end] = params;
    const cnt = lanes.filter(l => l.vxlan_id >= start && l.vxlan_id <= end
      && !RELEASED_STATUSES.includes(l.status)).length;
    return { rows: [{ cnt }] };
  }
  throw new Error(`fakeCybercoreQuery: unhandled query ${q.slice(0, 160)}`);
}

stubUtil('cybercore-db.js', { cybercorePool: {}, cybercoreQuery: fakeCybercoreQuery });

// ── Fake Proxmox ────────────────────────────────────────────────────────────
let proxmoxCalls = [];
let sdnZones = [];
let sdnVnets = [];

async function fakeProxmoxAPI(method, url, body) {
  proxmoxCalls.push({ method, url, body });
  if (method === 'GET' && url.endsWith('/cluster/sdn/zones')) return sdnZones.map(z => ({ ...z }));
  if (method === 'GET' && url.endsWith('/cluster/sdn/vnets')) return sdnVnets.map(v => ({ ...v }));
  if (method === 'GET' && url.endsWith('/cluster/status')) {
    return [{ type: 'node', name: 'node1', online: 1, ip: '10.0.0.1' }];
  }
  if (method === 'GET' && url.endsWith('/nodes')) return [{ node: 'node1' }];
  if (method === 'GET' && /\/nodes\/[^/]+\/network$/.test(url)) {
    return sdnVnets.map(v => ({ iface: v.vnet }));
  }
  if (method === 'POST' && url.endsWith('/cluster/sdn/zones')) {
    if (sdnZones.some(z => z.zone === body.zone)) throw new Error(`zone '${body.zone}' already exists`);
    sdnZones.push({ ...body });
    return {};
  }
  if (method === 'POST' && url.endsWith('/cluster/sdn/vnets')) {
    // Real Proxmox rejects a duplicate vnet id, and the shared provisioner
    // treats "already exists" as success (lab-network-provision.js createVnet).
    // A fake that silently appends instead would let a re-assert of an existing
    // block look like it doubled the VNet count.
    if (sdnVnets.some(v => v.vnet === body.vnet)) throw new Error(`vnet '${body.vnet}' already exists`);
    sdnVnets.push({ ...body });
    return {};
  }
  if (method === 'DELETE' && url.includes('/cluster/sdn/vnets/')) {
    const name = url.split('/').pop();
    sdnVnets = sdnVnets.filter(v => v.vnet !== name);
    return {};
  }
  if (method === 'DELETE' && url.includes('/cluster/sdn/zones/')) {
    const name = url.split('/').pop();
    sdnZones = sdnZones.filter(z => z.zone !== name);
    return {};
  }
  if (method === 'PUT' && url.endsWith('/cluster/sdn')) return {};
  throw new Error(`fakeProxmoxAPI: unhandled ${method} ${url}`);
}

stubUtil('proxmox.js', {
  proxmoxAPI: fakeProxmoxAPI, waitForTask: async () => ({}), forceDestroyVM: async () => true,
  findTemplateNode: async () => 'node1', waitForVmidsGone: async () => ({ surviving: [] }),
  PROXMOX_URL: 'https://x:8006',
});

// ── Everything else lane-deploy.js drags in at require time ─────────────────
stubUtil('site-config.js', {
  getDefaultTemplateNode: () => 'node1', getSchedulingConfig: () => ({}),
  getClusterNodes: () => ['node1'], getNodeAddress: () => '10.0.0.1',
  getV2LabNetwork: () => ({ bridge: 'vmbr0', vlan_tag: 60, cidr: '/24', subnet_base: '100.100.60.0' }),
  getPhysicalClusterIps: () => ({ node1: '10.0.0.1' }),
});
stubUtil('node-ssh.js', {
  nodeExec: async () => ({ stdout: '' }), pctExec: async () => ({ stdout: '' }),
  pctExecWithStdin: async () => ({ stdout: '' }), pctPushFromString: async () => ({ stdout: '' }),
});
stubUtil('node-selector.js', { selectBestNode: async () => ({ node: 'node1' }) });
stubUtil('guacamole.js', { guacAPI: async () => ({}) });
stubUtil('guac-credentials.js', { ensureGuacUser: async () => true, getGuacCredentials: async () => null });
stubUtil('tailscale.js', { deleteLaneDevices: async () => 0, isEnabled: () => false, mintLaneAuthKey: async () => ({ key: '', tags: [] }) });
stubUtil('lane-wan-allocator.js', {
  allocateLaneWanIps: async () => [], releaseLaneWanIps: async () => {},
  recordLaneWanLease: async () => {}, findWanIpConflicts: async () => [],
});
stubUtil('script-executor.js', {
  waitForGuestAgent: async () => true, executeScriptsOnVM: async () => ({}),
  guestFileWrite: async () => ({}), agentExec: async () => ({}),
  pollExecStatus: async () => ({}), getVMIPs: async () => [],
});
stubUtil('batch-deployer.js', {
  runBatch: async () => [], createCloneSemaphore: () => ({}), distributeAcrossNodes: async () => [],
});

const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'utils');
stub(path.join(CIAB, 'vuln-app-builder.js'), { ensureVulnImage: async (x) => x, resolveImageFile: () => null });
stub(path.join(CIAB, 'db.js'), {
  setPool: () => {}, getPool: () => null,
  query: async () => { throw new Error('clinic_db is not used by the reservation path'); },
  pool: null,
});

const laneDeploy = require(path.join(CIAB, 'lane-reservation.js'));
const { sanitizeZoneAbbrev, teardownLabNetwork, V3_INTERNAL_TAG_OFFSET } = require(path.join(UTILS, 'lab-network-provision.js'));

const PROFILE_A = 'aaaaaaaa-1111-4000-8000-000000000000';
const PROFILE_B = 'bbbbbbbb-2222-4000-8000-000000000000';

function reset() {
  challenges = [];
  lanes = [];
  nextId = 1;
  proxmoxCalls = [];
  sdnZones = [];
  sdnVnets = [];
}

/** A pre-A1 reservation: profile-only key, and no zone stamped in the spec. */
function seedLegacyReservation(profileId, { start, end }) {
  const row = {
    challenge_id: uuid(),
    challenge_key: `ciab-profile-${profileId.slice(0, 8)}`,
    name: 'CIAB Profile: Legacy Co',
    description: 'seeded',
    difficulty: 3,
    challenge_type: 'multi_vm',
    module_key: 'crucible',
    subnet_scheme: 'v2',
    status: 'active',
    spec: { vms: [{ name: 'web-01' }], vxlan_block: { start, end } },
    created_at: new Date().toISOString(),
  };
  challenges.push(row);
  for (let id = start; id <= end; id++) sdnVnets.push({ vnet: `v${id}`, zone: 'ciabprof', tag: id });
  sdnZones.push({ zone: 'ciabprof', type: 'vxlan', peers: '10.0.0.1' });
  return row;
}

// ── Continuity: the zone name must not move ────────────────────────────────

test('the CIAB zone is the same 8 characters both key formats sanitize to', () => {
  // If this ever stops holding, every VNet already on the cluster becomes
  // invisible to teardown and starts leaking. It holds only because
  // sanitizeZoneAbbrev truncates at 8 characters, which is not obvious.
  assert.strictEqual(laneDeploy.CIAB_ZONE_ABBREV, 'ciabprof');
  assert.strictEqual(sanitizeZoneAbbrev(`ciab-profile-${PROFILE_A.slice(0, 8)}`), laneDeploy.CIAB_ZONE_ABBREV);
  assert.strictEqual(
    sanitizeZoneAbbrev(laneDeploy.profileChallengeKey(PROFILE_A, 'external_blackbox')),
    laneDeploy.CIAB_ZONE_ABBREV);
});

// ── The key ────────────────────────────────────────────────────────────────

test('the reservation key names the engagement', () => {
  const external = laneDeploy.profileChallengeKey(PROFILE_A, 'external_blackbox');
  const internal = laneDeploy.profileChallengeKey(PROFILE_A, 'internal_credentialed');
  assert.notStrictEqual(external, internal);
  assert.ok(external.startsWith(laneDeploy.legacyProfileChallengeKey(PROFILE_A)));
  // crucible_challenge.challenge_key is VARCHAR(128).
  assert.ok(external.length <= 128);
});

test('engagement slugs are coerced, never trusted', () => {
  const s = laneDeploy.sanitizeEngagementType;
  assert.strictEqual(s(undefined), laneDeploy.DEFAULT_ENGAGEMENT_TYPE);
  assert.strictEqual(s(''), laneDeploy.DEFAULT_ENGAGEMENT_TYPE);
  assert.strictEqual(s('   '), laneDeploy.DEFAULT_ENGAGEMENT_TYPE);
  assert.strictEqual(s('External Blackbox'), 'externalblackbox');
  assert.strictEqual(s("'; DROP TABLE--"), 'droptable--');
  assert.ok(s('x'.repeat(200)).length <= 32);
});

// ── Two engagements, two reservations ──────────────────────────────────────

test('two engagements against one client get disjoint VXLAN blocks', async () => {
  reset();
  const ext = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 5, companyName: 'Acme', spec: { vms: [] }, subnetScheme: 'v2',
  });
  const int = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'internal_credentialed',
    requestedMax: 5, companyName: 'Acme', spec: { vms: [] }, subnetScheme: 'v2',
  });

  assert.notStrictEqual(ext.challenge_id, int.challenge_id);
  assert.strictEqual(ext.was_existing, false);
  assert.strictEqual(int.was_existing, false);
  // THE regression this guards: before A1 the second call returned the first's
  // block, and tearing either one down destroyed the other's lanes.
  assert.ok(int.vxlan_block.start > ext.vxlan_block.end,
    `blocks overlap: ${JSON.stringify(ext.vxlan_block)} vs ${JSON.stringify(int.vxlan_block)}`);
  assert.strictEqual(ext.max_students, 5);
});

test('re-asking for the same engagement is idempotent', async () => {
  reset();
  const first = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 5, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  const second = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 5, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(second.challenge_id, first.challenge_id);
  assert.strictEqual(second.was_existing, true);
  assert.deepStrictEqual(second.vxlan_block, first.vxlan_block);
});

// ── The shared provisioner is the one creating infrastructure ──────────────

test('creating a reservation provisions the shared zone, without ipam', async () => {
  reset();
  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  const zonePost = proxmoxCalls.find(c => c.method === 'POST' && c.url.endsWith('/cluster/sdn/zones'));
  assert.ok(zonePost, 'no SDN zone was created');
  assert.strictEqual(zonePost.body.zone, laneDeploy.CIAB_ZONE_ABBREV);
  // The two bugs the private provisioner carried.
  assert.strictEqual(zonePost.body.ipam, undefined, "ipam:'pve' has crashed the cluster at reboot");
  assert.strictEqual(zonePost.body.peers, '10.0.0.1',
    'peers must come from /cluster/status + site.json, never from a node index');
  assert.strictEqual(sdnVnets.length, 3, 'the whole block should be pre-provisioned');
});

test('a v3 reservation also provisions the internal VNets', async () => {
  reset();
  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v3',
  });
  assert.strictEqual(sdnVnets.length, 4, 'v3 needs an external and an internal VNet per lane');
});

// ── Legacy adoption ────────────────────────────────────────────────────────

test('a pre-engagement reservation is adopted, not abandoned', async () => {
  reset();
  const legacy = seedLegacyReservation(PROFILE_A, { start: 10100, end: 10109 });
  lanes.push({ vxlan_id: 10100, status: 'active' });   // a student is on it right now

  const got = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 10, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });

  // Same row, renamed in place. A new row would have carved a second block and
  // orphaned the live lane's reservation.
  assert.strictEqual(got.challenge_id, legacy.challenge_id);
  assert.strictEqual(got.was_existing, true);
  assert.deepStrictEqual(got.vxlan_block, { start: 10100, end: 10109 });
  assert.strictEqual(got.challenge_key,
    laneDeploy.profileChallengeKey(PROFILE_A, laneDeploy.DEFAULT_ENGAGEMENT_TYPE));
  assert.strictEqual(challenges.length, 1, 'adoption must not leave a duplicate behind');
});

test('adoption stamps the zone the old row never carried', async () => {
  reset();
  const legacy = seedLegacyReservation(PROFILE_A, { start: 10100, end: 10104 });
  assert.strictEqual(legacy.spec.zone, undefined, 'precondition: legacy rows have no zone');

  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 5, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });

  // Without this the shared teardown has no zone to remove and every VNet in
  // the block leaks.
  assert.strictEqual(challenges[0].spec.zone.abbrev, laneDeploy.CIAB_ZONE_ABBREV);
  assert.ok(Array.isArray(challenges[0].spec.vms), 'the rest of the spec must survive the stamp');
});

test('adoption is scoped to the default engagement', async () => {
  reset();
  const legacy = seedLegacyReservation(PROFILE_A, { start: 10100, end: 10104 });
  const ext = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 5, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  // The legacy block belongs to whatever was deployed before, which by
  // definition is not this new engagement.
  assert.notStrictEqual(ext.challenge_id, legacy.challenge_id);
  assert.strictEqual(ext.was_existing, false);
  assert.ok(challenges.some(c => c.challenge_key === laneDeploy.legacyProfileChallengeKey(PROFILE_A)));
});

test('a profile-only lookup does not rename anything', async () => {
  reset();
  seedLegacyReservation(PROFILE_A, { start: 10100, end: 10104 });
  const found = await laneDeploy.findProfileChallenge(PROFILE_A);
  assert.ok(found);
  assert.strictEqual(found.vxlan_block.start, 10100);
  assert.strictEqual(challenges[0].challenge_key, laneDeploy.legacyProfileChallengeKey(PROFILE_A),
    'a GET must not mutate the key');
});

// ── Resize ─────────────────────────────────────────────────────────────────

test('an empty reservation is re-carved at the new size', async () => {
  reset();
  const first = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  const resized = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 8, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(resized.max_students, 8);
  assert.notStrictEqual(resized.challenge_id, first.challenge_id);
  assert.strictEqual(challenges.length, 1);
  // The old block's VNets go with it. The DELETE this replaced dropped only the
  // row and orphaned them in Proxmox forever.
  assert.strictEqual(sdnVnets.length, 8);
});

test('a reservation with live lanes is never re-carved', async () => {
  reset();
  const first = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  lanes.push({ vxlan_id: first.vxlan_block.start, status: 'active' });

  const again = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 8, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(again.challenge_id, first.challenge_id);
  assert.strictEqual(again.max_students, 3);
  assert.strictEqual(again.was_existing, true);
});

test('a suspended lane still blocks a re-carve', async () => {
  reset();
  const first = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  // The shared count is claimsSql: pending and suspended are claims too. CIAB's
  // old private count looked only at active/deploying and re-carved underneath
  // lanes that were merely paused.
  lanes.push({ vxlan_id: first.vxlan_block.end, status: 'suspended' });
  const again = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 8, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(again.challenge_id, first.challenge_id);
});

// ── Release ────────────────────────────────────────────────────────────────

test('deleting a profile releases every engagement it owns', async () => {
  reset();
  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'internal_credentialed',
    requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  seedLegacyReservation(PROFILE_A, { start: 20000, end: 20001 });
  const other = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_B, requestedMax: 2, companyName: 'Other', spec: {}, subnetScheme: 'v2',
  });

  const res = await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.strictEqual(res.deleted, true);
  assert.strictEqual(res.released.length, 3, 'both engagements AND the legacy row');
  assert.deepStrictEqual(challenges.map(c => c.challenge_id), [other.challenge_id]);
  // Releasing one client must not touch another client's VNets.
  assert.strictEqual(sdnVnets.length, 2);
  assert.deepStrictEqual([...new Set(sdnVnets.map(v => v.tag))].sort((a, b) => a - b),
    [other.vxlan_block.start, other.vxlan_block.end]);
});

test('releasing one engagement leaves the others alone', async () => {
  reset();
  const ext = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  const int = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'internal_credentialed',
    requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  lanes.push({ vxlan_id: int.vxlan_block.start, status: 'active' });

  await laneDeploy.deleteProfileChallenge(PROFILE_A, { engagementType: 'external_blackbox' });
  assert.deepStrictEqual(challenges.map(c => c.challenge_id), [int.challenge_id]);
  assert.ok(!sdnVnets.some(v => v.tag >= ext.vxlan_block.start && v.tag <= ext.vxlan_block.end));
  assert.ok(sdnVnets.some(v => v.tag === int.vxlan_block.start));
});

test('releasing a profile that never deployed is a no-op', async () => {
  reset();
  const res = await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.strictEqual(res.deleted, false);
  assert.strictEqual(res.reason, 'no_challenge');
});

test('a legacy reservation is released even though its zone was never stamped', async () => {
  reset();
  seedLegacyReservation(PROFILE_A, { start: 10100, end: 10102 });
  const res = await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.strictEqual(res.deleted, true);
  assert.strictEqual(challenges.length, 0);
  assert.strictEqual(sdnVnets.length, 0);
  assert.strictEqual(sdnZones.length, 0, 'the last CIAB VNet going should take the zone with it');
});

// ── The spec column is shared between the reservation and the synthesizer ──

test('a spec rewritten by the deploy can still release its zone', async () => {
  reset();
  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(r.spec.zone.abbrev, laneDeploy.CIAB_ZONE_ABBREV, 'precondition');

  // What runProfileDeploy does moments after reserving: replace the whole spec
  // column with the synthesized one. spec.zone is reservation-owned and the
  // synthesizer never authors it, so the rewrite has to carry it forward.
  const rewritten = { vms: [{ name: 'web-01' }], vxlan_block: r.vxlan_block, zone: r.spec.zone };
  await fakeCybercoreQuery(
    'UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2',
    [JSON.stringify(rewritten), r.challenge_id]);

  await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.strictEqual(sdnVnets.length, 0);
  assert.strictEqual(sdnZones.length, 0,
    'the zone survived teardown — spec.zone.abbrev was lost, so teardownSdnForBlock skipped it');
});

test('CIAB releasing a zone-less spec self-heals; a caller outside CIAB does not', async () => {
  // Two things worth separating.
  //
  // deleteProfileChallenge stamps the zone before it tears down, so CIAB's own
  // release path survives a spec that lost its zone. That is a second line of
  // defence and it is deliberate.
  //
  // teardownLabNetwork on its own does not — and it has a caller outside CIAB:
  // the admin route DELETE /api/admin/lab-templates/:id (routes/lab-templates.js)
  // acts on any crucible_challenge row by id, CIAB's included, with no backfill
  // in front of it. For that path the zone key must actually be in the column,
  // which is why the deploy's spec rewrite has to carry it.
  reset();
  const a = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  await fakeCybercoreQuery(
    'UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2',
    [JSON.stringify({ vms: [], vxlan_block: a.vxlan_block }), a.challenge_id]);
  await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.strictEqual(sdnZones.length, 0, 'CIAB release should stamp then tear down');

  reset();
  const b = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_B, requestedMax: 2, companyName: 'Other', spec: {}, subnetScheme: 'v2',
  });
  await fakeCybercoreQuery(
    'UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2',
    [JSON.stringify({ vms: [], vxlan_block: b.vxlan_block }), b.challenge_id]);
  await teardownLabNetwork(b.challenge_id, { force: true });
  assert.strictEqual(sdnVnets.length, 0, 'VNets go either way — they are found by tag');
  assert.strictEqual(sdnZones.length, 1,
    'precondition for the source assertion below: a spec with no zone strands the zone');
});

test('adoptedSpec carries the reservation zone through the deploy spec rewrite', async () => {
  // Runtime, not source-text. The previous version of this test grepped the
  // adopt-fresh-spec block for the word "zone" — which its own explanatory
  // comment satisfies, so it would have stayed green while the code regressed.
  reset();
  const { adoptedSpec } = require(
    path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'routes', 'profile-deploy.js'));

  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });

  // profile-to-spec emits neither zone nor vxlan_block; both are reservation-owned.
  const rawSpec = { vms: [{ name: 'web-01' }], vuln_app_install: null };
  const merged = adoptedSpec(rawSpec, r);
  assert.strictEqual(merged.zone.abbrev, laneDeploy.CIAB_ZONE_ABBREV);
  assert.deepStrictEqual(merged.vxlan_block, r.vxlan_block);
  assert.deepStrictEqual(merged.vms, rawSpec.vms, 'the synthesized content must survive');

  // The zone_abbrev fallback branch — reached when a reservation shape carries
  // the abbrev but not a spec.zone object. Nothing else covers it.
  const fallback = adoptedSpec(rawSpec, {
    vxlan_block: r.vxlan_block, zone_abbrev: laneDeploy.CIAB_ZONE_ABBREV, spec: {},
  });
  assert.strictEqual(fallback.zone.abbrev, laneDeploy.CIAB_ZONE_ABBREV);
});

test('a spec adopted by the deploy still releases its zone end to end', async () => {
  // Closes the loop: run the REAL rewrite through the REAL teardown. The earlier
  // version hardcoded `zone: r.spec.zone` into the rewritten spec by hand, so it
  // proved the shared teardown works given a zone — never that the deploy supplies one.
  reset();
  const { adoptedSpec } = require(
    path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'routes', 'profile-deploy.js'));

  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  const rewritten = adoptedSpec({ vms: [{ name: 'web-01' }] }, r);
  await fakeCybercoreQuery(
    'UPDATE crucible_challenge SET spec = $1::jsonb WHERE challenge_id = $2',
    [JSON.stringify(rewritten), r.challenge_id]);

  // teardownLabNetwork directly, NOT deleteProfileChallenge — the latter stamps
  // the zone first and would mask a rewrite that dropped it.
  await teardownLabNetwork(r.challenge_id, { force: true });
  assert.strictEqual(sdnZones.length, 0,
    'the zone survived teardown: the deploy spec rewrite dropped spec.zone.abbrev');
});

// ── v3 internal VNets ──

test('releasing a reservation sweeps v3 internal VNets even when the row says v2', async () => {
  // crucible_challenge.subnet_scheme is written ONCE, at reservation time, and
  // nothing ever updates it. The scheme a lane is BUILT at is a per-deploy choice
  // (the admin picks v2/v3 on every deploy). Reserve at v2, later deploy at v3,
  // and ensureLaneVnets creates the internal VNets at tag+V3_INTERNAL_TAG_OFFSET
  // while the row still says v2 — so a scheme-gated teardown skips them, the
  // zone-empty check then sees them and keeps the zone, and deleting the row
  // leaves nothing that can ever name them again.
  reset();
  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(challenges[0].subnet_scheme, 'v2', 'precondition: reservation is v2');

  // Same max_students, so no re-carve: the reservation is returned untouched and
  // the row keeps saying v2 while the deploy proceeds at v3.
  const again = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v3',
  });
  assert.strictEqual(again.was_existing, true);
  assert.strictEqual(challenges[0].subnet_scheme, 'v2', 'the row still disagrees with the deploy');

  await laneDeploy.ensureLaneVnets({
    vxlanIds: [r.vxlan_block.start, r.vxlan_block.end], subnetScheme: 'v3', logTag: 'test',
  });
  const internalTags = sdnVnets.filter(v => v.tag >= r.vxlan_block.start + V3_INTERNAL_TAG_OFFSET);
  assert.strictEqual(internalTags.length, 2, 'precondition: v3 internal VNets exist');

  await laneDeploy.deleteProfileChallenge(PROFILE_A);
  assert.deepStrictEqual(sdnVnets, [],
    'internal VNets orphaned: teardown honoured the frozen row scheme instead of sweeping the block');
  assert.strictEqual(sdnZones.length, 0, 'the surviving internal VNets would also pin the zone');
});

test('the resize path sweeps the internal range too', async () => {
  reset();
  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  await laneDeploy.ensureLaneVnets({
    vxlanIds: [r.vxlan_block.start, r.vxlan_block.end], subnetScheme: 'v3', logTag: 'test',
  });
  assert.strictEqual(sdnVnets.length, 4);

  // Empty block + different size => re-carve. The old block's VNets must all go,
  // internal ones included, or they are stranded with no row pointing at them.
  const resized = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 5, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  assert.strictEqual(resized.max_students, 5);
  assert.ok(!sdnVnets.some(v => v.tag >= r.vxlan_block.start + V3_INTERNAL_TAG_OFFSET
                             && v.tag <= r.vxlan_block.end + V3_INTERNAL_TAG_OFFSET),
    'the re-carve left the old block’s internal VNets behind');
});

// ── Lookups a deploy group depends on ──────────────────────────────────────

test('a group resolves its reservation by the id it stored', async () => {
  reset();
  const ext = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'external_blackbox',
    requestedMax: 2, companyName: 'Acme', spec: { vms: [{ name: 'web-01' }] }, subnetScheme: 'v2',
  });
  await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, engagementType: 'internal_credentialed',
    requestedMax: 2, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  // Add-lanes and retry must land on the group's own reservation, not on
  // whichever one a re-derived key happens to name.
  const byId = await laneDeploy.getProfileChallengeById(ext.challenge_id);
  assert.strictEqual(byId.challenge_key, ext.challenge_key);
  assert.deepStrictEqual(byId.vxlan_block, ext.vxlan_block);
  assert.strictEqual(await laneDeploy.getProfileChallengeById(null), null);
});

// ── The VNet safety net ────────────────────────────────────────────────────

test('ensureLaneVnets does not apply SDN when nothing is missing', async () => {
  reset();
  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  proxmoxCalls = [];
  const out = await laneDeploy.ensureLaneVnets({
    vxlanIds: [r.vxlan_block.start, r.vxlan_block.end], subnetScheme: 'v2', logTag: 'test',
  });
  assert.strictEqual(out.missing, 0);
  // PUT /cluster/sdn commits every pending SDN change on the cluster, not just
  // this lab's. It must not fire on a batch deploy that needed nothing.
  assert.ok(!proxmoxCalls.some(c => c.method === 'PUT'), 'unnecessary cluster-wide SDN apply');
});

test('ensureLaneVnets repairs a VNet that went missing', async () => {
  reset();
  const r = await laneDeploy.getOrCreateProfileChallenge({
    profileId: PROFILE_A, requestedMax: 3, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
  });
  sdnVnets = sdnVnets.filter(v => v.tag !== r.vxlan_block.start);
  const out = await laneDeploy.ensureLaneVnets({
    vxlanIds: [r.vxlan_block.start, r.vxlan_block.end], subnetScheme: 'v2', logTag: 'test',
  });
  assert.strictEqual(out.repaired, true);
  assert.ok(sdnVnets.some(v => v.tag === r.vxlan_block.start));
  assert.ok(sdnVnets.every(v => v.zone === laneDeploy.CIAB_ZONE_ABBREV));
});

// ── The ceiling ────────────────────────────────────────────────────────────

test('a reservation past the 16-bit ceiling is refused, not wrapped', async () => {
  reset();
  // A v2 lane's LAN is 10.<vxlan>>8>.<vxlan & 255>.0/24, so an id above 65535
  // silently puts two lanes on one subnet.
  challenges.push({
    challenge_id: uuid(), challenge_key: 'someone-elses-lab', name: 'x', status: 'active',
    subnet_scheme: 'v2', spec: { vxlan_block: { start: 65500, end: 65530 } },
    created_at: new Date().toISOString(),
  });
  await assert.rejects(
    laneDeploy.getOrCreateProfileChallenge({
      profileId: PROFILE_A, requestedMax: 10, companyName: 'Acme', spec: {}, subnetScheme: 'v2',
    }),
    /ceiling/);
  assert.strictEqual(challenges.length, 1, 'a refused reservation must not leave a row behind');
});
