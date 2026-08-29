/**
 * ciab-lane-provision.test.js — Track A5: the wrapper that replaced CIAB's
 * private deploy orchestrator.
 *
 * ciab-deploy-parity.test.js pins the DESTINATION as source text — no private
 * clone loop, no direct Guacamole call, no hardcoded virtio. Source text cannot
 * tell you whether the replacement actually behaves, and three things here are
 * invisible to it:
 *
 *   1. The vulnScripts mapping. spec.vms[].post_clone_scripts and the deployer's
 *      [{vm_name, script_slug}] are different shapes, nothing converts between
 *      them automatically, and getting it wrong is SILENT: the deploy succeeds,
 *      the lanes come up, and every profile lane quietly loses its vuln planting
 *      — the only reason a real nmap matches the paper scan report.
 *
 *   2. The vuln-app hook's target lookup. A deployedVMs record carries both
 *      `name` (the spec name) and `proxmox_name` (the clone name, which has the
 *      student's username appended). vuln_app_install.target_vm is a SPEC name,
 *      so matching the wrong field finds nothing on every lane at once.
 *
 *   3. The mutex. It is the only thing stopping two admins deploying one profile
 *      simultaneously, and it lives in the shared progress registry because this
 *      app has one Node process and no job queue.
 *
 * challenge-lane-deployer pulls site-config at module load (via batch-deployer),
 * which reads a gitignored config/site.json — same require.cache stub the slot
 * and console-designation tests use.
 *
 * Run: node --test front-end/test/ciab-lane-provision.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');

require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'node-1',
  },
};

const laneProvision = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/lane-provision.js'));
const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));

// ── 1. the mapping that fails silently ──────────────────────────────────────

test('post_clone_scripts become the deployer vulnScripts shape', () => {
  const spec = {
    vms: [
      { name: 'DC-01',  post_clone_scripts: ['init-setup', 'win-smb-vuln'] },
      { name: 'WEB-01', post_clone_scripts: ['lin-apache-2449'] },
    ],
  };
  assert.deepStrictEqual(laneProvision.vulnScriptsFromSpec(spec), [
    { vm_name: 'DC-01',  script_slug: 'init-setup' },
    { vm_name: 'DC-01',  script_slug: 'win-smb-vuln' },
    { vm_name: 'WEB-01', script_slug: 'lin-apache-2449' },
  ]);
});

test('a VM with no scripts contributes nothing, and a spec with none yields []', () => {
  // The empty case matters: deployChallengeLanes treats a non-empty vulnScripts
  // as "run these", so a stray entry with an undefined slug would be dispatched.
  assert.deepStrictEqual(
    laneProvision.vulnScriptsFromSpec({ vms: [{ name: 'A', post_clone_scripts: [] }, { name: 'B' }] }),
    []);
  assert.deepStrictEqual(laneProvision.vulnScriptsFromSpec({ vms: [] }), []);
  assert.deepStrictEqual(laneProvision.vulnScriptsFromSpec({}), []);
  assert.deepStrictEqual(laneProvision.vulnScriptsFromSpec(null), []);
});

// ── 2. the vuln-app hook ────────────────────────────────────────────────────

test('no vuln app means no hook, so the deployer skips the phase entirely', () => {
  assert.strictEqual(laneProvision.makeVulnAppPostDeploy(null), null);
  assert.strictEqual(laneProvision.makeVulnAppPostDeploy({}), null);
});

test('the hook matches the SPEC name, not the Proxmox clone name', async () => {
  // A deployedVMs record is { vm_id, name, proxmox_name, type, node }. `name` is
  // the spec name; `proxmox_name` carries the student suffix. Matching the wrong
  // one finds nothing on every lane simultaneously.
  const hook = laneProvision.makeVulnAppPostDeploy({ target_vm: 'vuln-app', mode: 'docker' });
  await assert.rejects(
    () => hook({
      deployedVMs: [
        { vm_id: 600001, name: 'DC-01',    proxmox_name: 'dc-01-student1',    node: 'n1' },
        { vm_id: 610001, name: 'not-it',   proxmox_name: 'vuln-app-student1', node: 'n1' },
      ],
      logTag: '[test]',
    }),
    /vuln-app.*is not among this lane's machines/,
    'matching proxmox_name instead of name must not silently succeed');
});

test('a missing target names the machines that WERE there', async () => {
  // The failure is recorded as config.post_deploy_error and shown to the
  // instructor, so the message has to be diagnostic on its own.
  const hook = laneProvision.makeVulnAppPostDeploy({ target_vm: 'web-01', mode: 'docker' });
  await assert.rejects(
    () => hook({ deployedVMs: [{ name: 'DC-01' }, { name: 'FILE-01' }], logTag: '[t]' }),
    (err) => /DC-01/.test(err.message) && /FILE-01/.test(err.message));
});

// ── 3. lane naming ──────────────────────────────────────────────────────────

test('the lane name prefix stays inside the gateway hostname budget', () => {
  // The binding limit is the gateway LXC hostname: 63 chars, minus 18 reserved
  // for the `-b<16hex>` Tailscale claim secret, leaves 45 for `${laneName}-gw`.
  // laneName is `${prefix}-${vxlanId}`, so the prefix plus a 5-digit id plus the
  // separator must clear it. Overrun does not error — it truncates, and two
  // lanes collide on one hostname.
  const long = laneProvision.laneNamePrefix('A Very Long Course Name That Keeps Going And Going');
  assert.ok(long.length <= 5 + laneProvision.MAX_SLUG_LEN,
    `prefix '${long}' (${long.length}) exceeds the budget`);
  assert.ok(!long.endsWith('-'), 'truncation must not leave a trailing hyphen');
});

test('the prefix is a legal hostname fragment and never empty', () => {
  assert.strictEqual(laneProvision.laneNamePrefix('CYBV 480'), 'ciab-cybv480');
  assert.strictEqual(laneProvision.laneNamePrefix('Fall_26 / Cochise'), 'ciab-fall-26-cochise');
  // An unnamed group must still produce something cloneable rather than a
  // hostname starting with a bare hyphen.
  assert.strictEqual(laneProvision.laneNamePrefix(''), 'ciab');
  assert.strictEqual(laneProvision.laneNamePrefix(null), 'ciab');
  assert.strictEqual(laneProvision.laneNamePrefix('!!!'), 'ciab');
});

// ── 4. the mutex ────────────────────────────────────────────────────────────

test('a second deploy on the same group is refused with 409', () => {
  const groupId = 'mutex-group-a';
  const progressId = laneProvision.progressIdForGroup(groupId);
  laneDeployer.initProgress(progressId, 'test group', 3);
  try {
    assert.throws(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId }),
      (err) => err.status === 409 && /still running/.test(err.message));
  } finally {
    laneDeployer.finishProgress(progressId);
  }
});

test('the claim a caller just took for itself is not a conflict with itself', () => {
  // The deploy path calls initProgress and then immediately asserts. Without
  // ignoreProgressId every deploy would 409 on its own claim.
  const groupId = 'mutex-group-b';
  const progressId = laneProvision.progressIdForGroup(groupId);
  laneDeployer.initProgress(progressId, 'test group', 1);
  try {
    assert.doesNotThrow(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId, ignoreProgressId: progressId }));
  } finally {
    laneDeployer.finishProgress(progressId);
  }
});

test('two different lanes may be retried at once; the same lane may not', () => {
  // Two instructors fixing two students is the normal case and must not block.
  const groupId = 'mutex-group-c';
  const laneA = laneProvision.progressIdForLane(groupId, 'lane-a');
  laneDeployer.initProgress(laneA, 'retry a', 1);
  try {
    assert.doesNotThrow(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId, laneId: 'lane-b' }),
      'another lane\'s retry must not block this one');
    assert.throws(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId, laneId: 'lane-a' }),
      (err) => err.status === 409);
    // A group-scope operation conflicts with ANY lane operation: a teardown
    // landing mid-retry enumerates a lane that is still being rebuilt.
    assert.throws(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId }),
      (err) => err.status === 409);
  } finally {
    laneDeployer.finishProgress(laneA);
  }
});

test('a finished operation is not a conflict', () => {
  // 'complete' entries linger for an hour so a late poller can still read the
  // outcome. Without the exemption one finished deploy would 409 the group for
  // that hour.
  const groupId = 'mutex-group-d';
  const progressId = laneProvision.progressIdForGroup(groupId);
  laneDeployer.initProgress(progressId, 'test group', 1);
  laneDeployer.finishProgress(progressId);
  assert.doesNotThrow(() => laneProvision.assertNoConflictingProfileOperation({ groupId }));
});

test('an unrelated group never conflicts', () => {
  const other = laneProvision.progressIdForGroup('mutex-group-e');
  laneDeployer.initProgress(other, 'other', 1);
  try {
    assert.doesNotThrow(
      () => laneProvision.assertNoConflictingProfileOperation({ groupId: 'mutex-group-f' }));
  } finally {
    laneDeployer.finishProgress(other);
  }
});
