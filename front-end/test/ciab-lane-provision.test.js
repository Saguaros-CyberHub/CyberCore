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
 *   4. (C1) The golden-image boundary. This file is the last code a lane passes
 *      through before the first clone, and it is reached from THREE places — the
 *      first deploy, add-lanes and retry-lane — two of which rebuild their
 *      challenge from a spec that was persisted days earlier. A pre-baked lane
 *      built from an unresolved spec clones the stock catalog image, is "healed"
 *      by a repair that had nothing to repair, and reports active.
 *
 *   5. (C1) The pivot credential, end to end. spec.reseed.pivot had no producer
 *      anywhere, so resolveReseedPlan skipped the credential phase — every lane
 *      in a section holding the ONE password baked into the golden image, with
 *      every deploy reporting success. The producer is driven for real here
 *      (profile-deploy.prebakedSpecFromBake), through the real provisionProfileLanes
 *      and the real reseed, and the assertion is that two students end up with
 *      two different passwords in the directory.
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

// ── the cluster, replaced ───────────────────────────────────────────────────
//
// C1c drives the REAL per-lane reseed through the REAL provisionProfileLanes,
// which means every edge the reseed touches has to be ANSWERED rather than
// avoided: the guest agent, the flag table, the lane row, and the shared
// deployer itself. All of it goes into require.cache before lane-provision
// loads, the same way site-config does above, because lane-provision holds
// direct references to every one of them from module scope.
//
// The point of driving the real thing is that the defect being closed is
// invisible to a stub: spec.reseed.pivot had no producer, so resolveReseedPlan
// skipped the credential phase and reported doing so on the lane row — every
// lane in a section keeping the ONE password baked into the golden image, with
// the deploy reporting success throughout.

const crypto = require('crypto');
const CIAB_UTILS = path.join(ROOT, 'modules/crucible/plugins/ciab/utils');

function stub(absPath, exports) {
  const resolved = require.resolve(absPath);
  require.cache[resolved] = {
    id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
  };
  return exports;
}

/**
 * Every command the reseed dispatched into a guest, in order — plus a small
 * DISK, one per lane, keyed by vm id.
 *
 * The disk exists because the reseed is all-or-none across every place the
 * website publishes the pivot credential: it READS each publisher, stages a
 * rewrite, changes Active Directory only once every staging succeeded, and then
 * READS THE FILES BACK. A guest that answers "exit 0, no output" to everything
 * reports a publisher that is not there, which stops the phase before the
 * directory is touched — so a stub that models nothing would make this file's
 * headline assertion (two lanes, two credentials) unreachable for the right
 * reason. Four commands are interpreted, which is the whole file vocabulary
 * lane-reseed uses; everything else is the no-op it really is.
 */
const guest = { commands: [], flags: new Map(), disks: new Map() };

/** The lane's own copy of the golden image's docroot. */
function diskFor(vmId) {
  if (!guest.disks.has(vmId)) guest.disks.set(vmId, new Map(guest.seedFiles || []));
  return guest.disks.get(vmId);
}

function runGuestFile(files, command) {
  let stdout = '';
  for (const line of String(command).split('\n')) {
    const t = line.trim();
    if (!t || t === 'set -e' || t === 'umask 077' || t === 'exit 0') continue;
    let m;
    // read: `if [ -f 'P' ]; then base64 < 'P'; else printf %s '<sentinel>'; fi`
    if ((m = t.match(/^if \[ -f '(.+?)' \]; then base64 < '(.+?)'; else printf %s '(.+?)'; fi$/))) {
      stdout += files.has(m[1]) ? Buffer.from(files.get(m[1]), 'utf8').toString('base64') : m[3];
      continue;
    }
    if ((m = t.match(/^printf %s '([A-Za-z0-9+/=]*)' \| base64 -d > '(.+?)'$/))) {
      files.set(m[2], Buffer.from(m[1], 'base64').toString('utf8'));
      continue;
    }
    // chunked staged write: raw base64 accumulated, then decoded
    if ((m = t.match(/^printf %s '([A-Za-z0-9+/=]*)' (>>?) '(.+?)'$/))) {
      files.set(m[3], (m[2] === '>>' && files.has(m[3]) ? files.get(m[3]) : '') + m[1]);
      continue;
    }
    if ((m = t.match(/^base64 -d < '(.+?)' > '(.+?)'$/))) {
      if (!files.has(m[1])) return { exitcode: 1, stderr: `${m[1]}: no such file` };
      files.set(m[2], Buffer.from(files.get(m[1]), 'base64').toString('utf8'));
      continue;
    }
    // publish: a redirect INTO the existing file, which is what keeps its owner
    // and its mode
    if ((m = t.match(/^cat '(.+?)' > '(.+?)'$/))) {
      if (!files.has(m[1])) return { exitcode: 1, stderr: `${m[1]}: no such file` };
      files.set(m[2], files.get(m[1]));
      continue;
    }
    if ((m = t.match(/^\[ -f '(.+?)' \] \|\| \{ /))) {
      if (!files.has(m[1])) return { exitcode: 1, stderr: 'staged rewrite missing' };
      continue;
    }
    if (t.startsWith('rm -f ')) {
      for (const q of (t.match(/'[^']*'/g) || [])) files.delete(q.slice(1, -1));
      continue;
    }
  }
  return { exitcode: 0, stdout };
}

stub(path.join(UTILS, 'script-executor.js'), {
  waitForGuestAgent: async () => true,
  waitForAgentExecReady: async () => true,
  agentExecArgv: async (node, vmId, argv) => {
    guest.commands.push({ kind: 'win', node, vmId, command: argv[argv.length - 1] });
    return { pid: guest.commands.length };
  },
  agentShellExec: async (node, vmId, command) => {
    const entry = { kind: 'sh', node, vmId, command };
    // Run it against the disk NOW, so the effect is ordered with the command
    // rather than with whenever the poll happens to be answered.
    entry.result = runGuestFile(diskFor(vmId), command);
    guest.commands.push(entry);
    return { pid: guest.commands.length };
  },
  pollExecStatus: async () => {
    const entry = guest.commands[guest.commands.length - 1];
    return Object.assign({ exited: true, exitcode: 0, stdout: '', stderr: '' },
      (entry && entry.result) || {});
  },
});
stub(path.join(UTILS, 'proxmox.js'), {
  proxmoxAPI: async () => ({}), waitForTask: async () => ({}),
});
stub(path.join(UTILS, 'cybercore-db.js'), {
  cybercoreQuery: async () => ({ rowCount: 1, rows: [] }),
});
stub(path.join(UTILS, 'flag-manager.js'), {
  // Idempotent per (lane, vm, type), exactly as the real table is — that is what
  // lets the deployer plant the identical string later.
  ensureLaneFlags: async ({ laneId, userId, vms }) => {
    const out = [];
    for (const vm of vms) {
      for (const flagType of ['user', 'root']) {
        const key = `${laneId}:${vm.name}:${flagType}`;
        if (!guest.flags.has(key)) guest.flags.set(key, crypto.randomBytes(16).toString('hex'));
        out.push({
          vmName: vm.name, flagType, flagId: key,
          flagValue: guest.flags.get(key), plantStatus: 'pending', userId,
        });
      }
    }
    return out;
  },
  generateFlagValue: () => crypto.randomBytes(16).toString('hex'),
});
stub(path.join(CIAB_UTILS, 'db.js'), {
  query: async () => ({ rowCount: 1, rows: [] }),
  pool: { query: async () => ({ rows: [] }) },
  getPool: () => ({ query: async () => ({ rows: [] }) }),
  setPool: () => {},
});

/**
 * The shared deployer, replaced by the ONE behaviour these tests need: it
 * invokes postDeploy once per user, with the argument set the real one passes
 * (challenge-lane-deployer.js:2021). Everything C1c is about happens inside that
 * hook.
 */
const deployer = { calls: [] };
stub(path.join(UTILS, 'challenge-lane-deployer.js'), {
  deployChallengeLanes: async (args) => {
    deployer.calls.push(args);
    const spec = args.challenge.spec;
    const provisioned = [];
    for (const [i, user] of args.users.entries()) {
      const laneId = `lane-${user.id}`;
      const vxlanId = 20000 + i;
      const deployedVMs = (spec.vms || [])
        .filter((v) => (v.type || 'qemu') !== 'lxc')
        .map((v, n) => ({
          vm_id: 610000 + i * 100 + n, name: v.name,
          proxmox_name: `${v.name.toLowerCase()}-${user.id}`, type: 'qemu', node: 'n1',
        }));
      if (typeof args.postDeploy === 'function') {
        await args.postDeploy({
          laneId, user, vxlanId, spec, subnetScheme: args.challenge.subnet_scheme,
          node: 'n1', gatewayVmId: 100000 + vxlanId, gatewayTransitIp: '100.100.60.9',
          deployedVMs, net: {}, laneSubnetBase: '10.39.216',
          goadSubnetBase: (spec.goad && spec.goad.fixed_subnet && spec.goad.fixed_subnet.int) || '10.167.216',
          pinnedHosts: [], dnsRecords: [], logTag: '[test]',
        });
      }
      provisioned.push({ lane_id: laneId, vxlan_id: vxlanId, user_id: user.id, node: 'n1' });
    }
    return { provisioned, failed: [] };
  },
});

const laneProvision = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/lane-provision.js'));
const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));
const laneReseed = require(path.join(CIAB_UTILS, 'lane-reseed.js'));
// The website generator, so the modelled docroot below carries the bytes a
// golden image really would rather than bytes this file invented.
const labContent = require(path.join(CIAB_UTILS, 'goad-lab-content.js'));
const profileDeploy = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/routes/profile-deploy.js'));

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

// ── 5. C1: the golden-image boundary ────────────────────────────────────────
/*
 * A PRE-BAKED LANE THAT IS BUILT WRONG IS BUILT SILENTLY.
 *
 * profile-deploy resolves bake.golden_vmids onto the challenge spec and persists
 * it. THREE paths then read that persisted spec back — the first deploy,
 * add-lanes, and retry-lane — and only the first is anywhere near the code that
 * wrote it. If the overlay is ever missing (a stored spec written before the
 * client was baked, a hand-edited challenge row, a reservation adopted from an
 * older engagement), the lane clones the stock catalog image, the pre-baked heal
 * "repairs" a secure channel that was never established, and the lane reports
 * active. So the last thing before the first clone refuses.
 */

const BAKED_INT = '10.167.216';
const BAKED_EXT = '10.39.216';

// One roster entry in the shape the compiler emits. Needed because the bake
// overlay re-derives the company website off the bake's compiled lab to find
// where it publishes the pivot credential, and the site generator refuses a lab
// with no roster account it could plant — correctly: a DMZ box that leads
// nowhere is a defaced homepage rather than a way into the domain.
const CLINIC_DN = 'DC=clinic,DC=local';
function clinicUser(sam, password) {
  return {
    sam,
    firstname: sam.split('.')[0],
    surname: sam.split('.')[1] || 'staff',
    password,
    description: '',
    city: 'Tucson',
    path: `OU=Staff,${CLINIC_DN}`,
    domain: 'clinic.local',
    groups: [],
    spns: [],
  };
}

/**
 * The bytes a golden image really carries at each place the website publishes
 * the pivot credential.
 *
 * The PAGES are the generator's own output, byte for byte. The config file is a
 * stand-in for what roles/cc_web/templates/pivot-credential.j2 renders — the
 * real template is pinned against these descriptors in ciab-lane-reseed.test.js,
 * which is where the rewrite grammars are exercised; here it only has to be a
 * document the descriptor really addresses, and buildBakedDisk proves it is by
 * parsing the value back out with the reseed's own reader.
 */
function pivotConfigSkeleton(plant, value) {
  switch (plant.op) {
    case 'dotenv': return `# directory integration\n${plant.key}=${value}\n`;
    case 'ini':    return `[application]\nname = portal\n\n[${plant.section}]\n${plant.key} = ${value}\n`;
    case 'php':    return `<?php\n\nreturn [\n    '${plant.key}' => '${value}',\n];\n`;
    case 'json': {
      const root = {};
      let cur = root;
      plant.keys.forEach((k, i) => {
        if (i === plant.keys.length - 1) cur[k] = value;
        else { cur[k] = {}; cur = cur[k]; }
      });
      return `${JSON.stringify(root, null, 4)}\n`;
    }
    case 'xml': return `<configuration>\n  <directory>\n    <${plant.element}>${value}`
      + `</${plant.element}>\n  </directory>\n</configuration>\n`;
    default: throw new Error(`no skeleton for plant operation '${plant.op}'`);
  }
}

/** Seed a lane's docroot from the site the bake's compiled lab really produces. */
function buildBakedDisk(ir) {
  const site = labContent.generateSiteContent(ir, { runId: ir.run_id || ir.lab_name });
  const files = new Map();
  for (const route of site.routes) files.set(`${site.docroot}/${route.file}`, route.content);
  for (const plant of site.reseed.plants) {
    if (!files.has(plant.path)) files.set(plant.path, pivotConfigSkeleton(plant, site.pivot.password));
    assert.strictEqual(laneReseed.readPlantValue(plant, files.get(plant.path)), site.pivot.password,
      `the modelled disk does not carry the baked password where ${plant.path}'s descriptor says`);
  }
  return { site, files };
}

function prebakedSpec(over = {}) {
  return Object.assign({
    subnet_scheme: 'v3',
    goad: {
      enabled: true,
      prebaked: true,
      fixed_subnet: { int: BAKED_INT, ext: BAKED_EXT },
      lab: {
        forestRoot: 'clinic.local',
        vms: [
          { name: 'NWC-DC01', role: 'dc', os: 'windows', template_vmid: 700001, ipOctet: 80 },
          { name: 'NWC-SRV02', role: 'member', os: 'windows', template_vmid: 700002, ipOctet: 81 },
        ],
      },
    },
    vms: [
      { name: 'NWC-DC01', type: 'qemu', role: 'dc', template_vmid: 700001, ipOctet: 80 },
      { name: 'NWC-SRV02', type: 'qemu', role: 'server', template_vmid: 700002, ipOctet: 81 },
      { name: 'web-01', type: 'qemu', role: 'dmz', template_vmid: 700003, ipOctet: 240 },
    ],
    vuln_app_install: { mode: 'docker', target_vm: 'web-01' },
    reseed: { pivot: { sam: 'svc.webapp', domain: 'clinic.local' } },
  }, over);
}

test('a spec that is not pre-baked is never second-guessed', () => {
  // Every CIAB deploy shipping today. The guard has to be able to say nothing.
  for (const spec of [null, {}, { goad: {} }, { goad: { enabled: true } }, { vms: [{ name: 'a' }] }]) {
    assert.strictEqual(laneProvision.assertPrebakedTemplatesResolved(spec), spec);
  }
});

test('a pre-baked spec whose golden templates are resolved passes', () => {
  const spec = prebakedSpec();
  assert.strictEqual(laneProvision.assertPrebakedTemplatesResolved(spec), spec);
});

test('a forest machine with no golden template is refused, not cloned from the catalog', () => {
  const spec = prebakedSpec();
  delete spec.vms[1].template_vmid;
  assert.throws(
    () => laneProvision.assertPrebakedTemplatesResolved(spec),
    (err) => err.status === 409
      && err.code === 'CIAB_PREBAKED_TEMPLATES_UNRESOLVED'
      && /NWC-SRV02/.test(err.message),
    'a machine with no golden template clones the stock image: it boots, it joins nothing, the '
    + 'heal reports it repaired, and the lane still reads active');

  // The machine OUTSIDE the forest is not the guard's business — it legitimately
  // clones from the catalog on a live lane and from the capture on a baked one.
  const exempt = prebakedSpec();
  delete exempt.vms[2].template_vmid;
  assert.doesNotThrow(() => laneProvision.assertPrebakedTemplatesResolved(exempt));
});

test('a pre-baked spec that names no lab at all is refused', () => {
  // Nothing then says which machines the bake built, so "every forest machine
  // has its golden template" is vacuously true — the exact shape of a check that
  // passes because it examined nothing.
  const spec = prebakedSpec();
  delete spec.goad.lab;
  assert.throws(
    () => laneProvision.assertPrebakedTemplatesResolved(spec),
    (err) => /names no goad\.lab\.vms/.test(err.message));
});

test('a pre-baked spec missing either half of the pinned subnet is refused', () => {
  // applyPrebakedFixedSubnet catches a missing `int` at deploy time; `ext` is
  // passed through as-is, so a spec pinning only half of it is silently
  // half-right — and on a v3 lane `ext` is the segment Kali, the DMZ pivot and
  // every published console live on.
  for (const fixed of [{ int: BAKED_INT }, { ext: BAKED_EXT }, { int: '  ', ext: BAKED_EXT }, {}]) {
    const spec = prebakedSpec();
    spec.goad.fixed_subnet = fixed;
    assert.throws(
      () => laneProvision.assertPrebakedTemplatesResolved(spec),
      (err) => /fixed_subnet/.test(err.message),
      `fixed_subnet ${JSON.stringify(fixed)} must not pass`);
  }
});

test('the guard is on the live deploy path, and refuses before it claims the mutex', async () => {
  // Executed through provisionProfileLanes itself, because a guard that is
  // merely exported is the failure mode this whole track is about. And BEFORE
  // the claim: a refusal that left a progress entry behind would make the next
  // deploy of that group 409 on a lane nobody is building.
  const spec = prebakedSpec();
  delete spec.vms[0].template_vmid;

  await assert.rejects(
    () => laneProvision.provisionProfileLanes({
      groupId: 'c1-guard-group',
      groupName: 'c1 guard',
      groupSlug: 'c1guard',
      challenge: { challenge_id: 'ch', challenge_key: 'k', name: 'n', spec, subnet_scheme: 'v3' },
      students: [{ id: 'u1', email: 'a@clinic.local', index: 1 }],
    }),
    (err) => err.code === 'CIAB_PREBAKED_TEMPLATES_UNRESOLVED');

  assert.deepStrictEqual(laneProvision.groupOperationsInFlight('c1-guard-group'), [],
    'a refused deploy must leave no claim behind');
});

test('retry refuses BEFORE it destroys the lane it is retrying', async () => {
  // A retry tears the lane down first, so a refusal raised any later would leave
  // the student with no lane at all. This route is also the one most likely to
  // meet a stale stored spec: it rebuilds its challenge from the reservation row
  // days after the deploy that wrote it.
  const spec = prebakedSpec();
  spec.goad.fixed_subnet = { int: BAKED_INT };
  let tornDown = false;
  const origTeardown = laneDeployer.teardownLanes;
  laneDeployer.teardownLanes = async () => { tornDown = true; return { destroyed: 1, errors: [] }; };
  try {
    await assert.rejects(
      () => laneProvision.retryProfileLane({
        groupId: 'c1-retry-group',
        groupName: 'c1 retry',
        groupSlug: 'c1retry',
        challenge: { challenge_id: 'ch', challenge_key: 'k', name: 'n', spec, subnet_scheme: 'v3' },
        laneId: 'lane-x',
        user: { id: 'u1', email: 'a@clinic.local' },
        laneIndex: 1,
      }),
      (err) => err.code === 'CIAB_PREBAKED_TEMPLATES_UNRESOLVED');
    assert.strictEqual(tornDown, false, 'the lane was destroyed before the spec was judged');
  } finally {
    laneDeployer.teardownLanes = origTeardown;
  }
});

// ── 6. C1c: two lanes, two credentials, through the real deploy path ────────

/** Everything a lane-reseed command carries, decoded. */
const PS_B64 = /FromBase64String\('([A-Za-z0-9+/=]+)'\)/;
function adPasswordsFor(vmIds) {
  return guest.commands
    .filter((c) => c.kind === 'win' && /Set-ADAccountPassword/.test(c.command) && vmIds.has(c.vmId))
    .map((c) => {
      const m = c.command.match(PS_B64);
      return m ? Buffer.from(m[1], 'base64').toString('utf8') : null;
    });
}

test('spec.reseed.pivot reaches the reseed, and two lanes end up with DIFFERENT credentials', async () => {
  // THE END-TO-END CLAIM. The spec is built by the REAL producer
  // (prebakedSpecFromBake) from a bake row, handed to the REAL
  // provisionProfileLanes, which composes the REAL reseed hook, which the shared
  // deployer invokes once per student. Nothing here asserts that a stub returned
  // what it was told to.
  guest.commands.length = 0;
  guest.flags.clear();
  guest.disks.clear();
  deployer.calls.length = 0;

  const bake = {
    bake_id: 'bake-1',
    lab_name: 'CIAB-a1b2c3d4',
    status: 'ready',
    golden_vmids: {
      'NWC-DC01': { name: 'NWC-DC01', vmid: 700001, node: 'n1' },
      'NWC-SRV02': { name: 'NWC-SRV02', vmid: 700002, node: 'n1' },
      'web-01': { name: 'web-01', vmid: 700003, node: 'n1' },
    },
    spec: {
      subnet_scheme: 'v3',
      goad: {
        enabled: true,
        version: 'CIAB-a1b2c3d4',
        fixed_subnet: { int: BAKED_INT, ext: BAKED_EXT },
        // A LAB THE WEBSITE GENERATOR CAN AUTHOR A SITE FOR. The overlay
        // re-derives site.reseed off this IR to find out WHERE the website
        // publishes the pivot credential — without that block lane-reseed
        // rotates the directory and leaves every page serving the baked
        // password — so a skeleton lab here would prove only that the producer
        // survives a shape nothing emits. The entry is planted 'web_app_credential',
        // which is the case where the site publishes the foothold itself.
        lab: {
          lab_name: 'CIAB-a1b2c3d4',
          run_id: 'run-provision-1',
          domains: [{
            fqdn: 'clinic.local', netbios: 'CLINIC', dc_host_key: 'dc01',
            is_forest_root: true, parent_fqdn: null, trust_fqdn: null,
          }],
          hosts: [
            { key: 'dc01', hostname: 'NWC-DC01', type: 'dc', domain: 'clinic.local', path: CLINIC_DN, roles: [] },
            { key: 'srv02', hostname: 'NWC-SRV02', type: 'server', domain: 'clinic.local', path: CLINIC_DN, roles: ['web'] },
          ],
          principals: {
            users: [
              clinicUser('svc.webapp', 'Cedar-Harbor12!'),
              clinicUser('marcus.webb', 'Rivet-Landing-41!'),
              clinicUser('rosa.delaney', 'Quartz-Meadow-18!'),
              clinicUser('tom.ng', 'Sable-Junction-77!'),
            ],
            groups: [{
              name: 'ITOps', scope: 'global', path: `OU=Groups,${CLINIC_DN}`,
              domain: 'clinic.local', managed_by: null, members: [],
            }],
            ous: [
              { name: 'Staff', path: CLINIC_DN, domain: 'clinic.local' },
              { name: 'Groups', path: CLINIC_DN, domain: 'clinic.local' },
            ],
            declared_admins: [],
          },
          chain: {
            start: {
              kind: 'web_credential', principal: 'svc.webapp', host: 'srv02',
              how: 'the settings page prints the directory-integration password in the clear',
              plants: [],
            },
            objective: { kind: 'domain_admins', target: 'Domain Admins', domain: 'clinic.local' },
            edges: [{
              id: 'edge0', from: 'svc.webapp', to: 'marcus.webb', edge_type: 'acl',
              right: 'GenericAll', depth: 0, target_kind: 'user',
              created_by: { role: 'acl', host: 'dc01', item: 'edge-0', item_vars: {} },
            }],
            decoys: [],
            domain: 'clinic.local',
          },
          acls: { 'clinic.local': { 'edge-0': {} } },
          foothold_credential: {
            sam: 'svc.webapp', domain: 'clinic.local', password: 'Cedar-Harbor12!',
            honoured_by: 'ad',
            planted_at: { host_key: 'srv02', path: '/admin/integrations', format: 'web_app_credential' },
          },
        },
      },
    },
  };

  // What the synthesizer produces for this client: catalog templates, no goad
  // key, no reseed key. Exactly the spec a deploy has had since before bakes
  // existed.
  const synthesized = {
    subnet_scheme: 'v3',
    vms: [
      { name: 'NWC-DC01', type: 'qemu', role: 'server', os_family: 'windows',
        template_vmid: 9001, ipOctet: 80 },
      { name: 'NWC-SRV02', type: 'qemu', role: 'server', os_family: 'windows',
        template_vmid: 9002, ipOctet: 81 },
      { name: 'web-01', type: 'qemu', role: 'dmz', os_family: 'linux',
        template_vmid: 9003, ipOctet: 240, nics: [{ segment: 'ext' }, { segment: 'int' }] },
    ],
    vuln_app_install: { mode: 'ondemand', target_vm: 'web-01' },
  };

  // Every lane starts from the same golden docroot — which is the whole point of
  // a golden image, and the reason the reseed has to rewrite it per lane.
  const { site } = buildBakedDisk(bake.spec.goad.lab);
  guest.seedFiles = [...buildBakedDisk(bake.spec.goad.lab).files];

  const spec = profileDeploy.prebakedSpecFromBake(synthesized, bake, { subnetScheme: 'v3' });
  // The producer that did not exist: without this key resolveReseedPlan skips
  // the credential phase entirely and every lane keeps the baked password.
  assert.strictEqual(spec.reseed.pivot.sam, 'svc.webapp',
    'the account the website publishes — on this client the chain plants its entry web-side, so it '
    + 'is also the foothold');
  assert.strictEqual(spec.reseed.pivot.domain, 'clinic.local',
    "the account's DNS domain, which is what Set-ADAccountPassword -Server takes — the NetBIOS "
    + 'short name the page prints beside it authenticates nothing');
  assert.strictEqual(spec.reseed.pivot.rotate, true);
  assert.ok(spec.reseed.pivot.site && spec.reseed.pivot.site.plants.length >= 2,
    'the deploy spec carries nowhere for the reseed to rewrite, so the website would go on '
    + 'publishing the baked password while the directory honoured a different one');

  const students = [
    { id: 'stu-a', email: 'a@clinic.local', index: 1 },
    { id: 'stu-b', email: 'b@clinic.local', index: 2 },
  ];
  const result = await laneProvision.provisionProfileLanes({
    groupId: 'c1-reseed-group',
    groupName: 'c1 reseed',
    groupSlug: 'c1reseed',
    challenge: {
      challenge_id: 'ch', challenge_key: 'ciab-profile-1111-default',
      name: 'c1 reseed', spec, subnet_scheme: 'v3',
    },
    students,
    // null on purpose: the vuln-app install is a separate concern and its
    // absence must not stop the reseed, which is the ordering makeProfilePostDeploy
    // exists to guarantee.
    vulnAppInstall: null,
  });

  assert.strictEqual(result.provisioned.length, 2);
  assert.strictEqual(deployer.calls.length, 1, 'one batch, two lanes');

  // The clone list the deployer was actually given.
  const cloned = deployer.calls[0].challenge.spec.vms.map((v) => [v.name, v.template_vmid]);
  assert.deepStrictEqual(cloned, [
    ['NWC-DC01', 700001], ['NWC-SRV02', 700002], ['web-01', 700003],
  ], 'the golden templates are what the lanes clone — this is the loop closing');

  // THE HEADLINE. One bake, one golden image, two students: the password the
  // directory is actually set to must differ.
  const a = adPasswordsFor(new Set([610000, 610001, 610002]));
  const b = adPasswordsFor(new Set([610100, 610101, 610102]));
  assert.strictEqual(a.length, 1, `lane A reset one account (got ${a.length})`);
  assert.strictEqual(b.length, 1, `lane B reset one account (got ${b.length})`);
  assert.ok(a[0] && a[0].length >= laneReseed.PW_LENGTH, 'a real generated password, not a placeholder');
  assert.notStrictEqual(a[0], b[0],
    'TWO LANES FROM ONE BAKE MUST NOT SHARE A PIVOT CREDENTIAL — one student pastes it into the '
    + 'group chat and the cohort is finished');

  // …and it is the account the bake named, in the domain the bake named.
  const reset = guest.commands.find((c) => /Set-ADAccountPassword/.test(String(c.command)));
  assert.match(reset.command, /svc\.webapp/,
    'the account is the one the compiler planted on the web app, not one this layer invented');
  assert.match(reset.command, /-Server 'clinic\.local'/,
    'the DNS domain, not the NetBIOS short name the settings page prints beside the account');

  // AND THE WEBSITE AGREES WITH ITS OWN LANE. Rotating the directory while the
  // pages go on advertising the baked password is a green lane whose pivot does
  // not work, and it is invisible from every step name.
  const webA = guest.disks.get(610002);
  const webB = guest.disks.get(610102);
  for (const plant of site.reseed.plants) {
    const servedA = laneReseed.readPlantValue(plant, webA.get(plant.path));
    const servedB = laneReseed.readPlantValue(plant, webB.get(plant.path));
    assert.strictEqual(servedA, a[0], `${plant.path} disagrees with lane A's own AD password`);
    assert.strictEqual(servedB, b[0], `${plant.path} disagrees with lane B's own AD password`);
    assert.notStrictEqual(servedA, site.pivot.password,
      `${plant.path} still serves the BAKED password after a reseed that reported success`);
  }
});

test('with no reseed.pivot the credential phase is skipped — the defect, kept visible', async () => {
  // The other side of the same coin, and the reason the producer matters: this
  // is what EVERY deploy did before C1c, and it is indistinguishable from
  // success without looking at the lane record.
  guest.commands.length = 0;
  guest.flags.clear();

  const spec = prebakedSpec();
  delete spec.reseed;

  await laneProvision.provisionProfileLanes({
    groupId: 'c1-nopivot-group',
    groupName: 'c1 nopivot',
    groupSlug: 'c1nopivot',
    challenge: { challenge_id: 'ch', challenge_key: 'k', name: 'n', spec, subnet_scheme: 'v3' },
    students: [{ id: 'stu-c', email: 'c@clinic.local', index: 1 }],
    vulnAppInstall: null,
  });

  assert.strictEqual(
    guest.commands.filter((c) => /Set-ADAccountPassword/.test(String(c.command))).length, 0,
    'nothing named the account, so the directory was never touched — the lane deploys, reports '
    + 'active, and hands the student the password baked into the golden image');
});
