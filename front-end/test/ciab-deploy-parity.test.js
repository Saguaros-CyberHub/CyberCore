/**
 * ciab-deploy-parity.test.js — CIAB deploys through the shared primitive, or not at all.
 *
 * WHY THIS FILE EXISTS
 * There are three generations of the same "clone a gateway, clone the VMs, wire
 * the network" sequence in this repo, and CIAB owns a private fourth copy:
 *
 *   src/utils/lane-deployer.js            3864 lines — hardened, drives CLE + admin
 *   src/utils/challenge-lane-deployer.js  2302 lines — the spec.vms[] primitive
 *   ciab/utils/lane-deploy.js             1955 lines — CIAB's own, drifted
 *
 * lane-deployer.js:10-14 already states the thesis: each caller inlined the
 * sequence and "the third copy drifted and lost the non-obvious details that
 * actually make a lane reachable." CLE was migrated onto the shared primitive
 * (see cle/utils/lane-provision.js, and its warning at :21-24 that "a third copy
 * of that sequence is exactly how this plugin got broken the first time").
 * CIAB never was, and the drift is not cosmetic — a CIAB lane's console is dead
 * on arrival today, its Windows guests never DHCP, and its retry cannot succeed.
 *
 * WHAT THESE TESTS ARE
 * They encode the DESTINATION, not the current state. Every assertion below
 * fails against the pre-migration tree on purpose: this file is the objective
 * exit criterion for Track A, and Track A is done when it goes green.
 *
 * They are source-text assertions, which is a blunt instrument. It is the right
 * one here because the property being defended — "CIAB does not re-implement the
 * deploy sequence" — is exactly the kind that gets reintroduced by someone
 * reasonably inlining "just this one small case", and no runtime test can catch
 * that without a live Proxmox cluster.
 *
 * HOW THEY SURVIVE THE MIGRATION
 * `deployImpl()` reads the wrapper (ciab/utils/lane-provision.js) once it exists
 * and falls back to the legacy file until then, so the same assertions apply
 * before, during and after the strangler — including after lane-deploy.js is
 * deleted in A7.
 *
 * Defect IDs (W1..W8) map to the Track A table in the program plan.
 *
 * Run: node --test front-end/test/ciab-deploy-parity.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const abs = (rel) => path.join(ROOT, rel);
const exists = (rel) => fs.existsSync(abs(rel));
const read = (rel) => fs.readFileSync(abs(rel), 'utf8');

const WRAPPER = 'modules/crucible/plugins/ciab/utils/lane-provision.js';
const LEGACY = 'modules/crucible/plugins/ciab/utils/lane-deploy.js';
const ROUTE = 'modules/crucible/plugins/ciab/routes/profile-deploy.js';
const SYNTH = 'modules/crucible/plugins/ciab/utils/profile-to-spec.js';

const SHARED_SPEC_DEPLOYER = 'src/utils/challenge-lane-deployer.js';

/**
 * The file that IS the CIAB deploy implementation right now.
 *
 * During the strangler both files exist; the wrapper is the one that matters,
 * because it is what the route will call once CIAB_DEPLOY_V2 is the default.
 * Reading it preferentially means these tests measure progress toward the
 * destination instead of being pinned red by the legacy file that A7 deletes.
 */
function deployImpl() {
  const rel = exists(WRAPPER) ? WRAPPER : LEGACY;
  return { rel, src: read(rel) };
}

/**
 * Strip comments before asserting a token is ABSENT.
 *
 * This codebase documents its traps at length, and the traps are named after
 * exactly the identifiers these tests forbid — the wrapper is expected to carry
 * a comment saying "Guacamole is the shared deployer's job, do not call guacAPI
 * here". Without this, every "must not mention" assertion would fire on the
 * comment that exists to prevent the thing it is complaining about.
 */
function codeOnly(src) {
  return src
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*');
    })
    .join('\n');
}

const TRACK_A = 'See the program plan, Track A.';

// ── The delegation invariant ────────────────────────────────────────────────
// Everything else in this file is a symptom. This is the disease.

test('W-CORE: the CIAB deploy path delegates to deployChallengeLanes', () => {
  // challenge-lane-deployer, NOT lane-deployer. CIAB deploys a spec.vms[] set,
  // which is precisely what deployChallengeLanes consumes (challenge-lane-deployer.js:1689
  // resolveSpecVms). lane-deployer.deployLanes deploys ONE catalog workstation
  // per lane from cybercore_template_catalog — a 5-asset profile cannot be
  // expressed in it at all.
  const { rel, src } = deployImpl();
  // assert.ok rather than assert.match throughout: these sources are 1000-4000
  // lines, and assert.match prints the entire `actual` string on failure, which
  // buries the one line of guidance that tells the next session what to do.
  assert.ok(/deployChallengeLanes\(/.test(codeOnly(src)),
    `${rel} must call deployChallengeLanes() from ${SHARED_SPEC_DEPLOYER}. ${TRACK_A} (A5)`);
});

test('W-CORE: the CIAB deploy path does not clone machines itself', () => {
  // A clone call in CIAB is the signature of the fourth copy. Every detail that
  // makes a lane reachable — MAC pinning, NIC model, cloud-init, DHCP
  // reservations, console DNAT — hangs off the clone in the shared deployer,
  // and a private clone silently opts out of all of it at once.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  const offenders = [];
  code.split(/\r?\n/).forEach((line, i) => {
    if (/\/(qemu|lxc)\/\$\{[^}]*\}\/clone/.test(line)) offenders.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepStrictEqual(offenders, [],
    `${rel} clones VMs directly; deployChallengeLanes owns cloning. ${TRACK_A} (A5)\n`
    + offenders.join('\n'));
});

// ── W1 / W2 / W5: the console ───────────────────────────────────────────────

test('W1+W2+W5: the CIAB deploy path does not talk to Guacamole directly', () => {
  // One invariant covers three defects, because all three come from CIAB
  // building its own connection body:
  //   W1 it sets parameters.hostname to the LANE-LOCAL Kali IP. guacd runs on
  //      the orchestrator's Docker bridge with no route into 10.<vxh>.<vxl>.0/24,
  //      so the console is dead on arrival. lane-deployer.js:1779 sets
  //      `const consoleHost = gatewayWanIp` and :1765-1770 explains why it must
  //      ALWAYS be the gateway's WAN transit address.
  //   W2 it never grants the student READ on the connection. The shared path
  //      does it at lane-deployer.js:1251 via
  //      PATCH /users/:email/permissions.
  //   W5 it hardcodes username 'kali' / password 'kali' instead of the
  //      per-lane cloud-init credential.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  assert.ok(!/guacAPI\(/.test(code),
    `${rel} calls guacAPI directly. The shared deployer owns Guacamole — it targets the `
    + `gateway WAN IP, grants the student READ, and uses the real per-lane credential. ${TRACK_A} (A5)`);
});

test('W5: no hardcoded kali/kali credential reaches a console', () => {
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  assert.ok(!/password:\s*'kali'/.test(code),
    `${rel} hardcodes the Kali password. Credentials come from the shared deployer's `
    + `resolveWorkstationCredentials / cloud-init path. ${TRACK_A} (A5)`);
});

// ── W3: addressing ──────────────────────────────────────────────────────────

test('W3: the synthesizer and the deployer agree on the octet band', () => {
  // profile-to-spec.js MIRRORS SPEC_OCTET_MIN/MAX rather than importing them:
  // challenge-lane-deployer pulls site-config at module load (via
  // batch-deployer), and the synthesizer's whole value is being loadable with no
  // cluster, DB or config. A mirrored constant that drifts is worse than an
  // import, so the agreement is asserted here — the one place that can afford to
  // load both. Same site-config stub console-designation.test.js uses.
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
  const deployer = require(path.join(UTILS, 'challenge-lane-deployer.js'));
  const synth = require(path.join(ROOT, 'modules/crucible/plugins/ciab/utils/profile-to-spec.js'));

  assert.strictEqual(synth.SPEC_OCTET_MIN, deployer.SPEC_OCTET_MIN,
    'profile-to-spec would hand out addresses below the band the deployer pins from');
  assert.strictEqual(synth.SPEC_OCTET_MAX, deployer.SPEC_OCTET_MAX,
    'profile-to-spec would accept more machines than the deployer can pin');
});

test('W3: deterministic addressing is expressed as ipOctet on the spec', () => {
  // CIAB writes no DHCP reservations at all today, so every guest takes a random
  // pool lease and nothing is at a predictable address — which is also why the
  // gateway's baked wan0:3389 -> <base>.50 DNAT can never fire.
  //
  // The fix is not for CIAB to write reservations; it is for the synthesizer to
  // declare an octet per VM and let the shared deployer pin it. `ipOctet` is the
  // EXISTING key — challenge-lane-deployer.js:1167 honours it for consoles and
  // src/utils/attached-modules.js:106-141 for attached modules. Do not invent a
  // second spelling.
  const src = read(SYNTH);
  assert.ok(/ipOctet/.test(codeOnly(src)),
    `${SYNTH} must emit ipOctet per VM so the shared deployer can MAC-pin it. ${TRACK_A} (A4)`);
});

// ── W4: NIC model ───────────────────────────────────────────────────────────

test('W4: the NIC model is never hardcoded to virtio', () => {
  // Stock Windows images carry no virtio-net driver, so a virtio NIC comes up
  // dead and the guest never DHCPs. lane-deployer.js:488 resolveNicModel()
  // returns e1000 for any os_family starting 'windows', and every GOAD Windows
  // row in goad-deploy.js carries nic_model:'e1000' for the same reason.
  // A profile with a Windows Server asset cannot deploy while this is hardcoded.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  const offenders = [];
  code.split(/\r?\n/).forEach((line, i) => {
    if (/virtio,bridge=/.test(line)) offenders.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepStrictEqual(offenders, [],
    `${rel} hardcodes a virtio NIC; Windows guests will never DHCP. ${TRACK_A} (A2/A5)\n`
    + offenders.join('\n'));
});

// ── W7: VMID bands ──────────────────────────────────────────────────────────

test('W7: CIAB does not mint its own temp gateway template IDs', () => {
  // CIAB used TEMP_GW_TEMPLATE_BASE = 169200 with a naive counter and no
  // free-id scan. challenge-lane-deployer.js:81 uses the same 169200 base but
  // SCANS for free ids, and lane-deployer.js:72 deliberately moved to 169300 to
  // stay clear of groups.js. A CIAB batch running alongside an admin group
  // deploy collides on 169200/169201.
  const { rel, src } = deployImpl();
  assert.ok(!/TEMP_GW_TEMPLATE_BASE/.test(codeOnly(src)),
    `${rel} defines its own temp-template VMID band. Gateway replication belongs to the `
    + `shared deployer, which scans for free ids. ${TRACK_A} (A5)`);
});

// ── W8: progress + mutex ────────────────────────────────────────────────────

test('W8: CIAB uses the shared progress registry, not a private global', () => {
  // The shared registry is not just a progress bar: it carries the heartbeat and
  // staleness fields, and it doubles as the app's ONLY mutex (there is one Node
  // process and no job queue — see cle/utils/lane-provision.js:144-146).
  // A private global means nothing stops two concurrent deploys, or a deploy and
  // a teardown, from running against the same profile.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  assert.ok(!/_ciabProfileLaneProgress/.test(code),
    `${rel} keeps a private progress registry, so nothing serialises concurrent `
    + `operations on one profile. ${TRACK_A} (A5)`);
});

test('W8: a conflicting in-flight operation is refused', () => {
  // CLE's equivalent guard is assertNoConflictingWorkstationOperation
  // (cle/utils/lane-provision.js:161-180), which 409s the second caller.
  const { rel, src } = deployImpl();
  assert.ok(/assertNo\w*Conflict|conflict/i.test(codeOnly(src)),
    `${rel} must refuse a second concurrent deploy/teardown for the same profile. ${TRACK_A} (A5)`);
});

// ── The two SDN bugs found during design review ─────────────────────────────

test('SDN: CIAB does not create Proxmox SDN zones itself', () => {
  // CIAB's private ensureSdnZoneAndVnets posts zones with FABRICATED peer IPs —
  // `n.ip || 100.100.10.${10 + i}` over GET /nodes, which never returns an `ip`
  // field, so every peer list is invented — and with ipam:'pve'. Both are
  // documented in src/utils/lab-network-provision.js as cluster-affecting bugs
  // that the shared provisioner deliberately fixed.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  assert.ok(!/cluster\/sdn\/zones/.test(code),
    `${rel} creates SDN zones directly. Use the shared reserveLabNetwork/teardownLabNetwork. ${TRACK_A} (A1)`);
  assert.ok(!/ipam:\s*'pve'/.test(code),
    `${rel} sets ipam:'pve' on a zone — the shared provisioner documents why that is wrong. ${TRACK_A} (A1)`);
});

test('SDN: no fabricated Proxmox node peer addresses', () => {
  const { rel, src } = deployImpl();
  assert.ok(!/100\.100\.10\.\$\{\s*10\s*\+/.test(codeOnly(src)),
    `${rel} invents SDN peer IPs from a node index. ${TRACK_A} (A1)`);
});

test('the per-profile reservation goes through the shared network provisioner', () => {
  // Scanned across ALL of CIAB's deploy-side utils, not just the active deploy
  // implementation: the reservation and the deploy are deliberately different
  // modules. A5 moved the deploy into lane-provision.js while the reservation
  // stayed in lane-deploy.js, and A7 moves the reservation again — so pinning
  // this to one filename would fail on a refactor that changed nothing real.
  const candidates = [WRAPPER, LEGACY, 'modules/crucible/plugins/ciab/utils/lane-reservation.js']
    .filter(exists);
  assert.ok(candidates.length > 0, 'no CIAB deploy-side util found at all');
  const found = candidates.some(rel => /reserveLabNetwork|teardownLabNetwork/.test(codeOnly(read(rel))));
  assert.ok(found,
    `None of ${candidates.join(', ')} reserves or releases its lab network through `
    + `src/utils/lab-network-provision.js. ${TRACK_A} (A1)`);
});

// ── Rule 3: the reservation key must carry the engagement ───────────────────

test('the per-profile challenge key is scoped by engagement, not by profile alone', () => {
  // getOrCreateProfileChallenge keys on `ciab-profile-<profileId.slice(0,8)>`.
  // That is one reservation per PROFILE, so an EXTERNAL engagement and an
  // INTERNAL engagement against the same client alias onto a single
  // crucible_challenge — and tearing one down destroys the other's live lanes.
  //
  // "Client A wants internal, Client B wants external" is the headline
  // requirement of this whole program, and it cannot coexist with a
  // profile-only key.
  const srcs = [deployImpl(), ...(exists(WRAPPER) && exists(LEGACY) ? [{ rel: LEGACY, src: read(LEGACY) }] : [])];
  for (const { rel, src } of srcs) {
    const code = codeOnly(src);
    const m = code.match(/`ciab-profile-\$\{[^`]*`/);
    if (!m) continue;
    assert.match(m[0], /engagement/i,
      `${rel} keys the reservation on the profile alone (${m[0]}). It must include the `
      + `engagement type, or external and internal engagements against one client collide. ${TRACK_A} (A1)`);
  }
});

// ── A5: the mapping that is easy to drop silently ───────────────────────────

test('per-VM post_clone_scripts reach the shared deployer as vulnScripts', () => {
  // deployChallengeLanes takes vulnScripts: [{vm_name, script_slug}]
  // (challenge-lane-deployer.js:1662). profile-to-spec emits
  // spec.vms[].post_clone_scripts. Nothing maps one to the other automatically.
  //
  // Miss this and the deploy still succeeds, the lanes still come up, and every
  // profile lane quietly loses its init-setup bootstrap and all per-service
  // planting — the SMB shares, the vulnerable services, the whole reason a real
  // nmap against the lane matches the paper scan report.
  const { rel, src } = deployImpl();
  const code = codeOnly(src);
  assert.ok(/vulnScripts/.test(code),
    `${rel} must pass vulnScripts to deployChallengeLanes. ${TRACK_A} (A5)`);
  assert.ok(/post_clone_scripts/.test(code),
    `${rel} must map spec.vms[].post_clone_scripts into vulnScripts, or all vuln `
    + `planting is silently lost. ${TRACK_A} (A5)`);
});

// ── W6: retry ───────────────────────────────────────────────────────────────

test('W6: retry does not destroy the gateway it is about to start', () => {
  // job.vm_ids includes the gateway (allVmIds starts as [gatewayVmId] and is
  // persisted mid-deploy). The retry handler force-destroys every id in that
  // array — the 100000-199999 band is dispatched as 'lxc', so the gateway
  // container goes — then computes `gatewayVmId = 100000 + job.vxlan_id` and
  // calls deployOneLaneFromSpec, which is Phase 2 only and has no gateway-clone
  // step. It goes straight to POST .../lxc/<gatewayVmId>/status/start against a
  // container that no longer exists.
  //
  // Retry therefore cannot succeed for any lane whose deploy got far enough to
  // write vm_ids — which is every lane worth retrying.
  const src = read(ROUTE);
  const code = codeOnly(src);
  assert.ok(!/deployOneLaneFromSpec\(/.test(code),
    `${ROUTE} still drives a private single-lane deploy. Retry must re-enter the shared `
    + `path so the gateway is re-created, not started from rubble. ${TRACK_A} (A5)`);
});

// ── A7: the fourth copy is gone ─────────────────────────────────────────────

test('A7: ciab/utils/lane-deploy.js no longer exists', () => {
  assert.ok(!exists(LEGACY),
    `${LEGACY} is still present. Track A ends by deleting the fourth copy so it cannot `
    + `drift again; until then the shared primitive is advisory rather than mandatory. ${TRACK_A} (A7)`);
});

// ── Guard: the shared primitive keeps the contract these tests assume ───────

test('the shared spec deployer still exposes deployChallengeLanes and vulnScripts', () => {
  // If someone renames these, every assertion above turns into a false green.
  const src = read(SHARED_SPEC_DEPLOYER);
  assert.ok(/deployChallengeLanes,/.test(src),
    'challenge-lane-deployer must still export deployChallengeLanes');
  assert.ok(/vulnScripts\s*=\s*null,/.test(src),
    'deployChallengeLanesInner must still accept vulnScripts');
});
