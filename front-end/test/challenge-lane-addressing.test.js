/**
 * challenge-lane-addressing.test.js — the additive shared-core capabilities the
 * profile-driven (CiAB) deploy path needs, and the back-compat rule that makes
 * them safe to land ahead of it.
 *
 * Four capabilities were added to the shared deployer so a profile lane can be
 * built WITHOUT a fifth copy of the deploy sequence (see that module's header
 * for why a fourth copy is already the problem):
 *
 *   1. a NIC model derived from the spec's os_family      (resolveSpecNicModel)
 *   2. fixed addresses for non-console spec machines      (resolveSpecAddressing)
 *   3. stable in-lane DNS names on the spec path          (resolveSpecAddressing)
 *   4. a postDeploy hook
 *
 * The whole risk is (1)-(4) changing what an EXISTING challenge deploys.
 * Capabilities 2, 3 and 4 are off unless asked for, and the first block below
 * pins that: a spec shaped like today's challenges must produce exactly nothing
 * new.
 *
 * Capability 1 is the exception and is NOT inert — see 'the e1000 flip DOES
 * reach canvas-authored challenges'. A canvas-authored Windows machine already
 * carries os_family in its stored spec, so its NIC changes from virtio to
 * e1000. That is a deliberate fix rather than an accident, and it is pinned as
 * declared behaviour rather than denied.
 *
 * Pure functions, so no Proxmox / DB / SSH — but challenge-lane-deployer pulls
 * site-config at module load (via batch-deployer), which reads a gitignored
 * config/site.json. Same require.cache stub console-designation.test.js uses.
 *
 * Run: node front-end/test/challenge-lane-addressing.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');
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

const {
  resolveSpecAddressing, SPEC_OCTET_MIN, SPEC_OCTET_MAX,
} = require(path.join(UTILS, 'challenge-lane-deployer.js'));
const {
  resolveSpecNicModel, resolveVmNics,
} = require(path.join(UTILS, 'lane-networking.js'));

// A lane shaped like the CiAB profile deploys that motivated all of this: a
// handful of ordinary servers, no GOAD, no console_role, Kali as the console.
const PROFILE_VMS = [
  { name: 'web01',  template_vmid: 1601, type: 'qemu', role: 'web',    os_family: 'linux' },
  { name: 'file01', template_vmid: 1004, type: 'qemu', role: 'server', os_family: 'windows_server' },
  { name: 'dc01',   template_vmid: 1004, type: 'qemu', role: 'server', os_family: 'windows_server' },
];

const BASE = {
  subnetScheme: 'v2',
  laneSubnetBase: '10.39.16',
  goadSubnetBase: '10.39.16',
};

const addressing = (over = {}) => resolveSpecAddressing({ ...BASE, ...over });

// ── 1. back-compat: nothing new unless asked for ────────────────────────────
//
// This is the load-bearing block. Every existing caller — the admin group
// deploy, CLE's "Deploy Vulnerable Machine", vuln-lab-provision — passes none of
// the new options, and must keep writing exactly the reservations it wrote
// before. A single extra dhcp-host line here is not cosmetic: dnsmasq refuses to
// start when two lines claim one address, which takes DHCP down for the WHOLE
// lane while it still reports 'active'.

test('pinAllVms off pins nothing — the default is byte-identical', () => {
  const { pinnedHosts, dnsRecords } = addressing({ specVms: PROFILE_VMS });
  assert.deepStrictEqual(pinnedHosts, [], 'no machine may be pinned by default');
  assert.deepStrictEqual(dnsRecords, [], 'no host-record without dns_aliases');
});

test('a spec with no os_family keeps virtio — the pre-existing NIC', () => {
  // The derivation must not invent a change where the spec says nothing. A spec
  // carrying neither os_family nor nic_model — which is every spec authored
  // through POST /create-lab, and every one that predates the topology canvas —
  // resolves exactly as it did before.
  assert.strictEqual(resolveSpecNicModel({ name: 'web01' }), null);
  const { nets } = resolveVmNics({ name: 'web01' }, {
    subnetScheme: 'v2', bridges: { lan: 'vnet1' },
  });
  assert.match(nets.net0, /^virtio,bridge=vnet1$/);
});

test('the e1000 flip DOES reach canvas-authored challenges — it is not inert', () => {
  // An earlier version of this test asserted the opposite, and was wrong in a
  // way worth recording: it checked challenge-spec.buildSpecVm, which is the
  // CREATE path (POST /create-lab), and concluded that no stored spec can carry
  // os_family. The EDIT path is the one that actually persists specs, and it
  // does no whitelisting at all:
  //
  //   topology-editor.js:271   a palette drop stamps os_family from the catalog row
  //   topology-editor.js:441   stripInternal() strips ONLY __topoId
  //   admin-challenges.js:940  saveTemplate posts vm_specs, then spec.vms = vm_specs
  //   lab-templates.js:389     PUT does `nextSpec.vms = vm_specs` verbatim
  //
  // So this is the shape a canvas-authored Windows machine already has in
  // crucible_challenge.spec.vms[], and it now resolves to e1000 where it used to
  // resolve to virtio. That is a deliberate FIX — a stock Windows guest on
  // virtio has no driver and never DHCPs — but it changes already-authored labs,
  // so it is pinned here as the declared behaviour rather than denied.
  const CANVAS_WINDOWS_VM = {
    name: 'dc01', role: '', os: 'Windows Server 2019', os_family: 'windows_server',
    template_vmid: 1004, type: 'qemu', vm_offset: 600000,
  };
  assert.strictEqual(resolveSpecNicModel(CANVAS_WINDOWS_VM), 'e1000');
  const { nets } = resolveVmNics(CANVAS_WINDOWS_VM, {
    subnetScheme: 'v2', bridges: { lan: 'vnet1' },
  });
  assert.strictEqual(nets.net0, 'e1000,bridge=vnet1',
    'a canvas-authored Windows challenge deploys with e1000, not virtio');

  // The create path used to drop os_family, so a challenge authored purely
  // through POST /create-lab was genuinely unaffected. That is no longer true:
  // buildSpecVm's whitelist now carries os_family (see
  // test/challenge-spec-whitelist.test.js), because dropping it made the create
  // and edit paths store DIFFERENT specs for the same canvas — the exact class
  // of bug challenge-spec.js exists to close. So the flip reaches both paths,
  // which is the correct end state: one canvas, one stored spec, one NIC model.
  const { buildSpecVm } = require(path.join(UTILS, 'challenge-spec.js'));
  const created = buildSpecVm(CANVAS_WINDOWS_VM, 0, 'k');
  assert.strictEqual(created.os_family, 'windows_server');
  assert.strictEqual(resolveSpecNicModel(created), 'e1000');
});

test('both ipOctet and dns_aliases survive create-lab', () => {
  // This test has been through three states, and the history is the point.
  // It first asserted that NEITHER key survived buildSpecVm's whitelist; then
  // that `ipOctet` did and `dns_aliases` did not — a gap recorded here rather
  // than left to be rediscovered. Both now survive, so both halves of the
  // Designer's SIEM shape reach the deployer from CREATE, not just from the
  // edit path's whole-object merge.
  //
  // Why the pair matters together: a SIEM authored on the canvas as
  // `{ name:'elk', role:'siem', ipOctet:24, dns_aliases:['elk'] }` needs BOTH.
  // The octet is the address its host-record points at; the alias is the name a
  // baked elastic-agent.yml (`ELK_HOST=elk.cybercore.lan`) actually resolves.
  // With the alias dropped the machine still got its pinned address and its DHCP
  // reservation but no host-record — so the sensor's agent resolved nothing
  // while reporting perfectly healthy and shipping zero events. Silent, and
  // invisible on the canvas that authored it.
  const { buildSpecVm } = require(path.join(UTILS, 'challenge-spec.js'));
  const out = buildSpecVm(
    { name: 'elk01', template_vmid: 1601, type: 'qemu',
      ipOctet: 85, dns_aliases: ['elk'] }, 0, 'k');
  assert.strictEqual(out.ipOctet, 85);
  assert.deepStrictEqual(out.dns_aliases, ['elk'],
    'a baked agent pointed at elk.cybercore.lan needs the host-record this key produces');
});

// ── 2. NIC model from os_family ─────────────────────────────────────────────
//
// A stock Windows image has no virtio-net driver: the NIC comes up dead, the
// guest never DHCPs, and a "deployed" box is unreachable with nothing logged.
// The GOAD lab definitions have always hardcoded e1000 for this reason; a
// profile spec names its OS instead, so the same rule has to be derived.

test('a windows spec VM gets e1000, a linux one stays virtio', () => {
  assert.strictEqual(resolveSpecNicModel({ os_family: 'windows_server' }), 'e1000');
  assert.strictEqual(resolveSpecNicModel({ os_family: 'windows_client' }), 'e1000');
  assert.strictEqual(resolveSpecNicModel({ os_family: 'linux' }), null);
});

test('an explicit nic_model on the spec still wins over the derivation', () => {
  assert.strictEqual(
    resolveSpecNicModel({ os_family: 'windows_server', nic_model: 'virtio' }), 'virtio');
});

test('a GOAD lab NIC model outranks the spec derivation, in BOTH directions', () => {
  // prepareGoadMacs resolves the NIC model from the lab definition; that answer
  // is authoritative and must not be second-guessed by an os_family string.
  //
  // The fixtures must make the two candidates DISAGREE, or the test proves
  // nothing. An earlier version used os_family:'linux', for which
  // resolveSpecNicModel returns null — so `goadVm.nic_model || null || 'virtio'`
  // and the inverted `null || goadVm.nic_model || 'virtio'` both yield e1000 and
  // a precedence inversion sailed through.
  const goadVm = { mac: '02:00:CC:27:10:0A', nic_model: 'e1000' };
  const { nets } = resolveVmNics({ name: 'DC01', os_family: 'windows_server' }, {
    subnetScheme: 'v3', bridges: { ext: 'vext', int: 'vint' },
    goadMac: goadVm.mac, goadVm, isGoadVm: true,
  });
  assert.strictEqual(nets.net0, 'e1000,bridge=vint,macaddr=02:00:CC:27:10:0A');

  // The symmetric case is what actually pins the order: here the lab says
  // virtio and the spec derivation says e1000, so only the correct precedence
  // can produce virtio.
  const linuxLab = { mac: '02:00:CC:27:10:0B', nic_model: 'virtio' };
  const { nets: n2 } = resolveVmNics({ name: 'LX01', os_family: 'windows_server' }, {
    subnetScheme: 'v3', bridges: { ext: 'vext', int: 'vint' },
    goadMac: linuxLab.mac, goadVm: linuxLab, isGoadVm: true,
  });
  assert.strictEqual(n2.net0, 'virtio,bridge=vint,macaddr=02:00:CC:27:10:0B',
    'the GOAD lab definition must win over the os_family derivation');
});

test('a dual-homed windows pivot gets e1000 on BOTH NICs', () => {
  // The multi-NIC branch used to hardcode virtio, which is the same dead-NIC
  // defect in a second place — a v3 DMZ pivot running Windows never DHCPs.
  const { nets, dualHomed } = resolveVmNics(
    { name: 'dmz01', role: 'dmz', os_family: 'windows_server' },
    { subnetScheme: 'v3', bridges: { ext: 'vext', int: 'vint' } });
  assert.strictEqual(dualHomed, true);
  assert.strictEqual(nets.net0, 'e1000,bridge=vext');
  assert.strictEqual(nets.net1, 'e1000,bridge=vint');
});

test('a dual-homed linux pivot is unchanged — still virtio on both', () => {
  const { nets } = resolveVmNics(
    { name: 'dmz01', role: 'dmz' },
    { subnetScheme: 'v3', bridges: { ext: 'vext', int: 'vint' } });
  assert.strictEqual(nets.net0, 'virtio,bridge=vext');
  assert.strictEqual(nets.net1, 'virtio,bridge=vint');
});

// ── 3. fixed addressing for the machines the student attacks ────────────────

test('pinAllVms puts every spec machine in the .80-.99 band', () => {
  const { pinnedHosts } = addressing({ specVms: PROFILE_VMS, pinAllVms: true });
  assert.deepStrictEqual(pinnedHosts.map(h => h.name), ['web01', 'file01', 'dc01']);
  assert.deepStrictEqual(pinnedHosts.map(h => h.octet), [80, 81, 82]);
  assert.ok(pinnedHosts.every(h => h.subnetBase === '10.39.16'));
});

test('the console band is never re-used by a pinned machine', () => {
  // Two allocators handing one address to a console AND a pinned machine is
  // precisely the double-claim that stops dnsmasq starting.
  const { pinnedHosts } = addressing({
    specVms: PROFILE_VMS, pinAllVms: true,
    consoleOctetForVm: { web01: 60 },
    reserved: [50, 60],
  });
  assert.deepStrictEqual(pinnedHosts.map(h => h.name), ['file01', 'dc01'],
    'the console machine must not be pinned a second time');
  assert.ok(!pinnedHosts.some(h => h.octet === 60 || h.octet === 50));
});

test('an explicit ipOctet is honoured over the band', () => {
  const { pinnedHosts } = addressing({
    specVms: [{ name: 'web01', type: 'qemu', ipOctet: 15 }, { name: 'db01', type: 'qemu' }],
    pinAllVms: true,
  });
  assert.deepStrictEqual(pinnedHosts, [
    { name: 'web01', octet: 15, subnetBase: '10.39.16' },
    { name: 'db01',  octet: 80, subnetBase: '10.39.16' },
  ]);
});

test('an explicit ipOctet inside the band beats an auto-assignment', () => {
  // The allocator makes two passes for this reason. With one pass and a single
  // moving cursor, six unpinned machines take .80-.85 and the seventh — which
  // explicitly asked for .85 — is told its own address "is already taken",
  // naming a conflict the author cannot see anywhere in their spec and can only
  // work around by reordering the array. An explicit octet is the author's
  // contract with the generated paper, so it wins outright.
  const vms = [
    ...Array.from({ length: 6 }, (_, i) => ({ name: `srv${i}`, type: 'qemu' })),
    { name: 'web01', type: 'qemu', ipOctet: 85 },
  ];
  const { pinnedHosts } = addressing({ specVms: vms, pinAllVms: true });
  const byName = Object.fromEntries(pinnedHosts.map(h => [h.name, h.octet]));
  assert.strictEqual(byName.web01, 85, 'the explicit pin must be honoured');
  // and nothing auto-assigned may have taken it
  assert.strictEqual(new Set(pinnedHosts.map(h => h.octet)).size, 7, 'no duplicate octets');
  assert.ok(!Object.entries(byName).some(([n, o]) => n !== 'web01' && o === 85));
  // Order of the emitted list still follows spec order.
  assert.deepStrictEqual(pinnedHosts.map(h => h.name), vms.map(v => v.name));
});

test('an out-of-range or non-integer ipOctet is rejected, not silently masked', () => {
  // macForOctet does `octet & 0xFF`, so .300 would quietly become .44 and the
  // reservation would name an address nobody asked for. .1 is the lane gateway.
  // Number() also maps null -> 0 and true -> 1, which Number.isFinite accepts.
  for (const bad of [0, 1, -5, 300, 80.5, 255]) {
    assert.throws(
      () => addressing({ specVms: [{ name: 'x', type: 'qemu', ipOctet: bad }], pinAllVms: true }),
      /not a usable host address/,
      `ipOctet ${bad} must be rejected`);
  }
  // A machine that simply does not declare one is not "explicit" and must still
  // draw from the band rather than tripping the validator.
  const { pinnedHosts } = addressing({
    specVms: [{ name: 'x', type: 'qemu' }, { name: 'y', type: 'qemu', ipOctet: null }],
    pinAllVms: true,
  });
  assert.deepStrictEqual(pinnedHosts.map(h => h.octet), [80, 81]);
});

test('the lane gateway and the GOAD controller are never handed to a spec VM', () => {
  // .1 is the gateway itself. .5 is the GOAD controller, whose dhcp-host line is
  // written from liveGoadController and is therefore NOT in goadMacs — so the
  // allocator cannot learn it from there. On a v1/v2 lane the internal and
  // external bases are the same string, so a spec VM pinned to .5 emits a second
  // dhcp-host for one address and dnsmasq refuses to start, taking DHCP down for
  // the whole lane while it still reports 'active'.
  const INFRA = [1, 5];
  for (const octet of INFRA) {
    assert.throws(
      () => resolveSpecAddressing({
        ...BASE, specVms: [{ name: 'x', type: 'qemu', ipOctet: octet }],
        reserved: [50, 1, 5], pinAllVms: true,
      }),
      /already taken|not a usable host address/,
      `.${octet} must never be assignable`);
  }
});

test('a colliding ipOctet is named, not silently moved', () => {
  assert.throws(
    () => addressing({
      specVms: [{ name: 'web01', type: 'qemu', ipOctet: 50 }],
      pinAllVms: true, reserved: [50],
    }),
    /web01.*\.50.*already taken/);
});

test('overflowing the band is a named error, not a silent pool lease', () => {
  const many = Array.from({ length: 25 }, (_, i) => ({ name: `srv${i}`, type: 'qemu' }));
  assert.throws(
    () => addressing({ specVms: many, pinAllVms: true }),
    new RegExp(`\\.${SPEC_OCTET_MIN}-\\.${SPEC_OCTET_MAX} band is `));
});

test('GOAD hosts, LXCs and dual-homed machines are left alone', () => {
  // Each already has an address by another route, and pinning one writes a
  // reservation nothing ever requests:
  //   GOAD       — prepareGoadMacs gave it a static IP + MAC
  //   LXC        — takes net1; the template owns net0
  //   dual-homed — resolveVmNics builds those NICs inline and ignores the MAC
  const { pinnedHosts } = resolveSpecAddressing({
    ...BASE,
    subnetScheme: 'v3',
    goadSubnetBase: '10.39.17',
    specVms: [
      { name: 'DC01',  type: 'qemu' },
      { name: 'jump',  type: 'lxc' },
      { name: 'dmz01', type: 'qemu', role: 'dmz' },
      { name: 'web01', type: 'qemu' },
    ],
    goadMacs: { DC01: { mac: '02:00:CC:27:10:0A', static_ip: '10.39.17.10' } },
    pinAllVms: true,
  });
  assert.deepStrictEqual(pinnedHosts.map(h => h.name), ['web01']);
});

test('a v3 internal machine is reserved on the INTERNAL subnet', () => {
  // A reservation written against the external base offers a lease on a subnet
  // the guest's NIC is not attached to — indistinguishable from broken DHCP.
  const { pinnedHosts } = resolveSpecAddressing({
    ...BASE,
    subnetScheme: 'v3',
    goadSubnetBase: '10.39.17',
    specVms: [
      { name: 'int01', type: 'qemu', nics: [{ segment: 'int' }] },
      { name: 'ext01', type: 'qemu', nics: [{ segment: 'ext' }] },
    ],
    pinAllVms: true,
  });
  assert.strictEqual(pinnedHosts.find(h => h.name === 'int01').subnetBase, '10.39.17');
  assert.strictEqual(pinnedHosts.find(h => h.name === 'ext01').subnetBase, '10.39.16');
});

// ── 4. stable in-lane DNS names on the spec path ────────────────────────────
//
// The reservation hostname is per-lane, so it is useless as a link target: a
// baked config on one machine cannot know another's lane name. This is the gap
// that keeps `http://elk:9200` from resolving inside a spec-built lane.

test('a spec dns_alias resolves to that machine own pinned address', () => {
  const { dnsRecords } = addressing({
    specVms: [{ name: 'web01', type: 'qemu' },
              { name: 'elk01', type: 'qemu', dns_aliases: ['elk'] }],
    pinAllVms: true,
  });
  assert.deepStrictEqual(dnsRecords, [{ alias: 'elk', ip: '10.39.16.81' }]);
});

test('a console machine can carry an alias without pinAllVms', () => {
  const { dnsRecords } = addressing({
    specVms: [{ name: 'elk01', type: 'qemu', dns_aliases: ['elk'] }],
    consoleOctetForVm: { elk01: 60 },
  });
  assert.deepStrictEqual(dnsRecords, [{ alias: 'elk', ip: '10.39.16.60' }]);
});

test('an unpinned machine gets no host-record — an alias needs an address', () => {
  const { dnsRecords } = addressing({
    specVms: [{ name: 'elk01', type: 'qemu', dns_aliases: ['elk'] }],
  });
  assert.deepStrictEqual(dnsRecords, [], 'a pool lease has no address to publish');
});

test('an invalid alias is dropped rather than written into dnsmasq', () => {
  // One malformed line stops dnsmasq starting, which takes DHCP down for every
  // machine in the lane — so a bad alias must never reach the file.
  const { dnsRecords } = addressing({
    specVms: [{ name: 'elk01', type: 'qemu', dns_aliases: ['not a label', 'a.b', '', 'ok'] }],
    pinAllVms: true,
  });
  assert.deepStrictEqual(dnsRecords.map(r => r.alias), ['ok']);
});

test('two machines claiming one alias is an error, not a coin flip', () => {
  assert.throws(
    () => addressing({
      specVms: [{ name: 'a', type: 'qemu', dns_aliases: ['elk'] },
                { name: 'b', type: 'qemu', dns_aliases: ['elk'] }],
      pinAllVms: true,
    }),
    /'elk' is claimed by two machines/);
});

// ── 5. the postDeploy hook runs BEFORE flags ────────────────────────────────
//
// Structural, because deployLaneVms needs a whole cluster to call. The
// invariant is stated in that module's header and is easy to regress by moving
// one block: flags are planted LAST so nothing can clobber the files, which
// means a caller hook that seeds guest content must run ahead of them. A hook
// placed after plantFlagsForLane would be free to recreate a user profile on
// top of a planted user.txt, and the failure shows up as an unsolvable lab.

const SRC = fs.readFileSync(path.join(UTILS, 'challenge-lane-deployer.js'), 'utf8');

test('the postDeploy hook is invoked before flags are planted', () => {
  const hook  = SRC.indexOf('await ctx.postDeploy(');
  const flags = SRC.indexOf('await plantFlagsForLane(');
  assert.ok(hook > 0, 'postDeploy hook call not found');
  assert.ok(flags > 0, 'plantFlagsForLane call not found');
  assert.ok(hook < flags, 'postDeploy must run BEFORE plantFlagsForLane');
});

test('a postDeploy throw is recorded on the lane, not swallowed', () => {
  // Best-effort like vuln scripts and GOAD — but "best effort" has to reach the
  // instructor, or missing exercise content presents as "the lab just doesn't
  // work" on a lane that reports 'active'.
  assert.match(SRC, /postDeployError = hookErr\.message/);
  assert.match(SRC, /post_deploy_error: postDeployError/);
});

// ── 6. a rebuild must not drop the lane's pinning ───────────────────────────

test('rebuild replays pinned hosts from config rather than re-deriving them', () => {
  // The reservations file is rendered WHOLE-LANE on rebuild. Omitting the pinned
  // hosts deletes every one of their reservations and host-records, and those
  // machines fall to pool leases on their next reboot with nothing logged.
  assert.match(SRC, /cfg\.pinned_hosts/, 'rebuild must read pinned_hosts back from the lane config');
  assert.match(SRC, /cfg\.dns_records/,  'rebuild must read dns_records back from the lane config');
  // and the re-cloned VM has to get its MAC back, or it never matches the
  // reservation being rewritten.
  const rebuildAt = SRC.indexOf('async function rebuildLaneChallengeVms');
  assert.ok(rebuildAt > 0, 'rebuildLaneChallengeVms not found');
  assert.ok(SRC.indexOf('ctx._pinnedOctetForVm', rebuildAt) > rebuildAt,
    'rebuild must repopulate _pinnedOctetForVm so the clone keeps its pinned MAC');
});

// ── 7. dns_aliases parity for instructor-added machines (extras) ────────────
//
// resolveSpecAddressing built dnsRecords from specVms ONLY, so an extra
// workstation got a dhcp-host line from writeLaneReservations and NO
// host-record. Its aliases live on the CATALOG ROW (template.metadata), which is
// where the workstation path has always read them — the spec path simply never
// looked.
//
// Why it is not cosmetic: the CYBR 400 sensor image bakes
// ELK_HOST=elk.cybercore.lan into its elastic-agent.yml, and the ELK box MUST
// ride the extras path, because cloneChallengeVm never sets ciuser/cipassword —
// only cloneExtraWorkstation does. A spec-path ELK gets {username:null,
// password:null} in Guacamole: a lane that looks deployed and cannot be logged
// into. So ELK is an extra, and without a host-record the sensor's agent
// resolves nothing, reports healthy, and ships zero events. The exact silent
// failure this file exists to prevent.
//
// Shape: extraConsoles is [{ hostname, template, octet }], built by the deployer
// from consolePlan's 'extra' candidates plus the octet the console allocator
// just handed each one.

const EXTRA_ELK = {
  hostname: 'win-elk-0',
  template: { template_key: 'win-elk', metadata: { dns_aliases: ['elk'] } },
  octet: 60,
};

test('an extra carrying dns_aliases gets a host-record at its console address', () => {
  const { dnsRecords } = addressing({ specVms: [], extraConsoles: [EXTRA_ELK] });
  // The EXTERNAL base and the console octet — the same pair writeLaneReservations'
  // console loop emits the dhcp-host line from. If these two ever disagree the
  // record points at an address nothing on the lane holds.
  assert.deepStrictEqual(dnsRecords, [{ alias: 'elk', ip: '10.39.16.60' }]);
});

test('an extra alias needs no pinAllVms — it is a console, it already has an address', () => {
  // Extras are allocated by the console allocator, never by the pinning pass, so
  // their record is independent of pinAllVms exactly as a spec console's is.
  for (const pinAllVms of [false, true]) {
    const { dnsRecords, pinnedHosts } = addressing({
      specVms: [], extraConsoles: [EXTRA_ELK], pinAllVms,
    });
    assert.deepStrictEqual(dnsRecords, [{ alias: 'elk', ip: '10.39.16.60' }], `pinAllVms=${pinAllVms}`);
    assert.deepStrictEqual(pinnedHosts, [], 'an extra is never pinned — the console allocator owns it');
  }
});

test('an extra with no aliases produces no record — byte-identical for every existing caller', () => {
  // The back-compat assertion. Every caller in the tree today passes no
  // extraConsoles at all, and an added workstation from the ordinary catalog
  // carries no dns_aliases, so this pass must contribute exactly nothing.
  const plain = { hostname: 'win11-0', template: { template_key: 'win11', metadata: {} }, octet: 61 };
  assert.deepStrictEqual(addressing({ specVms: PROFILE_VMS, extraConsoles: [plain] }).dnsRecords, []);
  assert.deepStrictEqual(addressing({ specVms: PROFILE_VMS, extraConsoles: [] }).dnsRecords, []);
  assert.deepStrictEqual(addressing({ specVms: PROFILE_VMS }).dnsRecords, []);
  // No metadata at all, and no template at all — an extra loaded from a row that
  // predates the column must not throw.
  assert.deepStrictEqual(
    addressing({ extraConsoles: [{ hostname: 'a', template: {}, octet: 62 }] }).dnsRecords, []);
  assert.deepStrictEqual(
    addressing({ extraConsoles: [{ hostname: 'b', octet: 63 }] }).dnsRecords, []);
});

test('an extra with no allocated octet is skipped rather than publishing .undefined', () => {
  // Defensive: a record for `10.39.16.undefined` is a malformed dnsmasq
  // directive, and one of those stops dnsmasq starting — which takes DHCP down
  // for the whole lane.
  assert.deepStrictEqual(addressing({ extraConsoles: [{ ...EXTRA_ELK, octet: null }] }).dnsRecords, []);
  assert.deepStrictEqual(addressing({ extraConsoles: [{ ...EXTRA_ELK, octet: undefined }] }).dnsRecords, []);
  assert.deepStrictEqual(addressing({ extraConsoles: [null] }).dnsRecords, []);
});

test('a spec VM and an extra cannot both claim one alias — the throw names both', () => {
  // One claim table across both sources, not two. This is the shape a blue-team
  // lane produces by accident: an author adds an `elk` spec machine AND attaches
  // the registered ELK workstation. dnsmasq would answer with whichever
  // host-record it read first, so name both rather than publishing a coin flip.
  assert.throws(
    () => addressing({
      specVms: [{ name: 'elk01', type: 'qemu', dns_aliases: ['elk'] }],
      consoleOctetForVm: { elk01: 61 },
      extraConsoles: [EXTRA_ELK],
    }),
    (err) => {
      assert.match(err.message, /'elk' is claimed by two machines/);
      assert.match(err.message, /elk01/, 'the spec machine must be named');
      assert.match(err.message, /win-elk-0/, 'the added machine must be named');
      return true;
    });
});

test('two extras claiming one alias is the same error', () => {
  assert.throws(
    () => addressing({
      extraConsoles: [EXTRA_ELK, { ...EXTRA_ELK, hostname: 'win-elk-1', octet: 61 }],
    }),
    /'elk' is claimed by two machines on this lane \('win-elk-0' and 'win-elk-1'\)/);
});

test('spec records come first, so an existing lane keeps the addresses it had', () => {
  // Order is part of the output contract: dnsRecords is persisted onto the lane
  // config and replayed verbatim by the rebuild path, so a spec machine's record
  // must not move because an extra was added alongside it.
  const { dnsRecords } = addressing({
    specVms: [{ name: 'sensor', type: 'qemu', dns_aliases: ['sensor'] }],
    pinAllVms: true,
    extraConsoles: [EXTRA_ELK],
  });
  assert.deepStrictEqual(dnsRecords, [
    { alias: 'sensor', ip: '10.39.16.80' },
    { alias: 'elk', ip: '10.39.16.60' },
  ]);
});

test('an extra alias is validated by the SAME resolver the workstation path uses', () => {
  // Not a second regex. One malformed label stops dnsmasq starting, and the two
  // deploy paths must not disagree about what a valid alias is.
  const { dnsRecords } = addressing({
    extraConsoles: [{
      hostname: 'win-elk-0', octet: 60,
      template: { template_key: 'win-elk', metadata: { dns_aliases: ['not a label', 'a.b', '', 'ELK', 'elk'] } },
    }],
  });
  // lowercased, de-duplicated, and the three invalid entries dropped with a warning.
  assert.deepStrictEqual(dnsRecords, [{ alias: 'elk', ip: '10.39.16.60' }]);
});

test('the CYBR 400 shape end to end: sensor spec VM + ELK extra, one lane', () => {
  // Exactly what a defensive_monitoring lane emits: the loggen sensor is a spec
  // machine in the .80-.99 pin band, the ELK box is an extra in the .60-.79
  // console band, and both names resolve inside the lane. The sensor's baked
  // agent asks for elk.cybercore.lan; this is the record that answers it.
  const { pinnedHosts, dnsRecords } = addressing({
    specVms: [
      { name: 'web01', type: 'qemu' },
      { name: 'sensor', type: 'qemu', role: 'sensor', dns_aliases: ['sensor'] },
    ],
    pinAllVms: true,
    consoleOctetForVm: {},
    extraConsoles: [EXTRA_ELK],
  });
  assert.deepStrictEqual(pinnedHosts.map(h => `${h.name}.${h.octet}`), ['web01.80', 'sensor.81']);
  assert.deepStrictEqual(dnsRecords, [
    { alias: 'sensor', ip: '10.39.16.81' },
    { alias: 'elk', ip: '10.39.16.60' },
  ]);
});
