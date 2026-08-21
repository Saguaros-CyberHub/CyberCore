/**
 * challenge-extra-machines.test.js -- machines the instructor adds at deploy time.
 *
 * These are catalog workstations grafted onto an ENVIRONMENT lane, which is a
 * different problem from the workstation-only path: the environment owns the
 * VXLAN block, the spec owns the vm_offset namespace, and the lane already has
 * machines on it. Four rules make that safe, and each has a way of failing
 * silently, so each is pinned here:
 *
 *   1. VMIDs come from lane-deployer's SCANNED 300000-399999 band, never from
 *      the spec's vm_offset namespace -- findVmOffsetCollision guards that
 *      namespace, and an id invented per deploy would collide inside it.
 *   2. Added machines are recorded in config.vms[], never config.workstations[].
 *      teardownLanes reads the latter ONLY when the former is empty, which on a
 *      challenge lane it never is -- so anywhere else means an orphaned VM per
 *      student, per teardown.
 *   3. They never take .50. That octet is Kali's and is what the gateway bakes
 *      its DNAT against; two dhcp-host lines claiming one address stop dnsmasq,
 *      which takes DHCP down for the WHOLE lane.
 *   4. Flags are planted on the environment's own machines only. An added
 *      workstation is where the student works FROM.
 *
 * Pure/structural assertions -- the deploy path itself needs Proxmox. site-config
 * is stubbed the same way the slot tests do it.
 *
 * Run: node front-end/test/challenge-extra-machines.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');

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

const cld = require(path.join(UTILS, 'challenge-lane-deployer.js'));
const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));
const SRC = fs.readFileSync(path.join(UTILS, 'challenge-lane-deployer.js'), 'utf8');

// -- octet band --------------------------------------------------------------

test('the console octet band avoids every address another actor owns', () => {
  const { CONSOLE_OCTET_MIN, CONSOLE_OCTET_MAX } = cld;
  const KALI = require(path.join(UTILS, 'goad-deploy.js')).INFRA_IP_OCTETS.Kali;

  assert.ok(CONSOLE_OCTET_MIN > KALI,
    `the band must start above Kali's .${KALI} — the gateway bakes its DNAT against that address`);
  assert.ok(CONSOLE_OCTET_MIN > 23, 'must start above the GOAD lab hosts at .10-.23');
  assert.ok(CONSOLE_OCTET_MAX < 100,
    'must end below .100, where attached-modules starts allocating');
  assert.ok(CONSOLE_OCTET_MAX < 240, 'must stay clear of the v3 DMZ pivot at .240');
  // And inside lane-deployer's reserved workstation band, so nothing else on the
  // lane treats it as free.
  assert.ok(CONSOLE_OCTET_MIN >= laneDeployer.WORKSTATION_OCTET_BASE);
  assert.ok(CONSOLE_OCTET_MAX < laneDeployer.WORKSTATION_OCTET_BASE + laneDeployer.WORKSTATION_MAX_SLOTS);
});

// -- console plan handles the added machines ---------------------------------

test('every added machine gets a console, and one of them can be primary', () => {
  const { primary, consoles } = cld.resolveConsolePlan({
    specVms: [{ name: 'web01', template_vmid: 1601 }],
    attackBoxes: false,
    extraWorkstations: [{ hostname: 'kali-0' }, { hostname: 'win-1' }],
  });
  assert.strictEqual(consoles.length, 2, 'a machine you add is one to work from');
  assert.strictEqual(primary.name, 'kali-0', 'the first added machine is the default primary');
  assert.ok(!consoles.some((c) => c.kind === 'spec'),
    'an undesignated spec machine must not gain a console just because extras exist');
});

test('the added machines carry their slot index, so their VMID and octet can be found again', () => {
  const { consoles } = cld.resolveConsolePlan({
    specVms: [], attackBoxes: false,
    extraWorkstations: [{ hostname: 'a' }, { hostname: 'b' }],
  });
  assert.deepStrictEqual(consoles.map((c) => c.ref), ['ws:0', 'ws:1']);
  assert.deepStrictEqual(consoles.map((c) => c.index), [0, 1]);
});

// -- the source-level rules --------------------------------------------------

test('added machines are appended to config.vms, not config.workstations', () => {
  // Rule 2. teardownLanes: `if (cfg.vms.length) {...} else if (cfg.workstations...)`.
  assert.ok(/deployedVMs\.push\(\.\.\.deployedExtras/.test(SRC),
    'added machines must join the same list the environment machines are in');
  assert.ok(!/config\.workstations\s*=/.test(SRC),
    'the challenge path must never write config.workstations');
});

test('VMIDs come from the scanned band, never from vm_offset', () => {
  // Rule 1.
  assert.ok(/reserveWorkstationVmids\(extraSpecs\.length \* jobs\.length\)/.test(SRC),
    'one scan for the whole batch, before any clone');
  const cloneFn = SRC.slice(SRC.indexOf('async function cloneExtraWorkstation'));
  const body = cloneFn.slice(0, cloneFn.indexOf('\n}\n'));
  assert.ok(!/vm_offset/.test(body),
    'an added machine must not draw from the spec author\'s vm_offset namespace');
});

test('flags are planted on the environment\'s own machines only', () => {
  // Rule 4.
  assert.ok(/vms: deployedVMs\.filter\(v => v\.source !== 'instructor'\)/.test(SRC),
    'an added workstation is where the student works FROM — it must not carry a flag');
});

test('added machines are marked so every downstream filter can tell them apart', () => {
  const cloneFn = SRC.slice(SRC.indexOf('async function cloneExtraWorkstation'));
  assert.ok(/source: 'instructor'/.test(cloneFn.slice(0, 4000)));
});

test('an added machine resolves its console from its OWN catalog metadata', () => {
  // An SSH-only image published on 3389 is a console that connects to nothing.
  assert.ok(/template = c\.extra\.template;\s*\n\s*proto = laneDeployer\.resolveConsole\(template\)/.test(SRC),
    'extras must go through resolveConsole on their catalog row');
});

test('the catalog query uses the same predicate the picker does', () => {
  // A template that is offered must always be deployable, and one that is not
  // must be refused before any lane is built.
  const fn = SRC.slice(SRC.indexOf('async function loadExtraWorkstations'));
  const body = fn.slice(0, fn.indexOf('\n}\n'));
  for (const clause of ["template_type = 'workstation'", 'is_active     = TRUE',
                        "status        = 'active'", 'template_vmid IS NOT NULL']) {
    assert.ok(body.includes(clause), `catalog query is missing: ${clause}`);
  }
});

test('two added machines cannot share one template', () => {
  // dnsmasq keys DNS off the reservation hostname; a duplicate makes one machine
  // unresolvable inside the lane.
  const fn = SRC.slice(SRC.indexOf('async function loadExtraWorkstations'));
  assert.ok(/new Set\(ids\.map\(String\)\)\.size !== ids\.length/.test(fn.slice(0, 2000)));
});

test('attach mode refuses additions instead of dropping them', () => {
  const vlp = fs.readFileSync(path.join(
    __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils', 'vuln-lab-provision.js'
  ), 'utf8');
  assert.ok(/mode === 'attach' && \(\(extraWorkstations && extraWorkstations\.length\) \|\| consoleVm\)/.test(vlp),
    'attach grafts into someone else\'s lane — additions there are a different operation');
});
