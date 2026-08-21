/**
 * console-designation.test.js -- who gets the student's console.
 *
 * resolveConsolePlan is the one place that answers "which machine does the
 * student's console button open onto?" for a challenge lane. Before it existed,
 * the answer was hardcoded to Kali; the whole risk of this change is that the
 * new logic must reproduce that answer EXACTLY for every lane that predates it,
 * and only ever behave differently when a spec or an instructor explicitly asks
 * it to. That back-compat rule is what this file pins.
 *
 * Pure function, so no Proxmox / DB / SSH is stood up -- but challenge-lane-
 * deployer pulls site-config at module load (via batch-deployer), which reads a
 * gitignored config/site.json. Same require.cache stub the slot tests use.
 *
 * Run: node front-end/test/console-designation.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
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

const { resolveConsolePlan } = require(path.join(UTILS, 'challenge-lane-deployer.js'));

// A minimal CYBR-480-shaped spec: one vuln box, no console_role anywhere.
const VULN_ONLY = [{ name: 'web01', template_vmid: 1601, type: 'qemu', role: 'web' }];

// A CYBR-400-shaped spec: the ELK box declares itself the console.
const ELK_SENSOR = [
  { name: 'elk01', template_vmid: 1005, type: 'qemu', role: 'siem', console_role: 'primary' },
  { name: 'sensor', template_vmid: 1007, type: 'qemu', role: 'sensor' },
];

// -- the back-compat rule (the reason this file exists) ----------------------

test('CYBR-480 shape: attackBoxes on, no console_role -> Kali is the console, unchanged', () => {
  const { primary, consoles } = resolveConsolePlan({ specVms: VULN_ONLY, attackBoxes: true });
  assert.strictEqual(primary.kind, 'kali');
  assert.strictEqual(primary.name, 'kali');
  assert.strictEqual(consoles.length, 1, 'only Kali gets a console on a classic vuln lane');
  assert.strictEqual(consoles[0].primary, true);
});

test('THE REGRESSION GUARD: attackBoxes off, no console_role -> NO console at all', () => {
  // Must NOT promote spec.vms[0]. A legacy challenge deployed without an attack
  // box had no console, and must keep having none, or every redeploy grows a
  // DNAT + Guac connection + cloud-init pass nobody asked for.
  const { primary, consoles } = resolveConsolePlan({ specVms: VULN_ONLY, attackBoxes: false });
  assert.strictEqual(primary, null);
  assert.strictEqual(consoles.length, 0);
});

// -- console_role on the spec ------------------------------------------------

test('CYBR-400 shape: a spec VM marked primary becomes the console, not Kali', () => {
  const { primary, consoles } = resolveConsolePlan({ specVms: ELK_SENSOR, attackBoxes: false });
  assert.strictEqual(primary.kind, 'spec');
  assert.strictEqual(primary.name, 'elk01');
  assert.strictEqual(consoles.length, 1, 'the un-marked sensor gets no console');
  assert.strictEqual(consoles[0].name, 'elk01');
});

test('a spec primary beats Kali even when an attack box is also present', () => {
  const { primary, consoles } = resolveConsolePlan({ specVms: ELK_SENSOR, attackBoxes: true });
  assert.strictEqual(primary.name, 'elk01', 'the explicit console_role wins over the implicit Kali');
  // Kali still gets its own connection; it is just not the one the student opens.
  assert.ok(consoles.some((c) => c.kind === 'kali'));
  assert.ok(consoles.some((c) => c.name === 'elk01' && c.primary));
});

test('a secondary spec VM gets a console but is never the primary', () => {
  const spec = [
    { name: 'elk01', template_vmid: 1005, console_role: 'primary' },
    { name: 'jump', template_vmid: 1009, console_role: 'secondary' },
    { name: 'sensor', template_vmid: 1007 },
  ];
  const { primary, consoles } = resolveConsolePlan({ specVms: spec, attackBoxes: false });
  assert.strictEqual(primary.name, 'elk01');
  assert.deepStrictEqual(consoles.map((c) => c.name).sort(), ['elk01', 'jump']);
  assert.strictEqual(consoles.find((c) => c.name === 'jump').primary, false);
});

// -- the per-deploy override -------------------------------------------------

test('the modal override beats a spec console_role', () => {
  const { primary } = resolveConsolePlan({ specVms: ELK_SENSOR, attackBoxes: true, override: 'kali' });
  assert.strictEqual(primary.kind, 'kali', 'the instructor can send the student to Kali for one deploy');
});

test('an override PROMOTES a machine the spec never designated', () => {
  // "Which machine do students open?" has to be answerable with any machine on
  // the lane -- an environment's author cannot anticipate every exercise. The
  // sensor carries no console_role, and the override is what grants it one.
  const { primary, consoles } = resolveConsolePlan({
    specVms: ELK_SENSOR, attackBoxes: false, override: 'sensor',
  });
  assert.strictEqual(primary.name, 'sensor');
  assert.strictEqual(primary.consoleRole, 'primary');
  // elk01's own console_role still earns it a connection; it is just no longer
  // the one the student opens.
  assert.deepStrictEqual(consoles.map((c) => c.name).sort(), ['elk01', 'sensor']);
  assert.strictEqual(consoles.find((c) => c.name === 'elk01').primary, false);
});

test('an override naming nothing on the lane still throws', () => {
  assert.throws(
    () => resolveConsolePlan({ specVms: ELK_SENSOR, attackBoxes: false, override: 'nope' }),
    /names no machine on this lane/
  );
});

// -- validation --------------------------------------------------------------

test('two spec VMs both claiming primary is rejected', () => {
  const spec = [
    { name: 'a', template_vmid: 1, console_role: 'primary' },
    { name: 'b', template_vmid: 2, console_role: 'primary' },
  ];
  assert.throws(() => resolveConsolePlan({ specVms: spec, attackBoxes: false }),
    /both declare console_role 'primary'/);
});

// -- instructor add-ons ------------------------------------------------------

test('an added workstation gets a console and, with nothing else marked, is primary', () => {
  const { primary, consoles } = resolveConsolePlan({
    specVms: VULN_ONLY, attackBoxes: false,
    extraWorkstations: [{ hostname: 'kali-added' }],
  });
  assert.strictEqual(primary.kind, 'extra');
  assert.strictEqual(primary.name, 'kali-added');
  assert.strictEqual(consoles.length, 1);
});

test('Kali outranks an added workstation for the default primary', () => {
  const { primary, consoles } = resolveConsolePlan({
    specVms: VULN_ONLY, attackBoxes: true,
    extraWorkstations: [{ hostname: 'analyst-win' }],
  });
  assert.strictEqual(primary.kind, 'kali');
  // Both still get connections.
  assert.deepStrictEqual(consoles.map((c) => c.name).sort(), ['analyst-win', 'kali']);
});

test('an added workstation can be chosen as primary by override', () => {
  const { primary } = resolveConsolePlan({
    specVms: VULN_ONLY, attackBoxes: true,
    extraWorkstations: [{ hostname: 'analyst-win' }],
    override: 'ws:0',
  });
  assert.strictEqual(primary.name, 'analyst-win');
});
