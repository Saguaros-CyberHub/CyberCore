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

// -- E3d: the blue-team shape, now reachable from the Designer ---------------
//
// The elk01 fixture above predates the UI that can produce it. E3d makes the
// designation authorable in three places at once -- the canvas property panel's
// select, the canvas context menu, and the Designer's table radio -- so the
// rules below are what all three have to keep true. Every one of them is a
// property of resolveConsolePlan, which is the single reader.

const fs = require('fs');
const PUBLIC = path.join(__dirname, '..', 'public');

test('a GOAD blue-team lane: ws01 is the console and the headless SIEM is not', () => {
  // The shape E3d's exit criteria describe. ws01 is a domain-joined Windows 11
  // analyst box; the SIEM is a headless Ubuntu web app the student BROWSES to.
  // Designating the SIEM instead produces a lane that deploys clean and hands
  // the student a Guacamole session that connects to nothing.
  const spec = [
    { name: 'DC01', template_vmid: 1004, type: 'qemu', role: 'dc' },
    { name: 'ws01', template_vmid: 1002, type: 'qemu', role: 'workstation', console_role: 'primary' },
    { name: 'elk', template_vmid: 9001, type: 'qemu', role: 'siem', ipOctet: 24 },
  ];
  const { primary, consoles } = resolveConsolePlan({ specVms: spec, attackBoxes: false });
  assert.strictEqual(primary.name, 'ws01');
  assert.strictEqual(primary.kind, 'spec');
  assert.strictEqual(consoles.length, 1, 'the SIEM and the DC get no connection of their own');
});

test('ws01 as primary still beats Kali on a lane that also has an attack box', () => {
  // A defensive engagement may still carry Kali (the GOAD preset adds one by
  // default). The console button must open the analyst workstation, not the
  // attacker box -- which is what an explicit console_role buys.
  const spec = [
    { name: 'ws01', template_vmid: 1002, type: 'qemu', role: 'workstation', console_role: 'primary' },
    { name: 'elk', template_vmid: 9001, type: 'qemu', role: 'siem' },
  ];
  const { primary, consoles } = resolveConsolePlan({ specVms: spec, attackBoxes: true });
  assert.strictEqual(primary.name, 'ws01');
  assert.ok(consoles.some((c) => c.kind === 'kali'), 'Kali keeps its own connection, just not the button');
});

test('a SIEM CAN be designated -- the warning is advice, not a refusal', () => {
  // The Designer hints that a headless SIEM image cannot serve RDP as baked,
  // and it is only a hint: a site that adds a desktop + xrdp at bake time is
  // entitled to point students at it, and CYBR 400's hand-built Windows ELK box
  // (the elk01 fixture at the top of this file) is exactly that case.
  const { primary } = resolveConsolePlan({ specVms: ELK_SENSOR, attackBoxes: false });
  assert.strictEqual(primary.name, 'elk01');
  assert.strictEqual(primary.consoleRole, 'primary');
});

test('the three Designer editors all clear the previous primary, not just their own input', () => {
  // A radio group rendered over an array clears the other INPUTS, never the
  // DATA. Every editor therefore has to clear the previous holder itself, or a
  // spec saves with two primaries and this throws at deploy time.
  assert.throws(() => resolveConsolePlan({
    specVms: [
      { name: 'ws01', template_vmid: 1002, console_role: 'primary' },
      { name: 'elk', template_vmid: 9001, console_role: 'primary' },
    ],
    attackBoxes: false,
  }), /both declare console_role 'primary'/);

  const src = {
    table: fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-topology.js'), 'utf8'),
    canvas: fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-editor.js'), 'utf8'),
    template: fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-challenges.js'), 'utf8'),
  };
  assert.match(src.table, /function setTopoConsolePrimary\(idx\)/,
    'the Designer table needs its own radio handler -- the canvas select is not reachable from the table');
  assert.match(src.table, /else if \(vm\.console_role === 'primary'\) delete vm\.console_role;/,
    'and it must clear the previous holder');
  assert.match(src.canvas, /if \(other !== vm && other\.console_role === 'primary'\) delete other\.console_role;/,
    'the property panel select clears it too');
  assert.match(src.canvas, /vms\.forEach\(function \(o\) \{ if \(o\.console_role === 'primary'\) delete o\.console_role; \}\);/,
    'and so does the context menu\'s "Set as student console"');
  assert.match(src.template, /function setTemplateConsolePrimary\(idx\)/,
    'the template editor radio this column was modelled on is still there');
});

test('the table radio tells the canvas, so the console badge cannot go stale', () => {
  // The canvas paints '> student console' off console_role. A table edit that
  // did not refresh the editor would leave the badge on the previous machine --
  // two views of one array disagreeing about the answer to the one question
  // this whole feature exists to answer.
  const src = fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-topology.js'), 'utf8');
  assert.match(src, /function setTopoConsolePrimary\(idx\)[\s\S]{0,700}topoDesigner\.refresh\(topoVms\)/);
});

test('the headless-SIEM hint is shown where the choice is made, in both editors', () => {
  const panel = fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-editor.js'), 'utf8');
  const table = fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-topology.js'), 'utf8');
  assert.match(panel, /vm\.console_role && String\(vm\.role \|\| ''\)\.toLowerCase\(\) === 'siem'/,
    'the property panel warns when a SIEM is designated');
  assert.match(panel, /headless/i);
  assert.match(table, /const headless = String\(vm\.role \|\| ''\)\.toLowerCase\(\) === 'siem';/,
    'and so does the table column');
  assert.match(table, /no desktop and no xrdp/);
});

test('the canvas badge and the deploy-time answer read the SAME field', () => {
  // topology-render paints badge:'console' from console_role === 'primary';
  // resolveConsolePlan reads console_role. One field, so the canvas cannot show
  // one machine while the lane opens another.
  const editor = fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-editor.js'), 'utf8');
  assert.match(editor, /badge: vm\.console_role === 'primary' \? 'console' : ''/);
  const { consoles } = resolveConsolePlan({
    specVms: [{ name: 'ws01', template_vmid: 1002, console_role: 'primary' }],
    attackBoxes: false,
  });
  assert.strictEqual(consoles[0].name, 'ws01');
  assert.strictEqual(consoles[0].primary, true);
});
