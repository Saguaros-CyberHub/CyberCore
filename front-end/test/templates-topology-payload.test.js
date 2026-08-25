/**
 * templates-topology-payload.test.js -- the environment picker's drawable payload.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * GET /api/cle/templates/vulnerable gained a `topology` field so the deploy modal
 * can draw an environment that has never been deployed. It called
 * topology-validate.goadHostNames(), which returns NULL -- not an empty Set --
 * for any environment that is not a GOAD lab. Array.from(null) throws, the throw
 * escaped the row loop, the whole endpoint 500'd, and the instructor's picker
 * came back EMPTY with every environment silently missing.
 *
 * Non-GOAD is the overwhelmingly common case, so this broke essentially every
 * row at once while looking like "there are no environments".
 *
 * Two rules are pinned here:
 *   1. a plain non-GOAD spec produces a payload, not a throw;
 *   2. one unrenderable row cannot take the others down with it.
 *
 * Also asserts the payload stays a WHITELIST: the raw spec carries vxlan_block,
 * zone, template_node and goad.admin_password, none of which belong in an
 * instructor's browser.
 *
 * Run: node front-end/test/templates-topology-payload.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'templates.js'
);
// LF-normalised — extractFn() brace-matches on this text, and CRLF makes a
// bare-newline slice run past the function it meant to read.
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
const src = fs.readFileSync(ROUTE, 'utf8').split(CRLF).join(LF);

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

/**
 * The route pulls in Proxmox, the CLE pool and the audit writer at require time,
 * so the two pure helpers are lifted out of the source instead. Same idiom as
 * provision-slots.test.js.
 */
function extractFn(name) {
  let start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in templates.js — renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return src.slice(start, i + 1);
}

const { goadHostNames } = require(path.join(UTILS, 'topology-validate.js'));
const challengeLaneDeployer = require(path.join(UTILS, 'challenge-lane-deployer.js'));

// eslint-disable-next-line no-new-func
const helpers = new Function('goadHostNames', 'challengeLaneDeployer', 'console', `
  ${extractFn('buildTopologyPayload')}
  ${extractFn('safeTopologyPayload')}
  return { buildTopologyPayload, safeTopologyPayload };
`)(goadHostNames, challengeLaneDeployer, { warn() {} });

// Shapes taken from real rows in crucible_challenge.
const JUICE_SHOP = {
  vms: [{ os: 'windows', name: 'juice-shop', role: 'web', type: 'qemu', template_vmid: 1701 }],
  vxlan_block: { start: 10100, end: 10109 },
  zone: { abbrev: 'juice' },
  template_node: 'cyberhub-node-5',
};

const GOAD_LAB = {
  vms: [{ os: 'Windows Server 2019', name: 'DC01', role: 'dc', type: 'qemu', template_vmid: 1004 }],
  goad: { enabled: true, version: 'GOAD-Light', admin_password: 'vagrant' },
  vxlan_block: { start: 10200, end: 10209 },
};

// -- rule 1: a non-GOAD spec must not throw ---------------------------------

test('THE BUG: a plain non-GOAD environment produces a payload, not a throw', () => {
  assert.strictEqual(goadHostNames(JUICE_SHOP), null,
    'precondition: goadHostNames returns null, not an empty Set, for a non-GOAD spec');

  const out = helpers.buildTopologyPayload(JUICE_SHOP, 'v1');
  assert.deepStrictEqual(out.goad_host_names, []);
  assert.strictEqual(out.vms.length, 1);
  assert.strictEqual(out.vms[0].name, 'juice-shop');
});

test('a GOAD environment still reports its lab hosts', () => {
  const out = helpers.buildTopologyPayload(GOAD_LAB, 'v3');
  assert.ok(out.goad_host_names.length > 0, 'a GOAD lab should name its fixed hosts');
  assert.ok(out.goad_host_names.includes('dc01'));
});

test('a legacy single-VM spec with no vms[] is still drawable', () => {
  // metasploitable2-basic shape: a bare template_vmid and nothing else.
  const out = helpers.buildTopologyPayload({ template_vmid: 1600 }, 'v1');
  assert.strictEqual(out.vms.length, 1, 'resolveSpecVms synthesizes one entry');
});

test('an empty spec yields an empty payload rather than throwing', () => {
  const out = helpers.buildTopologyPayload({}, 'v2');
  assert.deepStrictEqual(out.vms, []);
  assert.deepStrictEqual(out.goad_host_names, []);
});

// -- rule 2: one bad row must not empty the picker --------------------------

test('an unrenderable environment degrades to an empty preview, not a 500', () => {
  const out = helpers.safeTopologyPayload(
    // A spec whose vms is a string rather than an array: resolveSpecVms returns
    // no entries and .map would be the throw site if anything downstream assumed.
    { get vms() { throw new Error('unreadable spec'); } }, 'v1', 'broken-row'
  );
  assert.deepStrictEqual(out.vms, []);
  assert.deepStrictEqual(out.goad_host_names, []);
  assert.strictEqual(out.subnet_scheme, 'v1');
});

test('the route calls the guarded wrapper, not the raw builder', () => {
  assert.ok(/topology: safeTopologyPayload\(/.test(src),
    'one bad spec must not be able to empty the whole picker again');
});

// -- the payload stays a whitelist ------------------------------------------

test('nothing sensitive rides along in the payload', () => {
  const out = helpers.buildTopologyPayload(GOAD_LAB, 'v3');
  const json = JSON.stringify(out);
  for (const leak of ['vxlan_block', 'admin_password', 'vagrant', 'zone', 'template_node']) {
    assert.ok(!json.includes(leak), `the topology payload leaked ${leak}`);
  }
});

test('per-VM keys are enumerated, so a future spec key cannot leak by default', () => {
  const out = helpers.buildTopologyPayload({
    vms: [{ name: 'web01', template_vmid: 1601, secret_note: 'do not ship this' }],
  }, 'v1');
  assert.ok(!JSON.stringify(out).includes('secret_note'));
  assert.deepStrictEqual(Object.keys(out.vms[0]).sort(), [
    'console_protocol', 'console_role', 'layout', 'name', 'nics',
    'os', 'os_family', 'role', 'template_vmid', 'type',
  ]);
});
