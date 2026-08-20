/**
 * provision-slots.test.js — sizing must not leak across machines.
 *
 * THE BUG THIS EXISTS TO PREVENT
 * The Provision Workstation modal PRE-FILLS its CPU/RAM/disk inputs from the
 * selected template's live Proxmox sizing (courses.html seedResourceInputs), so
 * a `resources` object is sent on essentially every deploy whether or not the
 * instructor touched it. `deployLanes` applies a scalar spec to EVERY slot.
 *
 * Put those two together for a CYBR 400 pair — a big Windows ELK box first, a
 * small Rocky sensor second — and every sensor gets cloned at the ELK box's
 * memory and disk. Silently, and multiplied by the size of the cohort: a class
 * of 30 turns 4 GB sensors into 16 GB ones and runs the cluster out of RAM.
 *
 * There is no error and nothing in the UI says it happened. So the rule is
 * pinned here: a scalar spec sizes machine 1 and nothing else.
 *
 * Run: node front-end/test/provision-slots.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');
const fs = require('fs');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'vms.js'
);
const src = fs.readFileSync(ROUTE, 'utf8');

// site-config reads config/site.json, which is gitignored and absent in a plain
// checkout — and batch-deployer calls it at MODULE level, so requiring
// lane-deployer for its validator would fail outside a deployed environment.
// Same require.cache stub lane-deployer-slots.test.js uses.
const UTILS = path.join(__dirname, '..', 'src', 'utils');
require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
  },
};

/**
 * The route pulls in the Proxmox client, the CLE pool and the audit writer at
 * require time, so lifting the two pure helpers out of the source is cheaper
 * and less brittle than standing all of that up. They are self-contained: only
 * `normalizeResourceSpec` crosses the boundary, and it is injected.
 */
function extractFn(name) {
  // Match `async function` too, and keep the keyword — dropping it leaves an
  // `await` inside a non-async function, which is a SyntaxError.
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in vms.js — did it get renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return { header: src.slice(start, open), body: src.slice(open, i + 1) };
}

const { header, body } = extractFn('parseRequestedResources');
// eslint-disable-next-line no-new-func
const parseRequestedResources = new Function(
  'normalizeResourceSpec',
  `return (${header}${body});`
)(require(path.join(UTILS, 'lane-deployer.js')).normalizeResourceSpec);

test('a scalar spec sizes ONLY the first machine', () => {
  const got = parseRequestedResources({ resources: { memory_mb: 16384, cores: 8 } }, 2);
  assert.ok(Array.isArray(got), 'a multi-slot deploy must receive a per-slot array');
  assert.deepStrictEqual(got[0], { memory_mb: 16384, cores: 8 });
  assert.strictEqual(got[1], null, 'machine 2 must fall through to its own template sizing');
});

test('a scalar spec is left scalar for a single-machine deploy', () => {
  // The pre-existing single-template path must be byte-identical.
  const got = parseRequestedResources({ resources: { memory_mb: 8192 } }, 1);
  assert.deepStrictEqual(got, { memory_mb: 8192 });
});

test('no resources at all stays null at any slot count', () => {
  assert.strictEqual(parseRequestedResources({}, 1), null);
  assert.strictEqual(parseRequestedResources({}, 2), null);
});

test('an explicit per-slot array is preserved', () => {
  const got = parseRequestedResources(
    { resources: [{ memory_mb: 16384 }, { memory_mb: 4096 }] }, 2
  );
  assert.deepStrictEqual(got, [{ memory_mb: 16384 }, { memory_mb: 4096 }]);
});

test('an array of empty specs collapses to null rather than a list of holes', () => {
  assert.strictEqual(parseRequestedResources({ resources: [{}, {}] }, 2), null);
});

test('more resource entries than machines is rejected, not silently truncated', () => {
  assert.throws(
    () => parseRequestedResources({ resources: [{ cores: 2 }, { cores: 2 }, { cores: 2 }] }, 2),
    /3 entries for 2 machine/
  );
});

test('an invalid value is still rejected inside an array', () => {
  // Out-of-range sizing must 400 up front, not after N lanes exist.
  assert.throws(() => parseRequestedResources({ resources: [{ cores: 0 }] }, 2));
  assert.throws(() => parseRequestedResources({ resources: { cores: 999999 } }, 2));
});

// ── template selection ───────────────────────────────────────────────────────

test('loadWorkstationTemplates rejects duplicate ids', async () => {
  // Two slots sharing one catalog row would make attack-target.js's
  // template-identity rung ambiguous (it needs exactly one match) and would
  // collide outright on a pinned console_wan_port.
  const { header: h2, body: b2 } = extractFn('loadWorkstationTemplates');
  const loadWorkstationTemplates = new Function(
    'loadWorkstationTemplate',
    `return (${h2}${b2});`
  )(async (id) => ({ id }));

  await assert.rejects(
    () => loadWorkstationTemplates({ template_ids: ['a', 'a'] }),
    /must be distinct/
  );
  await assert.rejects(() => loadWorkstationTemplates({}), /is required/);

  // Both single forms still work, and order is preserved.
  assert.deepStrictEqual(
    await loadWorkstationTemplates({ template_id: 'solo' }), [{ id: 'solo' }]
  );
  assert.deepStrictEqual(
    await loadWorkstationTemplates({ template_ids: ['elk', 'sensor'] }),
    [{ id: 'elk' }, { id: 'sensor' }]
  );
  // An empty array falls back to template_id rather than 400ing, so a client
  // that always sends both keys keeps working.
  assert.deepStrictEqual(
    await loadWorkstationTemplates({ template_id: 'solo', template_ids: [] }), [{ id: 'solo' }]
  );
});

test('the provision routes no longer read a bare template_id for the deploy', () => {
  // Guards against a partial revert: if either route resolved `template_id`
  // straight into a deploy again, the second machine would be dropped without
  // any error.
  assert.ok(
    !/const template = await loadWorkstationTemplate\(template_id\)/.test(src),
    'a provision route is still loading a single template directly'
  );
  assert.ok(
    /startProvision\(\{[^}]*templates[,}]/.test(src.replace(/\n/g, ' ')),
    'startProvision must be handed `templates`'
  );
});
