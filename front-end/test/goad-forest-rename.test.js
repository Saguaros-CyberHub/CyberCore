/** GOAD deploy contracts: catalog, preparation, addressing and generated delivery.
 * Actual orchestration failures and identity checks live in goad-runtime.test.js.
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const GOAD_REL = path.join('src', 'utils', 'goad-deploy.js');
const goad = require(path.join(ROOT, GOAD_REL));
const rebrand = require(path.join(ROOT, 'src', 'utils', 'goad-lab-rebrand.js'));

const {
  GOAD_LABS, GOAD_EXTENSIONS, extensionsForLab, resolveGoadLab, prepareGoadMacs,
  resolveGeneratedLab, deliverGeneratedLab,
} = goad;

const GOAD_SRC = fs.readFileSync(path.join(ROOT, GOAD_REL), 'utf8');

/** vxlanId + lane subnet base, the two arguments prepareGoadMacs takes. */
const LANE = [4242, '10.9.9'];

/** assert.throws returns nothing, and several of these assert on the message. */
function caught(fn) {
  try { fn(); } catch (e) { return e; }
  return null;
}

/** Optional development checkout; production never reads GOAD lab contents. */
const UPSTREAM = process.env.GOAD_SOURCE_DIR || path.resolve(ROOT, '../../GOAD/GOAD');

/**
 * ad/DRACARYS/data/config.json is NOT strict JSON — it carries an illegal
 * trailing comma, and it works upstream only because ansible loads it through a
 * YAML loader. Stripping trailing commas is therefore the only way to read the
 * shipped tree at all; nothing in src/ parses these files, so the leniency
 * stops here.
 */
function readUpstreamConfig(lab) {
  const file = path.join(UPSTREAM, 'ad', lab, 'data', 'config.json');
  if (!fs.existsSync(file)) return null;
  const text = fs.readFileSync(file, 'utf8');
  try {
    return JSON.parse(text);
  } catch (e) {
    return JSON.parse(text.replace(/,(\s*[}\]])/g, '$1'));
  }
}

// ════════════════════════════════════════════════════════════════════════════
// 1. GOAD_LABS.domains
// ════════════════════════════════════════════════════════════════════════════

test('every lab declares the full domain list its config.json builds', (t) => {
  if (!fs.existsSync(UPSTREAM)) {
    t.skip(`no ${UPSTREAM} checkout — the tracked half of this contract is asserted below`);
    return;
  }
  let checked = 0;
  for (const [name, lab] of Object.entries(GOAD_LABS)) {
    const cfg = readUpstreamConfig(name);
    if (!cfg) continue;
    checked += 1;
    // Sorted, because config.json's key order is upstream's and the table lists
    // the forest root first for a reader. The SET is the contract.
    assert.deepStrictEqual(
      lab.domains.slice().sort(), Object.keys(cfg.lab.domains).sort(),
      `GOAD_LABS.${name}.domains disagrees with ad/${name}/data/config.json. Every root, child and `
      + 'independent trust domain must be included when planning a renamed forest.');
  }
  assert.ok(checked > 0, 'the checkout exists but no lab config was readable — the paths moved');
});

test('domains is non-empty everywhere and contains the forest root', () => {
  // The tracked half: true with no checkout at all. A lab whose `domains` omits
  // its own forestRoot would pass the multi-domain refusal by shrinking the
  // list, which is the cheapest way to break this by accident.
  for (const [name, lab] of Object.entries(GOAD_LABS)) {
    assert.ok(Array.isArray(lab.domains) && lab.domains.length > 0,
      `GOAD_LABS.${name} has no domains[] — the rename cannot tell whether it is single-domain`);
    assert.ok(lab.domains.includes(lab.forestRoot),
      `GOAD_LABS.${name}.domains does not contain its own forestRoot ${lab.forestRoot}`);
    for (const d of lab.domains) {
      assert.strictEqual(typeof d, 'string', `${name}: every domain must be a string`);
    }
  }
});

test('NHA is the reason the list exists: two domains, and childSubdomain is null', () => {
  // The trap this field was added for. academy.ninja.lan is a TRUST partner of
  // ninja.hack, not a child (it is not a suffix of it), so childSubdomain is
  // correctly null — and a rename keyed on `childSubdomain === null` would have
  // said "single domain, go ahead" for the one lab whose second domain is wired
  // by name and cannot follow a rename at all.
  assert.strictEqual(GOAD_LABS.NHA.childSubdomain, null);
  assert.strictEqual(GOAD_LABS.NHA.domains.length, 2);
  assert.ok(!GOAD_LABS.NHA.domains[1].endsWith(`.${GOAD_LABS.NHA.forestRoot}`),
    'academy.ninja.lan is not a child of ninja.hack — if that changes, so does the whole argument');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. shipsLabConfig
// ════════════════════════════════════════════════════════════════════════════

test('the catalog declares which extensions carry a config of their own', () => {
  assert.strictEqual(GOAD_EXTENSIONS.elk.shipsLabConfig, false);
  assert.strictEqual(GOAD_EXTENSIONS.wazuh.shipsLabConfig, false);
  assert.strictEqual(GOAD_EXTENSIONS.ws01.shipsLabConfig, true);
  assert.strictEqual(GOAD_EXTENSIONS.lx01.shipsLabConfig, true);
  for (const [key, ext] of Object.entries(GOAD_EXTENSIONS)) {
    assert.strictEqual(typeof ext.shipsLabConfig, 'boolean',
      `${key}: shipsLabConfig must be declared — the rename refuses on it, and an undefined flag `
      + 'reads as "no config" for an extension that may well have one');
  }
});

test('extension flags match tracked controller recipe metadata at require time', () => {
  // This is the require-time guard's contract, restated where a reader will
  // find it. The guard itself already ran: goad-deploy.js was required at the
  // top of this file, and a disagreement would have thrown there.
  const recipes = new Set(rebrand.listExtensionBases());
  for (const [key, ext] of Object.entries(GOAD_EXTENSIONS)) {
    assert.strictEqual(ext.shipsLabConfig === true, recipes.has(key),
      `GOAD_EXTENSIONS.${key}.shipsLabConfig and src/data/goad-base-labs/_extensions/${key}/ `
      + 'disagree. The rename delivers a rewritten config for every flagged extension and refuses '
      + 'the lane when it cannot, so the two halves have to describe the same set.');
    if (ext.shipsLabConfig !== true) continue;
    const base = JSON.parse(fs.readFileSync(path.join(ROOT, 'src/data/goad-base-labs/_extensions', key, 'base.json'), 'utf8'));
    assert.strictEqual(base.controller_recipe, key);
    assert.ok(Object.keys(base.stock.hosts).length > 0, `${key} must describe the identities its controller recipe rewrites`);
  }
});

test('the deploy path never probes GOAD-main to answer that question', () => {
  // The trap goad-role-manifest.js documents: GOAD-main/ is gitignored with
  // zero tracked files, so a probe against it is not "false on a broken
  // machine", it is false on most machines and on CI — silently permissive
  // exactly where being wrong is unrecoverable.
  const lines = GOAD_SRC.split(/\r?\n/);
  const offenders = lines
    .map((line, i) => ({ line: line.trim(), n: i + 1 }))
    .filter(({ line }) => !line.startsWith('//') && !line.startsWith('*'))
    .filter(({ line }) => /GOAD-main/.test(line) || /existsSync/.test(line));
  assert.deepStrictEqual(offenders, [],
    'goad-deploy.js reads the upstream checkout at runtime. Declare it on the catalog instead — '
    + 'a probe there is absent from CI and permissive everywhere it is missing.');
});

// ════════════════════════════════════════════════════════════════════════════
// 3. extensionsForLab resolves compatibility against the BASE lab
// ════════════════════════════════════════════════════════════════════════════

/** What the funnel stamps: a GOAD-Mini lane deployed under a minted name. */
function renamedSpec(extra) {
  return rebrand.rebrandGoadSpec({
    goad: {
      enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true,
      ...(extra || {}),
    },
    vms: [{ name: 'DC01' }, { name: 'ws01' }],
  });
}

test('ws01 survives a minted lab name — it is judged on baseLab, not the name', () => {
  const spec = renamedSpec({ extensions: ['ws01'] });
  assert.match(spec.goad.version, /^CC-GOADMINI-/, 'the funnel must mint a name for this to mean anything');

  const rows = extensionsForLab(spec.goad.version, spec.goad.lab);
  const ws01 = rows.find(r => r.key === 'ws01');
  assert.strictEqual(ws01.ok, true,
    'ws01 declares compatibility with GOAD-Mini and this lane IS GOAD-Mini, renamed. Judging it on '
    + 'the minted name drops it from the roster in silence.');
});

test('THE SYMPTOM: without baseLab the failure is a stray-machine error naming ws01', () => {
  // The bug as it presents. A lab definition with no baseLab is judged on the
  // minted name, ws01 is filtered out, the composed roster loses it — and
  // spec.vms still carries the machine, so assertGoadRoster reports a stray. The
  // message says nothing about compatibility, the rename, or the minted name.
  const spec = renamedSpec({ extensions: ['ws01'] });
  const orphaned = { ...spec, goad: { ...spec.goad, lab: { ...spec.goad.lab } } };
  delete orphaned.goad.lab.baseLab;

  const rows = extensionsForLab(orphaned.goad.version, orphaned.goad.lab);
  assert.strictEqual(rows.find(r => r.key === 'ws01').ok, false,
    'this is the state the fix prevents; if it stops reproducing, the fix is somewhere else now');
  assert.throws(() => prepareGoadMacs(orphaned, 4242, '10.9.9'), /roster mismatch[\s\S]*ws01/i);

  // And with baseLab carried, the same lane resolves ws01 into the roster and
  // hands it a deterministic MAC and a reserved address.
  const macs = prepareGoadMacs(spec, 4242, '10.9.9');
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC01', 'ws01']);
  assert.strictEqual(macs.ws01.static_ip, `10.9.9.${GOAD_EXTENSIONS.ws01.ipOctet}`);
});

test('a lab name with no baseLab still resolves compatibility on itself', () => {
  // The un-renamed path, unchanged: GOAD_LABS entries carry no baseLab and are
  // judged on their own name, which is what every lane in flight relies on.
  assert.strictEqual(extensionsForLab('GOAD-Mini').find(r => r.key === 'ws01').ok, true);
  assert.strictEqual(extensionsForLab('NHA').find(r => r.key === 'ws01').ok, false);
});

// ════════════════════════════════════════════════════════════════════════════
// 4. The funnel
// ════════════════════════════════════════════════════════════════════════════

/** The body of one top-level function, by name. */
function bodyOf(name) {
  const at = GOAD_SRC.indexOf(`async function ${name}(`);
  assert.notStrictEqual(at, -1, `${GOAD_REL} no longer declares ${name}`);
  const next = GOAD_SRC.slice(at + 1).search(/\n(?:async )?function /);
  return next === -1 ? GOAD_SRC.slice(at) : GOAD_SRC.slice(at, at + 1 + next);
}

test('the rename is compiled before anything else in deployGoadLane reads the spec', () => {
  // Placement is the whole contract. resolveGoadLab, prepareGoadMacs, the WinRM
  // list and the delivery all read `spec`; a rename applied after any one of
  // them leaves two readers resolving two different labs, and nothing throws
  // when those disagree — the failure resolveGoadLab exists to prevent, one
  // level up.
  const body = bodyOf('deployGoadLane');
  const funnel = body.indexOf('prepareGoadDeploymentSpec(spec)');
  const firstResolve = body.indexOf('resolveGoadLab(spec)');
  assert.notStrictEqual(funnel, -1, 'deployGoadLane no longer applies the forest rename');
  assert.ok(funnel < firstResolve,
    'preparation must run before the first resolveGoadLab(spec) in deployGoadLane');
  assert.ok(/\n  spec = prepareGoadDeploymentSpec\(spec\);/.test(body),
    'the funnel must REBIND spec, or every reader below it still sees the authored one');
});

test('the authored spec and the rebranded one address the lane identically', () => {
  // TWO SPECS REACH prepareGoadMacs ON EVERY RENAMED LANE, and they must agree.
  // challenge-lane-deployer calls it with the AUTHORED spec to build the clone
  // MACs and the gateway's DHCP reservations; deployGoadLane rebinds `spec` to
  // the rebranded one and calls it again for the WinRM wait list and prep.sh's
  // HOST_MAP. The rename changes the DOMAIN and the hostnames inside the forest,
  // never the roster names or the octets — and if it ever did, the reservations
  // would name one machine and the controller would wait on another, with
  // nothing throwing.
  const authored = {
    goad: { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true, extensions: ['ws01'] },
    vms: [{ name: 'DC01' }, { name: 'ws01' }],
  };
  const renamed = rebrand.rebrandGoadSpec(authored);
  assert.notStrictEqual(renamed, authored, 'this lane must actually be rebranded');
  assert.deepStrictEqual(prepareGoadMacs(authored, ...LANE), prepareGoadMacs(renamed, ...LANE));
});

test('a spec with nothing to rebrand comes back by identity', () => {
  // The premise the funnel rests on: every lane authored before this existed
  // must deploy byte-for-byte what it deploys today, and identity is the
  // cheapest possible proof of it.
  const plain = { goad: { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org' }, vms: [] };
  assert.strictEqual(rebrand.rebrandGoadSpec(plain), plain,
    'no rename_forest means no rebrand, and the SAME object');
});

// ════════════════════════════════════════════════════════════════════════════
// 5. Delivery — tree first, extension configs second, one step
// ════════════════════════════════════════════════════════════════════════════

/** A recording pair of deps for deliverGeneratedLab. */
function recorder() {
  const calls = [];
  return {
    calls,
    deps: {
      pushLabTree: async (opts) => {
        calls.push({ what: 'tree', lab: opts.lab, force: opts.force });
        return { lab: opts.lab, skipped: false, pushed: true, treeSha256: 'a'.repeat(64), chainMode: 'per-lab' };
      },
      pushExtensionConfig: async (opts) => {
        calls.push({ what: `ext:${opts.key}`, force: opts.force, content: opts.content });
        return { key: opts.key, skipped: false, pushed: true, sha256: 'b'.repeat(64), dest: `/opt/goad/extensions/${opts.key}/data/config.json` };
      },
    },
  };
}

test('a WS01 rename plan includes the extension identity metadata with the same root', () => {
  const spec = renamedSpec({ extensions: ['ws01'] });
  assert.strictEqual(spec.goad.generated_lab, undefined);
  assert.deepStrictEqual(spec.goad.rename_plan.selected_extensions, ['ws01']);
  assert.ok(spec.goad.rename_plan.expected_identities.some(vm => vm.name === 'ws01'));
  assert.strictEqual(spec.goad.rename_plan.expected_identities.find(vm => vm.name === 'ws01').domain, 'cy400test.org');
});

test('the controller receives only selected extension keys in its rename plan', () => {
  const spec = renamedSpec({ extensions: ['ws01'] });
  assert.deepStrictEqual(spec.goad.rename_plan.selected_extensions, ['ws01']);
  assert.ok(!JSON.stringify(spec.goad.rename_plan).includes('local_admin_password'));
});

test('a generated lab with no extension configs pushes exactly what it pushed before', async () => {
  // Every CiAB engagement takes this path. The result object is returned
  // UNTOUCHED, so a caller that stores it whole — and the offline tests that
  // assert on it — see the object pushLabTree returned.
  const spec = {
    goad: {
      enabled: true, version: 'CIAB-3f9a2c1b',
      lab: { forestRoot: 'a.b', vms: [{ name: 'DC01', role: 'dc', os: 'w', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' }] },
      generated_lab: { name: 'CIAB-3f9a2c1b', files: { 'data/config.json': '{}' }, chain: ['build.yml'] },
    },
    vms: [{ name: 'DC01' }],
  };
  const rec = recorder();
  const out = await deliverGeneratedLab({ controllerVmId: 1700, bestNode: 'node-1', spec, deps: rec.deps });
  assert.deepStrictEqual(rec.calls.map(c => c.what), ['tree']);
  assert.strictEqual(out.extensionConfigs, undefined);
});

test('a CiAB rewritten extension config that is not a string is refused before delivery', () => {
  const spec = {
    goad: { enabled: true, version: 'GOAD-Mini', generated_lab: {
      name: 'GOAD-Mini', files: { 'data/config.json': '{}' }, chain: ['build.yml'],
      extension_configs: { ws01: { lab_extension: {} } },
    } }, vms: [{ name: 'DC01' }],
  };
  assert.throws(() => resolveGeneratedLab(spec), /extension_configs\.ws01[\s\S]*STRING/);
});

// ════════════════════════════════════════════════════════════════════════════
// 6. The pre-clone refusals
// ════════════════════════════════════════════════════════════════════════════

test('supported multi-domain labs compile before deployment with the full renamed domain set', () => {
  for (const version of ['GOAD-Light', 'GOAD']) {
    const prepared = goad.prepareGoadDeploymentSpec({
      goad: { enabled: true, version, domain: 'cy400test.org', rename_forest: true },
      vms: goad.getLab(version).vms.map(vm => ({ name: vm.name })),
    });
    assert.ok(prepared.goad.rename_plan);
    assert.ok(prepared.goad.lab.domains.includes('corp.cy400test.org'));
    assert.ok(!prepared.goad.lab.domains.some(domain => domain.endsWith('.local')));
  }
});

test('a pre-baked lane cannot be renamed: its NTDS already contains the baked forest', () => {
  assert.throws(() => prepareGoadMacs({
    goad: { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true, prebaked: true },
    vms: [{ name: 'DC01' }],
  }, ...LANE), (e) => e.code === rebrand.REBRAND_CODES.PREBAKED);
});

test('a CiAB engagement is not rebranded over the tree it was briefed against', () => {
  assert.throws(() => prepareGoadMacs({
    goad: {
      enabled: true, version: 'CIAB-3f9a2c1b', domain: 'cy400test.org', rename_forest: true,
      lab: { forestRoot: 'a.b', vms: [{ name: 'DC01', role: 'dc', os: 'w', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' }] },
      generated_lab: { name: 'CIAB-3f9a2c1b', files: { 'data/config.json': '{}' }, chain: ['build.yml'] },
    },
    vms: [{ name: 'DC01' }],
  }, ...LANE), (e) => e.code === rebrand.REBRAND_CODES.ALREADY_GENERATED);
});

test('a renamed lane whose plan lost extension identity metadata is refused', () => {
  // The two-files-disagree state arrived at from the other side: the lab is
  // renamed, ws01 is selected, and nothing was compiled for it. Delivering that
  // pair installs a renamed forest beside a config that still names the old one.
  const spec = renamedSpec({ extensions: ['ws01'] });
  spec.goad.rename_plan.selected_extensions = [];
  const err = caught(() => prepareGoadMacs(spec, ...LANE));
  assert.strictEqual(err && err.code, rebrand.REBRAND_CODES.ALREADY_GENERATED);
  assert.match(err.message, /untrusted rename plan/);
});

test('a lane that ticks only elk is renamed without complaint — elk ships no config', () => {
  // The flag doing its job in the permissive direction. elk and wazuh read the
  // main lab's data, so a renamed forest reaches them for free.
  const spec = rebrand.rebrandGoadSpec({
    goad: { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true, extensions: ['elk'] },
    vms: [{ name: 'DC01' }, { name: 'elk' }],
  });
  assert.deepStrictEqual(Object.keys(prepareGoadMacs(spec, ...LANE)), ['DC01'],
    'elk is inLab:false — an ordinary spec VM, absent from the MAC table by design');
});

test('a generated tree aimed at a lab nobody runs is refused before the clones, not after', () => {
  // resolveGeneratedLab already refuses this — but it used to run first inside
  // deliverGeneratedLab, i.e. inside challenge-lane-deployer's catch, where the
  // refusal is logged and the lane still reports active.
  assert.throws(() => prepareGoadMacs({
    goad: {
      enabled: true, version: 'GOAD-Light',
      generated_lab: { name: 'CIAB-3f9a2c1b', files: { 'data/config.json': '{}' }, chain: ['build.yml'] },
    },
    vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }],
  }, ...LANE), /generated_lab\.name is 'CIAB-3f9a2c1b' but this deploy runs lab 'GOAD-Light'/);
});

test('strict preparation rejects unsupported rename bases before runtime', () => {
  assert.throws(() => goad.prepareGoadDeploymentSpec({
    goad: { enabled: true, version: 'NHA', domain: 'cy400test.org', rename_forest: true },
    vms: goad.getLab('NHA').vms.map(vm => ({ name: vm.name })),
  }), error => error.status === 400 && error.code === rebrand.REBRAND_CODES.NO_BASE_TREE);
});

// ════════════════════════════════════════════════════════════════════════════
// 7. The scoped throw
// ════════════════════════════════════════════════════════════════════════════

test("version 'light' still resolves the GOAD-Light roster and does not throw", () => {
  // THE MASS-BRICK GUARD. lab-templates.js writes `version: goad.version ||
  // 'light'`, and 'light' is not a GOAD_LABS key — so an unconditional throw on
  // an unknown lab would refuse to deploy every GOAD challenge stored through
  // that path. (That default is a real bug, and a separate change.)
  const spec = {
    goad: { enabled: true, version: 'light' },
    vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }],
  };
  const resolved = resolveGoadLab(spec);
  assert.strictEqual(resolved.labDef, GOAD_LABS['GOAD-Light']);
  assert.deepStrictEqual(Object.keys(prepareGoadMacs(spec, ...LANE)), ['DC01', 'DC02', 'SRV02']);
});

test("'light' plus a forest rename compiles the canonical GOAD-Light base", () => {
  const prepared = goad.prepareGoadDeploymentSpec({
    goad: { enabled: true, version: 'light', domain: 'cy400test.org', rename_forest: true },
    vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }],
  });
  assert.strictEqual(prepared.goad.lab.baseLab, 'GOAD-Light');
  assert.strictEqual(prepared.goad.lab.forestRoot, 'cy400test.org');
});

test('an unknown version with no rename and no tree still falls back, loudly in the log', () => {
  // Pinned behaviour (ciab-engagement-model B0-107 mirrors it), and safe only
  // because the roster check downstream refuses the mismatch it creates.
  assert.strictEqual(resolveGoadLab({ goad: { enabled: true, version: 'nonesuch' } }).labDef,
    GOAD_LABS['GOAD-Light']);
  assert.throws(() => prepareGoadMacs(
    { goad: { enabled: true, version: 'nonesuch' }, vms: [{ name: 'NOPE-01' }] }, ...LANE), /NOPE-01/);
});
