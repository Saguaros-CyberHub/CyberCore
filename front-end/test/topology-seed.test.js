/**
 * topology-seed.test.js — the Topology tab's four seeding paths and its
 * create-lab body assembly.
 *
 * These transforms are where a mistake is expensive and silent. Cloning a
 * challenge that carries its source's vxlan_block would produce a spec claiming
 * another challenge's reserved network; dropping an authored vm_offset would move
 * machines nobody asked to move; aliasing instead of copying would let the
 * designer mutate the challenge-list cache. None of that shows up in a screenshot,
 * so it is asserted here.
 *
 * topology-seed.js touches no DOM at load time, so it loads in a `vm` sandbox with
 * a bare `window` — the same trick topology-editor-derive.test.js uses.
 *
 * Run: node front-end/test/topology-seed.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

function loadSeed() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'topology', 'topology-seed.js'), 'utf8'),
    sandbox, { filename: 'topology-seed.js' });
  return sandbox.CyberCoreTopologySeed;
}

const Seed = loadSeed();

/**
 * Sandbox objects carry the SANDBOX's Array/Object prototypes, so
 * deepStrictEqual rejects them as "same structure but not reference-equal" before
 * it ever looks at the values. Round-tripping through JSON re-homes them in this
 * realm — the same thing topology-editor-derive.test.js does for the same reason.
 */
function plain(v) {
  return JSON.parse(JSON.stringify(v === undefined ? null : v));
}

// A challenge row shaped like GET /lab-templates/:id (SELECT *), carrying every
// key a clone must refuse to copy.
function challengeRow(over) {
  return Object.assign({
    challenge_id: 'aaaa-bbbb',
    challenge_key: 'dundercorp-v1',
    name: 'DunderCorp Network',
    description: 'Paper company, poor segmentation',
    difficulty: 3,
    subnet_scheme: 'v3',
    status: 'active',
    created_at: '2026-01-02T00:00:00Z',
    spec: {
      vms: [
        { name: 'web01', role: 'dmz', os: 'Linux (Debian)', template_vmid: 1601, type: 'qemu',
          vm_offset: 620000, nics: [{ segment: 'ext' }, { segment: 'int' }], layout: { x: 300, y: 200 } },
        { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, type: 'qemu',
          vm_offset: 600000 },
      ],
      network: { version: 1, segments: [{ id: 'ext' }, { id: 'int' }], layout: { ext: { x: 120, y: 80 } } },
      phantom_assets: [{ hostname: 'printer01', ip: '10.0.0.9', role: 'printer', os: '', notes: '' }],
      goad: { enabled: true, version: 'GOAD-Light', include_kali: true },
      limits: { max_concurrent_lanes: 25 },
      // ── none of the following may survive a clone ──
      vxlan_block: { start: 10000, end: 10009 },
      zone: { abbrev: 'dunder' },
      cle: true,
      course_id: 'course-123',
      template_vmid: 1601,
      template_node: 'cyberhub-node-5',
    },
  }, over);
}

// ── blank ────────────────────────────────────────────────────────────────────

test('blank() seeds no placeholder VM row', () => {
  const s = Seed.blank('v3');
  assert.strictEqual(s.ok, true);
  assert.deepStrictEqual(plain(s.vms), []);
  assert.strictEqual(s.network, null);
  assert.strictEqual(s.subnet_scheme, 'v3');
  assert.strictEqual(s.challenge_key, '');
});

test('blank() defaults to v1 when no scheme is given', () => {
  assert.strictEqual(Seed.blank().subnet_scheme, 'v1');
});

// ── fromChallenge ────────────────────────────────────────────────────────────

test('a clone carries none of the reserved-network or regenerated keys', () => {
  const s = Seed.fromChallenge(challengeRow());
  const json = JSON.stringify(s);
  // challenge_key is the one entry that IS a seed field — blank, asserted below.
  for (const key of Seed.UNCLONEABLE_SPEC_KEYS) {
    if (key === 'challenge_key') continue;
    assert.ok(!(key in s), `seed must not expose ${key}`);
  }
  // The values must not have leaked anywhere either, at any depth.
  assert.ok(!json.includes('10009'), 'vxlan_block leaked');
  assert.ok(!json.includes('"dunder"'), 'zone.abbrev leaked');
  assert.ok(!json.includes('course-123'), 'course_id leaked');
  assert.ok(!json.includes('cyberhub-node-5'), 'template_node leaked');
});

test('a clone gets a BLANK challenge key and zone — the source key is unique', () => {
  const s = Seed.fromChallenge(challengeRow());
  assert.strictEqual(s.challenge_key, '');
  assert.strictEqual(s.zone_abbrev, '');
  assert.ok(s.notes.some(n => /challenge key/i.test(n)), 'should tell the author to name it');
});

test('a clone keeps the machines with their nics and layout', () => {
  const s = Seed.fromChallenge(challengeRow());
  assert.strictEqual(s.vms.length, 2);
  assert.deepStrictEqual(plain(s.vms[0].nics), [{ segment: 'ext' }, { segment: 'int' }]);
  assert.deepStrictEqual(plain(s.vms[0].layout), { x: 300, y: 200 });
  assert.strictEqual(s.vms[1].vm_offset, 600000);
});

test('a clone keeps network, phantoms and goad', () => {
  const s = Seed.fromChallenge(challengeRow());
  assert.deepStrictEqual(plain(s.network.layout), { ext: { x: 120, y: 80 } });
  assert.strictEqual(s.phantoms.length, 1);
  assert.strictEqual(s.goad.version, 'GOAD-Light');
});

test('a clone reads subnet_scheme from the ROW, not the spec', () => {
  // GET /lab-templates is SELECT * for this reason: the list endpoint omits the
  // column, and defaulting to v1 would draw one segment for a two-segment lab.
  assert.strictEqual(Seed.fromChallenge(challengeRow()).subnet_scheme, 'v3');
  assert.strictEqual(Seed.fromChallenge(challengeRow({ subnet_scheme: null })).subnet_scheme, 'v1');
});

test('a clone is a deep copy — mutating it cannot touch the source row', () => {
  const row = challengeRow();
  const before = JSON.stringify(row);
  const s = Seed.fromChallenge(row);
  s.vms[0].name = 'CHANGED';
  s.vms[0].nics.push({ segment: 'lan' });
  s.network.layout.ext.x = 999;
  s.phantoms[0].hostname = 'CHANGED';
  assert.strictEqual(JSON.stringify(row), before, 'the challenge-list cache must not be mutated');
});

test('a clone strips a persisted __topoId', () => {
  const row = challengeRow();
  row.spec.vms[0].__topoId = 'r1';
  const s = Seed.fromChallenge(row);
  assert.ok(!('__topoId' in s.vms[0]));
});

test('a clone falls back to row.vm_specs when spec.vms is empty', () => {
  const row = challengeRow({ spec: { limits: {} }, vm_specs: [{ name: 'legacy01', template_vmid: 1600 }] });
  const s = Seed.fromChallenge(row);
  assert.strictEqual(s.vms.length, 1);
  assert.strictEqual(s.vms[0].name, 'legacy01');
});

test('a clone parses a spec that arrives as a JSON string', () => {
  const row = challengeRow();
  row.spec = JSON.stringify(row.spec);
  const s = Seed.fromChallenge(row);
  assert.strictEqual(s.vms.length, 2);
  assert.ok(!('vxlan_block' in s));
});

test('a reservation-only challenge is refused, not cloned as an empty canvas', () => {
  const row = challengeRow({ spec: { vxlan_block: { start: 10000, end: 10009 }, cle: true, vms: [] } });
  const s = Seed.fromChallenge(row);
  assert.strictEqual(s.ok, false);
  assert.match(s.reason, /reserved lab network/i);
});

test('max_lanes is prefilled from spec.limits, with a sane default', () => {
  assert.strictEqual(Seed.fromChallenge(challengeRow()).max_lanes, 25);
  const row = challengeRow();
  delete row.spec.limits;
  assert.strictEqual(Seed.fromChallenge(row).max_lanes, 10);
});

test('the clone name is marked as a copy', () => {
  assert.strictEqual(Seed.fromChallenge(challengeRow()).name, 'DunderCorp Network (copy)');
});

test('stripUncloneableSpecKeys removes exactly the listed keys', () => {
  const spec = challengeRow().spec;
  const out = Seed.stripUncloneableSpecKeys(spec);
  for (const k of Seed.UNCLONEABLE_SPEC_KEYS) assert.ok(!(k in out), k);
  // ...and keeps the content.
  assert.ok(out.vms && out.network && out.goad && out.phantom_assets);
});

// ── fromGoadLab ──────────────────────────────────────────────────────────────

const LAB = {
  key: 'GOAD-Light',
  displayName: 'GOAD Light (3 hosts)',
  description: 'Trimmed GOAD',
  vms: [
    { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
    { name: 'DC02', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11, nic_model: 'e1000' },
    { name: 'SRV02', role: 'srv', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
  ],
};

test('a GOAD seed emits templateVMs shape with ARRAY services', () => {
  // The create form's builder emits comma STRINGS; the property panel calls
  // .join() on these, so a string would render as garbage characters.
  const s = Seed.fromGoadLab(LAB, {});
  assert.strictEqual(s.vms.length, 3);
  for (const v of s.vms) {
    assert.ok(Array.isArray(v.services), 'services must be an array');
    assert.ok(Array.isArray(v.default_scripts), 'default_scripts must be an array');
    assert.strictEqual(v.type, 'qemu');
  }
});

test('GOAD vm_offsets are unique and in the 600000 + n*10000 band', () => {
  const s = Seed.fromGoadLab(LAB, { includeKali: true, addPivot: true });
  const offsets = s.vms.map(v => v.vm_offset);
  assert.deepStrictEqual(offsets, [600000, 610000, 620000, 630000, 640000]);
  assert.strictEqual(new Set(offsets).size, offsets.length);
});

test('Kali is appended only when asked, and recorded in goad.include_kali', () => {
  assert.ok(!Seed.fromGoadLab(LAB, {}).vms.some(v => v.name === 'Kali'));
  assert.strictEqual(Seed.fromGoadLab(LAB, {}).goad.include_kali, false);
  const withKali = Seed.fromGoadLab(LAB, { includeKali: true });
  assert.strictEqual(withKali.vms[withKali.vms.length - 1].name, 'Kali');
  assert.strictEqual(withKali.goad.include_kali, true);
});

test('the pivot is appended only when asked, as a qemu dmz host with no nics', () => {
  const s = Seed.fromGoadLab(LAB, { addPivot: true });
  const pivot = s.vms.find(v => v.name === 'web01');
  assert.ok(pivot, 'pivot missing');
  assert.strictEqual(pivot.role, 'dmz');
  assert.strictEqual(pivot.type, 'qemu');
  assert.strictEqual(pivot.template_vmid, null);
  // No explicit nics: role dmz + qemu + v3 makes deriveSegments return
  // ['ext','int'] on its own, which keeps the spec matching the deploy derivation.
  assert.ok(!('nics' in pivot), 'the pivot must not carry explicit nics');
});

test('asking for the pivot forces v3 — there is nothing to pivot between otherwise', () => {
  assert.strictEqual(Seed.fromGoadLab(LAB, { addPivot: true }).subnet_scheme, 'v3');
  assert.strictEqual(Seed.fromGoadLab(LAB, { blankVmids: true }).subnet_scheme, 'v3');
  assert.strictEqual(Seed.fromGoadLab(LAB, {}).subnet_scheme, 'v1');
});

test('pre-baked mode blanks every non-Kali template_vmid and flags the subnets', () => {
  const s = Seed.fromGoadLab(LAB, { includeKali: true, addPivot: true, blankVmids: true });
  for (const v of s.vms) {
    if (v.name === 'Kali') assert.strictEqual(v.template_vmid, 1699);
    else assert.strictEqual(v.template_vmid, null, v.name);
  }
  assert.strictEqual(s.goad.prebaked, true);
  assert.deepStrictEqual(plain(s.goad.fixed_subnet), { int: '', ext: '' });
});

test('an unknown lab is refused', () => {
  assert.strictEqual(Seed.fromGoadLab(null, {}).ok, false);
  assert.strictEqual(Seed.fromGoadLab({ key: 'x' }, {}).ok, false);
});

test('goadHostNames returns the names whose placement the lab fixes', () => {
  assert.deepStrictEqual(Seed.goadHostNames(LAB), ['DC01', 'DC02', 'SRV02']);
  assert.strictEqual(Seed.goadHostNames(null), null);
});

// ── fromTopologyFile ─────────────────────────────────────────────────────────

const FILE = {
  format: 'cybercore.topology',
  version: 1,
  challenge_key: 'exported-lab',
  name: 'Exported Lab',
  subnet_scheme: 'v3',
  goad: null,
  network: { version: 1, segments: [{ id: 'ext' }, { id: 'int' }], layout: { ext: { x: 1, y: 2 } } },
  vms: [{ name: 'web01', role: 'dmz', template_vmid: 1601, vm_offset: 600000, nics: [{ segment: 'ext' }] }],
};

test('an import without the format marker is refused', () => {
  assert.strictEqual(Seed.fromTopologyFile({ vms: [{ name: 'a' }] }).ok, false);
  assert.match(Seed.fromTopologyFile({}).reason, /format marker/i);
});

test('an import with no machines is refused', () => {
  assert.strictEqual(Seed.fromTopologyFile({ format: 'cybercore.topology', vms: [] }).ok, false);
  assert.strictEqual(Seed.fromTopologyFile({ format: 'cybercore.topology' }).ok, false);
});

test('an import ADOPTS the file scheme — the designer owns it, unlike the modal', () => {
  // Adopting is what keeps the file's nics[].segment ids valid; the modal warns
  // instead only because there the challenge's scheme is already fixed.
  assert.strictEqual(Seed.fromTopologyFile(FILE).subnet_scheme, 'v3');
  const noScheme = Object.assign({}, FILE); delete noScheme.subnet_scheme;
  assert.strictEqual(Seed.fromTopologyFile(noScheme).subnet_scheme, 'v1');
});

test('an import prefills the key but never the zone', () => {
  const s = Seed.fromTopologyFile(FILE);
  assert.strictEqual(s.challenge_key, 'exported-lab');
  assert.strictEqual(s.zone_abbrev, '');
});

test('an import deep-copies and strips __topoId', () => {
  const payload = JSON.parse(JSON.stringify(FILE));
  payload.vms[0].__topoId = 'r3';
  const before = JSON.stringify(payload);
  const s = Seed.fromTopologyFile(payload);
  s.vms[0].name = 'CHANGED';
  assert.ok(!('__topoId' in s.vms[0]));
  assert.strictEqual(JSON.stringify(payload), before);
});

// ── deriveZone ───────────────────────────────────────────────────────────────

test('deriveZone mirrors the create form', () => {
  assert.strictEqual(Seed.deriveZone('metasploitable2-basic'), 'metasplo');
  assert.strictEqual(Seed.deriveZone('DunderCorp'), 'dunderco');
  assert.strictEqual(Seed.deriveZone('cybr-480'), 'cybr480');
  assert.strictEqual(Seed.deriveZone(''), '');
});

test('deriveZone can produce an invalid id, and the gate catches it', () => {
  // Proxmox rejects a leading digit; a key like "480-lab" needs an explicit zone.
  assert.strictEqual(Seed.deriveZone('480-lab'), '480lab');
  const problems = Seed.validateCreateState(
    { name: 'n', challenge_key: '480-lab', max_lanes: 10, vms: [{ name: 'a', template_vmid: 1 }] }, {});
  assert.ok(problems.some(p => p.field === 'zone_abbrev'), JSON.stringify(problems));
});

// ── validateCreateState ──────────────────────────────────────────────────────

function goodState(over) {
  return Object.assign({
    name: 'DunderCorp',
    challenge_key: 'dundercorp',
    zone_abbrev: 'dunder',
    max_lanes: 10,
    difficulty: 'intermediate',
    module: 'crucible',
    subnet_scheme: 'v3',
    vms: [{ name: 'web01', template_vmid: 1601, vm_offset: 620000 }],
    network: null, phantoms: [], goad: null,
  }, over);
}

test('a good state has no problems', () => {
  assert.deepStrictEqual(plain(Seed.validateCreateState(goodState(), {})), []);
});

test('name and key are required', () => {
  assert.ok(Seed.validateCreateState(goodState({ name: '  ' }), {}).some(p => p.field === 'name'));
  assert.ok(Seed.validateCreateState(goodState({ challenge_key: '' }), {}).some(p => p.field === 'challenge_key'));
});

test('a duplicate key is caught before the request, not after the 409', () => {
  const problems = Seed.validateCreateState(goodState(), { existingKeys: ['other', 'dundercorp'] });
  assert.ok(problems.some(p => p.field === 'challenge_key' && /already exists/.test(p.message)));
});

test('max_lanes must be a whole number in 1..200', () => {
  for (const v of [0, 201, -1, 2.5, 'ten', null]) {
    assert.ok(Seed.validateCreateState(goodState({ max_lanes: v }), {}).some(p => p.field === 'max_lanes'),
      `max_lanes ${v} should be rejected`);
  }
  for (const v of [1, 10, 200]) {
    assert.ok(!Seed.validateCreateState(goodState({ max_lanes: v }), {}).some(p => p.field === 'max_lanes'),
      `max_lanes ${v} should pass`);
  }
});

test('an empty canvas is blocked', () => {
  assert.ok(Seed.validateCreateState(goodState({ vms: [] }), {}).some(p => p.field === 'vms'));
});

test('a machine with no template VMID BLOCKS rather than being dropped', () => {
  // The create form filtered these out; on a canvas that silently deletes a
  // machine the author drew.
  const problems = Seed.validateCreateState(goodState({
    vms: [{ name: 'web01', template_vmid: 1601 }, { name: 'db01' }, { template_vmid: null }],
  }), {});
  const p = problems.find(x => x.field === 'vms');
  assert.ok(p, 'expected a vms problem');
  assert.match(p.message, /db01/);
  assert.match(p.message, /\(unnamed\)/);
});

test('pre-baked GOAD needs a fixed internal subnet, and int must differ from ext', () => {
  const noInt = Seed.validateCreateState(goodState({
    goad: { enabled: true, prebaked: true, fixed_subnet: { int: '', ext: '10.39.161' } },
  }), {});
  assert.ok(noInt.some(p => p.field === 'goad' && /internal subnet/i.test(p.message)));

  const clash = Seed.validateCreateState(goodState({
    goad: { enabled: true, prebaked: true, fixed_subnet: { int: '10.167.161', ext: '10.167.161' } },
  }), {});
  assert.ok(clash.some(p => p.field === 'goad' && /must differ/i.test(p.message)));

  const ok = Seed.validateCreateState(goodState({
    goad: { enabled: true, prebaked: true, fixed_subnet: { int: '10.167.161', ext: '10.39.161' } },
  }), {});
  assert.deepStrictEqual(plain(ok), []);
});

test('non-prebaked GOAD does not require subnets', () => {
  assert.deepStrictEqual(
    plain(Seed.validateCreateState(goodState({ goad: { enabled: true, version: 'GOAD-Light' } }), {})), []);
});

// ── toCreateLabBody ──────────────────────────────────────────────────────────

test('the body carries exactly the keys create-lab destructures', () => {
  const body = Seed.toCreateLabBody(goodState());
  for (const k of ['name', 'challenge_key', 'description', 'zone_abbrev', 'max_lanes',
    'difficulty', 'module', 'subnet_scheme', 'challenge_type', 'vms']) {
    assert.ok(k in body, `missing ${k}`);
  }
});

test('an AUTHORED vm_offset survives — the form used to overwrite it', () => {
  const body = Seed.toCreateLabBody(goodState({
    vms: [
      { name: 'a', template_vmid: 1, vm_offset: 777000 },
      { name: 'b', template_vmid: 2, vm_offset: 888000 },
    ],
  }));
  assert.deepStrictEqual(body.vms.map(v => v.vm_offset), [777000, 888000]);
});

test('VMs are not filtered by template_vmid', () => {
  const body = Seed.toCreateLabBody(goodState({
    vms: [{ name: 'a', template_vmid: 1 }, { name: 'b' }],
  }));
  assert.strictEqual(body.vms.length, 2);
});

test('max_lanes is coerced to a number', () => {
  assert.strictEqual(Seed.toCreateLabBody(goodState({ max_lanes: '30' })).max_lanes, 30);
});

test('challenge_type flips at two machines', () => {
  assert.strictEqual(Seed.toCreateLabBody(goodState()).challenge_type, 'single_vm');
  assert.strictEqual(Seed.toCreateLabBody(goodState({
    vms: [{ name: 'a', template_vmid: 1 }, { name: 'b', template_vmid: 2 }],
  })).challenge_type, 'multi_vm');
});

test('zone falls back to the derived value when left blank', () => {
  assert.strictEqual(Seed.toCreateLabBody(goodState({ zone_abbrev: '', challenge_key: 'dundercorp' })).zone_abbrev,
    'dundercorp'.substring(0, 8));
});

test('network, phantoms and goad are omitted when empty', () => {
  const body = Seed.toCreateLabBody(goodState());
  assert.ok(!('network' in body));
  assert.ok(!('phantom_assets' in body));
  assert.ok(!('goad' in body));
});

test('network, phantoms and goad are included when present', () => {
  const body = Seed.toCreateLabBody(goodState({
    network: { version: 1, segments: [{ id: 'ext' }], layout: {} },
    phantoms: [{ hostname: 'p1' }],
    goad: { enabled: true, version: 'GOAD-Light' },
  }));
  assert.ok(body.network);
  assert.strictEqual(body.phantom_assets.length, 1);
  assert.strictEqual(body.goad.version, 'GOAD-Light');
});

test('a disabled goad block is not posted', () => {
  const body = Seed.toCreateLabBody(goodState({ goad: { enabled: false } }));
  assert.ok(!('goad' in body));
});

test('name, key and description are trimmed', () => {
  const body = Seed.toCreateLabBody(goodState({
    name: '  DunderCorp  ', challenge_key: '  dundercorp  ', description: '  notes  ',
  }));
  assert.strictEqual(body.name, 'DunderCorp');
  assert.strictEqual(body.challenge_key, 'dundercorp');
  assert.strictEqual(body.description, 'notes');
});
