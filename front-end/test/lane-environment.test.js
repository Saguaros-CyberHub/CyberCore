'use strict';

const { test } = require('node:test');
const assert = require('node:assert/strict');
const {
  NAME_SUFFIX, laneKind, laneIdentity, studentOf, environmentOf, environmentKeysFor,
  specMachines, machineIdentity, createEnvironmentDirectory,
} = require('../src/utils/lane-environment');

const START = Date.parse('2026-09-13T18:00:00.000Z');
const GOAD_KEY = 'goad-ad-lab';

// The shape resolveGoadLab actually returns for GOAD-Light with the ws01 and elk
// extensions selected: ws01 joins the forest so it is already folded into
// labDef.vms, while elk sits outside it and only appears in extensions.external.
const LAB_DEF = {
  displayName: 'GOAD-Light (3 Win VMs, 2 domains)',
  forestRoot: 'cybersaguaros.local',
  vms: [
    { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 10 },
    { name: 'DC02', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 11 },
    { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 22 },
    { name: 'ws01', role: 'workstation', os: 'Windows 11', template_vmid: 1006, ipOctet: 31, extension: 'ws01' },
  ],
};
const EXTENSIONS = {
  elk: { key: 'elk', machine: 'elk', role: 'siem', os: 'Ubuntu Server (headless)', ipOctet: 24 },
};

function goadFake(options = {}) {
  const calls = [];
  return {
    calls,
    resolveGoadLab(spec) {
      calls.push(spec);
      if (options.throws) throw new Error(`Unknown GOAD lab version 'GOAD-Renamed', and this spec cannot fall back`);
      return {
        labName: 'GOAD-Light',
        labDef: LAB_DEF,
        fromSpec: false,
        extensions: { selected: ['ws01', 'elk'], inLab: [], external: new Set(['elk']) },
      };
    },
    getExtension(key) { return EXTENSIONS[String(key || '').toLowerCase()] || null; },
  };
}

// Deployer-written spec rows: names only, no os. That absence is the whole
// reason specMachines exists.
const goadSpec = () => ({
  goad: { enabled: true, version: 'GOAD-Light', extensions: ['ws01', 'elk'] },
  vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }, { name: 'ws01' }, { name: 'elk' },
    { name: 'Kali', role: 'attacker', os: 'Kali Linux' }],
});

// ---------------------------------------------------------------------------
// laneKind
// ---------------------------------------------------------------------------

test('laneKind answers every rung and keeps its precedence order', () => {
  assert.equal(laneKind({ ciab_bake: true }), 'staging');
  assert.equal(laneKind({ staging: true }), 'staging');
  assert.equal(laneKind({ analysis_profile: 'malware' }), 'malware');
  assert.equal(laneKind({ workstations: [{ analysis_profile: 'malware' }] }), 'malware');
  assert.equal(laneKind({ goad: { enabled: true } }), 'goad');
  assert.equal(laneKind({ ciab: true }), 'ciab');
  assert.equal(laneKind({ profile_lane_group: 'p1' }), 'ciab');
  assert.equal(laneKind({ cle: true, material_id: 'm1' }), 'course-lab');
  assert.equal(laneKind({ cle: true }), 'course');
  assert.equal(laneKind({ course_id: 'c1' }), 'course');
  assert.equal(laneKind({ group_id: 'g1' }), 'group');
  assert.equal(laneKind({ challenge_key: 'k1' }), 'challenge');
  assert.equal(laneKind({ challenge_id: 7 }), 'challenge');
  assert.equal(laneKind({}), 'lane');

  // Only two rungs were pinned before this file existed, so reordering the
  // ladder passed every test while silently blanking the admin dialog's group
  // headings (public/js/admin/admin-wazuh.js KIND_LABEL looks each string up and
  // drops an undefined result). One config carrying EVERY flag walks the ladder
  // down, losing the flags that just answered at each step.
  const cfg = { ciab_bake: true, staging: true, analysis_profile: 'malware', goad: { enabled: true },
    ciab: true, profile_lane_group: 'p1', cle: true, material_id: 'm1', course_id: 'c1',
    group_id: 'g1', challenge_key: 'k1', challenge_id: 7 };
  for (const [keys, expected] of [
    [['ciab_bake', 'staging'], 'staging'],
    [['analysis_profile'], 'malware'],
    [['goad'], 'goad'],
    [['ciab', 'profile_lane_group'], 'ciab'],
    [['material_id'], 'course-lab'],
    [['cle', 'course_id'], 'course'],
    [['group_id'], 'group'],
    [['challenge_key', 'challenge_id'], 'challenge'],
  ]) {
    assert.equal(laneKind(cfg), expected);
    for (const key of keys) delete cfg[key];
  }
  assert.equal(laneKind(cfg), 'lane');
});

// ---------------------------------------------------------------------------
// laneIdentity
// ---------------------------------------------------------------------------

test('laneIdentity prefers the recorded vxlan id and falls back to the name suffix', () => {
  const identity = laneIdentity({
    name: 'cle-cybr400-inperson-10882', vxlan_id: 10882,
    created_at: new Date('2026-09-01T00:00:00.000Z'),
  }, { cle: true, course_id: 'c1' });
  assert.deepEqual(identity, {
    vxlan_id: 10882,
    lane_number: 10882,
    family: 'cle-cybr400-inperson',
    created_at: '2026-09-01T00:00:00.000Z',
    kind: 'course',
  });

  const parsed = laneIdentity({ name: 'ciab-cochise101-4' }, { ciab: true });
  assert.equal(parsed.vxlan_id, null, 'a lane row without the column reports no vxlan id');
  assert.equal(parsed.lane_number, 4);
  assert.equal(parsed.family, 'ciab-cochise101');
  assert.equal(parsed.kind, 'ciab');

  // A string column survives the JOIN as a string on some read paths, so the
  // safe-integer test rejects it and the name has to answer instead.
  assert.equal(laneIdentity({ name: 'crucible-77', vxlan_id: '77' }, {}).lane_number, 77);
  assert.equal(laneIdentity({ name: 'crucible-77', vxlan_id: '77' }, {}).vxlan_id, null);
});

test('laneIdentity degrades to nulls rather than throwing on an unusable row', () => {
  const identity = laneIdentity({ name: 'Lab lane', created_at: 'garbage' }, {});
  assert.equal(identity.family, null, 'no -<digits> suffix means no family, not an empty string');
  assert.equal(identity.lane_number, null);
  assert.equal(identity.vxlan_id, null);
  // new Date('garbage').toISOString() throws RangeError, which would take the
  // whole inventory response with it.
  assert.equal(identity.created_at, null);
  assert.equal(identity.kind, 'lane');

  assert.deepEqual(laneIdentity(undefined, undefined), {
    vxlan_id: null, lane_number: null, family: null, created_at: null, kind: 'lane',
  });
  assert.equal(NAME_SUFFIX.test('cle-cybr400-inperson-10882'), true);
  assert.equal(NAME_SUFFIX.test('Lab lane'), false);
});

// ---------------------------------------------------------------------------
// studentOf
// ---------------------------------------------------------------------------

test('studentOf reads only the runner join and never the lane config', () => {
  assert.deepEqual(studentOf({
    lane_id: 'x', first_name: ' Ada ', last_name: 'Lovelace', student_email: 'ada@clinic.local',
  }), { name: 'Ada Lovelace', email: 'ada@clinic.local' });
  assert.deepEqual(studentOf({ student_email: 'ada@clinic.local' }), { name: null, email: 'ada@clinic.local' });
  assert.deepEqual(studentOf({ first_name: 'Ada' }), { name: 'Ada', email: null });
});

test('studentOf returns null for a lane with no join fields even when config snapshots an owner', () => {
  const lane = { lane_id: 'x', name: 'Own lane', config: {
    user_email: 'snapshot@example.test', owner_email: 'snapshot@example.test',
    first_name: 'Config', last_name: 'Snapshot', password: 'private-lane-password',
  } };
  assert.equal(studentOf(lane), null);
  assert.equal(studentOf({}), null);
  assert.equal(studentOf(undefined), null);
});

// ---------------------------------------------------------------------------
// environmentOf / environmentKeysFor
// ---------------------------------------------------------------------------

test('a workstation lane is a workstation environment even when it carries a challenge_key', () => {
  // cle/utils/lane-provision.js stamps the course's reserved-network key onto
  // every student lane, so key presence cannot be the test: 44 desktops would
  // otherwise group under the GOAD lab's title.
  const cfg = { cle: true, course_id: 'c1', challenge_key: 'cybr400-reserved-net',
    workstations: [{ slot: 0, vmid: 5101, hostname: 'cle-cybr400-inperson-10882-ws1' }] };
  assert.deepEqual(environmentOf({ name: 'cle-cybr400-inperson-10882' }, cfg), {
    key: 'workstation', type: 'workstation', challenge_key: null, label: 'Student workstations',
  });
  assert.deepEqual(environmentKeysFor({}, cfg), [], 'no spec read is worth doing for a desktop lane');

  const legacy = { challenge_key: 'cybr400-reserved-net', workstation_vmid: 5101, challenge_vm_id: 5102 };
  assert.equal(environmentOf({}, legacy).type, 'workstation');
});

test('an environment lane is typed from its config shape and keyed for a spec read', () => {
  const goad = { goad: { enabled: true }, challenge_key: GOAD_KEY,
    vms: [{ vm_id: 5201, name: 'DC01' }, { vm_id: 5202, name: 'elk' }] };
  assert.deepEqual(environmentOf({ name: 'cle-cybr400-goad-10900' }, goad), {
    key: GOAD_KEY, type: 'goad', challenge_key: GOAD_KEY, label: null,
  });
  assert.deepEqual(environmentKeysFor({}, goad), [GOAD_KEY]);

  const courseLab = { cle: true, material_id: 'm-42', vms: [{ vm_id: 5301, name: 'web01' }] };
  assert.deepEqual(environmentOf({}, courseLab), {
    key: 'm-42', type: 'course-lab', challenge_key: null, label: null,
  });
  assert.deepEqual(environmentKeysFor({}, courseLab), [],
    'a material-only lab has no challenge_key, so there is nothing to look up');

  const both = { material_id: 'm-42', challenge_key: 'lab-key', vms: [{ vm_id: 5301, name: 'web01' }] };
  assert.equal(environmentOf({}, both).key, 'lab-key', 'the challenge_key is the more specific key');
  assert.equal(environmentOf({}, both).type, 'course-lab');

  const challenge = { challenge_key: 'ctf-1', vms: [{ vm_id: 5401, name: 'target' }] };
  assert.equal(environmentOf({}, challenge).type, 'challenge');
  const legacy = { challenge_key: 'ctf-1', challenge_vm_id: 5401 };
  assert.equal(environmentOf({}, legacy).type, 'challenge');
});

test('an empty or missing config degrades to a plain lane instead of an "undefined" key', () => {
  // String(cfg.material_id) as a fallback yields the truthy literal 'undefined',
  // which would collapse every material-less lane into one nonsense group.
  for (const cfg of [{}, undefined, { vms: [] }, { workstations: [] }, { material_id: null }]) {
    const env = environmentOf({ name: 'Lab' }, cfg);
    assert.equal(env.key, 'lane');
    assert.equal(env.type, 'challenge');
    assert.equal(env.challenge_key, null);
    assert.equal(env.label, null);
    assert.deepEqual(environmentKeysFor({ name: 'Lab' }, cfg), []);
  }
});

test('attached module instances contribute their own challenge keys, deduplicated', () => {
  const cfg = { challenge_key: GOAD_KEY, vms: [{ vm_id: 5201, name: 'DC01' }], attached_modules: [
    { module_instance_id: 'i1', challenge_key: 'phishing-mod', vms: [{ vm_id: 5501, name: 'mail01' }] },
    { module_instance_id: 'i2', challenge_key: 'phishing-mod', vms: [{ vm_id: 5502, name: 'mail02' }] },
    { module_instance_id: 'i3', vms: [] },
  ] };
  assert.deepEqual(environmentKeysFor({}, cfg), [GOAD_KEY, 'phishing-mod']);
  // A desktop lane still needs its attached module described, even though its
  // own key is deliberately skipped.
  assert.deepEqual(environmentKeysFor({}, { workstations: [{ slot: 0 }], challenge_key: 'reserved',
    attached_modules: [{ challenge_key: 'phishing-mod' }] }), ['phishing-mod']);
});

// ---------------------------------------------------------------------------
// specMachines
// ---------------------------------------------------------------------------

test('specMachines folds the resolved GOAD roster and its external extensions over the spec rows', () => {
  const goad = goadFake();
  const machines = specMachines(goadSpec(), goad);
  assert.equal(goad.calls.length, 1);
  assert.deepEqual([...machines.keys()].sort(), ['dc01', 'dc02', 'elk', 'kali', 'srv02', 'ws01']);

  assert.deepEqual(machines.get('dc01'),
    { name: 'DC01', role: 'dc', os: 'Windows Server 2019', platform: 'windows', infra: false });
  assert.deepEqual(machines.get('srv02'),
    { name: 'SRV02', role: 'member', os: 'Windows Server 2019', platform: 'windows', infra: false });
  // ws01 joins the forest, so resolveGoadLab has already folded it into the lab
  // roster; it is never in extensions.external.
  assert.deepEqual(machines.get('ws01'),
    { name: 'ws01', role: 'workstation', os: 'Windows 11', platform: 'windows', infra: false });
  // elk sits outside the forest and is only reachable through getExtension.
  assert.deepEqual(machines.get('elk'),
    { name: 'elk', role: 'siem', os: 'Ubuntu Server (headless)', platform: 'linux', infra: true });
  assert.equal(machines.get('kali').infra, true, 'the attack box is never an install target');
  assert.equal(machines.get('kali').platform, 'linux');
});

test('specMachines degrades to the spec rows when the lab resolver throws', () => {
  const goad = goadFake({ throws: true });
  const machines = specMachines(goadSpec(), goad);
  assert.equal(goad.calls.length, 1);
  assert.deepEqual([...machines.keys()].sort(), ['dc01', 'dc02', 'elk', 'kali', 'srv02', 'ws01']);
  assert.deepEqual(machines.get('dc01'),
    { name: 'DC01', role: 'Server', os: 'Unknown', platform: null, infra: false });
  assert.equal(machines.get('kali').role, 'attacker', 'a role the spec itself carries still stands');
});

test('specMachines reports an unknown operating system as no platform at all', () => {
  const machines = specMachines({ vms: [
    { name: 'MYSTERY', os: 'Unknown' },
    { name: 'mac01', os: 'macOS 14' },
    { name: 'web01', os_family: 'linux' },
    { name: '' },
  ] }, goadFake());
  assert.equal(machines.get('mystery').platform, null);
  // darwin is a real answer from classifyPlatform and a lie on this wire: no
  // installer in this tree targets it.
  assert.equal(machines.get('mac01').platform, null);
  assert.equal(machines.get('mac01').os, 'macOS 14');
  assert.equal(machines.get('web01').platform, 'linux', 'os_family answers when os does not');
  assert.equal(machines.size, 3, 'a nameless row cannot be keyed and is dropped');
});

test('specMachines never resolves a lab for a spec that is not a GOAD spec', () => {
  const goad = goadFake();
  assert.equal(specMachines({ vms: [{ name: 'web01', os: 'Debian 12' }] }, goad).size, 1);
  assert.equal(specMachines({ goad: { enabled: false }, vms: [] }, goad).size, 0);
  assert.equal(specMachines(null, goad).size, 0);
  assert.deepEqual(goad.calls, []);
});

// ---------------------------------------------------------------------------
// machineIdentity
// ---------------------------------------------------------------------------

test('workstation slots collapse across lanes while their hostnames do not', () => {
  const env = environmentOf({}, { workstations: [{ slot: 0 }] });
  const keys = [];
  for (const vxlan of [10881, 10882, 10883]) {
    for (const slot of [0, 1]) {
      keys.push(machineIdentity({
        source: 'workstation', slot, vm_id: 5000 + vxlan % 10 * 2 + slot,
        name: `cle-cybr400-inperson-${vxlan}-ws${slot + 1}`, template_name: 'Win11-25H2',
      }, env));
    }
  }
  assert.deepEqual([...new Set(keys.map(row => row.machine_key))], ['workstation::slot0', 'workstation::slot1']);
  assert.equal(keys[0].machine_label, 'Workstation 1 · Win11-25H2');
  assert.equal(keys[1].machine_label, 'Workstation 2 · Win11-25H2');
  assert.equal(keys[0].environment_key, 'workstation');

  // Lanes provisioned before slots were recorded must not all become
  // `workstation::slotundefined`.
  const slotless = machineIdentity({ source: 'workstation', name: 'ws1' }, env);
  assert.equal(slotless.machine_key, 'workstation::slot0');
  assert.equal(slotless.machine_label, 'Workstation 1');
});

test('the same machine name in two environments produces two keys', () => {
  const goadEnv = { key: GOAD_KEY, machines: specMachines(goadSpec(), goadFake()) };
  const otherEnv = { key: 'blue-team-ctf', machines: new Map() };
  const target = { vm_id: 5201, name: 'dc01' };
  const first = machineIdentity(target, goadEnv);
  const second = machineIdentity(target, otherEnv);
  assert.equal(first.machine_key, `${GOAD_KEY}::dc01`);
  assert.equal(second.machine_key, 'blue-team-ctf::dc01');
  assert.notEqual(first.machine_key, second.machine_key,
    'one checkbox must not install on DC01 in an unrelated challenge');
  assert.equal(first.machine_label, 'DC01', 'the spec authored the casing; the deployer lowercased it');
  assert.equal(second.machine_label, 'dc01', 'without a spec the recorded name stands');
  assert.equal(first.environment_key, GOAD_KEY);
});

test('attached module and attack box targets get their own namespaces', () => {
  const env = { key: GOAD_KEY, machines: new Map() };
  assert.deepEqual(machineIdentity({ source: 'attached', module_key: 'phishing-mod', name: 'Mail 01' }, env), {
    machine_key: 'phishing-mod::mail-01', machine_label: 'Mail 01', environment_key: GOAD_KEY,
  });
  assert.equal(machineIdentity({ source: 'attached', name: 'mail01' }, env).machine_key, 'attached::mail01');
  assert.deepEqual(machineIdentity({ source: 'attack_box', vm_id: 5299, name: 'Attack box' }, env), {
    machine_key: `${GOAD_KEY}::attack-box`, machine_label: 'Attack box', environment_key: GOAD_KEY,
  });
});

test('machineIdentity tolerates a target with no name and an environment with no machines', () => {
  assert.deepEqual(machineIdentity({ vm_id: 907 }, undefined), {
    machine_key: 'lane::vm-907', machine_label: 'VM 907', environment_key: 'lane',
  });
  assert.equal(machineIdentity({}, { key: 'k' }).machine_key, 'k::vm');
  assert.equal(machineIdentity({ name: 'Windows  workstation' }, { key: 'k', machines: null }).machine_key,
    'k::windows-workstation');
});

// ---------------------------------------------------------------------------
// createEnvironmentDirectory
// ---------------------------------------------------------------------------

const SELECT = /^SELECT name, spec FROM [a-z0-9_]+ WHERE challenge_key = \$1$/;

function directory(options = {}) {
  const state = {
    clock: START,
    queries: [],
    deadlines: [],
    tables: options.tables || { crucible_challenge: { [GOAD_KEY]: { name: 'GOAD Active Directory', spec: goadSpec() } } },
    hang: !!options.hang,
    fail: options.fail || null,
  };
  const query = async (sql, args) => {
    state.queries.push({ sql, args: [...args] });
    assert.match(sql, SELECT, 'the loader issues exactly one statement shape');
    if (state.fail) throw new Error(state.fail);
    if (state.hang) return new Promise(() => {});
    const table = sql.match(/FROM ([a-z0-9_]+) /)[1];
    if (!Object.prototype.hasOwnProperty.call(state.tables, table)) {
      throw new Error(`relation "${table}" does not exist`);
    }
    const row = state.tables[table][args[0]];
    return { rows: row ? [row] : [] };
  };
  const service = createEnvironmentDirectory({
    query,
    now: () => state.clock,
    // A never-resolving deadline by default, so the loader alone decides the
    // race; the deadline test supplies its own.
    deadline: ms => { state.deadlines.push(ms); return (options.deadline || (() => new Promise(() => {})))(ms); },
    goad: options.goad || goadFake(),
  });
  return { state, service };
}

const goadLane = (overrides = {}) => ({ lane_id: 'l1', name: 'cle-cybr400-goad-10900', status: 'active',
  config: { goad: { enabled: true }, challenge_key: GOAD_KEY,
    vms: [{ vm_id: 5201, name: 'DC01' }, { vm_id: 5202, name: 'elk' }] }, ...overrides });

test('the directory describes a challenge key once and serves the rest from its memo', async () => {
  const h = directory();
  const first = await h.service.describeEnvironments([goadLane(), goadLane({ lane_id: 'l2' })]);
  assert.equal(h.state.queries.length, 1, 'two lanes sharing a key are one read');
  assert.deepEqual(h.state.queries[0].args, [GOAD_KEY]);
  assert.equal(h.state.queries[0].sql, 'SELECT name, spec FROM crucible_challenge WHERE challenge_key = $1');
  assert.deepEqual(h.state.deadlines, [1500]);

  const env = first.get(GOAD_KEY);
  assert.equal(env.label, 'GOAD Active Directory');
  assert.equal(env.goad, true);
  assert.equal(env.lab, 'GOAD-Light');
  assert.equal(env.labLabel, 'GOAD-Light (3 Win VMs, 2 domains)');
  assert.equal(env.machines.get('elk').role, 'siem');
  assert.equal(env.machines.get('dc01').platform, 'windows');

  h.state.clock += 59 * 1000;
  assert.equal((await h.service.describeEnvironments([goadLane()])).get(GOAD_KEY), env,
    'a poll inside the hit TTL reuses the memoised object');
  assert.equal(h.state.queries.length, 1);
  h.state.clock += 2 * 1000;
  await h.service.describeEnvironments([goadLane()]);
  assert.equal(h.state.queries.length, 2, 'an expired hit is refetched');
});

test('a miss is cached only briefly so a recovering table is picked up quickly', async () => {
  const h = directory({ tables: { crucible_challenge: {} } });
  assert.equal((await h.service.describeEnvironments([goadLane()])).get(GOAD_KEY), null);
  assert.equal(h.state.queries.length, 1);

  h.state.clock += 9 * 1000;
  await h.service.describeEnvironments([goadLane()]);
  assert.equal(h.state.queries.length, 1, 'still inside the miss TTL');

  h.state.clock += 2 * 1000;
  h.state.tables.crucible_challenge[GOAD_KEY] = { name: 'GOAD Active Directory', spec: goadSpec() };
  const env = (await h.service.describeEnvironments([goadLane()])).get(GOAD_KEY);
  assert.equal(h.state.queries.length, 2);
  assert.equal(env.label, 'GOAD Active Directory');
});

test('a module lane tries its own challenge table before the shared one', async () => {
  const h = directory({ tables: { ciab_challenge: { [GOAD_KEY]: { name: 'CiAB GOAD', spec: {} } },
    crucible_challenge: {} } });
  const lane = goadLane({ module_key: 'ciab' });
  const env = (await h.service.describeEnvironments([lane])).get(GOAD_KEY);
  assert.deepEqual(h.state.queries.map(row => row.sql.match(/FROM ([a-z0-9_]+) /)[1]), ['ciab_challenge']);
  assert.equal(env.label, 'CiAB GOAD');
  assert.equal(env.goad, false);
  assert.equal(env.machines.size, 0);

  // A missing module table is the expected first answer for most lanes, so the
  // shared table still has to be asked.
  const other = directory({ tables: { crucible_challenge: { [GOAD_KEY]: { name: 'Shared', spec: {} } } } });
  assert.equal((await other.service.describeEnvironments([goadLane({ module_key: 'ciab' })])).get(GOAD_KEY).label,
    'Shared');
  assert.deepEqual(other.state.queries.map(row => row.sql.match(/FROM ([a-z0-9_]+) /)[1]),
    ['ciab_challenge', 'crucible_challenge']);
});

test('a slow challenge table loses to the deadline and yields no environment', async () => {
  const h = directory({ hang: true, deadline: () => Promise.resolve(null) });
  const envs = await h.service.describeEnvironments([goadLane()]);
  assert.deepEqual([...envs], [[GOAD_KEY, null]]);
  assert.deepEqual(h.state.deadlines, [1500]);
});

test('an unreadable challenge table degrades to null and warns once', async () => {
  const warnings = [];
  const original = console.warn;
  console.warn = message => warnings.push(String(message));
  try {
    const h = directory({ fail: 'private database credentials rejected', tables: { crucible_challenge: {} } });
    const envs = await h.service.describeEnvironments([goadLane({ module_key: 'ciab' })]);
    assert.deepEqual([...envs], [[GOAD_KEY, null]]);
    assert.equal(h.state.queries.length, 2, 'both rungs are attempted before giving up');
  } finally {
    console.warn = original;
  }
  assert.equal(warnings.length, 1);
  assert.match(warnings[0], /could not load challenge spec 'goad-ad-lab'/);
  assert.match(warnings[0], /ciab_challenge, crucible_challenge/);
});

test('the directory reads nothing for lanes that have no environment to describe', async () => {
  const h = directory();
  const workstation = { lane_id: 'w1', name: 'cle-cybr400-inperson-10882', config: {
    cle: true, challenge_key: 'cybr400-reserved-net', password: 'private-lane-password',
    workstations: [{ slot: 0, vmid: 5101 }, { slot: 1, vmid: 5102 }] } };
  const envs = await h.service.describeEnvironments([workstation, { lane_id: 'e1', config: {} }, {}]);
  assert.equal(envs.size, 0);
  assert.deepEqual(h.state.queries, [], 'a desktop lane never triggers a crucible_challenge read');
  assert.deepEqual(await h.service.describeEnvironments([]), new Map());
  assert.deepEqual(await h.service.describeEnvironments(undefined), new Map());
});

test('the directory parses a spec stored as text and survives one that is not JSON', async () => {
  const h = directory({ tables: { crucible_challenge: {
    [GOAD_KEY]: { name: null, spec: JSON.stringify(goadSpec()) },
    broken: { name: 'Broken', spec: '{not json' },
  } } });
  const lanes = [goadLane(), goadLane({ lane_id: 'l2', config: { challenge_key: 'broken', vms: [{ vm_id: 1, name: 'x' }] } })];
  const envs = await h.service.describeEnvironments(lanes);
  assert.equal(envs.get(GOAD_KEY).label, GOAD_KEY, 'an unnamed challenge falls back to its key');
  assert.equal(envs.get(GOAD_KEY).machines.get('elk').platform, 'linux');
  assert.equal(envs.get('broken'), null);
});

test('the directory reads lane config handed to it as a JSON string', async () => {
  const h = directory();
  const lane = goadLane();
  const envs = await h.service.describeEnvironments([{ ...lane, config: JSON.stringify(lane.config) },
    { lane_id: 'bad', config: '{not json' }]);
  assert.equal(envs.get(GOAD_KEY).label, 'GOAD Active Directory');
  assert.equal(h.state.queries.length, 1);
});
