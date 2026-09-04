/**
 * goad-extensions.test.js — the optional machines an environment can add to a
 * GOAD lab, and the three ways adding one can silently break a lane.
 *
 * WHAT THIS FILE IS DEFENDING
 *
 *  1. `.50` IS KALI. GOAD's own extensions/elk/inventory pins elk at
 *     {{ip_range}}.50, and INFRA_IP_OCTETS.Kali is 50. On v3 those sat on
 *     different segments; on v1/v2 there is ONE flat subnet and they are the
 *     same address. Two dhcp-host lines claiming one address make dnsmasq
 *     refuse to start, which takes DHCP down for the WHOLE lane. So the catalog
 *     moves elk to .24 and a load-time guard refuses any extension on an infra
 *     octet.
 *
 *  2. THE SHAPE MISMATCH. The create form's buildGoadVmRows emits
 *     `services`/`default_scripts` as comma STRINGS; the canvas needs ARRAYS —
 *     topology-seed.js's own docstring calls this out. The extension row
 *     builder's consumer is the Designer canvas, so it must emit arrays or the
 *     property panel .join()s a string into garbage.
 *
 *  3. THE KALI PATTERN. onTopoGoadVersionChange() rebuilds the machine list
 *     WHOLESALE via fromGoadLab — correct for a lab change, catastrophic for an
 *     extension tick, which would discard the canvas layout and every
 *     hand-added machine. onTopoGoadKaliToggle() is deliberately surgical, and
 *     onTopoExtensionToggle must be too. Pinned here by identity, not by count:
 *     the editor closes over the ARRAY, so replacing it orphans the canvas even
 *     when the contents look right.
 *
 *  4. THE ROSTER RUNS BOTH WAYS. assertGoadRoster throws when spec.vms and the
 *     lab roster disagree in EITHER direction, so ws01 may only enter the
 *     roster when the spec actually selected it — widening the roster for
 *     existing specs would fail every GOAD lane in flight.
 *
 * Run: node front-end/test/goad-extensions.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const goad = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));
const {
  GOAD_EXTENSIONS, GOAD_LABS, INFRA_IP_OCTETS, ROLE_RESOURCES,
  getExtension, extensionsForLab, resolveGoadExtensions, resolveGoadLab, prepareGoadMacs,
} = goad;

// ── 1. catalog shape ────────────────────────────────────────────────────────

test('every extension declares the fields the placement paths read', () => {
  const keys = Object.keys(GOAD_EXTENSIONS);
  assert.deepStrictEqual(keys.sort(), ['elk', 'lx01', 'wazuh', 'ws01']);

  for (const [key, ext] of Object.entries(GOAD_EXTENSIONS)) {
    assert.strictEqual(ext.key, key, `${key}: key must match its table slot — getExtension() looks up by it`);
    assert.ok(ext.machine && typeof ext.machine === 'string', `${key}: needs a machine name`);
    assert.ok(Number.isInteger(ext.ipOctet) && ext.ipOctet >= 2 && ext.ipOctet <= 254,
      `${key}: ipOctet must be 2..254 — it is both the last octet and the last byte of the MAC`);
    assert.ok(Array.isArray(ext.instruments), `${key}: instruments drives the siem-blind-host finding`);
    assert.strictEqual(typeof ext.inLab, 'boolean', `${key}: inLab decides whether it joins the AD roster`);
    assert.ok(ext.compatibility === null || Array.isArray(ext.compatibility),
      `${key}: compatibility is null (every lab) or a list`);
  }
});

test('the four entries carry the placement the plan specifies', () => {
  assert.strictEqual(GOAD_EXTENSIONS.elk.ipOctet, 24);
  assert.strictEqual(GOAD_EXTENSIONS.elk.role, 'siem');
  assert.deepStrictEqual(GOAD_EXTENSIONS.elk.instruments, ['domain']);

  assert.strictEqual(GOAD_EXTENSIONS.wazuh.ipOctet, 51);
  assert.strictEqual(GOAD_EXTENSIONS.wazuh.role, 'siem');
  // The whole reason wazuh is an alternative rather than a duplicate: it is the
  // only one of the two that covers Linux.
  assert.deepStrictEqual(GOAD_EXTENSIONS.wazuh.instruments, ['domain', 'linux_domain']);

  assert.strictEqual(GOAD_EXTENSIONS.ws01.ipOctet, 31);
  assert.strictEqual(GOAD_EXTENSIONS.ws01.role, 'workstation');
  // 1006, not 1002: the Windows 11 template on this cluster. bake-win-client-template.sh
  // still defaults FINAL_VMID to 1002 and that default has drifted — the cluster wins.
  assert.strictEqual(GOAD_EXTENSIONS.ws01.template_vmid, 1006);

  assert.strictEqual(GOAD_EXTENSIONS.lx01.ipOctet, 32);
  assert.strictEqual(GOAD_EXTENSIONS.lx01.role, 'linux');
  assert.deepStrictEqual(GOAD_EXTENSIONS.lx01.instruments, ['linux_domain']);
});

test('getExtension is the catalog reader and is case-insensitive', () => {
  assert.strictEqual(getExtension('ELK'), GOAD_EXTENSIONS.elk);
  assert.strictEqual(getExtension('nope'), null);
  assert.strictEqual(getExtension(undefined), null);
});

// ── 2. ELK NEVER lands on .50 ───────────────────────────────────────────────

test('THE COLLISION: no extension sits on an infra octet, and elk specifically is not .50', () => {
  assert.strictEqual(INFRA_IP_OCTETS.Kali, 50,
    'if Kali ever moves, the reason elk is at .24 changes and this file needs rereading');
  assert.notStrictEqual(GOAD_EXTENSIONS.elk.ipOctet, INFRA_IP_OCTETS.Kali,
    'upstream pins elk at .50, which is Kali. On a flat v1/v2 lane that is one address, and dnsmasq '
    + 'refuses to start on a duplicate dhcp-host — DHCP down for every machine in the lane.');
  for (const [key, ext] of Object.entries(GOAD_EXTENSIONS)) {
    for (const [infra, octet] of Object.entries(INFRA_IP_OCTETS)) {
      assert.notStrictEqual(ext.ipOctet, octet, `${key} collides with the lane ${infra} at .${octet}`);
    }
  }
});

test('two extensions never share an octet either', () => {
  const seen = new Map();
  for (const ext of Object.values(GOAD_EXTENSIONS)) {
    assert.ok(!seen.has(ext.ipOctet),
      `${ext.key} reuses .${ext.ipOctet}, already ${seen.get(ext.ipOctet)} — ticking both is a dnsmasq refusal`);
    seen.set(ext.ipOctet, ext.key);
  }
});

// ── 3. compatibility filtering ──────────────────────────────────────────────

const okKeys = (labName) => extensionsForLab(labName).filter(e => e.ok).map(e => e.key).sort();

test('ws01 is offered on GOAD / GOAD-Light / GOAD-Mini and refused elsewhere', () => {
  for (const lab of ['GOAD', 'GOAD-Light', 'GOAD-Mini']) {
    assert.ok(okKeys(lab).includes('ws01'), `${lab} should offer ws01`);
  }
  for (const lab of ['NHA', 'SCCM', 'DRACARYS']) {
    assert.ok(!okKeys(lab).includes('ws01'), `${lab} must not offer ws01 — upstream ships no inventory for it`);
  }
});

test('a refusal carries the reason, because the UI shows it disabled rather than hiding it', () => {
  const row = extensionsForLab('NHA').find(e => e.key === 'ws01');
  assert.strictEqual(row.ok, false);
  assert.match(row.reason, /compatible with GOAD, GOAD-Light, GOAD-Mini only/);
});

test('SCCM refuses ws01 for the compatibility reason it declares, and it also already ships one', () => {
  // Both are true and the compatibility check runs first. What matters is that
  // the machine is refused: SCCM's own WS01 is at .43, and a second WS01 would
  // shadow it — assertValidLabDef's own duplicate-name rule, one level up.
  assert.ok(GOAD_LABS.SCCM.vms.some(v => v.name.toLowerCase() === 'ws01'));
  assert.ok(!okKeys('SCCM').includes('ws01'));
});

test('DRACARYS refuses lx01 on a NAME collision, not a compatibility one', () => {
  // lx01's compatibility is null (every lab), so the only thing standing
  // between DRACARYS and two machines called LX01 is the name check.
  assert.strictEqual(GOAD_EXTENSIONS.lx01.compatibility, null);
  const row = extensionsForLab('DRACARYS').find(e => e.key === 'lx01');
  assert.strictEqual(row.ok, false);
  assert.match(row.reason, /already ships a host named lx01/i);
});

test('the SIEMs are offered on every lab', () => {
  for (const lab of Object.keys(GOAD_LABS)) {
    const ok = okKeys(lab);
    assert.ok(ok.includes('elk'), `${lab} should offer elk`);
    assert.ok(ok.includes('wazuh'), `${lab} should offer wazuh`);
  }
});

// ── 4. selection → roster ───────────────────────────────────────────────────

test('a spec with no extensions resolves the lab table UNCHANGED, by identity', () => {
  // The back-compat guarantee. assertGoadRoster checks BOTH directions, so an
  // extra roster entry that spec.vms does not carry is a hard deploy failure —
  // quietly widening the roster would break every GOAD lane in flight.
  const { labDef } = resolveGoadLab({ goad: { enabled: true, version: 'GOAD-Light' } });
  assert.strictEqual(labDef, GOAD_LABS['GOAD-Light'],
    'no extensions must mean the SAME object, not an equal copy');
});

test('ws01 joins the roster only when the spec selects it', () => {
  const withExt = resolveGoadLab({
    goad: { enabled: true, version: 'GOAD-Light', extensions: ['ws01'] },
  });
  assert.deepStrictEqual(withExt.labDef.vms.map(v => v.name), ['DC01', 'DC02', 'SRV02', 'ws01']);
  // ...and the source table is not mutated in the process.
  assert.deepStrictEqual(GOAD_LABS['GOAD-Light'].vms.map(v => v.name), ['DC01', 'DC02', 'SRV02']);
});

test('a roster ws01 carries everything prepareGoadMacs needs from a lab row', () => {
  const { labDef } = resolveGoadLab({
    goad: { enabled: true, version: 'GOAD-Mini', extensions: ['ws01'] },
  });
  const ws = labDef.vms.find(v => v.name === 'ws01');
  assert.strictEqual(ws.ipOctet, 31);
  assert.strictEqual(ws.role, 'workstation');
  assert.ok(ROLE_RESOURCES[ws.role],
    'role must be one of ROLE_RESOURCES or assertValidLabDef rejects a spec-supplied copy of this roster');
  assert.strictEqual(ws.template_vmid, 1006);
  assert.ok(ws.nic_model, 'a Windows guest on virtio has no driver and never DHCPs');
});

test('the SIEMs stay OUT of the roster — that absence is what earns them a host-record', () => {
  // resolveSpecAddressing skips a machine only when goadMacs[name] exists, and
  // that function is the only source of the elk.cybercore.lan record.
  const r = resolveGoadLab({
    goad: { enabled: true, version: 'GOAD-Light', extensions: ['elk', 'wazuh', 'lx01'] },
  });
  assert.deepStrictEqual(r.labDef.vms.map(v => v.name), ['DC01', 'DC02', 'SRV02']);
  assert.deepStrictEqual([...r.extensions.external].sort(), ['elk', 'lx01', 'wazuh']);
});

test('an incompatible or unknown key is dropped, never thrown on', () => {
  // `extensions` is authored against a catalog that can move under an existing
  // challenge row; a spec saved last term must still deploy.
  const r = resolveGoadExtensions(['ws01', 'nonesuch', 'ELK', 'elk'], 'NHA', GOAD_LABS.NHA);
  assert.deepStrictEqual(r.selected, ['elk'], 'ws01 is incompatible with NHA; nonesuch does not exist');
  assert.deepStrictEqual(r.inLab, []);
});

test('an external extension machine is not a stray, so the roster check lets it through', () => {
  // Without the exemption this throws: isGoadManagedVm only exempts
  // EXTERNAL_ROLES, explicit nics[] and containers, and role 'linux'/'siem' are
  // neither.
  const spec = {
    goad: { enabled: true, version: 'GOAD-Mini', extensions: ['elk', 'ws01'] },
    vms: [
      { name: 'DC01', template_vmid: 1004, type: 'qemu', role: 'dc' },
      { name: 'ws01', template_vmid: 1006, type: 'qemu', role: 'workstation' },
      { name: 'elk', template_vmid: 9001, type: 'qemu', role: 'siem', ipOctet: 24 },
    ],
  };
  const macs = prepareGoadMacs(spec, 4242, '10.9.9');
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC01', 'ws01'],
    'the SIEM must NOT appear in goadMacs, or resolveSpecAddressing skips it and it loses its DNS record');
  assert.strictEqual(macs.ws01.static_ip, '10.9.9.31');
});

test('an elk machine on a spec that never selected the extension is still a stray', () => {
  // The exemption is per-spec on purpose. Exempting role 'siem' wholesale would
  // punch a permanent hole in the roster check.
  assert.throws(() => prepareGoadMacs({
    goad: { enabled: true, version: 'GOAD-Mini' },
    vms: [
      { name: 'DC01', template_vmid: 1004, type: 'qemu', role: 'dc' },
      { name: 'elk', template_vmid: 9001, type: 'qemu', role: 'siem' },
    ],
  }, 1, '10.0.0'), /roster mismatch/);
});

// ── 5. the prebaked secure-channel heal ─────────────────────────────────────

test('THE BUG: the prebaked heal covers workstation as well as member', () => {
  // deployPrebakedGoadLane split tagged machines into role==='dc' and
  // role==='member'. A 'workstation' fell into NEITHER, so it got no
  // secure-channel repair — and a domain-joined Windows clone needs exactly
  // that after a golden-image clone resets its machine identity. It boots, it
  // looks fine, and it cannot authenticate to the domain.
  //
  // Source-text rather than behavioural: the real function sleeps 90s + 45s and
  // needs a Proxmox guest agent, so a runtime test here would be a five-minute
  // no-op. What is asserted is the exact expression that decides the set.
  const src = fs.readFileSync(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'), 'utf8');
  assert.match(src, /const HEAL_ROLES = \['member', 'workstation'\];/,
    'the heal role set must still include workstation');
  assert.match(src, /const members = tagged\.filter\(v => HEAL_ROLES\.includes\(v\.labVm\.role\)\);/,
    'and the filter must still read it — an inlined role===\'member\' is the bug coming back');
  assert.ok(!/tagged\.filter\(v => v\.labVm\.role === 'member'\)/.test(src),
    'the narrow filter must be gone, not merely shadowed');
});

// ── 6. the API surface the Designer fetches ─────────────────────────────────

test('GET /goad/extensions exists beside /goad/labs and serves the catalog', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8');
  assert.match(src, /router\.get\('\/goad\/extensions', authenticateToken, adminOnly/,
    'the catalog endpoint must be admin-only, like /goad/labs');
  assert.match(src, /goadDeploy\.GOAD_EXTENSIONS/, 'and must serve the const, not a second copy of it');
  assert.match(src, /goadDeploy\.extensionsForLab\(key, lab\)/,
    'per-lab compatibility is computed server-side so there is one implementation of that rule');
});

test('the create handler stores goad.extensions through the same filter', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8');
  assert.match(src, /goadDeploy\.resolveGoadExtensions\(/,
    'an incompatible key must not reach the spec — ws01 on NHA would make assertGoadRoster fail every deploy');
  assert.match(src, /if \(resolved\.selected\.length\) spec\.goad\.extensions = resolved\.selected;/,
    'and a spec with no surviving extensions must stay byte-identical to one written before this existed');
});

// ── 7. the browser row builder ──────────────────────────────────────────────

function loadClient() {
  const sandbox = { console };
  sandbox.window = sandbox;
  sandbox.api = async () => ({ extensions: [] });
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'admin', 'goad-extensions.js'), 'utf8'),
    sandbox, { filename: 'goad-extensions.js' });
  return sandbox;
}

/** The catalog shape GET /goad/extensions actually returns, for one key. */
function apiShape(key) {
  const ext = GOAD_EXTENSIONS[key];
  return {
    key: ext.key, displayName: ext.displayName, description: ext.description,
    machine: ext.machine, role: ext.role, os: ext.os, template_vmid: ext.template_vmid,
    nic_model: ext.nic_model, ip_octet: ext.ipOctet, instruments: ext.instruments,
    dns_aliases: ext.dns_aliases || [], compatibility: ext.compatibility,
    in_lab: !!ext.inLab, headless: !!ext.headless,
  };
}

test('THE SHAPE TRAP: an extension row emits ARRAY services/default_scripts', () => {
  const s = loadClient();
  const row = s.buildGoadExtensionRow(apiShape('elk'), 620000);
  assert.ok(Array.isArray(row.services),
    'the create form emits comma STRINGS; the canvas property panel .join()s, so a string becomes "8,0,/,H"');
  assert.ok(Array.isArray(row.default_scripts));
  // JSON, not deepStrictEqual: these arrays were built inside the vm context and
  // carry ITS Array.prototype, which deepStrictEqual treats as a different type.
  assert.strictEqual(JSON.stringify(row.services), '[]');
  assert.strictEqual(JSON.stringify(row.default_scripts), '[]');
});

test('an external extension row carries its pinned octet; an in-lab one does not', () => {
  const s = loadClient();
  const elk = s.buildGoadExtensionRow(apiShape('elk'), 620000);
  assert.strictEqual(elk.ipOctet, 24, 'elk is an ordinary pinnable spec VM — the octet is how it is placed');
  assert.deepStrictEqual(elk.dns_aliases, ['elk']);

  const ws01 = s.buildGoadExtensionRow(apiShape('ws01'), 630000);
  assert.strictEqual(ws01.ipOctet, undefined,
    'ws01 is addressed by the GOAD layer from the lab roster; an ipOctet here would be dead data that '
    + 'reads as authoritative');
  assert.strictEqual(ws01.template_vmid, 1006);
});

test('the row is a canvas row: name, role, type and a vm_offset the caller chose', () => {
  const s = loadClient();
  const row = s.buildGoadExtensionRow(apiShape('wazuh'), 640000);
  assert.strictEqual(row.name, 'wazuh');
  assert.strictEqual(row.role, 'siem');
  assert.strictEqual(row.type, 'qemu');
  assert.strictEqual(row.vm_offset, 640000);
  assert.strictEqual(row.template_vmid, 1011,
    'the generic Ubuntu 22.04 base. It was null while the SIEMs were meant to be per-site golden images, '
    + 'which is exactly what produced the Designer error "has no template VMID, so there is nothing to '
    + 'clone" and made the extension unusable. The stack is installed in-lane by GOAD\'s own Ansible now, '
    + 'so one plain image serves every site');
});

test('goadExtensionsForLab honours the ok/reason the server computed', () => {
  const s = loadClient();
  s.__setCatalog = null;
  vm.runInContext('_goadExtCatalog = { extensions: __cat };',
    Object.assign(s, { __cat: ['elk', 'ws01'].map(apiShape) }));
  const rows = s.goadExtensionsForLab({
    key: 'NHA',
    extensions: [{ key: 'elk', ok: true, reason: null },
      { key: 'ws01', ok: false, reason: 'nope' }],
  });
  assert.deepStrictEqual(rows.map(r => [r.key, r.ok]), [['elk', true], ['ws01', false]]);
  assert.strictEqual(rows[1].reason, 'nope');
});

test('a lab row from an older server (no extensions key) degrades to "all offerable"', () => {
  const s = loadClient();
  vm.runInContext('_goadExtCatalog = { extensions: __cat };',
    Object.assign(s, { __cat: ['elk', 'ws01'].map(apiShape) }));
  const rows = s.goadExtensionsForLab({ key: 'GOAD-Light' });
  assert.deepStrictEqual(rows.map(r => r.ok), [true, true],
    'never worse than hiding a machine with no explanation');
});

// ── 8. THE KALI-PATTERN GUARANTEE ───────────────────────────────────────────

/**
 * A headless harness for admin-topology.js.
 *
 * The file is a classic script full of top-level `let`s and DOM calls, but
 * nothing runs at load — every getElementById is inside a function. So the two
 * scripts are run in one context and the toggle is driven through stub elements.
 * Top-level `let`/`const` in a vm script live in the context's LEXICAL global,
 * which is not a property of the sandbox object — hence the `__probe` dance.
 */
function loadDesigner() {
  const els = {
    topoGoadEnabled: { checked: true },
    topoGoadVersion: { value: 'GOAD-Light' },
    topoDesignVmList: null,   // renderTopoVmTable early-returns, which is fine here
  };
  const checked = new Set();

  const sandbox = {
    console,
    escHtml: (v) => String(v == null ? '' : v),
    difficultyLabel: (v) => String(v),
    api: async () => ({}),
    Toast: { info() {}, warning() {}, error() {}, success() {} },
    findGoadLab: (key) => ({ key, vms: (GOAD_LABS[key] || { vms: [] }).vms }),
    loadGoadCatalog: async () => ({ labs: [] }),
    document: {
      getElementById: (id) => (id in els ? els[id] : null),
      querySelector: (sel) => {
        const m = sel.match(/data-ext="([^"]+)"/);
        return (m && checked.has(m[1])) ? { checked: true } : null;
      },
      querySelectorAll: (sel) => {
        if (!/data-ext\]:checked/.test(sel)) return [];
        return [...checked].map((k) => ({ getAttribute: () => k }));
      },
      createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }),
      body: { appendChild() {}, removeChild() {}, contains: () => false },
      addEventListener() {}, removeEventListener() {},
    },
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  for (const f of ['public/js/admin/goad-extensions.js', 'public/js/admin/admin-topology.js']) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), sandbox, { filename: f });
  }
  vm.runInContext(`_goadExtCatalog = { extensions: ${JSON.stringify(
    Object.keys(GOAD_EXTENSIONS).map(apiShape))} };`, sandbox);
  return { sandbox, checked };
}

test('THE KALI-PATTERN GUARANTEE: ticking an extension does not reset the machine list', () => {
  const { sandbox, checked } = loadDesigner();

  // Seed the canvas with a lab host AND a hand-added machine carrying a layout —
  // exactly what a wholesale fromGoadLab rebuild would throw away.
  vm.runInContext(`
    topoVms.length = 0;
    topoVms.push(
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, type: 'qemu',
        vm_offset: 600000, services: [], default_scripts: [], layout: { x: 10, y: 20 } },
      { name: 'jump', role: '', os: 'Debian', template_vmid: 1500, type: 'qemu',
        vm_offset: 610000, services: ['22/SSH'], default_scripts: ['seed-me'], layout: { x: 99, y: 99 } }
    );
    __arrayBefore = topoVms;
    __rowsBefore = topoVms.slice();
  `, sandbox);

  checked.add('elk');
  vm.runInContext('onTopoExtensionToggle("elk");', sandbox);

  vm.runInContext(`
    __arraySame = (__arrayBefore === topoVms);
    __rowsSame = __rowsBefore.every(function (r, i) { return topoVms[i] === r; });
    __names = JSON.stringify(topoVms.map(function (v) { return v.name; }));
    __jumpLayout = JSON.stringify(topoVms[1].layout);
    __jumpScripts = JSON.stringify(topoVms[1].default_scripts);
  `, sandbox);

  assert.strictEqual(sandbox.__arraySame, true,
    'the editor CLOSES OVER this array. Replacing it orphans the canvas even when the contents look right — '
    + 'that is why onTopoGoadKaliToggle pushes and splices rather than filtering.');
  assert.strictEqual(sandbox.__rowsSame, true,
    'every pre-existing row must be the SAME OBJECT: the editor writes nics[] and layout onto these rows');
  assert.strictEqual(sandbox.__names, '["DC01","jump","elk"]');
  assert.strictEqual(sandbox.__jumpLayout, '{"x":99,"y":99}', 'a hand-placed machine keeps its position');
  assert.strictEqual(sandbox.__jumpScripts, '["seed-me"]');
});

test('unticking removes exactly that machine, by splice', () => {
  const { sandbox, checked } = loadDesigner();
  vm.runInContext(`
    topoVms.length = 0;
    topoVms.push({ name: 'DC01', role: 'dc', vm_offset: 600000, services: [], default_scripts: [] });
    __arrayBefore = topoVms;
  `, sandbox);

  checked.add('elk');
  vm.runInContext('onTopoExtensionToggle("elk");', sandbox);
  checked.delete('elk');
  vm.runInContext('onTopoExtensionToggle("elk"); __names = JSON.stringify(topoVms.map(function (v) { return v.name; })); __arraySame = (__arrayBefore === topoVms);', sandbox);

  assert.strictEqual(sandbox.__names, '["DC01"]');
  assert.strictEqual(sandbox.__arraySame, true, 'splice, not filter — filter would orphan the editor handle');
});

test('a tick claims a free vm_offset rather than colliding with a placed machine', () => {
  const { sandbox, checked } = loadDesigner();
  vm.runInContext(`
    topoVms.length = 0;
    topoVms.push(
      { name: 'a', vm_offset: 600000, services: [], default_scripts: [] },
      { name: 'b', vm_offset: 610000, services: [], default_scripts: [] }
    );
  `, sandbox);
  checked.add('wazuh');
  vm.runInContext('onTopoExtensionToggle("wazuh"); __offsets = JSON.stringify(topoVms.map(function (v) { return v.vm_offset; }));', sandbox);
  assert.strictEqual(sandbox.__offsets, '[600000,610000,620000]',
    'two VMs on one offset clone to the same VMID and the second deploy fails');
});

test('ticking ws01 never claims the student console — a roster machine cannot be one', () => {
  // REGRESSION, from a lane that deployed with DC01, elk and ws01 all Running
  // and nothing a student could reach. This toggle used to set
  // console_role: 'primary' on ws01 whenever nothing else claimed it, on the
  // reasoning that a domain-joined Windows analyst box is the natural
  // blue-team console. It is — but the deploy path cannot build one:
  //
  //   - resolveConsolePlan tags it kind 'spec', and challenge-lane-deployer
  //     resolves real credentials only for kind 'kali' and kind 'extra', so the
  //     Guacamole connection is created with username and password null.
  //   - in_lab machines carry no ipOctet (GOAD addresses them), so the console
  //     allocator draws one from the .60-.79 band while cloneChallengeVm lets
  //     the GOAD MAC win and the machine boots at its lab octet. The DNAT and
  //     the connection point at an address nothing answers.
  //
  // And it outranked Kali silently: resolveConsolePlan tests
  // `specPrimaries.length === 1` BEFORE it tests attackBoxes, so ticking ws01
  // took the console away from a Kali box that would have worked.
  const { sandbox, checked } = loadDesigner();
  vm.runInContext(`
    topoVms.length = 0;
    topoVms.push({ name: 'DC01', role: 'dc', vm_offset: 600000, services: [], default_scripts: [] });
  `, sandbox);
  checked.add('ws01');
  vm.runInContext('onTopoExtensionToggle("ws01"); __role = topoVms[1].console_role;', sandbox);
  assert.strictEqual(sandbox.__role, undefined,
    'ws01 is a TARGET that makes an intrusion cross hosts, instrumented for free by '
    + '[elk_log:children] domain. The console belongs to Kali or an added workstation.');

  // Unchanged and still load-bearing: an explicit choice elsewhere is never
  // touched by a checkbox.
  const second = loadDesigner();
  vm.runInContext(`
    topoVms.length = 0;
    topoVms.push({ name: 'Kali', role: 'attacker', vm_offset: 600000, console_role: 'primary',
                   services: [], default_scripts: [] });
  `, second.sandbox);
  second.checked.add('ws01');
  vm.runInContext('onTopoExtensionToggle("ws01"); __kali = topoVms[0].console_role; __ws = topoVms[1].console_role;',
    second.sandbox);
  assert.strictEqual(second.sandbox.__kali, 'primary', 'an author\'s explicit choice is never overwritten');
  assert.strictEqual(second.sandbox.__ws, undefined);
});

test('the extension machine names are name-locked, exactly like the lab hosts', () => {
  const { sandbox, checked } = loadDesigner();
  checked.add('elk');
  checked.add('ws01');
  vm.runInContext('__locked = JSON.stringify(topoGoadHostNames());', sandbox);
  assert.strictEqual(sandbox.__locked, '["DC01","DC02","SRV02","elk","ws01"]',
    'the names are a contract with the golden images and the baked agent configs, not labels');
});

// ════════════════════════════════════════════════════════════════════════════
// 6. THE INSTALL PATH
// ════════════════════════════════════════════════════════════════════════════
//
// Everything above is about PLACING an extension machine. This section is about
// the other half — whether anything is ever installed on it.
//
// Upstream installs an extension with `install_extension <key>`, which is
// nothing more than inventory layering plus one playbook run
// (GOAD-main/goad/provisioner/ansible/ansible.py:76 run_extension). CyberCore
// does the same in-lane: runGoadPlaybook hands the resolved keys to
// /opt/goad-light/run.sh as an OPTIONAL 5th argument, and run.sh renders that
// extension's inventory, layers it on the lab's, and runs
// extensions/<key>/ansible/install.yml.
//
// Two things have to hold for that to be safe, and both are pinned below:
//   · a lane that selected nothing must send the command line it has always
//     sent, because the controller is a BAKED TEMPLATE and every lane in flight
//     is running the run.sh it was baked with;
//   · a PRE-BAKED lane must never accept an extension at all — it runs no
//     Ansible, so the machine would be placed and nothing installed on it.

test('every extension names a template VMID — a null is the Designer error, not a placeholder', () => {
  for (const [key, ext] of Object.entries(GOAD_EXTENSIONS)) {
    assert.ok(Number.isInteger(ext.template_vmid) && ext.template_vmid > 0,
      key + '.template_vmid is ' + JSON.stringify(ext.template_vmid) + '. A null here is not "unset, fill '
      + 'it in later" — it is the literal cause of validateTopology\'s "has no template VMID, so there is '
      + 'nothing to clone", which is what made elk and wazuh impossible to tick.');
  }
  // The two SIEMs share ONE image on purpose. It is a PLAIN Ubuntu 22.04 base
  // with no stack on it; extensions/<key>/ansible builds Elasticsearch or the
  // Wazuh manager on it in the lane. That replaced a design in which each site
  // baked and registered its own golden SIEM image.
  assert.strictEqual(GOAD_EXTENSIONS.elk.template_vmid, 1011);
  assert.strictEqual(GOAD_EXTENSIONS.wazuh.template_vmid, 1011,
    'wazuh clones the same generic base as elk — nothing about the image is wazuh-specific');
});

test('both Windows 11 rows in this module name the same template', () => {
  // The bug this pins: GOAD_EXTENSIONS.ws01 and GOAD_LABS.SCCM's WS01 are both
  // 'Windows 11' and both carried 1002 — the bake script's FINAL_VMID default,
  // which has drifted from the cluster (1006). Two sites, one stale number, and
  // a wrong template_vmid clones silently rather than failing.
  const sccmWs = GOAD_LABS.SCCM.vms.find(v => v.name.toLowerCase() === 'ws01');
  assert.strictEqual(sccmWs.os, 'Windows 11');
  assert.strictEqual(sccmWs.template_vmid, 1006);
  assert.strictEqual(GOAD_EXTENSIONS.ws01.template_vmid, sccmWs.template_vmid,
    'the ws01 extension and SCCM\'s own WS01 are the same operating system, so they must be the same image');
});

// ── the run.sh command line ─────────────────────────────────────────────────
//
// HOW THIS IS CAPTURED WITHOUT A CLUSTER OR A 15-SECOND WAIT. runGoadPlaybook
// makes three guest-exec calls: two best-effort mssql pre-patches, each wrapped
// in a try/catch that only console.warns, and then the run.sh launch, which is
// NOT wrapped. A fake proxmoxAPI that refuses the patches never reaches
// pollExecStatus (which uses script-executor's OWN proxmoxAPI, not the injected
// one, and would poll a host that does not exist); throwing a sentinel on the
// run.sh exec captures the command and unwinds the function before its
// 15-second sentinel poll ever starts.

const RUNSH_VMS = [
  { name: 'DC01',  template_vmid: 1004, type: 'qemu', role: 'dc' },
  { name: 'DC02',  template_vmid: 1004, type: 'qemu', role: 'dc' },
  { name: 'SRV02', template_vmid: 1004, type: 'qemu', role: 'member' },
];
const runShSpec = (goadExtra = {}) => ({
  goad: { enabled: true, version: 'GOAD-Light', ...goadExtra },
  vms: RUNSH_VMS.map(v => ({ ...v })),
});

// `capable` models the controller's extension capability marker
// (/opt/goad-light/.cc-extension-install). Default true, because that is the
// controller a current bake produces; pass false to model a lane cloned from a
// template baked before extension support existed.
async function captureRunSh(spec, { capable = true } = {}) {
  let captured = null;
  const realWarn = console.warn;
  console.warn = () => {};
  let probePid = 0;
  const probeAnswers = new Map();
  const proxmoxAPI = async (method, url, body) => {
    // The capability probe polls exec-status with the INJECTED client, so the
    // harness has to answer that too. If this ever starts throwing "unexpected
    // call", the probe has been changed to bypass the injection seam again.
    if (method === 'GET' && /\/agent\/exec-status\?pid=(\d+)$/.test(url)) {
      const pid = Number(url.match(/pid=(\d+)$/)[1]);
      return { exited: 1, exitcode: 0, 'out-data': probeAnswers.get(pid) ?? '' };
    }
    if (method !== 'POST' || !/\/agent\/exec$/.test(url)) {
      throw new Error('unexpected call: ' + method + ' ' + url);
    }
    const argv = String(body).split('&').map(p => decodeURIComponent(p.replace(/^command=/, '')));
    const last = argv[argv.length - 1];
    if (last.includes('.cc-extension-install')) {
      probeAnswers.set(++probePid, capable ? 'yes\n' : 'no\n');
      return { pid: probePid };
    }
    if (last.includes('/opt/goad-light/run.sh')) {
      captured = last;
      throw new Error('__CAPTURED__');
    }
    throw new Error('__PATCH_REFUSED__');   // best-effort mssql patches; only warn
  };
  try {
    await goad.runGoadPlaybook({
      controllerVmId: 999, bestNode: 'pve1', spec, vxlanId: 4242,
      laneSubnetBase: '10.9.9', extSubnetBase: '10.9.9', proxmoxAPI,
    });
    throw new Error('runGoadPlaybook finished without ever launching run.sh');
  } catch (err) {
    if (err.message !== '__CAPTURED__') throw err;
  } finally {
    console.warn = realWarn;
  }
  return captured;
}

test('THE 5TH ARGUMENT: the selected extension keys reach run.sh, comma-joined and quoted', async () => {
  const cmd = await captureRunSh(runShSpec({ extensions: ['elk', 'wazuh'] }));
  assert.match(cmd,
    /\/opt\/goad-light\/run\.sh 'GOAD-Light' '[^']*' 'vagrant' 'vagrant' 'elk,wazuh' > \/var\/log\/goad-run-4242\.log/,
    'the keys must arrive as one quoted 5th argument, after the four that were always there:\n' + cmd);
});

// ── the capability gate ─────────────────────────────────────────────────────
//
// THE ONLY SILENT FAILURE IN THIS FEATURE, and it needs no bug — only someone
// forgetting to re-bake the controller template. An older run.sh binds $1..$4
// and never reads $5, so the extensions argument is inert: the forest builds,
// run.sh exits 0, the lane reports active, and there is no SIEM anywhere. Every
// other failure here is loud. This one hands a student an empty Kibana.

test('a controller with no capability marker REFUSES rather than deploying green', async () => {
  await assert.rejects(
    () => captureRunSh(runShSpec({ extensions: ['elk'] }), { capable: false }),
    (err) => {
      assert.ok(!/__CAPTURED__/.test(err.message),
        'run.sh must NOT be launched when the controller cannot install extensions');
      assert.match(err.message, /\.cc-extension-install/);
      assert.match(err.message, /re-bake/i);
      assert.match(err.message, /1700/, 'the refusal must name the template to re-bake');
      return true;
    });
});

test('the capability probe does not run when no extension is selected', async () => {
  // A lane that ticks nothing must not gain a new way to fail. Modelled by
  // asserting the four-argument command still gets through with capable:false —
  // if the probe ran unconditionally, this would refuse.
  const cmd = await captureRunSh(runShSpec(), { capable: false });
  assert.match(cmd, /run\.sh 'GOAD-Light' '[^']*' 'vagrant' 'vagrant' >/);
});

test('the order the spec ticked them in is the order run.sh installs them in', async () => {
  const cmd = await captureRunSh(runShSpec({ extensions: ['wazuh', 'elk'] }));
  assert.ok(cmd.includes("'wazuh,elk'"),
    'extension order is install order, so it must survive the trip: ' + cmd);
});

test('a key this lab cannot take never reaches the controller', async () => {
  // resolveGoadExtensions has already dropped it — unknown and incompatible keys
  // are dropped rather than thrown on, because a spec saved last term must still
  // deploy against a catalog that has moved. run.sh must never be handed a key
  // whose inventory would fight the lab's.
  const cmd = await captureRunSh(runShSpec({ extensions: ['elk', 'nonesuch'] }));
  assert.ok(cmd.includes("'elk'"), cmd);
  assert.ok(!cmd.includes('nonesuch'), 'an unknown key leaked through to run.sh: ' + cmd);
});

test('NO extensions means the command line every in-flight lane already runs', async () => {
  const absent  = await captureRunSh(runShSpec());                       // no key at all
  const empty   = await captureRunSh(runShSpec({ extensions: [] }));     // key, empty list
  const dropped = await captureRunSh(runShSpec({ extensions: ['nonesuch'] }));

  assert.strictEqual(absent, empty, 'an empty list must behave exactly like no list');
  assert.strictEqual(absent, dropped, 'a selection that resolves to nothing is a selection of nothing');

  // FOUR arguments, then the redirect. No trailing '', no trailing space.
  assert.match(absent,
    /\/opt\/goad-light\/run\.sh 'GOAD-Light' '[^']*' 'vagrant' 'vagrant' > \/var\/log\/goad-run-4242\.log 2>&1;/,
    'the four-argument form must be untouched:\n' + absent);
  assert.ok(!absent.includes("'vagrant' ''"),
    'the argument is OMITTED, not passed empty. The controller is a baked template and cannot be '
    + 'renegotiated: an empty 5th argument is still a 5th argument — $# becomes 5, and anything an older '
    + 'run.sh echoes from "$@" into the lane log changes with it. Omission makes "byte-identical to today" '
    + 'true by construction rather than by an assumption about a script on the other side of the boundary.');
});

// ── the prebaked fork ───────────────────────────────────────────────────────

const prebakedSpec = (extensions) => ({
  goad: {
    enabled: true, version: 'GOAD-Light', prebaked: true,
    fixed_subnet: { int: '10.9.9', ext: '10.9.9' },
    ...(extensions ? { extensions } : {}),
  },
  vms: RUNSH_VMS.map(v => ({ ...v })),
});

test('THE PREBAKED FORK: an extension on a pre-baked lane is refused before anything clones', () => {
  // A pre-baked lane runs NO Ansible: deployPrebakedGoadLane clones golden images
  // and heals secure channels, and challenge-lane-deployer's liveGoadController
  // is literally `enabled && !prebaked`, so run.sh never executes. elk would
  // be cloned, addressed, given a DNS record and a console, with no Elasticsearch
  // on it — and the lane would report ACTIVE.
  assert.throws(() => prepareGoadMacs(prebakedSpec(['elk']), 4242, '10.9.9'), (err) => {
    assert.match(err.message, /elk/, 'the message must name the extension');
    assert.match(err.message, /spec\.goad\.prebaked/, 'and the flag, spelled the way the spec spells it');
    assert.match(err.message, /run\.sh/, 'and say what it is that does not run');
    assert.match(err.message, /report active/i, 'and why it would otherwise pass unnoticed');
    return true;
  });
});

test('the refusal names every UNBAKED extension, not just the first', () => {
  assert.throws(() => prepareGoadMacs(prebakedSpec(['elk', 'wazuh']), 4242, '10.9.9'),
    /elk, wazuh/);
});

// -- the point of sealing: pre-baked + a sealed image is the STEADY STATE -----
//
// An earlier revision refused pre-baked + extensions outright. That was wrong,
// and wrong in the direction that blocks the intended workflow: install the
// extension once against a staging lab, seal the result into a golden template
// (seal-goad-elk-template.sh -> 1012, seal-goad-wazuh-template.sh -> 1013), then
// clone that forever. At that point nothing needs to install, because the image
// already carries the stack -- and pre-baked is the entire reason for sealing.
//
// So the rule is not "is this lane pre-baked" but "does this machine clone an
// image that has the stack on it". These pin both halves of that.

const sealedPrebakedSpec = (vmid) => ({
  goad: {
    enabled: true, version: 'GOAD-Light', prebaked: true,
    fixed_subnet: { int: '10.9.9', ext: '10.9.9' },
    extensions: ['elk'],
  },
  vms: [...RUNSH_VMS.map(v => ({ ...v })),
        { name: 'elk', role: 'siem', template_vmid: vmid, ipOctet: 24 }],
});

test('pre-baked + a SEALED elk template is allowed -- that is what sealing is for', () => {
  assert.doesNotThrow(() => prepareGoadMacs(sealedPrebakedSpec(1012), 4242, '10.9.9'));
});

test('pre-baked + the PLAIN Ubuntu base is still refused, and says which image', () => {
  assert.throws(() => prepareGoadMacs(sealedPrebakedSpec(goad.PLAIN_BASE_TEMPLATE_VMID), 4242, '10.9.9'),
    (err) => {
      assert.match(err.message, /generic Ubuntu base/,
        'it must say WHICH image is the problem, not just that one is');
      assert.match(err.message, /seal/i, 'and point at the remedy that keeps pre-baked');
      return true;
    });
});

test('the plain base is a NAMED constant, so the two enforcers cannot drift apart', () => {
  // goad-deploy enforces at deploy time and topology-validate at author time.
  // A second literal 1011 in either would be a rule that silently disagrees with
  // itself the day the base image is re-numbered.
  assert.strictEqual(goad.PLAIN_BASE_TEMPLATE_VMID, 1011);
  assert.strictEqual(GOAD_EXTENSIONS.elk.template_vmid, goad.PLAIN_BASE_TEMPLATE_VMID);
  assert.strictEqual(GOAD_EXTENSIONS.wazuh.template_vmid, goad.PLAIN_BASE_TEMPLATE_VMID);
});

test('a pre-baked lane with NO extensions is completely untouched', () => {
  // The prebaked path predates extensions and must keep working exactly as it
  // did — this guard may only ever fire on the pair.
  const macs = prepareGoadMacs(prebakedSpec(null), 4242, '10.9.9');
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC01', 'DC02', 'SRV02']);
  assert.strictEqual(macs.DC01.static_ip, '10.9.9.10');
});

test('a LIVE lane with the same extensions is fine — live is the mode that installs', () => {
  const macs = prepareGoadMacs(runShSpec({ extensions: ['elk', 'wazuh'] }), 4242, '10.9.9');
  assert.deepStrictEqual(Object.keys(macs).sort(), ['DC01', 'DC02', 'SRV02'],
    'the SIEMs stay out of goadMacs; that absence is what earns them a host-record');
});

test('assertGoadExtensionsRunnable fires on the PAIR and on nothing else', () => {
  const f = goad.assertGoadExtensionsRunnable;
  assert.doesNotThrow(() => f({ goad: { prebaked: true } }, []),        'prebaked, nothing ticked');
  assert.doesNotThrow(() => f({ goad: { prebaked: true } }, undefined), 'prebaked, no list at all');
  assert.doesNotThrow(() => f({ goad: { enabled: true } }, ['elk']),    'live lane, extension ticked');
  assert.doesNotThrow(() => f({}, ['elk']),                             'not a GOAD spec at all');
  assert.throws(() => f({ goad: { prebaked: true } }, ['elk']), /generic Ubuntu base/);
});
