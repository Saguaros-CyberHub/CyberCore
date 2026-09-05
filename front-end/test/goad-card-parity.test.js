/**
 * goad-card-parity.test.js — the GOAD configuration card, and the drift that
 * made it three different forms.
 *
 * WHAT THIS FILE IS DEFENDING
 *
 *  1. THE BUG. admin.html had THREE GOAD cards. The Topology Designer's
 *     (#topoGoad*) had editable forest/child domains with live validation, the
 *     Extensions group, the pre-baked toggle and the fixed-subnet pair. The
 *     TEMPLATE EDITOR's (#tplGoad*) — the one you land on when you press "Edit"
 *     on an existing environment — had a version dropdown, two fields labelled
 *     "(read-only)", a read-only password and Include Kali. That is all it had.
 *     So the pre-baked golden-image flow was unreachable from the only surface
 *     that edits an existing spec, and spec.goad.prebaked REQUIRES
 *     goad.fixed_subnet to deploy (challenge-lane-deployer.applyPrebakedFixedSubnet
 *     throws without it). Worse, LOADING an existing spec dropped extensions,
 *     prebaked and fixed_subnet on the floor and then saved that back: opening
 *     an environment to fix its name deleted its pre-baked configuration.
 *
 *  2. ONE IMPLEMENTATION. Three copies of one card is HOW that drift happened,
 *     so the fix is not a fourth copy. Every behaviour now lives once, in
 *     admin-topology.js's "GOAD CARD — ONE implementation, two surfaces"
 *     section, parameterised by a card descriptor; topoGoadCard() and
 *     tplGoadCard() are the only places the two surfaces differ. (The create
 *     form's #chalGoad* card is deliberately out of scope and left alone.)
 *
 *  3. THE DRIFT GATE. The MARKUP is still two blocks, because
 *     test/ad-domain-rules.test.js pins the Designer's block by reading
 *     public/admin.html, so generating it from JS would break a passing test on
 *     a working surface. That is the whole reason this file exists: it strips
 *     the prefix off both blocks and fails on the first field, handler or
 *     readonly flag that one card grows and the other does not. Two copies of
 *     markup are only acceptable with this gate holding them together.
 *
 *  4. THE ROUND TRIP. A field that renders and does not persist is worse than
 *     one that never rendered. readTplGoadFields must carry extensions,
 *     prebaked and fixed_subnet into the saved spec, loadTplGoadFields must put
 *     them back, and PUT /api/admin/lab-templates/:id must not drop them on the
 *     way through — it merges the spec wholesale, unlike buildSpecVm's
 *     whitelist on the create path.
 *
 * Run: node front-end/test/goad-card-parity.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');

const HTML = fs.readFileSync(path.join(PUBLIC, 'admin.html'), 'utf8');
const TOPO_SRC = fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-topology.js'), 'utf8');
const CHAL_SRC = fs.readFileSync(path.join(PUBLIC, 'js', 'admin', 'admin-challenges.js'), 'utf8');

// ════════════════════════════════════════════════════════════════════════════
// 1. THE DRIFT GATE
// ════════════════════════════════════════════════════════════════════════════
//
// Both cards are sliced from the enable checkbox to the field-error line, which
// is the first and last element every GOAD card has. Everything between is
// compared with the `topo`/`tpl` prefix removed, so styling may differ freely
// and the FIELD INVENTORY may not.

function cardBlock(prefix) {
  const open = `id="${prefix}GoadEnabled"`;
  const close = `id="${prefix}ErrGoad"`;
  const start = HTML.indexOf(open);
  assert.notStrictEqual(start, -1,
    `admin.html has no ${open} — the ${prefix} GOAD card was renamed or removed`);
  const end = HTML.indexOf(close, start);
  assert.notStrictEqual(end, -1,
    `the ${prefix} GOAD card has no ${close}. Every card ends with its own field-error line: `
    + 'it is where the AD domain rulebook paints, and without it goadCardValidateDomains has '
    + 'nowhere to say "that is not a DNS name".');
  return HTML.slice(start, end + close.length);
}

const BLOCKS = { topo: cardBlock('topo'), tpl: cardBlock('tpl') };
const HANDLER_PREFIX = { topo: 'Topo', tpl: 'Tpl' };

/** Every element the card declares, with the prefix stripped. */
function fieldIds(prefix) {
  const re = new RegExp(`id="${prefix}(Goad[A-Za-z0-9]+|ErrGoad)"`, 'g');
  return [...new Set([...BLOCKS[prefix].matchAll(re)].map(m => m[1]))].sort();
}

/** Every inline handler the card wires, with the prefix stripped. */
function handlerNames(prefix) {
  const re = new RegExp(`on(?:change|input)="on${HANDLER_PREFIX[prefix]}([A-Za-z0-9]+)\\(`, 'g');
  return [...new Set([...BLOCKS[prefix].matchAll(re)].map(m => m[1]))].sort();
}

/** The fields the card refuses to let anyone type into. */
function readonlyIds(prefix) {
  const re = new RegExp(`id="${prefix}(Goad[A-Za-z0-9]+)"[^>]*\\breadonly\\b`, 'g');
  return [...new Set([...BLOCKS[prefix].matchAll(re)].map(m => m[1]))].sort();
}

test('THE GATE: both GOAD cards declare exactly the same fields', () => {
  const topo = fieldIds('topo');
  const tpl = fieldIds('tpl');
  assert.deepStrictEqual(tpl, topo,
    'The Topology Designer\'s card and the template editor\'s must stay field-for-field identical.\n'
    + `  designer only: ${topo.filter(x => !tpl.includes(x)).join(', ') || '(none)'}\n`
    + `  editor only:   ${tpl.filter(x => !topo.includes(x)).join(', ') || '(none)'}\n`
    + 'The behaviour behind both is ONE implementation (admin-topology.js, "GOAD CARD"), so a field '
    + 'that exists on one card and not the other is a feature the other card cannot reach — which is '
    + 'exactly how the editor ended up with no Extensions group and no pre-baked toggle.');
});

test('THE GATE: both cards wire the same handlers', () => {
  assert.deepStrictEqual(handlerNames('tpl'), handlerNames('topo'),
    'a field rendered with no handler is a field that does nothing');
});

test('THE GATE: only the local-admin password is read-only, on both cards', () => {
  assert.deepStrictEqual(readonlyIds('topo'), ['GoadPassword']);
  assert.deepStrictEqual(readonlyIds('tpl'), ['GoadPassword'],
    'The editor used to mark Forest Domain and Child Subdomain read-only and label them "(read-only)". '
    + 'They are not: they are per-challenge values, GOAD_LABS carries a different forestRoot for every '
    + 'lab, and a card that cannot edit them stores whichever domain happened to be on screen. The '
    + 'admin password IS baked — it lives in GOAD\'s Autounattend.xml — so that one stays locked.');
});

test('the fields that were missing from the editor are present on BOTH cards', () => {
  // Named individually rather than left to the set comparison, so a failure says
  // WHICH capability is gone rather than "the sets differ".
  for (const prefix of ['topo', 'tpl']) {
    const block = BLOCKS[prefix];
    assert.ok(block.includes(`id="${prefix}GoadExtensions"`),
      `${prefix}: no extensions host — spec.goad.extensions could be neither authored nor seen`);
    assert.ok(block.includes(`id="${prefix}GoadPrebaked"`),
      `${prefix}: no pre-baked toggle — the golden-image flow is unreachable from this card`);
    assert.ok(block.includes(`id="${prefix}GoadFixedInt"`) && block.includes(`id="${prefix}GoadFixedExt"`),
      `${prefix}: no fixed-subnet fields. spec.goad.prebaked without goad.fixed_subnet.int makes `
      + 'applyPrebakedFixedSubnet throw at deploy — the toggle is useless without the pair.');
    assert.ok(new RegExp(`id="${prefix}GoadDomain"[^>]*oninput="on${HANDLER_PREFIX[prefix]}GoadDomainInput\\(\\)"`).test(block),
      `${prefix}: the forest domain is not validated as it is typed`);
    assert.ok(new RegExp(`id="${prefix}GoadChild"[^>]*oninput="on${HANDLER_PREFIX[prefix]}GoadDomainInput\\(\\)"`).test(block),
      `${prefix}: the child subdomain is not validated as it is typed`);
  }
});

test('the forest-rename opt-in is on BOTH cards, with its hint slot', () => {
  // Named individually for the same reason as the block above: a bare set
  // comparison would say "the sets differ", and the thing that actually matters
  // is that the surface which edits an EXISTING spec can reach the opt-in at
  // all. Without the hint slot the checkbox is unexplained, and what it does
  // (recompile the lab tree and push it) only becomes visible 40 minutes later
  // on a lane.
  for (const prefix of ['topo', 'tpl']) {
    const block = BLOCKS[prefix];
    assert.ok(block.includes(`id="${prefix}GoadRenameForest"`),
      `${prefix}: no rename opt-in — spec.goad.rename_forest could be neither authored nor seen, and a `
      + 'stored one would be invisible on the card that opened it');
    assert.ok(block.includes(`id="${prefix}GoadRenameHint"`),
      `${prefix}: no hint slot. It carries the migration-safety story ("unticked, the domain is a `
      + 'RECORD…"), the reason the box is disabled, and the reserved-TLD refusal — none of which has '
      + 'anywhere else to be said.');
    assert.ok(new RegExp(`id="${prefix}GoadRenameForest"[^>]*onchange="on${HANDLER_PREFIX[prefix]}GoadRenameForestToggle\\(\\)"`).test(block),
      `${prefix}: the rename opt-in does not repaint its hint when it is ticked`);
    // The domain fields must NOT become read-only when the opt-in exists: with
    // rename off the domain still drives the lane's DNS forwarder and Caldera's
    // AD facts, and a pre-baked lane has to be able to record whatever its
    // golden image was baked with. (readonlyIds pins the whole card; this names
    // the field the opt-in is most likely to tempt someone into locking.)
    assert.ok(!new RegExp(`id="${prefix}GoadDomain"[^>]*\\bdisabled\\b`).test(block),
      `${prefix}: the forest domain is disabled in MARKUP. Any disabling here is data-driven — which `
      + 'lab, and whether the lane is pre-baked — so it belongs in goadCardPaintRenameHint where the '
      + 'reason can be shown.');
  }
});

test('the create form\'s third card is deliberately untouched', () => {
  // #chalGoad* is the oldest and least capable surface and is explicitly out of
  // scope. Pinned so a future reader does not "finish the job" by wiring it to
  // the shared card without checking what buildGoadVmRows emits — that form's
  // rows carry services/default_scripts as comma STRINGS, not the canvas's
  // ARRAYS, and mixing the two is the shape trap goad-extensions.js documents.
  assert.ok(HTML.includes('id="chalGoadEnabled"'), 'the create form still has its own card');
  assert.match(CHAL_SRC, /function buildGoadVmRows\(labKey, includeKali, includeDmz\)/,
    'and its own row builder, which emits the comma-string shape');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. ONE IMPLEMENTATION, NOT TWO
// ════════════════════════════════════════════════════════════════════════════

const SHARED = [
  'goadCardEl', 'goadCardOn', 'goadCardFreeOffset', 'goadCardPopulateVersions',
  'goadCardUpdateDesc', 'goadCardResetDomainsFromLab', 'goadCardValidateDomains',
  'goadCardOnDomainInput', 'goadCardRebuildFromLab', 'goadCardOnToggle',
  'goadCardOnVersionChange', 'goadCardOnKaliToggle', 'goadCardOnPrebakedToggle',
  'goadCardReset', 'goadCardApplyFields', 'goadCardReadFields',
  'goadCardReadExtensions', 'goadCardRenderExtensions', 'goadCardToggleExtension',
  'goadCardHostNames',
  'goadCardOnRenameForestToggle', 'goadCardPaintRenameHint',
];

test('every shared card function is defined exactly ONCE across the admin scripts', () => {
  // Classic scripts share one global lexical scope, so a second copy would not
  // even be a syntax error — it would silently hoist over the first, which is
  // the failure mode this whole refactor exists to remove.
  for (const name of SHARED) {
    const re = new RegExp(`^(?:async )?function ${name}\\(`, 'gm');
    const hits = (TOPO_SRC.match(re) || []).length + (CHAL_SRC.match(re) || []).length;
    assert.strictEqual(hits, 1, `${name} is defined ${hits} times — it must be defined exactly once`);
  }
});

test('every tplGoad* handler is a binding, not a second implementation', () => {
  const bindings = {
    onTplGoadToggle: 'goadCardOnToggle',
    onTplGoadVersionChange: 'goadCardOnVersionChange',
    onTplGoadDomainInput: 'goadCardOnDomainInput',
    onTplGoadKaliToggle: 'goadCardOnKaliToggle',
    onTplGoadPrebakedToggle: 'goadCardOnPrebakedToggle',
    onTplGoadRenameForestToggle: 'goadCardOnRenameForestToggle',
    onTplExtensionToggle: 'goadCardToggleExtension',
    readTplGoadExtensions: 'goadCardReadExtensions',
    resetTplGoadFields: 'goadCardReset',
    readTplGoadFields: 'goadCardReadFields',
    loadTplGoadFields: 'goadCardApplyFields',
    tplGoadHostNames: 'goadCardHostNames',
  };
  for (const [wrapper, shared] of Object.entries(bindings)) {
    assert.match(CHAL_SRC, new RegExp(`function ${wrapper}\\([^)]*\\) \\{ return ${shared}\\(tplGoadCard\\(\\)|function ${wrapper}\\([^)]*\\) \\{ ${shared}\\(tplGoadCard\\(\\)`),
      `${wrapper} must delegate to ${shared} rather than re-implement it`);
  }
});

test('every topoGoad* handler is a binding too — the Designer is not the privileged copy', () => {
  const bindings = {
    onTopoGoadToggle: 'goadCardOnToggle',
    onTopoGoadVersionChange: 'goadCardOnVersionChange',
    resetTopoGoadDomainsFromLab: 'goadCardResetDomainsFromLab',
    validateTopoGoadDomains: 'goadCardValidateDomains',
    onTopoGoadKaliToggle: 'goadCardOnKaliToggle',
    onTopoGoadPrebakedToggle: 'goadCardOnPrebakedToggle',
    onTopoGoadRenameForestToggle: 'goadCardOnRenameForestToggle',
    onTopoExtensionToggle: 'goadCardToggleExtension',
    readTopoGoadFields: 'goadCardReadFields',
    applyTopoGoadFields: 'goadCardApplyFields',
    topoGoadHostNames: 'goadCardHostNames',
  };
  for (const [wrapper, shared] of Object.entries(bindings)) {
    assert.ok(new RegExp(`function ${wrapper}\\([^)]*\\) \\{ (?:return )?${shared}\\(topoGoadCard\\(\\)`).test(TOPO_SRC),
      `${wrapper} must delegate to ${shared}`);
  }
});

test('admin-challenges.js no longer reaches for the card\'s elements by id', () => {
  // The elements are addressed exactly once, by `card.prefix + 'Goad' + suffix`
  // in goadCardEl. A getElementById('tplGoad…') here would be the beginning of
  // the next copy.
  const stray = [...CHAL_SRC.matchAll(/getElementById\('(tplGoad[A-Za-z0-9]+|tplErrGoad)'\)/g)]
    .map(m => m[1]);
  assert.deepStrictEqual(stray, [],
    `admin-challenges.js reads ${stray.join(', ')} directly. Every card element belongs to `
    + 'goadCardEl(card, suffix); reading one here is how the two cards drift apart again.');
});

test('the retired duplicates are gone, not merely unused', () => {
  for (const dead of ['buildTplGoadVMs', 'tplVmFromGoad', 'populateTplGoadVersionDropdown', '_preTplGoadVMs']) {
    assert.ok(!CHAL_SRC.includes(dead),
      `${dead} is still in admin-challenges.js — it was the editor's private copy of a shared behaviour`);
  }
  // fromGoadLab is now the ONLY builder either canvas seeds from.
  assert.match(TOPO_SRC, /TopoSeed\(\)\.fromGoadLab\(lab, \{/,
    'the shared rebuild seeds from topology-seed.js, which is what gives the editor the v3 DMZ pivot '
    + 'and the blanked golden-image VMIDs it never had');
});

// ════════════════════════════════════════════════════════════════════════════
// 3. THE CARD, DRIVEN HEADLESS
// ════════════════════════════════════════════════════════════════════════════

const GOAD_LABS = {
  'GOAD-Light': {
    key: 'GOAD-Light', rebrandable: true,
    domains: ['cybersaguaros.local', 'tumamoc.cybersaguaros.local'],
    displayName: 'GOAD-Light',
    description: 'three machines',
    forestRoot: 'cybersaguaros.local',
    childSubdomain: 'tumamoc',
    vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'DC02', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004 },
    ],
  },
  'GOAD-Mini': {
    key: 'GOAD-Mini', rebrandable: true,
    displayName: 'GOAD-Mini',
    description: 'two machines, one domain',
    forestRoot: 'sevenkingdoms.local',
    childSubdomain: null,
    // Served once GOAD_LABS carries it. GOAD-Mini is the one lab a forest
    // rename is offered for, and this array is WHY — eligibility is a data
    // predicate on the row, not a list of lab keys in the card.
    domains: ['sevenkingdoms.local'],
    vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004 },
    ],
  },
  GOAD: {
    key: 'GOAD', rebrandable: true,
    displayName: 'GOAD',
    description: 'the full lab',
    forestRoot: 'sevenkingdoms.local',
    childSubdomain: 'north',
    domains: ['sevenkingdoms.local', 'north.sevenkingdoms.local', 'essos.local'],
    vms: [
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'DC02', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'DC03', role: 'dc', os: 'Windows Server 2016', template_vmid: 1004 },
      { name: 'SRV02', role: 'member', os: 'Windows Server 2019', template_vmid: 1004 },
      { name: 'SRV03', role: 'member', os: 'Windows Server 2019', template_vmid: 1004 },
    ],
  },
};

const EXTENSIONS = [
  {
    key: 'elk', displayName: 'ELK', machine: 'elk', role: 'siem', os: 'Ubuntu 22.04',
    template_vmid: 9001, in_lab: false, ip_octet: 24, description: 'Elasticsearch + Kibana',
    dns_aliases: ['elk.cybercore.lan'],
  },
  {
    key: 'ws01', displayName: 'ws01', machine: 'ws01', role: 'workstation', os: 'Windows 11',
    template_vmid: 1002, in_lab: true, ip_octet: 25, description: 'domain-joined analyst box',
  },
];

/**
 * A headless harness for the template editor's half of the card.
 *
 * The three admin scripts are classic scripts full of top-level `let`s and DOM
 * calls, but nothing runs at load — every getElementById is inside a function —
 * so they are run in ONE vm context, exactly as the browser runs them in one
 * global scope, and the card is driven through stub elements. Top-level
 * `let`/`const` live in the context's LEXICAL global rather than as properties
 * of the sandbox object, hence the `__probe` assignments used to read them back.
 *
 * topology-seed.js is loaded for real rather than stubbed: the rebuild path is
 * the one place the editor now inherits the v3 pivot and the blanked
 * golden-image VMIDs, and stubbing the seeder would prove nothing about that.
 */
function loadEditor(opts) {
  const extChecked = { topo: new Set(), tpl: new Set() };

  function input(value) {
    return { value: value === undefined ? '' : value, style: {} };
  }
  function box(checked) { return { checked: !!checked, style: {} }; }
  function div() {
    return {
      innerHTML: '', textContent: '', style: {},
      classList: { toggle() {}, remove() {}, add() {} },
    };
  }
  function select(value) {
    const el = { options: [], style: {}, value: value === undefined ? '' : value };
    let html = '';
    Object.defineProperty(el, 'innerHTML', {
      get: () => html,
      set: (v) => {
        html = v;
        el.options = [...String(v).matchAll(/value="([^"]*)"/g)].map(m => ({ value: m[1] }));
      },
    });
    return el;
  }

  const els = {
    tplGoadEnabled: box(false),
    tplGoadConfig: div(),
    tplGoadVersion: select('GOAD-Light'),
    tplGoadDomain: input('cybersaguaros.local'),
    tplGoadChild: input('tumamoc'),
    tplGoadPassword: input('vagrant'),
    tplGoadKali: box(true),
    tplGoadPrebaked: box(false),
    tplGoadPrebakedConfig: div(),
    tplGoadFixedInt: input(''),
    tplGoadFixedExt: input(''),
    tplGoadRenameForest: box(false),
    tplGoadRenameHint: div(),
    tplGoadExtensions: div(),
    tplGoadVersionDesc: div(),
    tplErrGoad: div(),
    tplVmList: div(),          // renderTemplateVMs writes the table here
    tplPhantomList: div(),
    topoDesignVmList: null,    // renderTopoVmTable early-returns, which is fine here
  };
  for (const [id, el] of Object.entries(els)) {
    if (!id.startsWith('tplGoad') && id !== 'tplErrGoad') continue;
    const target = id.replace(/^tpl/, 'topo');
    els[target] = 'options' in el ? select(el.value)
      : 'checked' in el ? box(el.checked) : 'value' in el ? input(el.value) : div();
  }

  function extScope(sel) {
    const m = sel.match(/#(topo|tpl)GoadExtensions/);
    return m ? extChecked[m[1]] : null;
  }

  const sandbox = {
    console: { log() {}, warn() {}, error() {} },
    escHtml: (v) => String(v == null ? '' : v),
    difficultyLabel: (v) => String(v),
    api: async () => ({}),
    Toast: { info() {}, warning() {}, error() {}, success() {} },
    document: {
      getElementById: (id) => (id in els ? els[id] : null),
      querySelector: (sel) => {
        const scope = extScope(sel);
        const m = sel.match(/data-ext="([^"]+)"/);
        return (scope && m && scope.has(m[1])) ? { checked: true } : null;
      },
      querySelectorAll: (sel) => {
        const scope = extScope(sel);
        if (!scope || !/data-ext\]:checked/.test(sel)) return [];
        return [...scope].map(k => ({ getAttribute: () => k }));
      },
      createElement: () => ({ style: {}, appendChild() {}, setAttribute() {} }),
      body: { appendChild() {}, removeChild() {}, contains: () => false },
      addEventListener() {}, removeEventListener() {},
    },
  };
  sandbox.window = sandbox;
  vm.createContext(sandbox);

  const files = [
    'public/js/topology/topology-seed.js',
    'public/js/admin/goad-extensions.js',
    'public/js/admin/admin-challenges.js',
    'public/js/admin/admin-topology.js',
  ];
  // The AD rulebook is opt-in per test rather than always loaded: the card
  // treats a missing window.CyberCoreAdDomainRules as "no opinion", and every
  // test written before the rename opt-in ran that way. Only the reserved-TLD
  // hint needs the real rules, so only that test pays for them.
  if (opts && opts.rules) files.unshift('public/js/topology/ad-domain-rules.js');

  for (const f of files) {
    vm.runInContext(fs.readFileSync(path.join(ROOT, f), 'utf8'), sandbox, { filename: f });
  }

  vm.runInContext(`
    _goadCatalog = { default_lab: 'GOAD-Light', labs: ${JSON.stringify(Object.values(GOAD_LABS))} };
    _goadExtCatalog = { extensions: ${JSON.stringify(EXTENSIONS)} };
  `, sandbox);

  return { sandbox, els, ext: extChecked.tpl, run: (code) => vm.runInContext(code, sandbox) };
}

test('the editor\'s canvas name-locks the extension machines, exactly like the Designer\'s', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.ext.add('elk');
  h.ext.add('ws01');
  h.run('__locked = JSON.stringify(tplGoadHostNames());');
  assert.strictEqual(h.sandbox.__locked, '["DC01","DC02","SRV02","elk","ws01"]',
    'the names are a contract with the golden images and the baked agent configs, not labels — '
    + 'renaming elk points every winlogbeat in the lane at a host that no longer answers');

  // And the mount actually hands them over, or the lock is decorative.
  assert.match(CHAL_SRC, /goadHosts: tplGoadHostNames\(\)/);
});

test('THE KALI PATTERN on the editor: ticking an extension does not reset the machine list', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.run(`
    templateVMs.length = 0;
    templateVMs.push(
      { name: 'DC01', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, type: 'qemu',
        vm_offset: 600000, services: [], default_scripts: [], layout: { x: 10, y: 20 } },
      { name: 'jump', role: '', os: 'Debian', template_vmid: 1500, type: 'qemu',
        vm_offset: 610000, services: ['22/SSH'], default_scripts: ['seed-me'], layout: { x: 99, y: 99 } }
    );
    tplTopo = { refreshed: null, hosts: null,
      refresh: function (v) { this.refreshed = v; },
      setGoadHosts: function (h) { this.hosts = h; } };
    __arrayBefore = templateVMs;
    __rowsBefore = templateVMs.slice();
  `);

  h.ext.add('elk');
  h.run('onTplExtensionToggle("elk");');
  h.run(`
    __arraySame = (__arrayBefore === templateVMs);
    __rowsSame = __rowsBefore.every(function (r, i) { return templateVMs[i] === r; });
    __names = JSON.stringify(templateVMs.map(function (v) { return v.name; }));
    __jumpLayout = JSON.stringify(templateVMs[1].layout);
    __handed = (tplTopo.refreshed === templateVMs);
    __hosts = JSON.stringify(tplTopo.hosts);
  `);

  assert.strictEqual(h.sandbox.__arraySame, true,
    'the editor CLOSES OVER this array. Replacing it orphans the canvas even when the contents look '
    + 'right — which is why the toggle pushes and splices rather than rebuilding from the lab.');
  assert.strictEqual(h.sandbox.__rowsSame, true,
    'every pre-existing row must be the SAME OBJECT: the canvas writes nics[] and layout onto them');
  assert.strictEqual(h.sandbox.__names, '["DC01","jump","elk"]');
  assert.strictEqual(h.sandbox.__jumpLayout, '{"x":99,"y":99}', 'a hand-placed machine keeps its position');
  assert.strictEqual(h.sandbox.__handed, true, 'the canvas is refreshed with the same array, not a copy');
  assert.strictEqual(h.sandbox.__hosts, '["DC01","DC02","SRV02","elk"]',
    'and the lock set is updated before the refresh, or the new machine is renameable for one frame');
});

test('unticking on the editor removes exactly that machine, by splice', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.run(`
    templateVMs.length = 0;
    templateVMs.push({ name: 'DC01', role: 'dc', vm_offset: 600000, services: [], default_scripts: [] });
    __arrayBefore = templateVMs;
  `);
  h.ext.add('elk');
  h.run('onTplExtensionToggle("elk");');
  h.ext.delete('elk');
  h.run('onTplExtensionToggle("elk"); __names = JSON.stringify(templateVMs.map(function (v) { return v.name; })); __same = (__arrayBefore === templateVMs);');
  assert.strictEqual(h.sandbox.__names, '["DC01"]');
  assert.strictEqual(h.sandbox.__same, true, 'splice, not filter — filter would orphan the editor handle');
});

test('a tick claims a free vm_offset rather than colliding with a placed machine', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.run(`
    templateVMs.length = 0;
    templateVMs.push(
      { name: 'a', vm_offset: 600000, services: [], default_scripts: [] },
      { name: 'b', vm_offset: 620000, services: [], default_scripts: [] }
    );
  `);
  h.ext.add('elk');
  h.run('onTplExtensionToggle("elk"); __offsets = JSON.stringify(templateVMs.map(function (v) { return v.vm_offset; }));');
  assert.strictEqual(h.sandbox.__offsets, '[600000,620000,610000]',
    'two VMs on one offset clone to the same VMID and the second deploy fails, so the gap is used '
    + 'rather than 600000 + length * 10000');
});

test('THE SAVE HALF: the editor now carries extensions, prebaked and fixed_subnet into the spec', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadPrebaked.checked = true;
  h.els.tplGoadFixedInt.value = ' 10.167.161 ';   // hand-typed, with the stray spaces
  h.els.tplGoadFixedExt.value = '';
  h.ext.add('elk');
  h.run('__goad = JSON.stringify(readTplGoadFields());');
  const goad = JSON.parse(h.sandbox.__goad);

  assert.deepStrictEqual(goad.extensions, ['elk'],
    'without this the Extensions group renders, ticks, and saves nothing');
  assert.strictEqual(goad.prebaked, true);
  assert.deepStrictEqual(goad.fixed_subnet, { int: '10.167.161', ext: '10.167.161' },
    'trimmed, and ext falls back to int — applyFixedSubnet ignores a falsy base, so " 10.167.161" '
    + 'would build " 10.167.161.1" as the gateway and no guest could reach it');
  assert.strictEqual(goad.domain, 'cybersaguaros.local');
  assert.strictEqual(goad.child_subdomain, 'tumamoc');
});

test('an untouched card still posts the body it always posted', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.run('__goad = JSON.stringify(readTplGoadFields());');
  const goad = JSON.parse(h.sandbox.__goad);
  assert.ok(!('extensions' in goad), 'nothing ticked must not write an empty array');
  assert.ok(!('prebaked' in goad));
  assert.ok(!('fixed_subnet' in goad));
  // THE MIGRATION GUARD, and the reason rename_forest is an opt-in rather than
  // `domain !== forestRoot`. lab-templates.js defaults every GOAD spec to
  // cybersaguaros.local/tumamoc whatever the lab is, so that comparison is true
  // for every stored GOAD-Mini spec that exists — a derived trigger would
  // recompile all of them into a forest nobody chose on their next deploy. Not
  // even `rename_forest: false` may be written: an absent key is what makes the
  // body byte-identical to the one this card posted before the feature existed.
  assert.ok(!('rename_forest' in goad),
    'an untouched card must post NO rename key at all, not a false one');
});

test('a single-domain lab stores NO child, rather than inventing tumamoc', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadVersion.value = 'GOAD-Mini';
  h.els.tplGoadChild.value = '';
  h.run('__goad = JSON.stringify(readTplGoadFields());');
  assert.strictEqual(JSON.parse(h.sandbox.__goad).child_subdomain, null,
    'the editor used to default this to "tumamoc" — a domain GOAD-Mini does not have, on a card that '
    + 'would not let anyone correct it');
});

// WHY admin_user IS 'vagrant' AND MUST STAY THAT WAY.
//
// It was 'Administrator' in four places -- lab-templates.js's create default,
// admin-challenges.js, admin-topology.js and topology-seed.js -- and that is the
// built-in account, which sysprep /generalize /oobe DISABLES. The Windows
// template bakes vagrant/vagrant into Administrators precisely so that one
// account survives generalization, and goad-deploy.js has always defaulted
// initialUser to 'vagrant' with a comment saying so. Every UI wrote
// 'Administrator' over the top of that default, so the default never once
// applied and run.sh was handed an account that cannot log in. A real lane died
// on it: "ntlm: the specified credentials were rejected by the server", after
// 300s of wait_for_connection, on a host whose sysprep GeneralizationState was 7
// and whose vagrant account was present and Enabled.
test('admin_user is the account that survives sysprep, not the built-in one', () => {
  // Source-text, across every writer, because the value has to be right in all
  // four or the one that is wrong is the one that authors the next spec.
  const WRITERS = {
    'admin-topology.js':  TOPO_SRC,
    'admin-challenges.js': CHAL_SRC,
    'topology-seed.js':   fs.readFileSync(path.join(PUBLIC, 'js', 'topology', 'topology-seed.js'), 'utf8'),
    'lab-templates.js':   fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8'),
  };
  for (const [name, src] of Object.entries(WRITERS)) {
    const assigns = [...src.matchAll(/admin_user:\s*(?:[\w.]+\s*\|\|\s*)?'([^']+)'/g)].map(m => m[1]);
    assert.ok(assigns.length, `${name}: no admin_user assignment found — did it move?`);
    for (const who of assigns) {
      assert.strictEqual(who, 'vagrant',
        `${name} writes admin_user: '${who}'. 'Administrator' is DISABLED by sysprep `
        + '/generalize /oobe; the Windows template bakes vagrant/vagrant into Administrators '
        + 'so that one account survives. Change this back and every GOAD lane dies in preflight '
        + "with 'the specified credentials were rejected by the server', on an account that "
        + 'exists and reads as fine.');
    }
  }
});

test('THE ROUND TRIP: what an existing spec stores is what the card shows and saves back', async () => {
  const h = loadEditor();
  const stored = {
    enabled: true,
    version: 'GOAD-Mini',
    domain: 'north.example.org',
    child_subdomain: null,
    admin_user: 'vagrant',
    admin_password: 'vagrant',
    include_kali: false,
    extensions: ['elk', 'ws01'],
    prebaked: true,
    fixed_subnet: { int: '10.167.161', ext: '10.39.161' },
  };
  h.sandbox.__stored = stored;
  await vm.runInContext('loadTplGoadFields(__stored)', h.sandbox);

  // The card is showing it…
  assert.strictEqual(h.els.tplGoadEnabled.checked, true);
  assert.strictEqual(h.els.tplGoadVersion.value, 'GOAD-Mini');
  assert.strictEqual(h.els.tplGoadDomain.value, 'north.example.org',
    'the STORED domain wins over the lab default — an edit must not silently rewrite the spec it opened');
  assert.strictEqual(h.els.tplGoadChild.value, '');
  assert.strictEqual(h.els.tplGoadKali.checked, false);
  assert.strictEqual(h.els.tplGoadPrebaked.checked, true);
  assert.strictEqual(h.els.tplGoadFixedInt.value, '10.167.161');
  assert.strictEqual(h.els.tplGoadFixedExt.value, '10.39.161');
  assert.ok(/data-ext="elk"[^>]* checked/.test(h.els.tplGoadExtensions.innerHTML),
    'and the ticked extensions come back ticked');
  assert.ok(/data-ext="ws01"[^>]* checked/.test(h.els.tplGoadExtensions.innerHTML));

  // …and reading it back yields the same spec. This is the assertion that would
  // have caught the old bug: the editor loaded four fields, ignored the rest,
  // and then saved the result over a spec that had them.
  h.ext.add('elk');
  h.ext.add('ws01');
  h.run('__goad = JSON.stringify(readTplGoadFields());');
  assert.deepStrictEqual(JSON.parse(h.sandbox.__goad), stored);
});

test('loading a spec does NOT rebuild the machine list from the catalog', () => {
  // A pre-baked spec's rows carry golden-image template_vmids. Rebuilding from
  // the lab would replace every one of them with the base Windows template and
  // the author would not be told.
  const h = loadEditor();
  h.run(`
    templateVMs.length = 0;
    templateVMs.push({ name: 'DC01', role: 'dc', template_vmid: 90001, vm_offset: 600000,
                       services: [], default_scripts: [] });
    __before = templateVMs;
  `);
  h.sandbox.__stored = { enabled: true, version: 'GOAD-Light', prebaked: true,
    fixed_subnet: { int: '10.167.161', ext: '10.39.161' } };
  return vm.runInContext('loadTplGoadFields(__stored)', h.sandbox).then(() => {
    h.run('__same = (__before === templateVMs); __vmid = templateVMs[0].template_vmid;');
    assert.strictEqual(h.sandbox.__same, true, 'the stored machines are kept as they are');
    assert.strictEqual(h.sandbox.__vmid, 90001, 'including their golden-image VMIDs');
  });
});

test('a version change on the editor resets the domains AND rebuilds from the lab', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadVersion.value = 'GOAD-Mini';
  h.run('templateVMs.length = 0; tplSubnetScheme = "v1";');
  h.run('onTplGoadVersionChange();');
  assert.strictEqual(h.els.tplGoadDomain.value, 'sevenkingdoms.local',
    'the fields describe the lab that is now selected — this is the stale-value bug the Designer '
    + 'already fixed and the editor never got');
  assert.strictEqual(h.els.tplGoadChild.value, '', 'GOAD-Mini has one domain');
  h.run('__names = JSON.stringify(templateVMs.map(function (v) { return v.name; }));');
  assert.strictEqual(h.sandbox.__names, '["DC01","SRV02","Kali"]');
});

test('pre-baked on the editor seeds the DMZ pivot and blanks the VMIDs the author must supply', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.run('templateVMs.length = 0; tplSubnetScheme = "v3";');
  h.els.tplGoadPrebaked.checked = true;
  h.run('onTplGoadPrebakedToggle();');
  h.run(`
    __names = JSON.stringify(templateVMs.map(function (v) { return v.name; }));
    __vmids = JSON.stringify(templateVMs.map(function (v) { return v.template_vmid; }));
  `);
  assert.strictEqual(h.sandbox.__names, '["DC01","DC02","SRV02","web01","Kali"]',
    'web01 is the dual-homed pivot a v3 attacker needs to reach the internal segment');
  assert.strictEqual(h.sandbox.__vmids, '[null,null,null,null,1699]',
    'every non-Kali VMID is blanked so the author supplies the golden image, not the base template');
  assert.strictEqual(h.els.tplGoadPrebakedConfig.style.display, 'block',
    'and the fixed-subnet pair is revealed, because prebaked without it throws at deploy');
});

test('a non-v3 environment is TOLD its scheme cannot be changed here, not silently retyped', () => {
  // subnet_scheme is a column on the challenge row, written once by
  // reserveLabNetwork and not accepted by PUT /lab-templates/:id. Flipping
  // tplSubnetScheme would make the canvas draw segments the lane will never have.
  const h = loadEditor();
  const warnings = [];
  h.sandbox.Toast.warning = (title, msg) => warnings.push(title + ': ' + msg);
  h.els.tplGoadEnabled.checked = true;
  h.run('templateVMs.length = 0; tplSubnetScheme = "v1";');
  h.els.tplGoadPrebaked.checked = true;
  h.run('onTplGoadPrebakedToggle(); __scheme = tplSubnetScheme;');
  assert.strictEqual(h.sandbox.__scheme, 'v1', 'the row still says v1, so the card must too');
  assert.strictEqual(warnings.length, 1, 'and the author is told exactly once');
  assert.match(warnings[0], /v3/);
});

// ════════════════════════════════════════════════════════════════════════════
// 3b. THE FOREST-RENAME OPT-IN
// ════════════════════════════════════════════════════════════════════════════
//
// THE BUG. An author typed cy400test.org into Forest Domain and the lane came up
// as sevenkingdoms.local with a DC calling itself kingslanding. spec.goad.domain
// was authored, validated, stored AND READ — it drives the lane's DNS forwarder
// and Caldera's AD facts — but the AD build ignored it, so every artifact said
// one domain and NTDS said another. rename_forest is what makes the typed domain
// the one the forest is actually built with.
//
// It is an OPT-IN and not `domain !== forestRoot` because the create handler
// defaults every GOAD spec to cybersaguaros.local/tumamoc whatever the lab is —
// so that comparison is already true for every stored GOAD-Mini spec, and a
// derived trigger would recompile all of them.

test('THE OPT-IN ROUND TRIP: rename_forest survives load → save', async () => {
  const h = loadEditor();
  const stored = {
    enabled: true,
    version: 'GOAD-Mini',
    domain: 'cy400test.org',
    child_subdomain: null,
    admin_user: 'vagrant',
    admin_password: 'vagrant',
    include_kali: true,
    rename_forest: true,
  };
  h.sandbox.__stored = stored;
  await vm.runInContext('loadTplGoadFields(__stored)', h.sandbox);

  assert.strictEqual(h.els.tplGoadRenameForest.checked, true,
    'a stored opt-in must come back TICKED. An author who opens the environment to change its name, '
    + 'cannot see that it renames its forest, and saves, silently turns the rename off — which is '
    + 'exactly the load-half bug that lost extensions and prebaked before this card was shared.');
  assert.strictEqual(h.els.tplGoadRenameForest.disabled, false,
    'GOAD-Mini has one domain and this lane is not pre-baked, so the box is live');
  assert.strictEqual(h.els.tplGoadDomain.value, 'cy400test.org');

  h.run('__goad = JSON.stringify(readTplGoadFields());');
  assert.deepStrictEqual(JSON.parse(h.sandbox.__goad), stored);
});

test('the unticked hint names the stock forest the lab still builds', async () => {
  const h = loadEditor();
  h.sandbox.__stored = { enabled: true, version: 'GOAD-Mini', domain: 'cy400test.org' };
  await h.run('loadTplGoadFields(__stored)');
  assert.match(h.els.tplGoadRenameHint.textContent, /builds sevenkingdoms.local as shipped/);
});

test('renamed GOAD previews root, authored child and independent trust domain with fixed hostnames', () => {
  const h = loadEditor({ rules: true });
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadVersion.value = 'GOAD';
  h.els.tplGoadDomain.value = 'cy400test.org';
  h.els.tplGoadChild.value = 'research';
  h.els.tplGoadRenameForest.checked = true;
  h.run('onTplGoadRenameForestToggle();');
  const hint = h.els.tplGoadRenameHint.textContent;
  for (const identity of ['cy400test.org', 'research.cy400test.org', 'cy400test-partner.org']) {
    assert.ok(hint.includes(identity), hint);
  }
  assert.match(hint, /fixed catalog roster/);
  assert.match(hint, /DC01, DC02, DC03/);
  assert.equal(h.els.tplGoadRenameForest.disabled, false);
});

test('changing to a supported multi-domain lab resets the opt-in and keeps it available', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadRenameForest.checked = true;
  h.run('templateVMs.length = 0; tplSubnetScheme = "v1";');
  h.els.tplGoadVersion.value = 'GOAD';
  h.run('onTplGoadVersionChange();');
  assert.equal(h.els.tplGoadRenameForest.checked, false);
  assert.equal(h.els.tplGoadRenameForest.disabled, false);
  assert.equal(h.els.tplGoadChild.value, 'north');
});

test('unsupported catalog entries explain missing transforms without claiming they have multiple domains', () => {
  const h = loadEditor();
  h.run("_goadCatalog.labs.push({ key: 'SCCM', displayName: 'SCCM', rebrandable: false, domains: ['sccm.lab'] });");
  h.els.tplGoadVersion.value = 'SCCM';
  h.run('onTplGoadRenameForestToggle();');
  assert.equal(h.els.tplGoadRenameForest.disabled, true);
  assert.match(h.els.tplGoadRenameHint.textContent, /no supported vendored transform/);
});

test('pre-baked UNTICKS the rename and disables it, and the domain stays editable', () => {
  const h = loadEditor();
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadVersion.value = 'GOAD-Mini';
  h.els.tplGoadRenameForest.checked = true;
  h.run('onTplGoadRenameForestToggle();');

  h.run('templateVMs.length = 0; tplSubnetScheme = "v3";');
  h.els.tplGoadDomain.value = 'baked.example.org';
  h.els.tplGoadPrebaked.checked = true;
  h.run('onTplGoadPrebakedToggle();');

  assert.strictEqual(h.els.tplGoadRenameForest.checked, false);
  assert.strictEqual(h.els.tplGoadRenameForest.disabled, true,
    'a pre-baked lane clones a golden image and runs no Ansible, so there is nothing here that could '
    + 'rename the forest in its NTDS');
  assert.match(h.els.tplGoadRenameHint.textContent, /pre-baked lane/);

  h.run('__goad = JSON.stringify(readTplGoadFields());');
  const goad = JSON.parse(h.sandbox.__goad);
  assert.ok(!('rename_forest' in goad));
  assert.strictEqual(goad.domain, 'baked.example.org',
    'and the domain field is still authoritative: a pre-baked lane MUST be able to record whatever '
    + 'its golden image was baked with, which is why the opt-in disables the checkbox and never the '
    + 'domain');
});

test('ticking rename on a .local domain says so — .local only WARNS on save but REFUSES a rename', () => {
  // The asymmetry, surfaced where it is authored. checkForestRoot only warns on
  // a reserved TLD because every lab CyberCore ships is named under .local — but
  // a rename mints the new tree through publicDomainOf, which refuses one
  // outright. Without this the author gets a green card and a 400.
  const h = loadEditor({ rules: true });
  h.els.tplGoadEnabled.checked = true;
  h.els.tplGoadVersion.value = 'GOAD-Mini';
  h.els.tplGoadDomain.value = 'sevenkingdoms.local';
  h.els.tplGoadRenameForest.checked = true;
  h.run('onTplGoadRenameForestToggle();');
  assert.match(h.els.tplGoadRenameHint.textContent, /reserved suffixes/);

  h.els.tplGoadDomain.value = 'cy400test.org';
  h.run('onTplGoadDomainInput();');
  assert.ok(!/reserved suffixes/.test(h.els.tplGoadRenameHint.textContent),
    'and it clears as the author types a mintable domain, or the warning is just decoration');
});

test('a compiled lab name is not silently rewritten to GOAD-Light on save', () => {
  // FOUND BY THIS TEST, before the fix: the version select dropped any stored
  // value the catalog does not list, so opening a CiAB engagement (whose
  // spec.goad.version is the minted CIAB-… lab name the controller actually
  // holds) and pressing Save stored version:'GOAD-Light' beside
  // generated_lab.name:'CIAB-…'. resolveGeneratedLab then throws on every later
  // deploy of a lane that had been working. A renamed forest mints the same
  // shape of name (CC-GOADMINI-…), so this is now on the rename's path too.
  const h = loadEditor();
  const stored = {
    enabled: true, version: 'CIAB-ACME-7f3a1b2c', domain: 'acme.example.org',
    child_subdomain: null, admin_user: 'vagrant', admin_password: 'vagrant',
    include_kali: true,
  };
  h.sandbox.__stored = stored;
  return vm.runInContext('loadTplGoadFields(__stored)', h.sandbox).then(() => {
    assert.strictEqual(h.els.tplGoadVersion.value, 'CIAB-ACME-7f3a1b2c',
      'the stored lab name has to be an option, or the dropdown cannot show it');
    h.run('__goad = JSON.stringify(readTplGoadFields());');
    assert.deepStrictEqual(JSON.parse(h.sandbox.__goad), stored,
      'opening an environment and saving it must not change which lab it runs');
  });
});

// ════════════════════════════════════════════════════════════════════════════
// 4. THE FIELDS SURVIVE THE SAVE
// ════════════════════════════════════════════════════════════════════════════
//
// The create path and the update path differ: POST /create-lab rebuilds each VM
// through buildSpecVm's WHITELIST, while PUT /lab-templates/:id merges the whole
// spec object. A new goad key therefore survives the update path for free — but
// only as long as that merge stays a merge, which is what is pinned here.

const ROUTE_SRC = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8');

/** The PUT handler's spec-merge block, lifted out and run for real. */
function mergeSpec({ currentSpec, spec, vm_specs, phantom_assets }) {
  const start = ROUTE_SRC.indexOf('let nextSpec = null;');
  assert.notStrictEqual(start, -1, 'PUT /lab-templates/:id no longer builds nextSpec — reshaped?');
  const end = ROUTE_SRC.indexOf('const result = await cybercoreQuery(', start);
  assert.notStrictEqual(end, -1);
  const body = ROUTE_SRC.slice(start, end);
  const PROTECTED_SPEC_KEYS = ['vxlan_block', 'zone', 'cle', 'course_id'];
  // eslint-disable-next-line no-new-func
  return new Function('currentSpec', 'spec', 'vm_specs', 'phantom_assets', 'PROTECTED_SPEC_KEYS',
    `${body} return nextSpec;`)(currentSpec, spec, vm_specs, phantom_assets, PROTECTED_SPEC_KEYS);
}

test('PUT /lab-templates/:id keeps the new goad keys — it merges the spec, it does not whitelist it', () => {
  const goad = {
    enabled: true, version: 'GOAD-Light', domain: 'cybersaguaros.local',
    child_subdomain: 'tumamoc', admin_user: 'vagrant', admin_password: 'vagrant',
    include_kali: true, extensions: ['elk'], prebaked: true,
    fixed_subnet: { int: '10.167.161', ext: '10.39.161' },
  };
  const next = mergeSpec({
    currentSpec: { vms: [{ name: 'DC01' }], goad: { enabled: true, version: 'GOAD-Light' } },
    spec: { goad, vms: [{ name: 'DC01' }] },
    vm_specs: [{ name: 'DC01' }],
    phantom_assets: [],
  });
  assert.deepStrictEqual(next.goad, goad,
    'a field that renders and does not persist is worse than one that never rendered');
});

test('the reserved-network keys still win over anything the editor posts', () => {
  const next = mergeSpec({
    currentSpec: { vxlan_block: { start: 100, end: 109 }, zone: { abbrev: 'cle1' }, course_id: 'c1' },
    spec: { vxlan_block: { start: 1, end: 2 }, zone: { abbrev: 'evil' }, goad: { enabled: true } },
    vm_specs: [],
    phantom_assets: [],
  });
  assert.deepStrictEqual(next.vxlan_block, { start: 100, end: 109 },
    'changing a reservation means tearing the lab down, not editing a JSON field');
  assert.deepStrictEqual(next.zone, { abbrev: 'cle1' });
  assert.strictEqual(next.course_id, 'c1');
  assert.deepStrictEqual(next.goad, { enabled: true }, 'but goad is the editor\'s to write');
});

test('unticking GOAD posts an explicit disable while retaining compiled metadata', () => {
  assert.match(CHAL_SRC, /else if \(!templateIsReservation\) \{/);
  assert.match(CHAL_SRC, /\.\.\.templateEditSpec\.goad, enabled: false/);
});

for (const prefix of ['topo', 'tpl']) {
  test(`${prefix} card preserves compiled metadata and explicit empty child through load/save`, async () => {
    const h = loadEditor();
    const stored = {
      enabled: true, version: 'CIAB-custom', domain: 'compiled.org', child_subdomain: null,
      admin_user: 'custom-admin', admin_password: 'fixture-password', include_kali: false,
      prebaked: true, fixed_subnet: { int: '10.1.2', ext: '10.3.4' },
      lab: { labName: 'CIAB-custom', forestRoot: 'compiled.org', vms: [{ name: 'CUSTOMDC' }] },
      generated_lab: { name: 'CIAB-custom', files: { 'data/config.json': '{}' } },
    };
    h.sandbox.__stored = stored;
    await h.run(prefix === 'tpl' ? 'loadTplGoadFields(__stored)' : 'applyTopoGoadFields(__stored)');
    const value = h.run(prefix === 'tpl' ? 'readTplGoadFields()' : 'readTopoGoadFields()');
    assert.deepEqual(JSON.parse(JSON.stringify(value)), stored);
    for (const suffix of ['Version', 'Domain', 'Child', 'Prebaked']) {
      assert.equal(h.els[`${prefix}Goad${suffix}`].disabled, true);
    }
    const names = h.run(prefix === 'tpl' ? 'tplGoadHostNames()' : 'topoGoadHostNames()');
    assert.deepEqual(JSON.parse(JSON.stringify(names)), ['CUSTOMDC']);
    assert.match(h.els[`${prefix}GoadRenameHint`].textContent, /Regenerate it to change its identity/);
  });
}
