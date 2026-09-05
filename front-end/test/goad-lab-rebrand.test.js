/**
 * goad-lab-rebrand.test.js — the forest-rename transform, and the five ways a
 * rename can look right and build the wrong forest.
 *
 * The bug this whole module exists for was found live: a CYBR 400 lane came up
 * with `agent.hostname: kingslanding` in Kibana and "Sign in to: SEVENKINGDOMS"
 * on the Proxmox console, while every artifact the students had said
 * `cy400test.org`. So the tests here are all shaped the same way — they assert
 * what an operator would SEE, not how the walker is written.
 *
 * WHAT EACH BLOCK DEFENDS
 *
 *  1. DN ARITY. `sevenkingdoms.local` is 2 RDNs, `lab.cy400test.org` is 3. A
 *     text replace keyed on the FQDN emits `DC=lab.cy400test,DC=org` — a legal
 *     DN for a domain that does not exist, which fails per-object deep inside
 *     ad-data.yml. The matrix runs 1, 2, 3 and 4 labels precisely because a
 *     text-replace implementation PASSES the 2-label case; that is the shape of
 *     bug that ships green and detonates on the first three-label domain.
 *
 *  2. ROUND TRIP. Renaming new→old and comparing is the strongest single
 *     assertion available: it proves nothing changed that should not have,
 *     without anyone having to enumerate what should not have. It runs against
 *     the transform's CANONICAL form, and a second test pins the canonical form
 *     against the pinned source bytes — see `canonicalConfig` below for why that is
 *     a stronger pair than a bare deepEqual, not a weaker one.
 *
 *  3. RESIDUE. A key path the walker does not know about is copied verbatim, so
 *     the sweep is the only thing standing between an upstream field addition
 *     and a half-renamed forest.
 *
 *  4. THE PASSWORDS, and the DC-promotion invariant run.sh's own header states:
 *     hosts[parent_dc].local_admin_password == domains[parent].domain_password.
 *     Break it and promotion fails as "bad credentials", which traces back to
 *     nothing.
 *
 *  5. THE CROSS-FILE JOIN — the ws01 bug, asserted. extensions/ws01/install.yml
 *     resolves lab.domains[lab.hosts.ws01.domain].domain_password against the
 *     MAIN lab's renamed data. Every positive here is paired with the negative
 *     (the unmodified pinned source config must FAIL the same join) because without
 *     it the test passes for a transform that does nothing at all.
 *
 * Run: node --test front-end/test/goad-lab-rebrand.test.js   (or npm test)
 */

'use strict';

const { test: nodeTest } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const R = { ...require('./support/goad-rebrand-oracle'), ...require('../src/utils/goad-lab-rebrand.js') };
let sourceAvailable = true;
try { R.resolveGoadSourceDir(); } catch (_) { sourceAvailable = false; }
const test = sourceAvailable ? nodeTest : nodeTest.skip;

// The plugin copies these tests hold the core module against. The MODULE may
// never require into modules/crucible/plugins/ (pinned below); a test may.
const VALIDATE = require('../modules/crucible/plugins/ciab/utils/goad-lab-validate.js');
const PUSH = require('../modules/crucible/plugins/ciab/utils/goad-lab-push.js');

const REPO = path.join(__dirname, '..', '..');
const BASE_LABS = path.join(__dirname, '..', 'src', 'data', 'goad-base-labs');
const MINI = path.join(BASE_LABS, 'GOAD-Mini');
const EXTS = path.join(BASE_LABS, '_extensions');

const BACKSLASH = String.fromCharCode(92);
const LF = String.fromCharCode(10);

const readJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

const MINI_BASE = readJson(path.join(MINI, 'base.json'));
const EXT_BASE = {
  ws01: readJson(path.join(EXTS, 'ws01', 'base.json')),
  lx01: readJson(path.join(EXTS, 'lx01', 'base.json')),
};

const STOCK_FQDN = MINI_BASE.stock.forest_root;          // sevenkingdoms.local
const STOCK_HOSTNAME = MINI_BASE.stock.hosts.dc01.hostname; // kingslanding
const ROSTER_NAME = MINI_BASE.stock.hosts.dc01.roster_name; // DC01

/** A fresh parse every time: nothing in a test may leak into the next one. */
const sourceConfig = () => JSON.parse(R.loadBaseLab('GOAD-Mini').files['data/config.json'].bytes.toString('utf8'));
const sourceExtConfig = (key) => R.loadExtensionBase(key).config;
const sourceText = (rel) => R.loadBaseLab('GOAD-Mini').files[rel].bytes.toString('utf8');

// ─── Helpers ────────────────────────────────────────────────────────────────

/**
 * Build a rename map by hand, so the DN matrix can reach arities publicDomainOf
 * refuses (a single-label domain is not a public domain, but rebaseDn still has
 * to be right about one).
 */
function mapTo(fqdn, hosts) {
  return R.buildRenameMap(
    R.stockSideOf(MINI_BASE, 'GOAD-Mini'),
    {
      fqdn,
      firstLabel: fqdn.split('.')[0],
      hosts: hosts || { dc01: ROSTER_NAME },
      labName: 'CC-TEST-00000000',
    },
  );
}

/** Every string in a structure, with the dotted path that reached it. */
function collectStrings(node, prefix, out) {
  const acc = out || [];
  if (typeof node === 'string') {
    acc.push({ path: prefix, value: node });
  } else if (Array.isArray(node)) {
    node.forEach((v, i) => collectStrings(v, `${prefix}[${i}]`, acc));
  } else if (node && typeof node === 'object') {
    for (const k of Object.keys(node)) collectStrings(node[k], `${prefix}.${JSON.stringify(k)}`, acc);
  }
  return acc;
}

/** The maximal trailing run of DC= components, as a string. */
function trailingDcRun(dn) {
  const rdns = String(dn).split(',');
  let i = rdns.length;
  while (i > 0 && /^\s*DC\s*=/i.test(rdns[i - 1])) i -= 1;
  return { prefix: rdns.slice(0, i).join(','), root: rdns.slice(i).join(',') };
}

/**
 * Pair every DN in the pinned source config with the DN that came out in its place.
 * Pairing by PATH rather than by order, so a walker that dropped or reordered a
 * key is a failure here rather than a silently shifted comparison.
 */
function dnPairs(stock, emitted) {
  const before = new Map(collectStrings(stock, '$').map((e) => [e.path, e.value]));
  const after = new Map(collectStrings(emitted, '$').map((e) => [e.path, e.value]));
  const pairs = [];
  for (const [p, value] of before) {
    if (!R.isDnShaped(value)) continue;
    // The domains{} key itself moves, so the path of everything under it moves
    // with it. Re-key on the tail past the domain name.
    const rekey = (q) => q.replace(/^\$\."lab"\."domains"\."[^"]*"/, '@');
    const tail = rekey(p);
    const hit = after.has(p) ? after.get(p) : [...after].find(([q]) => rekey(q) === tail);
    assert.ok(hit !== undefined, `no emitted counterpart for DN at ${p}`);
    pairs.push({ path: p, before: value, after: Array.isArray(hit) ? hit[1] : hit });
  }
  assert.ok(pairs.length >= 20, `expected the pinned source config to carry 20+ DNs, found ${pairs.length}`);
  return pairs;
}

/** Ansible's `combine(recursive=True)`, which is how install.yml merges. */
function combineRecursive(a, b) {
  const out = { ...a };
  for (const k of Object.keys(b)) {
    const l = out[k];
    const r = b[k];
    out[k] = (l && r && typeof l === 'object' && typeof r === 'object'
      && !Array.isArray(l) && !Array.isArray(r))
      ? combineRecursive(l, r)
      : r;
  }
  return out;
}

/** Every path at which two structures differ, with both values. */
function deepDiffPaths(a, b, prefix, out) {
  const acc = out || [];
  const at = prefix || '$';
  const bothObjects = a && b && typeof a === 'object' && typeof b === 'object'
    && Array.isArray(a) === Array.isArray(b);
  if (!bothObjects) {
    if (a !== b) acc.push({ path: at, a, b });
    return acc;
  }
  const keys = new Set([...Object.keys(a), ...Object.keys(b)]);
  for (const k of keys) deepDiffPaths(a[k], b[k], `${at}.${k}`, acc);
  return acc;
}

/**
 * The transform's own fixed point: rename sevenkingdoms.local to itself.
 *
 * The walker CANONICALISES the five NetBIOS-qualified principals — GOAD-Mini
 * spells them `sevenkingdoms\user` (the lower-case first label) while
 * netbios_name is `SEVENKINGDOMS`, and the transform always emits the NetBIOS
 * NAME because the first-label spelling only resolves when the two strings
 * coincide (ad/SCCM ships sccm.lab with netbios_name SCCMLAB, where it does
 * not). So a literal new→old→deepEqual against the pinned source bytes cannot hold,
 * and pretending otherwise would mean emitting a prefix that is wrong on the
 * next lab.
 *
 * The pair of assertions below is stronger than the bare deepEqual it replaces:
 * the round trip is exact against this fixed point, AND the fixed point's
 * entire distance from the pinned source file is enumerated, so a walker that
 * started canonicalising something else fails immediately.
 */
function canonicalConfig() {
  return R.rewriteLabConfig(
    sourceConfig(),
    R.buildRenameMap(
      R.stockSideOf(MINI_BASE, 'GOAD-Mini'),
      R.stockSideOf(MINI_BASE, 'GOAD-Mini'),
    ),
  );
}

// ════════════════════════════════════════════════════════════════════════════
// 1. DN ARITY — the test that pins the structural approach
// ════════════════════════════════════════════════════════════════════════════

test('DN arity matrix: a text replace passes 2 labels and fails 1, 3 and 4', () => {
  for (const fqdn of ['corpnet', 'cy400test.org', 'lab.cy400test.org', 'ad.lab.cy400test.org']) {
    const labels = fqdn.split('.');
    const stock = sourceConfig();
    const emitted = R.rewriteLabConfig(stock, mapTo(fqdn));
    const expectedRoot = R.rootDnForDomain(fqdn);

    for (const pair of dnPairs(stock, emitted)) {
      const was = trailingDcRun(pair.before);
      const now = trailingDcRun(pair.after);

      // The whole DN still parses as RDNs, and every component is one.
      for (const rdn of pair.after.split(',')) {
        assert.match(rdn, /^[A-Za-z][A-Za-z0-9-]*=[^,]+$/,
          `${fqdn}: emitted DN ${JSON.stringify(pair.after)} has an unparseable RDN at ${pair.path}`);
      }

      assert.equal(R.normalizeDn(now.root), R.normalizeDn(expectedRoot),
        `${fqdn}: DN at ${pair.path} ends in ${JSON.stringify(now.root)}, not the new root `
        + `${JSON.stringify(expectedRoot)}`);

      assert.equal(now.root.split(',').length, labels.length,
        `${fqdn}: DN at ${pair.path} has ${now.root.split(',').length} DC components for a `
        + `${labels.length}-label domain — this is the DC=lab.cy400test,DC=org failure`);

      assert.equal(now.prefix, was.prefix,
        `${fqdn}: the non-DC prefix at ${pair.path} changed from ${JSON.stringify(was.prefix)} to `
        + `${JSON.stringify(now.prefix)}; CN=AdminSDHolder,CN=System and OU=Crownlands name objects `
        + 'the exercise depends on and must survive byte for byte');
    }
  }
});

test('rebaseDn refuses a DN rooted in another domain rather than rebasing it', () => {
  assert.throws(
    () => R.rebaseDn('OU=Vale,DC=essos,DC=local', 'DC=sevenkingdoms,DC=local', 'DC=cy400test,DC=org'),
    (e) => e.code === R.REBRAND_CODES.FOREIGN_DN);
});

test('rebaseDn preserves an exotic prefix, spacing and all, and is case-blind on the root', () => {
  const out = R.rebaseDn(
    'CN=AdminSDHolder,CN=System,DC=SevenKingdoms,DC=Local',
    'DC=sevenkingdoms,DC=local',
    'DC=lab,DC=cy400test,DC=org');
  assert.equal(out, 'CN=AdminSDHolder,CN=System,DC=lab,DC=cy400test,DC=org');
});

test('a DN that IS the root becomes the new root exactly', () => {
  assert.equal(
    R.rebaseDn('DC=sevenkingdoms,DC=local', 'DC=sevenkingdoms,DC=local', 'DC=a,DC=b,DC=c'),
    'DC=a,DC=b,DC=c');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. ROUND TRIP — nothing changed that should not have
// ════════════════════════════════════════════════════════════════════════════

test('round-trip inverse: new -> old reproduces the config exactly', () => {
  const canonical = canonicalConfig();
  const forward = mapTo('lab.cy400test.org');
  const mid = R.rewriteLabConfig(canonical, forward);
  const back = R.rewriteLabConfig(mid, R.invertRenameMap(forward));
  assert.deepStrictEqual(back, canonical);
});

test('the transform canonicalises exactly five bytes of the pinned source config, and they are the NetBIOS prefixes', () => {
  const diffs = deepDiffPaths(sourceConfig(), canonicalConfig());
  assert.equal(diffs.length, 5,
    `expected exactly the 5 local_groups principals to differ, got ${diffs.length}: `
    + diffs.map((d) => d.path).join(', '));
  for (const d of diffs) {
    assert.match(d.path, /local_groups/,
      `an identity rename changed ${d.path}, which is not a NetBIOS-qualified principal`);
    assert.equal(String(d.a).toLowerCase(), String(d.b).toLowerCase(),
      'the canonicalisation may only change the CASE of the domain prefix');
    assert.ok(d.b.startsWith(MINI_BASE.stock.netbios + BACKSLASH),
      `${d.path} should carry the NetBIOS name, not the first label: ${JSON.stringify(d.b)}`);
  }
});

test('round-trip inverse: the inventories come back byte-identical', () => {
  const forward = mapTo('lab.cy400test.org');
  const inverse = R.invertRenameMap(forward);

  const inv = sourceText('data/inventory');
  assert.equal(R.rewriteInventory(R.rewriteInventory(inv, forward), inverse), inv);

  const prov = sourceText('providers/proxmox/inventory');
  assert.equal(
    R.rewriteProviderInventory(R.rewriteProviderInventory(prov, forward), inverse), prov);
});

// ════════════════════════════════════════════════════════════════════════════
// 3. RESIDUE — the backstop for every key path the walker does not know
// ════════════════════════════════════════════════════════════════════════════

test('no stock token survives anywhere in the emitted tree', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  assert.equal(out.rebranded, true);

  // Scoped per artifact, deliberately. `dragonstone` is lx01's stock HOSTNAME
  // and `DragonStone` is a GROUP in the main lab; sweeping the main tree for it
  // would demand renaming exercise content the transform is required to
  // preserve. Between the three needle sets every token in the task's list is
  // swept over the artifact where it is actually a name.
  const sweeps = [
    { what: 'main tree', needles: ['sevenkingdoms', 'SEVENKINGDOMS', 'kingslanding', 'GOAD-Mini'],
      texts: Object.keys(out.files).map((p) => ({
        path: p,
        text: Buffer.isBuffer(out.files[p])
          ? R.decodeVendored(out.files[p], R.loadBaseLab('GOAD-Mini').base.files[p].encoding)
          : out.files[p],
      })) },
    { what: 'ws01 config', needles: ['sevenkingdoms', 'SEVENKINGDOMS', 'casterlyrock'],
      texts: [{ path: 'extensions/ws01/data/config.json', text: out.extensionConfigs.ws01 }] },
    { what: 'lx01 config', needles: ['sevenkingdoms', 'SEVENKINGDOMS', 'dragonstone'],
      texts: [{ path: 'extensions/lx01/data/config.json', text: out.extensionConfigs.lx01 }] },
  ];

  for (const sweep of sweeps) {
    for (const file of sweep.texts) {
      for (const needle of sweep.needles) {
        assert.ok(!file.text.toLowerCase().includes(needle.toLowerCase()),
          `${sweep.what}: ${file.path} still contains ${JSON.stringify(needle)}`);
      }
    }
  }
});

test('the `GOAD-Mini` needle is the one that catches a forgotten domain_name=', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  assert.match(out.files['data/inventory'], new RegExp(`domain_name=${out.labName}`));
  assert.ok(!out.files['data/inventory'].includes('GOAD-Mini'));
});

test('a site the walker does not know about is REFUSED, not shipped half-renamed', () => {
  // An upstream field addition, simulated: a key the walker copies verbatim
  // that happens to carry the domain. The whole point of the sweep is that this
  // fails loudly instead of deploying a forest that is half one name.
  const stock = sourceConfig();
  stock.lab.hosts.dc01.some_new_upstream_field = `join ${STOCK_FQDN} please`;
  const emitted = R.rewriteLabConfig(stock, mapTo('cy400test.org'));
  assert.throws(
    () => R.assertNoResidue(
      [{ path: 'data/config.json', content: JSON.stringify(emitted), encoding: 'utf8' }],
      R.residueNeedlesFor(MINI_BASE, 'GOAD-Mini'),
      'test tree'),
    (e) => e.code === R.REBRAND_CODES.RESIDUE);
});

// ════════════════════════════════════════════════════════════════════════════
// 4. WHAT MUST NOT CHANGE
// ════════════════════════════════════════════════════════════════════════════

test('every password is byte-identical, and DC promotion still authenticates', () => {
  const stock = sourceConfig().lab;
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const lab = out.config.lab;
  const newFqdn = 'cy400test.org';

  assert.equal(lab.hosts.dc01.local_admin_password, stock.hosts.dc01.local_admin_password);
  assert.equal(lab.domains[newFqdn].domain_password, stock.domains[STOCK_FQDN].domain_password);

  const stockUsers = stock.domains[STOCK_FQDN].users;
  const newUsers = lab.domains[newFqdn].users;
  assert.equal(Object.keys(newUsers).length, 11);
  for (const u of Object.keys(stockUsers)) {
    assert.equal(newUsers[u].password, stockUsers[u].password, `password for ${u} changed`);
  }

  // run.sh's own header states this pair is what makes DC promotion
  // authenticate. Asserted on the OUTPUT, not trusted from the input.
  assert.equal(lab.hosts[lab.domains[newFqdn].dc].local_admin_password,
    lab.domains[newFqdn].domain_password);
  R.assertPromotionInvariant(lab, 'test');
});

test('OU, group and ACL names and rights are untouched, and so are the host-key join paths', () => {
  const stock = sourceConfig().lab.domains[STOCK_FQDN];
  const lab = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' }).config.lab;
  const now = lab.domains['cy400test.org'];

  assert.deepStrictEqual(Object.keys(now.organisation_units), Object.keys(stock.organisation_units));
  assert.deepStrictEqual(Object.keys(now.groups.global), Object.keys(stock.groups.global));
  assert.deepStrictEqual(Object.keys(now.acls), Object.keys(stock.acls));
  for (const name of Object.keys(stock.acls)) {
    assert.equal(now.acls[name].right, stock.acls[name].right, `${name}.right changed`);
    assert.equal(now.acls[name].inheritance, stock.acls[name].inheritance);
  }
  // `DragonStone` is a GROUP. lx01's stock hostname is `dragonstone`. They are
  // not the same thing and only one of them is naming.
  assert.ok(now.groups.global.DragonStone, 'the DragonStone group was renamed as if it were a host');

  // `dc01/templates/` is the HOST KEY — a directory under files/ — not a
  // hostname. Renaming it breaks the adcs_templates copy.
  assert.deepStrictEqual(lab.hosts.dc01.vulns_vars, sourceConfig().lab.hosts.dc01.vulns_vars);
  assert.equal(lab.hosts.dc01.vulns_vars.files.template.src, 'dc01/templates/');
  assert.equal(now.dc, 'dc01');
  assert.ok(lab.hosts.dc01, 'the host KEY dc01 was renamed; every join in the tree runs through it');
});

test('the hostname is the roster name, and the two computer-account ACLs move with it', () => {
  const lab = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' }).config.lab;
  assert.equal(lab.hosts.dc01.hostname, ROSTER_NAME);
  const acls = lab.domains['cy400test.org'].acls;
  assert.equal(acls.GenericAll_stanis_dc.to, `${ROSTER_NAME}$`);
  assert.equal(acls.GenericAll_group_acrrosdom_dc.to, `${ROSTER_NAME}$`);
});

test('an over-long, colliding or illegal hostname is REFUSED, never truncated', () => {
  const cases = [
    { hosts: { dc01: 'this-name-is-way-too-long' }, code: R.REBRAND_CODES.HOSTNAME_TOO_LONG },
    { hosts: { dc01: 'DC 01' }, code: R.REBRAND_CODES.HOSTNAME_ILLEGAL },
    { hosts: { dc01: '0123' }, code: R.REBRAND_CODES.HOSTNAME_ILLEGAL },
    { hosts: { dc01: '' }, code: R.REBRAND_CODES.UNMAPPED_HOST },
  ];
  for (const c of cases) {
    assert.throws(
      () => R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org', hostnames: c.hosts }),
      (e) => e.code === c.code,
      `expected ${c.code} for ${JSON.stringify(c.hosts)}`);
  }
  // A truncated computer name is the name in every Kerberos ticket and every
  // Kibana document, so nothing anywhere may produce one.
  assert.throws(
    () => R.assertHostname('this-name-is-way-too-long', 'dc01'),
    (e) => /REFUSED rather than truncated/.test(e.message));

  // GOAD-Mini has one host, so a collision cannot be provoked through it — but
  // two hosts booting as one name is a duplicate machine account, and the
  // second join silently takes over the first.
  assert.throws(
    () => R.assertNoHostnameCollision({ dc01: 'DC01', srv02: 'dc01' }),
    (e) => e.code === R.REBRAND_CODES.HOSTNAME_COLLISION);
});

test('ESC1.json travels as BYTES — a Buffer, byte-identical, never a utf8 string', () => {
  const rel = 'files/dc01/templates/ESC1.json';
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const emitted = out.files[rel];
  assert.ok(Buffer.isBuffer(emitted),
    'ESC1.json must stay a Buffer: it is UTF-16LE with a BOM, and pulling it through a utf8 string '
    + 'mangles every character while leaving a file that still looks like a file');
  assert.ok(emitted.equals(R.loadBaseLab('GOAD-Mini').files[rel].bytes));
  assert.equal(emitted[0], 0xff, 'the BOM is gone');
  assert.equal(emitted[1], 0xfe);
});

// ════════════════════════════════════════════════════════════════════════════
// 5. THE CROSS-FILE JOIN — the ws01 bug, asserted, with its negative
// ════════════════════════════════════════════════════════════════════════════

test('ws01: the renamed pair satisfies install.yml\'s join, and the UNMODIFIED config does not', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const mainLab = out.config.lab;

  // How extensions/ws01/ansible/install.yml assembles it: the main lab's
  // data.yml, then this file layered on as `lab_extension`, then
  // `lab | combine(lab_extension, recursive=True)`.
  const joinedGood = combineRecursive(mainLab, JSON.parse(out.extensionConfigs.ws01).lab_extension);
  const memberDomain = joinedGood.hosts.ws01.domain;
  assert.equal(memberDomain, 'cy400test.org');
  assert.ok(joinedGood.domains[memberDomain],
    'lab.domains[lab.hosts.ws01.domain] is undefined — this is the exact lookup that kills the play');
  assert.ok(joinedGood.domains[memberDomain].domain_password);

  // THE NEGATIVE. Without it this test passes for a transform that does
  // nothing: the stock ws01 config still says sevenkingdoms.local, and the
  // renamed main lab has no such key.
  const joinedBad = combineRecursive(mainLab, sourceExtConfig('ws01').lab_extension);
  assert.equal(joinedBad.hosts.ws01.domain, STOCK_FQDN);
  assert.equal(joinedBad.domains[joinedBad.hosts.ws01.domain], undefined,
    'the unmodified pinned source ws01 config must FAIL this join, or the positive above proves nothing');
});

test('lx01: the second hop resolves too — domains[d].dc -> hosts[dc].hostname -> dc_fqdn', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const mainLab = out.config.lab;

  const joined = combineRecursive(mainLab, JSON.parse(out.extensionConfigs.lx01).lab_extension);
  const memberDomain = joined.hosts.lx01.domain;
  assert.ok(joined.domains[memberDomain], 'lab.domains[lab.hosts.lx01.domain] is undefined');
  const dcKey = joined.domains[memberDomain].dc;
  assert.ok(joined.hosts[dcKey], `domains[${memberDomain}].dc = ${dcKey} resolves to no host`);
  assert.equal(`${joined.hosts[dcKey].hostname}.${memberDomain}`, `${ROSTER_NAME}.cy400test.org`);

  const joinedBad = combineRecursive(mainLab, sourceExtConfig('lx01').lab_extension);
  assert.equal(joinedBad.domains[joinedBad.hosts.lx01.domain], undefined,
    'the unmodified pinned source lx01 config must FAIL the first hop');
});

test('lx01\'s prefix-less local_groups are a NO-OP, not a refusal', () => {
  // sudoers/ssh carry BARE group names. Refusing them would make the one
  // extension that needs no principal rewriting the one that cannot be
  // rewritten at all.
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const lx = JSON.parse(out.extensionConfigs.lx01).lab_extension.hosts.lx01;
  assert.deepStrictEqual(lx.local_groups, sourceExtConfig('lx01').lab_extension.hosts.lx01.local_groups);
  assert.ok(!JSON.stringify(lx.local_groups).includes(BACKSLASH));
});

test('the ws01 NetBIOS prefix comes from the RENAMED MAIN config, not from the new FQDN\'s first label', () => {
  // In stock GOAD the two coincide. ad/SCCM (sccm.lab, netbios_name SCCMLAB) is
  // where they do not, so this forces the main config to be the source.
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const mainLab = JSON.parse(JSON.stringify(out.config.lab));
  mainLab.domains['cy400test.org'].netbios_name = 'CORPNETBIOS';

  const rewritten = R.rewriteExtensionConfig(
    sourceExtConfig('ws01'),
    mainLab,
    R.buildRenameMap(
      R.stockSideOf(EXT_BASE.ws01, null),
      { fqdn: 'cy400test.org', hosts: { ws01: 'ws01' } }));

  const members = rewritten.lab_extension.hosts.ws01.local_groups.Administrators;
  for (const m of members) {
    assert.ok(m.startsWith(`CORPNETBIOS${BACKSLASH}`),
      `${JSON.stringify(m)} took its prefix from the FQDN's first label instead of the main `
      + "config's netbios_name — the SCCM case (sccm.lab / SCCMLAB) is where that is wrong");
  }
});

test('ws01\'s local_admin_password is byte-identical and still matches its stock inventory literal', (t) => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const stock = sourceExtConfig('ws01').lab_extension.hosts.ws01.local_admin_password;
  assert.equal(JSON.parse(out.extensionConfigs.ws01).lab_extension.hosts.ws01.local_admin_password, stock);

  // The coupling is DORMANT on proxmox — the ansible_password= branch is only
  // rendered for aws/azure — which is exactly why nothing else in the pipeline
  // would notice it drifting.
  const inv = path.join(R.resolveGoadSourceDir(), 'extensions', 'ws01', 'inventory');
  if (!fs.existsSync(inv)) {
    t.skip('The external GOAD source is not available on this machine');
    return;
  }
  assert.ok(fs.readFileSync(inv, 'utf8').includes(`ansible_password=${stock}`),
    'ws01\'s local_admin_password no longer matches the ansible_password= literal in its inventory');
});

test('an extension shipping its own `domains` block is refused — the exchange case', () => {
  assert.throws(
    () => R.rewriteExtensionConfig(
      { lab_extension: { hosts: {}, domains: { 'the.eyrie': {} } } },
      R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' }).config.lab,
      mapTo('cy400test.org')),
    (e) => e.code === R.REBRAND_CODES.EXTENSION);
});

// ════════════════════════════════════════════════════════════════════════════
// 6. IDENTITY FALLBACK — every existing lane must be byte-identical to today
// ════════════════════════════════════════════════════════════════════════════

test('an explicit rename with an unusable domain fails before allocation', () => {
  for (const domain of ['', '   ', 'N/A', 'https://cy400test.org:443/lab', STOCK_FQDN, null, undefined]) {
    const spec = { goad: { version:'GOAD-Mini', domain, rename_forest:true } };
    assert.throws(() => R.rebrandGoadSpec(spec), e => e.code === R.REBRAND_CODES.UNUSABLE_DOMAIN);
  }
});

test('.local can never become a renamed forest, even though the Designer only warns about it', () => {
  // checkForestRoot warns (every shipped lab is .local and its name lives in
  // NTDS inside a golden image); publicDomainOf refuses. Surfacing that
  // asymmetry here is what stops an author getting a green canvas and a lane
  // that silently kept sevenkingdoms.local.
  const v = R.describeRebrand({ goad: { version: 'GOAD-Mini', domain: 'cy400test.local', rename_forest: true } });
  assert.equal(v.willRebrand, false);
  assert.equal(v.code, R.REBRAND_CODES.UNUSABLE_DOMAIN);
});

test('MIGRATION GUARD: every stored GOAD-Mini spec today rebrands NOTHING', () => {
  // lab-templates.js defaults EVERY goad spec to cybersaguaros.local/tumamoc
  // regardless of lab, so `domain !== forestRoot` is true for every stored
  // GOAD-Mini spec. A derived trigger would recompile all of them into a forest
  // nobody chose, on their next deploy. The opt-in is the explicit key.
  const spec = {
    goad: { version: 'GOAD-Mini', domain: 'cybersaguaros.local', child_subdomain: 'tumamoc' },
    vms: [{ name: 'DC01' }],
  };
  assert.strictEqual(R.rebrandGoadSpec(spec), spec);
  assert.equal(R.describeRebrand(spec).code, R.REBRAND_CODES.NOT_REQUESTED);

  // Even with a perfectly good public domain, absent the opt-in.
  const spec2 = { goad: { version: 'GOAD-Mini', domain: 'cy400test.org' }, vms: [{ name: 'DC01' }] };
  assert.strictEqual(R.rebrandGoadSpec(spec2), spec2);
});

test('an explicit rename with no source contract refuses without stock fallback', () => {
  const spec = { goad: { version:'NHA', domain:'cy400test.org', rename_forest:true } };
  assert.throws(() => R.rebrandGoadSpec(spec), e => e.code === R.REBRAND_CODES.NO_BASE_TREE);
  assert.equal(R.describeRebrand(spec).code, R.REBRAND_CODES.NO_BASE_TREE);
  assert.equal(R.loadBaseLab('NHA'), null);
  assert.equal(R.loadBaseLab('../../etc'), null);
});

test('applying the funnel twice is a no-op, not a refusal', () => {
  // The funnel sits inside a retry and inside challenge-lane-deployer's
  // swallowing catch. One that refused its own output would turn a harmless
  // re-entry into a failed lane — and the failure would be attributed to GOAD.
  const spec = { goad: { version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true }, vms: [{ name: 'DC01' }] };
  const once = R.rebrandGoadSpec(spec);
  assert.strictEqual(R.rebrandGoadSpec(once), once);
  assert.equal(R.describeRebrand(once).code, R.REBRAND_CODES.ALREADY_REBRANDED);
});

test('prebaked and already-generated specs THROW — a silent fallback there is the original bug', () => {
  assert.throws(
    () => R.rebrandGoadSpec({ goad: { version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true, prebaked: true } }),
    (e) => e.code === R.REBRAND_CODES.PREBAKED);
  assert.throws(
    () => R.rebrandGoadSpec({
      goad: {
        version: 'CIAB-3f9a2c1b', domain: 'cy400test.org', rename_forest: true,
        generated_lab: { name: 'CIAB-3f9a2c1b', files: {}, chain: ['build.yml'] },
      },
    }),
    (e) => e.code === R.REBRAND_CODES.ALREADY_GENERATED);
});

test('a rebranded spec carries only an identity plan and leaves the original untouched', () => {
  const spec = Object.freeze({
    goad: Object.freeze({ version: 'GOAD-Mini', domain: 'cy400test.org', rename_forest: true }),
    vms: [{ name: 'DC01' }],
  });
  const out = R.rebrandGoadSpec(spec);
  assert.notStrictEqual(out, spec);
  assert.equal(spec.goad.version, 'GOAD-Mini', 'the caller\'s spec was mutated');

  assert.match(out.goad.version, /^CC-GOADMINI-CY400TEST-[0-9a-f]{8}$/);
  assert.equal(out.goad.rename_plan.lab_name, out.goad.version);
  assert.equal(out.goad.generated_lab, undefined);
  assert.equal(out.goad.lab.forestRoot, 'cy400test.org');
  // extensionsForLab matches ext.compatibility against the lab name; ws01
  // declares ['GOAD','GOAD-Light','GOAD-Mini'], so without baseLab a minted
  // name drops it from the roster in silence and assertGoadRoster then fails
  // complaining about a stray machine.
  assert.equal(out.goad.lab.baseLab, 'GOAD-Mini');
  assert.deepStrictEqual(out.goad.rename_plan.expected_identities,
    [{ name: 'DC01', hostname: 'DC01', domain: 'cy400test.org' }]);
});

// ════════════════════════════════════════════════════════════════════════════
// 7. DETERMINISM
// ════════════════════════════════════════════════════════════════════════════

test('two runs produce byte-identical output and the same minted lab name', () => {
  const a = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const b = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  assert.equal(a.labName, b.labName);
  assert.deepStrictEqual(Object.keys(a.files), Object.keys(b.files));
  for (const p of Object.keys(a.files)) {
    if (Buffer.isBuffer(a.files[p])) assert.ok(a.files[p].equals(b.files[p]), `${p} differs`);
    else assert.equal(a.files[p], b.files[p], `${p} differs`);
  }
  assert.deepStrictEqual(a.extensionConfigs, b.extensionConfigs);

  // Determinism is what makes a redeploy hit pushLabTree's tree_sha256
  // short-circuit instead of re-pushing. It has to be a function of CONTENT: a
  // different domain must mint a different name.
  assert.notEqual(a.labName, R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy401test.org' }).labName);
});

test('the minted name changes when the transform does, so stale bytes cannot survive the sha short-circuit', () => {
  const args = { baseLab: 'GOAD-Mini', fqdn: 'cy400test.org', netbios: 'CY400TEST', hostnames: { dc01: 'DC01' }, goadRef: 'abc' };
  assert.notEqual(R.mintLabName(args), R.mintLabName({ ...args, goadRef: 'def' }));
  assert.notEqual(R.mintLabName(args), R.mintLabName({ ...args, hostnames: { dc01: 'DC02' } }));
});

// ════════════════════════════════════════════════════════════════════════════
// Contracts with the code on the other side of the push
// ════════════════════════════════════════════════════════════════════════════

test('the emitted tree survives the real assertLabName / assertChain / buildLabArchive', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  assert.equal(PUSH.assertLabName(out.labName), out.labName);
  assert.deepStrictEqual(PUSH.assertChain(out.chain), MINI_BASE.chain);
  for (const p of Object.keys(out.files)) assert.equal(PUSH.normalizeMemberPath(p), p);

  // buildLabArchive runs normalizeFiles and toBytes for real, which is the
  // step that would reject a Buffer round-tripped through JSON — the reason
  // this transform runs at DEPLOY time and is never persisted to JSONB.
  const archive = PUSH.buildLabArchive(out.files);
  assert.ok(archive.tarBytes > 0 && archive.treeSha256.length === 64);
  // Determinism all the way to the sha the push short-circuits on.
  assert.equal(
    PUSH.buildLabArchive(R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' }).files).treeSha256,
    archive.treeSha256);

  assert.throws(
    () => PUSH.buildLabArchive({ ...out.files, 'files/dc01/templates/ESC1.json': JSON.parse(JSON.stringify(out.files['files/dc01/templates/ESC1.json'])) }),
    /must be a string or Buffer/,
    'a Buffer that went through JSON becomes {type:"Buffer",data:[…]} and the pusher refuses it — '
    + 'at push time, on a live lane');
});

test('the CC- prefix is collision-proof against RESERVED_LAB_NAMES, read as SOURCE TEXT', () => {
  // Read as text, not required, because core must never depend on the CiAB
  // plugin being installed — this test is the only thing holding the two
  // together and it has to hold without importing across that line.
  const src = fs.readFileSync(
    path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab', 'utils', 'goad-lab-push.js'),
    'utf8');
  const block = /const RESERVED_LAB_NAMES = Object\.freeze\(\[([\s\S]*?)\]\)/.exec(src);
  assert.ok(block, 'RESERVED_LAB_NAMES is no longer spelled the way this test finds it');
  const names = [...block[1].matchAll(/'([^']+)'/g)].map((m) => m[1]);
  assert.ok(names.includes('GOAD-Mini') && names.includes('SCCM'), 'unexpected reserved list');
  for (const n of names) {
    assert.ok(!n.startsWith('CC-'),
      `RESERVED_LAB_NAMES now contains ${n}, which collides with the minted CC- prefix. pushLabTree `
      + 'swaps the whole ad/<name>/ directory and there is no undo.');
  }
  assert.ok(src.includes(String(R.LAB_NAME_RE)),
    `goad-lab-push.js no longer spells LAB_NAME_RE as ${R.LAB_NAME_RE}; the duplicate in `
    + 'goad-lab-rebrand.js has drifted and a name this module mints could be refused mid-push');
});

test('the duplicated DN helpers agree with goad-lab-validate\'s originals', () => {
  const corpus = [
    'sevenkingdoms.local', 'cy400test.org', 'lab.cy400test.org', 'a.b.c.d', 'corpnet', '', null,
  ];
  for (const fqdn of corpus) {
    assert.equal(R.rootDnForDomain(fqdn), VALIDATE.rootDnForDomain(fqdn), `rootDnForDomain(${fqdn})`);
  }
  for (const dn of [
    'CN=AdminSDHolder,CN=System,DC=sevenkingdoms,DC=local',
    'OU=Crownlands, DC=SevenKingdoms , DC=Local',
    'DC=a', '', null,
  ]) {
    assert.equal(R.normalizeDn(dn), VALIDATE.normalizeDn(dn), `normalizeDn(${dn})`);
  }
  // The DN-shaped predicate, pinned as source text against the one site that
  // uses it in goad-lab-validate.js.
  const validateSrc = fs.readFileSync(
    path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab', 'utils', 'goad-lab-validate.js'),
    'utf8');
  const rebrandSrc = fs.readFileSync(path.join(__dirname, 'support', 'goad-rebrand-oracle.js'), 'utf8');
  const predicate = '/(^|,)\\s*(CN|OU|DC)=/i';
  assert.ok(validateSrc.includes(predicate), 'goad-lab-validate.js no longer spells the DN predicate this way');
  assert.ok(rebrandSrc.includes(predicate), 'goad-lab-rebrand.js no longer spells the DN predicate this way');
});

test('the transform module has ZERO requires into modules/crucible/plugins/', () => {
  // Core has to work on an install where the CiAB plugin is absent. A require
  // across that line would only fail on such an install — i.e. not here.
  const src = fs.readFileSync(path.join(__dirname, '..', 'src', 'utils', 'goad-lab-rebrand.js'), 'utf8');
  for (const m of src.matchAll(/require\(\s*['"]([^'"]+)['"]\s*\)/g)) {
    assert.ok(!/plugins|crucible|ciab/.test(m[1]),
      `goad-lab-rebrand.js requires ${m[1]}; core must not depend on the CiAB plugin being installed`);
  }
});

test('the emitted config is strict JSON with no carriage return — the pusher refuses both', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  for (const [name, text] of [
    ['data/config.json', out.files['data/config.json']],
    ['ws01', out.extensionConfigs.ws01],
    ['lx01', out.extensionConfigs.lx01],
  ]) {
    // DRACARYS's own config.json has an illegal trailing comma and works only
    // because ansible reads it through a YAML loader, so "ansible accepted it"
    // is not evidence that a config is JSON.
    assert.doesNotThrow(() => JSON.parse(text), `${name} is not strict JSON`);
    assert.ok(!text.includes(String.fromCharCode(13)), `${name} carries a CR`);
    assert.ok(text.endsWith(LF), `${name} has no trailing newline`);
  }
});

test('a multi-domain config is refused outright, not renamed halfway', () => {
  const stock = sourceConfig();
  stock.lab.domains['essos.local'] = { dc: 'dc03', domain_password: 'x', netbios_name: 'ESSOS' };
  assert.throws(() => R.rewriteLabConfig(stock, mapTo('cy400test.org')),
    (e) => e.code === R.REBRAND_CODES.MULTI_DOMAIN);

  const trusting = sourceConfig();
  trusting.lab.domains[STOCK_FQDN].trust = 'essos.local';
  assert.throws(() => R.rewriteLabConfig(trusting, mapTo('cy400test.org')),
    (e) => e.code === R.REBRAND_CODES.MULTI_DOMAIN);
});

test('a principal in another domain is refused rather than silently re-prefixed', () => {
  const stock = sourceConfig();
  stock.lab.hosts.dc01.local_groups.Administrators.push(`essos${BACKSLASH}daenerys.targaryen`);
  assert.throws(() => R.rewriteLabConfig(stock, mapTo('cy400test.org')),
    (e) => e.code === R.REBRAND_CODES.FOREIGN_PRINCIPAL);
});

test('data/inventory keeps every host key — dns_domain=dc01 is NOT a DNS name', () => {
  const out = R.rebrandLab({ baseLab: 'GOAD-Mini', domain: 'cy400test.org' });
  const prov = out.files['providers/proxmox/inventory'];
  assert.ok(prov.includes('dns_domain=dc01'), 'dns_domain is an inventory host key, not a name');
  assert.ok(prov.includes('dict_key=dc01'));
  assert.ok(prov.includes('{{ip_range}}.10'), 'the lane substitutes {{ip_range}}; it must survive');
  assert.ok(prov.includes('; cy400test.org'), 'the banner comment still names the old forest');

  const inv = out.files['data/inventory'];
  for (const section of ['[domain]', '[dc]', '[parent_dc]', '[adcs]']) {
    assert.ok(inv.includes(section), `${section} was dropped from data/inventory`);
  }
  assert.equal(inv.split(LF).length, sourceText('data/inventory').split(LF).length,
    'the inventory gained or lost a line; only the domain_name= value may change');
});
