/**
 * ad-domain-rules.test.js — one rulebook, three readers, and the corpus that
 * keeps them the same rulebook.
 *
 * The AD naming rules exist in three places, and they have to, because each
 * runtime can only reach one of them:
 *
 *   src/utils/ad-domain-rules.js            core — the create handler's validator
 *   public/js/topology/ad-domain-rules.js   browser — the GOAD card's field errors
 *   .../ciab/utils/goad-lab-compile.js      the plugin compiler, which MINTS
 *                                           domains for a generated lab
 *
 * Core must never require into a plugin, so the compiler cannot be the shared
 * home even though it got here first; and public/ is served to a browser, not
 * required by Node. This is the same arrangement as resolveVmSegments /
 * deriveSegments — "two shapes, two readers, one rule" — and this file is the
 * price of it: every case below runs through EVERY copy and the answers must
 * match. A rule changed in one and not the others fails here rather than
 * producing a forest name the compiler would refuse and the Designer accept.
 *
 * ── THE RULE WORTH THE MOST ─────────────────────────────────────────────────
 * A child FQDN must be EXACTLY `<label>.<parent>`. GOAD's ad-child_domain.yml:20
 * derives parent_domain by dropping the child's first label and then reads
 * lab.domains[parent].domain_password WITH NO DEFAULT. Any other shape resolves
 * a domain that does not exist and kills the whole play — not the child stage,
 * the play.
 *
 * Run: node front-end/test/ad-domain-rules.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..');

const core = require(path.join(ROOT, 'src', 'utils', 'ad-domain-rules.js'));
const compiler = require(path.join(
  ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'utils', 'goad-lab-compile.js'));

/** The browser copy, loaded the way topology-editor-derive.test.js loads its mirror. */
function loadBrowser() {
  const sandbox = { console };
  sandbox.window = sandbox;
  vm.createContext(sandbox);
  vm.runInContext(
    fs.readFileSync(path.join(ROOT, 'public', 'js', 'topology', 'ad-domain-rules.js'), 'utf8'),
    sandbox, { filename: 'ad-domain-rules.js' });
  return sandbox.CyberCoreAdDomainRules;
}
const browser = loadBrowser();

// ── the shared corpus ───────────────────────────────────────────────────────
//
// Every shape the rules distinguish, plus the ones that have actually turned up
// in this field: an LLM-authored 'N/A', a pasted URL, a bare word, a legacy
// .local, and the six domains CyberCore's own GOAD labs are named under.
const CORPUS = [
  // legal
  'corp.acme.com', 'acme.com', 'a.co', 'north-side.example-corp.io',
  'sub.deep.example.org', 'x'.repeat(63) + '.com',
  // the labs we ship (five of six are reserved-TLD; two are not)
  'cybersaguaros.local', 'sevenkingdoms.local', 'ninja.hack', 'sccm.lab', 'dracarys.lab',
  'tumamoc.cybersaguaros.local', 'north.sevenkingdoms.local', 'academy.ninja.lan',
  // reserved TLDs, one each
  'a.invalid', 'a.test', 'a.example', 'a.localhost', 'a.internal', 'a.lan', 'a.home',
  'a.arpa', 'a.onion',
  // malformed
  '', '   ', 'N/A', 'none', 'acme', 'acme.', '.acme.com', 'acme..com', '-acme.com',
  'acme-.com', 'ACME.COM', 'acme.c', 'acme.123', 'acme.c0m', 'acme com', 'acme_corp.com',
  'x'.repeat(64) + '.com', 'x'.repeat(250) + '.com',
  // things people paste
  'https://www.acme.com/about', 'www.acme.com', 'acme.com.', 'HTTP://ACME.COM',
  // non-strings
  null, undefined, 0, 42, {}, [],
];

const SEEDS = [
  'acme', 'Acme Health', 'north', 'NORTH', '  spaced  ', '123', '---', '',
  'a-very-long-company-name-indeed', 'Ünïcødé Corp', 'x_y', null, undefined, 42,
];

// ── 1. the three copies agree ───────────────────────────────────────────────

test('publicDomainOf: core and the CiAB compiler return the same answer for every case', () => {
  for (const raw of CORPUS) {
    assert.strictEqual(core.publicDomainOf(raw), compiler.publicDomainOf(raw),
      `publicDomainOf(${JSON.stringify(raw)}) — core and goad-lab-compile disagree. The compiler is `
      + 'what generates a lab; the Designer is what authors one. If they disagree, an author can save a '
      + 'forest name the compiler would have refused.');
  }
});

test('publicDomainOf: the browser mirror agrees with core too', () => {
  for (const raw of CORPUS) {
    assert.strictEqual(browser.publicDomainOf(raw), core.publicDomainOf(raw),
      `publicDomainOf(${JSON.stringify(raw)}) — the browser mirror has drifted from core`);
  }
});

test('netbiosCandidate: all three agree', () => {
  for (const seed of SEEDS) {
    const c = core.netbiosCandidate(seed);
    assert.strictEqual(c, compiler.netbiosCandidate(seed),
      `netbiosCandidate(${JSON.stringify(seed)}) — core vs the CiAB compiler`);
    assert.strictEqual(c, browser.netbiosCandidate(seed),
      `netbiosCandidate(${JSON.stringify(seed)}) — core vs the browser mirror`);
  }
});

test('the reserved TLD set is literally the same set in all three', () => {
  // A TLD added to one and not the others is the quietest possible drift: the
  // Designer accepts a name, and the compiler refuses the same name months
  // later on a generated lab.
  const fromCore = [...core.RESERVED_TLDS].sort();
  const fromBrowser = [...browser.RESERVED_TLDS].sort();
  assert.deepStrictEqual(fromBrowser, fromCore);
  const compilerSrc = fs.readFileSync(path.join(
    ROOT, 'modules', 'crucible', 'plugins', 'ciab', 'utils', 'goad-lab-compile.js'), 'utf8');
  for (const tld of fromCore) {
    assert.ok(new RegExp(`'${tld}'`).test(compilerSrc),
      `'${tld}' is reserved here but does not appear in goad-lab-compile's RESERVED_TLDS`);
  }
  assert.deepStrictEqual(fromCore,
    ['arpa', 'example', 'home', 'internal', 'invalid', 'lan', 'local', 'localhost', 'onion', 'test']);
});

test('suffixRelated agrees, including the mirror-image direction', () => {
  const pairs = [
    ['corp.acme.com', 'corp.acme.com'],
    ['north.corp.acme.com', 'corp.acme.com'],
    ['corp.acme.com', 'north.corp.acme.com'],
    ['corp.acme.com', 'corp.other.com'],
    ['acme.com', 'notacme.com'],   // shares a tail but not a LABEL boundary
  ];
  for (const [a, b] of pairs) {
    const c = core.suffixRelated(a, b);
    assert.strictEqual(c, compiler.suffixRelated
      ? compiler.suffixRelated(a, b) : c, `suffixRelated(${a}, ${b}) vs the compiler`);
    assert.strictEqual(c, browser.suffixRelated(a, b), `suffixRelated(${a}, ${b}) vs the browser`);
  }
  assert.strictEqual(core.suffixRelated('acme.com', 'notacme.com'), false,
    'a shared tail is not a suffix relation — the boundary is a dot, or ad-trusts.yml builds a trust '
    + 'between two unrelated forests');
});

test('checkForestRoot / checkChild: core and the browser mirror agree on every case', () => {
  const parents = ['corp.acme.com', 'cybersaguaros.local', ''];
  const children = ['tumamoc', 'north', 'tumamoc.cybersaguaros.local', 'north.sevenkingdoms.local',
    'a.b.corp.acme.com', 'other.com', '', '-bad', 'bad-', 'Ünïcødé', 'x'.repeat(64)];
  for (const raw of CORPUS) {
    const a = core.checkForestRoot(raw);
    const b = browser.checkForestRoot(raw);
    assert.strictEqual(a.value, b.value, `checkForestRoot(${JSON.stringify(raw)}).value`);
    // JSON, not deepStrictEqual: the mirror's arrays carry the vm context's own
    // Array.prototype, which deepStrictEqual reads as a different type.
    assert.strictEqual(JSON.stringify(a.errors), JSON.stringify(b.errors),
      `checkForestRoot(${JSON.stringify(raw)}).errors`);
    assert.strictEqual(JSON.stringify(a.warnings), JSON.stringify(b.warnings),
      `checkForestRoot(${JSON.stringify(raw)}).warnings`);
  }
  for (const p of parents) {
    for (const c of children) {
      const a = core.checkChild(c, p);
      const b = browser.checkChild(c, p);
      assert.strictEqual(a.fqdn, b.fqdn, `checkChild(${JSON.stringify(c)}, ${JSON.stringify(p)}).fqdn`);
      assert.strictEqual(a.label, b.label, `checkChild(${JSON.stringify(c)}, ${JSON.stringify(p)}).label`);
      assert.strictEqual(JSON.stringify(a.errors), JSON.stringify(b.errors),
        `checkChild(${JSON.stringify(c)}, ${JSON.stringify(p)}).errors`);
      assert.strictEqual(JSON.stringify(a.warnings), JSON.stringify(b.warnings),
        `checkChild(${JSON.stringify(c)}, ${JSON.stringify(p)}).warnings`);
    }
  }
});

// ── 2. FQDN shape ───────────────────────────────────────────────────────────

test('a forest root needs at least two labels, lowercase, with internal hyphens only', () => {
  for (const bad of ['acme', 'N/A', '-acme.com', 'acme-.com', 'acme..com', 'acme_corp.com', 'acme com']) {
    const r = core.checkForestRoot(bad);
    assert.strictEqual(r.value, null, `${bad} should be refused`);
    assert.ok(r.errors.length, `${bad} should ERROR, not warn`);
  }
  assert.strictEqual(core.checkForestRoot('corp.acme.com').value, 'corp.acme.com');
  assert.strictEqual(core.checkForestRoot('  CORP.ACME.COM  ').value, 'corp.acme.com',
    'the field is typed by hand — case and whitespace are normalised, not refused');
});

test('a pasted URL is reduced rather than refused', () => {
  assert.strictEqual(core.checkForestRoot('https://www.acme.com/about').value, 'acme.com',
    'this field gets pasted from a browser bar at least as often as it is typed');
});

test('a label over 63 characters is an error, and a numeric TLD is too', () => {
  assert.match(core.checkForestRoot('x'.repeat(64) + '.com').errors[0], /caps a label at 63/);
  assert.match(core.checkForestRoot('acme.123').errors[0], /two or more letters, no digits/);
  assert.match(core.checkForestRoot('acme.c').errors[0], /two or more letters/);
});

test('an empty forest root is an error — the deploy has to greet the lane by something', () => {
  assert.match(core.checkForestRoot('').errors[0], /required/);
});

// ── 3. the legacy-defaults trap: .local WARNS, never errors ─────────────────

test('THE TRAP: .local is a WARNING, so an unedited legacy lab still authors', () => {
  // Every GOAD lab CyberCore ships is named under a reserved TLD or was, and
  // those names live in NTDS inside a golden image — renaming a forest is a
  // `rendom` operation, not a field edit. Hard-failing .local here would make
  // the shipped labs unauthorable.
  const r = core.checkForestRoot('cybersaguaros.local');
  assert.deepStrictEqual(r.errors, [], '.local must NOT block a save');
  assert.strictEqual(r.value, 'cybersaguaros.local', 'and the value must survive to be stored');
  assert.strictEqual(r.warnings.length, 1);
  assert.match(r.warnings[0], /mDNS-reserved/);
  assert.match(r.warnings[0], /mail relay/);
});

test('the compiler still REFUSES what the Designer only warns about — deliberately', () => {
  // The asymmetry is the point and it is stated in the warning text: a
  // hand-authored legacy lab authors, a GENERATED one with the same name does
  // not. publicDomainOf is the shared predicate that makes both true.
  assert.strictEqual(core.publicDomainOf('cybersaguaros.local'), null);
  assert.strictEqual(compiler.publicDomainOf('cybersaguaros.local'), null);
  assert.strictEqual(core.checkForestRoot('cybersaguaros.local').errors.length, 0);
});

test('every reserved TLD warns rather than errors', () => {
  for (const tld of core.RESERVED_TLDS) {
    const r = core.checkForestRoot(`acme.${tld}`);
    assert.deepStrictEqual(r.errors, [], `.${tld} must not block`);
    assert.strictEqual(r.warnings.length, 1, `.${tld} must warn`);
  }
});

test('the six labs we ship all author without an error', () => {
  const goad = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));
  for (const [key, lab] of Object.entries(goad.GOAD_LABS)) {
    const r = core.validateGoadDomains({ domain: lab.forestRoot, child_subdomain: lab.childSubdomain });
    assert.deepStrictEqual(r.errors, [], `${key} (${lab.forestRoot}) must author cleanly`);
    assert.strictEqual(r.domain, lab.forestRoot);
  }
});

// ── 4. THE CHILD SUFFIX RULE ────────────────────────────────────────────────

test('a bare label becomes <label>.<parent>', () => {
  const r = core.checkChild('tumamoc', 'cybersaguaros.local');
  assert.strictEqual(r.label, 'tumamoc');
  assert.strictEqual(r.fqdn, 'tumamoc.cybersaguaros.local');
  assert.deepStrictEqual(r.errors, []);
});

test('a full FQDN is accepted and reduced to its label', () => {
  const r = core.checkChild('tumamoc.cybersaguaros.local', 'cybersaguaros.local');
  assert.strictEqual(r.label, 'tumamoc', 'an author who types the whole name is not punished');
  assert.strictEqual(r.fqdn, 'tumamoc.cybersaguaros.local');
});

test('THE PLAY-KILLER: a child that is not inside its parent is an ERROR', () => {
  const r = core.checkChild('north.sevenkingdoms.local', 'cybersaguaros.local');
  assert.strictEqual(r.fqdn, null);
  assert.strictEqual(r.errors.length, 1);
  assert.match(r.errors[0], /ad-child_domain\.yml/);
  assert.match(r.errors[0], /no fallback/);
});

test('THE PLAY-KILLER, second shape: a GRANDCHILD is an error too', () => {
  // ad-child_domain.yml drops exactly ONE label to find the parent, so
  // a.b.corp.acme.com resolves 'b.corp.acme.com' — a domain that does not exist
  // in lab.domains, and the lookup has no default.
  const r = core.checkChild('a.b.corp.acme.com', 'corp.acme.com');
  assert.strictEqual(r.fqdn, null);
  assert.match(r.errors[0], /drops exactly ONE label/);
  assert.match(r.errors[0], /b\.corp\.acme\.com/, 'the message names the child that WOULD work');
});

test('an empty child is legal — GOAD-Mini, SCCM, NHA and DRACARYS have one domain each', () => {
  for (const raw of ['', '   ', null, undefined]) {
    const r = core.checkChild(raw, 'corp.acme.com');
    assert.deepStrictEqual(r.errors, [], `${JSON.stringify(raw)} must not be an error`);
    assert.strictEqual(r.fqdn, null);
    assert.strictEqual(r.label, null);
  }
});

test('a malformed child label is an error, not a silent repair', () => {
  for (const bad of ['-north', 'north-', 'no rth', 'nor_th']) {
    const r = core.checkChild(bad, 'corp.acme.com');
    assert.ok(r.errors.length, `${bad} should be refused`);
    assert.strictEqual(r.fqdn, null);
  }
});

test('a child with no usable parent says so once, not twice', () => {
  const r = core.validateGoadDomains({ domain: 'N/A', child_subdomain: 'north' });
  assert.strictEqual(r.errors.length, 1, 'two errors that both mean "fix the forest domain" is noise');
  assert.match(r.errors[0], /not a DNS name/);
});

// ── 5. NetBIOS ──────────────────────────────────────────────────────────────

test('a NetBIOS candidate is never empty and never all digits', () => {
  assert.strictEqual(core.netbiosCandidate(''), 'CORP');
  assert.strictEqual(core.netbiosCandidate('123'), 'CORP');
  assert.strictEqual(core.netbiosCandidate('---'), 'CORP');
  assert.strictEqual(core.netbiosCandidate(null), 'CORP');
});

test('a NetBIOS candidate is capped at 15 and uppercased', () => {
  assert.strictEqual(core.netbiosCandidate('a-very-long-company-name-indeed').length,
    core.MAX_NETBIOS_HOSTNAME);
  assert.strictEqual(core.netbiosCandidate('acme'), 'ACME');
  assert.strictEqual(core.MAX_NETBIOS_HOSTNAME, 15);
});

test('netbiosForDomain takes the FIRST label — upstream north.sevenkingdoms.local is NORTH', () => {
  assert.strictEqual(core.netbiosForDomain('north.sevenkingdoms.local'), 'NORTH');
  assert.strictEqual(core.netbiosForDomain('corp.acme.com'), 'CORP');
});

test('a child whose label would be truncated warns about the name it will actually be known by', () => {
  const r = core.checkChild('a-very-long-child-label', 'corp.acme.com');
  assert.deepStrictEqual(r.errors, [], 'a long label is legal DNS — it is the NetBIOS name that suffers');
  assert.strictEqual(r.warnings.length, 1);
  // 15 characters of 'A-VERY-LONG-CHILD-LABEL' — the name the domain is actually
  // known by everywhere it is typed.
  assert.match(r.warnings[0], /A-VERY-LONG-CHI /);
  assert.strictEqual(core.netbiosCandidate('a-very-long-child-label'), 'A-VERY-LONG-CHI');
});

// ── 6. the whole-card check the two callers share ───────────────────────────

test('validateGoadDomains returns what both callers need in one shape', () => {
  const r = core.validateGoadDomains({ domain: 'CORP.Acme.COM ', child_subdomain: 'North' });
  assert.deepStrictEqual(r.errors, []);
  assert.strictEqual(r.domain, 'corp.acme.com');
  assert.strictEqual(r.child_label, 'north');
  assert.strictEqual(r.child_fqdn, 'north.corp.acme.com');
});

test('the create handler runs this module, and 400s on an error', () => {
  const src = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8');
  assert.match(src, /require\('\.\.\/utils\/ad-domain-rules'\)/,
    'the route must use the shared rulebook, not a second regex');
  assert.match(src, /adDomainRules\.validateGoadDomains\(/);
  assert.match(src, /if \(goadDomains\.errors\.length\) \{[\s\S]{0,200}status\(400\)/,
    'a malformed domain must be refused before a VXLAN block is reserved');
  assert.match(src, /child_subdomain:\s*goadDomains\.child_label/,
    'the spec stores the LABEL, which is the shape ad-child_domain.yml wants');
});

test('the Designer paints the same rulebook into #topoErrGoad', () => {
  const src = fs.readFileSync(path.join(ROOT, 'public', 'js', 'admin', 'admin-topology.js'), 'utf8');
  assert.match(src, /window\.CyberCoreAdDomainRules/);
  assert.match(src, /topoErrGoad/);
  // A warning must not be painted danger-red: .local is the state every shipped
  // lab is already in, and a permanent red slot trains people to ignore it.
  assert.match(src, /classList\.toggle\('is-warning'/);
});

// ── 7. the fields are no longer readonly, and no longer stale ───────────────

test('THE STALE-FIELD BUG: a version change resets both domain fields from the lab', () => {
  const src = fs.readFileSync(path.join(ROOT, 'public', 'js', 'admin', 'admin-topology.js'), 'utf8');
  assert.match(src, /function onTopoGoadVersionChange\(\)[\s\S]{0,600}resetTopoGoadDomainsFromLab\(\)/,
    'without this, picking GOAD-Mini leaves cybersaguaros.local on screen while the lab is '
    + 'sevenkingdoms.local — and the wrong value is what gets stored');
  assert.match(src, /childEl\.value = \(lab && lab\.childSubdomain\) \|\| '';/,
    'and the child must reset to the lab\'s own, or to nothing for a single-domain lab');
});

test('the two inputs are editable and the catalog serves the per-lab defaults', () => {
  const html = fs.readFileSync(path.join(ROOT, 'public', 'admin.html'), 'utf8');
  assert.ok(!/id="topoGoadDomain"[^>]*readonly/.test(html), 'the forest domain must be editable');
  assert.ok(!/id="topoGoadChild"[^>]*readonly/.test(html), 'the child subdomain must be editable');
  assert.match(html, /id="topoGoadDomain"[^>]*oninput="onTopoGoadDomainInput\(\)"/);

  const route = fs.readFileSync(path.join(ROOT, 'src', 'routes', 'lab-templates.js'), 'utf8');
  assert.match(route, /childSubdomain: lab\.childSubdomain === undefined \? null : lab\.childSubdomain/,
    'the catalog has to carry the per-lab child, or the reset above has nothing to reset FROM');
});

test('GOAD_LABS records the child each lab actually has, and null where it has none', () => {
  // Verified against GOAD-main/ad/<LAB>/data/config.json on disk. NHA is the
  // interesting one: academy.ninja.lan is NOT a suffix of ninja.hack, so it is a
  // TRUST partner, not a child — recording it as a child_subdomain would make
  // ad-child_domain.yml derive 'ninja.lan', which does not exist.
  const { GOAD_LABS } = require(path.join(ROOT, 'src', 'utils', 'goad-deploy.js'));
  assert.strictEqual(GOAD_LABS['GOAD-Light'].childSubdomain, 'tumamoc');
  assert.strictEqual(GOAD_LABS.GOAD.childSubdomain, 'north');
  assert.strictEqual(GOAD_LABS['GOAD-Mini'].childSubdomain, null);
  assert.strictEqual(GOAD_LABS.NHA.childSubdomain, null);
  assert.strictEqual(GOAD_LABS.SCCM.childSubdomain, null);
  assert.strictEqual(GOAD_LABS.DRACARYS.childSubdomain, null);

  // And each declared child really is a strict suffix extension of its root.
  for (const [key, lab] of Object.entries(GOAD_LABS)) {
    if (!lab.childSubdomain) continue;
    const r = core.checkChild(lab.childSubdomain, lab.forestRoot);
    assert.deepStrictEqual(r.errors, [], `${key}'s child must satisfy the suffix rule`);
    assert.strictEqual(r.fqdn, `${lab.childSubdomain}.${lab.forestRoot}`);
  }
});
