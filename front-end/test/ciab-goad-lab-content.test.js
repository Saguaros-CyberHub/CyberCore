/**
 * ciab-goad-lab-content.test.js - the per-lab files/ and scripts/ emitter.
 *
 * WHAT THIS FILE IS ACTUALLY DEFENDING
 * GOAD's two per-lab escape hatches take no parameters. `vulns/files` is a
 * byte-for-byte win_copy and `roles/ps` runs a static .ps1 with no arguments and
 * no return value, so every hostname, username and GPO name upstream ships is a
 * hardcoded constant and the CyberSaguaros reskin had to hand-edit all seven
 * scripts alongside the JSON. Per-client content therefore has to be EMITTED,
 * and the mistakes an emitter makes are all quiet:
 *
 *   - one template with the nouns swapped. Deploys perfectly, teaches the same
 *     lesson to every cohort, and the answer key claims it came from this
 *     client's risk profile.
 *   - a planted credential the directory was never built with. The student
 *     finds it, sprays it, and the exercise has no second act. Nothing errors.
 *   - a non-ASCII character in a .ps1. PowerShell 5.1 reads a BOM-less script as
 *     the ANSI code page, where the UTF-8 bytes of an em dash end in U+201D -
 *     which it accepts as a string delimiter. The string terminates early and
 *     the parse fails fifty lines later on a correct line.
 *   - a script that is not replay-safe. The runner recovers by re-running the
 *     failed playbook, so a script that throws on its second run turns one
 *     transient failure into a permanently unbuildable lab.
 *   - a secret in a script. roles/ps stages the .ps1 into the connection user's
 *     temp directory on the guest, so that is a credential on disk in a path
 *     nobody chose.
 *   - the domain administrator's password planted on a file share. compileLab
 *     makes every host's local_admin_password equal to its domain_password, and
 *     that is the credential Ansible itself connects with.
 *
 * WHY SO MANY TESTS RUN THE WHOLE COMPILER
 * The emitter's real contract is that its output can be merged into a compiled
 * lab and still pass goad-lab-validate and goad-preflight. Asserting that on a
 * lab this test compiled is worth more than asserting it on a fixture, because
 * a fixture is the thing most likely to be wrong in the same direction as the
 * code.
 *
 * Run: node --test front-end/test/ciab-goad-lab-content.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'modules/crucible/plugins/ciab/utils');

const content = require(path.join(UTILS, 'goad-lab-content.js'));
const chainMod = require(path.join(UTILS, 'goad-attack-chain.js'));
const compile = require(path.join(UTILS, 'goad-lab-compile.js'));
const validate = require(path.join(UTILS, 'goad-lab-validate.js'));
const preflight = require(path.join(UTILS, 'goad-preflight.js'));
// The web-facts contract's OWN reader. The site block is checked against the
// function the scan documents use, not against a copy of its rules.
const { readWebFacts } = require(path.join(ROOT,
  'modules/crucible/plugins/ciab/ai/scan-documents/service-inference.js'));

// -- fixture -----------------------------------------------------------------
// A composer-shaped labIR big enough that no technique is skipped for want of a
// principal or a host: two forests with a trust (so sIDHistory has something to
// disable), a member server in each (so RBCD has a resource its own DC can
// resolve) and a roster with room for the graph plus inert filler.

const FQDN = 'northgate.example';
const ROOT_DN = 'DC=northgate,DC=example';
const FQDN_B = 'harborline.example';
const ROOT_DN_B = 'DC=harborline,DC=example';

const USER_NAMES = [
  'amara.velez', 'brian.olusola', 'cara.nguyen', 'derek.mbeki', 'elena.rossi',
  'farid.haddad', 'greta.lindqvist', 'hugo.martins', 'ines.okafor', 'jonas.petrov',
  'kiara.dsouza', 'lucas.moreau', 'maya.torres', 'nils.berg', 'olive.hart', 'pedro.silva',
];
const GROUP_NAMES = [
  'ITOps', 'HelpDesk', 'Finance', 'ProjectAtlas', 'BackupOperatorsLite',
  'FacilitiesLeads', 'AuditReviewers',
];

function baseIr(seed) {
  return {
    run_id: seed,
    tier: 'L',
    lab_name: 'CIAB-abcdef12',
    domains: [
      {
        fqdn: FQDN, netbios: 'NORTHGATE', dc_host_key: 'dc01',
        is_forest_root: true, parent_fqdn: null, trust_fqdn: FQDN_B,
      },
      {
        fqdn: FQDN_B, netbios: 'HARBORLINE', dc_host_key: 'dc03',
        is_forest_root: true, parent_fqdn: null, trust_fqdn: FQDN,
      },
    ],
    hosts: [
      { key: 'dc01', hostname: 'NG-DC01', type: 'dc', domain: FQDN, path: ROOT_DN, roles: [] },
      { key: 'srv02', hostname: 'NG-SRV02', type: 'server', domain: FQDN, path: `OU=Servers,${ROOT_DN}`, roles: [] },
      { key: 'srv03', hostname: 'NG-SRV03', type: 'server', domain: FQDN, path: `OU=Servers,${ROOT_DN}`, roles: [] },
      { key: 'web01', hostname: 'NG-WEB01', type: 'server', domain: FQDN, path: `OU=Servers,${ROOT_DN}`, roles: ['web'] },
      { key: 'dc03', hostname: 'HB-DC03', type: 'dc', domain: FQDN_B, path: ROOT_DN_B, roles: [] },
      { key: 'srv04', hostname: 'HB-SRV04', type: 'server', domain: FQDN_B, path: ROOT_DN_B, roles: [] },
    ],
    principals: {
      users: USER_NAMES.map((sam, i) => ({
        sam,
        firstname: sam.split('.')[0],
        surname: sam.split('.')[1],
        password: `Seeded-${i}-Pw!`,
        description: '',
        city: 'Tucson',
        path: `OU=Staff,${ROOT_DN}`,
        domain: FQDN,
        groups: [],
        spns: [],
      })).concat([
        {
          sam: 'quinn.abara', firstname: 'quinn', surname: 'abara', password: 'Harbor-Side-71!',
          description: '', city: 'Tucson', path: ROOT_DN_B, domain: FQDN_B, groups: [], spns: [],
        },
        {
          sam: 'rosa.dietrich', firstname: 'rosa', surname: 'dietrich', password: 'Harbor-Side-72!',
          description: '', city: 'Tucson', path: ROOT_DN_B, domain: FQDN_B, groups: [], spns: [],
        },
      ]),
      groups: GROUP_NAMES.map((name) => ({
        name, scope: 'global', path: `OU=Groups,${ROOT_DN}`, domain: FQDN,
        managed_by: null, members: [],
      })),
      ous: [
        { name: 'Staff', path: ROOT_DN, domain: FQDN },
        { name: 'Groups', path: ROOT_DN, domain: FQDN },
        { name: 'Servers', path: ROOT_DN, domain: FQDN },
        { name: 'Harbour', path: ROOT_DN_B, domain: FQDN_B },
      ],
    },
  };
}

const irCache = {};
/** The labIR one seed produces, chain applied - which is the shape production
 *  hands the emitter (compileLab, then applyAttackChain, then this module). */
function irFor(seed) {
  if (!irCache[seed]) irCache[seed] = chainMod.applyAttackChain(baseIr(seed), { runId: seed });
  return irCache[seed];
}

const contentCache = {};
function contentFor(seed) {
  if (!contentCache[seed]) contentCache[seed] = content.generateLabContent(irFor(seed), { runId: seed });
  return contentCache[seed];
}

/**
 * The seeds this file pins.
 *
 * They are pinned rather than scanned because the claim is "these two clients
 * get different labs", and a scan that searched for a differing pair would pass
 * even if every other seed collided. Each was chosen for the chain shape it
 * lands on, named here so a chain-designer change that moves them is visible:
 *   golf   entry asrep,                pattern adcs_esc1      (AD-side entry)
 *   delta  entry open_share,           pattern acl_ladder     (file entry)
 *   alpha  entry user_equals_password, pattern delegation_abuse
 *   s11    entry web_credential,       pattern delegation_abuse
 */
const PINNED = Object.freeze(['golf', 'delta', 'alpha', 's11']);

/** A wider spread, for the properties that must hold on every lab rather than
 *  on one lucky one. */
const SEEDS = Object.freeze([
  'golf', 'delta', 'alpha', 's11', 'bravo', 'charlie', 'echo', 'foxtrot', 'hotel',
  's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10', 's12',
]);

function scriptsOf(c) {
  return Object.keys(c.tree).filter((p) => p.startsWith(content.SCRIPTS_PREFIX));
}
function filesOf(c) {
  return Object.keys(c.tree).filter((p) => p.startsWith(content.FILES_PREFIX));
}

// -- profile fixtures, for the tests that compile a real lab ------------------

function profileFixture(o) {
  return {
    json_data: {
      student_view: {
        meta: { run_id: o.runId, client_type: o.clientType || 'SMB', difficulty: 'intermediate' },
        quick: { company_name: o.company, employees_total: o.employees },
        raw: {
          threats: {
            organization: {
              company_name: o.company,
              domain_public: o.domain,
              employees_total: o.employees,
              hq_city: 'Tucson, AZ',
              industry: 'Professional Services',
              department_breakdown: { Operations: 20, Sales: 10, Finance: 6, IT: 4, Administration: 5 },
            },
            it_environment: { delivery: 'Hybrid' },
          },
        },
        stakeholders: [
          { name: 'Dr. Jane Smith', role: 'Chief Executive Officer', department: 'Executive' },
          { name: 'Marcus Webb', role: 'IT Manager', department: 'IT' },
        ],
      },
    },
  };
}

const REAL = Object.freeze({
  S: { runId: 'RUN_2026_RIDGELINE', company: 'Ridgeline Dental Group', domain: 'ridgelinedental.com', employees: 42 },
  M: { runId: 'RUN_2026_CASCADE', company: 'Cascade Freight Services', domain: 'cascadefreight.com', employees: 110 },
  L: {
    runId: 'RUN_2026_VANTAGE',
    company: 'Vantage Utilities Cooperative',
    domain: 'vantageutil.coop',
    employees: 320,
    clientType: 'Utility_IT_OT',
  },
});

const realCache = {};
/** A lab the real composer built, with content generated and merged back in. */
function realLab(key) {
  if (!realCache[key]) {
    const out = compile.compileLab(profileFixture(REAL[key]));
    const lab = JSON.parse(out.files['data/config.json']).lab;
    const c = content.generateLabContent(out.ir, { runId: REAL[key].runId, lab });
    realCache[key] = { out, lab, c, merged: content.mergeLabContent(lab, c) };
  }
  return realCache[key];
}

// ---------------------------------------------------------------------------
// C1. Determinism, and variety that is not one template
// ---------------------------------------------------------------------------

test('C1-100 the same seed regenerates a byte-identical tree', () => {
  for (const seed of PINNED) {
    const a = content.generateLabContent(irFor(seed), { runId: seed });
    const b = content.generateLabContent(irFor(seed), { runId: seed });
    assert.deepStrictEqual(Object.keys(a.tree), Object.keys(b.tree));
    for (const p of Object.keys(a.tree)) {
      assert.strictEqual(a.tree[p], b.tree[p], `${seed}: ${p} is not reproducible`);
    }
  }
});

test('C1-101 two seeds differ in FILENAMES, not just in the nouns inside them', () => {
  const a = filesOf(contentFor('golf'));
  const b = filesOf(contentFor('delta'));
  // Names that carry a hostname or a person differ for free; the interesting
  // claim is that the artifact NAMES a reader sees on the share differ too.
  const base = (list) => list.map((p) => p.split('/').pop()).sort();
  assert.notDeepStrictEqual(base(a), base(b));
  const shared = base(a).filter((n) => base(b).indexOf(n) !== -1);
  assert.ok(shared.length <= 3,
    `too many identical filenames between two labs (${shared.join(', ')}) - that is one template `
    + 'with the nouns swapped');
});

test('C1-102 two clients plant different credentials, in different places', () => {
  // Two REAL clients have two different rosters, so no credential can be shared
  // at all. This is the assertion that matters, and it is made against labs the
  // composer built rather than against the shared fixture roster.
  const secretsOf = (c) => new Set(c.files.flatMap((f) => f.secrets.map((s) => s.value)));
  const m = secretsOf(realLab('M').c);
  const l = secretsOf(realLab('L').c);
  assert.ok(m.size >= 4, 'a lab with fewer than four planted credentials is not a lab');
  for (const v of m) assert.ok(!l.has(v), `two clients both plant ${JSON.stringify(v)}`);

  // Two seeds over the SAME roster cannot have disjoint credentials - there are
  // only so many inert accounts and each lab spends most of them - so the claim
  // there is about the ASSIGNMENT: which account's password ends up in the
  // unattend rather than in the vault is itself part of what differs.
  const placement = (c) => c.files
    .filter((f) => f.secrets.length)
    .map((f) => `${f.kind}=${f.secrets[0].account}`)
    .sort();
  const a = placement(contentFor('golf'));
  const b = placement(contentFor('delta'));
  const same = a.filter((x) => b.indexOf(x) !== -1);
  assert.ok(same.length * 2 <= a.length,
    `${same.length} of ${a.length} credential placements are identical (${same.join(', ')})`);
});

test('C1-103 the PROSE differs after every noun is normalised away', () => {
  // The cheap version of this component passes a names-only test: one document
  // per artifact kind with the client's nouns substituted in. So strip every
  // noun that could differ (sams, hostnames, domains, digits) and require the
  // remaining English to still be different.
  const strip = (text, ir) => {
    let s = String(text);
    const cap = (w) => (w ? w.charAt(0).toUpperCase() + w.slice(1).toLowerCase() : w);
    for (const u of ir.principals.users) {
      s = s.split(u.sam).join('#U');
      // Both cases: the artifacts title-case a name for display and keep the
      // sAMAccountName verbatim, so a strip that only knew one form would leave
      // the other behind and this test would pass on a difference in names.
      for (const part of [u.firstname, u.surname]) {
        s = s.split(part).join('#F');
        s = s.split(cap(part)).join('#F');
      }
      s = s.split(u.password).join('#P');
    }
    for (const h of ir.hosts) s = s.split(h.hostname).join('#H');
    for (const d of ir.domains) {
      s = s.split(d.fqdn).join('#D');
      s = s.split(d.netbios).join('#N');
      s = s.split(d.fqdn.split('.')[0]).join('#O');
      s = s.split(d.fqdn.split('.')[0].replace(/^./, (m) => m.toUpperCase())).join('#O');
    }
    return s.replace(/\d+/g, '#').replace(/\s+/g, ' ').trim();
  };
  const letterOf = (seed) => {
    const c = contentFor(seed);
    const artifact = c.files.filter((f) => f.kind === 'onboarding_letter')[0];
    assert.ok(artifact, `${seed}: no onboarding letter was emitted`);
    return strip(c.tree[artifact.tree_path], irFor(seed));
  };
  assert.notStrictEqual(letterOf('golf'), letterOf('delta'),
    'two labs got the same letter with the names swapped');

  const configOf = (seed) => {
    const c = contentFor(seed);
    const artifact = c.files.filter((f) => f.kind === 'web_app_config')[0];
    return strip(c.tree[artifact.tree_path], irFor(seed));
  };
  assert.notStrictEqual(configOf('golf'), configOf('delta'));
});

test('C1-104 the variant pools are actually exercised across a spread of seeds', () => {
  // A pool that only ever draws its first entry is a pool in name only, and the
  // symptom is invisible until two clients compare notes.
  const seen = { web: new Set(), letter: new Set(), sheet: new Set(), vault: new Set() };
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    const nameOf = (kind) => {
      const a = c.files.filter((f) => f.kind === kind)[0];
      return a ? a.tree_path.split('/').pop().replace(/^[a-z]+-/, '') : null;
    };
    const web = nameOf('web_app_config');
    if (web) seen.web.add(web);
    const letter = c.files.filter((f) => f.kind === 'onboarding_letter')[0];
    // The letter's filename shape IS its variant (handover / welcome / ticket /
    // memo), so the prefix is the discriminator here.
    if (letter) seen.letter.add(letter.tree_path.split('/').pop().replace(/[^a-z-]/g, '').replace(/-+$/, ''));
    const sheet = nameOf('share_spreadsheet');
    if (sheet) seen.sheet.add(sheet);
    const vault = nameOf('credential_vault');
    if (vault) seen.vault.add(vault);
  }
  assert.ok(seen.web.size >= 4, `web config drew only ${seen.web.size} distinct forms`);
  assert.ok(seen.letter.size >= 3, `letter drew only ${seen.letter.size} distinct forms`);
  assert.ok(seen.sheet.size >= 3, `spreadsheet drew only ${seen.sheet.size} distinct forms`);
  assert.ok(seen.vault.size >= 3, `vault drew only ${seen.vault.size} distinct forms`);
});

test('C1-105 the SecureString blob and its key differ per lab', () => {
  const blobOf = (seed) => {
    const a = contentFor(seed).files.filter((f) => f.kind === 'sysvol_secret')[0];
    return a ? a.securestring.blob : null;
  };
  assert.ok(blobOf('golf'));
  assert.notStrictEqual(blobOf('golf'), blobOf('delta'));
  // GOAD's own blob decrypts to `powerkingftw135` on every lab that copies it.
  assert.ok(!blobOf('golf').includes('MgB8AGkAcwBDACsAUwArADIAcABRAEcARABnAGYAMwA3AEEAcgBFAEIAYQB2AEEAPQA9AHwA'),
    'the shipped GOAD blob was copied rather than generated');
});

// ---------------------------------------------------------------------------
// C2. ASCII
// ---------------------------------------------------------------------------

test('C2-100 every emitted member is pure ASCII, on every seed', () => {
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    for (const [p, body] of Object.entries(c.tree)) {
      const bad = content.firstNonAscii(body);
      assert.strictEqual(bad, null,
        bad ? `${seed}: ${p} carries ${bad.hex} at line ${bad.line}, column ${bad.column}` : '');
    }
  }
});

test('C2-101 assertAscii reports the line, the column and the codepoint', () => {
  const text = '$Target = \'ok\'\n$Note = "a dash \u2014 here"\n';
  assert.throws(() => content.assertAscii(text, 'scripts/x.ps1'), (err) => {
    assert.strictEqual(err.code, 'CONTENT_NOT_ASCII');
    assert.strictEqual(err.status, 409);
    assert.match(err.message, /U\+2014/);
    assert.match(err.message, /line 2/);
    assert.match(err.message, /column 17/);
    // The message has to say WHY, because the reader is looking at a file that
    // renders correctly in their editor.
    assert.match(err.message, /string delimiter/i);
    return true;
  });
  const found = content.firstNonAscii(text);
  assert.strictEqual(found.codepoint, 0x2014);
  assert.strictEqual(found.line, 2);
  assert.strictEqual(content.isAscii('plain ascii only'), true);
  assert.strictEqual(content.isAscii('smart \u201cquotes\u201d'), false);
});

test('C2-102 no member carries a BOM or a CR', () => {
  for (const seed of PINNED) {
    for (const [p, body] of Object.entries(contentFor(seed).tree)) {
      assert.ok(body.charCodeAt(0) !== 0xfeff, `${p} starts with a BOM`);
      assert.ok(body.indexOf('\r') === -1, `${p} contains a CR; win_copy is a byte copy`);
    }
  }
});

test('C2-103 assertContentSound rejects a member somebody edited to non-ASCII', () => {
  const c = contentFor('delta');
  const target = scriptsOf(c)[0];
  const doctored = Object.assign({}, c, {
    tree: Object.assign({}, c.tree, { [target]: `${c.tree[target]}\n# rotate before Q3 \u2014 TL\n` }),
  });
  assert.throws(() => content.assertContentSound(doctored, irFor('delta'), null), (err) => {
    assert.strictEqual(err.code, 'CONTENT_NOT_ASCII');
    return true;
  });
});

// ---------------------------------------------------------------------------
// C3. Secrets
// ---------------------------------------------------------------------------

test('C3-100 every planted secret is a value the labIR declares', () => {
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const declared = content.declaredSecrets(ir, null);
    for (const artifact of contentFor(seed).files) {
      for (const secret of artifact.secrets) {
        assert.ok(declared.has(secret.value),
          `${seed}: ${artifact.tree_path} plants a credential for ${secret.account} that AD is `
          + 'never built with');
      }
    }
  }
});

test('C3-101 the secret is really in the bytes of the file that claims it', () => {
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    for (const artifact of c.files) {
      for (const secret of artifact.secrets) {
        if (secret.encrypted) continue;
        assert.ok(c.tree[artifact.tree_path].indexOf(secret.value) !== -1,
          `${seed}: ${artifact.tree_path} claims a credential it does not contain`);
      }
    }
  }
});

test('C3-102 the SYSVOL blob decrypts to the credential it declares - inline key and key file', () => {
  let sawInline = false;
  let sawExternal = false;
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    const artifact = c.files.filter((f) => f.kind === 'sysvol_secret')[0];
    if (!artifact) continue;
    const secret = artifact.secrets[0];
    const key = Buffer.from(artifact.securestring.key_bytes);
    assert.strictEqual(content.unprotectSecureString(artifact.securestring.blob, key), secret.value,
      `${seed}: the blob does not decrypt to the declared password`);

    if (artifact.securestring.external_key) {
      sawExternal = true;
      const keyFile = c.files.filter((f) => f.kind === 'sysvol_key')[0];
      assert.ok(keyFile, `${seed}: the blob points at a key file that was not emitted`);
      // The key on disk is what Get-Content reads back, so it is the one the
      // exercise actually uses - decrypt with THAT, not with the descriptor.
      const fromDisk = Buffer.from(c.tree[keyFile.tree_path].trim().split('\n').map((n) => Number(n.trim())));
      assert.strictEqual(fromDisk.length, 32);
      assert.strictEqual(content.unprotectSecureString(artifact.securestring.blob, fromDisk), secret.value);
    } else {
      sawInline = true;
      assert.ok(c.tree[artifact.tree_path].indexOf(artifact.securestring.key_bytes.join(', ')) !== -1,
        `${seed}: the key is meant to be inline but the script does not carry it`);
      assert.strictEqual(c.files.filter((f) => f.kind === 'sysvol_key').length, 0);
    }
  }
  assert.ok(sawInline && sawExternal,
    'both key placements must occur across the seed spread, or one branch is dead code');
});

test('C3-103 protectSecureString round-trips and matches the format PowerShell writes', () => {
  const key = content.seededBytes('seed', 'k', 32);
  const iv = content.seededBytes('seed', 'i', 16);
  const blob = content.protectSecureString('Ledger-Vantage-3318', key, iv);
  assert.ok(blob.startsWith(content.SECURESTRING_MAGIC));
  assert.strictEqual(content.unprotectSecureString(blob, key), 'Ledger-Vantage-3318');
  const body = Buffer.from(blob.slice(content.SECURESTRING_MAGIC.length), 'base64').toString('utf16le');
  // "2|<base64 iv>|<hex ciphertext>", which is what GOAD's own secret.ps1 holds.
  assert.match(body, /^2\|[A-Za-z0-9+/=]{24}\|[0-9a-f]+$/);
});

test('C3-104 no generated script contains any credential', () => {
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const declared = content.declaredSecrets(ir, null);
    const c = contentFor(seed);
    for (const p of scriptsOf(c)) {
      for (const value of declared) {
        assert.ok(c.tree[p].indexOf(value) === -1,
          `${seed}: ${p} carries a credential; roles/ps stages scripts into the guest temp dir`);
      }
    }
  }
});

test('C3-105 the domain administrator password is refused, not merely undeclared', () => {
  const DA = 'Ledger-Vantage-3318-DA!';
  const ir = irFor('delta');
  const lab = { domains: { [FQDN]: { domain_password: DA } }, hosts: { dc01: { local_admin_password: DA } } };
  const doctored = {
    tree: { 'files/dc01/share/unattend.xml': `<Password>${DA}</Password>` },
    files: [{
      tree_path: 'files/dc01/share/unattend.xml',
      kind: 'unattend',
      secrets: [{ value: DA, account: 'Administrator' }],
    }],
    scripts: [],
  };
  assert.throws(() => content.assertContentSound(doctored, ir, lab), (err) => {
    assert.strictEqual(err.code, 'CONTENT_SECRET_FORBIDDEN');
    assert.match(err.message, /Domain Admin before edge 0/);
    return true;
  });
  assert.ok(content.forbiddenSecrets(lab).has(DA));
});

test('C3-106 a credential this module invented is refused', () => {
  const doctored = {
    tree: { 'files/x/share/note.txt': 'password: Invented-Not-In-The-IR-1!' },
    files: [{
      tree_path: 'files/x/share/note.txt',
      kind: 'handover_note',
      secrets: [{ value: 'Invented-Not-In-The-IR-1!', account: 'nobody' }],
    }],
    scripts: [],
  };
  assert.throws(() => content.assertContentSound(doctored, irFor('delta'), null), (err) => {
    assert.strictEqual(err.code, 'CONTENT_SECRET_UNDECLARED');
    assert.match(err.message, /no second act/);
    return true;
  });
});

test('C3-107 only the FOOTHOLD is planted from the attack graph; every other credential is inert', () => {
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const c = contentFor(seed);
    const foothold = ir.foothold_credential;
    const bySam = new Map(ir.principals.users.map((u) => [u.sam, u]));
    const claimed = content.chainPrincipals(content.indexIr(ir, {}));
    for (const artifact of c.files) {
      for (const secret of artifact.secrets) {
        const account = String(secret.account || '');
        if (account === foothold.sam) continue;
        assert.ok(bySam.has(account), `${seed}: ${artifact.tree_path} names an unknown account`);
        assert.ok(!claimed.has(account.toLowerCase()),
          `${seed}: ${artifact.tree_path} plants the password of ${account}, which the attack `
          + 'graph depends on - a decoy whose credential is on a share is not a decoy');
      }
    }
  }
});

test('C3-108 the foothold is planted in a file exactly when the entry does not depend on it not being', () => {
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    const entry = irFor(seed).chain.start.kind;
    const defeated = content.ENTRIES_DEFEATED_BY_A_FILE.indexOf(entry) !== -1;
    if (defeated) {
      assert.strictEqual(c.foothold_planted_in, null,
        `${seed}: entry '${entry}' has to be earned; a copy of the password in a file makes the `
        + 'technique decorative');
      assert.ok(c.warnings.some((w) => w.includes(entry)),
        `${seed}: the decision not to plant the foothold has to be reported`);
    } else {
      assert.ok(c.foothold_planted_in,
        `${seed}: entry '${entry}' is read off a file, so the foothold must be in one`);
      assert.ok(c.tree[c.foothold_planted_in].indexOf(irFor(seed).foothold_credential.password) !== -1);
    }
  }
});

test('C3-109 for a file-borne entry, the artifact carrying the foothold is the one the chain named', () => {
  // The chain writes start.plants[].item_vars.src for open_share and
  // start.plantedAt for the web entries. An artifact planted somewhere else is a
  // lab whose `how` string describes a file that is not there.
  const c = contentFor('delta');
  assert.strictEqual(irFor('delta').chain.start.kind, 'open_share');
  assert.strictEqual(c.foothold_planted_in, 'files/shares/it-handover.txt');
  const declaredSrc = irFor('delta').chain.start.plants
    .filter((p) => p.role === 'vulns/files')[0].item_vars.src;
  assert.strictEqual(c.foothold_planted_in, content.FILES_PREFIX + declaredSrc);

  const web = contentFor('s11');
  assert.strictEqual(irFor('s11').chain.start.kind, 'web_credential');
  const artifact = web.files.filter((f) => f.tree_path === web.foothold_planted_in)[0];
  assert.strictEqual(artifact.kind, 'web_app_config');
  assert.strictEqual(artifact.host_key, irFor('s11').chain.start.host,
    'the app config has to be on the host the chain says the credential was found on');
});

// ---------------------------------------------------------------------------
// C4. The six techniques
// ---------------------------------------------------------------------------

test('C4-100 all six techniques emit, on a lab that can carry them', () => {
  for (const seed of PINNED) {
    const emitted = contentFor(seed).scripts.map((s) => s.technique);
    for (const technique of content.TECHNIQUES) {
      assert.ok(emitted.indexOf(technique) !== -1,
        `${seed}: ${technique} was not emitted (got ${emitted.join(', ')})`);
    }
  }
});

test('C4-101 every script parameter traces back to the labIR AND appears in the file', () => {
  const traceable = (ir, value) => {
    const v = String(value);
    if (ir.principals.users.some((u) => u.sam === v)) return true;
    if (ir.hosts.some((h) => h.hostname === v)) return true;
    if (ir.domains.some((d) => d.fqdn === v || d.netbios === v)) return true;
    if (ir.principals.ous.some((o) => v === `OU=${o.name},${o.path}`)) return true;
    if (ir.domains.some((d) => v === d.fqdn.split('.').map((l) => `DC=${l}`).join(','))) return true;
    // The GPO's own name is minted from the domain's first label, which is the
    // only per-lab noun a fresh object can inherit.
    if (ir.domains.some((d) => v.toLowerCase().indexOf(d.fqdn.split('.')[0].toLowerCase()) === 0)) return true;
    return false;
  };
  for (const seed of PINNED) {
    const ir = irFor(seed);
    const c = contentFor(seed);
    for (const s of c.scripts) {
      const body = c.tree[s.tree_path];
      assert.ok(Object.keys(s.targets || {}).length > 0, `${s.tree_path} declares no targets`);
      for (const [key, value] of Object.entries(s.targets)) {
        assert.ok(traceable(ir, value),
          `${seed}: ${s.tree_path} targets.${key} = ${JSON.stringify(value)}, which is in no part `
          + 'of the labIR - that is a constant, and constants are what this module exists to remove');
        assert.ok(body.indexOf(String(value)) !== -1,
          `${seed}: ${s.tree_path} declares targets.${key} but the script never names it`);
      }
    }
  }
});

test('C4-102 no upstream constant survived into a generated script', () => {
  // The exact literals upstream hardcodes. If any of these is in an emitted
  // file, a reference script was copied rather than regenerated.
  const UPSTREAM = [
    'brandon.stark', 'missandei', 'castelblack', 'jon.snow', 'sansa.stark', 'robb.stark',
    'eddard.stark', 'samwell.tarly', 'StarkWallpaper', 'sevenkingdoms.local', 'essos.local',
    'winterfell', 'FightP3aceAndHonor!', 'sexywolfy', 'powerkingftw135', '_L0ngCl@w_',
  ];
  // The header block comment cites upstream's constants on purpose - each script
  // names the file it was written against so the two can be diffed - so the
  // search is over the CODE, which is everything after the closing `#>`.
  const code = (body) => body.replace(/^<#[\s\S]*?#>\n/, '');
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    for (const [p, body] of Object.entries(c.tree)) {
      const isScript = p.startsWith(content.SCRIPTS_PREFIX);
      const haystack = isScript ? code(body) : body;
      // Guard the guard: if the header stopped being strippable this test would
      // silently start searching the whole file and never fail.
      if (isScript) assert.ok(haystack.length < body.length, `${p}: no header was stripped`);
      for (const needle of UPSTREAM) {
        assert.ok(haystack.indexOf(needle) === -1,
          `${seed}: ${p} still carries the upstream literal ${needle}`);
      }
    }
  }
});

test('C4-103 every script is guarded so a replay is safe', () => {
  // The runner recovers by replaying the failed playbook, so a script that is
  // not re-runnable turns one transient failure into an unbuildable lab. The
  // guard has two halves and both are asserted: an already-applied state exits
  // 0 quietly, and a missing precondition exits 1 loudly.
  for (const seed of PINNED) {
    const c = contentFor(seed);
    for (const s of c.scripts) {
      const body = c.tree[s.tree_path];
      assert.match(body, /RE-RUN CONTRACT/, `${s.tree_path} has no re-run contract in its header`);
      assert.ok(/Get-AD|Get-GPO|Get-GPInheritance|Get-ScheduledTask|Get-Module/.test(body),
        `${s.tree_path} never reads any state`);
      assert.match(body, /\bexit 1\b/, `${s.tree_path} never fails on a missing precondition`);
      // Two shapes are acceptable for "already applied". Most scripts detect the
      // state and exit 0. The coercion bot cannot: its interval and UNC path are
      // regenerated on every compile, so a task left over from a previous tree
      // would keep pointing at the previous lab - it removes and recreates
      // instead, which is replay-safe for a different reason.
      const quiet = /exit 0/.test(body) || /already/.test(body)
        || /Unregister-ScheduledTask/.test(body);
      assert.ok(quiet, `${s.tree_path} has no already-applied path`);
      assert.match(body, /Write-Error/, `${s.tree_path} never says what went wrong`);
      // The ordering assertion: the first thing that CHANGES the directory or
      // the machine must come after the first thing that reads it. Upstream's
      // asrep_roasting.ps1 is one line long and fails this by construction.
      // Header AND comments stripped: every one of these scripts explains in a
      // comment why it reads before it writes, and those comments name the
      // cmdlet they are talking about.
      const code = body.replace(/^<#[\s\S]*?#>\n/, '').replace(/^\s*#.*$/gm, '');
      const firstWrite = code.search(
        /(Set-AD|Set-GP|New-GPO|New-GPLink|Register-ScheduledTask|Install-WindowsFeature|netdom trust)/);
      const firstRead = code.search(/(Get-AD|Get-GPO|Get-GPInheritance|Get-ScheduledTask|Get-Module)/);
      assert.ok(firstWrite !== -1, `${s.tree_path} plants nothing`);
      assert.ok(firstRead !== -1 && firstRead < firstWrite,
        `${s.tree_path} writes before it reads, so a replay hits the un-guarded path`);
    }
  }
});

test('C4-104 every script runs on a domain controller of the domain it names', () => {
  // roles/ps runs the .ps1 on the host whose hosts[].scripts lists it, and
  // Get-ADUser -Identity resolves in that DC's own domain only. A script placed
  // on the wrong host fails with "cannot find an object with identity".
  for (const seed of PINNED) {
    const ir = irFor(seed);
    const c = contentFor(seed);
    const byKey = new Map(ir.hosts.map((h) => [h.key, h]));
    for (const [hostKey, names] of Object.entries(c.host_scripts)) {
      const host = byKey.get(hostKey);
      assert.ok(host, `${seed}: scripts assigned to unknown host ${hostKey}`);
      assert.strictEqual(host.type, 'dc',
        `${seed}: ${names.join(', ')} were put on ${hostKey}, which is not a domain controller`);
    }
    for (const s of c.scripts) {
      if (s.technique === 'sidhistory' || s.technique === 'coercion_bot') continue;
      const host = byKey.get(s.host_key);
      const named = Object.values(s.targets).filter((v) => ir.principals.users.some((u) => u.sam === v));
      for (const sam of named) {
        const user = ir.principals.users.filter((u) => u.sam === sam)[0];
        assert.strictEqual(user.domain, host.domain,
          `${seed}: ${s.tree_path} names ${sam} but runs on ${host.key}, a DC for ${host.domain}`);
      }
    }
  }
});

test('C4-105 an undeclared technique never touches a principal the graph depends on', () => {
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const claimed = content.chainPrincipals(content.indexIr(ir, {}));
    for (const s of contentFor(seed).scripts) {
      if (s.declared_by_chain) continue;
      for (const [key, value] of Object.entries(s.modifies || {})) {
        assert.ok(!claimed.has(String(value).replace(/\$$/, '').toLowerCase()),
          `${seed}: ${s.tree_path} modifies.${key} = ${value}, a graph principal`);
      }
    }
  }
});

test('C4-106 undeclared unconstrained delegation lands on an SPN-less USER, never a computer', () => {
  // On a member server this is a live route to whatever can be coerced, and
  // assertNoUnintendedShortcuts ran before this module and cannot see it. On an
  // account with no SPN there is no service to receive the authentication, so
  // BloodHound draws the edge and it goes nowhere. Upstream plants exactly this
  // on sansa.stark.
  let checked = 0;
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const plan = contentFor(seed).scripts.filter((s) => s.technique === 'unconstrained_delegation')[0];
    if (!plan || plan.declared_by_chain) continue;
    checked += 1;
    assert.strictEqual(plan.target_kind, 'user', `${seed}: undeclared delegation went on a computer`);
    const user = ir.principals.users.filter((u) => u.sam === plan.target)[0];
    assert.ok(user, `${seed}: the delegation target is not a roster user`);
    assert.strictEqual((user.spns || []).length, 0);
    assert.match(contentFor(seed).tree[plan.tree_path], /Get-ADUser -Identity \$Target/);
  }
  assert.ok(checked >= 5, 'the undeclared branch was barely exercised');
});

test('C4-107 RBCD reads the existing descriptor before rewriting it', () => {
  // -PrincipalsAllowedToDelegateToAccount REPLACES the attribute. A script that
  // passes only the new principal silently revokes every other RBCD grant on
  // that computer, which on a replay is how a planted edge disappears with no
  // task turning red.
  const c = contentFor('delta');
  const rbcd = c.scripts.filter((s) => s.technique === 'rbcd')[0];
  const body = c.tree[rbcd.tree_path];
  assert.match(body, /Get-ADComputer -Identity \$Resource -Properties PrincipalsAllowedToDelegateToAccount/);
  assert.match(body, /\$merged = \$existing \+ @\(\$principal\.DistinguishedName\)/);
  assert.match(body, /REPLACES/);
  // And the resource is never a domain controller.
  const target = irFor('delta').hosts.filter((h) => h.hostname === rbcd.target)[0];
  assert.ok(target && target.type !== 'dc');
});

test('C4-108 GPO abuse guards the link separately from the GPO', () => {
  // Upstream guards its whole body on `if ($gpo_exist)`, so a crash between
  // New-GPO and New-GPLink leaves an unlinked GPO no replay ever repairs.
  const c = contentFor('delta');
  const gpo = c.scripts.filter((s) => s.technique === 'gpo_abuse')[0];
  const body = c.tree[gpo.tree_path];
  assert.match(body, /Get-GPO -Name \$GpoName -ErrorAction SilentlyContinue/);
  assert.match(body, /Get-GPInheritance -Target \$LinkTarget/);
  assert.match(body, /Set-GPPermissions -Name \$GpoName -PermissionLevel GpoEditDeleteModifySecurity/);
  assert.ok(!/Domain Controllers/.test(gpo.link_target),
    'a GPO linked over the Domain Controllers OU is a different exercise');
});

test('C4-109 sIDHistory is emitted only where a trust exists, and says so when it is not', () => {
  const withTrust = contentFor('delta').scripts.filter((s) => s.technique === 'sidhistory')[0];
  assert.ok(withTrust);
  assert.strictEqual(withTrust.trusting, FQDN);
  assert.strictEqual(withTrust.trusted, FQDN_B);
  assert.match(contentFor('delta').tree[withTrust.tree_path], /netdom trust \$Trusting \/d:\$Trusted \/enablesidhistory:yes/);

  // A single-domain lab has nothing to disable SID filtering on. It has to say
  // so rather than emit a script that netdom refuses.
  const single = baseIr('single');
  single.domains = [Object.assign({}, single.domains[0], { trust_fqdn: null })];
  single.hosts = single.hosts.filter((h) => h.domain === FQDN);
  single.principals.users = single.principals.users.filter((u) => u.domain === FQDN);
  single.principals.ous = single.principals.ous.filter((o) => o.domain === FQDN);
  const ir = chainMod.applyAttackChain(single, { runId: 'single' });
  const c = content.generateLabContent(ir, { runId: 'single' });
  assert.strictEqual(c.scripts.filter((s) => s.technique === 'sidhistory').length, 0);
  assert.ok(c.warnings.some((w) => w.startsWith('sidhistory skipped:')),
    `a skipped technique must be reported; got ${JSON.stringify(c.warnings)}`);
});

test('C4-110 the coercion bot runs as SYSTEM and carries no password', () => {
  // Upstream's rdp_scheduler.ps1 and ntlm_relay.ps1 both pass
  // Register-ScheduledTask -Password with a literal.
  const c = contentFor('alpha');
  const bot = c.scripts.filter((s) => s.technique === 'coercion_bot')[0];
  assert.ok(bot, 'a delegation chain needs something to coerce');
  const body = c.tree[bot.tree_path];
  assert.match(body, /-User 'SYSTEM'/);
  assert.ok(!/-Password/.test(body), 'the bot must not carry a credential');
  assert.match(body, /Unregister-ScheduledTask -TaskName \$TaskName -Confirm:\$false/);
  assert.ok(bot.interval_minutes >= 1 && bot.interval_minutes <= 5);
  // indexOf, not a regex: the share names end in '$' and a UNC path is nothing
  // but backslashes, so a regex here tests the escaping rather than the script.
  assert.ok(body.indexOf(bot.unc) !== -1, `the bot never names ${bot.unc}`);
  assert.ok(bot.unc.indexOf(bot.targets.unc_host) !== -1);
  // No delegation edge, no bot: a coercion source with nothing to coerce into
  // is noise the answer key cannot explain.
  assert.strictEqual(contentFor('delta').scripts.filter((s) => s.technique === 'coercion_bot').length, 0);
});

// ---------------------------------------------------------------------------
// C5. The contract with the attack chain
// ---------------------------------------------------------------------------

test('C5-100 every vulns/files copy the chain declared has content at exactly that src', () => {
  for (const seed of SEEDS) {
    const ir = irFor(seed);
    const c = contentFor(seed);
    const requests = content.chainFileRequests(ir);
    for (const req of requests) {
      const p = content.FILES_PREFIX + req.src;
      assert.ok(c.tree[p], `${seed}: the chain copies from ${req.src} and nothing was emitted there`);
      const artifact = c.files.filter((f) => f.tree_path === p)[0];
      assert.strictEqual(artifact.dest, req.dest, `${seed}: ${p} was given a different dest`);
      assert.strictEqual(artifact.host_key, req.host_key);
    }
  }
});

test('C5-101 every roles/ps item the chain declared has a script under exactly its name', () => {
  for (const seed of SEEDS) {
    const c = contentFor(seed);
    for (const req of content.chainScriptRequests(irFor(seed))) {
      const p = `${content.SCRIPTS_PREFIX}${req.item}.ps1`;
      assert.ok(c.tree[p],
        `${seed}: the chain declares roles/ps item '${req.item}' and no script exists at ${p}`);
      assert.ok((c.host_scripts[req.host_key] || []).indexOf(`${req.item}.ps1`) !== -1,
        `${seed}: ${req.item}.ps1 is not listed on ${req.host_key}`);
    }
  }
});

test('C5-102 a chain-declared member that was not emitted is refused', () => {
  const c = contentFor('delta');
  const missing = 'files/shares/it-handover.txt';
  const tree = Object.assign({}, c.tree);
  delete tree[missing];
  assert.throws(
    () => content.assertContentSound(Object.assign({}, c, {
      tree,
      files: c.files.filter((f) => f.tree_path !== missing),
    }), irFor('delta'), null),
    (err) => {
      assert.strictEqual(err.code, 'CONTENT_CHAIN_FILE_MISSING');
      return true;
    });

  const scriptGone = Object.assign({}, c.tree);
  const declared = content.chainScriptRequests(irFor('delta'));
  if (declared.length) {
    const p = `${content.SCRIPTS_PREFIX}${declared[0].item}.ps1`;
    delete scriptGone[p];
    assert.throws(
      () => content.assertContentSound(Object.assign({}, c, {
        tree: scriptGone,
        scripts: c.scripts.filter((s) => s.tree_path !== p),
      }), irFor('delta'), null),
      (err) => {
        assert.strictEqual(err.code, 'CONTENT_CHAIN_SCRIPT_MISSING');
        return true;
      });
  }
});

test('C5-103 the ESC1 template is ESC1-shaped, and its OID is this lab s own', () => {
  const seeds = SEEDS.filter((s) => irFor(s).chain.shape.pattern === 'adcs_esc1');
  assert.ok(seeds.length >= 2, 'no seed produced an ESC1 chain');
  const oids = new Set();
  for (const seed of seeds) {
    const c = contentFor(seed);
    const artifact = c.files.filter((f) => f.kind === 'adcs_template')[0];
    assert.ok(artifact, `${seed}: the chain has an ESC1 edge and no template was emitted`);
    const json = JSON.parse(c.tree[artifact.tree_path]);
    // The four fields that ARE the vulnerability. Change any one and the
    // template is safe, the role still reports green, and the edge silently
    // does not exist.
    assert.strictEqual(json['msPKI-Certificate-Name-Flag'], 1, 'ENROLLEE_SUPPLIES_SUBJECT');
    assert.strictEqual(json['msPKI-Enrollment-Flag'], 0, 'no manager approval');
    assert.strictEqual(json['msPKI-RA-Signature'], 0, 'no authorised signatures');
    assert.deepStrictEqual(json.pKIExtendedKeyUsage, ['1.3.6.1.5.5.7.3.2'], 'client authentication');
    assert.strictEqual(json.name, json.displayName);
    assert.strictEqual(artifact.dest.endsWith(`${json.name}.json`), true);
    oids.add(json['msPKI-Cert-Template-OID']);
    // GOAD ships this OID in every lab that copies its ESC1.json.
    assert.notStrictEqual(json['msPKI-Cert-Template-OID'],
      '1.3.6.1.4.1.311.21.8.16735922.7437492.10570883.2539024.15756463.185.9025784.11813639');
  }
  assert.strictEqual(oids.size, seeds.length, 'two labs published the same template OID');
});

// ---------------------------------------------------------------------------
// C6. Ordering, and lowering into the lab dict
// ---------------------------------------------------------------------------

test('C6-100 the ordering rule agrees with the composer, byte for byte', () => {
  // The rank table is duplicated in this module to avoid a require cycle, so
  // the only thing keeping the two honest is this assertion.
  const pools = [
    ['permissions', 'directory', 'files', 'adcs_templates'],
    ['schedule', 'files', 'disable_firewall'],
    ['adcs_templates', 'files'],
    ['files', 'directory', 'permissions', 'credentials', 'autologon', 'disable_firewall'],
    ['disable_firewall', 'schedule', 'permissions', 'directory', 'files'],
    [],
  ];
  for (const pool of pools) {
    assert.deepStrictEqual(content.orderVulnsForContent(pool), compile.orderVulns(pool),
      `orderVulnsForContent disagrees with goad-lab-compile.orderVulns on ${pool.join(',')}`);
  }
  assert.deepStrictEqual(content.ROLE_RANK, { directory: 0, files: 1, permissions: 90, schedule: 91 });
});

test('C6-101 mergeLabContent puts files before everything that consumes what it copied', () => {
  const { lab, c } = realLab('L');
  const hostKey = Object.keys(c.files_vars)[0];
  // Give the host the three roles whose ordering the validator enforces, in the
  // worst possible order, and require the merge to fix it.
  const seeded = JSON.parse(JSON.stringify(lab));
  seeded.hosts[hostKey].vulns = ['schedule', 'adcs_templates', 'permissions', 'directory'];
  const merged = content.mergeLabContent(seeded, c);
  const v = merged.hosts[hostKey].vulns;
  const at = (name) => v.indexOf(name);
  assert.ok(at('files') !== -1, 'files was never added');
  assert.ok(at('directory') < at('files'), 'directory creates the folder files copies into');
  assert.ok(at('files') < at('adcs_templates'), 'adcs_templates imports the JSON files copied');
  assert.ok(at('files') < at('schedule'), 'schedule runs a script files copied');
  assert.ok(at('files') < at('permissions'), 'permissions ACLs a path files created');
  // vulns_vars is re-keyed in vulns order too: two lists in different orders is
  // how a reader concludes the file is generated slop.
  assert.deepStrictEqual(
    Object.keys(merged.hosts[hostKey].vulns_vars).filter((k) => v.indexOf(k) !== -1),
    v.filter((n) => merged.hosts[hostKey].vulns_vars[n] !== undefined));
});

test('C6-102 a merged lab still passes the validator and pre-flight, on all three tiers', () => {
  for (const key of ['S', 'M', 'L']) {
    const { out, merged } = realLab(key);
    const res = validate.assertLabCompiles({ lab: merged }, { labName: 'CIAB-CONTENT', throwOnError: false });
    assert.deepStrictEqual(res.errors, [], `tier ${key}: ${JSON.stringify(res.errors)}`);
    const pf = preflight.preflightGoadLab({
      config: { lab: merged },
      inventory: out.files['data/inventory'],
      providerInventory: out.files['providers/proxmox/inventory'],
      playbooks: out.chain,
      labName: 'CIAB-CONTENT',
    });
    assert.deepStrictEqual(pf.errors, [], `tier ${key}: ${JSON.stringify(pf.errors)}`);
  }
});

test('C6-103 mergeLabContent does not mutate the lab it was handed', () => {
  const { lab, c } = realLab('M');
  const before = JSON.stringify(lab);
  content.mergeLabContent(lab, c);
  assert.strictEqual(JSON.stringify(lab), before);
});

test('C6-104 every emitted script is listed on its host, once', () => {
  for (const key of ['S', 'M', 'L']) {
    const { c, merged } = realLab(key);
    for (const s of c.scripts) {
      const listed = merged.hosts[s.host_key].scripts.filter((n) => n === s.name);
      assert.strictEqual(listed.length, 1,
        `tier ${key}: ${s.name} appears ${listed.length} times on ${s.host_key}`);
    }
    // And a re-merge is idempotent: the composer may run this twice.
    const twice = content.mergeLabContent(merged, c);
    assert.deepStrictEqual(twice.hosts, merged.hosts);
  }
});

test('C6-105 every files_vars entry points at a member that exists in the tree', () => {
  for (const key of ['S', 'M', 'L']) {
    const { c } = realLab(key);
    for (const [hostKey, items] of Object.entries(c.files_vars)) {
      for (const [item, vars] of Object.entries(items)) {
        assert.ok(c.tree[content.FILES_PREFIX + vars.src],
          `tier ${key}: ${hostKey}.${item} copies from ${vars.src}, which is not in the tree`);
        assert.match(vars.dest, /^[A-Za-z]:\\/, `${vars.dest} is not an absolute Windows path`);
      }
    }
  }
});

test('C6-106 the real compiler produces every required artifact kind on a real lab', () => {
  const { c } = realLab('L');
  const kinds = new Set(c.files.map((f) => f.kind));
  for (const required of [
    'web_app_config', 'share_spreadsheet', 'unattend', 'rdp_shortcut', 'backup_script',
    'sysvol_logon_script', 'sysvol_secret', 'onboarding_letter', 'credential_vault',
  ]) {
    assert.ok(kinds.has(required), `no ${required} was emitted`);
    assert.ok(content.ARTIFACT_KINDS.indexOf(required) !== -1, `${required} is not in ARTIFACT_KINDS`);
  }
});

// ---------------------------------------------------------------------------
// C7. Refusals
// ---------------------------------------------------------------------------

test('C7-100 no seed is a refusal, not a random lab', () => {
  const ir = irFor('delta');
  assert.throws(() => content.generateLabContent(Object.assign({}, ir, { run_id: '', lab_name: '' }), {}),
    (err) => {
      assert.strictEqual(err.code, 'CONTENT_NO_SEED');
      assert.strictEqual(err.status, 409);
      assert.match(err.message, /cannot be regenerated/);
      return true;
    });
});

test('C7-101 an IR with no domain, or no DC, is refused with the reason', () => {
  assert.throws(() => content.generateLabContent({ run_id: 'x', domains: [] }, {}), (err) => {
    assert.strictEqual(err.code, 'CONTENT_NO_DOMAIN');
    return true;
  });
  const noDc = baseIr('nodc');
  noDc.hosts = noDc.hosts.filter((h) => h.type !== 'dc');
  assert.throws(() => content.generateLabContent(noDc, { runId: 'nodc' }), (err) => {
    assert.strictEqual(err.code, 'CONTENT_NO_DC');
    assert.match(err.message, /RSAT/);
    return true;
  });
});

test('C7-102 merging onto a lab that does not declare the host is refused', () => {
  const { c } = realLab('M');
  assert.throws(() => content.mergeLabContent({ hosts: { nowhere: {} } }, c), (err) => {
    assert.strictEqual(err.code, 'MERGE_UNKNOWN_HOST');
    assert.match(err.message, /never copied|does not declare/);
    return true;
  });
  assert.throws(() => content.mergeLabContent(null, c), (err) => {
    assert.strictEqual(err.code, 'MERGE_NO_LAB');
    return true;
  });
});

test('C7-103 a SecureString blob without the magic header is refused', () => {
  assert.throws(() => content.unprotectSecureString('not a blob', content.seededBytes('a', 'b', 32)),
    (err) => {
      assert.strictEqual(err.code, 'SECURESTRING_NO_MAGIC');
      return true;
    });
  assert.throws(() => content.protectSecureString('x', Buffer.alloc(16), Buffer.alloc(16)), (err) => {
    assert.strictEqual(err.code, 'SECURESTRING_BAD_KEY');
    return true;
  });
});

// ---------------------------------------------------------------------------
// S. THE COMPANY WEBSITE
//
// The DMZ host is the surface an external engagement starts from, and until the
// site generator existed the curated cc_web role had no content to install and
// no caller. These tests are about the three things the source text cannot
// check: that two clients get two different companies rather than one template
// with the nouns swapped, that the credential the site plants is the one Active
// Directory is built with, and that what the paper is allowed to claim is what
// the role is being told to build.
//
// The clients below are pinned rather than scanned, the same way PINNED is: the
// claim is "these two get different sites", and a scan that hunted for a
// differing pair would pass even if every other pair collided. Each run id is
// named with the chain shape it lands on, so a designer change that moves one is
// visible here rather than three tests later.
//   RUN_SITE_A_5  Ridgeline, entry web_credential          (a WEB-side plant)
//   RUN_SITE_B_2  Cascade,   entry web_credential          (a WEB-side plant)
//   RUN_SITE_A_0  Ridgeline, entry password_in_description  (the AD description,
//                                                            mirrored on the site)
//   RUN_SITE_A_1  Ridgeline, entry anonymous_rpc            (an AD-side plant that
//                                                            writes to `description`)
//   RUN_SITE_A_3  Ridgeline, entry asrep                    (an AD-side plant)
// ---------------------------------------------------------------------------

function siteProfile(o) {
  return {
    json_data: {
      student_view: {
        meta: { run_id: o.runId, client_type: 'SMB', difficulty: 'intermediate' },
        quick: { company_name: o.company, employees_total: o.employees },
        raw: {
          threats: {
            organization: {
              company_name: o.company,
              domain_public: o.domain,
              employees_total: o.employees,
              hq_city: o.city,
              industry: o.industry,
              department_breakdown: o.departments,
            },
            it_environment: { delivery: 'Hybrid' },
          },
        },
        stakeholders: o.stakeholders,
      },
    },
  };
}

const CLIENT_A = Object.freeze({
  company: 'Ridgeline Dental Group',
  domain: 'ridgelinedental.com',
  employees: 46,
  city: 'Boise, ID',
  industry: 'Healthcare',
  departments: { Clinical: 18, Administration: 9, Finance: 5, IT: 3 },
  stakeholders: [
    { name: 'Alice Kwan', role: 'Practice Principal', department: 'Clinical' },
    { name: 'Tom Iverson', role: 'Practice Manager', department: 'Administration' },
    { name: 'Nadia Farouk', role: 'Head of Nursing', department: 'Clinical' },
  ],
});

const CLIENT_B = Object.freeze({
  company: 'Cascade Freight Services',
  domain: 'cascadefreight.com',
  employees: 130,
  city: 'Portland, OR',
  industry: 'Transport',
  departments: { Logistics: 40, Fleet: 22, Sales: 14, Finance: 8, IT: 5 },
  stakeholders: [
    { name: 'Gerald Boyce', role: 'Managing Director', department: 'Executive' },
    { name: 'Priya Raman', role: 'Head of Logistics', department: 'Logistics' },
    { name: 'Sam Oduya', role: 'Fleet Supervisor', department: 'Fleet' },
  ],
});

const siteCache = {};
/** A real compiled lab with a proven chain, and the website generated for it. */
function siteFor(runId, base) {
  if (!siteCache[runId]) {
    const compiled = compile.compileLabWithChain(siteProfile(Object.assign({ runId }, base)));
    const lab = JSON.parse(compiled.files['data/config.json']).lab;
    siteCache[runId] = {
      ir: compiled.ir,
      lab,
      site: content.generateSiteContent(compiled.ir, { runId: compiled.run_id, lab }),
    };
  }
  return siteCache[runId];
}

const SITE_A = 'RUN_SITE_A_5';
const SITE_B = 'RUN_SITE_B_2';
const SITE_MIRROR = 'RUN_SITE_A_0';
const SITE_AD_DESC = 'RUN_SITE_A_1';
const SITE_AD_ASREP = 'RUN_SITE_A_3';

/** Every byte the site serves, as one string. */
function siteText(site) {
  return site.routes.map((r) => r.content).join('\n');
}
function routeAt(site, p) {
  return site.routes.filter((r) => r.path === p)[0];
}
/** Visible prose: tags, style and comments stripped, so a comparison is about
 *  what a person reads rather than about the markup they share. */
function visibleProse(html) {
  return String(html)
    .replace(/<style[\s\S]*?<\/style>/gi, ' ')
    .replace(/<!--[\s\S]*?-->/g, ' ')
    .replace(/<[^>]*>/g, ' ')
    .replace(/&[a-z]+;/gi, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

test('S1-100 the pinned clients still land on the chain shapes these tests are about', () => {
  const shapes = [
    [SITE_A, 'web_credential', 'web_app_credential'],
    [SITE_B, 'web_credential', 'web_app_credential'],
    [SITE_MIRROR, 'password_in_description', 'ad_description_mirrored_on_web'],
    [SITE_AD_DESC, 'anonymous_rpc', 'ad_description_via_anonymous'],
    [SITE_AD_ASREP, 'asrep', 'asrep_roastable'],
  ];
  for (const [runId, entry, format] of shapes) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { ir } = siteFor(runId, base);
    assert.strictEqual(ir.chain.start.kind, entry,
      `${runId} used to design a '${entry}' entry and now designs '${ir.chain.start.kind}'. The site `
      + 'tests below are about specific chain shapes; re-pin them rather than deleting the ones that '
      + 'stopped applying');
    assert.strictEqual(ir.foothold_credential.planted_at.format, format);
  }
});

test('S1-101 two clients get two different companies, not one template with the nouns swapped', () => {
  const a = siteFor(SITE_A, CLIENT_A).site;
  const b = siteFor(SITE_B, CLIENT_B).site;

  assert.notStrictEqual(a.org, b.org);
  assert.notStrictEqual(a.server_name, b.server_name);
  assert.ok(a.server_name.endsWith('.ridgelinedental.com'),
    `the site is served under the CLIENT's own public domain, not the internal forest root; got ${a.server_name}`);
  assert.ok(b.server_name.endsWith('.cascadefreight.com'));

  // The URL space differs, so even the report's link list is not shared.
  const pathsA = a.routes.map((r) => r.path).sort().join(',');
  const pathsB = b.routes.map((r) => r.path).sort().join(',');
  assert.notStrictEqual(pathsA, pathsB,
    'two clients whose sites live at identical URLs are one site with two coats of paint');

  // Neither client's identity appears anywhere in the other's site. This is the
  // one that would catch a writer reaching for a hard-coded example.
  const textA = siteText(a);
  const textB = siteText(b);
  for (const [text, other, label] of [[textA, CLIENT_B, 'A'], [textB, CLIENT_A, 'B']]) {
    assert.ok(text.indexOf(other.domain) === -1, `client ${label}'s site names the other client's domain`);
    assert.ok(text.indexOf(other.city) === -1, `client ${label}'s site names the other client's city`);
    for (const s of other.stakeholders) {
      assert.ok(text.indexOf(s.name) === -1,
        `client ${label}'s site names ${s.name}, who works for the other client`);
    }
  }

  // And the PROSE differs, not just the nouns inside it. Compared as sentences
  // with every proper noun already gone: two sites that share their sentences
  // are the same brochure.
  const scrub = (site, client) => visibleProse(routeAt(site, '/').content)
    .split(/(?<=\.)\s+/)
    .map((s) => s.replace(new RegExp(client.city, 'g'), '')
      .replace(new RegExp(site.org, 'g'), '')
      .replace(/\b\d+\b/g, '')
      .replace(/\s+/g, ' ')
      .trim())
    .filter((s) => s.length > 25);
  const homeA = scrub(a, CLIENT_A);
  const homeB = scrub(b, CLIENT_B);
  const shared = homeA.filter((s) => homeB.indexOf(s) !== -1);
  assert.ok(homeA.length >= 3 && homeB.length >= 3, 'a home page with under three sentences is a stub');
  assert.ok(shared.length * 2 < Math.min(homeA.length, homeB.length),
    'more than half the home page survives changing the client, so the two read as one document: '
    + `shared sentences were ${JSON.stringify(shared)}`);
});

test('S1-102 the site is a real site: nav, title, and every marketing page', () => {
  for (const [runId, base] of [[SITE_A, CLIENT_A], [SITE_B, CLIENT_B]]) {
    const { site } = siteFor(runId, base);
    const declared = site.web_facts.paths;
    assert.strictEqual(declared[0], '/', 'the root is the one path a fact block never has to spell out');
    assert.strictEqual(declared.length, 5,
      'the marketing surface is home, about, careers, contact and the portal — a client site missing '
      + `one of those reads as a fixture: got ${declared.join(', ')}`);
    for (const route of site.routes) {
      if (!/\.html$/.test(route.file)) continue;
      assert.ok(/<!doctype html>/i.test(route.content), `${route.path} is not a document`);
      assert.ok(/<title>[^<]+<\/title>/.test(route.content), `${route.path} has no title`);
      assert.ok(route.content.indexOf(site.org) !== -1, `${route.path} never names the company`);
      // Every page links to every other declared page: a "site" whose pages do
      // not reach each other is five files in a directory.
      for (const other of declared) {
        assert.ok(route.content.indexOf(`href="${other}"`) !== -1,
          `${route.path} does not link to ${other}`);
      }
    }
    const home = visibleProse(routeAt(site, '/').content);
    assert.ok(home.length > 250, `the home page has ${home.length} characters of prose; that is a stub`);
  }
});

test('S1-103 the About page carries the CLIENT\'s own stakeholders, and they exist in AD', () => {
  for (const [runId, base] of [[SITE_A, CLIENT_A], [SITE_B, CLIENT_B]]) {
    const { site, ir } = siteFor(runId, base);
    const about = site.routes.filter((r) => /about|who-we-are|company/.test(r.path))[0];
    assert.ok(about, 'every site has an about page');
    assert.ok(site.staff.length >= 3, `only ${site.staff.length} bios; the profile named 3 stakeholders`);

    for (const person of site.staff) {
      assert.ok(about.content.indexOf(person.name) !== -1,
        `${person.name} is recorded as a bio and does not appear on the page`);
      assert.ok(about.content.indexOf(person.title) !== -1,
        `${person.name}'s title '${person.title}' is not on the page`);
      // THE POINT OF DOING IT THIS WAY. The bios are not decoration: every one
      // of them is an account the forest really creates, so the staff list a
      // student reads off the website IS the spray list.
      const user = ir.principals.users.filter((u) => u.sam === person.sam)[0];
      assert.ok(user, `${person.sam} is on the About page and the forest creates no such account`);
      assert.strictEqual(user.description, `${person.title}, ${person.department}`);
    }
    // And they are the profile's people, not invented ones.
    const named = base.stakeholders.filter((s) => about.content.indexOf(s.name) !== -1);
    assert.ok(named.length >= 3,
      `the About page names ${named.length} of the client's own stakeholders; the bios are supposed to `
      + 'be drawn from the profile rather than made up');
  }
});

test('S1-104 the same lab regenerates a byte-identical site', () => {
  const { ir, lab } = siteFor(SITE_A, CLIENT_A);
  const once = content.generateSiteContent(ir, { runId: ir.run_id, lab });
  const twice = content.generateSiteContent(ir, { runId: ir.run_id, lab });
  assert.deepStrictEqual(twice, once,
    'a site that cannot be regenerated cannot be checked against the paper it was handed out with');
});

// --- the seam --------------------------------------------------------------

test('S2-100 the credential the site plants is EXACTLY the one the IR declares', () => {
  for (const [runId, base] of [[SITE_A, CLIENT_A], [SITE_B, CLIENT_B], [SITE_MIRROR, CLIENT_A]]) {
    const { site, ir } = siteFor(runId, base);
    const cred = ir.foothold_credential;
    assert.strictEqual(site.carries_foothold, true, `${runId} is a web-side plant`);
    assert.strictEqual(site.pivot.username, cred.sam,
      'the site plants a different account from the one the chain starts at');
    assert.strictEqual(site.pivot.password, cred.password,
      'the website hands out one string and the directory is built with another - both halves green, '
      + 'the login broken');
    // AND the AD side really honours it. Read off the roster rather than trusted.
    const user = ir.principals.users.filter((u) => u.sam === cred.sam)[0];
    assert.ok(user, 'the foothold names an account the forest does not create');
    assert.strictEqual(user.password, site.pivot.password);
  }
});

test('S2-101 the planted credential is reachable: it is in the bytes of the file, or of the page', () => {
  const { site } = siteFor(SITE_A, CLIENT_A);
  // The config file itself is written by the role, so what this can assert is
  // that the site told the role to write it under the docroot, at the URL the
  // site publishes, in a format the role can render.
  assert.strictEqual(site.pivot.path, `${site.docroot}${site.pivot_url}`);
  assert.strictEqual(site.pivot.allow_in_docroot, true,
    'a static site has no application to exploit for a file read, so a credential file OUTSIDE the '
    + 'docroot is one no student can ever reach - and cc_web refuses an in-docroot path that does '
    + 'not say so');
  const carriers = site.routes.filter((r) => r.carries_foothold);
  assert.strictEqual(carriers.length, 1, 'exactly one page carries the foothold');
  assert.ok(carriers[0].content.indexOf(site.pivot.password) !== -1);
  assert.ok(carriers[0].content.indexOf(site.pivot.username) !== -1);
});

test('S2-102 a site planting a credential AD does not honour is a COMPILE ERROR', () => {
  const { site, ir, lab } = siteFor(SITE_A, CLIENT_A);
  // The forest rotates the account's password and nobody tells the website.
  const drifted = JSON.parse(JSON.stringify(ir));
  const user = drifted.principals.users.filter((u) => u.sam === site.pivot.username)[0];
  user.password = 'Rotated-Overnight-99';
  assert.throws(
    () => content.generateSiteContent(drifted, { runId: drifted.run_id, lab }),
    (err) => err.code === 'SITE_CREDENTIAL_NOT_HONOURED' || err.code === 'CIAB_FOOTHOLD_PASSWORD_MISMATCH',
    'a website that hands out a password the forest does not set must refuse to be generated'
  );

  // And an account the forest never creates at all.
  const orphaned = JSON.parse(JSON.stringify(ir));
  orphaned.principals.users = orphaned.principals.users
    .filter((u) => u.sam !== site.pivot.username);
  assert.throws(
    () => content.generateSiteContent(orphaned, { runId: orphaned.run_id, lab }),
    (err) => err.code === 'SITE_CREDENTIAL_NOT_IN_AD' || err.code === 'CIAB_FOOTHOLD_PRINCIPAL_MISSING'
  );
});

test('S2-103 an IR credential the site never plants is a COMPILE ERROR, from the other side', () => {
  const { site, ir } = siteFor(SITE_A, CLIENT_A);
  // A site that published somebody else's account while the chain still starts
  // at the foothold: both halves individually plausible, the lab unsolvable.
  const wrong = JSON.parse(JSON.stringify(site));
  const other = ir.principals.users.filter((u) => u.sam !== site.pivot.username
    && String(u.password || '').length > 0)[0];
  wrong.pivot.username = other.sam;
  wrong.pivot.password = other.password;
  assert.throws(
    () => content.assertSiteSound(wrong, ir, null),
    (err) => err.code === 'SITE_FOOTHOLD_NOT_PLANTED',
    'the chain declares the foothold is planted on the website; a site that plants a different '
    + 'account has to be refused, not deployed'
  );
});

test('S2-104 the AD half of the seam is the COMPILER\'s gate, not a second copy of it', () => {
  const { site, ir, lab } = siteFor(SITE_A, CLIENT_A);
  // Break something only assertFootholdHonoured can see: the chain starts at a
  // principal that is not the foothold. The site's own checks have no opinion
  // about chain.start, so a failure here proves the compiler's gate really runs.
  const drifted = JSON.parse(JSON.stringify(ir));
  drifted.chain.start.principal = drifted.principals.users
    .filter((u) => u.sam !== site.pivot.username)[0].sam;
  assert.throws(
    () => content.generateSiteContent(drifted, { runId: drifted.run_id, lab }),
    (err) => err.code === 'CIAB_CHAIN_START_UNPLANTED',
    'assertFootholdHonoured is the one place this invariant lives; a second copy in the site '
    + 'generator would be a second thing to keep true'
  );
});

test('S2-105 an AD-side entry is never handed to the student off the website', () => {
  for (const runId of [SITE_AD_ASREP, SITE_AD_DESC]) {
    const { site, ir } = siteFor(runId, CLIENT_A);
    const cred = ir.foothold_credential;
    assert.strictEqual(site.carries_foothold, false,
      `${ir.chain.start.kind} is an AD-side entry: the website must not publish its credential`);
    assert.notStrictEqual(site.pivot.username, cred.sam);
    assert.ok(siteText(site).indexOf(cred.password) === -1,
      `the foothold password for a '${ir.chain.start.kind}' lab is on the website, so a student can `
      + 'GET the entry the exercise wanted them to earn and the intended technique is decoration');
    assert.ok(site.warnings.length > 0,
      'a site that deliberately does not plant the foothold says so, rather than being silently '
      + 'different from every other lab');
  }
});

test('S2-106 no OTHER declared credential reaches any page', () => {
  // THE REGRESSION THIS WAS WRITTEN FOR. Two of the seven entry points plant a
  // password into a user's AD `description`, the About page renders `description`
  // because that is where a job title lives, and the first version of this
  // generator published the foothold on the public About page of every
  // anonymous_rpc lab while every other check passed.
  for (const [runId, base] of [[SITE_A, CLIENT_A], [SITE_B, CLIENT_B], [SITE_AD_DESC, CLIENT_A],
    [SITE_AD_ASREP, CLIENT_A], [SITE_MIRROR, CLIENT_A]]) {
    const { site, ir, lab } = siteFor(runId, base);
    const allowed = new Set([site.pivot.password]);
    if (site.directory_path) allowed.add(ir.foothold_credential.password);
    const text = siteText(site);
    for (const secret of content.declaredSecrets(ir, lab)) {
      if (allowed.has(secret)) continue;
      assert.ok(text.indexOf(secret) === -1,
        `${runId}: the website publishes '${secret.slice(0, 4)}...', which is a credential this lab `
        + 'declares and the site is not supposed to hand out');
    }
  }
});

test('S2-107 the description-mirror entry really mirrors the description, on its own page', () => {
  const { site, ir } = siteFor(SITE_MIRROR, CLIENT_A);
  const cred = ir.foothold_credential;
  assert.strictEqual(site.directory_path, ir.foothold_credential.planted_at.path,
    'the chain fixed the path before this module ran; the answer key already prints it');
  const page = routeAt(site, site.directory_path);
  assert.ok(page && page.carries_foothold);
  const user = ir.principals.users.filter((u) => u.sam === cred.sam)[0];
  assert.ok(page.content.indexOf(user.description) !== -1,
    'the page is supposed to print the AD description attribute VERBATIM - that is what the chain\'s '
    + 'own `how` claims the site does');
  assert.ok(page.content.indexOf(cred.password) !== -1);
  assert.ok(site.web_facts.paths.indexOf(site.directory_path) !== -1,
    'the report links to the staff directory, so it has to be a declared path');
});

// --- what the paper is allowed to claim ------------------------------------

test('S3-100 web_facts is the contract readWebFacts consumes, and survives it unchanged', () => {
  for (const [runId, base] of [[SITE_A, CLIENT_A], [SITE_B, CLIENT_B]]) {
    const { site } = siteFor(runId, base);
    const facts = readWebFacts({ web_facts: site.web_facts });
    assert.ok(facts, 'the scan documents must be able to read the block the role is handed');
    assert.strictEqual(facts.product, 'apache');
    assert.deepStrictEqual(facts.ports.slice().sort(), site.web_facts.ports.slice().sort());
    assert.strictEqual(facts.tls.enabled, true);
    assert.strictEqual(facts.tls.port, 443);
    assert.ok(facts.ports.indexOf(80) !== -1 && facts.ports.indexOf(443) !== -1,
      'a company site answers on 80 and terminates TLS on 443');
    assert.deepStrictEqual(facts.paths, site.web_facts.paths,
      'the normaliser must not move a path the report links to');
  }
});

test('S3-101 every declared path has a page, and the filename is the one the role would derive', () => {
  for (const runId of [SITE_A, SITE_B, SITE_MIRROR, SITE_AD_ASREP]) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { site } = siteFor(runId, base);
    for (const declared of site.web_facts.paths) {
      assert.ok(site.routes.some((r) => r.path === declared),
        `${runId}: web_facts declares ${declared} and nothing serves it`);
    }
    const files = site.routes.map((r) => r.file);
    assert.strictEqual(new Set(files).size, files.length, 'two routes resolve to one file');
    // The rule mirrored from roles/cc_web/tasks/resolve.yml. Spot-checked here
    // as a rule rather than as a list, because that is what the role applies.
    assert.strictEqual(content.siteRouteFile('/'), 'index.html');
    assert.strictEqual(content.siteRouteFile('/about'), 'about/index.html');
    assert.strictEqual(content.siteRouteFile('/status/'), 'status/index.html');
    assert.strictEqual(content.siteRouteFile('/robots.txt'), 'robots.txt');
  }
});

test('S3-102 the settings page is NOT a declared path, and the portal names it anyway', () => {
  const { site } = siteFor(SITE_A, CLIENT_A);
  assert.ok(site.web_facts.paths.indexOf(site.admin_path) === -1,
    'a route the paper does not mention is legitimate exercise design; a declared path that serves '
    + 'nothing is the paper lying. The admin panel is the first kind');
  const portal = routeAt(site, site.portal_path);
  assert.ok(portal.content.indexOf(site.admin_path) !== -1,
    'the finding has to be findable: the portal carries the comment that names the unprotected page');
  const robots = routeAt(site, '/robots.txt');
  assert.ok(robots.content.indexOf(site.portal_path) !== -1);
  assert.ok(!/^Disallow: \/$/m.test(robots.content),
    'a robots.txt that disallows the whole site tells a scanner nothing');
});

test('S3-103 no page carries a Jinja delimiter, which ansible would evaluate on the way in', () => {
  for (const runId of [SITE_A, SITE_B, SITE_MIRROR, SITE_AD_DESC, SITE_AD_ASREP]) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { site } = siteFor(runId, base);
    for (const route of site.routes) {
      assert.ok(!/\{\{|\{%/.test(route.content),
        `${runId} ${route.path}: ansible renders a variable's value recursively, so this would either `
        + 'raise AnsibleUndefinedVariable or silently evaluate to something else');
      assert.ok(content.isAscii(route.content), `${runId} ${route.path} is not pure ASCII`);
      assert.ok(route.content.indexOf('\r') === -1, `${runId} ${route.path} carries a CR`);
    }
  }
});

test('S3-104 everything the site asks for is something the cc_web role can actually build', () => {
  // Read off the ROLE, not off a copy of the role's vocabulary. A pool that
  // drifted from the role would be a provisioning refusal ninety minutes in.
  const roleRoot = path.join(ROOT, '..', 'infrastructure', 'ansible', 'cc-web', 'roles', 'cc_web');
  const vars = fs.readFileSync(path.join(roleRoot, 'vars', 'main.yml'), 'utf8');
  const defaults = fs.readFileSync(path.join(roleRoot, 'defaults', 'main.yml'), 'utf8');

  const listAfter = (text, key) => {
    const at = text.indexOf(`\n${key}:`);
    assert.ok(at !== -1, `${key} is gone from the role`);
    return text.slice(at).split('\n').slice(1)
      .filter((l) => /^\s*-\s/.test(l))
      .map((l) => l.replace(/^\s*-\s*/, '').trim().replace(/^["']|["']$/g, ''));
  };
  const formats = listAfter(vars, 'cc_web_pivot_formats');
  const products = listAfter(defaults, 'cc_web_supported_products');
  const undeliverable = listAfter(vars, 'cc_web_undeliverable_protocols');
  const aliasKeys = vars.slice(vars.indexOf('\ncc_web_tls_alias:')).split('\n').slice(1)
    .filter((l) => /^\s{2}\S+:/.test(l))
    .map((l) => l.trim().split(':')[0].replace(/^["']|["']$/g, ''));

  for (const entry of content.SITE_CONFIG_FILES) {
    assert.ok(formats.indexOf(entry.format) !== -1,
      `the site can pick format '${entry.format}' and cc_web renders ${formats.join(', ')}`);
  }
  for (const set of content.SITE_TLS_SETS) {
    for (const token of set) {
      const squashed = token.toLowerCase().replace(/[^a-z0-9.]/g, '');
      assert.ok(aliasKeys.indexOf(squashed) !== -1,
        `the site can declare '${token}' and the role's alias table does not recognise '${squashed}'`);
      assert.ok(undeliverable.indexOf(squashed) === -1,
        `the site can declare '${token}', which the role refuses outright as undeliverable`);
    }
  }
  for (const runId of [SITE_A, SITE_B]) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { site } = siteFor(runId, base);
    assert.ok(products.indexOf(site.web_facts.product) !== -1,
      `the site declares product '${site.web_facts.product}' and the role delivers ${products.join(', ')}`);
    assert.ok(formats.indexOf(site.pivot.format) !== -1);
    assert.strictEqual(typeof site.pivot.mode, 'string',
      'YAML reads an unquoted 0640 as the integer 640, and cc_web asserts the mode is a string');
    assert.strictEqual(site.docroot, content.SITE_DOCROOT);
  }
});

test('S3-105 a site is refused rather than emitted when there is no credential to plant', () => {
  const { ir, lab } = siteFor(SITE_A, CLIENT_A);
  const stripped = JSON.parse(JSON.stringify(ir));
  stripped.foothold_credential = { sam: '', domain: '', password: '', planted_at: null };
  stripped.chain.start = null;
  for (const u of stripped.principals.users) u.password = '';
  assert.throws(
    () => content.generateSiteContent(stripped, { runId: stripped.run_id, lab }),
    (err) => err.code === 'SITE_NO_BIND_CREDENTIAL',
    'a DMZ box that leads nowhere is a defaced homepage rather than a way into the domain, and '
    + 'cc_web refuses to build one - so this has to refuse first'
  );
});

// ---------------------------------------------------------------------------
// S4. THE RESEED SEAM — where a per-lane reseed must rewrite what the site
//     publishes, and in which format.
//
//     The defect: a golden image bakes ONE pivot password, lane-reseed rotated
//     the account in AD per lane, and the website went on publishing the baked
//     value out of its own config file and off /admin/integrations for the
//     whole section. Nothing reported it — the lane was active, the flag was
//     planted, the reseed's warnings were empty — and the pivot the entire
//     engagement is built around simply did not work. These tests are about the
//     half of the fix that lives here: emitting WHERE and IN WHAT FORMAT,
//     because a reseed cannot rewrite what it cannot find and one that guesses
//     the path is the same bug with a longer fuse.
// ---------------------------------------------------------------------------

/** goad-lab-content's own esc(), which is what puts a value into a page. The
 *  descriptor is checked against ESCAPED bytes because that is what a browser
 *  and a reseed both actually meet. */
function esc(v) {
  return String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

test('S4-100 every pivot format the site can pick declares where its password sits', () => {
  // A format with no entry here is a config file the reseed cannot address, so
  // the lane would publish the baked password. generateSiteContent refuses that
  // outright (SITE_RESEED_FORMAT_UNADDRESSABLE); this is the same check one
  // step earlier, over the whole pool rather than over one run.
  for (const entry of content.SITE_CONFIG_FILES) {
    const field = content.SITE_PIVOT_FIELD[entry.format];
    assert.ok(field, `the site can plant a '${entry.format}' config and nothing records where the `
      + 'password sits inside one');
    assert.ok(content.SITE_RESEED_OPS.indexOf(field.op) !== -1,
      `SITE_PIVOT_FIELD.${entry.format} names operation '${field.op}', which is not one of `
      + content.SITE_RESEED_OPS.join(', '));
  }
  // The same, from the other end: every extension the chain may name.
  for (const format of Object.values({
    env: 'dotenv', php: 'php', json: 'json', ini: 'ini', conf: 'ini', cfg: 'ini', xml: 'xml',
  })) {
    assert.ok(content.SITE_PIVOT_FIELD[format], `a chain-named .${format} config is unaddressable`);
  }
});

test('S4-101 the field table addresses the line roles/cc_web really writes', () => {
  // Read off the TEMPLATE, not off a copy of it. If the role's layout changes,
  // the reseed would be pointed at a key that is no longer there and would fail
  // on every lane — so it has to fail here first.
  const j2 = fs.readFileSync(path.join(ROOT, '..', 'infrastructure', 'ansible', 'cc-web',
    'roles', 'cc_web', 'templates', 'pivot-credential.j2'), 'utf8');

  assert.ok(j2.indexOf(`${content.SITE_PIVOT_FIELD.dotenv.key}={{ _pass }}`) !== -1,
    'the dotenv branch no longer writes the key SITE_PIVOT_FIELD.dotenv names');
  assert.ok(j2.indexOf(`'${content.SITE_PIVOT_FIELD.php.key}' =>`) !== -1,
    'the php branch no longer writes the key SITE_PIVOT_FIELD.php names');
  assert.ok(j2.indexOf(`[${content.SITE_PIVOT_FIELD.ini.section}]`) !== -1
    && j2.indexOf(`${content.SITE_PIVOT_FIELD.ini.key} = {{ _pass }}`) !== -1,
  'the ini branch no longer writes the section/key SITE_PIVOT_FIELD.ini names');
  assert.ok(j2.indexOf(`<${content.SITE_PIVOT_FIELD.xml.element}>{{ _pass`) !== -1,
    'the xml branch no longer writes the element SITE_PIVOT_FIELD.xml names');
  const jsonKeys = content.SITE_PIVOT_FIELD.json.keys;
  assert.ok(j2.indexOf(`{'${jsonKeys[0]}': {`) !== -1 && j2.indexOf(`'${jsonKeys[1]}': _pass`) !== -1,
    `the json branch no longer nests the password under ${jsonKeys.join('.')}`);
});

test('S4-102 the descriptor names a page this run really wrote, with the password behind it', () => {
  for (const runId of [SITE_A, SITE_B, SITE_MIRROR, SITE_AD_DESC, SITE_AD_ASREP]) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { site } = siteFor(runId, base);
    const plan = site.reseed;
    assert.ok(plan && plan.plants.length >= 2,
      `${runId}: the site publishes the credential and declares ${plan ? plan.plants.length : 0} `
      + 'place(s) to rewrite it');

    // The config file: the path the role will really install, and the format
    // it will really render.
    const config = plan.plants.filter((p) => p.kind === 'app_config')[0];
    assert.ok(config, `${runId}: nothing names the application config`);
    assert.strictEqual(config.path, site.pivot.path);
    assert.strictEqual(config.format, site.pivot.format);
    assert.deepStrictEqual(config.op, content.SITE_PIVOT_FIELD[site.pivot.format].op);

    // Every page target: a file this run wrote, an anchor that occurs exactly
    // once, and the published password sitting behind it.
    const byFile = new Map(site.routes.map((r) => [`${site.docroot}/${r.file}`, r]));
    const pages = plan.plants.filter((p) => p.op === 'slot');
    assert.ok(pages.length >= 1, `${runId}: no page target at all`);
    for (const page of pages) {
      const route = byFile.get(page.path);
      assert.ok(route, `${runId}: ${page.path} is not a file this site writes`);
      const needle = `${page.anchor}${page.prefix}${esc(site.pivot.password)}${page.suffix}${page.terminator}`;
      const first = route.content.indexOf(needle);
      assert.ok(first !== -1,
        `${runId}: ${page.path} does not carry the password where the descriptor says it does`);
      assert.strictEqual(route.content.indexOf(needle, first + 1), -1,
        `${runId}: ${page.path} matches the descriptor twice, so a rewrite would pick one at random`);
    }
  }
});

test('S4-103 two clients get two different rewrite jobs, not one path with the nouns swapped', () => {
  // The whole reason the location has to travel: it is a fact about THIS
  // client's site. A reseed with a hardcoded path would be right for one lab
  // and silently wrong for every other.
  const a = siteFor(SITE_A, CLIENT_A).site.reseed;
  const b = siteFor(SITE_B, CLIENT_B).site.reseed;
  const pathsA = a.plants.map((p) => p.path).sort().join(',');
  const pathsB = b.plants.map((p) => p.path).sort().join(',');
  assert.notStrictEqual(pathsA, pathsB,
    'two clients publish the credential at identical paths, so nothing here is client-specific');

  // Across the pinned runs the FORMAT differs too, which is the half a regex
  // would get wrong.
  const formats = new Set([SITE_A, SITE_B, SITE_MIRROR, SITE_AD_DESC, SITE_AD_ASREP].map((runId) => {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    return siteFor(runId, base).site.pivot.format;
  }));
  assert.ok(formats.size >= 3,
    `the pinned clients only exercise ${[...formats].join(', ')}; the point is that the reseed has `
    + 'to handle more than one grammar');
});

test('S4-104 a page that stopped carrying the password is a COMPILE ERROR, not a stale descriptor', () => {
  // assertSiteSound proves the descriptor against the bytes this run emitted.
  // Without that, an edit to the settings page would leave a descriptor
  // pointing at markup that is gone — and lane-reseed would find nothing, on
  // every lane, after the images were already baked.
  const { ir, lab, site } = siteFor(SITE_A, CLIENT_A);
  const tampered = JSON.parse(JSON.stringify(site));
  const page = tampered.reseed.plants.filter((p) => p.op === 'slot')[0];
  const route = tampered.routes.filter((r) => `${tampered.docroot}/${r.file}` === page.path)[0];
  route.content = route.content.replace(content.SITE_ADMIN_PASSWORD_ANCHOR,
    '<th>Bind password</th><td><code>');
  assert.throws(
    () => content.assertSiteSound(tampered, ir, lab),
    (err) => err.code === 'SITE_RESEED_ANCHOR_NOT_UNIQUE',
    'a descriptor pointing at markup the page no longer has was accepted'
  );

  // The same from the other direction: a target no route serves.
  const moved = JSON.parse(JSON.stringify(site));
  moved.reseed.plants.filter((p) => p.op === 'slot')[0].path = '/var/www/cc-web/nowhere/index.html';
  assert.throws(
    () => content.assertSiteSound(moved, ir, lab),
    (err) => err.code === 'SITE_RESEED_TARGET_UNSERVED');

  // And a site that records nowhere to rewrite at all.
  const blank = JSON.parse(JSON.stringify(site));
  blank.reseed = { docroot: site.docroot, plants: [], unrotatable: [] };
  assert.throws(
    () => content.assertSiteSound(blank, ir, lab),
    (err) => err.code === 'SITE_RESEED_NO_PLAN',
    'a site that publishes a credential and records no way to rotate it was accepted');
});

test('S4-105 the description-mirror entry records the copy no file rewrite can reach', () => {
  // This entry plants the password in the account's AD `description`, and the
  // staff directory prints that attribute verbatim. The PAGE is rewritable; the
  // directory attribute is not, and saying nothing about it would be the same
  // silent success one layer down.
  const { ir, site } = siteFor(SITE_MIRROR, CLIENT_A);
  assert.strictEqual(ir.foothold_credential.planted_at.format, 'ad_description_mirrored_on_web');

  const dirPlant = site.reseed.plants.filter(
    (p) => p.op === 'slot' && p.path === `${site.docroot}/${routeAt(site, site.directory_path).file}`)[0];
  assert.ok(dirPlant, 'the mirrored staff directory is not in the plant list, so it would go on '
    + 'printing the baked password');
  assert.ok(dirPlant.prefix.length + dirPlant.suffix.length > 0,
    'the password is planted inside a sentence, so the prose either side has to travel with the '
    + 'descriptor or the rewrite would wipe the record');
  assert.ok(dirPlant.prefix.indexOf(site.pivot.password) === -1
    && dirPlant.suffix.indexOf(site.pivot.password) === -1,
  'the descriptor carries the secret itself — it is meant to carry only the words around it');

  const named = site.reseed.unrotatable.map((u) => u.where).join(' | ');
  assert.ok(/AD description of/.test(named),
    `nothing records that the directory attribute still spells the baked password: ${named}`);

  // A web-side plant that is NOT a description mirror has nothing unrotatable.
  const plain = siteFor(SITE_A, CLIENT_A).site;
  assert.deepStrictEqual(plain.reseed.unrotatable, []);
});

test('S4-106 the descriptor carries locations and prose, never a credential', () => {
  // It is written onto the deploy spec and read back on every lane, and lane
  // config is served to the lane's owner. A password in here would be the
  // answer key.
  for (const runId of [SITE_A, SITE_B, SITE_MIRROR, SITE_AD_DESC, SITE_AD_ASREP]) {
    const base = runId.indexOf('_B_') !== -1 ? CLIENT_B : CLIENT_A;
    const { ir, lab, site } = siteFor(runId, base);
    const text = JSON.stringify(site.reseed);
    for (const secret of content.declaredSecrets(ir, lab)) {
      assert.ok(text.indexOf(secret) === -1,
        `${runId}: the reseed descriptor contains a declared credential`);
    }
    assert.ok(text.indexOf(site.pivot.password) === -1,
      `${runId}: the reseed descriptor spells out the password it is supposed to replace`);
  }
});
