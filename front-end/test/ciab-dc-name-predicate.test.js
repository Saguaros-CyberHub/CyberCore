/**
 * ciab-dc-name-predicate.test.js — one question, one answer, on both sides.
 *
 * WHAT THIS FILE IS GUARDING
 *
 * "Is this register entry a domain controller?" is asked twice about the same
 * asset register, ninety minutes apart:
 *
 *   - ai/profile/validators.js/validateSizing (S-01, S-02) asks it to STRIP
 *     controllers off a profile whose org-sizing puts the client below the
 *     domain floor, or to trim them to max_dcs. What survives is what the
 *     student's paper says the client owns.
 *   - utils/goad-lab-compile.js/paperForestNames asks it to ADOPT the
 *     register's names into the forest, splitting them into the controller and
 *     member pools the chassis binds against.
 *
 * The two used to hold byte-identical copies of the regex, kept in step by a
 * comment. That is a social contract enforcing a mechanical invariant, and it
 * has a specific failure: the copies drift, one side files a machine as a
 * controller that the other files as a member, and the bake mints a controller
 * name the deploy spec never asks for. Nothing fails at generation time. The
 * bake runs for ~90 minutes, the golden templates come out named after machines
 * the deploy does not have, and profile-deploy refuses BAKE_GOLDEN_UNMATCHED.
 *
 * THE BUG THAT FORCED THE SHARING. `\bdc\b` needs a word boundary on BOTH sides
 * of the token. The generated hostname themes happen to give it one (`dc-01`,
 * `tuc-dc-01`); real clients typing their own register do not (`SVO-DC01`,
 * `HQDC1`, `ADDC01`), because a digit is a word character and kills the
 * trailing boundary. Half the client x register combinations measured had their
 * actual domain controller adopted as a member server. Widening the predicate
 * in one file only would have been the drift both files exist to prevent, so
 * the predicate moved to ai/profile/dc-name.js and both files import it.
 *
 * Run: node --test front-end/test/ciab-dc-name-predicate.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const P = (p) => path.join(ROOT, 'modules/crucible/plugins/ciab', p);

const dcName = require(P('ai/profile/dc-name.js'));
const validators = require(P('ai/profile/validators.js'));
const compile = require(P('utils/goad-lab-compile.js'));

// ─── The corpus ─────────────────────────────────────────────────────────────
/*
 * Every name below is a claim about a machine that ends up on a lane, so each
 * carries the reason it is classified the way it is. Three groups:
 *
 *   THEME      what ai/profile/prompts.js renders. These passed before the
 *              widening and must still pass — they are the regression half.
 *   REAL       what a client types on the real-client intake path. These are
 *              the defect: `DC` glued to a digit, with or without a site prefix
 *              glued to its front.
 *   NEAR-MISS  names carrying `dc` that are NOT controllers. Getting these
 *              wrong is the expensive direction: a false negative leaves the DC
 *              pool short and is warned about by name at bake time and refused
 *              at deploy, but a false positive silently promotes a file server
 *              into the forest's directory while every document the student
 *              holds still calls it a file server.
 */
const CORPUS = Object.freeze([
  // ── THEME: hyphen-delimited, what the generated profiles produce ──────────
  { role: 'server', hostname: 'DC-01',     dc: true, why: 'theme: the canonical generated controller' },
  { role: 'server', hostname: 'DC-02',     dc: true, why: 'theme: the second generated controller' },
  { role: 'server', hostname: 'tuc-dc-01', dc: true, why: 'theme: site-prefixed, lowercase' },
  { role: 'server', hostname: 'phx-dc-02', dc: true, why: 'theme: the other site prefix' },
  { role: 'server', hostname: 'SEA-DC-01', dc: true, why: 'theme: site-prefixed, uppercase' },
  { role: 'server', hostname: 'dc',        dc: true, why: 'the bare token, boundaries on both sides' },

  // ── REAL: typed by a client, DC glued to a digit ──────────────────────────
  { role: 'server', hostname: 'SVO-DC01', dc: true, why: 'real: site prefix, hyphen, DC + digits' },
  { role: 'server', hostname: 'HQDC1',    dc: true, why: 'real: site prefix glued straight onto DC' },
  { role: 'server', hostname: 'ADDC01',   dc: true, why: 'real: AD prefix glued onto DC' },
  { role: 'server', hostname: 'DC1',      dc: true, why: 'real: the shortest form there is' },
  { role: 'server', hostname: 'CORPDC02', dc: true, why: 'real: org prefix glued onto DC' },
  { role: 'server', hostname: 'DC01',     dc: true, why: 'real: no prefix, two digits' },
  { role: 'server', hostname: 'PDC01',    dc: true, why: 'real: the primary, in NT vocabulary' },
  { role: 'server', hostname: 'BDC2',     dc: true, why: 'real: the backup, in NT vocabulary' },
  { role: 'server', hostname: 'LONDC03',  dc: true, why: 'real: three-letter site code, glued' },
  { role: 'server', hostname: 'SRV1DC',   dc: true, why: 'real: DC after a digit, nothing following' },

  // ── REAL: the role sentence says it outright ──────────────────────────────
  { role: 'Domain Controller', hostname: 'SRV-11', dc: true, why: 'the role names it in words' },
  { role: 'domain-controller', hostname: 'SRV-12', dc: true, why: 'the same words, hyphenated' },
  { role: 'Active Directory Domain Services', hostname: 'SRV-13', dc: true, why: 'named by the service' },
  { role: 'Primary domain controller / DNS', hostname: 'SRV-14', dc: true, why: 'named inside a sentence' },

  // ── NEAR-MISS: carries `dc`, is not a controller ──────────────────────────
  { role: 'server', hostname: 'FS-DCOM01', dc: false, why: 'a fileserver: DC is followed by letters' },
  { role: 'server', hostname: 'ABDCEF',    dc: false, why: 'DC buried between letters on both sides' },
  { role: 'server', hostname: 'ABDC',      dc: false, why: 'letters glued in front and nothing after: the '
    + 'old predicate never claimed it and admitting it would buy only false positives' },
  { role: 'server', hostname: 'NAS-DCIM02', dc: false, why: 'DCIM is datacenter infrastructure management' },
  { role: 'server', hostname: 'EDCPRINT1',  dc: false, why: 'DC followed by letters, digits further out' },
  { role: 'server', hostname: 'MEDCART1',   dc: false, why: 'MEDCART: `dc` spans two words of one name' },
  { role: 'file server', hostname: 'FS-01',  dc: false, why: 'the member the register is full of' },
  { role: 'server', hostname: 'WEB-01',      dc: false, why: 'the DMZ pivot, never a forest host' },
  { role: 'server', hostname: 'APP-01',      dc: false, why: 'a plain member server' },
  { role: 'server', hostname: 'SQL01',       dc: false, why: 'a database member' },
  { role: 'server', hostname: 'PRINT-SRV02', dc: false, why: 'a print member' },
  { role: 'broadcast encoder', hostname: 'BCAST-01', dc: false, why: '`dc` inside an ordinary word' },
  { role: 'handcuff inventory host', hostname: 'EVID-02', dc: false, why: '`dc` inside another one' },
  { role: 'workstation', hostname: 'WS-014', dc: false, why: 'not a server at all' },
]);

test('DC-100 the corpus is big enough and covers both directions', () => {
  // A corpus that drifted to all-controllers would pass every assertion below
  // against a predicate that always says yes, which is the exact failure mode
  // the near-miss half exists to catch.
  assert.ok(CORPUS.length >= 25, `corpus is ${CORPUS.length} names, want >= 25`);
  assert.ok(CORPUS.filter((c) => c.dc).length >= 10, 'not enough controllers');
  assert.ok(CORPUS.filter((c) => !c.dc).length >= 10, 'not enough near-misses');
  const seen = new Set(CORPUS.map((c) => c.hostname));
  assert.strictEqual(seen.size, CORPUS.length,
    'hostnames must be unique — the validators probe below reports by hostname');
});

test('DC-101 the shared predicate classifies the whole corpus as the corpus says', () => {
  for (const c of CORPUS) {
    assert.strictEqual(dcName.isDcRecord(c), c.dc,
      `${c.role} / ${c.hostname} -> expected dc=${c.dc} (${c.why})`);
  }
});

test('DC-102 the widening is strictly a widening: nothing the old predicate matched is lost', () => {
  // The old predicate, spelled out here ONCE, as the thing being superseded.
  // Every string it accepted must still be accepted, or a profile that compiled
  // last week stops finding its controllers this week.
  const OLD = /domain controller|\bdc\b|active directory/i;
  const probes = CORPUS.map((c) => `${c.role} ${c.hostname}`).concat([
    'domain controller', 'ACTIVE DIRECTORY', 'srv dc corp', 'dc.example.com', 'the DC role',
  ]);
  for (const s of probes) {
    if (OLD.test(s)) {
      assert.ok(dcName.looksLikeDcName(s),
        `the old predicate matched ${JSON.stringify(s)} and the new one must too`);
    }
  }
});

test('DC-103 null, undefined and non-objects are members, not crashes', () => {
  // The register is LLM-authored on one path and client-typed on the other;
  // both produce entries with fields missing. A throw here fails a whole
  // profile generation over one malformed row.
  assert.strictEqual(dcName.isDcRecord(null), false);
  assert.strictEqual(dcName.isDcRecord(undefined), false);
  assert.strictEqual(dcName.isDcRecord('DC-01'), false, 'a bare string is not a record');
  assert.strictEqual(dcName.isDcRecord({}), false);
  assert.strictEqual(dcName.isDcRecord({ hostname: 'DC-01' }), true, 'a missing role is not a blocker');
  assert.strictEqual(dcName.isDcRecord({ role: 'Domain Controller' }), true, 'nor a missing hostname');
  assert.strictEqual(dcName.looksLikeDcName(null), false);
  assert.strictEqual(dcName.looksLikeDcName(undefined), false);
});

test('DC-104 the regex is stateless — no /g, so repeated calls do not alternate', () => {
  // A /g regex carries lastIndex across .test() calls, so the same name would
  // classify differently on the second asset register of the same process. The
  // compiler is required to be deterministic; this is one of the ways it would
  // silently stop being.
  assert.ok(!dcName.DC_NAME_RE.global, 'DC_NAME_RE must not be global');
  for (let i = 0; i < 3; i += 1) {
    assert.strictEqual(dcName.looksLikeDcName('SVO-DC01'), true, `call ${i}`);
    assert.strictEqual(dcName.looksLikeDcName('FS-DCOM01'), false, `call ${i}`);
  }
});

// ─── Both consumers, over the same corpus ───────────────────────────────────

/** A sizing object shaped the way computeOrgSizing returns one. */
function sizingFixture(over) {
  const o = over || {};
  return {
    sector: 'SMB',
    employees: 110,
    delivery_class: 'onprem',
    identity: Object.assign(
      { has_domain: true, max_dcs: 2, second_dc_at: 150, domain_floor: 15, directory: 'on-prem AD' },
      o.identity),
    servers: Object.assign({ max_file_servers: 99, max_total: 999 }, o.servers),
    security: Object.assign(
      { siem: true, siem_threshold: 250, edr_tier: 'edr', firewall_tier: 'smb' }, o.security),
    staffing: Object.assign({ it_fte: 2 }, o.staffing),
  };
}

/**
 * What validators.js thinks is a controller, read out of its OBSERVABLE
 * behaviour rather than out of a symbol it does not export.
 *
 * S-01 deletes exactly the controllers from a profile whose sizing says the
 * client has no domain, so the set that does NOT survive is the set
 * validateSizing calls controllers. That is the closest thing to asking the
 * question directly, and unlike a source-level probe it would still catch a
 * re-forked predicate.
 */
function validatorsDcSet(records) {
  const payload = {
    it_environment: {
      servers: records.map((r) => ({ role: r.role, hostname: r.hostname, os: 'Windows Server 2019' })),
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({ identity: { has_domain: false } }),
    employeeCount: 8,
  });
  const survivors = new Set(out.payload.it_environment.servers.map((s) => s.hostname));
  return new Set(records.map((r) => r.hostname).filter((h) => !survivors.has(h)));
}

test('DC-105 validateSizing and the compiler classify the corpus identically', () => {
  // THE test in this file. Not "both call the shared module" — that is a source
  // fact and a future edit can undo it — but "both answer the same about the
  // same thirty-odd names", which is the property the bake actually depends on.
  const paper = validatorsDcSet(CORPUS);

  const disagreements = [];
  for (const c of CORPUS) {
    const onPaper = paper.has(c.hostname);
    const onLane = compile.isPaperDc({ role: c.role, hostname: c.hostname });
    if (onPaper !== onLane) {
      disagreements.push(`${c.hostname}: validators=${onPaper} compiler=${onLane}`);
    }
    assert.strictEqual(onLane, c.dc, `compiler: ${c.hostname} (${c.why})`);
    assert.strictEqual(onPaper, c.dc, `validators: ${c.hostname} (${c.why})`);
  }
  assert.deepStrictEqual(disagreements, [],
    'the paper and the lane disagree about these machines, which is '
    + 'BAKE_GOLDEN_UNMATCHED ninety minutes into a bake');
});

test('DC-106 neither consumer keeps a private copy of the predicate', () => {
  // Source-level on purpose. DC-105 compares answers, but two copies that agree
  // today are exactly the state this defect started from — the drift arrives
  // with the NEXT edit, and by then the corpus has been extended against
  // whichever copy the author happened to be looking at. So the copies must not
  // exist at all.
  for (const rel of ['utils/goad-lab-compile.js', 'ai/profile/validators.js']) {
    const src = fs.readFileSync(P(rel), 'utf8');
    assert.ok(!src.includes('\\bdc\\b'),
      `${rel} spells a \\bdc\\b of its own — the predicate lives in ai/profile/dc-name.js`);
    assert.match(src, /require\(['"](?:\.\.\/ai\/profile\/dc-name|\.\/dc-name)['"]\)/,
      `${rel} must import the shared predicate`);
  }
});

// ─── validateSizing's own behaviour, unchanged ──────────────────────────────

test('DC-107 S-01 still removes every controller from a profile below the domain floor', () => {
  const payload = {
    it_environment: {
      servers: [
        { role: 'server', hostname: 'DC-01' },
        { role: 'file server', hostname: 'FS-01' },
        { role: 'server', hostname: 'APP-01' },
      ],
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({ identity: { has_domain: false, domain_floor: 25 } }),
    employeeCount: 12,
  });
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname), ['FS-01', 'APP-01']);
  assert.ok(out.review.some((r) => r.id === 'S-01'), 'the removal is flagged for review, never silent');
  assert.ok(out.warnings.some((w) => /S-01/.test(w) && /AD floor is 25/.test(w)),
    `the warning names the floor: ${out.warnings.join(' | ')}`);
});

test('DC-108 S-01 now also catches the real-world controller it used to miss', () => {
  // The same defect from the paper side. A 12-employee client whose register
  // names SVO-DC01 used to keep it: `\bdc\b` did not match, so the profile
  // shipped with a domain controller its own sizing said it could not have, and
  // the student's paper described a domain the lane's forest never served.
  const payload = {
    it_environment: {
      servers: [{ role: 'server', hostname: 'SVO-DC01' }, { role: 'server', hostname: 'FS-DCOM01' }],
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({ identity: { has_domain: false } }),
    employeeCount: 12,
  });
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname), ['FS-DCOM01'],
    'the controller goes, and the DCOM host — which is not a controller — stays');
  assert.ok(out.review.some((r) => r.id === 'S-01'));
});

test('DC-109 S-02 still trims controllers above max_dcs, keeping the first ones', () => {
  const payload = {
    it_environment: {
      servers: [
        { role: 'server', hostname: 'DC-01' },
        { role: 'server', hostname: 'DC-02' },
        { role: 'server', hostname: 'DC-03' },
        { role: 'file server', hostname: 'FS-01' },
      ],
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({ identity: { has_domain: true, max_dcs: 2, second_dc_at: 150 } }),
    employeeCount: 110,
  });
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname),
    ['DC-01', 'DC-02', 'FS-01'], 'register order is the tie-break, and the member is untouched');
  assert.ok(out.review.some((r) => r.id === 'S-02'));
  assert.ok(!out.review.some((r) => r.id === 'S-01'), 'a client WITH a domain is not stripped');
});

test('DC-110 S-02 counts real-world controller names too', () => {
  // Three controllers on a 110-employee client, named the way a client names
  // them. Before the widening this counted ZERO controllers, S-02 never fired,
  // and the profile shipped one more DC than its own sizing allows.
  const payload = {
    it_environment: {
      servers: [
        { role: 'server', hostname: 'HQDC1' },
        { role: 'server', hostname: 'ADDC01' },
        { role: 'server', hostname: 'CORPDC02' },
        { role: 'server', hostname: 'ABDCEF' },
      ],
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({ identity: { has_domain: true, max_dcs: 2 } }),
    employeeCount: 110,
  });
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname),
    ['HQDC1', 'ADDC01', 'ABDCEF'], 'the third controller is trimmed; the near-miss was never one');
  assert.ok(out.review.some((r) => r.id === 'S-02'));
});

test('DC-111 the rest of validateSizing is untouched by the widening', () => {
  // S-03/S-04 and the C-01 contradiction check read the servers array S-01 and
  // S-02 edit, so a change in what counts as a controller could quietly change
  // what they see. Pinned here so that stays deliberate.
  const payload = {
    it_environment: {
      servers: [
        { role: 'file server', hostname: 'FS-01' },
        { role: 'file server', hostname: 'FS-02' },
        { role: 'file server', hostname: 'FS-03' },
      ],
      endpoints: { windows_laptops: 100 },
      policies: 'all workstations are domain-joined',
    },
    network: {},
  };
  const out = validators.validateSizing(payload, {
    sizing: sizingFixture({
      identity: { has_domain: false },
      servers: { max_file_servers: 1, max_total: 2 },
    }),
    employeeCount: 110,
  });
  const ids = out.review.map((r) => r.id);
  assert.ok(!ids.includes('S-01'), 'no controllers were named, so nothing is stripped');
  assert.ok(ids.includes('S-03'), 'file servers are still trimmed by their own predicate');
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname), ['FS-01']);
  assert.ok(ids.includes('C-01'), 'domain-joined without a domain is still the contradiction check');
});

test('DC-112 validateSizing with no sizing is still a no-op, not a throw', () => {
  const payload = { it_environment: { servers: [{ role: 'server', hostname: 'DC-01' }] } };
  const out = validators.validateSizing(payload, {});
  assert.deepStrictEqual(out.payload.it_environment.servers.map((s) => s.hostname), ['DC-01']);
  assert.deepStrictEqual(out.warnings, []);
});
