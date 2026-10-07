/**
 * ciab-goad-lab-compile.test.js — the composer: profile in, deployable lab out.
 *
 * WHAT THIS FILE IS ACTUALLY GUARDING
 * Everything the compiler gets wrong is expensive in the same way: it does not
 * fail at generation time, it fails 30-95% of the way into a ~90 minute bake, or
 * it does not fail at all and a lane comes up green carrying somebody else's
 * lab. So the assertions below are weighted towards the mistakes that DEPLOY:
 *
 *   - a chassis placeholder that survived compilation (`chassis.invalid`,
 *     `CHASSIS-DC01`). Deploys perfectly. Is not this client's lab.
 *   - a DC whose local_admin_password drifted from its domain_password. Every
 *     child dcpromo authenticates with that credential; the failure names
 *     neither field.
 *   - a never_emit role. `shares` is broken upstream and `adcs_esc7`'s guard is
 *     inverted, so both report GREEN having planted nothing.
 *   - a foothold credential naming a principal AD never creates. The student
 *     finds it on the web app, sprays it, and the exercise has no second act.
 *   - two clients getting structurally the same lab. That is the GOAD-Light
 *     reskin failure: it renamed every noun and kept all twelve ACL edges, and
 *     the generated answer key then describes an attack path as if it had been
 *     derived from that client's risk profile.
 *
 * WHY SO MANY TESTS COMPILE A WHOLE LAB
 * The compiler's contract is that its output passes goad-lab-validate AND
 * goad-preflight. Asserting that on a real emitted tree is worth more than
 * asserting it on a hand-written fixture, because the fixture is the thing most
 * likely to be wrong in the same direction as the code.
 *
 * Run: node --test front-end/test/ciab-goad-lab-compile.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const P = (p) => path.join(ROOT, 'modules/crucible/plugins/ciab', p);

const compile = require(P('utils/goad-lab-compile.js'));
const validate = require(P('utils/goad-lab-validate.js'));
const preflight = require(P('utils/goad-preflight.js'));
const manifest = require(P('utils/goad-role-manifest.js'));
const push = require(P('utils/goad-lab-push.js'));

// ─── Fixtures ───────────────────────────────────────────────────────────────

const DEFAULT_STAKEHOLDERS = Object.freeze([
  { name: 'Dr. Jane Smith', role: 'Chief Executive Officer', department: 'Executive' },
  { name: 'Marcus Webb', role: 'IT Manager', department: 'IT' },
  { name: 'Priya Raghunathan-Venkataraman', role: 'Controller', department: 'Finance' },
  { name: 'Tom Ng Jr.', role: 'Operations Lead', department: 'Operations' },
]);

/**
 * A profile in the layout production actually hands the compiler: the DB row
 * spread over `json_data`, with the organization nested under
 * student_view.raw.threats. readProfile() also accepts the flat and quick-view
 * layouts; this is the one that matters.
 */
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
              hq_city: o.city === undefined ? 'Tucson, AZ' : o.city,
              industry: 'Professional Services',
              department_breakdown: o.departments
                || { Operations: 20, Sales: 10, Finance: 6, IT: 4, Administration: 5 },
            },
            it_environment: { delivery: o.delivery || 'Hybrid' },
          },
        },
        stakeholders: o.stakeholders === undefined ? DEFAULT_STAKEHOLDERS : o.stakeholders,
      },
    },
  };
}

/**
 * The tier a fixture lands on is DERIVED, never passed in, so each fixture's
 * size and sector is chosen to sit unambiguously inside one rung of the ladder:
 *   S  42 employees — below org-sizing's second-DC threshold for every seed
 *      (the baseline is drawn from 60-80, so anything under 60 is always S)
 *   M  110 employees, single site
 *   L  320 employees across the multiple sites org-sizing derives above ~150
 */
const FIXTURES = Object.freeze({
  S: { runId: 'RUN_2026_RIDGELINE', company: 'Ridgeline Dental Group', domain: 'ridgelinedental.com', employees: 42 },
  // The two M fixtures are the variety pair: same tier, same size, different
  // clients. Every structural axis below is asserted to differ between them.
  M_A: { runId: 'RUN_2026_CASCADE', company: 'Cascade Freight Services', domain: 'cascadefreight.com', employees: 110 },
  M_B: { runId: 'RUN_2026_TIDEWATER', company: 'Tidewater Marine Supply', domain: 'tidewatermarine.com', employees: 110 },
  L: {
    runId: 'RUN_2026_VANTAGE',
    company: 'Vantage Utilities Cooperative',
    domain: 'vantageutil.coop',
    employees: 320,
    clientType: 'Utility_IT_OT',
  },
});

const compiled = {};
function compileFixture(key) {
  if (!compiled[key]) compiled[key] = compile.compileLab(profileFixture(FIXTURES[key]));
  return compiled[key];
}

/** Every emitted lab, once, for the sweeps that must hold on all three tiers. */
function allTiers() {
  return ['S', 'M_A', 'M_B', 'L'].map((k) => ({ key: k, out: compileFixture(k) }));
}

function labOf(out) {
  return JSON.parse(out.files['data/config.json']).lab;
}

function groupsOf(out) {
  return validate.parseInventory(out.files['data/inventory']).groups;
}

// ─── B1. Tier selection ─────────────────────────────────────────────────────

test('B1-100 the ladder is domains, not DCs: each fixture selects its tier from sizing alone', () => {
  assert.strictEqual(compileFixture('S').tier, 'S');
  assert.strictEqual(compileFixture('M_A').tier, 'M');
  assert.strictEqual(compileFixture('M_B').tier, 'M');
  assert.strictEqual(compileFixture('L').tier, 'L');
});

test('B1-101 each tier emits the domain count its story requires', () => {
  // S is one domain because `lab.domains[d].dc` is a scalar and
  // roles/domain_controller_slave has zero references — a second DC is only
  // reachable as a second DOMAIN, so the ladder counts domains.
  assert.strictEqual(compileFixture('S').ir.domains.length, 1);

  const m = compileFixture('M_A').ir.domains;
  assert.strictEqual(m.length, 2);
  assert.strictEqual(m[0].is_forest_root, true);
  assert.strictEqual(m[1].is_forest_root, false);
  assert.strictEqual(m[1].parent_fqdn, m[0].fqdn);

  const l = compileFixture('L').ir.domains;
  assert.strictEqual(l.length, 3);
  assert.strictEqual(l.filter((d) => d.is_forest_root).length, 2, 'tier L is two forests');
  assert.strictEqual(l[0].trust_fqdn, l[2].fqdn);
  assert.strictEqual(l[2].trust_fqdn, l[0].fqdn, 'ad-trusts.yml builds the link in both directions');
});

test('B1-102 selectTier reuses org-sizing rather than forming a second opinion', () => {
  const { tier, sizing, reason } = compile.selectTier(compile.readProfile(profileFixture(FIXTURES.M_A)));
  assert.strictEqual(tier, 'M');
  assert.strictEqual(sizing.identity.has_domain, true);
  // The rung is named by the same numbers validators.js/validateSizing enforces
  // on the paper side (S-02 trims DCs above max_dcs at second_dc_at). A second
  // opinion here is how the paper and the lane drift apart.
  assert.ok(reason.includes(String(sizing.identity.second_dc_at)),
    `reason should name second_dc_at, got: ${reason}`);
});

test('B1-103 a profile below the domain floor is REFUSED, not given an empty forest', () => {
  const belowFloor = profileFixture({
    runId: 'RUN_2026_FOODBANK',
    company: 'Willow Street Food Bank',
    domain: 'willowfood.org',
    employees: 9,
    clientType: 'NonProfit',
    delivery: 'Cloud-First',
  });
  assert.throws(() => compile.compileLab(belowFloor), (err) => {
    assert.strictEqual(err.code, 'CIAB_NO_AD_TO_COMPILE');
    assert.strictEqual(err.status, 422);
    // The message has to name the REASON, not just the rule: whoever sees this
    // is deciding whether to deploy the lane without AD at all.
    assert.match(err.message, /has no Active Directory to compile/);
    assert.match(err.message, /9-employee NonProfit/);
    assert.match(err.message, /delivery=cloud/);
    assert.strictEqual(err.sizing.identity.has_domain, false);
    return true;
  });
});

test('B1-104 an on-prem org just above its sector floor still compiles', () => {
  // The floor is per sector AND per delivery posture: an SMB running on-prem has
  // a domain at 16 employees where a cloud-first one never does. Refusing the
  // whole band would be as wrong as building AD for everybody.
  const out = compile.compileLab(profileFixture({
    runId: 'RUN_2026_SMALLSHOP',
    company: 'Ironwood Cabinetry',
    domain: 'ironwoodcab.com',
    employees: 22,
    delivery: 'On-Premises',
  }));
  assert.strictEqual(out.tier, 'S');
});

test('B1-105 a profile with no run_id is refused rather than silently seeded', () => {
  const noSeed = profileFixture(Object.assign({}, FIXTURES.S));
  delete noSeed.json_data.student_view.meta.run_id;
  assert.throws(() => compile.compileLab(noSeed), (err) => {
    assert.strictEqual(err.code, 'CIAB_PROFILE_NO_RUN_ID');
    return true;
  });
});

// ─── B2. Determinism ────────────────────────────────────────────────────────

test('B2-100 the same profile compiles byte-identically twice', () => {
  // Paper-vs-lane parity is asserted BY regeneration, so a single Math.random()
  // or Date.now() anywhere in this path silently makes that impossible.
  const a = compile.compileLab(profileFixture(FIXTURES.L));
  const b = compile.compileLab(profileFixture(FIXTURES.L));
  for (const name of compile.TREE_FILES) {
    assert.strictEqual(a.files[name], b.files[name], `${name} is not reproducible`);
  }
  assert.deepStrictEqual(a.ir, b.ir);
  assert.strictEqual(a.ir.lab_name, b.ir.lab_name);
});

test('B2-101 a different run_id produces a different lab name', () => {
  assert.notStrictEqual(compileFixture('M_A').ir.lab_name, compileFixture('M_B').ir.lab_name);
});

test('B2-102 department key ORDER does not change the lab', () => {
  // An LLM emits department_breakdown keys in whatever order it feels like. If
  // that order reached the OU list, the same profile would compile to a
  // different directory on a re-run.
  const forward = profileFixture(Object.assign({}, FIXTURES.M_A, {
    departments: { Operations: 20, Sales: 10, Finance: 6, IT: 4, Administration: 5 },
  }));
  const shuffled = profileFixture(Object.assign({}, FIXTURES.M_A, {
    departments: { IT: 4, Administration: 5, Operations: 20, Finance: 6, Sales: 10 },
  }));
  assert.strictEqual(
    compile.compileLab(forward).files['data/config.json'],
    compile.compileLab(shuffled).files['data/config.json']
  );
});

// ─── B3. Structural variety ─────────────────────────────────────────────────

test('B3-100 two same-tier clients differ STRUCTURALLY, not just in names', () => {
  const a = compileFixture('M_A');
  const b = compileFixture('M_B');
  assert.strictEqual(a.tier, b.tier);

  // OU SHAPE — one client's directory is a tiered company OU, the other's is
  // flat CN=Users. Compared by count and container, never by OU name: two labs
  // whose only difference is the noun on the OU are the reskin failure.
  assert.notStrictEqual(a.ir.principals.ous.length, b.ir.principals.ous.length);
  const containers = (out) => [...new Set(out.ir.principals.groups.map((g) => g.path.replace(/,DC=.*/, '')))].sort();
  assert.notDeepStrictEqual(containers(a), containers(b));

  // GROUP SHAPE — scope mix, not group names. AGDLP's domainlocal resource tier
  // either exists or it does not.
  const scopeMix = (out) => out.ir.principals.groups
    .reduce((acc, g) => { acc[g.scope] = (acc[g.scope] || 0) + 1; return acc; }, {});
  assert.notDeepStrictEqual(scopeMix(a), scopeMix(b));

  // SERVICE PLACEMENT — which host carries which service is the first thing a
  // tester maps, and it is inventory truth, not cosmetics.
  const svc = (out) => {
    const g = groupsOf(out);
    return JSON.stringify({ iis: g.iis, mssql: g.mssql, mssql_ssms: g.mssql_ssms, webdav: g.webdav });
  };
  assert.notStrictEqual(svc(a), svc(b));

  // DEFENSIVE POSTURE — defender.yml's own groups.
  const def = (out) => {
    const g = groupsOf(out);
    return JSON.stringify({ on: g.defender_on, off: g.defender_off });
  };
  assert.notStrictEqual(def(a), def(b));

  // VULN PLACEMENT — per host, as a set, so a reordering does not read as a
  // difference and an identical plant cannot hide behind one.
  const vulns = (out) => JSON.stringify(Object.entries(labOf(out).hosts)
    .map(([k, h]) => [k, h.vulns.slice().sort()]));
  assert.notStrictEqual(vulns(a), vulns(b));

  // And the whole-lab fingerprint, which is all of the above at once.
  assert.notDeepStrictEqual(compile.structuralSignature(a.ir), compile.structuralSignature(b.ir));
});

test('B3-101 a run of same-size clients produces no two identical lab shapes', () => {
  // One pair differing is a coincidence away from being meaningless. This is the
  // property that matters: a cohort of clients does not get the same lab twice.
  const seen = new Map();
  for (let i = 0; i < 12; i++) {
    const out = compile.compileLab(profileFixture({
      runId: `RUN_2026_SWEEP_${i}`,
      company: `Client Number ${i} Services`,
      domain: `client${i}svc.com`,
      employees: 110,
    }));
    const sig = JSON.stringify(compile.structuralSignature(out.ir));
    assert.ok(!seen.has(sig), `run ${i} has the same shape as run ${seen.get(sig)}`);
    seen.set(sig, i);
  }
  assert.strictEqual(seen.size, 12);
});

test('B3-102 variety never costs correctness: every shape still validates and pre-flights', () => {
  for (let i = 0; i < 10; i++) {
    const out = compile.compileLab(profileFixture({
      runId: `RUN_2026_SHAPE_${i}`,
      company: `Shape Test ${i} Holdings`,
      domain: `shapetest${i}.org`,
      employees: 60 + i * 40,
      clientType: ['SMB', 'NonProfit', 'Utility_IT_OT', 'K12', 'Library'][i % 5],
      delivery: ['On-Premises', 'Hybrid'][i % 2],
    }));
    const result = validate.validateLab({
      lab: labOf(out), inventory: out.files['data/inventory'], labName: out.ir.lab_name,
    });
    assert.deepStrictEqual(result.errors, [], `${out.ir.lab_name} failed the validator`);
    const pf = preflight.preflightGoadLab({
      labName: out.ir.lab_name,
      config: out.files['data/config.json'],
      inventory: out.files['data/inventory'],
      providerInventory: out.files['providers/proxmox/inventory'],
      playbooks: out.chain,
    });
    assert.deepStrictEqual(pf.errors, [], `${out.ir.lab_name} failed pre-flight`);
  }
});

// ─── B4. The three password rules ───────────────────────────────────────────

test('B4-100 every domain_password satisfies the DEFAULT Windows policy', () => {
  // This string is win_domain's safe_mode_password at forest creation, which
  // runs FIVE playbooks before password_policy relaxes anything — so the default
  // policy applies no matter what the lab loosens later.
  for (const { key, out } of allTiers()) {
    for (const [fqdn, domain] of Object.entries(labOf(out).domains)) {
      const pw = String(domain.domain_password);
      assert.ok(pw.length >= validate.MIN_DOMAIN_PASSWORD_LEN,
        `${key} ${fqdn}: domain_password is ${pw.length} characters`);
      assert.ok(validate.passwordClasses(pw) >= validate.REQUIRED_PASSWORD_CLASSES,
        `${key} ${fqdn}: domain_password uses ${validate.passwordClasses(pw)} character classes`);
    }
  }
});

test('B4-101 every local_admin_password clears the local floor and avoids the account name', () => {
  for (const { key, out } of allTiers()) {
    for (const [hostKey, host] of Object.entries(labOf(out).hosts)) {
      const pw = String(host.local_admin_password);
      assert.ok(pw.length >= validate.MIN_LOCAL_ADMIN_PASSWORD_LEN,
        `${key} ${hostKey}: local_admin_password is ${pw.length} characters`);
      assert.ok(validate.passwordClasses(pw) >= validate.REQUIRED_PASSWORD_CLASSES,
        `${key} ${hostKey}: local_admin_password uses ${validate.passwordClasses(pw)} classes`);
      // Windows complexity rejects any password containing a 3+ character token
      // of the account name, and admin_user is `administrator` in every chassis.
      assert.ok(!validate.containsAccountName(pw, 'administrator'),
        `${key} ${hostKey}: local_admin_password contains the account name`);
    }
  }
});

test('B4-102 a DC local_admin_password IS its domain_password, in every domain of every tier', () => {
  // Holds 12/12 upstream and is load-bearing: the DC is promoted with its local
  // credential and every child dcpromo re-uses it, so a mismatch fails the
  // promotion with an authentication error that names neither field.
  let checked = 0;
  for (const { key, out } of allTiers()) {
    const lab = labOf(out);
    for (const [fqdn, domain] of Object.entries(lab.domains)) {
      const dc = lab.hosts[domain.dc];
      assert.ok(dc, `${key} ${fqdn}: .dc names '${domain.dc}', which is not a host`);
      assert.strictEqual(dc.local_admin_password, domain.domain_password,
        `${key} ${fqdn}: hosts.${domain.dc}.local_admin_password != domain_password`);
      checked++;
    }
  }
  assert.strictEqual(checked, 1 + 2 + 2 + 3, 'every domain across all four fixtures was checked');
});

test('B4-103 domain passwords are distinct per domain', () => {
  // A shared password across a forest and its child means one crack is the whole
  // estate, which removes the middle of the exercise.
  const lab = labOf(compileFixture('L'));
  const passwords = Object.values(lab.domains).map((d) => d.domain_password);
  assert.strictEqual(new Set(passwords).size, passwords.length);
});

// ─── B5. Identifier caps ────────────────────────────────────────────────────

test('B5-100 every sAMAccountName is within the 20-character cap', () => {
  // roles/onlyusers passes `name: item.key` to win_domain_user, which derives
  // sAMAccountName from it and FAILS rather than truncating.
  for (const { key, out } of allTiers()) {
    for (const [fqdn, domain] of Object.entries(labOf(out).domains)) {
      for (const sam of Object.keys(domain.users)) {
        assert.ok(sam.length <= validate.MAX_SAM_ACCOUNT_NAME,
          `${key} ${fqdn}: user '${sam}' is ${sam.length} characters`);
        assert.match(sam, /^[a-z0-9][a-z0-9._-]*$/, `${key} ${fqdn}: user '${sam}' has an odd charset`);
      }
    }
  }
});

test('B5-101 a long stakeholder name is shortened rather than rejected or truncated blind', () => {
  // 'Priya Raghunathan-Venkataraman' is 30 characters as first.last.
  const lab = labOf(compileFixture('S'));
  const sams = Object.keys(Object.values(lab.domains)[0].users);
  assert.ok(sams.every((s) => s.length <= validate.MAX_SAM_ACCOUNT_NAME));
  assert.ok(sams.some((s) => s.startsWith('p.') || s.startsWith('priya')),
    `expected the Controller to survive in some form, got: ${sams.join(', ')}`);
});

test('B5-102 a title is not promoted into a logon name', () => {
  // profile-to-intake.js:69 builds emails as name.replace(/\s+/g,'.'), which
  // turns "Dr. Jane Smith" into a leading honorific. Doing that to a
  // sAMAccountName is one of the few AD mistakes a student spots immediately.
  assert.deepStrictEqual(compile.splitPersonName('Dr. Jane Smith'), { firstname: 'Jane', surname: 'Smith' });
  assert.deepStrictEqual(compile.splitPersonName('Tom Ng Jr.'), { firstname: 'Tom', surname: 'Ng' });
  assert.deepStrictEqual(compile.splitPersonName('Prof. Alexandra Ruiz PhD'), { firstname: 'Alexandra', surname: 'Ruiz' });
  const lab = labOf(compileFixture('S'));
  const users = Object.values(lab.domains)[0].users;
  assert.ok(users['jane.smith'], `expected jane.smith, got: ${Object.keys(users).join(', ')}`);
  assert.ok(!Object.keys(users).some((s) => /^(dr|mr|mrs|ms|prof)\b/.test(s)));
});

test('B5-103 every group CN is within the 64-character cap', () => {
  for (const { key, out } of allTiers()) {
    for (const group of out.ir.principals.groups) {
      assert.ok(group.name.length <= validate.MAX_COMMON_NAME,
        `${key}: group '${group.name}' is ${group.name.length} characters`);
      // No unescaped RDN separator — AD rejects those outright.
      assert.ok(!/[,+"\\<>;=]/.test(group.name), `${key}: group '${group.name}' has an RDN separator in it`);
    }
  }
});

test('B5-104 hostnames are NetBIOS-legal and unique lab-wide', () => {
  for (const { key, out } of allTiers()) {
    const seen = new Set();
    for (const [hostKey, host] of Object.entries(labOf(out).hosts)) {
      assert.ok(host.hostname.length <= validate.MAX_NETBIOS_HOSTNAME,
        `${key} ${hostKey}: hostname '${host.hostname}' is ${host.hostname.length} characters`);
      assert.match(host.hostname, /^[A-Za-z0-9-]+$/, `${key} ${hostKey}: hostname charset`);
      assert.ok(!seen.has(host.hostname.toLowerCase()),
        `${key}: hostname '${host.hostname}' is used twice`);
      seen.add(host.hostname.toLowerCase());
    }
  }
});

test('B5-105 NetBIOS domain names are capped, legal and unique', () => {
  for (const { key, out } of allTiers()) {
    const seen = new Set();
    for (const domain of out.ir.domains) {
      assert.ok(domain.netbios.length <= validate.MAX_NETBIOS_HOSTNAME,
        `${key}: NetBIOS '${domain.netbios}' is ${domain.netbios.length} characters`);
      assert.match(domain.netbios, /^[A-Z0-9-]+$/);
      assert.ok(!seen.has(domain.netbios), `${key}: NetBIOS '${domain.netbios}' is used twice`);
      seen.add(domain.netbios);
    }
  }
});

// ─── B6. Domain minting ─────────────────────────────────────────────────────

test('B6-100 a well-formed public domain becomes corp.<domain>; a malformed one falls back', () => {
  assert.strictEqual(compileFixture('S').ir.domains[0].fqdn, 'corp.ridgelinedental.com');

  const junk = compile.compileLab(profileFixture({
    runId: 'RUN_2026_JUNKDOMAIN',
    company: 'Copperfield Legal LLC',
    domain: 'N/A',
    employees: 42,
  }));
  // Derived from the company name, because domain_public is LLM-authored and
  // arrives as anything. Refusing rather than repairing keeps a forest name we
  // did not choose out of the lab.
  assert.strictEqual(junk.ir.domains[0].fqdn, 'corp.copperfield-legal.com');
});

test('B6-101 .local is never minted, from any input', () => {
  // Doubly disqualified: mDNS-reserved (RFC 6762) AND blackholed by this
  // platform's own mail relay.
  assert.strictEqual(compile.publicDomainOf('acme.local'), null);
  assert.strictEqual(compile.publicDomainOf('acme.invalid'), null);
  assert.strictEqual(compile.publicDomainOf('acme.internal'), null);
  const out = compile.compileLab(profileFixture({
    runId: 'RUN_2026_LOCALDOMAIN',
    company: 'Acme Diagnostics',
    domain: 'acme.local',
    employees: 42,
  }));
  for (const d of out.ir.domains) assert.ok(!/\.local$/.test(d.fqdn), `minted ${d.fqdn}`);
  assert.strictEqual(out.ir.domains[0].fqdn, 'corp.acme-diagnostics.com');
});

test('B6-102 publicDomainOf normalises the URL shapes a profile actually carries', () => {
  assert.strictEqual(compile.publicDomainOf('http://www.zenithwater.gov/about'), 'zenithwater.gov');
  assert.strictEqual(compile.publicDomainOf('EXAMPLE-CLINIC.COM.'), 'example-clinic.com');
  assert.strictEqual(compile.publicDomainOf('acme clinic dot com'), null);
  assert.strictEqual(compile.publicDomainOf('localhost'), null);
});

test('B6-103 a child domain is a STRICT suffix extension of its parent', () => {
  // ad-child_domain.yml:20 derives parent_domain by dropping the first label and
  // then reads lab.domains[parent].domain_password with no default, so anything
  // but `<label>.<parent>` resolves a domain that does not exist.
  for (const key of ['M_A', 'M_B', 'L']) {
    const out = compileFixture(key);
    for (const d of out.ir.domains) {
      if (d.is_forest_root) continue;
      assert.strictEqual(d.fqdn.split('.').slice(1).join('.'), d.parent_fqdn,
        `${key}: '${d.fqdn}' does not drop to '${d.parent_fqdn}'`);
      assert.ok(labOf(out).domains[d.parent_fqdn], `${key}: parent of '${d.fqdn}' is not declared`);
    }
  }
});

test('B6-104 the two forest roots do not share a suffix', () => {
  // A second forest that is a suffix of the first is read as its child, and the
  // trust is then built between a domain and itself.
  const roots = compileFixture('L').ir.domains.filter((d) => d.is_forest_root).map((d) => d.fqdn);
  assert.strictEqual(roots.length, 2);
  const [a, b] = roots;
  assert.notStrictEqual(a, b);
  assert.ok(!a.endsWith(`.${b}`) && !b.endsWith(`.${a}`), `${a} and ${b} are suffix related`);
});

test('B6-105 the lab name is a legal GOAD lab directory and not one of upstream\'s', () => {
  for (const { key, out } of allTiers()) {
    assert.match(out.ir.lab_name, /^CIAB-[0-9a-f]{8}$/, `${key}: ${out.ir.lab_name}`);
    // assertLabName is the authority: the name becomes a shell path, a YAML key
    // and a tar member prefix, and `default` would rewrite every lab's chain.
    assert.doesNotThrow(() => push.assertLabName(out.ir.lab_name));
  }
});

// ─── B7. The output passes both checkers ────────────────────────────────────

test('B7-100 every emitted lab passes goad-lab-validate with zero errors', () => {
  for (const { key, out } of allTiers()) {
    const result = validate.validateLab({
      lab: labOf(out),
      inventory: out.files['data/inventory'],
      labName: out.ir.lab_name,
    });
    assert.deepStrictEqual(result.errors, [],
      `${key}: ${result.errors.map((e) => `${e.code} ${e.id}`).join(', ')}`);
  }
});

test('B7-101 every emitted lab passes goad-preflight with zero errors', () => {
  for (const { key, out } of allTiers()) {
    const result = preflight.preflightGoadLab({
      labName: out.ir.lab_name,
      config: out.files['data/config.json'],
      inventory: out.files['data/inventory'],
      providerInventory: out.files['providers/proxmox/inventory'],
      playbooks: out.chain,
    });
    assert.deepStrictEqual(result.errors, [],
      `${key}: ${result.errors.map((e) => `${e.code} ${e.id}`).join(', ')}`);
    assert.strictEqual(result.ok, true);
  }
});

test('B7-102 compileLab refuses to RETURN a lab either checker rejects', () => {
  // The gate is inside the compiler, not only in this test file: a composer
  // whose bugs are found on a lane is a composer with no gate.
  const out = compileFixture('L');
  assert.ok(out.files['data/config.json']);
  assert.doesNotThrow(() => validate.assertLabCompiles({
    lab: labOf(out), inventory: out.files['data/inventory'], labName: out.ir.lab_name,
  }));
  assert.doesNotThrow(() => preflight.assertGoadLabPreflight({
    labName: out.ir.lab_name,
    config: out.files['data/config.json'],
    inventory: out.files['data/inventory'],
    providerInventory: out.files['providers/proxmox/inventory'],
    playbooks: out.chain,
  }));
});

test('B7-103 an mssql host carries sa_password and a svcaccount from its OWN domain', () => {
  // servers.yml:31 is the only line in that play without a `| default(...)`,
  // and :24 resolves SQLSVCPASSWORD as
  // lab.domains[domain].users[svcaccount].password | default('') — so naming a
  // service account from another domain installs SQL with an empty password.
  let seen = 0;
  for (const { key, out } of allTiers()) {
    const lab = labOf(out);
    for (const hostKey of (groupsOf(out).mssql || [])) {
      const host = lab.hosts[hostKey];
      assert.ok(host.mssql && host.mssql.sa_password, `${key} ${hostKey}: no mssql.sa_password`);
      if (host.mssql.svcaccount) {
        const domain = lab.domains[host.domain];
        assert.ok(domain.users[host.mssql.svcaccount],
          `${key} ${hostKey}: svcaccount '${host.mssql.svcaccount}' is not a user of '${host.domain}'`);
        assert.ok(String(domain.users[host.mssql.svcaccount].password).length > 0);
      }
      seen++;
    }
  }
  assert.ok(seen > 0, 'no fixture placed SQL anywhere, so this rule went unchecked');
});

// ─── B8. Roles: never_emit and ordering ─────────────────────────────────────

test('B8-100 no emitted role is one the manifest marks never_emit', () => {
  // `shares` is broken upstream and `adcs_esc7`'s guard is inverted so ManageCA
  // is never granted — both report GREEN having planted nothing. The list is
  // ASKED FOR, never copied: it is a property of the pinned GOAD ref.
  const neverEmit = manifest.loadManifest().roles.filter((r) => r.never_emit).map((r) => `${r.kind}/${r.name}`);
  assert.ok(neverEmit.length >= 2, 'the manifest should still mark some roles never_emit');
  for (const { key, out } of allTiers()) {
    for (const [hostKey, host] of Object.entries(labOf(out).hosts)) {
      for (const kind of ['vulns', 'security']) {
        for (const name of host[kind] || []) {
          assert.ok(manifest.getRole(name, kind), `${key} ${hostKey}: '${kind}/${name}' is not a GOAD role`);
          assert.ok(!manifest.isNeverEmit(name, kind),
            `${key} ${hostKey}: emitted never_emit role '${kind}/${name}'`);
        }
      }
    }
  }
});

test('B8-101 manifestSafe drops broken and unknown names rather than trusting a hardcoded list', () => {
  const kept = compile.manifestSafe(['shares', 'openshares', 'not_a_real_role', 'smbv1'], 'vulns');
  assert.deepStrictEqual(kept, ['openshares', 'smbv1']);
  assert.deepStrictEqual(compile.manifestSafe(['adcs_esc7'], 'vulns'), []);
});

test('B8-102 the vulns array is a valid execution order', () => {
  // vulnerabilities.yml loops the array in place, and `permissions` ACLs a
  // folder `directory` creates. Getting it wrong is one red task in the middle
  // of a long play.
  assert.deepStrictEqual(
    compile.orderVulns(['permissions', 'smbv1', 'directory']),
    ['directory', 'smbv1', 'permissions']
  );
  for (const { key, out } of allTiers()) {
    for (const [hostKey, host] of Object.entries(labOf(out).hosts)) {
      const d = host.vulns.indexOf('directory');
      const p = host.vulns.indexOf('permissions');
      if (d !== -1 && p !== -1) {
        assert.ok(d < p, `${key} ${hostKey}: permissions runs before directory`);
      }
    }
  }
});

test('B8-103 every role that reads vars has them, and no vars are orphaned', () => {
  for (const { key, out } of allTiers()) {
    for (const [hostKey, host] of Object.entries(labOf(out).hosts)) {
      for (const [kind, varsKey] of [['vulns', 'vulns_vars'], ['security', 'security_vars']]) {
        for (const name of Object.keys(host[varsKey] || {})) {
          assert.ok(host[kind].includes(name),
            `${key} ${hostKey}: ${varsKey}.${name} is set but ${kind} never lists it`);
        }
        for (const name of host[kind] || []) {
          const role = manifest.getRole(name, kind);
          if (!role.consumes_vars) {
            assert.strictEqual(host[varsKey][name], undefined,
              `${key} ${hostKey}: ${name} reads no vars but ${varsKey}.${name} is set`);
          } else {
            assert.ok(host[varsKey][name] !== undefined,
              `${key} ${hostKey}: ${name} loops with_dict over an absent ${varsKey}.${name}`);
          }
        }
      }
    }
  }
});

// ─── B9. Emission: the tree, the chain, no placeholders ─────────────────────

test('B9-100 the tree is exactly what pushLabTree accepts — and playbooks.yml is not in it', () => {
  for (const { key, out } of allTiers()) {
    assert.deepStrictEqual(Object.keys(out.files).sort(), compile.TREE_FILES.slice().sort(), key);
    // pushLabTree REFUSES a tree containing playbooks.yml (goad-lab-push.js:982)
    // because it renders that file itself, under both the lab key and `default:`.
    // The chain therefore travels as a return value.
    assert.strictEqual(out.files['playbooks.yml'], undefined);
    assert.ok(Array.isArray(out.chain) && out.chain.length > 0);
    assert.doesNotThrow(() => push.assertChain(out.chain), `${key}: chain rejected by pushLabTree`);
  }
});

test('B9-101 tier S runs GOAD-Mini\'s own chain, not the 16-play default', () => {
  // ad/GOAD-Mini has its OWN entry in the fork's playbooks.yml. Falling through
  // to `default:` would run ad-child_domain.yml against an empty [child_dc] and
  // ad-trusts.yml against an empty [trust].
  const s = compileFixture('S').chain;
  assert.ok(!s.includes('ad-child_domain.yml'));
  assert.ok(!s.includes('ad-trusts.yml'));
  assert.ok(!s.includes('servers.yml'));
  assert.ok(s.includes('ad-parent_domain.yml') && s.includes('ad-acl.yml'));

  const m = compileFixture('M_A').chain;
  assert.deepStrictEqual(m, preflight.DEFAULT_CHAIN.slice(),
    'M and L have no entry of their own upstream, so they inherit `default:`');
});

test('B9-102 data/inventory names the emitted lab directory, not the chassis', () => {
  // ansible/data.yml builds its vars_files path from domain_name, so a stale
  // value loads ANOTHER lab's config.json.
  for (const { key, out } of allTiers()) {
    const vars = validate.parseInventory(out.files['data/inventory']).vars;
    assert.strictEqual(vars.domain_name, out.ir.lab_name, key);
    // The two inventory vars with no default anywhere in the chain.
    for (const name of preflight.REQUIRED_INVENTORY_VARS) {
      assert.ok(String(vars[name] || '').trim() !== '', `${key}: [all:vars] ${name} is empty`);
    }
  }
});

test('B9-103 no chassis placeholder survives compilation, in any emitted file', () => {
  // Every chassis placeholder is deliberately implausible so a leak is
  // unmistakable rather than believable. A leak is the failure mode that would
  // otherwise deploy perfectly and hand a client somebody else's lab.
  for (const tier of compile.TIERS) {
    const chassis = compile.loadChassis(tier);
    const ph = chassis.provenance.placeholders;
    const needles = []
      .concat(ph.domains, ph.hostnames, ph.netbios_names, ph.passwords, [ph.inventory_domain_name]);
    const key = tier === 'M' ? 'M_A' : tier;
    const out = compileFixture(key);
    for (const [name, text] of Object.entries(out.files)) {
      for (const needle of needles) {
        assert.ok(!String(text).includes(needle), `${tier} ${name} leaks '${needle}'`);
      }
      assert.ok(!/\.invalid\b/.test(String(text)), `${tier} ${name} still carries a .invalid domain`);
      assert.ok(!/CHASSIS[-_]/.test(String(text)), `${tier} ${name} still carries a CHASSIS- identifier`);
    }
  }
});

test('B9-104 the structural half of the inventory is inherited from the chassis verbatim', () => {
  // These groups drive dcpromo, the child promotion, the trust and the CA. They
  // are the half that was PROVEN to deploy; only the service and defender groups
  // are the compiler's to move.
  for (const tier of ['S', 'M', 'L']) {
    const chassis = compile.loadChassis(tier);
    const before = validate.parseInventory(chassis.inventoryText).groups;
    const after = groupsOf(compileFixture(tier === 'M' ? 'M_A' : tier));
    for (const g of ['domain', 'dc', 'server', 'workstation', 'parent_dc', 'child_dc', 'trust',
      'adcs', 'adcs_customtemplates', 'laps_dc', 'laps_server', 'laps_workstation']) {
      assert.deepStrictEqual(after[g] || [], before[g] || [], `${tier}: [${g}] was rewritten`);
    }
  }
});

test('B9-105 the provider inventory keeps its octets and its dict_key join', () => {
  // dict_key is the hinge of the whole scheme: every play says
  // lab.hosts[dict_key], and a mismatch does not error — it silently configures
  // one machine with another's identity.
  for (const tier of ['S', 'M', 'L']) {
    const chassis = compile.loadChassis(tier);
    const out = compileFixture(tier === 'M' ? 'M_A' : tier);
    const hostLine = /^(\S+)\s+ansible_host=(\S+)\s+dns_domain=(\S+)\s+dict_key=(\S+)$/;
    const lines = (text) => text.split('\n').map((l) => hostLine.exec(l.trim())).filter(Boolean)
      .map((m) => m.slice(1).join(' '));
    assert.deepStrictEqual(lines(out.files['providers/proxmox/inventory']),
      lines(chassis.providerText), `${tier}: provider host lines drifted`);
  }
});

test('B9-106 rewriteInventoryGroups replaces hosts and keeps the comments that explain them', () => {
  const text = [
    '; install mssql',
    '; usage : servers.yml',
    '[mssql]',
    'srv02',
    'srv03',
    '',
    '[iis]',
    'srv02',
  ].join('\n');
  const out = compile.rewriteInventoryGroups(text, { mssql: ['srv09'] });
  assert.ok(out.includes('; install mssql'), 'the comment that says which play consumes the group is load-bearing');
  assert.ok(out.includes('; usage : servers.yml'));
  const groups = validate.parseInventory(out).groups;
  assert.deepStrictEqual(groups.mssql, ['srv09']);
  assert.deepStrictEqual(groups.iis, ['srv02'], 'an untouched group keeps its members');
});

test('B9-107 config.json is emitted as STRICT json even though the read side tolerates more', () => {
  // ad/DRACARYS ships a trailing comma and deploys fine (Ansible loads it as
  // YAML). We read with that tolerance; we never write it, so nothing this repo
  // emits trips a strict loader downstream.
  for (const { key, out } of allTiers()) {
    assert.doesNotThrow(() => JSON.parse(out.files['data/config.json']), key);
    const parsed = JSON.parse(out.files['data/config.json']);
    assert.ok(parsed.lab && parsed.lab.hosts && parsed.lab.domains, `${key}: missing the lab envelope`);
  }
  // The tolerance is still there on the way IN — a chassis re-sync could carry a
  // trailing comma across from upstream.
  const tolerated = validate.parseLabConfig('{"lab":{"hosts":{},"domains":{},}}');
  assert.deepStrictEqual(tolerated.repairs, ['trailing-comma']);
});

// ─── B10. The foothold invariant ────────────────────────────────────────────

test('B10-100 the minted foothold names a principal AD actually creates', () => {
  for (const { key, out } of allTiers()) {
    const cred = out.ir.foothold_credential;
    assert.strictEqual(cred.honoured_by, 'ad', key);
    const user = labOf(out).domains[cred.domain].users[cred.sam];
    assert.ok(user, `${key}: foothold '${cred.sam}' is not a user of '${cred.domain}'`);
    assert.strictEqual(user.password, cred.password,
      `${key}: the credential the website would plant is not the one AD honours`);
    // planted_at is the WEB half and stays null until somebody plants it.
    assert.strictEqual(cred.planted_at, null);
  }
});

test('B10-101 a foothold naming a principal AD does not create is a COMPILE ERROR', () => {
  assert.throws(() => compile.compileLab(profileFixture(FIXTURES.S), {
    footholdCredential: { sam: 'ghost.user', domain: compileFixture('S').ir.domains[0].fqdn, password: 'x' },
  }), (err) => {
    assert.strictEqual(err.code, 'CIAB_FOOTHOLD_PRINCIPAL_MISSING');
    assert.match(err.message, /creates no such user/);
    return true;
  });
});

test('B10-102 a chain that starts on an unplanted credential is a COMPILE ERROR', () => {
  const base = compileFixture('S');
  const cred = base.ir.foothold_credential;
  // Same principal, same password, but nothing on the web side plants it: the
  // student has no way to get their first credential.
  assert.throws(() => compile.compileLab(profileFixture(FIXTURES.S), {
    footholdCredential: { sam: cred.sam, domain: cred.domain, password: cred.password, planted_at: null },
    chain: { start: { kind: 'credential', principal: cred.sam, how: 'config file on the intranet app' } },
  }), (err) => {
    assert.strictEqual(err.code, 'CIAB_CHAIN_START_UNPLANTED');
    return true;
  });

  // Plant it, and the same chain compiles.
  const ok = compile.compileLab(profileFixture(FIXTURES.S), {
    footholdCredential: {
      sam: cred.sam,
      domain: cred.domain,
      password: cred.password,
      planted_at: { host_key: 'web01', path: '/var/www/app/config/database.yml', format: 'yaml' },
    },
    chain: { start: { kind: 'credential', principal: cred.sam, how: 'config file on the intranet app' } },
  });
  assert.strictEqual(ok.ir.chain.start.principal, cred.sam);
  assert.ok(ok.ir.foothold_credential.planted_at);
});

test('B10-103 a chain that starts on a DIFFERENT principal than the one planted is refused', () => {
  const base = compileFixture('S');
  const cred = base.ir.foothold_credential;
  assert.throws(() => compile.compileLab(profileFixture(FIXTURES.S), {
    footholdCredential: {
      sam: cred.sam,
      domain: cred.domain,
      password: cred.password,
      planted_at: { host_key: 'web01', path: '/app/.env', format: 'dotenv' },
    },
    chain: { start: { kind: 'credential', principal: 'somebody.else', how: 'guessed' } },
  }), (err) => {
    assert.strictEqual(err.code, 'CIAB_CHAIN_START_UNPLANTED');
    return true;
  });
});

// ─── B11. The ACL designer's half ───────────────────────────────────────────

test('B11-100 an unfilled lab carries the chain and acls slots, shaped and empty', () => {
  // The IR is shared with the ACL designer, so the slots exist before they are
  // filled — a caller reading ir.chain.edges must not have to null-check its way
  // to an answer.
  //
  // The three `declared_*` slots are part of that shape and NOT decoration: the
  // normaliser used to keep only start/objective/edges/decoys, so a chain that
  // round-tripped through the composer lost every declaration on it and a
  // declared entry point came back out looking like an undeclared shortcut.
  const ir = compileFixture('M_A').ir;
  assert.deepStrictEqual(ir.chain, {
    start: null,
    objective: null,
    edges: [],
    decoys: [],
    domain: null,
    declared_admins: [],
    declared_broad_principals: [],
    declared_shared_passwords: [],
  });
  for (const d of ir.domains) assert.deepStrictEqual(ir.acls[d.fqdn], {});
  for (const domain of Object.values(labOf(compileFixture('M_A')).domains)) {
    assert.deepStrictEqual(domain.acls, {});
  }
});

test('B11-101 supplied ACLs are lowered into the domain they name, and validated there', () => {
  const base = compileFixture('S');
  const fqdn = base.ir.domains[0].fqdn;
  const lab = labOf(base);
  const users = Object.keys(lab.domains[fqdn].users);
  const groups = Object.keys(lab.domains[fqdn].groups.global);

  const out = compile.compileLab(profileFixture(FIXTURES.S), {
    acls: {
      [fqdn]: {
        GenericAll_helpdesk_exec: {
          for: groups[0],
          to: users[0],
          right: 'GenericAll',
          inheritance: 'None',
        },
      },
    },
  });
  const emitted = labOf(out).domains[fqdn].acls;
  assert.strictEqual(emitted.GenericAll_helpdesk_exec.right, 'GenericAll');
  assert.deepStrictEqual(out.ir.acls[fqdn], emitted);
});

test('B11-102 ACLs for a domain the lab does not declare are refused', () => {
  assert.throws(() => compile.compileLab(profileFixture(FIXTURES.S), {
    acls: { 'somewhere.else.com': { x: { for: 'a', to: 'b', right: 'GenericAll', inheritance: 'None' } } },
  }), (err) => {
    assert.strictEqual(err.code, 'CIAB_ACL_DOMAIN_UNKNOWN');
    return true;
  });
});

test('B11-103 an ACL right the domain role does not recognise is refused by the gate', () => {
  // The match upstream is ordinal and case-sensitive, so 'genericall' builds no
  // ACE and Ansible still reports the task GREEN. The compiler's own gate is
  // what turns that into a refusal.
  const fqdn = compileFixture('S').ir.domains[0].fqdn;
  assert.throws(() => compile.compileLab(profileFixture(FIXTURES.S), {
    acls: { [fqdn]: { bad: { for: 'a', to: 'b', right: 'genericall', inheritance: 'None' } } },
  }), (err) => {
    assert.strictEqual(err.code, 'LAB_DEFINITION_INVALID');
    assert.ok(err.errors.some((e) => e.code === 'UNKNOWN_ACL_RIGHT'));
    return true;
  });
});

// ─── B12. Principals are plausible, not just legal ──────────────────────────

test('B12-100 the roster is a sample of the headcount, not a copy of it', () => {
  // win_domain_user is a serialised WinRM round trip per user, and a directory
  // where every object is filler teaches nothing. The paper's headcount stays
  // the org's; the lab's roster is what a tester would actually enumerate.
  const out = compileFixture('L');
  assert.ok(out.ir.principals.users.length > FIXTURES.L.employees * 0.02);
  assert.ok(out.ir.principals.users.length < FIXTURES.L.employees,
    'a 1:1 roster would be most of an hour of bake time on its own');
  // Every named stakeholder survives the cap.
  const sams = new Set(out.ir.principals.users.map((u) => u.sam));
  assert.ok(sams.has('jane.smith') && sams.has('marcus.webb'));
});

test('B12-101 every domain has users and groups — an empty one is a green bake that built nothing', () => {
  // ad-data.yml binds ad_users / ad_groups straight off these with no default,
  // and pre-flight treats an EMPTY dict and an ABSENT key as the same finding.
  for (const { key, out } of allTiers()) {
    for (const [fqdn, domain] of Object.entries(labOf(out).domains)) {
      assert.ok(Object.keys(domain.users).length >= 3, `${key} ${fqdn}: ${Object.keys(domain.users).length} users`);
      assert.ok(Object.keys(domain.groups.global).length > 0, `${key} ${fqdn}: no global groups`);
      // All three scope buckets are re-emitted: roles/ad indexes
      // ad_groups.global with no default.
      assert.deepStrictEqual(Object.keys(domain.groups).sort(), ['domainlocal', 'global', 'universal']);
      assert.ok(Object.values(domain.users).some((u) => u.groups.includes('Domain Admins')),
        `${key} ${fqdn}: nobody is a Domain Admin`);
    }
  }
});

test('B12-102 group and user containers resolve to a declared OU, the root, or CN=Users', () => {
  // AD does not create intermediate OUs: an unresolved path means the object is
  // never made, and win_domain_user has no default for it either.
  for (const { key, out } of allTiers()) {
    for (const [fqdn, domain] of Object.entries(labOf(out).domains)) {
      const rootDn = validate.rootDnForDomain(fqdn);
      const allowed = new Set([validate.normalizeDn(rootDn), validate.normalizeDn(`CN=Users,${rootDn}`)]);
      for (const [ouName, ou] of Object.entries(domain.organisation_units)) {
        allowed.add(validate.normalizeDn(`OU=${ouName},${ou.path}`));
      }
      for (const [sam, user] of Object.entries(domain.users)) {
        assert.ok(allowed.has(validate.normalizeDn(user.path)),
          `${key} ${fqdn}: user '${sam}' path '${user.path}' resolves to nothing`);
      }
      for (const byName of Object.values(domain.groups)) {
        for (const [name, group] of Object.entries(byName)) {
          assert.ok(allowed.has(validate.normalizeDn(group.path)),
            `${key} ${fqdn}: group '${name}' path '${group.path}' resolves to nothing`);
        }
      }
    }
  }
});

test('B12-103 nested OUs are emitted parents-first', () => {
  // roles/ad/tasks/ou.yml iterates the dict in file order and
  // ADOrganizationalUnit needs the parent to exist already.
  for (const { key, out } of allTiers()) {
    for (const [fqdn, domain] of Object.entries(labOf(out).domains)) {
      const rootDn = validate.normalizeDn(validate.rootDnForDomain(fqdn));
      const created = new Set([rootDn]);
      for (const [ouName, ou] of Object.entries(domain.organisation_units)) {
        assert.ok(created.has(validate.normalizeDn(ou.path)),
          `${key} ${fqdn}: OU '${ouName}' is created before its parent '${ou.path}'`);
        created.add(validate.normalizeDn(`OU=${ouName},${ou.path}`));
      }
    }
  }
});

test('B12-104 every SPN names a host that genuinely runs that service', () => {
  // A kerberoastable service account whose SPN points at a machine with no such
  // service is scenery: the ticket cracks and leads nowhere.
  for (const { key, out } of allTiers()) {
    const lab = labOf(out);
    const groups = groupsOf(out);
    const hostFqdn = (hostKey) => `${lab.hosts[hostKey].hostname}.${lab.hosts[hostKey].domain}`.toLowerCase();
    const sqlNames = new Set((groups.mssql || []).map(hostFqdn));
    const webNames = new Set((groups.iis || []).map(hostFqdn));
    for (const user of out.ir.principals.users) {
      for (const spn of user.spns) {
        const [service, rest] = spn.split('/');
        const target = String(rest).split(':')[0].toLowerCase();
        if (service === 'MSSQLSvc') {
          assert.ok(sqlNames.has(target), `${key}: ${user.sam} has ${spn} but ${target} is not in [mssql]`);
        } else if (service === 'HTTP') {
          assert.ok(webNames.has(target), `${key}: ${user.sam} has ${spn} but ${target} is not in [iis]`);
        }
      }
    }
  }
});

test('B12-105 local_groups only ever name principals from the host\'s own domain', () => {
  // settings/adjust_rights runs with that domain's credentials; a name it cannot
  // resolve fails the task.
  for (const { key, out } of allTiers()) {
    const lab = labOf(out);
    const netbiosOf = {};
    for (const [fqdn, d] of Object.entries(lab.domains)) netbiosOf[fqdn] = d.netbios_name;
    for (const [hostKey, host] of Object.entries(lab.hosts)) {
      const domain = lab.domains[host.domain];
      const known = new Set(
        Object.keys(domain.users)
          .concat(Object.values(domain.groups).flatMap((byName) => Object.keys(byName)))
          .map((n) => n.toLowerCase())
      );
      for (const members of Object.values(host.local_groups || {})) {
        for (const member of members) {
          const [nb, name] = String(member).split('\\');
          assert.strictEqual(nb, netbiosOf[host.domain],
            `${key} ${hostKey}: local group member '${member}' is from another domain`);
          assert.ok(known.has(String(name).toLowerCase()),
            `${key} ${hostKey}: local group member '${member}' does not exist in '${host.domain}'`);
        }
      }
    }
  }
});

test('B12-106 a profile with no stakeholders still compiles, and says so', () => {
  const out = compile.compileLab(profileFixture(Object.assign({}, FIXTURES.S, {
    runId: 'RUN_2026_ANONYMOUS',
    stakeholders: [],
  })));
  assert.ok(out.ir.principals.users.length > 0);
  assert.ok(out.warnings.some((w) => w.code === 'CIAB_NO_STAKEHOLDERS'),
    'a lab whose roster matches no name on the paper profile is worth saying out loud');
});

// ─── B13. Passwords, once more, at the pool level ───────────────────────────

test('B13-100 makeMachinePassword always clears the default policy', () => {
  for (let i = 0; i < 200; i++) {
    const pw = compile.makeMachinePassword(`RUN_${i}`, `salt:${i}`);
    assert.ok(pw.length >= 12, pw);
    assert.strictEqual(validate.passwordClasses(pw), 4, pw);
    assert.ok(!validate.containsAccountName(pw, 'administrator'), pw);
    // No character that needs escaping on the JSON -> YAML -> PowerShell trip,
    // where only the first layer escapes for you.
    assert.ok(!/["'`$%{}\\]/.test(pw), pw);
  }
});

test('B13-101 user passwords include a weak handful — that is the spray surface', () => {
  // users[].password is set AFTER password_policy relaxes the domain, so weak
  // values are legal here and nowhere else. Upstream does the same thing.
  const lab = labOf(compileFixture('M_A'));
  const passwords = Object.values(lab.domains).flatMap((d) => Object.values(d.users).map((u) => u.password));
  assert.ok(passwords.some((pw) => validate.passwordClasses(pw) < 4),
    'no weak credential anywhere means nothing to find');
  assert.ok(passwords.some((pw) => validate.passwordClasses(pw) === 4),
    'every credential weak is not a directory, it is a target range');
});

// ─── B14. The Domain Admins declaration ─────────────────────────────────────
//
// WHY THIS SECTION EXISTS. The composer mints roster Domain Admins on purpose —
// a real company has them, and an IT director is one — but it used to mint them
// SILENTLY. The attack-chain designer's anti-shortcut gate then saw privileged
// principals it had no way to reason about and rejected every lab that had any:
// 60 realistic profiles compiled and 0 produced an attack chain. The fix is a
// declaration, not a relaxation, and the tests below defend both halves of it —
// the composer must declare every admin it creates (including through nesting
// and through a DC's local Administrators list), and it must REFUSE to emit one
// it forgot.

test('B14-100 every principal the composer makes privileged is declared, with a reason', () => {
  for (const { key, out } of allTiers()) {
    const declared = out.ir.principals.declared_admins;
    assert.ok(Array.isArray(declared) && declared.length > 0,
      `${key}: a forest with no declared admins is either implausible or undeclared`);
    for (const entry of declared) {
      assert.ok(entry.sam && entry.domain, `${key}: ${JSON.stringify(entry)} is incomplete`);
      assert.ok(['roster_realism', 'chain_terminus'].indexOf(entry.reason) !== -1,
        `${key}: '${entry.reason}' is not a reason the designer knows how to act on`);
    }
    // Every declaration names a principal the lab really creates.
    const lab = labOf(out);
    for (const entry of declared) {
      const users = lab.domains[entry.domain].users;
      const groups = lab.domains[entry.domain].groups;
      const isUser = Object.prototype.hasOwnProperty.call(users, entry.sam);
      const isGroup = Object.values(groups)
        .some((byName) => Object.prototype.hasOwnProperty.call(byName, entry.sam));
      assert.ok(isUser || isGroup,
        `${key}: declared admin '${entry.sam}' is not a principal this lab creates`);
    }
  }
});

test('B14-101 the declaration is re-derived from the emitted lab, not from bookkeeping', () => {
  // privilegedPrincipalsOf() walks config.json by a different route from the one
  // that made the declarations. Checking a registry against itself would prove
  // nothing; this is what gives the self-check teeth.
  for (const { key, out } of allTiers()) {
    const actual = compile.privilegedPrincipalsOf(labOf(out));
    const declaredKeys = new Set(out.ir.principals.declared_admins
      .map((a) => `${a.domain}\\${compile.principalKey(a.sam)}`));
    assert.strictEqual(actual.size, declaredKeys.size,
      `${key}: the emitted lab grants ${actual.size} privileged memberships but declares `
      + `${declaredKeys.size}`);
    for (const [k] of actual) {
      assert.ok(declaredKeys.has(k),
        `${key}: '${k}' is privileged in the emitted lab and undeclared`);
    }
  }
});

test('B14-102 a DC local Administrators list counts as a privileged membership', () => {
  // On a domain controller the local Administrators group IS the domain's
  // built-in Administrators — the same principal the endgame is defined by. A
  // check that read only users[].groups would call that account unprivileged,
  // which is how an undeclared domain admin ships.
  const out = compileFixture('M_A');
  const lab = labOf(out);
  const dcKeys = Object.keys(lab.hosts).filter((k) => lab.hosts[k].type === 'dc');
  assert.ok(dcKeys.length > 0);
  const viaDc = out.ir.principals.declared_admins.filter((a) => /Administrators/.test(a.via || ''));
  assert.ok(viaDc.length > 0,
    'the composer puts local admins on every host, so a DC always mints this kind');
  for (const entry of viaDc) {
    const listed = dcKeys.some((k) => (lab.hosts[k].local_groups.Administrators || [])
      .some((n) => compile.principalKey(n) === compile.principalKey(entry.sam)));
    assert.ok(listed, `${entry.sam} is declared via the DC local group but is not on one`);
  }
});

test('B14-103 nested membership is caught: a group inside Domain Admins makes every member one', () => {
  // The route nobody writes down. The self-check has to walk it, or an ordinary
  // helpdesk account is a domain admin and nothing anywhere says so.
  const lab = labOf(compileFixture('S'));
  const fqdn = Object.keys(lab.domains)[0];
  const domain = lab.domains[fqdn];
  const victim = Object.keys(domain.users)
    .find((s) => !domain.users[s].groups.includes('Domain Admins'));
  const group = Object.keys(domain.groups.global)[0];
  // Put the victim in a group, and the group inside Domain Admins.
  domain.users[victim].groups = [group];
  domain.groups.global[group].members = [];
  domain.groups.global['Domain Admins'] = { path: '', members: [group] };

  const found = compile.privilegedPrincipalsOf(lab);
  assert.ok(found.has(`${fqdn}\\${compile.principalKey(victim)}`),
    `'${victim}' reaches Domain Admins through '${group}' and the walk must say so`);
  assert.ok(found.has(`${fqdn}\\${compile.principalKey(group)}`),
    'the intermediate group is privileged too, and is equally a principal');
});

test('B14-104 an admin the composer forgot to declare is a COMPILE ERROR', () => {
  // Silence is what produced the original bug. The composer must refuse rather
  // than hand the designer a lab it cannot reason about.
  const lab = labOf(compileFixture('S'));
  assert.throws(
    () => compile.assertAdminsDeclared(lab, new Map(), 'CIAB-TEST'),
    (err) => {
      assert.strictEqual(err.code, 'CIAB_UNDECLARED_DOMAIN_ADMIN');
      assert.ok(Array.isArray(err.missing) && err.missing.length > 0);
      // The message has to name the principal AND the route, because "some
      // admin is undeclared" is not actionable.
      assert.ok(err.message.indexOf(err.missing[0].sam) !== -1, err.message);
      assert.ok(/via /.test(err.message), err.message);
      return true;
    });
});

test('B14-105 a declaration the lab does not honour is also a COMPILE ERROR', () => {
  // The mirror-image mistake: a stale declaration switches off the designer's
  // shorter-path check for a principal that never needed one.
  const lab = labOf(compileFixture('S'));
  const fqdn = Object.keys(lab.domains)[0];
  const declared = compile.privilegedPrincipalsOf(lab);
  declared.set(`${fqdn}\\ghost.account`,
    { sam: 'ghost.account', domain: fqdn, via: 'Domain Admins' });
  assert.throws(
    () => compile.assertAdminsDeclared(lab, declared, 'CIAB-TEST'),
    (err) => err.code === 'CIAB_STALE_ADMIN_DECLARATION' && /ghost\.account/.test(err.message));
});

test('B14-106 demoting a principal removes every privileged route they had', () => {
  const base = compileFixture('M_A');
  const target = base.ir.principals.declared_admins[0];
  const out = compile.compileLab(profileFixture(FIXTURES.M_A), { demoteAdmins: [target.sam] });
  const stillDeclared = out.ir.principals.declared_admins
    .filter((a) => compile.principalKey(a.sam) === compile.principalKey(target.sam));
  assert.deepStrictEqual(stillDeclared, [],
    `${target.sam} was demoted and must hold no privileged membership by any route`);
  // And the lab agrees — the group AND the DC's local Administrators list, which
  // is the route a demotion would otherwise leave wide open.
  const found = compile.privilegedPrincipalsOf(labOf(out));
  assert.ok(!found.has(`${target.domain}\\${compile.principalKey(target.sam)}`));
});

test('B14-107 demotion does not reshuffle anybody else, so the negotiation converges', () => {
  // The weak-password band is anchored on admin CANDIDACY rather than on the
  // resulting membership. If it were anchored on membership, every demotion
  // would move a password, the design would change underneath the negotiation,
  // and the loop would chase a moving target instead of settling.
  const base = compileFixture('M_A');
  const target = base.ir.principals.declared_admins[0];
  const out = compile.compileLab(profileFixture(FIXTURES.M_A), { demoteAdmins: [target.sam] });
  const before = labOf(base).domains[target.domain].users;
  const after = labOf(out).domains[target.domain].users;
  assert.deepStrictEqual(Object.keys(after), Object.keys(before), 'the roster itself moved');
  for (const sam of Object.keys(before)) {
    assert.strictEqual(after[sam].password, before[sam].password,
      `demoting ${target.sam} moved ${sam}'s password`);
  }
});

test('B14-108 a company has domain admins, not a directory made of them', () => {
  // A profile carrying seven stakeholders against a small domain slice used to
  // mint five Domain Admins out of nine accounts, which is not realism — and it
  // left two ordinary principals for the whole attack chain to be built from,
  // so the designer (correctly) refused to design a three-hop chain over two
  // nodes. The count is capped at a quarter of the domain's own roster, floor
  // one: somebody is always a Domain Admin, and it is never half the company.
  const crowded = profileFixture({
    runId: 'RUN_2026_CROWDED',
    company: 'Nakamura Precision Tools',
    domain: 'nakamuratools.com',
    employees: 210,
    departments: { Production: 60, Maintenance: 20, Quality: 10, IT: 5, Shipping: 18 },
    stakeholders: [
      { name: 'Dr. Jane Smith', role: 'CEO', department: 'Executive' },
      { name: 'Marcus Webb', role: 'IT Director', department: 'IT' },
      { name: 'Priya Rao', role: 'Controller', department: 'Finance' },
      { name: 'Tom Ng Jr.', role: 'Operations Lead', department: 'Operations' },
      { name: 'Alina Kovacs', role: 'HR Manager', department: 'Human Resources' },
      { name: 'Devon Ellery', role: 'Facilities Supervisor', department: 'Facilities' },
      { name: 'Renata Alvarez', role: 'Compliance Officer', department: 'Administration' },
    ],
  });
  const lab = labOf(compile.compileLab(crowded));
  for (const [fqdn, domain] of Object.entries(lab.domains)) {
    const users = Object.values(domain.users);
    const admins = users.filter((u) => u.groups.indexOf('Domain Admins') !== -1);
    assert.ok(admins.length >= 1, `${fqdn}: somebody has to be a Domain Admin`);
    assert.ok(admins.length <= Math.max(1, Math.round(users.length * 0.35)),
      `${fqdn}: ${admins.length} of ${users.length} accounts are Domain Admins, which is not an `
      + 'org chart, it is a shortcut');
  }
  // And the whole pipeline gets through it, which is the point of the cap.
  const out = compile.compileLabWithChain(crowded);
  assert.ok(out.chain_design.edges.length >= 3);
});

// ─── B15. Principal overrides: the seam, applied ────────────────────────────

test('B15-100 a design decision about an account lands on the EMITTED lab, not just the IR', () => {
  const base = compileFixture('S');
  const fqdn = base.ir.domains[0].fqdn;
  const sam = base.ir.foothold_credential.sam;
  const out = compile.compileLab(profileFixture(FIXTURES.S), {
    principalOverrides: { [fqdn]: { [sam]: { password: 'Chang3me', description: 'roasted' } } },
    footholdCredential: { sam, domain: fqdn, password: 'Chang3me', planted_at: null },
  });
  const lab = labOf(out);
  assert.strictEqual(lab.domains[fqdn].users[sam].password, 'Chang3me',
    'AD must be built with the string the website hands out, byte for byte');
  assert.strictEqual(lab.domains[fqdn].users[sam].description, 'roasted');
  assert.strictEqual(out.ir.principals.users.find((u) => u.sam === sam).password, 'Chang3me',
    'the IR and the emitted config must not disagree about the same account');
});

test('B15-101 an override naming an account the forest never builds is refused', () => {
  // Silently dropping it is how the website and the directory end up with two
  // different passwords, both halves green and the login broken.
  const fqdn = compileFixture('S').ir.domains[0].fqdn;
  assert.throws(
    () => compile.compileLab(profileFixture(FIXTURES.S), {
      principalOverrides: { [fqdn]: { 'nobody.here': { password: 'Chang3me' } } },
    }),
    (err) => err.code === 'CIAB_PRINCIPAL_OVERRIDE_UNKNOWN' && /nobody\.here/.test(err.message));
  assert.throws(
    () => compile.compileLab(profileFixture(FIXTURES.S), {
      principalOverrides: { 'not.a.domain': { x: { password: 'y' } } },
    }),
    (err) => err.code === 'CIAB_PRINCIPAL_OVERRIDE_DOMAIN_UNKNOWN');
});

// ─── B16. The composer/designer negotiation, end to end ─────────────────────
//
// THE EXIT CRITERION. Before this work, 60 of 60 realistic profiles compiled and
// 0 of 60 produced an attack chain. The corpus below is the standing proof that
// the two halves compose: for every profile the composer produces a lab, the
// designer produces a PROVEN chain over it, the emitted config.json re-parses
// and passes both external checkers, and the foothold credential is honoured in
// both directions. Anything less than every single one is a regression, and it
// is written as one assertion per profile so the failure names the client.

const CORPUS_CLIENTS = Object.freeze([
  // ── S: below org-sizing's second-DC threshold ──
  { company: 'Ridgeline Dental Group', domain: 'ridgelinedental.com', employees: 42, city: 'Tucson, AZ' },
  { company: 'Harborview Community Library', domain: 'harborviewlib.org', employees: 45, clientType: 'Library', city: 'Duluth, MN' },
  { company: 'Summitpoint Health Clinic', domain: 'summitpointhealth.com', employees: 38, city: 'Ogden, UT' },
  { company: 'The Delaney Group Holdings', domain: 'delaneygroup.com', employees: 52, city: 'Savannah, GA' },
  { company: 'Bramble Hill Winery', domain: 'bramblehill.com', employees: 36, city: 'Napa, CA' },
  { company: 'Hartman Legal Associates', domain: 'hartmanlegal.com', employees: 40, city: 'Providence, RI' },
  { company: 'Petrov and Sons Electric', domain: 'petrovelectric.com', employees: 48, city: 'Cleveland, OH' },
  // ── M: at or above the threshold, single site ──
  { company: 'Cascade Freight Services', domain: 'cascadefreight.com', employees: 110, city: 'Portland, OR' },
  { company: 'Tidewater Marine Supply', domain: 'tidewatermarine.com', employees: 110, city: 'Norfolk, VA' },
  { company: 'Brightpath Family Services', domain: 'brightpathfs.org', employees: 95, clientType: 'NonProfit', city: 'Boise, ID' },
  { company: 'Kestrel Aviation Services', domain: 'kestrelaviation.com', employees: 88, city: 'Wichita, KS' },
  { company: 'Meridian Analytics LLC', domain: 'meridiananalytics.com', employees: 92, city: 'Austin, TX' },
  { company: 'Iversen Marine Research', domain: 'iversenmarine.org', employees: 105, clientType: 'NonProfit', city: 'Newport, RI' },
  // ── L: multi-site AND second-DC-sized ──
  { company: 'Vantage Utilities Cooperative', domain: 'vantageutil.coop', employees: 320, clientType: 'Utility_IT_OT', city: 'Bend, OR' },
  { company: 'Northfield Unified School District', domain: 'northfieldusd.org', employees: 260, clientType: 'K12', city: 'Northfield, MN' },
  { company: 'Cedarline Manufacturing', domain: 'cedarline.com', employees: 180, city: 'Akron, OH' },
  { company: 'Stonebridge Insurance Partners', domain: 'stonebridgeins.com', employees: 240, city: 'Hartford, CT' },
  { company: 'Ironwood Timber Co', domain: 'ironwoodtimber.com', employees: 210, city: 'Missoula, MT' },
  { company: 'Clearwater Labs', domain: 'clearwaterlabs.io', employees: 400, city: 'Tampa, FL' },
  { company: 'Lakeshore Water Authority', domain: 'lakeshorewater.gov', employees: 175, clientType: 'Utility_IT_OT', city: 'Erie, PA' },
  { company: 'Whitfield Public Schools', domain: 'whitfieldschools.org', employees: 340, clientType: 'K12', city: 'Dalton, GA' },
  { company: 'Ospina Logistics', domain: 'ospinalogistics.com', employees: 500, city: 'Laredo, TX' },
  { company: 'Everly Senior Living', domain: 'everlyliving.com', employees: 380, city: 'Sarasota, FL' },
  { company: 'Quintana Foods Distribution', domain: 'quintanafoods.com', employees: 450, city: 'Fresno, CA' },
]);

const CORPUS_DEPARTMENTS = Object.freeze([
  { Operations: 20, Sales: 10, Finance: 6, IT: 4, Administration: 5 },
  { Engineering: 30, Operations: 25, Finance: 8, IT: 6, 'Customer Service': 12 },
  { Instruction: 90, 'Student Services': 30, 'Business Office': 10, Technology: 6, Facilities: 20 },
  { Programs: 40, Development: 12, Finance: 7, Administration: 9 },
  { 'Public Services': 14, 'Technical Services': 8, 'Youth Services': 6, Administration: 5 },
  { Production: 60, Maintenance: 20, Quality: 10, IT: 5, Shipping: 18 },
]);

const CORPUS_STAKEHOLDERS = Object.freeze([
  { name: 'Dr. Jane Smith', role: 'Chief Executive Officer', department: 'Executive' },
  { name: 'Marcus Webb', role: 'IT Director', department: 'IT' },
  { name: 'Priya Raghunathan-Venkataraman', role: 'Controller', department: 'Finance' },
  { name: 'Tom Ng Jr.', role: 'Operations Lead', department: 'Operations' },
  { name: 'Alina Kovacs', role: 'HR Manager', department: 'Human Resources' },
  { name: 'Devon Ellery', role: 'Facilities Supervisor', department: 'Facilities' },
  { name: 'Renata Alvarez', role: 'Compliance Officer', department: 'Administration' },
  { name: 'Kwame Boateng', role: 'Systems Administrator', department: 'IT' },
]);

/** One realistic profile per client, varied on every axis a real intake varies. */
function corpusProfile(i) {
  const client = CORPUS_CLIENTS[i];
  const tag = client.company.replace(/[^A-Za-z]/g, '').toUpperCase().slice(0, 10);
  return profileFixture(Object.assign({}, client, {
    runId: `RUN_CORPUS_${String(i).padStart(3, '0')}_${tag}`,
    departments: CORPUS_DEPARTMENTS[i % CORPUS_DEPARTMENTS.length],
    stakeholders: CORPUS_STAKEHOLDERS.slice(0, 4 + (i % 5)),
    delivery: ['Hybrid', 'On-Prem', 'Hybrid', 'On-Premises'][i % 4],
  }));
}

const corpusCache = new Map();
function corpusLab(i) {
  if (!corpusCache.has(i)) corpusCache.set(i, compile.compileLabWithChain(corpusProfile(i)));
  return corpusCache.get(i);
}

test('B16-100 the corpus spans all three tiers, so the gate is not proved on one shape', () => {
  const tiers = {};
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const t = compile.compileLab(corpusProfile(i)).tier;
    tiers[t] = (tiers[t] || 0) + 1;
  }
  assert.ok(CORPUS_CLIENTS.length >= 20, 'the corpus must carry at least 20 clients');
  for (const tier of compile.TIERS) {
    assert.ok(tiers[tier] >= 3, `only ${tiers[tier] || 0} tier-${tier} clients in the corpus`);
  }
});

test('B16-101 every corpus profile compiles AND designs a proven chain', () => {
  // The headline. One assertion per client so a failure names the client rather
  // than a count.
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const name = CORPUS_CLIENTS[i].company;
    const out = corpusLab(i);
    assert.ok(out.chain_design, `${name}: no chain was designed`);
    assert.ok(out.chain_design.edges.length >= compile.TIERS.length,
      `${name}: a chain of ${out.chain_design.edges.length} edges is not a graph`);
    assert.ok(out.chain_design.signature, `${name}: the design carries no signature`);
  }
});

test('B16-102 every emitted config.json re-parses and passes BOTH checkers', () => {
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const name = CORPUS_CLIENTS[i].company;
    const out = corpusLab(i);
    const parsed = validate.parseLabConfig(out.files['data/config.json'],
      { source: `${name} data/config.json` });
    validate.assertLabCompiles({
      lab: parsed.lab, inventory: out.files['data/inventory'], labName: out.ir.lab_name,
    });
    preflight.assertGoadLabPreflight({
      labName: out.ir.lab_name,
      config: out.files['data/config.json'],
      inventory: out.files['data/inventory'],
      providerInventory: out.files['providers/proxmox/inventory'],
      playbooks: out.chain,
    });
    // Every ACL the designer drew really is in the file the lane deploys.
    const domainAcls = parsed.lab.domains[out.chain_design.domain].acls;
    for (const edge of out.chain_design.edges.concat(out.chain_design.decoys)) {
      if (edge.edge_type !== 'acl') continue;
      assert.ok(domainAcls[edge.created_by.item],
        `${name}: designed ACL '${edge.created_by.item}' never reached config.json`);
    }
  }
});

test('B16-103 the foothold credential is honoured in BOTH directions, in the emitted file', () => {
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const name = CORPUS_CLIENTS[i].company;
    const out = corpusLab(i);
    const cred = out.ir.foothold_credential;
    // Composer side: AD creates the principal, with that exact password.
    compile.assertFootholdHonoured(out.ir);
    // Emitted side: the same string is in the file the lane actually deploys.
    const parsed = validate.parseLabConfig(out.files['data/config.json'], { source: name });
    const user = parsed.lab.domains[cred.domain].users[cred.sam];
    assert.ok(user, `${name}: the emitted forest has no '${cred.sam}'`);
    assert.strictEqual(user.password, cred.password,
      `${name}: the website would hand out one string and the directory was built with another`);
    // Designer side: the chain starts there and the web side plants it.
    assert.strictEqual(out.chain_design.start.principal, cred.sam);
    assert.ok(cred.planted_at && cred.planted_at.path && cred.planted_at.format,
      `${name}: nothing plants the credential the chain starts from`);
  }
});

test('B16-104 the whole pipeline is byte-identical under the same run_id', () => {
  // Paper-vs-lane parity is asserted BY regeneration, and the negotiation is
  // part of the pipeline now: if demoting an admin were order-dependent, the
  // same profile would produce two different forests.
  for (const i of [0, 8, 15]) {
    const a = compile.compileLabWithChain(corpusProfile(i));
    const b = compile.compileLabWithChain(corpusProfile(i));
    assert.deepStrictEqual(b.files, a.files, `${CORPUS_CLIENTS[i].company}: the tree drifted`);
    assert.deepStrictEqual(b.chain_design, a.chain_design, 'the design drifted');
    assert.deepStrictEqual(b.negotiation, a.negotiation, 'the negotiation drifted');
  }
});

test('B16-105 the negotiation is a guard, and realistic input does not need it', () => {
  // THE HONEST STATE OF THE WORLD, PINNED AS AN ASSERTION. Across the corpus —
  // and across 1,500 generated profiles while this was being built — the
  // demotion branch never fires: once the designer stopped binding declared
  // admins to chain nodes and stopped pointing decoys at them, no roster admin
  // is left within reach of the foothold. A test that claimed otherwise would be
  // asserting a fiction. What IS asserted is that the record exists and is
  // well-formed on every client, so a future composer change that DOES make an
  // admin cheap shows up here as a diff rather than as a silent demotion.
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const out = corpusLab(i);
    assert.ok(out.negotiation && Array.isArray(out.negotiation.rounds)
      && Array.isArray(out.negotiation.demoted),
    `${CORPUS_CLIENTS[i].company}: no negotiation record`);
    assert.ok(out.negotiation.rounds_used >= 1);
    // Nothing is privileged in the shipped lab that was demoted along the way.
    const found = compile.privilegedPrincipalsOf(labOf(out));
    for (const key of out.negotiation.demoted) {
      for (const [k] of found) {
        assert.notStrictEqual(k.split('\\')[1], key,
          `${key} was demoted and is still privileged in the emitted lab`);
      }
    }
  }
});

/**
 * A designer that reports one named admin as reachable too cheaply, once.
 *
 * The demotion branch cannot be reached from a profile — see B16-105 — and an
 * untested negotiation is one that will not work the first time a composer
 * change makes it necessary. So the branch is driven against a designer that
 * produces the finding the real one would produce, in exactly the shape the real
 * one produces it (goad-attack-chain's SHORTCUT_ADMIN_TOO_CHEAP carries
 * principal, hops, designed_hops and path). Everything downstream of the
 * finding — the demotion, the re-emit, the record, the refusal message — is the
 * real code.
 */
function cheapAdminDesigner(realDesigner, opts) {
  const settings = opts || {};
  let remaining = settings.times === undefined ? 1 : settings.times;
  return (ir, designOpts) => {
    const admin = ir.principals.declared_admins
      .filter((a) => a.reason === 'roster_realism')
      .filter((a) => !settings.exclude || settings.exclude.indexOf(a.sam) === -1)[0];
    if (admin && remaining > 0) {
      remaining -= 1;
      const err = new Error('attack chain: 1 unintended shortcut');
      err.code = 'CHAIN_HAS_SHORTCUTS';
      err.findings = [{
        code: 'SHORTCUT_ADMIN_TOO_CHEAP',
        message: `'${admin.sam}' is a declared roster_realism Domain Admin reachable in 2 hops`,
        link: `labIR.principals.declared_admins -> ${admin.sam}`,
        principal: admin.sam,
        reason: admin.reason,
        hops: 2,
        designed_hops: 7,
        path: [ir.foothold_credential.sam, 'ng-srv02$', admin.sam],
      }];
      throw err;
    }
    return realDesigner(ir, designOpts);
  };
}

test('B16-106 a cheap roster admin is demoted and the lab re-emitted, not waved through', () => {
  const profile = corpusProfile(0);
  const before = compile.compileLab(profile).ir.principals.declared_admins;
  assert.ok(before.length >= 2,
    'this fixture needs more than one admin, or demoting one proves nothing');

  const real = require(P('utils/goad-attack-chain.js')).designAttackChain;
  const out = compile.compileLabWithChain(profile, { designer: cheapAdminDesigner(real) });

  assert.strictEqual(out.negotiation.rounds.length, 1, 'exactly one demotion was needed');
  const demotedSam = out.negotiation.rounds[0].demoted[0];
  assert.ok(demotedSam, 'the round recorded no principal');
  // The finding's three facts are carried into the record, because "an admin was
  // demoted" without the short path is not something an instructor can judge.
  const finding = out.negotiation.rounds[0].findings[0];
  assert.strictEqual(finding.hops, 2);
  assert.strictEqual(finding.designed_hops, 7);
  assert.ok(Array.isArray(finding.path) && finding.path.length === 3);

  // The re-emitted lab really is different: that principal holds no privileged
  // membership by any route, and the OTHER admins survive — demoting the whole
  // roster would be "widening the check until it passes" by another name.
  const found = compile.privilegedPrincipalsOf(labOf(out));
  for (const [k] of found) assert.notStrictEqual(k.split('\\')[1], demotedSam);
  assert.ok(found.size >= 1, 'a company with no domain admin at all is not realism either');
  // And the lab that comes out is a complete, proven one.
  assert.ok(out.chain_design && out.chain_design.edges.length > 0);
  compile.assertFootholdHonoured(out.ir);
});

test('B16-107 the negotiation is bounded, and gives up loudly rather than quietly', () => {
  // The one outcome this pipeline treats as worse than a crash is a silent one.
  // A designer that keeps reporting a cheap admin must exhaust the rounds and
  // then REFUSE, naming the principal, the short path and the intended chain
  // length — never emit the lab anyway.
  const real = require(P('utils/goad-attack-chain.js')).designAttackChain;
  assert.throws(
    () => compile.compileLabWithChain(corpusProfile(0), {
      designer: cheapAdminDesigner(real, { times: Infinity }),
      maxNegotiationRounds: 3,
    }),
    (err) => {
      assert.strictEqual(err.code, 'CIAB_ADMIN_NEGOTIATION_FAILED');
      assert.ok(err.principal, 'the refusal must name the principal');
      assert.strictEqual(err.hops, 2);
      assert.strictEqual(err.designed_hops, 7);
      assert.ok(err.message.indexOf(err.principal) !== -1, err.message);
      assert.ok(/2 hops/.test(err.message), `the short path length is missing: ${err.message}`);
      assert.ok(/7 hops long/.test(err.message), `the intended length is missing: ${err.message}`);
      assert.ok(/ -> /.test(err.message), 'the refusal must print the short path it found');
      // And it must not have quietly widened anything to get there.
      assert.ok(Array.isArray(err.rounds) && err.rounds.length >= 1);
      return true;
    });
});

test('B16-108 the corpus keeps its variety: no two clients get the same lab', () => {
  // The reskin failure, re-asserted over the corpus rather than over a pair.
  const labSignatures = new Set();
  const chainSignatures = new Set();
  for (let i = 0; i < CORPUS_CLIENTS.length; i += 1) {
    const out = corpusLab(i);
    labSignatures.add(JSON.stringify(compile.structuralSignature(out.ir)));
    chainSignatures.add(JSON.stringify(out.chain_design.signature));
  }
  assert.strictEqual(labSignatures.size, CORPUS_CLIENTS.length,
    'two clients got structurally the same forest');
  assert.ok(chainSignatures.size >= CORPUS_CLIENTS.length - 2,
    `only ${chainSignatures.size} distinct graphs across ${CORPUS_CLIENTS.length} clients`);
});

// ─── B17. Generated-mode validation is WIRED, not merely available ──────────
/*
 * goad-lab-validate grew a 'generated' mode whose whole job is to refuse the
 * one lab that passes every other checker: a forest with a roster and no attack
 * path. The rule set landed complete and correct — and the compiler went on
 * calling assertLabCompiles with no mode at all, so nothing ever ran it. A guard
 * that is never engaged is indistinguishable from no guard, and the failure it
 * exists to catch is the one that deploys green and teaches nothing.
 *
 * These tests are about the WIRE. They drive the real negotiation with a
 * designer that returns a chain broken in one specific way and assert the
 * compile REFUSES — which it can only do if the mode is actually reaching the
 * validator on the pass whose output ships.
 */

const B17_PROFILE = () => profileFixture(FIXTURES.M_A);

/**
 * compileLabWithChain, with the designer's answer damaged on the way out.
 *
 * `designer` is already substitutable — B16 uses it to force the demotion
 * branch — so this needs no new seam. The real designer runs first, which
 * matters: the damage is applied to a chain that was genuinely designed against
 * this lab, so anything refused here is refused for the mutation and not for
 * some incidental incoherence in a hand-built fixture.
 */
function compileWithDamagedChain(damage) {
  const real = require(P('utils/goad-attack-chain.js')).designAttackChain;
  return compile.compileLabWithChain(B17_PROFILE(), {
    designer: (args) => { const designed = real(args); damage(designed); return designed; },
  });
}

function assertRefusedWithCode(damage, code, label) {
  assert.throws(() => compileWithDamagedChain(damage), (err) => {
    assert.strictEqual(err.code, 'LAB_DEFINITION_INVALID',
      `${label}: expected the validator's refusal, got ${err.code}: ${err.message}`);
    const codes = (err.errors || []).map((e) => e.code);
    assert.ok(codes.includes(code),
      `${label}: expected ${code} among [${codes.join(', ')}]`);
    return true;
  });
}

test('B17-101 the control still ships — the guard refuses damage, not everything', () => {
  const out = compileWithDamagedChain(() => {});
  assert.ok(out.ir.chain.edges.length > 0);
  assert.ok(Object.values(out.ir.acls).some((block) => Object.keys(block || {}).length > 0));
});

test('B17-102 THE DEFECT: a chain with no edges cannot be shipped', () => {
  // The exact shape the bake route used to push: a lab that both pre-existing
  // checkers pass, because neither has an opinion about whether the exercise is
  // solvable.
  assertRefusedWithCode((d) => { d.chain.edges = []; }, 'CHAIN_EMPTY', 'no edges');
});

test('B17-103 ACLs the designer drew but the composer never lowered are caught', () => {
  // The two-code-paths check: the designer draws the edge and the composer
  // lowers it into lab.domains[].acls. Only comparing the two catches a
  // lowering bug, and a lowering bug plants nothing while reporting success.
  assertRefusedWithCode((d) => { d.acls = {}; }, 'CHAIN_ACL_NOT_EMITTED', 'acls dropped');
});

test('B17-104 a chain that never reaches its objective is caught', () => {
  assertRefusedWithCode((d) => { d.chain.edges = d.chain.edges.slice(0, 1); },
    'CHAIN_OBJECTIVE_UNREACHED', 'truncated');
});

test('B17-105 a chain not rooted at the planted foothold is caught', () => {
  assertRefusedWithCode((d) => { d.chain.start = null; },
    'CHAIN_NOT_ROOTED_AT_FOOTHOLD', 'no start');
});

test('B17-106 a chain with no objective is caught', () => {
  assertRefusedWithCode((d) => { d.chain.objective = null; },
    'CHAIN_OBJECTIVE_MISSING', 'no objective');
});

test('B17-107 the DRAFT pass is deliberately NOT held to the generated rules', () => {
  // compileLabWithChain's first pass compiles with no chain on purpose — that
  // draft is what the designer reasons over, and it has exactly the acls:{} +
  // null-chain shape generated mode rejects. If the mode were engaged on every
  // compile rather than on the one that ships, the negotiation could never run
  // at all, so this pins the scoping as much as the guard.
  const draft = compile.compileLab(B17_PROFILE());
  assert.strictEqual(draft.ir.chain.edges.length, 0);
  assert.strictEqual(
    Object.values(draft.ir.acls).reduce((n, b) => n + Object.keys(b || {}).length, 0), 0);

  // And a PARTIAL chain handed straight to compileLab stays a reference-mode
  // compile too: B10 probes the foothold rules with a `start` and nothing else,
  // and a fragment nobody is going to ship is not the thing this guard is for.
  const base = compileFixture('S');
  const cred = base.ir.foothold_credential;
  const partial = compile.compileLab(profileFixture(FIXTURES.S), {
    footholdCredential: {
      sam: cred.sam, domain: cred.domain, password: cred.password,
      planted_at: { host_key: 'web01', path: '/var/www/app/config/database.yml', format: 'yaml' },
    },
    chain: { start: { kind: 'credential', principal: cred.sam, how: 'config file' } },
  });
  assert.strictEqual(partial.ir.chain.start.principal, cred.sam);
});

test('B17-108 the wire itself is pinned: the shipping pass asks for generated mode', () => {
  // Source-level, and deliberately so. Every test above would still pass if the
  // mode were engaged somewhere that happens to cover them today; this pins WHERE
  // it is engaged, because the regression being guarded against is not a wrong
  // answer but a silently absent one.
  const src = require('fs').readFileSync(P('utils/goad-lab-compile.js'), 'utf8');
  assert.match(src, /assertGenerated:\s*true/,
    'compileLabWithChain must mark its final compileLab as the pass that ships');
  assert.match(src, /mode:\s*MODE_GENERATED/,
    'assertEmitted must pass MODE_GENERATED through to the validator');
  assert.match(src, /generated:\s*options\.assertGenerated === true/,
    'the discriminator must be the explicit flag, not the presence of a chain');
});

// ─── B18. The forest is named by the client's own asset register ────────────
/*
 * WHY THIS IS A CORRECTNESS PROPERTY AND NOT A NICETY.
 *
 * The composer used to mint every hostname off the company name (HARBOR-DC01)
 * while profile-to-spec built spec.vms[].name straight from asset.hostname
 * (DC-01). Two estates, and the documents a student is handed name only one of
 * them: the scan report, the asset register and the topology diagram all print
 * the profile's names, and nmap answers to those.
 *
 * The mechanical half is worse than the cosmetic one. A bake's golden templates
 * are named after the STAGING lane's machines, so a bake minted as HARBOR-DC01
 * and a deploy synthesized as DC-01 have no machine in common at all, and
 * profile-deploy refuses every deploy of that client (BAKE_GOLDEN_UNMATCHED).
 * The correspondence asserted below is what closes that loop.
 */

/** A profile whose asset register names the machines the forest needs. */
function REGISTERED(over) {
  const assets = (over && over.assets) || [
    { hostname: 'DC-01', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
    { hostname: 'DC-02', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
    { hostname: 'FS-01', role: 'server', os: 'Windows Server 2016', services: ['445/SMB'] },
    { hostname: 'WEB-01', role: 'server', os: 'Windows Server 2019', services: ['80/HTTP'] },
    { hostname: 'WS-014', role: 'workstation', os: 'Windows 11', services: [] },
  ];
  // 110 employees, single site -> tier M: two controllers and one member, which
  // is exactly what ai/profile's own roles[] gives a client this size (a primary
  // DC, a secondary DC and a file server), because both sides read org-sizing.
  const base = profileFixture({ ...FIXTURES.M_A, ...(over || {}) });
  base.json_data.student_view.raw.threats.network = { assets };
  return base;
}

test('B18-101 forest hostnames are the client\'s own, and controllers take controller names', () => {
  const out = compile.compileLab(REGISTERED());
  const hosts = out.ir.hosts;
  assert.deepStrictEqual(hosts.map((h) => h.hostname), ['DC-01', 'DC-02', 'FS-01'],
    'the machines the paper names, in the order the chassis binds them — a name minted off the '
    + 'company name is a machine no document the student holds mentions');

  // And the DC/member split follows the register rather than the order: the file
  // server on the paper must not come back as a domain controller on the lane.
  const byName = Object.fromEntries(hosts.map((h) => [h.hostname, h.type]));
  assert.strictEqual(byName['DC-01'], 'dc');
  assert.strictEqual(byName['DC-02'], 'dc');
  assert.notStrictEqual(byName['FS-01'], 'dc');

  // The emitted lab carries the same names — this is the file the chain runs
  // against, so a rename that stopped at the IR would be a lab that disagrees
  // with its own compiler.
  const lab = JSON.parse(out.files['data/config.json']).lab;
  assert.deepStrictEqual(Object.values(lab.hosts).map((h) => h.hostname), ['DC-01', 'DC-02', 'FS-01']);
});

test('B18-102 the web server is never a forest host, because the lane makes it Linux', () => {
  // profile-to-spec forces every isWebServer() asset onto Linux and makes it the
  // lane's dual-homed DMZ pivot. A web asset adopted as a forest hostname would
  // therefore be a Windows domain member on one side and a Linux pivot on the
  // other, and the two would only meet on a lane.
  const out = compile.compileLab(REGISTERED());
  assert.ok(!out.ir.hosts.some((h) => h.hostname === 'WEB-01'),
    'WEB-01 declares an HTTP service, so it is the DMZ host and not an AD machine');
});

test('B18-103 a register with nothing left to offer falls back to the mint, and SAYS so', () => {
  // The client whose paper names one Windows server and whose org-sizing asks
  // for three. A minted name is a machine no document mentions AND the machine a
  // deploy will refuse over, so the reason has to be visible on the bake.
  const out = compile.compileLab(REGISTERED({
    assets: [{ hostname: 'DC-01', role: 'server', os: 'Windows Server 2019', services: [] }],
  }));
  assert.strictEqual(out.ir.hosts[0].hostname, 'DC-01');
  const minted = out.ir.hosts.slice(1).map((h) => h.hostname);
  assert.strictEqual(minted.length, 2);
  for (const name of minted) assert.ok(!/^DC-01$/i.test(name));

  const codes = out.warnings.map((w) => w.code);
  assert.strictEqual(codes.filter((c) => c === 'CIAB_LAB_HOST_NOT_ON_PAPER').length, 2,
    'one per host the register could not name');

  // A profile with no register at all is the same story and must still compile:
  // every hand-written fixture in this file is one.
  const bare = compile.compileLab(profileFixture(FIXTURES.M_A));
  assert.strictEqual(bare.ir.hosts.length, 3);
  for (const h of bare.ir.hosts) assert.match(h.hostname, /^[A-Za-z0-9-]+$/);
});

test('B18-103b a register LONGER than the tier is warned about too, and the DCs by name', () => {
  // The other direction of B18-103's mismatch, and the one that used to be
  // silent. A surplus Windows server still reaches the lane — the synthesizer
  // builds a spec machine for every selected asset — but the baked forest does
  // not name it, so deployLabDefFromBake skips it, prepareGoadMacs exempts it,
  // and it clones the STOCK catalog image with no account in the directory. A
  // machine the scan report calls a domain controller then boots as a workgroup
  // box and the lane reports active, which is the same paper-vs-lane divergence
  // the mint warning exists to prevent.
  const out = compile.compileLab(REGISTERED({
    assets: [
      { hostname: 'DC-01', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
      { hostname: 'DC-02', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
      { hostname: 'FS-01', role: 'server', os: 'Windows Server 2016', services: ['445/SMB'] },
      // Two the tier-M chassis has no host for.
      { hostname: 'DC-03', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
      { hostname: 'APP-01', role: 'server', os: 'Windows Server 2019', services: ['1433/MSSQL'] },
      { hostname: 'WEB-01', role: 'server', os: 'Windows Server 2019', services: ['80/HTTP'] },
    ],
  }));
  assert.deepStrictEqual(out.ir.hosts.map((h) => h.hostname), ['DC-01', 'DC-02', 'FS-01'],
    'the forest is still exactly the tier-M chassis, filled from the register in order');

  const w = out.warnings.find((x) => x.code === 'CIAB_PAPER_SERVER_NOT_IN_FOREST');
  assert.ok(w, `a surplus register must be reported: ${out.warnings.map((x) => x.code).join(', ')}`);
  assert.ok(w.message.includes('DC-03'), 'it names the surplus controller');
  assert.ok(w.message.includes('APP-01'), 'and the surplus member');
  assert.ok(!w.message.includes('WEB-01'),
    'the web asset was never a forest candidate, so it is not a surplus one either');
  assert.ok(/domain controller/.test(w.message),
    'a surplus CONTROLLER is called out separately — a standalone member server is a defensible '
    + 'environment, a domain controller with no domain is not');

  // A register that fits exactly says nothing, so the warning stays meaningful.
  assert.ok(!compile.compileLab(REGISTERED()).warnings
    .some((x) => x.code === 'CIAB_PAPER_SERVER_NOT_IN_FOREST'),
  'a register the tier consumes completely produces no surplus warning');
});

test('B18-104 a paper name Windows cannot use is refused rather than truncated', () => {
  // uniqueName() trims to fit, and a trimmed paper name (a 17-character host cut
  // to 15) is a machine the documents do not name either — so a candidate that
  // does not already satisfy the validator's own rules is dropped, warned about,
  // and the mint is used.
  const out = compile.compileLab(REGISTERED({
    assets: [
      { hostname: 'PRIMARY-DOMAIN-CONTROLLER-01', role: 'server', os: 'Windows Server 2019', services: [] },
      { hostname: 'FS-01', role: 'server', os: 'Windows Server 2016', services: [] },
    ],
  }));
  const names = out.ir.hosts.map((h) => h.hostname);
  assert.ok(!names.some((n) => /^PRIMARY-DOMAIN/i.test(n)), 'no truncated form of it survives');
  assert.ok(names.includes('FS-01'), 'the usable name is still adopted');
  assert.ok(out.warnings.some((w) => w.code === 'CIAB_PAPER_HOSTNAME_UNUSABLE'));
  for (const n of names) assert.ok(n.length <= validate.MAX_NETBIOS_HOSTNAME);
});

test('B18-105 every forest host carries the octet its own provider inventory addresses it at', () => {
  // The bake stands a staging lane from this IR and then runs the chain over the
  // emitted providers/proxmox/inventory. A machine placed on any other octet is
  // unreachable to every playbook — an hour of failed connections — so the octet
  // is a fact ABOUT the host, read out of that file rather than re-derived by
  // whoever builds the spec.
  for (const { key, out } of allTiers()) {
    const declared = {};
    for (const line of out.files['providers/proxmox/inventory'].split(/\r?\n/)) {
      const m = /^\s*(\S+)\s+ansible_host=\{\{ip_range\}\}\.(\d{1,3})\b/.exec(line);
      if (m) declared[m[1]] = Number(m[2]);
    }
    assert.ok(Object.keys(declared).length > 0, `${key}: the provider inventory names no hosts`);
    for (const host of out.ir.hosts) {
      assert.strictEqual(host.ipOctet, declared[host.key],
        `${key}: ${host.key} (${host.hostname}) is addressed at .${declared[host.key]} by ansible `
        + `and carries ipOctet ${host.ipOctet} on the IR`);
      assert.ok(Number.isInteger(host.ipOctet) && host.ipOctet >= 2 && host.ipOctet <= 254);
    }
  }
});

test('B18-106 a register named the way a REAL client names it keeps its own controller', () => {
  // THE real-client intake case, and the one the predicate used to get wrong.
  // Both generated hostname themes render a controller hyphen-delimited
  // (`dc-01`, `tuc-dc-01`), which is the only shape `\\bdc\\b` can see; a client
  // typing their own register writes SVO-DC01, HQDC1, ADDC01, where the digit
  // eats the trailing word boundary. The register's actual controller was then
  // adopted as a MEMBER, the forest minted SONORAN-DC01 for the controller slot
  // nobody had filled, and the bake's golden templates carried a name the
  // deploy spec never asks for — BAKE_GOLDEN_UNMATCHED, ~90 minutes in.
  const out = compile.compileLab(REGISTERED({
    assets: [
      { hostname: 'SVO-DC01', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
      { hostname: 'HQDC1', role: 'server', os: 'Windows Server 2019', services: ['389/LDAP'] },
      { hostname: 'FS-DCOM01', role: 'server', os: 'Windows Server 2016', services: ['445/SMB'] },
      { hostname: 'WEB-01', role: 'server', os: 'Windows Server 2019', services: ['80/HTTP'] },
    ],
  }));

  const hosts = out.ir.hosts;
  assert.deepStrictEqual(hosts.map((h) => h.hostname), ['SVO-DC01', 'HQDC1', 'FS-DCOM01'],
    'every forest host is a machine the client\'s own register names');

  const byName = Object.fromEntries(hosts.map((h) => [h.hostname, h.type]));
  assert.strictEqual(byName['SVO-DC01'], 'dc', 'the client\'s controller is the lab\'s controller');
  assert.strictEqual(byName['HQDC1'], 'dc', 'and so is the one with no separator at all');
  assert.notStrictEqual(byName['FS-DCOM01'], 'dc',
    'FS-DCOM01 carries a DC substring and is a member server — promoting it would silently '
    + 'change the forest the answer key was written against');

  // The warning is the tell. It fires once per forest host the register could
  // not name, so a register that fits and is READ correctly produces none; when
  // the controller was mis-filed, the mint had to invent a controller name and
  // this warning named it in the POST /bake 202 body.
  assert.ok(!out.warnings.some((w) => w.code === 'CIAB_LAB_HOST_NOT_ON_PAPER'),
    `the register named every host, so nothing is minted: ${JSON.stringify(out.warnings)}`);
  assert.ok(!out.warnings.some((w) => w.code === 'CIAB_PAPER_SERVER_NOT_IN_FOREST'));

  // And the emitted lab carries them, because that is the file the bake names
  // its golden templates after.
  const lab = JSON.parse(out.files['data/config.json']).lab;
  assert.deepStrictEqual(Object.values(lab.hosts).map((h) => h.hostname),
    ['SVO-DC01', 'HQDC1', 'FS-DCOM01']);
  for (const d of Object.values(lab.domains)) {
    // `domains[].dc` is a host KEY, so it is resolved through lab.hosts: the
    // machine that dcpromos each domain has to be one of the two the client
    // named, or the lane serves a directory off a host the paper calls a member.
    for (const key of [].concat(d.dc || [])) {
      const host = lab.hosts[key];
      assert.ok(host, `domain ${d.fqdn} names host key ${key}, which the lab does not define`);
      assert.match(host.hostname, /^(SVO-DC01|HQDC1)$/,
        `a domain is served by ${host.hostname}, which is not one of the register's controllers`);
    }
  }
});

test('B18-107 the compiler and validateSizing read the register with ONE predicate', () => {
  // goad-lab-compile splits the register into controller and member pools;
  // validators.js/validateSizing (S-01, S-02) strips and trims controllers off
  // the same register before it is ever printed. The two used to hold
  // byte-identical copies of the test, and a copy is a thing that drifts: a
  // machine one side demotes and the other adopts as a DC is a lab whose paper
  // and forest disagree about which host runs the directory, discovered at
  // BAKE_GOLDEN_UNMATCHED. The corpus that holds the two answers together lives
  // in ciab-dc-name-predicate.test.js; this pins that this file's side of it is
  // the shared function and not a third opinion.
  const { isDcRecord } = require(P('ai/profile/dc-name.js'));
  assert.strictEqual(compile.isPaperDc, isDcRecord,
    'goad-lab-compile must classify with ai/profile/dc-name.js itself');

  const src = require('fs').readFileSync(P('utils/goad-lab-compile.js'), 'utf8');
  assert.ok(!src.includes('\\bdc\\b'), 'no private copy of the predicate may survive here');
});
