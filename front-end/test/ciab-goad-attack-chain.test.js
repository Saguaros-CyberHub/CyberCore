/**
 * ciab-goad-attack-chain.test.js — Track I3: the ACL graph-shape designer.
 *
 * WHAT THIS FILE IS DEFENDING
 * The generator's whole claim is that two clients get two different labs. For
 * the AD half of the lab that claim is false unless the GRAPH differs, because
 * the graph is what BloodHound draws and what a repeat student remembers. All
 * three chassis descend from the same 12-edge ladder — GOAD-Mini is GOAD's
 * sevenkingdoms block with the other domains deleted, GOAD-Light is that ladder
 * renamed — so "inherit the chassis and rename the users" produces the identical
 * exercise every time. The assertions below are about SHAPE (length, branching,
 * which right at which depth, terminus, decoys, entry) precisely because the
 * cheap version of this component would pass a names-only test.
 *
 * THE OTHER HALF IS THE VOCABULARY, AND IT FAILS SILENTLY
 * roles/acl and roles/vulns/acls each embed their own $aclExtendValues literal
 * and they DISAGREE: the domain role carries Ext-ManageCA and Ext-Write-SPN, the
 * host role does not. Matching is .NET Array.Contains with the ordinal
 * comparer, so 'genericall', 'GENERICALL' and a host-context Ext-ManageCA all
 * write NO ACE while the Ansible task reports GREEN. There is no downstream
 * signal at all. That is why the tests here demand a compile ERROR for a bad
 * right and check the two vocabularies separately — a test that accepted a
 * warning would be asserting the wrong thing about the most dangerous field in
 * the system.
 *
 * `inheritance` is checked separately on purpose: it goes through an enum cast
 * that THROWS, so its failure mode is the opposite one. Folding the two checks
 * together is the refactor this file exists to block.
 *
 * Run: node --test front-end/test/ciab-goad-attack-chain.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'modules/crucible/plugins/ciab/utils');

const chain = require(path.join(UTILS, 'goad-attack-chain.js'));
const manifest = require(path.join(UTILS, 'goad-role-manifest.js'));
const probeModule = require(path.join(UTILS, 'goad-postcondition-probe.js'));

// ── fixture ────────────────────────────────────────────────────────────────
// A composer-shaped labIR: principals only, no chain, no acls. Generous enough
// that the length clamp never fires, so a short chain in a result is a DESIGN
// decision rather than a pool limit.

const FQDN = 'northgate.example';
const ROOT_DN = 'DC=northgate,DC=example';

const USER_NAMES = [
  'amara.velez', 'brian.olusola', 'cara.nguyen', 'derek.mbeki', 'elena.rossi',
  'farid.haddad', 'greta.lindqvist', 'hugo.martins', 'ines.okafor', 'jonas.petrov',
  'kiara.dsouza', 'lucas.moreau',
];
const GROUP_NAMES = [
  'ITOps', 'HelpDesk', 'Finance', 'ProjectAtlas', 'BackupOperatorsLite',
  'FacilitiesLeads', 'AuditReviewers',
];

function fixture(overrides) {
  const ir = {
    tier: 'M',
    lab_name: 'CIAB-abcdef12',
    domains: [{
      fqdn: FQDN,
      netbios: 'NORTHGATE',
      dc_host_key: 'dc01',
      is_forest_root: true,
      parent_fqdn: null,
      trust_fqdn: null,
    }],
    hosts: [
      { key: 'dc01', hostname: 'NG-DC01', type: 'dc', domain: FQDN, path: ROOT_DN, roles: [] },
      {
        key: 'srv02', hostname: 'NG-SRV02', type: 'server', domain: FQDN,
        path: `OU=Servers,${ROOT_DN}`, roles: [],
      },
      {
        key: 'web01', hostname: 'NG-WEB01', type: 'server', domain: FQDN,
        path: `OU=Servers,${ROOT_DN}`, roles: ['web'],
      },
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
      })),
      groups: GROUP_NAMES.map((name) => ({
        name, scope: 'global', path: `OU=Groups,${ROOT_DN}`, domain: FQDN,
        managed_by: null, members: [],
      })),
      ous: [
        { name: 'Staff', path: ROOT_DN, domain: FQDN },
        { name: 'Groups', path: ROOT_DN, domain: FQDN },
      ],
    },
  };
  return Object.assign(ir, overrides || {});
}

function design(seed, overrides) {
  return chain.designAttackChain(fixture(Object.assign({ run_id: seed }, overrides || {})),
    { runId: seed });
}

/** A spread of seeds, used wherever a property must hold for every design
 *  rather than for one lucky one. */
const SEEDS = [
  'seed-one', 'seed-two', 'alpha', 'bravo', 'charlie', 'delta', 'echo', 'foxtrot',
  'golf', 'hotel', 's1', 's2', 's3', 's4', 's5', 's6', 's7', 's8', 's9', 's10',
  's11', 's12', 's13', 's14', 's15',
];

// ── 1. shape varies, and it is the SHAPE that varies ───────────────────────

test('two seeds differ in length, branching factor AND terminus', () => {
  // Pinned seeds, not a scan: the claim is that a specific pair of clients get
  // structurally different labs, and a scan that searched for a differing pair
  // would pass even if 24 of 25 seeds were identical.
  const a = design('golf').chain.signature;
  const b = design('delta').chain.signature;

  assert.notStrictEqual(a.length, b.length, 'chain length must differ');
  assert.notStrictEqual(a.branching_factor, b.branching_factor,
    'branching factor must differ - one funnel, one branched');
  assert.notStrictEqual(a.terminus, b.terminus, 'the objective must differ');
  // And the differences are not cosmetic re-labelling of one graph.
  assert.notDeepStrictEqual(a.rights, b.rights);
  assert.notDeepStrictEqual(a.edge_types, b.edge_types);
});

test('every shape axis actually moves across seeds', () => {
  const seen = {
    length: new Set(), branching: new Set(), terminus: new Set(),
    entry: new Set(), pattern: new Set(), decoys: new Set(),
  };
  for (const seed of SEEDS) {
    const sig = design(seed).chain.signature;
    seen.length.add(sig.length);
    seen.branching.add(sig.branching);
    seen.terminus.add(sig.terminus);
    seen.entry.add(sig.entry);
    seen.pattern.add(sig.pattern);
    seen.decoys.add(sig.decoys);
  }
  // Every axis the module claims to vary must be observably varying. A single
  // frozen axis is how a generator quietly becomes a template again.
  assert.ok(seen.length.size >= 4, `only ${seen.length.size} distinct lengths`);
  assert.deepStrictEqual(Array.from(seen.branching).sort(),
    chain.BRANCHINGS.slice().sort(), 'all three branchings must occur');
  assert.deepStrictEqual(Array.from(seen.terminus).sort(),
    chain.TERMINUS_KINDS.slice().sort(), 'all four termini must occur');
  assert.deepStrictEqual(Array.from(seen.entry).sort(),
    chain.ENTRY_POINTS.slice().sort(),
    'all seven entry points must occur - the entry is what changes the first thirty minutes');
  assert.deepStrictEqual(Array.from(seen.pattern).sort(),
    chain.PATTERNS.slice().sort(), 'all three curated patterns must occur');
  assert.ok(seen.decoys.size >= 2, 'decoy count must vary');
});

test('chain length stays inside the shippable band', () => {
  for (const seed of SEEDS) {
    const c = design(seed).chain;
    assert.ok(c.length >= chain.MIN_LENGTH && c.length <= chain.MAX_LENGTH,
      `${seed}: length ${c.length} outside ${chain.MIN_LENGTH}..${chain.MAX_LENGTH}`);
  }
});

test('a branched design really branches, and both routes are the same length', () => {
  const branched = SEEDS.map(design).map((d) => d.chain)
    .filter((c) => c.shape.branching !== 'funnel');
  assert.ok(branched.length > 0, 'no branched design in the sample');
  for (const c of branched) {
    assert.strictEqual(c.signature.branching_factor, 2,
      'a branched chain must have a node with two outbound edges');
    // An alternate route one hop shorter is not a branch, it is a shortcut, and
    // it would make every edge on the long side decoration.
    assert.strictEqual(
      chain.shortestPath(c.edges, c.start.principal, c.objective.target), c.length,
      'the branch must not shorten the walk');
  }
  const funnels = SEEDS.map(design).map((d) => d.chain)
    .filter((c) => c.shape.branching === 'funnel');
  for (const c of funnels) {
    assert.strictEqual(c.signature.branching_factor, 1);
  }
});

// ── 2. never the inherited ladder ──────────────────────────────────────────

test('the emitted graph is never the chassis 12-edge ladder', () => {
  // The ladder is the thing being escaped, so pin what it is first. These are
  // the twelve rights of ad/GOAD-Mini sevenkingdoms.local (and, renamed,
  // GOAD-Light cybersaguaros.local) at the pinned ref.
  assert.strictEqual(chain.CHASSIS_LADDER_RIGHTS.length, 12);
  assert.strictEqual(chain.CHASSIS_LADDER_RIGHTS[0], 'Ext-User-Force-Change-Password');
  assert.strictEqual(chain.CHASSIS_LADDER_RIGHTS[3], 'Ext-Self-Self-Membership');

  for (const seed of SEEDS) {
    const c = design(seed).chain;
    assert.ok(!chain.isChassisLadder(c), `${seed} re-emitted the chassis ladder`);
  }

  // The detector is not vacuous: hand it the ladder and it says so. A prefix
  // counts, because a generated chain is at most nine hops and an inherited
  // ladder shows up as the first N of the twelve.
  const ladder = {
    edges: chain.CHASSIS_LADDER_RIGHTS.slice(0, 6).map((right, i) => ({
      id: `e${i}`, edge_type: 'acl', right, spine: true,
    })),
  };
  assert.ok(chain.isChassisLadder(ladder), 'a six-hop ladder prefix must be detected');
});

test('the right at a given depth is not fixed across seeds', () => {
  // The chassis always opens with ForceChangePassword and ends with GenericAll.
  // If our depth-0 right were also constant, the graph would still be the same
  // exercise however long it is.
  const depth0 = new Set();
  const depth1 = new Set();
  for (const seed of SEEDS) {
    const edges = design(seed).chain.edges.filter((e) => e.spine && e.edge_type === 'acl');
    if (edges[0]) depth0.add(edges[0].right);
    if (edges[1]) depth1.add(edges[1].right);
  }
  assert.ok(depth0.size >= 3, `depth 0 only ever used ${Array.from(depth0).join(', ')}`);
  assert.ok(depth1.size >= 3, `depth 1 only ever used ${Array.from(depth1).join(', ')}`);
});

// ── 3. every edge is producible, with the exact keys the role reads ────────

test('every edge and prerequisite names a producer that can actually make it', () => {
  for (const seed of SEEDS) {
    const c = design(seed).chain;
    const producible = [];
    for (const edge of c.edges.concat(c.decoys)) {
      producible.push([edge.id, edge.created_by]);
      for (const pre of (edge.prerequisites || [])) producible.push([edge.id, pre]);
    }
    for (const plant of c.start.plants) {
      if (plant.role) producible.push([plant.kind, plant]);
    }

    for (const [id, created] of producible) {
      const spec = chain.PRODUCERS[created.role];
      assert.ok(spec, `${seed}/${id}: producer '${created.role}' is not in PRODUCERS`);
      // Never throws for a well-formed design; this is the same guard the
      // designer runs, asserted from outside so a regression cannot hide behind
      // a silently-skipped internal call.
      assert.doesNotThrow(() => chain.assertProducer(created, id));

      if (spec.kind === 'manifest') {
        const role = manifest.getRole(spec.role);
        assert.ok(role, `${seed}/${id}: '${spec.role}' is not in the vendored manifest`);
        assert.strictEqual(role.never_emit, false,
          `${seed}/${id}: '${spec.role}' is never_emit - it reports green and plants nothing`);
        const have = Object.keys(created.item_vars || {});
        for (const key of role.required_item_keys) {
          assert.ok(have.indexOf(key) !== -1,
            `${seed}/${id}: '${spec.role}' reads item.value.${key}, which the edge does not supply`);
        }
      }
      if (created.role === 'acl') {
        // The four keys roles/acl passes into its own PowerShell `parameters:`
        // block, read off the manifest rather than typed out here.
        assert.deepStrictEqual(Object.keys(created.item_vars).sort(), chain.ACL_ITEM_KEYS.slice(),
          `${seed}/${id}: an ad_acls item must carry exactly ${chain.ACL_ITEM_KEYS.join('/')}`);
      }
    }
  }
});

test('no producer this designer can name is a never_emit role', () => {
  // vulns/shares and vulns/adcs_esc7 are structurally broken upstream and report
  // green, so an edge built on one would be a guaranteed silent no-op. The
  // module asserts this at require() time; asserting it again here means a
  // future PRODUCERS entry cannot slip past a load that happened to be cached.
  assert.doesNotThrow(() => chain.assertProducersAreEmittable());
  for (const key of Object.keys(chain.PRODUCERS)) {
    const spec = chain.PRODUCERS[key];
    if (spec.kind !== 'manifest') continue;
    assert.strictEqual(manifest.isNeverEmit(spec.role), false, `${key} is never_emit`);
  }
});

test('a never_emit or invented producer is a compile error', () => {
  assert.throws(
    () => chain.assertProducer({ role: 'vulns/shares', item_vars: { path: 'C:\\x' } }, 'e0'),
    (err) => err.code === 'EDGE_ROLE_NEVER_EMIT');
  assert.throws(
    () => chain.assertProducer({ role: 'vulns/not_a_role', item_vars: {} }, 'e0'),
    (err) => err.code === 'EDGE_ROLE_UNKNOWN');
  assert.throws(
    () => chain.assertProducer({ role: 'vulns/files', item_vars: { src: 'a' } }, 'e0'),
    (err) => err.code === 'EDGE_ROLE_MISSING_KEYS');
});

// ── 4/5. the two ACL vocabularies, kept apart ──────────────────────────────

test('a miscased right is a COMPILE ERROR, not a warning', () => {
  // Upstream: `$aclValues.contains($right)` is Array.Contains with the ordinal
  // comparer. 'genericall' matches nothing, $ace is never assigned, the task
  // sets Changed=$false, and Ansible prints GREEN. Nothing downstream will ever
  // report it, so this has to be fatal at generation time.
  assert.throws(() => chain.assertAclRight('genericall', 'domain', 'e0'), (err) => {
    assert.strictEqual(err.code, 'ACL_RIGHT_MISCASED');
    assert.strictEqual(err.status, 409);
    assert.match(err.message, /GenericAll/, 'the message must name the correct spelling');
    assert.match(err.message, /green/i, 'the message must say why silence is the danger');
    return true;
  });
  assert.throws(() => chain.assertAclRight('GENERICALL', 'domain', 'e0'),
    (err) => err.code === 'ACL_RIGHT_MISCASED');
  assert.throws(() => chain.assertAclRight('WriteDACL', 'domain', 'e0'),
    (err) => err.code === 'ACL_RIGHT_MISCASED');
  assert.throws(() => chain.assertAclRight('GenericAllTheThings', 'domain', 'e0'),
    (err) => err.code === 'ACL_RIGHT_UNKNOWN');
  assert.throws(() => chain.assertAclRight('', 'domain', 'e0'),
    (err) => err.code === 'ACL_RIGHT_MISSING');
  // Correct spelling passes through unchanged - the guard normalises nothing,
  // because normalising is exactly what makes a bad string ship.
  assert.strictEqual(chain.assertAclRight('GenericAll', 'domain', 'e0'), 'GenericAll');
});

test('a domain-only extended right in a host context is a compile error', () => {
  // The two roles embed SEPARATE $aclExtendValues literals. roles/acl has five
  // extended rights, roles/vulns/acls has three, and the two it lacks are
  // exactly these. Feeding one to the host role writes no ACE and reports green.
  const domain = manifest.aclRights('domain');
  const host = manifest.aclRights('host');
  assert.strictEqual(domain.extended.length, 5);
  assert.strictEqual(host.extended.length, 3);
  assert.deepStrictEqual(domain.standard, host.standard,
    'the 19 standard rights are shared; only the extended lists differ');

  for (const right of ['Ext-ManageCA', 'Ext-Write-SPN']) {
    assert.ok(domain.extended.indexOf(right) !== -1, `${right} must be a domain right`);
    assert.strictEqual(host.extended.indexOf(right), -1, `${right} must NOT be a host right`);
    assert.strictEqual(chain.assertAclRight(right, 'domain', 'e0'), right);
    assert.throws(() => chain.assertAclRight(right, 'host', 'e0'), (err) => {
      assert.strictEqual(err.code, 'ACL_RIGHT_WRONG_CONTEXT');
      assert.match(err.message, /vulns\/acls/);
      return true;
    });
  }
  // The catalog's own domain_only flags are derived from the manifest, never
  // hardcoded, so a re-vendor that moved a right cannot leave them stale.
  assert.doesNotThrow(() => chain.assertCatalogMatchesManifest());
  assert.strictEqual(chain.RIGHT_CATALOG['Ext-ManageCA'].domain_only, true);
  assert.strictEqual(chain.RIGHT_CATALOG.GenericAll.domain_only, false);
});

test('the designer never emits a domain-only right where it cannot land', () => {
  for (const seed of SEEDS) {
    const c = design(seed).chain;
    for (const edge of c.edges.concat(c.decoys)) {
      if (edge.edge_type !== 'acl') continue;
      assert.ok(manifest.isAclRight(edge.right, 'domain'),
        `${seed}/${edge.id}: '${edge.right}' is not in the domain vocabulary`);
      // Ext-ManageCA is only meaningful on a CA's computer object, so it is
      // never placed on an arbitrary chain hop.
      assert.notStrictEqual(edge.right, 'Ext-ManageCA',
        `${seed}/${edge.id}: ESC7 needs the CA's own object, not an arbitrary hop`);
      // A targeted Kerberoast is only walkable if the target's hash cracks.
      if (edge.right === 'Ext-Write-SPN') {
        assert.strictEqual(edge.target_kind, 'user',
          'an SPN written onto a computer yields an uncrackable machine hash');
        const pre = (edge.prerequisites || [])
          .filter((p) => p.role === 'onlyusers' && p.item_vars.password);
        assert.strictEqual(pre.length, 1,
          `${seed}/${edge.id}: Ext-Write-SPN must plant a crackable password on the target`);
        assert.ok(chain.CRACKABLE_PASSWORDS.indexOf(pre[0].item_vars.password) !== -1);
      }
    }
  }
});

test('inheritance fails the OPPOSITE way, and is validated separately', () => {
  // $inheritance goes through an ActiveDirectorySecurityInheritance cast: the
  // cast is case-INSENSITIVE and THROWS on an unknown value. So the failure is
  // loud on the lane rather than silent - but 'Descendants' still dies, because
  // Microsoft spells it 'Descendents'.
  assert.deepStrictEqual(chain.INHERITANCE_VALUES,
    manifest.loadManifest().acl_inheritance.values);
  assert.strictEqual(chain.assertInheritance('All', 'e0'), 'All');
  assert.strictEqual(chain.assertInheritance('descendents', 'e0'), 'Descendents',
    'the cast is case-insensitive, so a case variant normalises rather than failing');
  assert.throws(() => chain.assertInheritance('Descendants', 'e0'), (err) => {
    assert.strictEqual(err.code, 'ACL_INHERITANCE_UNKNOWN');
    assert.match(err.message, /Descendents/, 'the message must give the correct spelling');
    return true;
  });
  assert.throws(() => chain.assertInheritance('Yes', 'e0'),
    (err) => err.code === 'ACL_INHERITANCE_UNKNOWN');

  // And the value the designer chooses is meaningful, not decorative: an ACE on
  // a container with inheritance None grants control of the container object and
  // nothing inside it, which is the whole point of an OU terminus.
  assert.strictEqual(chain.inheritanceFor('ou'), 'All');
  assert.strictEqual(chain.inheritanceFor('container'), 'All');
  assert.strictEqual(chain.inheritanceFor('user'), 'None');
  for (const seed of SEEDS) {
    for (const edge of design(seed).chain.edges) {
      if (edge.edge_type !== 'acl') continue;
      assert.ok(chain.INHERITANCE_VALUES.indexOf(edge.inheritance) !== -1);
      assert.strictEqual(edge.inheritance, chain.inheritanceFor(edge.target_kind));
    }
  }
});

// ── 6. solvability is a proof ──────────────────────────────────────────────

test('an unsolvable chain is rejected, naming the broken link', () => {
  const designed = design('golf');
  const pool = chain.indexPrincipals(fixture().principals, FQDN);

  // A well-formed design proves out and returns the hop count.
  assert.strictEqual(
    chain.proveSolvable(designed.chain, designed.foothold_credential, pool),
    designed.chain.length);

  // Cut one link: edge 1 now starts at a principal nothing leads to.
  const broken = JSON.parse(JSON.stringify(designed.chain));
  broken.edges[1].from = 'nobody.here';
  assert.throws(
    () => chain.proveSolvable(broken, designed.foothold_credential, pool),
    (err) => {
      assert.strictEqual(err.code, 'CHAIN_UNSOLVABLE');
      assert.strictEqual(err.link, broken.edges[1].id,
        'the error must name the edge the walk cannot reach');
      assert.match(err.message, /nobody\.here/,
        'the message must name the principal nothing leads to');
      return true;
    });

  // Nothing rooted at the foothold at all.
  const unrooted = JSON.parse(JSON.stringify(designed.chain));
  unrooted.edges[0].from = 'someone.else';
  assert.throws(() => chain.proveSolvable(unrooted, designed.foothold_credential, pool),
    (err) => err.code === 'CHAIN_START_NOT_ROOTED');
});

test('the foothold is the seam: AD must create it and the web side must plant it', () => {
  const designed = design('delta');
  const pool = chain.indexPrincipals(fixture().principals, FQDN);
  const { chain: c, foothold_credential: foothold } = designed;

  assert.strictEqual(foothold.domain, FQDN);
  assert.strictEqual(foothold.honoured_by, 'ad');
  assert.strictEqual(c.start.principal, foothold.sam);
  assert.ok(foothold.planted_at.path && foothold.planted_at.format);
  assert.ok(USER_NAMES.indexOf(foothold.sam) !== -1, 'the foothold must be a principal AD creates');

  // A credential AD does not create.
  assert.throws(
    () => chain.assertFootholdContract(c, Object.assign({}, foothold, { sam: 'ghost.user' }), pool),
    (err) => err.code === 'FOOTHOLD_NOT_IN_AD');
  // A start that references something else.
  const drifted = JSON.parse(JSON.stringify(c));
  drifted.start.principal = 'brian.olusola';
  assert.throws(() => chain.assertFootholdContract(drifted, foothold, pool),
    (err) => err.code === 'CHAIN_START_NOT_FOOTHOLD');
  // The two halves disagreeing about the password: both green, login broken.
  const mismatched = JSON.parse(JSON.stringify(c));
  for (const plant of mismatched.start.plants) {
    if (plant.kind === 'ad_password') plant.item_vars.password = 'Something-Else-99';
  }
  assert.throws(() => chain.assertFootholdContract(mismatched, foothold, pool),
    (err) => err.code === 'FOOTHOLD_NOT_HONOURED');
  // Never below GOAD's own MinPasswordLength=5 (ansible/ad-data.yml).
  assert.throws(
    () => chain.assertFootholdContract(c, Object.assign({}, foothold, { password: 'abc' }), pool),
    (err) => err.code === 'FOOTHOLD_PASSWORD_TOO_SHORT');

  for (const seed of SEEDS) {
    const d = design(seed);
    assert.ok(String(d.foothold_credential.password).length >= chain.POLICY_MIN_PASSWORD_LEN);
    const honoured = d.chain.start.plants.filter(
      (p) => p.kind === 'ad_password' && p.item_vars.password === d.foothold_credential.password);
    assert.strictEqual(honoured.length, 1, `${seed}: exactly one ad_password plant must honour it`);
  }
});

test('a pool too small to carry a chain is rejected rather than faked', () => {
  const tiny = fixture({ run_id: 'golf' });
  tiny.principals.users = tiny.principals.users.slice(0, 1);
  tiny.principals.groups = [];
  assert.throws(() => chain.designAttackChain(tiny, { runId: 'golf' }),
    (err) => err.code === 'PRINCIPAL_POOL_TOO_SMALL');
});

test('a design with no seed is rejected: reproducibility is the contract', () => {
  const seedless = fixture();
  delete seedless.run_id;
  assert.throws(() => chain.designAttackChain(seedless, {}),
    (err) => err.code === 'CHAIN_NO_SEED');
});

// ── 7. the unintended-shortcut assertions ──────────────────────────────────

test('a clean design has no unintended shortcuts', () => {
  for (const seed of SEEDS) {
    const d = design(seed);
    const ir = fixture({ run_id: seed, acls: d.acls });
    assert.deepStrictEqual(chain.findUnintendedShortcuts(ir, d.chain), [],
      `${seed} produced a shortcut`);
  }
});

test('the shortcut assertions fire on a deliberately over-permissive fixture', () => {
  // `delta` is an acl_ladder design, so it declares no broad principal of its
  // own - anything the checks find below is genuinely the fixture's fault.
  const designed = design('delta');
  assert.deepStrictEqual(designed.chain.declared_broad_principals, []);

  const over = fixture({ run_id: 'delta' });
  // (a) a nested membership that starts a principal inside the endgame
  over.principals.users[3].groups = ['HelpDesk'];
  over.principals.groups.push({
    name: 'Domain Admins', scope: 'global', path: '', domain: FQDN, members: ['HelpDesk'],
  });
  // (b) two accounts sharing a password - an edge BloodHound cannot draw
  over.principals.users[5].password = over.principals.users[6].password;
  // (c) an ACE naming a principal every student already holds
  over.acls = {
    [FQDN]: Object.assign({}, designed.acls[FQDN], {
      helpful_it_grant: {
        for: 'Domain Users', to: 'Domain Admins', right: 'GenericAll', inheritance: 'None',
      },
    }),
  };

  const codes = chain.findUnintendedShortcuts(over, designed.chain).map((f) => f.code);
  assert.ok(codes.indexOf('SHORTCUT_PRIVILEGED_MEMBERSHIP') !== -1,
    'a nested route into Domain Admins must be caught');
  assert.ok(codes.indexOf('SHORTCUT_SHARED_PASSWORD') !== -1,
    'password reuse must be caught');
  assert.ok(codes.indexOf('SHORTCUT_BROAD_PRINCIPAL_ACL') !== -1,
    'an ACE for Domain Users must be caught');

  assert.throws(() => chain.assertNoUnintendedShortcuts(over, designed.chain), (err) => {
    assert.strictEqual(err.code, 'CHAIN_HAS_SHORTCUTS');
    assert.ok(Array.isArray(err.findings) && err.findings.length >= 3);
    return true;
  });
});

test('a nested group that short-circuits the designed path is caught', () => {
  // The subtle one: nobody writes "give the foothold the endgame". They put the
  // foothold in a group, and the group happens to be a later node in the chain.
  const designed = design('seed-two');
  const late = designed.chain.edges.filter((e) => e.spine && e.target_kind === 'group')
    .slice(-1)[0];
  assert.ok(late, 'seed-two must have a group somewhere on its spine');

  const over = fixture({ run_id: 'seed-two', acls: designed.acls });
  over.principals.users.find((u) => u.sam === designed.foothold_credential.sam)
    .groups = [late.to];
  const codes = chain.findUnintendedShortcuts(over, designed.chain).map((f) => f.code);
  assert.ok(codes.indexOf('SHORTCUT_MEMBERSHIP_BYPASS') !== -1,
    `membership in '${late.to}' must be caught as a bypass of the designed path`);
});

test('a declared shortcut is allowed, an undeclared identical one is not', () => {
  // The anonymous_rpc entry NEEDS an ACE for NT AUTHORITY\ANONYMOUS LOGON: it is
  // the entrance, not an accident. The rule is "declared or rejected", never
  // "sometimes ignored".
  const anon = SEEDS.map((s) => design(s))
    .filter((d) => d.chain.shape.entry === 'anonymous_rpc')[0];
  assert.ok(anon, 'no anonymous_rpc design in the sample');
  assert.ok(anon.chain.declared_broad_principals.indexOf('NT AUTHORITY\\ANONYMOUS LOGON') !== -1);
  const ir = fixture({ run_id: 'x', acls: anon.acls });
  assert.deepStrictEqual(chain.findUnintendedShortcuts(ir, anon.chain), []);

  // Same ACLs, nothing declared: now it is a finding.
  const undeclared = JSON.parse(JSON.stringify(anon.chain));
  undeclared.declared_broad_principals = [];
  const codes = chain.findUnintendedShortcuts(ir, undeclared).map((f) => f.code);
  assert.ok(codes.indexOf('SHORTCUT_BROAD_PRINCIPAL_ACL') !== -1);
});

// ── decoys ─────────────────────────────────────────────────────────────────

test('every decoy is a real ACE that genuinely dead-ends', () => {
  let sawDeadGroup = false;
  for (const seed of SEEDS) {
    const d = design(seed);
    const c = d.chain;
    assert.ok(c.decoys.length >= 1, `${seed}: a graph of 100% signal teaches "follow the arrows"`);
    for (const decoy of c.decoys) {
      // Real: it is lowered into labIR.acls, so it deploys and BloodHound
      // collects it. A "decoy" that is not written is not in the picture at all.
      assert.ok(c.domain in d.acls);
      assert.ok(d.acls[c.domain][decoy.created_by.item],
        `${seed}/${decoy.id}: decoy is not lowered into the ACL table`);
      assert.ok(decoy.dead_ends_because && decoy.dead_ends_because.length > 30,
        `${seed}/${decoy.id}: a decoy needs a stateable reason for the answer key`);
      assert.strictEqual(decoy.spine, false);
      if (/dead_group/.test(decoy.id)) sawDeadGroup = true;
    }
    // And none of them shortens the walk.
    const withDecoys = c.edges.concat(c.decoys);
    assert.strictEqual(
      chain.shortestPath(withDecoys, c.start.principal, c.objective.target), c.length,
      `${seed}: a decoy shortened the intended path`);
  }
  assert.ok(sawDeadGroup,
    'the GOAD-Light F-07 / GOAD-Mini F-08 memberless-group decoy must appear somewhere');
});

test('a live decoy is caught as a second solution', () => {
  const designed = design('delta');
  const c = JSON.parse(JSON.stringify(designed.chain));
  // Re-point a decoy so the foothold can enter it AND it reaches the objective.
  c.decoys[0].from = c.start.principal;
  c.decoys[0].to = c.objective.target;
  const codes = chain.findUnintendedShortcuts(fixture({ acls: designed.acls }), c)
    .map((f) => f.code);
  assert.ok(codes.indexOf('SHORTCUT_DECOY_LIVE') !== -1
    || codes.indexOf('SHORTCUT_MEMBERSHIP_BYPASS') !== -1,
  'a decoy that is both reachable and productive is a second solution, not a decoy');
});

// ── evidence probes ────────────────────────────────────────────────────────

test('every edge carries an evidence_probe the real probe builder accepts', () => {
  for (const seed of SEEDS) {
    const d = design(seed);
    const c = d.chain;
    const extra = c.edges.concat(c.decoys).map((e) => e.evidence_probe)
      .concat(c.start.plants.map((p) => p.evidence_probe).filter(Boolean));
    for (const check of extra) {
      assert.ok(check, `${seed}: an edge shipped with no evidence_probe`);
      assert.ok(probeModule.CHECK_KINDS.indexOf(check.kind) !== -1,
        `${seed}: check kind '${check.kind}' is not implemented by the probe script`);
      assert.ok(check.run_on, `${seed}: check '${check.id}' has no run_on host`);
      assert.ok(d.chain.edges.length > 0);
    }
    // buildExpectationSet throws on an unknown kind or a missing id/run_on, so
    // this is the real acceptance test rather than a shape guess.
    const set = probeModule.buildExpectationSet({ domains: {}, hosts: {} },
      { extra, labName: c.lab_name });
    assert.strictEqual(set.checks.length, extra.length);
    assert.deepStrictEqual(set.warnings, []);
    // A password must never reach the staged expectation file: it lands in
    // C:\Windows\Temp, which any authenticated user can traverse. The one
    // exemption is the sam-is-the-password entry - see the dedicated test below
    // for why it cannot be redacted and why that is not a weakening.
    const exempt = chain.probeSecretExemptions(d.foothold_credential);
    const secrets = [d.foothold_credential.password]
      .filter((secret) => exempt.indexOf(secret) === -1);
    assert.doesNotThrow(() => probeModule.assertNoSecrets(set, secrets));
  }
});

test('the sam-is-the-password entry is the one secret the probe cannot redact', () => {
  // Surfacing a genuine conflict between two modules rather than hiding it.
  // assertNoSecrets scans the staged expectation set for any lab secret. When
  // the password IS the sAMAccountName, that string is in every check - it is
  // the NAME of the object being asserted about - so the guard matches and would
  // refuse to probe the whole lab. Redaction is impossible (removing the sam
  // removes the check), so the runner drops that one value, and only that one.
  const spray = SEEDS.map(design)
    .filter((d) => d.chain.shape.entry === 'user_equals_password')[0];
  assert.ok(spray, 'no user_equals_password design in the sample');
  assert.strictEqual(spray.foothold_credential.password, spray.chain.start.principal);
  assert.deepStrictEqual(chain.probeSecretExemptions(spray.foothold_credential),
    [spray.foothold_credential.password]);

  const extra = spray.chain.edges.map((e) => e.evidence_probe);
  const set = probeModule.buildExpectationSet({ domains: {}, hosts: {} }, { extra });
  assert.throws(
    () => probeModule.assertNoSecrets(set, [spray.foothold_credential.password]),
    /lab secret/,
    'without the exemption the guard blocks the probe for the entire lab');
  assert.doesNotThrow(() => probeModule.assertNoSecrets(set, []));

  // Every other entry keeps the guard at full strength - the exemption is not
  // a general escape hatch.
  for (const seed of SEEDS) {
    const d = design(seed);
    if (d.chain.shape.entry === 'user_equals_password') continue;
    assert.deepStrictEqual(chain.probeSecretExemptions(d.foothold_credential), [],
      `${seed}: only the sam-is-the-password entry may exempt anything`);
  }
});

test('the declared vocabularies are exactly what gets emitted - nothing decorative', () => {
  const edgeTypes = new Set();
  const plantKinds = new Set();
  for (const seed of SEEDS) {
    const c = design(seed).chain;
    for (const edge of c.edges.concat(c.decoys)) {
      assert.ok(chain.EDGE_TYPES.indexOf(edge.edge_type) !== -1,
        `${seed}: edge type '${edge.edge_type}' is not in EDGE_TYPES`);
      edgeTypes.add(edge.edge_type);
    }
    for (const plant of c.start.plants) {
      assert.ok(chain.PLANT_KINDS.indexOf(plant.kind) !== -1,
        `${seed}: plant kind '${plant.kind}' is not in PLANT_KINDS`);
      plantKinds.add(plant.kind);
    }
  }
  // Both directions. A constant nothing emits is a branch nothing tests, and an
  // emitted value no constant declares is a producer nobody validated.
  assert.deepStrictEqual(Array.from(edgeTypes).sort(), chain.EDGE_TYPES.slice().sort());
  assert.deepStrictEqual(Array.from(plantKinds).sort(), chain.PLANT_KINDS.slice().sort());

  // Group membership is NOT an emittable edge, on purpose: it is composer-owned
  // data (principals.groups[].members), and two components writing one fact is
  // how the two halves end up disagreeing. It is still walked as an IMPLICIT
  // edge by the shortcut checks - see the nested-group test above.
  assert.strictEqual(chain.EDGE_TYPES.indexOf('group_member'), -1);
});

test('an evidence check the probe script cannot run is a compile error', () => {
  // The .ps1 reports an unknown kind as a FAILURE, not a skip, so shipping one
  // would read as a broken lab rather than a broken generator.
  assert.throws(
    () => chain.assertProbeKind({ id: 'x', kind: 'bloodhound', run_on: 'dc01' }, 'e0'),
    (err) => err.code === 'EVIDENCE_KIND_UNIMPLEMENTED');
  assert.throws(
    () => chain.assertProbeKind({ id: 'x', kind: 'acl' }, 'e0'),
    (err) => err.code === 'EVIDENCE_NO_RUN_ON');
  assert.doesNotThrow(
    () => chain.assertProbeKind({ id: 'x', kind: 'acl', run_on: 'dc01' }, 'e0'));
});

test('an ACL evidence_probe resolves the extended right to its ACE, GUID included', () => {
  const extended = [];
  for (const seed of SEEDS) {
    for (const edge of design(seed).chain.edges) {
      if (edge.edge_type === 'acl' && probeModule.EXTENDED_RIGHT_ACES[edge.right]) {
        extended.push(edge);
      }
    }
  }
  assert.ok(extended.length > 0, 'no extended right anywhere in the sample');
  for (const edge of extended) {
    const ace = probeModule.EXTENDED_RIGHT_ACES[edge.right];
    // An ExtendedRight ACE with the wrong ObjectType grants a different right
    // entirely, and a probe comparing only ActiveDirectoryRights would pass it.
    assert.strictEqual(edge.evidence_probe.ad_right, ace.ad_right);
    assert.strictEqual(edge.evidence_probe.object_type, ace.object_type);
    assert.strictEqual(edge.evidence_probe.known_right, true);
  }
});

// ── pattern-library invariants ─────────────────────────────────────────────

test('ESC1 sits at edge 0 or not at all', () => {
  // roles/vulns/adcs_templates publishes with -Identity "{{domain}}\Domain Users",
  // so every domain user can enrol. An ESC1 edge anywhere but the first hop is a
  // shortcut past everything before it.
  let sawEsc1 = false;
  for (const seed of SEEDS) {
    const c = design(seed).chain;
    c.edges.forEach((edge) => {
      if (edge.edge_type !== 'adcs_esc1') return;
      sawEsc1 = true;
      assert.strictEqual(edge.depth, 0, `${seed}: ESC1 at depth ${edge.depth} is a shortcut`);
      assert.strictEqual(edge.from, c.start.principal);
      assert.ok(c.declared_broad_principals.indexOf('Domain Users') !== -1,
        'a lab carrying ESC1 has a Domain Users grant by construction and must declare it');
      const pre = (edge.prerequisites || []).filter((p) => p.role === 'vulns/files');
      assert.strictEqual(pre.length, 1,
        'New-ADCSTemplate reads the template with Get-Content; nothing ships the file but files');
      assert.strictEqual(pre[0].item_vars.dest, edge.created_by.item_vars.template_file,
        'the delivered path and the published path must be the same path');
    });
    if (c.shape.pattern === 'adcs_esc1') {
      assert.notStrictEqual(c.shape.entry, 'kerberoast',
        'the entry cannot consume edge 0 when ESC1 must own it');
    }
  }
  assert.ok(sawEsc1, 'no ESC1 design in the sample');
});

test('delegation_abuse never ships on a tier with no member server', () => {
  // The abuse is a member server trusted for unconstrained delegation, coerced
  // by the DC. On tier S the only host IS the DC, so the pattern would degenerate
  // into "the DC delegates to itself" - which deploys and teaches nothing.
  const tierS = () => {
    const ir = fixture();
    ir.tier = 'S';
    ir.hosts = [ir.hosts[0]];
    return ir;
  };
  assert.deepStrictEqual(chain.PATTERNS.slice().sort(),
    ['acl_ladder', 'adcs_esc1', 'delegation_abuse']);
  for (const seed of SEEDS) {
    const ir = Object.assign(tierS(), { run_id: seed });
    const c = chain.designAttackChain(ir, { runId: seed }).chain;
    assert.notStrictEqual(c.shape.pattern, 'delegation_abuse',
      `${seed}: tier S has no member server to delegate through`);
    assert.strictEqual(
      chain.shortestPath(c.edges, c.start.principal, c.objective.target), c.length);
  }
  // On a tier with a member server it does appear, and it ends on the DC.
  const withMember = SEEDS.map(design).map((d) => d.chain)
    .filter((c) => c.shape.pattern === 'delegation_abuse');
  assert.ok(withMember.length > 0);
  for (const c of withMember) {
    assert.strictEqual(c.objective.kind, 'dc_computer');
    const last = c.edges.filter((e) => e.spine).slice(-1)[0];
    assert.strictEqual(last.edge_type, 'delegation');
    assert.strictEqual(last.to, 'NG-DC01$');
  }
});

test('the kerberoast entry plants an SPN and a wordlist password on the roasted account', () => {
  const roasts = SEEDS.map(design).filter((d) => d.chain.shape.entry === 'kerberoast');
  assert.ok(roasts.length > 0, 'no kerberoast design in the sample');
  for (const d of roasts) {
    const edge = d.chain.edges[0];
    assert.strictEqual(edge.edge_type, 'kerberoast');
    assert.strictEqual(edge.from, d.chain.start.principal);
    const vars = edge.created_by.item_vars;
    assert.ok(Array.isArray(vars.spns) && vars.spns.length === 1);
    assert.match(vars.spns[0], new RegExp(`/${edge.to}\\.${FQDN}$`));
    assert.ok(chain.CRACKABLE_PASSWORDS.indexOf(vars.password) !== -1,
      'a roastable account with an uncrackable password is a dead edge');
    assert.strictEqual(edge.evidence_probe.kind, 'kerberoast');
    assert.deepStrictEqual(edge.evidence_probe.spns, vars.spns);
  }
});

test('a leaked credential is never also a wordlist password', () => {
  // If the plaintext in an AD description or an open share were also in
  // rockyou, a student who sprays before they enumerate lands on the account by
  // accident and never finds the leak - which was the whole lesson.
  const discovered = ['anonymous_rpc', 'password_in_description', 'open_share', 'web_credential'];
  for (const seed of SEEDS) {
    const d = design(seed);
    if (discovered.indexOf(d.chain.shape.entry) === -1) continue;
    assert.strictEqual(chain.CRACKABLE_PASSWORDS.indexOf(d.foothold_credential.password), -1,
      `${seed}: a found credential must not also be sprayable`);
    assert.ok(chain.LEAKED_PASSWORDS.indexOf(d.foothold_credential.password) !== -1);
  }
  // ...and a credential meant to be CRACKED must be in the wordlist.
  for (const seed of SEEDS) {
    const d = design(seed);
    if (d.chain.shape.entry !== 'asrep') continue;
    assert.ok(chain.CRACKABLE_PASSWORDS.indexOf(d.foothold_credential.password) !== -1,
      `${seed}: an AS-REP hash nobody can crack is not an entry point`);
  }
});

// ── 8. determinism ─────────────────────────────────────────────────────────

test('the same seed reproduces byte-identically', () => {
  for (const seed of SEEDS) {
    const first = JSON.stringify(design(seed));
    const second = JSON.stringify(design(seed));
    assert.strictEqual(first, second, `${seed} is not reproducible`);
  }
  // Reproducible from run_id on the IR alone, with no explicit option: the
  // paper-vs-lane parity check regenerates from the profile, not from a call
  // site that happens to remember the seed.
  const viaOption = JSON.stringify(chain.designAttackChain(fixture({ run_id: 'delta' }),
    { runId: 'delta' }));
  const viaIr = JSON.stringify(chain.designAttackChain(fixture({ run_id: 'delta' }), {}));
  assert.strictEqual(viaOption, viaIr);
});

test('different seeds do not collide', () => {
  const seen = new Map();
  for (const seed of SEEDS) {
    const body = JSON.stringify(design(seed).chain.signature);
    if (seen.has(body)) {
      // Signatures carry no names, so a collision means two clients really did
      // get the same exercise.
      assert.fail(`${seed} and ${seen.get(body)} produced the same structural signature: ${body}`);
    }
    seen.set(body, seed);
  }
});

test('the shuffle is a pure function of the seed', () => {
  const list = USER_NAMES.slice();
  assert.deepStrictEqual(chain.seededShuffle('a', 's', list), chain.seededShuffle('a', 's', list));
  assert.notDeepStrictEqual(chain.seededShuffle('a', 's', list),
    chain.seededShuffle('b', 's', list));
  assert.deepStrictEqual(chain.seededShuffle('a', 's', list).slice().sort(), list.slice().sort(),
    'a shuffle must be a permutation, not a filter');
});

// ── applyAttackChain: the merge that closes the seam ───────────────────────

test('applyAttackChain writes the design back onto the principals, without mutating', () => {
  const before = fixture({ run_id: 'seed-one' });
  const beforeJson = JSON.stringify(before);
  const after = chain.applyAttackChain(before, { runId: 'seed-one' });

  assert.strictEqual(JSON.stringify(before), beforeJson, 'the input IR must not be mutated');
  const foothold = after.foothold_credential;
  const user = after.principals.users.filter((u) => u.sam === foothold.sam)[0];
  assert.strictEqual(user.password, foothold.password,
    'AD must be built with the string the web side plants - that is the whole seam');
  assert.ok(after.chain && after.acls[FQDN]);
  assert.strictEqual(after.chain.signature.entry, after.chain.start.kind);

  // The kerberoast decision lands on the principal too, not on a note the
  // composer is expected to read and act on.
  const roasted = after.principals.users.filter((u) => (u.spns || []).length > 0);
  assert.strictEqual(roasted.length, 1);
  assert.strictEqual(roasted[0].sam, after.chain.edges[0].to);
});

test('the checks still work on a chain that has been through a normaliser', () => {
  // goad-lab-compile.normalizeChain() keeps only start/objective/edges/decoys —
  // every additive field this module adds (domain, shape, declared_*) is
  // legitimately dropped on the way into the compiled IR. The danger is not the
  // loss: it is that findUnintendedShortcuts would then index an empty
  // principal pool and report ALL CLEAR, which is worse than throwing.
  const designed = design('delta');
  const normalized = {
    start: designed.chain.start,
    objective: designed.chain.objective,
    edges: designed.chain.edges.slice(),
    decoys: designed.chain.decoys.slice(),
  };

  const over = fixture({ run_id: 'delta', acls: designed.acls });
  over.principals.users[5].password = over.principals.users[6].password;
  const codes = chain.findUnintendedShortcuts(over, normalized).map((f) => f.code);
  assert.ok(codes.indexOf('SHORTCUT_SHARED_PASSWORD') !== -1,
    'a normalised chain must not silently make the shortcut checks vacuous');

  // And the signature still computes rather than throwing on the missing shape.
  const sig = chain.chainSignature(normalized);
  assert.strictEqual(sig.terminus, designed.chain.objective.kind);
  assert.strictEqual(sig.edges, designed.chain.edges.length);
  assert.strictEqual(sig.branching_factor, designed.chain.signature.branching_factor);
});

test('the ACL table is keyed by domain fqdn and carries every ACL edge', () => {
  for (const seed of SEEDS) {
    const d = design(seed);
    assert.deepStrictEqual(Object.keys(d.acls), [FQDN]);
    const aclEdges = d.chain.edges.concat(d.chain.decoys)
      .filter((e) => e.edge_type === 'acl');
    const entryAcls = d.chain.start.plants.filter((p) => p.role === 'acl');
    assert.strictEqual(Object.keys(d.acls[FQDN]).length, aclEdges.length + entryAcls.length,
      `${seed}: an ACL edge went missing on the way into the table - config.json's acls is a `
      + 'dict, so a duplicate key silently replaces an entry');
    for (const edge of aclEdges) {
      assert.deepStrictEqual(d.acls[FQDN][edge.created_by.item], {
        for: edge.from, to: edge.to, right: edge.right, inheritance: edge.inheritance,
      });
    }
  }
});

// ── 12. declared admins: the policy the two halves now share ───────────────
//
// THE FAILURE THIS SECTION ENDS. The composer mints roster Domain Admins on
// purpose — a real company has them. This module used to hardcode
// `declared_admins: []` and nothing ever populated it, so its no-unintended-
// shortcuts check rejected every domain admin that existed. Against real
// composer output the check could never pass: 60 realistic profiles compiled and
// 0 produced a chain.
//
// The resolution is not a relaxation. The composer DECLARES, and this module
// verifies the far more useful property — that no 'roster_realism' admin is
// reachable by a path shorter than the intended chain. Three domain admins in a
// company is realism; one of them two hops from the foothold when the lesson is
// seven hops is a shortcut with an org chart.

/** The fixture, plus a declared-admin roster and the composer-owned host facts
 *  (local admin, cached credentials) the reachability model now walks. */
function adminFixture(o) {
  const opts = o || {};
  const ir = fixture({ run_id: opts.seed || 'admin-seed' });
  ir.principals.declared_admins = opts.declared || [];
  for (const [sam, groups] of Object.entries(opts.groups || {})) {
    ir.principals.users.find((u) => u.sam === sam).groups = groups;
  }
  for (const [key, patch] of Object.entries(opts.hosts || {})) {
    Object.assign(ir.hosts.find((h) => h.key === key), patch);
  }
  return ir;
}

test('a DECLARED admin is allowed to exist; an undeclared one is still a finding', () => {
  // The whole point. `jonas.petrov` is the IT director; a forest without one is
  // not a forest anybody believes.
  const declaredIr = adminFixture({
    declared: [{ sam: 'jonas.petrov', reason: 'roster_realism' }],
    groups: { 'jonas.petrov': ['Domain Admins'] },
  });
  const designed = chain.designAttackChain(declaredIr, { runId: 'admin-seed' });
  const codes = chain.findUnintendedShortcuts(declaredIr, designed.chain).map((f) => f.code);
  assert.strictEqual(codes.indexOf('SHORTCUT_PRIVILEGED_MEMBERSHIP'), -1,
    'a declared admin must not be reported merely for existing');

  // Same lab, same graph, nothing declared on either side: the silence is the
  // bug, so it is still caught. This is the rule that stops "declared" becoming
  // "ignored" — it is declared or it is a finding, never sometimes waved past.
  const silent = adminFixture({ groups: { 'jonas.petrov': ['Domain Admins'] } });
  const undeclaredChain = JSON.parse(JSON.stringify(designed.chain));
  undeclaredChain.declared_admins = [];
  const silentCodes = chain.findUnintendedShortcuts(silent, undeclaredChain).map((f) => f.code);
  assert.ok(silentCodes.indexOf('SHORTCUT_PRIVILEGED_MEMBERSHIP') !== -1,
    'an UNDECLARED admin is exactly the case neither half can reason about');
});

test('the declaration travels on the chain, so a consumer sees what the composer decided', () => {
  const ir = adminFixture({
    declared: [{ sam: 'jonas.petrov', reason: 'roster_realism', domain: FQDN, via: 'Domain Admins' }],
    groups: { 'jonas.petrov': ['Domain Admins'] },
  });
  const designed = chain.designAttackChain(ir, { runId: 'admin-seed' });
  assert.deepStrictEqual(designed.chain.declared_admins.map((a) => a.sam), ['jonas.petrov']);
  assert.strictEqual(designed.chain.declared_admins[0].reason, 'roster_realism');
  // And this module never binds one to a chain node or points a decoy at one:
  // an admin halfway along the spine ends the exercise where they sit.
  const touched = designed.chain.edges.concat(designed.chain.decoys)
    .flatMap((e) => [chain.nodeKey(e.from), chain.nodeKey(e.to)]);
  assert.strictEqual(touched.indexOf(chain.nodeKey('jonas.petrov')), -1,
    'a declared admin must not appear on any edge the designer draws');
  assert.notStrictEqual(chain.nodeKey(designed.chain.start.principal),
    chain.nodeKey('jonas.petrov'), 'nor be the foothold');
});

test('a roster_realism admin reachable more cheaply than the chain is a finding', () => {
  // The property that actually protects the exercise, and the reason the
  // declaration mechanism is worth having at all.
  const ir = adminFixture({
    declared: [{ sam: 'jonas.petrov', reason: 'roster_realism' }],
    groups: { 'jonas.petrov': ['Domain Admins'] },
  });
  const designed = chain.designAttackChain(ir, { runId: 'admin-seed' });
  assert.ok(designed.chain.length >= 3);

  // Now weld the admin two hops from the foothold, the way a real estate does
  // it: the foothold is a local administrator on a member server, and that
  // server has the admin's password cached on it. No ACL, no BloodHound edge.
  const cheap = adminFixture({
    declared: [{ sam: 'jonas.petrov', reason: 'roster_realism' }],
    groups: { 'jonas.petrov': ['Domain Admins'] },
    hosts: {
      srv02: {
        local_admins: [designed.chain.start.principal],
        cached_credentials: ['jonas.petrov'],
      },
    },
  });
  const findings = chain.findUnintendedShortcuts(cheap, designed.chain);
  const cheapFinding = findings.filter((f) => f.code === 'SHORTCUT_ADMIN_TOO_CHEAP')[0];
  assert.ok(cheapFinding, `no SHORTCUT_ADMIN_TOO_CHEAP in ${findings.map((f) => f.code)}`);
  // The three facts the composer needs to act: who, how short, how long it
  // should have been — plus the route, so a human can judge it.
  assert.strictEqual(cheapFinding.principal, 'jonas.petrov');
  assert.strictEqual(cheapFinding.hops, 2);
  assert.strictEqual(cheapFinding.designed_hops, designed.chain.length);
  assert.deepStrictEqual(cheapFinding.path,
    [chain.nodeKey(designed.chain.start.principal), 'ng-srv02$', 'jonas.petrov']);
  assert.ok(/demote/.test(cheapFinding.message),
    'the message must say whose job the fix is: the composer demotes and re-emits');
});

test('reachability is computed over the edge set the CHAIN uses, not just ACLs', () => {
  // A walk over ACL edges alone would call the two-hop credential-reuse takeover
  // above "unreachable", which is precisely the shortcut that ruins a lab. Each
  // implicit family is asserted separately so a future simplification that drops
  // one is a failure rather than a silent weakening.
  const ir = adminFixture({ hosts: { srv02: { local_admins: ['cara.nguyen'], cached_credentials: ['derek.mbeki'] } } });
  const pool = chain.indexPrincipals(ir.principals, FQDN);
  const host = chain.hostEdges(ir, FQDN);
  assert.deepStrictEqual(host, [
    { from: 'cara.nguyen', to: 'NG-SRV02$', edge_type: 'implicit_local_admin', host: 'srv02' },
    { from: 'NG-SRV02$', to: 'derek.mbeki', edge_type: 'implicit_cached_credential', host: 'srv02' },
  ]);
  assert.strictEqual(chain.shortestPath(host, 'cara.nguyen', 'derek.mbeki'), 2);

  // Group nesting, including a DC's LOCAL Administrators list — which on a
  // domain controller IS the domain's built-in Administrators.
  const nested = adminFixture({
    groups: { 'cara.nguyen': ['HelpDesk'] },
    hosts: { dc01: { local_admins: ['elena.rossi'] } },
  });
  nested.principals.groups.find((g) => g.name === 'HelpDesk').members = [];
  const memberships = chain.membershipGraph(nested,
    chain.indexPrincipals(nested.principals, FQDN), FQDN);
  assert.deepStrictEqual(memberships.get('cara.nguyen'), ['helpdesk']);
  assert.deepStrictEqual(memberships.get('elena.rossi'), ['administrators'],
    "a DC's local Administrators list is domain-privileged membership, not local admin");

  // Password reuse: crack one, hold both, and BloodHound draws nothing.
  const shared = adminFixture({});
  shared.principals.users[2].password = shared.principals.users[5].password;
  const reuse = chain.sharedPasswordEdges(chain.indexPrincipals(shared.principals, FQDN));
  assert.strictEqual(reuse.length, 2, 'reuse is a route in both directions');
  assert.ok(reuse.every((e) => e.edge_type === 'implicit_shared_password'));
  assert.ok(pool.users.length > 0);
});

test('a chain_terminus admin is exempt, because being reachable is the point', () => {
  const declared = [{ sam: 'jonas.petrov', reason: 'roster_realism' }];
  const ir = adminFixture({ declared, groups: { 'jonas.petrov': ['Domain Admins'] } });
  const designed = chain.designAttackChain(ir, { runId: 'admin-seed' });
  const cheapHosts = {
    srv02: { local_admins: [designed.chain.start.principal], cached_credentials: ['jonas.petrov'] },
  };

  const asRealism = chain.findUnintendedShortcuts(
    adminFixture({ declared, groups: { 'jonas.petrov': ['Domain Admins'] }, hosts: cheapHosts }),
    designed.chain);
  assert.ok(asRealism.some((f) => f.code === 'SHORTCUT_ADMIN_TOO_CHEAP'));

  // Same lab, same route, declared as the thing the chain ENDS at.
  const terminusChain = JSON.parse(JSON.stringify(designed.chain));
  terminusChain.declared_admins = [{ sam: 'jonas.petrov', reason: 'chain_terminus' }];
  const asTerminus = chain.findUnintendedShortcuts(
    adminFixture({
      declared: terminusChain.declared_admins,
      groups: { 'jonas.petrov': ['Domain Admins'] },
      hosts: cheapHosts,
    }), terminusChain);
  assert.strictEqual(asTerminus.filter((f) => f.code === 'SHORTCUT_ADMIN_TOO_CHEAP').length, 0,
    'taking the objective account IS the exercise; reachability is the point, not the problem');
});

test('a declaration is read strictly: a bare string is the STRICTER reading, a typo is fatal', () => {
  // A bare string could mean either reason. Reading it as 'roster_realism'
  // applies the shorter-path gate; reading it as 'chain_terminus' would switch
  // the gate off. Only one of those is safe to guess.
  const bare = chain.normalizeDeclaredAdmins(['jonas.petrov']);
  assert.strictEqual(bare.get('jonas.petrov').reason, 'roster_realism');
  // chain_terminus is the stronger claim and may upgrade a duplicate, so the
  // same principal declared twice cannot end up exempt by accident of ordering.
  const dup = chain.normalizeDeclaredAdmins([
    { sam: 'x', reason: 'roster_realism' }, { sam: 'x', reason: 'chain_terminus' }]);
  assert.strictEqual(dup.get('x').reason, 'chain_terminus');
  // A typo must never be the thing that decides whether a lab is proven.
  assert.throws(
    () => chain.normalizeDeclaredAdmins([{ sam: 'x', reason: 'because_i_said_so' }]),
    (err) => err.code === 'ADMIN_REASON_UNKNOWN'
      && err.message.indexOf(chain.ADMIN_REASONS.join(', ')) !== -1);
});

test('a chain that lost its declarations to a normaliser recovers them from the IR', () => {
  // goad-lab-compile.normalizeChain keeps them now, but a caller in between may
  // not. Running the checks over an empty declaration and reporting all-clear
  // would be the same silence, arrived at from the other side.
  const ir = adminFixture({
    declared: [{ sam: 'jonas.petrov', reason: 'roster_realism' }],
    groups: { 'jonas.petrov': ['Domain Admins'] },
  });
  const designed = chain.designAttackChain(ir, { runId: 'admin-seed' });
  const stripped = JSON.parse(JSON.stringify(designed.chain));
  delete stripped.declared_admins;
  const codes = chain.findUnintendedShortcuts(ir, stripped).map((f) => f.code);
  assert.strictEqual(codes.indexOf('SHORTCUT_PRIVILEGED_MEMBERSHIP'), -1,
    'the declaration is recoverable from labIR.principals, where the composer put it');
});

// ── 13. generate -> prove -> repair ────────────────────────────────────────
//
// The second defect: the designer used to emit decoys and ACL edges that created
// a route shorter than the path it had just designed, and then fail its own
// solvability proof on them. That is a generator bug, not a policy question — a
// decoy that shortens the path is not a decoy, it is a second solution — so the
// check stays and the generator learns.

/** A fixture where every user is in a department group and the one member server
 *  hands out local admin and cached credentials: the shapes that used to make
 *  the designer contradict itself. */
function hostileFixture(seed) {
  const ir = fixture({ run_id: seed });
  const memberships = {
    'amara.velez': ['ITOps'],
    'brian.olusola': ['HelpDesk'],
    'cara.nguyen': ['Finance'],
    'derek.mbeki': ['ITOps'],
    'elena.rossi': ['ProjectAtlas'],
    'farid.haddad': ['HelpDesk'],
  };
  for (const [sam, groups] of Object.entries(memberships)) {
    ir.principals.users.find((u) => u.sam === sam).groups = groups;
  }
  Object.assign(ir.hosts.find((h) => h.key === 'srv02'), {
    local_admins: ['amara.velez', 'brian.olusola', 'cara.nguyen'],
    cached_credentials: ['derek.mbeki', 'elena.rossi', 'hugo.martins'],
  });
  return ir;
}

const HOSTILE_SEEDS = (() => {
  const out = [];
  for (let i = 0; i < 40; i += 1) out.push(`hostile-${i}`);
  return out;
})();

test('a pool full of shortcuts still yields a PROVEN chain, or a loud refusal', () => {
  let repaired = 0;
  for (const seed of HOSTILE_SEEDS) {
    const ir = hostileFixture(seed);
    const designed = chain.designAttackChain(ir, { runId: seed });
    // The proof is the point: whatever the generator had to do to get here, what
    // comes out has no shortcut in it.
    assert.deepStrictEqual(
      chain.findUnintendedShortcuts(Object.assign({}, ir, { acls: designed.acls }),
        designed.chain, { acls: designed.acls }), [],
      `${seed}: a design escaped the loop still carrying a shortcut`);
    if (designed.chain.shape.repair_attempts > 0) repaired += 1;
  }
  assert.ok(repaired > 0,
    'the repair loop never ran on 40 hostile seeds, so it is not being exercised');
});

test('the repair loop is deterministic: the same seed repairs the same way', () => {
  // A self-correcting generator that corrects differently each run is not
  // reproducible, and paper-vs-lane parity is asserted BY regeneration.
  for (const seed of ['hostile-3', 'hostile-11', 'hostile-27']) {
    const a = chain.designAttackChain(hostileFixture(seed), { runId: seed });
    const b = chain.designAttackChain(hostileFixture(seed), { runId: seed });
    assert.deepStrictEqual(b.chain, a.chain, `${seed}: the repaired design drifted`);
    assert.deepStrictEqual(b.acls, a.acls);
  }
});

test('the repair loop is bounded and records what it moved', () => {
  assert.strictEqual(typeof chain.MAX_REPAIR_ATTEMPTS, 'number');
  assert.ok(chain.MAX_REPAIR_ATTEMPTS >= 1 && chain.MAX_REPAIR_ATTEMPTS <= 16,
    'an unbounded repair loop is a hang, not a generator');
  const repaired = HOSTILE_SEEDS
    .map((s) => chain.designAttackChain(hostileFixture(s), { runId: s }).chain)
    .filter((c) => c.shape.repair_attempts > 0)[0];
  assert.ok(repaired, 'no seed in the hostile set needed a repair');
  assert.ok(repaired.shape.repair_attempts <= chain.MAX_REPAIR_ATTEMPTS);
  // PRUNE or RE-SITE, and say which: an instructor reading the answer key needs
  // to know the graph was moved and why.
  assert.ok(repaired.shape.notes.some((n) => /re-sited|pruned|capped|clamped/.test(n)),
    `no repair was recorded: ${JSON.stringify(repaired.shape.notes)}`);
});

test('an unrepairable design is refused LOUDLY, naming the axis it could not satisfy', () => {
  // Never emit an unproven chain, and never drop the guarantee to get a result.
  // Here every principal but the foothold is a declared admin, so the designer
  // has nothing left to re-site.
  const ir = fixture({ run_id: 'no-room' });
  ir.principals.declared_admins = ir.principals.users.slice(1)
    .map((u) => ({ sam: u.sam, reason: 'roster_realism' }));
  assert.throws(
    () => chain.designAttackChain(ir, { runId: 'no-room' }),
    (err) => {
      assert.ok(['CHAIN_UNREPAIRABLE', 'PRINCIPAL_POOL_EXHAUSTED', 'FOOTHOLD_POOL_EXHAUSTED']
        .indexOf(err.code) !== -1, err.code);
      assert.ok(err.message.length > 80, 'a refusal has to say what it could not do');
      return true;
    });
});

test('every decoy dead-ends against the FULL edge set, not just against the ACLs', () => {
  // The premise `leaf_target` states — "this account arrives nowhere" — used to
  // be asserted rather than checked, and the composer puts every user in a
  // department group. So the target routinely reached the objective through a
  // group the answer key never mentioned: a second solution wearing a decoy's
  // label. Now the premise is a predicate.
  for (const seed of SEEDS.concat(HOSTILE_SEEDS.slice(0, 10))) {
    const ir = /^hostile-/.test(seed) ? hostileFixture(seed) : fixture({ run_id: seed });
    const designed = chain.designAttackChain(ir, { runId: seed });
    const c = designed.chain;
    const pool = chain.indexPrincipals(ir.principals, FQDN);
    const implicit = chain.membershipEdges(chain.membershipGraph(ir, pool, FQDN))
      .concat(chain.hostEdges(ir, FQDN))
      .concat(chain.sharedPasswordEdges(pool));
    const everything = c.edges.concat(c.decoys).concat(implicit);
    const reached = chain.reachableFrom(c.edges.concat(implicit), [c.start.principal]);
    for (const decoy of c.decoys) {
      const entered = reached.has(chain.nodeKey(decoy.from));
      const exits = chain.shortestPath(everything, decoy.to, c.objective.target);
      assert.ok(!(entered && exits !== null),
        `${seed}/${decoy.id}: reachable AND productive is a second solution, not a decoy`);
    }
    // And the intended path is still the shortest one there is.
    assert.strictEqual(chain.shortestPath(everything, c.start.principal, c.objective.target),
      c.length, `${seed}: something shortened the intended path`);
  }
});

test('shortestPathNodes returns the route, which is what makes repair possible', () => {
  const edges = [
    { from: 'a', to: 'b' }, { from: 'b', to: 'c' }, { from: 'c', to: 'd' }, { from: 'a', to: 'd' },
  ];
  assert.deepStrictEqual(chain.shortestPathNodes(edges, 'a', 'd'), ['a', 'd']);
  assert.deepStrictEqual(chain.shortestPathNodes(edges, 'b', 'd'), ['b', 'c', 'd']);
  assert.strictEqual(chain.shortestPathNodes(edges, 'd', 'a'), null);
  assert.deepStrictEqual(chain.shortestPathNodes(edges, 'a', 'a'), ['a'], 'zero hops is a route');
  // Distances agree with the walk, because the repair and the report must not
  // disagree about how short the short path was.
  const dist = chain.distancesFrom(edges, 'a');
  assert.strictEqual(dist.get('d'), 1);
  assert.strictEqual(dist.get('c'), 2);
  assert.strictEqual(dist.get('a'), 0);
});
