/**
 * ciab-goad-role-manifest.test.js — Track Z1: GOAD is pinned, and its role
 * library is vendored where a test can actually see it.
 *
 * WHY THIS FILE EXISTS
 * GOAD-main/ is gitignored and has ZERO tracked files, while
 * infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh
 * clones upstream GOAD into controller template 1700. Two consequences, both of
 * which this file closes:
 *
 *   1. Anything derived from the working copy is invisible to `node --test`.
 *      A validator that walked ansible/roles/ at runtime would pass vacuously
 *      on every machine without the checkout — including CI — which is the
 *      worst possible failure for a validator.
 *
 *   2. GOAD_REF used to default to 'main'. "Immutable versioned bakes" is false
 *      while the ref moves: re-baking 1700 swaps the role library under lane
 *      data written against the old one, and GOAD roles fail QUIETLY, so the
 *      symptom is a green deploy with nothing planted.
 *
 * So every assertion below reads the VENDORED manifest through
 * ciab/utils/goad-role-manifest.js and never touches GOAD-main. If these tests
 * could only pass on a machine with the checkout they would be measuring the
 * wrong thing.
 *
 * The counts (29 vulns / 9 security) are asserted on purpose. They are the
 * cheapest possible drift detector: a re-vendor against a different upstream
 * ref that added or dropped a role fails here instead of failing months later
 * on a lane.
 *
 * Run: node --test front-end/test/ciab-goad-role-manifest.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const MANIFEST_JSON = path.join(
  ROOT, 'modules/crucible/plugins/ciab/data/goad-role-manifest.json');

const roleManifest = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-role-manifest.js'));

const manifest = roleManifest.loadManifest();

const KINDS = ['vulns', 'security'];
const SHAPES = ['dict_of_objects', 'dict_of_scalars', 'none'];

// ── 1. the artifact is real, tracked, and parseable ─────────────────────────

test('the manifest parses from the tracked JSON, not from GOAD-main', () => {
  // Read the file directly as well as through the module: the module caches, so
  // a manifest that had been deleted after first load would still "work" for
  // any later assertion in this process.
  assert.ok(fs.existsSync(MANIFEST_JSON), `${MANIFEST_JSON} must be committed`);
  const raw = JSON.parse(fs.readFileSync(MANIFEST_JSON, 'utf8'));
  assert.strictEqual(raw.schema_version, 1);
  assert.ok(Array.isArray(raw.roles) && raw.roles.length > 0, 'manifest carries no roles');
});

test('the manifest is exempted from the blanket data/ ignore rule', () => {
  // Found the hard way while vendoring this: .gitignore line 4 is `**/data/*`,
  // so a new file under any data/ directory is invisible to git by default.
  // Writing the manifest there and stopping would have reproduced the precise
  // failure this task exists to fix — an untracked artifact that works on the
  // authoring machine, is absent everywhere else, and shows up in no diff.
  // Each tracked data file earns an explicit negation; assert ours is still
  // there, because deleting it breaks nothing locally and everything remotely.
  const gitignore = fs.readFileSync(path.join(ROOT, '..', '.gitignore'), 'utf8');
  const lines = gitignore.split(/\r?\n/).map((l) => l.trim());
  assert.ok(lines.includes('!**/data/goad-role-manifest.json'),
    '.gitignore must keep the negation that makes goad-role-manifest.json trackable; '
    + 'without it the vendored manifest is as invisible as the GOAD checkout it replaces');
});

test('the manifest is traceable to a pinned commit', () => {
  // A ref that is a branch name defeats the entire point of vendoring: the
  // manifest would claim to describe "GOAD at main", which is not a thing that
  // stays true. Only a full 40-char SHA is acceptable.
  assert.match(manifest.goad_ref, /^[0-9a-f]{40}$/,
    `goad_ref must be a full commit SHA, got ${JSON.stringify(manifest.goad_ref)}`);
  assert.ok(manifest.generated_from && /ansible\/roles/.test(manifest.generated_from),
    'generated_from must name the tree this was vendored from');
});

test('the bake script pins the same commit the manifest was vendored from', () => {
  // The other half of the contract. If these two drift, the generator validates
  // against a role library the baked controller does not run — and every
  // resulting mismatch fails silently on the lane.
  const bake = fs.readFileSync(path.join(
    ROOT, '..', 'infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh'), 'utf8');
  const m = bake.match(/^GOAD_REF="\$\{GOAD_REF:-([^}"]*)\}"/m);
  assert.ok(m, 'bake-goad-controller-vm.sh must still define GOAD_REF with an env override');
  assert.strictEqual(m[1], manifest.goad_ref,
    'bake-goad-controller-vm.sh GOAD_REF and goad-role-manifest.json goad_ref must move together');
});

// ── 2. every entry is complete ──────────────────────────────────────────────

test('every role entry carries every required field', () => {
  // A generator reads these fields without checking for undefined; a missing
  // required_item_keys would read as "no required keys" and validate everything.
  for (const role of manifest.roles) {
    const at = `${role.kind}/${role.name}`;
    assert.ok(typeof role.name === 'string' && role.name.length > 0, `${at}: bad name`);
    assert.ok(KINDS.includes(role.kind), `${at}: kind must be one of ${KINDS.join('|')}`);
    assert.strictEqual(typeof role.consumes_vars, 'boolean', `${at}: consumes_vars must be boolean`);
    assert.ok(SHAPES.includes(role.vars_shape), `${at}: vars_shape '${role.vars_shape}' is not a known shape`);
    assert.ok(Array.isArray(role.required_item_keys), `${at}: required_item_keys must be an array`);
    assert.ok(Array.isArray(role.optional_item_keys), `${at}: optional_item_keys must be an array`);
    for (const opt of role.optional_item_keys) {
      assert.ok(typeof opt.key === 'string', `${at}: optional entry missing key`);
      // The literal default is the point — it is what a generator must emit to
      // reproduce upstream behaviour when it omits the key.
      assert.ok('default' in opt, `${at}: optional key '${opt.key}' records no default`);
    }
    // null is a meaningful value here ("no group required"), so assert the
    // field is PRESENT rather than truthy.
    assert.ok('needs_inventory_group' in role, `${at}: needs_inventory_group missing`);
    assert.strictEqual(typeof role.never_emit, 'boolean', `${at}: never_emit must be boolean`);
  }
});

test('shape and key lists agree with consumes_vars', () => {
  // A role that iterates nothing cannot have per-item keys, and a role that
  // iterates must declare a shape. Either inconsistency means the vendoring
  // scan misread the tasks.
  for (const role of manifest.roles) {
    const at = `${role.kind}/${role.name}`;
    if (role.consumes_vars) {
      assert.notStrictEqual(role.vars_shape, 'none', `${at}: consumes vars but shape is 'none'`);
    } else {
      assert.strictEqual(role.vars_shape, 'none', `${at}: consumes no vars but shape is '${role.vars_shape}'`);
      assert.deepStrictEqual(role.required_item_keys, [], `${at}: consumes no vars but requires keys`);
      assert.deepStrictEqual(role.optional_item_keys, [], `${at}: consumes no vars but has optional keys`);
    }
  }
});

test('every never_emit role explains itself', () => {
  // never_emit without a reason is an instruction to skip with no way to judge
  // whether it is still true after an upstream bump — the next session deletes
  // the flag rather than re-deriving the bug.
  for (const role of manifest.roles.filter((r) => r.never_emit)) {
    assert.ok(role.never_emit_reason && role.never_emit_reason.length > 40,
      `${role.kind}/${role.name}: never_emit needs a substantive reason`);
  }
});

// ── 3. the counts — the drift detector ──────────────────────────────────────

test('the vendored library is 29 vulns roles and 9 security roles', () => {
  const byKind = { vulns: 0, security: 0 };
  for (const role of manifest.roles) byKind[role.kind]++;
  assert.strictEqual(byKind.vulns, 29,
    'vulns role count changed — re-vendored against a different GOAD ref? Check goad_ref.');
  assert.strictEqual(byKind.security, 9,
    'security role count changed — re-vendored against a different GOAD ref? Check goad_ref.');
  // The declared counts are what a reader trusts without walking roles[].
  assert.deepStrictEqual({ vulns: manifest.counts.vulns, security: manifest.counts.security },
    byKind, 'manifest.counts disagrees with the actual roles[] contents');
});

test('role identity is (name, kind), because `directory` exists in both', () => {
  // The one genuinely ambiguous name in the library, and the two are NOT the
  // same role: one iterates vulns_vars, the other security_vars. A manifest
  // keyed on bare name would have silently dropped one of them.
  const qualified = manifest.roles.map((r) => `${r.kind}/${r.name}`);
  assert.strictEqual(new Set(qualified).size, qualified.length, 'duplicate kind/name in roles[]');
  assert.ok(qualified.includes('vulns/directory') && qualified.includes('security/directory'));
  assert.strictEqual(roleManifest.getRole('directory').kind, 'vulns',
    'a bare name must resolve to the vulns vocabulary');
  assert.strictEqual(roleManifest.getRole('security/directory').kind, 'security');
  assert.strictEqual(roleManifest.getRole('directory', 'security').kind, 'security');
});

// ── 4. the traps a generator must respect ───────────────────────────────────

test('`directory` is dict_of_scalars in both kinds', () => {
  // It consumes {{item.value}} BARE as the path. Every sibling role indexes
  // item.value.<key>, so this is the odd one out and the easy generator bug:
  // emit a nested object here and win_file gets the stringified dict as a path,
  // creating a directory literally named "{'path': 'C:\\share'}".
  for (const kind of KINDS) {
    const role = roleManifest.getRole('directory', kind);
    assert.strictEqual(role.vars_shape, 'dict_of_scalars', `${kind}/directory must be dict_of_scalars`);
    assert.deepStrictEqual(role.required_item_keys, [],
      `${kind}/directory takes no item keys — the value IS the path`);
  }
});

test('`shares` and `adcs_esc7` are never_emit', () => {
  // shares: perm.yml gets `item.value.full | split(',') | trim` — a Jinja STRING
  //   filter applied to the LIST split() returns. Raises on ansible-core >= 2.16
  //   and coerces on older cores, so the breakage is version-dependent, which is
  //   worse than a hard failure: it works on the maintainer's box.
  // adcs_esc7: the Get-Module -ListAvailable guard is INVERTED — the grant sits
  //   in the else branch — and the task right before it installs PSPKI, so the
  //   guard is always true and ManageCA is never granted. Reports green.
  assert.strictEqual(roleManifest.isNeverEmit('shares'), true);
  assert.strictEqual(roleManifest.isNeverEmit('adcs_esc7'), true);
  // Guard against a blanket flag: the rest of the library is emittable.
  const banned = manifest.roles.filter((r) => r.never_emit).map((r) => `${r.kind}/${r.name}`);
  assert.deepStrictEqual(banned.sort(), ['vulns/adcs_esc7', 'vulns/shares']);
});

test('an unknown role is not silently treated as emittable OR as never_emit', () => {
  // Both halves matter. getRole returning something for a typo would validate a
  // role ansible cannot include; isNeverEmit returning true would let a typo
  // sail through a `!isNeverEmit(x)` guard as if it had been deliberately
  // skipped.
  assert.strictEqual(roleManifest.getRole('no_such_role'), null);
  assert.strictEqual(roleManifest.isNeverEmit('no_such_role'), false);
});

test('the roles that need an inventory group say which one', () => {
  // Running these outside their group does not skip — it fails the task on the
  // lane: mssql shells out to SqlCmd, and the two certutil roles need a local
  // AD CS service.
  const groups = {};
  for (const role of manifest.roles.filter((r) => r.needs_inventory_group)) {
    groups[`${role.kind}/${role.name}`] = role.needs_inventory_group;
  }
  assert.deepStrictEqual(groups, {
    'vulns/adcs_esc11': 'adcs',
    'vulns/adcs_esc6': 'adcs',
    'vulns/mssql': 'mssql',
    'security/asr': 'defender_on',
  });
});

test('defaults are recorded verbatim so a generator can reproduce them', () => {
  // Spot-check the two roles that actually carry defaults. `multiple_instances`
  // defaults to the STRING '2' (win_scheduled_task wants the string), and
  // shares' description defaults to item.key rather than a literal — recording
  // "has a default" without the value would lose both facts.
  const schedule = roleManifest.getRole('schedule');
  const mi = schedule.optional_item_keys.find((o) => o.key === 'multiple_instances');
  assert.ok(mi, 'schedule.multiple_instances must be recorded as optional');
  assert.strictEqual(mi.default, "'2'");
  assert.deepStrictEqual(schedule.required_item_keys.slice().sort(), ['cmd', 'interval', 'name']);

  const shares = roleManifest.getRole('shares');
  const desc = shares.optional_item_keys.find((o) => o.key === 'description');
  assert.strictEqual(desc.default, 'item.key');
});

// ── 5. the two ACL vocabularies ─────────────────────────────────────────────

test('the domain and host ACL vocabularies are separate, and host lacks Ext-ManageCA', () => {
  // roles/acl (domain, over ad_acls) and roles/vulns/acls (host, over
  // vulns_vars) each embed their own $aclExtendValues literal. They agree on the
  // 19 standard rights and differ on the extended ones. Merging them — or
  // reusing one list for both contexts — means a host-level entry can carry
  // Ext-ManageCA, which matches neither list upstream and therefore writes no
  // ACE while the task still reports green.
  const domain = roleManifest.aclRights('domain');
  const host = roleManifest.aclRights('host');

  assert.strictEqual(domain.standard.length, 19);
  assert.strictEqual(host.standard.length, 19);
  assert.deepStrictEqual(host.standard, domain.standard,
    'the 19 standard rights are identical in both roles; only the extended lists differ');

  assert.strictEqual(domain.extended.length, 5);
  assert.strictEqual(host.extended.length, 3);
  assert.notDeepStrictEqual(domain.extended, host.extended,
    'the two extended vocabularies must not be the same list');

  assert.ok(domain.extended.includes('Ext-ManageCA'),
    'Ext-ManageCA is the sanctioned replacement for the broken adcs_esc7 role');
  assert.ok(domain.extended.includes('Ext-Write-SPN'));
  assert.ok(!host.extended.includes('Ext-ManageCA'),
    'roles/vulns/acls does not accept Ext-ManageCA — emitting it there is a silent no-op');
  assert.ok(!host.extended.includes('Ext-Write-SPN'),
    'roles/vulns/acls does not accept Ext-Write-SPN either');
});

test('right matching is ordinal case-sensitive, and the manifest says so', () => {
  // Upstream tests membership with PowerShell's $aclValues.contains($right) —
  // Array/IList.Contains with the ordinal comparer. Accepting 'genericall' here
  // would let through a string GOAD then drops on the floor with no error, so
  // isAclRight must NOT normalise case.
  assert.strictEqual(roleManifest.isAclRight('GenericAll', 'domain'), true);
  assert.strictEqual(roleManifest.isAclRight('genericall', 'domain'), false);
  assert.strictEqual(roleManifest.isAclRight('Ext-ManageCA', 'domain'), true);
  assert.strictEqual(roleManifest.isAclRight('Ext-ManageCA', 'host'), false);

  // The note is what tells a future reader why a "working" lane has no ACE.
  assert.match(manifest.acl_matching_note, /case-sensitive/i);
  assert.match(manifest.acl_matching_note, /green/i);
  assert.match(manifest.acl_vocabulary_note, /NEVER MERGE/i);
});

test('aclRights refuses an unknown context instead of guessing one', () => {
  // Defaulting to either vocabulary would be wrong half the time, and wrong
  // toward the permissive side if it defaulted to domain.
  assert.throws(() => roleManifest.aclRights('both'), /'domain' or 'host'/);
  assert.throws(() => roleManifest.aclRights(undefined), /'domain' or 'host'/);
});

test('the inheritance vocabulary is recorded and spelled the way .NET spells it', () => {
  // Unlike $right, $inheritance is a cast to
  // [System.DirectoryServices.ActiveDirectorySecurityInheritance], which throws
  // on an unknown value — so this one fails loudly. It is recorded anyway
  // because 'Descendents' is Microsoft's spelling and 'Descendants' is the
  // reflex.
  const inh = manifest.acl_inheritance.values;
  assert.ok(inh.includes('None') && inh.includes('All'));
  assert.ok(inh.includes('Descendents'), "the enum member is 'Descendents', not 'Descendants'");
  assert.ok(!inh.includes('Descendants'));
});

// ── 6. the frozen singleton ─────────────────────────────────────────────────

test('the manifest is deep-frozen, so one caller cannot corrupt another', () => {
  // Every caller shares this object. A generator that pushed onto
  // required_item_keys to "add a rule" would silently change validation for the
  // rest of the process. Frozen in non-strict code fails silently, so assert the
  // mutation did not land rather than expecting a throw.
  const role = roleManifest.getRole('acls');
  assert.ok(Object.isFrozen(manifest));
  assert.ok(Object.isFrozen(role));
  assert.ok(Object.isFrozen(role.required_item_keys));
  const before = role.required_item_keys.length;
  try { role.required_item_keys.push('injected'); } catch (_) { /* strict mode throws */ }
  assert.strictEqual(roleManifest.getRole('acls').required_item_keys.length, before);
  assert.ok(Object.isFrozen(roleManifest.aclRights('domain').extended));
});

test('the host acls role still declares the four keys the ACL payload reads', () => {
  // for/to/right/inheritance are all passed with no `| default(...)`, so an
  // omitted one reaches PowerShell as the literal string "None" via Jinja's
  // undefined handling and produces a nonsense ACE — or no ACE at all.
  assert.deepStrictEqual(
    roleManifest.getRole('acls').required_item_keys.slice().sort(),
    ['for', 'inheritance', 'right', 'to']);
});
