/**
 * ciab-goad-lab-validate.test.js — the lab-definition validator.
 *
 * WHAT IS ACTUALLY BEING DEFENDED
 * Every rule in goad-lab-validate.js exists because breaking it produces a GREEN
 * deploy with something missing — an ACE that was never written, a with_dict
 * loop over an empty dict, a scheduled task pointing at a script nobody copied.
 * A validator for loud failures would not be worth writing; the play already
 * reports those.
 *
 * That makes the false-positive rate the whole ballgame. A rule that rejects a
 * lab GOAD deploys every day is worse than no rule, because the first thing
 * anyone does with it is turn it off. So the corpus test below runs all eight
 * shipped labs and asserts the EXACT finding set for each, not merely "no
 * errors": if a rule starts firing somewhere new, this file names the lab, the
 * code and the location rather than going quietly greener.
 *
 * THE BASELINE IS CALIBRATED, NOT ASSUMED. All 11 corpus findings were run down
 * individually against the upstream role or playbook that consumes the value,
 * and all 11 are true positives — no rule was loosened to quiet the corpus, and
 * none was kept that fires on a lab that deploys. The verdict for each, with the
 * file, the line and what silently fails to exist, is in
 * ciab/data/goad-corpus-findings.md; a test at the bottom of this file keeps
 * that document and the EXPECTED table below from drifting apart.
 *
 * The corpus is gated on GOAD-main/ existing, because it is gitignored and has
 * zero tracked files — it is present on the authoring machine and absent in CI.
 * Everything that matters is therefore ALSO proven against hand-built fixtures
 * that need no checkout: one mutation per rule, each asserting that the rule
 * fires AND that the unmutated base is clean.
 *
 * Run: node --test front-end/test/ciab-goad-lab-validate.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');

const V = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-lab-validate.js'));
const { loadManifest } = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-role-manifest.js'));
// The composer, required for ONE test: that a lab this repo really produces
// passes generated mode. A hand-built chain fixture proves each rule fires; only
// a real compile proves the rules are satisfiable by the thing that has to
// satisfy them, and that the IR field names this validator reads
// (`chain`, `foothold_credential`) are the ones the compiler actually emits.
const compile = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-lab-compile.js'));

// ── fixtures ────────────────────────────────────────────────────────────────

/**
 * A minimal lab that must validate completely clean.
 *
 * Deliberately exercises the awkward shapes rather than the easy ones: a
 * directory-copy `dest` ending in a backslash feeding adcs_templates, a
 * schedule whose cmd only CONTAINS the planted path, a user in an OU and a user
 * in CN=Users, and weak users[].password values (legal — those are set after
 * password_policy relaxes the domain, which is exactly why only
 * domain_password and local_admin_password are checked).
 */
function baseLab() {
  return {
    hosts: {
      dc01: {
        hostname: 'LAB-DC01',
        type: 'dc',
        domain: 'range.local',
        path: 'DC=range,DC=local',
        local_admin_password: 'Kt7-Vqx#2Lm9',
        vulns: ['directory', 'files', 'adcs_templates', 'permissions'],
        vulns_vars: {
          directory: { setup: 'c:\\setup' },
          files: { tpl: { src: 'dc01/templates/', dest: 'C:\\setup\\' } },
          adcs_templates: { ESC1: { template_name: 'ESC1', template_file: 'C:\\setup\\ESC1.json' } },
          permissions: { staging: { path: 'C:\\setup', user: 'Users', rights: 'FullControl' } },
        },
        security: ['account_is_sensitive'],
        security_vars: { account_is_sensitive: { alice: { account: 'alice.stone' } } },
      },
      srv01: {
        hostname: 'LAB-SRV01',
        type: 'server',
        domain: 'range.local',
        path: 'DC=range,DC=local',
        local_admin_password: 'Qw4-Zn8#Pt1x',
        vulns: ['files', 'schedule'],
        vulns_vars: {
          files: { bot: { src: 'srv01/bot.ps1', dest: 'c:\\bot.ps1' } },
          schedule: { bot: { name: 'bot', cmd: 'powershell c:\\bot.ps1', interval: 'PT1M' } },
        },
      },
    },
    domains: {
      'range.local': {
        dc: 'dc01',
        domain_password: 'Kt7-Vqx#2Lm9',
        netbios_name: 'RANGE',
        organisation_units: { Field: { path: 'DC=range,DC=local' } },
        groups: {
          universal: {},
          global: { Operators: { path: 'OU=Field,DC=range,DC=local' } },
          domainlocal: {},
        },
        multi_domain_groups_member: {},
        acls: {
          genericwrite_alice_bob: {
            for: 'alice.stone', to: 'bob.reed', right: 'GenericWrite', inheritance: 'None',
          },
        },
        users: {
          'alice.stone': {
            firstname: 'Alice', surname: 'Stone', password: 'football',
            description: 'Alice Stone', groups: ['Operators'],
            path: 'CN=Users,DC=range,DC=local',
          },
          'bob.reed': {
            firstname: 'Bob', surname: 'Reed', password: 'princess',
            description: 'Bob Reed', groups: [],
            path: 'OU=Field,DC=range,DC=local',
          },
        },
      },
    },
  };
}

const BASE_INVENTORY = [
  '[all:vars]',
  'admin_user=administrator',
  '',
  '; computers inside domain',
  '[domain]',
  'dc01',
  'srv01',
  '',
  '[linux_domain]',
  '',
  '[dc]',
  'dc01',
  '',
  '[server]',
  'srv01',
].join('\n');

const clone = (o) => JSON.parse(JSON.stringify(o));

/** Mutate a copy of the base lab, validate it, return the result. */
function check(mutate, extra) {
  const lab = baseLab();
  if (mutate) mutate(lab);
  return V.validateLab(Object.assign(
    { lab, inventory: BASE_INVENTORY, labName: 'FIXTURE' }, extra || {}));
}

/**
 * The same lab, plus the three things a GENERATED lab additionally has to
 * carry: a chain, the foothold credential it is rooted at, and the emitted ACL
 * entries its edges refer to.
 *
 * Deliberately built on top of baseLab() rather than beside it, because the
 * property under test is that generated mode adds rules and changes none: the
 * same lab must be clean in both modes, and the only difference must be the
 * chain.
 *
 * Two ACL hops, alice -> bob -> Operators, ending on a group the lab really
 * declares. The second entry is added to the lab as well as to the chain: an IR
 * edge and an emitted acls entry are written by DIFFERENT code paths in
 * production (goad-attack-chain draws the edge, goad-lab-compile lowers it into
 * config.json), and every assertion below about them agreeing is only meaningful
 * because the fixture keeps them as two separate objects here too.
 */
function generatedLab() {
  const lab = baseLab();
  lab.domains['range.local'].acls.genericall_bob_operators = {
    for: 'bob.reed', to: 'Operators', right: 'GenericAll', inheritance: 'All',
  };
  return lab;
}

function generatedChain() {
  return {
    domain: 'range.local',
    start: {
      kind: 'web_credential',
      principal: 'alice.stone',
      // `onlyusers` is one of the three config.json-driven producers the vendored
      // manifest does NOT list (every lab runs it, no lab chooses it), so this
      // plant is also the regression guard for CORE_CHAIN_ROLES: drop that table
      // and getRole() returns null here, which would reject every real chain.
      plants: [{
        kind: 'ad_password',
        role: 'onlyusers',
        host: 'dc01',
        item: 'alice.stone',
        item_vars: { password: 'football' },
      }],
    },
    objective: { kind: 'group_control', target: 'Operators' },
    edges: [
      {
        id: 'edge0',
        from: 'alice.stone',
        to: 'bob.reed',
        edge_type: 'acl',
        depth: 0,
        spine: true,
        created_by: {
          role: 'acl',
          host: 'dc01',
          item: 'genericwrite_alice_bob',
          item_vars: {
            for: 'alice.stone', to: 'bob.reed', right: 'GenericWrite', inheritance: 'None',
          },
        },
      },
      {
        id: 'edge1',
        from: 'bob.reed',
        to: 'Operators',
        edge_type: 'acl',
        depth: 1,
        spine: true,
        created_by: {
          role: 'acl',
          host: 'dc01',
          item: 'genericall_bob_operators',
          item_vars: {
            for: 'bob.reed', to: 'Operators', right: 'GenericAll', inheritance: 'All',
          },
        },
      },
    ],
    decoys: [],
  };
}

function generatedFoothold() {
  return {
    sam: 'alice.stone',
    domain: 'range.local',
    password: 'football',
    planted_at: { host_key: 'srv01', path: '/admin/integrations', format: 'web_app_credential' },
    honoured_by: 'ad',
  };
}

/**
 * Mutate a copy of the generated triple (lab + chain + foothold) and validate it
 * in generated mode.
 *
 * The mutator receives all three because the failures being tested are
 * DISAGREEMENTS between them — an edge the lab does not emit, a credential the
 * roster does not create — and neither half is wrong on its own.
 */
function checkGenerated(mutate, extra) {
  const bundle = { lab: generatedLab(), chain: generatedChain(), foothold: generatedFoothold() };
  if (mutate) mutate(bundle);
  return V.validateLab(Object.assign({
    lab: bundle.lab,
    chain: bundle.chain,
    foothold: bundle.foothold,
    inventory: BASE_INVENTORY,
    labName: 'FIXTURE',
    mode: V.MODE_GENERATED,
  }, extra || {}));
}

const codesAt = (result) => result.findings.map((f) => `${f.code}@${f.id}`).sort();
const codes = (result) => result.findings.map((f) => f.code).sort();

/**
 * The corpus form, and the one difference from codesAt() that matters:
 * SEVERITY IS PART OF THE IDENTITY.
 *
 * Downgrading a rule from error to warning is the single cheapest way to make
 * this file green while making the validator useless — errors block a bake,
 * warnings do not. codesAt() cannot see that happen. This can.
 */
const findingsAt = (result) =>
  result.findings.map((f) => `${f.severity} ${f.code}@${f.id}`).sort();

/** Assert exactly one finding, of this code, at this severity. */
function onlyFinding(result, code, severity) {
  assert.deepStrictEqual(codes(result), [code],
    `expected exactly one ${code}, got ${JSON.stringify(codesAt(result))}`);
  assert.strictEqual(result.findings[0].severity, severity);
  return result.findings[0];
}

// ── 0. the fixture itself ───────────────────────────────────────────────────

test('the unmutated base lab is completely clean', () => {
  // Every rejection test below is only meaningful if this holds: otherwise a
  // mutation "firing" could just be the fixture's own noise.
  const r = check(null);
  assert.deepStrictEqual(codesAt(r), []);
});

// ── 1. asymmetric parsing: tolerant in, strict out ──────────────────────────

test('a trailing comma is tolerated, because Ansible loads config.json as YAML', () => {
  // ad/DRACARYS/data/config.json really does ship one and really does deploy.
  // Ansible reads vars_files with PyYAML, and YAML 1.1 flow collections allow a
  // trailing comma; the .json extension is a naming convention, not a contract.
  // A strict JSON.parse here rejects a working lab — the one error class this
  // validator must never produce.
  const text = '{"lab":{"hosts":{},"domains":{"a.b":{"acls":{"x":{"for":"u","to":"v"},}}}}}';
  assert.throws(() => JSON.parse(text), SyntaxError, 'fixture must be non-strict to be a real test');
  const parsed = V.parseLabConfig(text);
  assert.strictEqual(parsed.strict, false);
  assert.deepStrictEqual(parsed.repairs, ['trailing-comma']);
  assert.ok(parsed.lab.domains['a.b'].acls.x, 'the entry before the stray comma must survive');
});

test('strict JSON parses with no repairs, and the {"lab": …} envelope is unwrapped', () => {
  const parsed = V.parseLabConfig(JSON.stringify({ lab: { hosts: { dc01: {} }, domains: {} } }));
  assert.strictEqual(parsed.strict, true);
  assert.deepStrictEqual(parsed.repairs, []);
  assert.ok(parsed.lab.hosts.dc01, 'parseLabConfig must return the inner lab object');
});

test('the comma scanner is string-aware, so Windows paths survive intact', () => {
  // A bare /,(\s*[}\]])/g would eat the comma inside this value. This file is
  // full of backslash-heavy Windows paths; corrupting one silently would be a
  // far worse bug than the trailing comma it was trying to fix.
  const value = 'C:\\shares\\all,}';
  const text = JSON.stringify({ lab: { hosts: { a: { hostname: value } }, domains: {} } });
  assert.strictEqual(V.stripTrailingCommas(text), text, 'nothing outside a real trailing comma may change');
  assert.strictEqual(V.parseLabConfig(text).lab.hosts.a.hostname, value);
});

test('an escaped quote does not end the string for the scanner', () => {
  const text = '{"a":"he said \\"hi,\\" ok","b":[1,]}';
  assert.strictEqual(JSON.parse(V.stripTrailingCommas(text)).a, 'he said "hi," ok');
});

test('what we EMIT is strict JSON, tolerance never propagates', () => {
  // The read side forgives; the write side must not, or the next tool in the
  // chain (jq, a linter, a stricter loader) inherits the trap.
  const { lab } = V.parseLabConfig('{"lab":{"hosts":{},"domains":{"a.b":{"dc":"x",}}}}');
  const emitted = V.toStrictJson(lab);
  assert.doesNotThrow(() => JSON.parse(emitted));
  assert.strictEqual(JSON.parse(emitted).lab.domains['a.b'].dc, 'x');
  assert.ok(!/,\s*[}\]]/.test(emitted), 'emitted JSON must carry no trailing comma');
});

test('unparseable text throws rather than degrading to a permissive empty lab', () => {
  assert.throws(() => V.parseLabConfig('{"lab": '), /not parseable/);
});

// ── 2. inventory parsing ────────────────────────────────────────────────────

test('the inventory parser handles comments, empty groups and :vars sections', () => {
  // GOAD's own inventories put a `;` comment immediately after an EMPTY group
  // header ([linux_domain] in ad/GOAD). A parser that took the next non-blank
  // line as a hostname would invent a host called "; domain controler".
  const inv = V.parseInventory([
    '[all:vars]',
    'admin_user=goadadmin',
    '# a hash comment',
    '[domain]',
    'dc01 ansible_host=10.0.0.5',
    '',
    '[linux_domain]',
    '; usage : ad-servers.yml',
    '[dc]',
    'dc01',
  ].join('\n'));
  assert.deepStrictEqual(inv.groups.domain, ['dc01'], 'per-host vars must not become part of the name');
  assert.deepStrictEqual(inv.groups.linux_domain, [], 'an empty group must stay empty');
  assert.deepStrictEqual(inv.groups.dc, ['dc01']);
  assert.strictEqual(inv.vars.admin_user, 'goadadmin');
  assert.ok(!('all' in inv.groups), 'a :vars section is not a host group');
});

// ── 3. roles: existence, shape, never-emit ──────────────────────────────────

test('a misspelled role is rejected — including the hyphen in enable_nbt-ns', () => {
  // The name is used verbatim as `include_role: name=vulns/<x>`, so a typo dies
  // on the lane during the play, an hour after the click that caused it.
  const bad = check((lab) => { lab.hosts.srv01.vulns.push('enable_nbtns'); });
  onlyFinding(bad, 'UNKNOWN_ROLE', 'error');
  const good = check((lab) => { lab.hosts.srv01.vulns.push('enable_nbt-ns'); });
  assert.deepStrictEqual(codesAt(good), [], 'enable_nbt-ns is the one hyphenated role and is real');
});

test('vulns_vars keys must be a subset of the vulns list', () => {
  // This is half of the shipped GOAD `shares` defect: srv02 defines
  // vulns_vars.shares and never lists the role, so the block is dead config
  // that reads like a planted vulnerability.
  const r = check((lab) => {
    lab.hosts.srv01.vulns_vars.credentials = { c: { username: 'r\\u', secret: 's' } };
  });
  onlyFinding(r, 'ORPHAN_ROLE_VARS', 'error');
});

test('security_vars is held to the same subset rule as vulns_vars', () => {
  const r = check((lab) => {
    lab.hosts.dc01.security_vars.ldaps = { c: { pfx: 'c:\\a.pfx', cert_password: 'x' } };
  });
  onlyFinding(r, 'ORPHAN_ROLE_VARS', 'error');
});

test('a missing required item key is rejected — the role reads it with no default', () => {
  const r = check((lab) => { delete lab.hosts.dc01.vulns_vars.adcs_templates.ESC1.template_name; });
  const f = onlyFinding(r, 'MISSING_ROLE_ITEM_KEY', 'error');
  assert.match(f.message, /template_name/);
});

test('directory takes a bare string; every other with_dict role takes an object', () => {
  // `directory` is the odd one out in BOTH namespaces. Handing it an object
  // creates a folder named after the stringified dict.
  const asObject = check((lab) => { lab.hosts.dc01.vulns_vars.directory.setup = { path: 'c:\\setup' }; });
  onlyFinding(asObject, 'WRONG_VARS_SHAPE', 'error');

  const asScalar = check((lab) => { lab.hosts.srv01.vulns_vars.files.bot = 'c:\\bot.ps1'; });
  // The shape error also strands the schedule's file dependency, which is the
  // honest cascade: with no dest there is nothing planted.
  assert.deepStrictEqual(codes(asScalar), ['MISSING_FILE_DEPENDENCY', 'WRONG_VARS_SHAPE'].sort());

  // Both kinds of `directory` are dict_of_scalars, so the security one behaves
  // identically — proof the rule is driven by the manifest, not by a hardcoded
  // vulns-only list.
  assert.strictEqual(loadManifest().roles.filter((r) => r.name === 'directory').length, 2);
});

test('never_emit roles are rejected outright, with the upstream reason attached', () => {
  const shares = check((lab) => {
    lab.hosts.srv01.vulns.push('shares');
    lab.hosts.srv01.vulns_vars.shares = { s: { path: 'C:\\share' } };
  });
  const f = onlyFinding(shares, 'NEVER_EMIT_ROLE', 'error');
  assert.match(f.message, /BROKEN UPSTREAM/, 'the message must carry the manifest reason, not just a code');

  const esc7 = check((lab) => {
    lab.hosts.dc01.vulns.push('adcs_esc7');
    lab.hosts.dc01.vulns_vars.adcs_esc7 = { v: { ca_manager: 'range\\viserys' } };
  });
  onlyFinding(esc7, 'NEVER_EMIT_ROLE', 'error');
});

test('a with_dict role with no vars entry WARNS — it is a no-op, not a build failure', () => {
  // Erroring here would reject GOAD and GOAD-Light, which both list `shares` on
  // dc02 with no vulns_vars.shares. The role loops an empty dict, plants
  // nothing, and Ansible prints green — worth saying, not worth refusing.
  const r = check((lab) => { lab.hosts.srv01.vulns.push('credentials'); });
  const f = onlyFinding(r, 'ROLE_VARS_MISSING', 'warning');
  assert.match(f.message, /green|no-?op|plants nothing/i);
  assert.strictEqual(r.errors.length, 0);
});

test('vars for a role that reads none are flagged as ignored config', () => {
  const r = check((lab) => {
    lab.hosts.srv01.vulns.push('smbv1');
    lab.hosts.srv01.vulns_vars.smbv1 = { enabled: true };
  });
  onlyFinding(r, 'UNUSED_ROLE_VARS', 'warning');
});

// ── 4. role ORDER inside one host's vulns array ─────────────────────────────

test('the vulns array IS the execution order, and four pairs depend on it', () => {
  const swap = (list, a, b) => {
    const i = list.indexOf(a); const j = list.indexOf(b);
    list[i] = b; list[j] = a;
  };
  // files must precede adcs_templates (it stages the template JSON)…
  const tpl = check((lab) => { swap(lab.hosts.dc01.vulns, 'files', 'adcs_templates'); });
  assert.ok(codes(tpl).includes('ROLE_ORDER'));

  // …and schedule (it stages the script the task runs)…
  const sched = check((lab) => { swap(lab.hosts.srv01.vulns, 'files', 'schedule'); });
  assert.deepStrictEqual(codes(sched), ['ROLE_ORDER']);

  // …and permissions, along with directory (both create what it ACLs).
  const perms = check((lab) => {
    lab.hosts.dc01.vulns = ['permissions', 'directory', 'files', 'adcs_templates'];
  });
  assert.strictEqual(perms.findings.filter((f) => f.code === 'ROLE_ORDER').length, 2,
    'permissions before BOTH files and directory is two distinct broken dependencies');
});

// ── 5. same-host file dependencies ──────────────────────────────────────────

test('adcs_templates must import a path some files entry actually copied', () => {
  const r = check((lab) => {
    lab.hosts.dc01.vulns_vars.adcs_templates.ESC1.template_file = 'C:\\elsewhere\\ESC1.json';
  });
  const f = onlyFinding(r, 'MISSING_FILE_DEPENDENCY', 'error');
  assert.match(f.message, /c:\\setup\\/i, 'the message must name what WAS planted, or it is not diagnostic');
});

test('a dest ending in a backslash is a DIRECTORY copy, so matching is prefix-aware', () => {
  // GOAD-Light and GOAD-Mini both plant `dc01/templates/` at `C:\setup\` and
  // then ask for `C:\setup\ESC1.json`. An equality-only check rejects both.
  const dirCopy = check(null);
  assert.deepStrictEqual(codesAt(dirCopy), []);

  // Remove the trailing backslash and the same dest is a single FILE named
  // C:\setup — which does not contain ESC1.json.
  const fileCopy = check((lab) => { lab.hosts.dc01.vulns_vars.files.tpl.dest = 'C:\\setup'; });
  assert.deepStrictEqual(codes(fileCopy), ['MISSING_FILE_DEPENDENCY']);
});

test('a scheduled cmd is a command line, so the planted path is matched inside it', () => {
  // `powershell c:\bot.ps1` never equals `c:\bot.ps1`. Case and slash direction
  // are both normalised, because Windows treats them as equal and the lab data
  // mixes `c:\` and `C:\` freely.
  const mixedCase = check((lab) => {
    lab.hosts.srv01.vulns_vars.schedule.bot.cmd = 'PowerShell -File C:/BOT.PS1';
  });
  assert.deepStrictEqual(codesAt(mixedCase), []);

  const orphaned = check((lab) => {
    lab.hosts.srv01.vulns_vars.schedule.bot.cmd = 'powershell c:\\never-copied.ps1';
  });
  onlyFinding(orphaned, 'MISSING_FILE_DEPENDENCY', 'error');
});

// ── 6. DC identity and the inventory cross-check ────────────────────────────

test("a domain's dc must be a host, and that host must be type 'dc'", () => {
  const missing = check((lab) => { lab.domains['range.local'].dc = 'dc99'; });
  assert.ok(codes(missing).includes('DOMAIN_DC_UNKNOWN'));

  const wrongType = check((lab) => { lab.domains['range.local'].dc = 'srv01'; });
  assert.ok(codes(wrongType).includes('DOMAIN_DC_NOT_DC'));
});

test('[dc] membership and type:dc must agree in both directions', () => {
  const notListed = check(null, { inventory: BASE_INVENTORY.replace(/\[dc\]\ndc01/, '[dc]') });
  assert.deepStrictEqual(codes(notListed), ['DC_NOT_IN_INVENTORY_DC']);

  const listedButNotDc = check(null, { inventory: BASE_INVENTORY.replace('[dc]\ndc01', '[dc]\ndc01\nsrv01') });
  assert.deepStrictEqual(codes(listedButNotDc), ['INVENTORY_DC_NOT_TYPED_DC']);
});

test('a config host that no playbook targets is rejected', () => {
  const r = check(null, { inventory: BASE_INVENTORY.replace('dc01\nsrv01', 'dc01') });
  assert.deepStrictEqual(codes(r), ['HOST_NOT_IN_INVENTORY']);
});

test('an inventory host with no config entry is rejected — but only in the member groups', () => {
  const undeclared = check(null, { inventory: `${BASE_INVENTORY.replace('[dc]', '[dc]')}`.replace('dc01\nsrv01', 'dc01\nsrv01\nsrv99') });
  assert.deepStrictEqual(codes(undeclared), ['INVENTORY_HOST_UNDECLARED']);

  // THE SCOPING THAT MATTERS: SCCM's inventory puts `elk` in [elk_server] and
  // declares it nowhere in config.json, because it is a Linux appliance built by
  // elk.yml rather than an AD member. An unscoped inverse rule rejects a lab
  // upstream deploys every day.
  const appliance = check(null, { inventory: `${BASE_INVENTORY}\n\n[elk_server]\nelk\n\n[elk_log]\ndc01` });
  assert.deepStrictEqual(codesAt(appliance), []);
  assert.deepStrictEqual(V.MEMBER_GROUPS, ['domain', 'linux_domain']);
});

test('a Linux member declared in [linux_domain] satisfies the membership rule', () => {
  // DRACARYS's lx01 lives only there. Dropping linux_domain from MEMBER_GROUPS
  // would reject it.
  const r = check(
    (lab) => {
      lab.hosts.lx01 = {
        hostname: 'lab-lx01', type: 'server', os: 'linux',
        domain: 'range.local', path: 'DC=range,DC=local',
        local_admin_password: 'Zx9@Lq3-Wt7v',
      };
    },
    { inventory: BASE_INVENTORY.replace('[linux_domain]\n', '[linux_domain]\nlx01\n') });
  assert.deepStrictEqual(codesAt(r), []);
});

test('with no inventory the cross-checks are skipped LOUDLY, not silently', () => {
  // "Zero errors" must never be able to mean "that half never ran".
  const r = V.validateLab({ lab: baseLab(), labName: 'FIXTURE' });
  assert.deepStrictEqual(codes(r), ['INVENTORY_NOT_CHECKED']);
  assert.strictEqual(r.errors.length, 0);
});

// ── 7. passwords ────────────────────────────────────────────────────────────

test("the DC's local_admin_password must equal its domain's domain_password", () => {
  // Holds in all 12 upstream domains. The DC is promoted with its local
  // credential and every child-domain dcpromo re-uses it, so a mismatch fails
  // the promotion with an error naming neither field.
  const r = check((lab) => { lab.hosts.dc01.local_admin_password = 'Different#9xQz'; });
  assert.deepStrictEqual(codes(r), ['DC_PASSWORD_MISMATCH']);
});

test('domain_password must satisfy the DEFAULT policy, not the relaxed one', () => {
  // It is win_domain's safe_mode_password, set five playbooks before
  // password_policy loosens anything, so the lab's own relaxation is irrelevant.
  const r = check((lab) => {
    lab.domains['range.local'].domain_password = 'lowercaseonly';
    lab.hosts.dc01.local_admin_password = 'lowercaseonly';   // keep the pair equal
  });
  assert.deepStrictEqual(codes(r), ['WEAK_DOMAIN_PASSWORD', 'WEAK_LOCAL_ADMIN_PASSWORD'].sort());

  const short = check((lab) => {
    lab.domains['range.local'].domain_password = 'Ab1#de';   // 3 classes, 6 chars
    lab.hosts.dc01.local_admin_password = 'Ab1#de';
  });
  assert.deepStrictEqual(codes(short), ['WEAK_DOMAIN_PASSWORD', 'WEAK_LOCAL_ADMIN_PASSWORD'].sort());
});

test('users[].password is deliberately NOT policed — that is where weak lab creds belong', () => {
  // password_policy runs before the users are created, so "football" is legal
  // and load-bearing: half the lab's attack paths are a spray away.
  const r = check((lab) => { lab.domains['range.local'].users['bob.reed'].password = 'a'; });
  assert.deepStrictEqual(codesAt(r), []);
});

test('local_admin_password must not contain a token of the account name', () => {
  const r = check((lab) => { lab.hosts.srv01.local_admin_password = 'Administrator#1'; });
  assert.deepStrictEqual(codes(r), ['LOCAL_ADMIN_PASSWORD_CONTAINS_ACCOUNT']);

  // Windows splits the account name on , . - _ # and whitespace and only
  // rejects tokens longer than two characters, so a renamed admin changes the
  // answer — hence admin_user comes from the inventory, not a constant.
  assert.deepStrictEqual(V.accountNameTokens('svc.backup-01'), ['svc', 'backup']);
  assert.strictEqual(V.containsAccountName('Backup2024!', 'svc.backup-01'), true);
  assert.strictEqual(V.containsAccountName('Backup2024!', 'administrator'), false);
  const renamed = check(
    (lab) => { lab.hosts.srv01.local_admin_password = 'Backup2024!'; },
    { adminUser: 'svc.backup-01' });
  assert.deepStrictEqual(codes(renamed), ['LOCAL_ADMIN_PASSWORD_CONTAINS_ACCOUNT']);
});

test('passwordClasses counts the four Windows categories', () => {
  assert.strictEqual(V.passwordClasses('abc'), 1);
  assert.strictEqual(V.passwordClasses('Abc'), 2);
  assert.strictEqual(V.passwordClasses('Abc1'), 3);
  assert.strictEqual(V.passwordClasses('Abc1!'), 4);
  assert.strictEqual(V.passwordClasses('dc_and_domain_password'), 2, 'underscore is one class, not two');
});

// ── 8. names ────────────────────────────────────────────────────────────────

test('sAMAccountName is capped at 20 and the dict key IS the sAMAccountName', () => {
  // roles/onlyusers passes `name: item.key` to win_domain_user, which derives
  // sam from name — so the key carries both the CN and the sAM limit, and the
  // tighter one binds.
  const r = check((lab) => {
    lab.domains['range.local'].users['a.very.long.account.name'] =
      clone(lab.domains['range.local'].users['bob.reed']);
  });
  assert.deepStrictEqual(codes(r), ['SAM_ACCOUNT_NAME_TOO_LONG']);
  assert.strictEqual(V.MAX_SAM_ACCOUNT_NAME, 20);
});

test('a group CN is capped at 64', () => {
  const r = check((lab) => {
    lab.domains['range.local'].groups.global['G'.repeat(65)] = { path: 'CN=Users,DC=range,DC=local' };
  });
  assert.deepStrictEqual(codes(r), ['COMMON_NAME_TOO_LONG']);
});

test('hostnames are NetBIOS-legal, 15 characters, and unique lab-wide', () => {
  const long = check((lab) => { lab.hosts.srv01.hostname = 'LAB-SRV-TOO-LONG'; });
  assert.deepStrictEqual(codes(long), ['HOSTNAME_TOO_LONG']);

  const illegal = check((lab) => { lab.hosts.srv01.hostname = 'lab_srv01'; });
  assert.deepStrictEqual(codes(illegal), ['HOSTNAME_CHARSET']);

  // Case-insensitive: Windows does not consider these two different machines,
  // and the second join renames the first out of the domain.
  const dupe = check((lab) => { lab.hosts.srv01.hostname = 'lab-dc01'; });
  assert.deepStrictEqual(codes(dupe), ['HOSTNAME_DUPLICATE']);
});

// ── 9. ACLs ─────────────────────────────────────────────────────────────────

test('an unrecognised right is an ERROR, because the failure is invisible', () => {
  // PowerShell matches with an ordinal Array.Contains, so 'genericall' is not
  // 'GenericAll': $ace is never assigned, the task sets Changed=false, and
  // Ansible reports GREEN. A typo is indistinguishable from a correct
  // idempotent run, which is precisely why it cannot be a warning.
  const r = check((lab) => { lab.domains['range.local'].acls.genericwrite_alice_bob.right = 'genericall'; });
  const f = onlyFinding(r, 'UNKNOWN_ACL_RIGHT', 'error');
  assert.strictEqual(f.severity, 'error');
  assert.match(f.message, /case-sensitive/);
});

test('the domain and host right vocabularies are never merged', () => {
  // Ext-ManageCA is the sanctioned workaround for the broken adcs_esc7 role and
  // exists ONLY in the domain vocabulary. Feeding it to the host-level acls role
  // produces no ACE and a green task — the exact failure the split prevents.
  const atDomain = check((lab) => {
    lab.domains['range.local'].acls.genericwrite_alice_bob.right = 'Ext-ManageCA';
  });
  assert.deepStrictEqual(codesAt(atDomain), [], 'Ext-ManageCA is legal at the domain level');

  const atHost = check((lab) => {
    lab.hosts.dc01.vulns.push('acls');
    lab.hosts.dc01.vulns_vars.acls = {
      ca: { for: 'alice.stone', to: 'CN=Enrollment', right: 'Ext-ManageCA', inheritance: 'None' },
    };
  });
  const f = onlyFinding(atHost, 'UNKNOWN_ACL_RIGHT', 'error');
  assert.match(f.message, /only in the DOMAIN vocabulary/,
    'the message must say WHERE the right is valid, or the reader just retries it');
});

test('a host-level acls entry is validated against the host vocabulary', () => {
  const ok = check((lab) => {
    lab.hosts.dc01.vulns.push('acls');
    lab.hosts.dc01.vulns_vars.acls = {
      g: { for: 'Operators', to: 'CN=Foo', right: 'GenericAll', inheritance: 'None' },
    };
  });
  assert.deepStrictEqual(codesAt(ok), []);
});

test('all four ACL keys are mandatory — one missing kills the whole play', () => {
  // roles/acl indexes for/to/right/inheritance with no defaults, so a single
  // missing key aborts ad-acl.yml rather than skipping one entry.
  for (const key of ['for', 'to', 'right', 'inheritance']) {
    const r = check((lab) => { delete lab.domains['range.local'].acls.genericwrite_alice_bob[key]; });
    assert.ok(codes(r).includes('MISSING_ACL_KEY'), `omitting '${key}' must be rejected`);
  }
});

test('inheritance is validated against the enum the cast accepts', () => {
  // Unlike `right`, a bad inheritance THROWS (the [ActiveDirectorySecurityInheritance]
  // cast), so this one is loud — but catching it here still beats catching it an
  // hour into a deploy. The cast is case-insensitive and spelling-strict:
  // 'Descendents' is Microsoft's spelling.
  const wrong = check((lab) => { lab.domains['range.local'].acls.genericwrite_alice_bob.inheritance = 'Descendants'; });
  onlyFinding(wrong, 'UNKNOWN_ACL_INHERITANCE', 'error');

  const casing = check((lab) => { lab.domains['range.local'].acls.genericwrite_alice_bob.inheritance = 'all'; });
  assert.deepStrictEqual(codesAt(casing), []);
});

test('a zero-member group holding an ACL nobody can reach is a dead edge', () => {
  // WARNING, not an error: the ACE is planted and the deploy is green. What is
  // broken is the attack path. A zero-member group is not by itself suspicious —
  // GOAD deliberately empties the groups you are meant to add yourself to — so
  // the discriminator is whether ANYTHING grants membership.
  const dead = check((lab) => {
    const d = lab.domains['range.local'];
    d.groups.domainlocal.Orphans = { path: 'CN=Users,DC=range,DC=local' };
    d.acls.orphan_edge = { for: 'Orphans', to: 'LAB-DC01$', right: 'GenericAll', inheritance: 'None' };
  });
  const f = onlyFinding(dead, 'DEAD_ACL_EDGE', 'warning');
  assert.match(f.message, /Orphans/);

  // Each of the three ways to gain membership must exempt it, or the rule is
  // noise on every lab GOAD ships.
  const viaUser = check((lab) => {
    const d = lab.domains['range.local'];
    d.groups.domainlocal.Orphans = { path: 'CN=Users,DC=range,DC=local' };
    d.acls.orphan_edge = { for: 'Orphans', to: 'LAB-DC01$', right: 'GenericAll', inheritance: 'None' };
    d.users['bob.reed'].groups = ['Orphans'];
  });
  assert.deepStrictEqual(codesAt(viaUser), []);

  const viaMembers = check((lab) => {
    const d = lab.domains['range.local'];
    d.groups.domainlocal.Orphans = { path: 'CN=Users,DC=range,DC=local', members: ['RANGE\\LAB-SRV01$'] };
    d.acls.orphan_edge = { for: 'Orphans', to: 'LAB-DC01$', right: 'GenericAll', inheritance: 'None' };
  });
  assert.deepStrictEqual(codesAt(viaMembers), []);

  const viaCrossDomain = check((lab) => {
    const d = lab.domains['range.local'];
    d.groups.domainlocal.Orphans = { path: 'CN=Users,DC=range,DC=local' };
    d.acls.orphan_edge = { for: 'Orphans', to: 'LAB-DC01$', right: 'GenericAll', inheritance: 'None' };
    d.multi_domain_groups_member.Orphans = ['other.local\\intruder'];
  });
  assert.deepStrictEqual(codesAt(viaCrossDomain), []);

  const viaInboundAcl = check((lab) => {
    const d = lab.domains['range.local'];
    d.groups.domainlocal.Orphans = { path: 'CN=Users,DC=range,DC=local' };
    d.acls.orphan_edge = { for: 'Orphans', to: 'LAB-DC01$', right: 'GenericAll', inheritance: 'None' };
    d.acls.join_it = { for: 'alice.stone', to: 'Orphans', right: 'Ext-Write-Self-Membership', inheritance: 'All' };
  });
  assert.deepStrictEqual(codesAt(viaInboundAcl), [],
    'a group you can add yourself to is the whole point of GOAD, not a defect');
});

// ── 10. containers ──────────────────────────────────────────────────────────

test('every user, group and OU path must resolve to a container this config creates', () => {
  // AD does not create intermediate OUs; the object is simply never made.
  const user = check((lab) => {
    lab.domains['range.local'].users['bob.reed'].path = 'OU=Nowhere,DC=range,DC=local';
  });
  assert.deepStrictEqual(codes(user), ['UNRESOLVED_CONTAINER_PATH']);

  const group = check((lab) => {
    lab.domains['range.local'].groups.global.Operators.path = 'OU=Nowhere,DC=range,DC=local';
  });
  assert.deepStrictEqual(codes(group), ['UNRESOLVED_CONTAINER_PATH']);

  const nestedOu = check((lab) => {
    lab.domains['range.local'].organisation_units.Sub = { path: 'OU=Missing,DC=range,DC=local' };
  });
  assert.deepStrictEqual(codes(nestedOu), ['UNRESOLVED_CONTAINER_PATH']);

  // A declared OU nested under another declared OU resolves, whatever the
  // declaration order.
  const nestedOk = check((lab) => {
    lab.domains['range.local'].organisation_units.Sub = { path: 'OU=Field,DC=range,DC=local' };
    lab.domains['range.local'].users['bob.reed'].path = 'OU=Sub,OU=Field,DC=range,DC=local';
  });
  assert.deepStrictEqual(codesAt(nestedOk), []);
});

test('the domain root DN is derived from the FQDN and compared case-insensitively', () => {
  // GOAD declares north.sevenkingdoms.local's paths as `DC=North,…`. A
  // case-sensitive compare rejects a lab that has shipped for years.
  assert.strictEqual(V.rootDnForDomain('north.sevenkingdoms.local'), 'DC=north,DC=sevenkingdoms,DC=local');
  assert.strictEqual(V.normalizeDn('DC=North, DC=Sevenkingdoms ,DC=Local'), 'dc=north,dc=sevenkingdoms,dc=local');
  const r = check((lab) => { lab.domains['range.local'].users['bob.reed'].path = 'dc=RANGE,dc=local'; });
  assert.deepStrictEqual(codesAt(r), []);
});

// ── 11. the boundary ────────────────────────────────────────────────────────

test('assertLabCompiles throws a 409 with a stable code and the full findings', () => {
  let err = null;
  try {
    V.assertLabCompiles({
      lab: (() => { const l = baseLab(); l.hosts.srv01.vulns.push('enable_nbtns'); return l; })(),
      inventory: BASE_INVENTORY,
      labName: 'FIXTURE',
    });
  } catch (caught) {
    err = caught;
  }
  assert.ok(err, 'a lab with a blocking error must not return normally');
  assert.strictEqual(err.status, 409);
  assert.strictEqual(err.code, 'LAB_DEFINITION_INVALID');
  assert.strictEqual(err.errors.length, 1);
  assert.strictEqual(err.errors[0].code, 'UNKNOWN_ROLE');
  assert.ok(Array.isArray(err.warnings), 'a UI must be able to render the warnings too');
  assert.match(err.message, /FIXTURE/);
});

test('warnings never throw — two shipped labs would be unbuildable if they did', () => {
  const result = V.assertLabCompiles({
    lab: (() => { const l = baseLab(); l.hosts.srv01.vulns.push('credentials'); return l; })(),
    inventory: BASE_INVENTORY,
    labName: 'FIXTURE',
  });
  assert.strictEqual(result.warnings.length, 1);
  assert.strictEqual(result.errors.length, 0);
});

test('the core never throws, whatever it is handed', () => {
  // It is called from a generation loop; one malformed lab must not take the
  // batch down.
  for (const junk of [undefined, null, {}, { lab: null }, { lab: 'nope' }, { lab: [] }]) {
    const r = V.validateLab(junk);
    assert.ok(Array.isArray(r.errors) && Array.isArray(r.warnings));
  }
  assert.strictEqual(V.validateLab({ lab: 'nope' }).errors[0].code, 'LAB_NOT_AN_OBJECT');
});

test('every finding is shaped for a UI and names a remedy', () => {
  const r = check((lab) => {
    lab.hosts.srv01.vulns.push('enable_nbtns');
    lab.hosts.srv01.hostname = 'lab_srv01';
    lab.domains['range.local'].acls.genericwrite_alice_bob.right = 'genericall';
  });
  assert.ok(r.findings.length >= 3);
  for (const f of r.findings) {
    assert.match(f.code, /^[A-Z][A-Z0-9_]*$/, `code ${f.code} is not SCREAMING_SNAKE`);
    assert.ok(['error', 'warning'].includes(f.severity));
    assert.ok(f.id && typeof f.id === 'string');
    // The message is read in a toast by an instructor, not by whoever wrote the
    // validator: it has to say what is wrong AND what to do about it.
    assert.ok(f.message.length > 80, `message too terse to be actionable: ${f.message}`);
    assert.match(f.message, /\b(Add|Remove|Set|Use|Move|Fix|Shorten|Replace|Delete|Give|Make|Point|Declare|Wrap|Register|Pass|pick)\b/,
      `message names no remedy: ${f.message}`);
  }
  assert.deepStrictEqual(r.findings, r.errors.concat(r.warnings));
});

// ── 11b. generated labs: is there anything in here to attack? ───────────────
//
// THE HOLE THIS SECTION CLOSES. Every rule above asks "does this deploy?". A
// generated lab with `acls: {}` and a null chain answers yes — it deploys green,
// a student logs in to a working domain with a full roster and nothing to
// attack, and no rule in this file, in pre-flight, or on the lane says a word.
// It is the same silence as an unrecognised ACL right, one level up.
//
// AND THE TRAP THAT MAKES IT NON-TRIVIAL: the obvious rule, "a lab must have
// ACLs", rejects labs that ship and deploy. SCCM has zero ACL edges and zero OUs
// by design; DRACARYS has exactly one. Both are in the calibrated corpus below
// at zero findings. So the rule is scoped by a DECLARED mode rather than by a
// heuristic over the lab's contents — a heuristic that guesses wrong either
// breaks that baseline or lets a chainless generated lab through, and both
// failures are silent.

test('the mode is declared, never inferred — and the default is reference', () => {
  // The whole design rests on this: nothing about the lab decides which rules
  // run. A caller that says nothing gets the deploy rules and only those, which
  // is what keeps every existing caller (and the corpus) unchanged.
  const implicit = check(null);
  const explicit = check(null, { mode: V.MODE_REFERENCE });
  assert.deepStrictEqual(codesAt(implicit), []);
  assert.deepStrictEqual(codesAt(explicit), codesAt(implicit),
    'the default must BE reference mode, not merely resemble it');
  assert.deepStrictEqual(V.VALIDATION_MODES, ['reference', 'generated']);

  // An unrecognised mode is a BLOCKING ERROR, not a quiet fall back to
  // reference. Falling back would mean a typo'd 'Generated' skips every chain
  // rule and reports the lab clean — the exact silence the mode exists to end,
  // reintroduced by the mechanism meant to remove it.
  const typo = check(null, { mode: 'Generated' });
  const f = onlyFinding(typo, 'VALIDATION_MODE_UNKNOWN', 'error');
  assert.match(f.message, /generated/);

  // And it is reported even when the lab itself is unusable, because those two
  // mistakes travel together and naming only the second sends the reader to the
  // wrong file.
  const junk = V.validateLab({ lab: 'nope', mode: 'whatever', labName: 'FIXTURE' });
  assert.ok(codes(junk).includes('VALIDATION_MODE_UNKNOWN'));
  assert.ok(codes(junk).includes('LAB_NOT_AN_OBJECT'));
});

test('a lab with no ACLs at all is clean in reference mode — SCCM depends on it', () => {
  // The false-positive that a heuristic would produce, proven without the
  // corpus checkout. SCCM ships 0 ACL edges and 0 OUs and deploys every day; a
  // rule that read an empty acls block as "nothing to attack" would reject it
  // and the first thing anyone would do is turn the rule off.
  const r = check((lab) => { lab.domains['range.local'].acls = {}; });
  assert.deepStrictEqual(codesAt(r), []);
});

test('the unmutated generated fixture is clean — in BOTH modes', () => {
  // Same requirement as the base fixture: every rejection below is only
  // meaningful if this holds. The second half is the stronger claim — generated
  // mode ADDS rules and changes none, so a lab that satisfies them is still
  // exactly as clean as it was.
  assert.deepStrictEqual(codesAt(checkGenerated(null)), []);
  assert.deepStrictEqual(codesAt(checkGenerated(null, { mode: V.MODE_REFERENCE })), []);
});

test('a generated lab with an empty acls block and no chain is REJECTED', () => {
  // The headline defect, exactly as reported: this lab passes every deploy rule
  // and would bake green.
  const r = checkGenerated((b) => {
    b.lab.domains['range.local'].acls = {};
    b.chain = null;
    b.foothold = null;
  });
  assert.deepStrictEqual(codes(r), ['CHAIN_MISSING', 'FOOTHOLD_MISSING'].sort());
  assert.strictEqual(r.warnings.length, 0, 'a lab with nothing to attack is not a warning');
  assert.match(r.findings.find((x) => x.code === 'CHAIN_MISSING').message, /green/,
    'the message has to name the failure mode — it deploys — or it reads as pedantry');

  // The same lab in reference mode is clean, which is the entire point of the
  // split: this is not a lab that is broken, it is a lab that is not an
  // exercise, and only the caller knows which of those it asked for.
  const asReference = checkGenerated(
    (b) => { b.lab.domains['range.local'].acls = {}; b.chain = null; b.foothold = null; },
    { mode: V.MODE_REFERENCE });
  assert.deepStrictEqual(codesAt(asReference), []);
});

test('a chain with no edges is rejected as loudly as no chain at all', () => {
  const r = checkGenerated((b) => { b.chain.edges = []; });
  // The objective check needs edges to walk, so it stands down rather than
  // piling a second, less specific finding on top of the specific one.
  const f = onlyFinding(r, 'CHAIN_EMPTY', 'error');
  assert.match(f.message, /Add/);
});

test('every producer the chain names must be a role the manifest can produce', () => {
  // Same class as UNKNOWN_ROLE, one level up: the chain describes a hop, the
  // role behind it does not exist, and the answer key documents an ACE that was
  // never written.
  const typo = checkGenerated((b) => { b.chain.edges[0].created_by.role = 'vulns/acl_'; });
  const unknown = onlyFinding(typo, 'CHAIN_EDGE_ROLE_UNKNOWN', 'error');
  assert.match(unknown.message, new RegExp(loadManifest().goad_ref.slice(0, 12)),
    'the message must name the ref the role library was vendored at');

  // never_emit is its own code, because the remedy is different: the name is
  // real, the role is broken upstream, and the play reports GREEN having planted
  // nothing. `shares` is one of the two the manifest marks.
  const broken = checkGenerated((b) => { b.chain.edges[0].created_by.role = 'vulns/shares'; });
  const never = onlyFinding(broken, 'CHAIN_EDGE_ROLE_NEVER_EMIT', 'error');
  assert.match(never.message, /BROKEN UPSTREAM/,
    'the manifest reason has to travel with the finding, not just the code');

  // Prerequisites are held to the same rule. An ESC1 edge whose template JSON is
  // staged by a role that does not exist plants no template, and the certificate
  // hop the answer key describes cannot be walked.
  const pre = checkGenerated((b) => {
    b.chain.edges[0].prerequisites = [{ role: 'vulns/copyfiles', host: 'dc01', item: 'x', item_vars: {} }];
  });
  assert.deepStrictEqual(codes(pre), ['CHAIN_EDGE_ROLE_UNKNOWN']);

  // And the three config.json-driven producers are NOT unknown roles. They are
  // absent from the vendored manifest because no generator picks them — every
  // lab runs them — so a validator that only consulted getRole() would reject
  // every ACL edge ever designed.
  assert.deepStrictEqual(Object.keys(V.CORE_CHAIN_ROLES).sort(), ['acl', 'onlyusers', 'ps']);
  for (const role of Object.keys(V.CORE_CHAIN_ROLES)) {
    assert.strictEqual(require(path.join(
      ROOT, 'modules/crucible/plugins/ciab/utils/goad-role-manifest.js')).getRole(role), null,
    `${role} must be absent from manifest.roles, or CORE_CHAIN_ROLES is papering over a real lookup`);
  }
  const core = checkGenerated((b) => {
    b.chain.edges[0].created_by.role = 'acl';
    b.chain.start.plants[0].role = 'onlyusers';
  });
  assert.deepStrictEqual(codesAt(core), []);
});

test('a chain edge with no corresponding emitted ACL is rejected', () => {
  // THE TWO-CODE-PATHS CHECK. The chain is written by the ACL designer and the
  // acls block by the composer's lowering step; each is self-consistent on its
  // own, and only comparing them catches an edge that was designed and never
  // emitted. On the lane that is an ACE nobody plants and a BloodHound graph
  // missing the arrow the answer key sends the student to find.
  const dropped = checkGenerated((b) => {
    delete b.lab.domains['range.local'].acls.genericall_bob_operators;
  });
  const f = onlyFinding(dropped, 'CHAIN_ACL_NOT_EMITTED', 'error');
  assert.match(f.message, /genericall_bob_operators/);
  assert.match(f.message, /different code paths/,
    'the message must say WHY the two have to agree, or the fix is to delete the check');

  // Every edge, not just the first one found.
  const emptied = checkGenerated((b) => { b.lab.domains['range.local'].acls = {}; });
  assert.deepStrictEqual(codes(emptied), ['CHAIN_ACL_NOT_EMITTED', 'CHAIN_ACL_NOT_EMITTED']);

  // …and a domain block with NO acls key is an EMPTY acls block, not an unknown
  // one. Standing down there would skip the cross-check on precisely the lab
  // this rule exists for, and it would skip it in silence.
  const absent = checkGenerated((b) => { delete b.lab.domains['range.local'].acls; });
  assert.deepStrictEqual(codes(absent), ['CHAIN_ACL_NOT_EMITTED', 'CHAIN_ACL_NOT_EMITTED']);

  // Present under the right key but not the right ACE. The planted ACE is the
  // lab's and the documented one is the chain's, so the student is sent to look
  // for an edge that is not the edge that exists.
  const drifted = checkGenerated((b) => {
    b.lab.domains['range.local'].acls.genericall_bob_operators.right = 'WriteDacl';
  });
  const m = onlyFinding(drifted, 'CHAIN_ACL_MISMATCH', 'error');
  assert.match(m.message, /GenericAll/);
  assert.match(m.message, /WriteDacl/);

  // `right` is compared EXACTLY — upstream matches it with PowerShell's ordinal
  // Array.Contains, so 'genericall' is not 'GenericAll' — while inheritance is
  // compared case-insensitively, because the cast that consumes it is. Getting
  // these two backwards is a false positive on one side and a missed silent
  // no-op on the other.
  assert.deepStrictEqual(codes(checkGenerated((b) => {
    b.lab.domains['range.local'].acls.genericall_bob_operators.right = 'genericall';
  })), ['CHAIN_ACL_MISMATCH', 'UNKNOWN_ACL_RIGHT'].sort());
  assert.deepStrictEqual(codesAt(checkGenerated((b) => {
    b.lab.domains['range.local'].acls.genericall_bob_operators.inheritance = 'all';
  })), []);

  // Principals compare the way AD resolves them: case-insensitively, and a
  // `DOMAIN\` prefix on one side is the same account as the bare name on the
  // other. GOAD writes principals both ways in one file.
  assert.deepStrictEqual(codesAt(checkGenerated((b) => {
    b.chain.edges[1].created_by.item_vars.for = 'RANGE\\Bob.Reed';
  })), []);
});

test('a chain rooted at a credential the lab does not create is rejected', () => {
  // Direction one: the roster does not contain the account the website leaks.
  // The student sprays it, gets a logon failure, and the exercise has no second
  // act — nothing in the deploy reports that.
  const missing = checkGenerated((b) => { delete b.lab.domains['range.local'].users['alice.stone']; });
  const f = missing.findings.find((x) => x.code === 'FOOTHOLD_PRINCIPAL_MISSING');
  assert.ok(f, `expected FOOTHOLD_PRINCIPAL_MISSING, got ${JSON.stringify(codesAt(missing))}`);
  assert.strictEqual(f.severity, 'error');
  assert.match(f.message, /bob\.reed/, 'the message must name the roster that IS there');

  // A domain the lab never declares fails the same way and says so.
  const wrongDomain = checkGenerated((b) => { b.foothold.domain = 'other.local'; });
  assert.deepStrictEqual(codes(wrongDomain), ['FOOTHOLD_PRINCIPAL_MISSING']);

  // Direction two: the lab creates the credential, and the chain starts
  // somewhere else. Same dead end, arrived at from the other side. Note that
  // starting at bob.reed still REACHES the objective — the graph is fine, it is
  // rooted where the student cannot stand — which is why rootedness is its own
  // rule rather than something the reachability walk would have caught.
  const elsewhere = checkGenerated((b) => { b.chain.start.principal = 'bob.reed'; });
  assert.deepStrictEqual(codes(elsewhere), ['CHAIN_NOT_ROOTED_AT_FOOTHOLD']);

  // Start at an account nobody has and both rules fire, which is the honest
  // cascade: a graph rooted nowhere arrives nowhere.
  const nobody = checkGenerated((b) => { b.chain.start.principal = 'ghost.user'; });
  assert.deepStrictEqual(codes(nobody),
    ['CHAIN_NOT_ROOTED_AT_FOOTHOLD', 'CHAIN_OBJECTIVE_UNREACHED'].sort());

  // Direction three: the names agree and no edge leaves the start, so the chain
  // names the right account and never uses it.
  const stranded = checkGenerated((b) => { b.chain.edges[0].from = 'bob.reed'; });
  assert.ok(codes(stranded).includes('CHAIN_NOT_ROOTED_AT_FOOTHOLD'));

  // Case and the DOMAIN\ prefix do not make it a different account.
  assert.deepStrictEqual(codesAt(checkGenerated((b) => {
    b.chain.start.principal = 'RANGE\\Alice.Stone';
  })), []);

  // And generated mode refuses to run half-checked: no foothold at all is an
  // error, not a skipped rule, because "zero findings" must never be able to
  // mean "that half never ran".
  const noFoothold = checkGenerated((b) => { b.foothold = null; });
  const nf = onlyFinding(noFoothold, 'FOOTHOLD_MISSING', 'error');
  assert.match(nf.message, /Pass/);
});

test('the chain has to reach its declared objective, over its own edges', () => {
  const short = checkGenerated((b) => { b.chain.objective.target = 'Nobody-In-Particular'; });
  const f = onlyFinding(short, 'CHAIN_OBJECTIVE_UNREACHED', 'error');
  assert.match(f.message, /alice\.stone/);

  const unstated = checkGenerated((b) => { b.chain.objective = { kind: 'group_control' }; });
  onlyFinding(unstated, 'CHAIN_OBJECTIVE_MISSING', 'error');

  // DECOYS DO NOT COUNT. A decoy that reaches the objective is a second
  // solution, not a decoy — so the walk is over chain.edges only, and this is
  // the case that tells the two apart: the spine stops short while a decoy runs
  // straight to the goal.
  const viaDecoy = checkGenerated((b) => {
    b.chain.edges[1].to = 'bob.reed';
    b.chain.edges[1].created_by.item_vars.to = 'bob.reed';
    b.lab.domains['range.local'].acls.genericall_bob_operators.to = 'bob.reed';
    b.lab.domains['range.local'].acls.decoy_alice_operators = {
      for: 'alice.stone', to: 'Operators', right: 'WriteOwner', inheritance: 'All',
    };
    b.chain.decoys = [{
      id: 'decoy_0',
      from: 'alice.stone',
      to: 'Operators',
      edge_type: 'acl',
      created_by: {
        role: 'acl',
        host: 'dc01',
        item: 'decoy_alice_operators',
        item_vars: {
          for: 'alice.stone', to: 'Operators', right: 'WriteOwner', inheritance: 'All',
        },
      },
    }];
  });
  assert.deepStrictEqual(codes(viaDecoy), ['CHAIN_OBJECTIVE_UNREACHED'],
    'a decoy reaching the objective must not satisfy the objective');

  // The reachability walk is a graph walk, not an "is it the last edge" check:
  // a branch that rejoins still arrives, and a chain that arrives early still
  // arrives.
  assert.strictEqual(V.chainReaches(
    [{ from: 'a', to: 'b' }, { from: 'b', to: 'c' }], 'a', 'c'), true);
  assert.strictEqual(V.chainReaches([{ from: 'a', to: 'b' }], 'a', 'c'), false);
  // Cycles must terminate rather than hang the generation loop.
  assert.strictEqual(V.chainReaches(
    [{ from: 'a', to: 'b' }, { from: 'b', to: 'a' }], 'a', 'c'), false);
});

test('chain node identity is AD identity: case-folded, DOMAIN\\ stripped, DNs normalised', () => {
  // A chain that spells one object two ways is describing ONE object, and a walk
  // that disagreed would refuse a lab that is fine.
  assert.strictEqual(V.chainNodeKey('RANGE\\Alice.Stone'), 'alice.stone');
  assert.strictEqual(V.chainNodeKey('Domain Admins'), 'domain admins');
  assert.strictEqual(V.chainNodeKey('CN=AdminSDHolder, CN=System ,DC=Range,DC=Local'),
    'cn=adminsdholder,cn=system,dc=range,dc=local');
  assert.strictEqual(V.chainNodeKey(null), '');
});

test('a chain edge with no producer at all is rejected, not skipped', () => {
  const r = checkGenerated((b) => { delete b.chain.edges[1].created_by; });
  const f = onlyFinding(r, 'CHAIN_EDGE_PRODUCER_MISSING', 'error');
  assert.match(f.message, /edge1/, 'the edge id is the only handle the reader has');

  const noRole = checkGenerated((b) => { delete b.chain.edges[1].created_by.role; });
  onlyFinding(noRole, 'CHAIN_EDGE_PRODUCER_MISSING', 'error');
});

test('a chain drawn in a domain the lab does not declare is rejected', () => {
  const r = checkGenerated((b) => { b.chain.domain = 'elsewhere.local'; });
  // ad-acl.yml resolves lab.domains[domain].acls, so nothing is planted; the ACL
  // cross-check then has no block to look in and stands down rather than
  // reporting every edge twice.
  const f = onlyFinding(r, 'CHAIN_DOMAIN_UNKNOWN', 'error');
  assert.match(f.message, /range\.local/, 'the message must name the domains that DO exist');
});

test('every generated-mode finding is shaped for a UI and names a remedy', () => {
  // Same contract as the deploy rules: these are read by an instructor in a
  // toast. Asserted separately because a whole family of new codes is exactly
  // where the shape quietly stops being honoured.
  const r = checkGenerated((b) => {
    b.lab.domains['range.local'].acls = {};
    b.chain.edges[0].created_by.role = 'vulns/nonexistent';
    b.chain.objective.target = 'Nobody';
    b.foothold.sam = 'ghost.user';
  });
  const generatedCodes = r.findings.filter((f) => /^(CHAIN_|FOOTHOLD_|VALIDATION_MODE_)/.test(f.code));
  assert.ok(generatedCodes.length >= 4, `expected the generated family to fire, got ${JSON.stringify(codesAt(r))}`);
  for (const f of generatedCodes) {
    assert.match(f.code, /^[A-Z][A-Z0-9_]*$/);
    assert.strictEqual(f.severity, 'error',
      `${f.code} is a warning; a lab with nothing to attack must block the bake, not annotate it`);
    assert.ok(f.id && typeof f.id === 'string');
    assert.ok(f.message.length > 80, `message too terse to be actionable: ${f.message}`);
    assert.match(f.message, /\b(Add|Remove|Set|Use|Move|Fix|Shorten|Replace|Delete|Give|Make|Point|Declare|Wrap|Register|Pass|Emit|pick)\b/,
      `message names no remedy: ${f.message}`);
  }
});

test('assertLabCompiles refuses a chainless generated lab with the same 409', () => {
  // The boundary has to carry the new rules too, or the compiler's own
  // self-check is the one caller that never sees them.
  let err = null;
  try {
    V.assertLabCompiles({
      lab: generatedLab(),
      inventory: BASE_INVENTORY,
      labName: 'FIXTURE',
      mode: V.MODE_GENERATED,
    });
  } catch (caught) {
    err = caught;
  }
  assert.ok(err, 'a generated lab with no chain must not return normally');
  assert.strictEqual(err.status, 409);
  assert.strictEqual(err.code, 'LAB_DEFINITION_INVALID');
  assert.deepStrictEqual(err.errors.map((e) => e.code).sort(),
    ['CHAIN_MISSING', 'FOOTHOLD_MISSING']);

  // …and returns normally for the same lab WITH its chain, which is what makes
  // the refusal above a rule rather than a wall.
  const ok = V.assertLabCompiles({
    lab: generatedLab(),
    chain: generatedChain(),
    foothold: generatedFoothold(),
    inventory: BASE_INVENTORY,
    labName: 'FIXTURE',
    mode: V.MODE_GENERATED,
  });
  assert.strictEqual(ok.errors.length, 0);
});

// ── 11c. a lab the compiler really produced ─────────────────────────────────

/**
 * The profile layout production hands the compiler, at the tier-S fixture the
 * composer's own suite uses.
 *
 * A hand-built chain proves each rule FIRES. Only a real compile proves the
 * rules are SATISFIABLE by the pipeline that has to satisfy them — and that the
 * IR fields this validator reads are the ones goad-lab-compile emits. A rule set
 * that no real lab can pass is worse than no rule set: the first thing anybody
 * does with it is pass mode: 'reference' everywhere.
 */
function compileProfile(runId, company, domain, employees) {
  return {
    json_data: {
      student_view: {
        meta: { run_id: runId, client_type: 'SMB', difficulty: 'intermediate' },
        quick: { company_name: company, employees_total: employees },
        raw: {
          threats: {
            organization: {
              company_name: company,
              domain_public: domain,
              employees_total: employees,
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
          { name: 'Priya Raghunathan-Venkataraman', role: 'Controller', department: 'Finance' },
          { name: 'Tom Ng Jr.', role: 'Operations Lead', department: 'Operations' },
        ],
      },
    },
  };
}

test('a real lab from compileLabWithChain passes generated mode cleanly', () => {
  // Three tiers, because the chain shape varies with the roster the tier
  // produces (S has one domain, L has two forests and a trust) and a rule that
  // only the small one satisfies is a rule that fires on two thirds of clients.
  const cases = [
    ['RUN_2026_RIDGELINE', 'Ridgeline Dental Group', 'ridgelinedental.com', 42],
    ['RUN_2026_CASCADE', 'Cascade Freight Services', 'cascadefreight.com', 110],
    ['RUN_2026_VANTAGE', 'Vantage Utilities Cooperative', 'vantageutil.coop', 320],
  ];
  for (const [runId, company, domain, employees] of cases) {
    const out = compile.compileLabWithChain(compileProfile(runId, company, domain, employees));
    const parsed = V.parseLabConfig(out.files['data/config.json'], { source: runId });

    // Validated against the EMITTED config.json, not against the in-memory lab
    // object: the round trip through toStrictJson is the step where the IR and
    // the file could diverge, and validating the object would skip it.
    const result = V.validateLab({
      lab: parsed.lab,
      inventory: out.files['data/inventory'],
      labName: out.ir.lab_name,
      mode: V.MODE_GENERATED,
      chain: out.ir.chain,
      foothold: out.ir.foothold_credential,
    });

    assert.deepStrictEqual(result.errors.map((f) => `${f.code}@${f.id}`), [],
      `${runId}: a lab the compiler produced must pass its own generated-mode rules`);

    // Zero generated-family findings AT ANY SEVERITY. Errors alone would let a
    // rule be downgraded to a warning and still look satisfied; the deploy rules
    // may still warn here (the designer plants dead-end decoy edges on purpose,
    // which is exactly what DEAD_ACL_EDGE describes), and those are somebody
    // else's calibrated behaviour, not this section's.
    const generated = result.findings.filter((f) => /^(CHAIN_|FOOTHOLD_|VALIDATION_MODE_)/.test(f.code));
    assert.deepStrictEqual(generated, [], `${runId}: generated-mode findings on a real compile`);

    // And the rules are not passing vacuously: this lab really does carry a
    // chain with ACL edges, and every one of them really was looked up in the
    // emitted acls block.
    assert.ok(out.ir.chain.edges.length >= 3, `${runId}: too short a chain to be a real check`);
    const aclEdges = out.ir.chain.edges.filter((e) => e.created_by && e.created_by.role === 'acl');
    assert.ok(aclEdges.length >= 1, `${runId}: no ACL edge, so the cross-check proved nothing`);
    const emitted = parsed.lab.domains[out.ir.chain.domain].acls;
    for (const e of aclEdges) {
      assert.ok(emitted[e.created_by.item],
        `${runId}: ${e.created_by.item} is missing from the emitted acls block`);
    }
  }
});

test('the same compiled lab is rejected the moment its acls block is emptied', () => {
  // The mutation that produces the reported defect, applied to a REAL lab rather
  // than a fixture: everything else about it is unchanged and still deploys.
  const out = compile.compileLabWithChain(
    compileProfile('RUN_2026_RIDGELINE', 'Ridgeline Dental Group', 'ridgelinedental.com', 42));
  const lab = V.parseLabConfig(out.files['data/config.json']).lab;
  for (const domain of Object.values(lab.domains)) domain.acls = {};

  const stillDeploys = V.validateLab({
    lab, inventory: out.files['data/inventory'], labName: out.ir.lab_name, mode: V.MODE_REFERENCE,
  });
  assert.strictEqual(stillDeploys.errors.length, 0,
    'the point of the defect is that an empty forest still passes every deploy rule');

  const asGenerated = V.validateLab({
    lab,
    inventory: out.files['data/inventory'],
    labName: out.ir.lab_name,
    mode: V.MODE_GENERATED,
    chain: out.ir.chain,
    foothold: out.ir.foothold_credential,
  });
  assert.ok(asGenerated.errors.length > 0, 'and the point of the fix is that it no longer does');
  assert.deepStrictEqual(
    [...new Set(asGenerated.errors.map((f) => f.code))], ['CHAIN_ACL_NOT_EMITTED']);
});

// ── 12. the eight shipped labs ──────────────────────────────────────────────

const GOAD_AD = path.join(REPO, 'GOAD-main', 'ad');
const HAVE_GOAD = fs.existsSync(GOAD_AD);
// GOAD-main/ is gitignored with zero tracked files (see goad-role-manifest.js),
// so it is present on the authoring machine and absent in CI. Skipping keeps the
// suite green there; every rule above is already proven without it.
const skipCorpus = HAVE_GOAD ? false : 'GOAD-main/ not checked out (gitignored, absent in CI)';

/**
 * THE CALIBRATED BASELINE: the exact finding set for each shipped lab, as
 * `severity CODE@id`.
 *
 * Every entry here was individually run down against the upstream Ansible role
 * or playbook that consumes the value and confirmed a TRUE POSITIVE — a real
 * defect in a real lab, not a tolerated false positive. The evidence for each
 * (file, line, and what actually breaks or silently fails to exist) lives in
 * ciab/data/goad-corpus-findings.md, one section per finding, and the sync test
 * below keeps that document from drifting away from this table.
 *
 * Pinning severity as well as identity is deliberate: downgrading a rule from
 * error to warning is the cheapest way to make this file green while making the
 * validator useless, because errors block a bake and warnings do not.
 */
const EXPECTED = {
  // Ships with a trailing comma in its acls dict and deploys fine — the whole
  // reason parseLabConfig reads like YAML. Zero findings is the assertion.
  DRACARYS: [],

  // The documented `shares` defect, both halves: dc02 LISTS the broken role with
  // no vars (error + no-op warning), srv02 DEFINES the vars without listing it.
  // Between them the `thewall` share is created on no machine at all, while
  // jon.snow still carries HTTP/thewall.north.sevenkingdoms.local as an SPN.
  // Plus dc03's adcs_esc7, the other never_emit role — its ManageCA grant sits
  // in an unreachable else branch and reports green having granted nothing, and
  // no lab in the corpus grants that right by the working route either.
  GOAD: [
    'error NEVER_EMIT_ROLE@hosts.dc02.vulns[7]',
    'error NEVER_EMIT_ROLE@hosts.dc03.vulns[2]',
    'error ORPHAN_ROLE_VARS@hosts.srv02.vulns_vars.shares',
    'warning ROLE_VARS_MISSING@hosts.dc02.vulns[7]',
  ],

  // Inherits GOAD's dc02 `shares` line (this lab is a re-skin of it) WITHOUT
  // srv02's thewall block, so the line is pure vestige. And it adds the dead ACL
  // edge: CorporateResources has no members, no members list, no cross-domain
  // entry and no inbound ACL, so the GenericAll it holds on the root DC is
  // planted correctly and reachable by nobody.
  'GOAD-Light': [
    'error NEVER_EMIT_ROLE@hosts.dc02.vulns[8]',
    'warning DEAD_ACL_EDGE@domains["cybersaguaros.local"].acls.GenericAll_group_corporateresources_dc',
    'warning ROLE_VARS_MISSING@hosts.dc02.vulns[8]',
  ],

  // The same class of dead edge, left behind by the reduction rather than
  // authored: GOAD gives AcrossTheNarrowSea its only member through
  // multi_domain_groups_member from essos.local, and GOAD-Mini drops essos.
  // The GOAD/GOAD-Mini contrast is asserted directly further down.
  'GOAD-Mini': [
    'warning DEAD_ACL_EDGE@domains["sevenkingdoms.local"].acls.GenericAll_group_acrrosdom_dc',
  ],

  MINILAB: [],
  NHA: [],

  // Proves the [domain]/[linux_domain] scoping: SCCM's `elk` sits in
  // [elk_server] with no config.json entry and must not be flagged.
  SCCM: [],

  // TEMPLATE is the authoring skeleton, and its placeholder passwords are the
  // literal strings "dc_and_domain_password" and "srv_password" — lowercase plus
  // underscore, two of the four character classes. On dc01 that string is also
  // the DSRM safe-mode password, so dcpromo rejects it: the skeleton as shipped
  // cannot deploy. True positives, and the only lab of the eight that ships no
  // inventory_disable_vagrant, i.e. the only one nobody deploys — which is the
  // evidence that the member-server half of the rule is not noise, and is itself
  // asserted below rather than left as a claim in a comment.
  TEMPLATE: [
    'error WEAK_DOMAIN_PASSWORD@domains["template.lab"].domain_password',
    'error WEAK_LOCAL_ADMIN_PASSWORD@hosts.dc01.local_admin_password',
    'error WEAK_LOCAL_ADMIN_PASSWORD@hosts.srv01.local_admin_password',
  ],
};

/** Corpus-wide total. The count half of "count and identity". */
const CALIBRATED_TOTAL = 11;

/**
 * The corpus surface, pinned so the near-silence above cannot become vacuous.
 *
 * Six of the eight labs produce two findings or fewer. That is only reassuring
 * while the rules are actually reaching everything: a corpus that silently
 * shrank — a lab replaced by a stub, a config that stopped parsing into
 * anything — would also go quiet, and would look identical in EXPECTED.
 */
const CORPUS_SCALE = { hosts: 25, domains: 12, users: 115, groups: 59, acls: 59, roleRefs: 90 };

function readShippedLab(name) {
  const dir = path.join(GOAD_AD, name, 'data');
  const parsed = V.parseLabConfig(fs.readFileSync(path.join(dir, 'config.json'), 'utf8'), { source: name });
  return {
    parsed,
    result: V.validateLab({
      lab: parsed.lab,
      inventory: fs.readFileSync(path.join(dir, 'inventory'), 'utf8'),
      labName: name,
      // EXPLICIT, not defaulted. These eight are reference labs — somebody wrote
      // them, nobody generated them — and the calibrated table below is the set
      // of findings that mode produces. Spelling it out means a future change to
      // the DEFAULT mode cannot silently re-point the corpus baseline at a
      // different rule set; the default is pinned separately, in its own test.
      mode: V.MODE_REFERENCE,
    }),
  };
}

test('all eight shipped labs are accounted for', { skip: skipCorpus }, () => {
  const onDisk = fs.readdirSync(GOAD_AD)
    .filter((d) => fs.existsSync(path.join(GOAD_AD, d, 'data', 'config.json')))
    .sort();
  assert.deepStrictEqual(onDisk, Object.keys(EXPECTED).sort(),
    'a new lab appeared upstream — validate it and add its expected findings');
});

for (const [name, expected] of Object.entries(EXPECTED)) {
  test(`shipped lab ${name}: findings are exactly the calibrated set`, { skip: skipCorpus }, () => {
    const { result } = readShippedLab(name);
    assert.deepStrictEqual(findingsAt(result), expected.slice().sort(),
      `${name} drifted from the baseline in ciab/data/goad-corpus-findings.md — `
      + 'a NEW finding means either a real upstream change or a rule that got too strict, '
      + 'and a MISSING one means a rule stopped firing on a defect that is still there. '
      + 'Both need a verdict written up before this table is edited.');
  });
}

test('the corpus total is exactly the calibrated count, in both directions', { skip: skipCorpus }, () => {
  // The per-lab assertions above already pin identity. This pins the COUNT, so
  // the number in goad-corpus-findings.md ("11 findings, 11 true positives")
  // cannot quietly stop being true, and so a finding that migrated from one lab
  // to another fails as a total as well as a pair of per-lab diffs.
  const all = Object.keys(EXPECTED).flatMap((name) => findingsAt(readShippedLab(name).result));
  assert.strictEqual(all.length, CALIBRATED_TOTAL);
  assert.strictEqual(
    Object.values(EXPECTED).reduce((n, list) => n + list.length, 0), CALIBRATED_TOTAL,
    'the EXPECTED table and CALIBRATED_TOTAL disagree');

  // The per-code tally, so "one rule got noisier while another went silent"
  // cannot net out to the same total.
  const tally = {};
  for (const f of all) tally[f.split(' ')[1].split('@')[0]] = (tally[f.split(' ')[1].split('@')[0]] || 0) + 1;
  assert.deepStrictEqual(tally, {
    NEVER_EMIT_ROLE: 3,        // GOAD dc02 + dc03, GOAD-Light dc02
    ROLE_VARS_MISSING: 2,      // the empty-dict half of each `shares` line
    ORPHAN_ROLE_VARS: 1,       // GOAD srv02's thewall block, listed by nobody
    DEAD_ACL_EDGE: 2,          // GOAD-Light CorporateResources, GOAD-Mini AcrossTheNarrowSea
    WEAK_LOCAL_ADMIN_PASSWORD: 2,
    WEAK_DOMAIN_PASSWORD: 1,
  });

  // Six codes fire; every other rule in the validator is silent on all eight
  // labs. That is the property being defended — the rules are proven by the
  // fixtures above, and the corpus proves they do not misfire on real labs.
  assert.strictEqual(Object.keys(tally).length, 6);
});

test('the corpus surface is what it was calibrated against, so the quiet is not vacuous', { skip: skipCorpus }, () => {
  // Measured, not assumed: every one of these 25 hosts / 12 domains / 115 users
  // / 59 ACLs was confirmed reachable by mutating it to a known-bad value and
  // watching the matching rule fire. If the corpus shrinks, the near-empty
  // EXPECTED table stops meaning "the labs are clean" and starts meaning
  // "nothing was checked" — and it looks identical either way.
  const actual = { hosts: 0, domains: 0, users: 0, groups: 0, acls: 0, roleRefs: 0 };
  for (const name of Object.keys(EXPECTED)) {
    const { parsed } = readShippedLab(name);
    for (const host of Object.values(parsed.lab.hosts)) {
      actual.hosts += 1;
      actual.roleRefs += (host.vulns || []).length + (host.security || []).length;
    }
    for (const domain of Object.values(parsed.lab.domains)) {
      actual.domains += 1;
      actual.users += Object.keys(domain.users || {}).length;
      actual.acls += Object.keys(domain.acls || {}).length;
      for (const scope of Object.values(domain.groups || {})) actual.groups += Object.keys(scope).length;
    }
  }
  assert.deepStrictEqual(actual, CORPUS_SCALE);
});

test('DRACARYS is TOLERATED, not flagged — the tolerance is exercised, not theoretical', { skip: skipCorpus }, () => {
  const { parsed, result } = readShippedLab('DRACARYS');
  assert.strictEqual(parsed.strict, false, 'if upstream ever fixes the comma this test stops proving anything');
  assert.deepStrictEqual(parsed.repairs, ['trailing-comma']);
  assert.deepStrictEqual(codesAt(result), [], 'a non-strict but working lab must produce no finding at all');
});

test('the pair of upstream never_emit roles is exactly the pair the manifest names', { skip: skipCorpus }, () => {
  // Ties the corpus expectations to the manifest: if a third role is ever marked
  // never_emit, the GOAD expectations above become stale and this fails first,
  // with a message that says why.
  const flagged = new Set();
  for (const name of Object.keys(EXPECTED)) {
    const { parsed, result } = readShippedLab(name);
    for (const f of result.errors) {
      if (f.code !== 'NEVER_EMIT_ROLE') continue;
      const m = /vulns\[(\d+)\]$/.exec(f.id);
      const host = /^hosts\.([^.]+)\./.exec(f.id)[1];
      flagged.add(parsed.lab.hosts[host].vulns[Number(m[1])]);
    }
  }
  assert.deepStrictEqual([...flagged].sort(), ['adcs_esc7', 'shares']);
});

test('the twelve upstream domains all pair the DC password with the domain password', { skip: skipCorpus }, () => {
  // The rule's evidence base, asserted rather than asserted-about-in-a-comment.
  let domains = 0;
  for (const name of Object.keys(EXPECTED)) {
    const { parsed } = readShippedLab(name);
    for (const domain of Object.values(parsed.lab.domains)) {
      domains += 1;
      assert.strictEqual(parsed.lab.hosts[domain.dc].local_admin_password, domain.domain_password,
        `${name}: ${domain.dc}'s local password diverged from its domain password`);
    }
  }
  assert.strictEqual(domains, 12);
});

test('TEMPLATE is still the only lab nobody deploys', { skip: skipCorpus }, () => {
  // This is the whole evidentiary basis for the ONE finding in the baseline with
  // a house-rule component: WEAK_LOCAL_ADMIN_PASSWORD on TEMPLATE's srv01.
  // Windows itself would accept "srv_password" on a standalone member server —
  // complexity is disabled until the box joins a domain — so that half of the
  // rule is ours, not Microsoft's, and it is only defensible while it fires on
  // no lab anyone actually builds.
  //
  // inventory_disable_vagrant is the marker: every deployable lab ships one, and
  // TEMPLATE, the authoring skeleton you copy, does not. If a lab ever gains
  // this finding WITH that file present, the rule has become too strict for a
  // real lab and should be relaxed for non-DC hosts — see F-10 in
  // goad-corpus-findings.md, which states that condition so it can be tested
  // rather than re-argued.
  const undeployable = Object.keys(EXPECTED)
    .filter((name) => !fs.existsSync(path.join(GOAD_AD, name, 'data', 'inventory_disable_vagrant')));
  assert.deepStrictEqual(undeployable, ['TEMPLATE']);

  const weakOnDeployableLab = Object.keys(EXPECTED)
    .filter((name) => !undeployable.includes(name))
    .flatMap((name) => findingsAt(readShippedLab(name).result))
    .filter((f) => f.includes('WEAK_'));
  assert.deepStrictEqual(weakOnDeployableLab, [],
    'a password rule fired on a lab that ships an inventory_disable_vagrant, i.e. one that deploys');
});

test('the two dead ACL edges are dead for the reason claimed, not by coincidence', { skip: skipCorpus }, () => {
  // GOAD and GOAD-Mini carry a BYTE-IDENTICAL acls entry under the same key,
  // sourced from the same group. One is reachable and one is not, and the single
  // differing field is the one the rule reads — GOAD-Mini dropped essos.local,
  // so multi_domain_groups_member lost the only thing that could ever put a
  // principal into AcrossTheNarrowSea, while the ACL that depended on it stayed.
  //
  // Asserting the contrast rather than just the finding is what makes the
  // warning trustworthy: it shows the rule distinguishing two labs that differ
  // in exactly the way it claims to care about.
  const KEY = 'GenericAll_group_acrrosdom_dc';
  const goad = readShippedLab('GOAD').parsed.lab.domains['sevenkingdoms.local'];
  const mini = readShippedLab('GOAD-Mini').parsed.lab.domains['sevenkingdoms.local'];

  assert.deepStrictEqual(goad.acls[KEY], mini.acls[KEY], 'the ACL entries must be identical, or this proves nothing');
  assert.deepStrictEqual(goad.multi_domain_groups_member.AcrossTheNarrowSea, ['essos.local\\daenerys.targaryen']);
  assert.deepStrictEqual(mini.multi_domain_groups_member, {}, 'GOAD-Mini has no essos.local to source a member from');

  const fired = (name) => findingsAt(readShippedLab(name).result).some((f) => f.includes('DEAD_ACL_EDGE') && f.endsWith(KEY));
  assert.strictEqual(fired('GOAD'), false, 'a cross-domain member makes the edge live');
  assert.strictEqual(fired('GOAD-Mini'), true, 'with the member gone the edge is unreachable');

  // Nothing else in either lab can put anyone in the group: no explicit members
  // list, no user's groups array, and no inbound ACL naming it as `to`. Those
  // are the other three exemptions, checked here so a future "fix" that adds one
  // of them shows up as this test going green in the wrong direction.
  const grp = mini.groups.domainlocal.AcrossTheNarrowSea;
  assert.deepStrictEqual(Object.keys(grp), ['path'], 'no members list');
  assert.ok(!Object.values(mini.users).some((u) => (u.groups || []).includes('AcrossTheNarrowSea')));
  assert.ok(!Object.values(mini.acls).some((a) => a.to === 'AcrossTheNarrowSea'));
});

// ── 13. the baseline document ───────────────────────────────────────────────

test('goad-corpus-findings.md documents every finding in the calibrated set', () => {
  // NOT corpus-gated, on purpose. The document and EXPECTED are both tracked
  // source, so this runs in CI too — which matters, because the per-lab
  // assertions above are the ones that self-skip there. Somebody editing the
  // table without touching the write-up is the realistic drift, and it is the
  // one thing CI can still catch.
  //
  // The document is what a maintainer reads when the corpus output changes; a
  // finding present in the table and absent from the write-up has no recorded
  // verdict, which is exactly the state this whole exercise existed to leave
  // behind.
  const DOC = path.join(
    ROOT, 'modules/crucible/plugins/ciab/data/goad-corpus-findings.md');
  assert.ok(fs.existsSync(DOC), `${DOC} must exist — it is the baseline's evidence`);
  const doc = fs.readFileSync(DOC, 'utf8');

  for (const [lab, findings] of Object.entries(EXPECTED)) {
    assert.ok(doc.includes(lab), `goad-corpus-findings.md never mentions the lab ${lab}`);
    for (const f of findings) {
      // Verbatim, severity included: the document quotes the exact pinned string
      // so the two cannot drift into agreeing about a code while disagreeing
      // about where it fires or how hard.
      assert.ok(doc.includes(f), `goad-corpus-findings.md carries no section for '${f}'`);
    }
  }

  // The headline numbers the document asserts in prose must match the table it
  // is describing, or the first paragraph is a lie the reader has no way to spot.
  assert.ok(doc.includes(`exactly ${CALIBRATED_TOTAL} findings`),
    `the document must state the calibrated total of ${CALIBRATED_TOTAL}`);
  assert.ok(doc.includes(`${CALIBRATED_TOTAL} findings. ${CALIBRATED_TOTAL} true positives. 0 false positives.`),
    'the document must state the verdict split; if a false positive is ever found, this line changes with it');
  assert.ok(doc.includes(loadManifest().goad_ref),
    'the document must name the pinned GOAD commit its line numbers refer to');
});
