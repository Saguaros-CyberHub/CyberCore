/**
 * ciab-goad-preflight.test.js — the gate that costs seconds and saves ninety
 * minutes.
 *
 * WHY THIS FILE EXISTS
 * A GOAD lab is built by a CHAIN of separate ansible-playbook invocations —
 * sixteen of them for the `default` lab in playbooks.yml. Each is its own
 * process, so nothing in a later playbook is parsed until every earlier one has
 * finished against live guests. A missing key in config.json or data/inventory
 * therefore does not surface as a config error; it surfaces as
 * AnsibleUndefinedVariable at PLAY START, somewhere between 30% and 95% into a
 * ~90-minute bake, after the operator has already paid for all of it.
 *
 * The system's only existing pre-flight (bake-goad-controller.sh:374) runs
 * `ansible-playbook --syntax-check main.yml`, which checks the wrong file — the
 * chain comes from playbooks.yml, not main.yml — and --syntax-check does not
 * descend into include_role, which is how every roles/vulns/* and
 * roles/security/* task file is invoked.
 *
 * WHAT IS ACTUALLY UNDER TEST
 * Not "the checker runs". A validator that returns [] for everything runs fine.
 * The property is that it DISCRIMINATES: every §2-§5 case below takes the known-
 * good fixture, breaks exactly one thing, and asserts the checker names that one
 * thing. A check nobody can make fail is a check nobody should trust.
 *
 * PRESENT IS NOT THE SAME AS FILLED (§5b)
 * Those mutations all DELETE something. §5b empties instead: `users: {}`, a
 * `[dc]` that kept its header and lost its hosts, `domain_password: "  "`. Each
 * reads as "the key is there" to a presence check and each fails as hard as the
 * omission — the empty-dict case was found pre-flighting a payload-free chassis
 * completely clean, then dying in ad-data.yml an hour into the bake. Every type
 * gets its own answer there rather than one blanket truthiness rule, because
 * `trust: ""` is upstream's own encoding for "trusts nothing" and `0` is a value
 * Ansible resolves; rejecting those would be a false positive, and a gate that
 * cries wolf is a gate somebody switches off.
 *
 * THE TEMPLATE PROOF (§7)
 * ad/TEMPLATE is upstream's documented starting point for a new lab, and its
 * data/inventory defines neither admin_user nor dns_server_forwarder — both of
 * which are dereferenced with no default in 25+ places, the earliest being
 * roles/domain_controller (run from ad-parent_domain.yml, the third invocation).
 * So upstream's own "copy this to start" lab cannot be built. Asserting that the
 * seven real labs pass while TEMPLATE fails on exactly those two vars is the
 * strongest available evidence that the checker models Ansible and not itself.
 *
 * WHY §7 IS GUARDED AND §1-§6 ARE NOT
 * GOAD-main/ is gitignored (.gitignore:48), so it is absent on a fresh clone and
 * in CI. The synthetic fixtures are the real guard and always run; the shipped-
 * lab sweep is corroboration that runs only where the checkout exists. Same
 * reasoning as ciab-goad-role-manifest.test.js, which vendored its data for
 * precisely this reason.
 *
 * Run: node --test front-end/test/ciab-goad-preflight.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const REPO = path.join(ROOT, '..');

const pf = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-preflight.js'));

const GOAD_AD = path.join(REPO, 'GOAD-main', 'ad');
const GOAD_PLAYBOOKS = path.join(REPO, 'GOAD-main', 'playbooks.yml');
const HAVE_GOAD = fs.existsSync(GOAD_AD) && fs.existsSync(GOAD_PLAYBOOKS);
const NO_GOAD = HAVE_GOAD ? false : 'GOAD-main/ is gitignored and not present in this checkout';

// ── the known-good fixture ──────────────────────────────────────────────────
// Modelled on ad/GOAD: a parent forest, a child domain under it, a second forest
// reached by a bidirectional trust, and one member server carrying MSSQL. Small
// enough to read, wide enough that every gated check in §5 has something to bite
// on. It must produce ZERO findings, or every mutation below proves nothing.

function baseConfig() {
  return {
    lab: {
      hosts: {
        dc01: {
          hostname: 'dc01', domain: 'corp.lab', path: 'DC=corp,DC=lab',
          local_admin_password: 'dc_pw', type: 'dc',
        },
        dc02: {
          hostname: 'dc02', domain: 'sub.corp.lab', path: 'DC=sub,DC=corp,DC=lab',
          local_admin_password: 'dc_pw', type: 'dc',
        },
        dc03: {
          hostname: 'dc03', domain: 'other.lab', path: 'DC=other,DC=lab',
          local_admin_password: 'dc_pw', type: 'dc',
        },
        srv01: {
          hostname: 'srv01', domain: 'corp.lab', path: 'DC=corp,DC=lab',
          local_admin_password: 'srv_pw', type: 'server',
          mssql: { sa_password: 'Sup1_sa_P@ssw0rd!', sysadmins: ['CORP\\alice'] },
        },
      },
      domains: {
        'corp.lab': {
          dc: 'dc01', domain_password: 'corp_pw', netbios_name: 'CORP',
          trust: 'other.lab', ca_server: 'dc01', laps_path: 'OU=Laps,DC=corp,DC=lab',
          users: { alice: { password: 'a' } },
          groups: { global: { admins: {} } },
        },
        'sub.corp.lab': {
          dc: 'dc02', domain_password: 'sub_pw', netbios_name: 'SUB',
          users: { bob: { password: 'b' } },
          groups: { global: { subadmins: {} } },
        },
        'other.lab': {
          dc: 'dc03', domain_password: 'other_pw', netbios_name: 'OTHER',
          trust: 'corp.lab',
          users: { carol: { password: 'c' } },
          groups: { global: { otheradmins: {} } },
        },
      },
    },
  };
}

const BASE_INVENTORY = [
  '; GLOBAL CONFIG',
  '[all:vars]',
  'domain_name=FIXTURE',
  'admin_user=administrator',
  'dns_server_forwarder=1.1.1.1',
  'ansible_user=vagrant',
  '',
  '[domain]',
  'dc01', 'dc02', 'dc03', 'srv01',
  '[dc]',
  'dc01', 'dc02', 'dc03',
  '[server]',
  'srv01',
  '[parent_dc]',
  'dc01', 'dc03',
  '[child_dc]',
  'dc02',
  '[trust]',
  'dc01', 'dc03',
  '[adcs]',
  'dc01',
  '[adcs_customtemplates]',
  'dc01',
  '[mssql]',
  'srv01',
  '[laps_dc]',
  'dc01',
  '[laps_server]',
  'srv01',
  '; MINILAB ships these empty and is still supported — see MANDATORY_GROUPS.',
  '[workstation]',
  '[iis]',
  '[webdav]',
].join('\n');

const BASE_PROVIDER = [
  '[default]',
  'dc01 ansible_host=192.168.56.10 dns_domain=dc01 dict_key=dc01',
  'dc02 ansible_host=192.168.56.11 dns_domain=dc01 dict_key=dc02',
  'dc03 ansible_host=192.168.56.12 dns_domain=dc03 dict_key=dc03',
  'srv01 ansible_host=192.168.56.22 dns_domain=dc01 dict_key=srv01',
  '',
  '[all:vars]',
  'force_dns_server=yes',
  'dns_server=192.168.56.1',
].join('\n');

/** One mutation per test, applied to a fresh deep copy so cases cannot leak. */
function run(mutate) {
  const input = {
    labName: 'FIXTURE',
    config: baseConfig(),
    inventory: BASE_INVENTORY,
    providerInventory: BASE_PROVIDER,
    playbooks: null, // null => DEFAULT_CHAIN, i.e. every gated check is live
  };
  if (mutate) mutate(input);
  return pf.preflightGoadLab(input);
}

const codes = (result) => result.findings.map((f) => f.code);
const of = (result, code) => result.findings.filter((f) => f.code === code);

/** Report the whole finding list on failure — a bare "expected true" tells the
 *  next reader nothing about which of twenty checks moved. */
function dump(result) {
  return '\n' + (result.findings.length === 0
    ? '  (no findings)'
    : result.findings.map((f) => `  ${f.severity} ${f.code} [${f.id}] ${f.message}`).join('\n'));
}

// ── §1. the fixture itself ──────────────────────────────────────────────────

test('the known-good fixture produces no findings at all', () => {
  const r = run(null);
  assert.deepStrictEqual(r.findings, [], `fixture must be clean or every mutation below is void${dump(r)}`);
  assert.strictEqual(r.ok, true);
});

test('a finding carries exactly { id, code, severity, message }', () => {
  // Same shape as the plan/module issue lists so one browser renderer draws all
  // of them. A checker whose findings cannot be rendered gets read from a log,
  // which means it gets ignored.
  const r = run((i) => { delete i.config.lab.domains['corp.lab'].laps_path; });
  assert.ok(r.findings.length > 0, 'expected at least one finding to inspect');
  for (const f of r.findings) {
    assert.deepStrictEqual(Object.keys(f).sort(), ['code', 'id', 'message', 'severity']);
    assert.ok(typeof f.message === 'string' && f.message.length > 40,
      `message must state the situation AND the remedy, got: ${f.message}`);
  }
});

// ── §2. the two inventory vars upstream's own TEMPLATE omits ────────────────

test('a config missing admin_user is rejected, and the finding names admin_user', () => {
  const r = run((i) => { i.inventory = BASE_INVENTORY.replace('admin_user=administrator\n', ''); });
  assert.strictEqual(r.ok, false, `admin_user removal must be an error${dump(r)}`);
  const hits = of(r, pf.CODE.INVENTORY_VAR_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id), ['admin_user']);
  assert.match(hits[0].message, /admin_user/);
  // The remedy has to be actionable without opening the GOAD tree.
  assert.match(hits[0].message, /\[all:vars\]/);
});

test('a config missing dns_server_forwarder is rejected by name', () => {
  // Dies in roles/domain_controller, reached from ad-parent_domain.yml — the
  // THIRD invocation of sixteen, i.e. after every guest has already been cloned,
  // booted and WinRM-waited.
  const r = run((i) => { i.inventory = BASE_INVENTORY.replace('dns_server_forwarder=1.1.1.1\n', ''); });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.INVENTORY_VAR_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id), ['dns_server_forwarder']);
});

test('a var defined only in the PROVIDER inventory still counts', () => {
  // ad/GOAD/providers/aws and /azure override admin_user to `goadmin` there and
  // nowhere else. goad hands both files to ansible-playbook, so a checker that
  // read only data/inventory would reject two shipped provider configurations.
  const r = run((i) => {
    i.inventory = BASE_INVENTORY.replace('admin_user=administrator\n', '');
    i.providerInventory = `${BASE_PROVIDER}\nadmin_user=goadmin`;
  });
  assert.deepStrictEqual(r.findings, [], dump(r));
});

// ── §3. host and domain keys ────────────────────────────────────────────────

test('a host missing `type` is rejected even though no play targets it directly', () => {
  // roles/move_to_ou/tasks/main.yml:30 iterates `with_dict: {{lab.hosts}}` and
  // reads item.value.type with no default, so a single incomplete host entry
  // kills ad-data.yml's Move-to-OU play for the whole lab.
  const r = run((i) => { delete i.config.lab.hosts.srv01.type; });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.HOST_KEY_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id), ['srv01']);
  assert.match(hits[0].message, /type/);
});

test('each of the five required host keys is checked, not just the first', () => {
  // A loop that stops at the first miss would still pass the test above.
  for (const field of pf.REQUIRED_HOST_KEYS) {
    const r = run((i) => { delete i.config.lab.hosts.dc02[field]; });
    const hits = of(r, pf.CODE.HOST_KEY_MISSING).filter((f) => f.id === 'dc02');
    assert.ok(hits.some((f) => f.message.includes(field)),
      `removing hosts.dc02.${field} produced no finding naming it${dump(r)}`);
  }
});

test('each of the five required domain keys is checked', () => {
  for (const field of pf.REQUIRED_DOMAIN_KEYS) {
    const r = run((i) => { delete i.config.lab.domains['sub.corp.lab'][field]; });
    assert.strictEqual(r.ok, false, `removing domains['sub.corp.lab'].${field} was accepted${dump(r)}`);
    assert.ok(r.errors.some((f) => f.message.includes(field)),
      `no finding named ${field}${dump(r)}`);
  }
});

test('a domain whose .dc is not a real host is rejected', () => {
  // .dc is fed back into lab.hosts[...] AND hostvars[...].ansible_host, so a
  // dangling value fails the play instead of skipping the host.
  const r = run((i) => { i.config.lab.domains['other.lab'].dc = 'ghost01'; });
  assert.strictEqual(r.ok, false, dump(r));
  assert.ok(of(r, pf.CODE.DOMAIN_DC_UNRESOLVED).length > 0, dump(r));
  assert.ok(r.errors.some((f) => /ghost01/.test(f.message)), dump(r));
});

test('a host claiming an undeclared domain is rejected', () => {
  const r = run((i) => { i.config.lab.hosts.srv01.domain = 'nowhere.lab'; });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.DOMAIN_UNDECLARED);
  assert.deepStrictEqual(hits.map((f) => f.id), ['nowhere.lab']);
  // The message lists what IS declared, so the fix does not need a second round-trip.
  assert.match(hits[0].message, /corp\.lab/);
});

// ── §4. the three-way join: config key / inventory name / provider dict_key ──

test('a provider dict_key that does not match its own host name is rejected', () => {
  // The nastiest of the join failures: nothing errors. srv01 is simply built
  // from dc01's config — dc01's hostname, dc01's domain, dc01's local admin
  // password — and the bake reports success.
  const r = run((i) => {
    i.providerInventory = BASE_PROVIDER.replace('srv01 ansible_host=192.168.56.22 dns_domain=dc01 dict_key=srv01',
      'srv01 ansible_host=192.168.56.22 dns_domain=dc01 dict_key=dc01');
  });
  assert.strictEqual(r.ok, false, dump(r));
  assert.deepStrictEqual(of(r, pf.CODE.PROVIDER_DICT_KEY_MISMATCH).map((f) => f.id), ['srv01']);
});

test('a config host with no provider entry is rejected', () => {
  const r = run((i) => {
    i.providerInventory = BASE_PROVIDER.replace(/^srv01 .*$/m, '');
  });
  assert.strictEqual(r.ok, false, dump(r));
  assert.deepStrictEqual(of(r, pf.CODE.PROVIDER_HOST_MISSING).map((f) => f.id), ['srv01']);
});

test('two hosts on one ansible_host is rejected', () => {
  const r = run((i) => {
    i.providerInventory = BASE_PROVIDER.replace('srv01 ansible_host=192.168.56.22', 'srv01 ansible_host=192.168.56.10');
  });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.PROVIDER_ANSIBLE_HOST_DUPLICATE);
  assert.deepStrictEqual(hits.map((f) => f.id), ['srv01']);
  assert.match(hits[0].message, /dc01/, 'the message must name the OTHER claimant to be fixable');
});

test('a non-IPv4 ansible_host is rejected, but the {{ip_range}} placeholder is not', () => {
  // Upstream's own header: "ansible_host *MUST* be an IPv4 address or setting
  // things like DNS servers will break." Every shipped provider file writes
  // {{ip_range}}.10, which goad substitutes later — rejecting that would reject
  // all seven labs.
  const bad = run((i) => {
    i.providerInventory = BASE_PROVIDER.replace('ansible_host=192.168.56.22', 'ansible_host=srv01.corp.lab');
  });
  assert.ok(of(bad, pf.CODE.PROVIDER_ANSIBLE_HOST_MALFORMED).length === 1, dump(bad));

  const templated = run((i) => {
    i.providerInventory = BASE_PROVIDER.replace(/192\.168\.56\./g, '{{ip_range}}.');
  });
  assert.deepStrictEqual(templated.findings, [], dump(templated));
});

test('an inventory group naming a host config.json does not declare is rejected', () => {
  const r = run((i) => { i.inventory = `${BASE_INVENTORY}\n[mssql]\nsrv99`; });
  assert.strictEqual(r.ok, false, dump(r));
  assert.deepStrictEqual(of(r, pf.CODE.GROUP_HOST_UNKNOWN).map((f) => f.id), ['srv99']);
});

test('a config host in no inventory group at all is rejected', () => {
  const r = run((i) => {
    i.config.lab.hosts.srv02 = {
      hostname: 'srv02', domain: 'corp.lab', path: 'DC=corp,DC=lab',
      local_admin_password: 'p', type: 'server',
    };
    i.providerInventory = `${BASE_PROVIDER}\nsrv02 ansible_host=192.168.56.23 dict_key=srv02`;
  });
  assert.strictEqual(r.ok, false, dump(r));
  assert.deepStrictEqual(of(r, pf.CODE.HOST_NOT_IN_INVENTORY).map((f) => f.id), ['srv02']);
});

// ── §5. the group-gated dereferences ────────────────────────────────────────

test('missing ca_server on an [adcs_customtemplates] host is rejected', () => {
  // adcs.yml:29 `ca_host: "{{lab.domains[domain].ca_server}}"` — no default,
  // while ca_web_enrollment one play above IS defaulted. That asymmetry is
  // exactly why the omission survives review.
  const r = run((i) => { delete i.config.lab.domains['corp.lab'].ca_server; });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.CA_SERVER_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id), ['dc01']);
  assert.match(hits[0].message, /ca_server/);
  assert.match(hits[0].message, /adcs_customtemplates/);
});

test('missing mssql.sa_password on an [mssql] host is rejected', () => {
  // Every sibling in servers.yml's mssql play carries `| default(...)`.
  // sa_password alone does not, so it single-handedly decides whether the play
  // starts — and it is the last thing anyone thinks to check.
  const r = run((i) => { delete i.config.lab.hosts.srv01.mssql.sa_password; });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.MSSQL_SA_PASSWORD_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id), ['srv01']);
  assert.match(hits[0].message, /sa_password/);
});

test('an [mssql] host with no mssql block at all is rejected the same way', () => {
  const r = run((i) => { delete i.config.lab.hosts.srv01.mssql; });
  assert.deepStrictEqual(of(r, pf.CODE.MSSQL_SA_PASSWORD_MISSING).map((f) => f.id), ['srv01']);
});

test('a [child_dc] host whose derived parent domain is undeclared is rejected', () => {
  // ad-child_domain.yml:20 derives the parent by dropping the first label:
  // "{{'.'.join(domain.split('.')[1:])}}". There is no validation and no
  // default — north.sevenkingdoms.local only works because sevenkingdoms.local
  // happens to be declared too.
  const r = run((i) => {
    i.config.lab.hosts.dc02.domain = 'sub.orphan.lab';
    i.config.lab.domains['sub.orphan.lab'] = i.config.lab.domains['sub.corp.lab'];
    delete i.config.lab.domains['sub.corp.lab'];
  });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.CHILD_PARENT_UNDECLARED);
  assert.deepStrictEqual(hits.map((f) => f.id), ['dc02']);
  assert.match(hits[0].message, /orphan\.lab/, 'the message must name the DERIVED parent, not the child');
});

test('a [child_dc] parent whose dc is not a real host is rejected', () => {
  const r = run((i) => { i.config.lab.domains['corp.lab'].dc = 'ghost01'; });
  assert.strictEqual(r.ok, false, dump(r));
  assert.ok(of(r, pf.CODE.DOMAIN_DC_UNRESOLVED).some((f) => f.id === 'corp.lab'), dump(r));
});

test('a [trust] host whose domain declares no trust is rejected', () => {
  const r = run((i) => { delete i.config.lab.domains['corp.lab'].trust; });
  assert.strictEqual(r.ok, false, dump(r));
  assert.deepStrictEqual(of(r, pf.CODE.TRUST_MISSING).map((f) => f.id), ['dc01']);
});

test('an EMPTY trust string is rejected, not accepted as present', () => {
  // ad/GOAD ships `"trust": ""` on north.sevenkingdoms.local. A bare key-presence
  // check would call that configured; Ansible then sets remote_forest to '' and
  // dies on lab.domains[''].dc.
  const r = run((i) => { i.config.lab.domains['corp.lab'].trust = ''; });
  assert.deepStrictEqual(of(r, pf.CODE.TRUST_MISSING).map((f) => f.id), ['dc01']);
});

test('a trust pointing at an undeclared forest is rejected', () => {
  const r = run((i) => { i.config.lab.domains['corp.lab'].trust = 'ghost.lab'; });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.TRUST_UNDECLARED);
  assert.deepStrictEqual(hits.map((f) => f.id), ['dc01']);
  assert.match(hits[0].message, /ghost\.lab/);
});

test('a laps group with no laps_path is a WARNING, because the play stays green', () => {
  // laps.yml defaults laps_path to `false` and roles/laps/dc gates both imports
  // on `laps_path != false`. Nothing fails; LAPS is simply never installed. That
  // has to be reported, and it must not be reported as a build break — those are
  // different remedies for different people.
  const r = run((i) => { delete i.config.lab.domains['corp.lab'].laps_path; });
  assert.strictEqual(r.ok, true, `a silent no-op must not block the bake${dump(r)}`);
  assert.deepStrictEqual(r.errors, []);
  const hits = of(r, pf.CODE.LAPS_PATH_MISSING);
  assert.deepStrictEqual(hits.map((f) => f.id).sort(), ['dc01', 'srv01']);
  assert.ok(hits.every((f) => f.severity === pf.SEVERITY.WARNING));
});

test('mandatory groups are enforced; optional ones are not', () => {
  // MINILAB ships without [server], [child_dc], [trust], [mssql], [iis] and
  // [webdav] and is a supported lab, so demanding the full vocabulary would
  // reject upstream's own work.
  for (const name of pf.MANDATORY_GROUPS) {
    const r = run((i) => { i.inventory = BASE_INVENTORY.replace(new RegExp(`\\[${name}\\]\\n(\\w+\\n)+`), `[${name}]\n`); });
    assert.ok(of(r, pf.CODE.GROUP_EMPTY).some((f) => f.id === name),
      `emptying [${name}] produced no GROUP_EMPTY${dump(r)}`);
  }
  const stripped = run((i) => {
    i.inventory = BASE_INVENTORY
      .replace('[adcs_customtemplates]\ndc01\n', '')
      .replace('[mssql]\nsrv01\n', '')
      .replace('[trust]\ndc01\ndc03\n', '')
      .replace('[child_dc]\ndc02\n', '')
      .replace('[laps_dc]\ndc01\n', '')
      .replace('[laps_server]\nsrv01\n', '')
      .replace('[server]\nsrv01\n', '');
  });
  assert.deepStrictEqual(stripped.findings, [],
    `absent OPTIONAL groups must not be findings${dump(stripped)}`);
});

// ── §5b. present-but-empty is not present ───────────────────────────────────
//
// Every mutation above breaks the fixture by DELETING something. This section
// breaks it by leaving the key exactly where it is and emptying it, which is the
// shape a GENERATOR produces: a compiler walking a schema writes `users: {}`
// rather than omitting the key, and an inventory whose section headers come from
// a template keeps `[dc]` long after whatever was meant to fill it in did not. A
// key-presence check reads all of that as configured. Ansible does not, and the
// bill arrives 30-95% into the bake — which is the entire reason this module
// exists, so a hole here is not a missing nicety, it is the gate standing open
// on the one case it was built to catch.
//
// Each type gets its own answer, and they are not the same answer:
//   {} and []  → not filled. An empty payload is a payload nobody supplied.
//   "" / "  "  → not filled, but only where a value is REQUIRED; `trust: ""` is
//                upstream's encoding for "trusts nothing" and stays legal.
//   0 / false  → filled. They are values Ansible resolves. `false` means "off"
//                for laps_path alone, and that is decided at laps_path.

/** [code, id, severity] per finding, so an "absent" run and an "empty" run can
 *  be compared as wholes rather than through one hand-picked assertion. */
const shape = (result) => result.findings.map((f) => [f.code, f.id, f.severity]);

test('an empty users/groups dict is rejected with the code an ABSENT key produces', () => {
  // The verified hole: a chassis carrying `users: {}` and `groups: {}` on every
  // domain pre-flighted completely clean, then died in ad-data.yml — the 8th
  // playbook of the default chain, ~60 minutes in. ad-data.yml:20-22 binds
  // ad_users/ad_groups off these two keys with no `| default(...)`, and roles/ad
  // iterates them; empty resolves and builds a domain with nobody in it, which
  // this repo ranks below a crash because a lane that lies gets graded.
  for (const field of ['users', 'groups']) {
    const absent = run((i) => { delete i.config.lab.domains['corp.lab'][field]; });
    const empty = run((i) => { i.config.lab.domains['corp.lab'][field] = {}; });
    assert.strictEqual(empty.ok, false, `${field}: {} must not pre-flight clean${dump(empty)}`);
    assert.deepStrictEqual(shape(empty), shape(absent),
      `${field}: {} must be indistinguishable from an absent key${dump(empty)}`);
    assert.deepStrictEqual(of(empty, pf.CODE.DOMAIN_KEY_MISSING).map((f) => f.id), ['corp.lab']);
    assert.match(of(empty, pf.CODE.DOMAIN_KEY_MISSING)[0].message, new RegExp(`\\b${field}\\b`));
  }
});

test('an empty ARRAY is rejected too — a list where a dict belongs is still nothing', () => {
  // A generator that emits a list for a mapping is a different bug from one that
  // emits nothing, and both arrive here as "the key is present". with_dict over
  // [] iterates exactly as many times as with_dict over {}.
  const absent = run((i) => { delete i.config.lab.domains['corp.lab'].users; });
  const emptyList = run((i) => { i.config.lab.domains['corp.lab'].users = []; });
  assert.deepStrictEqual(shape(emptyList), shape(absent), dump(emptyList));
});

test('a payload-free lab fails on EVERY domain, not just the first one found', () => {
  // What the chassis case actually looks like: the skeleton is sound and only
  // the payload is missing. If the loop stopped at the first bad domain the
  // operator would fix one, re-run, and pay for the round trip twice more.
  const r = run((i) => {
    for (const dom of Object.values(i.config.lab.domains)) { dom.users = {}; dom.groups = {}; }
  });
  assert.strictEqual(r.ok, false, dump(r));
  const hits = of(r, pf.CODE.DOMAIN_KEY_MISSING);
  assert.strictEqual(hits.length, 6, `three domains x two keys${dump(r)}`);
  assert.deepStrictEqual([...new Set(hits.map((f) => f.id))].sort(),
    ['corp.lab', 'other.lab', 'sub.corp.lab']);
  assert.deepStrictEqual(r.findings, hits, `nothing else may be reported${dump(r)}`);
});

test('a domain that trusts nothing keeps its empty trust string', () => {
  // ad/GOAD ships `"trust": ""` on north.sevenkingdoms.local, whose DC is in
  // [child_dc] and NOT in [trust]. That is upstream saying "this domain trusts
  // nothing", and the emptiness rules must not turn a supported lab into a
  // finding. sub.corp.lab is the fixture's north: dc02, [child_dc], no [trust].
  const r = run((i) => { i.config.lab.domains['sub.corp.lab'].trust = ''; });
  assert.deepStrictEqual(r.findings, [],
    `an empty trust on a domain with no [trust] host is upstream's own encoding${dump(r)}`);
  // The contrast that gives the rule its edge: the SAME empty string on a domain
  // that does have a [trust] host is fatal, because ad-trusts.yml:16-18 sets
  // remote_forest from it and immediately does lab.domains[''].dc.
  const fatal = run((i) => { i.config.lab.domains['corp.lab'].trust = ''; });
  assert.deepStrictEqual(of(fatal, pf.CODE.TRUST_MISSING).map((f) => f.id), ['dc01'], dump(fatal));
});

test('whitespace-only is empty everywhere a value is required', () => {
  // Ansible does not trim: `domain_password: "  "` is a two-space password and
  // `admin_user=   ` is a three-space login, so neither raises undefined — they
  // build the wrong thing quietly. str() trims everywhere else in the module, so
  // a filled() that accepted "  " would also leave the rest of the file treating
  // a "present" field as ''. One rule, applied at every required value.
  const cases = [
    {
      what: 'an [all:vars] inventory var',
      mutate: (i) => { i.inventory = BASE_INVENTORY.replace('admin_user=administrator', 'admin_user=   '); },
      code: pf.CODE.INVENTORY_VAR_MISSING,
      id: 'admin_user',
    },
    {
      what: 'a required host key',
      mutate: (i) => { i.config.lab.hosts.dc01.hostname = '   '; },
      code: pf.CODE.HOST_KEY_MISSING,
      id: 'dc01',
      match: /hostname/,
    },
    {
      what: 'a required domain key',
      mutate: (i) => { i.config.lab.domains['corp.lab'].domain_password = '\t\t'; },
      code: pf.CODE.DOMAIN_KEY_MISSING,
      id: 'corp.lab',
      match: /domain_password/,
    },
    {
      what: 'mssql.sa_password',
      mutate: (i) => { i.config.lab.hosts.srv01.mssql.sa_password = ' '; },
      code: pf.CODE.MSSQL_SA_PASSWORD_MISSING,
      id: 'srv01',
    },
    {
      what: 'ca_server',
      mutate: (i) => { i.config.lab.domains['corp.lab'].ca_server = '  '; },
      code: pf.CODE.CA_SERVER_MISSING,
      id: 'dc01',
    },
    {
      what: 'a declared trust',
      mutate: (i) => { i.config.lab.domains['corp.lab'].trust = '   '; },
      code: pf.CODE.TRUST_MISSING,
      id: 'dc01',
    },
    {
      // Quoted, because splitInventoryLine is the only path that can carry a
      // blank through an INI line at all — and it is the path DRACARYS uses for
      // ansible_ssh_common_args, so it is not hypothetical.
      what: 'a quoted-blank provider dict_key',
      mutate: (i) => { i.providerInventory = BASE_PROVIDER.replace('dict_key=dc01', "dict_key='  '"); },
      code: pf.CODE.PROVIDER_DICT_KEY_MISMATCH,
      id: 'dc01',
      match: /sets no dict_key/,
    },
    {
      what: 'a quoted-blank provider ansible_host',
      mutate: (i) => { i.providerInventory = BASE_PROVIDER.replace('ansible_host=192.168.56.10', "ansible_host='  '"); },
      code: pf.CODE.PROVIDER_ANSIBLE_HOST_MISSING,
      id: 'dc01',
    },
  ];
  for (const c of cases) {
    const r = run(c.mutate);
    const hit = of(r, c.code).find((f) => f.id === c.id);
    assert.ok(hit, `${c.what}: whitespace passed for a value${dump(r)}`);
    if (c.match) assert.match(hit.message, c.match);
    assert.strictEqual(r.ok, false, `${c.what}: must be an error${dump(r)}`);
  }
});

test('a scalar that is merely falsy is still a value — 0 is not empty', () => {
  // The rules above are per-type on purpose. `0` and `false` ARE resolvable
  // values; a blanket !value would report a numeric password as missing, and
  // false positives are how a gate ends up with a --force flag on it. Whether 0
  // is a GOOD password is goad-lab-validate's question, not this file's — this
  // one only asks whether Ansible can resolve what it finds.
  const r = run((i) => { i.config.lab.hosts.srv01.local_admin_password = 0; });
  assert.deepStrictEqual(r.findings, [], `a defined scalar must not read as absent${dump(r)}`);
});

/** Strip a section's member lines (mode 'empty') or the whole section
 *  (mode 'delete'), so the two ways an inventory loses a group can be compared. */
function withoutSection(text, name, mode) {
  const out = [];
  let inSection = false;
  for (const line of text.split('\n')) {
    if (line.startsWith('[')) {
      inSection = line.trim() === `[${name}]`;
      if (inSection && mode === 'delete') continue;
      out.push(line);
      continue;
    }
    if (inSection && line.trim() !== '' && !line.startsWith(';')) continue;
    out.push(line);
  }
  return out.join('\n');
}

test('a mandatory group that kept its header but lost its hosts is rejected like a deleted one', () => {
  // The two look nothing alike in a diff and are identical to Ansible: `hosts:
  // dc` matching nothing is a SKIPPED play, not a failed one, so the bake goes
  // green having promoted no domain controller. Membership is what matters, and
  // the emptied form is the one that survives review.
  for (const name of pf.MANDATORY_GROUPS) {
    const emptied = run((i) => { i.inventory = withoutSection(BASE_INVENTORY, name, 'empty'); });
    const deleted = run((i) => { i.inventory = withoutSection(BASE_INVENTORY, name, 'delete'); });
    assert.deepStrictEqual(of(emptied, pf.CODE.GROUP_EMPTY).map((f) => f.id), [name],
      `[${name}] kept its header and lost its hosts; that is still empty${dump(emptied)}`);
    assert.deepStrictEqual(shape(emptied), shape(deleted),
      `[${name}]: emptied and deleted must report identically${dump(emptied)}`);
  }
});

test('membership through [grp:children] counts, because Ansible expands it', () => {
  // The other side of the same rule, and why it is a rule rather than a
  // truthiness test: a group can be fully populated and still have no direct
  // members. Reporting that as empty would reject a lab that builds.
  const r = run((i) => {
    i.inventory = withoutSection(BASE_INVENTORY, 'dc', 'empty')
      .replace('[dc]', '[dc:children]\nparent_dc\nchild_dc\n\n[unused]');
  });
  assert.deepStrictEqual(r.findings, [],
    `[dc:children] -> parent_dc/child_dc is a populated [dc]${dump(r)}`);
  // A children list that resolves to nothing is still empty — expansion must not
  // become a way to launder an empty group past the check.
  const hollow = run((i) => {
    i.inventory = withoutSection(BASE_INVENTORY, 'dc', 'empty')
      .replace('[dc]', '[dc:children]\nempty_group\n\n[empty_group]');
  });
  assert.deepStrictEqual(of(hollow, pf.CODE.GROUP_EMPTY).map((f) => f.id), ['dc'], dump(hollow));
});

test('laps_path: false is laps.yml\'s sentinel, not a value — the same warning as omitting it', () => {
  // laps.yml:14 substitutes `false` for an undefined laps_path and
  // roles/laps/dc/tasks/main.yml gates both imports on `laps_path != false`, so
  // writing the sentinel out literally lands in exactly the silent no-op an
  // absent key produces. filled() says a boolean is present — correctly, it IS
  // defined — which is why this one field is decided at its own site instead.
  const absent = run((i) => { delete i.config.lab.domains['corp.lab'].laps_path; });
  const sentinel = run((i) => { i.config.lab.domains['corp.lab'].laps_path = false; });
  assert.strictEqual(sentinel.ok, true, `a silent no-op must not block the bake${dump(sentinel)}`);
  assert.deepStrictEqual(sentinel.errors, []);
  assert.deepStrictEqual(
    of(sentinel, pf.CODE.LAPS_PATH_MISSING).map((f) => [f.id, f.severity]).sort(),
    of(absent, pf.CODE.LAPS_PATH_MISSING).map((f) => [f.id, f.severity]).sort(),
    dump(sentinel));
  assert.match(of(sentinel, pf.CODE.LAPS_PATH_MISSING)[0].message, /false/,
    'the remedy differs from the absent case, so the message has to say which it saw');
});

// ── §6. playbook gating, parsers, boundary ──────────────────────────────────

test('a check is skipped when the playbook that would fail is not in the chain', () => {
  // SCCM and NHA comment out `# - laps.yml` and `# - ad-child_domain.yml`;
  // DRACARYS has no servers.yml at all. Demanding sa_password from a lab whose
  // chain never runs servers.yml is crying wolf, and a gate that cries wolf gets
  // a --force flag added to it.
  const broken = (i) => { delete i.config.lab.hosts.srv01.mssql; };

  const withServers = run((i) => { broken(i); i.playbooks = ['build.yml', 'servers.yml']; });
  assert.strictEqual(withServers.ok, false, dump(withServers));

  const withoutServers = run((i) => { broken(i); i.playbooks = ['build.yml', 'ad-data.yml']; });
  assert.deepStrictEqual(withoutServers.findings, [], dump(withoutServers));
});

test('an unknown chain falls back to the default one rather than passing everything', () => {
  // The dangerous default is the permissive one: "caller gave me no chain" must
  // not mean "run no checks".
  const r = run((i) => { delete i.config.lab.hosts.srv01.mssql; i.playbooks = []; });
  assert.strictEqual(r.ok, false, `an empty chain must fall back to DEFAULT_CHAIN${dump(r)}`);
  assert.ok(pf.DEFAULT_CHAIN.includes('servers.yml'));
  assert.strictEqual(pf.DEFAULT_CHAIN.length, 16, 'the default chain is 16 invocations');
});

test('chainForLab reads a lab list, honours commented-out entries, and falls back to default', () => {
  const yml = [
    'SCCM:',
    '  - build.yml',
    '  # - laps.yml',
    '  - servers.yml',
    '',
    'default:',
    '  - build.yml',
    '  - laps.yml',
  ].join('\n');
  assert.deepStrictEqual(pf.chainForLab(yml, 'SCCM'), ['build.yml', 'servers.yml'],
    'a commented-out playbook is a semantic statement in this file, not a note');
  assert.deepStrictEqual(pf.chainForLab(yml, 'MINILAB'), ['build.yml', 'laps.yml'],
    'a lab with no entry of its own runs the default chain');
  assert.strictEqual(pf.chainForLab('', 'GOAD'), null);
});

test('parseInventory handles :vars, :children and quoted values', () => {
  const inv = pf.parseInventory([
    '; a comment',
    '[all:vars]',
    'admin_user=administrator',
    '[default]',
    "lx01 ansible_host=10.0.0.5 dict_key=lx01 ansible_ssh_common_args='-o StrictHostKeyChecking=no'",
    '[web:children]',
    'default',
  ].join('\n'));
  assert.deepStrictEqual(inv.groups.default, ['lx01']);
  assert.strictEqual(inv.groupVars.all.admin_user, 'administrator');
  // The quoted value has a space AND an inner '=' — a whitespace split would
  // invent two extra host vars out of it. ad/DRACARYS ships exactly this line.
  assert.deepStrictEqual(inv.hostVars.lx01, {
    ansible_host: '10.0.0.5',
    dict_key: 'lx01',
    ansible_ssh_common_args: '-o StrictHostKeyChecking=no',
  });
  // [web:children] lists a GROUP; folding it into groups[] would invent a host.
  assert.deepStrictEqual(inv.children.web, ['default']);
  assert.deepStrictEqual(inv.hostNames, ['lx01']);
});

test('parseGoadConfigJson tolerates a trailing comma but not real garbage', () => {
  // ansible/data.yml loads config.json via vars_files, i.e. PyYAML, which
  // accepts `,}`. ad/DRACARYS/data/config.json has one and is a runnable lab, so
  // strict JSON.parse would report a defect upstream does not have.
  const withComma = '{"lab":{"hosts":{"dc01":{"a":1,}},"domains":{},}}';
  assert.throws(() => JSON.parse(withComma), 'the fixture must actually be invalid strict JSON');
  assert.deepStrictEqual(pf.parseGoadConfigJson(withComma).lab.hosts.dc01, { a: 1 });
  // A comma inside a string literal is data, not syntax.
  assert.strictEqual(
    pf.parseGoadConfigJson('{"pw":"a,}b"}').pw, 'a,}b');
  assert.throws(() => pf.parseGoadConfigJson('{not json'), /not parseable/);
});

test('an unparseable config.json is one finding, not a thrown exception', () => {
  // The core is total: a caller iterating a hundred generated labs must not have
  // the loop killed by lab seventeen.
  const r = pf.preflightGoadLab({ labName: 'BROKEN', config: '{oops', inventory: '', providerInventory: '' });
  assert.strictEqual(r.ok, false);
  assert.deepStrictEqual(codes(r), [pf.CODE.CONFIG_UNPARSEABLE]);
});

test('a config with no lab.hosts / lab.domains stops at one shape finding', () => {
  const r = pf.preflightGoadLab({ labName: 'EMPTY', config: {}, inventory: '', providerInventory: '' });
  assert.deepStrictEqual(codes(r), [pf.CODE.CONFIG_SHAPE]);
});

test('assertGoadLabPreflight throws 422 listing every error, and passes warnings through', () => {
  assert.throws(
    () => pf.assertGoadLabPreflight({
      labName: 'FIXTURE', config: baseConfig(), inventory: BASE_INVENTORY.replace('admin_user=administrator\n', ''),
      providerInventory: BASE_PROVIDER,
    }),
    (err) => err.status === 422
      && /no VM was created/.test(err.message)
      && /admin_user/.test(err.message)
      && Array.isArray(err.findings));

  const warned = pf.assertGoadLabPreflight({
    labName: 'FIXTURE',
    config: (() => { const c = baseConfig(); delete c.lab.domains['corp.lab'].laps_path; return c; })(),
    inventory: BASE_INVENTORY,
    providerInventory: BASE_PROVIDER,
  });
  assert.strictEqual(warned.ok, true);
  assert.strictEqual(warned.warnings.length, 2, 'warnings must survive the boundary, not be thrown');
});

// ── §7. the shipped labs ────────────────────────────────────────────────────
// Guarded: GOAD-main/ is gitignored, so these do not run in CI or on a fresh
// clone. §1-§6 above are the load-bearing guard; this is corroboration against
// the real thing.

/** Prefer proxmox — the provider this repo actually deploys on. MINILAB and
 *  TEMPLATE predate it and only ship virtualbox/vmware. */
function readLab(name) {
  const dir = path.join(GOAD_AD, name);
  const provider = ['proxmox', 'virtualbox', 'vmware']
    .map((p) => path.join(dir, 'providers', p, 'inventory'))
    .find((p) => fs.existsSync(p));
  return {
    labName: name,
    config: fs.readFileSync(path.join(dir, 'data', 'config.json'), 'utf8'),
    inventory: fs.readFileSync(path.join(dir, 'data', 'inventory'), 'utf8'),
    providerInventory: fs.readFileSync(provider, 'utf8'),
    playbooks: pf.chainForLab(fs.readFileSync(GOAD_PLAYBOOKS, 'utf8'), name),
  };
}

test('every shipped lab except TEMPLATE passes clean', { skip: NO_GOAD }, () => {
  const labs = fs.readdirSync(GOAD_AD)
    .filter((n) => fs.existsSync(path.join(GOAD_AD, n, 'data', 'config.json')) && n !== 'TEMPLATE');
  assert.ok(labs.length >= 5, `expected the shipped lab set, found ${labs.join(', ')}`);
  for (const name of labs) {
    const r = pf.preflightGoadLab(readLab(name));
    assert.deepStrictEqual(r.findings, [],
      `ad/${name} is a lab upstream ships and builds; the checker must not reject it${dump(r)}`);
  }
});

test('ad/TEMPLATE FAILS on exactly the two missing inventory vars', { skip: NO_GOAD }, () => {
  // The proof the checker works. TEMPLATE is upstream's "copy this to start a
  // new lab" directory, its config.json is complete and self-consistent, and it
  // still cannot be built: data/inventory defines neither admin_user nor
  // dns_server_forwarder, and roles/domain_controller dereferences the second
  // one three playbooks into a sixteen-playbook chain.
  //
  // Asserting the EXACT finding set, not just ok === false, is the point. A
  // checker that rejected TEMPLATE for some incidental extra reason would pass a
  // looser assertion while proving nothing about the two vars.
  const r = pf.preflightGoadLab(readLab('TEMPLATE'));
  assert.strictEqual(r.ok, false, 'upstream\'s own starting template does not produce a runnable lab');
  assert.deepStrictEqual(
    r.findings.map((f) => [f.code, f.id, f.severity]),
    [
      [pf.CODE.INVENTORY_VAR_MISSING, 'admin_user', pf.SEVERITY.ERROR],
      [pf.CODE.INVENTORY_VAR_MISSING, 'dns_server_forwarder', pf.SEVERITY.ERROR],
    ],
    `TEMPLATE must fail on those two vars and nothing else${dump(r)}`);
});

test('adding the two vars is enough to make TEMPLATE pass', { skip: NO_GOAD }, () => {
  // The other half of the proof: the checker is not rejecting TEMPLATE for some
  // unrelated reason it happens to also report.
  const input = readLab('TEMPLATE');
  input.inventory = input.inventory.replace('[all:vars]',
    '[all:vars]\nadmin_user=administrator\ndns_server_forwarder=1.1.1.1');
  const r = pf.preflightGoadLab(input);
  assert.deepStrictEqual(r.findings, [], dump(r));
});

test('ad/DRACARYS parses despite the trailing comma upstream ships', { skip: NO_GOAD }, () => {
  // Guards the tolerant parser against a future "tidy-up" that swaps it for
  // JSON.parse: that change would look harmless and would make one shipped lab
  // unpreflightable.
  const raw = fs.readFileSync(path.join(GOAD_AD, 'DRACARYS', 'data', 'config.json'), 'utf8');
  assert.throws(() => JSON.parse(raw), 'DRACARYS config.json is expected to be invalid strict JSON');
  assert.ok(pf.parseGoadConfigJson(raw).lab.hosts.dc01, 'the tolerant parser must still read it');
});

test('every shipped lab resolves a chain out of playbooks.yml', { skip: NO_GOAD }, () => {
  // If chainForLab silently returned null the gated checks would all fall back
  // to DEFAULT_CHAIN, which is wrong for the four labs that override it.
  const yml = fs.readFileSync(GOAD_PLAYBOOKS, 'utf8');
  for (const name of fs.readdirSync(GOAD_AD)) {
    const chain = pf.chainForLab(yml, name);
    assert.ok(Array.isArray(chain) && chain.length > 0, `no chain resolved for ad/${name}`);
    assert.ok(chain.includes('build.yml'), `ad/${name} chain does not start from build.yml`);
  }
  // SCCM comments out laps.yml and ad-child_domain.yml; DRACARYS never lists
  // servers.yml. Both are the reason gating exists.
  assert.ok(!pf.chainForLab(yml, 'SCCM').includes('laps.yml'));
  assert.ok(!pf.chainForLab(yml, 'DRACARYS').includes('servers.yml'));
});

test('no shipped lab trips the emptiness rules, and every one of them trips when emptied',
  { skip: NO_GOAD }, () => {
  // The false-positive question, answered against the real labs instead of the
  // fixture. Two halves, and the second is what keeps the first from being
  // vacuous: a rule that never fires would also sweep seven labs clean.
  //
  // Every deployable lab ships a populated users and groups dict on every
  // domain — MINILAB carries four users and a single `global` group and is the
  // thinnest of them — so treating {} as unfilled cannot cost upstream a lab.
  const labs = fs.readdirSync(GOAD_AD)
    .filter((n) => fs.existsSync(path.join(GOAD_AD, n, 'data', 'config.json')) && n !== 'TEMPLATE');
  for (const expected of ['DRACARYS', 'GOAD', 'GOAD-Light', 'GOAD-Mini', 'MINILAB', 'NHA', 'SCCM']) {
    assert.ok(labs.includes(expected), `ad/${expected} is missing from the sweep`);
  }
  for (const name of labs) {
    const input = readLab(name);
    const asShipped = pf.preflightGoadLab(input);
    assert.deepStrictEqual(asShipped.findings, [],
      `ad/${name} builds today; the emptiness rules must not reject it${dump(asShipped)}`);

    const cfg = pf.parseGoadConfigJson(input.config);
    for (const dom of Object.values(cfg.lab.domains)) { dom.users = {}; dom.groups = {}; }
    const referenced = new Set(Object.values(cfg.lab.hosts)
      .map((h) => (h && h.domain ? h.domain : null)).filter(Boolean));
    const emptied = pf.preflightGoadLab({ ...input, config: cfg });
    assert.strictEqual(emptied.ok, false,
      `ad/${name} with its payload emptied must not pre-flight clean${dump(emptied)}`);
    assert.deepStrictEqual(
      emptied.findings.map((f) => f.code),
      new Array(referenced.size * 2).fill(pf.CODE.DOMAIN_KEY_MISSING),
      `ad/${name}: two findings per domain in use, and nothing else${dump(emptied)}`);
  }
});
