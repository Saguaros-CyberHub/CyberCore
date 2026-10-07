/**
 * ciab-goad-postcondition-probe.test.js — Track V1: after the bake, assert what
 * is ACTUALLY TRUE.
 *
 * WHY THIS FILE EXISTS
 * GOAD's deploy is 16 ansible-playbook invocations over ~90 minutes, and nothing
 * in a host's `vulns` is even parsed until ~95% of the way in. What comes back
 * is one exit code, and that exit code is close to meaningless here — not as an
 * opinion, as an audited fact about the pinned tree: `changed_when` appears
 * exactly TWICE in the whole role library, `error_action: stop` SIX times, and
 * an audit found 20 sites where a task reports SUCCESS and did nothing.
 *
 * Three of those 20 are SHIPPED VULNERABILITIES that are silently absent after a
 * fully green run, and the fixture in section 6 is built from exactly those
 * three. That fixture is the specification of why this component exists:
 *
 *   vulns/adcs_esc7       inverted PSPKI guard (the grant is in the else branch,
 *                         and the preceding task installs the module) -> ManageCA
 *                         is never granted.
 *   move_to_ou            `... = Get-ADOrganizationalUnit ... > $null` eats the
 *                         success stream, so the "already in place?" comparison
 *                         is against $null; a bad OU path lands in a typed catch
 *                         that returns green.
 *   vulns/no_ldap_signing writes Services\LDAP\LDAPServerSigningRequirements, a
 *                         path Windows does not read.
 *
 * WHAT IS TESTABLE AND WHAT IS NOT
 * The two halves that carry the knowledge are pure and are pinned here: the
 * BUILDER (which facts to assert, derived mechanically from the lab config) and
 * the PARSER (what an observation means). runPostconditionProbe() is the impure
 * skin — it needs a lane — so only its pure pieces (argv, playbook, host fan-out)
 * are asserted, and those are asserted for the property that matters: no secret
 * is ever in them.
 *
 * The parser tests are mostly FAIL-CLOSED tests, and that is deliberate. A probe
 * whose broken/missing/garbled output reads as "passed" is strictly worse than
 * no probe at all: it converts "we don't know" into "we checked", which is the
 * precise failure this whole component was written to end.
 *
 * Run: node --test front-end/test/ciab-goad-postcondition-probe.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const probe = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-postcondition-probe.js'));

// ── the lab under test ──────────────────────────────────────────────────────
//
// A deliberately small GOAD-shaped lab: two hosts, one domain, and exactly one
// instance of each of the three silent failures. Small enough that the full
// expectation-set id list can be asserted literally (section 2), which is what
// keeps section 6's generated fixture honest — the fixture is derived from the
// builder's output, so an independent pin on the ids is what stops a builder bug
// from quietly rewriting its own specification.

function silentFailureLab() {
  return {
    domains: {
      'north.sevenkingdoms.local': {
        dc: 'dc02',
        domain_password: 'NgtI75cKV+Pu',
        netbios_name: 'NORTH',
        organisation_units: { Servers: { path: 'DC=north,DC=sevenkingdoms,DC=local' } },
        groups: {
          global: { Stark: { path: 'CN=Users,DC=north,DC=sevenkingdoms,DC=local' } },
        },
        users: {
          'robb.stark': {
            firstname: 'Robb',
            surname: 'Stark',
            password: 'sexywolfy',
            groups: ['Stark'],
            path: 'CN=Users,DC=north,DC=sevenkingdoms,DC=local',
            spns: ['CIFS/winterfell.north.sevenkingdoms.local'],
          },
        },
        acls: {
          GenericAll_stark_robb: {
            for: 'Stark', to: 'robb.stark', right: 'GenericAll', inheritance: 'None',
          },
        },
      },
    },
    hosts: {
      dc02: {
        hostname: 'winterfell',
        type: 'dc',
        domain: 'north.sevenkingdoms.local',
        local_admin_password: 'NgtI75cKV+Pu',
        path: 'DC=north,DC=sevenkingdoms,DC=local',
        local_groups: { Administrators: ['north\\robb.stark'] },
        vulns: ['no_ldap_signing', 'adcs_esc7', 'files'],
        vulns_vars: {
          adcs_esc7: { esc7: { ca_manager: 'north\\robb.stark' } },
          files: { rdp: { src: 'dc02/bot_rdp.ps1', dest: 'C:\\setup\\bot_rdp.ps1' } },
        },
      },
      srv02: {
        hostname: 'castelblack',
        type: 'server',
        domain: 'north.sevenkingdoms.local',
        local_admin_password: 'NgtI75cKV+Pu',
        // A REAL OU, not the naming-context root — this is what makes the
        // move_to_ou check non-trivial, and it is the shape upstream uses
        // wherever it actually wants a computer moved.
        path: 'OU=Servers,DC=north,DC=sevenkingdoms,DC=local',
        local_groups: { Administrators: ['north\\jeor.mormont'] },
        vulns: [],
      },
    },
  };
}

const LAB = silentFailureLab();

// ── 1. the artifact is real and reviewable ──────────────────────────────────

test('the staged probe script is committed, not conjured at runtime', () => {
  assert.ok(fs.existsSync(probe.PROBE_SCRIPT_PATH),
    `${probe.PROBE_SCRIPT_PATH} must exist — the parser's contract is with THIS file`);
  const script = fs.readFileSync(probe.PROBE_SCRIPT_PATH, 'utf8');
  assert.ok(script.length > 2000, 'the probe script is implausibly small');
  assert.match(script, /param\(/, 'the script must take parameters, not read globals');
});

test('the probe directory is exempted from the blanket data/ ignore rule', () => {
  // .gitignore line 4 is `**/data/*`, so a new file under any data/ directory is
  // invisible to git by default — and git never descends into an excluded
  // DIRECTORY, so the /** negation alone re-includes nothing. Both lines are
  // required. Getting this wrong reproduces the exact class of failure the probe
  // exists to catch: an artifact that works on the authoring machine, is absent
  // everywhere else, and shows up in no diff.
  const gitignore = fs.readFileSync(path.join(ROOT, '..', '.gitignore'), 'utf8');
  const lines = gitignore.split(/\r?\n/).map((l) => l.trim());
  assert.ok(lines.includes('!**/data/probe/'), '.gitignore must un-ignore the probe DIRECTORY');
  assert.ok(lines.includes('!**/data/probe/**'), '.gitignore must un-ignore the probe directory CONTENTS');
});

test('the script reports observations and never a verdict', () => {
  // The split is the whole integrity argument: if the script could emit `ok`,
  // a script that hardcoded ok:$true would make every report vacuously green —
  // which is precisely the thing being defended against. Assert the observation
  // record has a `present` field and no `ok` field.
  const script = fs.readFileSync(probe.PROBE_SCRIPT_PATH, 'utf8');
  assert.match(script, /present\s+=\s+\$Present/, 'Add-Observation must record `present`');
  assert.ok(!/^\s*ok\s*=/m.test(script),
    'the probe script must not emit an `ok` field — the verdict belongs to the Node parser');
});

test('the script is pure ASCII, because 5.1 reads a BOM-less .ps1 as the ANSI code page', () => {
  // Found the hard way. An em dash inside a double-quoted string arrives from
  // its UTF-8 bytes as three cp1252 characters ending in U+201D RIGHT DOUBLE
  // QUOTATION MARK — which PowerShell accepts as a string delimiter. The string
  // terminates early and the rest of the function parses as garbage, which
  // Windows reports as a parse error somewhere else entirely. Adding a BOM is
  // not the fix: the playbook inlines this file with lookup('file', …) into
  // win_powershell's `script:`, so a BOM would ride along as a leading
  // character. Staying ASCII is the fix.
  const script = fs.readFileSync(probe.PROBE_SCRIPT_PATH, 'utf8');
  const offenders = [];
  for (let i = 0; i < script.length; i += 1) {
    if (script.charCodeAt(i) > 127) {
      const line = script.slice(0, i).split('\n').length;
      offenders.push(`line ${line}: U+${script.charCodeAt(i).toString(16).toUpperCase().padStart(4, '0')}`);
      if (offenders.length >= 5) break;
    }
  }
  assert.deepStrictEqual(offenders, [],
    'the probe script must contain no character above U+007F');
});

test('every kind the builder can emit is implemented by the script', () => {
  // The two files are one contract split across two languages, and the seam is
  // a string literal in a switch. A kind the builder emits and the script does
  // not handle is reported as "not implemented" — a failure, but a confusing
  // one, and it would only ever be discovered on a lane.
  const script = fs.readFileSync(probe.PROBE_SCRIPT_PATH, 'utf8');
  for (const kind of probe.CHECK_KINDS) {
    assert.ok(new RegExp(`'${kind}'\\s+\\{\\s*Test-`).test(script),
      `the probe script has no switch branch for check kind '${kind}'`);
  }
});

test('the script exits 0 even when preconditions are missing', () => {
  // A non-zero exit makes Ansible abort the play and destroy the report we came
  // for. A failing precondition is DATA and travels in the result document.
  const script = fs.readFileSync(probe.PROBE_SCRIPT_PATH, 'utf8');
  assert.match(script, /\nexit 0\s*$/, 'the script must end with exit 0');
  // And the result must be written without a BOM: PS 5.1's Out-File/Set-Content
  // default to UTF-16LE, and the controller reads this file back through `cat`.
  assert.match(script, /UTF8Encoding\(\$false\)/,
    'the result must be written with a no-BOM UTF8Encoding');
  assert.match(script, /ConvertTo-Json -Depth 10/,
    'ConvertTo-Json defaults to -Depth 2 and truncates nested `actual` SILENTLY');
});

// ── 2. the builder: mechanical derivation ───────────────────────────────────

test('the expectation set derives exactly the checks the lab config implies', () => {
  // Pinned literally, and this is the pin that section 6 leans on. Both halves
  // matter: a missing id is an unprobed precondition, and an unexpected id is a
  // check nobody can explain when it fails.
  const set = probe.buildExpectationSet(LAB, { labName: 'FIXTURE' });
  const ids = set.checks.map((c) => c.id).sort();
  assert.deepStrictEqual(ids, [
    'acl:north.sevenkingdoms.local:GenericAll_stark_robb',
    'ca:dc02:esc7',
    'file:dc02:files:rdp',
    'group:north.sevenkingdoms.local:Stark:robb.stark',
    'kerberoast:north.sevenkingdoms.local:robb.stark',
    'localgroup:dc02:Administrators:robb.stark',
    'localgroup:srv02:Administrators:jeor.mormont',
    'neg:acl:north.sevenkingdoms.local:robb.stark:Authenticated_Users',
    'neg:acl:north.sevenkingdoms.local:robb.stark:Domain_Users',
    'neg:acl:north.sevenkingdoms.local:robb.stark:Everyone',
    'neg:localgroup:dc02:Authenticated_Users',
    'neg:localgroup:dc02:Domain_Users',
    'neg:localgroup:srv02:Authenticated_Users',
    'neg:localgroup:srv02:Domain_Users',
    'ou:srv02',
    'registry:dc02:no_ldap_signing',
  ]);
});

test('directory queries are addressed to the domain DC, not to the subject host', () => {
  // ou:srv02 is a fact ABOUT srv02 that only the DC can answer. Routing it to
  // srv02 would make it fail on every lane at once, for a reason that has
  // nothing to do with the lab.
  const set = probe.buildExpectationSet(LAB);
  const byId = new Map(set.checks.map((c) => [c.id, c]));
  assert.strictEqual(byId.get('ou:srv02').run_on, 'dc02');
  assert.strictEqual(byId.get('ou:srv02').host, 'srv02');
  assert.strictEqual(byId.get('acl:north.sevenkingdoms.local:GenericAll_stark_robb').run_on, 'dc02');
  // Host-local facts stay on the host.
  assert.strictEqual(byId.get('localgroup:srv02:Administrators:jeor.mormont').run_on, 'srv02');
  assert.strictEqual(byId.get('registry:dc02:no_ldap_signing').run_on, 'dc02');
  assert.deepStrictEqual(probe.probeHosts(set), ['dc02', 'srv02']);
});

test('the registry check names the path WINDOWS reads, not the path the role wrote', () => {
  // THE no_ldap_signing CATCH, stated as data. Probing the written path would
  // prove only that the task ran — which Ansible already claimed, and which is
  // exactly the claim under suspicion.
  const set = probe.buildExpectationSet(LAB);
  const reg = set.checks.find((c) => c.id === 'registry:dc02:no_ldap_signing');
  assert.strictEqual(reg.path, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters');
  assert.strictEqual(reg.name, 'LDAPServerIntegrity');
  assert.strictEqual(reg.data_not_equal, 2);
  assert.strictEqual(reg.written_path, 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LDAP');
  assert.strictEqual(reg.written_name, 'LDAPServerSigningRequirements');
  assert.notStrictEqual(reg.path, reg.written_path,
    'if these ever match for no_ldap_signing, the catch has been neutralised');
  // The sibling role writes the effective path already, so a lab listing it has
  // a SATISFIED precondition. The probe reports the state of the lab, not the
  // correctness of a role, and conflating the two would be a false positive.
  const sibling = probe.REGISTRY_EFFECTS.no_ldap_integrity;
  assert.strictEqual(sibling.path, reg.path);
  assert.strictEqual(sibling.written_path, sibling.path);
});

test('OU placement mirrors the role\'s own notion of "already in place"', () => {
  // Upstream accepts CN=Computers under the target as in-place. Demanding the
  // exact OU would manufacture failures on labs that upstream considers correct,
  // and a report that cries wolf gets ignored exactly as fast as one that stays
  // silent.
  const set = probe.buildExpectationSet(LAB);
  const ou = set.checks.find((c) => c.id === 'ou:srv02');
  assert.strictEqual(ou.computer, 'castelblack', 'the AD object is the hostname, not the dict key');
  assert.deepStrictEqual(ou.accepted_parents, [
    'OU=Servers,DC=north,DC=sevenkingdoms,DC=local',
    'CN=Computers,OU=Servers,DC=north,DC=sevenkingdoms,DC=local',
  ]);
  assert.strictEqual(ou.trivial, false);
  assert.strictEqual(ou.role, 'move_to_ou');
});

test('a domain-root path is flagged trivial rather than counted as coverage', () => {
  // When `path` is the naming context root, the default CN=Computers location
  // already satisfies the role's comparison — so the check passes without
  // proving anything about move_to_ou. Passing quietly would inflate the
  // coverage number with a check that cannot fail.
  const lab = silentFailureLab();
  lab.hosts.srv02.path = 'DC=north,DC=sevenkingdoms,DC=local';
  const ou = probe.buildExpectationSet(lab).checks.find((c) => c.id === 'ou:srv02');
  assert.strictEqual(ou.trivial, true);
});

test('no OU check is emitted where the role does not run', () => {
  // The role's `when` is: not a DC, and not a LAPS host. Emitting outside it
  // invents a failure.
  const noOu = (mutate) => {
    const lab = silentFailureLab();
    mutate(lab);
    return probe.buildExpectationSet(lab).checks.filter((c) => c.kind === 'ou_placement').map((c) => c.id);
  };
  assert.deepStrictEqual(noOu((l) => { l.hosts.srv02.use_laps = true; }), []);
  assert.deepStrictEqual(noOu((l) => { l.hosts.srv02.type = 'dc'; }), []);
  assert.deepStrictEqual(noOu((l) => { delete l.hosts.srv02.path; }), []);
});

test('an extended ACL right carries its ObjectType GUID, because the GUID IS the right', () => {
  // An ExtendedRight ACE with the wrong (or empty) ObjectType grants something
  // else entirely, and a rights-only comparison would call it a pass.
  const lab = silentFailureLab();
  lab.domains['north.sevenkingdoms.local'].acls.ForceChange = {
    for: 'Stark', to: 'robb.stark', right: 'Ext-User-Force-Change-Password', inheritance: 'None',
  };
  const check = probe.buildExpectationSet(lab).checks
    .find((c) => c.id === 'acl:north.sevenkingdoms.local:ForceChange');
  assert.strictEqual(check.ad_right, 'ExtendedRight');
  assert.strictEqual(check.object_type, '00299570-246d-11d0-a768-00aa006e0529');
  assert.strictEqual(check.known_right, true);
});

test('a right outside the role\'s vocabulary is probed AND flagged, not dropped', () => {
  // GOAD matches with an ordinal Array.Contains, so 'genericall' assigns no $ace
  // at all: no ACE is written and the task still reports ok. The check must
  // still exist (the ACE really is absent — that is a true finding) and must say
  // WHY, or the next reader re-derives the whole trap.
  const lab = silentFailureLab();
  lab.domains['north.sevenkingdoms.local'].acls.GenericAll_stark_robb.right = 'genericall';
  const check = probe.buildExpectationSet(lab).checks
    .find((c) => c.id === 'acl:north.sevenkingdoms.local:GenericAll_stark_robb');
  assert.strictEqual(check.known_right, false);
  assert.strictEqual(check.right, 'genericall');
});

test('the host ACL vocabulary is used for host-scoped ACLs', () => {
  // roles/vulns/acls does NOT accept Ext-ManageCA. Validating a host entry
  // against the domain vocabulary would call a guaranteed no-op "known".
  const lab = silentFailureLab();
  lab.hosts.dc02.vulns.push('acls');
  lab.hosts.dc02.vulns_vars.acls = {
    manage: { for: 'robb.stark', to: 'winterfell$', right: 'Ext-ManageCA', inheritance: 'None' },
  };
  const check = probe.buildExpectationSet(lab).checks.find((c) => c.id === 'acl:dc02:host:manage');
  assert.strictEqual(check.context, 'host');
  assert.strictEqual(check.known_right, false,
    'Ext-ManageCA is domain-only; the host role writes no ACE for it and still reports green');
});

test('vulns/directory is read as the bare scalar it is, and an object is refused', () => {
  // The odd one out in the library: item.value IS the path. Every sibling role
  // indexes item.value.<key>, so an object here is the easy generator bug and
  // win_file creates a directory literally named after the stringified dict.
  // Probing "[object Object]" would be a check that can only ever fail for a
  // reason nobody could read.
  const lab = silentFailureLab();
  lab.hosts.dc02.vulns.push('directory');
  lab.hosts.dc02.vulns_vars.directory = { setup: 'C:\\setup' };
  let set = probe.buildExpectationSet(lab);
  const dir = set.checks.find((c) => c.id === 'file:dc02:directory:setup');
  assert.strictEqual(dir.path, 'C:\\setup');
  assert.strictEqual(dir.is_directory, true);
  assert.deepStrictEqual(set.warnings, []);

  lab.hosts.dc02.vulns_vars.directory = { setup: { path: 'C:\\setup' } };
  set = probe.buildExpectationSet(lab);
  assert.strictEqual(set.checks.filter((c) => c.id === 'file:dc02:directory:setup').length, 0);
  assert.strictEqual(set.warnings.length, 1);
  assert.match(set.warnings[0], /dict_of_scalars/);
});

test('the planted-file check asserts the exact dest, because AD cannot see disk', () => {
  // An edge can be perfectly present in AD and still unreachable: a wrong `dest`
  // prefix means the scheduled task's script was never delivered, and nothing in
  // the directory reflects that.
  const file = probe.buildExpectationSet(LAB).checks.find((c) => c.id === 'file:dc02:files:rdp');
  assert.strictEqual(file.path, 'C:\\setup\\bot_rdp.ps1');
  assert.strictEqual(file.is_directory, false);
  assert.strictEqual(file.role, 'files');
});

test('negative probes exist by default and can be switched off', () => {
  // They cost almost nothing — the DACL is already fetched for the positive
  // check on the same object — and they catch over-grants, which are invisible
  // to every other kind of validation because nothing was MISconfigured.
  const withNeg = probe.buildExpectationSet(LAB).checks.filter((c) => c.expect === 'absent');
  assert.strictEqual(withNeg.length, 7, '3 ACL over-grants + 2 hosts x 2 local-admin over-grants');
  for (const c of withNeg) assert.strictEqual(c.origin, 'negative-probe');
  const without = probe.buildExpectationSet(LAB, { negatives: false }).checks
    .filter((c) => c.expect === 'absent');
  assert.deepStrictEqual(without, []);
});

test('every check carries the role it is holding to account', () => {
  // by_role is what turns the report into "these roles reported green and
  // planted nothing". A check with no role is a finding nobody can act on.
  for (const check of probe.buildExpectationSet(LAB).checks) {
    assert.ok(check.role, `${check.id} names no role`);
    assert.ok(check.why && check.why.length > 20, `${check.id} does not say why it matters`);
    assert.ok(check.expected && check.expected.length > 0, `${check.id} has no readable expectation`);
    assert.ok(check.origin, `${check.id} does not say where in the lab it came from`);
  }
});

// ── 3. the secrets guard ────────────────────────────────────────────────────

test('no lab secret reaches the expectation set', () => {
  // The set is staged to C:\Windows\Temp, which is traversable by Users — the
  // exposure flag-manager.js refuses for capture flags, for the same reason: a
  // student holding the low-priv shell we deliberately gave them can read it.
  // The builder walks right past users[].password on its way to users[].spns, so
  // this is a test rather than a habit.
  const secrets = probe.collectLabSecrets(LAB);
  assert.ok(secrets.includes('sexywolfy'), 'the harvester must see the user password');
  assert.ok(secrets.includes('NgtI75cKV+Pu'), 'the harvester must see domain/local admin passwords');

  const set = probe.buildExpectationSet(LAB, { verifyCredentials: true });
  assert.doesNotThrow(() => probe.assertNoSecrets(set, secrets));
  const serialised = probe.toProbeJson(set);
  for (const secret of secrets) {
    assert.ok(serialised.indexOf(secret) === -1, `the staged JSON contains the secret ${secret.slice(0, 3)}…`);
  }
});

test('a credential is referenced by NAME, never carried', () => {
  const set = probe.buildExpectationSet(LAB, { verifyCredentials: true });
  const roast = set.checks.find((c) => c.kind === 'kerberoast');
  assert.strictEqual(roast.credential_ref, 'north.sevenkingdoms.local\\robb.stark');
  assert.strictEqual(roast.password, undefined);
  assert.deepStrictEqual(set.credential_refs, ['north.sevenkingdoms.local\\robb.stark']);
});

test('assertNoSecrets actually fires when a secret slips in', () => {
  // A guard nobody has seen fail is a guard nobody knows works.
  const set = probe.buildExpectationSet(LAB);
  set.checks[0].password = 'sexywolfy';
  assert.throws(() => probe.assertNoSecrets(set, probe.collectLabSecrets(LAB)),
    /world-traversable/);
  // And the error must not name the secret — it gets logged.
  try {
    probe.assertNoSecrets(set, probe.collectLabSecrets(LAB));
  } catch (err) {
    assert.ok(err.message.indexOf('sexywolfy') === -1, 'the guard must not echo the secret it found');
  }
});

test('credential-dependent checks are off by default', () => {
  // They report INCONCLUSIVE without a credential, which this module grades as a
  // failure. Emitting them unconditionally would make every credential-free run
  // red for a reason about the probe rather than the lab — and an always-red
  // report is exactly as useless as an always-green one.
  const off = probe.buildExpectationSet(LAB);
  assert.deepStrictEqual(off.credential_refs, []);
  assert.strictEqual(off.checks.filter((c) => c.kind === 'share_read').length, 0);
  assert.strictEqual(off.checks.find((c) => c.kind === 'kerberoast').credential_ref, undefined);

  const lab = silentFailureLab();
  lab.hosts.dc02.vulns.push('permissions');
  lab.hosts.dc02.vulns_vars.permissions = {
    share: { path: 'C:\\shares\\hr', user: 'north\\robb.stark', rights: 'Read' },
  };
  const on = probe.buildExpectationSet(lab, { verifyCredentials: true });
  const share = on.checks.find((c) => c.kind === 'share_read');
  assert.strictEqual(share.via, 'winrm');
  assert.strictEqual(share.credential_ref, 'north\\robb.stark');
  assert.strictEqual(share.target_host, 'winterfell');
});

// ── 4. builder traps ────────────────────────────────────────────────────────

test('a duplicate check id is a hard error, not a silent collapse', () => {
  // Two checks sharing an id merge on the way back through the result map — one
  // assertion silently stops being made, which is the exact failure mode this
  // component exists to catch.
  assert.throws(
    () => probe.buildExpectationSet(LAB, {
      extra: [
        { id: 'ou:srv02', kind: 'asrep', run_on: 'dc02', user: 'x' },
      ],
    }),
    /duplicate check id 'ou:srv02'/);
});

test('a declared check with an unknown kind is refused at build time', () => {
  // The script would report it as "not implemented" — a failure, not a skip —
  // but shipping it is a programming error and belongs in a diff, not a lane.
  assert.throws(
    () => probe.buildExpectationSet(LAB, { extra: [{ kind: 'sidhistory', run_on: 'dc02' }] }),
    /unknown check kind 'sidhistory'/);
  assert.throws(
    () => probe.buildExpectationSet(LAB, { extra: [{ kind: 'asrep', user: 'x' }] }),
    /has no run_on host/);
});

test('script-planted edges must be DECLARED, and are counted as such', () => {
  // GOAD plants AS-REP roasting and delegation through freeform
  // ad/<LAB>/scripts/*.ps1 run by roles/ps. There is no honest way to derive an
  // expectation from arbitrary PowerShell, so those edges are declared — and the
  // count is reported so the coverage claim stays truthful.
  const set = probe.buildExpectationSet(LAB, {
    extra: [
      { kind: 'asrep', run_on: 'dc02', host: 'dc02', user: 'brandon.stark', role: 'ps', why: 'asrep_roasting.ps1 is freeform PowerShell nothing validates' },
      {
        kind: 'delegation', run_on: 'dc02', host: 'dc02', principal: 'jon.snow', role: 'ps',
        delegation: 'constrained', allowed_to_delegate_to: ['CIFS/winterfell.north.sevenkingdoms.local'],
        why: 'constrained_delegation_use_any.ps1 is freeform PowerShell nothing validates',
      },
    ],
  });
  const declared = set.checks.filter((c) => c.origin === 'declared');
  assert.strictEqual(declared.length, 2);
  assert.deepStrictEqual(declared.map((c) => c.id), ['declared:asrep:1', 'declared:delegation:2']);
  assert.match(declared[0].expected, /brandon\.stark has DoesNotRequirePreAuth set/);
  assert.match(declared[1].expected, /constrained delegation to CIFS\/winterfell/);
});

test('a negative probe\'s expectation reads as a negative sentence', () => {
  // The `expected` string sits next to `actual` in front of an instructor. A
  // negative probe whose sentence read positively would invert the report's
  // meaning at the only point a human looks at it.
  const set = probe.buildExpectationSet(LAB);
  const neg = set.checks.find((c) => c.id === 'neg:localgroup:dc02:Domain_Users');
  assert.match(neg.expected, /is NOT a member of local Administrators on dc02/);
  const pos = set.checks.find((c) => c.id === 'localgroup:dc02:Administrators:robb.stark');
  assert.match(pos.expected, /is a member of local Administrators on dc02/);
});

// ── 5. the parser: fail-closed ──────────────────────────────────────────────

/** A result document in which every check observed exactly what was intended.
 *  `overrides` replaces individual observations by id. */
function greenDocument(set, runOn, overrides) {
  const results = set.checks
    .filter((c) => c.run_on === runOn)
    .map((c) => Object.assign({
      id: c.id,
      // A negative probe's intended observation is present:false.
      present: c.expect !== 'absent',
      actual: null,
      detail: 'as intended',
      error: '',
      inconclusive: false,
    }, (overrides || {})[c.id] || {}));
  return {
    schema_version: probe.SCHEMA_VERSION,
    probe_version: '1.0.0',
    run_on: runOn,
    started_at: '2026-08-31T00:00:00.0000000Z',
    finished_at: '2026-08-31T00:01:00.0000000Z',
    fatal: '',
    results,
  };
}

test('an all-green run passes', () => {
  const set = probe.buildExpectationSet(LAB);
  const result = probe.parseProbeResult(
    [greenDocument(set, 'dc02'), greenDocument(set, 'srv02')], set);
  assert.strictEqual(result.passed, true, probe.formatFailures(result));
  assert.strictEqual(result.summary.total, 16);
  assert.strictEqual(result.summary.ok, 16);
  assert.strictEqual(result.summary.failed, 0);
  assert.strictEqual(result.summary.negative, 7);
  assert.deepStrictEqual(result.errors, []);
});

test('a missing result fails every check rather than passing quietly', () => {
  // The single most important property in this file. runGoadPlaybook's readFile
  // idiom returns '__MISSING__' for an absent file, so that exact string is the
  // realistic input.
  const set = probe.buildExpectationSet(LAB);
  const result = probe.parseProbeResult(['__MISSING__', '__MISSING__'], set);
  assert.strictEqual(result.passed, false);
  assert.strictEqual(result.summary.failed, 16);
  assert.strictEqual(result.summary.ok, 0);
  assert.ok(result.errors.length > 0);
  for (const check of result.checks) {
    assert.match(check.detail, /no result|nothing about this precondition is known/);
  }
});

test('unparseable output is an error, not an exception', () => {
  // The parser is the thing that reports on a broken run; it cannot itself be
  // the thing that crashes.
  const set = probe.buildExpectationSet(LAB);
  let result;
  assert.doesNotThrow(() => { result = probe.parseProbeResult('At line:1 char:1 + oops', set); });
  assert.strictEqual(result.passed, false);
  assert.match(result.errors.join(' '), /not parseable JSON/);
  assert.strictEqual(probe.parseProbeResult(null, set).passed, false);
  assert.strictEqual(probe.parseProbeResult(undefined, set).passed, false);
});

test('a non-boolean observation is unknown, and unknown fails', () => {
  // `"present": "true"` — a JSON string — passes a truthiness test and is
  // exactly what a hand-rolled or drifting emitter produces.
  const set = probe.buildExpectationSet(LAB, { negatives: false });
  const doc = greenDocument(set, 'dc02', {
    'file:dc02:files:rdp': { present: 'true' },
  });
  const result = probe.parseProbeResult([doc, greenDocument(set, 'srv02')], set);
  const row = result.checks.find((c) => c.id === 'file:dc02:files:rdp');
  assert.strictEqual(row.ok, false);
  assert.match(row.detail, /non-boolean observation/);
});

test('a query that raised fails BOTH polarities', () => {
  // The subtle one. A negative probe whose query errored would otherwise read as
  // "absent, as intended" — a silent success, which is the whole bug class here.
  const set = probe.buildExpectationSet(LAB);
  const doc = greenDocument(set, 'dc02', {
    'neg:localgroup:dc02:Domain_Users': { present: false, error: 'The group name could not be found.' },
    'file:dc02:files:rdp': { present: true, error: 'Access is denied.' },
  });
  const result = probe.parseProbeResult([doc, greenDocument(set, 'srv02')], set);
  const negative = result.checks.find((c) => c.id === 'neg:localgroup:dc02:Domain_Users');
  const positive = result.checks.find((c) => c.id === 'file:dc02:files:rdp');
  assert.strictEqual(negative.ok, false, 'an errored negative probe must not read as satisfied');
  assert.strictEqual(positive.ok, false);
  assert.match(negative.detail, /error: The group name could not be found\./);
});

test('inconclusive is not satisfied, and is counted separately', () => {
  const set = probe.buildExpectationSet(LAB);
  const doc = greenDocument(set, 'dc02', {
    'ca:dc02:esc7': { present: false, inconclusive: true, detail: 'PSPKI is not installed on this host' },
  });
  const result = probe.parseProbeResult([doc, greenDocument(set, 'srv02')], set);
  const row = result.checks.find((c) => c.id === 'ca:dc02:esc7');
  assert.strictEqual(row.ok, false);
  assert.strictEqual(row.inconclusive, true);
  assert.strictEqual(result.summary.inconclusive, 1);
  assert.match(row.detail, /unproven, which is not the same as satisfied/);
});

test('an `ok` supplied by the script is ignored', () => {
  // The integrity property, exercised. A script that claimed ok:true on an
  // observation of present:false must not be believed — the verdict is computed
  // here, from `expect`, and nowhere else.
  const set = probe.buildExpectationSet(LAB, { negatives: false });
  const doc = greenDocument(set, 'dc02', {
    'file:dc02:files:rdp': { present: false, ok: true, detail: 'trust me' },
  });
  const result = probe.parseProbeResult([doc, greenDocument(set, 'srv02')], set);
  assert.strictEqual(result.checks.find((c) => c.id === 'file:dc02:files:rdp').ok, false);
});

test('a single observation arriving as a bare object is still read', () => {
  // ConvertTo-Json collapses a one-element array into an object. Normalised in
  // the script AND here, because a trap this cheap gets belt and braces.
  const set = probe.buildExpectationSet(LAB, { negatives: false, extra: [] });
  const one = probe.buildExpectationSet({
    hosts: { dc02: { hostname: 'winterfell', type: 'dc', domain: 'd', vulns: ['ntlmdowngrade'] } },
    domains: { d: { dc: 'dc02' } },
  }, { negatives: false });
  assert.strictEqual(one.checks.length, 1);
  const result = probe.parseProbeResult({
    schema_version: probe.SCHEMA_VERSION,
    run_on: 'dc02',
    results: { id: one.checks[0].id, present: true, actual: null, detail: 'ok', error: '', inconclusive: false },
  }, one);
  assert.strictEqual(result.passed, true, probe.formatFailures(result));
  assert.ok(set.checks.length > 0);
});

test('a UTF-8 BOM on the result does not defeat the parser', () => {
  const set = probe.buildExpectationSet(LAB);
  const raws = [
    '\ufeff' + JSON.stringify(greenDocument(set, 'dc02')),
    JSON.stringify(greenDocument(set, 'srv02')),
  ];
  assert.strictEqual(probe.parseProbeResult(raws, set).passed, true);
});

test('a result for an unknown id is drift, and drift is a failure', () => {
  // It means the probe answered a question nobody asked, so the questions we DID
  // ask may not be the ones that ran.
  const set = probe.buildExpectationSet(LAB);
  const doc = greenDocument(set, 'dc02');
  doc.results.push({ id: 'registry:dc02:from_an_older_set', present: true, actual: null, detail: '', error: '', inconclusive: false });
  const result = probe.parseProbeResult([doc, greenDocument(set, 'srv02')], set);
  assert.strictEqual(result.passed, false);
  assert.strictEqual(result.summary.extra, 1);
  assert.match(result.checks.find((c) => c.id === 'registry:dc02:from_an_older_set').detail, /drifted/);
});

test('one check reported by two hosts is a routing bug, not a pass', () => {
  const set = probe.buildExpectationSet(LAB);
  const dc = greenDocument(set, 'dc02');
  const srv = greenDocument(set, 'srv02');
  srv.results.push(dc.results.find((r) => r.id === 'ou:srv02'));
  const result = probe.parseProbeResult([dc, srv], set);
  const row = result.checks.find((c) => c.id === 'ou:srv02');
  assert.strictEqual(row.ok, false);
  assert.match(row.detail, /more than one host reported/);
});

test('a schema mismatch and a fatal are surfaced, not swallowed', () => {
  const set = probe.buildExpectationSet(LAB);
  const dc = greenDocument(set, 'dc02');
  dc.schema_version = 99;
  const srv = greenDocument(set, 'srv02');
  srv.fatal = 'expectation set unreadable: Could not find file';
  const result = probe.parseProbeResult([dc, srv], set);
  assert.strictEqual(result.passed, false);
  assert.match(result.errors.join(' | '), /schema_version 99/);
  assert.match(result.errors.join(' | '), /expectation set unreadable/);
});

// ── 6. THE FIXTURE — Ansible green, three preconditions absent ──────────────

test('the three silent failures are caught, and nothing else is', () => {
  // ============================================================================
  // THIS TEST IS THE SPECIFICATION OF THE WHOLE COMPONENT.
  //
  // The scenario is a bake that Ansible reported as a complete success. Every
  // task ran, every task was green, `changed` said whatever it said, and the
  // exit code was 0. And yet three shipped vulnerabilities are not in the
  // environment:
  //
  //   registry:dc02:no_ldap_signing  the role wrote Services\LDAP\
  //       LDAPServerSigningRequirements, which Windows does not read, so the
  //       value Windows DOES read (NTDS\Parameters\LDAPServerIntegrity) was
  //       never created.
  //   ca:dc02:esc7  the inverted PSPKI guard meant the ManageCA grant was in a
  //       branch that never executes, so the CA ACL has no entry for the
  //       intended manager. ESC7 IS that grant; without it there is no ESC7.
  //   ou:srv02  move_to_ou's `> $null` left $target_ou null, so the in-place
  //       comparison was nonsense and the move either never happened or threw
  //       into the typed catch. castelblack is still in CN=Computers.
  //
  // Everything else in the lab is genuinely fine, including all seven negative
  // probes. So the probe must report EXACTLY these three and no others: a report
  // with extra noise gets ignored just as fast as one that says nothing.
  // ============================================================================
  const set = probe.buildExpectationSet(LAB, { labName: 'FIXTURE' });

  const dc02 = greenDocument(set, 'dc02', {
    'registry:dc02:no_ldap_signing': {
      present: false,
      actual: null,
      detail: "value 'LDAPServerIntegrity' does not exist under "
        + "'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\NTDS\\Parameters'",
    },
    'ca:dc02:esc7': {
      present: false,
      actual: [
        { identity: 'NORTH\\Domain Admins', rights: 'Read, Enroll, ManageCA, ManageCertificates', type: 'Allow' },
        { identity: 'BUILTIN\\Administrators', rights: 'Read, Enroll, ManageCA, ManageCertificates', type: 'Allow' },
        { identity: 'NT AUTHORITY\\Authenticated Users', rights: 'Read, Enroll', type: 'Allow' },
      ],
      detail: "'north\\robb.stark' holds ManageCA on CA 'NORTH-WINTERFELL-CA': False",
    },
    'ou:srv02': {
      present: false,
      actual: {
        distinguished_name: 'CN=CASTELBLACK,CN=Computers,DC=north,DC=sevenkingdoms,DC=local',
        parent: 'CN=Computers,DC=north,DC=sevenkingdoms,DC=local',
      },
      detail: "'castelblack' sits under 'CN=Computers,DC=north,DC=sevenkingdoms,DC=local'",
    },
  });
  const srv02 = greenDocument(set, 'srv02');

  const result = probe.parseProbeResult(
    [JSON.stringify(dc02), JSON.stringify(srv02)], set);

  assert.strictEqual(result.passed, false, 'a lab missing three shipped vulns must not pass');
  assert.deepStrictEqual(
    probe.failures(result).map((c) => c.id).sort(),
    ['ca:dc02:esc7', 'ou:srv02', 'registry:dc02:no_ldap_signing'],
    'exactly the three silent failures, no more and no fewer');
  assert.strictEqual(result.summary.failed, 3);
  assert.strictEqual(result.summary.ok, 13);
  assert.strictEqual(result.summary.inconclusive, 0);
  assert.strictEqual(result.summary.missing, 0);
  assert.strictEqual(result.summary.extra, 0);
  assert.deepStrictEqual(result.errors, []);

  // The report has to name the CULPRIT ROLE, because "adcs_esc7 planted nothing"
  // is actionable and "check ca:dc02:esc7 failed" is a puzzle.
  assert.deepStrictEqual(result.summary.by_role.adcs_esc7, { total: 1, failed: 1 });
  assert.deepStrictEqual(result.summary.by_role.move_to_ou, { total: 1, failed: 1 });
  assert.deepStrictEqual(result.summary.by_role.no_ldap_signing, { total: 1, failed: 1 });
  // …and must not smear blame onto the roles that did their job.
  assert.deepStrictEqual(result.summary.by_role.files, { total: 1, failed: 0 });
  assert.deepStrictEqual(result.summary.by_role.acl, { total: 4, failed: 0 });

  // Every negative probe held: this is not a lab that "passed" by being empty.
  const negatives = result.checks.filter((c) => c.expect === 'absent');
  assert.strictEqual(negatives.length, 7);
  assert.ok(negatives.every((c) => c.ok), 'the over-grant probes must all be satisfied here');

  // The instructor-facing text has to carry the diagnosis on its own.
  const text = probe.formatFailures(result);
  assert.match(text, /\[adcs_esc7\]/);
  assert.match(text, /\[move_to_ou\]/);
  assert.match(text, /\[no_ldap_signing\]/);
  assert.match(text, /LDAPServerIntegrity' does not exist/);
  assert.match(text, /CN=Computers,DC=north/);
});

test('the same fixture with the three preconditions PRESENT passes', () => {
  // The other half of the specification. If the probe reported these three as
  // failures no matter what, it would be a constant, and a constant is not a
  // measurement.
  const set = probe.buildExpectationSet(LAB, { labName: 'FIXTURE' });
  const result = probe.parseProbeResult(
    [greenDocument(set, 'dc02'), greenDocument(set, 'srv02')], set);
  assert.strictEqual(result.passed, true, probe.formatFailures(result));
  assert.strictEqual(probe.failures(result).length, 0);
});

// ── 7. the controller-side invocation ───────────────────────────────────────

test('no secret is ever an ansible-playbook argument', () => {
  // script-executor.js interpolates script_args UNQUOTED and stages payloads in
  // C:\Windows\Temp with a tee'd log. Credentials travel in an --extra-vars FILE
  // written with umask 077 on the controller and reach the guest through
  // win_powershell `parameters:` under no_log — never through argv.
  const argv = probe.buildProbeArgv({ labName: 'GOAD', hosts: ['dc02', 'srv02'] });
  const joined = argv.join(' ');
  for (const secret of probe.collectLabSecrets(LAB)) {
    assert.ok(joined.indexOf(secret) === -1, 'a secret reached the command line');
  }
  assert.ok(joined.indexOf('--limit dc02,srv02') !== -1, 'the run must be limited to the probe hosts');
  assert.ok(argv.includes('/opt/goad/ad/GOAD/data/inventory'), 'the lab inventory must be first');
  assert.ok(argv.includes('/var/lib/goad-run/inventory_overrides'),
    'the same WinRM overrides Ansible connected with — a probe that connects differently '
    + 'cannot distinguish "not planted" from "could not reach the host"');
});

test('the playbook hides the credential and cleans up on failure', () => {
  const yaml = probe.buildProbePlaybook({});
  assert.match(yaml, /no_log: true/, 'the task carrying CredentialJson must be no_log');
  assert.match(yaml, /CredentialJson: /, 'credentials go through parameters, not a command line');
  assert.match(yaml, /always:/, 'cleanup must run even when the probe fails');
  assert.match(yaml, /state: absent/);
  // The staged expectation set is the only thing that lands on the guest, and it
  // is exactly the thing assertNoSecrets() guarantees is safe to land there.
  assert.match(yaml, /ciab_probe_expectation/);
  assert.ok(!/password/i.test(yaml.replace(/ansible_become_password: "\{\{ ciab_probe_become_password \}\}"/, '')),
    'no literal password may appear in the playbook body');
});

test('an empty expectation set needs no hosts and no run', () => {
  const empty = probe.buildExpectationSet({}, {});
  assert.deepStrictEqual(empty.checks, []);
  assert.deepStrictEqual(probe.probeHosts(empty), []);
  const result = probe.parseProbeResult([], empty);
  assert.strictEqual(result.passed, true, 'nothing asserted is vacuously satisfied');
  assert.strictEqual(result.summary.total, 0);
});

test('a domain with no DC is a warning, not a silent hole', () => {
  // Emitting no checks for a whole domain and saying nothing would be the same
  // invisible gap the probe exists to close.
  const set = probe.buildExpectationSet({ domains: { 'orphan.local': { acls: {} } }, hosts: {} });
  assert.strictEqual(set.checks.length, 0);
  assert.strictEqual(set.warnings.length, 1);
  assert.match(set.warnings[0], /names no DC/);
});
