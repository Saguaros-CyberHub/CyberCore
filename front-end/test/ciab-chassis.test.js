/**
 * ciab-chassis.test.js — the three stripped GOAD lab skeletons the AD compiler
 * repopulates per client profile.
 *
 * WHY CHASSIS EXIST AT ALL
 * Composing a GOAD topology from scratch is the riskiest thing the compiler
 * does. Inventory groups, the host-key / dict_key / ansible_host three-way join,
 * the playbook chain, the DNS wiring and the password invariants are each easy
 * to get subtly wrong, and a mistake does not surface until 30-95% into a ~90
 * minute bake. So we do not compose — we start from labs that are PROVEN to
 * deploy (ad/GOAD-Mini, ad/GOAD-Light, ad/GOAD at the pinned ref), strip every
 * scrap of payload out of them, and let the compiler put the payload back.
 *
 * WHY THE ASSERTIONS BELOW ARE MOSTLY ABOUT ABSENCE
 * A chassis that quietly keeps something is the failure mode. ad/GOAD-Light's
 * parent domain carries a twelve-edge ACL ladder; if a future re-sync copies it
 * in, every tier-M client gets the identical attack path, the generated answer
 * key describes it as if it were derived from their risk profile, and nothing
 * errors. Same for the ADCS templates, the SYSVOL bait, the MSSQL linked-server
 * hop and the staff roster. The "is it empty" tests are the guard against that,
 * and they are worth more than the "is it present" ones.
 *
 * WHY THESE FILES LIVE IN CYBERCORE AND NOT IN THE FORK
 * A chassis is COMPILE-TIME INPUT. The compiler reads it on the orchestrator and
 * emits ad/CIAB-<hash>/, which is pushed to the controller separately; the
 * controller never reads a chassis. Keeping them here means `node --test` can
 * read them — GOAD-main/ is gitignored and has zero tracked files, so anything
 * living there is invisible to CI (the exact trap ciab-goad-role-manifest.test.js
 * was written to close) — and a chassis edit does not force GOAD_REF churn.
 *
 * Run: node --test front-end/test/ciab-chassis.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CHASSIS_DIR = path.join(ROOT, 'modules/crucible/plugins/ciab/data/chassis');

const preflight = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-preflight.js'));
const roleManifest = require(path.join(
  ROOT, 'modules/crucible/plugins/ciab/utils/goad-role-manifest.js'));

/** The three tiers, and the upstream lab each one was carved out of. */
const TIERS = Object.freeze([
  { tier: 'S', derivedFrom: 'ad/GOAD-Mini',  hosts: 1, domains: 1, forests: 1 },
  { tier: 'M', derivedFrom: 'ad/GOAD-Light', hosts: 3, domains: 2, forests: 1 },
  { tier: 'L', derivedFrom: 'ad/GOAD',       hosts: 5, domains: 3, forests: 2 },
]);

/**
 * Every collection a chassis must carry as an EMPTY object.
 *
 * They are kept rather than deleted so the shape is legible: a composer author
 * reading the file sees the six slots it has to fill instead of inferring them
 * from an upstream lab that is no longer next to it.
 */
const EMPTY_DOMAIN_COLLECTIONS = Object.freeze([
  'users', 'groups', 'organisation_units', 'acls', 'multi_domain_groups_member', 'gmsa',
]);

/** Per-host payload. Arrays name roles to run; the *_vars dicts feed them. */
const EMPTY_HOST_ARRAYS = Object.freeze(['vulns', 'security', 'scripts']);
const EMPTY_HOST_DICTS = Object.freeze(['vulns_vars', 'security_vars', 'local_groups']);

// ── loading ─────────────────────────────────────────────────────────────────

function tierPath(tier, ...rest) { return path.join(CHASSIS_DIR, tier, ...rest); }

function readText(tier, ...rest) { return fs.readFileSync(tierPath(tier, ...rest), 'utf8'); }

/**
 * Load one chassis the way the compiler will.
 *
 * config.json is parsed with JSON.parse and NOT with goad-preflight's tolerant
 * parseGoadConfigJson(). Upstream files may legally carry a trailing comma
 * (ansible/data.yml loads them through PyYAML, which accepts one), but a chassis
 * is ours and there is no reason for it to be anything other than strict JSON —
 * so the strict parse is itself an assertion.
 */
function loadChassis(tier) {
  const chassis = JSON.parse(readText(tier, 'chassis.json'));
  const config = JSON.parse(readText(tier, 'data', 'config.json'));
  const inventoryText = readText(tier, 'data', 'inventory');
  const providerText = readText(tier, 'providers', 'proxmox', 'inventory');
  const playbooksPath = tierPath(tier, 'playbooks.yml');
  const playbooksText = fs.existsSync(playbooksPath) ? fs.readFileSync(playbooksPath, 'utf8') : null;
  return {
    tier,
    chassis,
    config,
    lab: config.lab,
    inventoryText,
    providerText,
    playbooksText,
    inventory: preflight.parseInventory(inventoryText),
    provider: preflight.parseInventory(providerText),
    // Tier S carries its own chain; M and L run upstream's `default:`, which is
    // what preflight assumes when handed null.
    playbooks: playbooksText ? preflight.chainForLab(playbooksText, `CHASSIS-${tier}`) : null,
  };
}

/** Everything preflightGoadLab() needs, from the files on disk. */
function preflightInput(c, config) {
  return {
    labName: `CHASSIS-${c.tier}`,
    config: config || c.config,
    inventory: c.inventoryText,
    providerInventory: c.providerText,
    playbooks: c.playbooks,
  };
}

function deepCopy(v) { return JSON.parse(JSON.stringify(v)); }

/** Walk every file in the chassis tree — used by the residue scan. */
function walkFiles(dir) {
  const out = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walkFiles(full));
    else out.push(full);
  }
  return out;
}

const LOADED = TIERS.map((t) => loadChassis(t.tier));

// ── 1. the artifacts exist, and are exactly the files a chassis may have ─────

test('the chassis tree is the three tiers and nothing else', () => {
  const dirs = fs.readdirSync(CHASSIS_DIR, { withFileTypes: true })
    .filter((e) => e.isDirectory()).map((e) => e.name).sort();
  assert.deepStrictEqual(dirs, ['L', 'M', 'S'],
    'a fourth directory under data/chassis/ is either an un-derived tier or a leftover');
});

test('every chassis parses as strict JSON', () => {
  // Strict on purpose — see loadChassis(). If this ever fails on a trailing
  // comma the fix is the comma, not a tolerant parser.
  for (const c of LOADED) {
    assert.ok(c.chassis && typeof c.chassis === 'object', `${c.tier}: chassis.json`);
    assert.ok(c.lab && typeof c.lab === 'object', `${c.tier}: config.json has no lab`);
    assert.ok(c.lab.hosts && c.lab.domains, `${c.tier}: config.json needs lab.hosts and lab.domains`);
  }
});

test('a chassis carries only the four proven skeleton files, never files/ or scripts/', () => {
  // The upstream labs ship files/ (the IIS webroot with the roslyn compiler in
  // it, ADCS template JSON, SYSVOL bait) and scripts/ (attack-path helpers
  // hardcoded to the source lab's account names). Both are payload. Neither can
  // come along, and enumerating the WHOLE tree rather than checking two
  // directory names catches the re-sync that copies the lab wholesale.
  for (const c of LOADED) {
    const rel = walkFiles(tierPath(c.tier))
      .map((f) => path.relative(tierPath(c.tier), f).split(path.sep).join('/')).sort();
    const expected = ['chassis.json', 'data/config.json', 'data/inventory',
      'providers/proxmox/inventory'];
    if (c.playbooksText !== null) expected.push('playbooks.yml');
    assert.deepStrictEqual(rel, expected.sort(),
      `${c.tier}: unexpected file in the chassis (files/, scripts/ and README.md are all payload)`);
  }
});

// ── 2. stripped-ness — the assertions that earn this file ───────────────────

test('every domain carries users, groups, OUs, ACLs, cross-domain members and gMSA as EMPTY objects', () => {
  // PRESENT and EMPTY, both halves. Present because the shape is the
  // documentation; empty because a single surviving entry is a client-visible
  // artefact that nothing downstream would flag.
  for (const c of LOADED) {
    for (const [name, domain] of Object.entries(c.lab.domains)) {
      for (const field of EMPTY_DOMAIN_COLLECTIONS) {
        const at = `${c.tier}: domains["${name}"].${field}`;
        assert.ok(Object.prototype.hasOwnProperty.call(domain, field), `${at} is missing`);
        assert.ok(domain[field] && typeof domain[field] === 'object' && !Array.isArray(domain[field]),
          `${at} must be an object`);
        assert.deepStrictEqual(domain[field], {},
          `${at} is not empty — a chassis carries no payload, and this one would be handed to every `
          + `tier-${c.tier} client`);
      }
    }
  }
});

test('no host plants a vuln, a security setting or a script', () => {
  // roles/vulns/* and roles/security/* are the attack surface. A chassis that
  // kept even disable_firewall would make every generated lab's exposure a
  // property of the chassis rather than of the client's risk profile.
  for (const c of LOADED) {
    for (const [key, host] of Object.entries(c.lab.hosts)) {
      for (const field of EMPTY_HOST_ARRAYS) {
        const at = `${c.tier}: hosts.${key}.${field}`;
        assert.ok(Array.isArray(host[field]), `${at} must be an array`);
        assert.deepStrictEqual(host[field], [], `${at} is not empty`);
      }
      for (const field of EMPTY_HOST_DICTS) {
        const at = `${c.tier}: hosts.${key}.${field}`;
        assert.ok(host[field] && typeof host[field] === 'object' && !Array.isArray(host[field]),
          `${at} must be an object`);
        assert.deepStrictEqual(host[field], {}, `${at} is not empty`);
      }
      // mssql is the other host-level payload block: an sa password, a service
      // account, sysadmin and EXECUTE AS mappings, and on tier L a linked-server
      // hop that carries the OTHER host's sa password in cleartext.
      assert.ok(!Object.prototype.hasOwnProperty.call(host, 'mssql'),
        `${c.tier}: hosts.${key}.mssql must be stripped — the composer emits it`);
    }
  }
});

test('no reskin or upstream-flavour residue survives anywhere in the tree', () => {
  // ad/GOAD-Light in the pinned fork is a themed rebrand of the original lab,
  // and its README still describes the ORIGINAL hosts while its scripts/ are
  // hardcoded to the rebrand's account names. Two different vocabularies, both
  // wrong for a client lab, and a re-sync can reintroduce either. Scanned across
  // every byte of every file rather than field-by-field, because the next leak
  // will be in a comment or a DN, not in a value anyone thought to check.
  const banned = ['cybersaguaros', 'TUC-', 'kingslanding', 'sevenkingdoms', 'croft', 'lannister'];
  for (const c of LOADED) {
    for (const file of walkFiles(tierPath(c.tier))) {
      const text = fs.readFileSync(file, 'utf8').toLowerCase();
      for (const needle of banned) {
        assert.ok(!text.includes(needle.toLowerCase()),
          `${path.relative(CHASSIS_DIR, file)} contains '${needle}'`);
      }
    }
  }
});

test('every placeholder is implausible enough that a leak is unmistakable', () => {
  // The point of the naming scheme. A chassis value that survives into a
  // generated lab must look WRONG at a glance rather than merely unfamiliar —
  // .invalid is the RFC 2606 reserved TLD and can never be a real client's
  // domain, and CHASSIS- prefixed hostnames read as a bug, not as a site code.
  for (const c of LOADED) {
    for (const name of Object.keys(c.lab.domains)) {
      assert.ok(name.endsWith('.invalid'), `${c.tier}: domain '${name}' must sit under .invalid`);
    }
    for (const [key, host] of Object.entries(c.lab.hosts)) {
      assert.match(host.hostname, /^CHASSIS-/, `${c.tier}: hosts.${key}.hostname`);
      // NetBIOS truncates silently over 15, and two hosts sharing a truncation
      // is a join failure nobody traces back to the chassis.
      assert.ok(host.hostname.length <= 15, `${c.tier}: hosts.${key}.hostname exceeds NetBIOS 15`);
      assert.match(host.local_admin_password, /^CHASSIS-PLACEHOLDER-/,
        `${c.tier}: hosts.${key}.local_admin_password must be an obvious placeholder, never a real secret`);
    }
    for (const [name, domain] of Object.entries(c.lab.domains)) {
      assert.match(domain.domain_password, /^CHASSIS-PLACEHOLDER-/,
        `${c.tier}: domains["${name}"].domain_password must be an obvious placeholder`);
      assert.ok(domain.netbios_name.length <= 15,
        `${c.tier}: domains["${name}"].netbios_name exceeds the NetBIOS 15-char ceiling`);
    }
    // domain_name is the ad/ FOLDER name, not a DNS name: ansible/data.yml
    // builds its vars_files path from it, so a chassis value that survives loads
    // a different lab's config.json — silently, if that lab happens to exist.
    assert.match(c.inventoryText, new RegExp(`^domain_name=CHASSIS-${c.tier}$`, 'm'),
      `${c.tier}: data/inventory must carry the placeholder domain_name`);
  }
});

// ── 3. the joins the chassis exists to preserve ─────────────────────────────

test('the host-key set agrees three ways: config.json, data/inventory, provider inventory', () => {
  // dict_key is the hinge of the whole scheme. Every play says
  // lab.hosts[dict_key]; dict_key is set per host in the PROVIDER inventory, the
  // config key lives in config.json and the Ansible host name lives in
  // data/inventory. Nothing upstream cross-checks the three, and a mismatch does
  // not error — it builds one machine with another's identity.
  for (const c of LOADED) {
    const fromConfig = Object.keys(c.lab.hosts).sort();
    const fromInventory = [...c.inventory.hostNames].sort();
    const fromProvider = [...c.provider.hostNames].sort();
    assert.deepStrictEqual(fromInventory, fromConfig, `${c.tier}: data/inventory vs config.json`);
    assert.deepStrictEqual(fromProvider, fromConfig, `${c.tier}: provider inventory vs config.json`);
    for (const host of fromProvider) {
      const vars = c.provider.hostVars[host] || {};
      assert.strictEqual(vars.dict_key, host,
        `${c.tier}: provider host ${host} must set dict_key=${host}`);
      assert.match(vars.ansible_host, /^\{\{ip_range\}\}\.\d{1,3}$/,
        `${c.tier}: ${host} ansible_host must stay the {{ip_range}}.N template — the octets are `
        + 'inherited from a lab that is proven to deploy and must not be renumbered');
    }
    // Two hosts on one octet is a lab that half-builds and reports green.
    const octets = fromProvider.map((h) => c.provider.hostVars[h].ansible_host);
    assert.strictEqual(new Set(octets).size, octets.length, `${c.tier}: duplicate ansible_host`);
  }
});

test('every domain names a DC that is a real host of type dc and is in [dc]', () => {
  // lab.domains[d].dc is read as lab.hosts[<dc>].hostname AND as
  // hostvars[<dc>].ansible_host, so an unresolvable value fails the play rather
  // than skipping it. The type check is separate and just as load-bearing:
  // pointing a domain at a member server promotes nothing.
  for (const c of LOADED) {
    const dcGroup = c.inventory.groups.dc || [];
    for (const [name, domain] of Object.entries(c.lab.domains)) {
      const dc = domain.dc;
      const at = `${c.tier}: domains["${name}"].dc = ${JSON.stringify(dc)}`;
      assert.ok(Object.prototype.hasOwnProperty.call(c.lab.hosts, dc), `${at} is not a hosts key`);
      assert.strictEqual(c.lab.hosts[dc].type, 'dc', `${at} names a host whose type is not 'dc'`);
      assert.ok(dcGroup.includes(dc), `${at} is not listed in data/inventory [dc]`);
    }
    // Each host's domain must be declared, or the very first play dies.
    for (const [key, host] of Object.entries(c.lab.hosts)) {
      assert.ok(Object.prototype.hasOwnProperty.call(c.lab.domains, host.domain),
        `${c.tier}: hosts.${key} claims undeclared domain "${host.domain}"`);
    }
  }
});

// ── 4. tier topology is what each tier claims ──────────────────────────────

test('S is one domain in one forest, with no child and no trust', () => {
  const c = LOADED.find((x) => x.tier === 'S');
  assert.strictEqual(Object.keys(c.lab.domains).length, 1);
  assert.strictEqual(Object.keys(c.lab.hosts).length, 1);
  assert.deepStrictEqual(c.inventory.groups.child_dc, []);
  assert.deepStrictEqual(c.inventory.groups.trust, []);
  const [name, domain] = Object.entries(c.lab.domains)[0];
  assert.strictEqual(domain.trust, '', `S: ${name} must not trust anything`);
  assert.ok((c.inventory.groups.parent_dc || []).includes(domain.dc),
    'S: the single DC must still be in [parent_dc] — ad-parent_domain.yml is what promotes it');
});

test('M is a parent and a child domain in one forest, and the child FQDN proves the parenthood', () => {
  // ad-child_domain.yml:20 derives the parent by DROPPING THE FIRST LABEL of the
  // child FQDN — `{{'.'.join(domain.split('.')[1:])}}` — with no validation and
  // no default, then immediately reads lab.domains[parent].domain_password. So
  // "the child is a child" is not a flag anywhere; it is a string relationship
  // between two keys, and a composer that renames one and not the other kills
  // the fourth playbook in the chain.
  const c = LOADED.find((x) => x.tier === 'M');
  const names = Object.keys(c.lab.domains);
  assert.strictEqual(names.length, 2);
  assert.strictEqual(c.inventory.groups.child_dc.length, 1, 'M: exactly one child DC');
  const childDc = c.inventory.groups.child_dc[0];
  const childDomain = c.lab.hosts[childDc].domain;
  const parentDomain = childDomain.split('.').slice(1).join('.');
  assert.ok(names.includes(parentDomain),
    `M: parent "${parentDomain}" derived from child "${childDomain}" is not a declared domain`);
  assert.ok((c.inventory.groups.parent_dc || []).includes(c.lab.domains[parentDomain].dc),
    'M: the parent domain\'s DC must be in [parent_dc]');
  // One forest, so no external trust anywhere.
  for (const [name, d] of Object.entries(c.lab.domains)) {
    assert.strictEqual(d.trust, '', `M: ${name} must not declare an external trust`);
  }
});

test('L is three domains across two forests with a non-empty bidirectional trust', () => {
  // Two forest roots is the whole reason this tier exists, and the trust is what
  // makes the second forest reachable. ad-trusts.yml:16 sets remote_forest from
  // .trust with no default and line 18 immediately does
  // lab.domains[remote_forest].dc, so a half-declared trust dies at play start.
  const c = LOADED.find((x) => x.tier === 'L');
  const names = Object.keys(c.lab.domains);
  assert.strictEqual(names.length, 3);

  const children = c.inventory.groups.child_dc.map((h) => c.lab.hosts[h].domain);
  assert.strictEqual(children.length, 1, 'L: one child domain');
  const roots = names.filter((n) => !children.includes(n));
  assert.strictEqual(roots.length, 2, 'L: two forest roots');

  // The roots must NOT share a suffix, or the second forest reads as a child of
  // the first the moment anything derives a parent by dropping a label.
  assert.ok(!roots[0].endsWith(`.${roots[1]}`) && !roots[1].endsWith(`.${roots[0]}`),
    `L: forest roots ${roots.join(' and ')} are in a parent/child relationship, not two forests`);

  for (const root of roots) {
    const other = roots.find((r) => r !== root);
    assert.strictEqual(c.lab.domains[root].trust, other,
      `L: ${root} must trust ${other} — the trust is declared on BOTH sides`);
    assert.ok(c.inventory.groups.trust.includes(c.lab.domains[root].dc),
      `L: ${root}'s DC must be in [trust], which is the group ad-trusts.yml runs against`);
  }
  assert.strictEqual(c.lab.domains[children[0]].trust, '',
    'L: the child domain inherits the forest trust and must not declare one of its own');
});

// ── 5. provenance ───────────────────────────────────────────────────────────

test('chassis.json describes the chassis next to it', () => {
  // Provenance that disagrees with the artifact is worse than none: the next
  // re-sync trusts it and diffs against the wrong upstream paths.
  for (const spec of TIERS) {
    const c = LOADED.find((x) => x.tier === spec.tier);
    const p = c.chassis;
    assert.strictEqual(p.tier, spec.tier);
    assert.strictEqual(p.derived_from, spec.derivedFrom);
    assert.strictEqual(p.goad_repo, 'https://github.com/joshmp087/GOAD.git');
    assert.strictEqual(p.hosts, Object.keys(c.lab.hosts).length,
      `${spec.tier}: chassis.json hosts count disagrees with config.json`);
    assert.strictEqual(p.domains, Object.keys(c.lab.domains).length,
      `${spec.tier}: chassis.json domains count disagrees with config.json`);
    assert.strictEqual(p.topology.forests, spec.forests);
    assert.deepStrictEqual(p.topology.domains.map((d) => d.name).sort(),
      Object.keys(c.lab.domains).sort(), `${spec.tier}: topology names a different domain set`);
    assert.deepStrictEqual(p.topology.dcs.slice().sort(), (c.inventory.groups.dc || []).slice().sort());
    assert.deepStrictEqual(p.topology.servers.slice().sort(),
      (c.inventory.groups.server || []).slice().sort());
    // The stripped list is what makes a re-sync mechanical rather than
    // archaeological, so it has to be real prose, not a token.
    assert.ok(Array.isArray(p.stripped) && p.stripped.length >= 8,
      `${spec.tier}: stripped[] must enumerate what was removed`);
    for (const item of p.stripped) {
      assert.ok(typeof item === 'string' && item.length > 20, `${spec.tier}: thin stripped[] entry`);
    }
    // The note is where "this thing does not deploy, on purpose" is written
    // down. Without it the next reader files the pre-flight failure as a bug.
    assert.match(p.note, /NOT DEPLOYABLE/);
    assert.match(p.note, /ad-data\.yml/);
  }
});

test('every chassis is pinned to the same GOAD commit as the vendored role library', () => {
  // The drift detector. The compiler picks roles out of the manifest and drops
  // them into a chassis-derived lab; if the two were vendored from different
  // refs it emits a role the baked controller does not have, and GOAD roles fail
  // QUIETLY — a green deploy with nothing planted.
  const manifestRef = roleManifest.loadManifest().goad_ref;
  assert.match(manifestRef, /^[0-9a-f]{40}$/);
  for (const c of LOADED) {
    assert.strictEqual(c.chassis.goad_ref, manifestRef,
      `${c.tier}: chassis.json goad_ref and goad-role-manifest.json goad_ref must move together`);
  }
});

test('the chassis tree is exempted from the blanket data/ ignore rule', () => {
  // .gitignore line 4 is `**/data/*`, so a new file under any data/ directory is
  // invisible to git by default — the trap that nearly lost the role manifest.
  // BOTH lines are required and for different reasons: the first un-excludes the
  // chassis DIRECTORY (git never descends into an excluded directory, so the
  // /** negation alone would re-include nothing), the second un-excludes the
  // files under it, including the nested data/ directories inside each tier.
  const gitignore = fs.readFileSync(path.join(ROOT, '..', '.gitignore'), 'utf8');
  const lines = gitignore.split(/\r?\n/).map((l) => l.trim());
  assert.ok(lines.includes('!**/data/chassis/'),
    '.gitignore must un-ignore the chassis directory itself');
  assert.ok(lines.includes('!**/data/chassis/**'),
    '.gitignore must un-ignore the files beneath it; without this the tree is untracked '
    + 'everywhere but the authoring machine, and shows up in no diff');
});

// ── 6. the playbook chain ───────────────────────────────────────────────────

test('tier S carries its own chain because ad/GOAD-Mini has one; M and L declare the default', () => {
  // goad/provisioner/ansible/ansible.py:41-60 resolves the chain by looking the
  // LAB DIRECTORY NAME up in the fork's single top-level playbooks.yml and
  // falling back to `default:`. The compiler emits ad/CIAB-<hash>/, which
  // matches no key — so tier S would silently inherit `default:`, and that chain
  // runs ad-child_domain.yml against an empty [child_dc] and ad-trusts.yml
  // against an empty [trust]. Carrying Mini's chain here is what lets the
  // composer merge it back under the emitted name.
  const s = LOADED.find((x) => x.tier === 'S');
  assert.ok(s.playbooksText, 'S must ship playbooks.yml');
  assert.deepStrictEqual(s.playbooks, [
    'build.yml', 'ad-servers.yml', 'ad-parent_domain.yml', 'ad-data.yml',
    'ad-relations.yml', 'adcs.yml', 'ad-acl.yml', 'security.yml', 'vulnerabilities.yml',
  ]);
  // The distinguishing absences, asserted by name so a future edit that "tidies"
  // the chain back toward default has to argue with this line.
  for (const absent of ['ad-child_domain.yml', 'ad-trusts.yml', 'servers.yml', 'laps.yml',
    'ad-members.yml', 'ad-gmsa.yml']) {
    assert.ok(!s.playbooks.includes(absent), `S: ${absent} has no groups to run against`);
  }
  assert.strictEqual(s.chassis.playbooks.file, 'playbooks.yml');
  assert.strictEqual(s.chassis.playbooks.upstream_key, 'GOAD-Mini');

  for (const tier of ['M', 'L']) {
    const c = LOADED.find((x) => x.tier === tier);
    assert.strictEqual(c.playbooksText, null,
      `${tier}: its source lab has no entry in playbooks.yml, so there is no chain to carry`);
    assert.strictEqual(c.chassis.playbooks.file, null);
    assert.strictEqual(c.chassis.playbooks.upstream_key, 'default');
  }
});

// ── 7. CROSS-CHECK against the pre-flight ───────────────────────────────────
//
// Two directions, and both are needed. Rejecting a chassis proves it is not a
// lab; accepting the same chassis once the payload is added proves the SKELETON
// is sound and that the rejection was about the payload and nothing else.

test('a chassis is rejected by the pre-flight — it is an input, not a lab', () => {
  // WHY THE TWO KEYS ARE DELETED RATHER THAN LEFT AS {}
  // goad-preflight's filled() answers true for ANY object, `{}` included, so
  // `users: {}` currently reads to it as "present". Ansible does not agree:
  // roles/ad indexes ad_groups.global with no default, so an empty groups dict
  // is exactly as fatal as an absent one — it just fails ~60 minutes into the
  // bake instead of before the first VM boots. Deleting the keys here is the
  // faithful reading of what the chassis means, and it keeps this test honest
  // in both worlds: it passes today, and it keeps passing the day filled()
  // learns to treat an empty object as unfilled.
  for (const c of LOADED) {
    const asMeant = deepCopy(c.config);
    for (const domain of Object.values(asMeant.lab.domains)) {
      delete domain.users;
      delete domain.groups;
    }
    const result = preflight.preflightGoadLab(preflightInput(c, asMeant));
    assert.strictEqual(result.ok, false, `${c.tier}: a payload-free chassis must not pre-flight clean`);
    const missing = result.errors.filter((e) => e.code === preflight.CODE.DOMAIN_KEY_MISSING);
    assert.ok(missing.some((e) => /\busers\b/.test(e.message)), `${c.tier}: users not reported`);
    assert.ok(missing.some((e) => /\bgroups\b/.test(e.message)), `${c.tier}: groups not reported`);
    // And the throwing boundary agrees, since that is what a route calls.
    assert.throws(() => preflight.assertGoadLabPreflight(preflightInput(c, asMeant)),
      (err) => err.status === 422 && Array.isArray(err.findings));
  }
  // The contract this test leans on, asserted rather than assumed: if a future
  // edit drops users/groups from REQUIRED_DOMAIN_KEYS, the rejection above stops
  // meaning anything and this line says so.
  assert.ok(preflight.REQUIRED_DOMAIN_KEYS.includes('users'));
  assert.ok(preflight.REQUIRED_DOMAIN_KEYS.includes('groups'));
});

test('nothing but the deliberately stripped payload can be wrong with a chassis', () => {
  // Fed AS IT SITS ON DISK, a chassis may only ever be faulted for the things
  // the composer is supposed to supply. Any OTHER code here — a broken three-way
  // join, an undeclared domain, a missing inventory var, an unresolvable DC — is
  // a defect in the skeleton itself, which is the one thing a chassis is
  // supposed to guarantee is right.
  const allowed = new Set([
    preflight.CODE.DOMAIN_KEY_MISSING,        // users / groups, once filled() sees {}
    preflight.CODE.MSSQL_SA_PASSWORD_MISSING, // hosts[*].mssql, stripped on M and L
  ]);
  for (const c of LOADED) {
    const result = preflight.preflightGoadLab(preflightInput(c));
    const unexpected = result.errors.filter((e) => !allowed.has(e.code));
    assert.deepStrictEqual(unexpected, [],
      `${c.tier}: the chassis skeleton itself does not pre-flight`);
    assert.deepStrictEqual(result.warnings, [], `${c.tier}: unexpected pre-flight warning`);
  }
});

test('the same chassis pre-flights clean the moment the payload is filled in', () => {
  // The positive control, and the assertion that makes the two above
  // non-vacuous: every other invariant — the three-way join, DC resolution, the
  // derived child/parent link, the bidirectional trust, ca_server for the custom
  // ADCS template, the inventory vars — already holds. The composer's whole job
  // is the payload.
  for (const c of LOADED) {
    const full = deepCopy(c.config);
    for (const [name, domain] of Object.entries(full.lab.domains)) {
      domain.users = {
        'test.user': {
          firstname: 'Test', surname: 'User', password: 'CHASSIS-TEST-PW',
          groups: [], path: `CN=Users,${dnFor(name)}`,
        },
      };
      // The three scopes roles/ad indexes by name; see EMPTY_DOMAIN_COLLECTIONS.
      domain.groups = { universal: {}, global: {}, domainlocal: {} };
    }
    for (const host of (c.inventory.groups.mssql || [])) {
      full.lab.hosts[host].mssql = { sa_password: 'CHASSIS-TEST-SA-PW' };
    }
    const result = preflight.preflightGoadLab(preflightInput(c, full));
    assert.deepStrictEqual(result.findings, [],
      `${c.tier}: a filled chassis must pre-flight clean`);
  }
});

test('the pre-flight cross-check is not vacuous: break the join and it fails', () => {
  // A negative control for the test above. If preflightGoadLab silently returned
  // ok for anything we handed it, every assertion in this section would pass on
  // a chassis that was garbage.
  const c = LOADED[0];
  const broken = c.providerText.replace(/dict_key=dc01/, 'dict_key=typo01');
  const result = preflight.preflightGoadLab({ ...preflightInput(c), providerInventory: broken });
  assert.strictEqual(result.ok, false);
  assert.ok(result.errors.some((e) => e.code === preflight.CODE.PROVIDER_DICT_KEY_MISMATCH));
});

/** `chassis.invalid` -> `DC=chassis,DC=invalid`. Local to the filled-in fixture. */
function dnFor(fqdn) {
  return fqdn.split('.').map((label) => `DC=${label}`).join(',');
}
