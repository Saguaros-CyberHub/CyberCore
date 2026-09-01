/**
 * ciab-goad-lab-registration.test.js — an unregistered GOAD lab is a HARD ERROR.
 *
 * WHY THIS FILE EXISTS
 * GOAD_LABS is a static object literal with no registration path, and
 * prepareGoadMacs matched a lowercased spec name against it with a bare
 * `if (!labVm) continue;`. For a generated or misnamed lab, an unmatched host
 * therefore got:
 *
 *   no deterministic MAC        → nothing to write a reservation against
 *   no DHCP reservation         → a random pool lease
 *   resolveVmSegments rung 4    → the EXTERNAL segment, not the internal one
 *   skipped by the prebaked heal → never DNS-repaired, never domain-joined
 *   a WinRM wait on the lab octet → polling an address nobody owns
 *
 * Not one of those throws. The lane finishes, `cybercore_lane` says active, and
 * an instructor hands it to a cohort. That is the worst failure mode in the
 * system: a lane that fails loudly gets retried, a lane that lies gets graded.
 *
 * So the property under test is not "the deploy works" — it is "the deploy
 * REFUSES". Every assertion below is about something being thrown, being named
 * in the message, or being resolved from exactly one place.
 *
 * THE TWO HALVES
 *   1. spec.goad.lab lets a GENERATED engagement describe its own forest, so
 *      "this lab is not in the table" stops being a reason to edit the table.
 *   2. With that escape hatch in place, an unmatched host has no innocent
 *      explanation left, and prepareGoadMacs throws.
 *
 * The source-text guard at the end (§5) is the blunt one, and it is the right
 * instrument for exactly one property: that no SIXTH read site of GOAD_LABS
 * appears. Five inlined copies of the lookup is how the sites drifted apart in
 * the first place, and no runtime test can catch a new one being added.
 *
 * Run: node --test front-end/test/ciab-goad-lab-registration.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');
const GOAD_REL = 'src/utils/goad-deploy.js';

const goad = require(path.join(UTILS, 'goad-deploy.js'));
const { GOAD_LABS, DEFAULT_LAB, prepareGoadMacs, resolveGoadLab, isGoadManagedVm } = goad;

/** A GOAD-Light spec whose roster is correct, so each test can spoil one thing. */
function lightSpec(extraVms = [], goadExtra = {}) {
  return {
    goad: Object.assign({ enabled: true, version: 'GOAD-Light' }, goadExtra),
    vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }, ...extraVms],
  };
}

const VXLAN = 10000;
const BASE = '10.39.16';

/**
 * Run `fn` and hand back the Error it threw.
 *
 * assert.throws returns undefined, so it cannot be used and then interrogated —
 * and half of what this file asserts is about the MESSAGE, because a refusal
 * nobody can act on is only marginally better than the silence it replaced.
 */
function caught(fn) {
  try { fn(); } catch (err) { return err; }
  assert.fail('expected a throw, got none');
}

// ── 1. the misdeploy is now a refusal ───────────────────────────────────────

test('a spec VM that is in no lab definition throws, and the message names it', () => {
  // The whole point. FILE-01 used to be skipped in silence.
  assert.throws(
    () => prepareGoadMacs(lightSpec([{ name: 'FILE-01' }]), VXLAN, BASE),
    (err) => /FILE-01/.test(err.message) && /roster mismatch/i.test(err.message),
    'an unmatched host must name itself in the error, not just fail');
});

test('every offending host is named, not just the first', () => {
  // A partial message sends someone round the loop once per stray: fix one,
  // redeploy, wait, fail again. Naming all of them is the difference between
  // one edit and four deploys.
  const err = caught(() => prepareGoadMacs(lightSpec([{ name: 'FILE-01' }, { name: 'PRINT-02' }]), VXLAN, BASE));
  assert.ok(/FILE-01/.test(err.message) && /PRINT-02/.test(err.message), err.message);
});

test('the error carries the remedy, including the spec-supplied lab escape hatch', () => {
  // This message is what a 3am reader has. If it only says "mismatch" they will
  // either rename the box at random or add an entry to GOAD_LABS for a one-off
  // engagement — the second of which is the reason spec.goad.lab exists.
  const err = caught(() => prepareGoadMacs(lightSpec([{ name: 'FILE-01' }]), VXLAN, BASE));
  assert.ok(/rename/i.test(err.message), 'remedy 1: rename to a lab host');
  assert.ok(/"role": "dmz"/.test(err.message) && /"role": "attacker"/.test(err.message),
    'remedy 2: mark it as living outside the forest');
  assert.ok(/goad\.lab = \{ forestRoot, vms:/.test(err.message),
    'remedy 4: describe a generated lab on the spec, rather than editing GOAD_LABS');
  assert.ok(/DC01, DC02, SRV02/.test(err.message),
    'the message must print the roster it was reconciled against, or "rename it" is unactionable');
});

test('a lab host MISSING from spec.vms throws too, and names the absent host', () => {
  // The mirror failure, and the quieter one: nothing clones SRV02, so
  // `macs['SRV02']` is undefined, `.filter(Boolean)` drops it from the WinRM
  // wait without a word, and the playbook provisions a forest with a hole in it.
  const spec = { goad: { enabled: true, version: 'GOAD-Light' }, vms: [{ name: 'DC01' }, { name: 'DC02' }] };
  const err = caught(() => prepareGoadMacs(spec, VXLAN, BASE));
  assert.ok(/SRV02/.test(err.message) && /not in spec\.vms/.test(err.message), err.message);
});

test('a name that differs only in case still matches — matching is lowercased, not trimmed', () => {
  // prepareGoadMacs keys on name.toLowerCase() with no trim, and the engagement
  // paper's mirror reproduces that exactly (ciab-engagement-model B0-107). The
  // reconciliation has to use the same rule or the two disagree about which
  // machines exist.
  const macs = prepareGoadMacs(
    { goad: { enabled: true }, vms: [{ name: 'dc01' }, { name: 'Dc02' }, { name: 'srv02' }] },
    VXLAN, BASE);
  assert.deepStrictEqual(Object.keys(macs).sort(), ['Dc02', 'dc01', 'srv02'].sort());
  // ...and the untrimmed rule is load-bearing: ' DC01' is a different machine.
  assert.throws(
    () => prepareGoadMacs({ goad: { enabled: true }, vms: [{ name: ' DC01' }, { name: 'DC02' }, { name: 'SRV02' }] },
      VXLAN, BASE),
    /DC01/);
});

// ── 2. what is deliberately NOT a lab host ──────────────────────────────────

test('the Kali and the v3 pivot are exempt — every GOAD preset ships them', () => {
  // topology-seed.fromGoadLab appends web01 (role 'dmz') and Kali (role
  // 'attacker') to the lab's own host list. If those counted as strays, the
  // refusal would fire on the DEFAULT product of the GOAD preset and nobody
  // could deploy anything.
  const spec = lightSpec([
    { name: 'web01', role: 'dmz', type: 'qemu' },
    { name: 'Kali', role: 'attacker', type: 'qemu' },
  ]);
  const macs = prepareGoadMacs(spec, VXLAN, BASE);
  assert.deepStrictEqual(Object.keys(macs), ['DC01', 'DC02', 'SRV02'],
    'exempt machines must be absent from the MAC map; that absence is how the '
    + 'deployer learns they are not lab hosts');
});

test('an explicitly placed machine and a container are exempt as well', () => {
  // nics[] is resolveVmSegments rung 1, which wins outright over lab membership
  // — the GOAD layer must not second-guess an author who placed a box by hand.
  // An LXC takes net1 with the template owning net0, so it can never be a lab
  // host at all.
  const spec = lightSpec([
    { name: 'JUMP-01', nics: [{ segment: 'ext' }] },
    { name: 'vuln-app', type: 'lxc' },
  ]);
  assert.deepStrictEqual(Object.keys(prepareGoadMacs(spec, VXLAN, BASE)), ['DC01', 'DC02', 'SRV02']);
});

test('isGoadManagedVm draws exactly that line', () => {
  assert.strictEqual(isGoadManagedVm({ name: 'DC01' }), true);
  assert.strictEqual(isGoadManagedVm({ name: 'SRV99', role: 'server' }), true,
    'an ordinary role is managed — that is what makes a typo fatal');
  assert.strictEqual(isGoadManagedVm({ name: 'Kali', role: 'attacker' }), false);
  assert.strictEqual(isGoadManagedVm({ name: 'web01', role: 'dmz' }), false);
  assert.strictEqual(isGoadManagedVm({ name: 'X', type: 'lxc' }), false);
  assert.strictEqual(isGoadManagedVm({ name: 'X', nics: [{ segment: 'int' }] }), false);
  // A nics[] entry with no segment places nothing, so it is not an opt-out.
  assert.strictEqual(isGoadManagedVm({ name: 'X', nics: [{}] }), true);
  assert.strictEqual(isGoadManagedVm({}), false);
  assert.strictEqual(isGoadManagedVm(null), false);
});

test('a container that STEALS a lab host name is still caught', () => {
  // The exemption is per-machine, not per-name: marking DC02 as an LXC removes
  // it from the managed set, which leaves the lab's DC02 unclaimed. A blanket
  // "skip containers" would have made that the silent misdeploy all over again.
  const spec = { goad: { enabled: true }, vms: [{ name: 'DC01' }, { name: 'DC02', type: 'lxc' }, { name: 'SRV02' }] };
  assert.throws(() => prepareGoadMacs(spec, VXLAN, BASE), /DC02/);
});

test('nothing at all happens unless goad.enabled', () => {
  // The refusal must not leak into ordinary challenge specs, which name their
  // machines whatever they like.
  assert.deepStrictEqual(prepareGoadMacs({ goad: { enabled: false }, vms: [{ name: 'anything' }] }, VXLAN, BASE), {});
  assert.deepStrictEqual(prepareGoadMacs({ vms: [{ name: 'anything' }] }, VXLAN, BASE), {});
  assert.deepStrictEqual(prepareGoadMacs({ goad: { enabled: true } }, VXLAN, BASE), {},
    'a spec with no vms array returns {} before the roster is ever consulted');
  assert.deepStrictEqual(prepareGoadMacs(null, VXLAN, BASE), {});
});

// ── 3. a spec-supplied lab definition ───────────────────────────────────────

const GENERATED_LAB = {
  forestRoot: 'acme-internal.local',
  vms: [
    { name: 'ACME-DC', role: 'dc', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 30, nic_model: 'e1000' },
    { name: 'ACME-FS', role: 'member', os: 'Windows Server 2019', template_vmid: 1004, ipOctet: 31 },
  ],
};

test('a spec-supplied goad.lab is used in preference to GOAD_LABS', () => {
  // The precedence that makes the refusal above fair: a generated engagement
  // describes its own forest instead of needing a commit to GOAD_LABS. Note the
  // version still says GOAD-Light — the spec definition wins over the NAMED lab,
  // not merely over the default.
  const spec = {
    goad: { enabled: true, version: 'GOAD-Light', lab: GENERATED_LAB },
    vms: [{ name: 'ACME-DC' }, { name: 'ACME-FS' }],
  };
  const macs = prepareGoadMacs(spec, VXLAN, BASE);
  assert.deepStrictEqual(Object.keys(macs), ['ACME-DC', 'ACME-FS']);
  assert.strictEqual(macs['ACME-DC'].static_ip, `${BASE}.30`);
  assert.strictEqual(macs['ACME-DC'].mac, goad.macForOctet(30, VXLAN),
    'the MAC must come from the SPEC lab octet, or the reservation names an address the NIC never claims');
  assert.strictEqual(macs['ACME-FS'].role, 'member');
  assert.strictEqual(macs['ACME-FS'].nic_model, 'e1000',
    'a lab entry that omits nic_model still gets e1000 — a Windows guest on virtio never DHCPs');
  assert.strictEqual(macs['ACME-FS'].memory, goad.ROLE_RESOURCES.member.memory,
    'role defaults apply to a spec-supplied lab exactly as to a built-in one');
});

test('GOAD-Light\'s own hosts become strays once the spec declares a different lab', () => {
  // The proof that the spec definition REPLACED the table rather than extending
  // it. A resolver that merged the two would leave DC01 addressable and the
  // whole precedence meaningless.
  const spec = { goad: { enabled: true, lab: GENERATED_LAB }, vms: [{ name: 'DC01' }, { name: 'DC02' }, { name: 'SRV02' }] };
  const err = caught(() => prepareGoadMacs(spec, VXLAN, BASE));
  assert.ok(/DC01/.test(err.message) && /spec\.goad\.lab/.test(err.message),
    'the message must say WHICH definition it reconciled against: ' + err.message);
});

test('resolveGoadLab implements exactly one precedence, and reports which arm won', () => {
  const fromSpec = resolveGoadLab({ goad: { enabled: true, version: 'NHA', lab: GENERATED_LAB } });
  assert.strictEqual(fromSpec.labDef, GENERATED_LAB);
  assert.strictEqual(fromSpec.fromSpec, true);
  // labName stays the VERSION even when the definition came from the spec:
  // run.sh takes the upstream ad/<name>/ playbook chain by name, and a spec
  // definition governs addressing, not which playbook runs.
  assert.strictEqual(fromSpec.labName, 'NHA');

  const byName = resolveGoadLab({ goad: { enabled: true, version: 'SCCM' } });
  assert.strictEqual(byName.labDef, GOAD_LABS.SCCM);
  assert.strictEqual(byName.fromSpec, false);

  const defaulted = resolveGoadLab({ goad: { enabled: true } });
  assert.strictEqual(defaulted.labDef, GOAD_LABS[DEFAULT_LAB]);
  assert.strictEqual(defaulted.labName, DEFAULT_LAB);

  // An unknown version still FALLS BACK rather than throwing. That is pinned
  // behaviour (ciab-engagement-model B0-107 mirrors it), and it is safe now
  // only because the roster check downstream refuses the mismatch it creates.
  assert.strictEqual(resolveGoadLab({ goad: { enabled: true, version: 'nonesuch' } }).labDef,
    GOAD_LABS[DEFAULT_LAB]);
  // And it is total, for the call sites that hold no spec at all.
  assert.strictEqual(resolveGoadLab(null).labDef, GOAD_LABS[DEFAULT_LAB]);
  assert.strictEqual(resolveGoadLab({}).labDef, GOAD_LABS[DEFAULT_LAB]);
});

test('a fallen-back unknown version is not silently deployable', () => {
  // The pairing that makes the fallback survivable: version 'nonesuch' resolves
  // to GOAD-Light, and a spec written for 'nonesuch' therefore fails the roster
  // check instead of deploying as a GOAD-Light lane wearing another lab's name.
  const spec = { goad: { enabled: true, version: 'nonesuch' }, vms: [{ name: 'NOPE-01' }] };
  assert.throws(() => prepareGoadMacs(spec, VXLAN, BASE), /NOPE-01/);
});

// ── 4. the spec-supplied definition is validated, because nothing else can ──

test('a malformed spec lab is rejected at the shape, with the shape in the message', () => {
  const bad = (lab) => () => resolveGoadLab({ goad: { enabled: true, lab } });
  assert.throws(bad('GOAD-Light'), /must be an object/, 'a string is a version, not a definition');
  assert.throws(bad([{ name: 'DC01' }]), /must be an object/);
  assert.throws(bad({ vms: [{ name: 'A', role: 'dc', ipOctet: 10 }] }), /forestRoot/);
  assert.throws(bad({ forestRoot: 'x.local' }), /vms\[\]/);
  assert.throws(bad({ forestRoot: 'x.local', vms: [] }), /vms\[\]/,
    'an empty roster would make every machine in spec.vms a stray');
});

test('a lab VM missing the fields the deploy actually reads is rejected', () => {
  const bad = (vms) => () => resolveGoadLab({ goad: { enabled: true, lab: { forestRoot: 'x.local', vms } } });
  // ipOctet is both the host's last octet and the last byte of its MAC; absent,
  // the reservation reads "<base>.undefined" and dnsmasq refuses to start, which
  // takes DHCP down for the WHOLE lane rather than for one machine.
  assert.throws(bad([{ name: 'A', role: 'dc' }]), /ipOctet/);
  assert.throws(bad([{ name: 'A', role: 'dc', ipOctet: '10' }]), /ipOctet/, 'a string octet is not an octet');
  assert.throws(bad([{ name: 'A', role: 'dc', ipOctet: 300 }]), /ipOctet/);
  assert.throws(bad([{ name: '', role: 'dc', ipOctet: 10 }]), /name/);
  // Role decides the WinRM filter: an unrecognised role on a Linux box means it
  // is polled on 5985 for the full 30-minute timeout before the deploy fails.
  assert.throws(bad([{ name: 'A', role: 'linuxbox', ipOctet: 10 }]), /role/);
  assert.throws(bad([{ name: 'A', ipOctet: 10 }]), /role/);
});

test('a spec lab may not collide with itself or with the lane infrastructure', () => {
  const bad = (vms) => () => resolveGoadLab({ goad: { enabled: true, lab: { forestRoot: 'x.local', vms } } });
  const dc = (name, ipOctet) => ({ name, role: 'dc', ipOctet });
  assert.throws(bad([dc('A', 10), dc('a', 11)]), /repeats the name/,
    'matching is case-insensitive, so the second entry would shadow the first');
  assert.throws(bad([dc('A', 10), dc('B', 10)]), /reuses ipOctet/,
    'two dhcp-host lines on one address stop dnsmasq starting at all');
  // The gateway is .1, which the 2..254 range check catches first — .1 is the
  // gateway on every lane, so there the range and the infra list are two
  // spellings of one rule. The controller (.5) sits INSIDE the range, and is
  // the case the infra list exists for.
  assert.throws(bad([dc('A', goad.INFRA_IP_OCTETS.gateway)]), /ipOctet/);
  assert.throws(bad([dc('A', goad.INFRA_IP_OCTETS.controller)]), /controller/);
  // Kali is NOT a collision: it lives on the external segment while lab hosts
  // live on the internal one, so on a v3 lane .50 is genuinely free.
  assert.doesNotThrow(bad([dc('A', goad.INFRA_IP_OCTETS.Kali)]));
});

// ── 5. the built-in labs are untouched ──────────────────────────────────────

test('every built-in lab still resolves to its own definition, unchanged', () => {
  // Not a hardcoded count: a lab ADDED to the table should be covered by this
  // test automatically rather than needing it edited. The floor guards against
  // the table being emptied or the export being renamed to something falsy.
  const names = Object.keys(GOAD_LABS);
  assert.ok(names.length >= 6, `GOAD_LABS declares only ${names.length} labs; the table lost entries`);
  for (const name of names) {
    const { labDef, labName, fromSpec } = resolveGoadLab({ goad: { enabled: true, version: name } });
    assert.strictEqual(labName, name);
    assert.strictEqual(fromSpec, false);
    assert.strictEqual(labDef, GOAD_LABS[name], `${name} must resolve to its own entry`);
    assert.ok(Array.isArray(labDef.vms) && labDef.vms.length > 0, `${name} declares no hosts`);
    assert.ok(typeof labDef.forestRoot === 'string' && labDef.forestRoot.includes('.'),
      `${name}.forestRoot is not a domain name`);
  }
});

test('each built-in lab, deployed as its own roster, addresses every host', () => {
  // The end-to-end shape of the thing being defended: give a lab exactly the
  // machines it declares and every one comes back with a MAC and an IP. A lab
  // whose entry drifted (a missing ipOctet, a renamed host) fails here rather
  // than at 2am on a cohort's lane.
  for (const [name, lab] of Object.entries(GOAD_LABS)) {
    const spec = { goad: { enabled: true, version: name }, vms: lab.vms.map(v => ({ name: v.name })) };
    const macs = prepareGoadMacs(spec, VXLAN, BASE);
    assert.deepStrictEqual(Object.keys(macs), lab.vms.map(v => v.name), `${name} roster`);
    for (const v of lab.vms) {
      assert.strictEqual(macs[v.name].static_ip, `${BASE}.${v.ipOctet}`, `${name}/${v.name} ip`);
      assert.strictEqual(macs[v.name].mac, goad.macForOctet(v.ipOctet, VXLAN), `${name}/${v.name} mac`);
      assert.strictEqual(macs[v.name].role, v.role, `${name}/${v.name} role`);
    }
  }
});

test("NHA's forest root is ninja.hack", () => {
  // It read 'north.sevenkingdoms.local' — a Seven Kingdoms domain from GOAD,
  // copy-pasted into a lab that has no connection to it. NHA's own
  // ad/NHA/data/config.json declares exactly two domains, ninja.hack and
  // academy.ninja.lan (a trust of the first), so ninja.hack is the forest root.
  assert.strictEqual(GOAD_LABS.NHA.forestRoot, 'ninja.hack');
  assert.ok(!/sevenkingdoms/.test(GOAD_LABS.NHA.forestRoot));
  // The labs that genuinely ARE Seven Kingdoms keep their domains, so this was
  // a fix to one entry rather than a search-and-replace.
  assert.strictEqual(GOAD_LABS.GOAD.forestRoot, 'sevenkingdoms.local');
  assert.strictEqual(GOAD_LABS['GOAD-Mini'].forestRoot, 'sevenkingdoms.local');
});

// ── 6. no sixth read site ───────────────────────────────────────────────────

test('GOAD_LABS is indexed in exactly two functions, and both are named here', () => {
  // The source-scan guard, and the one property that has no runtime test: the
  // lookup used to be inlined at five sites and a site that missed a term
  // resolved a DIFFERENT lab from its neighbours — the MAC table from one, the
  // WinRM wait list from another. Nothing throws when those disagree.
  //
  // getLab is the CATALOG reader ("what does CyberCore ship?"); resolveGoadLab
  // is the DEPLOY reader and the only one that honours spec.goad.lab. A third
  // name appearing here means a new site is resolving labs on its own terms.
  const src = fs.readFileSync(path.join(ROOT, GOAD_REL), 'utf8');
  const lines = src.split(/\r?\n/);
  const ALLOWED = ['getLab', 'resolveGoadLab'];
  const offenders = [];
  let fn = '(top level)';
  lines.forEach((line, i) => {
    const decl = line.match(/^(?:async )?function (\w+)\(/);
    if (decl) fn = decl[1];
    const t = line.trim();
    if (t.startsWith('//') || t.startsWith('*')) return;   // the doc comments name it on purpose
    if (!/GOAD_LABS\[/.test(line)) return;
    if (!ALLOWED.includes(fn)) offenders.push(`${i + 1}: ${fn}() — ${t}`);
  });
  assert.deepStrictEqual(offenders, [],
    `${GOAD_REL} reads GOAD_LABS outside ${ALLOWED.join('/')}. Route it through resolveGoadLab(spec) `
    + 'so a spec-supplied goad.lab reaches every site or none:\n' + offenders.join('\n'));
});

test('the roster check is reached from prepareGoadMacs, not bolted onto one caller', () => {
  // prepareGoadMacs is the funnel: writeDhcpReservations, runGoadPlaybook and
  // deployGoadLane all call it, and so do challenge-lane-deployer and the two
  // admin deploy routes. A guard placed in any one of those would leave the
  // other five able to misdeploy.
  const src = fs.readFileSync(path.join(ROOT, GOAD_REL), 'utf8');
  const body = src.match(/\nfunction prepareGoadMacs\([\s\S]*?\r?\n\}\r?\n/);
  assert.ok(body, 'prepareGoadMacs must still be a top-level function declaration');
  assert.ok(/assertGoadRoster\(/.test(body[0]),
    'prepareGoadMacs must reconcile spec.vms against the resolved lab before it returns a map');
  assert.ok(/resolveGoadLab\(spec\)/.test(body[0]),
    'and it must get that lab from the shared resolver');
});
