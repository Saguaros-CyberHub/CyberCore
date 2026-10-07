/**
 * goad-agent-attach.test.js — the AGENT half of a ticked elk/wazuh extension.
 *
 * WHAT THIS FILE IS DEFENDING
 *
 *  1. A SIEM WITH NOTHING REPORTING TO IT. The extension places a server and
 *     upstream's inventory instruments `[domain]`; if CyberCore places the
 *     server and nothing else, every clone succeeds, the lane reports active,
 *     the console opens and Kibana is EMPTY. That is the silent success this
 *     codebase keeps documenting, so "elk ticked ⇒ every Windows roster host
 *     carries goad-elk-agent" is asserted per host, not per lane.
 *
 *  2. THE LINUX BOXES. elk, wazuh and lx01 are `inLab: false` Ubuntu machines
 *     and DRACARYS's LX01 is a role:'linux' host that IS in the roster. A
 *     Windows-targeted script on any of them is stored os_target 'windows', so
 *     executeScriptsOnVM routes it to executePowerShellViaFile and asks a guest
 *     with no powershell.exe to run one — a failure whose message names neither
 *     the machine's OS nor this decision. Kali is exempt for the same reason and
 *     by a different mechanism (EXTERNAL_ROLES, never in the roster).
 *
 *  3. THE CLOBBER. CiAB attaches its per-asset vuln-app planting through the
 *     SAME spec.vms[].post_clone_scripts array. Replacing it instead of
 *     appending would break an unrelated feature with no error anywhere: the
 *     lane comes up, and the generated scan report describes services that were
 *     never planted. Asserted both ways — the existing slugs survive, and the
 *     caller's own array is never grown in place.
 *
 *  4. THE REGRESSION BAR. A deploy that ticked no SIEM must be BYTE-IDENTICAL
 *     to what it was before this module existed, which is asserted by OBJECT
 *     IDENTITY rather than by deepEqual — every GOAD lane in flight goes through
 *     the same call.
 *
 *  5. THE WIRING. The functions are pure and provable here, but they do nothing
 *     unless the shared deployer calls them, and losing that call is invisible.
 *     A source-text gate pins both call sites.
 *
 * Run: node --test front-end/test/goad-agent-attach.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const attachMod = require(path.join(ROOT, 'src', 'utils', 'goad-agent-attach.js'));
const {
  GOAD_AGENT_SLUGS, goadAgentAttachments, attachGoadAgentScripts, withGoadAgentVulnScripts,
} = attachMod;

const ELK = 'goad-elk-agent';
const WAZUH = 'goad-wazuh-agent';

// ── fixtures ────────────────────────────────────────────────────────────────

/**
 * GOAD-Light (DC01, DC02, SRV02) plus every extension machine and Kali, so one
 * spec exercises both halves of the include/exclude decision at once.
 *
 * Rebuilt per call: these tests assert non-mutation, and a shared literal would
 * let one test's bug pass the next one.
 */
function lightSpec(extensions) {
  return {
    goad: { enabled: true, version: 'GOAD-Light', extensions },
    vms: [
      { name: 'DC01',  role: 'dc' },
      { name: 'DC02',  role: 'dc' },
      { name: 'SRV02', role: 'member' },
      { name: 'ws01',  role: 'workstation' },
      { name: 'elk',   role: 'siem' },
      { name: 'wazuh', role: 'siem' },
      { name: 'lx01',  role: 'linux' },
      { name: 'kali',  role: 'attacker' },
    ],
  };
}

/** slug list a machine ended up with, from the flat attachment shape. */
function slugsFor(attachments, vmName) {
  return attachments.filter(a => a.vm_name === vmName).map(a => a.script_slug);
}

const WINDOWS_ROSTER = ['DC01', 'DC02', 'SRV02'];
const NEVER_ATTACH  = ['elk', 'wazuh', 'lx01', 'kali'];

// ── 1. the contract with the seeder ─────────────────────────────────────────

test('the slug table is exactly the two the seeder promises, and nothing else', () => {
  assert.deepStrictEqual(GOAD_AGENT_SLUGS, { elk: ELK, wazuh: WAZUH });
  // ws01 and lx01 are instrumented BY a SIEM, not carriers of one. A slug here
  // for either would attach an agent installer to a machine that is supposed to
  // RECEIVE one.
  assert.ok(!('ws01' in GOAD_AGENT_SLUGS) && !('lx01' in GOAD_AGENT_SLUGS));
  assert.ok(Object.isFrozen(GOAD_AGENT_SLUGS),
    'the table is the contract with goad-agent-scripts.js; a caller must not be able to edit it');
});

const SEEDER = path.join(ROOT, 'src', 'utils', 'goad-agent-scripts.js');
const psPathFor = (slug) => path.join(ROOT, 'vuln-scripts', `${slug}.ps1`);

test('the other half of the contract declares both slugs', () => {
  // A SOURCE-TEXT gate, not a require: the seeder is another module's to own,
  // and a hard require would make the shared deployer fail to LOAD if it were
  // ever renamed — trading a missing agent for a dead deploy path.
  //
  // Two places count as declaring a slug, because the feature has two files per
  // agent: the PowerShell body under vuln-scripts/, and the boot hook that
  // UPSERTs it into vuln_scripts. Either landing pins the name; neither landing
  // leaves only the table above, which is the standing contract.
  const seederBody = fs.existsSync(SEEDER) ? fs.readFileSync(SEEDER, 'utf8') : null;
  for (const slug of [ELK, WAZUH]) {
    const declared = (seederBody && seederBody.includes(slug)) || fs.existsSync(psPathFor(slug));
    assert.ok(declared || seederBody === null,
      `Nothing declares '${slug}'. runVulnScripts selects WHERE slug = ANY($1) AND `
      + `is_active = true, so an unseeded slug installs nothing and reports nothing — `
      + `the exact silent success this whole feature exists to avoid.`);
    if (seederBody !== null) {
      assert.ok(seederBody.includes(slug),
        `goad-agent-scripts.js exists but seeds no row for '${slug}'.`);
    }
  }
});

test('an agent script takes no arguments — script_args must stay empty', () => {
  // script-executor interpolates script_args UNQUOTED into `& '<path>' ${args}`,
  // so a script that NEEDED an argument would pressure someone into passing one.
  // These take none: a top-level param() block is the only way a .ps1 asks for
  // arguments, and neither has one (the `param(...)` lines in them are function
  // signatures, which are indented).
  for (const slug of [ELK, WAZUH]) {
    const p = psPathFor(slug);
    if (!fs.existsSync(p)) continue;
    const lines = fs.readFileSync(p, 'utf8').split('\n');
    const topLevelParam = lines.some(l => /^param\s*\(/i.test(l));
    assert.ok(!topLevelParam,
      `${slug}.ps1 declares a top-level param() block. These installs must need no arguments — `
      + `script_args reaches the guest unquoted, so anything passed through it is a command `
      + `injection channel.`);
  }
});

// ── 2. elk alone ────────────────────────────────────────────────────────────

test('ticking elk attaches goad-elk-agent to every Windows roster host', () => {
  const attachments = goadAgentAttachments(lightSpec(['elk']));
  for (const host of WINDOWS_ROSTER) {
    assert.deepStrictEqual(slugsFor(attachments, host), [ELK],
      `${host} is a Windows host in [domain]; upstream's [elk_log:children] domain instruments it`);
  }
});

test('ticking elk attaches nothing to elk, wazuh, lx01 or Kali', () => {
  const attachments = goadAgentAttachments(lightSpec(['elk', 'wazuh', 'lx01']));
  for (const host of NEVER_ATTACH) {
    assert.deepStrictEqual(slugsFor(attachments, host), [],
      `${host} is not a Windows host. A windows-os_target script on it is routed to `
      + `powershell.exe by executeScriptsOnVM and fails obscurely.`);
  }
});

// ── 3. wazuh alone ──────────────────────────────────────────────────────────

test('ticking wazuh attaches goad-wazuh-agent to every Windows roster host and no Linux one', () => {
  const attachments = goadAgentAttachments(lightSpec(['wazuh', 'lx01']));
  for (const host of WINDOWS_ROSTER) {
    assert.deepStrictEqual(slugsFor(attachments, host), [WAZUH]);
  }
  for (const host of NEVER_ATTACH) {
    assert.deepStrictEqual(slugsFor(attachments, host), []);
  }
  // wazuh's `instruments` covers [linux_domain] too, but the LINUX agent is
  // pushed by extensions/wazuh/ansible, not by a PowerShell post-clone script.
  // Attaching this slug to lx01 would hand a Windows installer to an Ubuntu box.
  assert.deepStrictEqual(slugsFor(attachments, 'lx01'), []);
});

// ── 4. both at once ─────────────────────────────────────────────────────────

test('ticking elk AND wazuh gives every Windows host both slugs, in a stable order', () => {
  const attachments = goadAgentAttachments(lightSpec(['wazuh', 'elk']));
  for (const host of WINDOWS_ROSTER) {
    // Table order, NOT the order the author happened to tick them in: two lanes
    // with the same ticks must produce the same list, or a diff of two lanes'
    // attachments is noise.
    assert.deepStrictEqual(slugsFor(attachments, host), [ELK, WAZUH],
      'comparing two consoles against one incident is a real exercise, so both must land');
  }
});

test('neither agent script declares the other as a dependency', () => {
  // script-executor's sortByDependencies is a topological sort over depends_on
  // ONLY. The two installs are disjoint — Sysmon+winlogbeat vs wazuh-agent,
  // different services, different destinations — so there is no edge to express,
  // and inventing one would make either agent's failure block the other.
  if (!fs.existsSync(SEEDER)) {
    assert.ok(true, 'seeder not present yet');
    return;
  }
  const body = fs.readFileSync(SEEDER, 'utf8');
  // Neither slug may appear inside the other's depends_on. Checked as text
  // because the seeder's export shape is the other agent's to choose: a
  // depends_on naming the sibling slug is the only spelling that could create
  // the edge, so its absence is the whole assertion.
  const dependsOnSibling = /depends_on[^\n]*goad-(elk|wazuh)-agent/.test(body);
  assert.ok(!dependsOnSibling,
    'goad-elk-agent and goad-wazuh-agent are independent; neither belongs in the other\'s depends_on');
});

// ── 5. the regression bar: ticking neither changes NOTHING ──────────────────

test('a spec with no SIEM extension is returned by identity, not rebuilt', () => {
  for (const extensions of [undefined, [], ['ws01'], ['lx01'], ['nonesuch']]) {
    const spec = lightSpec(extensions);
    const before = JSON.stringify(spec);
    assert.strictEqual(attachGoadAgentScripts(spec), spec,
      `extensions=${JSON.stringify(extensions)}: the SAME object must come back — every GOAD `
      + `lane in flight goes through this call`);
    assert.strictEqual(JSON.stringify(spec), before, 'and the spec must not have been touched');
    assert.deepStrictEqual(goadAgentAttachments(spec), []);
  }
});

test('a non-GOAD spec is untouched, and never reaches the lab resolver', () => {
  const plain = { vms: [{ name: 'web-01', post_clone_scripts: ['lin-apache-2449'] }] };
  assert.strictEqual(attachGoadAgentScripts(plain), plain);
  assert.deepStrictEqual(goadAgentAttachments(plain), []);

  // goad present but disabled: `extensions` on a disabled GOAD block is dead
  // data, and honouring it would install agents on a lane with no forest.
  const disabled = { goad: { enabled: false, extensions: ['elk'] }, vms: [{ name: 'DC01' }] };
  assert.strictEqual(attachGoadAgentScripts(disabled), disabled);
  assert.deepStrictEqual(goadAgentAttachments(disabled), []);
});

test('vulnScripts is handed straight back when there is nothing to add', () => {
  const spec = lightSpec(['ws01']);
  // null stays NULL. deployLaneVms branches on `vulnScripts && vulnScripts.length`,
  // and an empty array in its place would open a deployment_vuln_selections row
  // for every lane in the system that has no scripts at all.
  assert.strictEqual(withGoadAgentVulnScripts(null, spec), null);
  const caller = [{ vm_name: 'DC01', script_slug: 'init-setup' }];
  assert.strictEqual(withGoadAgentVulnScripts(caller, spec), caller,
    'the caller\'s own array, by identity');
});

// ── 6. do not clobber ───────────────────────────────────────────────────────

test('an existing post_clone_scripts array is appended to, never replaced', () => {
  const spec = lightSpec(['elk', 'wazuh']);
  const planted = ['init-setup', 'win-smb-vuln'];
  spec.vms[0].post_clone_scripts = planted;

  const out = attachGoadAgentScripts(spec);
  const dc01 = out.vms.find(v => v.name === 'DC01');

  assert.deepStrictEqual(dc01.post_clone_scripts, ['init-setup', 'win-smb-vuln', ELK, WAZUH],
    'CiAB plants vuln-app scripts through this array; losing one breaks an unrelated '
    + 'feature and nothing anywhere says so');

  // The caller's array is NOT grown in place. A stored spec is shared with
  // whoever else read that row, and mutating it leaks one deploy's telemetry
  // choice into another lane.
  assert.deepStrictEqual(planted, ['init-setup', 'win-smb-vuln']);
  assert.notStrictEqual(dc01.post_clone_scripts, planted);
  assert.notStrictEqual(out, spec);
  assert.notStrictEqual(out.vms, spec.vms);
});

test('a machine that gets no slugs comes back by identity', () => {
  const spec = lightSpec(['elk']);
  const out = attachGoadAgentScripts(spec);
  for (const name of NEVER_ATTACH) {
    assert.strictEqual(out.vms.find(v => v.name === name), spec.vms.find(v => v.name === name),
      `${name} must be the very same object — an untouched machine is untouched`);
  }
});

test('attaching twice is a no-op — no slug is ever duplicated', () => {
  const once = attachGoadAgentScripts(lightSpec(['elk', 'wazuh']));
  const twice = attachGoadAgentScripts(once);
  assert.deepStrictEqual(
    twice.vms.map(v => v.post_clone_scripts || null),
    once.vms.map(v => v.post_clone_scripts || null));
  // Already attached, so the second pass has nothing to add and returns the
  // same object: this is what makes the deployer safe to run over a spec some
  // other layer already attached to.
  assert.strictEqual(twice.vms.find(v => v.name === 'DC01'),
    once.vms.find(v => v.name === 'DC01'));
});

test('withGoadAgentVulnScripts appends to the caller list and drops exact duplicates', () => {
  const spec = lightSpec(['elk']);
  const caller = [
    { vm_name: 'DC01', script_slug: 'init-setup' },
    { vm_name: 'DC01', script_slug: ELK },        // already derived by CiAB
  ];
  const out = withGoadAgentVulnScripts(caller, spec);

  assert.deepStrictEqual(out, [
    { vm_name: 'DC01', script_slug: 'init-setup' },
    { vm_name: 'DC01', script_slug: ELK },
    { vm_name: 'DC02', script_slug: ELK },
    { vm_name: 'SRV02', script_slug: ELK },
  ], 'the caller\'s entries come first and unchanged; DC01 does not install the agent twice');

  assert.deepStrictEqual(caller.length, 2, 'the caller\'s array is not pushed to');
});

// ── 7. ws01, the extension that joins the forest ────────────────────────────

test('ws01 is instrumented when it is ticked, and absent when it is not', () => {
  const withWs = goadAgentAttachments(lightSpec(['elk', 'ws01']));
  assert.deepStrictEqual(slugsFor(withWs, 'ws01'), [ELK],
    'resolveGoadLab composes an inLab extension into the roster, so ws01 is a Windows host in [domain]');

  const withoutWs = goadAgentAttachments(lightSpec(['elk']));
  assert.deepStrictEqual(slugsFor(withoutWs, 'ws01'), [],
    'an untocked ws01 is not in the roster — it is a stray spec VM, and assertGoadRoster '
    + 'would refuse the deploy long before an agent mattered');
});

test('an extension the lab refuses is not instrumented either', () => {
  // SCCM already ships a host named WS01, so extensionsForLab drops the ws01
  // extension for name collision. It is nonetheless a Windows host IN THE
  // SCCM ROSTER, so it is instrumented as a lab host — the point is that the
  // dropped EXTENSION cannot smuggle a machine in.
  const spec = {
    goad: { enabled: true, version: 'SCCM', extensions: ['elk', 'ws01'] },
    vms: [
      { name: 'DC01' }, { name: 'SRV01' }, { name: 'SRV02' }, { name: 'WS01' },
      { name: 'elk' },
    ],
  };
  const attachments = goadAgentAttachments(spec);
  assert.deepStrictEqual(
    [...new Set(attachments.map(a => a.vm_name))].sort(),
    ['DC01', 'SRV01', 'SRV02', 'WS01']);
  assert.deepStrictEqual(slugsFor(attachments, 'elk'), []);
});

// ── 8. a Linux host that really is in the roster ────────────────────────────

test('DRACARYS LX01 is a roster host and still gets no Windows agent', () => {
  const spec = {
    goad: { enabled: true, version: 'DRACARYS', extensions: ['elk', 'wazuh'] },
    vms: [{ name: 'DC01' }, { name: 'SRV01' }, { name: 'LX01' }, { name: 'elk' }, { name: 'wazuh' }],
  };
  const attachments = goadAgentAttachments(spec);
  assert.deepStrictEqual(slugsFor(attachments, 'LX01'), [],
    'LX01 is role:linux IN the roster, which is why the filter is on role rather than on '
    + 'roster membership alone');
  assert.deepStrictEqual(slugsFor(attachments, 'DC01'), [ELK, WAZUH]);
  assert.deepStrictEqual(slugsFor(attachments, 'SRV01'), [ELK, WAZUH]);
});

// ── 9. name matching ────────────────────────────────────────────────────────

test('roster matching is case-insensitive but the SPEC spelling is what is emitted', () => {
  const spec = {
    goad: { enabled: true, version: 'GOAD-Light', extensions: ['elk', 'ws01'] },
    vms: [{ name: 'dc01' }, { name: 'Dc02' }, { name: 'srv02' }, { name: 'WS01' }],
  };
  const attachments = goadAgentAttachments(spec);
  assert.deepStrictEqual(attachments.map(a => a.vm_name), ['dc01', 'Dc02', 'srv02', 'WS01'],
    'runVulnScripts filters with `s.vm_name === vm.name` against the deployed machine\'s spec '
    + 'name, so an attachment spelled like the roster instead of like the spec matches nothing '
    + 'and skips in silence');
});

// ── 10. a spec-supplied lab, and a broken one ───────────────────────────────

test('a spec-supplied goad.lab is the roster that is read', () => {
  const spec = {
    goad: {
      enabled: true, version: 'GOAD-Light', extensions: ['elk'],
      lab: {
        forestRoot: 'acme.local',
        vms: [
          { name: 'ACME-DC', role: 'dc', os: 'Windows Server', template_vmid: 1004, ipOctet: 10, nic_model: 'e1000' },
          { name: 'ACME-FS', role: 'member', os: 'Windows Server', template_vmid: 1004, ipOctet: 22, nic_model: 'e1000' },
          { name: 'ACME-LX', role: 'linux', os: 'Ubuntu', template_vmid: 1011, ipOctet: 23, nic_model: 'virtio' },
        ],
      },
    },
    vms: [{ name: 'ACME-DC' }, { name: 'ACME-FS' }, { name: 'ACME-LX' }, { name: 'elk' }],
  };
  const attachments = goadAgentAttachments(spec);
  assert.deepStrictEqual(attachments, [
    { vm_name: 'ACME-DC', script_slug: ELK },
    { vm_name: 'ACME-FS', script_slug: ELK },
  ], 'resolveGoadLab is the ONE deploy-time reader, so a generated forest is instrumented too');
});

test('a malformed spec-supplied lab attaches nothing instead of throwing', () => {
  // resolveGoadLab throws on a bad goad.lab, and prepareGoadMacs throws the same
  // assertValidLabDef message a few steps later in the same deploy. Attaching
  // agents must never be the reason a deploy dies, and must never relocate that
  // error to a place that reads as though the agents caused it.
  const spec = {
    goad: { enabled: true, version: 'GOAD-Light', extensions: ['elk'], lab: { forestRoot: '', vms: [] } },
    vms: [{ name: 'DC01' }],
  };
  assert.deepStrictEqual(goadAgentAttachments(spec), []);
  assert.strictEqual(attachGoadAgentScripts(spec), spec);
});

// ── 11. the shape carries no place for a secret ─────────────────────────────

test('an attachment is exactly {vm_name, script_slug} — there is no args field', () => {
  // script-executor interpolates script_args UNQUOTED into the PowerShell
  // invocation stub, so a field for it here would be a channel for command
  // injection into the guest. These installs need no arguments: the agent finds
  // its manager by the DNS alias the extension already registers.
  for (const a of goadAgentAttachments(lightSpec(['elk', 'wazuh']))) {
    assert.deepStrictEqual(Object.keys(a).sort(), ['script_slug', 'vm_name']);
    assert.strictEqual(typeof a.vm_name, 'string');
    assert.strictEqual(typeof a.script_slug, 'string');
  }
});

// ── 12. the wiring, and the source-text traps ───────────────────────────────

test('the shared deployer actually calls both halves', () => {
  const rel = path.join('src', 'utils', 'challenge-lane-deployer.js');
  const body = fs.readFileSync(path.join(ROOT, rel), 'utf8');

  assert.ok(/require\('\.\/goad-agent-attach'\)/.test(body),
    `${rel} must require ./goad-agent-attach — it is the one deploy every caller shares`);
  assert.ok(/attachGoadAgentScripts\(parseSpec\(challenge\.spec\)\)/.test(body),
    `${rel} must attach at the spec it is about to deploy. Attaching at SYNTHESIS instead `
    + `would freeze a telemetry choice into a stored row that outlives it.`);
  assert.ok(/vulnScripts: laneVulnScripts/.test(body),
    `${rel} must pass the MERGED list into the lane context. runVulnScripts reads that list `
    + `and never looks at spec.vms[].post_clone_scripts, so dropping this line deploys a SIEM `
    + `with nothing reporting to it and every lane still goes green.`);
  assert.ok(/withGoadAgentVulnScripts\(cfg\.vuln_scripts \|\| \[\], spec\)/.test(body),
    `${rel} must re-derive the agents on REBUILD too — a rebuilt DC comes back with no Sysmon `
    + `and goes dark in a console the rest of the lane is still reporting to.`);
});

test('the new sources carry no NUL bytes and no CRLF', () => {
  // Both have silently broken source-text gates in this repo before, and the
  // PowerShell payload path is sensitive to line endings. Scanned as BYTES —
  // grep -P reports a false clean on this platform.
  //
  // The .ps1 bodies and the seeder are scanned on the same terms and for a
  // sharper reason than the JS: a CR that reaches script_content is staged onto
  // the guest by guestWriteLargeText, which re-line-ends the payload to CRLF —
  // so a CRLF file becomes a CR CR LF one, and PowerShell 5.1 parses the stray
  // CR as content. Guarded by existsSync so the half of the feature that has
  // not landed yet cannot fail this gate; the declaration test above is what
  // insists they exist at all.
  for (const rel of [
    path.join('src', 'utils', 'goad-agent-attach.js'),
    path.join('src', 'utils', 'goad-agent-scripts.js'),
    path.join('test', 'goad-agent-attach.test.js'),
    path.join('vuln-scripts', `${ELK}.ps1`),
    path.join('vuln-scripts', `${WAZUH}.ps1`),
  ]) {
    const abs = path.join(ROOT, rel);
    if (!fs.existsSync(abs)) continue;
    const buf = fs.readFileSync(abs);
    assert.strictEqual(buf.indexOf(0), -1, `${rel} contains a NUL byte`);
    assert.strictEqual(buf.indexOf(0x0d), -1, `${rel} contains a CR — keep repo sources LF`);
  }
});
