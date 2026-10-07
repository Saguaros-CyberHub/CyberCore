// ============================================================================
// scenario-compiler.test.js — Track E, phase E4.
//
// WHAT IS BEING DEFENDED. src/incident/scenario-compiler.js turns a CiAB
// client's threat scenario into two cc-emit playbooks — the intrusion and a
// benign floor built from that client's own hostnames — plus the staff-only key
// that grades the run.
//
// Every playbook the repo shipped before this one was HAND WRITTEN and reviewed
// by a person. A compiled playbook is none of those things: it never lands on
// disk, nobody reads it, and it is different on every engagement. So it is
// exactly the artefact that most needs the contract test/loggen-playbooks.test.js
// encodes — and the one that file, which walks `readdirSync(playbooks/)`, cannot
// reach. test/helpers/playbook-contract.js exists to close that gap, and this
// file applies EVERY assertion in it to the compiled pair.
//
// The failures those assertions catch are all silent in production. No error,
// no warning, no crash — just an exercise that is either broken or already
// solved:
//
//   * an unresolved {{token}} ships literal braces to Kibana
//   * a seventh top-level key falls to dynamic mapping under ecs@mappings and
//     silently REJECTS documents
//   * an untagged attack event is dropped by the agent's drop_event processor
//   * a source.host, a (source.type, source.name) pair, a closed metadata
//     vocabulary or an address space that occurs ONLY during the attack is a
//     one-terms-aggregation answer key
//
// ON TOP OF THE CONTRACT, this file holds the four things that are specific to
// compiling rather than to playbooks in general:
//
//   §5  the ALLOWLIST. cc-emit.js is baked into template 1007. A compiled
//       playbook that uses a feature the baked emitter does not have is a
//       re-bake plus a redeploy of every existing lane, discovered in class.
//   §6  the attack draws its hosts from the FLOOR'S pools — the whole reason
//       there are two playbooks and not one.
//   §7  the key counts the events the guest will actually write.
//   §9  `action` and `detection_opportunity` are the answer, and they never
//       reach the wire.
//   §10 with Sysmon in the lane (E3b), Windows host telemetry is CEDED, or
//       `_exists_: winlog.event_id` separates real from synthetic in one click.
//
// FIXTURES. Two shapes, both derived from the intake fixtures the CiAB plugin
// suite already carries (modules/crucible/plugins/ciab/test/fixtures/): a
// 50-person Windows-domain healthcare practice, and a 6-person non-profit that
// runs NO on-prem servers at all. The second one is not padding — an estate with
// no servers puts every server-shaped bucket through its fallback, which is the
// path that fails silently if it is wrong.
//
// Run: node --test front-end/test/scenario-compiler.test.js  (or npm test)
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const C = require(path.join(__dirname, '..', 'src', 'incident', 'scenario-compiler.js'));
const H = require(path.join(__dirname, 'helpers', 'playbook-contract.js'));

const emit = H.emit;

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const RUN_ID = '11111111-2222-3333-4444-555555555555';

/**
 * The lane's real .80–.99 band.
 *
 * challenge-lane-deployer pins deployed machines into it, and the plan says the
 * floor's `lanips` comes from there. Written out rather than imported because
 * this file must not grow an edge to the deployer.
 */
const LANE_IPS = Array.from({ length: 20 }, (_, i) => `100.100.60.${80 + i}`);

/**
 * FIXTURE 1 — intake-testing-healthcare.json grown into a profile.
 *
 * The intake fixture states the shape (Healthcare, 51-100 staff, 4 servers, one
 * Server 2019 DC, SMB/RDP/SSH/HTTP, AD domain mode); the assets below are what
 * the profile generator produces from it. Windows-dominant on purpose: that is
 * what makes §10's cede meaningful.
 */
const HEALTHCARE = {
  assets: [
    { hostname: 'DC01', ip: '10.50.10.10', role: 'server', os: 'Windows Server 2019 Standard', function: 'Primary domain controller and DNS', critical: true, services: ['389/LDAP', '445/SMB'] },
    { hostname: 'FILE01', ip: '10.50.10.11', role: 'server', os: 'Windows Server 2019', function: 'File share for finance and HR', critical: true, services: ['445/SMB'] },
    { hostname: 'SQL01', ip: '10.50.10.12', role: 'server', os: 'Windows Server 2022', function: 'Practice management database', critical: true, services: ['1433/MSSQL'] },
    { hostname: 'WEB01', ip: '10.50.10.13', role: 'server', os: 'Ubuntu Server 22.04', function: 'Public website', services: ['80/HTTP', '443/HTTPS'] },
    { hostname: 'MAIL-RELAY', ip: '10.50.10.14', role: 'server', os: 'Debian 12', function: 'Outbound smtp relay', services: ['25/SMTP'] },
    { hostname: 'APP-EHR-01', ip: '10.50.10.15', role: 'server', os: 'Windows Server 2019', function: 'EHR application server', services: ['8080/HTTP'] },
    { hostname: 'FW-EDGE', ip: '10.50.10.1', role: 'network', os: 'Embedded', function: 'Perimeter firewall' },
    { hostname: 'RECEPTION-WS', ip: '10.50.20.21', role: 'workstation', os: 'Windows 11 23H2', function: 'Front desk check-in' },
    { hostname: 'NURSE-WS-01', ip: '10.50.20.22', role: 'workstation', os: 'Windows 10 22H2', function: 'Nurse station' },
    { hostname: 'BILLING-WS', ip: '10.50.20.23', role: 'workstation', os: 'Windows 11 23H2', function: 'Billing and claims' },
    { hostname: 'ADMIN-LT', ip: '10.50.20.24', role: 'workstation', os: 'Windows 11 23H2', function: 'Practice manager laptop' },
    { hostname: 'LAB-LINUX', ip: '10.50.20.25', role: 'workstation', os: 'Ubuntu 22.04', function: 'Lab analysis workstation' },
  ],
  stakeholders: [
    { name: 'Dana Okafor', email: 'dokafor@example.org' },
    { name: 'Miguel Torres' },
    { name: 'Priya Raman' },
    { name: 'Sam Whitfield' },
    { name: 'Alice Chen' },
  ],
  scenario: {
    scenario_id: 'TS-001',
    name: 'Ransomware via phished billing credentials',
    type: 'ransomware',
    threat_actor: 'Opportunistic ransomware affiliate',
    initial_vector: 'Invoice-themed phishing email',
    attack_path: [
      { step: 1, action: 'Send an invoice-themed lure to billing staff', target: 'MAIL-RELAY', technique: 'T1566.001', detection_opportunity: 'Mail gateway records an external sender using a lookalike display name' },
      { step: 2, action: 'The macro launches a downloader', target: 'BILLING-WS', technique: 'T1059.001', detection_opportunity: 'An office application spawning a scripting host on a billing workstation' },
      { step: 3, action: 'Register a run key so the foothold survives reboot', target: 'BILLING-WS', technique: 'T1547.001', detection_opportunity: 'A new autorun value created outside a patching window' },
      { step: 4, action: 'Dump cached domain credentials', target: 'BILLING-WS', technique: 'T1003.001', detection_opportunity: 'Process memory access against LSASS from a non-administrative process' },
      { step: 5, action: 'Enumerate shares and domain administrators', target: 'DC01', technique: 'T1018', detection_opportunity: 'Broad SMB enumeration originating from one workstation' },
      { step: 6, action: 'Move laterally onto the file server', target: 'FILE01', technique: 'T1021.002', detection_opportunity: 'A service account holding an interactive logon at three in the morning' },
      { step: 7, action: 'Encrypt the finance share and remove shadow copies', target: 'FILE01', technique: 'T1486', detection_opportunity: 'Mass file rename immediately followed by vssadmin delete shadows' },
    ],
    impacted_assets: ['FILE01', 'SQL01'],
  },
};

/**
 * FIXTURE 2 — intake-az-cyber-initiative.json grown into a profile.
 *
 * Six people, THREE WORKSTATIONS AND THREE LAPTOPS, `server_count: "0"`, mail
 * and web both in the cloud, two of the six on macOS. profile-to-spec's own
 * prompt has a branch for exactly this ("this organization runs NO on-prem
 * servers"), so it is a shape the platform really produces.
 *
 * It is here because it drives every server-shaped bucket — srvpool, dbpool,
 * webpool, mailpool, authpool, apppool — into its fallback at once. A bucket
 * that comes out EMPTY is not a degraded exercise: samplePool returns null and
 * cc-emit ships a literal "{{dbpool}}" into Kibana.
 */
const NONPROFIT = {
  assets: [
    { hostname: 'front-desk-pc', ip: '192.168.7.21', role: 'workstation', os: 'Windows 11 23H2', function: 'Reception and donor intake' },
    { hostname: 'director-mbp', ip: '192.168.7.22', role: 'workstation', os: 'macOS 14 Sonoma', function: 'Executive director laptop' },
    { hostname: 'programs-mbp', ip: '192.168.7.23', role: 'workstation', os: 'macOS 14 Sonoma', function: 'Programs manager laptop' },
    { hostname: 'grants-pc', ip: '192.168.7.24', role: 'workstation', os: 'Windows 11 23H2', function: 'Grant writing and finance' },
    { hostname: 'volunteer-pc', ip: '192.168.7.25', role: 'workstation', os: 'Windows 10 22H2', function: 'Shared volunteer machine' },
    { hostname: 'outreach-lt', ip: '192.168.7.26', role: 'workstation', os: 'Windows 11 23H2', function: 'Outreach laptop' },
    { hostname: 'office-router', ip: '192.168.7.1', role: 'network', os: 'Embedded', function: 'Small business gateway and wifi' },
  ],
  stakeholders: [
    { name: 'Rosa Delgado', email: 'rdelgado@example.org' },
    { name: 'Chris Boone' },
    { name: 'Aisha Bello' },
  ],
  scenario: {
    scenario_id: 'TS-014',
    name: 'Business email compromise against the finance mailbox',
    type: 'phishing',
    threat_actor: 'Financially motivated BEC crew',
    initial_vector: 'Credential phishing page mimicking the cloud mail provider',
    attack_path: [
      { step: 1, action: 'Harvest the grants manager password through a cloned login page', target: 'grants-pc', technique: 'T1566.002', detection_opportunity: 'A cloud sign-in from an unfamiliar autonomous system minutes after a link click' },
      { step: 2, action: 'Sign in and create a hidden inbox rule', target: 'grants-pc', technique: 'T1078', detection_opportunity: 'Inbox rule creation moving supplier mail straight to a rarely opened folder' },
      { step: 3, action: 'Read the shared drive for pending invoices', target: 'director-mbp', technique: 'T1213', detection_opportunity: 'Bulk document reads outside the account normal working pattern' },
      { step: 4, action: 'Send the diverted payment instruction', target: 'volunteer-pc', technique: 'T1114.002', detection_opportunity: 'An outbound message replying to a supplier thread from a new client address' },
    ],
    impacted_assets: ['grants-pc'],
  },
};

/**
 * A one-phase scenario, for the coherence and burst assertions.
 *
 * assertOneAdversaryNotAShuffle, assertRigidBurstsElasticDwell and
 * assertPoolVariesBetweenEvents each measure ONE step: how many attacker
 * addresses appear, whether the burst window survives being asked for two
 * hours, whether the accounts vary. A seven-phase intrusion legitimately has two
 * addresses — an external one and an internal foothold — so those three are
 * applied here, and §3 states the two-address invariant for the multi-phase case
 * separately rather than pretending it is one.
 */
const SPRAY = {
  scenario_id: 'TS-002',
  name: 'Credential stuffing against the remote access service',
  type: 'credential_stuffing',
  threat_actor: 'Commodity credential-stuffing operator',
  initial_vector: 'Reused passwords from an unrelated breach',
  attack_path: [
    { step: 1, action: 'Replay a breach wordlist against the exposed service', target: 'WEB01', technique: 'T1110.003', detection_opportunity: 'Many accounts failing from a single source inside a short window' },
  ],
  impacted_assets: ['WEB01'],
};

/** Compile a fixture. Everything the compiler needs, nothing it does not. */
function compile(fixture, opts) {
  const o = opts || {};
  return C.compileScenario({
    scenario: o.scenario || fixture.scenario,
    assets: fixture.assets,
    options: Object.assign({
      runId: RUN_ID,
      laneIps: LANE_IPS,
      stakeholders: fixture.stakeholders,
    }, o.options || {}),
  });
}

/**
 * Compiled once per shape and reused.
 *
 * Planning the floor is the expensive half — 13k events — and every assertion
 * below wants the SAME sample, not a dozen independent draws that could
 * disagree about what benign traffic contains.
 */
const CASES = [
  { label: 'healthcare', out: compile(HEALTHCARE), fixture: HEALTHCARE },
  { label: 'nonprofit', out: compile(NONPROFIT), fixture: NONPROFIT },
];
for (const c of CASES) {
  c.floorPlan = H.planOf(c.out.floor, { label: `${c.label} floor` });
  c.attackPlan = H.planOf(c.out.attack, { label: `${c.label} attack` });
}

const linesOf = (plan) => plan.events.map((ev) => emit.toLine(ev, Date.now()));

// ===========================================================================
// §1  THE WIRE FORMAT
// ===========================================================================

test('§1 every compiled event carries exactly the six-key envelope', () => {
  for (const c of CASES) {
    H.assertSixKeyEnvelope(c.out.floor, { plan: c.floorPlan, label: `${c.label} floor` });
    H.assertSixKeyEnvelope(c.out.attack, { plan: c.attackPlan, label: `${c.label} attack` });
  }
});

test('§1 no compiled playbook ships an unresolved {{token}}', () => {
  for (const c of CASES) {
    H.assertNoUnresolvedTokens(c.out.floor, { plan: c.floorPlan, label: `${c.label} floor` });
    H.assertNoUnresolvedTokens(c.out.attack, { plan: c.attackPlan, label: `${c.label} attack` });
  }
});

test('§1 every compiled attack event is MITRE-tagged, or the agent drops it', () => {
  for (const c of CASES) {
    H.assertEveryAttackEventTagged(c.out.attack, { plan: c.attackPlan, label: `${c.label} attack` });
  }
});

test('§1 the serialization cc-attack.sh greps for is what a compiled attack emits', () => {
  for (const c of CASES) {
    H.assertGrepSerialization(c.out.attack, { plan: c.attackPlan });
  }
});

test('§1 every compiled metadata value is a STRING', () => {
  // loggen.metadata is mapped `flattened`. A number under a key Elasticsearch
  // has already seen as a string is a mapping conflict, and a data stream does
  // not coerce or warn on one — it REJECTS the document.
  for (const c of CASES) {
    for (const pb of [c.out.floor, c.out.attack]) {
      for (const step of pb.steps) {
        for (const [k, v] of Object.entries(step.metadata || {})) {
          assert.strictEqual(typeof v, 'string', `${c.label}: metadata.${k} is ${typeof v}`);
        }
        for (const tpl of step.templates || []) {
          for (const [k, v] of Object.entries((tpl && tpl.metadata) || {})) {
            assert.strictEqual(typeof v, 'string', `${c.label}: template metadata.${k} is ${typeof v}`);
          }
        }
      }
    }
  }
});

// ===========================================================================
// §2  THE ANTI-ORACLE ASSERTIONS — the reason there are two playbooks
// ===========================================================================

test('§2 the compiled floor covers every source pair, host, metadata value and address space the attack uses', () => {
  for (const c of CASES) {
    H.assertFloorCoversAttackValues(c.out.floor, {
      floorPlan: c.floorPlan,
      attacks: [{ playbook: c.out.attack, plan: c.attackPlan, label: `${c.label} attack` }],
      // NOT the default LOGGEN_HOSTS. On a defensive lane log-generator's own
      // baseline is off (LOGGEN_BASELINE_ENABLED defaults to 0), so cc-hostbase
      // is the ONLY benign traffic and the compiled floor has to cover the
      // attack entirely by itself.
      extraHosts: [],
    });
  }
});

test('§2 the compiled floor keeps a false-positive floor of MITRE labels', () => {
  for (const c of CASES) {
    H.assertBenignMitreFloor(c.out.floor, { plan: c.floorPlan });
  }
});

test('§2 no compiled event states the conclusion a student is meant to reach', () => {
  for (const c of CASES) {
    H.assertStatesNoConclusion(c.out.floor, { plan: c.floorPlan, label: `${c.label} floor` });
    H.assertStatesNoConclusion(c.out.attack, { plan: c.attackPlan, label: `${c.label} attack` });
  }
});

test('§2 the compiled floor is the CLIENT\'S estate, not the baked one', () => {
  // The whole point of E4. A floor still drawing web-01/db-01/ws-042 beside an
  // attack on DC01 is the one-click oracle this phase exists to remove.
  const generic = ['web-01', 'db-01', 'ws-042', 'srv-prod-01', 'fileserv-01', 'auth-01'];
  for (const c of CASES) {
    const hosts = new Set();
    for (const name of C.HOST_POOLS) for (const h of c.out.floor.pools[name]) hosts.add(h);
    for (const g of generic) {
      assert.ok(!hosts.has(g), `${c.label}: compiled floor still emits the baked host ${g}`);
    }
    for (const asset of c.fixture.assets) {
      assert.ok(hosts.has(asset.hostname),
        `${c.label}: ${asset.hostname} is in the estate but in none of the floor's host pools`);
    }
  }
});

// ===========================================================================
// §3  COHERENCE — one run has to read as one adversary
// ===========================================================================

test('§3 a compiled event never contradicts itself about who it describes', () => {
  for (const c of CASES) {
    H.assertNoSelfContradiction(c.out.floor, { plan: c.floorPlan, label: `${c.label} floor` });
    H.assertNoSelfContradiction(c.out.attack, { plan: c.attackPlan, label: `${c.label} attack` });
  }
});

test('§3 the same run id compiles the same attack on every lane', () => {
  for (const c of CASES) {
    H.assertDeterministicPerRunId(c.out.attack);
    H.assertDeterministicPerRunId(c.out.floor);
  }
});

test('§3 a single-phase compiled attack is ONE adversary, not a shuffle', () => {
  const { out } = compileSprayWithBurst();
  H.assertOneAdversaryNotAShuffle(out.attack);
});

test('§3 a multi-phase attack has exactly TWO addresses, and both are declared entities', () => {
  // The multi-phase case cannot satisfy assertOneAdversaryNotAShuffle and should
  // not pretend to: an intruder who reaches the file server from OUTSIDE the
  // estate has not moved laterally, they have teleported. So the invariant is
  // "one external adversary plus one internal foothold", and BOTH are entities
  // — resolved once per run — rather than per-event draws.
  for (const c of CASES) {
    const ips = new Set();
    for (const ev of c.attackPlan.events) {
      const m = /from (\d+\.\d+\.\d+\.\d+) port/.exec(ev.message);
      if (m) ips.add(m[1]);
    }
    const declared = new Set([c.attackPlan.entities.source_ip, c.attackPlan.entities.pivot_ip]);
    for (const ip of ips) {
      assert.ok(declared.has(ip),
        `${c.label}: ${ip} appears as an attacker address but is not a resolved entity`);
    }
    assert.ok(ips.size <= 2, `${c.label}: ${ips.size} attacker addresses — that is a shuffle`);
  }
});

test('§3 a compiled spray is many accounts from one source, not one account repeated', () => {
  const { out } = compileSprayWithBurst();
  H.assertPoolVariesBetweenEvents(out.attack);
});

// ===========================================================================
// §4  TIMING
// ===========================================================================

test('§4 a compiled burst stays rigid while dwell absorbs the requested duration', () => {
  // The rigid/elastic split is what keeps a brute force a brute force at the
  // console's two-hour option. Uniformly scaling 240 attempts across 7200s is
  // one attempt every thirty seconds — no threshold rule a student writes will
  // ever fire on it, and the exercise evaporates for the technique it matters
  // most for.
  const { out } = compileSprayWithBurst();
  H.assertRigidBurstsElasticDwell(out.attack, { label: 'compiled spray' });
});

test('§4 a compiled playbook plans at every duration it can honestly run, and refuses the rest', () => {
  for (const c of CASES) {
    H.assertPlansAtEveryDuration(c.out.floor, { label: `${c.label} floor` });
    H.assertPlansAtEveryDuration(c.out.attack, { label: `${c.label} attack` });
  }
});

test('§4 nominal_seconds is the laid-out length, and a shorter run is refused', () => {
  for (const c of CASES) {
    assert.strictEqual(c.out.attack.nominal_seconds,
      Math.max(Math.ceil(emit.layout(c.out.attack.steps, 1).end), emit.minSecondsFor(c.out.attack)),
      `${c.label}: nominal_seconds is not the playbook's own laid-out length`);
    const floorSeconds = emit.minSecondsFor(c.out.attack);
    assert.throws(
      () => compile(c.fixture, { options: { requestedSeconds: floorSeconds - 1 } }),
      /needs at least/,
      `${c.label}: compiling below the rigid floor should refuse, not compress`
    );
    // And one second above it must compile, so the refusal is a boundary rather
    // than a blanket.
    assert.ok(compile(c.fixture, { options: { requestedSeconds: floorSeconds + 1 } }).attack);
  }
});

// ===========================================================================
// §5  THE ALLOWLIST — cc-emit.js is BAKED
// ===========================================================================

/**
 * Every key cc-emit.js actually reads, and nothing else.
 *
 * Derived by reading the emitter, not by reading a compiled playbook: a key the
 * compiler emits and the emitter ignores is dead weight, but a key the compiler
 * emits EXPECTING the emitter to honour it is a feature that does not exist on
 * template 1007. That is a re-bake plus a redeploy of every deployed lane, and
 * it would be discovered as "the exercise behaves differently on the cluster
 * than it does in test".
 */
const ALLOW = {
  playbook: new Set(['name', 'story', 'technique', 'tactic', 'subtechnique',
    'nominal_seconds', 'entities', 'pools', 'bindings', 'skewed', 'rhythm', 'steps']),
  step: new Set(['gap', 'spread', 'count', 'overlap', 'level', 'source', 'message',
    'templates', 'metadata', 'technique', 'tactic', 'subtechnique']),
  source: new Set(['type', 'name', 'host']),
  template: new Set(['weight', 'message', 'level', 'metadata']),
  entity: new Set(['oneOf', 'ipv4Host']),
  binding: new Set(['pool', 'by']),
  rhythm: new Set(['utc_offset', 'hourly', 'weekend']),
};

/** cc-emit's own token grammar, copied from its TOKEN_RE. */
const TOKEN_RE = /\{\{([a-zA-Z0-9_]+)(?:\.(\d+))?(?::(\d+)-(\d+))?\}\}/g;
const BUILTIN_TOKENS = new Set(['rand', 'port', 'pid', 'seq']);

function checkAllowed(label, playbook) {
  for (const k of Object.keys(playbook)) {
    assert.ok(ALLOW.playbook.has(k), `${label}: top-level key "${k}" is not a cc-emit feature`);
  }
  for (const [key, spec] of Object.entries(playbook.entities || {})) {
    if (typeof spec === 'string' || typeof spec === 'number') continue;
    assert.ok(spec && typeof spec === 'object', `${label}: entity ${key} is neither a literal nor an object`);
    for (const k of Object.keys(spec)) {
      assert.ok(ALLOW.entity.has(k), `${label}: entity ${key} uses "${k}", which cc-emit cannot resolve`);
    }
  }
  for (const [key, b] of Object.entries(playbook.bindings || {})) {
    for (const k of Object.keys(b)) {
      assert.ok(ALLOW.binding.has(k), `${label}: binding ${key} uses "${k}"`);
    }
  }
  for (const k of Object.keys(playbook.rhythm || {})) {
    assert.ok(ALLOW.rhythm.has(k), `${label}: rhythm uses "${k}"`);
  }
  for (const [i, step] of (playbook.steps || []).entries()) {
    for (const k of Object.keys(step)) {
      assert.ok(ALLOW.step.has(k), `${label}: step ${i} uses "${k}", which cc-emit ignores`);
    }
    for (const k of Object.keys(step.source || {})) {
      assert.ok(ALLOW.source.has(k), `${label}: step ${i} source uses "${k}"`);
    }
    for (const tpl of step.templates || []) {
      for (const k of Object.keys(tpl || {})) {
        assert.ok(ALLOW.template.has(k), `${label}: step ${i} template uses "${k}"`);
      }
    }
  }
}

test('§5 a compiled playbook uses no cc-emit feature outside the baked allowlist', () => {
  for (const c of CASES) {
    checkAllowed(`${c.label} floor`, c.out.floor);
    checkAllowed(`${c.label} attack`, c.out.attack);
  }
});

test('§5 every {{token}} a compiled playbook writes is an entity, a pool or a builtin', () => {
  // The failure this catches is not an exception: cc-emit leaves an unresolvable
  // token INTACT rather than writing "undefined", so it reaches Kibana as
  // literal braces — precisely the "{clientIP}" tell log-generator ships and
  // this emitter exists not to reproduce.
  for (const c of CASES) {
    for (const [label, pb] of [[`${c.label} floor`, c.out.floor], [`${c.label} attack`, c.out.attack]]) {
      const known = new Set([
        ...Object.keys(pb.entities || {}),
        ...Object.keys(pb.pools || {}),
        ...Object.keys(pb.bindings || {}),
        ...BUILTIN_TOKENS,
      ]);
      const blob = JSON.stringify(pb.steps) + JSON.stringify(pb.pools);
      let m = TOKEN_RE.exec(blob);
      while (m) {
        assert.ok(known.has(m[1]), `${label}: {{${m[1]}}} resolves to nothing`);
        m = TOKEN_RE.exec(blob);
      }
      TOKEN_RE.lastIndex = 0;
    }
  }
});

// ===========================================================================
// §6  THE ATTACK LIVES INSIDE THE FLOOR
// ===========================================================================

test('§6 every attack source.host is drawn from a pool the floor also declares', () => {
  for (const c of CASES) {
    const floorPools = new Set(Object.keys(c.out.floor.pools));
    for (const name of Object.keys(c.out.attack.pools)) {
      assert.ok(floorPools.has(name),
        `${c.label}: the attack declares pool "${name}" that the floor does not — `
        + 'anything drawn from it can only ever occur during the attack');
      assert.deepStrictEqual(c.out.attack.pools[name], c.out.floor.pools[name],
        `${c.label}: attack pool "${name}" has drifted from the floor's`);
    }

    const floorHosts = new Set();
    for (const name of C.HOST_POOLS) for (const h of c.out.floor.pools[name] || []) floorHosts.add(h);
    for (const step of c.out.attack.steps) {
      const host = String(step.source.host);
      const m = /^\{\{([a-zA-Z0-9_]+)\}\}$/.exec(host);
      assert.ok(m, `${c.label}: attack source.host "${host}" is a literal, not a pool or entity token`);
      const entity = c.out.attack.entities[m[1]];
      if (entity !== undefined) {
        assert.ok(floorHosts.has(String(entity)),
          `${c.label}: attack targets ${entity}, which the floor never emits`);
      } else {
        assert.ok(Array.isArray(c.out.attack.pools[m[1]]),
          `${c.label}: attack source.host {{${m[1]}}} is neither an entity nor a pool`);
      }
    }
  }
});

test('§6 every attack host actually appears in the planned benign traffic', () => {
  // The structural check above is necessary and not sufficient: a host at the
  // tail of a `skewed` pool can be declared and still be drawn so rarely that
  // ordinary traffic never mentions it in a whole cycle. This is the empirical
  // half.
  for (const c of CASES) {
    const benign = new Set(c.floorPlan.events.map((e) => e.source.host));
    for (const ev of c.attackPlan.events) {
      assert.ok(benign.has(ev.source.host),
        `${c.label}: ${ev.source.host} is attacked but never appears in a benign cycle`);
    }
  }
});

// ===========================================================================
// §7  THE KEY DESCRIBES THE RUN THE GUEST WILL ACTUALLY MAKE
// ===========================================================================

test('§7 answerKey.totals.events is the number of events the guest writes', () => {
  for (const c of CASES) {
    const plan = emit.planTimeline(c.out.attack, {
      rng: emit.makeRng(emit.seedFrom(RUN_ID)),
      requested: c.out.attack.nominal_seconds,
    });
    assert.strictEqual(c.out.answerKey.totals.events, plan.events.length,
      `${c.label}: the key counts a different run than the guest will emit`);
  }
});

test('§7 the key holds every technique the scenario named, in kill-chain order', () => {
  for (const c of CASES) {
    const compiled = new Set(c.out.attack.steps.map((s) => s.technique));
    for (const t of c.out.answerKey.techniques) {
      assert.ok(compiled.has(t.id), `${c.label}: key lists ${t.id}, which no step emits`);
    }
    assert.strictEqual(c.out.answerKey.totals.techniques, c.out.answerKey.techniques.length);
    const offsets = c.out.answerKey.timeline.map((t) => t.offset_s);
    assert.deepStrictEqual(offsets, offsets.slice().sort((a, b) => a - b),
      `${c.label}: the timeline is not in the order it happens`);
  }
});

test('§7 the scenario half of the key is the part only the compiler knows', () => {
  const c = CASES[0];
  const key = c.out.answerKey.scenario;
  assert.strictEqual(key.scenario_id, 'TS-001');
  assert.strictEqual(key.steps.length, c.fixture.scenario.attack_path.length);
  for (const s of key.steps) {
    assert.ok(s.detection_opportunity, 'the key must carry the detection opportunity');
    assert.ok(s.action, 'the key must carry the action');
    assert.ok(s.target, 'the key must name the victim it resolved');
  }
});

test('§7 the run id is the seed and is not defaultable', () => {
  // The same refusal answer-key.js makes. A playbook compiled from '' describes
  // an intrusion no lane runs, and every symptom of that lands in a student's
  // grade rather than in a log.
  assert.throws(
    () => C.compileScenario({ scenario: HEALTHCARE.scenario, assets: HEALTHCARE.assets, options: {} }),
    /runId is the seed/
  );
});

// ===========================================================================
// §8  RECOMPILATION IS BYTE-IDENTICAL
// ===========================================================================

test('§8 the same (scenario, runId, requested) compiles byte-identically twice', () => {
  // Thirty lanes must see ONE exercise, not thirty, and a lane retried an hour
  // later has to match the twenty-nine that did not fail. An instructor saying
  // "there are 470 events, find them" has to be right on all of them.
  for (const fixture of [HEALTHCARE, NONPROFIT]) {
    const opts = { options: { requestedSeconds: 1800 } };
    const a = JSON.stringify(compile(fixture, opts));
    const b = JSON.stringify(compile(fixture, opts));
    assert.strictEqual(a, b);
  }
});

test('§8 a different run id compiles a different exercise', () => {
  // The run id reaches the exercise TWICE, and both halves are checked because
  // either one alone would be a semester of identical hunts.
  //
  //   compile time  which of a tactic's variants narrates the phase — a
  //                 credential-access step that is always sshd is one exercise
  //                 repeated, whatever the addresses say
  //   plan time     cc-emit resolves `oneOf` off the same seed, so the
  //                 adversary's address and the account they used differ
  //
  // The compiled ENTITIES are deliberately identical across run ids: a named
  // victim is a fact about the client's scenario, not about the run.
  const otherId = '99999999-8888-7777-6666-555555555555';
  const a = compile(HEALTHCARE);
  const b = compile(HEALTHCARE, { options: { runId: otherId } });
  assert.notStrictEqual(JSON.stringify(a.attack.steps), JSON.stringify(b.attack.steps),
    'two run ids narrated the identical phases — the seed is not reaching variant selection');

  const ra = emit.resolveEntities(a.attack, emit.makeRng(emit.seedFrom(RUN_ID)));
  const rb = emit.resolveEntities(b.attack, emit.makeRng(emit.seedFrom(otherId)));
  assert.notStrictEqual(ra.source_ip, rb.source_ip,
    'two run ids resolved the same adversary address');
});

// ===========================================================================
// §9  THE ANSWER NEVER REACHES THE WIRE
// ===========================================================================

test('§9 detection_opportunity appears in neither compiled playbook', () => {
  // detection_opportunity is LITERALLY the finding the student is graded on
  // discovering. A message built from it turns a hunt into reading, and it
  // would review as completely fine: the run works, the events land, the field
  // names are right.
  for (const c of CASES) {
    const blob = JSON.stringify({ floor: c.out.floor, attack: c.out.attack }).toLowerCase();
    for (const s of c.fixture.scenario.attack_path) {
      assert.ok(!blob.includes(s.detection_opportunity.toLowerCase()),
        `${c.label}: step ${s.step}'s detection_opportunity reached a playbook`);
      assert.ok(!blob.includes(s.action.toLowerCase()),
        `${c.label}: step ${s.step}'s action reached a playbook`);
    }
    // The scenario's own TITLE is the same problem one level up: the playbook is
    // staged inside the guest, and "Ransomware via phished billing credentials"
    // on the sensor's disk is the answer with a filename on it.
    assert.ok(!blob.includes(c.fixture.scenario.name.toLowerCase()),
      `${c.label}: the scenario title reached a playbook`);
  }
});

test('§9 the guard fires rather than trusting the code above it', () => {
  // A compiler that grows a "helpful" narrative field must fail LOUDLY here.
  // Fed a scenario whose detection_opportunity is a string the templates really
  // do emit, the guard has to notice.
  const leaky = JSON.parse(JSON.stringify(HEALTHCARE.scenario));
  leaky.attack_path[0].detection_opportunity =
    'pam_unix(sshd:session): session opened for user';
  assert.throws(
    () => C.compileScenario({
      scenario: leaky,
      assets: HEALTHCARE.assets,
      options: { runId: RUN_ID, laneIps: LANE_IPS, stakeholders: HEALTHCARE.stakeholders },
    }),
    /must never be on the wire/
  );
});

// ===========================================================================
// §10 HOST TELEMETRY IS CEDED TO SYSMON (E3b)
// ===========================================================================

test('§10 hostTelemetry drops Windows host steps from BOTH playbooks', () => {
  // With the GOAD ELK extension in the lane, Sysmon and winlogbeat already
  // report host activity on every Windows machine. A synthetic
  // source.type:'host' line about the same machine is the SAME EVENT narrated
  // twice by two schemas that disagree about everything — and
  // `_exists_: winlog.event_id` then separates real from synthetic in one
  // click, which is the oracle the whole two-playbook design removes.
  const out = compile(HEALTHCARE, { options: { hostTelemetry: true } });
  const windows = new Set(HEALTHCARE.assets.filter(C.isWindowsAsset).map((a) => a.hostname));
  assert.ok(windows.size >= 8, 'the healthcare fixture should be Windows-dominant');

  for (const [label, pb] of [['floor', out.floor], ['attack', out.attack]]) {
    const plan = H.planOf(pb, { label });
    for (const ev of plan.events) {
      if (ev.source.type !== 'host') continue;
      assert.ok(!windows.has(ev.source.host),
        `${label}: host telemetry for the Windows machine ${ev.source.host} is narrated twice`);
    }
    // Windows-only TOOLS are ceded outright rather than redirected: pointing
    // `registry` at the estate's one Linux box would put SetValue HKCU\... on a
    // machine with no registry, which is a worse artefact than the duplication.
    for (const step of pb.steps) {
      if (step.source.type !== 'host') continue;
      assert.ok(!C.WINDOWS_ONLY_HOST_TOOLS.has(step.source.name),
        `${label}: ${step.source.name} is Windows-only and should have been ceded`);
    }
  }
});

test('§10 without hostTelemetry the compiler narrates Windows host activity itself', () => {
  // The mirror image, and the reason §10 above is not vacuous: on a lane with
  // no Sysmon, host telemetry for a Windows machine is the ONLY host telemetry
  // there is, and dropping it would leave source.type:'host' absent from a
  // Windows estate entirely.
  const c = CASES[0];
  const windows = new Set(HEALTHCARE.assets.filter(C.isWindowsAsset).map((a) => a.hostname));
  const narrated = c.floorPlan.events.filter(
    (e) => e.source.type === 'host' && windows.has(e.source.host)
  );
  assert.ok(narrated.length > 0, 'a Windows estate with no Sysmon must still emit host events');
});

test('§10 a target the profile invented is treated as Windows while Sysmon is in the lane', () => {
  // The gap this closes. A scenario can name a host that is not in the asset
  // list — the profile generator is told not to and sometimes does anyway — and
  // the compiler then SAMPLES the victim. If an unresolvable target were
  // assumed non-Windows, a host-typed phase would be built and could land on a
  // machine winlogbeat is already narrating: the same duplication §10 exists to
  // prevent, arriving through the one door that is not a named asset.
  const invented = JSON.parse(JSON.stringify(HEALTHCARE.scenario));
  for (const s of invented.attack_path) s.target = `GHOST-${s.step}`;
  const out = compile(HEALTHCARE, { scenario: invented, options: { hostTelemetry: true } });
  const windows = new Set(HEALTHCARE.assets.filter(C.isWindowsAsset).map((a) => a.hostname));
  for (const [label, pb] of [['floor', out.floor], ['attack', out.attack]]) {
    for (const ev of H.planOf(pb, { label }).events) {
      if (ev.source.type !== 'host') continue;
      assert.ok(!windows.has(ev.source.host),
        `${label}: a sampled victim put host telemetry on the Windows machine ${ev.source.host}`);
    }
  }
  assert.ok(out.warnings.some((w) => w.code === C.WARNING_CODES.UNKNOWN_TARGET));
});

test('§10 ceding a phase is reported, never silent', () => {
  const out = compile(HEALTHCARE, { options: { hostTelemetry: true } });
  const codes = new Set(out.warnings.map((w) => w.code));
  assert.ok(codes.has(C.WARNING_CODES.HOST_TELEMETRY_CEDED),
    'a floor step was dropped and nothing said so');
  for (const w of out.warnings) {
    assert.ok(w.code && w.detail, 'a warning must carry both a code and a readable detail');
  }
});

// ===========================================================================
// §11 BUCKETS, FALLBACKS AND WARNINGS
// ===========================================================================

test('§11 every host pool is non-empty, on both fixtures', () => {
  // An empty pool is not a degraded exercise. samplePool returns null,
  // expandOnce leaves the token INTACT, and Kibana shows literal "{{dbpool}}".
  for (const c of CASES) {
    for (const name of C.HOST_POOLS) {
      assert.ok(Array.isArray(c.out.floor.pools[name]) && c.out.floor.pools[name].length,
        `${c.label}: ${name} is empty`);
    }
  }
});

test('§11 an estate with no servers falls back and SAYS so', () => {
  // intake-az-cyber-initiative.json has server_count "0". Every server-shaped
  // bucket therefore falls back to the whole estate, and an instructor has to be
  // able to see that the database step is happening on a laptop.
  const c = CASES[1];
  const codes = c.out.warnings.filter((w) => w.code === C.WARNING_CODES.EMPTY_BUCKET);
  assert.ok(codes.length >= 4, 'a server-less estate should report several bucket fallbacks');
  for (const w of codes) {
    assert.match(w.detail, /falling back to the whole estate/);
  }
});

test('§11 buckets are the client\'s machines, sorted with the scenario\'s targets first', () => {
  // srvpool, wspool and hosts are `skewed`: cc-emit reads them roughly
  // most-common-first with a long tail. A victim parked at the tail is a machine
  // ordinary traffic barely touches, which is a tell in itself — and, worse, one
  // that can make §6's empirical check flap.
  const { buckets } = C.bucketAssets(HEALTHCARE.assets, {
    priority: new Set(['file01', 'dc01']),
  });
  assert.ok(['FILE01', 'DC01'].includes(buckets.hosts[0]));
  assert.ok(buckets.fwpool.includes('FW-EDGE'), 'the firewall did not land in fwpool');
  assert.ok(buckets.dbpool.includes('SQL01'), 'the database did not land in dbpool');
  assert.ok(buckets.webpool.includes('WEB01'), 'the web server did not land in webpool');
  assert.ok(buckets.mailpool.includes('MAIL-RELAY'), 'the mail relay did not land in mailpool');
  assert.ok(buckets.authpool.includes('DC01'), 'the domain controller did not land in authpool');
  assert.ok(buckets.wspool.includes('BILLING-WS'), 'a workstation did not land in wspool');
  assert.ok(!buckets.wspool.includes('DC01'), 'a server landed in the workstation pool');
});

test('§11 lanips is the lane band plus the estate, and extips/dstips stay as baked', () => {
  const c = CASES[0];
  const baked = require(path.join(__dirname, '..', 'src', 'incident', 'playbooks', 'host-baseline.json'));
  for (const ip of LANE_IPS) {
    assert.ok(c.out.floor.pools.lanips.includes(ip), `lanips is missing the lane address ${ip}`);
  }
  assert.ok(c.out.floor.pools.lanips.includes('10.50.10.10'), 'lanips is missing an asset address');
  // Left alone on purpose: these two are what make 203/192/10 all ordinary
  // spaces, which is what stops "not one of ours" being a one-click filter.
  assert.deepStrictEqual(c.out.floor.pools.extips, baked.pools.extips);
  assert.deepStrictEqual(c.out.floor.pools.dstips, baked.pools.dstips);
});

test('§11 users is the client\'s people plus the service accounts every estate has', () => {
  const c = CASES[0];
  assert.ok(c.out.floor.pools.users.includes('dokafor'), 'a stakeholder is missing from users');
  assert.ok(c.out.floor.pools.users.includes('mtorres'), 'a derived account is missing from users');
  for (const svc of C.SERVICE_ACCOUNTS) {
    assert.ok(c.out.floor.pools.users.includes(svc), `service account ${svc} is missing`);
  }
});

test('§11 an unknown target is sampled from the nearest bucket and reported', () => {
  const odd = JSON.parse(JSON.stringify(HEALTHCARE.scenario));
  odd.attack_path[0].target = 'GHOST-01';
  const out = compile(HEALTHCARE, { scenario: odd });
  const w = out.warnings.find((x) => x.code === C.WARNING_CODES.UNKNOWN_TARGET);
  assert.ok(w && /GHOST-01/.test(w.detail), 'an unknown target was resolved silently');
  const hosts = new Set();
  for (const name of C.HOST_POOLS) for (const h of out.floor.pools[name]) hosts.add(h);
  for (const [k, v] of Object.entries(out.attack.entities)) {
    if (!/^target_/.test(k)) continue;
    assert.ok(hosts.has(String(v)), `${k} resolved to ${v}, which is not one of the client's hosts`);
  }
});

test('§11 an unmapped technique lands by kill-chain position and is reported', () => {
  const odd = {
    scenario_id: 'TS-X',
    name: 'Odd',
    attack_path: [
      { step: 1, action: 'a', target: 'WEB01', technique: 'T9999', detection_opportunity: 'x' },
      { step: 2, action: 'b', target: 'FILE01', technique: 't1486', detection_opportunity: 'z' },
    ],
  };
  const out = compile(HEALTHCARE, { scenario: odd });
  const w = out.warnings.find((x) => x.code === C.WARNING_CODES.UNMAPPED_TECHNIQUE);
  assert.ok(w && /T9999/.test(w.detail), 'an unmapped technique was placed silently');
  // Lowercase input is normalised, not fallen back on: three quarters of the
  // would-be fallbacks are just typing.
  assert.ok(out.attack.steps.some((s) => s.technique === 'T1486'),
    'a lowercase technique id should normalise to an exact hit');
});

test('§11 a step with no usable MITRE id is dropped, and a scenario of nothing but those refuses', () => {
  // A step with no technique carries no mitre tag, and the sensor's drop_event
  // processor keeps ONLY tagged events. Such a step would run, exit 0, report
  // lines>0 and put nothing in the index — a run that looks like a working
  // exercise and is not.
  const partly = {
    scenario_id: 'TS-Y',
    attack_path: [
      { step: 1, action: 'a', target: 'WEB01', technique: 'not-a-technique', detection_opportunity: 'x' },
      { step: 2, action: 'b', target: 'FILE01', technique: 'T1486', detection_opportunity: 'z' },
    ],
  };
  const out = compile(HEALTHCARE, { scenario: partly });
  assert.strictEqual(out.attack.steps.length, 1);
  assert.ok(out.warnings.some((w) => w.code === C.WARNING_CODES.UNPARSEABLE_TECHNIQUE));

  assert.throws(() => compile(HEALTHCARE, {
    scenario: { scenario_id: 'TS-Z', attack_path: [{ step: 1, technique: '???', target: 'WEB01' }] },
  }), /nothing to run/);
});

// ---------------------------------------------------------------------------
// Plumbing for §3/§4
// ---------------------------------------------------------------------------

/**
 * A compiled spray that actually contains the sshd burst.
 *
 * TA0006 offers three variants — sshd, a token service, and credential file
 * reads — and which one a run gets is a weighted draw off the run id. The three
 * helpers below measure the burst by its message, so the fixture has to be one
 * whose draw produced it. Searching a handful of run ids is deliberate: pinning
 * one magic id would make an unrelated edit to the templates fail here with a
 * message about nothing.
 */
function compileSprayWithBurst() {
  for (let i = 0; i < 24; i += 1) {
    const runId = `aaaaaaaa-bbbb-cccc-dddd-${String(i).padStart(12, '0')}`;
    const out = compile(HEALTHCARE, { scenario: SPRAY, options: { runId } });
    const hasBurst = out.attack.steps.some((s) => (s.templates || [])
      .some((t) => /^Failed password/.test(String(t.message))));
    if (hasBurst) return { out, runId };
  }
  assert.fail('no run id in 24 produced the sshd brute-force variant for a T1110 scenario');
  return null;
}
