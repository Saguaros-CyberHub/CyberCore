/**
 * challenge-rebuild-contract.test.js -- rebuildLaneChallengeVms vs its callees.
 *
 * WHY THIS FILE EXISTS
 * rebuildLaneChallengeVms rebuilds SOME machines inside a live environment lane
 * while the rest keep running. It shipped having never successfully executed, and
 * failed twice in production for two unrelated reasons:
 *
 *   1. All four of its SQL statements were truncated to their first line
 *      (`UPDATE cybercore_lane` with no SET or WHERE). Covered by
 *      test/sql-statement-complete.test.js.
 *
 *   2. It called resolveVnets(), which returns { resolved, missing }, but indexed
 *      the WRAPPER by vxlan id -- always undefined. So every rebuild died with
 *      "No SDN VNet for VXLAN <id> - a rebuilt machine would be cabled to
 *      nothing", naming a real and healthy VNet. It then read `.ext` / `.int` off
 *      that entry, where the real shape is { vnet, vnetInt } and each of those is
 *      a Proxmox VNet OBJECT whose `.vnet` property is the name. Three defects,
 *      one wrong assumption about a return shape.
 *
 * The general rule this pins: for every helper the rebuild path shares with the
 * DEPLOY path, the two must consume it the same way. The deploy path
 * (deployChallengeLanesInner / deployLaneVms) is the reference implementation --
 * it runs in production every time a class is deployed, so where the two differ,
 * the rebuild path is what is wrong.
 *
 * Source assertions: exercising the real function needs Proxmox, a gateway over
 * SSH and a live lane. The contracts worth pinning are visible in the text.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SRC_PATH = path.join(__dirname, '..', 'src', 'utils', 'challenge-lane-deployer.js');
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
// LF-normalised: git checks this out as CRLF on Windows, and every brace-match
// below would stop matching without saying why.
const src = fs.readFileSync(SRC_PATH, 'utf8').split(CRLF).join(LF);

/**
 * Extract a function body by brace-matching.
 *
 * The parameter list has to be skipped by PAREN matching first. Every function
 * here destructures its arguments -- `async function f({ a, b }) {` -- so
 * jumping to the first `{` after the name lands on the parameter object and the
 * depth count closes at the end of the SIGNATURE. The extract is then three
 * lines long and every assertion against it fails for a reason that has nothing
 * to do with the code under test.
 */
function extractFn(name) {
  const start = src.indexOf(`async function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found -- renamed?`);

  let i = src.indexOf('(', start);
  let depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')' && --depth === 0) break;
  }

  const bodyStart = src.indexOf('{', i);
  depth = 0;
  let j = bodyStart;
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) break;
  }
  const out = src.slice(start, j + 1);
  // A body that short means the paren skip failed and we are looking at a
  // signature again -- fail loudly rather than assert against nothing.
  assert.ok(out.length > 200, `${name} extracted only ${out.length} chars -- extractFn is broken`);
  return out;
}

const REBUILD = extractFn('rebuildLaneChallengeVms');
const DEPLOY_INNER = extractFn('deployChallengeLanesInner');
const DEPLOY_VMS = extractFn('deployLaneVms');
const RESOLVE_VNETS = extractFn('resolveVnets');

// -- the contract that broke --------------------------------------------------

test('resolveVnets still returns the wrapper this file assumes', () => {
  // If it is ever flattened to a bare map, every assertion below is wrong and
  // the call sites are right -- so pin the callee first.
  assert.ok(/return \{ resolved, missing \}/.test(RESOLVE_VNETS),
    'resolveVnets must return { resolved, missing }');
  assert.ok(/resolved\[vxlanId\] = \{ vnet, vnetInt \}/.test(RESOLVE_VNETS),
    'each entry must be { vnet, vnetInt }');
});

test('THE BUG: the rebuild path reads VNets out of .resolved, not the wrapper', () => {
  assert.ok(/resolved: vnetsByVxlan/.test(REBUILD),
    'rebuild must destructure { resolved } -- indexing the wrapper is always undefined');
  assert.ok(!/=\s*vnets\[lane\.vxlan_id\]/.test(REBUILD),
    'indexing the resolveVnets return value directly by vxlan id is the original bug');
});

test('both paths destructure resolveVnets the same way', () => {
  // The deploy path is the reference: it runs on every class deploy.
  for (const [name, fn] of [['deploy', DEPLOY_INNER], ['rebuild', REBUILD]]) {
    assert.ok(/resolved:\s*\w+/.test(fn) && /missing/.test(fn),
      `${name} path must take both { resolved, missing } from resolveVnets`);
  }
});

test('a VNet entry is unwrapped to its NAME the same way in both paths', () => {
  // entry.vnet is the Proxmox VNet object; entry.vnet.vnet is the name string.
  // Passing the object where a name is expected cables the clone to "[object Object]".
  assert.ok(/const vnetExtName = vnetPair\.vnet\.vnet;/.test(REBUILD),
    'rebuild must reach through the VNet object to its .vnet name');
  assert.ok(/const vnetIntName = isV3 \? vnetPair\.vnetInt\.vnet : vnetExtName;/.test(REBUILD),
    'the v3 internal VNet name comes from vnetInt, not from a .int key that does not exist');
  assert.ok(!/vnetPair\.(ext|int)\b/.test(REBUILD),
    'resolveVnets entries have no .ext / .int keys -- that was the wrong assumption');
  // And the deploy path, which works, does the same unwrap.
  assert.ok(/vnetExtName\s*=\s*vnet\.vnet;/.test(DEPLOY_VMS),
    'deploy path reference: the name is <vnetObject>.vnet');
});

test('a missing VNet reports WHY, not just that it is missing', () => {
  // resolveVnets already distinguishes "no VNet at all" from "v3 lane missing
  // only its internal VNet" -- those need different fixes, and the original
  // message named neither while also being wrong about the cause.
  assert.ok(/vnetsMissing\.find\(/.test(REBUILD),
    'the failure path should surface the reason resolveVnets recorded');
});

// -- the ctx handed to cloneChallengeVm --------------------------------------

test('the rebuild ctx carries every field cloneChallengeVm destructures', () => {
  // cloneChallengeVm reads these straight out of ctx. A missing one is undefined
  // at clone time: a missing cloneSem throws on .run, a missing templateNodeByVmid
  // sends the clone to the wrong node, a missing subnetScheme changes NIC
  // derivation. None of them announce themselves.
  const clone = extractFn('cloneChallengeVm');
  const destructured = clone.slice(0, clone.indexOf('\n\n'));
  const m = destructured.match(/const \{([^}]*)\} = ctx;/);
  assert.ok(m, 'cloneChallengeVm should destructure ctx in one statement');

  const fields = m[1].split(',').map((f) => f.trim().split(':')[0].trim()).filter(Boolean);
  assert.ok(fields.length > 3, `only found ${fields.length} ctx fields -- the parse is wrong`);

  const ctxLiteral = REBUILD.slice(REBUILD.indexOf('const ctx = {'));
  const body = ctxLiteral.slice(0, ctxLiteral.indexOf('};') + 2);
  const missing = fields.filter((f) => !new RegExp(`\\b${f}\\b`).test(body));
  assert.deepStrictEqual(missing, [],
    `the rebuild ctx omits field(s) cloneChallengeVm reads: ${missing.join(', ')}`);
});

// -- the console rules the rebuild must not break ----------------------------

test('the rebuild does NOT touch the console DNAT', () => {
  // Counter-intuitive, and correct. A rebuilt machine returns to the SAME
  // address: its MAC is derived from (octet, vxlanId), the console plan is
  // recomputed from the FULL machine list so octets do not shift, and the
  // reservation file is re-rendered whole-lane. The gateway's existing
  // wan0:<port> -> <ip>:<port> rules therefore still point at it, and they
  // survive a reboot via /etc/iptables/rules-save.
  //
  // Calling installConsoleDnat here would be actively harmful: its strip is
  // `iptables-save | grep -v "LANE-CONSOLE"` -- a substring match over the whole
  // ruleset -- so a call carrying only the rebuilt machines would delete the
  // console rules of every machine the rebuild left running.
  //
  // If this ever legitimately needs to publish a console, it must pass the FULL
  // lane target list, which is what the second half of this assertion allows.
  const calls = (REBUILD.match(/installConsoleDnat\(/g) || []).length;
  assert.ok(calls === 0 || calls === 1,
    `installConsoleDnat is called ${calls} times -- never more than once per gateway`);
  if (calls === 0) return;
  assert.ok(/consoleTargets|allConsoles|fullTargets/.test(REBUILD),
    'if the rebuild publishes DNAT at all it must pass the whole lane, not just the rebuilt machines');
});

test('the console plan is recomputed from the FULL machine list', () => {
  // This is what keeps addresses stable across a rebuild, and so what makes
  // skipping the DNAT above safe. Recomputing from only the requested machines
  // would renumber the survivors and silently point every existing rule and
  // Guacamole connection at the wrong box.
  // Scoped to the CALL, not a fixed window after it: a 400-char slice runs past
  // the call into the reservation loop, which legitimately mentions `wanted`.
  const at = REBUILD.indexOf('resolveConsolePlan({');
  assert.notStrictEqual(at, -1, 'the rebuild must compute a console plan');
  const plan = REBUILD.slice(at, REBUILD.indexOf('});', at) + 3);

  assert.ok(/\bspecVms\b/.test(plan),
    'the plan must be built from specVms (every machine), not from the rebuild subset');
  assert.ok(!/\bwanted\b/.test(plan),
    'building the console plan from `wanted` would renumber the machines left running');
});

test('the rebuild writes reservations through the shared installer', () => {
  // Not a bare push+restart: the gateway template bakes `dhcp-host=kali,<ext>.50`,
  // and dnsmasq refuses to start when two dhcp-host lines claim one address --
  // which takes DHCP down for the WHOLE lane while it still reports active.
  assert.ok(/writeLaneReservations\(/.test(REBUILD),
    'the rebuild must go through writeLaneReservations, which neutralises the baked entry');
});

// -- lane state ---------------------------------------------------------------

test('the lane returns to active even on partial failure', () => {
  // The gateway is up with the untouched machines behind it. Parking the row at
  // 'error' would release its VXLAN and WAN address while both are still in use.
  const writeBack = REBUILD.slice(REBUILD.indexOf('UPDATE cybercore_lane l'));
  assert.ok(/status = 'active'/.test(writeBack.slice(0, 1600)),
    'the write-back must restore status to active');
});

test('untouched machines are spliced by name, not overwritten wholesale', () => {
  // Their vm_id is the only handle teardown has on them. Dropping a record
  // orphans a running VM that nothing can destroy.
  const writeBack = REBUILD.slice(REBUILD.indexOf('UPDATE cybercore_lane l'));
  assert.ok(/NOT \(\(e->>'name'\) = ANY\(\$3::text\[\]\)\)/.test(writeBack.slice(0, 1600)),
    'records whose name was NOT rebuilt must be carried through verbatim');
});
