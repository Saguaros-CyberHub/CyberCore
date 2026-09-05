/**
 * goad-lane-reservations.test.js — the lane's DHCP table has TWO writers, and
 * for a while the second one deleted the first one's work.
 *
 * THE BUG, found on a live GOAD lane. challenge-lane-deployer.js renders
 * /etc/dnsmasq.d/lane-reservations.conf whole-lane before any guest boots: Kali
 * on the external .50, an extension host such as elk on .24, the consoles, the
 * GOAD roster, and every host-record the lane resolves by name. Then the GOAD
 * controller ran /opt/goad-light/prep.sh, which pushed ITS reservations into
 * that same path with a plain `cat >` — a truncating overwrite — leaving only
 * prep.sh's HOST_MAP: the GOAD roster, the controller, and Kali only when
 * spec.goad.include_kali is not false, which is a different switch from the
 * attack box the deploy clones. The observed lane came up with Kali on a pool
 * lease at .53 while the gateway's baked wan0:3389 DNAT still pointed at .50 —
 * a student console connected to nothing — and elk holding .24 only until its
 * next renewal, with winlogbeat on every Windows host aimed at <subnet>.24:9200.
 *
 * Two fixes, because they cover different lanes, and this file pins both:
 *
 *   1. BAKE SIDE (permanent). prep.sh writes goad-lane-reservations.conf, its
 *      own file. dnsmasq reads every *.conf in /etc/dnsmasq.d, so the two sets
 *      coexist — but it also REFUSES TO START when two dhcp-host lines claim one
 *      address, and the orchestrator's table is a superset of prep.sh's on a
 *      challenge lane. So the gateway half also drops any reservation another
 *      file already serves. Getting that wrong is not cosmetic: a dnsmasq that
 *      will not start leaves every machine on the lane without an address while
 *      the deploy still reports success.
 *
 *   2. ORCHESTRATOR SIDE (protects lanes cloned from a controller baked before
 *      the split). The deploy re-writes the same table after the GOAD block and
 *      before Kali is started.
 *
 * Run: cd front-end && node --test test/goad-lane-reservations.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const UTILS = path.join(ROOT, 'src', 'utils');
const REPO = path.join(ROOT, '..');
const BAKE_REL = 'infrastructure/proxmox-templates/vm-templates/bake-goad-controller-vm.sh';
const BAKE = path.join(REPO, BAKE_REL);

// Built, never typed: this file writes shell text and compares against shell
// text, and a backslash escape that survives one round of quoting too many is
// how this repo has broken before.
const BS = String.fromCharCode(92);
const LF = String.fromCharCode(10);
const CRLF = String.fromCharCode(13, 10);

// challenge-lane-deployer pulls site-config at module load (via batch-deployer),
// which reads a gitignored config/site.json. Same stub ciab-lane-dns.test.js uses.
require.cache[require.resolve(path.join(UTILS, 'site-config.js'))] = {
  id: 'site-config', filename: 'site-config', loaded: true,
  exports: {
    getSchedulingConfig: () => ({
      min_free_mem_gb: 8, min_free_disk_gb: 20,
      max_concurrent_lanes: 5, max_concurrent_clones: 4,
      node_score_weights: { cpu: 0.35, mem: 0.55, disk: 0.10 },
    }),
    getDefaultTemplateNode: () => 'node-1',
  },
};
// hostRecordLine bakes LANE_DNS_DOMAIN at module load, so pin it before the
// require or the expected host-record strings depend on the machine.
process.env.LANE_DNS_DOMAIN = 'cybercore.lan';

const laneDeployer = require(path.join(UTILS, 'lane-deployer.js'));
const goadDeploy = require(path.join(UTILS, 'goad-deploy.js'));
const { writeLaneReservations } = require(path.join(UTILS, 'challenge-lane-deployer.js'));

// LF-normalised: git checks these out as CRLF on Windows, and every slice below
// would stop matching without saying why.
const bake = fs.readFileSync(BAKE, 'utf8').split(CRLF).join(LF);
const deployerSrc = fs.readFileSync(path.join(UTILS, 'challenge-lane-deployer.js'), 'utf8')
  .split(CRLF).join(LF);

// ════════════════════════════════════════════════════════════════════════════
// 1. THE BAKE SIDE — prep.sh's redirect target
// ════════════════════════════════════════════════════════════════════════════

/** One `- path: <p>` write_files entry, from its header to the next entry. */
function writeFileBlock(p) {
  const header = `  - path: ${p}${LF}`;
  const at = bake.indexOf(header);
  assert.notStrictEqual(at, -1, `${BAKE_REL} no longer writes ${p} via cloud-init write_files`);
  const rest = bake.slice(at + header.length);
  const next = rest.search(new RegExp(`${LF} {2}- path: `));
  return next === -1 ? rest : rest.slice(0, next);
}

/**
 * The `content: |` block-scalar lines of one write_files entry, still carrying
 * the bake's six spaces and its escaping.
 *
 * Stops at the first non-blank line that is NOT indented six spaces, because
 * that is exactly where YAML stops: the entry is followed by prose comments at
 * two spaces, and swallowing them would let an assertion about prep.sh be
 * satisfied by a sentence about something else.
 */
function blockScalar(p) {
  const lines = writeFileBlock(p).split(LF);
  const at = lines.findIndex((l) => /^ {4}content: \|\s*$/.test(l));
  assert.notStrictEqual(at, -1, `${p} is no longer written as a content block scalar`);
  const body = [];
  for (const line of lines.slice(at + 1)) {
    if (line.trim() === '') { body.push(line); continue; }
    if (!line.startsWith('      ')) break;
    body.push(line);
  }
  return body;
}

const prepBody = blockScalar('/opt/goad-light/prep.sh');

/**
 * prep.sh as the LANE sees it: dedented by its six spaces, with the outer
 * heredoc's escaping undone. Everything below asserts against this rather than
 * the bake source, because `\$OURS` in the source and `$OURS` on the lane are
 * the same variable and only one of them ever runs.
 */
const prepSh = prepBody
  .map((l) => (l.startsWith('      ') ? l.slice(6) : l))
  .join(LF)
  .split(BS + '$').join('$');

test('THE REGRESSION: prep.sh does not write the orchestrator\'s reservations file', () => {
  // This is the whole bug in one assertion. `cat > /etc/dnsmasq.d/lane-reservations.conf`
  // truncates the file challenge-lane-deployer.js renders whole-lane, so every
  // machine the GOAD controller has never heard of — Kali, elk, the consoles —
  // loses its reservation and every host-record goes with them. Nothing logs it:
  // the lane still reports active and the guests still boot, onto pool leases.
  assert.ok(!prepSh.includes('/etc/dnsmasq.d/lane-reservations.conf'),
    'prep.sh must never name /etc/dnsmasq.d/lane-reservations.conf — that file belongs to '
    + 'challenge-lane-deployer.js and prep.sh only ever knows the GOAD roster');
  assert.ok(prepSh.includes('/etc/dnsmasq.d/goad-lane-reservations.conf'),
    'prep.sh must write its own drop-in, /etc/dnsmasq.d/goad-lane-reservations.conf');
});

test('prep.sh still wipes the leases', () => {
  // The reservations are useless on their own: a Windows VM that already took a
  // pool address keeps it across a renewal, so the wipe is what forces every
  // guest back to a DHCPREQUEST the reservation can answer.
  assert.ok(/: > \/var\/lib\/misc\/dnsmasq\.leases/.test(prepSh),
    'prep.sh must still clear /var/lib/misc/dnsmasq.leases before restarting dnsmasq');
});

test('every $ in prep.sh is escaped for the outer heredoc', () => {
  // The same rule ciab-controller-contract.test.js pins for run.sh and
  // extract-lab.sh, extended here because the gateway half is now a nested
  // heredoc carrying thirty of them. An unescaped $ is expanded by the BAKE's
  // shell — almost always to the empty string, since these are variables the
  // Proxmox node has never heard of — so the lane runs `cat > ""` and the
  // failure is a script with a hole in it that nothing reports.
  const offenders = [];
  prepBody.forEach((line, i) => {
    for (let p = 0; p < line.length; p += 1) {
      if (line[p] !== '$') continue;
      let n = 0;
      for (let j = p - 1; j >= 0 && line[j] === BS; j -= 1) n += 1;
      if (n % 2 === 0) { offenders.push(`prep.sh+${i + 1}: ${line.trim()}`); break; }
    }
  });
  assert.deepStrictEqual(offenders, [],
    'unescaped $ inside the prep.sh write_files body is expanded at BAKE time:' + LF
    + offenders.join(LF));
});

test('the prep.sh block scalar runs to the end of the script', () => {
  // `bash -n` on the bake sees NOTHING inside the cloud-init heredoc, so a line
  // that loses its indent ends the YAML block scalar early: cloud-init cannot
  // parse the user-data at all, runs nothing, and the image is written
  // untouched. The symptom is "bake did not complete" 25 minutes later, naming
  // nothing. blockScalar() stops where YAML would, so a truncated script shows
  // up here as a missing last line.
  //
  // The gateway heredoc is exactly the shape that invites the slip: its
  // terminator has to sit at the block's six-space indent so that it lands at
  // column 0 in the file cloud-init writes — at column 0 in the BAKE it would
  // instead end the block scalar and take the rest of the script with it.
  const last = [...prepBody].reverse().find((l) => l.trim() !== '');
  assert.strictEqual(last, '      echo "[prep.sh] Reservations applied."',
    'the block scalar no longer reaches prep.sh\'s last line — something above it lost its indent');
  assert.ok(prepBody.includes('      GWSCRIPT'),
    'the gateway heredoc terminator must sit at the block indent, not at column 0');
});

// ════════════════════════════════════════════════════════════════════════════
// 2. THE BAKE SIDE — the gateway half actually refuses to double-claim
// ════════════════════════════════════════════════════════════════════════════
//
// Executed, not read: the consequence of getting this wrong is that dnsmasq
// refuses to start, which takes DHCP down for the whole lane, and no source-text
// assertion can tell a filter that works from one that matches nothing.

/** The script prep.sh runs ON THE GATEWAY, lifted out of its heredoc. */
function gatewayScript() {
  const open = "<<'GWSCRIPT'" + LF;
  const at = prepSh.indexOf(open);
  assert.notStrictEqual(at, -1, 'prep.sh no longer sends the gateway a GWSCRIPT heredoc');
  const rest = prepSh.slice(at + open.length);
  const end = rest.indexOf(LF + 'GWSCRIPT' + LF);
  assert.ok(end > 0, 'the GWSCRIPT heredoc has no terminator');
  return rest.slice(0, end);
}

const gitBash = path.join(process.env.ProgramFiles || 'C:/Program Files', 'Git', 'bin', 'bash.exe');
const bash = process.platform === 'win32' && fs.existsSync(gitBash) ? gitBash : 'bash';
const hasBash = spawnSync(bash, ['-c', 'exit 0']).status === 0;

/**
 * Run the gateway script's file-building half against a fabricated
 * /etc/dnsmasq.d, and return the drop-in it produced.
 *
 * Only the half up to `cat "$OURS"` — everything after it restarts dnsmasq,
 * which no test machine has.
 */
function runGatewayFilter(dropins, candidate) {
  const sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'goad-resv-')).split(path.sep).join('/');
  fs.mkdirSync(path.join(sandbox, 'etc', 'dnsmasq.d'), { recursive: true });
  for (const [name, text] of Object.entries(dropins)) {
    fs.writeFileSync(path.join(sandbox, 'etc', name), text, 'utf8');
  }
  const body = gatewayScript();
  const marker = 'cat "$OURS"';
  const script = (body.slice(0, body.indexOf(marker)) + marker + LF)
    .split('/etc/dnsmasq').join(sandbox + '/etc/dnsmasq')
    .split('/tmp/goad-lane').join(sandbox + '/goad-lane');
  const file = path.join(sandbox, 'filter.sh');
  fs.writeFileSync(file, script, 'utf8');
  const run = spawnSync(bash, [file.split(path.sep).join('/')], { input: candidate, encoding: 'utf8' });
  assert.strictEqual(run.status, 0, `gateway script failed: ${run.stderr}`);
  fs.rmSync(sandbox, { recursive: true, force: true });
  return run.stdout.split(LF).filter((l) => l.startsWith('dhcp-host='));
}

const MAC_DC01 = '52:54:00:16:27:0a';
const MAC_KALI = '52:54:00:16:27:32';
const CANDIDATE = [
  '# GOAD lane DHCP reservations - written by /opt/goad-light/prep.sh',
  `dhcp-host=${MAC_DC01},10.39.16.10,DC01`,
  'dhcp-host=52:54:00:16:27:05,10.39.16.5,goad-controller',
  `dhcp-host=${MAC_KALI},10.39.16.50,kali`,
].join(LF) + LF;

test('the gateway half claims nothing the orchestrator already claims', (t) => {
  if (!hasBash) return t.skip('no bash on this machine');
  // A challenge lane: lane-reservations.conf is already installed and is a
  // SUPERSET of prep.sh's HOST_MAP. Writing ours blind would put a second
  // dhcp-host line on every one of those addresses, and dnsmasq dies on the
  // first duplicate — silently, because prep.sh's restart is best-effort.
  const live = runGatewayFilter({
    'dnsmasq.conf': `interface=lan0${LF}#dhcp-host=kali,10.39.16.50${LF}`,
    [path.join('dnsmasq.d', 'lane-reservations.conf')]: [
      '# Lane DHCP reservations — generated by challenge-lane-deployer.js',
      `dhcp-host=${MAC_KALI},10.39.16.50,kali`,
      'dhcp-host=52:54:00:16:27:18,10.39.16.24,elk',
      `dhcp-host=${MAC_DC01},10.39.16.10,DC01`,
      'dhcp-host=52:54:00:16:27:05,10.39.16.5,goad-controller',
      'host-record=elk.cybercore.lan,10.39.16.24',
    ].join(LF) + LF,
  }, CANDIDATE);
  assert.deepStrictEqual(live, [],
    'every candidate is already served by the orchestrator\'s file, so none may be re-claimed');
});

test('a baked reservation that is still live also blocks ours', (t) => {
  if (!hasBash) return t.skip('no bash on this machine');
  // The gateway's firstboot re-renders /etc/dnsmasq.conf on EVERY boot and
  // re-adds `dhcp-host=kali,<ext>.50`. installLaneReservations comments that out
  // when it writes the lane's file, but on a lane where it never ran the baked
  // line is live — and one hostname-matched line plus one MAC-matched line on
  // .50 is the same fatal duplicate.
  const live = runGatewayFilter({
    'dnsmasq.conf': `interface=lan0${LF}dhcp-host=kali,10.39.16.50${LF}`,
  }, CANDIDATE);
  assert.ok(!live.some((l) => l.includes('10.39.16.50')),
    'the address the baked line claims must not be claimed a second time');
  assert.strictEqual(live.length, 2, 'the other two reservations must still be written');
});

test('with no other writer, prep.sh still places the whole roster', (t) => {
  if (!hasBash) return t.skip('no bash on this machine');
  // The lanes prep.sh exists for: nobody else wrote reservations, so a filter
  // that dropped everything would silently restore the original symptom —
  // Windows hosts on pool leases and waitForWinRM polling the wrong addresses.
  const live = runGatewayFilter({
    'dnsmasq.conf': `interface=lan0${LF}`,
  }, CANDIDATE);
  assert.strictEqual(live.length, 3, 'all three reservations must be written');
  assert.ok(live.some((l) => l.endsWith(',kali')), 'including Kali');
});

// ════════════════════════════════════════════════════════════════════════════
// 3. THE ORCHESTRATOR SIDE — the re-write after GOAD
// ════════════════════════════════════════════════════════════════════════════

/** deployLaneVms' body, by brace-matching (the pattern challenge-rebuild-contract uses). */
function extractFn(name) {
  const start = deployerSrc.indexOf(`async function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found — renamed?`);
  let i = deployerSrc.indexOf('(', start);
  let depth = 0;
  for (; i < deployerSrc.length; i += 1) {
    if (deployerSrc[i] === '(') depth += 1;
    else if (deployerSrc[i] === ')' && (depth -= 1) === 0) break;
  }
  const bodyStart = deployerSrc.indexOf('{', i);
  depth = 0;
  let j = bodyStart;
  for (; j < deployerSrc.length; j += 1) {
    if (deployerSrc[j] === '{') depth += 1;
    else if (deployerSrc[j] === '}' && (depth -= 1) === 0) break;
  }
  const out = deployerSrc.slice(start, j + 1);
  assert.ok(out.length > 200, `${name} extracted only ${out.length} chars — extractFn is broken`);
  return out;
}

const DEPLOY_VMS = extractFn('deployLaneVms');

test('the reservations are re-written after GOAD and before Kali is started', () => {
  // Ordering IS the fix. prep.sh runs inside deployGoadLane; Kali is started in
  // the console phase after it. A re-write placed before the GOAD block, or
  // after Kali has already asked for an address, restores the file too late to
  // stop the attack box taking a pool lease (.53, observed).
  const calls = [...DEPLOY_VMS.matchAll(/await writeReservations\(\);/g)].map((m) => m.index);
  assert.strictEqual(calls.length, 2,
    'exactly two writes: once before any guest boots, once after the GOAD block');
  const goadAt = DEPLOY_VMS.indexOf('goadDeploy.deployGoadLane({');
  const kaliAt = DEPLOY_VMS.indexOf("setStatus('configuring_kali')");
  assert.ok(goadAt > 0 && kaliAt > 0, 'the GOAD and Kali phases must still be findable');
  assert.ok(calls[0] < goadAt, 'the first write must precede GOAD provisioning');
  assert.ok(calls[1] > goadAt, 'the second write must follow GOAD provisioning (prep.sh runs there)');
  assert.ok(calls[1] < kaliAt, 'and must land before the attack box is started');
});

test('the re-write is skipped on a pre-baked lane, which has no prep.sh', () => {
  // A golden-image lane runs no controller at all, so there is nothing to undo
  // and the second SSH round trip plus dnsmasq restart would be pure cost.
  const at = DEPLOY_VMS.lastIndexOf('await writeReservations();');
  const guard = DEPLOY_VMS.slice(DEPLOY_VMS.lastIndexOf('if (', at), at);
  assert.match(guard, /!spec\.goad\?\.prebaked/,
    'the post-GOAD re-write must be gated on the live (non-prebaked) GOAD path');
});

test('both writes carry the SAME attackBoxOctet, by construction', () => {
  // The one that mattered: Kali's reservation is what the gateway's baked
  // wan0:3389 DNAT is aimed at, so a second write that computed a different
  // octet — or omitted it — would reintroduce the bug through the back door.
  // There is exactly ONE argument list in this function and both writes go
  // through it, which is the strongest form of "the same": identity.
  const literals = [...DEPLOY_VMS.matchAll(/await writeLaneReservations\(\{/g)];
  assert.strictEqual(literals.length, 1,
    'deployLaneVms must build the reservation arguments in ONE place — a second '
    + 'argument list is how the two writes drift apart');
  assert.strictEqual((DEPLOY_VMS.match(/attackBoxOctet:/g) || []).length, 1,
    'and therefore exactly one attackBoxOctet expression');

  // Evaluated, not read: `attackBoxVmId ? …Kali : null` is an expression, and
  // an expression that is wrong reads exactly like one that is right.
  const from = literals[0].index + literals[0][0].length;
  const body = DEPLOY_VMS.slice(from, DEPLOY_VMS.indexOf('});', from));
  const build = new Function(
    'gatewayVmId', 'targetNode', 'vxlanId', 'goadMacs', 'attackBoxVmId', 'goadDeploy',
    'reservationOctets', 'pinnedHosts', 'dnsRecords', 'spec', 'subnetScheme',
    'laneSubnetBase', 'goadSubnetBase', 'laneId', 'logTag',
    `return {${body}};`);
  const call = (attackBoxVmId) => build(
    5001, 'node-1', 16, {}, attackBoxVmId, goadDeploy,
    {}, [], [], { goad: { enabled: true } }, 'v2',
    '10.39.16', '10.39.16', 'lane-1', '[test]');

  assert.strictEqual(call(9016).attackBoxOctet, goadDeploy.INFRA_IP_OCTETS.Kali,
    'a lane with an attack box must reserve Kali\'s octet on BOTH writes');
  assert.strictEqual(call(null).attackBoxOctet, null,
    'and a lane without one must reserve nothing for it');
  assert.strictEqual(call(9016).liveGoadController, true,
    'the live GOAD controller still gets its own reservation');
});

// ── what the re-write actually puts back ────────────────────────────────────

/**
 * The whole reservations file the deployer would install, as lines.
 * installLaneReservations is the only thing between writeLaneReservations and an
 * SSH session; patched on the module's own exports object because that is the
 * object the deployer dereferences at call time.
 */
async function reservationFile(args) {
  let captured = null;
  const realInstall = laneDeployer.installLaneReservations;
  const log = console.log;
  laneDeployer.installLaneReservations = async ({ lines }) => { captured = lines.slice(); };
  console.log = () => {};
  try {
    await writeLaneReservations(args);
  } finally {
    laneDeployer.installLaneReservations = realInstall;
    console.log = log;
  }
  return captured;
}

const EXT = '10.39.16';
const GOAD_LANE = {
  gatewayVmId: 5016, node: 'node-1', vxlanId: 16,
  goadMacs: { DC01: { mac: MAC_DC01, static_ip: `${EXT}.10` } },
  attackBoxOctet: goadDeploy.INFRA_IP_OCTETS.Kali,
  consoleOctets: {},
  // elk arrives as a pinned host, which is exactly why prep.sh cannot know it.
  pinnedHosts: [{ name: 'elk', octet: 24, subnetBase: EXT }],
  dnsRecords: [{ alias: 'elk', ip: `${EXT}.24` }],
  spec: {}, subnetScheme: 'v2',
  extSubnetBase: EXT, intSubnetBase: EXT,
  liveGoadController: true,
  laneId: 'lane-16', logTag: '[test]',
};

test('the re-written file carries the machines prep.sh cannot know about', async () => {
  // The consequence, stated as the lane sees it: after prep.sh has replaced the
  // file with its HOST_MAP, this render is what puts Kali's .50 and elk's .24
  // back — the two the live lane lost, one breaking the student's console and
  // one breaking every winlogbeat that ships to <subnet>.24:9200.
  const lines = await reservationFile(GOAD_LANE);
  assert.ok(lines.some((l) => l === `dhcp-host=${goadDeploy.macForOctet(goadDeploy.INFRA_IP_OCTETS.Kali, 16)},${EXT}.50,kali`),
    `Kali's reservation is missing from the rendered file:${LF}${lines.join(LF)}`);
  assert.ok(lines.some((l) => l.endsWith(`,${EXT}.24,elk`)), 'elk keeps its pinned .24');
  assert.ok(lines.some((l) => l === `dhcp-host=${MAC_DC01},${EXT}.10,DC01`), 'and the GOAD roster is still there');
  assert.ok(lines.includes(laneDeployer.hostRecordLine('elk', `${EXT}.24`)),
    'the host-record lives in this same file, so it is lost and restored with it');
});

test('the second write is byte-identical to the first', async () => {
  // What makes the re-write safe to run unconditionally: it is a no-op against a
  // gateway nothing clobbered. If this ever diverges, the post-GOAD write is
  // silently EDITING the lane rather than restoring it.
  const first = await reservationFile(GOAD_LANE);
  const second = await reservationFile(GOAD_LANE);
  assert.deepStrictEqual(second, first);
});
