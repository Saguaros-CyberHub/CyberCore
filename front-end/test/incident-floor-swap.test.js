// ============================================================================
// incident-floor-swap.test.js — Track E, phase E4: publishing the client's
// benign floor onto a lane's sensor, with no re-bake.
//
// WHAT IS BEING DEFENDED, AND WHY IT IS A TEST RATHER THAN A CODE REVIEW.
//
// cc-hostbase.service's ExecStart is a FIXED PATH:
//
//   /usr/bin/node /opt/cybercore/cc-emit.js --daemon
//     --playbook /opt/cybercore/host-baseline.json
//     --out /opt/log-generator/logs/current/host.json
//
// so the benign floor is replaceable per lane without touching template 1007.
// That is the whole reason E4's compiler can emit a floor at all. The swap
// itself is six shell commands, and two of them have failure modes that are
// COMPLETELY SILENT on a deployed lane:
//
//   1. THE LIVE LOG MUST BE REMOVED, NOT EMPTIED.
//      Filebeat's filestream input identifies a file by inode and keeps a byte
//      offset for it in its registry. `rm` gives the restarted generator a NEW
//      inode, which filestream treats as a new file and reads from offset 0 —
//      correct. Emptying the file in place (`: >`, `truncate -s 0`) keeps the
//      SAME inode with the registry offset still past the new end of file, and
//      filestream then ships NOTHING, for the life of the lane. The service is
//      running. The file is growing. The index is empty. Nothing reports an
//      error, and the first person to notice is a student with no data.
//
//   2. THE ORDER IS NOT COSMETIC.
//      Writing the playbook before stopping the service races the daemon's own
//      read; removing the log before stopping it lets the running generator keep
//      writing to the unlinked inode; publishing with anything but `mv -f`
//      leaves a partially written host-baseline.json that cc-hostbase then fails
//      to parse on every restart forever.
//
// Neither is visible in a diff unless you already know to look, and neither
// fails loudly. So they are pinned here, against the generated script text,
// with no cluster and no guest.
//
// STUB DISCIPLINE. blueteam-postdeploy.js destructures `cybercoreQuery` from
// src/utils/cybercore-db at module load, so the stub goes in FIRST — otherwise
// the real pg Pool is constructed against a host that is not there. Same
// ordering ciab-blueteam.test.js documents.
//
// Run: node --test front-end/test/incident-floor-swap.test.js  (or npm test)
// ============================================================================
'use strict';

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

// ── The stub, before anything that holds a DB handle ────────────────────────
const DB = require.resolve(path.join(__dirname, '..', 'src', 'utils', 'cybercore-db.js'));
require.cache[DB] = {
  id: DB,
  filename: DB,
  loaded: true,
  exports: { cybercoreQuery: async () => ({ rows: [] }) },
  children: [],
  paths: [],
};

const POSTDEPLOY = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'ciab',
  'utils', 'blueteam-postdeploy.js');
const P = require(POSTDEPLOY);

const C = require(path.join(__dirname, '..', 'src', 'incident', 'scenario-compiler.js'));

// ---------------------------------------------------------------------------
// A real compiled floor, not a hand-written stand-in.
//
// The size matters to this file: the payload is what decides whether the swap
// fits in one guest-agent call or has to go through executeShellViaFile's
// 48KB chunked path, and a toy playbook would answer that question wrongly.
// ---------------------------------------------------------------------------
const ASSETS = [
  { hostname: 'DC01', ip: '10.50.10.10', role: 'server', os: 'Windows Server 2019', function: 'Domain controller', critical: true },
  { hostname: 'FILE01', ip: '10.50.10.11', role: 'server', os: 'Windows Server 2019', function: 'Finance file share', critical: true },
  { hostname: 'SQL01', ip: '10.50.10.12', role: 'server', os: 'Windows Server 2022', function: 'Practice database' },
  { hostname: 'WEB01', ip: '10.50.10.13', role: 'server', os: 'Ubuntu Server 22.04', function: 'Public website', services: ['443/HTTPS'] },
  { hostname: 'MAIL-RELAY', ip: '10.50.10.14', role: 'server', os: 'Debian 12', function: 'Smtp relay' },
  { hostname: 'FW-EDGE', ip: '10.50.10.1', role: 'network', os: 'Embedded', function: 'Perimeter firewall' },
  { hostname: 'BILLING-WS', ip: '10.50.20.23', role: 'workstation', os: 'Windows 11 23H2', function: 'Billing' },
  { hostname: 'NURSE-WS-01', ip: '10.50.20.22', role: 'workstation', os: 'Windows 10 22H2', function: 'Nurse station' },
];

const SCENARIO = {
  scenario_id: 'TS-001',
  name: 'Ransomware via phished billing credentials',
  attack_path: [
    { step: 1, action: 'Phish the billing clerk', target: 'MAIL-RELAY', technique: 'T1566.001', detection_opportunity: 'External sender using a lookalike display name' },
    { step: 2, action: 'Move onto the file server', target: 'FILE01', technique: 'T1021.002', detection_opportunity: 'Service account interactive logon overnight' },
    { step: 3, action: 'Encrypt the finance share', target: 'FILE01', technique: 'T1486', detection_opportunity: 'Mass rename then shadow copy deletion' },
  ],
};

const COMPILED = C.compileScenario({
  scenario: SCENARIO,
  assets: ASSETS,
  options: {
    runId: '11111111-2222-3333-4444-555555555555',
    laneIps: Array.from({ length: 20 }, (_, i) => `100.100.60.${80 + i}`),
    stakeholders: [{ name: 'Dana Okafor' }, { name: 'Miguel Torres' }, { name: 'Priya Raman' }],
  },
});

const BUILT = P.buildFloorSwapScript(COMPILED.floor);
const SCRIPT = BUILT.script;

/** The script with the base64 payload elided, for the line-wise assertions. */
const SKELETON = SCRIPT.split(BUILT.base64).join('<PAYLOAD>');
const LINES = SKELETON.split(/\r?\n/);

/** Index of the first line matching a pattern, or -1. */
const lineAt = (re) => LINES.findIndex((l) => re.test(l));

// ===========================================================================
// §1  THE ORDER
// ===========================================================================

test('§1 the swap is stop -> rm -> staged write -> mv -f -> start, in that order', () => {
  const stop = lineAt(/^systemctl stop cc-hostbase\b/);
  const rmLive = lineAt(/^rm -f "\$LIVE"$/);
  const write = lineAt(/^printf %s '<PAYLOAD>' \| base64 -d > "\$STAGE"$/);
  const publish = lineAt(/^mv -f "\$STAGE" "\$PB"$/);
  const start = lineAt(/^systemctl start cc-hostbase$/);

  for (const [name, i] of [['stop', stop], ['rm', rmLive], ['write', write],
    ['mv -f', publish], ['start', start]]) {
    assert.ok(i >= 0, `the swap has no ${name} step:\n${SKELETON}`);
  }
  assert.ok(stop < rmLive,
    'the log is removed while the generator is still writing to it');
  assert.ok(rmLive < write, 'the new floor is staged before the old log is gone');
  assert.ok(write < publish, 'the playbook is published before it has been written');
  assert.ok(publish < start, 'cc-hostbase restarts before the new floor is in place');
});

test('§1 the new floor is staged and published atomically, never written in place', () => {
  // agentShellExec retries the TRANSPORT on 596/ECONNRESET, so a chunk can land
  // twice and a call can die mid-stream. Writing straight to the live path
  // would leave a half-written host-baseline.json that cc-hostbase fails to
  // parse on every restart, forever, with the unit in a crash loop.
  assert.ok(/^STAGE="\$PB\.ccfloor"$/m.test(SKELETON), 'there is no staging path');
  assert.ok(!new RegExp('> *"?\\$PB"?(?![.])').test(SKELETON),
    'something writes directly to the published playbook path');
  assert.ok(/^mv -f "\$STAGE" "\$PB"$/m.test(SKELETON), 'the publish is not an atomic mv -f');
});

test('§1 a floor that does not parse is never published, and the service comes back anyway', () => {
  // Publishing an unparseable floor leaves cc-hostbase crash-looping, which is
  // the same outcome as no floor at all: source.type:host then occurs ONLY
  // during attacks and one terms aggregation ends the exercise.
  const check = lineAt(/^node -e "JSON\.parse\(/);
  const publish = lineAt(/^mv -f "\$STAGE" "\$PB"$/);
  assert.ok(check >= 0 && check < publish, 'the staged floor is published unvalidated');
  assert.ok(/recover\(\) \{ systemctl start cc-hostbase/.test(SKELETON)
    && /trap recover EXIT/.test(SKELETON),
    'nothing restarts cc-hostbase when the swap fails partway');
});

// ===========================================================================
// §2  rm, NEVER truncate
// ===========================================================================

test('§2 the live host.json is REMOVED, never truncated or redirected over', () => {
  // The single most important line in this file. See the header: emptying the
  // file in place keeps the inode, strands filestream's registry offset past
  // EOF, and the lane silently ships nothing for the rest of its life.
  assert.ok(!/truncate/i.test(SCRIPT),
    'the swap truncates something — a stranded filestream offset ships nothing, silently');

  const live = BUILT.livePath;
  const escaped = live.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  for (const target of ['\\$LIVE', escaped]) {
    // Any redirect ONTO the live log: `> $LIVE`, `>>"$LIVE"`, and the `: >`
    // idiom that is the classic way to empty a file without calling truncate.
    const redirect = new RegExp(`>>?\\s*"?${target}"?`);
    assert.ok(!redirect.test(SCRIPT),
      `the swap redirects onto ${live} instead of unlinking it`);
  }
  assert.ok(/^rm -f "\$LIVE"$/m.test(SKELETON), 'the live log is not removed at all');
});

test('§2 the two paths are the ones cc-hostbase.service was baked against', () => {
  // Both are hardcoded in the bake's ExecStart. A drift here does not fail —
  // the swap succeeds, writes a floor nothing reads, and the lane keeps the
  // generic one.
  assert.strictEqual(BUILT.playbookPath, '/opt/cybercore/host-baseline.json');
  assert.strictEqual(BUILT.livePath, '/opt/log-generator/logs/current/host.json');
  assert.strictEqual(BUILT.unit, 'cc-hostbase');
  assert.ok(SCRIPT.includes(`PB='${BUILT.playbookPath}'`));
  assert.ok(SCRIPT.includes(`LIVE='${BUILT.livePath}'`));
});

// ===========================================================================
// §3  THE PAYLOAD
// ===========================================================================

test('§3 the floor travels base64 and arrives byte-identical', () => {
  // A base64 word is /^[A-Za-z0-9+\/=]+$/, so it is inert inside a
  // single-quoted POSIX word whatever the JSON holds — no quoting question is
  // left to get wrong. The same rule lane-reseed.js states for secrets, applied
  // here for correctness rather than confidentiality.
  assert.match(BUILT.base64, /^[A-Za-z0-9+/=]+$/);
  const round = JSON.parse(Buffer.from(BUILT.base64, 'base64').toString('utf-8'));
  assert.deepStrictEqual(round, COMPILED.floor);
});

test('§3 the payload is the size the chunked write path was chosen for', () => {
  // executeShellViaFile writes 48KB of base64 per agent call. The plan's
  // estimate is "roughly 30KB" of floor; if a compiled floor ever grew by an
  // order of magnitude the number of round trips would too, and this is where
  // that shows up rather than in a deploy that times out.
  assert.ok(BUILT.bytes > 10 * 1024 && BUILT.bytes < 128 * 1024,
    `a compiled floor of ${BUILT.bytes} bytes is outside the expected range`);
  assert.ok(SCRIPT.length < 256 * 1024, 'the swap script is too large to stage sensibly');
});

test('§3 the script is LF and starts with a POSIX shebang', () => {
  // A CRLF shebang makes the kernel look for an interpreter named "/bin/sh\r"
  // and report a bad interpreter — the same trap test/bake-payloads.test.js
  // records. executeShellViaFile normalises, but a script that needs
  // normalising is one nobody can run by hand while debugging a lane.
  assert.ok(SCRIPT.startsWith('#!/bin/sh\n'));
  assert.ok(!SCRIPT.includes('\r'), 'the generated shell contains CR');
});

test('§3 a floor with no steps is refused rather than published', () => {
  assert.throws(() => P.buildFloorSwapScript(null), /floor playbook with steps/);
  assert.throws(() => P.buildFloorSwapScript({ steps: [] }), /floor playbook with steps/);
});

// ===========================================================================
// §4  THE HOOK
// ===========================================================================

test('§4 the hook is null when there is nothing to do', () => {
  // The same "there is nothing to do" shape makeSensorStampPostDeploy and
  // makeVulnAppPostDeploy use, so chainPostDeploy needs no conditional at the
  // call site.
  const spec = { vms: [{ name: 'sensor-01', role: 'sensor' }] };
  assert.strictEqual(P.makeFloorSwapPostDeploy(spec, { floor: null }), null,
    'no compiled floor should mean no hook');
  assert.strictEqual(P.makeFloorSwapPostDeploy({ vms: [{ name: 'web', role: 'web' }] },
    { floor: COMPILED.floor }), null,
    'a spec with no sensor should mean no hook');
  assert.strictEqual(typeof P.makeFloorSwapPostDeploy(spec, { floor: COMPILED.floor }), 'function');
});

test('§4 a lane whose sensor is missing FAILS the lane, loudly', () => {
  // Not best-effort. A lane that keeps the generic floor is not a degraded
  // exercise — it is one where `loggen.source.host : DC01` returns the
  // intrusion and nothing else. Nothing downstream can detect that state, so
  // the only place it can surface is config.post_deploy_error.
  const hook = P.makeFloorSwapPostDeploy({ vms: [{ name: 'sensor-01', role: 'sensor' }] },
    { floor: COMPILED.floor });
  return assert.rejects(
    () => hook({ laneId: 7, deployedVMs: [{ name: 'web-01', vm_id: 101, node: 'n5' }] }),
    /is not among this lane's machines/
  );
});

test('§4 the swap is matched by SPEC name, never by the cloned proxmox name', () => {
  // `name` on a deployedVMs record is the spec name; `proxmox_name` carries the
  // student suffix. Matching on proxmox_name works on lane 1 and silently fails
  // on every other lane in the batch — the trap makeSensorStampPostDeploy
  // already records.
  const src = require('fs').readFileSync(POSTDEPLOY, 'utf8');
  const body = src.slice(src.indexOf('function makeFloorSwapPostDeploy'));
  assert.ok(/vm\.name === sensorVm\.name/.test(body),
    'the floor swap does not match the sensor by spec name');
  assert.ok(!/vm\.proxmox_name === /.test(body),
    'the floor swap matches on proxmox_name, which only works on lane 1');
});

test('§4 script-executor is required lazily, so this file loads with no cluster', () => {
  // src/utils/script-executor destructures src/utils/proxmox and src/utils/db at
  // module load. A top-level require here would put a pg Pool in the module
  // cache of every fixture suite that touches the CiAB plugin — and this test
  // file is the proof, because it just required blueteam-postdeploy.js with
  // neither available.
  assert.ok(!Object.prototype.hasOwnProperty.call(require.cache,
    require.resolve(path.join(__dirname, '..', 'src', 'utils', 'script-executor.js'))),
    'requiring blueteam-postdeploy.js dragged script-executor into the cache');
});
