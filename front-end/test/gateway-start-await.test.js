/**
 * gateway-start-await.test.js -- the gateway start must be awaited.
 *
 * THE INCIDENT
 * cloneGateway fired `POST .../status/start` and moved on. Proxmox returns a
 * UPID and starts the container asynchronously, so the deploy raced its own
 * gateway: waitForGatewayFirstboot began probing over `pct exec` while the LXC
 * was still booting, every probe answered
 *
 *     nodeExec exit 255 ... pct exec 110891 -- ... : container '110891' not running!
 *
 * and five of those inside ~15s exhausted its give-up budget. It returned false
 * and logged "cannot probe firstboot over SSH — continuing without waiting".
 *
 * For most courses a false bootReady is only a warning. For a MALWARE profile it
 * is fatal by design -- workstations must not start against a gateway whose
 * isolation config was never verified -- so the lane failed outright:
 *
 *     Malware gateway first boot could not be verified; workstations were not started.
 *
 * The gateway was fine. `pct start 110891` by hand returned 0 and it came up.
 * Two lanes on the same node in the same course differed only in which one's
 * container took longer than 15s to boot. It read as "node-8 is broken" and then
 * as "some VMIDs don't work", and it was neither.
 *
 * Three rules keep that from recurring, and all three are cheap:
 *   1. await the start task, so the container is up before anything probes it;
 *   2. confirm it actually reached 'running' before waiting on its innards;
 *   3. never let "not running" count toward the probe's give-up budget -- that
 *      string is the definition of not-ready-yet, not of a broken channel.
 *
 * Source assertions: exercising this needs a real Proxmox task queue and an LXC
 * that boots slowly. The rules are visible in the text, and each is one edit
 * away from silently regressing.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const SRC_PATH = path.join(__dirname, '..', 'src', 'utils', 'lane-deployer.js');
const CRLF = String.fromCharCode(13, 10);
const LF = String.fromCharCode(10);
const src = fs.readFileSync(SRC_PATH, 'utf8').split(CRLF).join(LF);

/** Body of an `async function name(` by brace-matching, skipping the params. */
function extractFn(name) {
  const start = src.indexOf(`async function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found -- renamed?`);
  let i = src.indexOf('(', start), depth = 0;
  for (; i < src.length; i++) {
    if (src[i] === '(') depth++;
    else if (src[i] === ')' && --depth === 0) break;
  }
  let j = src.indexOf('{', i);
  depth = 0;
  for (; j < src.length; j++) {
    if (src[j] === '{') depth++;
    else if (src[j] === '}' && --depth === 0) break;
  }
  const out = src.slice(start, j + 1);
  assert.ok(out.length > 200, `${name} extracted only ${out.length} chars -- extractFn is broken`);
  return out;
}

const CLONE_GW = extractFn('cloneGateway');
const FIRSTBOOT = extractFn('waitForGatewayFirstboot');

// -- rule 1: await the start -------------------------------------------------

test('THE BUG: the gateway start task is awaited, not fired and forgotten', () => {
  const at = CLONE_GW.indexOf("/status/start`");
  assert.notStrictEqual(at, -1, 'cloneGateway should start the gateway');

  // The POST's return value has to be captured and waited on. `await POST` alone
  // only waits for the API to hand back a UPID -- the container is still booting.
  const after = CLONE_GW.slice(at, at + 900);
  assert.ok(/const startUpid = await proxmoxAPI\('POST'/.test(CLONE_GW),
    'the start UPID must be captured');
  assert.ok(/waitForTask\(targetNode, startUpid/.test(after),
    'and the start task awaited before anything probes inside the container');
});

// -- rule 2: confirm it is running -------------------------------------------

test('it confirms the container reached running before probing inside it', () => {
  const at = CLONE_GW.indexOf("/status/start`");
  const after = CLONE_GW.slice(at);
  const poll = after.indexOf('/status/current');
  // The CALL, not the docblock above it that merely names the function -- that
  // reference sits earlier in cloneGateway and made this assertion fail against
  // correctly-ordered code.
  const probe = after.indexOf('await waitForGatewayFirstboot(');
  assert.ok(poll > -1, 'the status must be checked after starting');
  assert.ok(probe > -1, 'firstboot is still waited for');
  assert.ok(poll < probe,
    'the running check must come BEFORE the firstboot wait -- otherwise the probe ' +
    'spends its budget discovering the container is not up yet');
});

test('an unreadable status warns and continues; only a definite non-running stops', () => {
  // Fail on EVIDENCE, never on its absence. Proxmox reports {status:'stopped'}
  // for a container that did not start; a response we cannot parse is not proof
  // of anything, and blocking on one would stall every caller that mocks it.
  assert.ok(/statusReadable/.test(CLONE_GW), 'the unreadable case must be distinguished');
  assert.ok(/if \(!gwRunning && statusReadable\)/.test(CLONE_GW),
    'the throw must require a readable, definitely-not-running status');
});

// -- rule 3: "not running" is not a broken channel ---------------------------

test('THE TRAP: "not running" does not count toward the probe give-up budget', () => {
  // waitForGatewayFirstboot abandons after 5 consecutive errors (~15s). Counting
  // a still-booting container toward that is what turned a slow boot into a
  // failed lane.
  assert.ok(/if \(\/not running\/i\.test\(e\.message\)\) continue;/.test(FIRSTBOOT),
    '"container not running" must be retried, not counted as a channel failure');

  // And it must be skipped BEFORE the counter, or the guard is decorative.
  const skip = FIRSTBOOT.indexOf('not running');
  const bump = FIRSTBOOT.indexOf('consecutiveErrors++');
  assert.ok(skip > -1 && bump > -1 && skip < bump,
    'the not-running check must precede consecutiveErrors++');
});

test('a genuinely broken SSH channel still stops immediately', () => {
  // The give-up budget exists for a reason: one misconfigured key must not burn
  // the full 180s timeout per lane across a whole class.
  for (const phrase of ['missing or unreadable', 'permission denied',
                        'could not resolve', 'connection refused', 'no route to host']) {
    assert.ok(FIRSTBOOT.includes(phrase),
      `the fatal-channel list should still name "${phrase}"`);
  }
});

// -- the malware rule this protected ----------------------------------------

test('an unverified firstboot is still fatal for a malware profile', () => {
  // This behaviour is CORRECT and must not be relaxed: workstations must not be
  // started against a gateway whose isolation config was never confirmed. The
  // bug was never this check -- it was bootReady being false for a spurious
  // reason. Pinned so a future "fix" does not weaken the wrong end.
  assert.ok(/analysis_profile === 'malware'/.test(CLONE_GW),
    'the malware profile check must survive');
  assert.ok(/Malware gateway first boot could not be verified/.test(CLONE_GW),
    'and still refuse to start workstations behind an unverified gateway');
});

// -- rule 4: a failed start is retried -------------------------------------

test('THE SECOND BUG: a failed start is retried, not taken as final', () => {
  // `pct start` can fail on a rootfs mount that succeeds moments later:
  //     run_buffer: 569 Script exited with status 32
  //     lxc_init: 1037 Failed to run lxc.hook.pre-start for container "110891"
  // 32 is mount(8)'s exit code, and pre-start is where the rootfs is mounted --
  // the same udev/RBD symlink race the clone path already retries for.
  //
  // Established as transient, not damage: `lxc-start -F --logpriority=DEBUG` on
  // the failing VMID booted to a login prompt, and `fsck.ext4 -n -f` on its
  // rootfs was clean.
  assert.ok(/for \(let attempt = 1; attempt <= GATEWAY_START_ATTEMPTS/.test(CLONE_GW),
    'the start must be attempted more than once');
  assert.ok(/&& !gwRunning;/.test(CLONE_GW),
    'and must stop as soon as it is running');

  // The POST has to be INSIDE the loop -- retrying the status poll alone would
  // just re-read 'stopped' three times.
  const loop = CLONE_GW.indexOf('for (let attempt = 1;');
  const post = CLONE_GW.indexOf("/status/start`");
  assert.ok(loop > -1 && post > loop, 'the start POST must sit inside the retry loop');
});

test('only a failed start pays the delay', () => {
  // A whole cohort must not queue behind a pause that a healthy deploy never
  // needed. The sleep is reachable only from attempt 2.
  const at = CLONE_GW.indexOf('GATEWAY_START_RETRY_MS)');
  assert.ok(at > -1, 'the retry delay must be used');
  const before = CLONE_GW.slice(0, at);
  assert.ok(/if \(attempt > 1\) \{/.test(before),
    'the sleep must be guarded by attempt > 1, never paid on the first pass');
});

test('an unreadable status breaks the ladder instead of retrying it', () => {
  // Mirrors rule 3 above. Retrying against a status we cannot read proves
  // nothing and costs the delay -- and every test that stubs status/current
  // would sit through the full ladder for no reason.
  assert.ok(/if \(!statusReadable\) break;/.test(CLONE_GW),
    'an unreadable status must leave the loop, not drive another attempt');
});

test('the shipped ladder is bounded, and its numbers are sane', () => {
  const src2 = src;
  const attempts = Number(/const GATEWAY_START_ATTEMPTS = (\d+)/.exec(src2)[1]);
  const delay = Number(/const GATEWAY_START_RETRY_MS = (\d+)/.exec(src2)[1]);
  assert.ok(attempts >= 2, 'one attempt is not a retry');
  assert.ok(attempts <= 4, 'a container that failed four starts is not going to start');
  assert.ok(delay >= 1000, 'the volume needs a moment to settle; an instant retry re-races it');
  // Worst case is paid per lane, and lanes deploy in batches.
  assert.ok((attempts - 1) * delay <= 30000,
    `a failing gateway would stall its lane for ${(attempts - 1) * delay}ms`);
});

test('the failure message names the cause so it is not re-derived', () => {
  // This cost several days of chasing "node-8 is broken" and then "some VMIDs
  // do not work". The error should hand the next person the answer.
  assert.ok(/start attempts/.test(CLONE_GW), 'say how many times it tried');
  assert.ok(/lxc\.hook\.pre-start/.test(CLONE_GW), 'name the hook that fails');
  assert.ok(/not a damaged container/.test(CLONE_GW),
    'and say plainly that this is not corruption — fsck was clean, it boots by hand');
  assert.ok(/vzstart:/.test(CLONE_GW), 'and point at the task log that carries the detail');
});
