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
