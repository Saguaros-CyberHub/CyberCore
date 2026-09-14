'use strict';

/**
 * The beacon coupling.
 * ============================================================================
 * Four values live in two files and are only correct together. Nothing in the
 * type system, the linter or any other suite relates them, and the failure they
 * produce is both total and misleading:
 *
 *   Caldera stops trusting an agent whose last_seen is older than
 *   `untrusted_timer` (infrastructure/caldera/conf/agents.yml). freshAgent() in
 *   src/utils/caldera-lane-agents.js requires `trusted === true` AND a last_seen
 *   inside AGENT_FRESH_MS. launch() in caldera-lane-operations.js refuses the
 *   whole batch unless EVERY selected lane has a fresh trusted agent.
 *
 * So raising the beacon interval past either bound does not degrade anything
 * gently. Every classroom launch is refused, on every lane, with a message
 * naming agents that are beaconing perfectly well — and the person who raised
 * `sleep_max` for realism has no reason to connect the two.
 *
 * This file exists so that change fails HERE, in a suite that names the other
 * values, instead of on a cluster in front of a class.
 *
 * Run: node --test test/caldera-beacon-coupling.test.js
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

const agents = require('../src/utils/caldera-lane-agents');
const { AGENT_FRESH_MS, AGENT_SKEW_MS, CHECK_IN_ATTEMPTS, CHECK_IN_INTERVAL_MS,
  CHECK_IN_MARGIN_MS, JOB_TIMEOUT_MS } = agents;

const AGENTS_YML = path.join(__dirname, '..', '..', 'infrastructure', 'caldera', 'conf', 'agents.yml');

/** One scalar out of the flat agents.yml. Comments and blank lines ignored. */
function scalar(key) {
  const src = fs.readFileSync(AGENTS_YML, 'utf8');
  for (const line of src.split(/\r?\n/)) {
    const m = /^([A-Za-z_][A-Za-z0-9_]*):\s*(.+?)\s*$/.exec(line);
    if (m && m[1] === key) return m[2].replace(/^["']|["']$/g, '');
  }
  return null;
}

const num = (key) => {
  const raw = scalar(key);
  assert.ok(raw !== null, `agents.yml no longer defines ${key}`);
  const n = Number(raw);
  assert.ok(Number.isFinite(n), `agents.yml ${key} is not a number: ${raw}`);
  return n;
};

// ---------------------------------------------------------------------------

test('the beacon config is still where this test thinks it is', () => {
  assert.ok(fs.existsSync(AGENTS_YML), `agents.yml not found at ${AGENTS_YML}`);
  for (const key of ['sleep_min', 'sleep_max', 'untrusted_timer', 'implant_name']) {
    assert.ok(scalar(key) !== null, `agents.yml lost ${key}`);
  }
});

test('the beacon interval is a range, not a metronome', () => {
  const min = num('sleep_min');
  const max = num('sleep_max');
  assert.ok(min > 0, 'sleep_min must be positive');
  assert.ok(max > min, `sleep_max (${max}) must exceed sleep_min (${min}) or there is no jitter at all`);
  // A sub-15-second beacon is a metronome on the wire: on a lane where Sysmon
  // records every outbound connection, a fixed short period identifies the
  // implant with no analysis. This is the realism floor R2 exists to raise.
  assert.ok(min >= 15, `sleep_min is ${min}s; a beacon that fast is a metronome, not tradecraft`);
});

/**
 * THE ONE THAT BREAKS EVERY LAUNCH.
 *
 * Caldera must still trust an agent that has simply been sleeping. The margin is
 * a whole extra beacon, so a single dropped check-in does not cost the lane its
 * launchability.
 */
test('Caldera still trusts an agent that is merely between beacons', () => {
  const max = num('sleep_max');
  const untrusted = num('untrusted_timer');
  assert.ok(untrusted > max,
    `untrusted_timer (${untrusted}s) must exceed sleep_max (${max}s) or every agent goes untrusted between beacons`);
  assert.ok(untrusted >= max * 2,
    `untrusted_timer (${untrusted}s) leaves no margin over sleep_max (${max}s); one dropped beacon would strand the lane`);
});

/**
 * The same bound on CyberCore's side. These two windows describe the same fact
 * from opposite ends, so they are pinned to each other rather than merely both
 * being "big enough".
 */
test('CyberCore calls an agent present for exactly as long as Caldera will task it', () => {
  const untrusted = num('untrusted_timer');
  assert.equal(AGENT_FRESH_MS, untrusted * 1000,
    `AGENT_FRESH_MS (${AGENT_FRESH_MS}ms) and untrusted_timer (${untrusted}s) must describe the same window; `
    + 'a shorter AGENT_FRESH_MS refuses launches Caldera would have accepted, a longer one offers lanes Caldera will reject');
});

test('an agent between beacons is still fresh to freshAgent()', () => {
  const max = num('sleep_max');
  const at = 1_700_000_000_000;
  // Last seen one full beacon interval ago: the ordinary steady state.
  const sleeping = { trusted: true, last_seen: new Date(at - max * 1000).toISOString() };
  assert.equal(agents.freshAgent(sleeping, at), true,
    'an agent that beaconed one interval ago is the NORMAL case and must count as present');
  // Untrusted is never fresh, however recent.
  assert.equal(agents.freshAgent({ trusted: false, last_seen: new Date(at).toISOString() }, at), false);
  // Beyond the window it is correctly gone.
  assert.equal(agents.freshAgent({ trusted: true, last_seen: new Date(at - AGENT_FRESH_MS - 1000).toISOString() }, at), false);
});

/**
 * Install verification has to outlast one beacon too. Sandcat registers on
 * start, so first contact is normally immediate — but if that first beacon is
 * missed, the next is up to sleep_max away, and a shorter window reports a
 * healthy agent as a failed install.
 */
test('the install check-in window outlasts one full beacon interval', () => {
  const max = num('sleep_max');
  const window = CHECK_IN_ATTEMPTS * CHECK_IN_INTERVAL_MS;
  assert.ok(window > max * 1000,
    `the check-in window is ${window / 1000}s but a missed first beacon costs up to ${max}s; installs would report false failures`);
});

/**
 * ...and must still fit inside the job's own budget, or it reaches past
 * JOB_TIMEOUT_MS into currentJob() and the atomic claim, where a retry can steal
 * the VM from the installer still working on it.
 */
test('the check-in window still fits inside the job timeout', () => {
  const window = CHECK_IN_ATTEMPTS * CHECK_IN_INTERVAL_MS;
  const budget = JOB_TIMEOUT_MS - CHECK_IN_MARGIN_MS;
  assert.ok(window <= budget,
    `the check-in window (${window / 1000}s) exceeds the job budget (${budget / 1000}s); `
    + 'raising it further means raising JOB_TIMEOUT_MS and re-checking the claim SQL, not just this constant');
});

test('the forward skew window stays smaller than the freshness window', () => {
  assert.ok(AGENT_SKEW_MS < AGENT_FRESH_MS,
    'a forward skew as large as the freshness window would let a future timestamp mask a dead agent');
});

// ---------------------------------------------------------------------------
// The implant is not self-identifying
// ---------------------------------------------------------------------------

/**
 * The implant's name and path appear in every Sysmon process-create and
 * network-connect event on the lane. A name that says what it is hands the
 * exercise over on a single filter, which is the same class of oracle the
 * synthetic playbook contract exists to prevent.
 */
test('neither the implant name nor the installer paths name the product or the tool', () => {
  const forbidden = /caldera|sandcat|mitre|cybercore/i;
  const implant = scalar('implant_name');
  assert.ok(!forbidden.test(implant), `implant_name "${implant}" identifies the tooling in every process listing`);

  const scripts = require('../src/utils/caldera-agent-scripts');
  const linux = scripts.buildInstallScript({
    platform: 'linux',
    serverUrl: 'https://agents.example.org/agent/' + 'a'.repeat(64),
    group: 'lane-11111111-2222-3333-4444-555555555555',
    paw: 'b'.repeat(24),
  });
  const windows = scripts.buildInstallScript({
    platform: 'windows',
    serverUrl: 'https://agents.example.org/agent/' + 'a'.repeat(64),
    group: 'lane-11111111-2222-3333-4444-555555555555',
    paw: 'b'.repeat(24),
  });

  // Asserted on where the agent INSTALLS AND RUNS, which is what a student
  // browsing the filesystem or reading Sysmon sees. Not on the operator-facing
  // progress text, which reaches an instructor through the guest-agent exec and
  // never lands on disk; and deliberately not on the `legacy_` assignments,
  // which name the pre-rename location precisely so the installer can stop and
  // delete it.
  const assignments = (script, keys) => keys.map((key) => {
    const m = new RegExp(`^\\s*\\$?${key}\\s*=\\s*(.+)$`, 'm').exec(script);
    assert.ok(m, `install script no longer assigns ${key}; this test is now checking nothing`);
    return m[1];
  });

  for (const value of assignments(linux, ['agent_dir', 'binary', 'download'])) {
    assert.ok(!forbidden.test(value), `linux agent path names the tooling on disk: ${value}`);
  }
  for (const value of assignments(windows, ['agentDir', 'binary', 'download'])) {
    assert.ok(!forbidden.test(value), `windows agent path names the tooling on disk: ${value}`);
  }

  // The pre-rename location must still be referenced, or an upgraded lane keeps
  // a second agent beaconing on the same paw and every ability executes twice.
  for (const [name, script] of [['linux', linux], ['windows', windows]]) {
    assert.match(script, /legacy_dir|legacyDir/,
      `${name} install script no longer cleans up the pre-rename agent directory`);
  }
});
