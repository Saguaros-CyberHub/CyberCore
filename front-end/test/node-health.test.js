/**
 * node-health.test.js — the in-process node circuit breaker.
 *
 * WHY THIS FILE EXISTS
 * cyberhub-node-8 joined the cluster mid-Ceph-backfill and every challenge lane
 * placed on it failed identically: the gateway LXC cloned, then `pct start` died
 * with "Failed to run lxc.hook.pre-start ... status 32" because the hook lost the
 * race for the udev-created /dev/rbd-pve/<fsid>/<pool>/<image> symlink. The
 * scheduler then sent the NEXT lane to node-8 too, because a node doing nothing
 * but backfill has idle CPU and free RAM and therefore scores best in
 * utils/node-selector.js. src/utils/node-health.js is the only memory the
 * orchestrator has of "that node just failed", so the behaviour asserted here —
 * that a fault is remembered, that it expires on its own, and that an operator
 * can lift it early — is the whole of the protection.
 *
 * Run: node --test test/node-health.test.js
 */

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const NH = require(path.join(__dirname, '..', 'src', 'utils', 'node-health.js'));

const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

// markNodeFault logs on every call by design (an operator scrolling deploy logs
// needs to see the quarantine happen). Swallow it so the test output stays
// readable, and hand the captured lines back for the format assertion below.
function captureWarnings(fn) {
  const original = console.warn;
  const lines = [];
  console.warn = (...args) => { lines.push(args.join(' ')); };
  try {
    fn();
  } finally {
    console.warn = original;
  }
  return lines;
}

test('a marked node is quarantined and reported with its name and reason', () => {
  NH._resetForTests();

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', 'Failed to run lxc.hook.pre-start for container "110881"');
  });

  assert.strictEqual(NH.isNodeQuarantined('cyberhub-node-8'), true);

  const listed = NH.quarantinedNodes();
  assert.strictEqual(listed.length, 1);
  assert.strictEqual(listed[0].node, 'cyberhub-node-8');
  assert.match(listed[0].reason, /lxc\.hook\.pre-start/);
  assert.strictEqual(listed[0].count, 1);
  // ISO string, not a raw epoch — this goes straight into admin diagnostics.
  assert.strictEqual(typeof listed[0].until, 'string');
  assert.strictEqual(new Date(listed[0].until).toISOString(), listed[0].until);
});

test('a node nobody has faulted is not quarantined', () => {
  NH._resetForTests();

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', 'rbd symlink race');
  });

  // The whole point is that ONE bad node does not take the cluster with it.
  assert.strictEqual(NH.isNodeQuarantined('cyberhub-node-3'), false);
  assert.deepStrictEqual(NH.quarantinedNodes().map(q => q.node), ['cyberhub-node-8']);
});

test('a quarantine expires on its own and is pruned from the list', async () => {
  NH._resetForTests();

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', 'rbd symlink race', { ttlMs: 5 });
  });
  assert.strictEqual(NH.isNodeQuarantined('cyberhub-node-8'), true);

  await sleep(20);

  // A node that recovers on its own comes back with no operator action: this is
  // the reason the TTL exists at all instead of a sticky exclusion list.
  assert.strictEqual(NH.isNodeQuarantined('cyberhub-node-8'), false);
  assert.deepStrictEqual(NH.quarantinedNodes(), []);
});

test('clearNodeFault lifts a quarantine once and reports whether it did', () => {
  NH._resetForTests();

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', 'rbd symlink race');
  });

  assert.strictEqual(NH.clearNodeFault('cyberhub-node-8'), true);
  assert.strictEqual(NH.isNodeQuarantined('cyberhub-node-8'), false);
  assert.deepStrictEqual(NH.quarantinedNodes(), []);

  // Second call has nothing to remove. The boolean is what lets an admin route
  // answer "already clear" instead of claiming it just fixed something.
  assert.strictEqual(NH.clearNodeFault('cyberhub-node-8'), false);
});

test('marking twice extends the window and counts both faults', () => {
  NH._resetForTests();

  let first;
  let second;
  const lines = captureWarnings(() => {
    first = NH.markNodeFault('cyberhub-node-8', 'first pct start failure');
    second = NH.markNodeFault('cyberhub-node-8', 'second pct start failure');
  });

  // A node failing again gets a fresh full window from the SECOND failure, not
  // the tail of the first — otherwise a node failing every 14 minutes would fall
  // out of quarantine just in time to eat the next batch.
  assert.ok(second.until >= first.until,
    `second until ${second.until} should not be earlier than first ${first.until}`);
  assert.strictEqual(second.count, 2);

  const listed = NH.quarantinedNodes();
  assert.strictEqual(listed.length, 1, 're-marking must not create a duplicate entry');
  assert.strictEqual(listed[0].count, 2);
  assert.strictEqual(listed[0].reason, 'second pct start failure');

  // The log line is what an operator actually sees during a failing batch.
  assert.strictEqual(lines.length, 2);
  assert.match(lines[1], /^\[NodeHealth] cyberhub-node-8 quarantined for 15 min \(fault 2\): second pct start failure$/);
});

test('reasons are trimmed to one line and capped in length', () => {
  NH._resetForTests();

  const longReason = 'x'.repeat(500);
  const multiline = 'ssh: connect to host 10.42.129.1 port 22: No route to host\n    at ClientChannel.<anonymous>\n    at Socket.emit';

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', longReason);
    NH.markNodeFault('cyberhub-node-9', multiline);
  });

  const byNode = Object.fromEntries(NH.quarantinedNodes().map(q => [q.node, q.reason]));

  assert.ok(byNode['cyberhub-node-8'].length <= 200,
    `reason was ${byNode['cyberhub-node-8'].length} chars; a 500-char blob must not reach the log`);
  assert.ok(byNode['cyberhub-node-8'].startsWith('xxx'));

  // Errors arrive with a stack attached; only the sentence is useful.
  assert.strictEqual(byNode['cyberhub-node-9'],
    'ssh: connect to host 10.42.129.1 port 22: No route to host');
  assert.ok(!byNode['cyberhub-node-9'].includes('\n'));
});

test('remaining_s counts down inside the TTL', () => {
  NH._resetForTests();

  captureWarnings(() => {
    NH.markNodeFault('cyberhub-node-8', 'rbd symlink race');
  });

  const [entry] = NH.quarantinedNodes();
  const ttlSeconds = NH.NODE_QUARANTINE_MS / 1000;

  assert.strictEqual(typeof entry.remaining_s, 'number');
  assert.ok(entry.remaining_s > 0, `remaining_s was ${entry.remaining_s}`);
  assert.ok(entry.remaining_s <= ttlSeconds,
    `remaining_s ${entry.remaining_s} exceeded the ${ttlSeconds}s TTL`);
});
