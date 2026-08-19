/**
 * attack-command.test.js — what gets interpolated into a root shell.
 *
 * Every string these builders emit is executed by /bin/sh as root inside a
 * student's VM, via Proxmox's guest agent. The values come from an instructor's
 * browser. So the interesting assertions here are not "does it produce the
 * right command" but "does it REFUSE the wrong one", plus the handful of
 * details whose regression is completely silent:
 *
 *   - abort must kill the process GROUP. `kill -TERM $P` instead of
 *     `kill -TERM -$P` still exits 0, still marks the lane aborted, and leaves
 *     npm and node generating for another 40 minutes.
 *   - chain mode must never emit --duration. Product rule, DB CHECK, and here.
 *   - the staged wrapper must survive base64 byte-for-byte; a mangled script is
 *     a lane that refuses or, worse, half-runs.
 *
 * Run: node front-end/test/attack-command.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const P = path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils');
const runner = require(path.join(P, 'attack-runner.js'));

const RUN = '11111111-2222-3333-4444-555555555555';
const BASE = {
  runId: RUN, startEpoch: 1787170000, relDelaySeconds: 56,
  mode: 'technique', arg: 'T1110', duration: '30m', capSeconds: 2280, speed: '1.00',
};

test('a technique id carrying shell metacharacters is refused, not quoted', () => {
  for (const bad of ['T1110; rm -rf /', 'T1110 && curl evil', "T1110'", 'T1110`id`',
                     '$(id)', 'T1110|nc 1.2.3.4 1', '../../etc/passwd']) {
    assert.throws(
      () => runner.resolveSelection({ mode: 'technique', technique_id: bad, duration_seconds: 1800 }),
      `expected ${JSON.stringify(bad)} to be rejected`
    );
    assert.throws(() => runner.buildDispatchCommand({ ...BASE, arg: bad }));
  }
});

test('a newline in an id is rejected, and the anchors are why', () => {
  // Worth pinning, because the belief that JavaScript's `$` matches before a
  // trailing newline is widespread and wrong — it is Python and Perl that do
  // that. src/utils/flag-manager.js isSafePath() carries a comment asserting
  // the Python behaviour for JavaScript. Were it true here, an id ending in a
  // newline would pass validation and let a second shell statement through.
  assert.strictEqual(/^T\d{4}(\.\d{3})?$/.test('T1110\n'), false,
    'JS anchors must reject a trailing newline');

  for (const bad of ['T1110\n', 'T1110\nid', 'T1110\rid', '\nT1110']) {
    assert.throws(() => runner.resolveSelection({
      mode: 'technique', technique_id: bad, duration_seconds: 1800,
    }), `expected ${JSON.stringify(bad)} to be rejected`);
    assert.throws(() => runner.buildDispatchCommand({ ...BASE, arg: bad }));
  }
});

test('a well-formed id that is not in the catalog is still refused', () => {
  // The regex alone would accept T9999. Dispatching something the console never
  // offered means the guest silently generates nothing.
  assert.throws(() => runner.resolveSelection({
    mode: 'technique', technique_id: 'T9999', duration_seconds: 1800,
  }), /not in the log-generator catalog/);
});

test('chain keys are allowlisted by identity, not by pattern', () => {
  assert.throws(() => runner.resolveSelection({ mode: 'chain', chain_key: 'apt29-cozy-bear-evil' }));
  assert.throws(() => runner.buildDispatchCommand({ ...BASE, mode: 'chain', arg: 'nope', duration: '' }));
  assert.ok(runner.resolveSelection({ mode: 'chain', chain_key: 'apt29-cozy-bear' }));
});

test('durations outside the allowed window are refused', () => {
  for (const bad of [0, 29, 28801, -1, 1.5, 'abc', null]) {
    assert.throws(() => runner.resolveSelection({
      mode: 'technique', technique_id: 'T1110', duration_seconds: bad,
    }), `expected duration ${JSON.stringify(bad)} to be rejected`);
  }
});

test('chain mode never emits --duration', () => {
  const sel = runner.resolveSelection({ mode: 'chain', chain_key: 'apt29-cozy-bear', speed: 1 });
  assert.strictEqual(sel.durationSeconds, null);
  const cmd = runner.buildDispatchCommand({
    ...BASE, mode: 'chain', arg: sel.arg, duration: sel.duration, capSeconds: sel.capSeconds, speed: sel.speed,
  });
  assert.ok(!/--duration/.test(cmd), 'a chain must not carry a duration');
});

test('the dispatch command detaches, or QGA holds a channel open for 45 minutes', () => {
  const cmd = runner.buildDispatchCommand(BASE);
  assert.match(cmd, /nohup setsid /, 'must detach via nohup setsid');
  assert.ok(cmd.includes('</dev/null'), 'stdin must be closed');
  assert.ok(cmd.includes('>/dev/null 2>&1'), 'output must not flow back through the agent');
  assert.ok(cmd.trim().endsWith('&'), 'must background');
  // Without setsid the wrapper shares our process group and abort cannot reach
  // it, so a stripped image must fail loudly instead of launching unkillably.
  assert.match(cmd, /command -v setsid/, 'must refuse to launch when setsid is absent');
});

test('the staged wrapper round-trips through base64 byte-for-byte', () => {
  const cmd = runner.buildDispatchCommand(BASE);
  const m = cmd.match(/printf %s '([A-Za-z0-9+/=]+)'/);
  assert.ok(m, 'no base64 payload found in the dispatch command');
  assert.strictEqual(Buffer.from(m[1], 'base64').toString('utf8'), runner.WRAPPER_SH);
});

test('the wrapper is staged with every argument single-quoted', () => {
  const cmd = runner.buildDispatchCommand(BASE);
  const argv = cmd.slice(cmd.indexOf('cc-attack.sh '));
  assert.match(argv, /cc-attack\.sh '11111111-2222-3333-4444-555555555555' '1787170000' '56' 'technique' 'T1110' '30m' '2280' '1\.00'/);
});

test('abort signals the process GROUP', () => {
  const cmd = runner.buildAbortCommand(RUN);
  // The minus before "$P" is the whole point. Losing it is silent: the wrapper
  // dies, timeout/npm/node do not, and the lane keeps generating.
  assert.match(cmd, /kill -TERM -"\$P"/, 'must negate the pid to signal the group');
  assert.ok(!/kill -TERM "\$P"/.test(cmd), 'must not signal the wrapper alone');
});

test('the liveness probe needs no packages beyond the shell', () => {
  const cmd = runner.buildStateReadCommand(RUN);
  // pgrep lives in procps-ng, which a minimal image may not carry. kill -0 plus
  // a /proc/<pid>/cmdline check is builtin, and unlike a bare kill -0 it is not
  // fooled by PID recycling over a 45-minute run.
  assert.ok(!/pgrep/.test(cmd), 'must not depend on pgrep');
  assert.match(cmd, /kill -0/);
  assert.match(cmd, /cmdline/);
  assert.match(cmd, /STATE=/);
  assert.match(cmd, /ALIVE=/);
});

test('a non-UUID run id never reaches a path', () => {
  for (const bad of ['../../etc', 'abc', '', null, "x'; rm -rf /"]) {
    assert.throws(() => runner.buildStateReadCommand(bad));
    assert.throws(() => runner.buildAbortCommand(bad));
  }
});

test('guest state lines parse into the fields the reconciler writes', () => {
  const done = runner.parseGuestState('STATE=done rc=0 end=17 lines=42 skew=3600 fb=1 ref=abc\nALIVE=0');
  assert.strictEqual(done.phase, 'done');
  assert.strictEqual(done.rc, 0);
  assert.strictEqual(done.lines, 42);
  assert.strictEqual(done.skew, 3600);
  assert.strictEqual(done.fellBack, true);
  assert.strictEqual(done.alive, false);

  const refused = runner.parseGuestState('STATE=refused notinstalled ref=abc\nALIVE=0');
  assert.strictEqual(refused.phase, 'refused');
  assert.strictEqual(refused.reason, 'notinstalled');

  const running = runner.parseGuestState('STATE=running start=5 pid=99 skew=0 fb=0 split=1 ref=abc\nALIVE=1');
  assert.strictEqual(running.phase, 'running');
  assert.strictEqual(running.alive, true);
  assert.strictEqual(running.pid, 99);
  assert.strictEqual(running.split, true);

  // An empty state file is normal for a moment after dispatch, and must not be
  // mistaken for a finished run.
  const empty = runner.parseGuestState('STATE=\nALIVE=1');
  assert.strictEqual(empty.phase, '');
  assert.strictEqual(empty.alive, true);
});

test('lead time scales with the class but stays bounded', () => {
  assert.strictEqual(runner.leadSecondsFor(0), 30);
  assert.strictEqual(runner.leadSecondsFor(25), 50);
  assert.ok(runner.leadSecondsFor(1000) <= 180, 'lead must not grow without bound');
});
