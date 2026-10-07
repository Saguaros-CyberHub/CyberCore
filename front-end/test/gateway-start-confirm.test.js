/**
 * gateway-start-confirm.test.js — the gateway start gate, exercised for real.
 *
 * THE INCIDENT
 * Every challenge lane placed on cyberhub-node-8 failed, behind an error that
 * named nothing real. node-8 had just joined the cluster and was still doing a
 * Ceph backfill, so `pct start` on the freshly cloned gateway LXC lost the race
 * for the udev-created /dev/rbd-pve/<fsid>/<pool>/<image> symlink and died in
 * the pre-start hook:
 *
 *     run_buffer: 569 Script exited with status 32
 *     lxc_init: 1037 Failed to run lxc.hook.pre-start for container "110881"
 *
 * Nothing checked. The deployer fired the start, slept 5s, wrote DHCP
 * reservations into a stopped container, swallowed THAT behind
 * "Check PROXMOX_SSH_KEY / PROXMOX_SSH_USER", started every lane VM anyway,
 * cloned a GOAD controller, and finally died three to five minutes later with
 * "ssh: connect to host 10.42.129.1 port 22: No route to host" — an error about
 * a machine that was never the problem.
 *
 * WHY THIS FILE EXISTS ALONGSIDE gateway-start-await.test.js
 * That file asserts on SOURCE TEXT: it brace-matches the functions and greps
 * for the loop header, the guarded sleep, the error fragments. It was written
 * when the gate was inlined in lane-deployer.cloneGateway and could not be
 * reached without a live Proxmox task queue and an LXC that boots slowly.
 * Extracting the gate into utils/gateway-lifecycle.js removed that excuse: the
 * module takes proxmoxAPI through require.cache and every delay through an
 * argument, so the whole three-attempt ladder now runs in milliseconds. Source
 * greps catch a rename; only this file catches the ladder counting wrong,
 * throwing on the wrong evidence, or POSTing start at a running container.
 *
 * THE RULE MOST WORTH DEFENDING is the one that looks like a bug: an UNREADABLE
 * status must RESOLVE, not throw. Six test files replace proxmox.js wholesale
 * and answer {} to every URL they do not recognise, so treating "no answer" as
 * "not running" would fail deploys in suites that have nothing to do with
 * gateways. Fail on evidence, never on its absence.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stub(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// node-ssh reads site.json at load for its name -> IP map; it is gitignored and
// absent in a plain checkout.
stub('site-config.js', {
  getNodeAddress: () => '100.100.10.18',
  getClusterNodes: () => ['cyberhub-node-8'],
  getSchedulingConfig: () => ({ min_free_mem_gb: 8, min_free_disk_gb: 20 }),
});

// ── the stubbed cluster ─────────────────────────────────────────────────────
//
// statusPlan is consumed one entry per /status/current read, and the LAST entry
// repeats forever — so 'stopped' means "stays down" without writing 45 of them.
// A null entry is an UNREADABLE answer, which is a different thing from 'stopped'
// and the two must never be conflated.
let calls;
let statusPlan;
let taskBehaviour;

function resetCluster() {
  calls = { starts: [], statuses: [], tasks: [] };
  statusPlan = ['running'];
  taskBehaviour = 'ok';
}
resetCluster();

function nextStatus() {
  const v = statusPlan.length > 1 ? statusPlan.shift() : statusPlan[0];
  calls.statuses.push(v);
  return v === null ? {} : { status: v };
}

stub('proxmox.js', {
  PROXMOX_URL: 'https://stub',
  async proxmoxAPI(method, url) {
    if (method === 'POST' && /\/status\/start$/.test(url)) {
      calls.starts.push(url);
      return 'UPID:stub:vzstart::';
    }
    if (method === 'GET' && /\/status\/current$/.test(url)) return nextStatus();
    return {};
  },
  async waitForTask(node, upid) {
    calls.tasks.push(upid);
    if (taskBehaviour === 'throw') {
      throw new Error('Proxmox task failed: run_buffer: 569 Script exited with status 32');
    }
    return true;
  },
  // Deliberately NOT exported here: forceDestroyVM, waitForVmidsGone. If
  // gateway-lifecycle ever destructures one of those off proxmox.js, this file
  // fails at require — which is the point. lane-deployer-slots.test.js stubs
  // proxmox.js with an even smaller surface and would break the same way.
  async findTemplateNode(vmid, hint) { return hint || 'node-5'; },
});

// pctExec drives waitForGatewayFirstboot. Scripted per test.
let pctExecImpl = async () => ({ stdout: 'firstboot-done', stderr: '', code: 0 });
let pctExecCalls = 0;
stub('node-ssh.js', {
  pctExec: async (...a) => { pctExecCalls++; return pctExecImpl(...a); },
  pctPushFromString: async () => true,
});

const gw = require(path.join(UTILS, 'gateway-lifecycle.js'));

const NODE = 'cyberhub-node-8';
const VMID = 110881;
// Every call passes these. Production passes neither, so the real ladder still
// sleeps 6s between attempts and polls every 2s.
const FAST = { retryMs: 0, pollMs: 0 };

// ── startGatewayAndConfirm ──────────────────────────────────────────────────

test('a gateway that comes up is one start, one confirmation, no retries', async () => {
  resetCluster();
  statusPlan = ['running'];

  const r = await gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.deepStrictEqual(r, { running: true, statusReadable: true, lastStatus: 'running' });
  assert.strictEqual(calls.starts.length, 1, 'a healthy gateway must not be started twice');
  assert.match(calls.starts[0], /\/nodes\/cyberhub-node-8\/lxc\/110881\/status\/start$/);
  assert.strictEqual(calls.tasks.length, 1, 'the start UPID must be awaited, not discarded');
});

test('THE BUG: the start UPID is awaited, so nothing probes a container still booting', async () => {
  // POST .../status/start returns a UPID and starts the container
  // ASYNCHRONOUSLY. Awaiting only the POST means the deploy races its own
  // gateway: waitForGatewayFirstboot begins probing over `pct exec`, every probe
  // answers "container not running", and five of those inside ~15s exhausted its
  // give-up budget on a gateway that was always going to come up.
  resetCluster();
  statusPlan = ['running'];

  await gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.strictEqual(calls.tasks.length, 1);
  assert.match(calls.tasks[0], /^UPID:/);
});

test('a transient start failure is retried and the lane survives it', async () => {
  // The whole reason the ladder exists: the pre-start mount fails, then succeeds
  // seconds later once udev has caught up. `lxc-start -F` on the failing VMID
  // booted to a login prompt and fsck came back clean — nothing was wrong with
  // the container.
  resetCluster();
  // 15 polls of 'stopped' exhausts attempt 1, then attempt 2 finds it running.
  statusPlan = [...Array(15).fill('stopped'), 'running'];

  const r = await gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.strictEqual(r.running, true);
  assert.strictEqual(calls.starts.length, 2, 'exactly one retry should have been needed');
});

test('a gateway that never starts throws, naming the task log and the real cause', async () => {
  resetCluster();
  statusPlan = ['stopped'];

  await assert.rejects(
    () => gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST }),
    (err) => {
      // The message has to send the reader to the one file that explains it.
      assert.match(err.message, /vzstart:110881/, 'must name the start task to read');
      assert.match(err.message, /lxc\.hook\.pre-start/, 'must name the hook that actually failed');
      assert.match(err.message, /not a damaged container/, 'must stop someone rebuilding a healthy CT');
      assert.match(err.message, /3 start attempts/);
      assert.match(err.message, /is 'stopped', not running/);
      // Tagged, not just thrown: challenge-lane-deployer branches on this to
      // destroy the gateway and re-place the lane on another node. Without the
      // tag a start failure is indistinguishable from a clone failure.
      assert.strictEqual(err.gatewayNotRunning, true, 'must carry the gatewayNotRunning tag');
      assert.strictEqual(err.node, NODE);
      assert.strictEqual(err.lastStatus, 'stopped');
      return true;
    }
  );
  assert.strictEqual(calls.starts.length, 3, 'the full ladder is three attempts, no more, no fewer');
});

test('THE RULE: an UNREADABLE status resolves — fail on evidence, never on its absence', async () => {
  // Six test files replace proxmox.js wholesale and answer {} to every URL they
  // do not recognise. Treating that as "not running" would fail deploys across
  // suites that have nothing to do with gateways, and would make the ladder burn
  // its whole budget arguing with a mock.
  resetCluster();
  statusPlan = [null];

  const r = await gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.deepStrictEqual(r, { running: false, statusReadable: false, lastStatus: null });
  assert.strictEqual(calls.starts.length, 1, 'an unreadable status must not trigger the retry ladder');
});

test('a start task that reports oddly is not proof the container is down', async () => {
  // waitForTask throwing is NOT decisive. Proxmox has been seen reporting a
  // non-OK exitstatus for a start that worked; the status read is the authority.
  resetCluster();
  taskBehaviour = 'throw';
  statusPlan = ['running'];

  const r = await gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.strictEqual(r.running, true);
  assert.strictEqual(calls.starts.length, 1, 'a throwing task must not by itself force a retry');
});

test('when every attempt fails, the task error is named in the final message', async () => {
  resetCluster();
  taskBehaviour = 'throw';
  statusPlan = ['stopped'];

  await assert.rejects(
    () => gw.startGatewayAndConfirm({ node: NODE, gatewayVmid: VMID, ...FAST }),
    /status 32/
  );
});

// ── ensureGatewayRunning ────────────────────────────────────────────────────

test('ensureGatewayRunning does not POST start at a container already running', async () => {
  // Proxmox answers "CT 110881 already running" to a redundant start, which the
  // ladder records as startErr and then spends its whole budget arguing with a
  // perfectly healthy lane. deployLaneVms calls this on a gateway the gateway
  // phase already started, so the common case must be a single status read.
  resetCluster();
  statusPlan = ['running'];

  const r = await gw.ensureGatewayRunning({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.deepStrictEqual(r, { running: true, statusReadable: true, lastStatus: 'running' });
  assert.strictEqual(calls.starts.length, 0, 'a running gateway must never be re-started');
  assert.strictEqual(calls.statuses.length, 1, 'one read is enough to answer');
});

test('ensureGatewayRunning starts a stopped gateway and still throws when it will not come up', async () => {
  resetCluster();
  statusPlan = ['stopped'];

  await assert.rejects(
    () => gw.ensureGatewayRunning({ node: NODE, gatewayVmid: VMID, ...FAST }),
    (err) => err.gatewayNotRunning === true
  );
  assert.strictEqual(calls.starts.length, 3);
});

test('ensureGatewayRunning on an unreadable status falls through to one start, not a throw', async () => {
  resetCluster();
  statusPlan = [null];

  const r = await gw.ensureGatewayRunning({ node: NODE, gatewayVmid: VMID, ...FAST });

  assert.strictEqual(r.statusReadable, false);
  assert.strictEqual(calls.starts.length, 1);
});

// ── confirmGatewayRunning / readGatewayStatus ───────────────────────────────

test('readGatewayStatus reports null for an unreadable answer and never throws', async () => {
  resetCluster();
  statusPlan = [null];
  assert.strictEqual(await gw.readGatewayStatus(NODE, VMID), null);

  resetCluster();
  statusPlan = ['stopped'];
  assert.strictEqual(await gw.readGatewayStatus(NODE, VMID), 'stopped');
});

test('confirmGatewayRunning stops at the first unreadable answer rather than polling it out', async () => {
  resetCluster();
  statusPlan = [null];

  const r = await gw.confirmGatewayRunning({ node: NODE, gatewayVmid: VMID, polls: 15, pollMs: 0 });

  assert.deepStrictEqual(r, { running: false, statusReadable: false, lastStatus: null });
  assert.strictEqual(calls.statuses.length, 1, 'polling an unreadable endpoint 15 times proves nothing');
});

test('confirmGatewayRunning polls a stopped container for the whole window', async () => {
  resetCluster();
  statusPlan = ['stopped'];

  const r = await gw.confirmGatewayRunning({ node: NODE, gatewayVmid: VMID, polls: 4, pollMs: 0 });

  assert.deepStrictEqual(r, { running: false, statusReadable: true, lastStatus: 'stopped' });
  assert.strictEqual(calls.statuses.length, 4);
});

// ── waitForGatewayFirstboot ─────────────────────────────────────────────────

test('firstboot is observed when the marker appears', async () => {
  pctExecCalls = 0;
  pctExecImpl = async () => ({ stdout: 'firstboot-done\n', stderr: '', code: 0 });

  assert.strictEqual(await gw.waitForGatewayFirstboot(NODE, VMID, { timeoutMs: 500 }), true);
});

test('THE OTHER BUG: "container not running" must not count toward the give-up budget', async () => {
  // This string is the DEFINITION of not-ready-yet, not of a broken channel.
  // Counting it made a slow boot look like an unreachable node: five of them
  // inside 15s and the probe abandoned a gateway that was still starting — which
  // on a malware profile is a hard deploy failure ("Malware gateway first boot
  // could not be verified").
  pctExecCalls = 0;
  pctExecImpl = async () => { throw new Error("nodeExec exit 255: container '110881' not running!"); };

  const ok = await gw.waitForGatewayFirstboot(NODE, VMID, { timeoutMs: 250, probeMs: 0 });

  assert.strictEqual(ok, false, 'it still gives up at the deadline — it just does not give up EARLY');
  assert.ok(pctExecCalls > 5,
    `probe gave up after ${pctExecCalls} attempts — "not running" must not exhaust the 5-error budget`);
});

test('a genuinely broken SSH channel stops the probe immediately', async () => {
  // The counterweight to the test above: a lane deploy that cannot SSH the node
  // is a supported degraded outcome, and burning 180s per lane before reaching
  // it would turn one misconfigured key into a class-wide stall.
  pctExecCalls = 0;
  pctExecImpl = async () => { throw new Error('nodeExec exit 255: Permission denied (publickey).'); };

  const ok = await gw.waitForGatewayFirstboot(NODE, VMID, { timeoutMs: 5000 });

  assert.strictEqual(ok, false);
  assert.strictEqual(pctExecCalls, 1, 'a named-fatal channel error must stop on the first probe');
});

test('EVERY scheme waits now — subnetScheme no longer skips the firstboot marker', async () => {
  // History, because the option is still in the signature and looks live.
  // waitForGatewayFirstboot used to early-return true for subnetScheme 'v1':
  // 00-cybercore-firstboot.start -- the thing that renders dnsmasq.conf, installs
  // the CYBERCORE-KALI-RDP DNAT and persists /etc/iptables/rules-save -- is a
  // v2_gateway artifact, and template 1692 never received it, so the marker grep
  // could never match and every v1 lane burned the full 180s deadline in silence.
  //
  // v1 is retired. Both surviving gateway generations (1694, 1695) write the
  // marker, the early return is gone, and `subnetScheme` is accepted and ignored.
  // This test is the guard on that: if anyone reintroduces a scheme-shaped skip,
  // the firstboot race comes straight back -- firstboot rewrites /etc/dnsmasq.conf
  // from scratch and re-adds its baked dhcp-host=kali line, so a reservation
  // written before it lands leaves two entries claiming the same address and
  // dnsmasq refuses to start at all. 'v1' is in the loop deliberately: a stale
  // row on an un-migrated deployment must WAIT like everything else, not be
  // waved through.
  for (const scheme of ['v2', 'v3', 'v1', null, undefined]) {
    pctExecCalls = 0;
    pctExecImpl = async () => ({ stdout: '', stderr: '', code: 0 });
    const ok = await gw.waitForGatewayFirstboot(NODE, VMID, { subnetScheme: scheme, timeoutMs: 60, probeMs: 0 });
    assert.strictEqual(ok, false, `scheme ${scheme} must still require the marker`);
    assert.ok(pctExecCalls > 0, `scheme ${scheme} must actually probe`);
  }
});

test('the firstboot probe accepts a v3 gateway, not just v2', async () => {
  // v2 renders one flat `interface=lan0`; the v3 segmented gateway renders
  // `interface=ext0` and `interface=int0`. A probe that only knew lan0 was never
  // satisfied on a v3 lane — it sat out the full 180s and returned false every
  // time. Asserted on the probe text because the grep runs inside the container.
  let seen = null;
  pctExecImpl = async (node, vmid, argv) => {
    seen = argv.join(' ');
    return { stdout: 'firstboot-done', stderr: '', code: 0 };
  };

  await gw.waitForGatewayFirstboot(NODE, VMID, { timeoutMs: 500 });

  assert.match(seen, /interface=\(lan0\|ext0\)/, 'the probe must accept both gateway generations');
  assert.match(seen, /CYBERCORE-KALI-RDP/, 'the rules-save marker is what proves firstboot finished');
});
