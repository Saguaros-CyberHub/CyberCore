/**
 * lane-wan-allocator.test.js
 *
 * The allocator replaced `base + 10 + (vxlanId % 240)`, which handed two live
 * lanes the same gateway address and therefore the same Guacamole console host.
 * Every test here pins one of the properties that made the replacement worth
 * doing:
 *
 *   - a reserved / live / in-flight address is never returned
 *   - an address that ANSWERS ARP is skipped even when the database says free
 *   - a probe that cannot actually reach the VLAN REFUSES rather than reporting
 *     everything free (the failure mode that would quietly reintroduce the bug
 *     with a check standing in front of it)
 *   - two concurrent batches never overlap
 *   - exhaustion throws with the numbers rather than reissuing
 *
 * Postgres and ssh are stubbed; the candidate SQL's exclusion and ordering
 * contract is modelled in JS by the fake query layer, so it is exercised rather
 * than asserted about.
 *
 * Run: node --test front-end/test/lane-wan-allocator.test.js
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stubModule(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// ── world state the stubs answer from ────────────────────────────────────────
const world = {
  liveLaneIps: new Set(),
  reserved: ['100.100.60.1', '100.100.60.0', '100.100.63.255'],
  inFlightTokenIps: new Set(),
  lastUsed: new Map(),        // ip -> epoch ms
  arpAnswers: new Set(),      // ips that reply to arping
  hasArping: true,
  hasIface: true,
  sshFails: false,
  probeEnabled: true,
  hostFirst: '100.100.60.10',
  hostLast: '100.100.60.20',  // deliberately tiny, so exhaustion is reachable
  leases: [],
  execScripts: [],
  queryHook: null,   // (sql, params) => Error | null, for fault injection
};

function reset(over = {}) {
  Object.assign(world, {
    liveLaneIps: new Set(),
    inFlightTokenIps: new Set(),
    lastUsed: new Map(),
    arpAnswers: new Set(),
    hasArping: true,
    hasIface: true,
    sshFails: false,
    probeEnabled: true,
    hostFirst: '100.100.60.10',
    hostLast: '100.100.60.20',
    leases: [],
    execScripts: [],
    queryHook: null,
  }, over);
  alloc._internal._reservedWanIps.clear();
  alloc._internal._probeReady.clear();
}

const toInt = ip => ip.split('.').reduce((n, o) => n * 256 + Number(o), 0);
const toIp = n => [
  Math.floor(n / 16777216) % 256, Math.floor(n / 65536) % 256,
  Math.floor(n / 256) % 256, n % 256,
].join('.');

stubModule('site-config.js', {
  getClusterNodes: () => ['node1', 'node2'],
  getV2LabNetwork: () => ({
    bridge: 'vmbr0', vlan_tag: 60,
    subnet: '100.100.60.0/22', network: '100.100.60.0', broadcast: '100.100.63.255',
    prefix_len: 22, cidr: '/22', subnet_base: '100.100.60', gateway: '100.100.60.1',
    host_range: { first: world.hostFirst, last: world.hostLast },
    reserved: world.reserved,
    probe: { enabled: world.probeEnabled, node: null, interface: 'vmbr0.60', timeout_ms: 2000 },
  }),
});

// Models the candidate SQL in JS: the pool, minus reserved, minus live lanes,
// minus in-flight bootstrap tokens, ordered by last-used NULLS FIRST then
// address.
stubModule('cybercore-db.js', {
  cybercoreQuery: async (sql, params) => {
    // The allocator destructures cybercoreQuery at require time, so a test
    // cannot swap the export out afterwards — the binding is already made.
    // Route fault injection through the stub itself instead.
    if (world.queryHook) {
      const injected = world.queryHook(sql, params);
      if (injected) throw injected;
    }
    if (/INSERT INTO cybercore_lane_wan_lease/.test(sql)) {
      world.leases.push({ ip: params[0], laneId: params[1], vxlanId: params[2] });
      return { rows: [] };
    }
    if (/live_lanes/.test(sql)) {
      return { rows: [{ live_lanes: world.liveLaneIps.size, in_flight: world.inFlightTokenIps.size }] };
    }
    if (/WITH pool AS/.test(sql)) {
      const limit = params[4];
      // params[5] is the already-probed exclusion list. Modelling it matters:
      // without it the query re-serves the same rows every round and the
      // allocator's round-based search can never walk past a run of squatters.
      const exclude = new Set(params[5] || []);
      const out = [];
      for (let n = toInt(world.hostFirst); n <= toInt(world.hostLast); n++) {
        const ip = toIp(n);
        if (world.reserved.includes(ip)) continue;
        if (world.liveLaneIps.has(ip)) continue;
        if (world.inFlightTokenIps.has(ip)) continue;
        if (exclude.has(ip)) continue;
        out.push(ip);
      }
      out.sort((a, b) => {
        const la = world.lastUsed.has(a), lb = world.lastUsed.has(b);
        if (la !== lb) return la ? 1 : -1;                        // NULLS FIRST
        if (la && world.lastUsed.get(a) !== world.lastUsed.get(b)) {
          return world.lastUsed.get(a) - world.lastUsed.get(b);   // oldest first
        }
        return toInt(a) - toInt(b);
      });
      return { rows: out.slice(0, limit).map(ip => ({ ip })) };
    }
    return { rows: [] };
  },
});

stubModule('node-ssh.js', {
  nodeExec: async (node, args) => {
    const script = args[args.length - 1];
    world.execScripts.push(script);
    if (world.sshFails) throw new Error('ssh: connect to host node1 port 22: No route to host');
    if (/command -v arping/.test(script)) {
      return { stdout: (world.hasArping ? 'has-arping\n' : '') + (world.hasIface ? 'has-iface\n' : '') };
    }
    const ips = [...script.matchAll(/-I "[$]IF" (\d+\.\d+\.\d+\.\d+)/g)].map(m => m[1]);
    return { stdout: ips.map(ip => (world.arpAnswers.has(ip) ? 'TAKEN ' : 'FREE ') + ip).join('\n') + '\n' };
  },
});

const alloc = require(path.join(UTILS, 'lane-wan-allocator.js'));
const addrs = async (n, opts) => (await alloc.allocateLaneWanIps(n, opts)).map(w => w.address);

// ── tests ────────────────────────────────────────────────────────────────────

test('hands out distinct free addresses, lowest first', async () => {
  reset({ probeEnabled: false });
  assert.deepStrictEqual(await addrs(3), ['100.100.60.10', '100.100.60.11', '100.100.60.12']);
});

test('carries the configured prefix, not a hardcoded /24', async () => {
  reset({ probeEnabled: false });
  const [w] = await alloc.allocateLaneWanIps(1);
  assert.strictEqual(w.ip, '100.100.60.10/22');
  assert.strictEqual(w.gw, '100.100.60.1');
  assert.strictEqual(w.vlanTag, 60);
});

test('never returns an address a live lane holds', async () => {
  reset({ probeEnabled: false });
  world.liveLaneIps.add('100.100.60.10');
  world.liveLaneIps.add('100.100.60.11');
  assert.deepStrictEqual(await addrs(2), ['100.100.60.12', '100.100.60.13']);
});

test('never returns a reserved address — including the subnet gateway', async () => {
  reset({ probeEnabled: false, hostFirst: '100.100.60.1', hostLast: '100.100.60.12' });
  const got = await addrs(3);
  assert.ok(!got.includes('100.100.60.1'), 'gateway must never be handed out');
  assert.ok(!got.includes('100.100.60.0'), 'network address must never be handed out');
});

test('never returns an address an unconsumed bootstrap token claims', async () => {
  // A gateway is about to come up on it; its lane row does not exist yet.
  reset({ probeEnabled: false });
  world.inFlightTokenIps.add('100.100.60.10');
  assert.deepStrictEqual(await addrs(1), ['100.100.60.11']);
});

test('skips an address that answers ARP even though the database says free', async () => {
  // The case only the wire can see: markLaneError sets status='error', which
  // releases the address from the partial unique index, while the gateway LXC
  // that was already cloned is still running on it.
  reset();
  world.arpAnswers.add('100.100.60.10');
  world.arpAnswers.add('100.100.60.11');
  assert.deepStrictEqual(await addrs(1), ['100.100.60.12']);
});

test('REFUSES to allocate when the probe interface is missing', async () => {
  // The most important test in the file. An arping on an interface that is not
  // in the VLAN answers "free" for every address, so a tolerant fallback here
  // would reintroduce the collision bug with a check standing in front of it.
  reset({ hasIface: false });
  await assert.rejects(() => alloc.allocateLaneWanIps(1), /vmbr0\.60 is missing/);
  await assert.rejects(() => alloc.allocateLaneWanIps(1), /refused rather than guessed/);
});

test('REFUSES to allocate when arping is not installed', async () => {
  reset({ hasArping: false });
  await assert.rejects(() => alloc.allocateLaneWanIps(1), /iputils-arping/);
});

test('REFUSES to allocate when the probe node is unreachable', async () => {
  reset({ sshFails: true });
  await assert.rejects(() => alloc.allocateLaneWanIps(1), /refused rather than guessed/);
});

test('the probe can be turned off deliberately, and then the database alone decides', async () => {
  reset({ probeEnabled: false, hasIface: false, hasArping: false });
  assert.deepStrictEqual(await addrs(1), ['100.100.60.10']);
});

test('a candidate with no arping verdict is treated as in use, not as free', async () => {
  reset();
  const ssh = require(path.join(UTILS, 'node-ssh.js'));
  const realExec = ssh.nodeExec;
  ssh.nodeExec = async (node, args) => {
    const script = args[args.length - 1];
    if (/command -v arping/.test(script)) return realExec(node, args);
    return { stdout: '' };   // a truncated or crashed probe reports on nothing
  };
  try {
    await assert.rejects(() => alloc.allocateLaneWanIps(1), /allocation failed/);
  } finally {
    ssh.nodeExec = realExec;
  }
});

test('a missing optional table degrades instead of blocking every deploy', async () => {
  // cybercore_lane_wan_lease (migration 033) and lane_bootstrap_tokens (017) are
  // hand-run files. If one is absent the allocator must still protect against
  // the collision it exists to prevent — it just loses cooldown ordering and the
  // in-flight exclusion.
  reset({ probeEnabled: false });
  let sawFallback = false;
  world.queryHook = (sql) => {
    if (!/WITH pool AS/.test(sql)) return null;
    if (/cybercore_lane_wan_lease/.test(sql)) {
      const e = new Error('relation "cybercore_lane_wan_lease" does not exist');
      e.code = '42P01';
      return e;
    }
    sawFallback = true;   // the retry, with the optional clauses dropped
    return null;
  };
  try {
    world.liveLaneIps.add('100.100.60.10');
    assert.deepStrictEqual(await addrs(1), ['100.100.60.11'],
      'still skips the live lane — the protection that matters is intact');
    assert.ok(sawFallback, 'should have retried without the optional clauses');
  } finally {
    world.queryHook = null;
  }
});

test('a non-missing-table SQL error is NOT swallowed', async () => {
  reset({ probeEnabled: false });
  world.queryHook = (sql) => {
    if (!/WITH pool AS/.test(sql)) return null;
    const e = new Error('connection terminated unexpectedly');
    e.code = '57P01';
    return e;
  };
  try {
    await assert.rejects(() => alloc.allocateLaneWanIps(1), /connection terminated/);
  } finally {
    world.queryHook = null;
  }
});

test('two concurrent batches never overlap', async () => {
  reset({ probeEnabled: false, hostLast: '100.100.63.254' });
  const [a, b] = await Promise.all([addrs(5), addrs(5)]);
  const all = [...a, ...b];
  assert.strictEqual(new Set(all).size, 10, `overlap: ${all.join(', ')}`);
});

test('an in-process reservation holds until the lane row exists', async () => {
  reset({ probeEnabled: false });
  const first = await addrs(2);
  // The rows have not been INSERTed yet, so the database still reports these free.
  const second = await addrs(2);
  assert.strictEqual(new Set([...first, ...second]).size, 4);
});

test('releasing puts an unused address straight back', async () => {
  reset({ probeEnabled: false });
  const [a] = await addrs(1);
  await alloc.releaseLaneWanIps([a]);
  assert.deepStrictEqual(await addrs(1), [a]);
});

test('cooldown: a previously-used address comes after every never-used one', async () => {
  reset({ probeEnabled: false, hostFirst: '100.100.60.10', hostLast: '100.100.60.12' });
  world.lastUsed.set('100.100.60.10', 1000);   // torn down most recently
  world.lastUsed.set('100.100.60.11', 500);    // torn down longer ago
  // .12 was never used, so it goes first; then the longest-idle of the rest.
  // This is what keeps a stale Guacamole connection or OPNsense ARP entry from
  // pointing at a different student's gateway.
  assert.deepStrictEqual(await addrs(3), ['100.100.60.12', '100.100.60.11', '100.100.60.10']);
});

test('a genuinely full pool says so, and points at the subnet prefix', async () => {
  reset({ probeEnabled: false, hostFirst: '100.100.60.10', hostLast: '100.100.60.12' });
  await assert.rejects(
    () => alloc.allocateLaneWanIps(5),
    (e) => /allocation failed: needed 5 address\(es\), found 3/.test(e.message)
        && /100\.100\.60\.0\/22/.test(e.message)
        && /pool is genuinely full/.test(e.message)
        && /Widen cluster\.networking\.v2_lab_network\.subnet/.test(e.message)
        && /OPNsense VLAN-60 interface FIRST/.test(e.message)
  );
});

test('squatters do NOT stop the search — it walks past them into the free set', async () => {
  // THE REGRESSION THIS FILE EXISTS FOR. The first version fetched one batch of
  // n*2+8 candidates; when a run of orphaned gateway LXCs occupied all of them
  // it reported "pool exhausted" with ~150 addresses free behind it and told the
  // operator to widen the subnet. Observed live: 90 lanes on a 242-address pool,
  // 10 candidates fetched, 10 squatted, deploy refused.
  reset({ hostFirst: '100.100.60.10', hostLast: '100.100.60.254' });
  for (let i = 10; i <= 80; i++) world.arpAnswers.add('100.100.60.' + i);
  assert.deepStrictEqual(await addrs(2), ['100.100.60.81', '100.100.60.82']);
});

test('a wall of squatters is reported as ONE line, not one per address', async () => {
  reset({ hostFirst: '100.100.60.10', hostLast: '100.100.60.254' });
  for (let i = 10; i <= 60; i++) world.arpAnswers.add('100.100.60.' + i);
  const warns = [];
  const realWarn = console.warn;
  console.warn = (...a) => warns.push(a.join(' '));
  try { await addrs(1); } finally { console.warn = realWarn; }
  const squatterLines = warns.filter(w => /answered ARP/.test(w));
  assert.strictEqual(squatterLines.length, 1, 'exactly one summary line');
  assert.match(squatterLines[0], /51 address\(es\) answered ARP/);
  assert.match(squatterLines[0], /\+39 more/, 'the list is truncated, not dumped');
});

test('too many squatters blames the orphans, NOT the subnet prefix', async () => {
  // Wrong diagnosis is worse than no diagnosis: the operator widens a /24 that
  // was never the problem and the orphaned gateways keep eating the pool.
  reset({ hostFirst: '100.100.60.10', hostLast: '100.100.60.254' });
  for (let i = 10; i <= 254; i++) world.arpAnswers.add('100.100.60.' + i);
  await assert.rejects(
    () => alloc.allocateLaneWanIps(1),
    (e) => /allocation failed/.test(e.message)
        && /orphaned gateway LXCs/.test(e.message)
        && !/pool is genuinely full/.test(e.message)
  );
});

test('a rejected allocation does not poison the mutex for later callers', async () => {
  // routes/workstations.js chains its vmid mutex with .then(fn) only, which
  // leaves a rejected promise at the head and breaks every later caller in the
  // process. This allocator must not reproduce that.
  reset({ probeEnabled: false, hostFirst: '100.100.60.10', hostLast: '100.100.60.12' });
  await assert.rejects(() => alloc.allocateLaneWanIps(9));
  assert.deepStrictEqual(await addrs(1), ['100.100.60.10']);
});

test('recordLaneWanLease strips any prefix and writes history', async () => {
  reset({ probeEnabled: false });
  const ok = await alloc.recordLaneWanLease({ address: '100.100.60.10/22', laneId: 'l1', vxlanId: 10582 });
  assert.strictEqual(ok, true);
  assert.deepStrictEqual(world.leases[0], { ip: '100.100.60.10', laneId: 'l1', vxlanId: 10582 });
});

test('the probe script targets the tagged VLAN interface, not the bare bridge', async () => {
  reset();
  await addrs(1);
  const probe = world.execScripts.find(s => /arping -q/.test(s));
  assert.match(probe, /IF=vmbr0\.60/);
  assert.match(probe, /arping -q -c 2 -w 1 -D -I "[$]IF"/);
});
