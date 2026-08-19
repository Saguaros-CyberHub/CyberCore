/**
 * ============================================================================
 * LANE WAN TRANSIT ADDRESS ALLOCATOR
 * ----------------------------------------------------------------------------
 * Every v2/v3 lane gateway's wan0 lands on one shared VLAN (the "lab network",
 * 100.100.60.0/22 by default). That address is also the Guacamole console host
 * for every machine in the lane - guacd has no route into the lane's own
 * 10.x.y.0/24, so the gateway's wan0 DNAT is the only way in.
 *
 * It used to be derived: base + 10 + (vxlanId % 240). That is not an allocation,
 * it is a hash with 240 buckets, and VXLAN ids climb monotonically forever
 * (lab-network-provision.allocateVxlanBlock never reuses a freed block). Two live
 * lanes 240 ids apart got the SAME address on a shared broadcast domain and the
 * SAME Guacamole host:port - two students' consoles racing for whichever gateway
 * answered ARP first. Nothing checked the database, a reserved list, or the wire.
 *
 * This module replaces that with a real allocation:
 *   1. candidates from the configured pool, minus live lanes, minus the
 *      site.json reserved list, minus addresses an unconsumed bootstrap token
 *      says a gateway is about to claim
 *   2. ordered by longest cooldown, so a torn-down lane's address is not handed
 *      straight back to the next student while stale Guacamole connections and
 *      ARP entries still point at it
 *   3. ARP-probed on the lab VLAN before it is committed, which is the only way
 *      to see a squatter the database cannot know about
 *   4. persisted on cybercore_lane.gateway_wan_ip, behind a partial unique index
 *
 * WHY IT IS NOT IN lane-networking.js
 *   That module is required by three route files, the CIAB plugin,
 *   topology-validate and the tests - and test/lane-deployer-slots.test.js loads
 *   it deliberately unstubbed because it is "mostly pure maths". This one
 *   reaches Postgres and ssh. Keep the pure maths pure.
 * ============================================================================
 */

const { cybercoreQuery } = require('./cybercore-db');
const nodeSsh = require('./node-ssh');
const { getV2LabNetwork, getClusterNodes } = require('./site-config');
const { ipToInt } = require('./ipv4');

const LOG = '[WanAlloc]';

// Addresses handed out but not yet visible as a cybercore_lane row. Closes the
// window between the candidate SELECT and the INSERT, exactly as _reservedWsVmids
// does for workstation VMIDs in lane-deployer.js. TTL'd for the same reason: a
// deploy that never landed must not hold an address forever.
const _reservedWanIps = new Map();   // address -> Date.now()
const RESERVED_WAN_TTL_MS = 15 * 60 * 1000;

// Probe preflight result per node. Re-checked periodically rather than once per
// process, so fixing a node does not need an orchestrator restart.
const _probeReady = new Map();       // node -> { ok, at, detail }
const PROBE_PREFLIGHT_TTL_MS = 10 * 60 * 1000;

/**
 * Serialize the whole allocate body - candidate query, reservation, probe,
 * claim - so one batch cannot race itself or a concurrent batch.
 *
 * Chained with .then(fn, fn) like serializeLxcClone in lane-deployer.js, NOT
 * .then(fn) like the _vmidMutex in routes/workstations.js: that variant leaves a
 * rejected promise at the head of the chain, and every later caller in the
 * process inherits the rejection.
 */
let _wanMutex = Promise.resolve();
function serialize(fn) {
  const next = _wanMutex.then(fn, fn);
  _wanMutex = next.catch(() => {});
  return next;
}

function sweepReservations() {
  const cutoff = Date.now() - RESERVED_WAN_TTL_MS;
  for (const [ip, at] of _reservedWanIps) if (at < cutoff) _reservedWanIps.delete(ip);
}

/** Build a lane gateway wan config from an ALREADY-ASSIGNED address. */
function wanConfigFromAddress(address) {
  const net = getV2LabNetwork();
  const bare = String(address).split('/')[0];
  return {
    bridge:  net.bridge,
    vlanTag: net.vlan_tag,
    ip:      bare + net.cidr,   // what formatLaneGatewayNet0 concatenates
    gw:      net.gateway,
    address: bare,              // retires the .ip.split('/')[0] idiom
  };
}

// -- the probe ---------------------------------------------------------------

/** Which node to probe from. The lab VLAN is one L2 domain cluster-wide, so any
 *  node with an interface in it works - it need not be (and at allocation time
 *  is not yet) the node the lane will land on. */
function resolveProbeNode(explicit) {
  const net = getV2LabNetwork();
  const node = explicit || net.probe.node || getClusterNodes()[0];
  if (!node) {
    throw new Error(
      LOG + ' No cluster node available to probe lane WAN addresses from. Declare ' +
      'cluster.physical_cluster_ips in config/site.json, or set ' +
      'cluster.networking.v2_lab_network.probe.enabled=false to allocate from the database alone.'
    );
  }
  return node;
}

/**
 * Confirm the node can actually answer the question, and REFUSE if it cannot.
 *
 * This is the single most important guard in the file. An arping that cannot
 * reach the VLAN returns "no reply" for every address, which reads as "free" - a
 * check that silently always passes is worse than no check, because it
 * manufactures confidence. So: fail closed, with the fix inline.
 */
async function assertProbeUsable(node) {
  const cached = _probeReady.get(node);
  if (cached && Date.now() - cached.at < PROBE_PREFLIGHT_TTL_MS) {
    if (cached.ok) return;
    throw new Error(cached.detail);
  }

  const net = getV2LabNetwork();
  const iface = net.probe.interface;
  let out = '';
  try {
    // nodeExec throws on non-zero exit, so the script always exits 0 and the
    // answer is parsed from stdout.
    const r = await nodeSsh.nodeExec(node, ['/bin/sh', '-c',
      'command -v arping >/dev/null 2>&1 && echo has-arping; ' +
      'ip -o link show ' + iface + ' >/dev/null 2>&1 && echo has-iface; true',
    ], { timeoutMs: 15000 });
    out = String(r.stdout || '');
  } catch (e) {
    const detail =
      LOG + ' Cannot reach ' + node + ' over ssh to verify lane WAN addresses (' + e.message + '). ' +
      'Allocation is refused rather than guessed - check PROXMOX_SSH_KEY / PROXMOX_SSH_USER, or ' +
      'set cluster.networking.v2_lab_network.probe.enabled=false in config/site.json.';
    _probeReady.set(node, { ok: false, at: Date.now(), detail });
    throw new Error(detail);
  }

  const missing = [];
  if (!out.includes('has-arping')) missing.push('arping');
  if (!out.includes('has-iface'))  missing.push(iface);

  if (missing.length) {
    const detail =
      LOG + ' Lane WAN allocation cannot verify addresses on ' + node + ': ' + missing.join(' and ') +
      (missing.length > 1 ? ' are' : ' is') + ' missing. Every candidate would answer "free" ' +
      'whether or not something is using it, so allocation is refused rather than guessed.\n' +
      'Fix one of:\n' +
      (missing.includes('arping')
        ? '  - install the prober:  apt-get install -y iputils-arping\n' : '') +
      (missing.includes(iface)
        ? '  - create the VLAN interface (vmbr0 carries VLAN ' + net.vlan_tag + ' tagged, so an\n' +
          '    untagged probe on the bare bridge never sees a lane gateway):\n' +
          '      ip link add link vmbr0 name ' + iface + ' type vlan id ' + net.vlan_tag +
          ' && ip link set ' + iface + ' up\n' +
          '    then persist it in /etc/network/interfaces\n' +
          '  - or point cluster.networking.v2_lab_network.probe.interface at the right device\n' : '') +
      '  - or set cluster.networking.v2_lab_network.probe.enabled=false to allocate from the database alone';
    _probeReady.set(node, { ok: false, at: Date.now(), detail });
    throw new Error(detail);
  }

  _probeReady.set(node, { ok: true, at: Date.now() });
}

/**
 * ARP every candidate at once and return the set that answered.
 *
 * arping -D is duplicate-address-detection mode: it sources from 0.0.0.0 (so the
 * probe interface needs no address of its own - vmbr0.60 is `inet manual` on
 * every node) and exits 0 when NOBODY replies. Layer 2, so a gateway's INPUT
 * firewall cannot hide it the way it can hide ICMP. Fanned out, so a whole batch
 * costs one ssh round trip rather than one per address.
 */
async function probeTakenAddresses(node, candidates) {
  const net = getV2LabNetwork();
  if (!candidates.length) return new Set();

  const script =
    'IF=' + net.probe.interface + '\n' +
    candidates.map(ip =>
      '( arping -q -c 2 -w 1 -D -I "$IF" ' + ip +
      ' >/dev/null 2>&1 && echo "FREE ' + ip + '" || echo "TAKEN ' + ip + '" ) &'
    ).join('\n') +
    '\nwait\n';

  const budget = Math.max(30000, net.probe.timeout_ms + 15000);
  const { stdout } = await nodeSsh.nodeExec(node, ['/bin/sh', '-c', script], { timeoutMs: budget });

  const taken = new Set();
  const seen = new Set();
  for (const line of String(stdout || '').split('\n')) {
    const m = line.trim().match(/^(FREE|TAKEN)\s+(\S+)$/);
    if (!m) continue;
    seen.add(m[2]);
    if (m[1] === 'TAKEN') taken.add(m[2]);
  }

  // A candidate with no verdict was never actually tested. Treat it as taken:
  // the whole point of this function is that "no evidence" must not read as
  // "free".
  for (const ip of candidates) {
    if (!seen.has(ip)) {
      taken.add(ip);
      console.warn(LOG + ' ' + ip + ' produced no arping verdict on ' + node + ' - treating as in use.');
    }
  }
  return taken;
}

// -- candidate selection -----------------------------------------------------

/**
 * Free addresses in the pool, longest-cooldown first.
 *
 * Ordering is last_allocated_at NULLS FIRST, ip: never-used addresses in
 * ascending order (so the pool stays dense and readable while it is young),
 * then, once the range has been touched, longest-since-handed-out. That is what
 * keeps a torn-down lane's address from being reissued while a stale Guacamole
 * connection or an OPNsense ARP entry still points at the previous holder.
 */
async function candidateAddresses(limit) {
  const net = getV2LabNetwork();
  const firstOffset = ipToInt(net.host_range.first) - ipToInt(net.network);
  const lastOffset  = ipToInt(net.host_range.last)  - ipToInt(net.network);

  try {
    return await candidateQuery(net, firstOffset, lastOffset, limit, true);
  } catch (e) {
    // 42P01 undefined_table. cybercore_lane_wan_lease comes from migration 033
    // (and the boot hook), lane_bootstrap_tokens from 017 — both are hand-run
    // files. Blocking every lane deploy on a missing optional table is a worse
    // outcome than allocating with less information, so degrade and say so.
    // The lane table and the reserved list, which do the actual collision
    // prevention, are still consulted; only cooldown ordering and the in-flight
    // exclusion are lost.
    if (e.code !== '42P01') throw e;
    console.warn(
      `${LOG} Allocating without lease history / in-flight tokens: ${e.message}. ` +
      `Run migrations/033_lane_wan_ip.sql (and 017_lane_bootstrap_tokens.sql). Addresses are ` +
      `still checked against live lanes, the reserved list and ARP.`
    );
    return candidateQuery(net, firstOffset, lastOffset, limit, false);
  }
}

async function candidateQuery(net, firstOffset, lastOffset, limit, withOptional) {
  const res = await cybercoreQuery(`
    WITH pool AS (
      SELECT (host($1::cidr)::inet + gs) AS ip
        FROM generate_series($2::bigint, $3::bigint) AS gs
    ),
    live AS (
      SELECT DISTINCT gateway_wan_ip AS ip
        FROM cybercore_lane
       WHERE gateway_wan_ip IS NOT NULL
         AND status NOT IN ('error', 'deleted')
    ),
    last_use AS (
      ${withOptional
        ? `SELECT wan_ip AS ip, MAX(allocated_at) AS last_allocated_at
             FROM cybercore_lane_wan_lease
            GROUP BY wan_ip`
        : `SELECT NULL::inet AS ip, NULL::timestamptz AS last_allocated_at WHERE FALSE`}
    )
    SELECT p.ip::text AS ip
      FROM pool p
      LEFT JOIN last_use lu ON lu.ip = p.ip
     WHERE NOT (p.ip = ANY($4::inet[]))
       AND NOT EXISTS (SELECT 1 FROM live l WHERE l.ip = p.ip)
       ${withOptional ? `AND NOT EXISTS (
             SELECT 1 FROM lane_bootstrap_tokens b
              WHERE b.wan_ip = p.ip
                AND b.consumed_at IS NULL
                AND b.expires_at > NOW())` : ''}
     ORDER BY lu.last_allocated_at NULLS FIRST, p.ip
     LIMIT $5
  `, [net.network + '/' + net.prefix_len, firstOffset, lastOffset, net.reserved, limit]);

  return res.rows.map(r => r.ip);
}

/** Counts for the exhaustion message - worth one extra query when failing. */
async function poolCensus() {
  const net = getV2LabNetwork();
  const res = await cybercoreQuery(`
    SELECT
      (SELECT COUNT(*)::int FROM cybercore_lane
        WHERE gateway_wan_ip IS NOT NULL AND status NOT IN ('error','deleted')) AS live_lanes,
      (SELECT COUNT(*)::int FROM lane_bootstrap_tokens
        WHERE consumed_at IS NULL AND expires_at > NOW())                        AS in_flight
  `).catch(() => ({ rows: [{ live_lanes: null, in_flight: null }] }));
  const size = ipToInt(net.host_range.last) - ipToInt(net.host_range.first) + 1;
  return { ...res.rows[0], usable: size - net.reserved.length };
}

// -- public API --------------------------------------------------------------

/**
 * Allocate `count` distinct WAN transit addresses.
 *
 * Called ONCE per deploy batch, BEFORE any Proxmox work, so an exhausted pool
 * fails the request rather than half a classroom.
 */
async function allocateLaneWanIps(count, { probeNode = null, logTag = LOG } = {}) {
  const n = Number(count);
  if (!Number.isInteger(n) || n < 1) {
    throw new Error('allocateLaneWanIps: count must be >= 1 (got ' + count + ')');
  }

  return serialize(async () => {
    const net = getV2LabNetwork();
    sweepReservations();

    // Over-fetch so the probe has somewhere to go when it finds squatters.
    const pool = (await candidateAddresses(n * 2 + 8))
      .filter(ip => !_reservedWanIps.has(ip));

    let usable = pool;
    if (net.probe.enabled) {
      const node = resolveProbeNode(probeNode);
      await assertProbeUsable(node);
      const taken = await probeTakenAddresses(node, pool);
      for (const ip of taken) {
        // Expected, and worth saying out loud: markLaneError sets status='error',
        // which releases the address from the partial unique index, while the
        // gateway LXC cloned by cloneGateway may still be running on it. The
        // arping is the only thing that catches that.
        console.warn(
          logTag + ' ' + ip + ' answered ARP on ' + net.probe.interface +
          ' but no live lane claims it - skipping. Either a lane whose row was deleted while ' +
          'its gateway LXC is still running, or a device outside CyberCore. Add it to ' +
          'cluster.networking.v2_lab_network.reserved in config/site.json once you know which.'
        );
      }
      usable = pool.filter(ip => !taken.has(ip));
    }

    if (usable.length < n) {
      const census = await poolCensus();
      throw new Error(
        'Lane WAN pool exhausted: needed ' + n + ' address(es), found ' + usable.length + '.\n' +
        '  Pool       ' + net.subnet + ', host range ' + net.host_range.first + '-' +
          net.host_range.last + ' (' + census.usable + ' usable)\n' +
        '  Held       ' + (census.live_lanes ?? '?') + ' by live lanes (status not in error/deleted)\n' +
        '  Reserved   ' + net.reserved.length + ' in config/site.json\n' +
        '  In flight  ' + (census.in_flight ?? '?') + ' held by unconsumed lane_bootstrap_tokens\n' +
        '  Skipped    ' + (pool.length - usable.length) + ' answered ARP with no lane row\n\n' +
        'Widen cluster.networking.v2_lab_network.subnet in config/site.json - and the matching\n' +
        'prefix on the OPNsense VLAN-' + net.vlan_tag + ' interface FIRST, or the new addresses\n' +
        'will have no route. Or tear down stale lanes: GET /api/admin/wan-conflicts.'
      );
    }

    const chosen = usable.slice(0, n);
    const now = Date.now();
    for (const ip of chosen) _reservedWanIps.set(ip, now);
    console.log(logTag + ' Allocated ' + chosen.length + ' WAN address(es) from ' + net.subnet +
                ': ' + chosen.join(', '));
    return chosen.map(wanConfigFromAddress);
  });
}

/** Drop in-process holds for addresses a deploy decided not to use. The TTL would
 *  expire them anyway; releasing now keeps a big partially-failed batch from
 *  holding a chunk of the pool for 15 minutes. */
async function releaseLaneWanIps(addresses) {
  for (const a of addresses || []) _reservedWanIps.delete(String(a).split('/')[0]);
}

/**
 * Durable "who held this address, when".
 *
 * cybercore_lane rows are HARD-deleted on teardown (admin/lanes.js,
 * lane-deployer.teardownLanes, admin/groups.js, ciab lane-deploy), so the lane
 * table cannot answer "when was this last in use" - which is exactly what the
 * cooldown ordering needs. Never fatal: a lane that deployed is worth more than
 * a perfect audit trail.
 */
async function recordLaneWanLease({ address, laneId, vxlanId }) {
  if (!address) return false;
  try {
    await cybercoreQuery(
      'INSERT INTO cybercore_lane_wan_lease (wan_ip, lane_id, vxlan_id) VALUES ($1::inet, $2, $3)',
      [String(address).split('/')[0], laneId || null, vxlanId ?? null]
    );
    return true;
  } catch (e) {
    console.warn(LOG + ' Could not record WAN lease for ' + address + ': ' + e.message);
    return false;
  }
}

/**
 * Live lanes sharing a WAN transit address. Read-only; repairs nothing.
 * Feeds GET /api/admin/wan-conflicts and the boot warning.
 */
async function findWanIpConflicts() {
  const res = await cybercoreQuery(`
    -- host(), not ::text. An INET with no mask defaults to /32, so ::text
    -- renders '100.100.60.31/32' — accurate but noise in a warning an operator
    -- reads at 2am.
    SELECT host(l.gateway_wan_ip)            AS wan_ip,
           COUNT(*)::int                     AS lane_count,
           BOOL_OR(l.wan_ip_grandfathered)   AS grandfathered,
           MIN(l.created_at)                 AS first_deployed,
           MAX(l.created_at)                 AS last_deployed,
           JSONB_AGG(
             JSONB_BUILD_OBJECT(
               'lane_id',    l.lane_id,
               'vxlan_id',   l.vxlan_id,
               'name',       l.name,
               'status',     l.status,
               'module_key', l.module_key,
               'node',       l.config->>'node',
               'owner',      u.email,
               'created_at', l.created_at
             ) ORDER BY l.created_at
           )                                 AS lanes
      FROM cybercore_lane l
      LEFT JOIN cybercore_user u ON u.user_id = l.user_id
     WHERE l.gateway_wan_ip IS NOT NULL
       AND l.status NOT IN ('error', 'deleted')
     GROUP BY l.gateway_wan_ip
    HAVING COUNT(*) > 1
     ORDER BY COUNT(*) DESC, l.gateway_wan_ip
  `);
  return res.rows;
}

module.exports = {
  allocateLaneWanIps,
  releaseLaneWanIps,
  recordLaneWanLease,
  wanConfigFromAddress,
  findWanIpConflicts,
  // exported for tests
  _internal: { _reservedWanIps, _probeReady, probeTakenAddresses, resolveProbeNode },
};
