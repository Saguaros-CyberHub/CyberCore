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

// Search bounds. The allocator walks the free set in rounds because squatters
// (orphaned gateway LXCs still answering ARP for a lane whose row is gone) can
// occupy a long contiguous run of it. PROBE_BATCH_MIN keeps each round's ssh
// round trip worthwhile; the budget and round cap stop a pathological cluster
// from ARPing an entire /22 on every deploy.
const PROBE_BATCH_MIN   = 32;
// Simultaneous arpings per ssh round trip. Unlimited fan-out is what produced
// the false-positive storm this guard exists for: dozens of concurrent probes
// against a short deadline return non-zero without any reply arriving.
const PROBE_CONCURRENCY = 8;
// A batch at least this large coming back 100% occupied is treated as a broken
// probe, not a full pool. Below this a legitimate all-taken result is plausible.
const PROBE_SANITY_MIN  = 8;
const PROBE_ROUNDS_MAX  = 8;
const PROBE_BUDGET      = 512;   // addresses probed in one allocate() call

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
 * ARP the candidates and return the set that answered.
 *
 * READS THE REPLY COUNT, NOT THE EXIT CODE. This is the whole design of this
 * function and it is not a style choice. arping's exit status conflates two
 * completely different outcomes: "somebody replied" and "the command did not
 * finish". Fan 32 of them out at once against a one-second deadline and a busy
 * node returns non-zero for most of them without a single reply having arrived —
 * which read as "occupied" and reported an entire /24 as taken while sequential
 * probes of the same addresses came back free. So: parse
 * "Received N response(s)" from arping's own summary, which says exactly what
 * happened and nothing else.
 *
 * arping -D is RFC 5227 duplicate-address-detection: it sources from 0.0.0.0, so
 * the probe interface needs no address of its own (vmbr0.60 is `inet manual` on
 * every node). Layer 2, so a gateway's INPUT firewall cannot hide it the way it
 * can hide ICMP.
 *
 * Concurrency is bounded rather than unlimited. The point is not speed — it is
 * that dozens of simultaneous broadcast probes are exactly the condition that
 * produced the false positives above.
 */
async function probeTakenAddresses(node, rawCandidates) {
  const net = getV2LabNetwork();
  if (!rawCandidates.length) return { taken: new Set(), unknown: 0 };
  // Belt and braces after the /32 incident: arping takes a bare address, and a
  // caller handing it a masked one gets silence rather than an error it can act
  // on. Strip here as well as at the query, so no future caller can reintroduce
  // it.
  const candidates = rawCandidates.map(ip => String(ip).split('/')[0]);

  const waitSecs = Math.max(2, Math.ceil((net.probe.timeout_ms || 2000) / 1000));

  const script = [
    'IF=' + net.probe.interface,
    'probe() {',
    '  out=$(arping -c 2 -w ' + waitSecs + ' -D -I "$IF" "$1" 2>&1)',
    // The summary line is "Received N response(s)". Anything else means arping
    // did not run to completion, and that must NOT be read as either answer.
    '  n=$(printf "%s" "$out" | sed -n "s/.*Received \\([0-9][0-9]*\\) response.*/\\1/p" | tail -1)',
    '  if [ -z "$n" ]; then echo "UNKNOWN $1"',
    '  elif [ "$n" -gt 0 ]; then echo "TAKEN $1"',
    '  else echo "FREE $1"; fi',
    '}',
    'i=0',
    ...candidates.map(ip =>
      'probe ' + ip + ' & i=$((i+1)); [ $((i % ' + PROBE_CONCURRENCY + ')) -eq 0 ] && wait'
    ),
    'wait',
  ].join('\n') + '\n';

  const budget = Math.max(60000, candidates.length * 1500);
  const { stdout } = await nodeSsh.nodeExec(node, ['/bin/sh', '-c', script], { timeoutMs: budget });

  const taken = new Set();
  const unknown = [];
  const seen = new Set();
  for (const line of String(stdout || '').split('\n')) {
    const m = line.trim().match(/^(FREE|TAKEN|UNKNOWN)\s+(\S+)$/);
    if (!m) continue;
    seen.add(m[2]);
    if (m[1] === 'TAKEN') taken.add(m[2]);
    if (m[1] === 'UNKNOWN') { taken.add(m[2]); unknown.push(m[2]); }
  }

  // A candidate with no verdict at all was never actually tested. Treat it as
  // taken -- "no evidence" must never read as "free" -- but count it, because a
  // pile of these means the probe is broken, not that the pool is full.
  for (const ip of candidates) {
    if (!seen.has(ip)) { taken.add(ip); unknown.push(ip); }
  }

  // UNKNOWN is the ONLY evidence that the probe itself misbehaved. A TAKEN
  // carries a real "Received N response(s)" from the wire and is a fact; the
  // caller keys its "is this probe trustworthy" decision on unknown, never on
  // how many came back occupied. A genuinely full pool answers TAKEN for
  // everything, and telling the operator that is a broken probe would be its own
  // wrong diagnosis.
  if (unknown.length) {
    console.warn(
      LOG + ' ' + unknown.length + '/' + candidates.length + ' probe(s) on ' + node +
      ' produced no usable verdict; counting them as occupied. If this persists the probe is ' +
      'not working - verify by hand on the node with:  arping -c 2 -w 2 -D -I ' +
      net.probe.interface + ' <address>'
    );
  }

  return { taken, unknown: unknown.length };
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
async function candidateAddresses(limit, exclude = []) {
  const net = getV2LabNetwork();
  const firstOffset = ipToInt(net.host_range.first) - ipToInt(net.network);
  const lastOffset  = ipToInt(net.host_range.last)  - ipToInt(net.network);

  try {
    return await candidateQuery(net, firstOffset, lastOffset, limit, true, exclude);
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
    return candidateQuery(net, firstOffset, lastOffset, limit, false, exclude);
  }
}

async function candidateQuery(net, firstOffset, lastOffset, limit, withOptional, exclude = []) {
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
    -- host(), NOT ::text. An inet with no mask renders as '100.100.60.11/32',
    -- and these strings are handed straight to arping, which rejects them as
    -- addresses and prints no "Received N response(s)" line -- so every probe
    -- came back unparseable and, under the original exit-code reading, counted
    -- as occupied. That is what reported a 242-address pool as fully taken.
    SELECT host(p.ip) AS ip
      FROM pool p
      LEFT JOIN last_use lu ON lu.ip = p.ip
     WHERE NOT (p.ip = ANY($4::inet[]))
       AND NOT (p.ip = ANY($6::inet[]))
       AND NOT EXISTS (SELECT 1 FROM live l WHERE l.ip = p.ip)
       ${withOptional ? `AND NOT EXISTS (
             SELECT 1 FROM lane_bootstrap_tokens b
              WHERE b.wan_ip = p.ip
                AND b.consumed_at IS NULL
                AND b.expires_at > NOW())` : ''}
     ORDER BY lu.last_allocated_at NULLS FIRST, p.ip
     LIMIT $5
  `, [net.network + '/' + net.prefix_len, firstOffset, lastOffset, net.reserved, limit, exclude]);

  // ONE normalization point for the whole module: every address leaving here is
  // bare. host() above already does it in SQL, but this is the guarantee — a
  // masked string escaping into the allocator breaks two things at once, and
  // both failures are silent. It goes to arping, which rejects it and produces
  // no verdict; and it becomes a _reservedWanIps key that releaseLaneWanIps,
  // which strips, can never delete — so a released address stays held until the
  // TTL expires.
  return res.rows.map(r => String(r.ip).split('/')[0]);
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

    let node = null;
    if (net.probe.enabled) {
      node = resolveProbeNode(probeNode);
      await assertProbeUsable(node);
    }

    // Search in ROUNDS rather than one over-fetched batch.
    //
    // A single batch is only correct if squatters are rare. They are not: a lane
    // marked 'error' releases its address in the database while its gateway LXC
    // keeps running and answering ARP, and a hard-deleted lane whose teardown
    // half-failed does the same. On a cluster carrying a dozen of those, a
    // one-shot fetch could come back 100% squatted and report "pool exhausted"
    // with 150 genuinely free addresses sitting right behind it. So: keep
    // pulling the next slice of the free set until enough survive the probe,
    // the database runs out, or the probe budget is spent.
    const chosen = [];
    const tried = new Set();     // candidates already offered to the probe
    const squatters = [];
    let unknownTotal = 0;      // probes that produced no usable verdict
    let dbExhausted = false;

    for (let round = 0; chosen.length < n && round < PROBE_ROUNDS_MAX; round++) {
      const need = n - chosen.length;
      const limit = Math.max(PROBE_BATCH_MIN, need * 3);
      const rows = await candidateAddresses(limit, [...tried]);

      // Short of the LIMIT means the query has nothing more to give: the
      // database-free set really is used up, which is a different diagnosis
      // from "plenty free but squatted" and gets a different remedy below.
      if (rows.length < limit) dbExhausted = true;
      // Everything we SAW advances the cursor, not just what survived
      // filtering, or a round that is entirely in-flight reservations would ask
      // the same question forever.
      for (const ip of rows) tried.add(ip);

      const batch = rows.filter(ip => !_reservedWanIps.has(ip));
      if (!batch.length) { if (dbExhausted) break; continue; }

      if (!node) {                       // probe disabled: the database decides
        chosen.push(...batch.slice(0, need));
        break;
      }
      if (tried.size > PROBE_BUDGET) break;

      const { taken, unknown } = await probeTakenAddresses(node, batch);
      unknownTotal += unknown;
      for (const ip of batch) {
        if (taken.has(ip)) squatters.push(ip);
        else if (chosen.length < n) chosen.push(ip);
      }
    }

    // ONE summary line, not one per address. A cluster with a dozen orphaned
    // gateways would otherwise bury the actual outcome under warnings.
    if (squatters.length) {
      const shown = squatters.slice(0, 12).join(', ') +
        (squatters.length > 12 ? ', +' + (squatters.length - 12) + ' more' : '');
      console.warn(
        logTag + ' ' + squatters.length + ' address(es) answered ARP on ' + net.probe.interface +
        ' with no live lane claiming them - skipped: ' + shown + '. Each is either a lane whose ' +
        'row is gone or marked error while its gateway LXC is still running, or a device outside ' +
        'CyberCore. Destroy the orphaned gateways, or add fixed devices to ' +
        'cluster.networking.v2_lab_network.reserved in config/site.json.'
      );
    }

    if (chosen.length < n) {
      const census = await poolCensus();
      const header =
        'Lane WAN allocation failed: needed ' + n + ' address(es), found ' + chosen.length + '.\n' +
        '  Pool       ' + net.subnet + ', host range ' + net.host_range.first + '-' +
          net.host_range.last + ' (' + census.usable + ' usable)\n' +
        '  Held       ' + (census.live_lanes ?? '?') + ' by live lanes (status not in error/deleted)\n' +
        '  Reserved   ' + net.reserved.length + ' in config/site.json\n' +
        '  In flight  ' + (census.in_flight ?? '?') + ' held by unconsumed lane_bootstrap_tokens\n' +
        '  Probed     ' + tried.size + ', of which ' + squatters.length +
          ' answered ARP with no lane row' +
          (unknownTotal ? ' (' + unknownTotal + ' gave no usable verdict)' : '') + '\n\n';

      // Two genuinely different problems with two different fixes, and getting
      // the attribution wrong is worse than saying nothing: an operator told to
      // widen a subnet that was never the constraint widens it, and the
      // orphaned gateways carry on eating the new space too.
      //
      // The discriminator is SQUATTERS, not whether the query ran dry. Walking
      // the entire free set and finding every address answering ARP exhausts
      // the database AND is entirely an orphan problem — an earlier version
      // keyed on dbExhausted alone and blamed the prefix for exactly that case.
      const orphanAdvice =
        'The database has free addresses, but they are occupied on the wire by machines with\n' +
        'no lane row - orphaned gateway LXCs from failed or half-torn-down lanes. Destroy\n' +
        'those, or list any legitimate fixed devices under\n' +
        'cluster.networking.v2_lab_network.reserved so they stop being probed every time.';
      const widenAdvice =
        'The pool is genuinely full - every address is held by a live lane or reserved.\n' +
        'Widen cluster.networking.v2_lab_network.subnet in config/site.json, and the matching\n' +
        'prefix on the OPNsense VLAN-' + net.vlan_tag + ' interface FIRST, or the new addresses\n' +
        'will have no route. Or tear down stale lanes: GET /api/admin/wan-conflicts.';

      // CREDIBILITY GUARD, scoped to the whole search rather than one batch.
      // Finding NOTHING free after probing a meaningful sample is not a real
      // network state -- it is what a misbehaving probe looks like. Without this
      // it presents as "the pool is full", which sends the operator off to widen
      // a subnet that was never the constraint. (A single all-occupied batch is
      // fine and expected; a run of orphaned gateways is contiguous. It is
      // finding nothing free ANYWHERE that is implausible.)
      // Keyed on UNKNOWN verdicts, not on how many came back occupied. An
      // earlier version fired whenever nothing was free, which is exactly what a
      // legitimately exhausted pool looks like - it would have told an operator
      // whose /24 really was full that their probe was broken. A TAKEN carries a
      // reply count off the wire and is evidence; an UNKNOWN is the absence of
      // evidence, and only a pile of those means the probe cannot be trusted.
      if (chosen.length === 0 && tried.size >= PROBE_SANITY_MIN && unknownTotal * 2 >= tried.size) {
        throw new Error(
          header +
          unknownTotal + ' of the ' + tried.size + ' probes produced no usable verdict at all - not\n' +
          '"occupied", but "arping did not answer the question". The probe cannot be trusted, so\n' +
          'this is NOT being reported as a full pool.\n\n' +
          'Check by hand on ' + (node || '(probe node)') + ' -- ONE AT A TIME, not in parallel:\n' +
          '  arping -c 2 -w 2 -D -I ' + net.probe.interface + ' ' + squatters[0] + '\n' +
          '  arping -c 2 -w 2 -D -I ' + net.probe.interface + ' ' + squatters[squatters.length - 1] + '\n' +
          'If those report 0 responses, the probe is at fault, not the pool. Likely causes: proxy\n' +
          'ARP on the VLAN gateway, or a node whose probe interface sees traffic it should not.\n\n' +
          'To keep provisioning while you investigate, set\n' +
          'cluster.networking.v2_lab_network.probe.enabled=false in config/site.json. The database\n' +
          'uniqueness constraint, the live-lane check and the reserved list all still apply.'
        );
      }

      throw new Error(header + (squatters.length
        ? orphanAdvice + (dbExhausted
            ? '\n\nEvery free address was walked, so once the orphans are cleared the subnet may\n' +
              'still need widening — but clear them first, or you will widen into the same problem.'
            : '')
        : widenAdvice));
    }

    const now = Date.now();
    for (const ip of chosen) _reservedWanIps.set(ip, now);
    console.log(logTag + ' Allocated ' + chosen.length + ' WAN address(es) from ' + net.subnet +
                ': ' + chosen.join(', ') +
                (squatters.length ? ' (skipped ' + squatters.length + ' ARP-occupied)' : ''));
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
