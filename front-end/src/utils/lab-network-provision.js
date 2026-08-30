/**
 * ============================================================================
 * LAB NETWORK PROVISION
 * Reserve a VXLAN block + pre-create the SDN zone & VNets for a lab, keyed to
 * a crucible_challenge row. Extracted from the inline logic in
 * routes/lab-templates.js (POST /create-lab, DELETE /lab-templates/:id) so the
 * admin route AND the CLE plugin share one implementation.
 *
 *   crucible_challenge  → cybercore_db (cybercoreQuery)
 *   SDN zones / VNets   → Proxmox (proxmoxAPI)
 *
 * The SDN apply (PUT /cluster/sdn) is asynchronous: VNet bridges materialize on
 * the nodes over the following seconds. reserveLabNetwork polls until the
 * last-created VNet bridge shows up, so a lane deploy that starts right after
 * doesn't hit `bridge '<vnet>' does not exist`.
 * ============================================================================
 */

const { cybercoreQuery } = require('./cybercore-db');
const { proxmoxAPI } = require('./proxmox');
const { computeExpectedPeers, normalizePeers } = require('./reconcile-audit');
const { getPhysicalClusterIps } = require('./site-config');
const { claimsSql } = require('./lane-claims');

// A v3 lane's internal VNet uses tag = (vxlanId + this offset). MUST match
// V3_INTERNAL_TAG_OFFSET in utils/lane-networking.js.
const V3_INTERNAL_TAG_OFFSET = 4000000;

// Proxmox SDN zone IDs must match [a-z][a-z0-9]{0,7}: lowercase, start with a
// letter, ≤8 chars. Sanitize an arbitrary string (challenge key, UUID slice,
// admin input) into a valid zone id. A leading non-letter is prefixed with 'z'
// so UUID-derived ids (which start with a digit ~62.5% of the time) don't get
// rejected with a 400 at zone-create time.
function sanitizeZoneAbbrev(raw) {
  let s = String(raw || '').replace(/[^a-z0-9]/gi, '').toLowerCase();
  if (!/^[a-z]/.test(s)) s = `z${s}`;
  return s.substring(0, 8);
}

const ZONE_RE = /^[a-z][a-z0-9]{0,7}$/;

// Base-20 encode helper for VNet naming (matches the create-lab convention).
const _ALPHABET = 'abcdefghij0123456789';
function encodeBase20(n) {
  if (n === 0) return 'a';
  let s = '';
  let x = n;
  while (x > 0) {
    s = _ALPHABET[x % 20] + s;
    x = Math.floor(x / 20);
  }
  return s.padStart(8, 'a');
}

/**
 * Find the next free VXLAN block of `numLanes` ids by scanning the vxlan_block
 * of every existing crucible_challenge. Blocks are allocated sequentially after
 * the global max, so CLE/CIAB/crucible reservations never overlap.
 *
 * @param {number} numLanes
 * @param {object} [opts]
 * @param {number} [opts.maxVxlanId]  refuse to hand out a block whose end exceeds
 *   this id. Opt-in (default: no ceiling), so existing callers are unchanged.
 *
 *   The ceiling matters because a v2/v3 lane's LAN subnet is
 *   10.[(vxlanId >> 8) & 0xFF].[vxlanId & 0xFF].0/24 (lane-networking.js:147).
 *   Above 65535 those two bytes wrap and two lanes silently share a /24 — the
 *   allocator would report success and the collision would surface much later
 *   as unexplained cross-lane traffic. Blocks only ever climb (nothing is
 *   re-used below the global max), so this is reachable given enough labs.
 */
async function allocateVxlanBlock(numLanes, { maxVxlanId = null } = {}) {
  const n = parseInt(numLanes, 10);
  if (!Number.isFinite(n) || n < 1) throw new Error(`numLanes must be >= 1 (got ${numLanes})`);

  const existing = await cybercoreQuery(
    `SELECT (spec->'vxlan_block'->>'end')::int AS vxlan_end
       FROM crucible_challenge
      WHERE spec->'vxlan_block'->>'end' IS NOT NULL`
  );
  let maxEnd = 9999; // first block starts at 10000
  for (const row of existing.rows) {
    if (row.vxlan_end && row.vxlan_end > maxEnd) maxEnd = row.vxlan_end;
  }
  const start = maxEnd + 1;
  const end = start + n - 1;
  if (maxVxlanId != null && end > maxVxlanId) {
    throw new Error(
      `Cannot reserve ${n} contiguous VXLAN ids: the next free block is ${start}-${end}, ` +
      `past the ${maxVxlanId} ceiling. Delete retired labs to reclaim the top of the range.`
    );
  }
  return { start, end };
}

/**
 * Count lanes currently holding a vxlan in [start,end].
 *
 * Was status IN ('active','deploying'), which missed 'pending' and 'suspended'.
 * Not cosmetic: this count is how teardownLabNetwork and getOrCreateProfileChallenge
 * decide a reservation is empty, so the undercount let a block that suspended lanes
 * were sitting in be deleted and re-carved underneath them.
 */
async function countActiveLanesInBlock({ start, end }) {
  const res = await cybercoreQuery(
    `SELECT COUNT(*)::int AS cnt FROM cybercore_lane
      WHERE vxlan_id BETWEEN $1 AND $2 AND ${claimsSql()}`,
    [start, end]
  );
  return res.rows[0]?.cnt || 0;
}

/**
 * Ensure the SDN zone exists and create one VNet per VXLAN in the block
 * (v3 also creates the internal VNet at the offset tag), then reload SDN and
 * wait for the bridges to materialize.
 */
async function ensureSdnZoneAndVnets({ zone, vxlanStart, vxlanEnd, subnetScheme = 'v2', log = () => {} }) {
  // 1. Zone
  const zones = await proxmoxAPI('GET', '/api2/json/cluster/sdn/zones');
  let zoneCreated = false;
  const existingZone = zones.find(z => z.zone === zone);

  if (!existingZone) {
    log(`Creating SDN zone '${zone}'...`);

    // Peers come from /cluster/status, whose type:'node' entries are the only
    // place Proxmox hands back a node's address directly.
    //
    // What this replaces read nodeStatus.network from /nodes/<node>/status — a
    // key that endpoint does not return — so peerIps was ALWAYS empty and the
    // fallback always fired, writing peers derived from each node's INDEX in the
    // array: 100.100.10.10, .11, .12 and so on. That happened to match the
    // original six nodes, which is why it went unnoticed; any node added since,
    // or addressed outside that run, got a fabricated peer.
    //
    // computeExpectedPeers throws rather than guessing. reserveLabNetwork
    // already rolls back on a throw, so failing here is safe and loud.
    const clusterStatus = await proxmoxAPI('GET', '/api2/json/cluster/status');
    const peers = computeExpectedPeers(clusterStatus, getPhysicalClusterIps()).csv;

    // Deliberately NOT passing ipam: 'pve' — CyberCore manages lane IP space
    // internally (dnsmasq inside each lane gateway). ipam:'pve' writes per-VNet
    // dnsmasq config on every node and has crashed clusters at reboot.
    await proxmoxAPI('POST', '/api2/json/cluster/sdn/zones', { zone, type: 'vxlan', peers });
    zoneCreated = true;
    log(`SDN zone '${zone}' created with peers: ${peers}`);
  } else {
    // An EXISTING zone keeps whatever peers it was created with — joining a
    // node to the cluster never updates it, so lanes placed on a new node come
    // up with no VXLAN peering. Report it here; the repair is deliberately
    // operator-driven (Audit Proxmox -> Fix Peers), because applying SDN
    // commits every pending SDN change on the cluster, not just this one.
    log(`SDN zone '${zone}' already exists`);

    // A zone created before this module owned zone creation can still carry
    // ipam:'pve' — the setting the comment above refuses to write, because it
    // puts per-VNet dnsmasq config on every node and has crashed the cluster at
    // reboot. Nothing here can safely remove it (a zone PUT applies SDN
    // cluster-wide, committing every pending change), and nothing else in the
    // codebase reads zone settings at all, so without this line the hazard is
    // invisible forever. Repair is operator-driven:
    //   pvesh set /cluster/sdn/zones/<zone> --delete ipam && pvesh set /cluster/sdn
    if (existingZone.ipam) {
      log(`WARNING: zone '${zone}' has ipam='${existingZone.ipam}'. CyberCore manages lane ` +
          `IP space itself; pve IPAM writes per-VNet dnsmasq config on every node. ` +
          `Clear it with: pvesh set /cluster/sdn/zones/${zone} --delete ipam`);
    }

    try {
      const clusterStatus = await proxmoxAPI('GET', '/api2/json/cluster/status');
      const expected = computeExpectedPeers(clusterStatus, getPhysicalClusterIps());
      const current = normalizePeers(existingZone.peers);
      if (current === null) {
        log(`WARNING: zone '${zone}' reports no peers — check it in Audit Proxmox`);
      } else {
        const missing = expected.ips.filter(ip => !current.includes(ip));
        if (missing.length) {
          log(`WARNING: zone '${zone}' is missing VXLAN peers ${missing.join(', ')} — ` +
              `lanes on those nodes will have no VXLAN peering. ` +
              `Repair with Audit Proxmox -> Fix Peers.`);
        }
      }
    } catch (e) {
      log(`Could not verify peers on zone '${zone}': ${e.message}`);
    }
  }

  // 2. VNets
  // The full set of SDN tags this block must end up with. A lane deploy later
  // looks its vnet up by tag (routes/admin/lanes.js) and 503s if it's absent,
  // so every one of these must exist in the SDN config before we return.
  const expectedTags = [];
  for (let vxlanId = vxlanStart; vxlanId <= vxlanEnd; vxlanId++) {
    expectedTags.push(vxlanId);
    if (subnetScheme === 'v3') expectedTags.push(vxlanId + V3_INTERNAL_TAG_OFFSET);
  }

  // Create one VNet, retrying transient Proxmox failures. Proxmox SDN is a
  // single cluster-wide locked config; under load or during a concurrent apply
  // it returns lock-timeout / 5xx on individual POSTs, and proxmoxAPI does not
  // retry. Swallowing those (as the old code did) left silent holes in the
  // block. "already exists" is success. Returns true iff the vnet is in place.
  const createVnet = async (tag) => {
    const vnetName = encodeBase20(tag);
    const maxAttempts = 4;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        await proxmoxAPI('POST', '/api2/json/cluster/sdn/vnets', {
          vnet: vnetName, zone, tag, alias: `${zone}-vnet-${tag}`
        });
        return true;
      } catch (e) {
        if (e.message.includes('already exists')) return true;
        if (attempt === maxAttempts) {
          log(`VNet ${vnetName} (tag ${tag}) failed after ${maxAttempts} attempts: ${e.message}`);
          return false;
        }
        await new Promise(r => setTimeout(r, 500 * attempt));
      }
    }
    return false;
  };

  // Re-list the SDN config and return the expected tags that aren't present.
  // GET /cluster/sdn/vnets includes pending (un-applied) vnets, which is exactly
  // what the deploy-time lookup keys on, so this matches the deploy's view.
  const findMissingTags = async (tags) => {
    const existing = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const present = new Set((existing || []).map(v => v.tag));
    return tags.filter(t => !present.has(t));
  };

  let vnetsCreated = 0;
  for (let i = 0; i < expectedTags.length; i++) {
    if (await createVnet(expectedTags[i])) vnetsCreated++;
    // Rate limit on the iteration count (not successes) so pacing holds even
    // when some creates fail — Proxmox can be overwhelmed by rapid SDN calls.
    if ((i + 1) % 10 === 0) await new Promise(r => setTimeout(r, 500));
  }
  log(`${vnetsCreated}/${expectedTags.length} VNets created`);

  // 3. Reload SDN, then reconcile: recreate any expected vnet still missing and
  // reload again. A silent hole here 503s a lane deploy long after the fact, so
  // verify the whole set rather than trusting the create loop.
  log('Reloading SDN...');
  await proxmoxAPI('PUT', '/api2/json/cluster/sdn');

  let missing = await findMissingTags(expectedTags);
  for (let pass = 1; pass <= 3 && missing.length > 0; pass++) {
    log(`Reconcile pass ${pass}: ${missing.length} VNet(s) missing, recreating...`);
    for (const tag of missing) await createVnet(tag);
    await proxmoxAPI('PUT', '/api2/json/cluster/sdn');
    await new Promise(r => setTimeout(r, 1000 * pass));
    missing = await findMissingTags(expectedTags);
  }
  if (missing.length > 0) {
    // Fail loudly — reserveLabNetwork catches this and rolls back the block so
    // we never report a half-provisioned lab as ready.
    const preview = missing.slice(0, 10).map(encodeBase20).join(', ');
    const err = new Error(
      `SDN provisioning incomplete: ${missing.length}/${expectedTags.length} VNet(s) ` +
      `missing after retries (${preview}${missing.length > 10 ? ', …' : ''})`
    );
    err.missingTags = missing;
    throw err;
  }

  // 4. Wait for the VNet bridges to materialize — on EVERY node a lane could
  // land on, not just one. See verifyBridgesOnAllNodes for why that matters.
  const readiness = await verifyBridgesOnAllNodes({ tags: expectedTags, log });
  const bridgesUp = readiness.ready;

  return {
    vnetsCreated, zoneCreated, bridgesUp,
    expectedVnets: expectedTags.length,
    // The per-node detail, so a caller can persist WHICH nodes were confirmed
    // rather than a bare boolean. reserveLabNetwork spreads this through.
    bridgeReadiness: readiness,
  };
}

/**
 * Create the shared readiness table if it is missing.
 *
 * WHY cybercore_db AND NOT EITHER PLUGIN. "Were this block's bridges verified,
 * when, and on which nodes?" is a fact about the RESERVATION — the
 * crucible_challenge row — not about a CIAB engagement or a CLE course. Both
 * plugins reserve through reserveLabNetwork, so storing it per-plugin means the
 * same fact written twice, by two writers, in two databases that cannot join.
 * Here there is ONE writer (the shared provisioner) and two readers.
 *
 * A boot hook rather than a migration, because migrations only run against a
 * plugin's OWN database — the same reason ensureLaneWanColumns and
 * ensureAuditLog exist. Idempotent, and safe to call on every boot.
 */
async function ensureLabReadinessTable() {
  await cybercoreQuery(`
    CREATE TABLE IF NOT EXISTS cybercore_lab_readiness (
      challenge_id      UUID PRIMARY KEY,
      bridges_ready     BOOLEAN NOT NULL DEFAULT FALSE,
      nodes_ready       TEXT[]      NOT NULL DEFAULT '{}',
      nodes_pending     TEXT[]      NOT NULL DEFAULT '{}',
      nodes_unreachable TEXT[]      NOT NULL DEFAULT '{}',
      expected_vnets    INTEGER,
      report            JSONB,
      checked_at        TIMESTAMPTZ NOT NULL DEFAULT now()
    )
  `);
}

/**
 * Record a readiness result against its reservation. Best-effort: a reservation
 * that succeeded must not be reported as failed because its bookkeeping row
 * could not be written.
 */
async function recordLabReadiness(challengeId, readiness) {
  if (!challengeId || !readiness) return;
  try {
    await cybercoreQuery(
      `INSERT INTO cybercore_lab_readiness
         (challenge_id, bridges_ready, nodes_ready, nodes_pending, nodes_unreachable,
          expected_vnets, report, checked_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, now())
       ON CONFLICT (challenge_id) DO UPDATE
         SET bridges_ready = EXCLUDED.bridges_ready,
             nodes_ready = EXCLUDED.nodes_ready,
             nodes_pending = EXCLUDED.nodes_pending,
             nodes_unreachable = EXCLUDED.nodes_unreachable,
             expected_vnets = EXCLUDED.expected_vnets,
             report = EXCLUDED.report,
             checked_at = now()`,
      [
        challengeId, !!readiness.ready,
        readiness.nodesReady || [], readiness.nodesPending || [], readiness.nodesUnreachable || [],
        readiness.expected || null, JSON.stringify(readiness),
      ]
    );
  } catch (err) {
    console.warn(`[LabNetwork] Could not record readiness for ${challengeId}: ${err.message}`);
  }
}

/** The recorded readiness for one reservation, or null if it was never verified. */
async function getLabReadiness(challengeId) {
  if (!challengeId) return null;
  try {
    const r = await cybercoreQuery(
      `SELECT * FROM cybercore_lab_readiness WHERE challenge_id = $1`, [challengeId]);
    return r.rows[0] || null;
  } catch (err) {
    // The table is created by a boot hook; a plugin reading before that ran
    // should degrade to "unknown", not 500.
    return null;
  }
}

/** Readiness for many reservations at once, keyed by challenge_id. */
async function getLabReadinessMap(challengeIds) {
  const ids = (challengeIds || []).filter(Boolean);
  if (ids.length === 0) return {};
  try {
    const r = await cybercoreQuery(
      `SELECT * FROM cybercore_lab_readiness WHERE challenge_id = ANY($1::uuid[])`, [ids]);
    const out = {};
    for (const row of r.rows) out[row.challenge_id] = row;
    return out;
  } catch (err) {
    return {};
  }
}

/**
 * Confirm the SDN bridges for a set of VXLAN tags exist on every online node.
 *
 * WHY EVERY NODE. A lane's node is chosen at DEPLOY time by
 * batch-deployer.distributeAcrossNodes, which weighted-round-robins over
 * whatever is online and above the free-memory floor — and that set can change
 * between reserving a block and deploying from it (a node comes back, or drops
 * below the floor). So the only safe meaning of "this block is ready" is: the
 * bridges are up everywhere a lane might be placed. Checking one node answers a
 * question nobody asked.
 *
 * WHAT THIS REPLACES. The previous check read `(await GET /nodes)[0].node` —
 * whatever Proxmox happened to return first, with no online filter — polled only
 * that node, and swallowed every error into a log line so a wedged or offline
 * first node silently produced `bridgesUp: false` with no indication why. Its
 * result was then read by nobody.
 *
 * NODES ARE POLLED CONCURRENTLY, and every call carries its own timeout. Serially
 * sweeping nine nodes on proxmoxAPI's 30s default would let two dead nodes eat
 * the entire deadline before a single healthy one was checked.
 *
 * NEVER THROWS. A node that cannot be reached is reported as unreachable, not as
 * an exception — the caller decides whether an incomplete answer blocks a deploy.
 *
 * @param {object}   a
 * @param {number[]} a.tags            VXLAN tags whose bridges must exist (v3 internal tags included by the caller)
 * @param {string[]} [a.nodes]         override the node list; defaults to every ONLINE node
 * @param {number}   [a.timeoutMs]     overall deadline (default 240000)
 * @param {number}   [a.perCallMs]     per-request timeout (default 10000)
 * @param {number}   [a.intervalMs]    poll interval (default 4000)
 * @returns {Promise<{ready, nodesReady, nodesPending, nodesUnreachable, missingByNode, expected, checkedAt}>}
 */
async function verifyBridgesOnAllNodes({
  tags, nodes = null, timeoutMs = 240000, perCallMs = 10000, intervalMs = 4000, log = () => {},
}) {
  const expectedNames = [...new Set((tags || []).filter(Number.isFinite))].map(encodeBase20);
  const result = {
    ready: false,
    nodesReady: [], nodesPending: [], nodesUnreachable: [],
    missingByNode: {}, expected: expectedNames.length, checkedAt: null,
  };
  if (expectedNames.length === 0) {
    result.ready = true;
    return result;
  }

  // The SAME source distributeAcrossNodes uses, filtered the same way, so the
  // set we verify is the set a deploy can actually choose from.
  let nodeNames = nodes;
  if (!nodeNames) {
    try {
      const rows = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=node', null, { timeoutMs: perCallMs });
      nodeNames = (rows || []).filter(n => n.type === 'node' && n.status === 'online').map(n => n.node);
    } catch (e) {
      log(`Bridge readiness: could not list nodes (${e.message})`);
      return result;
    }
  }
  if (nodeNames.length === 0) {
    log('Bridge readiness: no online nodes to check');
    return result;
  }

  const deadline = Date.now() + timeoutMs;
  let pending = [...nodeNames];

  while (pending.length > 0 && Date.now() < deadline) {
    const checks = await Promise.all(pending.map(async (node) => {
      try {
        const ifaces = await proxmoxAPI('GET', `/api2/json/nodes/${node}/network`, null, { timeoutMs: perCallMs });
        const present = new Set((ifaces || []).map(i => i.iface));
        const missing = expectedNames.filter(n => !present.has(n));
        return { node, missing, reachable: true };
      } catch (e) {
        return { node, missing: expectedNames, reachable: false, error: e.message };
      }
    }));

    const stillPending = [];
    for (const c of checks) {
      if (c.reachable && c.missing.length === 0) {
        if (!result.nodesReady.includes(c.node)) result.nodesReady.push(c.node);
        delete result.missingByNode[c.node];
      } else {
        result.missingByNode[c.node] = c.reachable
          ? c.missing
          : [`unreachable: ${c.error}`];
        stillPending.push(c.node);
      }
    }
    pending = stillPending;
    if (pending.length === 0) break;
    if (Date.now() + intervalMs >= deadline) break;
    await new Promise(r => setTimeout(r, intervalMs));
  }

  // A node that never answered is reported separately from one that answered
  // and was simply missing bridges — they need different operator responses.
  for (const node of pending) {
    const miss = result.missingByNode[node] || [];
    if (miss.length === 1 && String(miss[0]).startsWith('unreachable:')) result.nodesUnreachable.push(node);
    else result.nodesPending.push(node);
  }

  result.ready = pending.length === 0;
  result.checkedAt = new Date().toISOString();

  if (result.ready) {
    log(`SDN bridges confirmed on all ${result.nodesReady.length} online node(s).`);
  } else {
    log(`WARNING: SDN bridges not confirmed on ${pending.length}/${nodeNames.length} node(s) — `
      + `pending: ${result.nodesPending.join(', ') || 'none'}; `
      + `unreachable: ${result.nodesUnreachable.join(', ') || 'none'}`);
  }
  return result;
}

/** Remove the block's VNets and (if it has no remaining VNets) its zone, then reload. */
async function teardownSdnForBlock({ zone, vxlanBlock, subnetScheme = 'v2', log = () => {} }) {
  let vnetsRemoved = 0;
  let zoneRemoved = false;
  if (!vxlanBlock?.start || !vxlanBlock?.end) return { vnetsRemoved, zoneRemoved };

  const blockMax = subnetScheme === 'v3' ? vxlanBlock.end + V3_INTERNAL_TAG_OFFSET : vxlanBlock.end;

  try {
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    for (const vnet of vnets) {
      const inExternal = vnet.tag >= vxlanBlock.start && vnet.tag <= vxlanBlock.end;
      const inInternal = subnetScheme === 'v3'
        && vnet.tag >= vxlanBlock.start + V3_INTERNAL_TAG_OFFSET
        && vnet.tag <= blockMax;
      if (inExternal || inInternal) {
        try { await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`); vnetsRemoved++; }
        catch (e) { log(`Failed to remove VNet ${vnet.vnet}: ${e.message}`); }
      }
    }
  } catch (e) {
    log(`Failed to query VNets: ${e.message}`);
  }

  if (zone) {
    try {
      const remaining = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
      if (!remaining.some(v => v.zone === zone)) {
        await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zone}`);
        zoneRemoved = true;
      }
    } catch (e) {
      log(`Failed to remove zone ${zone}: ${e.message}`);
    }
  }

  if (vnetsRemoved > 0 || zoneRemoved) {
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (_) {}
  }
  return { vnetsRemoved, zoneRemoved };
}

/**
 * Reserve a lab: allocate a VXLAN block, insert the crucible_challenge row with
 * the caller's spec (vxlan_block + zone.abbrev merged in), then create the SDN
 * zone + VNets and wait for bridges. Returns the challenge + block + infra info.
 *
 * @param {object}  a
 * @param {string}  a.challengeKey   unique key (throws 23505 if it exists)
 * @param {string}  a.name
 * @param {string}  [a.description]
 * @param {number}  [a.difficulty=2]
 * @param {string}  [a.subnetScheme='v2']
 * @param {number}  a.maxLanes       block size = number of VNets
 * @param {object}  [a.spec={}]      caller-built spec; merged with block + zone
 * @param {string}  [a.zoneAbbrev]   defaults to a sanitized challengeKey
 * @param {string}  [a.status='active']
 * @param {string}  [a.challengeType] crucible_challenge.challenge_type. Omitted from
 *   the INSERT when null, so the column default ('single_vm') still applies and
 *   existing callers write exactly the row they wrote before.
 * @param {string}  [a.moduleKey]     crucible_challenge.module_key, same treatment
 *   (column default is 'crucible').
 * @param {number}  [a.maxVxlanId]    passed to allocateVxlanBlock; see its note.
 * @param {Function}[a.log]
 */
async function reserveLabNetwork({
  challengeKey, name, description = null, difficulty = 2,
  subnetScheme = 'v2', maxLanes, spec = {}, zoneAbbrev, status = 'active',
  challengeType = null, moduleKey = null, maxVxlanId = null, log = () => {},
}) {
  if (!challengeKey || !name) throw new Error('reserveLabNetwork: challengeKey and name are required');
  const scheme = ['v1', 'v2', 'v3'].includes(subnetScheme) ? subnetScheme : 'v2';
  const numLanes = parseInt(maxLanes, 10);
  if (!Number.isFinite(numLanes) || numLanes < 1 || numLanes > 200) {
    throw new Error('maxLanes must be between 1 and 200');
  }

  const zone = sanitizeZoneAbbrev(zoneAbbrev || challengeKey);
  // Final assertion — sanitizeZoneAbbrev should always satisfy this, but guard
  // against an empty/degenerate input slipping a bad name through to Proxmox.
  if (!ZONE_RE.test(zone)) {
    throw new Error('zone abbreviation must be 1-8 alphanumeric characters starting with a letter');
  }

  log('Querying existing VXLAN blocks...');
  const block = await allocateVxlanBlock(numLanes, { maxVxlanId });
  log(`Allocated VXLAN block: ${block.start}-${block.end} (${numLanes} lanes)`);

  const fullSpec = {
    ...spec,
    zone: { ...(spec.zone || {}), abbrev: zone },
    vxlan_block: { start: block.start, end: block.end },
  };

  // challenge_type / module_key are appended only when the caller asked for
  // them. Building the column list this way (rather than passing NULL) is what
  // keeps the column DEFAULTs in play for every pre-existing caller.
  const cols = ['challenge_key', 'name', 'description', 'difficulty', 'spec', 'status', 'subnet_scheme'];
  const vals = [challengeKey, name, description, difficulty, JSON.stringify(fullSpec), status, scheme];
  const casts = { spec: '::jsonb' };
  if (challengeType != null) { cols.push('challenge_type'); vals.push(challengeType); }
  if (moduleKey != null) { cols.push('module_key'); vals.push(moduleKey); }
  const placeholders = cols.map((c, i) => `$${i + 1}${casts[c] || ''}`).join(', ');

  log('Inserting challenge record...');
  const ins = await cybercoreQuery(
    `INSERT INTO crucible_challenge (${cols.join(', ')})
     VALUES (${placeholders})
     RETURNING challenge_id, challenge_key`,
    vals
  );
  const challengeId = ins.rows[0].challenge_id;
  log(`Challenge created: ${challengeId}`);

  let infra;
  try {
    infra = await ensureSdnZoneAndVnets({
      zone, vxlanStart: block.start, vxlanEnd: block.end, subnetScheme: scheme, log,
    });
  } catch (err) {
    // The challenge row (and its VXLAN block reservation) is already committed.
    // If the SDN provisioning fails, undo it so we don't leak an orphaned
    // challenge + permanently-allocated block. Best-effort: surface the
    // original error regardless of cleanup outcome.
    log(`SDN provisioning failed (${err.message}); rolling back challenge ${challengeId}`);
    await teardownLabNetwork(challengeId, { force: true, log }).catch((e) =>
      log(`Rollback of challenge ${challengeId} failed: ${e.message}`)
    );
    throw err;
  }

  // ONE writer for the shared fact. Both plugins read it back through
  // getLabReadiness rather than each keeping their own copy in their own DB.
  await recordLabReadiness(challengeId, infra.bridgeReadiness);

  return {
    challenge_id: challengeId,
    challenge_key: challengeKey,
    zone,
    vxlan_block: block,
    subnet_scheme: scheme,
    ...infra,
  };
}

/**
 * Tear down a lab's network: refuse (unless `force`) while active/deploying
 * lanes still use the block, then remove VNets + zone and delete the challenge.
 * Throws an Error with `.status = 400` when blocked by active lanes.
 *
 * @param {string}  challengeId
 * @param {object}  [opts]
 * @param {boolean} [opts.force=false]
 * @param {string}  [opts.subnetScheme]  override the scheme used to decide which
 *   VNet tags belong to this block. Omit (the default) to read it off the
 *   challenge row exactly as before. See the note at the read site.
 * @param {Function}[opts.log]
 */
async function teardownLabNetwork(challengeId, { force = false, log = () => {}, subnetScheme: schemeOverride = null } = {}) {
  const chal = await cybercoreQuery(`SELECT * FROM crucible_challenge WHERE challenge_id = $1`, [challengeId]);
  if (chal.rows.length === 0) {
    const err = new Error('Challenge not found');
    err.status = 404;
    throw err;
  }
  const challenge = chal.rows[0];
  const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});
  const zone = spec.zone?.abbrev;
  const vxlanBlock = spec.vxlan_block;
  // The row's subnet_scheme is written once, at reservation time, and nothing
  // ever updates it — but the scheme a lane is actually BUILT at is a per-deploy
  // choice. When the two disagree (a block reserved v2 and later deployed v3),
  // the internal VNets at tag+V3_INTERNAL_TAG_OFFSET exist but the row says v2,
  // so the sweep below skips them and they are orphaned with nothing left that
  // can name them. schemeOverride lets a caller that knows better say so; the
  // internal range is derived from this block and can belong to no other lab, so
  // sweeping it when it happens to be empty is a no-op.
  const subnetScheme = schemeOverride || challenge.subnet_scheme || 'v2';

  let removed = { vnetsRemoved: 0, zoneRemoved: false };
  if (vxlanBlock?.start && vxlanBlock?.end) {
    if (!force) {
      const active = await countActiveLanesInBlock(vxlanBlock);
      if (active > 0) {
        const err = new Error(`Cannot delete: ${active} active lane(s) are using this challenge's VXLAN block`);
        err.status = 400;
        throw err;
      }
    }
    removed = await teardownSdnForBlock({ zone, vxlanBlock, subnetScheme, log });
  }

  await cybercoreQuery(`DELETE FROM crucible_challenge WHERE challenge_id = $1`, [challengeId]);
  log(`Deleted '${challenge.challenge_key}': ${removed.vnetsRemoved} VNets removed, zone removed: ${removed.zoneRemoved}`);

  return { challenge_key: challenge.challenge_key, vnets_removed: removed.vnetsRemoved, zone_removed: removed.zoneRemoved };
}

module.exports = {
  V3_INTERNAL_TAG_OFFSET,
  ZONE_RE,
  sanitizeZoneAbbrev,
  encodeBase20,
  allocateVxlanBlock,
  countActiveLanesInBlock,
  ensureSdnZoneAndVnets,
  verifyBridgesOnAllNodes,
  ensureLabReadinessTable,
  recordLabReadiness,
  getLabReadiness,
  getLabReadinessMap,
  teardownSdnForBlock,
  reserveLabNetwork,
  teardownLabNetwork,
};
