/**
 * ============================================================================
 * NODE SELECTOR
 * Determines the best Proxmox node for VM deployment by scoring each
 * node's available CPU and memory capacity.
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');
const { getSchedulingConfig } = require('./site-config');
const nodeHealth = require('./node-health');
const { probeNodesForBridges, bridgeNames } = require('./node-bridges');

// How often keepBridgeReadyNodes re-asks while it waits for a node's SDN reload
// to land. Five seconds: a reload takes minutes at best, and one poll is a
// single cheap GET per candidate node.
const BRIDGE_POLL_MS = 5000;

function clamp01(x) {
  if (!Number.isFinite(x)) return 1;
  return Math.max(0, Math.min(1, x));
}

/**
 * The one place that decides which cluster members are allowed to receive a new
 * lane. Both placement paths call it: selectBestNode() below, and
 * batch-deployer.distributeAcrossNodes().
 *
 * WHY IT IS SHARED
 * It used to be two different inline filters -- this file kept online + free
 * mem + free disk, batch-deployer kept online + free mem -- so "which nodes may
 * take a lane" had two answers depending on whether you deployed one lane or
 * six. When cyberhub-node-8 had to be kept out of placement there was nowhere
 * to say so once.
 *
 * THE INCIDENT
 * cyberhub-node-8 joined the cluster and started a Ceph backfill. Every lane
 * placed on it cloned fine and then died in `pct start`:
 *
 *     lxc-start: ... Failed to run lxc.hook.pre-start for container "110881"
 *     ... exited with status 32
 *
 * -- the pre-start hook losing the race for the udev-created symlink
 * /dev/rbd-pve/<fsid>/<pool>/<image>. The scoring below made it worse rather
 * than better: it ranks on FREE capacity, and a node whose only workload is
 * Ceph backfill has idle CPU and free RAM, so it scored BEST and the whole
 * batch marched into the one machine that could not start a container.
 *
 * THE FILTERS, IN THIS ORDER
 *   1. online         -- as before; Proxmox's own view of the node.
 *   2. HARD, config   -- cluster.scheduling.excluded_nodes. An operator drained
 *                        this node deliberately; the setting survives restarts
 *                        and is never overridden, not even to keep the cluster
 *                        deployable. If they drained everything they meant it.
 *   3. HARD, caller   -- opts.exclude: "not this node", e.g. a re-place after a
 *                        node-attributed failure on the first attempt.
 *   4. SOFT, health   -- the in-process quarantine in utils/node-health.js.
 *                        Dropped UNLESS dropping them would leave zero nodes,
 *                        in which case they are all kept and we warn. A
 *                        transient, self-healing node fault must never become a
 *                        cluster-wide outage: losing one lane on a suspect node
 *                        beats refusing to deploy anything at all.
 *
 * A FIFTH FILTER LIVES NEXT DOOR, in keepBridgeReadyNodes below: the lane's SDN
 * VNet bridge must actually be up on the node. It is not part of this function
 * because it is ASYNC -- it asks each surviving node what interfaces it really
 * has -- and this one stays synchronous, with its own direct callers and its own
 * test file. Both placement paths apply it immediately after this.
 *
 * Returns the RAW resource rows, not scored ones -- the two callers score
 * differently (this file weights disk, batch-deployer does not), and unifying
 * that is deliberately not part of this change.
 *
 * An empty cluster is NOT this function's error to raise: it returns [] when
 * nothing was online in the first place, so selectBestNode keeps reporting
 * 'No online nodes found in cluster' and batch-deployer keeps reporting its
 * own message. "The cluster is empty" and "you drained the cluster" are
 * different pages at 2am.
 *
 * @param {Array}    resources      rows from /cluster/resources?type=node
 * @param {Object}   [opts]
 * @param {string[]} [opts.exclude] extra node names this caller must not use
 * @param {string}   [opts.logTag]  log prefix, so the line names the real caller
 * @returns {Array} the resource rows that may receive a lane
 */
function filterSchedulableNodes(resources, { exclude = [], logTag = '[NodeSelector]' } = {}) {
  const rows = Array.isArray(resources) ? resources : [];
  const online = rows.filter(n => n && n.type === 'node' && n.status === 'online');
  if (online.length === 0) return [];

  // HARD 1 -- the operator's drain switch in config/site.json.
  const configured = getSchedulingConfig().excluded_nodes || [];
  const configuredSet = new Set(configured.map(String));
  let candidates = online.filter(n => !configuredSet.has(String(n.node)));
  if (candidates.length !== online.length) {
    const dropped = online.filter(n => configuredSet.has(String(n.node))).map(n => n.node);
    console.log(`${logTag} Excluding ${dropped.join(', ')} from placement (cluster.scheduling.excluded_nodes)`);
  }

  // HARD 2 -- this caller's own veto for this one placement.
  const callerSet = new Set((Array.isArray(exclude) ? exclude : []).map(String));
  if (callerSet.size > 0) {
    const before = candidates.length;
    candidates = candidates.filter(n => !callerSet.has(String(n.node)));
    if (candidates.length !== before) {
      console.log(`${logTag} Caller excluded ${[...callerSet].join(', ')} from placement`);
    }
  }

  if (candidates.length === 0) {
    throw new Error('No schedulable nodes: every online node is excluded (cluster.scheduling.excluded_nodes)');
  }

  // SOFT -- a node that just failed a deploy for a reason that was not the
  // lane's fault. Advisory only: see QUARANTINE IS SOFT in utils/node-health.js.
  const quarantined = candidates.filter(n => nodeHealth.isNodeQuarantined(n.node));
  if (quarantined.length === 0) return candidates;

  const healthy = candidates.filter(n => !nodeHealth.isNodeQuarantined(n.node));
  if (healthy.length === 0) {
    console.warn(`${logTag} Every schedulable node is quarantined (${candidates.map(n => n.node).join(', ')}); placing anyway rather than failing the deploy`);
    return candidates;
  }

  console.log(`${logTag} Skipping quarantined node(s): ${quarantined.map(n => n.node).join(', ')}`);
  return healthy;
}

/** Default wait, in ms, for the bridges to land somewhere. See cluster.scheduling. */
function defaultBridgeWaitMs() {
  let s = 300;
  try {
    const v = Number(getSchedulingConfig().bridge_wait_s);
    // Tests stub getSchedulingConfig with only the numeric keys they care about,
    // and config/site.json is gitignored so a fresh checkout has no scheduling
    // block at all. An absent key must not become NaN * 1000 here.
    if (Number.isFinite(v) && v >= 0) s = v;
  } catch (_) { /* keep the default */ }
  return s * 1000;
}

/** "node-6 (missing aaaabgdd), node-7 (unreachable: socket hang up)" */
function describePending(probe) {
  const parts = [];
  for (const [node, missing] of Object.entries(probe.missingByNode)) {
    parts.push(`${node} (missing ${missing.join(', ')})`);
  }
  for (const [node, why] of Object.entries(probe.unreachable)) {
    parts.push(`${node} (unreachable: ${String(why).split('\n')[0]})`);
  }
  return parts.join(', ') || 'no candidate nodes';
}

function bridgesNotOnAnyNodeError({ names, probe, candidates, waitedMs }) {
  const err = new Error(
    `No schedulable node has SDN bridge(s) ${names.join(', ')} yet ` +
    `(waited ${Math.round(waitedMs / 1000)}s across ${candidates.length} node(s)). ` +
    `Proxmox is still applying the SDN change on ${describePending(probe)} — ` +
    `PUT /cluster/sdn does not create bridges, it queues each node's own ` +
    `"SRV Networking" reload (ifreload -a), and a large zone can take a node ` +
    `minutes to hours. Lanes are placed ONLY on nodes whose bridges are up, so ` +
    `retry as soon as one finishes: ` +
    `pvesh get /nodes/<node>/tasks --source active --typefilter srvreload`
  );
  err.code = 'BRIDGES_NOT_ON_ANY_NODE';
  // Matches the err.status convention the CIAB routes already use, so a generic
  // res.status(err.status || 500) answers 503 rather than 500 — this is a "come
  // back in a minute", not a bug.
  err.status = 503;
  err.requiredBridges = names;
  err.candidates = candidates;
  err.missingByNode = probe ? probe.missingByNode : {};
  err.unreachable = probe ? probe.unreachable : {};
  err.waitedMs = waitedMs;
  return err;
}

/**
 * FILTER 5 -- THE ONE THAT MADE A NEW ENVIRONMENT UNDEPLOYABLE FOR HOURS.
 *
 * Keep only the candidates whose node has EVERY bridge in requireBridges up
 * right now.
 *
 * THE PROBLEM. Creating an environment carves a VXLAN block and commits it with
 * one cluster-wide `PUT /cluster/sdn`. That commit creates no bridges: it makes
 * every node queue its OWN "SRV Networking" reload (ifreload -a), and those run
 * independently. With hundreds of VNets in the shared zone, one node is done in
 * a minute and another is still working an hour later. A lane placed on the
 * second one clones perfectly and then dies at `pct start` with
 *
 *     bridge 'aaaabgdc' does not exist
 *
 * three to five minutes into the deploy, wearing the clothes of something else.
 * So deploys were held until the SLOWEST node had finished. Filtering here means
 * a block is deployable the moment ONE node is ready.
 *
 * THIS IS NOT A FAULT FILTER, and that drives everything below:
 *   - NOTHING IS QUARANTINED. A node without the bridge has done nothing wrong;
 *     it is mid-reload. Marking it would keep it out of the NEXT deploy too, by
 *     which time it is very likely the healthiest node in the cluster.
 *   - NOTHING IS PERSISTED. Readiness only ever improves after an apply, so the
 *     answer is worth exactly as long as it takes to place this batch — and
 *     there is no race in the dangerous direction: a bridge that is up does not
 *     go away while we place a lane on it.
 *   - IT WAITS, briefly, rather than failing at once. Deploying a minute after
 *     creating an environment is the normal case this exists for, and the first
 *     node usually lands inside the budget.
 *
 * ZERO COST WHEN UNUSED: no requireBridges means no probe, no Proxmox calls, and
 * the rows straight back — so every placement that does not cable a lane to a
 * VNet (a bare workstation clone) is exactly as cheap as it was before.
 *
 * @param {Array}    rows              raw resource rows from filterSchedulableNodes
 * @param {Object}   [opts]
 * @param {Array}    [opts.requireBridges] vnet names, or {vnet} rows, that must be up
 * @param {number}   [opts.waitMs]     wait budget; default cluster.scheduling.bridge_wait_s
 * @param {number}   [opts.intervalMs] poll interval while waiting
 * @param {number}   [opts.perCallMs]  per-node probe timeout
 * @param {Function} [opts.log]        extra sink for the waiting notice (progress UI)
 * @returns {Promise<Array>} the subset of rows that can take this lane right now
 * @throws  Error tagged code='BRIDGES_NOT_ON_ANY_NODE', status=503
 */
async function keepBridgeReadyNodes(rows, {
  requireBridges, waitMs, intervalMs, perCallMs,
  logTag = '[NodeSelector]', log = null,
} = {}) {
  // Not a default parameter: callers forward opts.intervalMs unconditionally, so
  // the common case passes an explicit undefined -- which a default handles, but
  // a 0 or a NaN from a config would not.
  const pollMs = Number.isFinite(Number(intervalMs)) && Number(intervalMs) > 0
    ? Number(intervalMs) : BRIDGE_POLL_MS;
  const list = Array.isArray(rows) ? rows : [];
  const names = bridgeNames(requireBridges);
  if (names.length === 0 || list.length === 0) return list;

  const budget = Number.isFinite(Number(waitMs)) ? Math.max(0, Number(waitMs)) : defaultBridgeWaitMs();
  const started = Date.now();
  const deadline = started + budget;
  const candidates = list.map(r => String(r.node));

  let probe = null;
  let round = 0;
  for (;;) {
    round++;
    probe = await probeNodesForBridges(candidates, names, { perCallMs });

    if (probe.ready.length > 0) {
      if (probe.ready.length < candidates.length) {
        console.log(
          `${logTag} Bridge(s) ${names.join(', ')} up on ${probe.ready.join(', ')}; ` +
          `skipping ${describePending(probe)} — their SDN reload has not landed yet`
        );
      }
      const readySet = new Set(probe.ready);
      return list.filter(r => readySet.has(String(r.node)));
    }

    const remaining = deadline - Date.now();
    if (remaining <= 0) break;

    // Loud on the first pass, then every ~30s. A silent five-minute wait reads as
    // a hung deploy; a line per poll reads as a broken one.
    if (round === 1 || round % 6 === 0) {
      const msg =
        `${logTag} No schedulable node has bridge(s) ${names.join(', ')} yet — ` +
        `${describePending(probe)}; waiting up to ${Math.ceil(remaining / 1000)}s more ` +
        `for a node to finish its SDN reload`;
      console.warn(msg);
      if (typeof log === 'function') { try { log(msg); } catch (_) { /* a log sink must never fail a deploy */ } }
    }
    await new Promise(r => setTimeout(r, Math.min(pollMs, remaining)));
  }

  throw bridgesNotOnAnyNodeError({ names, probe, candidates, waitedMs: Date.now() - started });
}

/**
 * Query Proxmox cluster resources and return the best node for deployment
 * @param {Object}   [opts]
 * @param {string[]} [opts.exclude] node names this placement must not use
 * @param {Array}    [opts.requireBridges] vnet names (or {vnet} rows) that must already be up there
 * @param {number}   [opts.waitMs]  how long to wait for those bridges (default: config)
 * @param {number}   [opts.intervalMs] how often to re-ask while waiting
 * @param {number}   [opts.perCallMs]  per-node probe timeout
 * @param {Function} [opts.log]     extra sink for the "waiting for the SDN reload" notice
 * @returns {{ node: string, score: number, cpu_pct: number, mem_pct: number, disk_pct: number, mem_free_gb: number }}
 */
async function selectBestNode(opts = {}) {
  const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=node');

  if (!Array.isArray(resources)) {
    throw new Error('Failed to get cluster resources');
  }

  const { min_free_mem_gb, min_free_disk_gb, node_score_weights: WEIGHTS } = getSchedulingConfig();

  // Filters 1-4 (sync), then filter 5 (async). A node that scores wonderfully and
  // has no bridge for this lane cannot run it at all, so the scoring below must
  // never see it.
  const schedulable = filterSchedulableNodes(resources, { exclude: opts.exclude });
  const bridgeReady = await keepBridgeReadyNodes(schedulable, {
    requireBridges: opts.requireBridges,
    waitMs: opts.waitMs,
    // Forwarded, not just accepted: without these the behavioural test cannot
    // run the poll ladder in milliseconds, and it would silently sleep the whole
    // default interval between rounds instead.
    intervalMs: opts.intervalMs,
    perCallMs: opts.perCallMs,
    log: opts.log,
  });

  // Normalize node data
  const nodes = bridgeReady
    .map(n => {
      const maxcpu = Number(n.maxcpu || 0);
      const maxmem = Number(n.maxmem || 0);
      const maxdisk = Number(n.maxdisk || 0);

      const cpuFrac = clamp01(Number(n.cpu || 0));
      const memFrac = clamp01(maxmem > 0 ? Number(n.mem || 0) / maxmem : 1);
      const diskFrac = clamp01(maxdisk > 0 ? Number(n.disk || 0) / maxdisk : 1);

      return {
        node: n.node,
        cpu_frac: cpuFrac,
        mem_frac: memFrac,
        disk_frac: diskFrac,
        mem_free_bytes: maxmem - Number(n.mem || 0),
        disk_free_bytes: maxdisk - Number(n.disk || 0),
      };
    });

  // Filter eligible nodes
  const minFreeMem  = min_free_mem_gb  * 1024 ** 3;
  const minFreeDisk = min_free_disk_gb * 1024 ** 3;

  const eligible = nodes.filter(n =>
    n.mem_free_bytes >= minFreeMem &&
    n.disk_free_bytes >= minFreeDisk
  );

  if (eligible.length === 0) {
    // Fall back to all online nodes if none meet the threshold
    console.warn('[NodeSelector] No nodes meet free resource thresholds, using least-loaded node');
    if (nodes.length === 0) throw new Error('No online nodes found in cluster');
    eligible.push(...nodes);
  }

  // Score and sort (lower = better)
  const scored = eligible.map(n => {
    const score = (n.cpu_frac * WEIGHTS.cpu) + (n.mem_frac * WEIGHTS.mem) + (n.disk_frac * WEIGHTS.disk);
    return {
      node: n.node,
      score: Math.round(score * 1000000) / 1000000,
      cpu_pct: Math.round(n.cpu_frac * 10000) / 100,
      mem_pct: Math.round(n.mem_frac * 10000) / 100,
      disk_pct: Math.round(n.disk_frac * 10000) / 100,
      mem_free_gb: Math.round(n.mem_free_bytes / (1024 ** 3) * 100) / 100,
      disk_free_gb: Math.round(n.disk_free_bytes / (1024 ** 3) * 100) / 100,
    };
  });

  scored.sort((a, b) => a.score - b.score);

  const best = scored[0];
  console.log(`[NodeSelector] Best node: ${best.node} (score: ${best.score}, CPU: ${best.cpu_pct}%, MEM: ${best.mem_pct}%, free: ${best.mem_free_gb}GB)`);

  return best;
}

module.exports = { selectBestNode, filterSchedulableNodes, keepBridgeReadyNodes, BRIDGE_POLL_MS };
