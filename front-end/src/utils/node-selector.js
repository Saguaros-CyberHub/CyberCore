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

/**
 * Query Proxmox cluster resources and return the best node for deployment
 * @param {Object}   [opts]
 * @param {string[]} [opts.exclude] node names this placement must not use
 * @returns {{ node: string, score: number, cpu_pct: number, mem_pct: number, disk_pct: number, mem_free_gb: number }}
 */
async function selectBestNode(opts = {}) {
  const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=node');

  if (!Array.isArray(resources)) {
    throw new Error('Failed to get cluster resources');
  }

  const { min_free_mem_gb, min_free_disk_gb, node_score_weights: WEIGHTS } = getSchedulingConfig();

  // Normalize node data
  const nodes = filterSchedulableNodes(resources, { exclude: opts.exclude })
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

module.exports = { selectBestNode, filterSchedulableNodes };
