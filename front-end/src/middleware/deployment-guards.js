/**
 * ============================================================================
 * DEPLOYMENT GUARDS MIDDLEWARE
 * Pre-flight resource checks before VM deployment operations
 * ============================================================================
 */

const { getSchedulingConfig } = require('../utils/site-config');

// Safety thresholds (env-var overrideable policy)
const MAX_NODE_MEMORY_PCT  = parseInt(process.env.MAX_NODE_MEMORY_PCT)  || 80;
const MAX_NODE_STORAGE_PCT = parseInt(process.env.MAX_NODE_STORAGE_PCT) || 90;
// Concurrency limit — source of truth is site.json; env var still overrides for ops flexibility
const MAX_CONCURRENT_DEPLOYS = parseInt(process.env.MAX_CONCURRENT_DEPLOYS) || getSchedulingConfig().max_concurrent_lanes;

/**
 * Fetch cluster resource summary from Proxmox
 * Returns { nodes[], totalVMs, warnings[] }
 */
async function getClusterHealth(proxmoxAPI) {
  // Fetch cluster resources and Ceph storage status in parallel
  const [resources, storageList] = await Promise.all([
    proxmoxAPI('GET', '/api2/json/cluster/resources'),
    proxmoxAPI('GET', '/api2/json/storage').catch(() => [])
  ]);

  // Two-pass: collect nodes first, then count VMs per node
  const nodes = {};
  let totalVMs = 0;

  // Pass 1: Build node map
  for (const r of resources) {
    if (r.type === 'node' && r.status === 'online') {
      nodes[r.node] = {
        node: r.node,
        status: r.status,
        cpu_pct: Math.round((r.cpu || 0) * 100),
        // Physical cores. Carried so buildResizePreview can say when a
        // requested core count exceeds what the node actually has.
        maxcpu: Number(r.maxcpu) || 0,
        mem_pct: Math.round(((r.mem || 0) / (r.maxmem || 1)) * 100),
        mem_used_gb: Math.round((r.mem || 0) / 1073741824 * 10) / 10,
        mem_total_gb: Math.round((r.maxmem || 0) / 1073741824 * 10) / 10,
        local_disk_pct: r.maxdisk ? Math.round(((r.disk || 0) / r.maxdisk) * 100) : 0,
        local_disk_used_gb: Math.round((r.disk || 0) / 1073741824 * 10) / 10,
        local_disk_total_gb: Math.round((r.maxdisk || 0) / 1073741824 * 10) / 10,
        vm_count: 0
      };
    }
  }

  // Pass 2: Count VMs per node
  for (const r of resources) {
    if (r.type === 'qemu' || r.type === 'lxc') {
      totalVMs++;
      if (nodes[r.node]) {
        nodes[r.node].vm_count++;
      }
    }
  }

  // Pass 3: Get Ceph/shared storage usage from storage resources.
  // Proxmox reports one storage row per (node, pool); collapse to one entry per
  // pool name since every node reports the same cluster-wide Ceph stats. The
  // dashboard used to grab rdbStorages[0], but Proxmox's row order isn't stable,
  // so with more than one pool (e.g. vmpool + targetpool) the display flipped
  // between them on each poll. Surface every pool in a stable order instead.
  const rbdStorages = resources.filter(r =>
    r.type === 'storage' && (r.plugintype === 'rbd' || r.storage === 'vmpool')
  );
  // Stable order: the primary VM pool first, then the rest alphabetically.
  rbdStorages.sort((a, b) => {
    if (a.storage === 'vmpool') return -1;
    if (b.storage === 'vmpool') return 1;
    return String(a.storage).localeCompare(String(b.storage));
  });
  const cephPools = [];
  const seenPools = new Set();
  for (const s of rbdStorages) {
    if (seenPools.has(s.storage)) continue;
    seenPools.add(s.storage);
    const maxdisk = Number(s.maxdisk || 0);
    const disk = Number(s.disk || 0);
    cephPools.push({
      storage: s.storage,
      used_bytes: disk,
      total_bytes: maxdisk,
      used_gb: Math.round(disk / 1073741824 * 10) / 10,
      total_gb: Math.round(maxdisk / 1073741824 * 10) / 10,
      used_tb: Math.round(disk / (1024 ** 4) * 100) / 100,
      total_tb: Math.round(maxdisk / (1024 ** 4) * 100) / 100,
      pct: maxdisk > 0 ? Math.round((disk / maxdisk) * 100) : 0
    });
  }
  // Primary pool drives the per-node disk display + storage warning (VMs live
  // on vmpool); fall back to the first pool if vmpool isn't present.
  const ceph = cephPools.find(p => p.storage === 'vmpool') || cephPools[0] || null;

  // Apply Ceph storage percentage to each node's disk display (since VMs live on Ceph, not local)
  const nodeList = Object.values(nodes);
  for (const n of nodeList) {
    n.disk_pct = ceph ? ceph.pct : n.local_disk_pct;
    n.disk_used_gb = ceph ? ceph.used_gb : n.local_disk_used_gb;
    n.disk_total_gb = ceph ? ceph.total_gb : n.local_disk_total_gb;
  }

  const warnings = [];

  for (const n of nodeList) {
    if (n.mem_pct >= MAX_NODE_MEMORY_PCT) {
      warnings.push(`Node ${n.node} memory at ${n.mem_pct}% (threshold: ${MAX_NODE_MEMORY_PCT}%)`);
    }
  }
  // Storage warning based on Ceph (cluster-wide, not per-node)
  if (ceph && ceph.pct >= MAX_NODE_STORAGE_PCT) {
    warnings.push(`Ceph storage at ${ceph.pct}% (${ceph.used_tb} / ${ceph.total_tb} TiB, threshold: ${MAX_NODE_STORAGE_PCT}%)`);
  }

  return {
    nodes: nodeList,
    totalVMs,
    ceph,
    cephPools,
    thresholds: {
      max_memory_pct: MAX_NODE_MEMORY_PCT,
      max_storage_pct: MAX_NODE_STORAGE_PCT,
      max_concurrent_deploys: MAX_CONCURRENT_DEPLOYS
    },
    warnings
  };
}

/**
 * Count currently deploying lanes
 */
async function getDeployingCount(cybercoreQuery) {
  const result = await cybercoreQuery(
    `SELECT COUNT(*) AS cnt FROM cybercore_lane WHERE status = 'deploying'`
  );
  return parseInt(result.rows[0].cnt) || 0;
}

/**
 * Build a deployment preview (resource impact summary)
 * @param {object} opts - { numLanes, attackBoxes, proxmoxAPI, cybercoreQuery }
 * @returns {object} preview with canProceed flag
 */
async function buildDeployPreview(opts) {
  const { numLanes = 1, attackBoxes = false, challengeVmCount = 1, proxmoxAPI, cybercoreQuery } = opts;

  const [health, deployingCount] = await Promise.all([
    getClusterHealth(proxmoxAPI),
    getDeployingCount(cybercoreQuery)
  ]);

  // VMs per lane: N challenge VMs + 1 gateway + (optional 1 attack box)
  const vmsPerLane = challengeVmCount + 1 + (attackBoxes ? 1 : 0);
  const totalNewVMs = numLanes * vmsPerLane;

  const errors = [];

  // Memory — block only if ALL nodes are over threshold
  const overMemory = health.nodes.filter(n => n.mem_pct >= MAX_NODE_MEMORY_PCT);
  if (overMemory.length === health.nodes.length && health.nodes.length > 0) {
    errors.push(`All nodes at or above memory threshold (${MAX_NODE_MEMORY_PCT}%)`);
  }

  // Storage — block only if ALL nodes are over threshold
  const overStorage = health.nodes.filter(n => n.disk_pct >= MAX_NODE_STORAGE_PCT);
  if (overStorage.length === health.nodes.length && health.nodes.length > 0) {
    errors.push(`All nodes at or above storage threshold (${MAX_NODE_STORAGE_PCT}%)`);
  }

  return {
    canProceed: errors.length === 0,
    summary: {
      new_vms: totalNewVMs,
      vms_per_lane: vmsPerLane,
      num_lanes: numLanes,
      current_vms: health.totalVMs,
      currently_deploying: deployingCount,
      max_concurrent: MAX_CONCURRENT_DEPLOYS
    },
    nodes: health.nodes,
    warnings: health.warnings,
    errors
  };
}

/**
 * Project each node's memory use if a set of machines were re-sized.
 *
 * PURE, so the arithmetic can be tested without a cluster — and it is worth
 * testing, because getting it wrong in either direction is bad in a way nobody
 * notices until class starts. Too lax and a bulk resize overcommits a node and
 * the guests start swapping or fail to boot; too strict and a legitimate
 * downsize gets refused.
 *
 * Three rules that are easy to get wrong:
 *
 *  1. THE DELTA IS WHAT MATTERS, NOT THE NEW SIZE. Node memory is already
 *     accounted for at the machine's CURRENT size; only the difference lands on
 *     the node. Summing the requested sizes would refuse a class that is
 *     already running.
 *
 *  2. STOPPED MACHINES CONTRIBUTE ZERO. A stopped VM consumes no host memory,
 *     and a resize deliberately leaves it stopped — so re-sizing a powered-off
 *     machine from 4 GB to 64 GB changes nothing on the node today. Counting it
 *     would block a whole batch on machines that are not running.
 *
 *  3. A DECREASE NEVER BLOCKS. Freeing memory cannot make a node unhealthier,
 *     even when it is already over the threshold — refusing "make these
 *     smaller" because the node is full is precisely backwards.
 *
 * @param {Array}  nodes    getClusterHealth().nodes
 * @param {Array}  targets  [{ node, running, current: { memory_mb } }]
 * @param {object} resources { memory_mb?, cores? } — the requested sizing
 * @returns {Array} one row per AFFECTED node
 */
function projectNodeMemory(nodes, targets, resources) {
  const want = Number(resources && resources.memory_mb) || null;
  const byNode = new Map();

  for (const t of (targets || [])) {
    if (!t || !t.node) continue;
    // Rule 2.
    if (!t.running) continue;
    const cur = Number(t.current && t.current.memory_mb) || 0;
    if (!want || !cur) continue;
    const delta = want - cur;
    const acc = byNode.get(t.node) || { delta_mb: 0, count: 0 };
    acc.delta_mb += delta;
    acc.count += 1;
    byNode.set(t.node, acc);
  }

  const out = [];
  for (const n of (nodes || [])) {
    const acc = byNode.get(n.node);
    if (!acc) continue;
    const total_gb = Number(n.mem_total_gb) || 0;
    const used_gb = Number(n.mem_used_gb) || 0;
    const delta_gb = acc.delta_mb / 1024;
    const projected_gb = used_gb + delta_gb;
    out.push({
      node: n.node,
      machines: acc.count,
      mem_pct: n.mem_pct,
      mem_used_gb: used_gb,
      mem_total_gb: total_gb,
      delta_gb: Math.round(delta_gb * 10) / 10,
      projected_gb: Math.round(projected_gb * 10) / 10,
      projected_pct: total_gb > 0 ? Math.round((projected_gb / total_gb) * 100) : 0,
      // Rule 3: only an increase can be over-threshold.
      over: delta_gb > 0 && total_gb > 0
        && (projected_gb / total_gb) * 100 > MAX_NODE_MEMORY_PCT,
    });
  }
  return out;
}

/**
 * Pre-flight a resize. Blocks only on projected node memory; everything else is
 * a warning, because overcommitting CPU is legal and sometimes intended.
 *
 * Deliberately NOT reusing buildDeployPreview: that one counts VMs and only
 * blocks when EVERY node is over threshold, which is right for a deploy that
 * can be placed anywhere and wrong here — a resize cannot choose its node, so
 * one full node is a hard stop for the machines that live on it.
 *
 * @param {object}   a
 * @param {Array}    a.targets   [{ node, vmid, label, running, current, maxcpu? }]
 * @param {object}   a.resources { cores?, memory_mb? }
 * @param {Function} a.proxmoxAPI
 */
async function buildResizePreview({ targets, resources, proxmoxAPI }) {
  const health = await getClusterHealth(proxmoxAPI);
  const nodeRows = projectNodeMemory(health.nodes, targets, resources);

  const errors = [];
  const warnings = [];

  for (const r of nodeRows) {
    if (r.over) {
      errors.push(
        `Node ${r.node} would be at ${r.projected_pct}% memory after this change ` +
        `(${r.projected_gb} of ${r.mem_total_gb} GB, threshold ${MAX_NODE_MEMORY_PCT}%). ` +
        `${r.machines} of the selected machines live on it.`);
    } else if (r.delta_gb > 0 && r.projected_pct >= MAX_NODE_MEMORY_PCT - 10) {
      warnings.push(`Node ${r.node} will be at ${r.projected_pct}% memory after this change.`);
    }
  }

  // CPU overcommit is allowed by Proxmox and is a normal thing to do in a lab,
  // so this is information rather than a gate.
  const wantCores = Number(resources && resources.cores) || null;
  if (wantCores) {
    const byNode = new Map((health.nodes || []).map(n => [n.node, n]));
    const busted = [...new Set((targets || [])
      .map(t => t && t.node)
      .filter(nm => {
        const n = byNode.get(nm);
        return n && Number(n.maxcpu) > 0 && wantCores > Number(n.maxcpu);
      }))];
    for (const nm of busted) {
      warnings.push(
        `${wantCores} cores is more than node ${nm} physically has ` +
        `(${byNode.get(nm).maxcpu}). Proxmox allows this, but the guest will contend for CPU.`);
    }
  }

  // Boots, but thrashes. Worth saying before an instructor does it to 30 machines.
  const wantMem = Number(resources && resources.memory_mb) || null;
  if (wantMem && wantMem < 2048) {
    warnings.push(`${wantMem} MB is below what a Windows desktop needs to run comfortably.`);
  }

  const running = (targets || []).filter(t => t && t.running).length;
  return {
    canProceed: errors.length === 0,
    summary: {
      machines: (targets || []).length,
      running,
      stopped: (targets || []).length - running,
      requested: resources,
    },
    nodes: nodeRows,
    warnings: warnings.concat(health.warnings || []),
    errors
  };
}

module.exports = {
  getClusterHealth,
  getDeployingCount,
  buildDeployPreview,
  buildResizePreview,
  projectNodeMemory,
  MAX_NODE_MEMORY_PCT,
  MAX_NODE_STORAGE_PCT,
  MAX_CONCURRENT_DEPLOYS
};