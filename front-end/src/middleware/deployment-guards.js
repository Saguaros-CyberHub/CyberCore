/**
 * ============================================================================
 * DEPLOYMENT GUARDS MIDDLEWARE
 * Pre-flight resource checks before VM deployment operations
 * ============================================================================
 */

// Thresholds from environment (or sensible defaults)
const MAX_NODE_MEMORY_PCT = parseInt(process.env.MAX_NODE_MEMORY_PCT) || 80;
const MAX_NODE_STORAGE_PCT = parseInt(process.env.MAX_NODE_STORAGE_PCT) || 90;
const MAX_CONCURRENT_DEPLOYS = parseInt(process.env.MAX_CONCURRENT_DEPLOYS) || 3;

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

  // Pass 3: Get Ceph/shared storage usage from storage resources
  // Look for RBD/Ceph storage entries in cluster resources
  let ceph = null;
  const storageResources = resources.filter(r => r.type === 'storage');
  // Find the primary VM storage pool (RBD type, or the one named vmpool)
  const rdbStorages = storageResources.filter(r =>
    r.storage === 'vmpool' || r.plugintype === 'rbd'
  );
  if (rdbStorages.length > 0) {
    // Use the first matching entry (all nodes report the same Ceph pool stats)
    const s = rdbStorages[0];
    const maxdisk = Number(s.maxdisk || 0);
    const disk = Number(s.disk || 0);
    ceph = {
      storage: s.storage,
      used_bytes: disk,
      total_bytes: maxdisk,
      used_gb: Math.round(disk / 1073741824 * 10) / 10,
      total_gb: Math.round(maxdisk / 1073741824 * 10) / 10,
      used_tb: Math.round(disk / (1024 ** 4) * 100) / 100,
      total_tb: Math.round(maxdisk / (1024 ** 4) * 100) / 100,
      pct: maxdisk > 0 ? Math.round((disk / maxdisk) * 100) : 0
    };
  }

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

module.exports = {
  getClusterHealth,
  getDeployingCount,
  buildDeployPreview,
  MAX_NODE_MEMORY_PCT,
  MAX_NODE_STORAGE_PCT,
  MAX_CONCURRENT_DEPLOYS
};