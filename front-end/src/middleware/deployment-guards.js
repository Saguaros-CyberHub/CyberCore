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
  const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources');

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
        disk_pct: r.maxdisk ? Math.round(((r.disk || 0) / r.maxdisk) * 100) : 0,
        disk_used_gb: Math.round((r.disk || 0) / 1073741824 * 10) / 10,
        disk_total_gb: Math.round((r.maxdisk || 0) / 1073741824 * 10) / 10,
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

  const nodeList = Object.values(nodes);
  const warnings = [];

  for (const n of nodeList) {
    if (n.mem_pct >= MAX_NODE_MEMORY_PCT) {
      warnings.push(`Node ${n.node} memory at ${n.mem_pct}% (threshold: ${MAX_NODE_MEMORY_PCT}%)`);
    }
    if (n.disk_pct >= MAX_NODE_STORAGE_PCT) {
      warnings.push(`Node ${n.node} storage at ${n.disk_pct}% (threshold: ${MAX_NODE_STORAGE_PCT}%)`);
    }
  }

  return {
    nodes: nodeList,
    totalVMs,
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