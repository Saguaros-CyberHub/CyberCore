/**
 * ============================================================================
 * NODE SELECTOR
 * Determines the best Proxmox node for VM deployment
 * Ported from N8N "Determine Best Node for Deployment" workflow
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');
const { getSchedulingConfig } = require('./site-config');

function clamp01(x) {
  if (!Number.isFinite(x)) return 1;
  return Math.max(0, Math.min(1, x));
}

/**
 * Query Proxmox cluster resources and return the best node for deployment
 * @returns {{ node: string, score: number, cpu_pct: number, mem_pct: number, disk_pct: number, mem_free_gb: number }}
 */
async function selectBestNode() {
  const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=node');

  if (!Array.isArray(resources)) {
    throw new Error('Failed to get cluster resources');
  }

  const { min_free_mem_gb, min_free_disk_gb, node_score_weights: WEIGHTS } = getSchedulingConfig();

  // Normalize node data
  const nodes = resources
    .filter(n => n && n.type === 'node' && n.status === 'online')
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

module.exports = { selectBestNode };
