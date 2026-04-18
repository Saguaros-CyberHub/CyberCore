/**
 * ============================================================================
 * BATCH DEPLOYER
 * Deploys multiple lanes in parallel with concurrency control.
 * Replaces the sequential for-loop in group deployment with a worker pool
 * that processes N lanes simultaneously.
 * ============================================================================
 */

const MAX_CONCURRENT_LANES = parseInt(process.env.MAX_CONCURRENT_DEPLOYS) || 5;
const MAX_CONCURRENT_CLONES = parseInt(process.env.MAX_CONCURRENT_CLONES) || 4;

/**
 * Semaphore — limits concurrent access to a shared resource.
 * Used to throttle Proxmox clone operations across all lanes.
 */
class Semaphore {
  constructor(max) {
    this.max = max;
    this.current = 0;
    this.queue = [];
  }

  async acquire() {
    if (this.current < this.max) {
      this.current++;
      return;
    }
    return new Promise(resolve => this.queue.push(resolve));
  }

  release() {
    this.current--;
    if (this.queue.length > 0) {
      this.current++;
      this.queue.shift()();
    }
  }

  /** Run an async function with the semaphore held */
  async run(fn) {
    await this.acquire();
    try {
      return await fn();
    } finally {
      this.release();
    }
  }
}

/**
 * Create a shared clone semaphore for a batch deployment.
 * This limits the total number of Proxmox clone operations in flight
 * regardless of how many lanes are deploying simultaneously.
 *
 * @param {number} maxClones - max concurrent clone operations (default MAX_CONCURRENT_CLONES)
 * @returns {Semaphore}
 */
function createCloneSemaphore(maxClones) {
  return new Semaphore(maxClones || MAX_CONCURRENT_CLONES);
}

/**
 * Run an array of async jobs with bounded concurrency.
 * @param {Array} jobs        - Array of work items
 * @param {Function} worker   - async (job, index) => result
 * @param {object} opts
 * @param {number}  opts.concurrency   - max parallel workers (default MAX_CONCURRENT_LANES)
 * @param {Function} opts.onProgress   - (completed, total, job, result|error) => void
 * @returns {Promise<{ results: Array, errors: Array }>}
 */
async function runBatch(jobs, worker, opts = {}) {
  const concurrency = opts.concurrency || MAX_CONCURRENT_LANES;
  const onProgress = opts.onProgress || (() => {});

  const results = new Array(jobs.length).fill(null);
  const errors = [];
  let nextIndex = 0;
  let completed = 0;

  async function runNext() {
    while (nextIndex < jobs.length) {
      const idx = nextIndex++;
      const job = jobs[idx];
      try {
        const result = await worker(job, idx);
        results[idx] = result;
        completed++;
        onProgress(completed, jobs.length, job, { success: true, result });
      } catch (err) {
        completed++;
        errors.push({ index: idx, job, error: err.message });
        results[idx] = { error: err.message };
        onProgress(completed, jobs.length, job, { success: false, error: err.message });
      }
    }
  }

  // Launch concurrency workers
  const workers = [];
  for (let i = 0; i < Math.min(concurrency, jobs.length); i++) {
    workers.push(runNext());
  }
  await Promise.all(workers);

  return { results, errors };
}

/**
 * Distribute lane jobs across cluster nodes using round-robin weighted assignment.
 * Queries node resources ONCE, then assigns each lane to a node based on capacity.
 *
 * @param {Function} selectBestNode - the existing selectBestNode function
 * @param {Function} proxmoxAPI     - Proxmox API helper
 * @param {number}   numLanes       - how many lanes to distribute
 * @returns {Promise<string[]>}     - array of node names, one per lane
 */
async function distributeAcrossNodes(proxmoxAPI, numLanes) {
  const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=node');

  if (!Array.isArray(resources) || resources.length === 0) {
    throw new Error('Failed to get cluster resources for batch distribution');
  }

  const MIN_FREE_MEM_GB = 8;
  const minFreeMem = MIN_FREE_MEM_GB * 1024 ** 3;

  // Score nodes (lower = more capacity)
  const nodes = resources
    .filter(n => n && n.type === 'node' && n.status === 'online')
    .map(n => {
      const maxmem = Number(n.maxmem || 0);
      const mem = Number(n.mem || 0);
      const maxcpu = Number(n.maxcpu || 0);
      const cpu = Number(n.cpu || 0);
      const memFree = maxmem - mem;
      const cpuFrac = maxcpu > 0 ? cpu : 1;
      const memFrac = maxmem > 0 ? mem / maxmem : 1;

      return {
        node: n.node,
        memFree,
        score: (cpuFrac * 0.35) + (memFrac * 0.55),
        eligible: memFree >= minFreeMem
      };
    })
    .filter(n => n.eligible)
    .sort((a, b) => a.score - b.score); // best first

  if (nodes.length === 0) {
    throw new Error('No eligible nodes with sufficient free resources');
  }

  // Weighted round-robin: assign proportionally more lanes to nodes with lower scores
  // Invert scores so lower score = higher weight
  const maxScore = Math.max(...nodes.map(n => n.score)) + 0.01;
  const weights = nodes.map(n => maxScore - n.score);
  const totalWeight = weights.reduce((sum, w) => sum + w, 0);

  const assignments = [];
  const nodeCounts = new Array(nodes.length).fill(0);

  for (let i = 0; i < numLanes; i++) {
    // Find the node that is most "under-assigned" relative to its weight
    let bestIdx = 0;
    let bestDeficit = -Infinity;
    for (let j = 0; j < nodes.length; j++) {
      const targetShare = (weights[j] / totalWeight) * (i + 1);
      const deficit = targetShare - nodeCounts[j];
      if (deficit > bestDeficit) {
        bestDeficit = deficit;
        bestIdx = j;
      }
    }
    nodeCounts[bestIdx]++;
    assignments.push(nodes[bestIdx].node);
  }

  console.log(`[BatchDeployer] Distributed ${numLanes} lanes across ${nodes.length} nodes:`,
    nodes.map((n, i) => `${n.node}=${nodeCounts[i]}`).join(', '));

  return assignments;
}

module.exports = { runBatch, distributeAcrossNodes, createCloneSemaphore, MAX_CONCURRENT_LANES, MAX_CONCURRENT_CLONES };
