/**
 * ============================================================================
 * CLUSTER STORAGE SCAN
 * ============================================================================
 * Enumerate every VM-disk volume on the cluster with the minimum number of
 * Proxmox calls, under a hard wall-clock deadline.
 *
 * Replaces a triple-nested SERIAL loop (nodes -> storages -> contents) that
 * cost 1 + N + (N x S) round trips, every one of them a fresh TLS handshake
 * against a single pveproxy with a 30s socket timeout and no overall budget.
 * On Ceph the inner listing returned byte-identical results from every node and
 * the caller deduped them AFTER paying for each, so adding nodes made the audit
 * linearly slower for no new information. At ~10 nodes it ran past Cloudflare's
 * 100s origin limit, which returns an HTML error page.
 * ============================================================================
 */

const { runBatch } = require('./batch-deployer');
const { planStorageScan } = require('./reconcile-audit');

/** Don't start a job that cannot plausibly finish. */
const MIN_SLICE_MS = 1500;

function sleepUntil(deadlineAt) {
  const ms = Math.max(0, deadlineAt - Date.now());
  return new Promise(resolve => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

/**
 * Every VM-disk volume visible on the cluster.
 *
 * NEVER REJECTS. This is an invariant, not a nicety. The caller starts this at
 * t=0 and awaits it last so it overlaps the cluster and DB queries; if one of
 * those throws first, this promise is never awaited, and Node 20 turns an
 * unhandled rejection into a process exit. Failures come back as
 * `complete: false` plus the reason.
 *
 * @param {object}      a
 * @param {Function}    a.proxmoxAPI        injected so tests need no stub
 * @param {number}      a.deadlineAt        absolute Date.now() stamp
 * @param {number}     [a.concurrency=4]
 * @param {number}     [a.perCallTimeoutMs=12000]
 * @param {number}     [a.maxReaderAttempts=2]
 * @param {string}     [a.preferredNode]    node whose IP the API URL points at
 * @param {string}     [a.storageFilter]    limit to one storage id
 * @param {AbortSignal}[a.signal]
 * @param {Function}   [a.onProgress]       (done, total, node) => void
 * @returns {Promise<object>} never rejects
 */
async function scanClusterVolumes({
  proxmoxAPI,
  deadlineAt,
  concurrency = Number(process.env.RECONCILE_SCAN_CONCURRENCY) || 4,
  perCallTimeoutMs = Number(process.env.RECONCILE_SCAN_CALL_TIMEOUT_MS) || 12000,
  maxReaderAttempts = 2,
  preferredNode = null,
  storageFilter = null,
  signal = null,
  onProgress = () => {},
}) {
  const startedAt = Date.now();
  // An explicit 0 means "force per-node scanning" — the escape hatch for a
  // cluster whose storage.cfg mislabels a node-local storage as shared.
  const assumeShared = process.env.RECONCILE_ASSUME_SHARED !== '0';

  const empty = (extra) => ({
    volumes: [],
    skipped: { nodes: [], storages: [] },
    storages_failed: [],
    storages_scanned: 0,
    stats: { calls_naive: 0, shared_storages: 0 },
    calls_made: 0,
    complete: false,
    duration_ms: Date.now() - startedAt,
    nodes_total: 0,
    nodes_scanned: 0,
    ...extra,
  });

  try {
    const remaining = () => deadlineAt - Date.now();
    if (remaining() <= MIN_SLICE_MS) {
      return empty({ error: 'Disk scan skipped — no time left in the audit budget' });
    }

    // ---- 1. node list -------------------------------------------------------
    let nodeList;
    let callsMade = 1;
    try {
      nodeList = await proxmoxAPI('GET', '/api2/json/nodes', null, {
        timeoutMs: Math.min(perCallTimeoutMs, remaining()), signal,
      });
    } catch (e) {
      return empty({ calls_made: 1, error: `Could not list cluster nodes: ${e.message}` });
    }

    const nodes = (Array.isArray(nodeList) ? nodeList : []).map(n => ({
      node: n.node,
      // Offline nodes are dropped BEFORE a socket is opened. Reaching one costs
      // the full per-call timeout and returns nothing.
      online: n.status === 'online',
    }));
    const nodesTotal = nodes.length;

    // ---- 2. per-node storage listings (parallel, cheap) ---------------------
    const listings = await runBatch(
      nodes,
      async (n) => {
        if (!n.online) return { node: n.node, online: false, storages: null, error: null };
        if (remaining() <= MIN_SLICE_MS) {
          return { node: n.node, online: true, storages: null, error: 'deadline reached' };
        }
        try {
          const storages = await proxmoxAPI('GET', `/api2/json/nodes/${n.node}/storage`, null, {
            timeoutMs: Math.min(perCallTimeoutMs, remaining()), signal,
          });
          return { node: n.node, online: true, storages: storages || [], error: null };
        } catch (e) {
          return { node: n.node, online: true, storages: null, error: e.message };
        }
      },
      { concurrency }
    );
    callsMade += nodes.filter(n => n.online).length;

    const nodeStorages = listings.results.map((r, i) =>
      r && r.node ? r : { node: nodes[i].node, online: nodes[i].online, storages: null, error: 'worker failed' }
    );

    // ---- 3. plan: one job per unique shared storage, one per node-local -----
    const plan = planStorageScan(nodeStorages, { preferredNode, assumeShared, storageFilter });

    const scannedNodes = new Set();
    const storagesFailed = [];
    const volumes = [];
    let contentCalls = 0;
    let progressDone = 0;

    const readJob = async (job) => {
      // A shared storage can be read from any node that has it active, so a
      // failed reader falls through to the next. Two attempts bounds one job's
      // worst case at 2 x perCallTimeoutMs.
      const attempts = job.shared
        ? job.readers.slice(0, maxReaderAttempts)
        : job.readers.slice(0, 1);
      let lastErr = null;

      for (const node of attempts) {
        if (remaining() <= MIN_SLICE_MS) { lastErr = new Error('deadline reached'); break; }
        try {
          contentCalls++;
          const items = await proxmoxAPI(
            'GET',
            `/api2/json/nodes/${node}/storage/${job.storage}/content?content=images`,
            null,
            { timeoutMs: Math.min(perCallTimeoutMs, remaining()), signal }
          );
          for (const item of (items || [])) {
            volumes.push({
              node, storage: job.storage, shared: job.shared,
              volid: item.volid, size: item.size || 0,
            });
          }
          scannedNodes.add(node);
          return true;
        } catch (e) {
          lastErr = e;
        }
      }
      storagesFailed.push({
        node: attempts[0] || '?', storage: job.storage,
        reason: lastErr ? lastErr.message : 'no reader available',
      });
      return false;
    };

    const batch = runBatch(plan.jobs, readJob, {
      concurrency,
      onProgress: () => {
        progressDone++;
        onProgress(progressDone, plan.jobs.length, null);
      },
    });

    // Third layer of deadline enforcement: even a pathological hang inside a
    // worker returns whatever has accumulated by the deadline.
    const raced = await Promise.race([batch.then(() => 'done'), sleepUntil(deadlineAt).then(() => 'deadline')]);
    callsMade += contentCalls;

    const hitDeadline = raced === 'deadline';
    const complete =
      !hitDeadline &&
      storagesFailed.length === 0 &&
      plan.skipped.nodes.length === 0;

    // A node whose local storage was never listed was not really scanned, even
    // if a shared read happened to be attributed to it.
    const nodesScanned = nodeStorages.filter(
      n => n.online && Array.isArray(n.storages)
    ).length;

    return {
      volumes,
      skipped: plan.skipped,
      storages_failed: storagesFailed,
      storages_scanned: plan.jobs.length - storagesFailed.length,
      stats: plan.stats,
      calls_made: callsMade,
      complete,
      duration_ms: Date.now() - startedAt,
      nodes_total: nodesTotal,
      nodes_scanned: nodesScanned,
      online_nodes: nodes.filter(n => n.online).map(n => n.node),
      ...(hitDeadline ? { error: 'Disk scan hit its time budget' } : {}),
    };
  } catch (e) {
    // The never-reject invariant. See the header comment.
    return empty({ error: `Disk scan failed: ${e.message}` });
  }
}

module.exports = { scanClusterVolumes, MIN_SLICE_MS };
