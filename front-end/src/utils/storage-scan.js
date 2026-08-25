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

/**
 * Whether a failure is worth a second attempt.
 *
 * A call that exhausted its deadline will exhaust the same deadline again, so
 * retrying it buys nothing and costs another full timeout — which is how a
 * retry meant to paper over transient forwarding errors instead halved the
 * number of nodes a fixed budget could reach.
 */
function worthRetrying(err) {
  return !(err && (err.code === 'PROXMOX_TIMEOUT' || err.code === 'PROXMOX_ABORTED'));
}

function sleep(ms) {
  return new Promise(resolve => {
    const t = setTimeout(resolve, ms);
    if (typeof t.unref === 'function') t.unref();
  });
}

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
 * @param {number}     [a.nodeListTimeoutMs=12000]  metadata reads
 * @param {number}     [a.contentTimeoutMs=90000]   volume enumeration
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
  // Two calls with wildly different shapes shared one timeout, and the shorter
  // one won. Listing a node's storages is a metadata read that returns in
  // milliseconds. Enumerating a storage's CONTENT walks every volume in it —
  // on a Ceph pool holding several hundred guests that legitimately runs past a
  // minute, and capping it at the metadata timeout turned a healthy pool into a
  // reported failure.
  nodeListTimeoutMs = Number(process.env.RECONCILE_NODE_LIST_TIMEOUT_MS) || 12000,
  contentTimeoutMs = Number(process.env.RECONCILE_CONTENT_TIMEOUT_MS) || 90000,
  maxReaderAttempts = 2,
  nodeListAttempts = Number(process.env.RECONCILE_NODE_LIST_ATTEMPTS) || 2,
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
    coverage: { shared_total: 0, shared_read: 0, local_total: 0, local_read: 0, shared_complete: false, nodes_unlisted: [] },
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
        timeoutMs: Math.min(nodeListTimeoutMs, remaining()), signal,
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
    // Every call lands on the ONE host in PROXMOX_API_URL, which forwards
    // anything addressed to a peer over the cluster link — a second internal
    // TLS hop through that peer's pveproxy. Those forwarded requests are the
    // ones that fail under load, with 595/596 or a reset, and they fail
    // transiently: the same node answers fine a moment later. One retry with a
    // short backoff turns most of that noise into a successful scan.
    const listNodeStorage = async (n) => {
      if (!n.online) return { node: n.node, online: false, storages: null, error: null };

      let lastErr = null;
      for (let attempt = 1; attempt <= nodeListAttempts; attempt++) {
        if (remaining() <= MIN_SLICE_MS) {
          return { node: n.node, online: true, storages: null, error: 'audit budget exhausted before this node was reached' };
        }
        try {
          callsMade++;
          const storages = await proxmoxAPI('GET', `/api2/json/nodes/${n.node}/storage`, null, {
            timeoutMs: Math.min(nodeListTimeoutMs, remaining()), signal,
          });
          return { node: n.node, online: true, storages: storages || [], error: null, attempts: attempt };
        } catch (e) {
          lastErr = e;
          if (!worthRetrying(e)) break;
          if (attempt < nodeListAttempts) await sleep(300 * attempt);
        }
      }
      return { node: n.node, online: true, storages: null, error: lastErr ? lastErr.message : 'unknown error' };
    };

    const listings = await runBatch(nodes, listNodeStorage, { concurrency });

    const nodeStorages = listings.results.map((r, i) =>
      r && r.node ? r : { node: nodes[i].node, online: nodes[i].online, storages: null, error: 'worker failed' }
    );

    // ---- 3. plan: one job per unique shared storage, one per node-local -----
    const plan = planStorageScan(nodeStorages, { preferredNode, assumeShared, storageFilter });

    const scannedNodes = new Set();
    const storagesFailed = [];
    const volumes = [];
    const jobOutcomes = [];
    let contentCalls = 0;
    let progressDone = 0;

    const readJob = async (job) => {
      // A shared storage can be read from any node that has it active, so a
      // failed reader falls through to the next, bounding one job's worst case
      // at maxReaderAttempts x contentTimeoutMs.
      const attempts = job.shared
        ? job.readers.slice(0, maxReaderAttempts)
        : job.readers.slice(0, 1);
      let lastErr = null;

      onProgress(progressDone, plan.jobs.length, job.storage);

      for (const node of attempts) {
        if (remaining() <= MIN_SLICE_MS) { lastErr = new Error('audit budget exhausted before this storage was read'); break; }
        try {
          contentCalls++;
          const items = await proxmoxAPI(
            'GET',
            `/api2/json/nodes/${node}/storage/${job.storage}/content?content=images`,
            null,
            { timeoutMs: Math.min(contentTimeoutMs, remaining()), signal }
          );
          for (const item of (items || [])) {
            volumes.push({
              node, storage: job.storage, shared: job.shared,
              volid: item.volid, size: item.size || 0,
            });
          }
          scannedNodes.add(node);
          jobOutcomes.push({ storage: job.storage, shared: job.shared, ok: true, node });
          return true;
        } catch (e) {
          lastErr = e;
          // Falling through to another node is for a reader that REFUSED. If
          // this one ran out of time, the next will too.
          if (!worthRetrying(e)) break;
        }
      }
      const reason = lastErr ? lastErr.message : 'no reader available';
      storagesFailed.push({ node: attempts[0] || '?', storage: job.storage, shared: job.shared, reason });
      jobOutcomes.push({ storage: job.storage, shared: job.shared, ok: false, reason });
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

    // Losing a node does NOT cost the same coverage on both storage kinds, and
    // conflating them badly overstates the damage on a Ceph cluster. A shared
    // pool is one logical volume list readable from ANY node that has it
    // active, so one reachable node covers it completely. Only node-LOCAL
    // images (local-lvm, local ZFS) go unseen when a node is unreachable — and
    // for a node whose storage list never came back, we cannot even say whether
    // it had any.
    const sharedJobs = jobOutcomes.filter(j => j.shared);
    const localJobs = jobOutcomes.filter(j => !j.shared);
    const coverage = {
      shared_total: sharedJobs.length,
      shared_read: sharedJobs.filter(j => j.ok).length,
      local_total: localJobs.length,
      local_read: localJobs.filter(j => j.ok).length,
      // True when every shared pool we know about was read: shared-storage
      // orphans are then a complete list, whatever happened elsewhere.
      shared_complete: sharedJobs.length > 0 && sharedJobs.every(j => j.ok),
      nodes_unlisted: nodeStorages.filter(n => n.online && !Array.isArray(n.storages)).map(n => n.node),
    };

    return {
      volumes,
      skipped: plan.skipped,
      storages_failed: storagesFailed,
      storages_scanned: plan.jobs.length - storagesFailed.length,
      stats: plan.stats,
      coverage,
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
