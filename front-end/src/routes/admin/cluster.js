/**
 * ============================================================================
 * Cluster & Reconcile Admin Routes
 * Cluster health, deploy preview, reconciliation, orphan sweeps,
 * activity log, and VM-level utilities.
 * ============================================================================
 */

const express = require('express');
const router = express.Router();
const { authenticateToken, requireRole } = require('../../middleware/auth');
const { proxmoxAPI } = require('../../utils/proxmox');
const { cybercoreQuery } = require('../../utils/cybercore-db');
const { query } = require('../../utils/db');
const { guacAPI } = require('../../utils/guacamole');
const { getClusterHealth, buildDeployPreview } = require('../../middleware/deployment-guards');
const { logActivity } = require('../../middleware/activity-logger');
const audit = require('../../utils/audit');
const reconcileJob = require('../../utils/reconcile-job');
const { runReconcileScan, RANGES } = require('../../utils/reconcile-scan');
const { scanClusterVolumes } = require('../../utils/storage-scan');
const {
  parseVolid, inCyberhubRange, vmidRole, computeExpectedPeers, buildLaneVmIndex,
} = require('../../utils/reconcile-audit');
const guards = require('../../utils/reconcile-guards');
const { claimsSql } = require('../../utils/lane-claims');
const { ZONE_RE } = require('../../utils/lab-network-provision');
const { getPhysicalClusterIps } = require('../../utils/site-config');
const { waitForGuestAgent } = require('../../utils/script-executor');

const adminOnly = requireRole('admin');

// The VMID ranges owned by CyberHub live in utils/reconcile-scan.js (RANGES),
// built from utils/attached-modules.js. Single-sourced so the audit and the
// disk sweep below cannot drift apart on what counts as "ours".


// ============================================================================
// CLUSTER HEALTH & DEPLOYMENT GUARDS
// ============================================================================

router.get('/proxmox/status', authenticateToken, adminOnly, async (req, res) => {
  try {
    await proxmoxAPI('GET', '/api2/json/version');
    res.json({ connected: true, url: process.env.PROXMOX_API_URL || 'https://100.100.10.10:8006' });
  } catch (error) {
    res.status(502).json({ connected: false, error: error.message });
  }
});

router.get('/cluster/health', authenticateToken, adminOnly, async (req, res) => {
  try {
    const health = await getClusterHealth(proxmoxAPI);
    res.json(health);
  } catch (error) {
    res.status(502).json({ error: `Failed to fetch cluster health: ${error.message}` });
  }
});

router.post('/deploy-preview', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { num_lanes = 1, attack_boxes = false, challenge_vm_count = 1 } = req.body;
    const preview = await buildDeployPreview({
      numLanes: parseInt(num_lanes) || 1,
      attackBoxes: !!attack_boxes,
      challengeVmCount: parseInt(challenge_vm_count) || 1,
      proxmoxAPI,
      cybercoreQuery
    });
    res.json(preview);
  } catch (error) {
    res.status(502).json({ error: `Failed to build deploy preview: ${error.message}` });
  }
});


// ============================================================================
// RECONCILE — compare DB state against live Proxmox resources
// ============================================================================
// The audit runs DETACHED from the request that starts it.
//
// It used to run inline, and on a Ceph cluster of any size it outlived
// Cloudflare's 100s origin timeout — which answers with an HTML page, so the
// admin UI reported a JSON parse error rather than a timeout. The scan is much
// faster now (see utils/storage-scan.js), but "fast enough today" is not a
// property worth depending on: one wedged node can still eat the budget. So the
// request only ever starts or reads a job, and the browser polls.
//
//   POST /reconcile/run           start (or join) a scan          -> 202
//   GET  /reconcile/status/:id    progress; result on the last poll
//   GET  /reconcile               the last completed audit, instantly
// ============================================================================

router.get('/reconcile', authenticateToken, adminOnly, async (req, res) => {
  try {
    // ?fresh=1 exists for curl and scripts; it starts a scan and returns the
    // job rather than blocking. The UI uses POST /reconcile/run.
    if (req.query.fresh === '1') {
      const claim = await reconcileJob.acquireJob({ startedBy: req.user?.userId });
      if (!claim.attached) startReconcileRun(req, claim.job.job_id);
      return res.status(202).json({ ...claim.job, attached: claim.attached });
    }

    const [cached, runningJobId] = await Promise.all([
      reconcileJob.getCachedResult(),
      reconcileJob.getLockOwner(),
    ]);

    if (!cached) {
      // 200, not 404: "no audit has run yet" is a normal render state. A 404
      // would take the api() helper's throw branch and paint a red error.
      return res.json({ cached: false, empty: true, age_seconds: null, running: !!runningJobId, job_id: runningJobId });
    }
    res.json({ ...cached, cached: true, running: !!runningJobId, job_id: runningJobId || null });
  } catch (error) {
    console.error('[Reconcile] Cache read failed:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * Kick off the detached scan.
 *
 * The actor is snapshotted HERE, synchronously: the runner outlives the
 * response and req.user must not be read from a closure after that point.
 */
function startReconcileRun(req, jobId) {
  const actor = req.user
    ? { userId: req.user.userId, email: req.user.email, role: req.user.role, type: 'user' }
    : null;

  (async () => {
    const t0 = Date.now();
    try {
      const result = await runReconcileScan({
        onPhase: (phase, detail, done, total) =>
          reconcileJob.updateJob(jobId, { phase, phase_detail: detail, done, total }),
      });
      await reconcileJob.finishJob(jobId, result, Date.now() - t0);
      audit.log({
        actor, action: 'reconcile_scan_completed', source: 'core',
        target: { type: 'infra', id: jobId },
        metadata: { duration_ms: Date.now() - t0, ...result.summary },
      });
    } catch (err) {
      console.error(`[Reconcile] Job ${jobId} failed: ${err.message}`);
      await reconcileJob.failJob(jobId, err.message);
      audit.log({
        actor, action: 'reconcile_scan_failed', status: 'failure', source: 'core',
        target: { type: 'infra', id: jobId }, metadata: { error: err.message },
      });
    } finally {
      await reconcileJob.releaseJob(jobId);
    }
  })();
}

router.post('/reconcile/run', authenticateToken, adminOnly, async (req, res) => {
  try {
    const claim = await reconcileJob.acquireJob({
      force: req.body?.force === true,
      startedBy: req.user?.userId,
    });

    // Two admins clicking at once share ONE scan. Not a 409 — the second admin
    // did nothing wrong, and doubling the load on pveproxy helps nobody.
    if (claim.attached) return res.status(202).json({ ...claim.job, attached: true });

    logActivity(req, 'reconcile_scan_started', 'infra', claim.job.job_id, { job_id: claim.job.job_id });
    startReconcileRun(req, claim.job.job_id);
    res.status(202).json({ ...claim.job, attached: false });
  } catch (error) {
    console.error('[Reconcile] Could not start scan:', error.message);
    res.status(500).json({ error: error.message });
  }
});

router.get('/reconcile/status/:job_id', authenticateToken, adminOnly, async (req, res) => {
  const jobId = req.params.job_id;
  if (!reconcileJob.isValidJobId(jobId)) {
    return res.status(400).json({ error: 'Malformed job id', state: 'unknown' });
  }
  try {
    const status = await reconcileJob.getJobStatus(jobId);
    if (!status) return res.status(404).json({ error: 'Unknown or expired job', state: 'unknown' });

    // The result rides along ONLY on the terminal poll — the client stops
    // there, so it costs one payload and saves a follow-up round trip.
    if (status.state === 'done') {
      const cached = await reconcileJob.getCachedResult();
      return res.json({ ...status, result: cached || null });
    }
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Every field the client sends here is a HINT. The vmid is re-checked against
// the CyberHub ranges and against a freshly rebuilt set of claimed lane VMIDs,
// and the node is re-derived from /cluster/resources — because this endpoint
// used to purge whatever it was given, and the audit that populated the button
// listed live lanes' slot-1+ workstations as orphans.
router.post('/reconcile/destroy-vm', authenticateToken, adminOnly, async (req, res) => {
  const vmid = Number(req.body?.vmid);
  if (!Number.isFinite(vmid)) return res.status(400).json({ error: 'vmid required' });
  try {
    await guards.requireFreshAudit(req.body?.audit_job_id);
    const [cluster, claimed] = await Promise.all([
      guards.readTrustedClusterView(),
      guards.readClaimedVmIds(),
    ]);
    const target = guards.assertDestroyableVm({
      vmid, cluster, claimed, inRange: (id) => inCyberhubRange(id, RANGES),
    });

    const base = `/api2/json/nodes/${target.node}/${target.type}/${vmid}`;
    try {
      await proxmoxAPI('POST', `${base}/status/stop`);
      await new Promise(r => setTimeout(r, 3000));
    } catch (e) { /* may already be stopped */ }
    try {
      await proxmoxAPI('PUT', `${base}/config`, { protection: 0 });
    } catch (e) { /* may not have protection set */ }
    const delPath = target.type === 'lxc'
      ? `${base}?purge=1&force=1`
      : `${base}?purge=1`;
    await proxmoxAPI('DELETE', delPath);
    console.log(`[Reconcile] Destroyed orphaned VM ${vmid} (${target.name || '?'}) on ${target.node}`);
    logActivity(req, 'destroy_orphan_vm', 'vm', vmid, {
      vmid, node: target.node, type: target.type, name: target.name,
    });
    res.json({ ok: true, vmid, node: target.node, type: target.type });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    console.error(`[Reconcile] Failed to destroy VM ${vmid}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

// Tombstoning a lane RELEASES its vxlan_id and gateway WAN address for reuse
// (utils/lane-claims.js), so it is only safe once nothing of the lane is left.
// This used to take the client's lane_id on trust and write the row — driven by
// a table that can be a day old, and by a staleness rule that fires whenever the
// WORKLOAD VMs are gone even if the gateway is still up.
router.post('/reconcile/mark-deleted', authenticateToken, adminOnly, async (req, res) => {
  const { lane_id } = req.body;
  if (!lane_id) return res.status(400).json({ error: 'lane_id required' });
  try {
    await guards.requireFreshAudit(req.body?.audit_job_id);
    const cluster = await guards.readTrustedClusterView();

    const laneRes = await cybercoreQuery(
      `SELECT lane_id, vxlan_id, name, status, config FROM cybercore_lane WHERE lane_id = $1`,
      [lane_id]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });
    const lane = laneRes.rows[0];

    // Re-derived server-side, and against EVERY recorded VMID rather than just
    // the workload set: a surviving gateway is disqualifying here even though it
    // does not stop computeStaleLanes from flagging the lane. Freeing the VXLAN
    // while that container is still answering ARP is how two lanes end up on one
    // L2 segment.
    const index = buildLaneVmIndex([lane], {
      includeWorkstations: true,
      includeNullVxlan: true,
    });
    const alive = [...(index.expectedByLane.get(lane.lane_id) || [])]
      .filter(id => cluster.liveVmIds.has(id));

    if (alive.length > 0) {
      return res.status(409).json({
        error:
          `Lane "${lane.name || lane_id}" still has ${alive.length} machine(s) on the cluster `
          + `(${alive.join(', ')}). Marking it deleted would release VXLAN ${lane.vxlan_id} `
          + 'while they are still running. Purge the lane instead.',
        alive_vmids: alive,
        lane_id,
      });
    }

    await cybercoreQuery(
      `UPDATE cybercore_lane SET status = 'deleted', updated_at = NOW() WHERE lane_id = $1`,
      [lane_id]
    );
    console.log(`[Reconcile] Marked lane ${lane_id} as deleted (verified: no VMs on the cluster)`);
    logActivity(req, 'lane_mark_deleted', 'lane', lane_id, {
      lane_id, vxlan_id: lane.vxlan_id, reason: 'verified stale — no Proxmox VMs',
    });
    res.json({ ok: true, lane_id });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-disk', authenticateToken, adminOnly, async (req, res) => {
  const { node, storage, volid } = req.body;
  if (!node || !storage || !volid) return res.status(400).json({ error: 'node, storage, and volid required' });

  // Had NO validation at all: any volid the client sent was deleted. The bulk
  // sweep below has always re-derived its target list server-side; the
  // single-disk button never did.
  try {
    const parsed = parseVolid(volid);
    if (!parsed) {
      return res.status(400).json({ error: `Cannot read an owning VMID out of '${volid}' — refusing to delete it.` });
    }
    if (!inCyberhubRange(parsed.vmid, RANGES)) {
      return res.status(400).json({
        error: `Disk ${volid} belongs to VMID ${parsed.vmid}, outside every CyberHub-owned range — refusing to delete it.`,
      });
    }
    await guards.requireFreshAudit(req.body?.audit_job_id);
    const cluster = await guards.readTrustedClusterView();
    if (cluster.liveVmIds.has(parsed.vmid)) {
      return res.status(409).json({
        error: `VMID ${parsed.vmid} is running on the cluster — ${volid} is its live disk, not an orphan. Re-run the audit.`,
      });
    }
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    return res.status(500).json({ error: error.message });
  }

  let lastErr = null;
  for (let attempt = 1; attempt <= 3; attempt++) {
    try {
      await proxmoxAPI('DELETE',
        `/api2/json/nodes/${node}/storage/${storage}/content/${encodeURIComponent(volid)}`);
      console.log(`[Reconcile] Destroyed orphaned disk ${volid} on ${node}/${storage}`);
      logActivity(req, 'destroy_orphan_disk', 'storage', null, { volid, node, storage });
      return res.json({ ok: true, volid, node, storage });
    } catch (e) {
      lastErr = e;
      if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
    }
  }
  console.error(`[Reconcile] Failed to destroy disk ${volid}: ${lastErr?.message}`);
  res.status(500).json({ error: lastErr?.message || 'Delete failed after 3 attempts' });
});

router.post('/reconcile/destroy-guac-connection', authenticateToken, adminOnly, async (req, res) => {
  const { id, name } = req.body;
  if (!id) return res.status(400).json({ error: 'id required' });
  try {
    await guards.requireFreshAudit(req.body?.audit_job_id);

    // Deleting a console a live lane still owns takes a student's only way in,
    // and the audit identifies CyberHub connections partly by NAME PATTERN
    // (computeOrphanedGuacConnections), which a renamed cohort can match by
    // accident. Re-check the id against what claiming lanes actually record.
    const held = await cybercoreQuery(
      `SELECT l.lane_id, l.name, l.status
         FROM cybercore_lane l
        WHERE ${claimsSql('l')}
          AND (
            l.config->>'guac_connection_id' = $1
            OR EXISTS (SELECT 1 FROM jsonb_array_elements(
                         COALESCE(l.config->'workstations', '[]'::jsonb)) w
                        WHERE w->>'guac_connection_id' = $1)
            OR EXISTS (SELECT 1 FROM jsonb_array_elements(
                         COALESCE(l.config->'consoles', '[]'::jsonb)) c
                        WHERE c->>'guac_connection_id' = $1)
          )
        LIMIT 1`,
      [String(id)]
    );
    if (held.rows.length > 0) {
      const l = held.rows[0];
      return res.status(409).json({
        error:
          `Guacamole connection ${id} is the console for lane "${l.name || l.lane_id}" `
          + `(status ${l.status}), which still holds it. Re-run the audit.`,
        lane_id: l.lane_id,
      });
    }

    await guacAPI('DELETE', `/connections/${encodeURIComponent(id)}`);
    console.log(`[Reconcile] Destroyed orphaned Guac connection ${id} (${name || '?'})`);
    logActivity(req, 'destroy_orphan_guac_connection', 'guacamole', null, { id, name });
    res.json({ ok: true, id });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    console.error(`[Reconcile] Failed to destroy Guac connection ${id}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-zone', authenticateToken, adminOnly, async (req, res) => {
  const { zone } = req.body;
  if (!zone) return res.status(400).json({ error: 'zone required' });
  // Validated before it reaches a Proxmox URL. Same guard the create path uses.
  if (!ZONE_RE.test(zone)) return res.status(400).json({ error: 'zone must be 1-8 alphanumeric characters starting with a letter' });
  try {
    await guards.requireFreshAudit(req.body?.audit_job_id);
    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
    const zoneVnets = (Array.isArray(vnets) ? vnets : []).filter(v => v.zone === zone);

    // The most destructive endpoint in this file — it removes EVERY VNet in the
    // zone — and it had no lane check whatsoever. A VNet tag is a lane's
    // vxlan_id, so a zone still carrying a claiming lane's tag is a zone whose
    // deletion cuts that lane's network out from under it.
    const zoneTags = zoneVnets.map(v => Number(v.tag)).filter(Number.isFinite);
    if (zoneTags.length > 0) {
      const held = await cybercoreQuery(
        `SELECT lane_id, name, vxlan_id, status FROM cybercore_lane
          WHERE vxlan_id = ANY($1::int[]) AND ${claimsSql()}`,
        [zoneTags]
      );
      if (held.rows.length > 0) {
        return res.status(409).json({
          error:
            `Zone '${zone}' still carries the VNet(s) for ${held.rows.length} live lane(s) `
            + `(vxlan ${held.rows.map(r => r.vxlan_id).join(', ')}). Deleting it would leave them `
            + 'with no network. Tear those lanes down first.',
          lanes: held.rows,
        });
      }
    }

    for (const vnet of zoneVnets) {
      console.log(`[Reconcile] Deleting VNet '${vnet.vnet}' in zone '${zone}'`);
      await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet.vnet}`);
    }
    console.log(`[Reconcile] Deleting SDN zone '${zone}'`);
    await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/zones/${zone}`);
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (e) { /* best effort */ }
    console.log(`[Reconcile] Zone '${zone}' destroyed (${zoneVnets.length} VNets removed)`);
    logActivity(req, 'destroy_orphan_zone', 'network', zone, { zone, vnets_removed: zoneVnets.length });
    res.json({ ok: true, zone, vnets_removed: zoneVnets.length });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    console.error(`[Reconcile] Failed to destroy zone ${zone}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});

router.post('/reconcile/destroy-vnet', authenticateToken, adminOnly, async (req, res) => {
  const { vnet } = req.body;
  if (!vnet) return res.status(400).json({ error: 'vnet required' });
  if (!/^[a-z][a-z0-9]{0,9}$/.test(vnet)) return res.status(400).json({ error: 'malformed vnet name' });
  try {
    await guards.requireFreshAudit(req.body?.audit_job_id);

    // Same check as destroy-zone, one VNet wide: the tag IS a lane's vxlan_id.
    const all = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets').catch(() => []);
    const target = (Array.isArray(all) ? all : []).find(v => v.vnet === vnet);
    const tag = target ? Number(target.tag) : NaN;
    if (Number.isFinite(tag)) {
      const held = await cybercoreQuery(
        `SELECT lane_id, name, vxlan_id, status FROM cybercore_lane
          WHERE vxlan_id = $1 AND ${claimsSql()}`,
        [tag]
      );
      if (held.rows.length > 0) {
        return res.status(409).json({
          error:
            `VNet '${vnet}' carries tag ${tag}, which lane "${held.rows[0].name || held.rows[0].lane_id}" `
            + `(status ${held.rows[0].status}) still holds. Deleting it would cut that lane off the network.`,
          lanes: held.rows,
        });
      }
    }

    await proxmoxAPI('DELETE', `/api2/json/cluster/sdn/vnets/${vnet}`);
    try { await proxmoxAPI('PUT', '/api2/json/cluster/sdn'); } catch (e) { /* best effort */ }
    console.log(`[Reconcile] Deleted orphaned VNet '${vnet}'`);
    logActivity(req, 'destroy_orphan_vnet', 'network', vnet, { vnet });
    res.json({ ok: true, vnet });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ORPHANED DISK SWEEP
// ============================================================================
// Shares the parallel, shared-storage-aware scan with the audit. It used to
// carry its own copy of the same triple-nested serial loop, so "Sweep All" hit
// the same tunnel timeout the audit did.
//
// Deletes still run SEQUENTIALLY, deliberately — concurrent RBD removals
// contend on cfs-lock and start failing each other.
// ============================================================================

router.post('/sweep-orphaned-disks', authenticateToken, adminOnly, async (req, res) => {
  const dry_run = req.body?.dry_run !== false;
  const storageFilter = req.body?.storage || null;
  const vmidPattern = req.body?.vmid_pattern ? new RegExp(req.body.vmid_pattern) : null;
  // Unlike the audit, this endpoint answers the request it is on, so it stays
  // under the tunnel's 100s origin timeout. It does NOT inherit the audit's
  // (much larger) detached budget.
  const budgetMs = Number(process.env.RECONCILE_SWEEP_BUDGET_MS) || 45000;
  const deleted = [];
  const errors = [];

  try {
    // Everything else here is already re-derived server-side; this only stops a
    // day-old page from starting a bulk delete without the operator re-scanning.
    await guards.requireFreshAudit(req.body?.audit_job_id);
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources', null, { timeoutMs: 15000 });
    const liveVmIds = new Set();
    for (const r of resources || []) {
      if ((r.type === 'qemu' || r.type === 'lxc') && typeof r.vmid === 'number') liveVmIds.add(r.vmid);
    }

    // Refuse to sweep against an empty cluster view: every image on shared
    // storage would classify as an orphan, and this endpoint deletes.
    if (liveVmIds.size === 0) {
      return res.status(409).json({
        error: 'Cluster reported no VMs — refusing to sweep. Every disk would look orphaned.',
      });
    }

    const scan = await scanClusterVolumes({
      proxmoxAPI,
      deadlineAt: Date.now() + budgetMs,
      storageFilter,
      concurrency: Number(process.env.RECONCILE_SCAN_CONCURRENCY) || 4,
    });
    if (scan.error) errors.push(scan.error);
    for (const f of scan.storages_failed) errors.push(`Content of ${f.storage} on ${f.node}: ${f.reason}`);
    for (const n of scan.skipped.nodes) errors.push(`Skipped node ${n.node}: ${n.reason}`);

    const seenVolids = new Set();
    const dedupedOrphans = [];
    for (const v of scan.volumes) {
      const parsed = parseVolid(v.volid);
      if (!parsed) continue;
      // Range-filter server-side. The UI used to send a vmid_pattern of
      // ^[167][0-9]{5}$, which silently excluded the goad_controller (2xxxxx)
      // and attached_module (8xxxxx) disks the audit had just listed.
      if (!inCyberhubRange(parsed.vmid, RANGES)) continue;
      if (vmidPattern && !vmidPattern.test(String(parsed.vmid))) continue;
      if (liveVmIds.has(parsed.vmid)) continue;
      if (seenVolids.has(v.volid)) continue;
      seenVolids.add(v.volid);
      dedupedOrphans.push({
        node: v.node, storage: v.storage, volid: v.volid, vmid: parsed.vmid,
        role: vmidRole(parsed.vmid, RANGES),
        size_bytes: v.size || 0,
        size_gb: v.size ? (v.size / (1024 ** 3)).toFixed(2) : '0.00',
      });
    }
    dedupedOrphans.sort((a, b) => a.volid.localeCompare(b.volid));

    if (!dry_run) {
      if (!scan.complete) {
        return res.status(409).json({
          error: 'Disk scan was incomplete — refusing to sweep on a partial view. Re-run the audit.',
          scan_errors: errors,
        });
      }
      for (const o of dedupedOrphans) {
        let ok = false;
        let lastErr = null;
        for (let attempt = 1; attempt <= 3 && !ok; attempt++) {
          try {
            await proxmoxAPI('DELETE',
              `/api2/json/nodes/${o.node}/storage/${o.storage}/content/${encodeURIComponent(o.volid)}`);
            deleted.push(o);
            console.log(`[Orphan Sweep] Deleted ${o.volid} on ${o.node}/${o.storage}`);
            ok = true;
          } catch (e) {
            lastErr = e;
            if (attempt < 3) await new Promise(r => setTimeout(r, 1500 * attempt));
          }
        }
        if (!ok && lastErr) errors.push(`Delete ${o.volid} on ${o.node}: ${lastErr.message}`);
      }
    }

    const totalBytes = dedupedOrphans.reduce((sum, o) => sum + (o.size_bytes || 0), 0);
    const reclaimedBytes = deleted.reduce((sum, o) => sum + (o.size_bytes || 0), 0);

    logActivity(req, dry_run ? 'scan_orphaned_disks' : 'sweep_orphaned_disks', 'storage', null,
      { storage_filter: storageFilter || 'all', found: dedupedOrphans.length, deleted: deleted.length, total_gb: (totalBytes / (1024 ** 3)).toFixed(2) }
    );

    res.json({
      success: true,
      dry_run,
      storage_filter: storageFilter,
      vmid_pattern: req.body?.vmid_pattern || null,
      scan_complete: scan.complete,
      orphans_found: dedupedOrphans.length,
      orphans_deleted: deleted.length,
      total_orphan_size_gb: (totalBytes / (1024 ** 3)).toFixed(2),
      reclaimed_size_gb: (reclaimedBytes / (1024 ** 3)).toFixed(2),
      orphans: dedupedOrphans,
      errors: errors.length > 0 ? errors : undefined
    });
  } catch (error) {
    if (guards.handleGuardError(error, res)) return;
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// SDN ZONE PEER REPAIR
// ============================================================================
// A VXLAN zone's `peers` list is written ONCE, when the zone is created
// (utils/lab-network-provision.js). Join a node to the cluster afterwards and
// no existing zone ever learns about it, so a lane placed on that node comes up
// with no VXLAN peering and nothing in the app notices. This is the repair.
//
// One zone per call, explicitly, matching the other reconcile actions — there
// is deliberately no "fix all", because applying SDN commits every pending SDN
// change on the cluster, not just ours.
// ============================================================================

router.post('/reconcile/fix-zone-peers', authenticateToken, adminOnly, async (req, res) => {
  const { zone, expected, digest, apply } = req.body || {};
  if (!zone) return res.status(400).json({ error: 'zone required' });
  if (!ZONE_RE.test(zone)) {
    return res.status(400).json({ error: 'zone must be 1-8 alphanumeric characters starting with a letter' });
  }

  try {
    const [zones, clusterStatus] = await Promise.all([
      proxmoxAPI('GET', '/api2/json/cluster/sdn/zones', null, { timeoutMs: 15000 }),
      proxmoxAPI('GET', '/api2/json/cluster/status', null, { timeoutMs: 15000 }),
    ]);

    const target = (Array.isArray(zones) ? zones : []).find(z => z.zone === zone);
    if (!target) return res.status(404).json({ error: `Zone '${zone}' not found` });
    if (target.type !== 'vxlan') {
      return res.status(400).json({ error: `Zone '${zone}' is type '${target.type}' — peers only apply to vxlan zones` });
    }

    // Recomputed server-side from a fresh /cluster/status. The client's list is
    // a confirmation token, never the source of truth.
    const fresh = computeExpectedPeers(clusterStatus, getPhysicalClusterIps());
    if (fresh.ips.length < 2) {
      return res.status(400).json({
        error: `Refusing to write a ${fresh.ips.length}-peer VXLAN zone — only ${fresh.ips.length} online node address(es) resolved`,
      });
    }

    if (Array.isArray(expected) && expected.length) {
      const claimed = [...new Set(expected.map(String))].sort().join(',');
      if (claimed !== fresh.csv) {
        // 409 means re-check, not fail. The api() helper preserves err.data, so
        // the UI can show the operator the set that is actually current.
        return res.status(409).json({
          error: 'The peer set changed since the audit — re-run it before repairing.',
          expected: fresh.ips,
        });
      }
    }

    const peersBefore = target.peers || '';
    const body = { peers: fresh.csv };
    // Proxmox rejects a stale digest, which turns "someone edited this zone
    // since your audit" into a clean 400 instead of a silent clobber.
    if (digest) body.digest = digest;
    await proxmoxAPI('PUT', `/api2/json/cluster/sdn/zones/${encodeURIComponent(zone)}`, body, { timeoutMs: 20000 });

    let applied = false;
    if (apply !== false) {
      await proxmoxAPI('PUT', '/api2/json/cluster/sdn', null, { timeoutMs: 30000 });
      applied = true;
    }

    const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets', null, { timeoutMs: 15000 })
      .catch(() => []);
    const vnetsInZone = (Array.isArray(vnets) ? vnets : []).filter(v => v.zone === zone).length;

    console.log(`[Reconcile] Zone '${zone}' peers: '${peersBefore}' -> '${fresh.csv}' (applied=${applied})`);
    logActivity(req, 'fix_zone_peers', 'network', zone, {
      zone, peers_before: peersBefore, peers_after: fresh.csv, applied, vnets_in_zone: vnetsInZone,
    });

    res.json({
      ok: true, zone,
      peers_before: peersBefore, peers_after: fresh.csv,
      applied, vnets_in_zone: vnetsInZone,
    });
  } catch (error) {
    console.error(`[Reconcile] Failed to fix peers on zone ${zone}: ${error.message}`);
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// ACTIVITY LOG
// ============================================================================

router.get('/activity-log', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { action_type, user_id: filterUserId, from, to, limit: lim, offset: off, search } = req.query;
    const limit = Math.min(parseInt(lim) || 50, 200);
    const offset = parseInt(off) || 0;

    let where = [];
    let params = [];
    let paramIdx = 1;

    if (action_type) { where.push(`a.action_type = $${paramIdx++}`); params.push(action_type); }
    if (filterUserId) { where.push(`a.user_id = $${paramIdx++}`); params.push(filterUserId); }
    if (from) { where.push(`a.created_at >= $${paramIdx++}`); params.push(from); }
    if (to) { where.push(`a.created_at <= $${paramIdx++}`); params.push(to); }
    if (search) {
      where.push(`(a.action_type ILIKE $${paramIdx} OR a.entity_type ILIKE $${paramIdx})`);
      params.push(`%${search}%`);
      paramIdx++;
    }

    const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';

    const [logs, countResult] = await Promise.all([
      query(
        `SELECT a.* FROM activity_log a ${whereClause} ORDER BY a.created_at DESC LIMIT $${paramIdx} OFFSET $${paramIdx + 1}`,
        [...params, limit, offset]
      ),
      query(`SELECT COUNT(*) AS total FROM activity_log a ${whereClause}`, params)
    ]);

    res.json({
      logs: logs.rows,
      total: parseInt(countResult.rows[0].total),
      limit,
      offset
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});


// ============================================================================
// VM PROGRESS LOG
// ============================================================================

router.get('/vm-progress/:laneId', authenticateToken, adminOnly, async (req, res) => {
  try {
    const { vm_name } = req.query;
    const laneResult = await cybercoreQuery(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 AND status = 'active'`,
      [req.params.laneId]
    );
    if (laneResult.rows.length === 0) return res.status(404).json({ error: 'Lane not found' });

    const config = typeof laneResult.rows[0].config === 'string'
      ? JSON.parse(laneResult.rows[0].config) : laneResult.rows[0].config;

    let vm = (config.vms || []).find(v => v.name === vm_name);
    if (!vm && config.challenge_vm_id) {
      vm = { vm_id: config.challenge_vm_id, node: config.node };
    }
    if (!vm && config.vms?.length === 1) vm = config.vms[0];
    if (!vm) return res.json({ log: 'VM not found' });

    const result = await proxmoxAPI('POST',
      `/api2/json/nodes/${vm.node}/qemu/${vm.vm_id}/agent/exec`, {
        command: 'powershell.exe',
        'input-data': `if (Test-Path 'C:\\LabApps\\progress.log') { Get-Content 'C:\\LabApps\\progress.log' -Raw } else { Write-Host 'No progress log yet' }\n[Environment]::Exit(0)\n`
      }
    );

    if (result?.pid) {
      const { pollExecStatus } = require('../../utils/script-executor');
      const execResult = await pollExecStatus(vm.node, vm.vm_id, result.pid, 10000);
      return res.json({ log: execResult.stdout || 'No output' });
    }
    res.json({ log: 'Could not read progress' });
  } catch (e) {
    res.json({ log: `Error: ${e.message}` });
  }
});


// ============================================================================
// VULN ASSET LIST
// ============================================================================

router.get('/vuln-asset-list', authenticateToken, adminOnly, async (req, res) => {
  try {
    const assetsDir = require('path').join(__dirname, '../../../vuln-assets');
    const files = require('fs').readdirSync(assetsDir)
      .filter(f => !f.startsWith('.') && f !== 'download-assets.ps1')
      .map(f => {
        const stat = require('fs').statSync(require('path').join(assetsDir, f));
        return { name: f, size_mb: (stat.size / 1048576).toFixed(1), size_bytes: stat.size };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
    res.json(files);
  } catch (e) {
    res.json([]);
  }
});

module.exports = router;
