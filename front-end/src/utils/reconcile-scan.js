/**
 * ============================================================================
 * RECONCILE SCAN
 * ============================================================================
 * The Proxmox audit: compare live cluster state against the database and report
 * what has drifted. Lifted out of routes/admin/cluster.js so it can run
 * detached from a request (see utils/reconcile-job.js) and be tested without a
 * live cluster.
 *
 * The shape of the returned object is the audit's public contract — the admin
 * UI renders it directly, so fields are added, never renamed.
 *
 * TIMING
 * The whole scan runs under a wall-clock budget. Browser traffic reaches this
 * app through a Cloudflare Tunnel whose origin timeout is 100s and whose
 * timeout response is an HTML page; a synchronous audit that overran it
 * surfaced in the UI as a JSON parse error rather than a timeout. The budget
 * keeps the answer well inside that even when a node is wedged.
 * ============================================================================
 */

const { proxmoxAPI, PROXMOX_URL } = require('./proxmox');
const { cybercoreQuery } = require('./cybercore-db');
const { query } = require('./db');
const { guacAPI } = require('./guacamole');
const attachedModules = require('./attached-modules');
const siteConfig = require('./site-config');
const { scanClusterVolumes } = require('./storage-scan');
const A = require('./reconcile-audit');

const RECONCILE_BUDGET_MS = Number(process.env.RECONCILE_BUDGET_MS) || 45000;
const CLUSTER_CALL_TIMEOUT_MS = Number(process.env.RECONCILE_CLUSTER_CALL_TIMEOUT_MS) || 15000;
const SCAN_CONCURRENCY = Number(process.env.RECONCILE_SCAN_CONCURRENCY) || 4;

const RANGES = A.buildCyberhubRanges({
  attachedBase: attachedModules.ATTACHED_VMID_BASE,
  attachedSlots: attachedModules.ATTACHED_MAX_SLOTS,
  attachedStep: attachedModules.ATTACHED_VMID_STEP,
});

const PHASES = {
  cluster: 'Reading cluster inventory and database',
  storage: 'Scanning storage',
  guacamole: 'Reading Guacamole connections',
  done: 'Finishing up',
};

/** Never-throwing wrapper: an optional subsystem must not fail the whole audit. */
function settle(promise) {
  return promise.then(
    value => ({ ok: true, value }),
    error => ({ ok: false, error: error.message })
  );
}

/**
 * The node the API URL points at, if it can be identified.
 *
 * A request for /nodes/<other>/... is forwarded pveproxy-to-pveproxy over the
 * cluster link — a second internal TLS hop, and a common source of 596s under
 * load. Reading shared storage from the API node avoids it. A stale site.json
 * only costs the hint, so the permanent module cache is harmless here.
 */
function findPreferredNode() {
  try {
    const apiHost = new URL(PROXMOX_URL).hostname;
    return siteConfig.getClusterNodes().find(n => siteConfig.getNodeAddress(n) === apiHost) || null;
  } catch (_) {
    return null;
  }
}

/**
 * Zone peers, preferring the index.
 *
 * GET /cluster/sdn/zones projects `peers` in practice, but the index's
 * documented return set is narrower than the full section config and has varied
 * across PVE versions — so fall back to a per-zone GET only for the zones the
 * index left undefined. One call in the good case; at most one per vxlan zone
 * (bounded by the challenge-template count) in the bad one.
 */
async function readZonePeers(vxlanZones, opts) {
  const out = [];
  for (const z of vxlanZones) {
    let peers = z.peers;
    let digest = z.digest;
    if (peers === undefined) {
      try {
        const full = await proxmoxAPI(
          'GET', `/api2/json/cluster/sdn/zones/${encodeURIComponent(z.zone)}`, null, opts);
        peers = full && full.peers;
        digest = (full && full.digest) || digest;
      } catch (_) {
        // Leave undefined. diffZonePeers reports readable:false and offers no
        // repair — never overwrite a value nobody managed to read.
      }
    }
    out.push({ zone: z.zone, type: z.type, peers, digest });
  }
  return out;
}

/**
 * CyberHub-generated Guacamole connections whose parent group is gone.
 * Both sets come from one pass over deployed_groups; the inline version parsed
 * every group's config JSON twice.
 */
function computeOrphanedGuacConnections(connList, dbGroups) {
  const trackedConnIds = new Set();
  const activeGuacGroupIds = new Set();

  for (const g of dbGroups) {
    const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : (g.config || {});
    for (const c of (cfg.guac_connections || [])) {
      if (c && c.id) trackedConnIds.add(String(c.id));
    }
    if (cfg.guac_group && cfg.guac_group.identifier) {
      activeGuacGroupIds.add(String(cfg.guac_group.identifier));
    }
  }

  const orphans = [];
  for (const c of connList) {
    const name = c.name || '';
    const id = String(c.identifier || c.id || '');
    const parent = String(c.parentIdentifier || 'ROOT');

    const looksLikeCyberhub = / - .* - (Kali|VulnWin|Target|Attack|RDP)/i.test(name)
      || trackedConnIds.has(id);
    if (!looksLikeCyberhub) continue;

    if (!activeGuacGroupIds.has(parent) || parent === 'ROOT') {
      orphans.push({ id, name, protocol: c.protocol || '', parent, tracked: trackedConnIds.has(id) });
    }
  }
  return orphans;
}

/**
 * Run the full audit.
 *
 * @param {{onPhase?: Function, budgetMs?: number}} a
 *   onPhase(phase, detail, done, total) drives the progress line in the UI.
 * @returns {Promise<object>} the audit payload
 */
async function runReconcileScan({ onPhase = () => {}, budgetMs = RECONCILE_BUDGET_MS } = {}) {
  const startedAt = Date.now();
  const deadlineAt = startedAt + budgetMs;
  const controller = new AbortController();
  const abortTimer = setTimeout(() => controller.abort(), budgetMs);
  if (typeof abortTimer.unref === 'function') abortTimer.unref();

  const callOpts = { timeoutMs: CLUSTER_CALL_TIMEOUT_MS, signal: controller.signal };

  try {
    onPhase('cluster', PHASES.cluster, 0, 1);

    // ---- t=0: start the two long-running reads, do NOT await them yet ------
    // Both are awaited last so they overlap everything below. scanClusterVolumes
    // is contractually non-rejecting; the .catch() is belt and braces, because
    // an un-awaited rejection here would exit the process.
    const pScan = scanClusterVolumes({
      proxmoxAPI,
      deadlineAt,
      concurrency: SCAN_CONCURRENCY,
      preferredNode: findPreferredNode(),
      signal: controller.signal,
      onProgress: (done, total) => onPhase('storage', PHASES.storage, done, total),
    }).catch(e => ({
      volumes: [], skipped: { nodes: [], storages: [] }, storages_failed: [],
      stats: {}, calls_made: 0, complete: false, nodes_total: 0, nodes_scanned: 0,
      error: `Disk scan failed: ${e.message}`,
    }));

    const pGuac = settle(guacAPI('GET', '/connections'));

    // ---- phase 1: everything short and independent, in parallel ------------
    const [
      pxResourcesR, vnetsR, zonesR, clusterStatusR, pendingR, lanesR, groupsR, challengesR,
    ] = await Promise.all([
      proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm', null, callOpts),
      settle(proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets', null, callOpts)),
      settle(proxmoxAPI('GET', '/api2/json/cluster/sdn/zones', null, callOpts)),
      settle(proxmoxAPI('GET', '/api2/json/cluster/status', null, callOpts)),
      settle(proxmoxAPI('GET', '/api2/json/cluster/sdn/zones?pending=1', null, callOpts)),
      cybercoreQuery(
        `SELECT lane_id, vxlan_id, name, status, config, created_at
           FROM cybercore_lane WHERE status NOT IN ('deleted')
          ORDER BY created_at DESC`),
      query(`SELECT id, group_name, config, created_at FROM deployed_groups ORDER BY created_at DESC`),
      cybercoreQuery(`SELECT challenge_key, name, spec FROM crucible_challenge`),
    ]);

    // ---- phase 2: pure computation ----------------------------------------
    const pxVMs = (Array.isArray(pxResourcesR) ? pxResourcesR : []).map(vm => ({
      vmid: vm.vmid, name: vm.name || '', status: vm.status, node: vm.node, type: vm.type,
    }));

    const pxVNets = (vnetsR.ok && Array.isArray(vnetsR.value) ? vnetsR.value : [])
      .map(v => ({ vnet: v.vnet, zone: v.zone, tag: v.tag, alias: v.alias || '' }));
    const pxZonesAll = (zonesR.ok && Array.isArray(zonesR.value) ? zonesR.value : []);
    const clusterStatus = (clusterStatusR.ok && Array.isArray(clusterStatusR.value))
      ? clusterStatusR.value : [];

    const dbLanes = lanesR.rows;
    const dbGroups = groupsR.rows;
    const dbChallenges = challengesR.rows;

    const dbZoneNames = new Set();
    for (const ch of dbChallenges) {
      const spec = typeof ch.spec === 'string' ? JSON.parse(ch.spec || '{}') : (ch.spec || {});
      const zoneName = (spec.zone && spec.zone.abbrev)
        || (ch.challenge_key && ch.challenge_key.substring(0, 8).replace(/[^a-z0-9]/gi, '').substring(0, 8));
      if (zoneName) dbZoneNames.add(zoneName);
    }

    const laneIndex = A.buildLaneVmIndex(dbLanes);
    const { vxlanZones, orphanedZones, orphanedVNets } =
      A.computeSdnOrphans({ pxZonesAll, pxVNets, dbZoneNames });

    const pxCyberhubVMs = pxVMs.filter(vm => A.inCyberhubRange(vm.vmid, RANGES));
    const pxVmIdSet = new Set(pxCyberhubVMs.map(vm => vm.vmid));
    const orphanedOnProxmox = A.computeOrphanedVMs(pxVMs, laneIndex.expectedVmIds, RANGES);
    const staleInDB = A.computeStaleLanes(dbLanes, laneIndex, pxVmIdSet);

    // ---- node drift --------------------------------------------------------
    // config/site.json is gitignored and bind-mounted from the host, so it can
    // be absent or malformed. That degrades THIS section; it must not take down
    // an audit whose orphan findings are perfectly valid without it.
    let declaredMap = {};
    let configError = null;
    try {
      declaredMap = siteConfig.getPhysicalClusterIps();
    } catch (e) {
      configError = `config/site.json could not be read: ${e.message}`;
    }

    const vmCounts = {};
    for (const vm of pxVMs) { if (vm.node) vmCounts[vm.node] = (vmCounts[vm.node] || 0) + 1; }

    const nodeDrift = A.diffClusterNodes({ clusterStatus, declaredMap, vmCounts });
    let freshness = {};
    let defaultTemplateNode = null;
    try {
      freshness = siteConfig.getConfigFreshness();
      defaultTemplateNode = siteConfig.getDefaultTemplateNode();
    } catch (_) { /* already reported via configError */ }

    const clusterNodes = {
      ...nodeDrift,
      ...freshness,
      default_template_node: defaultTemplateNode,
      config_readable: !configError,
      config_writable: false,   // bind-mounted :ro; the app can never repair this
    };
    // Without site.json every node looks undeclared, which is a config-read
    // failure wearing the costume of a drift finding. Say which it is.
    if (configError) {
      clusterNodes.undeclared = [];
      clusterNodes.issue_count = 0;
    }

    let zonePeerDrift = [];
    let peerError = configError;
    if (!configError) {
      try {
        const expected = A.computeExpectedPeers(clusterStatus, declaredMap);
        const withPeers = await readZonePeers(vxlanZones, callOpts);
        zonePeerDrift = A.diffZonePeers(withPeers, expected.ips, pxVNets);
      } catch (e) {
        peerError = e.message;
      }
    }

    const sdnPending = pendingR.ok && Array.isArray(pendingR.value)
      && pendingR.value.some(z => z.state === 'new' || z.state === 'changed' || z.state === 'deleted');

    // ---- phase 3: await the long ones --------------------------------------
    const scan = await pScan;
    onPhase('guacamole', PHASES.guacamole, 0, 1);
    const guac = await pGuac;

    const nodesOnline = clusterStatus.filter(e => e.type === 'node' && e.online === 1).length;
    const nodesTotal = clusterStatus.filter(e => e.type === 'node').length;
    const clusterView = {
      nodes_total: nodesTotal || scan.nodes_total || 0,
      nodes_online: nodesOnline || scan.nodes_scanned || 0,
      resources_count: pxVMs.length,
      trusted: !!(clusterStatusR.ok && nodesTotal > 0 && nodesOnline === nodesTotal && pxVMs.length > 0),
    };

    // A cluster view that returned nothing is the catastrophic case: every disk
    // on shared storage would classify as an orphan, with a Delete button.
    // Refuse to build that table rather than render it behind a warning.
    const diskResult = pxVMs.length > 0
      ? A.classifyOrphanDisks(scan.volumes, {
          liveVmIds: new Set(pxVMs.map(v => v.vmid)), ranges: RANGES,
        })
      : { disks: [], total_bytes: 0, total_gb: '0.00' };

    const diskScan = A.summarizeScan({ ...scan, budget_ms: budgetMs }, clusterView);
    if (scan.error) diskScan.warnings.unshift(scan.error);
    if (pxVMs.length === 0) {
      diskScan.warnings.unshift(
        'Cluster returned no VMs — disk classification skipped. Every image on shared ' +
        'storage would otherwise look orphaned.');
    }
    if (peerError) diskScan.warnings.push(`Zone peer check skipped: ${peerError}`);

    const orphanedGuacConnections = guac.ok
      ? computeOrphanedGuacConnections(
          Array.isArray(guac.value) ? guac.value : Object.values(guac.value || {}), dbGroups)
      : [];

    onPhase('done', PHASES.done, 1, 1);

    const warnings = [...diskScan.warnings];
    if (!vnetsR.ok || !zonesR.ok) warnings.push('SDN could not be read — zone and VNet findings are incomplete.');
    if (!guac.ok) warnings.push(`Guacamole could not be read: ${guac.error}`);
    if (clusterNodes.config_stale_in_memory) {
      warnings.push('config/site.json has changed on disk since the app started — restart the app to pick it up.');
    }
    if (configError) warnings.push(`${configError} — node drift and zone peers were not checked.`);

    return {
      timestamp: new Date().toISOString(),
      duration_ms: Date.now() - startedAt,
      summary: {
        proxmox_cyberhub_vms: pxCyberhubVMs.length,
        db_active_lanes: dbLanes.length,
        db_expected_vms: laneIndex.expectedVmIds.size,
        orphaned_on_proxmox: orphanedOnProxmox.length,
        stale_in_db: staleInDB.length,
        sdn_zones: vxlanZones.length,
        orphaned_zones: orphanedZones.length,
        sdn_vnets: pxVNets.length,
        orphaned_vnets: orphanedVNets.length,
        deployed_groups: dbGroups.length,
        orphaned_disks: diskResult.disks.length,
        orphaned_disks_total_gb: diskResult.total_gb,
        orphaned_guac_connections: orphanedGuacConnections.length,
        // node drift
        cluster_nodes_live: clusterNodes.live_count,
        cluster_nodes_declared: clusterNodes.declared_count,
        nodes_undeclared: clusterNodes.undeclared.length,
        nodes_stale_declared: clusterNodes.stale_declared.length,
        nodes_ip_mismatch: clusterNodes.ip_mismatch.length,
        nodes_offline: clusterNodes.offline.length,
        zones_peer_drift: zonePeerDrift.length,
        node_drift_issues: clusterNodes.issue_count + zonePeerDrift.length,
        // scan health
        disk_scan_complete: diskScan.complete,
        disk_scan_trusted: diskScan.trusted,
      },
      orphaned_on_proxmox: orphanedOnProxmox,
      stale_in_db: staleInDB,
      orphaned_zones: orphanedZones,
      orphaned_vnets: orphanedVNets,
      orphaned_disks: diskResult.disks,
      orphaned_guac_connections: orphanedGuacConnections,
      sdn_vnets: pxVNets,
      all_proxmox_cyberhub_vms: pxCyberhubVMs,
      cluster_nodes: clusterNodes,
      zone_peer_drift: zonePeerDrift,
      sdn_pending: sdnPending,
      disk_scan: diskScan,
      guac_scan: guac.ok ? { ok: true } : { ok: false, error: guac.error },
      sdn_scan: { ok: vnetsR.ok && zonesR.ok, error: vnetsR.error || zonesR.error || null },
      cluster_view: clusterView,
      warnings,
    };
  } finally {
    clearTimeout(abortTimer);
  }
}

module.exports = {
  runReconcileScan,
  computeOrphanedGuacConnections,
  readZonePeers,
  findPreferredNode,
  RANGES,
  PHASES,
  RECONCILE_BUDGET_MS,
};
