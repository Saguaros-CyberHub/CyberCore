/**
 * ============================================================================
 * RECONCILE GUARDS — server-side re-verification for destructive repairs
 * ============================================================================
 * Every repair button in the Proxmox Audit acted on whatever the CLIENT sent,
 * derived from a result that is cached for 24 hours and re-rendered every time
 * the tab is opened. POST /reconcile/destroy-vm took a vmid and a node and
 * purged them: no check that the id was in a CyberHub range, no check that a
 * live lane owned it, and no check that the node was even where it lived.
 *
 * That mattered because the audit itself produced false positives. Slot-1+
 * workstation VMIDs are ALLOCATED rather than derived, and buildLaneVmIndex did
 * not read cfg.workstations[] — so a healthy student's second machine appeared
 * in "Orphaned VMs" with a Destroy button beside it. One click destroyed it.
 *
 * The detection bug is fixed (utils/reconcile-audit.js), but detection is the
 * wrong place for the last line of defence. POST /sweep-orphaned-disks already
 * had the right shape: re-read the cluster, refuse on an empty view, and
 * re-derive the target set server-side rather than trusting the request. These
 * helpers are that logic, factored out so every endpoint can use it.
 *
 * Freshness is enforced by RE-VERIFICATION, not by a timer. A stale audit is
 * only dangerous because its claims may no longer hold; checking those claims
 * against the live cluster makes its age irrelevant. requireFreshAudit() sits on
 * top of that as a cheap way to tell the operator to re-scan — it is not what
 * makes any of this safe.
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');
const { cybercoreQuery } = require('./cybercore-db');
const { CLAIMING_STATUS_SET, claimsSql } = require('./lane-claims');
const { buildLaneVmIndex } = require('./reconcile-audit');
const reconcileJob = require('./reconcile-job');

/** Max age of the cached audit a destructive action may be driven from. */
const ACTION_MAX_AGE_S = Number(process.env.RECONCILE_ACTION_MAX_AGE_S) || 900;

/** An error carrying the HTTP status the route should answer with. */
class GuardError extends Error {
  constructor(status, message, data) {
    super(message);
    this.status = status;
    this.data = data || {};
  }
}

/**
 * A live cluster view, or a refusal.
 *
 * Refuses outright when /cluster/resources reports zero guests. That is the
 * catastrophic case: if pmxcfs loses quorum, every guest drops out of the
 * listing while its disks stay fully visible, so EVERYTHING classifies as an
 * orphan. Acting on that view would destroy the whole cluster's lanes.
 */
async function readTrustedClusterView({ timeoutMs = 15000 } = {}) {
  let resources;
  try {
    resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm', null, { timeoutMs });
  } catch (e) {
    throw new GuardError(502, `Could not read the cluster before acting: ${e.message}`);
  }

  const liveVmIds = new Set();
  const vmNodeMap = new Map();
  const vmNameMap = new Map();
  const vmTypeMap = new Map();
  for (const r of resources || []) {
    if ((r.type !== 'qemu' && r.type !== 'lxc') || typeof r.vmid !== 'number') continue;
    liveVmIds.add(r.vmid);
    vmNodeMap.set(r.vmid, r.node);
    vmNameMap.set(r.vmid, r.name || null);
    vmTypeMap.set(r.vmid, r.type);
  }

  if (liveVmIds.size === 0) {
    throw new GuardError(409,
      'Cluster reported no VMs — refusing to act. On a quorum-less cluster every '
      + 'guest disappears from the inventory while its disks stay visible, so '
      + 'everything would look orphaned.');
  }

  return { liveVmIds, vmNodeMap, vmNameMap, vmTypeMap, count: liveVmIds.size };
}

/**
 * Every VMID owned by a lane that still CLAIMS its resources, rebuilt from the
 * database right now rather than read out of the audit payload.
 *
 * Uses the same options the audit does, for the same reasons — in particular
 * includeWorkstations, without which a live lane's allocated slot-1+ machines
 * are absent from the claimed set and this guard would wave through exactly the
 * destroy it exists to stop.
 */
async function readClaimedVmIds() {
  const res = await cybercoreQuery(
    `SELECT lane_id, vxlan_id, name, status, config FROM cybercore_lane WHERE ${claimsSql()}`
  );
  const index = buildLaneVmIndex(res.rows, {
    includeWorkstations: true,
    includeNullVxlan: true,
    claimingStatuses: CLAIMING_STATUS_SET,
  });
  const claimed = new Map();
  for (const vmid of index.expectedVmIds) {
    claimed.set(vmid, index.laneVmMap[vmid] || null);
  }
  return claimed;
}

/**
 * Refuse to act on an audit result the server no longer recognises.
 *
 * Advisory by design: it tells the operator to re-scan rather than silently
 * acting on a day-old table. The real safety comes from the checks above, so a
 * caller that supplies no job id (curl, a script) is not blocked — but one that
 * supplies a WRONG or EXPIRED id is, because that is a browser sitting on a
 * stale render.
 */
async function requireFreshAudit(auditJobId) {
  if (!auditJobId) return { checked: false };

  const cached = await reconcileJob.getCachedResult();
  if (!cached) {
    throw new GuardError(409, 'No audit result is cached any more — re-run the audit.', { stale: true });
  }
  if (cached.job_id && auditJobId !== cached.job_id) {
    throw new GuardError(409,
      'This page is showing an older audit than the one cached — re-run the audit.',
      { stale: true, current_job_id: cached.job_id });
  }
  if (cached.age_seconds != null && cached.age_seconds > ACTION_MAX_AGE_S) {
    throw new GuardError(409,
      `The audit is ${Math.round(cached.age_seconds / 60)} minutes old — re-run it before repairing.`,
      { stale: true, age_seconds: cached.age_seconds });
  }
  return { checked: true, age_seconds: cached.age_seconds };
}

/**
 * Assert a VMID is safe to destroy: inside a CyberHub range, live, and claimed
 * by nobody. Returns the node it ACTUALLY lives on, never the caller's.
 *
 * @param {object}   a
 * @param {number}   a.vmid
 * @param {object}   a.cluster  from readTrustedClusterView
 * @param {Map}      a.claimed  from readClaimedVmIds
 * @param {Function} a.inRange  inCyberhubRange bound to the RANGES table
 */
function assertDestroyableVm({ vmid, cluster, claimed, inRange }) {
  if (!Number.isFinite(vmid)) throw new GuardError(400, 'vmid must be a number');

  if (!inRange(vmid)) {
    throw new GuardError(400,
      `VMID ${vmid} is outside every CyberHub-owned range — refusing to destroy it. `
      + 'It belongs to something this application did not create.');
  }

  const owner = claimed.get(vmid);
  if (owner) {
    throw new GuardError(409,
      `VMID ${vmid} belongs to lane "${owner.name || owner.lane_id}" (status ${owner.status}), `
      + 'which still holds it. Re-run the audit — this finding is out of date.',
      { lane_id: owner.lane_id, lane_status: owner.status });
  }

  if (!cluster.liveVmIds.has(vmid)) {
    throw new GuardError(404, `VMID ${vmid} is not on the cluster — nothing to destroy.`);
  }

  return {
    // RE-DERIVED. The caller's node used to go straight into a DELETE url; a
    // wrong one either 404s or, worse, names a different node that happens to
    // hold a same-numbered guest.
    node: cluster.vmNodeMap.get(vmid),
    type: cluster.vmTypeMap.get(vmid),
    name: cluster.vmNameMap.get(vmid),
  };
}

/** Express glue: answer a GuardError, or report that it was something else. */
function handleGuardError(err, res) {
  if (err instanceof GuardError) {
    res.status(err.status).json({ error: err.message, ...err.data });
    return true;
  }
  return false;
}

module.exports = {
  GuardError,
  ACTION_MAX_AGE_S,
  readTrustedClusterView,
  readClaimedVmIds,
  requireFreshAudit,
  assertDestroyableVm,
  handleGuardError,
};
