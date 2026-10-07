/**
 * ============================================================================
 * LANE RESOURCE CLAIMS — one definition of "this lane still owns its VXLAN"
 * ============================================================================
 * A lane's resource ids are almost all DERIVED from its vxlan_id: gateway
 * 100000+vxlan, GOAD controller 200000+vxlan, slot-0 workstation 600000+vxlan,
 * attack box 700000+vxlan, attached modules 800000+slot*10000+vxlan. The
 * gateway WAN transit address is allocated rather than derived, but it is held
 * on exactly the same terms.
 *
 * So "does this row still claim its vxlan_id" decides two things that must
 * never disagree:
 *
 *   1. whether the next deploy may be handed that id (utils/lane-deployer.js
 *      allocateVxlanIds, utils/lane-wan-allocator.js, and the partial unique
 *      indexes ux_cybercore_lane_vxlan_active / ux_cybercore_lane_wan_ip_active)
 *   2. whether the audit counts that row's VMIDs as accounted for, or reports
 *      them as orphans (utils/reconcile-audit.js buildLaneVmIndex)
 *
 * They DID disagree, and that was the bug this module exists to close. The
 * allocator's used-set excluded 'error', putting a failed lane's id straight
 * back in the pool, while the audit loaded every row that was not 'deleted' and
 * so counted that same lane's still-running machines as expected. The result
 * was a lane whose survivors were invisible to the audit at the same moment its
 * VXLAN was being handed to someone else — and once the new lane took it, the
 * contested-VXLAN guard in teardownLanes correctly refused to let the old row
 * destroy anything, ever.
 *
 * There were SIX spellings of this predicate before this file:
 *
 *   status NOT IN ('error','deleted')   lane-deployer.js, lane-wan-allocator.js,
 *                                       ciab/utils/lane-deploy.js, both indexes
 *   status NOT IN ('error')             routes/admin/lab-networks.js,
 *                                       routes/admin/lanes.js
 *                                         -> treats a 'deleted' lane as still
 *                                            holding its id, shrinking the pool
 *   status IN ('active','deploying')    utils/lab-network-provision.js
 *                                         -> misses 'pending' and 'suspended',
 *                                            so countActiveLanesInBlock can call
 *                                            a reservation empty and re-carve a
 *                                            block that lanes are sitting in
 *
 * NO IMPORTS, and no queries: this is the vocabulary, not a data-access layer.
 * That keeps it usable from utils/reconcile-audit.js, which must stay
 * import-free (see that file's header).
 * ============================================================================
 */

/** Statuses that RELEASE the vxlan_id and gateway WAN address for reuse. */
const RELEASED_STATUSES = Object.freeze(['error', 'deleted']);

/**
 * Statuses that still HOLD them. Must remain the exact complement of
 * RELEASED_STATUSES over the cybercore_lane_status enum
 * (config/postgres/001_init_db.sql) — test/lane-claims.test.js asserts it.
 */
const CLAIMING_STATUSES = Object.freeze(['pending', 'deploying', 'active', 'suspended']);

/** Every value the status enum can take. */
const ALL_STATUSES = Object.freeze([...CLAIMING_STATUSES, ...RELEASED_STATUSES]);

/** As a Set, for the audit's per-row checks. */
const CLAIMING_STATUS_SET = new Set(CLAIMING_STATUSES);

/**
 * The SQL predicate, as a literal constant.
 *
 * Deliberately not built by interpolating RELEASED_STATUSES: a constant string
 * is greppable, cannot be reached by a caller-supplied value, and reads the same
 * in the migrations that carry this predicate in an index.
 */
const CLAIMS_SQL = `status NOT IN ('error', 'deleted')`;

/**
 * The same predicate against an aliased table.
 * @param {string} [alias] table alias, e.g. 'l'. Alphanumeric + underscore only.
 */
function claimsSql(alias) {
  if (!alias) return CLAIMS_SQL;
  if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(alias)) {
    throw new Error(`claimsSql: refusing to build SQL from alias ${JSON.stringify(alias)}`);
  }
  return `${alias}.status NOT IN ('error', 'deleted')`;
}

/**
 * Whether a lane row still holds its vxlan_id and WAN address.
 * @param {{status?: string}} lane
 */
function holdsInfra(lane) {
  return !!lane && CLAIMING_STATUS_SET.has(lane.status);
}

module.exports = {
  RELEASED_STATUSES,
  CLAIMING_STATUSES,
  CLAIMING_STATUS_SET,
  ALL_STATUSES,
  CLAIMS_SQL,
  claimsSql,
  holdsInfra,
};
