/**
 * ============================================================================
 * LANE WORKSTATION CREDENTIALS
 * ----------------------------------------------------------------------------
 * One place to read the OS login a lane workstation was built with, so every
 * surface that shows it agrees on the same fallback order.
 *
 * Storage: cybercore_lane.config (JSONB), written by the deployers, PLAINTEXT.
 * Two writers with two different shapes, and both have to keep working:
 *
 *   - utils/lane-deployer.js writes one entry per slot into
 *     config.workstations[] (deployOneWorkstation), AND flattens slot 0 onto
 *     the top-level config.workstation_user / workstation_pass keys that
 *     plugins/cle/routes/{vms,labs}.js have always read.
 *   - utils/challenge-lane-deployer.js writes ONLY the flattened top-level
 *     keys — a challenge lane has a config.vms[] array, never workstations[].
 *
 * So: per-slot first, flattened second. Reversing that order hands every slot
 * of a multi-machine lane slot 0's password.
 *
 * WHAT THIS DELIBERATELY DOES NOT DO
 * It never mints, rotates, or writes. There is no rotation path for a lane
 * credential at all — the password lives in the guest (injected once through
 * cloud-init) and in the Guacamole connection parameters, and re-provisioning
 * is the only thing that changes it. A "reset" here would desynchronise all
 * three and leave a console that cannot connect.
 *
 * Callers are responsible for authorization. getLaneWorkstationCredentialForVm
 * below is the authorized read; the pure resolver is exported separately for
 * callers that already hold a lane row.
 * ============================================================================
 */

const { cybercoreQuery } = require('./cybercore-db');

const LOG = '[LaneCreds]';

/**
 * The OS login for one workstation of a lane.
 *
 * `source` is `credentials_source` as the deployer recorded it, and three of its
 * values are NOT interchangeable:
 *
 *   'cloudinit' — a password generated for this lane and injected through
 *                 cloud-init. Private to its owner. The normal case.
 *   'template'  — the template's own metadata.default_rdp_pass, used verbatim
 *                 with no injection at all. IDENTICAL on every lane built from
 *                 that image, so `shared` is set and callers must say so.
 *                 (lane-deployer.resolveWorkstationCredentials warns at deploy
 *                 time for the same reason; migrations 025/026 exist because
 *                 this field once held Packer's WinRM build secrets.)
 *   'baked'     — LXC, or a clone with no cloud-init drive. Nothing was
 *                 injected and nothing was recorded; the guest kept whatever
 *                 the bake left. There is no password to report.
 *
 * @param {object|null} laneConfig            cybercore_lane.config
 * @param {string|number|null} providerVmid   cybercore_vm_instance.provider_vmid
 * @returns {{username: ?string, password: ?string, source: string,
 *            available: boolean, shared: boolean, reason: ?string}}
 */
function resolveLaneWorkstationCredential(laneConfig, providerVmid) {
  const cfg = laneConfig || {};

  // String on BOTH sides: provider_vmid is stored as text (the deployers write
  // String(vmid)) while config.workstations[].vmid is a number. `===` between
  // them is false for every row, which would silently demote every multi-slot
  // lane to slot 0's credential. Same idiom as resolveDisplayName in
  // routes/guac-sessions.js.
  const slots = Array.isArray(cfg.workstations) ? cfg.workstations : [];
  const slot = providerVmid != null
    ? slots.find(w => w && String(w.vmid) === String(providerVmid))
    : null;

  // ?? rather than ||: a slot that recorded a username but no password must not
  // fall through and pick up slot 0's password from the flattened keys.
  const username = slot ? (slot.workstation_user ?? null) : (cfg.workstation_user ?? null);
  const password = slot ? (slot.workstation_pass ?? null) : (cfg.workstation_pass ?? null);
  const source = (slot ? slot.credentials_source : cfg.credentials_source) || 'none';

  if (!username && !password) {
    return {
      username: null, password: null, source, available: false, shared: false,
      // Distinguishable on purpose: 'baked' is a permanent property of how the
      // machine was built, not a transient gap that redeploying would close.
      reason: source === 'baked'
        ? 'This machine was cloned without cloud-init, so no personal password was set on it. '
          + 'It uses the login its image was built with — ask your instructor.'
        : 'No login was recorded for this machine.',
    };
  }

  // A username with no password is a real state, not a bug: source 'template'
  // means the image ships a stable account whose password the deployer never
  // knew, and metadata.default_rdp_pass is genuinely optional. Report the
  // account name — it is still useful — but do not claim a usable credential.
  if (!password) {
    return {
      username, password: null, source, available: false, shared: source === 'template',
      reason: 'This machine uses an account built into its image, and its password is not '
        + 'recorded here. Ask your instructor for it.',
    };
  }

  return {
    username,
    password,
    source,
    available: true,
    shared: source === 'template',
    reason: null,
  };
}

/**
 * Read the credential for one workstation, enforcing ownership.
 *
 * Scope is deliberately NARROW — the owner, or an admin. It is NOT the
 * `isPrivileged` (admin OR instructor) test the console-launch route uses: that
 * test is cluster-wide with no course scoping, so applying it here would let any
 * instructor read any other instructor's students' machines. An instructor
 * reading their OWN students goes through the course-scoped CLE routes, which
 * check course management first.
 *
 * Restricted to vm_category='lane_vm': a self-deployed workstation
 * (routes/workstations.js) has no per-VM password at all — that path never
 * injects cloud-init credentials — so there is nothing here to return for one.
 *
 * @returns {Promise<object|null>} the resolved credential plus `ownerUserId` and
 *   `vmName`, or null when the VM does not exist or is not the caller's.
 */
async function getLaneWorkstationCredentialForVm(vmInstanceId, { userId, isAdmin = false } = {}) {
  const SELECT_COLUMNS = `
      vi.provider_vmid,
      dl.config                    AS lane_config,
      r.name                       AS vm_name,
      vi.metadata->>'proxmox_name' AS proxmox_name,
      (SELECT a2.user_id FROM cybercore_allocation a2
        WHERE a2.resource_id = r.resource_id
          AND (a2.ends_at IS NULL OR a2.ends_at > NOW())
        ORDER BY a2.starts_at ASC LIMIT 1) AS owner_user_id`;

  const FROM_JOINS = `
    FROM cybercore_vm_instance vi
    JOIN cybercore_resource r ON r.resource_id = vi.resource_id
    LEFT JOIN cybercore_lane dl ON dl.lane_id::text = r.metadata->>'lane_id'`;

  // Mirrors LIVE_LANE_FILTER in routes/guac-sessions.js: a lane row that is gone
  // or torn down must not keep serving a credential through an orphaned resource
  // row that some teardown path forgot to retire.
  const LIVE_LANE = `
      AND EXISTS (
        SELECT 1 FROM cybercore_lane l
         WHERE l.lane_id::text = r.metadata->>'lane_id'
           AND l.status NOT IN ('deleted', 'error'))`;

  // Two branches rather than one query with an OR: the non-admin form has to
  // JOIN the allocation so that "not yours" and "does not exist" come back
  // identically, and the admin form must not require one.
  const sql = isAdmin
    ? `SELECT ${SELECT_COLUMNS} ${FROM_JOINS}
        WHERE vi.vm_instance_id = $1
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
          AND r.metadata->>'vm_category' = 'lane_vm'
          ${LIVE_LANE}`
    : `SELECT ${SELECT_COLUMNS} ${FROM_JOINS}
        JOIN cybercore_allocation a
          ON  a.resource_id = r.resource_id
          AND a.user_id     = $2
          AND (a.ends_at IS NULL OR a.ends_at > NOW())
        WHERE vi.vm_instance_id = $1
          AND vi.destroyed_at IS NULL
          AND r.status != 'retired'
          AND r.metadata->>'vm_category' = 'lane_vm'
          ${LIVE_LANE}`;

  const params = isAdmin ? [vmInstanceId] : [vmInstanceId, userId];
  const result = await cybercoreQuery(sql, params).catch((err) => {
    console.warn(`${LOG} Credential lookup failed for ${vmInstanceId}: ${err.message}`);
    throw err;
  });
  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  return {
    ...resolveLaneWorkstationCredential(row.lane_config, row.provider_vmid),
    ownerUserId: row.owner_user_id || null,
    vmName: row.proxmox_name || row.vm_name || null,
  };
}

module.exports = {
  resolveLaneWorkstationCredential,
  getLaneWorkstationCredentialForVm,
};
