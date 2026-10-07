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
const courseDirectory = require('./course-directory');
const { claimsSql } = require('./lane-claims');
const {
  hiddenBindValues, catalogJoinSql, studentHiddenSql,
} = require('./workspace-visibility');

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
 * Three scopes, tried in that order, and the ORDER is the design:
 *
 *   1. the OWNER  - the student whose allocation holds the machine
 *   2. an ADMIN   - no ownership join at all
 *   3. the INSTRUCTOR WHO TEACHES THIS LANE'S COURSE
 *
 * Scope 3 is emphatically NOT the `isPrivileged` (admin OR instructor) test the
 * console-launch route uses. That test is cluster-wide with no course scoping,
 * so applying it here would let any instructor read any other instructor's
 * students' machine passwords. This one matches a single fact -
 * `cybercore_lane.config->>'course_id'` - against the courses cle_db says this
 * person teaches, so an instructor reaches their own students and nobody else's.
 *
 * It discloses nothing the same instructor cannot already read: the course VM
 * list at cle/routes/vms.js GET / is `instructorOnly` + getManagedCourse and
 * already returns `workstation_pass` in plaintext for every lane of a course
 * they manage, and courses.html renders it. This route reaches the SAME lanes
 * by the SAME rule - it just answers per-VM, from the hub, with an audit row.
 *
 * WHY THE COURSE LOOKUP IS LAZY. It runs only when scopes 1 and 2 have already
 * missed. Courses live in cle_db and lanes in cybercore_db - separate pools, no
 * join - so scope 3 costs a query against a second database. An instructor
 * opening their OWN machine must not pay for that, and a student never reaches
 * it at all.
 *
 * FAILS CLOSED. courseIdsForInstructor funnels through course-directory's
 * `safely()`, which turns an unregistered provider, a throwing provider, or a
 * dead cle_db into []. An empty list matches no lane, so a directory outage
 * denies rather than grants - the correct direction for an authorization check,
 * and the same answer as before this scope existed.
 *
 * WHAT SCOPE 3 DOES NOT REACH, on purpose and by accident:
 *   - Lanes from POST /api/admin/deploy-group. That path stamps
 *     `config.group_id` and NO course reference (routes/admin/groups.js), and
 *     group_id resolves in clinic_db, invisible from here. Those instructors
 *     still get the 404 they get today. Scoping by roster instead would not
 *     help: that path mints synthetic students and never enrolls them in
 *     cle_course_enrollment, so an enrollment predicate matches nothing either.
 *     The fix for those lanes is to stamp a course at deploy time, not to widen
 *     this rule.
 *   - Enrollment. A lane keeps its `course_id` after its owner is dropped, and
 *     the course's own hidden infrastructure (the CYBR 400 sensor) is reachable
 *     too. Both are deliberate: an instructor cannot fix a machine they cannot
 *     see the login for, and this matches what the course VM list already shows.
 *
 * Restricted to vm_category='lane_vm': a self-deployed workstation
 * (routes/workstations.js) has no per-VM password at all — that path never
 * injects cloud-init credentials — so there is nothing here to return for one.
 *
 * @param {string} vmInstanceId
 * @param {object} opts
 * @param {string} opts.userId
 * @param {boolean} [opts.isAdmin=false]  skips the ownership join entirely
 * @param {boolean} [opts.isPrivileged=isAdmin]  admin OR instructor; only lifts
 *   the hidden-infrastructure filter, never the ownership scope
 * @param {string} [opts.role]  the caller's role. 'instructor' unlocks the
 *   course-scoped scope 3 above; anything else leaves behaviour unchanged.
 * @returns {Promise<object|null>} the resolved credential plus `ownerUserId` and
 *   `vmName`, or null when the VM does not exist, is not the caller's, or is
 *   hidden from them (utils/workspace-visibility.js).
 */
async function getLaneWorkstationCredentialForVm(
  vmInstanceId, { userId, isAdmin = false, isPrivileged = isAdmin, role = null } = {}
) {
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
    LEFT JOIN cybercore_lane dl ON dl.lane_id::text = r.metadata->>'lane_id'
    ${catalogJoinSql()}`;

  // A machine hidden from its own student (utils/workspace-visibility.js) does
  // not hand that student its password either. The console route and the list
  // both refuse it, and leaving this one open would mean the sensor's login is
  // still one click away on the card that the list no longer draws — reachable
  // by anyone replaying the request.
  //
  // Gated on `isPrivileged`, NOT on the ownership scope above it. Hidden means
  // hidden from the STUDENT; an instructor or admin looking up the sensor login
  // is the normal way that machine gets fixed, and it is also the only reading
  // that agrees with GET /vms, which still lists a professor's own sensor when
  // they ask for ?scope=mine. This relaxes nothing about WHOSE machine may be
  // read — a non-admin still has to clear the allocation join below.
  const NOT_HIDDEN = isPrivileged ? '' : `AND NOT ${studentHiddenSql({ param: 3 })}`;

  // Mirrors LIVE_LANE_FILTER in routes/guac-sessions.js: a lane row that is gone
  // or torn down must not keep serving a credential through an orphaned resource
  // row that some teardown path forgot to retire.
  const LIVE_LANE = `
      AND EXISTS (
        SELECT 1 FROM cybercore_lane l
         WHERE l.lane_id::text = r.metadata->>'lane_id'
           AND ${claimsSql('l')})`;

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
          ${LIVE_LANE}
          ${NOT_HIDDEN}`;

  // $3/$4 go ONLY where NOT_HIDDEN put placeholders for them. Postgres rejects
  // a bind that supplies more parameters than the statement references, so a
  // privileged non-admin caller would otherwise turn every credential read into
  // a 500 rather than the relaxation it is meant to be.
  const params = isAdmin
    ? [vmInstanceId]
    : (NOT_HIDDEN ? [vmInstanceId, userId, ...hiddenBindValues()] : [vmInstanceId, userId]);
  const run = (statement, binds) => cybercoreQuery(statement, binds).catch((err) => {
    console.warn(`${LOG} Credential lookup failed for ${vmInstanceId}: ${err.message}`);
    throw err;
  });

  let result = await run(sql, params);
  let via = isAdmin ? 'admin' : 'owner';

  // SCOPE 3: the instructor who teaches this lane's course. See the header.
  //
  // Reached ONLY after the owner/admin scope has already missed, so the common
  // path never crosses into cle_db.
  if (result.rows.length === 0 && !isAdmin && role === 'instructor') {
    // Case-folded on BOTH sides. config->>'course_id' is TEXT, and the value
    // stamped into it comes from a route parameter, so its spelling is whatever
    // the caller typed; the provider returns pg's canonical lowercase uuid. A
    // bare `=` between those two silently matches nothing, which is the failure
    // mode that makes an authorization arm look like it works and quietly deny
    // every instructor. courseIdsForInstructor must NOT fold case itself -
    // ticket-access.sameId compares exactly and would break.
    const taught = (await courseDirectory.courseIdsForInstructor({ userId, role }))
      .map(id => String(id).toLowerCase());

    // No taught courses -> no query. `= ANY('{}')` is false for every row, so
    // this is purely about not asking.
    if (taught.length > 0) {
      // No NOT_HIDDEN clause, matching the isPrivileged semantics above: hidden
      // means hidden from the STUDENT, and the sensor's login is exactly what an
      // instructor needs when it stops. Deliberately no enrollment predicate -
      // the lane's course is the scope, not the owner's current roster status.
      const courseScoped = await run(`
        SELECT ${SELECT_COLUMNS} ${FROM_JOINS}
          WHERE vi.vm_instance_id = $1
            AND vi.destroyed_at IS NULL
            AND r.status != 'retired'
            AND r.metadata->>'vm_category' = 'lane_vm'
            ${LIVE_LANE}
            AND lower(dl.config->>'course_id') = ANY($2::text[])`,
        [vmInstanceId, taught]);
      if (courseScoped.rows.length > 0) {
        result = courseScoped;
        via = 'course';
      }
    }
  }

  if (result.rows.length === 0) return null;

  const row = result.rows[0];
  return {
    ...resolveLaneWorkstationCredential(row.lane_config, row.provider_vmid),
    ownerUserId: row.owner_user_id || null,
    vmName: row.proxmox_name || row.vm_name || null,
    // Which scope authorized this read, for the audit row. 'course' is the only
    // one where the reader is neither the owner nor an admin, so it is the one
    // worth being able to find again.
    via,
  };
}

module.exports = {
  resolveLaneWorkstationCredential,
  getLaneWorkstationCredentialForVm,
};
