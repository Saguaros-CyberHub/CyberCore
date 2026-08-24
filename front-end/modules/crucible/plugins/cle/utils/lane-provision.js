/**
 * ============================================================================
 * CLE Lane Provisioning
 * ----------------------------------------------------------------------------
 * Thin course-aware wrapper over src/utils/lane-deployer.js — the shared
 * primitive extracted from the admin group-deploy path (routes/admin/groups.js),
 * which is the implementation proven to produce a lane a student can actually
 * connect to.
 *
 * Everything hard lives in lane-deployer: pinning each workstation to
 * <lane-base>.<50 + slot> by MAC, publishing its console port on the gateway's
 * WAN IP, the e1000 NIC for Windows guests, cloud-init credentials, the Tailscale
 * claim secret, workspace registration so the STUDENT sees the machine on their
 * own dashboard, and the hardened batch teardown.
 *
 * This file's only job is course context:
 *   - resolve the course's reserved VXLAN block from its crucible_challenge
 *   - stamp config.course_id on every lane so the CLE UI can find them again
 *   - map lanes back to courses for listing and teardown
 *
 * Keep it that way. If something here starts looking like deploy logic, it
 * belongs in lane-deployer instead — a third copy of that sequence is exactly
 * how this plugin got broken the first time.
 * ============================================================================
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const laneDeployer = require('../../../../../src/utils/lane-deployer');

const MODULE_KEY = 'crucible';
const SUBNET_SCHEME = 'v2';

const LOG = '[CLE Lane]';

/** Progress key for a course-wide deploy, so the UI can poll one stable id. */
function progressIdForCourse(courseId) {
  return `cle-course-${courseId}`;
}

/**
 * Progress key for a course-scope DESTRUCTIVE workstation operation — bulk
 * delete or bulk rebuild.
 *
 * Deliberately ONE key for both. Minting a separate '-delete' key would let a
 * delete and a rebuild run against the same course at once, and the first thing
 * either does is snapshot the lane rows.
 */
function progressIdForCourseRebuild(courseId) {
  return `${progressIdForCourse(courseId)}-rebuild`;
}

/**
 * Progress key for an operation on ONE lane, so two instructors fixing two
 * students do not block each other — and, more importantly, do not share an
 * entry. initProgress replaces the entry wholesale, so a shared key means the
 * second start erases the first's counters and the first poller reports the
 * second's numbers.
 *
 * courseId is a UUID, so `cle-course-<courseId>` is an unambiguous prefix of
 * every key in this family: the next character is '-' or the end of the string.
 * That is what makes the listProgressIds() enumeration below safe.
 */
function progressIdForLane(courseId, laneId) {
  return `${progressIdForCourse(courseId)}-lane-${laneId}`;
}

/**
 * Every workstation operation currently in flight against this course: the
 * provision, the course-scope destructive op, and any per-lane ones.
 *
 * Scope is derived by SLICING THE KEY rather than read off the entry, for the
 * same reason labOperationsInFlight does it (vuln-lab-provision.js): the deploy
 * paths call initProgress themselves and replace the object, so any field we
 * stashed on it would not survive the handover.
 *
 * @returns {Array<{progressId, scope:'provision'|'course'|'lane', laneId:string|null,
 *                  phase, phase_detail, completed, total}>}
 */
function courseOperationsInFlight(courseId) {
  const base = progressIdForCourse(courseId);
  const out = [];
  for (const progressId of laneDeployer.listProgressIds(base)) {
    const p = laneDeployer.readProgress(progressId);
    // 'complete' entries linger for an hour so a late poller can still read the
    // outcome. They are finished work, not a conflict — without this exemption
    // one finished bulk delete would 409 the whole course for that hour.
    if (!p || p.phase === 'complete') continue;

    const suffix = progressId.slice(base.length);
    let scope = null;
    let laneId = null;
    if (suffix === '') scope = 'provision';
    else if (suffix === '-rebuild') scope = 'course';
    else if (suffix.startsWith('-lane-')) { scope = 'lane'; laneId = suffix.slice('-lane-'.length); }
    // Anything else shares our prefix without belonging to this family. A
    // fixed-length UUID cannot prefix another, so this is unreachable today —
    // skipping rather than guessing keeps it that way if the format ever grows.
    else continue;

    out.push({
      progressId, scope, laneId,
      phase: p.phase,
      phase_detail: p.phase_detail,
      completed: p.completed,
      total: p.total,
    });
  }
  return out;
}

/**
 * Refuse to start a workstation operation that would collide with one already
 * running on this course.
 *
 * The progress registry is the only mutex available — this app has no job
 * queue. It works because there is exactly one Node process.
 *
 * Scoping rules:
 *   course scope (laneId null) — conflicts with ANYTHING on this course. A bulk
 *     delete landing mid-provision enumerates lanes whose VMs are still being
 *     cloned and orphans them; deployLanes allocates VXLAN ids and inserts the
 *     rows before any clone finishes.
 *   lane scope — conflicts with the provision, with any course-scope op, and
 *     with this same lane. Another lane's rebuild is independent and must not
 *     block: two instructors fixing two students is the normal case.
 *
 * A provision is course-wide by construction — its key names no lanes — so it
 * can never be proven disjoint from a single-lane op. Conservative and cheap.
 *
 * CALL THIS IN THE SAME SYNCHRONOUS BLOCK AS THE initProgress() CLAIM, with
 * every await already done. A check, an await, then a claim leaves the
 * double-click window wide open.
 *
 * @param {string}  a.ignoreProgressId  the claim the caller just took for itself
 * @throws {Error & {status:409}}
 */
function assertNoConflictingWorkstationOperation({ courseId, laneId = null, ignoreProgressId = null }) {
  const conflicts = courseOperationsInFlight(courseId).filter((op) => {
    if (op.progressId === ignoreProgressId) return false;
    if (laneId === null) return true;            // course scope: everything conflicts
    return op.scope !== 'lane' || op.laneId === laneId;
  });
  if (conflicts.length === 0) return;

  const c = conflicts[0];
  const who = c.scope === 'provision' ? 'A deploy on this course'
    : c.scope === 'course' ? 'Another bulk operation on this course'
    : 'Another operation on this lane';
  const err = new Error(
    `${who} is still running (${c.completed}/${c.total}, ${c.phase_detail || c.phase}). ` +
    `Wait for it to finish — running both at once would leave machines behind with ` +
    `nothing pointing at them.`
  );
  err.status = 409;
  throw err;
}

// Longest sanitized course code we will put in a lane name. The binding limit is
// the gateway LXC hostname: lane-deployer builds `${laneName}-gateway` inside a
// 63-char budget minus 18 reserved for the `-b<16hex>` claim secret, so laneName
// must stay ≤ 37. `cle-` + code + `-` + a 5-digit VXLAN id spends 10 of those,
// leaving 27; 24 keeps headroom. cle_course.code is VARCHAR(50), so a code CAN
// overrun this — truncating is better than a silently mangled gateway hostname.
const MAX_CODE_LEN = 24;

/**
 * Lane-name prefix for a course: `cle-<course-code>`, so a lane comes out as
 * `cle-cybv454-10003` rather than the old course-agnostic `cle-10003`. The name
 * becomes the Proxmox VM name, both LXC hostnames, the dnsmasq reservation
 * hostname and the Guacamole connection name — hence lowercase, and hostname
 * characters only (spaces stripped per the naming convention, everything else
 * unsafe folded to `-`). Falls back to a bare `cle` when the course has no code.
 */
function laneNamePrefix(courseCode) {
  const slug = String(courseCode || '')
    .toLowerCase()
    .replace(/\s+/g, '')          // "CYBV 454" → "cybv454"
    .replace(/[^a-z0-9-]/g, '-')  // anything else illegal in a hostname
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, MAX_CODE_LEN)
    .replace(/-$/, '');           // truncation must not leave a trailing hyphen
  return slug ? `cle-${slug}` : 'cle';
}

/**
 * Resolve a course's reserved lab: the crucible_challenge row created by
 * reserveLabNetwork at course-creation time, which owns the VXLAN block and the
 * pre-created SDN VNets.
 */
async function resolveCourseLab(challengeId) {
  const chal = await cybercoreQuery(
    `SELECT challenge_key, spec FROM crucible_challenge WHERE challenge_id = $1`,
    [challengeId]
  );
  if (chal.rows.length === 0) return null;
  const spec = typeof chal.rows[0].spec === 'string'
    ? JSON.parse(chal.rows[0].spec)
    : (chal.rows[0].spec || {});
  return { challengeKey: chal.rows[0].challenge_key, vxlanBlock: spec.vxlan_block };
}

/**
 * Provision one workstation lane per student out of the course's reserved VXLAN
 * block. Returns { provisioned: [...], failed: [...], progressId }.
 *
 * @param {object} args
 * @param {string} args.courseId
 * @param {object} args.challenge   { challenge_key, vxlan_block:{start,end} }
 * @param {object} [args.template]  cybercore_template_catalog row (workstation).
 *   Shorthand for a one-workstation lane.
 * @param {Array}  [args.templates] one catalog row per workstation, in slot
 *   order, when a course needs more than one machine per student. Slot 0 lands
 *   on <lane-base>.50 exactly as a single template does, so a course that sends
 *   one template is unaffected. The provision route currently only ever sends
 *   one — this is the pass-through, not a UI feature.
 * @param {Array}  args.students    [{ id, email }]
 * @param {string} [args.courseName]
 * @param {string} [args.courseCode] cle_course.code — names the lanes
 *   `cle-<code>-<vxlanId>`; omitted/blank falls back to `cle-<vxlanId>`.
 * @param {string} [args.progressId] override the course-wide progress key.
 *   The full-lane rebuild path passes the claim it already took, so its
 *   progress does not publish under — and then finish — the provision's key.
 * @param {string} [args.progressLabel] label for that entry.
 * @param {object} [args.resources] { cores, memory_mb, disk_gb } the instructor
 *   chose for this deploy, applied to each cloned workstation before its first
 *   boot. Pre-validated by the route with laneDeployer.normalizeResourceSpec;
 *   omitted fields keep the catalog template's own sizing.
 */
async function provisionLanes({ courseId, challenge, template, templates, students, courseName, courseCode, resources, progressId, progressLabel }) {
  if (!students.length) return { provisioned: [], failed: [], progressId: null };

  const vxlanBlock = challenge.vxlan_block || challenge.spec?.vxlan_block;
  if (!vxlanBlock?.start || !vxlanBlock?.end) {
    throw new Error('Course has no reserved VXLAN block — recreate the course to provision its network');
  }

  const result = await laneDeployer.deployLanes({
    users: students,
    template,
    templates,
    vxlanBlock,
    moduleKey: MODULE_KEY,
    subnetScheme: SUBNET_SCHEME,
    namePrefix: laneNamePrefix(courseCode),
    resources: resources || null,
    // config.course_id is how every CLE read path finds these lanes again —
    // listing, counts, teardown. It must be on every lane.
    laneConfig: {
      cle: true,
      course_id: courseId,
      challenge_key: challenge.challenge_key,
    },
    description: `Course: ${courseName || courseId}`,
    progressId: progressId || progressIdForCourse(courseId),
    progressLabel: progressLabel || courseName || `CLE course ${courseId}`,
  });

  console.log(
    `${LOG} Course ${courseId}: ${result.provisioned.length} provisioned, ${result.failed.length} failed`
  );
  return result;
}

/** Live progress for a course-wide deploy, or null once it has aged out. */
function getProvisionProgress(courseId) {
  return laneDeployer.readProgress(progressIdForCourse(courseId));
}

/**
 * Live progress for a destructive workstation operation, or null once it has
 * aged out. Pass a laneId for a single-lane rebuild, nothing for a bulk one.
 */
function getRebuildProgress(courseId, laneId = null) {
  return laneDeployer.readProgress(
    laneId ? progressIdForLane(courseId, laneId) : progressIdForCourseRebuild(courseId)
  );
}

/**
 * Every WORKSTATION lane of a course, or just the named ones.
 *
 * The single scoped read behind the VM Management tab: the list, the bulk
 * delete and the rebuild all go through here rather than each spelling the
 * predicate out again.
 *
 * THE `material_id IS NULL` PREDICATE IS THE ENTIRE SAFETY STORY OF THE BULK
 * PATHS, and it has to live in the query that produces the ids — never as a
 * second filtering pass over a separately-fetched list. Vulnerable-lab lanes
 * carry config.material_id and are torn down through vuln-lab-provision, which
 * knows about flag snapshots and module instances. One lab lane id reaching
 * laneDeployer.teardownLanes destroys an assignment's machines through a path
 * that has never heard of any of that. Callers must hand the RETURNED lane ids
 * downstream, never the ids they were asked about.
 *
 * Deliberately NOT scoped by enrollment. A lane whose owner has dropped the
 * course is exactly the leftover an instructor needs to find and remove, and it
 * is already visible in the tab for that reason.
 *
 * @param {string} courseId
 * @param {string[]|null} laneIds  null for every workstation lane of the course
 */
async function findCourseWorkstationLanes(courseId, laneIds = null) {
  const res = await cybercoreQuery(
    `SELECT l.lane_id, l.user_id, l.status, l.vxlan_id, l.name, l.config, l.created_at,
            u.email AS student_email, u.first_name, u.last_name
       FROM cybercore_lane l
       JOIN cybercore_user u ON u.user_id = l.user_id
      WHERE ($2::uuid[] IS NULL OR l.lane_id = ANY($2::uuid[]))
        AND l.config->>'course_id'   = $1
        AND l.config->>'material_id' IS NULL
        AND l.status <> 'deleted'
      ORDER BY l.created_at DESC`,
    [courseId, laneIds]
  );
  return res.rows;
}

/** Tear down a single student's lane. */
async function teardownLane(laneId) {
  const result = await laneDeployer.teardownLanes([laneId]);
  return { success: true, ...result };
}

/**
 * Tear down every lane belonging to a course in one hardened batch pass, rather
 * than looping one lane at a time (which took minutes for a full class and left
 * orphaned disks behind).
 */
async function teardownCourseLanes(courseId) {
  const lanes = await cybercoreQuery(
    `SELECT lane_id FROM cybercore_lane WHERE config->>'course_id' = $1`,
    [courseId]
  );
  const laneIds = lanes.rows.map(r => r.lane_id);
  if (laneIds.length === 0) {
    return { success: true, lanes_deleted: 0, vms_destroyed: 0, orphan_disks_swept: 0, errors: [] };
  }
  console.log(`${LOG} Tearing down ${laneIds.length} lane(s) for course ${courseId}`);
  const result = await laneDeployer.teardownLanes(laneIds);
  return { success: true, ...result };
}

module.exports = {
  MODULE_KEY,
  SUBNET_SCHEME,
  laneNamePrefix,
  resolveCourseLab,
  progressIdForCourse,
  progressIdForCourseRebuild,
  progressIdForLane,
  courseOperationsInFlight,
  assertNoConflictingWorkstationOperation,
  getRebuildProgress,
  findCourseWorkstationLanes,
  provisionLanes,
  getProvisionProgress,
  teardownLane,
  teardownCourseLanes,
};
