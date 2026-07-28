/**
 * ============================================================================
 * CLE Lane Provisioning
 * ----------------------------------------------------------------------------
 * Thin course-aware wrapper over src/utils/lane-deployer.js — the shared
 * primitive extracted from the admin group-deploy path (routes/admin/groups.js),
 * which is the implementation proven to produce a lane a student can actually
 * connect to.
 *
 * Everything hard lives in lane-deployer: pinning the workstation to
 * <lane-base>.50 by MAC, publishing its console port on the gateway's WAN IP,
 * the e1000 NIC for Windows guests, cloud-init credentials, the Tailscale claim
 * secret, workspace registration so the STUDENT sees the machine on their own
 * dashboard, and the hardened batch teardown.
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
 * @param {object} args.template    cybercore_template_catalog row (workstation)
 * @param {Array}  args.students    [{ id, email }]
 * @param {string} [args.courseName]
 */
async function provisionLanes({ courseId, challenge, template, students, courseName }) {
  if (!students.length) return { provisioned: [], failed: [], progressId: null };

  const vxlanBlock = challenge.vxlan_block || challenge.spec?.vxlan_block;
  if (!vxlanBlock?.start || !vxlanBlock?.end) {
    throw new Error('Course has no reserved VXLAN block — recreate the course to provision its network');
  }

  const result = await laneDeployer.deployLanes({
    users: students,
    template,
    vxlanBlock,
    moduleKey: MODULE_KEY,
    subnetScheme: SUBNET_SCHEME,
    namePrefix: 'cle',
    // config.course_id is how every CLE read path finds these lanes again —
    // listing, counts, teardown. It must be on every lane.
    laneConfig: {
      cle: true,
      course_id: courseId,
      challenge_key: challenge.challenge_key,
    },
    description: `Course: ${courseName || courseId}`,
    progressId: progressIdForCourse(courseId),
    progressLabel: courseName || `CLE course ${courseId}`,
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
  resolveCourseLab,
  provisionLanes,
  getProvisionProgress,
  teardownLane,
  teardownCourseLanes,
};
