/**
 * CLE Plugin — Target-student resolution
 * ----------------------------------------------------------------------------
 * Both provisioning paths (workstations in routes/vms.js, vulnerable labs in
 * routes/labs.js) need the same filter: actively enrolled, has an email
 * (Guacamole accounts are email-keyed), and isn't already holding whatever is
 * about to be deployed. Keeping one copy means a deploy can't silently disagree
 * with the list the UI showed the instructor.
 */

const { query } = require('./db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

/**
 * Resolve the students to act on.
 *
 * @param {string}   courseId
 * @param {string[]} [requestedIds]  null/undefined = every actively enrolled student
 * @param {object}   [opts]
 * @param {Function} [opts.excludeIf] async (studentIds) => Map<userId, reason>.
 *   Students the caller already covers (e.g. they hold a lane for this lab).
 * @returns {Promise<{students: Array<{id, email}>, skipped: Array<{student_id, reason}>}>}
 */
async function resolveTargetStudents(courseId, requestedIds, opts = {}) {
  const enrolled = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'`,
    [courseId]
  );
  const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

  const ids = requestedIds ? requestedIds.filter(Boolean) : [...enrolledIds];
  const skipped = [];
  const candidates = [];
  for (const id of ids) {
    if (!enrolledIds.has(id)) { skipped.push({ student_id: id, reason: 'not enrolled' }); continue; }
    candidates.push(id);
  }
  if (candidates.length === 0) return { students: [], skipped };

  const users = await cybercoreQuery(
    `SELECT user_id, email FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    [candidates]
  );
  const emailById = {};
  for (const r of users.rows) emailById[r.user_id] = r.email;

  const excluded = opts.excludeIf ? await opts.excludeIf(candidates) : new Map();

  const students = [];
  for (const id of candidates) {
    if (excluded.has(id)) { skipped.push({ student_id: id, reason: excluded.get(id) }); continue; }
    if (!emailById[id]) { skipped.push({ student_id: id, reason: 'no email on account' }); continue; }
    students.push({ id, email: emailById[id] });
  }
  return { students, skipped };
}

/**
 * Exclusion for the workstation path: a student already holding a live
 * WORKSTATION lane in this course would collide on the gateway/workstation
 * VMIDs for their VXLAN.
 *
 * `config.material_id IS NULL` is what separates the two kinds of lane. Both
 * carry config.course_id — lab lanes need it so the flag board, the VM list and
 * course teardown find them — so matching on course_id alone would count a
 * student's vulnerable-lab lane as their workstation and refuse to give them one.
 */
function excludeStudentsWithCourseLane(courseId) {
  return async (candidates) => {
    const existing = await cybercoreQuery(
      `SELECT user_id FROM cybercore_lane
        WHERE user_id = ANY($1::uuid[])
          AND config->>'course_id' = $2
          AND config->>'material_id' IS NULL
          AND status NOT IN ('deleted', 'error')`,
      [candidates, courseId]
    );
    return new Map(existing.rows.map(r => [r.user_id, 'already has a workstation']));
  };
}

/**
 * Exclusion for the vulnerable-lab path: a student already holding this lab —
 * either as a dedicated lane (config.material_id) or as an attached module on
 * one of their lanes. Re-deploying either would collide on VMIDs.
 *
 * 'error' lanes are INCLUDED deliberately. A lane that failed partway usually
 * still has VMs running at the ids the retry would clone into, so re-deploying
 * on top of it fails at the first clone with "VM already exists". The student is
 * reported as blocked with a reason that says to remove the failed lane first,
 * which is the only sequence that actually works.
 */
function excludeStudentsWithLab(materialId) {
  return async (candidates) => {
    const existing = await cybercoreQuery(
      `SELECT DISTINCT user_id, status FROM cybercore_lane
        WHERE user_id = ANY($1::uuid[])
          AND status <> 'deleted'
          AND (
            config->>'material_id' = $2
            OR (
              jsonb_typeof(config->'attached_modules') = 'array'
              AND EXISTS (
                SELECT 1 FROM jsonb_array_elements(config->'attached_modules') AS m
                 WHERE m->>'material_id' = $2
              )
            )
          )`,
      [candidates, materialId]
    );
    return new Map(existing.rows.map(r => [
      r.user_id,
      r.status === 'error'
        ? 'has a failed deployment of this lab — remove it before re-deploying'
        : 'already has this lab deployed',
    ]));
  };
}

module.exports = {
  resolveTargetStudents,
  excludeStudentsWithCourseLane,
  excludeStudentsWithLab,
};
