/**
 * CLE Plugin — Target-student resolution
 * ----------------------------------------------------------------------------
 * Both provisioning paths (workstations in routes/vms.js, vulnerable labs in
 * routes/labs.js) need the same filter: actively enrolled, has an email
 * (Guacamole accounts are email-keyed), and isn't already holding whatever is
 * about to be deployed. Keeping one copy means a deploy can't silently disagree
 * with the list the UI showed the instructor.
 *
 * STAFF-DEPLOY. The people who RUN a course need machines on it too — an
 * instructor walks an exercise before assigning it, and demos it in class — but
 * they are not enrolled in their own course: cle_course.instructor_id is the
 * relationship, and enrollment_role has no 'instructor' value, so the enrolment
 * filter above would reject them. `opts.extraUserIds` is the narrow exemption:
 * ids the route has already authorised may be targeted without an enrollment
 * row.
 *
 * That exemption used to be req.user.userId alone, which is only half the rule.
 * It let an instructor deploy for THEMSELVES while leaving an ADMIN unable to
 * deploy for the instructor they were trying to equip: the admin is the caller,
 * so the exemption covered the admin's own id and the instructor was still
 * dropped as 'not enrolled'. courseStaffIds() below states the whole rule — the
 * caller AND the course's own instructor. Both are safe to exempt because every
 * route using it has already run getManagedCourse, which is admin-aware (an
 * admin passes on any course, an instructor only on their own), so a caller who
 * may manage the course may equip the person who runs it.
 *
 * Everything downstream (the email requirement, the collision exclusions) still
 * applies to staff exactly as it does to a student, so a staff deploy cannot
 * double-book VMIDs.
 */

const { query } = require('./db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

/**
 * Resolve the students to act on.
 *
 * @param {string}   courseId
 * @param {string[]} [requestedIds]  null/undefined = every actively enrolled
 *   student. A null list NEVER picks up `extraUserIds`: "the whole class" means
 *   the roster, and quietly building the instructor a machine every time they
 *   press Deploy Whole Class would be a surprise.
 * @param {object}   [opts]
 * @param {Function} [opts.excludeIf] async (studentIds) => Map<userId, reason>.
 *   Students the caller already covers (e.g. they hold a lane for this lab).
 * @param {string[]} [opts.extraUserIds] ids that may be targeted WITHOUT an
 *   active enrollment — the caller themselves, for a self-deploy. Only honoured
 *   for ids the request actually named.
 * @returns {Promise<{students: Array<{id, email, enrolled}>, skipped: Array<{student_id, reason}>}>}
 */
async function resolveTargetStudents(courseId, requestedIds, opts = {}) {
  const enrolled = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND status = 'active'`,
    [courseId]
  );
  const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));
  const exempt = new Set((opts.extraUserIds || []).filter(Boolean));

  const ids = requestedIds ? requestedIds.filter(Boolean) : [...enrolledIds];
  const skipped = [];
  const candidates = [];
  for (const id of ids) {
    if (!enrolledIds.has(id) && !exempt.has(id)) { skipped.push({ student_id: id, reason: 'not enrolled' }); continue; }
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
    // `enrolled` lets a caller tell a student apart from a self-deploying
    // instructor without re-querying — the gradebook, for one, must not grow a
    // submission row for someone who is not on the roster.
    students.push({ id, email: emailById[id], enrolled: enrolledIds.has(id) });
  }
  return { students, skipped };
}

/**
 * The ids that count as this course's STAFF: the caller, and the course's own
 * instructor. Deduped, falsy-filtered, caller first.
 *
 * This is the single definition of "who may be targeted without an enrollment
 * row", handed to resolveTargetStudents' `extraUserIds` by every deploy,
 * teardown and redeploy route. Keeping one definition is the point: the bug this
 * replaced was five call sites each passing req.user.userId, which silently
 * means "the admin" whenever an admin is the one managing the course.
 *
 * Caller-first ordering matters downstream — when the caller IS the instructor,
 * the single resulting row is labelled "you" rather than "instructor".
 *
 * Pure: it reads a course row the caller has ALREADY proved they may manage via
 * getManagedCourse. It performs no authorisation itself, and must never be
 * called with a course row that was not fetched through that check.
 *
 * @param {{ instructor_id?: string }|null} course  a managed course row. Pass one
 *   selected WITHOUT instructor_id (or null) and this degrades to the caller
 *   alone, which is the old self-deploy-only behaviour.
 * @param {{ userId: string }|null} user  req.user
 * @returns {string[]}
 */
function courseStaffIds(course, user) {
  const ids = [];
  for (const id of [user && user.userId, course && course.instructor_id]) {
    if (id && !ids.includes(id)) ids.push(id);
  }
  return ids;
}

/**
 * The course's staff as deploy targets: the rows the deploy modals list
 * alongside the roster, so a machine can be built for someone who RUNS the
 * course rather than takes it.
 *
 * Rows with no email are dropped. Guacamole accounts are email-keyed, so such a
 * machine would come up with no console — offering it would only produce a
 * deploy that half-works.
 *
 * Callers MUST have already proved the user may manage this course
 * (getManagedCourse / canManageCourse); this helper does no authorisation of its
 * own. `enrolled` is reported rather than filtered on, because someone who IS
 * also enrolled (a TA teaching their own section) is already in the roster list
 * and must not be offered twice — the route drops those rows.
 *
 * @param {string} courseId
 * @param {{ userId: string }} user  req.user
 * @param {{ instructor_id?: string }} [course]  the managed course row
 * @returns {Promise<Array<{user_id, email, first_name, last_name, enrolled, is_self, is_course_instructor}>>}
 */
async function resolveCourseStaffTargets(courseId, user, course = null) {
  const ids = courseStaffIds(course, user);
  if (ids.length === 0) return [];

  const found = await cybercoreQuery(
    `SELECT user_id, email, first_name, last_name
       FROM cybercore_user WHERE user_id = ANY($1::uuid[])`,
    [ids]
  );
  if (found.rows.length === 0) return [];
  const byId = new Map(found.rows.map(r => [r.user_id, r]));

  // One probe for both ids rather than one each: the array is at most 2 long,
  // but this path runs on every open of both deploy modals.
  const enrolled = await query(
    `SELECT user_id FROM cle_course_enrollment
      WHERE course_id = $1 AND user_id = ANY($2::uuid[]) AND status = 'active'`,
    [courseId, ids]
  );
  const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

  const rows = [];
  for (const id of ids) {
    const row = byId.get(id);
    if (!row || !row.email) continue;
    rows.push({
      user_id: row.user_id,
      email: row.email,
      first_name: row.first_name || '',
      last_name: row.last_name || '',
      enrolled: enrolledIds.has(row.user_id),
      is_self: row.user_id === user.userId,
      is_course_instructor: !!(course && row.user_id === course.instructor_id),
    });
  }
  return rows;
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
        ? 'has a failed deployment of this environment — remove it before re-deploying'
        : 'already has this environment deployed',
    ]));
  };
}

/**
 * Run several exclusions and merge their results into one, so a caller can pass
 * more than one to resolveTargetStudents' single `excludeIf` slot. The first
 * reason recorded for a student wins — order the arguments most-specific first.
 *
 * Exclusions are independent predicates over the same candidate list, so running
 * them all and merging is equivalent to chaining, without needing a pipeline.
 */
function combineExclusions(...fns) {
  const active = fns.filter(Boolean);
  if (active.length <= 1) return active[0];
  return async (candidates) => {
    const merged = new Map();
    for (const fn of active) {
      for (const [id, reason] of await fn(candidates)) {
        if (!merged.has(id)) merged.set(id, reason);
      }
    }
    return merged;
  };
}

module.exports = {
  resolveTargetStudents,
  courseStaffIds,
  resolveCourseStaffTargets,
  excludeStudentsWithCourseLane,
  excludeStudentsWithLab,
  combineExclusions,
};
