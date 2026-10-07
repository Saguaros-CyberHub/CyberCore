/**
 * CLE Plugin — Capture Flag Visibility
 * Mounted at /api/cle/courses/:courseId/flags
 *
 * Instructor view of who has captured which user.txt / root.txt across the
 * cohort, plus the sharing signal (submissions of a flag belonging to another
 * student's lane).
 *
 * Scoped by ENROLLMENT, not by cybercore_lane.config. The two provisioning
 * paths stamp different keys onto the lane — CLE's own provisionLanes writes
 * config.course_id, while POST /api/admin/deploy-group (the path that actually
 * deploys challenge targets, and therefore the path a CYBV 480 class uses)
 * writes config.group_id and no course reference at all. Resolving the roster
 * from cle_course_enrollment and looking flags up per student covers both.
 *
 * Cross-DB: enrollment lives in cle_db, flags in cybercore_db. No join is
 * possible, so this is two queries — the same pattern used elsewhere for
 * user_id / lane_id references.
 *
 * The roster is not the whole list: an instructor who deployed a lab to
 * themselves holds flags without an enrollment row, and those rows come back
 * marked `staff` so the UI can keep them out of class statistics.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { getManagedCourse } = require('../utils/course-access');
const { courseStaffIds } = require('../utils/students');
const flagManager = require('../../../../../src/utils/flag-manager');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * GET / — cohort flag matrix for the course.
 * Includes flag values: the instructor has to be able to check a student's
 * claim against the correct answer for that student's own lane.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;

    const course = await getManagedCourse(courseId, req.user, 'course_id, instructor_id');
    if (!course) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    const enrolled = await query(
      `SELECT user_id
         FROM cle_course_enrollment
        WHERE course_id = $1
          AND status IN ('active', 'completed')`,
      [courseId]
    );
    const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

    // Staff hold flags too: an instructor can deploy a lab to themselves, and
    // the point of doing that is usually to confirm the flags actually planted
    // before a class hits them. Adding the ids is free — buildCohortRows only
    // emits a row for a user who HAS flags, so nobody who hasn't self-deployed
    // appears here.
    const staffIds = courseStaffIds(course, req.user).filter(id => !enrolledIds.has(id));
    const userIds = [...enrolledIds, ...staffIds];

    const state = await flagManager.getFlagStateForUsers(userIds);
    // `staff` keeps the instructor's own row out of anything the UI presents as
    // class performance.
    const students = flagManager.buildCohortRows(state)
      .map(row => (enrolledIds.has(row.userId) ? row : { ...row, staff: true }));
    res.json({ students });
  } catch (err) {
    console.error('[CLE Flags] Course flag state error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
