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
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { canManageCourse } = require('../utils/course-access');
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

    if (!(await canManageCourse(courseId, req.user))) {
      return res.status(403).json({ error: 'Course not found or access denied' });
    }

    const enrolled = await query(
      `SELECT user_id
         FROM cle_course_enrollment
        WHERE course_id = $1
          AND status IN ('active', 'completed')`,
      [courseId]
    );

    const state = await flagManager.getFlagStateForUsers(enrolled.rows.map(r => r.user_id));
    res.json({ students: flagManager.buildCohortRows(state) });
  } catch (err) {
    console.error('[CLE Flags] Course flag state error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
