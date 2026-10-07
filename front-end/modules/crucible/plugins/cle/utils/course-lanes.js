/**
 * CLE Plugin — lane counts per course.
 *
 * Lanes live in cybercore_db keyed by config->>'course_id'; courses live in
 * cle_db. There is no cross-DB FK and no way to join the two in one statement,
 * so every "how many machines does this course have" question is a separate
 * grouped count merged onto the course rows in JS.
 *
 * This lives in utils/ rather than inline in routes/courses.js because
 * routes/my-courses.js needs it too, and requiring one router module from
 * another to borrow a helper is how import cycles start.
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

/**
 * @param {string[]} courseIds
 * @returns {Promise<Object<string, number>>} course_id -> live (non-deleted) lane count
 *
 * The keys are TEXT, not uuid: config->>'course_id' is a text expression, so
 * the parameter has to be cast text[] or Postgres cannot compare them.
 *
 * A failure here degrades a COUNT, never the page, so it resolves to {}.
 */
async function laneCountsByCourse(courseIds) {
  if (!courseIds || courseIds.length === 0) return {};
  const result = await cybercoreQuery(
    `SELECT config->>'course_id' AS course_id, COUNT(*)::int AS vm_count
       FROM cybercore_lane
      WHERE config->>'course_id' = ANY($1::text[]) AND status <> 'deleted'
      GROUP BY 1`,
    [courseIds.map(String)]
  ).catch(() => ({ rows: [] }));

  const byId = {};
  for (const row of result.rows) byId[row.course_id] = row.vm_count;
  return byId;
}

/** Attach `vm_count` to each cle_course row, in place. */
async function attachLaneCounts(courseRows) {
  if (!courseRows || courseRows.length === 0) return courseRows;
  const byId = await laneCountsByCourse(courseRows.map(c => c.course_id));
  for (const c of courseRows) c.vm_count = byId[c.course_id] || 0;
  return courseRows;
}

module.exports = { laneCountsByCourse, attachLaneCounts };
