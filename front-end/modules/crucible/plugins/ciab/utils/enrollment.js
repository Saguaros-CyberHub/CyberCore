/**
 * CIAB Plugin — Enrollment gate
 * ----------------------------------------------------------------------------
 * Clinic-in-a-Box is a course, not a public feature. A student reaches it only
 * because an instructor put them on a section roster (migration 008).
 *
 * Before this existed, routes/pages.js served every /ciab/* page with NO
 * middleware at all -- unauthenticated included -- and the API gate was
 * `authenticateToken` alone, so any valid JWT was full student access to the
 * generator, workspace, interview simulator and risk assessment.
 *
 * INSTRUCTORS AND ADMINS ALWAYS PASS, AND NEVER TOUCH THE DATABASE TO DO IT.
 * That asymmetry is deliberate: a clinic_db outage must not lock staff out of
 * the very pages that would let them diagnose it, and staff are the people who
 * would fix a broken roster.
 *
 * SEE ALSO middleware/schedule.js. checkSchedule() runs AFTER this, and its
 * "student is in no group -> allow" branch is only defensible because of this
 * gate: with enrollment enforced, "in no group" means "enrolled, but the
 * instructor set no time window", which is a legitimate always-allowed state
 * rather than the hole it used to be.
 */

const { query } = require('./db');

// Joined to ciab_section on purpose: archiving a section must revoke its
// students' access, or "archive" is a label with no effect.
const ACTIVE_SQL = `
  SELECT 1
    FROM ciab_enrollment e
    JOIN ciab_section s ON s.section_id = e.section_id
   WHERE e.user_id = $1
     AND e.status = 'active'
     AND s.status = 'active'
   LIMIT 1`;

/**
 * How long a positive/negative answer is reused within one process.
 *
 * A student on /ciab/workspace fires 10-30 API calls per page; without this
 * every one of them is a database round trip. 60s of staleness on a REVOCATION
 * is not the weak link in this system -- the JWT itself carries a role claim
 * that is up to 7 days stale (src/routes/auth.js signs it once and nothing
 * re-reads the DB per request).
 *
 * GRANTS are never stale: every route that enrolls calls invalidate() on the
 * way out. Set CIAB_ENROLLMENT_CACHE_MS=0 to disable caching entirely.
 */
const TTL_MS = (() => {
  const raw = Number(process.env.CIAB_ENROLLMENT_CACHE_MS);
  return Number.isFinite(raw) && raw >= 0 ? raw : 60_000;
})();

// A class is ~30 keys. The cap only exists so a pathological workload cannot
// grow this without bound.
const MAX_CACHE = 5000;

/**
 * The rollback lever, and the reason this file can afford to fail closed.
 *
 * If migration 008 fails, the loader only warns and boot continues -- and
 * because the loader sends each .sql file as ONE query, a failure means ZERO
 * tables exist, so every check here throws 42P01. Setting
 * CIAB_ENROLLMENT_ENFORCE=false restores today's behaviour in one restart,
 * with no code deploy.
 */
const enforcing = () => process.env.CIAB_ENROLLMENT_ENFORCE !== 'false';

const isStaff = (u) => !!u && (u.role === 'instructor' || u.role === 'admin');

const cache = new Map(); // userId -> { enrolled, exp }

function invalidate(userId) {
  if (userId != null) cache.delete(String(userId));
}
function invalidateAll() {
  cache.clear();
}

/** @returns {Promise<boolean>} does this user hold any active enrollment? */
async function isEnrolled(userId) {
  if (userId == null) return false;
  const key = String(userId);

  if (TTL_MS > 0) {
    const hit = cache.get(key);
    if (hit && hit.exp > Date.now()) return hit.enrolled;
  }

  const result = await query(ACTIVE_SQL, [userId]);
  const enrolled = result.rowCount > 0;

  if (TTL_MS > 0) {
    if (cache.size > MAX_CACHE) cache.clear();
    cache.set(key, { enrolled, exp: Date.now() + TTL_MS });
  }
  return enrolled;
}

/** The sections a student is actually on, for their own dashboard. */
async function activeEnrollmentsFor(userId) {
  const result = await query(
    `SELECT s.section_id, s.name, s.code, s.term, s.instructor_id,
            e.enrollment_role, e.status, e.enrolled_at
       FROM ciab_enrollment e
       JOIN ciab_section s ON s.section_id = e.section_id
      WHERE e.user_id = $1 AND e.status = 'active' AND s.status = 'active'
      ORDER BY s.created_at DESC`,
    [userId]
  );
  return result.rows;
}

/**
 * Sections this user may manage.
 *
 * Admins get everything. Everyone else gets the sections they own OR are staff
 * on -- one predicate over ciab_section_instructor, because migration 008 also
 * inserts the owner there.
 */
async function sectionsManagedBy(user, { status = 'active' } = {}) {
  // Each branch builds its OWN params array. Threading one shared array through
  // both and neutralising the unused placeholder with "$1 IS NOT NULL OR TRUE"
  // is the trap test/sql-param-typing.test.js exists to catch: a NullTest
  // supplies no type, PostgreSQL fixes a parameter's type at its first
  // reference, and the statement fails to parse with "could not determine data
  // type of parameter $1" -- deterministically, for every caller.
  const admin = !!(user && user.role === 'admin');
  const params = admin ? [] : [user && user.userId];

  let statusClause = '';
  if (status !== 'all') {
    params.push(status);
    statusClause = `AND s.status = $${params.length}`;
  }

  if (admin) {
    const result = await query(
      `SELECT s.* FROM ciab_section s
        WHERE TRUE ${statusClause}
        ORDER BY s.created_at DESC`,
      params
    );
    return result.rows;
  }

  const result = await query(
    `SELECT DISTINCT s.* FROM ciab_section s
       LEFT JOIN ciab_section_instructor si ON si.section_id = s.section_id
      WHERE (s.instructor_id = $1 OR si.instructor_id = $1) ${statusClause}
      ORDER BY s.created_at DESC`,
    params
  );
  return result.rows;
}

/**
 * Fetch a section only if this caller may manage it, else null.
 *
 * Mirrors cle/utils/course-access.js getManagedCourse(): one call answers both
 * "does it exist" and "may you touch it", so a route cannot accidentally answer
 * the first without the second.
 */
async function getManagedSection(sectionId, user, columns = 'section_id') {
  if (!sectionId || !user) return null;
  if (user.role === 'admin') {
    const r = await query(
      `SELECT ${columns} FROM ciab_section WHERE section_id = $1`, [sectionId]
    );
    return r.rows[0] || null;
  }
  const r = await query(
    `SELECT ${columns.split(',').map((c) => `s.${c.trim()}`).join(', ')}
       FROM ciab_section s
       LEFT JOIN ciab_section_instructor si ON si.section_id = s.section_id
      WHERE s.section_id = $1 AND (s.instructor_id = $2 OR si.instructor_id = $2)
      LIMIT 1`,
    [sectionId, user.userId]
  );
  return r.rows[0] || null;
}

async function canManageSection(sectionId, user) {
  return !!(await getManagedSection(sectionId, user));
}

/**
 * The predicate GET /api/modules uses to decide whether to list CIAB at all.
 * Registered with the module loader by routes/api.js.
 *
 * Honours Student View. ViewMode is a PRESENTATION mode (public/js/app.js) --
 * "only what is DRAWN changes" -- so a previewing instructor must be shown the
 * sidebar a real student would get, which for CIAB means being judged on
 * enrollment rather than on role. Without this, Student View would keep showing
 * CIAB to staff who are not enrolled and stop being a faithful preview.
 */
async function canSeeCiab(req) {
  const user = req && req.user;
  if (!user) return false;
  const previewing = req.query && String(req.query.view || '') === 'student';
  if (!previewing && isStaff(user)) return true;
  try {
    return await isEnrolled(user.userId);
  } catch (err) {
    // Fail CLOSED, but never for a previewing instructor: a database blip
    // during a lecture must not make Student View look like a broken menu.
    if (previewing && isStaff(user)) return true;
    if (!enforcing()) return true;
    throw err;
  }
}

/**
 * API gate. JSON, never a redirect.
 *
 * Three distinct answers, and the distinction matters:
 *   401 no token at all
 *   403 authenticated, genuinely not on any roster -- with the fix in the body
 *   503 we could not find out
 *
 * The 503 is the one that is easy to get wrong. Telling a student "you are not
 * enrolled" when the database is merely unreachable sends them to an instructor
 * who cannot fix it, and tells the client not to retry. It is a different fact
 * and it gets a different status.
 */
function requireCiabAccess(req, res, next) {
  if (!req.user) {
    return res.status(401).json({ error: 'Authentication required', code: 'NO_TOKEN' });
  }
  if (isStaff(req.user)) return next();

  isEnrolled(req.user.userId)
    .then((ok) => {
      if (ok) return next();
      res.status(403).json({
        error: 'Clinic-in-a-Box is only available to students an instructor has enrolled. '
             + 'Ask your instructor to add you to a section.',
        code: 'CIAB_NOT_ENROLLED',
      });
    })
    .catch((err) => {
      console.error(`[CIAB] enrollment check failed for ${req.user.userId}:`, err.code || '', err.message);
      if (!enforcing()) return next();
      res.status(503).json({
        error: 'Clinic-in-a-Box is temporarily unavailable. Try again shortly.',
        code: 'CIAB_ACCESS_CHECK_FAILED',
      });
    });
}

/**
 * Page gate. Redirects, never JSON.
 *
 * Same shape as cle/routes/pages.js requireInstructorPage(): a browser
 * navigation that gets requireRole()'s JSON 403 body renders a raw error object
 * in the window, which is its own dead end. Anonymous -> /login (they can fix
 * that), everyone else -> /hub (they cannot).
 *
 * @param {'student'|'instructor'|'admin'} tier
 */
function requireCiabPage(tier = 'student') {
  return async (req, res, next) => {
    if (!req.user) return res.redirect('/login');

    if (req.user.role === 'admin') return next();
    if (tier === 'admin') return res.redirect('/hub');

    if (req.user.role === 'instructor') return next();
    if (tier === 'instructor') return res.redirect('/hub');

    try {
      if (await isEnrolled(req.user.userId)) return next();
    } catch (err) {
      console.error(`[CIAB] page enrollment check failed for ${req.user.userId}:`, err.code || '', err.message);
      if (!enforcing()) return next();
    }
    return res.redirect('/hub');
  };
}

module.exports = {
  isEnrolled,
  activeEnrollmentsFor,
  sectionsManagedBy,
  getManagedSection,
  canManageSection,
  canSeeCiab,
  requireCiabAccess,
  requireCiabPage,
  invalidate,
  invalidateAll,
  // Exported for tests and for the boot self-check in routes/api.js.
  isStaff,
  enforcing,
  ACTIVE_SQL,
};
