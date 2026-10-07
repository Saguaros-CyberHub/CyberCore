/**
 * CIAB Plugin — API Route Aggregator
 * Mounts all CIAB API sub-routers at their existing paths.
 * This router is mounted at "/" by the plugin loader, so
 * /api/profiles, /api/progress, etc. stay at their current URLs.
 */

const express = require('express');
const router = express.Router();

const { authenticateToken } = require('../../../../../src/middleware/auth');
const enrollment = require('../utils/enrollment');
const { requireCiabAccess } = enrollment;

// Plugin middleware
let checkSchedule;
try {
  checkSchedule = require('../middleware/schedule').checkSchedule;
} catch (e) {
  // Schedule middleware not available — pass through
  checkSchedule = (req, res, next) => next();
}

// CIAB route modules
const profileRoutes = require('./profiles');
const clinicApiRoutes = require('./clinic-api');
const progressRoutes = require('./progress');
const interviewRoutes = require('./interview');
const instructorRoutes = require('./instructor');
const intakeFormRoutes = require('./intake-form');
const realClientIntakeRoutes = require('./real-client-intake');
const intakesRoutes = require('./intakes');
const clinicRiskAssessmentRoutes = require('./clinic-risk-assessment');
const cisRamRoutes = require('./cis-ram');
const profileDeployRoutes = require('./profile-deploy');
const sectionRoutes = require('./sections');
const sectionRosterRoutes = require('./section-roster');
const sectionModuleRoutes = require('./section-modules');
const incidentRoutes = require('./incidents');

// The sidebar gate. GET /api/modules consults this to decide whether
// Clinic-in-a-Box appears in the navigation at all, so a student who is on no
// roster never sees a module they cannot open. Registered here rather than in
// module-loader.js so core carries no knowledge of a plugin's access rules.
//
// No circular-require hazard: module-loader.js require()s THIS file long after
// it has finished evaluating itself (see loadModulePlugins).
try {
  require('../../../../../src/module-loader').registerAccessGate('ciab', enrollment.canSeeCiab);
} catch (err) {
  console.warn('[CIAB] Could not register the sidebar access gate:', err.message);
}

// ============================================================================
// MOUNTING
// ----------------------------------------------------------------------------
// THIS ROUTER IS MOUNTED AT '/' (manifest.json), NOT AT /ciab.
//
// That single fact governs everything below. `router.use('/api', ...)` here
// matches EVERY /api/* request in the whole application -- core's, the CLE
// plugin's, any plugin added later -- not just Clinic-in-a-Box's.
//
// It was survivable while the catch-all's chain was authenticateToken +
// checkSchedule + clinicApiRoutes, because all three call next() for an
// ordinary signed-in user and the request fell through to whoever really owned
// the path. Putting requireCiabAccess there turned it into a chain that
// TERMINATES with a 403, and a student on no CIAB roster lost
// GET /api/cle/my/overview -- the hub's "My Courses" panel -- along with every
// other CLE route. Plugin load order is readdir order, so 'ciab' sorts before
// 'cle' and wins; core escaped only because server.js registers its routes
// before moduleLoader.loadAll(). See test/ciab-gate-scope.test.js.
//
// SO: the enrollment gate goes on CIAB-OWNED PREFIXES ONLY, never on the bare
// /api mount. clinic-api.js, which IS mounted there, carries the gate per route
// instead -- it owns five paths, and enumerating them is the price of sharing a
// prefix with the rest of the application.
//
// ORDERING (unchanged): any router with unauthenticated routes MUST be mounted
// BEFORE the /api catch-all, because Express matches router.use() prefixes in
// registration order. `/api/profile-deploy/image/<token>` is intentionally
// public -- token-gated for lane VMs that hold no JWT -- and would otherwise be
// claimed by the catch-all and rejected by its authenticateToken.
//
// ENROLLMENT BEFORE SCHEDULE, always. A student on no roster must be told that,
// not "access is only available Mon-Fri 08:00-17:00". It also makes
// checkSchedule's fail-open branch for a student in no group
// (middleware/schedule.js:31-33) defensible for the first time: "in no group"
// now means "enrolled, but no time window was set".
// ============================================================================

// Section rosters. CIAB-owned prefix, so gating here is correctly scoped.
router.use(
  '/api/instructor/sections/:sectionId/roster',
  authenticateToken, requireCiabAccess,
  (req, res, next) => { res.locals.sectionId = req.params.sectionId; next(); },
  sectionRosterRoutes
);

// Section modules. CIAB-owned prefix, so gating here is correctly scoped.
// Registered BEFORE the bare /api/instructor/sections mount for the same reason
// the roster is: Express matches router.use() prefixes in REGISTRATION ORDER,
// and sections.js owns the /:sectionId/... verbs this path sits under.
// No checkSchedule -- a staff surface, exactly like the two mounts around it.
router.use(
  '/api/instructor/sections/:sectionId/modules',
  authenticateToken, requireCiabAccess,
  (req, res, next) => { res.locals.sectionId = req.params.sectionId; next(); },
  sectionModuleRoutes
);
router.use('/api/instructor/sections', authenticateToken, requireCiabAccess, sectionRoutes);

router.use('/api/profiles', authenticateToken, requireCiabAccess, checkSchedule, profileRoutes);

// Admin-only, auth applied internally per route. MUST stay above the catch-all
// because /api/profile-deploy/image/:token is public. Deliberately NOT gated:
// that route has no req.user for the gate to read, and admins pass anyway.
router.use('/api/profile-deploy', checkSchedule, profileDeployRoutes);

// These three apply authenticateToken INTERNALLY, so a mount-level gate would
// run before req.user exists and 401 every request. The gate goes inside each
// file, one line after its own router.use(authenticateToken). Their mounts are
// CIAB-specific, so an internal router.use() is correctly scoped.
router.use('/api/intakes', checkSchedule, intakesRoutes);
router.use('/api/clinic-risk-assessment', checkSchedule, clinicRiskAssessmentRoutes);
router.use('/api/cis-ram', checkSchedule, cisRamRoutes);

// The catch-all. NO requireCiabAccess and NO checkSchedule here -- both would
// apply to the entire application. clinicApiRoutes gates its own five routes.
// authenticateToken stays because it predates this change and every route that
// falls through applies its own anyway.
router.use('/api', authenticateToken, clinicApiRoutes);

// CIAB-owned prefixes below the catch-all. They are reached because
// clinicApiRoutes calls next() when none of its five routes match.
// The blue-team board. /api/engagements is a CIAB-OWNED PREFIX, which is the
// only reason the full chain can be applied at the mount: the bare /api mount
// above matches every /api/* request in the application, so a gate there would
// close CLE's routes to a student on no CIAB roster. See that block's comment.
//
// Instructor sub-routes carry their own requireRole INSIDE the router -- there
// is no role gate here, so a handler that forgets one is open to every enrolled
// student. routes/incidents.js states that per route rather than by group.
router.use(
  '/api/engagements/:engagementId/incidents',
  authenticateToken, requireCiabAccess, checkSchedule,
  (req, res, next) => { res.locals.engagementId = req.params.engagementId; next(); },
  incidentRoutes
);

router.use('/api/progress', authenticateToken, requireCiabAccess, checkSchedule, progressRoutes);
router.use('/api/interview', authenticateToken, requireCiabAccess, checkSchedule, interviewRoutes);
// NOT gated: every route inside is requireRole('instructor','admin'), which is
// the right refusal for a student. The enrollment gate would answer "you are
// not enrolled" to somebody whose actual problem is that they are not staff.
router.use('/api/instructor', authenticateToken, instructorRoutes);
router.use('/api/intake-form', authenticateToken, requireCiabAccess, checkSchedule, intakeFormRoutes);
router.use('/api/real-client/intake', authenticateToken, requireCiabAccess, checkSchedule, realClientIntakeRoutes);

// ---------------------------------------------------------------------------
// BOOT SELF-CHECK
//
// migrations/008 creates the enrollment tables, and module-loader.js sends each
// .sql file as ONE query -- a single implicit transaction. So a failure there is
// all-or-nothing: ZERO tables, every gate throwing 42P01, and Clinic-in-a-Box
// down for every student. The loader only console.warn()s about it.
//
// Fail loudly at boot instead of one 503 at a time, and name the lever.
// ---------------------------------------------------------------------------
setTimeout(() => {
  const { query } = require('../utils/db');
  query('SELECT 1 FROM ciab_enrollment LIMIT 1')
    .then(() => console.log('[CIAB] ✓ enrollment tables present'))
    .catch((err) => {
      if (err.code === '42P01') {
        console.error(
          '[CIAB] ✗ enrollment tables missing — migration 008 did not run. '
          + 'Clinic-in-a-Box is now closed to students. Set CIAB_ENROLLMENT_ENFORCE=false '
          + 'and restart to restore access while you fix it.'
        );
      } else {
        console.warn(`[CIAB] enrollment self-check could not run: ${err.message}`);
      }
    });
// The pool is injected by the plugin loader AFTER this file is required, so the
// check has to wait for the current tick to finish.
}, 5000).unref?.();

module.exports = router;
