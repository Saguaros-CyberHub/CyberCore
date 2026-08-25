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

// Mount with auth + enrollment + schedule checking.
//
// IMPORTANT — ordering: any router that has unauthenticated routes (auth
// applied internally / per-route) MUST be mounted BEFORE the `/api` catch-all
// at line ~ below. Express matches router.use() prefixes in registration
// order, so a request to `/api/profile-deploy/image/<token>` will be claimed
// by the `/api` mount and rejected by its authenticateToken middleware before
// the `/api/profile-deploy` mount ever gets a turn. The image route is
// intentionally public (token-gated for lane VMs that have no JWT) — keep
// these specific-prefix mounts above the catch-all.
//
// ENROLLMENT — requireCiabAccess always runs BEFORE checkSchedule. Two reasons:
// a student on no roster must be told that, not "access is only available
// Mon–Fri 08:00–17:00"; and checkSchedule's fail-open branch for a student in
// no group (middleware/schedule.js:31-33) is only defensible with this gate in
// front of it, because "in no group" then means "enrolled, but no time window
// was set" rather than "nobody has ever checked".

// Section rosters. Above the `/api` catch-all for the same reason
// /api/profile-deploy is: Express matches router.use() prefixes in
// registration order. The /roster mount is a sibling of /sections rather than
// nested inside it so its verbs never contend with the /:userId routes there.
router.use(
  '/api/instructor/sections/:sectionId/roster',
  authenticateToken, requireCiabAccess,
  (req, res, next) => { res.locals.sectionId = req.params.sectionId; next(); },
  sectionRosterRoutes
);
router.use('/api/instructor/sections', authenticateToken, requireCiabAccess, sectionRoutes);

router.use('/api/profiles', authenticateToken, requireCiabAccess, checkSchedule, profileRoutes);
// Admin-only: deploy N cybercore lanes from a single CIAB profile. Auth
// applied internally per-route. MUST be above the `/api` catch-all because
// the lane image-pull endpoint here (`/api/profile-deploy/image/:token`) is
// public + token-gated for lane web VMs.
//
// Deliberately NOT gated: that public route has no req.user for the gate to
// read, and every other route in the file is already adminOnly — and admins
// pass the gate regardless, so nothing is lost by leaving it off.
router.use('/api/profile-deploy', checkSchedule, profileDeployRoutes);
// These three apply authenticateToken INTERNALLY (a router.use at the top of
// each file), so a mount-level gate here would run before req.user exists and
// 401 every request. The gate goes inside each file instead, one line after its
// own router.use(authenticateToken).
router.use('/api/intakes', checkSchedule, intakesRoutes);
router.use('/api/clinic-risk-assessment', checkSchedule, clinicRiskAssessmentRoutes);
router.use('/api/cis-ram', checkSchedule, cisRamRoutes);
// The catch-all — every path under /api/* that wasn't claimed above gets auth.
// It also covers the five specific mounts below it: Express runs this chain
// first and clinicApiRoutes calls next() when no route matches, so adding the
// enrollment gate here gates /api/progress, /api/interview, /api/instructor,
// /api/intake-form and /api/real-client/intake for free.
router.use('/api', authenticateToken, requireCiabAccess, checkSchedule, clinicApiRoutes);
router.use('/api/progress', authenticateToken, checkSchedule, progressRoutes);
router.use('/api/interview', authenticateToken, checkSchedule, interviewRoutes);
router.use('/api/instructor', authenticateToken, instructorRoutes);
router.use('/api/intake-form', authenticateToken, checkSchedule, intakeFormRoutes);
router.use('/api/real-client/intake', authenticateToken, checkSchedule, realClientIntakeRoutes);

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
