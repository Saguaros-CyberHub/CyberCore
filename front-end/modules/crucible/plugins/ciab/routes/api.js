/**
 * CIAB Plugin — API Route Aggregator
 * Mounts all CIAB API sub-routers at their existing paths.
 * This router is mounted at "/" by the plugin loader, so
 * /api/profiles, /api/progress, etc. stay at their current URLs.
 */

const express = require('express');
const router = express.Router();

const { authenticateToken } = require('../../../../../src/middleware/auth');

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

// Mount with auth + schedule checking.
//
// IMPORTANT — ordering: any router that has unauthenticated routes (auth
// applied internally / per-route) MUST be mounted BEFORE the `/api` catch-all
// at line ~ below. Express matches router.use() prefixes in registration
// order, so a request to `/api/profile-deploy/image/<token>` will be claimed
// by the `/api` mount and rejected by its authenticateToken middleware before
// the `/api/profile-deploy` mount ever gets a turn. The image route is
// intentionally public (token-gated for lane VMs that have no JWT) — keep
// these specific-prefix mounts above the catch-all.
router.use('/api/profiles', authenticateToken, checkSchedule, profileRoutes);
// Admin-only: deploy N cybercore lanes from a single CIAB profile. Auth
// applied internally per-route. MUST be above the `/api` catch-all because
// the lane image-pull endpoint here (`/api/profile-deploy/image/:token`) is
// public + token-gated for lane web VMs.
router.use('/api/profile-deploy', checkSchedule, profileDeployRoutes);
// Unified intakes API (Phase 0). intakesRoutes applies authenticateToken internally.
router.use('/api/intakes', checkSchedule, intakesRoutes);
// Clinic Risk Assessment API (Phase 1). Auth applied internally.
router.use('/api/clinic-risk-assessment', checkSchedule, clinicRiskAssessmentRoutes);
// CIS RAM Workbook API (Phase 2). Auth applied internally.
router.use('/api/cis-ram', checkSchedule, cisRamRoutes);
// The catch-all — every path under /api/* that wasn't claimed above gets auth.
router.use('/api', authenticateToken, checkSchedule, clinicApiRoutes);
router.use('/api/progress', authenticateToken, checkSchedule, progressRoutes);
router.use('/api/interview', authenticateToken, checkSchedule, interviewRoutes);
router.use('/api/instructor', authenticateToken, instructorRoutes);
router.use('/api/intake-form', authenticateToken, checkSchedule, intakeFormRoutes);
router.use('/api/real-client/intake', authenticateToken, checkSchedule, realClientIntakeRoutes);

module.exports = router;
