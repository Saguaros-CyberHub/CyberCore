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

// Mount with auth + schedule checking
router.use('/api/profiles', authenticateToken, checkSchedule, profileRoutes);
router.use('/api', authenticateToken, checkSchedule, clinicApiRoutes);
router.use('/api/progress', authenticateToken, checkSchedule, progressRoutes);
router.use('/api/interview', authenticateToken, checkSchedule, interviewRoutes);
router.use('/api/instructor', authenticateToken, instructorRoutes);
router.use('/api/intake-form', authenticateToken, checkSchedule, intakeFormRoutes);
router.use('/api/real-client/intake', authenticateToken, checkSchedule, realClientIntakeRoutes);
// Unified intakes API (Phase 0). intakesRoutes applies authenticateToken internally.
router.use('/api/intakes', checkSchedule, intakesRoutes);

module.exports = router;
