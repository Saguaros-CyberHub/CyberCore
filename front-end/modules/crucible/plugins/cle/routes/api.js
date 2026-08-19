/**
 * CLE Plugin — API Route Aggregator
 * Mounts all CLE API sub-routers. Mounted at "/" by plugin loader,
 * so endpoints appear at /api/cle/*.
 */

const express = require('express');
const router = express.Router();

const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');
const instructorOnly = requireRole('instructor', 'admin');

// CLE route modules
const coursesRoutes = require('./courses');
const courseStudentsRoutes = require('./course-students');
const vmsRoutes = require('./vms');
const labsRoutes = require('./labs');
const attacksRoutes = require('./attacks');
const guacamoleRoutes = require('./guacamole');
const templatesRoutes = require('./templates');
const studentRoutes = require('./students');
const sessionRoutes = require('./sessions');
const flagRoutes = require('./flags');
const myCoursesRoutes = require('./my-courses');
const courseRosterRoutes = require('./course-roster');

// Student-facing: enrolled courses + their capture-flag boards. No role gate —
// every route inside scopes to req.user.userId and checks enrollment itself.
router.use('/api/cle/my', authenticateToken, myCoursesRoutes);

// Global routes
router.use('/api/cle/templates', authenticateToken, templatesRoutes);
router.use('/api/cle/students', authenticateToken, instructorOnly, studentRoutes);
router.use('/api/cle/sessions', authenticateToken, instructorOnly, sessionRoutes);

// Courses main route
router.use('/api/cle/courses', authenticateToken, coursesRoutes);

// Nested course resources - use a middleware to pass courseId to nested routers
// Bulk roster operations (CSV import, cohort generation, per-student credential
// actions). Mounted BEFORE /students so it cannot collide with that router's
// /:studentId routes.
router.use('/api/cle/courses/:courseId/roster', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, courseRosterRoutes);

router.use('/api/cle/courses/:courseId/students', authenticateToken, (req, res, next) => {
  // Store courseId from params for nested router access
  res.locals.courseId = req.params.courseId;
  next();
}, courseStudentsRoutes);

router.use('/api/cle/courses/:courseId/vms', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, vmsRoutes);

router.use('/api/cle/courses/:courseId/labs', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, labsRoutes);

// CYBR 400 attack console. Mounted after /labs so the two never contend for a
// path; both use the same res.locals shim for the nested router.
router.use('/api/cle/courses/:courseId/attacks', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, attacksRoutes);

router.use('/api/cle/courses/:courseId/flags', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, flagRoutes);

router.use('/api/cle/courses/:courseId/students/:studentId/guac', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  res.locals.studentId = req.params.studentId;
  next();
}, guacamoleRoutes);

module.exports = router;
