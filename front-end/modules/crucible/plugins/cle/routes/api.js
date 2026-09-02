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
const incidentRoutes = require('./incidents');
const { requireCourseFeature } = require('../utils/course-features');

// The support ticket form has to offer a student the courses they are enrolled
// in, but tickets live in cybercore_db and courses live in cle_db — there is no
// join to make. Core therefore states the QUESTION and this plugin registers the
// ANSWER, the same inversion CIAB uses for its sidebar access gate a few lines
// down from here in ciab/routes/api.js.
//
// Registered from a route file rather than from the loader because that is what
// the loader require()s AFTER provisionDatabase() has injected this plugin's
// pool; a require at loader time would install a provider whose every call
// throws 'CLE database pool not initialized'.
//
// Non-fatal: core degrades to an empty course list, so a failure here costs the
// ticket form its dropdown, not the ability to file a ticket.
try {
  require('../../../../../src/utils/course-directory')
    .registerCourseDirectory(require('../utils/course-directory-provider'));
} catch (err) {
  console.warn('[CLE] Could not register the course directory:', err.message);
}

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

// The blue-team board, the defensive sibling of the attack console. Mounted
// beside /attacks and, like it, NOT gated at the mount: the blue_team feature
// gate is applied per WRITE inside the router, so a course that later disables
// the tab keeps its students' graded submissions readable. See that file's
// header, note 3 -- findings are graded work, and a feature checkbox must not
// make a student's own work unreachable.
router.use('/api/cle/courses/:courseId/incidents', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, incidentRoutes);

// Gated at the mount rather than in the handler so the whole router is covered
// by one check. Unlike the attack console there is no in-flight work to strand:
// this router is read-only reporting, so turning Flags off can close all of it.
router.use('/api/cle/courses/:courseId/flags', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  next();
}, requireCourseFeature('flags'), flagRoutes);

router.use('/api/cle/courses/:courseId/students/:studentId/guac', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  res.locals.studentId = req.params.studentId;
  next();
}, guacamoleRoutes);

module.exports = router;
