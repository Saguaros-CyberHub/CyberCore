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
const guacamoleRoutes = require('./guacamole');
const templatesRoutes = require('./templates');
const studentRoutes = require('./students');
const sessionRoutes = require('./sessions');

// Global routes
router.use('/api/cle/templates', authenticateToken, templatesRoutes);
router.use('/api/cle/students', authenticateToken, instructorOnly, studentRoutes);
router.use('/api/cle/sessions', authenticateToken, instructorOnly, sessionRoutes);

// Courses main route
router.use('/api/cle/courses', authenticateToken, coursesRoutes);

// Nested course resources - use a middleware to pass courseId to nested routers
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

router.use('/api/cle/courses/:courseId/students/:studentId/guac', authenticateToken, (req, res, next) => {
  res.locals.courseId = req.params.courseId;
  res.locals.studentId = req.params.studentId;
  next();
}, guacamoleRoutes);

module.exports = router;
