/**
 * CLE Plugin — API Route Aggregator
 * Mounts CLE API sub-routers. Mounted at "/" by plugin loader,
 * so endpoints appear at /api/cle/*.
 */

const express = require('express');
const router = express.Router();

const { authenticateToken, requireRole } = require('../../../../../src/middleware/auth');

const instructorOnly = requireRole('instructor', 'admin');

const studentRoutes = require('./students');
const sessionRoutes = require('./sessions');

router.use('/api/cle/students', authenticateToken, instructorOnly, studentRoutes);
router.use('/api/cle/sessions', authenticateToken, instructorOnly, sessionRoutes);

module.exports = router;
