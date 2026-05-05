/**
 * Forge Routes
 * Malware analysis and sandbox module API endpoints
 */
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

router.get('/', authenticateToken, async (req, res) => {
  res.json({success: true, message: 'Forge module is active', userId: req.user.userId});
});

module.exports = router;
