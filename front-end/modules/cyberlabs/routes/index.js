/**
 * CyberLabs Routes
 * On-demand virtualization module API endpoints
 */
const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

router.get('/', authenticateToken, async (req, res) => {
  res.json({success: true, message: 'CyberLabs module is active', userId: req.user.userId});
});

module.exports = router;
