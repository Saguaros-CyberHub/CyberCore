const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

// GET /api/modules/cyberwiki
router.get('/', authenticateToken, (req, res) => {
  res.json({ message: 'CyberWiki module' });
});

module.exports = router;
