const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

// GET /api/modules/library
router.get('/', authenticateToken, (req, res) => {
  res.json({ message: 'Library module' });
});

module.exports = router;
