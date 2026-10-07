const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

// GET /api/modules/archive
router.get('/', authenticateToken, (req, res) => {
  res.json({ message: 'The Archive module' });
});

module.exports = router;
