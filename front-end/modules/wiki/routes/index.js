const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

// GET /api/modules/wiki
router.get('/', authenticateToken, (req, res) => {
  res.json({ message: 'Wiki module' });
});

module.exports = router;
