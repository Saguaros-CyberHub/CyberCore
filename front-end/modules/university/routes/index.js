const express = require('express');
const router = express.Router();
const { authenticateToken } = require('../../../src/middleware/auth');

// GET /api/modules/university
router.get('/', authenticateToken, (req, res) => {
  res.json({ message: 'University module' });
});

module.exports = router;
