const express = require('express');
const path = require('path');
const router = express.Router();

const PAGES_DIR = path.join(__dirname, '../public/pages');

router.get('/dashboard', (req, res) => {
  res.sendFile(path.join(PAGES_DIR, 'dashboard.html'));
});

module.exports = router;
