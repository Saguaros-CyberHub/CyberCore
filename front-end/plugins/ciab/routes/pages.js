/**
 * CIAB Plugin — Page Routes
 * Serves HTML pages under /ciab/*
 */

const express = require('express');
const path = require('path');
const router = express.Router();

const PAGES_DIR = path.join(__dirname, '../public/pages');

const pages = {
  '/dashboard':   'dashboard.html',
  '/my-profiles': 'profiles.html',
  '/generator':   'generator.html',
  '/workspace':   'workspace.html',
  '/progress':    'progress.html',
  '/interview':   'interview.html',
  '/instructor':  'instructor.html',
  '/admin':       'admin.html',
  '/intake-form': 'intake-form.html',
  '/guide':       'guide.html',
  '/nice-framework': 'nice-framework.html',
  '/real-client-intake':        'real-client-intake.html',
  '/real-client-intakes':       'real-client-intakes.html',
};

// Dynamic page route for viewing a specific real-client intake
router.get('/real-client-intake/:id', (req, res) => {
  res.sendFile(path.join(PAGES_DIR, 'real-client-intake-detail.html'));
});

Object.entries(pages).forEach(([route, file]) => {
  router.get(route, (req, res) => {
    res.sendFile(path.join(PAGES_DIR, file));
  });
});

module.exports = router;
