/**
 * CIAB Plugin — Page Routes
 * Serves HTML pages under /ciab/*
 */

const express = require('express');
const path = require('path');
const router = express.Router();

const PAGES_DIR = path.join(__dirname, '../public/pages');

// HTML pages must NEVER be cached aggressively — otherwise a fix to inline
// page JS (e.g. the generator's progress poller) silently fails to reach
// users still holding a 304-able copy from a previous deploy. ETag-based
// revalidation is also disabled because some upstream proxies / browsers
// will skip the conditional GET when storage is fine.
function sendHtmlNoCache(res, file) {
  res.set('Cache-Control', 'no-cache, no-store, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(PAGES_DIR, file), { etag: false, lastModified: false });
}

const pages = {
  '/dashboard':   'dashboard.html',
  '/my-profiles': 'profiles.html',
  '/generator':   'generator.html',
  '/workspace':   'workspace.html',
  '/progress':    'progress.html',
  '/interview':   'interview.html',
  '/instructor':  'instructor.html',
  '/intake-form': 'intake-form.html',
  '/intake':      'real-client-intake.html', // Unified form (Phase 0). Dual-mode: ?profileId=X auto-saves; no param = standalone upload.
  '/guide':       'guide.html',
  '/nice-framework': 'nice-framework.html',
  '/real-client-intake':        'real-client-intake.html',
  '/real-client-intakes':       'real-client-intakes.html',
  '/admin-profile-lanes':       'admin-profile-lanes.html',
};

// Dynamic page route for viewing a specific real-client intake
router.get('/real-client-intake/:id', (req, res) => {
  sendHtmlNoCache(res, 'real-client-intake-detail.html');
});

// Clinic Risk Assessment — single-page app, profileId in path
router.get('/clinic-risk-assessment/:profileId/report', (req, res) => {
  // Standalone print-ready HTML report (opens in new tab)
  sendHtmlNoCache(res, 'clinic-risk-report.html');
});
router.get('/clinic-risk-assessment/:profileId', (req, res) => {
  sendHtmlNoCache(res, 'clinic-risk-assessment.html');
});
router.get('/clinic-risk-assessment', (req, res) => {
  sendHtmlNoCache(res, 'clinic-risk-assessment.html');
});

// Dynamic page route for the synthesize-challenge review page
router.get('/real-client-intake/:id/synthesize', (req, res) => {
  sendHtmlNoCache(res, 'real-client-intake-synthesize.html');
});

Object.entries(pages).forEach(([route, file]) => {
  router.get(route, (req, res) => {
    sendHtmlNoCache(res, file);
  });
});

module.exports = router;
