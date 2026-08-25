/**
 * CIAB Plugin — Page Routes
 * Serves HTML pages under /ciab/*
 *
 * These pages used to be served to ANYONE, unauthenticated included: this file
 * registered plain router.get(route, handler) with no middleware at all, so
 * /ciab/instructor and /ciab/admin-profile-lanes returned their full shell to
 * a stranger and the only gate was a client-side Auth.isRealInstructor()
 * redirect the page ran on itself.
 *
 * Gate the pages themselves, and REDIRECT rather than returning requireRole's
 * JSON 403 — these are browser navigations, not API calls, and a raw JSON error
 * body in the window is its own dead end. Same shape, same reasoning and the
 * same redirect targets as cle/routes/pages.js.
 */

const express = require('express');
const path = require('path');
const router = express.Router();

// optionalAuth, not authenticate: authenticate() answers with its own JSON 401,
// which is the wrong response to a browser navigation. optionalAuth populates
// req.user when a valid token is present and otherwise just continues, leaving
// us free to redirect.
const { optionalAuth } = require('../../../../../src/middleware/auth');
const { requireCiabPage } = require('../utils/enrollment');

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

// ---------------------------------------------------------------------------
// TIER 0 — PUBLIC. No gate, deliberately.
//
// real-client-intake.html loads NEITHER app.js NOR layout.js. Its own header
// says so: "DO NOT add external <script src> or <link href> tags — this file
// must run" standalone. It keeps answers in localStorage and offers "Download
// JSON" / "Download filled form (HTML)", because it is meant to be handed to an
// outside client who has no account and filled in offline.
//
// Everything it can POST to already requires a JWT, so an anonymous visitor can
// only fill-and-download. Gating it would break the intended workflow and
// protect nothing: the page ships no data.
// ---------------------------------------------------------------------------
const publicPages = {
  '/intake':             'real-client-intake.html',
  '/real-client-intake': 'real-client-intake.html',
};

// ---------------------------------------------------------------------------
// TIER 1 — STUDENT. Needs an active enrollment on an active section.
// ---------------------------------------------------------------------------
const studentPages = {
  '/dashboard':           'dashboard.html',
  '/generator':           'generator.html',
  '/workspace':           'workspace.html',
  '/progress':            'progress.html',
  '/interview':           'interview.html',
  '/intake-form':         'intake-form.html',
  '/guide':               'guide.html',
  '/nice-framework':      'nice-framework.html',
  '/real-client-intakes': 'real-client-intakes.html',
};

// ---------------------------------------------------------------------------
// TIER 2 — INSTRUCTOR.
// ---------------------------------------------------------------------------
const instructorPages = {
  '/instructor': 'instructor.html',
};

// ---------------------------------------------------------------------------
// TIER 3 — ADMIN.
// ---------------------------------------------------------------------------
const adminPages = {
  '/admin-profile-lanes': 'admin-profile-lanes.html',
};

const register = (pages, tier) => {
  Object.entries(pages).forEach(([route, file]) => {
    const chain = tier
      ? [optionalAuth, requireCiabPage(tier)]
      : [];
    router.get(route, ...chain, (req, res) => sendHtmlNoCache(res, file));
  });
};

register(publicPages, null);
register(studentPages, 'student');
register(instructorPages, 'instructor');
register(adminPages, 'admin');

// ---------------------------------------------------------------------------
// Dynamic routes. Registered after the static maps so the exact paths above
// win, and /synthesize before the bare /:id so the more specific one matches.
// ---------------------------------------------------------------------------

// Instructor tier: this page drives POST /api/real-client/intake/:id/
// synthesize-challenge, which builds VM specs from an intake.
router.get('/real-client-intake/:id/synthesize', optionalAuth, requireCiabPage('instructor'), (req, res) => {
  sendHtmlNoCache(res, 'real-client-intake-synthesize.html');
});

router.get('/real-client-intake/:id', optionalAuth, requireCiabPage('student'), (req, res) => {
  sendHtmlNoCache(res, 'real-client-intake-detail.html');
});

// Clinic Risk Assessment — single-page app, profileId in path
router.get('/clinic-risk-assessment/:profileId/report', optionalAuth, requireCiabPage('student'), (req, res) => {
  // Standalone print-ready HTML report (opens in new tab)
  sendHtmlNoCache(res, 'clinic-risk-report.html');
});
router.get('/clinic-risk-assessment/:profileId', optionalAuth, requireCiabPage('student'), (req, res) => {
  sendHtmlNoCache(res, 'clinic-risk-assessment.html');
});
router.get('/clinic-risk-assessment', optionalAuth, requireCiabPage('student'), (req, res) => {
  sendHtmlNoCache(res, 'clinic-risk-assessment.html');
});

module.exports = router;
