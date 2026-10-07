/**
 * CLE Plugin — Page Routes
 * Serves HTML pages under /cle/*
 *
 * These pages are instructor tooling. They used to be served to anyone —
 * including unauthenticated requests — with the only real gate being the 403s
 * the /api/cle/* routes returned once the page was already open. A student who
 * found the link got a rendered shell full of "Access denied", which is exactly
 * the kind of dead end that made the platform confusing to navigate.
 *
 * Gate the pages themselves, and redirect rather than returning requireRole's
 * JSON 403 — this is a browser navigation, not an API call.
 */

const express = require('express');
const path = require('path');
const router = express.Router();

// optionalAuth, not authenticate: authenticate() answers with its own JSON 401,
// which is the wrong response to a browser navigation. optionalAuth populates
// req.user when a valid token is present and otherwise just continues, leaving
// us free to redirect.
const { optionalAuth } = require('../../../../../src/middleware/auth');

const PAGES_DIR = path.join(__dirname, '../public/pages');

const pages = {
  '/dashboard': 'dashboard.html',
  '/courses':   'courses.html',
  '/students':  'students.html',
  '/sessions':  'sessions.html'
};

// Send un-authenticated visitors to the login page and non-instructors back to
// the hub, instead of a raw JSON error body in the browser window.
function requireInstructorPage(req, res, next) {
  if (!req.user) return res.redirect('/login');
  if (req.user.role !== 'instructor' && req.user.role !== 'admin') {
    return res.redirect('/hub');
  }
  next();
}

Object.entries(pages).forEach(([route, file]) => {
  router.get(route, optionalAuth, requireInstructorPage, (req, res) => {
    res.sendFile(path.join(PAGES_DIR, file));
  });
});

module.exports = router;
