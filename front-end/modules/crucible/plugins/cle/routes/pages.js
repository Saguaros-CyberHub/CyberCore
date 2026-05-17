/**
 * CLE Plugin — Page Routes
 * Serves HTML pages under /cle/*
 */

const express = require('express');
const path = require('path');
const router = express.Router();

const PAGES_DIR = path.join(__dirname, '../public/pages');

const pages = {
  '/dashboard': 'dashboard.html',
  '/courses':   'courses.html',
  '/students':  'students.html',
  '/sessions':  'sessions.html'
};

Object.entries(pages).forEach(([route, file]) => {
  router.get(route, (req, res) => {
    res.sendFile(path.join(PAGES_DIR, file));
  });
});

module.exports = router;
