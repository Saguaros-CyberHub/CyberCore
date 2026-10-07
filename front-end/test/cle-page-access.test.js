/**
 * cle-page-access.test.js — who may load the CLE instructor pages.
 *
 * /cle/dashboard, /cle/courses, /cle/students and /cle/sessions used to be
 * served to anyone at all, including unauthenticated requests. The only real
 * gate was the 403s the /api/cle/* routes returned once the page was already
 * open, so a student who found the link got a rendered shell in which every
 * panel said "Access denied".
 *
 * The pages are now gated themselves, and they REDIRECT rather than returning
 * requireRole()'s JSON 403 — these are browser navigations, not API calls, and
 * a raw JSON error body in the window is its own dead end.
 *
 * Run: node front-end/test/cle-page-access.test.js   (or npm test)
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'cle-page-access-test-secret';

const { test, before, after } = require('node:test');
const assert = require('assert');
const http = require('http');
const path = require('path');
const express = require('express');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const pagesRouter = require(
  path.join(__dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'pages')
);

const GATED_PAGES = ['/cle/dashboard', '/cle/courses', '/cle/students', '/cle/sessions'];

let server, port;

before(async () => {
  const app = express();
  app.use(cookieParser());
  app.use('/cle', pagesRouter);
  server = http.createServer(app);
  await new Promise(resolve => server.listen(0, resolve));
  port = server.address().port;
});

after(() => server && server.close());

const tokenFor = role => jwt.sign({ sub: 'u1', email: 'a@b.c', role }, process.env.JWT_SECRET, { expiresIn: '1h' });

/** GET a page, optionally as a bearer token or a cookie. */
function fetchPage(pagePath, { bearer = null, cookie = null } = {}) {
  const headers = {};
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  if (cookie) headers.Cookie = `token=${cookie}`;
  return new Promise((resolve, reject) => {
    const req = http.get({ port, path: pagePath, headers }, res => {
      res.resume();
      res.on('end', () => resolve({ status: res.statusCode, location: res.headers.location }));
    });
    req.on('error', reject);
  });
}

test('an anonymous visitor is sent to the login page', async () => {
  for (const page of GATED_PAGES) {
    const res = await fetchPage(page);
    assert.strictEqual(res.status, 302, `${page} should redirect`);
    assert.strictEqual(res.location, '/login', `${page} should point at /login`);
  }
});

test('a student is sent back to the hub, not shown a 403 body', async () => {
  const token = tokenFor('student');
  for (const page of GATED_PAGES) {
    const res = await fetchPage(page, { bearer: token });
    assert.strictEqual(res.status, 302, `${page} should redirect a student`);
    assert.strictEqual(res.location, '/hub');
  }
});

test('an instructor gets the page', async () => {
  const res = await fetchPage('/cle/dashboard', { bearer: tokenFor('instructor') });
  assert.strictEqual(res.status, 200);
});

test('an admin gets the page', async () => {
  const res = await fetchPage('/cle/dashboard', { bearer: tokenFor('admin') });
  assert.strictEqual(res.status, 200);
});

test('the cookie session is honoured, not just the Authorization header', async () => {
  // The hub signs users in with both; page navigations only carry the cookie.
  const res = await fetchPage('/cle/dashboard', { cookie: tokenFor('instructor') });
  assert.strictEqual(res.status, 200);
});

test('a half-finished sign-in cannot reach the pages', async () => {
  // A stage token proves one step of MFA / a forced password change. optionalAuth
  // refuses to treat it as a user, so this must land on /login.
  const stageToken = jwt.sign(
    { sub: 'u1', email: 'a@b.c', role: 'instructor', stage: 'mfa' },
    process.env.JWT_SECRET, { expiresIn: '1h' }
  );
  const res = await fetchPage('/cle/dashboard', { bearer: stageToken });
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.location, '/login');
});

test('a token signed with the wrong secret is rejected', async () => {
  const forged = jwt.sign({ sub: 'u1', role: 'admin' }, 'not-the-real-secret', { expiresIn: '1h' });
  const res = await fetchPage('/cle/dashboard', { bearer: forged });
  assert.strictEqual(res.status, 302);
  assert.strictEqual(res.location, '/login');
});
