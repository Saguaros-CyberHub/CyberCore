/**
 * ============================================================================
 * SESSION COOKIE SCOPE
 * ============================================================================
 * A cookie with no `domain` is HOST-ONLY. That is the right default, and it is
 * also what made the Caldera authoring console return a bare "HTTP ERROR 401":
 * the console is served on its own hostname (its SPA requests /api/v2/* from the
 * origin root, so it cannot live under a path), Caddy's forward_auth asks this
 * app to authorise each request, and the browser never sent the session cookie
 * to the subdomain — so the app correctly answered 401 with nothing wrong in any
 * log.
 *
 * COOKIE_DOMAIN opts into a parent-domain cookie. These tests pin the two
 * properties that make it safe to use and safe to leave unset.
 * ============================================================================
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const AUTH = path.join(__dirname, '..', 'src', 'routes', 'auth.js');
const src = fs.readFileSync(AUTH, 'utf8');

test('the session cookie only gains a domain when COOKIE_DOMAIN is set', () => {
  assert.match(
    src, /function sessionCookieOptions\s*\(/,
    'the set and the clear must share one options builder, or they drift'
  );
  assert.match(
    src, /const domain = \(process\.env\.COOKIE_DOMAIN \|\| ''\)\.trim\(\);\s*\n\s*if \(domain\) opts\.domain = domain;/,
    'COOKIE_DOMAIN must be opt-in: an empty or unset value has to leave the cookie HOST-ONLY, '
    + 'which is the pre-existing behaviour and the safer default'
  );
});

test('logout clears with the SAME options it set', () => {
  // A clearCookie whose domain/path differ from the set removes nothing. The
  // browser keeps the session, logout appears to succeed, and the user stays
  // logged in — which is a security bug, not a cosmetic one.
  assert.match(
    src, /res\.clearCookie\('token', sessionCookieOptions\(\)\)/,
    "logout must call res.clearCookie('token', sessionCookieOptions()) — a bare clearCookie('token') "
    + 'cannot remove a cookie that was set with a domain'
  );
  assert.ok(
    !/res\.clearCookie\('token'\s*\)/.test(src),
    'a bare clearCookie(\'token\') remains somewhere; it will not clear a domain-scoped cookie'
  );
});

test('the cookie stays httpOnly and keeps its sameSite policy', () => {
  const m = src.match(/function sessionCookieOptions[\s\S]*?\n}/);
  assert.ok(m, 'sessionCookieOptions not found');
  assert.match(m[0], /httpOnly:\s*true/, 'the session cookie must stay httpOnly');
  assert.match(m[0], /sameSite:\s*'lax'/, "sameSite 'lax' is what still allows the top-level navigation to the console subdomain");
});
