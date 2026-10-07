/**
 * Regenerates caldera-sso-vectors.json — the cross-language agreement fixture.
 *
 *     node front-end/test/fixtures/caldera-sso-vectors.gen.js
 *
 * NOT A TEST, and deliberately not named *.test.js so `npm test` (which globs
 * test/*.test.js) never runs it. Committed because the fixture is otherwise a
 * wall of opaque base64 that nobody can extend, and an unextendable fixture is
 * one that quietly stops covering new cases.
 *
 * WHEN TO RUN IT
 * Only on a DELIBERATE change to the token contract in
 * src/utils/caldera-sso.js. The vectors are the sole automated proof that the
 * Node minter and infrastructure/caldera/login_handler.py agree; regenerating
 * them to make a red test go green converts that proof into a tautology. If a
 * vector fails, the right question is which of the two sides is wrong.
 *
 * The secret here is a TEST secret and nothing else. It is in the repository on
 * purpose — a fixture that needed a real key could not be committed, and these
 * tokens authorise nothing anywhere.
 */

'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..', '..');
const sso = require(path.join(ROOT, 'src', 'utils', 'caldera-sso.js'));

const SECRET = 'cybercore-caldera-sso-vector-secret-0123456789';
const NOW = 1767225600; // 2026-01-01T00:00:00Z — frozen, so tokens are stable.
const env = { CALDERA_SSO_SECRET: SECRET };

const b64 = (b) => Buffer.from(b).toString('base64url');

/**
 * Sign an arbitrary payload with the test key.
 *
 * The forger's BEST case: several cases below need a token that is perfectly
 * signed and still wrong (role "student", a missing claim, a non-hex jti).
 * mintToken refuses to build those by design, which is itself a control — so
 * they are hand-signed here instead.
 */
function handSign(payloadObj) {
  const p = b64(Buffer.from(JSON.stringify(payloadObj), 'utf8'));
  const si = `v1.${p}`;
  const mac = crypto.createHmac('sha256', Buffer.from(SECRET, 'utf8')).update(si, 'ascii').digest();
  return `${si}.${b64(mac)}`;
}

const INSTRUCTOR_JTI = '0123456789abcdef0123456789abcdef';
const ADMIN_JTI = 'fedcba9876543210fedcba9876543210';

const valid = sso.mintToken(
  { sub: '11111111-1111-1111-1111-111111111111', role: 'instructor', path: '/caldera' },
  { env, now: NOW, jti: INSTRUCTOR_JTI }
);
const validAdmin = sso.mintToken(
  { sub: '22222222-2222-2222-2222-222222222222', role: 'admin', path: '/caldera' },
  { env, now: NOW, jti: ADMIN_JTI }
);

const [, vPayload, vMac] = valid.split('.');

// The escalation attempt: rewrite role to admin, keep the original MAC.
const escalated = JSON.parse(Buffer.from(vPayload, 'base64url').toString('utf8'));
escalated.role = 'admin';
const tamperedPayload = `v1.${b64(Buffer.from(JSON.stringify(escalated), 'utf8'))}.${vMac}`;

const flip = (c) => (c === 'A' ? 'B' : 'A');
const tamperedMac = `v1.${vPayload}.${vMac.slice(0, -1)}${flip(vMac.slice(-1))}`;

const base = { sub: 'u', path: '/caldera', exp: NOW + 60, jti: INSTRUCTOR_JTI };

const cases = [
  { name: 'a valid instructor token verifies', token: valid, request_path: '/caldera/', verify_at: NOW + 1, expect: 'ok',
    payload: { sub: '11111111-1111-1111-1111-111111111111', role: 'instructor', path: '/caldera', exp: NOW + 60, jti: INSTRUCTOR_JTI } },
  { name: 'a valid admin token verifies on a deep path', token: validAdmin, request_path: '/caldera/api/v2/abilities', verify_at: NOW + 30, expect: 'ok',
    payload: { sub: '22222222-2222-2222-2222-222222222222', role: 'admin', path: '/caldera', exp: NOW + 60, jti: ADMIN_JTI } },
  { name: 'a tampered payload (role escalated to admin) fails', token: tamperedPayload, request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_signature' },
  { name: 'a tampered MAC fails', token: tamperedMac, request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_signature' },
  { name: 'a truncated token fails', token: valid.split('.').slice(0, 2).join('.'), request_path: '/caldera/', verify_at: NOW + 1, expect: 'malformed' },
  { name: 'an empty token fails', token: '', request_path: '/caldera/', verify_at: NOW + 1, expect: 'malformed' },
  { name: 'an expired token fails one second past exp', token: valid, request_path: '/caldera/', verify_at: NOW + 61, expect: 'expired' },
  { name: 'exp is exclusive — exactly at exp is already expired', token: valid, request_path: '/caldera/', verify_at: NOW + 60, expect: 'expired' },
  { name: 'role "student" fails even with a perfect signature', token: handSign({ ...base, role: 'student' }), request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_role' },
  { name: 'a missing role fails', token: handSign({ sub: 'u', path: '/caldera', exp: NOW + 60, jti: INSTRUCTOR_JTI }), request_path: '/caldera/', verify_at: NOW + 1, expect: 'missing_claim' },
  { name: 'a path mismatch fails', token: valid, request_path: '/caldera-admin/steal', verify_at: NOW + 1, expect: 'path_mismatch' },
  { name: 'a sibling prefix is not a match (/calderaX)', token: valid, request_path: '/calderaX', verify_at: NOW + 1, expect: 'path_mismatch' },
  { name: 'an unknown version fails before anything else', token: `v2.${vPayload}.${vMac}`, request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_version' },
  { name: 'padded base64url is not canonical and fails', token: `v1.${vPayload}=.${vMac}`, request_path: '/caldera/', verify_at: NOW + 1, expect: 'malformed' },
  { name: 'a non-hex jti fails', token: handSign({ ...base, role: 'admin', jti: 'not-hex-not-hex-not-hex-not-hexx' }), request_path: '/caldera/', verify_at: NOW + 1, expect: 'malformed' },
  { name: 'a canonical but SHORT MAC is a rejection, not a crash', token: `v1.${vPayload}.${Buffer.from(vMac, 'base64url').subarray(0, 16).toString('base64url')}`, request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_signature' },
  { name: 'an over-long MAC is a rejection too', token: `v1.${vPayload}.${Buffer.concat([Buffer.from(vMac, 'base64url'), Buffer.alloc(8)]).toString('base64url')}`, request_path: '/caldera/', verify_at: NOW + 1, expect: 'bad_signature' },
];

const out = {
  _comment: 'Cross-language agreement vectors for the CyberCore/Caldera SSO token. '
    + 'Regenerate with test/fixtures/caldera-sso-vectors.gen.js, and only for a deliberate '
    + 'contract change: these are the ONLY proof that front-end/src/utils/caldera-sso.js and '
    + 'infrastructure/caldera/login_handler.py agree. The secret is a TEST secret.',
  secret: SECRET,
  header: sso.SSO_HEADER,
  version: sso.TOKEN_VERSION,
  ttl_seconds: sso.TOKEN_TTL_SECONDS,
  cases,
};

fs.writeFileSync(
  path.join(__dirname, 'caldera-sso-vectors.json'),
  `${JSON.stringify(out, null, 2)}\n`
);
console.log(`wrote ${cases.length} cases`);
