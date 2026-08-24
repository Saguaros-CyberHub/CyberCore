/**
 * workstation-deploy-access.test.js — who may deploy their own workstation.
 *
 * The hub's "Remote Workspaces → Available" tab clones and powers on a VM on
 * the Proxmox cluster. Both routes behind it — the template catalog and the
 * deploy itself — were `authenticateToken` only, so any student could mint
 * cluster VMs for themselves. They are now staff-only.
 *
 * Two things this pins that are easy to regress:
 *
 *  1. The gate is an ALLOWLIST. The DB default role is 'user', not 'student'
 *     (config/postgres/001_init_db.sql:27), so a `role !== 'student'` denylist
 *     would silently keep the feature for every legacy 'user' row.
 *  2. It is scoped to exactly two routes. Students still own the workstations
 *     provisioned FOR them — listing, console, power, snapshots and delete must
 *     keep working, so over-gating the router is as much a bug as under-gating.
 *
 * Run: node --test front-end/test/workstation-deploy-access.test.js
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'workstation-access-test-secret';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('assert');
const http = require('http');
const path = require('path');
const express = require('express');
const jwt = require('jsonwebtoken');

const UTILS = path.join(__dirname, '..', 'src', 'utils');

function stubModule(rel, exports) {
  const p = require.resolve(path.join(UTILS, rel));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

// The route module pulls in Postgres, Proxmox, Guacamole and the file logger at
// require time. None of them may be touched here: for a DENIED request
// requireRole short-circuits before the handler, and for an ALLOWED one we only
// care that it got past the gate.
const auditCalls = [];
stubModule('audit.js', { log: (entry) => { auditCalls.push(entry); return Promise.resolve(); } });
stubModule('cybercore-db.js', { cybercoreQuery: async () => ({ rows: [] }) });
stubModule('proxmox.js', {
  proxmoxAPI: async () => ({}), waitForTask: async () => {}, findTemplateNode: async () => 'node1',
});
stubModule('node-selector.js', { selectBestNode: async () => ({ node: 'node1' }) });
stubModule('guacamole.js', { guacAPI: async () => ({}), ensureGuacAccount: async () => true });
stubModule('site-config.js', { getDefaultTemplateNode: () => 'node1' });
const noop = () => {};
stubModule('logger.js', () => ({ error: noop, warn: noop, info: noop, http: noop, debug: noop }));

const workstationRoutes = require(path.join(__dirname, '..', 'src', 'routes', 'workstations.js'));

// Staff-only. Everything else on the router stays reachable by a student.
const GATED = [
  { method: 'GET',  path: '/api/workstations/templates' },
  { method: 'POST', path: '/api/workstations/00000000-0000-0000-0000-000000000001/deploy' },
];

let server, port;

before(async () => {
  const app = express();
  app.use(express.json());
  app.use('/api/workstations', workstationRoutes);
  server = http.createServer(app);
  await new Promise(resolve => server.listen(0, resolve));
  port = server.address().port;
});

after(() => server && server.close());

beforeEach(() => { auditCalls.length = 0; });

// A distinct `sub` per caller: requireRole dedupes its audit write for 60s per
// (user, route), so sharing one id across tests would hide the audit assertion.
let _sub = 0;
const tokenFor = role =>
  jwt.sign({ sub: `u${++_sub}`, email: 'a@b.c', role }, process.env.JWT_SECRET, { expiresIn: '1h' });

function call({ method, path: p }, bearer) {
  const headers = { 'Content-Type': 'application/json' };
  if (bearer) headers.Authorization = `Bearer ${bearer}`;
  return new Promise((resolve, reject) => {
    const req = http.request({ port, method, path: p, headers }, res => {
      let body = '';
      res.on('data', c => { body += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(body); } catch (_) { /* handler may not have replied JSON */ }
        resolve({ status: res.statusCode, json });
      });
    });
    req.on('error', reject);
    req.end(method === 'POST' ? '{}' : undefined);
  });
}

test('a student cannot list templates or deploy', async () => {
  const token = tokenFor('student');
  for (const route of GATED) {
    const res = await call(route, token);
    assert.strictEqual(res.status, 403, `${route.method} ${route.path} should refuse a student`);
    assert.deepStrictEqual(res.json.requiredRoles, ['instructor', 'admin']);
    assert.strictEqual(res.json.userRole, 'student');
  }
});

test("the legacy 'user' role is refused too — allowlist, not denylist", async () => {
  // 'user' is the column DEFAULT in 001_init_db.sql, so accounts created without
  // an explicit role land here. A `role !== 'student'` check would let them all
  // through; this is the test that fails if anyone rewrites the gate that way.
  const token = tokenFor('user');
  for (const route of GATED) {
    const res = await call(route, token);
    assert.strictEqual(res.status, 403, `${route.method} ${route.path} should refuse role 'user'`);
    assert.strictEqual(res.json.userRole, 'user');
  }
});

test('a token carrying no role at all is refused', async () => {
  // requireRole falls back to 'student' for a role-less token (auth.js:121).
  const token = jwt.sign({ sub: 'u-noRole', email: 'a@b.c' }, process.env.JWT_SECRET, { expiresIn: '1h' });
  for (const route of GATED) {
    const res = await call(route, token);
    assert.strictEqual(res.status, 403, `${route.method} ${route.path} should refuse a role-less token`);
  }
});

test('an anonymous caller is refused before the role check', async () => {
  for (const route of GATED) {
    const res = await call(route, null);
    assert.strictEqual(res.status, 401, `${route.method} ${route.path} should refuse anonymously`);
  }
});

test('a denial is written to the audit log', async () => {
  await call(GATED[1], tokenFor('student'));
  const denial = auditCalls.find(e => e.action === 'access.denied');
  assert.ok(denial, 'expected an access.denied audit entry');
  assert.strictEqual(denial.reason, 'role_denied');
  assert.deepStrictEqual(denial.metadata.required_roles, ['instructor', 'admin']);
  assert.strictEqual(denial.metadata.user_role, 'student');
});

test('an instructor gets past the gate', async () => {
  const res = await call(GATED[0], tokenFor('instructor'));
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.json.templates, []);   // the stubbed empty catalog
});

test('an admin gets past the gate', async () => {
  const res = await call(GATED[0], tokenFor('admin'));
  assert.strictEqual(res.status, 200);
});

test('an instructor reaches the deploy handler itself', async () => {
  // 404 "Template not found" is the stubbed DB answering, which means the
  // request got all the way through staffOnly into the handler body.
  const res = await call(GATED[1], tokenFor('instructor'));
  assert.notStrictEqual(res.status, 403);
  assert.strictEqual(res.status, 404);
});

test('a student keeps the workstations already provisioned for them', async () => {
  // The lockdown is two routes wide. If a later change gates the whole router,
  // students lose the lab machines their instructor deployed — this catches it.
  const res = await call({ method: 'GET', path: '/api/workstations/mine' }, tokenFor('student'));
  assert.notStrictEqual(res.status, 403, 'GET /mine must stay open to students');
  assert.notStrictEqual(res.status, 401);
});
