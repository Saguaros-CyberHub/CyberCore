/**
 * ciab-modules-api.test.js — Track D, phase D2: the Modules endpoint contract.
 *
 * Mounted in production at /api/instructor/sections/:sectionId/modules, above
 * the bare /api/instructor/sections mount, because Express matches router.use()
 * prefixes in registration order. That ordering is pinned in
 * ciab-module-spine.test.js; what is pinned HERE is what each verb does.
 *
 * THE ASSERTIONS ARE ABOUT WHAT MUST NEVER HAPPEN, because every one of these
 * failures is silent:
 *
 *   A MODULE IS NEVER LOADED BY ID ALONE. Every statement against ciab_module
 *   carries the section, so an id from another section is a 404 rather than a
 *   leak — and the section refusal is byte-identical on every verb, so section
 *   ids cannot be enumerated by status code or by message.
 *
 *   GET / AUTHORIZES BEFORE IT RESOLVES. spine.loadSectionForStaff performs no
 *   authorization of its own, so the ordering is the only thing standing
 *   between any instructor and any section's instructor_notes and roster
 *   rollup.
 *
 *   A REORDER IS ONE STATEMENT. Nothing in this plugin calls pool.connect(), so
 *   a second statement would have no rollback, and the statement's own section
 *   predicate SKIPS an id the section does not own — which is why the
 *   membership check has to precede the write rather than inspect rowCount
 *   afterwards.
 *
 *   A CLONE RECORDS ITS LINEAGE. cloned_from_module_id is the one fact no later
 *   ALTER can backfill; without it the cross-section repetition view is
 *   permanently blind for every module cloned this term. And a clone is always
 *   a draft with no window: one that inherited 'open' would publish unreviewed
 *   work to the whole roster the instant it was written.
 *
 *   EVERY RESPONSE CARRIES A JSON BODY, DELETE INCLUDED. public/js/app.js calls
 *   response.json() unconditionally, so a 204 surfaces to the instructor as a
 *   network error on a request that in fact succeeded.
 *
 * No database: ciab/utils/db.js is stubbed through require.cache before
 * anything under test is required, and the handler returns a benign result for
 * anything it does not recognise — a stub that THROWS prints a stack that
 * corrupts node --test's IPC and fails the whole FILE rather than one test.
 * ./lane-reservation is stubbed too, so nothing can reach Proxmox.
 *
 * Run: node --test "test/*.test.js"
 */

process.env.JWT_SECRET = process.env.JWT_SECRET || 'ciab-modules-api-secret';

const { test, before, after, beforeEach } = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

function stub(absPath, exports) {
  const p = require.resolve(absPath);
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return exports;
}

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;
const M1 = uuid(1);
const M2 = uuid(2);
const M3 = uuid(3);
const FOREIGN = uuid(9);
const P1 = uuid(11);
const P2 = uuid(12);
// uuid(n) above is all digits and dashes, so .toUpperCase() on it is a NO-OP.
// The two case-fold tests need ids that actually carry hex letters.
const HEX_A = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee01';
const HEX_B = 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeee02';
// REAL UUIDS, because ciab_section.section_id is a uuid column and the routes now
// shape-check a target_section_id before handing it to getManagedSection: a
// non-uuid there reached WHERE section_id = $1, raised 22P02, and surfaced as a
// 500 where the contract promises 403.
const SEC = uuid(101);
const SEC2 = uuid(102);

// ---- fixtures the stubs read and the tests assert on -----------------------
let dbCalls = [];        // every statement, in order
let writes = [];         // every MUTATING statement, audit excluded
let auditCalls = [];     // the never-awaited activity_log inserts
let auditRejects = false;
let managedCalls = [];
let managed = {};        // sectionId -> section row, or absent for "not yours"
let sectionRows = {};    // sectionId -> the ciab_section row spine reads
let moduleRows = [];     // ciab_module, for both spine and mustModule
let prereqRows = [];     // ciab_module_prereq
let dependentRows = [];  // what the dependents probe returns
let studentRecordRows = [];
let insertFails = null;  // an Error to throw on the next INSERT INTO ciab_module
let prereqInsertFails = null;
// Makes the ciab_module_prereq INSERT report rowCount 0, i.e. ON CONFLICT DO
// NOTHING found the edge already there. Without it the idempotent branch
// (200 / created:false) is unreachable and three shipped code paths untested.
let prereqEdgeExists = false;
// Makes the reorder UPDATE report one row short of the ids it was handed.
let reorderShort = false;
// Makes the single-row UPDATE (PATCH, archive) match nothing, which is what a
// hard delete landing between mustModule's SELECT and that UPDATE looks like.
let updateMisses = false;
let capReached = false;  // makes both INSERT ... SELECT statements return 0 rows
let user = { userId: 'ins-1', role: 'instructor' };

// The two booleans routes/sections.js's hard delete now probes for in ONE query.
let sectionHasEnrollments = false;
let sectionHasModules = false;

const moduleRow = (over = {}) => ({
  module_id: M1, section_id: SEC, position: 1, title: 'Scoping', brief: null,
  instructor_notes: null, profile_id: null, engagement_type: 'default',
  assessment_part: null, release_state: 'draft', release_at: null, close_at: null,
  cloned_from_module_id: null, created_by: 'ins-1', updated_by: 'ins-1',
  created_at: '2026-01-01T00:00:00.000Z', updated_at: '2026-01-01T00:00:00.000Z', ...over,
});

const isWrite = (sql) => /^\s*(INSERT|UPDATE|DELETE)/i.test(sql);

stub(path.join(CIAB, 'utils', 'db.js'), {
  getPool: () => null,
  setPool: () => {},
  pool: null,
  query: async (sql, params) => {
    const s = String(sql);
    dbCalls.push({ sql: s, params });

    if (/INSERT INTO activity_log/i.test(s)) {
      auditCalls.push({ sql: s, params });
      if (auditRejects) throw new Error('clinic_db went away');
      return { rows: [], rowCount: 1 };
    }
    if (isWrite(s)) writes.push({ sql: s, params });

    // ── spine reads ──
    if (/FROM ciab_section\b/i.test(s)) {
      const row = sectionRows[params[0]];
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }
    // Anchored to SELECT: the clone's edge copy is an INSERT ... SELECT that
    // also reads `FROM ciab_module_prereq p`, and answering it here would make
    // the copy look like it succeeded while writing nothing.
    if (/^\s*SELECT/i.test(s) && /FROM ciab_module_prereq p\b/i.test(s)) {
      return { rows: dependentRows, rowCount: dependentRows.length };
    }
    if (/COUNT\(\*\)::int AS n FROM ciab_module_prereq/i.test(s)) {
      const owned = prereqRows.filter((e) => e.section_id === params[0] && e.module_id === params[1]);
      return { rows: [{ n: owned.length }], rowCount: 1 };
    }
    if (/FROM ciab_module_prereq\b/i.test(s) && /^\s*SELECT/i.test(s)) {
      const rows = prereqRows.filter((e) => e.section_id === params[0]);
      return { rows, rowCount: rows.length };
    }
    if (/FROM ciab_module_student\b/i.test(s)) {
      return { rows: studentRecordRows, rowCount: studentRecordRows.length };
    }
    if (/AS has_enrollments/i.test(s)) {
      return { rows: [{ has_enrollments: sectionHasEnrollments, has_modules: sectionHasModules }], rowCount: 1 };
    }
    if (/COUNT\(\*\)::int AS n FROM ciab_enrollment/i.test(s)) return { rows: [{ n: 0 }], rowCount: 1 };
    if (/FROM ciab_enrollment\b/i.test(s)) return { rows: [], rowCount: 0 };
    if (/FROM assessment_progress\b/i.test(s)) return { rows: [], rowCount: 0 };
    if (/FROM profiles\b/i.test(s)) {
      return { rows: [{ id: P1, company_name: 'Acme', client_type_name: 'SMB', industry: 'x', difficulty: 'easy', hq_city: 'y' }], rowCount: 1 };
    }

    // ── ciab_module ──
    if (/INSERT INTO ciab_module\b/i.test(s)) {
      if (prereqInsertFails && /ciab_module_prereq/i.test(s)) throw prereqInsertFails;
      if (insertFails && !/ciab_module_prereq/i.test(s)) throw insertFails;
      if (/INSERT INTO ciab_module_prereq/i.test(s)) return { rows: [], rowCount: prereqEdgeExists ? 0 : 1 };
      if (capReached) return { rows: [], rowCount: 0 };
      // Mirror what the statement would actually store: a clone's release
      // columns are literals in the SQL, never parameters.
      //
      // MATCHED AGAINST THE INSERT'S COLUMN LIST, not the whole statement: every
      // statement here ends `RETURNING ${MODULE_COLUMNS}` and MODULE_COLUMNS
      // NAMES cloned_from_module_id, so a bare /cloned_from_module_id/ classed
      // every plain create as a clone and handed the route back a row whose
      // release_state was always 'draft' and whose cloned_from_module_id was the
      // create's release_state string.
      const cloning = /INSERT INTO ciab_module\s*\([^)]*cloned_from_module_id/i.test(s);
      const row = moduleRow({
        module_id: uuid(50 + moduleRows.length),
        section_id: params[0],
        position: moduleRows.length + 1,
        title: params[1], brief: params[2], instructor_notes: params[3],
        profile_id: params[4], engagement_type: params[5], assessment_part: params[6],
        release_state: cloning ? 'draft' : params[7],
        release_at: cloning ? null : params[8],
        close_at: cloning ? null : params[9],
        cloned_from_module_id: cloning ? params[7] : null,
      });
      return { rows: [row], rowCount: 1 };
    }
    if (/INSERT INTO ciab_module_prereq/i.test(s)) {
      if (prereqInsertFails) throw prereqInsertFails;
      return { rows: [], rowCount: prereqEdgeExists ? 0 : 1 };
    }
    if (/^\s*UPDATE ciab_module m\b/i.test(s)) {
      // THE REORDER. The statement carries no `position IS DISTINCT FROM
      // v.pos` (dropping it is what preserves last-write-wins under READ
      // COMMITTED), so it matches EVERY named row the section owns and rowCount
      // is n. The route reports `moved` from its own JS count instead.
      const ids = params.slice(2).map((id) => String(id).toLowerCase());
      const matched = ids.filter((id) => moduleRows.some(
        (r) => String(r.module_id).toLowerCase() === id && r.section_id === params[0]
      )).length;
      // A concurrent delete: a row named in the order is gone by the time the
      // statement runs, so rowCount comes back short of the id count.
      return { rows: [], rowCount: reorderShort ? Math.max(0, matched - 1) : matched };
    }
    if (/^\s*UPDATE ciab_module\b/i.test(s)) {
      const target = moduleRows.find((m) => m.module_id === params[params.length - 2])
        || moduleRows.find((m) => m.module_id === params[0]) || moduleRow();
      const archiving = /release_state = 'archived'/.test(s);
      if (updateMisses) return { rows: [], rowCount: 0 };
      return { rows: [{ ...target, ...(archiving ? { release_state: 'archived' } : {}) }], rowCount: 1 };
    }
    if (/^\s*DELETE FROM ciab_module_prereq/i.test(s)) {
      const hit = prereqRows.some((e) => e.module_id === params[1] && e.prereq_module_id === params[2]);
      return { rows: [], rowCount: hit ? 1 : 0 };
    }
    if (/^\s*DELETE FROM ciab_module\b/i.test(s)) return { rows: [], rowCount: 1 };
    if (/FROM ciab_module\b/i.test(s) && /module_id = \$1::uuid/.test(s)) {
      const row = moduleRows.find((m) => m.module_id === params[0] && m.section_id === params[1]);
      return { rows: row ? [row] : [], rowCount: row ? 1 : 0 };
    }
    if (/FROM ciab_module\b/i.test(s)) {
      const rows = moduleRows.filter((m) => m.section_id === params[0]);
      return { rows, rowCount: rows.length };
    }

    return { rows: [], rowCount: 0 };
  },
});

stub(path.join(CIAB, 'utils', 'lane-reservation.js'), {
  sanitizeEngagementType: (raw) => {
    const s = String(raw == null ? '' : raw).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    return s ? s.slice(0, 32) : 'default';
  },
});

const UUID_SHAPE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

stub(path.join(CIAB, 'utils', 'enrollment.js'), {
  getManagedSection: async (sectionId, u, columns) => {
    managedCalls.push({ sectionId, columns });
    // WHAT POSTGRESQL ACTUALLY DOES. getManagedSection's query is
    // `WHERE section_id = $1` against a uuid column, so a malformed value raises
    // 22P02 -- which carries no `status`, so fail() answered a generic 500 where
    // the contract promises 403. A stub that quietly returned null instead made
    // that unreachable, and the guard untestable.
    if (sectionId && !UUID_SHAPE.test(String(sectionId).trim())) {
      throw Object.assign(new Error('invalid input syntax for type uuid'), { code: '22P02' });
    }
    return managed[sectionId] || null;
  },
  invalidate: () => { throw new Error('this surface must not touch the enrollment cache'); },
  invalidateAll: () => { throw new Error('this surface must not touch the enrollment cache'); },
  requireCiabAccess: (req, res, next) => next(),
});

stub(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });
stub(path.join(ROOT, 'src', 'utils', 'account-provisioning.js'), {
  normalizeEmail: (e) => String(e || '').trim().toLowerCase(),
  isEmailShaped: () => true,
  findUsersByEmails: async () => new Map(),
  findUserByEmail: async () => null,
  findUserById: async () => null,
  isElevatedAccount: () => false,
  canManageAccount: () => true,
  provisionAccount: async () => ({ user: {}, created: false }),
});
stub(path.join(ROOT, 'src', 'utils', 'activation.js'), {
  issueActivationToken: async () => ({ token: 't', expiresAt: 'later' }),
  activationUrl: () => 'https://example.test/activate',
  pendingActivationFor: async () => ({}),
});

const modulesRouter = require(path.join(CIAB, 'routes', 'section-modules.js'));
const admin = require(path.join(CIAB, 'utils', 'module-admin.js'));
const S = require(path.join(CIAB, 'utils', 'module-states.js'));

// D1's SECOND RECORDED OBLIGATION, written into migration 014's header: the
// hard delete of a SECTION must now count modules as well as enrollments.
// ciab_module CASCADEs from ciab_section, so before this a section with modules
// and no enrollments deleted cleanly, answered 200, and took every module,
// every prerequisite edge and every per-student completion record with it.
const sectionsRouter = require(path.join(CIAB, 'routes', 'sections.js'));

const ROUTE_SRC = fs.readFileSync(path.join(CIAB, 'routes', 'section-modules.js'), 'utf8').replace(/\r\n/g, '\n');

let server, port;

before(async () => {
  const app = express();
  app.use((req, res, next) => {
    // The real chain is authenticateToken + requireCiabAccess above this
    // router, plus a shim that stamps :sectionId into res.locals. That chain is
    // covered by ciab-gate-scope.test.js; forging it here keeps these tests
    // about the handlers.
    req.user = user;
    res.locals.sectionId = SEC;
    next();
  });
  // No express.json() here, deliberately: the router mounts its own per
  // body-carrying route, and that is what must keep working.
  app.use('/modules', modulesRouter);
  app.use('/sections', sectionsRouter);
  server = http.createServer(app);
  await new Promise((r) => server.listen(0, r));
  port = server.address().port;
});

after(() => server && server.close());

beforeEach(() => {
  dbCalls = []; writes = []; auditCalls = []; managedCalls = [];
  auditRejects = false;
  insertFails = null; prereqInsertFails = null; capReached = false;
  prereqEdgeExists = false; reorderShort = false; updateMisses = false;
  user = { userId: 'ins-1', role: 'instructor' };
  managed = {
    [SEC]: { section_id: SEC, name: 'CYBR 480', code: 'CYBR-480', term: 'SP26', status: 'active', instructor_id: 'ins-1' },
    [SEC2]: { section_id: SEC2, name: 'CYBR 481', code: 'CYBR-481', term: 'SP26', status: 'active', instructor_id: 'ins-1' },
  };
  sectionRows = {
    [SEC]: { section_id: SEC, name: 'CYBR 480', code: 'CYBR-480', term: 'SP26', status: 'active' },
    [SEC2]: { section_id: SEC2, name: 'CYBR 481', code: 'CYBR-481', term: 'SP26', status: 'active' },
  };
  moduleRows = [
    moduleRow({ module_id: M1, position: 1, title: 'Scoping' }),
    moduleRow({ module_id: M2, position: 2, title: 'Assessment' }),
    moduleRow({ module_id: M3, position: 3, title: 'Report' }),
  ];
  prereqRows = [];
  dependentRows = [];
  studentRecordRows = [];
  sectionHasEnrollments = false;
  sectionHasModules = false;
});

function send(method, pathname, body) {
  const payload = body === undefined ? null : JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const headers = payload
      ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(payload) }
      : {};
    const req = http.request({ port, path: pathname, method, headers }, (res) => {
      let raw = '';
      res.on('data', (c) => { raw += c; });
      res.on('end', () => {
        let json = null;
        try { json = JSON.parse(raw); } catch (_) { /* not JSON */ }
        resolve({ status: res.statusCode, json, raw });
      });
    });
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}

const moduleSelects = () => dbCalls.filter((c) => /FROM ciab_module\b/i.test(c.sql) && /^\s*SELECT/i.test(c.sql));
const settle = () => new Promise((r) => setImmediate(r));

// ===========================================================================
// Source-text guarantees
// ===========================================================================

test('the route file requires ./lane-reservation nowhere, and trips none of the scanners', () => {
  assert.ok(!/require\(['"]\.\.\/utils\/lane-reservation['"]\)/.test(ROUTE_SRC),
    'engagement_type is written only through admin.engagementSlug(); a top-level require here '
    + 'crashes any dedicated route test with "Unable to deserialize cloned data"');
  const AUDIT_TABLE = ['cybercore', 'audit', 'log'].join('_');
  const LANE_TABLE = ['cybercore', 'lane'].join('_');
  assert.ok(!/\$\d+\s+IS\s+(NOT\s+)?NULL/i.test(ROUTE_SRC),
    'there is no NULL test on a parameter at all — the collision check is pure JavaScript');
  assert.ok(!ROUTE_SRC.includes(AUDIT_TABLE));
  assert.ok(!ROUTE_SRC.includes(LANE_TABLE));
  const code = ROUTE_SRC.replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');
  const hit = code.match(/\b(course|courses|material|materials|challenge|challenges|assignment|assignments|lesson|lessons)\b/i);
  assert.strictEqual(hit, null, `the route file names ${hit && hit[0]}`);
});

test('every mutation logs module.<verb> and never goes through the roster helper', () => {
  const noComments = ROUTE_SRC.replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');
  assert.ok(!/logRosterActivity/.test(noComments),
    'that helper hardcodes the roster. prefix and entity_type ciab_section, so it would file '
    + 'roster.module_created against a section id and make the trail unqueryable by module');
  const verbs = [...ROUTE_SRC.matchAll(/action:\s*'([a-z_]+)'/g)].map((m) => m[1]).sort();
  assert.deepStrictEqual([...new Set(verbs)], [
    'archived', 'cloned', 'created', 'deleted', 'prereq_added', 'prereq_removed', 'reordered', 'updated',
  ]);
});

// ===========================================================================
// GET /
// ===========================================================================

test('GET / returns the whole tab in one payload, with the server vocabulary', async () => {
  const res = await send('GET', '/modules/');
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.section.section_id, SEC);
  assert.strictEqual(res.json.modules.length, 3);
  assert.ok(Array.isArray(res.json.issues));
  assert.ok(Array.isArray(res.json.warnings));
  assert.ok(res.json.labels.release.draft, 'the browser hand-writes no badge word');
  assert.ok(Array.isArray(res.json.release_states));
  assert.ok(Array.isArray(res.json.parts));
  assert.deepStrictEqual(res.json.capabilities, { hard_delete: false },
    'the Delete control is rendered from a SERVER-computed flag, never from "am I an admin"');
  assert.strictEqual(res.json.clients[0].company_name, 'Acme');
});

test('GET / AUTHORIZES BEFORE IT RESOLVES', async () => {
  managed = {};
  const res = await send('GET', '/modules/');
  assert.strictEqual(res.status, 403);
  assert.strictEqual(res.json.error, 'Section not found or access denied');
  assert.strictEqual(res.json.code, 'SECTION_NOT_MANAGED');
  assert.strictEqual(dbCalls.length, 0,
    'loadSectionForStaff performs no authorization, so a single query here is any instructor '
    + 'reading any section\'s instructor_notes and roster rollup');
});

test('GET / stays inside its query budget, and the clients query is SECTION-scoped', async () => {
  await send('GET', '/modules/');
  assert.ok(dbCalls.length <= 8, `expected at most 8 queries, saw ${dbCalls.length}`);
  const clients = dbCalls.find((c) => /FROM profiles/i.test(c.sql));
  assert.ok(clients.sql.includes('id IN (SELECT profile_id FROM ciab_module'));
  assert.ok(clients.sql.includes('WHERE section_id = $2::uuid AND profile_id IS NOT NULL'),
    'the deliberate widening resolves only clients already bound in a section the caller manages');
  assert.strictEqual(clients.params[1], SEC);
});

test('GET / re-words exactly the two issue codes written for a student', async () => {
  const S = require(path.join(CIAB, 'utils', 'module-states.js'));
  // A prerequisite naming a module that is no longer here: PREREQ_MISSING.
  prereqRows = [{ section_id: SEC, module_id: M2, prereq_module_id: FOREIGN }];
  const res = await send('GET', '/modules/');
  const missing = res.json.issues.find((i) => i.code === S.ISSUE.PREREQ_MISSING);
  assert.ok(missing, 'the resolver must still report it');
  assert.strictEqual(missing.message,
    'This module requires a module that is no longer in this section, so it can never open. Remove that prerequisite.');
  assert.notStrictEqual(missing.message, S.messageFor(S.ISSUE.PREREQ_MISSING),
    '"Ask your instructor" reads as nonsense to the person who has to act');
  for (const issue of res.json.issues) {
    if (issue.code === S.ISSUE.PREREQ_MISSING || issue.code === S.ISSUE.PREREQ_CYCLE) continue;
    assert.strictEqual(issue.message, S.messageFor(issue.code), `${issue.code} must pass through untouched`);
  }
});

// ===========================================================================
// POST /
// ===========================================================================

test('POST / creates at the end of the sequence, in ONE fully cast statement', async () => {
  const res = await send('POST', '/modules/', { title: 'New work', profile_id: P1 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.json.module.title, 'New work');
  assert.deepStrictEqual(res.json.warnings, []);

  const ins = writes.find((w) => /INSERT INTO ciab_module\b/i.test(w.sql));
  assert.ok(ins);
  assert.ok(ins.sql.includes('COALESCE((SELECT MAX(position) FROM ciab_module WHERE section_id = $1::uuid), 0) + 1'),
    'the position is computed INSIDE the statement: no read-then-write race and no second query');
  for (const cast of ['$1::uuid', '$2::varchar', '$3::text', '$4::text', '$5::uuid', '$6::varchar',
    '$7::int', '$8::varchar', '$9::timestamptz', '$10::timestamptz', '$11::uuid']) {
    assert.ok(ins.sql.includes(cast), `every parameter is cast at its first reference: ${cast}`);
  }
  assert.ok(!/FROM ciab_module src/i.test(ins.sql),
    'a FROM-less SELECT makes rowCount 0 unambiguous proof the cap fired');
});

test('POST / refuses the documented 400s and writes nothing', async () => {
  for (const [body, code] of [
    [{ }, 'TITLE_REQUIRED'],
    [{ title: '  ' }, 'TITLE_REQUIRED'],
    [{ title: 't', release_state: 'published' }, 'RELEASE_STATE_INVALID'],
    [{ title: 't', release_at: 'nope' }, 'RELEASE_AT_INVALID'],
    [{ title: 't', close_at: 'nope' }, 'CLOSE_AT_INVALID'],
    [{ title: 't', assessment_part: 0 }, 'ASSESSMENT_PART_INVALID'],
    [{ title: 't', profile_id: 'nope' }, 'PROFILE_ID_INVALID'],
  ]) {
    writes = [];
    const res = await send('POST', '/modules/', body);
    assert.strictEqual(res.status, 400, JSON.stringify(body));
    assert.strictEqual(res.json.code, code);
    assert.strictEqual(writes.length, 0);
  }
});

test('POST / is 409 SECTION_MODULE_LIMIT when the cap predicate is false', async () => {
  capReached = true;
  const res = await send('POST', '/modules/', { title: 'One too many' });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'SECTION_MODULE_LIMIT');
  assert.match(res.json.error, /limited to 200 modules/);
});

test('POST / refuses a second module on one client and one assessment part', async () => {
  moduleRows[0] = moduleRow({ module_id: M1, profile_id: P1, assessment_part: 2, title: 'Existing' });
  const res = await send('POST', '/modules/', { title: 'Twin', profile_id: P1, assessment_part: 2 });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'ASSESSMENT_PART_COLLISION');
  assert.deepStrictEqual(res.json.conflict, { module_id: M1, title: 'Existing' });
  assert.strictEqual(writes.length, 0);

  // The repetition the programme exists for is NOT refused.
  writes = [];
  const ok = await send('POST', '/modules/', { title: 'Same client, next part', profile_id: P1, assessment_part: 3 });
  assert.strictEqual(ok.status, 201);
});

test("POST / ACCEPTS 'scheduled' with no date and answers with the warning", async () => {
  const S = require(path.join(CIAB, 'utils', 'module-states.js'));
  const res = await send('POST', '/modules/', { title: 'Later', release_state: 'scheduled' });
  assert.strictEqual(res.status, 201, 'refusing it would break correcting a window in two PATCHes');
  assert.strictEqual(res.json.warnings[0].code, S.ISSUE.SCHEDULED_WITHOUT_DATE);
  assert.strictEqual(res.json.warnings[0].message, S.messageFor(S.ISSUE.SCHEDULED_WITHOUT_DATE));

  const inverted = await send('POST', '/modules/', {
    title: 'Backwards', release_at: '2026-03-05T09:00:00Z', close_at: '2026-03-01T09:00:00Z',
  });
  assert.strictEqual(inverted.status, 201);
  assert.ok(inverted.json.warnings.some((w) => w.code === S.ISSUE.CLOSE_BEFORE_RELEASE));
});

test('POST / turns the profile foreign key into CLIENT_GONE, not a 500', async () => {
  insertFails = Object.assign(new Error('violates foreign key constraint'), { code: '23503' });
  const res = await send('POST', '/modules/', { title: 'Orphan', profile_id: P2 });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'CLIENT_GONE');
});

// ===========================================================================
// POST /reorder
// ===========================================================================

test('a reorder is exactly ONE mutating statement, section-scoped', async () => {
  const res = await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.json.order, [M3, M1, M2]);
  assert.strictEqual(writes.length, 1,
    'nothing in this plugin calls pool.connect(), so a second statement would have no rollback');
  assert.ok(writes[0].sql.includes('FROM (VALUES'));
  assert.ok(writes[0].sql.includes('AND m.section_id = $1::uuid'));
  assert.ok(writes[0].sql.includes('($3::uuid, 1)'));
  assert.strictEqual(writes[0].params[0], SEC);
});

test('the membership SELECT precedes the reorder UPDATE', async () => {
  await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
  const readAt = dbCalls.findIndex((c) => /^\s*SELECT/i.test(c.sql) && /FROM ciab_module\b/i.test(c.sql));
  const writeAt = dbCalls.findIndex((c) => /^\s*UPDATE ciab_module m/i.test(c.sql));
  assert.ok(readAt >= 0 && writeAt > readAt,
    'the statement SKIPS an id the section does not own, so inspecting rowCount afterwards is too late');
});

test('an incomplete or foreign order is 409 ORDER_STALE with the canonical order echoed back', async () => {
  const short = await send('POST', '/modules/reorder', { order: [M1, M2] });
  assert.strictEqual(short.status, 409, 'well-formed, and merely lost a race with a co-instructor');
  assert.strictEqual(short.json.code, 'ORDER_STALE');
  assert.deepStrictEqual(short.json.missing_from_order, [M3]);
  assert.deepStrictEqual(short.json.order, [M1, M2, M3]);
  assert.strictEqual(writes.length, 0);

  writes = [];
  const foreign = await send('POST', '/modules/reorder', { order: [M1, M2, M3, FOREIGN] });
  assert.strictEqual(foreign.status, 409);
  assert.deepStrictEqual(foreign.json.not_in_section, [FOREIGN]);
  assert.strictEqual(writes.length, 0);
});

test('a repeated module is 400 ORDER_INVALID naming it, and writes nothing', async () => {
  const res = await send('POST', '/modules/reorder', { order: [M1, M1, M2] });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.code, 'ORDER_INVALID');
  assert.deepStrictEqual(res.json.duplicates, [M1]);
  assert.strictEqual(writes.length, 0);
});

test('a hostile order never reaches a placeholder list or a ::uuid cast', async () => {
  for (const body of [{ order: [] }, { }, { order: 'nope' }, { order: { } }, { order: [M1, 'not-a-uuid'] }]) {
    dbCalls = []; writes = [];
    const res = await send('POST', '/modules/reorder', body);
    assert.strictEqual(res.status, 400, JSON.stringify(body));
    assert.strictEqual(res.json.code, 'ORDER_INVALID');
    assert.strictEqual(writes.length, 0);
  }
  dbCalls = [];
  const tooMany = await send('POST', '/modules/reorder', { order: Array.from({ length: 201 }, (_, i) => uuid(200 + i)) });
  assert.strictEqual(tooMany.status, 400);
  assert.strictEqual(dbCalls.length, 0, 'a hostile payload issues no query at all');
});

test('an UPPER-CASED order is accepted and reorders correctly', async () => {
  const res = await send('POST', '/modules/reorder', { order: [M3.toUpperCase(), M1.toUpperCase(), M2.toUpperCase()] });
  assert.strictEqual(res.status, 200,
    'PostgreSQL renders uuid lowercase; without folding, every id would land in not_in_section');
  assert.deepStrictEqual(res.json.order, [M3, M1, M2]);
});

test('reordering to the current arrangement writes the statement and reports moved: 0', async () => {
  const res = await send('POST', '/modules/reorder', { order: [M1, M2, M3] });
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.moved, 0, 'the position IS DISTINCT FROM v.pos predicate');
  assert.strictEqual(writes.length, 1);
});

test('the audit write is NEVER awaited', async () => {
  auditRejects = true;
  const res = await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
  assert.strictEqual(res.status, 200,
    'an awaited audit insert turns a transient clinic_db hiccup into a failed reorder the '
    + 'instructor reads as data loss');
  await settle();
  assert.strictEqual(auditCalls.length, 1);
  assert.strictEqual(auditCalls[0].params[1], 'module.reordered');
  assert.strictEqual(auditCalls[0].params[2], 'ciab_section', 'a reorder is not about one module');
});

// ===========================================================================
// PATCH /:moduleId
// ===========================================================================

test('PATCH refuses position and section_id explicitly, and writes nothing', async () => {
  const pos = await send('PATCH', `/modules/${M1}`, { position: 2 });
  assert.strictEqual(pos.status, 400);
  assert.strictEqual(pos.json.code, 'POSITION_NOT_EDITABLE');

  const sec = await send('PATCH', `/modules/${M1}`, { section_id: SEC2 });
  assert.strictEqual(sec.status, 400);
  assert.strictEqual(sec.json.code, 'SECTION_NOT_EDITABLE');
  assert.strictEqual(writes.length, 0, 'a 200 on an ignored key makes the client believe the write happened');
});

test('a PATCH naming no writable field is 400 and issues NO UPDATE', async () => {
  const res = await send('PATCH', `/modules/${M1}`, { module_id: M2, created_by: 'x' });
  assert.strictEqual(res.status, 400);
  assert.strictEqual(res.json.code, 'NOTHING_TO_UPDATE');
  assert.strictEqual(writes.length, 0, 'an empty PATCH must not silently bump updated_at');
});

test('a real PATCH writes updated_at AND updated_by through the same builder', async () => {
  const res = await send('PATCH', `/modules/${M1}`, { title: 'Renamed' });
  assert.strictEqual(res.status, 200);
  const upd = writes.find((w) => /^\s*UPDATE ciab_module\b/i.test(w.sql));
  assert.ok(/title = \$1/.test(upd.sql));
  assert.ok(/updated_by = \$2/.test(upd.sql));
  assert.ok(/updated_at = \$3/.test(upd.sql), 'there is not one CREATE TRIGGER in this tree');
  assert.ok(/WHERE module_id = \$4 AND section_id = \$5/.test(upd.sql),
    'a module is never loaded or written by id alone');
});

test('PATCH 404s a module from another section, without a section 404 twin', async () => {
  const res = await send('PATCH', `/modules/${FOREIGN}`, { title: 'Not mine' });
  assert.strictEqual(res.status, 404);
  assert.strictEqual(res.json.error, 'That module is not in this section');
  assert.strictEqual(res.json.code, 'MODULE_NOT_IN_SECTION');
  assert.strictEqual(writes.length, 0);
});

test('the assessment-part collision fires on PATCH too', async () => {
  moduleRows[1] = moduleRow({ module_id: M2, position: 2, profile_id: P1, assessment_part: 2, title: 'Holds part 2' });
  const res = await send('PATCH', `/modules/${M1}`, { profile_id: P1, assessment_part: 2 });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'ASSESSMENT_PART_COLLISION');
  assert.strictEqual(res.json.conflict.module_id, M2);
});

// ===========================================================================
// DELETE /:moduleId
// ===========================================================================

test('DELETE defaults to an ARCHIVE, and carries a JSON body', async () => {
  const res = await send('DELETE', `/modules/${M1}`);
  assert.strictEqual(res.status, 200);
  assert.strictEqual(res.json.archived, true);
  assert.strictEqual(res.json.module.release_state, 'archived');
  assert.ok(res.raw.length > 0, 'API.request parses a body unconditionally: a 204 reads as a network error');
  assert.ok(!writes.some((w) => /^\s*DELETE FROM ciab_module\b/i.test(w.sql)),
    'archiving is the only removal that keeps the rows the grading phase reads');
  assert.ok(writes.some((w) => /release_state = 'archived'/.test(w.sql)));
});

test('archive and hard delete give OPPOSITE consequences for the modules that follow', async () => {
  dependentRows = [{ module_id: M2, title: 'Assessment' }];

  const archive = await send('DELETE', `/modules/${M1}`);
  assert.strictEqual(archive.status, 409);
  assert.strictEqual(archive.json.code, 'MODULE_HAS_DEPENDENTS');
  assert.match(archive.json.error, /locked for the whole roster/);
  assert.deepStrictEqual(archive.json.required_by, [{ module_id: M2, title: 'Assessment' }]);

  user = { userId: 'adm-1', role: 'admin' };
  const hard = await send('DELETE', `/modules/${M1}?hard=1`);
  assert.strictEqual(hard.status, 409);
  assert.match(hard.json.error, /become available immediately/);

  // Both cleared by ?confirm=1, server-side, so a script hits the same wall a
  // browser Confirm does.
  writes = [];
  const confirmed = await send('DELETE', `/modules/${M1}?hard=1&confirm=1`);
  assert.strictEqual(confirmed.status, 200);
  assert.strictEqual(confirmed.json.archived, false);
  assert.strictEqual(confirmed.json.deleted_module_id, M1);
  assert.strictEqual(confirmed.json.warnings[0].code, 'PREREQ_EDGES_REMOVED');
});

test('a hard delete is admin-only, and never overrides student records', async () => {
  const denied = await send('DELETE', `/modules/${M1}?hard=1`);
  assert.strictEqual(denied.status, 403);
  assert.strictEqual(denied.json.code, 'ADMIN_ONLY');
  assert.strictEqual(writes.length, 0);

  user = { userId: 'adm-1', role: 'admin' };
  studentRecordRows = [{ '?column?': 1 }];
  writes = [];
  const records = await send('DELETE', `/modules/${M1}?hard=1&confirm=1`);
  assert.strictEqual(records.status, 409);
  assert.strictEqual(records.json.code, 'MODULE_HAS_STUDENT_RECORDS');
  assert.strictEqual(writes.length, 0, 'there is no confirm override for this one');
});

// ===========================================================================
// POST /:moduleId/clone — the repetition mechanism
// ===========================================================================

test('a clone ALWAYS records its lineage, and is always a draft with no window', async () => {
  moduleRows[0] = moduleRow({ module_id: M1, title: 'Scoping', release_state: 'open', cloned_from_module_id: FOREIGN });
  const res = await send('POST', `/modules/${M1}/clone`, { profile_id: P2 });
  assert.strictEqual(res.status, 201);

  const ins = writes.find((w) => /INSERT INTO ciab_module\b/i.test(w.sql) && !/prereq/i.test(w.sql));
  assert.strictEqual(ins.params[7], M1,
    'the SOURCE module id, never the source\'s own cloned_from_module_id — that would flatten '
    + 'the chain and lose a generation, and no ALTER can backfill it');
  assert.ok(ins.sql.includes("'draft', NULL::timestamptz, NULL::timestamptz"),
    'the release columns are LITERALS: a clone inheriting "open" publishes unreviewed work to the whole roster');
  assert.ok(ins.sql.includes('COALESCE((SELECT MAX(position) FROM ciab_module WHERE section_id = $1::uuid), 0) + 1'));
  assert.ok(!/SELECT MAX\(position\)[\s\S]*SELECT MAX\(position\)/.test(ins.sql), 'no separate MAX query');
  assert.strictEqual(res.json.module.release_state, 'draft');
  assert.ok(res.json.warnings.some((w) => w.code === 'RELEASE_RESET'));
  assert.deepStrictEqual(res.json.source, { section_id: SEC, module_id: M1 });
  assert.strictEqual(res.json.module.title, 'Scoping (copy)');
});

test('a clone copies only the REQUIRES edges, in one INSERT ... SELECT', async () => {
  // A requires B; C requires A. Cloning A brings the edge naming B and not the
  // one naming C — copying dependents would gate the rest of the term on
  // brand-new draft work.
  prereqRows = [
    { section_id: SEC, module_id: M1, prereq_module_id: M2 },
    { section_id: SEC, module_id: M3, prereq_module_id: M1 },
  ];
  const res = await send('POST', `/modules/${M1}/clone`, {});
  assert.strictEqual(res.status, 201);
  const edge = writes.find((w) => /INSERT INTO ciab_module_prereq/i.test(w.sql));
  assert.ok(edge, 'the edges are copied');
  assert.ok(edge.sql.includes('p.section_id = $1::uuid AND p.module_id = $4::uuid'),
    'the remap is expressed in SQL, which makes the mis-remapped-edge bug unwritable');
  assert.ok(!/prereq_module_id = \$4/.test(edge.sql), 'never the REQUIRED_BY direction');

  const insAt = writes.findIndex((w) => /INSERT INTO ciab_module\b/i.test(w.sql) && !/prereq/i.test(w.sql));
  const edgeAt = writes.indexOf(edge);
  assert.ok(insAt < edgeAt, 'the module is written BEFORE the edges');
});

test('a clone copies no gradebook', async () => {
  const res = await send('POST', `/modules/${M1}/clone`, {});
  assert.strictEqual(res.status, 201);
  assert.ok(!writes.some((w) => /INSERT INTO ciab_module_student/i.test(w.sql)),
    'a clone is new work; copying completions would mark a class done on a module they have not seen');
});

test('a failed edge copy is a 201 with a warning, never a 500', async () => {
  prereqRows = [{ section_id: SEC, module_id: M1, prereq_module_id: M2 }];
  prereqInsertFails = new Error('deadlock detected');
  const res = await send('POST', `/modules/${M1}/clone`, {});
  assert.strictEqual(res.status, 201,
    'there is no transaction; a 500 after the module row is committed tells the instructor '
    + 'nothing happened and they clone twice');
  assert.ok(res.json.warnings.some((w) => w.code === 'PREREQ_COPY_FAILED'));
  assert.strictEqual(res.json.prereqs_copied, 0);
});

test('a cross-section clone authorizes the TARGET independently and copies no edges', async () => {
  prereqRows = [{ section_id: SEC, module_id: M1, prereq_module_id: M2 }];
  const res = await send('POST', `/modules/${M1}/clone`, { target_section_id: SEC2 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(managedCalls.length, 2, 'the mount\'s gate authorised the SOURCE only');
  assert.strictEqual(managedCalls[1].sectionId, SEC2);
  assert.ok(!writes.some((w) => /INSERT INTO ciab_module_prereq/i.test(w.sql)),
    'the composite-FK 23503 is PREVENTED, not caught');
  assert.strictEqual(res.json.prereqs_copied, 0);
  assert.ok(res.json.warnings.some((w) => w.code === 'PREREQ_NOT_COPIED'));

  writes = [];
  delete managed[SEC2];
  const refused = await send('POST', `/modules/${M1}/clone`, { target_section_id: SEC2 });
  assert.strictEqual(refused.status, 403);
  assert.strictEqual(refused.json.error, 'Section not found or access denied');
  assert.strictEqual(refused.json.code, 'TARGET_SECTION_NOT_MANAGED');
  assert.strictEqual(writes.length, 0);
});

test('a 255-character source title yields 255 plus a truncation warning', async () => {
  moduleRows[0] = moduleRow({ module_id: M1, title: 'x'.repeat(255) });
  const res = await send('POST', `/modules/${M1}/clone`, {});
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.json.module.title.length, 255, '255 + " (copy)" is 262 and raises 22001');
  assert.ok(res.json.warnings.some((w) => w.code === 'TITLE_TRUNCATED'));
});

test('a clone into a colliding assessment part is refused in the TARGET', async () => {
  // Counted in the TARGET, because that is where the row lands.
  moduleRows[0] = moduleRow({ module_id: M1, profile_id: P1, assessment_part: 2, title: 'Source' });
  moduleRows.push(moduleRow({ module_id: FOREIGN, section_id: SEC2, position: 1, profile_id: P1, assessment_part: 2, title: 'Already there' }));
  const res = await send('POST', `/modules/${M1}/clone`, { target_section_id: SEC2 });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'ASSESSMENT_PART_COLLISION');
  assert.strictEqual(res.json.conflict.module_id, FOREIGN);
  assert.strictEqual(writes.length, 0);
});

test('a clone is refused at the cap, unambiguously', async () => {
  capReached = true;
  const res = await send('POST', `/modules/${M1}/clone`, {});
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'SECTION_MODULE_LIMIT');
});

// ===========================================================================
// Prerequisites
// ===========================================================================

test('a prerequisite insert targets the PRIMARY KEY and is idempotent', async () => {
  const res = await send('POST', `/modules/${M2}/prereqs`, { prereq_module_id: M1 });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.json.created, true);
  const ins = writes.find((w) => /INSERT INTO ciab_module_prereq/i.test(w.sql));
  assert.ok(ins.sql.includes('ON CONFLICT (module_id, prereq_module_id) DO NOTHING'),
    'naming three columns would be a 42P10 — there is no unique index on the triple');
  assert.ok(ins.sql.includes('VALUES ($1::uuid, $2::uuid, $3::uuid, $4::uuid)'));
});

test('the four prerequisite refusals reach the client with their own sentences', async () => {
  const self = await send('POST', `/modules/${M1}/prereqs`, { prereq_module_id: M1 });
  assert.strictEqual(self.status, 400);
  assert.strictEqual(self.json.code, 'PREREQ_SELF');

  const blank = await send('POST', `/modules/${M1}/prereqs`, { });
  assert.strictEqual(blank.status, 400);
  assert.strictEqual(blank.json.code, 'PREREQ_REQUIRED');

  const foreign = await send('POST', `/modules/${M1}/prereqs`, { prereq_module_id: FOREIGN });
  assert.strictEqual(foreign.status, 404);
  assert.strictEqual(foreign.json.code, 'PREREQ_NOT_IN_SECTION',
    'this is what prevents the composite-FK 23503, and the cycle check does not cover it');

  prereqRows = [{ section_id: SEC, module_id: M1, prereq_module_id: M2 }];
  writes = [];
  const cycle = await send('POST', `/modules/${M2}/prereqs`, { prereq_module_id: M1 });
  assert.strictEqual(cycle.status, 409);
  assert.strictEqual(cycle.json.code, 'PREREQ_CYCLE');
  assert.deepStrictEqual(cycle.json.detail.cyclic_module_ids.sort(), [M1, M2].sort());
  assert.strictEqual(writes.length, 0);
});

test('a 23503 on a prereq insert is 409 PREREQ_CROSS_SECTION, never a 500', async () => {
  prereqInsertFails = Object.assign(new Error('violates foreign key constraint'), { code: '23503' });
  const res = await send('POST', `/modules/${M2}/prereqs`, { prereq_module_id: M1 });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'PREREQ_CROSS_SECTION');
  assert.strictEqual(res.json.error, 'Both ends of a prerequisite must be modules in this section.');
});

test('DELETE of an edge is section-scoped, 404s when it removes nothing, and answers JSON', async () => {
  prereqRows = [{ section_id: SEC, module_id: M2, prereq_module_id: M1 }];
  const res = await send('DELETE', `/modules/${M2}/prereqs/${M1}`);
  assert.strictEqual(res.status, 200);
  assert.deepStrictEqual(res.json, { success: true, warnings: [] });
  const del = writes.find((w) => /DELETE FROM ciab_module_prereq/i.test(w.sql));
  assert.ok(del.sql.includes('WHERE section_id = $1::uuid AND module_id = $2::uuid AND prereq_module_id = $3::uuid'));

  const gone = await send('DELETE', `/modules/${M2}/prereqs/${M3}`);
  assert.strictEqual(gone.status, 404);
  assert.strictEqual(gone.json.code, 'PREREQ_EDGE_NOT_FOUND');
});

// ===========================================================================
// Cross-cutting
// ===========================================================================

test('the section refusal is byte-identical on EVERY verb, with zero writes', async () => {
  managed = {};
  const calls = [
    ['GET', '/modules/', undefined],
    ['POST', '/modules/', { title: 't' }],
    ['POST', '/modules/reorder', { order: [M1] }],
    ['PATCH', `/modules/${M1}`, { title: 't' }],
    ['DELETE', `/modules/${M1}`, undefined],
    ['POST', `/modules/${M1}/clone`, { }],
    ['POST', `/modules/${M1}/prereqs`, { prereq_module_id: M2 }],
    ['DELETE', `/modules/${M1}/prereqs/${M2}`, undefined],
  ];
  for (const [method, pathname, body] of calls) {
    writes = [];
    const res = await send(method, pathname, body);
    assert.strictEqual(res.status, 403, `${method} ${pathname}`);
    assert.strictEqual(res.json.error, 'Section not found or access denied',
      'the string never varies, so section ids cannot be enumerated by message');
    assert.strictEqual(res.json.code, 'SECTION_NOT_MANAGED');
    assert.strictEqual(writes.length, 0);
  }
});

test('no module is ever touched by id alone', async () => {
  await send('PATCH', `/modules/${M1}`, { title: 'x' });
  await send('DELETE', `/modules/${M2}`);
  const touching = dbCalls.filter((c) => /\bciab_module\b/.test(c.sql) && !/ciab_module_prereq|ciab_module_student/.test(c.sql));
  for (const call of touching) {
    assert.ok(/section_id/.test(call.sql),
      `every statement against ciab_module carries the section:\n${call.sql}`);
  }
});

test('every 2xx body carries warnings[], including both DELETE verbs', async () => {
  prereqRows = [{ section_id: SEC, module_id: M2, prereq_module_id: M1 }];
  const responses = await Promise.all([
    send('GET', '/modules/'),
    send('POST', '/modules/', { title: 'w' }),
    send('POST', '/modules/reorder', { order: [M1, M2, M3] }),
    send('PATCH', `/modules/${M1}`, { title: 'w' }),
    send('DELETE', `/modules/${M3}`),
    send('POST', `/modules/${M1}/clone`, { }),
    send('DELETE', `/modules/${M2}/prereqs/${M1}`),
  ]);
  for (const res of responses) {
    assert.ok(res.status < 300, `expected 2xx, saw ${res.status}: ${res.raw}`);
    assert.ok(Array.isArray(res.json.warnings), `no warnings[] in ${res.raw}`);
  }
});

test('no handler touches the enrollment cache', async () => {
  // enrollment.invalidate / invalidateAll are stubbed to THROW: this surface
  // touches neither ciab_enrollment nor ciab_section.status, so calling either
  // would surface here as a 500.
  const res = await send('DELETE', `/modules/${M1}`);
  assert.strictEqual(res.status, 200);
  assert.ok(!/invalidate/.test(ROUTE_SRC));
});


// ===========================================================================
// The defects an adjudicated review found in this phase. Each test below fails
// against the code as it was first written.
// ===========================================================================

test('a create names the module its own warnings are about', async () => {
  // The browser titles each warning toast with moduleTitle(w.module_id) and
  // falls back to 'This section' on a null id -- so a create answering
  // writeNotices(values), which carries no module_id, blamed the whole section
  // for a defect in one module, while the resolver's issues[] named the module
  // correctly on the very next repaint. The two disagreed on screen.
  const res = await send('POST', '/modules/', { title: 'Later', release_state: 'scheduled' });
  assert.strictEqual(res.status, 201);
  assert.strictEqual(res.json.warnings[0].code, S.ISSUE.SCHEDULED_WITHOUT_DATE);
  assert.strictEqual(res.json.warnings[0].module_id, res.json.module.module_id,
    'a warning about one module must carry that module id, exactly as PATCH and clone already do');
});

test('a same-section clone of a module holding a Deliverable says what to change', async () => {
  // THE HEADLINE FEATURE'S DEFAULT PATH. A same-section clone counts the
  // TARGET's modules and the target CONTAINS the source, and planClone inherits
  // assessment_part unconditionally -- so Clone, change nothing, Clone was a
  // guaranteed 409 whose sentence named "another module" and offered no remedy.
  // Only the cross-section collision was covered.
  moduleRows[0] = moduleRow({ module_id: M1, profile_id: P1, assessment_part: 2, title: 'Scoping' });
  const res = await send('POST', `/modules/${M1}/clone`, { profile_id: P1 });
  assert.strictEqual(res.status, 409, 'the rule is real: assessment_progress is UNIQUE (user, profile, part)');
  assert.strictEqual(res.json.code, 'ASSESSMENT_PART_COLLISION');
  assert.strictEqual(res.json.conflict.module_id, M1, 'the clash IS the module Clone was pressed on');
  assert.strictEqual(res.json.conflict.is_source, true);
  assert.match(res.json.error, /Pick a different client for the copy/,
    'the refusal must name the remedy, because the browser shows only err.message');
  assert.ok(!/Another module in this section/.test(res.json.error));
  assert.strictEqual(writes.length, 0);

  // AND THE REMEDY THE SENTENCE NAMES ACTUALLY WORKS. assessment_part is not
  // settable on a clone -- it inherits, unconditionally -- so the client is the
  // only field that can clear this, which is exactly why the browser now defaults
  // the clone dialog's client to blank rather than to the source's.
  const different = await send('POST', `/modules/${M1}/clone`, { profile_id: P2 });
  assert.strictEqual(different.status, 201, 'same shape, different client');
  const unbound = await send('POST', `/modules/${M1}/clone`, { profile_id: null });
  assert.strictEqual(unbound.status, 201, 'and an unbound copy is legal too');
});

test('a cross-section collision keeps the ORIGINAL sentence', async () => {
  moduleRows[0] = moduleRow({ module_id: M1, profile_id: P1, assessment_part: 2, title: 'Source' });
  moduleRows.push(moduleRow({ module_id: FOREIGN, section_id: SEC2, position: 1, profile_id: P1, assessment_part: 2, title: 'Already there' }));
  const res = await send('POST', `/modules/${M1}/clone`, { target_section_id: SEC2 });
  assert.strictEqual(res.status, 409);
  assert.match(res.json.error, /Another module in this section/);
  assert.strictEqual(res.json.conflict.is_source, false);
});

test('the clone INSERT writes exactly CLONE_COPIES plus the reset columns', async () => {
  // CLONE_COPIES is now READ by planClone, so adding a name to it changes the
  // clone. This is the other half: the statement's column list must agree, or a
  // column the plan carries is still dropped on the way to the database.
  await send('POST', `/modules/${M1}/clone`, {});
  const ins = writes.find((w) => /INSERT INTO ciab_module\b/i.test(w.sql) && !/ciab_module_prereq/i.test(w.sql));
  const columns = ins.sql.slice(ins.sql.indexOf('(') + 1, ins.sql.indexOf(')')).split(',').map((c) => c.trim());
  const expected = [
    ...admin.CLONE_COPIES,
    'section_id', 'position', 'release_state', 'release_at', 'close_at',
    'cloned_from_module_id', 'created_by', 'updated_by',
  ];
  assert.deepStrictEqual(columns.slice().sort(), expected.slice().sort(),
    'a column classified as a CLONE_COPY that the statement never names is still silently dropped');
});

test('an UPPER-CASED prerequisite cannot smuggle a loop past the cycle check', async () => {
  // buildGraph keys its map with PostgreSQL's lowercase canonical uuid and DROPS
  // an edge whose gated id is not in it, so an unfolded upper-case candidate
  // never entered the graph, the before/after diff came out equal, and the API
  // committed the exact loop it promises to refuse -- Postgres parses an
  // upper-case uuid literal happily and every constraint on the table is a value
  // comparison. The three checks before the cycle check all fold; this one did not.
  moduleRows = [
    moduleRow({ module_id: HEX_A, position: 1, title: 'Scoping' }),
    moduleRow({ module_id: HEX_B, position: 2, title: 'Assessment' }),
  ];
  prereqRows = [{ section_id: SEC, module_id: HEX_B, prereq_module_id: HEX_A }];
  const res = await send('POST', `/modules/${HEX_A.toUpperCase()}/prereqs`, { prereq_module_id: HEX_B.toUpperCase() });
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.code, 'PREREQ_CYCLE');
  assert.ok(!writes.some((w) => /INSERT INTO ciab_module_prereq/i.test(w.sql)),
    'the loop must never reach the table');
});

test('a legitimate UPPER-CASED prerequisite is inserted in NORMALIZED form', async () => {
  moduleRows = [
    moduleRow({ module_id: HEX_A, position: 1, title: 'Scoping' }),
    moduleRow({ module_id: HEX_B, position: 2, title: 'Assessment' }),
  ];
  const res = await send('POST', `/modules/${HEX_B.toUpperCase()}/prereqs`, { prereq_module_id: HEX_A.toUpperCase() });
  assert.strictEqual(res.status, 201);
  const ins = writes.find((w) => /INSERT INTO ciab_module_prereq/i.test(w.sql));
  assert.strictEqual(ins.params[1], HEX_B, 'the route writes the ids the cycle check judged, not the raw request ones');
  assert.strictEqual(ins.params[2], HEX_A);
  assert.deepStrictEqual(res.json.requires, [HEX_A]);
});

test('a repeated prerequisite is 200 with created:false, and lists the edge once', async () => {
  // ON CONFLICT DO NOTHING finding the edge already there. Three shipped paths
  // hang off this: `created = ins.rowCount > 0`, the 200-vs-201 status, and the
  // dedup guard that stops the id being pushed into `requires` twice.
  prereqEdgeExists = true;
  prereqRows = [{ section_id: SEC, module_id: M2, prereq_module_id: M1 }];
  const res = await send('POST', `/modules/${M2}/prereqs`, { prereq_module_id: M1 });
  assert.strictEqual(res.status, 200, 'an edge that already existed is idempotent, not an error');
  assert.strictEqual(res.json.created, false);
  assert.deepStrictEqual(res.json.requires, [M1], 'the id must appear exactly once');
  await settle();
  assert.strictEqual(JSON.parse(auditCalls[0].params[4]).created, false);
});

test('a reorder short of its own id count is still a 200 with the right order', async () => {
  // A concurrent delete. The statement now touches EVERY named row, so a short
  // rowCount means a row named in the order is gone -- the survivors are still
  // correctly renumbered, so this is a 200 and a log line, never a refusal the
  // instructor cannot act on.
  reorderShort = true;
  const warned = [];
  const realWarn = console.warn;
  console.warn = (msg) => warned.push(String(msg));
  try {
    const res = await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
    assert.strictEqual(res.status, 200);
    assert.deepStrictEqual(res.json.order, [M3, M1, M2]);
  } finally {
    console.warn = realWarn;
  }
  assert.ok(warned.some((w) => /reorder wrote 2 of 3/.test(w)));
});

test('`moved` is the JS-computed count, never the statement rowCount', async () => {
  // The statement no longer carries `position IS DISTINCT FROM v.pos` -- under
  // READ COMMITTED that qual meant an already-correct row was never scanned,
  // never locked and never EvalPlanQual-re-checked, so two co-instructors
  // reordering one section committed an interleaved order NEITHER asked for, as
  // a 200. rowCount is therefore n now and says nothing about how much moved.
  const res = await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
  assert.strictEqual(res.status, 200);
  assert.ok(!writes[0].sql.includes('IS DISTINCT FROM'));
  assert.strictEqual(res.json.moved, 3, 'every one of the three rows changed position');

  writes = [];
  const same = await send('POST', '/modules/reorder', { order: [M1, M2, M3] });
  assert.strictEqual(same.json.moved, 0, 'nothing moved, even though the statement matched all three');
  assert.strictEqual(writes.length, 1);
});

test('a non-uuid path segment is the documented refusal, never a 500', async () => {
  // Every one of these binds to a $n::uuid. 22P02 carries no `status`, so fail()
  // answered a generic 500 for what the contract calls a 404 or a 403 -- exactly
  // the class the /reorder shape check exists to prevent, applied to the reorder
  // body and to nothing else.
  for (const method of ['PATCH', 'DELETE']) {
    dbCalls = []; writes = [];
    const res = await send(method, '/modules/not-a-uuid', method === 'PATCH' ? { title: 'x' } : undefined);
    assert.strictEqual(res.status, 404, method);
    assert.strictEqual(res.json.error, 'That module is not in this section', method);
    assert.strictEqual(res.json.code, 'MODULE_NOT_IN_SECTION', method);
    assert.ok(!dbCalls.some((c) => /FROM ciab_module\b/i.test(c.sql) && /module_id = \$1::uuid/.test(c.sql)),
      'the malformed id must never reach the cast');
  }

  const cloned = await send('POST', '/modules/not-a-uuid/clone', {});
  assert.strictEqual(cloned.status, 404);
  assert.strictEqual(cloned.json.code, 'MODULE_NOT_IN_SECTION');

  writes = [];
  const target = await send('POST', `/modules/${M1}/clone`, { target_section_id: 'next-term' });
  assert.strictEqual(target.status, 403, 'a malformed target must not be distinguishable from an unmanaged one');
  assert.strictEqual(target.json.error, 'Section not found or access denied');
  assert.strictEqual(target.json.code, 'TARGET_SECTION_NOT_MANAGED');
  assert.strictEqual(writes.length, 0);

  dbCalls = [];
  const edge = await send('DELETE', `/modules/${M1}/prereqs/not-a-uuid`);
  assert.strictEqual(edge.status, 404);
  assert.strictEqual(edge.json.code, 'PREREQ_EDGE_NOT_FOUND');
  assert.ok(!dbCalls.some((c) => /DELETE FROM ciab_module_prereq/i.test(c.sql)));
});

test('a PATCH or an archive that loses a race reports the refusal and logs NOTHING', async () => {
  // mustModule saw the row; an admin hard delete between that SELECT and the
  // UPDATE leaves rowCount 0, and rowToModule returns null for a falsy row. The
  // instructor was told 'Saved' about a module that no longer exists, and an
  // audit row was filed for a write that never happened.
  updateMisses = true;

  const patched = await send('PATCH', `/modules/${M1}`, { title: 'Renamed' });
  assert.strictEqual(patched.status, 404);
  assert.strictEqual(patched.json.code, 'MODULE_NOT_IN_SECTION');
  await settle();
  assert.strictEqual(auditCalls.length, 0, 'nothing happened, so nothing is filed');

  const archived = await send('DELETE', `/modules/${M1}`);
  assert.strictEqual(archived.status, 404);
  assert.strictEqual(archived.json.code, 'MODULE_NOT_IN_SECTION');
  await settle();
  assert.strictEqual(auditCalls.length, 0);
});

test('every audit metadata key comes from a fixed allowlist of ids, counts and enums', async () => {
  // THE ONLY GUARD. audit-hygiene.test.js matches the shared helpers by name --
  // audit.log, logMany, batch, logActivity, auditAuth, auditProvision -- and
  // logModuleActivity is none of them, so a later author adding instructor_notes
  // (staff-only prose, never shown to a student) to a detail object would land it
  // unredacted in activity_log.metadata with the whole suite green.
  const ALLOWED = new Set([
    'section_id', 'module_id', 'release_state', 'previous_release_state', 'profile_id',
    'assessment_part', 'fields', 'count', 'moved', 'dependents', 'dependents_removed',
    'cloned_from_module_id', 'source_section_id', 'prereqs_copied', 'prereqs_requested',
    'prereq_module_id', 'created',
  ]);
  const COLUMN = /^[a-z_]+$/;

  user = { userId: 'adm-1', role: 'admin' };
  await send('POST', '/modules/', { title: 'Created', instructor_notes: 'do not leak me' });
  await send('POST', '/modules/reorder', { order: [M3, M1, M2] });
  await send('PATCH', `/modules/${M1}`, { title: 'Renamed', instructor_notes: 'do not leak me' });
  await send('POST', `/modules/${M1}/clone`, { title: 'Copy' });
  await send('POST', `/modules/${M2}/prereqs`, { prereq_module_id: M1 });
  prereqRows = [{ section_id: SEC, module_id: M2, prereq_module_id: M1 }];
  await send('DELETE', `/modules/${M2}/prereqs/${M1}`);
  await send('DELETE', `/modules/${M1}`);
  await send('DELETE', `/modules/${M3}?hard=1&confirm=1`);
  await settle();

  assert.ok(auditCalls.length >= 8, `every mutating verb files one entry, got ${auditCalls.length}`);
  for (const call of auditCalls) {
    const meta = JSON.parse(call.params[4]);
    for (const [key, value] of Object.entries(meta)) {
      assert.ok(ALLOWED.has(key), `${call.params[1]} put ${key} in activity_log.metadata`);
      if (Array.isArray(value)) {
        for (const entry of value) {
          assert.ok(COLUMN.test(entry), `${key} must be column NAMES, never values: ${entry}`);
        }
      } else {
        assert.ok(
          value === null || typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean',
          `${key} must be an id, a count, an enum value or a boolean`
        );
      }
    }
    assert.ok(!JSON.stringify(meta).includes('do not leak me'),
      'instructor_notes is staff-only prose and must never reach the audit trail');
  }
});

// ===========================================================================
// routes/sections.js — D1's second recorded obligation
// ===========================================================================

test('a section with MODULES and no enrollments can no longer be hard-deleted', async () => {
  user = { userId: 'adm-1', role: 'admin' };
  sectionHasModules = true;
  const res = await send('DELETE', `/sections/${SEC}?hard=1`);
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.error, 'This section still has modules. Archive it instead, or delete them first.');
  assert.ok(!writes.some((w) => /DELETE FROM ciab_section/i.test(w.sql)),
    'ciab_module CASCADEs from ciab_section: this delete used to answer 200 and destroy the term');
});

test('the original enrollments sentence is BYTE-INTACT', async () => {
  user = { userId: 'adm-1', role: 'admin' };
  sectionHasEnrollments = true;
  const res = await send('DELETE', `/sections/${SEC}?hard=1`);
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.error, 'This section still has enrollments. Archive it instead, or drop everyone first.');
});

test('both blockers get their own sentence, because a refusal naming the wrong one is useless', async () => {
  user = { userId: 'adm-1', role: 'admin' };
  sectionHasEnrollments = true;
  sectionHasModules = true;
  const res = await send('DELETE', `/sections/${SEC}?hard=1`);
  assert.strictEqual(res.status, 409);
  assert.strictEqual(res.json.error, 'This section still has enrollments and modules. Archive it instead.');
  assert.strictEqual(writes.length, 0);
});
