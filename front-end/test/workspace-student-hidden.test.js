/**
 * workspace-student-hidden.test.js — the CYBR 400 sensor, and the three doors
 * it has to be behind.
 *
 * A CYBR 400 lane deploys two machines to one student: the workstation they
 * work on, and the log-generator sensor the incident engine aims at. Both are
 * registered by lane-deployer.registerWorkspaceVm with an allocation to that
 * student, so before this both drew a card with an Open Console button, and
 * students logged into the emitter their own detection exercise depends on.
 *
 * WHAT THIS FILE CAN AND CANNOT PROVE
 * ----------------------------------------------------------------------------
 * The rule is a SQL predicate, and there is no Postgres here. So this suite
 * splits into two halves that are honest about which is which:
 *
 *   §1 is a real unit test of the predicate BUILDER — bind indexing, alias
 *      rejection, and the two shapes that were bugs waiting to happen: casting
 *      free-form metadata to boolean, and letting a LEFT JOIN's NULL become a
 *      row-dropping NULL in a WHERE clause.
 *
 *   §2 drives the actual Express routes with a stubbed database and asserts on
 *      the SQL TEXT AND BIND VALUES they emit per role. It does not prove
 *      Postgres agrees with the predicate; it proves the predicate reaches the
 *      student's query and stays out of the instructor's — which is the part a
 *      refactor silently breaks. A missing WHERE clause is invisible against a
 *      stub that returns rows regardless, so text is what there is to assert.
 *
 * The one thing that would make §2 pass while production is broken — the
 * expression being present but wrong — is what §1 covers, and both halves build
 * it from the same module rather than from a copied string.
 *
 * Run: node --test front-end/test/workspace-student-hidden.test.js  (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const path = require('node:path');
const http = require('node:http');
const express = require('express');
const jwt = require('jsonwebtoken');

const ROOT = path.join(__dirname, '..');

// ---------------------------------------------------------------------------
// Stubs, installed BEFORE the router is required
// ---------------------------------------------------------------------------

function stub(relPath, exports) {
  const p = require.resolve(path.join(ROOT, relPath));
  require.cache[p] = { id: p, filename: p, loaded: true, exports };
  return p;
}

/** Every statement the route ran, newest last. */
const QUERIES = [];

stub('src/utils/cybercore-db.js', {
  cybercoreQuery: async (text, params) => {
    QUERIES.push({ text, params: params || [] });
    return { rows: [], rowCount: 0 };
  },
  // Required at module load by some of the transitive requires below.
  cybercorePool: { query: async () => ({ rows: [] }) },
});

// audit.js opens a pg Pool at require time; the credential route awaits a write
// before it responds, so this has to resolve rather than merely exist.
stub('src/utils/audit.js', { log: async () => {}, redact: (m) => m });

// Guacamole and Proxmox are network clients. Nothing here reaches the point of
// calling them — the stubbed query returns no rows, so every route 404s first —
// but requiring the real ones opens sockets and reads env this suite has not set.
stub('src/utils/guacamole.js', {
  guacAPI: async () => ({}),
  guacFetchText: async () => ({ ok: false, text: '' }),
  mintGuacToken: async () => ({ authToken: 't' }),
  GUAC_DS: 'postgresql',
  GUAC_URL: 'http://guac.invalid',
});
stub('src/utils/proxmox.js', { proxmoxAPI: async () => ({ data: {} }) });

process.env.JWT_SECRET = 'workspace-student-hidden-test-secret';
// The list route returns `{vms: []}` unconditionally when Guacamole is off, and
// would never build a query at all.
process.env.GUAC_ENABLED = 'true';

const visibility = require(path.join(ROOT, 'src', 'utils', 'workspace-visibility.js'));
const guacSessions = require(path.join(ROOT, 'src', 'routes', 'guac-sessions.js'));

// ---------------------------------------------------------------------------
// §1 — the predicate builder
// ---------------------------------------------------------------------------

test('§1 the sensor role hint is what hides a machine, by default and alone', () => {
  assert.deepStrictEqual([...visibility.HIDDEN_ROLE_HINTS], ['loggen']);
  // The SIEMs are where students do the work. Hiding either would hide the lab.
  assert.ok(!visibility.HIDDEN_ROLE_HINTS.includes('elk'));
  assert.ok(!visibility.HIDDEN_ROLE_HINTS.includes('wazuh'));
});

test('§1 both lists are bound, on consecutive placeholders, never interpolated', () => {
  const sql = visibility.studentHiddenSql({ param: 2 });
  assert.match(sql, /role_hints && \$2::text\[\]/);
  assert.match(sql, /template_key = ANY\(\$3::text\[\]\)/);
  assert.ok(!sql.includes('loggen'), 'the hint list must not appear in the SQL text');
  // hiddenBindValues() supplies them in that order. A caller binding one value
  // for two placeholders is a runtime error on the student path only.
  assert.deepStrictEqual(
    visibility.hiddenBindValues(),
    [visibility.HIDDEN_ROLE_HINTS, visibility.HIDDEN_TEMPLATE_KEYS]
  );
});

test('§1 an env-pinned sensor is hidden even with nothing tagged', () => {
  // role_hints has NO admin UI, so an untagged catalog is the normal first-time
  // state and a site that pinned CYBR400_LOGGEN_TEMPLATE_KEY instead would
  // otherwise have a perfectly identified sensor this file could not see.
  const sql = visibility.studentHiddenSql({ param: 1 });
  assert.match(sql, /template_key = ANY/);
  // Unset here, so the list is empty — and `= ANY('{}')` is FALSE, never NULL,
  // which is what keeps an unconfigured site behaving exactly as before.
  assert.deepStrictEqual([...visibility.HIDDEN_TEMPLATE_KEYS], []);
});

test('§1 a bad bind index is refused rather than emitted', () => {
  for (const bad of [undefined, null, 0, -1, '1; DROP TABLE cybercore_resource', 'x']) {
    assert.throws(() => visibility.studentHiddenSql({ param: bad }), /bad bind index/);
  }
  // '$3' and 3 are the same request, spelled two ways.
  assert.strictEqual(
    visibility.studentHiddenSql({ param: '$3' }),
    visibility.studentHiddenSql({ param: 3 })
  );
});

test('§1 a non-identifier alias is refused rather than emitted', () => {
  assert.throws(() => visibility.studentHiddenSql({ param: 1, resource: 'r; --' }), /refusing/);
  assert.throws(() => visibility.studentHiddenSql({ param: 1, catalog: '1tc' }), /refusing/);
  assert.throws(() => visibility.catalogJoinSql({ resource: 'r)' }), /refusing/);
});

test('§1 the metadata override is compared as text, never cast to boolean', () => {
  const sql = visibility.studentHiddenSql({ param: 1 });
  // `(metadata->>'student_hidden')::boolean` throws 22P02 on any value that is
  // not boolean-ish. metadata is free-form JSONB that nothing validates, so one
  // row reading "yes" would 500 every workspace list on the site.
  assert.ok(!/student_hidden'\s*\)?::boolean/.test(sql), sql);
  assert.match(sql, /metadata->>'student_hidden' = 'true'/);
  assert.match(sql, /metadata->>'student_hidden' = 'false'/);
});

test('§1 a missing catalog row cannot make the predicate NULL', () => {
  // catalogJoinSql is a LEFT JOIN, so role_hints is NULL for every resource
  // without catalog_template_id — which includes everything registered by
  // challenge-lane-deployer.js. `NULL && ...` is NULL, `NOT NULL` is NULL, and
  // a NULL WHERE drops the row: without the COALESCE those machines would
  // silently vanish from every student's list.
  const sql = visibility.studentHiddenSql({ param: 1 });
  assert.match(sql, /COALESCE\(\s*tc\.role_hints && \$1::text\[\], FALSE\s*\)/);
  assert.match(sql, /COALESCE\(\s*tc\.template_key = ANY\(\$2::text\[\]\), FALSE\s*\)/);
  assert.match(visibility.catalogJoinSql(), /^LEFT JOIN cybercore_template_catalog/);
});

// ---------------------------------------------------------------------------
// §2 — the three doors
// ---------------------------------------------------------------------------

const app = express();
app.use(express.json());
app.use('/api/dashboard', guacSessions);
const server = app.listen(0);
test.after(() => server.close());

function token(role) {
  return jwt.sign(
    { userId: `00000000-0000-4000-8000-00000000000${role === 'student' ? 1 : 2}`, role },
    process.env.JWT_SECRET
  );
}

function call(method, url, role) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      host: '127.0.0.1', port: server.address().port, method, path: url,
      headers: { Authorization: `Bearer ${token(role)}`, 'Content-Type': 'application/json' },
    }, (res) => {
      let body = '';
      res.on('data', (c) => { body += c; });
      res.on('end', () => resolve({ status: res.statusCode, body }));
    });
    req.on('error', reject);
    req.end();
  });
}

/** The statements one request produced. */
async function queriesFor(method, url, role) {
  QUERIES.length = 0;
  await call(method, url, role);
  return QUERIES.slice();
}

const HIDDEN_PREDICATE = /AND NOT \(CASE/;
const VMID = '11111111-2222-4333-8444-555555555555';

test('§2 door 1: a student\'s workspace list excludes hidden machines', async () => {
  const [q] = await queriesFor('GET', '/api/dashboard/vms', 'student');
  assert.match(q.text, HIDDEN_PREDICATE);
  assert.deepStrictEqual(q.params.slice(-2), visibility.hiddenBindValues());
});

test('§2 door 2: a student cannot open a hidden machine\'s console', async () => {
  // Filtering the list alone is decluttering, not hiding — a vmId from a
  // bookmark, or from a page open since before this landed, still launches.
  const [q] = await queriesFor('POST', `/api/dashboard/vms/${VMID}/guac-session`, 'student');
  assert.match(q.text, HIDDEN_PREDICATE);
  assert.deepStrictEqual(q.params.slice(-2), visibility.hiddenBindValues());
});

test('§2 door 3: a student cannot read a hidden machine\'s password', async () => {
  const [q] = await queriesFor('GET', `/api/dashboard/vms/${VMID}/credentials`, 'student');
  assert.match(q.text, HIDDEN_PREDICATE);
  assert.deepStrictEqual(q.params.slice(-2), visibility.hiddenBindValues());
});

test('§2 every door\'s bind count matches its placeholders', async () => {
  // Postgres rejects a bind supplying more parameters than the statement
  // references. The predicate consumes TWO consecutive placeholders, and the
  // credential reader builds it conditionally — so the privileged form must
  // drop $3 AND $4 along with the clause that used them. Getting either wrong
  // turns a relaxation into a 500 on a path no unit test would otherwise walk.
  const reqs = [
    ['GET',  '/api/dashboard/vms',                              'student'],
    ['GET',  '/api/dashboard/vms',                              'instructor'],
    ['GET',  '/api/dashboard/vms?scope=mine',                   'instructor'],
    ['POST', `/api/dashboard/vms/${VMID}/guac-session`,          'student'],
    ['POST', `/api/dashboard/vms/${VMID}/guac-session`,          'instructor'],
    ['GET',  `/api/dashboard/vms/${VMID}/credentials`,           'student'],
    ['GET',  `/api/dashboard/vms/${VMID}/credentials`,           'instructor'],
    ['GET',  `/api/dashboard/vms/${VMID}/credentials`,           'admin'],
  ];
  for (const [method, url, role] of reqs) {
    for (const q of await queriesFor(method, url, role)) {
      const highest = [...q.text.matchAll(/\$(\d+)/g)]
        .reduce((max, m) => Math.max(max, Number(m[1])), 0);
      assert.strictEqual(
        q.params.length, highest,
        `${method} ${url} as ${role}: bound ${q.params.length} params for $1..$${highest}`
      );
    }
  }
});

test('§2 instructors and admins are not filtered, on either scope', async () => {
  for (const role of ['instructor', 'admin']) {
    for (const url of ['/api/dashboard/vms', '/api/dashboard/vms?scope=mine']) {
      const [q] = await queriesFor('GET', url, role);
      assert.doesNotMatch(
        q.text, HIDDEN_PREDICATE,
        `${role} on ${url} must see the sensor — it is theirs to restart when it stops`
      );
      // ...but the flag is selected, so the card can say so.
      assert.match(q.text, /AS student_hidden/);
    }

    const [launch] = await queriesFor('POST', `/api/dashboard/vms/${VMID}/guac-session`, role);
    assert.doesNotMatch(launch.text, HIDDEN_PREDICATE);

    const [cred] = await queriesFor('GET', `/api/dashboard/vms/${VMID}/credentials`, role);
    assert.doesNotMatch(cred.text, HIDDEN_PREDICATE);
  }
});

test('§2 the student list still ships no studentHidden flag', async () => {
  // Telling a student "one machine was withheld" is the same disclosure the
  // filter exists to prevent, dressed as a courtesy. The field is
  // privileged-only in the row mapper; this pins that the query it comes from
  // is the only place it is decided.
  const res = await call('GET', '/api/dashboard/vms', 'student');
  const body = JSON.parse(res.body);
  assert.deepStrictEqual(body.vms, []);
  assert.ok(!('studentHidden' in body));
});

// ---------------------------------------------------------------------------
// §3 — the fourth door: Guacamole itself
// ---------------------------------------------------------------------------
//
// The three doors above are CyberCore's. Guacamole has its own: the
// console-launch route hands the browser a SCOPED PER-USER Guac token, and a
// student holding one can open /guac directly and see every connection their
// Guac account has READ on. So the deploy must not grant that READ for lab
// infrastructure — filtering only CyberCore's surfaces hides the machine from
// the app, not from the student.

test('§3 a sensor template is recognised by tag, by key, and by neither', () => {
  const { isHiddenTemplateRow } = visibility;
  assert.strictEqual(isHiddenTemplateRow({ role_hints: ['loggen'] }), true);
  assert.strictEqual(isHiddenTemplateRow({ role_hints: ['web', 'loggen'] }), true);
  assert.strictEqual(isHiddenTemplateRow({ role_hints: ['elk'] }), false);
  assert.strictEqual(isHiddenTemplateRow({ role_hints: [] }), false);
  // The SIEM is where students work. Getting this backwards hides the lab.
  assert.strictEqual(isHiddenTemplateRow({ role_hints: ['wazuh'] }), false);
  assert.strictEqual(isHiddenTemplateRow(null), false);
  // A row that simply did not select role_hints must not read as "not hidden" —
  // it reads as no evidence, and lane-deployer looks the column up instead.
  assert.strictEqual(isHiddenTemplateRow({ template_key: 'cybr400-loggen-template' }), false);
});

test('§3 the pure predicate and the SQL one name the same two inputs', () => {
  // They are two implementations of one rule — one for a row in hand at deploy
  // time, one for a row in the database at read time. Divergence would mean a
  // machine hidden from the list but still granted in Guacamole, or the reverse.
  const sql = visibility.studentHiddenSql({ param: 1 });
  assert.match(sql, /role_hints/);
  assert.match(sql, /template_key/);
  assert.strictEqual(
    visibility.isHiddenTemplateRow({ role_hints: [...visibility.HIDDEN_ROLE_HINTS] }),
    visibility.HIDDEN_ROLE_HINTS.length > 0
  );
});
