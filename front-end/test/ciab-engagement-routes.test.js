/**
 * ciab-engagement-routes.test.js — Track B, phase B1a: the engagement MODEL
 * over HTTP.
 *
 * B0 shipped the model, the writer and the compiler. None of it had a route.
 * This file pins the route surface that B1a added at
 * modules/crucible/plugins/ciab/routes/engagements.js.
 *
 * SOURCE SCANS ABOVE, EXECUTED BEHAVIOUR BELOW — AND WHY BOTH.
 * Requiring the router pulls the whole plugin graph behind it — profile-deploy,
 * the batch lane deployer, the vuln-app generator, two database pools — none of
 * which exists in this checkout, which is why sections 1-10 read properties off
 * the file's text. A scan proves the code SAYS the right thing, not that it
 * DOES it: it cannot see a wrong status code, an unvalidated body or a broken
 * response shape, and every finding this file was extended for was exactly one
 * of those. A reviewer put the gap plainly — for a while, not one shipping line
 * of the router was ever RUN by this suite.
 *
 * So sections 11 and 12 replace the graph in require.cache and drive the REAL
 * router, with the REAL vocabulary, the REAL sanitizer and the REAL validator,
 * asserting on status codes and response bodies. Between them they execute
 * every handler in the file and every branch of its error renderer.
 * `node --test "test/*.test.js"` gives every file its own process, so that
 * cache write cannot reach another test file.
 *
 * The scans are kept rather than replaced. The two instruments answer different
 * questions: a scan pins a property over the WHOLE file at once ("no route
 * anywhere forgets its requireRole", "no audit call anywhere spreads the body"),
 * including code a future handler adds that no existing test calls. An executed
 * test pins what one call actually returns. Neither subsumes the other.
 *
 * THE PROPERTIES, AND WHY EACH ONE EARNS A TEST:
 *
 *   1. ONE error renderer that reads BOTH `status` and `statusCode`. The two
 *      producers this file calls disagree about the property name, and
 *      routes/profile-deploy.js:608 reads only one half — which is exactly why
 *      assertEngagementDeployable's 409 renders as a bare 500 there today.
 *   2. JSON on every path. public/js/app.js:38 calls response.json()
 *      unconditionally on a failure, so a body that is not JSON becomes
 *      APIError('Network error', 0) and the real status never reaches a handler.
 *   3. Role gating is per-route and exact. There is no requireCiabAccess on the
 *      /api/instructor mount, so a route that forgets its own requireRole is
 *      open to every authenticated user. The instructor/admin split is not
 *      cosmetic: CREATE and REPROVISION burn a VXLAN block the allocator can
 *      never hand back.
 *   4. resolveEngagement is called from POST /adopt and nowhere else. It falls
 *      through to adoptExistingReservation, which INSERTs. A read that writes is
 *      not a read.
 *   5. No DELETE, at all. ciab_module.engagement_type is a bare VARCHAR with no
 *      foreign key, so a hard delete silently orphans every module naming that
 *      (profile_id, engagement_type) pair with nothing able to notice.
 *   6. Registration order. '/types' and '/adopt' must be registered before
 *      '/:engagementId', or Express binds engagementId = 'types'.
 *   7. The audit rows carry names and counts, never a credential and never a
 *      spread of the request body. test/audit-hygiene.test.js is a source
 *      literal check over eleven identifiers and CANNOT SEE A SPREAD, so a
 *      spread there is not caught, merely unnoticed.
 *   8. The PATCH allowlist is exactly seven fields, and the two omissions
 *      (allowed_techniques, asset_selection) are the load-bearing part.
 *   9. project() strips challenge_key and challenge_id, so the page cannot
 *      render one even by accident.
 *  10. CREATE REFUSES AN UNKNOWN ENGAGEMENT TYPE. sanitizeEngagementType is a
 *      coercer, not a validator, and describeEngagementType is total by design —
 *      so one transposed character used to answer 202, carve a VXLAN block the
 *      allocator can never hand back, and store the OPPOSITE perspective. The
 *      refusal is one route handler, not an allowlist: B0 built the vocabulary
 *      as a REGISTRY and a custom slug stays expressible behind an explicit
 *      allow_custom_type.
 *  11. A malformed uuid (SQLSTATE 22P02) is a 400 that does not echo the
 *      offending input back — pg's message quotes it verbatim.
 *  12. The unadopted-reservation probe runs on EVERY list, not only an empty
 *      one, and a probe that COULD NOT RUN is reported as such rather than as
 *      "nothing is reserved" — which is how an outage becomes a second carve.
 *
 *  13. THE REST OF THE HANDLERS, EXECUTED (section 12). A PATCH the validator
 *      refuses renders as a 400 carrying its errors, not a 500 — and the route's
 *      own allowlist means a secret-shaped key never reaches the writer at all.
 *      The role split is enforced, not merely written down. Retiring needs
 *      confirm and records that NOTHING was released; force is a literal true
 *      and not a truthy string. A failed NAME is not a failed CREATE, because a
 *      500 there reads as "press Create again" and the block is already gone.
 *      resolveEngagement is reached from POST /adopt and from no other call.
 *      Every error path answers JSON with the right status: both property names,
 *      42P01 as a 503, and an unexpected pg error still a 500.
 *
 * And 12b, which is neither a route property nor optional: no audit metadata
 * KEY may match audit.js's SECRET_KEY_RE. That regex tests the KEY, not the
 * value, and it contains a bare `cred` — so `credential_slots: 2` was stored as
 * the string "[redacted]". The fix is always the key name here; the redactor is
 * shared core and is never weakened to make a test pass.
 *
 * Run: node --test front-end/test/ciab-engagement-routes.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const ROUTES_FILE = path.join(CIAB, 'routes', 'engagements.js');
const INSTRUCTOR_ROUTES = path.join(CIAB, 'routes', 'instructor.js');
const AUDIT_FILE = path.join(ROOT, 'src', 'utils', 'audit.js');

const SRC = fs.readFileSync(ROUTES_FILE, 'utf8');

// This checkout is not consistently one newline convention, so every scan that
// works line by line splits on a CRLF-tolerant boundary rather than '\n'.
const LINES = SRC.split(/\r?\n/);

// ── Small source-reading helpers ────────────────────────────────────────────

/**
 * The text between a call's opening paren and its match, quote- and
 * comment-aware. A naive indexOf(')') stops inside the first string containing
 * a paren, and this file's comments are full of them.
 */
function callSlice(src, startIndex) {
  const open = src.indexOf('(', startIndex);
  if (open === -1) return '';
  let depth = 0;
  let quote = null;
  for (let i = open; i < src.length; i += 1) {
    const c = src[i];
    const prev = src[i - 1];
    if (quote) {
      if (c === quote && prev !== '\\') quote = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(') depth += 1;
    else if (c === ')') {
      depth -= 1;
      if (depth === 0) return src.slice(open + 1, i);
    }
  }
  return '';
}

/** Every index at which `needle` occurs. */
function allIndexes(src, needle) {
  const out = [];
  let i = src.indexOf(needle);
  while (i !== -1) { out.push(i); i = src.indexOf(needle, i + 1); }
  return out;
}

/** Source lines with `//` and `*`-continuation comment lines removed. */
const CODE_LINES = LINES.filter((l) => {
  const t = l.trim();
  return t && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
});
const CODE = CODE_LINES.join('\n');

/**
 * Every route registration, as { method, routePath, gate, index }.
 * Deliberately reads the GATE ARGUMENT POSITIONALLY rather than trusting a
 * comment: the question is what Express is actually handed.
 */
function routeRegistrations() {
  const out = [];
  const re = /router\.(get|post|patch|put|delete)\(\s*'([^']*)'\s*,\s*([A-Za-z_$][\w$]*)/g;
  let m = re.exec(SRC);
  while (m) {
    out.push({ method: m[1].toUpperCase(), routePath: m[2], gate: m[3], index: m.index });
    m = re.exec(SRC);
  }
  return out;
}

// ── 1. The one error renderer ───────────────────────────────────────────────

test('B1a-R1: sendErr reads BOTH err.status and err.statusCode', () => {
  // engagement-provision.js throws `status`; loadProfileForDeploy throws
  // `statusCode`. Either half alone silently flattens one producer's real
  // status to 500 — the live defect at routes/profile-deploy.js:608.
  assert.ok(
    /err\.status\s*\|\|\s*err\.statusCode/.test(SRC),
    'sendErr must read err.status || err.statusCode, in that order'
  );
  assert.ok(
    !/err\.statusCode\s*\|\|\s*500/.test(CODE),
    'err.statusCode || 500 alone flattens engagement-provision.js\'s 409/404 to 500'
  );
  assert.ok(
    !/err\.status\s*\|\|\s*500/.test(CODE),
    'err.status || 500 alone flattens loadProfileForDeploy\'s 404/422 to 500'
  );
});

test('B1a-R2: there is exactly ONE error renderer, and every catch uses it', () => {
  const definitions = allIndexes(CODE, 'function sendErr(');
  assert.strictEqual(definitions.length, 1, 'exactly one sendErr definition');

  // Every catch block in the routes hands its error to sendErr rather than
  // inventing a second shape. Counting is enough: the file has no other
  // catch-and-respond form, and a new one would push the counts apart.
  const catches = (CODE.match(/\}\s*catch\s*\(/g) || []).length;
  const sends = (CODE.match(/sendErr\(res,/g) || []).length;
  assert.ok(catches >= 8, `expected a catch per route, saw ${catches}`);
  assert.ok(
    sends >= catches - 1,
    `every route catch must render through sendErr (catches=${catches}, sendErr=${sends})`
  );
});

test('B1a-R3: a missing relation answers 503 with a named remedy, not a bare 500', () => {
  // The plugin re-runs its own migrations on every boot and only console.errors
  // a failure, so a missing table is a DEPLOY state, not a request bug. 500
  // reads as "the server is broken" and sends an operator looking in the wrong
  // place.
  //
  // NOTE, for whoever lands B1b: the plan drafted this branch as
  // code:'DOCUMENT_STORE_MISSING' naming migration 020. Migration 020 does not
  // exist in B1a, so in B1a a 42P01 can only mean ciab_engagement is absent and
  // that string would send an operator hunting a boot-log line that cannot be
  // there. The branch answers ENGAGEMENT_STORE_MISSING instead. When 020 lands,
  // this branch has to distinguish the two stores and this assertion widens.
  const idx = SRC.indexOf("'42P01'");
  assert.ok(idx !== -1, 'sendErr must special-case the undefined-table SQLSTATE');
  const branch = SRC.slice(idx, idx + 900);
  assert.ok(/res\.status\(503\)\.json\(/.test(branch), '42P01 renders as 503 JSON');
  assert.ok(/code:\s*'[A-Z_]+'/.test(branch), 'the 503 body names a machine-readable code');
  assert.ok(
    !/migration 020/i.test(branch),
    'B1a must not name a migration that does not exist in B1a'
  );
});

// ── 2. JSON on every path ───────────────────────────────────────────────────

test('B1a-R4: every reply is JSON — no status-only reply, no res.send', () => {
  // public/js/app.js:38 calls response.json() unconditionally on a failure. A
  // body that is not JSON becomes APIError('Network error', 0) and the status —
  // and any remedy the body carried — is lost before a handler sees it.
  assert.ok(!/\.end\(\s*\)/.test(CODE), 'no status-only reply');
  assert.ok(!/res\.send\(/.test(CODE), 'no res.send — res.json only');
  assert.ok(!/res\.sendStatus\(/.test(CODE), 'no res.sendStatus');
  assert.ok(!/res\.redirect\(/.test(CODE), 'no redirect from a JSON API');

  // Every res.status(n) in the file is followed by .json(.
  const statuses = (CODE.match(/res\.status\(\s*\d+\s*\)/g) || []).length;
  const statusJson = (CODE.match(/res\.status\(\s*\d+\s*\)\.json\(/g) || []).length;
  assert.strictEqual(statusJson, statuses, 'every res.status(n) is followed by .json(');
});

// ── 3. Role gating ──────────────────────────────────────────────────────────

test('B1a-R5: every route carries its own requireRole, with the exact split', () => {
  // There is no requireCiabAccess and no checkSchedule on the /api/instructor
  // mount, so a route that omits its gate is open to every authenticated user,
  // students included.
  //
  // instructorOnly  reads and authoring — the daily work of the person teaching.
  // adminOnly       CREATE, ADOPT, REPROVISION, RETIRE. Creating one burns a
  //                 VXLAN block permanently (25-50 serial VNet POSTs plus a
  //                 cluster-wide SDN apply, and the allocator only climbs).
  const expected = {
    'GET /types': 'instructorOnly',
    'GET /': 'instructorOnly',
    'GET /:engagementId': 'instructorOnly',
    'PATCH /:engagementId': 'instructorOnly',
    'POST /': 'adminOnly',
    'POST /adopt': 'adminOnly',
    'POST /:engagementId/reprovision': 'adminOnly',
    'POST /:engagementId/retire': 'adminOnly',
    // Track E (E3). instructorOnly, and that is the same call PATCH makes:
    // choosing which SIEM an environment runs is authoring, not capacity. It
    // carves nothing, spends no VXLAN id, and setEngagementTelemetryPlan
    // re-derives the one field an instructor must not author.
    'PUT /:engagementId/telemetry': 'instructorOnly',
  };

  const seen = {};
  for (const r of routeRegistrations()) seen[`${r.method} ${r.routePath}`] = r.gate;

  assert.deepStrictEqual(
    Object.keys(seen).sort(), Object.keys(expected).sort(),
    "the engagement route surface is exactly these routes — B1a's eight plus E3's telemetry writer"
  );
  for (const key of Object.keys(expected)) {
    assert.strictEqual(seen[key], expected[key], `${key} must be ${expected[key]}`);
  }
});

test('B1a-R6: the two gates are built from requireRole, and admin is not instructor', () => {
  assert.ok(
    /const\s+instructorOnly\s*=\s*requireRole\(\s*'instructor'\s*,\s*'admin'\s*\)/.test(SRC),
    "instructorOnly is requireRole('instructor', 'admin')"
  );
  assert.ok(
    /const\s+adminOnly\s*=\s*requireRole\(\s*'admin'\s*\)/.test(SRC),
    "adminOnly is requireRole('admin') — and nothing else"
  );
  // A client-side role test is never the gate. `can` is advice for drawing
  // buttons; requireRole is the gate.
  assert.ok(!/isRealAdmin/.test(SRC), 'no client-side admin test in a route file');
});

test('B1a-R7: the router is mounted from routes/instructor.js, above every route', () => {
  // Mounting here rather than in routes/api.js is what keeps that shared file
  // at zero diff while several tracks edit it at once. The mount must sit ABOVE
  // every route in instructor.js, or a later '/:param' path shadows it.
  const src = fs.readFileSync(INSTRUCTOR_ROUTES, 'utf8');
  const mount = src.indexOf("router.use('/engagements'");
  assert.ok(mount !== -1, 'routes/instructor.js mounts the engagements router');

  const firstRoute = src.search(/router\.(get|post|patch|put|delete)\(/);
  assert.ok(firstRoute !== -1, 'instructor.js has routes of its own');
  assert.ok(mount < firstRoute, 'the sub-mount is registered above every route in the file');

  // And nothing in instructor.js claims a top-level path beginning /engagements,
  // which is what makes the sub-mount shadow nothing.
  const re = /router\.(?:get|post|patch|put|delete)\(\s*'(\/[^']*)'/g;
  let m = re.exec(src);
  while (m) {
    assert.ok(
      !m[1].startsWith('/engagements'),
      `instructor.js route ${m[1]} would collide with the sub-mount`
    );
    m = re.exec(src);
  }
});

// ── 4. The read that must not write ─────────────────────────────────────────

test('B1a-R8: resolveEngagement is CALLED from POST /adopt and nowhere else', () => {
  // resolveEngagement falls through to adoptExistingReservation, which INSERTs.
  // The existing admin GET does exactly that, which is why a read there has a
  // write in it. Here the write is an explicit, audited, admin-confirmed POST.
  const calls = allIndexes(CODE, 'resolveEngagement(');
  assert.strictEqual(calls.length, 1, 'exactly one resolveEngagement call site');

  const regs = routeRegistrations();
  const adopt = regs.find((r) => r.method === 'POST' && r.routePath === '/adopt');
  assert.ok(adopt, 'POST /adopt exists');
  const after = regs
    .filter((r) => r.index > adopt.index)
    .sort((a, b) => a.index - b.index)[0];
  const callIndex = SRC.indexOf('resolveEngagement(', SRC.indexOf("'/adopt'"));
  assert.ok(callIndex > adopt.index, 'the call is inside the /adopt handler');
  assert.ok(
    !after || callIndex < after.index,
    'the call does not spill into the route registered after /adopt'
  );

  // The list route reads with listEngagements only.
  const listIdx = SRC.indexOf("router.get('/',");
  assert.ok(listIdx !== -1, "GET '/' exists");
  const listBody = SRC.slice(listIdx, SRC.indexOf('router.', listIdx + 10));
  assert.ok(/listEngagements\(/.test(listBody), 'the list route calls listEngagements');
  assert.ok(!/resolveEngagement\(/.test(listBody), 'the list route never resolves');

  // The unadopted probe is the pure SELECT half of the adopt path.
  assert.ok(
    /findProfileChallenge\(/.test(listBody),
    'the list route probes for an unadopted reservation — the capacity branch depends on it'
  );
});

test('B1a-R9: engagement_type is read and written only through sanitizeEngagementType', () => {
  // The slug is baked into the reservation key, and the canonical identity of
  // an environment is the pair (profile_id, sanitized type). A raw slug written
  // here produces a row nothing else can ever join to.
  const writes = allIndexes(CODE, 'body.engagement_type');
  assert.ok(writes.length > 0, 'the create and adopt routes read a type from the body');
  for (const i of writes) {
    const line = CODE.slice(CODE.lastIndexOf('\n', i) + 1, CODE.indexOf('\n', i));
    assert.ok(
      /sanitizeEngagementType\(/.test(line),
      `a raw body engagement_type must go through sanitizeEngagementType: ${line.trim()}`
    );
  }
});

// ── 5. No DELETE ────────────────────────────────────────────────────────────

test('B1a-R10: there is no DELETE route, and retirement needs confirm:true', () => {
  assert.ok(!/router\.delete\(/.test(SRC), 'no DELETE route in B1a, at all');

  const retire = SRC.indexOf("'/:engagementId/retire'");
  assert.ok(retire !== -1, 'the retire route exists');
  const body = SRC.slice(retire, retire + 1400);
  assert.ok(/confirm\s*!==\s*true/.test(body), 'retire refuses without confirm: true');
  assert.ok(/res\.status\(400\)\.json\(/.test(body), 'the refusal is a 400 with a JSON body');
  // The 400 body is written to be shown to the operator verbatim: retiring
  // marks the row, it does NOT hand the carved block back. If that sentence is
  // softened, instructors retire expecting capacity and hit the ceiling anyway.
  assert.ok(
    /does NOT hand its reserved network back|not hand its reserved network back/.test(body),
    'the refusal body states plainly that retiring releases nothing'
  );
});

// ── 6. Registration order ───────────────────────────────────────────────────

test('B1a-R11: /types and /adopt are registered before /:engagementId', () => {
  // Otherwise Express binds engagementId = 'types' and the registry read becomes
  // a 404 for an engagement nobody asked for.
  const types = SRC.indexOf("'/types'");
  const adopt = SRC.indexOf("'/adopt'");
  const param = SRC.indexOf("'/:engagementId'");
  assert.ok(types !== -1 && adopt !== -1 && param !== -1, 'all three paths are present');
  assert.ok(types < param, "'/types' is registered before '/:engagementId'");
  assert.ok(adopt < param, "'/adopt' is registered before '/:engagementId'");
});

// ── 7. Audit hygiene ────────────────────────────────────────────────────────

test('B1a-R12: audit rows carry names and counts, never a credential or a body spread', () => {
  // redact() blanks issued_credentials wholesale because the key matches /cred/,
  // which makes the row useless rather than safe — while a FLATTENED credential
  // entry keeps username, target_vm, privilege and above all `note`, none of
  // which redact() matches, in a plaintext table published on adminer.
  //
  // audit.js also caps a serialized metadata object at 16KB and DISCARDS IT
  // WHOLE past that, so dumping a model here would lose profile_id with it.
  const slices = allIndexes(CODE, 'audit.log(').map((i) => callSlice(CODE, i));
  assert.ok(slices.length >= 4, `expected an audit call per write route, saw ${slices.length}`);

  for (const slice of slices) {
    assert.ok(!/issued_credentials\s*:/.test(slice), 'no credential list in an audit row');
    assert.ok(!/\.{3}\s*patch\b/.test(slice), 'no spread of the patch into metadata');
    assert.ok(!/\.{3}\s*body\b/.test(slice), 'no spread of the body into metadata');
    assert.ok(!/changes\s*:/.test(slice), 'no before/after changes block');
    assert.ok(!/req\.body/.test(slice), 'the request body never reaches an audit row');
    assert.ok(!/password|secret|token/i.test(slice), 'nothing secret-shaped in an audit row');
    assert.ok(/action:\s*'profile_engagement\./.test(slice), 'every action uses the profile_engagement prefix');
  }

  // The PATCH row names WHICH fields changed — a count of nothing is not an
  // audit trail — and counts everything else.
  const updated = slices.find((s) => /profile_engagement\.model_updated/.test(s));
  assert.ok(updated, 'the PATCH route writes profile_engagement.model_updated');
  assert.ok(/fields:\s*Object\.keys\(patch\)/.test(updated), 'the PATCH row records the field NAMES');
  assert.ok(/issued_account_slots:/.test(updated), 'and the account COUNT, not the credentials');
  assert.ok(/brief_chars:/.test(updated), 'and the brief LENGTH, not the brief');
});

test('B1a-R12b: no audit metadata KEY is eaten by audit.js\'s own redactor', () => {
  // redact() (audit.js) tests SECRET_KEY_RE against the KEY, not the value, and
  // that regex contains a bare `cred`. So `credential_slots: 2` — the one number
  // in the PATCH row that is safe by construction — was being STORED as the
  // string "[redacted]": the count survived the design review and then died in
  // the writer, silently, with the row still looking complete.
  //
  // The regex is read out of audit.js rather than copied, so this test tracks
  // the real redactor. The fix for a hit is ALWAYS the key name here: that
  // regex is shared core, it is on CLE's path, and every other key it catches
  // it catches correctly. Never weaken it to make this pass.
  const auditSrc = fs.readFileSync(AUDIT_FILE, 'utf8');
  const m = auditSrc.match(/const SECRET_KEY_RE\s*=\s*\/(.+)\/([a-z]*);/);
  assert.ok(m, 'SECRET_KEY_RE is still declared in audit.js — if not, retarget this test');
  const SECRET_KEY_RE = new RegExp(m[1], m[2]);

  const slices = allIndexes(CODE, 'audit.log(').map((i) => callSlice(CODE, i));
  assert.ok(slices.length >= 4, 'an audit call per write route');

  for (const slice of slices) {
    const metaIdx = slice.indexOf('metadata:');
    assert.ok(metaIdx !== -1, 'every audit row carries metadata');
    const meta = slice.slice(metaIdx);
    // Object keys are `identifier:` at a line start, which is enough here:
    // every metadata key in this file is written as a plain identifier.
    const keys = (meta.match(/^\s*([A-Za-z_$][\w$]*)\s*:/gm) || [])
      .map((k) => k.trim().replace(/:$/, ''))
      .filter((k) => k !== 'metadata');
    assert.ok(keys.length > 0, 'metadata has keys');
    for (const key of keys) {
      assert.ok(
        !SECRET_KEY_RE.test(key),
        `audit metadata key "${key}" matches audit.js's SECRET_KEY_RE and would `
        + 'be stored as "[redacted]". Rename the key — never weaken the redactor.'
      );
    }
  }
});

test('B1a-R13: profile_engagement has a category, so these rows do not file under config', () => {
  // routes/profile-deploy.js already emits profile_engagement.created and
  // .reprovisioned, and CATEGORY_BY_PREFIX had profile_lane but not
  // profile_engagement — so every one of them hit categoryOf's console.warn and
  // filed under 'config'. B1a's four new actions would have joined them.
  const src = fs.readFileSync(AUDIT_FILE, 'utf8');
  assert.ok(
    /profile_engagement:\s*'infra'/.test(src),
    "CATEGORY_BY_PREFIX must map profile_engagement to 'infra', beside profile_lane"
  );
});

// ── 8. The PATCH allowlist ──────────────────────────────────────────────────

test('B1a-R14: PATCH edits exactly seven fields, and the two omissions are deliberate', () => {
  const m = SRC.match(/const\s+B1_EDITABLE_FIELDS\s*=\s*Object\.freeze\(\[([\s\S]*?)\]\)/);
  assert.ok(m, 'the allowlist is a frozen array constant');
  const fields = (m[1].match(/'([a-z_]+)'/g) || []).map((s) => s.replace(/'/g, ''));

  assert.deepStrictEqual(fields.slice().sort(), [
    'brief', 'display_name', 'exposure_plan', 'issued_credentials',
    'objectives', 'scope_in', 'scope_out',
  ], 'exactly the seven fields compileEngagementPlan actually reads');

  // allowed_techniques: plan.techniques is ALWAYS derived from perspective and
  // credential posture; the stored column has no reader anywhere in the compile.
  // An editor there would persist an edit with zero effect AND stamp the field
  // into authored_fields, locking a later refresh out of it forever.
  assert.ok(!fields.includes('allowed_techniques'), 'allowed_techniques stays out of B1');
  // asset_selection changes what actually DEPLOYS. It belongs with the spec
  // writeback, not with an authoring form that has no deploy consequence.
  assert.ok(!fields.includes('asset_selection'), 'asset_selection stays out of B1');
  // And nothing secret-shaped is ever authorable.
  for (const f of fields) {
    assert.ok(!/pass|secret|token|key$/i.test(f), `${f} must not be authorable`);
  }
});

test('B1a-R15: the PATCH body is picked field by field, never spread', () => {
  const idx = SRC.indexOf("router.patch('/:engagementId'");
  assert.ok(idx !== -1, 'the PATCH route exists');
  const body = SRC.slice(idx, SRC.indexOf('router.', idx + 10));

  assert.ok(
    /for\s*\(\s*const\s+f\s+of\s+B1_EDITABLE_FIELDS\s*\)/.test(body),
    'the patch is built by iterating the allowlist'
  );
  assert.ok(!/\.{3}\s*(req\.)?body/.test(body), 'the request body is never spread into the patch');
  assert.ok(
    /body\[f\]\s*!==\s*undefined/.test(body),
    'an absent key stays absent — the writer treats present-and-undefined as a blank'
  );
  assert.ok(
    /Nothing to update/.test(body),
    'an empty patch is a 400, not a write that stamps authored_fields for nothing'
  );

  // The re-run reads the type and the scheme off the ROW, never the request —
  // the same arguments the writer used, or the warnings would not match.
  assert.ok(
    /validateEngagementPlan\(\s*patch\s*,\s*\{[\s\S]*?updated\.engagement_type[\s\S]*?updated\.subnet_scheme/.test(body),
    'the warnings re-run uses the row, not the request'
  );
});

// ── 9. Projection ───────────────────────────────────────────────────────────

test('B1a-R16: project() strips challenge_key and challenge_id', () => {
  // rowToEngagement really does carry both. They are reservation identifiers
  // with no meaning to an instructor, and the admin panel renders one today —
  // which is how a word that must never appear in instructor-facing copy gets
  // onto a screen. Deleting them server-side means the page cannot render one
  // even by accident.
  const idx = SRC.indexOf('function project(');
  assert.ok(idx !== -1, 'project() exists');
  const body = SRC.slice(idx, SRC.indexOf('\n}', idx));
  assert.ok(/delete\s+out\.challenge_key\s*;/.test(body), 'challenge_key is deleted');
  assert.ok(/delete\s+out\.challenge_id\s*;/.test(body), 'challenge_id is deleted');
  assert.ok(/display_label\s*=/.test(body), 'the label is resolved server-side');
  assert.ok(/type_descriptor\s*=/.test(body), 'and so is the type descriptor');

  // `can` is advice for drawing buttons. Every route still carries its own gate.
  assert.ok(/can\s*=\s*\{/.test(body), 'project attaches capability advice');
});

test('B1a-R17: the list route also answers can at the top level', () => {
  // The empty-list branch is precisely the branch that offers Create and Adopt,
  // and it has no row to read `can` off. Without a top-level copy an admin
  // visiting a client with no engagement sees prose where the button belongs —
  // and rendering the button unconditionally instead would manufacture
  // access.denied audit rows (requireRole's 403 calls auditDenial) against the
  // screen's primary user.
  const idx = SRC.indexOf("router.get('/',");
  const body = SRC.slice(idx, SRC.indexOf('router.', idx + 10));
  assert.ok(/unadopted_reservation:/.test(body), 'the capacity branch is reported');
  assert.ok(/\n\s*can:\s*\{/.test(body), 'and the capability flags travel with it');
});

// ── 10. SQL and scanner-set hygiene ─────────────────────────────────────────

test('B1a-R18: no $n IS [NOT] NULL, and the file stays out of the lane-claims scanner set', () => {
  // A parameter compared with IS NULL is untyped to node-postgres and the
  // planner cannot use an index on it — the property test/sql-param-typing.test.js
  // pins across this walk, which already includes this file.
  assert.ok(
    !/\$\d+\s+IS\s+(NOT\s+)?NULL/i.test(SRC),
    'no $n IS NULL — cast it or restructure the predicate'
  );

  // test/lane-claims.test.js:86-118 scans every file mentioning cybercore_lane
  // and requires it to build its predicate through claimsSql(). This file has no
  // business naming that table; if it ever does, it joins that set and must
  // adopt the helper rather than hand-writing the claim.
  assert.ok(!/cybercore_lane\b/.test(SRC), 'routes/engagements.js never names cybercore_lane');

  // Two queries, both parameterised. No interpolation into SQL anywhere.
  const sql = SRC.match(/query\(\s*`[^`]*`/g) || [];
  for (const q of sql) {
    assert.ok(!/\$\{/.test(q), `SQL is parameterised, never interpolated: ${q.slice(0, 60)}`);
  }
});

test('B1a-R19: the plan is compiled offline, from a freshly synthesized spec', () => {
  const idx = SRC.indexOf('async function compilePlanFor(');
  assert.ok(idx !== -1, 'compilePlanFor exists');
  const body = SRC.slice(idx, SRC.indexOf('\n}', idx));

  // provisionEngagementNetwork stores `spec: {}` deliberately — the real one is
  // written at deploy time — so reading it back would compile every freshly
  // created engagement to one SPEC_EMPTY problem and an empty plan.
  assert.ok(/synthesizeSpecFromProfile\(/.test(body), 'the spec is synthesized, not read back');
  assert.ok(!/engagement\.spec\b/.test(body), 'the stored spec is never used as the compile input');

  // vxlanBlock is omitted on purpose: profile-to-spec defaults it and only ever
  // writes it to spec.vxlan_block, which the compile never reads. That is what
  // lets a plan compile for an engagement holding no block at all.
  assert.ok(!/vxlanBlock/.test(body), 'no vxlanBlock — an unreserved engagement must still compile');

  // The require is lazy: profile-deploy pulls the batch deployer and the
  // vuln-app generator behind it, and this file is required at boot.
  assert.ok(
    /require\('\.\/profile-deploy'\)/.test(body),
    'profile-deploy is required inside the call, not at module load'
  );
  assert.ok(
    !/^const .*require\('\.\/profile-deploy'\)/m.test(SRC),
    'and not at the top level'
  );
});

test('B1a-R20: the detail route reports bridges_ready as null — unverified, not failed', () => {
  // getEngagementById attaches no readiness, unlike getEngagement and
  // listEngagements. An adopted pre-existing block genuinely has lanes running
  // on it with no bridge evidence anywhere, so inventing `false` would report a
  // healthy environment as broken.
  const idx = SRC.indexOf("router.get('/:engagementId'");
  const body = SRC.slice(idx, SRC.indexOf('router.', idx + 10));
  assert.ok(/bridges_ready:\s*null/.test(body), 'the detail response carries bridges_ready: null');
  assert.ok(/getEngagementById\(/.test(body), 'and reads by id');
  assert.ok(/Engagement not found/.test(body), 'a missing engagement is a 404, not an empty 200');
});

// ── 11. The one thing worth executing ───────────────────────────────────────

test('B1a-R21: the route\'s warnings re-run really does surface EXPOSURE_REQUIRES_V3', () => {
  // THIS IS THE POINT OF THE RE-RUN. updateEngagementModel computes `warnings`
  // and references them only inside its error throw; the success return
  // discards them. So the warning that tells an instructor their pivot
  // placement is a fiction on a flat v1/v2 lane can never reach the only path
  // an instructor uses — unless the route runs the validator a second time.
  //
  // engagement-model.js has zero requires, so it loads without a database.
  const model = require(path.join(CIAB, 'utils', 'engagement-model.js'));

  const patch = {
    exposure_plan: [
      { vm_name: 'web01', placement: 'pivot', services: ['80/HTTP'] },
    ],
  };

  // Exactly the arguments the route passes: the type and the scheme off the ROW.
  const v2 = model.validateEngagementPlan(patch, {
    engagementType: 'external_blackbox',
    subnetScheme: 'v2',
  });
  assert.ok(v2.valid, 'a pivot placement on v2 is authorable — it is a warning, not an error');
  assert.ok(
    v2.warnings.some((w) => w.code === 'EXPOSURE_REQUIRES_V3'),
    `expected EXPOSURE_REQUIRES_V3, got ${JSON.stringify(v2.warnings.map((w) => w.code))}`
  );
  // The warning names the offending path, so the screen can put it beside the
  // field that caused it rather than at the top of the form.
  const w = v2.warnings.find((x) => x.code === 'EXPOSURE_REQUIRES_V3');
  assert.ok(/placement$/.test(w.path), `the warning is anchored at the placement: ${w.path}`);

  // v3 is the scheme that actually has an ext/int boundary, so the same patch is
  // clean there — proving the warning tracks the scheme and is not unconditional.
  const v3 = model.validateEngagementPlan(patch, {
    engagementType: 'external_blackbox',
    subnetScheme: 'v3',
  });
  assert.ok(
    !v3.warnings.some((x) => x.code === 'EXPOSURE_REQUIRES_V3'),
    'a v3 environment has the boundary the placement describes'
  );
});

test('B1a-R22: a secret-shaped key is refused by the validator the route calls', () => {
  // Belt and braces on rule 3. The route never offers a password field, but the
  // writer it calls refuses one by NAME even for a column the model does not
  // have — so a caller that sends {password} is refused rather than ignored.
  const model = require(path.join(CIAB, 'utils', 'engagement-model.js'));
  const res = model.validateEngagementPlan({ password: 'hunter2' }, {});
  assert.ok(!res.valid, 'a patch naming a secret is invalid');
  assert.ok(res.errors.length > 0, 'and says why');
});

// ── 11. EXECUTED behaviour, not a source scan ───────────────────────────────
//
// Everything above reads the file's text, for the reason the header gives:
// requiring the router pulls profile-deploy, the batch lane deployer, the
// vuln-app generator and two database pools behind it, none of which exists in
// this checkout. The three properties below cannot be read off text honestly —
// "a typo does not carve a block", "a malformed id is a 400 that does not echo
// its input", and "the probe still runs when the list is not empty" are all
// claims about what RUNS — so the graph is replaced instead.
//
// `node --test "test/*.test.js"` gives every file its own process, so writing
// into require.cache here cannot reach another test file.

let LOADED = null;

/**
 * Mount the REAL router on a stubbed module cache and return it with the state
 * its stubs read and write. engagement-model and lane-reservation are the REAL
 * modules — the vocabulary and the sanitizer are exactly what is under test —
 * and only lane-reservation's own heavy leaves are replaced.
 */
function loadRouter() {
  if (LOADED) return LOADED;

  const state = {
    audit: [],
    created: [],        // one entry per carve — the capacity ledger
    profiles: [{ id: 'p1', company_name: 'Acme' }],
    engagements: [],
    reservation: null,
    probeThrows: false,
  };

  const put = (modPath, exports) => {
    const resolved = require.resolve(modPath);
    require.cache[resolved] = {
      id: resolved, filename: resolved, loaded: true, exports, children: [], paths: [],
    };
  };

  const badUuid = () => {
    const e = new Error('invalid input syntax for type uuid: "not-a-uuid"');
    e.code = '22P02';
    return e;
  };

  put(path.join(ROOT, 'src', 'utils', 'proxmox.js'), { proxmoxAPI: async () => ({}) });
  put(path.join(ROOT, 'src', 'utils', 'lab-network-provision.js'),
    new Proxy({}, { get: () => async () => ({}) }));
  put(path.join(ROOT, 'src', 'utils', 'lane-deployer.js'),
    new Proxy({}, { get: () => async () => ({}) }));
  put(path.join(ROOT, 'src', 'utils', 'cybercore-db.js'), { cybercoreQuery: async () => ({ rows: [] }) });
  put(path.join(ROOT, 'src', 'utils', 'audit.js'), { log: (e) => state.audit.push(e) });
  put(path.join(ROOT, 'src', 'middleware', 'auth.js'), {
    requireRole: (...roles) => (req, res, next) => (
      req.user && roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'forbidden' })
    ),
  });
  put(path.join(CIAB, 'utils', 'db.js'), {
    query: async (sql, params) => {
      if (/FROM profiles/.test(sql)) {
        if (params[0] === 'not-a-uuid') throw badUuid();
        return { rows: state.profiles.filter((p) => p.id === params[0]) };
      }
      return { rows: [] };
    },
  });
  put(path.join(CIAB, 'utils', 'engagement-plan.js'), { compileEngagementPlan: () => ({ problems: [] }) });
  put(path.join(CIAB, 'utils', 'profile-to-spec.js'), { synthesizeSpecFromProfile: () => ({ spec: {} }) });
  put(path.join(CIAB, 'routes', 'profile-deploy.js'), {
    loadProfileForDeploy: async () => ({ profile: { id: 'p1' }, assets: [] }),
    defaultAssetSelection: () => [],
  });

  const model = require(path.join(CIAB, 'utils', 'engagement-model.js'));
  put(path.join(CIAB, 'utils', 'engagement-provision.js'), {
    listEngagements: async () => state.engagements,
    getEngagementById: async (id) => {
      if (id === 'not-a-uuid') throw badUuid();
      return state.engagements.find((e) => e.engagement_id === id) || null;
    },
    // The CAPACITY LEDGER. Every call here is one VXLAN block the allocator can
    // never hand back.
    createEngagement: async (opts) => {
      const d = model.describeEngagementType(opts.engagementType);
      const row = {
        engagement_id: 'e' + (state.created.length + 1),
        profile_id: opts.profileId,
        engagement_type: opts.engagementType,
        subnet_scheme: opts.subnetScheme,
        max_students: opts.maxStudents,
        perspective: d.perspective,
        credential_posture: d.credential_posture,
        provision_status: 'provisioning',
      };
      state.created.push(row);
      state.engagements.push(row);
      return row;
    },
    updateEngagementModel: async (id, patch) => {
      const row = state.engagements.find((e) => e.engagement_id === id);
      if (!row) { const e = new Error('Engagement not found'); e.status = 404; throw e; }
      return Object.assign(row, patch);
    },
    reprovisionEngagement: async (id) => state.engagements.find((e) => e.engagement_id === id),
    retireEngagement: async (id) => state.engagements.find((e) => e.engagement_id === id),
    resolveEngagement: async () => null,
  });

  const laneReservation = require(path.join(CIAB, 'utils', 'lane-reservation.js'));
  laneReservation.findProfileChallenge = async () => {
    if (state.probeThrows) throw new Error('cybercore_db is unreachable');
    return state.reservation;
  };

  LOADED = { router: require(ROUTES_FILE), state };
  return LOADED;
}

/** One request through the router, with no socket and no port. */
function call(method, url, opts) {
  const o = opts || {};
  const { router } = loadRouter();
  return new Promise((resolve, reject) => {
    const req = {
      method, url, originalUrl: url, baseUrl: '',
      body: o.body || {}, query: o.query || {}, headers: {},
      user: { role: o.role || 'admin', userId: 'u1' },
    };
    const res = {
      statusCode: 200,
      headers: {},
      status(code) { this.statusCode = code; return this; },
      setHeader(k, v) { this.headers[k] = v; },
      getHeader(k) { return this.headers[k]; },
      json(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      send(payload) { resolve({ status: this.statusCode, body: payload }); return this; },
      end() { resolve({ status: this.statusCode, body: null }); return this; },
    };
    router(req, res, (err) => (err ? reject(err) : resolve({ status: 404, body: null })));
  });
}

test('B1a-R23: a mistyped engagement type is REFUSED, and carves nothing', async () => {
  // The whole point. sanitizeEngagementType is a COERCER, not a validator, and
  // describeEngagementType is TOTAL — so before this refusal existed, one
  // transposed character produced a 202, a permanently carved VXLAN block and
  // an engagement stored with the OPPOSITE perspective, silently.
  const { state } = loadRouter();
  state.created.length = 0;
  state.engagements.length = 0;

  const typo = await call('POST', '/', { body: { profile_id: 'p1', engagement_type: 'externl_blackbox' } });
  assert.strictEqual(typo.status, 400, 'an unknown type is refused');
  assert.strictEqual(typo.body.code, 'UNKNOWN_ENGAGEMENT_TYPE');
  assert.strictEqual(state.created.length, 0, 'AND NOTHING WAS CARVED — this is the finding');
  // The refusal carries the vocabulary, so the fix is in the response.
  const model = require(path.join(CIAB, 'utils', 'engagement-model.js'));
  assert.deepStrictEqual(
    typo.body.known_types.slice().sort(),
    Object.keys(model.ENGAGEMENT_TYPES).sort()
  );

  // A display alias is what the sanitizer makes of a type typed into a form.
  // It is NOT silently rewritten — the slug is baked into the reservation key,
  // so rewriting orphans a carve — so the canonical spelling is offered instead.
  const alias = await call('POST', '/', { body: { profile_id: 'p1', engagement_type: 'External Blackbox' } });
  assert.strictEqual(alias.status, 400);
  assert.strictEqual(alias.body.did_you_mean, 'external_blackbox');
  assert.strictEqual(state.created.length, 0, 'still nothing carved');

  // A registry key still creates, and stores the registry's perspective.
  const ok = await call('POST', '/', { body: { profile_id: 'p1', engagement_type: 'external_blackbox' } });
  assert.strictEqual(ok.status, 202);
  assert.strictEqual(ok.body.engagement.perspective, 'external');
  assert.strictEqual(state.created.length, 1);

  // An omitted type is 'default', which IS a registry key. Every production
  // writer emits exactly that (admin-profile-lanes.js:411), so the refusal must
  // not touch them.
  const omitted = await call('POST', '/', { body: { profile_id: 'p1' } });
  assert.strictEqual(omitted.status, 202, 'an omitted type is the default, not a refusal');
  assert.strictEqual(omitted.body.engagement.engagement_type, 'default');

  // B0 built the vocabulary as a REGISTRY, not an allowlist, and a locally
  // defined slug must stay expressible — deliberately, with the intention
  // stated, never by typo.
  const custom = await call('POST', '/', {
    body: { profile_id: 'p1', engagement_type: 'purple_team', allow_custom_type: true },
  });
  assert.strictEqual(custom.status, 202, 'the override is what keeps a custom slug expressible');
  assert.strictEqual(custom.body.engagement.engagement_type, 'purple_team');
  assert.strictEqual(custom.body.engagement.type_descriptor.known, false);
  const row = state.audit.filter((a) => a.action === 'profile_engagement.created').pop();
  assert.strictEqual(row.metadata.custom_type, true, 'and the deliberate choice is audited');
});

test('B1a-R24: a malformed id is a 400 that does not echo the id back', async () => {
  // 22P02 is invalid_text_representation — a CLIENT error. It used to fall
  // through to the 500 branch, which also copied pg's message (invalid input
  // syntax for type uuid: "<value>") into the body, echoing an attacker-chosen
  // path segment straight into a toast.
  const bad = await call('GET', '/not-a-uuid', { role: 'instructor' });
  assert.strictEqual(bad.status, 400, '22P02 is a client error, not a 500');
  assert.strictEqual(bad.body.code, 'INVALID_ID');
  assert.ok(
    !JSON.stringify(bad.body).includes('not-a-uuid'),
    'the reply never echoes the offending input back'
  );

  // The same on a body-supplied id, so the mapping lives in the renderer and is
  // not bolted onto one handler.
  const create = await call('POST', '/', { body: { profile_id: 'not-a-uuid', engagement_type: 'default' } });
  assert.strictEqual(create.status, 400);
  assert.strictEqual(create.body.code, 'INVALID_ID');
});

test('B1a-R25: the unadopted probe runs on EVERY list, and a failed probe says so', async () => {
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.reservation = { engagement_type: 'default', challenge_key: 'ciab-profile-p1' };

  // THE FINDING: the probe was gated on rows.length === 0, so a pre-engagement
  // block went permanently invisible the moment ANY engagement row existed —
  // and "one client, many engagements" is what this table was added for. The
  // admin then sees Create where Adopt belongs, and carves a second block.
  state.engagements.push({ engagement_id: 'x1', profile_id: 'p1', engagement_type: 'external_blackbox' });
  const withRows = await call('GET', '/', { query: { profile_id: 'p1' }, role: 'instructor' });
  assert.strictEqual(withRows.status, 200);
  assert.deepStrictEqual(withRows.body.unadopted_reservation, { engagement_type: 'default' });
  assert.strictEqual(withRows.body.unadopted_probe, 'ok');

  // But a reservation an engagement row already names is ADOPTED, not
  // unadopted. Offering Adopt for it would be its own wrong answer.
  state.engagements.push({ engagement_id: 'x2', profile_id: 'p1', engagement_type: 'default' });
  const adopted = await call('GET', '/', { query: { profile_id: 'p1' }, role: 'instructor' });
  assert.strictEqual(adopted.body.unadopted_reservation, null);
  assert.strictEqual(adopted.body.unadopted_probe, 'ok');

  // A FAILED PROBE IS NOT AN ABSENT RESERVATION. Collapsing the two is how a
  // cybercore_db outage becomes a duplicate carve.
  state.probeThrows = true;
  const down = await call('GET', '/', { query: { profile_id: 'p1' }, role: 'instructor' });
  assert.strictEqual(down.status, 200, 'the list itself still renders');
  assert.strictEqual(down.body.engagements.length, 2);
  assert.strictEqual(down.body.unadopted_reservation, null);
  assert.strictEqual(down.body.unadopted_probe, 'unavailable', 'the screen is told it does not know');
  state.probeThrows = false;
});

// ── 12. The rest of the surface, EXECUTED ───────────────────────────────────
//
// A reviewer proved that not one shipping line of this router was ever RUN by
// the suite: every property above section 11 is read off the file's text, and a
// source scan cannot see a wrong status code, an unvalidated body or a broken
// response shape — which is the entire class every finding in this round
// belonged to. Section 11 executed the three findings it was written for. This
// section executes the REST of the handlers, so the next wrong status code is
// caught by a test rather than by an instructor.
//
// The stubs are section 11's. Where a test needs a different one it swaps it in
// and puts the original back in a finally, because node:test runs the tests in
// this file in order and in one process.

/** Swap one export on the provision stub for the duration of one call. */
async function withProvision(overrides, fn) {
  const provision = require(path.join(CIAB, 'utils', 'engagement-provision.js'));
  const saved = {};
  for (const k of Object.keys(overrides)) { saved[k] = provision[k]; provision[k] = overrides[k]; }
  try { return await fn(provision); }
  finally { for (const k of Object.keys(saved)) provision[k] = saved[k]; }
}

/** audit.js's real redactor, read out of the file rather than copied. */
function secretKeyRe() {
  const m = fs.readFileSync(AUDIT_FILE, 'utf8').match(/const SECRET_KEY_RE\s*=\s*\/(.+)\/([a-z]*);/);
  assert.ok(m, 'SECRET_KEY_RE is still declared in audit.js — if not, retarget this test');
  return new RegExp(m[1], m[2]);
}

test('B1a-R26: a PATCH the validator refuses is a 400 carrying its errors, not a 500', async () => {
  // updateEngagementModel throws {status:400, code:'ENGAGEMENT_PLAN_INVALID',
  // errors, warnings}. `status`, not `statusCode` — and routes/profile-deploy.js
  // reads only `statusCode`, which is why an equivalent refusal renders as a
  // bare 500 there today. sendErr reads both, and forwards the errors array so
  // the form can put each message beside the field that caused it. None of that
  // is visible to a regex: it is a status code and a body shape.
  const { state } = loadRouter();
  const model = require(path.join(CIAB, 'utils', 'engagement-model.js'));
  state.engagements.length = 0;
  state.engagements.push({
    engagement_id: 'e-patch', profile_id: 'p1', engagement_type: 'external_blackbox',
    subnet_scheme: 'v2', perspective: 'external', credential_posture: 'none',
  });
  state.audit.length = 0;

  // The REAL validator, throwing exactly the shape the real writer throws — so
  // this pins the route's rendering of it, not a rendering of an invention.
  const realWriter = async (id, patch) => {
    const row = state.engagements.find((e) => e.engagement_id === id);
    if (!row) throw Object.assign(new Error('Engagement not found'), { status: 404 });
    const { errors, warnings, value } = model.validateEngagementPlan(patch, {
      engagementType: row.engagement_type,
      subnetScheme: row.subnet_scheme || null,
    });
    if (errors.length > 0) {
      throw Object.assign(new Error(errors[0].message), {
        status: 400, code: 'ENGAGEMENT_PLAN_INVALID', errors, warnings,
      });
    }
    return Object.assign(row, value);
  };

  await withProvision({ updateEngagementModel: realWriter }, async () => {
    // scope_in is a list of RULES; a bare string is not one. The validator
    // refuses it, and the refusal has to reach the instructor as a 400 with a
    // reason attached to the field that caused it.
    const bad = await call('PATCH', '/e-patch', {
      role: 'instructor', body: { scope_in: 'everything on the /24' },
    });
    assert.strictEqual(bad.status, 400, 'a refused patch is a client error, not a server one');
    assert.strictEqual(bad.body.code, 'ENGAGEMENT_PLAN_INVALID');
    assert.ok(Array.isArray(bad.body.errors) && bad.body.errors.length > 0,
      'and the errors array is FORWARDED — the form anchors each message to its field');
    assert.ok(bad.body.errors[0].path, 'each error names the path it belongs to');
    assert.strictEqual(state.audit.length, 0,
      'a refused patch writes no audit row — nothing happened to record');

    // A SECRET NEVER GETS AS FAR AS THE VALIDATOR, because the route's
    // allowlist is the FIRST line and the validator's refusal-by-name is the
    // second. B1a-R22 pins the second (validateEngagementPlan({password}) is
    // invalid); this pins the first, and the two together are why a body
    // carrying a password is a 200 that stored only the field it was allowed to
    // store, with the secret in no column, no audit row and no response.
    const patched = [];
    await withProvision({
      updateEngagementModel: async (id, patch) => { patched.push(patch); return realWriter(id, patch); },
    }, async () => {
      const secret = await call('PATCH', '/e-patch', {
        role: 'instructor', body: { display_name: 'ok', password: 'hunter2' },
      });
      assert.strictEqual(secret.status, 200);
      assert.deepStrictEqual(Object.keys(patched[0]), ['display_name'],
        'the secret never reaches the writer — the body is picked, never spread');
      assert.ok(!JSON.stringify(secret.body).includes('hunter2'),
        'and it is nowhere in the reply either');
      const audited = state.audit.filter((a) => a.action === 'profile_engagement.model_updated').pop();
      assert.ok(!JSON.stringify(audited.metadata).includes('hunter2'),
        'nor in the audit row, which is published on adminer in plaintext');
    });
    state.audit.length = 0;

    // THE RE-RUN, THROUGH THE ROUTE. The writer computes warnings and its
    // success return discards them, so EXPOSURE_REQUIRES_V3 — the warning that
    // tells an instructor a pivot placement is a fiction on a flat v2 lane —
    // can only reach them if the ROUTE runs the validator a second time.
    const ok = await call('PATCH', '/e-patch', {
      role: 'instructor',
      body: { exposure_plan: [{ vm_name: 'web01', placement: 'pivot', services: ['80/HTTP'] }] },
    });
    assert.strictEqual(ok.status, 200);
    assert.ok(ok.body.warnings.some((w) => w.code === 'EXPOSURE_REQUIRES_V3'),
      'the re-run warnings reach the response: ' + JSON.stringify(ok.body.warnings));
  });
});

test('B1a-R27: PATCH forwards exactly the seven fields, and audits counts only', async () => {
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.engagements.push({
    engagement_id: 'e-allow', profile_id: 'p1', engagement_type: 'internal_credentialed',
    subnet_scheme: 'v3', perspective: 'internal', credential_posture: 'credentialed',
    issued_credentials: [], scope_in: [], scope_out: [], objectives: [], exposure_plan: [],
  });
  state.audit.length = 0;

  const seen = [];
  await withProvision({
    updateEngagementModel: async (id, patch) => {
      seen.push(patch);
      const row = state.engagements.find((e) => e.engagement_id === id);
      return Object.assign(row, patch);
    },
  }, async () => {
    // A body carrying ONLY the two deliberate omissions is "nothing to update",
    // not a silent 200. An editor that answers success for an edit it discarded
    // is worse than one that refuses: it looks like it worked.
    const none = await call('PATCH', '/e-allow', {
      role: 'instructor', body: { allowed_techniques: ['anything'], asset_selection: [{ hostname: 'x' }] },
    });
    assert.strictEqual(none.status, 400);
    assert.strictEqual(none.body.error, 'Nothing to update');
    assert.strictEqual(seen.length, 0, 'and the writer was never called');

    // The body is picked field by field, never spread, so an unknown key cannot
    // reach the writer and markAuthored cannot stamp a field this file does not
    // offer — a field listed there is one B2's refresh path refuses to
    // overwrite forever.
    const mixed = await call('PATCH', '/e-allow', {
      role: 'instructor',
      body: {
        display_name: 'Q3 internal',
        issued_credentials: [{ username: 'svc_backup', target_vm: 'app01', note: 'domain user' }],
        allowed_techniques: ['ignored'],
        asset_selection: [{ hostname: 'ignored' }],
        engagement_type: 'external_blackbox',
        retired_at: '2020-01-01',
        provision_status: 'ready',
      },
    });
    assert.strictEqual(mixed.status, 200);
    assert.deepStrictEqual(
      Object.keys(seen[0]).sort(), ['display_name', 'issued_credentials'],
      'only the allowlisted fields reached the writer'
    );
    assert.strictEqual(seen[0].engagement_type, undefined, 'the identity is not editable here');
    assert.strictEqual(seen[0].retired_at, undefined, 'and neither is retirement');

    // THE AUDIT ROW: names and counts, never a credential and never a spread.
    const row = state.audit.filter((a) => a.action === 'profile_engagement.model_updated').pop();
    assert.ok(row, 'a successful patch is audited');
    const meta = row.metadata;
    assert.deepStrictEqual(meta.fields, ['display_name', 'issued_credentials']);
    assert.strictEqual(meta.issued_account_slots, 1, 'the COUNT is recorded');
    const flat = JSON.stringify(meta);
    for (const leak of ['svc_backup', 'app01', 'domain user']) {
      assert.ok(!flat.includes(leak),
        'no credential field reaches the audit row — found ' + leak);
    }
    // And the count SURVIVES. audit.js redacts on the KEY, and its regex holds a
    // bare `cred`, so `credential_slots` was stored as the string "[redacted]":
    // the one number here that is safe by construction was the one that died.
    // Checked against the keys actually emitted, not against a source literal.
    const RE = secretKeyRe();
    for (const key of Object.keys(meta)) {
      assert.ok(!RE.test(key),
        'emitted audit key "' + key + '" is eaten by audit.js\'s redactor — rename the '
        + 'key here; the redactor is shared core and is never weakened for a test');
    }
  });
});

test('B1a-R28: the instructor/admin split is enforced at runtime, not just written down', async () => {
  // There is no requireCiabAccess on the /api/instructor mount, so a route that
  // forgets its own requireRole is open to every authenticated user. The split
  // is not cosmetic: CREATE and REPROVISION each burn a VXLAN block the
  // allocator can never hand back.
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.engagements.push({ engagement_id: 'e-role', profile_id: 'p1', engagement_type: 'default' });
  state.created.length = 0;

  const capacity = [
    ['POST', '/', { profile_id: 'p1', engagement_type: 'default' }],
    ['POST', '/adopt', { profile_id: 'p1' }],
    ['POST', '/e-role/reprovision', {}],
    ['POST', '/e-role/retire', { confirm: true }],
  ];
  for (const [method, url, body] of capacity) {
    const res = await call(method, url, { role: 'instructor', body });
    assert.strictEqual(res.status, 403, 'an instructor is refused ' + method + ' ' + url);
  }
  assert.strictEqual(state.created.length, 0, 'and no refusal carved anything');

  // A student reaches nothing at all, read routes included.
  const reads = [['GET', '/types'], ['GET', '/'], ['GET', '/e-role'], ['PATCH', '/e-role']];
  for (const [method, url] of reads) {
    const res = await call(method, url, {
      role: 'student', query: { profile_id: 'p1' }, body: { display_name: 'x' },
    });
    assert.strictEqual(res.status, 403, 'a student is refused ' + method + ' ' + url);
  }

  // The authoring routes ARE the instructor's daily work, and are open to them.
  const types = await call('GET', '/types', { role: 'instructor' });
  assert.strictEqual(types.status, 200);
  const list = await call('GET', '/', { role: 'instructor', query: { profile_id: 'p1' } });
  assert.strictEqual(list.status, 200);
  // can.* is ADVICE FOR THE SCREEN and is computed for the CALLER, so the same
  // list answers differently to the two roles — that is what stops the page
  // drawing a button whose 403 files an access-denied row against its own user.
  assert.strictEqual(list.body.can.create, false, 'an instructor is not offered Create');
  assert.strictEqual(list.body.can.edit, true, 'but authoring is theirs');
  const asAdmin = await call('GET', '/', { role: 'admin', query: { profile_id: 'p1' } });
  assert.strictEqual(asAdmin.body.can.create, true);
});

test('B1a-R29: the projection strips both reservation identifiers, and /types is not an id', async () => {
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.engagements.push({
    engagement_id: 'e-proj', profile_id: 'p1', engagement_type: 'external_blackbox',
    challenge_key: 'ciab-profile-p1-external_blackbox', challenge_id: 'ch-9',
    provision_status: 'ready',
  });

  const list = await call('GET', '/', { role: 'instructor', query: { profile_id: 'p1' } });
  const row = list.body.engagements[0];
  // The admin reservation panel renders one of these today, which is how a word
  // that must never appear in instructor-facing copy gets onto a screen. The
  // page cannot render what it is never sent.
  assert.ok(!('challenge_key' in row) && !('challenge_id' in row),
    'neither reservation identifier is projected');
  assert.ok(!JSON.stringify(list.body).includes('ciab-profile-p1'),
    'and the key does not survive anywhere else in the body');
  // The vocabulary is resolved SERVER-SIDE, once. The browser cannot load
  // engagement-model.js — manifest.json's staticDir is "public" — so a page
  // that had to derive this would be inventing a second vocabulary.
  assert.strictEqual(row.display_label, 'External — black box');
  assert.strictEqual(row.type_descriptor.perspective, 'external');

  // REGISTRATION ORDER IS LOAD-BEARING: '/types' before '/:engagementId', or
  // Express binds engagementId = 'types' and the registry read becomes a 404
  // for an engagement nobody asked for.
  const types = await call('GET', '/types', { role: 'instructor' });
  assert.strictEqual(types.status, 200);
  assert.ok(Array.isArray(types.body.types) && types.body.types.length > 0);
  assert.ok(types.body.types.every((t) => t.key), 'each entry is keyed');

  // The detail route: 404 in JSON for an id that is well-formed and unknown,
  // and bridges_ready null — UNVERIFIED, not failed. getEngagementById attaches
  // no readiness, and an adopted pre-existing block genuinely has lanes running
  // with no bridge evidence anywhere, so inventing `false` would report a
  // healthy environment as broken.
  const missing = await call('GET', '/e-nope', { role: 'instructor' });
  assert.strictEqual(missing.status, 404);
  assert.strictEqual(missing.body.error, 'Engagement not found');
  const detail = await call('GET', '/e-proj', { role: 'instructor' });
  assert.strictEqual(detail.status, 200);
  assert.strictEqual(detail.body.bridges_ready, null);
  assert.ok(!('challenge_key' in detail.body.engagement));
});

test('B1a-R30: retire needs confirm, records that nothing was released, and force is exact', async () => {
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.engagements.push({
    engagement_id: 'e-cap', profile_id: 'p1', engagement_type: 'default',
    perspective: 'internal', max_students: 30, provision_status: 'failed',
  });
  state.audit.length = 0;

  // `confirm: true` in the BODY, not inferred from the method, so an accidental
  // replay of a POST cannot end an engagement.
  const bare = await call('POST', '/e-cap/retire', { role: 'admin', body: {} });
  assert.strictEqual(bare.status, 400);
  assert.strictEqual(bare.body.code, 'CONFIRM_REQUIRED');
  assert.ok(/does NOT hand its reserved network back/.test(bare.body.error),
    'and the refusal says the thing the operator is most likely to have wrong');
  assert.strictEqual(state.audit.length, 0);

  const done = await call('POST', '/e-cap/retire', { role: 'admin', body: { confirm: true } });
  assert.strictEqual(done.status, 200);
  const retired = state.audit.pop();
  assert.strictEqual(retired.action, 'profile_engagement.retired');
  // Stated explicitly in the row, because the copy above it exists to defend
  // exactly this fact: retiring marks a row, it does not hand a block back.
  assert.strictEqual(retired.metadata.capacity_released, false);

  // FORCE IS EXACTLY true. Re-provisioning a HEALTHY block carves a second one,
  // and a truthy string arriving from a query string or a form must not be
  // enough to do it.
  const forced = [];
  await withProvision({
    reprovisionEngagement: async (id, opts) => {
      forced.push(opts.force);
      return state.engagements.find((e) => e.engagement_id === id);
    },
  }, async () => {
    const plain = await call('POST', '/e-cap/reprovision', { role: 'admin', body: {} });
    assert.strictEqual(plain.status, 202, 'the carve runs detached; the row is unchanged');
    await call('POST', '/e-cap/reprovision', { role: 'admin', body: { force: 'true' } });
    await call('POST', '/e-cap/reprovision', { role: 'admin', body: { force: 1 } });
    await call('POST', '/e-cap/reprovision', { role: 'admin', body: { force: true } });
    assert.deepStrictEqual(forced, [false, false, false, true],
      'only a literal true forces — not the string "true", not 1');
  });

  // ADOPT CONSUMES NO CAPACITY, and it is the one route allowed to call
  // resolveEngagement. With nothing to adopt it is a 404, never an accidental
  // carve.
  const nothing = await call('POST', '/adopt', { role: 'admin', body: { profile_id: 'p1' } });
  assert.strictEqual(nothing.status, 404);
  assert.strictEqual(nothing.body.error, 'No existing reservation to adopt');
  const noId = await call('POST', '/adopt', { role: 'admin', body: {} });
  assert.strictEqual(noId.status, 400, 'and a missing client id is refused before anything else');
});

test('B1a-R31: every error path renders as JSON with the right status', async () => {
  // public/js/app.js calls response.json() unconditionally on a failure, so a
  // body that is not JSON becomes APIError('Network error', 0) and the real
  // status never reaches a handler: a 409 carrying a named remedy would present
  // to the operator as a network outage.
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.engagements.push({ engagement_id: 'e-err', profile_id: 'p1', engagement_type: 'default' });

  const noProfile = await call('GET', '/', { role: 'instructor' });
  assert.strictEqual(noProfile.status, 400);
  assert.strictEqual(noProfile.body.error, 'profile_id is required');

  // BOTH property names. loadProfileForDeploy throws `statusCode`, the
  // provision layer throws `status`, and reading either half alone is exactly
  // why assertEngagementDeployable's 409 renders as a bare 500 in
  // routes/profile-deploy.js today.
  await withProvision({
    getEngagementById: async () => {
      throw Object.assign(new Error('Client file missing'), { statusCode: 422 });
    },
  }, async () => {
    const r = await call('GET', '/e-err', { role: 'instructor' });
    assert.strictEqual(r.status, 422, 'statusCode is honoured');
    assert.strictEqual(r.body.error, 'Client file missing');
  });
  await withProvision({
    getEngagementById: async () => {
      throw Object.assign(new Error('conflict'), { status: 409, code: 'ENGAGEMENT_BUSY' });
    },
  }, async () => {
    const r = await call('GET', '/e-err', { role: 'instructor' });
    assert.strictEqual(r.status, 409, 'status is honoured too');
    assert.strictEqual(r.body.code, 'ENGAGEMENT_BUSY');
  });

  // A missing relation is a DEPLOY state, not a request bug: this plugin's own
  // migrations are re-run at every boot and their failures are only
  // console.error'd, so 503 with the remedy named beats a 500 that reads as
  // "the server is broken".
  await withProvision({
    getEngagementById: async () => {
      throw Object.assign(new Error('relation "ciab_engagement" does not exist'), { code: '42P01' });
    },
  }, async () => {
    const r = await call('GET', '/e-err', { role: 'instructor' });
    assert.strictEqual(r.status, 503);
    assert.strictEqual(r.body.code, 'ENGAGEMENT_STORE_MISSING');
    assert.ok(/Migration failed/.test(r.body.error), 'and names the log line to look for');
  });

  // An UNEXPECTED database error stays a 500. Turning every pg error into
  // something friendlier would hide the ones that are real.
  await withProvision({
    getEngagementById: async () => {
      throw Object.assign(new Error('deadlock detected'), { code: '40P01' });
    },
  }, async () => {
    const r = await call('GET', '/e-err', { role: 'instructor' });
    assert.strictEqual(r.status, 500, 'an unexpected pg error is still a 500');
    assert.strictEqual(r.body.code, '40P01');
  });
});

test('B1a-R32: create-then-name, and a name that fails does not invite a SECOND carve', async () => {
  // createEngagement's signature accepts no model field, so naming an
  // engagement is a second call. If that call fails the engagement EXISTS and
  // has ALREADY BURNED A VXLAN BLOCK — so answering with an error would invite
  // the operator to press Create again and burn another, permanently, because
  // the allocator only ever climbs. The name is therefore best-effort and the
  // reply is still 202. That is a decision no source scan can check: it is a
  // status code on a path where a database call threw.
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.created.length = 0;
  state.audit.length = 0;

  const named = await call('POST', '/', {
    role: 'admin',
    body: { profile_id: 'p1', engagement_type: 'internal_credentialed', display_name: 'Q3 internal' },
  });
  assert.strictEqual(named.status, 202, '202: the row exists, the network does not yet');
  assert.strictEqual(named.body.engagement.display_name, 'Q3 internal');
  assert.strictEqual(state.created.length, 1, 'exactly one block was spent');
  const createdRow = state.audit.filter((a) => a.action === 'profile_engagement.created').pop();
  assert.strictEqual(createdRow.metadata.named, true);
  assert.strictEqual(createdRow.metadata.custom_type, false, 'a registry key is not a custom type');
  assert.strictEqual(createdRow.metadata.perspective, 'internal',
    'the stored perspective comes from the registry, not from the caller');

  state.created.length = 0;
  state.audit.length = 0;
  await withProvision({
    updateEngagementModel: async () => { throw Object.assign(new Error('cannot write'), { status: 500 }); },
  }, async () => {
    const unnamed = await call('POST', '/', {
      role: 'admin',
      body: { profile_id: 'p1', engagement_type: 'external_blackbox', display_name: 'Q3 external' },
    });
    assert.strictEqual(unnamed.status, 202,
      'THE POINT: a failed NAME is not a failed CREATE — a 500 here reads as '
      + '"press Create again", and the block is already gone');
    assert.strictEqual(state.created.length, 1, 'and still exactly one block was spent');
    const row = state.audit.filter((a) => a.action === 'profile_engagement.created').pop();
    assert.strictEqual(row.metadata.named, false, 'the audit row says the name did not land');
    // engagementDisplayName falls back through the registry, so an unnamed
    // engagement renders as a readable label rather than as a broken one.
    assert.strictEqual(unnamed.body.engagement.display_label, 'External — black box');
  });

  // AND THE CLIENT IS CHECKED BEFORE ANY OF IT. A create for a client that does
  // not exist must not carve first and discover second.
  state.created.length = 0;
  const noClient = await call('POST', '/', {
    role: 'admin', body: { profile_id: 'p-missing', engagement_type: 'default' },
  });
  assert.strictEqual(noClient.status, 404);
  assert.strictEqual(noClient.body.error, 'Profile not found');
  assert.strictEqual(state.created.length, 0, 'nothing was carved for a client that is not there');
});

test('B1a-R33: adopt takes over a carve, audits it, and is the only caller of resolveEngagement', async () => {
  // The write that today happens invisibly on somebody else's GET becomes an
  // explicit, audited, admin-confirmed action. resolveEngagement falls through
  // to adoptExistingReservation, which INSERTs — a read that writes is not a
  // read — so which routes call it is a property worth executing, not just
  // reading.
  const { state } = loadRouter();
  state.engagements.length = 0;
  state.audit.length = 0;
  state.created.length = 0;

  const resolved = [];
  await withProvision({
    resolveEngagement: async (profileId, type) => {
      resolved.push([profileId, type]);
      return {
        engagement_id: 'e-adopted', profile_id: profileId, engagement_type: type,
        challenge_key: 'ciab-profile-p1-default', challenge_id: 'ch-1',
        provision_status: 'ready', perspective: 'internal', credential_posture: 'none',
      };
    },
  }, async () => {
    // A DISPLAY alias is sanitized on the way in, always. The slug is baked into
    // the reservation key, and the canonical identity of an environment is the
    // pair (profile_id, sanitizeEngagementType(engagement_type)) — a raw slug
    // written here produces a row the environment surface can never join to.
    const r = await call('POST', '/adopt', {
      role: 'admin', body: { profile_id: 'p1', engagement_type: 'Default Engagement!' },
    });
    assert.strictEqual(r.status, 200);
    assert.deepStrictEqual(resolved, [['p1', 'defaultengagement']],
      'the slug reaching the resolver is sanitized, never raw');
    assert.strictEqual(state.created.length, 0, 'ADOPTING CARVES NOTHING');

    const row = state.audit.pop();
    assert.strictEqual(row.action, 'profile_engagement.adopted');
    assert.strictEqual(row.metadata.profile_id, 'p1');

    // And the reservation identifiers do not travel to the browser even on this
    // route, where the whole subject IS the reservation.
    assert.ok(!('challenge_key' in r.body.engagement) && !('challenge_id' in r.body.engagement));
    assert.ok(!JSON.stringify(r.body).includes('ciab-profile-p1'));
  });

  // Every OTHER route leaves it alone. This is the read-that-must-not-write
  // property, executed: the list route in particular is polled every five
  // seconds by an open tab.
  resolved.length = 0;
  await withProvision({
    resolveEngagement: async () => { resolved.push('called'); return null; },
  }, async () => {
    await call('GET', '/', { role: 'instructor', query: { profile_id: 'p1' } });
    await call('GET', '/types', { role: 'instructor' });
    state.engagements.push({ engagement_id: 'e-r', profile_id: 'p1', engagement_type: 'default' });
    await call('GET', '/e-r', { role: 'instructor' });
    await call('PATCH', '/e-r', { role: 'instructor', body: { display_name: 'x' } });
    await call('POST', '/e-r/reprovision', { role: 'admin', body: {} });
    await call('POST', '/e-r/retire', { role: 'admin', body: { confirm: true } });
    assert.deepStrictEqual(resolved, [],
      'no read, and no other write, resolves a reservation into existence');
  });
});
