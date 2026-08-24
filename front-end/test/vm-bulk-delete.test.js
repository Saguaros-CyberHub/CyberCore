/**
 * Tests for bulk workstation-lane deletion (cle/routes/vms.js)
 *
 * Two pure helpers, both of which fail in ways that look like success:
 *
 *   parseLaneIds — the boundary between a client array and an `= ANY($1::uuid[])`
 *     query. A malformed element there turns a clean result into a 500 (the same
 *     reason loadWorkstationTemplates loops instead of using ANY), and a silent
 *     truncation at the cap would tell an instructor who ticked 60 rows that 50
 *     were deleted without saying which ten survived.
 *
 *   bulkDeleteStatus — the 200/207 decision. teardownLanes returns
 *     `errors: [...errors, ...warnings]` while its ROW decision keys on `errors`
 *     alone, so a Guacamole 403 — which leaves nothing running anywhere — lands
 *     in that array. Keying the status on `errors.length` would turn every
 *     Guacamole hiccup into a partial-failure banner, and keying it on
 *     `lanes_deleted` would miss the all-or-nothing row commit entirely.
 *
 * Both are lifted out of the route source by brace-matching rather than requiring
 * the route, which pulls in the Proxmox client, the CLE pool and the audit writer
 * at require time — same technique as provision-slots.test.js.
 *
 * Run: node --test "test/*.test.js"
 */

const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

const ROUTE = path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'routes', 'vms.js'
);
const src = fs.readFileSync(ROUTE, 'utf8');

function extractFn(name) {
  let start = src.indexOf(`async function ${name}(`);
  if (start === -1) start = src.indexOf(`function ${name}(`);
  assert.notStrictEqual(start, -1, `${name} not found in vms.js — did it get renamed?`);
  let depth = 0, i = src.indexOf('{', start);
  const open = i;
  for (; i < src.length; i++) {
    if (src[i] === '{') depth++;
    else if (src[i] === '}' && --depth === 0) break;
  }
  return { header: src.slice(start, open), body: src.slice(open, i + 1) };
}

function lift(name, ...injected) {
  const { header, body } = extractFn(name);
  // eslint-disable-next-line no-new-func
  return new Function(...injected.map(i => i[0]), `return (${header}${body});`)(
    ...injected.map(i => i[1])
  );
}

const MAX_BULK_LANES = 50;
const LANE_ID_RE = /^[0-9a-f-]{36}$/i;
const parseLaneIds = lift('parseLaneIds',
  ['MAX_BULK_LANES', MAX_BULK_LANES], ['LANE_ID_RE', LANE_ID_RE]);
const bulkDeleteStatus = lift('bulkDeleteStatus');

const U = (n) => `${String(n).padStart(8, '0')}-1111-1111-1111-111111111111`;

// ── parseLaneIds ────────────────────────────────────────────────────────────

test('a non-array or empty lane_ids is a 400', () => {
  for (const body of [{}, { lane_ids: [] }, { lane_ids: 'abc' }, { lane_ids: null }]) {
    assert.throws(() => parseLaneIds(body), (e) => e.status === 400,
      `expected 400 for ${JSON.stringify(body)}`);
  }
  assert.throws(() => parseLaneIds(undefined), (e) => e.status === 400);
});

test('a malformed id is skipped, not thrown, and never reaches the query', () => {
  // The table polls every 8s. One row a co-instructor tore down three seconds
  // ago must not fail the other eleven with no way to tell which.
  const { ids, skipped } = parseLaneIds({ lane_ids: [U(1), 'not-a-uuid', U(2)] });
  assert.deepStrictEqual(ids, [U(1), U(2)]);
  assert.deepStrictEqual(skipped, [{ lane_id: 'not-a-uuid', reason: 'not a lane id' }]);
});

test('SQL-injection-shaped input is rejected by shape, not escaped', () => {
  const { ids, skipped } = parseLaneIds({
    lane_ids: ["'; DROP TABLE cybercore_lane; --", U(3)],
  });
  assert.deepStrictEqual(ids, [U(3)]);
  assert.strictEqual(skipped.length, 1);
  assert.strictEqual(skipped[0].reason, 'not a lane id');
});

test('non-string entries are skipped without throwing', () => {
  const { ids, skipped } = parseLaneIds({ lane_ids: [U(1), 42, null, { a: 1 }, U(2)] });
  assert.deepStrictEqual(ids, [U(1), U(2)]);
  assert.strictEqual(skipped.length, 3);
});

test('duplicates collapse before the cap, so the reported counts cannot lie', () => {
  const { ids, skipped } = parseLaneIds({ lane_ids: [U(1), U(1), U(1), U(2)] });
  assert.deepStrictEqual(ids, [U(1), U(2)]);
  assert.deepStrictEqual(skipped, [], 'a duplicate is not a skip — it is the same lane');
});

test('the cap is a hard 400, never a silent truncation', () => {
  const many = Array.from({ length: MAX_BULK_LANES + 1 }, (_, i) => U(i));
  assert.throws(() => parseLaneIds({ lane_ids: many }), (e) => {
    assert.strictEqual(e.status, 400);
    assert.match(e.message, /at most 50/);
    return true;
  });
  // Exactly at the cap is fine.
  const atCap = Array.from({ length: MAX_BULK_LANES }, (_, i) => U(i));
  assert.strictEqual(parseLaneIds({ lane_ids: atCap }).ids.length, MAX_BULK_LANES);
});

test('a request of only malformed ids is a 400, not an empty success', () => {
  assert.throws(() => parseLaneIds({ lane_ids: ['x', 'y'] }), (e) => e.status === 400);
});

// ── bulkDeleteStatus ────────────────────────────────────────────────────────

test('a clean teardown is 200 even with Guacamole warnings in errors[]', () => {
  // THE load-bearing assertion. teardownLanes merges warnings into `errors`
  // (`errors: [...errors, ...warnings]`) while deciding the row outcome on
  // `errors` alone. A Guacamole 403 leaves nothing running anywhere, so it must
  // not fabricate a partial failure.
  const got = bulkDeleteStatus({
    lanes_deleted: 12, lanes_kept_for_retry: 0, vms_destroyed: 25,
    errors: ['Guac connection abc: 403'], warnings: ['Guac connection abc: 403'],
  }, 12);
  assert.strictEqual(got.status, 200);
  assert.strictEqual(got.success, true);
  assert.match(got.message, /Removed 12 workstation lanes/);
});

test('a survivor is 207 and the message explains the all-or-nothing row commit', () => {
  // One refusing gateway leaves EVERY lane in the batch as 'error', including
  // the eleven that tore down perfectly. Unless the message says so, the
  // instructor sees twelve failed rows and cannot tell that a retry is cheap.
  const got = bulkDeleteStatus({
    lanes_deleted: 0, lanes_kept_for_retry: 12, vms_destroyed: 22,
    errors: ['qemu 600123 (workstation slot 0): failed on all nodes'], warnings: [],
  }, 12);
  assert.strictEqual(got.status, 207);
  assert.strictEqual(got.success, false);
  assert.match(got.message, /press Delete again/i);
  assert.match(got.message, /retry will find nothing left/i);
});

test('status keys on lanes_kept_for_retry, not on lanes_deleted or errors', () => {
  // A batch can legitimately delete zero rows and still be clean — every lane
  // already gone — so `lanes_deleted === 0` must not imply failure.
  assert.strictEqual(bulkDeleteStatus(
    { lanes_deleted: 0, lanes_kept_for_retry: 0, vms_destroyed: 0, errors: [] }, 1).status, 200);
  assert.strictEqual(bulkDeleteStatus(
    { lanes_deleted: 5, lanes_kept_for_retry: 5, vms_destroyed: 9, errors: [] }, 5).status, 207);
});

test('singular and plural read correctly for one lane', () => {
  const got = bulkDeleteStatus(
    { lanes_deleted: 1, lanes_kept_for_retry: 0, vms_destroyed: 1, errors: [] }, 1);
  assert.match(got.message, /Removed 1 workstation lane \(/);
  assert.match(got.message, /1 machine destroyed/);
});

// ── source-level guards ─────────────────────────────────────────────────────

test('bulk delete hands teardownLanes the SERVER-derived ids', () => {
  // The whole scope check is worthless if the handler passes req.body.lane_ids
  // straight through. Text assertion, but it documents the rule at the one place
  // someone would "simplify" it away.
  const start = src.indexOf("router.post('/bulk-delete'");
  assert.notStrictEqual(start, -1);
  const handler = src.slice(start, src.indexOf('\nrouter.', start + 10));
  assert.match(handler, /const laneIds = lanes\.map\(l => l\.lane_id\);/);
  assert.match(handler, /teardownLanes\(laneIds\)/);
  assert.ok(!/teardownLanes\(\s*ids\s*\)/.test(handler),
    'must not pass the client-supplied id array to teardownLanes');
});

test('bulk delete goes through the shared scoped query', () => {
  const start = src.indexOf("router.post('/bulk-delete'");
  const handler = src.slice(start, src.indexOf('\nrouter.', start + 10));
  assert.match(handler, /findCourseWorkstationLanes\(courseId, ids\)/,
    'the material_id IS NULL guard must come from the shared helper');
  // ...and it must not re-implement the predicate inline, which is how the
  // fourth copy eventually drops a clause. Matches the SQL form specifically —
  // the handler's prose comment names material_id on purpose.
  assert.ok(!/config->>'material_id'/.test(handler),
    'the scope predicate belongs in findCourseWorkstationLanes, not inline here');
  assert.ok(!/FROM cybercore_lane/i.test(handler),
    'bulk delete must not run its own lane query');
});

test('bulk delete releases its mutex claim on every path', () => {
  const start = src.indexOf("router.post('/bulk-delete'");
  const handler = src.slice(start, src.indexOf('\nrouter.', start + 10));
  assert.match(handler, /finally\s*\{/, 'the claim must be released in a finally');
  assert.match(handler, /finishProgress\(claimed\)/);
});
