/**
 * Tests for redeploy request validation and lane eligibility (cle/routes/vms.js)
 *
 * The three pure helpers behind POST /redeploy. What they protect:
 *
 *   parseRedeployRequest — `slots` is a machine SUBSET, and getting it wrong
 *     means rebuilding a machine nobody asked about or silently skipping one
 *     they did. It is expressed as slot numbers rather than vmids on purpose:
 *     slot is the stable identity (it determines the octet, the console WAN
 *     port, the DHCP reservation and the DNAT rule) while a vmid is
 *     cluster-global and would be a cluster-wide destroy primitive if a scope
 *     check were ever dropped.
 *
 *   redeployEligibility — an in-place rebuild's entire premise is that the
 *     gateway, VXLAN, WAN address and Guacamole connection survive. An 'error'
 *     lane preserves none of that, so letting one through would clone machines
 *     behind a gateway that may not exist.
 *
 *   machineSlotsOf — a legacy lane with no config.workstations[] must still
 *     report slot 0, or every lane deployed before that key existed becomes
 *     un-rebuildable.
 *
 * Lifted from the route source by brace-matching rather than requiring the
 * route, which pulls in the Proxmox client and the CLE pool at require time —
 * same technique as provision-slots.test.js.
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
  return src.slice(start, i + 1);
}

const WORKSTATION_MAX_SLOTS = 30;
// parseRedeployRequest calls machineSlotsOf, so both are compiled together.
// eslint-disable-next-line no-new-func
const { parseRedeployRequest, machineSlotsOf, redeployEligibility } = new Function(
  'WORKSTATION_MAX_SLOTS',
  `${extractFn('parseRedeployRequest')}
   ${extractFn('machineSlotsOf')}
   ${extractFn('redeployEligibility')}
   return { parseRedeployRequest, machineSlotsOf, redeployEligibility };`
)(WORKSTATION_MAX_SLOTS);

const lane = (over = {}) => ({
  lane_id: 'aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  status: 'active',
  config: { workstations: [{ slot: 0, vmid: 610003 }, { slot: 1, vmid: 310221 }] },
  ...over,
});

// ── machineSlotsOf ──────────────────────────────────────────────────────────

test('recorded slots are reported', () => {
  assert.deepStrictEqual(machineSlotsOf(lane()), [0, 1]);
});

test('a legacy lane with only flat keys still reports slot 0', () => {
  assert.deepStrictEqual(machineSlotsOf({ config: { workstation_vmid: 610007 } }), [0]);
});

test('a lane with nothing recorded reports no slots', () => {
  assert.deepStrictEqual(machineSlotsOf({ config: {} }), []);
  assert.deepStrictEqual(machineSlotsOf({}), []);
});

// ── parseRedeployRequest ────────────────────────────────────────────────────

test('no slots means every machine', () => {
  assert.deepStrictEqual(parseRedeployRequest({}, [lane()]), { slots: null, fullLane: false });
  assert.deepStrictEqual(
    parseRedeployRequest({ slots: null }, [lane()]), { slots: null, fullLane: false });
});

test('a subset is de-duped and sorted', () => {
  const got = parseRedeployRequest({ slots: [1, 0, 1] }, [lane()]);
  assert.deepStrictEqual(got.slots, [0, 1]);
});

test('slots require exactly one lane', () => {
  // With two lanes "which machines?" has no single answer — a per-lane machine
  // matrix would be a table, not a request body.
  assert.throws(() => parseRedeployRequest({ slots: [0] }, [lane(), lane()]), (e) => {
    assert.strictEqual(e.status, 400);
    assert.match(e.message, /exactly one lane/);
    return true;
  });
});

test('an unknown slot is a 400 naming it, never a silent skip', () => {
  // Quietly rebuilding fewer machines than asked is invisible until a student
  // reports it.
  assert.throws(() => parseRedeployRequest({ slots: [0, 7] }, [lane()]), (e) => {
    assert.strictEqual(e.status, 400);
    assert.match(e.message, /no machine in slot 7/);
    return true;
  });
});

test('a non-integer or out-of-band slot is rejected', () => {
  // null/''/[] all coerce to 0 through Number(), which is a real slot — so a
  // malformed body must be rejected, not silently aimed at the console machine.
  for (const bad of ['x', -1, 1.5, WORKSTATION_MAX_SLOTS, null, '', [], true, {}]) {
    assert.throws(() => parseRedeployRequest({ slots: [bad] }, [lane()]),
      (e) => e.status === 400, `expected 400 for slot ${bad}`);
  }
});

test('an empty slots array is rejected rather than meaning "all"', () => {
  // Silently widening an empty selection to every machine is the opposite of
  // what an instructor who unticked everything intended.
  assert.throws(() => parseRedeployRequest({ slots: [] }, [lane()]), (e) => e.status === 400);
});

test('slots cannot be combined with full_lane', () => {
  // A whole-lane rebuild destroys and recreates everything; a subset of that is
  // not a coherent request.
  assert.throws(() => parseRedeployRequest({ slots: [0], full_lane: true }, [lane()]), (e) => {
    assert.strictEqual(e.status, 400);
    assert.match(e.message, /full_lane/);
    return true;
  });
});

test('full_lane must be exactly true, so a stray truthy value cannot arm it', () => {
  // This is the flag that invalidates every connection detail a student holds.
  assert.strictEqual(parseRedeployRequest({ full_lane: 'yes' }, [lane()]).fullLane, false);
  assert.strictEqual(parseRedeployRequest({ full_lane: 1 }, [lane()]).fullLane, false);
  assert.strictEqual(parseRedeployRequest({ full_lane: true }, [lane()]).fullLane, true);
});

test('a subset works against a legacy lane with only slot 0', () => {
  const legacy = lane({ config: { workstation_vmid: 610007 } });
  assert.deepStrictEqual(parseRedeployRequest({ slots: [0] }, [legacy]).slots, [0]);
  assert.throws(() => parseRedeployRequest({ slots: [1] }, [legacy]), (e) => e.status === 400);
});

// ── redeployEligibility ─────────────────────────────────────────────────────

test('only an active lane may be rebuilt in place', () => {
  assert.strictEqual(redeployEligibility(lane(), false).ok, true);

  // An 'error' lane got there either from markLaneError (so there may be no
  // gateway to rebuild INTO) or from a failed teardown (so the row is a
  // tombstone pointing at survivors). Neither preserves what in-place needs.
  const err = redeployEligibility(lane({ status: 'error' }), false);
  assert.strictEqual(err.ok, false);
  assert.match(err.reason, /whole-lane rebuild/);
});

test('a full-lane rebuild accepts an error lane — that is what it is for', () => {
  assert.strictEqual(redeployEligibility(lane({ status: 'error' }), true).ok, true);
});

test('a deploying lane is refused on BOTH paths', () => {
  // The mutex should already have caught this; the status check is the belt.
  assert.strictEqual(redeployEligibility(lane({ status: 'deploying' }), false).ok, false);
  assert.strictEqual(redeployEligibility(lane({ status: 'deploying' }), true).ok, false);
});

test('an active lane recording no machines cannot be rebuilt in place', () => {
  const empty = lane({ config: {} });
  const v = redeployEligibility(empty, false);
  assert.strictEqual(v.ok, false);
  assert.match(v.reason, /whole-lane rebuild/);
});

// ── source-level guards ─────────────────────────────────────────────────────

function redeployHandler() {
  const start = src.indexOf("router.post('/redeploy'");
  assert.notStrictEqual(start, -1);
  return src.slice(start, src.indexOf('\nrouter.', start + 10));
}

test('redeploy resolves lanes through the shared scoped query', () => {
  const h = redeployHandler();
  assert.match(h, /findCourseWorkstationLanes\(courseId, ids\)/);
  assert.ok(!/config->>'material_id'/.test(h),
    'the scope predicate belongs in findCourseWorkstationLanes, not inline');
});

test('redeploy never resolves students — the lane is the unit', () => {
  // resolveTargetStudents excludes exactly the students a redeploy targets, and
  // its enrollment filter would skip a dropped student's leftover lane — which
  // is precisely the row an instructor most needs to rebuild or remove.
  const h = redeployHandler();
  assert.ok(!/resolveTargetStudents\(/.test(h),
    'lane ⊆ managed course is the authorization here');
});

test('the mutex is claimed and handed to exactly one owner', () => {
  const h = redeployHandler();
  assert.match(h, /assertNoConflictingWorkstationOperation\(/);
  // The background block owns the claim once the 202 is out; nulling `claimed`
  // is what stops the catch from releasing it a second time.
  assert.match(h, /claimed = null;\s*\/\/ ownership handed to the background block/);
  assert.match(h, /if \(res\.headersSent\) return;/);
});

test('a single-lane rebuild claims a per-lane key, not the course key', () => {
  // Two instructors fixing two students must not queue behind each other.
  const h = redeployHandler();
  assert.match(h, /progressIdForLane\(courseId, single\)/);
  assert.match(h, /progressIdForCourseRebuild\(courseId\)/);
});
