/**
 * lane-teardown-parity.test.js — one teardown, one gate.
 *
 * WHY THIS FILE EXISTS
 * There were FIVE lane teardown implementations and only one of them was
 * correct. The other four each dropped a different subset of the safety work,
 * and the difference was invisible at every call site because they all returned
 * something that looked like success:
 *
 *   - admin DELETE /lanes/:id      deleted the row unconditionally, never read
 *                                  cfg.workstations[], no ownership check, no
 *                                  retry rounds, no disk sweep
 *   - admin DELETE /groups/:id     deleted the rows inside a Promise.all with no
 *                                  gate, alongside a cybercore_user DELETE that
 *                                  CASCADES to those same rows
 *   - CIAB teardownLane            deleted the row AND swallowed the delete's own
 *                                  failure, ignored forceDestroyVM's return value
 *   - detachModuleFromLane         stripped the instance from config even when a
 *                                  VM survived, losing the only record of its id
 *
 * Each of those orphans a machine AND releases its vxlan_id, which is what lets
 * the next deploy clone a gateway on top of a container that is still running.
 * Once that happens the contested-VXLAN guard correctly refuses to let the old
 * row destroy anything, so the survivors can never be cleaned up by any path.
 *
 * These are source-text assertions. That is a blunt instrument, but the property
 * being defended — "nothing else deletes a lane row" — is exactly the kind that
 * gets reintroduced by someone reasonably inlining "just this one small case".
 *
 * Run: node front-end/test/lane-teardown-parity.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

const DEPLOYER = 'src/utils/lane-deployer.js';
const ROUTES = [
  'src/routes/admin/lanes.js',
  'src/routes/admin/groups.js',
  // A7 split CIAB's fourth copy in two: the reservation (and this teardown) into
  // lane-reservation.js, the deploy into lane-provision.js. Both are listed so a
  // DELETE reintroduced in either is caught.
  'modules/crucible/plugins/ciab/utils/lane-reservation.js',
  'modules/crucible/plugins/ciab/utils/lane-provision.js',
  'modules/crucible/plugins/ciab/routes/profile-deploy.js',
];

// ── the single delete point ─────────────────────────────────────────────────

test('only lane-deployer.js deletes cybercore_lane rows', () => {
  // The lane row is the ONLY handle on a lane's derived VMIDs, and deleting it
  // frees the vxlan_id. Both consequences are why the delete lives behind the
  // gate in teardownLanes and nowhere else.
  const offenders = [];
  for (const rel of ROUTES) {
    const src = read(rel);
    src.split(/\r?\n/).forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*') || t.startsWith('--')) return;
      if (/DELETE\s+FROM\s+cybercore_lane\b/i.test(line)) {
        offenders.push(`${rel}:${i + 1}  ${t}`);
      }
    });
  }
  assert.deepStrictEqual(offenders, [],
    'Only teardownLanes may delete a lane row, and only when nothing survived:\n'
    + offenders.join('\n'));
});

test('the gate in teardownLanes keys on errors, not on warnings', () => {
  const src = read(DEPLOYER);
  // `errors` means something this teardown owns is still out there. `warnings`
  // means bookkeeping in another system (a Guacamole 403) that holds nothing on
  // the cluster. Keying the row decision on warnings would leave every torn-down
  // machine on screen as a permanent ERROR after one Guacamole hiccup.
  const gateStart = src.indexOf('let deleted = 0;');
  assert.notStrictEqual(gateStart, -1);
  const gateEnd = src.indexOf('\n  console.log(', gateStart);
  assert.ok(gateEnd > gateStart);
  const gate = src.slice(gateStart, gateEnd);
  const failureBranch = gate.indexOf('\n  } else {');
  assert.notStrictEqual(failureBranch, -1);
  const success = gate.slice(0, failureBranch);
  assert.match(success, /^let deleted = 0;\s+if \(errors\.length === 0\) \{/,
    'the only row-delete branch must remain gated on no teardown errors');
  assert.strictEqual((success.match(/DELETE FROM cybercore_lane/g) || []).length, 1);
  assert.ok(!/DELETE FROM cybercore_lane/.test(gate.slice(failureBranch)),
    'the failure branch must never delete retained lane rows');

  // warnings.length IS referenced in the gate — to log the Guacamole/workspace
  // failures after the fact. What must never happen is it being consulted BEFORE
  // the delete, which would turn one Guacamole 403 into a permanently retained
  // lane row for every machine that was in fact destroyed cleanly.
  const del = gate.indexOf('DELETE FROM cybercore_lane');
  const warnRef = gate.indexOf('warnings.length');
  assert.notStrictEqual(del, -1);
  if (warnRef !== -1) {
    assert.ok(warnRef > del,
      'warnings.length is consulted before the row delete — it must only be reported after it');
  }
  assert.match(gate, /status = 'error'/, 'a failed teardown must keep the row for retry');
});

test('the single lane DELETE atomically hands the latest safe registration metadata to cleanup', () => {
  const src = read(DEPLOYER);
  const statement = src.match(/`WITH removed AS \([\s\S]*?SELECT lane_id FROM removed`/)?.[0];
  assert.ok(statement, 'DELETE and outbox INSERT must share one database statement');
  assert.match(statement, /DELETE FROM cybercore_lane[\s\S]*RETURNING lane_id, config/);
  assert.match(statement, /INSERT INTO cybercore_wazuh_cleanup \(lane_id, registrations\)/);
  assert.match(statement, /jsonb_each\(CASE[\s\S]*removed\.config->'wazuh_agent_jobs'/,
    'handoff must use the deleted row rather than the initial teardown snapshot');
  const selectedFields = [...statement.matchAll(/'([a-z_]+)', job\.value->>?'/g)].map(match => match[1]);
  assert.deepStrictEqual(selectedFields, ['job_id', 'vm_id', 'manager', 'agent_id', 'agent_name'],
    'outbox must retain only registration identity, never keys or unrelated lane configuration');
  assert.match(statement, /registrations = cybercore_wazuh_cleanup\.registrations \|\| EXCLUDED\.registrations/);
  assert.match(statement, /retain_until = GREATEST\(/);
  const teardown = src.slice(src.indexOf('async function teardownLanes('));
  assert.ok(teardown.indexOf('await wazuhCleanup.ensureSchema()') < teardown.indexOf("proxmoxAPI('GET'"),
    'missing outbox schema must fail before infrastructure is touched');
  assert.ok(teardown.indexOf('wazuh_teardown_started: true') < teardown.indexOf("proxmoxAPI('GET'"),
    'new enrollment jobs must be blocked before VM teardown');
});

// ── the delegating routes ───────────────────────────────────────────────────

test('every lane teardown route delegates to teardownLanes', () => {
  for (const rel of ['src/routes/admin/lanes.js', 'src/routes/admin/groups.js']) {
    assert.match(read(rel), /teardownLanes\(/, `${rel} must delegate`);
  }
  assert.match(read('modules/crucible/plugins/ciab/utils/lane-reservation.js'),
    /laneDeployer\.teardownLanes\(/, 'the CIAB path must delegate too');
});

test('the CIAB path passes its job-table VMIDs through as extraVmIds', () => {
  // ciab_profile_lane_jobs.vm_ids is written as the deploy progresses, so a lane
  // whose config write never landed has its machines recorded nowhere else.
  // They must still go through the contested and ownership checks, which is why
  // they are handed to teardownLanes rather than destroyed directly.
  const src = read('modules/crucible/plugins/ciab/utils/lane-reservation.js');
  const start = src.indexOf('async function teardownLane(');
  assert.notStrictEqual(start, -1);
  const fn = src.slice(start, start + 1600);
  assert.match(fn, /extraVmIds:/, 'vm_ids must reach teardownLanes as extraVmIds');
  assert.ok(!/forceDestroyVM\(/.test(fn),
    'must not destroy VMs directly — that path had no ownership or contested check');
});

test('contested lanes drop caller-supplied VMIDs too', () => {
  // extraVmIds arrive as bare ids with no lane attached, so when a live lane has
  // recycled the VXLAN there is no way to tell whose machines they name. The
  // contested rule is "destroy nothing", not "destroy what we can guess".
  const src = read(DEPLOYER);
  const start = src.indexOf('if (extraVmIds.length > 0)');
  assert.notStrictEqual(start, -1);
  assert.match(src.slice(start, start + 500), /contested\.size > 0/);
});

// ── the CASCADE that undoes the gate ────────────────────────────────────────

test('user deletes are gated on the teardown having actually finished', () => {
  // cybercore_lane.user_id is ON DELETE CASCADE, so deleting a student erases
  // the very rows the gate just kept — with no Proxmox interaction at all,
  // orphaning every survivor permanently and releasing its vxlan_id.
  const groups = read('src/routes/admin/groups.js');
  assert.match(groups, /const canDeleteUsers = \(teardown\.lanes_kept_for_retry \|\| 0\) === 0;/);
  const del = groups.indexOf('DELETE FROM cybercore_user');
  assert.notStrictEqual(del, -1);
  assert.match(groups.slice(Math.max(0, del - 400), del), /canDeleteUsers/,
    'the cybercore_user DELETE must sit behind canDeleteUsers');

  const ciab = read('modules/crucible/plugins/ciab/routes/profile-deploy.js');
  assert.match(ciab, /lanesKeptForRetry === 0 && studentIds\.length > 0/,
    'the CIAB student delete must be gated the same way');
});

test('nothing keys the row decision on errors.length in a delegating route', () => {
  // teardownLanes returns errors: [...errors, ...warnings], so errors.length is
  // true for a Guacamole 403 that left nothing running. Every caller must read
  // lanes_kept_for_retry instead.
  for (const rel of ROUTES) {
    const src = read(rel);
    src.split(/\r?\n/).forEach((line, i) => {
      const t = line.trim();
      if (t.startsWith('//') || t.startsWith('*')) return;
      assert.ok(!/(teardown|result)\.errors\.length\s*===?\s*0/.test(line),
        `${rel}:${i + 1} keys a decision on errors.length; use lanes_kept_for_retry — ${t}`);
    });
  }
});

// ── attached modules ────────────────────────────────────────────────────────

test('detach keeps the module recorded when a VM survived', () => {
  // config.attached_modules[] is the only record of an instance's VMIDs. Strip
  // it while a machine is alive and nothing can find that machine again except a
  // full-band audit sweep.
  const src = read('src/routes/admin/lanes.js');
  const start = src.indexOf("router.delete('/lanes/:laneId/modules/:moduleInstanceId'");
  assert.notStrictEqual(start, -1);
  const handler = src.slice(start, src.indexOf('\nrouter.', start + 10));
  assert.match(handler, /if \(errors\.length > 0\) \{/, 'must branch on destroy errors');
  assert.match(handler, /detach_errors/, 'must record why, mirroring teardown_errors');
  const strip = handler.indexOf('attached_modules = (curCfg.attached_modules');
  const guard = handler.indexOf('if (errors.length > 0) {');
  assert.ok(guard !== -1 && guard < strip,
    'the config strip must come after the failure branch returns');
});
