/**
 * ============================================================================
 * bake-orchestrator.js — Track G5: the per-profile bake, made durable,
 * restartable and safe to refuse.
 * ----------------------------------------------------------------------------
 * WHAT A BAKE IS
 * One compiled client environment, built once on a STAGING lane, verified, and
 * captured as golden templates that every student lane afterwards merely clones.
 * The expensive part is the middle: a GOAD chain is 16 separate
 * ansible-playbook invocations, ~90 minutes, and nothing in vulnerabilities.yml
 * is so much as PARSED until ~95% of that has already been paid for.
 *
 * WHAT THIS MODULE IS FOR
 * The chain cannot be trusted to report its own health. An audit of the vendored
 * role library found 20 sites where a task reports SUCCESS and did nothing —
 * three of them shipped vulnerabilities that are simply not present afterwards
 * (vulns/adcs_esc7's `Get-Module -ListAvailable` guard is inverted and the task
 * before it installs the module, so ManageCA is never granted; move_to_ou writes
 * `$target_ou = Get-ADOrganizationalUnit -Identity $ou_path > $null`, which
 * consumes the success stream so the variable is always null and a bad OU path
 * is swallowed by a typed catch; no_ldap_signing writes
 * HKLM:\SYSTEM\CurrentControlSet\Services\LDAP\LDAPServerSigningRequirements,
 * a path Windows does not read, while its sibling no_ldap_integrity targets the
 * correct NTDS\Parameters one). Tree-wide, `changed_when` appears exactly TWICE
 * and `error_action: stop` six times. Neither "changed" nor the exit code
 * carries information.
 *
 * So the orchestrator's job is not to run the chain — it is to make the run
 * OBSERVABLE while it happens, RECOVERABLE when the process dies under it, and
 * REFUSABLE when what it produced is no longer what the profile says.
 *
 * ----------------------------------------------------------------------------
 * SHAPE: engagement-provision.js, deliberately
 * ----------------------------------------------------------------------------
 * That module is this codebase's established durable-status precedent, and its
 * header explains what it improves on (CLE's provision path: no re-provision, no
 * boot recovery, no concurrency guard). Everything it does, this does:
 * an in-process mutex, a detached worker that cannot throw out of its own top
 * level, a boot sweep, and a hard deploy gate with no inline fallback.
 *
 * What this ADDS, because the resource being managed is bigger:
 *
 *   - PROGRESS. Reserving a VXLAN block takes minutes and writes one terminal
 *     row. A bake takes ninety and, before this module, also wrote one terminal
 *     row — up to two hours later. status + phase_detail are streamed as work
 *     happens, because otherwise a working bake and a hung bake are the same
 *     row. phase_detail is deliberately the SAME COLUMN NAME as
 *     ciab_profile_lane_jobs.phase_detail (migration 006), which the admin UI
 *     already polls and renders. A second status channel would mean a second
 *     renderer and a second thing to keep true.
 *
 *   - TEARDOWN ON RECOVERY. A stranded engagement leaks bookkeeping. A stranded
 *     bake leaks an entire lane plus a controller VM, and nothing else in the
 *     system can enumerate them once the row stops pointing at them. So the
 *     sweep marks the row failed AND schedules the staging lane's demolition.
 *
 *   - DRIFT AS A REFUSAL. An engagement is deployable when its network exists.
 *     A bake is deployable only while it still describes the profile it was
 *     built from and the toolchain it was built with — see assertBakeDeployable.
 *
 * ----------------------------------------------------------------------------
 * RESUMABILITY: THE WHOLE BAKE RESTARTS; EACH PHASE IS IDEMPOTENT
 * ----------------------------------------------------------------------------
 * There is deliberately NO per-phase resume. A resumed bake would have to
 * re-enter a chain that cannot be re-entered: /opt/goad-light/run.sh is not
 * idempotent, and a half-promoted forest is not a state any playbook in the
 * chain is written to start from. The push, by contrast, IS content-addressed —
 * pushing ad/CIAB-<hash8> that already exists byte-for-byte is a no-op — and the
 * compile is pure, so re-running the early phases costs seconds.
 *
 * A restart therefore means a FRESH staging lane, and the previous one is torn
 * down first. That is cheaper and more honest than a resume that would have to
 * guess how far the chain got from output nobody can trust, and the worst case
 * is already bounded: runGoadPlaybook (src/utils/goad-deploy.js) carries a 2-hour
 * watchdog on the run it detaches into the controller.
 *
 * ----------------------------------------------------------------------------
 * THE PHASES ARE INJECTED, AND A MISSING ONE IS A FAILURE, NOT A SKIP
 * ----------------------------------------------------------------------------
 * This module owns sequencing, status, progress, recovery and refusal. It does
 * not own compiling, pushing, provisioning, verifying or capturing — those are
 * separate modules with their own tests, and hard-requiring them here would make
 * the orchestrator untestable offline and would couple its lifecycle to theirs.
 *
 * A step that is absent throws and the bake is recorded FAILED naming the phase.
 * It is never skipped. Skipping is the precise failure this whole track exists
 * to eliminate: a run that reports success and did nothing.
 * ============================================================================
 */

const { query } = require('./db');

const LOG = '[CIAB Bake]';

// ─── Vocabulary ─────────────────────────────────────────────────────────────
// These lists are the JS half of migration 015's CHECK constraint. They must
// agree: a status this file writes that the constraint does not accept raises
// 23514, and a pg error carries neither `status` nor `statusCode`, so every
// renderer in routes/profile-deploy.js turns it into an unhandled 500 naming a
// constraint. test/ciab-bake-orchestrator.test.js parses the migration and
// diffs the two, so the disagreement fails a test rather than a bake.

/** Every legal value of ciab_profile_bake.status. */
const BAKE_STATUSES = Object.freeze([
  'pending', 'compiling', 'pushing', 'provisioning',
  'verifying', 'capturing', 'ready', 'failed', 'superseded',
]);

/**
 * The five statuses that mean "a process in THIS node was doing work". These
 * are the ones migration 015's partial index covers and the ones that leak a
 * staging lane when a restart lands on them. 'pending' is non-terminal too, but
 * it has allocated nothing — the sweep handles it separately.
 */
const ACTIVE_STATUSES = Object.freeze([
  'compiling', 'pushing', 'provisioning', 'verifying', 'capturing',
]);

/** Nothing will move these on its own. */
const TERMINAL_STATUSES = Object.freeze(['ready', 'failed', 'superseded']);

/**
 * The bake, in order.
 *
 * `status` is what the row reads while the phase runs; `label` is the initial
 * phase_detail, which the step then overwrites with something specific as it
 * learns anything. The label is a full sentence because it is read by an
 * instructor in a panel, not by the person who wrote this file.
 */
const PHASES = Object.freeze([
  Object.freeze({
    step: 'compile', status: 'compiling',
    label: 'Compiling the lab definition and validating it against the pinned role manifest',
  }),
  Object.freeze({
    step: 'push', status: 'pushing',
    label: 'Pushing the lab definition to the controller',
  }),
  Object.freeze({
    step: 'provision', status: 'provisioning',
    label: 'Building the staging lane and running the GOAD chain (this takes about ninety minutes)',
  }),
  Object.freeze({
    step: 'verify', status: 'verifying',
    label: 'Checking that what the playbooks reported is actually on the machines',
  }),
  Object.freeze({
    step: 'capture', status: 'capturing',
    label: 'Capturing golden templates from the staging lane',
  }),
]);

/**
 * The ONLY columns a phase may write back.
 *
 * A whitelist rather than a spread, for the same reason rowToEngagement is one:
 * a step that returns a key nobody wired up must FAIL rather than have its value
 * silently dropped. Dropping it is indistinguishable from the step not having
 * produced it, which is how a bake ends up 'ready' with no staging_lane_id and
 * a lane nothing can find.
 */
const STEP_PATCH_COLUMNS = Object.freeze([
  'staging_lane_id', 'staging_vxlan_id', 'controller_vmid',
  'verify_report', 'bh_report', 'golden_vmids',
]);

/**
 * Which of those are jsonb. Every one is JSON.stringify'd and cast on FIRST
 * reference — Postgres fixes a parameter's type at its first use, and there is
 * deliberately no `$n IS NULL` construction anywhere in this file (the pattern
 * test/sql-param-typing.test.js scans every .js under src/ and modules/ for).
 */
const JSONB_PATCH_COLUMNS = new Set(['verify_report', 'bh_report', 'golden_vmids']);

/**
 * The three sign-offs, with the words an operator sees when one is missing.
 *
 * They exist because the toolchain reports green while planting nothing, so the
 * last line of defence is a person having actually looked:
 *   solvable      — someone walked the intended path end to end on the built lab
 *   paper         — the scan report / answer key describes the lab that exists
 *   no_unintended — nothing shorter than the intended path was found
 */
const GATES = Object.freeze([
  Object.freeze({ column: 'gate_solvable', label: 'the intended solve path has been walked end to end' }),
  Object.freeze({ column: 'gate_paper', label: 'the paper artefacts match the environment that was built' }),
  Object.freeze({ column: 'gate_no_unintended', label: 'no unintended shortcut was found' }),
]);

/** How often a running phase touches updated_at. See startHeartbeat(). */
const HEARTBEAT_MS = 60000;

/**
 * Bakes running in THIS process.
 *
 * The DB status is not sufficient on its own, for exactly the reason
 * engagement-provision.js gives: two requests can both read a non-terminal
 * status before either writes. The resource underneath is worse than a VXLAN
 * block, though — a staging lane is not idempotent in any sense. A second
 * concurrent bake of one row allocates a SECOND lane and a SECOND controller VM,
 * then both write staging_lane_id over each other, and whichever loses is
 * unfindable forever. One Node process, so a Set is a real mutex here (same
 * reasoning as the progress registry in lane-provision.js).
 */
const _inFlight = new Set();

// ─── Pure helpers ───────────────────────────────────────────────────────────

/**
 * The ad/<LAB> directory name for a compiled lab.
 *
 * ONE derivation, called at INSERT and nowhere else — the result is stored in
 * lab_name. Recomputing it on read would mean a later change to this rule
 * silently renames a directory that already exists on a controller and has
 * templates captured against it.
 *
 * Eight hex characters is 4 billion, against a population of at most a few
 * thousand compiled labs ever; the full hash stays in lab_hash, which is what
 * identity is actually measured on.
 */
function labNameForHash(labHash) {
  if (typeof labHash !== 'string' || !/^[0-9a-f]{8,64}$/.test(labHash)) {
    throw Object.assign(
      new Error('lab_hash must be a lowercase hex digest of at least 8 characters'),
      { status: 400, code: 'BAKE_LAB_HASH_INVALID' }
    );
  }
  return `CIAB-${labHash.slice(0, 8)}`;
}

/**
 * Every VMID a bake owns outside its lane row: the controller, plus whatever
 * golden templates were captured.
 *
 * Tolerant of three shapes because the capture step is not this module's and
 * its report shape is its own business: a bare array of numbers, an array of
 * `{vmid}`/`{vm_id}` records, or a name-keyed object of either. Guessing wrong
 * here is a silent leak — teardown enumerates nothing, reports success, and the
 * templates sit on the cluster forever — so it accepts all three rather than
 * pinning one and failing quietly on the others.
 */
function vmidsFromGolden(golden) {
  if (!golden) return [];
  const entries = Array.isArray(golden)
    ? golden
    : (typeof golden === 'object' ? Object.values(golden) : []);
  const out = [];
  for (const entry of entries) {
    const raw = (entry && typeof entry === 'object')
      ? (entry.vmid != null ? entry.vmid : entry.vm_id)
      : entry;
    const n = Number(raw);
    if (Number.isInteger(n) && n > 0) out.push(n);
  }
  return Array.from(new Set(out));
}

/**
 * Controller + golden templates, deduped, controller FIRST.
 *
 * The order is deliberate rather than incidental: the controller is the one VM
 * a bake is guaranteed to have made, so putting it at the head means a teardown
 * that dies partway through has destroyed the thing most likely to be running.
 * Everything else the lane owns is enumerated from the lane row itself.
 */
function vmidsForTeardown(bake) {
  if (!bake) return [];
  const controller = Number(bake.controller_vmid);
  const head = (Number.isInteger(controller) && controller > 0) ? [controller] : [];
  return Array.from(new Set([...head, ...vmidsFromGolden(bake.golden_vmids)]));
}

// ─── Reads ──────────────────────────────────────────────────────────────────

/**
 * The projection every caller sees.
 *
 * A WHITELIST, not a spread of the row: a column added by a later migration and
 * not added here is invisible to callers even though SELECT * really does return
 * it, and the test diffs this list against the migration's column list so the
 * omission fails a test rather than a demo.
 */
function rowToBake(row) {
  if (!row) return null;
  return {
    bake_id: row.bake_id,
    profile_id: row.profile_id,
    lab_hash: row.lab_hash,
    lab_name: row.lab_name,
    goad_ref: row.goad_ref,
    manifest_sha: row.manifest_sha,
    spec: row.spec,
    staging_lane_id: row.staging_lane_id,
    staging_vxlan_id: row.staging_vxlan_id,
    controller_vmid: row.controller_vmid,
    status: row.status,
    phase_detail: row.phase_detail,
    error: row.error,
    verify_report: row.verify_report,
    bh_report: row.bh_report,
    gate_solvable: row.gate_solvable,
    gate_paper: row.gate_paper,
    gate_no_unintended: row.gate_no_unintended,
    gates_approved_by: row.gates_approved_by,
    gates_approved_at: row.gates_approved_at,
    golden_vmids: row.golden_vmids,
    started_at: row.started_at,
    finished_at: row.finished_at,
    created_by: row.created_by,
    created_at: row.created_at,
    updated_at: row.updated_at,
  };
}

async function getBakeById(bakeId) {
  const res = await query(`SELECT * FROM ciab_profile_bake WHERE bake_id = $1`, [bakeId]);
  return rowToBake(res.rows[0]);
}

/** The bake for one exact content version. This is the identity that matters. */
async function getBake(profileId, labHash) {
  const res = await query(
    `SELECT * FROM ciab_profile_bake WHERE profile_id = $1 AND lab_hash = $2`,
    [profileId, labHash]
  );
  return rowToBake(res.rows[0]);
}

async function listBakes(profileId) {
  const res = await query(
    `SELECT * FROM ciab_profile_bake WHERE profile_id = $1 ORDER BY created_at DESC`,
    [profileId]
  );
  return res.rows.map(rowToBake);
}

/**
 * The bake a deploy would use: the most recently finished 'ready' one.
 *
 * Deliberately does NOT filter on the current lab_hash. Whether this bake is
 * still current is assertBakeDeployable's question, and it must be able to
 * answer "your profile was edited since this was built" — which it cannot do if
 * the read already dropped the row on the floor and produced BAKE_NOT_BUILT
 * instead. A stale bake with an accurate refusal is worth more than no bake with
 * a vague one.
 */
async function getLatestReadyBake(profileId) {
  const res = await query(
    `SELECT * FROM ciab_profile_bake
      WHERE profile_id = $1 AND status = 'ready'
      ORDER BY finished_at DESC NULLS LAST, created_at DESC
      LIMIT 1`,
    [profileId]
  );
  return rowToBake(res.rows[0]);
}

// ─── Writers ────────────────────────────────────────────────────────────────

/**
 * Enter a phase: the status, the opening phase_detail, and the start stamp.
 *
 * started_at is COALESCEd rather than assigned so entering phase two does not
 * move it. restartBake clears it, which is what makes a restart read as a fresh
 * attempt rather than one that has been running for six hours.
 */
async function setBakePhase(bakeId, status, detail) {
  await query(
    `UPDATE ciab_profile_bake
        SET status = $2, phase_detail = $3,
            started_at = COALESCE(started_at, now()), updated_at = now()
      WHERE bake_id = $1`,
    [bakeId, status, detail == null ? null : String(detail).slice(0, 2000)]
  );
}

/**
 * Durable progress inside a phase.
 *
 * BEST EFFORT, ALWAYS. A failed progress write must never fail a bake — losing
 * a line of text is a cosmetic problem and killing ninety minutes of work over
 * it is not. That asymmetry is deliberate and is the opposite of
 * recordBakeFields() below, which must not swallow anything.
 */
async function setBakeDetail(bakeId, detail) {
  try {
    await query(
      `UPDATE ciab_profile_bake
          SET phase_detail = $2, updated_at = now()
        WHERE bake_id = $1`,
      [bakeId, detail == null ? null : String(detail).slice(0, 2000)]
    );
    return true;
  } catch (err) {
    console.warn(`${LOG} progress write dropped for ${bakeId}: ${err.message}`);
    return false;
  }
}

/**
 * Persist what a phase learned.
 *
 * NOT best effort. staging_lane_id is the only handle anything will ever have on
 * the lane this bake is building; a swallowed write here is the leak the whole
 * recovery path exists to prevent, so a failure propagates and fails the bake
 * while the lane is still identifiable from the process that made it.
 *
 * The column names interpolated into the SQL come from STEP_PATCH_COLUMNS — a
 * frozen module constant — and never from a caller: an unlisted key is rejected
 * above, so nothing a step returns can reach the statement text. Only values are
 * parameters.
 */
function assertStepPatch(patch, where) {
  if (patch == null) return null;
  if (typeof patch !== 'object' || Array.isArray(patch)) {
    throw new Error(`${where} returned ${Array.isArray(patch) ? 'an array' : typeof patch} — a phase may only return an object of columns to record`);
  }
  const unknown = Object.keys(patch).filter(k => !STEP_PATCH_COLUMNS.includes(k));
  if (unknown.length > 0) {
    throw new Error(
      `${where} tried to record unknown column(s): ${unknown.join(', ')}. ` +
      `A bake may only write ${STEP_PATCH_COLUMNS.join(', ')} — silently dropping the rest ` +
      `is how a bake reaches 'ready' with no staging lane recorded.`
    );
  }
  return patch;
}

async function recordBakeFields(bakeId, patch) {
  const params = [bakeId];
  const sets = [];
  for (const column of STEP_PATCH_COLUMNS) {
    if (!Object.prototype.hasOwnProperty.call(patch, column)) continue;
    const raw = patch[column];
    if (JSONB_PATCH_COLUMNS.has(column)) {
      params.push(JSON.stringify(raw === undefined ? null : raw));
      sets.push(`${column} = $${params.length}::jsonb`);
    } else {
      params.push(raw === undefined ? null : raw);
      sets.push(`${column} = $${params.length}`);
    }
  }
  if (sets.length === 0) return false;
  // Set by hand: this schema has no triggers anywhere, and every other UPDATE in
  // this file does the same.
  sets.push('updated_at = now()');
  await query(
    `UPDATE ciab_profile_bake SET ${sets.join(', ')} WHERE bake_id = $1`,
    params
  );
  return true;
}

/**
 * A running phase's proof of life.
 *
 * phase_detail answers "what is it doing"; this answers "is anything still
 * doing it". A ninety-minute provisioning phase can legitimately report nothing
 * new for twenty minutes, and without a heartbeat that is indistinguishable from
 * a process that died — which is the single most expensive ambiguity in the
 * whole pipeline, because the wrong guess costs either an hour of waiting or an
 * hour of re-baking.
 *
 * .unref() so the timer can never hold the process (or a test runner) open, and
 * the caller always clears it in a finally.
 */
function startHeartbeat(bakeId, everyMs) {
  if (!Number.isFinite(everyMs) || everyMs <= 0) return () => {};
  const timer = setInterval(() => {
    query(`UPDATE ciab_profile_bake SET updated_at = now() WHERE bake_id = $1`, [bakeId])
      .catch(err => console.warn(`${LOG} heartbeat dropped for ${bakeId}: ${err.message}`));
  }, everyMs);
  if (typeof timer.unref === 'function') timer.unref();
  return () => clearInterval(timer);
}

// ─── Staging-lane teardown ──────────────────────────────────────────────────

/**
 * lane-deployer is required LAZILY, on the one path that needs it.
 *
 * It pulls site-config at module load, which reads a gitignored config/site.json,
 * and it is the largest module in the tree. A top-level require would make this
 * file unloadable in any test that had not stubbed both — and the whole point of
 * an orchestrator is that its sequencing, recovery and refusal logic is testable
 * with nothing running. Same reasoning as module-admin.js's lazy require of
 * lane-reservation.
 */
function defaultTeardown() {
  // eslint-disable-next-line global-require
  const { teardownLanes } = require('../../../../../src/utils/lane-deployer');
  return teardownLanes;
}

/**
 * Demolish a bake's staging lane and everything it owns outside the lane row.
 *
 * NOTE THE ASYMMETRY IN teardownLanes: it returns immediately when laneIds is
 * empty, so extraVmIds ALONE are never destroyed. That is not a bug there — a
 * VMID with no lane row has no recorded node, and nothing can destroy a VM it
 * cannot place. It does mean a bake that died before staging_lane_id was written
 * has left VMs this function genuinely cannot clean, and it says so rather than
 * returning a success that would close the ticket.
 *
 * @param {object} bake                the row (needs staging_lane_id, controller_vmid, golden_vmids)
 * @param {object} [opts]
 * @param {?Function} [opts.teardown]  injected teardownLanes, for tests
 * @returns {Promise<{cleaned:boolean, note:?string, result:?object}>}
 */
async function teardownStagingLane(bake, { teardown = null } = {}) {
  const extraVmIds = vmidsForTeardown(bake);
  if (!bake || !bake.staging_lane_id) {
    if (extraVmIds.length === 0) return { cleaned: true, note: null, result: null };
    return {
      cleaned: false,
      note: `left VM(s) ${extraVmIds.join(', ')} on the cluster: this bake recorded no staging lane, ` +
            `so nothing knows which node they are on. Remove them by hand.`,
      result: null,
    };
  }

  const fn = teardown || defaultTeardown();
  const result = await fn([bake.staging_lane_id], { extraVmIds, purgeJanitors: true });
  const errors = (result && Array.isArray(result.errors)) ? result.errors : [];
  return {
    cleaned: errors.length === 0,
    note: errors.length === 0 ? null : `staging lane teardown reported: ${errors.join('; ')}`,
    result,
  };
}

/** Append to a row's error without losing what is already there. */
async function noteBakeError(bakeId, note) {
  await query(
    `UPDATE ciab_profile_bake
        SET error = left(COALESCE(error, '') || $2, 4000), updated_at = now()
      WHERE bake_id = $1`,
    [bakeId, ` ${note}`]
  ).catch(err => console.error(`${LOG} could not annotate ${bakeId}: ${err.message}`));
}

/**
 * Clear the staging columns once the lane they name is gone, so the next
 * restart cannot try to tear down a lane that no longer exists and so the UI
 * stops offering a link to it.
 */
async function clearStagingRefs(bakeId) {
  await query(
    `UPDATE ciab_profile_bake
        SET staging_lane_id = NULL, staging_vxlan_id = NULL, controller_vmid = NULL,
            updated_at = now()
      WHERE bake_id = $1`,
    [bakeId]
  );
}

// ─── The bake ───────────────────────────────────────────────────────────────

/**
 * Run one bake to a terminal state.
 *
 * DETACHED BY ITS CALLER — nothing awaits this. It must therefore NEVER throw
 * out of its own top level, or the rejection lands on an unhandled-rejection
 * handler instead of in the row, where it is the only thing an operator can see.
 * Status first, then the phases, then a terminal state, all inside
 * try/catch/finally.
 *
 * A returned summary exists for tests and for a caller that chooses to await;
 * the production caller detaches with a bare .catch and ignores it.
 *
 * @param {object}  bake                     the row (rowToBake projection)
 * @param {object}  [opts]
 * @param {object}  [opts.steps]             { compile, push, provision, verify, capture }
 * @param {?Function} [opts.teardown]        injected teardownLanes, for tests
 * @param {number}  [opts.heartbeatMs]       0 disables the proof-of-life timer
 * @returns {Promise<{bake_id:string, status:string, skipped:boolean, error:?string}>}
 */
async function bakeProfile(bake, { steps = {}, teardown = null, heartbeatMs = HEARTBEAT_MS } = {}) {
  // Before the mutex and before the try: a caller that hands us nothing has a
  // bug, and there is no row to record it in. Log and return — never throw.
  if (!bake || !bake.bake_id) {
    console.error(`${LOG} bakeProfile called with no bake row — nothing to do`);
    return { bake_id: null, status: null, skipped: true, error: 'no bake row' };
  }
  const id = bake.bake_id;

  if (_inFlight.has(id)) {
    console.warn(`${LOG} bake already in flight for ${id} — ignoring duplicate`);
    return { bake_id: id, status: null, skipped: true, error: null };
  }
  _inFlight.add(id);

  // The live view of the row. record() merges into it so a later phase reads
  // what an earlier one wrote — capture needs the staging_lane_id provision
  // produced, and re-SELECTing between every phase to get it would be three
  // round trips to re-learn something this process already knows.
  const state = { ...bake };
  let stopHeartbeat = () => {};

  try {
    // Started before the teardown below, not after: demolishing a lane is
    // minutes of Proxmox work and the row must not look dead while it happens.
    stopHeartbeat = startHeartbeat(id, heartbeatMs);

    // A previous attempt's lane, if any, goes FIRST — before a status is set,
    // so the row still reads 'failed' (or 'pending') while the demolition runs
    // and nothing looks like progress that is not. See the header: a restart is
    // a fresh lane, never a resume.
    if (state.staging_lane_id) {
      await setBakeDetail(id, 'Tearing down the previous attempt’s staging lane before starting over');
      const cleanup = await teardownStagingLane(state, { teardown });
      if (cleanup.note) console.warn(`${LOG} ${id}: ${cleanup.note}`);
      await clearStagingRefs(id);
      state.staging_lane_id = null;
      state.staging_vxlan_id = null;
      state.controller_vmid = null;
      // golden_vmids stays on the row deliberately: it is the record of what a
      // previous attempt captured, teardownStagingLane has just been given it,
      // and the capture phase overwrites it wholesale.
    }

    for (const phase of PHASES) {
      await setBakePhase(id, phase.status, phase.label);
      state.status = phase.status;

      const step = steps[phase.step];
      if (typeof step !== 'function') {
        // NOT a skip. A phase with no implementation is exactly the failure this
        // track exists to eliminate — a run that reports success and did nothing.
        throw new Error(
          `the '${phase.step}' phase has no implementation wired up, so this bake would have ` +
          `reported success without ${phase.label.toLowerCase()}`
        );
      }

      const where = `the '${phase.step}' phase`;
      const patch = await step({
        bake: state,
        phase: phase.status,
        step: phase.step,
        // Progress, best effort — see setBakeDetail.
        setDetail: (detail) => setBakeDetail(id, detail),
        // Facts, not best effort. A step calls this the MOMENT it knows an id,
        // never at the end of its phase: the whole point is that a crash one
        // second later still leaves something findable.
        record: async (fields) => {
          const clean = assertStepPatch(fields, where);
          if (!clean) return false;
          const wrote = await recordBakeFields(id, clean);
          Object.assign(state, clean);
          return wrote;
        },
      });

      // The return value is a convenience for a step whose phase produced its
      // facts all at once; it goes through the identical whitelist.
      const clean = assertStepPatch(patch, where);
      if (clean) {
        await recordBakeFields(id, clean);
        Object.assign(state, clean);
      }
    }

    await query(
      `UPDATE ciab_profile_bake
          SET status = 'ready', phase_detail = $2, error = NULL,
              finished_at = now(), updated_at = now()
        WHERE bake_id = $1`,
      [id, 'Baked. Approve the three gates to make it deployable.']
    );
    state.status = 'ready';

    // SUPERSEDE THE PREVIOUS VERSION ONLY NOW, AND ONLY IF IT WAS READY.
    //
    // Not at creation: a new bake that fails would otherwise have retired the
    // working environment a class is running on, and a client with no deployable
    // version is a worse state than a client running last week's. You do not
    // retire the version that works until the replacement works.
    //
    // 'ready' only: a FAILED sibling keeps its error, which is evidence, and an
    // ACTIVE sibling is a different content version still building — marking
    // that superseded would be a lie about a row a process is still writing.
    const superseded = await query(
      `UPDATE ciab_profile_bake
          SET status = 'superseded',
              phase_detail = 'Superseded by a newer bake of this environment.',
              updated_at = now()
        WHERE profile_id = $1 AND bake_id <> $2 AND status = 'ready'
        RETURNING bake_id`,
      [state.profile_id, id]
    );

    console.log(`${LOG} ${state.lab_name || id} ready for profile ${String(state.profile_id).slice(0, 8)}`
      + (superseded.rows.length ? ` (superseded ${superseded.rows.length} earlier bake(s))` : ''));

    return { bake_id: id, status: 'ready', skipped: false, error: null };
  } catch (err) {
    const message = String(err && err.message ? err.message : err).slice(0, 2000);
    console.error(`${LOG} bake failed for ${id}: ${message}`);
    // phase_detail is deliberately LEFT ALONE. It still holds the last thing the
    // failing phase said, which is most of the diagnosis; overwriting it with
    // the error would keep the row's status and lose where it happened.
    await query(
      `UPDATE ciab_profile_bake
          SET status = 'failed', error = $2, finished_at = now(), updated_at = now()
        WHERE bake_id = $1`,
      [id, message]
    ).catch(e => console.error(`${LOG} could not record failure for ${id}: ${e.message}`));

    // The staging lane is deliberately NOT torn down here. A failed bake is the
    // only artefact anyone has to diagnose a ninety-minute GOAD chain that lied,
    // and destroying it on the way out would delete the evidence at exactly the
    // moment it became interesting. It is cleaned when an operator restarts the
    // bake, which is a decision, and by the boot sweep, where the process that
    // owned it is provably gone.
    return { bake_id: id, status: 'failed', skipped: false, error: message };
  } finally {
    stopHeartbeat();
    _inFlight.delete(id);
  }
}

// ─── Creating and restarting ────────────────────────────────────────────────

function bad(message, code) {
  return Object.assign(new Error(message), { status: 400, code });
}

/**
 * Validate the identity of a bake before it becomes a row.
 *
 * The CHECK constraints in migration 015 are backstops for a writer that is NOT
 * this function (a psql session, a future import script). They are not the
 * guarantee: an off-vocabulary value that reaches Postgres raises 23514, and a
 * pg error carries neither `status` nor `statusCode`, so the route renderers in
 * routes/profile-deploy.js turn it into an unhandled 500 naming a constraint
 * instead of the 400 they already know how to produce. Same split, and same
 * reasoning, as updateEngagementModel in engagement-provision.js.
 */
function validateBakeIdentity({ profileId, labHash, goadRef, manifestSha, spec }) {
  if (!profileId) throw bad('profile_id required', 'BAKE_PROFILE_REQUIRED');

  if (typeof labHash !== 'string' || !/^[0-9a-f]{8,64}$/.test(labHash)) {
    throw bad(
      'lab_hash must be a lowercase hex digest of 8-64 characters — it becomes the ad/<LAB> ' +
      'directory name on the controller and a key in playbooks.yml, so a digest carrying "/" or "+" ' +
      'would fail ninety minutes into the bake as a path that does not exist.',
      'BAKE_LAB_HASH_INVALID'
    );
  }

  if (typeof goadRef !== 'string' || !/^[0-9a-f]{40}$/.test(goadRef)) {
    throw bad(
      'goad_ref must be a full 40-character commit SHA. A branch name here would make the bake ' +
      'unreproducible — re-baking would swap the role library under lane data written against the ' +
      'old one, and GOAD roles fail quietly.',
      'BAKE_GOAD_REF_INVALID'
    );
  }

  if (typeof manifestSha !== 'string' || manifestSha.trim() === '' || manifestSha.length > 128) {
    throw bad(
      'manifest_sha required — a bake validated against one role manifest and run against another ' +
      'fails silently, which is the exact failure the vendored manifest exists to prevent.',
      'BAKE_MANIFEST_SHA_INVALID'
    );
  }

  if (!spec || typeof spec !== 'object' || Array.isArray(spec)) {
    throw bad('spec must be an object', 'BAKE_SPEC_INVALID');
  }
  // Only the parts whose absence is unambiguously wrong are checked. The IR's
  // shape belongs to the compiler, and a validator that guessed at keys it does
  // not own would reject a legitimate compiler change — so this asserts the
  // three facts a LANE cannot be cloned without and stops.
  if (!spec.goad || typeof spec.goad !== 'object' || !spec.goad.lab || typeof spec.goad.lab !== 'object') {
    throw bad(
      'spec.goad.lab must be the compiled lab definition — without it the lanes cloned from this ' +
      'bake resolve a DIFFERENT forest than the templates were built with, and nothing throws.',
      'BAKE_SPEC_NO_LAB'
    );
  }
  if (spec.subnet_scheme != null && !['v1', 'v2', 'v3'].includes(spec.subnet_scheme)) {
    throw bad('spec.subnet_scheme must be v1|v2|v3', 'BAKE_SPEC_SCHEME_INVALID');
  }
  if (spec.fixed_subnet != null && typeof spec.fixed_subnet !== 'string') {
    throw bad('spec.fixed_subnet must be a string', 'BAKE_SPEC_SUBNET_INVALID');
  }
}

/**
 * Insert the row for one content version, or find the one that already exists.
 *
 * RE-BAKING IDENTICAL CONTENT IS A NO-OP. That is what UNIQUE (profile_id,
 * lab_hash) buys and it is done in ONE statement — ON CONFLICT DO NOTHING rather
 * than SELECT-then-INSERT, because two admins pressing Bake at the same instant
 * would both read "no row" and the loser's INSERT would raise 23505 as a 500.
 *
 * @returns {Promise<{bake:object, created:boolean}>}
 */
async function createBake({
  profileId, labHash, goadRef, manifestSha, spec, actingUserId = null,
}) {
  validateBakeIdentity({ profileId, labHash, goadRef, manifestSha, spec });
  const labName = labNameForHash(labHash);

  const res = await query(
    `INSERT INTO ciab_profile_bake
       (profile_id, lab_hash, lab_name, goad_ref, manifest_sha, spec, status, phase_detail, created_by)
     VALUES ($1, $2, $3, $4, $5, $6::jsonb, 'pending', $7, $8)
     ON CONFLICT (profile_id, lab_hash) DO NOTHING
     RETURNING *`,
    [profileId, labHash, labName, goadRef, manifestSha, JSON.stringify(spec),
      'Queued.', actingUserId]
  );
  if (res.rows.length > 0) return { bake: rowToBake(res.rows[0]), created: true };

  // DO NOTHING returns no row, so the existing one is read back explicitly.
  const existing = await getBake(profileId, labHash);
  return { bake: existing, created: false };
}

/**
 * Create the row and, if it is new, start baking it in the background.
 *
 * Returns as soon as the row exists — the caller responds immediately and the UI
 * polls status/phase_detail, the same contract createEngagement has.
 *
 * AN EXISTING ROW IS NEVER RESTARTED HERE, whatever state it is in. A 'ready'
 * one is the answer already; a 'failed' one needs restartBake, which is an
 * operator's decision with its own confirmation. Auto-restarting on a repeated
 * press would re-run ninety minutes of work because somebody double-clicked.
 *
 * @returns {Promise<{bake:object, created:boolean, started:boolean}>}
 */
async function startBake(opts = {}) {
  const { steps = {}, teardown = null, heartbeatMs = HEARTBEAT_MS } = opts;
  const { bake, created } = await createBake(opts);
  if (!created) return { bake, created: false, started: false };

  // Detached, exactly as createEngagement does it. The bare .catch() is the last
  // line of defence: bakeProfile records its own failures, so this only fires if
  // the failure UPDATE itself threw.
  bakeProfile(bake, { steps, teardown, heartbeatMs })
    .catch(err => console.error(`${LOG} background bake crashed: ${err.message}`));

  return { bake, created: true, started: true };
}

/**
 * Re-run a bake from the beginning.
 *
 * Refused while one is in flight, and refused for a bake that is already ready
 * unless forced: re-baking a healthy environment throws away golden templates
 * that lanes may currently be cloning from, and the content is identical by
 * definition (a different content version would be a different row).
 *
 * The previous attempt's staging lane is torn down by bakeProfile itself, not
 * here — that keeps the demolition inside the mutex, where a second Restart
 * cannot start a fresh lane while the first is still destroying the old one.
 */
async function restartBake(bakeId, { steps = {}, teardown = null, heartbeatMs = HEARTBEAT_MS, force = false } = {}) {
  const bake = await getBakeById(bakeId);
  if (!bake) throw Object.assign(new Error('Bake not found'), { status: 404 });

  if (_inFlight.has(bakeId) || ACTIVE_STATUSES.includes(bake.status)) {
    throw Object.assign(
      new Error(`This bake is already running (${bake.phase_detail || bake.status}). Wait for it to finish.`),
      { status: 409, code: 'BAKE_IN_PROGRESS' }
    );
  }
  if (bake.status === 'ready' && !force) {
    throw Object.assign(
      new Error(
        'This environment is already baked. Re-baking it would destroy the golden templates ' +
        'lanes are cloning from and rebuild identical content — edit the client and bake that ' +
        'instead, which produces a new version rather than replacing this one.'
      ),
      { status: 409, code: 'BAKE_ALREADY_READY' }
    );
  }

  // A fresh attempt, so the stamps and the sign-off are cleared. The gates
  // approved a specific built environment; the one this run produces is a
  // different set of machines and has not been looked at.
  const res = await query(
    `UPDATE ciab_profile_bake
        SET status = 'pending', phase_detail = 'Queued for a re-bake.', error = NULL,
            started_at = NULL, finished_at = NULL,
            gate_solvable = NULL, gate_paper = NULL, gate_no_unintended = NULL,
            gates_approved_by = NULL, gates_approved_at = NULL,
            updated_at = now()
      WHERE bake_id = $1
      RETURNING *`,
    [bakeId]
  );
  const fresh = rowToBake(res.rows[0]) || bake;

  bakeProfile(fresh, { steps, teardown, heartbeatMs })
    .catch(err => console.error(`${LOG} re-bake crashed: ${err.message}`));
  return fresh;
}

// ─── The gates ──────────────────────────────────────────────────────────────

/**
 * Record a human's review of a finished bake.
 *
 * Each gate is stored as given, so "reviewed and rejected" (FALSE) stays
 * distinguishable from "never looked at" (NULL) — see migration 015. The
 * approval STAMP is written only when all three pass, and it is the single fact
 * assertBakeDeployable reads: a row cannot be approved by setting two of three
 * booleans and hoping.
 *
 * Refused unless the bake is 'ready'. Approving a bake that has not finished is
 * approving something nobody has seen, and it would survive into the ready state
 * as a sign-off that predates the environment it signs off on.
 */
async function approveBakeGates(bakeId, {
  gateSolvable = null, gatePaper = null, gateNoUnintended = null, actingUserId = null,
} = {}) {
  const bake = await getBakeById(bakeId);
  if (!bake) throw Object.assign(new Error('Bake not found'), { status: 404 });
  if (bake.status !== 'ready') {
    throw Object.assign(
      new Error(`This bake is '${bake.status}', not ready — there is nothing built to review yet.`),
      { status: 409, code: 'BAKE_NOT_READY' }
    );
  }

  const all = gateSolvable === true && gatePaper === true && gateNoUnintended === true;
  const res = await query(
    `UPDATE ciab_profile_bake
        SET gate_solvable = $2, gate_paper = $3, gate_no_unintended = $4,
            gates_approved_by = CASE WHEN $5::boolean THEN $6::uuid ELSE NULL END,
            gates_approved_at = CASE WHEN $5::boolean THEN now() ELSE NULL END,
            updated_at = now()
      WHERE bake_id = $1
      RETURNING *`,
    [bakeId, gateSolvable, gatePaper, gateNoUnintended, all, actingUserId]
  );
  if (res.rows.length === 0) {
    // Deleted between the read and the write.
    throw Object.assign(new Error('Bake not found'), { status: 404 });
  }
  return rowToBake(res.rows[0]);
}

// ─── The deploy gate ────────────────────────────────────────────────────────

function refuse(message, code) {
  return Object.assign(new Error(message), { status: 409, code });
}

/**
 * Refuse a deploy whose environment is not one this bake actually describes.
 *
 * DELIBERATELY HAS NO INLINE FALLBACK, and for a stronger reason than
 * assertEngagementDeployable's. Reserving a VXLAN block inline "just this once"
 * is slow; baking inline is ninety minutes inside an HTTP request, so nobody
 * would ever write that fallback. The thing that WOULD get written is the quiet
 * one: deploying from the newest ready bake and not mentioning that the profile
 * has been edited since. That produces a class of lanes whose machines do not
 * match the client the students were briefed on, with nothing anywhere reporting
 * a problem — the same silent-success family as the broken GOAD roles.
 *
 * So the drift comparison is MANDATORY, not opportunistic: a caller that cannot
 * supply what the profile currently compiles to gets a refusal, never a pass.
 * "I could not check" and "there is no drift" must never be the same answer.
 *
 * @param {?object} bake                         a rowToBake projection, or null
 * @param {object}  ctx
 * @param {string}  ctx.currentGoadRef           the SHA the toolchain is pinned at NOW
 * @param {string}  ctx.currentLabHash           what the profile compiles to NOW
 * @param {?string} [ctx.profileId]              for the message only
 * @returns {object} the bake, when it is deployable
 * @throws {Error & {status:409, code:string}}
 */
function assertBakeDeployable(bake, { currentGoadRef, currentLabHash, profileId = null } = {}) {
  const who = profileId ? ` for client ${String(profileId).slice(0, 8)}` : '';

  if (!bake) {
    throw refuse(
      `This client's environment has not been baked yet${who}. Bake it first — the build takes about ` +
      `ninety minutes and is done ahead of time so deploy day is a clone, not a build.`,
      'BAKE_NOT_BUILT'
    );
  }

  if (_inFlight.has(bake.bake_id) || ACTIVE_STATUSES.includes(bake.status) || bake.status === 'pending') {
    throw refuse(
      `This client's environment is still baking: ${bake.phase_detail || bake.status}. ` +
      `Watch the bake panel and deploy when it reads Ready — a bake cannot be deployed halfway.`,
      'BAKE_IN_PROGRESS'
    );
  }

  if (bake.status === 'failed') {
    throw refuse(
      `This client's environment failed to bake: ${bake.error || 'no reason recorded'}. ` +
      `Use Re-bake — a restart tears down the failed staging lane and builds from scratch.`,
      'BAKE_FAILED'
    );
  }

  if (bake.status === 'superseded') {
    throw refuse(
      `This bake (${bake.lab_name}) has been superseded by a newer one for the same client. ` +
      `Deploy from the current bake instead.`,
      'BAKE_SUPERSEDED'
    );
  }

  if (bake.status !== 'ready') {
    // Defensive: a status this file does not know about is not a licence to
    // deploy. Reached only if the vocabulary grows and this function does not.
    throw refuse(
      `This bake is in an unrecognised state ('${bake.status}') and cannot be deployed from.`,
      'BAKE_NOT_READY'
    );
  }

  // Gates before drift, on purpose: the sign-off is a fact recorded ON THIS ROW
  // and can always be evaluated, while the two comparisons below depend on
  // arguments the caller supplies. Checking the un-skippable condition first
  // means the most common refusal is never masked by a caller's omission.
  if (!bake.gates_approved_at) {
    const missing = GATES.filter(g => bake[g.column] !== true).map(g => g.label);
    throw refuse(
      `This environment is built but nobody has signed it off${who}. ` +
      (missing.length
        ? `Still to confirm: ${missing.join('; ')}. `
        : 'All three gates are ticked but the approval was never recorded. ') +
      `The playbooks report success whether or not they planted anything, so the sign-off is the ` +
      `only evidence that someone checked.`,
      'BAKE_GATES_NOT_APPROVED'
    );
  }

  if (!currentGoadRef || !currentLabHash) {
    throw refuse(
      `Cannot confirm this bake is still current: the caller supplied ` +
      `${!currentGoadRef ? 'no pinned GOAD ref' : ''}${!currentGoadRef && !currentLabHash ? ' and ' : ''}` +
      `${!currentLabHash ? 'no compiled content hash' : ''} to compare against. ` +
      `Refusing rather than assuming — "not checked" and "no drift" are not the same answer.`,
      'BAKE_DRIFT_UNKNOWN'
    );
  }

  if (bake.goad_ref !== currentGoadRef) {
    throw refuse(
      `This environment was baked against GOAD ${String(bake.goad_ref).slice(0, 8)} but the toolchain is ` +
      `now pinned at ${String(currentGoadRef).slice(0, 8)}. The role library moved under the templates, ` +
      `and GOAD roles fail quietly — re-bake before deploying.`,
      'BAKE_TOOLCHAIN_DRIFT'
    );
  }

  if (bake.lab_hash !== currentLabHash) {
    throw refuse(
      `This client has been edited since the environment was baked (${bake.lab_name} was built from ` +
      `${String(bake.lab_hash).slice(0, 8)}, the client now compiles to ${String(currentLabHash).slice(0, 8)}). ` +
      `Deploying would hand students machines that do not match their brief. Re-bake to pick up the changes.`,
      'BAKE_CONTENT_DRIFT'
    );
  }

  return bake;
}

// ─── Boot recovery ──────────────────────────────────────────────────────────

/**
 * Boot sweep for bakes a restart abandoned.
 *
 * A bake is fire-and-forget async work inside THIS process, so any row still
 * non-terminal at boot is by definition abandoned — nothing is going to pick it
 * up, and without this it reads "Provisioning" forever, which is precisely the
 * CLE failure this plugin's engagement path was written to avoid.
 *
 * IT DOES MORE THAN recoverStrandedEngagements, because the wreckage is bigger.
 * A stranded engagement leaves bookkeeping. A stranded bake leaves an entire
 * lane, a controller VM, and possibly half a set of captured templates — and the
 * row is the ONLY thing that knows their ids. Marking it failed without cleaning
 * up would preserve the record and leak the cluster.
 *
 * IT NEVER AUTO-RETRIES. An operator pressing Re-bake is a decision; an
 * automatic retry at every boot is a loop — and this loop costs ninety minutes
 * of cluster time per iteration.
 *
 * TWO STATEMENTS, ON PURPOSE. The five ACTIVE statuses match migration 015's
 * partial index, mean a lane exists somewhere, and get teardown scheduled.
 * 'pending' has allocated nothing, needs no teardown, and deserves an accurate
 * message rather than one about an interrupted build it never started.
 *
 * @param {object} [opts]
 * @param {?Function} [opts.teardown]  injected teardownLanes, for tests
 * @param {boolean} [opts.cleanup]     false to sweep the rows and skip demolition
 */
async function recoverStrandedBakes({ teardown = null, cleanup = true } = {}) {
  try {
    // `status` inside the SET expression is the OLD value — Postgres evaluates
    // the whole SET list against the row as it was — so the message can name the
    // phase it died in without a second read.
    const active = await query(
      `UPDATE ciab_profile_bake
          SET status = 'failed',
              error = 'Interrupted by a server restart while ' || status ||
                      '. Its staging lane is being torn down; press Re-bake to build again.',
              finished_at = now(), updated_at = now()
        WHERE status IN ('compiling','pushing','provisioning','verifying','capturing')
        RETURNING bake_id, profile_id, lab_name, staging_lane_id, controller_vmid, golden_vmids`
    );

    const pending = await query(
      `UPDATE ciab_profile_bake
          SET status = 'failed',
              error = 'Queued when the server restarted, and never started. Press Re-bake to build it.',
              finished_at = now(), updated_at = now()
        WHERE status = 'pending'
        RETURNING bake_id, lab_name`
    );

    if (active.rows.length > 0) {
      console.warn(`${LOG} Marked ${active.rows.length} bake(s) failed — stranded mid-build by a restart: `
        + active.rows.map(r => `${r.lab_name} (${String(r.profile_id).slice(0, 8)})`).join(', '));
    }
    if (pending.rows.length > 0) {
      console.warn(`${LOG} Marked ${pending.rows.length} queued bake(s) failed — never started: `
        + pending.rows.map(r => r.lab_name).join(', '));
    }

    // DETACHED. Boot must not wait on Proxmox: teardownLanes destroys VMs and
    // waits for the cluster to agree they are gone, which is minutes per lane,
    // and holding the process's startup on that would trade one visible problem
    // for a server that appears hung.
    let scheduled = 0;
    if (cleanup) {
      for (const row of active.rows) {
        if (!row.staging_lane_id && vmidsForTeardown(row).length === 0) continue;
        scheduled++;
        teardownStagingLane(row, { teardown })
          .then(async (result) => {
            if (result.note) {
              console.warn(`${LOG} ${row.lab_name}: ${result.note}`);
              await noteBakeError(row.bake_id, result.note);
            } else {
              console.log(`${LOG} ${row.lab_name}: stranded staging lane torn down`);
              // Not swallowed: a row still pointing at a destroyed lane is what
              // makes the NEXT restart try to tear down something that is gone.
              await clearStagingRefs(row.bake_id)
                .catch(e => console.warn(`${LOG} ${row.lab_name}: could not clear the stale lane ids: ${e.message}`));
            }
          })
          .catch(async (err) => {
            console.error(`${LOG} ${row.lab_name}: staging lane teardown failed: ${err.message}`);
            await noteBakeError(row.bake_id, `Staging lane teardown failed: ${err.message}`);
          });
      }
    }

    return {
      interrupted: active.rows.length,
      never_started: pending.rows.length,
      teardowns_scheduled: scheduled,
    };
  } catch (err) {
    // The table may not exist yet on a first boot after deploy — the migration
    // runs in the same startup, but ordering across plugins is not guaranteed.
    console.warn(`${LOG} stranded-bake sweep skipped: ${err.message}`);
    return { interrupted: 0, never_started: 0, teardowns_scheduled: 0 };
  }
}

// ─── The steps object ───────────────────────────────────────────────────────
/**
 * WHAT THIS SECTION IS FOR
 * bakeProfile sequences five injected functions and hard-fails on a missing one
 * (see the header). Injection is what keeps the orchestrator testable, but it
 * leaves one question open that no test in this file can answer: is anything
 * actually plugged in? buildBakeSteps() is that answer — the one place the five
 * phases are bound to the code that performs them, so a route calls
 * `startBake({ …, steps: buildBakeSteps() })` and cannot invent its own set.
 *
 * A PHASE WITH NO IMPLEMENTATION REFUSES BY NAME. Four of the five have real
 * code behind them; the compile phase's chassis composer does not exist yet, so
 * it raises BakeStepNotImplemented naming the phase and what is missing — unless
 * the spec already carries a tree compiled elsewhere, which is a real source
 * rather than a silent success. That is deliberate and it is the whole doctrine
 * of this track: a step that quietly returns nothing produces a bake that
 * reaches 'ready' having built nothing, which is indistinguishable from a good
 * one until a class sits down in front of it. A refusal costs an operator one
 * clear error; a no-op costs a client engagement.
 */

/** Named, so a caller can tell "not built yet" from "built and it failed". */
class BakeStepNotImplemented extends Error {
  constructor(step, detail) {
    super(`The '${step}' phase has no implementation yet: ${detail}`);
    this.name = 'BakeStepNotImplemented';
    this.code = 'BAKE_STEP_NOT_IMPLEMENTED';
    this.step = step;
    this.status = 501;
  }
}

/**
 * Grade a recorded probe report.
 *
 * PURE, and separate from the step, because this is the decision the whole
 * verification path exists to make and it must be assertable without a lane.
 *
 * Tolerant of two shapes for the same reason vmidsFromGolden is tolerant of
 * three: the report is produced by goad-deploy, not by this module, and pinning
 * one shape here would turn a change over there into a bake that passes on a
 * report it did not understand. It accepts the envelope goad-deploy's
 * runLaneVerification returns ({ ran, passed, reason, error, report }) and the
 * bare parseProbeResult document ({ passed, summary, checks }).
 *
 * THREE OUTCOMES, AND "I COULD NOT CHECK" IS NOT A PASS. That is the same rule
 * assertBakeDeployable applies to drift, for the same reason: a probe that could
 * not answer and a lab with its vulnerabilities intact must never produce the
 * same verdict, or the probe has bought nothing.
 *
 * @returns {{ok:boolean, detail:string}}
 */
function gradeVerifyReport(recorded) {
  if (!recorded || typeof recorded !== 'object' || Array.isArray(recorded)) {
    return {
      ok: false,
      detail: 'the provision phase recorded no post-condition report. A bake cannot be verified by '
        + 'assumption: the chain reports success whether or not it planted anything, which is the '
        + 'entire reason the probe exists.',
    };
  }

  // A shape this function does not recognise is NOT a failing report: an empty
  // object would otherwise be graded as 'checks unsatisfied', which reads as a
  // broken lab when what actually happened is that nothing recorded anything.
  const shaped = ['ran', 'passed', 'report', 'checks', 'summary']
    .some(k => Object.prototype.hasOwnProperty.call(recorded, k));
  if (!shaped) {
    return {
      ok: false,
      detail: 'the provision phase recorded no post-condition report (the value it wrote is not one). '
        + 'A bake cannot be verified by assumption: the chain reports success whether or not it '
        + 'planted anything.',
    };
  }

  // The envelope. `ran:false` means the probe never got to look — a failed
  // playbook, a lab it could not resolve, a controller it could not reach.
  if (Object.prototype.hasOwnProperty.call(recorded, 'ran') && recorded.ran !== true) {
    return {
      ok: false,
      detail: `the post-condition probe did not run: ${recorded.error || recorded.reason || 'no reason recorded'}. `
        + '"Not checked" and "nothing wrong" are not the same answer.',
    };
  }

  const report = (recorded.report && typeof recorded.report === 'object') ? recorded.report : recorded;
  const summary = report.summary || {};
  const failed = Array.isArray(report.checks) ? report.checks.filter(c => c && !c.ok) : [];

  if (report.passed !== true) {
    const named = failed.slice(0, 8).map(c => c.id).join(', ');
    return {
      ok: false,
      detail: `the post-condition probe found ${failed.length || summary.failed || 'some'} of `
        + `${summary.total || 'its'} checks unsatisfied on the built lab`
        + (named ? `: ${named}${failed.length > 8 ? `, and ${failed.length - 8} more` : ''}` : '')
        + (report.errors && report.errors.length ? ` (probe errors: ${report.errors.join('; ')})` : '')
        + '. The playbooks reported success anyway — that is what this check is for.',
    };
  }

  return {
    ok: true,
    detail: `Verified: ${summary.ok != null ? summary.ok : 'every'} post-condition holds on the built lab`
      + (summary.negative ? `, including ${summary.negative} over-grant probe(s)` : '')
      + (summary.declared ? ` and ${summary.declared} declared edge(s)` : '') + '.',
  };
}

/**
 * Build the steps object bakeProfile runs.
 *
 * @param {object}  [impl]
 * @param {?Function} [impl.compileLab]          (stepArgs) -> { name, files, chain }
 * @param {?Function} [impl.provisionStagingLane](stepArgs+{spec,tree}) -> column patch
 * @param {?Function} [impl.captureGolden]       (stepArgs+{spec,tree}) -> { golden_vmids }
 * @param {?object}   [impl.push]                goad-lab-push, injected for tests
 * @param {?object}   [impl.staging]             bake-staging, injected for tests
 * @param {?object}   [impl.stagingDeps]         bake-staging's impure seam, for tests
 * @returns {{compile:Function, push:Function, provision:Function, verify:Function, capture:Function}}
 */
function buildBakeSteps(impl = {}) {
  // Carried between phases IN THIS PROCESS ONLY. None of it is a bake column:
  // a lab tree is megabytes and belongs on the controller, not in a row that
  // every list query selects. bakeProfile is the only caller and it is
  // single-flight per bake_id (see _inFlight), so one object per steps set is a
  // safe channel — build a fresh set per bake, which is what startBake does.
  const ctx = { tree: null, spec: null, treeSha256: null };

  const lazyPush = () => impl.push
    // eslint-disable-next-line global-require
    || require('./goad-lab-push');

  /**
   * bake-staging, required LAZILY on the two paths that need it.
   *
   * Same reasoning as lazyPush and as defaultTeardown above: bake-staging's own
   * dependency edges reach challenge-lane-deployer and proxmox, and a top-level
   * require here would make the orchestrator — whose whole value is that its
   * sequencing, recovery and refusal logic is testable with nothing running —
   * unloadable without a cluster. bake-staging itself requires those one level
   * deeper still, so this costs nothing until a bake actually runs.
   */
  const lazyStaging = () => impl.staging
    // eslint-disable-next-line global-require
    || require('./bake-staging');

  // The two phases below hand bake-staging its impure seam so a test can drive
  // the REAL step against a fake cluster rather than replacing the step.
  const stagingArgs = (args) => ({
    ...args, spec: ctx.spec, tree: ctx.tree, treeSha256: ctx.treeSha256,
    ...(impl.stagingDeps ? { deps: impl.stagingDeps } : {}),
  });

  // ── compile ───────────────────────────────────────────────────────────────
  // NOT BUILT. Nothing in the tree composes ciab/data/chassis/<S|M|L>/ plus a
  // client profile into an ad/<LAB> tree; the chassis are compile-time INPUT
  // (see their chassis.json: "A CHASSIS IS DELIBERATELY NOT DEPLOYABLE") and the
  // composer that repopulates them is a separate piece of work.
  //
  // The one case that IS answerable today is a spec that already carries its
  // compiled tree — an engagement generated elsewhere. Taking it is a real
  // source, not a silent success: the tree is named, validated by the push
  // phase, and delivered byte-for-byte to the controller.
  const compile = async (args) => {
    if (typeof impl.compileLab === 'function') {
      ctx.tree = await impl.compileLab(args);
      if (!ctx.tree) {
        throw new Error('the compile implementation returned no lab tree, so there is nothing to push');
      }
      ctx.spec = args.bake.spec;
      await args.setDetail(`Compiled ${ctx.tree.name || args.bake.lab_name}.`);
      return null;
    }

    const spec = args.bake.spec;
    const carried = spec && spec.goad ? spec.goad.generated_lab : null;
    if (carried && typeof carried === 'object' && !Array.isArray(carried)) {
      ctx.tree = carried;
      ctx.spec = spec;
      await args.setDetail(`Using the lab tree already compiled onto this bake's spec (${carried.name || args.bake.lab_name}).`);
      return null;
    }

    throw new BakeStepNotImplemented('compile',
      'nothing composes a chassis (ciab/data/chassis/S|M|L) plus a client profile into an ad/<LAB> '
      + 'tree yet, and this bake\'s spec carries no spec.goad.generated_lab to use instead. Pass '
      + 'buildBakeSteps({ compileLab }) once the composer exists.');
  };

  // ── push ──────────────────────────────────────────────────────────────────
  /**
   * WHERE THE BYTES ACTUALLY MOVE, AND WHY NOT HERE.
   *
   * pushLabTree needs { node, vmId } for a controller. At this phase there is
   * no controller — provision is what clones it — and the row could not place
   * one if there were: STEP_PATCH_COLUMNS records controller_vmid and nothing
   * that says which NODE it lives on. So the delivery is performed by
   * goad-deploy's deliverGeneratedLab, which holds both, at the first instant
   * the controller answers and before run.sh looks for the lab.
   *
   * That leaves this phase the half it CAN do, and it is not nothing: it proves
   * the tree is deliverable and attaches it to the spec provision will deploy.
   * Everything below refuses on exactly what pushLabTree would refuse on, an
   * hour and a half earlier and for free — a reserved or malformed lab name, a
   * chain with a path in it, a tree with no data/, a hand-written playbooks.yml
   * competing with the rendered one, an archive over the 16 MiB ceiling. The
   * push itself is content-addressed, so this phase claiming "pushed" and the
   * delivery doing it are not two pushes; they are one, checked twice.
   */
  const push = async (args) => {
    const tree = ctx.tree;
    if (!tree) {
      throw new Error('the compile phase produced no lab tree, so there is nothing to deliver');
    }
    const P = lazyPush();
    const lab = P.assertLabName(tree.name || args.bake.lab_name);
    const chain = P.assertChain(tree.chain);
    const entries = Array.isArray(tree.files)
      ? tree.files
      : Object.keys(tree.files || {}).map(p => ({ path: p, content: tree.files[p] }));
    // The two things pushLabTree refuses BEFORE it builds an archive, so they
    // are refused here too rather than surviving to the delivery. Both are
    // silent otherwise: a tree with no data/ stages a directory run.sh stops
    // on, and a hand-written playbooks.yml is a second source of truth for the
    // chain with nothing to say which one won.
    if (!entries.some(f => String(f.path).startsWith('data/'))) {
      throw new Error(
        `compiled lab '${lab}' has no data/ directory. A GOAD lab is data/config.json plus ` +
        'data/inventory; without them run.sh stops at "Lab not found" and the push would have ' +
        'staged an unusable directory.');
    }
    if (entries.some(f => String(f.path) === 'playbooks.yml')) {
      throw new Error(
        `compiled lab '${lab}' ships its own playbooks.yml. That file is rendered from the ` +
        'chain, so that one source of truth ends up in both artifacts — remove the file, or ' +
        'drop the chain and let the file be the chain.');
    }
    // Renders the same playbooks.yml pushLabTree will, over the same tree, so
    // the content address computed here is the one the delivery will find
    // already installed. Built for its refusals and its sha, not to be sent.
    const archive = P.buildLabArchive([
      ...entries,
      { path: 'playbooks.yml', content: P.renderLabPlaybooksYaml(lab, chain) },
    ]);
    ctx.treeSha256 = archive.treeSha256;

    // A NEW spec object rather than a mutation of the row's: the row's spec is
    // the record of what was asked for, and a phase that edited it in place
    // would leave a restart compiling from something a previous attempt wrote.
    const base = args.bake.spec || {};
    ctx.spec = {
      ...base,
      goad: { ...(base.goad || {}), version: lab, generated_lab: { ...tree, name: lab, chain } },
    };

    await args.setDetail(
      `Lab ${lab} is ready to deliver at ${archive.treeSha256.slice(0, 12)} `
      + `(${archive.gzBytes} compressed bytes, ${chain.length}-playbook chain). `
      + 'It is installed on the controller as soon as the staging lane has one.');
    return null;
  };

  // ── provision ─────────────────────────────────────────────────────────────
  /**
   * ONE staging lane, driven through the SHARED deployer.
   *
   * bake-staging.provisionStagingLane is the implementation. It is deliberately
   * not lane-provision.provisionProfileLanes, which builds one lane PER STUDENT
   * for a group, mirrors every lane into the table the student panel reads, and
   * tears the batch down together — three properties a bake wants the opposite
   * of (one lane, nobody's lane, and it must OUTLIVE its deploy because its VMs
   * are what capture converts).
   *
   * It records staging_lane_id, staging_vxlan_id and controller_vmid the moment
   * the lane row exists rather than when the ninety-minute chain returns, which
   * is what makes teardownStagingLane and the boot sweep able to find a lane a
   * crash stranded. An injected implementation still wins, for tests.
   */
  const provision = typeof impl.provisionStagingLane === 'function'
    ? async (args) => impl.provisionStagingLane(stagingArgs(args))
    : async (args) => lazyStaging().provisionStagingLane(stagingArgs(args));

  // ── verify ────────────────────────────────────────────────────────────────
  /**
   * THE DECISION THE PROBE EXISTS FOR.
   *
   * goad-deploy runs the post-condition probe on the lane and RECORDS the
   * report; it deliberately does not act on it, because at that layer a failing
   * probe and a broken probe would abort the deploy identically. Here they do
   * not: a report that says checks failed refuses the bake, a report that says
   * the probe never ran also refuses it, and only a clean report passes. That
   * is why this phase exists rather than the probe simply throwing on the lane.
   */
  const verify = async (args) => {
    const verdict = gradeVerifyReport(args.bake.verify_report);
    if (!verdict.ok) {
      throw Object.assign(new Error(verdict.detail), { code: 'BAKE_VERIFY_FAILED' });
    }
    await args.setDetail(verdict.detail);
    return null;
  };

  // ── capture ───────────────────────────────────────────────────────────────
  /**
   * THE POINT OF NO RETURN.
   *
   * bake-staging.captureGolden stops each staging VM cleanly, strips its
   * cloud-init drive, converts it to a template and records the VMID — after
   * every conversion, not at the end, because a crash halfway leaves templates
   * that only golden_vmids can name.
   *
   * It does NOT sysprep, and that is a decision rather than an omission: see the
   * comment on captureOne. It refuses a lane that is already half converted
   * rather than assembling a golden set out of two runs of the chain, and it
   * refuses outright without spec.goad.fixed_subnet for both segments.
   */
  const capture = typeof impl.captureGolden === 'function'
    ? async (args) => impl.captureGolden(stagingArgs(args))
    : async (args) => lazyStaging().captureGolden(stagingArgs(args));

  return { compile, push, provision, verify, capture };
}

module.exports = {
  // Reads
  getBakeById,
  getBake,
  listBakes,
  getLatestReadyBake,
  rowToBake,
  // The steps object: the ONE place the five phases are bound to the code
  // that performs them. A route builds a fresh set per bake.
  buildBakeSteps,
  gradeVerifyReport,
  BakeStepNotImplemented,
  // Lifecycle
  createBake,
  startBake,
  bakeProfile,
  restartBake,
  approveBakeGates,
  // Recovery
  recoverStrandedBakes,
  teardownStagingLane,
  // The gate
  assertBakeDeployable,
  // Pure, so they are testable without a cluster or a database.
  labNameForHash,
  vmidsFromGolden,
  vmidsForTeardown,
  validateBakeIdentity,
  assertStepPatch,
  // Vocabulary, so a caller (and the migration test) reports the same lists this
  // file enforces.
  PHASES,
  GATES,
  BAKE_STATUSES,
  ACTIVE_STATUSES,
  TERMINAL_STATUSES,
  STEP_PATCH_COLUMNS,
  HEARTBEAT_MS,
};
