/**
 * ============================================================================
 * bake-staging.js — Track G5: the two bake phases that touch the cluster.
 * ----------------------------------------------------------------------------
 * bake-orchestrator.js sequences five phases and refuses to run one that has no
 * implementation. Three of them had code. This file is the other two:
 *
 *   provision  stand ONE staging lane and let the GOAD chain run on it
 *   capture    turn that lane's VMs into the golden templates every later lane
 *              of this profile clones
 *
 * ----------------------------------------------------------------------------
 * WHY A STAGING LANE IS NOT A CLASS SET
 * ----------------------------------------------------------------------------
 * lane-provision.provisionProfileLanes already deploys CIAB lanes, and it is the
 * wrong shape here in three ways that all matter:
 *
 *   - it builds one lane PER STUDENT for a deploy group; a bake wants exactly
 *     one, and a second lane means a second 90-minute chain and a second set of
 *     machines nothing will ever capture;
 *   - it mirrors every lane into ciab_profile_lane_jobs, which is the table the
 *     student-facing panel reads — a staging lane appearing there is a lane an
 *     instructor can hand out before it has been signed off;
 *   - it tears the batch down together, and a staging lane must SURVIVE its
 *     deploy: its VMs are the thing being captured.
 *
 * So this file drives the SHARED deployer directly, for one lane, with none of
 * the group bookkeeping. It is deliberately not a sixth copy of the deploy
 * sequence — every clone, VNet, DHCP reservation, console and GOAD call still
 * happens inside src/utils/challenge-lane-deployer.js, which is the only place
 * that sequence is allowed to live (see lane-provision.js's header for what
 * happened the last time it was copied).
 *
 * ----------------------------------------------------------------------------
 * WHAT RECOVERY NEEDS, AND WHEN IT NEEDS IT
 * ----------------------------------------------------------------------------
 * Both phases run inside a DETACHED bake. Nothing awaits them, nothing catches
 * for them except bakeProfile's own try/catch, and a bake that dies without
 * having recorded where its lane is leaks an entire lane plus a controller VM
 * that nothing in the system can enumerate — teardownStagingLane says so
 * explicitly: a VMID with no lane row has no recorded node, and nothing can
 * destroy a VM it cannot place.
 *
 * That is why staging_lane_id is written by a WATCHER rather than from the
 * deployer's return value. deployChallengeLanes inserts the lane row minutes in
 * and returns ninety minutes later; recording only what it returns would leave
 * the whole chain running against a lane the row cannot name. The watcher polls
 * for the row the deployer inserted (keyed on the bake id this file puts in the
 * lane's own config) and records the three ids the moment they exist, so a crash
 * one second later still leaves something findable.
 *
 * Run: node --test front-end/test/ciab-bake-staging.test.js
 * ============================================================================
 */

const LOG = '[CIAB Bake/Staging]';

/** The module key every CIAB lane carries. Same value lane-provision uses. */
const MODULE_KEY = 'ciab';

/**
 * The GOAD ansible controller's VMID, as goad-deploy.deployController derives
 * it: `200000 + vxlanId`.
 *
 * DUPLICATED ON PURPOSE, and this is the whole justification: goad-deploy does
 * not export the offset, the controller is created ~two minutes into a
 * ninety-minute run, and its VMID is one of the three facts recovery needs. A
 * bake that waited for goad-deploy to hand the number back would have nothing to
 * record for the entire window in which the controller is the most likely thing
 * to be left running. So it is derived from the vxlan id the instant that is
 * known, and then OVERWRITTEN from the lane row's own goad metadata once the
 * deploy finishes — the derived value is a recovery handle, the recorded one is
 * the fact. test/ciab-bake-staging.test.js pins the two against each other.
 */
const CONTROLLER_VMID_OFFSET = 200000;

/** How often the watcher looks for the lane row the deployer inserted. */
const LANE_WATCH_INTERVAL_MS = 5000;

/**
 * How long a guest gets to shut down cleanly before capture gives up.
 *
 * Windows Server writes AD out on shutdown; ten minutes is generous for that and
 * still short enough that a genuinely wedged guest does not hold a bake open
 * indefinitely. See stopForCapture for why the timeout is a REFUSAL and not a
 * hard stop.
 */
const SHUTDOWN_WAIT_MS = 600000;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A refusal an operator can act on: named code, no stack-trace archaeology. */
function refuse(message, code) {
  return Object.assign(new Error(message), { code, status: 409 });
}

// ─── Injected impurity ──────────────────────────────────────────────────────
/**
 * Every edge to Proxmox, to the cluster database and to the shared deployer,
 * behind one object.
 *
 * LAZILY REQUIRED, one level down, for the same reason bake-orchestrator's
 * defaultTeardown is: challenge-lane-deployer pulls site-config at module load,
 * which reads a gitignored config/site.json, and a top-level require would make
 * this file unloadable in any test that had not stubbed it. Requiring inside the
 * wrapper means loading this module costs nothing and a test that injects every
 * dep never loads the real ones at all.
 */
function defaultDeps() {
  /* eslint-disable global-require */
  return {
    deployChallengeLanes: (a) => require('../../../../../src/utils/challenge-lane-deployer').deployChallengeLanes(a),
    findProfileChallenge: (profileId) => require('./lane-reservation').findProfileChallenge(profileId),
    cybercoreQuery: (text, params) => require('../../../../../src/utils/cybercore-db').cybercoreQuery(text, params),
    proxmoxAPI: (m, p, b, o) => require('../../../../../src/utils/proxmox').proxmoxAPI(m, p, b, o),
    waitForTask: (node, upid, t) => require('../../../../../src/utils/proxmox').waitForTask(node, upid, t),
    waitForPowerState: (node, vmid, type, want, o) =>
      require('../../../../../src/utils/proxmox').waitForPowerState(node, vmid, type, want, o),
    // The controller-side run. Same two primitives goad-deploy hands
    // runPostconditionProbe, for the same reason: the pure half of this module
    // must stay loadable without script-executor, which pulls the proxmox client
    // and, through it, the gitignored config/site.json.
    agentExecArgv: (node, vmid, argv, api) =>
      require('../../../../../src/utils/script-executor').agentExecArgv(node, vmid, argv, api),
    pollExecStatus: (node, vmid, pid, t) =>
      require('../../../../../src/utils/script-executor').pollExecStatus(node, vmid, pid, t),
    sleep,
  };
  /* eslint-enable global-require */
}

function withDeps(deps) {
  return { ...defaultDeps(), ...(deps || {}) };
}

/** The qemu API path for one VM. Spelled here so a test can match on it. */
function qemuBase(node, vmid) {
  return `/api2/json/nodes/${node}/qemu/${vmid}`;
}

// ─── Pure guards ────────────────────────────────────────────────────────────

/**
 * The pinned subnet, or a refusal naming the field.
 *
 * THIS IS THE ONE PROPERTY A GOLDEN AD IMAGE CANNOT SURVIVE WITHOUT. A
 * provisioned forest writes its own addresses into itself: the AD-integrated DNS
 * zone, the SYSVOL/DFS referral paths and every SPN name the IP the machine was
 * built on. Clone that image onto a lane with a different base and each of those
 * records points at an address that does not exist there — while nothing fails.
 * The clones boot, DHCP hands them the lane's own addresses, the lane reports
 * `active`, and the first `nxc`, domain join or Kerberos request is where a
 * student finds out the forest is fiction. That is the exact silent-success
 * family this whole track exists to eliminate, so the bake refuses to produce
 * templates that no lane can be built correctly from.
 *
 * BOTH SEGMENTS, not just the internal one. src/utils/challenge-lane-deployer's
 * applyPrebakedFixedSubnet passes `ext` through as-is rather than defaulting it,
 * so a spec that pins only `int` leaves the external segment per-lane — and on a
 * v3 lane that is the segment Kali, the DMZ pivot and every published console
 * live on. A bake that declared one and not the other would produce a template
 * set that is right about AD and wrong about everything a student can reach.
 *
 * Empty counts as missing, and for a documented reason: applyFixedSubnet ignores
 * a falsy base, so `fixed_subnet: { int: '' }` — which is what the topology
 * canvas seeds a new pre-baked challenge with — takes the silent per-lane path
 * with a field present to make it look answered.
 *
 * @param {object} spec  the compiled spec the push phase prepared
 * @returns {{int:string, ext:string}}
 * @throws {Error & {code:'BAKE_CAPTURE_NO_FIXED_SUBNET'}}
 */
function assertFixedSubnet(spec) {
  const fixed = (spec && spec.goad && spec.goad.fixed_subnet) || {};
  const int = String(fixed.int == null ? '' : fixed.int).trim();
  const ext = String(fixed.ext == null ? '' : fixed.ext).trim();

  const missing = [];
  if (!int) missing.push('spec.goad.fixed_subnet.int');
  if (!ext) missing.push('spec.goad.fixed_subnet.ext');
  if (missing.length > 0) {
    throw refuse(
      `This environment declares no ${missing.join(' and no ')}, so there is no subnet its golden `
      + 'templates could be cloned onto. A provisioned AD forest bakes its own addresses into its '
      + 'DNS zone, its SYSVOL referrals and every SPN, so every lane built from these templates has '
      + 'to share one base per segment — and a lane built on any other one comes up looking healthy '
      + 'while its forest names addresses that do not exist. Set '
      + 'spec.goad.fixed_subnet = { int: "<internal base>", ext: "<external base>" } on the client '
      + 'and re-bake.',
      'BAKE_CAPTURE_NO_FIXED_SUBNET'
    );
  }

  // A base is the first three octets of a /24 — applyFixedSubnet builds
  // `${base}.1` as the gateway address from it, so '10.39.16.0/24' here becomes
  // a gateway of '10.39.16.0/24.1', which Proxmox accepts as a net config and no
  // guest can reach.
  for (const [key, value] of [['int', int], ['ext', ext]]) {
    if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)) {
      throw refuse(
        `spec.goad.fixed_subnet.${key} is '${value}', which is not a /24 base. It must be the first `
        + 'three octets only (e.g. "10.39.16") — the deploy path appends the host octet itself, so '
        + 'anything longer builds an address Proxmox accepts and no guest can reach.',
        'BAKE_CAPTURE_NO_FIXED_SUBNET'
      );
    }
  }
  return { int, ext };
}

/**
 * What a bake can actually be run against.
 *
 * `prebaked` is the interesting refusal. A pre-baked spec tells the deployer to
 * clone golden images and skip the chain entirely — so baking one would stand a
 * lane of clones, run no ansible, and capture templates OF templates. Everything
 * would report success and the "new" bake would be a byte-for-byte copy of the
 * old one under a new content hash, which is worse than a failure because it
 * looks like a rebuild.
 */
function assertBakeableSpec(spec) {
  if (!spec || typeof spec !== 'object') {
    throw refuse('the push phase prepared no spec, so there is nothing to deploy', 'BAKE_PROVISION_NO_SPEC');
  }
  const goad = spec.goad || {};
  if (!goad.enabled) {
    throw refuse(
      'this environment does not declare spec.goad.enabled, so no AD forest would be provisioned and '
      + 'there would be nothing to capture. A bake exists to pay for the chain once.',
      'BAKE_PROVISION_NOT_GOAD'
    );
  }
  if (goad.prebaked) {
    throw refuse(
      'this environment is already marked spec.goad.prebaked, which tells the deploy path to CLONE '
      + 'golden images instead of running the chain. Baking it would capture templates of templates: '
      + 'no ansible would run, every phase would report success, and the result would be a copy of '
      + 'the existing image set under a new content hash. Clear spec.goad.prebaked to bake, or deploy '
      + 'from the bake that produced those images.',
      'BAKE_PROVISION_ALREADY_PREBAKED'
    );
  }
  return spec;
}

/**
 * The VXLAN block the staging lane draws its one id from.
 *
 * THE CLIENT'S OWN RESERVATION, NEVER A NEW ONE. A bake's spec carries the
 * compiled lab and nothing about networking — the reservation is created by the
 * deploy path (getOrCreateProfileChallenge), and it is sized to the class. A
 * bake that created its own reservation instead would be creating one sized for
 * a single lane, and the client's first real deploy would ask for twenty; that
 * resize is a teardownLabNetwork of the whole block, which would delete the SDN
 * zone and VNets out from under the staging lane while the chain was still
 * running on it.
 *
 * Drawing from the client's existing block is also what protects the staging
 * lane: lab-network-provision's emptiness check counts claims by VXLAN RANGE, so
 * a live staging lane inside the block refuses a resize rather than being
 * silently demolished by one.
 *
 * @returns {Promise<{start:number, end:number}>}
 */
async function resolveVxlanBlock({ bake, spec, override, deps }) {
  const candidates = [override, spec && spec.vxlan_block];
  for (const block of candidates) {
    if (block && Number.isFinite(Number(block.start)) && Number.isFinite(Number(block.end))) {
      return { start: Number(block.start), end: Number(block.end) };
    }
  }

  const reservation = await deps.findProfileChallenge(bake.profile_id);
  const block = reservation && reservation.vxlan_block;
  if (block && Number.isFinite(Number(block.start)) && Number.isFinite(Number(block.end))) {
    return { start: Number(block.start), end: Number(block.end) };
  }

  throw refuse(
    'this client has no reserved VXLAN block, so the staging lane has no lane id to allocate and no '
    + 'SDN zone to attach to. Create the client\'s lab reservation first (the deploy page does it), '
    + 'then bake — a bake that reserved its own block would have it torn down and resized by the '
    + 'client\'s first real deploy, with the chain still running on it.',
    'BAKE_PROVISION_NO_VXLAN_BLOCK'
  );
}

/** The controller VMID for a lane, or null when the vxlan id is not usable. */
function controllerVmidFor(vxlanId) {
  const n = Number(vxlanId);
  if (!Number.isInteger(n) || n <= 0) return null;
  return CONTROLLER_VMID_OFFSET + n;
}

/**
 * The challenge record deployChallengeLanes consumes, built from a bake.
 *
 * PURE, and exported, because everything that makes this a STAGING lane rather
 * than a student's lane is expressed here — the key, the name, the config the
 * watcher keys on — and none of it is assertable once a deploy is running.
 */
function stagingChallenge(bake, spec, vxlanBlock = null) {
  const merged = vxlanBlock ? { ...spec, vxlan_block: vxlanBlock } : spec;
  return {
    // No challenge_id: a bake is not a catalog challenge, and the lane's config
    // records it as null rather than borrowing the profile's reservation id,
    // which points at a row describing the STUDENT environment.
    challenge_id: null,
    // Lowercased lab name, so it is stable for one content version and different
    // for the next. It reaches log tags, the lane's config, and resolveSpecVms'
    // single-VM fallback name.
    challenge_key: String(bake.lab_name || '').toLowerCase(),
    name: `Bake staging lane — ${bake.lab_name}`,
    module_key: MODULE_KEY,
    spec: merged,
    // v3 by construction: a golden AD image needs an internal segment to be
    // baked on and an external one for the attack path, and assertFixedSubnet
    // requires a base for both. A spec that names its own scheme still wins.
    subnet_scheme: merged.subnet_scheme || 'v3',
  };
}

/**
 * The lane config that makes a staging lane findable and un-handoutable.
 *
 * `ciab_bake_id` is the watcher's key AND the recovery key: it is the only thing
 * that connects a cybercore_lane row to the bake that made it, and it is written
 * by the deployer's own INSERT (laneConfig is spread verbatim into config), so
 * it exists from the instant the row does.
 */
function stagingLaneConfig(bake) {
  return {
    ciab: true,
    ciab_bake: true,
    ciab_bake_id: bake.bake_id,
    ciab_bake_lab: bake.lab_name || null,
    profile_id: bake.profile_id || null,
    // NOT profile_lane_group. That flag is what puts a lane in the student panel,
    // and a staging lane is machines nobody has signed off on yet.
    staging: true,
  };
}

// ─── The lane the deployer inserted ─────────────────────────────────────────

const LANE_BY_BAKE_SQL = `
  SELECT lane_id, vxlan_id, status, config
    FROM cybercore_lane
   WHERE config->>'ciab_bake_id' = $1
   ORDER BY created_at DESC
   LIMIT 1`;

async function findStagingLaneRow(bakeId, deps) {
  const res = await deps.cybercoreQuery(LANE_BY_BAKE_SQL, [String(bakeId)]);
  const row = res && Array.isArray(res.rows) ? res.rows[0] : null;
  if (!row) return null;
  return {
    lane_id: row.lane_id,
    vxlan_id: row.vxlan_id,
    status: row.status,
    config: (row.config && typeof row.config === 'object') ? row.config : {},
  };
}

async function loadLaneById(laneId, deps) {
  const res = await deps.cybercoreQuery(
    `SELECT lane_id, vxlan_id, status, config FROM cybercore_lane WHERE lane_id = $1`,
    [laneId]
  );
  const row = res && Array.isArray(res.rows) ? res.rows[0] : null;
  if (!row) return null;
  return {
    lane_id: row.lane_id,
    vxlan_id: row.vxlan_id,
    status: row.status,
    config: (row.config && typeof row.config === 'object') ? row.config : {},
  };
}

/**
 * The three ids a bake row needs, derived from whatever the lane already knows.
 *
 * The controller VMID prefers what goad-deploy actually recorded on the lane and
 * falls back to the derivation — "what was built" beats "what should have been
 * built", and the fallback is what covers the window before the controller
 * exists, which is precisely the window a crash leaves it running in.
 */
function idsFromLane(lane) {
  if (!lane) return null;
  const goad = (lane.config && lane.config.goad) || {};
  const recorded = Number(goad.controller_vmid);
  return {
    staging_lane_id: lane.lane_id,
    staging_vxlan_id: Number(lane.vxlan_id) || null,
    controller_vmid: (Number.isInteger(recorded) && recorded > 0)
      ? recorded
      : controllerVmidFor(lane.vxlan_id),
  };
}

/**
 * Poll for the lane row until it exists, record its ids once, then stop.
 *
 * BEST EFFORT ON EVERY EDGE, and never a reason a bake fails: a dropped poll is
 * one missed chance at an early record, and killing ninety minutes of cluster
 * work over a transient cluster-DB read would be the wrong trade in exactly the
 * direction bake-orchestrator's setBakeDetail already documents.
 *
 * .unref()'d so the timer can never hold a test runner (or the process) open,
 * and the caller always stops it in a finally.
 *
 * @returns {Function} stop()
 */
function watchForStagingLane({ bakeId, record, setDetail, deps, intervalMs = LANE_WATCH_INTERVAL_MS }) {
  if (!Number.isFinite(intervalMs) || intervalMs <= 0) return () => {};
  let stopped = false;
  let recorded = false;

  const tick = async () => {
    if (stopped || recorded) return;
    const lane = await findStagingLaneRow(bakeId, deps);
    if (!lane || stopped || recorded) return;
    const ids = idsFromLane(lane);
    // Set BEFORE the await: a second tick firing while this one is mid-write
    // would record the same row twice and, worse, race the authoritative write
    // the provision path does when the deploy returns.
    recorded = true;
    await record(ids);
    if (setDetail) {
      await setDetail(
        `Staging lane ${ids.staging_lane_id} is up on VXLAN ${ids.staging_vxlan_id}; `
        + `the GOAD chain runs on it next (about ninety minutes).`
      );
    }
  };

  const timer = setInterval(() => {
    tick().catch((err) => console.warn(`${LOG} lane watch poll dropped: ${err.message}`));
  }, intervalMs);
  if (typeof timer.unref === 'function') timer.unref();

  return () => { stopped = true; clearInterval(timer); };
}

// ─── PROVISION ──────────────────────────────────────────────────────────────

/**
 * The verification report the provision phase hands to the verify phase.
 *
 * goad-deploy stores the FULL probe document nowhere durable — it summarises it
 * onto the lane row (config.goad.probe) because a lane config is polled every
 * couple of seconds by the admin UI and a report can carry hundreds of checks.
 * The bake's verify_report column is sized for the whole thing, but the deploy
 * ran inside deployChallengeLanes, which swallows deployGoadLane's return value,
 * so the summary on the lane is what is actually reachable from here.
 *
 * gradeVerifyReport (bake-orchestrator) accepts exactly this shape — it is the
 * `{ ran, passed, reason, error, summary, errors, failed_checks }` envelope —
 * and it refuses a bake whose probe never ran just as hard as one whose checks
 * failed. So a lane with no goad metadata at all returns a report that SAYS so
 * rather than nothing: "not recorded" must reach the verify phase as a refusal,
 * never as an absence it could mistake for a pass.
 */
function verifyReportFromLane(lane) {
  const goad = (lane && lane.config && lane.config.goad) || null;
  if (!goad) {
    return {
      ran: false,
      applicable: true,
      passed: null,
      reason: 'the staging lane recorded no GOAD metadata, so the post-condition probe left no '
        + 'report to grade — the chain may never have run at all.',
      error: null,
      report: null,
    };
  }
  if (goad.probe) return goad.probe;
  return {
    ran: false,
    applicable: true,
    passed: null,
    reason: goad.status === 'failed'
      ? `the GOAD chain failed on the staging lane, so there is no finished forest to grade: ${goad.error || 'no reason recorded'}`
      : 'the staging lane ran the chain but recorded no post-condition probe, so nothing checked '
        + 'whether the vulnerabilities the playbooks reported are actually on the machines.',
    error: goad.error || null,
    report: null,
  };
}

/**
 * Stand ONE staging lane and run the GOAD chain on it.
 *
 * Wired into bake-orchestrator.buildBakeSteps as the 'provision' phase, so it
 * receives that module's step arguments plus the spec and tree the push phase
 * prepared.
 *
 * THE OWNER IS THE PERSON WHO PRESSED BAKE. cybercore_lane.user_id is not
 * optional and a bake has no student, so the lane belongs to bake.created_by —
 * which is not a fudge but the right answer twice over: it is a real cybercore
 * user id (see migration 015's header), and the three gates require somebody to
 * walk the intended solve path on this exact lane before it can be deployed
 * from. A lane owned by nobody is a lane nobody can sign off.
 *
 * @param {object}   args                      bake-orchestrator's step arguments
 * @param {object}   args.bake                 the live bake row
 * @param {Function} args.record               persist bake columns NOW, not later
 * @param {Function} args.setDetail            best-effort progress text
 * @param {object}   [args.spec]               the spec the push phase prepared
 * @param {string}   [args.ownerUserId]        overrides bake.created_by
 * @param {object}   [args.vxlanBlock]         overrides the client's reservation
 * @param {number}   [args.watchIntervalMs]    0 disables the early-record watcher
 * @param {object}   [args.deps]               injected impurity, for tests
 * @returns {Promise<object>} a bake-column patch
 */
async function provisionStagingLane(args) {
  const { bake, record, setDetail } = args;
  const deps = withDeps(args.deps);
  const spec = args.spec || (bake && bake.spec);

  assertBakeableSpec(spec);
  // The SAME refusal capture makes, ninety minutes earlier and for free. Capture
  // still checks it independently — it is the phase that cannot be allowed to
  // produce an unusable template set — but there is no reason to pay for the
  // chain first when the answer is already knowable.
  const fixed = assertFixedSubnet(spec);

  const ownerId = args.ownerUserId || bake.created_by;
  if (!ownerId) {
    throw refuse(
      'this bake records no created_by, so its staging lane would have no owner. '
      + 'cybercore_lane.user_id is not optional, and the owner is also the person who has to walk '
      + 'the intended solve path before the gates can be signed — start the bake as a logged-in '
      + 'admin rather than from a script with no acting user.',
      'BAKE_PROVISION_NO_OWNER'
    );
  }
  const owner = await resolveOwner(ownerId, deps);
  const vxlanBlock = await resolveVxlanBlock({ bake, spec, override: args.vxlanBlock, deps });

  const challenge = stagingChallenge(bake, spec, vxlanBlock);
  // One key per BAKE, not per profile: two content versions of one client are
  // two different builds and must not look like one operation. The orchestrator's
  // _inFlight set is the mutex — this id exists so the deployer's own progress
  // registry has somewhere to write, and so an operator can watch the clone phase.
  const progressId = `ciab-bake-${bake.bake_id}`;

  await setDetail(
    `Standing up a single staging lane for ${bake.lab_name} on ${fixed.int}.0/24 (internal) `
    + `and ${fixed.ext}.0/24 (external).`
  );

  const stopWatch = watchForStagingLane({
    bakeId: bake.bake_id, record, setDetail, deps,
    intervalMs: args.watchIntervalMs == null ? LANE_WATCH_INTERVAL_MS : args.watchIntervalMs,
  });

  let result;
  try {
    result = await deps.deployChallengeLanes({
      // EXACTLY ONE. deployChallengeLanes deploys one lane per user, so the
      // length of this array IS the lane count, and a bake that passed two would
      // pay for the chain twice and capture one of them.
      users: [owner],
      challenge,
      moduleKey: MODULE_KEY,
      // Kali comes along: the gates are the only evidence anyone looked at what
      // the playbooks claim they built, and an operator cannot walk the intended
      // path without a box inside the lane to walk it from. It is excluded from
      // capture — see captureTargets.
      attackBoxes: spec.goad.include_kali !== false,
      // The same addressing contract a CIAB profile lane deploys under. It has
      // to match, because these machines become the templates those lanes clone:
      // an address pinned at bake time and drawn from a pool at deploy time is a
      // machine whose baked identity and lane address disagree.
      pinAllVms: true,
      laneConfig: stagingLaneConfig(bake),
      namePrefix: `bake-${String(bake.lab_name || 'ciab').toLowerCase()}`,
      guacParent: 'ROOT',
      description: `CIAB bake staging lane for ${bake.lab_name} (${String(bake.profile_id || '').slice(0, 8)})`,
      progressId,
      progressLabel: `Bake ${bake.lab_name}`,
    });
  } catch (err) {
    // THE LEAK WINDOW. deployChallengeLanes marks any row it inserted 'error'
    // before it rethrows, so the lane is still there and still findable — but
    // only if the id reaches the bake row. The watcher may not have ticked yet,
    // so sweep once more here, RECORD, and only then let the failure propagate.
    await recordWhateverExists(bake, record, deps);
    throw err;
  } finally {
    stopWatch();
  }

  const provisioned = Array.isArray(result && result.provisioned) ? result.provisioned : [];
  const failed = Array.isArray(result && result.failed) ? result.failed : [];

  if (provisioned.length !== 1) {
    // Same sweep, same reason: a lane row can exist for a lane that failed to
    // finish, and that lane is exactly the one somebody has to clean up.
    await recordWhateverExists(bake, record, deps);
    const why = failed.length > 0
      ? failed.map((f) => f.reason || 'no reason recorded').join('; ')
      : 'the deployer returned no provisioned lane and no failure';
    throw refuse(
      `the staging lane did not come up (${provisioned.length} of 1 deployed): ${why}`,
      'BAKE_PROVISION_FAILED'
    );
  }

  const deployed = provisioned[0];
  // Authoritative, from the row itself rather than from the deployer's summary:
  // the lane config is where goad-deploy wrote the controller VMID it actually
  // created, and where the probe report is.
  const lane = await loadLaneById(deployed.lane_id, deps)
    || { lane_id: deployed.lane_id, vxlan_id: deployed.vxlan_id, config: {} };

  const ids = idsFromLane(lane);
  await record(ids);

  const verify = verifyReportFromLane(lane);

  // ── the other half of the deliverable ────────────────────────────────────
  // The chain has finished, so the machines are up and the controller is idle:
  // this is the moment the curated web tier can be applied. It runs INSIDE the
  // provision phase rather than as a sixth bake step because the DMZ host is one
  // of the machines capture is about to freeze — a website installed after the
  // capture would exist on the staging lane and on no lane cloned from it.
  //
  // A failure here is recorded and then REFUSED. The company website is half of
  // what an external engagement is: a bake that reached 'ready' with a forest
  // and no company in front of it would be exactly the silent success this whole
  // track exists to remove.
  let web;
  try {
    web = await installCompanyWebsite({
      spec, lane, controllerVmId: ids.controller_vmid, setDetail, deps,
    });
  } catch (err) {
    web = {
      ran: false,
      applicable: true,
      passed: false,
      reason: `the company website could not be installed: ${err.message}`,
      code: err.code || null,
      differences: [],
    };
  }
  const report = { ...verify, cc_web: web };
  if (web.applicable !== false && web.passed !== true) {
    // RECORD FIRST, THEN THROW. The row is the only place an operator can read
    // what went wrong, and a phase that threw before writing would leave a
    // ninety-minute bake with a status and no reason.
    await record({ verify_report: report });
    throw refuse(
      `the staging lane's company website is not installed: ${web.reason}`
      + (web.differences && web.differences.length ? ` (${web.differences.join('; ')})` : ''),
      web.code || 'BAKE_PROVISION_WEB_FAILED'
    );
  }

  await setDetail(
    `Staging lane ${ids.staging_lane_id} built on VXLAN ${ids.staging_vxlan_id} `
    + `(controller ${ids.controller_vmid}). `
    + (web.applicable === false
      ? `No company website: ${web.reason} `
      : `${web.server_name} is serving ${web.routes.length} pages on ${web.host}. `)
    + 'The chain has run; grading its post-condition report next.'
  );

  return { ...ids, verify_report: report };
}

/** The lane owner as deployChallengeLanes wants them: { id, email }. */
async function resolveOwner(ownerId, deps) {
  try {
    const res = await deps.cybercoreQuery(
      `SELECT user_id AS id, email FROM cybercore_user WHERE user_id = $1`,
      [ownerId]
    );
    const row = res && Array.isArray(res.rows) ? res.rows[0] : null;
    if (row && row.email) return { id: row.id, email: row.email };
  } catch (err) {
    console.warn(`${LOG} could not read the bake owner's email: ${err.message}`);
  }
  throw refuse(
    `the user who started this bake (${String(ownerId).slice(0, 8)}) has no account on the cluster `
    + 'database, so the staging lane could not be given an owner or a console. Bake as an admin who '
    + 'has a CyberCore account.',
    'BAKE_PROVISION_NO_OWNER'
  );
}

/**
 * Record whatever the lane row already knows, swallowing everything.
 *
 * Called only on the failure paths, where the caller is about to throw and the
 * ONLY thing that matters is that the ids reach the row before it does. A throw
 * from here would replace a diagnosable deploy failure with a cleanup failure
 * and leave the lane unfindable on top of it.
 */
async function recordWhateverExists(bake, record, deps) {
  try {
    const lane = await findStagingLaneRow(bake.bake_id, deps);
    if (!lane) return false;
    await record(idsFromLane(lane));
    return true;
  } catch (err) {
    console.error(`${LOG} could not record the staging lane ids for ${bake.bake_id}: ${err.message}`);
    return false;
  }
}

// ─── THE COMPANY WEBSITE ────────────────────────────────────────────────────
/**
 * WHAT THIS IS, AND WHY IT LIVES IN THE PROVISION PHASE.
 *
 * An engagement has two halves. The GOAD chain builds the forest; the company
 * website is the surface a student reaches it THROUGH — the DMZ box at .240 is
 * the lane's one dual-homed machine, and a domain service account sitting in an
 * app config on it is what turns a web finding into an Active Directory
 * foothold. infrastructure/ansible/cc-web has held a curated, verified role for
 * exactly that host, and nothing has ever invoked it: every bake to date
 * produced a forest with no company in front of it.
 *
 * So this runs here, immediately after deployChallengeLanes returns — which is
 * the instant the chain has finished and the machines are up — and it runs the
 * REAL role against the REAL host with variables derived from the lab, not from
 * a literal.
 *
 * WHY IT RUNS FROM THE CONTROLLER
 * The controller is the only Ansible runner on the lane: it carries ansible and
 * python3 and has a route to both segments, and the orchestrator container has
 * none of those. That is already true of the GOAD chain and of the
 * post-condition probe, and the shape below is deliberately the probe's —
 * stage the tree, write a 0600 vars file, launch `ansible-playbook` DETACHED
 * with a sentinel, poll the sentinel with short guest-exec calls, read the
 * result back. Every failure mode that shape exists to dodge (QGA deadlocking on
 * a long-running process's stdio, losing track of long-running PIDs) applies
 * here identically, and a second mechanism would meet all of them again.
 *
 * WHY IT READS THE HOST BACK
 * cc_web's verify.yml publishes what it OBSERVED to /etc/cybercore/cc-web-observed.json,
 * shaped like asset.web_facts. This phase fetches that file and compares it to
 * the facts the site declared, through readWebFacts() — the SAME normaliser the
 * scan documents use. That comparison is acceptance gate (ii) obtained
 * structurally: the paper says apache on 80 and 443 with TLS 1.0 because the
 * host answered that way, not because a checker was told to agree.
 */

/** Where the staged role tree and the run's artifacts live on the controller.
 *  Beside /var/lib/goad-run, which run.sh already owns and which is root-only. */
const CC_WEB_RUN_DIR = '/var/lib/goad-run/cc-web';

/** The role tree, in this repository. Six levels up from ciab/utils/. */
const CC_WEB_TREE_REL = '../../../../../../infrastructure/ansible/cc-web';

/**
 * The DMZ host's last octet, on BOTH segments.
 *
 * DUPLICATED FROM src/utils/challenge-lane-deployer.js's DUAL_HOMED_OCTET, and
 * for the same reason CONTROLLER_VMID_OFFSET is duplicated at the top of this
 * file: the deployer does not export it, and this phase has to know the address
 * before it can talk to the machine. It is not a guess — a dual-homed guest is
 * pinned there by ipconfig0/ipconfig1 at clone time and is deliberately absent
 * from `config.pinned_hosts` (a machine missing from that list is not a machine
 * with no address), so there is nothing on the lane row to read it off.
 */
const CC_WEB_DMZ_OCTET = 240;

/** The account the baked web template ships. Every VM template's cloud-init
 *  sets `web`/`bake-debug`, and a DUAL-HOMED spec VM keeps its baked accounts:
 *  cloneChallengeVm writes ipconfig0/ipconfig1 for the pivot and never sets
 *  ciuser, so no per-lane credential is injected on this one machine. */
const CC_WEB_SSH_USER = 'web';

/** How long the role gets. A cold apt plus a certificate plus the verification
 *  pass is a couple of minutes; twenty is generous enough that a slow mirror is
 *  not a failure and short enough that a wedged run does not hold a bake open. */
const CC_WEB_TIMEOUT_MS = 20 * 60 * 1000;

/** Base64 characters per guest-exec call. The QGA argv is not a place to put a
 *  40 KB page: vuln-app-install.js chunks at 48 KB for the same reason, and
 *  unlike that (quarantined) writer every chunk here is polled to completion
 *  before the next one is sent. */
const CC_WEB_CHUNK = 32768;

/** Names this phase is willing to interpolate into a shell command. Everything
 *  reaching a command line is either a module constant or passes this. */
function shellSafe(value, what) {
  const s = String(value == null ? '' : value);
  if (!/^[A-Za-z0-9._/-]+$/.test(s)) {
    throw refuse(
      `the company-website step would have put ${what} ('${s}') on a shell command line, and it `
      + 'carries a character this phase will not quote. That is a programming error rather than a '
      + 'lane problem: fix the derivation, do not relax the check.',
      'BAKE_PROVISION_WEB_UNSAFE_NAME'
    );
  }
  return s;
}

/** Is this spec.goad.lab a compiled labIR, or a stub that only names a forest?
 *
 *  The bake route puts `compiled.ir` here — domains, hosts, principals, the
 *  attack chain and the foothold credential — and the site is authored from all
 *  of it. A spec that carries only a lab NAME describes no client, so there is
 *  nobody to write a website about; that is reported rather than invented. */
function hasCompiledLab(spec) {
  const lab = spec && spec.goad && spec.goad.lab;
  return !!(lab && typeof lab === 'object'
    && Array.isArray(lab.domains) && lab.domains.length > 0
    && lab.principals && Array.isArray(lab.principals.users) && lab.principals.users.length > 0);
}

/**
 * Which machine on this lane is the dual-homed DMZ web host.
 *
 * The answer is a NAME first and an address second, because the address is
 * structural (.240 on both segments, pinned by the deployer) while the name is
 * whatever the spec called it. The candidates are read in the order the rest of
 * the pipeline already agrees on:
 *
 *   spec.cc_web.host           an operator saying so outright
 *   spec.dns.web_vm            the machine the lane publishes www.<domain> for
 *   vuln_app_install.target_vm profile-to-spec's resolveDmzVm derives the pivot
 *                              from exactly this field, so it IS the contract
 *   an explicitly dual-homed spec VM, or one with role 'dmz'
 *
 * and only then a name-shaped guess against the lane's own machine list, which
 * is last on purpose: guessing is how a bake would install a client's website
 * onto the file server.
 */
function resolveDmzHost({ spec, lane }) {
  const config = (lane && lane.config) || {};
  const laneVms = Array.isArray(config.vms) ? config.vms : [];
  const names = [];
  const push = (v) => {
    const s = String(v == null ? '' : v).trim();
    if (s && names.indexOf(s) === -1) names.push(s);
  };

  const cc = (spec && spec.cc_web) || {};
  push(cc.host);
  push(((spec && spec.dns) || {}).web_vm);
  push(((spec && spec.vuln_app_install) || {}).target_vm);
  for (const vm of (Array.isArray(spec && spec.vms) ? spec.vms : [])) {
    if (!vm || !vm.name) continue;
    const segments = (Array.isArray(vm.nics) ? vm.nics : [])
      .map((n) => n && n.segment).filter(Boolean);
    if (vm.role === 'dmz' || new Set(segments).size > 1) push(vm.name);
  }

  const find = (name) => laneVms.find((v) => v && String(v.name).toLowerCase() === String(name).toLowerCase());
  let vm = null;
  for (const name of names) {
    vm = find(name);
    if (vm) break;
  }
  if (!vm) {
    // LAST, AND ONLY AS A LAST RESORT. Kali and the gateway are excluded by
    // name because both would match a loose pattern and neither is a web host.
    vm = laneVms.find((v) => v && /^(web|www|dmz|vuln|site|portal)/i.test(String(v.name))
      && !/^(kali|gateway)/i.test(String(v.name)));
  }
  if (!vm) {
    throw refuse(
      'this lane has no dual-homed DMZ web host, so the company website has nowhere to be '
      + `installed (the lane's machines are: ${laneVms.map((v) => v && v.name).filter(Boolean).join(', ') || 'none recorded'}). `
      + 'The website is half of what an external engagement is: without it a student nmaps the lane, '
      + 'finds a forest with no company in front of it, and there is no credential anywhere to pivot '
      + 'on. Give the environment a dual-homed machine — name it in spec.cc_web.host, in '
      + 'spec.dns.web_vm or as spec.vuln_app_install.target_vm — or set spec.cc_web.enabled = false '
      + 'to state on the record that this environment is deliberately AD-only.',
      'BAKE_PROVISION_NO_DMZ_HOST'
    );
  }

  // "What was built" beats "what should have been built", the same order
  // idsFromLane reads the controller VMID in: the deployer records the external
  // base it really used, and the fixed subnet is what it was asked for.
  const base = String(config.lane_subnet_base
    || ((spec && spec.goad && spec.goad.fixed_subnet) || {}).ext || '').trim();
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(base)) {
    throw refuse(
      `the lane records no usable external subnet base ('${base}'), so the DMZ host's address cannot `
      + 'be derived. The web host is pinned to .240 on that base at clone time; without the base '
      + 'there is no host for ansible to connect to.',
      'BAKE_PROVISION_WEB_NO_SUBNET'
    );
  }

  return {
    name: String(vm.name),
    vm_id: Number(vm.vm_id) || null,
    node: String(vm.node || config.node || ''),
    ip: `${base}.${CC_WEB_DMZ_OCTET}`,
  };
}

/**
 * The cc-web tree, read out of this repository.
 *
 * READ, NOT REBUILT. The role is the artifact under review — it carries the
 * fail-fast gate, the OpenSSL policy relaxation a weak protocol actually needs
 * and the verification pass that re-reads the host — and a copy of it inside a
 * JS string would be a second role that nobody edits when the first one changes.
 * `fs` and `path` are required here rather than at the top of the file so this
 * module keeps its "loads with nothing stubbed" property.
 */
function readCcWebTree() {
  /* eslint-disable global-require */
  const fs = require('fs');
  const path = require('path');
  /* eslint-enable global-require */
  const root = path.join(__dirname, CC_WEB_TREE_REL);
  const out = {};
  const walk = (dir, prefix) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = prefix ? `${prefix}/${entry.name}` : entry.name;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) { walk(full, rel); continue; }
      // The README is documentation for a human, not an artifact the run needs,
      // and it is the biggest file in the tree.
      if (rel === 'README.md') continue;
      out[rel] = fs.readFileSync(full, 'utf8');
    }
  };
  walk(root, '');
  if (!out['cc-web.yml'] || !out['ansible.cfg'] || !out['roles/cc_web/tasks/main.yml']) {
    throw refuse(
      `the cc-web ansible tree at ${root} is missing cc-web.yml, ansible.cfg or the cc_web role, so `
      + 'there is nothing to stage on the controller. This is a broken checkout rather than a broken '
      + 'lane.',
      'BAKE_PROVISION_WEB_TREE_MISSING'
    );
  }
  return out;
}

/**
 * Mark a string so the vars file tags it `!unsafe`.
 *
 * THE TRAP THIS EXISTS FOR: ansible renders a variable's value RECURSIVELY, so
 * a page containing {{ }} is evaluated while the variable is being substituted,
 * long before the copy task sees the bytes — AnsibleUndefinedVariable if you are
 * lucky, silently something else if you are not. roles/cc_web/tasks/content.yml
 * says the role cannot defend against this and that the CALLER must tag the
 * value. This is the caller. (goad-lab-content refuses to emit a page carrying a
 * Jinja delimiter as well; belt and braces, because the cost of being wrong is a
 * page that renders as "49" and a day spent finding out why.)
 */
function unsafeScalar(text) {
  return { __cc_unsafe: String(text == null ? '' : text) };
}

function isUnsafeScalar(v) {
  return !!v && typeof v === 'object' && typeof v.__cc_unsafe === 'string';
}

/**
 * The minimum YAML this phase needs, hand-rolled.
 *
 * Hand-rolled because this repository carries no schema or YAML library and
 * because the emitted set is tiny and known: maps, lists, booleans, integers and
 * strings, all of them ASCII. Every string is emitted with JSON.stringify, whose
 * output is a valid YAML double-quoted scalar for ASCII input — the escapes are
 * the same set — so a page full of quotes, backslashes and newlines survives
 * without a quoting rule of our own.
 */
function toVarsYaml(value) {
  const scalar = (v) => {
    if (isUnsafeScalar(v)) return `!unsafe ${JSON.stringify(v.__cc_unsafe)}`;
    if (v === true || v === false) return String(v);
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    return JSON.stringify(String(v == null ? '' : v));
  };
  const isScalar = (v) => isUnsafeScalar(v) || v == null || typeof v !== 'object';

  const block = (v, indent) => {
    const pad = ' '.repeat(indent);
    const lines = [];
    if (Array.isArray(v)) {
      if (v.length === 0) return [`${pad}[]`];
      for (const item of v) {
        if (isScalar(item)) { lines.push(`${pad}- ${scalar(item)}`); continue; }
        const sub = block(item, indent + 2);
        lines.push(`${pad}- ${sub[0].slice(indent + 2)}`);
        for (let i = 1; i < sub.length; i += 1) lines.push(sub[i]);
      }
      return lines;
    }
    const keys = Object.keys(v);
    if (keys.length === 0) return [`${pad}{}`];
    for (const key of keys) {
      const child = v[key];
      if (isScalar(child)) { lines.push(`${pad}${key}: ${scalar(child)}`); continue; }
      if (Array.isArray(child) && child.length === 0) { lines.push(`${pad}${key}: []`); continue; }
      if (!Array.isArray(child) && Object.keys(child).length === 0) { lines.push(`${pad}${key}: {}`); continue; }
      lines.push(`${pad}${key}:`);
      for (const line of block(child, indent + 2)) lines.push(line);
    }
    return lines;
  };

  return `---\n${block(value, 0).join('\n')}\n`;
}

/**
 * The role's variables, DERIVED FROM THE LAB — never a literal.
 *
 * cc_web_facts is `asset.web_facts` verbatim, the same object the scan documents
 * read through readWebFacts(). cc_web_routes is the site the generator authored.
 * cc_web_pivot is the credential the generator proved Active Directory honours.
 * Nothing in this function names a company, and nothing in the role does either:
 * that is what lets one role build every client's site.
 */
function buildCcWebVars({ site, factsOut, observedDest }) {
  return {
    cc_web_facts: site.web_facts,
    cc_web_server_name: site.server_name,
    cc_web_docroot: site.docroot,
    // Passed EXPLICITLY rather than left to the role's default, because the
    // collection play below is not the role and does not see role defaults —
    // both plays have to agree about which file to read.
    cc_web_facts_out: factsOut,
    cc_web_observed_dest: observedDest,
    cc_web_routes: site.routes.map((r) => ({
      path: r.path,
      file: r.file,
      content: unsafeScalar(r.content),
    })),
    cc_web_pivot: site.pivot,
  };
}

/** The inventory. One group, `cc_web`, holding exactly the lane's DMZ host —
 *  the contract cc-web.yml's header states, and it must not overlap any GOAD
 *  group. Key-based, because the controller has no sshpass. */
function buildCcWebInventory({ host, keyPath, user }) {
  const invName = String(host.name).toLowerCase().replace(/[^a-z0-9-]+/g, '-').replace(/^-+|-+$/g, '')
    || 'ccweb';
  return `${[
    '# Written by the bake. One group, one host: the lane\'s dual-homed DMZ box.',
    '[cc_web]',
    `${invName} ansible_host=${host.ip}`,
    '',
    '[cc_web:vars]',
    'ansible_connection=ssh',
    `ansible_user=${user}`,
    `ansible_ssh_private_key_file=${keyPath}`,
    'ansible_become=true',
    'ansible_become_method=sudo',
    'ansible_python_interpreter=/usr/bin/python3',
    // The lane is rebuilt constantly and every host key is new, so a known-hosts
    // check here only ever fails. StrictHostKeyChecking is off in this tree's
    // ansible.cfg too; this covers the ssh client ansible actually forks.
    'ansible_ssh_common_args=-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=20',
  ].join('\n')}\n`;
}

/**
 * The second play: bring the OBSERVED facts back to the controller.
 *
 * A SEPARATE PLAY, RUN IN THE SAME INVOCATION, rather than a wrapper that
 * re-declares the role. cc-web.yml is THE play that applies cc_web — its header
 * says so and its inventory contract is the one used here — and a second copy of
 * `roles: [cc_web]` would be a second place to keep in step. ansible-playbook
 * takes several playbook files and runs them in order, so this appends a
 * collection step without editing or duplicating the role's own entry point.
 */
function buildCcWebCollectPlaybook() {
  return `${[
    '---',
    '# Written by the bake. Runs AFTER cc-web.yml, in the same ansible-playbook',
    '# invocation, so the file it fetches is the one this run just published.',
    '- name: Collect what the curated web tier actually installed',
    '  hosts: "{{ cc_web_hosts | default(\'cc_web\') }}"',
    '  become: true',
    '  gather_facts: false',
    '  tasks:',
    '    - name: Fetch the observed web facts back to the controller',
    '      ansible.builtin.fetch:',
    '        src: "{{ cc_web_facts_out }}"',
    '        dest: "{{ cc_web_observed_dest }}"',
    '        flat: true',
  ].join('\n')}\n`;
}

/**
 * The ansible-playbook argv. Pure, so a test can assert that no credential is
 * ever an argument: the pivot password lives only in the 0600 vars file.
 */
function buildCcWebArgv({ inventoryPath, collectPath, varsPath }) {
  return [
    'ansible-playbook',
    '-i', inventoryPath,
    // Relative on purpose: the run cds into the staged tree so that this
    // directory's ansible.cfg (and therefore ./roles ahead of upstream GOAD's
    // read-only role library) is the one in force.
    'cc-web.yml',
    collectPath,
    '--extra-vars', `@${varsPath}`,
  ];
}

/**
 * Compare what the site DECLARED with what the host actually answered.
 *
 * Both sides go through readWebFacts() — the scan documents' own normaliser — so
 * this cannot pass on a spelling difference the report would trip over, and
 * cannot fail on one it would not. The extra fields the role publishes beyond
 * the contract (server_name, docroot, pivot_credential_path) are compared
 * directly: they are how this step learns the credential landed where the site
 * said it would.
 */
function compareWebFacts(declared, observed) {
  /* eslint-disable global-require */
  const { readWebFacts } = require('../ai/scan-documents/service-inference');
  /* eslint-enable global-require */
  const differences = [];
  const want = readWebFacts({ web_facts: declared });
  const got = readWebFacts({ web_facts: observed });
  if (!want) {
    differences.push('the site declared no usable web facts');
    return { match: false, differences, want: null, got: got || null };
  }
  if (!got) {
    differences.push('the host published no usable web facts, so nothing confirms what it serves');
    return { match: false, differences, want, got: null };
  }
  const list = (v) => (Array.isArray(v) ? v.slice().sort() : []);
  const same = (a, b) => JSON.stringify(list(a)) === JSON.stringify(list(b));

  if (String(want.product).toLowerCase() !== String(got.product).toLowerCase()) {
    differences.push(`product: the paper says '${want.product}', the host serves '${got.product}'`);
  }
  if (String(want.version) !== String(got.version)) {
    differences.push(`version: the paper says '${want.version || '(none)'}', the host serves `
      + `'${got.version || '(none)'}'`);
  }
  if (!same(want.ports, got.ports)) {
    differences.push(`ports: the paper says ${list(want.ports).join(', ')}, the host binds `
      + `${list(got.ports).join(', ') || '(none)'}`);
  }
  if (want.tls.enabled !== got.tls.enabled) {
    differences.push(`TLS: the paper says enabled=${want.tls.enabled}, the host says ${got.tls.enabled}`);
  } else if (want.tls.enabled) {
    if (Number(want.tls.port) !== Number(got.tls.port)) {
      differences.push(`TLS port: the paper says ${want.tls.port}, the host terminates on ${got.tls.port}`);
    }
    if (!same(want.tls.protocols, got.tls.protocols)) {
      differences.push(`TLS protocols: the paper says ${list(want.tls.protocols).join(', ')}, the host `
        + `completed handshakes for ${list(got.tls.protocols).join(', ') || '(none)'}`);
    }
  }
  if (!same(want.paths, got.paths)) {
    differences.push(`paths: the paper links to ${list(want.paths).join(', ')}, the host resolves `
      + `${list(got.paths).join(', ') || '(none)'}`);
  }
  return { match: differences.length === 0, differences, want, got };
}

/** Everything the role installed, checked against everything the site declared. */
function gradeWebInstall({ site, observed, exitCode, log }) {
  if (exitCode !== 0) {
    const tail = String(log || '').trim().split('\n').slice(-12).join('\n');
    return {
      ran: true,
      applicable: true,
      passed: false,
      reason: `the cc_web role exited ${exitCode === null ? '(never finished)' : exitCode}. `
        + 'Its own fail-fast gate names the variable or the host it refused on; the tail of the run '
        + 'is below.',
      differences: [],
      log_tail: tail,
    };
  }
  if (!observed || typeof observed !== 'object') {
    return {
      ran: true,
      applicable: true,
      passed: false,
      reason: 'the role reported success and published no observed facts, so nothing confirms what '
        + 'the host actually serves. "It said green" is not evidence — that is the whole reason the '
        + 'role writes this file.',
      differences: [],
      log_tail: String(log || '').trim().split('\n').slice(-12).join('\n'),
    };
  }
  const facts = compareWebFacts(site.web_facts, observed);
  const extra = [];
  if (String(observed.server_name || '') !== String(site.server_name)) {
    extra.push(`ServerName: the site is written for '${site.server_name}', the host serves `
      + `'${observed.server_name || '(none)'}'`);
  }
  if (String(observed.docroot || '') !== String(site.docroot)) {
    extra.push(`docroot: the site is installed at '${site.docroot}', the host reports `
      + `'${observed.docroot || '(none)'}'`);
  }
  if (String(observed.pivot_credential_path || '') !== String(site.pivot.path)) {
    extra.push(`pivot credential: the site plants it at '${site.pivot.path}', the host reports `
      + `'${observed.pivot_credential_path || '(none)'}'`);
  }
  const differences = facts.differences.concat(extra);
  return {
    ran: true,
    applicable: true,
    passed: differences.length === 0,
    reason: differences.length === 0
      ? `the DMZ host serves ${site.org}'s site at ${site.server_name} and the facts it published `
        + 'match the ones the scan documents are allowed to claim'
      : 'the host the role built and the facts the scan documents assert do not agree. The report '
        + 'would describe a machine that is not on the lane, which is the one failure the web-facts '
        + 'contract exists to make impossible',
    differences,
    log_tail: null,
  };
}

/**
 * Author this client's website and install it on the lane's DMZ host.
 *
 * @param {object}   a
 * @param {object}   a.spec            the spec the push phase prepared
 * @param {object}   a.lane            the lane row the deployer inserted
 * @param {number}   a.controllerVmId  the ansible runner
 * @param {Function} a.setDetail
 * @param {object}   a.deps
 * @returns {Promise<object>} a report, in the same envelope the probe uses
 */
async function installCompanyWebsite({ spec, lane, controllerVmId, setDetail, deps }) {
  const cc = (spec && spec.cc_web) || {};
  if (cc.enabled === false) {
    // A DECLARATION, NOT A SILENCE. Same reading cc_web_pivot_required takes:
    // "this environment has no website" and "we forgot the website" must not be
    // the same outcome, so the only way to skip is to say so on the spec.
    return {
      ran: false,
      applicable: false,
      passed: null,
      reason: 'spec.cc_web.enabled is false: this environment declares itself AD-only and has no '
        + 'company website.',
      differences: [],
    };
  }
  if (!hasCompiledLab(spec)) {
    return {
      ran: false,
      applicable: false,
      passed: null,
      reason: 'this bake carries no compiled lab (spec.goad.lab has no domains and no roster), so '
        + 'there is no client to author a website for. A bake made by the profile route always '
        + 'carries one; a spec that only names a forest describes no company.',
      differences: [],
    };
  }
  if (!Number.isInteger(controllerVmId) || controllerVmId <= 0) {
    throw refuse(
      'the staging lane recorded no ansible controller, so the cc_web role has nothing to run from. '
      + 'The controller is the only Ansible runner on a lane — the orchestrator container has '
      + 'neither ansible nor python3 — so without it the company website cannot be installed at all.',
      'BAKE_PROVISION_WEB_NO_CONTROLLER'
    );
  }

  /* eslint-disable global-require */
  const labContent = require('./goad-lab-content');
  /* eslint-enable global-require */

  const ir = spec.goad.lab;
  // THE SEAM IS PROVED HERE, BEFORE ANY HOST IS TOUCHED. generateSiteContent
  // refuses to emit a site whose planted credential Active Directory does not
  // honour, and refuses one that fails to plant a credential the chain says the
  // web side hands out. Both are compile errors, so a mismatch is a refusal in
  // the first seconds of this step rather than a student's login failing later.
  const site = labContent.generateSiteContent(ir, {
    runId: ir.run_id || ir.lab_name,
    apacheVersion: cc.apache_version,
  });

  const host = resolveDmzHost({ spec, lane });
  const node = String((lane.config || {}).node || host.node || '');
  if (!node) {
    throw refuse(
      'the lane records no Proxmox node, so neither the controller nor the DMZ host can be reached '
      + 'through the guest agent.',
      'BAKE_PROVISION_WEB_NO_NODE'
    );
  }

  const runId = `${Date.now().toString(36)}`;
  const runDir = shellSafe(`${CC_WEB_RUN_DIR}/${runId}`, 'the run directory');
  const treeDir = `${runDir}/cc-web`;
  const keyPath = `${runDir}/id_ed25519`;
  const varsPath = `${runDir}/cc-web-vars.yml`;
  const invPath = `${runDir}/inventory`;
  const collectPath = `${runDir}/cc-web-collect.yml`;
  const observedDest = `${runDir}/observed.json`;
  const logPath = `${runDir}/cc-web.log`;
  const donePath = `${runDir}/done.txt`;
  const factsOut = '/etc/cybercore/cc-web-observed.json';

  // PER-VM NODE, not the lane's. The controller and the DMZ host are separate
  // guests and a lane's machines are not guaranteed to be co-located: a
  // guest-exec addressed to the wrong node is a 500 from Proxmox, not a wrong
  // answer, but it is one that would only ever show up on a two-node cluster.
  const nodeFor = (vmId) => (vmId === controllerVmId ? node : (host.node || node));
  const execRaw = async (vmId, argv, timeoutMs) => {
    const on = nodeFor(vmId);
    const { pid } = await deps.agentExecArgv(on, vmId, argv, deps.proxmoxAPI);
    return deps.pollExecStatus(on, vmId, pid, timeoutMs || 60000);
  };
  /** Every staging step, checked. A guest-exec that reported a non-zero exit
   *  and was ignored is how a run reaches ansible with half a role staged and
   *  then fails ninety seconds later on a file that was never written. */
  const exec = async (vmId, argv, timeoutMs, what) => {
    const r = await execRaw(vmId, argv, timeoutMs);
    if (!r || r.exited !== true || Number(r.exitcode) !== 0) {
      throw refuse(
        `${what} failed on VM ${vmId} (exit ${r ? r.exitcode : 'none'}): `
        + `${String((r && r.stderr) || (r && r.stdout) || 'no output').trim().slice(0, 400)}`,
        'BAKE_PROVISION_WEB_STAGING_FAILED'
      );
    }
    return r;
  };

  /** Write one file on the controller, in polled chunks, never world-readable. */
  const write = async (destPath, content, mode) => {
    const dir = destPath.slice(0, destPath.lastIndexOf('/'));
    const b64 = Buffer.from(String(content), 'utf8').toString('base64');
    for (let i = 0; i < b64.length || i === 0; i += CC_WEB_CHUNK) {
      const part = b64.slice(i, i + CC_WEB_CHUNK);
      const redirect = i === 0 ? '>' : '>>';
      // umask 077 BEFORE the redirect, so the file is never briefly readable;
      // the explicit chmod covers a pre-existing file the redirect truncates
      // rather than recreates.
      await exec(controllerVmId, ['/bin/sh', '-c',
        `umask 077; mkdir -p '${dir}' && printf '%s' '${part}' ${redirect} '${destPath}.b64'`],
      60000, `staging ${destPath}`);
    }
    await exec(controllerVmId, ['/bin/sh', '-c',
      `umask 077; base64 -d < '${destPath}.b64' > '${destPath}' && rm -f '${destPath}.b64' `
      + `&& chmod ${mode || '600'} '${destPath}'`], 60000, `decoding ${destPath}`);
  };

  const readFile = async (vmId, p) => {
    // __MISSING__ rather than a non-zero exit, so "the file is not there yet" is
    // an ANSWER the poll loop can act on instead of an error it has to catch.
    const r = await execRaw(vmId, ['/bin/sh', '-c',
      `[ -f '${p}' ] && cat '${p}' || echo __MISSING__`], 30000);
    return String((r && r.stdout) || '').trim();
  };

  await setDetail(`Authoring ${site.org}'s website (${site.routes.length} pages, `
    + `${site.web_facts.ports.join('/')}) and installing it on ${host.name} at ${host.ip}.`);

  // 1. the role tree, verbatim out of this repository.
  const tree = readCcWebTree();
  for (const [rel, body] of Object.entries(tree)) {
    await write(`${treeDir}/${shellSafe(rel, `the role member '${rel}'`)}`, body, '644');
  }

  // 2. a keypair on the controller, and the public half authorised on the DMZ
  //    host through the guest agent.
  //
  //    WHY NOT A PASSWORD. ansible over SSH with ansible_password needs sshpass,
  //    and the controller template does not install it (see its cloud-init
  //    package list). Rather than depend on a package that is not there — or on
  //    an apt-get reaching the internet from inside a lane — the orchestrator
  //    uses the one channel it already has to both machines: the guest agent.
  const keygen = await exec(controllerVmId, ['/bin/sh', '-c',
    `umask 077; mkdir -p '${runDir}'; [ -f '${keyPath}' ] || ssh-keygen -q -t ed25519 -N '' `
    + `-C cc-web-bake -f '${keyPath}' >/dev/null 2>&1; cat '${keyPath}.pub'`],
  120000, 'generating the controller SSH key');
  const pubKey = String((keygen && keygen.stdout) || '').trim().split('\n').filter(Boolean).pop() || '';
  if (!/^ssh-ed25519 [A-Za-z0-9+/=]+/.test(pubKey)) {
    throw refuse(
      'the controller could not produce an SSH key for the cc_web run, so ansible has no way to '
      + `reach the DMZ host (ssh-keygen said: ${String((keygen && keygen.stderr) || '').trim().slice(0, 200) || 'nothing'}).`,
      'BAKE_PROVISION_WEB_NO_KEY'
    );
  }
  if (!host.vm_id) {
    throw refuse(
      `the lane records no VMID for '${host.name}', so the bake cannot authorise the controller's key `
      + 'on it through the guest agent.',
      'BAKE_PROVISION_WEB_NO_DMZ_VMID'
    );
  }
  const user = shellSafe(cc.ssh_user || CC_WEB_SSH_USER, 'the DMZ ssh user');
  const keyB64 = Buffer.from(`${pubKey}\n`, 'utf8').toString('base64');
  await exec(host.vm_id, ['/bin/sh', '-c',
    `set -e; home=$(getent passwd '${user}' | cut -d: -f6); [ -n "$home" ] || exit 9; `
    + 'mkdir -p "$home/.ssh"; chmod 700 "$home/.ssh"; touch "$home/.ssh/authorized_keys"; '
    + `echo '${keyB64}' | base64 -d > /tmp/cc-web.pub; `
    // grep -qxF: exact whole-line match, so a replay adds nothing and a rerun of
    // the bake does not grow the file by one key per attempt.
    + 'grep -qxF "$(cat /tmp/cc-web.pub)" "$home/.ssh/authorized_keys" '
    + '|| cat /tmp/cc-web.pub >> "$home/.ssh/authorized_keys"; '
    + `rm -f /tmp/cc-web.pub; chmod 600 "$home/.ssh/authorized_keys"; `
    + `chown -R '${user}:${user}' "$home/.ssh" 2>/dev/null || chown -R '${user}' "$home/.ssh"`],
  120000, `authorising the controller key for '${user}' on the DMZ host`);

  // 3. the inventory, the variables and the collection play.
  await write(invPath, buildCcWebInventory({ host, keyPath, user }), '600');
  await write(collectPath, buildCcWebCollectPlaybook(), '600');
  // 0600 AND NOTHING ELSE. This file carries the pivot password, which is the
  // credential the whole engagement pivots on; it never reaches a command line,
  // a task banner or the job log.
  await write(varsPath, toVarsYaml(buildCcWebVars({ site, factsOut, observedDest })), '600');

  // 4. run it, detached, with a sentinel — the shape runPostconditionProbe uses,
  //    because QGA buffers a long-running process's stdio in memory and loses
  //    track of long-running PIDs entirely.
  const argv = buildCcWebArgv({ inventoryPath: invPath, collectPath, varsPath });
  const quoted = argv.map((a) => `'${String(a).replace(/'/g, `'\\''`)}'`).join(' ');
  const inner = `cd '${treeDir}' && ANSIBLE_CONFIG=./ansible.cfg ${quoted} > '${logPath}' 2>&1; `
    + `echo \\$? > '${donePath}'`;
  await deps.agentExecArgv(node, controllerVmId, ['/bin/bash', '-c',
    `rm -f '${donePath}'; nohup setsid sh -c "${inner}" </dev/null >/dev/null 2>&1 &`], deps.proxmoxAPI);

  const timeoutMs = Number(cc.timeout_ms) > 0 ? Number(cc.timeout_ms) : CC_WEB_TIMEOUT_MS;
  const deadline = Date.now() + timeoutMs;
  let exitCode = null;
  while (Date.now() < deadline) {
    await deps.sleep(10000);
    let done = '';
    try { done = await readFile(controllerVmId, donePath); } catch (_) { /* transient; keep polling */ }
    if (done && done !== '__MISSING__') {
      const n = parseInt(done, 10);
      exitCode = Number.isFinite(n) ? n : 1;
      break;
    }
  }

  let log = '';
  try { log = await readFile(controllerVmId, logPath); } catch (_) { log = ''; }
  let observed = null;
  try {
    const raw = await readFile(controllerVmId, observedDest);
    if (raw && raw !== '__MISSING__') observed = JSON.parse(raw);
  } catch (_) { observed = null; }

  const report = gradeWebInstall({ site, observed, exitCode, log });
  return Object.assign(report, {
    host: host.name,
    ip: host.ip,
    server_name: site.server_name,
    docroot: site.docroot,
    routes: site.routes.map((r) => r.path),
    declared_facts: site.web_facts,
    observed_facts: observed,
    pivot_path: site.pivot.path,
    // THE ACCOUNT, NEVER THE PASSWORD. This report is written to a bake row an
    // instructor can read, and the pivot credential is the lane's way in.
    pivot_account: `${site.pivot.domain}\\${site.pivot.username}`,
    carries_foothold: site.carries_foothold,
    site_warnings: site.warnings,
  });
}

// ─── CAPTURE ────────────────────────────────────────────────────────────────

/**
 * The machines a capture turns into templates.
 *
 * PURE, so what is and is not captured is assertable without a cluster. Three
 * exclusions, each of which would break something specific:
 *
 *   the gateway     an LXC cloned per lane from 1692/1694/1695, whose whole
 *                   config is derived from the lane's own vxlan id. Templating
 *                   it would freeze one lane's addressing into every lane.
 *   Kali            cloned from the shared attack-box template on every deploy
 *                   and carrying a per-lane generated password. A captured Kali
 *                   would hand every student the staging lane's credential.
 *   the controller  the ansible box. It exists to run the chain once; a lane
 *                   built from golden images runs no chain at all
 *                   (deployPrebakedGoadLane takes no controller), and it is the
 *                   one VM teardown is guaranteed to have to destroy.
 */
function captureTargets({ bake, lane }) {
  const cfg = (lane && lane.config) || {};
  const vms = Array.isArray(cfg.vms) ? cfg.vms : [];

  const excluded = new Set();
  for (const candidate of [cfg.gateway_vm_id, cfg.attack_box_vm_id, bake && bake.controller_vmid,
    controllerVmidFor(lane && lane.vxlan_id)]) {
    const n = Number(candidate);
    if (Number.isInteger(n) && n > 0) excluded.add(n);
  }

  const out = [];
  for (const vm of vms) {
    const vmid = Number(vm && vm.vm_id);
    if (!Number.isInteger(vmid) || vmid <= 0) continue;
    // LXC guests are the gateway and nothing else on a challenge lane; a golden
    // image set is qemu by construction.
    if (vm.type && vm.type !== 'qemu') continue;
    if (excluded.has(vmid)) continue;
    if (String(vm.name || '').toLowerCase() === 'kali') continue;
    out.push({
      name: vm.name || `vm-${vmid}`,
      vmid,
      // The lane's node when the VM record does not carry one: teardown and
      // every Proxmox call need a node, and a VMID without one cannot be placed.
      node: vm.node || cfg.node || null,
    });
  }
  return out;
}

/**
 * What the lane's own config says it was built on.
 *
 * deployLaneVms writes lane_subnet_base for every lane and lane_subnet_internal
 * for a v3 one, so an active lane always carries at least the external base.
 * A lane that carries neither is a lane whose addressing cannot be read, which
 * is a refusal rather than a default — see assertSubnetMatch.
 */
function observedSubnetBases(lane) {
  const cfg = (lane && lane.config) || {};
  const ext = cfg.lane_subnet_base || null;
  const int = cfg.lane_subnet_internal || cfg.lane_subnet_base || null;
  return { int: int || null, ext: ext || null };
}

/**
 * Refuse a capture whose templates would be baked on a different subnet than
 * the one every lane of this profile will be built on.
 *
 * THE MISMATCH IS THE WHOLE FAILURE, restated one layer down: the declared
 * fixed_subnet is what the deploy path will pin future lanes to, and the
 * observed base is what these images actually wrote into their DNS zone, their
 * SYSVOL referrals and their SPNs. If they disagree, every lane cloned from this
 * capture comes up `active` with a forest that names addresses it does not have.
 *
 * A lane that reports no bases at all is refused for the same reason a probe
 * that did not run is: "could not check" and "no drift" are not the same answer.
 */
function assertSubnetMatch(fixed, lane) {
  const observed = observedSubnetBases(lane);
  if (!observed.int && !observed.ext) {
    throw refuse(
      'the staging lane records no subnet bases (config.lane_subnet_base), so there is no way to '
      + 'confirm these images were built on the subnet future lanes will be pinned to '
      + `(${fixed.int}.0/24 internal, ${fixed.ext}.0/24 external). Refusing rather than assuming — a `
      + 'template set baked on the wrong base produces lanes that report healthy and resolve nothing.',
      'BAKE_CAPTURE_SUBNET_UNKNOWN'
    );
  }
  const wrong = [];
  if (observed.int && observed.int !== fixed.int) wrong.push(`internal ${observed.int} ≠ ${fixed.int}`);
  if (observed.ext && observed.ext !== fixed.ext) wrong.push(`external ${observed.ext} ≠ ${fixed.ext}`);
  if (wrong.length > 0) {
    throw refuse(
      `the staging lane was built on a different subnet than this environment pins its lanes to `
      + `(${wrong.join(', ')}). A golden AD image writes its own addresses into DNS, SYSVOL and every `
      + 'SPN, so capturing this lane would produce templates that are fiction on every lane cloned '
      + 'from them — and nothing would report a problem. Either set spec.goad.fixed_subnet to the '
      + 'bases this lane actually used, or pin the staging lane to the declared bases '
      + '(applyPrebakedFixedSubnet in src/utils/challenge-lane-deployer.js is where that pin is '
      + 'applied today) and re-bake.',
      'BAKE_CAPTURE_SUBNET_MISMATCH'
    );
  }
  return observed;
}

/**
 * Turn a set of read-back VM states into a decision.
 *
 * PURE, and this is the idempotence rule of the whole phase. Capture is the last
 * thing a bake does and it is the point of no return: a converted VM cannot be
 * un-converted, so a retry that lands on a half-converted lane has exactly three
 * honest options and only one of them is safe.
 *
 *   every target already a template   the previous attempt finished; record the
 *                                     VMIDs and return. A retry after a complete
 *                                     capture is a no-op, not a rebuild.
 *   no target a template              the normal path.
 *   SOME of them templates            REFUSED. Converting the rest would produce
 *                                     a template set assembled from two runs of
 *                                     a ninety-minute chain, and the machines
 *                                     from the first run were shut down while
 *                                     the second run's were still writing to a
 *                                     forest they were part of. Nothing about
 *                                     that set is verifiable, and half of it
 *                                     already passed a probe that no longer
 *                                     describes it.
 *
 * A target that cannot be read is refused for the same reason: a template set
 * missing a machine is a lane that will be missing a machine, and guessing which
 * is worse than saying so.
 */
function classifyCapture(states) {
  const unreadable = states.filter((s) => !s.exists);
  if (unreadable.length > 0) {
    throw refuse(
      `cannot read ${unreadable.length} of ${states.length} staging VM(s) on the cluster `
      + `(${unreadable.map((s) => `${s.name}/${s.vmid}: ${s.error || 'not found'}`).join('; ')}). `
      + 'Capturing the rest would produce a template set missing a machine, and every lane cloned '
      + 'from it would be missing it too. Re-bake rather than capture a partial environment.',
      'BAKE_CAPTURE_VM_UNREADABLE'
    );
  }

  const already = states.filter((s) => s.isTemplate);
  const pending = states.filter((s) => !s.isTemplate);

  if (already.length > 0 && pending.length > 0) {
    throw refuse(
      `this staging lane is HALF CAPTURED: ${already.length} of ${states.length} machine(s) are `
      + `already templates (${already.map((s) => s.name).join(', ')}) and `
      + `${pending.length} are not (${pending.map((s) => s.name).join(', ')}). A previous capture `
      + 'stopped partway. Finishing it would assemble a golden set out of two different runs of the '
      + 'chain, with no way to tell whether the halves ever described one forest — and the probe that '
      + 'passed describes neither. Re-bake: a restart tears the staging lane down and builds a whole '
      + 'one, which is the only state this design can vouch for.',
      'BAKE_CAPTURE_PARTIAL'
    );
  }

  return {
    mode: pending.length === 0 ? 'already_captured' : 'capture',
    already,
    pending,
  };
}

/** golden_vmids, in the name-keyed shape vmidsFromGolden reads for teardown. */
function goldenEntry(state) {
  return { name: state.name, vmid: state.vmid, node: state.node };
}

/**
 * Read one target's state: does it exist, is it already a template, is it
 * running, and where is its cloud-init drive.
 */
async function readTargetState(target, deps) {
  if (!target.node) {
    return { ...target, exists: false, error: 'the lane records no node for this machine' };
  }
  try {
    const base = qemuBase(target.node, target.vmid);
    const cfg = await deps.proxmoxAPI('GET', `${base}/config`);
    const status = await deps.proxmoxAPI('GET', `${base}/status/current`);
    const isTemplate = Number((cfg && cfg.template) || (status && status.template) || 0) === 1;
    return {
      ...target,
      exists: true,
      error: null,
      isTemplate,
      power: (status && status.status) || 'unknown',
      ciDrive: findCloudInitDrive(cfg),
    };
  } catch (err) {
    return { ...target, exists: false, error: err.message };
  }
}

/** The cloud-init drive key on a QEMU VM (ide2, sata3, …), or null. */
function findCloudInitDrive(cfg) {
  if (!cfg || typeof cfg !== 'object') return null;
  return Object.keys(cfg).find((k) => (
    /^(ide|sata|scsi|virtio)\d+$/.test(k)
    && typeof cfg[k] === 'string'
    && /cloudinit/i.test(cfg[k])
  )) || null;
}

/**
 * Shut a guest down cleanly, or refuse.
 *
 * ACPI SHUTDOWN, NEVER `status/stop`, AND A TIMEOUT IS A REFUSAL.
 *
 * A hard stop is a power cut. On a domain controller that means NTDS.dit and the
 * SYSVOL/DFSR database are frozen mid-write, and the damage is INHERITED: every
 * lane cloned from that template starts from the same torn database. Windows
 * repairs a dirty shutdown on the next boot often enough that the clones come up,
 * report healthy, and fail later — replication that never converges, SYSVOL that
 * never publishes, a GPO that silently does not apply. That is the same
 * silent-success family as the broken GOAD roles, manufactured by the one step
 * whose entire purpose is to freeze a known-good forest.
 *
 * So a guest that will not stop cleanly refuses the capture. The staging lane
 * survives (bakeProfile does not tear down a failed bake), so an operator can go
 * look at why — and re-baking is ninety minutes, while a bad golden set is every
 * lane of that client for as long as it stays deployed.
 */
async function stopForCapture(state, deps, setDetail) {
  if (state.power === 'stopped') return;
  const base = qemuBase(state.node, state.vmid);
  await setDetail(`Shutting ${state.name} down cleanly before capture (AD must flush to disk).`);
  await deps.proxmoxAPI('POST', `${base}/status/shutdown`, { timeout: Math.round(SHUTDOWN_WAIT_MS / 1000) });
  try {
    await deps.waitForPowerState(state.node, state.vmid, 'qemu', 'stopped', { timeoutMs: SHUTDOWN_WAIT_MS });
  } catch (err) {
    throw refuse(
      `${state.name} (VM ${state.vmid}) did not shut down cleanly within `
      + `${Math.round(SHUTDOWN_WAIT_MS / 60000)} minutes: ${err.message}. Refusing to force it off — `
      + 'a power cut freezes NTDS.dit and SYSVOL mid-write, and every lane cloned from the resulting '
      + 'template inherits the damage and still boots, so nothing reports it. Investigate the guest '
      + 'on the staging lane, or re-bake.',
      'BAKE_CAPTURE_STOP_FAILED'
    );
  }
}

/**
 * Convert one stopped VM into a golden template.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * DO NOT SYSPREP. THIS IS THE REFLEX ANSWER AND IT IS WRONG HERE.
 * ─────────────────────────────────────────────────────────────────────────────
 * "Generalise the image before you template it" is correct for a stock Windows
 * build and catastrophic for this one. Sysprep on a DOMAIN CONTROLLER is
 * explicitly unsupported by Microsoft: /generalize resets the machine SID, the
 * computer account password and the machine's identity, and a DC's identity IS
 * the directory. Running it does not produce a clean DC — it destroys the domain
 * that ninety minutes of ansible just built, and the destruction is not visible
 * until a clone tries to authenticate something. Sysprepping the MEMBERS is no
 * better: each one's baked AD account (TUC-SRV02$ and friends) is matched by
 * name and secure-channel password, and a generalised member rejoins as a
 * stranger to a forest that still holds its old account.
 *
 * The design does not need generalisation, because it never lets two clones
 * collide in the first place:
 *
 *   atomic clone      every lane clones the WHOLE set together, so the forest
 *                     that comes up is the forest that was captured — same
 *                     hostnames, same SIDs, same trust relationships, isolated
 *                     inside its own VXLAN.
 *   cloud-init strip  below. Without it Proxmox regenerates a cloud-init ISO on
 *                     every clone and cloudbase-init's SetHostNamePlugin renames
 *                     the guest to the Proxmox VM name — which is precisely how
 *                     a member's baked account stops matching its host and its
 *                     secure channel breaks, while the lane still reports
 *                     `active`. (DCs survive it only because Windows refuses to
 *                     rename a DC, which is why only members broke in testing.)
 *   pinned subnet     assertFixedSubnet, above. Every lane shares one base per
 *                     segment, so the addresses baked into DNS, SYSVOL and the
 *                     SPNs stay true.
 *
 * Those three together are what make the baked hostname, IP and machine password
 * still valid on a clone. Sysprep would invalidate all three at once.
 */
async function captureOne(state, deps, setDetail) {
  const base = qemuBase(state.node, state.vmid);

  await stopForCapture(state, deps, setDetail);

  // Strip the cloud-init drive BEFORE the template conversion: a template's
  // config is what every clone inherits, so a drive still attached here is a
  // drive attached on every lane, and the rename happens on first boot.
  if (state.ciDrive) {
    await setDetail(`Stripping ${state.name}'s cloud-init drive (${state.ciDrive}) so clones keep their baked hostname.`);
    await deps.proxmoxAPI('PUT', `${base}/config`, { delete: state.ciDrive });
  } else {
    console.log(`${LOG} ${state.name}: no cloud-init drive to strip`);
  }

  await setDetail(`Converting ${state.name} (VM ${state.vmid}) to a golden template.`);
  const task = await deps.proxmoxAPI('POST', `${base}/template`);
  // Proxmox returns a UPID for this on current versions and an empty body on
  // older ones. Following it when there is one is what turns "the request was
  // accepted" into "the conversion finished".
  if (typeof task === 'string' && task.startsWith('UPID:')) {
    await deps.waitForTask(state.node, task, 300000);
  }

  // CONFIRMED, not assumed. This is the phase whose failure mode is a bake that
  // reads 'ready' while lanes clone from templates that do not exist.
  const after = await deps.proxmoxAPI('GET', `${base}/config`);
  if (Number((after && after.template) || 0) !== 1) {
    throw refuse(
      `${state.name} (VM ${state.vmid}) did not become a template — Proxmox accepted the conversion `
      + 'and the VM is still a VM. Refusing to record it as golden: a lane cloning from it would '
      + 'get a running machine\'s disk, or nothing at all.',
      'BAKE_CAPTURE_NOT_TEMPLATE'
    );
  }
}

/**
 * Turn the staging lane's machines into the golden templates every later lane
 * of this profile clones.
 *
 * Wired into bake-orchestrator.buildBakeSteps as the 'capture' phase.
 *
 * THE STAGING LANE IS NOT TORN DOWN HERE, and that is deliberate. The captured
 * templates ARE that lane's VMs, converted in place, and teardownStagingLane's
 * own note explains why the lane row has to outlive them: a VMID with no lane
 * row has no recorded node, so nothing can destroy a VM it cannot place. Keeping
 * the row is what keeps the golden set destroyable — by a forced Re-bake, which
 * says out loud that it throws the templates away, and by the boot sweep.
 *
 * @param {object}   args              bake-orchestrator's step arguments
 * @param {object}   [args.spec]       the spec the push phase prepared
 * @param {object}   [args.deps]       injected impurity, for tests
 * @returns {Promise<{golden_vmids:object}>}
 */
async function captureGolden(args) {
  const { bake, record, setDetail } = args;
  const deps = withDeps(args.deps);
  const spec = args.spec || (bake && bake.spec);

  // FIRST, before anything is read off the cluster and long before anything is
  // converted: a capture without a pinned subnet produces a template set no lane
  // can be correctly built from, and the conversion is irreversible.
  const fixed = assertFixedSubnet(spec);

  if (!bake || !bake.staging_lane_id) {
    throw refuse(
      'this bake recorded no staging lane, so there are no machines to capture. The provision phase '
      + 'either never ran or never got far enough to write staging_lane_id — re-bake rather than '
      + 'capture whatever happens to be on the cluster.',
      'BAKE_CAPTURE_NO_LANE'
    );
  }

  const lane = await loadLaneById(bake.staging_lane_id, deps);
  if (!lane) {
    throw refuse(
      `staging lane ${bake.staging_lane_id} no longer exists on the cluster database, so its `
      + 'machines cannot be enumerated or placed. Re-bake.',
      'BAKE_CAPTURE_NO_LANE'
    );
  }

  assertSubnetMatch(fixed, lane);

  const targets = captureTargets({ bake, lane });
  if (targets.length === 0) {
    throw refuse(
      `staging lane ${lane.lane_id} lists no capturable machines (its config records `
      + `${Array.isArray(lane.config.vms) ? lane.config.vms.length : 0} VM(s), all of them the `
      + 'gateway, the attack box or the ansible controller). There is nothing to turn into a golden '
      + 'template, and a bake that reached \'ready\' here would leave every lane cloning from '
      + 'nothing.',
      'BAKE_CAPTURE_NO_TARGETS'
    );
  }

  await setDetail(`Reading the state of ${targets.length} staging machine(s) before touching any of them.`);
  const states = [];
  for (const target of targets) states.push(await readTargetState(target, deps));

  // The point of no return, and the one guard that makes a retry safe.
  const plan = classifyCapture(states);

  if (plan.mode === 'already_captured') {
    const golden = {};
    for (const state of plan.already) golden[state.name] = goldenEntry(state);
    await record({ golden_vmids: golden });
    await setDetail(
      `Every one of the ${plan.already.length} staging machine(s) is already a template — a previous `
      + 'capture finished. Recorded the existing VMIDs rather than rebuilding them.'
    );
    return { golden_vmids: golden };
  }

  const golden = {};
  let done = 0;
  for (const state of plan.pending) {
    await captureOne(state, deps, setDetail);
    golden[state.name] = goldenEntry(state);
    done++;
    // RECORDED AFTER EVERY MACHINE, not at the end. A crash here leaves N
    // templates on the cluster, and the bake row is the only thing that can
    // name them: teardownStagingLane enumerates golden_vmids, and what it is
    // not told about it cannot destroy. The cost of writing four times instead
    // of once is four UPDATEs; the cost of not doing it is a leaked template
    // per machine, forever.
    await record({ golden_vmids: { ...golden } });
    await setDetail(`Captured ${done}/${plan.pending.length}: ${state.name} is golden template ${state.vmid}.`);
  }

  await setDetail(
    `Captured ${done} golden template(s) from staging lane ${lane.lane_id}: `
    + `${Object.keys(golden).join(', ')}. Lanes of this client now clone instead of build.`
  );
  return { golden_vmids: golden };
}

module.exports = {
  // The two phases, as bake-orchestrator.buildBakeSteps binds them.
  provisionStagingLane,
  captureGolden,
  // Pure, so every refusal is assertable without a cluster or a database.
  assertFixedSubnet,
  assertBakeableSpec,
  assertSubnetMatch,
  resolveVxlanBlock,
  // The company website: the curated cc_web role, driven from the controller.
  installCompanyWebsite,
  resolveDmzHost,
  readCcWebTree,
  buildCcWebVars,
  buildCcWebInventory,
  buildCcWebCollectPlaybook,
  buildCcWebArgv,
  compareWebFacts,
  gradeWebInstall,
  toVarsYaml,
  unsafeScalar,
  hasCompiledLab,
  CC_WEB_RUN_DIR,
  CC_WEB_DMZ_OCTET,
  CC_WEB_SSH_USER,
  classifyCapture,
  captureTargets,
  observedSubnetBases,
  stagingChallenge,
  stagingLaneConfig,
  controllerVmidFor,
  idsFromLane,
  verifyReportFromLane,
  findCloudInitDrive,
  // Injectable seam + the watcher, so the early-record property has a handle.
  defaultDeps,
  watchForStagingLane,
  // Vocabulary
  CONTROLLER_VMID_OFFSET,
  MODULE_KEY,
  SHUTDOWN_WAIT_MS,
  LANE_WATCH_INTERVAL_MS,
};
