/**
 * ============================================================================
 * CIAB Lane Provisioning — Track A, phase A5
 * ----------------------------------------------------------------------------
 * Thin profile/engagement-aware wrapper over src/utils/challenge-lane-deployer.js,
 * which is the shared implementation that produces a lane a student can actually
 * connect to. This file replaces ciab/utils/lane-deploy.js's private orchestrator
 * — the fourth copy of the clone-and-wire sequence, and the reason a CIAB lane's
 * console was dead on arrival.
 *
 * challenge-lane-deployer, NOT lane-deployer: CIAB deploys a `spec.vms[]` set,
 * which is exactly what deployChallengeLanes consumes. lane-deployer.deployLanes
 * deploys ONE catalog workstation per lane, and a five-asset profile cannot be
 * expressed in it at all.
 *
 * Everything hard already lives in the shared deployer, and A2 added the four
 * things a profile lane needs that a course lane does not:
 *
 *   pinAllVms      every single-homed spec VM gets a fixed lane address via a
 *                  MAC-keyed DHCP reservation, so the lane matches the addresses
 *                  its own generated scan report names (A4 emits the octets)
 *   dns_aliases    spec-level, so `ping web01` works inside the lane
 *   os_family NIC  e1000 for Windows guests, which otherwise never DHCP
 *   postDeploy     the per-lane hook this file uses to install the vuln app
 *
 * All four are OFF unless asked for. Passing them is this file's job.
 *
 * This file's only remaining responsibilities are CIAB context:
 *   - hold the operation mutex for a deploy group
 *   - turn spec.vms[].post_clone_scripts into the deployer's vulnScripts shape
 *   - install the LLM-generated vuln app through the postDeploy hook
 *   - mirror the deployer's results into ciab_profile_lane_jobs
 *
 * Keep it that way. If something here starts looking like deploy logic — a
 * clone, a Guacamole call, an iptables rule, a dnsmasq line — it belongs in the
 * shared deployer instead. A fifth copy of that sequence is exactly how this
 * plugin got broken the first time.
 * ============================================================================
 */

const { query } = require('./db');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const challengeLaneDeployer = require('../../../../../src/utils/challenge-lane-deployer');
const { installVulnAppOnVM } = require('./vuln-app-install');
const { ensureVulnImage } = require('./vuln-app-builder');

const MODULE_KEY = 'ciab';
const LOG = '[CIAB Lane]';

// ─── Progress keys ──────────────────────────────────────────────────────────
// The shared registry, not a private global. It carries the heartbeat and
// staleness fields the UI needs, and — because this app has one Node process and
// no job queue — it doubles as the only mutex available. CIAB's old private
// `global._ciabProfileLaneProgress` had neither, so nothing stopped two admins
// deploying the same profile at once.

/** One stable id per deploy group, so the admin UI can poll a single URL. */
function progressIdForGroup(groupId) {
  return `ciab-group-${groupId}`;
}

/** Per-lane key for a single-lane retry. Shares the group prefix so the mutex sees it. */
function progressIdForLane(groupId, laneId) {
  return `${progressIdForGroup(groupId)}-lane-${laneId}`;
}

/**
 * Every operation currently running against this deploy group.
 *
 * Mirrors cle/utils/lane-provision.js:courseOperationsInFlight — same registry,
 * same prefix trick, same reason. 'complete' entries linger for an hour so a
 * late poller can still read the outcome; they are finished work, not a
 * conflict.
 */
function groupOperationsInFlight(groupId) {
  const base = progressIdForGroup(groupId);
  const out = [];
  for (const progressId of laneDeployer.listProgressIds(base)) {
    const p = laneDeployer.readProgress(progressId);
    if (!p || p.phase === 'complete') continue;

    const suffix = progressId.slice(base.length);
    let scope = null;
    let laneId = null;
    if (suffix === '') scope = 'deploy';
    else if (suffix.startsWith('-lane-')) { scope = 'lane'; laneId = suffix.slice('-lane-'.length); }
    else continue;

    out.push({
      progressId, scope, laneId,
      phase: p.phase, phase_detail: p.phase_detail,
      completed: p.completed, total: p.total,
    });
  }
  return out;
}

/**
 * Refuse to start an operation that would collide with one already running on
 * this group.
 *
 * A group-scope deploy conflicts with ANYTHING: deployChallengeLanes allocates
 * VXLAN ids and inserts lane rows before any clone finishes, so a teardown or a
 * second deploy landing mid-flight enumerates half-built lanes and orphans them.
 * A single-lane retry conflicts with the group deploy and with itself, but not
 * with another lane's retry — two admins fixing two students is the normal case.
 *
 * CALL THIS IN THE SAME SYNCHRONOUS BLOCK AS THE initProgress() CLAIM, with
 * every await already done. A check, an await, then a claim leaves the
 * double-click window wide open.
 *
 * @throws {Error & {status:409}}
 */
function assertNoConflictingProfileOperation({ groupId, laneId = null, ignoreProgressId = null }) {
  const conflicts = groupOperationsInFlight(groupId).filter((op) => {
    if (op.progressId === ignoreProgressId) return false;
    if (laneId === null) return true;                 // group scope: everything conflicts
    return op.scope !== 'lane' || op.laneId === laneId;
  });
  if (conflicts.length === 0) return;

  const c = conflicts[0];
  const who = c.scope === 'deploy'
    ? 'A deploy on this group'
    : 'Another operation on this lane';
  const err = new Error(
    `${who} is still running (${c.completed}/${c.total}, ${c.phase_detail || c.phase}). ` +
    `Wait for it to finish — running both at once would leave machines behind with ` +
    `nothing pointing at them.`
  );
  err.status = 409;
  throw err;
}

// ─── Lane naming ────────────────────────────────────────────────────────────

// Longest sanitized group slug we will put in a lane name. The binding limit is
// the gateway LXC hostname: the shared deployer builds `${laneName}-gw` inside a
// 63-char budget minus 18 reserved for the `-b<16hex>` Tailscale claim secret, so
// laneName must stay <= 37. `ciab-` + slug + `-` + a 5-digit VXLAN id spends 11
// of those.
const MAX_SLUG_LEN = 26;

/** Lanes come out as `ciab-<group-slug>-<vxlanId>`. */
function laneNamePrefix(groupSlug) {
  const slug = String(groupSlug || '')
    .toLowerCase()
    .replace(/\s+/g, '')
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .substring(0, MAX_SLUG_LEN)
    .replace(/-$/, '');
  return slug ? `ciab-${slug}` : 'ciab';
}

// ─── The mapping that is easy to drop silently ──────────────────────────────

/**
 * spec.vms[].post_clone_scripts  →  deployChallengeLanes' vulnScripts shape.
 *
 * The synthesizer records which vuln_scripts each asset needs ON the VM entry;
 * the deployer wants a flat [{ vm_name, script_slug }] list. Nothing converts
 * between the two automatically, and the failure mode if this is forgotten is
 * the worst kind: the deploy still succeeds, the lanes still come up, and every
 * profile lane quietly loses its init-setup bootstrap and all per-service
 * planting — the SMB shares, the vulnerable services, the whole reason a real
 * nmap against the lane matches the paper scan report.
 */
function vulnScriptsFromSpec(spec) {
  const out = [];
  for (const vm of (spec && spec.vms) || []) {
    for (const slug of vm.post_clone_scripts || []) {
      out.push({ vm_name: vm.name, script_slug: slug });
    }
  }
  return out;
}

// ─── The vuln-app install, as a postDeploy hook ─────────────────────────────

/**
 * Build the per-lane hook that installs the LLM-generated vulnerable app.
 *
 * This is the one piece of per-lane work that is genuinely CIAB's and has no
 * equivalent on a course lane, which is exactly what the postDeploy hook exists
 * for. It runs after the vuln scripts and before flag planting.
 *
 * The hook is best-effort by contract: the shared deployer records a throw as
 * config.post_deploy_error and does not fail the lane. That is the right
 * trade — a lane with a working console and no web app is recoverable by
 * redeploying the app; a lane torn down because one Docker pull failed is not.
 * The error reaches the instructor rather than presenting as "the exercise
 * content just isn't there".
 */
function makeVulnAppPostDeploy(vulnAppInstall) {
  if (!vulnAppInstall || !vulnAppInstall.target_vm) return null;

  return async function installVulnAppForLane({ deployedVMs, logTag }) {
    // `name` is the SPEC name on a deployedVMs record (proxmox_name is the
    // clone name, which carries the student suffix) — and target_vm is a spec
    // name, so these match directly.
    const target = (deployedVMs || []).find(vm => vm.name === vulnAppInstall.target_vm);
    if (!target) {
      throw new Error(
        `vuln-app target '${vulnAppInstall.target_vm}' is not among this lane's machines ` +
        `(${(deployedVMs || []).map(v => v.name).join(', ') || 'none'})`
      );
    }
    const res = await installVulnAppOnVM({
      node: target.node,
      vmId: target.vm_id,
      vmName: target.name,
      vulnAppInstall,
      logTag,
    });
    if (res && res.success === false && !res.skipped) {
      throw new Error(res.error || 'vuln-app install failed');
    }
  };
}

// ─── ciab_profile_lane_jobs as a derived mirror ─────────────────────────────

/**
 * Record one lane's outcome in the CIAB-side job table.
 *
 * The job row is a MIRROR, not the source of truth. cybercore_lane is, and it
 * lives in a different database with no foreign key back here — so a stale row
 * must be cosmetic rather than something that drives a destructive action. That
 * is why this upserts on (group_id, lane_index) and never deletes.
 *
 * Best-effort on purpose: losing a mirror row must not fail a lane that
 * actually deployed.
 */
async function mirrorLaneJob({ groupId, laneId, vxlanId, laneIndex, status, node, errorMsg = null }) {
  try {
    await query(
      `INSERT INTO ciab_profile_lane_jobs
         (group_id, lane_id, vxlan_id, lane_index, status, target_node, error_msg, started_at, finished_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), NOW())
       ON CONFLICT (group_id, lane_index) DO UPDATE
         SET lane_id     = EXCLUDED.lane_id,
             vxlan_id    = EXCLUDED.vxlan_id,
             status      = EXCLUDED.status,
             target_node = EXCLUDED.target_node,
             error_msg   = EXCLUDED.error_msg,
             finished_at = NOW()`,
      [groupId, laneId, vxlanId, laneIndex, status, node || null, errorMsg]
    );
  } catch (err) {
    console.warn(`${LOG} Could not mirror job row for lane ${laneId}: ${err.message}`);
  }
}

// ─── Entry point ────────────────────────────────────────────────────────────

/**
 * Deploy one lane per student for a CIAB profile engagement.
 *
 * Does NOT allocate VXLAN ids, allocate gateway WAN addresses, or insert
 * cybercore_lane rows — deployChallengeLanes owns all three, and CIAB doing them
 * a second time is what W1-W7 were. The caller's job is to have a reservation
 * (getOrCreateProfileChallenge) and a set of student accounts
 * (provisionLaneStudents); everything after that is here.
 *
 * @param {object} a
 * @param {string} a.groupId            ciab_profile_lane_groups.id
 * @param {string} a.groupName
 * @param {string} a.groupSlug          from provisionLaneStudents
 * @param {object} a.challenge          { challenge_id, challenge_key, name, spec, subnet_scheme }
 * @param {Array}  a.students           [{ id, email, index }] from provisionLaneStudents
 * @param {boolean}[a.attackBoxes=true]
 * @param {object} [a.vulnAppInstall]   spec.vuln_app_install, or null
 * @param {Array}  [a.instructorEmails]
 * @returns {Promise<{progressId, provisioned, failed}>}
 */
async function provisionProfileLanes({
  groupId, groupName, groupSlug, challenge, students,
  attackBoxes = true, vulnAppInstall = null, instructorEmails = [],
}) {
  if (!groupId) throw new Error('provisionProfileLanes: groupId is required');
  if (!challenge) throw new Error('provisionProfileLanes: challenge is required');
  if (!Array.isArray(students) || students.length === 0) {
    return { progressId: null, provisioned: [], failed: [] };
  }

  const progressId = progressIdForGroup(groupId);

  // Claim and conflict-check in ONE synchronous block, every await already done.
  assertNoConflictingProfileOperation({ groupId, ignoreProgressId: progressId });
  laneDeployer.initProgress(progressId, groupName || groupId, students.length);

  const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});

  // Pre-build the vuln-app image ONCE for the batch. The orchestrator has
  // internet; the lane subnet does not, so each lane pulls the ready image over
  // the one iptables hole rather than building it. Returns its input unchanged
  // when Docker is unavailable or the build fails, so the on-VM path stays the
  // fallback.
  let resolvedVulnApp = vulnAppInstall;
  if (vulnAppInstall && vulnAppInstall.mode === 'docker') {
    resolvedVulnApp = await ensureVulnImage(vulnAppInstall, { logTag: `${LOG}[${groupName}]` })
      .catch(err => {
        console.warn(`${LOG} vuln-app image prebuild failed (on-VM fallback): ${err.message}`);
        return vulnAppInstall;
      });
  }

  const indexByUserId = new Map(students.map(s => [s.id, s.index]));

  const result = await challengeLaneDeployer.deployChallengeLanes({
    users: students.map(s => ({ id: s.id, email: s.email })),
    challenge,
    moduleKey: MODULE_KEY,
    attackBoxes,

    // A4's addressing contract. Without this the octets the synthesizer emitted
    // — and the generated scan report already names — are ignored, every guest
    // takes a random pool lease, and the paper is wrong about its own lane.
    pinAllVms: true,

    // Per-asset vuln planting. See vulnScriptsFromSpec for why forgetting this
    // is silent rather than loud.
    vulnScripts: vulnScriptsFromSpec(spec),

    postDeploy: makeVulnAppPostDeploy(resolvedVulnApp),

    // Batch-wide only: laneConfig is spread verbatim into every lane's config,
    // so nothing per-student belongs here. Student identity is already on the
    // lane row as user_id, and the lane index lives in the job mirror.
    laneConfig: {
      ciab: true,
      profile_lane_group: true,
      group_id: groupId,
    },
    namePrefix: laneNamePrefix(groupSlug),
    guacParent: 'ROOT',
    instructorEmails,
    description: `CIAB profile deploy: ${groupName || groupId}`,
    progressId,
    progressLabel: groupName || challenge.name || challenge.challenge_key,
  });

  // Mirror outcomes. Authoritative pass — the hook cannot run for a lane that
  // failed before it, and a failed lane still needs a row the UI can show.
  for (const lane of result.provisioned || []) {
    await mirrorLaneJob({
      groupId,
      laneId: lane.lane_id,
      vxlanId: lane.vxlan_id,
      laneIndex: indexByUserId.get(lane.user_id) || 0,
      status: 'active',
      node: lane.node,
    });
  }
  for (const f of result.failed || []) {
    await mirrorLaneJob({
      groupId,
      laneId: f.lane_id,
      vxlanId: f.vxlan_id || 0,
      laneIndex: indexByUserId.get(f.user_id) || 0,
      status: 'error',
      node: null,
      errorMsg: f.reason,
    });
  }

  const failedCount = (result.failed || []).length;
  const groupStatus = failedCount === 0 ? 'active'
    : (result.provisioned || []).length === 0 ? 'error'
      : 'partial';
  await query(
    `UPDATE ciab_profile_lane_groups SET status = $2, updated_at = NOW() WHERE id = $1`,
    [groupId, groupStatus]
  ).catch(err => console.warn(`${LOG} Could not update group status: ${err.message}`));

  return result;
}

/**
 * Re-deploy ONE failed lane.
 *
 * TEARS DOWN FIRST, THEN REDEPLOYS — and that ordering is the whole fix. The
 * path this replaces force-destroyed every VMID recorded on the job row (which
 * includes the gateway, written as the first entry) and then called a Phase-2-only
 * function whose first act is `POST .../lxc/<gatewayVmId>/status/start`. It was
 * starting a container it had just deleted, so retry could never succeed for any
 * lane whose deploy got far enough to record its VMIDs — which is every lane
 * worth retrying.
 *
 * The lane comes back with a NEW lane_id: teardownLanes deletes the row (that is
 * what frees the VXLAN id), and deployChallengeLanes inserts a fresh one. The job
 * mirror upserts on (group_id, lane_index), so the new id replaces the old under
 * the same student.
 *
 * @param {object} a
 * @param {string} a.laneId      the FAILED lane, destroyed by this call
 * @param {object} a.user        { id, email } — the student who owns it
 * @param {number} a.laneIndex   1-based, for the job mirror
 * @param {Array}  [a.extraVmIds] VMIDs from the job row, for machines whose lane
 *   config write never landed and which are therefore recorded nowhere else
 */
async function retryProfileLane({
  groupId, groupName, groupSlug, challenge, laneId, user, laneIndex,
  attackBoxes = true, vulnAppInstall = null, extraVmIds = [],
}) {
  if (!laneId) throw new Error('retryProfileLane: laneId is required');
  if (!user || !user.id) throw new Error('retryProfileLane: user is required');

  const progressId = progressIdForLane(groupId, laneId);
  assertNoConflictingProfileOperation({ groupId, laneId, ignoreProgressId: progressId });
  laneDeployer.initProgress(progressId, `${groupName || groupId} — retry`, 1);

  let torn;
  try {
    torn = await teardownProfileLanes([laneId], { extraVmIds });
  } catch (err) {
    laneDeployer.finishProgress(progressId);
    throw err;
  }

  // teardownLanes keeps the row when a machine refused to die. Redeploying on
  // top of that would clone a gateway over a container that is still running,
  // and the contested-VXLAN guard would then refuse to clean up either of them.
  if ((torn.lanes_kept_for_retry || 0) > 0) {
    laneDeployer.finishProgress(progressId);
    const err = new Error(
      `Cannot retry: the failed lane did not tear down cleanly (${torn.errors.join('; ')}). ` +
      `Something is still running, and deploying over it would leave two lanes on one VXLAN id.`
    );
    err.status = 409;
    throw err;
  }

  const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});

  let resolvedVulnApp = vulnAppInstall;
  if (vulnAppInstall && vulnAppInstall.mode === 'docker') {
    resolvedVulnApp = await ensureVulnImage(vulnAppInstall, { logTag: `${LOG}[retry]` })
      .catch(() => vulnAppInstall);
  }

  const result = await challengeLaneDeployer.deployChallengeLanes({
    users: [{ id: user.id, email: user.email }],
    challenge,
    moduleKey: MODULE_KEY,
    attackBoxes,
    pinAllVms: true,
    vulnScripts: vulnScriptsFromSpec(spec),
    postDeploy: makeVulnAppPostDeploy(resolvedVulnApp),
    laneConfig: { ciab: true, profile_lane_group: true, group_id: groupId },
    namePrefix: laneNamePrefix(groupSlug),
    guacParent: 'ROOT',
    description: `CIAB profile deploy: ${groupName || groupId} (retry)`,
    progressId,
    progressLabel: `${groupName || groupId} — retry`,
  });

  const fresh = (result.provisioned || [])[0];
  const failed = (result.failed || [])[0];
  await mirrorLaneJob({
    groupId,
    laneId: fresh ? fresh.lane_id : (failed && failed.lane_id) || laneId,
    vxlanId: fresh ? fresh.vxlan_id : 0,
    laneIndex,
    status: fresh ? 'active' : 'error',
    node: fresh ? fresh.node : null,
    errorMsg: failed ? failed.reason : null,
  });

  return result;
}

/**
 * Read the live progress for a group's deploy.
 *
 * Exists so route handlers never reach into the registry's internals, and so the
 * key format stays owned by this file.
 */
function readGroupProgress(groupId) {
  return laneDeployer.readProgress(progressIdForGroup(groupId));
}

/**
 * Tear down lanes for a deploy group.
 *
 * Delegates outright: teardownLanes is the ONLY path allowed to delete a
 * cybercore_lane row, because deleting one both frees its VXLAN id and discards
 * the only handle on its derived VMIDs. It refuses when anything survived, which
 * is what stops the next deploy cloning a gateway on top of a running container.
 */
async function teardownProfileLanes(laneIds, { extraVmIds = [] } = {}) {
  if (!Array.isArray(laneIds) || laneIds.length === 0) {
    return { destroyed: 0, lanes_kept_for_retry: 0, errors: [] };
  }
  return laneDeployer.teardownLanes(laneIds, { extraVmIds, purgeJanitors: true });
}

module.exports = {
  MODULE_KEY,
  provisionProfileLanes,
  retryProfileLane,
  teardownProfileLanes,
  readGroupProgress,
  progressIdForGroup,
  progressIdForLane,
  groupOperationsInFlight,
  assertNoConflictingProfileOperation,
  // Pure, so they are testable without a cluster.
  vulnScriptsFromSpec,
  laneNamePrefix,
  makeVulnAppPostDeploy,
  MAX_SLUG_LEN,
};
