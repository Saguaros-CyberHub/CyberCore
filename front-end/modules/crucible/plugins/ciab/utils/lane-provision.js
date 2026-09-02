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
 *   - reseed everything that must differ per student, through the same hook
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
const laneReseed = require('./lane-reseed');
// E3. chainPostDeploy is the composer; the sensor stamp is what makes the
// incident engine's target ladder hit rung 0 on the first run. Both are inert
// on an engagement with no telemetry: makeSensorStampPostDeploy returns null
// when the spec declares no sensor, and chainPostDeploy of one hook IS that
// hook, so an offensive lane composes to exactly what it composed to before.
const blueteamPostDeploy = require('./blueteam-postdeploy');
// E7. Where the CLIENT'S OWN benign floor comes from. floorForEngagement() is
// best-effort by design and returns null for every ordinary "there is no floor
// here" state — an offensive engagement, a client with no threat scenarios, an
// engagement whose scenario has not been chosen yet — which composes to no hook
// at all and leaves the lane exactly as it was before this phase.
const scenarioSource = require('./scenario-source');

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

// ─── The last place a golden-image lane can be caught being built wrong ─────

/**
 * Refuse to build a PRE-BAKED lane whose spec does not actually name the golden
 * templates it is supposed to clone.
 *
 * THIS IS A BOUNDARY CHECK, NOT A SECOND OPINION. profile-deploy resolves
 * bake.golden_vmids onto the spec and persists the result; three call paths then
 * read that persisted spec back — the first deploy, add-lanes and retry-lane —
 * and only the first of them is anywhere near the code that wrote it. If the
 * overlay is ever lost (a stored spec written before the client was baked, a
 * hand-edited challenge row, a reservation adopted from an older engagement),
 * every symptom is silent:
 *
 *   no template_vmid on a lab host   the clone falls back to the CATALOG image,
 *                                    so the lane comes up with a stock Windows
 *                                    box carrying none of the baked AD state,
 *                                    and the pre-baked heal then "repairs" a
 *                                    secure channel that was never established.
 *   no fixed_subnet                  every lane takes its own per-lane base
 *                                    while the golden images answer on the one
 *                                    they were baked on. applyPrebakedFixedSubnet
 *                                    catches the missing `int` today; `ext` is
 *                                    passed through as-is, so a spec pinning
 *                                    only half of it is silently half-right.
 *
 * All of them end with a lane that reports `active`. So this refuses at the last
 * moment before the first clone, which is the only place left that can.
 *
 * Pure and exported, so the refusal is assertable without a cluster.
 *
 * @param {object} spec  the challenge spec about to be deployed
 * @returns {object} the same spec
 * @throws {Error & {status:409, code:'CIAB_PREBAKED_TEMPLATES_UNRESOLVED'}}
 */
function assertPrebakedTemplatesResolved(spec) {
  const goad = (spec && spec.goad) || {};
  if (!goad.prebaked) return spec;

  const fixed = goad.fixed_subnet || {};
  const missingBase = ['int', 'ext']
    .filter((k) => !String(fixed[k] == null ? '' : fixed[k]).trim())
    .map((k) => `goad.fixed_subnet.${k}`);

  // The lab definition is what says which machines are INSIDE the forest, and
  // therefore which ones must have come from the capture. A spec VM outside it
  // (Kali, the DMZ pivot) legitimately still clones from the catalog.
  const labVms = (goad.lab && Array.isArray(goad.lab.vms)) ? goad.lab.vms : [];
  const byName = new Map(labVms.map((v) => [String(v.name || '').toLowerCase(), v]));
  const unresolved = [];
  for (const vm of (spec && Array.isArray(spec.vms) ? spec.vms : [])) {
    if (!byName.has(String(vm.name || '').toLowerCase())) continue;
    const vmid = Number(vm.template_vmid);
    if (!Number.isInteger(vmid) || vmid <= 0) unresolved.push(vm.name);
  }

  if (missingBase.length === 0 && labVms.length > 0 && unresolved.length === 0) return spec;

  const problems = [];
  if (labVms.length === 0) problems.push('it names no goad.lab.vms, so nothing says which machines the bake built');
  if (unresolved.length > 0) problems.push(`${unresolved.join(', ')} carr${unresolved.length === 1 ? 'ies' : 'y'} no template_vmid`);
  if (missingBase.length > 0) problems.push(`it declares no ${missingBase.join(' and no ')}`);

  const err = new Error(
    `Refusing to deploy: this challenge is marked pre-baked GOAD (spec.goad.prebaked) but `
    + `${problems.join('; ')}. A pre-baked lane clones golden images and runs no ansible, so a `
    + 'machine with no golden template clones the stock catalog image instead — it boots, it joins '
    + 'nothing, the heal reports it repaired, and the lane still reads active. Re-deploy this group '
    + "from the client's bake, or clear spec.goad.prebaked to provision the lab live."
  );
  err.status = 409;
  err.code = 'CIAB_PREBAKED_TEMPLATES_UNRESOLVED';
  throw err;
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

// ─── Per-lane reseed, on the same hook ─────────────────────────────────

/**
 * Compose the two pieces of per-lane work CIAB owns into the ONE postDeploy
 * function the deployer accepts.
 *
 * ORDER IS LOAD-BEARING. The vuln app is installed first because the reseed
 * writes the lane's flag, its pivot credential and its seeded record ids INTO
 * that app's directory — reseeding before the install would have the installer
 * overwrite every one of them.
 *
 * A FAILED INSTALL DOES NOT SKIP THE RESEED. Its error is held and rethrown at
 * the end, so config.post_deploy_error keeps exactly the meaning it has today,
 * but the reseed still runs in between. That matters: the SSH host keys, the
 * machine-id and above all the AD-side credential are per-student values that
 * have nothing to do with whether a Docker pull succeeded, and leaving them at
 * the golden image's baked values is the defect this whole design exists to
 * remove.
 *
 * The reseed hook never throws — see lane-reseed.reseedLane — so it can never
 * be the reason a lane that otherwise deployed is reported as failed.
 */
function makeProfilePostDeploy({ vulnAppInstall, reseedHook }) {
  const vulnHook = makeVulnAppPostDeploy(vulnAppInstall);
  if (!vulnHook && !reseedHook) return null;

  return async function profilePostDeploy(hookArgs) {
    let vulnErr = null;
    if (vulnHook) {
      try {
        await vulnHook(hookArgs);
      } catch (err) {
        vulnErr = err;
      }
    }
    if (reseedHook) await reseedHook(hookArgs);
    if (vulnErr) throw vulnErr;
  };
}

/**
 * Re-apply the reseed records once deployChallengeLanes has finished.
 *
 * NOT REDUNDANT WITH THE WRITE reseedLane ALREADY DID. challenge-lane-deployer
 * builds each lane's active config from the batch-wide `laneConfig` object and
 * writes it WHOLE (`config = $2::jsonb`) in its final step — which runs AFTER
 * the postDeploy hook. Anything the hook merged into config is therefore gone
 * by the time the deploy returns. This is the pass that makes the reseed
 * outcome, and the verification result on it, actually reach the instructor.
 *
 * Best-effort per lane: losing the record must not fail a lane that deployed.
 */
async function applyReseedRecords(records) {
  for (const [laneId, record] of (records || new Map())) {
    await laneReseed.recordReseedOnLane(laneId, record).catch((err) => {
      console.warn(`${LOG} Could not record reseed on lane ${laneId}: ${err.message}`);
    });
  }
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
 * @param {string} [a.engagementId]     E3: stamped on every lane's config
 * @param {string} [a.profileId]        E3: stamped on every lane's config
 * @returns {Promise<{progressId, provisioned, failed}>}
 */
async function provisionProfileLanes({
  groupId, groupName, groupSlug, challenge, students,
  attackBoxes = true, vulnAppInstall = null, instructorEmails = [],
  // E3. Both are written onto every lane's config and nowhere else. See the
  // laneConfig block below for why they are what lets the incident engine find
  // a CiAB lane at all.
  engagementId = null, profileId = null,
}) {
  if (!groupId) throw new Error('provisionProfileLanes: groupId is required');
  if (!challenge) throw new Error('provisionProfileLanes: challenge is required');
  if (!Array.isArray(students) || students.length === 0) {
    return { progressId: null, provisioned: [], failed: [] };
  }

  const progressId = progressIdForGroup(groupId);
  const spec = typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {});

  // BEFORE the mutex claim, so a refusal leaves no progress entry behind that a
  // later deploy would have to wait out. See assertPrebakedTemplatesResolved for
  // why a golden-image lane that is built from the wrong templates is silent.
  assertPrebakedTemplatesResolved(spec);

  // Claim and conflict-check in ONE synchronous block, every await already done.
  assertNoConflictingProfileOperation({ groupId, ignoreProgressId: progressId });
  laneDeployer.initProgress(progressId, groupName || groupId, students.length);

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

  // Per-lane reseed. Everything a student is supposed to DISCOVER has to be
  // written after the clone, because a golden image is identical by definition
  // — see lane-reseed.js. `records` is drained after the deploy returns.
  const reseed = laneReseed.makeReseedPostDeploy({ logTag: `${LOG}[${groupName || groupId}]` });

  // E3. Same drain-afterwards shape as the reseed above, and for the same
  // reason: the deployer writes each lane's config WHOLE after the hook runs,
  // so a stamp made inside the hook does not survive. `records` is drained
  // below, once the deploy has returned.
  const sensorStampRecords = new Map();
  const sensorStamp = blueteamPostDeploy.makeSensorStampPostDeploy(spec, {
    records: sensorStampRecords,
    logTag: `${LOG}[${groupName || groupId}]`,
  });

  // ── E7: THE FLOOR SWAP ────────────────────────────────────────────────────
  //
  // The baked sensor image ships a GENERIC benign floor — web-01, db-01,
  // ws-042. A CiAB client's estate is DC01, FILE01, HMI-01. Leave the generic
  // floor in place and every event the incident emits names a machine ordinary
  // traffic never mentions, so one terms aggregation on `loggen.source.host` in
  // Discover ends the exercise — and every part of it reviews as working.
  //
  // Compiled ONCE for the batch, not per lane: the floor describes the CLIENT,
  // so it is identical on every environment of an engagement.
  //
  // Awaited BEFORE the deploy rather than inside the hook, so a client profile
  // that cannot produce a floor is one log line here instead of one per lane.
  const clientFloor = await scenarioSource.floorForEngagement(engagementId, {
    logTag: `${LOG}[${groupName || groupId}]`,
  });
  const floorSwap = blueteamPostDeploy.makeFloorSwapPostDeploy(spec, {
    floor: clientFloor ? clientFloor.floor : null,
    logTag: `${LOG}[${groupName || groupId}]`,
  });
  if (clientFloor) {
    console.log(`${LOG}[${groupName || groupId}] publishing the client's own benign floor `
      + `(scenario ${clientFloor.scenarioId}) onto every sensor`);
  }

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

    // CHAINED, not merged into makeProfilePostDeploy. The vuln-app install is a
    // Docker pull over the lane's one iptables hole and fails for reasons that
    // have nothing to do with telemetry; chainPostDeploy runs each function in
    // its own try, so a throw there cannot skip the sensor stamp. With no
    // sensor in the spec the second entry is null and this IS the first hook.
    postDeploy: blueteamPostDeploy.chainPostDeploy(
      makeProfilePostDeploy({
        vulnAppInstall: resolvedVulnApp,
        reseedHook: reseed.hook,
      }),
      sensorStamp,
      // AFTER the stamp, and that ordering is deliberate rather than
      // incidental: chainPostDeploy runs every hook in its own try, so the
      // order does not decide whether one runs — but the stamp is the cheap
      // one-statement write that makes the environment findable at all, and it
      // should land before a 30KB guest exec that can take a while.
      floorSwap,
    ),

    // Batch-wide only: laneConfig is spread verbatim into every lane's config,
    // so nothing per-student belongs here. Student identity is already on the
    // lane row as user_id, and the lane index lives in the job mirror.
    laneConfig: {
      ciab: true,
      profile_lane_group: true,
      group_id: groupId,
      // ── E3: how anything outside this plugin FINDS a CiAB lane. ──────────
      //
      // The incident engine discovers a scope's lanes by querying
      // cybercore_lane.config: a course lane is `config->>'course_id' = $1`,
      // and a CiAB lane is `config->>'engagement_id' = $1 AND
      // config->>'ciab' = 'true'`. Without these two keys the second arm
      // matches nothing, and a defensive engagement deploys a sensor and a
      // SIEM that no run can ever be aimed at.
      //
      // NO ALLOWLIST EDIT IS NEEDED, and that is worth stating because there IS
      // an allowlist and it is easy to assume this must be in it.
      // LANE_CONFIG_PASSTHROUGH_KEYS belongs to lane-deployer.js's WORKSTATION
      // path; challenge-lane-deployer spreads `laneConfig` VERBATIM into the
      // active config it writes. These keys arrive intact with no change on
      // that side.
      //
      // Both are null on a group deployed before engagements existed, which is
      // exactly right: `config->>'engagement_id'` is then SQL NULL and the
      // discovery query does not match it, rather than matching it wrongly.
      engagement_id: engagementId || null,
      profile_id: profileId || null,
    },
    namePrefix: laneNamePrefix(groupSlug),
    guacParent: 'ROOT',
    instructorEmails,
    description: `CIAB profile deploy: ${groupName || groupId}`,
    progressId,
    progressLabel: groupName || challenge.name || challenge.challenge_key,
  });

  // The deployer has now written each lane's config whole, so this is the first
  // moment a reseed record can survive being written. See applyReseedRecords.
  await applyReseedRecords(reseed.records);
  // Same moment, same reason. See makeSensorStampPostDeploy's header.
  await blueteamPostDeploy.applySensorStamps(sensorStampRecords);

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
  // E3. A retry produces a NEW lane row, so it has to re-state everything the
  // first deploy stamped on the old one. Omitting them here would leave exactly
  // one lane in a class invisible to the incident engine — the one that was
  // already having a bad day, which is the hardest kind of gap to notice.
  engagementId = null, profileId = null,
}) {
  if (!laneId) throw new Error('retryProfileLane: laneId is required');
  if (!user || !user.id) throw new Error('retryProfileLane: user is required');

  // BEFORE the teardown, not after it. A retry DESTROYS the lane first, so a
  // refusal raised any later would leave the student with no lane at all — and
  // this route is the one most likely to be reached with a stale stored spec,
  // because it rebuilds its challenge object from the reservation row days after
  // the deploy that wrote it.
  assertPrebakedTemplatesResolved(
    typeof challenge.spec === 'string' ? JSON.parse(challenge.spec) : (challenge.spec || {}));

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

  // A retry is a fresh lane row with a fresh VXLAN id, so it needs the same
  // per-lane reseed the first deploy did — the rebuilt machines are clones of
  // the same golden images and carry the same baked values.
  const reseed = laneReseed.makeReseedPostDeploy({ logTag: `${LOG}[retry]` });
  const sensorStampRecords = new Map();
  const sensorStamp = blueteamPostDeploy.makeSensorStampPostDeploy(spec, {
    records: sensorStampRecords,
    logTag: `${LOG}[retry]`,
  });

  // E7. A retried environment is a fresh clone of the same golden image, so it
  // comes back carrying the GENERIC baked floor. Rebuilding one lane without
  // this would put a single environment on a different vocabulary from the rest
  // of the engagement — and the student sitting at it would be the only one who
  // could end the hunt with one aggregation.
  const clientFloor = await scenarioSource.floorForEngagement(engagementId, {
    logTag: `${LOG}[retry]`,
  });
  const floorSwap = blueteamPostDeploy.makeFloorSwapPostDeploy(spec, {
    floor: clientFloor ? clientFloor.floor : null,
    logTag: `${LOG}[retry]`,
  });

  const result = await challengeLaneDeployer.deployChallengeLanes({
    users: [{ id: user.id, email: user.email }],
    challenge,
    moduleKey: MODULE_KEY,
    attackBoxes,
    pinAllVms: true,
    vulnScripts: vulnScriptsFromSpec(spec),
    postDeploy: blueteamPostDeploy.chainPostDeploy(
      makeProfilePostDeploy({
        vulnAppInstall: resolvedVulnApp,
        reseedHook: reseed.hook,
      }),
      sensorStamp,
      floorSwap,
    ),
    // Must stay in step with provisionProfileLanes' laneConfig, key for key.
    // A retried lane that is missing engagement_id is a lane the incident
    // engine's discovery query does not return.
    laneConfig: {
      ciab: true,
      profile_lane_group: true,
      group_id: groupId,
      engagement_id: engagementId || null,
      profile_id: profileId || null,
    },
    namePrefix: laneNamePrefix(groupSlug),
    guacParent: 'ROOT',
    description: `CIAB profile deploy: ${groupName || groupId} (retry)`,
    progressId,
    progressLabel: `${groupName || groupId} — retry`,
  });

  await applyReseedRecords(reseed.records);
  await blueteamPostDeploy.applySensorStamps(sensorStampRecords);

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
  assertPrebakedTemplatesResolved,
  vulnScriptsFromSpec,
  laneNamePrefix,
  makeVulnAppPostDeploy,
  makeProfilePostDeploy,
  applyReseedRecords,
  MAX_SLUG_LEN,
};
