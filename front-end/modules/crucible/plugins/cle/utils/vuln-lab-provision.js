/**
 * ============================================================================
 * CLE Vulnerable-Lab Provisioning
 * ----------------------------------------------------------------------------
 * Deploys the vulnerable application an instructor assigns to students, in one
 * of two modes:
 *
 *   'lane'   — a full lab lane per student: gateway + the challenge's VMs + a
 *              Kali attack box, on a VXLAN drawn from THE CHALLENGE'S OWN
 *              reserved block. This is byte-for-byte the admin Group Deploy
 *              sequence (utils/challenge-lane-deployer.js), which is the only
 *              path that works for a v3/GOAD challenge — the internal VNets at
 *              (tag + 4000000) exist only in the challenge's own reservation,
 *              never in the course's v2 workstation block.
 *
 *   'attach' — graft the challenge's VMs onto the lane the student already has
 *              in this course, via utils/attached-modules.js. Cheap (no extra
 *              VXLAN, no second Kali) but only legal for a single-VNet,
 *              non-GOAD challenge that declares spec.attachable.
 *
 * Like lane-provision.js, this file is COURSE CONTEXT ONLY. The deploy logic
 * lives in the shared utils; if something here starts looking like Proxmox
 * orchestration, it belongs there instead.
 * ============================================================================
 */

const { cybercoreQuery, cybercorePool } = require('../../../../../src/utils/cybercore-db');
const {
  proxmoxAPI, waitForTask, forceDestroyVM, waitForVmidsGone,
} = require('../../../../../src/utils/proxmox');
const { getDefaultTemplateNode } = require('../../../../../src/utils/site-config');
const { resolveLaneNetworking } = require('../../../../../src/utils/lane-networking');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const challengeLaneDeployer = require('../../../../../src/utils/challenge-lane-deployer');
const attachedModules = require('../../../../../src/utils/attached-modules');
const flagManager = require('../../../../../src/utils/flag-manager');
const laneProvision = require('./lane-provision');

const LOG = '[CLE VulnLab]';

const MODES = ['lane', 'attach'];

/**
 * Read-modify-write cybercore_lane.config under a real row lock.
 *
 * Must run on a PINNED connection. `cybercoreQuery` checks a connection out of
 * the pool per call, so issuing BEGIN / SELECT … FOR UPDATE / UPDATE / COMMIT
 * through it gives four unrelated backends: the lock is taken and released
 * inside its own implicit transaction, the UPDATE autocommits, COMMIT lands on a
 * connection with nothing open, and the one that ran BEGIN goes back to the pool
 * mid-transaction to be inherited by whatever query grabs it next.
 *
 * Two attaches (or an attach racing a detach) on the same lane would then both
 * read the same attached_modules array and the second write would drop the
 * first — leaving that module's VMs running with nothing referencing them, since
 * teardownLab finds instances only through this array.
 *
 * @param {string}   laneId
 * @param {Function} mutate  (config) => config — must return the new config
 */
async function withLaneConfig(laneId, mutate) {
  const client = await cybercorePool.connect();
  try {
    await client.query('BEGIN');
    const cur = await client.query(
      `SELECT config FROM cybercore_lane WHERE lane_id = $1 FOR UPDATE`,
      [laneId]
    );
    if (cur.rows.length === 0) {
      await client.query('ROLLBACK');
      const err = new Error(`Lane ${laneId} no longer exists`);
      err.status = 409;
      throw err;
    }
    const config = typeof cur.rows[0].config === 'string'
      ? JSON.parse(cur.rows[0].config || '{}')
      : (cur.rows[0].config || {});

    const next = mutate(config);
    await client.query(
      `UPDATE cybercore_lane SET config = $2::jsonb, updated_at = NOW() WHERE lane_id = $1`,
      [laneId, JSON.stringify(next)]
    );
    await client.query('COMMIT');
    return next;
  } catch (err) {
    await client.query('ROLLBACK').catch(() => {});
    throw err;
  } finally {
    client.release();
  }
}

/** Progress key for one lab deploy, so the UI can poll a stable id. */
function progressIdForLab(materialId) {
  return `cle-lab-${materialId}`;
}

/**
 * Progress key for an operation on ONE student's copy of a lab.
 *
 * Separate from the lab-wide key so two students can be redeployed at once
 * without clobbering each other's progress — initProgress replaces the entry
 * wholesale, so a shared key means the second start erases the first's state and
 * the first poller reports the second's numbers.
 *
 * materialId is a UUID, so `cle-lab-<materialId>` is an unambiguous prefix of
 * every key belonging to this lab: the next character is either '-' or the end
 * of the string. That is what makes listProgressIds() below safe.
 */
function progressIdForLabStudent(materialId, userId) {
  return `cle-lab-${materialId}-${userId}`;
}

/** Live progress for a lab deploy (or one student's), or null once it aged out. */
function getLabProgress(materialId, userId = null) {
  return laneDeployer.readProgress(
    userId ? progressIdForLabStudent(materialId, userId) : progressIdForLab(materialId)
  );
}

/**
 * Every operation currently in flight against this lab — the lab-wide one and
 * any per-student ones.
 *
 * The owning user is derived by SLICING THE KEY, not read off the entry: the
 * deploy paths call initProgress themselves and replace the object, so any field
 * we stashed on it would not survive the handover from teardown to deploy.
 *
 * @returns {Array<{progressId, userId:string|null, phase, phase_detail, completed, total}>}
 */
function labOperationsInFlight(materialId) {
  const groupKey = progressIdForLab(materialId);
  const out = [];
  for (const progressId of laneDeployer.listProgressIds(`${groupKey}`)) {
    const p = laneDeployer.readProgress(progressId);
    // 'complete' entries linger for an hour so a late poller can still read the
    // outcome; they are finished work, not a conflict.
    if (!p || p.phase === 'complete') continue;
    const suffix = progressId.slice(groupKey.length);
    out.push({
      progressId,
      userId: suffix.startsWith('-') ? suffix.slice(1) : null,
      phase: p.phase,
      phase_detail: p.phase_detail,
      completed: p.completed,
      total: p.total,
    });
  }
  return out;
}

/**
 * Refuse to start an operation that would collide with one already running.
 *
 * The registry is the only mutex available — this app has no job queue, and
 * progress lives in an in-process global. It works because there is exactly one
 * Node process.
 *
 * Scoping rules:
 *   group scope (userId null) — conflicts with ANYTHING under this lab. Tearing
 *     down the whole lab while one student is being rebuilt would snapshot the
 *     lane rows mid-flight and leave the machines the deploy is still cloning
 *     with nothing pointing at them.
 *   student scope — conflicts with the lab-wide entry, or this student's own.
 *     Another student's redeploy is independent and must not block.
 *
 * @param {string}  a.ignoreProgressId  the claim the caller just took for itself
 * @throws {Error & {status:409}}
 */
function assertNoConflictingLabOperation({ materialId, userId = null, ignoreProgressId = null }) {
  const conflicts = labOperationsInFlight(materialId).filter((op) => {
    if (op.progressId === ignoreProgressId) return false;
    if (userId === null) return true;          // group scope: everything conflicts
    return op.userId === null || op.userId === userId;
  });
  if (conflicts.length === 0) return;

  const c = conflicts[0];
  const who = c.userId ? 'one student of this lab' : 'this lab';
  const err = new Error(
    `Another operation on ${who} is still running (${c.completed}/${c.total}, ${c.phase_detail || c.phase}). ` +
    `Wait for it to finish — running both at once would leave machines behind with nothing pointing at them.`
  );
  err.status = 409;
  throw err;
}

/**
 * waitForVmidsGone now lives in src/utils/proxmox.js and is imported above.
 *
 * It moved because lane-deployer needs it for the in-place workstation rebuild
 * and src/utils must never require a plugin. The single call site in this file
 * (teardownLabScoped) is unchanged. It was never on this module's exports, so
 * nothing outside this file is affected.
 *
 * The reason it exists is easy to lose in a move, so it is worth restating
 * here: Proxmox DELETE is asynchronous, and an attach-mode redeploy re-attaches
 * into the slots it just freed — findFreeSlots hands them back immediately, so
 * vmidForSlot yields exactly the ids still being destroyed and the clone fails
 * with "VM already exists".
 */

/**
 * Load a deployable vulnerable challenge by id. Rejects the per-course network
 * reservations (spec.cle = true) — those exist only to own a VXLAN block and
 * have no VMs.
 */
async function loadChallenge(challengeId) {
  const r = await cybercoreQuery(
    `SELECT challenge_id, challenge_key, name, description, difficulty,
            spec, subnet_scheme, module_key, status
       FROM crucible_challenge
      WHERE challenge_id = $1
        AND status = 'active'
        AND spec->>'cle' IS DISTINCT FROM 'true'`,
    [challengeId]
  );
  if (r.rows.length === 0) {
    const err = new Error('Environment template not found, not active, or not deployable');
    err.status = 404;
    throw err;
  }
  const row = r.rows[0];
  row.spec = challengeLaneDeployer.parseSpec(row.spec);
  return row;
}

/**
 * Describe what a challenge can and cannot do, so the picker and the deploy
 * endpoint agree instead of the instructor finding out after clicking Deploy.
 */
function describeChallenge(challenge) {
  const spec = challenge.spec || {};
  const vms = challengeLaneDeployer.resolveSpecVms(spec, challenge.challenge_key);
  const subnetScheme = challenge.subnet_scheme || 'v1';
  const goadEnabled = !!spec.goad?.enabled;

  const attachBlockers = [];
  if (spec.attachable !== true) attachBlockers.push('the environment does not declare spec.attachable');
  if (subnetScheme === 'v3') attachBlockers.push('v3 environments need their own segmented gateway (ext0/int0)');
  if (goadEnabled) attachBlockers.push('GOAD environments provision Active Directory across the whole lane');

  const laneBlockers = [];
  if (vms.length === 0) laneBlockers.push('the environment declares no VMs');
  if (!spec.vxlan_block?.start || !spec.vxlan_block?.end) {
    laneBlockers.push('the environment has no reserved VXLAN block — recreate it via Admin → Environment Templates');
  }
  // Two VMs sharing a vm_offset clone to the same VMID; catching it here means
  // the picker greys the challenge out instead of the deploy dying mid-lane.
  const collision = challengeLaneDeployer.findVmOffsetCollision(vms);
  if (collision) laneBlockers.push(collision);

  // Not a blocker — the lane still deploys — but a GOAD host whose name doesn't
  // match the lab definition lands on the wrong network segment with no reserved
  // IP and no domain join, which the instructor would otherwise only discover
  // when a student says the box is unreachable.
  const goadMismatch = challengeLaneDeployer.findGoadHostMismatch(spec, vms);

  // Which machine the environment's author designated as the student console,
  // and whether it already ships an attacker box. Both feed the deploy modal:
  // the first pre-selects its console picker, the second stops an instructor
  // adding a second Kali onto <ext>.50 where the first one already sits.
  const consoleVm = vms.find((v) => v.console_role === 'primary');
  const hasSpecAttacker = vms.some((v) => String(v.role || '').toLowerCase() === 'attacker');

  return {
    challenge_id:   challenge.challenge_id,
    challenge_key:  challenge.challenge_key,
    name:           challenge.name,
    subnet_scheme:  subnetScheme,
    vm_count:       vms.length,
    vxlan_block:    spec.vxlan_block || null,
    goad_enabled:   goadEnabled,
    goad_prebaked:  !!spec.goad?.prebaked,
    attachable:     spec.attachable === true,
    default_console_vm: consoleVm ? consoleVm.name : null,
    has_spec_attacker:  hasSpecAttacker,
    can_deploy_lane:   laneBlockers.length === 0,
    can_attach:        attachBlockers.length === 0,
    lane_blockers:     laneBlockers,
    attach_blockers:   attachBlockers,
    // Deployable, but something about it will not behave as intended.
    warnings: [
      ...(goadMismatch ? [goadMismatch] : []),
      ...(hasSpecAttacker ? [
        'This environment already declares an attacker box — adding a Kali attack ' +
        'box as well puts two machines on <ext>.50 and dnsmasq will refuse to start.',
      ] : []),
    ],
  };
}

/**
 * How many more lanes a reserved VXLAN block can still hold. Asks the same
 * allocator the deploy uses, so the number the picker shows and the number the
 * deploy gets cannot disagree.
 *
 * @param {{start:number,end:number}|null} block  spec.vxlan_block
 */
async function countFreeLanes(block) {
  if (!block?.start || !block?.end) return 0;
  const size = block.end - block.start + 1;
  const free = await laneDeployer.allocateVxlanIds(block, size);
  return free.length;
}

/**
 * The active WORKSTATION lane each student holds in this course — the lane
 * 'attach' mode grafts onto.
 *
 * `config.material_id IS NULL` is load-bearing. Vulnerable-lab lanes also carry
 * config.course_id (every CLE read path keys on it), so without this filter a
 * student who already has one lab could get the next lab attached to that lab's
 * lane instead of their workstation — putting the target on the wrong network,
 * consuming that lane's attached-module slots, and tying its lifetime to the
 * wrong assignment.
 */
async function findCourseLanes(userIds, courseId) {
  if (!userIds.length) return {};
  const r = await cybercoreQuery(
    // gateway_wan_ip is read back, never re-derived — attachLabToLane resolves
    // this lane's networking from it, and the old derivation was not unique.
    `SELECT lane_id, user_id, vxlan_id, name, status, config, module_key,
            host(gateway_wan_ip) AS gateway_wan_ip
       FROM cybercore_lane
      WHERE user_id = ANY($1::uuid[])
        AND config->>'course_id' = $2
        AND config->>'material_id' IS NULL
        AND status = 'active'
      ORDER BY created_at DESC`,
    [userIds, courseId]
  );
  const byUser = {};
  for (const row of r.rows) {
    if (!byUser[row.user_id]) byUser[row.user_id] = row;
  }
  return byUser;
}

// ── mode: lane ───────────────────────────────────────────────────────────────

/**
 * Deploy a dedicated lab lane per student on the challenge's own VXLAN block.
 * Returns whatever deployChallengeLanes returns.
 */
async function deployLabLanes({
  course, challenge, students, materialId, instructorEmails, progressId, flagSeeds,
  attackBoxes = true, consoleVm = null, extraWorkstations = [],
}) {
  return challengeLaneDeployer.deployChallengeLanes({
    users: students.map(s => ({ id: s.id, email: s.email })),
    challenge,
    moduleKey: challenge.module_key || laneProvision.MODULE_KEY,
    // Was hardcoded `true`. Now the instructor's choice, still defaulting to
    // true everywhere it is not sent.
    attackBoxes,
    consoleVm,
    extraWorkstations,
    // config.course_id is how EVERY CLE read path finds these lanes again —
    // the VM list, the flag board, teardown. material_id ties them to the
    // specific lab assignment so one course can run several at once.
    laneConfig: {
      cle: true,
      course_id: course.course_id,
      course_name: course.course_name,
      material_id: materialId,
    },
    // Lanes come out as `cle-<course-code>-<vxlanId>`, matching the workstation
    // path's naming so both kinds of lane read the same way in Proxmox.
    namePrefix: laneProvision.laneNamePrefix(course.code),
    guacParent: 'ROOT',
    instructorEmails,
    description: `CLE course: ${course.course_name || course.course_id}`,
    progressId: progressId || progressIdForLab(materialId),
    progressLabel: `${challenge.name} — ${course.course_name || course.code || 'course'}`,
    // Replays the previous lane's flag values and captures, when this is a
    // rebuild rather than a first deploy. Null on the normal path.
    flagSeeds,
  });
}

// ── mode: attach ─────────────────────────────────────────────────────────────

/**
 * Graft the challenge onto one student's existing course lane. Mirrors
 * POST /api/admin/lanes/:laneId/modules, including the FOR UPDATE transaction
 * that appends to config.attached_modules — a plain read-modify-write loses
 * instances when two attaches land on the same lane at once.
 */
async function attachLabToLane({ lane, challenge, materialId, moduleKey }) {
  const laneConfig = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
  const laneSubnetScheme = laneConfig.subnet_scheme
    || (laneConfig.lane_subnet_base?.startsWith('10.') ? 'v2' : 'v1');
  const laneModule = lane.module_key || laneConfig.module || moduleKey;

  const wanIp = lane.gateway_wan_ip || laneConfig.gateway_wan_ip;
  if (!wanIp && laneSubnetScheme !== 'v1') {
    throw new Error(
      `Lane ${lane.lane_id} has no recorded gateway WAN address. Run migration ` +
      `033_lane_wan_ip.sql to backfill it — re-deriving it here would name a different ` +
      `lane's gateway.`
    );
  }
  const net = resolveLaneNetworking(laneSubnetScheme, laneModule, lane.vxlan_id, { wanIp });
  const laneSubnetBase = (net.lanExt || net.lan).base3;

  const vnets = await proxmoxAPI('GET', '/api2/json/cluster/sdn/vnets');
  const vnet = (vnets || []).find(v => v.tag === lane.vxlan_id);
  if (!vnet) {
    throw new Error(`No VNet found with tag ${lane.vxlan_id} in Proxmox SDN`);
  }

  const bestNode = laneConfig.node;
  if (!bestNode) throw new Error('Lane config is missing `node` — cannot place attached VMs');

  // The slots this attach will consume. attachModuleToLane computes the same set
  // internally; recomputing here lets us clean up after a partial failure, which
  // it cannot do itself — it throws mid-loop with VMs already cloned and no
  // instance record ever persisted. Those VMs would then be invisible to every
  // teardown path, AND their slots would look free to the next attach, whose
  // clone would collide on the same VMID.
  const specVmCount = (challenge.spec.vms || []).length;
  const claimedSlots = attachedModules.findFreeSlots(laneConfig.attached_modules, specVmCount);

  let instance;
  try {
    instance = await attachedModules.attachModuleToLane({
      lane,
      laneConfig,
      challenge,
      spec: challenge.spec,
      module: laneModule,
      laneSubnetBase,
      vnetName: vnet.vnet,
      bestNode,
      templateNode: challenge.spec.template_node || getDefaultTemplateNode(),
      gatewayVmId: laneConfig.gateway_vm_id || laneConfig.gateway_vmid || (100000 + lane.vxlan_id),
      proxmoxAPI,
      waitForTask,
    });
  } catch (attachErr) {
    for (const slot of claimedSlots) {
      const vmid = attachedModules.vmidForSlot(slot, lane.vxlan_id);
      try {
        const destroyed = await forceDestroyVM(vmid, 'qemu', bestNode);
        if (destroyed) console.log(`${LOG} Cleaned up ${vmid} after a failed attach on lane ${lane.lane_id}`);
      } catch (e) {
        console.warn(`${LOG} Could not clean up ${vmid} after a failed attach: ${e.message}`);
      }
    }
    throw attachErr;
  }
  instance.material_id = materialId;

  await withLaneConfig(lane.lane_id, (cfg) => ({
    ...cfg,
    attached_modules: [...(Array.isArray(cfg.attached_modules) ? cfg.attached_modules : []), instance],
  }));

  return instance;
}

/**
 * Attach the challenge to every named student's existing lane, one at a time so
 * two attaches never race for the same slot on the same lane.
 */
async function attachLabToStudents({ course, challenge, students, materialId, progressId: progressIdOverride }) {
  const progressId = progressIdOverride || progressIdForLab(materialId);
  const progress = laneDeployer.initProgress(
    progressId,
    `${challenge.name} — ${course.course_name || course.code || 'course'}`,
    students.length
  );
  laneDeployer.setPhase(progress, 'deploying', `Attaching ${challenge.name} to ${students.length} lane(s)`);

  const lanesByUser = await findCourseLanes(students.map(s => s.id), course.course_id);
  const provisioned = [];
  const failed = [];

  for (const student of students) {
    const lane = lanesByUser[student.id];
    if (!lane) {
      failed.push({
        user_id: student.id, user_email: student.email,
        reason: 'Student has no active workstation lane in this course — provision one first, or deploy in "lane" mode',
      });
      // Still count it, or the progress bar never reaches total and the UI polls
      // forever waiting for a lane that was never going to be attached.
      if (progress) {
        progress.completed++;
        progress.failed++;
        progress.phase_detail = `Attaching: ${progress.completed}/${students.length} complete`;
      }
      continue;
    }
    if (progress) {
      progress.lanes[lane.lane_id] = {
        user: student.email, student: student.email, vxlan: lane.vxlan_id,
        node: null, status: 'attaching', _startedAt: Date.now(),
      };
    }
    try {
      const instance = await attachLabToLane({
        lane, challenge, materialId, moduleKey: challenge.module_key || laneProvision.MODULE_KEY,
      });
      provisioned.push({
        lane_id: lane.lane_id,
        user_id: student.id,
        user_email: student.email,
        vxlan_id: lane.vxlan_id,
        module_instance_id: instance.module_instance_id,
        vms: instance.vms,
      });
      if (progress) {
        progress.lanes[lane.lane_id].status = 'active';
        progress.succeeded++;
      }
      console.log(`${LOG} Attached ${challenge.challenge_key} to lane ${lane.lane_id} for ${student.email}`);
    } catch (err) {
      failed.push({ user_id: student.id, user_email: student.email, lane_id: lane.lane_id, reason: err.message });
      if (progress) {
        progress.lanes[lane.lane_id].status = 'error';
        progress.failed++;
      }
      console.error(`${LOG} Attach failed for ${student.email}: ${err.message}`);
    }
    if (progress) {
      progress.completed++;
      laneDeployer.recordLaneDone(progress, 1);
      progress.phase_detail = `Attaching: ${progress.completed}/${students.length} complete`;
    }
  }

  laneDeployer.finishProgress(progressId);
  return { provisioned, failed, progressId };
}

// ── entry point ──────────────────────────────────────────────────────────────

/**
 * Deploy a vulnerable lab to a set of students.
 *
 * @param {object} a
 * @param {object} a.course     cle_course row (course_id, course_name, code)
 * @param {object} a.challenge  row from loadChallenge()
 * @param {Array}  a.students   [{ id, email }] — already validated as enrolled
 * @param {string} a.materialId cle_course_material.material_id for this lab
 * @param {string} a.mode       'lane' | 'attach'
 * @param {Array}  [a.instructorEmails] extra Guacamole READ grants
 * @param {string} [a.progressId]  override the lab-wide key (per-student redeploy)
 * @param {object} [a.flagSeeds]   { [userId]: snapshot rows } — 'lane' mode only;
 *   in 'attach' mode the host lane survives, so its flag rows do too and there is
 *   nothing to replay.
 * @param {boolean} [a.attackBoxes=true]  deploy a Kali attack box per lane.
 *   DEFAULTS TO TRUE, which is what this path hardcoded before it was a choice —
 *   so an older client, and every course deployed before this field existed,
 *   keeps behaving exactly as it did.
 * @param {string}  [a.consoleVm]  which machine the student's console opens:
 *   a spec VM name, 'kali', or 'ws:<index>'. Absent falls through to the
 *   environment's own console_role, then Kali (see resolveConsolePlan).
 * @param {Array}   [a.extraWorkstations] machines the instructor added at deploy
 *   time, in slot order. 'lane' mode only.
 */
async function deployVulnLab({
  course, challenge, students, materialId, mode, instructorEmails = [],
  progressId = null, flagSeeds = null,
  attackBoxes = true, consoleVm = null, extraWorkstations = [],
}) {
  if (!MODES.includes(mode)) throw new Error(`Unknown deploy mode '${mode}'`);
  if (!students.length) return { provisioned: [], failed: [], progressId: null };

  const caps = describeChallenge(challenge);
  if (mode === 'lane' && !caps.can_deploy_lane) {
    const err = new Error(`Cannot deploy '${challenge.name}' as its own environment: ${caps.lane_blockers.join('; ')}`);
    err.status = 409;
    throw err;
  }
  if (mode === 'attach' && !caps.can_attach) {
    const err = new Error(`Cannot attach '${challenge.name}' to an existing lane: ${caps.attach_blockers.join('; ')}`);
    err.status = 409;
    throw err;
  }

  console.log(
    `${LOG} Deploying '${challenge.challenge_key}' (${mode}) to ${students.length} student(s) ` +
    `in course ${course.course_id}`
  );

  // Attach mode grafts into a lane that already exists, with its own console and
  // its own .100+ address band. Adding machines or an attack box there is not a
  // smaller version of the same thing — it is a different operation on someone
  // else's lane — so it is refused rather than silently ignored.
  if (mode === 'attach' && ((extraWorkstations && extraWorkstations.length) || consoleVm)) {
    const err = new Error(
      'Attach mode adds this environment to the lane the student already has, and keeps that ' +
      'lane’s console. Deploy it as its own environment to add machines or choose a console.'
    );
    err.status = 400;
    throw err;
  }

  return mode === 'attach'
    ? attachLabToStudents({ course, challenge, students, materialId, progressId })
    : deployLabLanes({
        course, challenge, students, materialId, instructorEmails, progressId, flagSeeds,
        attackBoxes, consoleVm, extraWorkstations,
      });
}

// ── teardown ─────────────────────────────────────────────────────────────────

/**
 * Detach one attached-module instance from its lane: destroy its VMs, remove its
 * dnsmasq file, and drop it from config.attached_modules.
 */
async function detachInstance(lane, laneConfig, instance) {
  const { destroyed, errors } = await attachedModules.detachModuleFromLane({
    moduleInstance: instance,
    bestNode: laneConfig.node,
    gatewayVmId: laneConfig.gateway_vm_id || laneConfig.gateway_vmid || (100000 + lane.vxlan_id),
    proxmoxAPI,
    forceDestroyVM,
  });

  // Drop it from the lane's config even when some VMs survived: they are
  // reported in `errors`, and leaving the instance behind would make a retry
  // attempt to destroy the same ids again while the record claims they exist.
  await withLaneConfig(lane.lane_id, (cfg) => ({
    ...cfg,
    attached_modules: (cfg.attached_modules || [])
      .filter(m => m.module_instance_id !== instance.module_instance_id),
  })).catch((e) => {
    // The lane row may have gone in the meantime; the VMs are already destroyed.
    errors.push(`Could not update lane ${lane.lane_id} config: ${e.message}`);
  });

  return { destroyed, errors };
}

/**
 * Tear down what a lab assignment deployed: whole lanes for 'lane' mode,
 * attached-module instances for 'attach' mode. Safe to call for a lab that
 * deployed nothing.
 *
 * Both are matched on material_id, which both modes stamp — lanes on
 * config.material_id, attached instances on the instance record — so a course
 * running several labs at once tears down only the one asked for.
 *
 * SCOPE. With `userId` set this touches only that student's copy. Note what that
 * CANNOT hit, because it is the whole safety argument for the per-student button:
 * branch 1 selects on `config->>'material_id' = $1`, and a student's workstation
 * lane has material_id NULL, so the host lane can never be selected there no
 * matter what user_id says. Branch 2 finds the host lane but only ever calls
 * detachInstance on it — the lane, its gateway, its console and its workstation
 * are left running.
 *
 * FAILURE GRADES. laneDeployer.teardownLanes returns `errors` with its
 * `warnings` already folded in (Guacamole, workspace bookkeeping). Those are
 * things that outlived the lane in ANOTHER system — nothing is still running on
 * the cluster and the lane row cannot help clean them up. They must not count as
 * a failure, or a Guacamole 403 both blocks a redeploy and tells the instructor
 * to retry a teardown that already succeeded. They are subtracted back out here
 * and reported separately.
 *
 * @param {string}  a.materialId
 * @param {string}  [a.userId]            null = the whole lab
 * @param {string}  [a.ignoreProgressId]  the caller's own progress claim
 * @param {boolean} [a.waitForVms]        confirm on the cluster that detached VMs are gone
 */
async function teardownLabScoped({ materialId, userId = null, ignoreProgressId = null, waitForVms = false }) {
  const result = {
    scope: userId ? 'student' : 'lab',
    mode_seen: [],
    detached_instances: [],
    flag_snapshot: {},
    lanes_deleted: 0, lanes_kept_for_retry: 0, vms_destroyed: 0, instances_detached: 0,
    surviving_vmids: [],
    errors: [], warnings: [],
    safe_to_redeploy: false,
  };

  // A deploy still running would keep cloning VMs after we take our snapshot,
  // and those would be orphaned. Make the caller wait rather than half-tear-down.
  assertNoConflictingLabOperation({ materialId, userId, ignoreProgressId });

  // 1. Dedicated lab lanes. 'error' lanes are included: a previous teardown may
  //    have kept them precisely so this retry can find their surviving VMs.
  const lanes = await cybercoreQuery(
    `SELECT lane_id FROM cybercore_lane
      WHERE config->>'material_id' = $1 AND status <> 'deleted'
        AND ($2::uuid IS NULL OR user_id = $2::uuid)`,
    [materialId, userId]
  );
  const laneIds = lanes.rows.map(r => r.lane_id);
  if (laneIds.length > 0) {
    result.mode_seen.push('lane');

    // Snapshot the flags BEFORE anything is destroyed. cybercore_lane_flag
    // CASCADEs off cybercore_lane and teardownLanes hard-deletes the row, so
    // this is the last moment the student's captures exist. The caller decides
    // whether to replay them; taking the snapshot is cheap and unconditional so
    // the decision can be made after the fact.
    try {
      const snap = await flagManager.snapshotLaneFlags(laneIds);
      for (const row of snap) {
        (result.flag_snapshot[row.user_id] ||= []).push(row);
      }
    } catch (e) {
      // Not fatal, but the caller must not silently believe progress was kept.
      result.warnings.push(`Could not snapshot capture flags before teardown: ${e.message}`);
    }

    console.log(
      `${LOG} Tearing down ${laneIds.length} lab lane(s) for material ${materialId}` +
      (userId ? ` (student ${userId})` : '')
    );
    const t = await laneDeployer.teardownLanes(laneIds);
    result.lanes_deleted = t.lanes_deleted || 0;
    result.lanes_kept_for_retry = t.lanes_kept_for_retry || 0;
    result.vms_destroyed += t.vms_destroyed || 0;

    const warnSet = new Set(t.warnings || []);
    result.warnings.push(...(t.warnings || []));
    result.errors.push(...(t.errors || []).filter(e => !warnSet.has(e)));
  }

  // 2. Attached instances on lanes this lab did NOT own.
  //    jsonb_array_elements rather than a JS scan: a course can have dozens of
  //    lanes and only a couple carrying this lab.
  const attachedLanes = await cybercoreQuery(
    `SELECT lane_id, vxlan_id, user_id, config FROM cybercore_lane
      WHERE status <> 'deleted'
        AND ($2::uuid IS NULL OR user_id = $2::uuid)
        AND jsonb_typeof(config->'attached_modules') = 'array'
        AND EXISTS (
          SELECT 1 FROM jsonb_array_elements(config->'attached_modules') AS m
           WHERE m->>'material_id' = $1
        )`,
    [materialId, userId]
  );

  const detachedVmids = [];
  for (const lane of attachedLanes.rows) {
    const cfg = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    const instances = (cfg.attached_modules || []).filter(m => m.material_id === materialId);
    if (instances.length > 0 && !result.mode_seen.includes('attach')) result.mode_seen.push('attach');
    for (const instance of instances) {
      try {
        const r = await detachInstance(lane, cfg, instance);
        result.instances_detached++;
        result.vms_destroyed += (r.destroyed || []).length;
        result.errors.push(...(r.errors || []));
        // Recorded so the caller can rotate exactly these VMs' flags on request.
        // The host lane survives, so its flag rows survive with it — which is
        // what preserves the student's captures by default.
        result.detached_instances.push({
          lane_id: lane.lane_id,
          user_id: lane.user_id,
          module_instance_id: instance.module_instance_id,
          vm_names: (instance.vms || []).map(v => v.name).filter(Boolean),
        });
        for (const vm of (instance.vms || [])) {
          if (vm?.vm_id != null) detachedVmids.push(vm.vm_id);
        }
      } catch (err) {
        result.errors.push(`Detach ${instance.module_instance_id} from lane ${lane.lane_id}: ${err.message}`);
      }
    }
  }

  // 3. For attach mode only, confirm on the cluster that the VMs really went.
  //    Lane mode does not need this: teardownLanes already polls for up to three
  //    rounds and refuses to delete the lane row while anything survives, so a
  //    clean return there IS the proof. Nothing enforces that for a detach —
  //    detachInstance drops the instance record even when VMs survive — and the
  //    re-attach would otherwise clone straight into the ids still being purged.
  if (waitForVms && detachedVmids.length > 0) {
    const { surviving } = await waitForVmidsGone(detachedVmids);
    result.surviving_vmids = surviving;
    if (surviving.length > 0) {
      result.errors.push(
        `Machine(s) ${surviving.join(', ')} were still present on the cluster two minutes after being destroyed.`
      );
    }
  }

  result.safe_to_redeploy =
    result.lanes_kept_for_retry === 0 &&
    result.surviving_vmids.length === 0 &&
    result.errors.length === 0;

  return result;
}

/** Tear down everything a lab assignment deployed, for every student. */
async function teardownLab(materialId) {
  return teardownLabScoped({ materialId });
}

/**
 * Tear down ONE student's copy of a lab, leaving the rest of the class alone.
 * In attach mode the student's workstation lane is kept — only the lab's own
 * machines go.
 */
async function teardownLabForStudent({ materialId, userId, ignoreProgressId = null }) {
  if (!userId) throw new Error('teardownLabForStudent: userId is required');
  return teardownLabScoped({ materialId, userId, ignoreProgressId, waitForVms: true });
}

/**
 * Discard the capture flags a teardown left behind, so the rebuild mints fresh
 * values and clears capture state. The instructor's opt-in when a lab is being
 * redeployed because the answers leaked rather than because the box broke.
 *
 * Only meaningful for 'attach' mode. A dedicated lab lane is DELETED by teardown
 * and cybercore_lane_flag CASCADEs with it, so rotation there is the default and
 * preservation is the thing that takes work (flagSeeds). An attached module's
 * host lane survives, so its flag rows survive too and ensureLaneFlags would
 * faithfully re-plant the same values — correct by default, and this is the
 * escape hatch.
 *
 * @param {Array} detachedInstances  teardown result's `detached_instances`
 * @returns {Promise<number>} flag rows deleted
 */
async function resetFlagsForDetached(detachedInstances) {
  let deleted = 0;
  for (const inst of (detachedInstances || [])) {
    try {
      deleted += await flagManager.deleteLaneFlagsForVms({
        laneId: inst.lane_id,
        vmNames: inst.vm_names,
      });
    } catch (e) {
      console.warn(`${LOG} Could not reset flags on lane ${inst.lane_id}: ${e.message}`);
    }
  }
  return deleted;
}

/**
 * Exclusion for the group deploy: students with a per-student operation already
 * in flight against this lab.
 *
 * excludeStudentsWithLab cannot see them. Between teardownLanes deleting the row
 * and the deploy inserting the new one, a redeploying student holds NO lane at
 * all — so a group deploy landing in that window would build them a second lane
 * on a second VXLAN, and the redeploy's own insert would then collide.
 *
 * Lives here rather than in students.js because this module owns the key format.
 */
function excludeStudentsInFlight(materialId) {
  return async (candidates) => {
    const busy = new Map();
    const ops = labOperationsInFlight(materialId);
    const ids = new Set(candidates);
    for (const op of ops) {
      if (op.userId && ids.has(op.userId)) {
        busy.set(op.userId, 'a redeploy of this lab is already running for them');
      }
    }
    return busy;
  };
}

module.exports = {
  MODES,
  progressIdForLab,
  progressIdForLabStudent,
  getLabProgress,
  labOperationsInFlight,
  assertNoConflictingLabOperation,
  loadChallenge,
  describeChallenge,
  countFreeLanes,
  findCourseLanes,
  deployVulnLab,
  teardownLab,
  teardownLabForStudent,
  resetFlagsForDetached,
  excludeStudentsInFlight,
};
