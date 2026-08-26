/**
 * CLE Plugin — VM Management Routes (lane-native)
 * Mounted at /api/cle/courses/:courseId/vms
 *
 * Workstations are provisioned as per-student cybercore_lane rows (gateway LXC +
 * workstation VM) drawn from the course's reserved VXLAN block, through the
 * shared src/utils/lane-deployer.js — the same sequence the admin group deploy
 * uses for its attack boxes. cybercore_lane is the source of truth for the lane;
 * lane-deployer additionally registers each workstation in cybercore_resource /
 * vm_instance / allocation so the STUDENT sees it on their own dashboard.
 *
 * Scope: WORKSTATION lanes only. Vulnerable-lab lanes (routes/labs.js) also carry
 * config.course_id — every CLE read path keys on it — so every query here also
 * requires config.material_id IS NULL. Without that, lab lanes would surface in
 * the Workstations tab and could be destroyed by DELETE /:laneId, which bypasses
 * the lab's own teardown and leaves the assignment pointing at nothing.
 */

const express = require('express');
const router = express.Router({ mergeParams: true });
const { requireRole } = require('../../../../../src/middleware/auth');
const { query } = require('../utils/db');
const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { resolveLaneWorkstationCredential } = require('../../../../../src/utils/lane-credentials');
const { mintGuacToken, GUAC_URL, GUAC_DS } = require('../../../../../src/utils/guacamole');
const {
  buildDeployPreview, buildResizePreview,
} = require('../../../../../src/middleware/deployment-guards');
const vmResize = require('../../../../../src/utils/vm-resize');
const { runBatch } = require('../../../../../src/utils/batch-deployer');
const laneDeployer = require('../../../../../src/utils/lane-deployer');
const { normalizeResourceSpec, WORKSTATION_MAX_SLOTS } = laneDeployer;
const { buildLaneTopology } = require('../../../../../src/utils/lane-topology');
const laneProvision = require('../utils/lane-provision');
const vulnLab = require('../utils/vuln-lab-provision');
const audit = require('../../../../../src/utils/audit');
const { getManagedCourse: getManagedCourseRow } = require('../utils/course-access');
const {
  resolveTargetStudents: resolveStudents,
  excludeStudentsWithCourseLane,
  courseStaffIds,
} = require('../utils/students');

const instructorOnly = requireRole('instructor', 'admin');

/**
 * Re-sizing a deployed machine is ADMIN-ONLY, unlike every other route in this
 * file.
 *
 * The gate is about the cluster, not the course. Raising RAM on a cohort
 * commits shared node memory that other courses are drawing from, and an
 * instructor can see neither those other courses nor the node headroom the
 * change consumes — so the decision is a platform one. It also power-cycles
 * machines students may be sitting in front of.
 *
 * This is IN ADDITION TO getManagedCourse, never instead of it: requireRole
 * denials are recorded by auditDenial (middleware/auth.js), and the course
 * scope check still has to run so an admin cannot resize a lane by id alone.
 */
const adminOnly = requireRole('admin');

// Columns every provision path needs. os_family drives the NIC model (stock
// Windows images have no virtio-net driver, so a virtio NIC never DHCPs) and
// metadata carries console protocol / RDP credentials — omitting either is how
// a Windows template ends up deployed but unreachable.
const TEMPLATE_COLS = `
  id, template_key, os_name, os_family, os_version,
  template_vmid, node, provider_type, metadata
`;

/** Guacamole client launch URL (base64("<connId>\0c\0<datasource>")). */
function buildGuacLaunchUrl(connId) {
  const base = (process.env.GUAC_PUBLIC_BASE_URL || '/guac').replace(/\/$/, '');
  const clientToken = Buffer.from(`${connId}\0c\0${GUAC_DS}`).toString('base64');
  return `${base}/#/client/${clientToken}`;
}

/** Verify the course exists and the caller may manage it. Returns the course row
 *  (with its reserved-lab linkage) or null. Admin-aware via the shared helper. */
function getManagedCourse(courseId, user) {
  // `code` names the lanes (cle-<code>-<vxlanId>) — see lane-provision.laneNamePrefix.
  // instructor_id feeds courseStaffIds: an admin managing someone else's course
  // must be able to deploy for that course's instructor, who is never enrolled.
  return getManagedCourseRow(courseId, user, 'course_id, course_name, code, challenge_id, challenge_key, instructor_id');
}

/** Load + validate the workstation template a provision request names. */
async function loadWorkstationTemplate(templateId) {
  const tpl = await cybercoreQuery(`
    SELECT ${TEMPLATE_COLS}
      FROM cybercore_template_catalog
     WHERE id = $1 AND template_type = 'workstation' AND is_active = TRUE AND status = 'active'
  `, [templateId]);
  if (tpl.rows.length === 0) {
    const err = new Error('Template not found or not active');
    err.status = 404;
    throw err;
  }
  const template = tpl.rows[0];
  if (!template.template_vmid) {
    const err = new Error(`Template '${template.os_name}' has no Proxmox VMID configured`);
    err.status = 409;
    throw err;
  }
  return template;
}

/**
 * Load every workstation template a provision request names, in SLOT ORDER.
 *
 * `template_ids: [elk, sensor]` is the multi-machine form — slot 0 lands on
 * <lane>.50 with the gateway's baked wan0:3389 DNAT, slot 1 on .51, and so on
 * (lane-deployer.js octetForSlot). `template_id` remains accepted so every
 * existing caller and the single-machine UI path are unchanged.
 *
 * Loops the single-row loader rather than one `= ANY($1::uuid[])` query on
 * purpose: `id` is a UUID column, so a malformed value in the array would turn
 * today's clean 404 into a 500, and N is 2.
 */
async function loadWorkstationTemplates(body) {
  const ids = Array.isArray(body.template_ids) && body.template_ids.length
    ? body.template_ids
    : (body.template_id ? [body.template_id] : []);

  if (!ids.length) {
    const err = new Error('template_id, or a non-empty template_ids array, is required');
    err.status = 400;
    throw err;
  }
  // Two slots sharing one catalog row would make attack-target.js's
  // template-identity rung ambiguous (it requires exactly one match), and would
  // collide outright if that template ever pins metadata.console_wan_port.
  if (new Set(ids.map(String)).size !== ids.length) {
    const err = new Error('template_ids must be distinct — two machines cannot share one catalog row');
    err.status = 400;
    throw err;
  }

  const templates = [];
  for (const id of ids) templates.push(await loadWorkstationTemplate(id));
  return templates;
}

/** Resolve the course's reserved lab (VXLAN block + challenge key). */
async function loadCourseLab(course) {
  if (!course.challenge_id) {
    const err = new Error('Course has no reserved lab — recreate the course to provision its network');
    err.status = 409;
    throw err;
  }
  const lab = await laneProvision.resolveCourseLab(course.challenge_id);
  if (!lab) {
    const err = new Error('Reserved lab challenge missing for this course');
    err.status = 409;
    throw err;
  }
  return { challenge_key: lab.challengeKey, vxlan_block: lab.vxlanBlock };
}

/**
 * Resolve the students to provision: actively enrolled, with an email (Guacamole
 * accounts are email-keyed), and not already holding a lane in this course —
 * re-provisioning would collide on the gateway/workstation VMIDs for their VXLAN.
 *
 * The filter itself lives in utils/students.js so the vulnerable-lab path applies
 * exactly the same rules.
 *
 * `staffIds` is the course's staff — the caller and the course's own instructor,
 * from courseStaffIds() — passed by the routes that let a workstation be built
 * for whoever RUNS the course. It exempts those ids from the enrollment
 * requirement and nothing else: they still need an email, and the
 * already-has-a-lane exclusion applies to them exactly as it does to a student.
 * Every route that passes it has already run getManagedCourse, so the ids are
 * ones the caller is authorised to act on.
 */
function resolveTargetStudents(courseId, requestedIds, staffIds = []) {
  return resolveStudents(courseId, requestedIds, {
    excludeIf: excludeStudentsWithCourseLane(courseId),
    extraUserIds: staffIds || [],
  });
}

/**
 * Validate the instructor's optional hardware sizing for this deploy. Returns
 * { cores, memory_mb, disk_gb } with only the fields they actually set — the
 * rest keep the catalog template's own sizing. Throws a 400-shaped error so a
 * mistyped core count is rejected up front rather than after N lanes exist.
 *
 * Sizing is applied to each CLONE before its first boot; the catalog template is
 * never modified, so two courses can deploy the same image at different sizes.
 */
function parseRequestedResources(body, slotCount = 1) {
  const raw = body.resources;

  // Explicit per-slot sizing: one entry per machine, index-matched to
  // template_ids. deployLanes already supports this (resourcesFor); holes keep
  // that slot's own template sizing.
  if (Array.isArray(raw)) {
    if (raw.length > slotCount) {
      const err = new Error(`resources has ${raw.length} entries for ${slotCount} machine(s)`);
      err.status = 400;
      throw err;
    }
    const out = raw.map((entry) => {
      const { resources, errors } = normalizeResourceSpec(entry);
      if (errors.length) {
        const err = new Error(errors.join('; '));
        err.status = 400;
        throw err;
      }
      return resources;
    });
    return out.some(Boolean) ? out : null;
  }

  const { resources, errors } = normalizeResourceSpec(raw);
  if (errors.length) {
    const err = new Error(errors.join('; '));
    err.status = 400;
    throw err;
  }

  // A SCALAR spec sizes machine 1 only, never every machine.
  //
  // The provision modal PRE-FILLS its CPU/RAM/disk inputs from the selected
  // template's live Proxmox sizing (courses.html seedResourceInputs), so a
  // resources object is sent on essentially every deploy whether or not the
  // instructor touched it. Applying it to all slots would clone a 4 GB Linux
  // sensor at the ELK box's 16 GB — silently, and multiplied by the cohort.
  // Later slots fall through to their own template's sizing instead.
  if (resources && slotCount > 1) {
    const perSlot = new Array(slotCount).fill(null);
    perSlot[0] = resources;
    return perSlot;
  }
  return resources;
}

/** Kick off the background deploy. Shared by /provision and /provision-all. */
function startProvision({ courseId, courseName, courseCode, challenge, templates, students, resources }) {
  // `templates` only: deployLanes treats a 1-element array exactly as it treats
  // a single `template`, so the single-machine path is byte-identical.
  laneProvision.provisionLanes({ courseId, courseName, courseCode, challenge, templates, students, resources })
    .then(result => console.log(`[CLE] Provision finished for course ${courseId}:`, JSON.stringify({
      provisioned: result.provisioned.length, failed: result.failed.length,
    })))
    .catch(err => console.error(`[CLE] Provision failed for course ${courseId}: ${err.message}`));
}

// A bulk cluster operation is nothing like a bulk DB write: 50 lanes is ~150
// VMs handed to teardownLanes in one call, already 10x its own concurrency of
// 15. admin/settings.js caps its user batch at 500 because that one only
// touches Postgres.
const MAX_BULK_LANES = 50;

// lane_id is a uuid column. A malformed element inside `= ANY($1::uuid[])`
// turns a clean result into a 500 — the same reason loadWorkstationTemplates
// loops instead of using ANY.
const LANE_ID_RE = /^[0-9a-f-]{36}$/i;

/**
 * Validate and de-duplicate a bulk request's lane_ids.
 *
 * Malformed ids become `skipped` rather than a rejection of the whole batch,
 * matching how both provision routes report the students they could not act on.
 * The table polls every 8s, so one row torn down by a co-instructor three
 * seconds ago must not fail the other eleven with no way to tell which.
 *
 * The cap is a hard 400, never a silent truncation: an instructor who ticked 60
 * rows and saw 50 deleted has no way to know which ten survived.
 *
 * @throws {Error & {status:400}}
 */
function parseLaneIds(body) {
  const raw = (body || {}).lane_ids;
  if (!Array.isArray(raw) || raw.length === 0) {
    const e = new Error(`non-empty lane_ids array required`); e.status = 400; throw e;
  }
  const skipped = [];
  const seen = new Set();
  const ids = [];
  for (const v of raw) {
    const id = typeof v === 'string' ? v.trim() : '';
    if (!LANE_ID_RE.test(id)) { skipped.push({ lane_id: String(v), reason: 'not a lane id' }); continue; }
    if (seen.has(id)) continue;          // de-duped BEFORE the cap, so the
    seen.add(id);                        // counts reported back cannot lie
    ids.push(id);
  }
  if (ids.length > MAX_BULK_LANES) {
    const e = new Error(`select at most ${MAX_BULK_LANES} lanes at a time (got ${ids.length})`);
    e.status = 400; throw e;
  }
  if (ids.length === 0) {
    const e = new Error(`no valid lane ids in the request`); e.status = 400; throw e;
  }
  return { ids, skipped };
}

/**
 * Validate a redeploy request against the lanes it actually resolved to.
 *
 * `slots` is expressed as SLOT NUMBERS, never vmids. Slot is the stable
 * identity — it determines the octet, the console WAN port, the DHCP
 * reservation and the DNAT rule — whereas a vmid is cluster-global, and an
 * unvalidated one would be a cluster-wide destroy primitive if a scope check
 * were ever dropped.
 *
 * An unknown slot is a 400 NAMING it, not a silent skip: with exactly one lane
 * there is no batch to partially honour, and quietly rebuilding fewer machines
 * than asked is the class of bug that is invisible until a student reports it.
 *
 * @throws {Error & {status:400}}
 */
function parseRedeployRequest(body, lanes) {
  const b = body || {};
  const fullLane = b.full_lane === true;
  let slots = null;

  if (b.slots !== undefined && b.slots !== null) {
    if (fullLane) {
      const e = new Error(`slots cannot be combined with full_lane \u2014 a whole-lane rebuild replaces every machine`); e.status = 400; throw e;
    }
    if (!Array.isArray(b.slots) || b.slots.length === 0) {
      const e = new Error(`slots must be a non-empty array of slot numbers`); e.status = 400; throw e;
    }
    if (lanes.length !== 1) {
      const e = new Error(
        `slots can only be used when exactly one lane is selected (got ${lanes.length})`);
      e.status = 400; throw e;
    }
    const known = new Set(machineSlotsOf(lanes[0]));
    const out = new Set();
    for (const raw of b.slots) {
      // Number() alone is not a validator here: Number(null), Number('') and
      // Number([]) are all 0 — a slot that exists on every lane — so a malformed
      // body would silently rebuild slot 0, the one machine holding the
      // student's console. Accept a real integer, or a string of digits.
      const n = typeof raw === 'number' ? raw
        : (typeof raw === 'string' && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN);
      if (!Number.isInteger(n) || n < 0 || n >= WORKSTATION_MAX_SLOTS) {
        const e = new Error(`'${raw}' is not a slot number`); e.status = 400; throw e;
      }
      if (!known.has(n)) {
        const e = new Error(`This lane has no machine in slot ${n}`); e.status = 400; throw e;
      }
      out.add(n);
    }
    slots = [...out].sort((a, b2) => a - b2);
  }
  return { slots, fullLane };
}

/** The slot numbers a lane row records, synthesizing slot 0 for legacy lanes. */
function machineSlotsOf(lane) {
  const cfg = lane.config || {};
  const ws = Array.isArray(cfg.workstations) ? cfg.workstations : [];
  if (ws.length) return ws.filter(w => w && w.slot != null).map(w => w.slot);
  return cfg.workstation_vmid ? [0] : [];
}

/**
 * Which lanes an IN-PLACE rebuild may touch.
 *
 * Only 'active'. The whole premise is that the gateway, VXLAN, WAN address,
 * DNAT rules and Guacamole connection survive, and an 'error' lane got there
 * one of two ways, neither of which preserves them: markLaneError after a
 * gateway or workstation failure (so there may be nothing to rebuild INTO), or
 * teardownLanes marking it (so the row is a tombstone pointing at survivors).
 * Those go to the full-lane path, which is teardown + fresh deploy and is
 * exactly what an error state is designed to be recovered by.
 *
 * 'deploying' is refused on both paths — the mutex should already have caught
 * it, and this is the belt.
 */
function redeployEligibility(lane, fullLane) {
  if (lane.status === 'deploying') {
    return { ok: false, reason: 'a deploy or rebuild is already running on this lane' };
  }
  if (fullLane) return { ok: true };
  if (lane.status !== 'active') {
    return {
      ok: false,
      reason: `lane is in an ${lane.status} state \u2014 use a whole-lane rebuild`,
    };
  }
  if (!machineSlotsOf(lane).length) {
    return { ok: false, reason: 'lane records no machines \u2014 use a whole-lane rebuild' };
  }
  return { ok: true };
}

/**
 * A resize may aim at far more machines than a teardown, because it destroys
 * nothing. MAX_BULK_LANES is 50 because 50 lanes is ~150 VMs handed to
 * teardownLanes in one call; a resize clones nothing, writes no disks and
 * touches one config key per machine, so the same ceiling would leave a
 * 60-student course unable to use the feature at all. Still a hard 400 and
 * never a silent truncation, for the same reason parseLaneIds is: an admin who
 * selected 300 machines and saw 200 resized has no way to know which 100 were
 * skipped.
 */
const MAX_RESIZE_TARGETS = 200;

/**
 * Validate the sizing half of a resize request.
 *
 * DISK IS REFUSED HERE, LOUDLY. Silently dropping it would be the worst of the
 * options: an admin who typed a new disk size, saw the machines reboot and saw
 * the row still say 128 GB would reasonably conclude the whole feature is
 * broken. Proxmox cannot shrink a volume at all, and growing one moves the
 * block device without moving the filesystem inside it — there is no
 * growpart/Resize-Partition step anywhere in this app, because every existing
 * resize happens before a guest's first boot where cloud-init does that work.
 *
 * @throws {Error & {status:400}}
 */
function parseResizeSpec(body) {
  const raw = (body || {}).resources;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
    const e = new Error('resources must be an object with cores and/or memory_mb');
    e.status = 400; throw e;
  }
  if (raw.disk_gb !== undefined && raw.disk_gb !== null && raw.disk_gb !== '') {
    const e = new Error(
      'Disk size cannot be changed on a machine that is already deployed. Proxmox cannot ' +
      'shrink a disk, and growing one enlarges the virtual disk without enlarging the ' +
      'filesystem inside it, so the student would see no extra space. Rebuild the machine ' +
      'to change its disk.');
    e.status = 400; throw e;
  }
  // Through the shared validator so the bounds live in exactly one place.
  const { resources, errors } = normalizeResourceSpec({
    cores: raw.cores, memory_mb: raw.memory_mb,
  });
  if (errors.length) { const e = new Error(errors.join('; ')); e.status = 400; throw e; }
  if (!resources) {
    const e = new Error('supply a new core count, a new memory size, or both');
    e.status = 400; throw e;
  }
  return resources;
}

/**
 * Turn a scope request into the concrete (lane, slot) machines to act on.
 *
 * `lanes` MUST already be the output of findCourseWorkstationLanes — that read
 * carries the `material_id IS NULL` predicate that keeps every bulk path off
 * vulnerable-lab lanes. Nothing here re-derives it, and nothing here trusts a
 * client-supplied lane id: for the 'course' and 'template' scopes the caller
 * never names lanes at all.
 *
 * DELIBERATELY UNLIKE parseRedeployRequest, which refuses `slots` unless
 * exactly one lane is selected. That restriction exists because a mis-aimed
 * rebuild DESTROYS a machine, so a slot number that means different things on
 * different lanes is a data-loss bug. A resize destroys nothing, and
 * "give every student's slot-1 sensor more RAM" is the main thing anyone wants
 * from it — so slots apply across the whole selection, and a lane that has no
 * such slot is SKIPPED rather than failing the batch.
 *
 * @returns {{targets: Array, skipped: Array}}
 */
function resolveResizeTargets(body, lanes) {
  const b = body || {};
  const scope = b.scope || 'lanes';
  const skipped = [];

  let wantSlots = null;
  if (b.slots !== undefined && b.slots !== null) {
    if (!Array.isArray(b.slots) || b.slots.length === 0) {
      const e = new Error('slots must be a non-empty array of slot numbers');
      e.status = 400; throw e;
    }
    const out = new Set();
    for (const raw of b.slots) {
      // Number() alone is not a validator: Number(null), Number('') and
      // Number([]) are all 0 — a slot that exists on every lane — so a
      // malformed body would silently target slot 0, the student's console.
      const n = typeof raw === 'number' ? raw
        : (typeof raw === 'string' && /^\d+$/.test(raw.trim()) ? Number(raw.trim()) : NaN);
      if (!Number.isInteger(n) || n < 0 || n >= WORKSTATION_MAX_SLOTS) {
        const e = new Error(`'${raw}' is not a slot number`); e.status = 400; throw e;
      }
      out.add(n);
    }
    wantSlots = [...out].sort((a, b2) => a - b2);
  }

  const wantTemplate = scope === 'template' ? String(b.template_id || '') : null;
  if (scope === 'template' && !wantTemplate) {
    const e = new Error('template_id is required for a template-scoped resize');
    e.status = 400; throw e;
  }

  const targets = [];
  for (const lane of lanes) {
    if (lane.status !== 'active') {
      skipped.push({
        lane_id: lane.lane_id,
        reason: lane.status === 'deploying'
          ? 'a deploy or rebuild is already running on this lane'
          : `lane is in an ${lane.status} state`,
      });
      continue;
    }
    const records = laneDeployer.laneWorkstationRecords(lane);
    if (!records.length) {
      skipped.push({ lane_id: lane.lane_id, reason: 'lane records no machines' });
      continue;
    }
    let picked = records;
    if (wantSlots) picked = picked.filter(r => wantSlots.includes(r.slot));
    if (wantTemplate) picked = picked.filter(r => String(r.template_id || '') === wantTemplate);
    if (!picked.length) {
      skipped.push({
        lane_id: lane.lane_id,
        reason: wantTemplate ? 'no machine on this lane came from that template'
                             : 'this lane has none of the selected slots',
      });
      continue;
    }
    for (const r of picked) {
      if (r.vmid == null) continue;
      targets.push({
        lane_id: lane.lane_id,
        lane_name: lane.name,
        student_email: lane.student_email,
        user_id: lane.user_id,
        slot: r.slot,
        vmid: Number(r.vmid),
        provider_type: r.provider_type || null,
        template_id: r.template_id || null,
        hostname: r.hostname || null,
        recorded_resources: r.resources || null,
      });
    }
  }

  if (targets.length > MAX_RESIZE_TARGETS) {
    const e = new Error(
      `select at most ${MAX_RESIZE_TARGETS} machines at a time (got ${targets.length})`);
    e.status = 400; throw e;
  }
  return { targets, skipped };
}

/**
 * HTTP status + message for a teardownLanes result.
 *
 * KEYS ON lanes_kept_for_retry, NEVER errors.length. teardownLanes returns
 * `errors: [...errors, ...warnings]` while its row decision keys on `errors`
 * alone, so a Guacamole 403 — which leaves nothing running anywhere — lands in
 * that array. Keying on it would turn every Guacamole hiccup into a partial-
 * failure banner.
 *
 * The 207 message states teardownLanes' all-or-nothing row commit out loud:
 * one refusing gateway leaves EVERY lane in the batch as 'error', including
 * the eleven that tore down perfectly. Without saying so, the instructor sees
 * twelve failed rows and no way to know eleven of them are already clean.
 */
function bulkDeleteStatus(result, requested) {
  const kept = result.lanes_kept_for_retry || 0;
  if (kept === 0) {
    const n = result.lanes_deleted || 0;
    return {
      status: 200, success: true,
      message: `Removed ${n} workstation lane${n === 1 ? '' : 's'} (${result.vms_destroyed || 0} machine${(result.vms_destroyed || 0) === 1 ? '' : 's'} destroyed)`,
    };
  }
  return {
    status: 207, success: false,
    message:
      `Some machines could not be destroyed. All ${kept} selected lane record${kept === 1 ? '' : 's'} ` +
      `were kept so the survivors stay reachable — press Delete again once the cause is ` +
      `cleared, and the retry will find nothing left and remove them.`,
  };
}
/**
 * One entry per MACHINE on a lane, in slot order.
 *
 * A lane holds N workstations — lane-deployer records each one in
 * config.workstations[] and additionally flattens SLOT 0 onto the top-level
 * config keys this file has always read. The lane row above describes slot 0
 * only; this is what lets the UI offer "rebuild just these machines" and what
 * gives the row an honest machine count.
 *
 * Lanes deployed before config.workstations[] existed have the flat keys and
 * no array, so slot 0 is synthesized from them — the same fallback
 * laneDeployer.teardownLanes carries. Those lanes get a one-machine picker
 * rather than none.
 *
 * Credentials go through resolveLaneWorkstationCredential PER VMID rather than
 * reading the flat keys, because reversing that order hands every slot of a
 * multi-machine lane slot 0's password (see src/utils/lane-credentials.js).
 * The plaintext password belongs here for the same reason it is already on the
 * row: this route is instructorOnly and course-scoped, and handing a student
 * their slot-1 login is the workflow. It must never reach audit metadata or a
 * log line.
 *
 * DELIBERATELY ABSENT: mac and octet (derivable, pure noise on an 8s poll),
 * workspace_resource_id, and guac_connection_id — the last is the identifier
 * GET /:laneId/console mints tokens against, and no UI needs raw Guacamole ids
 * in a polled document.
 *
 * @param {object} cfg        cybercore_lane.config
 * @param {object} byVmid     live /cluster/resources rows keyed by String(vmid)
 * @param {string} laneStatus cybercore_lane.status
 * @param {string} laneName   cybercore_lane.name
 */
function projectMachines(cfg, byVmid, laneStatus, laneName) {
  const c = cfg || {};
  const recorded = Array.isArray(c.workstations) ? c.workstations : [];

  // Legacy single-machine lane: rebuild slot 0 from the flat keys.
  const slots = recorded.length > 0 ? recorded : (c.workstation_vmid ? [{
    slot: 0,
    vmid: c.workstation_vmid,
    hostname: laneName || null,
    provider_type: c.provider_type || null,
    template_id: c.template_id || null,
    template_name: c.template_name || null,
    ip: c.workstation_ip || c.ip || null,
    console_protocol: c.console_protocol || null,
    console_port: c.console_port || null,
    console_host: c.console_host || null,
    console_via: c.console_via || null,
    guac_connection_id: c.guac_connection_id || null,
    resources: c.resources || c.requested_resources || null,
    resource_warnings: c.resource_warnings || null,
  }] : []);

  const wsIp = c.ws_ip || {};
  const wsIpOk = c.ws_ip_confirmed || {};
  const rebuiltSlots = (c.rebuild && c.rebuild.slots) || {};

  return slots
    .filter(w => w && w.slot != null)
    .slice()
    .sort((a, b) => a.slot - b.slot)
    .map((w) => {
      const key = String(w.slot);
      const cred = resolveLaneWorkstationCredential(c, w.vmid);
      const live = byVmid[String(w.vmid)];
      const powerState = live
        ? (live.status === 'running' ? 'running' : live.status === 'stopped' ? 'stopped' : live.status)
        : (laneStatus === 'active' ? 'unknown' : laneStatus);
      const rb = rebuiltSlots[key] || null;
      return {
        slot:              w.slot,
        vmid:              w.vmid ?? null,
        hostname:          w.hostname || null,
        provider_type:     w.provider_type || null,
        template_id:       w.template_id || null,
        template_name:     w.template_name || null,
        ip:                w.ip || null,
        // Per-slot, and deliberately NOT falling back to the flat slot-0 key:
        // slot 1 inheriting slot 0's confirmation would claim a machine took a
        // reserved lease that nothing ever checked.
        ip_confirmed:      wsIpOk[key] === true,
        observed_ip:       wsIp[key] || null,
        console_protocol:  w.console_protocol || null,
        console_port:      w.console_port ?? null,
        console_via:       w.console_via || null,
        console_endpoint:  w.console_host ? `${w.console_host}:${w.console_port}` : null,
        has_console:       !!w.guac_connection_id,
        // Live, per machine. The row-level power_state above collapses to the
        // LANE status whenever the lane is not active, which is right for a
        // one-row-per-lane table but useless in a picker that has to say which
        // of these three machines is actually running.
        power_state:       powerState,
        workstation_user:  cred.username,
        workstation_pass:  cred.password,
        credentials_shared: cred.shared,
        resources:         w.resources || null,
        resource_warnings: w.resource_warnings || null,
        // Survives the 1h progress eviction and a restart, so the picker can
        // pre-tick the slots whose last rebuild failed.
        rebuild_error:     rb && rb.status === 'error' ? (rb.message || 'Rebuild failed') : null,
        rebuilt_at:        rb ? (rb.at || null) : null,
      };
    });
}
/**
 * GET / — List provisioned workstation lanes for all students in this course.
 * Reads cybercore_lane (source of truth) and live-syncs workstation power state.
 */
router.get('/', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Scoped by config.course_id, NOT by the roster. A lane's owner need not be
    // an enrolled student: an instructor can provision a workstation for
    // themselves, and a student who is dropped after their lane is built stops
    // being enrolled while their VMs keep running. Listing by enrollment hid
    // both — and a hidden lane cannot be deleted from this tab either, since
    // Delete is reached from the row.
    const enrolled = await query(
      `SELECT user_id FROM cle_course_enrollment WHERE course_id = $1 AND status = 'active'`,
      [courseId]
    );
    const enrolledIds = new Set(enrolled.rows.map(r => r.user_id));

    // Through the shared scoped read rather than a fourth copy of the
    // predicate. The `material_id IS NULL` guard is the reason the bulk
    // endpoints below cannot be pointed at a vulnerable-lab lane; keeping one
    // query is what keeps them honest.
    const laneRows = await laneProvision.findCourseWorkstationLanes(courseId);

    // Live power-state for the workstation VMs via a single cluster call.
    // Live power state. Falling back to the lane's own status when Proxmox is
    // unreachable is correct, but swallowing the reason is not: every row then
    // renders 'unknown' with nothing anywhere saying why, which is
    // indistinguishable from "the VMID does not match". Say which it is.
    let byVmid = {};
    try {
      const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of (resources || [])) byVmid[String(r.vmid)] = r;
      if (Object.keys(byVmid).length === 0) {
        console.warn('[CLE] /cluster/resources returned no VMs — every lane will show power state "unknown". Check the Proxmox API token\'s read permission on /.');
      }
    } catch (e) {
      console.warn(`[CLE] Could not read live VM state from Proxmox (${e.message}) — lanes will show their stored status instead of live power state.`);
    }

    const vms = laneRows.map(row => {
      const cfg = row.config || {};
      const wsCred = resolveLaneWorkstationCredential(cfg, cfg.workstation_vmid);
      const live = byVmid[String(cfg.workstation_vmid)];
      const powerState = live
        ? (live.status === 'running' ? 'running' : live.status === 'stopped' ? 'stopped' : live.status)
        : (row.status === 'active' ? 'unknown' : row.status);
      return {
        lane_id:        row.lane_id,
        lane_status:    row.status,                  // deploying | active | error
        power_state:    row.status === 'active' ? powerState : row.status,
        vxlan_id:       row.vxlan_id,
        user_id:        row.user_id,
        student_email:  row.student_email,
        first_name:     row.first_name,
        last_name:      row.last_name,
        // False for an instructor's own machine and for a dropped student's
        // leftovers — the UI labels those rather than passing them off as class
        // members.
        enrolled:       enrolledIds.has(row.user_id),
        is_self:        row.user_id === req.user.userId,
        // Distinguishes the instructor's machine from a dropped student's
        // leftovers. Without it an admin sees the instructor's box badged
        // "not enrolled", which reads as an orphan to be cleaned up.
        is_course_instructor: row.user_id === course.instructor_id,
        template_id:    cfg.template_id || null,
        vm_name:        cfg.template_name || `cle-${row.vxlan_id}`,
        ip_address:     cfg.ip || null,
        ip_confirmed:   cfg.ip_confirmed === true,
        has_console:    !!cfg.guac_connection_id,
        // How the student reaches it. The endpoint is always the lane gateway's
        // WAN transit IP (guacd has no route into the lane subnet); console_via
        // says which DNAT carries it — 'gateway' (our per-lane rule),
        // 'gateway-baked-dnat' (ours failed, using the template's built-in 3389
        // rule), or 'unreachable' (no rule for this protocol).
        console_via:      cfg.console_via || null,
        console_protocol: cfg.console_protocol || null,
        console_endpoint: cfg.console_host ? `${cfg.console_host}:${cfg.console_port}` : null,
        // Through the shared resolver rather than reading the two flattened
        // keys directly, so this list, the labs list and the student's own
        // card cannot disagree about which slot's login they are showing.
        workstation_user: wsCred.username,
        workstation_pass: wsCred.password,
        // 'template' means the password is the image's built-in one and is
        // identical on every lane from it — not this student's alone.
        credentials_shared: wsCred.shared,
        // How the machine was actually sized. While it's still deploying only
        // the request exists; `resource_warnings` says what Proxmox refused
        // (e.g. a disk target smaller than the template's image).
        resources:          cfg.resources || cfg.requested_resources || null,
        resource_warnings:  cfg.resource_warnings || null,
        error:            cfg.error || null,
        // Amber, not the red `error` badge: a lane whose rebuild failed on one
        // slot is still active with its other machines running, so badging the
        // whole row broken would be a lie.
        rebuild_status:   cfg.rebuild ? (cfg.rebuild.status || null) : null,
        rebuild_error:    cfg.rebuild ? (cfg.rebuild.error || null) : null,
        rebuild_at:       cfg.rebuild ? (cfg.rebuild.at || null) : null,
        created_at:     row.created_at,
        // Every machine on the lane. The row above still describes slot 0, so
        // nothing that reads this list today has to change.
        machines:       projectMachines(cfg, byVmid, row.status, row.name),
      };
    });

    res.json({ vms });
  } catch (error) {
    console.error('[CLE] Get VMs error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /provision — Provision workstation lanes for the named students.
 * Each student gets their own isolated lane (gateway + workstation) on their own
 * VXLAN, drawn from the course's reserved block. Responds immediately; lanes
 * surface via GET / polling and GET /provision-progress.
 */
router.post('/provision', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { student_ids } = req.body;

    if (!Array.isArray(student_ids) || student_ids.length === 0) {
      return res.status(400).json({ error: 'non-empty student_ids array required' });
    }

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Templates BEFORE resources: a scalar sizing spec is scoped by slot count.
    const templates = await loadWorkstationTemplates(req.body);
    const resources = parseRequestedResources(req.body, templates.length);
    const challenge = await loadCourseLab(course);
    // Course staff may be ticked in the picker and get a workstation on this
    // course's network: an instructor building their own, or an admin building
    // one FOR the instructor. provision-all below deliberately does NOT pass
    // them — "the whole class" is the roster.
    const { students, skipped } = await resolveTargetStudents(courseId, student_ids, courseStaffIds(course, req.user));

    if (!students.length) {
      return res.status(400).json({ error: 'No eligible students to provision', skipped });
    }

    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      progress_url: `/api/cle/courses/${courseId}/vms/provision-progress`,
      ...(resources ? { resources } : {}),
      ...(skipped.length ? { skipped } : {}),
    });

    audit.batch({
      req,
      source: 'cle',
      action: 'vm.provisioned',
      targetAction: 'vm.provisioned',
      target: { type: 'course', id: courseId, label: course.course_name },
      // template_id/template stay singular-shaped so existing audit readers keep
      // working; template_ids carries the full slot order.
      metadata: {
        course_id: courseId,
        template: templates.map(t => t.os_name).join(' + '),
        template_id: templates[0].id,
        template_ids: templates.map(t => t.id),
        scope: 'selected',
      },
      targets: students.map(st => ({
        id: st.id, label: st.email,
        metadata: { course_id: courseId, template_id: templates[0].id },
      })),
    });

    startProvision({ courseId, courseName: course.course_name, courseCode: course.code, challenge, templates, students, resources });
  } catch (error) {
    console.error('[CLE] Provision VMs error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * POST /provision-all — Provision a workstation for every actively-enrolled
 * student who doesn't already have one. This is the "deploy the class" button.
 *
 * Runs the same cluster capacity pre-flight the admin group deploy uses: without
 * `confirm: true` it returns a preview instead of deploying, so the instructor
 * sees the resource impact before committing a whole cohort.
 */
router.post('/provision-all', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const { confirm } = req.body;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Templates BEFORE resources: a scalar sizing spec is scoped by slot count.
    const templates = await loadWorkstationTemplates(req.body);
    const resources = parseRequestedResources(req.body, templates.length);
    const challenge = await loadCourseLab(course);
    const { students, skipped } = await resolveTargetStudents(courseId, null);

    if (!students.length) {
      return res.status(400).json({
        error: 'Every enrolled student already has a workstation, or none are eligible',
        skipped,
      });
    }

    if (!confirm) {
      try {
        // One entry per workstation slot; the gateway is counted by the guard
        // itself. attackBoxes stays false — this path never deploys a Kali.
        const preview = await buildDeployPreview({
          numLanes: students.length,
          attackBoxes: false,
          challengeVmCount: templates.length,
          proxmoxAPI,
          cybercoreQuery,
        });
        return res.json({
          preview: true,
          student_count: students.length,
          // Joined rather than an array: the UI renders this with escHtml, so a
          // string needs no client change to describe a two-machine deploy.
          template: templates.map(t => t.os_name).join(' + '),
          // Echoed so the confirm step can show what the cohort will cost at the
          // chosen size. buildDeployPreview gates on node headroom, not per-VM
          // sizing, so this is informational only.
          ...(resources ? { resources } : {}),
          ...(skipped.length ? { skipped } : {}),
          ...preview,
        });
      } catch (err) {
        // A failed pre-flight must not block the deploy — the admin path treats
        // it the same way. Fall through and provision.
        console.error('[CLE] Pre-flight check failed:', err.message);
      }
    }

    res.json({
      success: true,
      message: `Provisioning started for ${students.length} student(s)`,
      count: students.length,
      progress_url: `/api/cle/courses/${courseId}/vms/provision-progress`,
      ...(resources ? { resources } : {}),
      ...(skipped.length ? { skipped } : {}),
    });

    audit.batch({
      req,
      source: 'cle',
      action: 'vm.provisioned_bulk',
      targetAction: 'vm.provisioned',
      target: { type: 'course', id: courseId, label: course.course_name },
      metadata: {
        course_id: courseId,
        template: templates.map(t => t.os_name).join(' + '),
        template_id: templates[0].id,
        template_ids: templates.map(t => t.id),
        scope: 'whole_class',
      },
      targets: students.map(st => ({
        id: st.id, label: st.email,
        metadata: { course_id: courseId, template_id: templates[0].id },
      })),
    });

    startProvision({ courseId, courseName: course.course_name, courseCode: course.code, challenge, templates, students, resources });
  } catch (error) {
    console.error('[CLE] Provision-all error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * GET /provision-progress — Live phase/ETA for an in-flight class deploy.
 * 404 once the deploy has finished and aged out; the client should fall back to
 * polling GET / for lane status.
 */
router.get('/provision-progress', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const progress = laneProvision.getProvisionProgress(courseId);
    if (!progress) return res.status(404).json({ error: 'No active deployment for this course' });
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /bulk-delete — Tear down several workstation lanes in one pass.
 *
 * POST rather than DELETE-with-a-body: every existing bulk operation in this
 * codebase is a POST with an array, and DELETE bodies are unspecified in
 * RFC 9110 and stripped by some intermediaries.
 *
 * Takes lane_ids, never student_ids. The lane is the thing being destroyed, a
 * user can hold more than one row in a course, and GET / deliberately lists
 * lanes whose owner has dropped the course — exactly the leftovers an
 * instructor needs to clean up, which student resolution would skip as
 * "not enrolled".
 *
 * SYNCHRONOUS on purpose. teardownLanes' dominant costs are per-CALL, not
 * per-lane — one 30s stop-wait ceiling, up to three 8s orphan rounds, one disk
 * sweep per node — so twelve lanes cost roughly what the single-lane DELETE
 * below already costs synchronously today, and twelve sequential calls would
 * pay all of it twelve times. Nothing in front of this sets a response timeout
 * (Caddy has no transport block; server.js sets no requestTimeout).
 */
router.post('/bulk-delete', instructorOnly, async (req, res) => {
  let claimed = null;
  try {
    const { courseId } = req.params;
    // Shape first, before any DB work — the order /provision uses.
    const { ids, skipped } = parseLaneIds(req.body);

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // ONE scoped query. Its material_id IS NULL predicate is the only thing
    // standing between this endpoint and an assignment's lanes being destroyed
    // through a teardown path that knows nothing about flag snapshots.
    const lanes = await laneProvision.findCourseWorkstationLanes(courseId, ids);
    const found = new Set(lanes.map(l => l.lane_id));
    for (const id of ids) {
      // One opaque reason on purpose. Distinguishing "another course" from
      // "that is a lab lane" from "already gone" would make this endpoint an
      // oracle for lanes the caller cannot otherwise see.
      if (!found.has(id)) skipped.push({ lane_id: id, reason: 'not in this course' });
    }
    if (lanes.length === 0) {
      return res.status(404).json({
        error: 'None of the selected lanes are in this course', skipped,
      });
    }

    // Check and claim in ONE synchronous block, every await already done. A
    // check, an await, then a claim leaves the double-click window open —
    // Node cannot interleave two synchronous statements, and that is the only
    // property making this a mutex at all.
    laneProvision.assertNoConflictingWorkstationOperation({ courseId });
    claimed = laneProvision.progressIdForCourseRebuild(courseId);
    const progress = laneDeployer.initProgress(
      claimed, `Delete — ${course.course_name}`, lanes.length);
    // Nothing polls this: the response is synchronous and a deleted row simply
    // vanishing from GET / is already a completion signal on the 8s refresh.
    // The entry exists so courseOperationsInFlight can see the lock.
    laneDeployer.setPhase(progress, 'deleting',
      `Removing ${lanes.length} workstation lane(s)`);

    // SERVER-DERIVED ids — never req.body.lane_ids. Everything in this array
    // has been through the scoped query above.
    const laneIds = lanes.map(l => l.lane_id);
    const result = await laneDeployer.teardownLanes(laneIds);
    const { status, success, message } = bulkDeleteStatus(result, laneIds.length);

    audit.batch({
      req,
      source: 'cle',
      action: 'vm.destroyed_bulk',
      targetAction: 'vm.destroyed',
      target: { type: 'course', id: courseId, label: course.course_name },
      status: success ? 'success' : 'failure',
      metadata: {
        course_id: courseId, scope: 'selected',
        requested: laneIds.length,
        lanes_deleted: result.lanes_deleted,
        lanes_kept_for_retry: result.lanes_kept_for_retry,
        vms_destroyed: result.vms_destroyed,
        orphan_disks_swept: result.orphan_disks_swept,
        errors: (result.errors || []).slice(0, 5),
      },
      // targets[].id is the USER id, with the lane in metadata — the shape
      // every other per-student row in this file uses.
      targets: lanes.map(l => ({
        id: l.user_id, label: l.student_email,
        status: success ? 'success' : 'failure',
        reason: success ? null : 'teardown left machines behind',
        metadata: { course_id: courseId, lane_id: l.lane_id, vxlan_id: l.vxlan_id },
      })),
    });

    res.status(status).json({
      success,
      message,
      requested: laneIds.length,
      lanes_deleted: result.lanes_deleted,
      lanes_kept_for_retry: result.lanes_kept_for_retry,
      vms_destroyed: result.vms_destroyed,
      orphan_disks_swept: result.orphan_disks_swept,
      errors: result.errors || [],
      warnings: result.warnings || [],
      ...(skipped.length ? { skipped } : {}),
    });
  } catch (error) {
    console.error('[CLE] Bulk delete error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  } finally {
    // A leaked claim 409s every workstation operation on this course for an
    // hour — finishProgress only schedules the entry for deletion then.
    if (claimed) laneDeployer.finishProgress(claimed);
  }
});

/**
 * POST /redeploy — Rebuild the machines on the selected lanes.
 *
 * DEFAULT (in place): destroys and re-clones the machines INSIDE each lane.
 * The lane row, vxlan_id, gateway, gateway_wan_ip, console host:port and
 * Guacamole connections all survive, so connection details already handed to
 * students keep working. With exactly one lane selected, `slots` narrows it to
 * a subset; every other machine is left running and untouched.
 *
 * full_lane: tears the lane down and deploys a fresh one. New VXLAN, new
 * console address, new Guacamole connections — everything a student has
 * written down becomes wrong. For lanes whose gateway is broken, which the
 * in-place path refuses by design.
 *
 * Both replay each lane's OWN recorded machines and sizing. There is no
 * template picking: a roster where some students have one machine and others
 * three stays that way.
 *
 * 202 + progress_url, mirroring the per-student lab redeploy. Everything that
 * can be checked cheaply is checked BEFORE the 202, while the student still
 * has working machines.
 */
router.post('/redeploy', instructorOnly, async (req, res) => {
  let claimed = null;
  try {
    const { courseId } = req.params;
    const { ids, skipped } = parseLaneIds(req.body);

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const found = await laneProvision.findCourseWorkstationLanes(courseId, ids);
    const foundIds = new Set(found.map(l => l.lane_id));
    for (const id of ids) {
      if (!foundIds.has(id)) skipped.push({ lane_id: id, reason: 'not in this course' });
    }
    if (found.length === 0) {
      return res.status(404).json({
        error: 'None of the selected lanes are in this course', skipped,
      });
    }

    const { slots, fullLane } = parseRedeployRequest(req.body, found);

    const lanes = [];
    for (const l of found) {
      const verdict = redeployEligibility(l, fullLane);
      if (verdict.ok) lanes.push(l);
      else skipped.push({ lane_id: l.lane_id, reason: verdict.reason });
    }
    if (lanes.length === 0) {
      // With one lane there is no batch to partially honour, so an empty
      // success would just look like nothing happened.
      const e = new Error(found.length === 1
        ? `This lane cannot be rebuilt in place: ${skipped[skipped.length - 1].reason}.`
        : 'None of the selected lanes can be rebuilt.');
      e.status = 409; throw e;
    }

    // Pre-flight the templates for the whole batch in one query. Safe to use
    // ANY here precisely because these ids come from lane config rather than
    // from the client.
    const wantTemplates = [...new Set(
      lanes.flatMap(l => (l.config?.workstations || [])
        .map(w => w && w.template_id)
        .concat([l.config?.template_id]))
        .filter(Boolean)
    )];
    if (wantTemplates.length) {
      const okT = await cybercoreQuery(
        `SELECT id FROM cybercore_template_catalog`,
        [wantTemplates]
      );
      const alive = new Set(okT.rows.map(r => r.id));
      const dead = wantTemplates.filter(t => !alive.has(t));
      if (dead.length) {
        const e = new Error(
          `${dead.length} template(s) these lanes were built from are no longer active in the catalog, so the machines cannot be replaced. Re-activate them, or rebuild the whole lane with a template you choose.`);
        e.status = 409; throw e;
      }
    }

    // Capacity BEFORE any teardown. Afterwards is too late — the student has
    // nothing and cannot be rebuilt.
    let challenge = null;
    if (fullLane) {
      challenge = await loadCourseLab(course);
      const free = await vulnLab.countFreeLanes(challenge.vxlan_block);
      if (free + lanes.length < lanes.length) {
        const e = new Error(`Not enough free lanes in this course's VXLAN block to rebuild ${lanes.length}.`); e.status = 409; throw e;
      }
    }

    const single = lanes.length === 1 ? lanes[0].lane_id : null;

    // Check and claim in ONE synchronous block, every await already done.
    laneProvision.assertNoConflictingWorkstationOperation({ courseId, laneId: single });
    claimed = single
      ? laneProvision.progressIdForLane(courseId, single)
      : laneProvision.progressIdForCourseRebuild(courseId);
    const progress = laneDeployer.initProgress(
      claimed, `Rebuild \u2014 ${course.course_name}`, lanes.length);
    laneDeployer.setPhase(progress, 'preparing',
      `Rebuilding ${lanes.length} lane(s)`);
    // Seed every row so the client renders the whole batch from its first poll
    // instead of watching lanes appear one at a time.
    for (const l of lanes) {
      progress.lanes[l.lane_id] = {
        user: l.student_email, vxlan: l.vxlan_id, node: (l.config || {}).node || null,
        status: 'pending', workstations: machineSlotsOf(l).length,
        slots: slots || machineSlotsOf(l), error: null,
      };
    }

    const progressUrl = `/api/cle/courses/${courseId}/vms/redeploy-progress${single ? `?lane_id=${single}` : ''}`;

    audit.batch({
      req,
      source: 'cle',
      action: 'lane.redeployed_bulk',
      targetAction: 'lane.redeployed',
      target: { type: 'course', id: courseId, label: course.course_name },
      metadata: {
        course_id: courseId,
        mode: fullLane ? 'full_lane' : 'in_place',
        full_lane: fullLane,
        // An auditor tracing "why did this student's RDP address change"
        // needs this to be findable.
        endpoint_changed: fullLane,
        scope: lanes.length === 1 ? 'single' : 'selected',
        lane_count: lanes.length,
        ...(slots ? { slots } : {}),
      },
      targets: lanes.map(l => ({
        id: l.user_id, label: l.student_email,
        metadata: {
          course_id: courseId, lane_id: l.lane_id, vxlan_id: l.vxlan_id,
          slots: slots || machineSlotsOf(l),
        },
      })),
    });

    res.status(202).json({
      success: true,
      message: fullLane
        ? `Rebuilding ${lanes.length} whole lane(s)`
        : `Rebuilding machines on ${lanes.length} lane(s)`,
      mode: fullLane ? 'full_lane' : 'in_place',
      count: lanes.length,
      lanes: lanes.map(l => ({
        lane_id: l.lane_id, user_id: l.user_id, student_email: l.student_email,
        slots: slots || machineSlotsOf(l),
        console_via: (l.config || {}).console_via || null,
      })),
      progress_id: claimed,
      progress_url: progressUrl,
      ...(skipped.length ? { skipped } : {}),
    });

    // Frozen before the IIFE: re-deriving any of this inside the background
    // block would read post-teardown state.
    const claimedId = claimed;
    claimed = null;   // ownership handed to the background block
    const ctx = Object.freeze({
      courseId, course, lanes, slots, fullLane, challenge, progress,
      courseCode: course.code, courseName: course.course_name,
    });

    (async () => {
      try {
        if (ctx.fullLane) await runFullLaneRebuild(ctx, claimedId);
        else await runInPlaceRebuild(ctx, claimedId);
      } catch (e) {
        console.error('[CLE] Rebuild batch failed:', e.message);
        if (ctx.progress) ctx.progress.error = e.message;
      } finally {
        laneDeployer.finishProgress(claimedId);
      }
    })();
  } catch (error) {
    console.error('[CLE] Redeploy error:', error.message);
    if (claimed) { laneDeployer.finishProgress(claimed); claimed = null; }
    // Only the 202 itself can throw with headers already sent, and replying
    // twice throws again out of an async handler Express 4 does not catch.
    if (res.headersSent) return;
    res.status(error.status || 500).json({ error: error.message });
  }
});

/** In-place: one shared clone semaphore, lanes bounded by max_concurrent_lanes. */
async function runInPlaceRebuild(ctx, progressId) {
  const { lanes, slots, progress } = ctx;
  // ONE semaphore for the whole batch: max_concurrent_clones is what keeps a
  // 24-lane rebuild from flattening a node's disks, and a per-lane semaphore
  // would bound nothing across the batch.
  const cloneSem = laneDeployer.createCloneSemaphore();
  laneDeployer.setPhase(progress, 'cloning', `Rebuilding machines: 0/${lanes.length} complete`);

  let done = 0;
  for (const lane of lanes) {
    try {
      const r = await laneDeployer.rebuildLaneWorkstations({
        laneId: lane.lane_id,
        slots: slots || null,
        progress,
        cloneSem,
      });
      if (r.status === 'active' && r.errors.length === 0) progress.succeeded++;
      else progress.failed++;
    } catch (e) {
      progress.failed++;
      if (progress.lanes[lane.lane_id]) {
        progress.lanes[lane.lane_id].status = 'error';
        progress.lanes[lane.lane_id].error = e.message;
      }
      console.error(`[CLE] Rebuild of lane ${lane.lane_id} failed: ${e.message}`);
    }
    progress.completed = ++done;
    laneDeployer.setPhase(progress, 'cloning',
      `Rebuilding machines: ${done}/${lanes.length} complete`);
  }
}

/**
 * Whole lane: teardown, then a fresh deploy from the machines the lane
 * recorded. Gated on the teardown coming back clean — teardownLanes keeps the
 * row as 'error' when machines survive, and deploying over survivors collides
 * on the gateway VMID, which is derived from the VXLAN.
 */
async function runFullLaneRebuild(ctx, progressId) {
  const { courseId, lanes, challenge, progress, courseName, courseCode } = ctx;
  laneDeployer.setPhase(progress, 'preparing', 'Tearing down the current lanes');

  let done = 0;
  for (const lane of lanes) {
    try {
      const cfg = lane.config || {};
      const recorded = Array.isArray(cfg.workstations) ? cfg.workstations : [];
      const templateIds = recorded.length
        ? recorded.slice().sort((a, b) => a.slot - b.slot).map(w => w.template_id)
        : [cfg.template_id];
      const resources = recorded.length
        ? recorded.slice().sort((a, b) => a.slot - b.slot).map(w => w.resources || null)
        : (cfg.resources || null);

      const templates = [];
      for (const id of templateIds) templates.push(await loadWorkstationTemplate(id));

      const teardown = await laneDeployer.teardownLanes([lane.lane_id]);
      if (teardown.lanes_kept_for_retry > 0) {
        throw new Error(
          `Could not fully tear the lane down (${(teardown.errors || [])[0] || 'machines survived'}), so it was not rebuilt.`);
      }

      await laneProvision.provisionLanes({
        courseId, challenge, templates, resources,
        students: [{ id: lane.user_id, email: lane.student_email }],
        courseName, courseCode,
        // Publish under the claim this route already holds, not under the
        // provision key — otherwise the two progress endpoints disagree and
        // deployLanes finishes a claim that is not its own.
        progressId, progressLabel: `Rebuild \u2014 ${courseName}`,
      });
      progress.succeeded++;
    } catch (e) {
      progress.failed++;
      if (progress.lanes[lane.lane_id]) {
        progress.lanes[lane.lane_id].status = 'error';
        progress.lanes[lane.lane_id].error = e.message;
      }
      console.error(`[CLE] Full rebuild of lane ${lane.lane_id} failed: ${e.message}`);
    }
    progress.completed = ++done;
  }
}

/**
 * GET /redeploy-progress — Live progress for a rebuild.
 *
 * Separate from /provision-progress, which is hard-wired to the course-wide
 * provision key. Multiplexing the two would make each return the other's
 * numbers depending on timing, and the client stops polling on
 * phase === 'complete' — so a provision finishing mid-rebuild would kill the
 * wrong banner.
 */
router.get('/redeploy-progress', instructorOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneId = req.query.lane_id ? String(req.query.lane_id) : null;
    // Validated before it becomes part of a registry key.
    if (laneId && !LANE_ID_RE.test(laneId)) {
      return res.status(400).json({ error: 'lane_id is not a lane id' });
    }
    const progress = laneProvision.getRebuildProgress(courseId, laneId);
    if (!progress) return res.status(404).json({ error: 'No active rebuild for this course' });
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /resize — Change CPU and RAM on machines that are ALREADY DEPLOYED,
 * without destroying what is on them.
 *
 * The counterpart to /redeploy, and the opposite trade. A redeploy replaces the
 * machine: it can change anything, and everything the student did is gone. A
 * resize stops the machine, edits two numbers in its Proxmox config and starts
 * it again: the disk is never touched, so files, installed software and
 * configuration all survive. Between "the class is under-sized" and "wipe
 * everyone's work", this is the missing third option.
 *
 * ADMIN-ONLY — see the adminOnly docblock at the top of this file.
 *
 * Body:
 *   {
 *     scope: 'lanes' | 'course' | 'template',   // default 'lanes'
 *     lane_ids: [...],        // scope=lanes
 *     template_id: '...',     // scope=template
 *     slots: [1],             // optional machine subset, ANY number of lanes
 *     resources: { cores?, memory_mb? },
 *     confirm: true           // omit for a capacity preview
 *   }
 *
 * TWO-STEP, like /provision-all. Without `confirm` this returns a 200 preview:
 * the machines it resolved to and what the change would do to each node's
 * memory. Raising RAM across a cohort is the one way this feature can hurt a
 * cluster, and it commits memory that courses the caller cannot see are also
 * drawing on — so the number gets shown before it gets spent, not after.
 */
router.post('/resize', adminOnly, async (req, res) => {
  let claimed = null;
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const resources = parseResizeSpec(req.body);
    const scope = (req.body || {}).scope || 'lanes';

    // Lane resolution. For 'lanes' the ids are validated and capped first; for
    // the other two scopes the client never names lanes at all and the server
    // enumerates them, which is what makes "every VM from this template"
    // impossible to point at another course's machines.
    let found;
    let skipped = [];
    if (scope === 'lanes') {
      const parsed = parseLaneIds(req.body);
      skipped = parsed.skipped;
      found = await laneProvision.findCourseWorkstationLanes(courseId, parsed.ids);
      const foundIds = new Set(found.map(l => l.lane_id));
      for (const id of parsed.ids) {
        if (!foundIds.has(id)) skipped.push({ lane_id: id, reason: 'not in this course' });
      }
    } else if (scope === 'course' || scope === 'template') {
      found = await laneProvision.findCourseWorkstationLanes(courseId);
    } else {
      const e = new Error(`unknown scope '${scope}'`); e.status = 400; throw e;
    }

    if (!found.length) {
      return res.status(404).json({
        error: scope === 'lanes'
          ? 'None of the selected lanes are in this course'
          : 'This course has no workstation lanes',
        skipped,
      });
    }

    const resolved = resolveResizeTargets(req.body, found);
    const targets = resolved.targets;
    skipped = skipped.concat(resolved.skipped);

    if (!targets.length) {
      const e = new Error(found.length === 1
        ? `This lane has no machine that can be resized: ${(skipped[skipped.length - 1] || {}).reason || 'none matched'}.`
        : 'None of the selected machines can be resized.');
      e.status = 409; throw e;
    }

    // Live cluster read, ONCE for the batch. Two things come out of it that the
    // lane row cannot supply: the node a VM is on RIGHT NOW (a migrated machine's
    // recorded node is stale, and every call against the wrong host fails), and
    // whether it is running (which decides both the capacity maths and whether
    // it gets powered back on afterwards).
    const byVmid = {};
    try {
      const cluster = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
      for (const r of (cluster || [])) byVmid[String(r.vmid)] = r;
    } catch (e) {
      const err = new Error(
        `Could not read the cluster to see where these machines are (${e.message}). ` +
        `Nothing was changed.`);
      err.status = 503; throw err;
    }

    const live = [];
    for (const t of targets) {
      const l = byVmid[String(t.vmid)];
      if (!l) {
        skipped.push({
          lane_id: t.lane_id,
          reason: `slot ${t.slot} (vmid ${t.vmid}) is not in the cluster`,
        });
        continue;
      }
      live.push({
        ...t,
        node: l.node,
        running: l.status === 'running',
        current: { cores: Number(l.maxcpu) || null, memory_mb: Math.round((Number(l.maxmem) || 0) / 1048576) || null },
      });
    }
    if (!live.length) {
      const e = new Error('None of the selected machines exist in the cluster.');
      e.status = 409; throw e;
    }

    const preview = await buildResizePreview({ targets: live, resources, proxmoxAPI });

    // ── step one: preview ────────────────────────────────────────────────────
    if (req.body.confirm !== true) {
      return res.json({
        success: true,
        preview: true,
        ...preview,
        machines: live.map(t => ({
          lane_id: t.lane_id, slot: t.slot, vmid: t.vmid, node: t.node,
          hostname: t.hostname, student_email: t.student_email,
          running: t.running, current: t.current,
        })),
        ...(skipped.length ? { skipped } : {}),
      });
    }

    if (!preview.canProceed) {
      const e = new Error(preview.errors[0]); e.status = 409; throw e;
    }

    // ── step two: apply ──────────────────────────────────────────────────────
    const laneIds = [...new Set(live.map(t => t.lane_id))];
    const single = laneIds.length === 1 ? laneIds[0] : null;

    // Check and claim in ONE synchronous block, every await already done — the
    // progress registry is the only mutex this app has, and a check, an await
    // and then a claim leaves the double-click window wide open.
    laneProvision.assertNoConflictingWorkstationOperation({ courseId, laneId: single });
    claimed = single
      ? laneProvision.progressIdForLane(courseId, single)
      : laneProvision.progressIdForCourseResize(courseId);
    const progress = laneDeployer.initProgress(
      claimed, `Resize — ${course.course_name}`, live.length);
    laneDeployer.setPhase(progress, 'preparing', `Resizing ${live.length} machine(s)`);
    // Seeded so the client renders the whole batch from its first poll rather
    // than watching machines appear one at a time.
    for (const t of live) {
      progress.lanes[`${t.lane_id}:${t.slot}`] = {
        user: t.student_email, vxlan: null, node: t.node,
        status: 'pending', workstations: 1, slots: [t.slot], error: null,
      };
    }

    const progressUrl =
      `/api/cle/courses/${courseId}/vms/resize-progress${single ? `?lane_id=${single}` : ''}`;

    audit.batch({
      req,
      source: 'cle',
      action: 'lane.resized_bulk',
      targetAction: 'lane.resized',
      target: { type: 'course', id: courseId, label: course.course_name },
      metadata: {
        course_id: courseId,
        scope,
        machine_count: live.length,
        lane_count: laneIds.length,
        to: resources,
        // No endpoint_changed key, unlike the redeploy audit: a resize changes
        // no address, port or Guacamole connection, so nothing an instructor
        // has already handed out stops working.
        ...(req.body.slots ? { slots: req.body.slots } : {}),
        ...(scope === 'template' ? { template_id: req.body.template_id } : {}),
      },
      targets: live.map(t => ({
        id: t.user_id, label: t.student_email,
        metadata: {
          course_id: courseId, lane_id: t.lane_id, slot: t.slot, vmid: t.vmid,
          node: t.node, from: t.current, to: resources,
        },
      })),
    });

    res.status(202).json({
      success: true,
      message: `Resizing ${live.length} machine(s) on ${laneIds.length} lane(s)`,
      count: live.length,
      lanes: laneIds,
      progress_id: claimed,
      progress_url: progressUrl,
      ...(skipped.length ? { skipped } : {}),
    });

    // Frozen before the IIFE: re-deriving any of this inside the background
    // block would read post-stop state.
    const claimedId = claimed;
    claimed = null;   // ownership handed to the background block
    const ctx = Object.freeze({ courseId, live, resources, progress });

    (async () => {
      try {
        await runResizeBatch(ctx);
      } catch (e) {
        console.error('[CLE] Resize batch failed:', e.message);
        if (ctx.progress) ctx.progress.error = e.message;
      } finally {
        laneDeployer.finishProgress(claimedId);
      }
    })();
  } catch (error) {
    console.error('[CLE] Resize error:', error.message);
    if (claimed) { laneDeployer.finishProgress(claimed); claimed = null; }
    // Only the 202 itself can throw with headers already sent, and replying
    // twice throws again out of an async handler Express 4 does not catch.
    if (res.headersSent) return;
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * Run the resize across the batch, then write the outcome back to each lane.
 *
 * Bounded concurrency rather than the sequential loop runInPlaceRebuild uses:
 * a rebuild is disk-bound and its semaphore exists to stop 24 clones flattening
 * a node, whereas a resize does no disk I/O at all and is almost entirely spent
 * waiting for guests to shut down and boot. Serially, a 30-machine class would
 * take three quarters of an hour.
 */
async function runResizeBatch(ctx) {
  const { live, resources, progress } = ctx;
  laneDeployer.setPhase(progress, 'resizing', `Resizing machines: 0/${live.length} complete`);

  // Grouped so each lane's config is written ONCE, with every slot that
  // changed on it. One write per machine would have several concurrent workers
  // splicing the same lane row.
  const byLane = new Map();
  let done = 0;

  await runBatch(
    live,
    async (t) => {
      const key = `${t.lane_id}:${t.slot}`;
      const setStatus = (st, err) => {
        if (progress.lanes[key]) {
          progress.lanes[key].status = st;
          if (err !== undefined) progress.lanes[key].error = err;
        }
      };
      setStatus('running');

      const result = await vmResize.resizeOneVm({
        node: t.node,
        vmid: t.vmid,
        providerType: t.provider_type,
        resources,
        label: `${t.hostname || t.lane_name || t.lane_id} slot ${t.slot}`,
        onPhase: (phase) => setStatus(phase),
        // Durable intent, written BEFORE the guest is stopped. If this process
        // dies between the stop and the start, recoverInterruptedResizes() in
        // server.js finds this marker at boot and powers the machine back on.
        onIntent: async ({ was_running }) => {
          await markResizeInFlight(t, was_running);
        },
        // Cleared only when the machine ended in the power state it should be
        // in. Left in place otherwise, so recoverInterruptedResizes() picks it
        // up at the next boot and tries the start again — the marker is the
        // only durable record that a running machine was taken down.
        onSettled: async ({ settled }) => {
          if (settled) await clearResizeInFlight(t.lane_id);
        },
      });

      if (!byLane.has(t.lane_id)) byLane.set(t.lane_id, []);
      byLane.get(t.lane_id).push({ target: t, result });

      if (result.status === 'failed') { progress.failed++; setStatus('error', result.error); }
      else { progress.succeeded++; setStatus('done', null); }
      return result;
    },
    {
      concurrency: vmResize.RESIZE_CONCURRENCY,
      onProgress: () => {
        progress.completed = ++done;
        laneDeployer.setPhase(progress, 'resizing',
          `Resizing machines: ${done}/${live.length} complete`);
      },
    }
  );

  laneDeployer.setPhase(progress, 'recording', 'Recording the new sizing');
  for (const [laneId, entries] of byLane) {
    try {
      await recordLaneResize(laneId, entries);
    } catch (e) {
      console.error(`[CLE] Could not record the resize on lane ${laneId}: ${e.message}`);
    }
  }
}

/**
 * Write the "this machine is down for a resize" marker.
 *
 * Deliberately does NOT set lane status to 'deploying'. The lane is genuinely
 * active — its gateway is up and its other machines are untouched — and
 * recoverStrandedLanes() sweeps every 'deploying' row without a config.rebuild
 * key to 'error' on boot, which would condemn a healthy lane on every restart.
 * In-flight state is held by the progress-registry mutex instead; this marker
 * exists only so power can be restored.
 */
async function markResizeInFlight(t, wasRunning) {
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = jsonb_set(
                       COALESCE(config, '{}'::jsonb), '{resize}',
                       COALESCE(config->'resize', '{}'::jsonb) || $2::jsonb),
            updated_at = NOW()
      WHERE lane_id = $1`,
    [t.lane_id, JSON.stringify({
      status: 'running',
      at: new Date().toISOString(),
      in_flight: {
        slot: t.slot, vmid: t.vmid, node: t.node,
        provider_type: t.provider_type, was_running: !!wasRunning,
      },
    })]
  ).catch(e => console.warn(`[CLE] resize marker write failed for ${t.lane_id}: ${e.message}`));
}

async function clearResizeInFlight(laneId) {
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = jsonb_set(
                       COALESCE(config, '{}'::jsonb), '{resize}',
                       COALESCE(config->'resize', '{}'::jsonb) - 'in_flight'),
            updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId]
  ).catch(() => {});
}

/**
 * Persist the achieved sizing onto the lane's slot records.
 *
 * This is what makes the change stick beyond the running VM. The VM Management
 * table renders config.workstations[].resources, and — more importantly —
 * rebuildLaneWorkstations replays it as "the sizing that was ACHIEVED, not the
 * request". Skip this write and the numbers in the UI stay stale AND the next
 * rebuild silently reverts the machine to its old size.
 *
 * Goes through spliceLaneWorkstations so untouched slots stay byte-identical,
 * and through flatResourceMirrorPatch so the flat slot-0 mirror is written only
 * when slot 0 was actually one of the machines resized.
 */
async function recordLaneResize(laneId, entries) {
  const lane = (await cybercoreQuery(
    `SELECT lane_id, name, vxlan_id, config FROM cybercore_lane WHERE lane_id = $1`, [laneId]
  )).rows[0];
  if (!lane) return;

  const existing = laneDeployer.laneWorkstationRecords(lane);
  const bySlot = new Map(existing.map(r => [r.slot, r]));

  const records = [];
  const touchedKeys = [];
  const slotsPatch = {};

  for (const { target, result } of entries) {
    const base = bySlot.get(target.slot);
    if (!base) continue;
    touchedKeys.push(String(target.slot));

    const record = { ...base };
    if (result.status === 'resized' || result.status === 'unchanged') {
      record.resources = {
        ...(base.resources || {}),
        ...(result.after.cores ? { cores: result.after.cores } : {}),
        ...(result.after.memory_mb ? { memory_mb: result.after.memory_mb } : {}),
      };
      record.resource_warnings = result.warnings.length ? result.warnings : null;
      record.resized_at = new Date().toISOString();
    } else {
      // The recorded sizing is left ALONE on failure — it still describes the
      // machine, which was not changed.
      record.resource_warnings = [result.error].concat(result.warnings).filter(Boolean);
    }
    records.push(record);

    slotsPatch[String(target.slot)] = {
      status: result.status,
      at: new Date().toISOString(),
      from: result.before || null,
      to: (result.status === 'failed') ? null : (result.after || null),
      power_restored: result.power_restored,
      forced: result.forced,
      ...(result.error ? { message: String(result.error).slice(0, 500) } : {}),
    };
  }
  if (!records.length) return;

  const failedCount = entries.filter(e => e.result.status === 'failed').length;
  const firstError = (entries.find(e => e.result.error) || { result: {} }).result.error || null;
  const resizePatch = {
    resize: {
      at: new Date().toISOString(),
      status: failedCount === 0 ? 'ok'
        : (failedCount < entries.length ? 'partial' : 'failed'),
      error: firstError,
      slots: slotsPatch,
    },
  };

  await laneDeployer.spliceLaneWorkstations(
    laneId,
    records,
    touchedKeys,
    { ...laneDeployer.flatResourceMirrorPatch(records), ...resizePatch }
    // No status argument: the lane was active throughout and stays active.
  );
}

/**
 * GET /resize-progress — Live progress for a resize.
 *
 * Its own endpoint and its own registry key rather than sharing
 * /redeploy-progress. The client stops polling the moment it reads
 * phase === 'complete', so multiplexing the two would let a finishing rebuild
 * tear down the resize banner — the same reason /redeploy-progress is separate
 * from /provision-progress.
 */
router.get('/resize-progress', adminOnly, async (req, res) => {
  try {
    const { courseId } = req.params;
    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneId = req.query.lane_id ? String(req.query.lane_id) : null;
    // Validated before it becomes part of a registry key.
    if (laneId && !LANE_ID_RE.test(laneId)) {
      return res.status(400).json({ error: 'lane_id is not a lane id' });
    }
    const progress = laneProvision.getResizeProgress(courseId, laneId);
    if (!progress) return res.status(404).json({ error: 'No active resize for this course' });
    res.json(progress);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /:laneId/console — Return a Guacamole launch URL for a student's
 * workstation, resolved from the lane's stored guac_connection_id.
 */
router.get('/:laneId/console', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;
    if (process.env.GUAC_ENABLED !== 'true') {
      return res.status(503).json({ error: 'Remote console is not enabled on this instance.' });
    }

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneRes = await cybercoreQuery(
      `SELECT config FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2
          AND config->>'material_id' IS NULL AND status <> 'deleted'`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    const connId = laneRes.rows[0].config?.guac_connection_id;
    if (!connId) return res.status(404).json({ error: 'No remote console is configured for this workstation yet' });

    // mintGuacToken, NOT getGuacToken: the cached token is the one this process
    // uses for every Guacamole call it makes. Handing that same token to a
    // browser means the console tab's logout (or its session ending) destroys
    // the orchestrator's session too, and every subsequent Guac call — console
    // provisioning, and the connection cleanup in lane teardown — fails with
    // 403 PERMISSION_DENIED until the cache turns over ~50 minutes later.
    let guacToken = null;
    try { guacToken = (await mintGuacToken()).authToken; } catch (e) {
      console.warn(`[CLE] Guac token fetch failed: ${e.message}`);
    }

    // An instructor opening a console on a student's machine is exactly the
    // kind of access an admin needs to be able to review after the fact.
    audit.log({
      req,
      action: 'access.console_opened',
      source: 'cle',
      target: { type: 'lane', id: laneId },
      metadata: { course_id: courseId, connection_id: connId },
    });

    res.json({
      launchUrl: buildGuacLaunchUrl(connId),
      connection_id: connId,
      guac_url: GUAC_URL,
      ...(guacToken ? { guacToken, dataSource: GUAC_DS } : { clearGuacAuth: true }),
    });
  } catch (error) {
    console.error('[CLE] Console error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

/**
 * GET /:laneId/topology — the live network diagram for one of this course's lanes.
 *
 * The instructor-scoped door onto the same builder the admin route uses, so an
 * instructor sees the identical picture without needing admin. It cannot simply
 * be the admin route with a relaxed role: that handler does NO course scoping and
 * will describe any laneId it is handed, so widening it to `instructor` would let
 * every instructor read every lane in the range.
 *
 * Unlike the rest of this file, the material_id guard is deliberately DROPPED.
 * The scope note at the top of this file exists because DELETE would destroy a
 * lab lane through the wrong teardown path; a read-only diagram has no such
 * hazard, and an instructor wants to see a vulnerable-lab lane's topology at
 * least as much as a workstation's.
 */
router.get('/:laneId/topology', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    const laneRes = await cybercoreQuery(
      `SELECT lane_id FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2 AND status <> 'deleted'`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    res.json(await buildLaneTopology(laneId));
  } catch (error) {
    console.error('[CLE] Topology error:', error.message);
    res.status(error.status || 500).json({ error: error.message });
  }
});

/**
 * DELETE /:laneId — Tear down a student's workstation lane (workstation +
 * gateway + Guac connection + workspace records + lane row).
 */
router.delete('/:laneId', instructorOnly, async (req, res) => {
  try {
    const { courseId, laneId } = req.params;

    const course = await getManagedCourse(courseId, req.user);
    if (!course) return res.status(403).json({ error: 'Course not found or access denied' });

    // Confirm the lane belongs to this course before destroying anything.
    const laneRes = await cybercoreQuery(
      // material_id IS NULL: a vulnerable-lab lane must be removed through
      // DELETE /labs/:labId, which also clears the assignment it belongs to.
      `SELECT lane_id FROM cybercore_lane
        WHERE lane_id = $1 AND config->>'course_id' = $2 AND config->>'material_id' IS NULL`,
      [laneId, courseId]
    );
    if (laneRes.rows.length === 0) return res.status(404).json({ error: 'Lane not found in this course' });

    const result = await laneProvision.teardownLane(laneId);
    audit.log({
      req,
      action: 'vm.destroyed',
      source: 'cle',
      target: { type: 'lane', id: laneId },
      metadata: { course_id: courseId },
    });
    res.json({ success: true, message: 'Workstation lane removed', ...result });
  } catch (error) {
    console.error('[CLE] Delete VM error:', error.message);
    res.status(500).json({ error: error.message });
  }
});

module.exports = router;
