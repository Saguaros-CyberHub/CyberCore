/**
 * ============================================================================
 * TICKET MACHINES — "which machine is this about?", as a list of options
 * ============================================================================
 * Pure projection: rows in, option objects out. No queries, no imports, so the
 * whole thing is testable without a cluster or a database.
 *
 * A student's machines come from two places that do not overlap cleanly:
 *
 *   - LANE workstations (cybercore_lane.config.workstations[]) — the machines a
 *     course deployment gave them. These carry config.course_id, which is what
 *     lets the picker filter by the selected course.
 *   - SELF-SERVICE workstations (cybercore_vm_instance ⋈ cybercore_allocation)
 *     — machines they deployed themselves, belonging to no course.
 *
 * TWO THINGS THIS DELIBERATELY DOES NOT DO
 * ----------------------------------------------------------------------------
 * 1. It does NOT filter on `config.material_id IS NULL`.
 *
 *    findCourseWorkstationLanes() in cle/utils/lane-provision.js carries that
 *    predicate and its comment explains why: it is a TEARDOWN SAFETY property,
 *    keeping vulnerable-lab lane ids out of anything that calls teardownLanes.
 *    We destroy nothing. Copying it here would hide every assignment lab
 *    machine from the picker — which is precisely the category of machine
 *    students file tickets about.
 *
 * 2. It does NOT decide which lanes are eligible. The caller supplies rows it
 *    has already filtered with claimsSql() from utils/lane-claims.js. That
 *    predicate has exactly one definition in this codebase, for reasons that
 *    file documents at length, and this module is not going to become a
 *    seventh spelling of it.
 *
 * The slot records come from laneWorkstationRecords() in utils/lane-deployer.js
 * rather than being re-derived here. Lanes deployed before config.workstations[]
 * existed carry only flat slot-0 keys, and that function already owns the
 * fallback — a second copy would drift the first time the shape changed.
 * ============================================================================
 */

/** Lane machines first, then self-service. Stable, so the <select> never jumps. */
const KIND_LANE = 'lane_workstation';
const KIND_SELF = 'workstation';

function str(v) {
  return v == null ? null : String(v);
}

function toInt(v) {
  if (v == null || v === '') return null;
  const n = Number(v);
  return Number.isFinite(n) ? n : null;
}

/**
 * One option from a lane slot record.
 *
 * The label is what the student picks from and what gets SNAPSHOT onto the
 * ticket, so it has to stay meaningful after the lane is torn down. Hostname
 * first because that is the name they see in Guacamole and in their own shell
 * prompt; the lane name plus slot is the fallback; the raw VMID is the last
 * resort and is still better than a bare UUID.
 */
function laneMachineOption(lane, slot) {
  const laneId = str(lane.lane_id);
  const laneName = str(lane.name);
  const vmid = toInt(slot.vmid);
  const label = str(slot.hostname)
    || (laneName ? (slot.slot === 0 ? laneName : `${laneName} slot ${slot.slot}`) : null)
    || (vmid == null ? 'unnamed machine' : `VM ${vmid}`);

  return {
    key: `lane:${laneId}:${slot.slot}`,
    label,
    kind: KIND_LANE,
    laneId,
    laneName,
    laneStatus: str(lane.status),
    slot: toInt(slot.slot),
    vmid,
    ip: str(slot.ip),
    // The only field that makes course filtering possible. Lanes deployed by
    // POST /api/admin/deploy-group carry no course reference at all, so this is
    // legitimately null for a whole class of real machines — they show under
    // every course rather than none.
    courseId: str((lane.config || {}).course_id),
  };
}

/** One option from a self-service workstation row. Never belongs to a course. */
function selfServiceOption(row) {
  const vmid = toInt(row.provider_vmid);
  return {
    key: `vm:${str(row.vm_instance_id)}`,
    label: str(row.vm_name) || (vmid == null ? 'unnamed machine' : `VM ${vmid}`),
    kind: KIND_SELF,
    laneId: null,
    laneName: null,
    laneStatus: null,
    slot: null,
    vmid,
    ip: str(row.ip_address),
    courseId: null,
  };
}

/**
 * Every machine this student could be writing about, as picker options.
 *
 * @param {Array<{lane: object, slots: Array<object>}>} lanes
 *        Lane rows already filtered with claimsSql(), each paired with its
 *        laneWorkstationRecords() output.
 * @param {Array<object>} workstations
 *        Self-service rows: { vm_instance_id, vm_name, provider_vmid, ip_address }.
 * @returns {Array<object>} options, lane machines first
 *
 * DEDUPE BY VMID, and it is not theoretical: a lane workstation is ALSO
 * registered as a cybercore_resource with an allocation to the same student, so
 * a machine can legitimately arrive down both paths. Showing "cybr400-pat-ws0"
 * twice in a dropdown makes the picker look broken; the lane entry wins because
 * it is the one that carries the course.
 */
function projectMachines(lanes, workstations) {
  const options = [];
  const seenVmids = new Set();
  const seenKeys = new Set();

  for (const entry of Array.isArray(lanes) ? lanes : []) {
    const lane = entry && entry.lane;
    if (!lane || !lane.lane_id) continue;
    for (const slot of Array.isArray(entry.slots) ? entry.slots : []) {
      if (!slot || slot.slot == null) continue;
      const opt = laneMachineOption(lane, slot);
      if (seenKeys.has(opt.key)) continue;
      seenKeys.add(opt.key);
      if (opt.vmid != null) seenVmids.add(opt.vmid);
      options.push(opt);
    }
  }

  for (const row of Array.isArray(workstations) ? workstations : []) {
    if (!row || !row.vm_instance_id) continue;
    const opt = selfServiceOption(row);
    if (seenKeys.has(opt.key)) continue;
    if (opt.vmid != null && seenVmids.has(opt.vmid)) continue;
    seenKeys.add(opt.key);
    if (opt.vmid != null) seenVmids.add(opt.vmid);
    options.push(opt);
  }

  return options;
}

/**
 * Resolve a client-supplied key against a server-built list.
 *
 * This is the ONLY way a machineKey from a request body may be turned into
 * ticket columns. The route rebuilds the list for the authenticated user and
 * looks the key up here, so a student cannot attach someone else's machine to
 * a ticket by guessing an id — an unknown key simply is not in their list.
 * Never parse the key and trust its parts.
 */
function findMachine(options, key) {
  if (!key) return null;
  const wanted = String(key);
  return (Array.isArray(options) ? options : []).find(o => o.key === wanted) || null;
}

/**
 * The subset of a machine option that gets snapshot onto the ticket.
 *
 * Snapshot, not reference: lanes are torn down routinely, and
 * "ticket about lane a3f2… (gone)" is useless where "ticket about
 * cybr400-pat-ws0 (VM 601234)" is still diagnosable a month later.
 */
function machineSnapshot(option) {
  if (!option) return { lane_id: null, machine_key: null, machine_label: null, machine_vmid: null };
  return {
    lane_id: option.laneId || null,
    machine_key: option.key,
    machine_label: option.label,
    machine_vmid: option.vmid,
  };
}

/**
 * Options relevant to a chosen course.
 *
 * A machine with no course_id is kept, not dropped: self-service boxes and
 * lanes from the deploy-group path have no course reference, and a student
 * whose problem is with one of those must still be able to say so.
 * Client-side convenience only — the server validates by key, not by course.
 */
function filterByCourse(options, courseId) {
  const list = Array.isArray(options) ? options : [];
  if (!courseId) return list.slice();
  const wanted = String(courseId);
  return list.filter(o => o.courseId == null || o.courseId === wanted);
}

module.exports = {
  KIND_LANE,
  KIND_SELF,
  laneMachineOption,
  selfServiceOption,
  projectMachines,
  findMachine,
  machineSnapshot,
  filterByCourse,
};
