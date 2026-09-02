/**
 * CLE Plugin — locate the log-generator host inside a lane (CYBR 400)
 * ============================================================================
 * The Attack Console fires one command per lane, at exactly one VM: the Rocky
 * sensor running log-generator. Finding it is the hardest part of the feature,
 * because lane config does not record template identity.
 *
 * challenge-lane-deployer.js writes `config.vms[] = {vm_id, name, proxmox_name,
 * type, node}` and nothing else -- no template_id, no os. Workstation lanes
 * (lane-deployer.js workstationConfigEntry) are a DIFFERENT shape that DOES
 * carry template_id/template_name. Both exist in the wild, so both are handled.
 *
 * The ladder, most authoritative first, stopping at the first hit:
 *
 *   0 cache      lane.config.loggen, written by a previous run
 *   1 template   catalog row tagged role_hints @> {loggen} -> spec -> lane
 *   2 spec_role  spec.vms[].role names it explicitly
 *   3 sole_linux exactly one non-infrastructure Linux VM is left
 *   4 probe      ask the guest whether log-generator is installed
 *
 * WHICH RUNG ACTUALLY FIRES DEPENDS ON HOW THE LANE WAS BUILT.
 *
 * CYBR 400 lanes are WORKSTATION lanes — two catalog templates deployed as
 * slots 0 and 1 by lane-deployer.js — and a workstation lane has no challenge
 * spec at all. So `specVms` is empty, rungs 2 and 3 cannot fire (rung 3 reads
 * `os` off the spec, and with none every candidate is unclassifiable), and
 * resolution lands on:
 *
 *   - rung 1, matching `config.workstations[].template_id` directly against the
 *     catalog row tagged `role_hints @> {loggen}` — no spec hop needed. This is
 *     the intended path: tag the sensor template, or set
 *     CYBR400_LOGGEN_TEMPLATE_KEY, and resolution is deterministic.
 *   - failing that, rung 4, which probes each candidate. It will test the
 *     WINDOWS box first (harmlessly failing) before finding the sensor.
 *
 * Rungs 2 and 3 serve CHALLENGE lanes, where a spec does exist. Rung 3 is what
 * lets a hand-built two-VM challenge resolve with no tagging at all.
 *
 * NEVER GUESS. When two candidates survive, this returns null with a reason,
 * the target is recorded 'skipped', and the instructor sees why on that lane's
 * row. Picking one at random would fire an attack at a student's ELK box.
 *
 * Everything except the probe is a PURE function over injected lookups, so the
 * ladder is unit-testable against fixture configs with no database.
 * ============================================================================
 */

const { cybercoreQuery } = require('../utils/cybercore-db');
const { normalizeOs } = require('../utils/flag-manager');

/** spec.vms[].role values that name the sensor outright. */
const LOGGEN_ROLES = new Set(['loggen', 'log-generator', 'log_generator', 'siem-source', 'sensor']);

/** Marker file the bake script writes; the probe tests for it. */
const LOGGEN_MARKER = '/opt/log-generator/package.json';

/**
 * Which catalog row is the sensor image. role_hints is a TEXT[] on
 * cybercore_template_catalog, so the tag travels with the template rather than
 * living in a config file that can drift from it.
 *
 * CYBR400_LOGGEN_TEMPLATE_KEY overrides for a site that baked its own under a
 * different name, or to pin a second image during a migration.
 */
async function loadLoggenTemplate() {
  const key = process.env.CYBR400_LOGGEN_TEMPLATE_KEY;
  const r = await cybercoreQuery(
    key
      ? `SELECT id, template_vmid, template_key, os_name
           FROM cybercore_template_catalog
          WHERE template_key = $1`
      : `SELECT id, template_vmid, template_key, os_name
           FROM cybercore_template_catalog
          WHERE 'loggen' = ANY(role_hints) AND is_active
          ORDER BY preferred DESC, updated_at DESC
          LIMIT 1`,
    key ? [key] : []
  );
  return r.rows[0] || null;
}

/**
 * The challenge spec behind a lane, or [] when there isn't one.
 *
 * Table name is derived from module_key with the same sanitising pattern
 * routes/admin/lanes.js and flag-manager.rotateLaneFlags use -- the value comes
 * from the DB rather than a request, but it is interpolated, so it is stripped
 * to [a-z0-9_] regardless. A miss is not an error: workstation lanes have no
 * challenge at all and resolve on rung 1 or 3 instead.
 */
async function loadSpecVms(lane, config) {
  const moduleKey = lane.module_key || config.module;
  if (!moduleKey || !config.challenge_key) return [];
  try {
    const table = `${String(moduleKey).replace(/[^a-z0-9_]/gi, '')}_challenge`;
    const r = await cybercoreQuery(
      `SELECT spec FROM ${table} WHERE challenge_key = $1`,
      [config.challenge_key]
    );
    if (!r.rows.length) return [];
    const spec = typeof r.rows[0].spec === 'string'
      ? JSON.parse(r.rows[0].spec)
      : (r.rows[0].spec || {});
    return Array.isArray(spec.vms) ? spec.vms : [];
  } catch (err) {
    console.warn(`[AttackTarget] could not load challenge spec for lane ${lane.lane_id}: ${err.message}`);
    return [];
  }
}

/**
 * Normalise both lane-config VM shapes into one candidate list.
 *
 * challenge lanes: config.vms[]            -> {vm_id, name, proxmox_name, type, node}
 * workstation lanes: config.workstations[] -> {slot, vmid, hostname, provider_type, template_id, ...}
 * attached modules: config.attached_modules[].vms[]
 *
 * Infrastructure is dropped here rather than in each rung: the gateway is an
 * LXC with no guest-agent exec API at all, and the Kali attack box is never a
 * log source. Both would otherwise survive to rung 3 and make it ambiguous.
 */
function laneCandidates(config) {
  const infra = new Set(
    [config.gateway_vm_id, config.gateway_vmid, config.attack_box_vm_id]
      .filter((v) => v != null)
      .map(Number)
  );
  const out = [];

  const push = (vmid, name, providerType, templateId, source) => {
    const id = Number(vmid);
    if (!Number.isInteger(id) || infra.has(id)) return;
    // Guest-agent exec is QEMU-only. An LXC target cannot be dispatched to at
    // all, so it is not a candidate -- it is not even a skip reason.
    if (providerType && String(providerType).toLowerCase() !== 'qemu') return;
    out.push({ vmid: id, name: name || null, template_id: templateId || null, source });
  };

  for (const vm of (Array.isArray(config.vms) ? config.vms : [])) {
    push(vm.vm_id ?? vm.vmid, vm.name || vm.proxmox_name, vm.type || vm.providerType, vm.template_id, 'vms');
  }
  for (const ws of (Array.isArray(config.workstations) ? config.workstations : [])) {
    push(ws.vmid, ws.hostname || ws.name, ws.provider_type, ws.template_id, 'workstations');
  }
  for (const mod of (Array.isArray(config.attached_modules) ? config.attached_modules : [])) {
    for (const vm of (Array.isArray(mod.vms) ? mod.vms : [])) {
      push(vm.vm_id ?? vm.vmid, vm.name || vm.proxmox_name, vm.type || vm.providerType, vm.template_id, 'attached');
    }
  }
  return out;
}

/** Case-insensitive name match, the same way plantFlagsForLane pairs spec to lane. */
function sameName(a, b) {
  return !!a && !!b && String(a).trim().toLowerCase() === String(b).trim().toLowerCase();
}

/**
 * Resolve the sensor VM for one lane.
 *
 * Pure apart from `probe`, which is injected so tests never touch Proxmox.
 *
 * @param {object}   lane      cybercore_lane row (lane_id, module_key, config)
 * @param {object}   ctx
 * @param {object}   [ctx.template]  cybercore_template_catalog row, from loadLoggenTemplate()
 * @param {object[]} [ctx.specVms]   challenge spec vms[], from loadSpecVms()
 * @param {Function} [ctx.probe]     async ({node, vmid}) => boolean
 * @returns {Promise<{vmid, node, vm_name, resolved_by}|{vmid:null, reason:string}>}
 */
async function resolveLoggenTarget(lane, ctx = {}) {
  const config = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
  const node = config.node || null;
  const { template = null, specVms = [], probe = null } = ctx;

  if (!node) return { vmid: null, reason: 'lane config has no Proxmox node' };

  // --- 0. cache -----------------------------------------------------------
  // Trusted only if the VM it names is still in the lane. A redeploy reuses
  // lane_id while replacing every vmid, so a stale hit would aim at a VM that
  // no longer exists -- or worse, at a recycled id belonging to something else.
  const candidates = laneCandidates(config);
  const cached = config.loggen;
  if (cached && Number.isInteger(Number(cached.vmid))) {
    const still = candidates.find((c) => c.vmid === Number(cached.vmid));
    if (still) {
      return { vmid: still.vmid, node, vm_name: cached.vm_name || still.name, resolved_by: 'cache' };
    }
  }

  if (candidates.length === 0) {
    return { vmid: null, reason: 'lane has no QEMU VMs that could host log-generator' };
  }

  // --- 1. template identity ----------------------------------------------
  if (template) {
    // Workstation lanes record template_id directly -- no spec hop needed.
    const byTemplateId = candidates.filter((c) => c.template_id && c.template_id === template.id);
    if (byTemplateId.length === 1) {
      return { vmid: byTemplateId[0].vmid, node, vm_name: byTemplateId[0].name, resolved_by: 'template' };
    }
    // Challenge lanes: spec knows template_vmid, lane knows name. Join on name.
    const specNames = specVms
      .filter((v) => Number(v.template_vmid) === Number(template.template_vmid))
      .map((v) => v.name);
    const bySpec = candidates.filter((c) => specNames.some((n) => sameName(n, c.name)));
    if (bySpec.length === 1) {
      return { vmid: bySpec[0].vmid, node, vm_name: bySpec[0].name, resolved_by: 'template' };
    }
  }

  // --- 2. explicit spec role ---------------------------------------------
  const roleNames = specVms
    .filter((v) => LOGGEN_ROLES.has(String(v.role || '').trim().toLowerCase()))
    .map((v) => v.name);
  const byRole = candidates.filter((c) => roleNames.some((n) => sameName(n, c.name)));
  if (byRole.length === 1) {
    return { vmid: byRole[0].vmid, node, vm_name: byRole[0].name, resolved_by: 'spec_role' };
  }

  // --- 3. sole Linux ------------------------------------------------------
  // normalizeOs deliberately returns null for 'Unknown' and for human strings
  // like 'Windows Server 2019' it cannot classify, so an unclassifiable VM is
  // neither counted as Linux nor eliminated -- it stays a candidate and makes
  // the result ambiguous, which is the safe direction.
  const withOs = candidates.map((c) => {
    const spec = specVms.find((v) => sameName(v.name, c.name));
    return { ...c, os: normalizeOs(spec && spec.os) };
  });
  const linux = withOs.filter((c) => c.os === 'linux');
  const unknown = withOs.filter((c) => c.os === null);
  if (linux.length === 1 && unknown.length === 0) {
    return { vmid: linux[0].vmid, node, vm_name: linux[0].name, resolved_by: 'sole_linux' };
  }

  // --- 4. guest probe -----------------------------------------------------
  if (probe) {
    const maybe = linux.length ? linux.concat(unknown) : withOs.filter((c) => c.os !== 'windows');
    for (const c of maybe) {
      let hit = false;
      try {
        hit = await probe({ node, vmid: c.vmid });
      } catch (_) {
        hit = false;   // an unreachable guest is not a match, and not fatal
      }
      if (hit) return { vmid: c.vmid, node, vm_name: c.name, resolved_by: 'probe' };
    }
  }

  const names = withOs.map((c) => c.name || c.vmid).join(', ');
  return {
    vmid: null,
    reason: linux.length > 1
      ? `could not identify the log-generator host: ${linux.length} Linux VMs and none tagged (${names})`
      : `could not identify the log-generator host among ${withOs.length} VM(s) (${names})`,
  };
}

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

/**
 * Remember where the sensor was, so the next run skips the ladder.
 *
 * jsonb_set on a single key, NEVER read-modify-write. This is the exact hazard
 * src/utils/script-executor.js updateScriptStatus() has: it SELECTs the JSONB,
 * mutates it in Node and UPDATEs the whole column, so two concurrent writers
 * lose one of the two edits. A dispatch resolves N lanes at once, and although
 * each writes a different lane row today, keeping the write single-statement
 * costs nothing and removes the failure mode entirely.
 *
 * COALESCE + create_missing=true so a lane whose config somehow lacks the key
 * (or is NULL) still gets one, which plain jsonb_set would silently no-op on.
 *
 * Best-effort: a cache write failing must never fail the run it belongs to.
 */
async function cacheLoggenTarget(laneId, resolved) {
  if (!resolved || !Number.isInteger(Number(resolved.vmid))) return;
  const payload = {
    vmid: Number(resolved.vmid),
    node: resolved.node,
    vm_name: resolved.vm_name || null,
    resolved_by: resolved.resolved_by || null,
    at: new Date().toISOString(),
  };
  try {
    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET config = jsonb_set(COALESCE(config, '{}'::jsonb), '{loggen}', $2::jsonb, true),
              updated_at = NOW()
        WHERE lane_id = $1`,
      [laneId, JSON.stringify(payload)]
    );
  } catch (err) {
    console.warn(`[AttackTarget] could not cache loggen target for lane ${laneId}: ${err.message}`);
  }
}

/**
 * Forget it. Called when a dispatch comes back 'refused notinstalled' -- the
 * cached VM is real but is not the sensor, so the next run must re-run the
 * ladder rather than keep aiming at the same wrong box.
 */
async function invalidateLoggenCache(laneId) {
  try {
    await cybercoreQuery(
      `UPDATE cybercore_lane
          SET config = config #- '{loggen}', updated_at = NOW()
        WHERE lane_id = $1`,
      [laneId]
    );
  } catch (err) {
    console.warn(`[AttackTarget] could not clear loggen cache for lane ${laneId}: ${err.message}`);
  }
}

module.exports = {
  resolveLoggenTarget,
  cacheLoggenTarget,
  invalidateLoggenCache,
  loadLoggenTemplate,
  loadSpecVms,
  // exported for tests
  laneCandidates,
  LOGGEN_ROLES,
  LOGGEN_MARKER,
};
