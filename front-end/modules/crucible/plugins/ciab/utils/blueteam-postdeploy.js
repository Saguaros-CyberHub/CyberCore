/**
 * blueteam-postdeploy.js — Track E, phase E3: composing per-lane hooks, and
 * telling the incident engine where the sensor landed
 * ============================================================================
 *
 * TWO THINGS LIVE HERE, AND THEY ARE HERE TOGETHER FOR ONE REASON.
 *
 * `deployChallengeLanes` takes exactly ONE `postDeploy` function
 * (challenge-lane-deployer.js), and CiAB already spends it: the vuln-app
 * install and the per-lane reseed are composed into it by
 * lane-provision.makeProfilePostDeploy. E3 needs a third piece of per-lane
 * work — recording the sensor's VMID on the lane — and bolting it onto that
 * composer would make three pieces of unrelated work share one try/catch, where
 * a failed Docker pull can decide whether the incident engine can find the
 * sensor.
 *
 * ── WHY chainPostDeploy IS HERE AND NOT IN src/utils/ ──────────────────────
 * It belongs in shared core (a course lane will want it the moment CLE grows a
 * second hook), and the phase plan says so. It is HERE for now because core is
 * being edited by another track in the same working tree and a new file under
 * src/utils/ is the kind of change that collides silently. Moving it later is a
 * file move and an import change; nothing about the contract has to alter.
 *
 * ── WHY A STAMP AT ALL ─────────────────────────────────────────────────────
 * The incident engine finds a lane's sensor with a ladder, most authoritative
 * first (cle/utils/attack-target.js): rung 0 is `lane.config.loggen`, rung 1 is
 * the tagged catalog row, rung 2 is `spec.vms[].role`, rung 3 guesses from "the
 * only Linux box", rung 4 probes each candidate over guest-exec. Rung 2 fires
 * for a CiAB lane the moment the spec carries `role: 'sensor'` — 'sensor' is
 * already in LOGGEN_ROLES — so this stamp is not what makes resolution POSSIBLE.
 * It makes the FIRST run cost nothing, and it means a run does not depend on
 * the challenge spec still being readable months later. Rung 2 remains the
 * recovery path if the stamp is ever lost.
 * ============================================================================
 */

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');

const LOG = '[CIAB BlueTeam]';

/**
 * Compose several postDeploy hooks into the ONE the deployer accepts.
 *
 * EVERY FUNCTION RUNS. Each is invoked inside its own try, so a throw in one
 * cannot skip the next — which is the entire point. The vuln-app install is a
 * Docker pull over a lane's single iptables hole and fails for reasons that
 * have nothing to do with the sensor; letting it decide whether the incident
 * engine can aim at that lane would be a coupling nobody would look for.
 *
 * WHAT IT THROWS, AND WHY THE ONE-FAILURE CASE IS DELIBERATELY NOT AN
 * AggregateError. The deployer records `hookErr.message` verbatim as
 * `config.post_deploy_error` and that string is shown to the instructor. When
 * exactly one hook failed there is nothing to aggregate, and wrapping it would
 * replace a diagnostic message ("vuln-app target 'x' is not among this lane's
 * machines (...)") with a summary of it. So: one failure rethrows that error
 * unchanged, and two or more throw an AggregateError whose `message` names
 * every one of them, because a summary IS the right answer when there are
 * several. `.errors` carries the originals in both branches of that decision.
 *
 * Null and undefined entries are skipped, so a caller can pass a hook that
 * built itself out of nothing (makeVulnAppPostDeploy returns null when there is
 * no app) without a conditional at every call site. All-null returns null,
 * which is what `deployChallengeLanes` expects for "no hook".
 *
 * @param {...(Function|null)} fns
 * @returns {Function|null}
 */
function chainPostDeploy(...fns) {
  const hooks = fns.filter(fn => typeof fn === 'function');
  if (hooks.length === 0) return null;
  if (hooks.length === 1) return hooks[0];

  return async function chainedPostDeploy(hookArgs) {
    const failures = [];
    for (const fn of hooks) {
      try {
        await fn(hookArgs);
      } catch (err) {
        failures.push(err);
      }
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length > 1) {
      throw new AggregateError(
        failures,
        `${failures.length} post-deploy steps failed: ` +
        failures.map(e => e && e.message ? e.message : String(e)).join(' | ')
      );
    }
  };
}

/**
 * Which spec machine is the sensor.
 *
 * Keyed on `role`, not on the name, because the name is a convenience and the
 * role is the contract the incident engine reads. 'sensor' is one of the values
 * in that engine's LOGGEN_ROLES set, so the two agree by construction.
 *
 * Returns the FIRST match. A spec with two sensors is a spec whose author meant
 * something this code cannot guess, and picking the first is at least stable
 * across deploys of the same spec.
 */
function findSensorSpecVm(spec) {
  const vms = spec && Array.isArray(spec.vms) ? spec.vms : [];
  return vms.find(vm => String(vm && vm.role || '').trim().toLowerCase() === 'sensor') || null;
}

/**
 * Write `cybercore_lane.config.loggen` for one lane.
 *
 * jsonb_set ON A SINGLE KEY, NEVER READ-MODIFY-WRITE. This mirrors
 * cle/utils/attack-target.js cacheLoggenTarget statement for statement, and the
 * reason is the one that module records: a read-modify-write of a JSONB column
 * loses one of two concurrent edits, and this runs inside a batch that is
 * deploying many lanes at once. COALESCE plus create_missing=true so a lane
 * whose config is NULL or simply lacks the key still gets one — plain jsonb_set
 * would silently no-op on both.
 *
 * BEST-EFFORT AT THE STATEMENT LEVEL is NOT what this does — it returns false
 * and lets the caller decide, because the caller has two different situations
 * to handle and only one of them is worth an error on the lane.
 */
async function writeLoggenStamp(laneId, payload) {
  await cybercoreQuery(
    `UPDATE cybercore_lane
        SET config = jsonb_set(COALESCE(config, '{}'::jsonb), '{loggen}', $2::jsonb, true),
            updated_at = NOW()
      WHERE lane_id = $1`,
    [laneId, JSON.stringify(payload)]
  );
}

/**
 * Build the per-lane hook that records where the sensor landed.
 *
 * Returns null when the spec has no sensor, so an ordinary offensive engagement
 * composes to exactly the hook it composed to before — the same shape
 * makeVulnAppPostDeploy uses for "there is no app".
 *
 * ── THE WRITE HERE IS NOT THE WRITE THAT LASTS ─────────────────────────────
 * challenge-lane-deployer builds each lane's active config from the batch-wide
 * `laneConfig` object and writes it WHOLE (`config = $2::jsonb`) in its final
 * step, which runs AFTER this hook. So anything this merges into config is gone
 * by the time the deploy returns. That is not a bug to route around here — it is
 * the same fact lane-provision.applyReseedRecords exists for, and the answer is
 * the same: record what was written, and re-apply it once the deployer has
 * finished. Pass `opts.records` (a Map) and lane-provision drains it.
 *
 * The immediate write is kept anyway, and not out of superstition: it is one
 * cheap statement, and it is the only stamp a caller gets if it uses this hook
 * WITHOUT draining the map — which a future single-lane path could easily do.
 * A stamp that is present and then overwritten is recoverable (rung 2 of the
 * ladder re-derives it); a path that silently never stamps is not.
 *
 * @param {object} spec           the challenge spec being deployed
 * @param {object} [opts]
 * @param {Map}    [opts.records] laneId -> payload, drained by applySensorStamps
 * @param {string} [opts.logTag]
 * @returns {Function|null}
 */
function makeSensorStampPostDeploy(spec, { records = null, logTag = LOG } = {}) {
  const sensorVm = findSensorSpecVm(spec);
  if (!sensorVm || !sensorVm.name) return null;

  return async function stampSensorForLane({ laneId, deployedVMs }) {
    // `name` on a deployedVMs record is the SPEC name; `proxmox_name` is the
    // clone name and carries the student suffix. Matching on proxmox_name would
    // work on lane 1 and silently fail on every other one.
    const target = (deployedVMs || []).find(vm => vm.name === sensorVm.name);
    if (!target) {
      // A spec that declares a sensor and a lane that has none is worth a
      // recorded error: the environment looks complete, the SIEM is up, and
      // every incident run against this lane will resolve nothing. The ladder's
      // later rungs cannot save it — there is no machine to find.
      throw new Error(
        `sensor '${sensorVm.name}' is not among this lane's machines ` +
        `(${(deployedVMs || []).map(v => v.name).join(', ') || 'none'}), so the incident engine has ` +
        `nothing to aim at on it`
      );
    }

    const payload = {
      vmid: Number(target.vm_id),
      node: target.node || null,
      vm_name: target.name,
      // The ladder records which rung answered. 'postdeploy' is rung 0's
      // provenance and is what a `GET /targets` response reports.
      resolved_by: 'postdeploy',
      at: new Date().toISOString(),
    };

    if (!Number.isFinite(payload.vmid)) {
      throw new Error(
        `sensor '${sensorVm.name}' deployed without a usable VMID (${target.vm_id}), so it cannot ` +
        `be recorded as this lane's telemetry target`
      );
    }

    if (records instanceof Map) records.set(laneId, payload);

    // Best-effort: the durable write is the re-apply. A failure here must not
    // fail a lane whose machines are all up.
    await writeLoggenStamp(laneId, payload).catch((err) => {
      console.warn(`${logTag} could not stamp sensor on lane ${laneId}: ${err.message}`);
    });
  };
}

/**
 * Re-apply every stamp after `deployChallengeLanes` has written each lane's
 * config whole.
 *
 * NOT REDUNDANT WITH THE WRITE THE HOOK ALREADY DID — see that function's
 * header. This is the pass that actually survives, and lane-provision calls it
 * in the same place, and for the same reason, that it calls applyReseedRecords.
 *
 * Best-effort per lane: losing the stamp costs one ladder walk on the first
 * incident run, and must never fail a lane that deployed.
 */
async function applySensorStamps(records) {
  for (const [laneId, payload] of (records || new Map())) {
    await writeLoggenStamp(laneId, payload).catch((err) => {
      console.warn(`${LOG} could not record sensor target on lane ${laneId}: ${err.message}`);
    });
  }
}

// ============================================================================
// THE FLOOR SWAP (Track E, phase E4)
// ============================================================================
// E4's compiler emits TWO playbooks: the intrusion, and a benign floor built
// from the CLIENT'S OWN hostnames. The intrusion is staged per dispatch and has
// always been replaceable. The floor was not — until you notice that
// cc-hostbase.service's ExecStart is a FIXED PATH:
//
//   ExecStart=/usr/bin/node /opt/cybercore/cc-emit.js --daemon
//             --playbook /opt/cybercore/host-baseline.json
//             --out /opt/log-generator/logs/current/host.json
//
// The unit reads whatever is at that path. So the floor is swappable per lane
// with NO RE-BAKE of template 1007 and no redeploy of anything, provided the
// compiled floor uses no cc-emit feature the baked emitter lacks — which is
// exactly the constraint src/incident/scenario-compiler.js is written under.
//
// WHY THIS IS WORTH A DEPLOY-TIME HOOK. The baked floor draws its hosts from
// generic pools (web-01, db-01, ws-042). A CiAB profile's assets are DC01,
// FILE01, HMI-01. Leave the generic floor in place and every attack event names
// a machine ordinary traffic never mentions, so
//
//     loggen.source.host : DC01
//
// returns the intrusion and nothing else. One terms aggregation in Discover and
// the exercise is over — and every part of it would review as working.
//
// ── rm, NEVER truncate ─────────────────────────────────────────────────────
// The live log MUST be removed, not emptied. Filebeat's filestream input tracks
// a file by inode and keeps a byte offset for it in its registry. `rm` gives the
// restarted generator a NEW inode, which filestream treats as a new file and
// reads from offset 0 — correct. Truncating (`: >` or `truncate -s 0`) keeps the
// SAME inode with the registry offset still pointing past the new end of file,
// and filestream then ships nothing at all, silently, for the life of the lane.
// The service is running, the file is growing, the index stays empty.
//
// ── Honest residual ────────────────────────────────────────────────────────
// cc-hostbase starts at guest boot, minutes before this hook runs, so a few
// hundred generic-host events may already exist and may already have shipped.
// In practice Elasticsearch on the freshly cloned SIEM is not accepting yet,
// but that is not guaranteed. The plan's belt-and-braces `_delete_by_query` for
// `@timestamp < now` belongs on the SIEM side and is deliberately not done here.
// ============================================================================

/** cc-hostbase.service's ExecStart --playbook. Fixed at bake; see above. */
const HOST_BASELINE_PATH = '/opt/cybercore/host-baseline.json';

/** cc-hostbase.service's --out. The file whose INODE must change. */
const LIVE_HOST_LOG = '/opt/log-generator/logs/current/host.json';

const HOSTBASE_UNIT = 'cc-hostbase';

/**
 * The guest shell that replaces one lane's benign floor.
 *
 * Pure: it builds a string and touches nothing. That is what lets
 * test/incident-floor-swap.test.js hold the rm-not-truncate rule and the
 * stop -> rm -> stage -> mv -f -> start ordering with no cluster.
 *
 * SHAPE NOTES, all load-bearing:
 *   - the payload is BASE64. A base64 word is /^[A-Za-z0-9+/=]+$/, so it is
 *     inert inside a single-quoted POSIX word whatever the JSON contains. The
 *     same rule lane-reseed.js states for secrets, applied here for
 *     correctness rather than confidentiality.
 *   - the write is STAGED and published with `mv -f`. agentShellExec retries the
 *     TRANSPORT on 596/ECONNRESET, so a chunk can land twice; a partial or
 *     duplicated write must never become a half-written host-baseline.json that
 *     cc-hostbase then fails to parse on every restart forever.
 *   - the new floor is PARSED before it is published, and the service is
 *     restarted on the OLD floor if it does not parse.
 *   - every operative command sits at column 0 and the recovery helper does
 *     not, so the ordering test can anchor on line starts instead of guessing.
 *
 * @param {object} floor  the compiled benign floor (a cc-emit playbook)
 * @returns {{script: string, base64: string, playbookPath: string,
 *            livePath: string, unit: string, bytes: number}}
 */
function buildFloorSwapScript(floor) {
  if (!floor || !Array.isArray(floor.steps) || !floor.steps.length) {
    throw new Error('buildFloorSwapScript: a compiled floor playbook with steps is required');
  }
  // Compact, not pretty-printed. This travels base64'd over the guest agent and
  // indentation would be a third of the bytes for nothing.
  const json = JSON.stringify(floor);
  const base64 = Buffer.from(json, 'utf-8').toString('base64');

  const script = [
    '#!/bin/sh',
    '# Track E floor swap. Generated by ciab/utils/blueteam-postdeploy.js.',
    'set -eu',
    '',
    "PB='" + HOST_BASELINE_PATH + "'",
    "LIVE='" + LIVE_HOST_LOG + "'",
    'STAGE="$PB.ccfloor"',
    '',
    '# If anything below fails the service comes back on the OLD floor. A lane',
    '# with no benign floor at all is strictly worse than one with a generic',
    '# floor: source.type:host would then occur ONLY during attacks.',
    '  recover() { systemctl start ' + HOSTBASE_UNIT + ' >/dev/null 2>&1 || true; }',
    '  trap recover EXIT',
    '',
    'systemctl stop ' + HOSTBASE_UNIT + ' >/dev/null 2>&1 || true',
    '',
    '# rm, never empty-in-place. A new inode makes filestream read from 0;',
    '# zeroing the SAME inode strands the registry offset past EOF and the lane',
    '# then silently ships nothing for the rest of its life.',
    'rm -f "$LIVE"',
    '',
    'rm -f "$STAGE"',
    "printf %s '" + base64 + "' | base64 -d > \"$STAGE\"",
    'test -s "$STAGE"',
    'node -e "JSON.parse(require(\'fs\').readFileSync(process.argv[1],\'utf8\'))" "$STAGE"',
    '',
    'mv -f "$STAGE" "$PB"',
    'chmod 0644 "$PB"',
    '',
    '  trap - EXIT',
    'systemctl start ' + HOSTBASE_UNIT,
    'echo "cc-floor-swap: published ' + json.length + ' bytes to $PB"',
    '',
  ].join('\n');

  return {
    script,
    base64,
    playbookPath: HOST_BASELINE_PATH,
    livePath: LIVE_HOST_LOG,
    unit: HOSTBASE_UNIT,
    bytes: json.length,
  };
}

/**
 * Build the per-lane hook that publishes the compiled floor onto the sensor.
 *
 * Returns null when the spec has no sensor or the caller has no compiled floor
 * — the same "there is nothing to do" shape makeSensorStampPostDeploy and
 * makeVulnAppPostDeploy use, so chainPostDeploy needs no conditional.
 *
 * THROWS rather than warns when the sensor is missing or the guest rejects the
 * swap. A lane that keeps the generic floor is not a degraded exercise; it is
 * one where a single terms aggregation on loggen.source.host ends the hunt, and
 * nothing downstream can detect that state. The deployer records the message as
 * `config.post_deploy_error`, which is where an instructor will look.
 *
 * WIRED IN E7. utils/lane-provision.js composes it into the postDeploy chain of
 * BOTH deploy paths — provisionProfileLanes and retryProfileLane — with the
 * floor from utils/scenario-source.floorForEngagement(), which compiles it from
 * the scenario the engagement recorded on ciab_engagement.telemetry_plan.
 *
 * Composing it in lane-provision rather than in routes/profile-deploy.js is
 * what makes a RETRIED environment get the client's floor too: a retry is a
 * fresh clone of the same golden image, so it comes back carrying the generic
 * baked one, and a single environment on a different vocabulary from the rest of
 * its engagement is a student who can end the hunt with one aggregation.
 *
 * floorForEngagement() returns null for every ordinary "there is no floor here"
 * state — an offensive engagement, a client with no threat scenarios, a
 * scenario not yet chosen — so this returns null in turn and chainPostDeploy
 * composes to exactly what it composed to before the phase.
 *
 * @param {object} spec         the challenge spec being deployed
 * @param {object} opts
 * @param {object} opts.floor   compiled floor from src/incident/scenario-compiler
 * @param {string} [opts.logTag]
 * @returns {Function|null}
 */
function makeFloorSwapPostDeploy(spec, { floor = null, logTag = LOG } = {}) {
  const sensorVm = findSensorSpecVm(spec);
  if (!sensorVm || !sensorVm.name || !floor) return null;

  // Built ONCE, outside the per-lane closure: the floor describes the CLIENT,
  // not the student, so it is identical on every lane of an engagement, and
  // base64-ing 30KB thirty times is thirty times the work for one string.
  const built = buildFloorSwapScript(floor);

  return async function swapFloorForLane({ laneId, deployedVMs }) {
    // `name` is the SPEC name; `proxmox_name` carries the student suffix.
    // Matching on proxmox_name works on lane 1 and silently fails on every
    // other one — the same trap makeSensorStampPostDeploy records.
    const target = (deployedVMs || []).find(vm => vm.name === sensorVm.name);
    if (!target) {
      throw new Error(
        `sensor '${sensorVm.name}' is not among this lane's machines ` +
        `(${(deployedVMs || []).map(v => v.name).join(', ') || 'none'}), so the client's benign ` +
        `floor cannot be published and the generic one would end the exercise in one click`
      );
    }

    // Required lazily. script-executor destructures src/utils/proxmox and
    // src/utils/db at module load, and this file is required by the plugin
    // fixture suite, which has neither.
    const { executeShellViaFile } = require('../../../../../src/utils/script-executor');

    const result = await executeShellViaFile(target.node, Number(target.vm_id), built.script);
    if (!result || !result.exited || Number(result.exitcode) !== 0) {
      throw new Error(
        `floor swap failed on sensor '${sensorVm.name}' ` +
        `(exit ${result && result.exitcode}): ` +
        `${String((result && (result.stdout || result.stderr)) || '').slice(0, 400)}`
      );
    }
    console.log(`${logTag} published ${built.bytes}-byte client floor on lane ${laneId}`);
  };
}

module.exports = {
  chainPostDeploy,
  makeSensorStampPostDeploy,
  applySensorStamps,
  makeFloorSwapPostDeploy,
  // Pure, so the ladder's contract is testable with no cluster and no database.
  findSensorSpecVm,
  buildFloorSwapScript,
  HOST_BASELINE_PATH,
  LIVE_HOST_LOG,
  HOSTBASE_UNIT,
};
