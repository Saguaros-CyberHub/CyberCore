/**
 * CLE Plugin — dispatch log-generator attacks into every lane (CYBR 400)
 * ============================================================================
 * Owns the guest-side contract: the wrapper script, the commands that stage,
 * inspect and abort it, and the validation of everything interpolated into them.
 *
 * WHY NOT systemd-run. It exists on Rocky 9 and `systemctl is-active`/`stop`
 * would be pleasant, but src/utils/goad-deploy.js already solved this exact
 * problem for 2-hour Ansible runs and documents the two ways QGA fails on
 * long-lived processes: it buffers stdout in memory until the exec deadlocks,
 * and it loses track of the child so guest-exec-status reports exited=false
 * forever. Its answer -- nohup setsid, output redirected to a file, state in a
 * sentinel file, short-lived execs to poll -- is proven here. systemd-run would
 * add a dbus dependency nothing else in this codebase has, need --collect to
 * avoid lingering failed units, and force quoting through four layers, all to
 * buy a hard timeout that coreutils `timeout` gives for free.
 *
 * WHY ONE EXEC PER LANE. Dispatch latency is the enemy of a synchronized start.
 * waitForAgentExecReady() is deliberately NOT called: it costs 5-6s per VM and
 * exists for freshly-cloned guests, whereas these lanes are long-running and
 * 'active'. agentShellExec already retries transient 596s with 2/4/6/8s backoff.
 *
 * WHY THE START IS SCHEDULED. 30 lanes cannot be dispatched instantaneously, so
 * firing on arrival would spread the class over minutes and make timeline
 * comparison worthless. Every guest is told an absolute epoch AND a relative
 * delay; see the wrapper for why both.
 * ============================================================================
 */

const {
  agentShellExec,
  pollExecStatus,
} = require('../../../../../src/utils/script-executor');
const { formatDuration, findTechnique, findTactic, findChain, TECHNIQUE_RE, TACTIC_RE } = require('./loggen-catalog');

/** Where the wrapper and its per-run state live on the guest. */
const GUEST_BASE = '/opt/cybercore';
const WRAPPER_PATH = `${GUEST_BASE}/cc-attack.sh`;

/** How long a guest may run before `timeout` kills it, regardless of mode. */
const CHAIN_CAP_FLOOR_S = 3 * 3600;

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

/**
 * Everything below is interpolated into a single-quoted shell word. The quoting
 * is real protection, but it is the SECOND layer -- these validators are the
 * first, and they are what make the quoting merely belt-and-braces.
 *
 * On the newline check specifically: JavaScript's `$` does NOT match before a
 * trailing newline the way Python's and Perl's do, so the anchored regexes
 * already reject one. (The comment on
 * src/utils/flag-manager.js isSafePath() states the opposite; that describes
 * Python's behaviour, not this runtime's.) The guard stays anyway: it is one
 * comparison, it gives a far clearer error than a regex mismatch, and it keeps
 * holding if a validator here is ever loosened or a new field is threaded
 * through without one.
 */
function assertNoNewline(value, label) {
  if (/[\r\n]/.test(String(value))) {
    throw new Error(`${label} contains a newline`);
  }
}

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function assertUuid(value, label) {
  const s = String(value == null ? '' : value);
  assertNoNewline(s, label);
  if (!UUID_RE.test(s)) throw new Error(`${label} is not a UUID: ${JSON.stringify(value)}`);
  return s;
}

function assertInt(value, label, { min = 0, max = Number.MAX_SAFE_INTEGER } = {}) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${label} must be an integer in [${min}, ${max}], got ${JSON.stringify(value)}`);
  }
  return n;
}

/**
 * A speed multiplier reaches the guest as a decimal string, so constrain both
 * the range and the spelling rather than trusting Number#toString.
 */
function assertSpeed(value) {
  const n = Number(value);
  if (!Number.isFinite(n) || n < 0.1 || n > 20) {
    throw new Error(`speed must be between 0.1 and 20, got ${JSON.stringify(value)}`);
  }
  return n.toFixed(2);
}


// ---------------------------------------------------------------------------
// The guest wrapper
// ---------------------------------------------------------------------------

/**
 * cc-attack.sh, read from disk rather than embedded as a template literal.
 *
 * Keeping it a real .sh file means `sh -n` can lint it, an editor highlights
 * it, and — the reason it moved out of here — its backslashes (printf '%s\n',
 * awk field refs) do not have to survive JavaScript string escaping on top of
 * three layers of shell quoting. Embedding it cost a silent corruption of the
 * state-file writer the first time it was written that way.
 *
 * Read once at require time: the file ships with the app, so re-reading per
 * dispatch would only add I/O and a chance of a torn read during a deploy.
 */
const WRAPPER_SH = require('fs').readFileSync(require('path').join(__dirname, 'cc-attack.sh'), 'utf8');
const WRAPPER_B64 = Buffer.from(WRAPPER_SH, 'utf8').toString('base64');

/**
 * Playbooks, read once at require time for the same reasons as the wrapper.
 *
 * Keyed by technique id (`T1110.001`) and by `chain-<key>`, matching the
 * filenames. A technique with a playbook runs the emitter; one without falls
 * back to log-generator's keyword filter, so the two paths can coexist while
 * playbooks are written.
 *
 * The ENGINE is baked into the image rather than staged like the wrapper. That
 * is a deliberate trade: it freezes engine behaviour at the image, so an engine
 * change needs a re-bake and a redeploy of already-built lanes, but it keeps the
 * dispatch command near 12 KB instead of ~26 KB on a path that already throws
 * transient 596s. Playbooks -- the half that actually changes -- still ship on
 * every dispatch with no re-bake.
 */
const PLAYBOOKS = (() => {
  const fs = require('fs');
  const path = require('path');
  const dir = path.join(__dirname, '..', 'playbooks');
  const out = new Map();
  let names = [];
  try { names = fs.readdirSync(dir); } catch (e) { return out; }
  for (const f of names) {
    if (!f.endsWith('.json')) continue;
    // Re-serialised rather than shipped verbatim: strips the authoring
    // indentation, which is a third of the bytes in a file that has to survive
    // base64 inflation into a guest-exec argument.
    const raw = fs.readFileSync(path.join(dir, f), 'utf8');
    out.set(f.replace(/\.json$/, ''), JSON.stringify(JSON.parse(raw)));
  }
  return out;
})();

/**
 * The playbook for a resolved selection, or null when the technique has none.
 *
 * Tactic mode never has one: a tactic is a dozen unrelated behaviours and there
 * is no single honest story to script for it, so it stays on the keyword filter.
 */
function playbookFor(selection) {
  if (!selection) return null;
  if (selection.mode === 'chain') return PLAYBOOKS.get(`chain-${selection.arg}`) || null;
  if (selection.mode === 'technique') return PLAYBOOKS.get(selection.arg) || null;
  return null;
}

// ---------------------------------------------------------------------------
// Command construction
// ---------------------------------------------------------------------------

/**
 * Validate an attack selection and resolve it to the argv the wrapper needs.
 *
 * Rejects rather than coerces. A technique id that fails TECHNIQUE_RE is a bug
 * or an attack, never a typo worth guessing at, and the alternative to throwing
 * is interpolating it into a shell command.
 *
 * @returns {{mode, arg, durationSeconds, capSeconds, speed, label}}
 */
function resolveSelection({ mode, technique_id, tactic_id, chain_key, duration_seconds, speed }) {
  if (mode === 'technique' || mode === 'tactic') {
    const isTech = mode === 'technique';
    const raw = String((isTech ? technique_id : tactic_id) || '');
    assertNoNewline(raw, mode === 'technique' ? 'technique_id' : 'tactic_id');
    const re = isTech ? TECHNIQUE_RE : TACTIC_RE;
    if (!re.test(raw)) throw new Error(`invalid ${isTech ? 'technique' : 'tactic'} id: ${JSON.stringify(raw)}`);
    // Present in the catalog too, so the console can never dispatch something
    // it did not offer -- the regex alone would accept e.g. T9999.
    const entry = isTech ? findTechnique(raw) : findTactic(raw);
    if (!entry) throw new Error(`${raw} is not in the log-generator catalog`);

    const durationSeconds = assertInt(duration_seconds, 'duration_seconds', { min: 30, max: 28800 });
    return {
      mode,
      arg: raw,
      durationSeconds,
      duration: formatDuration(durationSeconds),
      // 20% headroom plus two minutes for npm/ts-node startup. The generator
      // self-exits at --duration; this only fires if it wedges.
      capSeconds: Math.ceil(durationSeconds * 1.2) + 120,
      speed: '1.00',
      label: `${raw} ${entry.name}`,
    };
  }

  if (mode === 'chain') {
    const key = String(chain_key || '');
    assertNoNewline(key, 'chain_key');
    // Allowlisted by identity, not by pattern: there are exactly three.
    const chain = findChain(key);
    if (!chain) throw new Error(`unknown attack chain: ${JSON.stringify(key)}`);
    const spd = speed == null ? '1.00' : assertSpeed(speed);
    // Chains run their own length, so there is no duration to scale a cap off.
    // Three times the template's estimate, floored, absorbs a slow lane without
    // letting a wedged run generate overnight.
    const capSeconds = Math.max(
      CHAIN_CAP_FLOOR_S,
      Math.ceil((chain.estimated_minutes * 60 * 3) / Number(spd))
    );
    return { mode, arg: key, durationSeconds: null, duration: '', capSeconds, speed: spd, label: chain.name };
  }

  throw new Error(`unknown mode: ${JSON.stringify(mode)}`);
}

/**
 * Stage the wrapper and launch it detached, in one exec.
 *
 * `nohup setsid ... </dev/null >/dev/null 2>&1 &` is the goad-deploy idiom:
 * detaching means QGA sees this exec finish in milliseconds instead of holding
 * a channel open for 45 minutes and eventually losing track of the child.
 * setsid also makes the wrapper a process-group leader, which is what lets
 * abort kill npm and node along with it rather than orphaning them.
 *
 * Invoked as `/bin/sh <path>` rather than relying on the exec bit, so a /opt
 * mounted noexec still works.
 */
function buildDispatchCommand(args) {
  const runId = assertUuid(args.runId, 'runId');
  const startEpoch = assertInt(args.startEpoch, 'startEpoch', { min: 1_600_000_000, max: 4_000_000_000 });
  const relDelay = assertInt(args.relDelaySeconds, 'relDelaySeconds', { min: 0, max: 3600 });
  const capSeconds = assertInt(args.capSeconds, 'capSeconds', { min: 60, max: 86400 });

  const mode = String(args.mode);
  if (!['technique', 'tactic', 'chain'].includes(mode)) throw new Error(`unknown mode: ${mode}`);

  const arg = String(args.arg || '');
  assertNoNewline(arg, 'arg');
  if (mode === 'chain') {
    if (!findChain(arg)) throw new Error(`unknown attack chain: ${JSON.stringify(arg)}`);
  } else {
    const re = mode === 'technique' ? TECHNIQUE_RE : TACTIC_RE;
    if (!re.test(arg)) throw new Error(`invalid ${mode} id: ${JSON.stringify(arg)}`);
  }

  const duration = String(args.duration || '');
  assertNoNewline(duration, 'duration');
  if (mode !== 'chain' && !/^(\d+h)?(\d+m)?(\d+s)?$/.test(duration)) {
    throw new Error(`invalid duration: ${JSON.stringify(duration)}`);
  }
  const speed = assertSpeed(args.speed == null ? 1 : args.speed);

  // A playbook switches the wrapper onto the emitter. The DB keeps the run's
  // own mode ('technique'/'chain') -- migration 006's CHECK constraint does not
  // know 'playbook' and must not be edited in place -- so the token is derived
  // here and never persisted.
  const playbook = args.playbookJson || null;
  const wrapperMode = playbook ? 'playbook' : mode;

  const runDir = `${GUEST_BASE}/runs/${runId}`;
  const playbookPath = `${runDir}/playbook.json`;

  const argv = [runId, String(startEpoch), String(relDelay), wrapperMode, arg, duration, String(capSeconds), speed]
    .map((a) => `'${a}'`)
    .join(' ');

  const links = [
    // Fail loudly rather than launch ungrouped. Without setsid the wrapper
    // shares OUR process group, so buildAbortCommand's `kill -TERM -$P` would
    // either miss it or signal the wrong group -- an attack nobody can stop.
    // util-linux provides setsid and is essential on Rocky; this guard exists
    // so a stripped image reports the problem instead of hiding it.
    `command -v setsid >/dev/null 2>&1 || { echo 'setsid is missing on this guest' >&2; exit 3; }`,
    `mkdir -p ${GUEST_BASE} ${runDir}`,
    // Staged via .tmp + mv -f, and that is NOT tidiness.
    //
    // `>` truncates the SAME inode, and /bin/sh does not slurp a script -- it
    // reads in blocks and seeks back after each command. The wrapper parks
    // mid-file for the whole run: first at the start-delay sleep, then for up to
    // 45 minutes inside `timeout`. A second dispatch to this lane during that
    // window rewrites the file underneath a shell that will resume at its saved
    // byte offset in the NEW content and execute a fragment of a different line.
    //
    // This was harmless only while every staged copy was byte-identical. It
    // stopped being harmless the moment cc-attack.sh changed length. rename(2)
    // leaves the running shell on its own inode. Same idiom as say()'s state
    // write, for the same reason.
    `printf %s '${WRAPPER_B64}' | base64 -d > ${WRAPPER_PATH}.tmp`,
    `chmod 700 ${WRAPPER_PATH}.tmp`,
    `mv -f ${WRAPPER_PATH}.tmp ${WRAPPER_PATH}`,
  ];

  if (playbook) {
    // A file, not a ninth argument: students have an SSH console on this box,
    // and a base64 playbook in argv is the whole answer sheet in `ps auxww`.
    const b64 = Buffer.from(playbook, 'utf8').toString('base64');
    links.push(`printf %s '${b64}' | base64 -d > ${playbookPath}.tmp`);
    links.push(`mv -f ${playbookPath}.tmp ${playbookPath}`);
  }

  links.push(`nohup setsid /bin/sh ${WRAPPER_PATH} ${argv} </dev/null >/dev/null 2>&1 &`);
  return links.join(' && ');
}

/**
 * Read one run's state plus whether its process group is still alive.
 *
 * `echo "K=$(...)"` rather than printf with an escape: every backslash here
 * would have to survive a JS template literal, curl's form encoding and
 * /bin/sh, and each layer eats one. Avoiding them entirely is cheaper than
 * counting them.
 */
function buildStateReadCommand(runId) {
  const id = assertUuid(runId, 'runId');
  const state = `${GUEST_BASE}/runs/${id}/state`;
  return [
    `echo "STATE=$(head -1 ${state} 2>/dev/null)"`,
    `P=$(grep -o 'pid=[0-9][0-9]*' ${state} 2>/dev/null | head -1 | cut -d= -f2)`,
    'A=0',
    // kill -0 alone would be fooled by PID recycling over a 45-minute run, so
    // confirm the PID is still OUR wrapper by reading its cmdline. Both are
    // shell/procfs builtins: no pgrep, and therefore no procps-ng dependency on
    // the sensor image.
    `if [ -n "$P" ] && kill -0 "$P" 2>/dev/null && grep -aq cc-attack /proc/"$P"/cmdline 2>/dev/null; then A=1; fi`,
    'echo "ALIVE=$A"',
  ].join('; ');
}

/**
 * Kill the process GROUP, not just the wrapper.
 *
 * `kill -TERM -$P` -- note the leading minus on the pid -- signals every
 * process in the group setsid created. Signalling the wrapper alone leaves
 * `timeout`, npm and node running, so the lane keeps generating after the
 * console reports it stopped. That regression is completely silent, which is
 * why attack-command.test.js asserts on the minus.
 */
function buildAbortCommand(runId) {
  const id = assertUuid(runId, 'runId');
  const state = `${GUEST_BASE}/runs/${id}/state`;
  return [
    `P=$(grep -o 'pid=[0-9][0-9]*' ${state} 2>/dev/null | head -1 | cut -d= -f2)`,
    `if [ -n "$P" ]; then kill -TERM -"$P" 2>/dev/null || true; fi`,
    `echo "aborted end=$(date +%s)" > ${state} 2>/dev/null || true`,
  ].join('; ');
}

/**
 * Parse what buildStateReadCommand printed.
 *
 * The state line is a flat `key=value` bag written by the wrapper's say(); its
 * first word is the phase. Unknown keys are ignored rather than rejected so an
 * older image talking to a newer server still reports something useful.
 *
 * @returns {{phase, alive, rc, lines, skew, fb, split, ref, pid, raw}}
 */
function parseGuestState(stdout) {
  const text = String(stdout || '');
  const stateLine = (text.match(/^STATE=(.*)$/m) || [, ''])[1].trim();
  const alive = (text.match(/^ALIVE=(\d)$/m) || [, '0'])[1] === '1';

  const kv = {};
  for (const tok of stateLine.split(/\s+/)) {
    const eq = tok.indexOf('=');
    if (eq > 0) kv[tok.slice(0, eq)] = tok.slice(eq + 1);
  }
  const num = (v) => (v != null && /^-?\d+$/.test(v) ? Number(v) : null);

  return {
    phase: stateLine.split(/\s+/)[0] || '',      // scheduled|running|done|refused|aborted
    reason: /^refused/.test(stateLine) ? (stateLine.split(/\s+/)[1] || 'unknown') : null,
    alive,
    rc: num(kv.rc),
    lines: num(kv.lines),
    skew: num(kv.skew),
    fellBack: kv.fb === '1',
    split: kv.split == null ? null : kv.split === '1',
    ref: kv.ref || null,
    // 'emitter' when a playbook produced the run, 'loggen' for the keyword
    // filter. Absent on older images, which parseGuestState tolerates by
    // design -- unknown keys are ignored rather than rejected.
    src: kv.src || null,
    pid: num(kv.pid),
    raw: stateLine,
  };
}

// ---------------------------------------------------------------------------
// Target discovery
// ---------------------------------------------------------------------------

const { cybercoreQuery } = require('../../../../../src/utils/cybercore-db');
const { proxmoxAPI } = require('../../../../../src/utils/proxmox');
const { query } = require('./db');
const { getSchedulingConfig } = require('../../../../../src/utils/site-config');

/**
 * Lazily required. src/utils/batch-deployer calls getSchedulingConfig() at
 * MODULE level, and that reads config/site.json -- which is gitignored and
 * absent in a plain checkout. Requiring it at the top would make this whole
 * file unimportable outside a deployed environment, and the pure command
 * builders above have to stay unit-testable with no infrastructure at all.
 * Deferring to first use costs one property lookup per dispatch.
 */
let _runBatch = null;
function runBatch(...args) {
  if (!_runBatch) _runBatch = require('../../../../../src/utils/batch-deployer').runBatch;
  return _runBatch(...args);
}

/** Same reason: resolved per call, not at load. */
function dispatchConcurrency() {
  return Math.max(1, Number(getSchedulingConfig().max_concurrent_lanes) || 5);
}
const attackTarget = require('./attack-target');

/**
 * Every active lane belonging to a course, with its owner's email.
 *
 * Deliberately NOT filtered to `config->>'material_id' IS NULL` the way
 * vuln-lab-provision.findCourseLanes() is. That filter separates a student's
 * workstation lane from their vulnerable-lab lane, but CYBR 400's sensor pair
 * can legitimately arrive by either route depending on how the instructor
 * deployed it. Resolving both and skipping the one without a sensor is honest;
 * guessing the wrong route silently targets nothing.
 */
async function findCourseLanes(courseId) {
  const r = await cybercoreQuery(
    `SELECT l.lane_id, l.user_id, l.name, l.status, l.module_key, l.config,
            u.email AS student_email, u.first_name, u.last_name
       FROM cybercore_lane l
       JOIN cybercore_user u ON u.user_id = l.user_id
      WHERE l.config->>'course_id' = $1
        AND l.status = 'active'
      ORDER BY u.email, l.created_at DESC`,
    [courseId]
  );
  return r.rows;
}

/**
 * Live power state for every VM in the cluster, keyed by vmid.
 *
 * One call, up front. Skipping a stopped VM BEFORE attempting exec is the
 * single biggest protection for the synchronized start: agentShellExec retries
 * a dead guest five times with 2/4/6/8s backoff, so thirty stopped lanes would
 * burn twenty minutes of the start window on hosts that were never going to
 * answer. Same one-call pattern as cle/routes/labs.js.
 */
async function loadPowerStates() {
  try {
    const resources = await proxmoxAPI('GET', '/api2/json/cluster/resources?type=vm');
    const byVmid = new Map();
    for (const r of (resources || [])) byVmid.set(Number(r.vmid), r.status || 'unknown');
    return byVmid;
  } catch (err) {
    // A cluster-wide read failing must not block the run: fall through with an
    // empty map so every lane is attempted, and let per-lane dispatch report.
    console.warn(`[AttackRunner] could not read cluster power states: ${err.message}`);
    return new Map();
  }
}

/**
 * Resolve every lane in a course to its sensor VM.
 *
 * One catalog + spec lookup is shared across lanes rather than repeated per
 * lane. Lanes are then collapsed per student: a student holding both a
 * workstation lane and a lab lane must be attacked once, on whichever lane
 * actually carries the sensor.
 *
 * @returns {Promise<Array>} one entry per STUDENT, resolvable or not
 */
async function resolveCourseTargets(courseId, { probe = null } = {}) {
  const [lanes, template, power] = await Promise.all([
    findCourseLanes(courseId),
    attackTarget.loadLoggenTemplate().catch(() => null),
    loadPowerStates(),
  ]);

  const specCache = new Map();
  const byUser = new Map();

  for (const lane of lanes) {
    const config = typeof lane.config === 'string' ? JSON.parse(lane.config || '{}') : (lane.config || {});
    const cacheKey = `${lane.module_key || config.module}::${config.challenge_key}`;
    if (!specCache.has(cacheKey)) {
      specCache.set(cacheKey, await attackTarget.loadSpecVms(lane, config));
    }
    const resolved = await attackTarget.resolveLoggenTarget(lane, {
      template,
      specVms: specCache.get(cacheKey),
      probe,
    });

    const entry = {
      lane_id: lane.lane_id,
      user_id: lane.user_id,
      lane_name: lane.name,
      student_email: lane.student_email,
      student_name: [lane.first_name, lane.last_name].filter(Boolean).join(' ') || null,
      node: resolved.vmid ? resolved.node : (config.node || null),
      vmid: resolved.vmid || null,
      vm_name: resolved.vm_name || null,
      resolved_by: resolved.resolved_by || null,
      power_state: resolved.vmid ? (power.get(Number(resolved.vmid)) || 'unknown') : null,
      skip_reason: resolved.vmid ? null : resolved.reason,
    };
    if (entry.vmid && entry.power_state !== 'running' && entry.power_state !== 'unknown') {
      entry.skip_reason = `the log-generator VM is ${entry.power_state}`;
    }
    entry.resolvable = !entry.skip_reason;

    // Keep the lane that actually resolved; a student's other lane is noise.
    const prev = byUser.get(lane.user_id);
    if (!prev || (entry.resolvable && !prev.resolvable)) byUser.set(lane.user_id, entry);
  }

  return [...byUser.values()].sort((a, b) => String(a.student_email).localeCompare(String(b.student_email)));
}

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

/** Bounds on the lead time granted for dispatch before the shared start. */
const LEAD_MIN_S = 30;
const LEAD_MAX_S = 180;

/**
 * How long to give dispatch before every guest fires.
 *
 * Linear in lane count with a floor and a ceiling: 30 lanes lands on ~56s,
 * which is long enough to stage every wrapper without making the instructor
 * watch a countdown they will find intolerable. Exposed so the route can show
 * it and the tests can pin it.
 */
function leadSecondsFor(targetCount) {
  return Math.min(LEAD_MAX_S, Math.max(LEAD_MIN_S, Math.round(20 + 1.2 * targetCount)));
}

/** Guest probe used during resolution — cheap, and only reached on rung 4. */
function makeGuestProbe(api = proxmoxAPI) {
  return async ({ node, vmid }) => {
    const { pid } = await agentShellExec(node, vmid, `test -f ${attackTarget.LOGGEN_MARKER} && echo YES || echo NO`);
    const status = await pollExecStatus(node, vmid, pid, 30000);
    return /YES/.test(status && status.stdout ? status.stdout : '');
  };
}

/**
 * Fan a resolved run out to every target and record what happened.
 *
 * Runs detached from the HTTP request (the route has already returned 202), but
 * unlike every other background job in this codebase its state is durable: the
 * cle_attack_target rows are the record, not an in-memory registry, so a
 * restart mid-dispatch loses at most the rows still marked 'dispatching' —
 * which recoverAttackRuns() then marks 'unknown' rather than inventing an
 * outcome for.
 */
async function dispatchRun({ runId, selection, targets, api = proxmoxAPI }) {
  const dispatchable = targets.filter((t) => t.resolvable && t.vmid && t.node);
  const lead = leadSecondsFor(dispatchable.length);
  const startEpoch = Math.floor(Date.now() / 1000) + lead;

  await query(
    `UPDATE cle_attack_run
        SET lead_seconds = $2, scheduled_start_at = to_timestamp($3), status = 'dispatching'
      WHERE run_id = $1`,
    [runId, lead, startEpoch]
  );

  const concurrency = dispatchConcurrency();

  await runBatch(dispatchable, async (t) => {
    // Recomputed per lane, at the instant this lane is actually dispatched.
    // That is what makes the relative fallback trustworthy on a guest whose
    // clock disagrees: it never depends on a shared epoch.
    const relDelay = Math.max(0, startEpoch - Math.floor(Date.now() / 1000));
    // Too late to make the common start. Fire immediately and say so, rather
    // than skipping a student who would otherwise get nothing.
    const late = relDelay < 5;

    await query(
      `UPDATE cle_attack_target
          SET status = 'dispatching', dispatched_at = NOW(), late = $3, updated_at = NOW()
        WHERE run_id = $1 AND lane_id = $2`,
      [runId, t.lane_id, late]
    );

    try {
      const cmd = buildDispatchCommand({
        runId,
        startEpoch,
        relDelaySeconds: late ? 0 : relDelay,
        mode: selection.mode,
        arg: selection.arg,
        duration: selection.duration,
        capSeconds: selection.capSeconds,
        speed: selection.speed,
        playbookJson: playbookFor(selection),
      });

      // waitForAgentExecReady is deliberately skipped: it costs 5-6s per VM and
      // targets freshly-cloned guests, while agentShellExec already retries
      // transient 596s internally. See this file's header.
      const { pid } = await agentShellExec(t.node, t.vmid, cmd);
      // Short poll, and deliberately SHORT. This exec only stages the wrapper
      // and forks it, so a healthy guest answers in well under a second.
      //
      // It used to wait 60s. That is dangerous at class scale for a reason that
      // has nothing to do with the guest: exec-status GETs cross the
      // pveproxy -> pvedaemon hop this repo documents as a common source of
      // transient 596s, and every one of them is swallowed by the poll loop. A
      // lane whose polls all 596 burned the full 60s before giving up, and with
      // 30 lanes sharing a concurrency pool that pushes later lanes past the
      // synchronized start -- the one thing this whole feature exists to get
      // right.
      //
      // Since the sweeper confirms liveness from the guest state file within
      // 30s, and the catch below no longer fails a target the sweeper has
      // advanced, this poll is advisory. Fail fast and let the sweeper decide.
      const status = await pollExecStatus(t.node, t.vmid, pid, 15000);

      // A TIMEOUT IS NOT A FAILURE, and conflating the two is what reported a
      // live attack as failed.
      //
      // `exited: false` means only that we could not watch the exec finish --
      // on this cluster usually a transient 596 on the pveproxy -> pvedaemon
      // hop that exec-status crosses. The wrapper's state file is the authority
      // and the sweeper reads it within 30s. If the wrapper genuinely died
      // without writing anything, attack-worker terminalizes the target with
      // "wrapper exited before writing any state", which is both accurate and
      // more useful than anything guessable from here.
      //
      // Shortening this poll to 15s made the old behaviour strictly worse: the
      // sweeper only claims 'dispatching' targets after 20s, so a compare-and-set
      // guard against it could never fire and the dispatcher always won.
      //
      // A non-zero EXIT is different -- that is the guest telling us staging
      // actually failed (no setsid, bad base64), and it should fail fast.
      if (status.exited && status.exitcode !== 0) {
        throw new Error(
          `staging exited ${status.exitcode}: ${(status.stderr || status.stdout || '').slice(0, 300)}`
        );
      }
      const staged = status.exited && status.exitcode === 0;

      const expectedFinish = startEpoch + (selection.durationSeconds || selection.capSeconds);
      // Only move the status if the sweeper has not already moved it further.
      // pollExecStatus above can take up to 60s, and the sweeper claims
      // 'dispatching' targets after 20s -- so by the time we get here it may
      // already have read the guest's state file and set 'running'. Writing
      // 'scheduled' unconditionally would walk that backwards.
      // expected_finish_at is set either way -- attack-worker schedules its
      // finishing poll off it, and a target with no deadline is one the sweeper
      // never checks at the right moment.
      //
      // The STATUS only advances when staging was actually confirmed. Moving an
      // unconfirmed target to 'scheduled' would hide it from the sweeper's
      // empty-state check, which only fires while status is 'dispatching' --
      // so a wrapper that never started would sit at 'scheduled' forever
      // instead of being failed with a real reason.
      await query(
        `UPDATE cle_attack_target
            SET status = CASE WHEN status = 'dispatching' AND $4::boolean
                              THEN 'scheduled' ELSE status END,
                expected_finish_at = to_timestamp($3), error = NULL, updated_at = NOW()
          WHERE run_id = $1 AND lane_id = $2`,
        [runId, t.lane_id, expectedFinish, staged]
      );
      // Cheap on a hit, and saves the whole ladder next time.
      await attackTarget.cacheLoggenTarget(t.lane_id, {
        vmid: t.vmid, node: t.node, vm_name: t.vm_name, resolved_by: t.resolved_by,
      });
      return { lane_id: t.lane_id, ok: true };
    } catch (err) {
      // The staging exec is NOT authoritative about whether the attack is
      // running, and treating it as such reports live attacks as failures.
      //
      // It watches a guest-exec that only stages the wrapper and forks it. The
      // wrapper writing /opt/cybercore/runs/<id>/state is far stronger evidence,
      // and the sweeper reads that every 30s. pollExecStatus waits a full 60s
      // before giving up, so the sweeper has usually already claimed this target
      // and advanced it -- and an unconditional UPDATE here then overwrites a
      // RUNNING attack with 'failed'.
      //
      // Observed exactly that: T1005 generating a visible spike in Kibana while
      // the console showed "staging exited -1: Timed out", with started_at and
      // clock_skew_s already populated by the sweeper on the same row.
      //
      // So: only fail a target that is still sitting where dispatch left it.
      const r = await query(
        `UPDATE cle_attack_target
            SET status = 'failed', error = $3, finished_at = NOW(), updated_at = NOW()
          WHERE run_id = $1 AND lane_id = $2
            AND status = 'dispatching'`,
        [runId, t.lane_id, String(err.message || err).slice(0, 500)]
      );
      if (!r.rowCount) {
        // Already past 'dispatching' -- the guest answered, so the wrapper is
        // alive and this exception was about our visibility, not the attack.
        return { lane_id: t.lane_id, ok: true };
      }
      return { lane_id: t.lane_id, ok: false };
    }
  }, { concurrency });

  await finalizeRunStatus(runId);
  return { lead, startEpoch, dispatched: dispatchable.length };
}

/**
 * Roll per-target rows up into the run's own status.
 *
 * 'partial' is a first-class outcome, not an error: with 30 lanes, one box
 * being off is routine and must not present as a failed class-wide attack.
 * The run only becomes terminal once no target is still in flight.
 */
async function finalizeRunStatus(runId) {
  const r = await query(
    `SELECT
        COUNT(*)                                                          AS total,
        COUNT(*) FILTER (WHERE status IN ('dispatching','scheduled','running')) AS live,
        COUNT(*) FILTER (WHERE status = 'completed')                      AS completed,
        COUNT(*) FILTER (WHERE status IN ('failed','unknown'))            AS bad,
        COUNT(*) FILTER (WHERE status = 'skipped')                        AS skipped,
        COUNT(*) FILTER (WHERE status = 'aborted')                        AS aborted
       FROM cle_attack_target WHERE run_id = $1`,
    [runId]
  );
  const s = r.rows[0] || {};
  const n = (v) => Number(v || 0);
  if (n(s.live) > 0) {
    await query(`UPDATE cle_attack_run SET status = 'running' WHERE run_id = $1 AND status <> 'aborted'`, [runId]);
    return 'running';
  }
  let status = 'completed';
  if (n(s.aborted) > 0 && n(s.completed) === 0) status = 'aborted';
  else if (n(s.completed) === 0 && n(s.bad) > 0) status = 'failed';
  else if (n(s.bad) > 0 || n(s.skipped) > 0) status = 'partial';

  await query(
    `UPDATE cle_attack_run SET status = $2, finished_at = COALESCE(finished_at, NOW()) WHERE run_id = $1`,
    [runId, status]
  );
  return status;
}

// ---------------------------------------------------------------------------
// Abort / retry
// ---------------------------------------------------------------------------

/**
 * Stop a run everywhere it is still live.
 *
 * Marks rows aborted whether or not the kill lands: a guest we cannot reach is
 * one we also cannot verify, and leaving it 'running' forever would block the
 * course's next dispatch on a lane nobody can fix.
 */
async function abortRun(runId, api = proxmoxAPI) {
  const r = await query(
    `SELECT lane_id, node, vmid FROM cle_attack_target
      WHERE run_id = $1 AND status IN ('dispatching','scheduled','running')`,
    [runId]
  );
  const live = r.rows.filter((t) => t.node && t.vmid);
  const cmd = buildAbortCommand(runId);

  await runBatch(live, async (t) => {
    try {
      const { pid } = await agentShellExec(t.node, t.vmid, cmd);
      await pollExecStatus(t.node, t.vmid, pid, 45000);
    } catch (err) {
      console.warn(`[AttackRunner] abort could not reach lane ${t.lane_id}: ${err.message}`);
    }
  }, { concurrency: dispatchConcurrency() });

  await query(
    `UPDATE cle_attack_target
        SET status = 'aborted', finished_at = NOW(), updated_at = NOW()
      WHERE run_id = $1 AND status IN ('dispatching','scheduled','running')`,
    [runId]
  );
  await query(
    `UPDATE cle_attack_run SET status = 'aborted', finished_at = COALESCE(finished_at, NOW()) WHERE run_id = $1`,
    [runId]
  );
  return { aborted: live.length };
}

/**
 * Re-fire the lanes that missed, at a fresh common start.
 *
 * They cannot join the original one — that moment has passed — so every retried
 * target is flagged `late` and its attempt is bumped, and the UI says "started
 * N minutes late" rather than implying the class is back in lockstep. Firing
 * them at a shared T2 still keeps the retried group comparable with each other,
 * which is the usual case ("three lanes were asleep, fire those three").
 */
async function retryTargets({ runId, laneIds = null, selection, api = proxmoxAPI }) {
  const r = await query(
    laneIds && laneIds.length
      ? `SELECT * FROM cle_attack_target WHERE run_id = $1 AND lane_id = ANY($2::uuid[])`
      : `SELECT * FROM cle_attack_target WHERE run_id = $1 AND status IN ('failed','skipped','unknown')`,
    laneIds && laneIds.length ? [runId, laneIds] : [runId]
  );
  if (r.rows.length === 0) return { retried: 0 };

  // Re-resolve rather than reusing the stored vmid: the usual reason a lane was
  // skipped is that it had no identifiable sensor, and a lane repaired since
  // then needs the ladder run again.
  const fresh = await resolveCourseTargets(
    (await query(`SELECT course_id FROM cle_attack_run WHERE run_id = $1`, [runId])).rows[0].course_id,
    { probe: makeGuestProbe(api) }
  );
  const wanted = new Set(r.rows.map((t) => t.lane_id));
  const targets = fresh.filter((t) => wanted.has(t.lane_id));

  for (const t of targets) {
    await query(
      `UPDATE cle_attack_target
          SET status = $3, node = $4, vmid = $5, vm_name = $6, resolved_by = $7,
              skip_reason = $8, late = TRUE, attempt = attempt + 1,
              error = NULL, exit_code = NULL, event_count = NULL,
              started_at = NULL, finished_at = NULL, last_checked_at = NULL,
              check_failures = 0, updated_at = NOW()
        WHERE run_id = $1 AND lane_id = $2`,
      [runId, t.lane_id, t.resolvable ? 'pending' : 'skipped',
       t.node, t.vmid, t.vm_name, t.resolved_by, t.skip_reason]
    );
  }

  await query(`UPDATE cle_attack_run SET status = 'dispatching', finished_at = NULL WHERE run_id = $1`, [runId]);
  const result = await dispatchRun({ runId, selection, targets, api });
  return { retried: targets.filter((t) => t.resolvable).length, ...result };
}

module.exports = {
  // command construction (pure — unit tested)
  resolveSelection,
  buildDispatchCommand,
  buildStateReadCommand,
  buildAbortCommand,
  parseGuestState,
  leadSecondsFor,
  // discovery + orchestration
  findCourseLanes,
  loadPowerStates,
  resolveCourseTargets,
  makeGuestProbe,
  dispatchRun,
  finalizeRunStatus,
  abortRun,
  retryTargets,
  // constants
  WRAPPER_SH,
  PLAYBOOKS,
  playbookFor,
  GUEST_BASE,
  WRAPPER_PATH,
};
