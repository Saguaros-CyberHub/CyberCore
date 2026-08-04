/**
 * ============================================================================
 * FLAG MANAGER
 * HTB-style user/root capture flags, one random pair per VM per student lane.
 * ----------------------------------------------------------------------------
 * Values are generated HERE, persisted, and only then written into the guest.
 * The guest never generates anything. That ordering is what makes planting
 * idempotent: re-running a plant re-reads the canonical value out of the DB
 * instead of minting a new one and silently desyncing disk from database.
 *
 * SECURITY — why this module does not use executeScriptsOnVM:
 *   executePowerShellViaFile stages the script to C:\Windows\Temp\vuln_*.ps1
 *   and tees its output to a sibling .log. The Remove-Item lives INSIDE the
 *   stub, so a timed-out run leaves the script on disk, and the log cleanup is
 *   fire-and-forget (.catch(() => {})). C:\Windows\Temp is traversable by
 *   Users. A student holding the low-priv shell we deliberately gave them
 *   could read the root flag out of either file and skip the privilege
 *   escalation entirely. So flags go through agentExecArgv / agentShellExec:
 *   one short command, no staged file, no log, nothing left behind.
 * ============================================================================
 */

const crypto = require('crypto');
const { cybercoreQuery } = require('./cybercore-db');
const { proxmoxAPI } = require('./proxmox');
const {
  waitForGuestAgent,
  waitForAgentExecReady,
  agentExecArgv,
  agentShellExec,
  pollExecStatus
} = require('./script-executor');

// 32 lowercase hex — matches HackTheBox, and matches what the existing
// 480Scripts/Plant-Loot.ps1 already produces, so guides don't need rewriting.
const FLAG_RE = /^[a-f0-9]{32}$/;

// Full path so QEMU guest-agent CreateProcess resolves it regardless of the
// guest's PATH. Same constant goad-deploy.js uses.
const WIN_PS = 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe';

// Uniform response for every failure mode. A flag belonging to another
// student's lane is indistinguishable from random garbage — the student must
// not be able to use the error message as an oracle telling them a shared
// value was "real, just not yours".
const INCORRECT_MESSAGE = 'Incorrect Flag';

// Windows profile directories that never belong to a student-facing account.
const WIN_BUILTIN_PROFILES = [
  'Public', 'Default', 'Default User', 'All Users', 'Administrator', 'defaultuser0'
];

const FLAG_TYPES = ['user', 'root'];

// ============================================================================
// GENERATION + PERSISTENCE
// ============================================================================

/** @returns {string} 32 lowercase hex characters from the CSPRNG. */
function generateFlagValue() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Constant-time string compare. A plain `===` (or a SQL `=` on the indexed
 * column) leaks match position through timing.
 */
function timingSafeEqualStr(a, b) {
  const ba = Buffer.from(String(a), 'utf8');
  const bb = Buffer.from(String(b), 'utf8');
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

/**
 * Pull a flag out of whatever the student pasted. They routinely paste the
 * whole line from the file ("Flag: abc123...") or wrap it in braces.
 * @returns {string|null} the normalized 32-hex value, or null if there isn't one
 */
function normalizeSubmission(raw) {
  const s = String(raw == null ? '' : raw).trim().toLowerCase();
  if (FLAG_RE.test(s)) return s;
  const m = s.match(/[a-f0-9]{32}/);
  return m ? m[0] : null;
}

/**
 * Create the user+root flag rows for every VM in a lane, or return the
 * existing values untouched if they are already there.
 *
 * The ON CONFLICT branch deliberately re-assigns the column to itself. That is
 * a no-op write whose only purpose is to make RETURNING fire on the conflict
 * path, so the caller always gets the canonical value back whether the row was
 * just created or already existed. Calling this twice never rotates a flag.
 *
 * @param {object}   a
 * @param {string}   a.laneId
 * @param {string}   a.userId  owning student (cybercore_user.user_id)
 * @param {Array<{name:string}>} a.vms
 * @returns {Promise<Array<{vmName:string, flagType:string, flagId:string, flagValue:string, plantStatus:string}>>}
 */
async function ensureLaneFlags({ laneId, userId, vms }) {
  const out = [];
  for (const vm of (vms || [])) {
    if (!vm || !vm.name) continue;
    for (const flagType of FLAG_TYPES) {
      const result = await cybercoreQuery(
        `INSERT INTO cybercore_lane_flag (lane_id, user_id, vm_name, flag_type, flag_value)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (lane_id, vm_name, flag_type)
         DO UPDATE SET flag_value = cybercore_lane_flag.flag_value,
                       updated_at = NOW()
         RETURNING flag_id, flag_value, plant_status`,
        [laneId, userId, vm.name, flagType, generateFlagValue()]
      );
      const row = result.rows[0];
      out.push({
        vmName: vm.name,
        flagType,
        flagId: row.flag_id,
        flagValue: row.flag_value,
        plantStatus: row.plant_status
      });
    }
  }
  return out;
}

async function setPlantStatus(flagId, status, error = null) {
  await cybercoreQuery(
    `UPDATE cybercore_lane_flag
        SET plant_status = $2,
            plant_error  = $3,
            planted_at   = CASE WHEN $2 = 'planted' THEN NOW() ELSE planted_at END,
            updated_at   = NOW()
      WHERE flag_id = $1`,
    [flagId, status, error ? String(error).substring(0, 1000) : null]
  );
}

// ============================================================================
// PLANTING
// ============================================================================

/**
 * Ask the guest agent what OS it is running. Used only when the challenge spec
 * doesn't declare `vms[].os`, so existing challenge rows keep working unedited.
 * @returns {Promise<'windows'|'linux'|null>}
 */
async function detectGuestOs(node, vmId, api = proxmoxAPI) {
  try {
    const info = await api('GET', `/api2/json/nodes/${node}/qemu/${vmId}/agent/get-osinfo`);
    const r = info?.result || info || {};
    const hay = `${r.id || ''} ${r.name || ''} ${r['pretty-name'] || ''}`.toLowerCase();
    if (!hay.trim()) return null;
    return /windows|mswindows/.test(hay) ? 'windows' : 'linux';
  } catch (e) {
    return null;
  }
}

/**
 * Coerce a challenge spec's `vms[].os` into 'windows' | 'linux', or null when it
 * says nothing useful and the guest should be probed instead.
 *
 * The raw value is NOT trustworthy as a discriminator. Admin → Create Lab writes
 * `os: vm.os || 'Unknown'` (routes/lab-templates.js), and migration 024 only
 * backfills specs where the key is ABSENT — so 'Unknown' survives. An admin who
 * types a human OS name gets 'Windows Server 2019'. Both are truthy, so the old
 * `spec.os || detectGuestOs()` short-circuited the probe, and the subsequent
 * `os === 'windows'` test then failed, sending a /bin/sh flag planter at a
 * Windows domain controller. Every flag on a GOAD lane failed that way.
 *
 * Anything unrecognized returns null so the caller falls back to the guest-agent
 * probe, which is authoritative.
 */
function normalizeOs(raw) {
  const s = String(raw || '').trim().toLowerCase();
  if (!s) return null;
  if (/win/.test(s)) return 'windows';
  if (/linux|ubuntu|debian|centos|rocky|rhel|fedora|alpine|kali|suse|arch|bsd|unix/.test(s)) return 'linux';
  return null;  // 'Unknown', or something we shouldn't guess at — probe instead.
}

/**
 * Paths come from admin-authored challenge spec JSON, but they end up inside a
 * single-quoted shell/PowerShell literal, so validate rather than trust.
 * Rejects quotes, backticks, $, ; and newlines.
 *
 * The explicit newline check is not redundant with the character class: in
 * JavaScript `$` also matches immediately BEFORE a trailing newline, so
 * /^[safe]+$/ happily accepts "/root/root.txt\n" — which would terminate the
 * command and let whatever follows run as its own statement.
 */
function isSafePath(p) {
  return typeof p === 'string'
    && p.length > 0
    && p.length <= 260
    && !/[\r\n]/.test(p)
    && /^[A-Za-z0-9 _.:\\/\-]+$/.test(p);
}

function assertPlantable(flagValue) {
  if (!FLAG_RE.test(flagValue)) {
    throw new Error('refusing to plant a flag that is not 32 hex characters');
  }
}

/**
 * Run one command in a Windows guest and throw unless it exits 0.
 * argv form — no shell, no staged file, no interpolation by a shell parser.
 */
async function winExec(node, vmId, psCommand, api = proxmoxAPI, timeoutMs = 120000) {
  const { pid } = await agentExecArgv(
    node, vmId,
    [WIN_PS, '-NoProfile', '-NonInteractive', '-Command', psCommand],
    api
  );
  const status = await pollExecStatus(node, vmId, pid, timeoutMs);
  if (!status.exited) throw new Error('guest command timed out');
  if (status.exitcode !== 0) {
    throw new Error(`guest command exited ${status.exitcode}: ${(status.stderr || status.stdout || '').substring(0, 300)}`);
  }
  return status;
}

/** Run one command in a Linux guest and throw unless it exits 0. */
async function linuxExec(node, vmId, shellCommand, timeoutMs = 120000) {
  const { pid } = await agentShellExec(node, vmId, shellCommand);
  const status = await pollExecStatus(node, vmId, pid, timeoutMs);
  if (!status.exited) throw new Error('guest command timed out');
  if (status.exitcode !== 0) {
    throw new Error(`guest command exited ${status.exitcode}: ${(status.stderr || status.stdout || '').substring(0, 300)}`);
  }
  return status;
}

/**
 * Write user.txt to every real user profile on a Windows guest.
 *
 * Writing to all non-builtin profiles rather than discovering "the" student
 * account avoids a second round-trip and is robust to the target having more
 * than one low-priv user — whichever account the student lands on, they find
 * the same value. An explicit `targets.user.path` in the challenge spec
 * overrides this entirely.
 */
async function plantWindowsUserFlag(node, vmId, flagValue, explicitPath, api) {
  assertPlantable(flagValue);

  if (explicitPath) {
    if (!isSafePath(explicitPath)) throw new Error(`unsafe user flag path: ${explicitPath}`);
    const dir = explicitPath.replace(/\\[^\\]+$/, '');
    return winExec(node, vmId,
      `New-Item -ItemType Directory -Force -Path '${dir}' | Out-Null; ` +
      `Set-Content -LiteralPath '${explicitPath}' -Value '${flagValue}' -Encoding ascii -NoNewline`,
      api);
  }

  const skip = WIN_BUILTIN_PROFILES.map(n => `'${n}'`).join(',');
  return winExec(node, vmId,
    `$skip = @(${skip}); ` +
    `$n = 0; ` +
    `Get-ChildItem 'C:\\Users' -Directory -ErrorAction SilentlyContinue | ` +
    `Where-Object { $skip -notcontains $_.Name } | ForEach-Object { ` +
    `  $d = Join-Path $_.FullName 'Desktop'; ` +
    `  New-Item -ItemType Directory -Force -Path $d | Out-Null; ` +
    `  Set-Content -LiteralPath (Join-Path $d 'user.txt') -Value '${flagValue}' -Encoding ascii -NoNewline; ` +
    `  $n++ }; ` +
    // A target with no student profile yet is a real misconfiguration, not a
    // transient — fail loudly so it shows on the instructor dashboard.
    `if ($n -eq 0) { Write-Error 'no non-builtin user profile found'; exit 1 }; exit 0`,
    api);
}

/**
 * Write root.txt to the Administrator desktop and strip inherited ACLs so the
 * low-priv account genuinely cannot read it. Without the icacls step the whole
 * exercise is pointless — the student could read root.txt from their user shell.
 */
async function plantWindowsRootFlag(node, vmId, flagValue, explicitPath, api) {
  assertPlantable(flagValue);

  const target = explicitPath || 'C:\\Users\\Administrator\\Desktop\\root.txt';
  if (!isSafePath(target)) throw new Error(`unsafe root flag path: ${target}`);
  const dir = target.replace(/\\[^\\]+$/, '');

  return winExec(node, vmId,
    `New-Item -ItemType Directory -Force -Path '${dir}' | Out-Null; ` +
    `Set-Content -LiteralPath '${target}' -Value '${flagValue}' -Encoding ascii -NoNewline; ` +
    `icacls '${target}' /inheritance:r /grant 'BUILTIN\\Administrators:F' /grant 'NT AUTHORITY\\SYSTEM:F' | Out-Null; ` +
    `exit $LASTEXITCODE`,
    api);
}

/**
 * Write user.txt into every /home/<user> directory, owned by that directory's
 * owner and world-readable — same "any account the student lands on finds it"
 * reasoning as the Windows side.
 */
async function plantLinuxUserFlag(node, vmId, flagValue, explicitPath) {
  assertPlantable(flagValue);

  if (explicitPath) {
    if (!isSafePath(explicitPath)) throw new Error(`unsafe user flag path: ${explicitPath}`);
    const dir = explicitPath.replace(/\/[^/]+$/, '') || '/';
    return linuxExec(node, vmId,
      `mkdir -p '${dir}' && printf %s '${flagValue}' > '${explicitPath}' && chmod 644 '${explicitPath}'`);
  }

  return linuxExec(node, vmId,
    `n=0; for d in /home/*; do ` +
    `[ -d "$d" ] || continue; ` +
    `u=$(stat -c %U "$d" 2>/dev/null || echo root); ` +
    `printf %s '${flagValue}' > "$d/user.txt" || continue; ` +
    // User only, no group: `chown u:u` fails outright on a distro that does not
    // create a matching per-user group, and mode 644 already makes it readable.
    `chown "$u" "$d/user.txt" 2>/dev/null; ` +
    `chmod 644 "$d/user.txt"; ` +
    `n=$((n+1)); ` +
    `done; ` +
    `if [ "$n" -eq 0 ]; then echo "no /home/* directory found" >&2; exit 1; fi; exit 0`);
}

/** Write /root/root.txt as 0600 root:root — unreadable without escalation. */
async function plantLinuxRootFlag(node, vmId, flagValue, explicitPath) {
  assertPlantable(flagValue);

  const target = explicitPath || '/root/root.txt';
  if (!isSafePath(target)) throw new Error(`unsafe root flag path: ${target}`);
  const dir = target.replace(/\/[^/]+$/, '') || '/';

  return linuxExec(node, vmId,
    `mkdir -p '${dir}' && printf %s '${flagValue}' > '${target}' && ` +
    `chown root:root '${target}' && chmod 600 '${target}'`);
}

/**
 * Generate (or re-read) and plant both flags on every QEMU VM in a lane.
 *
 * This is the single entry point every deploy path calls. Best-effort by
 * design: one unreachable VM must not abort the rest of a class deploy, so
 * failures are recorded as plant_status='failed' (surfaced on the instructor
 * dashboard) rather than thrown.
 *
 * LXC containers are skipped — they have no QEMU guest agent. The lane gateway
 * is the only LXC in a normal lane and is plumbing, not a target.
 *
 * @param {object} a
 * @param {string} a.laneId
 * @param {string} a.userId
 * @param {Array<{name:string, vm_id:number, node:string, type:string}>} a.vms  deployed VMs
 * @param {Array<object>} [a.specVms]  challenge spec vms[], for `os` and `flags` overrides
 * @param {function}      [a.api]      injected proxmoxAPI (deploy paths pass their own)
 * @param {string}        [a.logTag]
 * @returns {Promise<{planted:number, failed:number, skipped:number}>}
 */
async function plantFlagsForLane({ laneId, userId, vms, specVms = [], api = proxmoxAPI, logTag = '[Flags]' }) {
  const summary = { planted: 0, failed: 0, skipped: 0 };
  const targets = (vms || []).filter(v => v && v.name && v.type === 'qemu');
  summary.skipped = (vms || []).length - targets.length;

  if (targets.length === 0) {
    console.log(`${logTag} Lane ${laneId}: no QEMU VMs to plant flags on`);
    return summary;
  }

  const flags = await ensureLaneFlags({ laneId, userId, vms: targets });
  const byVm = new Map();
  for (const f of flags) {
    if (!byVm.has(f.vmName)) byVm.set(f.vmName, {});
    byVm.get(f.vmName)[f.flagType] = f;
  }

  for (const vm of targets) {
    const pair = byVm.get(vm.name);
    if (!pair) continue;

    const spec = (specVms || []).find(s => String(s.name).toLowerCase() === String(vm.name).toLowerCase()) || {};
    const overrides = spec.flags || {};

    try {
      const agentUp = await waitForGuestAgent(vm.node, vm.vm_id, 300000);
      if (!agentUp) throw new Error('guest agent never came up (5m)');

      // normalizeOs, not spec.os directly: a spec saying 'Unknown' or
      // 'Windows Server 2019' must fall through to the probe / resolve to
      // windows rather than be treated as Linux. See normalizeOs.
      const os = normalizeOs(spec.os) || await detectGuestOs(vm.node, vm.vm_id, api);
      if (!os) throw new Error('could not determine guest OS (declare vms[].os as "windows" or "linux" in the challenge spec)');

      // The exec channel 596s for a while after ping starts answering; probe it
      // for real before sending the first command. Only meaningful on Linux —
      // the Windows argv path goes through the standard proxmoxAPI, not curl.
      if (os === 'linux') {
        const execUp = await waitForAgentExecReady(vm.node, vm.vm_id, `${logTag}[${vm.name}]`, 180000);
        if (!execUp) throw new Error('guest exec channel never became ready (3m)');
      }

      for (const flagType of FLAG_TYPES) {
        const flag = pair[flagType];
        if (!flag) continue;
        try {
          const explicitPath = overrides[flagType]?.path;
          if (os === 'windows') {
            if (flagType === 'user') await plantWindowsUserFlag(vm.node, vm.vm_id, flag.flagValue, explicitPath, api);
            else                     await plantWindowsRootFlag(vm.node, vm.vm_id, flag.flagValue, explicitPath, api);
          } else {
            if (flagType === 'user') await plantLinuxUserFlag(vm.node, vm.vm_id, flag.flagValue, explicitPath);
            else                     await plantLinuxRootFlag(vm.node, vm.vm_id, flag.flagValue, explicitPath);
          }
          await setPlantStatus(flag.flagId, 'planted');
          summary.planted++;
          console.log(`${logTag} Planted ${flagType} flag on ${vm.name} (vm ${vm.vm_id}, ${os})`);
        } catch (err) {
          await setPlantStatus(flag.flagId, 'failed', err.message);
          summary.failed++;
          console.error(`${logTag} Failed to plant ${flagType} flag on ${vm.name}: ${err.message}`);
        }
      }
    } catch (err) {
      // VM-level failure — mark both flags failed so the instructor sees why.
      for (const flagType of FLAG_TYPES) {
        const flag = pair[flagType];
        if (flag) {
          await setPlantStatus(flag.flagId, 'failed', err.message).catch(() => {});
          summary.failed++;
        }
      }
      console.error(`${logTag} Failed to reach ${vm.name} (vm ${vm.vm_id}): ${err.message}`);
    }
  }

  console.log(`${logTag} Lane ${laneId}: ${summary.planted} planted, ${summary.failed} failed, ${summary.skipped} skipped`);
  return summary;
}

/**
 * Discard a lane's flag values and plant fresh ones. Admin escape hatch for a
 * lane where flags leaked or planting failed. Deletes rather than updates so
 * ensureLaneFlags regenerates; capture state is reset with them.
 */
async function rotateLaneFlags({ laneId, api = proxmoxAPI, logTag = '[Flags]' }) {
  const laneResult = await cybercoreQuery(
    `SELECT lane_id, user_id, module_key, config FROM cybercore_lane WHERE lane_id = $1`,
    [laneId]
  );
  if (laneResult.rows.length === 0) throw new Error('lane not found');

  const lane = laneResult.rows[0];
  const config = typeof lane.config === 'string' ? JSON.parse(lane.config) : (lane.config || {});

  // Re-resolve the challenge spec so os/flag-path overrides survive a rotate.
  // Lane config stores challenge_key but not the spec itself. Table name is
  // built from module_key with the same sanitizing pattern used in
  // routes/admin/lanes.js; on any miss we fall through to the get-osinfo probe.
  let specVms = [];
  const moduleKey = lane.module_key || config.module;
  if (moduleKey && config.challenge_key) {
    try {
      const table = `${String(moduleKey).replace(/[^a-z0-9_]/gi, '')}_challenge`;
      const chal = await cybercoreQuery(
        `SELECT spec FROM ${table} WHERE challenge_key = $1`,
        [config.challenge_key]
      );
      if (chal.rows.length > 0) {
        const spec = typeof chal.rows[0].spec === 'string'
          ? JSON.parse(chal.rows[0].spec) : (chal.rows[0].spec || {});
        specVms = Array.isArray(spec.vms) ? spec.vms : [];
      }
    } catch (err) {
      console.warn(`${logTag} Could not resolve challenge spec for rotate: ${err.message}`);
    }
  }

  await cybercoreQuery(`DELETE FROM cybercore_lane_flag WHERE lane_id = $1`, [laneId]);

  return plantFlagsForLane({
    laneId,
    userId: lane.user_id,
    vms: config.vms || [],
    specVms,
    api,
    logTag
  });
}

// ============================================================================
// SUBMISSION + VERIFICATION
// ============================================================================

async function recordSubmission({ userId, laneId = null, value, result, vmName = null, flagType = null, ip = null }) {
  try {
    await cybercoreQuery(
      `INSERT INTO cybercore_flag_submission
         (user_id, lane_id, submitted_value, result, vm_name, flag_type, ip_address)
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [userId, laneId, String(value).substring(0, 512), result, vmName, flagType, ip]
    );
  } catch (err) {
    // Never let audit-log failure block the student's answer.
    console.error(`[Flags] Failed to record submission: ${err.message}`);
  }
}

/**
 * Check a submitted flag against the submitting student's OWN lanes only.
 *
 * A value that is a real flag from someone else's lane returns exactly the same
 * response as random garbage, so the student cannot use the endpoint to confirm
 * a shared value is genuine. It is logged as `foreign_lane` for the instructor.
 *
 * @param {object} a
 * @param {string} a.userId
 * @param {string} a.value   raw student input
 * @param {string} [a.ip]
 * @returns {Promise<{correct:boolean, already?:boolean, vmName?:string, flagType?:string, message?:string}>}
 */
async function verifySubmission({ userId, value, ip = null }) {
  const candidate = normalizeSubmission(value);
  const auditValue = String(value == null ? '' : value).trim().substring(0, 512);

  if (!candidate) {
    await recordSubmission({ userId, value: auditValue, result: 'incorrect', ip });
    return { correct: false, message: INCORRECT_MESSAGE };
  }

  // Load the student's own flags and compare in Node. A SQL `=` on the indexed
  // flag_value column would be a non-constant-time compare; the row count here
  // is a handful per student, so the scan is free.
  const own = await cybercoreQuery(
    `SELECT f.flag_id, f.lane_id, f.vm_name, f.flag_type, f.flag_value, f.captured_at
       FROM cybercore_lane_flag f
       JOIN cybercore_lane l ON l.lane_id = f.lane_id
      WHERE f.user_id = $1
        AND l.status <> 'deleted'`,
    [userId]
  );

  const match = own.rows.find(r => timingSafeEqualStr(r.flag_value, candidate));

  if (match) {
    if (match.captured_at) {
      await recordSubmission({
        userId, laneId: match.lane_id, value: candidate, result: 'duplicate',
        vmName: match.vm_name, flagType: match.flag_type, ip
      });
      return {
        correct: true, already: true,
        vmName: match.vm_name, flagType: match.flag_type,
        capturedAt: match.captured_at
      };
    }

    // Guard the write too: two racing submissions must only award once.
    const claimed = await cybercoreQuery(
      `UPDATE cybercore_lane_flag
          SET captured_at = NOW(), updated_at = NOW()
        WHERE flag_id = $1 AND captured_at IS NULL
        RETURNING captured_at`,
      [match.flag_id]
    );
    const firstCapture = claimed.rowCount > 0;

    await recordSubmission({
      userId, laneId: match.lane_id, value: candidate,
      result: firstCapture ? 'correct' : 'duplicate',
      vmName: match.vm_name, flagType: match.flag_type, ip
    });

    return {
      correct: true,
      already: !firstCapture,
      vmName: match.vm_name,
      flagType: match.flag_type,
      capturedAt: claimed.rows[0]?.captured_at || match.captured_at
    };
  }

  // Not theirs. Is it anyone's? The student never learns the difference.
  const foreign = await cybercoreQuery(
    `SELECT lane_id, vm_name, flag_type FROM cybercore_lane_flag WHERE flag_value = $1`,
    [candidate]
  );
  const isForeign = foreign.rowCount > 0;

  await recordSubmission({
    userId,
    laneId: isForeign ? foreign.rows[0].lane_id : null,
    value: candidate,
    result: isForeign ? 'foreign_lane' : 'incorrect',
    vmName: isForeign ? foreign.rows[0].vm_name : null,
    flagType: isForeign ? foreign.rows[0].flag_type : null,
    ip
  });

  return { correct: false, message: INCORRECT_MESSAGE };
}

// ============================================================================
// READS
// ============================================================================

/**
 * A student's own capture progress. Deliberately never selects flag_value —
 * this response goes straight to the browser.
 */
async function getUserFlagProgress(userId) {
  const result = await cybercoreQuery(
    `SELECT f.lane_id, f.vm_name, f.flag_type, f.captured_at, f.plant_status, l.name AS lane_name
       FROM cybercore_lane_flag f
       JOIN cybercore_lane l ON l.lane_id = f.lane_id
      WHERE f.user_id = $1
        AND l.status <> 'deleted'
      ORDER BY l.created_at, f.vm_name, f.flag_type DESC`,
    [userId]
  );
  return result.rows.map(r => ({
    laneId: r.lane_id,
    laneName: r.lane_name,
    vmName: r.vm_name,
    flagType: r.flag_type,
    captured: !!r.captured_at,
    capturedAt: r.captured_at,
    // A student can't capture what was never written. Surface it so they
    // report a broken box instead of hunting for a file that isn't there.
    available: r.plant_status === 'planted'
  }));
}

/**
 * A student's flags with enough lane context to attribute them to a course.
 * Values are never selected — this feeds the student-facing board.
 */
async function getUserFlagRows(userId) {
  const result = await cybercoreQuery(
    `SELECT f.flag_id, f.lane_id, f.vm_name, f.flag_type, f.captured_at, f.plant_status,
            l.name AS lane_name,
            l.config->>'course_id'     AS course_id,
            l.config->>'challenge_key' AS challenge_key
       FROM cybercore_lane_flag f
       JOIN cybercore_lane l ON l.lane_id = f.lane_id
      WHERE f.user_id = $1
        AND l.status <> 'deleted'
      ORDER BY l.created_at, f.vm_name, f.flag_type DESC`,
    [userId]
  );
  return result.rows;
}

/**
 * Shape raw flag rows into the per-machine board the student UI renders:
 * one entry per VM holding its user and root flag state.
 */
function buildStudentBoard(rows) {
  const byVm = new Map();
  for (const r of rows) {
    const key = `${r.lane_id}:${r.vm_name}`;
    if (!byVm.has(key)) {
      byVm.set(key, {
        laneId: r.lane_id,
        laneName: r.lane_name,
        challengeKey: r.challenge_key,
        vmName: r.vm_name,
        user: null,
        root: null
      });
    }
    byVm.get(key)[r.flag_type] = {
      captured: !!r.captured_at,
      capturedAt: r.captured_at,
      // plant_status !== 'planted' means the file was never written into the
      // guest. The student must be told, or they hunt for a file that is not there.
      available: r.plant_status === 'planted'
    };
  }

  const machines = Array.from(byVm.values())
    .sort((a, b) => String(a.vmName).localeCompare(String(b.vmName)));

  const total    = rows.length;
  const captured = rows.filter(r => r.captured_at).length;

  return { machines, captured, total };
}

/** Full state for one lane, flag values included. Instructor/admin only. */
async function getLaneFlagState(laneId) {
  const result = await cybercoreQuery(
    `SELECT flag_id, lane_id, user_id, vm_name, flag_type, flag_value,
            plant_status, plant_error, planted_at, captured_at
       FROM cybercore_lane_flag
      WHERE lane_id = $1
      ORDER BY vm_name, flag_type DESC`,
    [laneId]
  );
  return result.rows;
}

/**
 * Cohort matrix for an instructor: every flag held by the given students, plus
 * each student's foreign-lane submission count (the sharing signal).
 *
 * Keyed on user_id rather than on cybercore_lane.config, deliberately. The two
 * provisioning paths stamp different keys — CLE's provisionLanes writes
 * config.course_id, while POST /api/admin/deploy-group (the path that actually
 * deploys challenge targets) writes config.group_id and no course at all. A
 * config-based filter would quietly return nothing for a group-deployed class.
 * The caller resolves the roster; this only has to look up their flags.
 *
 * @param {string[]} userIds
 */
async function getFlagStateForUsers(userIds) {
  const ids = (userIds || []).filter(Boolean);
  if (ids.length === 0) return { flags: [], foreignByUser: {} };

  const flags = await cybercoreQuery(
    `SELECT f.flag_id, f.lane_id, f.user_id, f.vm_name, f.flag_type, f.flag_value,
            f.plant_status, f.plant_error, f.captured_at,
            u.email, u.first_name, u.last_name
       FROM cybercore_lane_flag f
       JOIN cybercore_lane l ON l.lane_id = f.lane_id
       LEFT JOIN cybercore_user u ON u.user_id = f.user_id
      WHERE f.user_id = ANY($1::uuid[])
        AND l.status <> 'deleted'
      ORDER BY u.email, f.vm_name, f.flag_type DESC`,
    [ids]
  );

  const foreign = await cybercoreQuery(
    `SELECT user_id, COUNT(*)::int AS foreign_attempts, MAX(created_at) AS last_attempt
       FROM cybercore_flag_submission
      WHERE result = 'foreign_lane'
        AND user_id = ANY($1::uuid[])
      GROUP BY user_id`,
    [ids]
  );

  const foreignByUser = {};
  for (const r of foreign.rows) {
    foreignByUser[r.user_id] = { attempts: r.foreign_attempts, lastAttempt: r.last_attempt };
  }

  return { flags: flags.rows, foreignByUser };
}

/**
 * Collapse getFlagStateForUsers output into one row per student, ready for a
 * dashboard table. Shared by the CLE course view and any future group view.
 */
function buildCohortRows({ flags, foreignByUser }) {
  const byUser = new Map();
  for (const f of flags) {
    if (!byUser.has(f.user_id)) {
      byUser.set(f.user_id, {
        userId: f.user_id,
        email: f.email,
        name: [f.first_name, f.last_name].filter(Boolean).join(' ') || null,
        laneId: f.lane_id,
        flags: [],
        captured: 0,
        total: 0,
        plantFailures: 0,
        foreignAttempts: foreignByUser[f.user_id]?.attempts || 0,
        lastForeignAttempt: foreignByUser[f.user_id]?.lastAttempt || null
      });
    }
    const entry = byUser.get(f.user_id);
    entry.flags.push({
      vmName: f.vm_name,
      flagType: f.flag_type,
      flagValue: f.flag_value,
      plantStatus: f.plant_status,
      plantError: f.plant_error,
      captured: !!f.captured_at,
      capturedAt: f.captured_at
    });
    entry.total++;
    if (f.captured_at) entry.captured++;
    if (f.plant_status === 'failed') entry.plantFailures++;
  }

  return Array.from(byUser.values())
    .sort((a, b) => String(a.email || '').localeCompare(String(b.email || '')));
}

module.exports = {
  // generation / persistence
  generateFlagValue,
  normalizeSubmission,
  timingSafeEqualStr,
  ensureLaneFlags,
  // planting
  plantFlagsForLane,
  rotateLaneFlags,
  detectGuestOs,
  normalizeOs,
  isSafePath,
  // submission
  verifySubmission,
  // reads
  getUserFlagProgress,
  getUserFlagRows,
  buildStudentBoard,
  getLaneFlagState,
  getFlagStateForUsers,
  buildCohortRows,
  // constants (tests + routes)
  FLAG_RE,
  INCORRECT_MESSAGE
};
