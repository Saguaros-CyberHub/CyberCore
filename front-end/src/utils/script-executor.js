/**
 * ============================================================================
 * SCRIPT EXECUTOR
 * Runs vulnerability scripts on deployed VMs via Proxmox Guest Agent
 *
 * Key Proxmox API details:
 * - agent/exec: `command` = full command string with args (space-separated, quoted as needed)
 * - agent/file-write: `content` is stored verbatim on disk — we always chunk + reassemble with FromBase64String on the VM for binary safety
 * - agent/exec-status: `out-data`/`err-data` are returned as plain text, only after the process exits
 * - agent/file-read: used to tail a Tee'd log file for real-time progress during long-running scripts
 * ============================================================================
 */

const { proxmoxAPI } = require('./proxmox');
const { query } = require('./db');

/**
 * Wait for the QEMU guest agent to become responsive
 */
async function waitForGuestAgent(node, vmId, timeoutMs = 180000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      await proxmoxAPI('POST', `/api2/json/nodes/${node}/qemu/${vmId}/agent/ping`);
      return true;
    } catch (e) {
      await new Promise(r => setTimeout(r, 5000));
    }
  }
  return false;
}

/**
 * Write a file to the VM via guest agent.
 *
 * Proxmox's agent/file-write stores `content` verbatim on disk (no base64
 * decode). To handle arbitrary/binary-safe payloads we chunk the bytes,
 * write each chunk as base64 text, and reassemble on the VM with
 * [Convert]::FromBase64String. This matches the proven push-file pattern.
 */
async function guestFileWrite(node, vmId, filePath, content) {
  const cleaned = content
    .replace(/^\uFEFF/, '')
    .replace(/\r?\n/g, '\r\n')
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'");

  await guestWriteLargeText(node, vmId, filePath, cleaned);
}

/**
 * Execute a command via guest agent
 * Proxmox only accepts { command: "full command string" }
 * Works reliably for short commands (~350 chars proven)
 */
async function agentExec(node, vmId, command) {
  console.log(`[AgentExec] ${command.substring(0, 120)}... (${command.length} chars)`);

  const result = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    { command: command }
  );

  const pid = result?.pid;
  if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
  return { pid };
}

/**
 * Poll guest-exec-status until command completes
 */
async function pollExecStatus(node, vmId, pid, timeoutMs = 1800000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const status = await proxmoxAPI('GET',
        `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec-status?pid=${pid}`
      );

      if (status?.exited) {
        // Proxmox returns out-data/err-data as plain text (already decoded from QGA base64)
        return {
          exited: true,
          exitcode: status.exitcode ?? 0,
          stdout: status['out-data'] || '',
          stderr: status['err-data'] || ''
        };
      }
    } catch (e) {
      // May error while process is still running
    }

    await new Promise(r => setTimeout(r, 3000));
  }

  return { exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' };
}

/**
 * Write a potentially-large text payload (e.g., a PowerShell script) to a path
 * on the VM via the guest agent. Single file-write for small payloads, chunked
 * write + PowerShell reassembly for payloads over Proxmox's 61,440-char base64 cap.
 * The only traffic is over virtio-serial; no TCP path from VM to host is required.
 */
async function guestWriteLargeText(node, vmId, remotePath, content) {
  // Normalize line endings to Windows CRLF so the file looks right when opened in PS.
  const normalized = content.replace(/\r?\n/g, '\r\n');
  const bytes = Buffer.from(normalized, 'utf-8');

  // Always chunk using the proven push-file pattern: each chunk file holds
  // base64 TEXT, reassembled on the VM with [Convert]::FromBase64String.
  // This is binary-safe and avoids any ambiguity about whether QGA decodes
  // the `content` field (it does not — contents are written verbatim).
  const CHUNK_SIZE = 45 * 1024; // 45 KB raw -> ~60,000 b64 chars (under 61,440 cap)
  const tempDir = `C:\\Windows\\Temp\\psw_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const totalChunks = Math.ceil(bytes.length / CHUNK_SIZE);

  const mkdir = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': `New-Item -ItemType Directory -Path '${tempDir}' -Force | Out-Null\n[Environment]::Exit(0)\n`
    }
  );
  if (mkdir?.pid) await pollExecStatus(node, vmId, mkdir.pid, 10000);

  for (let i = 0; i < totalChunks; i++) {
    const start = i * CHUNK_SIZE;
    const end = Math.min(start + CHUNK_SIZE, bytes.length);
    const b64 = bytes.subarray(start, end).toString('base64');
    const chunkPath = `${tempDir}\\chunk_${String(i).padStart(4, '0')}`;

    let retries = 3;
    while (retries > 0) {
      try {
        await proxmoxAPI('POST',
          `/api2/json/nodes/${node}/qemu/${vmId}/agent/file-write`, {
            file: chunkPath,
            content: b64
          }
        );
        break;
      } catch (e) {
        retries--;
        if (retries === 0) throw new Error(`Chunk ${i} failed after 3 retries: ${e.message}`);
        await new Promise(r => setTimeout(r, 2000));
      }
    }
    if (i % 10 === 9) await new Promise(r => setTimeout(r, 300));
  }

  const reassemble = `
$ErrorActionPreference = 'Stop'
$chunks = Get-ChildItem '${tempDir}\\chunk_*' | Sort-Object Name
$parent = Split-Path -Parent '${remotePath}'
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$out = [System.IO.File]::Create('${remotePath}')
try {
  foreach ($c in $chunks) {
    $b64 = [System.IO.File]::ReadAllText($c.FullName)
    $b = [Convert]::FromBase64String($b64)
    $out.Write($b, 0, $b.Length)
  }
} finally {
  $out.Close()
}
Remove-Item '${tempDir}' -Recurse -Force -ErrorAction SilentlyContinue
$finalSize = (Get-Item '${remotePath}').Length
Write-Host "[Reassemble] Wrote ${remotePath} ($finalSize bytes from ${totalChunks} chunks)"
[Environment]::Exit(0)

`;
  const rs = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': reassemble
    }
  );
  if (rs?.pid) {
    const rsResult = await pollExecStatus(node, vmId, rs.pid, 120000);
    if (rsResult.stdout) console.log(`[ScriptExec] ${rsResult.stdout.trim()}`);
    if (rsResult.stderr) console.error(`[ScriptExec] Reassemble stderr: ${rsResult.stderr.trim()}`);
    if (rsResult.exitcode !== 0) {
      throw new Error(`Reassembly failed (exit ${rsResult.exitcode}): ${rsResult.stderr || rsResult.stdout}`);
    }
  }
}

/**
 * Execute a PowerShell script on a Windows VM.
 *
 * Always writes the script to disk via guest agent file-write (chunked if large),
 * then runs it with a short exec call whose `input-data` is just the invocation
 * stub. This avoids piping the full script through virtio-serial in one message,
 * which crashes the QEMU guest agent on larger payloads and trips Perl
 * "Wide character" errors on any non-ASCII content.
 */
async function executePowerShellViaFile(node, vmId, scriptContent, scriptArgs = '', onProgress = null) {
  // Strip BOM, map common smart-punctuation to ASCII, then drop any remaining
  // non-ASCII. Proxmox's Perl API has no utf8::encode on this path, so any
  // multi-byte character in the payload can crash the exec call.
  const cleanedLocal = scriptContent
    .replace(/^\uFEFF/, '')
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u2014]/g, '--')
    .replace(/[\u2013]/g, '-')
    .replace(/[\u2192]/g, '->')
    .replace(/[\u2190]/g, '<-')
    .replace(/[^\x00-\x7F]/g, '');

  const strippedCount = scriptContent.length - cleanedLocal.length;
  if (strippedCount > 0) {
    console.log(`[ScriptExec] Stripped ${strippedCount} non-ASCII chars from script (preserves agent stability)`);
  }

  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  const ps1Path = `C:\\Windows\\Temp\\vuln_${ts}_${rand}.ps1`;
  const logPath = `C:\\Windows\\Temp\\vuln_${ts}_${rand}.log`;
  const size = Buffer.byteLength(cleanedLocal, 'utf-8');

  console.log(`[ScriptExec] Writing ${size}-byte script to ${ps1Path} on VM ${vmId} (chunked, matches push-file)`);
  await guestWriteLargeText(node, vmId, ps1Path, cleanedLocal);

  // Mirror push-file's shape exactly: command=powershell.exe with a small
  // input-data payload of FLAT top-level statements (no try/catch block —
  // PS reading stdin as a REPL needs a blank line to flush multi-line blocks,
  // and without one the block sits on the `>>` continuation prompt forever
  // and the script never runs). `*>&1` merges ALL streams including Write-Host
  // (Information stream). Tee duplicates to a log so Node can tail it via
  // agent/file-read for live progress. Remove-Item runs only after
  // $LASTEXITCODE is captured — script is guaranteed to finish first.
  const runStub =
    `$ErrorActionPreference = 'Continue'\n` +
    `$sz = (Get-Item '${ps1Path}' -ErrorAction SilentlyContinue).Length\n` +
    `Write-Host "[ScriptExec] Running ${ps1Path} ($sz bytes)"\n` +
    `& '${ps1Path}' ${scriptArgs} *>&1 | Tee-Object -FilePath '${logPath}' -Encoding utf8\n` +
    `$ec = $LASTEXITCODE\n` +
    `if ($null -eq $ec) { $ec = 0 }\n` +
    `Write-Host "[ScriptExec] Exit code: $ec"\n` +
    `Remove-Item '${ps1Path}' -Force -ErrorAction SilentlyContinue\n` +
    `[Environment]::Exit($ec)\n\n`;

  console.log(`[ScriptExec] Invoking on VM ${vmId} (stub: ${runStub.length} chars, log: ${logPath})`);

  const result = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    {
      command: 'powershell.exe',
      'input-data': runStub
    }
  );

  const pid = result?.pid;
  if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);

  const finalStatus = await pollExecStatusWithLog(node, vmId, pid, logPath, onProgress);

  // Cleanup log on the VM (fire-and-forget). Script.ps1 already removed by the stub.
  proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    {
      command: 'powershell.exe',
      'input-data': `Remove-Item '${logPath}' -Force -ErrorAction SilentlyContinue\n[Environment]::Exit(0)\n`
    }
  ).catch(() => {});

  // exec-status stdout includes the echoed input-data plus the script output.
  // Prefer the clean log (script output only) when available.
  if (finalStatus._logSoFar) {
    finalStatus.stdout = finalStatus._logSoFar;
  }
  delete finalStatus._logSoFar;

  return finalStatus;
}

/**
 * Read a text file from the VM via guest agent. Proxmox returns
 * { content, truncated } where `content` is plain text for text files.
 * Returns '' on any failure (file not yet created, transient error, etc).
 */
async function guestFileRead(node, vmId, filePath) {
  try {
    const resp = await proxmoxAPI('GET',
      `/api2/json/nodes/${node}/qemu/${vmId}/agent/file-read?file=${encodeURIComponent(filePath)}`
    );
    return typeof resp?.content === 'string' ? resp.content : '';
  } catch (e) {
    return '';
  }
}

/**
 * Poll exec-status while tailing a log file for real-time visibility.
 * Emits new log content to console as it appears. Returns the same shape
 * as pollExecStatus.
 */
async function pollExecStatusWithLog(node, vmId, pid, logPath, onProgress = null, timeoutMs = 1800000) {
  const start = Date.now();
  let lastLen = 0;
  let fullLog = '';
  let lastProgressAt = 0;

  const tail = async ({ force = false } = {}) => {
    const content = await guestFileRead(node, vmId, logPath);
    if (content.length > lastLen) {
      const delta = content.slice(lastLen);
      process.stdout.write(`[ScriptExec:${vmId}] ${delta.replace(/\n(?!$)/g, `\n[ScriptExec:${vmId}] `)}`);
      lastLen = content.length;
      fullLog = content;
    }
    if (onProgress && (force || Date.now() - lastProgressAt > 4000) && fullLog) {
      lastProgressAt = Date.now();
      try { await onProgress(fullLog); } catch (e) { /* best-effort */ }
    }
  };

  while (Date.now() - start < timeoutMs) {
    let exited = false;
    let statusSnapshot = null;
    try {
      const status = await proxmoxAPI('GET',
        `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec-status?pid=${pid}`
      );
      if (status?.exited) {
        exited = true;
        statusSnapshot = status;
      }
    } catch (e) { /* may error while running */ }

    await tail();

    if (exited) {
      await tail({ force: true });
      return {
        exited: true,
        exitcode: statusSnapshot.exitcode ?? 0,
        stdout: statusSnapshot['out-data'] || '',
        stderr: statusSnapshot['err-data'] || '',
        _logSoFar: fullLog
      };
    }

    await new Promise(r => setTimeout(r, 2500));
  }

  return { exited: false, exitcode: -1, stdout: '', stderr: 'Timed out', _logSoFar: fullLog };
}

// ============================================================================
// ARGV-STYLE + LINUX EXEC PRIMITIVES
// ----------------------------------------------------------------------------
// These are the "short command, no staged file" primitives. Prefer them over
// executePowerShellViaFile whenever the payload is small AND secret: the staged
// path writes the script to C:\Windows\Temp and tees output to a .log there,
// neither of which is reliably cleaned up (the Remove-Item lives inside the
// stub, so a timeout leaves it behind; the log cleanup is fire-and-forget).
// C:\Windows\Temp is traversable by Users. Anything sensitive — capture flags
// above all — must go through agentExecArgv/agentShellExec instead.
// ============================================================================

/**
 * Run an argv-style command inside a QEMU VM via the guest agent.
 *
 * Proxmox's agent/exec wants `command` either as a single string (executable
 * only, no args) OR multiple `command=...` form params (executable + args).
 * The default proxmoxAPI helper encodes objects as plain k=v, which collapses
 * the argv into one giant "executable path with embedded spaces" -> ENOENT.
 * This wrapper builds the form body by hand with `command` repeated per argv
 * element, then POSTs the raw string body.
 *
 * The `api` parameter exists so callers that already receive an injected
 * proxmoxAPI (goad-deploy, attached-modules) can pass theirs through unchanged.
 *
 * @returns {Promise<{pid:number}>}
 */
async function agentExecArgv(node, vmId, argv, api = proxmoxAPI) {
  const body = argv.map(a => `command=${encodeURIComponent(a)}`).join('&');
  const result = await api(
    'POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
    body
  );
  if (!result?.pid) {
    throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
  }
  return { pid: result.pid };
}

/**
 * POST form-urlencoded pairs to Proxmox by shelling out to curl.
 *
 * Node's https.request consistently gets HTTP 596 (pveproxy 3-second backend
 * timeout) on PVE 9.1.9 for agent/exec, while curl with the same token + body
 * + endpoint returns 200 in ~200ms. No Node-side fix was ever found (URL
 * encoding, content-type, JSON vs form, keep-alive, Content-Length all tried).
 * The ~50ms fork cost is irrelevant next to the work the agent does.
 *
 * Originally lived in the CIAB plugin; promoted here so there is exactly one
 * Linux guest-exec implementation in the codebase.
 */
async function proxmoxFormPOST(path, pairs) {
  const { spawn } = require('child_process');
  const { PROXMOX_URL } = require('./proxmox');
  const tokenId = process.env.PROXMOX_TOKEN_ID;
  const tokenSecret = process.env.PROXMOX_TOKEN_SECRET;
  const url = `${PROXMOX_URL}${path}`;

  const args = [
    '-k', '-s',
    '-w', 'HTTP_STATUS:%{http_code}',
    '-X', 'POST',
    '-H', `Authorization: PVEAPIToken=${tokenId}=${tokenSecret}`
  ];
  for (const [k, v] of pairs) {
    args.push('--data-urlencode', `${k}=${v}`);
  }
  args.push(url);

  return new Promise((resolve, reject) => {
    // Absolute path — alpine's apk installs curl to /usr/bin/curl unconditionally.
    // Bypasses PATH search so a Node process whose env.PATH is missing /usr/bin
    // still finds the binary. Override via CURL_BIN if curl ever moves.
    const curlBin = process.env.CURL_BIN || '/usr/bin/curl';
    const child = spawn(curlBin, args);
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', d => stdout += d.toString());
    child.stderr.on('data', d => stderr += d.toString());
    child.on('error', err => reject(new Error(`${curlBin} spawn failed: ${err.message}`)));
    child.on('close', code => {
      if (code !== 0) {
        return reject(new Error(`curl exited ${code}: ${stderr.slice(0, 300)}`));
      }
      const m = stdout.match(/^([\s\S]*)HTTP_STATUS:(\d+)$/);
      if (!m) return reject(new Error(`unparseable curl output: ${stdout.slice(0, 300)}`));
      const body = m[1];
      const status = parseInt(m[2], 10);
      if (status >= 400) {
        return reject(new Error(`Proxmox POST ${path} failed (${status}): ${body}`));
      }
      try {
        const json = JSON.parse(body);
        resolve(json.data !== undefined ? json.data : json);
      } catch {
        resolve(body);
      }
    });
  });
}

/**
 * Run a shell command inside a Linux QEMU guest — the equivalent of
 * `qm guest exec <vmid> -- /bin/sh -c "..."`.
 *
 * Retries transient 596s: pveproxy -> pvedaemon -> QMP timeouts still happen
 * when back-to-back exec calls race on the agent's serial channel, even after
 * a verified-complete probe.
 *
 * @returns {Promise<{pid:number}>}
 */
async function agentShellExec(node, vmId, shellCmd) {
  console.log(`[AgentShellExec] /bin/sh -c '${shellCmd.substring(0, 100).replace(/\n/g, ' ')}...' (${shellCmd.length} chars)`);

  const pairs = [
    ['command', '/bin/sh'],
    ['command', '-c'],
    ['command', shellCmd]
  ];

  let lastErr;
  for (let attempt = 1; attempt <= 5; attempt++) {
    try {
      const result = await proxmoxFormPOST(
        `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`,
        pairs
      );
      const pid = result?.pid;
      if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);
      return { pid };
    } catch (err) {
      lastErr = err;
      const msg = String(err && err.message || err);
      const transient = /\(596\)/.test(msg)
        || /\b596\b/.test(msg)
        || /ECONNRESET|ETIMEDOUT|socket hang up|EPIPE/.test(msg);
      if (attempt === 1) {
        console.warn(`[AgentShellExec] vm=${vmId} attempt 1 raw error (transient=${transient}): ${msg.substring(0, 200)}`);
      }
      if (!transient || attempt === 5) throw err;
      const delayMs = 2000 * attempt;  // 2s, 4s, 6s, 8s
      console.warn(`[AgentShellExec] vm=${vmId} attempt ${attempt} got transient error, retrying in ${delayMs / 1000}s`);
      await new Promise(r => setTimeout(r, delayMs));
    }
  }
  throw lastErr;
}

/**
 * Wait until the guest's exec channel actually works.
 *
 * waitForGuestAgent only verifies guest-ping; the guest-exec RPC frequently
 * 596's for several seconds afterward, especially on freshly-cloned VMs.
 * Probe with a real exec until success or timeout.
 *
 * @returns {Promise<boolean>} true if exec succeeded at least once
 */
async function waitForAgentExecReady(node, vmId, logTag = '[AgentExec]', timeoutMs = 180000) {
  const startedAt = Date.now();
  let attempt = 0;
  while (Date.now() - startedAt < timeoutMs) {
    attempt++;
    try {
      const r = await agentShellExec(node, vmId, 'true');
      // Actually wait for the probe to COMPLETE agent-side before declaring
      // ready. The API returns a PID instantly but the agent may still be
      // processing the previous command — the next call then 596s.
      if (r && r.pid) {
        const status = await pollExecStatus(node, vmId, r.pid, 30000);
        if (!status || !status.exited) {
          throw new Error(`probe pid=${r.pid} did not complete within 30s`);
        }
      }
      console.log(`${logTag} Agent exec ready on vm=${vmId} (after ${attempt} attempt(s), ${Math.round((Date.now() - startedAt) / 1000)}s)`);
      // Empirically the agent still rejects back-to-back calls with 596 even
      // after a verified-complete probe. 2s eliminates it.
      await new Promise(r => setTimeout(r, 2000));
      return true;
    } catch (err) {
      if (Date.now() - startedAt >= timeoutMs) break;
      const waitMs = Math.min(15000, 5000 + attempt * 2000);
      console.warn(`${logTag} Agent exec not ready on vm=${vmId} (round ${attempt}): ${err.message.substring(0, 120)} — waiting ${waitMs / 1000}s`);
      await new Promise(r => setTimeout(r, waitMs));
    }
  }
  return false;
}

/**
 * Get IP addresses from a VM via guest agent
 */
async function getVMIPs(node, vmId) {
  try {
    const agentData = await proxmoxAPI('GET',
      `/api2/json/nodes/${node}/qemu/${vmId}/agent/network-get-interfaces`
    );
    const ips = [];
    if (agentData?.result) {
      for (const iface of agentData.result) {
        if (iface.name === 'lo' || iface.name === 'Loopback Pseudo-Interface 1') continue;
        for (const addr of (iface['ip-addresses'] || [])) {
          if (addr['ip-address-type'] === 'ipv4' && !addr['ip-address'].startsWith('127.')) {
            ips.push(addr['ip-address']);
          }
        }
      }
    }
    return ips;
  } catch (e) {
    return [];
  }
}

/**
 * Linux counterpart to executePowerShellViaFile.
 *
 * Writes the script to /tmp via base64 chunks over agentShellExec (the same
 * proven path CIAB uses — Node's https.request 596s on PVE 9.1.9 for
 * agent/exec, so proxmoxFormPOST shells out to curl), then runs it with
 * output tee'd to a log we can tail for live progress.
 *
 * Returns the same shape as executePowerShellViaFile.
 */
async function executeShellViaFile(node, vmId, scriptContent, scriptArgs = '', onProgress = null) {
  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  const shPath = `/tmp/vuln_${ts}_${rand}.sh`;
  const logPath = `/tmp/vuln_${ts}_${rand}.log`;

  // Normalize to LF — a CRLF shebang line makes the kernel report ENOENT for
  // "/bin/bash\r", which surfaces as a baffling "no such file or directory".
  const normalized = scriptContent.replace(/\r\n/g, '\n');
  const b64 = Buffer.from(normalized, 'utf-8').toString('base64');
  const CHUNK = 48 * 1024;  // 48KB of base64 per agent call

  console.log(`[ScriptExec] Writing ${normalized.length}-byte shell script to ${shPath} on VM ${vmId}`);

  const runShell = async (cmd, timeoutMs = 120000) => {
    const { pid } = await agentShellExec(node, vmId, cmd);
    const status = await pollExecStatus(node, vmId, pid, timeoutMs);
    if (!status.exited) throw new Error(`guest command timed out: ${cmd.substring(0, 80)}`);
    return status;
  };

  if (b64.length <= CHUNK) {
    await runShell(`printf %s '${b64}' | base64 -d > '${shPath}' && chmod +x '${shPath}'`);
  } else {
    const tmpPath = `${shPath}.b64`;
    await runShell(`: > '${tmpPath}'`);
    for (let i = 0; i < b64.length; i += CHUNK) {
      await runShell(`printf %s '${b64.slice(i, i + CHUNK)}' >> '${tmpPath}'`);
    }
    await runShell(`base64 -d < '${tmpPath}' > '${shPath}' && chmod +x '${shPath}' && rm -f '${tmpPath}'`);
  }

  // Redirect rather than pipe through tee: /bin/sh is dash on Debian, which has
  // no PIPESTATUS, so a pipeline would report tee's exit code (always 0) and
  // silently swallow every script failure. Redirecting keeps $? honest, and
  // pollExecStatusWithLog tails the same file for live progress either way.
  const { pid } = await agentShellExec(node, vmId,
    `sh '${shPath}' ${scriptArgs} > '${logPath}' 2>&1`);

  const finalStatus = await pollExecStatusWithLog(node, vmId, pid, logPath, onProgress);

  // Best-effort cleanup.
  agentShellExec(node, vmId, `rm -f '${shPath}' '${logPath}'`).catch(() => {});

  if (finalStatus._logSoFar) {
    finalStatus.stdout = finalStatus._logSoFar;
  }
  delete finalStatus._logSoFar;

  return finalStatus;
}

/**
 * Sort scripts by dependency order (topological sort)
 */
function sortByDependencies(scripts) {
  const slugMap = {};
  scripts.forEach(s => { slugMap[s.slug] = s; });
  const visited = new Set();
  const sorted = [];

  function visit(slug) {
    if (visited.has(slug)) return;
    visited.add(slug);
    const script = slugMap[slug];
    if (!script) return;
    for (const dep of (script.depends_on || [])) {
      if (slugMap[dep]) visit(dep);
    }
    sorted.push(script);
  }

  scripts.forEach(s => visit(s.slug));
  return sorted;
}

/**
 * Execute all selected scripts on a VM in dependency order
 */
async function executeScriptsOnVM(node, vmId, vmName, scripts, deploymentId) {
  const sorted = sortByDependencies(scripts);

  for (const script of sorted) {
    const scriptKey = `${vmName}:${script.slug}`;
    console.log(`[ScriptExec] Running ${scriptKey} on VM ${vmId} (node ${node})`);

    await updateScriptStatus(deploymentId, vmName, script.slug, 'running');

    try {
      const onProgress = async (logSoFar) => {
        // Stream partial log into DB output field so the UI panel sees live progress.
        await updateScriptStatus(deploymentId, vmName, script.slug, 'running', null, logSoFar);
      };
      // os_target has been stored and filtered on for a long time but was
      // never honored here — every script went to powershell.exe regardless,
      // so a Linux script failed obscurely with "powershell doesn't exist".
      const isLinux = String(script.os_target || 'windows').toLowerCase() === 'linux';
      const result = isLinux
        ? await executeShellViaFile(node, vmId, script.script_content, script.script_args || '', onProgress)
        : await executePowerShellViaFile(node, vmId, script.script_content, script.script_args || '', onProgress);

      if (result.exited) {
        const output = (result.stdout || '') + (result.stderr ? `\nSTDERR:\n${result.stderr}` : '');
        if (result.exitcode === 0) {
          console.log(`[ScriptExec] ${scriptKey} completed (exit: 0)`);
          await updateScriptStatus(deploymentId, vmName, script.slug, 'completed', null, output);
        } else {
          console.error(`[ScriptExec] ${scriptKey} failed (exit: ${result.exitcode})\nOUTPUT: ${output.substring(0, 2000)}`);
          await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', `Exit code: ${result.exitcode}`, output);
        }
      } else {
        console.error(`[ScriptExec] ${scriptKey} timed out`);
        await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', 'Script timed out');
      }
    } catch (e) {
      console.error(`[ScriptExec] ${scriptKey} error: ${e.message}`);
      await updateScriptStatus(deploymentId, vmName, script.slug, 'failed', e.message);
    }
  }
}

/**
 * Update script status in deployment_vuln_selections (clinic_db)
 */
async function updateScriptStatus(deploymentId, vmName, scriptSlug, status, error = null, output = null) {
  if (!deploymentId) return;
  try {
    const result = await query(
      `SELECT selected_scripts FROM deployment_vuln_selections WHERE id = $1`,
      [deploymentId]
    );
    if (result.rows.length === 0) return;

    const scripts = result.rows[0].selected_scripts || [];
    const entry = scripts.find(s => s.vm_name === vmName && s.script_slug === scriptSlug);
    // Sanitize: strip UTF-16 BOM, NULL bytes, and any other characters JSONB rejects.
    // Tee-Object on PS 5.1 defaults to UTF-16LE which leaves \u0000 bytes between chars;
    // Postgres JSONB rejects \u0000 with "unsupported Unicode escape sequence".
    const clean = (s) => typeof s === 'string'
      ? s.replace(/^\uFEFF/, '').replace(/\u0000/g, '').replace(/\uFFFD/g, '')
      : s;
    if (entry) {
      entry.status = status;
      if (error) entry.error = clean(error);
      if (output) entry.output = clean(output);
      entry.updated_at = new Date().toISOString();
    }

    await query(
      `UPDATE deployment_vuln_selections SET selected_scripts = $1, updated_at = NOW() WHERE id = $2`,
      [JSON.stringify(scripts), deploymentId]
    );
  } catch (e) {
    console.error(`[ScriptExec] Failed to update script status: ${e.message}`);
  }
}

module.exports = {
  waitForGuestAgent,
  guestFileWrite,
  guestFileRead,
  agentExec,
  agentExecArgv,
  agentShellExec,
  proxmoxFormPOST,
  waitForAgentExecReady,
  pollExecStatus,
  executePowerShellViaFile,
  executeShellViaFile,
  getVMIPs,
  sortByDependencies,
  executeScriptsOnVM,
  updateScriptStatus
};
