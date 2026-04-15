/**
 * ============================================================================
 * SCRIPT EXECUTOR
 * Runs vulnerability scripts on deployed VMs via Proxmox Guest Agent
 *
 * Key Proxmox API details:
 * - agent/exec: `command` = executable path only, `arg0`..`argN` = separate args
 * - agent/file-write: `content` = base64 string; do NOT pass `encode: 1` — that makes Proxmox double-encode and the literal base64 ends up on disk
 * - agent/exec-status: `out-data`/`err-data` are returned as plain text (Proxmox decodes)
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
$chunks = Get-ChildItem '${tempDir}\\chunk_*' | Sort-Object Name
$parent = Split-Path -Parent '${remotePath}'
if ($parent -and -not (Test-Path $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
$out = [System.IO.File]::Create('${remotePath}')
foreach ($c in $chunks) {
    $b64 = [System.IO.File]::ReadAllText($c.FullName)
    $b = [Convert]::FromBase64String($b64)
    $out.Write($b, 0, $b.Length)
}
$out.Close()
Remove-Item '${tempDir}' -Recurse -Force -ErrorAction SilentlyContinue
[Environment]::Exit(0)
`;
  const rs = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': reassemble
    }
  );
  if (rs?.pid) await pollExecStatus(node, vmId, rs.pid, 120000);
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
async function executePowerShellViaFile(node, vmId, scriptContent, scriptArgs = '') {
  // Strip BOM, map common smart-punctuation to ASCII, then drop any remaining
  // non-ASCII. Proxmox's Perl API has no utf8::encode on this path, so any
  // multi-byte character in the payload can crash the exec call.
  const cleaned = scriptContent
    .replace(/^\uFEFF/, '')
    .replace(/[\u201C\u201D]/g, '"')
    .replace(/[\u2018\u2019]/g, "'")
    .replace(/[\u2014]/g, '--')
    .replace(/[\u2013]/g, '-')
    .replace(/[\u2192]/g, '->')
    .replace(/[\u2190]/g, '<-')
    .replace(/[^\x00-\x7F]/g, '');

  const strippedCount = scriptContent.length - cleaned.length;
  if (strippedCount > 0) {
    console.log(`[ScriptExec] Stripped ${strippedCount} non-ASCII chars from script (preserves agent stability)`);
  }

  const ts = Date.now();
  const rand = Math.random().toString(36).slice(2, 8);
  const ps1Path = `C:\\Windows\\Temp\\vuln_${ts}_${rand}.ps1`;
  const logPath = `C:\\Windows\\Temp\\vuln_${ts}_${rand}.log`;
  const size = Buffer.byteLength(cleaned, 'utf-8');

  console.log(`[ScriptExec] Writing ${size}-byte script to ${ps1Path} on VM ${vmId}`);
  await guestWriteLargeText(node, vmId, ps1Path, cleaned);

  // Stub: Tee-Object gives us a line-flushed log that Node can tail in real
  // time via agent/file-read while exec-status is still running. The script
  // is guaranteed to finish (synchronous &) before Remove-Item; the log is
  // left on disk so the final tail-read can drain it, then Node removes it.
  const runStub = [
    `$ErrorActionPreference = 'Continue'`,
    `$ec = 0`,
    `try {`,
    `  & '${ps1Path}' ${scriptArgs} 2>&1 | Tee-Object -FilePath '${logPath}'`,
    `  $ec = $LASTEXITCODE`,
    `} catch {`,
    `  $_ | Out-File -FilePath '${logPath}' -Append -Encoding ascii`,
    `  $ec = 1`,
    `}`,
    `Remove-Item '${ps1Path}' -Force -ErrorAction SilentlyContinue`,
    `[Environment]::Exit($ec)`
  ].join('\n') + '\n';

  console.log(`[ScriptExec] Invoking script on VM ${vmId} (stub: ${runStub.length} chars, log: ${logPath})`);

  const result = await proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': runStub
    }
  );

  const pid = result?.pid;
  if (!pid) throw new Error(`agent/exec did not return a PID: ${JSON.stringify(result)}`);

  const finalStatus = await pollExecStatusWithLog(node, vmId, pid, logPath);

  // Clean up log on the VM (fire-and-forget — don't block caller).
  proxmoxAPI('POST',
    `/api2/json/nodes/${node}/qemu/${vmId}/agent/exec`, {
      command: 'powershell.exe',
      'input-data': `Remove-Item '${logPath}' -Force -ErrorAction SilentlyContinue\n[Environment]::Exit(0)\n`
    }
  ).catch(() => {});

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
async function pollExecStatusWithLog(node, vmId, pid, logPath, timeoutMs = 1800000) {
  const start = Date.now();
  let lastLen = 0;
  const tail = async () => {
    const content = await guestFileRead(node, vmId, logPath);
    if (content.length > lastLen) {
      const delta = content.slice(lastLen);
      process.stdout.write(`[ScriptExec:${vmId}] ${delta.replace(/\n(?!$)/g, `\n[ScriptExec:${vmId}] `)}`);
      lastLen = content.length;
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
      // One more drain to capture anything written after the last tail.
      await tail();
      return {
        exited: true,
        exitcode: statusSnapshot.exitcode ?? 0,
        stdout: statusSnapshot['out-data'] || '',
        stderr: statusSnapshot['err-data'] || ''
      };
    }

    await new Promise(r => setTimeout(r, 2500));
  }

  return { exited: false, exitcode: -1, stdout: '', stderr: 'Timed out' };
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
      const result = await executePowerShellViaFile(node, vmId, script.script_content, script.script_args || '');

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
    if (entry) {
      entry.status = status;
      if (error) entry.error = error;
      if (output) entry.output = output;
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
  agentExec,
  pollExecStatus,
  executePowerShellViaFile,
  getVMIPs,
  sortByDependencies,
  executeScriptsOnVM,
  updateScriptStatus
};
