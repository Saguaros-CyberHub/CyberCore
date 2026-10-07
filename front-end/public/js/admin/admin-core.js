// ============================================================================
// HELPERS
// ============================================================================
const TOKEN = () => localStorage.getItem('token');
const headers = () => ({ 'Authorization': `Bearer ${TOKEN()}`, 'Content-Type': 'application/json' });

// A gateway that gives up on the origin answers with an HTML page, not JSON.
// Mapped here so the message names the real failure instead of surfacing a JSON
// parse error from the body of a Cloudflare interstitial. The audit button hit
// 524 routinely and reported `Unexpected token '<'`, which named neither the
// timeout nor the tunnel.
const GATEWAY_MESSAGES = {
  502: 'Bad gateway (502) - the app did not answer the proxy',
  503: 'Service unavailable (503) - the app is starting or overloaded',
  504: 'Gateway timeout (504)',
  520: 'Cloudflare: unknown origin error (520)',
  521: 'Cloudflare: the origin refused the connection (521)',
  522: 'Cloudflare: the connection to the origin timed out (522)',
  523: 'Cloudflare: origin unreachable (523)',
  524: "Gateway timeout (524) - the request ran past the tunnel's 100s limit",
};

async function api(method, path, body = null, opts = {}) {
  const timeoutMs = opts.timeoutMs ?? 30000;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);

  let resp;
  try {
    const fetchOpts = { method, headers: headers(), signal: controller.signal };
    if (body) fetchOpts.body = JSON.stringify(body);
    resp = await fetch(`/api/admin${path}`, fetchOpts);
  } catch (e) {
    // Never reached the server: our own abort, or a dead network. status 0 is
    // deliberate - no caller tests for it, and it keeps err.status a number.
    const err = new Error(e.name === 'AbortError'
      ? `Request timed out after ${Math.round(timeoutMs / 1000)}s`
      : `Network error: ${e.message}`);
    err.status = 0;
    err.data = null;
    throw err;
  } finally {
    clearTimeout(timer);
  }

  // Read the body ONCE, as text. resp.json() used to run BEFORE the resp.ok
  // check, so an HTML error page threw `Unexpected token '<'` and destroyed the
  // status that actually explained the failure.
  const raw = await resp.text();
  let data = null;
  let parsed = false;
  try { data = raw ? JSON.parse(raw) : null; parsed = true; } catch (_) { /* not JSON */ }

  if (resp.ok) {
    if (!parsed) {
      const err = new Error(`Unexpected non-JSON response (${resp.status})`);
      err.status = resp.status;
      err.data = { raw: raw.slice(0, 500) };
      throw err;
    }
    return data;   // an empty 2xx body now yields null instead of throwing
  }

  // Callers have always read e.message and still can. The status and body ride
  // along for the ones that need to tell responses apart - a broadcast whose
  // audience shifted comes back 409 with fresh counts, which is a prompt to
  // re-check rather than an error to show and forget.
  const err = new Error(
    (parsed && data && data.error) ||
    GATEWAY_MESSAGES[resp.status] ||
    `Request failed (${resp.status})`
  );
  err.status = resp.status;
  err.data = parsed ? data : { raw: raw.slice(0, 500) };
  throw err;
}

function switchTab(tabId, btn) {
  document.querySelectorAll('.tab-content').forEach(t => t.classList.remove('active'));
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
  document.getElementById(`tab-${tabId}`).classList.add('active');
  btn.classList.add('active');
}

function closeModal(id) {
  document.getElementById(id).classList.remove('active');
  // Reset permissions modal size if it was expanded
  if (id === 'permissionsModal') {
    const mc = document.querySelector('#permissionsModal .modal-content');
    mc.style.maxWidth = '';
    mc.style.width = '';
  }
}

// ============================================================================
// STATUS CHECK
// ============================================================================

async function checkGuacStatus() {
  try {
    const data = await api('GET', '/guac/status');
    document.getElementById('guacStatusIcon').textContent = '✅';
    document.getElementById('guacStatusText').textContent = 'Connected';
    document.getElementById('guacStatusText').style.color = '#38a169';
    return true;
  } catch (e) {
    document.getElementById('guacStatusIcon').textContent = '❌';
    document.getElementById('guacStatusText').textContent = 'Offline';
    document.getElementById('guacStatusText').style.color = '#e53e3e';
    Toast.error('Guacamole Unreachable', e.message);
    return false;
  }
}

async function checkProxmoxStatus() {
  try {
    await api('GET', '/proxmox/status');
    document.getElementById('proxmoxStatusIcon').textContent = '✅';
    document.getElementById('proxmoxStatusText').textContent = 'Connected';
    document.getElementById('proxmoxStatusText').style.color = '#38a169';
    return true;
  } catch (e) {
    document.getElementById('proxmoxStatusIcon').textContent = '❌';
    document.getElementById('proxmoxStatusText').textContent = 'Offline';
    document.getElementById('proxmoxStatusText').style.color = '#e53e3e';
    Toast.error('Proxmox Unreachable', e.message);
    return false;
  }
}

// ============================================================================
// CLUSTER HEALTH
// ============================================================================

async function loadClusterHealth() {
  const bar = document.getElementById('clusterHealthBar');
  try {
    const health = await api('GET', '/cluster/health');
    bar.style.display = 'block';

    // VM counts
    document.getElementById('clusterVMCount').textContent = health.totalVMs;

    // Status badge
    const statusEl = document.getElementById('clusterHealthStatus');
    if (health.warnings.length > 0) {
      statusEl.textContent = `${health.warnings.length} warning(s)`;
      statusEl.className = 'badge badge-yellow';
    } else {
      statusEl.textContent = 'Healthy';
      statusEl.className = 'badge badge-green';
    }

    // Ceph storage bars (cluster-wide, shown above per-node gauges). When more
    // than one pool exists they sit side by side, left to right, on their own
    // full-width row. Fall back to the single `ceph` entry for older responses.
    const gauges = document.getElementById('clusterNodeGauges');
    const cephPools = (health.cephPools && health.cephPools.length)
      ? health.cephPools
      : (health.ceph ? [health.ceph] : []);
    let cephHtml = '';
    if (cephPools.length) {
      const poolCards = cephPools.map(c => `
        <div style="background: #f7fafc; border-radius: 8px; padding: 0.6rem 0.75rem;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.3rem; gap: 0.5rem;">
            <span style="font-weight: 600; font-size: 0.8rem;">Ceph Storage <span style="font-weight: 400; color: var(--gray-500);">(${escHtml(c.storage)})</span></span>
            <span style="font-size: 0.8rem; font-weight: 600; color: ${gaugeColor(c.pct)};">${c.used_tb} / ${c.total_tb} TiB (${c.pct}%)</span>
          </div>
          <div style="background: #e2e8f0; border-radius: 4px; height: 8px;">
            <div style="background: ${gaugeColor(c.pct)}; height: 100%; border-radius: 4px; width: ${c.pct}%; transition: width 0.5s;"></div>
          </div>
        </div>`).join('');
      cephHtml = `
        <div style="grid-column: 1 / -1; display: grid; grid-template-columns: repeat(${cephPools.length}, 1fr); gap: 0.75rem;">
          ${poolCards}
        </div>`;
    }

    // Per-node gauges (CPU + MEM only, disk is shared via Ceph)
    gauges.innerHTML = cephHtml + health.nodes.map(n => `
      <div style="background: #f7fafc; border-radius: 8px; padding: 0.6rem 0.75rem;">
        <div style="font-weight: 600; font-size: 0.8rem; margin-bottom: 0.4rem;">${escHtml(n.node)} <span style="font-weight: 400; color: var(--gray-500);">(${n.vm_count} VMs)</span></div>
        <div style="display: flex; gap: 0.5rem; font-size: 0.75rem;">
          <div style="flex: 1;">
            <div style="display: flex; justify-content: space-between;"><span>CPU</span><span>${n.cpu_pct}%</span></div>
            <div style="background: #e2e8f0; border-radius: 4px; height: 6px; margin-top: 2px;">
              <div style="background: ${gaugeColor(n.cpu_pct)}; height: 100%; border-radius: 4px; width: ${n.cpu_pct}%;"></div>
            </div>
          </div>
          <div style="flex: 1;">
            <div style="display: flex; justify-content: space-between;"><span>MEM</span><span>${n.mem_pct}%</span></div>
            <div style="background: #e2e8f0; border-radius: 4px; height: 6px; margin-top: 2px;">
              <div style="background: ${gaugeColor(n.mem_pct)}; height: 100%; border-radius: 4px; width: ${n.mem_pct}%;"></div>
            </div>
          </div>
        </div>
      </div>
    `).join('');

    // Warnings
    const warnEl = document.getElementById('clusterWarnings');
    if (health.warnings.length > 0) {
      warnEl.style.display = 'block';
      warnEl.innerHTML = health.warnings.map(w =>
        `<div style="font-size: 0.8rem; color: #b7791f; padding: 0.25rem 0;">⚠ ${escHtml(w)}</div>`
      ).join('');
    } else {
      warnEl.style.display = 'none';
    }
  } catch (e) {
    // Proxmox may be unreachable — show bar with error
    bar.style.display = 'block';
    document.getElementById('clusterHealthStatus').textContent = 'Unreachable';
    document.getElementById('clusterHealthStatus').className = 'badge badge-red';
    document.getElementById('clusterNodeGauges').innerHTML =
      `<p style="color: var(--gray-500); font-size: 0.8rem;">Could not reach Proxmox: ${escHtml(e.message)}</p>`;
  }
}

function gaugeColor(pct) {
  if (pct >= 90) return '#e53e3e';
  if (pct >= 75) return '#d69e2e';
  return '#38a169';
}

// ============================================================================
// UTILITIES
// ============================================================================

function escHtml(str) {
  const div = document.createElement('div');
  div.textContent = str || '';
  return div.innerHTML;
}

function formatTime(totalSecs) {
  if (totalSecs == null || totalSecs < 0) return '--';
  const m = Math.floor(totalSecs / 60);
  const s = totalSecs % 60;
  return m > 0 ? `${m}m ${s}s` : `${s}s`;
}

// ============================================================================
// DEPLOY CONFIRMATION FLOW
// ============================================================================

let pendingDeployAction = null;

function showDeployConfirmation(preview, onConfirm) {
  const body = document.getElementById('deployConfirmBody');

  const s = preview.summary;
  let html = `
    <div style="margin-bottom: 1rem;">
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; font-size: 0.85rem;">
        <div style="padding: 0.5rem 0.75rem; background: #f7fafc; border-radius: 6px;">
          <span style="color: var(--gray-500);">New VMs</span><br>
          <strong>${s.new_vms}</strong> <span style="color: var(--gray-500); font-size: 0.8rem;">(${s.num_lanes} lane${s.num_lanes > 1 ? 's' : ''} x ${s.vms_per_lane} VMs)</span>
        </div>
        <div style="padding: 0.5rem 0.75rem; background: #f7fafc; border-radius: 6px;">
          <span style="color: var(--gray-500);">Total After</span><br>
          <strong>${s.projected_vms}</strong> / ${s.max_vms}
        </div>
        <div style="padding: 0.5rem 0.75rem; background: #f7fafc; border-radius: 6px;">
          <span style="color: var(--gray-500);">Currently Deploying</span><br>
          <strong>${s.currently_deploying}</strong> / ${s.max_concurrent}
        </div>
        <div style="padding: 0.5rem 0.75rem; background: #f7fafc; border-radius: 6px;">
          <span style="color: var(--gray-500);">Existing VMs</span><br>
          <strong>${s.current_vms}</strong>
        </div>
      </div></div>`;

  if (preview.errors.length > 0) {
    html += `<div style="background: #fed7d7; color: #9b2c2c; padding: 0.75rem; border-radius: 8px; margin-bottom: 0.75rem;">
      <strong>Cannot proceed:</strong>
      ${preview.errors.map(e => `<div style="margin-top: 0.25rem;">• ${escHtml(e)}</div>`).join('')}
    </div>`;
  }

  if (preview.warnings.length > 0) {
    html += `<div style="background: #fffbeb; color: #b7791f; padding: 0.75rem; border-radius: 8px; margin-bottom: 0.75rem;">
      <strong>Warnings:</strong>
      ${preview.warnings.map(w => `<div style="margin-top: 0.25rem;">⚠ ${escHtml(w)}</div>`).join('')}
    </div>`;
  }

  body.innerHTML = html;

  const confirmBtn = document.getElementById('deployConfirmBtn');
  if (preview.errors.length > 0) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Blocked';
    confirmBtn.style.opacity = '0.5';
  } else {
    confirmBtn.disabled = false;
    confirmBtn.textContent = 'Confirm Deploy';
    confirmBtn.style.opacity = '1';
  }

  pendingDeployAction = onConfirm;
  confirmBtn.onclick = () => {
    closeModal('deployConfirmModal');
    if (pendingDeployAction) pendingDeployAction();
    pendingDeployAction = null;
  };

  document.getElementById('deployConfirmModal').classList.add('active');
}
