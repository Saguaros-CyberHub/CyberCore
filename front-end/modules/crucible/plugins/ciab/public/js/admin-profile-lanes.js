/**
 * admin-profile-lanes.js — UI for the admin profile-to-N-lanes feature.
 *
 * Three tabs:
 *   1. Generate + Deploy — fires /api/profiles/generate-and-deploy
 *   2. Deploy From Existing — pick/upload a profile, tick assets, deploy
 *   3. Active Groups — list + per-group status with retry/teardown
 *
 * Talks to:
 *   POST /api/profile-deploy/preview
 *   POST /api/profile-deploy/deploy
 *   GET  /api/profile-deploy/groups
 *   GET  /api/profile-deploy/groups/:id
 *   GET  /api/profile-deploy/groups/:id/progress
 *   POST /api/profile-deploy/groups/:id/retry/:laneId
 *   DELETE /api/profile-deploy/groups/:id
 *   POST /api/profiles/upload
 *   POST /api/profiles/generate-and-deploy
 *   GET  /api/profiles?user_id=*
 */

let CURRENT_PROFILE = null;   // last loaded profile (from picker or upload)
let CURRENT_ASSETS  = [];     // assets from that profile
let GROUPS_POLL_TIMER = null;

// ─── Tabs ───────────────────────────────────────────────────────────────────

function switchTab(name) {
  document.querySelectorAll('.tab').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${name}`));
  if (name === 'existing') refreshProfiles();
  if (name === 'groups')   refreshGroups();
}

// ─── HTTP helpers ───────────────────────────────────────────────────────────

async function apiCall(path, opts = {}) {
  if (typeof API !== 'undefined' && API.request) {
    return API.request(path, opts);
  }
  // Fallback raw fetch
  const token = localStorage.getItem('token');
  const resp = await fetch(`/api${path}`, {
    method: opts.method || 'GET',
    headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
    body: opts.body ? (typeof opts.body === 'string' ? opts.body : JSON.stringify(opts.body)) : undefined
  });
  const ct = resp.headers.get('content-type') || '';
  const data = ct.includes('application/json') ? await resp.json() : await resp.text();
  if (!resp.ok) throw Object.assign(new Error(data.error || resp.statusText), { status: resp.status, body: data });
  return data;
}

function renderBanner(elId, kind, html) {
  document.getElementById(elId).innerHTML = `<div class="status-banner ${kind}">${html}</div>`;
}

function clearBanner(elId) {
  const el = document.getElementById(elId);
  if (el) el.innerHTML = '';
}

// ─── TAB 1: Generate + Deploy ──────────────────────────────────────────────

async function generateAndDeploy() {
  const vulnAppEnabled = document.getElementById('gen-vuln-app').checked;
  const payload = {
    client_type: document.getElementById('gen-client-type').value,
    difficulty:  document.getElementById('gen-difficulty').value,
    industry:    document.getElementById('gen-industry').value || undefined,
    employees:   parseInt(document.getElementById('gen-employees').value, 10) || undefined,
    num_lanes:   parseInt(document.getElementById('gen-num-lanes').value, 10),
    group_name:  document.getElementById('gen-group-name').value || undefined,
    subnet_scheme: document.getElementById('gen-subnet-scheme').value,
    attack_boxes: document.getElementById('gen-attack-boxes').checked,
    vuln_app: { enabled: vulnAppEnabled, delivery_mode: 'docker' }
  };

  renderBanner('gen-result', 'info', '⏳ Generating profile via N8N… this can take 1–2 minutes. Don\'t close this tab.');

  try {
    const result = await apiCall('/profiles/generate-and-deploy', { method: 'POST', body: payload });
    const profileName = result.profile?.companyName || result.profile?.company_name || result.profile?.id;
    renderBanner('gen-result', 'success',
      `✅ Profile <strong>${profileName}</strong> generated. Lane group <code>${result.deploy.group_id}</code> deploying.<br>
       Switching to Active Groups tab to watch progress…`);
    setTimeout(() => switchTab('groups'), 1200);
  } catch (err) {
    renderBanner('gen-result', 'error', `❌ ${err.message}`);
  }
}

// ─── TAB 2: Pick / upload profile ──────────────────────────────────────────

async function refreshProfiles() {
  const picker = document.getElementById('profile-picker');
  picker.innerHTML = '<option>Loading…</option>';
  try {
    // user_id=* returns every profile (admin only). Falls back to user's own if not supported.
    const data = await apiCall('/profiles?limit=100&user_id=*').catch(() => apiCall('/profiles?limit=100'));
    const profiles = data.profiles || data || [];
    if (profiles.length === 0) {
      picker.innerHTML = '<option value="">No profiles found</option>';
      return;
    }
    picker.innerHTML = '<option value="">— select —</option>' + profiles.map(p => {
      const id = p.id;
      const name = p.companyName || p.company_name || id.slice(0, 8);
      const date = (p.createdAt || p.created_at || '').slice(0, 10);
      return `<option value="${id}">${name} (${date})</option>`;
    }).join('');
  } catch (err) {
    picker.innerHTML = `<option value="">Error: ${err.message}</option>`;
  }
}

document.addEventListener('change', async (e) => {
  if (e.target.id === 'profile-upload' && e.target.files[0]) {
    const file = e.target.files[0];
    renderBanner('profile-load-result', 'info', `📤 Uploading ${file.name}…`);
    try {
      const text = await file.text();
      const json = JSON.parse(text);
      const data = await apiCall('/profiles/upload', { method: 'POST', body: json });
      renderBanner('profile-load-result', 'success',
        `✅ Uploaded as profile <code>${data.profile.id}</code> (${data.asset_count} assets). Loading…`);
      await loadProfileById(data.profile.id);
    } catch (err) {
      renderBanner('profile-load-result', 'error', `❌ Upload failed: ${err.message}`);
    }
  }
});

async function loadSelectedProfile() {
  const id = document.getElementById('profile-picker').value;
  if (!id) {
    renderBanner('profile-load-result', 'error', 'Pick a profile first.');
    return;
  }
  await loadProfileById(id);
}

async function loadProfileById(id) {
  clearBanner('profile-load-result');
  try {
    const data = await apiCall(`/profiles/${id}`);
    const profile = data.profile || data;
    CURRENT_PROFILE = profile;

    // Profile JSON may not be embedded in /api/profiles/:id response — try its raw file
    // (the synthesizer reads from disk server-side, here we only need the asset list for display)
    let assets = profile?.json?.student_view?.raw?.threats?.network?.assets
              || profile?.studentView?.raw?.threats?.network?.assets
              || profile?.assets;
    if (!Array.isArray(assets)) {
      // Fetch directly from the static file path
      const jsonPath = profile.jsonFilePath || profile.json_file_path;
      if (jsonPath) {
        try {
          const fileResp = await fetch('/' + jsonPath.replace(/^\/+/, ''));
          if (fileResp.ok) {
            const raw = await fileResp.json();
            assets = raw?.student_view?.raw?.threats?.network?.assets || raw?.assets || [];
          }
        } catch (_) { /* ignore */ }
      }
    }
    CURRENT_ASSETS = Array.isArray(assets) ? assets : [];

    renderAssetTable();
    document.getElementById('asset-selection-card').style.display = '';
    document.getElementById('dep-group-name').placeholder =
      `${(profile.companyName || profile.company_name || 'profile').replace(/\s/g,'-').toLowerCase()}-${new Date().toISOString().slice(0,10)}`;
  } catch (err) {
    renderBanner('profile-load-result', 'error', `❌ ${err.message}`);
  }
}

function renderAssetTable() {
  const tbody = document.getElementById('asset-table-body');
  if (CURRENT_ASSETS.length === 0) {
    tbody.innerHTML = '<tr><td colspan="5" class="empty">No assets in this profile.</td></tr>';
    return;
  }
  tbody.innerHTML = CURRENT_ASSETS.map((a, i) => {
    const isServer = String(a.role || '').toLowerCase() === 'server';
    const services = Array.isArray(a.services) ? a.services.join(', ') : '';
    return `<tr>
      <td><input type="checkbox" data-asset-idx="${i}" ${isServer ? 'checked' : ''} /></td>
      <td><code>${escapeHtml(a.hostname || '')}</code></td>
      <td><span class="role-${isServer ? 'server' : 'workstation'}">${escapeHtml(a.role || '')}</span></td>
      <td>${escapeHtml(a.os || '')}</td>
      <td class="muted">${escapeHtml(services)}</td>
    </tr>`;
  }).join('');
}

function gatherAssetSelection() {
  return CURRENT_ASSETS.map((a, i) => {
    const cb = document.querySelector(`input[data-asset-idx="${i}"]`);
    return { hostname: a.hostname, role: a.role, os: a.os, included: cb ? cb.checked : false };
  });
}

async function runPreview() {
  if (!CURRENT_PROFILE) return;
  clearBanner('preview-result');
  try {
    const data = await apiCall('/profile-deploy/preview', {
      method: 'POST',
      body: {
        profile_id: CURRENT_PROFILE.id,
        num_lanes: parseInt(document.getElementById('dep-num-lanes').value, 10),
        attack_boxes: document.getElementById('dep-attack-boxes').checked
      }
    });
    const s = data.summary || {};
    const banner = data.canProceed ? 'success' : 'error';
    renderBanner('preview-result', banner,
      `Preview: <strong>${s.new_vms}</strong> new VMs (${s.vms_per_lane}/lane × ${s.num_lanes}).
       Currently <strong>${s.current_vms}</strong> running. Servers in profile: ${data.profile_asset_summary?.servers}.
       ${data.errors.length ? '<br>⚠ ' + data.errors.join('; ') : ''}`);
  } catch (err) {
    renderBanner('preview-result', 'error', `❌ ${err.message}`);
  }
}

async function runDeploy() {
  if (!CURRENT_PROFILE) return;
  const payload = {
    profile_id: CURRENT_PROFILE.id,
    num_lanes: parseInt(document.getElementById('dep-num-lanes').value, 10),
    group_name: document.getElementById('dep-group-name').value || undefined,
    attack_boxes: document.getElementById('dep-attack-boxes').checked,
    subnet_scheme: document.getElementById('dep-subnet-scheme').value,
    asset_selection: gatherAssetSelection(),
    vuln_app: {
      enabled: document.getElementById('dep-vuln-app').checked,
      delivery_mode: document.getElementById('dep-vuln-app-dedicated').checked ? 'standalone_vm' : 'docker'
    }
  };

  renderBanner('deploy-result', 'info', '⏳ Starting deployment…');
  try {
    const data = await apiCall('/profile-deploy/deploy', { method: 'POST', body: payload });
    renderBanner('deploy-result', 'success',
      `✅ Deploy started. Group <code>${data.group_id}</code> — ${data.lanes.length} lanes.
       ${data.service_gaps.length ? `<br>⚠ ${data.service_gaps.length} service gaps` : ''}
       ${data.template_misses.length ? `<br>⚠ ${data.template_misses.length} template misses` : ''}<br>
       Switching to Active Groups…`);
    setTimeout(() => switchTab('groups'), 1500);
  } catch (err) {
    const extra = [];
    if (err.body?.template_misses?.length) extra.push(`Template misses: ${err.body.template_misses.map(m => m.hostname).join(', ')}`);
    if (err.body?.service_gaps?.length)    extra.push(`Service gaps: ${err.body.service_gaps.length}`);
    renderBanner('deploy-result', 'error', `❌ ${err.message}${extra.length ? '<br>' + extra.join('<br>') : ''}`);
  }
}

// ─── TAB 3: Active groups ──────────────────────────────────────────────────

async function refreshGroups() {
  document.getElementById('groups-status').textContent = 'Loading…';
  try {
    const data = await apiCall('/profile-deploy/groups');
    renderGroups(data.groups || []);
    document.getElementById('groups-status').textContent = `${(data.groups || []).length} groups`;
    schedulePoll();
  } catch (err) {
    document.getElementById('groups-list').innerHTML = `<div class="empty">Error: ${err.message}</div>`;
  }
}

function schedulePoll() {
  if (GROUPS_POLL_TIMER) clearInterval(GROUPS_POLL_TIMER);
  GROUPS_POLL_TIMER = setInterval(async () => {
    // Only poll while we're on the Groups tab
    if (!document.getElementById('tab-groups').classList.contains('active')) return;
    try {
      const data = await apiCall('/profile-deploy/groups');
      renderGroups(data.groups || []);
    } catch (_) {}
  }, 6000);
}

function renderGroups(groups) {
  const list = document.getElementById('groups-list');
  if (groups.length === 0) {
    list.innerHTML = '<div class="empty">No groups yet. Deploy from Tab 1 or Tab 2.</div>';
    return;
  }
  list.innerHTML = groups.map(g => `
    <div class="card" id="group-${g.id}">
      <div style="display:flex; justify-content:space-between; align-items:center;">
        <div>
          <h3 style="margin:0;">${escapeHtml(g.group_name)}
            <span class="pill pill-${g.status}">${g.status}</span></h3>
          <div class="muted">${escapeHtml(g.profile_company || '?')} — ${g.num_lanes} lanes —
            ${(g.created_at || '').slice(0, 19).replace('T',' ')} —
            ${g.gap_count} service gaps, ${g.miss_count} template misses</div>
        </div>
        <div style="display:flex; gap:0.5rem;">
          <button class="btn btn-secondary btn-small" onclick="loadGroupDetail('${g.id}')">Details</button>
          <button class="btn btn-danger btn-small" onclick="teardownGroup('${g.id}', '${escapeHtml(g.group_name)}')">Tear down</button>
        </div>
      </div>
      <div id="group-${g.id}-detail"></div>
    </div>
  `).join('');
}

async function loadGroupDetail(groupId) {
  const target = document.getElementById(`group-${groupId}-detail`);
  target.innerHTML = '<div class="muted">Loading detail…</div>';
  try {
    const [detail, progress] = await Promise.all([
      apiCall(`/profile-deploy/groups/${groupId}`),
      apiCall(`/profile-deploy/groups/${groupId}/progress`).catch(() => null)
    ]);
    const group = detail.group;
    const jobs = detail.jobs || [];
    const ipWriteback = group.lane_ip_writeback || {};

    const phase = progress
      ? `<div class="muted">Phase: <strong>${progress.phase || 'n/a'}</strong> ${progress.phase_detail || ''}
         — ${progress.completed || 0}/${progress.total} (✅ ${progress.succeeded || 0} ❌ ${progress.failed || 0})
         ${progress.eta_s ? ' — ETA ' + Math.ceil(progress.eta_s / 60) + 'min' : ''}</div>`
      : '';

    const gapsHtml = (group.service_gaps && group.service_gaps.length > 0)
      ? `<div class="gap-card"><strong>${group.service_gaps.length} service gaps</strong> (declared services with no installer):
         ${group.service_gaps.slice(0, 10).map(g =>
           `<code>${escapeHtml(g.vm)}:${g.port || '?'}/${escapeHtml(g.service)}</code>`).join(' ')}</div>`
      : '';
    const missHtml = (group.template_misses && group.template_misses.length > 0)
      ? `<div class="miss-card"><strong>${group.template_misses.length} template misses</strong>:
         ${group.template_misses.slice(0, 10).map(m =>
           `<code>${escapeHtml(m.hostname)} (${escapeHtml(m.os || 'n/a')})</code>`).join(' ')}</div>`
      : '';

    const lanesHtml = `
      <div class="lane-row header">
        <div>#</div><div>VXLAN</div><div>Status</div><div>VM IPs</div><div></div>
      </div>
      ${jobs.map(j => {
        const ipsForLane = Object.entries(ipWriteback)
          .filter(([_, m]) => m && m[j.lane_id])
          .map(([host, m]) => `${host}=${m[j.lane_id]}`)
          .join(' ');
        const isError = j.status === 'error';
        return `<div class="lane-row">
          <div>${j.lane_index}</div>
          <div><code>${j.vxlan_id}</code></div>
          <div><span class="pill pill-${j.status}">${j.status}</span>
            ${j.error_msg ? `<div class="muted" title="${escapeHtml(j.error_msg)}">⚠ ${escapeHtml(j.error_msg).slice(0, 60)}</div>` : ''}</div>
          <div class="ip-list">${escapeHtml(ipsForLane || '—')}</div>
          <div>${isError
            ? `<button class="btn btn-small btn-secondary" onclick="retryLane('${groupId}','${j.lane_id}')">Retry</button>`
            : ''}</div>
        </div>`;
      }).join('')}
    `;

    target.innerHTML = `${phase}${gapsHtml}${missHtml}<div style="margin-top:0.5rem;">${lanesHtml}</div>`;
  } catch (err) {
    target.innerHTML = `<div class="status-banner error">${err.message}</div>`;
  }
}

async function retryLane(groupId, laneId) {
  try {
    await apiCall(`/profile-deploy/groups/${groupId}/retry/${laneId}`, { method: 'POST' });
    setTimeout(() => loadGroupDetail(groupId), 500);
  } catch (err) {
    alert(`Retry failed: ${err.message}`);
  }
}

async function teardownGroup(groupId, name) {
  if (!confirm(`Tear down group "${name}" and destroy all its lanes?`)) return;
  try {
    await apiCall(`/profile-deploy/groups/${groupId}`, { method: 'DELETE' });
    refreshGroups();
  } catch (err) {
    alert(`Teardown failed: ${err.message}`);
  }
}

// ─── utils ─────────────────────────────────────────────────────────────────
function escapeHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ─── boot ──────────────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  // Default tab is "generate" — no auto-fetch needed.
});
