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
  // Top-level tabs only (skip the nested subtabs which use data-subtab)
  document.querySelectorAll('.tab[data-tab]').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${name}`));
  if (name === 'existing') refreshProfiles();
  if (name === 'groups')   refreshGroups();
}

// Subtabs inside Tab 1 (Basic / Organization / Technical / Advanced / Lane Deployment)
function switchSubTab(name) {
  document.querySelectorAll('.tab[data-subtab]').forEach(t => t.classList.toggle('active', t.dataset.subtab === name));
  document.querySelectorAll('.subtab-content').forEach(c => {
    c.style.display = (c.id === `subtab-${name}`) ? '' : 'none';
  });
}

// ─── Client-type → industry list (mirrors generator.html CLIENT_TYPES) ─────
const CLIENT_TYPE_INDUSTRIES = {
  SMB: [
    'Regional Logistics & Warehousing', 'Mid-size Dental Group', 'Light Manufacturing',
    'Professional Services Firm', 'Retail Chain (Regional)'
  ],
  NonProfit: ['Community Health Center', 'Social Services Agency'],
  Utility_IT_OT: ['Municipal Water/Wastewater', 'Rural Electric Cooperative'],
  K12: ['Rural School District', 'Suburban School District']
};
const CLIENT_TYPE_DEFAULTS = {
  SMB:           { emp:[25,200],  stak:[5,8],  end:[20,90],  fw:[5,15],  weak:[3,8]  },
  NonProfit:     { emp:[10,100],  stak:[4,7],  end:[15,60],  fw:[3,10],  weak:[3,6]  },
  Utility_IT_OT: { emp:[50,500],  stak:[6,12], end:[50,300], fw:[15,50], weak:[5,12] },
  K12:           { emp:[100,2000],stak:[5,10], end:[200,5000],fw:[10,30],weak:[4,10] }
};

function onClientTypeChange() {
  const type = document.getElementById('gen-client-type').value;
  const industries = CLIENT_TYPE_INDUSTRIES[type] || [];
  const dropdown = document.getElementById('gen-industry');
  dropdown.innerHTML = '<option value="">🎲 Random (recommended)</option>' +
    industries.map(i => `<option value="${i}">${i}</option>`).join('');

  // Update default ranges to match the client type's typical scale
  const d = CLIENT_TYPE_DEFAULTS[type];
  if (d) {
    const setIf = (id, v) => { const el = document.getElementById(id); if (el) el.value = v; };
    setIf('gen-emp-min',  d.emp[0]);   setIf('gen-emp-max',  d.emp[1]);
    setIf('gen-stak-min', d.stak[0]);  setIf('gen-stak-max', d.stak[1]);
    setIf('gen-end-min',  d.end[0]);   setIf('gen-end-max',  d.end[1]);
    setIf('gen-fw-min',   d.fw[0]);    setIf('gen-fw-max',   d.fw[1]);
    setIf('gen-weak-min', d.weak[0]);  setIf('gen-weak-max', d.weak[1]);
  }
}

function onDifficultyChange() {
  // Weakness range follows difficulty (admin can still override after)
  const diff = document.getElementById('gen-difficulty').value;
  const weakDefaults = { beginner:[3,5], intermediate:[3,8], advanced:[6,12] };
  const d = weakDefaults[diff];
  if (d) {
    document.getElementById('gen-weak-min').value = d[0];
    document.getElementById('gen-weak-max').value = d[1];
  }
}

// Keep max_students >= num_lanes so the form doesn't submit an invalid combo.
// If admin bumps num_lanes above current max_students, bump max_students too.
function syncMaxStudents() {
  const numLanes = parseInt(document.getElementById('gen-num-lanes').value, 10) || 0;
  const maxStud = parseInt(document.getElementById('gen-max-students').value, 10) || 0;
  if (numLanes > maxStud) document.getElementById('gen-max-students').value = numLanes;
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
  // ─── Helpers to safely read form fields ──────────────────────────────────
  const $ = id => document.getElementById(id);
  const valStr = id => { const v = $(id)?.value?.trim(); return v ? v : undefined; };
  const valInt = id => { const v = parseInt($(id)?.value, 10); return Number.isFinite(v) ? v : undefined; };
  const valFloat = id => { const v = parseFloat($(id)?.value); return Number.isFinite(v) ? v : undefined; };
  const range = (minId, maxId) => {
    const min = valInt(minId), max = valInt(maxId);
    if (min == null && max == null) return undefined;
    return { min: min ?? max, max: max ?? min };
  };

  const empRange = range('gen-emp-min', 'gen-emp-max');
  const payload = {
    // Basic
    client_type: valStr('gen-client-type'),
    difficulty:  valStr('gen-difficulty'),
    industry:    valStr('gen-industry'),

    // Organization
    company_name: valStr('gen-company-name'),
    domain:       valStr('gen-domain'),
    hq_city:      valStr('gen-hq-city'),
    maturity:     valStr('gen-maturity'),
    employees:    empRange,
    stakeholder_count: range('gen-stak-min', 'gen-stak-max'),
    framework:    valStr('gen-framework'),

    // Technical
    delivery:        valStr('gen-delivery'),
    endpoint_range:  range('gen-end-min', 'gen-end-max'),
    firewall_rules_range: range('gen-fw-min', 'gen-fw-max'),
    weakness_range:  range('gen-weak-min', 'gen-weak-max'),

    // Advanced
    cooperation:  valStr('gen-cooperation'),
    scaffolding:  valStr('gen-scaffolding'),
    est_hours:    valInt('gen-est-hours'),
    llmModel:     valStr('gen-llm-model'),
    temperature:  valFloat('gen-temperature'),
    custom_seed:  valStr('gen-custom-seed'),

    // Lane deployment
    num_lanes:    valInt('gen-num-lanes'),
    max_students: valInt('gen-max-students'),
    group_name:   valStr('gen-group-name'),
    subnet_scheme: valStr('gen-subnet-scheme') || 'v2',
    attack_boxes: $('gen-attack-boxes').checked,
    vuln_app: {
      enabled: $('gen-vuln-app').checked,
      delivery_mode: $('gen-vuln-app-dedicated').checked ? 'standalone_vm' : 'docker'
    }
  };

  if (!payload.num_lanes || payload.num_lanes < 1) {
    renderBanner('gen-result', 'error', 'Number of lanes must be at least 1.');
    return;
  }

  renderBanner('gen-result', 'info', '⏳ Generating profile via Claude (4 parallel calls)… this typically takes 30–90 seconds. Don\'t close this tab.');

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

    // Show this profile's VXLAN reservation status (if any)
    await loadReservationStatus(id);
  } catch (err) {
    renderBanner('profile-load-result', 'error', `❌ ${err.message}`);
  }
}

async function loadReservationStatus(profileId) {
  const el = document.getElementById('dep-reservation-status');
  if (!el) return;
  try {
    const r = await apiCall(`/profile-deploy/profiles/${profileId}/reservation`);
    if (r.reserved) {
      const maxStudInput = document.getElementById('dep-max-students');
      maxStudInput.value = r.max_students;
      // Empty reservation (no lanes deployed) is resizable — the server will
      // delete-and-recreate the challenge with the new max on next deploy.
      if (r.slots_used === 0) {
        maxStudInput.disabled = false;
        el.innerHTML = `<div class="status-banner info">
          🔓 Profile reservation: <strong>0/${r.max_students}</strong> slots used —
          VXLAN range <code>${r.vxlan_range_start}-${r.vxlan_range_end}</code>,
          challenge <code>${(r.challenge_key||'').slice(0,40)}</code>.
          No lanes deployed yet — <strong>max students can still be changed</strong>; the reservation will be resized on next deploy.
        </div>`;
      } else {
        maxStudInput.disabled = true;
        el.innerHTML = `<div class="status-banner info">
          🔒 Profile reservation: <strong>${r.slots_used}/${r.max_students}</strong> slots used —
          VXLAN range <code>${r.vxlan_range_start}-${r.vxlan_range_end}</code>,
          challenge <code>${(r.challenge_key||'').slice(0,40)}</code>.
          Max students locked (lanes deployed). <strong>${r.slots_free}</strong> free slot${r.slots_free===1?'':'s'} for new lanes.
        </div>`;
      }
    } else {
      const maxStudInput = document.getElementById('dep-max-students');
      maxStudInput.disabled = false;
      const win = r.search_window || { min: 10100, max: 65535 };
      el.innerHTML = `<div class="status-banner info">
        🆕 No reservation yet — first deploy will carve a <strong id="rsv-preview-max">${maxStudInput.value}</strong>-slot VXLAN block
        out of the first free gap in <code>${win.min}-${win.max}</code> (same mechanism as challenge templates).
        Max students locks at that value once set.
      </div>`;
    }
  } catch (err) {
    el.innerHTML = '';
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
        attack_boxes: document.getElementById('dep-attack-boxes').checked,
        vuln_app_enabled: document.getElementById('dep-vuln-app').checked
      }
    });
    const s = data.summary || {};
    const banner = data.canProceed ? 'success' : 'error';

    // Compose the headline VM line (existing behavior).
    const headline =
      `<strong>${s.new_vms}</strong> new VMs (${s.vms_per_lane}/lane × ${s.num_lanes}).
       Currently <strong>${s.current_vms}</strong> running. Servers in profile: ${data.profile_asset_summary?.servers}.`;

    // Cost block — render details if present.
    const ce = data.cost_estimate;
    let costHtml = '';
    if (ce) {
      const t = ce.totals;
      const usd = t.llm_total_usd;
      const usdLabel = usd === 0 ? 'Free (local model)'
        : usd < 0.01 ? '< $0.01'
        : `$${usd.toFixed(2)}`;
      const components = ce.components.map(c =>
        `<li><strong>${c.component === 'vuln_app_generation' ? 'Vuln-app generation' : c.component}</strong> — ${c.description}
          → ${c.input_tokens.toLocaleString()} in / ${c.output_tokens.toLocaleString()} out → <strong>$${c.total_usd.toFixed(2)}</strong></li>`
      ).join('');
      const cachedNote = t.vuln_app_already_cached
        ? '<em style="color:#38a169;">Vuln-app already generated for this profile — reusing cached source (no LLM cost).</em>'
        : (components ? '' : '<em>No LLM calls needed — vuln-app disabled.</em>');
      costHtml = `
        <div style="margin-top:0.75rem; padding:0.75rem; background:#f8fafc; border-left:3px solid #1e40af; border-radius:4px;">
          <div style="font-weight:700; margin-bottom:0.35rem;">
            Estimated cost: ${usdLabel} &nbsp;·&nbsp;
            Total VMs: ${t.vms.total} (${t.vms.per_lane}/lane) &nbsp;·&nbsp;
            Est. deploy time: ~${t.estimated_deploy_minutes} min
          </div>
          ${components ? `<ul style="margin:0.25rem 0 0.5rem 1.25rem; padding:0; font-size:0.9em;">${components}</ul>` : ''}
          ${cachedNote}
        </div>`;
    }

    renderBanner('preview-result', banner,
      headline + (data.errors.length ? '<br>⚠ ' + data.errors.join('; ') : '') + costHtml);
  } catch (err) {
    renderBanner('preview-result', 'error', `❌ ${err.message}`);
  }
}

async function runDeploy() {
  if (!CURRENT_PROFILE) return;
  const payload = {
    profile_id: CURRENT_PROFILE.id,
    num_lanes: parseInt(document.getElementById('dep-num-lanes').value, 10),
    max_students: parseInt(document.getElementById('dep-max-students').value, 10),
    group_name: document.getElementById('dep-group-name').value || undefined,
    attack_boxes: document.getElementById('dep-attack-boxes').checked,
    subnet_scheme: document.getElementById('dep-subnet-scheme').value,
    asset_selection: gatherAssetSelection(),
    vuln_app: {
      enabled: document.getElementById('dep-vuln-app').checked,
      delivery_mode: document.getElementById('dep-vuln-app-dedicated').checked ? 'standalone_vm' : 'docker',
      // Per-deploy difficulty (easy|medium|hard) chosen by admin/instructor in the UI.
      // Drives the LLM prompt's vuln-pool selection. Falls back to 'easy' if no radio
      // is selected (shouldn't happen because 'easy' is checked by default in the HTML).
      difficulty: (document.querySelector('input[name="dep-vuln-difficulty"]:checked') || {}).value || 'easy'
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
          <button class="btn btn-secondary btn-small" onclick="promptAddLanes('${g.id}','${g.profile_id || ''}','${escapeHtml(g.group_name)}')">+ Add lanes</button>
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

async function promptAddLanes(groupId, profileId, groupName) {
  // Fetch the profile's current reservation so we know how many slots are free
  let free = null, max = null;
  if (profileId) {
    try {
      const r = await apiCall(`/profile-deploy/profiles/${profileId}/reservation`);
      if (r.reserved) { free = r.slots_free; max = r.max_students; }
    } catch (_) { /* fall through to plain prompt */ }
  }
  const promptMsg = free != null
    ? `Add how many lanes to "${groupName}"?  (${free}/${max} slots free in the profile's reservation)`
    : `Add how many lanes to "${groupName}"?`;
  const answer = window.prompt(promptMsg, '1');
  if (answer == null) return;
  const count = parseInt(answer, 10);
  if (!Number.isFinite(count) || count < 1) return;
  if (free != null && count > free) {
    alert(`Cannot add ${count} — only ${free} slot${free===1?'':'s'} free in the profile's reservation.`);
    return;
  }
  try {
    const result = await apiCall(`/profile-deploy/groups/${groupId}/add-lanes`, {
      method: 'POST', body: { count }
    });
    alert(`✅ Added ${result.added} lane${result.added===1?'':'s'} to ${groupName}. Now ${result.total_lanes_now} total.`);
    refreshGroups();
    setTimeout(() => loadGroupDetail(groupId), 1000);
  } catch (err) {
    alert(`Add-lanes failed: ${err.message}`);
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
document.addEventListener('DOMContentLoaded', async () => {
  // Trigger Auth.check() → fires 'authReady' → layout.js re-injects the
  // sidebar with the real user/role (so the Admin badge + name show up).
  // Without this, layout renders with Auth.user=null and the footer shows
  // "User / Student" with no Admin button.
  if (typeof Auth !== 'undefined' && Auth.requireAuth) {
    if (!await Auth.requireAuth()) return;
    const user = Auth.getUser();
    if (user && user.role !== 'admin') {
      if (typeof Toast !== 'undefined') Toast.error('Access Denied', 'Admin role required for this page.');
      window.location.href = '/ciab/dashboard';
      return;
    }
  }
  // Populate the industry dropdown for the default client type (SMB)
  if (typeof onClientTypeChange === 'function') onClientTypeChange();

  // Hide the Vuln-App difficulty row when the vuln-app checkbox is off —
  // the selector is meaningless if no vuln-app will be generated.
  const vulnCb = document.getElementById('dep-vuln-app');
  const diffRow = document.getElementById('dep-vuln-difficulty-row');
  if (vulnCb && diffRow) {
    const syncDifficultyVisibility = () => {
      diffRow.style.display = vulnCb.checked ? '' : 'none';
    };
    syncDifficultyVisibility();
    vulnCb.addEventListener('change', syncDifficultyVisibility);
  }
});
