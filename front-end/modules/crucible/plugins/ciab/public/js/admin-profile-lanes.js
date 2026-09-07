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

// The browser half of utils/profile-to-spec.js's DEFAULT_SUBNET_SCHEME. This
// file cannot require() it, so it is re-stated ONCE here rather than spelled
// inline at each <select> read — the six bare 'v2' literals scattered across
// the server routes are exactly what made the server-side flip inert, and the
// same drift is available in the UI. The two <select>s in
// public/pages/admin-profile-lanes.html mark this value `selected`; this
// constant only covers the case where the element is missing entirely.
const DEFAULT_SUBNET_SCHEME = 'v3';

let CURRENT_PROFILE = null;   // last loaded profile (from picker or upload)
let CURRENT_ASSETS  = [];     // assets from that profile
let GROUPS_POLL_TIMER = null;

// ─── Tabs ───────────────────────────────────────────────────────────────────

function switchTab(name) {
  // Two tabs now: Deploy Lanes and Active Groups. Generation lives on /ciab/generator.
  document.querySelectorAll('.tab[data-tab]').forEach(t => t.classList.toggle('active', t.dataset.tab === name));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === `tab-${name}`));
  if (name === 'existing') {
    refreshProfiles();
    // INSIDE switchTab, not on the onclick: switchTab is also called
    // programmatically (see runDeploy), and a hook on the button would miss
    // those. Cytoscape measures its container at create(), and .tab-content is
    // display:none until it is .active, so the mount cannot happen any earlier.
    if (typeof LaneTopo !== 'undefined') LaneTopo.onTabShown();
  }
  if (name === 'groups') refreshGroups();
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
    // Kept in step with API.request, which spreads options into the fetch config:
    // the live diagram aborts superseded plan requests.
    signal: opts.signal,
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

// ─── TAB 1: Pick / upload profile ──────────────────────────────────────────

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
      return `<option value="${escapeHtml(id)}">${escapeHtml(name)} (${escapeHtml(date)})</option>`;
    }).join('');
  } catch (err) {
    picker.innerHTML = `<option value="">Error: ${escapeHtml(err.message)}</option>`;
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

    // GET /api/profiles/:id embeds the asset list server-side — no need to
    // fetch the raw profile JSON directly.
    const assets = profile?.assets;
    CURRENT_ASSETS = Array.isArray(assets) ? assets : [];

    renderAssetTable();
    // First draw. Everything after this is driven by the delegated listener in
    // admin-profile-lanes-topo.js.
    if (typeof LaneTopo !== 'undefined') LaneTopo.schedule();
    document.getElementById('asset-selection-card').style.display = '';
    document.getElementById('dep-group-name').placeholder =
      `${(profile.companyName || profile.company_name || 'profile').replace(/\s/g,'-').toLowerCase()}-${new Date().toISOString().slice(0,10)}`;

    // Show this profile's VXLAN reservation status (if any)
    await loadReservationStatus(id);
  } catch (err) {
    renderBanner('profile-load-result', 'error', `❌ ${err.message}`);
  }
}

/**
 * The scheme the block was CARVED at wins over the selector on every deploy
 * (runProfileDeploy's carvedScheme). Once a reservation exists, showing a live
 * v2/v3 dropdown invites a choice that cannot be honoured — so it is set to the
 * carve and disabled, with the reason on screen.
 */
function lockSchemeToCarve(scheme) {
  const sel = document.getElementById('dep-subnet-scheme');
  const note = document.getElementById('dep-scheme-note');
  if (!sel) return;
  if (!scheme) {
    sel.disabled = false;
    if (note) note.textContent = '';
    return;
  }
  sel.value = scheme;
  sel.disabled = true;
  if (note) {
    note.textContent = 'Locked: this profile\'s network was reserved as ' + scheme
      + ', and lanes are built at the scheme the block was carved at.';
  }
}

async function loadReservationStatus(profileId) {
  const el = document.getElementById('dep-reservation-status');
  if (!el) return;
  try {
    const r = await apiCall(`/profile-deploy/profiles/${profileId}/reservation`);
    lockSchemeToCarve(r.subnet_scheme || null);
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
      // A8b: nothing reserved. Reserving is a slow, cluster-wide operation
      // (25-50 serial VNet POSTs, a cluster-wide SDN apply, then a per-node
      // bridge wait), so it is an EXPLICIT action taken ahead of deploy day
      // rather than something the first deploy does while an instructor waits.
      await renderEngagementPanel(profileId, el);
    }
  } catch (err) {
    el.innerHTML = '';
  }
}


// ─── A8b: the reservation panel ─────────────────────────────────────────────
// Reserving a VXLAN block is minutes of cluster-wide work, so its state has to
// be visible. Without this the wait is invisible and reads as a hang.

/** Poll handle, so switching profiles cannot leave two timers running. */
let ENGAGEMENT_POLL = null;

function stopEngagementPoll() {
  if (ENGAGEMENT_POLL) { clearTimeout(ENGAGEMENT_POLL); ENGAGEMENT_POLL = null; }
}

async function renderEngagementPanel(profileId, el) {
  stopEngagementPoll();
  const maxStudInput = document.getElementById('dep-max-students');
  let engagements = [];
  try {
    const r = await apiCall(`/profile-deploy/profiles/${profileId}/engagements`);
    engagements = Array.isArray(r.engagements) ? r.engagements : [];
  } catch (_) { /* fall through to the "reserve it" state */ }

  const eng = engagements[0] || null;

  if (!eng) {
    if (maxStudInput) maxStudInput.disabled = false;
    el.innerHTML = `<div class="status-banner info">
      🆕 <strong>No network reserved yet.</strong> Carving the VXLAN block takes a few minutes —
      it creates one VNet per lane, applies SDN across the whole cluster, then waits for the
      bridges to come up on every node. Do it now and deploy day is fast.
      <div style="margin-top:10px">
        <button class="btn btn-primary" id="btn-reserve-engagement">Reserve network</button>
        <span class="muted" style="margin-left:8px">
          Reserves <strong id="rsv-preview-max">${maxStudInput ? maxStudInput.value : ''}</strong> slots.
          Max students locks once set.
        </span>
      </div>
    </div>`;
    const btn = document.getElementById('btn-reserve-engagement');
    if (btn) btn.onclick = () => reserveEngagement(profileId, el);
    return;
  }

  if (maxStudInput) {
    maxStudInput.value = eng.max_students;
    // The block size is fixed once carved — changing it here would ask the
    // resize path to re-carve a block lanes may already be sitting in.
    maxStudInput.disabled = true;
  }

  if (eng.provision_status === 'provisioning') {
    el.innerHTML = `<div class="status-banner info">
      ⏳ <strong>Reserving the network…</strong> Creating ${eng.max_students} VNets, applying SDN
      across the cluster, then confirming the bridges on every node. This takes a few minutes and
      continues if you navigate away.
    </div>`;
    // Poll rather than leaving the operator guessing. Cleared on profile switch.
    ENGAGEMENT_POLL = setTimeout(() => renderEngagementPanel(profileId, el), 5000);
    return;
  }

  if (eng.provision_status === 'failed') {
    el.innerHTML = `<div class="status-banner error">
      ❌ <strong>Network reservation failed.</strong>
      <div class="muted" style="margin-top:4px">${escapeHtml(eng.provision_error || 'No reason recorded.')}</div>
      <div style="margin-top:10px">
        <button class="btn btn-secondary" id="btn-reprovision-engagement">Re-provision</button>
        <span class="muted" style="margin-left:8px">A failed reservation self-cleans, so retrying is safe.</span>
      </div>
    </div>`;
    const btn = document.getElementById('btn-reprovision-engagement');
    if (btn) btn.onclick = () => reprovisionEngagement(eng.engagement_id, profileId, el);
    return;
  }

  // ready
  const bridgeNote = eng.bridges_ready
    ? '<span class="muted">Bridges confirmed on every online node.</span>'
    : `<span class="muted">⚠ Bridges not confirmed on every node — lanes placed on an
       unconfirmed node will fail to cable. Re-provision once the node is back.</span>`;
  el.innerHTML = `<div class="status-banner ${eng.bridges_ready ? 'info' : 'warning'}">
    ✅ <strong>Network ready</strong> — ${eng.max_students} slots,
    engagement <code>${escapeHtml(eng.engagement_type)}</code>,
    challenge <code>${escapeHtml((eng.challenge_key || '').slice(0, 40))}</code>.
    <div style="margin-top:4px">${bridgeNote}</div>
  </div>`;
}

async function reserveEngagement(profileId, el) {
  const maxStudInput = document.getElementById('dep-max-students');
  const btn = document.getElementById('btn-reserve-engagement');
  if (btn) Utils.setBtnLoading(btn, true);
  try {
    await apiCall('/profile-deploy/engagements', {
      method: 'POST',
      body: {
        profile_id: profileId,
        engagement_type: 'default',
        subnet_scheme: (document.getElementById('dep-subnet-scheme') || {}).value || DEFAULT_SUBNET_SCHEME,
        max_students: parseInt(maxStudInput.value, 10),
      },
    });
    Toast.success('Reserving Network', 'Carving the VXLAN block and creating one VNet per lane — this takes a few minutes.');
    await renderEngagementPanel(profileId, el);
  } catch (err) {
    Toast.error('Reservation Failed', err.message || 'Could not start the reservation.');
  } finally {
    if (btn) Utils.setBtnLoading(btn, false);
  }
}

async function reprovisionEngagement(engagementId, profileId, el) {
  const btn = document.getElementById('btn-reprovision-engagement');
  if (btn) Utils.setBtnLoading(btn, true);
  try {
    await apiCall(`/profile-deploy/engagements/${engagementId}/reprovision`, { method: 'POST' });
    Toast.success('Re-provisioning', 'Re-running the network carve for this engagement.');
    await renderEngagementPanel(profileId, el);
  } catch (err) {
    Toast.error('Re-provision Failed', err.message || 'Could not re-provision.');
  } finally {
    if (btn) Utils.setBtnLoading(btn, false);
  }
}

// ─── The asset rail ─────────────────────────────────────────────────────────
//
// Selection lives in a Set of asset indices rather than in the DOM. The table it
// replaced read `input[data-asset-idx]` back out of the document on every
// gather, which meant selection could not survive a filter, a search or a
// re-render — and the rail does all three. gatherAssetSelection() keeps its
// exact [{hostname, role, os, included}] contract so runDeploy is untouched.

const SELECTED = new Set();      // asset indices the admin wants deployed
let RAIL_FILTER = 'all';         // all | servers | ghosts
let RAIL_SEARCH = '';
// hostname (lowercased) -> what POST /plan says will become of it. Filled by
// LaneTopo on every response; empty until the first one lands.
let RAIL_FATE = new Map();

/** The default selection, and the one runProfileDeploy applies when none is sent. */
function selectDefault() {
  SELECTED.clear();
  CURRENT_ASSETS.forEach((a, i) => {
    if (String(a.role || '').toLowerCase() === 'server') SELECTED.add(i);
  });
}

/**
 * The row's fate IN THE LANE, not its role — which is the whole point of the
 * glyph. Everything except 'parked' comes from the server's plan; nothing here
 * decides placement.
 */
const FATE = {
  pivot:    { glyph: '\u25C6', cls: 'fate-pivot',    label: 'dual-homed pivot at .240' },
  internal: { glyph: '\u25CF', cls: 'fate-internal', label: 'builds, on the corporate segment' },
  external: { glyph: '\u25B2', cls: 'fate-external', label: 'builds, on the attacker segment' },
  lan:      { glyph: '\u25AC', cls: 'fate-lan',      label: 'builds, flat lane' },
  gap:      { glyph: '\u26A0', cls: 'fate-gap',      label: 'builds, but a declared service has no installer' },
  ghost:    { glyph: '\u2716', cls: 'fate-ghost',    label: 'no template matched — this will NOT be built' },
  parked:   { glyph: '\u2014', cls: 'fate-parked',   label: 'not selected' },
  pending:  { glyph: '\u00B7', cls: 'fate-parked',   label: 'working it out…' },
};

function fateFor(asset, idx) {
  if (!SELECTED.has(idx)) return FATE.parked;
  return RAIL_FATE.get(String(asset.hostname || '').toLowerCase()) || FATE.pending;
}

/** Called by LaneTopo when a plan lands, so the list and the diagram agree. */
function applyPlanToRail(plan) {
  RAIL_FATE = new Map();
  (plan.machines || []).forEach((m) => {
    const key = String(m.hostname || m.name || '').toLowerCase();
    let fate;
    if (m.is_pivot) fate = FATE.pivot;
    else if (m.severity === 'warning') fate = FATE.gap;
    else if (m.segments.indexOf('lan') !== -1) fate = FATE.lan;
    else if (m.segments.indexOf('int') !== -1) fate = FATE.internal;
    else fate = FATE.external;
    RAIL_FATE.set(key, fate);
  });
  (plan.ghosts || []).forEach((g) => {
    RAIL_FATE.set(String(g.hostname || g.name || '').toLowerCase(),
      Object.assign({}, FATE.ghost, { why: g.reason_text, remedies: g.remedies }));
  });
  renderAssetRail();
}

function railMatches(a, idx) {
  if (RAIL_SEARCH) {
    const hay = [a.hostname, a.os, a.role].join(' ').toLowerCase();
    if (hay.indexOf(RAIL_SEARCH) === -1) return false;
  }
  if (RAIL_FILTER === 'servers') return String(a.role || '').toLowerCase() === 'server';
  if (RAIL_FILTER === 'ghosts') return fateFor(a, idx) === FATE.ghost
    || (fateFor(a, idx) && fateFor(a, idx).cls === 'fate-ghost');
  return true;
}

/**
 * Rows grouped by the profile's own subnet when it declares one, else by role.
 * Grouping by the CLIENT's network is what lets an admin reason in the story's
 * terms ("everything in the DMZ") rather than in ours.
 */
function railGroups() {
  const groups = new Map();
  CURRENT_ASSETS.forEach((a, i) => {
    if (!railMatches(a, i)) return;
    const key = a.subnet || a.role || 'other';
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(i);
  });
  return groups;
}

function renderAssetRail() {
  const host = document.getElementById('dep-asset-list');
  if (!host) return;

  const count = document.getElementById('rail-count');
  if (count) {
    const ghosts = CURRENT_ASSETS.filter(
      (a, i) => SELECTED.has(i) && fateFor(a, i).cls === 'fate-ghost').length;
    count.textContent = SELECTED.size + ' of ' + CURRENT_ASSETS.length + ' selected'
      + (ghosts ? ' · ' + ghosts + ' will not build' : '');
  }

  if (CURRENT_ASSETS.length === 0) {
    host.innerHTML = '<div class="empty">No assets in this profile.</div>';
    return;
  }

  const groups = railGroups();
  if (groups.size === 0) {
    host.innerHTML = '<div class="empty">Nothing matches that filter.</div>';
  } else {
    let out = '';
    groups.forEach((idxs, key) => {
      const on = idxs.filter((i) => SELECTED.has(i)).length;
      out += '<div class="rail-group"><div class="rail-group-head">'
        + '<span>' + escapeHtml(key) + '</span><span>' + on + '/' + idxs.length + '</span></div>';
      out += idxs.map((i) => {
        const a = CURRENT_ASSETS[i];
        const f = fateFor(a, i);
        const isGhost = f.cls === 'fate-ghost';
        return '<label class="asset-row' + (isGhost ? ' is-ghost' : '') + '"'
          + ' data-asset-row="' + i + '" title="' + escapeHtml(f.label) + '">'
          + '<input type="checkbox" data-asset-idx="' + i + '"' + (SELECTED.has(i) ? ' checked' : '') + ' />'
          + '<span><code>' + escapeHtml(a.hostname || '') + '</code>'
          + '<span class="asset-sub">' + escapeHtml(a.os || a.role || '') + '</span></span>'
          + '<span class="fate ' + f.cls + '">' + f.glyph + '</span>'
          + '</label>';
      }).join('');
      out += '</div>';
    });
    host.innerHTML = out;
  }

  renderParked();
}

function renderParked() {
  const host = document.getElementById('dep-parked');
  if (!host) return;
  const parked = CURRENT_ASSETS.map((a, i) => ({ a, i })).filter(({ i }) => !SELECTED.has(i));
  if (parked.length === 0) { host.innerHTML = ''; return; }
  host.innerHTML = '<div class="parked-strip"><span class="muted" style="font-size:0.72rem;">'
    + 'PARKED (' + parked.length + ') — click to include</span><br>'
    + parked.map(({ a, i }) =>
      '<button type="button" class="parked-chip" data-park-add="' + i + '">'
      + escapeHtml(a.hostname || '') + ' +</button>').join('')
    + '</div>';
}

/** Back-compat alias: the old name, still called on profile load. */
function renderAssetTable() {
  selectDefault();
  renderAssetRail();
}

// One delegated listener for the whole rail. Rows are re-rendered on every
// change, so per-row handlers would be re-bound constantly.
document.addEventListener('click', (e) => {
  const chip = e.target.closest('[data-rail-filter]');
  if (chip) {
    RAIL_FILTER = chip.getAttribute('data-rail-filter');
    document.querySelectorAll('[data-rail-filter]').forEach(
      (b) => b.classList.toggle('active', b === chip));
    renderAssetRail();
    return;
  }
  const bulk = e.target.closest('[data-rail-select]');
  if (bulk) {
    const mode = bulk.getAttribute('data-rail-select');
    if (mode === 'none') SELECTED.clear();
    else if (mode === 'servers') selectDefault();
    else CURRENT_ASSETS.forEach((a, i) => SELECTED.add(i));
    renderAssetRail();
    if (typeof LaneTopo !== 'undefined') LaneTopo.schedule();
    return;
  }
  const park = e.target.closest('[data-park-add]');
  if (park) {
    SELECTED.add(parseInt(park.getAttribute('data-park-add'), 10));
    renderAssetRail();
    if (typeof LaneTopo !== 'undefined') LaneTopo.schedule();
  }
});

document.addEventListener('change', (e) => {
  const cb = e.target.closest('input[data-asset-idx]');
  if (!cb) return;
  const idx = parseInt(cb.getAttribute('data-asset-idx'), 10);
  if (cb.checked) SELECTED.add(idx); else SELECTED.delete(idx);
  // The row is repainted to 'pending' immediately; the real fate arrives with
  // the plan. Optimistic UI may only DIM — it must never guess a placement.
  renderAssetRail();
});

document.addEventListener('input', (e) => {
  if (!e.target.closest('#rail-search')) return;
  RAIL_SEARCH = e.target.value.trim().toLowerCase();
  renderAssetRail();
});

function gatherAssetSelection() {
  return CURRENT_ASSETS.map((a, i) => (
    { hostname: a.hostname, role: a.role, os: a.os, included: SELECTED.has(i) }
  ));
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
        vuln_app_enabled: document.getElementById('dep-vuln-app').checked,
        // Without these the server re-counted every server asset in the PROFILE
        // and sized the cluster against a number that had nothing to do with
        // what was ticked.
        asset_selection: gatherAssetSelection(),
        subnet_scheme: document.getElementById('dep-subnet-scheme').value
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
        <div style="margin-top:0.75rem; padding:0.75rem; background:#f8fafc; border-left:3px solid var(--primary, #0c234b); border-radius:4px;">
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
      // Always docker: vuln-app-generator.js overrides delivery_mode regardless
      // of what is sent, so sending anything else would be a lie the diagram
      // would then have to draw.
      delivery_mode: 'docker',
      // Per-deploy difficulty (easy|medium|hard) chosen by admin/instructor in the UI.
      // Drives the LLM prompt's vuln-pool selection. Falls back to 'easy' if no radio
      // is selected (shouldn't happen because 'easy' is checked by default in the HTML).
      difficulty: (document.querySelector('input[name="dep-vuln-difficulty"]:checked') || {}).value || 'easy'
    }
  };

  const ghosts = (typeof LaneTopo !== 'undefined' && LaneTopo.ghosts()) || [];
  if (ghosts.length) {
    const names = ghosts.map((g) => g.name).join(', ');
    const ok = await Confirm.show({
      title: 'Some selected assets will not be built',
      message: ghosts.length + ' selected asset' + (ghosts.length === 1 ? '' : 's')
        + ' resolve no VM template and will be skipped silently: ' + names + '.',
      confirmText: 'Deploy anyway',
    });
    if (!ok) return;
  }

  renderBanner('deploy-result', 'info', '⏳ Starting deployment…');
  try {
    const data = await apiCall('/profile-deploy/deploy', { method: 'POST', body: payload });

    // Build the credentials block (one-time display — these passwords are
    // never recoverable in plaintext again). Escape the password field
    // because random charsets include HTML-sensitive chars like < > & " '.
    const escapeHtml = (s) => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    let credsBlock = '';
    if (Array.isArray(data.credentials) && data.credentials.length) {
      const rows = data.credentials.map(c =>
        `<tr><td><code>${escapeHtml(c.email)}</code></td>` +
        `<td><code>${escapeHtml(c.password)}</code></td>` +
        `<td>${escapeHtml(c.role)}</td></tr>`
      ).join('');
      credsBlock = `
        <div style="margin-top:1rem; background:rgba(245,158,11,0.12); border:2px solid rgba(245,158,11,0.4); padding:1rem; border-radius:6px;">
          <strong style="color:var(--warning, #744210);">⚠️ One-time student credentials — copy these now</strong>
          <p style="margin:0.5rem 0; font-size:0.875rem; color:var(--text-secondary, #744210);">These passwords are NOT recoverable. Re-deploying this group rotates them.</p>
          <table style="width:100%; border-collapse:collapse; font-size:0.875rem; margin-top:0.5rem;">
            <thead><tr style="background:#744210; color:#fff;">
              <th style="padding:0.4rem 0.75rem; text-align:left;">Email</th>
              <th style="padding:0.4rem 0.75rem; text-align:left;">Password</th>
              <th style="padding:0.4rem 0.75rem; text-align:left;">Role</th>
            </tr></thead>
            <tbody>${rows}</tbody>
          </table>
          <button onclick="copyCredsToClipboard()" class="btn btn-secondary" style="margin-top:0.5rem; font-size:0.85rem;">📋 Copy as CSV</button>
        </div>`;
      // Stash for the copy button
      window._lastDeployCredentials = data.credentials;
    }

    renderBanner('deploy-result', 'success',
      `✅ Deploy started. Group <code>${data.group_id}</code> — ${data.lanes.length} lanes, ${data.students?.length || 0} students.
       ${data.service_gaps.length ? `<br>⚠ ${data.service_gaps.length} service gaps` : ''}
       ${data.template_misses.length ? `<br>⚠ ${data.template_misses.length} template misses` : ''}
       ${credsBlock}`);
    // Don't auto-switch tabs when we have credentials to show — let the admin
    // copy them first. They can click into Active Groups themselves.
    if (!credsBlock) setTimeout(() => switchTab('groups'), 1500);
  } catch (err) {
    const extra = [];
    if (err.body?.template_misses?.length) extra.push(`Template misses: ${err.body.template_misses.map(m => m.hostname).join(', ')}`);
    if (err.body?.service_gaps?.length)    extra.push(`Service gaps: ${err.body.service_gaps.length}`);
    renderBanner('deploy-result', 'error', `❌ ${err.message}${extra.length ? '<br>' + extra.join('<br>') : ''}`);
  }
}

// Copy the credentials block as a CSV the admin can paste into a class roster
// email, spreadsheet, or LMS. One row per student; password is the plaintext
// shown in the table — only available in this session, not retrievable later.
function copyCredsToClipboard() {
  const creds = window._lastDeployCredentials || [];
  if (!creds.length) return;
  const csv = 'email,password,role\n' +
    creds.map(c => `${c.email},"${String(c.password).replace(/"/g, '""')}",${c.role}`).join('\n');
  navigator.clipboard.writeText(csv).then(
    () => Toast.success('Copied', 'Credentials copied as CSV. Paste into your spreadsheet.'),
    () => {
      // fallback if clipboard API blocked — alert() kept intentionally: it shows
      // the CSV in a selectable dialog so the admin can still copy it manually.
      Toast.warning('Clipboard Blocked', 'Showing credentials CSV in a dialog — copy it manually.');
      alert(csv);
    }
  );
}

// One-time credentials modal — used by add-lanes (which lands on the Active
// Groups tab where the deploy-result banner doesn't exist). Passwords are
// only ever visible here; closing the modal discards them.
function showCredsModal(credentials, title = 'One-time student credentials') {
  if (!Array.isArray(credentials) || credentials.length === 0) return;
  window._lastDeployCredentials = credentials;
  const esc = s => String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  const rows = credentials.map(c =>
    `<tr><td style="padding:0.3rem 0.6rem;"><code>${esc(c.email)}</code></td>` +
    `<td style="padding:0.3rem 0.6rem;"><code>${esc(c.password)}</code></td>` +
    `<td style="padding:0.3rem 0.6rem;">${esc(c.role)}</td></tr>`).join('');
  const overlay = document.createElement('div');
  overlay.style.cssText = 'position:fixed;inset:0;background:rgba(15,23,42,0.55);z-index:400;display:flex;align-items:center;justify-content:center;padding:20px;';
  overlay.innerHTML = `
    <div style="background:var(--bg-card,#fff);color:var(--text-primary,#111827);border-radius:10px;max-width:580px;width:100%;max-height:80vh;overflow:auto;padding:1.25rem;box-shadow:0 10px 40px rgba(0,0,0,0.35);">
      <strong style="color:var(--warning,#b45309);">⚠️ ${esc(title)} — copy these now</strong>
      <p style="margin:0.5rem 0;font-size:0.875rem;">These passwords are NOT recoverable later. Re-deploying rotates them.</p>
      <table style="width:100%;border-collapse:collapse;font-size:0.875rem;">
        <thead><tr>
          <th style="text-align:left;padding:0.3rem 0.6rem;">Email</th>
          <th style="text-align:left;padding:0.3rem 0.6rem;">Password</th>
          <th style="text-align:left;padding:0.3rem 0.6rem;">Role</th>
        </tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div style="display:flex;gap:0.5rem;margin-top:0.75rem;justify-content:flex-end;">
        <button class="btn btn-secondary" onclick="copyCredsToClipboard()">📋 Copy as CSV</button>
        <button class="btn btn-primary" data-close>Done</button>
      </div>
    </div>`;
  overlay.addEventListener('click', e => {
    if (e.target === overlay || e.target.closest('[data-close]')) overlay.remove();
  });
  document.body.appendChild(overlay);
}

// ─── TAB 2: Active groups ──────────────────────────────────────────────────

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
    list.innerHTML = '<div class="empty">No groups yet. Deploy some from the Deploy Lanes tab.</div>';
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
          <button class="btn btn-secondary btn-small" data-group-action="details"
            data-group-id="${escapeHtml(g.id)}">Details</button>
          <button class="btn btn-secondary btn-small" data-group-action="add-lanes"
            data-group-id="${escapeHtml(g.id)}" data-profile-id="${escapeHtml(g.profile_id || '')}"
            data-group-name="${escapeHtml(g.group_name)}">+ Add lanes</button>
          <button class="btn btn-danger btn-small" data-group-action="teardown"
            data-group-id="${escapeHtml(g.id)}" data-group-name="${escapeHtml(g.group_name)}">Tear down</button>
        </div>
      </div>
      <div id="group-${g.id}-detail"></div>
    </div>
  `).join('');
}

document.addEventListener('click', (e) => {
  const btn = e.target.closest('[data-group-action]');
  if (!btn) return;
  const id = btn.getAttribute('data-group-id');
  const name = btn.getAttribute('data-group-name') || '';
  switch (btn.getAttribute('data-group-action')) {
    case 'details':   loadGroupDetail(id); break;
    case 'add-lanes': promptAddLanes(id, btn.getAttribute('data-profile-id') || '', name); break;
    case 'teardown':  teardownGroup(id, name); break;
    case 'retry':     retryLane(id, btn.getAttribute('data-lane-id')); break;
    // The deployed lane, drawn by the same renderer as the pre-deploy preview.
    case 'topology':
      if (typeof LaneTopo !== 'undefined') {
        LaneTopo.openLive(btn.getAttribute('data-lane-id'), btn.getAttribute('data-lane-name'));
      }
      break;
  }
});

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
          <div style="display:flex; gap:0.35rem;">${j.lane_id
            ? `<button class="btn btn-small btn-secondary" data-group-action="topology"
                 data-lane-id="${escapeHtml(j.lane_id)}"
                 data-lane-name="${escapeHtml(j.lane_name || ('lane ' + j.lane_index))}"
                 title="What this lane actually built">Topology</button>`
            : ''}${isError
            ? `<button class="btn btn-small btn-secondary" data-group-action="retry"
                 data-group-id="${escapeHtml(groupId)}" data-lane-id="${escapeHtml(j.lane_id)}">Retry</button>`
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
    Toast.error('Cannot Add Lanes', `Only ${free} slot${free===1?'':'s'} free in the profile's reservation.`);
    return;
  }
  try {
    const result = await apiCall(`/profile-deploy/groups/${groupId}/add-lanes`, {
      method: 'POST', body: { count }
    });
    Toast.success('Lanes Added', `Added ${result.added} lane${result.added===1?'':'s'} to ${groupName}. Now ${result.total_lanes_now} total.`);
    // Each added lane gets its own auto-provisioned student — surface the
    // one-time credentials before anything re-renders.
    showCredsModal(result.credentials, `New student credentials for ${groupName}`);
    refreshGroups();
    setTimeout(() => loadGroupDetail(groupId), 1000);
  } catch (err) {
    Toast.error('Add Lanes Failed', err.message);
  }
}

async function retryLane(groupId, laneId) {
  try {
    await apiCall(`/profile-deploy/groups/${groupId}/retry/${laneId}`, { method: 'POST' });
    setTimeout(() => loadGroupDetail(groupId), 500);
  } catch (err) {
    Toast.error('Retry Failed', err.message);
  }
}

async function teardownGroup(groupId, name) {
  if (!await Confirm.show({
    title: 'Tear Down Group',
    message: `Tear down group "${name}" and destroy all its lanes?`,
    confirmText: 'Tear Down',
    danger: true
  })) return;
  try {
    await apiCall(`/profile-deploy/groups/${groupId}`, { method: 'DELETE' });
    Toast.success('Teardown Started', `Group "${name}" is being torn down.`);
    refreshGroups();
  } catch (err) {
    Toast.error('Teardown Failed', err.message);
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
    // isRealAdmin(), not user.role: Student View rewrites the drawn role, and
    // gating entry on it would bounce an admin off this page mid-recording.
    const user = Auth.getUser();
    if (user && !Auth.isRealAdmin()) {
      if (typeof Toast !== 'undefined') Toast.error('Access Denied', 'Admin role required for this page.');
      window.location.href = '/ciab/dashboard';
      return;
    }
  }
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

  // Deploy Lanes is the tab the page OPENS on now that Generate + Deploy is gone,
  // so the profile list has to be fetched here. It used to arrive only via
  // switchTab('existing'), which nothing calls when that tab is already active.
  refreshProfiles();
});
