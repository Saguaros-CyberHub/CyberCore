// ============================================================================
// AUDIT LOG
// ----------------------------------------------------------------------------
// Replaces admin-activity-log.js, which had three live bugs:
//   1. It rendered `l.email`, a field the API never selected, so every row
//      showed "system". The actor is now a real column on the row.
//   2. loadAuditLog() was never called on load or tab switch, so the tab was
//      blank until you clicked Search. The tab button now calls
//      auditTabActivate().
//   3. The action dropdown was eleven hardcoded values, six of which nothing
//      ever wrote. It is now built from /audit/facets.
// ============================================================================

let auditOffset = 0;
let auditPageSize = 50;
let auditRefreshTimer = null;
let auditFacets = null;
let auditLoaded = false;

// Category drives the badge colour rather than a per-action lookup, so adding
// an action can never leave the UI with an uncoloured badge.
const AUDIT_CATEGORY_BADGE = {
  auth:       'badge-green',
  user:       'badge-blue',
  enrollment: 'badge-blue',
  infra:      'badge-yellow',
  access:     'badge-gray',
  content:    'badge-gray',
  config:     'badge-gray',
};

function auditBadgeClass(row) {
  if (row.status !== 'success') return 'badge-red';
  return AUDIT_CATEGORY_BADGE[row.category] || 'badge-gray';
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

async function auditTabActivate() {
  if (auditLoaded) return;
  auditLoaded = true;
  await loadAuditFacets();
  await loadAuditLog(0);
}

async function loadAuditFacets() {
  try {
    auditFacets = await api('GET', '/audit/facets');
  } catch (e) {
    auditFacets = { actions: [], actors: [], categories: [], statuses: [] };
    Toast.warning('Filters unavailable', e.message);
    return;
  }

  // Actions, grouped by category so a long list stays navigable.
  const actionSel = document.getElementById('auditAction');
  if (actionSel) {
    const byCategory = {};
    for (const a of auditFacets.actions) (byCategory[a.category] ||= []).push(a);
    actionSel.innerHTML = '<option value="">All Actions</option>' +
      Object.keys(byCategory).sort().map(cat => `
        <optgroup label="${escHtml(cat)}">
          ${byCategory[cat].map(a =>
            `<option value="${escHtml(a.action)}">${escHtml(a.action)} (${a.count})</option>`).join('')}
        </optgroup>`).join('');
  }

  // Actor picker: a datalist gives a searchable dropdown with no library,
  // which is what the no-bundler admin console allows.
  const actorList = document.getElementById('auditActorList');
  if (actorList) {
    actorList.innerHTML = auditFacets.actors.map(a =>
      `<option value="${escHtml(a.actor_email || a.actor_user_id)}">${escHtml(a.actor_role || '')} — ${a.count} events</option>`
    ).join('');
  }
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

function auditFilterParams() {
  const params = new URLSearchParams();
  const val = id => document.getElementById(id)?.value?.trim() || '';

  if (val('auditSearch'))     params.set('q', val('auditSearch'));
  if (val('auditCategory'))   params.set('category', val('auditCategory'));
  if (val('auditAction'))     params.set('action', val('auditAction'));
  if (val('auditStatus'))     params.set('status', val('auditStatus'));
  if (val('auditSource'))     params.set('source', val('auditSource'));
  if (val('auditFrom'))       params.set('from', val('auditFrom'));
  if (val('auditTo'))         params.set('to', `${val('auditTo')}T23:59:59`);

  // The actor box holds an email; resolve it to a user id via the facets so
  // the query hits idx_audit_actor instead of scanning on the text column.
  const actor = val('auditActor');
  if (actor) {
    const match = auditFacets?.actors?.find(a => a.actor_email === actor);
    if (match) params.set('actor_user_id', match.actor_user_id);
    else params.set('q', actor);
  }

  const targetUser = val('auditTargetUser');
  if (targetUser) params.set('q', targetUser);

  return params;
}

function auditApplyChip(filters) {
  document.getElementById('auditSearch').value = '';
  document.getElementById('auditCategory').value = filters.category || '';
  document.getElementById('auditAction').value = '';
  document.getElementById('auditStatus').value = filters.status || '';
  document.getElementById('auditActor').value = '';
  document.getElementById('auditFrom').value = filters.from || '';
  document.getElementById('auditTo').value = '';
  if (filters.actor_role) document.getElementById('auditSearch').value = '';
  loadAuditLog(0, filters.actor_role ? { actor_role: filters.actor_role } : {});
}

function auditReset() {
  ['auditSearch', 'auditCategory', 'auditAction', 'auditStatus', 'auditSource',
   'auditActor', 'auditTargetUser', 'auditFrom', 'auditTo']
    .forEach(id => { const el = document.getElementById(id); if (el) el.value = ''; });
  loadAuditLog(0);
}

// ---------------------------------------------------------------------------
// List
// ---------------------------------------------------------------------------

async function loadAuditLog(offset = 0, extra = {}) {
  auditOffset = offset;
  const container = document.getElementById('auditTable');
  if (!container) return;
  container.innerHTML = '<p style="color: var(--gray-500);">Loading…</p>';

  try {
    const params = auditFilterParams();
    for (const [k, v] of Object.entries(extra)) params.set(k, v);
    params.set('limit', auditPageSize);
    params.set('offset', offset);

    const data = await api('GET', `/audit?${params}`);
    renderAuditActorCard(params.get('actor_user_id'));

    if (!data.rows.length) {
      container.innerHTML = `<div style="background: var(--bg-card, white); border-radius: 12px; padding: 2rem; text-align: center; box-shadow: var(--shadow-sm); color: var(--gray-500);">No activity matches these filters.</div>`;
      document.getElementById('auditPagination').innerHTML = '';
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>Time</th><th>Actor</th><th>Action</th><th>Target</th>
          <th>Status</th><th>Source</th><th>IP</th>
        </tr></thead>
        <tbody>
          ${data.rows.map(r => `
            <tr onclick="showAuditDetail(${r.audit_id})" style="cursor: pointer;">
              <td style="font-size: 0.8rem; white-space: nowrap;">${new Date(r.occurred_at).toLocaleString()}</td>
              <td style="font-size: 0.8rem;">
                ${escHtml(r.actor_email || (r.actor_type === 'system' ? 'system' : '—'))}
                ${r.actor_role ? `<span class="badge badge-gray" style="margin-left: 0.3rem;">${escHtml(r.actor_role)}</span>` : ''}
              </td>
              <td><span class="badge ${auditBadgeClass(r)}">${escHtml(r.action)}</span></td>
              <td style="font-size: 0.8rem;">
                ${escHtml(r.target_label || r.target_id || '')}
                ${r.target_type ? `<span style="color: var(--gray-500);"> (${escHtml(r.target_type)})</span>` : ''}
              </td>
              <td style="font-size: 0.8rem;">
                ${r.status === 'success' ? '✓' : `<span style="color: #e53e3e;">${escHtml(r.status)}${r.reason ? ` · ${escHtml(r.reason)}` : ''}</span>`}
              </td>
              <td style="font-size: 0.8rem;">${escHtml(r.source)}</td>
              <td style="font-size: 0.8rem;">${escHtml(r.ip_address || '—')}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;

    const pag = document.getElementById('auditPagination');
    const totalPages = Math.max(1, Math.ceil(data.total / auditPageSize));
    const currentPage = Math.floor(offset / auditPageSize) + 1;
    let html = `<span style="font-size: 0.8rem; color: var(--gray-500);">${data.total} total</span>`;
    if (currentPage > 1) html += `<button class="btn btn-sm btn-outline" onclick="loadAuditLog(${offset - auditPageSize})">Prev</button>`;
    html += `<span style="font-size: 0.8rem;">Page ${currentPage}/${totalPages}</span>`;
    if (currentPage < totalPages) html += `<button class="btn btn-sm btn-outline" onclick="loadAuditLog(${offset + auditPageSize})">Next</button>`;
    if (data.dropped) html += `<span class="badge badge-red" title="Audit writes that failed since restart">${data.dropped} dropped</span>`;
    pag.innerHTML = html;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${escHtml(e.message)}</p>`;
  }
}

/** Header card summarising one instructor, shown when an actor filter is on. */
async function renderAuditActorCard(actorUserId) {
  const card = document.getElementById('auditActorCard');
  if (!card) return;
  if (!actorUserId) { card.style.display = 'none'; return; }
  try {
    const { actor_summary: s } = await api('GET', `/audit/facets?actor_user_id=${encodeURIComponent(actorUserId)}`);
    const email = document.getElementById('auditActor')?.value || '';
    card.style.display = 'block';
    card.innerHTML = `
      <strong>${escHtml(email)}</strong>
      <span style="color: var(--gray-500);">
        · ${s.total} events · ${s.students_added} students added · ${s.infra_events} VM/lane events
        ${s.problems ? ` · <span style="color:#e53e3e;">${s.problems} failed/denied</span>` : ''}
        · last active ${s.last_active ? new Date(s.last_active).toLocaleString() : '—'}
      </span>`;
  } catch { card.style.display = 'none'; }
}

// ---------------------------------------------------------------------------
// Detail drawer
// ---------------------------------------------------------------------------

async function showAuditDetail(auditId) {
  const drawer = document.getElementById('auditDrawer');
  const body = document.getElementById('auditDrawerBody');
  drawer.classList.add('open');
  body.innerHTML = '<p style="color: var(--gray-500);">Loading…</p>';

  try {
    const { event: e, related } = await api('GET', `/audit/${auditId}`);
    const kv = (label, value) => value
      ? `<div style="display:flex; gap:0.5rem; padding:0.2rem 0;"><span style="color:var(--gray-500); min-width:110px;">${label}</span><span style="word-break:break-all;">${escHtml(value)}</span></div>`
      : '';

    const changesHtml = e.changes && Object.keys(e.changes).length ? `
      <h4 style="margin:1rem 0 0.4rem;">Changes</h4>
      <table class="admin-table"><thead><tr><th>Field</th><th>From</th><th>To</th></tr></thead><tbody>
        ${Object.entries(e.changes).map(([field, d]) => `
          <tr><td>${escHtml(field)}</td>
              <td>${escHtml(JSON.stringify(d?.from ?? d))}</td>
              <td>${escHtml(JSON.stringify(d?.to ?? ''))}</td></tr>`).join('')}
      </tbody></table>` : '';

    const relatedHtml = related?.length ? `
      <h4 style="margin:1rem 0 0.4rem;">${related.length} related event${related.length > 1 ? 's' : ''}</h4>
      <div style="max-height:220px; overflow:auto; font-size:0.8rem;">
        ${related.map(r => `<div style="padding:0.25rem 0; border-bottom:1px solid var(--border-color);">
            ${escHtml(r.action)} — ${escHtml(r.target_label || r.target_id || '')}</div>`).join('')}
      </div>` : '';

    body.innerHTML = `
      <h3 style="margin-bottom:0.25rem;">${escHtml(e.action)}</h3>
      <div style="margin-bottom:0.75rem;">
        <span class="badge ${auditBadgeClass(e)}">${escHtml(e.status)}</span>
        <span class="badge badge-gray">${escHtml(e.category)}</span>
        <span class="badge badge-gray">${escHtml(e.source)}</span>
        <span style="color:var(--gray-500); font-size:0.8rem; margin-left:0.4rem;">${new Date(e.occurred_at).toLocaleString()}</span>
      </div>
      <h4 style="margin:0.75rem 0 0.3rem;">Actor</h4>
      ${kv('Email', e.actor_email || (e.actor_type === 'system' ? 'system' : '—'))}
      ${kv('Role', e.actor_role)}${kv('Type', e.actor_type)}${kv('User ID', e.actor_user_id)}
      ${kv('IP', e.ip_address)}${kv('User agent', e.user_agent)}
      <h4 style="margin:0.75rem 0 0.3rem;">Target</h4>
      ${kv('Type', e.target_type)}${kv('Label', e.target_label)}${kv('ID', e.target_id)}
      ${e.target_user_id ? `<div style="padding:0.2rem 0;"><a href="#" onclick="auditFilterByTargetUser('${escHtml(e.target_user_id)}'); return false;">View everything done to this user →</a></div>` : ''}
      ${e.reason ? kv('Reason', e.reason) : ''}
      ${changesHtml}
      <h4 style="margin:1rem 0 0.4rem;">Metadata</h4>
      <pre style="background:var(--bg-code, #f7fafc); padding:0.6rem; border-radius:6px; overflow:auto; font-size:0.75rem; max-height:280px;">${escHtml(JSON.stringify(e.metadata || {}, null, 2))}</pre>
      <h4 style="margin:1rem 0 0.3rem;">Request</h4>
      ${kv('Method', e.http_method)}${kv('Route', e.route)}${kv('Request ID', e.request_id)}
      ${relatedHtml}`;
  } catch (err) {
    body.innerHTML = `<p style="color:#e53e3e;">Error: ${escHtml(err.message)}</p>`;
  }
}

function closeAuditDrawer() {
  document.getElementById('auditDrawer')?.classList.remove('open');
}

function auditFilterByTargetUser(userId) {
  closeAuditDrawer();
  loadAuditLog(0, { target_user_id: userId });
}

// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------

/**
 * Fetched rather than linked: the admin console authenticates with a bearer
 * token from localStorage (admin-core.js:4-5), so a plain <a href> would 401.
 */
async function exportAuditCsv(btn) {
  Utils.setBtnLoading(btn, true, 'Exporting…');
  try {
    const params = auditFilterParams();
    const resp = await fetch(`/api/admin/audit/export.csv?${params}`, { headers: headers() });
    if (!resp.ok) throw new Error(`Export failed (${resp.status})`);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `audit-${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    Toast.success('Exported', 'Audit log downloaded');
  } catch (e) {
    Toast.error('Export failed', e.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

// ---------------------------------------------------------------------------
// Auto-refresh — delegated so it survives innerHTML churn
// ---------------------------------------------------------------------------

document.addEventListener('change', (e) => {
  if (e.target.id === 'auditAutoRefresh') {
    clearInterval(auditRefreshTimer);
    if (e.target.checked) {
      auditRefreshTimer = setInterval(() => loadAuditLog(auditOffset), 30000);
    }
  }
  if (e.target.id === 'auditPageSize') {
    auditPageSize = parseInt(e.target.value, 10) || 50;
    loadAuditLog(0);
  }
});

// The old code never cleared this interval, so enabling auto-refresh left it
// polling forever even after switching tabs.
document.addEventListener('click', (e) => {
  const btn = e.target.closest('.tab-btn');
  if (btn && !btn.getAttribute('onclick')?.includes("'actlog'")) {
    clearInterval(auditRefreshTimer);
    const cb = document.getElementById('auditAutoRefresh');
    if (cb) cb.checked = false;
  }
});
