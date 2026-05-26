// ============================================================================
// CRUCIBLE EVENTS
// ============================================================================

async function apiCrucible(method, path, body = null) {
  const opts = { method, headers: headers() };
  if (body) opts.body = JSON.stringify(body);
  const resp = await fetch(`/api/crucible${path}`, opts);
  const data = await resp.json();
  if (!resp.ok) throw new Error(data.error || `Request failed (${resp.status})`);
  return data;
}

const EVENT_TYPE_LABELS = {
  weekly:    'Weekly Challenges',
  vuln:      'Vulnerable Boxes',
  groupctf:  'Group CTF',
  koth:      'King of the Hill',
  redvsblue: 'Red vs Blue',
  ir:        'IR / SOC Sim',
  ctf_event: 'CTF Events',
  byoctf:    'BYO CTF',
};

const EVENT_TYPE_ICONS = {
  weekly: '📅', vuln: '💀', groupctf: '🏁', koth: '👑',
  redvsblue: '⚔️', ir: '🚨', ctf_event: '🎯', byoctf: '🛠️',
};

let cachedCrucibleEvents = [];
let crucibleEventTypeFilter = '';

async function loadCrucibleEvents() {
  const container = document.getElementById('crucibleEventsList');
  if (!container) return;
  container.innerHTML = '<p style="color:var(--gray-500);">Loading...</p>';

  try {
    const params = crucibleEventTypeFilter ? `?type=${crucibleEventTypeFilter}` : '';
    const events = await apiCrucible('GET', `/events${params}`);
    cachedCrucibleEvents = events.events || [];
    renderCrucibleEvents();
  } catch (e) {
    container.innerHTML = `<p style="color:#ef4444;">Error: ${escHtml(e.message)}</p>`;
  }
}

function renderCrucibleEvents() {
  const container = document.getElementById('crucibleEventsList');
  if (!container) return;

  const events = cachedCrucibleEvents;

  if (events.length === 0) {
    container.innerHTML = '<div style="text-align:center;padding:2rem;color:var(--gray-500);">No events found. Click "+ New Event" to create one.</div>';
    return;
  }

  const statusBadge = s => {
    const map = { active: 'badge-success', draft: 'badge-warning', archived: 'badge-gray' };
    return `<span class="badge ${map[s] || 'badge-gray'}">${escHtml(s)}</span>`;
  };

  const rows = events.map(e => {
    const typeLabel = EVENT_TYPE_LABELS[e.event_type] || e.event_type || '—';
    const typeIcon  = EVENT_TYPE_ICONS[e.event_type] || '🎯';
    const startDate = e.starts_at ? new Date(e.starts_at).toLocaleDateString() : '—';
    const endDate   = e.ends_at   ? new Date(e.ends_at).toLocaleDateString()   : '—';

    return `
      <tr>
        <td><strong>${escHtml(e.name)}</strong></td>
        <td>${typeIcon} ${escHtml(typeLabel)}</td>
        <td>${statusBadge(e.status)}</td>
        <td>${startDate}</td>
        <td>${endDate}</td>
        <td>${e.max_players ?? '∞'}</td>
        <td>${e.is_public ? '✅' : '🔒'}</td>
        <td>
          <div style="display:flex;gap:0.4rem;flex-wrap:wrap;">
            ${e.status !== 'active'   ? `<button class="btn btn-sm btn-outline" onclick="setCrucibleEventStatus('${e.event_id}','active')">Activate</button>` : ''}
            ${e.status === 'active'   ? `<button class="btn btn-sm btn-outline" onclick="setCrucibleEventStatus('${e.event_id}','archived')">Archive</button>` : ''}
            ${e.status === 'archived' ? `<button class="btn btn-sm btn-outline" onclick="setCrucibleEventStatus('${e.event_id}','draft')">Restore</button>` : ''}
            <button class="btn btn-sm btn-outline" onclick="editCrucibleEvent('${e.event_id}')">Edit</button>
            <button class="btn btn-sm btn-danger" onclick="deleteCrucibleEvent('${e.event_id}',${JSON.stringify(e.name)})">Delete</button>
          </div>
        </td>
      </tr>`;
  }).join('');

  container.innerHTML = `
    <table class="admin-table">
      <thead>
        <tr>
          <th>Name</th><th>Type</th><th>Status</th><th>Starts</th><th>Ends</th><th>Max Players</th><th>Public</th><th>Actions</th>
        </tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>`;
}

function filterCrucibleEventsByType(type) {
  crucibleEventTypeFilter = type;
  document.querySelectorAll('.crucible-type-filter').forEach(btn => {
    btn.classList.toggle('active', btn.dataset.type === type);
  });
  loadCrucibleEvents();
}

function showCreateCrucibleEventModal() {
  document.getElementById('crucibleEventId').value = '';
  document.getElementById('crucibleEventName').value = '';
  document.getElementById('crucibleEventType').value = 'weekly';
  document.getElementById('crucibleEventDesc').value = '';
  document.getElementById('crucibleEventStart').value = '';
  document.getElementById('crucibleEventEnd').value = '';
  document.getElementById('crucibleEventMaxPlayers').value = '';
  document.getElementById('crucibleEventPublic').checked = true;
  document.getElementById('crucibleEventModalTitle').textContent = 'New Crucible Event';
  document.getElementById('crucibleEventModal').classList.add('active');
}

function editCrucibleEvent(id) {
  const ev = cachedCrucibleEvents.find(e => e.event_id === id);
  if (!ev) return;

  document.getElementById('crucibleEventId').value = ev.event_id;
  document.getElementById('crucibleEventName').value = ev.name;
  document.getElementById('crucibleEventType').value = ev.event_type || 'weekly';
  document.getElementById('crucibleEventDesc').value = ev.description || '';
  document.getElementById('crucibleEventStart').value = ev.starts_at ? ev.starts_at.slice(0, 16) : '';
  document.getElementById('crucibleEventEnd').value   = ev.ends_at   ? ev.ends_at.slice(0, 16)   : '';
  document.getElementById('crucibleEventMaxPlayers').value = ev.max_players || '';
  document.getElementById('crucibleEventPublic').checked = ev.is_public;
  document.getElementById('crucibleEventModalTitle').textContent = 'Edit Event';
  document.getElementById('crucibleEventModal').classList.add('active');
}

async function saveCrucibleEvent() {
  const id   = document.getElementById('crucibleEventId').value;
  const name = document.getElementById('crucibleEventName').value.trim();
  const type = document.getElementById('crucibleEventType').value;

  if (!name) { alert('Name is required'); return; }

  const payload = {
    name,
    event_type:  type,
    description: document.getElementById('crucibleEventDesc').value.trim() || null,
    starts_at:   document.getElementById('crucibleEventStart').value || null,
    ends_at:     document.getElementById('crucibleEventEnd').value   || null,
    max_players: parseInt(document.getElementById('crucibleEventMaxPlayers').value) || null,
    is_public:   document.getElementById('crucibleEventPublic').checked,
  };

  try {
    if (id) {
      await apiCrucible('PATCH', `/events/${id}`, payload);
    } else {
      await apiCrucible('POST', '/events', payload);
    }
    closeModal('crucibleEventModal');
    loadCrucibleEvents();
  } catch (e) {
    alert('Error saving event: ' + e.message);
  }
}

async function setCrucibleEventStatus(id, status) {
  try {
    await apiCrucible('PATCH', `/events/${id}`, { status });
    loadCrucibleEvents();
  } catch (e) {
    alert('Error updating status: ' + e.message);
  }
}

async function deleteCrucibleEvent(id, name) {
  if (!confirm(`Delete event "${name}"? This cannot be undone.`)) return;
  try {
    await apiCrucible('DELETE', `/events/${id}`);
    loadCrucibleEvents();
  } catch (e) {
    alert('Error deleting event: ' + e.message);
  }
}
