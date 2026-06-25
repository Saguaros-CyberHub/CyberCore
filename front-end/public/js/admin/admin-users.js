// ============================================================================
// USERS
// ============================================================================

async function loadMergedUsers() {
  const container = document.getElementById('mergedUsersTable');
  const groupContainer = document.getElementById('groupControlsList');
  container.innerHTML = '<p style="color: var(--gray-500);">Loading users...</p>';

  try {
    // Fetch clinic users, Guac users, and groups in parallel
    const [clinicUsers, guacUsersRaw, groups] = await Promise.all([
      api('GET', '/users'),
      api('GET', '/guac/users').catch(() => ({})),
      api('GET', '/groups')
    ]);

    const guacUsers = Object.values(guacUsersRaw);
    const guacMap = {};
    guacUsers.forEach(u => { guacMap[u.username] = u; });

    // Update stat counts
    document.getElementById('userCount').textContent = guacUsers.length;

    // ── Group Controls ──
    if (groups.length > 0) {
      groupContainer.innerHTML = `
        <h3 style="margin: 0 0 0.75rem;">Group Controls</h3>
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 1rem;">
          ${await Promise.all(groups.map(async g => {
            const cfg = typeof g.config === 'string' ? JSON.parse(g.config) : g.config;
            const numStudents = (cfg.students || []).length;
            let scheduleHtml = '';
            try {
              const sched = await api('GET', `/groups/${g.id}/schedule`);
              if (sched.schedule !== null && sched.active_days) {
                const dayNames = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];
                const days = sched.active_days.map(d => dayNames[d]).join(', ');
                const overrideLabel = sched.override_active === true ? '<span class="badge badge-green">Override: ON</span>' :
                                      sched.override_active === false ? '<span class="badge badge-red">Override: OFF</span>' :
                                      '<span class="badge badge-gray">Using Schedule</span>';
                scheduleHtml = `
                  <div style="font-size: 0.8rem; margin-top: 0.5rem; padding: 0.5rem; background: var(--gray-50); border-radius: 6px;">
                    <strong>Schedule:</strong> ${days} ${sched.active_start}–${sched.active_end} (${sched.timezone}) ${overrideLabel}
                  </div>`;
              } else {
                scheduleHtml = `<div style="font-size: 0.8rem; margin-top: 0.5rem; color: var(--gray-500);">No schedule set</div>`;
              }
            } catch (e) { scheduleHtml = ''; }

            return `
            <div style="background: var(--bg-card, white); border-radius: 10px; padding: 1rem; box-shadow: 0 2px 8px rgba(0,0,0,0.08);">
              <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
                <strong>${escHtml(g.group_name)}</strong>
                <span class="badge badge-gray">${numStudents} students</span>
              </div>
              <div style="display: flex; gap: 0.4rem; flex-wrap: wrap;">
                <button class="btn btn-sm btn-outline" style="font-size: 0.75rem;" onclick="toggleGroupActive('${g.id}', true)">Enable All</button>
                <button class="btn btn-sm" style="font-size: 0.75rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="toggleGroupActive('${g.id}', false)">Disable All</button>
                <button class="btn btn-sm btn-outline" style="font-size: 0.75rem;" onclick="showScheduleModal('${g.id}', '${escHtml(g.group_name)}')">Set Schedule</button>
                <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; color: #38a169; border-color: #38a169;" onclick="overrideSchedule('${g.id}', true)">Override: ON</button>
                <button class="btn btn-sm btn-outline" style="font-size: 0.75rem; color: #e53e3e; border-color: #e53e3e;" onclick="overrideSchedule('${g.id}', false)">Override: OFF</button>
                <button class="btn btn-sm btn-outline" style="font-size: 0.75rem;" onclick="overrideSchedule('${g.id}', null)">Clear Override</button>
              </div>
              ${scheduleHtml}
            </div>`;
          })).then(cards => cards.join(''))}
        </div>`;
    } else {
      groupContainer.innerHTML = '';
    }

    // ── Merged Users Table ──
    // Build rows from clinic users, enriched with Guac status
    const clinicRows = clinicUsers.map(u => {
      const guac = guacMap[u.email];
      return { ...u, guac_exists: !!guac, guac_disabled: guac?.attributes?.disabled === 'true', guac_last_active: guac?.lastActive };
    });

    // Find Guac-only users (not in clinic DB — e.g., cactus-admin)
    const clinicEmails = new Set(clinicUsers.map(u => u.email));
    const guacOnlyRows = guacUsers
      .filter(u => !clinicEmails.has(u.username))
      .map(u => ({
        email: u.username, first_name: '', last_name: '', role: 'guac-only',
        group_name: null, is_active: !u.attributes?.disabled, last_login: u.lastActive,
        guac_exists: true, guac_disabled: u.attributes?.disabled === 'true', guac_last_active: u.lastActive,
        is_guac_only: true
      }));

    const allRows = [...clinicRows, ...guacOnlyRows];

    if (allRows.length === 0) {
      container.innerHTML = '<p style="color: var(--gray-500);">No users found.</p>';
      return;
    }

    container.innerHTML = `
      <h3 style="margin: 1.5rem 0 0.75rem;">All Users (${clinicRows.length} clinic, ${guacUsers.length} Guacamole)</h3>
      <table class="admin-table">
        <thead><tr>
          <th>Email / Username</th>
          <th>Name</th>
          <th>Role</th>
          <th>Group</th>
          <th>Clinic Status</th>
          <th>Guac Status</th>
          <th>Last Login</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>
          ${allRows.map(u => {
            const isProtected = u.email === 'cactus-admin' || u.email === 'guacadmin';
            return `
            <tr>
              <td><code style="font-size: 0.8rem;">${escHtml(u.email)}</code></td>
              <td>${escHtml(((u.first_name || '') + ' ' + (u.last_name || '')).trim() || '—')}</td>
              <td><span class="badge ${u.role === 'admin' ? 'badge-red' : u.role === 'instructor' ? 'badge-blue' : u.role === 'guac-only' ? 'badge-yellow' : 'badge-gray'}">${u.role}</span></td>
              <td style="font-size: 0.8rem;">${u.group_name ? escHtml(u.group_name) : '<span style="color: var(--gray-400);">—</span>'}</td>
              <td>${u.is_guac_only ? '<span style="color: var(--gray-400);">—</span>' : (u.is_active ? '<span class="badge badge-green">Active</span>' : '<span class="badge badge-red">Disabled</span>')}</td>
              <td>${u.guac_exists ? (u.guac_disabled ? '<span class="badge badge-red">Disabled</span>' : '<span class="badge badge-green">Active</span>') : '<span style="color: var(--gray-400);">No account</span>'}</td>
              <td style="font-size: 0.8rem;">${u.last_login ? new Date(u.last_login).toLocaleString() : (u.guac_last_active ? new Date(u.guac_last_active).toLocaleString() : '<span style="color: var(--gray-400);">Never</span>')}</td>
              <td style="display: flex; gap: 0.3rem; flex-wrap: wrap;">
                ${u.guac_exists ? `<button class="btn btn-sm btn-outline" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;" onclick="viewPermissions('${escHtml(u.email)}')">Perms</button>` : ''}
                ${u.guac_exists ? `<button class="btn btn-sm btn-outline" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;" onclick="resetPassword('${escHtml(u.email)}')">Reset PW</button>` : ''}
                ${u.guac_exists && !isProtected ? `<button class="btn btn-sm" style="font-size: 0.7rem; padding: 0.15rem 0.4rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="deleteUser('${escHtml(u.email)}')">Delete Guac</button>` : ''}
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

// Keep old name as alias for any remaining references
async function loadUsers() { await loadMergedUsers(); }

function showCreateUserModal() {
  document.getElementById('newUsername').value = '';
  document.getElementById('newPassword').value = '';
  document.getElementById('createUserModal').classList.add('active');
}

async function createUser() {
  const username = document.getElementById('newUsername').value.trim();
  const password = document.getElementById('newPassword').value;
  if (!username || !password) { Toast.warning('Missing', 'Username and password required'); return; }

  try {
    await api('POST', '/guac/users', { username, password });
    Toast.success('Created', `User "${username}" created`);
    closeModal('createUserModal');
    loadUsers();
  } catch (e) { Toast.error('Error', e.message); }
}

function showCreateCybercoreUserModal() {
  document.getElementById('ccUsername').value = '';
  document.getElementById('ccEmail').value = '';
  document.getElementById('ccFirstName').value = '';
  document.getElementById('ccLastName').value = '';
  document.getElementById('ccOrganization').value = 'Independent';
  document.getElementById('ccRole').value = 'user';
  document.getElementById('ccPassword').value = '';
  document.getElementById('ccStatus').innerHTML = '';
  document.getElementById('createCybercoreUserModal').classList.add('active');
}

async function createCybercoreUser() {
  const username = document.getElementById('ccUsername').value.trim();
  const email = document.getElementById('ccEmail').value.trim();
  const firstName = document.getElementById('ccFirstName').value.trim();
  const lastName = document.getElementById('ccLastName').value.trim();
  const organization = document.getElementById('ccOrganization').value.trim() || 'Independent';
  const role = document.getElementById('ccRole').value;
  const password = document.getElementById('ccPassword').value;

  const statusEl = document.getElementById('ccStatus');

  if (!username || !email || !password) {
    statusEl.innerHTML = '<p style="color: #e53e3e; margin-top: 0.5rem;">Username, email, and password are required</p>';
    return;
  }

  statusEl.innerHTML = '<p style="color: var(--gray-500); margin-top: 0.5rem;">Creating user...</p>';

  try {
    const userData = {
      username,
      email,
      firstName: firstName || null,
      lastName: lastName || null,
      organization,
      role,
      password
    };

    const result = await api('POST', '/users', userData);
    Toast.success('User Created', `"${username}" (${email}) added to system`);
    closeModal('createCybercoreUserModal');
    loadMergedUsers();
  } catch (e) {
    statusEl.innerHTML = `<p style="color: #e53e3e; margin-top: 0.5rem;">Error: ${e.message}</p>`;
    Toast.error('Error', e.message);
  }
}

// ============================================================================
// BATCH USER CREATION
// ============================================================================

function showBatchUsersModal() {
  document.getElementById('batchRole').value = 'student';
  document.getElementById('batchOrganization').value = 'Independent';
  document.getElementById('batchRoster').value = '';
  document.getElementById('batchStatus').innerHTML = '';
  document.getElementById('batchResults').innerHTML = '';
  document.getElementById('batchUsersModal').classList.add('active');
}

// Parse the pasted roster into user rows. Each line is comma- or tab-separated:
//   email, first name, last name, password
// Only email is required; a header row (first cell === "email") is skipped.
function parseRoster(text) {
  const rows = [];
  const lines = text.split(/\r?\n/);
  lines.forEach((raw, idx) => {
    const line = raw.trim();
    if (!line) return;
    const cells = (line.includes('\t') ? line.split('\t') : line.split(',')).map(c => c.trim());
    // Skip a header row like "email, first, last, password"
    if (idx === 0 && cells[0] && cells[0].toLowerCase() === 'email') return;
    rows.push({
      line: idx + 1,
      email: cells[0] || '',
      firstName: cells[1] || null,
      lastName: cells[2] || null,
      password: cells[3] || null,
    });
  });
  return rows;
}

async function createBatchUsers() {
  const statusEl = document.getElementById('batchStatus');
  const resultsEl = document.getElementById('batchResults');
  const btn = document.getElementById('batchCreateBtn');

  const role = document.getElementById('batchRole').value;
  const organization = document.getElementById('batchOrganization').value.trim() || 'Independent';
  const users = parseRoster(document.getElementById('batchRoster').value);

  if (users.length === 0) {
    statusEl.innerHTML = '<p style="color: #e53e3e; margin-top: 0.5rem;">Paste at least one user (email required).</p>';
    return;
  }

  statusEl.innerHTML = `<p style="color: var(--gray-500); margin-top: 0.5rem;">Creating ${users.length} user(s)…</p>`;
  resultsEl.innerHTML = '';
  btn.disabled = true;
  btn.textContent = 'Creating…';

  try {
    const data = await api('POST', '/users/batch', { users, defaults: { role, organization } });
    statusEl.innerHTML = '';
    renderBatchResults(data);
    const { created, failed } = data.summary;
    if (failed === 0) Toast.success('Batch Complete', `${created} user(s) created`);
    else Toast.warning('Batch Complete', `${created} created, ${failed} failed`);
    loadMergedUsers();
  } catch (e) {
    statusEl.innerHTML = `<p style="color: #e53e3e; margin-top: 0.5rem;">Error: ${e.message}</p>`;
    Toast.error('Error', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Users';
  }
}

function renderBatchResults(data) {
  const { summary, created, failed } = data;
  const resultsEl = document.getElementById('batchResults');
  let html = `<h4 style="margin: 0.5rem 0;">Results: ${summary.created} created, ${summary.failed} failed (of ${summary.total})</h4>`;

  if (created.length) {
    html += `
      <div style="display: flex; align-items: center; gap: 0.5rem; margin: 0.5rem 0;">
        <strong style="font-size: 0.85rem;">Created accounts</strong>
        <button class="btn btn-sm btn-outline" style="font-size: 0.7rem;" onclick="copyBatchCredentials()">Copy credentials</button>
        <span style="font-size: 0.75rem; color: var(--gray-500);">Generated passwords are shown once — copy them now.</span>
      </div>
      <table class="admin-table" style="font-size: 0.82rem;">
        <thead><tr><th>Email</th><th>Username</th><th>Role</th><th>Password</th></tr></thead>
        <tbody>
          ${created.map(u => `
            <tr>
              <td><code style="font-size: 0.78rem;">${escHtml(u.email)}</code></td>
              <td><code style="font-size: 0.78rem;">${escHtml(u.username)}</code></td>
              <td><span class="badge badge-gray">${escHtml(u.role)}</span></td>
              <td>${u.generated_password
                ? `<code style="font-size: 0.78rem;">${escHtml(u.generated_password)}</code>`
                : '<span style="color: var(--gray-400);">set by you</span>'}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  if (failed.length) {
    html += `
      <strong style="font-size: 0.85rem; display: block; margin: 0.75rem 0 0.4rem; color: #e53e3e;">Skipped rows</strong>
      <table class="admin-table" style="font-size: 0.82rem;">
        <thead><tr><th>Line</th><th>Email</th><th>Reason</th></tr></thead>
        <tbody>
          ${failed.map(f => `
            <tr>
              <td>${f.line}</td>
              <td><code style="font-size: 0.78rem;">${escHtml(f.email)}</code></td>
              <td style="color: #e53e3e;">${escHtml(f.error)}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  }

  // Stash created credentials for the copy button.
  window._batchCreated = created;
  resultsEl.innerHTML = html;
}

function copyBatchCredentials() {
  const created = window._batchCreated || [];
  if (!created.length) return;
  const lines = ['email,username,password'];
  created.forEach(u => lines.push(`${u.email},${u.username},${u.generated_password || ''}`));
  navigator.clipboard.writeText(lines.join('\n'))
    .then(() => Toast.success('Copied', `${created.length} credential(s) copied as CSV`))
    .catch(() => Toast.error('Error', 'Could not copy to clipboard'));
}

async function deleteUser(username) {
  if (!await Confirm.show({ title: 'Delete User', message: `Delete Guacamole user "${username}"?`, confirmText: 'Delete', danger: true })) return;
  try {
    await api('DELETE', `/guac/users/${encodeURIComponent(username)}`);
    Toast.success('Deleted', `User "${username}" removed`);
    loadUsers();
  } catch (e) { Toast.error('Error', e.message); }
}

async function resetPassword(username) {
  const newPw = prompt(`Enter new password for "${username}":`);
  if (!newPw) return;
  try {
    await api('PUT', `/guac/users/${encodeURIComponent(username)}/password`, { password: newPw });
    Toast.success('Password Reset', `Password updated for "${username}"`);
  } catch (e) { Toast.error('Error', e.message); }
}

async function viewPermissions(username) {
  document.getElementById('permUsername').textContent = username;
  const body = document.getElementById('permissionsBody');
  body.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';
  document.getElementById('permissionsModal').classList.add('active');

  try {
    const perms = await api('GET', `/guac/users/${encodeURIComponent(username)}/permissions`);

    let html = '';

    // System permissions
    const sysPerms = Object.keys(perms.systemPermissions || {});
    if (sysPerms.length) {
      html += `<h4 style="margin: 0.5rem 0;">System Permissions</h4>`;
      html += sysPerms.map(p => `<span class="badge badge-blue" style="margin: 0.2rem;">${p}</span>`).join(' ');
    }

    // Connection permissions
    const connPerms = perms.connectionPermissions || {};
    const connIds = Object.keys(connPerms);
    if (connIds.length) {
      html += `<h4 style="margin: 1rem 0 0.5rem;">Connection Permissions (${connIds.length})</h4>`;
      html += `<table class="admin-table" style="font-size: 0.85rem;">
        <thead><tr><th>Connection ID</th><th>Permissions</th></tr></thead>
        <tbody>${connIds.map(id =>
          `<tr><td>${id}</td><td>${connPerms[id].map(p => `<span class="badge badge-gray">${p}</span>`).join(' ')}</td></tr>`
        ).join('')}</tbody></table>`;
    }

    // Connection group permissions
    const groupPerms = perms.connectionGroupPermissions || {};
    const groupIds = Object.keys(groupPerms);
    if (groupIds.length) {
      html += `<h4 style="margin: 1rem 0 0.5rem;">Group Permissions (${groupIds.length})</h4>`;
      html += `<table class="admin-table" style="font-size: 0.85rem;">
        <thead><tr><th>Group ID</th><th>Permissions</th></tr></thead>
        <tbody>${groupIds.map(id =>
          `<tr><td>${id}</td><td>${groupPerms[id].map(p => `<span class="badge badge-gray">${p}</span>`).join(' ')}</td></tr>`
        ).join('')}</tbody></table>`;
    }

    if (!html) html = '<p style="color: var(--gray-500);">No permissions assigned.</p>';
    body.innerHTML = html;
  } catch (e) {
    body.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

// ============================================================================
// USER MANAGEMENT & SCHEDULES
// ============================================================================

// loadClinicUsers merged into loadMergedUsers above
async function loadClinicUsers() { await loadMergedUsers(); }

async function toggleGroupActive(groupId, active) {
  const action = active ? 'enable' : 'disable';
  if (!await Confirm.show({ title: `${active ? 'Enable' : 'Disable'} Group Accounts`, message: `${active ? 'Enable' : 'Disable'} all student accounts in this group?`, confirmText: active ? 'Enable All' : 'Disable All', danger: !active })) return;
  try {
    const data = await api('PATCH', `/groups/${groupId}/toggle-active`, { active });
    Toast.success('Updated', `${data.students_updated} students ${action}d`);
    loadMergedUsers();
  } catch (e) { Toast.error('Error', e.message); }
}

async function overrideSchedule(groupId, value) {
  try {
    await api('PATCH', `/groups/${groupId}/schedule/override`, { override_active: value });
    const label = value === true ? 'Override ON (access forced)' : value === false ? 'Override OFF (access blocked)' : 'Override cleared (using schedule)';
    Toast.success('Schedule Override', label);
    loadMergedUsers();
  } catch (e) { Toast.error('Error', e.message); }
}

function showScheduleModal(groupId, groupName) {
  // Reuse permissions modal for schedule form
  const body = document.getElementById('permissionsBody');
  document.getElementById('permUsername').textContent = `Schedule — ${groupName}`;

  body.innerHTML = `
    <div class="form-group">
      <label>Active Days</label>
      <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
        ${['Sun','Mon','Tue','Wed','Thu','Fri','Sat'].map((d, i) => `
          <label style="display: flex; align-items: center; gap: 0.25rem; font-size: 0.85rem;">
            <input type="checkbox" class="sched-day" value="${i}" ${[1,2,3,4,5].includes(i) ? 'checked' : ''} style="width: auto;">
            ${d}
          </label>
        `).join('')}
      </div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
      <div class="form-group">
        <label>Start Time</label>
        <input type="time" id="schedStart" value="08:00">
      </div>
      <div class="form-group">
        <label>End Time</label>
        <input type="time" id="schedEnd" value="17:00">
      </div>
    </div>
    <div class="form-group">
      <label>Timezone</label>
      <select id="schedTimezone">
        <option value="America/Chicago">Central (America/Chicago)</option>
        <option value="America/New_York">Eastern (America/New_York)</option>
        <option value="America/Denver">Mountain (America/Denver)</option>
        <option value="America/Los_Angeles">Pacific (America/Los_Angeles)</option>
        <option value="America/Phoenix">Arizona (America/Phoenix)</option>
      </select>
    </div>
    <button class="btn btn-primary" onclick="saveSchedule('${groupId}')" style="width: 100%;">Save Schedule</button>
  `;

  // Load existing schedule
  api('GET', `/groups/${groupId}/schedule`).then(sched => {
    if (sched.active_days) {
      document.querySelectorAll('.sched-day').forEach(cb => {
        cb.checked = sched.active_days.includes(parseInt(cb.value));
      });
      document.getElementById('schedStart').value = sched.active_start || '08:00';
      document.getElementById('schedEnd').value = sched.active_end || '17:00';
      if (sched.timezone) document.getElementById('schedTimezone').value = sched.timezone;
    }
  }).catch(() => {});

  document.getElementById('permissionsModal').classList.add('active');
}

async function saveSchedule(groupId) {
  const active_days = Array.from(document.querySelectorAll('.sched-day:checked')).map(cb => parseInt(cb.value));
  const active_start = document.getElementById('schedStart').value;
  const active_end = document.getElementById('schedEnd').value;
  const timezone = document.getElementById('schedTimezone').value;

  if (active_days.length === 0) { Toast.warning('Missing', 'Select at least one day'); return; }

  try {
    await api('PUT', `/groups/${groupId}/schedule`, { active_days, active_start, active_end, timezone });
    Toast.success('Schedule Saved', `${active_start}–${active_end}`);
    closeModal('permissionsModal');
    loadMergedUsers();
  } catch (e) { Toast.error('Error', e.message); }
}
