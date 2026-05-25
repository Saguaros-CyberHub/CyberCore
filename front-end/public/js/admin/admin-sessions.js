// ============================================================================
// ACTIVE SESSIONS
// ============================================================================

async function loadActiveSessions() {
  const container = document.getElementById('sessionsTable');
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  try {
    const sessions = await api('GET', '/guac/active');
    const sessionList = Object.values(sessions);
    document.getElementById('activeCount').textContent = sessionList.length;

    if (sessionList.length === 0) {
      container.innerHTML = `
        <div style="text-align: center; padding: 3rem; color: var(--gray-500);">
          <div style="font-size: 2rem; margin-bottom: 0.5rem;">😴</div>
          <p>No active sessions</p>
        </div>`;
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>User</th>
          <th>Connection</th>
          <th>Started</th>
          <th>Remote Host</th>
          <th>Actions</th>
        </tr></thead>
        <tbody>
          ${sessionList.map(s => `
            <tr>
              <td><strong>${escHtml(s.username || 'Unknown')}</strong></td>
              <td>${escHtml(s.connectionIdentifier || '-')}</td>
              <td>${s.startDate ? new Date(s.startDate).toLocaleString() : '-'}</td>
              <td>${escHtml(s.remoteHost || '-')}</td>
              <td>
                <button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="killSession('${s.identifier}', '${escHtml(s.username || '')}')">Kill</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

async function killSession(id, username) {
  if (!confirm(`Kill session for "${username}"?`)) return;
  try {
    await api('DELETE', `/guac/active/${id}`);
    Toast.success('Session Killed', `Disconnected ${username}`);
    loadActiveSessions();
  } catch (e) { Toast.error('Error', e.message); }
}
