// ============================================================================
// ACTIVITY LOG
// ============================================================================

let actlogOffset = 0;
let actlogAutoRefreshTimer = null;

async function loadActivityLog(offset = 0) {
  actlogOffset = offset;
  const container = document.getElementById('actlogTable');
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  const search = document.getElementById('actlogSearch')?.value || '';
  const action_type = document.getElementById('actlogAction')?.value || '';

  try {
    const params = new URLSearchParams({ limit: 50, offset });
    if (search) params.set('search', search);
    if (action_type) params.set('action_type', action_type);

    const data = await api('GET', `/activity-log?${params}`);

    if (data.logs.length === 0) {
      container.innerHTML = '<div style="background: white; border-radius: 12px; padding: 2rem; text-align: center; box-shadow: 0 2px 8px rgba(0,0,0,0.08); color: var(--gray-500);">No activity found.</div>';
      document.getElementById('actlogPagination').innerHTML = '';
      return;
    }

    const actionColors = {
      login: 'badge-green', logout: 'badge-gray', register: 'badge-blue',
      deploy_lane: 'badge-blue', deploy_group: 'badge-blue',
      delete_lane: 'badge-red', delete_group: 'badge-red',
      toggle_accounts: 'badge-yellow', submission: 'badge-green',
      review: 'badge-green', profile_generation: 'badge-blue'
    };

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>Time</th>
          <th>User</th>
          <th>Action</th>
          <th>Entity</th>
          <th>IP</th>
          <th>Details</th>
        </tr></thead>
        <tbody>
          ${data.logs.map(l => `
            <tr>
              <td style="font-size: 0.8rem; white-space: nowrap;">${new Date(l.created_at).toLocaleString()}</td>
              <td><code style="font-size: 0.75rem;">${escHtml(l.email || 'system')}</code></td>
              <td><span class="badge ${actionColors[l.action_type] || 'badge-gray'}">${escHtml(l.action_type)}</span></td>
              <td style="font-size: 0.8rem;">${escHtml(l.entity_type || '')} ${l.entity_id ? `<code style="font-size: 0.7rem;">${l.entity_id.substring(0, 8)}...</code>` : ''}</td>
              <td style="font-size: 0.8rem;">${escHtml(l.ip_address || '—')}</td>
              <td style="font-size: 0.75rem; max-width: 200px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="${escHtml(JSON.stringify(l.metadata || ''))}">${l.metadata ? escHtml(JSON.stringify(l.metadata)).substring(0, 60) : '—'}</td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;

    // Pagination
    const pag = document.getElementById('actlogPagination');
    const totalPages = Math.ceil(data.total / 50);
    const currentPage = Math.floor(offset / 50) + 1;
    let pagHtml = `<span style="font-size: 0.8rem; color: var(--gray-500);">${data.total} total</span>`;
    if (currentPage > 1) pagHtml += `<button class="btn btn-sm btn-outline" onclick="loadActivityLog(${offset - 50})">Prev</button>`;
    pagHtml += `<span style="font-size: 0.8rem;">Page ${currentPage}/${totalPages}</span>`;
    if (currentPage < totalPages) pagHtml += `<button class="btn btn-sm btn-outline" onclick="loadActivityLog(${offset + 50})">Next</button>`;
    pag.innerHTML = pagHtml;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

// Auto-refresh toggle
document.addEventListener('change', (e) => {
  if (e.target.id === 'actlogAutoRefresh') {
    if (e.target.checked) {
      actlogAutoRefreshTimer = setInterval(() => loadActivityLog(actlogOffset), 30000);
    } else {
      clearInterval(actlogAutoRefreshTimer);
    }
  }
});
