// ============================================================================
// CONNECTIONS
// ============================================================================

let cachedGroups = []; // for populating parent group selects

async function loadConnections() {
  const container = document.getElementById('connectionTree');
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  try {
    const tree = await api('GET', '/guac/tree');
    cachedGroups = [];
    collectGroups(tree, 'ROOT');
    container.innerHTML = renderTree(tree);
    updateGroupSelects();

    // Count connections
    const conns = await api('GET', '/guac/connections');
    document.getElementById('connCount').textContent = Object.keys(conns).length;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

function collectGroups(node, parentId) {
  if (node.identifier) {
    cachedGroups.push({ id: node.identifier, name: node.name || node.identifier });
  }
  if (node.childConnectionGroups) {
    node.childConnectionGroups.forEach(g => collectGroups(g, node.identifier));
  }
}

function updateGroupSelects() {
  ['connParentGroup', 'groupParent'].forEach(selId => {
    const sel = document.getElementById(selId);
    if (!sel) return;
    sel.innerHTML = cachedGroups.map(g =>
      `<option value="${g.id}">${g.name}</option>`
    ).join('');
  });
}

function renderTree(node, depth = 0) {
  let html = '';

  // Render child connections
  if (node.childConnections) {
    node.childConnections.forEach(c => {
      const proto = c.protocol || 'unknown';
      html += `
        <div class="tree-item" style="margin-left: ${depth * 1.5}rem;">
          <span class="icon">${proto === 'rdp' ? '🖥️' : proto === 'ssh' ? '💻' : '📺'}</span>
          <span class="name">${escHtml(c.name)}</span>
          <span class="badge proto-${proto}" style="margin-left: 0.5rem;">${proto.toUpperCase()}</span>
          <span class="meta" style="margin-left: auto;">
            ${c.activeConnections > 0 ? `<span class="badge badge-green">${c.activeConnections} active</span>` : ''}
          </span>
          <button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="deleteConnection('${c.identifier}', '${escHtml(c.name)}')">Delete</button>
        </div>`;
    });
  }

  // Render child groups recursively
  if (node.childConnectionGroups) {
    node.childConnectionGroups.forEach(g => {
      const connCount = (g.childConnections || []).length;
      const groupCount = (g.childConnectionGroups || []).length;
      html += `
        <div class="tree-item" style="margin-left: ${depth * 1.5}rem; font-weight: 600;">
          <span class="icon">📁</span>
          <span class="name">${escHtml(g.name)}</span>
          <span class="meta" style="margin-left: 0.5rem;">${connCount} conn, ${groupCount} groups</span>
          <button class="btn btn-sm" style="font-size: 0.75rem; padding: 0.2rem 0.5rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent; margin-left: auto;" onclick="deleteGroup('${g.identifier}', '${escHtml(g.name)}')">Delete</button>
        </div>`;
      html += renderTree(g, depth + 1);
    });
  }

  return html || '<p style="color: var(--gray-500); padding: 1rem;">No connections found.</p>';
}

async function deleteConnection(id, name) {
  if (!confirm(`Delete connection "${name}"?`)) return;
  try {
    await api('DELETE', `/guac/connections/${id}`);
    Toast.success('Deleted', `Connection "${name}" removed`);
    loadConnections();
  } catch (e) { Toast.error('Error', e.message); }
}

async function deleteGroup(id, name) {
  if (!confirm(`Delete group "${name}" and all its connections?`)) return;
  try {
    await api('DELETE', `/guac/groups/${id}`);
    Toast.success('Deleted', `Group "${name}" removed`);
    loadConnections();
  } catch (e) { Toast.error('Error', e.message); }
}

function showCreateConnectionModal() {
  updateGroupSelects();
  // Set default port based on protocol
  document.getElementById('connProtocol').onchange = function() {
    const portMap = { rdp: '3389', ssh: '22', vnc: '5900' };
    document.getElementById('connPort').value = portMap[this.value] || '';
  };
  document.getElementById('connPort').value = '3389';
  document.getElementById('createConnModal').classList.add('active');
}

function showCreateGroupModal() {
  updateGroupSelects();
  document.getElementById('createGroupModal').classList.add('active');
}

async function createConnection() {
  const name = document.getElementById('connName').value.trim();
  const protocol = document.getElementById('connProtocol').value;
  const hostname = document.getElementById('connHostname').value.trim();
  const port = document.getElementById('connPort').value.trim();
  const parentIdentifier = document.getElementById('connParentGroup').value;
  const username = document.getElementById('connUsername').value.trim();
  const password = document.getElementById('connPassword').value;

  if (!name || !hostname) {
    Toast.warning('Missing Fields', 'Name and hostname are required');
    return;
  }

  const parameters = { hostname, port: port || undefined };
  if (username) parameters.username = username;
  if (password) parameters.password = password;

  // RDP-specific defaults
  if (protocol === 'rdp') {
    parameters['security'] = 'any';
    parameters['ignore-cert'] = 'true';
  }

  try {
    await api('POST', '/guac/connections', { name, protocol, parentIdentifier, parameters });
    Toast.success('Created', `Connection "${name}" created`);
    closeModal('createConnModal');
    loadConnections();
  } catch (e) { Toast.error('Error', e.message); }
}

async function createGroup() {
  const name = document.getElementById('groupName').value.trim();
  const type = document.getElementById('groupType').value;
  const parentIdentifier = document.getElementById('groupParent').value;

  if (!name) { Toast.warning('Missing', 'Group name is required'); return; }

  try {
    await api('POST', '/guac/groups', { name, type, parentIdentifier });
    Toast.success('Created', `Group "${name}" created`);
    closeModal('createGroupModal');
    loadConnections();
  } catch (e) { Toast.error('Error', e.message); }
}
