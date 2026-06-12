// ============================================================================
// VULN SCRIPTS
// ============================================================================

// cachedVulnScripts is declared in admin-lanes.js (shared global)
let scriptTypeFilterValue = '';

function setScriptTypeFilter(type) {
  scriptTypeFilterValue = type || '';
  // Flip the active-button styling
  document.querySelectorAll('#scriptTypeFilter .stf-btn').forEach(b => {
    const active = (b.dataset.type || '') === scriptTypeFilterValue;
    b.classList.toggle('active', active);
    if (active) {
      b.style.background = scriptTypeFilterValue === 'baseline' ? '#16a34a'
                         : scriptTypeFilterValue === 'vulnerable' ? '#dc2626'
                         : (getComputedStyle(document.documentElement).getPropertyValue('--primary') || '#0c234b');
      b.style.color = '#fff';
    } else {
      b.style.background = 'var(--bg-card, #fff)';
      b.style.color = (b.dataset.type === 'baseline') ? 'var(--success, #166534)'
                    : (b.dataset.type === 'vulnerable') ? 'var(--danger, #991b1b)'
                    : 'var(--gray-700, #2d3748)';
    }
  });
  loadVulnScripts();
}

function renderScriptTypeBadge(type) {
  const t = (type || 'vulnerable').toLowerCase();
  if (t === 'baseline') {
    return `<span title="Baseline — enables a service cleanly, no vulnerabilities baked in" style="display:inline-flex;align-items:center;gap:3px;font-size:0.7rem;font-weight:600;padding:2px 7px;border-radius:10px;background:#dcfce7;color:#166534;border:1px solid #16a34a;">🛡️ Baseline</span>`;
  }
  return `<span title="Vulnerable — deliberately introduces weaknesses" style="display:inline-flex;align-items:center;gap:3px;font-size:0.7rem;font-weight:600;padding:2px 7px;border-radius:10px;background:#fee2e2;color:#991b1b;border:1px solid #dc2626;">☠️ Vulnerable</span>`;
}

async function loadVulnScripts() {
  const container = document.getElementById('vulnScriptsList');
  const catFilter = document.getElementById('vulnScriptCategoryFilter')?.value || '';
  const typeFilter = scriptTypeFilterValue;
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  try {
    const qs = new URLSearchParams();
    if (catFilter)  qs.set('category', catFilter);
    if (typeFilter) qs.set('script_type', typeFilter);
    const params = qs.toString() ? `?${qs.toString()}` : '';
    const scripts = await api('GET', `/vuln-scripts${params}`);
    cachedVulnScripts = scripts;

    // Populate category filter
    const categories = [...new Set(scripts.map(s => s.category))].sort();
    const catSel = document.getElementById('vulnScriptCategoryFilter');
    const currentVal = catSel.value;
    catSel.innerHTML = '<option value="">All Categories</option>' +
      categories.map(c => `<option value="${c}" ${c === currentVal ? 'selected' : ''}>${c}</option>`).join('');

    // Summary line
    const baseCount = scripts.filter(s => (s.script_type || 'vulnerable') === 'baseline').length;
    const vulnCount = scripts.length - baseCount;
    const summaryEl = document.getElementById('scriptListSummary');
    if (summaryEl) {
      summaryEl.innerHTML = `${scripts.length} total · <span style="color:#166534;font-weight:600;">${baseCount} baseline</span> · <span style="color:#991b1b;font-weight:600;">${vulnCount} vulnerable</span>`;
    }

    if (scripts.length === 0) {
      const msg = typeFilter
        ? `No <strong>${typeFilter}</strong> scripts${catFilter ? ` in category "${escHtml(catFilter)}"` : ''}.`
        : 'No scripts found. Click "+ New Script" to create one.';
      container.innerHTML = `<div style="text-align: center; padding: 2rem; color: var(--gray-500);">${msg}</div>`;
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr><th>Slug</th><th>Name</th><th>Type</th><th>Category</th><th>OS</th><th>Difficulty</th><th>Services</th><th>Deps</th><th>Actions</th></tr></thead>
        <tbody>
          ${scripts.map(s => {
            const isBaseline = (s.script_type || 'vulnerable') === 'baseline';
            const rowTint = isBaseline
              ? 'border-left: 3px solid #16a34a;'
              : 'border-left: 3px solid #dc2626;';
            return `
            <tr style="${rowTint}">
              <td><code style="font-size: 0.75rem;">${escHtml(s.slug)}</code></td>
              <td><strong>${escHtml(s.name)}</strong><br><span style="font-size: 0.75rem; color: var(--gray-500);">${escHtml((s.description || '').substring(0, 80))}</span></td>
              <td>${renderScriptTypeBadge(s.script_type)}</td>
              <td><span class="badge badge-blue" style="font-size: 0.7rem;">${escHtml(s.category)}</span></td>
              <td style="font-size: 0.8rem;">${s.os_target}</td>
              <td style="font-size: 0.8rem;">${s.difficulty}</td>
              <td style="font-size: 0.75rem;">${(s.services_exposed || []).join(', ') || '—'}</td>
              <td style="font-size: 0.75rem;">${(s.depends_on || []).join(', ') || '—'}</td>
              <td style="display: flex; gap: 0.3rem;">
                <button class="btn btn-sm btn-outline" style="font-size: 0.7rem; padding: 0.15rem 0.4rem;" onclick="editVulnScript('${s.id}')">Edit</button>
                <button class="btn btn-sm" style="font-size: 0.7rem; padding: 0.15rem 0.4rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="deleteVulnScript('${s.id}', '${escHtml(s.name)}')">Delete</button>
              </td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

function showCreateScriptModal() {
  document.getElementById('scriptEditorTitle').textContent = 'New Script';
  document.getElementById('scriptEditId').value = '';
  ['scriptSlug','scriptName','scriptDesc','scriptServices','scriptDependsOn','scriptContent','scriptArgs'].forEach(id => document.getElementById(id).value = '');
  document.getElementById('scriptCategory').value = 'Network Services';
  document.getElementById('scriptOS').value = 'windows';
  document.getElementById('scriptDifficulty').value = 'intermediate';
  document.getElementById('scriptTypeVulnerable').checked = true;
  document.getElementById('scriptEditorModal').classList.add('active');
}

async function editVulnScript(id) {
  try {
    const script = await api('GET', `/vuln-scripts/${id}`);
    document.getElementById('scriptEditorTitle').textContent = `Edit: ${script.name}`;
    document.getElementById('scriptEditId').value = id;
    document.getElementById('scriptSlug').value = script.slug;
    document.getElementById('scriptName').value = script.name;
    document.getElementById('scriptDesc').value = script.description || '';
    document.getElementById('scriptCategory').value = script.category;
    document.getElementById('scriptOS').value = script.os_target;
    document.getElementById('scriptDifficulty').value = script.difficulty;
    const type = (script.script_type || 'vulnerable').toLowerCase();
    document.getElementById(type === 'baseline' ? 'scriptTypeBaseline' : 'scriptTypeVulnerable').checked = true;
    document.getElementById('scriptServices').value = (script.services_exposed || []).join(', ');
    document.getElementById('scriptDependsOn').value = (script.depends_on || []).join(', ');
    document.getElementById('scriptContent').value = script.script_content || '';
    document.getElementById('scriptArgs').value = script.script_args || '';
    document.getElementById('scriptEditorModal').classList.add('active');
  } catch (e) { Toast.error('Error', e.message); }
}

async function saveVulnScript() {
  const editId = document.getElementById('scriptEditId').value;
  const scriptTypeEl = document.querySelector('input[name=scriptType]:checked');
  const body = {
    slug: document.getElementById('scriptSlug').value.trim(),
    name: document.getElementById('scriptName').value.trim(),
    description: document.getElementById('scriptDesc').value.trim(),
    category: document.getElementById('scriptCategory').value,
    script_type: scriptTypeEl ? scriptTypeEl.value : 'vulnerable',
    os_target: document.getElementById('scriptOS').value,
    difficulty: document.getElementById('scriptDifficulty').value,
    script_content: document.getElementById('scriptContent').value,
    services_exposed: document.getElementById('scriptServices').value.split(',').map(s => s.trim()).filter(Boolean),
    depends_on: document.getElementById('scriptDependsOn').value.split(',').map(s => s.trim()).filter(Boolean),
    script_args: document.getElementById('scriptArgs').value.trim()
  };

  if (!body.slug || !body.name || !body.script_content) {
    Toast.warning('Missing', 'Slug, name, and script content are required');
    return;
  }

  try {
    if (editId) {
      await api('PUT', `/vuln-scripts/${editId}`, body);
      Toast.success('Updated', `Script "${body.name}" updated`);
    } else {
      await api('POST', '/vuln-scripts', body);
      Toast.success('Created', `Script "${body.name}" created`);
    }
    closeModal('scriptEditorModal');
    loadVulnScripts();
  } catch (e) { Toast.error('Error', e.message); }
}

async function deleteVulnScript(id, name) {
  if (!confirm(`Deactivate script "${name}"?`)) return;
  try {
    await api('DELETE', `/vuln-scripts/${id}`);
    Toast.success('Deleted', `Script "${name}" deactivated`);
    loadVulnScripts();
  } catch (e) { Toast.error('Error', e.message); }
}
