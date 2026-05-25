// ============================================================================
// WORKSTATION TEMPLATES
// ============================================================================

function showWorkstationTemplateForm(tpl = null) {
  document.getElementById('wsTplEditId').value = tpl ? tpl.template_id : '';
  document.getElementById('workstationFormTitle').textContent = tpl ? 'Edit Workstation Template' : 'New Workstation Template';
  document.getElementById('wsTplSaveLabel').textContent = tpl ? 'Save Changes' : 'Create Workstation Template';
  document.getElementById('wsTplName').value         = tpl?.name         || '';
  document.getElementById('wsTplKey').value          = tpl?.template_key  || '';
  document.getElementById('wsTplDesc').value         = tpl?.description   || '';
  document.getElementById('wsTplVmid').value         = tpl?.template_vmid || '';
  document.getElementById('wsTplOsFamily').value     = tpl?.os_family     || 'linux';
  document.getElementById('wsTplOsVersion').value    = tpl?.os_version    || '';
  document.getElementById('wsTplMaxInstances').value = tpl?.max_instances || 10;
  document.getElementById('wsTplStatus').value       = tpl?.status        || 'draft';
  document.getElementById('wsTplModule').value       = tpl?.module_key    || '';
  document.getElementById('wsTplNotes').value        = tpl?.notes         || '';
  document.getElementById('wsTplIsActive').checked   = tpl ? tpl.is_active !== false : true;
  document.getElementById('wsTplStatus2').textContent = '';

  document.getElementById('workstationTemplateForm').style.display = 'block';
  document.getElementById('workstationTemplateForm').scrollIntoView({ behavior: 'smooth', block: 'start' });
}

function closeWorkstationTemplateForm() {
  document.getElementById('workstationTemplateForm').style.display = 'none';
  document.getElementById('wsTplEditId').value = '';
}

function wsTplAutoKey() {
  if (document.getElementById('wsTplEditId').value) return;
  const name = document.getElementById('wsTplName').value;
  document.getElementById('wsTplKey').value = name
    .toLowerCase().trim()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-|-$/g, '');
}

async function saveWorkstationTemplate() {
  const editId   = document.getElementById('wsTplEditId').value;
  const statusEl = document.getElementById('wsTplStatus2');

  const body = {
    template_key:  document.getElementById('wsTplKey').value.trim(),
    name:          document.getElementById('wsTplName').value.trim(),
    description:   document.getElementById('wsTplDesc').value.trim() || null,
    template_vmid: Number(document.getElementById('wsTplVmid').value),
    os_family:     document.getElementById('wsTplOsFamily').value,
    os_version:    document.getElementById('wsTplOsVersion').value.trim() || null,
    module_key:    document.getElementById('wsTplModule').value || null,
    max_instances: Number(document.getElementById('wsTplMaxInstances').value) || 10,
    status:        document.getElementById('wsTplStatus').value,
    notes:         document.getElementById('wsTplNotes').value.trim() || null,
    is_active:     document.getElementById('wsTplIsActive').checked
  };

  if (!body.template_key || !body.name || !body.template_vmid) {
    statusEl.innerHTML = '<span style="color:#e53e3e;">Name, key, and VMID are required.</span>';
    return;
  }

  statusEl.innerHTML = '<span style="color:var(--gray-500);">Saving…</span>';
  try {
    if (editId) {
      await api('PUT', `/workstation-templates/${editId}`, body);
    } else {
      await api('POST', '/workstation-templates', body);
    }
    statusEl.innerHTML = '<span style="color:#38a169;">Saved.</span>';
    closeWorkstationTemplateForm();
    loadWorkstationTemplates();
  } catch (e) {
    statusEl.innerHTML = `<span style="color:#e53e3e;">Error: ${escHtml(e.message)}</span>`;
  }
}

async function wsTplToggleActive(id, checkbox) {
  checkbox.disabled = true;
  try {
    const result = await api('PATCH', `/workstation-templates/${id}/toggle`);
    checkbox.checked = result.is_active;
  } catch (e) {
    checkbox.checked = !checkbox.checked; // revert on failure
    alert(`Toggle failed: ${e.message}`);
  } finally {
    checkbox.disabled = false;
  }
}

async function wsTplVerify(id, name) {
  const resultEl   = document.getElementById(`wsTplVerifyResult-${id}`);
  const nodeEl     = document.getElementById(`wsTplNode-${id}`);
  if (!resultEl) return;
  resultEl.innerHTML = '<span style="color:var(--gray-400);">Checking…</span>';
  try {
    const r = await api('GET', `/workstation-templates/${id}/verify`);
    if (r.found) {
      const tplFlag = r.is_template
        ? '<span style="color:#38a169;">✓ template</span>'
        : '<span style="color:#e53e3e;">✗ not a template</span>';
      const mem  = r.maxmem_gb  ? ` · ${r.maxmem_gb}GB RAM`  : '';
      const disk = r.maxdisk_gb ? ` · ${r.maxdisk_gb}GB disk` : '';
      resultEl.innerHTML = `<span style="color:#38a169;">✓ ${escHtml(r.node)}</span> ${tplFlag}<span style="color:var(--gray-400);">${mem}${disk}</span>`;
      if (nodeEl && r.node) nodeEl.textContent = r.node;
    } else {
      resultEl.innerHTML = `<span style="color:#e53e3e;">✗ VMID ${r.template_vmid} not found</span>`;
      if (r.auto_disabled) {
        const row        = document.getElementById(`wsTplRow-${id}`);
        const statusCell = document.getElementById(`wsTplStatusCell-${id}`);
        if (row) {
          const cb = row.querySelector('input[type=checkbox]');
          if (cb) cb.checked = false;
        }
        if (statusCell) statusCell.innerHTML = '<span class="badge badge-yellow">draft</span>';
      }
    }
  } catch (e) {
    resultEl.innerHTML = `<span style="color:#e53e3e;">Error: ${escHtml(e.message)}</span>`;
  }
}

async function loadWorkstationTemplates() {
  const container = document.getElementById('workstationTemplatesList');
  container.innerHTML = '<p style="color:var(--gray-500);">Loading…</p>';
  try {
    const templates = await api('GET', '/workstation-templates');
    if (templates.length === 0) {
      container.innerHTML = '<div style="text-align:center; padding:2rem; color:var(--gray-500);">No workstation templates yet. Click "+ New Template" to create one.</div>';
      return;
    }
    const statusBadge = s => s === 'active'
      ? '<span class="badge badge-green">active</span>'
      : s === 'retired'
      ? '<span class="badge badge-gray">retired</span>'
      : '<span class="badge badge-yellow">draft</span>';

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr>
          <th>Template</th><th>Key</th><th>OS Family / VMID</th><th>Node</th>
          <th>Module</th><th>Max</th><th>Status</th><th>Enabled</th><th>Actions</th>
        </tr></thead>
        <tbody>
          ${templates.map(t => `
            <tr id="wsTplRow-${t.template_id}">
              <td>
                <strong>${escHtml(t.name)}</strong>
                ${t.description ? `<br><span style="font-size:0.75rem;color:var(--gray-500);">${escHtml(t.description.substring(0,70))}</span>` : ''}
              </td>
              <td><code style="font-size:0.75rem;">${escHtml(t.template_key)}</code></td>
              <td style="font-size:0.8rem;">${escHtml(t.os_family || '—')}${t.os_version ? ' ' + escHtml(t.os_version) : ''}<br><span style="color:var(--gray-500);">VMID ${t.template_vmid}</span></td>
              <td style="font-size:0.8rem;" id="wsTplNode-${t.template_id}">${t.node ? escHtml(t.node) : '<span style="color:var(--gray-400);">—</span>'}</td>
              <td style="font-size:0.8rem;">${escHtml(t.module_key || '—')}</td>
              <td style="font-size:0.8rem;">${t.max_instances}</td>
              <td id="wsTplStatusCell-${t.template_id}">${statusBadge(t.status)}</td>
              <td>
                <label class="toggle-switch">
                  <input type="checkbox" ${t.is_active ? 'checked' : ''} onchange="wsTplToggleActive('${t.template_id}', this)">
                  <span class="toggle-slider"></span>
                </label>
              </td>
              <td style="white-space:nowrap;">
                <button class="btn btn-sm btn-outline" style="font-size:0.7rem;" onclick="wsTplVerify('${t.template_id}', '${escHtml(t.name)}')">Test</button>
                <button class="btn btn-sm btn-outline" style="font-size:0.7rem;margin-left:0.25rem;" onclick="editWorkstationTemplate('${t.template_id}')">Edit</button>
                <button class="btn btn-sm" style="font-size:0.7rem;padding:0.15rem 0.4rem;border:1px solid #e53e3e;color:#e53e3e;background:transparent;margin-left:0.25rem;" onclick="deleteWorkstationTemplate('${t.template_id}','${escHtml(t.name)}')">Delete</button>
                <span id="wsTplVerifyResult-${t.template_id}" style="font-size:0.75rem;margin-left:0.4rem;"></span>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color:#e53e3e;">Error: ${escHtml(e.message)}</p>`;
  }
}

async function editWorkstationTemplate(id) {
  try {
    const tpl = await api('GET', `/workstation-templates/${id}`);
    showWorkstationTemplateForm(tpl);
  } catch (e) {
    alert(`Failed to load template: ${e.message}`);
  }
}

async function deleteWorkstationTemplate(id, name) {
  if (!confirm(`Delete workstation template "${name}"? This cannot be undone.`)) return;
  try {
    await api('DELETE', `/workstation-templates/${id}`);
    loadWorkstationTemplates();
  } catch (e) {
    alert(`Delete failed: ${e.message}`);
  }
}
