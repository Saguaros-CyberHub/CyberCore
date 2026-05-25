// ============================================================================
// CHALLENGE TEMPLATES
// ============================================================================

let cachedTemplates = [];

let challengeVMs = [];

// === Real-Client Intake context (populated when admin.html is opened with ?from_intake_id=…) ===
let activeIntakeContext = null;

async function loadIntakeContextFromQuery() {
  const params = new URLSearchParams(window.location.search);
  const intakeId = params.get('from_intake_id');
  if (!intakeId) return;
  try {
    const res = await fetch('/api/real-client/intake/' + encodeURIComponent(intakeId), { credentials: 'same-origin' });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const body = await res.json();
    const it = body.intake;
    const p = it.payload || {};
    const net = p.sections?.network || {};
    const suggestedName = params.get('suggested_name') || it.cover_name;
    activeIntakeContext = { id: it.id, cover_name: it.cover_name, suggested_name: suggestedName };

    // Show the panel
    document.getElementById('intakeContextPanel').style.display = 'block';
    document.getElementById('intakeCtxCover').textContent = it.cover_name;
    document.getElementById('intakeCtxLink').href = '/ciab/real-client-intake/' + encodeURIComponent(it.id);

    const roles = [
      ['Domain Controller', net.role_dc], ['File Server', net.role_file],
      ['Mail Server', net.role_mail], ['Web / App Server', net.role_web],
      ['Database Server', net.role_db], ['Backup Server', net.role_backup],
      ['Print Server', net.role_print], ['Other', net.role_other]
    ].filter(([, v]) => v && v !== 'no' && v !== '' && v !== '—').map(([k, v]) => `<li>${escHtml(k)}: <strong>${escHtml(v)}</strong></li>`).join('');
    const services = (net.services || []).map(s => `<span style="display:inline-block; background:#fed7aa; color:#7c2d12; padding:2px 8px; border-radius:10px; margin:2px; font-size:11px;">${escHtml(s)}</span>`).join('');
    const segRows = (net.segments || []).map(s => `<tr><td>${escHtml(s.vlan)}</td><td><code>${escHtml(s.cidr)}</code></td><td>${escHtml(s.purpose)}</td></tr>`).join('');

    document.getElementById('intakeCtxBody').innerHTML = `
      <div style="display:grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 0.75rem 1.25rem; margin-bottom: 0.75rem;">
        <div><strong>Desktops:</strong> ${escHtml(net.workstation_count || 0)}</div>
        <div><strong>Laptops:</strong> ${escHtml(net.laptop_count || 0)}</div>
        <div><strong>Servers:</strong> ${escHtml(net.server_count || 0)}</div>
        <div><strong>Domain mode:</strong> ${escHtml(net.domain_mode || '—')}</div>
        <div><strong>Domain cover:</strong> <code>${escHtml(net.domain_cover || '—')}</code></div>
      </div>
      ${roles ? `<div style="margin-bottom:0.5rem;"><strong>Server roles reported:</strong><ul style="margin:0.25rem 0 0 1.25rem;">${roles}</ul></div>` : ''}
      ${services ? `<div style="margin-bottom:0.5rem;"><strong>Services in use:</strong> ${services}</div>` : ''}
      ${segRows ? `<div><strong>Network segments:</strong><table style="width:100%; border-collapse: collapse; margin-top:0.25rem; font-size:0.8rem;"><thead><tr style="background:#ffedd5;"><th style="text-align:left; padding:4px 8px;">VLAN</th><th style="text-align:left; padding:4px 8px;">CIDR</th><th style="text-align:left; padding:4px 8px;">Purpose</th></tr></thead><tbody>${segRows}</tbody></table></div>` : ''}
      <div style="margin-top:0.75rem; color:#7c2d12; font-style:italic;">Use these values to hand-author a realistic VM list below. The challenge will be auto-linked to this intake on save.</div>`;

    // Switch to Challenges tab, open the form, pre-populate name/key
    try { if (typeof showTab === 'function') showTab('challenges'); } catch (_) {}
    showCreateChallengeForm();
    const keySlug = (suggestedName || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 40) || 'real-client';
    const nameEl = document.getElementById('newChalName');
    const keyEl  = document.getElementById('newChalKey');
    const zoneEl = document.getElementById('newChalZone');
    if (nameEl && !nameEl.value) nameEl.value = suggestedName;
    if (keyEl  && !keyEl.value)  keyEl.value  = keySlug;
    if (zoneEl && !zoneEl.value) zoneEl.value = keySlug.replace(/[^a-z0-9]/g, '').slice(0, 8);
  } catch (err) {
    console.warn('[intake context] failed to load:', err);
  }
}

function showCreateChallengeForm() {
  const form = document.getElementById('createChallengeForm');
  const opening = form.style.display === 'none';
  form.style.display = opening ? 'block' : 'none';

  // Auto-generate zone abbrev from challenge key
  document.getElementById('newChalKey').oninput = function() {
    const key = this.value.replace(/[^a-z0-9]/gi, '').substring(0, 8).toLowerCase();
    document.getElementById('newChalZone').value = key;
  };

  // Start with one VM if empty
  if (challengeVMs.length === 0) {
    challengeVMs = [{ name: '', role: 'Primary Target', os: 'Windows 11 25H2', template_vmid: '', services: '', default_scripts: '' }];
    renderChallengeVMs();
  }

  // Reset GOAD section to off whenever the form opens fresh
  if (opening) resetChalGoadFields();
}

function addChallengeVM() {
  challengeVMs.push({ name: '', role: '', os: '', template_vmid: '', services: '', default_scripts: '' });
  renderChallengeVMs();
}

function removeChallengeVM(idx) {
  challengeVMs.splice(idx, 1);
  renderChallengeVMs();
}

function renderChallengeVMs() {
  const container = document.getElementById('challengeVmList');
  if (challengeVMs.length === 0) {
    container.innerHTML = '<p style="color: var(--gray-400); font-size: 0.85rem;">No VMs added. Click "+ Add VM" to add a target machine.</p>';
    return;
  }

  container.innerHTML = challengeVMs.map((vm, i) => `
    <div style="background: #f7fafc; border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem; border: 1px solid #e2e8f0;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <strong style="font-size: 0.85rem;">VM ${i + 1}${vm.name ? ': ' + vm.name : ''}</strong>
        ${challengeVMs.length > 1 ? `<button style="font-size: 0.7rem; padding: 0.1rem 0.3rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent; border-radius: 4px; cursor: pointer;" onclick="removeChallengeVM(${i})">Remove</button>` : ''}
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr 1fr; gap: 0.5rem; font-size: 0.85rem;">
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">VM Name</label>
          <input type="text" value="${escHtml(vm.name)}" placeholder="e.g., web01" onchange="challengeVMs[${i}].name=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">Role</label>
          <input type="text" value="${escHtml(vm.role)}" placeholder="e.g., Web Server" onchange="challengeVMs[${i}].role=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">OS</label>
          <input type="text" value="${escHtml(vm.os)}" placeholder="e.g., Windows 11" onchange="challengeVMs[${i}].os=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">Template VMID</label>
          <input type="number" value="${vm.template_vmid || ''}" placeholder="e.g., 1002" onchange="challengeVMs[${i}].template_vmid=parseInt(this.value)||null" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.85rem;">
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">Services (comma-sep)</label>
          <input type="text" value="${escHtml(vm.services)}" placeholder="22/SSH, 445/SMB, 80/HTTP" onchange="challengeVMs[${i}].services=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
        <div>
          <label style="font-size: 0.7rem; color: var(--gray-500);">Default Scripts (comma-sep slugs)</label>
          <input type="text" value="${escHtml(vm.default_scripts)}" placeholder="smb-config, ssh-config, life-artifacts" onchange="challengeVMs[${i}].default_scripts=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;">
        </div>
      </div>
    </div>
  `).join('');
}

// ============================================================================
// GOAD helpers — shared catalog + form-specific handlers
// ============================================================================
// Catalog is fetched once from /api/admin/goad/labs and reused for both
// the Create-Challenge form and the Template editor modal.
let _goadCatalog = null;
async function loadGoadCatalog() {
  if (_goadCatalog) return _goadCatalog;
  try {
    _goadCatalog = await api('GET', '/goad/labs');
  } catch (e) {
    console.error('Failed to load GOAD lab catalog', e);
    _goadCatalog = { default_lab: 'GOAD-Light', labs: [] };
  }
  return _goadCatalog;
}
function findGoadLab(key) {
  return _goadCatalog?.labs.find(l => l.key === key);
}

// Convert a lab's VM list into challengeVMs / templateVMs row shape.
// Kali (optional) appended at the end.
function buildGoadVmRows(labKey, includeKali) {
  const lab = findGoadLab(labKey);
  if (!lab) return [];
  const rows = lab.vms.map(v => ({
    name:          v.name,
    role:          v.role,
    os:            v.os,
    template_vmid: v.template_vmid,
    services:      '',
    default_scripts: ''
  }));
  if (includeKali) {
    rows.push({ name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, services: '', default_scripts: '' });
  }
  return rows;
}

// ---- Create-Challenge form (chalGoad*) ----
let _preChalGoadVMs = null;
async function populateChalGoadVersionDropdown() {
  const catalog = await loadGoadCatalog();
  const select = document.getElementById('chalGoadVersion');
  const previous = select.value || catalog.default_lab;
  select.innerHTML = (catalog.labs || []).map(l =>
    `<option value="${l.key}">${escHtml(l.displayName)}</option>`
  ).join('') || `<option value="GOAD-Light">GOAD-Light</option>`;
  select.value = (catalog.labs || []).some(l => l.key === previous) ? previous : (catalog.default_lab || 'GOAD-Light');
  onChalGoadVersionChange();
}
async function onChalGoadToggle() {
  const enabled = document.getElementById('chalGoadEnabled').checked;
  document.getElementById('chalGoadConfig').style.display = enabled ? 'block' : 'none';
  if (enabled) {
    await populateChalGoadVersionDropdown();
    if (_preChalGoadVMs === null) _preChalGoadVMs = challengeVMs.slice();
    const labKey = document.getElementById('chalGoadVersion').value;
    const includeKali = document.getElementById('chalGoadKali').checked;
    challengeVMs = buildGoadVmRows(labKey, includeKali);
    renderChallengeVMs();
    if (typeof Toast !== 'undefined') Toast.info('GOAD enabled', `VM list set to ${labKey} topology`);
  } else {
    if (_preChalGoadVMs !== null) {
      challengeVMs = _preChalGoadVMs;
      _preChalGoadVMs = null;
    } else {
      challengeVMs = [];
    }
    renderChallengeVMs();
  }
}
function onChalGoadVersionChange() {
  const labKey = document.getElementById('chalGoadVersion').value;
  const lab = findGoadLab(labKey);
  const desc = document.getElementById('chalGoadVersionDesc');
  if (desc && lab) desc.textContent = lab.description || '';
  if (document.getElementById('chalGoadEnabled').checked) {
    const includeKali = document.getElementById('chalGoadKali').checked;
    challengeVMs = buildGoadVmRows(labKey, includeKali);
    renderChallengeVMs();
  }
}
function onChalGoadKaliToggle() {
  if (!document.getElementById('chalGoadEnabled').checked) return;
  const includeKali = document.getElementById('chalGoadKali').checked;
  const hasKali = challengeVMs.some(v => v.name === 'Kali');
  if (includeKali && !hasKali) {
    challengeVMs.push({ name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, services: '', default_scripts: '' });
    renderChallengeVMs();
  } else if (!includeKali && hasKali) {
    challengeVMs = challengeVMs.filter(v => v.name !== 'Kali');
    renderChallengeVMs();
  }
}
function readChalGoadFields() {
  if (!document.getElementById('chalGoadEnabled').checked) return null;
  return {
    enabled:         true,
    version:         document.getElementById('chalGoadVersion').value || 'GOAD-Light',
    domain:          document.getElementById('chalGoadDomain').value.trim() || 'cybersaguaros.local',
    child_subdomain: document.getElementById('chalGoadChild').value.trim() || 'tumamoc',
    admin_user:      'Administrator',
    admin_password:  document.getElementById('chalGoadPassword').value || 'vagrant',
    include_kali:    document.getElementById('chalGoadKali').checked
  };
}
function resetChalGoadFields() {
  _preChalGoadVMs = null;
  const cb = document.getElementById('chalGoadEnabled');
  if (cb) cb.checked = false;
  const cfg = document.getElementById('chalGoadConfig');
  if (cfg) cfg.style.display = 'none';
}

// Network-topology selector — updates the helper text under the dropdown.
function onChalSubnetSchemeChange() {
  const sel = document.getElementById('newChalSubnetScheme');
  const desc = document.getElementById('chalSubnetSchemeDesc');
  if (!sel || !desc) return;
  const text = {
    v1: 'All lane VMs share one flat subnet. Legacy scheme — kept for in-flight classes.',
    v2: 'Each lane gets its own /24 (10.x.x.0/24). Required for Tailscale BYOD access.',
    v3: 'Two subnets per lane — external (Kali/BYOD) and internal (GOAD AD) — with the gateway firewall-blocking traffic between them. Give one VM the role "dmz": it becomes the dual-homed pivot the attacker must exploit to reach the internal network.'
  };
  desc.textContent = text[sel.value] || text.v1;
}

async function createChallenge() {
  const name = document.getElementById('newChalName').value.trim();
  const challenge_key = document.getElementById('newChalKey').value.trim();
  const description = document.getElementById('newChalDesc').value.trim();
  const zone_abbrev = document.getElementById('newChalZone').value.trim() ||
    challenge_key.replace(/[^a-z0-9]/gi, '').substring(0, 8).toLowerCase();
  const max_lanes = document.getElementById('newChalMaxLanes').value;
  const difficulty = document.getElementById('newChalDiff').value;
  const module = document.getElementById('newChalModule').value;
  const subnet_scheme = document.getElementById('newChalSubnetScheme').value;
  const goad = readChalGoadFields();
  const status = document.getElementById('createChallengeStatus');

  if (!name || !challenge_key) {
    Toast.warning('Missing', 'Name and Challenge Key are required');
    return;
  }

  // Validate VMs
  const validVMs = challengeVMs.filter(vm => vm.template_vmid);
  if (validVMs.length === 0) {
    Toast.warning('Missing', 'Add at least one VM with a Template VMID');
    return;
  }

  // Build VM specs array — auto-assign offsets (600000, 610000, 620000, ...)
  const vms = validVMs.map((vm, idx) => ({
    name: vm.name || `vm-${vm.template_vmid}`,
    role: vm.role || 'Server',
    os: vm.os || 'Unknown',
    template_vmid: vm.template_vmid,
    type: 'qemu',
    vm_offset: 600000 + (idx * 10000),
    services: vm.services ? vm.services.split(',').map(s => s.trim()).filter(Boolean) : [],
    default_scripts: vm.default_scripts ? vm.default_scripts.split(',').map(s => s.trim()).filter(Boolean) : []
  }));

  status.textContent = goad ? `Creating GOAD challenge (${goad.version}) + SDN infrastructure...` : 'Creating challenge + SDN infrastructure...';
  status.style.color = 'var(--gray-500)';

  try {
    const body = {
      name, challenge_key, description, zone_abbrev,
      vms, max_lanes, difficulty, module, subnet_scheme,
      challenge_type: vms.length > 1 ? 'multi_vm' : 'single_vm'
    };
    if (goad) body.goad = goad;
    const data = await api('POST', '/create-lab', body);

    status.innerHTML = `
      <strong style="color: #38a169;">Challenge created!</strong><br>
      <span style="font-size: 0.8rem;">
        Key: <code>${escHtml(data.challenge_key)}</code> |
        Zone: <code>${escHtml(data.zone_abbrev)}</code> |
        VXLAN: ${data.vxlan_block.start}–${data.vxlan_block.end} |
        VNets: ${data.vnets_created} |
        VMs: ${vms.length}
      </span>
      <details style="margin-top: 0.5rem; font-size: 0.75rem;">
        <summary style="cursor: pointer; color: var(--gray-500);">Creation log</summary>
        <div style="background: #f7fafc; padding: 0.5rem; border-radius: 4px; margin-top: 0.25rem; white-space: pre-wrap;">${data.steps.join('\n')}</div>
      </details>`;

    Toast.success('Challenge Created', `${vms.length} VM(s), ${data.vnets_created} VNets`);

    // If this challenge was built from a real-client intake, link them.
    if (activeIntakeContext && activeIntakeContext.id && data.challenge_id) {
      try {
        await fetch('/api/real-client/intake/' + encodeURIComponent(activeIntakeContext.id) + '/link', {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'same-origin',
          body: JSON.stringify({ linked_challenge_id: data.challenge_id })
        });
        Toast.success('Intake Linked', `Linked to intake "${activeIntakeContext.cover_name}"`);
        activeIntakeContext = null;
        document.getElementById('intakeContextPanel').style.display = 'none';
      } catch (linkErr) {
        console.warn('[intake link] failed:', linkErr);
        Toast.warning('Link failed', 'Challenge created but could not be linked to intake: ' + linkErr.message);
      }
    }

    document.getElementById('createChallengeForm').style.display = 'none';
    challengeVMs = [];
    loadChallengeTemplates();
    loadModulesAndChallenges();
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    Toast.error('Failed', e.message);
  }
}

async function deleteChallenge(id, name) {
  if (!confirm(`Delete challenge "${name}"?\n\nThis will also remove the SDN zone and VNets from Proxmox.\n\nActive lanes using this challenge will NOT be affected.`)) return;
  try {
    const data = await api('DELETE', `/lab-templates/${id}`);
    Toast.success('Deleted', `Challenge "${name}" deleted${data.vnets_removed ? ` (${data.vnets_removed} VNets removed)` : ''}`);
    loadChallengeTemplates();
    loadModulesAndChallenges();
  } catch (e) { Toast.error('Error', e.message); }
}

async function loadChallengeTemplates() {
  const container = document.getElementById('challengeTemplatesList');
  container.innerHTML = '<p style="color: var(--gray-500);">Loading...</p>';

  try {
    const templates = await api('GET', '/lab-templates');
    cachedTemplates = templates;

    if (templates.length === 0) {
      container.innerHTML = '<div style="text-align: center; padding: 2rem; color: var(--gray-500);">No challenges found. Click "+ New Challenge" to create one.</div>';
      return;
    }

    container.innerHTML = `
      <table class="admin-table">
        <thead><tr><th>Challenge</th><th>Key</th><th>Difficulty</th><th>VXLAN Block</th><th>VMs</th><th>Status</th><th>Created</th><th>Actions</th></tr></thead>
        <tbody>
          ${templates.map(t => `
            <tr>
              <td><strong>${escHtml(t.name)}</strong><br><span style="font-size: 0.75rem; color: var(--gray-500);">${escHtml((t.description || '').substring(0, 60))}</span></td>
              <td><code style="font-size: 0.75rem;">${escHtml(t.challenge_key)}</code></td>
              <td><span class="badge ${t.difficulty === 'advanced' ? 'badge-red' : t.difficulty === 'beginner' ? 'badge-green' : 'badge-yellow'}">${escHtml(t.difficulty || 'intermediate')}</span></td>
              <td style="font-size: 0.8rem;">${t.vxlan_block ? `${t.vxlan_block.start}–${t.vxlan_block.end}` : '—'}</td>
              <td>${t.vm_count}</td>
              <td><span class="badge ${t.status === 'active' ? 'badge-green' : 'badge-gray'}">${escHtml(t.status)}</span></td>
              <td style="font-size: 0.8rem;">${new Date(t.created_at).toLocaleDateString()}</td>
              <td>
                <button class="btn btn-sm" style="font-size: 0.7rem; padding: 0.15rem 0.4rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="deleteChallenge('${t.id}', '${escHtml(t.name)}')">Delete</button>
              </td>
            </tr>
          `).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e;">Error: ${e.message}</p>`;
  }
}

let templateVMs = [];
let templatePhantoms = [];

// ---- Template editor GOAD handlers (tplGoad*) ----
let _preTplGoadVMs = null;
async function populateTplGoadVersionDropdown() {
  const catalog = await loadGoadCatalog();
  const select = document.getElementById('tplGoadVersion');
  const previous = select.value || catalog.default_lab;
  select.innerHTML = (catalog.labs || []).map(l =>
    `<option value="${l.key}">${escHtml(l.displayName)}</option>`
  ).join('') || `<option value="GOAD-Light">GOAD-Light</option>`;
  select.value = (catalog.labs || []).some(l => l.key === previous) ? previous : (catalog.default_lab || 'GOAD-Light');
  onTplGoadVersionChange();
}
// Convert a GOAD VM row (from catalog) to the templateVMs shape
function tplVmFromGoad(v, idx) {
  return {
    name:            v.name,
    role:            v.role,
    os:              v.os,
    template_vmid:   v.template_vmid,
    type:            'qemu',
    vm_offset:       600000 + idx * 10000,
    default_scripts: [],
    services:        []
  };
}
function buildTplGoadVMs(labKey, includeKali) {
  const lab = findGoadLab(labKey);
  if (!lab) return [];
  const vms = lab.vms.map((v, i) => tplVmFromGoad(v, i));
  if (includeKali) {
    vms.push({ name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, type: 'qemu', vm_offset: 600000 + vms.length * 10000, default_scripts: [], services: [] });
  }
  return vms;
}
async function onTplGoadToggle() {
  const enabled = document.getElementById('tplGoadEnabled').checked;
  document.getElementById('tplGoadConfig').style.display = enabled ? 'block' : 'none';
  if (enabled) {
    await populateTplGoadVersionDropdown();
    if (_preTplGoadVMs === null) _preTplGoadVMs = templateVMs.slice();
    const labKey = document.getElementById('tplGoadVersion').value;
    const includeKali = document.getElementById('tplGoadKali').checked;
    templateVMs = buildTplGoadVMs(labKey, includeKali);
    renderTemplateVMs();
    if (typeof Toast !== 'undefined') Toast.info('GOAD enabled', `VM list set to ${labKey} topology`);
  } else {
    if (_preTplGoadVMs !== null) { templateVMs = _preTplGoadVMs; _preTplGoadVMs = null; }
    else templateVMs = [];
    renderTemplateVMs();
  }
}
function onTplGoadVersionChange() {
  const labKey = document.getElementById('tplGoadVersion').value;
  const lab = findGoadLab(labKey);
  const desc = document.getElementById('tplGoadVersionDesc');
  if (desc && lab) desc.textContent = lab.description || '';
  if (document.getElementById('tplGoadEnabled').checked) {
    const includeKali = document.getElementById('tplGoadKali').checked;
    templateVMs = buildTplGoadVMs(labKey, includeKali);
    renderTemplateVMs();
  }
}
function onTplGoadKaliToggle() {
  if (!document.getElementById('tplGoadEnabled').checked) return;
  const includeKali = document.getElementById('tplGoadKali').checked;
  const hasKali = templateVMs.some(v => v.name === 'Kali');
  if (includeKali && !hasKali) {
    templateVMs.push({ name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, type: 'qemu', vm_offset: 600000 + templateVMs.length * 10000, default_scripts: [], services: [] });
    renderTemplateVMs();
  } else if (!includeKali && hasKali) {
    templateVMs = templateVMs.filter(v => v.name !== 'Kali');
    renderTemplateVMs();
  }
}
function readTplGoadFields() {
  if (!document.getElementById('tplGoadEnabled').checked) return null;
  return {
    enabled:         true,
    version:         document.getElementById('tplGoadVersion').value || (_goadCatalog?.default_lab) || 'GOAD-Light',
    domain:          document.getElementById('tplGoadDomain').value.trim() || 'cybersaguaros.local',
    child_subdomain: document.getElementById('tplGoadChild').value.trim() || 'tumamoc',
    admin_user:      'Administrator',
    admin_password:  document.getElementById('tplGoadPassword').value || 'vagrant',
    include_kali:    document.getElementById('tplGoadKali').checked
  };
}
function resetTplGoadFields() {
  _preTplGoadVMs = null;
  const cb = document.getElementById('tplGoadEnabled');
  if (cb) cb.checked = false;
  const cfg = document.getElementById('tplGoadConfig');
  if (cfg) cfg.style.display = 'none';
  const desc = document.getElementById('tplGoadVersionDesc');
  if (desc) desc.textContent = '';
}
async function loadTplGoadFields(goad) {
  if (!goad || !goad.enabled) { resetTplGoadFields(); return; }
  document.getElementById('tplGoadEnabled').checked = true;
  document.getElementById('tplGoadConfig').style.display = 'block';
  await populateTplGoadVersionDropdown();
  const select = document.getElementById('tplGoadVersion');
  const version = goad.version || (_goadCatalog?.default_lab) || 'GOAD-Light';
  if ([...select.options].some(o => o.value === version)) select.value = version;
  // Forest domain / child subdomain / local-admin password are read-only —
  // they reflect the GOAD fork + Windows template, not per-challenge values.
  // Leave the static read-only fields as-is; only version + Kali are editable.
  document.getElementById('tplGoadKali').checked   = goad.include_kali !== false;
  onTplGoadVersionChange();
}

function showCreateTemplateModal() {
  document.getElementById('templateEditorTitle').textContent = 'New Challenge Template';
  document.getElementById('tplEditId').value = '';
  document.getElementById('tplName').value = '';
  document.getElementById('tplDesc').value = '';
  document.getElementById('tplDifficulty').value = 'intermediate';
  templateVMs = [{ name: '', role: '', os: 'Windows 11 25H2', template_vmid: '', type: 'qemu', vm_offset: 600000, default_scripts: [], services: [] }];
  templatePhantoms = [];
  resetTplGoadFields();
  renderTemplateVMs();
  renderTemplatePhantoms();
  document.getElementById('templateEditorModal').classList.add('active');
}

async function editTemplate(id) {
  try {
    const t = await api('GET', `/lab-templates/${id}`);
    const spec = t.spec ? (typeof t.spec === 'string' ? JSON.parse(t.spec) : t.spec) : {};
    document.getElementById('templateEditorTitle').textContent = `Edit: ${t.name}`;
    document.getElementById('tplEditId').value = id;
    document.getElementById('tplName').value = t.name;
    document.getElementById('tplDesc').value = t.description || '';
    document.getElementById('tplDifficulty').value = t.difficulty;
    document.getElementById('tplModule').value = t.module || 'crucible';
    document.getElementById('tplChallengeKey').value = t.challenge_key || '';
    templateVMs = (spec.vms && spec.vms.length)
      ? spec.vms
      : (typeof t.vm_specs === 'string' ? JSON.parse(t.vm_specs) : (t.vm_specs || []));
    templatePhantoms = (spec.phantom_assets && spec.phantom_assets.length)
      ? spec.phantom_assets
      : (typeof t.phantom_assets === 'string' ? JSON.parse(t.phantom_assets) : (t.phantom_assets || []));
    await loadTplGoadFields(spec.goad);
    renderTemplateVMs();
    renderTemplatePhantoms();
    document.getElementById('templateEditorModal').classList.add('active');
  } catch (e) { Toast.error('Error', e.message); }
}

function addTemplateVM() {
  const nextOffset = 600000 + (templateVMs.length * 10000);
  templateVMs.push({ name: '', role: '', os: 'Windows 11 25H2', template_vmid: '', type: 'qemu', vm_offset: nextOffset, default_scripts: [], services: [] });
  renderTemplateVMs();
}

function removeTemplateVM(idx) { templateVMs.splice(idx, 1); renderTemplateVMs(); }

function renderTemplateVMs() {
  document.getElementById('tplVmList').innerHTML = templateVMs.map((vm, i) => `
    <div style="background: #f7fafc; border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem; border: 1px solid #e2e8f0;">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <strong style="font-size: 0.85rem;">VM ${i + 1}</strong>
        <button class="btn btn-sm" style="font-size: 0.65rem; padding: 0.1rem 0.3rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent;" onclick="removeTemplateVM(${i})">Remove</button>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem; font-size: 0.85rem;">
        <div><label style="font-size: 0.75rem;">Name</label><input type="text" value="${escHtml(vm.name)}" onchange="templateVMs[${i}].name=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
        <div><label style="font-size: 0.75rem;">Role</label><input type="text" value="${escHtml(vm.role)}" onchange="templateVMs[${i}].role=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
        <div><label style="font-size: 0.75rem;">OS</label><input type="text" value="${escHtml(vm.os)}" onchange="templateVMs[${i}].os=this.value" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem; font-size: 0.85rem;">
        <div><label style="font-size: 0.75rem;">Template VMID</label><input type="number" value="${vm.template_vmid || ''}" onchange="templateVMs[${i}].template_vmid=parseInt(this.value)||null" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
        <div><label style="font-size: 0.75rem;">VM Offset</label><input type="number" value="${vm.vm_offset}" onchange="templateVMs[${i}].vm_offset=parseInt(this.value)" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
        <div><label style="font-size: 0.75rem;">Services (comma-sep)</label><input type="text" value="${(vm.services || []).join(', ')}" onchange="templateVMs[${i}].services=this.value.split(',').map(s=>s.trim()).filter(Boolean)" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
      </div>
      <div style="margin-top: 0.5rem;"><label style="font-size: 0.75rem;">Default Scripts (comma-sep slugs)</label><input type="text" value="${(vm.default_scripts || []).join(', ')}" onchange="templateVMs[${i}].default_scripts=this.value.split(',').map(s=>s.trim()).filter(Boolean)" style="width: 100%; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0; font-size: 0.8rem;"></div>
    </div>
  `).join('');
}

function addTemplatePhantom() {
  templatePhantoms.push({ hostname: '', ip: '', role: '', os: '', notes: '' });
  renderTemplatePhantoms();
}

function removeTemplatePhantom(idx) { templatePhantoms.splice(idx, 1); renderTemplatePhantoms(); }

function renderTemplatePhantoms() {
  document.getElementById('tplPhantomList').innerHTML = templatePhantoms.map((p, i) => `
    <div style="display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.4rem; font-size: 0.8rem;">
      <input type="text" value="${escHtml(p.hostname)}" placeholder="Hostname" onchange="templatePhantoms[${i}].hostname=this.value" style="flex: 1; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0;">
      <input type="text" value="${escHtml(p.ip)}" placeholder="IP" onchange="templatePhantoms[${i}].ip=this.value" style="width: 120px; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0;">
      <input type="text" value="${escHtml(p.role)}" placeholder="Role" onchange="templatePhantoms[${i}].role=this.value" style="flex: 1; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0;">
      <input type="text" value="${escHtml(p.os)}" placeholder="OS" onchange="templatePhantoms[${i}].os=this.value" style="width: 120px; padding: 0.3rem; border-radius: 4px; border: 1px solid #e2e8f0;">
      <button style="font-size: 0.7rem; border: 1px solid #e53e3e; color: #e53e3e; background: transparent; border-radius: 4px; padding: 0.15rem 0.3rem; cursor: pointer;" onclick="removeTemplatePhantom(${i})">X</button>
    </div>
  `).join('') || '<p style="color: var(--gray-400); font-size: 0.8rem;">No phantom assets. Click "+ Add Phantom Host" to add fake hosts for profile realism.</p>';
}

async function saveTemplate() {
  const editId = document.getElementById('tplEditId').value;
  const goad = readTplGoadFields();
  const body = {
    name: document.getElementById('tplName').value.trim(),
    description: document.getElementById('tplDesc').value.trim(),
    difficulty: document.getElementById('tplDifficulty').value,
    module: document.getElementById('tplModule').value,
    challenge_key: document.getElementById('tplChallengeKey').value.trim() || null,
    vm_specs: templateVMs,
    phantom_assets: templatePhantoms
  };
  // POST /create-lab reads goad at the top level. PUT /lab-templates/:id
  // overwrites the spec atomically, so embed there too.
  if (goad) {
    body.goad = goad;
    body.spec = { vms: templateVMs, phantom_assets: templatePhantoms, goad };
  }

  if (!body.name || templateVMs.length === 0) {
    Toast.warning('Missing', 'Name and at least one VM are required');
    return;
  }

  try {
    if (editId) {
      await api('PUT', `/lab-templates/${editId}`, body);
      Toast.success('Updated', `Template "${body.name}" updated`);
    } else {
      await api('POST', '/lab-templates', body);
      Toast.success('Created', `Template "${body.name}" created`);
    }
    closeModal('templateEditorModal');
    loadChallengeTemplates();
  } catch (e) { Toast.error('Error', e.message); }
}

async function deleteTemplate(id, name) {
  if (!confirm(`Deactivate template "${name}"?`)) return;
  try {
    await api('DELETE', `/lab-templates/${id}`);
    Toast.success('Deleted', `Template "${name}" deactivated`);
    loadChallengeTemplates();
  } catch (e) { Toast.error('Error', e.message); }
}

// ============================================================================
// DEPLOY CHALLENGE NETWORK
// ============================================================================

async function onTemplateSelected() {
  const tplId = document.getElementById('challengeTemplateSel').value;
  const selector = document.getElementById('templateVulnSelector');
  const btn = document.getElementById('deployChallengeBtn');

  if (!tplId) {
    selector.style.display = 'none';
    btn.disabled = true;
    return;
  }

  try {
    const template = await api('GET', `/lab-templates/${tplId}`);
    const vmSpecs = typeof template.vm_specs === 'string' ? JSON.parse(template.vm_specs) : template.vm_specs;
    const allScripts = cachedVulnScripts.length > 0 ? cachedVulnScripts : await api('GET', '/vuln-scripts');

    let html = '<h4 style="margin: 0 0 0.75rem; font-size: 0.9rem;">Select Vulnerability Scripts per VM</h4>';
    html += vmSpecs.map((vm, i) => {
      const compatScripts = allScripts.filter(s => s.os_target === 'any' || s.os_target === (vm.os?.toLowerCase().includes('linux') ? 'linux' : 'windows'));
      const defaults = vm.default_scripts || [];
      return `
        <div style="background: #f7fafc; border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem;">
          <strong style="font-size: 0.85rem;">${escHtml(vm.name)} — ${escHtml(vm.role)}</strong>
          <span style="font-size: 0.75rem; color: var(--gray-500); margin-left: 0.5rem;">${escHtml(vm.os)}</span>
          <div style="display: flex; flex-wrap: wrap; gap: 0.4rem; margin-top: 0.5rem;">
            ${compatScripts.map(s => `
              <label style="display: flex; align-items: center; gap: 0.2rem; font-size: 0.75rem; padding: 0.2rem 0.4rem; background: white; border: 1px solid #e2e8f0; border-radius: 4px;">
                <input type="checkbox" class="challenge-script-cb" data-vm="${escHtml(vm.name)}" data-slug="${escHtml(s.slug)}" ${defaults.includes(s.slug) ? 'checked' : ''} style="width: auto;">
                ${escHtml(s.name)}
              </label>
            `).join('')}
          </div>
        </div>`;
    }).join('');

    selector.innerHTML = html;
    selector.style.display = 'block';
    btn.disabled = false;
  } catch (e) {
    selector.innerHTML = `<p style="color: #e53e3e;">Error loading template: ${e.message}</p>`;
    selector.style.display = 'block';
  }
}

async function deployChallengeNetwork() {
  const tplId = document.getElementById('challengeTemplateSel').value;
  const userInput = document.getElementById('challengeUserId').value.trim();
  const status = document.getElementById('challengeDeployStatus');
  const btn = document.getElementById('deployChallengeBtn');

  if (!tplId) { Toast.warning('Missing', 'Select a template'); return; }

  // Collect selected scripts
  const selected = [];
  document.querySelectorAll('.challenge-script-cb:checked').forEach(cb => {
    selected.push({ vm_name: cb.dataset.vm, script_slug: cb.dataset.slug });
  });

  btn.disabled = true;
  btn.textContent = 'Checking resources...';
  status.textContent = 'Running pre-flight check...';
  status.style.color = 'var(--gray-500)';

  try {
    // Step 1: preview
    const preview = await api('POST', '/deploy-lab-network', {
      template_id: tplId, selected_scripts: selected
    });

    if (preview.preview) {
      showDeployConfirmation(preview, () => deployChallengeNetworkConfirmed(tplId, userInput, selected));
      btn.disabled = false;
      btn.textContent = 'Deploy Challenge Network';
      status.textContent = '';
      return;
    }
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    btn.disabled = false;
    btn.textContent = 'Deploy Challenge Network';
    return;
  }

  btn.disabled = false;
  btn.textContent = 'Deploy Challenge Network';
}

async function deployChallengeNetworkConfirmed(tplId, userInput, selected) {
  const status = document.getElementById('challengeDeployStatus');
  const btn = document.getElementById('deployChallengeBtn');

  btn.disabled = true;
  btn.textContent = 'Deploying...';
  status.textContent = 'Deploying challenge network (cloning VMs, running scripts)...';
  status.style.color = 'var(--gray-500)';

  try {
    const body = {
      template_id: tplId,
      selected_scripts: selected,
      confirm: true
    };
    if (userInput) body.user_id = userInput;

    const data = await api('POST', '/deploy-lab-network', body);
    status.innerHTML = `
      <strong style="color: #38a169;">Challenge network deploying!</strong><br>
      Lane: <code>${data.lane_id}</code> | VXLAN: ${data.vxlan_id} | VMs: ${data.vm_count} | Scripts: ${data.scripts_count}<br>
      <span style="font-size: 0.8rem; color: var(--gray-500);">Deployment ID: ${data.deployment_id} — poll status for progress.</span><br>
      <button class="btn btn-sm btn-outline" style="margin-top: 0.5rem;" onclick="pollChallengeStatus('${data.lane_id}')">Check Status</button>
      <button class="btn btn-sm btn-primary" style="margin-top: 0.5rem; display: none;" id="genProfileBtn-${data.lane_id}" onclick="generateChallengeProfile('${data.lane_id}')">Generate Profile</button>
    `;
    Toast.success('Deploying', `${data.vm_count} VMs + ${data.scripts_count} scripts`);
    loadClusterHealth();
  } catch (e) {
    status.textContent = `Error: ${e.message}`;
    status.style.color = '#e53e3e';
    Toast.error('Deploy Failed', e.message);
  } finally {
    btn.disabled = false;
    btn.textContent = 'Deploy Challenge Network';
  }
}

async function pollChallengeStatus(laneId) {
  try {
    const data = await api('GET', `/lab-networks/${laneId}/status`);
    const s = data.script_summary;
    let statusHtml = `<strong>Status: ${data.status}</strong> | Scripts: ${s.completed}/${s.total} complete`;
    if (s.running > 0) statusHtml += ` | ${s.running} running`;
    if (s.failed > 0) statusHtml += ` | <span style="color: #e53e3e;">${s.failed} failed</span>`;

    if (data.all_complete) {
      statusHtml += `<br><span style="color: #38a169; font-weight: 600;">All scripts complete! Ready to generate profile.</span>`;
      const genBtn = document.getElementById(`genProfileBtn-${laneId}`);
      if (genBtn) genBtn.style.display = 'inline-block';
    }

    Toast.info('Status', statusHtml);
  } catch (e) { Toast.error('Error', e.message); }
}

async function generateChallengeProfile(laneId) {
  const industry = prompt('Industry for the profile (e.g., Technology, Healthcare, Finance):') || 'Technology';
  const difficulty = prompt('Difficulty (beginner/intermediate/advanced):') || 'intermediate';

  try {
    Toast.info('Generating', 'Creating challenge network profile...');
    const data = await api('POST', `/lab-networks/${laneId}/generate-profile`, {
      industry, difficulty, client_type: 'SMB'
    });
    Toast.success('Profile Generated', `${data.assets_included} assets (${data.real_vms} real VMs + ${data.phantom_hosts} phantom)`);
  } catch (e) { Toast.error('Error', e.message); }
}
