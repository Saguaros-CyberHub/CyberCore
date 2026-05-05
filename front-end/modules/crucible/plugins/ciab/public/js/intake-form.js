// ============================================================================
// INTAKE FORM - Frontend Logic (V8 - 10 Sections + IG1 Safeguards)
// Matches real-client intake form structure with PII for simulated companies
// ============================================================================

let profileId = null;
let profileData = null;

// Section keys match DB column names for zero-mapping save/load
const SECTIONS = [
  'company_info',      // 1. Organization Profile
  'network_security',  // 2. Network Topology
  'wireless',          // 3. Wireless
  'endpoint_security', // 4. Endpoint Security
  'email_web',         // 5. Email & Web
  'admin_privileges',  // 6. Account & Access
  'data_management',   // 7. Data Protection
  'vuln_management',   // 8. Vulnerability & Audit
  'compliance',        // 9. IG1 Safeguards
  'pentesting'         // 10. Additional Notes
];

let formData = {};
SECTIONS.forEach(s => { formData[s] = {}; });

// Also send empty objects for unused legacy columns so the backend doesn't error
const LEGACY_SECTIONS = ['security_policies', 'software_assets', 'secure_config', 'network_ports', 'network_devices'];

let autoSaveTimeout = null;
let interviewSessionId = null;

// IG1 and help data (loaded from inline JSON in HTML)
let IG1 = [];
let HELP = {};
let GUIDES = {};

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Parse inline data
  try { IG1 = JSON.parse(document.getElementById('ig1-safeguards').textContent); } catch (_) {}
  try { HELP = JSON.parse(document.getElementById('help-definitions').textContent); } catch (_) {}
  try { GUIDES = JSON.parse(document.getElementById('section-guides').textContent); } catch (_) {}

  // Render IG1 safeguards
  renderIG1Safeguards();

  // Setup interactive features
  setupRoleToggles();
  setupServiceToggles();
  setupSegments();
  setupHelpSystem();

  if (!await Auth.requireAuth()) return;

  const params = new URLSearchParams(window.location.search);
  profileId = params.get('profileId');

  if (!profileId) {
    Toast.error('Error', 'No profile specified');
    window.location.href = '/ciab/my-profiles';
    return;
  }

  await loadIntakeForm();
  setupAutoSave();
});

// ============================================================================
// RENDER IG1 SAFEGUARDS
// ============================================================================

function renderIG1Safeguards() {
  const container = document.getElementById('ig1-container');
  if (!container || !IG1.length) return;

  const grouped = {};
  IG1.forEach(sg => { (grouped[sg.control] ||= []).push(sg); });

  Object.keys(grouped).sort((a, b) => +a - +b).forEach(ctrl => {
    const list = grouped[ctrl];
    const div = document.createElement('div');
    div.className = 'ig1-control';
    div.innerHTML = `<h3>Control ${ctrl} &mdash; ${list[0].control_name}</h3>` +
      list.map(sg => `
        <div class="ig1-safeguard" data-ig1="${sg.num}">
          <div><span class="sg-num">${sg.num}</span><span class="sg-title">${sg.name}</span></div>
          <div class="radio-row">
            <label><input type="radio" name="ig1_${sg.num}" value="yes" data-section="compliance" /> Yes</label>
            <label><input type="radio" name="ig1_${sg.num}" value="partial" data-section="compliance" /> Partial</label>
            <label><input type="radio" name="ig1_${sg.num}" value="no" data-section="compliance" /> No</label>
            <label><input type="radio" name="ig1_${sg.num}" value="unknown" data-section="compliance" /> Don't know</label>
          </div>
          <textarea name="ig1_${sg.num}_notes" data-section="compliance" placeholder="Evidence or notes (optional)"></textarea>
        </div>`).join('');
    container.appendChild(div);
  });
}

// ============================================================================
// SERVER ROLE VERSION TOGGLES
// ============================================================================

function setupRoleToggles() {
  document.querySelectorAll('.role-select').forEach(sel => {
    sel.addEventListener('change', () => toggleRoleVersion(sel));
    toggleRoleVersion(sel);
  });
}

function toggleRoleVersion(select) {
  const versionInput = select.closest('.role-field')?.querySelector('.role-version');
  if (!versionInput) return;
  versionInput.style.display = select.value === 'yes' ? '' : 'none';
  if (select.value !== 'yes') versionInput.value = '';
}

// ============================================================================
// SERVICE VERSION TOGGLES
// ============================================================================

function setupServiceToggles() {
  document.querySelectorAll('.svc-check').forEach(cb => {
    cb.addEventListener('change', () => toggleSvcVersion(cb));
    toggleSvcVersion(cb);
  });
}

function toggleSvcVersion(checkbox) {
  const versionInput = checkbox.closest('.svc-field')?.querySelector('.svc-version');
  if (!versionInput) return;
  versionInput.style.display = checkbox.checked ? '' : 'none';
  if (!checkbox.checked) versionInput.value = '';
}

// ============================================================================
// NETWORK SEGMENTS (dynamic rows)
// ============================================================================

function setupSegments() {
  document.getElementById('btn-add-segment')?.addEventListener('click', () => {
    addSegment();
    scheduleAutoSave();
  });
  // Start with one empty row
  addSegment();
}

function addSegment(data) {
  const list = document.getElementById('segments-list');
  if (!list) return;
  const row = document.createElement('div');
  row.className = 'segment-row';
  row.innerHTML = `
    <input type="text" placeholder="VLAN ID (e.g., 10)" data-seg="vlan" value="${data?.vlan ?? ''}">
    <input type="text" placeholder="CIDR (e.g., 10.0.10.0/24)" data-seg="cidr" value="${data?.cidr ?? ''}">
    <input type="text" placeholder="Purpose (e.g., workstations)" data-seg="purpose" value="${data?.purpose ?? ''}">
    <button class="btn btn-danger" type="button" style="padding:0.375rem 0.625rem;">X</button>`;
  row.querySelector('button').addEventListener('click', () => { row.remove(); scheduleAutoSave(); });
  row.querySelectorAll('input').forEach(i => i.addEventListener('input', scheduleAutoSave));
  list.appendChild(row);
}

function collectSegments() {
  const list = document.getElementById('segments-list');
  if (!list) return [];
  return Array.from(list.querySelectorAll('.segment-row')).map(row => ({
    vlan: row.querySelector('[data-seg=vlan]')?.value || '',
    cidr: row.querySelector('[data-seg=cidr]')?.value || '',
    purpose: row.querySelector('[data-seg=purpose]')?.value || ''
  }));
}

function restoreSegments(segments) {
  const list = document.getElementById('segments-list');
  if (!list || !Array.isArray(segments)) return;
  list.innerHTML = '';
  segments.forEach(addSegment);
  if (segments.length === 0) addSegment();
}

// ============================================================================
// HELP SYSTEM (tooltips + section guides)
// ============================================================================

let activePop = null;

function setupHelpSystem() {
  document.addEventListener('click', (e) => {
    // Section guide
    const guide = e.target.closest('.guide-trigger');
    if (guide) { e.preventDefault(); openGuide(guide.dataset.guide, guide); return; }

    // Help tooltip
    const t = e.target.closest('.help-trigger');
    if (t) {
      e.preventDefault();
      closePop();
      const key = t.dataset.help;
      const text = (HELP[key] || 'No definition available.').replace(/\n/g, '<br>');
      const pop = document.createElement('div');
      pop.className = 'help-pop';
      pop.innerHTML = `<strong>${key}</strong><br>${text}`;
      document.body.appendChild(pop);
      positionPop(pop, t);
      activePop = pop;
      return;
    }

    if (!e.target.closest('.help-pop, .guide-pop')) closePop();
  });

  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closePop(); });
}

function closePop() { if (activePop) { activePop.remove(); activePop = null; } }

function positionPop(pop, anchor) {
  const r = anchor.getBoundingClientRect();
  pop.style.top = (window.scrollY + r.bottom + 6) + 'px';
  const left = Math.min(window.scrollX + r.left, window.scrollX + window.innerWidth - pop.offsetWidth - 16);
  pop.style.left = Math.max(8, left) + 'px';
}

function openGuide(key, anchor) {
  closePop();
  const guide = GUIDES[key];
  if (!guide) return;
  const pop = document.createElement('div');
  pop.className = 'guide-pop';
  const steps = (guide.steps || []).map(s => `<li>${s}</li>`).join('');
  const platforms = (guide.platforms || []).map(p => `<div class="plat"><strong>${p.label}:</strong> ${p.howto}</div>`).join('');
  const tip = guide.tip ? `<div class="tip">${guide.tip}</div>` : '';
  pop.innerHTML = `<button class="close" aria-label="Close">&times;</button>
    <h4>${guide.title}</h4>
    ${steps ? `<ol>${steps}</ol>` : ''}
    ${platforms}
    ${tip}`;
  document.body.appendChild(pop);
  pop.querySelector('.close').addEventListener('click', closePop);
  positionPop(pop, anchor);
  activePop = pop;
}

// ============================================================================
// LOAD FORM DATA
// ============================================================================

async function loadIntakeForm() {
  try {
    const token = localStorage.getItem('token');
    if (!token) {
      Toast.error('Error', 'Not authenticated');
      setTimeout(() => window.location.href = '/login', 1500);
      return;
    }

    const response = await fetch(`/api/intake-form/${profileId}`, {
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' }
    });

    if (!response.ok) {
      if (response.status === 401) {
        localStorage.removeItem('token');
        setTimeout(() => window.location.href = '/login', 1500);
        return;
      }
      throw new Error(`Server returned ${response.status}`);
    }

    const data = await response.json();
    profileData = data.profile_data;

    // Merge saved form data
    if (data.form_data) {
      SECTIONS.forEach(section => {
        if (data.form_data[section] && typeof data.form_data[section] === 'object') {
          formData[section] = data.form_data[section];
        }
      });
    }

    // Pre-fill from profile
    prefillFromProfile();

    // Load all saved data
    populateAllFields();
    updateProgress();
    await startInterviewSession();

  } catch (error) {
    console.error('Error loading form:', error);
    Toast.error('Error', `Failed to load intake form: ${error.message}`);
  }
}

// ============================================================================
// PRE-FILL FROM PROFILE DATA
// ============================================================================

function prefillFromProfile() {
  if (!profileData) return;

  const q = profileData.quick || {};

  // Company name (always set, readonly)
  const companyName = q.company_name || 'Unknown Organization';
  document.getElementById('companyName').textContent = companyName;
  const nameInput = document.getElementById('company_name');
  if (nameInput) nameInput.value = companyName;

  // Only pre-fill fields that are currently empty (don't overwrite saved data)
  function prefill(id, value) {
    if (!value) return;
    const el = document.getElementById(id);
    if (!el || el.value) return;
    el.value = value;
  }

  // Industry - try to match dropdown option
  if (q.industry) {
    const industryEl = document.getElementById('industry');
    if (industryEl && !industryEl.value) {
      // Try exact match first
      const options = Array.from(industryEl.options);
      const match = options.find(o => o.textContent.toLowerCase().includes(q.industry.toLowerCase()));
      if (match) industryEl.value = match.value;
      else industryEl.value = q.industry; // May not match a dropdown option but that's ok
    }
  }

  // Employee count - map numeric to band
  if (q.employees_total) {
    const bandEl = document.getElementById('employees_band');
    if (bandEl && !bandEl.value) {
      const n = parseInt(q.employees_total);
      if (n <= 10) bandEl.value = '1-10';
      else if (n <= 50) bandEl.value = '11-50';
      else if (n <= 100) bandEl.value = '51-100';
      else if (n <= 250) bandEl.value = '101-250';
      else if (n <= 500) bandEl.value = '251-500';
      else if (n <= 1000) bandEl.value = '501-1000';
      else if (n <= 5000) bandEl.value = '1001-5000';
      else bandEl.value = '5000+';
    }
  }

  // Location
  prefill('locations', q.hq_city || q.region);
  prefill('business_address', q.hq_city);

  // Compliance frameworks from profile
  if (q.compliance_frameworks || profileData.raw?.threats?.organization?.compliance_frameworks) {
    const frameworks = q.compliance_frameworks || profileData.raw?.threats?.organization?.compliance_frameworks || [];
    if (Array.isArray(frameworks)) {
      const fwMap = {
        'HIPAA': 'fw_hipaa', 'PCI-DSS': 'fw_pci', 'PCI DSS': 'fw_pci',
        'CMMC': 'fw_cmmc', 'SOX': 'fw_sox', 'GLBA': 'fw_glba',
        'GDPR': 'fw_gdpr', 'FERPA': 'fw_ferpa', 'NIST CSF': 'fw_nist', 'NIST-CSF': 'fw_nist'
      };
      frameworks.forEach(fw => {
        const id = fwMap[fw];
        if (id) {
          const el = document.getElementById(id);
          if (el && !el.checked) el.checked = true;
        }
      });
    }
  }
}

// ============================================================================
// POPULATE ALL FIELDS FROM SAVED DATA
// ============================================================================

function populateAllFields() {
  SECTIONS.forEach(section => {
    const sectionData = formData[section];
    if (!sectionData || typeof sectionData !== 'object') return;

    Object.entries(sectionData).forEach(([key, value]) => {
      // Handle segments specially
      if (key === 'segments') {
        restoreSegments(value);
        return;
      }

      // Try by ID first
      const element = document.getElementById(key);
      if (element) {
        if (element.type === 'checkbox') {
          element.checked = !!value;
        } else {
          element.value = value ?? '';
        }
        // Re-trigger toggles
        if (element.classList.contains('role-select')) toggleRoleVersion(element);
        if (element.classList.contains('svc-check')) toggleSvcVersion(element);
        return;
      }

      // Handle radio buttons by name (IG1 safeguards use name="ig1_X.X")
      const radios = document.querySelectorAll(`input[name="${key}"]`);
      if (radios.length > 0) {
        radios.forEach(radio => {
          if (radio.value === value) radio.checked = true;
        });
        return;
      }

      // Handle textareas by name (IG1 notes use name="ig1_X.X_notes")
      const textarea = document.querySelector(`textarea[name="${key}"]`);
      if (textarea) textarea.value = value ?? '';
    });
  });
}

// ============================================================================
// COLLECT FORM DATA
// ============================================================================

function collectFormData() {
  // Reset
  SECTIONS.forEach(s => { formData[s] = {}; });

  // Collect all elements with data-section
  document.querySelectorAll('[data-section]').forEach(el => {
    const section = el.dataset.section;
    if (!formData[section]) return;

    if (el.type === 'checkbox') {
      // Use id as key for checkboxes
      if (el.id) formData[section][el.id] = el.checked;
    } else if (el.type === 'radio') {
      if (el.checked) {
        formData[section][el.name] = el.value;
      }
    } else if (el.tagName === 'TEXTAREA' && el.name && !el.id) {
      // IG1 note textareas have name but no id
      formData[section][el.name] = el.value;
    } else if (el.id) {
      formData[section][el.id] = el.value;
    }
  });

  // Also collect IG1 radio buttons that might not have been caught
  document.querySelectorAll('input[type="radio"][data-section="compliance"]:checked').forEach(radio => {
    formData.compliance[radio.name] = radio.value;
  });

  // Collect IG1 note textareas
  document.querySelectorAll('textarea[data-section="compliance"]').forEach(ta => {
    if (ta.name && ta.value) formData.compliance[ta.name] = ta.value;
  });

  // Collect network segments
  formData.network_security.segments = collectSegments();
}

// ============================================================================
// AUTO-SAVE
// ============================================================================

function setupAutoSave() {
  document.querySelectorAll('.field-input, input[type="text"], input[type="number"], input[type="email"], input[type="tel"], input[type="url"], textarea, select').forEach(field => {
    field.addEventListener('input', scheduleAutoSave);
    field.addEventListener('change', scheduleAutoSave);
  });

  document.querySelectorAll('input[type="checkbox"], input[type="radio"]').forEach(field => {
    field.addEventListener('change', scheduleAutoSave);
  });
}

function scheduleAutoSave() {
  clearTimeout(autoSaveTimeout);
  autoSaveTimeout = setTimeout(saveDraft, 1500);
}

// ============================================================================
// SAVE DRAFT
// ============================================================================

async function saveDraft() {
  try {
    collectFormData();

    // Build payload with all 15 DB columns (active + legacy empty)
    const payload = {};
    SECTIONS.forEach(s => { payload[s] = formData[s]; });
    LEGACY_SECTIONS.forEach(s => { payload[s] = payload[s] || {}; });

    const response = await fetch(`/api/intake-form/${profileId}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(payload)
    });

    if (!response.ok) throw new Error('Failed to save');

    const data = await response.json();
    updateProgress(data.completion);
    showSavedIndicator();

    // Notify parent (workspace)
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage({
        type: 'intake-form-saved',
        status: data.completion === 100 ? 'complete' : 'in_progress',
        completion: data.completion
      }, window.location.origin);
    }

  } catch (error) {
    console.error('Error saving form:', error);
    Toast.error('Save Failed', 'Could not save form data');
  }
}

// ============================================================================
// PROGRESS TRACKING
// ============================================================================

function updateProgress(completion) {
  if (completion === undefined) {
    let totalFields = 0;
    let completedFields = 0;
    const countedRadioGroups = new Set();

    document.querySelectorAll('[data-section]').forEach(el => {
      if (el.type === 'radio') {
        if (!countedRadioGroups.has(el.name)) {
          countedRadioGroups.add(el.name);
          totalFields++;
          if (document.querySelector(`input[name="${el.name}"]:checked`)) completedFields++;
        }
      } else if (el.type === 'checkbox') {
        // Don't count individual checkboxes towards completion
      } else {
        totalFields++;
        if (el.value && el.value.trim() !== '') completedFields++;
      }
    });

    completion = totalFields > 0 ? Math.round((completedFields / totalFields) * 100) : 0;
  }

  document.getElementById('progressBar').style.width = `${completion}%`;
  document.getElementById('progressText').textContent = `${completion}% Complete`;
}

// ============================================================================
// COMPLETE FORM
// ============================================================================

async function completeForm() {
  try {
    await saveDraft();

    const response = await fetch(`/api/intake-form/${profileId}/complete`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });

    if (!response.ok) throw new Error('Failed to complete');

    Toast.success('Complete!', 'Form marked as complete');

    if (window.opener && !window.opener.closed) {
      window.opener.postMessage({
        type: 'intake-form-saved',
        status: 'complete',
        completion: 100
      }, window.location.origin);
    }

    downloadPDF();

    setTimeout(() => { window.close(); }, 2000);

  } catch (error) {
    console.error('Error completing form:', error);
    Toast.error('Error', 'Failed to complete form');
  }
}

// ============================================================================
// DOWNLOAD PDF
// ============================================================================

async function downloadPDF() {
  try {
    const response = await fetch(`/api/intake-form/${profileId}/export`, {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    if (!response.ok) throw new Error('Export failed');

    const blob = await response.blob();
    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `intake-form-${profileId}.pdf`;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);
  } catch (error) {
    console.error('Error downloading PDF:', error);
    Toast.error('Error', 'Failed to export PDF');
  }
}

// ============================================================================
// SAVED INDICATOR
// ============================================================================

function showSavedIndicator() {
  const existing = document.querySelector('.saved-indicator');
  if (existing) existing.remove();

  const indicator = document.createElement('div');
  indicator.className = 'saved-indicator';
  indicator.textContent = 'Saved';
  document.body.appendChild(indicator);
  setTimeout(() => indicator.remove(), 2000);
}

// ============================================================================
// INTERVIEW SIMULATOR (unchanged from original)
// ============================================================================

let interviewStakeholders = [];

async function startInterviewSession() {
  try {
    const token = localStorage.getItem('token');
    await loadStakeholders();

    const response = await fetch('/api/interview/start', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ profile_id: profileId, stakeholder_id: 'all' })
    });

    if (response.ok) {
      const data = await response.json();
      interviewSessionId = data.session.id;
      if (data.stakeholders && data.stakeholders.length > 0 && interviewStakeholders.length === 0) {
        interviewStakeholders = data.stakeholders;
        renderStakeholderChips();
      }
    }
  } catch (error) {
    console.error('Error starting interview:', error);
    updateStakeholderChips([{ name: 'Unavailable', role: 'Error loading' }]);
  }
}

async function loadStakeholders() {
  try {
    const token = localStorage.getItem('token');
    const response = await fetch(`/api/interview/stakeholders/${profileId}`, {
      headers: { 'Authorization': `Bearer ${token}` }
    });
    if (response.ok) {
      const data = await response.json();
      interviewStakeholders = data.stakeholders || [];
      renderStakeholderChips();
    }
  } catch (error) {
    console.error('Error loading stakeholders:', error);
  }
}

function renderStakeholderChips() {
  const chipsContainer = document.getElementById('stakeholderChips');
  if (!chipsContainer || interviewStakeholders.length === 0) return;
  chipsContainer.innerHTML = interviewStakeholders.map(s =>
    `<span class="stakeholder-chip" data-name="${s.name}">
      ${s.name}<span class="chip-role">(${s.role})</span>
    </span>`
  ).join('');
}

function highlightStakeholder(name) {
  document.querySelectorAll('.stakeholder-chip').forEach(chip => {
    chip.classList.toggle('active', chip.dataset.name === name);
  });
  setTimeout(() => {
    document.querySelectorAll('.stakeholder-chip.active').forEach(chip => chip.classList.remove('active'));
  }, 3000);
}

async function sendQuestion() {
  const input = document.getElementById('questionInput');
  const question = input.value.trim();
  if (!question || !interviewSessionId) return;

  addMessage('user', question);
  input.value = '';

  const sendBtn = document.getElementById('sendBtn');
  sendBtn.disabled = true;
  sendBtn.textContent = 'Thinking...';

  try {
    const response = await fetch(`/api/interview/${interviewSessionId}/message`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ message: question })
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.error || 'Failed to send message');
    }

    const data = await response.json();
    const label = data.stakeholder_name
      ? `${data.stakeholder_name} (${data.stakeholder_role})`
      : 'Stakeholder';
    addMessage('ai', data.response, label);
    highlightStakeholder(data.stakeholder_name);

  } catch (error) {
    console.error('Error sending question:', error);
    addMessage('ai', 'Sorry, I encountered an error. Please try again.', 'System');
  } finally {
    sendBtn.disabled = false;
    sendBtn.textContent = 'Send';
  }
}

function askQuick(question) {
  document.getElementById('questionInput').value = question;
  sendQuestion();
}

function addMessage(role, text, stakeholderLabel = null) {
  const messagesDiv = document.getElementById('chatMessages');
  const messageDiv = document.createElement('div');
  messageDiv.className = `message message-${role}`;

  const bubble = document.createElement('div');
  bubble.className = 'message-bubble';
  bubble.textContent = text;
  messageDiv.appendChild(bubble);

  if (role === 'ai' && stakeholderLabel) {
    const stakeholder = document.createElement('div');
    stakeholder.className = 'message-stakeholder';
    stakeholder.textContent = `-- ${stakeholderLabel}`;
    messageDiv.appendChild(stakeholder);
  }

  messagesDiv.appendChild(messageDiv);
  messagesDiv.scrollTop = messagesDiv.scrollHeight;
}
