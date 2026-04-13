// ============================================================================
// INTAKE FORM - Frontend Logic (V7.2 - 15 Sections)
// ============================================================================

let profileId = null;
let profileData = null;
let formData = {
  company_info: {},
  security_policies: {},
  data_management: {},
  network_security: {},
  wireless: {},
  endpoint_security: {},
  compliance: {},
  software_assets: {},
  vuln_management: {},
  admin_privileges: {},
  secure_config: {},
  email_web: {},
  network_ports: {},
  network_devices: {},
  pentesting: {}
};
let autoSaveTimeout = null;
let interviewSessionId = null;

// ============================================================================
// INITIALIZATION
// ============================================================================

document.addEventListener('DOMContentLoaded', async () => {
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
      Object.keys(formData).forEach(section => {
        if (data.form_data[section]) {
          formData[section] = data.form_data[section];
        }
      });
    }
    
    // Pre-fill company name
    const companyName = profileData?.quick?.company_name || 'Unknown Organization';
    document.getElementById('companyName').textContent = companyName;
    const companyInput = document.getElementById('company_name');
    if (companyInput) companyInput.value = companyName;
    
    // Pre-fill industry if available
    if (profileData?.quick?.industry) {
      const industryInput = document.getElementById('industry_sector');
      if (industryInput) industryInput.value = profileData.quick.industry;
    }
    
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
// POPULATE ALL FIELDS
// ============================================================================

function populateAllFields() {
  Object.keys(formData).forEach(section => {
    const sectionData = formData[section];
    if (!sectionData) return;
    
    Object.entries(sectionData).forEach(([key, value]) => {
      // Handle text/number inputs
      const element = document.getElementById(key);
      if (element) {
        if (element.type === 'checkbox') {
          element.checked = !!value;
        } else {
          element.value = value;
        }
        return;
      }
      
      // Handle radio buttons by name
      const radios = document.querySelectorAll(`input[name="${key}"]`);
      radios.forEach(radio => {
        if (radio.value === value) {
          radio.checked = true;
        }
      });
    });
  });
}

// ============================================================================
// AUTO-SAVE
// ============================================================================

function setupAutoSave() {
  // Text inputs and textareas
  document.querySelectorAll('.field-input, input[type="text"], input[type="number"], input[type="email"], input[type="tel"], input[type="url"], textarea').forEach(field => {
    field.addEventListener('input', () => {
      clearTimeout(autoSaveTimeout);
      autoSaveTimeout = setTimeout(saveDraft, 2000);
    });
  });
  
  // Checkboxes and radios
  document.querySelectorAll('input[type="checkbox"], input[type="radio"]').forEach(field => {
    field.addEventListener('change', () => {
      clearTimeout(autoSaveTimeout);
      autoSaveTimeout = setTimeout(saveDraft, 1000);
    });
  });
}

// ============================================================================
// COLLECT FORM DATA
// ============================================================================

function collectFormData() {
  // Reset all sections
  Object.keys(formData).forEach(section => {
    formData[section] = {};
  });
  
  // Collect all text/number inputs by data-section attribute
  document.querySelectorAll('[data-section]').forEach(element => {
    const section = element.dataset.section;
    const id = element.id;
    
    if (!section || !formData[section]) return;
    
    if (element.type === 'checkbox') {
      formData[section][id] = element.checked;
    } else if (element.type === 'radio') {
      if (element.checked) {
        formData[section][element.name] = element.value;
      }
    } else {
      formData[section][id] = element.value;
    }
  });
  
  // Collect radio buttons without data-section (using name attribute mapping)
  const radioGroups = {};
  document.querySelectorAll('input[type="radio"]:checked').forEach(radio => {
    if (radio.dataset.section) {
      formData[radio.dataset.section][radio.name] = radio.value;
    }
  });
}

// ============================================================================
// SAVE DRAFT
// ============================================================================

async function saveDraft() {
  try {
    collectFormData();
    
    const response = await fetch(`/api/intake-form/${profileId}`, {
      method: 'PUT',
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(formData)
    });
    
    if (!response.ok) throw new Error('Failed to save');
    
    const data = await response.json();
    updateProgress(data.completion);
    showSavedIndicator();
    
    // Notify parent window (workspace) that form was saved
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
    
    // Count all inputs with data-section
    document.querySelectorAll('[data-section]').forEach(element => {
      if (element.type === 'checkbox' || element.type === 'radio') {
        // Only count radio groups once
        if (element.type === 'radio') {
          const groupName = element.name;
          if (!document.querySelector(`input[name="${groupName}"].counted`)) {
            totalFields++;
            element.classList.add('counted');
            if (document.querySelector(`input[name="${groupName}"]:checked`)) {
              completedFields++;
            }
          }
        }
      } else {
        totalFields++;
        if (element.value && element.value.trim() !== '') {
          completedFields++;
        }
      }
    });
    
    // Clean up counted class
    document.querySelectorAll('.counted').forEach(el => el.classList.remove('counted'));
    
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
    
    // Notify parent window (workspace) that form is complete
    if (window.opener && !window.opener.closed) {
      window.opener.postMessage({
        type: 'intake-form-saved',
        status: 'complete',
        completion: 100
      }, window.location.origin);
    }
    
    downloadPDF();
    
    setTimeout(() => {
      window.close();
    }, 2000);
    
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
  indicator.textContent = '✓ Saved';
  document.body.appendChild(indicator);
  
  setTimeout(() => indicator.remove(), 2000);
}

// ============================================================================
// INTERVIEW SIMULATOR
// ============================================================================

let interviewStakeholders = [];

async function startInterviewSession() {
  try {
    const token = localStorage.getItem('token');

    // Fetch stakeholders for the profile
    await loadStakeholders();

    // Start the interview session in "all stakeholders" group briefing mode
    const response = await fetch('/api/interview/start', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ profile_id: profileId, stakeholder_id: 'all' })
    });

    if (response.ok) {
      const data = await response.json();
      interviewSessionId = data.session.id;

      // Use stakeholders from session start if we didn't get them already
      if (data.stakeholders && data.stakeholders.length > 0 && interviewStakeholders.length === 0) {
        interviewStakeholders = data.stakeholders;
        renderStakeholderChips();
      }
    } else {
      console.error('Failed to start interview session:', response.status);
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
  // Remove highlight after 3 seconds
  setTimeout(() => {
    document.querySelectorAll('.stakeholder-chip.active').forEach(chip => {
      chip.classList.remove('active');
    });
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
