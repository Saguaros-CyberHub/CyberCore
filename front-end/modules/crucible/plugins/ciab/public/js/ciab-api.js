/**
 * CIAB Plugin — Frontend API Extensions
 * Loaded AFTER app.js on CIAB pages. Extends the global API object
 * with CIAB-specific methods (profiles, progress, interview, etc.)
 */

// Profile endpoints
API.profiles = {
  async list(params = {}) {
    const query = new URLSearchParams(params).toString();
    return API.request(`/profiles${query ? '?' + query : ''}`);
  },

  async get(id) {
    return API.request(`/profiles/${id}`);
  },

  async create(data) {
    return API.request('/profiles', { method: 'POST', body: data });
  },

  async update(id, data) {
    return API.request(`/profiles/${id}`, { method: 'PUT', body: data });
  },

  async delete(id) {
    return API.request(`/profiles/${id}`, { method: 'DELETE' });
  },

  async stats() {
    return API.request('/profiles/stats/summary');
  },

  async recent(limit = 5) {
    return API.request(`/profiles/recent?limit=${limit}`);
  },

  async download(id) {
    const data = await API.request(`/profiles/${id}`);
    const profile = data.profile || data;
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${(profile.company_name || profile.companyName || profile.name || 'profile').replace(/[^a-z0-9]/gi, '_')}.json`;
    a.click();
    URL.revokeObjectURL(url);
  },

  async policies(id) {
    return API.request(`/profiles/${id}/policies`);
  },

  async generatePolicies(id, options = {}) {
    return API.request(`/profiles/${id}/policies/generate`, { method: 'POST', body: options });
  },

  async policyHtml(id, slug) {
    const response = await fetch(`/api/profiles/${id}/policies/${slug}`, {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    });
    if (!response.ok) throw new Error('Failed to fetch policy');
    return response.text();
  },

  async documents(id) {
    return API.request(`/profiles/${id}/documents`);
  },

  downloadDocumentsPdf(id) {
    const a = document.createElement('a');
    a.href = `/api/profiles/${id}/documents/pdf`;
    a.download = 'Security_Documents.pdf';
    fetch(`/api/profiles/${id}/documents/pdf`, {
      headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
    }).then(async r => {
      if (!r.ok) {
        const errData = await r.json().catch(() => ({}));
        throw new Error(errData.error || `PDF generation failed (${r.status})`);
      }
      return r.blob();
    }).then(blob => {
      const url = URL.createObjectURL(blob);
      a.href = url;
      a.click();
      URL.revokeObjectURL(url);
    }).catch(err => {
      console.error('PDF download error:', err);
      if (typeof Toast !== 'undefined') Toast.error('Download Failed', err.message);
    });
  }
};

// Generation endpoint
API.generate = async function(config) {
  return API.request('/generate', { method: 'POST', body: config });
};

// Chat endpoint
API.chat = async function(message, sessionId) {
  return API.request('/chat', { method: 'POST', body: { message, sessionId } });
};

// Config endpoint
API.getConfig = async function() {
  return API.request('/config');
};

// Progress tracking
API.progress = {
  async get(profileId) {
    return API.request(`/progress/${profileId}`);
  },
  async update(profileId, partNumber, data) {
    return API.request(`/progress/${profileId}/${partNumber}`, { method: 'PUT', body: data });
  },
  async submit(profileId, partNumber) {
    return API.request(`/progress/${profileId}/${partNumber}/submit`, { method: 'POST' });
  },
  async summary() {
    return API.request('/progress/summary');
  }
};

// Interview simulation
API.interview = {
  async start(profileId, stakeholderId) {
    return API.request('/interview/start', {
      method: 'POST',
      body: { profile_id: profileId, stakeholder_id: stakeholderId }
    });
  },
  async message(sessionId, message) {
    return API.request(`/interview/${sessionId}/message`, { method: 'POST', body: { message } });
  },
  async end(sessionId) {
    return API.request(`/interview/${sessionId}/end`, { method: 'POST' });
  },
  async sessions(profileId) {
    return API.request(`/interview/sessions/${profileId}`);
  },
  async stakeholders(profileId) {
    return API.request(`/interview/stakeholders/${profileId}`);
  }
};

// Instructor functions
API.instructor = {
  async dashboard() {
    return API.request('/instructor/dashboard');
  },
  async review(progressId, data) {
    return API.request(`/instructor/review/${progressId}`, { method: 'POST', body: data });
  },
  async assign(data) {
    return API.request('/instructor/assign', { method: 'POST', body: data });
  },
  async generateDocuments(profileId) {
    return API.request('/instructor/generate-documents', {
      method: 'POST',
      body: { profile_id: profileId }
    });
  },
  async studentProgress(studentId) {
    return API.request(`/instructor/student/${studentId}/progress`);
  },
  async rubric(profileId) {
    return API.request(`/instructor/rubric/${profileId}`);
  }
};

// Intake Form
API.intakeForm = {
  async get(profileId) {
    return API.request(`/intake-form/${profileId}`);
  },
  async update(profileId, data) {
    return API.request(`/intake-form/${profileId}`, { method: 'PUT', body: data });
  },
  async getStatus(profileId) {
    return API.request(`/intake-form/${profileId}/status`);
  },
  async complete(profileId) {
    return API.request(`/intake-form/${profileId}/complete`, { method: 'POST' });
  },
  async export(profileId) {
    const token = localStorage.getItem('token');
    const response = await fetch(`${API.baseUrl}/intake-form/${profileId}/export`, {
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    });
    if (!response.ok) {
      const error = await response.json();
      throw new APIError(error.error || 'Export failed', response.status, error);
    }
    return await response.blob();
  }
};
