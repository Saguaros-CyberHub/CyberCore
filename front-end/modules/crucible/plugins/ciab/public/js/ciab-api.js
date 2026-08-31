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
    // Opens the combined scan-reports print view — real HTML with a print
    // button, so "Print > Save as PDF" produces the PDF (no server-side PDF
    // generation involved).
    window.open(`/api/profiles/${id}/documents/print`, '_blank');
  }
};

// Generation endpoint
API.generate = async function(config) {
  return API.request('/generate', { method: 'POST', body: config });
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
  async dashboard(scope) {
    const q = scope ? '?section=' + encodeURIComponent(scope) : '';
    return API.request('/instructor/dashboard' + q);
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

// Engagements (Track B1)
// One namespace per route in modules/crucible/plugins/ciab/routes/engagements.js,
// mounted by routes/instructor.js under /api/instructor/engagements. API.request
// (public/js/app.js:16-77) attaches the bearer token, JSON-stringifies `body`
// and throws APIError{message, status, data} — so a 400's err.data.errors and
// err.data.warnings reach the form that raised it without any unwrapping here.
//
// EVERY id GOES THROUGH encodeURIComponent, exactly as list() already does with
// its query parameter. An engagement id is a uuid on the happy path, but the id
// these methods receive comes from a row the page is holding — and a page that
// re-renders from stale state, a hand-typed id, or a future non-uuid identifier
// puts arbitrary text into the path. Unencoded, a '#' truncates the request at
// the fragment, a '?' turns the rest of the path into a query string, and a '/'
// or an encoded '..' re-points the call at a DIFFERENT ROUTE — which on this
// namespace means a POST landing on /reprovision or /retire, both of which
// spend or end capacity. Encoding is one call and removes the whole class.
API.engagements = {
  types()                { return API.request('/instructor/engagements/types'); },
  list(profileId)        { return API.request(`/instructor/engagements?profile_id=${encodeURIComponent(profileId)}`); },
  get(id)                { return API.request(`/instructor/engagements/${encodeURIComponent(id)}`); },
  patch(id, body)        { return API.request(`/instructor/engagements/${encodeURIComponent(id)}`, { method: 'PATCH', body }); },
  create(body)           { return API.request('/instructor/engagements', { method: 'POST', body }); },
  adopt(body)            { return API.request('/instructor/engagements/adopt', { method: 'POST', body }); },
  reprovision(id, force) { return API.request(`/instructor/engagements/${encodeURIComponent(id)}/reprovision`, { method: 'POST', body: { force: !!force } }); },
  retire(id)             { return API.request(`/instructor/engagements/${encodeURIComponent(id)}/retire`, { method: 'POST', body: { confirm: true } }); },
  // B1b's route. Declared with the rest of the namespace so the two halves of
  // the phase do not disagree about the URL; nothing in B1a calls it.
  generateDocs(id, types){ return API.request(`/instructor/engagements/${encodeURIComponent(id)}/documents`, { method: 'POST', body: { types } }); },
};
