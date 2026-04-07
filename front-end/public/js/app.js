/**
 * ============================================================================
 * CLINIC-IN-A-BOX - API CLIENT & UTILITIES
 * ============================================================================
 * UPDATED: Added missing methods for dashboard.html compatibility
 */

const API = {
  baseUrl: '/api',
  
  /**
   * Make an API request
   */
  async request(endpoint, options = {}) {
    const url = `${this.baseUrl}${endpoint}`;
    
    // Get token from localStorage
    const token = localStorage.getItem('token');
    
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      },
      credentials: 'include',
      ...options
    };
    
    // Add Authorization header if token exists
    if (token) {
      config.headers['Authorization'] = `Bearer ${token}`;
    }

    if (options.body && typeof options.body === 'object') {
      config.body = JSON.stringify(options.body);
    }

    try {
      const response = await fetch(url, config);
      const data = await response.json();

      if (!response.ok) {
        // Handle auth errors
        if (response.status === 401) {
          const code = data.code;
          if (code === 'TOKEN_EXPIRED' || code === 'INVALID_TOKEN' || code === 'NO_TOKEN') {
            // Redirect to login
            if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
              window.location.href = '/login?expired=true';
            }
          }
        }
        throw new APIError(data.error || 'Request failed', response.status, data);
      }

      return data;
    } catch (error) {
      if (error instanceof APIError) throw error;
      throw new APIError('Network error', 0, { original: error.message });
    }
  },

  // Auth endpoints
  auth: {
    async login(email, password) {
      return API.request('/auth/login', {
        method: 'POST',
        body: { email, password }
      });
    },

    async register(data) {
      return API.request('/auth/register', {
        method: 'POST',
        body: data
      });
    },

    async logout() {
      return API.request('/auth/logout', { method: 'POST' });
    },

    async me() {
      return API.request('/auth/me');
    },

    async verify() {
      return API.request('/auth/verify');
    },

    async updateProfile(data) {
      return API.request('/auth/profile', {
        method: 'PUT',
        body: data
      });
    },

    async changePassword(currentPassword, newPassword) {
      return API.request('/auth/password', {
        method: 'PUT',
        body: { currentPassword, newPassword }
      });
    }
  },

  // Profile endpoints
  profiles: {
    async list(params = {}) {
      const query = new URLSearchParams(params).toString();
      return API.request(`/profiles${query ? '?' + query : ''}`);
    },

    async get(id) {
      return API.request(`/profiles/${id}`);
    },

    async create(data) {
      return API.request('/profiles', {
        method: 'POST',
        body: data
      });
    },

    async update(id, data) {
      return API.request(`/profiles/${id}`, {
        method: 'PUT',
        body: data
      });
    },

    async delete(id) {
      return API.request(`/profiles/${id}`, { method: 'DELETE' });
    },

    // ========== ADDED: Missing methods for dashboard.html ==========
    
    // Get profile statistics - now calls /stats/summary
    async stats() {
      return API.request('/profiles/stats/summary');
    },

    // Get recent profiles
    async recent(limit = 5) {
      return API.request(`/profiles/recent?limit=${limit}`);
    },

    // Download profile as JSON
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

    // List policy documents for a profile
    async policies(id) {
      return API.request(`/profiles/${id}/policies`);
    },

    // Generate (or regenerate) policies for an existing profile
    async generatePolicies(id) {
      return API.request(`/profiles/${id}/policies/generate`, { method: 'POST' });
    },

    // Get single policy HTML by slug
    async policyHtml(id, slug) {
      const response = await fetch(`/api/profiles/${id}/policies/${slug}`, {
        headers: { 'Authorization': `Bearer ${localStorage.getItem('token')}` }
      });
      if (!response.ok) throw new Error('Failed to fetch policy');
      return response.text();
    },

    // List generated documents (Nessus, ZAP, NMAP)
    async documents(id) {
      return API.request(`/profiles/${id}/documents`);
    },

    // Download combined PDF of all security documents
    downloadDocumentsPdf(id) {
      const a = document.createElement('a');
      a.href = `/api/profiles/${id}/documents/pdf`;
      a.download = 'Security_Documents.pdf';
      // Need auth header, so use fetch
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
  },
  
  

  // Generation endpoint
  async generate(config) {
    return API.request('/generate', {
      method: 'POST',
      body: config
    });
  },

  // Chat endpoint
  async chat(message, sessionId) {
    return API.request('/chat', {
      method: 'POST',
      body: { message, sessionId }
    });
  },

  // Config endpoint
  async getConfig() {
    return API.request('/config');
  },

  // ========== ADDED: Progress tracking for Training Guidance ==========
  progress: {
    async get(profileId) {
      return API.request(`/progress/${profileId}`);
    },

    async update(profileId, partNumber, data) {
      return API.request(`/progress/${profileId}/${partNumber}`, {
        method: 'PUT',
        body: data
      });
    },

    async submit(profileId, partNumber) {
      return API.request(`/progress/${profileId}/${partNumber}/submit`, {
        method: 'POST'
      });
    },

    async summary() {
      return API.request('/progress/summary');
    }
  },

  // ========== ADDED: Interview simulation ==========
  interview: {
    async start(profileId, stakeholderId) {
      return API.request('/interview/start', {
        method: 'POST',
        body: { profile_id: profileId, stakeholder_id: stakeholderId }
      });
    },

    async message(sessionId, message) {
      return API.request(`/interview/${sessionId}/message`, {
        method: 'POST',
        body: { message }
      });
    },

    async end(sessionId) {
      return API.request(`/interview/${sessionId}/end`, {
        method: 'POST'
      });
    },

    async sessions(profileId) {
      return API.request(`/interview/sessions/${profileId}`);
    }
  },

  // ========== ADDED: Instructor functions ==========
  instructor: {
    async dashboard() {
      return API.request('/instructor/dashboard');
    },

    async review(progressId, data) {
      return API.request(`/instructor/review/${progressId}`, {
        method: 'POST',
        body: data
      });
    },

    async assign(data) {
      return API.request('/instructor/assign', {
        method: 'POST',
        body: data
      });
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
  },
	// ========== ADDED: Intake Form ==========
  intakeForm: {
    async get(profileId) {
      return API.request(`/intake-form/${profileId}`);
    },

    async update(profileId, data) {
      return API.request(`/intake-form/${profileId}`, {
        method: 'PUT',
        body: data
      });
    },

    async getStatus(profileId) {
      return API.request(`/intake-form/${profileId}/status`);
    },

    async complete(profileId) {
      return API.request(`/intake-form/${profileId}/complete`, {
        method: 'POST'
      });
    },

    async export(profileId) {
      // Direct download - not JSON response
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
  }
};

/**
 * Custom API Error class
 */
class APIError extends Error {
  constructor(message, status, data) {
    super(message);
    this.name = 'APIError';
    this.status = status;
    this.data = data;
  }
}

/**
 * Toast notification system
 */
const Toast = {
  container: null,

  init() {
    if (!this.container) {
      this.container = document.createElement('div');
      this.container.className = 'toast-container';
      document.body.appendChild(this.container);
    }
  },

  show(type, title, message, duration = 5000) {
    this.init();
    
    const icons = {
      success: '✓',
      error: '✕',
      warning: '⚠',
      info: 'ℹ'
    };

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || 'ℹ'}</span>
      <div class="toast-content">
        <div class="toast-title">${title}</div>
        <div class="toast-message">${message}</div>
      </div>
      <button class="toast-close" onclick="this.parentElement.remove()">✕</button>
    `;

    this.container.appendChild(toast);

    if (duration > 0) {
      setTimeout(() => toast.remove(), duration);
    }

    return toast;
  },

  success(title, message) {
    return this.show('success', title, message);
  },

  error(title, message) {
    return this.show('error', title, message);
  },

  warning(title, message) {
    return this.show('warning', title, message);
  },

  info(title, message) {
    return this.show('info', title, message);
  }
};

/**
 * Auth helper functions
 */
const Auth = {
  user: null,

  async check() {
    try {
      const data = await API.auth.me();
      this.user = data.user;
      return true;
    } catch (error) {
      this.user = null;
      return false;
    }
  },

  async requireAuth() {
    const isLoggedIn = await this.check();
    if (!isLoggedIn) {
      window.location.href = '/login';
      return false;
    }
    return true;
  },

  async logout() {
    try {
      await API.auth.logout();
    } catch (e) {
      // Ignore errors
    }
    
    // Clear token from localStorage
    localStorage.removeItem('token');
    
    this.user = null;
    window.location.href = '/login';
  },

  getUser() {
    return this.user;
  },
  
  getToken() {
    return localStorage.getItem('token');
  },

  isAdmin() {
    return this.user?.role === 'admin';
  },

  isInstructor() {
    return this.user?.role === 'instructor' || this.user?.role === 'admin';
  },

  // Added for compatibility
  isAuthenticated() {
    return this.user !== null;
  }
};

/**
 * Utility functions
 */
const Utils = {
  formatDate(dateString) {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleDateString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });
  },

  formatDateTime(dateString) {
    if (!dateString) return '-';
    return new Date(dateString).toLocaleString('en-US', {
      month: 'short',
      day: 'numeric',
      year: 'numeric',
      hour: 'numeric',
      minute: '2-digit'
    });
  },

  debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        clearTimeout(timeout);
        func(...args);
      };
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
    };
  },

  escapeHtml(text) {
    if (!text) return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  getQueryParam(name) {
    const params = new URLSearchParams(window.location.search);
    return params.get(name);
  },

  // Get initials from name
  getInitials(firstName, lastName) {
    return `${(firstName || '')[0] || ''}${(lastName || '')[0] || ''}`.toUpperCase() || '??';
  },

  // Badge class for client type
  getClientTypeBadgeClass(type) {
    const classes = {
      'SMB': 'badge-smb',
      'NonProfit': 'badge-nonprofit',
      'Utility_IT_OT': 'badge-utility',
      'K12': 'badge-k12'
    };
    return classes[type] || 'badge-primary';
  },

  // Badge class for difficulty
  getDifficultyBadgeClass(difficulty) {
    const classes = {
      'beginner': 'badge-beginner',
      'intermediate': 'badge-intermediate',
      'advanced': 'badge-advanced'
    };
    return classes[difficulty] || 'badge-primary';
  },

  // Show loading state
  showLoading(elementId) {
    const el = document.getElementById(elementId);
    if (el) {
      el.innerHTML = '<div class="loading">Loading...</div>';
    }
  },

  // Show error state
  showError(elementId, message) {
    const el = document.getElementById(elementId);
    if (el) {
      el.innerHTML = `<div class="error">${this.escapeHtml(message)}</div>`;
    }
  }
};

/**
 * Form validation helpers
 */
const Validator = {
  email(value) {
    const regex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return regex.test(value);
  },

  password(value) {
    // At least 8 chars, 1 uppercase, 1 lowercase, 1 number
    const regex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
    return regex.test(value);
  },

  required(value) {
    return value !== null && value !== undefined && value.toString().trim() !== '';
  },

  minLength(value, min) {
    return value && value.length >= min;
  },

  maxLength(value, max) {
    return !value || value.length <= max;
  }
};

// Export for module usage if needed
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { API, Toast, Auth, Utils, Validator };
}