/**
 * ============================================================================
 * CYBERHUB - CORE API CLIENT & UTILITIES
 * ============================================================================
 * Core API methods (auth, modules). Plugin-specific methods (profiles,
 * progress, interview, etc.) are loaded from plugin JS files.
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
    },

    // Step 2 of login: verify a TOTP/recovery code with the short-lived
    // mfa-stage token returned by login(). Returns the full session on success.
    async loginMfa(mfaToken, code) {
      return API.request('/auth/login/mfa', {
        method: 'POST',
        headers: { Authorization: `Bearer ${mfaToken}` },
        body: { code }
      });
    },

    // Begin TOTP enrollment. Pass a stageToken for forced enrollment (login
    // page); omit it for self-enrollment (uses the logged-in session).
    async mfaSetup(stageToken) {
      return API.request('/auth/mfa/setup', {
        method: 'POST',
        ...(stageToken ? { headers: { Authorization: `Bearer ${stageToken}` } } : {})
      });
    },

    // Finish enrollment by verifying a code. Returns recovery_codes (once), plus
    // a session token when this was a forced (stageToken) enrollment.
    async mfaVerify(code, stageToken) {
      return API.request('/auth/mfa/verify', {
        method: 'POST',
        ...(stageToken ? { headers: { Authorization: `Bearer ${stageToken}` } } : {}),
        body: { code }
      });
    },

    async mfaDisable(code) {
      return API.request('/auth/mfa/disable', { method: 'POST', body: { code } });
    }
  },

  // Module discovery
  modules: {
    async list() {
      return API.request('/modules');
    }
  },

  // Dashboard — VM workspaces & Guacamole sessions
  dashboard: {
    async listVms() {
      return API.request('/dashboard/vms');
    },

    async requestGuacSession(vmId) {
      return API.request(`/dashboard/vms/${encodeURIComponent(vmId)}/guac-session`, {
        method: 'POST'
      });
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

    // Titles/messages often carry API error text — never trust it as HTML.
    const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.setAttribute('role', type === 'error' ? 'alert' : 'status');
    toast.innerHTML = `
      <span class="toast-icon">${icons[type] || 'ℹ'}</span>
      <div class="toast-content">
        <div class="toast-title">${esc(title)}</div>
        <div class="toast-message">${esc(message)}</div>
      </div>
      <button class="toast-close" aria-label="Dismiss notification" onclick="this.parentElement.remove()">✕</button>
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
 * Async confirmation modal — drop-in replacement for window.confirm().
 * Usage: if (await Confirm.show({ title: 'Delete asset?', message: '…', danger: true })) { … }
 * Reuses the shared .modal-overlay/.modal styles so dark mode just works.
 */
const Confirm = {
  show({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false } = {}) {
    return new Promise(resolve => {
      const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay active';
      overlay.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="confirmModalTitle" style="max-width: 420px;">
          <div class="modal-header">
            <h3 class="modal-title" id="confirmModalTitle">${esc(title)}</h3>
          </div>
          <div class="modal-body">${esc(message)}</div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-action="cancel">${esc(cancelText)}</button>
            <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-action="confirm">${esc(confirmText)}</button>
          </div>
        </div>
      `;
      const prevFocus = document.activeElement;
      const close = result => {
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        if (prevFocus && prevFocus.focus) prevFocus.focus();
        resolve(result);
      };
      const onKey = e => {
        if (e.key === 'Escape') close(false);
        if (e.key === 'Enter') close(true);
      };
      overlay.addEventListener('click', e => {
        if (e.target === overlay) close(false);
        const action = e.target.closest('[data-action]')?.dataset.action;
        if (action === 'confirm') close(true);
        if (action === 'cancel') close(false);
      });
      document.addEventListener('keydown', onKey);
      document.body.appendChild(overlay);
      overlay.querySelector('[data-action="confirm"]').focus();
    });
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
      window.dispatchEvent(new Event('authReady'));
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
  },

  // Toggle a button into a busy/loading state while an async action runs.
  // Usage: Utils.setBtnLoading(btn, true, 'Saving…'); … Utils.setBtnLoading(btn, false);
  setBtnLoading(btn, loading, busyText) {
    if (!btn) return;
    if (loading) {
      btn.dataset.restoreHtml = btn.innerHTML;
      btn.disabled = true;
      btn.classList.add('btn-loading');
      btn.innerHTML = `<span class="btn-spinner" aria-hidden="true"></span>${this.escapeHtml(busyText || 'Working…')}`;
    } else {
      btn.disabled = false;
      btn.classList.remove('btn-loading');
      if (btn.dataset.restoreHtml !== undefined) {
        btn.innerHTML = btn.dataset.restoreHtml;
        delete btn.dataset.restoreHtml;
      }
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
  module.exports = { API, Toast, Confirm, Auth, Utils, Validator };
}