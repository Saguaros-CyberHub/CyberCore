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
    }
  },

  // Module discovery
  modules: {
    async list() {
      return API.request('/modules');
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