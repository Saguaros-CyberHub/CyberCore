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
      ...options,
      credentials: 'include',
      headers: {
        'Content-Type': 'application/json',
        // Session token is the default Authorization; an explicit header in
        // options (e.g. an mfa/enroll stage token) takes precedence.
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...options.headers
      }
    };

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
          if (code === 'TOKEN_EXPIRED' || code === 'INVALID_TOKEN') {
            if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
              window.location.href = '/login?expired=true';
            }
          } else if (code === 'NO_TOKEN') {
            if (window.location.pathname !== '/login' && window.location.pathname !== '/register') {
              window.location.href = '/login';
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
    },

    // Replace a temporary password using the short-lived pwchange-stage token
    // login() returned instead of a session. Returns the full session on success.
    async setInitialPassword(stageToken, newPassword) {
      return API.request('/auth/password/initial', {
        method: 'POST',
        headers: { Authorization: `Bearer ${stageToken}` },
        body: { newPassword }
      });
    },

    // Redeem a single-use activation link and set a first password. No auth
    // header — the token in the body IS the authentication, because the
    // recipient has no credential yet.
    async activate(token, newPassword) {
      return API.request('/auth/activate', {
        method: 'POST',
        body: { token, newPassword }
      });
    }
  },

  // Module discovery
  modules: {
    // asStudent forwards Student View to the server. The module list is now
    // filtered per user -- Clinic-in-a-Box only appears for someone enrolled --
    // so without this an instructor previewing as a student would still be
    // served their own menu and the preview would stop being faithful.
    async list({ asStudent = false } = {}) {
      return API.request(asStudent ? '/modules?view=student' : '/modules');
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
  },

  // Global AI assistant. Layout.sendChat() calls this from the chat widget,
  // which is injected on EVERY page — so it has to live in the core client.
  // It used to be defined only in the CIAB plugin's ciab-api.js, which the hub
  // never loads, so the widget threw "API.chat is not a function" everywhere
  // outside /ciab/* and showed "having trouble connecting" instead.
  async chat(message, sessionId) {
    return API.request('/chat', { method: 'POST', body: { message, sessionId } });
  },

  // Is an LLM actually configured on this deployment? Used to hide the chat
  // launcher entirely rather than offer a button that always fails.
  async chatStatus() {
    return API.request('/chat/status');
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
  /**
   * `checkbox: { label, checked }` adds one opt-in toggle to the dialog, for a
   * destructive action with a meaningful variant (e.g. "also reset flags").
   *
   * Resolving stays backward compatible with the 26 existing
   * `if (!await Confirm.show(…))` call sites: cancel is still false, and confirm
   * is still `true` UNLESS a checkbox was requested, in which case it is
   * `{ checked }` — an object, so it is truthy either way.
   */
  show({ title = 'Are you sure?', message = '', confirmText = 'Confirm', cancelText = 'Cancel', danger = false, checkbox = null } = {}) {
    return new Promise(resolve => {
      const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
      const overlay = document.createElement('div');
      overlay.className = 'modal-overlay active';
      overlay.innerHTML = `
        <div class="modal" role="dialog" aria-modal="true" aria-labelledby="confirmModalTitle" style="max-width: 420px;">
          <div class="modal-header">
            <h3 class="modal-title" id="confirmModalTitle">${esc(title)}</h3>
          </div>
          <div class="modal-body">${esc(message)}${checkbox ? `
            <label style="display:flex; align-items:center; gap:0.5rem; margin-top:0.9rem; font-size:0.85rem; cursor:pointer;">
              <input type="checkbox" data-role="confirm-checkbox"${checkbox.checked ? ' checked' : ''}>
              <span>${esc(checkbox.label || '')}</span>
            </label>` : ''}</div>
          <div class="modal-footer">
            <button type="button" class="btn btn-secondary" data-action="cancel">${esc(cancelText)}</button>
            <button type="button" class="btn ${danger ? 'btn-danger' : 'btn-primary'}" data-action="confirm">${esc(confirmText)}</button>
          </div>
        </div>
      `;
      const box = overlay.querySelector('[data-role="confirm-checkbox"]');
      // Read the box at close time, not at build time — Enter can confirm the
      // dialog after the user has toggled it.
      const accept = () => (checkbox ? { checked: !!(box && box.checked) } : true);
      const prevFocus = document.activeElement;
      const close = result => {
        overlay.remove();
        document.removeEventListener('keydown', onKey);
        if (prevFocus && prevFocus.focus) prevFocus.focus();
        resolve(result);
      };
      const onKey = e => {
        if (e.key === 'Escape') close(false);
        // Space toggles the checkbox; Enter while it is focused must not also
        // submit the dialog out from under the user.
        if (e.key === 'Enter' && e.target !== box) close(accept());
      };
      overlay.addEventListener('click', e => {
        if (e.target === overlay) close(false);
        const action = e.target.closest('[data-action]')?.dataset.action;
        if (action === 'confirm') close(accept());
        if (action === 'cancel') close(false);
      });
      document.addEventListener('keydown', onKey);
      document.body.appendChild(overlay);
      overlay.querySelector('[data-action="confirm"]').focus();
    });
  }
};

/**
 * Modal controller for the shared .modal-overlay pattern.
 * Usage: Modal.open('assignProfileModal') / Modal.close('assignProfileModal').
 *
 * Legacy pages still open overlays with classList.add('active') directly, so
 * the document-level Esc / backdrop-click / focus-trap handlers below derive
 * everything from DOM state, never from internal bookkeeping. Opener-focus
 * restore is the one thing only Modal.open() can provide. A modal that must
 * not be dismissed mid-flow (multi-step import wizards) opts out with the
 * data-modal-static attribute.
 */
const Modal = {
  // Who had focus before open() — restored on close(). WeakMap keyed by the
  // overlay element, so a removed overlay cannot leak its opener.
  _openers: new WeakMap(),

  // Visible, tabbable descendants of `scope`, in DOM order.
  _focusables(scope) {
    const sel = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])';
    return [...scope.querySelectorAll(sel)].filter(el => el.offsetParent !== null);
  },

  open(id) {
    const overlay = document.getElementById(id);
    if (!overlay) return;
    this._openers.set(overlay, document.activeElement);
    overlay.classList.add('active');
    overlay.removeAttribute('aria-hidden');
    document.body.style.overflow = 'hidden';
    // Focus the first control inside the dialog box; fall back to the overlay.
    const box = overlay.querySelector('.modal, .modal-content') || overlay;
    const first = this._focusables(box)[0] || overlay;
    if (first.focus) first.focus();
  },

  // Accepts an id or the overlay element itself (the document handlers below
  // already hold the element).
  close(id) {
    const overlay = typeof id === 'string' ? document.getElementById(id) : id;
    if (!overlay) return;
    overlay.classList.remove('active');
    // No aria-hidden stamp here: without .active the overlay is display:none,
    // which already removes it from the accessibility tree — and legacy pages
    // reopen via classList.add('active') alone, so a stamped attribute would
    // never be cleared and the reopened modal would be invisible to AT.
    const opener = this._openers.get(overlay);
    this._openers.delete(overlay);
    if (opener && opener.focus) opener.focus();
    // Modals can stack (e.g. a Confirm above a form modal) — release the body
    // scroll lock only once no active overlay remains anywhere in the DOM.
    if (!document.querySelector('.modal-overlay.active')) {
      document.body.style.overflow = '';
    }
  }
};

// Installed unconditionally at load, NOT lazily from open(): overlays opened
// by legacy classList code must get Esc/backdrop/trap behavior too.
document.addEventListener('keydown', e => {
  const actives = [...document.querySelectorAll('.modal-overlay.active')];
  if (!actives.length) return;
  if (e.key === 'Escape') {
    // Esc acts on the TOPMOST overlay only. If that one is static, nothing
    // happens — reaching through it to close a dialog underneath would
    // dismiss something the user cannot even see.
    const top = actives[actives.length - 1];
    if (!top.hasAttribute('data-modal-static')) Modal.close(top);
  } else if (e.key === 'Tab') {
    // Cycle focus within the topmost overlay instead of tabbing behind it.
    const top = actives[actives.length - 1];
    const items = Modal._focusables(top);
    if (!items.length) return;
    const first = items[0];
    const last = items[items.length - 1];
    const outside = !top.contains(document.activeElement);
    if (e.shiftKey && (document.activeElement === first || outside)) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && (document.activeElement === last || outside)) {
      e.preventDefault();
      first.focus();
    }
  }
});

// Backdrop close pairs mousedown with click: a text-selection drag that
// starts inside the dialog and releases over the backdrop fires click on the
// overlay (common-ancestor rule) and must NOT dismiss the modal.
document.addEventListener('mousedown', e => {
  Modal._downTarget = e.target;
});

document.addEventListener('click', e => {
  // Backdrop click: the overlay ITSELF is the target, not a child of it.
  const t = e.target;
  if (t instanceof Element && t.classList.contains('modal-overlay') &&
      t.classList.contains('active') && !t.hasAttribute('data-modal-static') &&
      Modal._downTarget === t) {
    Modal.close(t);
  }
});

/**
 * Student View — an instructor-facing PRESENTATION mode.
 *
 * Its only job is to make the interface look the way a student's does, so a
 * lecture recording does not show instructor-only navigation that the audience
 * cannot find on their own screens. Think of D2L's Student View: the
 * staff-specific chrome goes away, everything a student would normally see
 * stays.
 *
 * It is NOT a permission change and NOT impersonation. The instructor stays
 * signed in as themselves and keeps every bit of access they had — nothing is
 * blocked, no request is refused, no page redirects. Only what is DRAWN
 * changes. That matters because this gets toggled mid-recording: a mode that
 * started returning 403s would ruin the take.
 *
 * Because the server is not involved, the flag is plain localStorage, next to
 * `ciab-theme`. It survives navigation for the length of a recording session.
 */
const ViewMode = {
  KEY: 'cc-student-view',
  VALUE: '1',

  isActive() {
    try { return localStorage.getItem(this.KEY) === this.VALUE; } catch (_) { return false; }
  },

  // Who is offered the toggle. Students and unprivileged users have no
  // instructor chrome to hide, so it would do nothing for them.
  canPreview(u) {
    return !!u && (u.role === 'admin' || u.role === 'instructor');
  },

  enter() { this._write(true);  this._reload(); },
  exit()  { this._write(false); this._reload(); },

  // Silent — no reload. Used by logout and by the self-heal in Auth.check(),
  // where reloading would loop.
  clear() { this._write(false); },

  _write(on) {
    try {
      if (on) localStorage.setItem(this.KEY, this.VALUE);
      else localStorage.removeItem(this.KEY);
    } catch (_) { /* private mode — the toggle simply won't stick */ }
    // The sidebar payload is per-user AND per-view now, and _reload() below
    // does not clear sessionStorage — so without this, toggling Student View
    // would re-render the cached menu and appear to do nothing.
    Auth.clearSessionCaches();
  },

  _reload() {
    // Required, not cosmetic: essentially every page reads Auth.getUser().role
    // once at DOMContentLoaded and never re-renders.
    window.location.reload();
  }
};

// localStorage fires `storage` in OTHER tabs only, so a second window left open
// on the same account follows along instead of showing a stale layout.
window.addEventListener('storage', e => {
  if (e.key === ViewMode.KEY) window.location.reload();
});

/**
 * Auth helper functions
 */
const Auth = {
  // EFFECTIVE user — role reads 'student' while previewing. Everything that
  // gates UI reads this, which is why no per-page edits were needed.
  user: null,
  // SERVER TRUTH — never rewritten. Read this for ACCESS decisions and for
  // the Student View toggle itself, via isRealAdmin()/isRealInstructor().
  realUser: null,

  /**
   * Resolve the current session via /auth/me.
   * Returns:
   *   true  — authenticated (this.user populated)
   *   false — genuinely unauthenticated (401); caller should send to /login
   *   null  — could not determine (429 / 5xx / network). Do NOT log the user
   *           out: a rate-limit or transient error is not an auth failure, and
   *           bouncing to /login only drops them into the login limiter too.
   * Transient failures are retried with backoff before giving up.
   */
  async check() {
    const maxAttempts = 3;
    for (let attempt = 1; attempt <= maxAttempts; attempt++) {
      try {
        const data = await API.auth.me();
        // realUser is what the server said. `user` is what the interface is
        // DRAWN from, and in Student View its role reads 'student'.
        //
        // Splitting them here is what makes this a handful of lines instead of
        // an edit to every page: the existing chrome checks — Auth.getUser(),
        // Auth.isAdmin(), the `Auth.user.role === 'admin'` tests scattered
        // through the pages, and the subnav filter in layout.js — all read
        // `user`, so they flip together.
        //
        // The rule for new code: DRAW from `user`, decide ACCESS from
        // realUser / isRealInstructor(). Getting that backwards is what would
        // lock an instructor out of their own page mid-recording.
        this.realUser = data.user;
        this.user = (ViewMode.isActive() && ViewMode.canPreview(data.user))
          ? { ...data.user, role: 'student', realRole: data.user.role, viewingAsStudent: true }
          : data.user;
        // A student has no instructor chrome to hide, so the flag is dead
        // weight on their account. Clear it rather than carry it.
        if (ViewMode.isActive() && !ViewMode.canPreview(data.user)) ViewMode.clear();
        window.dispatchEvent(new Event('authReady'));
        return true;
      } catch (error) {
        const status = (error instanceof APIError) ? error.status : 0;
        // Genuine auth failure — session is invalid.
        if (status === 401) {
          this.user = null;
          return false;
        }
        // Transient (429 rate-limit, 5xx, or network error): retry, then bail
        // without clearing an existing session.
        if (attempt < maxAttempts) {
          await new Promise(r => setTimeout(r, 500 * attempt));
          continue;
        }
        return this.user ? true : null;
      }
    }
    return this.user ? true : null;
  },

  async requireAuth() {
    const result = await this.check();
    // Only redirect on a confirmed unauthenticated result. `null` means we
    // couldn't reach /auth/me (rate-limited/transient) — leave the user where
    // they are rather than logging them out.
    if (result === false) {
      window.location.href = '/login';
      return false;
    }
    return result === true;
  },

  /**
   * Per-tab caches that are keyed to WHO IS SIGNED IN, and were never cleared.
   *
   *   cyberhub-modules       the sidebar payload (layout.js loadModules)
   *   cyberhub-chat-enabled  whether the AI assistant exists here
   *
   * Both are sessionStorage, so they survive a logout and the next sign-in on
   * the same tab. That was already wrong -- an instructor signing out and a
   * student signing in got the instructor's menu from cache -- and it became
   * load-bearing once /api/modules started filtering per user: a student who
   * is not enrolled would keep seeing Clinic-in-a-Box until they closed the
   * tab.
   */
  clearSessionCaches() {
    try {
      sessionStorage.removeItem('cyberhub-modules');
      sessionStorage.removeItem('cyberhub-chat-enabled');
    } catch (_) { /* private mode — nothing was cached anyway */ }
  },

  async logout() {
    try {
      await API.auth.logout();
    } catch (e) {
      // Ignore errors
    }
    
    // Clear token from localStorage
    localStorage.removeItem('token');
    ViewMode.clear();
    this.clearSessionCaches();
    
    this.user = null;
    this.realUser = null;
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

  // The REAL role, ignoring Student View. Use these wherever the question is
  // "may this person do it?" — page access gates, destructive-action guards
  // — and never for deciding what to draw, which would defeat the mode.
  isRealAdmin() {
    return this.realUser?.role === 'admin';
  },

  isRealInstructor() {
    return this.realUser?.role === 'instructor' || this.realUser?.role === 'admin';
  },

  isViewingAsStudent() {
    return this.user?.viewingAsStudent === true;
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
      // Already loading: re-capturing now would save the spinner markup as
      // restoreHtml, and every later restore would bring the spinner back.
      if (btn.classList.contains('btn-loading')) return;
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