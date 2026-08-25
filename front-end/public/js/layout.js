/**
 * CyberHub Shared Layout Components
 * - Dynamic Sidebar Navigation (modules fetched from API)
 * - Context-sensitive sub-navigation per module
 * - Persistent Global AI Chat
 */

const Layout = {
  // Current page detection
  currentPage: window.location.pathname,

  // Cached module data
  _modules: null,

  // Subnav configs fetched from /api/modules (populated by plugins)
  _subnavs: {},

  // Initialize layout components
  init() {
    this.initTheme();
    this.injectSidebar();
    this.applyStudentViewFlag();
    this.injectGlobalChat();
    this.loadChatHistory();
    this.setupEventListeners();
    // Patch white backgrounds after DOM is ready
    if (document.documentElement.getAttribute('data-theme') === 'dark') {
      requestAnimationFrame(() => this.patchDarkBackgrounds());
      setTimeout(() => this.patchDarkBackgrounds(), 500);
      setTimeout(() => this.patchDarkBackgrounds(), 2000);
    }
  },

  // Theme management
  initTheme() {
    const saved = localStorage.getItem('ciab-theme');
    if (saved === 'dark') {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
  },

  // ── Student View ────────────────────────────────────────────────
  // Draws the interface the way a student sees it, so instructor-only
  // navigation stays out of lecture recordings. Presentation only: the
  // instructor keeps all of their access. See ViewMode in app.js.

  toggleStudentView() {
    if (Auth.isViewingAsStudent()) ViewMode.exit();
    else ViewMode.enter();
  },

  exitStudentView() {
    ViewMode.exit();
  },

  /**
   * Stamp html[data-student-view] so CSS can hide instructor-only chrome.
   *
   * This is the general escape hatch: anything a student would not normally
   * see can be marked `data-instructor-only` in the markup and it disappears
   * in Student View, with no JS. Use it for new instructor-only UI rather
   * than adding another role check.
   *
   * Deliberately NO banner. The whole point is that the recording looks like
   * a student's screen, and a bar reading "Student View" in every frame is
   * exactly the confusion this is meant to avoid. The amber toggle in the
   * sidebar footer is the indicator, and since nothing is actually blocked,
   * leaving it on by accident costs nothing.
   */
  applyStudentViewFlag() {
    if (Auth.isViewingAsStudent()) {
      document.documentElement.setAttribute('data-student-view', '');
    } else {
      document.documentElement.removeAttribute('data-student-view');
    }
  },

  toggleTheme() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    if (isDark) {
      document.documentElement.removeAttribute('data-theme');
      localStorage.setItem('ciab-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
      localStorage.setItem('ciab-theme', 'dark');
    }
    this.updateThemeButton();
    this.patchDarkBackgrounds();
  },

  updateThemeButton() {
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const icon = document.getElementById('themeIcon');
    const label = document.getElementById('themeLabel');
    if (icon) icon.textContent = isDark ? '☀️' : '🌙';
    if (label) label.textContent = isDark ? 'Light Mode' : 'Dark Mode';
  },

  // Placeholder — dark mode is now handled purely via CSS
  patchDarkBackgrounds() {},

  // Detect which module is active based on URL
  getActiveModule() {
    const path = this.currentPage;
    const segments = path.split('/').filter(Boolean);
    // /ciab/dashboard → 'ciab', /crucible → 'crucible', /hub → 'hub'
    return segments[0] || 'hub';
  },

  // Detect which sub-page is active (for context sub-nav)
  getActiveSubPage() {
    const path = this.currentPage;
    // Crucible challenge types are selected via ?type= on the dashboard; the
    // dashboard defaults to 'weekly' when no type is present.
    if (this.getActiveModule() === 'crucible') {
      const type = new URLSearchParams(window.location.search).get('type');
      return type || 'weekly';
    }
    // Handle both /ciab/dashboard and legacy /dashboard
    if (path.includes('dashboard')) return 'dashboard';
    if (path.includes('profile') || path.includes('my-profiles')) return 'profiles';
    if (path.includes('generator')) return 'generator';
    if (path.includes('workspace')) return 'workspace';
    if (path.includes('progress')) return 'progress';
    if (path.includes('interview')) return 'interview';
    if (path.includes('instructor')) return 'instructor';
    if (path.includes('admin')) return 'admin';
    if (path.includes('clinic-risk-assessment')) return 'clinic-risk-assessment';
    if (path.includes('intake-form')) return 'intake-form';
    // CLE pages
    if (path.includes('courses')) return 'courses';
    if (path.includes('students')) return 'students';
    if (path.includes('sessions')) return 'sessions';
    if (path.includes('builder')) return 'builder';
    return '';
  },

  // Generate the skeleton sidebar (header + footer, nav populated async)
  getSidebarHTML() {
    const user = Auth.getUser();
    const initials = user?.firstName && user?.lastName
      ? `${user.firstName[0]}${user.lastName[0]}`.toUpperCase()
      : user?.email?.substring(0, 2).toUpperCase() || '--';
    const userName = user?.firstName && user?.lastName
      ? `${user.firstName} ${user.lastName}`
      : user?.email?.split('@')[0] || 'User';
    const userRole = user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Student';

    return `
      <div class="sidebar-header">
        <a href="/hub" class="sidebar-logo">
          <span class="icon">🛡️</span>
          <span id="sidebarSiteName">CyberHub</span>
        </a>
      </div>

      <nav class="sidebar-nav" id="sidebarNav">
        <div class="nav-section">
          <div class="nav-section-title" style="color:var(--text-muted);font-size:0.75rem">Loading modules...</div>
        </div>
      </nav>

      <div class="sidebar-footer">
        ${user?.role === 'admin' ? `
        <a href="/admin" class="admin-link-btn" title="Admin Dashboard">
          <span class="admin-link-icon">&#9881;</span>
          <span>Admin</span>
        </a>` : ''}
        <div class="theme-toggle-row">
          <button class="theme-toggle-btn" onclick="Layout.toggleTheme()" title="Toggle dark/light mode" id="themeToggleBtn">
            <span class="theme-icon" id="themeIcon">🌙</span>
            <span class="theme-label" id="themeLabel">Dark Mode</span>
          </button>
        </div>
        ${Auth.isRealInstructor() ? `
        <div class="student-view-row">
          <button class="student-view-btn${Auth.isViewingAsStudent() ? ' is-on' : ''}"
                  onclick="Layout.toggleStudentView()"
                  aria-pressed="${Auth.isViewingAsStudent()}"
                  title="Hide instructor-only menus so the interface looks the way a student's does — for lecture recordings. Your access is unchanged.">
            <span class="student-view-icon">${Auth.isViewingAsStudent() ? '🎓' : '👁️'}</span>
            <span class="student-view-label">${Auth.isViewingAsStudent() ? 'Exit Student View' : 'Student View'}</span>
          </button>
        </div>` : ''}
        <div class="user-menu">
          <div class="user-avatar" id="userAvatar">${initials}</div>
          <div class="user-info">
            <div class="user-name" id="userName">${userName}</div>
            <div class="user-role" id="userRole">${userRole}</div>
          </div>
          <button class="logout-btn" onclick="Auth.logout()" title="Sign Out">🚪</button>
        </div>
      </div>
    `;
  },

  // ── Sidebar accordion state ────────────────────────────────────────────────
  // The sidebar is re-injected on every page load (and again on `authReady`),
  // so which sections are open cannot live in the DOM — persist it instead.
  NAV_OPEN_KEY: 'cyberhub-nav-open',

  getOpenNavKeys() {
    try {
      const raw = JSON.parse(localStorage.getItem(this.NAV_OPEN_KEY));
      return Array.isArray(raw) ? raw : null;
    } catch (_) {
      return null;
    }
  },

  setOpenNavKeys(keys) {
    try {
      localStorage.setItem(this.NAV_OPEN_KEY, JSON.stringify(keys));
    } catch (_) {}
  },

  // Open/close one nav section and remember the choice across page loads.
  toggleNavSection(btn) {
    const key = btn.dataset.navToggle;
    const panel = document.getElementById(`subnav-${key}`);
    if (!panel) return;

    const open = btn.getAttribute('aria-expanded') !== 'true';
    btn.setAttribute('aria-expanded', String(open));
    panel.hidden = !open;

    const keys = new Set(this.getOpenNavKeys() || [this.getActiveModule()]);
    if (open) keys.add(key); else keys.delete(key);
    this.setOpenNavKeys([...keys]);
  },

  // Build the dynamic nav from module data.
  //
  // Modules and plugins are merged into ONE flat list ordered by display_order.
  // The old "Modules" / "Plugins" split meant a plugin could never sort above a
  // module (so the Cyber Learning Environment could not be promoted to the top),
  // and the headings meant nothing to students. `category` itself is left alone
  // so the admin settings UI and the hub card grid keep working.
  buildNavHTML(modules, plugins) {
    const user = Auth.getUser();
    const activeModule = this.getActiveModule();
    const activeSubPage = this.getActiveSubPage();

    // Check if we're on a legacy (non-namespaced) CIAB page
    const legacyCiabPages = ['dashboard','profiles','generator','workspace','progress','interview','instructor','intake-form','guide'];
    const isLegacyCiab = legacyCiabPages.includes(activeModule);
    const effectiveModule = isLegacyCiab ? 'ciab' : activeModule;

    const entryKeyOf = (mod) => (mod.entry_url || '').split('/').filter(Boolean)[0];
    const isModuleActive = (mod) => mod.key === effectiveModule || entryKeyOf(mod) === effectiveModule;
    const subnavOf = (mod) => this._subnavs[mod.key] || this._subnavs[entryKeyOf(mod)];

    // The sub-items this user is actually allowed to see.
    // Known false on this tab only once /api/chat/status has answered; treat
    // anything else as "show it" so the entry never flickers out for a working
    // deployment.
    let chatDisabled = false;
    try { chatDisabled = sessionStorage.getItem('cyberhub-chat-enabled') === 'false'; } catch (_) {}

    const visibleItems = (mod) => {
      const sn = subnavOf(mod);
      if (!sn || !Array.isArray(sn.items)) return [];
      return sn.items.filter(item => {
        if (item.roles && !item.roles.includes(user?.role)) return false;
        // A menu entry that opens the chat is dead weight with no LLM configured.
        if (chatDisabled && item.onclick && item.onclick.includes('openChat')) return false;
        return true;
      });
    };

    // Hide a whole entry when every one of its children is gated to a role the
    // user doesn't hold. That is what makes the Cyber Learning Environment
    // instructor/admin-only without a schema change.
    //
    // This deliberately fails CLOSED: on the first paint `Auth.user` has not
    // resolved yet (it is populated by the async /auth/me that fires
    // `authReady`), so a role-gated entry stays hidden until the authReady
    // re-render rather than flashing at every student on every page load.
    const isEntryVisible = (mod) => {
      const sn = subnavOf(mod);
      if (!sn || !Array.isArray(sn.items) || sn.items.length === 0) return true;
      return visibleItems(mod).length > 0;
    };

    const buildSubnav = (mod, expanded) => {
      const items = visibleItems(mod);
      if (!items.length) return '';
      let s = `<div class="module-subnav" id="subnav-${mod.key}"${expanded ? '' : ' hidden'}>`;
      items.forEach(item => {
        // Sub-page matching is substring-based and shared across plugins
        // ('dashboard' matches CIAB and CLE alike), so only ever mark a child
        // active inside the module you're actually in.
        const active = isModuleActive(mod) && activeSubPage === item.page ? 'active' : '';
        const onclick = item.onclick ? ` onclick="${item.onclick}"` : '';
        s += `<a href="${item.url}" class="nav-item subnav-item ${active}"${onclick}>
          <span>${item.label}</span>
          ${item.page === 'profiles' ? '<span class="nav-badge" id="profileCount">0</span>' : ''}
        </a>`;
      });
      s += `</div>`;
      return s;
    };

    // First visit: only the module you're currently in is open.
    const openKeys = this.getOpenNavKeys() || [effectiveModule];

    // Home first. Previously only the logo went home, which students didn't find.
    let html = `<div class="nav-section">
      <a href="/hub" class="nav-item ${activeModule === 'hub' ? 'active' : ''}">
        <span class="icon">🏠</span>
        <span>Home</span>
      </a>`;

    [...(modules || []), ...(plugins || [])]
      .filter(isEntryVisible)
      .sort((a, b) => (a.display_order ?? 0) - (b.display_order ?? 0))
      .forEach(mod => {
        const active = isModuleActive(mod);
        const items = visibleItems(mod);
        const expanded = items.length > 0 && (active || openKeys.includes(mod.key));

        html += `<div class="nav-row">
          <a href="${mod.entry_url}" class="nav-item ${active ? 'active' : ''}">
            <span>${mod.name}</span>
          </a>`;
        // The arrow is a real button so it has its own hit target, keyboard
        // handling and focus ring — clicking it must NOT follow the link.
        if (items.length) {
          html += `<button type="button" class="nav-toggle" data-nav-toggle="${mod.key}" aria-expanded="${expanded}" aria-controls="subnav-${mod.key}" aria-label="Toggle ${mod.name} menu"></button>`;
        }
        html += `</div>`;
        html += buildSubnav(mod, expanded);
      });

    html += `</div>`;
    return html;
  },

  // Inject sidebar into page
  injectSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    // Render skeleton immediately
    sidebar.innerHTML = this.getSidebarHTML();
    this.updateThemeButton();

    // Fetch modules and populate nav
    this.loadModules();
  },

  // Fetch modules from API and populate sidebar nav
  async loadModules() {
    try {
      let data = this._modules;
      if (!data) {
        // The server filters this list per user — Clinic-in-a-Box only appears
        // for someone an instructor enrolled — so Student View has to travel
        // with the request. Without it a previewing instructor keeps their own
        // menu and the preview silently stops matching what a student sees.
        const asStudent = typeof ViewMode !== 'undefined' && ViewMode.isActive();
        data = await API.modules.list({ asStudent });
        this._modules = data;
        this._subnavs = data.subnavs || {};
        // Persist across full page navigations so a transient failure (e.g. an
        // /api/ rate-limit during quick navigation) doesn't collapse the menu.
        try { sessionStorage.setItem('cyberhub-modules', JSON.stringify(data)); } catch (_) {}
      }

      this.renderNav(data);

      // Load profile count if CIAB sub-nav is visible
      this.loadProfileCount();
    } catch (e) {
      // The fetch failed — fall back to the last-known-good module list so the
      // menu stays usable. Only show the bare Home link if we've never had one.
      let cached = null;
      try { cached = JSON.parse(sessionStorage.getItem('cyberhub-modules')); } catch (_) {}
      if (cached) {
        this._subnavs = cached.subnavs || {};
        this.renderNav(cached);
        this.loadProfileCount();
        return;
      }
      const nav = document.getElementById('sidebarNav');
      if (nav) {
        nav.innerHTML = `
          <div class="nav-section">
            <a href="/hub" class="nav-item active">
              <span class="icon">🏠</span>
              <span>Home</span>
            </a>
          </div>`;
      }
    }
  },

  // Render the nav sections from a modules payload and scroll the active item
  // into view. Shared by the live fetch and the cached fallback.
  renderNav(data) {
    const nav = document.getElementById('sidebarNav');
    if (!nav) return;
    nav.innerHTML = this.buildNavHTML(data.modules || [], data.plugins || []);
    const activeModuleItem = nav.querySelector('.nav-item.active:not(.subnav-item)');
    if (activeModuleItem) {
      const navRect = nav.getBoundingClientRect();
      const itemRect = activeModuleItem.getBoundingClientRect();
      nav.scrollTop = nav.scrollTop + itemRect.top - navRect.top - 8;
    }
  },

  // Load profile count for badge
  async loadProfileCount() {
    try {
      const countEl = document.getElementById('profileCount');
      if (!countEl) return;
      // API.profiles only exists on CIAB pages (ciab-api.js). The CIAB subnav is
      // now rendered from every page, so the badge can be present when the
      // client isn't loaded.
      if (!API.profiles) return;
      const data = await API.profiles.list();
      if (data.profiles) {
        countEl.textContent = data.profiles.length;
      }
    } catch (e) {
      // Silent fail
    }
  },

  // Get global chat HTML
  getGlobalChatHTML() {
    return `
      <button class="global-chat-toggle" id="globalChatToggle" onclick="Layout.toggleChat()">
        💬
      </button>
      <div class="global-chat-window" id="globalChatWindow">
        <div class="global-chat-header">
          <span class="global-chat-title">🤖 AI Assistant</span>
          <div class="global-chat-actions">
            <button class="global-chat-btn" onclick="Layout.clearChat()" title="Clear Chat">🗑️</button>
            <button class="global-chat-btn" onclick="Layout.toggleChat()" title="Close">✕</button>
          </div>
        </div>
        <div class="global-chat-messages" id="globalChatMessages">
          <div class="chat-message assistant">
            👋 Hi! I'm your CyberHub assistant. I can help you with:
            <ul style="margin: 10px 0; padding-left: 20px;">
              <li>Finding your way around the platform</li>
              <li>Understanding your course labs and assignments</li>
              <li>Cybersecurity concepts you're stuck on</li>
              <li>Working through your assessment deliverables</li>
            </ul>
            How can I help you today?
          </div>
        </div>
        <div class="global-chat-input-area">
          <input type="text" class="global-chat-input" id="globalChatInput" 
                 placeholder="Ask me anything..." 
                 onkeypress="if(event.key==='Enter') Layout.sendChat()">
          <button class="global-chat-send" id="globalChatSend" onclick="Layout.sendChat()">
            ➤
          </button>
        </div>
      </div>
    `;
  },

  // Does this deployment have an LLM configured? Cached per tab so it costs one
  // request per session rather than one per page load.
  async isChatEnabled() {
    const CACHE_KEY = 'cyberhub-chat-enabled';
    try {
      const cached = sessionStorage.getItem(CACHE_KEY);
      if (cached !== null) return cached === 'true';
    } catch (_) {}

    try {
      const { enabled } = await API.chatStatus();
      try { sessionStorage.setItem(CACHE_KEY, String(!!enabled)); } catch (_) {}
      return !!enabled;
    } catch (_) {
      // Not signed in yet, or the endpoint is unreachable. Assume no assistant
      // rather than render a launcher that is guaranteed to fail.
      return false;
    }
  },

  // Inject global chat
  async injectGlobalChat() {
    // Check if chat already exists (avoid duplicates)
    if (document.getElementById('globalChatContainer')) return;

    // No API key on this deployment means every send would fail with a generic
    // "having trouble connecting". Show nothing at all instead.
    if (!(await this.isChatEnabled())) return;

    // Create container
    const chatContainer = document.createElement('div');
    chatContainer.id = 'globalChatContainer';
    chatContainer.innerHTML = this.getGlobalChatHTML();
    document.body.appendChild(chatContainer);

    // Add styles if not already present
    if (!document.getElementById('globalChatStyles')) {
      const styles = document.createElement('style');
      styles.id = 'globalChatStyles';
      styles.textContent = this.getChatStyles();
      document.head.appendChild(styles);
    }

    // init() calls loadChatHistory() synchronously, which is now before this
    // await resolves — replay it here, once the markup exists.
    this.loadChatHistory();
  },

  // Chat styles
  getChatStyles() {
    return `
      /* Global Chat Toggle Button */
      .global-chat-toggle {
        position: fixed;
        bottom: 25px;
        right: 25px;
        width: 60px;
        height: 60px;
        border-radius: 50%;
        background: linear-gradient(135deg, var(--primary, #0c234b), var(--primary-light, #1e5288));
        color: white;
        border: none;
        font-size: 1.5em;
        cursor: pointer;
        box-shadow: 0 4px 15px rgba(30, 82, 136, 0.4);
        z-index: 9999;
        transition: all 0.3s ease;
      }
      .global-chat-toggle:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 20px rgba(30, 82, 136, 0.5);
      }
      .global-chat-toggle.active {
        background: #e53e3e;
      }

      /* Global Chat Window */
      .global-chat-window {
        position: fixed;
        bottom: 100px;
        right: 25px;
        width: 380px;
        height: 500px;
        background: white;
        border-radius: 16px;
        box-shadow: 0 10px 40px rgba(0, 0, 0, 0.2);
        display: none;
        flex-direction: column;
        z-index: 9998;
        overflow: hidden;
        animation: chatSlideIn 0.3s ease;
      }
      .global-chat-window.open {
        display: flex;
      }
      @keyframes chatSlideIn {
        from { opacity: 0; transform: translateY(20px); }
        to { opacity: 1; transform: translateY(0); }
      }

      /* Chat Header */
      .global-chat-header {
        padding: 15px 20px;
        background: linear-gradient(135deg, var(--primary-dark, #001c48), var(--primary, #0c234b));
        color: white;
        display: flex;
        justify-content: space-between;
        align-items: center;
      }
      .global-chat-title {
        font-weight: 600;
        font-size: 1.1em;
      }
      .global-chat-actions {
        display: flex;
        gap: 8px;
      }
      .global-chat-btn {
        background: rgba(255,255,255,0.2);
        border: none;
        color: white;
        width: 30px;
        height: 30px;
        border-radius: 6px;
        cursor: pointer;
        transition: background 0.2s;
      }
      .global-chat-btn:hover {
        background: rgba(255,255,255,0.3);
      }

      /* Chat Messages */
      .global-chat-messages {
        flex: 1;
        overflow-y: auto;
        padding: 15px;
        background: #f8fafc;
      }
      .global-chat-messages .chat-message {
        margin-bottom: 12px;
        padding: 12px 15px;
        border-radius: 12px;
        max-width: 85%;
        line-height: 1.5;
        font-size: 0.9em;
      }
      .global-chat-messages .chat-message.user {
        background: var(--primary, #0c234b);
        color: white;
        margin-left: auto;
        border-bottom-right-radius: 4px;
      }
      .global-chat-messages .chat-message.assistant {
        background: white;
        color: var(--primary-dark, #001c48);
        border: 1px solid #e2e8f0;
        border-bottom-left-radius: 4px;
      }
      .global-chat-messages .chat-message.thinking {
        color: #a0aec0;
        font-style: italic;
      }

      /* Thinking Animation */
      .thinking-dots {
        display: inline-flex;
        align-items: center;
        gap: 4px;
      }
      .thinking-dots .dot {
        width: 8px;
        height: 8px;
        background: #a0aec0;
        border-radius: 50%;
        animation: thinking-bounce 1.4s ease-in-out infinite;
      }
      .thinking-dots .dot:nth-child(1) { animation-delay: 0s; }
      .thinking-dots .dot:nth-child(2) { animation-delay: 0.2s; }
      .thinking-dots .dot:nth-child(3) { animation-delay: 0.4s; }
      @keyframes thinking-bounce {
        0%, 60%, 100% { transform: translateY(0); opacity: 0.4; }
        30% { transform: translateY(-8px); opacity: 1; }
      }

      /* Chat Input */
      .global-chat-input-area {
        padding: 15px;
        background: white;
        border-top: 1px solid #e2e8f0;
        display: flex;
        gap: 10px;
      }
      .global-chat-input {
        flex: 1;
        padding: 12px 15px;
        border: 1px solid #e2e8f0;
        border-radius: 25px;
        font-size: 0.9em;
        outline: none;
        transition: border-color 0.2s;
      }
      .global-chat-input:focus {
        border-color: var(--primary, #0c234b);
      }
      .global-chat-send {
        width: 45px;
        height: 45px;
        border-radius: 50%;
        background: var(--primary, #0c234b);
        color: white;
        border: none;
        font-size: 1.2em;
        cursor: pointer;
        transition: background 0.2s;
      }
      .global-chat-send:hover {
        background: var(--primary-light, #1e5288);
      }
      .global-chat-send:disabled {
        background: #a0aec0;
        cursor: not-allowed;
      }

      /* Responsive */
      @media (max-width: 480px) {
        .global-chat-window {
          width: calc(100vw - 30px);
          right: 15px;
          bottom: 90px;
          height: 60vh;
        }
        .global-chat-toggle {
          right: 15px;
          bottom: 15px;
        }
      }
    `;
  },

  // Toggle chat visibility
  toggleChat() {
    const chatWindow = document.getElementById('globalChatWindow');
    const chatToggle = document.getElementById('globalChatToggle');
    // The widget isn't injected when no LLM is configured.
    if (!chatWindow || !chatToggle) return;

    chatWindow.classList.toggle('open');
    chatToggle.classList.toggle('active');
    chatToggle.textContent = chatWindow.classList.contains('open') ? '✕' : '💬';
    
    if (chatWindow.classList.contains('open')) {
      document.getElementById('globalChatInput').focus();
    }
  },

  // Open chat (used by sidebar link)
  openChat() {
    const chatWindow = document.getElementById('globalChatWindow');
    if (!chatWindow) return;
    if (!chatWindow.classList.contains('open')) {
      this.toggleChat();
    }
  },

  // Chat processing state
  isChatProcessing: false,

  // Send chat message
  async sendChat() {
    if (this.isChatProcessing) return;

    const input = document.getElementById('globalChatInput');
    const sendBtn = document.getElementById('globalChatSend');
    const messagesDiv = document.getElementById('globalChatMessages');
    const message = input.value.trim();
    
    if (!message) return;

    // Add user message
    messagesDiv.innerHTML += `<div class="chat-message user">${this.escapeHtml(message)}</div>`;
    input.value = '';
    
    // Save to history
    this.saveChatMessage('user', message);

    // Show thinking indicator
    messagesDiv.innerHTML += `
      <div class="chat-message assistant thinking" id="globalThinkingIndicator">
        <span class="thinking-dots">
          <span class="dot"></span>
          <span class="dot"></span>
          <span class="dot"></span>
        </span>
      </div>
    `;
    messagesDiv.scrollTop = messagesDiv.scrollHeight;

    this.isChatProcessing = true;
    input.disabled = true;
    sendBtn.disabled = true;

    try {
      const user = Auth.getUser();
      const data = await API.chat(message, user?.id);
      
      // Remove thinking indicator
      document.getElementById('globalThinkingIndicator')?.remove();
      
      // Add response. Escape it — this is model output echoing user-influenced
      // text, and it was the one string here going in as raw HTML.
      messagesDiv.innerHTML += `<div class="chat-message assistant">${this.formatChatText(data.response)}</div>`;
      
      // Save to history
      this.saveChatMessage('assistant', data.response);
    } catch (error) {
      document.getElementById('globalThinkingIndicator')?.remove();
      const errorMsg = 'Sorry, I\'m having trouble connecting. Please try again.';
      messagesDiv.innerHTML += `<div class="chat-message assistant">${errorMsg}</div>`;
    } finally {
      this.isChatProcessing = false;
      input.disabled = false;
      sendBtn.disabled = false;
      input.focus();
      messagesDiv.scrollTop = messagesDiv.scrollHeight;
    }
  },

  // Save chat message to localStorage
  saveChatMessage(role, content) {
    try {
      const history = JSON.parse(localStorage.getItem('clinicChatHistory') || '[]');
      history.push({ role, content, timestamp: Date.now() });
      
      // Keep only last 50 messages
      if (history.length > 50) {
        history.splice(0, history.length - 50);
      }
      
      localStorage.setItem('clinicChatHistory', JSON.stringify(history));
    } catch (e) {
      // Storage might be full or unavailable
    }
  },

  // Load chat history from localStorage
  loadChatHistory() {
    try {
      const history = JSON.parse(localStorage.getItem('clinicChatHistory') || '[]');
      const messagesDiv = document.getElementById('globalChatMessages');
      
      if (history.length > 0 && messagesDiv) {
        // Clear default welcome message if we have history
        messagesDiv.innerHTML = '';
        
        history.forEach(msg => {
          messagesDiv.innerHTML += `<div class="chat-message ${msg.role === 'user' ? 'user' : 'assistant'}">${this.formatChatText(msg.content)}</div>`;
        });
        
        messagesDiv.scrollTop = messagesDiv.scrollHeight;
      }
    } catch (e) {
      // Silent fail
    }
  },

  // Clear chat history
  clearChat() {
    localStorage.removeItem('clinicChatHistory');
    const messagesDiv = document.getElementById('globalChatMessages');
    if (messagesDiv) {
      messagesDiv.innerHTML = `
        <div class="chat-message assistant">
          👋 Chat cleared! How can I help you today?
        </div>
      `;
    }
  },

  // Escape chat text, then restore paragraph breaks. Chat replies are plain
  // text, so this is all the formatting they need.
  formatChatText(text) {
    return this.escapeHtml(text == null ? '' : String(text)).replace(/\n/g, '<br>');
  },

  // HTML escape utility
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Show/hide the sidebar on narrow screens. The markup has called this since
  // the mobile header was added (hub.html, module-placeholder.html and the CIAB
  // risk-assessment page all have onclick="Layout.toggleSidebar()") but it was
  // never defined, so the hamburger threw on every phone and tablet. The CSS
  // (.sidebar.open / .sidebar-overlay.active) was already in place.
  toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;
    const open = sidebar.classList.toggle('open');

    let overlay = document.querySelector('.sidebar-overlay');
    if (!overlay) {
      overlay = document.createElement('div');
      overlay.className = 'sidebar-overlay';
      overlay.addEventListener('click', () => this.toggleSidebar());
      document.body.appendChild(overlay);
    }
    overlay.classList.toggle('active', open);
  },

  // Setup additional event listeners.
  //
  // init() runs more than once per page (DOMContentLoaded, the `authReady`
  // re-render, and several pages call it themselves), so guard registration —
  // otherwise every listener fires N times per event.
  setupEventListeners() {
    if (this._listenersBound) return;
    this._listenersBound = true;

    // Close chat on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const chatWindow = document.getElementById('globalChatWindow');
        if (chatWindow?.classList.contains('open')) {
          this.toggleChat();
        }
      }
    });

    // Sidebar accordion. Delegated on `document` because the sidebar's innerHTML
    // is replaced several times per page load, which would discard a listener
    // bound to the nav itself.
    document.addEventListener('click', (e) => {
      const btn = e.target.closest?.('.nav-toggle');
      if (!btn) return;
      e.preventDefault();
      this.toggleNavSection(btn);
    });
  },

  // Load and apply site name from backend
  async loadSiteNameFromSettings() {
    try {
      // Skip if on admin page - admin.html handles its own site name loading
      if (window.location.pathname.includes('/admin')) {
        return;
      }
      
      // Check if user is authenticated
      const token = localStorage.getItem('token');
      if (!token) {
        return;
      }

      const response = await fetch('/api/admin/settings', {
        headers: {
          'Authorization': `Bearer ${token}`,
          'Content-Type': 'application/json'
        }
      });

      if (response.ok) {
        const data = await response.json();
        const siteName = data.site_name || 'CyberHub';
        this.updateSiteName(siteName);
      } else if (response.status === 403) {
        // User is not admin - that's fine, just use default
        return;
      }
    } catch (err) {
      // Silent fail - just use default CyberHub
      console.debug('[Layout] Could not load site name:', err.message);
    }
  },

  // Update site name everywhere in the UI
  updateSiteName(siteName) {
    if (!siteName) return;
    
    // Update sidebar
    const sidebarEl = document.getElementById('sidebarSiteName');
    if (sidebarEl) sidebarEl.textContent = siteName;
    
    // Update page title
    document.title = siteName;
    
    // Store in localStorage
    localStorage.setItem('site_name', siteName);
  }
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Small delay to ensure Auth is loaded
  setTimeout(() => {
    Layout.init();
    // Load site name from localStorage (set by admin page or API)
    const siteName = localStorage.getItem('site_name');
    if (siteName) {
      Layout.updateSiteName(siteName);
    }
  }, 100);
});

// Re-update sidebar after auth check
window.addEventListener('authReady', () => {
  Layout.injectSidebar();
  // Auth.realUser is null on the first paint (it arrives with the async
  // /auth/me), so this is the pass that settles the mode — the same reason
  // the Admin gear only appears here.
  Layout.applyStudentViewFlag();
  // Refresh site name from API for authenticated users
  Layout.loadSiteNameFromSettings();
});
