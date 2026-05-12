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

  // Build the dynamic nav sections from module data
  buildNavHTML(modules, plugins) {
    const user = Auth.getUser();
    const activeModule = this.getActiveModule();
    const activeSubPage = this.getActiveSubPage();

    // Check if we're on a legacy (non-namespaced) CIAB page
    const legacyCiabPages = ['dashboard','profiles','generator','workspace','progress','interview','instructor','intake-form','guide'];
    const isLegacyCiab = legacyCiabPages.includes(activeModule);
    const effectiveModule = isLegacyCiab ? 'ciab' : activeModule;

    const isModuleActive = (mod) => {
      const entryKey = (mod.entry_url || '').split('/').filter(Boolean)[0];
      return mod.key === effectiveModule || entryKey === effectiveModule;
    };

    let html = '';

    // Modules section
    if (modules.length > 0) {
      html += `<div class="nav-section">
        <div class="nav-section-title">Modules</div>`;
      modules.forEach(mod => {
        const active = isModuleActive(mod) ? 'active' : '';
        html += `<a href="${mod.entry_url}" class="nav-item ${active}">
          <span class="icon">${mod.icon || ''}</span>
          <span>${mod.name}</span>
        </a>`;
      });
      html += `</div>`;
    }

    // Plugins section
    if (plugins.length > 0) {
      html += `<div class="nav-section">
        <div class="nav-section-title">Plugins</div>`;
      plugins.forEach(mod => {
        const active = isModuleActive(mod) ? 'active' : '';
        html += `<a href="${mod.entry_url}" class="nav-item ${active}">
          <span class="icon">${mod.icon || ''}</span>
          <span>${mod.name}</span>
        </a>`;
      });
      html += `</div>`;
    }

    // Context sub-navigation (show when inside a module that has sub-pages)
    const subnavData = this._subnavs[effectiveModule];
    const subnav = subnavData?.items;
    if (subnav) {
      html += `<div class="nav-section module-subnav">
        <div class="nav-section-title">${subnavData?.label || effectiveModule}</div>`;
      subnav.forEach(item => {
        // Role filtering
        if (item.roles && !item.roles.includes(user?.role)) return;

        const active = activeSubPage === item.page ? 'active' : '';
        const onclick = item.onclick ? ` onclick="${item.onclick}"` : '';
        html += `<a href="${item.url}" class="nav-item subnav-item ${active}"${onclick}>
          <span class="icon">${item.icon}</span>
          <span>${item.label}</span>
          ${item.page === 'profiles' ? '<span class="nav-badge" id="profileCount">0</span>' : ''}
        </a>`;
      });
      html += `</div>`;
    }

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
        data = await API.modules.list();
        this._modules = data;
        this._subnavs = data.subnavs || {};
      }

      const nav = document.getElementById('sidebarNav');
      if (nav) {
        nav.innerHTML = this.buildNavHTML(data.modules || [], data.plugins || []);
      }

      // Load profile count if CIAB sub-nav is visible
      this.loadProfileCount();
    } catch (e) {
      // Fallback: show hub link if modules fail to load
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

  // Load profile count for badge
  async loadProfileCount() {
    try {
      const countEl = document.getElementById('profileCount');
      if (!countEl) return;
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
            👋 Hi! I'm your AI assistant for the Clinic-in-a-Box toolkit. I can help you with:
            <ul style="margin: 10px 0; padding-left: 20px;">
              <li>Understanding risk assessment concepts</li>
              <li>Analyzing your generated profiles</li>
              <li>Completing your assessment deliverables</li>
              <li>Interview preparation tips</li>
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

  // Inject global chat
  injectGlobalChat() {
    // Check if chat already exists (avoid duplicates)
    if (document.getElementById('globalChatContainer')) return;

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
        background: linear-gradient(135deg, #3182ce, #2c5282);
        color: white;
        border: none;
        font-size: 1.5em;
        cursor: pointer;
        box-shadow: 0 4px 15px rgba(49, 130, 206, 0.4);
        z-index: 9999;
        transition: all 0.3s ease;
      }
      .global-chat-toggle:hover {
        transform: scale(1.1);
        box-shadow: 0 6px 20px rgba(49, 130, 206, 0.5);
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
        background: linear-gradient(135deg, #1a365d, #2c5282);
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
        background: #3182ce;
        color: white;
        margin-left: auto;
        border-bottom-right-radius: 4px;
      }
      .global-chat-messages .chat-message.assistant {
        background: white;
        color: #1a365d;
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
        border-color: #3182ce;
      }
      .global-chat-send {
        width: 45px;
        height: 45px;
        border-radius: 50%;
        background: #3182ce;
        color: white;
        border: none;
        font-size: 1.2em;
        cursor: pointer;
        transition: background 0.2s;
      }
      .global-chat-send:hover {
        background: #2c5282;
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
      
      // Add response
      messagesDiv.innerHTML += `<div class="chat-message assistant">${data.response}</div>`;
      
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
          messagesDiv.innerHTML += `<div class="chat-message ${msg.role}">${msg.content}</div>`;
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

  // HTML escape utility
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  // Setup additional event listeners
  setupEventListeners() {
    // Close chat on escape key
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        const chatWindow = document.getElementById('globalChatWindow');
        if (chatWindow?.classList.contains('open')) {
          this.toggleChat();
        }
      }
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
  // Refresh site name from API for authenticated users
  Layout.loadSiteNameFromSettings();
});
