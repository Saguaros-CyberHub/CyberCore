/**
 * Clinic-in-a-Box Shared Layout Components
 * - Unified Sidebar Navigation
 * - Persistent Global AI Chat
 */

const Layout = {
  // Current page detection
  currentPage: window.location.pathname,

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
      // Also patch after dynamic content loads
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

  // Generate unified sidebar HTML
  getSidebarHTML(activePage = '') {
    const user = Auth.getUser();
    const initials = user?.firstName && user?.lastName 
      ? `${user.firstName[0]}${user.lastName[0]}`.toUpperCase()
      : user?.email?.substring(0, 2).toUpperCase() || '--';
    const userName = user?.firstName && user?.lastName 
      ? `${user.firstName} ${user.lastName}`
      : user?.email?.split('@')[0] || 'User';
    const userRole = user?.role ? user.role.charAt(0).toUpperCase() + user.role.slice(1) : 'Student';
    const isInstructor = user?.role === 'instructor' || user?.role === 'admin';

    // Determine active states
    const isActive = (page) => activePage === page ? 'active' : '';

    return `
      <div class="sidebar-header">
        <a href="/dashboard" class="sidebar-logo">
          <span class="icon">🏥</span>
          <span>Clinic-in-a-Box</span>
        </a>
      </div>
      
      <nav class="sidebar-nav">
        <div class="nav-section">
          <div class="nav-section-title">Main</div>
          <a href="/dashboard" class="nav-item ${isActive('dashboard')}">
            <span class="icon">📊</span>
            <span>Dashboard</span>
          </a>
          <a href="/my-profiles" class="nav-item ${isActive('profiles')}">
            <span class="icon">📁</span>
            <span>My Profiles</span>
            <span class="nav-badge" id="profileCount">0</span>
          </a>
          <a href="/generator" class="nav-item ${isActive('generator')}">
            <span class="icon">⚡</span>
            <span>Generate New</span>
          </a>
        </div>
        
        <div class="nav-section">
          <div class="nav-section-title">Assessment</div>
          <a href="/workspace" class="nav-item ${isActive('workspace')}">
            <span class="icon">📝</span>
            <span>Workspace</span>
          </a>
          <a href="/progress" class="nav-item ${isActive('progress')}">
            <span class="icon">📈</span>
            <span>My Progress</span>
          </a>
        </div>
        
        ${isInstructor ? `
        <div class="nav-section">
          <div class="nav-section-title">Instructor</div>
          <a href="/instructor" class="nav-item ${isActive('instructor')}">
            <span class="icon">👨‍🏫</span>
            <span>Instructor Dashboard</span>
          </a>
        </div>
        ` : ''}

        ${user?.role === 'admin' ? `
        <div class="nav-section">
          <div class="nav-section-title">Administration</div>
          <a href="/admin" class="nav-item ${isActive('admin')}">
            <span class="icon">🖥️</span>
            <span>CyberHub Admin</span>
          </a>
        </div>
        ` : ''}
        
        <div class="nav-section">
          <div class="nav-section-title">Resources</div>
          <a href="#" class="nav-item ${isActive('ai-assistant')}" onclick="Layout.openChat(); return false;">
            <span class="icon">🤖</span>
            <span>AI Assistant</span>
          </a>
          <a href="/interview" class="nav-item ${isActive('interview')}">
            <span class="icon">🎤</span>
            <span>Interview Simulator</span>
          </a>
        </div>
      </nav>
      
      <div class="sidebar-footer">
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

  // Inject sidebar into page
  injectSidebar() {
    const sidebar = document.getElementById('sidebar');
    if (!sidebar) return;

    // Detect current page
    let activePage = '';
    const path = this.currentPage;
    if (path.includes('dashboard')) activePage = 'dashboard';
    else if (path.includes('profile') || path.includes('my-profiles')) activePage = 'profiles';
    else if (path.includes('generator')) activePage = 'generator';
    else if (path.includes('progress')) activePage = 'progress';

    else if (path.includes('interview')) activePage = 'interview';
    else if (path.includes('instructor')) activePage = 'instructor';
    else if (path.includes('workspace')) activePage = 'workspace';
    else if (path === 'admin' || path.includes('admin')) activePage = 'admin';

    sidebar.innerHTML = this.getSidebarHTML(activePage);

    // Update theme button state
    this.updateThemeButton();

    // Load profile count
    this.loadProfileCount();
  },

  // Load profile count for badge
  async loadProfileCount() {
    try {
      const data = await API.profiles.list();
      const countEl = document.getElementById('profileCount');
      if (countEl && data.profiles) {
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
  }
};

// Auto-initialize when DOM is ready
document.addEventListener('DOMContentLoaded', () => {
  // Small delay to ensure Auth is loaded
  setTimeout(() => {
    Layout.init();
  }, 100);
});

// Re-update sidebar after auth check
window.addEventListener('authReady', () => {
  Layout.injectSidebar();
});
