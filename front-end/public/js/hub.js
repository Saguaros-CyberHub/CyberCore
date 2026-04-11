/**
 * CyberHub Dashboard
 * Fetches active modules and renders the card grid.
 */

// Loaded plugin keys (populated from API subnavs — if a module has subnav, it has content)
let loadedPluginKeys = [];

function renderModuleCard(mod) {
  const isActive = loadedPluginKeys.includes(mod.key);
  const statusClass = isActive ? 'active' : 'coming-soon';
  const statusLabel = isActive ? 'Available' : 'Coming Soon';

  return `
    <a href="${mod.entry_url}" class="module-card" style="--card-accent: ${mod.color || '#3182ce'}">
      <div class="module-card-header">
        <div class="module-card-icon" style="--icon-bg: ${mod.color}15">${mod.icon || ''}</div>
        <div class="module-card-name">${mod.name}</div>
      </div>
      <div class="module-card-desc">${mod.description || ''}</div>
      <div class="module-card-status ${statusClass}">${statusLabel}</div>
    </a>
  `;
}

async function initHub() {
  // Auth check
  const authed = await Auth.requireAuth();
  if (!authed) return;

  // Welcome message
  const user = Auth.getUser();
  if (user?.firstName) {
    document.getElementById('welcomeTitle').textContent = `Welcome back, ${user.firstName}`;
  }
  document.getElementById('headerUser').textContent = user?.email || '';

  // Init sidebar
  Layout.init();

  // Fetch modules
  try {
    const data = await API.modules.list();

    // Determine which modules are active (have loaded plugin routes/subnav)
    loadedPluginKeys = Object.keys(data.subnavs || {});

    // Render module cards
    const moduleGrid = document.getElementById('moduleGrid');
    if (data.modules && data.modules.length > 0) {
      moduleGrid.innerHTML = data.modules.map(renderModuleCard).join('');
    } else {
      moduleGrid.innerHTML = '<p style="color:var(--text-muted)">No modules available.</p>';
    }

    // Render plugin cards
    const pluginGrid = document.getElementById('pluginGrid');
    const pluginsTitle = document.getElementById('pluginsTitle');
    if (data.plugins && data.plugins.length > 0) {
      pluginsTitle.style.display = '';
      pluginGrid.innerHTML = data.plugins.map(renderModuleCard).join('');
    }
  } catch (error) {
    console.error('Failed to load modules:', error);
    document.getElementById('moduleGrid').innerHTML =
      '<p style="color:var(--text-muted)">Failed to load modules. Please try again.</p>';
  }
}

document.addEventListener('DOMContentLoaded', initHub);
