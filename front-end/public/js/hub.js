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
  const href = isActive ? (mod.entry_url || '/' + mod.key) : '/' + mod.key;

  return `
    <a href="${href}" class="module-card" style="--card-accent: ${mod.color || '#0c234b'}">
      <div class="module-card-header">
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

    // Hide an entry when every one of its sub-items is gated to a role this
    // user doesn't hold — the same rule the sidebar uses, so a student never
    // sees a Cyber Learning Environment card they'd only get 403s from.
    // Fails closed while Auth.user is still resolving.
    const user = Auth.getUser();
    const isVisible = (mod) => {
      const sn = (data.subnavs || {})[mod.key];
      if (!sn || !Array.isArray(sn.items) || sn.items.length === 0) return true;
      return sn.items.some(item => !item.roles || item.roles.includes(user?.role));
    };

    // One grid, ordered by display_order. Modules and plugins were split into
    // two headed sections, which meant nothing to students and — with the
    // scaffolding modules now hidden — left a heading over a single card.
    const entries = [...(data.modules || []), ...(data.plugins || [])]
      .filter(isVisible)
      .sort((a, b) => (a.display_order ?? 0) - (b.display_order ?? 0));

    const moduleGrid = document.getElementById('moduleGrid');
    if (entries.length > 0) {
      moduleGrid.innerHTML = entries.map(renderModuleCard).join('');
    } else {
      moduleGrid.innerHTML = '<p style="color:var(--text-muted)">No modules available.</p>';
    }
  } catch (error) {
    console.error('Failed to load modules:', error);
    document.getElementById('moduleGrid').innerHTML =
      '<p style="color:var(--text-muted)">Failed to load modules. Please try again.</p>';
  }
}

document.addEventListener('DOMContentLoaded', initHub);
