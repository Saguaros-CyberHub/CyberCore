// ============================================================================
// SETTINGS TAB
// ============================================================================

async function loadSiteSettings() {
  try {
    const data = await api('GET', '/settings');
    const siteName = data.site_name || 'CyberHub';
    const logoUrl = data.site_logo_url || '';
    const faviconUrl = data.site_favicon_url || '';
    const description = data.site_description || '';

    // Update everywhere via Layout
    Layout.updateSiteName(siteName + ' Administration');

    // Pre-fill the input fields
    const nameInput = document.getElementById('settingsSiteName');
    const logoInput = document.getElementById('settingsSiteLogo');
    const faviconInput = document.getElementById('settingsSiteFavicon');
    const descInput = document.getElementById('settingsSiteDesc');

    if (nameInput) nameInput.value = siteName;
    if (logoInput) logoInput.value = logoUrl;
    if (faviconInput) faviconInput.value = faviconUrl;
    if (descInput) descInput.value = description;
  } catch (e) {
    console.warn('[Settings] Could not load site settings:', e.message);
  }
}

async function saveSiteSettings() {
  const siteName = document.getElementById('settingsSiteName').value.trim();
  const logoUrl = document.getElementById('settingsSiteLogo').value.trim();
  const faviconUrl = document.getElementById('settingsSiteFavicon').value.trim();
  const description = document.getElementById('settingsSiteDesc').value.trim();
  const status = document.getElementById('siteSettingsStatus');

  if (!siteName) {
    Toast.warning('Missing', 'Site display name is required');
    return;
  }

  status.innerHTML = '<strong style="color: var(--gray-500);">Saving...</strong>';

  try {
    const data = await api('PATCH', '/settings/site-config', {
      site_name: siteName,
      site_logo_url: logoUrl || null,
      site_favicon_url: faviconUrl || null,
      site_description: description || null
    });

    // Update everywhere via Layout
    Layout.updateSiteName(siteName + ' Administration');

    // Also update the admin page header
    document.getElementById('pageTitle').textContent = siteName + ' Administration';

    status.innerHTML = `<strong style="color: #38a169;">✓ Saved successfully</strong>`;
    Toast.success('Settings Saved', `Site configured successfully`);
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Error:</strong> ${escHtml(e.message)}`;
    Toast.error('Save Failed', e.message);
  }
}

async function loadModules() {
  const container = document.getElementById('modulesPluginsList');
  container.innerHTML = '<p style="color: var(--gray-500); text-align: center; padding: 2rem;">Loading...</p>';

  try {
    const data = await api('GET', '/settings/modules');
    const modules = data.modules || [];

    if (modules.length === 0) {
      container.innerHTML = '<p style="color: var(--gray-500); text-align: center; padding: 2rem;">No modules found.</p>';
      return;
    }

    let html = '';
    modules.forEach(module => {
      const plugins = module.plugins || [];
      html += `
        <div style="border: 1px solid #e2e8f0; border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
          <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.75rem;">
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <input type="checkbox" id="module-${escHtml(module.key)}"
                ${module.enabled ? 'checked' : ''}
                data-type="module" data-key="${escHtml(module.key)}"
                style="width: auto; cursor: pointer;">
              <label for="module-${escHtml(module.key)}" style="cursor: pointer; margin: 0; font-weight: 600; font-size: 0.95rem;">
                ${escHtml(module.name || module.key)}
              </label>
            </div>
            <span class="badge ${module.enabled ? 'badge-green' : 'badge-gray'}">
              ${module.enabled ? 'Enabled' : 'Disabled'}
            </span>
          </div>
          ${module.description ? `<p style="color: var(--gray-500); font-size: 0.8rem; margin: 0 0 0.75rem 1.75rem;">${escHtml(module.description)}</p>` : ''}

          ${plugins.length > 0 ? `
            <div style="margin-left: 1.75rem; padding-left: 0.75rem; border-left: 2px solid #e2e8f0;">
              ${plugins.map(plugin => `
                <div style="display: flex; align-items: center; gap: 0.5rem; padding: 0.5rem 0;">
                  <input type="checkbox" id="plugin-${escHtml(plugin.key)}"
                    ${plugin.enabled ? 'checked' : ''}
                    data-type="plugin" data-key="${escHtml(plugin.key)}" data-parent="${escHtml(module.key)}"
                    style="width: auto; cursor: pointer;">
                  <label for="plugin-${escHtml(plugin.key)}" style="cursor: pointer; margin: 0; font-size: 0.9rem;">
                    ${escHtml(plugin.name || plugin.key)}
                  </label>
                  <span style="font-size: 0.7rem; color: var(--gray-500); margin-left: auto;">
                    ${plugin.enabled ? '✓' : '−'}
                  </span>
                </div>
              `).join('')}
            </div>
          ` : ''}
        </div>`;
    });

    container.innerHTML = html;

    // Add event listeners to update visual feedback
    container.querySelectorAll('input[type="checkbox"]').forEach(checkbox => {
      checkbox.addEventListener('change', function() {
        const badgeEl = this.closest('div').querySelector('.badge');
        if (badgeEl) {
          badgeEl.textContent = this.checked ? 'Enabled' : 'Disabled';
          badgeEl.className = `badge ${this.checked ? 'badge-green' : 'badge-gray'}`;
        }
        const statusIcon = this.parentElement.querySelector('[style*="margin-left: auto"]');
        if (statusIcon && this.dataset.type === 'plugin') {
          statusIcon.textContent = this.checked ? '✓' : '−';
        }
      });
    });
  } catch (e) {
    container.innerHTML = `<p style="color: #e53e3e; text-align: center; padding: 2rem;">Error loading modules: ${escHtml(e.message)}</p>`;
    Toast.error('Load Failed', e.message);
  }
}

async function saveModuleSettings() {
  const container = document.getElementById('modulesPluginsList');
  const status = document.getElementById('moduleSettingsStatus');

  // Collect all checkbox states
  const modules = [];
  const plugins = [];

  container.querySelectorAll('input[data-type="module"]').forEach(checkbox => {
    modules.push({
      key: checkbox.dataset.key,
      enabled: checkbox.checked
    });
  });

  container.querySelectorAll('input[data-type="plugin"]').forEach(checkbox => {
    plugins.push({
      key: checkbox.dataset.key,
      parent: checkbox.dataset.parent,
      enabled: checkbox.checked
    });
  });

  if (modules.length === 0 && plugins.length === 0) {
    Toast.warning('No Changes', 'No modules or plugins to save');
    return;
  }

  status.innerHTML = '<strong style="color: var(--gray-500);">Saving...</strong>';

  try {
    const data = await api('PATCH', '/settings/modules', { modules, plugins });
    status.innerHTML = `<strong style="color: #38a169;">✓ Saved successfully</strong>`;
    Toast.success('Modules Updated', `${modules.length} modules and ${plugins.length} plugins configured`);
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Error:</strong> ${escHtml(e.message)}`;
    Toast.error('Save Failed', e.message);
  }
}
