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

    const mfaScopeSelect = document.getElementById('settingsMfaScope');
    if (mfaScopeSelect) mfaScopeSelect.value = data.mfa_required_scope === 'all' ? 'all' : 'privileged';
  } catch (e) {
    console.warn('[Settings] Could not load site settings:', e.message);
  }
}

async function saveMfaScope() {
  const scope = document.getElementById('settingsMfaScope').value;
  const status = document.getElementById('mfaScopeStatus');
  status.innerHTML = '<strong style="color: var(--gray-500);">Saving...</strong>';
  try {
    await api('PATCH', '/settings/mfa', { mfa_required_scope: scope });
    status.innerHTML = `<strong style="color: #38a169;">✓ Saved</strong>`;
    Toast.success('MFA Policy Saved', scope === 'all' ? 'MFA now required for all users' : 'MFA required for admins & instructors');
  } catch (e) {
    status.innerHTML = `<strong style="color: #e53e3e;">Error:</strong> ${escHtml(e.message)}`;
    Toast.error('Save Failed', e.message);
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

// ============================================================================
// EMAIL DELIVERY
// ============================================================================
//
// Read-only by design: mail is configured by environment variables, and a
// settings screen that appeared to change them would be lying. What this panel
// is for is answering "will an invitation actually reach a student", which
// previously required shell access to the container.

/** One label/value row. Values come from the server, so they are escaped. */
function mailRow(label, value, tone) {
  const color = tone === 'bad' ? '#e53e3e' : tone === 'good' ? '#38a169' : 'inherit';
  return `<div style="display: flex; justify-content: space-between; gap: 1rem; padding: 0.3rem 0; border-bottom: 1px solid var(--border-color, #e2e8f0);">
      <span style="color: var(--gray-500);">${escHtml(label)}</span>
      <span style="text-align: right; word-break: break-all; color: ${color};">${escHtml(value)}</span>
    </div>`;
}

async function loadMailStatus() {
  const box = document.getElementById('mailStatusBox');
  if (!box) return;

  try {
    const s = await api('GET', '/mail/status');
    // Shared with the Broadcast tab, which needs to warn about an unconfigured
    // relay the instant it opens rather than after a second round trip.
    window.__mailStatus = s;
    if (typeof paintBroadcastMailBanner === 'function') paintBroadcastMailBanner();

    // Both of these must be true for anything to send, and each fails in its
    // own quiet way — enabled-without-a-key still records every message as
    // suppressed, which looks identical to "working" from the outside.
    const ready = s.enabled && s.encryption_key_configured;

    let html = `<div style="padding: 0.5rem 0.75rem; border-radius: 6px; margin-bottom: 0.75rem; background: ${ready ? '#f0fff4' : '#fffbeb'}; color: ${ready ? '#276749' : '#b7791f'};">
        <strong>${ready ? '✓ Mail is configured' : '⚠ Mail will not send'}</strong>
      </div>`;

    html += mailRow('Enabled', s.enabled ? 'yes' : 'no', s.enabled ? 'good' : 'bad');
    html += mailRow('Encryption key', s.encryption_key_configured ? 'configured' : 'missing',
      s.encryption_key_configured ? 'good' : 'bad');
    html += mailRow('Relay', s.host ? `${s.host}:${s.port}` : '—');
    html += mailRow('From', s.from || '—');
    html += mailRow('Public URL', s.public_url || '— (activation links will be broken)',
      s.public_url ? null : 'bad');
    html += mailRow('Recipient allowlist',
      (s.allowed_recipient_domains && s.allowed_recipient_domains.length)
        ? s.allowed_recipient_domains.join(', ')
        : 'any domain');
    html += mailRow('Cohort domain (never emailed)', s.cohort_domain || '—');

    const queue = s.queue || [];
    html += `<div style="margin-top: 0.75rem;"><strong>Queue</strong></div>`;
    html += queue.length
      ? queue.map(q => mailRow(q.status, String(q.n), q.status === 'failed' ? 'bad' : null)).join('')
      : `<div style="color: var(--gray-500); padding: 0.3rem 0;">empty</div>`;

    for (const hint of [s.hint, s.hint_key].filter(Boolean)) {
      html += `<div style="margin-top: 0.5rem; font-size: 0.78rem; color: #b7791f;">${escHtml(hint)}</div>`;
    }

    box.innerHTML = html;
  } catch (e) {
    box.innerHTML = `<p style="color: #e53e3e; padding: 1rem 0;">Could not load mail status: ${escHtml(e.message)}</p>`;
  }
}

async function sendMailTest() {
  const to = document.getElementById('mailTestTo').value.trim();
  const status = document.getElementById('mailTestStatus');
  const btn = document.getElementById('mailTestBtn');

  if (!to) {
    Toast.warning('Missing', 'Enter an address to send the test to');
    return;
  }

  Utils.setBtnLoading(btn, true, 'Sending…');
  status.innerHTML = '';

  try {
    const result = await api('POST', '/mail/test', { to });
    status.innerHTML = `<strong style="color: #38a169;">✓ Accepted by the relay</strong>
      <div style="margin-top: 0.35rem; color: var(--gray-500);">${escHtml(result.note || '')}</div>`;
    Toast.success('Test Sent', `The relay accepted a message for ${to}`);
    loadMailStatus();
  } catch (e) {
    // A refusal here is the diagnostic, not an incidental error — it is the
    // relay's own words about why it will not take the message.
    status.innerHTML = `<strong style="color: #e53e3e;">Relay refused:</strong> ${escHtml(e.message)}`;
    Toast.error('Test Failed', e.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}
