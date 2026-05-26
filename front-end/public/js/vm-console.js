/**
 * ============================================================================
 * VmConsole — Embedded remote console panel (Apache Guacamole via iframe)
 * ============================================================================
 * Requests a Guacamole launch URL from the CyberCore backend, which enforces
 * authorization before returning a safe URL. The frontend never handles
 * credentials, VM IPs, or Guacamole connection parameters directly.
 *
 * Usage:
 *   VmConsole.open(vmId, containerElement)  — launch console into a container
 *   VmConsole.close()                        — dismiss active console
 * ============================================================================
 */

const VmConsole = (() => {
  'use strict';

  // Track the vmId currently being requested so stale callbacks don't render.
  let _activeVmId = null;

  // ──────────────────────────────────────────────────────────────────────────
  // Rendering helpers
  // ──────────────────────────────────────────────────────────────────────────

  function _toolbar(label) {
    return `
      <div class="vmc-toolbar">
        <span class="vmc-title">${label}</span>
        <button class="vmc-close-btn" onclick="VmConsole.close()" title="Close console">
          ✕ Close
        </button>
      </div>
    `;
  }

  function _renderLoading(container) {
    container.innerHTML = `
      <div class="vmc-panel">
        ${_toolbar('Connecting...')}
        <div class="vmc-body vmc-center">
          <div class="vmc-spinner"></div>
          <span class="vmc-status-text">Establishing secure connection…</span>
        </div>
      </div>
    `;
  }

  function _renderError(container, message) {
    container.innerHTML = `
      <div class="vmc-panel">
        ${_toolbar('Console Error')}
        <div class="vmc-body vmc-center">
          <span class="vmc-error-icon">⚠</span>
          <p class="vmc-error-msg">${Utils.escapeHtml(message)}</p>
          <button class="btn btn-sm" onclick="VmConsole.close()">Dismiss</button>
        </div>
      </div>
    `;
  }

  function _renderIframe(container, launchUrl) {
    container.innerHTML = `
      <div class="vmc-panel">
        ${_toolbar('Remote Console')}
        <div class="vmc-body vmc-iframe-wrap">
          <iframe
            src="${launchUrl}"
            class="vmc-iframe"
            allow="clipboard-read; clipboard-write; fullscreen; pointer-lock"
            referrerpolicy="no-referrer"
            sandbox="allow-scripts allow-same-origin allow-forms allow-downloads allow-modals"
          ></iframe>
        </div>
      </div>
    `;
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Public API
  // ──────────────────────────────────────────────────────────────────────────

  /**
   * Launch the remote console for `vmId` into `container`.
   * @param {string}      vmId      — cybercore_vm_instance.vm_instance_id (UUID)
   * @param {HTMLElement} container — element that will receive the console panel
   */
  async function open(vmId, container) {
    _activeVmId = vmId;
    container.style.display = 'block';
    _renderLoading(container);

    try {
      const data = await API.request(
        `/dashboard/vms/${encodeURIComponent(vmId)}/guac-session`,
        { method: 'POST' }
      );

      // Discard result if user navigated away or opened a different console
      if (_activeVmId !== vmId) return;

      // Pre-authenticate with Guacamole so the iframe never shows the login prompt.
      if (data.guacToken) {
        localStorage.setItem('GUAC_AUTH', JSON.stringify({
          authToken:            data.guacToken,
          username:             data.username,
          dataSource:           data.dataSource,
          availableDataSources: data.availableDataSources,
        }));
      } else if (data.clearGuacAuth) {
        localStorage.removeItem('GUAC_AUTH');
      }

      _renderIframe(container, data.launchUrl);
    } catch (err) {
      if (_activeVmId !== vmId) return;
      const message = err?.data?.error || err?.message || 'Could not connect to remote console.';
      _renderError(container, message);
    }
  }

  /**
   * Dismiss the active console and clear the container.
   */
  function close() {
    _activeVmId = null;
    const panel = document.querySelector('.vmc-panel');
    if (panel) {
      const container = panel.closest('[id]') || panel.parentElement;
      panel.remove();
      if (container) container.style.display = 'none';
    }
  }

  return { open, close };
})();

// ============================================================================
// VM list renderer — used by hub.html "My Workspaces" tab
// ============================================================================

const VmWorkspaces = (() => {
  'use strict';

  const MODULE_LABELS = {
    crucible:   'The Crucible',
    cyberlabs:  'CyberLabs',
    forge:      'The Forge',
    university: 'Saguaros University',
  };

  const POWER_BADGE = {
    running:    { cls: 'vml-badge-on',      label: 'Running' },
    stopped:    { cls: 'vml-badge-off',     label: 'Stopped' },
    suspended:  { cls: 'vml-badge-idle',    label: 'Suspended' },
    unknown:    { cls: 'vml-badge-unknown', label: 'Unknown' },
  };

  // Admin/instructor-only toggle controlling ?scope on /api/dashboard/vms.
  // Default ON for privileged users so they land on the cluster-wide view.
  let _scopeAll = true;
  let _lastListEl = null;
  let _lastConsoleId = null;

  function _isPrivileged() {
    const u = (typeof Auth !== 'undefined') ? Auth.getUser() : null;
    return u && (u.role === 'admin' || u.role === 'instructor');
  }

  function _powerBadge(state) {
    const b = POWER_BADGE[state] || POWER_BADGE.unknown;
    return `<span class="vml-badge ${b.cls}">${b.label}</span>`;
  }

  function _moduleTag(key) {
    const label = MODULE_LABELS[key] || key || 'Unknown';
    return `<span class="vml-module-tag">${Utils.escapeHtml(label)}</span>`;
  }

  function _vmCard(vm, consoleContainerId) {
    const canLaunch = vm.hasConsole && vm.powerState === 'running';
    const launchBtn = vm.hasConsole
      ? `<button
           class="btn btn-sm vml-launch-btn"
           onclick="VmWorkspaces.launch('${vm.id}', '${consoleContainerId}')"
           ${canLaunch ? '' : 'disabled title="VM must be running to open console"'}
         >
           ▶ Open Console
         </button>`
      : `<span class="vml-no-console">No console configured</span>`;

    const ownerBadge = vm.ownerEmail
      ? `<span class="wks-vm-owner" title="Owner">👤 ${Utils.escapeHtml(vm.ownerEmail)}</span>`
      : '';

    return `
      <div class="vml-card">
        <div class="vml-card-header">
          <span class="vml-vm-icon">🖥</span>
          <div class="vml-card-info">
            <div class="vml-vm-name">${Utils.escapeHtml(vm.name)}</div>
            <div class="vml-vm-meta">
              ${_moduleTag(vm.moduleKey)}
              ${_powerBadge(vm.powerState || 'unknown')}
              ${ownerBadge}
            </div>
          </div>
        </div>
        <div class="vml-card-actions">${launchBtn}</div>
      </div>
    `;
  }

  // Inject the admin/instructor scope toggle next to the "Lane VMs" section
  // header. Idempotent — safe to call on every render.
  function _renderHeaderToggle() {
    const title = document.querySelector('#workspaces-myworkspacesContent .section-title[data-lane-section="lanes"]')
                || document.querySelector('#workspaces-myworkspacesContent .section-title:first-of-type');
    if (!title) return;
    if (!_isPrivileged()) {
      const existing = document.getElementById('vmlScopeToggle');
      if (existing) existing.remove();
      return;
    }
    let toggle = document.getElementById('vmlScopeToggle');
    if (!toggle) {
      toggle = document.createElement('div');
      toggle.id = 'vmlScopeToggle';
      toggle.style.cssText = 'display:inline-flex;gap:8px;margin-left:16px;font-size:12px;font-weight:normal;text-transform:none;letter-spacing:normal;';
      toggle.innerHTML = `
        <span style="color:var(--text-secondary)">Show:</span>
        <a href="#" data-scope="all" class="wks-scope-link">All users</a>
        <span style="color:var(--text-secondary)">|</span>
        <a href="#" data-scope="mine" class="wks-scope-link">Me only</a>`;
      title.appendChild(toggle);
      toggle.querySelectorAll('a').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const next = a.dataset.scope === 'all';
          if (next === _scopeAll) return;
          _scopeAll = next;
          if (_lastListEl) render(_lastListEl, _lastConsoleId);
        });
      });
    }
    toggle.querySelectorAll('a').forEach(a => {
      const active = (a.dataset.scope === 'all') === _scopeAll;
      a.style.fontWeight = active ? '600' : 'normal';
      a.style.color = active ? 'var(--text-primary)' : 'var(--text-secondary)';
      a.style.textDecoration = active ? 'underline' : 'none';
    });
  }

  /**
   * Fetch and render the user's VM list into `listEl`.
   * `consoleContainerId` is the ID of the element VmConsole should render into.
   */
  async function render(listEl, consoleContainerId) {
    _lastListEl = listEl;
    _lastConsoleId = consoleContainerId;
    _renderHeaderToggle();
    listEl.innerHTML = '<div class="vml-loading">Loading workspaces…</div>';

    try {
      // Admins/instructors default to scope=all; non-admins ignore the param server-side.
      const scopeQuery = _isPrivileged() && !_scopeAll ? '?scope=mine' : '';
      const data = await API.request(`/dashboard/vms${scopeQuery}`);
      const vms = data.vms || [];

      if (vms.length === 0) {
        const adminAll = _isPrivileged() && _scopeAll;
        listEl.innerHTML = adminAll
          ? `<div class="vml-empty">
               <span class="vml-empty-icon">🖥</span>
               <p>No active lane VMs in the cluster.</p>
               <p style="font-size:0.85rem;color:var(--text-muted)">
                 Lane VMs deployed by Crucible / CyberLabs / Forge appear here.
               </p>
             </div>`
          : `<div class="vml-empty">
               <span class="vml-empty-icon">🖥</span>
               <p>No VMs are currently assigned to your account.</p>
               <p style="font-size:0.85rem;color:var(--text-muted)">
                 VMs provisioned by CyberLabs, Forge, or other modules will appear here.
               </p>
             </div>`;
        return;
      }

      listEl.innerHTML = vms.map(vm => _vmCard(vm, consoleContainerId)).join('');
    } catch (err) {
      const msg = err?.data?.error || err?.message || 'Failed to load workspaces.';
      listEl.innerHTML = `<div class="vml-error">⚠ ${Utils.escapeHtml(msg)}</div>`;
    }
  }

  /**
   * Triggered by "Open Console" button in a VM card.
   */
  function launch(vmId, consoleContainerId) {
    const container = document.getElementById(consoleContainerId);
    if (!container) return;
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    VmConsole.open(vmId, container);
  }

  return { render, launch };
})();
