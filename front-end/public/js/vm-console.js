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
  // Most recent launch URL, kept for the "Open in new tab" button.
  let _activeLaunchUrl = null;

  // ──────────────────────────────────────────────────────────────────────────
  // Rendering helpers
  // ──────────────────────────────────────────────────────────────────────────

  function _toolbar(label, withControls = false) {
    const controls = withControls
      ? `<button class="vmc-tool-btn" onclick="VmConsole.fullscreen()" title="Toggle full-screen (Esc to exit)">⛶ Full-screen</button>
         <button class="vmc-tool-btn" onclick="VmConsole.popout()" title="Open console in a new tab">⇗ Pop out</button>`
      : '';
    return `
      <div class="vmc-toolbar">
        <span class="vmc-title">${label}</span>
        <span class="vmc-tool-spacer"></span>
        ${controls}
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
    _activeLaunchUrl = launchUrl;
    // No sandbox attribute: Guacamole is same-origin (served behind /guacamole),
    // so sandbox+allow-same-origin provided no isolation anyway — and sandboxing
    // broke keyboard capture in the embedded client (typing only worked in the
    // popped-out window).
    container.innerHTML = `
      <div class="vmc-panel">
        ${_toolbar('Remote Console', true)}
        <div class="vmc-body vmc-iframe-wrap">
          <iframe
            src="${launchUrl}"
            class="vmc-iframe"
            tabindex="0"
            allow="clipboard-read; clipboard-write; fullscreen; pointer-lock"
            referrerpolicy="no-referrer"
          ></iframe>
        </div>
      </div>
    `;
    // Guacamole's keyboard handler only sees keystrokes once the iframe's
    // document has focus. Focus it on load and re-focus on any click inside
    // the panel so the user can always just click the screen and type.
    const frame = container.querySelector('.vmc-iframe');
    if (frame) {
      frame.addEventListener('load', () => { try { frame.focus(); } catch (_) {} });
      container.querySelector('.vmc-iframe-wrap')?.addEventListener('mousedown', () => {
        try { frame.focus(); } catch (_) {}
      });
    }
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
    _activeLaunchUrl = null;
    const panel = document.querySelector('.vmc-panel');
    if (panel) {
      const container = panel.closest('[id]') || panel.parentElement;
      panel.remove();
      if (container) container.style.display = 'none';
    }
  }

  /**
   * Open the active console in a new browser tab so it can run in its own
   * window (resizable, full-tab area, no iframe nesting). Closes the
   * embedded iframe immediately so the user doesn't end up with two live
   * sessions competing for the same Guacamole connection (max-connections
   * per user is usually 1 — leaving both open would prevent the popout from
   * actually connecting).
   */
  function popout() {
    if (!_activeLaunchUrl) return;
    const url = _activeLaunchUrl;
    // window.open returns immediately; the new tab is still loading when
    // close() removes the iframe, so the embedded session releases its
    // Guac slot well before the new tab tries to claim it.
    window.open(url, '_blank', 'noopener,noreferrer');
    close();
  }

  /**
   * Request browser fullscreen on the active console panel. Press Esc to exit.
   */
  function fullscreen() {
    const panel = document.querySelector('.vmc-panel');
    if (!panel) return;
    if (document.fullscreenElement) {
      document.exitFullscreen().catch(() => {});
    } else {
      panel.requestFullscreen().catch(err => {
        console.warn('Fullscreen request failed:', err.message);
      });
    }
  }

  return { open, close, popout, fullscreen };
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
  // UI-side filter: hide cards that have no Guac console (lane target VMs
  // are pivot-only, never directly accessed). Default ON because the typical
  // student/admin only cares about cards they can actually click.
  let _consoleOnly = true;
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

  // Inject the scope toggle (admin-only) + the console filter toggle (everyone)
  // next to the "Lane VMs" section header. Idempotent — safe to call on every render.
  function _renderHeaderToggle() {
    const title = document.querySelector('#workspaces-myworkspacesContent .section-title[data-lane-section="lanes"]')
                || document.querySelector('#workspaces-myworkspacesContent .section-title:first-of-type');
    if (!title) return;

    // Console filter — visible to all users
    let consoleToggle = document.getElementById('vmlConsoleToggle');
    if (!consoleToggle) {
      consoleToggle = document.createElement('div');
      consoleToggle.id = 'vmlConsoleToggle';
      consoleToggle.style.cssText = 'display:inline-flex;gap:8px;margin-left:16px;font-size:12px;font-weight:normal;text-transform:none;letter-spacing:normal;';
      consoleToggle.innerHTML = `
        <span style="color:var(--text-secondary)">Show:</span>
        <a href="#" data-filter="console" class="wks-scope-link">With console</a>
        <span style="color:var(--text-secondary)">|</span>
        <a href="#" data-filter="all" class="wks-scope-link">All VMs</a>`;
      title.appendChild(consoleToggle);
      consoleToggle.querySelectorAll('a').forEach(a => {
        a.addEventListener('click', (e) => {
          e.preventDefault();
          const next = a.dataset.filter === 'console';
          if (next === _consoleOnly) return;
          _consoleOnly = next;
          if (_lastListEl) render(_lastListEl, _lastConsoleId);
        });
      });
    }
    consoleToggle.querySelectorAll('a').forEach(a => {
      const active = (a.dataset.filter === 'console') === _consoleOnly;
      a.style.fontWeight = active ? '600' : 'normal';
      a.style.color = active ? 'var(--text-primary)' : 'var(--text-secondary)';
      a.style.textDecoration = active ? 'underline' : 'none';
    });

    // Scope toggle — admin/instructor only
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
        <span style="color:var(--text-secondary)">Users:</span>
        <a href="#" data-scope="all" class="wks-scope-link">All</a>
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
      const rawVms = data.vms || [];
      // Console filter: by default we only show cards the user can actually
      // click. Lane target VMs (ws01, ws02, etc.) have no Guac connection —
      // they're pivot-only from Kali — so listing them is just visual noise.
      // Flip via the "All VMs" toggle to see the full inventory.
      const vms = _consoleOnly ? rawVms.filter(v => v.hasConsole) : rawVms;

      if (vms.length === 0) {
        const adminAll = _isPrivileged() && _scopeAll;
        // If the console filter is hiding everything, hint at the toggle.
        if (_consoleOnly && rawVms.length > 0) {
          listEl.innerHTML = `
            <div class="vml-empty">
              <span class="vml-empty-icon">🖥</span>
              <p>${rawVms.length} VM${rawVms.length === 1 ? '' : 's'} hidden — none have a console configured.</p>
              <p style="font-size:0.85rem;color:var(--text-muted)">
                Lane target VMs are accessed by pivoting from Kali. Click <strong>All VMs</strong> above to see them.
              </p>
            </div>`;
          return;
        }
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
