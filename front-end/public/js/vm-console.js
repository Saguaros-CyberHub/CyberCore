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
  let _activeContainer = null;
  let _activeAnalysis = null;
  let _launchRequest = 0;

  function _analysisNotice() {
    if (_activeAnalysis?.profile !== 'malware') return '';
    const labels = {
      preparation: 'Preparation · Internet available',
      isolating: 'Securing lab and starting FakeNet…',
      analysis: 'Analysis active · Internet blocked · Clipboard exchange disabled',
      resetting: 'Resetting lab · Restoring clean templates…',
      error: 'Analysis is not ready · Check the lab status below',
    };
    return `<div class="vmc-analysis-notice" role="status">${Utils.escapeHtml(labels[_activeAnalysis.state] || 'Checking lab status…')}</div>`;
  }

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
      ${_analysisNotice()}
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
  async function open(vmId, container, analysis = null) {
    _activeVmId = vmId;
    _activeContainer = container;
    _activeAnalysis = analysis;
    const request = ++_launchRequest;
    container.style.display = 'block';
    _renderLoading(container);

    try {
      const data = await API.request(
        `/dashboard/vms/${encodeURIComponent(vmId)}/guac-session`,
        { method: 'POST' }
      );

      // Discard result if user navigated away or opened a different console
      if (_activeVmId !== vmId || request !== _launchRequest) return;

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
      if (_activeVmId !== vmId || request !== _launchRequest) return;
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
    _activeContainer = null;
    _activeAnalysis = null;
    ++_launchRequest;
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

  function setAnalysis(vmId, analysis) {
    if (_activeVmId !== vmId) return;
    _activeAnalysis = analysis;
    const panel = _activeContainer?.querySelector('.vmc-panel');
    if (!panel) return;
    panel.querySelector('.vmc-analysis-notice')?.remove();
    panel.querySelector('.vmc-toolbar')?.insertAdjacentHTML('afterend', _analysisNotice());
  }

  function reconnect(vmId) {
    if (_activeVmId !== vmId || !_activeContainer) return;
    return open(vmId, _activeContainer, _activeAnalysis);
  }

  return { open, close, popout, fullscreen, setAnalysis, reconnect, activeVmId: () => _activeVmId };
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
  const _views = new Map();
  const _vms = new Map();
  const _operations = new Map();
  const _posting = new Set();

  function _laneKey(vm) {
    return vm?.analysis?.laneId || vm?.laneId || vm?.id;
  }

  function _analysisControls(vm) {
    const analysis = vm.analysis;
    if (analysis?.profile !== 'malware') return '';
    const busy = ['isolating', 'resetting'].includes(analysis.state) || _posting.has(_laneKey(vm));
    const labels = {
      preparation: 'Preparation · Internet available',
      isolating: 'Securing lab and starting FakeNet…',
      analysis: 'Analysis active · Internet blocked',
      resetting: 'Resetting lab · Restoring clean templates…',
      error: 'Analysis is not ready',
    };
    const startLabel = analysis.state === 'analysis' ? 'Analysis Active'
      : analysis.state === 'isolating' ? 'Securing Lab…' : 'Start Analysis';
    const tone = analysis.state === 'analysis' ? 'ready' : analysis.state === 'error' ? 'error' : 'pending';
    return `
      <div class="vml-analysis-status vml-analysis-${tone}" role="status" aria-live="polite">
        <strong>${Utils.escapeHtml(labels[analysis.state] || 'Checking lab status…')}</strong>
        ${analysis.message ? `<span>${Utils.escapeHtml(analysis.message)}</span>` : ''}
        ${analysis.state === 'analysis' ? '<span>FakeNet captures and logs are in C:\\Analysis. Copy/paste within the workstation still works.</span>' : ''}
      </div>
      <div class="vml-card-actions vml-analysis-actions" aria-busy="${busy}">
        <button type="button" class="btn btn-sm vml-analysis-start" data-analysis-action="start"
          ${!busy && analysis.canStart === true ? '' : 'disabled'}>${startLabel}</button>
        <button type="button" class="btn btn-sm vml-analysis-reset" data-analysis-action="reset"
          ${!busy && analysis.canReset === true ? '' : 'disabled'}>${analysis.state === 'resetting' ? 'Resetting Lab…' : 'Reset Lab'}</button>
      </div>`;
  }

  function _bindAnalysisActions(listEl) {
    listEl.querySelectorAll('[data-analysis-action]').forEach(button => {
      button.addEventListener('click', () => {
        const vmId = button.closest('[data-vm-id]')?.dataset.vmId;
        if (vmId) runAnalysis(vmId, button.dataset.analysisAction);
      });
    });
  }

  function _paintView(listEl, view) {
    listEl.innerHTML = view.vms.map(vm => _vmCard(vm, view.consoleContainerId)).join('');
    _bindAnalysisActions(listEl);
  }

  function _applyAnalysis(vmId, analysis) {
    const source = _vms.get(vmId);
    const laneKey = analysis.laneId || _laneKey(source);
    const affected = [];
    for (const [id, vm] of _vms) {
      if (id !== vmId && (!laneKey || _laneKey(vm) !== laneKey)) continue;
      if (vm.analysis?.profile !== 'malware') continue;
      vm.analysis = { ...analysis };
      affected.push(id);
      VmConsole.setAnalysis(id, vm.analysis);
    }
    for (const [listEl, view] of _views) {
      if (!listEl.isConnected) { _views.delete(listEl); continue; }
      if (!view.vms.length) continue;
      view.vms = view.vms.map(vm => _vms.get(vm.id) || vm);
      _paintView(listEl, view);
    }
    return affected;
  }

  async function _refreshViews() {
    await Promise.all([..._views].filter(([el]) => el.isConnected)
      .map(([el, view]) => render(el, view.consoleContainerId, { ...view.opts, quiet: true })));
  }

  function _statusPath(vmId, response) {
    // API.request adds /api. Never poll a foreign URL supplied in a response.
    const path = response?.statusUrl;
    return typeof path === 'string' && /^\/(?:api\/)?dashboard\//.test(path)
      ? path.replace(/^\/api\//, '/') : `/dashboard/vms/${encodeURIComponent(vmId)}/analysis`;
  }

  function _scheduleAnalysis(vmId, response = {}, action = null, delay = 1500) {
    const laneKey = _laneKey(_vms.get(vmId));
    const existingId = laneKey && [..._operations.keys()].find(id => _laneKey(_vms.get(id)) === laneKey);
    if (existingId && existingId !== vmId) return _scheduleAnalysis(existingId, response, action, delay);
    let operation = _operations.get(vmId);
    if (!operation) {
      operation = { path: _statusPath(vmId, response), action, timer: null, inFlight: false };
      _operations.set(vmId, operation);
    } else {
      if (response.statusUrl) operation.path = _statusPath(vmId, response);
      if (action) operation.action = action;
    }
    if (operation.timer || operation.inFlight) return;
    operation.timer = setTimeout(async () => {
      operation.timer = null;
      operation.inFlight = true;
      try {
        const data = await API.request(operation.path);
        const analysis = data.analysis || data;
        if (analysis.profile !== 'malware' || !analysis.state) throw new Error('Lab status is unavailable.');
        const affected = _applyAnalysis(vmId, analysis);
        if (['isolating', 'resetting'].includes(analysis.state)) {
          operation.inFlight = false;
          _scheduleAnalysis(vmId, data);
          return;
        }
        _operations.delete(vmId);
        if (analysis.state === 'analysis') {
          // The backend ends pre-analysis sessions; reconnect the embedded console
          // only after it reports both containment and the new console policy ready.
          for (const id of affected) await VmConsole.reconnect(id);
          if (operation.action === 'start') Toast.success('Analysis ready', 'Internet and clipboard exchange are disabled.');
        } else if (analysis.state === 'preparation' && operation.action === 'reset') {
          Toast.success('Lab reset', 'Your clean lab is ready. All previous files and changes were removed.');
        } else if (analysis.state === 'error') {
          Toast.error('Lab needs attention', analysis.message || 'The operation could not be completed.');
        }
        await _refreshViews();
      } catch (err) {
        const vm = _vms.get(vmId);
        if (vm?.analysis) _applyAnalysis(vmId, {
          ...vm.analysis,
          message: 'Connection interrupted. Checking lab status again…',
          canStart: false, canReset: false,
        });
        operation.inFlight = false;
        _scheduleAnalysis(vmId, {}, null, 5000);
      }
    }, delay);
  }

  async function runAnalysis(vmId, action) {
    const vm = _vms.get(vmId);
    if (!vm || vm.analysis?.profile !== 'malware' || !['start', 'reset'].includes(action)) return;
    const key = _laneKey(vm);
    if (_posting.has(key) || ['isolating', 'resetting'].includes(vm.analysis.state)) return;
    if (action === 'start' ? !vm.analysis.canStart : !vm.analysis.canReset) return;
    if (action === 'reset' && !window.confirm('Reset this lab? All downloaded files, samples, and changes on every machine in this lab will be deleted. The workstation and gateway will be rebuilt from their clean templates.')) return;

    _posting.add(key);
    _applyAnalysis(vmId, {
      ...vm.analysis, state: action === 'start' ? 'isolating' : 'resetting',
      message: action === 'start' ? 'Wait for Analysis active before opening a sample.' : 'Rebuilding the lab can take several minutes.',
      canStart: false, canReset: false,
    });
    try {
      const data = await API.request(`/dashboard/vms/${encodeURIComponent(vmId)}/analysis/${action}`, { method: 'POST' });
      if (data.analysis) _applyAnalysis(vmId, data.analysis);
      if (action === 'reset' && _laneKey(_vms.get(VmConsole.activeVmId())) === key) VmConsole.close();
      _scheduleAnalysis(vmId, data, action, 100);
    } catch (err) {
      const message = err?.data?.error || err?.message || 'Could not request the lab operation.';
      Toast.error(action === 'start' ? 'Could not start analysis' : 'Could not reset lab', message);
      // A lost response can mean the request succeeded. Read server state before
      // enabling another destructive action or showing the lab as ready.
      _applyAnalysis(vmId, { ...vm.analysis, message: `${message} Checking lab status…`, canStart: false, canReset: false });
      _scheduleAnalysis(vmId, {}, action, 100);
    } finally {
      _posting.delete(key);
    }
  }

  function _isPrivileged() {
    const u = (typeof Auth !== 'undefined') ? Auth.getUser() : null;
    return u && (u.role === 'admin' || u.role === 'instructor');
  }

  // Drawing the list the way a student's looks, for lecture recordings.
  function _studentView() {
    return typeof Auth !== 'undefined'
      && typeof Auth.isViewingAsStudent === 'function'
      && Auth.isViewingAsStudent();
  }

  function _powerBadge(state) {
    const b = POWER_BADGE[state] || POWER_BADGE.unknown;
    return `<span class="vml-badge ${b.cls}">${b.label}</span>`;
  }

  function _moduleTag(key) {
    const label = MODULE_LABELS[key] || key || 'Unknown';
    return `<span class="vml-module-tag">${Utils.escapeHtml(label)}</span>`;
  }

  // Known keys get their own colour (see hub.html .vml-os-*); anything the
  // backend couldn't classify returns no label and gets no tag at all, which
  // reads better than a wrong one.
  function _osTag(vm) {
    if (!vm.osLabel) return '';
    const key = String(vm.osKey || 'other').replace(/[^a-z0-9]/gi, '');
    return `<span class="vml-os-tag vml-os-${key}">${Utils.escapeHtml(vm.osLabel)}</span>`;
  }

  function _vmCard(vm, consoleContainerId) {
    const transitioning = ['isolating', 'resetting'].includes(vm.analysis?.state);
    const canLaunch = vm.hasConsole && vm.powerState === 'running' && !transitioning;
    const launchBtn = vm.hasConsole
      ? `<button
           class="btn btn-sm vml-launch-btn"
           onclick="VmWorkspaces.launch('${vm.id}', '${consoleContainerId}')"
           ${canLaunch ? '' : `disabled title="${transitioning ? 'Wait for the lab operation to finish' : 'VM must be running to open console'}"`}
         >
           ▶ Open Console
         </button>`
      : `<span class="vml-no-console">No console configured</span>`;

    const ownerBadge = vm.ownerEmail
      ? `<span class="wks-vm-owner" title="Owner">👤 ${Utils.escapeHtml(vm.ownerEmail)}</span>`
      : '';

    // Lab infrastructure the student who owns it cannot see, launch, or read a
    // password for (server-side — see src/utils/workspace-visibility.js). The
    // flag only ever reaches an admin or instructor, so this badge cannot
    // appear on a student's page and tell them what they are missing. Without
    // it, the rule is invisible: an instructor comparing their screen to a
    // student's would find an extra card and no explanation for it.
    // The title is one line on purpose: a browser renders a tooltip attribute
    // verbatim, newlines and source indentation included.
    const hiddenBadge = vm.studentHidden
      ? `<span class="vml-badge vml-badge-idle" title="Lab infrastructure. The student this is allocated to cannot see it, open its console, or read its password.">🙈 Hidden from student</span>`
      : '';

    // displayName is the Proxmox guest name (e.g. "cle-cybv454-10446"), which is
    // what an instructor sees in the Proxmox UI. vm.name is the internal unique
    // resource name — kept in the tooltip so a card can still be traced back.
    const label = vm.displayName || vm.name;
    const tooltip = [vm.name, vm.vmid ? `VMID ${vm.vmid}` : null]
      .filter(Boolean).join(' · ');

    // Deliberately NOT gated on powerState the way the console button is: a
    // stopped machine's password is still worth reading, and a student who has
    // just been told to start their VM should not have to start it first to
    // find out how to log in.
    //
    // The label is read back out of the rendered DOM rather than interpolated
    // into this handler: vm.displayName is server data, and anything carrying
    // a quote would break out of the attribute string.
    const credBtn = vm.hasCredentials
      ? `<button
             class="btn btn-sm vml-cred-btn"
             onclick="VmWorkspaces.credentials(&quot;${vm.id}&quot;, this.closest(&quot;.vml-card&quot;).querySelector(&quot;.vml-vm-name&quot;).textContent)"
             title="Show the username and password for this machine"
           >
             🔑 Credentials
           </button>`
      : '';

    return `
      <div class="vml-card" data-vm-id="${Utils.escapeHtml(vm.id)}">
        <div class="vml-card-header">
          <span class="vml-vm-icon">🖥</span>
          <div class="vml-card-info">
            <div class="vml-vm-name" title="${Utils.escapeHtml(tooltip)}">${Utils.escapeHtml(label)}</div>
            <div class="vml-vm-meta">
              ${_osTag(vm)}
              ${_moduleTag(vm.moduleKey)}
              ${_powerBadge(vm.powerState || 'unknown')}
              ${hiddenBadge}
              ${ownerBadge}
            </div>
          </div>
        </div>
        <div class="vml-card-actions">${credBtn}${launchBtn}</div>
        ${_analysisControls(vm)}
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
   *
   * `opts` exists so the CyberHub home page can render a SECOND, embedded
   * copy of this list without disturbing the My Workspaces tab. Called with
   * two arguments this behaves exactly as it always has.
   *
   *   toggles:  false skips _renderHeaderToggle(), whose selector and element
   *             ids (#vmlConsoleToggle / #vmlScopeToggle) are hard-bound to
   *             #workspaces-myworkspacesContent — rendering twice would move
   *             those toggles out of the tab that owns them.
   *   embedded: true leaves _lastListEl/_lastConsoleId alone. They are
   *             single-slot and the toggle handlers re-render through them, so
   *             the tab's toggles must keep pointing at the tab's own list.
   *   scope:    'mine' pins the per-user query. _scopeAll defaults to true for
   *             admins and instructors, so without this a professor's HOME
   *             page would list the whole cluster instead of their machines.
   */
  async function render(listEl, consoleContainerId, opts = {}) {
    const { toggles = true, scope = null, embedded = false, quiet = false } = opts;
    if (!embedded) {
      _lastListEl = listEl;
      _lastConsoleId = consoleContainerId;
    }
    if (toggles) _renderHeaderToggle();
    if (!quiet) listEl.innerHTML = '<div class="vml-loading">Loading workspaces…</div>';

    try {
      // Admins/instructors default to scope=all; non-admins ignore the param server-side.
      // Student View has to ask for ?scope=mine EXPLICITLY.
      //
      // Both list endpoints treat a privileged caller as cluster-wide by DEFAULT
      // and only narrow when the client requests it (`showAll = isPrivileged &&
      // req.query.scope !== 'mine'`). Student View changes nothing on the server,
      // so the caller is still privileged there — which means hiding the scope
      // toggle alone would leave the full cluster on screen, every student's VM
      // and email address included, in the middle of a recording.
      // An embedded caller can pin it too — see opts.scope above.
      const scopeQuery = (scope === 'mine' || _studentView() || (_isPrivileged() && !_scopeAll))
        ? '?scope=mine'
        : '';
      const data = await API.request(`/dashboard/vms${scopeQuery}`);
      const rawVms = data.vms || [];
      for (const vm of rawVms) _vms.set(vm.id, vm);
      // Console filter: by default we only show cards the user can actually
      // click. Lane target VMs (ws01, ws02, etc.) have no Guac connection —
      // they're pivot-only from Kali — so listing them is just visual noise.
      // Flip via the "All VMs" toggle to see the full inventory.
      // A failed reset can leave only a durable recovery card while every old
      // VM has been retired. Keep its Reset Lab action reachable without a console.
      const vms = _consoleOnly ? rawVms.filter(v => v.hasConsole || v.analysis?.profile === 'malware') : rawVms;
      const view = { vms, consoleContainerId, opts };
      _views.set(listEl, view);
      for (const vm of vms) {
        if (vm.analysis?.profile === 'malware' && ['isolating', 'resetting'].includes(vm.analysis.state)) {
          _scheduleAnalysis(vm.id, {
            statusUrl: vm.analysis.statusUrl || (vm.analysis.operationId
              ? `/api/dashboard/analysis-operations/${encodeURIComponent(vm.analysis.operationId)}` : null),
          });
        }
      }

      if (vms.length === 0) {
        const adminAll = _isPrivileged() && _scopeAll && scope !== 'mine' && !_studentView();
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

      _paintView(listEl, view);
    } catch (err) {
      const msg = err?.data?.error || err?.message || 'Failed to load workspaces.';
      listEl.innerHTML = `<div class="vml-error">⚠ ${Utils.escapeHtml(msg)}</div>`;
    }
  }


  // ──────────────────────────────────────────────────────────────────────────
  // Workstation credentials
  // ──────────────────────────────────────────────────────────────────────────
  //
  // Guacamole types the workstation password into the guest, so a student never
  // sees it — and then cannot get past a locked Windows session, a sudo prompt,
  // or their own RDP client, and has to ask their instructor to look it up.
  //
  // Fetched on demand rather than carried in the list payload: the server logs
  // every disclosure, so merely opening the page must not count as reading every
  // password. Same reasoning as the instructor roster's "Show console logins".
  //
  // EVERYTHING BELOW USES DOM NODES AND textContent — never innerHTML, never an
  // inline onclick. Utils.escapeHtml is HTML-escaping, and the browser
  // HTML-DECODES an attribute before the JS inside it is parsed, so a generated
  // password containing an apostrophe would break straight out of the string.
  // (The instructor-side renderCredentialCell carries the same warning.)

  let _credOverlay = null;

  function _closeCredentials() {
    if (_credOverlay) { _credOverlay.remove(); _credOverlay = null; }
  }

  function _copy(text, label) {
    navigator.clipboard.writeText(text).then(
      () => Toast.success('Copied', `${label} copied to clipboard`),
      () => Toast.error('Could not copy', 'Select the text and copy it manually.')
    );
  }

  /** One labelled row: value in a <code>, plus its buttons. */
  function _credRow(label, value, { secret = false } = {}) {
    const row = document.createElement('div');
    row.className = 'vml-cred-row';

    const key = document.createElement('span');
    key.className = 'vml-cred-key';
    key.textContent = label;

    const code = document.createElement('code');
    code.className = 'vml-cred-value';
    // The real value only ever reaches the DOM as text. Masking is a display
    // state, so the node keeps the truth and the mask is re-rendered from it.
    let revealed = !secret;
    const paint = () => { code.textContent = revealed ? value : '•'.repeat(Math.min(value.length, 16)); };
    paint();

    const actions = document.createElement('span');
    actions.className = 'vml-cred-actions';

    if (secret) {
      const toggle = document.createElement('button');
      toggle.type = 'button';
      toggle.className = 'btn btn-sm vml-cred-mini';
      toggle.textContent = 'Show';
      toggle.addEventListener('click', () => {
        revealed = !revealed;
        toggle.textContent = revealed ? 'Hide' : 'Show';
        paint();
      });
      actions.appendChild(toggle);
    }

    const copy = document.createElement('button');
    copy.type = 'button';
    copy.className = 'btn btn-sm vml-cred-mini';
    copy.textContent = 'Copy';
    copy.addEventListener('click', () => _copy(value, label));
    actions.appendChild(copy);

    row.append(key, code, actions);
    return row;
  }

  function _renderCredentialModal(vmLabel, cred) {
    _closeCredentials();

    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) _closeCredentials(); });

    const dialog = document.createElement('div');
    dialog.className = 'modal-dialog';
    dialog.style.maxWidth = '520px';

    const header = document.createElement('div');
    header.className = 'modal-header';
    const title = document.createElement('h3');
    title.className = 'modal-title';
    title.textContent = 'Workstation login';
    const close = document.createElement('button');
    close.type = 'button';
    close.className = 'modal-close';
    close.textContent = '✕';
    close.addEventListener('click', _closeCredentials);
    header.append(title, close);

    const body = document.createElement('div');
    body.className = 'modal-body';

    const which = document.createElement('p');
    which.className = 'vml-cred-subject';
    which.textContent = vmLabel;
    body.appendChild(which);

    if (!cred.available) {
      const note = document.createElement('p');
      note.className = 'vml-cred-note';
      note.textContent = cred.reason || 'No login is recorded for this machine.';
      body.appendChild(note);
      if (cred.username) body.appendChild(_credRow('Username', cred.username));
    } else {
      if (cred.username) body.appendChild(_credRow('Username', cred.username));
      body.appendChild(_credRow('Password', cred.password, { secret: true }));

      if (cred.shared) {
        // Never let a shared bake credential pass as a personal one. This is the
        // template's own built-in account: the same password is on every
        // classmate's machine, so it protects nothing.
        const warn = document.createElement('p');
        warn.className = 'vml-cred-warn';
        warn.textContent = 'This login is built into the machine image, so every student in '
          + 'this class has the same one. Treat it as shared, not private.';
        body.appendChild(warn);
      }

      const hint = document.createElement('p');
      hint.className = 'vml-cred-note';
      hint.textContent = 'Open Console signs you in automatically. You need this login when the '
        + 'screen locks, when a task asks for an administrator or sudo password, or if you '
        + 'connect with your own RDP or SSH client.';
      body.appendChild(hint);
    }

    const footer = document.createElement('div');
    footer.className = 'modal-footer';
    const done = document.createElement('button');
    done.type = 'button';
    done.className = 'btn btn-primary';
    done.textContent = 'Done';
    done.addEventListener('click', _closeCredentials);
    footer.appendChild(done);

    dialog.append(header, body, footer);
    overlay.appendChild(dialog);
    document.body.appendChild(overlay);
    _credOverlay = overlay;
  }

  /**
   * Triggered by the "Credentials" button in a VM card.
   * `vmLabel` is passed through only for the modal heading.
   */
  async function credentials(vmId, vmLabel) {
    try {
      const cred = await API.request(`/dashboard/vms/${encodeURIComponent(vmId)}/credentials`);
      _renderCredentialModal(vmLabel || 'This workstation', cred);
    } catch (err) {
      const msg = err?.data?.error || err?.message || 'Could not read the workstation login.';
      Toast.error('Credentials unavailable', msg);
    }
  }

  /**
   * Triggered by "Open Console" button in a VM card.
   */
  function launch(vmId, consoleContainerId) {
    const container = document.getElementById(consoleContainerId);
    if (!container) return;
    container.scrollIntoView({ behavior: 'smooth', block: 'start' });
    VmConsole.open(vmId, container, _vms.get(vmId)?.analysis);
  }

  return { render, launch, credentials, runAnalysis };
})();
