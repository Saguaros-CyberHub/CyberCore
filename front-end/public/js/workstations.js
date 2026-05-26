/**
 * Workstations — user-facing workstation VM management.
 * Handles template browsing/deploy and per-VM power/snapshot controls.
 * Exposed as window.Workstations so hub.html inline handlers can reach it.
 */
const Workstations = (() => {
  'use strict';

  let _myVms      = [];
  let _templates  = [];
  let _snapVmId   = null;
  let _snapshots  = [];
  let _availLoaded  = false;
  let _myLoaded     = false;
  let _refreshTimer = null;
  let _pendingDeployId   = null;
  let _pendingDeployName = null;

  function _headers() {
    return {
      'Authorization': `Bearer ${localStorage.getItem('token')}`,
      'Content-Type': 'application/json',
    };
  }

  async function _api(method, path, body) {
    const opts = { method, headers: _headers() };
    if (body) opts.body = JSON.stringify(body);
    const res  = await fetch(`/api/workstations${path}`, opts);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  function _esc(s) {
    return Utils.escapeHtml ? Utils.escapeHtml(s) : String(s || '')
      .replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  // ── Toast notifications ──────────────────────────────────────────────────────

  function _showToast(msg, type = 'info') {
    const container = document.getElementById('wksToastContainer');
    if (!container) return;
    const toast = document.createElement('div');
    toast.className = `wks-toast wks-toast-${type}`;
    toast.textContent = msg;
    container.appendChild(toast);
    requestAnimationFrame(() => toast.classList.add('wks-toast-visible'));
    setTimeout(() => {
      toast.classList.remove('wks-toast-visible');
      setTimeout(() => toast.remove(), 350);
    }, 5000);
  }

  // ── Available Templates ─────────────────────────────────────────────────────

  async function loadTemplates() {
    if (_availLoaded) return;
    const el = document.getElementById('wksTemplateGrid');
    if (!el) return;
    el.innerHTML = '<div class="wks-loading">Loading templates…</div>';
    try {
      const data = await _api('GET', '/templates');
      _templates  = data.templates || [];
      _availLoaded = true;
      _renderTemplates(el);
    } catch (err) {
      el.innerHTML = `<div class="wks-error">⚠ ${_esc(err.message)}</div>`;
    }
  }

  function _renderTemplates(el) {
    if (_templates.length === 0) {
      el.innerHTML = `
        <div class="wks-empty">
          <div class="wks-empty-icon">🖥</div>
          <p>No workstation templates available yet.</p>
          <p class="wks-empty-sub">Ask your administrator to publish workstation templates.</p>
        </div>`;
      return;
    }
    el.innerHTML = _templates.map(t => `
      <div class="wks-tpl-card">
        <div class="wks-tpl-icon">🖥</div>
        <div class="wks-tpl-name">${_esc(t.name)}</div>
        ${t.description ? `<div class="wks-tpl-desc">${_esc(t.description)}</div>` : ''}
        <div class="wks-tpl-meta">
          ${t.provider_type === 'lxc'  ? '<span class="wks-type-badge wks-type-lxc">LXC Container</span>' : t.provider_type === 'qemu' ? '<span class="wks-type-badge wks-type-vm">QEMU VM</span>' : ''}
          ${t.os_family  ? `<span>${_esc(t.os_family)}</span>`  : ''}
          ${t.os_version ? `<span>${_esc(t.os_version)}</span>` : ''}
        </div>
        <button class="btn btn-primary btn-sm wks-deploy-btn"
                onclick="Workstations.confirmDeploy('${t.template_id}')">
          Deploy Workstation
        </button>
      </div>`).join('');
  }

  function confirmDeploy(templateId) {
    const tpl = _templates.find(t => t.template_id === templateId);
    _pendingDeployId   = templateId;
    _pendingDeployName = tpl?.name || templateId;

    document.getElementById('wksDeployModalName').textContent = _pendingDeployName;

    const devSection = document.getElementById('wksDeployDevSection');
    const user = typeof Auth !== 'undefined' ? Auth.getUser() : null;
    if (devSection) devSection.style.display = (user?.role === 'admin') ? 'block' : 'none';

    const cb = document.getElementById('wksDeploySkipLane');
    if (cb) cb.checked = false;

    const btn = document.getElementById('wksDeploySubmitBtn');
    if (btn) { btn.disabled = false; btn.textContent = 'Deploy'; }

    document.getElementById('wksDeployModal').classList.add('active');
  }

  async function submitDeploy() {
    if (!_pendingDeployId) return;
    const skipLane = document.getElementById('wksDeploySkipLane')?.checked ?? false;
    const btn = document.getElementById('wksDeploySubmitBtn');
    btn.disabled    = true;
    btn.textContent = 'Starting…';
    try {
      const data = await _api('POST', `/${_pendingDeployId}/deploy`, { skipLane });
      // Backend responds 202 immediately — close modal and show deploying card
      document.getElementById('wksDeployModal').classList.remove('active');
      _myLoaded = false;
      await loadMyWorkstations(true);
      _showToast(`"${data.name}" is deploying — this usually takes 1–2 minutes.`, 'info');
    } catch (err) {
      btn.disabled    = false;
      btn.textContent = 'Deploy';
      alert('Deploy failed: ' + err.message);
    }
  }

  // ── My Workstations ─────────────────────────────────────────────────────────

  async function loadMyWorkstations(force = false) {
    const el = document.getElementById('wksMyList');
    if (!el) return;
    if (_myLoaded && !force) return;
    if (!_myLoaded) el.innerHTML = '<div class="wks-loading">Loading your workstations…</div>';
    try {
      const data = await _api('GET', '/mine');
      _myVms    = data.vms || [];
      _myLoaded = true;
      _renderMyWorkstations(el);
      _scheduleRefresh();
    } catch (err) {
      el.innerHTML = `<div class="wks-error">⚠ ${_esc(err.message)}</div>`;
    }
  }

  // Adaptive polling: 5s when any VM is in a transient state, 30s otherwise.
  function _scheduleRefresh() {
    if (_refreshTimer) clearTimeout(_refreshTimer);
    const hasTransient = _myVms.some(v =>
      v.powerState === 'deploying' || v.powerState === 'deleting' || v.powerState === 'pending'
    );
    _refreshTimer = setTimeout(_doRefresh, hasTransient ? 5000 : 30000);
  }

  async function _doRefresh() {
    _refreshTimer = null;
    if (!document.getElementById('wksMyList')) return;

    // Snapshot previous states to detect transitions
    const prevStates = {};
    for (const v of _myVms) prevStates[v.vmId] = v.powerState;

    try {
      const data = await _api('GET', '/mine');
      _myVms = data.vms || [];

      // Notify on notable transitions
      for (const vm of _myVms) {
        const prev = prevStates[vm.vmId];
        if (prev === 'deploying') {
          if (vm.powerState === 'running') {
            _showToast(`"${vm.name}" is now running!`, 'success');
          } else if (vm.powerState === 'failed') {
            _showToast(`"${vm.name}" failed to deploy. Contact your administrator.`, 'error');
          }
        }
      }

      const el = document.getElementById('wksMyList');
      if (el) _renderMyWorkstations(el);
    } catch (_) {}

    _scheduleRefresh();
  }

  function _renderMyWorkstations(el) {
    if (_myVms.length === 0) {
      el.innerHTML = `
        <div class="wks-empty">
          <div class="wks-empty-icon">🖥</div>
          <p>You haven't deployed any workstations yet.</p>
          <p class="wks-empty-sub">Go to <strong>Available</strong> to deploy a template.</p>
        </div>`;
      return;
    }
    el.innerHTML = _myVms.map(_vmCard).join('');
  }

  const _BADGE = {
    running:   ['wks-badge-on',        'Running'],
    stopped:   ['wks-badge-off',       'Stopped'],
    pending:   ['wks-badge-pending',   'Pending…'],
    deploying: ['wks-badge-deploying', 'Deploying…'],
    deleting:  ['wks-badge-deleting',  'Deleting…'],
    failed:    ['wks-badge-failed',    'Failed'],
  };

  function _powerBadge(state) {
    const [cls, label] = _BADGE[state] || ['wks-badge-unk', state || 'Unknown'];
    return `<span class="wks-badge ${cls}">${label}</span>`;
  }

  function _typeBadge(providerType) {
    if (providerType === 'lxc')  return '<span class="wks-type-badge wks-type-lxc">LXC</span>';
    if (providerType === 'qemu') return '<span class="wks-type-badge wks-type-vm">VM</span>';
    return '';
  }

  function _vmCard(vm) {
    const running    = vm.powerState === 'running';
    const stopped    = vm.powerState === 'stopped';
    const pending    = vm.powerState === 'pending';
    const deploying  = vm.powerState === 'deploying';
    const failed     = vm.powerState === 'failed';
    const disableAll  = pending || deploying || failed;
    const disableStart = running || pending || deploying || failed;
    const disableStop  = stopped || pending || deploying || failed;
    return `
      <div class="wks-vm-card" id="wks-vm-${vm.vmId}">
        <div class="wks-vm-header">
          <span class="wks-vm-icon">🖥</span>
          <div class="wks-vm-info">
            <div class="wks-vm-name">${_esc(vm.name)}</div>
            <div class="wks-vm-meta">
              ${_powerBadge(vm.powerState)}
              ${_typeBadge(vm.providerType)}
              ${vm.templateName ? `<span class="wks-vm-tpl">${_esc(vm.templateName)}</span>` : ''}
              ${vm.devDeploy    ? `<span class="wks-dev-tag">DEV</span>` : ''}
            </div>
          </div>
        </div>
        <div class="wks-vm-actions">
          <button class="btn btn-sm" onclick="Workstations.action('${vm.vmId}','start')"
                  ${disableStart ? 'disabled' : ''}>▶ Start</button>
          <button class="btn btn-sm" onclick="Workstations.action('${vm.vmId}','shutdown')"
                  ${disableStop ? 'disabled' : ''}>⏹ Shutdown</button>
          <button class="btn btn-sm" onclick="Workstations.action('${vm.vmId}','reboot')"
                  ${disableStop ? 'disabled' : ''}>↺ Reboot</button>
          <button class="btn btn-sm" onclick="Workstations.openSnapshots('${vm.vmId}')"
                  ${disableAll ? 'disabled' : ''}>📷 Snapshots</button>
          ${vm.hasConsole ? `<button class="btn btn-sm wks-btn-console"
                  onclick="Workstations.openConsole('${vm.vmId}')"
                  ${!running ? 'disabled' : ''}>🖥 Console</button>` : ''}
          <button class="btn btn-sm wks-btn-danger" onclick="Workstations.confirmDelete('${vm.vmId}')"
                  ${disableAll ? 'disabled' : ''}>🗑 Delete</button>
        </div>
      </div>`;
  }

  async function openConsole(vmId) {
    try {
      const res = await fetch(`/api/dashboard/vms/${vmId}/guac-session`, {
        method: 'POST',
        headers: _headers(),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);

      // Pre-authenticate with Guacamole so the user doesn't see the login prompt.
      // localStorage is shared across same-origin tabs, so setting it here means
      // the new Guacamole tab will find the token on load and skip login.
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

      window.open(data.launchUrl, '_blank', 'noopener,noreferrer');
    } catch (err) {
      alert('Console error: ' + err.message);
    }
  }

  async function action(vmId, actionName) {
    const vm = _myVms.find(v => v.vmId === vmId);
    if (!vm) return;

    vm.powerState = 'pending';
    const el = document.getElementById('wksMyList');
    if (el) _renderMyWorkstations(el);

    try {
      await _api('POST', `/${vmId}/action`, { action: actionName });
    } catch (err) {
      alert(`Action "${actionName}" failed: ` + err.message);
      _pollUntilSettled(vmId);
      return;
    }

    _pollUntilSettled(vmId);
  }

  function _pollUntilSettled(vmId, maxMs = 45000) {
    const start = Date.now();
    const interval = setInterval(async () => {
      if (Date.now() - start > maxMs) {
        clearInterval(interval);
        _myLoaded = false;
        loadMyWorkstations(true);
        return;
      }
      try {
        const s = await _api('GET', `/${vmId}/status`);
        const vm = _myVms.find(v => v.vmId === vmId);
        if (vm && s.powerState !== 'pending') {
          vm.powerState = s.powerState;
          clearInterval(interval);
          const el = document.getElementById('wksMyList');
          if (el) _renderMyWorkstations(el);
        }
      } catch (_) {}
    }, 3000);
  }

  async function confirmDelete(vmId) {
    const name = _myVms.find(v => v.vmId === vmId)?.name || vmId;
    if (!confirm(`Delete workstation "${name}"? This permanently destroys the VM and cannot be undone.`)) return;
    const vm = _myVms.find(v => v.vmId === vmId);
    if (vm) {
      vm.powerState = 'deleting';
      const el = document.getElementById('wksMyList');
      if (el) _renderMyWorkstations(el);
    }
    try {
      await _api('DELETE', `/${vmId}`);
      _myVms = _myVms.filter(v => v.vmId !== vmId);
      const el = document.getElementById('wksMyList');
      if (el) _renderMyWorkstations(el);
    } catch (err) {
      alert('Delete failed: ' + err.message);
      _myLoaded = false;
      loadMyWorkstations(true);
    }
  }

  // ── Snapshots modal ─────────────────────────────────────────────────────────

  async function openSnapshots(vmId) {
    const vmName = _myVms.find(v => v.vmId === vmId)?.name || vmId;
    _snapVmId = vmId;
    document.getElementById('wksSnapTitle').textContent = `Snapshots — ${vmName}`;
    document.getElementById('wksSnapNewName').value = '';
    document.getElementById('wksSnapNewDesc').value = '';
    document.getElementById('wksSnapshotModal').classList.add('active');
    await _loadSnapshots();
  }

  async function _loadSnapshots() {
    const el = document.getElementById('wksSnapList');
    el.innerHTML = '<div class="wks-loading">Loading snapshots…</div>';
    try {
      const data  = await _api('GET', `/${_snapVmId}/snapshots`);
      _snapshots  = data.snapshots || [];
      _renderSnapshots(el);
    } catch (err) {
      el.innerHTML = `<div class="wks-error">⚠ ${_esc(err.message)}</div>`;
    }
  }

  function _renderSnapshots(el) {
    if (_snapshots.length === 0) {
      el.innerHTML = '<p class="wks-snap-empty">No snapshots yet.</p>';
      return;
    }
    el.innerHTML = _snapshots.map(s => `
      <div class="wks-snap-row">
        <div class="wks-snap-info">
          <strong>${_esc(s.name)}</strong>
          ${s.description ? `<span class="wks-snap-desc"> — ${_esc(s.description)}</span>` : ''}
        </div>
        <button class="btn btn-sm" onclick="Workstations.rollback('${_esc(s.name)}')">↩ Rollback</button>
      </div>`).join('');
  }

  async function createSnapshot() {
    const name = document.getElementById('wksSnapNewName').value.trim();
    const desc = document.getElementById('wksSnapNewDesc').value.trim();
    if (!name) { alert('Snapshot name is required'); return; }
    const btn = document.getElementById('wksSnapCreateBtn');
    btn.disabled = true;
    try {
      await _api('POST', `/${_snapVmId}/snapshot`, { name, description: desc });
      document.getElementById('wksSnapNewName').value = '';
      document.getElementById('wksSnapNewDesc').value = '';
      await _loadSnapshots();
    } catch (err) {
      alert('Snapshot failed: ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function rollback(snapname) {
    if (!confirm(`Roll back to snapshot "${snapname}"? The VM will be stopped.`)) return;
    try {
      await _api('POST', `/${_snapVmId}/rollback`, { snapname });
      const vm = _myVms.find(v => v.vmId === _snapVmId);
      if (vm) {
        vm.powerState = 'stopped';
        const el = document.getElementById('wksMyList');
        if (el) _renderMyWorkstations(el);
      }
      closeSnapshots();
      alert('Rollback complete. The VM is now stopped — start it when ready.');
    } catch (err) {
      alert('Rollback failed: ' + err.message);
    }
  }

  function closeSnapshots() {
    document.getElementById('wksSnapshotModal').classList.remove('active');
    _snapVmId  = null;
    _snapshots = [];
  }

  return {
    loadTemplates,
    loadMyWorkstations,
    confirmDeploy,
    submitDeploy,
    action,
    confirmDelete,
    openSnapshots,
    createSnapshot,
    rollback,
    closeSnapshots,
    openConsole,
  };
})();
