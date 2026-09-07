/* global api, Modal */
// Admin counterpart of CALDERA's three-step group installer. Jobs live on the
// server; the browser owns only selections and an open dialog's status poll.
(function () {
  'use strict';
  let state = null;
  const templates = new WeakMap();
  const el = id => document.getElementById(id);
  const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[ch]));
  const key = (lane, target) => JSON.stringify([String(lane.lane_id), String(target.vm_id)]);
  const nameKey = target => String(target.name || '').trim().toLowerCase();
  const id = (kind, value) => `wazuh${kind}-${encodeURIComponent(value)}`;
  const jobs = lane => Array.isArray(lane.jobs) ? lane.jobs : [];
  const connected = target => ['active', 'connected'].includes(String(target.agent?.status || '').toLowerCase());
  const busy = (lane, target) => jobs(lane).some(job => String(job.vm_id) === String(target.vm_id) && ['queued', 'running'].includes(job.status));
  const laneAvailable = lane => lane.runnable === true && lane.internet_enabled !== false;
  const available = (lane, target) => laneAvailable(lane) && target.type === 'qemu' && target.runnable === true && !busy(lane, target);
  const openNow = s => state === s && s.overlay.classList.contains('active');
  const lanes = s => Array.isArray(s.payload?.lanes) ? s.payload.lanes : [];
  const rows = s => lanes(s).filter(lane => s.lanes.has(String(lane.lane_id)))
    .flatMap(lane => (lane.targets || []).filter(target => target.type === 'qemu').map(target => ({ lane, target })));
  const platform = (s, lane, target) => s.platforms.has(key(lane, target)) ? s.platforms.get(key(lane, target))
    : s.machinePlatforms.get(nameKey(target)) || (['windows', 'linux'].includes(target.platform) ? target.platform : '');
  const selected = s => rows(s).filter(({ lane, target }) => available(lane, target) && s.targets.has(key(lane, target)))
    .map(({ lane, target }) => ({ lane_id: lane.lane_id, vm_id: target.vm_id, platform: platform(s, lane, target) }));
  const badge = status => ({ queued: 'badge-yellow', running: 'badge-blue', completed: 'badge-green', failed: 'badge-red', active: 'badge-green', connected: 'badge-green' }[status] || 'badge-gray');

  function setHtml(elementId, html) {
    const element = el(elementId);
    // Compare templates, not serialized innerHTML (browsers normalize it).
    if (templates.get(element) === html) return;
    const focused = document.activeElement;
    const focusId = focused?.id && element.contains(focused) ? focused.id : null;
    element.innerHTML = html;
    templates.set(element, html);
    if (focusId && !el(focusId)?.disabled) el(focusId)?.focus({ preventScroll: true });
  }

  function options(value, placeholder) {
    return `<option value=""${value ? '' : ' selected'}>${placeholder}</option>`
      + ['windows', 'linux'].map(os => `<option value="${os}"${value === os ? ' selected' : ''}>${os === 'windows' ? 'Windows' : 'Linux'}</option>`).join('');
  }

  function applyNames(s) {
    rows(s).forEach(({ lane, target }) => {
      const vmKey = key(lane, target);
      if (s.machines.has(nameKey(target)) && !s.excluded.has(vmKey) && available(lane, target) && !connected(target)) s.targets.add(vmKey);
    });
  }

  function close() {
    if (!state) return;
    clearTimeout(state.timer);
    state.timer = null;
    Modal.close(state.overlay);
  }

  function schedule(s) {
    clearTimeout(s.timer);
    if (openNow(s) && !s.submitting) s.timer = setTimeout(() => refresh(s), 5000);
  }

  async function open() {
    if (state) {
      if (openNow(state)) return;
      state.fresh = false;
      Modal.open(state.overlay.id);
      render(state);
      return refresh(state);
    }
    const overlay = document.createElement('div');
    overlay.id = 'adminWazuhModal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `<div class="modal waz-modal" role="dialog" aria-modal="true" aria-labelledby="wazuhTitle">
      <div class="modal-header"><h3 id="wazuhTitle">Deploy Wazuh agents</h3>
        <button type="button" id="wazuhClose" class="modal-close" aria-label="Close Wazuh deployment">&times;</button></div>
      <form id="wazuhForm" class="waz-form">
        <div class="waz-body">
          <p class="waz-lede">Install Wazuh on running lane VMs across the platform. Pick lanes, pick machine names, then review individual targets.</p>
          <div id="wazuhManager" class="waz-manager"></div>
          <details class="waz-explain"><summary>What installation does</summary>
            <p>Downloads and installs the Windows or Linux agent, enrolls it with the configured Wazuh manager, and starts its service. Existing agents pointing to another manager are not migrated automatically; those targets report an error.</p>
            <p>Queue up to 200 targets at once; up to 4 installations run concurrently. Jobs continue when this window closes. Completion confirms an agent check-in; inspect collected events in Wazuh to verify your monitoring configuration.</p></details>
          <section class="waz-panel">
            <div class="waz-panel-head"><span class="waz-step">1</span><h4 class="waz-panel-title">Running lanes</h4><span id="wazuhLaneCount" class="waz-count"></span>
              <div class="waz-panel-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhAllLanes">All available</button><button type="button" class="btn btn-outline btn-sm" id="wazuhClearLanes">Clear</button></div></div>
            <div id="wazuhLanes" class="waz-panel-body"></div></section>
          <div id="wazuhMachines"></div>
          <section class="waz-panel">
            <div class="waz-panel-head"><span class="waz-step">3</span><h4 class="waz-panel-title">Targets</h4><span id="wazuhTargetCount" class="waz-count"></span>
              <div class="waz-panel-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhMissing">Select missing agents</button><button type="button" class="btn btn-outline btn-sm" id="wazuhRetry">Select failed targets</button><button type="button" class="btn btn-outline btn-sm" id="wazuhClearTargets">Clear</button></div></div>
            <div id="wazuhTargets"></div></section>
          <div id="wazuhResults" class="waz-results" aria-live="polite"></div>
        </div>
        <div class="waz-footer"><p id="wazuhError" role="alert"></p>
          <div class="waz-footer-row"><div class="waz-bar-state"><p id="wazuhSummary" class="waz-bar-text" role="status" aria-live="polite"></p><p id="wazuhUpdated" class="waz-hint"></p></div>
            <div class="waz-bar-actions"><button type="button" class="btn btn-outline btn-sm" id="wazuhRefresh">Refresh status</button><button type="submit" class="btn btn-primary" id="wazuhSubmit" disabled>Install selected agents</button></div></div></div>
      </form></div>`;
    document.body.appendChild(overlay);
    const s = { overlay, payload: null, fresh: false, refreshing: false, submitting: false, error: '', timer: null,
      revision: 0, updated: '', lanes: new Set(), machines: new Set(), targets: new Set(), excluded: new Set(),
      platforms: new Map(), machinePlatforms: new Map(), results: [] };
    state = s;
    el('wazuhClose').onclick = close;
    el('wazuhRefresh').onclick = () => refresh(s);
    el('wazuhForm').onsubmit = event => { event.preventDefault(); return submit(s); };
    el('wazuhAllLanes').onclick = () => {
      if (s.submitting) return;
      lanes(s).filter(laneAvailable).forEach(lane => s.lanes.add(String(lane.lane_id)));
      applyNames(s); render(s);
    };
    el('wazuhClearLanes').onclick = () => { if (!s.submitting) { s.lanes.clear(); render(s); } };
    el('wazuhMissing').onclick = () => {
      if (s.submitting) return;
      rows(s).filter(({ lane, target }) => available(lane, target) && !connected(target)).forEach(({ lane, target }) => {
        s.targets.add(key(lane, target)); s.excluded.delete(key(lane, target));
      }); render(s);
    };
    el('wazuhClearTargets').onclick = () => {
      if (s.submitting) return;
      s.targets.clear(); s.machines.clear(); s.excluded.clear(); render(s);
    };
    el('wazuhRetry').onclick = () => {
      if (s.submitting) return;
      s.targets.clear(); s.machines.clear();
      rows(s).filter(({ lane, target }) => failed(s, lane, target) && available(lane, target)).forEach(({ lane, target }) => s.targets.add(key(lane, target)));
      render(s);
    };
    // The shared Modal handles Escape, backdrop clicks, focus trapping/restore.
    // Stop polling whichever close path is used; a reopened dialog refreshes.
    s.observer = new MutationObserver(() => { if (!openNow(s)) { clearTimeout(s.timer); s.timer = null; } });
    s.observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    Modal.open(overlay.id);
    render(s);
    return refresh(s);
  }

  function failed(s, lane, target) {
    return jobs(lane).some(job => String(job.vm_id) === String(target.vm_id) && job.status === 'failed')
      || s.results.some(result => String(result.lane_id) === String(lane.lane_id) && String(result.vm_id) === String(target.vm_id) && result.error);
  }

  function render(s) {
    if (!openNow(s)) return;
    const data = s.payload || {};
    const inventory = lanes(s);
    const vmRows = rows(s);
    const locked = s.submitting;
    let manager = data.manager ? `Manager: <strong>${esc(data.manager)}</strong>` : 'Wazuh manager is not configured.';
    try {
      const url = new URL(data.console_url);
      if (['http:', 'https:'].includes(url.protocol) && !url.username && !url.password) manager += ` <a href="${esc(url.href)}" target="_blank" rel="noopener noreferrer">Open Wazuh console &nearr;</a>`;
    } catch (_) { /* Invalid or missing console URL: show the manager only. */ }
    setHtml('wazuhManager', s.payload ? manager : 'Loading Wazuh configuration and lane inventory…');
    setHtml('wazuhLanes', inventory.length ? `<div class="waz-lanegrid">${inventory.map(lane => {
      const eligible = laneAvailable(lane);
      const picked = s.lanes.has(String(lane.lane_id));
      const reason = lane.runnable !== true ? 'lane not running' : lane.internet_enabled === false ? 'internet off' : '';
      const count = (lane.targets || []).filter(target => target.type === 'qemu' && target.runnable === true).length;
      return `<label class="waz-lane${picked ? ' is-picked' : ''}${eligible ? '' : ' is-off'}"><input type="checkbox" id="${esc(id('Lane', lane.lane_id))}"${picked ? ' checked' : ''}${locked || !eligible ? ' disabled' : ''}><span class="waz-lane-name">${esc(lane.name || lane.lane_id)}</span><span class="waz-lane-meta">${count} running</span>${reason ? `<span class="badge badge-gray">${reason}</span>` : ''}</label>`;
    }).join('')}</div>` : `<div class="waz-empty"><strong>${s.payload ? 'No deployed lanes' : s.error ? 'Lane inventory unavailable' : 'Loading lanes…'}</strong><p>${s.payload ? 'Deploy or resume an environment, then refresh status.' : s.error ? 'Refresh status to try again.' : 'Checking running VMs and saved installation jobs.'}</p></div>`);
    inventory.forEach(lane => {
      el(id('Lane', lane.lane_id)).onchange = event => {
        if (s.submitting || !laneAvailable(lane)) return;
        if (event.target.checked) s.lanes.add(String(lane.lane_id)); else s.lanes.delete(String(lane.lane_id));
        applyNames(s); render(s);
      };
    });
    el('wazuhLaneCount').textContent = `${inventory.filter(lane => s.lanes.has(String(lane.lane_id))).length} selected`;
    el('wazuhAllLanes').disabled = locked || !inventory.some(laneAvailable);
    el('wazuhClearLanes').disabled = locked || !s.lanes.size;
    renderMachines(s, vmRows);
    renderTargets(s, vmRows);
    renderResults(s, inventory);
    const targets = selected(s);
    const unknown = targets.filter(target => !['windows', 'linux'].includes(target.platform)).length;
    el('wazuhSummary').textContent = `${targets.length} VM${targets.length === 1 ? '' : 's'} selected in ${new Set(targets.map(target => target.lane_id)).size} lane(s).`
      + (unknown ? ` Choose Windows or Linux for ${unknown} target(s).` : '')
      + (targets.length > 200 ? ' Select at most 200 targets per batch.' : '');
    el('wazuhSummary').className = `waz-bar-text${unknown || targets.length > 200 ? ' is-blocked' : targets.length ? ' is-ready' : ''}`;
    el('wazuhError').textContent = [s.error, data.configuration_error, data.agents_error, data.power_error].filter(Boolean).join('\n');
    el('wazuhUpdated').textContent = s.refreshing ? 'Refreshing status…' : s.updated ? `Updated ${s.updated}. Refreshes every 5 seconds while open.` : '';
    el('wazuhRefresh').disabled = locked || s.refreshing;
    el('wazuhSubmit').disabled = locked || !s.fresh || !data.manager || !!data.configuration_error || !!data.power_error || !!data.agents_error || !targets.length || targets.length > 200 || !!unknown;
    el('wazuhSubmit').textContent = locked ? 'Queuing installations…' : targets.length ? `Install ${targets.length} agent${targets.length === 1 ? '' : 's'}` : 'Install selected agents';
  }

  function renderMachines(s, vmRows) {
    const names = [...new Set(vmRows.map(({ target }) => nameKey(target)).filter(Boolean))].sort();
    setHtml('wazuhMachines', names.length ? `<section class="waz-panel"><div class="waz-panel-head"><span class="waz-step">2</span><h4 class="waz-panel-title">Machine names</h4></div><div class="waz-panel-body"><p class="waz-hint">Select a name to pick matching VMs across selected lanes, ignoring case. Connected agents are skipped. An OS chosen here applies to every matching VM; individual targets can override it.</p><div class="waz-mgrid"><span class="waz-mgrid-h">Machine</span><span class="waz-mgrid-h">Needs agent</span><span class="waz-mgrid-h">Operating system</span>${names.map(name => {
      const matching = vmRows.filter(({ lane, target }) => nameKey(target) === name && available(lane, target) && !connected(target));
      const display = vmRows.find(({ target }) => nameKey(target) === name).target.name;
      const picked = matching.length && matching.every(({ lane, target }) => s.targets.has(key(lane, target)));
      return `<label class="waz-mpick"><input type="checkbox" id="${esc(id('Machine', name))}"${picked ? ' checked' : ''}${s.submitting || !matching.length ? ' disabled' : ''}><span class="waz-mname">${esc(display)}</span></label><span class="badge badge-gray">${matching.length}</span><label class="waz-molabel"><span class="waz-sr-only">Operating system for ${esc(display)}</span><select class="waz-select" id="${esc(id('MachineOs', name))}"${s.submitting ? ' disabled' : ''}>${options(s.machinePlatforms.get(name) || '', 'Use each VM’s own OS')}</select></label>`;
    }).join('')}</div></div></section>` : '');
    names.forEach(name => {
      el(id('Machine', name)).onchange = event => {
        if (s.submitting) return;
        if (event.target.checked) s.machines.add(name); else s.machines.delete(name);
        vmRows.filter(({ target }) => nameKey(target) === name).forEach(({ lane, target }) => {
          const vmKey = key(lane, target); s.excluded.delete(vmKey);
          if (event.target.checked && available(lane, target) && !connected(target)) s.targets.add(vmKey); else s.targets.delete(vmKey);
        }); render(s);
      };
      const os = el(id('MachineOs', name));
      os.value = s.machinePlatforms.get(name) || '';
      os.onchange = () => {
        if (s.submitting) return;
        s.machinePlatforms.set(name, os.value);
        vmRows.filter(({ target }) => nameKey(target) === name).forEach(({ lane, target }) => s.platforms.delete(key(lane, target)));
        render(s);
      };
    });
  }

  function renderTargets(s, vmRows) {
    const scroll = el('wazuhTargetScroll');
    const scrollTop = scroll?.scrollTop || 0;
    const scrollLeft = scroll?.scrollLeft || 0;
    const selectable = vmRows.filter(({ lane, target }) => available(lane, target));
    el('wazuhTargetCount').textContent = `${vmRows.length} rows · ${selectable.length} selectable`;
    el('wazuhMissing').disabled = s.submitting || !selectable.some(({ target }) => !connected(target));
    el('wazuhRetry').disabled = s.submitting || !selectable.some(({ lane, target }) => failed(s, lane, target));
    el('wazuhClearTargets').disabled = s.submitting || !s.targets.size;
    setHtml('wazuhTargets', vmRows.length ? `<div class="waz-tablewrap" id="wazuhTargetScroll"><table class="data-table waz-table"><thead><tr><th class="waz-c-pick"><span class="waz-sr-only">Install</span></th><th>Lane</th><th>Machine</th><th class="waz-c-vm">VM</th><th class="waz-c-os">Operating system</th><th class="waz-c-status">Status</th></tr></thead><tbody>${vmRows.map(({ lane, target }) => {
      const vmKey = key(lane, target);
      const eligible = available(lane, target);
      const picked = eligible && s.targets.has(vmKey);
      return `<tr class="waz-row${picked ? ' is-picked' : ''}${eligible ? '' : ' is-off'}"><td class="waz-c-pick"><label class="waz-pick"><input type="checkbox" id="${esc(id('Target', vmKey))}"${picked ? ' checked' : ''}${s.submitting || !eligible ? ' disabled' : ''}><span class="waz-sr-only">Install on ${esc(lane.name || lane.lane_id)} ${esc(target.name || target.vm_id)}</span></label></td><td>${esc(lane.name || lane.lane_id)}</td><td class="waz-mname">${esc(target.name || 'VM')}</td><td class="waz-c-vm waz-mono">${esc(target.vm_id)}</td><td class="waz-c-os"><label class="waz-molabel"><span class="waz-sr-only">Operating system for ${esc(target.name || target.vm_id)} in ${esc(lane.name || lane.lane_id)}</span><select class="waz-select" id="${esc(id('TargetOs', vmKey))}"${s.submitting || !eligible ? ' disabled' : ''}>${options(platform(s, lane, target), 'Choose OS…')}</select></label></td><td class="waz-c-status" id="${esc(id('Status', vmKey))}"></td></tr>`;
    }).join('')}</tbody></table></div>` : `<div class="waz-empty"><strong>${s.lanes.size ? 'No QEMU VMs in selected lanes' : 'No lanes selected'}</strong><p>${s.lanes.size ? 'Refresh status after the VMs finish deploying.' : 'Select lanes above to see their machines.'}</p></div>`);
    if (el('wazuhTargetScroll')) {
      el('wazuhTargetScroll').scrollTop = scrollTop;
      el('wazuhTargetScroll').scrollLeft = scrollLeft;
    }
    vmRows.forEach(({ lane, target }) => {
      const vmKey = key(lane, target);
      el(id('Target', vmKey)).onchange = event => {
        if (s.submitting || !available(lane, target)) return;
        if (event.target.checked) { s.targets.add(vmKey); s.excluded.delete(vmKey); }
        else { s.targets.delete(vmKey); s.excluded.add(vmKey); }
        render(s);
      };
      const os = el(id('TargetOs', vmKey));
      os.value = platform(s, lane, target);
      os.onchange = () => { if (!s.submitting && available(lane, target)) { s.platforms.set(vmKey, os.value); render(s); } };
      const job = jobs(lane).find(entry => String(entry.vm_id) === String(target.vm_id) && ['queued', 'running'].includes(entry.status));
      const status = job ? (job.status === 'queued' ? 'install queued' : 'installing')
        : !laneAvailable(lane) ? (lane.internet_enabled === false ? 'internet off' : 'lane unavailable')
          : target.runnable !== true ? target.power_state || 'power unknown' : connected(target) ? 'connected' : target.agent?.status || 'agent missing';
      const seen = target.agent?.lastKeepAlive || target.agent?.last_seen;
      // Status cells are separate islands: a changing check-in timestamp cannot
      // replace a focused OS selector, checkbox, or the target table scroll.
      setHtml(id('Status', vmKey), `<span class="badge ${badge(job?.status || status)}">${esc(status)}</span>${seen ? `<small class="waz-last-seen">Last seen: ${esc(seen)}</small>` : ''}`);
    });
  }

  function renderResults(s, inventory) {
    const all = inventory.flatMap(lane => jobs(lane).map(job => ({ lane, job })));
    const failures = s.results.filter(result => result.error);
    const metrics = ['queued', 'running', 'completed', 'failed'].map(status => {
      const count = all.filter(({ job }) => job.status === status).length;
      return `<span class="badge ${count ? badge(status) : 'badge-gray'}">${count} ${status}</span>`;
    }).join('');
    setHtml('wazuhResults', all.length || failures.length ? `<h4 class="waz-results-title">Installation progress</h4><div class="waz-metrics">${metrics}</div>`
      + failures.map(result => `<div class="waz-job is-bad"><strong class="waz-job-name">${esc(inventory.find(lane => String(lane.lane_id) === String(result.lane_id))?.name || result.lane_id)} · VM ${esc(result.vm_id)}</strong><p class="waz-job-msg">${esc(result.error)}</p></div>`).join('')
      + all.slice().sort((a, b) => Number(b.job.status === 'failed') - Number(a.job.status === 'failed')).map(({ lane, job }) => `<div class="waz-job is-${job.status === 'failed' ? 'bad' : job.status === 'completed' ? 'good' : 'live'}"><div class="waz-job-head"><strong class="waz-job-name">${esc(lane.name || lane.lane_id)} · VM ${esc(job.vm_id)}</strong><span class="badge ${badge(job.status)}">${esc(job.status || 'unknown')}</span></div><p class="waz-job-msg">${esc(job.error || job.message || '')}</p>${job.status === 'completed' ? `<p class="waz-job-ok">Agent check-in confirmed${job.agent_name ? `: ${esc(job.agent_name)}` : ''}.</p>` : ''}${job.last_seen ? `<p class="waz-job-msg">Last seen: ${esc(job.last_seen)}</p>` : ''}</div>`).join('') : '');
  }

  async function refresh(s) {
    if (!openNow(s) || s.refreshing || s.submitting) return;
    clearTimeout(s.timer);
    s.refreshing = true;
    const revision = s.revision;
    render(s);
    try {
      const data = await api('GET', '/wazuh-agents');
      if (revision !== s.revision) return;
      if (!data || !Array.isArray(data.lanes)) throw new Error('Invalid Wazuh inventory response. Refresh status to try again.');
      s.payload = data;
      s.fresh = true;
      s.error = '';
      s.updated = new Date().toLocaleTimeString();
      // Polls only remove unavailable targets. New machines are never silently
      // added to an operator's reviewed selection by a background refresh.
      const live = new Set(lanes(s).flatMap(lane => (lane.targets || []).filter(target => available(lane, target)).map(target => key(lane, target))));
      [...s.targets].forEach(vmKey => { if (!live.has(vmKey)) s.targets.delete(vmKey); });
    } catch (error) {
      if (revision !== s.revision) return;
      s.fresh = false;
      s.error = `Could not refresh Wazuh status: ${error.message}`;
    } finally {
      s.refreshing = false;
      if (openNow(s)) {
        render(s);
        schedule(s);
      }
    }
  }

  async function submit(s) {
    if (!openNow(s) || el('wazuhSubmit').disabled) return;
    const targets = selected(s);
    if (!targets.length || targets.length > 200 || targets.some(target => !['windows', 'linux'].includes(target.platform))) return;
    clearTimeout(s.timer);
    s.revision += 1; // Ignore any pre-submit inventory request arriving late.
    s.submitting = true;
    s.error = '';
    s.results = [];
    render(s);
    try {
      const data = await api('POST', '/wazuh-agents/batch', { targets });
      if (!data || !Array.isArray(data.results)) throw new Error('The queue response was incomplete. Refresh status to check which jobs were saved.');
      s.results = data.results;
      data.results.forEach(result => {
        const lane = lanes(s).find(entry => String(entry.lane_id) === String(result.lane_id));
        if (!lane || !result.job) return;
        lane.jobs = jobs(lane).filter(job => String(job.vm_id) !== String(result.vm_id)).concat(result.job);
        s.targets.delete(key(lane, { vm_id: result.vm_id }));
        s.excluded.add(key(lane, { vm_id: result.vm_id }));
      });
    } catch (error) {
      s.fresh = false;
      s.error = `Could not confirm the deployment request: ${error.message} Refresh status before retrying.`;
    } finally {
      s.submitting = false;
      if (openNow(s)) { render(s); schedule(s); }
    }
  }

  window.AdminWazuh = { open, close };
})();
