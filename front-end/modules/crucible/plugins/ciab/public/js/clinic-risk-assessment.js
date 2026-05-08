/**
 * Clinic Risk Assessment — frontend controller.
 * Loads the dashboard bundle, renders ECharts visualizations, wires the risk
 * register drawer and CSF maturity sliders, exports the PDF deliverable with
 * embedded chart PNGs.
 */
(function () {
  'use strict';

  // === State ===
  const state = {
    profileId: null,
    bundle: null,         // /api/clinic-risk-assessment/:profileId response
    charts: {},           // ECharts instances keyed by container id
    activeTab: 'overview',
  };

  const CSF_FN_ORDER = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];
  const CSF_FN_NAMES = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' };
  const CSF_FN_COLORS = { GV: '#7c3aed', ID: '#0ea5e9', PR: '#16a34a', DE: '#d97706', RS: '#dc2626', RC: '#0891b2' };

  // === API helpers ===
  function apiUrl(suffix) { return '/api/clinic-risk-assessment' + suffix; }

  async function api(method, suffix, body) {
    const opts = {
      method,
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
    };
    if (body !== undefined) opts.body = JSON.stringify(body);
    const res = await fetch(apiUrl(suffix), opts);
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (_) {}
      throw new Error(msg);
    }
    if (res.status === 204) return null;
    return res.json();
  }

  // === Toast ===
  let toastTimer = null;
  function toast(msg, ms = 2200) {
    const el = document.getElementById('toast');
    if (!el) return;
    el.textContent = msg;
    el.classList.add('show');
    if (toastTimer) clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), ms);
  }

  // === Bootstrap ===
  function extractProfileId() {
    // URL: /ciab/clinic-risk-assessment/<uuid>
    const m = location.pathname.match(/\/clinic-risk-assessment\/([^/?#]+)/);
    if (m) return decodeURIComponent(m[1]);
    const qs = new URLSearchParams(location.search);
    return qs.get('profileId');
  }

  async function bootstrap() {
    const authed = await Auth.requireAuth();
    if (!authed) return;
    const user = Auth.getUser();
    document.getElementById('headerUser').textContent = user?.email || '';
    Layout.init();

    state.profileId = extractProfileId();
    if (!state.profileId) {
      await renderPicker();
      return;
    }

    wireTabs();
    wireDrawer();
    wireReportButtons();
    document.getElementById('btnRefresh').addEventListener('click', () => loadAndRender());

    await loadAndRender();
  }

  // === Picker (no profileId in URL) ===
  async function renderPicker() {
    document.getElementById('craCompanyName').textContent = 'Open Risk Assessment';
    document.getElementById('craSubtitle').textContent = 'Pick a profile or real-client engagement to begin.';
    document.getElementById('btnRefresh').style.display = 'none';

    // Hide tabs and tab content; we're rendering a different layout in their place.
    document.querySelector('.cra-tabs').style.display = 'none';
    document.querySelectorAll('.cra-pane').forEach(p => p.classList.remove('active'));

    const shell = document.getElementById('craShell');
    const pickerEl = document.createElement('div');
    pickerEl.id = 'craPicker';
    pickerEl.innerHTML = `
      <div class="cra-grid cols-2" style="margin-top:8px">
        <div class="cra-card" id="pickerAiCard">
          <h3>AI Training Profiles</h3>
          <p class="sub" style="color:var(--text-muted); font-size:0.85rem; margin: -4px 0 12px 0;">Generated profiles for practice. Watermarked as training samples in the deliverable.</p>
          <div id="pickerAiList"><div class="empty-state">Loading…</div></div>
        </div>
        <div class="cra-card" id="pickerRealCard">
          <h3>Real-Client Engagements</h3>
          <p class="sub" style="color:var(--text-muted); font-size:0.85rem; margin: -4px 0 12px 0;">Uploaded intakes. Click to open the assessment — a profile will be created automatically if one isn't linked yet.</p>
          <div id="pickerRealList"><div class="empty-state">Loading…</div></div>
        </div>
      </div>
    `;
    shell.appendChild(pickerEl);

    let data;
    try {
      data = await api('GET', '/pickable');
    } catch (err) {
      pickerEl.querySelectorAll('.empty-state').forEach(el => el.textContent = 'Load failed: ' + err.message);
      return;
    }

    renderPickerList('pickerAiList', data.ai_profiles, (p) => `
      <div class="picker-row" data-profile="${p.id}">
        <div class="row-main">
          <div class="row-title">${escapeHtml(p.company_name || 'Untitled')}</div>
          <div class="row-meta">${escapeHtml(p.industry || 'Unspecified')} · ${escapeHtml(p.difficulty || '—')} · ${new Date(p.created_at).toLocaleDateString()}</div>
        </div>
        <button class="btn primary">Open</button>
      </div>
    `, (row) => {
      location.href = `/ciab/clinic-risk-assessment/${row.dataset.profile}`;
    }, 'No AI profiles yet. Generate one from /ciab/generator.');

    renderPickerList('pickerRealList', data.real_client_intakes, (i) => `
      <div class="picker-row" data-intake="${i.id}" data-profile="${i.profile_id || ''}">
        <div class="row-main">
          <div class="row-title">${escapeHtml(i.cover_name || 'Untitled')}</div>
          <div class="row-meta">${i.profile_id ? 'Linked' : 'No profile yet'} · ${i.completion_percentage || 0}% complete · ${new Date(i.created_at).toLocaleDateString()}</div>
        </div>
        <button class="btn primary">${i.profile_id ? 'Open' : 'Open & create profile'}</button>
      </div>
    `, async (row) => {
      const existing = row.dataset.profile;
      if (existing) { location.href = `/ciab/clinic-risk-assessment/${existing}`; return; }
      // Lazy-create profile, then redirect.
      const intakeId = row.dataset.intake;
      const btn = row.querySelector('button');
      btn.disabled = true; btn.textContent = 'Creating profile…';
      try {
        const r = await api('POST', `/from-intake/${encodeURIComponent(intakeId)}`);
        location.href = `/ciab/clinic-risk-assessment/${r.profile_id}`;
      } catch (err) {
        toast('Failed: ' + err.message, 4000);
        btn.disabled = false; btn.textContent = 'Open & create profile';
      }
    }, 'No real-client intakes yet. Upload one at /ciab/real-client-intake.');

    // Inject styles for picker rows once.
    if (!document.getElementById('pickerStyles')) {
      const style = document.createElement('style');
      style.id = 'pickerStyles';
      style.textContent = `
        .picker-row { display: flex; justify-content: space-between; align-items: center; gap: 12px; padding: 10px 4px; border-bottom: 1px solid var(--border-color, #e2e8f0); }
        .picker-row:last-child { border-bottom: 0; }
        .picker-row .row-title { font-weight: 600; color: var(--text-primary); }
        .picker-row .row-meta { font-size: 0.8rem; color: var(--text-muted, #64748b); margin-top: 2px; }
        .picker-row .btn { white-space: nowrap; }
      `;
      document.head.appendChild(style);
    }
  }

  function renderPickerList(hostId, items, rowFn, onClick, emptyMsg) {
    const host = document.getElementById(hostId);
    if (!items || items.length === 0) {
      host.innerHTML = `<div class="empty-state" style="padding: 24px 8px; font-size: 0.85rem;">${escapeHtml(emptyMsg)}</div>`;
      return;
    }
    host.innerHTML = items.map(rowFn).join('');
    host.querySelectorAll('.picker-row').forEach(row => {
      row.querySelector('button').addEventListener('click', (e) => {
        e.stopPropagation();
        onClick(row);
      });
    });
  }

  async function loadAndRender() {
    try {
      state.bundle = await api('GET', '/' + encodeURIComponent(state.profileId));
    } catch (err) {
      document.getElementById('craCompanyName').textContent = 'Error';
      document.getElementById('craSubtitle').textContent = err.message;
      return;
    }
    renderHeader();
    renderOverviewStats();
    renderHeatmap();
    renderRadar();
    renderCisBars();
    renderCsfBars();
    renderFindingsTable();
    renderCsfSliders();
    renderReportFields();
  }

  // === Header ===
  function renderHeader() {
    const b = state.bundle;
    const cover = b.profile.company_name || b.intake?.cover_name || 'Untitled Engagement';
    document.getElementById('craCompanyName').textContent = cover;
    const intakeStatus = b.intake ? `Intake: ${b.intake.completion_percentage}% (${b.intake.status})` : 'No intake yet';
    document.getElementById('craSubtitle').textContent =
      `${b.profile.industry || 'Unspecified industry'} · ${intakeStatus}`;

    const badge = document.getElementById('craSourceBadge');
    if (b.intake) {
      const isReal = b.intake.source === 'real_client';
      badge.style.display = '';
      badge.textContent = isReal ? 'REAL CLIENT' : 'TRAINING';
      badge.className = 'status-pill ' + (isReal ? 'status-mitigated' : 'status-accepted');
    }
  }

  // === Overview stats ===
  function renderOverviewStats() {
    const b = state.bundle;
    const findings = b.findings || [];
    const avgRisk = findings.length === 0 ? 0
      : (findings.reduce((s, f) => s + (f.inherent_risk || 0), 0) / findings.length).toFixed(1);
    const csfAvg = (() => {
      const vals = CSF_FN_ORDER.map(k => Number(b.csf_scores[k]) || 0).filter(v => v > 0);
      return vals.length === 0 ? 0 : (vals.reduce((a, c) => a + c, 0) / vals.length).toFixed(1);
    })();
    const cards = [
      { label: 'Findings',          value: findings.length, hint: 'in register' },
      { label: 'Avg Inherent Risk', value: avgRisk,         hint: 'L × I, scale 1–25' },
      { label: 'IG1 Coverage',      value: b.cis_coverage.score + '%', hint: `${b.cis_coverage.yes} yes · ${b.cis_coverage.partial} partial` },
      { label: 'CSF Maturity',      value: csfAvg,          hint: 'avg of 6 functions, 0–5' },
    ];
    const host = document.getElementById('overviewStats');
    host.innerHTML = cards.map(c => `
      <div class="cra-stat-card">
        <div class="label">${c.label}</div>
        <div class="value">${c.value}</div>
        <div class="hint">${c.hint}</div>
      </div>
    `).join('');
  }

  // === ECharts helpers ===
  function getOrInitChart(id) {
    let c = state.charts[id];
    if (c && !c.isDisposed()) return c;
    const el = document.getElementById(id);
    if (!el) return null;
    c = echarts.init(el, null, { renderer: 'canvas' });
    state.charts[id] = c;
    return c;
  }

  function disposeAllCharts() {
    Object.values(state.charts).forEach(c => { try { c.dispose(); } catch (_) {} });
    state.charts = {};
  }

  // === Heat map ===
  function renderHeatmap() {
    const c = getOrInitChart('chartHeatmap');
    if (!c) return;
    const findings = state.bundle.findings || [];
    // 5 likelihood × 5 impact; counts.
    const grid = {};
    for (const f of findings) {
      if (!f.likelihood || !f.impact) continue;
      const k = `${f.likelihood},${f.impact}`;
      grid[k] = (grid[k] || 0) + 1;
    }
    const data = [];
    for (let l = 1; l <= 5; l++) {
      for (let i = 1; i <= 5; i++) {
        data.push([i - 1, l - 1, grid[`${l},${i}`] || 0]);
      }
    }
    c.setOption({
      grid: { left: 60, right: 30, top: 30, bottom: 50 },
      xAxis: { type: 'category', data: ['1', '2', '3', '4', '5'], name: 'Impact', nameLocation: 'middle', nameGap: 28 },
      yAxis: { type: 'category', data: ['1', '2', '3', '4', '5'], name: 'Likelihood', nameLocation: 'middle', nameGap: 38 },
      visualMap: {
        min: 0, max: Math.max(1, ...data.map(d => d[2])),
        calculable: false, orient: 'horizontal', left: 'center', bottom: 0,
        inRange: { color: ['#e0f2fe', '#bae6fd', '#fcd34d', '#fb923c', '#dc2626', '#7f1d1d'] },
        textStyle: { fontSize: 10 },
      },
      tooltip: {
        formatter: (p) => `Likelihood ${p.value[1] + 1} × Impact ${p.value[0] + 1}: <b>${p.value[2]}</b> finding(s)`,
      },
      series: [{
        type: 'heatmap',
        data,
        label: { show: true, fontSize: 11, fontWeight: 600, formatter: (p) => p.value[2] || '' },
        itemStyle: { borderColor: '#fff', borderWidth: 1 },
      }],
    }, true);
  }

  // === Radar ===
  function renderRadar() {
    const c = getOrInitChart('chartRadar');
    if (!c) return;
    const scores = state.bundle.csf_scores || {};
    const indicator = CSF_FN_ORDER.map(k => ({ name: CSF_FN_NAMES[k], max: 5 }));
    const value = CSF_FN_ORDER.map(k => Number(scores[k]) || 0);
    c.setOption({
      tooltip: {},
      radar: { indicator, radius: '70%', axisName: { color: '#475569', fontSize: 11 } },
      series: [{
        type: 'radar',
        data: [{
          value, name: 'Maturity',
          areaStyle: { color: 'rgba(30, 64, 175, 0.25)' },
          lineStyle: { color: '#1e40af', width: 2 },
          itemStyle: { color: '#1e40af' },
          label: { show: true, fontSize: 10, formatter: (p) => p.value.toFixed(1) },
        }],
      }],
    }, true);
  }

  // === CIS coverage bars ===
  function renderCisBars() {
    const c = getOrInitChart('chartCis');
    if (!c) return;
    const cv = state.bundle.cis_coverage;
    c.setOption({
      grid: { left: 80, right: 30, top: 20, bottom: 30 },
      tooltip: {},
      xAxis: { type: 'value', max: cv.total, axisLabel: { fontSize: 10 } },
      yAxis: { type: 'category', data: ['Yes', 'Partial', 'No', 'Unanswered'], axisLabel: { fontSize: 11 } },
      series: [{
        type: 'bar',
        data: [
          { value: cv.yes,     itemStyle: { color: '#16a34a' } },
          { value: cv.partial, itemStyle: { color: '#d97706' } },
          { value: cv.no,      itemStyle: { color: '#dc2626' } },
          { value: cv.unknown, itemStyle: { color: '#94a3b8' } },
        ],
        label: { show: true, position: 'right', fontSize: 11, formatter: (p) => `${p.value} / ${cv.total}` },
        barWidth: 22,
      }],
    }, true);
  }

  function renderCsfBars() {
    const c = getOrInitChart('chartCsf');
    if (!c) return;
    const scores = state.bundle.csf_scores || {};
    const data = CSF_FN_ORDER.map(k => ({ value: Number(scores[k]) || 0, itemStyle: { color: CSF_FN_COLORS[k] } }));
    c.setOption({
      grid: { left: 80, right: 30, top: 20, bottom: 30 },
      tooltip: {},
      xAxis: { type: 'value', max: 5 },
      yAxis: { type: 'category', data: CSF_FN_ORDER.map(k => CSF_FN_NAMES[k]), axisLabel: { fontSize: 11 } },
      series: [{ type: 'bar', data, barWidth: 18, label: { show: true, position: 'right', fontSize: 11, formatter: (p) => p.value.toFixed(1) } }],
    }, true);
  }

  // Re-fit charts when their tab becomes visible (ECharts can't measure hidden divs).
  function resizeAllCharts() {
    Object.values(state.charts).forEach(c => { try { c.resize(); } catch (_) {} });
  }

  // === Findings table ===
  function riskBucket(r) {
    if (!r) return '';
    if (r >= 16) return 'critical';
    if (r >= 10) return 'high';
    if (r >= 5)  return 'medium';
    return 'low';
  }

  function renderFindingsTable() {
    const findings = state.bundle.findings || [];
    document.getElementById('registerCount').textContent =
      findings.length === 0 ? 'No findings yet.' : `${findings.length} finding${findings.length === 1 ? '' : 's'}`;

    const tbody = document.getElementById('findingsTbody');
    if (findings.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7"><div class="empty-state"><div class="big-icon">📋</div>No findings yet — click "+ Add Finding" to create one.</div></td></tr>`;
      return;
    }
    tbody.innerHTML = findings.map(f => `
      <tr data-id="${f.id}">
        <td><strong>${escapeHtml(f.finding_code || '')}</strong></td>
        <td>${escapeHtml(f.title || '')}</td>
        <td>${escapeHtml(f.category || '—')}</td>
        <td>${f.likelihood ?? '—'}</td>
        <td>${f.impact ?? '—'}</td>
        <td>${f.inherent_risk != null ? `<span class="risk-badge risk-${riskBucket(f.inherent_risk)}">${f.inherent_risk}</span>` : '—'}</td>
        <td><span class="status-pill status-${f.status || 'open'}">${escapeHtml(f.status || 'open')}</span></td>
      </tr>
    `).join('');
    tbody.querySelectorAll('tr').forEach(row => {
      row.addEventListener('click', () => openDrawer(row.dataset.id));
    });
  }

  function escapeHtml(s) { return String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])); }

  // === Drawer ===
  function wireDrawer() {
    document.getElementById('btnAddFinding').addEventListener('click', () => openDrawer(null));
    document.getElementById('btnCloseDrawer').addEventListener('click', closeDrawer);
    document.getElementById('btnCancelFinding').addEventListener('click', closeDrawer);
    document.getElementById('drawerBackdrop').addEventListener('click', closeDrawer);
    document.getElementById('btnSaveFinding').addEventListener('click', saveFinding);
    document.getElementById('btnDeleteFinding').addEventListener('click', deleteFinding);
    ['fLikelihood', 'fImpact'].forEach(id => {
      document.getElementById(id).addEventListener('input', (e) => {
        document.getElementById(id + 'Val').textContent = e.target.value;
      });
    });
  }

  function openDrawer(findingId) {
    const f = findingId ? (state.bundle.findings || []).find(x => x.id === findingId) : null;
    document.getElementById('drawerTitle').textContent = f ? `Edit ${f.finding_code || 'Finding'}` : 'Add Finding';
    document.getElementById('findingId').value = f?.id || '';
    document.getElementById('fTitle').value = f?.title || '';
    document.getElementById('fDescription').value = f?.description || '';
    document.getElementById('fCategory').value = f?.category || '';
    document.getElementById('fStatus').value = f?.status || 'open';
    document.getElementById('fLikelihood').value = f?.likelihood ?? 3;
    document.getElementById('fLikelihoodVal').textContent = f?.likelihood ?? 3;
    document.getElementById('fImpact').value = f?.impact ?? 3;
    document.getElementById('fImpactVal').textContent = f?.impact ?? 3;
    document.getElementById('fRecommendation').value = f?.recommendation || '';
    const refs = Array.isArray(f?.control_refs) ? f.control_refs : [];
    document.getElementById('fControlRefs').value = refs.map(r => `${r.framework}:${r.id}`).join(', ');
    document.getElementById('btnDeleteFinding').style.display = f ? '' : 'none';
    document.getElementById('drawer').classList.add('open');
    document.getElementById('drawerBackdrop').classList.add('open');
    document.getElementById('fTitle').focus();
  }

  function closeDrawer() {
    document.getElementById('drawer').classList.remove('open');
    document.getElementById('drawerBackdrop').classList.remove('open');
  }

  function parseControlRefs(s) {
    if (!s || !s.trim()) return [];
    return s.split(',').map(part => {
      const m = part.trim().match(/^([^:]+):(.+)$/);
      return m ? { framework: m[1].trim(), id: m[2].trim() } : null;
    }).filter(Boolean);
  }

  async function saveFinding() {
    const id = document.getElementById('findingId').value;
    const body = {
      title:          document.getElementById('fTitle').value.trim(),
      description:    document.getElementById('fDescription').value || null,
      category:       document.getElementById('fCategory').value || null,
      status:         document.getElementById('fStatus').value,
      likelihood:     parseInt(document.getElementById('fLikelihood').value, 10),
      impact:         parseInt(document.getElementById('fImpact').value, 10),
      recommendation: document.getElementById('fRecommendation').value || null,
      control_refs:   parseControlRefs(document.getElementById('fControlRefs').value),
    };
    if (!body.title) { toast('Title is required'); return; }
    try {
      if (id) {
        await api('PUT', `/${encodeURIComponent(state.profileId)}/findings/${encodeURIComponent(id)}`, body);
        toast('Finding updated');
      } else {
        await api('POST', `/${encodeURIComponent(state.profileId)}/findings`, body);
        toast('Finding added');
      }
      closeDrawer();
      await loadAndRender();
    } catch (err) {
      toast('Save failed: ' + err.message, 4000);
    }
  }

  async function deleteFinding() {
    const id = document.getElementById('findingId').value;
    if (!id) return;
    if (!confirm('Delete this finding? This cannot be undone.')) return;
    try {
      await api('DELETE', `/${encodeURIComponent(state.profileId)}/findings/${encodeURIComponent(id)}`);
      toast('Finding deleted');
      closeDrawer();
      await loadAndRender();
    } catch (err) {
      toast('Delete failed: ' + err.message, 4000);
    }
  }

  // === Tabs ===
  function wireTabs() {
    document.querySelectorAll('.cra-tab').forEach(btn => {
      btn.addEventListener('click', () => {
        const tab = btn.dataset.tab;
        if (tab === state.activeTab) return;
        state.activeTab = tab;
        document.querySelectorAll('.cra-tab').forEach(t => t.classList.toggle('active', t === btn));
        document.querySelectorAll('.cra-pane').forEach(p => p.classList.toggle('active', p.id === `pane-${tab}`));
        // ECharts needs a resize after a hidden div becomes visible.
        requestAnimationFrame(resizeAllCharts);
      });
    });
  }

  // === CSF maturity sliders ===
  function renderCsfSliders() {
    const auto = state.bundle.csf_scores_auto || {};
    const manual = state.bundle.report.csf_scores_manual || {};
    const host = document.getElementById('csfSliders');
    host.innerHTML = CSF_FN_ORDER.map(k => {
      const val = manual[k] ?? auto[k] ?? 0;
      const isManual = k in manual;
      return `
        <div class="csf-slider-grid">
          <div class="name">${CSF_FN_NAMES[k]} <span class="auto-pill">${isManual ? 'manual' : 'auto'}</span></div>
          <input type="range" min="0" max="5" step="0.1" value="${val}" data-fn="${k}">
          <div class="val" data-val="${k}">${Number(val).toFixed(1)}</div>
        </div>
      `;
    }).join('');
    host.querySelectorAll('input[type=range]').forEach(slider => {
      slider.addEventListener('input', (e) => {
        const k = e.target.dataset.fn;
        host.querySelector(`[data-val="${k}"]`).textContent = Number(e.target.value).toFixed(1);
      });
    });
  }

  async function saveCsfScores() {
    const csf_scores = {};
    document.querySelectorAll('#csfSliders input[type=range]').forEach(s => {
      csf_scores[s.dataset.fn] = parseFloat(s.value);
    });
    try {
      await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { csf_scores });
      toast('CSF scores saved');
      await loadAndRender();
    } catch (err) {
      toast('Save failed: ' + err.message, 4000);
    }
  }

  async function resetCsfScores() {
    try {
      await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { csf_scores: {} });
      toast('Reset to auto-derived scores');
      await loadAndRender();
    } catch (err) {
      toast('Reset failed: ' + err.message, 4000);
    }
  }

  // === Report tab ===
  function renderReportFields() {
    document.getElementById('execSummary').value = state.bundle.report.exec_summary || '';
  }

  function wireReportButtons() {
    document.getElementById('btnSaveCsf').addEventListener('click', saveCsfScores);
    document.getElementById('btnResetCsf').addEventListener('click', resetCsfScores);
    document.getElementById('btnSaveSummary').addEventListener('click', async () => {
      const exec_summary = document.getElementById('execSummary').value;
      try {
        await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { exec_summary });
        toast('Summary saved');
        state.bundle.report.exec_summary = exec_summary;
      } catch (err) { toast('Save failed: ' + err.message, 4000); }
    });
    document.getElementById('btnFinalize').addEventListener('click', async () => {
      if (!confirm('Mark this report as final? You can still edit afterwards.')) return;
      try {
        await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { status: 'final' });
        toast('Report marked final');
        await loadAndRender();
      } catch (err) { toast('Failed: ' + err.message, 4000); }
    });
    document.getElementById('btnExport').addEventListener('click', exportPdf);
  }

  // === PDF export ===
  async function exportPdf() {
    // Force a render of all 4 charts so getDataURL has something to capture.
    // Cycle through tabs invisibly is overkill — instead, we ensure overview is
    // rendered (it's the default tab) and just call getDataURL on each instance.
    if (state.activeTab !== 'overview') {
      // Briefly switch to overview to render charts, then switch back.
      const prev = state.activeTab;
      document.querySelector('.cra-tab[data-tab="overview"]').click();
      await new Promise(r => setTimeout(r, 200));  // let layout settle
      // Capture
      const charts = capturePngs();
      document.querySelector(`.cra-tab[data-tab="${prev}"]`).click();
      return doExport(charts);
    }
    return doExport(capturePngs());
  }

  function capturePngs() {
    const out = {};
    const map = {
      heatmap_png: 'chartHeatmap',
      radar_png:   'chartRadar',
      cis_png:     'chartCis',
      csf_png:     'chartCsf',
    };
    for (const [k, id] of Object.entries(map)) {
      const c = state.charts[id];
      if (!c) continue;
      try {
        out[k] = c.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#ffffff' });
      } catch (e) {
        console.warn('chart capture failed for', id, e);
      }
    }
    return out;
  }

  async function doExport(charts) {
    toast('Generating PDF…', 5000);
    try {
      const res = await fetch(apiUrl(`/${encodeURIComponent(state.profileId)}/export`), {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ charts }),
      });
      if (!res.ok) {
        let msg = 'HTTP ' + res.status;
        try { const j = await res.json(); if (j.error) msg = j.error; } catch (_) {}
        throw new Error(msg);
      }
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const cover = (state.bundle.profile.company_name || 'report').replace(/[^a-zA-Z0-9]/g, '-');
      a.download = `clinic-risk-assessment-${cover}.pdf`;
      document.body.appendChild(a);
      a.click();
      setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
      toast('PDF downloaded');
    } catch (err) {
      toast('Export failed: ' + err.message, 4000);
    }
  }

  // === Resize handler ===
  window.addEventListener('resize', () => requestAnimationFrame(resizeAllCharts));

  // === Go ===
  document.addEventListener('DOMContentLoaded', bootstrap);
})();
