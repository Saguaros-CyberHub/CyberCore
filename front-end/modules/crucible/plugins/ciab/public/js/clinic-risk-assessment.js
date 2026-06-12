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
    cisram: null,         // /api/cis-ram/:profileId response
    cisramExpanded: null, // currently expanded safeguard_num (only one at a time)
    cisramSaveTimers: {}, // debounced field-save timers per safeguard_num
    cisramCollapsed: null, // Set<controlNum> of currently-collapsed controls; null until first render seeds it
    frameworks: null,     // /frameworks catalog (cis_ig1 + nist_csf_2_0), lazy-loaded for the intake breakdown
  };

  const CSF_HIDE_KEY = 'cra-hide-csf'; // localStorage: '1' => hide NIST CSF charts in Overview

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
    wireCsfToggle();
    wireIntakeDrawer();
    wireOverviewSections();
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
    // Load CIS RAM bundle in parallel; tolerate failure (e.g. migration not applied).
    try {
      const ramRes = await fetch('/api/cis-ram/' + encodeURIComponent(state.profileId), {
        credentials: 'same-origin',
      });
      if (ramRes.ok) state.cisram = await ramRes.json();
      else state.cisram = null;
    } catch (_) {
      state.cisram = null;
    }
    renderHeader();
    renderOverviewStats();
    renderHeatmap();
    renderHeatmapResidual();
    renderRadar();
    renderCisBars();
    renderCsfBars();
    applyCsfVisibility();
    renderFindingsTable();
    renderCsfSliders();
    renderReportFields();
    renderCisRam();
  }

  // === Header ===
  function renderHeader() {
    const b = state.bundle;
    const cover = b.profile.company_name || b.intake?.cover_name || 'Untitled Engagement';
    document.getElementById('craCompanyName').textContent = cover;
    const crumb = document.getElementById('craBreadcrumbName');
    if (crumb) crumb.textContent = cover;
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
    const ramRows = collectScoredRamRows();
    // Combined avg risk across CIS RAM rows (1–9 native) and free-form findings
    // (1–5×1–5 projected to 1–9 band scale).
    const ramRisks = ramRows.map(r => (r.likelihood || 0) * Math.max(r.mission_impact || 0, r.obligations_impact || 0));
    const findingRisks = findings.map(f => bandTo3(f.likelihood) * bandTo3(f.impact));
    const allRisks = [...ramRisks, ...findingRisks].filter(v => v > 0);
    const avgRisk = allRisks.length === 0 ? '0.0'
      : (allRisks.reduce((a, c) => a + c, 0) / allRisks.length).toFixed(1);
    const totalRows = ramRows.length + findings.length;

    const csfNonZero = CSF_FN_ORDER.map(k => Number(b.csf_scores[k]) || 0).filter(v => v > 0);
    const csfAvg = csfNonZero.length === 0 ? '0.0'
      : (csfNonZero.reduce((a, c) => a + c, 0) / csfNonZero.length).toFixed(1);

    const ramTotals = state.cisram?.totals || { scored: 0, total: 56, reasonable: 0 };

    const cards = [
      { label: 'CIS RAM Scored',    value: `${ramTotals.scored} / ${ramTotals.total}`, hint: `${ramTotals.reasonable} reasonable` },
      { label: 'Avg Inherent Risk', value: avgRisk, hint: `${totalRows} entries, scale 1–9` },
      { label: 'IG1 Coverage',      value: b.cis_coverage.score + '%', hint: `${b.cis_coverage.yes} yes · ${b.cis_coverage.partial} partial` },
      { label: 'CSF Maturity',      value: csfAvg,  hint: `avg of ${csfNonZero.length} scored function${csfNonZero.length === 1 ? '' : 's'} (of 6), 0–5` },
    ];
    const host = document.getElementById('overviewStats');
    host.innerHTML = cards.map(c => `
      <div class="cra-stat-card">
        <div class="label">${c.label}</div>
        <div class="value">${c.value}</div>
        <div class="hint">${c.hint}</div>
      </div>
    `).join('');

    // Compliance posture callout (only when intake._meta.posture is present)
    const posture = b.intake?.payload?._meta?.posture;
    const calloutEl = document.getElementById('postureCallout');
    if (calloutEl) {
      if (posture && posture.name) {
        const pretty = String(posture.name)
          .split('-').map(s => s.charAt(0).toUpperCase() + s.slice(1)).join(' ');
        document.getElementById('postureTitle').textContent = pretty;
        document.getElementById('postureBody').textContent =
          posture.description || 'Distinct compliance pattern detected for this profile.';
        calloutEl.style.display = '';
      } else {
        calloutEl.style.display = 'none';
      }
    }
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

  // Map a 1–5 likelihood/impact to a 1–3 band so free-form findings can render
  // on the CIS RAM tri-factor heat map alongside CIS RAM rows.
  // 1→1, 2→1, 3→2, 4→2, 5→3 — keeps "5" rare and central-skews 3.
  function bandTo3(v) {
    if (!v) return 0;
    return Math.min(3, Math.ceil(v / 2));
  }

  // === Heat map (FINDINGS-ONLY 3×3) ===
  // Standard risk-assessment practice: the heat map plots IDENTIFIED RISKS
  // (entries on the risk register). CIS RAM safeguard scoring is presented
  // separately in the Risk Register tab and CIS RAM Workbook tab — mixing
  // the two scales (RAM 1-3 + findings 1-5→1-3) on one chart creates
  // ambiguity. Both the on-screen dashboard and the printable report use
  // the same algorithm so the numbers match.
  function renderHeatmap() {
    const c = getOrInitChart('chartHeatmap');
    if (!c) return;
    const findings = state.bundle.findings || [];

    const grid = {};
    const bump = (l, i) => {
      if (!l || !i) return;
      const k = `${l},${i}`;
      grid[k] = (grid[k] || 0) + 1;
    };
    for (const f of findings) {
      bump(bandTo3(f.likelihood), bandTo3(f.impact));
    }

    const data = [];
    for (let l = 1; l <= 3; l++) {
      for (let i = 1; i <= 3; i++) {
        data.push([i - 1, l - 1, grid[`${l},${i}`] || 0]);
      }
    }
    const maxCount = Math.max(1, ...data.map(d => d[2]));
    c.setOption({
      grid: { left: 100, right: 30, top: 20, bottom: 50 },
      xAxis: { type: 'category', data: ['1 Acceptable', '2 Unacceptable', '3 Catastrophic'], name: 'Impact', nameLocation: 'middle', nameGap: 28, axisLabel: { fontSize: 10 }, splitArea: { show: false } },
      yAxis: { type: 'category', data: ['1 Not Expected', '2 Foreseeable', '3 Expected'], name: 'Likelihood', nameLocation: 'middle', nameGap: 70, nameRotate: 90, axisLabel: { fontSize: 10 }, splitArea: { show: false } },
      visualMap: {
        show: false,
        min: 0, max: maxCount,
        inRange: { color: ['#e0f2fe', '#bae6fd', '#fcd34d', '#fb923c', '#dc2626', '#7f1d1d'] }
      },
      tooltip: {
        formatter: (p) => `Likelihood ${p.value[1] + 1} × Impact ${p.value[0] + 1} (risk ${(p.value[1] + 1) * (p.value[0] + 1)}): <b>${p.value[2]}</b> finding${p.value[2] === 1 ? '' : 's'}`,
      },
      series: [{
        type: 'heatmap',
        data,
        label: { show: true, fontSize: 14, fontWeight: 700, formatter: (p) => p.value[2] || '' },
        itemStyle: { borderColor: '#fff', borderWidth: 2 },
      }],
    }, true);
  }

  // === Residual heat map — same algorithm as renderHeatmap but uses
  // residual_likelihood / residual_impact (post-treatment projection).
  // Findings without residual scoring are excluded from this view.
  function renderHeatmapResidual() {
    const c = getOrInitChart('chartHeatmapResidual');
    if (!c) return;
    const findings = (state.bundle.findings || [])
      .filter(f => f.residual_likelihood && f.residual_impact);

    const grid = {};
    const bump = (l, i) => {
      if (!l || !i) return;
      const k = `${l},${i}`;
      grid[k] = (grid[k] || 0) + 1;
    };
    for (const f of findings) {
      bump(bandTo3(f.residual_likelihood), bandTo3(f.residual_impact));
    }

    const data = [];
    for (let l = 1; l <= 3; l++) {
      for (let i = 1; i <= 3; i++) {
        data.push([i - 1, l - 1, grid[`${l},${i}`] || 0]);
      }
    }
    const maxCount = Math.max(1, ...data.map(d => d[2]));
    c.setOption({
      grid: { left: 100, right: 30, top: 20, bottom: 50 },
      xAxis: { type: 'category', data: ['1 Acceptable', '2 Unacceptable', '3 Catastrophic'], name: 'Impact', nameLocation: 'middle', nameGap: 28, axisLabel: { fontSize: 10 }, splitArea: { show: false } },
      yAxis: { type: 'category', data: ['1 Not Expected', '2 Foreseeable', '3 Expected'], name: 'Likelihood', nameLocation: 'middle', nameGap: 70, nameRotate: 90, axisLabel: { fontSize: 10 }, splitArea: { show: false } },
      visualMap: {
        show: false,
        min: 0, max: maxCount,
        inRange: { color: ['#e0f2fe', '#bae6fd', '#fcd34d', '#fb923c', '#dc2626', '#7f1d1d'] }
      },
      tooltip: {
        formatter: (p) => `Residual L ${p.value[1] + 1} × I ${p.value[0] + 1}: <b>${p.value[2]}</b> finding${p.value[2] === 1 ? '' : 's'}`,
      },
      series: [{
        type: 'heatmap',
        data,
        label: { show: true, fontSize: 14, fontWeight: 700, formatter: (p) => p.value[2] || '' },
        itemStyle: { borderColor: '#fff', borderWidth: 2 },
      }],
    }, true);
  }

  // Pull all CIS RAM safeguard rows that have been scored (have inherent risk).
  function collectScoredRamRows() {
    if (!state.cisram?.controls) return [];
    const out = [];
    for (const ctrl of state.cisram.controls) {
      for (const r of (ctrl.rows || [])) {
        if (r.likelihood && (r.mission_impact || r.obligations_impact)) out.push(r);
      }
    }
    return out;
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

  // === NIST CSF visibility toggle (Overview) ===
  // Hide/show the NIST CSF 2.0 Maturity radar and the Function Scores bar chart.
  // Preference persists per browser in localStorage. When the function-scores
  // card is hidden, the CIS IG1 Coverage card expands to full width.
  function csfHidden() { return localStorage.getItem(CSF_HIDE_KEY) === '1'; }

  function applyCsfVisibility() {
    const hidden = csfHidden();
    const radarRow = document.getElementById('csfRadarRow');
    const barsCard = document.getElementById('csfBarsCard');
    const cisRow   = document.getElementById('cisCsfRow');
    if (radarRow) radarRow.style.display = hidden ? 'none' : '';
    if (barsCard) barsCard.style.display = hidden ? 'none' : '';
    // Drop the 2-column grid when the right-hand CSF card is gone so CIS goes full width.
    if (cisRow) cisRow.classList.toggle('cols-2', !hidden);
    const btn = document.getElementById('btnToggleCsf');
    if (btn) btn.textContent = hidden ? 'Show NIST CSF' : 'Hide NIST CSF';
    // ECharts can't measure a freshly-shown div until it's laid out.
    if (!hidden) requestAnimationFrame(resizeAllCharts);
  }

  function wireCsfToggle() {
    const btn = document.getElementById('btnToggleCsf');
    if (!btn) return;
    btn.addEventListener('click', () => {
      localStorage.setItem(CSF_HIDE_KEY, csfHidden() ? '0' : '1');
      applyCsfVisibility();
    });
  }

  // Collapsible overview sections: ECharts renders 0×0 inside a closed
  // <details>, so charts must resize when a section is opened. Also makes the
  // CIS IG1 card (role=button) keyboard-operable.
  function wireOverviewSections() {
    document.querySelectorAll('details.cra-section').forEach(d => {
      d.addEventListener('toggle', () => {
        if (d.open) requestAnimationFrame(resizeAllCharts);
      });
    });
    const cisCard = document.getElementById('cisCard');
    if (cisCard) {
      cisCard.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); cisCard.click(); }
      });
    }
  }

  // === Intake breakdown drawer (opened from the CIS IG1 Coverage card) ===
  const INTAKE_SECTION_LABELS = {
    company: 'Company', network: 'Network & Assets', wireless: 'Wireless',
    endpoint: 'Endpoints', email_web: 'Email & Web', access: 'Access & Identity',
    data: 'Data', vuln_audit: 'Vulnerability & Audit', ig1: 'CIS IG1 Safeguards',
    notes: 'Notes',
  };
  const INTAKE_SECTION_ORDER = ['company', 'network', 'wireless', 'endpoint', 'email_web', 'access', 'data', 'vuln_audit', 'ig1', 'notes'];
  const MUTED_DASH = '<span style="color:var(--text-muted)">—</span>';

  function humanizeKey(k) {
    return String(k)
      .replace(/_/g, ' ')
      .replace(/\b\w/g, c => c.toUpperCase())
      .replace(/\bId\b/g, 'ID').replace(/\bIp\b/g, 'IP').replace(/\bOs\b/g, 'OS')
      .replace(/\bMfa\b/g, 'MFA').replace(/\bVpn\b/g, 'VPN').replace(/\bUrl\b/g, 'URL');
  }

  function formatIntakeValue(v) {
    if (v === null || v === undefined || v === '') return MUTED_DASH;
    if (typeof v === 'boolean') return v ? 'Yes' : 'No';
    if (Array.isArray(v)) return v.length ? v.map(x => escapeHtml(String(x))).join(', ') : MUTED_DASH;
    if (typeof v === 'object') {
      const parts = Object.entries(v)
        .filter(([, val]) => val !== '' && val != null)
        .map(([kk, val]) => `${escapeHtml(humanizeKey(kk))}: ${escapeHtml(String(val))}`);
      return parts.length ? parts.join('; ') : MUTED_DASH;
    }
    return escapeHtml(String(v));
  }

  function renderKvSection(secVal) {
    if (!secVal || typeof secVal !== 'object') {
      if (secVal === '' || secVal == null) return '';
      return `<div class="intake-kv"><div class="k">Value</div><div class="v">${escapeHtml(String(secVal))}</div></div>`;
    }
    const entries = Object.entries(secVal).filter(([k, v]) =>
      !k.startsWith('_') && v !== '' && v != null && !(Array.isArray(v) && v.length === 0));
    if (!entries.length) return '';
    const rows = entries.map(([k, v]) =>
      `<div class="k">${escapeHtml(humanizeKey(k))}</div><div class="v">${formatIntakeValue(v)}</div>`).join('');
    return `<div class="intake-kv">${rows}</div>`;
  }

  function renderIg1Section(secVal) {
    const cat = state.frameworks?.cis_ig1;
    const ans = secVal || {};
    const label = INTAKE_SECTION_LABELS.ig1;
    if (!cat || !Array.isArray(cat.safeguards) || !cat.safeguards.length) {
      const inner = renderKvSection(ans);
      return inner ? `<div class="intake-section"><div class="sec-title">${escapeHtml(label)}</div>${inner}</div>` : '';
    }
    // Group safeguards by control number, preserving catalog order.
    const groups = [];
    const byControl = {};
    for (const sg of cat.safeguards) {
      if (!byControl[sg.control]) {
        byControl[sg.control] = { control: sg.control, name: sg.control_name, items: [] };
        groups.push(byControl[sg.control]);
      }
      byControl[sg.control].items.push(sg);
    }
    let html = `<div class="intake-section"><div class="sec-title">${escapeHtml(label)} ` +
      `<span style="font-weight:400;text-transform:none;letter-spacing:normal;color:var(--text-muted)">(${cat.safeguards.length} safeguards)</span></div>`;
    for (const g of groups) {
      const rows = g.items.map(sg => {
        const v = ans[`ig1_${sg.num}`];
        const norm = (v === 'yes' || v === 'partial' || v === 'no') ? v : 'unknown';
        const ansLabel = norm === 'unknown' ? 'Unanswered' : norm;
        return `<div class="ig1-sg">` +
          `<span class="num">${escapeHtml(sg.num)}</span>` +
          `<span class="name">${escapeHtml(sg.name)}</span>` +
          `<span class="ig1-ans ${norm}">${escapeHtml(ansLabel)}</span>` +
          `</div>`;
      }).join('');
      html += `<div class="ig1-control"><div class="ctrl-name">${escapeHtml(String(g.control))}. ${escapeHtml(g.name || '')}</div>${rows}</div>`;
    }
    html += `</div>`;
    return html;
  }

  function renderIntakeBreakdown() {
    const body = document.getElementById('intakeBody');
    const titleEl = document.getElementById('intakeDrawerTitle');
    const b = state.bundle;
    const company = b?.profile?.company_name || b?.intake?.cover_name || 'Client';
    titleEl.textContent = `${company} — Intake Form`;

    const payload = b?.intake_payload;
    if (!payload || !payload.sections) {
      body.innerHTML = `<div class="empty-state"><div class="big-icon">📋</div>No intake form has been submitted for this engagement yet.</div>`;
      return;
    }
    const sections = payload.sections;
    const cv = b.cis_coverage || {};

    // Summary line — mirrors the CIS IG1 Coverage chart that was clicked.
    let html = `<div class="intake-summary">` +
      `<span class="pill ig1-ans yes">Yes ${cv.yes || 0}</span>` +
      `<span class="pill ig1-ans partial">Partial ${cv.partial || 0}</span>` +
      `<span class="pill ig1-ans no">No ${cv.no || 0}</span>` +
      `<span class="pill ig1-ans unknown">Unanswered ${cv.unknown || 0}</span>` +
      `<span class="pill" style="background:var(--primary,#1e40af);color:#fff;">IG1 Coverage ${cv.score != null ? cv.score + '%' : '—'}</span>` +
      `</div>`;

    // Intake meta (source / completion / status).
    if (b.intake) {
      html += `<div class="intake-section"><div class="intake-kv">` +
        `<div class="k">Source</div><div class="v">${escapeHtml(b.intake.source === 'real_client' ? 'Real client' : 'Training')}</div>` +
        `<div class="k">Completion</div><div class="v">${escapeHtml(String(b.intake.completion_percentage ?? '—'))}%</div>` +
        `<div class="k">Status</div><div class="v">${escapeHtml(b.intake.status || '—')}</div>` +
        `</div></div>`;
    }

    // Ordered sections first, then any extras present in the payload.
    const keys = [
      ...INTAKE_SECTION_ORDER.filter(k => k in sections),
      ...Object.keys(sections).filter(k => !INTAKE_SECTION_ORDER.includes(k) && !k.startsWith('_')),
    ];
    for (const secKey of keys) {
      const secVal = sections[secKey];
      if (secKey === 'ig1') { html += renderIg1Section(secVal); continue; }
      const inner = renderKvSection(secVal);
      if (!inner) continue; // skip empty sections
      const label = INTAKE_SECTION_LABELS[secKey] || humanizeKey(secKey);
      html += `<div class="intake-section"><div class="sec-title">${escapeHtml(label)}</div>${inner}</div>`;
    }

    body.innerHTML = html;
  }

  function wireIntakeDrawer() {
    const card = document.getElementById('cisCard');
    if (card) card.addEventListener('click', openIntakeDrawer);
    document.getElementById('btnCloseIntake')?.addEventListener('click', closeIntakeDrawer);
    document.getElementById('intakeBackdrop')?.addEventListener('click', closeIntakeDrawer);
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && document.getElementById('intakeDrawer')?.classList.contains('open')) {
        closeIntakeDrawer();
      }
    });
  }

  async function openIntakeDrawer() {
    document.getElementById('intakeDrawer').classList.add('open');
    document.getElementById('intakeBackdrop').classList.add('open');
    document.getElementById('intakeBody').innerHTML = '<div class="empty-state">Loading…</div>';
    // Lazy-load the IG1 catalog once so we can label/group safeguards.
    if (!state.frameworks) {
      try { state.frameworks = await api('GET', '/frameworks'); }
      catch (_) { state.frameworks = { cis_ig1: null }; }
    }
    renderIntakeBreakdown();
  }

  function closeIntakeDrawer() {
    document.getElementById('intakeDrawer').classList.remove('open');
    document.getElementById('intakeBackdrop').classList.remove('open');
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
    const btn = document.getElementById('btnSaveFinding');
    Utils.setBtnLoading(btn, true, 'Saving…');
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
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  }

  async function deleteFinding() {
    const id = document.getElementById('findingId').value;
    if (!id) return;
    const ok = await Confirm.show({ title: 'Delete this finding?', message: 'This cannot be undone.', confirmText: 'Delete', danger: true });
    if (!ok) return;
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

  // === CIS RAM Workbook ===
  function renderCisRam() {
    const host = document.getElementById('ramControls');
    if (!host) return;
    if (!state.cisram) {
      host.innerHTML = `<div class="empty-state"><div class="big-icon">📚</div>CIS RAM data unavailable. Confirm migration 005 has been applied.</div>`;
      return;
    }

    // Header values
    const acceptable = state.cisram.assessment.acceptable_risk_score;
    const acceptableInput = document.getElementById('ramAcceptable');
    if (acceptableInput && document.activeElement !== acceptableInput) {
      acceptableInput.value = acceptable;
      acceptableInput.onchange = () => onAcceptableChanged(acceptableInput.value);
    }
    const totals = state.cisram.totals;
    document.getElementById('ramScored').textContent = `${totals.scored} / ${totals.total}`;
    document.getElementById('ramReasonable').textContent = `${totals.reasonable} / ${totals.total}`;

    // Seed the collapsed set on first render: collapse controls that have no
    // scored rows yet so the page isn't a wall of empty rows. Subsequent
    // renders respect explicit user toggles in this set.
    if (state.cisramCollapsed === null) {
      state.cisramCollapsed = new Set(
        (state.cisram.controls || []).filter(c => c.scored === 0).map(c => c.control)
      );
    }
    // If a row is currently expanded, ensure its control is open (otherwise
    // the drawer is invisible — confusing right after a click).
    if (state.cisramExpanded) {
      const ctrl = parseInt(state.cisramExpanded.split('.')[0], 10);
      state.cisramCollapsed.delete(ctrl);
    }

    host.innerHTML = (state.cisram.controls || []).map(ctrl => renderControlSection(ctrl)).join('');
    wireControlHandlers();
  }

  function renderControlSection(ctrl) {
    const collapsed = state.cisramCollapsed?.has(ctrl.control) ? 'collapsed' : '';
    const rowsHtml = ctrl.rows.map(r => renderRamRow(r)).join('');
    return `
      <div class="ram-control ${collapsed}" data-control="${ctrl.control}">
        <div class="ram-control-header" data-toggle="${ctrl.control}">
          <h4><span class="caret">▾</span> Control ${ctrl.control} — ${escapeHtml(ctrl.control_name)}</h4>
          <span class="ctrl-progress">${ctrl.scored} / ${ctrl.total} scored</span>
        </div>
        <div class="ram-rows">${rowsHtml}</div>
      </div>`;
  }

  function scoreClass(v) {
    if (v == null) return 'score-empty';
    if (v <= 2) return 'score-2';
    if (v <= 4) return 'score-4';
    return 'score-9';
  }
  function scoreBadge(v) {
    return `<span class="score-badge ${scoreClass(v)}">${v == null ? '—' : v}</span>`;
  }
  function reasonableMark(row) {
    if (row.is_reasonable === true)  return '<span title="Treatment residual ≤ acceptable" style="color:#16a34a;font-weight:700;">✓</span>';
    if (row.is_reasonable === false) return '<span title="Treatment residual > acceptable — not yet reasonable" style="color:#dc2626;font-weight:700;">✗</span>';
    return '<span style="color:var(--text-muted, #94a3b8);">—</span>';
  }

  function renderRamRow(r) {
    const cat = state.cisram.safeguard_catalog[r.safeguard_num] || { name: r.safeguard_num };
    const expanded = state.cisramExpanded === r.safeguard_num ? 'expanded' : '';
    return `
      <div class="ram-row ${expanded}" data-num="${escapeHtml(r.safeguard_num)}">
        <div class="num">${escapeHtml(r.safeguard_num)}</div>
        <div>
          <div class="name">${escapeHtml(cat.name)}</div>
          <div class="asset">${r.asset_class ? 'Asset: ' + escapeHtml(r.asset_class) : '<em style="color:var(--text-muted)">no asset class set</em>'}</div>
        </div>
        <div class="asset" style="text-align:center">${escapeHtml(r.status || 'open')}</div>
        <div class="score" title="Inherent risk">${scoreBadge(r.inherent_risk_score)}</div>
        <div class="score" title="Residual risk">${scoreBadge(r.residual_risk_score)}</div>
        <div class="reasonable">${reasonableMark(r)}</div>
      </div>
      ${expanded ? renderDrawer(r, cat) : ''}`;
  }

  function selOpt(val, current) {
    return `<option value="${val}" ${String(val) === String(current ?? '') ? 'selected' : ''}>${val}</option>`;
  }
  function impactSelect(field, current) {
    return `<select data-field="${field}">
      <option value="" ${current == null ? 'selected' : ''}>—</option>
      ${selOpt(1, current)}${selOpt(2, current)}${selOpt(3, current)}
    </select>`;
  }
  function statusSelect(current) {
    const opts = ['open', 'accepted', 'mitigated', 'transferred', 'not_applicable'];
    return `<select data-field="status">
      ${opts.map(o => `<option value="${o}" ${o === current ? 'selected' : ''}>${o.replace('_', ' ')}</option>`).join('')}
    </select>`;
  }

  function renderDrawer(r, cat) {
    return `
      <div class="ram-drawer" data-drawer="${escapeHtml(r.safeguard_num)}">
        <div class="group-title">Safeguard ${escapeHtml(r.safeguard_num)} — ${escapeHtml(cat.name)}</div>
        <div class="grid">
          <div class="field">
            <label>Asset class</label>
            <input type="text" data-field="asset_class" value="${escapeHtml(r.asset_class || '')}" placeholder="Workstations, Servers, Data, …">
          </div>
          <div class="field">
            <label>Status</label>
            ${statusSelect(r.status)}
          </div>
        </div>

        <div class="group-title">Inherent Risk (1=Acceptable, 2=Unacceptable, 3=Catastrophic)</div>
        <div class="grid three">
          <div class="field"><label>Mission impact</label>${impactSelect('mission_impact', r.mission_impact)}</div>
          <div class="field"><label>Obligations impact</label>${impactSelect('obligations_impact', r.obligations_impact)}</div>
          <div class="field"><label>Likelihood</label>${impactSelect('likelihood', r.likelihood)}</div>
        </div>

        <div class="group-title">Treatment Plan</div>
        <div class="grid">
          <div class="field"><label>Treatment safeguard #</label>
            <input type="text" data-field="treatment_safeguard" value="${escapeHtml(r.treatment_safeguard || r.safeguard_num)}">
          </div>
          <div class="field"><label>Treatment cost</label>
            <input type="text" data-field="treatment_cost" value="${escapeHtml(r.treatment_cost || '')}" placeholder="Low / Medium / $5k / …">
          </div>
        </div>
        <div class="field" style="margin-top:8px"><label>Treatment title</label>
          <input type="text" data-field="treatment_title" value="${escapeHtml(r.treatment_title || '')}" placeholder="Short label for the proposed safeguard">
        </div>
        <div class="field" style="margin-top:8px"><label>Treatment description</label>
          <textarea data-field="treatment_description" rows="3" placeholder="What the client should do.">${escapeHtml(r.treatment_description || '')}</textarea>
        </div>

        <div class="group-title">Residual Risk (after treatment)</div>
        <div class="grid three">
          <div class="field"><label>Mission impact</label>${impactSelect('treatment_mission_impact', r.treatment_mission_impact)}</div>
          <div class="field"><label>Obligations impact</label>${impactSelect('treatment_obligations_impact', r.treatment_obligations_impact)}</div>
          <div class="field"><label>Likelihood</label>${impactSelect('treatment_likelihood', r.treatment_likelihood)}</div>
        </div>

        <div class="grid" style="margin-top:12px">
          <div class="field"><label>Implementation year</label>
            <input type="number" data-field="implementation_year" min="2024" max="2099" value="${r.implementation_year || ''}">
          </div>
          <div class="field"><label>Last completed</label>
            <input type="date" data-field="last_completed_date" value="${r.last_completed_date ? String(r.last_completed_date).slice(0,10) : ''}">
          </div>
        </div>
        <div class="field" style="margin-top:8px"><label>Notes</label>
          <textarea data-field="notes" rows="2">${escapeHtml(r.notes || '')}</textarea>
        </div>
      </div>`;
  }

  function wireControlHandlers() {
    // Section collapse toggles. Persist to state so subsequent re-renders
    // (e.g. after a row click) honor the user's choice instead of falling
    // back to "auto-collapse if 0 scored".
    document.querySelectorAll('.ram-control-header[data-toggle]').forEach(h => {
      h.addEventListener('click', () => {
        const ctrlNum = parseInt(h.dataset.toggle, 10);
        if (state.cisramCollapsed.has(ctrlNum)) state.cisramCollapsed.delete(ctrlNum);
        else state.cisramCollapsed.add(ctrlNum);
        h.parentElement.classList.toggle('collapsed');
      });
    });
    // Row click → expand drawer (only one at a time).
    document.querySelectorAll('.ram-row[data-num]').forEach(row => {
      row.addEventListener('click', (e) => {
        // Ignore clicks bubbling from drawer inputs.
        if (e.target.closest('.ram-drawer')) return;
        const num = row.dataset.num;
        state.cisramExpanded = state.cisramExpanded === num ? null : num;
        renderCisRam(); // simple rerender — drawer count is small
      });
    });
    // Drawer field changes → debounced PUT.
    document.querySelectorAll('.ram-drawer [data-field]').forEach(el => {
      el.addEventListener('input', () => {
        const drawer = el.closest('.ram-drawer');
        const num = drawer.dataset.drawer;
        scheduleRamSave(num, el.dataset.field, el.value);
      });
    });
  }

  function scheduleRamSave(safeguardNum, field, value) {
    if (state.cisramSaveTimers[safeguardNum]) clearTimeout(state.cisramSaveTimers[safeguardNum].timer);
    if (!state.cisramSaveTimers[safeguardNum]) state.cisramSaveTimers[safeguardNum] = { changes: {} };
    state.cisramSaveTimers[safeguardNum].changes[field] = value;
    state.cisramSaveTimers[safeguardNum].timer = setTimeout(() => {
      const changes = state.cisramSaveTimers[safeguardNum].changes;
      state.cisramSaveTimers[safeguardNum].changes = {};
      saveRamRow(safeguardNum, changes);
    }, 600);
  }

  async function saveRamRow(safeguardNum, changes) {
    try {
      const res = await fetch(`/api/cis-ram/${encodeURIComponent(state.profileId)}/safeguards/${encodeURIComponent(safeguardNum)}`, {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(changes),
      });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || ('HTTP ' + res.status));
      }
      const body = await res.json();
      // Patch local state and recompute totals/heatmap without a full reload.
      patchLocalRamRow(body.row);
      recomputeRamTotals();
      // Re-render only the row + the visible totals + the heatmap (cheap).
      renderCisRam();
      if (state.activeTab === 'overview') {
        renderOverviewStats();
        renderHeatmap();
      }
      toast(`Saved ${safeguardNum}`);
    } catch (err) {
      toast(`Save ${safeguardNum} failed: ${err.message}`, 4000);
    }
  }

  function patchLocalRamRow(updated) {
    if (!state.cisram) return;
    for (const ctrl of state.cisram.controls) {
      const idx = ctrl.rows.findIndex(r => r.safeguard_num === updated.safeguard_num);
      if (idx >= 0) ctrl.rows[idx] = updated;
    }
  }

  function recomputeRamTotals() {
    if (!state.cisram) return;
    const all = state.cisram.controls.flatMap(c => c.rows);
    const acceptable = state.cisram.assessment.acceptable_risk_score;
    const scored = all.filter(r => r.inherent_risk_score != null).length;
    const reasonable = all.filter(r => r.is_reasonable === true).length;
    state.cisram.totals = {
      total: all.length, scored, reasonable,
      above_acceptable: all.filter(r => r.inherent_risk_score != null && r.inherent_risk_score > acceptable).length,
    };
    // Update per-control scored count too.
    for (const c of state.cisram.controls) c.scored = c.rows.filter(r => r.inherent_risk_score != null).length;
  }

  async function onAcceptableChanged(rawValue) {
    const n = parseInt(rawValue, 10);
    if (!Number.isFinite(n) || n < 1 || n > 9) {
      toast('Acceptable must be 1–9', 3000);
      return;
    }
    try {
      const res = await fetch(`/api/cis-ram/${encodeURIComponent(state.profileId)}`, {
        method: 'PUT', credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ acceptable_risk_score: n }),
      });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      // Reload bundle so is_reasonable flags get recomputed.
      const bundle = await (await fetch(`/api/cis-ram/${encodeURIComponent(state.profileId)}`, { credentials: 'same-origin' })).json();
      state.cisram = bundle;
      renderCisRam();
      if (state.activeTab === 'overview') {
        renderOverviewStats();
        renderHeatmap();
      }
      toast('Acceptable risk updated');
    } catch (err) {
      toast('Update failed: ' + err.message, 4000);
    }
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
    const btn = document.getElementById('btnSaveCsf');
    Utils.setBtnLoading(btn, true, 'Saving…');
    try {
      await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { csf_scores });
      toast('CSF scores saved');
      await loadAndRender();
    } catch (err) {
      toast('Save failed: ' + err.message, 4000);
    } finally {
      Utils.setBtnLoading(btn, false);
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
    // btnSaveSummary is wired in wireDeloitteExecSave() — it saves all 5 exec
    // fields in one PUT. Binding it here too caused a duplicate request per click.
    document.getElementById('btnFinalize').addEventListener('click', async (e) => {
      const ok = await Confirm.show({ title: 'Mark report as final?', message: 'You can still edit afterwards.', confirmText: 'Mark Final' });
      if (!ok) return;
      const btn = e.currentTarget;
      Utils.setBtnLoading(btn, true, 'Finalizing…');
      try {
        await api('PUT', `/${encodeURIComponent(state.profileId)}/report`, { status: 'final' });
        toast('Report marked final');
        await loadAndRender();
      } catch (err) { toast('Failed: ' + err.message, 4000); }
      finally { Utils.setBtnLoading(btn, false); }
    });
    document.getElementById('btnExport').addEventListener('click', exportPdf);
    // Open the standalone HTML report in a new tab — student can hit
    // Print → Save as PDF for a polished print-quality output.
    const htmlBtn = document.getElementById('btnOpenHtmlReport');
    if (htmlBtn) htmlBtn.addEventListener('click', () => {
      window.open(`/ciab/clinic-risk-assessment/${encodeURIComponent(state.profileId)}/report`, '_blank');
    });
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

  // ════════════════════════════════════════════════════════════════════
  // TIER 1-3 EXTENSIONS — Assets / POA&M / Insurance / Snapshots /
  // Library / OWASP / FAIR / ALE / Deloitte exec / extended finding drawer
  // ════════════════════════════════════════════════════════════════════

  // ── Extended state ────────────────────────────────────────────────
  state.assets = [];
  state.insurance = null;
  state.snapshots = [];
  state.scenarioLib = null;

  // Hook into loadAndRender to pull the additional data + render the new tabs.
  // We monkey-patch by wrapping the existing function — see initExtensions().
  function initExtensions() {
    const origLoad = loadAndRender;
    window._origCraLoad = origLoad;
    // Wrap the load function so the new tabs render every time data refreshes.
    loadAndRender = async function () {
      await origLoad.apply(this, arguments);
      await loadAssets();
      await loadInsurance();
      await loadSnapshots();
      renderAssets();
      renderPoam();
      renderInsurance();
      renderSnapshots();
      renderDeloitteExec();
      enhanceFindingsTable();
    };
    wireAssetDrawer();
    wireLibraryModal();
    wireInsuranceTab();
    wireSnapshotTab();
    wireDeloitteExecSave();
    wireAleCalculator();
    wireExtendedFindingDrawer();
    wirePoamDownload();
  }
  // Defer until DOMContentLoaded — bootstrap hasn't necessarily replaced loadAndRender yet
  document.addEventListener('DOMContentLoaded', () => {
    if (typeof loadAndRender !== 'function') return;
    initExtensions();
    // Ensure the new tabs get an initial paint after bootstrap has loaded data
    setTimeout(() => {
      if (state.bundle) {
        loadAssets().then(renderAssets);
        loadInsurance().then(renderInsurance);
        loadSnapshots().then(renderSnapshots);
        renderPoam();
        renderDeloitteExec();
        enhanceFindingsTable();
      }
    }, 500);
  });

  // ── Data fetchers ─────────────────────────────────────────────────
  async function loadAssets() {
    try {
      const r = await api('GET', '/' + encodeURIComponent(state.profileId) + '/assets');
      state.assets = r.assets || [];
    } catch (e) { state.assets = []; }
  }
  async function loadInsurance() {
    try {
      const r = await api('GET', '/' + encodeURIComponent(state.profileId) + '/insurance-readiness');
      state.insurance = r.readiness || null;
    } catch (e) { state.insurance = null; }
  }
  async function loadSnapshots() {
    try {
      const r = await api('GET', '/' + encodeURIComponent(state.profileId) + '/snapshots');
      state.snapshots = r.snapshots || [];
    } catch (e) { state.snapshots = []; }
  }
  async function loadScenarioLib() {
    if (state.scenarioLib) return state.scenarioLib;
    try {
      const r = await api('GET', '/scenarios');
      state.scenarioLib = r.scenarios || [];
    } catch (e) { state.scenarioLib = []; }
    return state.scenarioLib;
  }

  // ── ASSETS TAB ────────────────────────────────────────────────────
  function renderAssets() {
    const tbody = document.getElementById('assetsTbody');
    const count = document.getElementById('assetsCount');
    if (!tbody) return;
    const assets = state.assets;
    count.textContent = assets.length === 0
      ? 'No assets yet. Every risk should trace back to one or more assets.'
      : `${assets.length} assets · ${assets.filter(a => a.criticality_tier === 1).length} Tier 1 (crown jewels)`;
    if (assets.length === 0) {
      tbody.innerHTML = `<tr><td colspan="6" style="padding:24px; text-align:center; color:var(--text-muted); font-style:italic;">No assets recorded yet. Click "+ Add Asset" to begin, or generate the answer key for AI-populated assets.</td></tr>`;
      return;
    }
    const dcClass = c => `dc-${String(c || 'internal').toLowerCase()}`;
    const tierColor = t => ({ 1: '#dc2626', 2: '#d97706', 3: '#0891b2' })[t] || '#94a3b8';
    tbody.innerHTML = assets.map(a => `
      <tr style="cursor:pointer; border-left:3px solid ${tierColor(a.criticality_tier)};" data-asset-id="${a.id}">
        <td><strong>${escapeHtml(a.name)}</strong>${a.hostname ? `<br><small style="color:var(--text-muted)">${escapeHtml(a.hostname)}</small>` : ''}</td>
        <td>${escapeHtml((a.asset_type || '').replace(/_/g, ' '))}</td>
        <td>${escapeHtml(a.owner_role || '—')}${a.custodian && a.custodian !== a.owner_role ? `<br><small style="color:var(--text-muted)">${escapeHtml(a.custodian)}</small>` : ''}</td>
        <td><strong>T${a.criticality_tier ?? '—'}</strong></td>
        <td>${a.confidentiality ?? '?'} / ${a.integrity ?? '?'} / ${a.availability ?? '?'}</td>
        <td><span class="${dcClass(a.data_classification)}" style="font-weight:600;">${escapeHtml(a.data_classification || '—')}</span></td>
      </tr>
    `).join('');
    tbody.querySelectorAll('tr[data-asset-id]').forEach(tr => {
      tr.addEventListener('click', () => openAssetDrawer(tr.dataset.assetId));
    });
  }

  function wireAssetDrawer() {
    const btn = document.getElementById('btnAddAsset');
    if (btn) btn.addEventListener('click', () => openAssetDrawer(null));
    ['btnCloseAssetDrawer', 'btnCancelAsset'].forEach(id => {
      const el = document.getElementById(id);
      if (el) el.addEventListener('click', closeAssetDrawer);
    });
    document.getElementById('assetBackdrop')?.addEventListener('click', closeAssetDrawer);
    document.getElementById('btnSaveAsset')?.addEventListener('click', saveAsset);
    document.getElementById('btnDeleteAsset')?.addEventListener('click', deleteAsset);
    ['aConf', 'aInteg', 'aAvail'].forEach(id => {
      const inp = document.getElementById(id);
      if (inp) inp.addEventListener('input', () => {
        document.getElementById(id + 'Val').textContent = inp.value;
      });
    });
  }
  function openAssetDrawer(assetId) {
    const a = assetId ? state.assets.find(x => x.id === assetId) : null;
    document.getElementById('assetDrawerTitle').textContent = a ? 'Edit Asset' : 'Add Asset';
    document.getElementById('assetId').value = a?.id || '';
    document.getElementById('aName').value = a?.name || '';
    document.getElementById('aType').value = a?.asset_type || '';
    document.getElementById('aCriticality').value = a?.criticality_tier || '';
    document.getElementById('aOwner').value = a?.owner_role || '';
    document.getElementById('aCustodian').value = a?.custodian || '';
    document.getElementById('aHostname').value = a?.hostname || '';
    document.getElementById('aIp').value = a?.ip_address || '';
    document.getElementById('aDataClass').value = a?.data_classification || '';
    ['aConf', 'aInteg', 'aAvail'].forEach((id, i) => {
      const key = ['confidentiality', 'integrity', 'availability'][i];
      const val = a?.[key] ?? 2;
      document.getElementById(id).value = val;
      document.getElementById(id + 'Val').textContent = val;
    });
    document.getElementById('aDescription').value = a?.description || '';
    document.getElementById('btnDeleteAsset').style.display = a ? '' : 'none';
    document.getElementById('assetDrawer').classList.add('open');
    document.getElementById('assetBackdrop').classList.add('open');
  }
  function closeAssetDrawer() {
    document.getElementById('assetDrawer').classList.remove('open');
    document.getElementById('assetBackdrop').classList.remove('open');
  }
  async function saveAsset() {
    const id = document.getElementById('assetId').value;
    const payload = {
      name: document.getElementById('aName').value.trim(),
      asset_type: document.getElementById('aType').value || null,
      criticality_tier: parseInt(document.getElementById('aCriticality').value) || null,
      owner_role: document.getElementById('aOwner').value || null,
      custodian: document.getElementById('aCustodian').value || null,
      hostname: document.getElementById('aHostname').value || null,
      ip_address: document.getElementById('aIp').value || null,
      data_classification: document.getElementById('aDataClass').value || null,
      confidentiality: parseInt(document.getElementById('aConf').value),
      integrity: parseInt(document.getElementById('aInteg').value),
      availability: parseInt(document.getElementById('aAvail').value),
      description: document.getElementById('aDescription').value || null
    };
    if (!payload.name) { toast('Asset name required', 3000); return; }
    const btn = document.getElementById('btnSaveAsset');
    Utils.setBtnLoading(btn, true, 'Saving…');
    try {
      if (id) await api('PUT', `/${state.profileId}/assets/${id}`, payload);
      else    await api('POST', `/${state.profileId}/assets`, payload);
      closeAssetDrawer();
      await loadAssets();
      renderAssets();
      toast(id ? 'Asset updated' : 'Asset added');
    } catch (e) { toast('Save failed: ' + e.message, 4000); }
    finally { Utils.setBtnLoading(btn, false); }
  }
  async function deleteAsset() {
    const id = document.getElementById('assetId').value;
    if (!id) return;
    const ok = await Confirm.show({ title: 'Delete this asset?', message: 'Findings that reference it keep their data, but the asset link is removed.', confirmText: 'Delete', danger: true });
    if (!ok) return;
    try {
      await api('DELETE', `/${state.profileId}/assets/${id}`);
      closeAssetDrawer();
      await loadAssets();
      renderAssets();
      toast('Asset deleted');
    } catch (e) { toast('Delete failed: ' + e.message, 4000); }
  }

  // ── POA&M TAB ─────────────────────────────────────────────────────
  function renderPoam() {
    const tbody = document.getElementById('poamTbody');
    if (!tbody) return;
    const open = (state.bundle?.findings || []).filter(f => f.status !== 'mitigated');
    if (open.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted); font-style:italic;">All findings mitigated, or no findings recorded. Nothing to plan.</td></tr>`;
      return;
    }
    open.sort((a, b) => (Number(b.inherent_risk) || 0) - (Number(a.inherent_risk) || 0));
    const sevClass = r => r >= 16 ? 'risk-critical' : r >= 12 ? 'risk-high' : r >= 6 ? 'risk-medium' : 'risk-low';
    const sevLabel = r => r >= 16 ? 'CRIT' : r >= 12 ? 'HIGH' : r >= 6 ? 'MED' : 'LOW';
    tbody.innerHTML = open.map(f => `
      <tr>
        <td><strong>${escapeHtml(f.finding_code)}</strong></td>
        <td>${escapeHtml(f.title)}</td>
        <td>${escapeHtml((f.discovery_method || '').replace(/_/g, ' '))}</td>
        <td>${escapeHtml(f.owner_name || f.owner_role || '—')}</td>
        <td>${f.target_completion_date ? new Date(f.target_completion_date).toLocaleDateString() : '—'}</td>
        <td><span class="risk-badge ${sevClass(f.inherent_risk)}">${f.inherent_risk ?? '?'}</span> ${sevLabel(f.inherent_risk)}</td>
        <td><span class="status-pill status-${f.status || 'open'}">${(f.status || 'open').toUpperCase()}</span></td>
      </tr>
    `).join('');
  }
  function wirePoamDownload() {
    const btn = document.getElementById('btnDownloadPoam');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      try {
        const r = await fetch(apiUrl(`/${encodeURIComponent(state.profileId)}/poam.csv`), { credentials: 'same-origin' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        const blob = await r.blob();
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = `poam-${state.profileId.slice(0, 8)}.csv`;
        document.body.appendChild(a); a.click(); a.remove();
        setTimeout(() => URL.revokeObjectURL(a.href), 1000);
      } catch (e) { toast('POA&M download failed: ' + e.message, 4000); }
    });
  }

  // ── INSURANCE READINESS TAB ───────────────────────────────────────
  const READINESS_CTRLS = [
    { k: 'mfa_email',           label: 'MFA on email accounts',                weight: 12, type: 'choice' },
    { k: 'mfa_remote',          label: 'MFA on remote / VPN access',           weight: 12, type: 'choice' },
    { k: 'mfa_privileged',      label: 'MFA on privileged / admin accounts',   weight: 14, type: 'choice' },
    { k: 'mfa_cloud',           label: 'MFA on cloud / SaaS sessions',         weight: 10, type: 'choice' },
    { k: 'edr_coverage_pct',    label: 'EDR coverage across endpoints (%)',    weight: 10, type: 'percent' },
    { k: 'immutable_backups',   label: 'Immutable / WORM offsite backups',     weight: 8,  type: 'choice' },
    { k: 'tested_restore_12mo', label: 'Backup restore test in last 12 months',weight: 6,  type: 'choice' },
    { k: 'ir_plan_written',     label: 'Documented incident response plan',    weight: 6,  type: 'choice' },
    { k: 'tabletop_12mo',       label: 'Tabletop exercise in last 12 months',  weight: 5,  type: 'choice' },
    { k: 'pam_in_place',        label: 'Privileged Access Management (PAM)',   weight: 6,  type: 'choice' },
    { k: 'security_training',   label: 'Annual security awareness training',   weight: 6,  type: 'choice' },
    { k: 'vuln_scanning',       label: 'Regular vulnerability scanning',       weight: 5,  type: 'choice' }
  ];
  function renderInsurance() {
    const host = document.getElementById('insControls');
    if (!host) return;
    const r = state.insurance || {};
    host.innerHTML = READINESS_CTRLS.map(c => {
      if (c.type === 'percent') {
        const v = r[c.k] ?? '';
        return `<div style="display:flex; align-items:center; gap:12px; padding:8px 0; border-bottom:1px solid var(--border-color,#e2e8f0);">
          <div style="flex:1;">${escapeHtml(c.label)} <small style="color:var(--text-muted);">(${c.weight} pts)</small></div>
          <input type="number" min="0" max="100" id="ins_${c.k}" value="${v}" style="width:80px; padding:6px; border:1px solid var(--border-color,#e2e8f0); border-radius:4px;">
          <span style="width:40px;">%</span>
        </div>`;
      }
      const cur = r[c.k] || '';
      const optBtn = (val, lbl, color) =>
        `<button type="button" class="ins-opt ${cur === val ? 'active' : ''}" data-k="${c.k}" data-v="${val}" style="padding:4px 12px; border:1px solid ${cur === val ? color : 'var(--border-color,#e2e8f0)'}; background:${cur === val ? color : 'white'}; color:${cur === val ? 'white' : 'var(--text-primary)'}; border-radius:4px; cursor:pointer; font-size:0.8rem; font-weight:600;">${lbl}</button>`;
      return `<div style="display:flex; align-items:center; gap:8px; padding:8px 0; border-bottom:1px solid var(--border-color,#e2e8f0);">
        <div style="flex:1;">${escapeHtml(c.label)} <small style="color:var(--text-muted);">(${c.weight} pts)</small></div>
        ${optBtn('yes', 'YES', '#16a34a')}
        ${optBtn('partial', 'PARTIAL', '#d97706')}
        ${optBtn('no', 'NO', '#dc2626')}
      </div>`;
    }).join('');
    host.querySelectorAll('.ins-opt').forEach(btn => {
      btn.addEventListener('click', () => {
        const k = btn.dataset.k;
        if (!state.insurance) state.insurance = {};
        state.insurance[k] = btn.dataset.v;
        renderInsurance();  // re-render to update active state
      });
    });

    // Tile updates
    document.getElementById('insScore').textContent = r.readiness_score ?? '—';
    const tier = r.readiness_tier || '—';
    document.getElementById('insTier').textContent = tier;
    const tierColors = { 'Insurable':'#16a34a','Conditional':'#d97706','Restricted':'#ea580c','Uninsurable':'#dc2626' };
    const tierHints = {
      'Insurable':   'standard market — competitive premiums',
      'Conditional': 'sub-standard / restricted coverage',
      'Restricted':  'only specialist carriers will quote',
      'Uninsurable': 'declination expected — must remediate first'
    };
    const tile = document.getElementById('insTierTile');
    if (tile && tierColors[tier]) tile.style.borderLeftColor = tierColors[tier];
    document.getElementById('insTierHint').textContent = tierHints[tier] || '';
  }
  function wireInsuranceTab() {
    const btn = document.getElementById('btnSaveInsurance');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const payload = { ...(state.insurance || {}) };
      READINESS_CTRLS.forEach(c => {
        if (c.type === 'percent') payload[c.k] = parseInt(document.getElementById('ins_' + c.k)?.value) || 0;
      });
      Utils.setBtnLoading(btn, true, 'Saving…');
      try {
        const r = await api('PUT', `/${state.profileId}/insurance-readiness`, payload);
        state.insurance = r.readiness;
        renderInsurance();
        toast(`Saved — score ${r.readiness.readiness_score}/100 (${r.readiness.readiness_tier})`);
      } catch (e) { toast('Save failed: ' + e.message, 4000); }
      finally { Utils.setBtnLoading(btn, false); }
    });
  }

  // ── SNAPSHOTS TAB ─────────────────────────────────────────────────
  function renderSnapshots() {
    const tbody = document.getElementById('snapshotsTbody');
    const deltaHost = document.getElementById('snapshotDeltaSection');
    if (!tbody) return;
    const snaps = state.snapshots;
    if (snaps.length === 0) {
      tbody.innerHTML = `<tr><td colspan="7" style="padding:24px; text-align:center; color:var(--text-muted); font-style:italic;">No snapshots yet. Take your first snapshot to establish a baseline; re-snapshot after implementing recommendations to see the delta.</td></tr>`;
      if (deltaHost) deltaHost.innerHTML = '';
      return;
    }
    tbody.innerHTML = snaps.map(s => `
      <tr>
        <td><strong>${escapeHtml(s.label)}</strong></td>
        <td>${new Date(s.created_at).toLocaleString()}</td>
        <td>${s.findings_total ?? '—'}</td>
        <td>${s.findings_critical ?? '—'}</td>
        <td>${s.ig1_coverage_pct ?? '—'}%</td>
        <td>${s.total_inherent_risk ?? '—'}</td>
        <td>${escapeHtml(s.notes || '')}</td>
      </tr>
    `).join('');
    // Delta cards (compare 2 most recent)
    if (snaps.length >= 2 && deltaHost) {
      const [now, prior] = snaps;
      const delta = (label, n, p, opts={}) => {
        const d = (Number(n)||0) - (Number(p)||0);
        const arr = d > 0 ? '▲' : d < 0 ? '▼' : '—';
        const cls = (opts.coverage ? (d > 0 ? 'down' : 'up') : (d > 0 ? 'up' : 'down'));  // coverage: up=good (green); findings: up=bad (red)
        const color = cls === 'down' ? 'var(--risk-low)' : cls === 'up' ? 'var(--risk-high)' : 'var(--text-muted)';
        const sign = d > 0 ? '+' : '';
        return `<div class="cra-stat-card" style="margin:0; border-left-color:${color};">
          <div class="label">${escapeHtml(label)}</div>
          <div class="value">${n ?? '—'}${opts.suffix||''}</div>
          <div class="hint" style="color:${color}; font-weight:700;">${arr} ${sign}${d}${opts.suffix||''} vs prior</div>
        </div>`;
      };
      deltaHost.innerHTML = `
        <div class="cra-card" style="margin-bottom:14px;">
          <h3 style="margin-top:0;">Delta vs Prior Snapshot</h3>
          <p class="sub" style="font-size:0.85rem;">Comparing <strong>${escapeHtml(now.label)}</strong> against <strong>${escapeHtml(prior.label)}</strong>.</p>
          <div class="cra-grid cols-4">
            ${delta('Total Findings',  now.findings_total,    prior.findings_total)}
            ${delta('Critical Risks',  now.findings_critical, prior.findings_critical)}
            ${delta('IG1 Coverage',    now.ig1_coverage_pct,  prior.ig1_coverage_pct, { suffix:'%', coverage:true })}
            ${delta('Inherent Risk',   now.total_inherent_risk, prior.total_inherent_risk)}
          </div>
        </div>`;
    } else if (deltaHost) {
      deltaHost.innerHTML = `<div class="cra-card" style="background:var(--bg-table-head, #f8fafc);"><p class="sub" style="margin:0;">Take at least 2 snapshots to see a delta comparison here.</p></div>`;
    }
  }
  function wireSnapshotTab() {
    const btn = document.getElementById('btnCreateSnapshot');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const label = prompt('Snapshot label?', `Snapshot ${new Date().toISOString().slice(0,10)}`);
      if (!label) return;
      Utils.setBtnLoading(btn, true, 'Snapshotting…');
      try {
        await api('POST', `/${state.profileId}/snapshots`, { label });
        await loadSnapshots();
        renderSnapshots();
        toast('Snapshot saved');
      } catch (e) { toast('Snapshot failed: ' + e.message, 4000); }
      finally { Utils.setBtnLoading(btn, false); }
    });
  }

  // ── LIBRARY MODAL (Add finding from canonical scenarios) ─────────
  function wireLibraryModal() {
    const openBtn = document.getElementById('btnLibrary');
    if (!openBtn) return;
    openBtn.addEventListener('click', openLibrary);
    document.getElementById('btnCloseLib')?.addEventListener('click', closeLibrary);
    document.getElementById('libBackdrop')?.addEventListener('click', closeLibrary);
    document.getElementById('libSearch')?.addEventListener('input', renderLibList);
    document.getElementById('libCategory')?.addEventListener('change', renderLibList);
  }
  async function openLibrary() {
    document.getElementById('libDrawer').classList.add('open');
    document.getElementById('libBackdrop').classList.add('open');
    await loadScenarioLib();
    renderLibList();
  }
  function closeLibrary() {
    document.getElementById('libDrawer').classList.remove('open');
    document.getElementById('libBackdrop').classList.remove('open');
  }
  function renderLibList() {
    const list = state.scenarioLib || [];
    const q = (document.getElementById('libSearch').value || '').toLowerCase();
    const cat = document.getElementById('libCategory').value;
    const filtered = list.filter(s =>
      (!cat || s.category === cat) &&
      (!q || s.title.toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q))
    );
    const host = document.getElementById('libList');
    if (filtered.length === 0) {
      host.innerHTML = `<p style="color:var(--text-muted); font-style:italic;">No scenarios match. Try clearing filters.</p>`;
      return;
    }
    const catColor = c => ({ technical:'#0ea5e9', people:'#dc2626', process:'#d97706', physical:'#16a34a' })[c] || '#94a3b8';
    host.innerHTML = filtered.map(s => `
      <div style="border:1px solid var(--border-color,#e2e8f0); border-radius:6px; padding:12px; margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:flex-start; gap:10px;">
          <div style="flex:1;">
            <div style="font-weight:700;">${escapeHtml(s.title)}</div>
            <div style="font-size:0.75rem; color:var(--text-muted); margin-top:3px;">
              <span style="color:${catColor(s.category)}; font-weight:600;">${escapeHtml(s.category)}</span>
              · ${escapeHtml(s.threat_source || '?')}
              · default L${s.default_likelihood}/I${s.default_impact}
            </div>
            <p style="font-size:0.85rem; margin:8px 0;">${escapeHtml((s.description || '').slice(0, 240))}${s.description && s.description.length > 240 ? '…' : ''}</p>
          </div>
          <button class="btn primary" data-key="${escapeHtml(s.key)}">+ Add</button>
        </div>
      </div>
    `).join('');
    host.querySelectorAll('button[data-key]').forEach(btn => {
      btn.addEventListener('click', () => instantiateScenario(btn.dataset.key));
    });
  }
  async function instantiateScenario(key) {
    try {
      await api('POST', `/${state.profileId}/scenarios/${encodeURIComponent(key)}/instantiate`, {});
      closeLibrary();
      await loadAndRender();
      toast('Finding added from library — edit to customize');
    } catch (e) { toast('Add failed: ' + e.message, 4000); }
  }

  // ── DELOITTE EXEC SUMMARY EDITOR ──────────────────────────────────
  function renderDeloitteExec() {
    if (!state.bundle?.report) return;
    const r = state.bundle.report;
    const setIf = (id, v) => { const el = document.getElementById(id); if (el && document.activeElement !== el) el.value = v || ''; };
    setIf('execCurrentPosture', r.exec_current_posture);
    setIf('execTopRisks',       r.exec_top_risks);
    setIf('execProgress',       r.exec_progress);
    setIf('execDecisionsNeeded',r.exec_decisions_needed);
    setIf('execSummary',        r.exec_summary);
  }
  function wireDeloitteExecSave() {
    const btn = document.getElementById('btnSaveSummary');
    if (!btn || btn.dataset.wired) return;
    btn.dataset.wired = '1';
    btn.addEventListener('click', async () => {
      Utils.setBtnLoading(btn, true, 'Saving…');
      try {
        const payload = {
          exec_summary: document.getElementById('execSummary').value,
          exec_current_posture: document.getElementById('execCurrentPosture')?.value || null,
          exec_top_risks:       document.getElementById('execTopRisks')?.value || null,
          exec_progress:        document.getElementById('execProgress')?.value || null,
          exec_decisions_needed:document.getElementById('execDecisionsNeeded')?.value || null
        };
        await api('PUT', `/${state.profileId}/report`, payload);
        toast('Exec summary saved');
      } catch (e) { toast('Save failed: ' + e.message, 4000); }
      finally { Utils.setBtnLoading(btn, false); }
    }, { once: false });
  }

  // ── ALE/SLE/ARO CALCULATOR ────────────────────────────────────────
  function wireAleCalculator() {
    const btn = document.getElementById('btnCalcAle');
    if (!btn) return;
    btn.addEventListener('click', async () => {
      const av  = parseFloat(document.getElementById('aleAV').value);
      const ef  = parseFloat(document.getElementById('aleEF').value);
      const aro = parseFloat(document.getElementById('aleARO').value);
      if (!av || isNaN(ef) || isNaN(aro)) { toast('Enter all three values', 3000); return; }
      try {
        const r = await api('POST', '/utils/ale-sle-aro', { asset_value_usd: av, exposure_factor: ef, aro });
        const fmt = n => '$' + Number(n).toLocaleString();
        const el = document.getElementById('aleResult');
        el.style.display = '';
        el.innerHTML = `
          <div style="display:grid; grid-template-columns:1fr 1fr; gap:14px;">
            <div>
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.1em; font-weight:700;">Single Loss Expectancy (SLE)</div>
              <div style="font-size:1.6rem; font-weight:800; color:var(--text-primary);">${fmt(r.sle)}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">${r.breakdown.formula_sle} = ${fmt(av)} × ${ef}</div>
            </div>
            <div>
              <div style="font-size:0.7rem; text-transform:uppercase; color:var(--text-muted); letter-spacing:0.1em; font-weight:700;">Annualized Loss Expectancy (ALE)</div>
              <div style="font-size:1.6rem; font-weight:800; color:#dc2626;">${fmt(r.ale)}</div>
              <div style="font-size:0.75rem; color:var(--text-muted);">${r.breakdown.formula_ale} = ${fmt(r.sle)} × ${aro}</div>
            </div>
          </div>`;
      } catch (e) { toast('Calculation failed: ' + e.message, 4000); }
    });
  }

  // ── EXTENDED FINDING DRAWER (slider updates + OWASP + FAIR) ──────
  const OWASP_L_FACTORS = [
    ['skill_level','Skill level'], ['motive','Motive'], ['opportunity','Opportunity'], ['size','Threat-agent size'],
    ['ease_of_discovery','Ease of discovery'], ['ease_of_exploit','Ease of exploit'], ['awareness','Awareness'], ['intrusion_detection','Intrusion detection']
  ];
  const OWASP_I_FACTORS = [
    ['loss_of_confidentiality','Loss of confidentiality'], ['loss_of_integrity','Loss of integrity'],
    ['loss_of_availability','Loss of availability'], ['loss_of_accountability','Loss of accountability'],
    ['financial_damage','Financial damage'], ['reputation_damage','Reputation damage'],
    ['non_compliance','Non-compliance'], ['privacy_violation','Privacy violation']
  ];
  function renderOwaspFactors(existing) {
    const host = document.getElementById('owaspFactors');
    if (!host) return;
    const f = existing || {};
    const row = ([k, label]) => `
      <div style="display:grid; grid-template-columns:1fr 60px 50px; gap:6px; align-items:center; margin-bottom:4px;">
        <label style="font-size:0.8rem;">${escapeHtml(label)}</label>
        <input type="range" id="ow_${k}" min="0" max="9" step="1" value="${f[k] ?? 5}">
        <span id="ow_${k}_v" style="text-align:center; font-weight:600;">${f[k] ?? 5}</span>
      </div>`;
    host.innerHTML = `
      <div style="margin-bottom:8px;"><strong style="font-size:0.8rem; color:var(--text-muted);">LIKELIHOOD FACTORS</strong></div>
      ${OWASP_L_FACTORS.map(row).join('')}
      <div style="margin:12px 0 8px;"><strong style="font-size:0.8rem; color:var(--text-muted);">IMPACT FACTORS</strong></div>
      ${OWASP_I_FACTORS.map(row).join('')}
    `;
    host.querySelectorAll('input[type=range]').forEach(sl => {
      sl.addEventListener('input', () => { document.getElementById(sl.id + '_v').textContent = sl.value; });
    });
  }
  function wireExtendedFindingDrawer() {
    // Slider value updates for residual sliders
    ['fResLikelihood', 'fResImpact'].forEach(id => {
      const sl = document.getElementById(id);
      if (!sl) return;
      sl.addEventListener('input', () => {
        document.getElementById(id + 'Val').textContent = sl.value;
      });
    });
    // Render OWASP factors when drawer opens (we observe drawer open via the existing openDrawer call)
    // Initialize empty OWASP factors UI
    renderOwaspFactors(null);
    // OWASP "Compute Severity" button
    document.getElementById('btnApplyOwasp')?.addEventListener('click', async () => {
      const findingId = document.getElementById('findingId').value;
      if (!findingId) { toast('Save the finding first, then run OWASP scoring', 3000); return; }
      const factors = {};
      [...OWASP_L_FACTORS, ...OWASP_I_FACTORS].forEach(([k]) => {
        factors[k] = parseInt(document.getElementById('ow_' + k).value);
      });
      try {
        const r = await api('PUT', `/${state.profileId}/findings/${findingId}/owasp`, { factors });
        const el = document.getElementById('owaspResult');
        el.innerHTML = `<strong>L=${r.rollup.likelihood_score} (${r.rollup.likelihood_band})</strong> · <strong>I=${r.rollup.impact_score} (${r.rollup.impact_band})</strong> → <strong style="color:#dc2626;">${r.rollup.severity}</strong>`;
      } catch (e) { toast('OWASP scoring failed: ' + e.message, 4000); }
    });
    // FAIR Monte Carlo button
    document.getElementById('btnRunFair')?.addEventListener('click', async () => {
      const findingId = document.getElementById('findingId').value;
      if (!findingId) { toast('Save the finding first, then run FAIR analysis', 3000); return; }
      const lef = {
        min:  parseFloat(document.getElementById('fairLefMin').value),
        mode: parseFloat(document.getElementById('fairLefMode').value),
        max:  parseFloat(document.getElementById('fairLefMax').value)
      };
      const lm = {
        min:  parseFloat(document.getElementById('fairLmMin').value),
        mode: parseFloat(document.getElementById('fairLmMode').value),
        max:  parseFloat(document.getElementById('fairLmMax').value)
      };
      if (isNaN(lef.min) || isNaN(lm.min)) { toast('Fill in LEF and LM values', 3000); return; }
      try {
        const r = await api('POST', `/${state.profileId}/findings/${findingId}/fair`, { lef, lm });
        const fmt = n => '$' + Math.round(n).toLocaleString();
        document.getElementById('fairResult').innerHTML =
          `<strong>ALE mean: ${fmt(r.fair.ale_mean)}</strong> · p10: ${fmt(r.fair.ale_p10)} · p90: ${fmt(r.fair.ale_p90)} (${r.fair.iterations} iterations)`;
      } catch (e) { toast('FAIR run failed: ' + e.message, 4000); }
    });
  }

  // Wrap the existing openDrawer to populate the new fields when editing
  function enhanceFindingsTable() {
    // The findings table renderer is in the original code; we re-render the table
    // (calling its existing function) to pick up new columns (Owner / Due / Status).
    // Patch: extend the original openDrawer to populate new fields.
    if (window._origOpenDrawer || typeof openDrawer !== 'function') return;
    window._origOpenDrawer = openDrawer;
    openDrawer = function (findingId) {
      window._origOpenDrawer(findingId);
      const f = findingId ? (state.bundle?.findings || []).find(x => x.id === findingId) : null;
      const set = (id, v) => { const el = document.getElementById(id); if (el) el.value = v ?? ''; };
      set('fThreatSource',     f?.threat_source);
      set('fDiscoveryMethod',  f?.discovery_method);
      set('fOwnerRole',        f?.owner_role);
      set('fOwnerName',        f?.owner_name);
      set('fReviewer',         f?.reviewer);
      set('fTargetDate',       f?.target_completion_date ? String(f.target_completion_date).slice(0, 10) : '');
      set('fEvidence',         f?.evidence_observed);
      const setSlider = (id, v) => {
        const sl = document.getElementById(id);
        const val = document.getElementById(id + 'Val');
        if (sl && v != null) { sl.value = v; if (val) val.textContent = v; }
      };
      setSlider('fResLikelihood', f?.residual_likelihood ?? Math.max(1, (f?.likelihood ?? 3) - 2));
      setSlider('fResImpact',     f?.residual_impact     ?? Math.max(1, (f?.impact ?? 3) - 1));
      // OWASP factors — load existing
      renderOwaspFactors(f?.owasp_factors || null);
      document.getElementById('owaspResult').innerHTML = f?.owasp_factors?._rollup
        ? `<strong>L=${f.owasp_factors._rollup.likelihood_score} (${f.owasp_factors._rollup.likelihood_band})</strong> · <strong>I=${f.owasp_factors._rollup.impact_score} (${f.owasp_factors._rollup.impact_band})</strong> → <strong style="color:#dc2626;">${f.owasp_factors._rollup.severity}</strong>`
        : '';
      // FAIR result
      const fq = f?.fair_quant;
      if (fq) {
        const fmt = n => '$' + Math.round(n).toLocaleString();
        document.getElementById('fairResult').innerHTML =
          `<strong>ALE mean: ${fmt(fq.ale_mean)}</strong> · p10: ${fmt(fq.ale_p10)} · p90: ${fmt(fq.ale_p90)}`;
        if (fq.inputs) {
          ['min','mode','max'].forEach(k => {
            const lefEl = document.getElementById('fairLef' + k.charAt(0).toUpperCase() + k.slice(1));
            const lmEl  = document.getElementById('fairLm'  + k.charAt(0).toUpperCase() + k.slice(1));
            if (lefEl && fq.inputs.lef) lefEl.value = fq.inputs.lef[k];
            if (lmEl  && fq.inputs.lm)  lmEl.value  = fq.inputs.lm[k];
          });
        }
      } else {
        document.getElementById('fairResult').innerHTML = '';
      }
    };

    // Also extend saveFinding to include the new fields
    if (window._origSaveFinding || typeof saveFinding !== 'function') return;
    window._origSaveFinding = saveFinding;
    saveFinding = async function () {
      // Inject the new field values into the body before the original save runs
      // by setting them on the form (the original saveFinding reads from DOM).
      // We need to intercept the actual POST/PUT to add residual + new fields.
      // Easiest: re-implement saveFinding inline using the same API.
      const id = document.getElementById('findingId').value;
      const payload = {
        title: document.getElementById('fTitle').value,
        description: document.getElementById('fDescription').value || null,
        category: document.getElementById('fCategory').value || null,
        likelihood: parseInt(document.getElementById('fLikelihood').value),
        impact: parseInt(document.getElementById('fImpact').value),
        residual_likelihood: parseInt(document.getElementById('fResLikelihood')?.value) || null,
        residual_impact:     parseInt(document.getElementById('fResImpact')?.value) || null,
        status: document.getElementById('fStatus').value || 'open',
        recommendation: document.getElementById('fRecommendation').value || null,
        control_refs: parseControlRefs(document.getElementById('fControlRefs').value),
        threat_source:        document.getElementById('fThreatSource')?.value || null,
        discovery_method:     document.getElementById('fDiscoveryMethod')?.value || null,
        owner_role:           document.getElementById('fOwnerRole')?.value || null,
        owner_name:           document.getElementById('fOwnerName')?.value || null,
        reviewer:             document.getElementById('fReviewer')?.value || null,
        target_completion_date: document.getElementById('fTargetDate')?.value || null,
        evidence_observed:    document.getElementById('fEvidence')?.value || null
      };
      try {
        if (id) await api('PUT',  `/${state.profileId}/findings/${id}`, payload);
        else    await api('POST', `/${state.profileId}/findings`, payload);
        closeDrawer();
        await loadAndRender();
        toast(id ? 'Finding updated' : 'Finding added');
      } catch (e) { toast('Save failed: ' + e.message, 4000); }
    };
    // Re-wire the save button so it calls our wrapped version (the original
    // wireDrawer registered the listener before we redefined saveFinding).
    const saveBtn = document.getElementById('btnSaveFinding');
    if (saveBtn && !saveBtn.dataset.tier13Wired) {
      // Remove the old listener by cloning the node
      const clone = saveBtn.cloneNode(true);
      saveBtn.parentNode.replaceChild(clone, saveBtn);
      clone.addEventListener('click', () => saveFinding());
      clone.dataset.tier13Wired = '1';
    }
  }
  function parseControlRefs(str) {
    if (!str) return [];
    return str.split(',').map(s => s.trim()).filter(Boolean).map(s => {
      const [framework, id] = s.split(':');
      return { framework: framework?.trim(), id: id?.trim() };
    }).filter(x => x.framework && x.id);
  }

  // === Resize handler ===
  window.addEventListener('resize', () => requestAnimationFrame(resizeAllCharts));

  // === Go ===
  document.addEventListener('DOMContentLoaded', bootstrap);
})();
