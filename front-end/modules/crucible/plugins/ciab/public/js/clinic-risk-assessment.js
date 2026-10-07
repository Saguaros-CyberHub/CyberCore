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
    registerFilters: { search: '', status: 'all', severity: 'all', sortKey: null, sortDir: 'asc' }, // Risk Register toolbar (client-side filter/sort)
    forceLightCharts: false, // temporarily true while capturing PNGs for the white-paper PDF export
  };

  const CSF_HIDE_KEY = 'cra-hide-csf'; // localStorage: '1' => hide NIST CSF charts in Overview

  const CSF_FN_ORDER = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];
  const CSF_FN_NAMES = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' };

  // University of Arizona brand palette — single source of truth for chart colors.
  const UA = {
    blue: '#0c234b', midnight: '#001c48', azurite: '#1e5288', oasis: '#378dbd',
    sky: '#81d3eb', red: '#ab0520', bloom: '#ef4056', leaf: '#70b865',
  };

  // Severity ramp shared by the heat maps, their legends, and the CSS
  // --risk-* tokens (see the <style> block). `max` is the upper bound of the
  // 1–25 L×I product covered by the band; dark variants are brightened so the
  // tiles keep their punch on the dark card surface. The bands subdivide the
  // register's riskBucket() tiers without ever contradicting them (e.g. every
  // matrix "critical" cell is also a register "critical").
  const SEVERITY_LEVELS = [
    { key: 'low',      name: 'Low',      max: 4,  light: '#2f9e6e', dark: '#35a878' },
    { key: 'guarded',  name: 'Guarded',  max: 9,  light: '#d9a514', dark: '#dfb02e' },
    { key: 'elevated', name: 'Elevated', max: 14, light: '#e07b39', dark: '#e8904f' },
    { key: 'high',     name: 'High',     max: 15, light: '#c43d4b', dark: '#d4525f' },
    { key: 'critical', name: 'Critical', max: 25, light: '#8b0015', dark: '#aa1126' },
  ];
  function severityForScore(score) {
    return SEVERITY_LEVELS.find(s => score <= s.max) || SEVERITY_LEVELS[SEVERITY_LEVELS.length - 1];
  }

  // Inline stroke SVGs for the Overview stat cards (theme-tinted via currentColor).
  const STAT_ICONS = {
    clipboard: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="8" y="2" width="8" height="4" rx="1"/><path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2"/><path d="m9 13.5 2 2 4-4"/></svg>',
    gauge:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="m12 14 4-4"/><path d="M3.34 19a10 10 0 1 1 17.32 0"/></svg>',
    shield:    '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z"/><path d="m9 12 2 2 4-4"/></svg>',
    chart:     '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><line x1="6" y1="20" x2="6" y2="16"/><line x1="12" y1="20" x2="12" y2="10"/><line x1="18" y1="20" x2="18" y2="4"/></svg>',
  };

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
    wireHero();
    wireRegisterToolbar();
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
    renderTopRisks();
    renderHero();
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
      { icon: 'clipboard', label: 'CIS RAM Scored',    value: `${ramTotals.scored} / ${ramTotals.total}`, hint: `${ramTotals.reasonable} reasonable` },
      { icon: 'gauge',     label: 'Avg Inherent Risk', value: avgRisk, hint: `${totalRows} entries, scale 1–9` },
      { icon: 'shield',    label: 'IG1 Coverage',      value: b.cis_coverage.score + '%', hint: `${b.cis_coverage.yes} yes · ${b.cis_coverage.partial} partial` },
      { icon: 'chart',     label: 'CSF Maturity',      value: csfAvg,  hint: `avg of ${csfNonZero.length} scored function${csfNonZero.length === 1 ? '' : 's'} (of 6), 0–5` },
    ];
    const host = document.getElementById('overviewStats');
    host.innerHTML = cards.map(c => `
      <div class="cra-stat-card">
        <span class="stat-icon" aria-hidden="true">${STAT_ICONS[c.icon] || ''}</span>
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

  // === Executive hero (Overview banner) ===
  // Programmatic tab switch used by the hero quick actions + checklist links.
  function switchToTab(tab) {
    document.querySelector(`.cra-tab[data-tab="${tab}"]`)?.click();
  }

  // Overall risk grade: weighted blend of (a) inverse avg inherent risk across
  // findings + CIS RAM (40%), (b) CIS IG1 coverage % (25%), (c) NIST CSF
  // maturity avg (20%), (d) insurance readiness score (15%). Weights are
  // renormalized across whichever inputs are actually present.
  function deriveOverallGrade(bundle, cisram, insurance) {
    const clamp = v => Math.max(0, Math.min(100, v));
    const parts = [];

    // (a) Inverse of average inherent risk (1–9 scale → 0–100 goodness).
    const findings = bundle?.findings || [];
    const ramRisks = [];
    for (const ctrl of (cisram?.controls || [])) {
      for (const r of (ctrl.rows || [])) {
        if (r.likelihood && (r.mission_impact || r.obligations_impact)) {
          ramRisks.push((r.likelihood || 0) * Math.max(r.mission_impact || 0, r.obligations_impact || 0));
        }
      }
    }
    const risks = [
      ...ramRisks,
      ...findings.map(f => bandTo3(f.likelihood) * bandTo3(f.impact)),
    ].filter(v => v > 0);
    if (risks.length) {
      const avg = risks.reduce((a, c) => a + c, 0) / risks.length;
      parts.push({ key: 'risk', weight: 0.40, score: clamp(((9 - avg) / 8) * 100) });
    }

    // (b) CIS IG1 coverage — counted only when at least one safeguard was answered.
    const cv = bundle?.cis_coverage;
    if (cv && cv.total > 0 && ((cv.yes || 0) + (cv.partial || 0) + (cv.no || 0)) > 0) {
      parts.push({ key: 'ig1', weight: 0.25, score: clamp(Number(cv.score) || 0) });
    }

    // (c) NIST CSF maturity (avg of scored functions, 0–5 → 0–100).
    const csf = bundle?.csf_scores || {};
    const fnScores = CSF_FN_ORDER.map(k => Number(csf[k]) || 0).filter(v => v > 0);
    if (fnScores.length) {
      const avg = fnScores.reduce((a, c) => a + c, 0) / fnScores.length;
      parts.push({ key: 'csf', weight: 0.20, score: clamp((avg / 5) * 100) });
    }

    // (d) Insurance readiness (already 0–100), when the scorecard is saved.
    if (insurance && insurance.readiness_score != null) {
      parts.push({ key: 'insurance', weight: 0.15, score: clamp(Number(insurance.readiness_score) || 0) });
    }

    if (!parts.length) return { score: null, letter: '–', tone: 'none', parts };
    const totalW = parts.reduce((a, p) => a + p.weight, 0);
    const score = Math.round(parts.reduce((a, p) => a + p.score * (p.weight / totalW), 0));
    const letter = score >= 90 ? 'A' : score >= 80 ? 'B' : score >= 70 ? 'C' : score >= 60 ? 'D' : 'F';
    const tone = score >= 80 ? 'success' : score >= 70 ? 'warning' : 'danger';
    return { score, letter, tone, parts };
  }

  // The 7 engagement milestones surfaced in the hero completeness meter.
  function computeCompleteness() {
    const b = state.bundle || {};
    const report = b.report || {};
    const ramTotals = state.cisram?.totals;
    const csf = b.csf_scores || {};
    const execDone = ['exec_summary', 'exec_current_posture', 'exec_top_risks', 'exec_progress', 'exec_decisions_needed']
      .some(k => String(report[k] || '').trim().length > 0);
    return [
      { label: 'Record at least one asset',          done: (state.assets || []).length > 0,    tab: 'assets' },
      { label: 'Log at least one finding',           done: (b.findings || []).length > 0,      tab: 'register' },
      { label: 'Score 50%+ of CIS RAM safeguards',   done: !!ramTotals && ramTotals.total > 0 && (ramTotals.scored / ramTotals.total) >= 0.5, tab: 'cisram' },
      { label: 'CSF maturity scored (auto or manual)', done: CSF_FN_ORDER.some(k => Number(csf[k]) > 0), tab: 'maturity' },
      { label: 'Insurance scorecard saved',          done: !!(state.insurance && state.insurance.readiness_score != null), tab: 'insurance' },
      { label: 'Executive summary written',          done: execDone,                            tab: 'report' },
      { label: 'Baseline snapshot taken',            done: (state.snapshots || []).length > 0,  tab: 'snapshots' },
    ];
  }

  function renderHero() {
    const hero = document.getElementById('craHero');
    if (!hero || !state.bundle) return;
    const b = state.bundle;

    // Grade chip + score
    const grade = deriveOverallGrade(b, state.cisram, state.insurance);
    const chip = document.getElementById('heroGradeChip');
    if (chip) {
      chip.textContent = grade.letter;
      chip.className = 'grade-chip grade-' + grade.tone;
    }
    const scoreEl = document.getElementById('heroGradeScore');
    if (scoreEl) scoreEl.textContent = grade.score == null ? '—' : grade.score;
    const basisNames = { risk: 'inherent risk', ig1: 'IG1 coverage', csf: 'CSF maturity', insurance: 'insurance readiness' };
    const basisEl = document.getElementById('heroGradeBasis');
    if (basisEl) {
      basisEl.textContent = grade.parts.length
        ? 'Blend of ' + grade.parts.map(p => basisNames[p.key]).join(', ')
        : 'Add findings or score safeguards to compute a grade';
    }

    // Engagement metadata (source badge lives here too — set by renderHeader)
    const companyEl = document.getElementById('heroCompany');
    if (companyEl) companyEl.textContent = b.profile?.company_name || b.intake?.cover_name || 'Untitled Engagement';
    const metaEl = document.getElementById('heroMetaLine');
    if (metaEl) {
      metaEl.textContent = [
        b.profile?.industry || 'Unspecified industry',
        b.intake ? `Intake ${b.intake.completion_percentage ?? 0}% complete` : 'No intake yet',
      ].join(' · ');
    }

    // Completeness meter + checklist
    const items = computeCompleteness();
    const done = items.filter(i => i.done).length;
    const pct = Math.round((done / items.length) * 100);
    const stepsEl = document.getElementById('heroStepsLabel');
    if (stepsEl) stepsEl.textContent = `${done} of ${items.length} steps`;
    const pctEl = document.getElementById('heroStepsPct');
    if (pctEl) pctEl.textContent = pct + '%';
    const fillEl = document.getElementById('heroMeterFill');
    if (fillEl) fillEl.style.width = pct + '%';
    const listEl = document.getElementById('heroChecklistItems');
    if (listEl) {
      listEl.innerHTML = items.map(i => i.done
        ? `<li class="done"><span class="mark">✓</span><span>${escapeHtml(i.label)}</span></li>`
        : `<li class="todo"><span class="mark">○</span><a href="#" data-goto="${i.tab}">${escapeHtml(i.label)}</a></li>`
      ).join('');
    }
  }

  function wireHero() {
    document.getElementById('btnHeroReport')?.addEventListener('click', () => switchToTab('report'));
    document.getElementById('btnHeroSnapshot')?.addEventListener('click', () => switchToTab('snapshots'));
    // Delegated: checklist items are re-rendered on every refresh.
    document.getElementById('heroChecklistItems')?.addEventListener('click', (e) => {
      const link = e.target.closest('a[data-goto]');
      if (!link) return;
      e.preventDefault();
      switchToTab(link.dataset.goto);
    });
  }

  // === Top Risks panel (Overview) ===
  function renderTopRisks() {
    const host = document.getElementById('topRisksList');
    if (!host || !state.bundle) return;
    const findings = state.bundle.findings || [];

    // Remediation progress: mitigated / total
    const mitigated = findings.filter(f => f.status === 'mitigated').length;
    const pct = findings.length ? Math.round((mitigated / findings.length) * 100) : 0;
    const remFill = document.getElementById('remediationFill');
    if (remFill) remFill.style.width = pct + '%';
    const remLabel = document.getElementById('remediationLabel');
    if (remLabel) remLabel.textContent = findings.length ? `${mitigated} of ${findings.length} mitigated (${pct}%)` : '—';

    const top = findings
      .filter(f => (f.status || 'open') === 'open')
      .slice()
      .sort((a, b) => (Number(b.inherent_risk) || 0) - (Number(a.inherent_risk) || 0))
      .slice(0, 5);

    if (!top.length) {
      host.innerHTML = findings.length
        ? `<div class="cra-empty compact"><div class="title">No open findings</div><div class="desc">Every finding on the register has been treated, accepted, or transferred.</div></div>`
        : `<div class="cra-empty compact"><div class="title">No findings logged yet</div><div class="desc">Start the register from the threat library or add a finding manually.</div><button class="btn primary" data-cta="finding" type="button">+ Add Finding</button></div>`;
      host.querySelector('[data-cta="finding"]')?.addEventListener('click', () => document.getElementById('btnAddFinding')?.click());
      return;
    }

    host.innerHTML = top.map(f => {
      const bucket = riskBucket(f.inherent_risk) || 'low';
      const due = f.target_completion_date ? new Date(f.target_completion_date).toLocaleDateString() : 'no due date';
      const owner = f.owner_name || f.owner_role || 'Unassigned';
      return `
        <div class="top-risk-row" data-id="${f.id}">
          <span class="risk-badge risk-${bucket}">${f.inherent_risk ?? '—'}</span>
          <span class="tr-code">${escapeHtml(f.finding_code || '—')}</span>
          <div class="tr-main">
            <div class="tr-title">${escapeHtml(f.title || '')}</div>
            <div class="tr-sub">${escapeHtml(owner)} · due ${escapeHtml(due)}</div>
          </div>
          <span class="status-pill status-${f.status || 'open'}">${escapeHtml(f.status || 'open')}</span>
        </div>`;
    }).join('');
    host.querySelectorAll('.top-risk-row').forEach(row => {
      row.addEventListener('click', () => openDrawer(row.dataset.id));
    });
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

  // === Theme-aware chart styling ===
  // Every option builder pulls its text/axis/grid/tooltip colors from here so
  // light and dark mode stay consistent. A MutationObserver on
  // html[data-theme] re-renders all charts when the user flips the theme.
  function isDarkTheme() {
    return !state.forceLightCharts && document.documentElement.dataset.theme === 'dark';
  }

  function chartTheme() {
    const dark = isDarkTheme();
    // The card surface color doubles as the "gap" between heat-map tiles so
    // they read as rounded chips floating on the card.
    let cardBg = '';
    if (!state.forceLightCharts) {
      try { cardBg = getComputedStyle(document.documentElement).getPropertyValue('--bg-card').trim(); } catch (_) {}
    }
    return {
      dark,
      capture: !!state.forceLightCharts,   // disables animation so getDataURL grabs a settled frame
      text:      dark ? '#e8edf6' : '#1e293b',
      textMuted: dark ? '#9aa8bd' : '#64748b',
      gridLine:  dark ? 'rgba(148,163,184,0.16)' : 'rgba(100,116,139,0.16)',
      splitAreaA: dark ? 'rgba(148,163,184,0.045)' : 'rgba(30,82,136,0.035)',
      splitAreaB: 'rgba(0,0,0,0)',
      emptyCell: dark ? 'rgba(148,163,184,0.09)' : 'rgba(100,116,139,0.08)',
      cellGap:   cardBg || (dark ? '#111c33' : '#ffffff'),
      barTrack:  dark ? 'rgba(148,163,184,0.10)' : 'rgba(100,116,139,0.08)',
      neutral:   dark ? 'rgba(148,163,184,0.45)' : 'rgba(100,116,139,0.42)',
      accent:    dark ? UA.oasis : UA.azurite,
      tooltipBg:     dark ? '#101a30' : '#ffffff',
      tooltipBorder: dark ? 'rgba(148,163,184,0.28)' : 'rgba(100,116,139,0.18)',
      tooltipText:   dark ? '#e8edf6' : '#1e293b',
      severity: (score) => { const s = severityForScore(score); return dark ? s.dark : s.light; },
    };
  }

  // Shared tooltip chrome: card-style surface that flips with the theme.
  function tooltipBase(t) {
    return {
      confine: true,
      backgroundColor: t.tooltipBg,
      borderColor: t.tooltipBorder,
      borderWidth: 1,
      padding: [10, 12],
      textStyle: { color: t.tooltipText, fontSize: 12 },
      extraCssText: 'border-radius:10px; box-shadow:0 10px 28px rgba(2,6,23,0.22); max-width:320px; white-space:normal;',
    };
  }

  // Left→right gradient for horizontal bars (declarative form — no
  // echarts.graphic dependency).
  function horizGradient(from, to) {
    return { type: 'linear', x: 0, y: 0, x2: 1, y2: 0, colorStops: [{ offset: 0, color: from }, { offset: 1, color: to }] };
  }

  // Map a 1–5 likelihood/impact to a 1–3 band — used by the Overview stat
  // tiles and the overall grade so free-form findings can be averaged on the
  // same 1–9 scale as CIS RAM tri-factor rows. (The heat maps render findings
  // at their native 5×5 resolution and do not use this.)
  // 1→1, 2→1, 3→2, 4→2, 5→3 — keeps "5" rare and central-skews 3.
  function bandTo3(v) {
    if (!v) return 0;
    return Math.min(3, Math.ceil(v / 2));
  }

  // === Risk heat maps (FINDINGS-ONLY, native 5×5) ===
  // Standard risk-assessment practice: the heat map plots IDENTIFIED RISKS
  // (entries on the risk register). CIS RAM safeguard scoring is presented
  // separately in the CIS RAM Workbook tab. Findings carry native 1–5
  // likelihood/impact scores, so the matrix renders at full 5×5 resolution.
  // Tile color encodes the severity band of the cell's L×I product (not the
  // count) — the count renders inside the tile; empty cells stay neutral so
  // the page doesn't read "all green" when nothing has been logged.
  const HEAT_L_WORDS = ['Rare', 'Unlikely', 'Possible', 'Likely', 'Almost certain'];
  const HEAT_I_WORDS = ['Minimal', 'Minor', 'Moderate', 'Major', 'Severe'];

  // Bucket findings into a 5×5 counts grid plus per-cell finding titles for
  // the tooltip. lKey/iKey select inherent vs residual fields.
  function buildHeatmapMatrix(findings, lKey, iKey) {
    const counts = Array.from({ length: 5 }, () => Array(5).fill(0));
    const titles = Array.from({ length: 5 }, () => Array.from({ length: 5 }, () => []));
    let total = 0;
    for (const f of findings) {
      const rawL = Number(f[lKey]), rawI = Number(f[iKey]);
      if (!rawL || !rawI) continue;
      const l = Math.min(5, Math.max(1, Math.round(rawL)));
      const i = Math.min(5, Math.max(1, Math.round(rawI)));
      counts[l - 1][i - 1]++;
      titles[l - 1][i - 1].push(f.title || f.finding_code || 'Untitled finding');
      total++;
    }
    return { counts, titles, total };
  }

  // Shared option builder so the inherent and residual matrices stay
  // pixel-identical in style. x = likelihood (→), y = impact (↑).
  function buildHeatmapOption(matrix, t, opts = {}) {
    const data = [];
    for (let x = 0; x < 5; x++) {
      for (let y = 0; y < 5; y++) {
        const count = matrix.counts[x][y];
        const score = (x + 1) * (y + 1);
        data.push({
          value: [x, y, count],
          itemStyle: {
            color: count > 0 ? t.severity(score) : t.emptyCell,
            borderColor: t.cellGap,
            borderWidth: 3,
            borderRadius: 6,
          },
        });
      }
    }
    return {
      animation: !t.capture,
      animationDuration: 350,
      grid: { left: 92, right: 14, top: 14, bottom: 64 },
      xAxis: {
        type: 'category', data: HEAT_L_WORDS,
        name: 'Likelihood →', nameLocation: 'middle', nameGap: 46,
        nameTextStyle: { color: t.textMuted, fontSize: 11, fontWeight: 700 },
        axisLabel: { color: t.textMuted, fontSize: 9.5, interval: 0, lineHeight: 13, formatter: (v, i) => `${i + 1}\n${v}` },
        axisTick: { show: false }, axisLine: { show: false }, splitArea: { show: false }, splitLine: { show: false },
      },
      yAxis: {
        type: 'category', data: HEAT_I_WORDS,
        name: 'Impact ↑', nameLocation: 'middle', nameGap: 76, nameRotate: 90,
        nameTextStyle: { color: t.textMuted, fontSize: 11, fontWeight: 700 },
        axisLabel: { color: t.textMuted, fontSize: 9.5, formatter: (v, i) => `${i + 1} · ${v}` },
        axisTick: { show: false }, axisLine: { show: false }, splitArea: { show: false }, splitLine: { show: false },
      },
      tooltip: Object.assign(tooltipBase(t), {
        formatter: (p) => {
          const l = p.value[0] + 1, i = p.value[1] + 1, count = p.value[2];
          const score = l * i;
          const sev = severityForScore(score);
          const head = `<div style="display:flex;align-items:center;gap:7px;font-weight:700;">` +
            `<span style="width:10px;height:10px;border-radius:3px;background:${t.severity(score)};display:inline-block;"></span>` +
            `${sev.name} · score ${score}</div>`;
          const sub = `<div style="color:${t.textMuted};font-size:11px;margin:2px 0 4px;">` +
            `${HEAT_L_WORDS[l - 1]} likelihood × ${HEAT_I_WORDS[i - 1].toLowerCase()} impact</div>`;
          const countLine = `<div><b>${count}</b> finding${count === 1 ? '' : 's'}${opts.residual ? ' after treatment' : ''}</div>`;
          const names = (matrix.titles[l - 1][i - 1] || []).slice(0, 3)
            .map(name => `<div style="font-size:11px;margin-top:3px;">– ${escapeHtml(name)}</div>`).join('');
          const more = count > 3 ? `<div style="font-size:11px;color:${t.textMuted};margin-top:3px;">+${count - 3} more</div>` : '';
          return head + sub + countLine + names + more;
        },
      }),
      series: [{
        type: 'heatmap',
        data,
        label: {
          show: true, fontSize: 13, fontWeight: 700, color: '#fff',
          textShadowBlur: 4, textShadowColor: 'rgba(0,0,0,0.30)',
          formatter: (p) => p.value[2] || '',
        },
        emphasis: { itemStyle: { shadowBlur: 10, shadowColor: 'rgba(2,6,23,0.35)' } },
      }],
    };
  }

  // Severity-chip legend rendered under each heat map (replaces the stock
  // ECharts visualMap slider).
  function renderSeverityLegend(hostId, note) {
    const host = document.getElementById(hostId);
    if (!host) return;
    const t = chartTheme();
    host.innerHTML = SEVERITY_LEVELS.map(s =>
      `<span class="legend-chip"><span class="dot" style="background:${t.dark ? s.dark : s.light}"></span>${s.name}</span>`
    ).join('') + (note ? `<span class="legend-note">${escapeHtml(note)}</span>` : '');
  }

  function renderHeatmap() {
    const c = getOrInitChart('chartHeatmap');
    if (!c || !state.bundle) return;
    const matrix = buildHeatmapMatrix(state.bundle.findings || [], 'likelihood', 'impact');
    c.setOption(buildHeatmapOption(matrix, chartTheme()), true);
    renderSeverityLegend('legendHeatmap', `${matrix.total} finding${matrix.total === 1 ? '' : 's'} plotted`);
  }

  // Residual heat map — same builder, but uses residual_likelihood /
  // residual_impact (post-treatment projection). Findings without residual
  // scoring are excluded from this view.
  function renderHeatmapResidual() {
    const c = getOrInitChart('chartHeatmapResidual');
    if (!c || !state.bundle) return;
    const all = state.bundle.findings || [];
    const scored = all.filter(f => f.residual_likelihood && f.residual_impact);
    const matrix = buildHeatmapMatrix(scored, 'residual_likelihood', 'residual_impact');
    c.setOption(buildHeatmapOption(matrix, chartTheme(), { residual: true }), true);
    renderSeverityLegend('legendHeatmapResidual', `${matrix.total} of ${all.length} finding${all.length === 1 ? '' : 's'} residual-scored`);
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

  // === NIST CSF radar ===
  function renderRadar() {
    const c = getOrInitChart('chartRadar');
    if (!c || !state.bundle) return;
    const t = chartTheme();
    const scores = state.bundle.csf_scores || {};
    const manual = state.bundle.report?.csf_scores_manual || {};
    const value = CSF_FN_ORDER.map(k => Number(scores[k]) || 0);
    // Indicator names carry the function key; the axisName formatter expands
    // them into a small-caps label with the score (✎ = manual override).
    const indicator = CSF_FN_ORDER.map(k => ({ name: k, max: 5 }));
    c.setOption({
      animation: !t.capture,
      tooltip: Object.assign(tooltipBase(t), {
        formatter: () => {
          const rows = CSF_FN_ORDER.map((k, idx) => {
            const src = (k in manual) ? 'manual' : 'auto';
            return `<div style="display:flex;justify-content:space-between;gap:18px;margin-top:2px;">` +
              `<span>${CSF_FN_NAMES[k]} <span style="color:${t.textMuted};font-size:10px;">(${src})</span></span>` +
              `<b>${value[idx].toFixed(1)} / 5</b></div>`;
          }).join('');
          return `<div style="font-weight:700;margin-bottom:4px;">NIST CSF 2.0 Maturity</div>${rows}`;
        },
      }),
      radar: {
        indicator,
        shape: 'polygon',
        radius: '62%',
        center: ['50%', '52%'],
        splitNumber: 5,
        axisName: {
          formatter: (name) => {
            const score = (Number(scores[name]) || 0).toFixed(1);
            const mark = (name in manual) ? ' ✎' : '';
            return `{fn|${(CSF_FN_NAMES[name] || name).toUpperCase()}}\n{val|${score}${mark}}`;
          },
          rich: {
            fn:  { color: t.textMuted, fontSize: 10, fontWeight: 700, align: 'center' },
            val: { color: t.text, fontSize: 12, fontWeight: 700, align: 'center', padding: [3, 0, 0, 0] },
          },
        },
        splitArea: { show: true, areaStyle: { color: [t.splitAreaA, t.splitAreaB] } },
        splitLine: { lineStyle: { color: t.gridLine } },
        axisLine: { lineStyle: { color: t.gridLine } },
      },
      series: [{
        type: 'radar',
        symbol: 'circle',
        symbolSize: 6,
        data: [{
          value, name: 'Maturity',
          areaStyle: {
            // Azurite → transparent wash so the polygon stays readable over the grid.
            color: {
              type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
              colorStops: [
                { offset: 0, color: t.dark ? 'rgba(55,141,189,0.42)' : 'rgba(30,82,136,0.32)' },
                { offset: 1, color: t.dark ? 'rgba(55,141,189,0.06)' : 'rgba(30,82,136,0.04)' },
              ],
            },
          },
          lineStyle: { color: t.accent, width: 2.5 },
          itemStyle: { color: t.accent, borderColor: t.cellGap, borderWidth: 2 },
        }],
      }],
    }, true);
    renderRadarLegend(manual);
  }

  // Legend row under the radar: series swatch + auto/manual provenance.
  function renderRadarLegend(manual) {
    const host = document.getElementById('legendRadar');
    if (!host) return;
    const t = chartTheme();
    const manualCount = CSF_FN_ORDER.filter(k => k in manual).length;
    host.innerHTML =
      `<span class="legend-chip"><span class="dot" style="background:${t.accent};border-radius:999px;"></span>Maturity (0–5)</span>` +
      (manualCount
        ? `<span class="legend-chip">✎ ${manualCount} manual override${manualCount === 1 ? '' : 's'} — rest auto-derived from IG1</span>`
        : `<span class="legend-chip" style="font-weight:500;">All scores auto-derived from IG1 intake</span>`) +
      `<span class="legend-note">Outer ring = 5.0 (optimized)</span>`;
  }

  // === CIS coverage bars ===
  function renderCisBars() {
    const c = getOrInitChart('chartCis');
    if (!c || !state.bundle) return;
    const t = chartTheme();
    const cv = state.bundle.cis_coverage || {};
    const total = cv.total || 0;
    const pct = v => total ? Math.round(((v || 0) / total) * 100) : 0;
    // UA-blue gradient for implemented; Arizona Red reserved for the gap row.
    const rows = [
      { label: 'Yes',        value: cv.yes || 0,     color: horizGradient(UA.azurite, UA.oasis),  hint: 'Safeguard reported as implemented on intake' },
      { label: 'Partial',    value: cv.partial || 0, color: horizGradient('#b58410', '#d9a514'),  hint: 'Partially implemented — counts half toward coverage' },
      { label: 'No',         value: cv.no || 0,      color: horizGradient(UA.red, UA.bloom),      hint: 'Not implemented — these gaps drive findings' },
      { label: 'Unanswered', value: cv.unknown || 0, color: t.neutral,                            hint: 'Not answered on intake — treat as unknown risk' },
    ];
    c.setOption({
      animation: !t.capture,
      grid: { left: 92, right: 70, top: 14, bottom: 28 },
      tooltip: Object.assign(tooltipBase(t), {
        formatter: (p) => {
          const r = rows[p.dataIndex];
          return `<div style="font-weight:700;">${r.label}</div>` +
            `<div style="margin-top:2px;"><b>${r.value}</b> of ${total} safeguards · ${pct(r.value)}%</div>` +
            `<div style="color:${t.textMuted};font-size:11px;margin-top:2px;">${r.hint}</div>`;
        },
      }),
      xAxis: {
        type: 'value', max: total || 1,
        axisLabel: { color: t.textMuted, fontSize: 10 },
        splitLine: { lineStyle: { color: t.gridLine } },
        axisLine: { show: false }, axisTick: { show: false },
      },
      yAxis: {
        type: 'category', inverse: true, data: rows.map(r => r.label),
        axisLabel: { color: t.textMuted, fontSize: 11, fontWeight: 600 },
        axisLine: { show: false }, axisTick: { show: false },
      },
      series: [{
        type: 'bar',
        barWidth: 20,
        showBackground: true,
        backgroundStyle: { color: t.barTrack, borderRadius: [0, 10, 10, 0] },
        data: rows.map(r => ({ value: r.value, itemStyle: { color: r.color, borderRadius: [0, 10, 10, 0] } })),
        label: { show: true, position: 'right', color: t.text, fontWeight: 700, fontSize: 11, formatter: (p) => `${p.value} · ${pct(p.value)}%` },
      }],
    }, true);
  }

  // === CSF function score bars ===
  function renderCsfBars() {
    const c = getOrInitChart('chartCsf');
    if (!c || !state.bundle) return;
    const t = chartTheme();
    const scores = state.bundle.csf_scores || {};
    const manual = state.bundle.report?.csf_scores_manual || {};
    const vals = CSF_FN_ORDER.map(k => Number(scores[k]) || 0);
    c.setOption({
      animation: !t.capture,
      grid: { left: 92, right: 60, top: 14, bottom: 28 },
      tooltip: Object.assign(tooltipBase(t), {
        formatter: (p) => {
          const k = CSF_FN_ORDER[p.dataIndex];
          const v = vals[p.dataIndex];
          const src = (k in manual) ? 'manual override' : 'auto-derived from IG1';
          const gap = (v > 0 && v < 2)
            ? `<div style="color:${UA.bloom};font-size:11px;font-weight:600;margin-top:2px;">Priority gap — below 2.0</div>` : '';
          return `<div style="font-weight:700;">${CSF_FN_NAMES[k]} (${k})</div>` +
            `<div style="margin-top:2px;"><b>${v.toFixed(1)}</b> / 5 maturity</div>` +
            `<div style="color:${t.textMuted};font-size:11px;margin-top:2px;">${src}</div>` + gap;
        },
      }),
      xAxis: {
        type: 'value', max: 5, interval: 1,
        axisLabel: { color: t.textMuted, fontSize: 10 },
        splitLine: { lineStyle: { color: t.gridLine } },
        axisLine: { show: false }, axisTick: { show: false },
      },
      yAxis: {
        type: 'category', inverse: true, data: CSF_FN_ORDER.map(k => CSF_FN_NAMES[k]),
        axisLabel: { color: t.textMuted, fontSize: 11, fontWeight: 600 },
        axisLine: { show: false }, axisTick: { show: false },
      },
      series: [{
        type: 'bar',
        barWidth: 16,
        showBackground: true,
        backgroundStyle: { color: t.barTrack, borderRadius: [0, 8, 8, 0] },
        data: vals.map(v => ({
          value: v,
          itemStyle: {
            // Arizona Red accent only for clearly failing functions (< 2.0).
            color: (v > 0 && v < 2) ? horizGradient(UA.red, UA.bloom) : horizGradient(UA.azurite, UA.oasis),
            borderRadius: [0, 8, 8, 0],
          },
        })),
        label: {
          show: true, position: 'right', color: t.text, fontWeight: 700, fontSize: 11,
          formatter: (p) => `${p.value.toFixed(1)}${(CSF_FN_ORDER[p.dataIndex] in manual) ? ' ✎' : ''}`,
        },
      }],
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
      `<span class="pill" style="background:var(--primary,#0c234b);color:#fff;">IG1 Coverage ${cv.score != null ? cv.score + '%' : '—'}</span>` +
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

  // Rebuild every visualization with fresh chartTheme() colors (options bake
  // colors in, so a resize alone isn't enough), then re-fit.
  function rerenderAllVisuals() {
    if (!state.bundle) return;
    renderHeatmap();
    renderHeatmapResidual();
    renderRadar();
    renderCisBars();
    renderCsfBars();
    requestAnimationFrame(resizeAllCharts);
  }

  // Watch html[data-theme] so charts and HTML legends restyle the moment the
  // user toggles light/dark mode.
  new MutationObserver((muts) => {
    if (muts.some(m => m.attributeName === 'data-theme')) rerenderAllVisuals();
  }).observe(document.documentElement, { attributes: true, attributeFilter: ['data-theme'] });

  // === Findings table ===
  function riskBucket(r) {
    if (!r) return '';
    if (r >= 16) return 'critical';
    if (r >= 10) return 'high';
    if (r >= 5)  return 'medium';
    return 'low';
  }

  // Status pills shown in the register toolbar (key → label).
  const REGISTER_STATUSES = [['all', 'All'], ['open', 'Open'], ['mitigated', 'Mitigated'], ['accepted', 'Accepted'], ['transferred', 'Transferred']];

  // Apply the register toolbar's filter + sort state over state.bundle.findings.
  function getRegisterRows() {
    const f = state.registerFilters;
    const all = state.bundle?.findings || [];
    let rows = all.filter(x => {
      if (f.status !== 'all' && (x.status || 'open') !== f.status) return false;
      if (f.severity !== 'all' && riskBucket(x.inherent_risk) !== f.severity) return false;
      if (f.search) {
        const q = f.search.toLowerCase();
        const hay = [x.finding_code, x.title, x.owner_name, x.owner_role]
          .map(v => String(v || '').toLowerCase()).join(' ');
        if (!hay.includes(q)) return false;
      }
      return true;
    });
    if (f.sortKey) {
      const dir = f.sortDir === 'desc' ? -1 : 1;
      const getters = {
        code:   x => String(x.finding_code || '').toLowerCase(),
        title:  x => String(x.title || '').toLowerCase(),
        risk:   x => x.inherent_risk == null ? null : Number(x.inherent_risk),
        due:    x => x.target_completion_date ? new Date(x.target_completion_date).getTime() : null,
        status: x => String(x.status || 'open'),
      };
      const get = getters[f.sortKey];
      if (get) {
        rows = rows.slice().sort((a, b) => {
          const va = get(a), vb = get(b);
          if (va == null && vb == null) return 0;
          if (va == null) return 1;  // missing values always sort last
          if (vb == null) return -1;
          return va < vb ? -dir : va > vb ? dir : 0;
        });
      }
    }
    return rows;
  }

  function renderRegisterPills() {
    const host = document.getElementById('regStatusPills');
    if (!host) return;
    const all = state.bundle?.findings || [];
    const counts = { all: all.length, open: 0, mitigated: 0, accepted: 0, transferred: 0 };
    for (const x of all) {
      const s = x.status || 'open';
      if (counts[s] != null) counts[s]++;
    }
    const active = state.registerFilters.status;
    host.innerHTML = REGISTER_STATUSES.map(([k, label]) =>
      `<button type="button" class="filter-pill ${active === k ? 'active' : ''}" data-status="${k}" aria-pressed="${active === k}">${label}<span class="pill-count">${counts[k] ?? 0}</span></button>`
    ).join('');
  }

  function updateRegisterSortIndicators() {
    const f = state.registerFilters;
    document.querySelectorAll('#findingsTable th.sortable').forEach(th => {
      const ind = th.querySelector('.sort-ind');
      if (!ind) return;
      ind.textContent = f.sortKey === th.dataset.sort ? (f.sortDir === 'asc' ? '▲' : '▼') : '';
    });
  }

  // One-time wiring for the register toolbar; pill + header clicks are
  // delegated so re-renders don't need to re-bind.
  function wireRegisterToolbar() {
    const search = document.getElementById('regSearch');
    search?.addEventListener('input', () => {
      state.registerFilters.search = search.value.trim();
      renderFindingsTable();
    });
    document.getElementById('regSeverity')?.addEventListener('change', (e) => {
      state.registerFilters.severity = e.target.value;
      renderFindingsTable();
    });
    document.getElementById('regStatusPills')?.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-status]');
      if (!btn) return;
      state.registerFilters.status = btn.dataset.status;
      renderFindingsTable();
    });
    document.querySelector('#findingsTable thead')?.addEventListener('click', (e) => {
      const th = e.target.closest('th.sortable');
      if (!th) return;
      const f = state.registerFilters;
      if (f.sortKey === th.dataset.sort) f.sortDir = f.sortDir === 'asc' ? 'desc' : 'asc';
      else { f.sortKey = th.dataset.sort; f.sortDir = 'asc'; }
      renderFindingsTable();
    });
  }

  function clearRegisterFilters() {
    state.registerFilters.search = '';
    state.registerFilters.status = 'all';
    state.registerFilters.severity = 'all';
    const s = document.getElementById('regSearch');
    if (s) s.value = '';
    const sev = document.getElementById('regSeverity');
    if (sev) sev.value = 'all';
    renderFindingsTable();
  }

  function renderFindingsTable() {
    const all = state.bundle.findings || [];
    const rows = getRegisterRows();
    const filtered = rows.length !== all.length;
    document.getElementById('registerCount').textContent =
      all.length === 0 ? 'No findings yet.'
        : filtered ? `${rows.length} of ${all.length} finding${all.length === 1 ? '' : 's'} shown`
        : `${all.length} finding${all.length === 1 ? '' : 's'}`;

    renderRegisterPills();
    updateRegisterSortIndicators();

    const tbody = document.getElementById('findingsTbody');
    if (all.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9"><div class="cra-empty">
        <div class="title">No findings yet</div>
        <div class="desc">Document your first risk — add one manually or instantiate a scenario from the threat library.</div>
        <button class="btn primary" data-cta="finding" type="button">+ Add Finding</button>
      </div></td></tr>`;
      tbody.querySelector('[data-cta="finding"]')?.addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('btnAddFinding')?.click();
      });
      return;
    }
    if (rows.length === 0) {
      tbody.innerHTML = `<tr><td colspan="9"><div class="cra-empty">
        <div class="title">No findings match the current filters</div>
        <button class="btn" data-cta="clear" type="button">Clear filters</button>
      </div></td></tr>`;
      tbody.querySelector('[data-cta="clear"]')?.addEventListener('click', (e) => {
        e.stopPropagation();
        clearRegisterFilters();
      });
      return;
    }
    tbody.innerHTML = rows.map(f => `
      <tr data-id="${f.id}">
        <td><strong>${escapeHtml(f.finding_code || '')}</strong></td>
        <td class="td-title">${escapeHtml(f.title || '')}</td>
        <td>${escapeHtml(f.category || '—')}</td>
        <td class="ta-num">${f.likelihood ?? '—'}</td>
        <td class="ta-num">${f.impact ?? '—'}</td>
        <td class="ta-num">${f.inherent_risk != null ? `<span class="risk-badge risk-${riskBucket(f.inherent_risk)}">${f.inherent_risk}</span>` : '—'}</td>
        <td>${escapeHtml(f.owner_name || f.owner_role || '—')}</td>
        <td>${f.target_completion_date ? new Date(f.target_completion_date).toLocaleDateString() : '—'}</td>
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
    if (row.is_reasonable === true)  return '<span title="Treatment residual ≤ acceptable" style="color:var(--risk-low, #2f9e6e);font-weight:700;">✓</span>';
    if (row.is_reasonable === false) return '<span title="Treatment residual > acceptable — not yet reasonable" style="color:var(--risk-high, #c43d4b);font-weight:700;">✗</span>';
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
      renderHero();
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
      renderHero();
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
    // The PDF composites charts onto white paper. If the dashboard is in dark
    // mode, re-render with the light palette (and animations off) for the
    // capture, then restore — otherwise light text vanishes on the page.
    const wasDark = document.documentElement.dataset.theme === 'dark';
    if (wasDark) { state.forceLightCharts = true; rerenderAllVisuals(); }
    try {
      for (const [k, id] of Object.entries(map)) {
        const c = state.charts[id];
        if (!c) continue;
        try {
          out[k] = c.getDataURL({ type: 'png', pixelRatio: 2, backgroundColor: '#ffffff' });
        } catch (e) {
          console.warn('chart capture failed for', id, e);
        }
      }
    } finally {
      if (wasDark) { state.forceLightCharts = false; rerenderAllVisuals(); }
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
      renderHero(); // refresh grade + completeness now that assets/insurance/snapshots are in
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
        renderHero();
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
      tbody.innerHTML = `<tr><td colspan="6"><div class="cra-empty">
        <div class="title">No assets recorded yet</div>
        <div class="desc">Every risk should trace back to an asset — start with the crown jewels, or generate the answer key for AI-populated assets.</div>
        <button class="btn primary" data-cta="asset" type="button">+ Add Asset</button>
      </div></td></tr>`;
      tbody.querySelector('[data-cta="asset"]')?.addEventListener('click', (e) => {
        e.stopPropagation();
        document.getElementById('btnAddAsset')?.click();
      });
      return;
    }
    const dcClass = c => `dc-${String(c || 'internal').toLowerCase()}`;
    // Tier accent: crown jewels in Arizona Red, important in amber, standard in Oasis.
    const tierColor = t => ({ 1: UA.red, 2: '#b58410', 3: UA.oasis })[t] || '#94a3b8';
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
      renderHero();
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
      renderHero();
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
        `<button type="button" class="ins-opt ${cur === val ? 'active' : ''}" data-k="${c.k}" data-v="${val}" style="padding:4px 12px; border:1px solid ${cur === val ? color : 'var(--border-color,#e2e8f0)'}; background:${cur === val ? color : 'var(--bg-card, white)'}; color:${cur === val ? 'white' : 'var(--text-primary)'}; border-radius:4px; cursor:pointer; font-size:0.8rem; font-weight:600;">${lbl}</button>`;
      return `<div style="display:flex; align-items:center; gap:8px; padding:8px 0; border-bottom:1px solid var(--border-color,#e2e8f0);">
        <div style="flex:1;">${escapeHtml(c.label)} <small style="color:var(--text-muted);">(${c.weight} pts)</small></div>
        ${optBtn('yes', 'YES', 'var(--risk-low, #2f9e6e)')}
        ${optBtn('partial', 'PARTIAL', 'var(--risk-medium, #b58410)')}
        ${optBtn('no', 'NO', 'var(--risk-high, #c43d4b)')}
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
    const tierColors = { 'Insurable': '#2f9e6e', 'Conditional': '#b58410', 'Restricted': '#e07b39', 'Uninsurable': UA.red };
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
        renderHero();
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
        renderHero();
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
    const catColor = c => ({ technical: UA.azurite, people: UA.red, process: '#b58410', physical: '#2f9e6e' })[c] || '#94a3b8';
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
              <div style="font-size:1.6rem; font-weight:800; color:var(--risk-high, #c43d4b);">${fmt(r.ale)}</div>
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
        el.innerHTML = `<strong>L=${r.rollup.likelihood_score} (${r.rollup.likelihood_band})</strong> · <strong>I=${r.rollup.impact_score} (${r.rollup.impact_band})</strong> → <strong style="color:var(--risk-high, #c43d4b);">${r.rollup.severity}</strong>`;
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
        ? `<strong>L=${f.owasp_factors._rollup.likelihood_score} (${f.owasp_factors._rollup.likelihood_band})</strong> · <strong>I=${f.owasp_factors._rollup.impact_score} (${f.owasp_factors._rollup.impact_band})</strong> → <strong style="color:var(--risk-high, #c43d4b);">${f.owasp_factors._rollup.severity}</strong>`
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
