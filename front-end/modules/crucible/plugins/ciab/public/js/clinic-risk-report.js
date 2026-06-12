/**
 * clinic-risk-report.js — Standalone HTML report page.
 * Fetches the report bundle and renders every section + chart.
 *
 * Designed for "Print to PDF" via the browser's native print dialog.
 * The @media print CSS in the HTML drives page breaks + color preservation.
 */
(function () {
  'use strict';

  // ── URL parsing ────────────────────────────────────────────────────
  const match = window.location.pathname.match(/\/ciab\/clinic-risk-assessment\/([^/]+)\/report/);
  const profileId = match ? match[1] : null;
  if (!profileId) {
    document.body.innerHTML = '<div class="error">Missing profile ID in URL.</div>';
    return;
  }

  const CSF_FN = { GV: 'Govern', ID: 'Identify', PR: 'Protect', DE: 'Detect', RS: 'Respond', RC: 'Recover' };
  const charts = {};

  // ── Bootstrap ──────────────────────────────────────────────────────
  document.addEventListener('DOMContentLoaded', boot);

  async function boot() {
    let bundle;
    try {
      bundle = await fetchBundle();
    } catch (err) {
      console.error('[clinic-risk-report] fetch failed:', err);
      const el = document.getElementById('loadingOverlay');
      el.textContent = 'Failed to load report: ' + err.message;
      el.className = 'error';
      el.style.display = '';
      return;
    }
    hideLoading();

    // Render each section in isolation — if one throws, the others still
    // populate. Errors surface in the console and as a banner at the top.
    const banner = [];
    const safe = (name, fn) => {
      try { fn(); }
      catch (err) {
        console.error(`[clinic-risk-report] ${name} failed:`, err);
        banner.push(`${name}: ${err.message}`);
      }
    };

    if (typeof echarts === 'undefined') {
      banner.push('ECharts library failed to load — charts will be missing. Check that /ciab/vendor/echarts.min.js is reachable.');
    }

    safe('cover',             () => renderCover(bundle));
    safe('exec dashboard',    () => renderExecDashboard(bundle));
    safe('asset register',    () => renderAssetRegister(bundle));
    safe('heat map',          () => renderHeatmap(bundle));
    safe('findings table',    () => renderFindingsTable(bundle));
    safe('IG1',               () => renderIg1(bundle));
    safe('CSF',               () => renderCsf(bundle));
    safe('recommendations',   () => renderRecommendations(bundle));
    safe('insurance readiness',() => renderInsuranceReadiness(bundle));
    safe('snapshot delta',    () => renderSnapshotDelta(bundle));
    safe('CIS RAM',           () => renderCisRam(bundle));
    safe('detailed findings', () => renderDetailedFindings(bundle));

    document.title = `Risk Assessment — ${bundle.profile.company_name || 'Profile'}`;
    requestAnimationFrame(() => Object.values(charts).forEach(c => c && c.resize && c.resize()));

    if (banner.length) {
      const b = document.createElement('div');
      b.className = 'error no-print';
      b.style.cssText = 'position:sticky;top:50px;z-index:99;padding:10px 16px;background:#fef3c7;border:1px solid #d97706;color:#1e293b;border-radius:4px;margin:8px;font-size:0.85rem;';
      b.innerHTML = `<strong>Some sections couldn't render:</strong><br>${banner.map(s => '· ' + s.replace(/</g, '&lt;')).join('<br>')}`;
      document.body.insertBefore(b, document.querySelector('.report'));
    }
  }

  async function fetchBundle() {
    const url = `/api/clinic-risk-assessment/${encodeURIComponent(profileId)}/report-data`;
    const token = localStorage.getItem('token') || '';
    const res = await fetch(url, {
      headers: { 'Authorization': 'Bearer ' + token, 'Accept': 'application/json' },
      credentials: 'include'
    });
    if (!res.ok) {
      let msg = 'HTTP ' + res.status;
      try { const j = await res.json(); if (j.error) msg = j.error; } catch (_) {}
      throw new Error(msg);
    }
    return res.json();
  }

  function hideLoading() {
    const el = document.getElementById('loadingOverlay');
    if (el) el.style.display = 'none';
  }

  // ── Helpers ────────────────────────────────────────────────────────
  function severityClass(risk) {
    const r = Number(risk) || 0;
    if (r >= 16) return 'crit';
    if (r >= 12) return 'high';
    if (r >= 6)  return 'med';
    if (r >= 1)  return 'low';
    return 'low';
  }
  function severityLabel(risk) {
    const r = Number(risk) || 0;
    if (r >= 16) return 'CRITICAL';
    if (r >= 12) return 'HIGH';
    if (r >= 6)  return 'MEDIUM';
    if (r >= 1)  return 'LOW';
    return '—';
  }
  function severityColor(risk) {
    return { crit: '#dc2626', high: '#ea580c', med: '#d97706', low: '#0891b2' }[severityClass(risk)];
  }
  function prettyArchetype(name) {
    return String(name || '').split('-')
      .map(s => s.charAt(0).toUpperCase() + s.slice(1))
      .join(' ');
  }
  function fmtDate(d) {
    return new Date(d || Date.now()).toLocaleDateString('en-US',
      { year: 'numeric', month: 'long', day: 'numeric' });
  }
  function escapeHtml(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ── Cover ──────────────────────────────────────────────────────────
  function renderCover(b) {
    const name = b.profile.company_name || b.intake?.cover_name || 'Untitled';
    const isTraining = b.intake?.source === 'ai_simulated' || b.profile.profile_source !== 'real_intake';
    const reportId = (b.report.id || '').slice(0, 8).toUpperCase() || 'DRAFT';
    const date = fmtDate(null);
    const criticalCount = (b.findings || []).filter(f => Number(f.inherent_risk || 0) >= 16).length;
    const highCount     = (b.findings || []).filter(f => {
      const r = Number(f.inherent_risk || 0);
      return r >= 12 && r < 16;
    }).length;
    const csfAvg = (['GV','ID','PR','DE','RS','RC']
      .reduce((s, k) => s + (b.csf_scores[k] || 0), 0) / 6).toFixed(1);

    document.getElementById('coverCompany').textContent = name;
    document.getElementById('coverDate').textContent = `Prepared ${date}`;
    document.getElementById('hdrCompany').textContent = name;
    if (isTraining) document.getElementById('trainingBadge').style.display = '';

    document.getElementById('coverMeta').innerHTML = [
      ['Report ID',       reportId],
      ['Engagement Type', isTraining ? 'Training engagement' : 'Real-client engagement'],
      ['Findings',        `${(b.findings || []).length} (${criticalCount} critical · ${highCount} high)`],
      ['IG1 Coverage',    `${b.cis_coverage.score}%`],
      ['CSF Maturity',    `${csfAvg} / 5`],
      ['Prepared By',     b.report.branding?.prepared_by || 'Clinic-in-a-Box Platform']
    ].map(([k, v]) => `
      <div class="item">
        <div class="label">${escapeHtml(k)}</div>
        <div class="value">${escapeHtml(v)}</div>
      </div>
    `).join('');
  }

  // ── Executive Dashboard ────────────────────────────────────────────
  function renderExecDashboard(b) {
    const findings = b.findings || [];
    const criticalCount = findings.filter(f => Number(f.inherent_risk || 0) >= 16).length;
    const csfAvg = (['GV','ID','PR','DE','RS','RC']
      .reduce((s, k) => s + (b.csf_scores[k] || 0), 0) / 6).toFixed(1);

    const tiles = [
      { label: 'Total Findings', value: findings.length,
        sub: criticalCount ? `${criticalCount} critical` : 'none critical',
        color: criticalCount ? '#dc2626' : '#0891b2' },
      { label: 'Critical Risks', value: criticalCount,
        sub: criticalCount === 0 ? 'all under control' : 'immediate attention',
        color: criticalCount ? '#dc2626' : '#16a34a' },
      { label: 'IG1 Coverage', value: `${b.cis_coverage.score}%`,
        sub: `${b.cis_coverage.yes} of ${b.cis_coverage.total} met · ${b.cis_coverage.partial} partial`,
        color: b.cis_coverage.score >= 70 ? '#16a34a' : b.cis_coverage.score >= 40 ? '#d97706' : '#dc2626' },
      { label: 'CSF Maturity', value: csfAvg,
        sub: 'avg of 6 functions, scale 0–5',
        color: csfAvg >= 3.5 ? '#16a34a' : csfAvg >= 2 ? '#d97706' : '#dc2626' }
    ];

    document.getElementById('kpiGrid').innerHTML = tiles.map(t => `
      <div class="kpi-tile" style="--accent:${t.color}">
        <div class="label">${escapeHtml(t.label)}</div>
        <div class="value">${escapeHtml(t.value)}</div>
        <div class="sub">${escapeHtml(t.sub)}</div>
      </div>
    `).join('');

    // Posture callout
    if (b.posture && b.posture.name) {
      document.getElementById('postureCallout').innerHTML = `
        <div class="callout">
          <div class="title">Compliance Posture: ${escapeHtml(prettyArchetype(b.posture.name))}</div>
          <div class="body">${escapeHtml(b.posture.description || '')}</div>
        </div>`;
    }

    // Exec summary — prefer Deloitte 4-section if populated, else fall back
    // to the legacy single-block summary, else show pending notice.
    const deloitte = {
      posture: b.report.exec_current_posture,
      risks:   b.report.exec_top_risks,
      prog:    b.report.exec_progress,
      decis:   b.report.exec_decisions_needed
    };
    const hasDeloitte = deloitte.posture || deloitte.risks || deloitte.prog || deloitte.decis;
    const deloitteWrap = document.getElementById('execDeloitte');
    const legacyEl = document.getElementById('execSummary');
    if (hasDeloitte) {
      deloitteWrap.style.display = '';
      legacyEl.style.display = 'none';
      const setBlock = (id, text) => {
        const el = document.getElementById(id);
        el.innerHTML = text
          ? escapeHtml(text).replace(/\n\n/g, '</p><p>').replace(/^/, '<p>').replace(/$/, '</p>')
          : '<p style="color:var(--text-mute);font-style:italic">Not yet drafted.</p>';
      };
      setBlock('execCurrentPostureBody',   deloitte.posture);
      setBlock('execTopRisksBody',         deloitte.risks);
      setBlock('execProgressBody',         deloitte.prog);
      setBlock('execDecisionsNeededBody',  deloitte.decis);
    } else {
      deloitteWrap.style.display = 'none';
      legacyEl.style.display = '';
      const summary = b.report.exec_summary;
      legacyEl.innerHTML = summary
        ? escapeHtml(summary).replace(/\n\n/g, '</p><p>').replace(/^/, '<p>').replace(/$/, '</p>')
        : '<p style="color:var(--text-mute);font-style:italic">Executive summary pending — the assessor has not yet drafted it on the Report tab.</p>';
    }

    // Engagement scope
    const company = b.intake?.payload?.sections?.company || {};
    const network = b.intake?.payload?.sections?.network || {};
    const ep      = b.intake?.payload?.sections?.endpoint || {};
    const access  = b.intake?.payload?.sections?.access || {};
    const dp      = b.intake?.payload?.sections?.data || {};
    const lines = [
      ['Industry',         company.industry || '—'],
      ['Employee band',    company.employees_band || '—'],
      ['Revenue band',     company.revenue_band || '—'],
      ['HQ region',        company.region || '—'],
      ['Endpoints',        String(network.endpoint_count ?? '—')],
      ['Servers',          String(network.server_count ?? '—')],
      ['Domain mode',      (network.domain_mode || '—').toUpperCase()],
      ['Compliance scope', Array.isArray(company.frameworks) && company.frameworks.length ? company.frameworks.join(', ') : 'None declared'],
      ['Primary EDR',      ep.av_vendor || '—'],
      ['MFA coverage',     access.mfa_coverage || '—'],
      ['Backups',          dp.backup_cadence ? `${dp.backup_cadence} · offsite=${dp.offsite_backup || 'n/a'}` : '—']
    ];
    document.getElementById('scopeTable').innerHTML = lines.map(([k, v]) =>
      `<tr><td>${escapeHtml(k)}</td><td>${escapeHtml(v)}</td></tr>`).join('');
  }

  // ── Heat Map ───────────────────────────────────────────────────────
  // FINDINGS-ONLY (standard risk-assessment practice):
  // A risk heat map plots IDENTIFIED RISKS — i.e. entries on the risk
  // register — not raw control scoring. Two maps shown side-by-side:
  //   INHERENT  = today's exposure (likelihood × impact as scored)
  //   RESIDUAL  = projected exposure after recommended treatments are
  //               applied (residual_likelihood × residual_impact)
  // This is the standard NIST 800-30 / CIS RAM / ISO 27005 deliverable
  // pattern. Risks should visibly migrate from upper-right (red) to
  // lower-left (green) between the two.

  // Returns a 3×3 grid keyed by [likelihoodBand][impactBand] = count.
  function buildHeatmapGrid(findings, lField, iField) {
    const grid = Array.from({ length: 3 }, () => Array.from({ length: 3 }, () => 0));
    const bandIdx = v => v >= 4 ? 2 : v >= 2 ? 1 : 0;
    for (const f of findings) {
      const lv = Number(f[lField] || 0);
      const iv = Number(f[iField] || 0);
      if (!lv || !iv) continue;
      grid[bandIdx(lv)][bandIdx(iv)]++;
    }
    return grid;
  }

  function renderOneHeatmap(elId, grid, mapName) {
    const data = [];
    for (let li = 0; li < 3; li++) for (let ii = 0; ii < 3; ii++) {
      data.push([ii, li, grid[li][ii]]);
    }
    const maxCount = Math.max(1, ...data.map(d => d[2]));
    const el = document.getElementById(elId);
    if (!el) return null;
    const chart = echarts.init(el);
    chart.setOption({
      tooltip: { formatter: p =>
        `Likelihood ${p.value[1] + 1} × Impact ${p.value[0] + 1}: <b>${p.value[2]}</b> finding${p.value[2] === 1 ? '' : 's'}` },
      grid: { left: 100, right: 20, top: 20, bottom: 50, containLabel: false },
      xAxis: { type: 'category', name: 'Impact', nameLocation: 'middle', nameGap: 28,
        nameTextStyle: { fontWeight: 700, color: '#64748b', fontSize: 10 },
        data: ['1 Acceptable', '2 Unacceptable', '3 Catastrophic'],
        axisLabel: { fontSize: 10 }, axisLine: { show: false }, axisTick: { show: false }, splitArea: { show: false } },
      yAxis: { type: 'category', name: 'Likelihood', nameLocation: 'middle', nameGap: 78, nameRotate: 90,
        nameTextStyle: { fontWeight: 700, color: '#64748b', fontSize: 10 },
        data: ['1 Not Expected', '2 Foreseeable', '3 Expected'],
        axisLabel: { fontSize: 10 }, axisLine: { show: false }, axisTick: { show: false }, splitArea: { show: false } },
      visualMap: {
        show: false,
        min: 0, max: maxCount,
        inRange: { color: ['#e0f2fe', '#bae6fd', '#fcd34d', '#fb923c', '#dc2626', '#7f1d1d'] }
      },
      series: [{ type: 'heatmap', data,
        label: { show: true, fontSize: 14, fontWeight: 700, color: '#1e293b',
          formatter: p => p.value[2] || '' },
        itemStyle: { borderColor: '#fff', borderWidth: 2 }
      }]
    });
    return chart;
  }

  function renderHeatmap(b) {
    const findings = b.findings || [];

    // Inherent map — uses likelihood / impact (always populated)
    const inherentGrid = buildHeatmapGrid(findings, 'likelihood', 'impact');
    charts.heatmap = renderOneHeatmap('chartHeatmap', inherentGrid, 'inherent');

    // Residual map — uses residual_likelihood / residual_impact when present;
    // findings without residual scores are dropped from this view.
    const scoredResidual = findings.filter(f => f.residual_likelihood && f.residual_impact);
    const residualGrid = buildHeatmapGrid(scoredResidual, 'residual_likelihood', 'residual_impact');
    charts.heatmapResidual = renderOneHeatmap('chartHeatmapResidual', residualGrid, 'residual');

    // Comparison callout — quantify the shift
    const sumRisk = (arr, lf, ifld) => arr.reduce((s, f) => s + (Number(f[lf] || 0) * Number(f[ifld] || 0)), 0);
    const inherentTotal = sumRisk(findings, 'likelihood', 'impact');
    const residualTotal = sumRisk(scoredResidual, 'residual_likelihood', 'residual_impact');
    const reduction = inherentTotal > 0 ? Math.round(((inherentTotal - residualTotal) / inherentTotal) * 100) : 0;
    if (scoredResidual.length === findings.length && findings.length > 0 && reduction > 0) {
      const el = document.getElementById('residualSummary');
      el.style.display = '';
      el.innerHTML = `
        <div class="title">Projected risk reduction: ${reduction}%</div>
        <div class="body">
          Total inherent risk score (Σ L×I across all ${findings.length} findings): <strong>${inherentTotal}</strong>.
          After the recommended treatments in Section 06 are implemented, projected residual is <strong>${residualTotal}</strong> —
          a ${reduction}% reduction in aggregate exposure. Critical-band cells (red) should be empty or near-empty on the residual map if the treatment plan is sound.
        </div>`;
    } else if (scoredResidual.length < findings.length) {
      const el = document.getElementById('residualSummary');
      el.style.display = '';
      el.className = 'callout warn';
      el.innerHTML = `
        <div class="title">Residual scoring incomplete</div>
        <div class="body">
          Only ${scoredResidual.length} of ${findings.length} findings have residual_likelihood/residual_impact scored.
          The residual map shows the scored subset only.
        </div>`;
    }

    // Top critical cards
    const top = [...findings]
      .filter(f => Number(f.inherent_risk || 0) >= 12)
      .sort((a, b) => Number(b.inherent_risk || 0) - Number(a.inherent_risk || 0))
      .slice(0, 3);
    document.getElementById('critCards').innerHTML = top.map(f => `
      <div class="crit-card" style="border-left-color:${severityColor(f.inherent_risk)};background:rgba(${severityColor(f.inherent_risk).match(/\w\w/g).map(h => parseInt(h, 16)).join(',')},0.05)">
        <div class="meta" style="color:${severityColor(f.inherent_risk)}">${severityLabel(f.inherent_risk)} · RISK ${f.inherent_risk}</div>
        <div class="title">${escapeHtml(f.finding_code)} — ${escapeHtml(f.title)}</div>
        <div class="sub">L${f.likelihood ?? '?'} × I${f.impact ?? '?'} · ${escapeHtml(f.category || 'uncategorized')}</div>
      </div>
    `).join('') || '<p style="color:var(--text-mute);font-style:italic">No high-severity findings recorded.</p>';
  }

  // ── Findings table ─────────────────────────────────────────────────
  function renderFindingsTable(b) {
    const findings = b.findings || [];
    if (findings.length === 0) {
      document.getElementById('findingsBody').innerHTML =
        '<tr><td colspan="8" style="text-align:center;padding:20px;color:var(--text-mute);font-style:italic">No findings recorded yet.</td></tr>';
      return;
    }
    document.getElementById('findingsBody').innerHTML = findings.map(f => `
      <tr class="sev-${severityClass(f.inherent_risk)}">
        <td class="code">${escapeHtml(f.finding_code || '—')}</td>
        <td class="title">${escapeHtml(f.title || '')}</td>
        <td class="cat">${escapeHtml(f.category || '—')}</td>
        <td class="num">${f.likelihood ?? '—'}</td>
        <td class="num">${f.impact ?? '—'}</td>
        <td class="num">${f.inherent_risk ?? '—'}</td>
        <td><span class="badge ${severityClass(f.inherent_risk)}">${severityLabel(f.inherent_risk)}</span></td>
        <td>${escapeHtml((f.status || 'open').toUpperCase())}</td>
      </tr>
    `).join('');
  }

  // ── CIS IG1 compliance ─────────────────────────────────────────────
  function renderIg1(b) {
    const c = b.cis_coverage;
    document.getElementById('ig1KpiGrid').innerHTML = [
      { label: 'Coverage Score', value: `${c.score}%`, sub: `of ${c.total} safeguards`, color: '#0c234b' },
      { label: 'Met (Yes)',      value: c.yes,     sub: 'fully implemented',    color: '#16a34a' },
      { label: 'Partial',        value: c.partial, sub: 'in progress',          color: '#d97706' },
      { label: 'Not Met',        value: c.no,      sub: 'remediation required', color: '#dc2626' }
    ].map(t => `
      <div class="kpi-tile" style="--accent:${t.color}">
        <div class="label">${escapeHtml(t.label)}</div>
        <div class="value">${escapeHtml(t.value)}</div>
        <div class="sub">${escapeHtml(t.sub)}</div>
      </div>
    `).join('');

    // CIS bar chart
    const chart = echarts.init(document.getElementById('chartCis'));
    charts.cis = chart;
    chart.setOption({
      grid: { left: 80, right: 40, top: 10, bottom: 20 },
      xAxis: { type: 'value', max: c.total, splitLine: { show: true, lineStyle: { color: '#e2e8f0' } } },
      yAxis: { type: 'category', data: ['Yes', 'Partial', 'No', 'Unanswered'],
        axisLabel: { fontWeight: 600 } },
      series: [{
        type: 'bar', barWidth: 20,
        data: [
          { value: c.yes,     itemStyle: { color: '#16a34a' } },
          { value: c.partial, itemStyle: { color: '#d97706' } },
          { value: c.no,      itemStyle: { color: '#dc2626' } },
          { value: c.unknown, itemStyle: { color: '#94a3b8' } }
        ],
        label: { show: true, position: 'right', formatter: p => `${p.value} / ${c.total}` }
      }]
    });

    // Posture callout
    if (b.posture && b.posture.name) {
      document.getElementById('ig1Posture').innerHTML = `
        <div class="callout">
          <div class="title">Why this distribution? Posture: ${escapeHtml(prettyArchetype(b.posture.name))}</div>
          <div class="body">${escapeHtml(b.posture.description || 'Inconsistent posture across control families.')}</div>
        </div>`;
    }

    // Top unmet
    const unmet = b.top_unmet_safeguards || [];
    document.getElementById('topUnmet').innerHTML = unmet.length
      ? unmet.map(sg => `<li><strong>${escapeHtml(sg.num)}</strong> — ${escapeHtml(sg.name)} <em style="color:var(--text-mute)">(${escapeHtml(sg.control_name)})</em></li>`).join('')
      : '<li style="color:var(--text-mute);font-style:italic">No unmet safeguards — every IG1 control is at least partially implemented.</li>';
  }

  // ── NIST CSF Maturity ──────────────────────────────────────────────
  function renderCsf(b) {
    const scores = b.csf_scores || {};
    const fnIds = ['GV', 'ID', 'PR', 'DE', 'RS', 'RC'];

    // Radar
    const radar = echarts.init(document.getElementById('chartRadar'));
    charts.radar = radar;
    radar.setOption({
      tooltip: {},
      radar: {
        indicator: fnIds.map(id => ({ name: CSF_FN[id], max: 5 })),
        splitArea: { show: true, areaStyle: { color: ['#f8fafc', 'white'] } },
        splitLine: { lineStyle: { color: '#e2e8f0' } },
        axisLine: { lineStyle: { color: '#cbd5e1' } },
        axisLabel: { color: '#64748b' }
      },
      series: [{
        type: 'radar', symbolSize: 6,
        data: [{ value: fnIds.map(id => Number(scores[id] || 0)), name: 'Maturity',
          areaStyle: { color: 'rgba(12, 35, 75, 0.15)' },
          itemStyle: { color: '#0c234b' },
          lineStyle: { color: '#0c234b', width: 2 },
          label: { show: true, formatter: v => v.value.toFixed(1), color: '#1e293b', fontWeight: 700 }
        }]
      }]
    });

    // Function bar chart
    const colors = { GV: '#ab0520', ID: '#1e5288', PR: '#16a34a', DE: '#ea580c', RS: '#dc2626', RC: '#0891b2' };
    const bar = echarts.init(document.getElementById('chartCsf'));
    charts.csf = bar;
    bar.setOption({
      grid: { left: 70, right: 50, top: 10, bottom: 20 },
      xAxis: { type: 'value', max: 5, splitLine: { show: true, lineStyle: { color: '#e2e8f0' } } },
      yAxis: { type: 'category', data: fnIds.map(id => CSF_FN[id]), axisLabel: { fontWeight: 600 } },
      series: [{
        type: 'bar', barWidth: 18,
        data: fnIds.map(id => ({ value: Number(scores[id] || 0), itemStyle: { color: colors[id] } })),
        label: { show: true, position: 'right', formatter: p => p.value.toFixed(1) }
      }]
    });

    // Function score grid
    const ranked = fnIds.map(id => ({ id, name: CSF_FN[id], score: Number(scores[id] || 0) }));
    const minScore = Math.min(...ranked.map(r => r.score));
    const maxScore = Math.max(...ranked.map(r => r.score));
    document.getElementById('csfGrid').innerHTML = ranked.map(r => `
      <div class="csf-fn-tile ${r.score === minScore ? 'weak' : r.score === maxScore ? 'strong' : ''}">
        <div class="name">${escapeHtml(r.name)}</div>
        <div class="score">${r.score.toFixed(1)} <span style="font-size:0.7em;color:var(--text-mute);font-weight:500">/ 5</span></div>
      </div>
    `).join('');

    const weakest = ranked.sort((a, b) => a.score - b.score)[0];
    if (weakest && weakest.score < 3) {
      document.getElementById('csfWeakCallout').innerHTML = `
        <div class="callout danger">
          <div class="title">Weakest Function: ${escapeHtml(weakest.name)} (${weakest.score.toFixed(1)} / 5)</div>
          <div class="body">Prioritize controls aligned to NIST CSF "${escapeHtml(weakest.name)}" first — this is where the organization is most exposed today.</div>
        </div>`;
    }
  }

  // ── Recommendations ────────────────────────────────────────────────
  function renderRecommendations(b) {
    const recs = b.recommendations || { quickWins: [], strategic: [] };
    document.getElementById('quickWins').innerHTML = recs.quickWins.length
      ? recs.quickWins.map(r => `<li>${escapeHtml(r)}</li>`).join('')
      : '<li style="color:var(--text-mute);font-style:italic">No quick-win recommendations — the baseline controls are mostly in place.</li>';
    document.getElementById('strategic').innerHTML = recs.strategic.length
      ? recs.strategic.map(r => `<li>${escapeHtml(r)}</li>`).join('')
      : '<li style="color:var(--text-mute);font-style:italic">No strategic initiatives identified at this maturity level.</li>';
  }

  // ── CIS RAM Register + Treatment ───────────────────────────────────
  function renderCisRam(b) {
    const ram = b.cis_ram;
    if (!ram || !ram.controls || ram.controls.length === 0) return;
    document.getElementById('ramRegisterSection').style.display = '';
    document.getElementById('ramTreatmentSection').style.display = '';
    document.getElementById('ramAcceptable').textContent = ram.assessment?.acceptable_risk_score ?? 6;

    // Register grouped by control
    document.getElementById('ramRegister').innerHTML = ram.controls.map(ctrl => `
      <div class="ram-control">
        <h4>Control ${ctrl.control} — ${escapeHtml(ctrl.control_name)}
          <span class="count">(${ctrl.rows.length} safeguard${ctrl.rows.length === 1 ? '' : 's'})</span>
        </h4>
        <table class="ram">
          <thead>
            <tr>
              <th style="width:50px">#</th><th>Safeguard</th>
              <th style="width:90px">Asset</th>
              <th class="num" style="width:42px">Inh</th>
              <th class="num" style="width:42px">Res</th>
              <th class="num" style="width:62px">Reasonable</th>
              <th class="num" style="width:50px">Yr</th>
              <th style="width:80px">Status</th>
            </tr>
          </thead>
          <tbody>
            ${ctrl.rows.map(r => `
              <tr>
                <td class="num"><strong>${escapeHtml(r.safeguard_num)}</strong></td>
                <td>${escapeHtml(r.safeguard_name || '')}</td>
                <td>${escapeHtml(r.asset_class || '—')}</td>
                <td class="num">${r.inherent_risk_score ?? '—'}</td>
                <td class="num">${r.residual_risk_score ?? '—'}</td>
                <td class="num">${r.is_reasonable ? '<span class="ok">✓</span>' : '<span class="no">✗</span>'}</td>
                <td class="num">${r.implementation_year || '—'}</td>
                <td>${escapeHtml(r.status || 'open')}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `).join('');

    // Treatment plan — sort by inherent risk desc, only items not 'mitigated'
    const treatments = ram.rows
      .filter(r => r.status !== 'mitigated' && r.inherent_risk_score > 0)
      .sort((a, b) => (b.inherent_risk_score || 0) - (a.inherent_risk_score || 0));
    document.getElementById('ramTreatmentCount').textContent = treatments.length;
    document.getElementById('ramTreatment').innerHTML = treatments.length === 0
      ? '<p style="color:var(--text-mute);font-style:italic">All safeguards are either mitigated or unscored. No treatment plan needed.</p>'
      : treatments.map(r => `
          <div class="treatment-card">
            <div class="head">
              <div class="ttl"><span class="num">${escapeHtml(r.safeguard_num)}</span>${escapeHtml(r.safeguard_name || r.treatment_title || '')}</div>
              <div class="meta">
                Asset: <strong>${escapeHtml(r.asset_class || '—')}</strong> ·
                Inherent <strong>${r.inherent_risk_score ?? '—'}</strong> →
                Residual <strong>${r.residual_risk_score ?? '—'}</strong> ·
                ${r.is_reasonable ? '<span style="color:var(--ok);font-weight:700">Reasonable ✓</span>' : '<span style="color:var(--crit);font-weight:700">Not reasonable ✗</span>'} ·
                Target ${r.implementation_year || '—'} ·
                Cost ${escapeHtml(r.treatment_cost || '—')}
              </div>
            </div>
            <div class="body">
              <div class="field-label" style="font-size:0.65rem;margin-top:8px">Treatment</div>
              <div><strong>${escapeHtml(r.treatment_title || '—')}</strong></div>
              <div style="margin-top:4px">${escapeHtml(r.treatment_description || '')}</div>
              ${r.notes ? `<div class="field-label" style="font-size:0.65rem;margin-top:8px">Notes</div><div style="font-size:0.82rem;color:var(--text-mute)">${escapeHtml(r.notes)}</div>` : ''}
            </div>
          </div>
        `).join('');
  }

  // ── Detailed findings appendix ─────────────────────────────────────
  function renderDetailedFindings(b) {
    const findings = b.findings || [];
    if (findings.length === 0) {
      document.getElementById('detailedFindings').innerHTML =
        '<p style="color:var(--text-mute);font-style:italic">No findings recorded for this engagement.</p>';
      return;
    }
    const refsFmt = refs => Array.isArray(refs) && refs.length
      ? `Control refs: ${refs.map(r => `<strong>${escapeHtml(r.framework || '?')}:${escapeHtml(r.id || '?')}</strong>`).join(', ')}`
      : '';
    document.getElementById('detailedFindings').innerHTML = findings.map(f => `
      <div class="finding-card sev-${severityClass(f.inherent_risk)}">
        <div class="head">
          <div class="ttl"><span class="num">${escapeHtml(f.finding_code || '—')}</span>${escapeHtml(f.title || '')}</div>
          <span class="badge ${severityClass(f.inherent_risk)}">${severityLabel(f.inherent_risk)}</span>
        </div>
        <div class="meta-row">
          Category: <strong>${escapeHtml(f.category || '—')}</strong> ·
          Likelihood ${f.likelihood ?? '?'} × Impact ${f.impact ?? '?'} = Risk ${f.inherent_risk ?? '?'} ·
          Status: <strong>${escapeHtml((f.status || 'open').toUpperCase())}</strong>
        </div>
        ${f.description ? `<div class="field-label">Description</div><div class="field-body">${escapeHtml(f.description)}</div>` : ''}
        ${f.recommendation ? `<div class="field-label">Recommendation</div><div class="field-body">${escapeHtml(f.recommendation)}</div>` : ''}
        ${refsFmt(f.control_refs) ? `<div class="refs">${refsFmt(f.control_refs)}</div>` : ''}
      </div>
    `).join('');
  }

  // ── Asset Register (Tier 1) ────────────────────────────────────────
  function renderAssetRegister(b) {
    const assets = b.assets || [];
    if (assets.length === 0) return;  // section stays hidden if no assets
    document.getElementById('assetRegisterSection').style.display = '';
    const dcClass = c => `dc-${String(c || 'internal').toLowerCase()}`;
    document.getElementById('assetTableBody').innerHTML = assets.map(a => `
      <tr class="tier-${a.criticality_tier || 3}">
        <td><strong>${escapeHtml(a.name)}</strong>${a.hostname ? `<br><span style="color:var(--text-mute);font-size:0.75em">${escapeHtml(a.hostname)}</span>` : ''}</td>
        <td>${escapeHtml((a.asset_type || '').replace(/_/g, ' '))}</td>
        <td>${escapeHtml(a.owner_role || '—')}${a.custodian && a.custodian !== a.owner_role ? `<br><span style="color:var(--text-mute);font-size:0.75em">${escapeHtml(a.custodian)}</span>` : ''}</td>
        <td class="num"><strong>T${a.criticality_tier ?? '—'}</strong></td>
        <td class="num">${a.confidentiality ?? '—'}</td>
        <td class="num">${a.integrity ?? '—'}</td>
        <td class="num">${a.availability ?? '—'}</td>
        <td class="${dcClass(a.data_classification)}">${escapeHtml(a.data_classification || '—')}</td>
      </tr>
    `).join('');
  }

  // ── Cyber-Insurance Readiness (Tier 2) ─────────────────────────────
  const READINESS_LABELS = {
    mfa_email:           'MFA on email accounts',
    mfa_remote:          'MFA on remote / VPN access',
    mfa_privileged:      'MFA on privileged / admin accounts',
    mfa_cloud:           'MFA on cloud / SaaS sessions',
    edr_coverage_pct:    'EDR coverage across endpoints',
    immutable_backups:   'Immutable / WORM offsite backups',
    tested_restore_12mo: 'Backup restore test in last 12 months',
    ir_plan_written:     'Documented incident response plan',
    tabletop_12mo:       'Tabletop exercise in last 12 months',
    pam_in_place:        'Privileged Access Management (PAM)',
    security_training:   'Annual security awareness training',
    vuln_scanning:       'Regular vulnerability scanning program'
  };
  const READINESS_WEIGHTS = {
    mfa_email: 12, mfa_remote: 12, mfa_privileged: 14, mfa_cloud: 10,
    edr_coverage_pct: 10, immutable_backups: 8, tested_restore_12mo: 6,
    ir_plan_written: 6, tabletop_12mo: 5, pam_in_place: 6,
    security_training: 6, vuln_scanning: 5
  };
  function renderInsuranceReadiness(b) {
    const r = b.insurance_readiness;
    if (!r) return;  // hidden if no scorecard
    document.getElementById('insuranceSection').style.display = '';
    document.getElementById('insuranceScoreValue').textContent = r.readiness_score ?? '—';
    document.getElementById('insuranceTierValue').textContent = r.readiness_tier || '—';
    const tierColors = {
      'Insurable':    '#16a34a',
      'Conditional':  '#d97706',
      'Restricted':   '#ea580c',
      'Uninsurable':  '#dc2626'
    };
    const tierSub = {
      'Insurable':    'standard market — competitive premiums',
      'Conditional':  'sub-standard / restricted coverage',
      'Restricted':   'only specialist carriers will quote',
      'Uninsurable':  'declination expected — must remediate first'
    };
    const tile = document.getElementById('insuranceTierTile');
    tile.style.setProperty('--accent', tierColors[r.readiness_tier] || '#dc2626');
    document.getElementById('insuranceTierSub').textContent = tierSub[r.readiness_tier] || '';

    document.getElementById('insuranceTableBody').innerHTML = Object.keys(READINESS_LABELS).map(k => {
      const val = r[k];
      let display, statusClass;
      if (k === 'edr_coverage_pct') {
        display = (val || 0) + '%';
        statusClass = val >= 95 ? 'yes' : val >= 70 ? 'partial' : 'no';
      } else {
        display = (val || 'no').toUpperCase();
        statusClass = val === 'yes' ? 'yes' : val === 'partial' ? 'partial' : 'no';
      }
      const wt = READINESS_WEIGHTS[k];
      const earned = k === 'edr_coverage_pct'
        ? Math.round(wt * (Number(val || 0) / 100))
        : Math.round(wt * (val === 'yes' ? 1 : val === 'partial' ? 0.5 : 0));
      return `<tr>
        <td>${escapeHtml(READINESS_LABELS[k])}</td>
        <td class="status-${statusClass}">${escapeHtml(display)}</td>
        <td class="num">${earned} / ${wt}</td>
      </tr>`;
    }).join('');
  }

  // ── Snapshot delta comparison (Tier 2) ─────────────────────────────
  function renderSnapshotDelta(b) {
    const snaps = b.snapshots || [];
    if (snaps.length < 2) return;  // need at least 2 for a delta
    document.getElementById('snapshotSection').style.display = '';
    const [now, prior] = snaps;
    const dateOf = d => new Date(d).toLocaleDateString('en-US', { year:'numeric', month:'short', day:'numeric' });

    const tile = (label, nowVal, priorVal, opts = {}) => {
      const diff = (Number(nowVal) || 0) - (Number(priorVal) || 0);
      const direction = diff > 0 ? 'up' : diff < 0 ? 'down' : 'flat';
      const arrow = diff > 0 ? '▲' : diff < 0 ? '▼' : '—';
      const sign = diff > 0 ? '+' : '';
      const cls = opts.coverage ? 'coverage' : '';
      return `<div class="delta-tile ${cls}">
        <div class="label">${escapeHtml(label)}</div>
        <div class="now">${escapeHtml(String(nowVal ?? '—'))}${opts.suffix || ''}</div>
        <div class="change ${direction}">${arrow} ${sign}${diff}${opts.suffix || ''}</div>
        <div class="prior">prior: ${escapeHtml(String(priorVal ?? '—'))}${opts.suffix || ''}</div>
      </div>`;
    };

    document.getElementById('snapshotDelta').innerHTML = `
      <p style="font-size:0.8rem;color:var(--text-mute);">
        Comparing <strong>${escapeHtml(now.label)}</strong> (${dateOf(now.created_at)}) against <strong>${escapeHtml(prior.label)}</strong> (${dateOf(prior.created_at)}).
      </p>
      <div class="delta-grid">
        ${tile('Total Findings',  now.findings_total,    prior.findings_total)}
        ${tile('Critical Risks',  now.findings_critical, prior.findings_critical)}
        ${tile('IG1 Coverage',    now.ig1_coverage_pct,  prior.ig1_coverage_pct, { suffix: '%', coverage: true })}
        ${tile('Total Inherent Risk', now.total_inherent_risk, prior.total_inherent_risk)}
      </div>
      <p style="font-size:0.85rem;">
        ${now.findings_critical < prior.findings_critical
          ? `<span style="color:var(--ok);font-weight:700">✓ Reduced ${prior.findings_critical - now.findings_critical} critical risk${prior.findings_critical - now.findings_critical === 1 ? '' : 's'}</span> since the prior assessment.`
          : now.findings_critical > prior.findings_critical
          ? `<span style="color:var(--crit);font-weight:700">⚠ ${now.findings_critical - prior.findings_critical} new critical risk${now.findings_critical - prior.findings_critical === 1 ? '' : 's'}</span> emerged since the prior assessment.`
          : 'Critical-risk count unchanged.'}
        ${now.ig1_coverage_pct > prior.ig1_coverage_pct
          ? ` IG1 coverage improved by ${now.ig1_coverage_pct - prior.ig1_coverage_pct} points.`
          : ''}
      </p>
    `;
  }

  // ── Toolbar: POA&M CSV download ────────────────────────────────────
  function wireToolbarExtras() {
    const tb = document.querySelector('.toolbar');
    if (!tb) return;
    if (document.getElementById('btnDownloadPoam')) return;
    const btn = document.createElement('button');
    btn.id = 'btnDownloadPoam';
    btn.className = 'secondary';
    btn.title = 'Download a POA&M-formatted CSV of all open findings (NIST/CMMC standard)';
    btn.textContent = '⬇ POA&M CSV';
    btn.style.marginRight = '4px';
    btn.onclick = async () => {
      const url = `/api/clinic-risk-assessment/${encodeURIComponent(profileId)}/poam.csv`;
      const token = localStorage.getItem('token') || '';
      const r = await fetch(url, { headers: { 'Authorization': 'Bearer ' + token } });
      if (!r.ok) { alert('POA&M export failed: HTTP ' + r.status); return; }
      const blob = await r.blob();
      const a = document.createElement('a');
      a.href = URL.createObjectURL(blob);
      a.download = `poam-${profileId.slice(0,8)}.csv`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 1000);
    };
    // Insert before the existing "Print to PDF" button
    const printBtn = tb.querySelector('button');
    if (printBtn) tb.insertBefore(btn, printBtn);
    else tb.appendChild(btn);
  }
  // Fire after first paint
  document.addEventListener('DOMContentLoaded', () => setTimeout(wireToolbarExtras, 100));

  // ── Resize charts on window resize ─────────────────────────────────
  window.addEventListener('resize', () => {
    Object.values(charts).forEach(c => c && c.resize && c.resize());
  });
})();
