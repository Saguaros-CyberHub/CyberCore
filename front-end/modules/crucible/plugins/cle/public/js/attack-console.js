/**
 * ============================================================================
 * CLE — CYBR 400 Attack Console
 * ============================================================================
 * Drives the Attack Console tab on the course detail page: pick a MITRE
 * technique, tactic or attack chain, choose who gets it, fire it into every
 * student lane at the same moment, then watch what each lane did with it.
 *
 * DEPENDS ON GLOBALS from courses.html's inline <script>: api(), escHtml(),
 * escAttr(), toast(), currentCourseId. The <script> tag for this file MUST come
 * after that block — placed before it, `currentCourseId` is not yet defined.
 * (Same contract roster-import.js documents.)
 *
 * WHY LANE SELECTION IS OPT-OUT
 * The picker starts with every lane ticked and sends only the EXCLUSIONS. A
 * lane deployed between opening this tab and pressing Launch is then included
 * by default. The opposite — sending an explicit include list — would silently
 * leave that student out of the exercise, which is the failure nobody notices
 * until grading.
 *
 * WHY THE COUNTDOWN USES SERVER TIME
 * /status returns server_time alongside scheduled_start_at, and the countdown
 * is computed from the offset between that and the browser clock. An
 * instructor's laptop being a minute off would otherwise show a countdown that
 * disagrees with when the lanes actually fire.
 */

/* global api, escHtml, escAttr, toast, currentCourseId */

(function () {
  'use strict';

  const POLL_MS = 2000;

  let catalog = null;
  let targets = [];
  let excluded = new Set();
  let activeRunId = null;
  let pollTimer = null;
  let countdownTimer = null;
  let serverOffsetMs = 0;      // serverTime - browserTime
  let loadedForCourse = null;
  let mode = 'technique';      // technique | tactic | chain
  let selectedId = null;
  let search = '';
  let tacticFilter = '';

  // ---- helpers ------------------------------------------------------------

  const el = (id) => document.getElementById(id);
  const root = () => el('attackConsoleContent');

  function fmtDuration(sec) {
    if (!sec) return '—';
    const h = Math.floor(sec / 3600);
    const m = Math.floor((sec % 3600) / 60);
    const s = sec % 60;
    return [h ? h + 'h' : '', m ? m + 'm' : '', s ? s + 's' : ''].join('') || '0s';
  }

  function volumeBadge(v) {
    const colour = v === 'high' ? '#2f855a' : v === 'medium' ? '#b7791f' : '#718096';
    const label = v === 'high' ? 'high yield' : v === 'medium' ? 'medium yield' : 'low yield';
    return `<span style="font-size:.7rem;padding:.1rem .4rem;border-radius:3px;background:${colour};color:#fff;">${label}</span>`;
  }

  // Replaces the yield badge rather than sitting beside it.
  //
  // expected_volume is documented in the catalog as "an estimate read off the
  // matcher source, not a measurement" -- a guess at how many lines a keyword
  // filter happens to hit. Once a playbook drives the technique that stops being
  // a guess: the count is the sum of its steps. Showing both would put two
  // near-inverse claims in adjacent columns ("high yield" means imprecise
  // keywords, which is the opposite of high fidelity).
  function yieldCell(t) {
    if (t.fidelity !== 'high' || t.expected_events == null) return volumeBadge(t.expected_volume);
    return `<span style="font-size:.7rem;padding:.1rem .4rem;border-radius:3px;background:#2b6cb0;color:#fff;"
                  title="Scripted playbook — this is the exact number of events, not an estimate">
              ${escHtml(String(t.expected_events))} events
            </span>`;
  }

  /** Durations a selection can honestly run in. */
  function allowedDuration(sel, seconds) {
    return !sel || sel.min_seconds == null || seconds >= sel.min_seconds;
  }

  const STATUS_COLOURS = {
    pending: '#718096', skipped: '#a0aec0', dispatching: '#3182ce',
    scheduled: '#805ad5', running: '#2b6cb0', completed: '#2f855a',
    failed: '#c53030', aborted: '#975a16', unknown: '#4a5568',
  };

  function statusChip(status) {
    return `<span style="font-size:.72rem;padding:.15rem .45rem;border-radius:3px;`
      + `background:${STATUS_COLOURS[status] || '#718096'};color:#fff;">${escHtml(status)}</span>`;
  }

  // ---- rendering ----------------------------------------------------------

  function renderShell() {
    const chosen = currentSelection();
    root().innerHTML = `
      <div class="info-box">
        <p><strong>How this works.</strong> Each student's Rocky sensor runs
           <code>log-generator</code>. Launching fires the same command on every lane at the
           same moment, and the events land in that student's own ELK stack.</p>
        <p style="margin-top:.5rem;"><strong>Two kinds of technique.</strong>
           A <span style="padding:.05rem .3rem;border-radius:3px;background:#2b6cb0;color:#fff;font-size:.72rem;">N&nbsp;events</span>
           badge means a scripted playbook: real technique behaviour on the right log sources,
           one coherent adversary, and exactly that many events. A
           ${volumeBadge('medium')} badge means the older keyword filter — it narrows the
           ordinary generated stream to entries whose text happens to match, so what you get
           varies a lot. Attack <em>chains</em> are scripted multi-stage campaigns.</p>
        <p style="margin-top:.5rem;"><strong>Nothing labels an event as the attack.</strong>
           Scripted runs use the same log sources, hosts and accounts as ordinary traffic, and
           benign traffic carries MITRE labels too. Finding the attack is analysis, not a
           filter — which is the point.</p>
      </div>

      <div style="display:flex;gap:.5rem;margin:1rem 0;">
        <button class="btn ${mode === 'technique' ? 'btn-primary' : 'btn-secondary'}"
                onclick="CleAttack.setMode('technique')">Techniques</button>
        <button class="btn ${mode === 'tactic' ? 'btn-primary' : 'btn-secondary'}"
                onclick="CleAttack.setMode('tactic')">Tactics</button>
        <button class="btn ${mode === 'chain' ? 'btn-primary' : 'btn-secondary'}"
                onclick="CleAttack.setMode('chain')">Attack Chains</button>
        <span style="flex:1"></span>
        <button class="btn btn-secondary" onclick="CleAttack.refreshTargets()">↻ Refresh lanes</button>
        <button class="btn btn-secondary" id="acReclaimBtn" onclick="CleAttack.reclaim()"
                title="Delete rotated logs, vacuum the journal, and claim any unused disk on every sensor. Live logs are never touched.">Free disk space</button>
      </div>
      <div id="acReclaim"></div>

      <div id="acPicker"></div>

      <div style="margin:1.25rem 0;padding:1rem;border:1px solid var(--border,#ddd);border-radius:6px;">
        <div style="display:flex;gap:1.5rem;align-items:flex-end;flex-wrap:wrap;">
          <div>
            <label style="display:block;font-size:.8rem;color:var(--text-secondary);">Duration</label>
            <select id="acDuration" ${mode === 'chain' ? 'disabled' : ''}
                    style="padding:.4rem;min-width:9rem;">
              ${[[300, '5 minutes'], [900, '15 minutes'], [1800, '30 minutes'],
                 [3600, '1 hour'], [7200, '2 hours']].map(([secs, label]) => {
                   // A playbook refuses a duration shorter than its own bursts,
                   // and it is right to: compressing a 90-second brute force
                   // into 20 seconds is not a faster brute force, and
                   // truncating it loses the successful logon at the end.
                   // Disable it here so the instructor finds out before
                   // launching rather than lane by lane.
                   const off = !allowedDuration(chosen, secs);
                   const sel = secs === 1800 && !off ? 'selected' : '';
                   return `<option value="${secs}" ${off ? 'disabled' : ''} ${sel}>`
                        + `${label}${off ? ' — too short for this technique' : ''}</option>`;
                 }).join('')}
            </select>
            ${mode === 'chain'
              ? `<div style="font-size:.72rem;color:var(--text-secondary);margin-top:.25rem;max-width:16rem;">
                   Chains run their own scripted length${chosen ? ` — about ${chosen.estimated_minutes} minutes` : ''}.
                 </div>`
              : ''}
          </div>
          <div>
            <label style="display:block;font-size:.8rem;color:var(--text-secondary);">Selected</label>
            <div id="acSelected" style="font-weight:600;padding:.4rem 0;">
              ${chosen ? escHtml(chosen.name || chosen.id) : '<span style="color:var(--text-secondary);font-weight:400;">nothing yet</span>'}
            </div>
          </div>
          <span style="flex:1"></span>
          <button class="btn btn-primary" id="acLaunchBtn" onclick="CleAttack.launch()"
                  ${chosen ? '' : 'disabled'}>Launch to selected lanes</button>
        </div>
      </div>

      <h3 style="margin-top:1.5rem;">Lanes</h3>
      <div id="acTargets"></div>

      <div id="acRun" style="margin-top:1.5rem;"></div>
    `;
    renderPicker();
    renderTargets();
  }

  function currentSelection() {
    if (!catalog || !selectedId) return null;
    if (mode === 'chain') return catalog.chains.find((c) => c.key === selectedId) || null;
    if (mode === 'tactic') return catalog.tactics.find((t) => t.id === selectedId) || null;
    return catalog.techniques.find((t) => t.id === selectedId) || null;
  }

  function renderPicker() {
    const box = el('acPicker');
    if (!box || !catalog) return;

    if (mode === 'chain') {
      box.innerHTML = `<div style="display:grid;gap:.75rem;grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));">`
        + catalog.chains.map((c) => `
          <div onclick="CleAttack.select('${escAttr(c.key)}')"
               style="cursor:pointer;padding:.85rem;border-radius:6px;border:2px solid ${selectedId === c.key ? 'var(--accent,#3182ce)' : 'var(--border,#ddd)'};">
            <div style="font-weight:600;">${escHtml(c.name)}</div>
            <div style="font-size:.75rem;color:var(--text-secondary);margin:.25rem 0;">
              ${escHtml(c.category)} · ${escHtml(c.difficulty)} · ~${c.estimated_minutes} min ·
              ${c.techniques.length} techniques
            </div>
            <div style="font-size:.8rem;">${escHtml(c.description)}</div>
          </div>`).join('')
        + `</div>`;
      return;
    }

    if (mode === 'tactic') {
      box.innerHTML = `<div style="display:grid;gap:.4rem;grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));">`
        + catalog.tactics.map((t) => `
          <div onclick="CleAttack.select('${escAttr(t.id)}')"
               style="cursor:pointer;padding:.5rem .7rem;border-radius:4px;border:2px solid ${selectedId === t.id ? 'var(--accent,#3182ce)' : 'var(--border,#ddd)'};">
            <strong>${escHtml(t.id)}</strong> ${escHtml(t.name)}
          </div>`).join('')
        + `</div>
        <p style="font-size:.78rem;color:var(--text-secondary);margin-top:.5rem;">
          A tactic matches every technique beneath it, so it produces noticeably more events
          than any single technique — usually the better choice for a live demo.
        </p>`;
      return;
    }

    const q = search.trim().toLowerCase();
    const rows = catalog.techniques.filter((t) => {
      if (tacticFilter && t.tactic !== tacticFilter) return false;
      if (!q) return true;
      return (t.id + ' ' + t.name + ' ' + t.description + ' ' + t.keywords.join(' ')).toLowerCase().includes(q);
    });

    box.innerHTML = `
      <div style="display:flex;gap:.5rem;margin-bottom:.5rem;flex-wrap:wrap;">
        <input id="acSearch" type="search" placeholder="Search techniques…" value="${escAttr(search)}"
               oninput="CleAttack.setSearch(this.value)" style="flex:1;min-width:12rem;padding:.4rem;">
        <select onchange="CleAttack.setTactic(this.value)" style="padding:.4rem;">
          <option value="">All tactics</option>
          ${catalog.tactics.map((t) => `<option value="${escAttr(t.id)}" ${tacticFilter === t.id ? 'selected' : ''}>${escHtml(t.id)} ${escHtml(t.name)}</option>`).join('')}
        </select>
      </div>
      <div style="max-height:22rem;overflow:auto;border:1px solid var(--border,#ddd);border-radius:6px;">
        <table style="width:100%;border-collapse:collapse;font-size:.85rem;">
          <thead><tr style="position:sticky;top:0;background:var(--bg-secondary,#f7f7f7);">
            <th style="text-align:left;padding:.45rem;">ID</th>
            <th style="text-align:left;padding:.45rem;">Technique</th>
            <th style="text-align:left;padding:.45rem;">Tactic</th>
            <th style="text-align:left;padding:.45rem;">Matches on</th>
            <th style="text-align:left;padding:.45rem;">Yield</th>
          </tr></thead>
          <tbody>
            ${rows.length === 0
              ? `<tr><td colspan="5" style="padding:1rem;color:var(--text-secondary);">No technique matches that filter.</td></tr>`
              : rows.map((t) => `
              <tr onclick="CleAttack.select('${escAttr(t.id)}')" style="cursor:pointer;border-top:1px solid var(--border,#eee);
                  ${selectedId === t.id ? 'background:rgba(49,130,206,.12);' : ''}">
                <td style="padding:.45rem;font-family:monospace;">${escHtml(t.id)}</td>
                <td style="padding:.45rem;">${escHtml(t.name)}
                  <div style="font-size:.74rem;color:var(--text-secondary);">${escHtml(t.description)}</div></td>
                <td style="padding:.45rem;font-size:.78rem;">${escHtml(t.tactic_name || t.tactic)}</td>
                <td style="padding:.45rem;font-family:monospace;font-size:.72rem;color:var(--text-secondary);">
                  ${escHtml(t.keywords.join(', '))}</td>
                <td style="padding:.45rem;">${yieldCell(t)}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  }

  function renderTargets() {
    const box = el('acTargets');
    if (!box) return;
    if (targets.length === 0) {
      box.innerHTML = `<p style="color:var(--text-secondary);">No active lanes found for this course.
        Deploy the environment first.</p>`;
      return;
    }
    const usable = targets.filter((t) => t.resolvable).length;
    const chosen = targets.filter((t) => t.resolvable && !excluded.has(t.lane_id)).length;

    box.innerHTML = `
      <p style="font-size:.85rem;color:var(--text-secondary);margin:.25rem 0 .5rem;">
        ${chosen} of ${usable} usable lane(s) selected${targets.length - usable > 0
          ? ` · ${targets.length - usable} cannot be targeted` : ''}
      </p>
      <table style="width:100%;border-collapse:collapse;font-size:.85rem;">
        <thead><tr style="background:var(--bg-secondary,#f7f7f7);">
          <th style="width:2rem;padding:.4rem;"></th>
          <th style="text-align:left;padding:.4rem;">Student</th>
          <th style="text-align:left;padding:.4rem;">Sensor VM</th>
          <th style="text-align:left;padding:.4rem;">Found by</th>
          <th style="text-align:left;padding:.4rem;">State</th>
        </tr></thead>
        <tbody>
        ${targets.map((t) => `
          <tr style="border-top:1px solid var(--border,#eee);${t.resolvable ? '' : 'opacity:.6;'}">
            <td style="padding:.4rem;text-align:center;">
              <input type="checkbox" ${t.resolvable ? '' : 'disabled'}
                     ${t.resolvable && !excluded.has(t.lane_id) ? 'checked' : ''}
                     onchange="CleAttack.toggleLane('${escAttr(t.lane_id)}', this.checked)">
            </td>
            <td style="padding:.4rem;">${escHtml(t.student_email || t.user_id)}</td>
            <td style="padding:.4rem;font-family:monospace;font-size:.78rem;">
              ${t.vmid ? escHtml((t.vm_name || '') + ' (' + t.vmid + ')') : '—'}</td>
            <td style="padding:.4rem;font-size:.75rem;color:var(--text-secondary);">
              ${t.resolved_by ? escHtml(t.resolved_by) : '—'}</td>
            <td style="padding:.4rem;font-size:.78rem;">
              ${t.resolvable
                ? '<span style="color:#2f855a;">ready</span>'
                : `<span style="color:#c53030;">${escHtml(t.skip_reason || 'unavailable')}</span>`}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  function renderRun(data) {
    const box = el('acRun');
    if (!box) return;
    if (!data) { box.innerHTML = ''; return; }

    const r = data.run;
    const startsIn = r.scheduled_start_at
      ? Math.round((new Date(r.scheduled_start_at).getTime() - (Date.now() + serverOffsetMs)) / 1000)
      : null;

    const counts = Object.entries(data.counts || {})
      .map(([k, v]) => `${statusChip(k)} ${v}`).join(' &nbsp; ');

    const terminal = ['completed', 'partial', 'failed', 'aborted'].includes(r.status);
    const retryable = (data.targets || []).filter((t) => ['failed', 'skipped', 'unknown'].includes(t.status)).length;
    // cc-attack.sh declines below a 2 GiB floor and says so rather than filling
    // the disk mid-run. That refusal is the one failure an instructor can fix
    // from this screen, so it gets its own button instead of being one more row
    // in the Detail column reading like every other error.
    const outOfSpace = (data.targets || [])
      .filter((t) => /nospace/i.test(`${t.error || ''} ${t.skip_reason || ''} ${t.guest_state || ''}`));

    box.innerHTML = `
      <h3>Current run</h3>
      <div style="padding:.85rem;border:1px solid var(--border,#ddd);border-radius:6px;">
        <div style="display:flex;gap:1rem;align-items:center;flex-wrap:wrap;">
          <strong>${escHtml(r.selection || '')}</strong>
          ${statusChip(r.status)}
          ${r.duration_seconds ? `<span style="font-size:.8rem;color:var(--text-secondary);">for ${escHtml(fmtDuration(r.duration_seconds))}</span>` : ''}
          <span style="flex:1"></span>
          <span style="font-size:.85rem;">total events: <strong>${data.total_events || 0}</strong></span>
          ${terminal ? '' : `<button class="btn btn-secondary" onclick="CleAttack.abort()">Abort</button>`}
          ${retryable ? `<button class="btn btn-secondary" onclick="CleAttack.retry()">Retry ${retryable} lane(s)</button>` : ''}
          ${outOfSpace.length ? `<button class="btn btn-secondary" onclick="CleAttack.reclaim()"
              title="These lanes refused because the sensor is nearly full. Free space, then Retry.">Free space on ${outOfSpace.length} lane(s)</button>` : ''}
          <button class="btn btn-secondary" onclick="CleAttack.answerBook()"
              title="Exactly what this attack wrote to every lane: the messages, the adversary, and the queries that return them.">Answer book</button>
        </div>
        ${startsIn !== null && startsIn > 0
          ? `<p style="margin-top:.5rem;font-size:.9rem;">Starts on every lane in
               <strong id="acCountdown">${startsIn}</strong>s</p>`
          : ''}
        ${r.error ? `<p style="margin-top:.5rem;color:#c53030;">${escHtml(r.error)}</p>` : ''}
        <p style="margin-top:.5rem;font-size:.85rem;">${counts}</p>
      </div>
      <table style="width:100%;border-collapse:collapse;font-size:.85rem;margin-top:.75rem;">
        <thead><tr style="background:var(--bg-secondary,#f7f7f7);">
          <th style="text-align:left;padding:.4rem;">Student</th>
          <th style="text-align:left;padding:.4rem;">Status</th>
          <th style="text-align:left;padding:.4rem;">Started</th>
          <th style="text-align:left;padding:.4rem;">Events</th>
          <th style="text-align:left;padding:.4rem;">Clock</th>
          <th style="text-align:left;padding:.4rem;">Detail</th>
        </tr></thead>
        <tbody>
        ${(data.targets || []).map((t) => `
          <tr style="border-top:1px solid var(--border,#eee);">
            <td style="padding:.4rem;">${escHtml(t.student_email || t.user_id)}</td>
            <td style="padding:.4rem;">${statusChip(t.status)}${t.late ? ' <span style="font-size:.7rem;color:#975a16;">late</span>' : ''}</td>
            <td style="padding:.4rem;font-size:.78rem;">${t.started_at ? escHtml(new Date(t.started_at).toLocaleTimeString()) : '—'}</td>
            <td style="padding:.4rem;">${t.event_count == null ? '—' : t.event_count}</td>
            <td style="padding:.4rem;font-size:.78rem;">${t.clock_skew_s == null ? '—'
              : (Math.abs(t.clock_skew_s) < 2 ? 'in sync' : `${t.clock_skew_s > 0 ? '+' : ''}${t.clock_skew_s}s off`)}</td>
            <td style="padding:.4rem;font-size:.75rem;color:var(--text-secondary);">
              ${escHtml(t.error || t.skip_reason || t.guest_state || '')}</td>
          </tr>`).join('')}
        </tbody>
      </table>`;
  }

  // ---- data ---------------------------------------------------------------

  async function load() {
    if (!currentCourseId) return;
    try {
      if (!catalog) catalog = await api('GET', `/courses/${currentCourseId}/attacks/catalog`);
      renderShell();
      await refreshTargets();
      await loadLatestRun();
      loadedForCourse = currentCourseId;
    } catch (e) {
      root().innerHTML = `<p style="color:#c53030;">Could not load the attack console: ${escHtml(e.message)}</p>`;
    }
  }

  async function refreshTargets() {
    if (!currentCourseId) return;
    try {
      const data = await api('GET', `/courses/${currentCourseId}/attacks/targets`);
      targets = data.targets || [];
      // Never carry an exclusion across a refresh for a lane that no longer
      // exists: it would silently shrink a later launch.
      const live = new Set(targets.map((t) => t.lane_id));
      excluded = new Set([...excluded].filter((id) => live.has(id)));
      renderTargets();
    } catch (e) {
      toast('Could not list lanes: ' + e.message, true);
    }
  }

  /** Re-attach to whatever is already going, so a reload does not lose the run. */
  async function loadLatestRun() {
    try {
      const data = await api('GET', `/courses/${currentCourseId}/attacks`);
      const latest = (data.runs || [])[0];
      if (!latest) return;
      activeRunId = latest.run_id;
      await pollOnce();
      if (!['completed', 'partial', 'failed', 'aborted'].includes(latest.status)) startPolling();
    } catch (_) { /* history is a nicety, not a requirement */ }
  }

  async function pollOnce() {
    if (!activeRunId || !currentCourseId) return null;
    const data = await api('GET', `/courses/${currentCourseId}/attacks/${activeRunId}/status`);
    // Trust the server's clock, not the browser's — see this file's header.
    if (data.server_time) serverOffsetMs = new Date(data.server_time).getTime() - Date.now();
    renderRun(data);
    return data;
  }

  function startPolling() {
    stopPolling();
    pollTimer = setInterval(async () => {
      try {
        const data = await pollOnce();
        if (data && ['completed', 'partial', 'failed', 'aborted'].includes(data.run.status)) {
          stopPolling();
        }
      } catch (e) {
        // A transient failure must not kill the poller; a persistent one is
        // visible because the table stops advancing.
        console.warn('[attack-console] poll failed:', e.message);
      }
    }, POLL_MS);

    // Separate 1s tick so the countdown moves smoothly between 2s polls, the
    // same shape admin-lanes.js uses for deploy ETAs.
    countdownTimer = setInterval(() => {
      const c = el('acCountdown');
      if (!c) return;
      const n = Number(c.textContent) - 1;
      c.textContent = n > 0 ? String(n) : '0';
    }, 1000);
  }

  function stopPolling() {
    if (pollTimer) clearInterval(pollTimer);
    if (countdownTimer) clearInterval(countdownTimer);
    pollTimer = countdownTimer = null;
  }

  // ---- actions ------------------------------------------------------------

  async function launch() {
    const sel = currentSelection();
    if (!sel) return toast('Pick a technique, tactic or chain first', true);

    const body = { exclude_lane_ids: [...excluded] };
    if (mode === 'chain') body.chain_key = sel.key;
    else if (mode === 'tactic') body.tactic_id = sel.id;
    else body.technique_id = sel.id;
    body.mode = mode;
    // Deliberately omitted for chains: the server rejects a duration on a chain
    // outright rather than silently ignoring it.
    if (mode !== 'chain') body.duration_seconds = Number(el('acDuration').value);

    const btn = el('acLaunchBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Launching…'; }
    try {
      const r = await api('POST', `/courses/${currentCourseId}/attacks`, body);
      activeRunId = r.run_id;
      toast('Attack scheduled across the class');
      await pollOnce().catch(() => {});
      startPolling();
    } catch (e) {
      toast(e.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Launch to selected lanes'; }
    }
  }

  async function abort() {
    if (!activeRunId) return;
    try {
      await api('POST', `/courses/${currentCourseId}/attacks/${activeRunId}/abort`);
      toast('Abort sent to every running lane');
      startPolling();
    } catch (e) { toast(e.message, true); }
  }

  /**
   * Show what the attack actually wrote, for marking.
   *
   * Rendered into the existing reclaim panel rather than a modal: the console
   * has no modal of its own, and an instructor marking thirty submissions wants
   * this on screen NEXT TO the lane table, not covering it.
   */
  async function answerBook() {
    if (!activeRunId) return;
    const box = el('acReclaim');
    if (box) box.innerHTML = '<p style="font-size:.85rem;color:var(--text-secondary);margin:.5rem 0;">Compiling the answer book...</p>';
    try {
      const b = await api('GET', `/courses/${currentCourseId}/attacks/${activeRunId}/answer-book`);
      lastBook = b;
      renderAnswerBook(b);
    } catch (e) {
      if (box) box.innerHTML = `<p style="margin:.5rem 0;color:#c53030;font-size:.85rem;">${escHtml(e.message)}</p>`;
    }
  }

  let lastBook = null;

  /** Plain text, so it can go straight into a grading sheet or an email. */
  function bookAsText(b) {
    const L = [];
    L.push(`ANSWER BOOK - ${b.selection.label || b.selection.mode}`);
    L.push(`run ${b.run_id}`);
    L.push(`${b.totals.events_per_lane} events on every lane, over ${b.selection.duration_seconds}s`);
    L.push('');
    L.push('ADVERSARY');
    for (const [k, v] of Object.entries(b.adversary || {})) L.push(`  ${k}: ${v}`);
    L.push('');
    L.push('WHAT IT WROTE');
    for (const a of b.activity) {
      L.push(`  [${a.level}] ${a.source_type}/${a.source_name} on ${a.hosts.join(', ')} - ${a.event_count} events (${a.first_offset_s}s-${a.last_offset_s}s)`);
      for (const m of a.messages) L.push(`     x${m.count}  ${m.examples[0]}`);
    }
    L.push('');
    L.push('QUERIES (paste into Discover, set the time range to the run window)');
    for (const q of b.queries) L.push(`  ${q.kql}\n     expect ${q.expect_events} events - ${q.label}`);
    if ((b.look_alikes || []).length) {
      L.push('');
      L.push('BENIGN LOOK-ALIKES - a student reporting these is not simply wrong');
      for (const l of b.look_alikes) L.push(`  ${l.source_type}/${l.source_name}${l.technique ? ` (tagged ${l.technique})` : ''} - ${l.why}`);
    }
    return L.join('\n');
  }

  function copyBook() {
    if (!lastBook) return;
    const text = bookAsText(lastBook);
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(() => toast('Answer book copied'), () => toast('Could not copy', true));
    } else {
      // Older browsers in a lab image. A textarea + execCommand still works and
      // is better than telling the instructor to select it by hand.
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('Answer book copied'); }
      catch (e) { toast('Could not copy', true); }
      document.body.removeChild(ta);
    }
  }

  function renderAnswerBook(b) {
    const box = el('acReclaim');
    if (!box) return;
    const adversary = Object.entries(b.adversary || {})
      .map(([k, v]) => `<code style="font-size:.78rem;">${escHtml(k)}=${escHtml(String(v))}</code>`).join(' &nbsp; ');

    box.innerHTML = `
      <div style="margin:.5rem 0;padding:.75rem;border:1px solid var(--border,#ddd);border-radius:6px;">
        <div style="display:flex;align-items:center;gap:.75rem;flex-wrap:wrap;">
          <strong style="font-size:.95rem;">Answer book — ${escHtml(b.selection.label || b.selection.mode || '')}</strong>
          <span style="font-size:.8rem;color:var(--text-secondary);">
            ${b.totals.events_per_lane} events on every lane · ${b.totals.iocs} indicator(s)</span>
          <span style="flex:1"></span>
          <button class="btn btn-secondary" onclick="CleAttack.copyBook()">Copy as text</button>
        </div>
        <p style="margin:.5rem 0 .25rem;font-size:.8rem;color:var(--text-secondary);">Adversary</p>
        <div>${adversary || '<span style="font-size:.8rem;color:var(--text-secondary);">none resolved</span>'}</div>

        <p style="margin:.75rem 0 .25rem;font-size:.8rem;color:var(--text-secondary);">What it wrote</p>
        ${b.activity.map((a) => `
          <div style="margin-bottom:.5rem;padding:.4rem .5rem;background:var(--bg-secondary,#f7f7f7);border-radius:4px;">
            <div style="font-size:.8rem;">
              <strong>${escHtml(a.source_type)}/${escHtml(a.source_name)}</strong>
              <span style="color:var(--text-secondary);">
                ${escHtml(a.level)} · ${a.event_count} events · ${a.first_offset_s}s–${a.last_offset_s}s
                · ${escHtml(a.hosts.join(', '))}</span>
            </div>
            ${a.messages.map((m) => `
              <div style="font-family:monospace;font-size:.72rem;margin-top:.2rem;color:var(--text-secondary);">
                <span style="display:inline-block;min-width:3.5rem;">×${m.count}</span>${escHtml(m.examples[0])}
              </div>`).join('')}
          </div>`).join('')}

        <p style="margin:.75rem 0 .25rem;font-size:.8rem;color:var(--text-secondary);">
          Queries — set the time range to the run window, then paste into Discover</p>
        ${b.queries.length ? b.queries.map((q) => `
          <div style="margin-bottom:.3rem;font-size:.78rem;">
            <code style="font-family:monospace;">${escHtml(q.kql)}</code>
            <span style="color:var(--text-secondary);"> → expect <strong>${q.expect_events}</strong></span>
          </div>`).join('')
          : '<p style="font-size:.78rem;color:var(--text-secondary);">No indicator is unique to this run.</p>'}

        ${(b.look_alikes || []).length ? `
          <p style="margin:.75rem 0 .25rem;font-size:.8rem;color:var(--text-secondary);">
            Benign look-alikes — a student reporting one of these is not simply wrong</p>
          ${b.look_alikes.map((l) => `
            <div style="font-size:.78rem;margin-bottom:.2rem;">
              <code>${escHtml(l.source_type)}/${escHtml(l.source_name)}</code>
              ${l.technique ? `<span style="color:#975a16;"> tagged ${escHtml(l.technique)}</span>` : ''}
              <span style="color:var(--text-secondary);"> — ${escHtml(l.why)}</span>
            </div>`).join('')}` : ''}
      </div>`;
  }

  /**
   * Free disk on every resolvable sensor in the course.
   *
   * Synchronous on purpose. abort() and retry() fire-and-poll because a run
   * already exists to watch; this has no run, and the instructor is standing at
   * the console deciding whether the lane is usable for the next ten minutes.
   * The numbers ARE the answer, so they are worth waiting a few seconds for and
   * worth rendering rather than reducing to a toast.
   */
  async function reclaim() {
    if (!currentCourseId) return;
    const btn = el('acReclaimBtn');
    const box = el('acReclaim');
    if (btn) { btn.disabled = true; btn.textContent = 'Freeing space...'; }
    if (box) box.innerHTML = '<p style="font-size:.85rem;color:var(--text-secondary);margin:.5rem 0;">Working through the lanes, a few seconds each...</p>';
    try {
      const r = await api('POST', `/courses/${currentCourseId}/attacks/reclaim`, {});
      renderReclaim(r);
      toast(`Freed ${fmtKb(r.freed_kb_total)} across ${r.reclaimed} lane(s)`);
      // Free space changes whether a lane is targetable at all, so the picker's
      // state is stale the moment this returns.
      await refreshTargets();
    } catch (e) {
      if (box) box.innerHTML = '';
      toast('Could not free space: ' + e.message, true);
    } finally {
      if (btn) { btn.disabled = false; btn.textContent = 'Free disk space'; }
    }
  }

  /** KB to something a person reads, signed so a gain is obviously a gain. */
  function fmtKb(kb) {
    const n = Number(kb) || 0;
    const abs = Math.abs(n);
    const s = abs >= 1048576 ? `${(abs / 1048576).toFixed(1)} GB`
      : abs >= 1024 ? `${(abs / 1024).toFixed(0)} MB`
      : `${abs} KB`;
    return n < 0 ? `-${s}` : s;
  }

  function renderReclaim(r) {
    const box = el('acReclaim');
    if (!box) return;
    if (!r || !r.lanes) {
      box.innerHTML = '<p style="font-size:.85rem;color:var(--text-secondary);margin:.5rem 0;">No reachable lanes to clean.</p>';
      return;
    }
    // Worst-off first: the lane still short of the 2 GiB floor is the one the
    // instructor has to deal with, and it should not be somewhere in the middle
    // of an alphabetical list of successes.
    const rows = (r.results || []).slice().sort((a, b) => {
      if (a.ok !== b.ok) return a.ok ? 1 : -1;
      return (a.after_kb || 0) - (b.after_kb || 0);
    });
    const FLOOR_KB = 2097152;
    box.innerHTML = `
      <div style="margin:.5rem 0;padding:.6rem .75rem;border:1px solid var(--border,#ddd);border-radius:6px;">
        <strong style="font-size:.9rem;">Freed ${escHtml(fmtKb(r.freed_kb_total))}</strong>
        <span style="font-size:.85rem;color:var(--text-secondary);">
          across ${r.reclaimed} of ${r.lanes} lane(s)${r.unreachable ? ` · ${r.unreachable} unreachable` : ''}
        </span>
        <table style="width:100%;border-collapse:collapse;font-size:.8rem;margin-top:.5rem;">
          <thead><tr style="background:var(--bg-secondary,#f7f7f7);">
            <th style="text-align:left;padding:.3rem;">Student</th>
            <th style="text-align:left;padding:.3rem;">Freed</th>
            <th style="text-align:left;padding:.3rem;">Free now</th>
            <th style="text-align:left;padding:.3rem;">Disk</th>
          </tr></thead>
          <tbody>
          ${rows.map((x) => {
            const short = x.ok && x.after_kb != null && x.after_kb < FLOOR_KB;
            return `
            <tr style="border-top:1px solid var(--border,#eee);${x.ok ? '' : 'opacity:.65;'}">
              <td style="padding:.3rem;">${escHtml(x.student_email || x.lane_name || x.lane_id)}</td>
              <td style="padding:.3rem;">${x.ok ? escHtml(fmtKb(x.freed_kb)) : '—'}</td>
              <td style="padding:.3rem;${short ? 'color:#c53030;font-weight:600;' : ''}">
                ${x.ok ? escHtml(fmtKb(x.after_kb)) : '—'}
                ${short ? ' (still under the 2 GB floor)' : ''}</td>
              <td style="padding:.3rem;color:var(--text-secondary);">
                ${x.ok ? escHtml(fmtKb(x.total_kb)) : escHtml(x.error || 'unreachable')}</td>
            </tr>`;
          }).join('')}
          </tbody>
        </table>
      </div>`;
  }

  async function retry() {
    if (!activeRunId) return;
    try {
      await api('POST', `/courses/${currentCourseId}/attacks/${activeRunId}/retry`, {});
      toast('Re-firing the lanes that missed');
      startPolling();
    } catch (e) { toast(e.message, true); }
  }

  // ---- lifecycle ----------------------------------------------------------

  /**
   * Called by viewCourse() when a different course is opened. Everything that
   * could paint the previous course's data into this one is dropped here; the
   * panel itself is not loaded until the tab is actually shown.
   */
  function reset(courseId) {
    stopPolling();
    targets = [];
    excluded = new Set();
    activeRunId = null;
    selectedId = null;
    search = '';
    tacticFilter = '';
    if (loadedForCourse !== courseId) loadedForCourse = null;
    const box = root();
    if (box) box.innerHTML = '<p style="color:var(--text-secondary);">Loading…</p>';
  }

  /** First show of the tab for this course does the expensive work. */
  function onShow() {
    if (loadedForCourse === currentCourseId) return;
    load();
  }

  window.CleAttack = {
    load,
    onShow,
    reset,
    cancelPolling: stopPolling,
    refreshTargets,
    launch,
    abort,
    retry,
    reclaim,
    answerBook,
    copyBook,
    setMode(m) { mode = m; selectedId = null; renderShell(); },
    select(id) { selectedId = id; renderShell(); },
    setSearch(v) {
      search = v;
      renderPicker();
      // Re-rendering the picker replaces the input, so put the caret back where
      // the instructor left it or every keystroke would lose focus.
      const i = el('acSearch');
      if (i) { i.focus(); i.setSelectionRange(i.value.length, i.value.length); }
    },
    setTactic(v) { tacticFilter = v; renderPicker(); },
    toggleLane(laneId, checked) {
      if (checked) excluded.delete(laneId); else excluded.add(laneId);
      renderTargets();
    },
  };
})();
