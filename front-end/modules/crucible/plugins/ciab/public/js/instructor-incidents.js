/**
 * instructor-incidents.js — the Incidents tab (Track E, phase E6).
 * ============================================================================
 * The staff side of a defensive engagement: pick a Section, pick an Engagement
 * inside it, fire a synthetic incident into every Environment at once, watch it
 * land, then adjudicate what the students banked and release the verdicts.
 *
 * WHAT IT TALKS TO
 *   GET  /api/instructor/sections                       the Section picker
 *   GET  /api/instructor/sections/:id/modules           which Clients that
 *                                                       Section's curriculum
 *                                                       binds (modules carry
 *                                                       profile_id) plus their
 *                                                       display names
 *   GET  /api/instructor/engagements?profile_id=…       every Engagement on one
 *                                                       Client, filtered here
 *                                                       to the defensive type
 *   GET  /api/engagements/:id/incidents                 incidents, newest first
 *   GET  /api/engagements/:id/incidents/catalog         techniques/tactics/chains
 *   GET  /api/engagements/:id/incidents/scenarios       this Client's own
 *                                                       incidents, projected
 *   GET  /api/engagements/:id/incidents/targets         the Environment picker
 *   POST /api/engagements/:id/incidents                 launch
 *   GET  /api/engagements/:id/incidents/:runId/status   the 2s poll
 *   POST /api/engagements/:id/incidents/:runId/abort    stop it
 *   POST /api/engagements/:id/incidents/:runId/retry    re-fire what missed
 * and it hands the BOARD itself to /js/blueteam/blueteam-board.js, which is the
 * same component the student workspace mounts — one board, two tiers, decided
 * by the server and never by the `role` this file passes.
 *
 * ── THE 'SCENARIO' MODE, AND WHY IT IS FIRST ────────────────────────────────
 * A Scenario is the Client's OWN incident: one entry from their threat profile,
 * compiled against their own machines, their own people and their own addresses
 * (src/incident/scenario-compiler.js). The other three modes fire a generic
 * MITRE selection at whatever is in the environment; this one fires the thing
 * the Client's report says would actually happen to them. It leads the picker
 * because it is the mode this product exists for.
 *
 * It is fed by GET .../incidents/scenarios rather than by the catalog, because a
 * Scenario is not a catalog entry — it is one Client's document, and the server
 * projects it down to five fields on the way out. The per-step
 * `detection_opportunity` prose IS the answer key, so it never leaves the
 * server: what arrives here is a name, a type and a technique count.
 *
 * THE COUNT IS SHOWN BEFORE LAUNCH AND ONLY TO STAFF. A student who knows there
 * are six techniques knows when to stop looking, which is why
 * src/incident/projection.js keeps that number off every student payload and
 * why the release gate withholds it pre-release.
 *
 * ── WHY THE POLL TARGET ENDS IN /status ─────────────────────────────────────
 * src/server.js exempts GETs matching /\/status$/ from the global API rate
 * limiter. Instructors are not admins, so polling any OTHER path at 2s exhausts
 * their bucket and a class-length exercise starts 429ing mid-incident. The
 * cadence and the stop conditions below are lifted from the proven
 * implementation in the neighbouring plugin's attack console: poll every 2s
 * while the run is live, stop the moment it reaches a terminal status, and
 * never let one failed poll kill the loop.
 *
 * THE THIRD STOP CONDITION IS THIS TAB'S OWN. activateTabModule() tells a module
 * when it is ENTERED and never when it is left, so a run left in flight while
 * the instructor works on another tab would poll forever behind a panel nobody
 * is looking at. Rather than bolt a leave-hook onto instructor-core.js — the one
 * file several tracks are editing at once — the tick asks whether the panel is
 * still the active one and stops itself if it is not. ensureInit() restarts it
 * on the way back in.
 *
 * ── VOCABULARY ──────────────────────────────────────────────────────────────
 * Section / Module / Client / Engagement / Environment / Incident. The
 * neighbouring plugin's nouns are banned in anything a person reads on this
 * screen, and front-end/test/ciab-vocabulary.test.js is the gate on that. The
 * word "lane" is in the same bin: `exclude_lane_ids` and `lane_id` are the
 * shared engine's KEY NAMES — renaming them here would fork the payload the
 * shared board understands — but nothing rendered ever says it.
 *
 * ── LOAD ORDER IS LOAD-BEARING ──────────────────────────────────────────────
 * The <script> tag MUST come after instructor-core.js (esc/escJs/timeAgo are
 * top-level `const`s there, so an earlier tag reads them inside their temporal
 * dead zone) and after all four /js/blueteam/*.js files in the order
 * api -> timeline -> score -> board, because blueteam-board.js reads the other
 * three off window at mount time. A wrong order is DETECTED rather than assumed
 * away: see the guard at the bottom of this file, and note that it is a BARE
 * read inside a try/catch and not `typeof`, which is the one operator that
 * cannot throw on an undeclared name and therefore reports success on exactly
 * the failure being tested for.
 *
 * Depends on instructor-core.js globals (esc, escJs, timeAgo) and the app.js kit
 * (API, Toast, Confirm, Utils). Those kit names are top-level consts in app.js,
 * NOT window properties — feature-detect them by bare name, never window.API.
 */
/* global API, Toast, Confirm, Utils, esc, escJs, timeAgo, switchTab */

(function () {
  'use strict';

  // Everything below lives inside this IIFE on purpose. Classic scripts share
  // ONE global lexical scope, so a bare top-level `const POLL_MS` here would
  // make a second dashboard module's identically-named const a whole-script
  // SyntaxError. The only thing this file adds to the global object is
  // window.Incidents.

  const POLL_MS = 2000;

  /**
   * The one Engagement type that can host an incident.
   *
   * Mirrors BLUE_TEAM_TYPE_KEY in ciab/utils/engagement-model.js. DUPLICATED
   * rather than imported: manifest.json's staticDir is "public", so utils/ is
   * never served to a browser. The server is still the authority — a launch
   * against anything else is refused there — so this constant only decides what
   * the picker OFFERS.
   */
  const DEFENSIVE_TYPE = 'defensive_monitoring';

  /** The statuses that mean "still going". Everything else is terminal. */
  const LIVE_STATUSES = ['scheduling', 'dispatching', 'running'];
  const isLive = (status) => LIVE_STATUSES.indexOf(String(status)) !== -1;

  const DURATIONS = [
    [300, '5 minutes'], [900, '15 minutes'], [1800, '30 minutes'],
    [3600, '1 hour'], [7200, '2 hours'],
  ];

  const el = (id) => document.getElementById(id);

  /** Is this tab the one on screen? The poll's third stop condition. */
  function panelIsActive() {
    const panel = el('tab-incidents');
    return !!panel && panel.classList.contains('active');
  }

  // ── State ─────────────────────────────────────────────────────────────────

  const S = {
    booted: false,
    sections: [],
    sectionId: null,
    engagements: [],
    engagementId: null,
    catalog: null,
    // This Client's own threat scenarios, projected by the server. `chosen` is
    // the one the Engagement is already committed to — the benign traffic on
    // every Environment here was compiled from it at deploy time, so launching
    // a different one is a real choice with a real consequence and the picker
    // says so rather than leaving it to be discovered in Discover.
    scenarios: [],
    scenarioChosen: null,
    targets: [],
    // OPT-OUT, not opt-in — see toggleEnvironment(). Holds the engine's
    // lane_id values, which are identifiers and never appear in copy.
    excluded: new Set(),
    mode: 'technique',        // scenario | technique | tactic | chain
    selectedId: null,
    search: '',
    tacticFilter: '',
    runs: [],
    runId: null,
    status: null,             // the last /status payload
    pollTimer: null,
    board: null,              // the BlueTeamBoard handle, so it can be destroyed
    boardRunId: null,
  };

  // ── Transport ─────────────────────────────────────────────────────────────

  /**
   * The incidents collection for the selected Engagement, WITHOUT the /api
   * prefix — API.request adds it. boardBase() below is the same URL WITH the
   * prefix, because BlueTeamApi speaks raw fetch and knows no baseUrl.
   *
   * encodeURIComponent on the id, always: an unencoded '/' or an encoded '..'
   * re-points the call at a different route, and on this namespace that means a
   * POST landing on /abort or /retry.
   */
  const scopePath = (id) => `/engagements/${encodeURIComponent(id)}/incidents`;
  const boardBase = (id) => `/api${scopePath(id)}`;

  function inc(path, options) {
    return API.request(scopePath(S.engagementId) + (path || ''), options);
  }

  /**
   * One refusal renderer.
   *
   * The dispatch mutex is a UNIQUE index on (scope_type, scope_id) WHERE the run
   * is still scheduling or dispatching, so a second Launch is a 409 carrying
   * code INCIDENT_IN_FLIGHT. It SURVIVES A RESTART — it is a row, not an
   * in-memory registry — so the message says how to clear it rather than
   * implying it expires on its own.
   */
  function explain(err) {
    const status = err && err.status;
    const code = err && err.data && err.data.code;
    if (status === 409 || code === 'INCIDENT_IN_FLIGHT') {
      return 'An incident is already dispatching for this engagement. '
        + 'Wait for it to finish, or abort it first.';
    }
    if (status === 404) {
      return 'That engagement is no longer available to you.';
    }
    return (err && err.message) || 'Request failed';
  }

  // ── Small renderers ───────────────────────────────────────────────────────

  const STATUS_COLOURS = {
    scheduling: '#805ad5', dispatching: '#3182ce', running: '#2b6cb0',
    completed: '#2f855a', partial: '#b7791f', failed: '#c53030', aborted: '#975a16',
  };

  function statusChip(status) {
    const bg = STATUS_COLOURS[status] || '#718096';
    return `<span style="font-size:0.72rem; padding:0.15rem 0.45rem; border-radius:3px;`
      + ` background:${bg}; color:#fff;">${esc(status || 'unknown')}</span>`;
  }

  function fmtDuration(seconds) {
    if (!seconds) return '';
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return [h ? `${h}h` : '', m ? `${m}m` : '', s ? `${s}s` : ''].join('') || '0s';
  }

  function volumeBadge(v) {
    const colour = v === 'high' ? '#2f855a' : v === 'medium' ? '#b7791f' : '#718096';
    const label = v === 'high' ? 'high yield' : v === 'medium' ? 'medium yield' : 'low yield';
    return `<span style="font-size:0.7rem; padding:0.1rem 0.4rem; border-radius:3px;`
      + ` background:${colour}; color:#fff;">${label}</span>`;
  }

  /**
   * A scripted playbook REPLACES the yield badge rather than sitting beside it.
   * expected_volume is documented in the catalog as an estimate read off a
   * keyword matcher; once a playbook drives the technique the count is the sum
   * of its steps and is exact. Showing both would put two near-inverse claims in
   * adjacent columns.
   */
  function yieldCell(t) {
    if (t.fidelity !== 'high' || t.expected_events == null) return volumeBadge(t.expected_volume);
    return `<span style="font-size:0.7rem; padding:0.1rem 0.4rem; border-radius:3px;`
      + ` background:#2b6cb0; color:#fff;"`
      + ` title="Scripted playbook — this is the exact number of events, not an estimate">`
      + `${esc(String(t.expected_events))} events</span>`;
  }

  /** A playbook refuses a duration shorter than its own bursts, and is right to. */
  function allowedDuration(selection, seconds) {
    return !selection || selection.min_seconds == null || seconds >= selection.min_seconds;
  }

  function currentSelection() {
    if (!S.selectedId) return null;
    // Scenario mode is the one that does not read the catalog: its rows came
    // from this Client's own profile, not from a shipped list.
    if (S.mode === 'scenario') {
      return (S.scenarios || []).find((s) => s.scenario_id === S.selectedId) || null;
    }
    if (!S.catalog) return null;
    if (S.mode === 'chain') return (S.catalog.chains || []).find((c) => c.key === S.selectedId) || null;
    if (S.mode === 'tactic') return (S.catalog.tactics || []).find((t) => t.id === S.selectedId) || null;
    return (S.catalog.techniques || []).find((t) => t.id === S.selectedId) || null;
  }

  /** What a stored run was launched with, named from the catalog when we have it. */
  function runLabel(run) {
    if (!run) return '';
    // scenario_ref is the SNAPSHOT the launcher wrote — what the scenario was
    // called WHEN IT RAN. Read before the live list on purpose: a profile that
    // has been regenerated since must not silently rename a graded incident.
    if (run.mode === 'scenario') {
      const snap = run.scenario_ref && run.scenario_ref.name;
      if (snap) return snap;
      const live = (S.scenarios || []).find((x) => x.scenario_id === run.scenario_id);
      return (live && live.name) || run.scenario_id || 'scenario';
    }
    if (run.mode === 'chain') {
      const c = S.catalog && (S.catalog.chains || []).find((x) => x.key === run.chain_key);
      return c ? c.name : (run.chain_key || 'attack chain');
    }
    if (run.mode === 'tactic') {
      const t = S.catalog && (S.catalog.tactics || []).find((x) => x.id === run.tactic_id);
      return t ? `${t.id} ${t.name}` : (run.tactic_id || 'tactic');
    }
    const tech = S.catalog && (S.catalog.techniques || []).find((x) => x.id === run.technique_id);
    return tech ? `${tech.id} ${tech.name}` : (run.technique_id || 'technique');
  }

  // ── Load: sections, then engagements, then the incident surface ───────────

  function showMain(show) {
    const main = el('incidentMain');
    const empty = el('incidentNoScope');
    if (main) main.style.display = show ? '' : 'none';
    if (empty) empty.style.display = show ? 'none' : '';
  }

  function emptyState(icon, heading, body) {
    const box = el('incidentNoScope');
    if (!box) return;
    box.innerHTML = `<div class="icon">${icon}</div><h3>${esc(heading)}</h3><p>${body}</p>`;
    showMain(false);
  }

  async function load() {
    // Paint before anything is awaited: instructor-core.js calls switchTab()
    // before its dashboard fetch resolves, so a deep link to #incidents
    // activates this tab while nothing at all is loaded.
    const launcher = el('incidentLauncher');
    if (launcher) launcher.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(3);
    showMain(true);

    let sections;
    try {
      // Its own fetch, deliberately, exactly as the Modules tab does:
      // InstructorState.sections comes from the dashboard payload and carries no
      // status, and Sections.all belongs to another tab. Reading either couples
      // this tab to a fetch it does not own.
      const res = await API.request('/instructor/sections');
      sections = res.sections || [];
    } catch (err) {
      emptyState('&#9888;&#65039;', 'Could not load your sections',
        `${esc((err && err.message) || 'Request failed')}<br>Reload the page to try again.`);
      return;
    }

    S.sections = sections;
    if (!S.sections.length) {
      emptyState('&#127891;', 'No sections yet',
        'An incident runs inside an engagement, and an engagement is reached through '
        + 'a section&rsquo;s modules.<br>Create a section first, then bind a module to a client.');
      return;
    }

    const has = (id) => !!id && S.sections.some((s) => s.section_id === id);
    if (!has(S.sectionId)) {
      const fromSections = window.Sections && window.Sections.currentId;
      S.sectionId = has(fromSections) ? fromSections : S.sections[0].section_id;
    }

    const select = el('incidentSectionSelect');
    if (select) {
      select.innerHTML = S.sections.map((s) => {
        const bits = [s.name];
        if (s.code) bits.push(`(${s.code})`);
        if (s.term) bits.push(`— ${s.term}`);
        if (s.status === 'archived') bits.push('· archived');
        return `<option value="${esc(s.section_id)}">${esc(bits.join(' '))}</option>`;
      }).join('');
      select.value = S.sectionId;
    }

    await onSectionChange();
  }

  /**
   * Which engagements this section can host an incident in.
   *
   * ciab_module is the ONLY link between a section and an engagement that
   * exists: an engagement hangs off a CLIENT, and a module names the pair
   * (profile_id, engagement_type) — the same pair the engagement table is
   * UNIQUE on. So the walk is section -> modules -> distinct clients ->
   * that client's engagements, filtered to the defensive type and to the ones
   * still holding their network reservation.
   *
   * One unreadable client must not empty the whole picker, so each lookup
   * catches for itself.
   */
  async function loadEngagementsForSection() {
    const res = await API.request(`/instructor/sections/${encodeURIComponent(S.sectionId)}/modules`);
    const modules = res.modules || [];
    const clients = res.clients || [];
    const nameById = new Map(clients.map((c) => [
      c.id, c.company_name || c.client_type_name || c.industry || '',
    ]));

    const profileIds = [];
    for (const m of modules) {
      if (m.profile_id && profileIds.indexOf(m.profile_id) === -1) profileIds.push(m.profile_id);
    }

    const lists = await Promise.all(profileIds.map((pid) => API.engagements.list(pid)
      .then((r) => ({ pid, rows: r.engagements || [] }))
      .catch(() => ({ pid, rows: [] }))));

    const found = [];
    for (const { pid, rows } of lists) {
      for (const row of rows) {
        if (row.engagement_type !== DEFENSIVE_TYPE) continue;
        // retired_at set means the block was handed back. Anything launched into
        // it would target environments with no network left to run on, and the
        // server 404s it anyway.
        if (row.retired_at) continue;
        found.push(Object.assign({}, row, { client_name: nameById.get(pid) || '' }));
      }
    }
    return found;
  }

  async function onSectionChange() {
    const select = el('incidentSectionSelect');
    if (select && select.value) S.sectionId = select.value;
    if (!S.sectionId) return;

    stopPoll();
    destroyBoard();
    S.engagements = [];
    S.engagementId = null;
    S.catalog = null;
    S.targets = [];
    S.excluded = new Set();
    S.runs = [];
    S.runId = null;
    S.status = null;

    const launcher = el('incidentLauncher');
    if (launcher) launcher.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(3);
    renderRun();

    try {
      S.engagements = await loadEngagementsForSection();
    } catch (err) {
      if (launcher) {
        launcher.innerHTML = '<div class="card"><div class="card-body">'
          + '<p class="text-muted">Could not read this section&rsquo;s modules: '
          + `${esc((err && err.message) || 'Request failed')}</p></div></div>`;
      }
      return;
    }

    renderEngagementPicker();
    if (S.engagements.length) {
      S.engagementId = S.engagements[0].engagement_id;
      const eng = el('incidentEngagementSelect');
      if (eng) eng.value = S.engagementId;
      await onEngagementChange();
    }
  }

  function renderEngagementPicker() {
    const field = el('incidentEngagementField');
    const select = el('incidentEngagementSelect');
    const meta = el('incidentScopeMeta');
    const launcher = el('incidentLauncher');

    if (!S.engagements.length) {
      // Say it plainly instead of offering an empty dropdown. The reason is
      // structural, not a loading state: only a defensive engagement stands up a
      // sensor and a SIEM, and without those an incident has nowhere to land.
      if (field) field.style.display = 'none';
      if (meta) meta.textContent = '';
      if (launcher) {
        launcher.innerHTML = `
          <div class="card">
            <div class="card-body">
              <div class="empty-state" style="padding:1.5rem 1rem;">
                <div class="icon">&#128373;&#65039;</div>
                <h3>No defensive engagement in this section</h3>
                <p>An incident can only be fired into a <strong>Defensive &mdash; monitoring</strong>
                   engagement: it is the only one that stands up a sensor and a SIEM for the team
                   to hunt in.<br>
                   Bind one of this section&rsquo;s modules to a client that has a defensive
                   engagement, or create that engagement on the Engagements tab, then come back.</p>
                <button class="btn btn-primary" onclick="switchTab('engagements')">Go to Engagements</button>
              </div>
            </div>
          </div>`;
      }
      renderRun();
      destroyBoard();
      return;
    }

    if (field) field.style.display = '';
    if (select) {
      select.innerHTML = S.engagements.map((e) => {
        const bits = [];
        if (e.client_name) bits.push(e.client_name);
        bits.push(e.display_label || 'Defensive — monitoring');
        return `<option value="${esc(e.engagement_id)}">${esc(bits.join(' — '))}</option>`;
      }).join('');
    }
  }

  async function onEngagementChange() {
    const select = el('incidentEngagementSelect');
    if (select && select.value) S.engagementId = select.value;
    if (!S.engagementId) return;

    stopPoll();
    destroyBoard();
    S.targets = [];
    S.excluded = new Set();
    S.selectedId = null;
    S.runs = [];
    S.runId = null;
    S.status = null;

    const launcher = el('incidentLauncher');
    if (launcher) launcher.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(3);

    // The catalog is static for the life of the server process and cached
    // privately for five minutes, so re-fetching it per engagement costs one
    // conditional round trip and keeps the state simple.
    try {
      S.catalog = await inc('/catalog');
    } catch (err) {
      if (launcher) {
        launcher.innerHTML = '<div class="card"><div class="card-body">'
          + `<p class="text-muted">${esc(explain(err))}</p></div></div>`;
      }
      return;
    }

    // The Client's own scenarios, and a failure here is NOT fatal the way a
    // missing catalog is. A Client whose profile has no threat scenarios — or
    // whose profile JSON has moved — is an ordinary state; the mode simply is
    // not offered, and the other three still are. Blanking the whole launcher
    // over it would take away the incident an instructor could still run.
    S.scenarios = [];
    S.scenarioChosen = null;
    try {
      const payload = await inc('/scenarios');
      S.scenarios = (payload && payload.scenarios) || [];
      S.scenarioChosen = (payload && payload.chosen) || null;
    } catch (err) {
      console.warn('[instructor-incidents] scenarios unavailable:', err && err.message);
    }
    // Lead with the Client's own incident when there is one, and fall back
    // rather than stranding the picker on a mode with nothing in it.
    S.mode = S.scenarios.length ? 'scenario' : 'technique';
    S.selectedId = S.scenarios.length && S.scenarioChosen
      && S.scenarios.some((x) => x.scenario_id === S.scenarioChosen)
      ? S.scenarioChosen : null;

    renderScopeMeta();
    renderLauncher();
    await refreshTargets();
    await loadRuns();
  }

  function renderScopeMeta() {
    const meta = el('incidentScopeMeta');
    if (!meta) return;
    const eng = S.engagements.find((e) => e.engagement_id === S.engagementId);
    if (!eng) { meta.textContent = ''; return; }
    const bits = [];
    if (eng.client_name) bits.push(`Client: ${eng.client_name}`);
    bits.push(`Engagement: ${eng.display_label || 'Defensive — monitoring'}`);
    const usable = S.targets.filter((t) => t.resolvable).length;
    if (S.targets.length) bits.push(`${usable} of ${S.targets.length} environments ready`);
    meta.textContent = bits.join(' · ');
  }

  // ── The launcher ──────────────────────────────────────────────────────────

  function renderLauncher() {
    const box = el('incidentLauncher');
    if (!box || !S.catalog) return;
    const chosen = currentSelection();

    box.innerHTML = `
      <div class="card" style="margin-bottom: 1rem;">
        <div class="card-header">
          <span class="card-title">&#9889; Launch an incident</span>
        </div>
        <div class="card-body">
          <p class="text-muted" style="margin: 0 0 0.75rem; font-size: 0.9rem;">
            Every environment in this engagement runs a sensor feeding its own SIEM. Launching fires
            the same activity into all of them at the same moment, and the events land beside the
            ordinary traffic the environment already generates. Nothing labels an event as the
            incident &mdash; finding it is the exercise.
          </p>

          <div style="display:flex; gap:0.5rem; flex-wrap:wrap; margin-bottom:1rem;">
            ${S.scenarios.length
              ? `<button class="btn btn-sm ${S.mode === 'scenario' ? 'btn-primary' : 'btn-outline'}"
                    onclick="Incidents.setMode('scenario')">This Client&rsquo;s Scenarios</button>`
              : ''}
            <button class="btn btn-sm ${S.mode === 'technique' ? 'btn-primary' : 'btn-outline'}"
                    onclick="Incidents.setMode('technique')">Techniques</button>
            <button class="btn btn-sm ${S.mode === 'tactic' ? 'btn-primary' : 'btn-outline'}"
                    onclick="Incidents.setMode('tactic')">Tactics</button>
            <button class="btn btn-sm ${S.mode === 'chain' ? 'btn-primary' : 'btn-outline'}"
                    onclick="Incidents.setMode('chain')">Attack Chains</button>
          </div>

          <div id="incidentPicker"></div>

          <div style="display:flex; gap:1.5rem; align-items:flex-end; flex-wrap:wrap;
                      margin-top:1.25rem; padding-top:1rem; border-top:1px solid var(--border-color);">
            <div>
              <label for="incidentDuration" style="display:block; font-size:0.8rem; font-weight:600;
                     color:var(--gray-500);">Duration</label>
              <select id="incidentDuration" class="form-input" style="min-width:11rem;"
                      ${S.mode === 'chain' ? 'disabled' : ''}>
                ${DURATIONS.map(([secs, label]) => {
                  // Disabled HERE so the instructor finds out before launching
                  // rather than environment by environment: compressing a
                  // 90-second burst into 20 seconds is not a faster burst, it is
                  // a truncated one that loses the event at the end.
                  const off = !allowedDuration(chosen, secs);
                  const sel = secs === 1800 && !off ? 'selected' : '';
                  return `<option value="${secs}" ${off ? 'disabled' : ''} ${sel}>`
                    + `${esc(label)}${off ? ' — too short for this selection' : ''}</option>`;
                }).join('')}
              </select>
              ${S.mode === 'chain'
                ? `<div style="font-size:0.72rem; color:var(--gray-500); margin-top:0.25rem; max-width:16rem;">
                     Attack chains run their own scripted length${chosen && chosen.estimated_minutes
                       ? ` — about ${esc(String(chosen.estimated_minutes))} minutes` : ''}.
                   </div>`
                : ''}
            </div>
            <div>
              <div style="font-size:0.8rem; font-weight:600; color:var(--gray-500);">Selected</div>
              <div style="font-weight:600; padding:0.4rem 0;">
                ${chosen
                  ? esc(chosen.name || chosen.id || chosen.scenario_id)
                  : '<span style="color:var(--gray-500); font-weight:400;">nothing yet</span>'}
              </div>
            </div>
            <div style="flex:1;"></div>
            <button class="btn btn-primary" id="incidentLaunchBtn"
                    onclick="Incidents.launch(this)" ${chosen ? '' : 'disabled'}>
              Launch into selected environments
            </button>
          </div>
        </div>
      </div>

      <div class="card" style="margin-bottom: 1rem;">
        <div class="card-header" style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem;">
          <span class="card-title">&#128421;&#65039; Environments</span>
          <button class="btn btn-outline btn-sm" onclick="Incidents.refreshTargets()">&#8635; Refresh</button>
        </div>
        <div class="card-body" id="incidentTargets"></div>
      </div>`;

    renderPicker();
    renderTargets();
  }

  function renderPicker() {
    const box = el('incidentPicker');
    if (!box) return;

    if (S.mode === 'scenario') {
      if (!S.scenarios.length) {
        box.innerHTML = '<p class="text-muted" style="margin:0; font-size:0.85rem;">'
          + 'This Client&rsquo;s profile declares no threat scenarios, so there is nothing to '
          + 'compile an incident from. Pick a technique, a tactic or an attack chain instead.</p>';
        return;
      }
      box.innerHTML = '<div style="display:grid; gap:0.75rem; grid-template-columns:repeat(auto-fit,minmax(20rem,1fr));">'
        + S.scenarios.map((sc) => {
          const isChosen = sc.scenario_id === S.scenarioChosen;
          return `
          <div onclick="Incidents.select('${escJs(sc.scenario_id)}')"
               style="cursor:pointer; padding:0.85rem; border-radius:6px;
                      border:2px solid ${S.selectedId === sc.scenario_id ? 'var(--primary)' : 'var(--border-color)'};">
            <div style="font-weight:600;">${esc(sc.name || sc.scenario_id)}</div>
            <div style="font-size:0.75rem; color:var(--gray-500); margin:0.25rem 0;">
              ${esc(sc.scenario_id)}${sc.type ? ` &middot; ${esc(sc.type)}` : ''} &middot;
              ${esc(String(sc.technique_count))} technique${sc.technique_count === 1 ? '' : 's'}
              across ${esc(String(sc.step_count))} phase${sc.step_count === 1 ? '' : 's'}
            </div>
            ${sc.threat_actor
              ? `<div style="font-size:0.8rem;">${esc(sc.threat_actor)}</div>` : ''}
            ${sc.initial_vector
              ? `<div style="font-size:0.78rem; color:var(--gray-500);">via ${esc(sc.initial_vector)}</div>` : ''}
            ${isChosen
              ? '<div style="font-size:0.72rem; margin-top:0.4rem; color:var(--primary);">'
                + '&#10003; the ordinary traffic in these Environments was built around this one</div>'
              : ''}
          </div>`;
        }).join('')
        + '</div>'
        + '<p style="font-size:0.78rem; color:var(--gray-500); margin-top:0.5rem;">'
        + 'A scenario runs against this Client&rsquo;s own machines, accounts and addresses &mdash; '
        + 'every host it names is one the Environment&rsquo;s ordinary traffic also names, which is '
        + 'what stops a single search from separating the two. Launching a scenario the '
        + 'Environments were not built around still works, and the background traffic will keep '
        + 'describing the previous one until they are rebuilt.</p>';
      return;
    }

    if (!S.catalog) return;

    if (S.mode === 'chain') {
      box.innerHTML = '<div style="display:grid; gap:0.75rem; grid-template-columns:repeat(auto-fit,minmax(18rem,1fr));">'
        + (S.catalog.chains || []).map((c) => `
          <div onclick="Incidents.select('${escJs(c.key)}')"
               style="cursor:pointer; padding:0.85rem; border-radius:6px;
                      border:2px solid ${S.selectedId === c.key ? 'var(--primary)' : 'var(--border-color)'};">
            <div style="font-weight:600;">${esc(c.name)}</div>
            <div style="font-size:0.75rem; color:var(--gray-500); margin:0.25rem 0;">
              ${esc(c.category)} · ${esc(c.difficulty)} · ~${esc(String(c.estimated_minutes))} min ·
              ${esc(String((c.techniques || []).length))} techniques
            </div>
            <div style="font-size:0.8rem;">${esc(c.description)}</div>
          </div>`).join('')
        + '</div>';
      return;
    }

    if (S.mode === 'tactic') {
      box.innerHTML = '<div style="display:grid; gap:0.4rem; grid-template-columns:repeat(auto-fit,minmax(14rem,1fr));">'
        + (S.catalog.tactics || []).map((t) => `
          <div onclick="Incidents.select('${escJs(t.id)}')"
               style="cursor:pointer; padding:0.5rem 0.7rem; border-radius:4px;
                      border:2px solid ${S.selectedId === t.id ? 'var(--primary)' : 'var(--border-color)'};">
            <strong>${esc(t.id)}</strong> ${esc(t.name)}
          </div>`).join('')
        + '</div>'
        + '<p style="font-size:0.78rem; color:var(--gray-500); margin-top:0.5rem;">'
        + 'A tactic matches every technique beneath it, so it produces noticeably more events than '
        + 'any single technique. It is also the one mode with <strong>no answer key</strong>: a '
        + 'dozen unrelated behaviours have no single honest story to script, so every claim comes '
        + 'back unscored and you decide each one yourself.</p>';
      return;
    }

    const q = S.search.trim().toLowerCase();
    const rows = (S.catalog.techniques || []).filter((t) => {
      if (S.tacticFilter && t.tactic !== S.tacticFilter) return false;
      if (!q) return true;
      return `${t.id} ${t.name} ${t.description} ${(t.keywords || []).join(' ')}`
        .toLowerCase().includes(q);
    });

    box.innerHTML = `
      <div style="display:flex; gap:0.5rem; margin-bottom:0.5rem; flex-wrap:wrap;">
        <input id="incidentSearch" type="search" class="form-input" style="flex:1; min-width:12rem;"
               placeholder="Search techniques&hellip;" value="${esc(S.search)}"
               oninput="Incidents.setSearch(this.value)">
        <select class="form-input" style="max-width:16rem;" onchange="Incidents.setTactic(this.value)">
          <option value="">All tactics</option>
          ${(S.catalog.tactics || []).map((t) => `<option value="${esc(t.id)}"`
            + `${S.tacticFilter === t.id ? ' selected' : ''}>${esc(t.id)} ${esc(t.name)}</option>`).join('')}
        </select>
      </div>
      <div style="max-height:22rem; overflow:auto; border:1px solid var(--border-color); border-radius:6px;">
        <table style="width:100%; border-collapse:collapse; font-size:0.85rem;">
          <thead><tr style="position:sticky; top:0; background:var(--bg-page);">
            <th style="text-align:left; padding:0.45rem;">ID</th>
            <th style="text-align:left; padding:0.45rem;">Technique</th>
            <th style="text-align:left; padding:0.45rem;">Tactic</th>
            <th style="text-align:left; padding:0.45rem;">Matches on</th>
            <th style="text-align:left; padding:0.45rem;">Yield</th>
          </tr></thead>
          <tbody>
            ${rows.length === 0
              ? '<tr><td colspan="5" style="padding:1rem; color:var(--gray-500);">No technique matches that filter.</td></tr>'
              : rows.map((t) => `
              <tr onclick="Incidents.select('${escJs(t.id)}')"
                  style="cursor:pointer; border-top:1px solid var(--border-color);
                         ${S.selectedId === t.id ? 'background:rgba(49,130,206,.12);' : ''}">
                <td style="padding:0.45rem; font-family:monospace;">${esc(t.id)}</td>
                <td style="padding:0.45rem;">${esc(t.name)}
                  <div style="font-size:0.74rem; color:var(--gray-500);">${esc(t.description)}</div></td>
                <td style="padding:0.45rem; font-size:0.78rem;">${esc(t.tactic_name || t.tactic)}</td>
                <td style="padding:0.45rem; font-family:monospace; font-size:0.72rem; color:var(--gray-500);">
                  ${esc((t.keywords || []).join(', '))}</td>
                <td style="padding:0.45rem;">${yieldCell(t)}</td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  }

  function renderTargets() {
    const box = el('incidentTargets');
    if (!box) return;

    if (!S.targets.length) {
      box.innerHTML = '<p class="text-muted" style="margin:0; font-size:0.9rem;">'
        + 'No environments are deployed in this engagement yet. Deploy them first &mdash; an incident '
        + 'fires into a running sensor, so there is nothing to send it to.</p>';
      return;
    }

    const usable = S.targets.filter((t) => t.resolvable).length;
    const chosen = S.targets.filter((t) => t.resolvable && !S.excluded.has(String(t.lane_id))).length;

    box.innerHTML = `
      <p class="text-muted" style="font-size:0.85rem; margin:0 0 0.5rem;">
        ${chosen} of ${usable} usable environment(s) selected${S.targets.length - usable > 0
          ? ` · ${S.targets.length - usable} cannot be targeted` : ''}
      </p>
      <div style="overflow-x:auto;">
      <table style="width:100%; border-collapse:collapse; font-size:0.85rem;">
        <thead><tr style="background:var(--bg-page);">
          <th style="width:2rem; padding:0.4rem;"></th>
          <th style="text-align:left; padding:0.4rem;">Student</th>
          <th style="text-align:left; padding:0.4rem;">Sensor VM</th>
          <th style="text-align:left; padding:0.4rem;">Found by</th>
          <th style="text-align:left; padding:0.4rem;">State</th>
        </tr></thead>
        <tbody>
        ${S.targets.map((t) => `
          <tr style="border-top:1px solid var(--border-color); ${t.resolvable ? '' : 'opacity:.6;'}">
            <td style="padding:0.4rem; text-align:center;">
              <input type="checkbox" ${t.resolvable ? '' : 'disabled'}
                     ${t.resolvable && !S.excluded.has(String(t.lane_id)) ? 'checked' : ''}
                     onchange="Incidents.toggleEnvironment('${escJs(t.lane_id)}', this.checked)">
            </td>
            <td style="padding:0.4rem;">${esc(t.student_email || t.user_id || '—')}</td>
            <td style="padding:0.4rem; font-family:monospace; font-size:0.78rem;">
              ${t.vmid ? esc(`${t.vm_name || ''} (${t.vmid})`) : '—'}</td>
            <td style="padding:0.4rem; font-size:0.75rem; color:var(--gray-500);">
              ${t.resolved_by ? esc(t.resolved_by) : '—'}</td>
            <td style="padding:0.4rem; font-size:0.78rem;">
              ${t.resolvable
                ? '<span style="color:var(--success);">ready</span>'
                : `<span style="color:var(--danger);">${esc(t.skip_reason || 'unavailable')}</span>`}</td>
          </tr>`).join('')}
        </tbody>
      </table>
      </div>`;
  }

  // ── The run card ──────────────────────────────────────────────────────────

  function renderRun() {
    const box = el('incidentRun');
    if (!box) return;

    if (!S.runs.length) {
      box.innerHTML = '';
      return;
    }

    const run = S.runs.find((r) => r.run_id === S.runId) || S.runs[0];
    const status = (S.status && S.status.run_id === run.run_id) ? S.status : null;
    const state = (status && status.status) || run.status;
    const live = isLive(state);
    const released = !!(status && status.released);
    const submitted = status ? status.submitted : null;

    // The release banner. Release is the gate that turns "submitted" into
    // verdicts for a student, and it is the single most consequential control on
    // this screen — so it is a banner and not a word in a button's tooltip.
    const banner = released
      ? '<div style="margin-top:0.85rem; padding:0.7rem 0.9rem; border-radius:6px;'
        + ' border-left:4px solid var(--success); background:rgba(79,145,83,.12);">'
        + '<strong>Verdicts are open.</strong> Every student in this engagement can now see their '
        + 'score and the verdict on each thing they recorded. <em>Retract</em> on the board below '
        + 'puts them back out of sight.</div>'
      : '<div style="margin-top:0.85rem; padding:0.7rem 0.9rem; border-radius:6px;'
        + ' border-left:4px solid var(--warning); background:rgba(245,158,11,.12);">'
        + '<strong>Verdicts are hidden.</strong> Students can see what they recorded and nothing '
        + 'else &mdash; no score, no right-or-wrong, no count of what they missed. Press '
        + '<em>Release scores</em> on the board below when you want that opened.</div>';

    box.innerHTML = `
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header" style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem;">
          <span class="card-title">&#128300; Incident</span>
          ${S.runs.length > 1
            ? `<select class="form-input" style="max-width:24rem;" onchange="Incidents.selectRun(this.value)">
                 ${S.runs.map((r) => `<option value="${esc(r.run_id)}"${r.run_id === run.run_id ? ' selected' : ''}>`
                   + `${esc(runLabel(r))} · ${esc(r.status)} · ${esc(timeAgo(r.created_at))}</option>`).join('')}
               </select>`
            : ''}
        </div>
        <div class="card-body">
          <div style="display:flex; gap:1rem; align-items:center; flex-wrap:wrap;">
            <strong>${esc(runLabel(run))}</strong>
            ${statusChip(state)}
            ${run.duration_seconds
              ? `<span class="text-muted" style="font-size:0.85rem;">for ${esc(fmtDuration(run.duration_seconds))}</span>`
              : ''}
            <span class="text-muted" style="font-size:0.85rem;">launched ${esc(timeAgo(run.created_at))}</span>
            <span style="flex:1;"></span>
            ${submitted != null
              ? `<span style="font-size:0.85rem;">recorded so far: <strong>${esc(String(submitted))}</strong></span>`
              : ''}
            ${live
              ? '<button class="btn btn-outline btn-sm" onclick="Incidents.abort(this)">Abort</button>'
              : ''}
            ${!live && (state === 'partial' || state === 'failed')
              ? '<button class="btn btn-outline btn-sm" onclick="Incidents.retry(this)">Re-fire the environments that missed</button>'
              : ''}
          </div>
          ${run.error
            ? `<p style="margin:0.6rem 0 0; color:var(--danger); font-size:0.85rem;">${esc(run.error)}</p>`
            : ''}
          ${banner}
        </div>
      </div>`;
  }

  // ── The board ─────────────────────────────────────────────────────────────

  function destroyBoard() {
    if (S.board && typeof S.board.destroy === 'function') {
      try { S.board.destroy(); } catch (e) { /* a torn-down board is still gone */ }
    }
    S.board = null;
    S.boardRunId = null;
    const box = el('incidentBoard');
    if (box) box.innerHTML = '';
  }

  /**
   * Mount the shared board for the selected incident.
   *
   * `role: 'staff'` picks the LAYOUT and is not a permission: the server returns
   * a `tier` on every read and the component renders the tier it was GIVEN. The
   * answer key never travels — src/incident/projection.js owns that — so the
   * worst an edited role can do here is draw a staff layout around a student
   * payload, which is an empty table.
   */
  function mountBoard() {
    const box = el('incidentBoard');
    if (!box) return;
    if (!S.runId) { destroyBoard(); return; }
    if (S.boardRunId === S.runId && S.board) return;

    destroyBoard();

    if (!window.BlueTeamBoard || !window.BlueTeamApi
        || !window.BlueTeamTimeline || !window.BlueTeamScore) {
      // Loud rather than blank. The four /js/blueteam/*.js tags must be present
      // AND in the order api -> timeline -> score -> board; blueteam-board.js
      // reads the other three off window when it mounts.
      console.error('[instructor-incidents] the blue-team board scripts are missing or out of order; '
        + 'instructor.html must load /js/blueteam/blueteam-api.js, blueteam-timeline.js, '
        + 'blueteam-score.js and blueteam-board.js, in that order, before this file.');
      box.innerHTML = '<div class="card"><div class="card-body"><p class="text-muted">'
        + 'The board did not load. Reload the page; if it persists, the script order in '
        + 'instructor.html is wrong.</p></div></div>';
      return;
    }

    try {
      S.board = window.BlueTeamBoard.mount(box, {
        base: boardBase(S.engagementId),
        role: 'staff',
        runId: S.runId,
      });
      S.boardRunId = S.runId;
    } catch (err) {
      box.innerHTML = '<div class="card"><div class="card-body"><p class="text-muted">'
        + `${esc((err && err.message) || 'The board could not be opened.')}</p></div></div>`;
    }
  }

  // ── Runs + polling ────────────────────────────────────────────────────────

  async function loadRuns({ keepSelection = false } = {}) {
    try {
      const data = await inc('');
      S.runs = data.runs || [];
    } catch (err) {
      S.runs = [];
      renderRun();
      return;
    }
    if (!S.runs.length) { S.runId = null; S.status = null; renderRun(); destroyBoard(); return; }

    const stillThere = keepSelection && S.runs.some((r) => r.run_id === S.runId);
    if (!stillThere) S.runId = S.runs[0].run_id;

    renderRun();
    mountBoard();
    await pollOnce().catch(() => {});
    const run = S.runs.find((r) => r.run_id === S.runId);
    if (run && isLive(run.status)) startPoll();
  }

  async function pollOnce() {
    if (!S.runId || !S.engagementId) return null;
    const data = await inc(`/${encodeURIComponent(S.runId)}/status`);
    S.status = data;
    // Keep the row in the list honest too, so the history dropdown and the run
    // card cannot disagree about what happened.
    const run = S.runs.find((r) => r.run_id === data.run_id);
    if (run) { run.status = data.status; run.finished_at = data.finished_at; }
    renderRun();
    return data;
  }

  function startPoll() {
    stopPoll();
    S.pollTimer = setInterval(async () => {
      // Stop condition three: the instructor has moved to another tab. See the
      // file header — activateTabModule() has no leave hook, and a timer that
      // outlives its panel repaints a screen nobody is looking at.
      if (!panelIsActive()) { stopPoll(); return; }
      try {
        const data = await pollOnce();
        if (data && !isLive(data.status)) {
          stopPoll();
          // The list carries columns /status does not (the error, the selection),
          // and a finished run is exactly when those matter.
          await loadRuns({ keepSelection: true }).catch(() => {});
        }
      } catch (err) {
        // A transient failure must not kill the poller; a persistent one is
        // visible because the card stops advancing.
        console.warn('[instructor-incidents] poll failed:', err && err.message);
      }
    }, POLL_MS);
  }

  function stopPoll() {
    if (S.pollTimer) clearInterval(S.pollTimer);
    S.pollTimer = null;
  }

  // ── Actions ───────────────────────────────────────────────────────────────

  async function refreshTargets() {
    if (!S.engagementId) return;
    try {
      const data = await inc('/targets');
      S.targets = data.targets || [];
      // Never carry an exclusion across a refresh for an environment that no
      // longer exists: it would silently shrink a later launch.
      const alive = new Set(S.targets.map((t) => String(t.lane_id)));
      S.excluded = new Set([...S.excluded].filter((id) => alive.has(id)));
    } catch (err) {
      S.targets = [];
      Toast.error('Environments', explain(err));
    }
    renderTargets();
    renderScopeMeta();
  }

  async function launch(btn) {
    const selection = currentSelection();
    if (!selection) {
      Toast.error('Nothing selected',
        'Pick one of this Client’s scenarios, a technique, a tactic or an attack chain first.');
      return;
    }

    // OPT-OUT, not opt-in. An environment deployed between opening this tab and
    // pressing Launch is then included by default; sending an explicit include
    // list would silently leave that student out of the exercise, which is the
    // failure nobody notices until grading.
    const body = { mode: S.mode, exclude_lane_ids: [...S.excluded] };
    if (S.mode === 'scenario') body.scenario_id = selection.scenario_id;
    else if (S.mode === 'chain') body.chain_key = selection.key;
    else if (S.mode === 'tactic') body.tactic_id = selection.id;
    else body.technique_id = selection.id;
    // Deliberately omitted for a chain: the server REFUSES a duration on one
    // rather than silently ignoring it, and a database constraint backs that up.
    if (S.mode !== 'chain') {
      const dur = el('incidentDuration');
      if (dur) body.duration_seconds = Number(dur.value);
    }

    if (btn) Utils.setBtnLoading(btn, true, 'Launching…');
    try {
      const res = await inc('', { method: 'POST', body });
      S.runId = res.run_id;
      S.status = null;
      Toast.success('Incident launched', 'Dispatching to every selected environment.');
      await loadRuns({ keepSelection: true });
      startPoll();
    } catch (err) {
      Toast.error('Could not launch', explain(err));
    } finally {
      if (btn) Utils.setBtnLoading(btn, false);
    }
  }

  async function abort(btn) {
    if (!S.runId) return;
    const ok = await Confirm.show({
      title: 'Abort this incident?',
      message: 'Every environment still running it is signalled to stop. What students have already '
             + 'recorded is kept, and the incident cannot be resumed — you would launch a new one.',
      confirmText: 'Abort',
      danger: true,
    });
    if (!ok) return;
    if (btn) Utils.setBtnLoading(btn, true, 'Aborting…');
    try {
      await inc(`/${encodeURIComponent(S.runId)}/abort`, { method: 'POST', body: {} });
      Toast.info('Abort sent', 'Every environment still running it has been signalled.');
      startPoll();
    } catch (err) {
      Toast.error('Could not abort', explain(err));
    } finally {
      if (btn) Utils.setBtnLoading(btn, false);
    }
  }

  async function retry(btn) {
    if (!S.runId) return;
    if (btn) Utils.setBtnLoading(btn, true, 'Re-firing…');
    try {
      // No selection in the body: a retry means what the ORIGINAL launch meant,
      // rebuilt server side from the stored row. Sending one here would let a
      // retry quietly become a different incident from the one students were
      // graded against.
      await inc(`/${encodeURIComponent(S.runId)}/retry`, { method: 'POST', body: {} });
      Toast.info('Re-firing', 'The environments that missed are being sent it again.');
      startPoll();
    } catch (err) {
      Toast.error('Could not re-fire', explain(err));
    } finally {
      if (btn) Utils.setBtnLoading(btn, false);
    }
  }

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  /**
   * Called by activateTabModule() every time this tab is entered.
   *
   * First entry does the loading. Later entries only RESUME: the expensive walk
   * is section -> modules -> clients -> engagements, and repeating it on every
   * tab flip would make the dashboard feel broken. Whatever the instructor left
   * selected is still selected, and a run that is still in flight starts polling
   * again — the poll stopped itself when the panel went inactive.
   */
  function ensureInit() {
    if (!S.booted) {
      S.booted = true;
      load().catch((err) => {
        console.error('[instructor-incidents] load failed:', err);
        emptyState('&#9888;&#65039;', 'Incidents did not load',
          `${esc((err && err.message) || 'Request failed')}<br>Reload the page to try again.`);
      });
      return;
    }
    const run = S.runs.find((r) => r.run_id === S.runId);
    if (run && isLive(run.status)) { pollOnce().catch(() => {}); startPoll(); }
  }

  window.Incidents = {
    ensureInit,
    onSectionChange,
    onEngagementChange,
    refreshTargets,
    launch,
    abort,
    retry,
    selectRun(runId) {
      if (!runId || runId === S.runId) return;
      stopPoll();
      S.runId = runId;
      S.status = null;
      renderRun();
      mountBoard();
      pollOnce().then((data) => { if (data && isLive(data.status)) startPoll(); }).catch(() => {});
    },
    setMode(mode) { S.mode = mode; S.selectedId = null; renderLauncher(); },
    select(id) { S.selectedId = id; renderLauncher(); },
    setSearch(value) {
      S.search = value;
      renderPicker();
      // Re-rendering the picker replaces the input, so put the caret back where
      // the instructor left it or every keystroke would lose focus.
      const input = el('incidentSearch');
      if (input) { input.focus(); input.setSelectionRange(input.value.length, input.value.length); }
    },
    setTactic(value) { S.tacticFilter = value; renderPicker(); },
    toggleEnvironment(laneId, checked) {
      if (checked) S.excluded.delete(String(laneId)); else S.excluded.add(String(laneId));
      renderTargets();
      renderScopeMeta();
    },
    // Exposed for the same reason the neighbouring console exposes its own: a
    // page that navigates away should be able to stop the timer.
    stopPoll,
  };

  // ── The load-order guard ──────────────────────────────────────────────────
  //
  // A BARE read inside try/catch, deliberately NOT `typeof esc`: typeof is the
  // one operator that cannot throw on an undeclared name, so it reports success
  // on exactly the failure being tested for. `esc` and `escJs` are top-level
  // consts in instructor-core.js, which makes them global LEXICAL bindings — not
  // window properties — so a tag placed before that file reads them inside their
  // temporal dead zone and every render in this file throws.
  (function checkLoadOrder() {
    let ok = true;
    try { void esc; void escJs; void timeAgo; } catch (e) { ok = false; }
    if (ok) return;
    console.error('[instructor-incidents] this file ran before instructor-core.js. '
      + 'instructor.html must load app.js, ciab-api.js, layout.js, instructor-core.js, '
      + 'then /js/blueteam/blueteam-api.js, blueteam-timeline.js, blueteam-score.js, '
      + 'blueteam-board.js, and only then instructor-incidents.js.');
    const panel = document.getElementById('tab-incidents');
    if (panel) {
      panel.innerHTML = '<div class="card"><div class="empty-state">'
        + '<div class="icon">&#9888;&#65039;</div><h3>Incidents did not load</h3>'
        + '<p>This tab&rsquo;s script ran before the dashboard it attaches to. '
        + 'Reload the page; if it persists, the script order in instructor.html is wrong.</p>'
        + '</div></div>';
    }
  }());
}());
