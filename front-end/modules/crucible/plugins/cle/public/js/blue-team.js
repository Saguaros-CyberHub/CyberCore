/**
 * ============================================================================
 * CLE — CYBR 400 Blue Team Board (mount)
 * ============================================================================
 * The defensive half of the same course: an instructor fires an intrusion into
 * every lane, and this is where what the student concluded from hunting it is
 * recorded and graded.
 *
 * THIS FILE IS A MOUNT, NOT A BOARD. Everything the board does — the submit
 * form, the timeline, the scorecard, the instructor's overrides, the poll —
 * lives in /js/blueteam/*.js, which is core and is shared verbatim with the
 * Clinic-in-a-Box pages. All that differs between the two products is the
 * collection URL, so all this file does is:
 *
 *   1. work out that URL for the course currently open,
 *   2. ask the server which incidents exist and, in the same answer, WHO IT
 *      THINKS IS ASKING,
 *   3. let the viewer pick one, and hand the pair to BlueTeamBoard.mount().
 *
 * Adding rendering here would fork the board a third time. Don't.
 *
 * DEPENDS ON GLOBALS from courses.html's inline <script>: escHtml(),
 * currentCourseId. The <script> tag for this file MUST come after that block
 * and after the four /js/blueteam/*.js tags. (Same contract roster-import.js
 * documents.)
 *
 * ── WHY THE TIER COMES FROM THE SERVER, NOT FROM Auth.user.role ─────────────
 * GET /api/cle/courses/:id/incidents answers `{ tier, runs }`, and `tier` is
 * resolved per request against THIS course: manage it and you are staff,
 * enrolled in it and you are a student, neither and the whole router 404s. An
 * instructor is therefore staff on their own course and a STUDENT on a
 * colleague's — a distinction `Auth.user.role === 'instructor'` cannot make,
 * and getting it wrong here would draw the instructor layout over a student
 * payload. Read the tier the server volunteered; never infer it.
 *
 * And the tier passed to mount() is a LAYOUT HINT ONLY. blueteam-board.js
 * re-reads the tier off every board payload and renders that, so a viewer who
 * edits this value in the console gets the staff frame around a student
 * payload: an empty table, not a disclosure.
 *
 * ── WHAT THE RUN PICKER MAY SAY ─────────────────────────────────────────────
 * The label is built from whatever fields the payload actually carries.
 * src/incident/projection.js strips technique_id / tactic_id / chain_key /
 * playbook / answer_key from a student's run list at the SQL layer, so for a
 * student those keys are simply absent and the label falls back to the status
 * and the start time. That is why this reads optional fields instead of
 * branching on tier: the projection is the gate, and code that asks "am I
 * allowed to show this?" is code that can answer wrong.
 *
 * Nothing here may count anything, either. "6 techniques" is the hint that
 * tells a student when to stop hunting; it is withheld until release, and it
 * must not be reconstructed on the client.
 * ============================================================================
 */

/* global escHtml, currentCourseId */

(function () {
  'use strict';

  /**
   * The one URL in this file, in the shape routes/api.js mounts it.
   *
   * Kept as a literal with a placeholder rather than assembled from fragments
   * so test/blueteam-mount.test.js can compare it, character for character,
   * against the path the router is actually registered under. A base that has
   * drifted from the mount produces a 404 that looks exactly like "this course
   * has no incidents", which is the failure nobody reports as a bug.
   */
  var BASE_PATH = '/api/cle/courses/{courseId}/incidents';

  var loadedForCourse = null;   // which course the panel below was drawn for
  var tier = null;              // 'staff' | 'student', as the SERVER reported it
  var runs = [];
  var board = null;             // the BlueTeamBoard.mount() handle, or null

  var root = function () { return document.getElementById('blueTeamContent'); };

  function baseFor(courseId) {
    return BASE_PATH.replace('{courseId}', encodeURIComponent(courseId));
  }

  /** A short local timestamp; an unparseable or absent date renders as a dash. */
  function when(value) {
    if (!value) return '—';
    var t = Date.parse(value);
    return isFinite(t) ? new Date(t).toLocaleString() : '—';
  }

  /** One <option> label. See the header: optional fields only, no counting. */
  function runLabel(run) {
    var what = run.technique_id || run.chain_key || run.tactic_id || null;
    return (what ? what + ' · ' : '')
      + (run.status || 'unknown') + ' · ' + when(run.scheduled_start_at);
  }

  // ---- rendering ----------------------------------------------------------

  function renderShell() {
    var box = root();
    if (!box) return;

    if (!runs.length) {
      box.innerHTML = '<div class="info-box"><p>No incidents have been run for this course yet. '
        + (tier === 'staff'
          ? 'Launch one from the Attack Console, then come back here to grade what the class found.'
          : 'Your instructor will start one during the exercise.')
        + '</p></div>';
      return;
    }

    box.innerHTML = ''
      + '<div style="display:flex; gap:0.5rem; align-items:center; flex-wrap:wrap; margin-bottom:1rem;">'
      + '<label for="blueTeamRunSelect" style="font-size:0.85rem; color:var(--text-secondary);">Incident</label>'
      + '<select id="blueTeamRunSelect" style="min-width:22rem;">'
      + runs.map(function (r) {
        return '<option value="' + escHtml(r.run_id) + '">' + escHtml(runLabel(r)) + '</option>';
      }).join('')
      + '</select>'
      + '<button type="button" class="btn btn-secondary" id="blueTeamRefresh">↻ Refresh</button>'
      + '</div>'
      + '<div id="blueTeamBoard"></div>';

    // addEventListener rather than an inline onclick: the same rule
    // roster-import.js documents for markup it builds at runtime.
    var select = document.getElementById('blueTeamRunSelect');
    select.addEventListener('change', function () { mountRun(select.value); });
    document.getElementById('blueTeamRefresh').addEventListener('click', function () {
      loadedForCourse = null;
      load();
    });

    // Newest first is the server's order, so the top entry is the run an
    // instructor just fired and the one a student is hunting right now.
    mountRun(runs[0].run_id);
  }

  /**
   * Swap the board over to `runId`.
   *
   * destroy() FIRST, always. The board polls /status every 2s while a run is in
   * flight; a handle dropped without destroying keeps that timer alive and
   * keeps writing the previous run's payload into an element the new board now
   * owns. Same class of bug cancelCoursePollers() exists for in courses.html.
   */
  function mountRun(runId) {
    if (board) {
      try { board.destroy(); } catch (e) { /* already gone */ }
      board = null;
    }
    var host = document.getElementById('blueTeamBoard');
    if (!host || !runId) return;
    board = window.BlueTeamBoard.mount(host, {
      base: baseFor(currentCourseId),
      role: tier === 'staff' ? 'staff' : 'student',   // layout hint only; see the header
      runId: runId,
    });
  }

  // ---- loading ------------------------------------------------------------

  function load() {
    var box = root();
    if (!box) return Promise.resolve();

    if (!window.BlueTeamApi || !window.BlueTeamBoard) {
      box.innerHTML = '<p style="color:#ef4444;">The blue-team board failed to load.</p>';
      return Promise.resolve();
    }

    // Captured, and re-checked when the answer arrives: an instructor who
    // clicks Back and opens another course mid-request must not have this
    // course's incidents painted into that one.
    var courseId = currentCourseId;
    if (!courseId) return Promise.resolve();

    box.innerHTML = '<p style="color:var(--text-secondary);">Loading…</p>';

    return window.BlueTeamApi.create({ base: baseFor(courseId) }).listRuns()
      .then(function (data) {
        if (courseId !== currentCourseId) return;
        tier = data.tier === 'staff' ? 'staff' : 'student';
        runs = data.runs || [];
        loadedForCourse = courseId;
        renderShell();
      })
      .catch(function (err) {
        if (courseId !== currentCourseId) return;
        box.innerHTML = '<p style="color:#ef4444;">' + escHtml(err.message) + '</p>';
      });
  }

  // ---- lifecycle ----------------------------------------------------------

  /**
   * Tear down the mounted board and its poll timer.
   *
   * Named to match the other pollers on this page so it can be called from
   * cancelCoursePollers() alongside them.
   */
  function cancelPolling() {
    if (board) {
      try { board.destroy(); } catch (e) { /* already gone */ }
      board = null;
    }
  }

  /**
   * Called by viewCourse() when a different course is opened — including when
   * the tab is hidden, so the panel can never hold the previous course's runs.
   * Only in-memory state; the request itself is deferred to the first show.
   */
  function reset() {
    cancelPolling();
    tier = null;
    runs = [];
    loadedForCourse = null;
    var box = root();
    if (box) box.innerHTML = '<p style="color:var(--text-secondary);">Loading…</p>';
  }

  /**
   * First show of the tab for this course does the work.
   *
   * The board has no measure-on-init constraint the way the topology canvas
   * does — it is lazy because the run list is a request, and a course opened to
   * check its roster should not pay for a tab nobody looked at.
   */
  function onShow() {
    if (loadedForCourse === currentCourseId) return;
    load();
  }

  window.CleBlueTeam = {
    load: load,
    onShow: onShow,
    reset: reset,
    cancelPolling: cancelPolling,
  };
})();
