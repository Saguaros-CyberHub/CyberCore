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
 * ── ATTACK AUTHORING, AND WHY IT IS RENDERED HERE ───────────────────────────
 * Adversaries are built in a separate Caldera console on a machine outside every
 * lane, with no agents on it: it executes nothing. This panel is where an
 * instructor prepares that console for THIS course and then opens it.
 *
 * "Adding rendering here would fork the board" still holds — and this is not the
 * board. It renders no finding, no timeline and no score, it reads no run, and
 * it is drawn only for tier === 'staff'. A student's payload never carries a
 * tier of 'staff' (routes/incidents.js resolves it per request against this
 * course), so a student sees no part of it.
 *
 * THE ORDER OF TWO REQUESTS IS THE WHOLE FEATURE. The console has no idea which
 * course anybody is authoring for — it has no per-user view and no ownership at
 * all — so what it must be told is a set of facts: the machines this course
 * actually deployed. POST .../authoring/fact-source refreshes those, and the
 * link is not rendered until that answer comes back `ready`.
 *
 * DO NOT REPLACE THAT WITH A PLAIN <a href>. A link followed before the refresh
 * lands is an instructor authoring against the machines the PREVIOUS deployment
 * had. It fails invisibly: the adversary is built, the console still holds last
 * term's facts, and every step aimed at a machine this course does not have
 * simply never runs while the operation reports success.
 *
 * AND PICKING ONE CANNOT LAUNCH IT. Nothing in this file sends an adversary id
 * anywhere; routes/attacks.js — the file that can launch — takes no such
 * parameter, and the engine registry refuses the engine outright. The panel says
 * so in a sentence rather than greying a control out.
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
  var authoring = null;         // the attack-authoring panel's state; see below
  var mountedRunId = null;      // which run the board is showing, so a re-render keeps it

  /**
   * The authoring panel's whole state, blank.
   *
   * `state` is ONE discriminant rather than a pair of booleans because the link
   * and the platform summary arrive in one answer and must be shown together or
   * not at all — two flags would admit a state that shows the link without the
   * summary, which is the failure the ordering rule exists to prevent.
   */
  function blankAuthoring() {
    return {
      state: 'idle',      // idle | working | ready | unavailable
      reason: null,
      data: null,
      list: 'idle',       // the adversary picker's own load state
      listReason: null,
      items: [],
      picked: null,       // an id on this page and nowhere else
      upstream: null
    };
  }

  /**
   * One request against the authoring endpoints.
   *
   * WHY THIS IS NOT A BlueTeamApi METHOD. That module is CORE and is shared
   * verbatim with the Clinic-in-a-Box board, whose incidents collection has no
   * authoring endpoints at all: adding two methods there would put dead calls in
   * a component two products mount. The auth header is built the same way
   * BlueTeamApi builds it — a bearer token read fresh from localStorage per
   * request, because a token can be rotated mid-page — and this file's single
   * /api/ literal is still BASE_PATH, which is what test/blueteam-mount.test.js
   * pins.
   */
  function authoringRequest(path, options) {
    var opts = options || {};
    var headers = { 'Content-Type': 'application/json' };
    var token = null;
    try { token = localStorage.getItem('token'); } catch (e) { token = null; }
    if (token) headers.Authorization = 'Bearer ' + token;
    return fetch(baseFor(currentCourseId) + path, {
      method: opts.method || 'GET',
      credentials: 'include',
      headers: headers,
      body: opts.method && opts.method !== 'GET' ? JSON.stringify(opts.body || {}) : undefined
    }).then(function (res) {
      return res.json().catch(function () { return {}; }).then(function (data) {
        if (!res.ok) throw new Error((data && data.error) || ('Request failed (' + res.status + ')'));
        return data;
      });
    });
  }

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

  /**
   * What an administrator has to do, per refusal code.
   *
   * The server answers in CODES and this file writes the sentences. The two
   * products on this platform deliberately do not share copy — the clinic side
   * says Engagement and Environment where this one says course and lane — and a
   * shared string is exactly how one product's nouns reach the other's screen.
   *
   * Every branch names an ACTION. "Authoring is unavailable" on its own sends an
   * instructor to a help desk that cannot help them either.
   */
  function authoringProblem(reason, upstream) {
    var where = upstream ? ' (' + escHtml(upstream) + ')' : '';
    switch (reason) {
      case 'not_configured':
        return 'Attack authoring is not set up on this platform. An administrator needs to tell '
          + 'CyberCore where the authoring machine is: set '
          + '<code>CALDERA_AUTHORING_UPSTREAM=&lt;host-or-ip&gt;:8888</code> on both the app and '
          + 'the proxy, then restart them.';
      case 'no_api_key':
        return 'The authoring machine' + where + ' is configured, but CyberCore has no key to '
          + 'read it with. An administrator needs to mount the red API key and point '
          + '<code>CALDERA_AUTHORING_API_KEY_FILE</code> at it.';
      case 'unreachable':
        return 'The authoring machine' + where + ' did not answer. It may be powered off, or the '
          + 'network path from this server to it may be down.';
      case 'unauthorized':
        return 'The authoring machine' + where + ' refused CyberCore&rsquo;s key. An administrator '
          + 'needs to re-issue it: the key CyberCore holds and the one on that machine are not '
          + 'the same.';
      case 'no_spec':
        return 'This course has nothing deployed to author against yet. Deploy the lanes first '
          + '&mdash; an adversary aimed at a machine that does not exist produces a step that '
          + 'silently never runs.';
      case 'sync_failed':
        return 'The authoring machine answered but would not accept this course&rsquo;s machine '
          + 'list, so nothing was changed there. An administrator can find the reason in the '
          + 'application log.';
      default:
        return 'Attack authoring could not be prepared. An administrator can find the reason in '
          + 'the application log.';
    }
  }

  /** "3 Windows machines and 1 Linux machine" — the sentence, not the object. */
  function platformSentence(p) {
    var parts = [];
    var n = function (count, word) { return count + ' ' + word + (count === 1 ? '' : 's'); };
    if (p.windows) parts.push(n(p.windows, 'Windows machine'));
    if (p.linux) parts.push(n(p.linux, 'Linux machine'));
    if (p.other) parts.push(n(p.other, 'machine of another or unrecorded type'));
    if (!parts.length) return 'no machines that can be targeted';
    if (parts.length === 1) return parts[0];
    return parts.slice(0, -1).join(', ') + ' and ' + parts[parts.length - 1];
  }

  /**
   * The adversary picker's markup.
   *
   * PICKING ONE IS NOT A LAUNCH AND MUST NOT LOOK LIKE ONE: there is no control
   * here that fires anything and no request in this file carries an adversary
   * id. The reason is spelled out rather than expressed as a disabled button —
   * an instructor who cannot tell why something is greyed out concludes the
   * platform is broken, and it is not broken, it is waiting on infrastructure
   * that has not been signed off.
   */
  function adversaryHtml(a) {
    var head = '<div style="display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap; margin-bottom:0.5rem;">'
      + '<strong style="font-size:0.9rem;">Adversaries on the authoring console</strong>'
      + '<span style="flex:1;"></span>'
      + '<button type="button" class="btn btn-secondary" id="blueTeamAdversaryRefresh"'
      + (a.list === 'working' ? ' disabled' : '') + '>&#8635; Refresh</button></div>';

    if (a.list === 'working') return head + '<p>Loading&hellip;</p>';
    if (a.list === 'unavailable') {
      return head + '<p style="font-size:0.85rem;">' + authoringProblem(a.listReason, a.upstream) + '</p>';
    }
    if (a.list === 'idle') return head + '<p style="font-size:0.85rem;">Not loaded yet.</p>';
    if (!a.items.length) {
      return head + '<p style="font-size:0.85rem;">Nothing has been built on the authoring console '
        + 'yet. Open it above, build an adversary against the machines listed here, then refresh '
        + 'this list.</p>';
    }

    var rows = a.items.map(function (it) {
      var on = it.adversary_id === a.picked;
      return '<div class="blueTeamAdversary" data-adversary-id="' + escHtml(it.adversary_id) + '"'
        + ' style="cursor:pointer; padding:0.6rem 0.7rem; border-radius:6px; margin-bottom:0.4rem;'
        + ' border:2px solid ' + (on ? 'var(--primary, #2b6cb0)' : 'var(--border-color, #d7dbe0)') + ';">'
        + '<div style="font-weight:600; font-size:0.88rem;">' + escHtml(it.name) + '</div>'
        + '<div style="font-size:0.75rem; opacity:0.75;">' + escHtml(String(it.ability_count))
        + ' step(s)' + (it.description ? ' &middot; ' + escHtml(it.description) : '') + '</div>'
        + '</div>';
    }).join('');

    var picked = null;
    a.items.forEach(function (it) { if (it.adversary_id === a.picked) picked = it; });
    var note = picked
      ? '<div style="margin-top:0.6rem; padding:0.7rem 0.9rem; border-radius:6px;'
        + ' border-left:4px solid #f59e0b; background:rgba(245,158,11,.12); font-size:0.85rem;">'
        + '<strong>' + escHtml(picked.name) + ' is prepared, not scheduled.</strong> '
        + 'An adversary from this console cannot be fired into the lanes yet: that half is '
        + 'switched on once the cluster it needs has been signed off. Until then, launch from the '
        + 'Attack Console as usual.</div>'
      : '';

    return head + rows + note;
  }

  /**
   * The authoring panel, or NOTHING AT ALL for a student.
   *
   * The tier is the SERVER's, read off the run-list payload — see the header. A
   * student's payload never says 'staff', so this returns '' and no part of the
   * panel, its link, or its wording reaches them.
   */
  function authoringHtml() {
    if (tier !== 'staff') return '';
    var a = authoring || blankAuthoring();
    var head = '<div class="info-box" style="margin-bottom:1rem;">'
      + '<h4 style="margin:0 0 0.5rem;">Attack authoring</h4>';
    var tail = '</div>';

    if (a.state === 'idle' || a.state === 'working') {
      return head
        + '<p style="font-size:0.9rem;">Adversaries are built in a separate console that sits '
        + 'outside every lane and runs nothing. Before it opens, CyberCore refreshes what it knows '
        + 'about the machines this course actually deployed &mdash; so what you build there '
        + 'addresses machines that exist here.</p>'
        + '<button type="button" class="btn btn-primary" id="blueTeamAuthorBtn"'
        + (a.state === 'working' ? ' disabled' : '') + '>'
        + (a.state === 'working' ? 'Preparing&hellip;' : 'Author attacks') + '</button>'
        + tail;
    }

    if (a.state === 'unavailable') {
      // NO LINK ON THIS BRANCH, ever. A link to a machine that is not there, or
      // that CyberCore could not refresh, is worse than none: the instructor
      // authors anyway, against whatever it happens to hold.
      return head
        + '<p style="font-weight:600; margin:0 0 0.4rem;">Attack authoring is not set up.</p>'
        + '<p style="font-size:0.88rem;">' + authoringProblem(a.reason, a.upstream) + '</p>'
        + '<button type="button" class="btn btn-secondary" id="blueTeamAuthorBtn">Try again</button>'
        + tail;
    }

    var d = a.data || {};
    var plat = d.platforms || { windows: 0, linux: 0, other: 0 };
    var hosts = d.hosts || [];
    var warnings = d.warnings || [];
    var factName = (d.fact_source || {}).name || '';

    return head
      + '<p style="margin:0 0 0.5rem;"><strong>This course has ' + escHtml(platformSentence(plat))
      + '.</strong></p>'
      + '<p style="font-size:0.85rem;">The authoring console now holds this course&rsquo;s machine '
      + 'list under <code>' + escHtml(factName) + '</code>. Build against those names: anything '
      + 'else has nothing here to run on.</p>'
      + (hosts.length
        ? '<div style="font-family:monospace; font-size:0.75rem; opacity:0.75; margin:0 0 0.75rem;'
          + ' word-break:break-all;">'
          + hosts.map(function (h) { return escHtml(h.fqdn || h.name); }).join(' &middot; ')
          + '</div>'
        : '')
      + (warnings.length
        ? '<ul style="margin:0 0 0.75rem 1rem; padding:0; font-size:0.78rem;">'
          + warnings.slice(0, 3).map(function (w) { return '<li>' + escHtml(String(w)) + '</li>'; }).join('')
          + (warnings.length > 3
            ? '<li>and ' + (warnings.length - 3) + ' more &mdash; see the application log</li>' : '')
          + '</ul>'
        : '')
      + '<a class="btn btn-primary" href="' + escHtml(d.console_path || '') + '" target="_blank"'
      + ' rel="noopener noreferrer">Open the authoring console &#8599;</a>'
      + '<hr style="margin:1rem 0; border:0; border-top:1px solid var(--border-color, #d7dbe0);">'
      + adversaryHtml(a)
      + tail;
  }

  /**
   * Wire the panel's controls.
   *
   * addEventListener rather than an inline onclick, on markup this file builds
   * at runtime — the same rule roster-import.js documents and the same rule the
   * run picker below already follows.
   */
  function wireAuthoring() {
    // Each handler RETURNS its promise. A browser ignores the return value of a
    // listener, so this costs nothing there — and it is what lets
    // test/caldera-authoring-ui.test.js press the button the way a person does
    // and then await the result, instead of guessing at a number of ticks.
    var prepare = document.getElementById('blueTeamAuthorBtn');
    if (prepare) prepare.addEventListener('click', function () { return authorAttacks(); });

    var refresh = document.getElementById('blueTeamAdversaryRefresh');
    if (refresh) refresh.addEventListener('click', function () { return loadAdversaries(); });

    var rows = document.querySelectorAll('.blueTeamAdversary');
    Array.prototype.forEach.call(rows, function (row) {
      row.addEventListener('click', function () {
        // Sets a value on this page and does nothing else. Nothing reads it into
        // a request, and the launcher takes no adversary parameter.
        var id = row.getAttribute('data-adversary-id');
        authoring.picked = authoring.picked === id ? null : id;
        renderShell();
      });
    });
  }

  /**
   * "Author attacks" — refresh first, hand over the link second.
   *
   * The promise chain below IS the feature: nothing renders a link until the
   * server has answered ready, and it only fills console_path in once it has
   * refreshed this course's machine list on the authoring console.
   */
  function authorAttacks() {
    authoring = authoring || blankAuthoring();
    authoring.state = 'working';
    authoring.reason = null;
    renderShell();
    return authoringRequest('/authoring/fact-source', { method: 'POST', body: {} })
      .then(function (res) {
        authoring.upstream = res.upstream || null;
        if (res.ready) {
          authoring.state = 'ready';
          authoring.data = res;
          renderShell();
          // Only now, and only because the refresh landed.
          return loadAdversaries();
        }
        authoring.state = 'unavailable';
        authoring.reason = res.reason || 'error';
        renderShell();
        return undefined;
      })
      .catch(function (err) {
        // A failure from THIS platform, not from the authoring machine — that
        // one answers 200 with a reason. Same calm panel either way: the
        // instructor's next move is to tell an administrator.
        authoring.state = 'unavailable';
        authoring.reason = 'error';
        renderShell();
        if (window.console) window.console.warn('[blue-team] authoring prepare failed:', err && err.message);
      });
  }

  /** What the authoring console holds. A read; it changes nothing anywhere. */
  function loadAdversaries() {
    if (!authoring) return Promise.resolve();
    authoring.list = 'working';
    renderShell();
    return authoringRequest('/authoring/adversaries')
      .then(function (res) {
        authoring.upstream = res.upstream || authoring.upstream;
        if (res.ready) {
          authoring.list = 'ready';
          authoring.items = res.adversaries || [];
          // A pick that is gone from a store several instructors share is an
          // ordinary event, not an error: drop it rather than leave it pointing
          // at nothing.
          var still = false;
          authoring.items.forEach(function (x) { if (x.adversary_id === authoring.picked) still = true; });
          if (!still) authoring.picked = null;
        } else {
          authoring.list = 'unavailable';
          authoring.listReason = res.reason || 'error';
        }
      })
      .catch(function () {
        authoring.list = 'unavailable';
        authoring.listReason = 'error';
      })
      .then(function () { renderShell(); });
  }

  function renderShell() {
    var box = root();
    if (!box) return;

    // The authoring panel is drawn WHETHER OR NOT a run exists: an instructor
    // prepares the console before the first launch, which is precisely when
    // this course has no runs at all. It returns '' for a student.
    var authoringMarkup = authoringHtml();

    if (!runs.length) {
      box.innerHTML = authoringMarkup
        + '<div class="info-box"><p>No incidents have been run for this course yet. '
        + (tier === 'staff'
          ? 'Launch one from the Attack Console, then come back here to grade what the class found.'
          : 'Your instructor will start one during the exercise.')
        + '</p></div>';
      wireAuthoring();
      return;
    }

    box.innerHTML = authoringMarkup
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
    wireAuthoring();

    var select = document.getElementById('blueTeamRunSelect');
    select.addEventListener('change', function () { mountRun(select.value); });
    document.getElementById('blueTeamRefresh').addEventListener('click', function () {
      loadedForCourse = null;
      load();
    });

    // Newest first is the server's order, so the top entry is the run an
    // instructor just fired and the one a student is hunting right now.
    //
    // KEEP WHAT IS ALREADY MOUNTED. renderShell() is now re-entered by the
    // authoring panel above on every one of its state changes, and snapping back
    // to runs[0] there would tear an instructor off the incident they were
    // grading mid-click. mountedRunId is what the board is showing, if anything.
    var wanted = mountedRunId && runs.some(function (r) { return r.run_id === mountedRunId; })
      ? mountedRunId
      : runs[0].run_id;
    select.value = wanted;
    mountRun(wanted);
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
    mountedRunId = runId;
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
        if (!authoring) authoring = blankAuthoring();
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
    // A different course is a different set of machines, so every authored fact
    // about the last one is wrong here. Blanked rather than refreshed:
    // refreshing writes to a server every instructor shares, and nobody asked.
    authoring = null;
    mountedRunId = null;
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
    // Exposed for test/caldera-authoring-ui.test.js, which drives this file in a
    // sandbox to prove a student is rendered NOTHING of the panel. A getter, so
    // the test reads the same markup the shell writes rather than a copy of it.
    authoringHtml: authoringHtml
  };
})();
