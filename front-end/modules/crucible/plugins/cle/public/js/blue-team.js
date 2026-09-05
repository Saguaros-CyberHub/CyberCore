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
 * Adversaries are built in a separate Caldera console outside every lane. This
 * panel prepares that console for THIS course; the agent dialog connects a
 * selected VM to it so an instructor can control it from the console.
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
 * ── AND A SECOND, SEPARATE PANEL: IS THE CONSOLE THERE AT ALL? ─────────────
 * "Author attacks" answers a question about THIS course: were its machines
 * pushed to the console, and what are they called there. GET
 * /api/caldera-authoring/status answers a question about the PLATFORM: has
 * anybody stood that console up, and is it answering right now.
 *
 * The second question has an answer before this course has deployed anything,
 * and the instructor who most needs to hear "it was never set up" is exactly
 * the one who has not pressed the button yet — so it is its own panel with its
 * own copy, drawn above the other one and gated on the same staff tier.
 *
 * THE ADDRESS COMES OFF THE PAYLOAD AND IS NEVER WRITTEN HERE. That console has
 * already moved once, from a path on this site to its own hostname; a link
 * assembled from a constant in a browser file outlives the deployment that made
 * it true, and the result is a 404 an instructor reports as a broken platform.
 * `console_url` is the address; `path` is a LEGACY CONSTANT the server emits on
 * every deployment whether or not one is set up. consoleAvailability() below
 * says which of the two may be read, when, and why reading the wrong one is how
 * a dead link gets shipped.
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

  /**
   * The PLATFORM's authoring-console endpoint — the second and last /api/
   * literal in this file, and the only one not addressed by course.
   *
   * test/blueteam-mount.test.js pins the whole set: the rule there is not "one
   * literal" for its own sake, it is that every /api/ string in this file is
   * one a test has checked against the route the server actually registers. A
   * third one added without touching that list fails the suite, which is the
   * point.
   */
  var STATUS_PATH = '/api/caldera-authoring/status';

  var loadedForCourse = null;   // which course the panel below was drawn for
  var tier = null;              // 'staff' | 'student', as the SERVER reported it
  var runs = [];
  var board = null;             // the BlueTeamBoard.mount() handle, or null
  var authoring = null;         // the attack-authoring panel's state; see below
  // The console's own availability: null, or { state, url }. A PLATFORM fact
  // rather than a course one, so it is not part of blankAuthoring() and is not
  // re-asked when the instructor presses Author attacks.
  //   probing  the status request is in flight
  //   ready    configured and answering; `url` is safe to link
  //   down     configured and did NOT answer — no link on this branch
  //   unset    nobody has told this platform where the console is
  //   error    the check itself failed, which is a different claim from "down"
  //   hidden   the endpoint refused this viewer; draw nothing whatsoever
  var consoleStatus = null;
  // The "you may not ask" answer, as an object nobody else can produce. See
  // refreshConsoleStatus().
  var REFUSED = {};
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
    return fetch(baseFor(opts.courseId || currentCourseId) + path, {
      method: opts.method || 'GET',
      credentials: 'include',
      signal: opts.signal,
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
        + 'Choosing it here does not start it. Open the Caldera console to run it against '
        + 'installed agents, or use the Attack Console for managed exercises.</div>'
      : '';

    return head + rows + note;
  }

  /**
   * One /status answer, reduced to the one state the panel can draw.
   *
   * TWO INDEPENDENT "CONFIGURED" FLAGS, because the server has two variables
   * that fail in two different ways and a link needs both:
   *
   *   console_configured / console_url  CALDERA_HOST - the console's own public
   *                                     hostname, where a BROWSER goes.
   *   configured / upstream             CALDERA_AUTHORING_UPSTREAM - where the
   *                                     proxy dials, container to container.
   *                                     Not resolvable from a browser and never
   *                                     rendered.
   *
   * Either can be set without the other, and with either missing the link is
   * dead, so both must hold before one is offered.
   *
   * `path` IS LEGACY AND IS A SERVER-SIDE CONSTANT: '/caldera' on every
   * deployment, set up or not, working only because the main site keeps a 302
   * from it to console_url. It is therefore read ONLY when the answer predates
   * console_configured altogether - on a server that sends that field, a null
   * console_url means there is no hostname to redirect TO. Reading it on the
   * older shape is what keeps this file correct whichever way round the two
   * halves of this feature were deployed.
   */
  function consoleAvailability(payload) {
    if (!payload) return { state: 'error', url: null };

    var hasConsoleFlag = typeof payload.console_configured === 'boolean';
    // '!== false' rather than truthiness: a field an older server omits is not
    // a field it denied.
    var proxied = payload.configured !== false;
    var published = hasConsoleFlag ? payload.console_configured : true;
    var raw = payload.console_url || (hasConsoleFlag ? null : payload.path);
    var url = typeof raw === 'string' && raw.trim() ? raw.trim() : null;

    // Reported apart from "did not answer" because the two send an
    // administrator to opposite places: one is a variable nobody set, the other
    // is a machine that is down.
    if (!proxied || !published || !url) return { state: 'unset', url: null };
    // Strictly === true: `reachable` is null when nothing was probed, and a
    // truthiness test would read that as up.
    if (payload.reachable !== true) return { state: 'down', url: null };
    return { state: 'ready', url: url };
  }

  /**
   * Ask whether the authoring console is set up, and whether it answered.
   *
   * NEVER REJECTS. Every outcome is a state the panel below can draw, including
   * the two that draw nothing at all.
   *
   * A STUDENT NEVER ASKS. The tier is the SERVER's word, resolved per request
   * against THIS course, and a viewer who is a student here is not merely
   * hidden from the panel — no request is made on their behalf either. The
   * endpoint would refuse them anyway (it is instructor/admin-only and answers
   * 403), and that refusal is handled as "there is no authoring surface for
   * you" rather than as an error: a red banner reading "Access denied" on a
   * course board would announce a surface they cannot have and cannot act on.
   */
  function refreshConsoleStatus() {
    if (tier !== 'staff') { consoleStatus = null; return Promise.resolve(); }
    consoleStatus = { state: 'probing', url: null };
    var headers = {};
    var token = null;
    try { token = localStorage.getItem('token'); } catch (e) { token = null; }
    if (token) headers.Authorization = 'Bearer ' + token;
    return fetch(STATUS_PATH, { method: 'GET', credentials: 'include', headers: headers })
      .then(function (res) {
        // Not an error. See above. Signalled by REFUSED's own identity rather
        // than by a flag on an object: a flag would be a key the payload could
        // one day carry for its own reasons, and this comparison cannot be
        // fooled by one.
        if (res.status === 401 || res.status === 403) return REFUSED;
        if (!res.ok) throw new Error('status ' + res.status);
        return res.json();
      })
      .then(function (payload) {
        if (payload === REFUSED) { consoleStatus = { state: 'hidden', url: null }; return; }
        consoleStatus = consoleAvailability(payload);
      })
      .catch(function () { consoleStatus = { state: 'error', url: null }; })
      .then(function () { renderShell(); });
  }

  /**
   * The console panel, or nothing.
   *
   * THE LINK IS ON EXACTLY ONE BRANCH: configured AND answering. A link to a
   * console that is not there is worse than none — the instructor follows it,
   * gets a browser error, and concludes the platform is broken — whereas a
   * sentence naming what is wrong is something they can hand to an
   * administrator.
   *
   * target="_blank" is load-bearing, not habit: the console is a SEPARATE
   * ORIGIN on its own hostname, so a same-tab navigation discards this page
   * along with the incident being graded on it.
   *
   * NO INTERNAL ADDRESS IS EVER PRINTED. The not-set-up copy names the variable
   * an administrator must set, which is what they can act on; the host and port
   * of a lab machine is not.
   */
  function consoleStatusHtml() {
    if (tier !== 'staff') return '';
    var c = consoleStatus;
    if (!c || c.state === 'hidden') return '';

    var head = '<div class="info-box" style="margin-bottom:1rem;">'
      + '<h4 style="margin:0 0 0.5rem;">Authoring console</h4>';
    var tail = '</div>';
    var again = '<button type="button" class="btn btn-secondary" '
      + 'id="blueTeamConsoleRecheck">Check again</button>';

    if (c.state === 'probing') {
      return head + '<p style="font-size:0.9rem;">Checking whether the attack authoring '
        + 'console is up&hellip;</p>' + tail;
    }

    if (c.state === 'ready') {
      return head
        + '<p style="font-size:0.9rem;">Adversaries are built in a shared console that sits '
        + 'outside every lane and runs nothing. It opens in a new tab: it is a separate site '
        + 'with its own sign-in, and a same-tab jump would throw away the course you have open '
        + 'here.</p>'
        + '<a class="btn btn-primary" href="' + escHtml(c.url) + '" target="_blank"'
        + ' rel="noopener noreferrer">Open the authoring console &#8599;</a>'
        + tail;
    }

    if (c.state === 'down') {
      return head
        + '<p style="font-weight:600; margin:0 0 0.4rem;">The authoring console is not '
        + 'responding.</p>'
        + '<p style="font-size:0.88rem;">It is set up on this platform, but nothing answered '
        + 'when CyberCore tried it just now. The machine may be powered off, or the network path '
        + 'from this server to it may be down. An administrator can bring it back &mdash; '
        + 'nothing about this course needs changing.</p>'
        + again + tail;
    }

    if (c.state === 'unset') {
      return head
        + '<p style="font-weight:600; margin:0 0 0.4rem;">Attack authoring is not set up.</p>'
        + '<p style="font-size:0.88rem;">The authoring console is published on its own hostname, '
        + 'and this platform has not been told what that hostname is. An administrator needs to '
        + 'set <code>CALDERA_HOST</code> and add the tunnel route that reaches it, then restart '
        + 'the proxy. Until then there is nothing here to open.</p>'
        + tail;
    }

    return head
      + '<p style="font-weight:600; margin:0 0 0.4rem;">CyberCore could not check the authoring '
      + 'console.</p>'
      + '<p style="font-size:0.88rem;">The check itself failed, so whether the console is up is '
      + 'unknown &mdash; and an address nobody has confirmed is not offered as a link. Try again '
      + 'in a moment; if it keeps failing, an administrator can find the reason in the '
      + 'application log.</p>'
      + again + tail;
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
        + 'outside every lane and runs the Caldera console. Before it opens, CyberCore refreshes what it knows '
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

    var agents = document.getElementById('blueTeamCalderaAgent');
    if (agents) agents.addEventListener('click', function () { return showLaneCalderaModal(); });

    var recheck = document.getElementById('blueTeamConsoleRecheck');
    if (recheck) recheck.addEventListener('click', function () { return refreshConsoleStatus(); });

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
    var authoringMarkup = calderaAgentsHtml() + consoleStatusHtml() + authoringHtml();

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

  // ============================================================================
  // CALDERA AGENTS ON A RUNNING LANE
  // ============================================================================

  let _laneCalderaModal = null;

  function calderaAgentsHtml() {
    if (tier !== 'staff') return '';
    return '<div class="info-box" style="margin-bottom:1rem;">'
      + '<h4 style="margin:0 0 0.5rem;">Caldera agents</h4>'
      + '<p>Add a Sandcat agent to a running lane, then control it from the Caldera console.</p>'
      + '<button type="button" class="btn btn-primary" id="blueTeamCalderaAgent">Caldera Agent</button></div>';
  }

  function laneCalderaHttpUrl(value) {
    try {
      const url = new URL(value);
      return ['https:', 'http:'].includes(url.protocol) && !url.username && !url.password ? url.href : null;
    } catch (_) { return null; }
  }

  function laneCalderaModalOpen(state) {
    return _laneCalderaModal === state && state.courseId === currentCourseId
      && tier === 'staff' && state.overlay.classList.contains('active');
  }

  function closeLaneCalderaModal() {
    const state = _laneCalderaModal;
    if (!state) return;
    _laneCalderaModal = null;
    clearTimeout(state.timer);
    state.requests.forEach(controller => controller.abort());
    state.observer.disconnect();
    Modal.close(state.overlay);
    state.overlay.remove();
  }

  async function showLaneCalderaModal() {
    if (tier !== 'staff' || !currentCourseId) return;
    closeLaneCalderaModal();
    const overlay = document.createElement('div');
    overlay.id = 'laneCalderaModal';
    overlay.className = 'modal-overlay';
    overlay.innerHTML = `
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="laneCalderaTitle" style="max-width: 720px;">
        <div class="modal-header">
          <h3 id="laneCalderaTitle">Caldera Agent</h3>
          <button id="laneCalderaClose" class="modal-close" aria-label="Close Caldera Agent">&times;</button>
        </div>
        <p style="color: var(--gray-500); font-size: 0.85rem;">Install a Sandcat agent on a running Windows or Linux VM. Control it from the Caldera console using this lane's group.</p>
        <div id="laneCalderaConnection" style="margin-bottom: 1rem; overflow-wrap: anywhere;"></div>
        <p id="laneCalderaNetwork" style="font-size: 0.85rem; color: #b7791f;"></p>
        <form id="laneCalderaForm" style="display: grid; gap: 0.75rem;">
          <div class="form-group">
            <label for="laneCalderaLane">Lane with running VMs</label>
            <select id="laneCalderaLane" required disabled><option value="">Loading lanes...</option></select>
          </div>
          <div class="form-group">
            <label for="laneCalderaVm">Target VM</label>
            <select id="laneCalderaVm" required disabled><option value="">Loading VMs...</option></select>
          </div>
          <div class="form-group">
            <label for="laneCalderaPlatform">Operating system</label>
            <select id="laneCalderaPlatform" required disabled aria-describedby="laneCalderaPlatformHint">
              <option value="">Select operating system...</option>
              <option value="windows">Windows</option>
              <option value="linux">Linux</option>
            </select>
            <p id="laneCalderaPlatformHint" style="color: var(--gray-500); font-size: 0.8rem;"></p>
          </div>
          <button id="laneCalderaInstall" type="submit" class="btn btn-primary" disabled>Install Agent</button>
          <button id="laneCalderaRefresh" type="button" class="btn btn-secondary">Refresh status</button>
        </form>
        <p id="laneCalderaError" role="alert" style="color: #e53e3e; white-space: pre-wrap;"></p>
        <div id="laneCalderaJob" role="status" aria-live="polite" style="margin-top: 1rem;"></div>
        <h4 style="margin-bottom: 0.5rem;">Agents seen by Caldera in this lane</h4>
        <div id="laneCalderaAgents" aria-live="polite" style="font-size: 0.85rem;">Loading check-ins...</div>
        <p style="color: var(--gray-500); font-size: 0.8rem;">You can close this window while installation runs. Reopen Caldera Agent to check progress.</p>
      </div>`;
    document.body.appendChild(overlay);
    const state = { courseId: currentCourseId, laneId: null, overlay, payload: null, data: null, timer: null, requests: new Set(), submitting: false, refreshing: false, misses: 0, revision: 0, installError: '' };
    _laneCalderaModal = state;
    document.getElementById('laneCalderaClose').addEventListener('click', closeLaneCalderaModal);
    document.getElementById('laneCalderaLane').onchange = () => selectCalderaLane(state);
    document.getElementById('laneCalderaForm').onsubmit = event => { event.preventDefault(); return installLaneCalderaAgent(); };
    document.getElementById('laneCalderaVm').onchange = () => syncLaneCalderaTarget(state, true);
    document.getElementById('laneCalderaPlatform').onchange = () => syncLaneCalderaTarget(state);
    document.getElementById('laneCalderaRefresh').onclick = () => refreshLaneCalderaModal(state);
    // The shared modal controller also closes via Escape and backdrop click.
    state.observer = new MutationObserver(() => {
      if (_laneCalderaModal === state && !overlay.classList.contains('active')) closeLaneCalderaModal();
    });
    state.observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    Modal.open(overlay.id);
    await refreshLaneCalderaModal(state);
  }

  async function laneCalderaRequest(state, path, options = {}) {
    const controller = new AbortController();
    state.requests.add(controller);
    const timeout = setTimeout(() => controller.abort(), 15000);
    try {
      return await authoringRequest(path, { ...options, courseId: state.courseId, signal: controller.signal });
    } catch (error) {
      if (error.name === 'AbortError') throw new Error('The request timed out');
      throw error;
    } finally {
      clearTimeout(timeout);
      state.requests.delete(controller);
    }
  }

  function selectCalderaLane(state) {
    if (!laneCalderaModalOpen(state)) return;
    const selected = document.getElementById('laneCalderaLane').value;
    if (selected !== state.laneId) {
      state.data = null;
      state.installError = '';
      document.getElementById('laneCalderaVm').value = '';
      document.getElementById('laneCalderaPlatform').value = '';
    }
    state.laneId = selected || null;
    const lane = (state.payload?.lanes || []).find(item => item.lane_id === selected);
    renderLaneCalderaStatus(state, { ...state.payload, ...(lane || { lane_status: null, runnable: false, targets: [], agents: [], job: null }) });
  }

  function renderCalderaLanes(state, payload) {
    const previous = state.payload;
    state.payload = payload;
    const select = document.getElementById('laneCalderaLane');
    const lanes = Array.isArray(payload.lanes) ? payload.lanes : [];
    const oldLanes = previous?.lanes || [];
    const laneOptions = items => items.map(lane => [lane.lane_id, lane.name, lane.runnable]);
    if (JSON.stringify(laneOptions(oldLanes)) !== JSON.stringify(laneOptions(lanes)) || !previous) {
      select.innerHTML = '<option value="">Select a lane with running VMs...</option>' + lanes.map(lane =>
        `<option value="${escHtml(lane.lane_id)}"${lane.runnable === true ? '' : ' disabled'}>${escHtml(lane.name || lane.lane_id)}${lane.runnable === true ? '' : ' (unavailable)'}</option>`
      ).join('');
      select.value = lanes.some(lane => lane.lane_id === state.laneId) ? state.laneId : lanes.find(lane => lane.runnable === true)?.lane_id || '';
    }
    select.disabled = state.submitting || !!payload.power_error || !lanes.some(lane => lane.runnable === true);
    selectCalderaLane(state);
  }

  function syncLaneCalderaTarget(state, changed = false) {
    if (!laneCalderaModalOpen(state)) return;
    const vmSelect = document.getElementById('laneCalderaVm');
    const platformSelect = document.getElementById('laneCalderaPlatform');
    const target = (state.data?.targets || []).find(vm => String(vm.vm_id) === vmSelect.value);
    if (changed) platformSelect.value = ['windows', 'linux'].includes(target?.platform) ? target.platform : '';
    document.getElementById('laneCalderaPlatformHint').textContent = !target ? '' : target.runnable !== true
      ? 'This VM is unavailable for installation. Select a running VM or refresh its status.' : target.platform
      ? 'Operating system is preselected from the VM configuration. Change it if needed.'
      : 'The operating system could not be detected. Select Windows or Linux before installing.';
    const busy = state.submitting || state.data?.job?.status === 'running';
    document.getElementById('laneCalderaLane').disabled = state.submitting || !!state.data?.power_error
      || !(state.payload?.lanes || []).some(lane => lane.runnable === true);
    vmSelect.disabled = busy || !state.data?.targets?.length;
    platformSelect.disabled = busy || target?.runnable !== true;
    const button = document.getElementById('laneCalderaInstall');
    button.disabled = busy || !target || !['windows', 'linux'].includes(platformSelect.value)
      || state.data?.runnable !== true || target?.runnable !== true || !!state.data?.power_error
      || !laneCalderaHttpUrl(state.data?.server_url)
      || state.data?.internet_enabled === false
      || !!state.data?.configuration_error;
    button.textContent = state.submitting ? 'Starting installation...' : busy ? 'Installation running...' : 'Install Agent';
  }

  function renderLaneCalderaStatus(state, data) {
    const previous = state.data;
    state.data = data;
    const targets = Array.isArray(data.targets) ? data.targets.filter(vm => vm.type === 'qemu') : [];
    state.data.targets = targets;
    const vmSelect = document.getElementById('laneCalderaVm');
    const selected = vmSelect.value;
    // Replacing the options on every poll interrupts a keyboard selection.
    if (JSON.stringify(previous?.targets) !== JSON.stringify(targets)) {
      vmSelect.innerHTML = '<option value="">Select a VM...</option>' + targets.map(vm =>
        `<option value="${escHtml(String(vm.vm_id))}"${vm.runnable === true ? '' : ' disabled'}>${escHtml(vm.name || 'VM')} (${escHtml(String(vm.vm_id))})${vm.role ? ` - ${escHtml(vm.role)}` : ''} - ${escHtml(vm.power_state || 'unknown')}</option>`
      ).join('');
      const retained = targets.find(vm => String(vm.vm_id) === selected);
      const initial = !previous && targets.find(vm => vm.runnable === true && !/gateway|router|firewall/i.test(`${vm.role || ''} ${vm.name || ''}`));
      vmSelect.value = retained ? selected : initial ? String(initial.vm_id) : '';
      syncLaneCalderaTarget(state, !retained);
    }
    const consoleUrl = laneCalderaHttpUrl(data.console_url);
    document.getElementById('laneCalderaConnection').innerHTML = `
      <div style="font-size: 0.85rem;">Agent server: <code>${escHtml(data.server_url || 'Not configured')}</code></div>
      <div style="font-size: 0.85rem;">Lane group: <code>${escHtml(state.laneId ? data.group || 'Not configured' : 'Select a lane')}</code></div>
      ${state.laneId ? `<div style="font-size: 0.85rem;">Saved lane status: ${escHtml(data.lane_status || 'unknown')}</div>
      <div style="font-size: 0.85rem;">VM power: ${data.power_error ? 'Unavailable' : `${targets.filter(vm => vm.power_state === 'running').length} of ${targets.length} VMs running`}</div>
      ${data.retained_after_failure && data.runnable === true ? '<p style="font-size: 0.85rem;">Suspended after a provisioning error; running VMs can still be used.</p>' : ''}` : ''}
      ${consoleUrl ? `<a href="${escHtml(consoleUrl)}" target="_blank" rel="noopener noreferrer" style="display: inline-block; margin-top: 0.5rem;">Open Caldera console &nearr;</a>` : ''}`;
    document.getElementById('laneCalderaNetwork').textContent = !state.laneId ? ''
      : data.lifecycle_eligible === false ? 'This lane is unavailable for agent installation. Resume the lane, then refresh status.'
      : data.internet_enabled === false
        ? 'Internet is off for this lane. Enable Internet access for this lane before installing a Caldera agent, then refresh status.'
        : 'The VM must be running and able to reach the agent server. Its QEMU guest agent must be available.';
    const job = data.job;
    let jobHtml = '';
    if (job) {
      const label = job.status === 'failed' ? 'Installation failed' : job.status === 'completed' ? 'Install script finished' : 'Installing agent';
      jobHtml = `<strong>${label}${job.vm_id ? ` on VM ${escHtml(String(job.vm_id))}` : ''}</strong>
        <p style="white-space: pre-wrap;">${escHtml(job.error || job.message || '')}</p>`;
      if (job.agent?.paw) jobHtml += `<p style="color: #38a169;">Caldera confirmed check-in: ${escHtml(job.agent.host || job.agent.paw)}.</p>`;
      else if (job.status === 'completed') jobHtml += '<p>No check-in has been confirmed for this installation yet. Check the VM can reach the agent server and refresh status.</p>';
    }
    document.getElementById('laneCalderaJob').innerHTML = jobHtml;
    const agents = Array.isArray(data.agents) ? data.agents : [];
    document.getElementById('laneCalderaAgents').innerHTML = data.agents_error
      ? `<p>Check-in status unavailable: ${escHtml(data.agents_error)}</p>`
      : agents.length ? `<div style="overflow-x: auto;"><table style="width: 100%; text-align: left;">
          <thead><tr><th>Host</th><th>Agent ID</th><th>Platform</th><th>Last check-in</th></tr></thead>
          <tbody>${agents.map(agent => `<tr>
            <td>${escHtml(agent.host || 'Unknown')}${agent.trusted === false ? ' (untrusted)' : ''}</td>
            <td><code>${escHtml(agent.paw || '')}</code></td><td>${escHtml(agent.platform || '')}</td>
            <td>${escHtml(agent.last_seen || 'Not reported')}</td>
          </tr>`).join('')}</tbody></table></div>`
        : state.laneId ? '<p>No agents have checked in to this lane group yet.</p>' : '<p>Select a lane to view its agent check-ins.</p>';
    const lanes = Array.isArray(state.payload?.lanes) ? state.payload.lanes : [];
    document.getElementById('laneCalderaError').textContent = data.configuration_error
      || state.installError
      || (data.power_error ? `VM power status is unavailable: ${data.power_error}. Refresh status before installing.` : '')
      || (!laneCalderaHttpUrl(data.server_url) ? 'The Caldera agent server is not configured. Ask an administrator to configure its callback URL.' : '')
      || (!lanes.length ? 'No deployed lanes were found for this course. Deploy a lane, then refresh status.' : '')
      || (!lanes.some(lane => lane.runnable === true)
        ? lanes.every(lane => lane.lifecycle_eligible === false)
          ? 'No lanes are available for agent installation. Resume a suspended lane, then refresh status.'
          : 'No running VMs were found for this course. Start a Windows or Linux VM in a lane, then refresh status.' : '')
      || (state.laneId && !targets.length ? 'No supported VMs were found in this lane. Add a Windows or Linux QEMU VM before installing.' : '')
      || (state.laneId && !targets.some(vm => vm.runnable === true) ? 'No running VMs are available for installation in this lane. Refresh status after starting a VM.' : '');
    syncLaneCalderaTarget(state);
  }

  async function refreshLaneCalderaModal(state = _laneCalderaModal) {
    if (!state || !laneCalderaModalOpen(state) || state.refreshing || state.submitting) return;
    clearTimeout(state.timer);
    state.refreshing = true;
    const revision = state.revision;
    document.getElementById('laneCalderaRefresh').disabled = true;
    try {
      const data = await laneCalderaRequest(state, '/caldera-agents/status');
      if (!laneCalderaModalOpen(state) || revision !== state.revision) return;
      state.misses = 0;
      renderCalderaLanes(state, data);
    } catch (error) {
      if (!laneCalderaModalOpen(state) || revision !== state.revision) return;
      state.misses++;
      document.getElementById('laneCalderaError').textContent = `Could not refresh Caldera status: ${error.message}. ${state.misses >= 3 ? 'Automatic updates paused. Use Refresh status to try again.' : 'Retry with Refresh status.'}`;
      if (!state.data) {
        document.getElementById('laneCalderaVm').innerHTML = '<option value="">VM list unavailable</option>';
        document.getElementById('laneCalderaAgents').textContent = 'Check-in status unavailable.';
      }
    } finally {
      state.refreshing = false;
      if (laneCalderaModalOpen(state)) {
        document.getElementById('laneCalderaRefresh').disabled = state.submitting;
        if (!state.submitting && state.misses < 3) state.timer = setTimeout(() => refreshLaneCalderaModal(state), 5000);
      }
    }
  }

  async function installLaneCalderaAgent() {
    const state = _laneCalderaModal;
    if (!state || !laneCalderaModalOpen(state) || state.submitting || state.data?.job?.status === 'running') return;
    const vmId = document.getElementById('laneCalderaVm').value;
    const platform = document.getElementById('laneCalderaPlatform').value;
    const target = (state.data?.targets || []).find(vm => String(vm.vm_id) === vmId);
    const errorBox = document.getElementById('laneCalderaError');
    if (!target || !['windows', 'linux'].includes(platform)) {
      errorBox.textContent = 'Select a target VM and its operating system before installing.';
      return;
    }
    if (state.data.runnable !== true || target.runnable !== true || state.data.power_error) {
      errorBox.textContent = 'Select an available running VM and refresh status before installing.';
      return;
    }
    if (state.data.configuration_error || !laneCalderaHttpUrl(state.data.server_url)) return;
    if (state.data.internet_enabled === false) {
      errorBox.textContent = 'Enable Internet access for this lane before installing a Caldera agent, then refresh status.';
      return;
    }
    state.submitting = true;
    state.requests.forEach(controller => controller.abort());
    state.revision++;
    clearTimeout(state.timer);
    errorBox.textContent = '';
    state.installError = '';
    document.getElementById('laneCalderaRefresh').disabled = true;
    syncLaneCalderaTarget(state);
    try {
      const result = await laneCalderaRequest(state, '/caldera-agents', { method: 'POST', body: { lane_id: state.laneId, vm_id: target.vm_id, platform } });
      if (!laneCalderaModalOpen(state)) return;
      const lane = state.payload.lanes.find(item => item.lane_id === state.laneId);
      if (lane) lane.job = result.job;
      renderLaneCalderaStatus(state, { ...state.data, job: result.job });
    } catch (error) {
      if (!laneCalderaModalOpen(state)) return;
      state.installError = `Could not start installation: ${error.message}. Refresh status to check whether a job started before retrying.`;
      errorBox.textContent = state.installError;
    } finally {
      state.submitting = false;
      if (laneCalderaModalOpen(state)) {
        syncLaneCalderaTarget(state);
        document.getElementById('laneCalderaRefresh').disabled = false;
        state.misses = 0;
        state.timer = setTimeout(() => refreshLaneCalderaModal(state), 1500);
      }
    }
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
        if (tier !== 'staff') closeLaneCalderaModal();
        runs = data.runs || [];
        if (!authoring) authoring = blankAuthoring();
        loadedForCourse = courseId;
        renderShell();
        // NOT AWAITED, and deliberately after the first paint. The status
        // endpoint dials the authoring machine and waits up to three seconds
        // for it; holding the board back for that would make a tab that is
        // otherwise ready look broken. refreshConsoleStatus() re-renders on its
        // own when it lands, and never rejects.
        refreshConsoleStatus();
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
    closeLaneCalderaModal();
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
    // Not because the answer changes per course — it does not — but because
    // `tier` is about to be re-resolved against a course this viewer may only
    // be enrolled in, and a panel left on screen from the last one would be a
    // staff surface drawn for a student.
    consoleStatus = null;
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
    authoringHtml: authoringHtml,
    // Same reason: the test drives the probe and reads the markup the shell
    // writes, rather than a copy of either.
    refreshConsoleStatus: refreshConsoleStatus,
    consoleStatusHtml: consoleStatusHtml,
    calderaAgentsHtml: calderaAgentsHtml,
    showCalderaAgents: showLaneCalderaModal,
    closeCalderaAgents: closeLaneCalderaModal
  };
})();
