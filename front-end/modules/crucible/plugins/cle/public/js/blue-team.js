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
 * PICKING AN AUTHORING ROW DOES NOT LAUNCH IT. The separate classroom launch
 * dialog requires an explicit profile and lane selection before calling the
 * course-scoped Caldera operations API. Legacy incident-engine gates remain.
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
        if (!res.ok) throw Object.assign(new Error((data && data.error) || ('Request failed (' + res.status + ')')), { status: res.status });
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

  /**
   * The attribute-position escaper.
   *
   * escHtml() is courses.html's `div.textContent = s; return div.innerHTML`, and
   * that escapes & < > but NOT quotes — so a value carrying a double quote
   * breaks out of any attribute it is interpolated into. courses.html declares
   * its own escAttr for exactly this, but that one is not in this file's scope
   * (the global comment at the top of this file lists what is), so the modal
   * code below carries its own rather than interpolating raw quotes.
   *
   * Idempotent by construction: escHtml runs first, so the ampersands it
   * introduces are already entities and these replacements cannot double-escape
   * them.
   *
   * Escaping " also hardens a test seam. test/caldera-classroom-ui.test.js finds
   * elements by regex-scanning innerHTML for id="…" and then decides `disabled`
   * / `checked` from a tag slice that ends at the first '>' it sees — so one raw
   * '>' inside an attribute value silently truncates that slice and the harness
   * reads the wrong state off the element.
   */
  function escAttr(value) {
    return escHtml(String(value === null || value === undefined ? '' : value))
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
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
   * here that fires anything. Classroom execution belongs to the separate Run
   * Caldera attack dialog, where the instructor explicitly chooses target lanes.
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
        + 'Choosing it here does not start it. Use Run Caldera attack to launch it across '
        + 'selected lanes, or open the Caldera console to control individual operations.</div>'
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
        + 'outside every lane. The console builds attack profiles and controls installed '
        + 'agents. It opens in a new tab so this course stays open.</p>'
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

    var groupAgents = document.getElementById('blueTeamCalderaGroupInstall');
    if (groupAgents) groupAgents.addEventListener('click', function () { return showClassroomCaldera('install'); });
    var launch = document.getElementById('blueTeamCalderaAttack');
    if (launch) launch.addEventListener('click', function () { return showClassroomCaldera('attack'); });

    var recheck = document.getElementById('blueTeamConsoleRecheck');
    if (recheck) recheck.addEventListener('click', function () { return refreshConsoleStatus(); });

    var refresh = document.getElementById('blueTeamAdversaryRefresh');
    if (refresh) refresh.addEventListener('click', function () { return loadAdversaries(); });

    var rows = document.querySelectorAll('.blueTeamAdversary');
    Array.prototype.forEach.call(rows, function (row) {
      row.addEventListener('click', function () {
        // Authoring selection is informational. Launch has its own explicit
        // profile/lane selection and submit action in the classroom dialog.
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
      + '<p>Install agents on the machines students monitor, then run the same attack profile in each selected lane.</p>'
      + '<div style="display:flex; gap:0.5rem; flex-wrap:wrap;">'
      + '<button type="button" class="btn btn-secondary" id="blueTeamCalderaAgent">Caldera Agent</button>'
      + '<button type="button" class="btn btn-primary" id="blueTeamCalderaGroupInstall">Group install agents</button>'
      + '<button type="button" class="btn btn-primary" id="blueTeamCalderaAttack">Run Caldera attack</button></div>'
      + '<p style="font-size:0.85rem; margin-top:0.75rem;">An ability is one attack step. An adversary is an ordered profile of abilities. '
      + 'A launch creates a separate operation for each lane. Each target must forward its logs to that lane&rsquo;s SIEM.</p></div>';
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
    closeClassroomCaldera();
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
            <p style="color: var(--gray-500); font-size: 0.8rem;">Windows installation attempts to disable Defender scanning and blocking settings and exclude this agent's folder. It proceeds with a verified folder exclusion if some protections remain on. Applied changes remain on the target VM.</p>
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
        `<option value="${escAttr(lane.lane_id)}"${lane.runnable === true ? '' : ' disabled'}>${escHtml(lane.name || lane.lane_id)}${lane.runnable === true ? '' : ' (unavailable)'}</option>`
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
    const job = selectedLaneCalderaJob(state);
    const busy = state.submitting || ['queued', 'running'].includes(job?.status);
    document.getElementById('laneCalderaLane').disabled = state.submitting || !!state.data?.power_error
      || !(state.payload?.lanes || []).some(lane => lane.runnable === true);
    vmSelect.disabled = state.submitting || !state.data?.targets?.length;
    platformSelect.disabled = busy || target?.runnable !== true;
    const button = document.getElementById('laneCalderaInstall');
    button.disabled = busy || !target || !['windows', 'linux'].includes(platformSelect.value)
      || state.data?.runnable !== true || target?.runnable !== true || !!state.data?.power_error
      || !laneCalderaHttpUrl(state.data?.server_url)
      || state.data?.internet_enabled === false
      || !!state.data?.configuration_error;
    button.textContent = state.submitting ? 'Starting installation...' : job?.status === 'queued' ? 'Installation queued...' : busy ? 'Installation running...' : 'Install Agent';
    renderSelectedLaneCalderaJob(state, job);
  }

  function selectedLaneCalderaJob(state) {
    const vmId = document.getElementById('laneCalderaVm').value;
    return (state.data?.jobs || []).find(job => String(job.vm_id) === vmId)
      || (String(state.data?.job?.vm_id) === vmId ? state.data.job : null);
  }

  function renderSelectedLaneCalderaJob(state, job) {
    let jobHtml = '';
    if (job) {
      const label = job.status === 'failed' ? 'Installation failed' : job.status === 'completed' ? 'Install script finished'
        : job.status === 'queued' ? 'Installation queued' : 'Installing agent';
      jobHtml = `<strong>${label}${job.vm_id ? ` on VM ${escHtml(String(job.vm_id))}` : ''}</strong>
        <p style="white-space: pre-wrap;">${escHtml(job.error || job.message || '')}</p>`;
      const warnings = Array.isArray(job.warnings) ? job.warnings.filter(warning => typeof warning === 'string' && warning.trim()).slice(0, 5) : [];
      if (warnings.length) jobHtml += `<div style="color: #b7791f;"><strong>Installation notice</strong>${warnings.map(warning => `<p style="white-space: pre-wrap;">${escHtml(warning.slice(0, 1000))}</p>`).join('')}</div>`;
      if (job.agent?.paw) jobHtml += `<p style="color: #38a169;">Caldera confirmed check-in: ${escHtml(job.agent.host || job.agent.paw)}.</p>`;
      else if (job.status === 'completed') jobHtml += '<p>No check-in has been confirmed for this installation yet. Check the VM can reach the agent server and refresh status.</p>';
    }
    document.getElementById('laneCalderaJob').innerHTML = jobHtml;
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
        `<option value="${escAttr(String(vm.vm_id))}"${vm.runnable === true ? '' : ' disabled'}>${escHtml(vm.name || 'VM')} (${escHtml(String(vm.vm_id))})${vm.role ? ` - ${escHtml(vm.role)}` : ''} - ${escHtml(vm.power_state || 'unknown')}</option>`
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
      ${consoleUrl ? `<a href="${escAttr(consoleUrl)}" target="_blank" rel="noopener noreferrer" style="display: inline-block; margin-top: 0.5rem;">Open Caldera console &nearr;</a>` : ''}`;
    document.getElementById('laneCalderaNetwork').textContent = !state.laneId ? ''
      : data.lifecycle_eligible === false ? 'This lane is unavailable for agent installation. Resume the lane, then refresh status.'
      : data.internet_enabled === false
        ? 'Internet is off for this lane. Enable Internet access for this lane before installing a Caldera agent, then refresh status.'
        : 'The VM must be running and able to reach the agent server. Its QEMU guest agent must be available.';
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
    if (!state || !laneCalderaModalOpen(state) || state.submitting || ['queued', 'running'].includes(selectedLaneCalderaJob(state)?.status)) return;
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
      const jobs = (state.data.jobs || []).filter(job => String(job.vm_id) !== String(target.vm_id)).concat([result.job]);
      if (lane) { lane.job = result.job; lane.jobs = jobs; }
      renderLaneCalderaStatus(state, { ...state.data, job: result.job, jobs });
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


  // Classroom controls use the course-scoped APIs. Selection is always rebuilt
  // from the latest inventory; a matching name never supplies an OS by guess.
  let _classroomCaldera = null;
  const _pendingCalderaLaunches = new Map();
  const _classroomHtmlTemplates = new WeakMap();
  const classroomVmKey = (lane, vm) => `${lane.lane_id}:${vm.vm_id}`;
  const classroomJobs = lane => Array.isArray(lane.jobs) ? lane.jobs : lane.job ? [lane.job] : [];
  const classroomBusy = (lane, vm) => classroomJobs(lane).some(job => String(job.vm_id) === String(vm.vm_id) && ['queued', 'running'].includes(job.status));

  // ---- classroom identity, measurement and grouping -----------------------

  /**
   * A stable element id built from a value the SERVER owns — a lane id, a group
   * key, a machine key — rather than from the row's index in the rendered list.
   *
   * Index-based ids (classroomLane0, classroomTarget3) shift under the
   * instructor the moment the rendered set changes: type one character into the
   * search box and classroomLane0 names a different lane than the one whose
   * checkbox the pointer is over, so the handler rebound at that index toggles
   * somebody else's lane. Keying on identity makes a binding survive filtering,
   * grouping, collapsing and a poll that inserts a lane above it.
   *
   * The escape is STRICTER than encodeURIComponent, which leaves !'()*~ intact.
   * A single quote would close an attribute in markup this file builds by
   * concatenation, and the test harness decides `checked` / `disabled` from a raw
   * tag slice that ends at the first '>' it finds — so an id carrying a quote or
   * an angle bracket corrupts the very element it names. What survives here is
   * [A-Za-z0-9._%-] and nothing else, which needs no escaping in an attribute.
   */
  const classroomId = (kind, value) => `classroom${kind}-`
    + encodeURIComponent(String(value === null || value === undefined ? '' : value))
      .replace(/[!'()*~]/g, character => `%${character.charCodeAt(0).toString(16).toUpperCase()}`);

  // Every deployer names a lane `<family>-<vxlanId>`: cle-cybr400-10880. The
  // server sends lane_number outright; parsing the suffix off the name keeps the
  // number visible against a server that predates that field.
  const CLASSROOM_NAME_SUFFIX = /^(.*?)-(\d+)$/;
  const classroomLaneNumber = lane => Number.isSafeInteger(lane.lane_number) ? lane.lane_number
    : Number((String(lane.name || '').match(CLASSROOM_NAME_SUFFIX) || [])[2]) || null;

  /** Who this lane belongs to, in the order an instructor recognises it. */
  const classroomLanePrimary = lane => String(lane.student?.name || '').trim() || lane.name || lane.lane_id;

  const CLASSROOM_KIND_LABEL = { course: 'Course', 'course-lab': 'Course lab', ciab: 'CiAB profile',
    group: 'Deployed group', challenge: 'Challenge', goad: 'GOAD', workstation: 'Student workstations',
    malware: 'Malware analysis', staging: 'Staging', lane: 'Other' };

  /**
   * The environment heading for a lane.
   *
   * THE FALLBACK CHAIN IS LOAD-BEARING, NOT DEFENSIVE PADDING. The server sends
   * environment.label === null whenever the challenge spec behind the lane was
   * not answered — the normal state for a GOAD lane whose spec row has not been
   * read, and for every lane if the directory lookup missed its deadline. Reading
   * `environment.label` alone would print a blank group heading over six real
   * machines, and grouping on that empty string would merge two unrelated
   * environments into one pile.
   */
  function classroomEnvLabel(lane) {
    const environment = lane.environment || {};
    return environment.label || environment.key || CLASSROOM_KIND_LABEL[lane.kind] || CLASSROOM_KIND_LABEL.lane;
  }

  /** "13 abilities" / "1 ability" — the count and the word, never split apart. */
  const classroomAbilities = count => `${count} abilit${count === 1 ? 'y' : 'ies'}`;
  const cmpText = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true, sensitivity: 'base' });
  const classroomTokens = query => String(query || '').toLowerCase().split(/\s+/).filter(Boolean);
  const classroomMatches = (haystack, tokens) => tokens.every(token => haystack.includes(token));

  /**
   * A check-in age, at MINUTE granularity, and coarse ON PURPOSE.
   *
   * classroomSetHtml() skips the DOM write whenever the template is byte-identical
   * to the last one, and that cache is the only reason a 5s poll does not steal
   * the caret, the scroll position and the open dropdown out of this dialog. A
   * second-granularity string ("42s ago") differs on every single tick, so it
   * would defeat the cache for every island it appears in and rebuild the table
   * under the instructor twelve times a minute.
   *
   * A last_seen in the future (clock skew between the Caldera host and this
   * browser) reads as "just now" rather than as a negative age.
   */
  function classroomAgo(value, now) {
    const at = Date.parse(value);
    if (!isFinite(at)) return '';
    const minutes = Math.floor(((Number.isFinite(now) ? now : Date.now()) - at) / 60000);
    if (minutes < 1) return 'just now';
    if (minutes < 60) return `${minutes}m ago`;
    const hours = Math.floor(minutes / 60);
    return hours < 24 ? `${hours}h ago` : `${Math.floor(hours / 24)}d ago`;
  }

  /**
   * The environment a lane's machines are grouped under.
   *
   * IT IS ONE FUNCTION BECAUSE THE TWO PLACES THAT NEEDED IT DISAGREED. The
   * machine key fell back to 'lane' while the Machines grid fell back to
   * `kind:${lane.kind}`, so on the very payload those fallbacks exist for — an
   * older server that sends no `environment` — a GOAD lane and a challenge lane
   * both keyed their DC01 to `lane::dc01` and then filed it under two different
   * group headings. The grid rendered the same element id twice; the bind loop
   * resolved both entries to whichever element getElementById returned, so the
   * first checkbox on screen installed on the other lane's VM and the second
   * never received a handler at all.
   */
  const classroomEnvKey = lane => ((lane && lane.environment && lane.environment.key) || 'lane');

  /**
   * The identity a machine is grouped by ACROSS lanes.
   *
   * The server's machine_key is scoped to the environment — `goad-ad::dc01`,
   * `workstation::slot0` — which is what makes 44 workstation lanes with 44
   * unique hostnames collapse into one row while DC01 in two different
   * environments stays two rows. The fallback exists so an older server degrades
   * to today's cross-lane grouping (the bare lowercased VM name, now at least
   * qualified by the environment) instead of losing the grouping entirely.
   */
  const classroomMachineKey = (lane, vm) => vm.machine_key
    || `${classroomEnvKey(lane)}::${String(vm.name || '').trim().toLowerCase()}`;

  const classroomMachineLabel = vm => vm.machine_label || vm.name || `VM ${vm.vm_id}`;

  /**
   * [label, modifier] for the .cal-role chip beside a machine name.
   *
   * The modifier picks the tint; the LABEL is written here rather than taken
   * from the server, so a role string nobody anticipated cannot land in the UI
   * dressed as copy. An unrecognised role is still shown, in the neutral tint,
   * because the raw word tells an instructor more than hiding it would.
   *
   * THE ROLE IS READ BEFORE vm.infra, AND THAT ORDER IS THE FIX. infra is one
   * boolean over a whole SET of roles — src/incident/caldera/fact-source.js
   * INFRASTRUCTURE_ROLES holds gateway, router, firewall, controller, attacker,
   * kali, siem, elk, wazuh and sensor — so testing it first labelled every one
   * of them "SIEM". A real GOAD lane sends its attack box as
   * {role:'attacker', infra:true}, and an instructor reading "SIEM" over Kali is
   * being told the wrong thing about the machine; the .cal-role-atk tint the
   * stylesheet defines was unreachable for exactly the rows it was drawn for.
   *
   * infra survives as the LAST branch, where it belongs: it is the only answer
   * left for a machine the server flagged as plumbing without naming a role, and
   * classroomInfra() reads this modifier, so that fallback is what keeps such a
   * row unticked by default.
   */
  function classroomRoleLabel(vm) {
    const role = String(vm.role || '').trim();
    const value = role.toLowerCase();
    if (/\bdc\b|domain/.test(value)) return ['Domain controller', 'dc'];
    if (/workstation|\bws\b|desktop|client/.test(value)) return ['Workstation', 'ws'];
    // Ahead of the SIEM and member-server tests: 'attacker' matches neither
    // today, but 'red-team-server' would match /server/ and quietly lose the
    // one tint that says "Caldera already lives here".
    if (/attack|\bkali\b|\bred\b/.test(value)) return ['Attack box', 'atk'];
    if (/siem|elk|sensor|wazuh|splunk/.test(value)) return ['SIEM', 'siem'];
    if (/server|\bsrv\b|member/.test(value)) return ['Member server', 'srv'];
    if (role) return [role, 'other'];
    return vm.infra === true ? ['Infrastructure', 'siem'] : ['', ''];
  }

  const CLASSROOM_REASON_BADGE = { 'lane not running': 'badge-muted', 'internet off': 'badge-warning',
    'no agent checked in': 'badge-warning', 'no running VMs': 'badge-muted', unavailable: 'badge-gray' };

  /**
   * WHY a lane cannot be used, or '' when it can. THE BRANCH ORDER IS THE WHOLE
   * CONTRACT, because it is the order in which these facts are independently
   * true — not a cascade of guesses behind a single boolean.
   *
   * It replaces a gate that tested lane.runnable FIRST and then invented a
   * reason to match it. In attack mode that was a lie an instructor could act
   * on: src/utils/caldera-lane-operations.js folds `agents.length > 0` into
   * `runnable`, so a lane that is powered on and perfectly healthy but has no
   * agent checked in arrives with runnable === false — and the old code labelled
   * it "lane not running", sending the instructor off to start a lane that was
   * already started. The "no agent checked in" branch was unreachable for
   * precisely the lanes it describes.
   *
   * lifecycle_eligible is the only field that actually means "the lane is not
   * running", so it goes first. internet_enabled === false is the next fact that
   * stands on its own (an agent cannot be fetched without egress). Only after
   * those is runnable consulted, and the two trailing branches name the residue:
   * an eligible lane with nothing powered on, and an older server that sends
   * neither of the new fields at all.
   */
  function classroomLaneReason(state, lane) {
    if (lane.lifecycle_eligible === false) return 'lane not running';
    if (lane.internet_enabled === false) return 'internet off';
    if (state.mode === 'attack' && !(Array.isArray(lane.agents) && lane.agents.length)) return 'no agent checked in';
    if (lane.runnable === true) return '';
    if (state.mode === 'install' && lane.lifecycle_eligible === true) return 'no running VMs';
    return 'unavailable';
  }

  const classroomLaneAvailable = (state, lane) => classroomLaneReason(state, lane) === '';

  /**
   * The Caldera agent running ON this VM, or null.
   *
   * The server attaches one to each target, and that is the only match that is
   * certain: it is made from the paw the installer minted for this lane and VM.
   * The two fallbacks exist for a server that predates that field and sends the
   * lane's agent roster alone — first by the vm_id the roster may carry, then by
   * hostname, which is what the agent itself reported and is therefore the only
   * remaining link between a Caldera record and a Proxmox VM. Without them an
   * older server renders an entire installed class as "no agent", and every
   * quick action in this dialog would offer to install onto machines that are
   * already done.
   *
   * THE HOSTNAME FALLBACK ONLY EVER LOOKS AT UNBOUND ROSTER ROWS. An agent that
   * already carries a vm_id has been joined to a machine by the server, and
   * matching it to a DIFFERENT machine on a hostname collision is worse than
   * finding nothing: hostnames repeat across lanes and environments, and a
   * roster row bound to DC01 whose host reads "ws01" makes WS01 render as
   * "checked in" with a timestamp. classroomFresh() agrees, so "Only missing
   * agents" and "Retry failed" both skip a VM that has no Caldera agent at
   * all — it is dropped from the install batch and reported as done.
   */
  function classroomAgentOf(lane, vm) {
    if (vm.agent) return vm.agent;
    const agents = Array.isArray(lane.agents) ? lane.agents : [];
    const bound = agent => agent.vm_id !== undefined && agent.vm_id !== null;
    const name = String(vm.name || '').trim().toLowerCase();
    return agents.find(agent => bound(agent) && String(agent.vm_id) === String(vm.vm_id))
      || (name ? agents.find(agent => !bound(agent) && String(agent.host || '').trim().toLowerCase() === name) : null)
      || null;
  }

  /**
   * Has Caldera heard from this VM's agent recently?
   *
   * `fresh` is the server's own verdict against its clock, which is the only one
   * worth trusting here. An agent present with no `fresh` field at all is an
   * older server that does not compute it: treat it as fresh rather than telling
   * a class of installed machines that they have no agent.
   */
  function classroomFresh(lane, vm) {
    const agent = classroomAgentOf(lane, vm);
    return !!agent && agent.fresh !== false;
  }

  /**
   * Is this machine something an instructor should NOT be installing an attack
   * agent on by default?
   *
   * The SIEM is the box the class watches the attack FROM, and the attack box is
   * where Caldera already lives; Sandcat on either is noise at best. This is the
   * single predicate behind three separate surfaces — the "not a target" badge in
   * the machine picker, the "Needs agent" facet count, and what "Only missing
   * agents" ticks — so the pill cannot say a lane still needs work that the
   * button then refuses to select.
   *
   * It is a DEFAULT, not a prohibition: every one of these machines is still
   * listed and can still be ticked by hand. An instructor who genuinely wants an
   * agent on the SIEM may have one, and silently refusing would be worse than
   * showing the row.
   */
  const classroomInfra = vm => vm.infra === true || vm.source === 'attack_box'
    || ['siem', 'atk'].includes(classroomRoleLabel(vm)[1]);

  // classroomLaneAvailable() and classroomVmAvailable() are called dozens of
  // times per lane per render, and each call used to rescan that lane's job
  // list. Each payload lane is measured ONCE into this WeakMap instead; a poll
  // replaces the lane objects wholesale, so the entries invalidate themselves.
  // submitClassroomCaldera() mutates lane.jobs / lane.operations in place, which
  // the WeakMap cannot see, so it deletes those entries explicitly.
  const _classroomLaneStats = new WeakMap();

  function classroomLaneStat(state, lane) {
    const cached = _classroomLaneStats.get(lane);
    // The mode is part of the measurement — `agents` and `reason` mean different
    // things in the two dialogs — and only one classroom dialog is open at a
    // time. That makes a cross-mode hit impossible in practice, and silently
    // wrong if it ever happened, so it is checked rather than assumed.
    if (cached && cached.mode === state.mode) return cached;
    const targets = (lane.targets || []).filter(vm => vm.type === 'qemu');
    const jobs = classroomJobs(lane);
    const busyIds = new Set(jobs.filter(job => ['queued', 'running'].includes(job.status)).map(job => String(job.vm_id)));
    const failedIds = new Set(jobs.filter(job => job.status === 'failed').map(job => String(job.vm_id)));
    const reason = classroomLaneReason(state, lane);
    const eligible = reason === '';
    const selectable = targets.filter(vm => eligible && vm.runnable === true && !busyIds.has(String(vm.vm_id)));
    const laneAgents = Array.isArray(lane.agents) ? lane.agents.length : 0;
    // Install mode counts agents ON MACHINES, because machines are what it is
    // about to change; attack mode counts what Caldera can actually drive, which
    // is the lane's agent roster. The fallback covers a server that does not
    // attach an agent to each target yet: reporting 0 there would tell an
    // instructor that a fully installed class has nothing installed.
    const agents = state.mode === 'attack' ? laneAgents
      : targets.some(vm => vm.agent) ? targets.filter(vm => classroomFresh(lane, vm)).length : laneAgents;
    const measured = { mode: state.mode, reason, eligible,
      number: classroomLaneNumber(lane), primary: classroomLanePrimary(lane), env: classroomEnvLabel(lane),
      kind: CLASSROOM_KIND_LABEL[lane.kind] || CLASSROOM_KIND_LABEL.lane,
      targets, running: targets.filter(vm => vm.runnable === true).length, agents,
      // Infrastructure is excluded: an ELK or Wazuh box with no Sandcat on it is
      // not work outstanding, and counting it would leave every lane in the
      // "needs agent" facet forever. classroomInfra() is the same predicate the
      // "Only missing agents" button selects by, so the count and the action
      // cannot disagree about what is left to do.
      missing: selectable.filter(vm => !classroomInfra(vm) && !classroomFresh(lane, vm)).length,
      busyIds, failedIds, busy: busyIds.size, failedJobs: failedIds.size,
      // One lowercase string per lane, so a keystroke is a substring scan rather
      // than a walk of every target. Deliberately excludes lane_id: a UUID's hex
      // makes any short numeric query match half the inventory.
      haystack: [lane.name, lane.student?.name, lane.student?.email, classroomLaneNumber(lane),
        lane.environment?.label, lane.environment?.key, lane.family, CLASSROOM_KIND_LABEL[lane.kind],
        ...targets.flatMap(vm => [vm.name, vm.machine_label, vm.role, vm.vm_id, vm.os])]
        .filter(value => value !== null && value !== undefined && value !== '').join(' ').toLowerCase() };
    _classroomLaneStats.set(lane, measured);
    return measured;
  }

  // Counts are informational, so these predicates may overlap. The pill label,
  // the pill count and the filter all read this one map, which is the only way
  // the three cannot drift apart.
  const CLASSROOM_LANE_FACETS = {
    install: {
      all: { label: 'All', test: () => true },
      needs: { label: 'Needs agent', test: measured => measured.eligible && measured.missing > 0 },
      installing: { label: 'Installing', test: measured => measured.busy > 0 },
      failed: { label: 'Failed', test: (measured, lane, errors) => measured.failedJobs > 0 || errors.has(String(lane.lane_id)) },
      done: { label: 'All installed', test: measured => measured.eligible && measured.missing === 0 && measured.agents > 0 },
      off: { label: 'Unavailable', test: measured => !measured.eligible },
    },
    attack: {
      all: { label: 'All', test: () => true },
      ready: { label: 'Ready', test: measured => measured.eligible },
      noagent: { label: 'No agent', test: (measured, lane) => !(Array.isArray(lane.agents) && lane.agents.length) },
      off: { label: 'Unavailable', test: measured => !measured.eligible },
    },
  };
  const classroomFacets = state => CLASSROOM_LANE_FACETS[state.mode] || CLASSROOM_LANE_FACETS.install;

  /**
   * The group a lane belongs to.
   *
   * KEYS ARE IDS, NEVER LABELS. An environment label resolves one poll later, or
   * not at all (see classroomEnvLabel) — so keying on it would put the same
   * environment in two groups on the same screen and reshuffle every collapsed
   * header underneath the instructor as the label arrived.
   */
  function classroomGroupKey(state, lane) {
    const by = state.view.groupBy;
    if (by === 'none') return 'all';
    if (by === 'student') {
      const student = lane.student || {};
      const identity = String(student.email || student.name || '').trim().toLowerCase();
      return identity ? `student:${identity}` : 'nostudent';
    }
    const environment = lane.environment || {};
    if (environment.key) return `env:${environment.key}`;
    return lane.kind ? `kind:${lane.kind}` : 'other';
  }

  /**
   * `members` is every lane carrying this key in the WHOLE inventory, not the
   * filtered or sorted subset: a heading derived from "the first visible lane"
   * moves when the instructor types or changes a facet, and a heading that moves
   * is a heading nobody can use to find anything twice.
   */
  function classroomGroupLabel(key, members) {
    if (key === 'all') return '';
    if (key === 'other') return 'Other lanes';
    if (key === 'nostudent') return 'No student assigned';
    if (key.startsWith('kind:')) return CLASSROOM_KIND_LABEL[key.slice(5)] || CLASSROOM_KIND_LABEL.lane;
    if (key.startsWith('env:')) {
      const labelled = members.find(lane => lane.environment && lane.environment.label);
      return labelled ? labelled.environment.label : members.length ? classroomEnvLabel(members[0]) : key.slice(4);
    }
    const named = members.find(lane => lane.student && lane.student.name);
    if (named) return named.student.name;
    const addressed = members.find(lane => lane.student && lane.student.email);
    return addressed ? addressed.student.email : 'Student';
  }

  /**
   * Everything the lane step needs, measured once per (payload, view) pair.
   *
   * The memo key carries the payload revision and every view field that can
   * change the answer. Collapse state is deliberately NOT one of them: it
   * changes what is drawn, not what matches, and including it would rebuild the
   * whole view on every header click.
   *
   * facetCounts are computed over the WHOLE inventory rather than the filtered
   * subset, so the pills say how much work exists rather than how much of it the
   * current filter happens to be showing — a "Failed 4" that drops to 0 because
   * you searched for a student is worse than no count at all.
   */
  function classroomLaneView(state) {
    const view = state.view;
    const cacheKey = [state.payloadRevision, view.groupBy, view.laneFacet, view.laneQuery].join(String.fromCharCode(0));
    if (state.laneViewKey === cacheKey) return state.laneView;
    const inventory = Array.isArray(state.payload?.lanes) ? state.payload.lanes : [];
    const tokens = classroomTokens(view.laneQuery);
    const facets = classroomFacets(state);
    const all = inventory.map((lane, index) => ({ lane, measured: classroomLaneStat(state, lane), index, key: classroomGroupKey(state, lane) }));
    const membersByKey = new Map();
    all.forEach(row => {
      if (!membersByKey.has(row.key)) membersByKey.set(row.key, []);
      membersByKey.get(row.key).push(row.lane);
    });
    const labels = new Map([...membersByKey].map(([key, members]) => [key, classroomGroupLabel(key, members)]));
    const facet = (facets[view.laneFacet] || facets.all).test;
    const matching = all.filter(row => facet(row.measured, row.lane, state.resultErrors)
      && classroomMatches(row.measured.haystack, tokens));
    const groups = new Map();
    matching.forEach(row => {
      if (!groups.has(row.key)) groups.set(row.key, { key: row.key, label: labels.get(row.key),
        order: row.key === 'other' || row.key === 'nostudent' ? 1 : 0, rows: [] });
      groups.get(row.key).rows.push(row);
    });
    // Lane number, then payload index — and the payload order is the server's
    // (name, lane_id) order, so lanes with no number at all keep the sequence
    // this dialog has always shown them in instead of being shuffled by a null.
    const compare = (a, b) => {
      if (a.measured.number === b.measured.number) return a.index - b.index;
      if (a.measured.number === null) return 1;
      if (b.measured.number === null) return -1;
      return a.measured.number - b.measured.number;
    };
    const list = [...groups.values()].map(group => ({ ...group, rows: group.rows.slice().sort(compare) }))
      .sort((a, b) => a.order - b.order || cmpText(a.label, b.label));
    const facetCounts = Object.fromEntries(Object.keys(facets)
      .map(name => [name, all.filter(row => facets[name].test(row.measured, row.lane, state.resultErrors)).length]));
    state.laneViewKey = cacheKey;
    state.laneView = { groups: list, matching, matchingIds: new Set(matching.map(row => row.lane.lane_id)),
      allGroupKeys: [...membersByKey.keys()], facetCounts };
    return state.laneView;
  }

  /**
   * One lane chip, on TWO lines, because one line cannot carry the identity.
   *
   * With 45 lanes named cle-cybr400-inperson-10880 a single-line chip ellipsises
   * to "cle-cybr400-i…" and every chip on screen is identical. Line one is the
   * student (the only label an instructor recognises); line two carries the lane
   * number, the environment, the work outstanding and the reason it cannot be
   * used, and is allowed to wrap rather than being squeezed to zero.
   *
   * The title goes on the <label>, NOT on the <input>. The test harness slices a
   * tag from the '<' before an id to the next '>' to read checked/disabled, so an
   * attribute sitting ahead of the input's id would land inside that slice — and
   * escHtml does not escape quotes, so in a real browser a lane name containing
   * one would break out of the attribute as well. Everything the instructor reads
   * is a text node AFTER the input, for the same reason.
   */
  function classroomLaneChip(state, row, locked) {
    const lane = row.lane;
    const measured = row.measured;
    const picked = state.lanes.has(lane.lane_id);
    const meta = state.mode === 'attack'
      ? `${classroomPlural(measured.agents, 'agent')} ready`
      : `${classroomPlural(measured.targets.length, 'VM')} · ${classroomPlural(measured.agents, 'agent')}`;
    return `<label class="cal-lane${picked ? ' is-picked' : ''}${measured.eligible ? '' : ' is-off'}" title="${escAttr(lane.name || lane.lane_id)}">`
      + `<input type="checkbox" id="${classroomId('Lane', lane.lane_id)}"${picked ? ' checked' : ''}${locked || !measured.eligible ? ' disabled' : ''}>`
      + '<span class="cal-lane-body">'
      + `<span class="cal-lane-name">${escHtml(measured.primary)}</span>`
      + '<span class="cal-lane-sub">'
      + (measured.number === null ? '' : `<span class="cal-lane-num">#${escHtml(String(measured.number))}</span>`)
      + `<span class="cal-lane-env">${escHtml(measured.env)}</span>`
      + `<span class="cal-lane-meta">${escHtml(meta)}</span>`
      // measured.reason is escaped like every other value in this template even
      // though it cannot need it today: classroomLaneReason() returns one of six
      // fixed literals it writes itself, none of which contains a markup
      // character. The escape is what keeps that from mattering. The moment a
      // reason is taken from the payload instead -- a server-supplied
      // "why this lane is unusable" string is the obvious next step -- this line
      // would be the one unescaped interpolation in a template where every
      // neighbour is escaped, and nothing about it would look wrong in review.
      + (measured.reason ? `<span class="badge ${CLASSROOM_REASON_BADGE[measured.reason] || 'badge-gray'}">${escHtml(measured.reason)}</span>` : '')
      + '</span></span></label>';
  }

  /**
   * One collapsible group of lane chips, with a tri-state select-all.
   *
   * A SEARCH FORCES EVERY MATCHING GROUP OPEN and disables the toggle, WITHOUT
   * touching state.view.collapsed: a hit hidden behind a closed header is
   * indistinguishable from having no hit at all, and clearing the box must
   * restore exactly the arrangement the instructor chose before they typed.
   * Disabling the toggle says so, rather than letting a press do nothing.
   *
   * `rendered` collects the rows that were actually drawn. It is the only array
   * the rebinding loop may walk: getElementById is unguarded there, so a chip
   * left inside a collapsed group and then dereferenced would throw and abort
   * the render half-bound, leaving every control after it inert.
   */
  function classroomGroupHtml(state, group, locked, searching, rendered) {
    const open = searching || !state.view.collapsed.has(group.key);
    if (open) rendered.push(...group.rows);
    const bodyId = classroomId('GroupBody', group.key);
    const body = open
      ? `<div class="cal-lanegrid" id="${bodyId}">${group.rows.map(row => classroomLaneChip(state, row, locked)).join('')}</div>`
      : '';
    if (group.key === 'all') return body;
    const eligible = group.rows.filter(row => row.measured.eligible);
    const picked = eligible.filter(row => state.lanes.has(row.lane.lane_id)).length;
    const vms = group.rows.reduce((total, row) => total + row.measured.targets.length, 0);
    const agents = group.rows.reduce((total, row) => total + row.measured.agents, 0);
    const off = group.rows.length - eligible.length;
    const meta = [classroomPlural(group.rows.length, 'lane'), classroomPlural(vms, 'VM'),
      classroomPlural(agents, 'agent'), `${picked} selected`].concat(off ? [`${off} off`] : []).join(' · ');
    return `<div class="cal-group${open ? '' : ' is-collapsed'}"><div class="cal-group-head">`
      // aria-controls is emitted ONLY while the body exists. A collapsed group
      // renders no #classroomGroupBody-… at all -- see `body` above, which is the
      // empty string -- so a constant aria-controls would point at nothing for
      // exactly the state in which a screen reader most wants to follow it, and
      // that dangling idref is what some ATs report as a broken control rather
      // than as a closed one. Dropping the attribute instead of always rendering
      // the body keeps the collapsed case genuinely empty, which is the whole
      // reason `rendered` exists: a chip that is not drawn is never rebound.
      // aria-expanded="false" still carries the state on its own.
      + `<button type="button" class="cal-group-toggle" id="${classroomId('Group', group.key)}" aria-expanded="${open ? 'true' : 'false'}"${open ? ` aria-controls="${bodyId}"` : ''}${searching ? ' disabled' : ''}>`
      + '<span class="cal-chev" aria-hidden="true"></span>'
      + `<span class="cal-group-title">${escHtml(group.label)}</span></button>`
      + `<label class="cal-gpick${picked && picked < eligible.length ? ' is-partial' : ''}">`
      + `<input type="checkbox" id="${classroomId('GroupAll', group.key)}"${eligible.length && picked === eligible.length ? ' checked' : ''}${locked || !eligible.length ? ' disabled' : ''}>`
      + `<span class="cal-sr-only">Select every available lane in ${escHtml(group.label)}</span></label>`
      + `<span class="cal-group-meta">${escHtml(meta)}</span></div>${body}</div>`;
  }

  function classroomOpen(state) {
    return _classroomCaldera === state && state.courseId === currentCourseId
      && tier === 'staff' && state.overlay.classList.contains('active');
  }

  function closeClassroomCaldera() {
    const state = _classroomCaldera;
    if (!state) return;
    _classroomCaldera = null;
    clearTimeout(state.timer);
    state.requests.forEach(controller => controller.abort());
    state.observer.disconnect();
    Modal.close(state.overlay);
    state.overlay.remove();
  }

  function classroomSetHtml(id, html) {
    const element = document.getElementById(id);
    // DOM serialization normalizes attributes/entities. Comparing innerHTML to
    // our template would rebuild unchanged inputs and interrupt choices on polls.
    if (_classroomHtmlTemplates.get(element) !== html) {
      element.innerHTML = html;
      _classroomHtmlTemplates.set(element, html);
    }
  }

  async function showClassroomCaldera(mode) {
    if (tier !== 'staff' || !currentCourseId) return;
    closeLaneCalderaModal();
    closeClassroomCaldera();
    const overlay = document.createElement('div');
    overlay.id = 'classroomCalderaModal';
    overlay.className = 'modal-overlay';
    const install = mode === 'install';
    // The pills are built from the same map the filter and the counts read, so a
    // label, its count and what it actually selects cannot drift apart. The
    // counts start at 0 and are written by every render; they are never markup.
    const shellFacets = classroomFacets({ mode });
    const facetPills = Object.keys(shellFacets).map(name =>
      `<button type="button" class="filter-pill${name === 'all' ? ' active' : ''}" id="classroomCalderaLaneFacet-${name}">`
      + `${shellFacets[name].label} <span class="pill-count" id="classroomCalderaLaneFacetCount-${name}">0</span></button>`).join('');
    // THE SHELL IS BUILT ONCE AND NEVER RE-RENDERED. Everything below that polls
    // writes into one of the island ids (Adversaries / Lanes / Machines /
    // Targets / SummaryBadges / Results); the ids OUTSIDE those islands are bound
    // here, once, so a 5s poll cannot destroy a control mid-keystroke and take
    // the caret with it. Shell-owned, in order of appearance: the profile filter
    // and its scope pills, the lane search box and its clear button
    // (classroomCalderaLaneSearch / …Clear), the Group by select
    // (classroomCalderaGroupBy), Expand all / Collapse all, the lane facet pills
    // and their counts (classroomCalderaLaneFacet-<key> /
    // classroomCalderaLaneFacetCount-<key>), the shown / hidden line
    // (classroomCalderaLaneShown / …Hidden), every panel counter, and the whole
    // footer. A search box rebuilt by a poll would eat its own caret; a facet
    // pill rebuilt under the pointer would move out from under the click.
    //
    // Nesting an island inside another island would also break
    // classroomSetHtml()'s identity cache, since its WeakMap is keyed on the
    // element object the parent render would replace. THE ONE EXCEPTION is a
    // LEAF island that carries no id= at all and is written AFTER its parent:
    // nothing inside it is addressed by id, so the parent rewriting it is not a
    // loss, and it lets a fast-changing cell re-render without rebuilding the
    // table around it.
    //
    // NO INLINE STYLES. The old markup carried style="max-width:1000px" plus a
    // handful of raw hexes (#e53e3e, --gray-500) that had no dark-theme value,
    // which is most of why this dialog read as unstyled; an inline style would
    // also beat the .cal-* rules in courses.html.
    //
    // Layout is header / scrolling body / pinned footer, and the <form> spans
    // body AND footer so the submit button is a plain in-form submit rather than
    // a detached button relying on form="…". The old dialog put everything in
    // .modal, which is max-height:90vh with its own scroll, so with six lanes
    // and eighteen target rows the submit button scrolled off the bottom.
    overlay.innerHTML = `<div class="modal cal-modal" role="dialog" aria-modal="true" aria-labelledby="classroomCalderaTitle">
      <div class="modal-header">
        <h3 id="classroomCalderaTitle">${install ? 'Group install agents' : 'Run Caldera attack'}</h3>
        <button type="button" id="classroomCalderaClose" class="modal-close" aria-label="Close Caldera classroom controls">&times;</button>
      </div>
      <form id="classroomCalderaForm" class="cal-form">
        <div class="cal-body">
          <div class="info-box cal-lede"><p>${install
            ? 'Install the Caldera agent on many lane VMs at once. Pick lanes, pick machines, then review the target list &mdash; nothing is sent until you press Install.'
            : 'Start one Caldera operation per selected lane. Each lane gets its own operation and agent group; execution begins at each agent&rsquo;s next check-in, not when you press Launch.'}</p></div>
          <details class="cal-explain"><summary>${install ? 'What installing changes on a VM' : 'How adversary profiles work'}</summary>
            <p>${install
              ? 'Windows targets get the same Microsoft Defender adjustments and agent-folder exclusion as the single-VM installer, and those changes stay on the VM afterwards. Linux targets get the agent binary started as a detached background process &mdash; there is no service and nothing survives a reboot, so a restarted Linux VM has to be installed again. You can close this window while installation runs &mdash; reopen it to check progress.'
              : 'An ability is one attack step; an adversary is an ordered profile of abilities. Build them in the Caldera console, ordering abilities and choosing executors that match the agents you installed. Students inspect the resulting activity in their lane&rsquo;s existing ELK/SIEM. You can close this window while the exercise runs &mdash; reopen it to check progress.'}</p>
          </details>
          ${install ? '<div id="classroomCalderaAdversaries"></div>' : `<section class="cal-panel">
            <div class="cal-panel-head"><span class="cal-step">1</span><h4 class="cal-panel-title">Adversary profile</h4>
              <span class="cal-count" id="classroomCalderaAdvCount"></span></div>
            <div class="cal-panel-body">
              <div class="cal-advtools">
                <div class="cal-search">
                  <input type="search" id="classroomCalderaAdversarySearch" class="cal-searchbox" placeholder="Filter profiles" autocomplete="off" aria-label="Filter adversary profiles by name">
                  <button type="button" class="cal-search-clear" id="classroomCalderaAdversaryClear" aria-label="Clear the profile filter">&times;</button>
                </div>
                <div class="cal-advpills">
                  <button type="button" class="filter-pill" id="classroomCalderaAdvScopeBuilt">Profiles</button>
                  <button type="button" class="filter-pill" id="classroomCalderaAdvScopeAll">Past launches</button>
                </div>
              </div>
              <div id="classroomCalderaAdversaries"></div>
            </div></section>`}
          <section class="cal-panel">
            <div class="cal-panel-head"><span class="cal-step">${install ? '1' : '2'}</span><h4 class="cal-panel-title">Student lanes</h4>
              <span class="cal-count" id="classroomCalderaLaneCount"></span>
              <div class="cal-panel-actions">
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaSelectLanes">All available</button>
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaClearLanes">Clear</button>
              </div></div>
            <div class="cal-tools">
              <div class="cal-search">
                <input type="search" id="classroomCalderaLaneSearch" class="cal-searchbox" placeholder="Search students, lanes, machines" autocomplete="off" aria-label="Filter lanes by student, lane name or number, environment, machine name or VM id">
                <button type="button" class="cal-search-clear" id="classroomCalderaLaneSearchClear" aria-label="Clear the lane filter">&times;</button>
              </div>
              <label class="cal-toollabel">Group by <select id="classroomCalderaGroupBy" class="cal-select cal-select-sm"><option value="environment">Environment</option><option value="student">Student</option><option value="none">None</option></select></label>
              <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaExpandAll">Expand all</button>
              <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaCollapseAll">Collapse all</button>
            </div>
            <div class="filter-pills cal-facets" role="group" aria-label="Lane status filter">${facetPills}</div>
            <p class="cal-shown"><span id="classroomCalderaLaneShown" role="status"></span> <span id="classroomCalderaLaneHidden" class="cal-flagged"></span></p>
            <div class="cal-panel-body cal-lanescroll" id="classroomCalderaLanes"></div>
          </section>
          ${install ? `<div id="classroomCalderaMachines"></div>
          <section class="cal-panel" id="classroomCalderaTargetPanel">
            <div class="cal-panel-head"><span class="cal-step">3</span><h4 class="cal-panel-title">Targets</h4>
              <span class="cal-count" id="classroomCalderaTargetCount"></span>
              <div class="cal-panel-actions">
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaTargetsShown">Select all shown</button>
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaTargetsMissing">Only missing agents</button>
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaTargetsRetry">Retry failed</button>
                <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaTargetsClear">Clear</button>
              </div></div>
            <div class="cal-tools">
              <div class="cal-search">
                <input type="search" id="classroomCalderaTargetSearch" class="cal-searchbox" placeholder="Search machines, VM ids, status" autocomplete="off" aria-label="Filter the target list by student, lane, machine name, VM id, operating system or status">
                <button type="button" class="cal-search-clear" id="classroomCalderaTargetSearchClear" aria-label="Clear the target filter">&times;</button>
              </div>
            </div>
            <p class="cal-shown"><span id="classroomCalderaTargetShown" role="status"></span> <span id="classroomCalderaTargetHidden" class="cal-flagged"></span></p>
            <div id="classroomCalderaTargets"></div>
          </section>` : ''}
          <div id="classroomCalderaResults" class="cal-results" aria-live="polite"></div>
        </div>
        <div class="cal-footer">
          <p id="classroomCalderaError" role="alert"></p>
          ${install ? '<p id="classroomCalderaHiddenNote" class="cal-hint is-warn"></p>' : ''}
          <div class="cal-footer-row">
            <div class="cal-bar-state">
              <div id="classroomCalderaSummaryBadges" class="cal-chips"></div>
              <p id="classroomCalderaSummary" class="cal-bar-text" role="status" aria-live="polite"></p>
            </div>
            <div class="cal-bar-actions">
              <button type="button" class="btn btn-secondary btn-sm" id="classroomCalderaRefresh">Refresh status</button>
              <button type="submit" class="btn btn-primary" id="classroomCalderaSubmit" disabled>${install ? 'Install selected agents' : 'Launch on selected lanes'}</button>
            </div>
          </div>
        </div>
      </form>
    </div>`;
    document.body.appendChild(overlay);
    const pending = install ? null : _pendingCalderaLaunches.get(currentCourseId);
    const state = { mode, courseId: currentCourseId, overlay, payload: null, timer: null, requests: new Set(),
      submitting: false, refreshing: false, misses: 0, revision: 0, fresh: false, error: '',
      lanes: new Set(pending?.lane_ids || []), machines: new Set(), targets: new Set(), excludedTargets: new Set(), platforms: new Map(), machinePlatforms: new Map(),
      // THE VIEW LIVES HERE, NEVER IN THE DOM. A poll landing mid-keystroke
      // rewrites the lane island, and anything this render read back out of an
      // input would be lost along with it.
      view: { laneQuery: '', laneFacet: 'all', groupBy: 'environment', collapsed: new Set(),
        targetQuery: '', targetSort: 'lane', targetDir: 'asc' },
      // payloadRevision invalidates the memoized lane view; resultErrors is the
      // per-lane index the "failed" facet reads. Both are refreshed wherever
      // state.payload or state.results is assigned — and wherever a submission
      // mutates a lane in place — so no view can outlive the data behind it.
      payloadRevision: 0, laneViewKey: null, laneView: null, resultErrors: new Set(),
      // Filter state for the adversary picker. Held here, never read back off
      // the DOM, so a poll landing mid-typing cannot lose it.
      adversarySearch: '', adversaryScope: 'built',
      // The profile the payload in hand was requested for. Full ability detail
      // arrives for that one profile alone, so this is what says whether the
      // card can be drawn from the payload or has to wait for another request.
      payloadAdversary: null,
      adversary: pending?.adversary_id || '', pending, results: [] };
    _classroomCaldera = state;
    document.getElementById('classroomCalderaClose').onclick = closeClassroomCaldera;
    document.getElementById('classroomCalderaRefresh').onclick = () => refreshClassroomCaldera(state);
    document.getElementById('classroomCalderaForm').onsubmit = event => { event.preventDefault(); return submitClassroomCaldera(state); };
    document.getElementById('classroomCalderaSelectLanes').onclick = () => selectClassroomLanes(state, true);
    document.getElementById('classroomCalderaClearLanes').onclick = () => selectClassroomLanes(state, false);
    // Bound ONCE, on the shell, because #classroomCalderaLanes is rewritten by
    // every poll: a search box living inside that island would eat its own focus
    // and the caret with it on each keystroke. Handlers are .onX PROPERTIES, not
    // addEventListener, and none of them needs an event argument — the test
    // harness calls .onclick() with none at all and .onchange({ target: el })
    // with nothing else on the event.
    const laneSearch = document.getElementById('classroomCalderaLaneSearch');
    laneSearch.oninput = laneSearch.onchange = () => { state.view.laneQuery = laneSearch.value; renderClassroomCaldera(state); };
    const clearLaneSearch = () => {
      laneSearch.value = '';
      state.view.laneQuery = '';
      renderClassroomCaldera(state);
      laneSearch.focus();
    };
    document.getElementById('classroomCalderaLaneSearchClear').onclick = clearLaneSearch;
    laneSearch.onkeydown = event => {
      // EVERY control in this dialog sits inside #classroomCalderaForm, and that
      // form's submit queues the entire batch. An unswallowed Enter in the search
      // box installs agents on every selected VM. The guards exist because the
      // harness invokes this with no argument, and a bare call must not throw.
      if (!event) return;
      if (event.key === 'Enter' && event.preventDefault) event.preventDefault();
      // app.js closes the topmost overlay on Escape. Swallow it only while there
      // is text to clear, so an empty box still closes the dialog.
      if (event.key === 'Escape' && laneSearch.value) {
        if (event.preventDefault) event.preventDefault();
        if (event.stopPropagation) event.stopPropagation();
        clearLaneSearch();
      }
    };
    const groupBy = document.getElementById('classroomCalderaGroupBy');
    groupBy.onchange = () => {
      state.view.groupBy = groupBy.value;
      // Keys mean something else on a new axis, so the old collapse set is not
      // stale — it is meaningless, and keeping it would close arbitrary groups.
      state.view.collapsed = new Set();
      renderClassroomCaldera(state);
    };
    document.getElementById('classroomCalderaExpandAll').onclick = () => { state.view.collapsed = new Set(); renderClassroomCaldera(state); };
    document.getElementById('classroomCalderaCollapseAll').onclick = () => {
      state.view.collapsed = new Set(classroomLaneView(state).allGroupKeys.filter(key => key !== 'all'));
      renderClassroomCaldera(state);
    };
    Object.keys(classroomFacets(state)).forEach(name => {
      document.getElementById(`classroomCalderaLaneFacet-${name}`).onclick = () => { state.view.laneFacet = name; renderClassroomCaldera(state); };
    });
    if (install) {
      // The target search and the four quick actions are shell-owned for the
      // same reason the lane search is: #classroomCalderaTargets is rewritten by
      // every 5s poll, and a search box inside it would eat its own caret. The
      // quick actions recompute the row list from state rather than closing over
      // the array the last render built, which by now may name lanes that have
      // been torn down.
      const targetSearch = document.getElementById('classroomCalderaTargetSearch');
      targetSearch.oninput = targetSearch.onchange = () => { state.view.targetQuery = targetSearch.value; renderClassroomCaldera(state); };
      const clearTargetSearch = () => {
        targetSearch.value = '';
        state.view.targetQuery = '';
        renderClassroomCaldera(state);
        targetSearch.focus();
      };
      document.getElementById('classroomCalderaTargetSearchClear').onclick = clearTargetSearch;
      targetSearch.onkeydown = event => {
        // Same trap as the lane search: this input sits inside
        // #classroomCalderaForm, whose submit queues the whole batch.
        if (!event) return;
        if (event.key === 'Enter' && event.preventDefault) event.preventDefault();
        if (event.key === 'Escape' && targetSearch.value) {
          if (event.preventDefault) event.preventDefault();
          if (event.stopPropagation) event.stopPropagation();
          clearTargetSearch();
        }
      };
      document.getElementById('classroomCalderaTargetsShown').onclick = () => {
        if (state.submitting) return;
        classroomTargetView(state, classroomTargetRows(state)).shown
          .filter(row => classroomVmAvailable(state, row.lane, row.vm))
          .forEach(row => {
            const key = classroomVmKey(row.lane, row.vm);
            state.targets.add(key);
            state.excludedTargets.delete(key);
          });
        renderClassroomCaldera(state);
      };
      document.getElementById('classroomCalderaTargetsMissing').onclick = () => {
        if (state.submitting) return;
        // DESELECTS as well as selects, and that is the point: the instructor is
        // asking for "the machines that still need an agent and nothing else".
        // A purely additive version would leave the SIEM and the attack box
        // ticked from an earlier machine-level selection and quietly queue an
        // install onto both. Everything it removes is also excluded, so the
        // machine selection above does not put it straight back.
        classroomTargetView(state, classroomTargetRows(state)).shown.forEach(row => {
          const key = classroomVmKey(row.lane, row.vm);
          if (classroomVmAvailable(state, row.lane, row.vm) && !classroomInfra(row.vm) && !classroomFresh(row.lane, row.vm)) {
            state.targets.add(key);
            state.excludedTargets.delete(key);
          } else {
            state.targets.delete(key);
            state.excludedTargets.add(key);
          }
        });
        renderClassroomCaldera(state);
      };
      document.getElementById('classroomCalderaTargetsRetry').onclick = () => {
        if (state.submitting) return;
        state.targets.clear();
        state.machines.clear();
        // A VM whose job says failed but whose agent is checked in is NOT
        // retried. That combination is the exact defect this release fixes: the
        // Windows installer's detached agent holds the guest-exec pipes open, the
        // exec wait times out, the job records a failure — and the agent is
        // beaconing the whole time. Re-running the install on those machines is
        // pure churn, and it would make "Retry failed" the button that undoes a
        // working class.
        classroomTargetView(state, classroomTargetRows(state)).shown.forEach(row => {
          if (!classroomVmAvailable(state, row.lane, row.vm) || classroomFresh(row.lane, row.vm)) return;
          if (row.word !== 'install failed' && !state.resultErrors.has(String(row.lane.lane_id))) return;
          const key = classroomVmKey(row.lane, row.vm);
          state.targets.add(key);
          state.excludedTargets.delete(key);
        });
        renderClassroomCaldera(state);
      };
      document.getElementById('classroomCalderaTargetsClear').onclick = () => {
        if (state.submitting) return;
        state.targets.clear();
        state.machines.clear();
        state.excludedTargets.clear();
        renderClassroomCaldera(state);
      };
    }
    if (!install) {
      // Bound once, on the shell, for the reason the filter lives there at all:
      // #classroomCalderaAdversaries is rewritten wholesale on every 5s poll, and
      // a search box inside it would eat its own focus on each keystroke.
      //
      // Handlers are .onX PROPERTIES, not addEventListener, and none of them
      // reads an event argument — the test harness invokes .onclick() with no
      // arguments at all and .onchange({ target: el }) with nothing else on it.
      const search = document.getElementById('classroomCalderaAdversarySearch');
      search.oninput = search.onchange = () => { state.adversarySearch = search.value; renderClassroomCaldera(state); };
      const clearAdversarySearch = () => {
        search.value = ''; state.adversarySearch = ''; renderClassroomCaldera(state); search.focus();
      };
      document.getElementById('classroomCalderaAdversaryClear').onclick = clearAdversarySearch;
      search.onkeydown = event => {
        // THE SAME TRAP AS THE LANE AND TARGET SEARCHES, and the most expensive
        // one to fall into. This input is a text control inside
        // #classroomCalderaForm, and by the time an instructor is narrowing the
        // profile list they have already chosen lanes and a profile, so
        // #classroomCalderaSubmit is enabled — which is exactly the condition
        // for implicit submission. Enter typed to filter "worm" would run
        // submitClassroomCaldera and POST one Caldera operation per selected
        // lane, across the whole class, with no confirmation step in between.
        // The guards exist because the harness invokes this with no argument,
        // and a bare call must not throw.
        if (!event) return;
        if (event.key === 'Enter' && event.preventDefault) event.preventDefault();
        // app.js closes the topmost overlay on Escape. Swallow it only while
        // there is text to clear, so an empty box still closes the dialog.
        if (event.key === 'Escape' && search.value) {
          if (event.preventDefault) event.preventDefault();
          if (event.stopPropagation) event.stopPropagation();
          clearAdversarySearch();
        }
      };
      document.getElementById('classroomCalderaAdvScopeBuilt').onclick = () => { state.adversaryScope = 'built'; renderClassroomCaldera(state); };
      document.getElementById('classroomCalderaAdvScopeAll').onclick = () => { state.adversaryScope = 'all'; renderClassroomCaldera(state); };
    }
    state.observer = new MutationObserver(() => {
      if (_classroomCaldera === state && !overlay.classList.contains('active')) closeClassroomCaldera();
    });
    state.observer.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    Modal.open(overlay.id);
    await refreshClassroomCaldera(state);
  }

  function classroomVmAvailable(state, lane, vm) {
    return classroomLaneAvailable(state, lane) && vm.type === 'qemu' && vm.runnable === true && !classroomBusy(lane, vm);
  }

  /**
   * The OS this VM will be installed with: a row override, else the choice made
   * against its MACHINE, else whatever the server inferred from the template.
   *
   * state.machines and state.machinePlatforms are keyed on the machine key, not
   * on the bare lowercased VM name they used to key on, and that rekeying is a
   * bug fix in both directions. The old key grouped nothing in a course whose 44
   * workstation lanes each carry a unique hostname (cle-cybr400-inperson-10880-ws1),
   * so "tick one name, select it everywhere" selected exactly one VM — and at the
   * same time it collided DC01 in one challenge environment with DC01 in another
   * onto a single checkbox, so choosing Windows for one silently chose it for a
   * machine in a different environment the instructor had not looked at. The
   * machine key is scoped to the environment and stable across lanes, which is
   * what both cases actually need.
   */
  function classroomPlatform(state, lane, vm) {
    if (state.platforms.has(classroomVmKey(lane, vm))) return state.platforms.get(classroomVmKey(lane, vm));
    return state.machinePlatforms.get(classroomMachineKey(lane, vm))
      || (['windows', 'linux'].includes(vm.platform) ? vm.platform : '');
  }

  function classroomSelectedTargets(state) {
    return (state.payload?.lanes || []).flatMap(lane => state.lanes.has(lane.lane_id)
      ? (lane.targets || []).filter(vm => state.targets.has(classroomVmKey(lane, vm)) && classroomVmAvailable(state, lane, vm))
        .map(vm => ({ lane_id: lane.lane_id, vm_id: vm.vm_id, platform: classroomPlatform(state, lane, vm) })) : []);
  }

  function selectClassroomLanes(state, all) {
    if (!classroomOpen(state) || state.submitting || state.pending) return;
    // "All available" is ADDITIVE and scoped to what the filter is showing, so
    // an instructor can search two students in turn and select both. Collapse is
    // presentation only, so a matching lane inside a closed group is selected
    // too. Clear stays global: clearing a filtered list means all of it, and a
    // Clear that left invisible lanes selected would queue them on submit.
    if (all) classroomLaneView(state).matching.filter(row => row.measured.eligible).forEach(row => state.lanes.add(row.lane.lane_id));
    else state.lanes.clear();
    applyClassroomMachineSelection(state);
    renderClassroomCaldera(state);
  }

  function applyClassroomMachineSelection(state) {
    (state.payload?.lanes || []).forEach(lane => {
      if (!state.lanes.has(lane.lane_id)) return;
      (lane.targets || []).forEach(vm => {
        const key = classroomVmKey(lane, vm);
        if (state.machines.has(classroomMachineKey(lane, vm)) && !state.excludedTargets.has(key) && classroomVmAvailable(state, lane, vm)) state.targets.add(key);
      });
    });
  }

  /** "1 VM" / "3 VMs" — the count and the word, never split across elements. */
  const classroomPlural = (count, word) => `${count} ${word}${count === 1 ? '' : 's'}`;

  /**
   * A Caldera / job / power status, mapped to a badge modifier.
   *
   * Only the modifiers that main.css gives a [data-theme="dark"] rule are
   * reachable from here. .badge-primary and the .alert-* family are deliberately
   * absent: they are hardcoded light hexes with no dark counterpart, so they are
   * illegible in the theme half this page's users actually run.
   */
  function classroomStatusBadge(status) {
    const value = String(status || '').toLowerCase();
    if (['running', 'started', 'preparing', 'paused', 'installing'].includes(value)) return 'badge-info';
    if (['finished', 'completed'].includes(value)) return 'badge-success';
    if (['failed', 'aborted'].includes(value)) return 'badge-danger';
    if (['stopped', 'cleanup', 'out_of_time'].includes(value)) return 'badge-muted';
    if (['queued', 'pending'].includes(value)) return 'badge-warning';
    return 'badge-gray';
  }

  /**
   * Is this adversary a snapshot of a past launch rather than something a human
   * built?
   *
   * Every classroom launch writes its profile back to Caldera under a generated
   * name, so after a term the picker is mostly rows nobody chose to create and
   * nobody wants to launch again. src/utils/caldera-lane-operations.js:157 is
   * where they are minted, and the name and the description it stamps are the
   * ONLY signal on the wire — the adversary projection carries no origin field —
   * so both are matched here. If that naming ever changes, this degrades to
   * showing snapshots alongside built profiles, which is today's behaviour.
   */
  function classroomSnapshot(adversary) {
    return /^Classroom [0-9a-f]{8}: /.test(adversary.name || '')
      || adversary.description === 'Snapshot for a CyberCore classroom exercise.';
  }

  /** The profile's name with the generated snapshot prefix taken back off. */
  const classroomAdversaryName = adversary =>
    String(adversary.name || adversary.adversary_id || '').replace(/^Classroom [0-9a-f]{8}: /, '');

  /**
   * The OS <select> options.
   *
   * The placeholder is a parameter because the two call sites mean different
   * things by an empty value: on a machine name it means "use each VM's own OS",
   * on a single row it means "not chosen yet, and this blocks submission". It
   * used to be one hardcoded label that the machine-name call site then deleted
   * again with a regex over its own output.
   *
   * The placeholder is trusted markup (an entity-carrying literal from this
   * file), never server data.
   */
  function classroomPlatformOptions(selected, placeholder) {
    return `<option value=""${selected ? '' : ' selected'}>${placeholder}</option>`
      + ['windows', 'linux'].map(platform => `<option value="${platform}"${selected === platform ? ' selected' : ''}>${platform === 'windows' ? 'Windows' : 'Linux'}</option>`).join('');
  }

  function renderClassroomCaldera(state) {
    if (!classroomOpen(state)) return;
    const data = state.payload || {};
    const lanes = Array.isArray(data.lanes) ? data.lanes : [];
    const locked = state.submitting || !!state.pending;
    const view = classroomLaneView(state);
    const searching = classroomTokens(state.view.laneQuery).length > 0;
    // Preserved across the island rewrite. Forty-five lanes make this list
    // scroll, and a poll that dropped the instructor back at the top every five
    // seconds would make the bottom of the class unreachable by scrolling.
    const laneScroll = document.getElementById('classroomCalderaLanes').scrollTop || 0;
    // The ONLY array the rebind loop below may walk — see classroomGroupHtml().
    const rendered = [];
    classroomSetHtml('classroomCalderaLanes', !lanes.length
      ? '<div class="cal-empty"><strong>No deployed lanes</strong><p>Deploy this course&rsquo;s lanes from the Environments tab, then press Refresh status.</p></div>'
      : !view.groups.length
        ? '<div class="cal-empty"><strong>No lanes match</strong><p>Nothing in this course matches the search box and the status filter together.</p><button type="button" class="btn btn-secondary btn-sm" id="classroomLaneNoMatchClear">Clear filters</button></div>'
        : view.groups.map(group => classroomGroupHtml(state, group, locked, searching, rendered)).join(''));
    document.getElementById('classroomCalderaLanes').scrollTop = laneScroll;
    rendered.forEach(({ lane }) => {
      document.getElementById(classroomId('Lane', lane.lane_id)).onchange = event => {
        if (locked || !classroomLaneAvailable(state, lane)) return;
        if (event.target.checked) state.lanes.add(lane.lane_id); else state.lanes.delete(lane.lane_id);
        applyClassroomMachineSelection(state);
        renderClassroomCaldera(state);
      };
    });
    view.groups.forEach(group => {
      if (group.key === 'all') return;
      document.getElementById(classroomId('Group', group.key)).onclick = () => {
        // Disabled in the markup while a search is running, but the harness can
        // still call this: a press that quietly rearranged collapse state behind
        // a forced-open group would surface as a scrambled list on clearing.
        if (searching) return;
        if (state.view.collapsed.has(group.key)) state.view.collapsed.delete(group.key); else state.view.collapsed.add(group.key);
        renderClassroomCaldera(state);
      };
      const box = document.getElementById(classroomId('GroupAll', group.key));
      const eligible = group.rows.filter(row => row.measured.eligible);
      const picked = eligible.filter(row => state.lanes.has(row.lane.lane_id)).length;
      // indeterminate has no HTML attribute, so it is set here as a property;
      // the .is-partial class in the template mirrors it for anything reading
      // the markup rather than the live element.
      box.indeterminate = picked > 0 && picked < eligible.length;
      box.onchange = () => {
        if (locked) return;
        eligible.forEach(row => {
          if (box.checked) state.lanes.add(row.lane.lane_id); else state.lanes.delete(row.lane.lane_id);
        });
        applyClassroomMachineSelection(state);
        renderClassroomCaldera(state);
      };
    });
    // Present only in the no-match empty state, so this one getElementById is
    // guarded where the others are not.
    const noMatch = document.getElementById('classroomLaneNoMatchClear');
    if (noMatch) noMatch.onclick = () => {
      state.view.laneQuery = '';
      state.view.laneFacet = 'all';
      document.getElementById('classroomCalderaLaneSearch').value = '';
      renderClassroomCaldera(state);
    };
    const availableLanes = lanes.filter(lane => classroomLaneAvailable(state, lane)).length;
    const filtered = searching || state.view.laneFacet !== 'all';
    // .textContent + .className rather than markup: this counter is small enough
    // to be plain text, and keeping it so means the panel header never re-creates
    // an element the poll-identity contract depends on.
    const laneCount = document.getElementById('classroomCalderaLaneCount');
    laneCount.textContent = `${state.lanes.size} of ${availableLanes} selected`
      + (filtered ? ` · ${view.matching.length} of ${lanes.length} shown` : '');
    laneCount.className = `cal-count${state.lanes.size ? ' is-ok' : ''}`;
    // ADDITIVE over what the filter is showing, and it says so: "All available"
    // on an unfiltered list means the class, but pressing it after searching for
    // one student must not silently queue the other forty-four.
    const unpicked = view.matching.filter(row => row.measured.eligible && !state.lanes.has(row.lane.lane_id)).length;
    const selectLanes = document.getElementById('classroomCalderaSelectLanes');
    selectLanes.textContent = filtered ? `All matching (${unpicked})` : 'All available';
    selectLanes.disabled = locked || !view.matching.some(row => row.measured.eligible);
    document.getElementById('classroomCalderaClearLanes').disabled = locked || !state.lanes.size;
    document.getElementById('classroomCalderaLaneShown').textContent = !lanes.length ? ''
      : filtered ? `Showing ${view.matching.length} of ${lanes.length} lanes`
        : classroomPlural(lanes.length, 'lane');
    // Intersected with the LIVE payload: state.lanes keeps the ids of lanes that
    // have since been torn down, and counting those would report a phantom
    // hidden selection forever, with no filter active at all.
    const hiddenLanes = lanes.filter(lane => state.lanes.has(lane.lane_id) && !view.matchingIds.has(lane.lane_id)).length;
    document.getElementById('classroomCalderaLaneHidden').textContent = hiddenLanes
      ? `${classroomPlural(hiddenLanes, 'selected lane')} hidden by the filter` : '';
    const facets = classroomFacets(state);
    Object.keys(facets).forEach(name => {
      const pill = document.getElementById(`classroomCalderaLaneFacet-${name}`);
      const active = state.view.laneFacet === name;
      pill.className = `filter-pill${active ? ' active' : ''}`;
      pill.ariaPressed = active ? 'true' : 'false';
      document.getElementById(`classroomCalderaLaneFacetCount-${name}`).textContent = String(view.facetCounts[name]);
    });
    // Assigned on EVERY render, not trusted to the markup: writing innerHTML on
    // the shell sets the parent's value from its first <option>, so this select
    // reads '' in the test harness until something assigns it, and a cache hit
    // means classroomSetHtml() never touches the DOM at all.
    document.getElementById('classroomCalderaGroupBy').value = state.view.groupBy;
    // The view controls stay enabled while a submission is in flight: they only
    // change what is drawn, never what is queued, and locking an instructor out
    // of the search box while forty installs run is the opposite of useful.
    // Expand / Collapse are the exception, because a search already forces every
    // matching group open and there is nothing left for them to do.
    const grouped = state.view.groupBy !== 'none' && view.groups.length > 0;
    document.getElementById('classroomCalderaExpandAll').disabled = !grouped || searching;
    document.getElementById('classroomCalderaCollapseAll').disabled = !grouped || searching;
    document.getElementById('classroomCalderaRefresh').disabled = state.submitting || state.refreshing;
    if (state.mode === 'install') renderClassroomInstall(state, lanes); else renderClassroomAttack(state, lanes);
    // abilities_error belongs in this chain for the same reason every other
    // field in it does: the profile card degrades silently without it. A catalog
    // read that failed leaves `summary: null` and `abilities: {}`, which is
    // indistinguishable from a profile the server genuinely has nothing to say
    // about — so the card would quietly describe a real 13-step operation as
    // undescribable and nothing on screen would mention the outage.
    document.getElementById('classroomCalderaError').textContent = data.configuration_error || data.power_error || data.agents_error || data.operations_error || data.abilities_error || state.error || '';
  }

  // ---- install mode: machines, targets, progress ---------------------------

  /**
   * Every QEMU machine in every SELECTED lane, in payload order.
   *
   * Recomputed from state on each call rather than handed down, because the
   * quick-action buttons are shell-owned and bound once at open: closing over
   * the array a render built would let a button act on lanes a later poll has
   * already torn down.
   */
  function classroomTargetRows(state) {
    return (state.payload?.lanes || []).flatMap(lane => state.lanes.has(lane.lane_id)
      ? (lane.targets || []).filter(vm => vm.type === 'qemu').map(vm => ({ lane, vm })) : []);
  }

  /** This VM's most recent install job, whatever its status, or null. */
  const classroomJobFor = (lane, vm) => classroomJobs(lane).find(job => String(job.vm_id) === String(vm.vm_id)) || null;

  /**
   * The OS the server read off the challenge spec, or '' when it does not know.
   *
   * The spec's own default for an unanswered row is the LITERAL STRING "Unknown",
   * which is a placeholder, not knowledge. Letting it through would make a search
   * for "unknown" match every machine nobody has described, which is the exact
   * set of machines that search is least able to help with.
   */
  const classroomOs = vm => {
    const os = String(vm.os || '').trim();
    return os && os.toLowerCase() !== 'unknown' ? os : '';
  };

  /**
   * ONE WORD for what is true of this VM right now: the string the target table
   * sorts on, searches over, and that the quick actions test.
   *
   * "checked in" OUTRANKS "install failed", and that branch order is the whole of
   * this release's honesty fix. The Windows installer starts Sandcat detached,
   * the detached process keeps the guest-exec output handles open, and QEMU only
   * reports the script as exited once they close — so the exec wait hits its
   * deadline and the job records a failure while the agent has been beaconing to
   * Caldera the entire time. Reading the job first told an instructor to go and
   * repair four machines that were already working.
   */
  function classroomTargetWord(state, lane, vm) {
    const job = classroomJobFor(lane, vm);
    if (job && ['queued', 'running'].includes(job.status)) return job.status === 'running' ? 'installing' : 'install queued';
    const agent = classroomAgentOf(lane, vm);
    if (agent && agent.fresh !== false) return 'checked in';
    if (job && job.status === 'failed') return 'install failed';
    if (agent) return 'stale';
    if (!classroomLaneAvailable(state, lane)) return 'lane unavailable';
    if (vm.runnable !== true) return String(vm.power_state || 'unknown');
    return 'no agent';
  }

  // Work in flight first, work outstanding next, finished work last — and a bare
  // power-state word, which is none of those, after all of them.
  const CLASSROOM_STATUS_RANK = { installing: 0, 'install queued': 1, 'install failed': 2,
    'no agent': 3, stale: 4, 'checked in': 5, 'lane unavailable': 6 };

  // [sortKey, label, column class]. Agent carries a null key deliberately: its
  // cell is a leaf island whose contents change on their own, and sorting on it
  // would sort on exactly the facts the Status key already sorts on.
  const CLASSROOM_TARGET_COLUMNS = [['lane', 'Lane', ''], ['machine', 'Machine', 'cal-c-machine'],
    ['os', 'Operating system', 'cal-c-os'], [null, 'Agent', 'cal-c-agent'], ['status', 'Status', 'cal-c-status']];

  /**
   * Which target rows to draw, and in what order.
   *
   * THE DEFAULT SORT REPRODUCES THE PAYLOAD ORDER BYTE FOR BYTE — lane number,
   * then the row's index in the payload. That matters more than it looks: a poll
   * that changes nothing then produces an identical template, classroomSetHtml()
   * declines to touch the DOM at all, and the caret, the scroll position and any
   * open dropdown stay where the instructor left them. A sort that reshuffled
   * equal rows would rebuild this table twelve times a minute.
   */
  function classroomTargetView(state, rows) {
    const tokens = classroomTokens(state.view.targetQuery);
    const direction = state.view.targetDir === 'desc' ? -1 : 1;
    const annotated = rows.map(({ lane, vm }, index) => {
      const measured = classroomLaneStat(state, lane);
      const word = classroomTargetWord(state, lane, vm);
      return { lane, vm, index, measured, word,
        haystack: [measured.primary, lane.name, measured.number, measured.env, classroomMachineLabel(vm), vm.name,
          vm.vm_id, classroomRoleLabel(vm)[0], classroomOs(vm), classroomPlatform(state, lane, vm), word]
          .filter(value => value !== null && value !== undefined && value !== '').join(' ').toLowerCase() };
    });
    const shown = annotated.filter(row => classroomMatches(row.haystack, tokens));
    const getters = {
      lane: row => row.measured.number,
      machine: row => classroomMachineLabel(row.vm),
      os: row => classroomPlatform(state, row.lane, row.vm) || null,
      status: row => CLASSROOM_STATUS_RANK[row.word] ?? 7,
    };
    const get = getters[state.view.targetSort] || getters.lane;
    shown.sort((a, b) => {
      const x = get(a), y = get(b);
      if (x === y) return a.index - b.index;
      // Unknowns sink in BOTH directions: reversing a sort must not promote
      // "nobody knows" to the top of the list.
      if (x === null || x === undefined) return 1;
      if (y === null || y === undefined) return -1;
      return (typeof x === 'number' ? x - y : cmpText(x, y)) * direction;
    });
    return { shown };
  }

  /**
   * The empty option of a machine's OS select, which now CARRIES INFORMATION.
   *
   * Leaving it blank made forty-five rows read as forty-five open questions when
   * the server already knew the answer for every one of them. Saying which answer
   * it knows removes the decision instead of styling it away.
   *
   * Every string here is a fixed literal owned by this file, never server data,
   * which is what lets classroomPlatformOptions() interpolate it as trusted
   * markup — it carries entities and must not be escaped.
   */
  function classroomMachinePlaceholder(machine) {
    const platforms = [...machine.platforms];
    if (platforms.length === 1 && platforms[0]) return platforms[0] === 'windows' ? 'Windows &middot; from template' : 'Linux &middot; from template';
    return platforms.some(Boolean) ? 'Use each VM&rsquo;s own OS' : 'Choose OS&hellip;';
  }

  /**
   * Step 2: one row per MACHINE, grouped by the environment it belongs to.
   *
   * The environment heading is not decoration. Machine names are unique only
   * WITHIN an environment — two challenge specs can each ship a DC01 — so a flat
   * list of names prints the same word twice with no way to tell which is which,
   * and (before the rekeying in classroomPlatform) merged the two onto a single
   * checkbox.
   *
   * Infrastructure is listed, flagged and left unticked rather than hidden: an
   * instructor who genuinely wants Sandcat on the SIEM may have it, and a machine
   * that silently refused to appear would read as a deployment failure.
   */
  function renderClassroomMachines(state, rows) {
    const environments = new Map();
    // EVERY MACHINE KEY IS RENDERED IN EXACTLY ONE GROUP, and this map is what
    // guarantees it. The grouping axis (the lane's environment) and the keying
    // axis (the server's machine_key) are two different facts about a row, and
    // nothing makes them agree: an attached module VM keys under its module's
    // own challenge_key while its lane groups under the lane's environment, so
    // the same machine key can reach here from two groups. Both would then emit
    // id="classroomMachine-<key>", the bind loop below would resolve both to one
    // element, and the checkbox an instructor clicked would install on the other
    // group's VM while the second one silently did nothing. First group wins;
    // later entries join the machine where it already is.
    const placed = new Map();
    rows.forEach(({ lane, vm }) => {
      const environment = lane.environment || {};
      const envKey = classroomEnvKey(lane);
      if (!environments.has(envKey)) environments.set(envKey,
        { key: envKey, label: classroomEnvLabel(lane), labelled: !!environment.label, machines: new Map() });
      const key = classroomMachineKey(lane, vm);
      const machines = (placed.get(key) || environments.get(envKey)).machines;
      if (!machines.has(key)) {
        machines.set(key, { key, label: classroomMachineLabel(vm), role: classroomRoleLabel(vm),
          infra: classroomInfra(vm), platforms: new Set(), entries: [] });
        placed.set(key, environments.get(envKey));
      }
      const machine = machines.get(key);
      machine.platforms.add(['windows', 'linux'].includes(vm.platform) ? vm.platform : '');
      machine.entries.push({ lane, vm });
    });
    const groups = [...environments.values()].sort((a, b) => cmpText(a.label, b.label)).map(group => ({ ...group,
      // Infrastructure sinks inside its own environment: the machines an
      // instructor came here to tick should not sit below the one they must not.
      machines: [...group.machines.values()].sort((a, b) => (a.infra ? 1 : 0) - (b.infra ? 1 : 0) || cmpText(a.label, b.label)) }));
    const all = groups.flatMap(group => group.machines);
    // A lone environment whose label is only classroomEnvLabel()'s fallback has
    // nothing to add that the machine names do not, so its heading is dropped
    // rather than printed as "Other lanes" above the only group on screen.
    const headings = groups.length > 1 || (groups.length === 1 && groups[0].labelled);
    const machineAvailable = machine => machine.entries.filter(({ lane, vm }) => classroomVmAvailable(state, lane, vm));
    // Derived from the TARGETS, not from state.machines: unticking the last row
    // of a machine down in the target table has to uncheck the machine box too,
    // or the box would go on claiming a selection that no longer exists.
    const machinePicked = available => available.length > 0
      && available.every(({ lane, vm }) => state.targets.has(classroomVmKey(lane, vm)));
    // THE HEADER COUNTS THE BOXES THE ROWS BELOW IT ACTUALLY DRAW AS TICKED, out
    // of the same machinePicked() the rows use, and NOT state.machines.size.
    // The two are not the same number and are not meant to be: state.machines is
    // the record of what the instructor ticked up here, which
    // applyClassroomMachineSelection() still needs when the lane selection
    // changes, so it deliberately outlives the targets. Untick a machine's last
    // target row in step 3 and its key stays in the set while the row's own
    // derivation clears the box -- so the old header read "1 of 6 selected" over
    // six empty checkboxes, and an instructor chasing the phantom selection has
    // nothing on screen to untick. Only the DISPLAYED count changed here; the
    // set itself is still written by the change handler below.
    const pickedCount = all.filter(machine => machinePicked(machineAvailable(machine))).length;
    const machineRow = machine => {
      const available = machineAvailable(machine);
      const picked = machinePicked(available);
      const [roleLabel, roleModifier] = machine.role;
      return `<label class="cal-mpick"><input type="checkbox" id="${classroomId('Machine', machine.key)}"${picked ? ' checked' : ''}${state.submitting || !available.length ? ' disabled' : ''}><span class="cal-mname">${escHtml(machine.label)}</span></label>`
        + `<span class="cal-mrole">${roleLabel ? `<span class="cal-role cal-role-${roleModifier}">${escHtml(roleLabel)}</span>` : ''}`
        + `${machine.infra ? `<span class="badge badge-gray">not a target (${escHtml(roleLabel || 'infrastructure')})</span>` : ''}</span>`
        + `<span><span class="badge ${available.length ? 'badge-blue' : 'badge-gray'}">${available.length} of ${classroomPlural(machine.entries.length, 'lane')}</span></span>`
        + `<label class="cal-molabel"><span class="cal-sr-only">Operating system for ${escHtml(machine.label)}</span><select class="cal-select" id="${classroomId('MachineOs', machine.key)}"${state.submitting ? ' disabled' : ''}>${classroomPlatformOptions(state.machinePlatforms.get(machine.key) || '', classroomMachinePlaceholder(machine))}</select></label>`;
    };
    classroomSetHtml('classroomCalderaMachines', all.length ? `<section class="cal-panel">
      <div class="cal-panel-head"><span class="cal-step">2</span><h4 class="cal-panel-title">Machines</h4>
        <span class="cal-count${pickedCount ? ' is-ok' : ''}">${pickedCount} of ${all.length} selected</span></div>
      <div class="cal-panel-body">
        <p class="cal-hint">Ticking a machine selects it in every selected lane of that environment. An OS chosen here applies to all of them; a row in Targets can still override it. Machines marked <em>not a target</em> are the ones the class watches the attack from &mdash; nothing ticks them for you, but you can tick them.</p>
        <div class="cal-mgrid">
          <span class="cal-mgrid-h">Machine</span><span class="cal-mgrid-h">Role</span><span class="cal-mgrid-h">Available</span><span class="cal-mgrid-h">Operating system</span>
          ${groups.map(group => (headings ? `<div class="cal-mgroup">${escHtml(group.label)}</div>` : '') + group.machines.map(machineRow).join('')).join('')}
        </div></div></section>` : '');
    all.forEach(machine => {
      document.getElementById(classroomId('Machine', machine.key)).onchange = event => {
        if (state.submitting) return;
        if (event.target.checked) state.machines.add(machine.key); else state.machines.delete(machine.key);
        machine.entries.forEach(({ lane, vm }) => {
          const key = classroomVmKey(lane, vm);
          state.excludedTargets.delete(key);
          if (event.target.checked && classroomVmAvailable(state, lane, vm)) state.targets.add(key); else state.targets.delete(key);
        });
        renderClassroomCaldera(state);
      };
      const os = document.getElementById(classroomId('MachineOs', machine.key));
      // Assigned every render: on a cache hit classroomSetHtml() never touches
      // the DOM, and the test harness derives a parent's value from the first
      // <option> in the markup rather than from this select's own `selected`.
      os.value = state.machinePlatforms.get(machine.key) || '';
      os.onchange = () => {
        state.machinePlatforms.set(machine.key, os.value);
        machine.entries.forEach(({ lane, vm }) => state.platforms.delete(classroomVmKey(lane, vm)));
        renderClassroomCaldera(state);
      };
    });
  }

  /**
   * The Status cell: what the hypervisor says, plus the lane's own verdict.
   *
   * Status as a BADGE, not link-blue body text: "running" used to render in the
   * same colour as a hyperlink, in a column where nothing is a link. What the
   * install job is doing lives in the Agent column instead, because that is the
   * column an instructor watches and it updates without rebuilding this row.
   */
  function classroomTargetStatusHtml(state, lane, vm) {
    return (vm.power_state === 'running'
      ? '<span class="badge badge-success">running</span>'
      : `<span class="badge badge-muted">${escHtml(vm.power_state || 'unknown')}</span>`)
      + (classroomLaneAvailable(state, lane) ? '' : '<span class="badge badge-gray">lane unavailable</span>');
  }

  /**
   * The Agent cell's contents — a LEAF ISLAND, written after the table.
   *
   * "3m ago" changes on its own while the instructor is working. Writing it into
   * the row template would change that template every minute and force
   * classroomSetHtml() to rebuild the whole table, taking with it the caret in a
   * search box and any OS dropdown left open. Written separately, this one cell
   * re-renders and the row around it is never touched.
   *
   * IT MUST CARRY NO id= OF ITS OWN. The parent island rewrites this element on
   * any table change, and an id inside it would name an element the rebinding
   * loop had just dereferenced out from under itself.
   */
  function classroomAgentHtml(state, lane, vm, now) {
    const job = classroomJobFor(lane, vm);
    if (job && ['queued', 'running'].includes(job.status)) {
      return `<span class="badge ${classroomStatusBadge(job.status)}">${job.status === 'running' ? 'installing' : 'install queued'}</span>`;
    }
    const agent = classroomAgentOf(lane, vm);
    const ago = agent ? classroomAgo(agent.last_seen, now) : '';
    const seen = ago ? ` <span class="cal-ago">${escHtml(ago)}</span>` : '';
    if (agent && agent.fresh !== false) return `<span class="badge badge-success">checked in</span>${seen}`;
    if (agent) return `<span class="badge badge-warning">stale</span>${seen}`;
    if (job && job.status === 'failed') return '<span class="badge badge-danger">install failed</span>';
    return '<span class="badge badge-gray">none</span>';
  }

  /**
   * Step 3: the target table. Returns the keys of the rows actually drawn, so the
   * footer can say how much of the batch the filter is hiding.
   *
   * Row ids are built from lane_id and vm_id, NOT from an array index. An
   * index-based id names a different machine the moment a sort or a search
   * changes the rendered set, so the handler rebound at that index would install
   * onto somebody else's VM.
   */
  function renderClassroomTargets(state, rows) {
    // Preserved across the island rewrite, on both axes: the table scrolls
    // vertically past a dozen rows and horizontally below 44rem, and a poll that
    // reset either every five seconds would put the far end out of reach.
    const scroller = document.getElementById('classroomCalderaTargetScroll');
    const scrollTop = scroller?.scrollTop || 0;
    const scrollLeft = scroller?.scrollLeft || 0;
    const shown = classroomTargetView(state, rows).shown;
    const searching = classroomTokens(state.view.targetQuery).length > 0;
    const selectable = rows.filter(({ lane, vm }) => classroomVmAvailable(state, lane, vm));
    const now = Date.now();
    const order = state.view.targetDir === 'asc' ? 'ascending' : 'descending';
    const head = '<th class="cal-c-pick"><span class="cal-sr-only">Install</span></th>'
      + CLASSROOM_TARGET_COLUMNS.map(([sortKey, label, columnClass]) => {
        if (!sortKey) return `<th class="${columnClass}">${label}</th>`;
        const on = state.view.targetSort === sortKey;
        // aria-sort belongs on the header CELL; the button is only its activator.
        return `<th class="${columnClass ? `${columnClass} ` : ''}cal-sortable" aria-sort="${on ? order : 'none'}">`
          + `<button type="button" class="cal-sort${on ? ' is-on' : ''}" id="${classroomId('Sort', sortKey)}">${label}`
          + `<span class="cal-sort-ind" aria-hidden="true">${on ? (state.view.targetDir === 'asc' ? '&#9650;' : '&#9660;') : ''}</span></button></th>`;
      }).join('');
    const targetRow = row => {
      const { lane, vm } = row;
      const key = classroomVmKey(lane, vm);
      const available = classroomVmAvailable(state, lane, vm);
      const picked = available && state.targets.has(key);
      const platform = classroomPlatform(state, lane, vm);
      const inherited = ['windows', 'linux'].includes(vm.platform) ? vm.platform : '';
      // .is-known renders the select as plain text — still a real control, so an
      // override is one click away — because a column of identical bordered
      // dropdowns over an answer the server already gave reads as a column of
      // open questions.
      const known = !!inherited && platform === inherited;
      const label = classroomMachineLabel(vm);
      const [roleLabel, roleModifier] = classroomRoleLabel(vm);
      return `<tr class="cal-row${picked ? ' is-picked' : ''}${classroomBusy(lane, vm) ? ' is-busy' : ''}${available ? '' : ' is-off'}${known ? ' is-known' : ''}">`
        + `<td class="cal-c-pick"><label class="cal-pick"><input type="checkbox" id="${classroomId('Target', key)}"${picked ? ' checked' : ''}${state.submitting || !available ? ' disabled' : ''}><span class="cal-sr-only">Install on ${escHtml(row.measured.primary)} ${escHtml(label)}</span></label></td>`
        + `<td>${classroomLaneCellHtml(state, lane)}</td>`
        + `<td class="cal-c-machine"><span class="cal-cell-main">${escHtml(label)}</span><span class="cal-cell-sub">`
        + `${roleLabel ? `<span class="cal-role cal-role-${roleModifier}">${escHtml(roleLabel)}</span>` : ''}`
        + `<span class="cal-mono">VM ${escHtml(String(vm.vm_id))}</span></span></td>`
        + `<td class="cal-c-os"><label class="cal-molabel"><span class="cal-sr-only">Operating system for ${escHtml(label)} in ${escHtml(row.measured.primary)}</span>`
        + `<select class="cal-select" id="${classroomId('TargetOs', key)}"${state.submitting || !available ? ' disabled' : ''}>${classroomPlatformOptions(platform, 'Choose OS&hellip;')}</select></label></td>`
        + `<td class="cal-c-agent" id="${classroomId('TargetAgent', key)}"></td>`
        + `<td class="cal-c-status">${classroomTargetStatusHtml(state, lane, vm)}</td></tr>`;
    };
    const blockedNote = selectable.length < rows.length
      ? `<div class="cal-note cal-note-warn"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><div>${rows.length - selectable.length} of ${rows.length} machines cannot be installed on right now &mdash; powered off, an install already running, or a lane that is unavailable. They stay listed so the reason is visible.</div></div>`
      : '';
    classroomSetHtml('classroomCalderaTargets', !rows.length
      ? (state.lanes.size
        ? '<div class="cal-empty"><strong>Nothing to install on</strong><p>The selected lanes have no QEMU machines.</p></div>'
        : '<div class="cal-empty"><strong>No lanes selected</strong><p>Tick one or more lanes above and their machines appear here.</p></div>')
      : !shown.length
        ? '<div class="cal-empty"><strong>No machines match</strong><p>Nothing in the selected lanes matches the target search.</p></div>'
        : `<div class="cal-panel-body">${blockedNote}</div>`
          + '<div class="cal-tablewrap" id="classroomCalderaTargetScroll"><table class="data-table cal-table">'
          + `<thead><tr>${head}</tr></thead><tbody>${shown.map(targetRow).join('')}</tbody></table></div>`);
    const restored = document.getElementById('classroomCalderaTargetScroll');
    if (restored) {
      restored.scrollTop = scrollTop;
      restored.scrollLeft = scrollLeft;
    }
    shown.forEach(row => {
      const key = classroomVmKey(row.lane, row.vm);
      document.getElementById(classroomId('Target', key)).onchange = event => {
        if (state.submitting || !classroomVmAvailable(state, row.lane, row.vm)) return;
        if (event.target.checked) { state.targets.add(key); state.excludedTargets.delete(key); }
        else { state.targets.delete(key); state.excludedTargets.add(key); }
        renderClassroomCaldera(state);
      };
      const os = document.getElementById(classroomId('TargetOs', key));
      os.value = classroomPlatform(state, row.lane, row.vm);
      os.onchange = () => { state.platforms.set(key, os.value); renderClassroomCaldera(state); };
      // Written AFTER the row that contains it, and only into an element the
      // write above has just created. See classroomAgentHtml().
      classroomSetHtml(classroomId('TargetAgent', key), classroomAgentHtml(state, row.lane, row.vm, now));
    });
    CLASSROOM_TARGET_COLUMNS.forEach(([sortKey]) => {
      if (!sortKey) return;
      // Absent in both empty states, so this lookup is guarded where the row
      // bindings above are not.
      const button = document.getElementById(classroomId('Sort', sortKey));
      if (!button) return;
      button.onclick = () => {
        if (state.view.targetSort === sortKey) state.view.targetDir = state.view.targetDir === 'asc' ? 'desc' : 'asc';
        else { state.view.targetSort = sortKey; state.view.targetDir = 'asc'; }
        renderClassroomCaldera(state);
      };
    });
    // Shell-owned controls below: property writes only, so none of them can
    // disturb the island above or lose the caret in the search box beside them.
    // The count is over EVERY row of the selected lanes, not the filtered subset,
    // because the header has to keep saying how much work there is in total.
    document.getElementById('classroomCalderaTargetCount').textContent =
      `${classroomPlural(rows.length, 'row')} · ${selectable.length} selectable`;
    document.getElementById('classroomCalderaTargetsShown').disabled = state.submitting
      || !shown.some(row => classroomVmAvailable(state, row.lane, row.vm));
    document.getElementById('classroomCalderaTargetsMissing').disabled = state.submitting
      || !shown.some(row => classroomVmAvailable(state, row.lane, row.vm) && !classroomInfra(row.vm) && !classroomFresh(row.lane, row.vm));
    document.getElementById('classroomCalderaTargetsRetry').disabled = state.submitting
      || !shown.some(row => classroomVmAvailable(state, row.lane, row.vm) && !classroomFresh(row.lane, row.vm)
        && (row.word === 'install failed' || state.resultErrors.has(String(row.lane.lane_id))));
    document.getElementById('classroomCalderaTargetsClear').disabled = state.submitting || !state.targets.size;
    document.getElementById('classroomCalderaTargetShown').textContent = !rows.length ? ''
      : searching ? `Showing ${shown.length} of ${rows.length} machines` : classroomPlural(rows.length, 'machine');
    const shownKeys = new Set(shown.map(row => classroomVmKey(row.lane, row.vm)));
    const hidden = rows.filter(({ lane, vm }) => state.targets.has(classroomVmKey(lane, vm))
      && !shownKeys.has(classroomVmKey(lane, vm))).length;
    document.getElementById('classroomCalderaTargetHidden').textContent = hidden
      ? `${classroomPlural(hidden, 'selected machine')} hidden by the filter` : '';
    return shownKeys;
  }

  /**
   * The job card heading.
   *
   * Replaces "cle-cybr400-inperson-10880 · VM 660882", which named the lane by a
   * string every lane in the course shares a prefix with and the machine by a
   * Proxmox id nobody recognises. The machine label is resolved out of the lane's
   * own target list; a job whose VM has since left the lane keeps the id, because
   * a heading naming no machine at all would be worse than an unfriendly one.
   */
  function classroomJobLabel(lane, job) {
    const vm = (lane.targets || []).find(target => String(target.vm_id) === String(job.vm_id));
    const number = classroomLaneNumber(lane);
    return [classroomLanePrimary(lane), number === null ? '' : `#${number}`,
      vm ? classroomMachineLabel(vm) : `VM ${job.vm_id}`].filter(Boolean).join(' · ');
  }

  /**
   * What an instructor should DO about a failure, for the two failures this
   * installer actually produces. Anything else gets no hint rather than a guess.
   *
   * Both strings are fixed literals in this file; the server's own error text is
   * rendered separately and escaped.
   */
  function classroomJobHint(job) {
    const text = `${job.error || ''} ${job.message || ''}`;
    if (/timed out|did not report completion/i.test(text)) {
      return 'The install script may never have reported completion even though the agent started: a detached Windows agent holds the script’s output open, and the guest agent only reports an exit once it closes. Check the Agent column for this machine — if it says checked in, the install worked and there is nothing to do. If it says none, use Retry failed.';
    }
    if (/guest agent|qga/i.test(text)) {
      return 'The QEMU guest agent never answered, so the install script was never started on this VM. Confirm the guest agent is running inside the VM, then retry.';
    }
    return '';
  }

  /**
   * A job the server recorded as FAILED whose machine is nevertheless running an
   * agent Caldera has heard from recently.
   *
   * This is not a cosmetic softening of an error. It is the honest reading of the
   * four Windows installs an instructor watched "fail" while all four agents were
   * connected: the failure is in the exit reporting, not on the VM. The card keeps
   * the server's error text as secondary detail, because the reporting problem is
   * real and worth seeing — it just is not a broken machine.
   */
  function classroomJobReconciled(lane, job) {
    if (job.status !== 'failed') return false;
    const vm = (lane.targets || []).find(target => String(target.vm_id) === String(job.vm_id));
    return vm ? classroomFresh(lane, vm) : !!(job.agent && job.agent.paw);
  }

  function renderClassroomProgress(state, lanes) {
    const jobs = lanes.flatMap(lane => classroomJobs(lane).map(job => ({ lane, job, reconciled: classroomJobReconciled(lane, job) })));
    // Failures first. Every card below is read-only, so reordering cannot steal a
    // caret or an open dropdown the way it would in the target table above — and
    // the job an instructor opened this window for is the one that broke. A
    // reconciled failure sorts with the completed work it actually is.
    const rank = { failed: 0, running: 1, queued: 2, completed: 3 };
    const ordered = jobs.slice().sort((a, b) =>
      (a.reconciled ? 3 : rank[a.job.status] ?? 4) - (b.reconciled ? 3 : rank[b.job.status] ?? 4));
    // "3 queued" MUST stay one contiguous text node — a test matches /3 queued/
    // against this island's HTML, and <span>3</span> queued would fail it. That
    // is also why these are chips rather than stat tiles with a separate value
    // and label. A zero is dimmed; a failure is the one that shouts. The counts
    // are the SERVER's statuses, unreconciled, so a chip can never contradict the
    // status badge on the card it is counting.
    const tone = { queued: 'is-live', running: 'is-live', completed: 'is-good', failed: 'is-bad' };
    const metrics = ['queued', 'running', 'completed', 'failed'].map(status => {
      const count = jobs.filter(({ job }) => job.status === status).length;
      return `<span class="cal-metric ${count ? tone[status] : 'is-zero'}">${count} ${status}</span>`;
    }).join('');
    const failures = jobs.filter(({ job }) => job.status === 'failed');
    const reconciled = failures.filter(entry => entry.reconciled).length;
    const broken = failures.length - reconciled;
    const recoveredLine = reconciled
      ? ` ${classroomPlural(reconciled, 'install')} recorded a failure but the agent has since checked in — those need nothing.`
      : '';
    const failNote = !failures.length ? ''
      : broken
        ? `<div class="cal-note cal-note-danger"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><div><p class="cal-note-head">${classroomPlural(broken, 'install')} failed</p><p>The lane, the machine and the reason Caldera reported are in the list below.${recoveredLine}</p></div></div>`
        : `<div class="cal-note cal-note-ok"><span class="cal-note-icon" aria-hidden="true">&#10003;</span><div><p>${classroomPlural(reconciled, 'install')} reported a failure, and every one of those agents is checked in. Nothing needs reinstalling.</p></div></div>`;
    const errors = state.results.filter(result => result.error).map(result => {
      const lane = lanes.find(entry => entry.lane_id === result.lane_id);
      const label = lane ? classroomJobLabel(lane, result) : `${result.lane_id} · VM ${result.vm_id}`;
      return `<div class="cal-note cal-note-danger"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><div><strong>${escHtml(label)}</strong><p>${escHtml(result.error)}</p></div></div>`;
    }).join('');
    // NO <img> AND NO INLINE <svg> ANYWHERE IN THIS ISLAND. A test forbids both
    // outright, because that assertion is what proves injected markup arriving in
    // a warning was escaped rather than rendered. Every glyph here is an entity.
    classroomSetHtml('classroomCalderaResults', !jobs.length && !state.results.length ? ''
      : `<h4 class="cal-results-title">Installation progress</h4><div class="cal-metrics">${metrics}</div>${failNote}${errors}`
        + ordered.map(({ lane, job, reconciled: ok }) => {
          const hint = job.status === 'failed' ? classroomJobHint(job) : '';
          return `<div class="cal-job is-${ok || job.status === 'completed' ? 'good' : job.status === 'failed' ? 'bad' : 'live'}">
        <div class="cal-job-head"><strong class="cal-job-name">${escHtml(classroomJobLabel(lane, job))}</strong>
          ${ok ? '<span class="badge badge-success">agent checked in</span>' : `<span class="badge ${classroomStatusBadge(job.status)}">${escHtml(job.status || 'unknown')}</span>`}</div>
        ${job.error || job.message ? `<p class="cal-job-msg">${escHtml(job.error || job.message)}</p>` : ''}
        ${hint ? `<p class="cal-job-hint">${escHtml(hint)}</p>` : ''}
        ${(Array.isArray(job.warnings) ? job.warnings : []).filter(value => typeof value === 'string').slice(0, 5).map(warning => `<p class="cal-note cal-note-warn cal-job-note"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><span>${escHtml(warning.slice(0, 1000))}</span></p>`).join('')}
        ${job.agent?.paw ? `<p class="cal-job-ok"><span class="cal-note-icon" aria-hidden="true">&#10003;</span> Caldera confirmed check-in: ${escHtml(job.agent.host || job.agent.paw)}.</p>`
    : job.status === 'completed' ? '<p class="cal-job-msg">No fresh agent check-in has been confirmed yet.</p>' : ''}
      </div>`;
        }).join(''));
  }

  function renderClassroomInstall(state, lanes) {
    const rows = classroomTargetRows(state);
    renderClassroomMachines(state, rows);
    const shownKeys = renderClassroomTargets(state, rows);
    const targets = classroomSelectedTargets(state);
    const unknown = targets.filter(target => !['windows', 'linux'].includes(target.platform)).length;
    const laneTotal = new Set(targets.map(target => target.lane_id)).size;
    // PLAIN TEXT, FOREVER. test/caldera-classroom-ui.test.js reads this element
    // through .textContent, and its fake DOM does not derive textContent from
    // innerHTML — so markup written here would be invisible to the assertion and
    // to a screen reader's status announcement alike. The visual weight this
    // gating count needs comes from the class set on the element and from the
    // badge island beside it, never from markup inside it.
    const summary = document.getElementById('classroomCalderaSummary');
    summary.textContent = `${classroomPlural(targets.length, 'VM')} selected in ${classroomPlural(laneTotal, 'lane')}.`
      + (unknown ? ` Choose Windows or Linux for ${unknown} of them.` : '');
    summary.className = `cal-bar-text${unknown ? ' is-blocked' : targets.length ? ' is-ready' : ''}`;
    // The target search never deselects, so the batch can hold rows the
    // instructor cannot currently see. Say so beside the count they are about to
    // install, rather than letting Install queue work off-screen.
    const hiddenTargets = targets.filter(target => !shownKeys.has(`${target.lane_id}:${target.vm_id}`));
    document.getElementById('classroomCalderaHiddenNote').textContent = hiddenTargets.length
      ? `${classroomPlural(hiddenTargets.length, 'selected machine')} in ${classroomPlural(new Set(hiddenTargets.map(target => target.lane_id)).size, 'lane')} are hidden by the target search. Clear it to review them before installing.`
      : '';
    classroomSetHtml('classroomCalderaSummaryBadges',
      `<span class="badge ${targets.length ? 'badge-blue' : 'badge-gray'}">${classroomPlural(targets.length, 'VM')}</span>`
      + `<span class="badge badge-gray">${classroomPlural(laneTotal, 'lane')}</span>`
      + (unknown ? `<span class="badge badge-warning cal-loud">${unknown} need an OS</span>` : '')
      + (state.submitting ? '<span class="badge badge-info">queuing&hellip;</span>' : ''));
    const button = document.getElementById('classroomCalderaSubmit');
    button.disabled = state.submitting || !state.fresh || !targets.length || !!unknown || !!state.payload?.configuration_error
      || !!state.payload?.power_error || !laneCalderaHttpUrl(state.payload?.server_url);
    button.textContent = state.submitting ? 'Queuing installations…' : targets.length ? `Install ${classroomPlural(targets.length, 'agent')}` : 'Install selected agents';
    renderClassroomProgress(state, lanes);
  }

  // ---- attack mode: the adversary profile card ----------------------------

  /**
   * The ordered step list of a profile, and how many steps that is.
   *
   * THE STEP COUNT NEVER COMES FROM THE TACTIC TOTALS. summary.tactics skips
   * every ability whose tactic is null — a custom or plugin-authored row
   * commonly has none — so those counts can sum to less than the profile
   * actually runs, and an instructor adding them up would be told a thirteen
   * step operation was a nine step one. ability_ids IS the ordering;
   * ability_count is that same length before ids too long to serve as lookup
   * keys were filtered out of it, and stands in for a server that sends no
   * ordering at all.
   */
  const classroomAbilityIds = adversary => (Array.isArray(adversary.ability_ids) ? adversary.ability_ids : [])
    .filter(id => typeof id === 'string' && id);
  const classroomSteps = adversary => classroomAbilityIds(adversary).length || Number(adversary.ability_count) || 0;

  // The platforms the server counts, in the order it counts them. summary.platforms
  // is a map of COUNTS ({windows: 9, linux: 4, darwin: 0}), never a list, so the
  // order a sentence reads them in has to be decided here.
  const CLASSROOM_SUMMARY_PLATFORMS = ['windows', 'linux', 'darwin'];

  /**
   * A platform's display name, written HERE rather than taken off the wire.
   *
   * One map serves the summary sentence, the fit verdict and the platform column
   * of the ability list, so those three can never call the same machine by two
   * different names on one screen. A platform nobody anticipated is still
   * printed — the raw word tells an instructor more than an omission does — and
   * it is escaped at every call site, because it came from the stockpile.
   */
  const CLASSROOM_PLATFORM_NAME = { windows: 'Windows', linux: 'Linux', darwin: 'macOS' };
  const classroomPlatformName = value => {
    const platform = String(value === null || value === undefined ? '' : value).trim();
    return CLASSROOM_PLATFORM_NAME[platform.toLowerCase()] || platform;
  };

  /** "A", "A and B", "A, B and C" — never a list that ends in a bare comma. */
  const classroomJoinWords = (list, conjunction) => list.length < 2 ? list[0] || ''
    : `${list.slice(0, -1).join(', ')} ${conjunction || 'and'} ${list[list.length - 1]}`;

  /** 'lateral-movement' → 'Lateral Movement'. Caldera's tactic ids are kebab-cased. */
  const classroomTacticLabel = tactic => String(tactic === null || tactic === undefined ? '' : tactic)
    .trim().split(/[\s_-]+/).filter(Boolean)
    .map(word => word.charAt(0).toUpperCase() + word.slice(1)).join(' ');

  /**
   * Up to three executor names this profile actually uses on one platform.
   *
   * They can only come from the ability catalog, one ability at a time:
   * summary.platforms carries counts and nothing else, so "psh, cmd" is not in
   * it and cannot be derived from it. The server ships that catalog for the
   * SELECTED profile alone, which is why this is only ever called for the
   * profile the instructor has chosen.
   *
   * First-seen order over the profile's own ordering, so the names read in the
   * order the operation reaches them rather than alphabetically.
   */
  function classroomExecutorNames(ids, abilities, platform) {
    const names = [];
    for (const id of ids) {
      const entry = abilities[id];
      if (!entry || !Array.isArray(entry.executors)) continue;
      for (const executor of entry.executors) {
        if (!executor || String(executor.platform || '').trim().toLowerCase() !== platform) continue;
        const name = String(executor.name || '').trim();
        if (name && !names.includes(name)) names.push(name);
        if (names.length === 3) return names;
      }
    }
    return names;
  }

  /**
   * One sentence describing what a profile does, assembled from the server's own
   * rollup: "13 steps across 4 tactics: Discovery (5), … ; runs on Windows
   * (psh, cmd) and Linux (sh)."
   *
   * Every degraded shape the endpoint can send has a sentence of its own rather
   * than a zero. `summary` is null whenever the ability catalog could not be
   * read at all, and answering that with "0 tactics" would be a confident lie
   * about the profile in place of an honest admission about the server. The
   * tactic counts can also sum to less than the step count (see classroomSteps),
   * which is why the two numbers in this sentence come from different places.
   */
  function classroomProfileSummary(adversary, abilities) {
    const ids = classroomAbilityIds(adversary);
    const steps = classroomSteps(adversary);
    const stepWord = `${steps} step${steps === 1 ? '' : 's'}`;
    const summary = adversary.summary;
    if (!summary || typeof summary !== 'object') return `${stepWord}. This server does not report tactics or platforms for profiles.`;
    const tactics = (Array.isArray(summary.tactics) ? summary.tactics : [])
      .map(entry => ({ label: classroomTacticLabel(entry && entry.tactic), count: Number(entry && entry.count) || 0 }))
      .filter(entry => entry.label)
      // Biggest first, because "what does this profile mostly do" is the question
      // a one-line summary is read to answer; ties break on the name so the order
      // cannot shuffle between two polls that measured the very same thing.
      .sort((a, b) => b.count - a.count || cmpText(a.label, b.label));
    const listed = tactics.slice(0, 4).map(entry => `${entry.label} (${entry.count})`).join(', ');
    const more = tactics.length - 4;
    const head = tactics.length
      ? `${stepWord} across ${tactics.length} tactic${tactics.length === 1 ? '' : 's'}: ${listed}${more > 0 ? ` and ${more} more` : ''}`
      : stepWord;
    const counts = summary.platforms && typeof summary.platforms === 'object' ? summary.platforms : {};
    const platforms = CLASSROOM_SUMMARY_PLATFORMS.filter(platform => (Number(counts[platform]) || 0) > 0)
      .map(platform => {
        const names = classroomExecutorNames(ids, abilities, platform);
        return `${classroomPlatformName(platform)}${names.length ? ` (${names.join(', ')})` : ''}`;
      });
    const unknown = Number(summary.unknown_abilities) || 0;
    return `${head}; ${platforms.length ? `runs on ${classroomJoinWords(platforms)}` : 'no platform information'}.`
      + (unknown > 0 ? ` ${classroomAbilities(unknown)} could not be described: not in the ability catalog.` : '');
  }

  /**
   * Which agent platforms are actually on the ground in the selected lanes.
   *
   * `other` is the bucket platformSentence() prints as "of another or unrecorded
   * type", and it is excluded here deliberately: it counts agents this dialog
   * could not identify, and an unidentified agent is not evidence that a step
   * will run.
   */
  const classroomAgentPlatforms = mix => new Set(Object.keys(mix)
    .filter(platform => platform && platform !== 'other' && (Number(mix[platform]) || 0) > 0));

  /**
   * The distinct platforms a set of abilities needs, optionally minus the ones
   * already checked in, named and ordered for a sentence.
   */
  function classroomPlatformUnion(ids, abilities, exclude) {
    const seen = [];
    ids.forEach(id => ((abilities[id] && abilities[id].platforms) || []).forEach(value => {
      const platform = String(value).trim().toLowerCase();
      if (!platform || (exclude && exclude.has(platform)) || seen.includes(platform)) return;
      seen.push(platform);
    }));
    const rank = platform => (CLASSROOM_SUMMARY_PLATFORMS.indexOf(platform) + 1) || 99;
    return seen.sort((a, b) => rank(a) - rank(b) || cmpText(a, b)).map(classroomPlatformName);
  }

  const CLASSROOM_FIT_NOTE = { ok: 'cal-note-ok', warn: 'cal-note-warn', danger: 'cal-note-danger', info: 'cal-note-info' };
  const CLASSROOM_FIT_ICON = { ok: '&#10003;', warn: '&#9888;', danger: '&#9888;', info: '&#9432;' };

  /**
   * Will this profile actually run on the agents in the selected lanes?
   *
   * This replaces a verdict that was deliberately HALF an answer, because the
   * adversary projection used to carry {adversary_id, name, description,
   * ability_count} and nothing else — no executors, no platforms — so the only
   * honest thing it could do was state the agent mix and send the instructor off
   * to the console. The endpoint now ships the ability catalog for the SELECTED
   * profile, so the question is answerable, and answering it is the difference
   * between an operation that does thirteen things and one that silently does
   * nine.
   *
   * THE VERDICT IS NEVER EXTENDED TO ABILITIES THE CATALOG DID NOT DESCRIBE. An
   * id the catalog does not hold, and a row that lists no platforms at all, are
   * counted separately and named in the note rather than being quietly assumed
   * to work — an assumed-green step is exactly the kind of claim this dialog has
   * just spent a release removing.
   */
  function classroomProfileFit(adversary, abilities, mix, laneCount) {
    const nothing = new Set();
    if (!laneCount) return { tone: 'info', skipped: nothing,
      text: 'Select lanes below to see which agent platforms are ready.' };
    const ids = classroomAbilityIds(adversary);
    const steps = classroomSteps(adversary);
    // Unique ids: an ordering is allowed to run the same ability twice, and a
    // profile is not half unrunnable because one of its steps repeats. The
    // STEP counts below go back to the ordering itself, where a repeat is two
    // things that will happen rather than one thing that exists.
    const judged = [...new Set(ids)].filter(id => abilities[id]
      && Array.isArray(abilities[id].platforms) && abilities[id].platforms.length);
    if (!adversary.summary || !judged.length) return { tone: 'info', skipped: nothing,
      text: `Those lanes have ${platformSentence(mix)} checked in. This server did not describe what this profile’s steps run on, so confirm in the Caldera console that its abilities have executors for those platforms.` };
    const ready = classroomAgentPlatforms(mix);
    const skipped = new Set(judged.filter(id => !abilities[id].platforms
      .some(platform => ready.has(String(platform).trim().toLowerCase()))));
    const unchecked = new Set(ids).size - judged.length;
    const note = unchecked ? ` ${classroomAbilities(unchecked)} could not be checked: the catalog does not say what they run on.` : '';
    if (!skipped.size) return { tone: 'ok', skipped,
      text: `Every step has an executor for the agents checked in: ${platformSentence(mix)}.${note}` };
    if (skipped.size === judged.length) {
      const targets = classroomJoinWords(classroomPlatformUnion(judged, abilities, null));
      return { tone: 'danger', skipped,
        text: `No step in this profile can run on the agents checked in: ${platformSentence(mix)}.`
          + ` It targets ${targets || 'platforms this server did not name'}.${note}` };
    }
    const missing = classroomJoinWords(classroomPlatformUnion([...skipped], abilities, ready), 'or');
    const names = [...skipped].slice(0, 5).map(id => abilities[id].name || id);
    const rest = skipped.size - names.length;
    return { tone: 'warn', skipped,
      text: `${ids.filter(id => skipped.has(id)).length} of ${steps} steps will be skipped because no ${missing || 'matching'} agent is checked in: `
        + `${names.join(', ')}${rest > 0 ? ` and ${rest} more` : ''}.${note}` };
  }

  /**
   * The profile's steps, in the order Caldera will run them.
   *
   * A COUNT WAS NEVER ENOUGH. "13 abilities" told an instructor nothing about
   * what a class was about to watch happen, so choosing a profile meant leaving
   * this dialog and reading the same list in the console instead.
   *
   * Platform names are TEXT, never glyphs. The results island forbids <img> and
   * inline <svg> outright, because that assertion is what proves injected markup
   * arrived escaped rather than rendered, and the same habit is worth keeping in
   * a list built entirely out of strings a plugin author controls. Every field
   * below is escaped for that reason.
   */
  function classroomAbilityList(abilityIds, abilities, skipped, unreadable) {
    if (!abilityIds.length) return '';
    return '<ol class="cal-abilities">' + abilityIds.map((id, index) => {
      const step = `<span class="cal-ab-step">${index + 1}</span>`;
      const entry = abilities[id];
      // An id in the ordering the catalog cannot answer for. Saying so outright
      // is the point: printing the bare identifier as if it were a name would
      // read as a step nobody bothered to describe rather than as one this
      // server could not find.
      //
      // WHICH OF THE TWO IT IS DEPENDS ON abilities_error, and conflating them
      // is a confident false claim. When the catalog read FAILED the server
      // sends `abilities: {}` — every id in the ordering misses, and the list
      // then asserted that all thirteen named abilities had been deleted from
      // the stockpile when the stockpile simply had not answered. That reading
      // is stable, not transient: the detail refetch has already landed, so
      // nothing re-polls to correct it.
      if (!entry) return `<li class="cal-ab is-unknown">${step}<span class="cal-ab-name">${unreadable ? 'The ability catalog could not be read' : 'Not in the ability catalog'}</span>`
        + `<span class="cal-ab-sub"><span class="cal-ab-tech">${escHtml(id)}</span></span></li>`;
      const platforms = (Array.isArray(entry.platforms) ? entry.platforms : []).map(classroomPlatformName);
      const off = !!skipped && skipped.has(id);
      return `<li class="cal-ab${off ? ' is-skipped' : ''}">${step}`
        + `<span class="cal-ab-name">${escHtml(entry.name || id)}</span>`
        + `<span class="cal-plats">${platforms.map(escHtml).join(' &middot; ')}</span>`
        + '<span class="cal-ab-sub">'
        + (off ? '<span class="badge badge-warning">skipped</span>' : '')
        + (entry.tactic ? `<span class="cal-ab-tactic">${escHtml(classroomTacticLabel(entry.tactic))}</span>` : '')
        + (entry.technique_id ? `<span class="cal-ab-tech">${escHtml(entry.technique_id)}</span>` : '')
        + (entry.technique_name ? `<span class="cal-ab-techname">${escHtml(entry.technique_name)}</span>` : '')
        + '</span>'
        + (entry.description ? `<details class="cal-ab-desc"><summary>What this step does</summary><p>${escHtml(entry.description)}</p></details>` : '')
        + '</li>';
    }).join('') + '</ol>';
  }

  /**
   * A lane, on two lines, inside a table cell: who it is, then where.
   *
   * Shared by the target table and the lane operations table so one lane cannot
   * read as "Student one · #10880 · GOAD" in one and as
   * "cle-cybr400-inperson-10880" in the other — which is what the operations
   * table showed until this release: a name every lane in the course shares a
   * prefix with, ellipsised to the point of being unreadable.
   */
  function classroomLaneCellHtml(state, lane) {
    const measured = classroomLaneStat(state, lane);
    return `<span class="cal-cell-main">${escHtml(measured.primary)}</span><span class="cal-cell-sub">`
      + (measured.number === null ? '' : `<span>#${escHtml(String(measured.number))}</span>`)
      + `<span>${escHtml(measured.env)}</span></span>`;
  }

  function renderClassroomAttack(state, lanes) {
    const locked = state.submitting || !!state.pending;
    const adversaries = Array.isArray(state.payload?.adversaries) ? state.payload.adversaries : [];
    const needle = (state.adversarySearch || '').trim().toLowerCase();
    const inScope = adversary => state.adversaryScope === 'all' || !classroomSnapshot(adversary);
    const hit = adversary => !needle || `${adversary.name || ''} ${adversary.description || ''}`.toLowerCase().includes(needle);
    // The CHOSEN profile is emitted whatever the filter says. Without this, a
    // filter typed after choosing would leave select.value pointing at an option
    // the browser no longer has: the selection silently reads as '' in the
    // browser while state.adversary still arms the submit button.
    const shown = adversaries.filter(adversary => (inScope(adversary) && hit(adversary)) || adversary.adversary_id === state.adversary);
    // Counted separately from shown.length, which the force-emitted selection
    // inflates: a filter that matches nothing must still SAY so, even while the
    // one row still in the list is the profile already chosen.
    const matched = adversaries.filter(adversary => inScope(adversary) && hit(adversary)).length;
    // Snapshots the scope pill is holding back — not ones the text filter missed,
    // which the "Showing N of M" count already covers, and not the selected one,
    // which is force-emitted above however the filter is set.
    const hidden = adversaries.filter(adversary => !inScope(adversary) && !shown.includes(adversary)).length;
    const option = adversary => {
      // Number(), not the raw field: a count coerced to a number cannot carry
      // markup, so it needs no escaping and the plural below can read it.
      const count = Number(adversary.ability_count) || 0;
      return `<option value="${escAttr(adversary.adversary_id)}"${adversary.adversary_id === state.adversary ? ' selected' : ''}>`
        + `${escHtml(classroomAdversaryName(adversary))} &mdash; ${count} abilit${count === 1 ? 'y' : 'ies'}</option>`;
    };
    const built = shown.filter(adversary => !classroomSnapshot(adversary)).map(option).join('');
    const snapshots = shown.filter(classroomSnapshot).map(option).join('');
    const picked = adversaries.find(adversary => adversary.adversary_id === state.adversary);
    const steps = picked ? classroomSteps(picked) : 0;
    // The ability catalog the server sent for the SELECTED profile, and for no
    // other. A poll made while nothing is chosen carries `abilities: {}`, which
    // is not an error and must not be rendered as one.
    const catalog = state.payload && state.payload.abilities && typeof state.payload.abilities === 'object'
      ? state.payload.abilities : {};
    // The server's own admission that the stockpile did not answer. It is the
    // only thing that separates "this ability is gone" from "we could not ask",
    // and the ability list says different words for each.
    const catalogUnreadable = !!(state.payload && String(state.payload.abilities_error || '').trim());
    const live = lanes.filter(lane => state.lanes.has(lane.lane_id) && classroomLaneAvailable(state, lane));
    // Counted by the agent's OWN platform string rather than folded into three
    // buckets on the way in. platformSentence() still reads windows / linux /
    // other and is unchanged, but the fit verdict has to know exactly which
    // platforms are on the ground: a darwin agent must not be indistinguishable
    // from an agent whose platform Caldera never recorded.
    const mix = { windows: 0, linux: 0, other: 0 };
    live.forEach(lane => (lane.agents || []).forEach(agent => {
      const platform = String(agent.platform || '').trim().toLowerCase();
      if (platform) mix[platform] = (mix[platform] || 0) + 1;
      if (!['windows', 'linux'].includes(platform)) mix.other++;
    }));
    const fit = picked ? classroomProfileFit(picked, catalog, mix, live.length) : null;
    const abilityIds = picked ? classroomAbilityIds(picked) : [];
    // CHANGING THE LANE SELECTION REWRITES THIS CARD, and that closes any
    // <details> the instructor had opened on an ability. It is the right trade
    // rather than an oversight: the verdict below is a statement about the
    // agents in the SELECTED lanes, so a card left standing while the selection
    // moved underneath it would be a green "every step has an executor" about a
    // set of lanes nobody is launching on.
    const detail = picked ? `<div class="cal-advcard">
      <div class="cal-advcard-head"><strong class="cal-advcard-name">${escHtml(classroomAdversaryName(picked))}</strong>
        <span class="badge badge-blue">${classroomAbilities(steps)}</span>
        ${classroomSnapshot(picked) ? '<span class="badge badge-gray">past launch</span>' : ''}</div>
      ${picked.description ? `<p class="cal-advcard-desc">${escHtml(picked.description)}</p>`
    : '<p class="cal-advcard-desc is-muted">No description was set for this profile in the Caldera console.</p>'}
      <p class="cal-advcard-summary">${escHtml(classroomProfileSummary(picked, catalog))}</p>
      ${steps > 40 ? `<div class="cal-note cal-note-warn"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><span>${classroomAbilities(steps)} is a long profile. Expect a long run and a lot of SIEM noise in every selected lane.</span></div>` : ''}
      <div class="cal-note ${CLASSROOM_FIT_NOTE[fit.tone]}"><span class="cal-note-icon" aria-hidden="true">${CLASSROOM_FIT_ICON[fit.tone]}</span><span>${escHtml(fit.text)}</span></div>
      ${classroomAbilityList(abilityIds, catalog, fit.skipped, catalogUnreadable)}</div>` : '';
    // STILL A REAL <select>, WITH size="8". That single attribute is the whole
    // fix for "the open dropdown covers the lane selector": a sized select is an
    // inline listbox and can never overlay anything. Keeping it a <select> keeps
    // .value / .onchange / .disabled exactly as they were — which matters,
    // because a card list would need querySelectorAll + getAttribute + event
    // delegation, and the test harness has none of the three (that is why the
    // card picker in adversaryHtml() above is a silent no-op under test).
    //
    // The <select> is emitted in EVERY state, including the empty and no-match
    // ones, so the unguarded getElementById below can never hit null.
    classroomSetHtml('classroomCalderaAdversaries',
      `<select class="cal-advlist" id="classroomCalderaAdversary" size="8" aria-label="Adversary profile"${locked ? ' disabled' : ''}>`
      + '<option value="">Select an adversary&hellip;</option>'
      + (built ? `<optgroup label="Profiles">${built}</optgroup>` : '')
      + (snapshots ? `<optgroup label="Snapshots of past launches">${snapshots}</optgroup>` : '')
      + '</select>'
      + (adversaries.length
        ? `<p class="cal-hint">Showing ${shown.length} of ${adversaries.length}.${hidden ? ` ${hidden} snapshot${hidden === 1 ? '' : 's'} of past launches hidden.` : ''}</p>`
          + (matched ? '' : '<div class="cal-empty"><strong>No profile matches that filter</strong><p>Clear the filter, or turn on Past launches to include snapshots of previous exercises.</p></div>')
          + detail
        : '<div class="cal-empty"><strong>No adversary profiles</strong><p>Build one in the Caldera console &mdash; add abilities in the order you want them, with executors that match your agents &mdash; then press Refresh status.</p></div>'));
    const select = document.getElementById('classroomCalderaAdversary');
    // Assigned imperatively rather than trusted to the `selected` attribute: on a
    // cache hit classroomSetHtml() does not touch the DOM at all, and the fake
    // DOM creates the option-less child with value ''.
    select.value = state.adversary;
    select.onchange = () => {
      if (locked) return;
      state.adversary = select.value;
      // Redraw from what is already in hand — the step count and the summary
      // ride on every profile's projection — then go back for the chosen
      // profile's ability detail, which the server sends only when it is named
      // in the request.
      renderClassroomCaldera(state);
      if (classroomProfileNeedsDetail(state)) classroomRefreshSoon(state);
    };
    // Shell controls — created once at open, so these are property writes, never
    // markup, and they cannot disturb the island above.
    const advCount = document.getElementById('classroomCalderaAdvCount');
    advCount.textContent = state.adversary ? 'Selected' : `${adversaries.length} available`;
    advCount.className = `cal-count${state.adversary ? ' is-ok' : ''}`;
    const scopeBuilt = document.getElementById('classroomCalderaAdvScopeBuilt');
    const scopeAll = document.getElementById('classroomCalderaAdvScopeAll');
    scopeBuilt.textContent = `Profiles (${adversaries.filter(adversary => !classroomSnapshot(adversary)).length})`;
    scopeAll.textContent = `Past launches (${adversaries.filter(classroomSnapshot).length})`;
    scopeBuilt.className = `filter-pill${state.adversaryScope === 'built' ? ' active' : ''}`;
    scopeAll.className = `filter-pill${state.adversaryScope === 'all' ? ' active' : ''}`;
    scopeBuilt.disabled = locked;
    scopeAll.disabled = locked;
    document.getElementById('classroomCalderaAdversarySearch').disabled = locked;
    document.getElementById('classroomCalderaAdversaryClear').disabled = locked;
    const selected = lanes.filter(lane => state.lanes.has(lane.lane_id) && classroomLaneAvailable(state, lane));
    const agentCount = selected.reduce((total, lane) => total + (lane.agents || []).length, 0);
    // Plain text for the same reason as the install summary: this element is read
    // through .textContent.
    const summary = document.getElementById('classroomCalderaSummary');
    summary.textContent = state.pending
      ? 'A launch request is awaiting confirmation. Retry sends the same request, so it cannot create a second batch.'
      : `${classroomPlural(selected.length, 'lane')} selected. Each lane gets its own operation and agent group; agent check-ins set the exact start time.`;
    summary.className = `cal-bar-text${state.pending ? ' is-blocked' : selected.length && state.adversary ? ' is-ready' : ''}`;
    classroomSetHtml('classroomCalderaSummaryBadges',
      `<span class="badge ${selected.length ? 'badge-blue' : 'badge-gray'}">${classroomPlural(selected.length, 'lane')}</span>`
      + `<span class="badge badge-gray">${classroomPlural(agentCount, 'agent')} ready</span>`
      + (!state.adversary ? '<span class="badge badge-warning">no profile chosen</span>' : '')
      + (state.pending ? '<span class="badge badge-warning cal-loud">awaiting confirmation</span>' : ''));
    const button = document.getElementById('classroomCalderaSubmit');
    button.disabled = state.submitting || !state.fresh || !!state.payload?.configuration_error || !!state.payload?.agents_error
      || (!state.pending && (!selected.length || !adversaries.some(adversary => adversary.adversary_id === state.adversary)));
    button.textContent = state.submitting ? 'Starting operations…' : state.pending ? 'Retry launch request' : selected.length ? `Launch on ${classroomPlural(selected.length, 'lane')}` : 'Launch on selected lanes';
    const batches = new Map();
    lanes.forEach(lane => (lane.operations || []).forEach(operation => {
      const key = operation.batch_id || operation.operation_id;
      if (!batches.has(key)) batches.set(key, []);
      batches.get(key).push({ lane, operation });
    }));
    const entries = [...batches];
    const errors = state.results.filter(result => result.error).map(result =>
      `<div class="cal-note cal-note-danger"><span class="cal-note-icon" aria-hidden="true">&#9888;</span><div><strong>${escHtml(lanes.find(lane => lane.lane_id === result.lane_id)?.name || result.lane_id)}</strong><p>${escHtml(result.error)}</p></div></div>`).join('');
    // One badge per distinct status, so a twenty-lane batch reads as
    // "18 running · 2 failed" at the head instead of as twenty bullets.
    const roll = operations => [...new Set(operations.map(({ operation }) => operation.status || 'unknown'))]
      .map(status => `<span class="badge ${classroomStatusBadge(status)}">${operations.filter(({ operation }) => (operation.status || 'unknown') === status).length} ${escHtml(status)}</span>`).join('');
    // Batch order is NOT changed: the index is the classroomStop{i} seam, and
    // that button is focusable — reordering it under a poll would move the
    // control out from under the pointer. when() stays absolute for the same
    // family of reasons: a relative timestamp would rewrite this island's HTML
    // on every 5s tick and defeat classroomSetHtml()'s identity cache.
    classroomSetHtml('classroomCalderaResults', '<h4 class="cal-results-title">Lane operations</h4>' + errors
      + (entries.length ? entries.map(([batchId, operations], i) => {
        const active = operations.some(({ operation }) => !['finished', 'completed', 'out_of_time', 'cleanup', 'failed', 'stopped', 'aborted'].includes(operation.status));
        return `<div class="cal-batch">
          <div class="cal-batch-head"><strong class="cal-batch-name">${escHtml(operations[0].operation.adversary_name || operations[0].operation.name || 'Caldera exercise')}</strong>
            ${roll(operations)}<span class="cal-batch-when">Started ${escHtml(when(operations[0].operation.started_at))}</span>
            ${operations[0].operation.batch_id && active ? `<button type="button" class="btn btn-secondary btn-sm" id="classroomStop${i}"${state.submitting ? ' disabled' : ''}>Stop batch</button>` : ''}</div>
          <div class="cal-tablewrap"><table class="data-table cal-table"><tbody>${operations.map(({ lane, operation }) =>
    `<tr><td>${classroomLaneCellHtml(state, lane)}</td>
              <td><span class="badge ${classroomStatusBadge(operation.status)}">${escHtml(operation.status || 'unknown')}</span></td>
              <td class="cal-mono">${operation.operation_id ? escHtml(operation.operation_id) : ''}</td>
              <td class="cal-cell-err">${operation.error ? escHtml(operation.error) : ''}</td></tr>`).join('')}</tbody></table></div></div>`;
      }).join('') : '<div class="cal-empty"><strong>Nothing launched yet</strong><p>Choose a profile and lanes, then press Launch.</p></div>'));
    entries.forEach(([batchId, operations], i) => {
      const stop = document.getElementById(`classroomStop${i}`);
      if (stop) stop.onclick = () => stopClassroomBatch(state, batchId, [...new Set(operations.map(({ lane }) => lane.lane_id))]);
    });
  }

  // Short enough that choosing a profile feels like it answered, long enough
  // that arrowing down a 28-row picker queues ONE request rather than 28.
  const CLASSROOM_SOON_MS = 250;

  /**
   * Would another status request actually tell this dialog something new about
   * the selected profile?
   *
   * Three conditions, and all three are load-bearing. The payload has to have
   * been fetched for a DIFFERENT profile (or for none) — that is the only thing
   * that stops a server whose ability catalog is unreadable from being polled
   * every 250 ms forever, because the answer to "did the detail arrive" would be
   * no on every attempt. The profile has to exist in the payload, and it has to
   * have steps this payload cannot describe: re-asking for a profile with an
   * empty ordering is pure churn on a five-second poll.
   */
  function classroomProfileNeedsDetail(state) {
    if (state.mode !== 'attack' || !state.fresh) return false;
    const selected = state.adversary || '';
    if (selected === (state.payloadAdversary || '')) return false;
    const adversary = (state.payload?.adversaries || []).find(entry => entry.adversary_id === selected);
    if (!adversary) return false;
    const abilities = state.payload?.abilities || {};
    return classroomAbilityIds(adversary).some(id => !abilities[id]);
  }

  /**
   * Bring the next refresh forward.
   *
   * ONE TIMER SLOT, CLEARED FIRST. state.timer is the only scheduler this dialog
   * has, and clicking through profiles has to collapse into a single pending
   * request instead of stacking a queue of them that each land on top of the
   * last. A response that crossed a later selection is not thrown away — it is a
   * perfectly good status payload, it just describes the previous profile — so
   * state.payloadAdversary records what each one was fetched FOR, and the poll's
   * own tail schedules another prompt refresh whenever that no longer matches
   * what the instructor has selected.
   */
  function classroomRefreshSoon(state) {
    clearTimeout(state.timer);
    state.timer = setTimeout(() => refreshClassroomCaldera(state), CLASSROOM_SOON_MS);
  }

  async function refreshClassroomCaldera(state) {
    if (!classroomOpen(state) || state.refreshing || state.submitting) return;
    clearTimeout(state.timer);
    state.refreshing = true;
    const revision = state.revision;
    document.getElementById('classroomCalderaRefresh').disabled = true;
    try {
      // The operations endpoint ships full ability detail for ONE profile — the
      // one named in the query string — and a summary for every other. Naming
      // the selected id here is what fills the card; naming nothing when nothing
      // is chosen is not an error, it simply yields `abilities: {}`. The path is
      // BASE_PATH-relative and goes through laneCalderaRequest, so the query
      // string adds no second api-path literal to this file.
      //
      // ONLY ASKED FOR WHEN THE PAYLOAD SAYS THERE IS SOMETHING TO ASK FOR.
      // `ability_ids` and the `abilities` map ship from the same projection, so
      // a profile this payload lists no ordering for is one the server has no
      // catalog rows to send for either — naming it would hang a parameter on
      // every five-second poll of a server that predates the contract and can
      // only ignore it. The first poll after opening therefore carries no id at
      // all, and the tail of this function comes straight back for the detail
      // as soon as the profile's ordering is known.
      const selected = state.mode === 'attack' ? state.adversary || '' : '';
      const wanted = selected && classroomAbilityIds((state.payload?.adversaries || [])
        .find(entry => entry.adversary_id === selected) || {}).length ? selected : '';
      const data = await laneCalderaRequest(state, state.mode === 'install' ? '/caldera-agents/status'
        : `/caldera-operations/status${wanted ? `?adversary_id=${encodeURIComponent(wanted)}` : ''}`);
      if (!classroomOpen(state) || revision !== state.revision) return;
      state.payload = data;
      // What this payload was FETCHED for, never what it happens to contain: a
      // request that crossed a selection is answered for the profile that was
      // selected when it left, and this is the only record of which one that was.
      state.payloadAdversary = wanted;
      // Every memo behind the lane view is keyed on this number, and the lane
      // stats are keyed on the lane objects this assignment just replaced.
      state.payloadRevision++;
      state.fresh = true;
      state.misses = 0;
      if (!state.pending) state.error = '';
    } catch (error) {
      if (!classroomOpen(state) || revision !== state.revision) return;
      state.fresh = false;
      state.misses++;
      state.error = `Could not refresh Caldera status: ${error.message}.${state.misses >= 3 ? ' Automatic updates paused. Use Refresh status to try again.' : ''}`;
    } finally {
      state.refreshing = false;
      if (classroomOpen(state)) {
        renderClassroomCaldera(state);
        // A profile chosen WHILE this request was in flight left the payload
        // describing the wrong one, and the prompt refresh that selection asked
        // for was swallowed by the `refreshing` guard at the top of this
        // function. Coming back at the short delay is what stops the card
        // reading "this server did not describe this profile" for a full poll
        // interval after a click that should have answered it.
        if (!state.submitting && state.misses < 3) {
          state.timer = setTimeout(() => refreshClassroomCaldera(state),
            classroomProfileNeedsDetail(state) ? CLASSROOM_SOON_MS : 5000);
        }
      }
    }
  }

  function beginClassroomSubmission(state) {
    state.submitting = true;
    state.error = '';
    state.requests.forEach(controller => controller.abort());
    state.revision++;
    clearTimeout(state.timer);
    renderClassroomCaldera(state);
  }

  async function submitClassroomCaldera(state) {
    if (!classroomOpen(state) || state.submitting || document.getElementById('classroomCalderaSubmit').disabled) return;
    const install = state.mode === 'install';
    const targets = install ? classroomSelectedTargets(state) : [];
    if (!install && !state.pending) {
      state.pending = { request_id: window.crypto.randomUUID(), adversary_id: state.adversary,
        lane_ids: (state.payload.lanes || []).filter(lane => state.lanes.has(lane.lane_id) && classroomLaneAvailable(state, lane)).map(lane => lane.lane_id) };
      _pendingCalderaLaunches.set(state.courseId, state.pending);
    }
    beginClassroomSubmission(state);
    try {
      const data = await laneCalderaRequest(state, install ? '/caldera-agents/batch' : '/caldera-operations',
        { method: 'POST', body: install ? { targets } : state.pending });
      // A closed window may still receive the accepted response: clear only
      // the identical pending request, preserving any newer course launch.
      if (!install && _pendingCalderaLaunches.get(state.courseId) === state.pending) _pendingCalderaLaunches.delete(state.courseId);
      if (!classroomOpen(state)) return;
      state.results = Array.isArray(data.results) ? data.results : [];
      // The batch's own per-lane errors are what the "failed" facet counts when
      // no job row exists yet, and both branches below mutate lane objects the
      // stats memo is keyed on — a mutation a WeakMap cannot notice.
      state.resultErrors = new Set(state.results.filter(result => result.error).map(result => String(result.lane_id)));
      state.payloadRevision++;
      if (install) {
        state.results.forEach(result => {
          if (!result.job) return;
          const lane = state.payload.lanes.find(item => item.lane_id === result.lane_id);
          if (!lane) return;
          lane.jobs = classroomJobs(lane).filter(job => String(job.vm_id) !== String(result.vm_id)).concat([result.job]);
          _classroomLaneStats.delete(lane);
          state.targets.delete(`${result.lane_id}:${result.vm_id}`);
          state.excludedTargets.add(`${result.lane_id}:${result.vm_id}`);
        });
      } else {
        state.results.forEach(result => {
          const lane = state.payload.lanes.find(item => item.lane_id === result.lane_id);
          if (!lane || !data.batch_id) return;
          _classroomLaneStats.delete(lane);
          lane.operations = (lane.operations || []).filter(operation => operation.batch_id !== data.batch_id).concat([{
            ...result, batch_id: data.batch_id, started_at: data.started_at || new Date().toISOString(),
            adversary_name: state.payload.adversaries?.find(adversary => adversary.adversary_id === state.adversary)?.name || 'Caldera exercise',
          }]);
        });
        state.pending = null;
        state.lanes.clear();
      }
    } catch (error) {
      if (!classroomOpen(state)) return;
      state.fresh = false;
      const rejected = error.status >= 400 && error.status < 500;
      if (!install && rejected) { _pendingCalderaLaunches.delete(state.courseId); state.pending = null; }
      state.error = `${install ? 'Could not confirm installation requests' : rejected ? 'The launch was rejected' : 'Could not confirm the launch'}: ${error.message}. Refresh status ${install || rejected ? 'before retrying' : 'and retry the same launch request'}.`;
    } finally {
      state.submitting = false;
      if (classroomOpen(state)) {
        renderClassroomCaldera(state);
        state.misses = 0;
        state.timer = setTimeout(() => refreshClassroomCaldera(state), 1500);
      }
    }
  }

  async function stopClassroomBatch(state, batchId, laneIds) {
    if (!classroomOpen(state) || state.submitting) return;
    beginClassroomSubmission(state);
    try {
      const data = await laneCalderaRequest(state, '/caldera-operations/stop', { method: 'POST', body: { lane_ids: laneIds, batch_id: batchId } });
      if (!classroomOpen(state)) return;
      state.results = Array.isArray(data.results) ? data.results : [];
      state.resultErrors = new Set(state.results.filter(result => result.error).map(result => String(result.lane_id)));
      state.payloadRevision++;
    } catch (error) {
      if (classroomOpen(state)) state.error = `Could not confirm the stop request: ${error.message}. Refresh status before retrying.`;
    } finally {
      state.submitting = false;
      if (classroomOpen(state)) {
        renderClassroomCaldera(state);
        state.timer = setTimeout(() => refreshClassroomCaldera(state), 1500);
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
        if (tier !== 'staff') { closeLaneCalderaModal(); closeClassroomCaldera(); }
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
    closeClassroomCaldera();
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
    closeCalderaAgents: closeLaneCalderaModal,
    showGroupCalderaAgents: function () { return showClassroomCaldera('install'); },
    showCalderaAttack: function () { return showClassroomCaldera('attack'); },
    closeClassroomCaldera: closeClassroomCaldera
  };
})();
