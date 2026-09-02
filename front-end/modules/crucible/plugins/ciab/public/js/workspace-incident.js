/**
 * ============================================================================
 * workspace-incident.js — the Incident Board, inside the student workspace
 * ============================================================================
 * Track E, phase E5. public/js/blueteam/ shipped a complete board (transport,
 * scorecard, timeline, the board itself) and NOTHING LOADED IT. This file, plus
 * five script tags in workspace.html, is the CiAB student half of that wiring.
 *
 * WHY IT LIVES IN THE WORKSPACE AND NOT ON A PAGE OF ITS OWN
 * ----------------------------------------------------------------------------
 * Hunting and writing up are one sitting. A student flips between "what did the
 * sensors actually show" and "what am I claiming in Part 4" every few minutes,
 * and a second browser tab loses that thread. So the board is a panel beside
 * the eight deliverables rather than a ninth deliverable: it is not graded as a
 * part, it has no progress row, and switching to it does not disturb the part
 * the student was editing.
 *
 * HOW IT SHOWS AND HIDES, AND WHY IT IS A CLASS
 * ----------------------------------------------------------------------------
 * workspace.js OWNS the inline `display` styles on #noProfileState and
 * #workspaceContent — loadProfile() and showEmptyState() write them, and they
 * are the page's real state. If this file wrote them too it would restore a
 * stale value the moment a student switched profile with the panel open. So it
 * toggles ONE class on .workspace-main and lets an `!important` stylesheet rule
 * beat the inline style while the panel is up. Close the panel and workspace.js
 * is still right about what belongs underneath, with nothing to re-synchronise.
 *
 * THE RELEASE GATE IS THE POINT, AND THE PAGE SAYS SO OUT LOUD
 * ----------------------------------------------------------------------------
 * Before an instructor releases, a student sees their own submissions and
 * nothing else: no verdicts, no score, and NO COUNT OF WHAT THEY MISSED.
 * "There are six" is the most valuable hint on the page — it tells a student
 * exactly when to stop hunting, which is most of the skill being taught — so
 * the server withholds the totals entirely (src/incident/projection.js) and
 * neither this file nor blueteam-score.js reconstructs them.
 *
 * That gate is invisible if nobody names it. A page that quietly shows three
 * rows and no verdicts reads as broken, and a student who thinks the page is
 * broken stops trusting it. So the banner below states the state in words —
 * "not yet released by your instructor" — in both directions.
 *
 * WHAT THIS FILE DOES NOT DECIDE
 * ----------------------------------------------------------------------------
 * Anything about permission. `role: 'student'` below picks a LAYOUT. The server
 * stamps a `tier` on every read and blueteam-board.js renders the tier it was
 * given, so editing that string in a console produces the staff layout drawn
 * around a student payload — an empty table, not a disclosure.
 *
 * Requires, in this order, from workspace.html:
 *   /js/blueteam/blueteam-api.js, -timeline.js, -score.js, -board.js
 * ============================================================================
 */
(function () {
  'use strict';

  var UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

  /** Mirrors workspace.js's 'activeProfileId'. See resolveEngagementId(). */
  var ENGAGEMENT_KEY = 'ciab-active-engagement';

  /**
   * The banner's own poll, 20s, and it is NOT the board's 2s one.
   *
   * blueteam-board.js polls /status while an incident is in flight and stops on
   * a terminal status — correct for load, and it means a FINISHED run stops
   * watching for the one thing that still changes about it: release. This slow
   * poll covers that gap and nothing else. /status is the rate-limiter-exempt
   * path (src/server.js exempts GETs matching /\/status$/), so it is also the
   * only URL here that may be polled at all.
   */
  var BANNER_POLL_MS = 20000;

  var els = {};
  var client = null;        // BlueTeamApi client, or null before the first open
  var boardHandle = null;   // BlueTeamBoard.mount() handle, or null
  var engagementId = null;
  var currentRunId = null;
  var staffTier = false;
  var lastReleased = null;  // null = never observed; the first read must not redraw
  var bannerTimer = null;
  var opened = false;

  function el(id) { return document.getElementById(id); }

  function esc(v) {
    return String(v == null ? '' : v)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // ---------------------------------------------------------------------------
  // WHERE THE ENGAGEMENT ID COMES FROM
  //
  // The page's existing context is the PROFILE: workspace.js reads ?profile=
  // from the URL and mirrors it into localStorage as 'activeProfileId'. There is
  // no engagement anywhere in that context, and there is no student-readable
  // route that would supply one — every engagement route in this plugin is
  // instructor-or-admin, and the board's own collection URL needs the id before
  // it will answer anything. So the id travels exactly the way the profile
  // already does: on the link an instructor hands out, mirrored into storage so
  // a reload or a bookmark keeps working.
  //
  //   /ciab/workspace?engagement=<uuid>              registers it
  //   /ciab/workspace?engagement=<uuid>&incident=1   registers it and opens here
  //
  // window.CIAB_ENGAGEMENT_ID is read FIRST so a future page-context script can
  // supply it without this file changing at all.
  //
  // The uuid shape is checked BEFORE anything is stored. A junk value would
  // otherwise be persisted and then produce the same flat 404 on every reload,
  // with nothing on screen explaining why.
  // ---------------------------------------------------------------------------
  function resolveEngagementId() {
    var injected = window.CIAB_ENGAGEMENT_ID;
    if (injected && UUID_RE.test(String(injected))) return String(injected);

    var fromUrl = '';
    try {
      fromUrl = (new URLSearchParams(window.location.search).get('engagement') || '').trim();
    } catch (e) { fromUrl = ''; }

    if (UUID_RE.test(fromUrl)) {
      try { localStorage.setItem(ENGAGEMENT_KEY, fromUrl); } catch (e) { /* private mode */ }
      return fromUrl;
    }

    var stored = null;
    try { stored = localStorage.getItem(ENGAGEMENT_KEY); } catch (e) { stored = null; }
    return UUID_RE.test(String(stored || '')) ? String(stored) : null;
  }

  // ---------------------------------------------------------------------------
  // Copy
  //
  // Vocabulary: Client, Engagement, Environment, Incident. Nothing here borrows
  // a noun from the neighbouring product's model — a student running a clinic
  // never sees one, and would not know what it meant if they did.
  // ---------------------------------------------------------------------------

  var NOTE_NO_ENGAGEMENT = ''
    + '<strong>No environment is linked to this workspace yet.</strong>'
    + '<p>The Incident Board opens on the engagement environment your instructor assigned to '
    + 'you, and it learns which one from the link you were given. Open this workspace from that '
    + 'link and the board connects itself.</p>'
    + '<p>If you have not been given one, ask your instructor for the Incident Board link for '
    + 'this engagement.</p>';

  var NOTE_NO_RUNS = ''
    + '<strong>No incidents have run in this engagement yet.</strong>'
    + '<p>When your instructor starts one it appears here, and you can begin recording what you '
    + 'find in your environment.</p>';

  var NOTE_NOT_YOURS = ''
    + '<strong>There is nothing here for you.</strong>'
    + '<p>This account has no environment in that engagement, so there is no board to open. '
    + 'Check the link your instructor gave you, or ask them to confirm your environment is '
    + 'ready.</p>';

  var NOTE_STAFF = ''
    + '<strong>Instructor access.</strong>'
    + '<p>You are reading this engagement with staff access, so the board below shows every '
    + 'submission rather than one person’s. The release wording a student sees does not '
    + 'apply to you.</p>';

  var BANNER_LOCKED = ''
    + '<strong>Not yet released by your instructor.</strong>'
    + '<p>Everything below is your own work and nothing else. There are no verdicts yet, and '
    + 'this page deliberately does not tell you how much is left to find — knowing the '
    + 'number would be most of the answer. Keep hunting until you believe you have the whole '
    + 'story.</p>'
    + '<p>Verdicts, anything you missed and the scored timeline appear here the moment your '
    + 'instructor releases this incident.</p>';

  var BANNER_RELEASED = ''
    + '<strong>Released by your instructor.</strong>'
    + '<p>Verdicts, anything you missed and your score are shown below. Submissions for this '
    + 'incident are closed — the results are on your screen, so anything recorded now '
    + 'would be a transcription rather than a finding.</p>';

  /**
   * A run's state, in words a student can act on.
   *
   * 'partial' and 'failed' are collapsed rather than surfaced verbatim: they are
   * operational detail about the generator, and the only thing they change for a
   * student is whether there is anything in the sensors to look at.
   */
  function statusWord(status) {
    switch (String(status || '')) {
      case 'scheduling':
      case 'dispatching': return 'preparing';
      case 'running':     return 'in progress';
      case 'completed':
      case 'partial':     return 'finished';
      case 'failed':      return 'did not run';
      case 'aborted':     return 'stopped';
      default:            return 'unknown';
    }
  }

  /**
   * A run, named for the picker.
   *
   * Deliberately NOT the run's `mode`. The student projection ships it, but
   * "chain" against "technique" tells a student up front whether they are
   * hunting one step or several, which is part of what the exercise asks them to
   * work out. A date and a plain-English state is all they need to pick a row.
   */
  function runLabel(run, ordinal) {
    var when = (run && run.scheduled_start_at) ? new Date(run.scheduled_start_at) : null;
    var stamp = (when && isFinite(when.getTime()))
      ? when.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })
      : 'not scheduled';
    return 'Incident ' + ordinal + ' — ' + stamp + ' — ' + statusWord(run && run.status);
  }

  // ---------------------------------------------------------------------------
  // Rendering
  // ---------------------------------------------------------------------------

  function showNote(html) {
    els.note.innerHTML = html;
    els.note.hidden = false;
  }

  function hideNote() {
    els.note.innerHTML = '';
    els.note.hidden = true;
  }

  function renderBanner(released) {
    els.banner.className = 'incident-banner incident-banner-' + (released ? 'released' : 'locked');
    els.banner.innerHTML = released ? BANNER_RELEASED : BANNER_LOCKED;
    els.banner.hidden = false;
  }

  function hideBanner() {
    els.banner.hidden = true;
    els.banner.innerHTML = '';
  }

  // ---------------------------------------------------------------------------
  // Loading
  // ---------------------------------------------------------------------------

  function start() {
    engagementId = resolveEngagementId();
    if (!engagementId) {
      showNote(NOTE_NO_ENGAGEMENT);
      return;
    }

    els.sub.textContent = 'Engagement ' + engagementId.slice(0, 8);
    client = window.BlueTeamApi.create({
      base: '/api/engagements/' + encodeURIComponent(engagementId) + '/incidents'
    });
    loadRuns();
  }

  function loadRuns() {
    showNote('<strong>Loading the incidents in this engagement…</strong>');
    client.listRuns().then(function (data) {
      var runs = (data && Array.isArray(data.runs)) ? data.runs : [];
      staffTier = !!(data && data.tier === 'staff');

      if (!runs.length) {
        els.picker.hidden = true;
        showNote(NOTE_NO_RUNS);
        return;
      }

      // Newest first is what the route returns, so the first row is the one a
      // student almost always wants and the ordinal counts down from the total.
      els.select.innerHTML = runs.map(function (run, i) {
        return '<option value="' + esc(run.run_id) + '">'
          + esc(runLabel(run, runs.length - i)) + '</option>';
      }).join('');
      els.picker.hidden = false;

      if (staffTier) showNote(NOTE_STAFF); else hideNote();
      selectRun(runs[0].run_id);
    }).catch(function (err) {
      els.picker.hidden = true;
      // 404 is the route's ONE answer to "no such engagement", "not your
      // engagement" and "no environment of yours in it" — deliberately
      // indistinguishable, so this message must not guess which it was.
      if (err && err.status === 404) {
        showNote(NOTE_NOT_YOURS);
        return;
      }
      showNote('<strong>The Incident Board could not be loaded.</strong><p>'
        + esc(err && err.message ? err.message : 'Unknown error') + '</p>');
    });
  }

  function selectRun(runId) {
    if (boardHandle) { boardHandle.destroy(); boardHandle = null; }
    currentRunId = runId;
    lastReleased = null;
    hideBanner();

    boardHandle = window.BlueTeamBoard.mount(els.mount, {
      // The incidents COLLECTION url for this engagement. It is the only thing
      // that differs between this page and the same board elsewhere; nothing in
      // blueteam-*.js branches on which product it is running in.
      base: client.base,
      // The layout, not a permission. See this file's header.
      role: 'student',
      runId: runId
    });

    refreshBanner();
    startBannerPoll();
  }

  // ---------------------------------------------------------------------------
  // The release banner
  // ---------------------------------------------------------------------------

  function refreshBanner() {
    if (!client || !currentRunId || staffTier) return;
    var runId = currentRunId;
    client.getStatus(runId).then(function (st) {
      // The picker may have moved while this was in flight. Answering for the
      // previous run would put the wrong release state above the right board.
      if (runId !== currentRunId) return;
      var released = !!(st && st.released === true);
      renderBanner(released);
      // The board stops polling once a run reaches a terminal status, so on a
      // finished incident it would never notice the release by itself. When this
      // slow poll sees the flip, ask it to redraw.
      if (lastReleased !== null && released !== lastReleased && boardHandle) boardHandle.refresh();
      lastReleased = released;
    }).catch(function () {
      // A poll failure is not worth a toast, and the banner already on screen is
      // still the last state that was actually observed.
    });
  }

  function startBannerPoll() {
    stopBannerPoll();
    if (staffTier) return;
    bannerTimer = setInterval(refreshBanner, BANNER_POLL_MS);
  }

  function stopBannerPoll() {
    if (bannerTimer) { clearInterval(bannerTimer); bannerTimer = null; }
  }

  // ---------------------------------------------------------------------------
  // Open / close
  // ---------------------------------------------------------------------------

  function open() {
    els.main.classList.add('incident-open');
    els.navBtn.classList.add('active');
    els.navBtn.setAttribute('aria-expanded', 'true');
    if (!opened) { opened = true; start(); }
    else if (currentRunId) { refreshBanner(); startBannerPoll(); }
  }

  function close() {
    els.main.classList.remove('incident-open');
    els.navBtn.classList.remove('active');
    els.navBtn.setAttribute('aria-expanded', 'false');
    // The board stays mounted so reopening is instant; only the banner's own
    // timer stops, because nobody is reading it.
    stopBannerPoll();
  }

  function toggle() {
    if (els.main.classList.contains('incident-open')) close(); else open();
  }

  // ---------------------------------------------------------------------------
  // Init
  // ---------------------------------------------------------------------------

  function init() {
    els = {
      main:     el('workspaceMain'),
      nav:      el('incidentNav'),
      navBtn:   el('incidentNavBtn'),
      closeBtn: el('incidentCloseBtn'),
      panel:    el('incidentPanel'),
      sub:      el('incidentSub'),
      picker:   el('incidentPicker'),
      select:   el('incidentRunSelect'),
      banner:   el('incidentBanner'),
      note:     el('incidentNote'),
      mount:    el('incidentMount')
    };
    if (!els.main || !els.navBtn || !els.panel) return;

    // If the four board files did not load — a stale cache, a blocked request —
    // hide the entry rather than offering a button that throws. An honest
    // absence beats a control that fails when it is pressed.
    if (!window.BlueTeamApi || !window.BlueTeamBoard
        || !window.BlueTeamScore || !window.BlueTeamTimeline) {
      if (els.nav) els.nav.hidden = true;
      return;
    }

    els.navBtn.addEventListener('click', toggle);
    els.closeBtn.addEventListener('click', close);
    els.select.addEventListener('change', function () {
      if (els.select.value) selectRun(els.select.value);
    });

    // Deep link. `incident=1` is what opens the panel; `engagement` alone only
    // registers the id, so a link that sets up the workspace does not yank a
    // student away from the deliverable they came here for.
    var wantsBoard = false;
    try {
      wantsBoard = new URLSearchParams(window.location.search).get('incident') === '1';
    } catch (e) { wantsBoard = false; }
    if (wantsBoard) open();
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
  else init();
})();
