/**
 * HubCourses — the CyberHub landing page.
 *
 * Replaces the module-card grid that used to sit here. Every module on that
 * grid is already in the left sidebar, so it repeated navigation the user had
 * just walked past. What professors asked for instead: the courses they are
 * involved in, and a way into their remote workspaces.
 *
 * TWO RELATIONSHIPS, ONE LIST
 *   A student is a row in cle_course_enrollment. A professor is the scalar
 *   cle_course.instructor_id — they are NOT enrolled in the course they teach,
 *   which is why neither existing endpoint could answer this. GET
 *   /api/cle/my/overview merges both and tags each card with `relationship`.
 *
 * THE CARD'S DESTINATION IS COMPUTED HERE, from `relationship` + `features`,
 * not sent by the server. A pre-computed action list would be a second source
 * of truth for one decision, and the two would drift.
 *
 * Exposed as window.HubCourses for hub.html inline handlers, matching the
 * Flags / Workstations / VmWorkspaces pattern.
 */
const HubCourses = (() => {
  'use strict';

  let _courses      = [];
  let _adminSummary = null;
  let _role         = null;
  let _previewing   = false;
  let _loaded       = false;
  // Re-entering the tab should not refetch the VM list on every click.
  let _vmsLoadedAt  = 0;
  const VM_TTL_MS   = 10000;

  function _esc(s) {
    return (typeof Utils !== 'undefined' && Utils.escapeHtml)
      ? Utils.escapeHtml(s)
      : String(s == null ? '' : s)
          .replace(/&/g, '&amp;').replace(/</g, '&lt;')
          .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _el(id) { return document.getElementById(id); }

  // ── Course cards ────────────────────────────────────────────────────────────

  function _dateRange(c) {
    const fmt = (d) => (typeof Utils !== 'undefined' && Utils.formatDate)
      ? Utils.formatDate(d) : new Date(d).toLocaleDateString();
    // There is no term/semester column in cle_course. The period is
    // start_date/end_date, both nullable and never set by the create endpoint,
    // and the term is embedded in `code` (CYBR-480-7W1-1). So the code carries
    // the term and this is simply omitted when the dates are absent.
    if (c.startDate && c.endDate) return `${fmt(c.startDate)} – ${fmt(c.endDate)}`;
    if (c.startDate) return `from ${fmt(c.startDate)}`;
    if (c.endDate)   return `until ${fmt(c.endDate)}`;
    return null;
  }

  function _roleBadge(c) {
    if (c.relationship === 'instructor') {
      return `<span class="hub-role-badge hub-role-badge-instructor">Instructor</span>`;
    }
    const label = c.enrollmentRole === 'ta' ? 'TA'
                : c.enrollmentRole === 'lab_assistant' ? 'Lab Assistant'
                : c.enrollmentRole === 'guest' ? 'Guest'
                : 'Student';
    return `<span class="hub-role-badge hub-role-badge-student">${label}</span>`;
  }

  function _meta(c) {
    const isInstructor = c.relationship === 'instructor';
    const parts = [];

    const range = _dateRange(c);
    if (range) parts.push(_esc(range));

    // Only a student needs telling who runs the course.
    if (!isInstructor && c.instructor && c.instructor.name) {
      parts.push(`Taught by ${_esc(c.instructor.name)}`);
    }
    if (isInstructor) {
      const n = c.studentCount || 0;
      const v = c.vmCount || 0;
      parts.push(`👥 ${n} student${n === 1 ? '' : 's'}`);
      parts.push(`🖥 ${v} lab machine${v === 1 ? '' : 's'}`);
      if (c.alsoEnrolled) parts.push('also enrolled');
    }
    if (!c.isActive) parts.push('archived');

    // Mirrors courseStatusBadge() on the instructor course page, so the two
    // views describe a half-built lab the same way.
    if (c.provisionStatus === 'provisioning') parts.push('⏳ Initializing…');
    if (c.provisionStatus === 'failed')       parts.push('⚠ Setup failed');

    return parts.filter(Boolean).join(' · ');
  }

  function _progress(c) {
    if (!c.flags) return '';
    const { captured, total } = c.flags;
    if (total === 0) {
      return `<div class="hub-course-chips">
                <span class="flag-chip flag-chip-none">no lab deployed yet</span>
              </div>`;
    }
    const pct  = Math.round((captured / total) * 100);
    const chip = captured === total
      ? `<span class="flag-chip flag-chip-done">✓ all ${total} captured</span>`
      : `<span class="flag-chip flag-chip-todo">${captured} / ${total} flags</span>`;
    return `<div class="hub-course-chips">${chip}</div>
            <div class="flag-bar"><div class="flag-bar-fill" style="width:${pct}%"></div></div>`;
  }

  /**
   * Where this card goes. Kept as its own function because it is the one piece
   * of real logic here and test/hub-course-target.test.js pins it.
   */
  function cardTarget(c) {
    if (c.relationship === 'instructor') {
      return { kind: 'link', href: `/cle/courses?course=${encodeURIComponent(c.courseId)}`, label: 'Manage course' };
    }
    // Every student course is openable, flags or not. GET /api/cle/my/courses/:id
    // serves both, so a course with Flags off is a real view rather than a card
    // that does nothing when tapped.
    return {
      kind: 'inline',
      courseId: c.courseId,
      label: (c.flags && c.flags.total > 0) ? 'Open flag board'
           : (c.features && c.features.flags) ? 'Open flag board'
           : 'View course',
    };
  }

  function _actions(c) {
    const t = cardTarget(c);
    if (t.kind === 'link') {
      // A real anchor, so middle-click and open-in-new-tab work.
      return `<a class="btn btn-sm btn-primary" href="${_esc(t.href)}">${_esc(t.label)}</a>`;
    }
    return `<button type="button" class="btn btn-sm btn-primary"
              onclick="HubCourses.openCourse('${_esc(t.courseId)}')">${_esc(t.label)}</button>`;
  }

  function _card(c) {
    const meta = _meta(c);
    return `
      <article class="hub-course-card${c.isActive ? '' : ' hub-course-card-archived'}">
        <div class="hub-course-head">
          <span class="hub-course-name">${_esc(c.courseName)}</span>
          ${_roleBadge(c)}
        </div>
        ${c.code ? `<div class="hub-course-code">${_esc(c.code)}</div>` : ''}
        ${meta ? `<div class="hub-course-meta">${meta}</div>` : ''}
        ${c.description ? `<p class="hub-course-desc">${_esc(c.description)}</p>` : ''}
        ${_progress(c)}
        <div class="hub-course-actions">${_actions(c)}</div>
      </article>`;
  }

  function _adminCallout() {
    if (!_adminSummary) return '';
    const { activeCourses, totalCourses } = _adminSummary;
    // One row, not N cards. Rendering every course in the system would turn a
    // personal home page into a fleet console, which /cle/courses already is.
    return `
      <div class="hub-ws-card" style="margin-top:16px;">
        <span class="hub-ws-icon">📚</span>
        <div class="hub-ws-body">
          <div class="hub-ws-title">Course administration</div>
          <div class="hub-ws-sub">
            You administer <span class="hub-ws-stat">${activeCourses}</span>
            active course${activeCourses === 1 ? '' : 's'} (${totalCourses} total).
          </div>
        </div>
        <div class="hub-ws-actions">
          <a class="btn btn-sm btn-secondary" href="/cle/courses">Open course management</a>
        </div>
      </div>`;
  }

  function _empty() {
    const previewNote = _previewing
      ? `<p>You're previewing as a student — the courses you teach are hidden.
           Exit Student View to see them.</p>`
      : '';

    if (_role === 'instructor') {
      return `<div class="hub-empty">
                <h3>No courses assigned to you.</h3>
                <p>Ask an administrator to assign you a course.</p>
                <p><a href="/cle/courses">Open course management</a></p>
              </div>`;
    }
    if (_role === 'admin') {
      return `<div class="hub-empty">
                <h3>No courses exist yet.</h3>
                <p><a href="/cle/courses">Create the first one</a></p>
              </div>`;
    }
    return `<div class="hub-empty">
              <h3>No courses yet.</h3>
              <p>When your instructor enrolls you, your classes and their lab
                 assignments show up here.</p>
              ${previewNote}
            </div>`;
  }

  function _renderCourses(unattributed) {
    const root = _el('hubCoursesPanel');
    if (!root) return;

    if (_courses.length === 0) {
      root.innerHTML = _empty() + _adminCallout();
      return;
    }

    const warn = unattributed > 0
      ? `<div class="flag-note">${unattributed} flag${unattributed === 1 ? '' : 's'} on your lanes
         could not be matched to one of your courses. Ask your instructor which course they
         belong to.</div>`
      : '';

    root.innerHTML =
      `<div class="hub-course-grid">${_courses.map(_card).join('')}</div>` +
      warn + _adminCallout();
  }

  async function load(force = false) {
    if (_loaded && !force) return;
    const root = _el('hubCoursesPanel');
    if (!root) return;

    root.innerHTML = '<div class="hub-skel">Loading your courses…</div>';
    try {
      // Student View is a client-side presentation mode, so the framing has
      // to be requested explicitly — the server still sees the real role.
      // Without this the instructor's taught-course cards and admin summary
      // stay on the home page in the middle of a lecture recording.
      const previewing = typeof Auth !== 'undefined'
        && typeof Auth.isViewingAsStudent === 'function'
        && Auth.isViewingAsStudent();
      const data = await API.request(`/cle/my/overview${previewing ? '?as=student' : ''}`);
      _courses      = data.courses || [];
      _adminSummary = data.adminSummary || null;
      _role         = data.role || null;
      _previewing   = data.viewingAsStudent === true;
      _loaded       = true;
      _renderCourses(data.unattributedFlags || 0);
    } catch (err) {
      // 404 means the CLE plugin is not mounted on this deployment. That is a
      // configuration, not a failure — hide the section rather than shout.
      if (err && err.status === 404) {
        const section = _el('hubCoursesSection');
        if (section) section.style.display = 'none';
        return;
      }
      const msg = (err && (err.data?.error || err.message)) || 'Request failed';
      root.innerHTML = `
        <div class="hub-error">
          <span>⚠ Could not load your courses: ${_esc(msg)}</span>
          <button type="button" class="btn btn-sm btn-secondary"
                  onclick="HubCourses.load(true)">Retry</button>
        </div>`;
    }
  }

  // ── The flag board / course drill-down ──────────────────────────────────────

  function openCourse(courseId) {
    if (typeof Flags === 'undefined') return;
    const panel = _el('flagCoursesPanel');
    if (!panel) return;

    const courses = _el('hubCoursesSection');
    const wks     = _el('hubWorkspacesSection');
    if (courses) courses.style.display = 'none';
    if (wks)     wks.style.display     = 'none';
    panel.style.display = 'block';

    Flags.openCourse(courseId);
  }

  /** Registered with Flags as its back handler — see Flags.setBackHandler. */
  function showList() {
    const panel = _el('flagCoursesPanel');
    if (panel) { panel.innerHTML = ''; panel.style.display = 'none'; }

    const courses = _el('hubCoursesSection');
    const wks     = _el('hubWorkspacesSection');
    if (courses) courses.style.display = '';
    if (wks)     wks.style.display     = '';

    const scroller = document.querySelector('.page-content');
    if (scroller) scroller.scrollTop = 0;
  }

  // ── Remote workspaces ───────────────────────────────────────────────────────

  /**
   * The live VM list, rendered right here on the home page rather than behind a
   * click. One fetch covers everything: GET /api/dashboard/vms?scope=mine
   * filters on cybercore_allocation only — its LIVE_LANE_FILTER excludes dead
   * LANE VMs and explicitly leaves non-lane VMs alone — so the result already
   * includes both lane VMs and self-deployed workstations, and VmConsole drives
   * every one of them through the same guac-session endpoint.
   *
   * scope:'mine' is not optional. VmWorkspaces defaults admins and instructors
   * to the cluster-wide view; on a personal home page a professor wants their
   * own machines, and the cluster toggle stays where it has always been, on the
   * My Workspaces tab.
   */
  function renderWorkspaces(force = false) {
    if (typeof VmWorkspaces === 'undefined') return;
    const list = _el('hubVmList');
    if (!list) return;
    if (!force && Date.now() - _vmsLoadedAt < VM_TTL_MS) return;
    _vmsLoadedAt = Date.now();

    VmWorkspaces.render(list, 'hubVmConsole', {
      toggles:  false,   // those belong to the My Workspaces tab
      scope:    'mine',
      embedded: true,    // do not steal _lastListEl from that tab
    });
  }

  // ── Init ────────────────────────────────────────────────────────────────────

  function init() {
    if (typeof Flags !== 'undefined' && Flags.setBackHandler) {
      Flags.setBackHandler(showList);
    }
    load();
  }

  return { init, load, openCourse, showList, renderWorkspaces, cardTarget };
})();

// Node's test runner evaluates this file in a sandbox to pin cardTarget().
if (typeof module !== 'undefined' && module.exports) {
  module.exports = HubCourses;
}
