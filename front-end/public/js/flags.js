/**
 * Flags — student-facing capture flag board, scoped to a course.
 *
 * The student opens a course they are enrolled in and works its assignment:
 * find user.txt / root.txt on each machine in their lane and submit the value.
 * Verification is server-side against their OWN lane only; a flag from another
 * student's lane comes back as "Incorrect Flag" exactly like random input, so
 * this UI never needs to distinguish the two.
 *
 * Two views in one pane: the course list, and one course's board. Exposed as
 * window.Flags for hub.html inline handlers, matching the Workstations /
 * VmWorkspaces module pattern.
 */
const Flags = (() => {
  'use strict';

  let _courses      = [];
  let _board        = null;
  let _openCourseId = null;
  let _listLoaded   = false;
  let _busy         = false;

  function _headers() {
    return {
      'Authorization': `Bearer ${localStorage.getItem('token')}`,
      'Content-Type': 'application/json',
    };
  }

  async function _get(path) {
    const res  = await fetch(path, { headers: _headers() });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  async function _post(path, body) {
    const res  = await fetch(path, { method: 'POST', headers: _headers(), body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    return data;
  }

  function _esc(s) {
    return (typeof Utils !== 'undefined' && Utils.escapeHtml)
      ? Utils.escapeHtml(s)
      : String(s == null ? '' : s)
          .replace(/&/g, '&amp;').replace(/</g, '&lt;')
          .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
  }

  function _pct(captured, total) {
    return total > 0 ? Math.round((captured / total) * 100) : 0;
  }

  function _bar(captured, total) {
    return `<div class="flag-bar"><div class="flag-bar-fill" style="width:${_pct(captured, total)}%"></div></div>`;
  }

  // Deliberately not an id ending in "Content" — hub.html's switchDashboardTab
  // hides every [id$="Content"] element on each nav change.
  function _root() { return document.getElementById('flagCoursesPanel'); }

  // ── Course list ─────────────────────────────────────────────────────────────

  async function loadCourses(force = false) {
    if (_listLoaded && !force && !_openCourseId) return;
    const root = _root();
    if (!root) return;

    _openCourseId = null;
    root.innerHTML = '<p style="color: var(--text-muted);">Loading your courses…</p>';

    try {
      const data = await _get('/api/cle/my/courses');
      _courses    = data.courses || [];
      _listLoaded = true;
      _renderCourses(data.unattributedFlags || 0);
    } catch (err) {
      root.innerHTML = `<p style="color: var(--danger);">Could not load your courses: ${_esc(err.message)}</p>`;
    }
  }

  function _renderCourses(unattributed) {
    const root = _root();
    if (!root) return;

    if (_courses.length === 0) {
      root.innerHTML = `
        <div class="flag-empty">
          <p><strong>You are not enrolled in any courses yet.</strong></p>
          <p>Once your instructor enrolls you and deploys your lab, the assignment
             and its flags will appear here.</p>
        </div>`;
      return;
    }

    const cards = _courses.map(c => {
      const hasFlags = c.total > 0;
      const done     = hasFlags && c.captured === c.total;

      const status = !hasFlags
        ? `<span class="flag-chip flag-chip-none">no lab deployed yet</span>`
        : done
          ? `<span class="flag-chip flag-chip-done">✓ all ${c.total} captured</span>`
          : `<span class="flag-chip flag-chip-todo">${c.captured} / ${c.total} flags</span>`;

      const meta = [
        c.code ? _esc(c.code) : null,
        c.machineCount ? `${c.machineCount} machine${c.machineCount === 1 ? '' : 's'}` : null,
        c.assignmentCount ? `${c.assignmentCount} assignment${c.assignmentCount === 1 ? '' : 's'}` : null,
        c.isActive ? null : 'archived'
      ].filter(Boolean).join(' · ');

      return `
        <button type="button" class="flag-course-card" onclick="Flags.openCourse('${_esc(c.courseId)}')">
          <div class="flag-course-head">
            <span class="flag-course-name">${_esc(c.courseName)}</span>
            ${status}
          </div>
          ${meta ? `<div class="flag-course-meta">${meta}</div>` : ''}
          ${hasFlags ? _bar(c.captured, c.total) : ''}
        </button>`;
    }).join('');

    const warn = unattributed > 0
      ? `<div class="flag-note">${unattributed} flag${unattributed === 1 ? '' : 's'} on your lanes
         could not be matched to one of your courses. Ask your instructor which course they belong to.</div>`
      : '';

    root.innerHTML = `<div class="flag-course-grid">${cards}</div>${warn}`;
  }

  // ── One course's board ──────────────────────────────────────────────────────

  async function openCourse(courseId) {
    const root = _root();
    if (!root) return;

    _openCourseId = courseId;
    root.innerHTML = '<p style="color: var(--text-muted);">Loading assignment…</p>';

    try {
      _board = await _get(`/api/cle/my/courses/${encodeURIComponent(courseId)}/flags`);
      _renderBoard();
    } catch (err) {
      root.innerHTML = `
        <button class="btn btn-secondary btn-sm" onclick="Flags.loadCourses(true)">← Back to courses</button>
        <p style="color: var(--danger); margin-top:12px;">Could not load this course: ${_esc(err.message)}</p>`;
    }
  }

  function _renderBoard() {
    const root = _root();
    if (!root || !_board) return;

    const { course, assignments, machines, captured, total } = _board;

    const assignmentHtml = (assignments || []).length > 0
      ? (assignments).map(a => `
          <div class="flag-assignment">
            <div class="flag-assignment-title">${_esc(a.title)}</div>
            ${a.description ? `<p class="flag-assignment-desc">${_esc(a.description)}</p>` : ''}
          </div>`).join('')
      : `<div class="flag-note">Your instructor has not published an assignment brief for this
         course yet. The machines below are still live — the flags are on them.</div>`;

    const boardHtml = (machines || []).length > 0
      ? `<div class="flag-rows">${machines.map(_machineRow).join('')}</div>`
      : `<div class="flag-empty">
           <p><strong>No lab machines are deployed for you yet.</strong></p>
           <p>Once your instructor deploys this course's lab, every target will have a
              <code>user.txt</code> and a <code>root.txt</code> waiting.</p>
         </div>`;

    const submitHtml = (machines || []).length > 0
      ? `<div class="flag-submit-row">
           <input id="flagInput" type="text" class="flag-input" autocomplete="off"
                  spellcheck="false" placeholder="Paste a flag from user.txt or root.txt"
                  onkeydown="Flags.onKeyDown(event)">
           <button id="flagSubmitBtn" class="btn btn-primary" onclick="Flags.submit()">Submit</button>
         </div>
         <p class="flag-hint">Flags are unique to your lane. A classmate's flag will not be accepted.</p>`
      : '';

    root.innerHTML = `
      <button class="btn btn-secondary btn-sm" onclick="Flags.loadCourses(true)">← Back to courses</button>

      <div class="flag-board-head">
        <h2 class="flag-board-title">${_esc(course.courseName)}</h2>
        ${course.code ? `<span class="flag-course-meta">${_esc(course.code)}</span>` : ''}
      </div>

      ${assignmentHtml}

      <div class="flag-panel">
        <div class="flag-summary">
          <strong>${captured} / ${total}</strong> flags captured
          ${total > 0 ? _bar(captured, total) : ''}
        </div>
        ${submitHtml}
        <div class="flag-progress">${boardHtml}</div>
      </div>`;

    const input = document.getElementById('flagInput');
    if (input) input.focus();
  }

  function _machineRow(m) {
    const cell = (f, label) => {
      if (!f) return `<span class="flag-chip flag-chip-none">no ${label}</span>`;
      if (f.captured) {
        const when = f.capturedAt ? new Date(f.capturedAt).toLocaleString() : '';
        return `<span class="flag-chip flag-chip-done" title="Captured ${_esc(when)}">✓ ${label}</span>`;
      }
      if (!f.available) {
        return `<span class="flag-chip flag-chip-broken"
                 title="This flag failed to deploy — report it to your instructor">! ${label}</span>`;
      }
      return `<span class="flag-chip flag-chip-todo">${label}</span>`;
    };

    return `
      <div class="flag-row">
        <span class="flag-vm">${_esc(m.vmName)}</span>
        <span class="flag-cells">${cell(m.user, 'user')}${cell(m.root, 'root')}</span>
      </div>`;
  }

  // ── Submission ──────────────────────────────────────────────────────────────

  async function submit() {
    if (_busy) return;
    const input = document.getElementById('flagInput');
    if (!input) return;

    const value = input.value.trim();
    if (!value) {
      Toast.info('Nothing to submit', 'Paste a flag first.');
      return;
    }

    _busy = true;
    const btn = document.getElementById('flagSubmitBtn');
    if (btn) { btn.disabled = true; btn.textContent = 'Checking…'; }

    try {
      const result = await _post('/api/flags/submit', { flag: value });

      if (result.correct && result.already) {
        Toast.info('Already Captured',
          `You already submitted the ${result.flagType} flag for ${result.vmName}.`);
        input.value = '';
      } else if (result.correct) {
        Toast.success('Flag Captured',
          `${result.flagType === 'root' ? 'Root' : 'User'} flag on ${result.vmName}. Nice work.`);
        input.value = '';
        if (_openCourseId) await openCourse(_openCourseId);
      } else {
        // Covers a wrong value AND another student's real flag — the server
        // does not distinguish them, and neither should this message.
        Toast.error('Incorrect Flag', result.message || 'Incorrect Flag');
        input.select();
      }
    } catch (err) {
      Toast.error('Submission Failed', err.message);
    } finally {
      _busy = false;
      const b = document.getElementById('flagSubmitBtn');
      if (b) { b.disabled = false; b.textContent = 'Submit'; }
    }
  }

  function onKeyDown(event) {
    if (event.key === 'Enter') {
      event.preventDefault();
      submit();
    }
  }

  return { loadCourses, openCourse, submit, onKeyDown };
})();
