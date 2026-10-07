/**
 * instructor-overview.js — Overview tab: hero stats, action items, recent
 * submissions.
 * ============================================================================
 * Pure view over InstructorState — this module fetches nothing itself. The
 * hero markup is static in instructor.html (so the frame paints before data);
 * this module fills the values and owns the two cards beneath it.
 *
 * Loaded after instructor-core.js; depends on its globals (InstructorState,
 * esc, partLabel, timeAgo, isOverdue, switchTab) and the kit (Auth).
 */
/* global InstructorState, Auth, esc, partLabel, timeAgo, isOverdue, switchTab */

const Overview = {
  _inited: false,

  ensureInit() {
    if (this._inited) return;
    this._inited = true;
    InstructorState.on('loading', () => this.renderLoading());
    InstructorState.on('dashboard', () => this.render());
    InstructorState.on('error', () => this.renderError());
    // Render whatever state exists right now (first visit may race the fetch).
    if (InstructorState.status === 'ready') this.render();
    else if (InstructorState.status === 'error') this.renderError();
    else this.renderLoading();
    this.renderGreeting();
  },

  renderGreeting() {
    const el = document.getElementById('heroGreeting');
    if (!el) return;
    const user = Auth.getUser() || {};
    const name = user.first_name || user.firstName || '';
    const hour = new Date().getHours();
    const salute = hour < 12 ? 'Good morning' : hour < 18 ? 'Good afternoon' : 'Good evening';
    el.textContent = name ? `${salute}, ${name}` : salute;
  },

  renderLoading() {
    ['statStudents', 'statPending', 'statCompleted', 'statDocs'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.innerHTML = '<span class="instr-hero-skel"></span>';
    });
    const scope = document.getElementById('heroScope');
    if (scope) scope.textContent = 'Loading…';
    const skel = `
      <div class="skeleton skel-row"></div>
      <div class="skeleton skel-row"></div>`;
    const actions = document.getElementById('actionItemsContent');
    if (actions) actions.innerHTML = skel;
    const recent = document.getElementById('recentSubmissions');
    if (recent) recent.innerHTML = skel;
  },

  render() {
    const d = InstructorState.dashboard || {};
    this.renderScopeChip();

    const students = d.students || [];
    const pendingTotal = d.pending_total ?? (d.pending_submissions || []).length;
    const completed = students.reduce((acc, s) => acc + (parseInt(s.completed_reviews) || 0), 0);

    this.setStat('statStudents', d.total_students ?? students.length);
    this.setStat('statPending', pendingTotal);
    this.setStat('statCompleted', completed);
    this.setStat('statDocs', d.documents_generated ?? 0);

    this.renderActionItems();
    this.renderRecentSubmissions();
  },

  renderError() {
    ['statStudents', 'statPending', 'statCompleted', 'statDocs'].forEach((id) => this.setStat(id, '—'));
    const scope = document.getElementById('heroScope');
    if (scope) scope.textContent = 'Unavailable';
    const actions = document.getElementById('actionItemsContent');
    if (actions) {
      actions.innerHTML = `
        <div class="empty-state" style="padding: 1.5rem;">
          <div class="icon">⚠️</div>
          <h3>Couldn't load the dashboard</h3>
          <p>${esc(InstructorState.error?.message || 'Something went wrong.')}</p>
          <button class="btn btn-primary btn-sm" onclick="InstructorState.refresh()">Retry</button>
        </div>`;
    }
    const recent = document.getElementById('recentSubmissions');
    if (recent) recent.innerHTML = '';
  },

  setStat(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  },

  renderScopeChip() {
    const el = document.getElementById('heroScope');
    if (!el) return;
    const { scope, scopeApplied, sections } = InstructorState;
    if (scopeApplied === 'mine') {
      const n = sections.length;
      el.textContent = `My sections · ${n} section${n === 1 ? '' : 's'}`;
    } else if (scopeApplied && scopeApplied !== 'all') {
      const section = sections.find((s) => s.section_id === scopeApplied);
      el.textContent = section ? `Section: ${section.code || section.name}` : 'One section';
    } else if (scope === 'mine') {
      // Asked for 'mine', server fell back — the instructor manages no sections.
      el.textContent = 'All students — no sections yet';
    } else {
      el.textContent = 'All students';
    }
  },

  renderActionItems() {
    const container = document.getElementById('actionItemsContent');
    if (!container) return;
    const d = InstructorState.dashboard || {};
    const items = [];

    const pending = d.pending_submissions || [];
    const pendingTotal = d.pending_total ?? pending.length;
    if (pendingTotal > 0) {
      const names = pending.slice(0, 3)
        .map((s) => `${esc(s.student_name?.trim() || s.student_email)} — Part ${s.part_number}`)
        .join(', ');
      const more = pendingTotal > 3 ? ` +${pendingTotal - 3} more` : '';
      items.push(`
        <div class="action-item warn">
          <div>
            <strong>${pendingTotal} submission${pendingTotal === 1 ? '' : 's'} awaiting review</strong>
            <div class="action-item-detail">${names}${more}</div>
          </div>
          <button class="btn btn-sm btn-primary" onclick="switchTab('reviews')">Review Now</button>
        </div>`);
    }

    const noProfiles = (d.students || []).filter((s) => !(s.generated_profiles || []).length);
    if (noProfiles.length > 0) {
      const names = noProfiles.slice(0, 4)
        .map((s) => esc(s.student_name?.trim() || s.student_email))
        .join(', ');
      const more = noProfiles.length > 4 ? ` +${noProfiles.length - 4} more` : '';
      items.push(`
        <div class="action-item">
          <div>
            <strong>${noProfiles.length} student${noProfiles.length === 1 ? '' : 's'} without profiles</strong>
            <div class="action-item-detail">${names}${more}</div>
          </div>
          <button class="btn btn-sm btn-outline" onclick="switchTab('students')">View Students</button>
        </div>`);
    }

    container.innerHTML = items.length
      ? `<div class="action-item-list">${items.join('')}</div>`
      : `
        <div class="empty-state" style="padding: 1.5rem;">
          <div class="icon">✅</div>
          <h3>All Caught Up</h3>
          <p>Nothing needs your attention right now.</p>
        </div>`;
  },

  renderRecentSubmissions() {
    const container = document.getElementById('recentSubmissions');
    if (!container) return;
    const pending = InstructorState.dashboard?.pending_submissions || [];

    if (!pending.length) {
      container.innerHTML = `
        <div class="empty-state" style="padding: 1.5rem;">
          <div class="icon">📭</div>
          <h3>No Recent Submissions</h3>
          <p>Student submissions will appear here.</p>
        </div>`;
      return;
    }

    // The queue arrives oldest-first; "recent" is the other end of it.
    const recent = pending.slice(-5).reverse();
    container.innerHTML = recent.map((sub) => `
      <div class="review-card compact" role="button" tabindex="0" onclick="switchTab('reviews')"
           onkeydown="if(event.key==='Enter')switchTab('reviews')">
        <div class="review-card-head">
          <span class="review-card-student">${esc(sub.student_name?.trim() || sub.student_email)}</span>
          <span class="age-chip ${isOverdue(sub.submitted_at) ? 'overdue' : ''}">${esc(timeAgo(sub.submitted_at))}</span>
        </div>
        <div class="review-card-chips">
          <span class="badge badge-primary">${esc(partLabel(sub.part_number))}</span>
          ${sub.profile_name ? `<span class="badge badge-info">${esc(sub.profile_name)}</span>` : ''}
        </div>
      </div>`).join('');
  },
};

window.Overview = Overview;
