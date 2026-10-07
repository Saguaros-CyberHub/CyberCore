/**
 * instructor-students.js — Students tab: list pipeline, detail panels,
 * claim/enroll/assign flows.
 * ============================================================================
 * Renders from InstructorState only; own fetches are limited to per-student
 * detail (progress/documents/labs) and the action endpoints. The toolbar lives
 * in static markup OUTSIDE #studentsList, so typing never loses the caret.
 *
 * Perf contract: search/filter/sort re-render the list (chunked, 60 cards at a
 * time); expanding a card, claiming, or releasing must NOT — those touch only
 * that one card's DOM.
 *
 * Loaded after instructor-core.js; depends on its globals (InstructorState,
 * esc, PART_NAMES, openModal/closeModal, switchTab) and the kit
 * (API, Auth, Toast, Confirm, Utils).
 */
/* global InstructorState, API, Auth, Toast, Confirm, Utils, esc, PART_NAMES, openModal, closeModal, switchTab */

const CHUNK_SIZE = 60;

const STATUS_PILLS = {
  not_started: ['not-started', 'Not Started'],
  in_progress: ['in-progress', 'In Progress'],
  submitted: ['submitted', 'Submitted'],
  reviewed: ['reviewed', 'Reviewed'],
  revision_requested: ['revision-requested', 'Revision Needed'],
};

function statusPill(status) {
  const [cls, label] = STATUS_PILLS[status] || STATUS_PILLS.not_started;
  return `<span class="status-pill ${cls}">${label}</span>`;
}

const Students = {
  _inited: false,
  _visible: [],
  _chunk: CHUNK_SIZE,
  _expandedId: null,
  _sectionFilter: null, // section_id, client-side narrowing; null = no pill
  _debouncedApply: null,

  ensureInit() {
    if (this._inited) return;
    this._inited = true;
    InstructorState.on('loading', () => this.renderLoading());
    InstructorState.on('dashboard', () => this.onDashboard());
    InstructorState.on('error', () => this.renderError());
    if (InstructorState.status === 'ready') this.onDashboard();
    else if (InstructorState.status === 'error') this.renderError();
    else this.renderLoading();
  },

  onDashboard() {
    // A refresh can shrink the managed-section list out from under the pill.
    if (this._sectionFilter
        && !InstructorState.sections.some((s) => s.section_id === this._sectionFilter)) {
      this._sectionFilter = null;
    }
    this.renderPills();
    this.render();
  },

  // ── Data access ───────────────────────────────────────────────────────────

  all() { return (InstructorState.dashboard || {}).students || []; },
  find(id) { return this.all().find((s) => s.student_id === id); },

  displayName(s) { return (s.student_name || '').trim() || 'Unnamed Student'; },

  // Old getFilteredStudents semantics: "mine" means I watch OR I assigned.
  // /auth/me exposes the cybercore user_id as `id` (there is no `sub` field —
  // the old inline page compared undefined === undefined here).
  isMine(s) {
    const me = Auth.getUser()?.id;
    return (s.watching_instructors || []).some((w) => w.instructor_id === me)
        || (s.assignments || []).some((a) => a.instructor_id === me);
  },

  hasInstructor(s) {
    return (s.watching_instructors || []).some((w) => w.instructor_id)
        || (s.assignments || []).some((a) => a.instructor_id);
  },

  // ── Toolbar: section pills ────────────────────────────────────────────────

  renderPills() {
    const host = document.getElementById('studentSectionPills');
    if (!host) return;
    const { scope, sections } = InstructorState;
    const scopeActive = (s) => !this._sectionFilter && scope === s;
    const pills = [
      `<button type="button" class="filter-pill ${scopeActive('all') ? 'active' : ''}"
               onclick="Students.setScope('all')">All students</button>`,
      `<button type="button" class="filter-pill ${scopeActive('mine') ? 'active' : ''}"
               onclick="Students.setScope('mine')">My sections</button>`,
    ];
    // Per-section pills narrow CLIENT-side on student.sections — no refetch.
    sections.forEach((sec) => {
      const n = this.all().filter((s) => (s.sections || [])
        .some((x) => x.section_id === sec.section_id)).length;
      pills.push(`<button type="button" class="filter-pill ${this._sectionFilter === sec.section_id ? 'active' : ''}"
               onclick="Students.setSection('${esc(sec.section_id)}')">${esc(sec.code || sec.name)}<span class="pill-count">${n}</span></button>`);
    });
    host.innerHTML = pills.join('');
  },

  setScope(scope) {
    this._sectionFilter = null;
    InstructorState.refresh({ scope });
  },

  setSection(sectionId) {
    this._sectionFilter = this._sectionFilter === sectionId ? null : sectionId;
    this.renderPills();
    this.render();
  },

  // ── Toolbar: search / filter / sort ───────────────────────────────────────

  onSearchInput() {
    const input = document.getElementById('studentSearch');
    const clear = document.getElementById('studentSearchClear');
    if (clear) clear.hidden = !(input && input.value);
    this._debouncedApply = this._debouncedApply
      || Utils.debounce(() => this.applyFilters(), 250);
    this._debouncedApply();
  },

  clearSearch() {
    const input = document.getElementById('studentSearch');
    if (input) input.value = '';
    const clear = document.getElementById('studentSearchClear');
    if (clear) clear.hidden = true;
    this.applyFilters();
    if (input) input.focus();
  },

  clearFilters() {
    const input = document.getElementById('studentSearch');
    if (input) input.value = '';
    const clear = document.getElementById('studentSearchClear');
    if (clear) clear.hidden = true;
    const filter = document.getElementById('studentFilter');
    if (filter) filter.value = 'all';
    this._sectionFilter = null;
    this.renderPills();
    this.render();
  },

  applyFilters() { this.render(); },

  pipeline() {
    const q = (document.getElementById('studentSearch')?.value || '').trim().toLowerCase();
    const filter = document.getElementById('studentFilter')?.value || 'all';
    const sort = document.getElementById('studentSort')?.value || 'name';

    let rows = this.all().filter((s) => {
      if (q && !((s.student_name || '').toLowerCase().includes(q)
        || (s.first_name || '').toLowerCase().includes(q)
        || (s.last_name || '').toLowerCase().includes(q)
        || (s.student_email || '').toLowerCase().includes(q))) return false;

      if (this._sectionFilter
        && !(s.sections || []).some((x) => x.section_id === this._sectionFilter)) return false;

      switch (filter) {
        case 'mine': return this.isMine(s);
        case 'unassigned': return !this.hasInstructor(s);
        case 'has-profiles': return (s.generated_profiles || []).length > 0;
        case 'pending': return (parseInt(s.pending_reviews) || 0) > 0;
        case 'no-section': return !(s.sections || []).length;
        default: return true;
      }
    });

    rows = rows.slice();
    if (sort === 'pending') {
      rows.sort((a, b) => (parseInt(b.pending_reviews) || 0) - (parseInt(a.pending_reviews) || 0));
    } else if (sort === 'joined') {
      rows.sort((a, b) => new Date(b.student_joined || 0) - new Date(a.student_joined || 0));
    } else {
      rows.sort((a, b) => this.displayName(a).localeCompare(this.displayName(b)));
    }
    return rows;
  },

  // ── List rendering ────────────────────────────────────────────────────────

  renderLoading() {
    const container = document.getElementById('studentsList');
    if (container) {
      container.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(6);
    }
    const count = document.getElementById('studentCount');
    if (count) count.textContent = '';
  },

  renderError() {
    const container = document.getElementById('studentsList');
    if (!container) return;
    container.innerHTML = `
      <div class="empty-state">
        <div class="icon">⚠️</div>
        <h3>Couldn't load students</h3>
        <p>${esc(InstructorState.error?.message || 'Something went wrong.')}</p>
        <button class="btn btn-primary btn-sm" onclick="InstructorState.refresh()">Retry</button>
      </div>`;
    const count = document.getElementById('studentCount');
    if (count) count.textContent = '';
  },

  render() {
    const container = document.getElementById('studentsList');
    if (!container) return;

    this._visible = this.pipeline();
    this._chunk = CHUNK_SIZE;
    this._expandedId = null; // a full re-render drops any open detail panel

    const total = this.all().length;
    const count = document.getElementById('studentCount');
    if (count) count.textContent = `Showing ${this._visible.length} of ${total} students`;

    if (!total) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">👥</div>
          <h3>No students yet</h3>
          <p>Students appear here once they are enrolled on a section.<br>
             Use the Sections tab to add them.</p>
          <button class="btn btn-primary btn-sm" onclick="switchTab('sections')">Open Sections</button>
        </div>`;
      return;
    }
    if (!this._visible.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">🔍</div>
          <h3>No matches</h3>
          <p>No students match your search and filters.</p>
          <button class="btn btn-outline btn-sm" onclick="Students.clearFilters()">Clear search &amp; filters</button>
        </div>`;
      return;
    }

    container.innerHTML = this._visible.slice(0, this._chunk).map((s) => this.cardHtml(s)).join('')
      + this.chunkMoreHtml();
  },

  chunkMoreHtml() {
    const remaining = this._visible.length - this._chunk;
    if (remaining <= 0) return '';
    return `
      <div class="chunk-more">
        <button class="btn btn-outline" onclick="Students.showMore()">
          Show ${Math.min(CHUNK_SIZE, remaining)} more (${remaining} remaining)
        </button>
      </div>`;
  },

  // Appends the next chunk instead of re-rendering, so an expanded card in the
  // already-shown range keeps its detail panel.
  showMore() {
    const container = document.getElementById('studentsList');
    if (!container) return;
    const more = container.querySelector('.chunk-more');
    if (more) more.remove();
    const start = this._chunk;
    this._chunk += CHUNK_SIZE;
    container.insertAdjacentHTML('beforeend',
      this._visible.slice(start, this._chunk).map((s) => this.cardHtml(s)).join('')
      + this.chunkMoreHtml());
  },

  cardHtml(student) {
    const id = esc(student.student_id);
    const pending = parseInt(student.pending_reviews) || 0;
    const parts = parseInt(student.parts_started) || 0;
    const profiles = (student.generated_profiles || []).length;
    return `
      <div class="student-card" data-student-id="${id}">
        <div class="student-head" onclick="Students.toggle('${id}')">
          <div class="student-id">${this.identityHtml(student)}</div>
          <div class="student-metrics">
            <div class="student-metric">
              <div class="student-metric-value">${parts}/8</div>
              <div class="student-metric-label">Parts</div>
            </div>
            <div class="student-metric">
              <div class="student-metric-value ${pending > 0 ? 'attention' : ''}">${pending}</div>
              <div class="student-metric-label">Pending</div>
            </div>
            <div class="student-metric">
              <div class="student-metric-value">${profiles}</div>
              <div class="student-metric-label">Profiles</div>
            </div>
            <div class="student-chevron">▼</div>
          </div>
        </div>
        <div id="student-detail-${id}"></div>
      </div>`;
  },

  identityHtml(student) {
    const id = esc(student.student_id);
    const mine = this.isMine(student);
    const sections = student.sections || [];

    const badges = sections.length
      ? sections.map((s) => `<span class="badge badge-blue" title="${esc(s.name)}">${esc(s.code || s.name)}</span>`).join(' ')
      : '<span class="badge badge-gray">No section</span>';

    const claim = mine
      ? `<button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); Students.release('${id}')">Release</button>`
      : `<button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); Students.claim('${id}')">+ Claim</button>`;

    let enroll = '';
    if (!sections.length) {
      enroll = InstructorState.sections.length
        ? `<button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); Students.showEnrollModal('${id}')">+ Enroll</button>`
        : '<button class="btn btn-sm btn-outline" disabled title="Create a section first">+ Enroll</button>';
    }

    return `
      <h4>${esc(this.displayName(student))} ${mine ? '<span class="badge badge-blue">Yours</span>' : ''}</h4>
      <p>${esc(student.student_email)}${student.organization ? ` · ${esc(student.organization)}` : ''}</p>
      <div class="student-badges">${badges} ${claim} ${enroll}</div>`;
  },

  // Surgical repaint after claim/release/enroll — name badge + badges row only;
  // metrics and any open detail panel stay untouched.
  repaintIdentity(studentId) {
    const student = this.find(studentId);
    const card = document.querySelector(`.student-card[data-student-id="${studentId}"]`);
    if (!student || !card) return;
    const identity = card.querySelector('.student-id');
    if (identity) identity.innerHTML = this.identityHtml(student);
  },

  // ── Expansion + detail panel ──────────────────────────────────────────────
  // toggle() touches only the two cards involved — never the list.

  toggle(studentId) {
    if (this._expandedId === studentId) {
      this.collapse(studentId);
      this._expandedId = null;
      return;
    }
    if (this._expandedId) this.collapse(this._expandedId);
    this._expandedId = studentId;

    const card = document.querySelector(`.student-card[data-student-id="${studentId}"]`);
    const host = document.getElementById(`student-detail-${studentId}`);
    const student = this.find(studentId);
    if (!card || !host || !student) return;
    card.classList.add('expanded');
    host.innerHTML = this.detailHtml(student);
    const panel = host.querySelector('[data-subtab-panel="progress"]');
    if (panel) this.loadSubtab(studentId, 'progress', panel);
  },

  collapse(studentId) {
    const card = document.querySelector(`.student-card[data-student-id="${studentId}"]`);
    if (!card) return;
    card.classList.remove('expanded');
    const host = document.getElementById(`student-detail-${studentId}`);
    if (host) host.innerHTML = '';
  },

  detailHtml(student) {
    const id = esc(student.student_id);
    const tab = (name, label, active) => `
      <button class="detail-subtab ${active ? 'active' : ''}" data-subtab="${name}"
              onclick="event.stopPropagation(); Students.subtab('${id}', '${name}', this)">${label}</button>`;
    return `
      <div class="student-detail">
        <div style="display: flex; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 1rem;">
          <button class="btn btn-sm btn-primary" onclick="Students.showAssignModal('${id}')">Assign Profile</button>
          <button class="btn btn-sm btn-outline" onclick="Students.viewProgress('${id}')">Full Progress View</button>
        </div>
        <div class="detail-subtabs">
          ${tab('progress', 'Progress', true)}
          ${tab('documents', 'Documents', false)}
          ${tab('labs', 'Labs', false)}
        </div>
        <div data-subtab-panel="progress"></div>
        <div data-subtab-panel="documents" hidden></div>
        <div data-subtab-panel="labs" hidden></div>
      </div>`;
  },

  subtab(studentId, name, btn) {
    const card = btn.closest('.student-card');
    if (!card) return;
    card.querySelectorAll('.detail-subtab').forEach((b) => {
      b.classList.toggle('active', b.dataset.subtab === name);
    });
    card.querySelectorAll('[data-subtab-panel]').forEach((p) => {
      p.hidden = p.dataset.subtabPanel !== name;
    });
    const panel = card.querySelector(`[data-subtab-panel="${name}"]`);
    // Lazy: fetch once per expansion; flipping back is instant.
    if (panel && !panel.dataset.loaded) this.loadSubtab(studentId, name, panel);
  },

  loadSubtab(studentId, name, panel) {
    panel.dataset.loaded = '1';
    panel.innerHTML = '<div class="skeleton skel-line"></div><div class="skeleton skel-line"></div>';
    if (name === 'progress') this.loadProgress(studentId, panel);
    else if (name === 'documents') this.loadDocs(studentId, panel);
    else this.loadLabs(studentId, panel);
  },

  // Retry hook for the per-subtab error states.
  reloadSubtab(studentId, name) {
    const card = document.querySelector(`.student-card[data-student-id="${studentId}"]`);
    const panel = card && card.querySelector(`[data-subtab-panel="${name}"]`);
    if (panel) this.loadSubtab(studentId, name, panel);
  },

  // Progress subtab. The server groups progress per profile ({parts: {n:…}});
  // the old inline renderer assumed a flat list and matched nothing.
  async loadProgress(studentId, panel) {
    try {
      const data = await API.instructor.studentProgress(studentId);
      const byProfile = data.progress || [];
      if (!byProfile.length) {
        panel.innerHTML = '<p class="text-muted" style="font-size: 0.85rem;">No assessment progress yet.</p>';
        return;
      }
      panel.innerHTML = byProfile.map((pp) => `
        ${byProfile.length > 1 ? `<div style="font-weight: 600; font-size: 0.85rem; margin: 0.5rem 0;">🏢 ${esc(pp.profile_name || 'Unknown Profile')}</div>` : ''}
        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 0.75rem; margin-bottom: 0.75rem;">
          ${[1, 2, 3, 4, 5, 6, 7, 8].map((n) => {
            const part = (pp.parts || {})[n];
            return `
              <div style="padding: 0.6rem 0.75rem; border-radius: 8px; border: 1px solid var(--border-color);">
                <div style="font-weight: 600; font-size: 0.8rem;">Part ${n}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-bottom: 0.3rem;">${esc(PART_NAMES[n])}</div>
                ${statusPill(part?.status)}
                ${part?.score != null ? `<div style="font-size: 0.7rem; color: var(--text-muted); margin-top: 0.25rem;">Score: ${esc(part.score)}</div>` : ''}
              </div>`;
          }).join('')}
        </div>`).join('');
    } catch (e) {
      panel.innerHTML = `
        <p style="color: var(--danger); font-size: 0.85rem;">Error loading progress: ${esc(e.message)}</p>
        <button class="btn btn-sm btn-outline" onclick="Students.reloadSubtab('${esc(studentId)}', 'progress')">Retry</button>`;
    }
  },

  // Documents subtab — parallel loads, one render (the old loop fetched each
  // profile serially).
  async loadDocs(studentId, panel) {
    const student = this.find(studentId);
    const profiles = student?.generated_profiles || [];
    if (!profiles.length) {
      panel.innerHTML = '<p class="text-muted" style="font-size: 0.85rem;">No profiles generated — no documents available.</p>';
      return;
    }
    const sid = esc(studentId);
    const results = await Promise.all(profiles.map(async (profile) => {
      try {
        const docs = await API.request(`/instructor/documents/${profile.profile_id}`);
        return { profile, docs: Array.isArray(docs) ? docs : (docs.documents || []) };
      } catch (e) {
        return { profile, error: e };
      }
    }));

    panel.innerHTML = results.map(({ profile, docs, error }) => {
      const pid = esc(profile.profile_id);
      const name = esc(profile.company_name || 'Unnamed');
      if (error) {
        return `<div style="margin-bottom: 0.5rem; padding: 0.5rem; color: var(--text-muted); font-size: 0.8rem;">${name} — could not load documents</div>`;
      }
      return `
        <div style="margin-bottom: 1rem; padding: 0.75rem; background: var(--bg-card-hover); border-radius: 8px;">
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap; margin-bottom: 0.5rem;">
            <strong style="font-size: 0.85rem;">${name}</strong>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn btn-sm btn-outline" onclick="Students.generateDocsForProfile('${pid}', '${sid}')">Generate</button>
              <button class="btn btn-sm btn-outline" onclick="window.open('/api/profiles/${pid}/documents/print', '_blank')">Scans</button>
              <button class="btn btn-sm btn-outline" onclick="window.open('/api/profiles/${pid}/policies/print', '_blank')">Policies</button>
            </div>
          </div>
          <div style="display: flex; gap: 0.5rem; flex-wrap: wrap;">
            ${docs.length
              ? docs.map((d) => `<span class="badge badge-success">${esc((d.type || d.document_type || '').toUpperCase())}</span>`).join('')
              : '<span style="font-size: 0.75rem; color: var(--text-muted);">No documents generated yet</span>'}
          </div>
        </div>`;
    }).join('');
  },

  async generateDocsForProfile(profileId, studentId) {
    try {
      Toast.info('Generating', 'Sending document generation request…');
      await API.instructor.generateDocuments(profileId);
      Toast.success('Generated', 'Scan documents are ready for this profile');
      this.reloadSubtab(studentId, 'documents');
    } catch (e) {
      Toast.error('Generation failed', e.message);
    }
  },

  // Labs subtab.
  async loadLabs(studentId, panel) {
    try {
      const response = await API.request('/instructor/lanes');
      const lanes = (Array.isArray(response) ? response : response.lanes || [])
        .filter((l) => l.user_id === studentId);
      if (!lanes.length) {
        panel.innerHTML = '<p class="text-muted" style="font-size: 0.85rem;">No lab environment deployed for this student.</p>';
        return;
      }
      const badgeCls = {
        active: 'badge-success', deploying: 'badge-warning', error: 'badge-danger',
        suspended: 'badge-info', pending: 'badge-info',
      };
      panel.innerHTML = lanes.map((l) => {
        const lid = esc(l.lane_id);
        const inet = (l.config || {}).internet_enabled;
        return `
          <div style="padding: 0.75rem; background: var(--bg-card-hover); border-radius: 8px; margin-bottom: 0.5rem;">
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap;">
              <div>
                <span class="badge ${badgeCls[l.status] || 'badge-gray'}">${esc(l.status)}</span>
                <span style="font-size: 0.8rem; margin-left: 0.5rem;">VXLAN ${esc(l.vxlan_id || '—')}</span>
              </div>
              <div style="display: flex; gap: 0.4rem; align-items: center;">
                ${l.status === 'active' ? `
                  <label style="display: flex; align-items: center; gap: 0.2rem; font-size: 0.75rem; cursor: pointer;">
                    <input type="checkbox" ${inet ? 'checked' : ''} style="width: auto;"
                           onchange="event.stopPropagation(); Students.toggleLaneInternet('${lid}', this.checked, this)">
                    Internet
                  </label>
                  <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); Students.connectToLane('${lid}')">Connect</button>
                ` : ''}
                <button class="btn btn-sm btn-outline" onclick="event.stopPropagation(); Students.fetchLaneIPs('${lid}')">IPs</button>
              </div>
            </div>
            <div id="inline-ips-${lid}" style="margin-top: 0.25rem;"></div>
          </div>`;
      }).join('');
    } catch (e) {
      panel.innerHTML = `
        <p style="color: var(--danger); font-size: 0.85rem;">Error loading labs: ${esc(e.message)}</p>
        <button class="btn btn-sm btn-outline" onclick="Students.reloadSubtab('${esc(studentId)}', 'labs')">Retry</button>`;
    }
  },

  async fetchLaneIPs(laneId) {
    const host = document.getElementById(`inline-ips-${laneId}`);
    if (!host) return;
    host.innerHTML = '<span style="font-size: 0.75rem; color: var(--text-muted);">Loading IPs…</span>';
    try {
      const data = await API.request(`/instructor/lanes/${laneId}/ips`);
      const entries = Object.entries(data.ips || {}).filter(([, v]) => v);
      host.innerHTML = entries.length
        ? entries.map(([k, v]) => `<span style="font-size: 0.75rem; margin-right: 0.75rem;"><strong>${esc(k)}:</strong> <code>${esc(v)}</code></span>`).join('')
        : '<span style="font-size: 0.75rem; color: var(--text-muted);">No IPs found</span>';
    } catch (e) {
      host.innerHTML = '<span style="font-size: 0.75rem; color: var(--danger);">Failed to load IPs</span>';
    }
  },

  async connectToLane(laneId) {
    try {
      const data = await API.request(`/instructor/lanes/${laneId}/connect`);
      if (data.guac_url) window.open(data.guac_url, '_blank');
      else Toast.warning('No Connection', 'Could not find a Guacamole connection for this lane');
    } catch (e) {
      Toast.error('Could not connect', e.message);
    }
  },

  async toggleLaneInternet(laneId, enabled, checkbox) {
    try {
      await API.request(`/instructor/lanes/${laneId}/internet`, { method: 'PATCH', body: { enabled } });
      Toast.success(`Internet ${enabled ? 'Enabled' : 'Disabled'}`, 'Lane updated');
    } catch (e) {
      Toast.error('Could not update the lane', e.message);
      if (checkbox) checkbox.checked = !enabled; // put it back where it was
    }
  },

  // ── Claim / release ───────────────────────────────────────────────────────
  // Mutate the shared payload in place and repaint ONE card — a claim must not
  // rebuild 200+ siblings.

  async claim(studentId) {
    const student = this.find(studentId);
    try {
      await API.request('/instructor/claim-student', { method: 'POST', body: { student_id: studentId } });
      if (student) {
        const me = Auth.getUser() || {};
        student.watching_instructors = student.watching_instructors || [];
        student.watching_instructors.push({
          instructor_id: me.id,
          instructor_name: `${me.firstName || me.first_name || ''} ${me.lastName || me.last_name || ''}`.trim(),
          instructor_email: me.email,
        });
      }
      Toast.success('Claimed', `${student ? this.displayName(student) : 'Student'} is on your roster now`);
      this.repaintIdentity(studentId);
    } catch (e) {
      Toast.error('Could not claim', e.message);
    }
  },

  async release(studentId) {
    const student = this.find(studentId);
    if (!await Confirm.show({
      title: `Release ${student ? this.displayName(student) : 'this student'}?`,
      message: 'They come off your roster. Their work and any feedback are kept.',
      confirmText: 'Release',
      danger: true,
    })) return;
    try {
      await API.request(`/instructor/release-student/${studentId}`, { method: 'DELETE' });
      if (student) {
        const me = Auth.getUser()?.id;
        student.watching_instructors = (student.watching_instructors || [])
          .filter((w) => w.instructor_id !== me);
      }
      Toast.success('Released', `${student ? this.displayName(student) : 'Student'} removed from your roster`);
      this.repaintIdentity(studentId);
    } catch (e) {
      Toast.error('Could not release', e.message);
    }
  },

  // ── Enroll on one of my sections ──────────────────────────────────────────

  showEnrollModal(studentId) {
    const student = this.find(studentId);
    if (!student) { Toast.error('Error', 'Student not found'); return; }
    const sections = InstructorState.sections;
    if (!sections.length) {
      Toast.warning('No sections yet', 'Create a section first — the Sections tab has the button');
      return;
    }
    const container = document.getElementById('enrollStudentModalContent');
    container.innerHTML = `
      <div style="margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);">
        <p style="margin: 0;"><strong>${esc(this.displayName(student))}</strong></p>
        <p style="margin: 0.25rem 0 0; color: var(--text-muted);">${esc(student.student_email)}</p>
      </div>
      <form onsubmit="Students.submitEnroll(event, '${esc(studentId)}')">
        <div class="form-group">
          <label for="enrollSectionSelect">Section</label>
          <select id="enrollSectionSelect" class="form-input" required>
            ${sections.map((s) => {
              const bits = [s.name];
              if (s.code) bits.push(`(${s.code})`);
              if (s.term) bits.push(`— ${s.term}`);
              return `<option value="${esc(s.section_id)}">${esc(bits.join(' '))}</option>`;
            }).join('')}
          </select>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 1.5rem;">
          <button type="button" class="btn btn-outline" onclick="closeModal('enrollStudentModal')">Cancel</button>
          <button type="submit" class="btn btn-primary" id="enrollStudentSubmitBtn">Enroll</button>
        </div>
      </form>`;
    openModal('enrollStudentModal');
  },

  async submitEnroll(event, studentId) {
    event.preventDefault();
    const sectionId = document.getElementById('enrollSectionSelect').value;
    if (!sectionId) return;
    const btn = document.getElementById('enrollStudentSubmitBtn');
    Utils.setBtnLoading(btn, true);
    try {
      // Same payload as Sections.addStudent — one server contract, two doors.
      await API.request(`/instructor/sections/${sectionId}/students`, {
        method: 'POST', body: { user_id: studentId },
      });
      const s = InstructorState.sections.find((x) => x.section_id === sectionId);
      Toast.success('Enrolled', `Added to ${s ? s.name : 'the section'} — they can open Clinic-in-a-Box now`);
      closeModal('enrollStudentModal');
      await InstructorState.refresh();
    } catch (err) {
      Toast.error('Could not enroll', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // ── Assign a profile ──────────────────────────────────────────────────────

  showAssignModal(studentId) {
    const student = this.find(studentId);
    if (!student) { Toast.error('Error', 'Student not found'); return; }
    const own = student.generated_profiles || [];
    const container = document.getElementById('assignProfileModalContent');

    // Prefer the student's own generated profiles; fall back to the
    // instructor's profile library (InstructorState.profiles) when they have
    // none — the old page's allProfiles, now with display_name labels.
    const options = own.length
      ? own.map((p) => `<option value="${esc(p.profile_id)}">🏢 ${esc(p.company_name || 'Unnamed')} (${esc(p.industry || 'Unknown industry')}, ${esc(p.difficulty || 'Standard')})</option>`).join('')
      : InstructorState.profiles.map((p) => `<option value="${esc(p.id)}">${esc(p.display_name)}</option>`).join('');

    container.innerHTML = `
      <div style="margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);">
        <p style="margin: 0;"><strong>${esc(this.displayName(student))}</strong></p>
        <p style="margin: 0.25rem 0 0; color: var(--text-muted);">📧 ${esc(student.student_email)}</p>
      </div>
      <form onsubmit="Students.submitAssign(event, '${esc(studentId)}')">
        <div class="form-group">
          <label for="assignProfileSelect">${own.length ? "Student's generated profiles" : 'Select from your profiles'}</label>
          ${own.length ? '' : `
            <div class="info-box" style="margin-bottom: 0.75rem;">
              This student hasn't generated any profiles yet — assigning one of yours.
            </div>`}
          <select id="assignProfileSelect" class="form-input" required>
            <option value="">-- Select a profile --</option>
            ${options}
          </select>
        </div>
        <div class="form-group">
          <label for="assignDueDate">Due date (optional)</label>
          <input type="date" id="assignDueDate" class="form-input">
        </div>
        <div class="form-group">
          <label for="assignNotes">Notes (optional)</label>
          <textarea id="assignNotes" class="form-input" rows="2" placeholder="Any special instructions…"></textarea>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 1.5rem;">
          <button type="button" class="btn btn-outline" onclick="closeModal('assignProfileModal')">Cancel</button>
          <button type="submit" class="btn btn-primary" id="assignProfileSubmitBtn">Assign Profile</button>
        </div>
      </form>`;
    openModal('assignProfileModal');
  },

  async submitAssign(event, studentId) {
    event.preventDefault();
    const profileId = document.getElementById('assignProfileSelect').value;
    if (!profileId) { Toast.error('No profile selected', 'Pick a profile to assign'); return; }
    const btn = document.getElementById('assignProfileSubmitBtn');
    Utils.setBtnLoading(btn, true);
    try {
      await API.instructor.assign({
        student_id: studentId,
        profile_id: profileId,
        due_date: document.getElementById('assignDueDate').value || null,
        notes: document.getElementById('assignNotes').value || null,
      });
      const student = this.find(studentId);
      Toast.success('Profile Assigned', `${student ? this.displayName(student) : 'The student'} can start working on it now`);
      closeModal('assignProfileModal');
      await InstructorState.refresh();
    } catch (error) {
      Toast.error('Could not assign the profile', error.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // ── Full progress modal ───────────────────────────────────────────────────

  async viewProgress(studentId) {
    const container = document.getElementById('viewProgressModalContent');
    container.innerHTML = `
      <div class="empty-state" style="padding: 2rem;">
        <div class="icon">⏳</div>
        <h3>Loading student progress…</h3>
      </div>`;
    openModal('viewProgressModal');

    try {
      const response = await API.instructor.studentProgress(studentId);
      if (response.success === false) throw new Error(response.error || 'Failed to load progress');
      const { student, profiles = [], progress = [], intake_responses: intakes = [] } = response;
      const studentName = student.name || 'Unnamed Student';

      // Generate documents / Answer key live in the Docs module; guard so this
      // tab still works if that module failed to load.
      const profileActions = (pid, pname) => pid ? `
        <span style="display: inline-flex; gap: 0.35rem; margin-left: 0.5rem;">
          <button class="btn btn-sm btn-outline" onclick="window.Docs && Docs.showGenerateDocsModal('${esc(pid)}')">Generate documents</button>
          <button class="btn btn-sm btn-outline" onclick="window.Docs && Docs.openAnswerKeyForProfile('${esc(pid)}', '${escJs(pname || '')}')">Answer key</button>
        </span>` : '';

      let html = `
        <div style="margin-bottom: 1.5rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);">
          <h4 style="margin: 0 0 0.5rem;">${esc(studentName)}</h4>
          <p style="margin: 0; color: var(--text-muted);">📧 ${esc(student.email)}</p>
          ${student.organization ? `<p style="margin: 0.25rem 0 0; color: var(--text-muted);">🏛️ ${esc(student.organization)}</p>` : ''}
          <p style="margin: 0.25rem 0 0; font-size: 0.85rem; color: var(--text-muted);">Joined: ${esc(Utils.formatDate(student.joined))}</p>
        </div>

        <div style="margin-bottom: 1.5rem;">
          <h5 style="margin: 0 0 0.75rem;">📁 Generated Profiles (${profiles.length})</h5>
          ${profiles.length ? profiles.map((p) => `
            <div style="display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; flex-wrap: wrap; padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 8px; margin-bottom: 0.5rem; font-size: 0.85rem;">
              <span>🏢 ${esc(p.company_name || 'Unnamed')}
                <span style="color: var(--text-muted);">(${esc(p.industry || 'Unknown')}, ${esc(p.difficulty || 'Standard')})</span>
              </span>
              ${profileActions(p.id || p.profile_id, p.company_name)}
            </div>`).join('')
          : '<p style="color: var(--text-muted); margin: 0;">No profiles generated yet.</p>'}
        </div>

        <div style="margin-bottom: 1rem;">
          <h5 style="margin: 0 0 0.75rem;">📊 Assessment Progress</h5>`;

      if (!progress.length) {
        html += '<p style="color: var(--text-muted); margin: 0;">No assessment progress yet.</p>';
      } else {
        for (const pp of progress) {
          const parts = pp.parts || {};
          const reviewed = Object.values(parts).filter((p) => p.status === 'reviewed').length;
          const submitted = Object.values(parts).filter((p) => p.status === 'submitted').length;
          html += `
            <div style="background: var(--bg-card-hover); border-radius: 8px; padding: 1rem; margin-bottom: 1rem;">
              <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem;">
                <strong>🏢 ${esc(pp.profile_name || 'Unknown Profile')}</strong>
                <span style="font-size: 0.85rem; color: var(--text-muted);">${reviewed}/8 reviewed</span>
              </div>
              <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.5rem;">
                ${[1, 2, 3, 4, 5, 6, 7, 8].map((n) => {
                  const part = parts[n];
                  return `
                    <div style="padding: 0.5rem; background: var(--bg-card); border-radius: 6px; border: 1px solid var(--border-color); font-size: 0.8rem;">
                      <div style="font-weight: 500; margin-bottom: 0.25rem;" title="${esc(PART_NAMES[n])}">Part ${n}</div>
                      ${statusPill(part?.status)}
                      ${part?.score != null ? `<div style="margin-top: 0.25rem; font-size: 0.75rem; color: var(--text-muted);">Score: ${esc(part.score)}</div>` : ''}
                    </div>`;
                }).join('')}
              </div>
              ${submitted > 0 ? `
                <div style="margin-top: 0.75rem; text-align: right;">
                  <button class="btn btn-sm btn-primary" onclick="closeModal('viewProgressModal'); switchTab('reviews')">
                    Review Submissions (${submitted})
                  </button>
                </div>` : ''}
            </div>`;
        }
      }
      html += '</div>';

      if (intakes.length) {
        html += `
          <div style="margin-bottom: 1rem;">
            <h5 style="margin: 0 0 0.75rem;">📝 Intake Forms</h5>
            ${intakes.map((ir) => `
              <div style="padding: 0.75rem; background: var(--bg-card-hover); border-radius: 8px; margin-bottom: 0.5rem; display: flex; justify-content: space-between; align-items: center;">
                <span>🏢 ${esc(ir.profile_name || 'Unknown Profile')}</span>
                ${ir.status === 'complete'
                  ? '<span class="status-pill reviewed">✓ Complete</span>'
                  : `<span class="status-pill in-progress">In Progress (${parseInt(ir.completion_percentage) || 0}%)</span>`}
              </div>`).join('')}
          </div>`;
      }

      html += `
        <div style="display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem; padding-top: 1rem; border-top: 1px solid var(--border-color);">
          <button class="btn btn-outline" onclick="closeModal('viewProgressModal')">Close</button>
        </div>`;

      container.innerHTML = html;
    } catch (error) {
      console.error('Failed to load student progress:', error);
      container.innerHTML = `
        <div class="empty-state" style="padding: 2rem;">
          <div class="icon">⚠️</div>
          <h3>Failed to load progress</h3>
          <p>${esc(error.message)}</p>
          <button class="btn btn-outline btn-sm" onclick="closeModal('viewProgressModal')">Close</button>
        </div>`;
    }
  },
};

window.Students = Students;
