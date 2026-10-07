/**
 * instructor-reviews.js — Review Queue tab: queue, review modal, submission
 * viewer.
 * ============================================================================
 * Pure view over InstructorState for the queue itself; the only fetches here
 * are the per-profile rubric and the review POST. The server sends
 * pending_submissions OLDEST-FIRST, capped at 50, with pending_total as the
 * true count — the cap note below exists because of that LIMIT.
 *
 * Loaded after instructor-core.js; depends on its globals (InstructorState,
 * esc, PART_NAMES, partLabel, timeAgo, isOverdue, openModal, closeModal) and
 * the kit (API, Toast, Utils).
 *
 * Bulk actions are deferred — no server endpoint yet. When one lands, the
 * checkbox column goes in a 24px gutter at the left edge of .review-card.
 */
/* global API, Toast, Utils, InstructorState, esc, PART_NAMES, partLabel,
   timeAgo, isOverdue, openModal, closeModal */

const Reviews = {
  _inited: false,
  _search: '',
  _part: null,        // single-select part filter, or null
  _searchTimer: null,
  _scoreEdited: false, // instructor typed their own overall score this modal

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
  },

  // ── Data pipeline ─────────────────────────────────────────────────────────

  queue() {
    return InstructorState.dashboard?.pending_submissions || [];
  },

  pendingTotal() {
    const d = InstructorState.dashboard || {};
    return d.pending_total ?? this.queue().length;
  },

  filtered() {
    const q = this._search.trim().toLowerCase();
    return this.queue().filter((s) => {
      if (this._part !== null && Number(s.part_number) !== this._part) return false;
      if (!q) return true;
      return [s.student_name, s.student_email, s.profile_name]
        .some((f) => (f || '').toLowerCase().includes(q));
    });
  },

  onSearchInput() {
    clearTimeout(this._searchTimer);
    this._searchTimer = setTimeout(() => {
      this._search = document.getElementById('reviewSearch')?.value || '';
      this.render();
    }, 250);
  },

  togglePart(n) {
    this._part = this._part === n ? null : n;
    this.render();
  },

  clearFilters() {
    this._search = '';
    this._part = null;
    const input = document.getElementById('reviewSearch');
    if (input) input.value = '';
    this.render();
  },

  // ── Render states ─────────────────────────────────────────────────────────

  renderLoading() {
    const host = document.getElementById('reviewQueue');
    if (host) {
      host.innerHTML = `
        <div class="skeleton skel-row"></div>
        <div class="skeleton skel-row"></div>
        <div class="skeleton skel-row"></div>`;
    }
    const count = document.getElementById('reviewCount');
    if (count) count.textContent = '';
    const pills = document.getElementById('reviewPartPills');
    if (pills) pills.innerHTML = '';
    const note = document.getElementById('reviewCapNote');
    if (note) note.innerHTML = '';
  },

  renderError() {
    const host = document.getElementById('reviewQueue');
    if (host) {
      host.innerHTML = `
        <div class="empty-state">
          <div class="icon">⚠️</div>
          <h3>Couldn't load the review queue</h3>
          <p>${esc(InstructorState.error?.message || 'Something went wrong.')}</p>
          <button class="btn btn-primary btn-sm" onclick="InstructorState.refresh()">Retry</button>
        </div>`;
    }
    const count = document.getElementById('reviewCount');
    if (count) count.textContent = '';
  },

  render() {
    const host = document.getElementById('reviewQueue');
    if (!host) return;
    // Markup handlers (search, mode select) can fire before data is ready.
    if (InstructorState.status === 'error') { this.renderError(); return; }
    if (InstructorState.status !== 'ready') { this.renderLoading(); return; }

    const all = this.queue();
    // A part filter whose last item was just graded away is stale — drop it.
    if (this._part !== null && !all.some((s) => Number(s.part_number) === this._part)) {
      this._part = null;
    }
    const rows = this.filtered();

    this.renderPills(all);
    this.renderCapNote(all.length);
    const count = document.getElementById('reviewCount');
    if (count) count.textContent = `Showing ${rows.length} of ${this.pendingTotal()} pending`;

    if (!all.length) {
      host.innerHTML = `
        <div class="empty-state">
          <div class="icon">✅</div>
          <h3>All caught up!</h3>
          <p>No pending submissions to review.</p>
        </div>`;
      return;
    }
    if (!rows.length) {
      host.innerHTML = `
        <div class="empty-state">
          <div class="icon">🔍</div>
          <h3>No submissions match</h3>
          <p><a href="#reviews" onclick="Reviews.clearFilters(); return false;">Clear filters</a>
             to see the whole queue.</p>
        </div>`;
      return;
    }

    const mode = document.getElementById('reviewGroupMode')?.value || 'student';
    host.innerHTML = mode === 'flat'
      ? rows.map((s) => this.card(s, false)).join('') // server order = oldest first
      : this.grouped(rows);
  },

  renderPills(all) {
    const host = document.getElementById('reviewPartPills');
    if (!host) return;
    const counts = {};
    all.forEach((s) => {
      const n = Number(s.part_number);
      counts[n] = (counts[n] || 0) + 1;
    });
    host.innerHTML = Object.keys(counts).map(Number).sort((a, b) => a - b)
      .map((n) => `
        <button type="button" class="filter-pill ${this._part === n ? 'active' : ''}"
                title="${esc(PART_NAMES[n] || `Part ${n}`)}" onclick="Reviews.togglePart(${n})">
          P${n} <span class="pill-count">${counts[n]}</span>
        </button>`).join('');
  },

  renderCapNote(listLen) {
    const note = document.getElementById('reviewCapNote');
    if (!note) return;
    // Under section scoping the server filters AFTER its LIMIT 50, so the
    // visible list can be shorter than 50 while the true total is larger —
    // say the real count, not a hardcoded "50".
    note.innerHTML = this.pendingTotal() > listLen
      ? `<div class="info-box" style="margin-bottom: 1rem;">
           Showing the ${listLen} longest-waiting submissions — grade some to pull in more.
         </div>`
      : '';
  },

  // Grouped mode: rows arrive oldest-first, so Map insertion order already
  // ranks groups by their oldest submission.
  grouped(rows) {
    const groups = new Map();
    rows.forEach((s) => {
      const key = s.user_id || s.student_email;
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(s);
    });
    let html = '';
    groups.forEach((items) => {
      const name = items[0].student_name?.trim() || items[0].student_email;
      html += `
        <div class="review-group">
          <div class="review-group-head">${esc(name)} · ${items.length} submission${items.length === 1 ? '' : 's'}</div>
          ${items.map((s) => this.card(s, true)).join('')}
        </div>`;
    });
    return html;
  },

  card(sub, compact) {
    const when = sub.submitted_at || sub.updated_at;
    const id = esc(sub.id);
    const chips = `
      <span class="badge badge-primary">${esc(partLabel(Number(sub.part_number)))}</span>
      ${sub.profile_name ? `<span class="badge badge-info">${esc(sub.profile_name)}</span>` : ''}`;
    const age = `<span class="age-chip ${isOverdue(when) ? 'overdue' : ''}">${esc(timeAgo(when))}</span>`;
    const actions = `
      <div class="review-card-actions">
        <button class="btn btn-sm btn-primary" onclick="Reviews.openReview('${id}')">📝 Review</button>
        <button class="btn btn-sm btn-outline" onclick="Reviews.viewSubmission('${id}')">👁️ View</button>
      </div>`;

    if (compact) {
      // Grouped mode: the student's name lives on the group head, not the card.
      return `
        <div class="review-card compact">
          <div class="review-card-head">
            <div class="review-card-chips" style="margin-bottom: 0;">${chips}</div>
            ${age}
          </div>
          ${actions}
        </div>`;
    }
    return `
      <div class="review-card">
        <div class="review-card-head">
          <span class="review-card-student">${esc(sub.student_name?.trim() || sub.student_email)}</span>
          ${age}
        </div>
        <div class="review-card-chips">${chips}</div>
        ${actions}
      </div>`;
  },

  // ── Review modal ──────────────────────────────────────────────────────────

  async openReview(progressId) {
    const sub = this.queue().find((s) => s.id === progressId);
    if (!sub) {
      Toast.error('Submission not found', 'It may have just been graded — the queue will refresh.');
      return;
    }
    const partNumber = Number(sub.part_number);

    let rubric = {};
    try {
      const rubricResponse = await API.instructor.rubric(sub.profile_id);
      rubric = rubricResponse.rubric || {};
    } catch (e) {
      // No stored rubric for this profile — the generic default below covers it.
    }

    // Stored keys look like 'part2_scoping' — prefix-match on the part number.
    // (The old page looked up the literal key `part${n}_*`, which never matched,
    // so every review silently used the generic default.)
    const entry = Object.entries(rubric).find(([k]) => k.startsWith('part' + partNumber + '_'));
    const partRubric = entry?.[1]?.criteria ? entry[1] : this.getDefaultPartRubric(partNumber);
    const criteria = partRubric.criteria || [];
    const maxTotal = criteria.reduce((acc, c) => acc + (parseInt(c.points) || 0), 0) || 100;

    this._scoreEdited = false;

    document.getElementById('reviewModalContent').innerHTML = `
      <div style="margin-bottom: 1.5rem;">
        <p><strong>Student:</strong> ${esc(sub.student_name?.trim() || sub.student_email)}</p>
        <p><strong>Part:</strong> ${esc(partLabel(partNumber))}</p>
        <p><strong>Profile:</strong> ${esc(sub.profile_name || 'Unknown')}</p>
        <p><strong>Submitted:</strong> ${esc(Utils.formatDateTime(sub.submitted_at || sub.updated_at))}</p>
      </div>

      <div class="rubric-section">
        <h4>Rubric Scoring</h4>
        ${criteria.length ? criteria.map((c, i) => `
          <div class="rubric-item">
            <label for="rubric_${i}">${esc(c.item)}</label>
            <input type="number" id="rubric_${i}" min="0" max="${parseInt(c.points) || 0}"
                   value="0" oninput="Reviews.onRubricInput()">
            <span class="max-points">/ ${parseInt(c.points) || 0}</span>
          </div>`).join('') : '<p>No rubric available</p>'}
        <div class="rubric-total">Suggested: <strong id="rubricSuggested">0</strong> / ${maxTotal}</div>
      </div>

      <div class="form-group">
        <label for="reviewFeedback">Feedback</label>
        <textarea id="reviewFeedback" class="form-input" rows="5"
                  placeholder="Provide constructive feedback..."></textarea>
      </div>

      <div class="form-group">
        <label for="overallScore">Overall Score (0-100)</label>
        <input type="number" id="overallScore" class="form-input" min="0" max="100"
               value="0" oninput="Reviews.onScoreEdited()">
      </div>

      <div style="display: flex; gap: 0.75rem; justify-content: flex-end; margin-top: 1.5rem; flex-wrap: wrap;">
        <button class="btn btn-outline" onclick="closeModal('reviewModal')">Cancel</button>
        <!-- No .btn-warning in the kit: outline + warning tokens reads as
             corrective without btn-danger's destructive red. -->
        <button class="btn btn-outline" style="color: var(--warning); border-color: var(--warning);"
                onclick="Reviews.submit(this, '${esc(sub.id)}', 'revision_requested')">Request Revision</button>
        <button class="btn btn-success"
                onclick="Reviews.submit(this, '${esc(sub.id)}', 'reviewed')">✓ Approve</button>
      </div>`;

    openModal('reviewModal');
  },

  // Parts 1 and 8 have no profile-specific rubric by design — they always land here.
  getDefaultPartRubric() {
    return {
      criteria: [
        { item: 'Completeness', points: 25 },
        { item: 'Accuracy', points: 25 },
        { item: 'Analysis Quality', points: 25 },
        { item: 'Professional Presentation', points: 25 },
      ],
    };
  },

  onRubricInput() {
    let sum = 0;
    let max = 0;
    document.querySelectorAll('#reviewModalContent [id^="rubric_"]').forEach((input) => {
      sum += parseInt(input.value) || 0;
      max += parseInt(input.max) || 0;
    });
    const suggested = document.getElementById('rubricSuggested');
    if (suggested) suggested.textContent = sum;
    // Pre-fill, never fight: once the instructor types their own overall score
    // (oninput on that field flips _scoreEdited) we stop touching it.
    // Stored rubrics weight parts within a 100-point course (part 3 sums to
    // 20, part 2 to 15…) while this field is 0-100 — scale, never just clamp,
    // or a perfect part-3 submission would prefill as 20/100.
    if (!this._scoreEdited) {
      const overall = document.getElementById('overallScore');
      if (overall) {
        overall.value = max > 0
          ? Math.min(100, Math.round((sum / max) * 100))
          : Math.min(100, sum);
      }
    }
  },

  onScoreEdited() {
    this._scoreEdited = true;
  },

  async submit(btn, progressId, status) {
    const sub = this.queue().find((s) => s.id === progressId);
    const student = sub ? (sub.student_name?.trim() || sub.student_email) : 'the student';
    const feedback = document.getElementById('reviewFeedback')?.value || '';
    const score = parseInt(document.getElementById('overallScore')?.value) || 0;

    const rubricScores = {};
    document.querySelectorAll('#reviewModalContent [id^="rubric_"]').forEach((input) => {
      const idx = input.id.split('_')[1];
      rubricScores[`criterion_${idx}`] = parseInt(input.value) || 0;
    });

    Utils.setBtnLoading(btn, true);
    try {
      await API.instructor.review(progressId, {
        feedback,
        score,
        rubric_scores: rubricScores,
        status,
      });
      if (status === 'reviewed') {
        Toast.success('Approved', `${student}'s submission is marked reviewed`);
      } else {
        Toast.success('Revision requested', `${student} will see your feedback and can resubmit`);
      }
      closeModal('reviewModal');
      InstructorState.refresh();
    } catch (error) {
      Toast.error('Could not submit the review', error.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // ── Submission viewer ─────────────────────────────────────────────────────

  viewSubmission(progressId) {
    const submission = this.queue().find((s) => s.id === progressId);
    if (!submission) {
      Toast.error('Submission not found', 'It may have just been graded — the queue will refresh.');
      return;
    }
    const student = submission.student_name?.trim() || submission.student_email;
    const id = esc(submission.id);

    // textContent, not innerHTML — the title carries a student-supplied name.
    document.getElementById('viewSubmissionModalTitle').textContent =
      `📄 ${student} — ${partLabel(Number(submission.part_number))}`;

    document.getElementById('viewSubmissionModalContent').innerHTML = `
      <div style="margin-bottom: 1rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border-color);">
        <p style="margin: 0;"><strong>Student:</strong> ${esc(student)}</p>
        <p style="margin: 0.25rem 0;"><strong>Profile:</strong> ${esc(submission.profile_name || 'Unknown')}</p>
        <p style="margin: 0;"><strong>Submitted:</strong> ${esc(Utils.formatDateTime(submission.submitted_at || submission.updated_at))}</p>
      </div>
      <div style="background: var(--bg-card-hover); padding: 1rem; border-radius: 8px; max-height: 400px; overflow-y: auto;">
        <pre style="white-space: pre-wrap; word-wrap: break-word; margin: 0; font-family: inherit; font-size: 0.9rem;">${esc(submission.content || 'No content available')}</pre>
      </div>
      <div style="display: flex; gap: 0.75rem; justify-content: flex-end; padding-top: 1rem; margin-top: 1rem; border-top: 1px solid var(--border-color);">
        <button class="btn btn-outline" onclick="closeModal('viewSubmissionModal')">Close</button>
        <button class="btn btn-primary"
                onclick="closeModal('viewSubmissionModal'); Reviews.openReview('${id}')">📝 Review This Submission</button>
      </div>`;

    openModal('viewSubmissionModal');
  },
};

window.Reviews = Reviews;
