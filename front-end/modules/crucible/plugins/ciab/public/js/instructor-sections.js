/**
 * CIAB — Sections tab controller
 * ----------------------------------------------------------------------------
 * Section CRUD, the roster table, and the single-add path.
 *
 * LOADED AFTER instructor.html's inline <script>, deliberately. It depends on
 * globals that block defines -- Toast, closeModal(), escapeHtml(), switchTab()
 * -- exactly the way cle/public/js/roster-import.js depends on globals in
 * courses.html. Moving either <script> tag above the inline block breaks both.
 *
 * WHY A SEPARATE FILE AT ALL
 *   instructor.html already carries ~2,900 lines of inline JS. Adding another
 *   600 to it would be worse than the split, and extracting the EXISTING 2,900
 *   is a distinct, untested refactor with no bearing on this feature.
 *
 * NOTHING HERE DECIDES ACCESS. Every per-row control is rendered from a
 * server-computed flag (can_regenerate), never inferred, so the UI cannot offer
 * a button the API will refuse.
 */
/* global Toast, Confirm, closeModal, escapeHtml, switchTab */

const Sections = {
  all: [],
  currentId: null,
  roster: [],
  available: [],

  api(path, options = {}) {
    return API.request(`/instructor/sections${path}`, options);
  },

  // -------------------------------------------------------------------------
  // Load
  // -------------------------------------------------------------------------

  async load() {
    try {
      const { sections } = await this.api('');
      this.all = sections || [];
    } catch (err) {
      Toast.error('Could not load sections', err.message);
      this.all = [];
    }

    const empty = document.getElementById('sectionsEmpty');
    const main = document.getElementById('sectionsMain');
    if (!this.all.length) {
      if (empty) empty.style.display = '';
      if (main) main.style.display = 'none';
      return;
    }
    if (empty) empty.style.display = 'none';
    if (main) main.style.display = '';

    const select = document.getElementById('sectionSelect');
    select.innerHTML = this.all.map((s) => {
      const bits = [s.name];
      if (s.code) bits.push(`(${s.code})`);
      if (s.term) bits.push(`— ${s.term}`);
      if (s.status === 'archived') bits.push('· ARCHIVED');
      return `<option value="${escapeHtml(s.section_id)}">${escapeHtml(bits.join(' '))} · ${s.active_count} enrolled</option>`;
    }).join('');

    // Keep the instructor where they were across a reload, so archiving or
    // importing does not bounce them back to the first section in the list.
    if (this.currentId && this.all.some((s) => s.section_id === this.currentId)) {
      select.value = this.currentId;
    } else {
      this.currentId = this.all[0].section_id;
    }
    await this.onSectionChange();
  },

  current() {
    return this.all.find((s) => s.section_id === this.currentId) || null;
  },

  async onSectionChange() {
    const select = document.getElementById('sectionSelect');
    if (select && select.value) this.currentId = select.value;

    const s = this.current();
    const meta = document.getElementById('sectionMeta');
    if (meta && s) {
      const bits = [];
      if (s.max_students) bits.push(`${s.active_count} of ${s.max_students} seats used`);
      else bits.push(`${s.active_count} enrolled`);
      if (s.dropped_count) bits.push(`${s.dropped_count} dropped`);
      if (s.status === 'archived') {
        // Not a cosmetic badge: the gate joins ciab_section, so an archived
        // section's students lose Clinic-in-a-Box entirely.
        bits.push('archived — its students have no Clinic-in-a-Box access');
      }
      if (s.source && s.source.startsWith('backfill')) {
        bits.push('created automatically when enrollment was introduced — worth checking');
      }
      meta.textContent = bits.join(' · ');
    }
    await this.loadRoster();
  },
};

// ---------------------------------------------------------------------------
// Section create / edit / archive
// ---------------------------------------------------------------------------

Sections.showSectionModal = function showSectionModal(sectionId) {
  const editing = sectionId ? this.all.find((s) => s.section_id === sectionId) : null;
  this.editingId = editing ? editing.section_id : null;

  document.getElementById('sectionModalTitle').textContent = editing ? 'Edit Section' : 'New Section';
  document.getElementById('sectionName').value = editing ? editing.name : '';
  document.getElementById('sectionCode').value = (editing && editing.code) || '';
  document.getElementById('sectionTerm').value = (editing && editing.term) || '';
  document.getElementById('sectionMax').value = (editing && editing.max_students) || '';
  document.getElementById('sectionDescription').value = (editing && editing.description) || '';
  document.getElementById('sectionModal').classList.add('active');
};

Sections.saveSection = async function saveSection(event) {
  event.preventDefault();
  const btn = document.getElementById('sectionSaveBtn');
  const body = {
    name: document.getElementById('sectionName').value.trim(),
    code: document.getElementById('sectionCode').value.trim(),
    term: document.getElementById('sectionTerm').value.trim(),
    max_students: document.getElementById('sectionMax').value,
    description: document.getElementById('sectionDescription').value.trim(),
  };

  Utils.setBtnLoading(btn, true);
  try {
    if (this.editingId) {
      await this.api(`/${this.editingId}`, { method: 'PATCH', body });
      Toast.success('Saved', 'Section updated');
    } else {
      const { section } = await this.api('', { method: 'POST', body });
      this.currentId = section.section_id;
      Toast.success('Created', `${section.name} is ready — add students to it`);
    }
    closeModal('sectionModal');
    await this.load();
  } catch (err) {
    // 409 is the section-code collision, and its message already explains why
    // codes must be unique. Surfacing it verbatim beats a generic failure.
    Toast.error('Could not save the section', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

Sections.archiveSection = async function archiveSection() {
  const s = this.current();
  if (!s) return;

  if (s.status === 'archived') {
    if (!await Confirm.show({
      title: 'Reactivate this section?',
      message: `${s.name} and its ${s.active_count} enrolled student(s) will regain access to Clinic-in-a-Box.`,
      confirmText: 'Reactivate',
    })) return;
    try {
      await this.api(`/${s.section_id}`, { method: 'PATCH', body: { status: 'active' } });
      Toast.success('Reactivated', `${s.name} is active again`);
      await this.load();
    } catch (err) { Toast.error('Could not reactivate', err.message); }
    return;
  }

  // Archiving is a real revocation, not a filing action: the access gate joins
  // ciab_section, so students on no OTHER active section lose Clinic-in-a-Box
  // outright. Say how many before asking.
  if (!await Confirm.show({
    title: `Archive ${s.name}?`,
    message: 'Students enrolled only on this section will lose access to Clinic-in-a-Box. '
           + 'Nothing is deleted, and you can reactivate it at any time.',
    confirmText: 'Archive',
    danger: true,
  })) return;

  try {
    const r = await this.api(`/${s.section_id}`, { method: 'DELETE' });
    Toast.success('Archived', r.revoked_access_for
      ? `${r.revoked_access_for} student(s) lost Clinic-in-a-Box access`
      : 'No student lost access — they are all on another section');
    this.currentId = null;
    await this.load();
  } catch (err) { Toast.error('Could not archive', err.message); }
};

// ---------------------------------------------------------------------------
// Roster
// ---------------------------------------------------------------------------

Sections.loadRoster = async function loadRoster() {
  if (!this.currentId) return;
  const container = document.getElementById('sectionRosterContent');
  container.innerHTML = '<div class="empty-state"><div class="icon">⏳</div><h3>Loading roster…</h3></div>';
  const status = document.getElementById('rosterStatus').value || 'active';
  try {
    const { students } = await this.api(`/${this.currentId}/students?status=${encodeURIComponent(status)}`);
    this.roster = students || [];
  } catch (err) {
    container.innerHTML = `<div class="empty-state"><div class="icon">⚠️</div><h3>Could not load the roster</h3><p>${escapeHtml(err.message)}</p></div>`;
    return;
  }
  this.renderRoster();
};

Sections.renderRoster = function renderRoster() {
  const container = document.getElementById('sectionRosterContent');
  const q = (document.getElementById('rosterSearch').value || '').trim().toLowerCase();
  const rows = this.roster.filter((s) => !q
    || (s.email || '').toLowerCase().includes(q)
    || `${s.first_name} ${s.last_name}`.toLowerCase().includes(q)
    || (s.username || '').toLowerCase().includes(q));

  if (!rows.length) {
    container.innerHTML = this.roster.length
      ? '<div class="empty-state"><div class="icon">🔍</div><h3>No matches</h3><p>Nobody on this roster matches that search.</p></div>'
      : '<div class="empty-state"><div class="icon">👥</div><h3>Nobody enrolled yet</h3>'
        + '<p>Use <strong>Add Student</strong>, <strong>Import Roster</strong> or <strong>Generate Cohort Accounts</strong> above.</p></div>';
    return;
  }

  container.innerHTML = `
    <div class="card"><div class="card-body" style="padding: 0; overflow-x: auto;">
      <table class="data-table" style="width: 100%;">
        <thead><tr>
          <th>Name</th><th>Email</th><th>Username</th><th>Status</th>
          <th>Progress</th><th style="text-align: right;">Actions</th>
        </tr></thead>
        <tbody>${rows.map((s) => this.rosterRow(s)).join('')}</tbody>
      </table>
    </div></div>
    <p style="color: var(--gray-500); font-size: 0.85rem; margin-top: 0.5rem;">${rows.length} of ${this.roster.length} shown</p>`;
};

Sections.rosterRow = function rosterRow(s) {
  const name = [s.first_name, s.last_name].filter(Boolean).join(' ') || '—';

  const badges = [];
  if (s.status === 'dropped') badges.push('<span class="badge badge-secondary">dropped</span>');
  else badges.push('<span class="badge badge-success">enrolled</span>');
  if (s.elevated) badges.push(`<span class="badge badge-warning">${escapeHtml(s.role)}</span>`);
  if (s.pending_activation) badges.push('<span class="badge badge-info">invited</span>');
  if (s.provisioned_via === 'ciab_cohort') badges.push('<span class="badge">cohort</span>');
  else if (s.provisioned_via === 'ciab_import') badges.push('<span class="badge">imported</span>');
  else if (s.provisioned_via === 'group_deploy') badges.push('<span class="badge">lane deploy</span>');

  const progress = s.parts_started
    ? `${s.parts_started} part(s)${s.pending_reviews ? ` · ${s.pending_reviews} to review` : ''}`
    : '<span style="color: var(--gray-400);">not started</span>';

  const id = escapeHtml(s.user_id);
  const actions = [];
  actions.push(`<button class="btn btn-sm btn-outline" onclick="Sections.viewProgress('${id}')">Progress</button>`);

  // can_regenerate is computed SERVER-SIDE from account provenance. Rendering
  // these off anything else would put buttons on screen that the API refuses --
  // the rule cle/public/pages/courses.html:1540-1543 spells out.
  if (s.can_regenerate) {
    if (s.pending_activation) {
      actions.push(`<button class="btn btn-sm btn-outline" onclick="Sections.resendInvite('${id}')">Resend invite</button>`);
    } else {
      actions.push(`<button class="btn btn-sm btn-outline" onclick="Sections.resetPassword('${id}')">Reset password</button>`);
    }
  }
  actions.push(s.status === 'dropped'
    ? `<button class="btn btn-sm btn-primary" onclick="Sections.reinstate('${id}')">Reinstate</button>`
    : `<button class="btn btn-sm btn-outline" onclick="Sections.drop('${id}')">Drop</button>`);

  return `<tr>
    <td>${escapeHtml(name)}</td>
    <td>${escapeHtml(s.email)}</td>
    <td>${escapeHtml(s.username || '—')}</td>
    <td>${badges.join(' ')}</td>
    <td>${progress}</td>
    <td style="text-align: right; white-space: nowrap;">${actions.join(' ')}</td>
  </tr>`;
};

// ---------------------------------------------------------------------------
// Per-student actions
// ---------------------------------------------------------------------------

Sections.drop = async function drop(userId) {
  const s = this.roster.find((r) => r.user_id === userId);
  if (!await Confirm.show({
    title: `Drop ${s ? s.email : 'this student'}?`,
    // Soft, and says so: the API sets status='dropped' and their work is keyed
    // on user_id, so nothing is destroyed.
    message: 'They lose access to Clinic-in-a-Box unless they are on another section. '
           + 'Their profiles, submissions and feedback are kept, and you can reinstate them here.',
    confirmText: 'Drop',
    danger: true,
  })) return;

  try {
    await this.api(`/${this.currentId}/students/${userId}`, { method: 'DELETE' });
    Toast.success('Dropped', 'They no longer have access through this section');
    await this.load();
  } catch (err) { Toast.error('Could not drop that student', err.message); }
};

Sections.reinstate = async function reinstate(userId) {
  try {
    await this.api(`/${this.currentId}/students/${userId}/reinstate`, { method: 'POST' });
    Toast.success('Reinstated', 'Access restored');
    await this.load();
  } catch (err) { Toast.error('Could not reinstate', err.message); }
};

Sections.resetPassword = async function resetPassword(userId) {
  const s = this.roster.find((r) => r.user_id === userId);
  if (!await Confirm.show({
    title: 'Email a password-reset link?',
    message: `${s ? s.email : 'This student'} will get a single-use link. Their current password `
           + 'keeps working until they use it, and any earlier link is invalidated.',
    confirmText: 'Send link',
  })) return;

  try {
    const r = await this.api(`/${this.currentId}/roster/students/${userId}/password`, { method: 'POST' });
    Toast.success('Sent', r.note || `A reset link is on its way to ${r.email}`);
  } catch (err) {
    // The 409s here are informative, not failures: a cohort account has an
    // unreachable @cohort.invalid address by design, and the message names the
    // remaining path (an admin sets it directly).
    Toast.warning('Not sent', err.message);
  }
};

Sections.resendInvite = async function resendInvite(userId) {
  try {
    const r = await this.api(`/${this.currentId}/roster/students/${userId}/activation/resend`, { method: 'POST' });
    Toast.success('Invitation resent', `A fresh link is on its way to ${r.email}`);
    await this.loadRoster();
  } catch (err) { Toast.warning('Not sent', err.message); }
};

Sections.viewProgress = function viewProgress(userId) {
  // Reuses the existing per-student progress modal from the inline block rather
  // than growing a second one that would drift from it.
  if (typeof viewStudentProgress === 'function') return viewStudentProgress(userId);
  switchTab('students');
};

// ---------------------------------------------------------------------------
// Add one existing account
// ---------------------------------------------------------------------------

Sections.showAddStudent = async function showAddStudent() {
  if (!this.currentId) return;
  document.getElementById('ciabStudentSearch').value = '';
  const select = document.getElementById('ciabAddStudentSelect');
  select.innerHTML = '<option disabled>Loading…</option>';
  document.getElementById('ciabAddStudentModal').classList.add('active');

  try {
    const { students } = await this.api(`/${this.currentId}/students/available`);
    this.available = students || [];
    this.filterAvailable();
  } catch (err) {
    select.innerHTML = '';
    Toast.error('Could not load accounts', err.message);
  }
};

Sections.filterAvailable = function filterAvailable() {
  const q = (document.getElementById('ciabStudentSearch').value || '').trim().toLowerCase();
  const select = document.getElementById('ciabAddStudentSelect');
  const rows = this.available.filter((u) => !q
    || (u.email || '').toLowerCase().includes(q)
    || (u.username || '').toLowerCase().includes(q)
    || `${u.first_name || ''} ${u.last_name || ''}`.toLowerCase().includes(q));

  select.innerHTML = rows.length
    ? rows.map((u) => {
      const name = [u.first_name, u.last_name].filter(Boolean).join(' ');
      const label = name ? `${name} — ${u.email}` : u.email;
      return `<option value="${escapeHtml(u.user_id)}">${escapeHtml(label)}</option>`;
    }).join('')
    : '<option disabled>No accounts match — use Import Roster to create one</option>';
};

Sections.addStudent = async function addStudent() {
  const select = document.getElementById('ciabAddStudentSelect');
  const userId = select.value;
  if (!userId) { Toast.warning('Nobody selected', 'Pick an account from the list'); return; }

  const btn = document.getElementById('ciabAddStudentBtn');
  Utils.setBtnLoading(btn, true);
  try {
    await this.api(`/${this.currentId}/students`, { method: 'POST', body: { user_id: userId } });
    Toast.success('Added', 'They can open Clinic-in-a-Box now');
    closeModal('ciabAddStudentModal');
    await this.load();
  } catch (err) {
    Toast.error('Could not add that student', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

window.Sections = Sections;
