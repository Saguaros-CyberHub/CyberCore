/**
 * CIAB — Roster import: CSV, cohort generation, and pulling a CLE roster.
 * ----------------------------------------------------------------------------
 * Ported from cle/public/js/roster-import.js so the two plugins behave
 * identically for an instructor who uses both.
 *
 * LOADED AFTER instructor.html's inline <script> and after /js/csv.js. It uses
 * globals from both (Toast, closeModal, escapeHtml; CsvRoster).
 *
 * TWO RULES CARRIED OVER VERBATIM, because both are security-relevant:
 *
 *  1. A PASSWORD IS NEVER INTERPOLATED INTO MARKUP. It goes into a <code> via
 *     textContent. The browser HTML-decodes inside attributes, so a generated
 *     password containing an apostrophe breaks out of an onclick string --
 *     which is how a credential ends up executing as code.
 *  2. THE PREVIEW IS THE PRODUCT. Every call without `confirm` mutates nothing.
 *     An instructor sees the seat maths, the duplicates and the staff accounts
 *     before anything exists.
 */
/* global Toast, closeModal, escapeHtml, Sections, CsvRoster */

const RosterImport = {
  parsed: null,      // { rows, problems, skipped, hasHeader }
  lastResult: null,  // the run we are showing credentials for
  cohortPlan: null,
  clePreviewed: false,

  sectionId() {
    return Sections.currentId;
  },

  api(path, options = {}) {
    return API.request(`/instructor/sections/${this.sectionId()}/roster${path}`, options);
  },

  /** Both modals return to a usable state and the roster is re-read. */
  done() {
    closeModal('ciabRosterImportModal');
    closeModal('ciabCohortModal');
    closeModal('ciabFromCleModal');
    this.setStage('input');
    this.setCohortStage('input');
    Sections.load();
  },

  // -------------------------------------------------------------------------
  // Stage plumbing
  // -------------------------------------------------------------------------

  setStage(stage) {
    ['input', 'preview', 'result'].forEach((s) => {
      const el = document.getElementById(`ciabRosterStage-${s}`);
      if (el) el.style.display = s === stage ? '' : 'none';
    });
  },

  setCohortStage(stage) {
    ['input', 'preview', 'result'].forEach((s) => {
      const el = document.getElementById(`ciabCohortStage-${s}`);
      if (el) el.style.display = s === stage ? '' : 'none';
    });
  },

  showImport() {
    if (!this.sectionId()) { Toast.warning('No section', 'Create a section first'); return; }
    this.parsed = null;
    document.getElementById('ciabRosterFile').value = '';
    document.getElementById('ciabRosterPaste').value = '';
    document.getElementById('ciabRosterParseSummary').innerHTML = '';
    this.setStage('input');
    document.getElementById('ciabRosterImportModal').classList.add('active');
  },

  showCohort() {
    if (!this.sectionId()) { Toast.warning('No section', 'Create a section first'); return; }
    this.cohortPlan = null;
    this.setCohortStage('input');
    document.getElementById('ciabCohortModal').classList.add('active');
  },

  /** A small stat line, the same shape CLE's preview uses. */
  statRow(label, value, tone) {
    const color = tone === 'bad' ? 'var(--danger)' : tone === 'warn' ? 'var(--warning)' : 'var(--text-primary)';
    return `<div style="display: flex; justify-content: space-between; padding: 0.25rem 0;">
      <span style="color: var(--gray-600);">${escapeHtml(label)}</span>
      <strong style="color: ${color};">${escapeHtml(String(value))}</strong></div>`;
  },
};

// ---------------------------------------------------------------------------
// CSV parsing — /js/csv.js does the actual work
// ---------------------------------------------------------------------------

RosterImport.onFile = function onFile(event) {
  const file = event.target.files && event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = () => {
    document.getElementById('ciabRosterPaste').value = String(reader.result || '');
    this.parseNow();
  };
  reader.readAsText(file);
};

RosterImport.parseNow = function parseNow() {
  const text = document.getElementById('ciabRosterPaste').value || '';
  const summary = document.getElementById('ciabRosterParseSummary');
  if (!text.trim()) { this.parsed = null; summary.innerHTML = ''; return; }

  this.parsed = CsvRoster.parseRoster(text);
  const bits = [this.statRow('Rows found', this.parsed.rows.length)];
  if (this.parsed.hasHeader) bits.push(this.statRow('Header row', 'detected and skipped'));
  // A D2L classlist export contains the instructor. csv.js holds those rows
  // back rather than silently enrolling staff as students.
  if (this.parsed.skipped && this.parsed.skipped.length) {
    bits.push(this.statRow('Held back (look like staff)', this.parsed.skipped.length, 'warn'));
  }
  if (this.parsed.problems && this.parsed.problems.length) {
    bits.push(this.statRow('Unreadable rows', this.parsed.problems.length, 'bad'));
  }
  summary.innerHTML = `<div class="info-box">${bits.join('')}</div>`;
};

// ---------------------------------------------------------------------------
// CSV import — preview then confirm
// ---------------------------------------------------------------------------

RosterImport.preview = async function preview() {
  this.parseNow();
  if (!this.parsed || !this.parsed.rows.length) {
    Toast.warning('Nothing to import', 'Choose a file or paste some rows first');
    return;
  }
  const btn = document.getElementById('ciabRosterPreviewBtn');
  Utils.setBtnLoading(btn, true);
  try {
    // No `confirm` — this call changes nothing at all.
    const r = await this.api('/import', {
      method: 'POST',
      body: {
        rows: this.parsed.rows,
        notify_existing: document.getElementById('ciabRosterNotifyExisting').checked,
      },
    });
    this.renderPreview(r);
    this.setStage('preview');
  } catch (err) {
    Toast.error('Preview failed', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

RosterImport.renderPreview = function renderPreview(r) {
  const s = r.summary;
  const body = document.getElementById('ciabRosterPreviewBody');

  const stats = [
    this.statRow('New accounts to create', s.will_create),
    this.statRow('Existing accounts to enroll', s.will_enroll_existing),
    this.statRow('Previously dropped, re-enrolling', s.will_reactivate),
    this.statRow('Already enrolled (no change)', s.already_enrolled),
    s.will_fill_names ? this.statRow('Missing names this file fills in', s.will_fill_names) : '',
    s.duplicates ? this.statRow('Duplicates within the file', s.duplicates, 'warn') : '',
    s.invalid ? this.statRow('Rows that could not be read', s.invalid, 'bad') : '',
    this.statRow('Seats after import', s.max_students ? `${s.seats_after} of ${s.max_students}` : String(s.seats_after)),
    this.statRow('Emails to send', s.emails_to_send),
  ].join('');

  const problems = (r.rows || [])
    .filter((row) => row.action === 'invalid' || row.action === 'skip' || row.warning)
    .slice(0, 25)
    .map((row) => `<tr>
      <td>${row.line}</td>
      <td>${escapeHtml(row.email || '—')}</td>
      <td>${escapeHtml(row.reason || row.warning || row.action)}</td>
    </tr>`).join('');

  body.innerHTML = `
    ${(r.errors || []).map((e) => `<div class="alert alert-danger">${escapeHtml(e)}</div>`).join('')}
    ${(r.warnings || []).map((w) => `<div class="alert alert-warning">${escapeHtml(w)}</div>`).join('')}
    <div class="info-box" style="margin-bottom: 1rem;">${stats}</div>
    ${problems ? `<h4>Rows needing attention</h4>
      <table class="data-table" style="width: 100%;">
        <thead><tr><th>Line</th><th>Email</th><th>What will happen</th></tr></thead>
        <tbody>${problems}</tbody></table>` : ''}`;

  // The server said no; do not let the button pretend otherwise.
  document.getElementById('ciabRosterConfirmBtn').disabled = !r.canProceed;
};

RosterImport.confirm = async function confirm() {
  const btn = document.getElementById('ciabRosterConfirmBtn');
  Utils.setBtnLoading(btn, true, 'Importing…');
  try {
    const r = await this.api('/import', {
      method: 'POST',
      body: {
        rows: this.parsed.rows,
        notify_existing: document.getElementById('ciabRosterNotifyExisting').checked,
        confirm: true,
      },
    });
    this.lastResult = r;
    this.renderResult(r);
    this.setStage('result');
  } catch (err) {
    // A 409 here means the blocking conditions changed between preview and
    // confirm — the seat cap filled, say. The server re-checks on purpose.
    Toast.error('Import refused', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

// ---------------------------------------------------------------------------
// Results — the only place plaintext credentials are ever shown
// ---------------------------------------------------------------------------

/**
 * Render a credential list.
 *
 * The password goes in via textContent, NEVER interpolated into the markup
 * string above. The browser HTML-decodes inside attributes, so a generated
 * password containing an apostrophe would break out of a quoted attribute -- and
 * a credential that escapes into an onclick handler is a credential that
 * executes. cle/public/js/roster-import.js:351-376 does the same thing for the
 * same reason; ciab/public/js/admin-profile-lanes.js:498 does NOT, and is the
 * example to avoid.
 */
RosterImport.renderCredentials = function renderCredentials(container, list, label) {
  if (!list || !list.length) return;
  const table = document.createElement('table');
  table.className = 'data-table';
  table.style.width = '100%';
  table.innerHTML = '<thead><tr><th>Username</th><th>Email</th><th>Password</th></tr></thead><tbody></tbody>';
  const tbody = table.querySelector('tbody');

  for (const c of list) {
    const tr = document.createElement('tr');
    const tdUser = document.createElement('td');
    tdUser.textContent = c.username || '';
    const tdEmail = document.createElement('td');
    tdEmail.textContent = c.email || '';
    const tdPw = document.createElement('td');
    const code = document.createElement('code');
    code.textContent = c.password || c.temp_password || '';   // <- the rule
    tdPw.appendChild(code);
    tr.append(tdUser, tdEmail, tdPw);
    tbody.appendChild(tr);
  }

  const heading = document.createElement('h4');
  heading.textContent = label;
  container.appendChild(heading);
  container.appendChild(table);
};

RosterImport.renderResult = function renderResult(r) {
  const s = r.summary;
  const body = document.getElementById('ciabRosterResultBody');
  body.innerHTML = `
    <div class="alert alert-success">Imported ${s.enrolled} student(s) — ${s.created} new account(s) created.</div>
    <div class="info-box" style="margin-bottom: 1rem;">
      ${this.statRow('Accounts created', s.created)}
      ${this.statRow('Enrolled', s.enrolled)}
      ${this.statRow('Skipped', s.skipped)}
      ${s.failed ? this.statRow('Failed', s.failed, 'bad') : ''}
      ${this.statRow('Invitations sent', s.emails_queued)}
      ${s.emails_suppressed ? this.statRow('Invitations not sent', s.emails_suppressed, 'warn') : ''}
    </div>`;

  if (r.failed && r.failed.length) {
    const list = document.createElement('div');
    list.className = 'alert alert-warning';
    list.textContent = `${r.failed.length} row(s) failed: `
      + r.failed.slice(0, 5).map((f) => `${f.email || f.username} (${f.error})`).join('; ');
    body.appendChild(list);
  }

  // Only accounts whose invitation could NOT be delivered carry a password.
  // A credential that reached a mailbox must not also be echoed to the screen.
  const withPasswords = (r.created || []).filter((c) => c.temp_password);
  if (withPasswords.length) {
    const note = document.createElement('div');
    note.className = 'alert alert-warning';
    note.textContent = 'These accounts could not be emailed, so hand these temporary passwords over '
      + 'yourself. They are shown once and cannot be retrieved later.';
    body.appendChild(note);
    this.renderCredentials(body, withPasswords, 'Temporary passwords');
  }

  const csvBtn = document.getElementById('ciabRosterCsvBtn');
  if (csvBtn) csvBtn.style.display = withPasswords.length ? '' : 'none';
};

/** RFC 4180 quoting for one cell. */
RosterImport.csvCell = function csvCell(v) {
  const s = String(v == null ? '' : v);
  return /[",\r\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
};

RosterImport.toCsv = function toCsv(rows, headers) {
  const lines = [headers.join(',')];
  for (const r of rows) lines.push(headers.map((h) => this.csvCell(r[h])).join(','));
  // A UTF-8 BOM, so Excel does not mangle accented names.
  return `﻿${lines.join('\r\n')}`;
};

/**
 * Put the credential sheet on the clipboard.
 *
 * NOT a download. The artifact viewer and several browsers block page-initiated
 * downloads, and a credential sheet that silently fails to save is worse than
 * one the instructor has to paste. Falls back to a selectable textarea when the
 * clipboard is unavailable (http origins, permissions).
 */
RosterImport.copyAsCsv = async function copyAsCsv(rows, headers, what) {
  const csv = this.toCsv(rows, headers);
  try {
    await navigator.clipboard.writeText(csv);
    Toast.success('Copied', `${what} copied — paste into a spreadsheet now`);
  } catch (_) {
    const ta = document.createElement('textarea');
    ta.value = csv;
    ta.style.cssText = 'position:fixed;top:10%;left:10%;width:80%;height:60%;z-index:99999;';
    document.body.appendChild(ta);
    ta.select();
    Toast.warning('Copy manually', 'Your browser blocked clipboard access — select the text and copy it, then click anywhere to dismiss.');
    const dismiss = () => { ta.remove(); document.removeEventListener('click', dismiss, true); };
    setTimeout(() => document.addEventListener('click', dismiss, true), 100);
  }
};

RosterImport.downloadCredentials = function downloadCredentials() {
  const rows = ((this.lastResult && this.lastResult.created) || [])
    .filter((c) => c.temp_password)
    .map((c) => ({ username: c.username, email: c.email, password: c.temp_password }));
  this.copyAsCsv(rows, ['username', 'email', 'password'], 'Temporary passwords');
};

RosterImport.downloadCohort = function downloadCohort() {
  const rows = ((this.lastResult && this.lastResult.credentials) || [])
    .map((c) => ({ username: c.username, email: c.email, password: c.password }));
  this.copyAsCsv(rows, ['username', 'email', 'password'], 'Cohort credentials');
};

// ---------------------------------------------------------------------------
// Cohort generation
// ---------------------------------------------------------------------------

RosterImport.cohortBody = function cohortBody(confirmFlag) {
  return {
    count: Number(document.getElementById('ciabCohortCount').value),
    start_index: Number(document.getElementById('ciabCohortStartIndex').value) || 1,
    enrollment_role: document.getElementById('ciabCohortRole').value,
    require_password_change: document.getElementById('ciabCohortRequireChange').checked,
    ...(confirmFlag ? { confirm: true } : {}),
  };
};

RosterImport.cohortPreview = async function cohortPreview() {
  const btn = document.getElementById('ciabCohortPreviewBtn');
  Utils.setBtnLoading(btn, true);
  try {
    const r = await this.api('/cohort', { method: 'POST', body: this.cohortBody(false) });
    this.cohortPlan = r;
    const s = r.summary;
    document.getElementById('ciabCohortPreviewBody').innerHTML = `
      ${(r.errors || []).map((e) => `<div class="alert alert-danger">${escapeHtml(e)}</div>`).join('')}
      ${(r.warnings || []).map((w) => `<div class="alert alert-warning">${escapeHtml(w)}</div>`).join('')}
      <div class="info-box" style="margin-bottom: 1rem;">
        ${this.statRow('Accounts to create', s.count)}
        ${this.statRow('Numbered', `${s.start_index} to ${s.end_index}`)}
        ${s.skipped_existing ? this.statRow('Names already taken (skipped)', s.skipped_existing, 'warn') : ''}
        ${this.statRow('Seats after', s.max_students ? `${s.seats_after} of ${s.max_students}` : String(s.seats_after))}
      </div>
      <h4>Example names</h4>
      <p><code>${(r.sample_usernames || []).map(escapeHtml).join('</code>, <code>')}</code></p>`;
    document.getElementById('ciabCohortConfirmBtn').disabled = !r.canProceed;
    this.setCohortStage('preview');
  } catch (err) {
    Toast.error('Preview failed', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

RosterImport.cohortConfirm = async function cohortConfirm() {
  const btn = document.getElementById('ciabCohortConfirmBtn');
  Utils.setBtnLoading(btn, true, 'Generating…');
  try {
    const r = await this.api('/cohort', { method: 'POST', body: this.cohortBody(true) });
    this.lastResult = r;
    const body = document.getElementById('ciabCohortResultBody');
    body.innerHTML = `
      <div class="alert alert-success">Created ${r.summary.created} account(s).</div>
      ${(r.warnings || []).map((w) => `<div class="alert alert-warning">${escapeHtml(w)}</div>`).join('')}`;
    this.renderCredentials(body, r.credentials, 'Credentials — shown once');
    this.setCohortStage('result');
  } catch (err) {
    Toast.error('Generation refused', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

// ---------------------------------------------------------------------------
// Import from a CLE course
// ---------------------------------------------------------------------------

RosterImport.showFromCle = async function showFromCle() {
  if (!this.sectionId()) { Toast.warning('No section', 'Create a section first'); return; }
  const select = document.getElementById('ciabCleCourseSelect');
  select.innerHTML = '<option disabled>Loading…</option>';
  document.getElementById('ciabFromCleBody').innerHTML = '';
  this.clePreviewed = false;
  const goBtn = document.getElementById('ciabFromCleBtn');
  if (goBtn) goBtn.textContent = 'Preview';
  document.getElementById('ciabFromCleModal').classList.add('active');

  try {
    // The CLE plugin's own endpoint, so it only ever lists courses this caller
    // manages. If CLE is not installed this 404s and we say so plainly.
    const r = await API.request('/cle/courses');
    const courses = r.courses || r || [];
    select.innerHTML = courses.length
      ? courses.map((c) => `<option value="${escapeHtml(c.course_id)}">${escapeHtml(c.code ? `${c.code} — ${c.course_name}` : c.course_name)}</option>`).join('')
      : '<option disabled>You do not teach any CLE courses</option>';
  } catch (err) {
    select.innerHTML = '<option disabled>Unavailable</option>';
    document.getElementById('ciabFromCleBody').innerHTML =
      '<div class="alert alert-warning">The Cyber Learning Environment is not available on this deployment.</div>';
  }
};

RosterImport.fromCle = async function fromCle() {
  const courseId = document.getElementById('ciabCleCourseSelect').value;
  if (!courseId) return;
  const btn = document.getElementById('ciabFromCleBtn');
  const body = document.getElementById('ciabFromCleBody');
  // Explicit state, not a read of the button's own label: setBtnLoading()
  // rewrites innerHTML while the request is in flight, so inferring the stage
  // from the caption is only correct by accident.
  const previewing = !this.clePreviewed;

  Utils.setBtnLoading(btn, true);
  try {
    // Same preview-then-confirm contract as the CSV path, because it IS the
    // CSV path -- the server feeds these rows through runImport().
    const r = await this.api('/import-from-cle', {
      method: 'POST',
      body: { course_id: courseId, ...(previewing ? {} : { confirm: true }) },
    });

    if (r.preview) {
      body.innerHTML = `
        ${(r.errors || []).map((e) => `<div class="alert alert-danger">${escapeHtml(e)}</div>`).join('')}
        <div class="info-box">
          ${this.statRow('Students found', r.summary.total)}
          ${this.statRow('Will enroll', r.summary.will_enroll_existing + r.summary.will_reactivate)}
          ${this.statRow('Already enrolled', r.summary.already_enrolled)}
        </div>`;
      this.clePreviewed = true;
      btn.dataset.restoreHtml = 'Import';
    } else {
      Toast.success('Imported', `${r.summary.enrolled} student(s) enrolled from that course`);
      this.clePreviewed = false;
      btn.dataset.restoreHtml = 'Preview';
      closeModal('ciabFromCleModal');
      Sections.load();
    }
  } catch (err) {
    Toast.error('Could not import', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

window.RosterImport = RosterImport;
