/**
 * ============================================================================
 * CLE — Roster import UI
 * ============================================================================
 * Drives the Import Roster modal on the course Students tab.
 *
 * DEPENDS ON GLOBALS from courses.html's inline <script>: api(), escHtml(),
 * escAttr(), toast(), showModal(), closeModal(), copyText(), currentCourseId,
 * currentCourseData, loadStudents(). The <script> tag for this file MUST come
 * after that block — placed before it, `currentCourseId` is not yet defined.
 *
 * WHY THE FILE IS PARSED HERE RATHER THAN UPLOADED
 * The app has no multipart handling and deliberately does not add any — the
 * same decision is already documented at ciab/routes/profiles.js:432. Parsing
 * in the browser also lets the preview surface malformed rows before anything
 * reaches the server, which is what preview-then-confirm wants anyway. A
 * 500-row roster is ~30 KB of JSON, well inside express.json's 10 MB limit.
 */

/* global api, escHtml, escAttr, toast, showModal, closeModal, copyText,
          currentCourseId, currentCourseData, loadStudents, CleCsv */

(function () {
  'use strict';

  // Rosters are text. A file far larger than a class list is a wrong file, and
  // reading it would freeze the tab before the server ever said no.
  const MAX_FILE_BYTES = 1024 * 1024;
  const MAX_ROWS = 500;

  let parsedRows = [];
  let parseProblems = [];
  let parseSkipped = [];
  let lastPreview = null;
  let lastResult = null;

  // ==========================================================================
  // MODAL LIFECYCLE
  // ==========================================================================

  function showRosterImportModal() {
    parsedRows = [];
    parseProblems = [];
    parseSkipped = [];
    lastPreview = null;
    lastResult = null;

    document.getElementById('rosterFileInput').value = '';
    document.getElementById('rosterPasteInput').value = '';
    document.getElementById('rosterNotifyExisting').checked = true;
    document.getElementById('rosterParseSummary').innerHTML = '';
    document.getElementById('rosterPreviewArea').innerHTML = '';
    document.getElementById('rosterResultArea').innerHTML = '';
    setStage('input');
    showModal('rosterImportModal');
  }

  /** Only one of input / preview / result is visible at a time. */
  function setStage(stage) {
    ['input', 'preview', 'result'].forEach(s => {
      const el = document.getElementById(`rosterStage-${s}`);
      if (el) el.style.display = s === stage ? '' : 'none';
    });
  }

  // ==========================================================================
  // PARSING
  // ==========================================================================

  function onRosterFileChosen(input) {
    const file = input.files && input.files[0];
    if (!file) return;
    if (file.size > MAX_FILE_BYTES) {
      toast(`That file is ${(file.size / 1024 / 1024).toFixed(1)} MB. A roster should be well under 1 MB — is it the right file?`, true);
      input.value = '';
      return;
    }
    const reader = new FileReader();
    reader.onload = () => {
      document.getElementById('rosterPasteInput').value = String(reader.result || '');
      parseRosterInput();
    };
    reader.onerror = () => toast('Could not read that file', true);
    reader.readAsText(file);
  }

  function parseRosterInput() {
    const text = document.getElementById('rosterPasteInput').value;
    const summary = document.getElementById('rosterParseSummary');

    if (!text.trim()) {
      parsedRows = [];
      parseProblems = [];
      parseSkipped = [];
      summary.innerHTML = '';
      return;
    }

    const parsed = CleCsv.parseRoster(text);
    parsedRows = parsed.rows;
    parseProblems = parsed.problems;
    parseSkipped = parsed.skipped || [];

    const bits = [];
    bits.push(`<strong>${parsedRows.length}</strong> row${parsedRows.length === 1 ? '' : 's'} read`);
    if (parsed.hasHeader) bits.push('header detected, columns mapped by name');
    else bits.push('no header found — reading columns as <code>email, first name, last name</code>');

    let html = `<div style="font-size:0.85rem; color:var(--text-secondary,#555);">${bits.join(' · ')}</div>`;

    // Held-back staff rows are NOT a problem — a D2L classlist legitimately
    // contains the instructor. Shown separately from the warning block so it
    // reads as "handled", and shown at all so nobody concludes the import
    // silently lost a row.
    if (parseSkipped.length > 0) {
      html += `<div class="alert alert-info" style="margin-top:0.5rem; font-size:0.85rem;">
        <div><strong>${parseSkipped.length} non-student row${parseSkipped.length === 1 ? '' : 's'} held back</strong>
          — a classlist export includes teaching staff, who should not be enrolled as students.</div>
        ${parseSkipped.slice(0, 5).map(k =>
          `<div>Line ${k.line}: ${escHtml(k.name || k.email || '(no name)')} — ${escHtml(k.role)}</div>`).join('')}
        ${parseSkipped.length > 5 ? `<div>…and ${parseSkipped.length - 5} more.</div>` : ''}
      </div>`;
    }

    if (parseProblems.length > 0) {
      html += `<div class="alert alert-warning" style="margin-top:0.5rem; font-size:0.85rem;">
        ${parseProblems.slice(0, 8).map(p =>
          `<div>${p.line ? `Line ${p.line}: ` : ''}${escHtml(p.message)}</div>`).join('')}
        ${parseProblems.length > 8 ? `<div>…and ${parseProblems.length - 8} more.</div>` : ''}
      </div>`;
    }
    if (parsedRows.length > MAX_ROWS) {
      html += `<div class="alert alert-danger" style="margin-top:0.5rem; font-size:0.85rem;">
        This file has ${parsedRows.length} rows; the limit is ${MAX_ROWS} per import. Split it and import in parts.
      </div>`;
    }

    summary.innerHTML = html;
  }

  // ==========================================================================
  // PREVIEW
  // ==========================================================================

  async function previewRosterImport() {
    parseRosterInput();
    if (parsedRows.length === 0) {
      toast('Nothing to import — choose a file or paste a roster first', true);
      return;
    }
    if (parsedRows.length > MAX_ROWS) {
      toast(`Too many rows (${parsedRows.length}). The limit is ${MAX_ROWS}.`, true);
      return;
    }

    const btn = document.getElementById('rosterPreviewBtn');
    btn.disabled = true;
    btn.textContent = 'Checking...';
    try {
      lastPreview = await api('POST', `/courses/${currentCourseId}/roster/import`, {
        rows: parsedRows,
        notify_existing: document.getElementById('rosterNotifyExisting').checked,
        confirm: false,
      });
      renderPreview(lastPreview);
      setStage('preview');
    } catch (err) {
      toast(err.message || 'Could not check the roster', true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Check Roster';
    }
  }

  const ACTION_LABELS = {
    create: 'Create account + invite',
    enroll_existing: 'Enroll existing account',
    reactivate: 'Re-enroll (was dropped)',
    already_enrolled: 'Already enrolled — no change',
    skip: 'Skipped',
    invalid: 'Cannot read',
  };

  function statRow(label, value, emphasis) {
    return `<div style="display:flex; justify-content:space-between; padding:0.25rem 0;
                        ${emphasis ? 'font-weight:600;' : ''}">
      <span style="color:var(--text-secondary,#555);">${escHtml(label)}</span>
      <span>${escHtml(String(value))}</span>
    </div>`;
  }

  function renderPreview(preview) {
    const s = preview.summary;
    const area = document.getElementById('rosterPreviewArea');

    const seatsOver = s.max_students && s.seats_after > s.max_students;

    let html = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0 1.5rem; margin-bottom:1rem;">
        <div>
          ${statRow('New accounts to create', s.will_create, true)}
          ${statRow('Existing accounts to enroll', s.will_enroll_existing)}
          ${s.will_reactivate ? statRow('Re-enrolling (previously dropped)', s.will_reactivate) : ''}
          ${s.already_enrolled ? statRow('Already enrolled', s.already_enrolled) : ''}
          ${s.will_fill_names ? statRow('Missing names to fill in', s.will_fill_names) : ''}
        </div>
        <div>
          ${statRow('Seats used now', `${s.seats_used}${s.max_students ? ` of ${s.max_students}` : ''}`)}
          ${statRow('Seats after import', `${s.seats_after}${s.max_students ? ` of ${s.max_students}` : ''}`, seatsOver)}
          ${statRow('Emails to send', s.email_enabled ? s.emails_to_send : 'none (email off)')}
          ${s.duplicates ? statRow('Duplicate rows', s.duplicates) : ''}
          ${s.invalid ? statRow('Unreadable rows', s.invalid) : ''}
        </div>
      </div>`;

    if (preview.errors && preview.errors.length) {
      html += `<div class="alert alert-danger" style="margin-bottom:1rem;">
        ${preview.errors.map(e => `<div>${escHtml(e)}</div>`).join('')}
      </div>`;
    }
    if (preview.warnings && preview.warnings.length) {
      html += `<div class="alert alert-warning" style="margin-bottom:1rem; font-size:0.9rem;">
        ${preview.warnings.map(w => `<div>${escHtml(w)}</div>`).join('')}
      </div>`;
    }

    html += `<div style="max-height:260px; overflow:auto; border:1px solid var(--border,#ddd); border-radius:6px;">
      <table class="data-table" style="margin:0; font-size:0.85rem;">
        <thead><tr><th>Line</th><th>Email</th><th>Name</th><th>What will happen</th></tr></thead>
        <tbody>
          ${preview.rows.map(r => `
            <tr>
              <td>${escHtml(String(r.line))}</td>
              <td>${escHtml(r.email)}</td>
              <td>${escHtml([r.first_name, r.last_name].filter(Boolean).join(' ') || '—')}</td>
              <td>
                ${escHtml(ACTION_LABELS[r.action] || r.action)}
                ${r.elevated ? '<span class="badge" style="margin-left:0.35rem;">staff</span>' : ''}
                ${r.reason ? `<div style="font-size:0.75rem; color:var(--text-secondary,#777);">${escHtml(r.reason)}</div>` : ''}
              </td>
            </tr>`).join('')}
        </tbody>
      </table>
    </div>`;

    area.innerHTML = html;

    // The confirm button reflects the server's verdict, not the client's. A
    // blocked run must not be one disabled attribute away from executing.
    // Re-importing a corrected file over a class that is ALREADY enrolled has
    // nothing to enroll, but it does have names to repair. Counting only
    // enrollments there labelled the button "Import 0 student(s)" over a run
    // that was about to do real work.
    const confirmBtn = document.getElementById('rosterConfirmBtn');
    const toImport = s.will_create + s.will_enroll_existing + (s.will_reactivate || 0);
    const toFill = s.will_fill_names || 0;

    confirmBtn.disabled = !preview.canProceed || (toImport === 0 && toFill === 0);
    confirmBtn.textContent = !preview.canProceed
      ? 'Blocked — fix the errors above'
      : toImport > 0
        ? `Import ${toImport} student(s)` + (toFill ? ` and fill ${toFill} name(s)` : '')
        : toFill > 0
          ? `Fill in ${toFill} missing name${toFill === 1 ? '' : 's'}`
          : 'Nothing to change';
  }

  // ==========================================================================
  // CONFIRM
  // ==========================================================================

  async function confirmRosterImport() {
    if (!lastPreview || !lastPreview.canProceed) return;

    const btn = document.getElementById('rosterConfirmBtn');
    btn.disabled = true;
    btn.textContent = 'Importing...';
    try {
      lastResult = await api('POST', `/courses/${currentCourseId}/roster/import`, {
        rows: parsedRows,
        notify_existing: document.getElementById('rosterNotifyExisting').checked,
        confirm: true,
      });
      renderResult(lastResult);
      setStage('result');
      if (typeof loadStudents === 'function') loadStudents();
    } catch (err) {
      toast(err.message || 'Import failed', true);
      btn.disabled = false;
      btn.textContent = 'Retry import';
    }
  }

  function renderResult(result) {
    const s = result.summary;
    const area = document.getElementById('rosterResultArea');

    let html = `<div class="alert alert-success" style="margin-bottom:1rem;">
      Created <strong>${s.created}</strong> account(s), enrolled <strong>${s.enrolled}</strong> student(s).
      ${s.emails_queued ? `${s.emails_queued} invitation(s) queued.` : ''}
      ${s.failed ? `<strong>${s.failed}</strong> row(s) failed.` : ''}
    </div>`;

    if (result.warnings && result.warnings.length) {
      html += `<div class="alert alert-warning" style="margin-bottom:1rem; font-size:0.9rem;">
        ${result.warnings.map(w => `<div>${escHtml(w)}</div>`).join('')}
      </div>`;
    }

    // Any temporary passwords the server returned (the mail-unavailable path)
    // are shown once and never again, so they get their own loud panel.
    const withPasswords = (result.created || []).filter(c => c.temp_password);
    if (withPasswords.length > 0) {
      html += `<div class="alert alert-warning" style="margin-bottom:1rem;">
          <strong>Save these now.</strong> These passwords are shown once and cannot be retrieved later.
        </div>
        <div style="margin-bottom:0.75rem;">
          <button class="btn btn-sm btn-outline" id="rosterCopyCredsBtn">Copy all</button>
          <button class="btn btn-sm btn-outline" id="rosterDownloadCredsBtn">Download CSV</button>
        </div>`;
    }

    if (result.created && result.created.length) {
      html += `<h4 style="margin:1rem 0 0.5rem;">Accounts created</h4>
        <div style="max-height:220px; overflow:auto; border:1px solid var(--border,#ddd); border-radius:6px;">
          <table class="data-table" style="margin:0; font-size:0.85rem;">
            <thead><tr><th>Email</th><th>Username</th><th>Invitation</th>${withPasswords.length ? '<th>Temporary password</th>' : ''}</tr></thead>
            <tbody id="rosterCreatedBody"></tbody>
          </table>
        </div>`;
    }

    if (result.failed && result.failed.length) {
      html += `<h4 style="margin:1rem 0 0.5rem;">Rows that failed</h4>
        <div style="max-height:160px; overflow:auto; border:1px solid var(--border,#ddd); border-radius:6px;">
          <table class="data-table" style="margin:0; font-size:0.85rem;">
            <thead><tr><th>Line</th><th>Email</th><th>Reason</th></tr></thead>
            <tbody>
              ${result.failed.map(f => `<tr>
                <td>${escHtml(String(f.line))}</td>
                <td>${escHtml(f.email)}</td>
                <td>${escHtml(f.error)}</td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>`;
    }

    area.innerHTML = html;

    // Passwords are written with textContent, never interpolated into markup or
    // an inline handler — the same rule courses.html documents for
    // renderCredentialCell: inside onclick="fn('…')" the browser HTML-decodes
    // first, so a password containing an apostrophe breaks out of the string.
    const tbody = document.getElementById('rosterCreatedBody');
    if (tbody) {
      for (const c of result.created) {
        const tr = document.createElement('tr');
        const td = (text) => { const e = document.createElement('td'); e.textContent = text; return e; };
        tr.appendChild(td(c.email));
        tr.appendChild(td(c.username || '—'));
        tr.appendChild(td(c.activation_sent ? 'Sent' : (c.email_note || 'Not sent')));
        if (withPasswords.length) {
          const pw = document.createElement('td');
          if (c.temp_password) {
            const code = document.createElement('code');
            code.textContent = c.temp_password;
            pw.appendChild(code);
          } else {
            pw.textContent = '—';
          }
          tr.appendChild(pw);
        }
        tbody.appendChild(tr);
      }
    }

    const copyBtn = document.getElementById('rosterCopyCredsBtn');
    if (copyBtn) copyBtn.addEventListener('click', () => copyText(credentialsCsv(withPasswords)));
    const dlBtn = document.getElementById('rosterDownloadCredsBtn');
    if (dlBtn) dlBtn.addEventListener('click', () => downloadCredentials(withPasswords));
  }

  // ==========================================================================
  // CREDENTIAL EXPORT
  // ==========================================================================

  /**
   * RFC 4180 quoting on the way out as well as in.
   *
   * The existing credential exports in admin-lanes.js wrap values in bare
   * quotes, which breaks on any value containing one. Passwords cannot today
   * (generatePassword's symbol set is !@#$%&*), but names come from a roster an
   * instructor uploaded and absolutely will contain commas.
   */
  function csvCell(value) {
    return '"' + String(value == null ? '' : value).replace(/"/g, '""') + '"';
  }

  function credentialsCsv(rows) {
    const lines = [['email', 'username', 'temporary_password'].map(csvCell).join(',')];
    for (const r of rows) {
      lines.push([r.email, r.username || '', r.temp_password || ''].map(csvCell).join(','));
    }
    return lines.join('\r\n');
  }

  function downloadCredentials(rows) {
    const code = (currentCourseData && (currentCourseData.code || currentCourseData.course_name)) || 'course';
    const safe = String(code).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    // Leading BOM so Excel opens it as UTF-8 and does not mangle accented names.
    const blob = new Blob(['﻿' + credentialsCsv(rows)], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${safe}-credentials.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ==========================================================================
  // COHORT GENERATION
  // ==========================================================================

  let cohortPreview = null;

  function setCohortStage(stage) {
    ['input', 'preview', 'result'].forEach(s => {
      const el = document.getElementById(`cohortStage-${s}`);
      if (el) el.style.display = s === stage ? '' : 'none';
    });
  }

  function showCohortModal() {
    cohortPreview = null;
    document.getElementById('cohortCount').value = 25;
    document.getElementById('cohortStartIndex').value = 1;
    document.getElementById('cohortRequireChange').checked = false;
    document.getElementById('cohortPreviewArea').innerHTML = '';
    document.getElementById('cohortResultArea').innerHTML = '';
    setCohortStage('input');
    showModal('cohortModal');
  }

  function cohortRequestBody(confirm) {
    return {
      count: Number(document.getElementById('cohortCount').value),
      start_index: Number(document.getElementById('cohortStartIndex').value) || 1,
      enrollment_role: document.getElementById('cohortRole').value,
      require_password_change: document.getElementById('cohortRequireChange').checked,
      confirm,
    };
  }

  async function previewCohort() {
    const btn = document.getElementById('cohortPreviewBtn');
    btn.disabled = true;
    btn.textContent = 'Checking...';
    try {
      cohortPreview = await api('POST', `/courses/${currentCourseId}/roster/cohort`, cohortRequestBody(false));
      renderCohortPreview(cohortPreview);
      setCohortStage('preview');
    } catch (err) {
      toast(err.message || 'Could not plan the cohort', true);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Preview';
    }
  }

  function renderCohortPreview(preview) {
    const s = preview.summary;
    let html = `
      <div style="display:grid; grid-template-columns:1fr 1fr; gap:0 1.5rem; margin-bottom:1rem;">
        <div>
          ${statRow('Accounts to create', s.count, true)}
          ${statRow('Numbered', `${s.start_index} – ${s.end_index}`)}
          ${s.skipped_existing ? statRow('Existing names skipped', s.skipped_existing) : ''}
        </div>
        <div>
          ${statRow('Seats used now', `${s.seats_used}${s.max_students ? ` of ${s.max_students}` : ''}`)}
          ${statRow('Seats after', `${s.seats_after}${s.max_students ? ` of ${s.max_students}` : ''}`)}
        </div>
      </div>`;

    if (preview.sample_usernames && preview.sample_usernames.length) {
      html += `<div style="margin-bottom:1rem;">
        <div style="font-size:0.85rem; color:var(--text-secondary,#555); margin-bottom:0.25rem;">Names will look like:</div>
        <code style="font-size:0.85rem;">${preview.sample_usernames.map(escHtml).join('<br>')}</code>
      </div>`;
    }
    if (preview.errors && preview.errors.length) {
      html += `<div class="alert alert-danger" style="margin-bottom:1rem;">
        ${preview.errors.map(e => `<div>${escHtml(e)}</div>`).join('')}</div>`;
    }
    if (preview.warnings && preview.warnings.length) {
      html += `<div class="alert alert-warning" style="margin-bottom:1rem; font-size:0.9rem;">
        ${preview.warnings.map(w => `<div>${escHtml(w)}</div>`).join('')}</div>`;
    }

    document.getElementById('cohortPreviewArea').innerHTML = html;

    const btn = document.getElementById('cohortConfirmBtn');
    btn.disabled = !preview.canProceed;
    btn.textContent = preview.canProceed ? `Generate ${s.count} account(s)` : 'Blocked — fix the errors above';
  }

  async function confirmCohort() {
    if (!cohortPreview || !cohortPreview.canProceed) return;
    const btn = document.getElementById('cohortConfirmBtn');
    btn.disabled = true;
    btn.textContent = 'Generating...';
    try {
      const result = await api('POST', `/courses/${currentCourseId}/roster/cohort`, cohortRequestBody(true));
      renderCohortResult(result);
      setCohortStage('result');
      if (typeof loadStudents === 'function') loadStudents();
    } catch (err) {
      toast(err.message || 'Generation failed', true);
      btn.disabled = false;
      btn.textContent = 'Retry';
    }
  }

  function renderCohortResult(result) {
    const s = result.summary;
    const area = document.getElementById('cohortResultArea');

    let html = `<div class="alert alert-warning" style="margin-bottom:1rem;">
        <strong>Save these now.</strong> These passwords are shown once and cannot be retrieved later —
        if you lose them, you'll have to regenerate each account's password individually.
      </div>
      <div style="margin-bottom:0.5rem; font-size:0.9rem;">
        Created <strong>${s.created}</strong> account(s)${s.failed ? `, <strong>${s.failed}</strong> failed` : ''}.
      </div>
      <div style="margin-bottom:0.75rem;">
        <button class="btn btn-sm btn-outline" id="cohortCopyBtn">Copy all</button>
        <button class="btn btn-sm btn-outline" id="cohortDownloadBtn">Download CSV</button>
      </div>
      <div style="max-height:300px; overflow:auto; border:1px solid var(--border,#ddd); border-radius:6px;">
        <table class="data-table" style="margin:0; font-size:0.85rem;">
          <thead><tr><th>Username</th><th>Password</th></tr></thead>
          <tbody id="cohortCredsBody"></tbody>
        </table>
      </div>`;

    if (result.failed && result.failed.length) {
      html += `<h4 style="margin:1rem 0 0.5rem;">Failed</h4>
        <div style="font-size:0.85rem;">
          ${result.failed.map(f => `<div>${escHtml(f.username)}: ${escHtml(f.error)}</div>`).join('')}
        </div>`;
    }

    area.innerHTML = html;

    // textContent only — same rule as renderCredentialCell in courses.html.
    // A generated password interpolated into markup or an inline handler is one
    // apostrophe away from breaking out of the string.
    const tbody = document.getElementById('cohortCredsBody');
    for (const c of result.credentials || []) {
      const tr = document.createElement('tr');
      const nameCell = document.createElement('td');
      const nameCode = document.createElement('code');
      nameCode.textContent = c.username;
      nameCell.appendChild(nameCode);
      const pwCell = document.createElement('td');
      const pwCode = document.createElement('code');
      pwCode.textContent = c.password;
      pwCell.appendChild(pwCode);
      tr.appendChild(nameCell);
      tr.appendChild(pwCell);
      tbody.appendChild(tr);
    }

    const creds = result.credentials || [];
    document.getElementById('cohortCopyBtn').addEventListener('click', () => copyText(cohortCsv(creds)));
    document.getElementById('cohortDownloadBtn').addEventListener('click', () => downloadCohort(creds));
  }

  function cohortCsv(creds) {
    const lines = [['username', 'password', 'email'].map(csvCell).join(',')];
    for (const c of creds) lines.push([c.username, c.password, c.email].map(csvCell).join(','));
    return lines.join('\r\n');
  }

  function downloadCohort(creds) {
    const code = (currentCourseData && (currentCourseData.code || currentCourseData.course_name)) || 'course';
    const safe = String(code).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
    const blob = new Blob(['﻿' + cohortCsv(creds)], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${safe}-cohort-credentials.csv`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }

  // ==========================================================================
  // PER-STUDENT CREDENTIAL ACTIONS
  // ==========================================================================

  /**
   * Regenerate one student's password.
   *
   * Only rendered when the server said can_regenerate, but the server re-checks
   * regardless — this button is a convenience, not the authorization.
   */
  async function regenerateStudentPassword(studentId) {
    if (!confirm('Generate a new password for this student?\n\nTheir current password stops working immediately, and the new one is shown only once.')) return;

    try {
      const result = await api('POST', `/courses/${currentCourseId}/roster/students/${studentId}/password`, {});
      showPasswordResult(result);
      if (typeof loadStudents === 'function') loadStudents();
    } catch (err) {
      toast(err.message || 'Could not regenerate the password', true);
    }
  }

  /**
   * Show a regenerated password once.
   *
   * Built with DOM nodes and textContent rather than innerHTML — the same rule
   * courses.html documents for renderCredentialCell. A password interpolated
   * into markup or an inline handler is one apostrophe away from breaking out
   * of the string.
   */
  function showPasswordResult(result) {
    const overlay = document.createElement('div');
    overlay.className = 'modal-overlay active';

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.style.maxWidth = '520px';

    const h2 = document.createElement('h2');
    h2.textContent = 'New password';
    modal.appendChild(h2);

    // Whether the student already has their own copy changes what the
    // instructor has to do next, so it leads rather than sitting in a footnote.
    const warn = document.createElement('div');
    warn.className = result.emailed ? 'alert alert-success' : 'alert alert-warning';
    warn.style.marginBottom = '1rem';
    warn.textContent = result.emailed
      ? `Emailed to ${result.email}. It is also shown below, once — it cannot be retrieved later.`
      : 'This is shown once and cannot be retrieved later. Give it to the student now.'
        + (result.email_note ? ` Not emailed: ${result.email_note}.` : '');
    modal.appendChild(warn);

    const box = document.createElement('div');
    box.style.cssText = 'background:var(--bg-muted,#f4f4f6); padding:0.75rem; border-radius:6px; margin-bottom:1rem;';
    const line = (label, value) => {
      const row = document.createElement('div');
      row.style.marginBottom = '0.25rem';
      const strong = document.createElement('strong');
      strong.textContent = `${label}: `;
      const code = document.createElement('code');
      code.textContent = value;
      row.appendChild(strong);
      row.appendChild(code);
      return row;
    };
    box.appendChild(line('Username', result.username || result.email));
    box.appendChild(line('Password', result.password));
    modal.appendChild(box);

    const note = document.createElement('div');
    note.style.cssText = 'font-size:0.8rem; color:var(--text-secondary,#777); margin-bottom:1rem;';
    // An expiry the instructor cannot see is an expiry they will be surprised
    // by when the student calls a week later saying the password stopped working.
    const expiry = result.expires_at
      ? ` It stops working on ${new Date(result.expires_at).toLocaleString()}.`
      : '';
    note.textContent = 'They will be asked to choose their own password at their next sign-in.'
      + expiry
      + (result.warnings && result.warnings.length ? ' ' + result.warnings.join(' ') : '');
    modal.appendChild(note);

    const buttons = document.createElement('div');
    buttons.className = 'form-buttons';
    const copyBtn = document.createElement('button');
    copyBtn.className = 'btn btn-secondary';
    copyBtn.textContent = 'Copy password';
    copyBtn.addEventListener('click', () => copyText(result.password));
    const doneBtn = document.createElement('button');
    doneBtn.className = 'btn btn-primary';
    doneBtn.textContent = 'Done';
    doneBtn.addEventListener('click', () => overlay.remove());
    buttons.appendChild(copyBtn);
    buttons.appendChild(doneBtn);
    modal.appendChild(buttons);

    overlay.appendChild(modal);
    document.body.appendChild(overlay);
  }

  /** Reissue an invitation link, invalidating any earlier one. */
  async function resendStudentActivation(studentId) {
    try {
      const result = await api('POST', `/courses/${currentCourseId}/roster/students/${studentId}/activation/resend`, {});
      toast(result.note || 'Invitation sent');
    } catch (err) {
      toast(err.message || 'Could not send the invitation', true);
    }
  }

  // ==========================================================================
  // EXPORTS (inline onclick handlers in courses.html reference these)
  // ==========================================================================

  window.regenerateStudentPassword = regenerateStudentPassword;
  window.resendStudentActivation = resendStudentActivation;

  window.showCohortModal = showCohortModal;
  window.previewCohort = previewCohort;
  window.confirmCohort = confirmCohort;
  window.backToCohortInput = () => setCohortStage('input');
  window.closeCohortModal = () => closeModal('cohortModal');

  window.showRosterImportModal = showRosterImportModal;
  window.onRosterFileChosen = onRosterFileChosen;
  window.parseRosterInput = parseRosterInput;
  window.previewRosterImport = previewRosterImport;
  window.confirmRosterImport = confirmRosterImport;
  window.backToRosterInput = () => setStage('input');
  window.closeRosterImportModal = () => closeModal('rosterImportModal');
})();
