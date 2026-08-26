/**
 * ============================================================================
 * TICKET WIDGET — the Submit a Ticket modal, on every page with a sidebar
 * ============================================================================
 * Loaded lazily by Layout.ensureTicketWidget(), so no page needs a script tag.
 *
 * WHY THIS IS NOT IN layout.js
 * layout.js is evaluated inside stub VM contexts by test/sidebar-nav.test.js and
 * test/view-mode-nav.test.js. Fetch-driven modal code there means a new stub
 * every time this changes, and eventually a test that passes because it stubbed
 * away the thing under test.
 *
 * THREE TABS, ONE CONTROL, NO NEW PAGE
 *   New Ticket    — everyone
 *   My Tickets    — everyone: the tickets you filed, whatever your role
 *   Course Tickets— instructors and admins: the queue they can act on
 *
 * A new page would need a server route, a role gate AND a sidebar entry — and
 * the sidebar is data-driven from cybercore_module, so a "Support" entry means
 * a table seed and a display_order argument with CLE and Crucible. For a list
 * this size the modal is the right shape. Admins who want filters and
 * pagination have the Admin page's Support Tickets tab.
 * ============================================================================
 */

const TicketWidget = {
  _mounted: false,
  _form: null,        // { courses, machines, notice, ... } from GET /form
  _tab: 'new',
  _detailId: null,

  // ── mounting ─────────────────────────────────────────────────────────────

  /**
   * Build the overlay once, on document.body.
   *
   * NOT inside #sidebar: injectSidebar() replaces that element's innerHTML
   * wholesale on the `authReady` re-render, which would wipe a half-typed
   * ticket out from under the person writing it.
   */
  mount() {
    if (this._mounted || document.getElementById('ticketModalOverlay')) return;
    const el = document.createElement('div');
    el.id = 'ticketModalOverlay';
    el.className = 'modal-overlay ticket-modal-overlay';
    el.innerHTML = this.markup();
    document.body.appendChild(el);

    // Click-outside and Escape both close. Bound once, here, rather than on
    // every open.
    el.addEventListener('click', e => { if (e.target === el) this.close(); });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && el.classList.contains('active')) this.close();
    });
    this._mounted = true;
  },

  markup() {
    return `
      <div class="modal" role="dialog" aria-modal="true" aria-labelledby="ticketModalTitle"
           style="max-width: 680px;">
        <div class="modal-header">
          <span class="modal-title" id="ticketModalTitle">Support</span>
          <button class="modal-close" aria-label="Close" onclick="TicketWidget.close()">&times;</button>
        </div>
        <div class="tabs" id="ticketTabs" style="padding:0 1.25rem;"></div>
        <div class="modal-body" id="ticketModalBody"></div>
      </div>`;
  },

  // ── open / close ─────────────────────────────────────────────────────────

  async open(tab) {
    this.mount();
    document.getElementById('ticketModalOverlay').classList.add('active');
    this._tab = tab || 'new';
    this._detailId = null;
    this.renderTabs();
    await this.renderTab();
  },

  close() {
    const el = document.getElementById('ticketModalOverlay');
    if (el) el.classList.remove('active');
  },

  isStaff() {
    return typeof Auth !== 'undefined' && (Auth.isAdmin?.() || Auth.isInstructor?.());
  },

  renderTabs() {
    const tabs = [
      ['new', 'New Ticket'],
      ['mine', 'My Tickets'],
    ];
    // data-instructor-only means Student View hides it with no JS —
    // layout.css already carries that rule.
    if (this.isStaff()) tabs.push(['queue', 'Course Tickets']);

    document.getElementById('ticketTabs').innerHTML = tabs.map(([key, label]) => `
      <button class="tab-btn ${this._tab === key ? 'active' : ''}"
              ${key === 'queue' ? 'data-instructor-only' : ''}
              onclick="TicketWidget.switchTab('${key}')">${label}</button>`).join('');
  },

  async switchTab(tab) {
    this._tab = tab;
    this._detailId = null;
    this.renderTabs();
    await this.renderTab();
  },

  async renderTab() {
    const body = document.getElementById('ticketModalBody');
    body.innerHTML = '<div class="loading-spinner" style="margin:2rem auto;"></div>';
    try {
      if (this._tab === 'new') return await this.renderNew(body);
      return await this.renderList(body, this._tab === 'mine' ? '/tickets/mine' : '/tickets');
    } catch (err) {
      body.innerHTML = `<div class="alert alert-danger">${esc(err.message)}</div>`;
    }
  },
};

/** Local escape — Utils is loaded on every page, but never assume it here. */
function esc(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// ── the form ────────────────────────────────────────────────────────────────

Object.assign(TicketWidget, {
  /**
   * Bootstrap on OPEN, not on page load: one request per use rather than one
   * per page view, on a control most people never touch.
   */
  async renderNew(body) {
    if (!this._form) this._form = await API.request('/tickets/form');
    const f = this._form;

    // globalSuppression() verbatim from the server. Saying this BEFORE they
    // write is the whole point — afterwards it is just a suppressed row nobody
    // looks at.
    const notice = f.notice
      ? `<div class="alert alert-warning">Email is not configured on this server, so your
           ticket will be recorded but nobody will be notified by email.
           <span style="opacity:.75">(${esc(f.notice)})</span></div>`
      : '';

    const courseOptions = f.courses.length
      ? f.courses.map(c => `<option value="${esc(c.courseId)}">${esc(c.label)}</option>`).join('')
      : `<option value="" disabled>${f.coursesUnavailable
            ? 'Course list unavailable right now'
            : 'No enrolled courses'}</option>`;

    body.innerHTML = `
      ${notice}
      <div class="form-group">
        <label class="form-label" for="tkSubject">What is wrong?</label>
        <input id="tkSubject" class="form-input" maxlength="${f.limits.subject}"
               placeholder="Cannot reach my Kali box">
        <small class="form-hint">
          Keep this short, and don't put passwords or private details here —
          subject lines appear in mail notifications and server logs.
        </small>
      </div>
      <div class="form-group">
        <label class="form-label" for="tkCourse">Course <span style="color:var(--text-muted)">(optional)</span></label>
        <select id="tkCourse" class="form-select" onchange="TicketWidget.filterMachines()">
          <option value="">Not related to a course</option>
          ${courseOptions}
        </select>
      </div>
      <div class="form-group">
        <label class="form-label" for="tkMachine">Machine <span style="color:var(--text-muted)">(optional)</span></label>
        <select id="tkMachine" class="form-select"></select>
      </div>
      <div class="form-group">
        <label class="form-label" for="tkBody">What happened?</label>
        <textarea id="tkBody" class="form-textarea" rows="6" maxlength="${f.limits.body}"
                  placeholder="What you tried, what you expected, and what happened instead."></textarea>
      </div>
      <div class="modal-footer" style="padding-left:0;padding-right:0;">
        <button class="btn btn-secondary" onclick="TicketWidget.close()">Cancel</button>
        <button class="btn btn-primary" id="tkSubmit" onclick="TicketWidget.submit(this)">Submit ticket</button>
      </div>`;
    this.filterMachines();
  },

  /**
   * Narrow the machine list to the chosen course.
   *
   * Machines with no course are ALWAYS kept: self-service workstations and
   * lanes from the deploy-group path carry no course reference, and a student
   * whose problem is with one of those must still be able to name it.
   */
  filterMachines() {
    const courseId = document.getElementById('tkCourse')?.value || '';
    const sel = document.getElementById('tkMachine');
    if (!sel) return;
    const list = (this._form.machines || [])
      .filter(m => !courseId || !m.courseId || m.courseId === courseId);
    sel.innerHTML = `<option value="">Not about a specific machine</option>` + list.map(m => {
      const suffix = m.vmid ? ` (VM ${m.vmid})` : '';
      return `<option value="${esc(m.key)}">${esc(m.label)}${esc(suffix)}</option>`;
    }).join('');
  },

  async submit(btn) {
    const subject = document.getElementById('tkSubject').value.trim();
    const bodyText = document.getElementById('tkBody').value.trim();
    if (!subject || !bodyText) {
      return Toast.warning('Missing', 'Please fill in both the summary and the description.');
    }
    Utils.setBtnLoading(btn, true, 'Submitting…');
    try {
      const out = await API.request('/tickets', {
        method: 'POST',
        body: {
          subject,
          body: bodyText,
          courseId: document.getElementById('tkCourse').value || null,
          machineKey: document.getElementById('tkMachine').value || null,
        },
      });
      const n = out.ticket.ticketNumber;
      // Report what actually happened rather than a blanket "sent": a
      // suppressed queue is a real state on an offline deployment.
      const sent = out.notified.status === 'queued'
        ? `Ticket #${n} — ${out.notified.admins} admin${out.notified.admins === 1 ? '' : 's'} notified.`
        : `Ticket #${n} recorded, but no email went out (${out.notified.reason || 'mail unavailable'}).`;
      Toast.success('Ticket submitted', sent);
      // Cached form data is still valid; the ticket list is not.
      await this.switchTab('mine');
    } catch (err) {
      Toast.error('Could not submit', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },
});

// ── lists and threads ───────────────────────────────────────────────────────

Object.assign(TicketWidget, {
  BADGES: {
    open: 'badge-info', in_progress: 'badge-primary', pending: 'badge-warning',
    resolved: 'badge-success', closed: 'badge-muted',
  },
  LABELS: {
    open: 'Open', in_progress: 'In Progress', pending: 'Pending',
    resolved: 'Resolved', closed: 'Closed',
  },

  chip(status) {
    return `<span class="badge ${this.BADGES[status] || 'badge-muted'}">${esc(this.LABELS[status] || status)}</span>`;
  },

  when(iso) {
    if (!iso) return '';
    try { return new Date(iso).toLocaleString(); } catch { return String(iso); }
  },

  async renderList(body, endpoint) {
    const data = await API.request(endpoint);
    if (!data.tickets.length) {
      body.innerHTML = `<p style="color:var(--text-muted);text-align:center;padding:2rem 0;">
        ${endpoint === '/tickets/mine'
          ? 'You have not submitted any tickets.'
          : 'No tickets for your courses.'}</p>`;
      return;
    }
    const unavailable = data.coursesUnavailable
      ? `<div class="alert alert-warning">Your course list could not be loaded, so this queue may
           be showing fewer tickets than it should.</div>`
      : '';
    body.innerHTML = unavailable + `
      <div class="table-container">
        <table class="table">
          <thead><tr><th>#</th><th>Subject</th><th>Status</th><th>Opened</th></tr></thead>
          <tbody>${data.tickets.map(t => `
            <tr style="cursor:pointer" onclick="TicketWidget.detail('${esc(t.ticketId)}')">
              <td>${esc(t.ticketNumber)}</td>
              <td>${esc(t.subject)}
                ${t.courseCode ? `<div style="color:var(--text-muted);font-size:.8em">${esc(t.courseCode)}${
                    t.machineLabel ? ' · ' + esc(t.machineLabel) : ''}</div>` : ''}</td>
              <td>${this.chip(t.status)}</td>
              <td style="white-space:nowrap">${esc(this.when(t.createdAt))}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  },

  /**
   * One ticket's thread.
   *
   * Note what this does NOT do: filter internal notes. The server has already
   * removed them for anyone who is not staff on this ticket
   * (utils/ticket-access.js serializeEvents). Filtering here as well would be a
   * second, weaker copy of the rule, and the kind that gets trusted.
   */
  async detail(ticketId) {
    this._detailId = ticketId;
    const body = document.getElementById('ticketModalBody');
    body.innerHTML = '<div class="loading-spinner" style="margin:2rem auto;"></div>';
    const data = await API.request(`/tickets/${encodeURIComponent(ticketId)}`);
    const t = data.ticket;

    const thread = data.events.map(e => {
      if (e.kind === 'status') {
        return `<div style="color:var(--text-muted);font-size:.85em;padding:.4rem 0;">
          ${esc(e.authorName || 'Someone')} changed the status
          ${e.fromStatus ? `from ${esc(this.LABELS[e.fromStatus] || e.fromStatus)} ` : ''}to
          ${esc(this.LABELS[e.toStatus] || e.toStatus)} · ${esc(this.when(e.createdAt))}</div>`;
      }
      const internal = e.visibility === 'internal';
      return `<div style="padding:.6rem .8rem;margin:.5rem 0;border-radius:var(--border-radius);
                   background:var(--bg-card-hover);${internal
                     ? 'border-left:3px solid var(--warning,#d69e2e);' : ''}">
        <div style="font-size:.85em;color:var(--text-muted);margin-bottom:.3rem;">
          ${esc(e.authorName || 'Unknown')} · ${esc(this.when(e.createdAt))}
          ${internal ? ' · <strong>Internal note — students cannot see this</strong>' : ''}
        </div>
        <div style="white-space:pre-wrap">${esc(e.body)}</div>
      </div>`;
    }).join('');

    const facts = [
      t.courseCode || t.courseName ? ['Course', [t.courseCode, t.courseName].filter(Boolean).join(' — ')] : null,
      t.machineLabel ? ['Machine', t.machineLabel + (t.machineVmid ? ` (VM ${t.machineVmid})` : '')] : null,
      ['Opened by', t.requesterName || t.requesterEmail],
    ].filter(Boolean);

    body.innerHTML = `
      <button class="btn btn-ghost btn-sm" onclick="TicketWidget.switchTab('${esc(this._tab)}')">&larr; Back</button>
      <h3 style="margin:.75rem 0 .25rem;">#${esc(t.ticketNumber)} ${esc(t.subject)}</h3>
      <div style="margin-bottom:.75rem;">${this.chip(t.status)}</div>
      <div style="font-size:.85em;color:var(--text-muted);margin-bottom:1rem;">
        ${facts.map(([k, v]) => `${esc(k)}: ${esc(v)}`).join(' &middot; ')}
      </div>
      ${thread}
      ${t.canManage ? this.staffControls(t, data.statuses) : this.requesterControls(t)}`;
  },
});

// ── controls ────────────────────────────────────────────────────────────────

Object.assign(TicketWidget, {
  staffControls(t, statuses) {
    return `
      <hr style="border:none;border-top:1px solid var(--border-color);margin:1rem 0;">
      <div class="form-group">
        <label class="form-label" for="tkStatus">Status</label>
        <div style="display:flex;gap:.5rem;">
          <select id="tkStatus" class="form-select">
            ${statuses.map(s => `<option value="${esc(s.value)}"${
              s.value === t.status ? ' selected' : ''}>${esc(s.label)}</option>`).join('')}
          </select>
          <button class="btn btn-secondary" onclick="TicketWidget.changeStatus(this)">Change</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="tkReply">Message</label>
        <textarea id="tkReply" class="form-textarea" rows="4"
                  placeholder="A reply is emailed to the student. An internal note is not."></textarea>
      </div>
      <div style="display:flex;gap:.5rem;justify-content:flex-end;">
        <button class="btn btn-outline" onclick="TicketWidget.post(this, 'note')">Add internal note</button>
        <button class="btn btn-primary" onclick="TicketWidget.post(this, 'reply')">Post reply</button>
      </div>`;
  },

  requesterControls(t) {
    // Closed is the one state a student cannot talk into. Everything else can
    // be answered — especially Pending, which explicitly asks them to.
    if (t.status === 'closed') {
      return `<p style="color:var(--text-muted);font-size:.9em;">
        This ticket is closed. Submit a new one if the problem comes back.</p>`;
    }
    return `
      <hr style="border:none;border-top:1px solid var(--border-color);margin:1rem 0;">
      ${t.status === 'pending'
        ? `<div class="alert alert-warning">Support is waiting on you — please reply below.</div>` : ''}
      <div class="form-group">
        <label class="form-label" for="tkReply">Add a message</label>
        <textarea id="tkReply" class="form-textarea" rows="4"></textarea>
      </div>
      <div style="display:flex;justify-content:flex-end;">
        <button class="btn btn-primary" onclick="TicketWidget.post(this, 'comment')">Send</button>
      </div>`;
  },

  async changeStatus(btn) {
    const next = document.getElementById('tkStatus').value;
    Utils.setBtnLoading(btn, true, 'Saving…');
    try {
      const out = await API.request(`/tickets/${encodeURIComponent(this._detailId)}/status`, {
        method: 'PATCH',
        body: { status: next },
      });
      // The server treats a move to the same status as a no-op and sends
      // nothing, so say so rather than claiming the student was emailed.
      Toast.success('Status', out.changed
        ? `Now ${this.LABELS[next] || next}. The student has been emailed.`
        : `Already ${this.LABELS[next] || next}.`);
      await this.detail(this._detailId);
    } catch (err) {
      Toast.error('Could not change the status', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  async post(btn, kind) {
    const el = document.getElementById('tkReply');
    const bodyText = el.value.trim();
    if (!bodyText) return Toast.warning('Empty', 'Write something first.');

    // An internal note is invisible to the student by design, which makes
    // posting one by accident — meaning to reply — a real and quiet mistake.
    if (kind === 'note' && !await Confirm.show({
      title: 'Add an internal note?',
      message: 'Staff only. The student will not see this and will not be emailed.',
      confirmText: 'Add note',
    })) return;

    Utils.setBtnLoading(btn, true, 'Posting…');
    try {
      await API.request(`/tickets/${encodeURIComponent(this._detailId)}/${kind}`, {
        method: 'POST',
        body: { body: bodyText },
      });
      Toast.success('Posted', kind === 'note'
        ? 'Internal note added. Nobody was emailed.'
        : 'Sent, and the recipient has been emailed.');
      await this.detail(this._detailId);
    } catch (err) {
      Toast.error('Could not post', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },
});

// A ticket link in an email is /hub?ticket=<id> for every role — see
// ticketUrl() in src/utils/email-templates.js. The widget is on every page with
// a sidebar, so opening it here is all the deep link needs.
//
// DO NOT listen for DOMContentLoaded here. This file is injected by
// Layout.ensureTicketWidget(), which runs from Layout.init() — itself already
// 100ms past DOMContentLoaded. A dynamically created <script> is async, so by
// the time this line executes the event has long fired and the listener would
// never run: every emailed ticket link would land on /hub and do nothing.
function openTicketFromUrl() {
  let id = null;
  try { id = new URLSearchParams(window.location.search).get('ticket'); } catch (_) {}
  if (!id) return;
  TicketWidget.open('mine')
    .then(() => TicketWidget.detail(id))
    .catch(() => {});
}

window.TicketWidget = TicketWidget;

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', openTicketFromUrl);
} else {
  openTicketFromUrl();
}
