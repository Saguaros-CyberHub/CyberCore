/**
 * ============================================================================
 * ADMIN — Support Tickets tab
 * ============================================================================
 * The staff queue, with filters and a detail modal. Lazy: nothing loads until
 * the tab is opened, matching admin-broadcast.js.
 *
 * THIS FILE CALLS API.request('/tickets…'), NOT the page's local api() helper.
 * admin-core.js's api(method, path) hard-codes an /api/admin prefix, and there
 * is deliberately no /api/admin/tickets — one router scopes by role internally
 * so instructors and admins share the same endpoints and the same authorization
 * rule. api() here would 404 on every call.
 *
 * The sidebar widget (public/js/ticket-widget.js) shows the same tickets in a
 * modal on every page. That is the personal- and instructor-scale view; this is
 * the one with filters and pagination, for a queue that can run to hundreds.
 * ============================================================================
 */

const TICKET_BADGES = {
  open: 'badge-info', in_progress: 'badge-primary', pending: 'badge-warning',
  resolved: 'badge-success', closed: 'badge-muted',
};
const TICKET_LABELS = {
  open: 'Open', in_progress: 'In Progress', pending: 'Pending',
  resolved: 'Resolved', closed: 'Closed',
};

let _ticketsLoaded = false;
let _ticketDetailId = null;

/** Lazy tab activation — one load on first open, refresh on demand after. */
function ticketsTabActivate() {
  if (_ticketsLoaded) return;
  _ticketsLoaded = true;
  ticketsLoad();
}

function tkChip(status) {
  const cls = TICKET_BADGES[status] || 'badge-muted';
  return `<span class="badge ${cls}">${Utils.escapeHtml(TICKET_LABELS[status] || status)}</span>`;
}

async function ticketsLoad() {
  const wrap = document.getElementById('tkTable');
  const counts = document.getElementById('tkCounts');
  if (!wrap) return;
  wrap.innerHTML = '<p style="color:var(--text-muted)">Loading…</p>';

  try {
    const status = document.getElementById('tkFilterStatus').value;
    const q = document.getElementById('tkFilterQ').value.trim();
    const params = new URLSearchParams();
    if (status) params.set('status', status);
    if (q) params.set('q', q);
    params.set('limit', '200');

    const [data, stats] = await Promise.all([
      API.request(`/tickets?${params.toString()}`),
      API.request('/tickets/stats'),
    ]);

    counts.innerHTML = Object.entries(stats.counts)
      .map(([s, n]) => `${tkChip(s)} <span style="margin-right:.75rem">${n}</span>`).join('');

    if (!data.tickets.length) {
      wrap.innerHTML = '<p style="color:var(--text-muted)">No tickets match that filter.</p>';
      return;
    }

    wrap.innerHTML = `
      <div class="table-container">
        <table class="table">
          <thead><tr>
            <th>#</th><th>Subject</th><th>From</th><th>Course</th>
            <th>Machine</th><th>Status</th><th>Opened</th>
          </tr></thead>
          <tbody>${data.tickets.map(t => `
            <tr style="cursor:pointer" onclick="ticketDetail('${Utils.escapeHtml(t.ticketId)}')">
              <td>${Utils.escapeHtml(t.ticketNumber)}</td>
              <td>${Utils.escapeHtml(t.subject)}</td>
              <td>${Utils.escapeHtml(t.requesterName || t.requesterEmail || '')}</td>
              <td>${Utils.escapeHtml(t.courseCode || t.courseName || '—')}</td>
              <td>${Utils.escapeHtml(t.machineLabel || '—')}</td>
              <td>${tkChip(t.status)}</td>
              <td style="white-space:nowrap">${Utils.escapeHtml(Utils.formatDateTime(t.createdAt))}</td>
            </tr>`).join('')}
          </tbody>
        </table>
      </div>
      <p style="color:var(--text-muted);font-size:.85em;margin-top:.5rem;">
        Showing ${data.tickets.length} of ${data.total}.</p>`;
  } catch (err) {
    wrap.innerHTML = `<div class="alert alert-danger">${Utils.escapeHtml(err.message)}</div>`;
  }
}

/**
 * The detail modal.
 *
 * Built on demand and appended to body once, then reused — the same idiom the
 * other admin tabs use for their modals.
 */
function tkEnsureModal() {
  if (document.getElementById('ticketDetailModal')) return;
  const el = document.createElement('div');
  el.id = 'ticketDetailModal';
  // The chat launcher is z-index 9999 and .modal-overlay is 1000, so it floats
  // over this dialog's buttons. layout.css already defines the lift.
  el.className = 'modal-overlay ticket-modal-overlay';
  el.innerHTML = `
    <div class="modal" role="dialog" aria-modal="true" style="max-width:720px;">
      <div class="modal-header">
        <span class="modal-title" id="tkDetailTitle">Ticket</span>
        <button class="modal-close" aria-label="Close" onclick="closeModal('ticketDetailModal')">&times;</button>
      </div>
      <div class="modal-body" id="tkDetailBody"></div>
    </div>`;
  document.body.appendChild(el);
  el.addEventListener('click', e => { if (e.target === el) closeModal('ticketDetailModal'); });
}

async function ticketDetail(ticketId) {
  tkEnsureModal();
  _ticketDetailId = ticketId;
  const body = document.getElementById('tkDetailBody');
  body.innerHTML = '<div class="loading-spinner" style="margin:2rem auto;"></div>';
  document.getElementById('ticketDetailModal').classList.add('active');

  try {
    const data = await API.request(`/tickets/${encodeURIComponent(ticketId)}`);
    const t = data.ticket;
    document.getElementById('tkDetailTitle').textContent = `#${t.ticketNumber} · ${t.subject}`;

    const thread = data.events.map(e => {
      if (e.kind === 'status') {
        return `<div style="color:var(--text-muted);font-size:.85em;padding:.35rem 0;">
          ${Utils.escapeHtml(e.authorName || 'Someone')} set the status to
          ${Utils.escapeHtml(TICKET_LABELS[e.toStatus] || e.toStatus)} ·
          ${Utils.escapeHtml(Utils.formatDateTime(e.createdAt))}</div>`;
      }
      const internal = e.visibility === 'internal';
      return `<div style="padding:.6rem .8rem;margin:.5rem 0;border-radius:var(--border-radius);
                  background:var(--bg-card-hover);${internal
                    ? 'border-left:3px solid var(--warning,#d69e2e);' : ''}">
        <div style="font-size:.85em;color:var(--text-muted);margin-bottom:.3rem;">
          ${Utils.escapeHtml(e.authorName || 'Unknown')} ·
          ${Utils.escapeHtml(Utils.formatDateTime(e.createdAt))}
          ${internal ? ' · <strong>Internal note — students cannot see this</strong>' : ''}
        </div>
        <div style="white-space:pre-wrap">${Utils.escapeHtml(e.body)}</div>
      </div>`;
    }).join('');

    const facts = [
      ['From', `${t.requesterName || ''} <${t.requesterEmail || ''}>`],
      ['Course', [t.courseCode, t.courseName].filter(Boolean).join(' — ') || '—'],
      ['Machine', t.machineLabel ? `${t.machineLabel}${t.machineVmid ? ` (VM ${t.machineVmid})` : ''}` : '—'],
      ['Opened', Utils.formatDateTime(t.createdAt)],
    ];

    body.innerHTML = `
      <div style="margin-bottom:.75rem;">${tkChip(t.status)}</div>
      <table class="table" style="margin-bottom:1rem;">
        ${facts.map(([k, v]) => `<tr><td style="width:120px;color:var(--text-muted)">${
          Utils.escapeHtml(k)}</td><td>${Utils.escapeHtml(v)}</td></tr>`).join('')}
      </table>
      ${thread}
      <hr style="border:none;border-top:1px solid var(--border-color);margin:1rem 0;">
      <div class="form-group">
        <label class="form-label" for="tkDetailStatus">Status</label>
        <div style="display:flex;gap:.5rem;">
          <select id="tkDetailStatus" class="form-select">
            ${data.statuses.map(s => `<option value="${Utils.escapeHtml(s.value)}"${
              s.value === t.status ? ' selected' : ''}>${Utils.escapeHtml(s.label)}</option>`).join('')}
          </select>
          <button class="btn btn-secondary" onclick="ticketSetStatus(this)">Change</button>
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="tkDetailBodyText">Message</label>
        <textarea id="tkDetailBodyText" class="form-textarea" rows="4"
          placeholder="A reply is emailed to the student and copies the instructor. An internal note is not."></textarea>
      </div>
      <div style="display:flex;gap:.5rem;justify-content:flex-end;">
        <button class="btn btn-outline" onclick="ticketPost(this, 'note')">Add internal note</button>
        <button class="btn btn-primary" onclick="ticketPost(this, 'reply')">Post reply</button>
      </div>`;
  } catch (err) {
    body.innerHTML = `<div class="alert alert-danger">${Utils.escapeHtml(err.message)}</div>`;
  }
}

async function ticketSetStatus(btn) {
  const next = document.getElementById('tkDetailStatus').value;
  Utils.setBtnLoading(btn, true, 'Saving…');
  try {
    const out = await API.request(`/tickets/${encodeURIComponent(_ticketDetailId)}/status`, {
      method: 'PATCH', body: { status: next },
    });
    // The server no-ops a move to the same status and sends nothing. Say which
    // happened rather than claiming an email that did not go out.
    Toast.success('Status', out.changed
      ? `Now ${TICKET_LABELS[next] || next}. The student has been emailed.`
      : `Already ${TICKET_LABELS[next] || next}. Nothing was sent.`);
    await ticketDetail(_ticketDetailId);
    ticketsLoad();
  } catch (err) {
    Toast.error('Could not change the status', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

async function ticketPost(btn, kind) {
  const bodyText = document.getElementById('tkDetailBodyText').value.trim();
  if (!bodyText) return Toast.warning('Empty', 'Write something first.');

  // Posting an internal note when you meant to reply is a quiet mistake: the
  // student sees nothing and hears nothing, and the ticket looks answered.
  if (kind === 'note' && !await Confirm.show({
    title: 'Add an internal note?',
    message: 'Staff only. The student will not see this and will not be emailed.',
    confirmText: 'Add note',
  })) return;

  Utils.setBtnLoading(btn, true, 'Posting…');
  try {
    await API.request(`/tickets/${encodeURIComponent(_ticketDetailId)}/${kind}`, {
      method: 'POST', body: { body: bodyText },
    });
    Toast.success('Posted', kind === 'note'
      ? 'Internal note added. Nobody was emailed.'
      : 'Reply sent. The student has been emailed and the instructor copied.');
    await ticketDetail(_ticketDetailId);
    ticketsLoad();
  } catch (err) {
    Toast.error('Could not post', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}
