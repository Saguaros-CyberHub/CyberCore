// ============================================================================
// BROADCAST
// ============================================================================
//
// Compose one message, see exactly who gets it, send it to yourself first, then
// queue it. Every number on this screen comes from the server: the browser
// never decides who is emailable, because that policy lives in mailer.js and a
// second copy here would drift from it within a release.
//
// The tab is lazy (see the onclick in admin.html) - nothing here is fetched
// until somebody opens it.

// ── state ───────────────────────────────────────────────────────────────────

let _bcUsers = [];               // every account, for the hand-pick list
let _bcPicked = new Set();       // user_ids ticked by hand; survives filtering
let _bcExcludeSelf = false;      // lives here, not in the DOM, because the
                                 // audience panel is rebuilt on every resolve
let _bcRenderTimer = null;
let _bcRenderSeq = 0;            // api() has no AbortSignal, so stale renders
                                 // are dropped by sequence number instead
let _bcLoaded = false;

/**
 * escHtml() (admin-core.js) escapes & < > but NOT quotes, so it is unsafe for
 * an attribute. Most of this file uses data-* and event delegation instead;
 * this exists for the few places a value really does belong in an attribute.
 */
function escAttr(str) {
  return String(str ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

// ── activation ──────────────────────────────────────────────────────────────

async function broadcastTabActivate() {
  paintBroadcastMailBanner();
  if (_bcLoaded) return;
  _bcLoaded = true;

  const filter = document.getElementById('broadcastUserFilter');
  if (filter) filter.addEventListener('input', renderBroadcastUserList);

  // One delegated listener rather than an onchange per row: the list is
  // rebuilt on every keystroke in the filter box.
  const list = document.getElementById('broadcastUserList');
  if (list) {
    list.addEventListener('change', (e) => {
      const cb = e.target.closest('input.bc-user');
      if (!cb) return;
      if (cb.checked) _bcPicked.add(cb.value); else _bcPicked.delete(cb.value);
      updateBroadcastPickedCount();
    });
  }

  if (!window.__mailStatus && typeof loadMailStatus === 'function') loadMailStatus();

  await loadBroadcastUsers();
  loadBroadcastCampaigns();
  renderBroadcastPreview();
}

/**
 * Says up front whether anything can actually be sent.
 *
 * The distinction that matters: "Send test to me" bypasses the queue and so
 * does not need MAIL_ENCRYPT_KEY, while a real broadcast stores an encrypted
 * body and is suppressed without one. A successful test is therefore not proof
 * a broadcast will go out, which is exactly the false confidence this banner
 * exists to prevent.
 */
function paintBroadcastMailBanner() {
  const box = document.getElementById('broadcastMailBanner');
  if (!box) return;

  const s = window.__mailStatus;
  if (!s) { box.innerHTML = ''; return; }

  const ready = s.enabled && s.encryption_key_configured;
  const sendBtn = document.getElementById('broadcastSendBtn');

  if (ready) {
    const notes = [];
    const allow = (s.allowed_recipient_domains || []);
    if (allow.length) {
      notes.push(`<strong>This server only delivers to ${escHtml(allow.join(', '))}.</strong>
        Everyone outside those domains is suppressed, so an "all users" audience may reach far fewer people than it names.`);
    }
    // Config that parses fine and still cannot deliver - worth saying before a
    // send hangs rather than after.
    for (const hint of [s.hint_port, s.hint_auth].filter(Boolean)) notes.push(escHtml(hint));

    box.innerHTML = notes.length
      ? `<div style="padding: 0.6rem 0.85rem; border-radius: 8px; background: #fffbeb; color: #b7791f;">
           &#9888; ${notes.join('<div style="margin-top: 0.4rem;"></div>')}
         </div>`
      : '';
    if (sendBtn) { sendBtn.disabled = false; sendBtn.style.opacity = '1'; }
    return;
  }

  const hints = [s.hint, s.hint_key].filter(Boolean).map(h => `<div style="margin-top: 0.3rem;">${escHtml(h)}</div>`).join('');
  box.innerHTML = `<div style="padding: 0.75rem 0.85rem; border-radius: 8px; background: #fed7d7; color: #9b2c2c;">
      <strong>Nothing will be sent from this server.</strong> Every message would be recorded as suppressed.
      ${hints}
      <div style="margin-top: 0.4rem; font-size: 0.82rem;">You can still send a test to yourself &mdash; that path bypasses the queue, so its succeeding does not mean a broadcast would.</div>
    </div>`;
  if (sendBtn) { sendBtn.disabled = true; sendBtn.style.opacity = '0.5'; }
}

// ── audience: the hand-pick list ────────────────────────────────────────────

async function loadBroadcastUsers() {
  try {
    // The Users tab's endpoint, unchanged. It already returns everything the
    // picker and the organization dropdown need.
    _bcUsers = await api('GET', '/users');
  } catch (e) {
    _bcUsers = [];
    const list = document.getElementById('broadcastUserList');
    if (list) list.innerHTML = `<p style="color: #e53e3e; font-size: 0.82rem; padding: 0.5rem;">Could not load users: ${escHtml(e.message)}</p>`;
    return;
  }

  const orgSelect = document.getElementById('broadcastOrg');
  if (orgSelect) {
    const orgs = [...new Set(_bcUsers.map(u => u.organization).filter(Boolean))].sort();
    orgSelect.innerHTML = '<option value="">Any organization</option>'
      + orgs.map(o => `<option value="${escAttr(o)}">${escHtml(o)}</option>`).join('');
  }

  renderBroadcastUserList();
}

function renderBroadcastUserList() {
  const list = document.getElementById('broadcastUserList');
  if (!list) return;

  const needle = (document.getElementById('broadcastUserFilter')?.value || '').trim().toLowerCase();
  const matches = _bcUsers.filter(u => {
    if (!needle) return true;
    const hay = `${u.first_name || ''} ${u.last_name || ''} ${u.email || ''}`.toLowerCase();
    return hay.includes(needle);
  });

  if (matches.length === 0) {
    list.innerHTML = `<p style="color: var(--gray-500); font-size: 0.82rem; padding: 0.5rem; margin: 0;">No accounts match.</p>`;
    return;
  }

  // Capped for the DOM's sake, not for correctness - the filter box is how you
  // reach anyone past the cap, and the count says so.
  const shown = matches.slice(0, 200);
  list.innerHTML = shown.map(u => {
    const name = [u.first_name, u.last_name].filter(Boolean).join(' ');
    return `<label class="bc-pick">
        <input type="checkbox" class="bc-user" value="${escAttr(u.id)}"${_bcPicked.has(u.id) ? ' checked' : ''}>
        <span style="flex: 1; min-width: 0;">
          <span style="display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escHtml(name || u.email)}</span>
          ${name ? `<span style="color: var(--gray-500); font-size: 0.75rem;">${escHtml(u.email)}</span>` : ''}
        </span>
        <span class="badge badge-gray" style="flex: 0 0 auto;">${escHtml(u.role || '')}</span>
      </label>`;
  }).join('')
  + (matches.length > shown.length
      ? `<p style="color: var(--gray-500); font-size: 0.78rem; padding: 0.4rem; margin: 0;">${matches.length - shown.length} more &mdash; narrow the filter to reach them.</p>`
      : '');

  updateBroadcastPickedCount();
}

function updateBroadcastPickedCount() {
  const el = document.getElementById('broadcastPickedCount');
  if (el) el.textContent = _bcPicked.size ? `(${_bcPicked.size} selected)` : '';
}

// ── reading the form ────────────────────────────────────────────────────────

function collectBroadcastAudience() {
  const org = document.getElementById('broadcastOrg')?.value || '';
  return {
    roles: [...document.querySelectorAll('#broadcastRoles .bc-role:checked')].map(c => c.value),
    activity: document.getElementById('broadcastActivity')?.value || null,
    organizations: org ? [org] : [],
    userIds: [..._bcPicked],
    addresses: document.getElementById('broadcastAddresses')?.value || '',
    excludeSelf: _bcExcludeSelf,
  };
}

function collectBroadcastMessage() {
  return {
    subject: document.getElementById('broadcastSubject')?.value || '',
    bodyText: document.getElementById('broadcastBody')?.value || '',
    buttonLabel: document.getElementById('broadcastButtonLabel')?.value || '',
    buttonUrl: document.getElementById('broadcastButtonUrl')?.value || '',
    includeGreeting: document.getElementById('broadcastGreeting')?.checked !== false,
  };
}

function insertBroadcastMerge(key) {
  const ta = document.getElementById('broadcastBody');
  if (!ta) return;
  const token = `{{${key}}}`;
  const start = ta.selectionStart ?? ta.value.length;
  const end = ta.selectionEnd ?? start;
  ta.value = ta.value.slice(0, start) + token + ta.value.slice(end);
  ta.focus();
  ta.selectionStart = ta.selectionEnd = start + token.length;
  queueBroadcastRender();
}

// ── live preview ────────────────────────────────────────────────────────────

function queueBroadcastRender() {
  clearTimeout(_bcRenderTimer);
  _bcRenderTimer = setTimeout(renderBroadcastPreview, 500);
}

/**
 * The preview is rendered by the SAME server function that renders the send.
 * Building it in the browser would be faster and would eventually lie.
 */
async function renderBroadcastPreview() {
  const frame = document.getElementById('broadcastPreviewFrame');
  const note = document.getElementById('broadcastPreviewNote');
  const errBox = document.getElementById('broadcastMessageErrors');
  if (!frame) return;

  const seq = ++_bcRenderSeq;
  try {
    const data = await api('POST', '/broadcast/render', { message: collectBroadcastMessage() });
    if (seq !== _bcRenderSeq) return;   // a later keystroke already won

    // srcdoc as a property: the shell is a full document full of quotes, and
    // an innerHTML template literal would shred the attribute.
    frame.srcdoc = data.message.html;

    if (note) {
      note.textContent = data.personalized
        ? `Personalized - shown as ${data.rendered_for?.email || 'you'} would see it`
        : 'Identical for every recipient';
    }
    if (errBox) {
      errBox.innerHTML = (data.errors || []).length
        ? `<div style="color: #b7791f;">${data.errors.map(e => `&#9888; ${escHtml(e)}`).join('<br>')}</div>`
        : '';
    }
  } catch (e) {
    if (seq !== _bcRenderSeq) return;
    if (errBox) errBox.innerHTML = `<div style="color: #e53e3e;">Preview failed: ${escHtml(e.message)}</div>`;
  }
}

// ── audience resolution ─────────────────────────────────────────────────────

async function resolveBroadcastAudience() {
  const btn = document.getElementById('broadcastResolveBtn');
  Utils.setBtnLoading(btn, true, 'Resolving...');
  try {
    const data = await requestBroadcastPreview();
    renderBroadcastAudienceResult(data);
    return data;
  } catch (e) {
    document.getElementById('broadcastAudienceResult').innerHTML =
      `<div style="color: #e53e3e;">${escHtml(e.message)}</div>`;
    Toast.error('Could not resolve audience', e.message);
    return null;
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

function requestBroadcastPreview() {
  return api('POST', '/broadcast/preview', {
    audience: collectBroadcastAudience(),
    message: collectBroadcastMessage(),
  });
}

function renderBroadcastAudienceResult(data) {
  const box = document.getElementById('broadcastAudienceResult');
  if (!box) return;

  const s = data.summary;
  let html = `<div style="display: grid; grid-template-columns: 1fr 1fr; gap: 0.5rem; margin-bottom: 0.75rem;">
      <div style="padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 6px;">
        <span style="color: var(--gray-500);">Will receive</span><br>
        <strong style="font-size: 1.15rem; color: ${s.deliverable ? '#38a169' : '#e53e3e'};">${s.deliverable}</strong>
      </div>
      <div style="padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 6px;">
        <span style="color: var(--gray-500);">Suppressed</span><br>
        <strong style="font-size: 1.15rem;">${s.suppressed}</strong>
      </div>
    </div>`;

  for (const err of data.errors || []) {
    html += `<div style="background: #fed7d7; color: #9b2c2c; padding: 0.5rem 0.7rem; border-radius: 6px; margin-bottom: 0.4rem;">${escHtml(err)}</div>`;
  }
  for (const warn of data.warnings || []) {
    html += `<div style="background: #fffbeb; color: #b7791f; padding: 0.5rem 0.7rem; border-radius: 6px; margin-bottom: 0.4rem;">&#9888; ${escHtml(warn)}</div>`;
  }

  if ((data.suppression || []).length) {
    html += `<table class="admin-table" style="margin-top: 0.5rem;"><thead><tr><th>Not sent, because</th><th style="width: 60px;">Count</th></tr></thead><tbody>`;
    for (const group of data.suppression) {
      html += `<tr><td>${escHtml(group.reason)}<div style="color: var(--gray-500); font-size: 0.75rem;">${escHtml(group.examples.join(', '))}${group.count > group.examples.length ? ', ...' : ''}</div></td>
        <td><strong>${group.count}</strong></td></tr>`;
    }
    html += `</tbody></table>`;
  }

  if (data.self_included) {
    html += `<label style="display: flex; align-items: center; gap: 0.4rem; margin-top: 0.7rem; font-size: 0.82rem;">
        <input type="checkbox" id="broadcastExcludeSelf"${_bcExcludeSelf ? ' checked' : ''} onchange="toggleBroadcastExcludeSelf(this.checked)">
        You are in this audience &mdash; tick to leave yourself out
      </label>`;
  }

  if (s.duplicates_removed) {
    html += `<p style="color: var(--gray-500); font-size: 0.78rem; margin: 0.5rem 0 0;">
        From ${s.sources.filter || 0} by filter, ${s.sources.picked || 0} picked, ${s.sources.pasted || 0} pasted.
      </p>`;
  }

  box.innerHTML = html;
}

function toggleBroadcastExcludeSelf(checked) {
  _bcExcludeSelf = !!checked;
  resolveBroadcastAudience();
}

// ── test send ───────────────────────────────────────────────────────────────

async function sendBroadcastTest() {
  const btn = document.getElementById('broadcastTestBtn');
  const status = document.getElementById('broadcastStatus');
  Utils.setBtnLoading(btn, true, 'Sending...');
  status.innerHTML = '';
  try {
    const result = await api('POST', '/broadcast/test', { message: collectBroadcastMessage() });
    status.innerHTML = `<strong style="color: #38a169;">&#10003; Sent to ${escHtml(result.to)}</strong>
      <div style="margin-top: 0.3rem; color: var(--gray-500);">${escHtml(result.note || '')}</div>
      ${result.warning ? `<div style="margin-top: 0.3rem; color: #b7791f;">&#9888; ${escHtml(result.warning)}</div>` : ''}`;
    Toast.success('Test Sent', `The relay accepted a message for ${result.to}`);
  } catch (e) {
    // A refusal is the diagnostic, not an incidental error - it is the relay's
    // own words about why it will not take the message.
    status.innerHTML = `<strong style="color: #e53e3e;">Not sent:</strong> ${escHtml(e.message)}`;
    Toast.error('Test Failed', e.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

// ── send ────────────────────────────────────────────────────────────────────

async function previewAndSendBroadcast() {
  const btn = document.getElementById('broadcastSendBtn');
  Utils.setBtnLoading(btn, true, 'Checking...');
  try {
    const data = await requestBroadcastPreview();
    renderBroadcastAudienceResult(data);
    showBroadcastConfirmation(data);
  } catch (e) {
    Toast.error('Could not prepare send', e.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

/**
 * The confirm step. Deliberately not showDeployConfirmation(): that helper
 * renders VM counts and its modal is titled "Confirm Deployment".
 */
function showBroadcastConfirmation(data) {
  const body = document.getElementById('broadcastConfirmBody');
  const confirmBtn = document.getElementById('broadcastConfirmBtn');
  const title = document.getElementById('broadcastConfirmTitle');
  const s = data.summary;
  const blocked = (data.errors || []).length > 0 || s.deliverable === 0;

  // The details view borrows this modal and hides the action button, so reset
  // both here rather than relying on a close handler - Cancel calls closeModal()
  // directly and would never restore them.
  if (title) title.textContent = 'Send this broadcast?';
  confirmBtn.style.display = '';

  let html = `<div style="margin-bottom: 0.9rem;">
      <div style="font-size: 0.85rem; color: var(--gray-500);">Subject</div>
      <div style="font-weight: 600;">${escHtml(document.getElementById('broadcastSubject').value || '(none)')}</div>
    </div>
    <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem; margin-bottom: 0.9rem;">
      <div style="padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 6px;">
        <span style="color: var(--gray-500); font-size: 0.8rem;">Recipients</span><br><strong style="font-size: 1.1rem;">${s.deliverable}</strong>
      </div>
      <div style="padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 6px;">
        <span style="color: var(--gray-500); font-size: 0.8rem;">Suppressed</span><br><strong style="font-size: 1.1rem;">${s.suppressed}</strong>
      </div>
      <div style="padding: 0.5rem 0.75rem; background: var(--bg-card-hover); border-radius: 6px;">
        <span style="color: var(--gray-500); font-size: 0.8rem;">Drains in about</span><br><strong style="font-size: 1.1rem;">${data.estimate.minutes} min</strong>
      </div>
    </div>`;

  if (data.estimate.backlog > 0) {
    html += `<div style="background: #fffbeb; color: #b7791f; padding: 0.6rem 0.75rem; border-radius: 8px; margin-bottom: 0.6rem;">
        &#9888; ${data.estimate.backlog} message(s) are already queued. The mail worker sends
        ${data.estimate.batch_per_tick} every ${data.estimate.poll_seconds}s in the order they were queued,
        so anything enqueued after this &mdash; a roster import's activation links, for instance &mdash; waits behind it.
      </div>`;
  }

  for (const err of data.errors || []) {
    html += `<div style="background: #fed7d7; color: #9b2c2c; padding: 0.6rem 0.75rem; border-radius: 8px; margin-bottom: 0.5rem;"><strong>Cannot send:</strong> ${escHtml(err)}</div>`;
  }
  for (const warn of data.warnings || []) {
    html += `<div style="background: #fffbeb; color: #b7791f; padding: 0.6rem 0.75rem; border-radius: 8px; margin-bottom: 0.5rem;">&#9888; ${escHtml(warn)}</div>`;
  }

  html += `<p style="color: var(--gray-500); font-size: 0.82rem; margin: 0.6rem 0 0;">
      This cannot be recalled once queued. Send a test to yourself first if you have not.
    </p>`;

  body.innerHTML = html;

  if (blocked) {
    confirmBtn.disabled = true;
    confirmBtn.textContent = 'Blocked';
    confirmBtn.style.opacity = '0.5';
  } else {
    confirmBtn.disabled = false;
    confirmBtn.textContent = `Send to ${s.deliverable}`;
    confirmBtn.style.opacity = '1';
  }

  confirmBtn.onclick = () => {
    closeModal('broadcastConfirmModal');
    confirmBroadcastSend(data.fingerprint);
  };

  document.getElementById('broadcastConfirmModal').classList.add('active');
}

async function confirmBroadcastSend(fingerprint) {
  const btn = document.getElementById('broadcastSendBtn');
  const status = document.getElementById('broadcastStatus');
  Utils.setBtnLoading(btn, true, 'Queueing...');
  status.innerHTML = '';
  try {
    const result = await api('POST', '/broadcast/send', {
      audience: collectBroadcastAudience(),
      message: collectBroadcastMessage(),
      fingerprint,
    });
    status.innerHTML = `<strong style="color: #38a169;">&#10003; Queued ${result.queued} message(s).</strong>
      <div style="margin-top: 0.3rem; color: var(--gray-500);">
        Expect delivery to finish in about ${result.estimated_minutes} minute(s). Campaign
        <code>${escHtml(result.campaign_id)}</code>.
      </div>`;
    Toast.success('Broadcast Queued', `${result.queued} message(s) on their way`);
    loadBroadcastCampaigns();
  } catch (e) {
    if (e.status === 409) {
      // The audience or the message moved between preview and confirm. Not an
      // error to dismiss - re-resolve and make them look at the new numbers.
      Toast.warning('Audience changed', 'Numbers have been refreshed - review and confirm again.');
      status.innerHTML = `<strong style="color: #b7791f;">${escHtml(e.message)}</strong>`;
      const fresh = await resolveBroadcastAudience();
      if (fresh) showBroadcastConfirmation(fresh);
    } else {
      status.innerHTML = `<strong style="color: #e53e3e;">Not sent:</strong> ${escHtml(e.message)}`;
      Toast.error('Send Failed', e.message);
    }
  } finally {
    Utils.setBtnLoading(btn, false);
  }
}

// ── history ─────────────────────────────────────────────────────────────────

async function loadBroadcastCampaigns() {
  const box = document.getElementById('broadcastCampaigns');
  if (!box) return;
  try {
    const data = await api('GET', '/broadcast/campaigns');
    if (!data.campaigns.length) {
      box.innerHTML = `<p style="color: var(--gray-500); font-size: 0.85rem;">No broadcasts in the last ${data.retention_days} days.</p>`;
      return;
    }
    box.innerHTML = `<table class="admin-table">
        <thead><tr><th>Sent</th><th>Subject</th><th>Delivered</th><th>Pending</th><th>Failed</th><th></th></tr></thead>
        <tbody>${data.campaigns.map(c => `<tr>
            <td>${escHtml(new Date(c.started_at).toLocaleString())}</td>
            <td>${escHtml(c.subject)}</td>
            <td><span class="badge badge-green">${c.sent} / ${c.total}</span></td>
            <td>${c.queued + c.sending}</td>
            <td>${c.failed ? `<span class="badge badge-red">${c.failed}</span>` : '0'}</td>
            <td><button class="btn btn-sm btn-outline bc-campaign" data-campaign="${escAttr(c.campaign_id)}">Details</button></td>
          </tr>`).join('')}</tbody>
      </table>`;

    box.querySelectorAll('.bc-campaign').forEach(btn => {
      btn.addEventListener('click', () => viewBroadcastCampaign(btn.dataset.campaign));
    });
  } catch (e) {
    box.innerHTML = `<p style="color: #e53e3e; font-size: 0.85rem;">Could not load broadcasts: ${escHtml(e.message)}</p>`;
  }
}

async function viewBroadcastCampaign(campaignId) {
  try {
    const data = await api('GET', `/broadcast/campaigns/${encodeURIComponent(campaignId)}`);
    const body = document.getElementById('broadcastConfirmBody');
    body.innerHTML = `<table class="admin-table">
        <thead><tr><th>Recipient</th><th>Status</th><th>Detail</th></tr></thead>
        <tbody>${data.messages.map(m => `<tr>
            <td>${escHtml(m.to_address)}</td>
            <td><span class="badge ${m.status === 'sent' ? 'badge-green' : m.status === 'failed' ? 'badge-red' : 'badge-gray'}">${escHtml(m.status)}</span></td>
            <td style="color: var(--gray-500); font-size: 0.8rem;">${escHtml(m.last_error || (m.sent_at ? new Date(m.sent_at).toLocaleString() : ''))}</td>
          </tr>`).join('')}</tbody>
      </table>`;

    const title = document.getElementById('broadcastConfirmTitle');
    if (title) title.textContent = 'Delivery report';
    // Read-only view: there is nothing to confirm. showBroadcastConfirmation()
    // puts the button back.
    document.getElementById('broadcastConfirmBtn').style.display = 'none';
    document.getElementById('broadcastConfirmModal').classList.add('active');
  } catch (e) {
    Toast.error('Could not load campaign', e.message);
  }
}
