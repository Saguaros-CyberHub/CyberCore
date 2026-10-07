/**
 * CIAB — Modules tab controller
 * ----------------------------------------------------------------------------
 * A module is one client, one engagement and one place in a section's sequence.
 * This file owns the whole of that tab: the ordered list, create/edit, reorder,
 * CLONE — same shape, different client, which is the repetition the programme is
 * built on — prerequisite editing, archive/delete, and the resolver's diagnoses.
 *
 * LOAD ORDER IS A DEPENDENCY, NOT A PREFERENCE. instructor.html loads this file
 * last, below /ciab/js/instructor-core.js, which is the declared provider of
 * API/Toast/Confirm/Utils (via app.js), InstructorState, switchTab, openModal,
 * closeModal, esc/escapeHtml, escJs, partLabel and profileDisplayName. Moving
 * the tag above core breaks every one of them.
 *
 * The last line is `window.CiabModules = CiabModules;` and it is load-bearing:
 * a top-level `const` in a classic script is a lexical global and never becomes
 * a property of `window`, while instructor-core.js's activateTabModule() reads
 * `window.CiabModules` by property lookup. Without that one line the tab opens
 * and silently does nothing.
 *
 * NOTHING HERE DECIDES ACCESS. Every per-row control is rendered from a
 * server-computed flag — the Delete button from `capabilities.hard_delete`,
 * never from "am I an admin" — so the UI cannot offer a control the API
 * refuses. `Auth.isRealAdmin()` is deliberately absent from the render path.
 *
 * NOTHING HERE WRITES A VOCABULARY WORD EITHER. Every badge word, deliverable
 * name, release option and issue sentence comes out of the payload
 * (`labels`, `release_states`, `parts`, `issues[].message`), so a wording change
 * on the server lands without a browser cache being right about anything.
 *
 * REORDER is ▲/▼, and the request carries the FULL ordered id list rather than
 * a pair of indices. There is no drag-and-drop list anywhere in this product to
 * follow, every list here repaints by replacing innerHTML (which destroys drag
 * state), and ▲/▼ are keyboard-reachable for free on a page that already does
 * roving-tabindex arrow navigation. Because the endpoint takes the whole list,
 * a later drag implementation produces a byte-identical body and needs no
 * server change at all.
 */
/* global API, Toast, Confirm, Utils, InstructorState, esc, escapeHtml, escJs,
          openModal, closeModal, switchTab, partLabel, profileDisplayName */

// Colour only. The WORD always comes from labels.release[phase], so a phase this
// file has never heard of still renders its real label, just in a neutral badge.
const RELEASE_BADGE = {
  draft: 'badge-secondary',
  pending: 'badge-info',
  open: 'badge-success',
  closed: 'badge-muted',
  archived: 'badge-muted',
};

// Long enough to collapse a burst of ▲/▼ taps into one write, short enough that
// the sequence is saved before an instructor switches tabs.
const ORDER_DEBOUNCE_MS = 400;

// datetime-local <-> ISO, round-tripping. NOT the admin-crucible-events.js idiom
// (raw local value on write, iso.slice(0, 16) on read) — that is local on write
// and UTC on read, so it moves the value by the browser's offset every save. On
// a decorative start time that is cosmetic; on release_at, which decides whether
// a module is open, it opens the module at the wrong hour while the form
// redisplays exactly what the instructor typed.
const fromLocalInput = (v) => (v ? new Date(v).toISOString() : null);
const toLocalInput = (iso) => {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '';
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
};

/**
 * The affordance that turns a diagnosis into something the instructor can do,
 * keyed by issue.code and consulted AT RUNTIME — an unknown code renders its
 * sentence with no button and throws nothing. An issue nobody can act on is a
 * log line, not a banner.
 *
 * Each entry is a function of the issue, because the target is not always the
 * module the issue is filed against: PREREQ_UNPUBLISHED is reported on the
 * module that is stuck, and the fix is on the earlier one named in its detail.
 */
const ISSUE_ACTIONS = {
  PREREQ_CYCLE: (i) => (i.module_id
    ? { label: 'Edit prerequisites', onclick: `CiabModules.showPrereqs('${escJs(i.module_id)}')` }
    : null),
  PREREQ_MISSING: (i) => (i.module_id
    ? { label: 'Edit prerequisites', onclick: `CiabModules.showPrereqs('${escJs(i.module_id)}')` }
    : null),
  PREREQ_UNPUBLISHED: (i) => {
    const target = i.detail && i.detail.prereq_module_id;
    return target
      ? { label: 'Publish the earlier module', onclick: `CiabModules.showModuleModal('${escJs(target)}','release')` }
      : null;
  },
  SCHEDULED_WITHOUT_DATE: (i) => (i.module_id
    ? { label: 'Set a release time', onclick: `CiabModules.showModuleModal('${escJs(i.module_id)}','release_at')` }
    : null),
  CLOSE_BEFORE_RELEASE: (i) => (i.module_id
    ? { label: 'Fix the window', onclick: `CiabModules.showModuleModal('${escJs(i.module_id)}','close_at')` }
    : null),
  CLIENT_UNBOUND: (i) => (i.module_id
    ? { label: 'Choose a client', onclick: `CiabModules.showModuleModal('${escJs(i.module_id)}','client')` }
    : null),
  DUPLICATE_POSITION: () => ({ label: 'Renumber the sequence', onclick: 'CiabModules.normalizePositions()' }),
  // The sentence already names the remedy, and the remedy is "publish one",
  // which is the New Module button and every row's Edit.
  NO_PUBLISHED_MODULES: () => null,
  SHARED_ENVIRONMENT: (i) => {
    const ids = (i.detail && i.detail.module_ids) || [];
    return ids.length
      ? { label: 'Show these modules', onclick: `CiabModules.highlight('${escJs(ids.join(','))}')` }
      : null;
  },
};

const CiabModules = {
  sections: [],
  sectionId: null,

  view: null,
  modules: [],
  clients: [],
  labels: {},
  releaseStates: [],
  parts: [],
  capabilities: {},

  editingId: null,
  cloningId: null,
  prereqId: null,

  _savingOrder: false,
  _orderDirty: false,
  _orderTimer: null,
  _profilesBound: false,

  // API.request already prefixes /api. ciab-api.js is untouched: it defines no
  // request function of its own, it is a set of namespace extensions on app.js's
  // API — and API.modules there is core's plugin-discovery namespace, read by
  // public/js/layout.js, which is exactly why this object is CiabModules.
  api(path, options = {}) {
    return API.request(`/instructor/sections/${this.sectionId}/modules${path}`, options);
  },

  // -------------------------------------------------------------------------
  // Load
  // -------------------------------------------------------------------------

  async load() {
    // instructor.html ships #modulesMain as style="display: none;", so a
    // skeleton, an error card and its Retry button all painted INSIDE it were
    // invisible until the sections fetch resolved — which on the failure path it
    // never does. Unhidden HERE, before anything is painted and before anything
    // is awaited; the no-sections branch below re-hides it.
    this.showMain(true);

    const container = document.getElementById('moduleListContent');
    // Paint the loading state BEFORE anything is awaited. instructor-core.js
    // calls switchTab() before its dashboard fetch, so a deep link to #modules
    // activates this tab while nothing at all is loaded.
    if (container) {
      container.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(3);
    }
    const issues = document.getElementById('moduleIssues');
    if (issues) issues.innerHTML = '';

    // AFTER the paint, which is synchronous on purpose, and BEFORE the first
    // await that can change this.sectionId: a debounced reorder belongs to the
    // section it was made in, and saveOrder reads this.sectionId and this.modules
    // at fire time.
    await this.flushPendingOrder();

    this.bindProfiles();

    let sections;
    try {
      // Its own fetch, deliberately. InstructorState.sections comes from the
      // dashboard and carries no status; Sections.all carries it but belongs to
      // another tab. Reading either couples this tab to a fetch it does not own.
      const res = await API.request('/instructor/sections');
      sections = res.sections || [];
    } catch (err) {
      this.renderLoadFailure(err);
      return;
    }
    this.sections = sections;

    if (!this.sections.length) {
      this.showMain(false);
      return;
    }
    this.showMain(true);

    // Keep the instructor where they were, and inherit the Sections tab's
    // selection when they have just come from it.
    const has = (id) => !!id && this.sections.some((s) => s.section_id === id);
    if (!has(this.sectionId)) {
      const fromSections = window.Sections && Sections.currentId;
      this.sectionId = has(fromSections) ? fromSections : this.sections[0].section_id;
    }

    const select = document.getElementById('moduleSectionSelect');
    if (select) {
      select.innerHTML = this.sections.map((s) => {
        const bits = [s.name];
        if (s.code) bits.push(`(${s.code})`);
        if (s.term) bits.push(`— ${s.term}`);
        if (s.status === 'archived') bits.push('· archived');
        return `<option value="${esc(s.section_id)}">${esc(bits.join(' '))}</option>`;
      }).join('');
      select.value = this.sectionId;
    }

    await this.onSectionChange();
  },

  async onSectionChange() {
    // BEFORE this.sectionId is reassigned and before this.modules is replaced:
    // a pending reorder was made against the section still in those two fields,
    // and saveOrder reads both at FIRE time. Without this flush the move is
    // either dropped on the floor or POSTed against the section the instructor
    // just switched to.
    await this.flushPendingOrder();

    const select = document.getElementById('moduleSectionSelect');
    if (select && select.value) this.sectionId = select.value;
    if (!this.sectionId) return;

    const container = document.getElementById('moduleListContent');
    if (container) {
      container.innerHTML = '<div class="skeleton skel-row"></div>'.repeat(3);
    }

    let payload;
    try {
      payload = await this.api('');
    } catch (err) {
      this.renderLoadFailure(err);
      return;
    }

    this.view = payload;
    this.modules = payload.modules || [];
    this.clients = payload.clients || [];
    this.labels = payload.labels || {};
    this.releaseStates = payload.release_states || [];
    this.parts = payload.parts || [];
    this.capabilities = payload.capabilities || {};

    this.renderMeta();
    this.renderIssues();
    this.render();
  },

  // #modulesMain and #modulesNoSection are the two halves of one switch, so
  // they move together and nothing else touches either style.
  showMain(on) {
    const none = document.getElementById('modulesNoSection');
    const main = document.getElementById('modulesMain');
    if (none) none.style.display = on ? 'none' : '';
    if (main) main.style.display = on ? '' : 'none';
  },

  renderLoadFailure(err) {
    Toast.error('Could not load the modules', err.message);
    // The card below, and the Retry button that is the only way out of this
    // state, live INSIDE #modulesMain. A toast fades; a permanently blank tab
    // does not.
    this.showMain(true);
    const container = document.getElementById('moduleListContent');
    if (!container) return;
    container.innerHTML = `
      <div class="empty-state">
        <div class="icon">⚠️</div>
        <h3>Could not load the modules</h3>
        <p>${esc(err.message || 'Unknown error')}</p>
        <button class="btn btn-primary" onclick="CiabModules.load()">Retry</button>
      </div>`;
  },

  // The dashboard's profile list can land after this tab has already painted.
  // It never feeds the picker — the endpoint's clients[] does, because that
  // query is a union that also covers a co-instructor's bound clients — it only
  // tops the list up if it arrives while a modal is open.
  bindProfiles() {
    if (this._profilesBound) return;
    if (!window.InstructorState || typeof InstructorState.on !== 'function') return;
    this._profilesBound = true;
    InstructorState.on('profiles', () => {
      const modal = document.getElementById('moduleModal');
      if (modal && modal.classList.contains('active')) {
        const current = this.fieldValue('moduleProfile');
        this.populateClientSelect('moduleProfile', current, this.fieldValue('moduleClientFilter'));
      }
      const clone = document.getElementById('moduleCloneModal');
      if (clone && clone.classList.contains('active')) {
        const current = this.fieldValue('moduleCloneProfile');
        this.populateClientSelect('moduleCloneProfile', current, this.fieldValue('moduleCloneClientFilter'));
      }
    });
  },

  // -------------------------------------------------------------------------
  // Small DOM helpers — every one tolerates a missing element, so a modal field
  // that has not been added to the page yet cannot throw halfway through a
  // populate and leave the rest of the form holding the previous module's data.
  // -------------------------------------------------------------------------

  fieldValue(id) {
    const el = document.getElementById(id);
    return el ? String(el.value ?? '') : '';
  },

  setField(id, value) {
    const el = document.getElementById(id);
    if (el) el.value = value == null ? '' : value;
  },

  setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text == null ? '' : text;
  },

  moduleById(id) {
    if (id == null) return null;
    const wanted = String(id);
    return this.modules.find((m) => String(m.module_id) === wanted) || null;
  },

  moduleTitle(id) {
    const m = this.moduleById(id);
    if (m) return m.title;
    return `Module ${String(id || '').slice(0, 8)}`;
  },

  clientName(profileId) {
    if (!profileId) return '';
    const wanted = String(profileId);
    const c = this.clientList().find((x) => String(x.id) === wanted);
    if (!c) return `Client ${wanted.slice(0, 8)}`;
    return c.company_name || c.client_type_name || c.industry || `Client ${wanted.slice(0, 8)}`;
  },

  // clients[] first and authoritative; the dashboard's own profiles only fill
  // gaps. No comparator: the server already returns these ordered by company.
  clientList() {
    const seen = new Set();
    const out = [];
    for (const c of this.clients || []) {
      const id = String(c.id ?? '');
      if (!id || seen.has(id)) continue;
      seen.add(id);
      out.push(c);
    }
    const profiles = (window.InstructorState && InstructorState.profiles) || [];
    for (const p of profiles) {
      const id = String(p.id ?? '');
      if (!id || seen.has(id)) continue;
      seen.add(id);
      out.push(p);
    }
    return out;
  },

  // -------------------------------------------------------------------------
  // Section meta line
  // -------------------------------------------------------------------------

  renderMeta() {
    const meta = document.getElementById('moduleSectionMeta');
    if (!meta) return;
    const v = this.view || {};
    const s = v.section || {};
    const counts = v.counts || {};
    const releaseLabels = this.labels.release || {};

    const bits = [];
    bits.push(`${counts.total || 0} module(s)`);
    for (const key of ['draft', 'pending', 'open', 'closed', 'archived']) {
      if (counts[key]) bits.push(`${counts[key]} ${releaseLabels[key] || key}`);
    }
    bits.push(`${v.roster_size || 0} enrolled`);
    if (s.status === 'archived') {
      bits.push('this section is archived — its students have no Clinic-in-a-Box access');
    }
    meta.textContent = bits.join(' · ');
  },

  // -------------------------------------------------------------------------
  // Issues — the resolver's diagnoses, and this tab's reason to exist
  // -------------------------------------------------------------------------

  // The title an instructor reads above the server's sentence: whose problem is
  // it. Section-wide issues carry a null module_id by design.
  issueTitle(issue) {
    return issue.module_id ? this.moduleTitle(issue.module_id) : 'This section';
  },

  issueEntry(issue) {
    const weight = issue.severity === 'error' ? ' error' : (issue.severity === 'warning' ? ' warn' : '');
    const builder = ISSUE_ACTIONS[issue.code];
    let action = null;
    try {
      action = typeof builder === 'function' ? builder(issue) : null;
    } catch (e) {
      action = null;
    }
    const button = action
      ? `<button class="btn btn-sm btn-outline" onclick="${action.onclick}">${esc(action.label)}</button>`
      : '';
    return `
      <div class="action-item${weight}">
        <div>
          <strong>${esc(this.issueTitle(issue))}</strong>
          <div class="action-item-detail">${esc(issue.message)}</div>
        </div>
        ${button}
      </div>`;
  },

  renderIssues() {
    const container = document.getElementById('moduleIssues');
    if (!container) return;
    const all = (this.view && this.view.issues) || [];
    if (!all.length) { container.innerHTML = ''; return; }

    // Partition, not a comparator: errors above warnings above info, and inside
    // each severity the order the resolver already chose, which is module order.
    const errors = all.filter((i) => i.severity === 'error');
    const warns = all.filter((i) => i.severity === 'warning');
    const infos = all.filter((i) => i.severity !== 'error' && i.severity !== 'warning');
    const loud = errors.length + warns.length;

    if (!loud) {
      container.innerHTML = `
        <div style="margin-bottom: 1rem; display: flex; flex-direction: column; gap: 0.5rem;">
          ${infos.map((i) => this.issueEntry(i)).join('')}
        </div>`;
      return;
    }

    const entries = [...errors, ...warns, ...infos];
    container.innerHTML = `
      <div class="card" style="margin-bottom: 1rem;">
        <div class="card-header">
          <span class="card-title">Needs attention (${loud})</span>
        </div>
        <div class="card-body">
          <div class="action-item-list">${entries.map((i) => this.issueEntry(i)).join('')}</div>
        </div>
      </div>`;
  },

  // A mutation's warnings[] share the issue shape exactly, so the same builder
  // decides what they say — the instructor is told at the moment they cause it,
  // and the banner keeps saying it afterwards.
  applyWarnings(res) {
    const list = (res && res.warnings) || [];
    for (const w of list) {
      const title = this.issueTitle(w);
      if (w.severity === 'error') Toast.error(title, w.message);
      else if (w.severity === 'warning') Toast.warning(title, w.message);
      else Toast.info(title, w.message);
    }
  },

  // -------------------------------------------------------------------------
  // List
  // -------------------------------------------------------------------------

  hideArchived() {
    const box = document.getElementById('moduleHideArchived');
    return !!(box && box.checked);
  },

  visibleModules() {
    return this.hideArchived()
      ? this.modules.filter((m) => m.release_state !== 'archived')
      : this.modules.slice();
  },

  render() {
    const container = document.getElementById('moduleListContent');
    if (!container) return;

    const sectionName = (this.view && this.view.section && this.view.section.name) || 'this section';

    if (!this.modules.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">🧩</div>
          <h3>No modules in ${esc(sectionName)} yet</h3>
          <p>A module is one client, one engagement and one place in the sequence.<br>
             Build the first one, then clone it onto another client — that is how a term gets its repetition.</p>
          <button class="btn btn-primary" onclick="CiabModules.showModuleModal()">＋ New Module</button>
        </div>`;
      return;
    }

    const rows = this.visibleModules();
    if (!rows.length) {
      container.innerHTML = `
        <div class="empty-state">
          <div class="icon">📦</div>
          <h3>Everything here is put away</h3>
          <p>Every module in ${esc(sectionName)} has been archived. Untick <strong>Hide archived</strong> to see them.</p>
        </div>`;
      return;
    }

    // RENDERED IN THE ORDER THE SERVER RETURNED. The server's order is
    // (position, created_at, module_id); a browser sort on position alone
    // disagrees with it the moment two rows tie, which is exactly the state
    // DUPLICATE_POSITION reports.
    const body = rows.map((m, i) => this.row(m, i, rows.length)).join('');
    const footer = this.hideArchived()
      ? `<p style="color: var(--gray-500); font-size: 0.85rem; margin-top: 0.5rem;">${rows.length} of ${this.modules.length} shown</p>`
      : '';

    container.innerHTML = `
      <div class="card"><div class="card-body" style="padding: 0; overflow-x: auto;">
        <table class="data-table" style="width: 100%;">
          <thead><tr>
            <th style="width: 5.5rem;">#</th>
            <th>Module</th><th>Client</th><th>Engagement</th><th>Deliverable</th>
            <th>Release</th><th>Prereqs</th><th>Cohort</th>
            <th style="text-align: right;">Actions</th>
          </tr></thead>
          <tbody>${body}</tbody>
        </table>
      </div></div>${footer}`;
  },

  row(m, i, total) {
    const id = String(m.module_id);
    const jsId = escJs(id);
    const archived = m.release_state === 'archived';

    // Disabled while a save is in flight, rather than spinner-ised: the row is
    // re-rendered during the await, so Utils.setBtnLoading's finally would
    // restore innerHTML onto a detached node while the live button sat idle.
    const busy = this._savingOrder ? ' disabled' : '';
    const up = `<button class="btn btn-sm btn-icon" title="Move up" aria-label="Move up"${i === 0 ? ' disabled' : busy} onclick="CiabModules.move('${jsId}',-1)">▲</button>`;
    const down = `<button class="btn btn-sm btn-icon" title="Move down" aria-label="Move down"${i === total - 1 ? ' disabled' : busy} onclick="CiabModules.move('${jsId}',1)">▼</button>`;

    const briefSnippet = m.brief
      ? `<div style="color: var(--gray-500); font-size: 0.8rem;">${esc(String(m.brief).replace(/\s+/g, ' ').slice(0, 90))}${String(m.brief).length > 90 ? '…' : ''}</div>`
      : '';
    const problem = (m.prereq_problems || []).length
      ? ` <span title="${esc(`Prerequisite problem: ${(m.prereq_problems || []).join(', ')}`)}">⚠️</span>`
      : '';

    const client = m.profile_id
      ? esc(this.clientName(m.profile_id))
      : '<span class="badge badge-warning">No client</span>';

    const peers = (m.shares_environment_with || []).length;
    const shared = peers
      ? ` <span title="${esc(`Shares one environment with ${peers} other module(s)`)}">🔗</span>`
      : '';

    const part = m.assessment_part
      ? `<span title="${esc(partLabel(m.assessment_part))}">Part ${esc(m.assessment_part)}</span>`
      : '—';

    const phase = m.release_phase;
    const releaseLabels = this.labels.release || {};
    const badgeClass = RELEASE_BADGE[phase] || 'badge-secondary';
    const windowBits = [];
    if (m.release_at) windowBits.push(`Opens ${Utils.formatDateTime(m.release_at)}`);
    if (m.close_at) windowBits.push(`Closes ${Utils.formatDateTime(m.close_at)}`);
    const release = `<span class="badge ${badgeClass}">${esc(releaseLabels[phase] || phase || '—')}</span>`
      + (windowBits.length
        ? `<div style="color: var(--gray-500); font-size: 0.75rem; margin-top: 0.2rem;">${esc(windowBits.join(' · '))}</div>`
        : '');

    const requires = (m.requires_module_ids || []).length;
    const requiredBy = (m.required_by_module_ids || []).length;
    const prereqs = `<button class="btn btn-sm btn-outline" onclick="CiabModules.showPrereqs('${jsId}')" title="Edit prerequisites">⛓ ${requires}</button>`
      + (requiredBy ? ` <span style="color: var(--gray-500); font-size: 0.75rem;">· ${requiredBy} follow</span>` : '');

    // BRANCH ON students ITSELF, never on students.enrolled: the rollup is null
    // only when no roster was SUPPLIED. An empty roster is a real answer — zero
    // enrolled — and gets the zeroed rollup.
    let cohort = '—';
    if (m.students) {
      const completionLabels = this.labels.completion || {};
      const done = (m.students.completion && m.students.completion.complete) || 0;
      cohort = `${done}/${m.students.enrolled || 0} ${esc(completionLabels.complete || 'complete')}`;
      if (m.students.blocked_by_prereq) {
        cohort += ` <span class="badge badge-warning">${m.students.blocked_by_prereq} blocked</span>`;
      }
    }

    const actions = [];
    actions.push(`<button class="btn btn-sm btn-outline" onclick="CiabModules.showModuleModal('${jsId}')">Edit</button>`);
    actions.push(`<button class="btn btn-sm btn-outline" onclick="CiabModules.showCloneModal('${jsId}')">Clone</button>`);
    actions.push(`<button class="btn btn-sm btn-outline" onclick="CiabModules.showPrereqs('${jsId}')">Prereqs</button>`);
    actions.push(archived
      ? `<button class="btn btn-sm btn-primary" onclick="CiabModules.restoreModule('${jsId}')">Restore</button>`
      : `<button class="btn btn-sm btn-outline" onclick="CiabModules.archiveModule('${jsId}')">Archive</button>`);
    // Server-computed. The UI must never work out "am I an admin" for itself.
    if (this.capabilities.hard_delete) {
      actions.push(`<button class="btn btn-sm btn-danger" onclick="CiabModules.deleteModule('${jsId}')">Delete</button>`);
    }

    return `<tr data-module-id="${esc(id)}"${archived ? ' class="mod-archived"' : ''}>
      <td><span class="mod-pos">${i + 1}</span><span class="mod-order-btns">${up}${down}</span></td>
      <td><strong>${esc(m.title)}</strong>${problem}${briefSnippet}</td>
      <td>${client}</td>
      <td><code>${esc(m.engagement_type || 'default')}</code>${shared}</td>
      <td>${part}</td>
      <td>${release}</td>
      <td style="white-space: nowrap;">${prereqs}</td>
      <td>${cohort}</td>
      <td style="text-align: right; white-space: nowrap;">${actions.join(' ')}</td>
    </tr>`;
  },

  // SHARED_ENVIRONMENT's affordance: point at the rows it is talking about.
  highlight(ids) {
    const wanted = String(ids || '').split(',').map((s) => s.trim()).filter(Boolean);
    if (!wanted.length) return;
    // A highlighted module may be one of the archived rows currently filtered
    // out; showing nothing at all would read as a broken button.
    const box = document.getElementById('moduleHideArchived');
    if (box && box.checked && wanted.some((id) => {
      const m = this.moduleById(id);
      return m && m.release_state === 'archived';
    })) {
      box.checked = false;
      this.render();
    }
    const container = document.getElementById('moduleListContent');
    if (!container) return;
    let first = null;
    container.querySelectorAll('tr[data-module-id]').forEach((tr) => {
      if (!wanted.includes(tr.dataset.moduleId)) return;
      tr.classList.add('mod-flash');
      if (!first) first = tr;
      setTimeout(() => tr.classList.remove('mod-flash'), 2500);
    });
    if (first && first.scrollIntoView) first.scrollIntoView({ block: 'center', behavior: 'smooth' });
  },
};

// ---------------------------------------------------------------------------
// Create / edit
// ---------------------------------------------------------------------------

CiabModules.populateClientSelect = function populateClientSelect(selectId, selectedId, query) {
  const select = document.getElementById(selectId);
  if (!select) return;
  const q = String(query || '').trim().toLowerCase();
  const all = this.clientList();
  const rows = q ? all.filter((c) => profileDisplayName(c).toLowerCase().includes(q)) : all;

  // The bound client always stays selectable, even when it does not match the
  // filter and even when it belongs to a co-instructor: a <select> that cannot
  // re-select the current value turns a title edit into a silent unbinding.
  const wanted = selectedId ? String(selectedId) : '';
  if (wanted && !rows.some((c) => String(c.id) === wanted)) {
    const bound = all.find((c) => String(c.id) === wanted);
    if (bound) rows.unshift(bound);
  }

  select.innerHTML = '<option value="">— No client yet —</option>'
    + rows.map((c) => `<option value="${esc(c.id)}">${esc(profileDisplayName(c))}</option>`).join('');
  select.value = wanted;
};

CiabModules.filterClients = function filterClients(target) {
  const clone = target === 'clone';
  const filterId = clone ? 'moduleCloneClientFilter' : 'moduleClientFilter';
  const selectId = clone ? 'moduleCloneProfile' : 'moduleProfile';
  this.populateClientSelect(selectId, this.fieldValue(selectId), this.fieldValue(filterId));
};

// Type-ahead with no library: the engagement slugs already in use in this
// section, offered as a datalist. Free text still wins — a new engagement is
// created by typing its name.
CiabModules.populateEngagementList = function populateEngagementList() {
  const seen = new Set();
  for (const m of this.modules) {
    const t = m.engagement_type;
    if (t) seen.add(String(t));
  }
  const options = [...seen].map((t) => `<option value="${esc(t)}"></option>`).join('');
  for (const listId of ['moduleEngagementList', 'moduleCloneEngagementList']) {
    const el = document.getElementById(listId);
    if (el) el.innerHTML = options;
  }
};

CiabModules.populateReleaseSelect = function populateReleaseSelect(selectId, selected) {
  const select = document.getElementById(selectId);
  if (!select) return;
  const releaseLabels = this.labels.release || {};
  const states = this.releaseStates.length ? this.releaseStates : [selected].filter(Boolean);
  select.innerHTML = states
    .map((s) => `<option value="${esc(s)}">${esc(releaseLabels[s] || s)}</option>`).join('');
  select.value = selected || states[0] || '';
};

CiabModules.populatePartSelect = function populatePartSelect(selectId, selected) {
  const select = document.getElementById(selectId);
  if (!select) return;
  select.innerHTML = '<option value="">— None —</option>'
    + this.parts.map((p) => `<option value="${esc(p.number)}">${esc(`Part ${p.number} — ${p.name}`)}</option>`).join('');
  select.value = selected == null ? '' : String(selected);
};

CiabModules.showModuleModal = function showModuleModal(moduleId, focusField) {
  const m = moduleId ? this.moduleById(moduleId) : null;
  this.editingId = m ? String(m.module_id) : null;

  this.setText('moduleModalTitle', m ? 'Edit Module' : 'New Module');
  this.setField('moduleTitle', m ? m.title : '');
  this.setField('moduleClientFilter', '');
  this.populateClientSelect('moduleProfile', m ? m.profile_id : '', '');
  this.populateEngagementList();
  this.setField('moduleEngagement', m ? (m.engagement_type || '') : '');
  this.populatePartSelect('modulePart', m ? m.assessment_part : null);
  this.populateReleaseSelect('moduleReleaseState', m ? m.release_state : 'draft');
  this.setField('moduleReleaseAt', m ? toLocalInput(m.release_at) : '');
  this.setField('moduleCloseAt', m ? toLocalInput(m.close_at) : '');
  // <input type="datetime-local"> carries no zone, and fromLocalInput converts
  // through whatever zone THIS browser is set to. Without saying so, a
  // co-instructor two timezones away reads a different wall-clock time out of
  // the same field with nothing on screen explaining why. Guarded:
  // resolvedOptions is not required to report a timeZone, and an empty <small>
  // is better than the word 'undefined' under a release time.
  let tz = '';
  try { tz = (Intl.DateTimeFormat().resolvedOptions() || {}).timeZone || ''; } catch (e) { tz = ''; }
  this.setText('moduleReleaseTz', tz ? `Times are in ${tz}.` : '');
  this.setField('moduleBrief', m ? (m.brief || '') : '');
  this.setField('moduleNotes', m ? (m.instructor_notes || '') : '');

  // openModal is the only path that records the opener and restores focus on
  // close, so it is never bypassed with classList.add('active').
  openModal('moduleModal');

  // Which control an issue's Fix button lands on. The whole mechanism behind
  // "surface a diagnosis where the instructor can act on it".
  const targetId = {
    title: 'moduleTitle',
    client: 'moduleProfile',
    engagement: 'moduleEngagement',
    part: 'modulePart',
    release: 'moduleReleaseState',
    release_at: 'moduleReleaseAt',
    close_at: 'moduleCloseAt',
    brief: 'moduleBrief',
    notes: 'moduleNotes',
  }[focusField];
  if (targetId) {
    const el = document.getElementById(targetId);
    if (el && el.focus) el.focus();
  }
};

CiabModules.saveModule = async function saveModule(event) {
  if (event) event.preventDefault();
  const btn = document.getElementById('moduleSaveBtn');

  const partValue = this.fieldValue('modulePart');
  const body = {
    title: this.fieldValue('moduleTitle').trim(),
    brief: this.fieldValue('moduleBrief').trim() || null,
    instructor_notes: this.fieldValue('moduleNotes').trim() || null,
    profile_id: this.fieldValue('moduleProfile') || null,
    engagement_type: this.fieldValue('moduleEngagement').trim() || 'default',
    assessment_part: partValue ? Number(partValue) : null,
    release_state: this.fieldValue('moduleReleaseState') || 'draft',
    release_at: fromLocalInput(this.fieldValue('moduleReleaseAt')),
    close_at: fromLocalInput(this.fieldValue('moduleCloseAt')),
  };

  Utils.setBtnLoading(btn, true, 'Saving…');
  try {
    const editing = this.editingId;
    const res = await this.api(editing ? `/${editing}` : '', {
      method: editing ? 'PATCH' : 'POST',
      body,
    });
    closeModal('moduleModal');
    Toast.success('Saved', editing
      ? `${body.title} is updated`
      : `${body.title} is at the end of the sequence`);
    // Full re-fetch, never an optimistic patch of the one row: publishing this
    // module can clear or raise an issue on another one.
    await this.load();
    // AFTER the re-fetch, never before. applyWarnings titles each toast with
    // moduleTitle(w.module_id), which reads this.modules — and on a create the
    // new module is not in it yet, so every warning came out titled
    // `Module 7f3c1a90`. The banner names it correctly on the same repaint, so
    // the two disagreed on screen.
    this.applyWarnings(res);
  } catch (err) {
    Toast.error('Could not save the module', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

// ---------------------------------------------------------------------------
// Reorder
// ---------------------------------------------------------------------------

CiabModules.move = function move(moduleId, delta) {
  const id = String(moduleId);
  const visible = this.visibleModules();
  const vi = visible.findIndex((m) => String(m.module_id) === id);
  if (vi === -1) return;
  const neighbour = visible[vi + delta];
  if (!neighbour) return;

  // Move relative to the neighbouring VISIBLE row, but splice inside the FULL
  // array: with archived rows hidden, a blind ±1 in the full array would swap a
  // module past a row nobody can see and look like the button did nothing.
  const from = this.modules.findIndex((m) => String(m.module_id) === id);
  const to = this.modules.findIndex((m) => String(m.module_id) === String(neighbour.module_id));
  if (from === -1 || to === -1) return;
  const [moved] = this.modules.splice(from, 1);
  this.modules.splice(to, 0, moved);

  this.render();          // optimistic: the visible move IS the feedback
  this._orderDirty = true;
  clearTimeout(this._orderTimer);
  this._orderTimer = setTimeout(() => this.saveOrder(), ORDER_DEBOUNCE_MS);
};

/**
 * A pending debounced reorder, sent NOW rather than in 400 ms.
 *
 * saveOrder reads this.sectionId and this.modules at FIRE time, so anything that
 * reassigns either must call this first, while both still describe the section
 * the move was made in. Called from load() and from onSectionChange(), which is
 * every path that switches sections — including the clone that follows a copy
 * into another section.
 */
CiabModules.flushPendingOrder = async function flushPendingOrder() {
  if (!this._orderTimer) return;
  clearTimeout(this._orderTimer);
  this._orderTimer = null;
  await this.saveOrder();
};

CiabModules.saveOrder = async function saveOrder() {
  // Single-flight with a trailing re-send: a second burst of taps while a POST
  // is in the air is folded into one more request carrying the final order,
  // never into two requests racing to define the sequence.
  if (this._savingOrder) { this._orderDirty = true; return; }
  this._savingOrder = true;
  this.render();
  try {
    do {
      this._orderDirty = false;
      // THE FULL SET, ALWAYS. 'Hide archived' filters the RENDER only: the
      // endpoint requires every module in the section exactly once, so sending
      // just the visible ones is a guaranteed 409 that reads like a server bug.
      const order = this.modules.map((m) => m.module_id);
      const res = await this.api('/reorder', { method: 'POST', body: { order } });
      (res.order || []).forEach((mid, i) => {
        const m = this.moduleById(mid);
        if (m) m.position = i + 1;
      });
      this.applyWarnings(res);
    } while (this._orderDirty);
  } catch (err) {
    if (err.data && err.data.code === 'ORDER_STALE') {
      // A refusal, not a failure: somebody else moved something first.
      Toast.warning('The sequence changed', err.message);
    } else {
      Toast.error('Could not save the new order', err.message);
    }
    this._savingOrder = false;
    await this.load();     // the server is authoritative about the sequence
    return;
  } finally {
    this._savingOrder = false;
  }
  this.render();           // re-enable the arrows
};

// The DUPLICATE_POSITION remedy: the same write, with the order already on
// screen. The server renumbers 1..n, which is all "two modules share a position"
// ever needs.
CiabModules.normalizePositions = async function normalizePositions() {
  clearTimeout(this._orderTimer);
  this._orderTimer = null;
  await this.saveOrder();
  // AND THEN RE-FETCH, which is what every other mutation in this file does.
  // saveOrder alone writes m.position onto the in-memory rows and repaints — but
  // the # cell is the render index, not m.position, and this.modules is already
  // in the server's order, so the repaint is byte-identical. Without the
  // re-fetch, this.view.issues is untouched, the DUPLICATE_POSITION banner and
  // its own button stay on screen, and the instructor sees literally nothing
  // happen on the one control the warning told them to press.
  await this.load();
};

// ---------------------------------------------------------------------------
// Clone — the repetition mechanism: same shape, different client
// ---------------------------------------------------------------------------

CiabModules.showCloneModal = function showCloneModal(moduleId) {
  const m = this.moduleById(moduleId);
  if (!m) return;
  this.cloningId = String(m.module_id);

  this.setText('moduleCloneModalTitle', `Clone "${m.title}"`);
  // ONE control carries the source title — the labelled readonly field. The
  // <small> beside it used to print the same string a second time.
  this.setField('moduleCloneSource', m.title);

  // 255 is the column width; a source already at the limit plus ' (copy)' is a
  // truncation error on a clone that looks perfectly correct.
  this.setField('moduleCloneTitle', `${m.title} (copy)`.slice(0, 255));
  this.setField('moduleCloneClientFilter', '');
  // A DELIBERATELY BLANK CLIENT WHEN THE SOURCE HOLDS A DELIVERABLE.
  // assessment_progress is UNIQUE (user_id, profile_id, part_number) with no
  // section column, so two modules cannot share one client AND one Deliverable
  // — and a same-section clone is counted against a list that CONTAINS the
  // source. Prefilling the source's client therefore made Clone → change
  // nothing → Clone a guaranteed 409 on the tab's headline feature. The copy
  // inherits the Deliverable, so the client is the field that has to move; the
  // <small> under this select has always said so.
  const inheritsPart = m.assessment_part !== null && m.assessment_part !== undefined;
  this.populateClientSelect('moduleCloneProfile', inheritsPart ? '' : m.profile_id, '');
  this.populateEngagementList();
  this.setField('moduleCloneEngagement', m.engagement_type || '');

  const sectionSelect = document.getElementById('moduleCloneSection');
  if (sectionSelect) {
    sectionSelect.innerHTML = this.sections.map((s) => {
      const bits = [s.name];
      if (s.code) bits.push(`(${s.code})`);
      if (s.term) bits.push(`— ${s.term}`);
      return `<option value="${esc(s.section_id)}">${esc(bits.join(' '))}</option>`;
    }).join('');
    sectionSelect.value = this.sectionId;
    // Bound here as well as inline, so the reflection below cannot be lost to a
    // markup edit that forgets the attribute.
    sectionSelect.onchange = () => this.onCloneSectionChange();
  }

  const box = document.getElementById('moduleClonePrereqs');
  if (box) box.checked = true;
  const count = (m.requires_module_ids || []).length;
  this.setText('moduleClonePrereqsLabel', `Copy the ${count} prerequisite(s) this module follows`);
  this.onCloneSectionChange();

  openModal('moduleCloneModal');
};

// A client-side REFLECTION of a server rule, never a client-side decision: the
// server still refuses to copy prerequisites across a section boundary, because
// both ends of an edge must live in the same section.
CiabModules.onCloneSectionChange = function onCloneSectionChange() {
  const target = this.fieldValue('moduleCloneSection') || this.sectionId;
  const cross = String(target) !== String(this.sectionId);
  const box = document.getElementById('moduleClonePrereqs');
  if (box) {
    box.disabled = cross;
    if (cross) box.checked = false;
  }
  this.setText('moduleClonePrereqsNote', cross ? 'Prerequisites stay in their own section.' : '');
};

CiabModules.cloneModule = async function cloneModule(event) {
  if (event) event.preventDefault();
  if (!this.cloningId) return;
  const btn = document.getElementById('moduleCloneBtn');

  const target = this.fieldValue('moduleCloneSection') || this.sectionId;
  const box = document.getElementById('moduleClonePrereqs');
  const body = {
    title: this.fieldValue('moduleCloneTitle').trim(),
    profile_id: this.fieldValue('moduleCloneProfile') || null,
    engagement_type: this.fieldValue('moduleCloneEngagement').trim() || 'default',
    target_section_id: target,
    include_prereqs: !!(box && box.checked && !box.disabled),
  };

  Utils.setBtnLoading(btn, true, 'Cloning…');
  try {
    const res = await this.api(`/${this.cloningId}/clone`, { method: 'POST', body });
    closeModal('moduleCloneModal');
    Toast.success('Cloned', 'It is at the end of the sequence as a draft.');
    // Follow the copy: landing back on the source section after cloning into
    // another one hides the thing that was just made. The pending reorder is
    // flushed FIRST, because this reassignment is one of the two places that
    // moves this.sectionId out from under a scheduled saveOrder.
    if (String(target) !== String(this.sectionId)) {
      await this.flushPendingOrder();
      this.sectionId = String(target);
      const select = document.getElementById('moduleSectionSelect');
      if (select) select.value = this.sectionId;
    }
    await this.load();
    // AFTER the re-fetch: every clone carries a RELEASE_RESET notice naming the
    // NEW module's id, which this.modules cannot resolve until it has been
    // reloaded. Before this, every single clone toasted `Module 7f3c1a90`.
    this.applyWarnings(res);
  } catch (err) {
    Toast.error('Could not clone the module', err.message);
  } finally {
    Utils.setBtnLoading(btn, false);
  }
};

// ---------------------------------------------------------------------------
// Prerequisites
// ---------------------------------------------------------------------------

CiabModules.showPrereqs = function showPrereqs(moduleId) {
  const m = this.moduleById(moduleId);
  if (!m) return;
  this.prereqId = String(m.module_id);
  this.setText('modulePrereqModalTitle', `Prerequisites for "${m.title}"`);
  this.renderPrereqs();
  openModal('modulePrereqModal');
};

CiabModules.renderPrereqs = function renderPrereqs() {
  const container = document.getElementById('modulePrereqContent');
  if (!container) return;
  const m = this.moduleById(this.prereqId);
  if (!m) { container.innerHTML = ''; return; }

  const jsId = escJs(String(m.module_id));
  const releaseLabels = this.labels.release || {};

  const follows = (m.requires_module_ids || []).map((pid) => {
    const target = this.moduleById(pid);
    const jsPid = escJs(String(pid));
    // A dangling edge names a module that is no longer in this section. It has
    // no title to show and no other way to be cleared, and it is exactly what
    // PREREQ_MISSING is reporting.
    const label = target
      ? `<strong>${esc(target.title)}</strong> <span class="badge ${RELEASE_BADGE[target.release_phase] || 'badge-secondary'}">${esc(releaseLabels[target.release_phase] || target.release_phase || '—')}</span>`
      : `<em>Missing module ${esc(String(pid).slice(0, 8))}</em>`;
    return `<div class="action-item" style="margin-bottom: 0.5rem;">
      <div>${label}</div>
      <button class="btn btn-sm btn-outline" onclick="CiabModules.removePrereq('${jsId}','${jsPid}')">Remove</button>
    </div>`;
  }).join('');

  // EVERY other module in the section, unfiltered by cycle. A browser-side
  // graph walk would be a second cycle detector disagreeing with the server's;
  // the server refuses with a 409 that names the loop, and this file renders
  // that sentence and highlights the modules it names.
  const options = this.modules
    .filter((x) => String(x.module_id) !== String(m.module_id))
    .map((x) => `<option value="${esc(x.module_id)}">${esc(x.title)}</option>`)
    .join('');

  const followedBy = (m.required_by_module_ids || []).map((mid) => {
    const target = this.moduleById(mid);
    return `<li>${esc(target ? target.title : this.moduleTitle(mid))}</li>`;
  }).join('');

  container.innerHTML = `
    <div class="form-group">
      <label>Follows</label>
      ${follows || '<p style="color: var(--gray-500); font-size: 0.85rem;">Nothing yet — this module can open on its own.</p>'}
    </div>
    <div class="form-group">
      <label for="modulePrereqAdd">Add a prerequisite</label>
      <div style="display: flex; gap: 0.5rem;">
        <select id="modulePrereqAdd" style="flex: 1;">
          ${options || '<option value="" disabled>No other module in this section</option>'}
        </select>
        <button type="button" class="btn btn-primary btn-sm" id="modulePrereqAddBtn"
                onclick="CiabModules.addPrereq('${jsId}')"${options ? '' : ' disabled'}>Add</button>
      </div>
    </div>
    <div class="form-group">
      <label>Followed by</label>
      ${followedBy
    ? `<ul style="margin: 0; padding-left: 1.1rem; color: var(--gray-500); font-size: 0.85rem;">${followedBy}</ul>`
    : '<p style="color: var(--gray-500); font-size: 0.85rem;">Nothing — no module waits on this one.</p>'}
    </div>`;
};

CiabModules.addPrereq = async function addPrereq(moduleId) {
  const prereq = this.fieldValue('modulePrereqAdd');
  if (!prereq) return;
  // NO Utils.setBtnLoading here, for the reason the reorder arrows give: this
  // button lives inside #modulePrereqContent, which renderPrereqs() replaces
  // wholesale during the await, so the restore would land on a detached node.
  // The button is disabled in place instead, and the repaint is the feedback.
  const btn = document.getElementById('modulePrereqAddBtn');
  if (btn) btn.disabled = true;
  try {
    const res = await this.api(`/${moduleId}/prereqs`, {
      method: 'POST',
      body: { prereq_module_id: prereq },
    });
    Toast.success('Added', res.created === false
      ? 'It already followed that module'
      : `It now follows ${this.moduleTitle(prereq)}`);
    this.applyWarnings(res);
    await this.load();
    this.renderPrereqs();
  } catch (err) {
    // A 409 here is a refusal with a reason, not a failure — the server has
    // just explained which loop it would create.
    if (err.status === 409) {
      Toast.warning('Not added', err.message);
      const cyclic = err.data && err.data.detail && err.data.detail.cyclic_module_ids;
      if (cyclic && cyclic.length) this.highlight(cyclic.join(','));
    } else {
      Toast.error('Could not add the prerequisite', err.message);
    }
  } finally {
    // Only meaningful when the modal was NOT repainted, i.e. on a refusal.
    if (btn && btn.isConnected !== false) btn.disabled = false;
  }
};

CiabModules.removePrereq = async function removePrereq(moduleId, prereqModuleId) {
  const m = this.moduleById(moduleId);
  // Removing a gate from a module students are working in right now changes
  // what they can reach mid-session, so it is asked for rather than assumed.
  if (m && m.release_phase === 'open') {
    if (!await Confirm.show({
      title: 'Remove this prerequisite?',
      message: `"${m.title}" is open to students now. Removing this requirement lets everyone in, `
             + 'whether or not they have finished the earlier module.',
      confirmText: 'Remove',
      danger: true,
    })) return;
  }
  try {
    const res = await this.api(`/${moduleId}/prereqs/${prereqModuleId}`, { method: 'DELETE' });
    Toast.success('Removed', 'That requirement is gone');
    this.applyWarnings(res);
    await this.load();
    this.renderPrereqs();
  } catch (err) {
    Toast.error('Could not remove the prerequisite', err.message);
  }
};

// ---------------------------------------------------------------------------
// Archive / restore / delete
// ---------------------------------------------------------------------------

// THE CLIENT NEVER PRE-EMPTS A SERVER REFUSAL. A 409 MODULE_HAS_DEPENDENTS is
// answered by quoting the server's own sentence back and retrying with
// confirm=1 — which is why a later phase can add "this will tear down 12 lanes"
// to that same 409 and this file needs no change at all.
CiabModules.retryWithConfirm = async function retryWithConfirm(err, title, path) {
  if (!err.data || err.data.code !== 'MODULE_HAS_DEPENDENTS') return false;
  const names = (err.data.required_by || []).map((d) => d.title).filter(Boolean);
  const message = err.message + (names.length ? ` — ${names.join(', ')}` : '');
  if (!await Confirm.show({ title, message, confirmText: 'Go ahead', danger: true })) return true;
  try {
    const res = await this.api(path, { method: 'DELETE' });
    Toast.success('Done', 'The sequence has been updated');
    this.applyWarnings(res);
    await this.load();
  } catch (second) {
    Toast.error('Could not remove the module', second.message);
  }
  return true;
};

CiabModules.archiveModule = async function archiveModule(moduleId) {
  const m = this.moduleById(moduleId);
  if (!m) return;
  const followers = (m.required_by_module_ids || []).length;
  // Plain concatenation: Confirm escapes its message, so markup would render as
  // literal text. Name the concrete consequence and its scope.
  const message = `Students will no longer see "${m.title}". Every completion and override is kept, `
    + 'and you can restore it at any time.'
    + (followers
      ? ` ${followers} module(s) that follow it will stay locked until you change their prerequisites.`
      : '');

  if (!await Confirm.show({
    title: `Archive "${m.title}"?`,
    message,
    confirmText: 'Archive',
    danger: true,
  })) return;

  try {
    const res = await this.api(`/${m.module_id}`, { method: 'DELETE' });
    Toast.success('Done', 'It is out of the sequence, and nothing was deleted');
    this.applyWarnings(res);
    await this.load();
  } catch (err) {
    if (await this.retryWithConfirm(err, `Archive "${m.title}" anyway?`, `/${m.module_id}?confirm=1`)) return;
    Toast.error('Could not archive the module', err.message);
  }
};

CiabModules.restoreModule = async function restoreModule(moduleId) {
  const m = this.moduleById(moduleId);
  if (!m) return;
  if (!await Confirm.show({
    title: `Restore "${m.title}"?`,
    message: 'It goes back into the sequence unpublished, so students will not see it until you '
           + 'set its release. Every completion and override it already had is still there.',
    confirmText: 'Restore',
  })) return;

  try {
    const res = await this.api(`/${m.module_id}`, {
      method: 'PATCH',
      body: { release_state: 'draft' },
    });
    Toast.success('Restored', 'It is back in the sequence — publish it when you are ready');
    this.applyWarnings(res);
    await this.load();
  } catch (err) {
    Toast.error('Could not restore the module', err.message);
  }
};

CiabModules.deleteModule = async function deleteModule(moduleId) {
  const m = this.moduleById(moduleId);
  if (!m) return;
  if (!await Confirm.show({
    title: `Delete "${m.title}"?`,
    message: `"${m.title}" and its prerequisite links are deleted permanently. This cannot be undone.`,
    confirmText: 'Delete',
    danger: true,
  })) return;

  try {
    const res = await this.api(`/${m.module_id}?hard=1`, { method: 'DELETE' });
    Toast.success('Deleted', 'It is gone from the sequence');
    this.applyWarnings(res);
    await this.load();
  } catch (err) {
    if (await this.retryWithConfirm(err, `Delete "${m.title}" anyway?`, `/${m.module_id}?hard=1&confirm=1`)) return;
    // MODULE_HAS_STUDENT_RECORDS has no override, by design: archiving is the
    // only removal that keeps the rows the grading phase reads.
    if (err.data && err.data.code === 'MODULE_HAS_STUDENT_RECORDS') {
      Toast.warning('Not deleted', err.message);
      return;
    }
    Toast.error('Could not delete the module', err.message);
  }
};

// A top-level const is a lexical global, never a window property, and
// activateTabModule() reads window.CiabModules by property lookup.
window.CiabModules = CiabModules;
