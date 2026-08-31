/**
 * instructor-engagements.js — the Engagements tab (Track B, phase B1a).
 * ============================================================================
 * One client environment, one perspective, one network reservation. This tab
 * is the authoring surface for the engagement MODEL that B0 shipped
 * (utils/engagement-model.js + the 011 columns) and the read surface for the
 * plan that compileEngagementPlan derives from it (utils/engagement-plan.js).
 *
 * WHAT IT TALKS TO — all under /api/instructor/engagements, all through
 * API.engagements in ciab-api.js:
 *   GET  /types                    the ENGAGEMENT_TYPES registry, projected
 *   GET  /?profile_id=…            every engagement for one client, plus
 *                                  unadopted_reservation and unadopted_probe —
 *                                  the second says whether the first is an
 *                                  ANSWER or an absence of one, and this tab
 *                                  renders those as three states, not two
 *   GET  /:id                      one engagement + its compiled plan
 *   PATCH /:id                     seven authorable fields, one at a time
 *   POST /  /adopt  /:id/reprovision  /:id/retire      (admin-gated server side)
 *
 * ── LOAD ORDER IS LOAD-BEARING ──────────────────────────────────────────────
 * The <script> tag for this file MUST come AFTER instructor-core.js: TAB_NAMES
 * and activateTabModule are declared there, and neither exists yet if this file
 * evaluates first. A wrong order is DETECTED, not assumed away — the check is
 * `typeof window.activateTabModule === 'function'` (a function declaration is a
 * real property of the global object; a top-level `const` is not) plus a BARE
 * read of TAB_NAMES inside a try/catch. It is deliberately NOT `typeof
 * TAB_NAMES`, which is the one operator that cannot throw on an undeclared name
 * and which therefore reports success on exactly the failure being tested for.
 * On a wrong order the module registers nothing, writes one console.error
 * naming the required order, and says so in the panel. See the bottom of this
 * file.
 *
 * ── WHY THIS TAB REGISTERS ITSELF (and why that is worth the indirection) ───
 * Every other tab is wired by two lines inside instructor-core.js: a name in
 * TAB_NAMES and an entry in activateTabModule's dispatch literal. This one is
 * not. Three tracks are editing this dashboard in one working tree with no
 * commits between them, and those exact two lines are the single highest
 * -probability collision on the whole surface — where the failure mode is a
 * silent last-writer-wins overwrite, not a merge conflict anyone can see.
 * So instructor-core.js gets ZERO lines from Track B, and the registration
 * lives here instead. The cost is real: a future reader looking for
 * 'engagements' in instructor-core.js will not find it. That cost is
 * acknowledged, and the wrapper is written to COMPOSE — it delegates every
 * other tab name to whatever activateTabModule was already installed, so a
 * second self-registering tab, or the ordinary two-line edit landing later,
 * both keep working.
 *
 * ── THINGS THIS FILE DELIBERATELY DOES NOT DO ───────────────────────────────
 *  * NO ADDRESSES ANYWHERE, AND THAT IS ENFORCED, NOT MERELY DECLARED. The
 *    compile publishes hosts[].segment_for_address BEFORE it proposes exposure,
 *    and overwrites ip_octet / placement / nics AFTER it, so joining those two
 *    fields names a machine at ext.<n> that will live at int.<n>. Placement
 *    LABELS carry the pedagogy and none of the hazard. Addresses are B2's,
 *    after that ordering is closed.
 *    The rule covers TEMPLATES too, and that half was the one this file broke:
 *    brief.facts.surface_url and start_position.note are written for a per-lane
 *    brief and carry an unfilled {placeholder} for a lane that does not exist
 *    on this screen. Rendered here they read as a real starting URL and resolve
 *    nowhere — worse than showing nothing. The URL is not read at all now, and
 *    every server-authored sentence this tab prints goes through engProse(),
 *    which drops any sentence still holding a placeholder. plan.problems is
 *    deliberately exempt: a diagnostic that names a fixed pin IS its actionable
 *    content, and scrubbing it leaves a broken plan with the reason deleted.
 *  * NO TECHNIQUES EDITOR. plan.techniques is always derived from perspective
 *    and credential posture; the stored allowed_techniques column has no reader
 *    anywhere in the compile. An editor there would persist an edit with zero
 *    effect AND stamp the field into authored_fields, locking a later
 *    "refresh from the client file" out of it forever. Read-only, captioned.
 *  * NO asset_selection EDITOR. It changes what actually deploys; it belongs
 *    with the spec writeback in B2.
 *  * NO SECRET, EVER. issued_credentials records WHICH accounts the client
 *    agreed to hand over — slot key, username, machine, privilege — and never
 *    a password. The per-lane secret is minted at deploy time.
 *  * NEVER renders the engagement row's challenge_key / challenge_id. They are
 *    stripped server-side by project() and named here only in this sentence.
 *
 * ── VOCABULARY ──────────────────────────────────────────────────────────────
 * Section / Module / Client / Engagement / Environment. Nothing on this screen
 * borrows a word from the neighbouring plugin's naming. Every engagement label
 * comes from the server-projected display_label or type_descriptor.label —
 * never derived from a slug in the browser.
 *
 * ── ACCESS ──────────────────────────────────────────────────────────────────
 * Every privileged control renders from the server-computed can.* flags on the
 * projected row, never from a client-side role test. requireRole's 403 writes
 * an access.denied audit row, so a button an instructor cannot press would
 * manufacture denial records for this screen's primary user.
 *
 * Depends on instructor-core.js globals (InstructorState, esc, escJs,
 * closeModal, TAB_NAMES, activateTabModule) and the app.js kit (API, Toast,
 * Confirm, Utils, Modal). Toast/Confirm/Utils/API are top-level consts in
 * app.js, NOT window properties — feature-detect them by bare name.
 */
/* global TAB_NAMES, InstructorState, API, Toast, Confirm, Utils, Modal,
          esc, escJs, closeModal */

// ── Vocabulary mirrors ──────────────────────────────────────────────────────
// These mirror utils/engagement-model.js (SCOPE_KINDS :180, ACCOUNT_KINDS :186,
// CREDENTIAL_SOURCES :189, PLACEMENTS :225). They are DUPLICATED, not imported:
// manifest.json's staticDir is "public", so utils/ is never served to a
// browser. The server re-validates every one of these on the PATCH — a select
// here is a convenience, never the authority. If they drift, the server wins
// and says so through err.data.errors[].
//
// EVERY top-level name in this file carries an ENG_ / eng prefix. Classic
// scripts share ONE global lexical scope, so a bare `const PLACEMENTS` here
// would make a second tab's identically-named const a whole-script
// SyntaxError — in a dashboard three tracks are adding files to at once, that
// is a collision waiting to happen, and it costs one prefix to remove.

const ENG_SCOPE_KINDS = ['all', 'vm', 'role', 'cidr', 'url', 'hostname_pattern', 'text'];
const ENG_ACCOUNT_KINDS = ['local', 'domain', 'app', 'service'];
const ENG_CREDENTIAL_SOURCES = ['cloudinit', 'template', 'baked', 'app_seed', 'manual'];
const ENG_PLACEMENTS = ['pivot', 'public', 'internal'];
const ENG_SUBNET_SCHEMES = ['v1', 'v2', 'v3'];

const ENG_PLACEMENT_LABELS = {
  pivot: 'Pivot (dual-homed)',
  public: 'Public surface',
  internal: 'Internal',
};

const ENG_PROVISION_LABELS = {
  none: 'Not reserved',
  provisioning: 'Reserving',
  ready: 'Ready',
  failed: 'Reservation failed',
};

const ENG_FIELD_LABELS = {
  display_name: 'Engagement name',
  brief: 'Engagement brief',
  scope_in: 'In scope',
  scope_out: 'Out of scope',
  exposure_plan: 'Placement',
  issued_credentials: 'Handed-over accounts',
  objectives: 'Objectives',
};

// The credential line is FIXED TEXT and must stay fixed: it is the only thing
// on this screen that tells an instructor where the secret actually comes from.
const ENG_CREDENTIAL_LINE =
  'The password is generated per lane at deploy time and delivered as a file. '
  + 'It is never stored here and never shown on this screen.';

// Reserving carves a VXLAN block the allocator can never hand back. Both
// sentences are load-bearing; softening either one is how an operator comes to
// press Create twice.
const ENG_CREATE_WARNING =
  'Creating an engagement reserves a network block permanently. '
  + 'Retiring the engagement later does not return it.';
const ENG_ADOPT_WARNING =
  'Adopting records the reservation this client already holds. '
  + 'It does not reserve anything new and consumes no capacity.';

// ── Row-editor column specs ─────────────────────────────────────────────────
// One generic editor drives the five list-shaped fields. Each row is an OBJECT
// CLONE of what the server returned, and a cell edit writes exactly one named
// key — so keys this screen does not offer (a credential's `delivery` block,
// an objective's `maps_to`) survive a round trip untouched instead of being
// silently dropped by a rebuild.

const ENG_ROW_FIELDS = {
  scope_in: {
    addLabel: 'Add a rule',
    empty: 'No rules authored. The whole environment is in scope by default.',
    blank: () => ({ kind: 'vm', value: '', note: null }),
    columns: [
      { key: 'kind', type: 'select', label: 'Kind', options: ENG_SCOPE_KINDS, width: '10rem' },
      { key: 'value', type: 'text', label: 'Value', placeholder: 'web01 · a CIDR · a URL' },
      { key: 'note', type: 'text', label: 'Note (optional)' },
    ],
  },
  scope_out: {
    addLabel: 'Add a rule',
    empty: 'No exclusions authored.',
    blank: () => ({ kind: 'vm', value: '', note: null }),
    columns: [
      { key: 'kind', type: 'select', label: 'Kind', options: ENG_SCOPE_KINDS, width: '10rem' },
      { key: 'value', type: 'text', label: 'Value', placeholder: 'payroll01 · a CIDR' },
      { key: 'note', type: 'text', label: 'Note (optional)' },
    ],
  },
  exposure_plan: {
    addLabel: 'Place a machine',
    empty: 'Nothing placed by hand. Placement is derived from the environment.',
    blank: () => ({ vm_name: '', placement: 'internal', services: [], note: null }),
    columns: [
      { key: 'vm_name', type: 'text', label: 'Machine', list: 'engVmNames', width: '14rem' },
      {
        key: 'placement', type: 'select', label: 'Placement',
        options: ENG_PLACEMENTS, optionLabels: ENG_PLACEMENT_LABELS, width: '12rem',
      },
      { key: 'services', type: 'list', label: 'Services (comma separated)', placeholder: '80/HTTP, 443/HTTPS' },
      { key: 'note', type: 'text', label: 'Note (optional)' },
    ],
  },
  issued_credentials: {
    addLabel: 'Add an account',
    empty: 'No accounts are handed over on this engagement.',
    blank: () => ({
      slot_key: '', username: '', account_kind: 'local',
      target_vm: '', privilege: '', source: 'cloudinit', note: null,
    }),
    columns: [
      { key: 'slot_key', type: 'text', label: 'Slot key', placeholder: 'helpdesk', width: '10rem' },
      { key: 'username', type: 'text', label: 'Account name', width: '10rem' },
      { key: 'account_kind', type: 'select', label: 'Kind', options: ENG_ACCOUNT_KINDS, width: '8rem' },
      { key: 'target_vm', type: 'text', label: 'On machine', list: 'engVmNames', width: '11rem' },
      { key: 'privilege', type: 'text', label: 'Privilege', placeholder: 'standard', width: '9rem' },
      { key: 'source', type: 'select', label: 'Source', options: ENG_CREDENTIAL_SOURCES, width: '9rem' },
      { key: 'note', type: 'text', label: 'Note (optional)' },
    ],
  },
  objectives: {
    addLabel: 'Add an objective',
    empty: 'No objectives authored. The compile proposes one pair per machine.',
    blank: () => ({ objective_key: '', title: '', points: 10, maps_to: { kind: 'manual' } }),
    columns: [
      { key: 'title', type: 'text', label: 'Objective' },
      { key: 'points', type: 'number', label: 'Points', width: '7rem' },
    ],
  },
};

// ── Small local helpers ─────────────────────────────────────────────────────

function engArr(v) { return Array.isArray(v) ? v : []; }

// Structured clone by round trip. The five list fields are plain JSON from the
// database, so this is total for every value they can hold, and it guarantees
// the draft can never share a reference with the rendered engagement.
function engClone(v) {
  if (v === null || v === undefined) return v;
  try { return JSON.parse(JSON.stringify(v)); } catch (_) { return v; }
}

function engBadge(text, variant) {
  return `<span class="badge ${variant ? `badge-${variant}` : 'badge-gray'}">${esc(text)}</span>`;
}

function engCard(title, inner, subtitle) {
  return `
    <div class="card" style="margin-bottom:1rem;">
      <div class="card-header">
        <div>
          <div class="card-title">${esc(title)}</div>
          ${subtitle ? `<div style="color:var(--text-muted); font-size:.85rem; margin-top:.15rem;">${esc(subtitle)}</div>` : ''}
        </div>
      </div>
      ${inner}
    </div>`;
}

function engNames(names, emptyText) {
  const list = engArr(names).filter(Boolean);
  if (!list.length) return `<p style="color:var(--text-muted); margin:.25rem 0;">${esc(emptyText)}</p>`;
  return `<div style="display:flex; flex-wrap:wrap; gap:.35rem; margin:.25rem 0;">${
    list.map((n) => `<span class="badge badge-secondary">${esc(n)}</span>`).join('')
  }</div>`;
}

/**
 * THE INVARIANT, ENFORCED RATHER THAN ASSERTED.
 *
 * The compile writes prose for a BRIEF, and a brief is substituted per lane at
 * deploy time — so several of its sentences carry an unfilled `{placeholder}`
 * standing in for a value that does not exist yet. On this screen there is no
 * lane and nothing to substitute with, so such a sentence renders verbatim:
 * braces and all, naming a place that resolves nowhere. That is not "an address
 * B1a chose not to hide" — it is a broken one, which is strictly worse than
 * none, and it made the header's NO ADDRESSES rule aspirational rather than
 * true.
 *
 * So: any server-authored free-text this tab renders passes through here, and a
 * sentence still holding a placeholder is dropped rather than shown. It drops a
 * whole sentence, never half of one — a partially-scrubbed sentence is how prose
 * ends up saying the opposite of what its author wrote.
 *
 * DIAGNOSTICS ARE NOT ROUTED THROUGH THIS. plan.problems names fixed pins by
 * octet on purpose ("the bridge answers at the pinned octet, the lab reserved it
 * at another") and that IS the actionable content of the message. Suppressing it
 * would leave an operator a broken plan with the reason removed.
 */
function engProse(text) {
  const s = typeof text === 'string' ? text.trim() : '';
  if (!s) return '';
  return /\{[a-z0-9_]+\}/i.test(s) ? '' : s;
}

/**
 * Perspective and posture, resolved the way the compile resolves them
 * (engagement-plan.js:1545-1550): the engagement's OWN column wins, and the
 * type descriptor is only the fallback. Reading the descriptor alone would
 * label a custom-slug engagement 'Internal / no accounts' — describeEngagementType's
 * deliberately conservative default for an unknown type — even when the row
 * explicitly says otherwise, and the brief beneath it would then disagree with
 * its own badges.
 */
function engPosture(row, descriptor) {
  const d = descriptor || {};
  const p = String((row && row.perspective) || '').toLowerCase();
  const c = String((row && row.credential_posture) || '').toLowerCase();
  return {
    perspective: p === 'internal' || p === 'external' ? p : (d.perspective || 'internal'),
    credential_posture: c === 'none' || c === 'credentialed' ? c : (d.credential_posture || 'none'),
  };
}

// ── The tab ─────────────────────────────────────────────────────────────────

const Engagements = {
  _inited: false,
  _profileId: null,      // the client currently selected
  _engagements: [],      // every engagement for that client, retired included
  _unadopted: null,      // { engagement_type } | null — a pre-A8 carved block
  _unadoptedProbe: 'ok', // 'ok' | 'unavailable' — WHETHER the line above is an
                         // ANSWER or an ABSENCE OF ONE. null means "nothing is
                         // reserved" only when the probe actually ran; on
                         // 'unavailable' it means nothing was learned, and the
                         // screen must not spend capacity on that difference.
  _listCan: null,        // server-computed capability flags for THIS user
  _openId: null,         // the engagement whose detail is on screen
  _detail: null,         // { engagement, plan, bridges_ready }
  _draft: {},            // per-field edit buffers, keyed by field name
  _notices: {},          // per-field { errors, warnings } from the last PATCH
  _types: [],            // the projected ENGAGEMENT_TYPES registry
  _typesStatus: 'idle',  // 'idle' | 'loading' | 'ready' | 'failed' — [] means
                         // BOTH "not loaded" and "loaded and empty", and the
                         // list branch has to tell those two apart
  _pollTimer: null,
  _pollCount: 0,
  _seq: 0,               // stale-response guard for the list fetch

  // ── Lifecycle ─────────────────────────────────────────────────────────────

  ensureInit() {
    if (this._inited) return;
    if (!this.renderShell()) return;   // panel not in the DOM yet — try again next visit
    this._inited = true;

    this.renderClientPicker();
    InstructorState.on('profiles', () => this.renderClientPicker());
    this.renderEmptyPrompt();

    this.loadTypes();
  },

  /**
   * The registry. A failure here is NOT fatal and must not be silently
   * permanent: it costs the create modal its type list, and the modal reports
   * that loss itself. Retryable, and retried from renderList().
   */
  loadTypes() {
    if (this._typesStatus === 'loading' || this._typesStatus === 'ready') return;
    this._typesStatus = 'loading';
    API.engagements.types()
      .then((r) => {
        this._types = engArr(r && r.types);
        this._typesStatus = 'ready';
        // The list decides whether to offer "New engagement" by asking whether
        // this client is missing a type, so it has to be repainted if the
        // registry lands after a list is already on screen.
        if (this._profileId && !this._openId && this._engagements.length) this.renderList();
      })
      .catch((err) => {
        this._typesStatus = 'failed';
        console.error('Engagements: could not load the type registry:', err);
      });
  },

  // The panel is a bare <div id="tab-engagements"> in instructor.html — three
  // added lines, no markup — so the whole frame is painted from here. That
  // keeps Track B out of a file two other tracks are editing at the same time.
  renderShell() {
    const panel = document.getElementById('tab-engagements');
    if (!panel) return false;
    if (panel.dataset.engShell === '1') return true;
    panel.innerHTML = `
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <div>
            <div class="card-title">Engagements</div>
            <div style="color:var(--text-muted); font-size:.9rem; margin-top:.25rem;">
              An engagement is one client environment with one perspective.
              Each engagement holds its own network reservation.
            </div>
          </div>
        </div>
        <div class="form-group" style="max-width:34rem; margin:1rem 0 0;">
          <label class="form-label" for="engClientSelect">Client</label>
          <select id="engClientSelect" class="form-select"
                  onchange="Engagements.onClientChange(this.value)"></select>
        </div>
      </div>
      <div id="engBody"></div>
      <div id="engModalHost"></div>`;
    panel.dataset.engShell = '1';
    return true;
  },

  body() { return document.getElementById('engBody'); },

  // ── Client picker ─────────────────────────────────────────────────────────

  renderClientPicker() {
    const select = document.getElementById('engClientSelect');
    if (!select) return;
    const prev = select.value;
    const profiles = engArr(InstructorState.profiles);
    select.innerHTML = '<option value="">— Select a client —</option>'
      + profiles.map((p) => `<option value="${esc(p.id)}">${esc(p.display_name)}</option>`).join('');
    if (prev && profiles.some((p) => p.id === prev)) {
      select.value = prev;
    } else if (prev) {
      // The selected client vanished from the list — drop back to the prompt
      // rather than leaving a list on screen that belongs to nothing.
      this._profileId = null;
      this.renderEmptyPrompt();
    }
  },

  renderEmptyPrompt() {
    const body = this.body();
    if (!body) return;
    body.innerHTML = `
      <div class="card">
        <div class="empty-state">
          <div class="icon">📁</div>
          <h3>No client selected</h3>
          <p>Choose a client to see its engagements.</p>
        </div>
      </div>`;
  },

  // Activation never fetches and never writes: the list load starts here, on a
  // deliberate choice of client.
  onClientChange(profileId) {
    this.stopPoll();
    this._openId = null;
    this._detail = null;
    this._draft = {};
    this._notices = {};
    this._profileId = profileId || null;
    if (!this._profileId) { this.renderEmptyPrompt(); return; }
    this.loadList();
  },

  // ── List ──────────────────────────────────────────────────────────────────

  async loadList({ silent = false } = {}) {
    const profileId = this._profileId;
    if (!profileId) return;
    const seq = ++this._seq;
    if (!silent && !this._openId) this.renderLoading();
    try {
      const data = await API.engagements.list(profileId);
      // A slower response for a client the user has already navigated away
      // from must never overwrite the one on screen.
      if (seq !== this._seq || profileId !== this._profileId) return;
      this._engagements = engArr(data.engagements);
      this._unadopted = data.unadopted_reservation || null;
      // THREE ANSWERS, NOT TWO — the server distinguishes "probed, found
      // nothing" from "could not probe", and dropping the distinction here
      // would put the server's fix back where it started: the empty state
      // would offer Create on the strength of an outage. Defaulted to 'ok' so
      // a server that predates the field behaves exactly as it does today.
      this._unadoptedProbe = data.unadopted_probe === 'unavailable' ? 'unavailable' : 'ok';
      // can.* is computed by the server for THIS user, so it is a fact about
      // the person, not about the client — worth remembering across a client
      // switch, because the empty-list branch has no row to read it from.
      const rowCan = this._engagements.length ? this._engagements[0].can : null;
      this._listCan = data.can || rowCan || this._listCan;
      if (this._openId) {
        // A DETAIL ON SCREEN IS NEVER REPAINTED ON A TIMER. The reservation
        // poll runs every five seconds, and every repaint rebuilds the editors
        // — which would take the caret out of whatever box the instructor is
        // typing in, twelve times a minute. Only a REAL state transition
        // (reserving → ready, or → failed) earns a re-read, and that one is
        // worth interrupting for.
        const row = this._engagements.find((e) => e.engagement_id === this._openId);
        const shown = this._detail && this._detail.engagement;
        if (row && shown && row.provision_status !== shown.provision_status) {
          this.reloadDetail();
        }
      } else {
        this.renderList();
      }
      this.syncPoll();
    } catch (err) {
      if (seq !== this._seq) return;
      console.error('Engagements: list failed:', err);
      this.stopPoll();
      if (!silent) this.renderError(err && err.message);
    }
  },

  renderLoading() {
    const body = this.body();
    if (!body) return;
    body.innerHTML = `
      <div class="card">
        <div class="skeleton skel-row"></div>
        <div class="skeleton skel-row"></div>
      </div>`;
  },

  renderError(message) {
    const body = this.body();
    if (!body) return;
    body.innerHTML = `
      <div class="card">
        <div class="empty-state">
          <div class="icon">⚠️</div>
          <h3>Couldn't load engagements</h3>
          <p>${esc(message || 'Request failed')}</p>
          <button class="btn btn-outline btn-sm" onclick="Engagements.loadList()">Retry</button>
        </div>
      </div>`;
    },

  renderList() {
    const body = this.body();
    if (!body) return;
    if (!this._engagements.length) { body.innerHTML = this.emptyBranch(); return; }
    const can = this._listCan || {};
    // EVERY engagement, never engagements[0]. One client can hold several — an
    // internal credentialed one and an external black-box one are different
    // environments against the same client file, and the type is the identity
    // that keeps them apart.
    const types = new Set(this._engagements.map((e) => e.engagement_type));
    // "THIS CLIENT ALREADY HOLDS EVERY TYPE" AND "I NEVER LOADED THE REGISTRY"
    // ARE NOT THE SAME ANSWER. _types is [] in both states, and treating the
    // second as the first silently and permanently removes the only route to a
    // new engagement — for every client that already holds one — on the strength
    // of a single failed GET /types at tab-open. The registry is a convenience
    // here; the server is the authority on what may be created. So when it is
    // not loaded, offer the action: openCreate() falls back to the one type that
    // is always valid and says so, and create() surfaces any server refusal.
    const registryLoaded = this._typesStatus === 'ready' && this._types.length > 0;
    const spare = registryLoaded
      ? this._types.some((t) => !types.has(t.key))
      : true;
    // And take the failure off the screen's critical path entirely: one retry
    // per repaint, so a registry that was down at tab-open recovers by itself
    // instead of waiting for a page reload.
    if (this._typesStatus === 'failed') this.loadTypes();
    body.innerHTML = `
      ${this.capacityNotice()}
      ${can.create && spare ? `
        <div style="display:flex; justify-content:flex-end; margin-bottom:.75rem;">
          <button class="btn btn-sm btn-primary" onclick="Engagements.openCreate()">New engagement</button>
        </div>` : ''}
      ${this._engagements.map((row) => this.renderCard(row)).join('')}`;
  },

  /**
   * THE CAPACITY NOTICE, ABOVE A LIST THAT IS NOT EMPTY.
   *
   * The server probes for an unadopted reservation on EVERY list, not only an
   * empty one — because a client that already holds one engagement can still
   * hold a separately carved block that no row names, and that is the normal
   * case this table was added for. Until this existed the probe's answer was
   * read in one place only, emptyBranch(), so on a non-empty list the server
   * answered a question the screen never asked and the block stayed invisible
   * exactly where it had been invisible before.
   *
   * Returns '' when there is nothing to say, so it can be concatenated
   * unconditionally.
   */
  capacityNotice() {
    const can = this._listCan || {};
    if (this._unadopted) {
      const type = this._unadopted.engagement_type || 'default';
      return `
        <div class="card" style="border-left:3px solid var(--warning);">
          <h4 style="margin:0 0 .35rem;">This client also holds a reserved network nothing records</h4>
          <p style="margin:0 0 .5rem;">
            It was reserved before engagements were tracked, as
            <code>${esc(type)}</code>. ${esc(ENG_ADOPT_WARNING)}
          </p>
          ${can.adopt
            ? `<button class="btn btn-sm btn-outline" onclick="Engagements.adopt('${escJs(type)}', this)">Adopt existing reservation</button>`
            : '<p style="margin:0; color:var(--text-muted);">An administrator records the existing reservation.</p>'}
        </div>`;
    }
    if (this._unadoptedProbe === 'unavailable') return this.probeUnavailableNote();
    return '';
  },

  /**
   * THE PROBE COULD NOT RUN, AND SAYING SO IS THE WHOLE POINT.
   *
   * unadopted_reservation is null in two completely different situations, and
   * the server now names which: 'ok' means it looked and found nothing,
   * 'unavailable' means it could not look. Rendering the second as the first
   * is how a database outage turns into a second permanently carved block —
   * the screen would say "nothing is reserved" on exactly the evidence that
   * nothing is known. So the uncertainty is shown, and Create is still offered
   * beside it: refusing the only route forward on a transient outage is its
   * own failure, and the person pressing it can now see what is unverified.
   */
  probeUnavailableNote() {
    return `
      <div class="card" style="border-left:3px solid var(--warning);">
        <h4 style="margin:0 0 .35rem;">Existing reservations could not be checked</h4>
        <p style="margin:0 0 .5rem;">
          This client may already hold a reserved network that nothing records here.
          Nothing below is wrong — but "no reservation" has not been confirmed, so
          reserve a new one only if you know this client holds none.
        </p>
        <button class="btn btn-sm btn-outline" onclick="Engagements.loadList()">Check again</button>
      </div>`;
  },

  /**
   * THE CAPACITY BRANCH. "Nothing reserved" and "a reservation nobody has
   * adopted" look identical from here unless the server says which it is, and
   * confusing them is how an operator presses Create and carves a SECOND block
   * for a client that already holds one — permanently, because the allocator
   * only ever climbs.
   *
   * THREE STATES, NOT TWO. A probe that could not RUN is a third answer and is
   * rendered as one: see probeUnavailableNote().
   */
  emptyBranch() {
    const can = this._listCan || {};
    if (this._unadopted) {
      const type = this._unadopted.engagement_type || 'default';
      return `
        <div class="card">
          <div class="empty-state">
            <div class="icon">🔗</div>
            <h3>This client already holds a reserved network</h3>
            <p>
              It was reserved before engagements were tracked, as
              <code>${esc(type)}</code>. ${esc(ENG_ADOPT_WARNING)}
            </p>
            ${can.adopt
              ? `<button class="btn btn-primary" onclick="Engagements.adopt('${escJs(type)}', this)">Adopt existing reservation</button>`
              : '<p style="color:var(--text-muted);">An administrator records the existing reservation.</p>'}
          </div>
        </div>`;
    }
    // NOT "no reservation exists" — "no engagement is recorded". Those are
    // different sentences, and only the second is known when the probe failed.
    return `
      ${this._unadoptedProbe === 'unavailable' ? this.probeUnavailableNote() : ''}
      <div class="card">
        <div class="empty-state">
          <div class="icon">📋</div>
          <h3>No engagement recorded for this client</h3>
          <p>${esc(ENG_CREATE_WARNING)}</p>
          ${can.create
            ? '<button class="btn btn-primary" onclick="Engagements.openCreate()">Create engagement</button>'
            : '<p style="color:var(--text-muted);">An administrator creates the engagement and reserves its network.</p>'}
        </div>
      </div>`;
  },

  renderCard(row) {
    const can = row.can || {};
    const type = row.type_descriptor || {};
    const retired = !!row.retired_at;
    const stance = engPosture(row, type);
    const perspective = stance.perspective === 'external' ? 'External' : 'Internal';
    // ONE SOURCE FOR BOTH HALVES OF THE BADGE. The text and the variant are two
    // renderings of one fact, and reading them from two places is how the same
    // engagement showed a grey "Credentialed" chip in the list and a primary one
    // in the detail: `stance` follows the compile (the row's own column wins,
    // the descriptor is only the fallback), while `type.credential_posture` is
    // the descriptor alone — which answers 'none' for every custom slug, because
    // describeEngagementType is deliberately total and conservative.
    const credentialed = stance.credential_posture === 'credentialed';
    const posture = credentialed ? 'Credentialed' : 'No accounts issued';
    const postureVariant = credentialed ? 'primary' : 'gray';
    // An engagement created but never named still renders under its type's
    // name. Create and name can be two different people, and a create whose
    // follow-up PATCH failed has ALREADY burned a network block — showing that
    // row as an error is how the block gets burned a second time.
    const label = row.display_label || type.label || 'Engagement';
    return `
      <div class="card" style="margin-bottom:1rem;${retired ? ' opacity:.6;' : ''}">
        <div class="card-header">
          <div>
            <div class="card-title" title="${esc(label)}">${esc(label)}</div>
            <div style="color:var(--text-secondary); font-size:.9rem; margin-top:.15rem;">${esc(type.label || '')}</div>
            ${type.summary ? `<div style="color:var(--text-muted); font-size:.85rem; margin-top:.15rem;">${esc(type.summary)}</div>` : ''}
            <div style="display:flex; gap:.35rem; margin-top:.5rem; flex-wrap:wrap;">
              ${engBadge(perspective, 'info')}
              ${engBadge(posture, postureVariant)}
              ${type.known ? '' : engBadge('Locally defined type', 'warning')}
              ${retired ? engBadge('Retired', 'muted') : ''}
            </div>
          </div>
          <div style="display:flex; gap:.5rem; align-items:flex-start;">
            ${retired ? '' : `<button class="btn btn-sm btn-outline" onclick="Engagements.open('${escJs(row.engagement_id)}')">Open</button>`}
          </div>
        </div>
        ${this.stateRow(row, { bridgesReady: row.bridges_ready })}
        ${retired ? '' : this.cardActions(row, can)}
      </div>`;
  },

  cardActions(row, can) {
    const buttons = [];
    if (can.reprovision && row.provision_status === 'failed') {
      buttons.push(`<button class="btn btn-sm btn-outline" onclick="Engagements.reprovision('${escJs(row.engagement_id)}', this)">Retry reservation</button>`);
    }
    if (can.retire) {
      buttons.push(`<button class="btn btn-sm btn-outline" onclick="Engagements.retire('${escJs(row.engagement_id)}', this)">Retire</button>`);
    }
    if (!buttons.length) return '';
    return `<div style="display:flex; gap:.5rem; margin-top:.75rem; flex-wrap:wrap;">${buttons.join('')}</div>`;
  },

  /**
   * The state row renders in EVERY branch, including a restart-stranded
   * 'failed'. The admin page it replaces drew its equivalent only on the
   * not-yet-reserved path, which is exactly why a failed reservation there was
   * a dead end with no way back.
   */
  stateRow(row, { bridgesReady } = {}) {
    const status = row.provision_status || 'none';
    const label = ENG_PROVISION_LABELS[status] || status;
    const slots = Number.isInteger(row.max_students) ? row.max_students : null;
    let icon = 'ℹ️';
    let text = esc(label);
    let border = 'var(--border-color)';

    if (status === 'ready') {
      icon = '✅';
      border = 'var(--success)';
      text = slots === null
        ? 'Environment ready.'
        : `Environment ready — ${slots} student slot${slots === 1 ? '' : 's'}.`;
    } else if (status === 'provisioning') {
      icon = '⏳';
      text = 'Reserving the network…';
    } else if (status === 'failed') {
      icon = '❌';
      border = 'var(--danger)';
      text = 'Network reservation failed.';
    }

    // bridges_ready is TRI-STATE and the third state is not a failure: an
    // adopted reservation genuinely exists — lanes may be running on it — but
    // nothing ever verified its bridges on every node, and the detail read by
    // id attaches no readiness at all. Rendering null as "failed" would
    // manufacture an incident out of a missing record.
    let bridges = '';
    if (status === 'ready') {
      if (bridgesReady === true) bridges = engBadge('Bridges verified', 'success');
      else if (bridgesReady === false) bridges = engBadge('Bridges not verified', 'warning');
      else bridges = engBadge('Bridges unverified', 'gray');
    }

    return `
      <div style="display:flex; align-items:center; gap:.6rem; flex-wrap:wrap;
                  margin-top:.75rem; padding:.6rem .75rem; border-radius:6px;
                  background:var(--bg-card); border:1px solid var(--border-color);
                  border-left:3px solid ${border};">
        <span aria-hidden="true">${icon}</span>
        <span style="color:var(--text-primary);">${text}</span>
        ${bridges}
        ${status === 'failed' && row.provision_error
          ? `<div style="flex-basis:100%; color:var(--danger); font-size:.85rem;">${esc(row.provision_error)}</div>`
          : ''}
      </div>`;
  },

  // ── Poll ──────────────────────────────────────────────────────────────────
  // setInterval with a ceiling and a single clear path, not a recursive
  // setTimeout: a re-entrant timer is how the admin page ended up with one
  // stopper and several running loops after a client switch.

  syncPoll() {
    if (this.anyProvisioning()) this.startPoll(); else this.stopPoll();
  },

  anyProvisioning() {
    return this._engagements.some((e) => e.provision_status === 'provisioning');
  },

  /**
   * THE OTHER HALF OF stopPoll(). Leaving the tab stops the timer — correct, a
   * loop repainting a panel nobody is looking at is exactly what that stop is
   * for — but nothing restarted it, and a reservation takes MINUTES. An
   * instructor who starts one and goes to look at their roster while it runs
   * comes back to a card frozen on "Reserving the network…" for the rest of the
   * page's life, describing a reservation that may have finished, or failed,
   * ten minutes ago. Every route back in went through ensureInit(), which
   * returns on its first line once _inited is set.
   *
   * Only restarts when there is something to watch, so an idle re-entry costs
   * nothing. Takes a reading IMMEDIATELY as well as scheduling the next one: the
   * state the instructor came back to look at is the one that changed while they
   * were away, and it should not take another five seconds to appear.
   *
   * startPoll() resets the ten-minute ceiling, and that is deliberate here — the
   * ceiling exists to stop an unattended loop running forever, and a deliberate
   * return to the tab is the opposite of unattended.
   */
  resumePoll() {
    if (!this._inited || !this._profileId) return;
    if (this._pollTimer) return;
    if (!this.anyProvisioning()) return;
    this.startPoll();
    this.loadList({ silent: true });
  },

  startPoll() {
    if (this._pollTimer) return;
    this._pollCount = 0;
    this._pollTimer = setInterval(() => {
      this._pollCount += 1;
      // 120 × 5s = 10 minutes. A reservation is 25-50 serial VNet POSTs plus a
      // cluster-wide apply; past ten minutes the answer is a page refresh, not
      // another request every five seconds forever.
      if (this._pollCount > 120) {
        this.stopPoll();
        if (typeof Toast !== 'undefined') {
          Toast.warning('Still reserving',
            'The network reservation is taking longer than expected. Reload to check again.');
        }
        return;
      }
      this.loadList({ silent: true });
    }, 5000);
  },

  stopPoll() {
    if (!this._pollTimer) return;
    clearInterval(this._pollTimer);
    this._pollTimer = null;
    this._pollCount = 0;
  },

  // ── Detail ────────────────────────────────────────────────────────────────

  async open(engagementId) {
    this._openId = engagementId;
    this._detail = null;
    this._draft = {};
    this._notices = {};
    this.renderLoading();
    try {
      const data = await API.engagements.get(engagementId);
      if (this._openId !== engagementId) return;
      this._detail = data;
      this.resetDraft();
      this.renderDetail();
    } catch (err) {
      if (this._openId !== engagementId) return;
      console.error('Engagements: detail failed:', err);
      const body = this.body();
      if (body) {
        body.innerHTML = `
          <div class="card">
            <div class="empty-state">
              <div class="icon">⚠️</div>
              <h3>Couldn't open this engagement</h3>
              <p>${esc((err && err.message) || 'Request failed')}</p>
              <button class="btn btn-outline btn-sm" onclick="Engagements.back()">Back to the list</button>
            </div>
          </div>`;
      }
    }
  },

  back() {
    this._openId = null;
    this._detail = null;
    this._draft = {};
    this._notices = {};
    this.renderList();
  },

  // Only the fields NOT named in `except` are reset, so a save on one field
  // never discards half-typed work in another.
  // Re-read the named fields from the engagement the server just returned.
  // `fields` defaults to ALL of them; after a save it is the ONE field that was
  // saved, so anything half-typed in another editor survives the repaint.
  resetDraft({ fields = null } = {}) {
    const eng = (this._detail && this._detail.engagement) || {};
    const wanted = Array.isArray(fields) ? fields : Object.keys(ENG_FIELD_LABELS);
    Object.keys(ENG_FIELD_LABELS).forEach((field) => {
      if (wanted.indexOf(field) === -1) return;
      const value = eng[field];
      if (field === 'display_name' || field === 'brief') {
        this._draft[field] = value === null || value === undefined ? '' : String(value);
      } else {
        this._draft[field] = engClone(engArr(value));
      }
    });
  },

  renderDetail() {
    const body = this.body();
    if (!body || !this._detail) return;
    const eng = this._detail.engagement || {};
    const plan = this._detail.plan || {};
    const type = eng.type_descriptor || {};
    const retired = !!eng.retired_at;
    const can = eng.can || {};

    // An engagement created but never named still renders. Create and name can
    // be two different people, and a PATCH that failed after a successful
    // create leaves a row that has ALREADY burned a network block — treating
    // that as an error state is how the block gets burned twice.
    const label = eng.display_label || (type.label || 'Engagement');
    // plan.engagement is the compile's own answer to the same question, and it
    // is the one the brief below was written from — so when a plan compiled,
    // it wins outright and the badges cannot contradict the prose.
    const stance = engPosture(plan.engagement || eng, type);

    body.innerHTML = `
      <div style="margin-bottom:.75rem;">
        <button class="btn btn-sm btn-outline" onclick="Engagements.back()">← All engagements</button>
      </div>

      <div class="card" style="margin-bottom:1rem;${retired ? ' opacity:.75;' : ''}">
        <div class="card-header">
          <div>
            <div class="card-title" title="${esc(label)}">${esc(label)}</div>
            <div style="color:var(--text-secondary); font-size:.9rem;">${esc(type.label || '')}</div>
            <div style="display:flex; gap:.35rem; margin-top:.5rem; flex-wrap:wrap;">
              ${engBadge(stance.perspective === 'external' ? 'External' : 'Internal', 'info')}
              ${engBadge(stance.credential_posture === 'credentialed' ? 'Credentialed' : 'No accounts issued',
                stance.credential_posture === 'credentialed' ? 'primary' : 'gray')}
              ${retired ? engBadge('Retired', 'muted') : ''}
            </div>
          </div>
        </div>
        ${this.stateRow(eng, { bridgesReady: this._detail.bridges_ready })}
        ${retired ? '' : this.cardActions(eng, can)}
      </div>

      ${this.vmDatalist(plan)}
      ${retired ? '' : this.nameCard(eng)}
      ${this.briefCard(plan)}
      ${this.startPositionCard(plan)}
      ${this.publicSurfaceCard(plan)}
      ${this.scopeCard(plan)}
      ${this.exposureCard(plan)}
      ${this.credentialsCard(plan)}
      ${this.objectivesCard(plan)}
      ${this.techniquesCard(plan)}
      ${this.capacityCard(plan)}
      ${this.problemsCard(plan)}`;

    Object.keys(this._notices).forEach((field) => this.paintNotice(field));
  },

  // A datalist of the machines the compile actually resolved, so the machine
  // boxes below suggest real names instead of inviting a typo that would come
  // back as a warning after the save.
  vmDatalist(plan) {
    const names = engArr(plan.hosts).map((h) => h && h.vm_name).filter(Boolean);
    if (!names.length) return '';
    return `<datalist id="engVmNames">${
      names.map((n) => `<option value="${esc(n)}"></option>`).join('')
    }</datalist>`;
  },

  // ── Detail: authoring cards ───────────────────────────────────────────────

  fieldFrame(field, inner, { title, subtitle, saveLabel = 'Save' } = {}) {
    return `
      <div class="card" style="margin-bottom:1rem;">
        <div class="card-header">
          <div>
            <div class="card-title">${esc(title || ENG_FIELD_LABELS[field])}</div>
            ${subtitle ? `<div style="color:var(--text-muted); font-size:.85rem; margin-top:.15rem;">${esc(subtitle)}</div>` : ''}
          </div>
          <button class="btn btn-sm btn-primary"
                  onclick="Engagements.save('${escJs(field)}', this)">${esc(saveLabel)}</button>
        </div>
        <div id="engNotice-${esc(field)}"></div>
        <div id="engEditor-${esc(field)}">${inner}</div>
      </div>`;
  },

  nameCard(eng) {
    const value = this._draft.display_name === undefined ? '' : this._draft.display_name;
    const inner = `
      <div class="form-group" style="margin:0;">
        <input type="text" class="form-input" maxlength="200"
               value="${esc(value)}"
               placeholder="${esc((eng.type_descriptor && eng.type_descriptor.label) || 'Engagement')}"
               oninput="Engagements.setScalar('display_name', this.value)">
        <div class="form-hint">Left blank, this engagement shows its type's name.</div>
      </div>`;
    return this.fieldFrame('display_name', inner, {
      subtitle: 'What this engagement is called everywhere it appears.',
    });
  },

  /**
   * "Engagement brief — scope and starting position", and never "what the
   * student sees". A module carries its OWN brief, server-gated so a locked
   * module cannot leak next week's text. Two briefs is correct — one is
   * per-module pedagogy, one is per-environment scope — but a screen that
   * confuses them will visibly contradict the other one.
   */
  briefCard(plan) {
    const brief = plan.brief || {};
    const value = this._draft.brief === undefined ? '' : this._draft.brief;
    const authored = !!(brief.text && String(brief.text).trim());
    const suggested = brief.suggested_text || '';
    const inner = `
      ${authored ? '' : `
        <div style="display:flex; align-items:center; gap:.5rem; margin-bottom:.5rem; flex-wrap:wrap;">
          ${engBadge('Suggested', 'warning')}
          <span style="color:var(--text-muted); font-size:.85rem;">
            Nothing authored yet. This text is derived from the client file and this engagement's type.
          </span>
          ${suggested
            ? '<button class="btn btn-sm btn-outline" onclick="Engagements.useSuggestedBrief(this)">Use this text</button>'
            : ''}
        </div>
        ${suggested ? `<pre style="white-space:pre-wrap; font-family:inherit; background:var(--bg-card);
             border:1px solid var(--border-color); border-radius:6px; padding:.75rem; margin:0 0 .75rem;
             color:var(--text-secondary); max-height:18rem; overflow:auto;">${esc(suggested)}</pre>` : ''}`}
      <div class="form-group" style="margin:0;">
        <textarea class="form-textarea" rows="10" maxlength="20000"
                  oninput="Engagements.setScalar('brief', this.value)"
                  placeholder="Scope, starting position, and the rules the team works under.">${esc(value)}</textarea>
      </div>`;
    return this.fieldFrame('brief', inner, {
      title: 'Engagement brief — scope and starting position',
      subtitle: 'The environment-level brief. A module carries its own, separately.',
    });
  },

  scopeCard(plan) {
    const declared = engArr(plan.declared_only);
    const inner = `
      <div style="margin-bottom:1rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.25rem;">Resolved in scope</div>
        ${engNames(plan.in_scope, 'Nothing resolves in scope.')}
        <div style="font-weight:600; color:var(--text-primary); margin:.75rem 0 .25rem;">Resolved out of scope</div>
        ${engNames(plan.out_of_scope, 'Nothing is excluded.')}
        ${declared.length ? `
          <div style="font-weight:600; color:var(--text-primary); margin:.75rem 0 .25rem;">Documentary rules</div>
          <div style="color:var(--text-muted); font-size:.85rem; margin-bottom:.35rem;">
            Carried into the brief as text. An address or a URL cannot be matched to a machine before
            deploy, so these describe scope rather than filter it.
          </div>
          <ul style="margin:0 0 0 1.1rem; color:var(--text-secondary);">
            ${declared.map((d) => `<li>${esc(d.direction === 'out' ? 'Excluded' : 'Included')}: <code>${esc(d.value)}</code>${d.note ? ` — ${esc(d.note)}` : ''}</li>`).join('')}
          </ul>` : ''}
      </div>
      <div style="border-top:1px solid var(--border-color); padding-top:.75rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.35rem;">In-scope rules</div>
        <div id="engEditor-scope_in">${this.rowEditor('scope_in')}</div>
        <div id="engNotice-scope_in"></div>
        <button class="btn btn-sm btn-primary" style="margin-top:.5rem;"
                onclick="Engagements.save('scope_in', this)">Save in-scope rules</button>
      </div>
      <div style="border-top:1px solid var(--border-color); padding-top:.75rem; margin-top:.75rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.35rem;">Out-of-scope rules</div>
        <div id="engEditor-scope_out">${this.rowEditor('scope_out')}</div>
        <div id="engNotice-scope_out"></div>
        <button class="btn btn-sm btn-primary" style="margin-top:.5rem;"
                onclick="Engagements.save('scope_out', this)">Save out-of-scope rules</button>
      </div>`;
    return engCard('Scope', inner,
      'Authored rules constrain what deploys and what the brief names. Everything else is derived.');
  },

  /**
   * NO ADDRESSES. Every row here is a machine name and a placement LABEL. The
   * compile writes each host's addressing segment during the host loop, BEFORE
   * it proposes exposure, and overwrites placement, cards and octet AFTER it —
   * so a rendered "<segment>.<octet>" would name a machine on the segment the
   * team already stands on, for a machine they are supposed to have to pivot
   * to reach. Placement labels carry the pedagogy and none of that hazard.
   */
  exposureCard(plan) {
    const exposure = engArr(plan.exposure);
    const inner = `
      ${exposure.length ? `
        <div style="overflow-x:auto;">
          <table class="data-table" style="width:100%;">
            <thead><tr><th>Machine</th><th>Placement</th><th>Services</th><th>Note</th></tr></thead>
            <tbody>
              ${exposure.map((e) => `
                <tr>
                  <td>${esc(e.vm_name)}${e.resolved ? '' : ` ${engBadge('Not in this environment', 'warning')}`}</td>
                  <td>${esc(ENG_PLACEMENT_LABELS[e.placement] || e.placement || '')}</td>
                  <td>${esc(engArr(e.services).join(', '))}</td>
                  <td style="color:var(--text-muted); font-size:.85rem;">${esc(e.note || '')}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>`
        : '<p style="color:var(--text-muted);">Nothing is placed outward. Every machine sits on the internal segment.</p>'}
      <div style="border-top:1px solid var(--border-color); padding-top:.75rem; margin-top:.75rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.35rem;">Authored placement</div>
        <div id="engEditor-exposure_plan">${this.rowEditor('exposure_plan')}</div>
        <div id="engNotice-exposure_plan"></div>
        <button class="btn btn-sm btn-primary" style="margin-top:.5rem;"
                onclick="Engagements.save('exposure_plan', this)">Save placement</button>
      </div>`;
    return engCard('Placement', inner,
      'Which segment each machine is homed on. Exactly one machine can be the bridge, and no address is decided here.');
  },

  credentialsCard(plan) {
    const creds = plan.credentials || {};
    const slots = engArr(creds.slots);
    const inner = `
      ${slots.length ? `
        <div style="overflow-x:auto;">
          <table class="data-table" style="width:100%;">
            <thead><tr><th>Slot</th><th>Account</th><th>On machine</th><th>Privilege</th><th>Kind</th></tr></thead>
            <tbody>
              ${slots.map((s) => `
                <tr>
                  <td><code>${esc(s.slot_key)}</code></td>
                  <td>${esc(s.username || '')}</td>
                  <td>${esc(s.target_vm || '—')}</td>
                  <td>${esc(s.privilege || '—')}</td>
                  <td>${esc(s.account_kind || '')}</td>
                </tr>`).join('')}
            </tbody>
          </table>
        </div>`
        : '<p style="color:var(--text-muted);">No accounts are handed over on this engagement.</p>'}
      ${creds.delivery_note ? `<p style="color:var(--text-muted); font-size:.85rem; margin-top:.75rem;">${esc(creds.delivery_note)}</p>` : ''}
      <p style="color:var(--text-secondary); font-size:.85rem; margin-top:.5rem;"><strong>${esc(ENG_CREDENTIAL_LINE)}</strong></p>
      <div style="border-top:1px solid var(--border-color); padding-top:.75rem; margin-top:.75rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.35rem;">Accounts the client hands over</div>
        <div id="engEditor-issued_credentials">${this.rowEditor('issued_credentials')}</div>
        <div id="engNotice-issued_credentials"></div>
        <button class="btn btn-sm btn-primary" style="margin-top:.5rem;"
                onclick="Engagements.save('issued_credentials', this)">Save accounts</button>
      </div>`;
    return engCard('Handed-over accounts', inner,
      'Account intents only — which accounts exist, on which machine, at what privilege.');
  },

  objectivesCard(plan) {
    const objectives = engArr(plan.objectives);
    const total = objectives.reduce((sum, o) => sum + (Number.isInteger(o.points) ? o.points : 0), 0);
    const inner = `
      ${objectives.length ? `
        <ul style="margin:0 0 .5rem 1.1rem; color:var(--text-secondary);">
          ${objectives.map((o) => `<li>${esc(o.title)} — <strong>${esc(String(o.points))}</strong> points</li>`).join('')}
        </ul>
        <p style="color:var(--text-primary); margin:0;"><strong>${esc(String(objectives.length))}</strong> objectives, <strong>${esc(String(total))}</strong> points in total.</p>`
        : '<p style="color:var(--text-muted);">No objectives.</p>'}
      <div style="border-top:1px solid var(--border-color); padding-top:.75rem; margin-top:.75rem;">
        <div style="font-weight:600; color:var(--text-primary); margin-bottom:.35rem;">Authored objectives</div>
        <div style="color:var(--text-muted); font-size:.85rem; margin-bottom:.35rem;">
          Authoring any objective replaces the derived list entirely.
        </div>
        <div id="engEditor-objectives">${this.rowEditor('objectives')}</div>
        <div id="engNotice-objectives"></div>
        <button class="btn btn-sm btn-primary" style="margin-top:.5rem;"
                onclick="Engagements.save('objectives', this)">Save objectives</button>
      </div>`;
    return engCard('Objectives', inner);
  },

  // ── Detail: read-only cards ───────────────────────────────────────────────

  startPositionCard(plan) {
    const start = plan.start_position || {};
    const external = start.perspective === 'external';
    const headline = external
      ? 'The team starts outside, on the attack box, with nothing but the forward-facing site.'
      : 'The team starts inside, with the accounts below handed over on day one.';
    // engProse, not start.note: on an external engagement the compile's note is
    // written for a per-lane brief and still holds the lane's own unfilled
    // external /24. See engProse — a placeholder that never gets filled in is
    // the same defect as an address, one layer up.
    const note = engProse(start.note);
    const inner = `
      <p style="color:var(--text-primary); margin:0 0 .5rem;">${esc(headline)}</p>
      ${note ? `<p style="color:var(--text-muted); font-size:.9rem; margin:0;">${esc(note)}</p>` : ''}`;
    return engCard('Starting position', inner);
  },

  /**
   * 'asset' and 'synthetic' get DIFFERENT sentences on purpose. Collapsing them
   * makes every client look like it runs a web site — the distinction is
   * editorial, not technical: one means the client file has a web server, the
   * other means the environment supplied one for this engagement.
   */
  publicSurfaceCard(plan) {
    const surface = plan.public_surface;
    if (!surface) {
      return engCard('Public surface',
        '<p style="color:var(--text-muted); margin:0;">Nothing in this environment faces outward.</p>');
    }
    let sentence;
    if (surface.source === 'asset') sentence = "The client's own web server is the forward-facing surface.";
    else if (surface.source === 'synthetic') sentence = 'The environment supplies a forward-facing site for this engagement.';
    else sentence = 'The forward-facing surface is the machine this engagement places outward.';

    // NO STARTING POINT LINE. brief.facts.surface_url is a TEMPLATE, not an
    // address: the compile emits it with the lane's own external /24 left as an
    // unfilled placeholder, because the lane that substitutes it does not exist
    // until deploy time. Printing it here handed the instructor something that
    // looks like a URL, reads like one, and resolves nowhere — worse than
    // printing nothing, and a direct breach of this file's own rule. The
    // machine and its placement label carry the whole of the pedagogy. B2
    // renders addresses, once the compile's pre/post-exposure ordering is
    // closed and there is a real one to render.
    const inner = `
      <p style="color:var(--text-primary); margin:0 0 .35rem;">${esc(sentence)}</p>
      <p style="color:var(--text-secondary); margin:0;">${esc(surface.target_vm)}${
        surface.placement ? ` — ${esc(ENG_PLACEMENT_LABELS[surface.placement] || surface.placement)}` : ''}</p>`;
    return engCard('Public surface', inner);
  },

  /**
   * READ-ONLY, and it stays read-only. The rules of engagement are always
   * derived from the perspective and the credential posture; the stored column
   * has no reader in the compile at all. An editor here would save an edit that
   * changes nothing AND stamp the field as authored, which would lock a later
   * refresh out of it permanently.
   */
  techniquesCard(plan) {
    const techniques = engArr(plan.techniques);
    if (!techniques.length) return '';
    const inner = `
      <ul style="margin:0 0 0 1.1rem; color:var(--text-secondary);">
        ${techniques.map((t) => `
          <li style="margin-bottom:.3rem;">
            ${t.allowed ? '✅' : '⛔'} <strong>${esc(t.label)}</strong>
            ${t.constraint ? `<div style="color:var(--text-muted); font-size:.85rem;">${esc(t.constraint)}</div>` : ''}
            ${t.note ? `<div style="color:var(--text-muted); font-size:.85rem;">${esc(t.note)}</div>` : ''}
          </li>`).join('')}
      </ul>`;
    return engCard('Rules of engagement', inner,
      'Derived from the perspective and credential posture.');
  },

  capacityCard(plan) {
    const cap = plan.capacity || {};
    const inner = `
      <p style="margin:0; color:var(--text-primary);">
        <strong>${esc(String(cap.pinnable == null ? '—' : cap.pinnable))}</strong>
        of <strong>${esc(String(cap.pinnable_capacity == null ? '—' : cap.pinnable_capacity))}</strong>
        addressable machines used.
      </p>
      ${cap.over_capacity
        ? `<p style="color:var(--danger); margin:.35rem 0 0;">Over capacity. Deselect machines, or split this client across two engagements.</p>`
        : ''}`;
    return engCard('Capacity', inner);
  },

  problemsCard(plan) {
    const problems = engArr(plan.problems);
    if (!problems.length) {
      return engCard('Problems',
        '<p style="color:var(--text-muted); margin:0;">Nothing to report. This engagement compiles clean.</p>');
    }
    const order = { error: 0, warn: 1, info: 2 };
    const icons = { error: '❌', warn: '⚠️', info: 'ℹ️' };
    const sorted = problems.slice().sort((a, b) => (order[a.severity] ?? 3) - (order[b.severity] ?? 3));
    const inner = `
      <ul style="list-style:none; margin:0; padding:0;">
        ${sorted.map((p) => `
          <li style="padding:.5rem 0; border-bottom:1px solid var(--border-color);">
            <div>${icons[p.severity] || 'ℹ️'} <strong>${esc(p.message)}</strong></div>
            ${p.ref ? `<div style="margin-top:.2rem;"><code>${esc(p.ref)}</code></div>` : ''}
          </li>`).join('')}
      </ul>`;
    return engCard('Problems', inner);
  },

  // ── Row editor ────────────────────────────────────────────────────────────

  rowEditor(field) {
    const spec = ENG_ROW_FIELDS[field];
    const rows = engArr(this._draft[field]);
    const body = rows.length
      ? rows.map((row, i) => this.rowEditorRow(field, spec, row, i)).join('')
      : `<p style="color:var(--text-muted); margin:.25rem 0;">${esc(spec.empty)}</p>`;
    return `
      ${body}
      <button class="btn btn-sm btn-outline" style="margin-top:.35rem;"
              onclick="Engagements.addRow('${escJs(field)}')">${esc(spec.addLabel)}</button>`;
  },

  rowEditorRow(field, spec, row, index) {
    const cells = spec.columns.map((col) => {
      const raw = row[col.key];
      const value = col.type === 'list' ? engArr(raw).join(', ')
        : (raw === null || raw === undefined ? '' : String(raw));
      const style = `flex:${col.width ? '0 0 ' + col.width : '1 1 10rem'}; min-width:7rem;`;
      const handler = `Engagements.setCell('${escJs(field)}', ${index}, '${escJs(col.key)}', this.value)`;
      if (col.type === 'select') {
        const labels = col.optionLabels || {};
        return `
          <label style="${style}">
            <span style="display:block; font-size:.75rem; color:var(--text-muted);">${esc(col.label)}</span>
            <select class="form-select" onchange="${handler}">
              ${col.options.map((o) => `<option value="${esc(o)}"${o === value ? ' selected' : ''}>${esc(labels[o] || o)}</option>`).join('')}
            </select>
          </label>`;
      }
      return `
        <label style="${style}">
          <span style="display:block; font-size:.75rem; color:var(--text-muted);">${esc(col.label)}</span>
          <input type="${col.type === 'number' ? 'number' : 'text'}" class="form-input"
                 ${col.list ? `list="${esc(col.list)}"` : ''}
                 ${col.placeholder ? `placeholder="${esc(col.placeholder)}"` : ''}
                 value="${esc(value)}" oninput="${handler}">
        </label>`;
    }).join('');
    return `
      <div style="display:flex; gap:.5rem; align-items:flex-end; flex-wrap:wrap;
                  padding:.5rem 0; border-bottom:1px solid var(--border-color);">
        ${cells}
        <button class="btn btn-sm btn-outline" title="Remove this row"
                onclick="Engagements.removeRow('${escJs(field)}', ${index})">Remove</button>
      </div>`;
  },

  repaintEditor(field) {
    const host = document.getElementById(`engEditor-${field}`);
    if (host) host.innerHTML = this.rowEditor(field);
  },

  addRow(field) {
    const spec = ENG_ROW_FIELDS[field];
    if (!spec) return;
    if (!Array.isArray(this._draft[field])) this._draft[field] = [];
    this._draft[field].push(spec.blank());
    this.repaintEditor(field);
  },

  removeRow(field, index) {
    if (!Array.isArray(this._draft[field])) return;
    this._draft[field].splice(index, 1);
    this.repaintEditor(field);
  },

  // Writes ONE named key on ONE row. Everything else on that row — a
  // credential's delivery block, an objective's mapping — is left exactly as
  // the server sent it, so a field this screen does not offer cannot be
  // silently dropped by an edit to the field beside it.
  setCell(field, index, key, raw) {
    const spec = ENG_ROW_FIELDS[field];
    const rows = this._draft[field];
    if (!spec || !Array.isArray(rows) || !rows[index]) return;
    const col = spec.columns.find((c) => c.key === key);
    const type = col ? col.type : 'text';
    if (type === 'list') {
      rows[index][key] = String(raw).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (type === 'number') {
      const n = parseInt(raw, 10);
      rows[index][key] = Number.isInteger(n) ? n : null;
    } else {
      const s = String(raw);
      rows[index][key] = s.trim() === '' ? null : s;
    }
  },

  setScalar(field, value) {
    this._draft[field] = String(value);
  },

  useSuggestedBrief(btn) {
    const plan = (this._detail && this._detail.plan) || {};
    const suggested = (plan.brief && plan.brief.suggested_text) || '';
    if (!suggested) return;
    this._draft.brief = suggested;
    this.save('brief', btn);
  },

  // ── Save ──────────────────────────────────────────────────────────────────

  /**
   * ONE FIELD PER REQUEST. The route picks seven names out of the body and
   * ignores everything else, so a request carrying one field can only ever
   * stamp that one field as authored — which is what keeps a later refresh
   * able to update the rest.
   */
  async save(field, btn) {
    if (!this._openId || !ENG_FIELD_LABELS[field]) return;
    const body = {};
    body[field] = this._draft[field];
    if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, true, 'Saving…');
    this._notices[field] = null;
    this.paintNotice(field);
    try {
      const data = await API.engagements.patch(this._openId, body);
      // The warnings the writer computes and throws away on the success path —
      // "this placement needs a v3 reservation", "that machine is not in this
      // environment" — reach the instructor here and nowhere else.
      this._notices[field] = { errors: [], warnings: engArr(data.warnings) };
      Toast.success('Saved', `${ENG_FIELD_LABELS[field]} updated.`);
      // Re-read the detail: the brief, the exposure rows, the scope lists and
      // the problem list are all DERIVED from what was just written, so a
      // partial repaint would leave the screen disagreeing with itself.
      await this.reloadDetail({ refreshField: field });
    } catch (err) {
      const data = (err && err.data) || {};
      this._notices[field] = {
        errors: engArr(data.errors),
        warnings: engArr(data.warnings),
        message: (err && err.message) || 'Request failed',
      };
      this.paintNotice(field);
      Toast.error("Couldn't save", (err && err.message) || 'Request failed');
    } finally {
      if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, false);
    }
  },

  async reloadDetail({ refreshField = null } = {}) {
    const id = this._openId;
    if (!id) return;
    try {
      const data = await API.engagements.get(id);
      if (this._openId !== id) return;
      this._detail = data;
      // Only the saved field is re-read from the server; anything half-typed in
      // another field survives.
      this.resetDraft(refreshField ? { fields: [refreshField] } : {});
      this.renderDetail();
    } catch (err) {
      console.error('Engagements: could not refresh the plan:', err);
      Toast.warning('Saved, but not refreshed',
        'The change was saved. Reopen this engagement to see the recompiled plan.');
    }
  },

  paintNotice(field) {
    const host = document.getElementById(`engNotice-${field}`);
    if (!host) return;
    const notice = this._notices[field];
    if (!notice) { host.innerHTML = ''; return; }
    const errors = engArr(notice.errors);
    const warnings = engArr(notice.warnings);
    if (!errors.length && !warnings.length && !notice.message) { host.innerHTML = ''; return; }
    host.innerHTML = `
      ${errors.length || notice.message ? `
        <div style="margin:.5rem 0; padding:.6rem .75rem; border-radius:6px;
                    border:1px solid var(--danger); color:var(--danger);">
          ${errors.length ? `
            <ul style="margin:0 0 0 1.1rem;">
              ${errors.map((e) => `<li>${e.path ? `<code>${esc(e.path)}</code> — ` : ''}${esc(e.message || e.code || '')}</li>`).join('')}
            </ul>`
            : esc(notice.message)}
        </div>` : ''}
      ${warnings.length ? `
        <div style="margin:.5rem 0; padding:.6rem .75rem; border-radius:6px;
                    border:1px solid var(--warning); color:var(--text-secondary);">
          <strong style="color:var(--warning);">Saved, with notes</strong>
          <ul style="margin:.25rem 0 0 1.1rem;">
            ${warnings.map((w) => `<li>${w.path ? `<code>${esc(w.path)}</code> — ` : ''}${esc(w.message || w.code || '')}</li>`).join('')}
          </ul>
        </div>` : ''}`;
  },

  // ── Create ────────────────────────────────────────────────────────────────

  openCreate() {
    const host = document.getElementById('engModalHost');
    if (!host || !this._profileId) return;
    // engagement_type IS the identity — UNIQUE (profile_id, engagement_type) —
    // so a type this client already holds would come back a 409, not a second
    // engagement. Disable rather than hide: the reason is the useful part.
    const held = new Set(this._engagements.map((e) => e.engagement_type));
    // 'default' is a REAL registry key, not an invented one, so the fallback
    // stays valid against a server that validates the slug it is sent.
    const registryLoaded = this._typesStatus === 'ready' && this._types.length > 0;
    const types = registryLoaded
      ? this._types
      : [{ key: 'default', label: 'Standard engagement', summary: '' }];
    // The list offers this button even when the registry never loaded, because
    // "could not ask" must not read as "nothing left to create". Say which
    // state we are in, here, where the choice is actually being made.
    if (!registryLoaded) this.loadTypes();

    host.innerHTML = `
      <div class="modal-overlay" id="engCreateModal" role="dialog" aria-modal="true"
           aria-labelledby="engCreateTitle">
        <div class="modal">
          <div class="modal-header">
            <h3 class="modal-title" id="engCreateTitle">Create engagement</h3>
            <button class="modal-close" aria-label="Close" onclick="closeModal('engCreateModal')">✕</button>
          </div>
          <div class="modal-body">
            <div class="form-group">
              <label class="form-label" for="engNewType">Engagement type</label>
              <select id="engNewType" class="form-select" onchange="Engagements.onCreateTypeChange()">
                ${types.map((t) => `
                  <option value="${esc(t.key)}"${held.has(t.key) ? ' disabled' : ''}>
                    ${esc(t.label)}${held.has(t.key) ? ' — already recorded for this client' : ''}
                  </option>`).join('')}
              </select>
              <div class="form-hint" id="engNewTypeSummary"></div>
              ${registryLoaded ? '' : `
                <div class="form-hint" style="color:var(--warning);">
                  The engagement type list could not be loaded, so only the standard
                  engagement is offered here. Reopen this after a reload to choose another.
                </div>`}
            </div>
            <div class="form-group">
              <label class="form-label" for="engNewName">Engagement name (optional)</label>
              <input type="text" id="engNewName" class="form-input" maxlength="200"
                     placeholder="Left blank, it takes the type's name.">
            </div>
            <div class="form-group">
              <label class="form-label" for="engNewScheme">Subnet scheme</label>
              <select id="engNewScheme" class="form-select">
                ${ENG_SUBNET_SCHEMES.map((s) => `<option value="${esc(s)}"${s === 'v2' ? ' selected' : ''}>${esc(s)}</option>`).join('')}
              </select>
              <div class="form-hint">
                An outward-facing surface and a bridge machine need v3 — a v2 reservation has one flat segment.
              </div>
            </div>
            <div class="form-group">
              <label class="form-label" for="engNewMax">Student slots</label>
              <input type="number" id="engNewMax" class="form-input" min="1" max="200" value="30">
            </div>
            <p style="color:var(--warning); font-size:.85rem; margin:0;">${esc(ENG_CREATE_WARNING)}</p>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeModal('engCreateModal')">Cancel</button>
            <button class="btn btn-primary" onclick="Engagements.create(this)">Create engagement</button>
          </div>
        </div>
      </div>`;
    this.onCreateTypeChange();
    if (typeof Modal !== 'undefined') Modal.open('engCreateModal');
  },

  onCreateTypeChange() {
    const select = document.getElementById('engNewType');
    const hint = document.getElementById('engNewTypeSummary');
    if (!select || !hint) return;
    const type = this._types.find((t) => t.key === select.value);
    hint.textContent = (type && type.summary) || '';
  },

  async create(btn) {
    const profileId = this._profileId;
    if (!profileId) return;
    const engagementType = (document.getElementById('engNewType') || {}).value || 'default';
    const displayName = ((document.getElementById('engNewName') || {}).value || '').trim();
    const subnetScheme = (document.getElementById('engNewScheme') || {}).value || 'v2';
    const maxStudents = parseInt((document.getElementById('engNewMax') || {}).value, 10);

    if (!Number.isInteger(maxStudents) || maxStudents < 1 || maxStudents > 200) {
      Toast.warning('Check the slot count', 'Student slots must be a whole number between 1 and 200.');
      return;
    }

    const ok = await Confirm.show({
      title: 'Reserve a network for this engagement?',
      message: ENG_CREATE_WARNING,
      confirmText: 'Create engagement',
      cancelText: 'Cancel',
      danger: true,
    });
    if (!ok) return;

    if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, true, 'Reserving…');
    try {
      await API.engagements.create({
        profile_id: profileId,
        engagement_type: engagementType,
        subnet_scheme: subnetScheme,
        max_students: maxStudents,
        display_name: displayName || undefined,
      });
      closeModal('engCreateModal');
      Toast.success('Engagement created', 'The network reservation is running now.');
      await this.loadList();
    } catch (err) {
      console.error('Engagements: create failed:', err);
      Toast.error("Couldn't create the engagement", (err && err.message) || 'Request failed');
    } finally {
      if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, false);
    }
  },

  // ── Adopt ─────────────────────────────────────────────────────────────────

  async adopt(engagementType, btn) {
    const profileId = this._profileId;
    if (!profileId) return;
    const ok = await Confirm.show({
      title: 'Record the existing reservation?',
      message: ENG_ADOPT_WARNING,
      confirmText: 'Adopt reservation',
      cancelText: 'Cancel',
    });
    if (!ok) return;

    if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, true, 'Adopting…');
    try {
      await API.engagements.adopt({ profile_id: profileId, engagement_type: engagementType });
      Toast.success('Reservation adopted', 'The existing network is now recorded as an engagement.');
      await this.loadList();
    } catch (err) {
      console.error('Engagements: adopt failed:', err);
      Toast.error("Couldn't adopt the reservation", (err && err.message) || 'Request failed');
    } finally {
      if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, false);
    }
  },

  // ── Reprovision ───────────────────────────────────────────────────────────

  /**
   * Offered only on a FAILED reservation. Force is behind a SECOND
   * confirmation, and it is only ever reached after the plain retry has been
   * refused — re-running a reservation that is actually healthy carves a
   * second block that nothing can hand back.
   */
  async reprovision(engagementId, btn) {
    const ok = await Confirm.show({
      title: 'Retry the network reservation?',
      message: 'This resumes the reservation that failed. Nothing new is carved unless the previous attempt left nothing behind.',
      confirmText: 'Retry reservation',
      cancelText: 'Cancel',
    });
    if (!ok) return;

    if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, true, 'Retrying…');
    try {
      await API.engagements.reprovision(engagementId, false);
      Toast.success('Reservation restarted', 'The network reservation is running again.');
      await this.loadList();
      return;
    } catch (err) {
      if (!err || err.status !== 409) {
        console.error('Engagements: reprovision failed:', err);
        Toast.error("Couldn't retry the reservation", (err && err.message) || 'Request failed');
        return;
      }
      // 409 means the server does not consider this engagement to need
      // re-reserving. Forcing past that is the one action on this screen that
      // can silently double a client's capacity cost, so it gets its own
      // confirmation with the cost spelled out.
      const forced = await Confirm.show({
        title: 'Force a new reservation?',
        message: `${err.message} Forcing carves a NEW network block. The one this engagement already holds is not returned.`,
        confirmText: 'Force new reservation',
        cancelText: 'Leave it alone',
        danger: true,
      });
      if (!forced) return;
      try {
        await API.engagements.reprovision(engagementId, true);
        Toast.success('Reservation restarted', 'A new network block is being reserved.');
        await this.loadList();
      } catch (forceErr) {
        console.error('Engagements: forced reprovision failed:', forceErr);
        Toast.error("Couldn't reserve a new network", (forceErr && forceErr.message) || 'Request failed');
      }
    } finally {
      if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, false);
    }
  },

  // ── Retire ────────────────────────────────────────────────────────────────

  async retire(engagementId, btn) {
    const ok = await Confirm.show({
      title: 'Retire this engagement?',
      message: 'Retiring marks the engagement closed and hides its actions. '
        + 'It does NOT return the network block — nothing in this product hands one back. '
        + 'The engagement stays listed so nobody creates a duplicate.',
      confirmText: 'Retire engagement',
      cancelText: 'Cancel',
      danger: true,
    });
    if (!ok) return;

    if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, true, 'Retiring…');
    try {
      await API.engagements.retire(engagementId);
      Toast.success('Engagement retired', 'It stays listed, with its actions closed.');
      if (this._openId === engagementId) this._openId = null;
      await this.loadList();
    } catch (err) {
      console.error('Engagements: retire failed:', err);
      Toast.error("Couldn't retire the engagement", (err && err.message) || 'Request failed');
    } finally {
      if (typeof Utils !== 'undefined') Utils.setBtnLoading(btn, false);
    }
  },
};

window.Engagements = Engagements;

// ── Self-registration: ZERO lines in instructor-core.js ──────────────────
//
// THE THREE MECHANICS THIS RELIES ON, each verified against instructor-core.js:
//
//  1. TAB_NAMES is a top-level `const` in a CLASSIC script. It is therefore NOT
//     a window property, but it IS visible by bare name to every classic script
//     that evaluates after it — and the ARRAY's contents are mutable even though
//     the binding is not. switchTab() reads TAB_NAMES.includes(name) and falls
//     back to 'overview' for anything absent, so the push is what makes
//     #engagements a reachable tab at all.
//  2. activateTabModule is a function DECLARATION, so it IS a real property of
//     the global object and can be wrapped. The bare-name call inside
//     switchTab() resolves to that same property, so the wrapper is seen.
//  3. instructor-core.js boots on DOMContentLoaded, which fires only after every
//     classic script has evaluated — so both edits are in place before
//     initTabs() and the first switchTab() run.
//
// IT COMPOSES, DELIBERATELY. Another tab registering the same way still works,
// and if the ordinary two-line edit for this tab ever lands in
// instructor-core.js, the wrapper's own branch simply answers first and the
// delegate never sees the name. Nothing here overwrites anyone.

/**
 * HAS instructor-core.js EVALUATED YET?
 *
 * THE OBVIOUS TEST IS THE WRONG ONE, and this file shipped with it. `typeof X`
 * is the one operator in the language that does NOT throw on an undeclared
 * identifier — it answers the string 'undefined' and carries on — so
 * `try { typeof TAB_NAMES } catch` can never enter its catch, for any input, on
 * any engine. Wrapped around a `typeof` test, a try/catch is decoration. The
 * guard that existed to turn a mis-ordered <script> tag into one loud console
 * line produced instead exactly the silent dead tab it named.
 *
 * WHAT ACTUALLY DISTINGUISHES THE TWO STATES. instructor-core.js declares
 * TAB_NAMES with `const` and activateTabModule / switchTab with `function`.
 * Those two forms land in DIFFERENT PLACES in a classic script:
 *   • a top-level `const` goes into the global LEXICAL environment — reachable
 *     by bare name from a later script, and NEVER a property of window. So
 *     `window.TAB_NAMES` is undefined whether core ran or not, and tests nothing.
 *   • a top-level function DECLARATION goes onto the global OBJECT. So
 *     `window.activateTabModule` exists if and only if some script has already
 *     declared it — which, on this page, means instructor-core.js has run.
 * That property is the detector. It is also precisely the thing this file needs
 * to exist before it can wrap it, which is what makes it the honest test rather
 * than a proxy for one.
 *
 * And for TAB_NAMES the test is a BARE reference inside try/catch, not a
 * `typeof`: a bare read of an undeclared — or temporal-dead-zone'd — binding
 * throws ReferenceError, which is the signal we want and the one `typeof`
 * swallows.
 */
function engCoreGlobals() {
  let names = null;
  let reason = null;
  try {
    // Bare, deliberately. `typeof TAB_NAMES` here would answer 'undefined' and
    // report success on the very failure this is here to catch.
    names = TAB_NAMES;
  } catch (err) {
    reason = (err && err.message) || String(err);
  }
  return {
    tabNames: Array.isArray(names) ? names : null,
    tabNamesError: reason,
    // The global-object property, not a lexical binding: see above.
    dispatcher: typeof window.activateTabModule === 'function' ? window.activateTabModule : null,
  };
}

const ENG_LOAD_ORDER_HELP =
  'instructor-engagements.js: the Engagements tab did NOT register and is unreachable. Its <script> '
  + 'tag must come AFTER instructor-core.js in instructor.html, which is where TAB_NAMES and '
  + 'activateTabModule are declared. Required order: '
  + 'app.js → ciab-api.js → layout.js → instructor-core.js → instructor-engagements.js.';

(function engRegisterTab() {
  const core = engCoreGlobals();

  // FAIL LOUDLY. Nothing below can work without both of these, and installing
  // half of it is worse than installing none: a wrapper written onto window
  // before instructor-core.js evaluates is overwritten outright by that file's
  // own function declaration, leaving a wrapper that exists, ran, and is
  // unreachable — the hardest shape of this bug to see from a console.
  if (!core.tabNames || !core.dispatcher) {
    console.error(ENG_LOAD_ORDER_HELP, {
      TAB_NAMES_visible: !!core.tabNames,
      TAB_NAMES_error: core.tabNamesError,
      activateTabModule_installed: !!core.dispatcher,
    });
    // Loud on the page too, not just in a console nobody has open. The panel is
    // only there if instructor.html carries it; when it is, an instructor sees a
    // reason instead of an empty tab.
    const panel = document.getElementById('tab-engagements');
    if (panel) {
      panel.innerHTML = '<div class="card"><div class="empty-state">'
        + '<div class="icon">⚠️</div><h3>Engagements did not load</h3>'
        + '<p>This tab’s script ran before the dashboard it attaches to. '
        + 'Reload the page; if it persists, the script order in instructor.html is wrong.</p>'
        + '</div></div>';
    }
    return;
  }

  // The push is guarded: a double-evaluated script must not list the tab twice.
  // The bare name is safe HERE and only here — the branch above returned unless
  // the bare read succeeded, so this line cannot be the one that throws.
  if (TAB_NAMES.indexOf('engagements') === -1) TAB_NAMES.push('engagements');

  const _prevActivateTabModule = core.dispatcher;
  window.activateTabModule = function (name) {
    // Leaving the tab stops the reservation poll. A timer that outlives its
    // panel is how a background loop ends up repainting a screen nobody is
    // looking at, for a client the user has already moved on from.
    if (name !== 'engagements') { Engagements.stopPoll(); }
    else {
      // ensureInit() returns on its first line after the first visit, so the
      // restart cannot live inside it — see resumePoll().
      Engagements.ensureInit();
      Engagements.resumePoll();
      return undefined;
    }
    return _prevActivateTabModule.apply(this, arguments);
  };
}());
