/**
 * instructor-core.js — Instructor Dashboard shell: state, tabs, shared helpers.
 * ============================================================================
 * Replaces the old inline <script> block as the provider of the page globals.
 * Load order matters and is wired in instructor.html:
 *
 *   app.js → ciab-api.js → layout.js → THIS FILE → instructor-overview.js →
 *   instructor-students.js → instructor-reviews.js → instructor-documents.js →
 *   csv.js → instructor-sections.js → instructor-roster-import.js
 *
 * GLOBALS CONTRACT (names frozen — instructor-sections.js and
 * instructor-roster-import.js depend on them; see their headers):
 *   switchTab(name)   — tab activation; accepts legacy 'dashboard' → 'overview'
 *   closeModal(id)    — delegates to the kit Modal helper in app.js
 *   escapeHtml(s)     — alias of Utils.escapeHtml
 * Plus, for the per-tab modules:
 *   InstructorState   — shared store; one /dashboard fetch feeds every tab
 *   PART_NAMES        — canonical part labels (mirrors utils/part-definitions.js)
 *   timeAgo(iso)      — relative age for submission chips
 *
 * Per-tab modules register as window.Overview / Students / Reviews / Docs /
 * Incidents with an ensureInit() that renders once from current state and
 * subscribes once.
 * The Sections tab keeps its original contract: Sections.load() on every visit.
 */
/* global API, Toast, Auth, Utils, Modal */

// ── Shared helpers ──────────────────────────────────────────────────────────

// Not Utils.escapeHtml: the kit's textContent trick leaves quotes alone,
// which is unsafe for the `title="${esc(...)}"` attribute interpolations
// these modules use. This escaper covers both element and attribute context.
const escapeHtml = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => (
  { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
));
const esc = escapeHtml;

// For values interpolated into an inline onclick's '…' JS string. esc() alone
// is not enough there: the HTML parser decodes &#39; back to a raw quote
// BEFORE the JS engine reads the attribute, so quotes must be backslash-
// escaped for the JS context first, then entity-escaped for the attribute.
const escJs = (s) => esc(String(s ?? '').replace(/\\/g, '\\\\').replace(/'/g, "\\'"));

// Mirrors ciab/utils/part-definitions.js — the single server-side source of
// truth. The old page carried three disagreeing copies of this list.
const PART_NAMES = {
  1: 'Clinic Orientation',
  2: 'Organizational Understanding',
  3: 'Threat Identification',
  4: 'Vulnerability Discovery',
  5: 'Risk Analysis',
  6: 'Controls and Mitigations',
  7: 'Reporting and Communication',
  8: 'Reflection and Workforce Alignment',
};

function partLabel(n) {
  return `Part ${n}: ${PART_NAMES[n] || 'Assessment'}`;
}

function timeAgo(iso) {
  if (!iso) return '';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '';
  const mins = Math.floor((Date.now() - then) / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  return Utils.formatDate(iso);
}

// Older than this and a submission is a problem, not a queue item.
const OVERDUE_DAYS = 7;

function isOverdue(iso) {
  if (!iso) return false;
  return Date.now() - new Date(iso).getTime() > OVERDUE_DAYS * 24 * 3600 * 1000;
}

// ── Shared state ────────────────────────────────────────────────────────────
// One /dashboard payload feeds four tabs. Mutations go through refresh() so a
// review submit repaints the hero, the queue, and the student card in one pass.

const InstructorState = {
  dashboard: null,     // full /dashboard payload
  sections: [],        // sections the instructor manages (drives filters)
  scope: 'mine',       // what we ASK for: 'mine' | 'all' | <section uuid>
  scopeApplied: null,  // what the server DID ('mine' falls back to 'all' when
                       // the instructor manages no sections)
  profiles: [],        // the instructor's own profiles (Documents tab, assign)
  status: 'idle',      // 'idle' | 'loading' | 'ready' | 'error'
  error: null,
  _subs: {},

  on(evt, fn) { (this._subs[evt] = this._subs[evt] || []).push(fn); },
  emit(evt, data) { (this._subs[evt] || []).forEach((fn) => fn(data)); },

  async refresh({ scope } = {}) {
    if (scope) this.scope = scope;
    this.status = 'loading';
    this.emit('loading');
    try {
      const response = await API.instructor.dashboard(this.scope);
      this.dashboard = response.dashboard || {};
      this.sections = this.dashboard.sections || [];
      this.scopeApplied = this.dashboard.scope_applied || 'all';
      this.status = 'ready';
      this.error = null;
      this.emit('dashboard', this.dashboard);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
      this.status = 'error';
      this.error = error;
      const msg = error?.message || 'Unknown error';
      if (error?.status === 401 || msg.includes('Authentication')) {
        Toast.error('Session Expired', 'Please log in again.');
        setTimeout(() => { window.location.href = '/login'; }, 2000);
      } else if (error?.status === 403) {
        Toast.error('Access Denied', 'Your account needs the instructor role. Contact an administrator.');
      } else {
        Toast.error('Error', `Failed to load instructor dashboard: ${msg}`);
      }
      this.emit('error', error);
    }
  },

  async loadProfiles() {
    try {
      const response = await API.profiles.list();
      this.profiles = (response.profiles || []).map((p) => ({
        ...p,
        display_name: profileDisplayName(p),
      }));
      this.emit('profiles', this.profiles);
    } catch (error) {
      console.error('Failed to load profiles:', error);
    }
  },
};

// Descriptive dropdown label: company, then industry/difficulty/city context.
function profileDisplayName(p) {
  let name = p.companyName || p.company_name || p.name;
  if (!name) {
    name = p.clientTypeName || p.client_type_name || p.industry
      || `Profile ${(p.id || '').substring(0, 8)}`;
  }
  const extras = [];
  if (p.industry && (p.companyName || p.company_name)) extras.push(p.industry);
  if (p.difficulty) extras.push(p.difficulty);
  const city = p.hqCity || p.hq_city || '';
  if (city) extras.push(city);
  return extras.length ? `${name} — ${extras.join(' | ')}` : name;
}

// ── Modals ──────────────────────────────────────────────────────────────────
// The kit Modal helper (app.js) owns Esc/backdrop/focus-trap/scroll-lock.
// closeModal keeps its historical name — Sections/RosterImport call it.

function openModal(id) { Modal.open(id); }
function closeModal(id) { Modal.close(id); }

// ── Tabs: hash routing + keyboard ───────────────────────────────────────────

const TAB_NAMES = ['overview', 'sections', 'modules', 'students', 'reviews', 'documents', 'incidents'];
const TAB_ALIASES = { dashboard: 'overview' }; // legacy callers/bookmarks

function activateTabModule(name) {
  // Sections keeps its original contract — a fresh load() on every visit,
  // preserving the selected section. The rebuilt tabs render once from state
  // and repaint via InstructorState subscriptions.
  if (name === 'sections') { if (window.Sections) Sections.load(); return; }
  // Sections-style re-fetch on EVERY visit, not an ensureInit() map entry: this
  // tab's content hangs off a section list the Sections tab can create or
  // archive, and a co-instructor's reorder must never render stale.
  if (name === 'modules') { if (window.CiabModules) CiabModules.load(); return; }
  const mod = {
    overview: window.Overview,
    students: window.Students,
    reviews: window.Reviews,
    documents: window.Docs,
    // ensureInit() on EVERY visit here too, and it is not a re-fetch: the
    // Incidents tab loads once and afterwards only resumes, because the walk
    // that fills its two pickers crosses four endpoints and repeating it on
    // every tab flip would make the dashboard feel broken.
    //
    // Resuming is the part that matters: that tab's 2s status poll stops itself
    // when its panel stops being the active one, because activateTabModule
    // reports an ENTRY and never a departure. The poll's own visibility check is
    // what ends it, and this call is what restarts it. See
    // instructor-incidents.js.
    incidents: window.Incidents,
  }[name];
  if (mod && typeof mod.ensureInit === 'function') mod.ensureInit();
}

function switchTab(name, { updateHash = true } = {}) {
  name = TAB_ALIASES[name] || name;
  if (!TAB_NAMES.includes(name)) name = 'overview';

  document.querySelectorAll('.tabs [role="tab"]').forEach((btn) => {
    const active = btn.dataset.tab === name;
    btn.classList.toggle('active', active);
    btn.setAttribute('aria-selected', active ? 'true' : 'false');
    btn.tabIndex = active ? 0 : -1;
  });
  document.querySelectorAll('.tab-content').forEach((panel) => {
    panel.classList.toggle('active', panel.id === `tab-${name}`);
  });

  if (updateHash && window.location.hash !== `#${name}`) {
    // replaceState: no scroll jump, no history spam while flipping tabs.
    history.replaceState(null, '', `#${name}`);
  }
  activateTabModule(name);
}

function initTabs() {
  const tablist = document.querySelector('.tabs[role="tablist"]');
  if (!tablist) return;

  tablist.addEventListener('click', (e) => {
    const btn = e.target.closest('[role="tab"]');
    if (btn) switchTab(btn.dataset.tab);
  });

  tablist.addEventListener('keydown', (e) => {
    const tabs = Array.from(tablist.querySelectorAll('[role="tab"]'));
    const idx = tabs.indexOf(document.activeElement);
    if (idx === -1) return;
    let next = null;
    if (e.key === 'ArrowRight') next = (idx + 1) % tabs.length;
    else if (e.key === 'ArrowLeft') next = (idx - 1 + tabs.length) % tabs.length;
    else if (e.key === 'Home') next = 0;
    else if (e.key === 'End') next = tabs.length - 1;
    if (next === null) return;
    e.preventDefault();
    tabs[next].focus();
    switchTab(tabs[next].dataset.tab);
  });

  window.addEventListener('hashchange', () => {
    switchTab(window.location.hash.slice(1) || 'overview', { updateHash: false });
  });
}

// Pending-count badge on the Review Queue tab button.
function updateReviewTabCount() {
  const el = document.getElementById('reviewsTabCount');
  if (!el) return;
  const d = InstructorState.dashboard || {};
  const total = d.pending_total ?? (d.pending_submissions || []).length;
  el.textContent = total;
  el.hidden = !total;
}

// ── Boot ────────────────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', async () => {
  if (!await Auth.requireAuth()) return;

  // isRealInstructor(), not user.role: Student View rewrites the drawn role to
  // 'student', and gating entry on that would bounce an instructor off their
  // own dashboard the moment they turned the mode on.
  const user = Auth.getUser();
  if (!Auth.isRealInstructor()) {
    Toast.error('Access Denied', 'You must be an instructor to access this page');
    window.location.href = '/dashboard';
    return;
  }

  // Admins default to the whole platform; instructors to their sections (the
  // server falls back to 'all' — and says so via scope_applied — when they
  // manage none).
  InstructorState.scope = Auth.isRealAdmin() ? 'all' : 'mine';

  initTabs();
  InstructorState.on('dashboard', updateReviewTabCount);

  // Land on the deep-linked tab first so its loading state shows while the
  // data is in flight.
  switchTab(window.location.hash.slice(1) || 'overview', { updateHash: false });

  // Reveal the Vuln-App Answer Key card for instructor + admin DRAWN roles.
  // user.role, not isRealInstructor(): this is chrome, and an answer key is
  // the last thing that should be on screen in a lecture recording. In
  // Student View it stays hidden.
  if (user.role === 'instructor' || user.role === 'admin') {
    const card = document.getElementById('vulnCheatSheetCard');
    if (card) card.style.display = '';
  }

  await Promise.all([
    InstructorState.refresh(),
    InstructorState.loadProfiles(),
  ]);
});
