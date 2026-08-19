/**
 * audit-ui.test.js — what the Activity Log tab actually renders.
 *
 * The tab it replaces shipped with three bugs that were invisible in review
 * and obvious in use. Each one is locked in here:
 *
 *   1. Every row rendered "system". admin-activity-log.js:51 read `l.email`,
 *      but the API did `SELECT a.*` from a table in a DIFFERENT database from
 *      cybercore_user (cluster.js:602), so that field never existed and could
 *      not have been joined in.
 *   2. The tab was blank until you clicked Search — loadActivityLog() was
 *      absent from refreshAll() (admin-init.js:5-21) and switchTab dispatched
 *      nothing.
 *   3. The action dropdown was eleven hardcoded values. Six of them (login,
 *      logout, register, submission, review, profile_generation) were never
 *      written by anything, and roughly twenty that WERE written were missing.
 *
 * Follows the repo's vm-stub idiom (see sidebar-nav.test.js): the source is
 * evaluated in a fake browser context and the produced HTML is asserted on.
 *
 * Run: node front-end/test/audit-ui.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const AUDIT_SRC = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'js', 'admin', 'admin-audit.js'), 'utf8'
);
const ADMIN_HTML = fs.readFileSync(
  path.join(__dirname, '..', 'public', 'admin.html'), 'utf8'
);

const ROWS = [
  {
    audit_id: 1,
    occurred_at: '2026-08-18T12:00:00Z',
    actor_user_id: 'u-1', actor_email: 'jane@example.edu', actor_role: 'instructor',
    actor_type: 'user',
    action: 'enrollment.student_added', category: 'enrollment', status: 'success', reason: null,
    target_type: 'course', target_id: 'c-1', target_label: 'CYBV 480',
    target_user_id: 's-1', source: 'cle', ip_address: '10.0.0.7', metadata: {},
  },
  {
    audit_id: 2,
    occurred_at: '2026-08-18T12:05:00Z',
    actor_user_id: null, actor_email: null, actor_role: null, actor_type: 'system',
    action: 'auth.login', category: 'auth', status: 'failure', reason: 'bad_password',
    target_type: null, target_id: null, target_label: null,
    target_user_id: null, source: 'core', ip_address: '10.0.0.9', metadata: {},
  },
];

const FACETS = {
  actions: [
    { action: 'enrollment.student_added', category: 'enrollment', count: 41 },
    { action: 'lane.deployed', category: 'infra', count: 12 },
    { action: 'auth.login', category: 'auth', count: 300 },
  ],
  actors: [
    { actor_user_id: 'u-1', actor_email: 'jane@example.edu', actor_role: 'instructor', count: 41 },
  ],
  sources: [{ source: 'cle', count: 53 }],
  categories: ['auth', 'user', 'enrollment', 'infra', 'content', 'config', 'access'],
  statuses: ['success', 'failure', 'denied'],
};

/**
 * Minimal DOM: elements are bags of properties, and innerHTML is just a
 * string we read back. Enough to exercise the render path without jsdom,
 * which is not a dependency of this repo.
 */
function makeContext({ rows = ROWS, total = 2, apiOverride = null } = {}) {
  const elements = new Map();
  const el = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, value: '', innerHTML: '', checked: false, style: {},
        classList: { add() {}, remove() {}, contains: () => false },
        closest: () => null,
      });
    }
    return elements.get(id);
  };

  const context = {
    document: {
      getElementById: el,
      addEventListener() {},
      createElement: () => ({ set textContent(v) { this._t = v; }, get innerHTML() { return String(this._t ?? ''); }, click() {} }),
      querySelectorAll: () => [],
    },
    // The admin console's own escaper (admin-core.js:168) — same semantics.
    escHtml: (s) => String(s ?? '')
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;'),
    api: apiOverride || (async (method, url) => {
      if (url.startsWith('/audit/facets')) return FACETS;
      if (url.startsWith('/audit?')) return { rows, total, limit: 50, offset: 0, dropped: 0 };
      return {};
    }),
    Toast: { success() {}, error() {}, warning() {}, info() {} },
    Utils: { setBtnLoading() {} },
    headers: () => ({}),
    fetch: async () => ({ ok: true, blob: async () => ({}) }),
    URL: { createObjectURL: () => 'blob:x', revokeObjectURL() {} },
    setInterval: () => 0,
    clearInterval() {},
    Date,
    JSON,
    Math,
    console,
    encodeURIComponent,
    URLSearchParams,
  };
  context.window = context;
  vm.createContext(context);
  vm.runInContext(AUDIT_SRC, context);
  return { context, el };
}

test('BUG 1: a row renders the actor email, not "system"', async () => {
  const { context, el } = makeContext();
  await context.loadAuditLog(0);

  const html = el('auditTable').innerHTML;
  assert.ok(html.includes('jane@example.edu'), 'the actor must be named');
  assert.ok(html.includes('instructor'), 'the role badge is shown beside it');
});

test('a genuinely system-originated row still says "system"', async () => {
  const { context, el } = makeContext();
  await context.loadAuditLog(0);
  assert.ok(el('auditTable').innerHTML.includes('system'));
});

test('a row with no actor at all renders an em dash, not "undefined"', async () => {
  const { context, el } = makeContext({
    rows: [{ ...ROWS[0], actor_email: null, actor_role: null, actor_type: 'anonymous' }],
    total: 1,
  });
  await context.loadAuditLog(0);
  const html = el('auditTable').innerHTML;
  assert.ok(html.includes('—'));
  assert.ok(!html.includes('undefined'));
});

test('BUG 2: activating the tab loads data without a Search click', async () => {
  const { context, el } = makeContext();
  await context.auditTabActivate();
  assert.ok(el('auditTable').innerHTML.includes('jane@example.edu'));
});

test('BUG 2: the tab button wires the loader, so the tab is never blank', () => {
  const button = ADMIN_HTML.match(/<button[^>]*switchTab\('actlog'[^>]*>/);
  assert.ok(button, 'the Activity Log tab button still exists');
  assert.ok(
    button[0].includes('auditTabActivate()'),
    'switching to the tab must trigger a load — this is the bug that made it render empty'
  );
});

test('BUG 3: the action dropdown is built from live facets, not a literal list', async () => {
  const { context, el } = makeContext();
  await context.loadAuditFacets();

  const html = el('auditAction').innerHTML;
  assert.ok(html.includes('enrollment.student_added'));
  assert.ok(html.includes('lane.deployed'));
  assert.ok(html.includes('<optgroup'), 'actions are grouped by category');
  assert.ok(html.includes('(41)'), 'counts come from the data');
});

test('BUG 3: the markup ships no hardcoded action list to go stale', () => {
  const tab = ADMIN_HTML.slice(
    ADMIN_HTML.indexOf('<div class="tab-content" id="tab-actlog">'),
    ADMIN_HTML.indexOf('<!-- Detail drawer')
  );
  const select = tab.slice(tab.indexOf('id="auditAction"'));
  const options = select.slice(0, select.indexOf('</select>')).match(/<option/g) || [];
  assert.strictEqual(options.length, 1, 'only the "All Actions" placeholder is static');
  // The six that were offered but never written by anything.
  for (const dead of ['"submission"', '"review"', '"profile_generation"', '"toggle_accounts"']) {
    assert.ok(!tab.includes(dead), `stale hardcoded option ${dead} is gone`);
  }
});

test('the actor datalist is populated from facets so instructors are pickable', async () => {
  const { context, el } = makeContext();
  await context.loadAuditFacets();
  const html = el('auditActorList').innerHTML;
  assert.ok(html.includes('jane@example.edu'));
  assert.ok(html.includes('41 events'));
});

test('every interpolated field is escaped', async () => {
  const { context, el } = makeContext({
    rows: [{
      ...ROWS[0],
      actor_email: '<img src=x onerror=alert(1)>',
      target_label: '"><script>alert(2)</script>',
    }],
    total: 1,
  });
  await context.loadAuditLog(0);

  const html = el('auditTable').innerHTML;
  assert.ok(!html.includes('<img src=x'), 'actor email must not render as markup');
  assert.ok(!html.includes('<script>'), 'target label must not render as markup');
  assert.ok(html.includes('&lt;img'));
});

test('a failed event shows its status and reason rather than a tick', async () => {
  const { context, el } = makeContext();
  await context.loadAuditLog(0);
  const html = el('auditTable').innerHTML;
  assert.ok(html.includes('bad_password'), 'the reason is visible in the list');
  assert.ok(html.includes('badge-red'), 'a non-success row is coloured as a problem');
});

test('the empty state is a card, and uses a theme token rather than literal white', async () => {
  const { context, el } = makeContext({ rows: [], total: 0 });
  await context.loadAuditLog(0);
  const html = el('auditTable').innerHTML;
  assert.ok(html.includes('No activity matches'));
  // layout.js runs a dark-mode patch pass over hardcoded backgrounds; the old
  // code hardcoded `background: white` here and broke under data-theme="dark".
  assert.ok(html.includes('var(--bg-card'));
});

test('pagination reports the true total and only offers reachable pages', async () => {
  const { context, el } = makeContext({ rows: ROWS, total: 120 });
  await context.loadAuditLog(0);
  const pag = el('auditPagination').innerHTML;
  assert.ok(pag.includes('120 total'));
  assert.ok(pag.includes('Page 1/3'));
  assert.ok(pag.includes('Next'));
  assert.ok(!pag.includes('Prev'), 'no Prev on the first page');
});

test('an API error surfaces in the tab instead of leaving it on "Loading…"', async () => {
  const { context, el } = makeContext({
    apiOverride: async () => { throw new Error('boom'); },
  });
  await context.loadAuditLog(0);
  assert.ok(el('auditTable').innerHTML.includes('boom'));
});

test('the script tag is loaded before admin-init.js', () => {
  const audit = ADMIN_HTML.indexOf('/js/admin/admin-audit.js');
  const init = ADMIN_HTML.indexOf('/js/admin/admin-init.js');
  assert.ok(audit > 0, 'admin-audit.js is referenced');
  assert.ok(audit < init, 'admin-init.js must stay last');
  assert.ok(!ADMIN_HTML.includes('admin-activity-log.js'), 'the replaced file is not still referenced');
});
