/**
 * ticket-sidebar.test.js — the Submit a Ticket control in the sidebar footer.
 *
 * WHY THIS FILE EXISTS
 * The footer is shared ground. It already carries an admin-only link, an
 * instructor-only Student View toggle and the user menu, and
 * test/view-mode-nav.test.js asserts several NEGATIVE properties about it: a
 * student's footer must contain no href="/admin", a previewing admin's must
 * contain no >Admin<, and a student's must not mention Student View. Those are
 * easy to break from a distance — an HTML comment inside getSidebarHTML() is
 * enough to do it, because the comment ships in the returned markup.
 *
 * So this file pins the positive property (every role gets the control) beside
 * the negatives, and pins the two structural rules that make the widget work at
 * all: getSidebarHTML() stays a pure string builder, and the modal is appended
 * to document.body rather than into the sidebar it would otherwise be wiped
 * from on the authReady re-render.
 *
 * Run: node front-end/test/ticket-sidebar.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const PUBLIC = path.join(__dirname, '..', 'public');

/** A stub browser, mirroring the one in view-mode-nav.test.js. */
function makeWindow() {
  const sandbox = {};
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.console = console;
  sandbox.location = { protocol: 'https:', pathname: '/hub', href: '/hub', search: '', reload() {} };
  sandbox.addEventListener = () => {};
  sandbox.removeEventListener = () => {};
  sandbox.URLSearchParams = URLSearchParams;
  sandbox.setTimeout = () => {};
  sandbox.setInterval = () => {};
  sandbox.clearInterval = () => {};
  sandbox.requestAnimationFrame = fn => fn();

  const created = [];
  const appendedToHead = [];
  const appendedToBody = [];
  sandbox.document = {
    addEventListener() {}, removeEventListener() {},
    createElement: (tag) => {
      const el = { tag, style: {}, dataset: {}, appendChild() {},
                   setAttribute() {}, addEventListener() {},
                   classList: { add() {}, remove() {}, contains: () => false }, innerHTML: '' };
      created.push(el);
      return el;
    },
    querySelector: () => null,
    querySelectorAll: () => [],
    getElementById: () => null,
    head: { appendChild: el => appendedToHead.push(el) },
    body: { appendChild: el => appendedToBody.push(el), classList: { add() {}, remove() {} } },
    documentElement: { getAttribute: () => null, setAttribute() {}, removeAttribute() {} },
  };
  sandbox.localStorage = makeStorage();
  sandbox.sessionStorage = makeStorage();
  sandbox.navigator = { userAgent: 'node' };
  sandbox.fetch = () => Promise.reject(new Error('fetch not stubbed'));

  vm.createContext(sandbox);
  for (const f of ['js/app.js', 'js/layout.js']) {
    vm.runInContext(fs.readFileSync(path.join(PUBLIC, f), 'utf8'), sandbox, { filename: f });
  }
  for (const name of ['Auth', 'ViewMode', 'Layout', 'Utils']) {
    sandbox[name] = vm.runInContext(name, sandbox);
  }
  sandbox._created = created;
  sandbox._head = appendedToHead;
  sandbox._body = appendedToBody;
  return sandbox;
}

function makeStorage() {
  const map = new Map();
  return {
    getItem: k => (map.has(k) ? map.get(k) : null),
    setItem: (k, v) => map.set(k, String(v)),
    removeItem: k => map.delete(k),
  };
}

function signIn(sb, { role, previewing = false }) {
  const server = { id: 'u1', email: 'pat@clinic.local', firstName: 'Pat', lastName: 'Kim', role };
  sb.Auth.realUser = server;
  sb.Auth.user = previewing
    ? { ...server, role: 'student', realRole: role, viewingAsStudent: true }
    : server;
}

const ROLES = ['student', 'instructor', 'admin'];

// ── the control is there, for everyone ──────────────────────────────────────

test('every role gets a Submit a Ticket control', () => {
  // The only footer control that is not gated on something. A student with a
  // broken VM is precisely the person who needs it most.
  for (const role of ROLES) {
    const sb = makeWindow();
    signIn(sb, { role });
    const html = sb.Layout.getSidebarHTML();
    assert.match(html, /class="ticket-btn"/, `${role} has no ticket button`);
    assert.match(html, />Submit a Ticket</, `${role} has no ticket label`);
    assert.match(html, /Layout\.openTicketModal\(\)/, `${role} button is not wired`);
  }
});

test('an instructor previewing as a student keeps it', () => {
  const sb = makeWindow();
  signIn(sb, { role: 'instructor', previewing: true });
  assert.match(sb.Layout.getSidebarHTML(), /class="ticket-btn"/);
});

test('it is the first control in the footer', () => {
  // Directly under where the eye leaves the nav, and above the admin link so
  // the two tinted buttons do not compete for the same spot.
  const sb = makeWindow();
  signIn(sb, { role: 'admin' });
  const html = sb.Layout.getSidebarHTML();
  const footer = html.indexOf('sidebar-footer');
  assert.ok(html.indexOf('ticket-btn') > footer, 'not inside the footer');
  assert.ok(html.indexOf('ticket-btn') < html.indexOf('admin-link-btn'),
    'the ticket button should come before the admin link');
});

// ── the negatives view-mode-nav.test.js guards, restated here ───────────────
//
// Restated deliberately. Those assertions are about Student View and read as
// being about the admin link; someone adding footer chrome would not think to
// run that file. A comment inside getSidebarHTML() is enough to break all three,
// because the comment ships in the returned markup.

test('the ticket control is a button, never a link to /admin', () => {
  for (const role of ROLES) {
    const sb = makeWindow();
    signIn(sb, { role });
    const html = sb.Layout.getSidebarHTML();
    assert.match(html, /<button type="button" class="ticket-btn"/,
      `${role}: the ticket control must be a <button>`);
  }
  const student = makeWindow();
  signIn(student, { role: 'student' });
  assert.doesNotMatch(student.Layout.getSidebarHTML(), /href="\/admin"/);
});

test('nothing in the footer leaks the strings the Student View tests forbid', () => {
  const student = makeWindow();
  signIn(student, { role: 'student' });
  const html = student.Layout.getSidebarHTML();
  assert.doesNotMatch(html, /Student View/);
  assert.doesNotMatch(html, />Admin</);

  const previewing = makeWindow();
  signIn(previewing, { role: 'admin', previewing: true });
  assert.doesNotMatch(previewing.Layout.getSidebarHTML(), />Admin</);
});

test('getSidebarHTML never touches the DOM or the network', () => {
  // Its sandbox returns null from getElementById and rejects every fetch, so a
  // DOM read here does not fail loudly — it returns null and the sidebar
  // silently loses a control.
  const sb = makeWindow();
  signIn(sb, { role: 'admin' });
  sb.document.getElementById = () => { throw new Error('getSidebarHTML read the DOM'); };
  sb.fetch = () => { throw new Error('getSidebarHTML made a request'); };
  assert.doesNotThrow(() => sb.Layout.getSidebarHTML());
});

// ── the widget loader ───────────────────────────────────────────────────────

test('the widget script is injected once, into head, not per page', () => {
  // 21 pages draw a sidebar. A <script> tag in each is 21 edits and 21 chances
  // to miss one, so layout.js loads it — but injectSidebar() runs at least
  // twice per page (DOMContentLoaded, then again on authReady), so it must be
  // idempotent.
  const sb = makeWindow();
  signIn(sb, { role: 'student' });
  sb.Layout.ensureTicketWidget();
  assert.strictEqual(sb._head.length, 1);
  assert.strictEqual(sb._head[0].src, '/js/ticket-widget.js');
  assert.strictEqual(sb._head[0].id, 'ticketWidgetScript');

  // Second call: the tag is now findable by id.
  const injected = sb._head[0];
  sb.document.getElementById = id => (id === 'ticketWidgetScript' ? injected : null);
  sb.Layout.ensureTicketWidget();
  assert.strictEqual(sb._head.length, 1, 'the widget script was injected twice');
});

test('an already-loaded widget is not re-fetched', () => {
  const sb = makeWindow();
  sb.TicketWidget = { open() {} };
  sb.Layout.ensureTicketWidget();
  assert.strictEqual(sb._head.length, 0);
});

test('clicking the button with the widget present opens it immediately', () => {
  const sb = makeWindow();
  let opened = 0;
  sb.TicketWidget = { open() { opened++; } };
  sb.Layout.openTicketModal();
  assert.strictEqual(opened, 1);
  // And no polling was started for a widget that is already here.
  assert.strictEqual(sb._head.length, 0);
});

test('ensureTicketWidget survives a document with no head', () => {
  // layout.js is evaluated in more than one stub context; a missing head must
  // not throw and take injectSidebar() -- and therefore the whole sidebar --
  // down with it.
  const sb = makeWindow();
  sb.document.head = null;
  assert.doesNotThrow(() => sb.Layout.ensureTicketWidget());
});

test('the modal is appended to body, never into the sidebar', () => {
  // injectSidebar() replaces #sidebar's innerHTML wholesale on the authReady
  // re-render. A modal nested inside it would be destroyed out from under
  // someone half-way through typing a ticket.
  const widget = fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8');
  assert.match(widget, /document\.body\.appendChild\(el\)/);
  assert.doesNotMatch(widget, /getElementById\('sidebar'\)/);
  // And mounting is guarded, because open() can be called many times.
  assert.match(widget, /if \(this\._mounted \|\| document\.getElementById\('ticketModalOverlay'\)\) return;/);
});

test('the modal overlay carries the class that lifts it over the chat launcher', () => {
  // .modal-overlay is z-index 1000; the chat button is 9999 and sits bottom
  // right, directly over the modal's submit control.
  const widget = fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8');
  assert.match(widget, /ticket-modal-overlay/);
  const css = fs.readFileSync(path.join(PUBLIC, 'css', 'layout.css'), 'utf8');
  assert.match(css, /\.ticket-modal-overlay\s*\{\s*z-index:\s*10000/);
});

test('the Course Tickets tab is marked instructor-only for Student View', () => {
  // layout.css already hides [data-instructor-only] under
  // html[data-student-view], so this costs no JS.
  const widget = fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8');
  assert.match(widget, /data-instructor-only/);
  const css = fs.readFileSync(path.join(PUBLIC, 'css', 'layout.css'), 'utf8');
  assert.match(css, /\[data-student-view\] \[data-instructor-only\]/);
});

// ── the emailed deep link ───────────────────────────────────────────────────

test('the deep-link handler does not wait for DOMContentLoaded', () => {
  // This file is injected by Layout.ensureTicketWidget(), which runs from
  // Layout.init() -- itself already 100ms past DOMContentLoaded -- and a
  // dynamically created <script> is async. A DOMContentLoaded listener here
  // would never fire, so every emailed ticket link would land on /hub and do
  // nothing at all. Silent, and invisible until a student says the link is broken.
  const widget = fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8');
  assert.match(widget, /document\.readyState === 'loading'/,
    'the deep link must run immediately when the document is already parsed');
});

test('the widget actually runs the deep link when injected late', () => {
  // Evaluate it the way the browser will: after the document is parsed.
  const sb = makeWindow();
  sb.document.readyState = 'complete';
  sb.location.search = '?ticket=11111111-2222-3333-4444-555555555555';

  const calls = [];
  sb.TicketWidget = undefined;
  sb.API = { request: async () => ({ tickets: [], statuses: [] }) };
  sb.Toast = { success() {}, error() {}, warning() {} };

  vm.runInContext(
    fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8'), sb,
    { filename: 'ticket-widget.js' });

  // Replace the two entry points and re-run the handler, so this asserts the
  // wiring rather than the whole render path.
  sb.TicketWidget.open = async (tab) => { calls.push(['open', tab]); };
  sb.TicketWidget.detail = async (id) => { calls.push(['detail', id]); };
  vm.runInContext('openTicketFromUrl()', sb);

  return new Promise(resolve => setImmediate(() => {
    assert.deepStrictEqual(calls[0], ['open', 'mine']);
    assert.deepStrictEqual(calls[1], ['detail', '11111111-2222-3333-4444-555555555555']);
    resolve();
  }));
});

test('a page with no ticket parameter opens nothing', () => {
  const sb = makeWindow();
  sb.document.readyState = 'complete';
  sb.location.search = '';
  let opened = 0;
  vm.runInContext(
    fs.readFileSync(path.join(PUBLIC, 'js', 'ticket-widget.js'), 'utf8'), sb,
    { filename: 'ticket-widget.js' });
  sb.TicketWidget.open = async () => { opened++; };
  vm.runInContext('openTicketFromUrl()', sb);
  assert.strictEqual(opened, 0);
});
