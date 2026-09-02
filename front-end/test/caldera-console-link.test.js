/**
 * caldera-console-link.test.js — the LINK to the attack authoring console, in
 * both instructor surfaces.
 *
 * ############################################################################
 * # NO CALDERA SERVER HAS EVER BEEN RUN AGAINST THIS CODE. Every answer in   #
 * # this file comes from a fake defined here. Nothing below proves the       #
 * # authoring console works; what it proves is that CyberCore never offers a #
 * # link to one it has not just been told is answering.                      #
 * ############################################################################
 *
 * WHAT THIS FIXES
 * ----------------------------------------------------------------------------
 * GET /api/caldera-authoring/status exists precisely so a console can say
 * "authoring is not set up" instead of offering a dead link — and until this
 * change nothing consumed it. The authoring console was reachable only by
 * typing its address, which no instructor would ever discover.
 *
 * THE FOUR STATES, AND WHY EACH ONE IS A SEPARATE ASSERTION
 * ----------------------------------------------------------------------------
 *   configured + reachable   ->  a link, opening in a NEW TAB
 *   configured + NOT reachable -> a sentence saying it did not answer, and NO
 *                                anchor anywhere on the panel
 *   not configured           ->  a sentence naming what an administrator must
 *                                do (CALDERA_HOST, the tunnel route) and NO
 *                                anchor
 *   403                      ->  nothing whatsoever, not an error
 *
 * The three no-link branches are the ones worth a test each, because they all
 * look the same from the outside — "the panel says something" — and only one of
 * them is allowed to be reached by a mistake in the branch above it. A link
 * drawn on the unreachable branch is the exact failure the status endpoint was
 * written to prevent: the instructor follows it, gets a browser error page, and
 * concludes the platform is broken.
 *
 * THE HREF IS THE PAYLOAD'S, NEVER A LITERAL. The console has already moved
 * once — from /caldera on this site to its own hostname — and a browser file
 * that spells either one outlives the deployment that made it true. So §3 scans
 * both files for a hard-coded address, and the href assertions use an invented
 * host that appears in no source file: a passing test therefore means the answer
 * was read, not that a constant happened to match.
 *
 * AND `path` IS NOT AN ADDRESS. The server emits path: '/caldera' on EVERY
 * deployment, configured or not; it resolves only because the main site keeps a
 * 302 from it to console_url. So it may be read on exactly one shape of answer —
 * one so old it carries no console_configured field at all, where it really was
 * the address — and on no other. STATUS_NO_HOSTNAME is the fixture that proves
 * it: configured true, reachable true, a `path` that looks like a link, and
 * nothing for the redirect to land on. A consumer that falls back whenever
 * console_url is missing ships a dead link there, which is the one failure this
 * whole surface was built to prevent.
 *
 * AND THE TWO COPIES STAY SEPARATE. CiAB says Environment; CLE says lane and
 * course. One shared string is exactly how one product's nouns reach the
 * other's screen, so §4 pins that they differ.
 *
 * Run: node --test front-end/test/caldera-console-link.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const CLE = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle');

const CIAB_JS = path.join(CIAB, 'public', 'js', 'instructor-incidents.js');
const CLE_JS = path.join(CLE, 'public', 'js', 'blue-team.js');

const COURSE = '11111111-1111-1111-1111-111111111111';

/**
 * The address the fakes hand back.
 *
 * Deliberately NOT the production hostname and NOT '/caldera'. If either file
 * ever hard-codes a real one, the href assertions below would still pass
 * against a literal — this value cannot be guessed, so a passing test means the
 * payload was read.
 */
const CONSOLE_URL = 'https://authoring.invalid.test/';
const LEGACY_PATH = '/authoring-console-legacy/';

/**
 * Everything set up and answering.
 *
 * Shaped like src/routes/caldera-authoring.js's real answer, which carries TWO
 * independent configured flags: console_configured (CALDERA_HOST, the hostname
 * a browser is sent to) and configured (CALDERA_AUTHORING_UPSTREAM, where the
 * proxy dials). `path` rides along on every one of these fixtures because the
 * server emits it unconditionally — it is a constant there, not an address.
 */
const STATUS_READY = Object.freeze({
  console_url: CONSOLE_URL,
  console_configured: true,
  console_detail: null,
  path: LEGACY_PATH,
  configured: true,
  upstream: 'authoring.lab.test:8888',
  reachable: true,
  http_status: 401,
  latency_ms: 12,
  detail: null,
  checked_at: '2026-09-01T00:00:00.000Z',
});

/**
 * The SAME platform, answered by a server that predates console_url entirely.
 *
 * The two halves of this feature landed separately, and a browser holding a
 * cached copy of the newer file can be talking to the older server for as long
 * as a deploy takes. On that shape `path` was the address, so it is read.
 */
const STATUS_READY_LEGACY = Object.freeze({
  path: LEGACY_PATH,
  configured: true,
  upstream: 'authoring.lab.test:8888',
  reachable: true,
  http_status: 302,
  latency_ms: 8,
  detail: null,
});

/** Fully set up, and nothing answered inside the server's deadline. */
const STATUS_DOWN = Object.freeze({
  console_url: CONSOLE_URL,
  console_configured: true,
  console_detail: null,
  path: LEGACY_PATH,
  configured: true,
  upstream: 'authoring.lab.test:8888',
  reachable: false,
  http_status: null,
  latency_ms: 3000,
  detail: 'timeout',
});

/**
 * NO CALDERA_HOST — and this is the fixture that earns its keep.
 *
 * The upstream IS configured and the box IS answering, so every field a naive
 * reader looks at says "up": configured true, reachable true, and a `path` that
 * looks exactly like a link. It is not one. `path` is '/caldera' on every
 * deployment ever made and only resolves because the main site keeps a 302 from
 * it to console_url — which is null here, so the redirect has nowhere to go.
 * A consumer that falls back to `path` whenever console_url is missing ships a
 * dead link on precisely this deployment.
 */
const STATUS_NO_HOSTNAME = Object.freeze({
  console_url: null,
  console_configured: false,
  console_detail: 'not_configured',
  path: LEGACY_PATH,
  configured: true,
  upstream: 'authoring.lab.test:8888',
  reachable: true,
  http_status: 401,
  latency_ms: 9,
  detail: null,
});

/** Neither variable set: nothing to send a browser to and nothing to dial. */
const STATUS_UNSET = Object.freeze({
  console_url: null,
  console_configured: false,
  console_detail: 'not_configured',
  path: LEGACY_PATH,
  configured: false,
  upstream: null,
  reachable: null,
  http_status: null,
  detail: 'not_configured',
});

/**
 * A hostname to send a browser to, but no upstream for the proxy to dial.
 *
 * Answering the console's own address gets whatever the proxy does with a
 * reverse_proxy it has no target for, which is not the console. Also not a
 * link.
 */
const STATUS_NO_UPSTREAM = Object.freeze({
  console_url: CONSOLE_URL,
  console_configured: true,
  console_detail: null,
  path: LEGACY_PATH,
  configured: false,
  upstream: null,
  reachable: null,
  http_status: null,
  detail: 'not_configured',
});

// ---------------------------------------------------------------------------
// Harnesses — the same sandbox approach test/caldera-authoring-ui.test.js uses
// ---------------------------------------------------------------------------

/**
 * A DOM small enough to render into and read back. Elements are property bags;
 * innerHTML is a string. jsdom is not a dependency of this repo.
 */
function makeDom() {
  const elements = new Map();
  const el = (id) => {
    if (!elements.has(id)) {
      elements.set(id, {
        id, value: '', innerHTML: '', textContent: '', checked: false, style: {},
        handlers: {},
        classList: { add() {}, remove() {}, contains: () => true },
        addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); },
        setSelectionRange() {}, focus() {},
        getAttribute() { return null; },
      });
    }
    return elements.get(id);
  };
  return {
    elements,
    document: {
      getElementById: el,
      querySelectorAll: () => [],
      querySelector: () => null,
      createElement: () => el('scratch'),
    },
  };
}

/** What API.request throws: the app kit's APIError carries a numeric status. */
function apiError(message, status) {
  const err = new Error(message);
  err.status = status;
  return err;
}

/**
 * Load the CiAB Incidents tab into a sandbox.
 *
 * `answers` is a list of [regexp, value] against the path API.request is
 * called with; a value may be a function so a test can hand back a promise
 * that never settles.
 */
function mountCiab(answers) {
  const dom = makeDom();
  const calls = [];
  const toasts = [];
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

  const context = {
    window: {},
    document: dom.document,
    console: { warn() {}, error() {}, log() {} },
    setTimeout, clearTimeout, setInterval, clearInterval, Promise, JSON, Math, Date, Number, String,
    Array, Object, Set, Map, encodeURIComponent, isFinite, parseInt,
    esc,
    escJs: (s) => String(s == null ? '' : s).replace(/['\\]/g, '\\$&'),
    timeAgo: () => 'just now',
    switchTab: () => {},
    // Every toast is recorded. A refused probe must raise none.
    Toast: {
      success(...a) { toasts.push(['success', ...a]); },
      error(...a) { toasts.push(['error', ...a]); },
      info(...a) { toasts.push(['info', ...a]); },
    },
    Confirm: { show: async () => true },
    Utils: { setBtnLoading() {} },
    API: {
      request: (p, opts) => {
        calls.push({ path: p, method: (opts && opts.method) || 'GET' });
        for (const [re, value] of answers) {
          if (re.test(p)) {
            return typeof value === 'function' ? value() : Promise.resolve(value);
          }
        }
        return Promise.reject(apiError(`unscripted API call ${p}`, 500));
      },
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(CIAB_JS, 'utf8'), context, { filename: 'instructor-incidents.js' });

  const box = () => dom.document.getElementById('incidentAuthoringConsole').innerHTML;
  return { context, dom, calls, toasts, box, Incidents: context.window.Incidents };
}

/** Load the CLE course blue-team mount into a sandbox. */
function mountCle({ tier, status, statusCode }) {
  const dom = makeDom();
  const fetches = [];
  const context = {
    window: {
      BlueTeamApi: { create: () => ({ listRuns: async () => ({ tier, runs: [] }) }) },
      BlueTeamBoard: { mount: () => ({ destroy() {} }) },
      console: { warn() {} },
    },
    document: dom.document,
    console: { warn() {}, error() {}, log() {} },
    escHtml: (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c])),
    currentCourseId: COURSE,
    localStorage: { getItem: () => 'token-value' },
    Promise, JSON, Date, Array, Object, String, Number, encodeURIComponent, isFinite,
    setTimeout, clearTimeout,
    fetch: async (url, opts) => {
      fetches.push({ url, method: (opts && opts.method) || 'GET' });
      if (/caldera-authoring\/status$/.test(url)) {
        const code = statusCode || 200;
        return { ok: code >= 200 && code < 300, status: code, json: async () => (status || {}) };
      }
      throw new Error(`unscripted fetch ${url}`);
    },
  };
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(fs.readFileSync(CLE_JS, 'utf8'), context, { filename: 'blue-team.js' });

  const box = () => dom.document.getElementById('blueTeamContent').innerHTML;
  return { context, dom, fetches, box, CleBlueTeam: context.window.CleBlueTeam };
}

/** Every anchor in a fragment. The no-link branches must produce none. */
const anchors = (html) => html.match(/<a\b[^>]*>/g) || [];

// ---------------------------------------------------------------------------
// §1 CiAB — the Incidents tab
// ---------------------------------------------------------------------------

test('L1: CiAB renders the link ONLY when the console is configured and answering', async () => {
  const h = mountCiab([[/caldera-authoring\/status$/, STATUS_READY]]);
  await h.Incidents.refreshAuthoringConsole();

  const html = h.box();
  const found = anchors(html);
  assert.strictEqual(found.length, 1, `exactly one link, got ${found.length}: ${html}`);

  // THE ADDRESS IS THE PAYLOAD'S. CONSOLE_URL is an invented host that appears
  // in no source file, so this cannot pass against a hard-coded link.
  assert.match(html, new RegExp(`href="${CONSOLE_URL}"`));

  // A NEW TAB. The console is a separate origin; a same-tab navigation loses
  // whatever the instructor had open here.
  assert.match(found[0], /target="_blank"/);
  assert.match(found[0], /rel="noopener noreferrer"/);
});

test('L2: CiAB prefers console_url, and falls back to path when it is absent', async () => {
  // The two halves of this feature are landing separately. Whichever order they
  // arrive in, the link has to work — so BOTH shapes of the payload are pinned.
  const withUrl = mountCiab([[/caldera-authoring\/status$/, STATUS_READY]]);
  await withUrl.Incidents.refreshAuthoringConsole();
  assert.match(withUrl.box(), new RegExp(`href="${CONSOLE_URL}"`));
  assert.ok(!withUrl.box().includes(`href="${LEGACY_PATH}"`),
    'console_url must win when the payload carries both');

  const legacy = mountCiab([[/caldera-authoring\/status$/, STATUS_READY_LEGACY]]);
  await legacy.Incidents.refreshAuthoringConsole();
  assert.match(legacy.box(), new RegExp(`href="${LEGACY_PATH}"`),
    'a payload with no console_url must still produce a working link from path');
});

test('L3: CiAB — configured but NOT answering says so, and offers no link', async () => {
  const h = mountCiab([[/caldera-authoring\/status$/, STATUS_DOWN]]);
  await h.Incidents.refreshAuthoringConsole();

  const html = h.box();
  assert.match(html, /not responding/i);
  assert.match(html, /powered off|network path/i, 'the copy names what to check');
  assert.deepStrictEqual(anchors(html), [],
    'a link to a console that did not answer is the exact failure /status exists to prevent');

  // And no internal address is printed at a viewer who cannot act on one.
  assert.ok(!/authoring\.lab\.test/.test(html), 'the lab address leaked into the page');
  assert.ok(!/\[object|undefined|Error:/.test(html), 'a raw error reached the page');
});

test('L4: CiAB — not configured names what an administrator must do, with no link', async () => {
  const h = mountCiab([[/caldera-authoring\/status$/, STATUS_UNSET]]);
  await h.Incidents.refreshAuthoringConsole();

  const html = h.box();
  assert.match(html, /not set up/i);
  // The ACTION, not just the diagnosis. "Authoring is unavailable" on its own
  // sends an instructor to a help desk that cannot help them either.
  assert.match(html, /CALDERA_HOST/);
  assert.match(html, /tunnel route/i);
  assert.deepStrictEqual(anchors(html), []);
  // The variable NAME is an instruction; a host and port is topology. Only one
  // of them belongs on an instructor's screen.
  assert.ok(!/authoring\.lab\.test|:8888/.test(html), 'an internal address leaked into the page');
});

test('L4b: CiAB — a legacy `path` is NOT a link when no hostname is published', async () => {
  // THE ONE THAT WOULD HAVE SHIPPED A DEAD LINK. Both of these answer with a
  // `path` that looks like an address, and neither is one: the first has no
  // CALDERA_HOST for the 302 to land on, the second has no upstream behind the
  // hostname. Everything else in the payload reads as healthy.
  for (const [label, payload] of [
    ['no CALDERA_HOST', STATUS_NO_HOSTNAME],
    ['no upstream', STATUS_NO_UPSTREAM],
  ]) {
    const h = mountCiab([[/caldera-authoring\/status$/, payload]]);
    // eslint-disable-next-line no-await-in-loop
    await h.Incidents.refreshAuthoringConsole();
    const html = h.box();
    assert.deepStrictEqual(anchors(html), [], `${label}: offered a link`);
    assert.ok(!html.includes(LEGACY_PATH), `${label}: rendered the legacy path as an address`);
    assert.match(html, /not set up/i, `${label}: did not say what is missing`);
    assert.match(html, /CALDERA_HOST/, `${label}: did not name the action`);
  }
});

test('L5: CiAB — a 403 renders NOTHING AT ALL, and is not an error', async () => {
  const h = mountCiab([
    [/caldera-authoring\/status$/, () => Promise.reject(apiError('Access denied.', 403))],
  ]);
  await h.Incidents.refreshAuthoringConsole();

  assert.strictEqual(h.box(), '',
    'the endpoint is staff-only; a viewer it refuses must be shown no panel, no heading, nothing');
  assert.deepStrictEqual(h.toasts, [],
    'a refusal is the answer, not a failure — a toast would announce a surface they cannot have');
});

test('L6: CiAB — the probe does not hold up the rest of the tab', async () => {
  // The status endpoint does a LIVE reachability check with a 3s deadline on the
  // server. If the tab's first paint waited on it, an instructor would stare at
  // an empty panel for three seconds to find out whether one link is drawn.
  let release;
  const hung = new Promise((resolve) => { release = resolve; });

  const h = mountCiab([
    [/caldera-authoring\/status$/, () => hung],
    [/instructor\/sections$/, { sections: [] }],
  ]);

  h.Incidents.ensureInit();
  // One turn of the microtask queue: enough for load() to have issued its own
  // request, nowhere near enough for a probe that has not been released.
  await Promise.resolve();
  await Promise.resolve();

  assert.ok(h.calls.some((c) => /instructor\/sections/.test(c.path)),
    'the tab waited on the console probe before loading its own data');
  assert.match(h.box(), /Checking whether/,
    'the panel should say it is still checking rather than sit blank');

  release(STATUS_READY);
  await hung;
  await Promise.resolve();
  assert.match(h.box(), new RegExp(`href="${CONSOLE_URL}"`), 'the answer never landed');
});

// ---------------------------------------------------------------------------
// §2 CLE — the course blue-team surface
// ---------------------------------------------------------------------------

test('L7: CLE renders the link only when configured and answering, in a new tab', async () => {
  const h = mountCle({ tier: 'staff', status: STATUS_READY });
  await h.CleBlueTeam.load();
  await h.CleBlueTeam.refreshConsoleStatus();

  const html = h.CleBlueTeam.consoleStatusHtml();
  const found = anchors(html);
  assert.strictEqual(found.length, 1, `exactly one link, got ${found.length}: ${html}`);
  assert.match(html, new RegExp(`href="${CONSOLE_URL}"`));
  assert.match(found[0], /target="_blank"/);
  assert.match(found[0], /rel="noopener noreferrer"/);

  // And it really is on the page, not merely returned by the builder.
  assert.match(h.box(), new RegExp(`href="${CONSOLE_URL}"`));
});

test('L8: CLE falls back to path when the payload carries no console_url', async () => {
  const h = mountCle({ tier: 'staff', status: STATUS_READY_LEGACY });
  await h.CleBlueTeam.load();
  await h.CleBlueTeam.refreshConsoleStatus();
  assert.match(h.CleBlueTeam.consoleStatusHtml(), new RegExp(`href="${LEGACY_PATH}"`));
});

test('L9: CLE — unreachable and not-configured each get their own copy and no link', async () => {
  const down = mountCle({ tier: 'staff', status: STATUS_DOWN });
  await down.CleBlueTeam.load();
  await down.CleBlueTeam.refreshConsoleStatus();
  let html = down.CleBlueTeam.consoleStatusHtml();
  assert.match(html, /not responding/i);
  assert.deepStrictEqual(anchors(html), []);
  assert.ok(!/authoring\.lab\.test/.test(html), 'the lab address leaked into the page');

  const unset = mountCle({ tier: 'staff', status: STATUS_UNSET });
  await unset.CleBlueTeam.load();
  await unset.CleBlueTeam.refreshConsoleStatus();
  html = unset.CleBlueTeam.consoleStatusHtml();
  assert.match(html, /not set up/i);
  assert.match(html, /CALDERA_HOST/);
  assert.match(html, /tunnel route/i);
  assert.deepStrictEqual(anchors(html), []);
  assert.ok(!/authoring\.lab\.test|:8888/.test(html));

  // Neither branch put an anchor anywhere else on the board either.
  assert.deepStrictEqual(anchors(unset.box()), []);
});

test('L9b: CLE — a legacy `path` is NOT a link when no hostname is published', async () => {
  for (const payload of [STATUS_NO_HOSTNAME, STATUS_NO_UPSTREAM]) {
    const h = mountCle({ tier: 'staff', status: payload });
    // eslint-disable-next-line no-await-in-loop
    await h.CleBlueTeam.load();
    // eslint-disable-next-line no-await-in-loop
    await h.CleBlueTeam.refreshConsoleStatus();
    const html = h.CleBlueTeam.consoleStatusHtml();
    assert.deepStrictEqual(anchors(html), []);
    assert.ok(!html.includes(LEGACY_PATH), 'rendered the legacy path as an address');
    assert.match(html, /not set up/i);
    assert.match(html, /CALDERA_HOST/);
  }
});

test('L10: CLE — a 403 renders nothing, and a STUDENT is never even asked for', async () => {
  const refused = mountCle({ tier: 'staff', status: {}, statusCode: 403 });
  await refused.CleBlueTeam.load();
  await refused.CleBlueTeam.refreshConsoleStatus();
  assert.strictEqual(refused.CleBlueTeam.consoleStatusHtml(), '');
  assert.ok(!/Authoring console/.test(refused.box()),
    'a refused viewer must not be told the surface exists');

  // A student is a stronger claim than "renders nothing": no request is made on
  // their behalf at all. The tier is the SERVER's word, resolved against THIS
  // course, so an instructor viewing a colleague's course is a student here too.
  const student = mountCle({ tier: 'student', status: STATUS_READY });
  await student.CleBlueTeam.load();
  await student.CleBlueTeam.refreshConsoleStatus();
  assert.strictEqual(student.CleBlueTeam.consoleStatusHtml(), '');
  assert.deepStrictEqual(
    student.fetches.filter((f) => /caldera-authoring/.test(f.url)), [],
    'the status endpoint was probed on a student\u2019s behalf'
  );
  for (const forbidden of [/Authoring console/, /caldera/i, /adversar/i]) {
    assert.ok(!forbidden.test(student.box()), `a student was shown ${forbidden}`);
  }
});

test('L11: CLE — the probe is fired by load(), not by a button nobody presses', async () => {
  const h = mountCle({ tier: 'staff', status: STATUS_READY });
  await h.CleBlueTeam.load();
  assert.ok(h.fetches.some((f) => /caldera-authoring\/status$/.test(f.url)),
    'nothing consumes /status unless load() asks for it — which was the whole bug');
});

// ---------------------------------------------------------------------------
// §3 The address is never written down
// ---------------------------------------------------------------------------

/** Source with its comments removed: the rule below is about CODE. */
function codeOnly(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, '')
    .split(/\r?\n/)
    .filter((line) => {
      const t = line.trim();
      return !t.startsWith('//') && !t.startsWith('*');
    })
    .join('\n');
}

test('L12: neither console hard-codes the authoring console\u2019s address', () => {
  for (const file of [CIAB_JS, CLE_JS]) {
    const rel = path.relative(ROOT, file).split(path.sep).join('/');
    const code = codeOnly(fs.readFileSync(file, 'utf8'));

    // No absolute URL literal of any kind. The console lives on its own
    // hostname now and that hostname is deployment-specific.
    const absolute = code.match(/(['"`])https?:\/\/[^'"`]+\1/g) || [];
    assert.deepStrictEqual(absolute, [], `${rel} spells an absolute URL`);

    // And no literal equal to the console's old same-site path. The API
    // endpoint '/caldera-authoring/status' is a DIFFERENT string and is allowed
    // — it is this app's own route, which the server registers and a test pins.
    const consolePath = code.match(/(['"`])\/caldera\/?\1/g) || [];
    assert.deepStrictEqual(consolePath, [],
      `${rel} spells the console's path; it must come off the /status payload`);

    // The positive half: console_url is read, and `path` is read ONLY behind the
    // flag that says the answer is too old to carry console_configured.
    assert.match(code, /console_url/, `${rel} must read console_url`);
    assert.match(code, /hasConsoleFlag\s*\?\s*null\s*:\s*payload\.path/,
      `${rel} must fall back to path only on an answer that predates console_configured`);
  }
});

// ---------------------------------------------------------------------------
// §4 The CiAB copy obeys the CiAB vocabulary gate
// ---------------------------------------------------------------------------

test('L13: the CiAB console copy speaks CiAB, in every state', async () => {
  // ciab-vocabulary.test.js scans the whole file, comments included. This is the
  // same rule applied to the RENDERED strings — the thing an instructor
  // actually reads — so a future edit that only touches a template string is
  // still caught here.
  const FORBIDDEN = /course|material|cohort|CYBR|challenge/i;

  const rendered = [];
  for (const payload of [STATUS_READY, STATUS_READY_LEGACY, STATUS_DOWN, STATUS_UNSET,
    STATUS_NO_HOSTNAME, STATUS_NO_UPSTREAM]) {
    const h = mountCiab([[/caldera-authoring\/status$/, payload]]);
    // eslint-disable-next-line no-await-in-loop
    await h.Incidents.refreshAuthoringConsole();
    rendered.push(h.box());
  }
  // The state nothing else reaches: the check itself failed.
  const broken = mountCiab([
    [/caldera-authoring\/status$/, () => Promise.reject(apiError('Network error', 0))],
  ]);
  await broken.Incidents.refreshAuthoringConsole();
  rendered.push(broken.box());

  for (const html of rendered) {
    assert.ok(html.length > 0, 'a state rendered nothing at all');
    assert.ok(!FORBIDDEN.test(html),
      `Section / Client / Engagement / Environment / Incident is the vocabulary:\n${html}`);
    // "lane" is the shared engine's key name and never a word on this screen.
    assert.ok(!/\blanes?\b/i.test(html), `the CiAB screen said "lane":\n${html}`);
  }

  // The positive half: it does speak the right noun.
  assert.ok(rendered.some((h) => /Environment/.test(h)), 'the CiAB copy names an Environment');
});

test('L14: the two products do not share one string', () => {
  // A shared string is how one product's nouns end up on the other's screen.
  // The CLE copy may say lane and course; the CiAB copy may not, and neither
  // may be a copy of the other.
  const cle = fs.readFileSync(CLE_JS, 'utf8');
  const ciab = fs.readFileSync(CIAB_JS, 'utf8');
  assert.ok(/outside every lane and runs/.test(cle), 'the CLE copy speaks CLE');
  assert.ok(/outside every Environment and runs/.test(ciab), 'the CiAB copy speaks CiAB');
  assert.ok(!/outside every lane and runs/.test(ciab), 'the CiAB file borrowed the CLE sentence');
});
