/**
 * ciab-modules-ui.test.js — Track D, phase D2: the Modules tab in the browser.
 *
 * TWO IDIOMS IN ONE FILE, because there is no DOM library in this repo
 * (devDependencies is { nodemon } and nothing else):
 *
 *   1. THE RENDER PATH RUNS FOR REAL, inside node:vm against a hand-rolled
 *      element bag, with context.window = context AND context.globalThis =
 *      context. That is the only way to assert what the tab actually paints —
 *      that a title carrying a script tag comes out escaped, that the list is
 *      in the order the server sent, that the Delete control is drawn from a
 *      server flag, that a reorder carries the FULL id list.
 *
 *   2. instructor.html and instructor-core.js are asserted as SOURCE TEXT,
 *      because their failure mode is silence: switchTab() rewrites an unknown
 *      tab name to 'overview' BEFORE it touches the DOM, so a tab button added
 *      without a TAB_NAMES entry looks completely wired — the button exists,
 *      the delegated click fires, hash routing runs — and quietly opens
 *      Overview with no console error.
 *
 * Every file is read through an LF-normalising reader, because this is a
 * Windows checkout with core.autocrlf=true: a stray \r terminates a JavaScript
 * regex line, so a //-stripper silently stops stripping and a slice stops
 * matching. Comments are stripped before any scan, so prose cannot satisfy an
 * assertion the code is supposed to.
 *
 * Run: node --test "test/*.test.js"
 */

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');
const JS = path.join(CIAB, 'public', 'js');

/** LF-normalising, because a stray \r terminates a regex line and silently
 *  breaks every //-stripper and every slice below. */
const read = (p) => fs.readFileSync(p, 'utf8').replace(/\r\n/g, '\n');

const stripComments = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .split('\n').map((l) => l.replace(/\/\/.*$/, '')).join('\n');

const HTML = read(path.join(CIAB, 'public', 'pages', 'instructor.html'));
const CORE = read(path.join(JS, 'instructor-core.js'));
const MODULES = read(path.join(JS, 'instructor-modules.js'));
const MODULES_CODE = stripComments(MODULES);

const S = require(path.join(CIAB, 'utils', 'module-states.js'));

// ===========================================================================
// PART 1 — the markup and the tab wiring
// ===========================================================================

test('the tab button and its panel carry the matching ARIA id pair', () => {
  assert.match(HTML, /<button class="tab" role="tab" id="tabbtn-modules" data-tab="modules"/);
  assert.match(HTML, /aria-controls="tab-modules"/);
  assert.match(HTML, /id="tab-modules" role="tabpanel" aria-labelledby="tabbtn-modules"/,
    'switchTab toggles panels by testing panel.id === "tab-" + name, and aria-labelledby is the '
    + 'panel\'s only accessible name');

  // The panel must carry no `hidden` and no inline display: visibility is the
  // .active class, and classList.toggle would silently lose to an inline style.
  const panel = HTML.slice(HTML.indexOf('id="tab-modules"'));
  const openTag = panel.slice(0, panel.indexOf('>'));
  assert.ok(!/\bhidden\b/.test(openTag));
  assert.ok(!/style=/.test(openTag));
});

test('the tab is in TAB_NAMES and activateTabModule re-fetches on every visit', () => {
  const core = stripComments(CORE);
  assert.match(core, /const TAB_NAMES = \[[^\]]*'modules'/,
    'without this entry the button exists, the click fires, hash routing runs, and switchTab '
    + 'silently rewrites the name to "overview" with no error at all');
  assert.ok(core.includes("if (name === 'modules') { if (window.CiabModules) CiabModules.load(); return; }"),
    'a Sections-style re-fetch, not an ensureInit() map entry: this tab hangs off a section list '
    + 'the Sections tab can change, and a co-instructor\'s reorder must not render stale');

  // The strip reads in the programme's own order.
  const names = core.match(/const TAB_NAMES = \[([^\]]*)\]/)[1]
    .split(',').map((s) => s.trim().replace(/'/g, ''));
  assert.deepStrictEqual(names, ['overview', 'sections', 'modules', 'students', 'reviews', 'documents']);
});

test('instructor-modules.js is loaded AFTER instructor-core.js, and exports itself onto window', () => {
  const core = HTML.indexOf('/ciab/js/instructor-core.js');
  const mine = HTML.indexOf('/ciab/js/instructor-modules.js');
  assert.ok(core > 0 && mine > core,
    'core is the declared provider of switchTab, openModal, esc, escJs, partLabel and '
    + 'profileDisplayName; loading above it breaks every one of them');

  const lastLine = MODULES.trimEnd().split('\n').pop().trim();
  assert.strictEqual(lastLine, 'window.CiabModules = CiabModules;',
    'a top-level const in a classic script is a lexical global and never a window property, and '
    + 'activateTabModule reads window.CiabModules by property lookup');
});

test('no top-level name collides with a sibling controller', () => {
  const SIBLINGS = [
    'instructor-core.js', 'instructor-overview.js', 'instructor-students.js',
    'instructor-reviews.js', 'instructor-documents.js', 'instructor-sections.js',
    'instructor-roster-import.js',
  ];
  const topLevel = (src) => new Set(
    [...stripComments(src).matchAll(/^(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/gm)]
      .map((m) => m[1])
  );
  const mine = topLevel(MODULES);
  assert.ok(mine.has('CiabModules'));
  for (const file of SIBLINGS) {
    for (const name of topLevel(read(path.join(JS, file)))) {
      assert.ok(!mine.has(name),
        `${name} is declared in both ${file} and instructor-modules.js — a duplicate top-level `
        + 'const across two classic scripts is a SyntaxError that silently kills the entire later '
        + 'file at parse time, with nothing in the console pointing at it');
    }
  }
});

test('the file uses the house kit and never the browser dialogs', () => {
  assert.ok(!/\balert\s*\(/.test(MODULES_CODE), 'the house kit is Toast');
  assert.ok(!/(^|[^.\w])confirm\s*\(/.test(MODULES_CODE.replace(/Confirm\.show/g, '')),
    'the house kit is Confirm.show, awaited guard-style');
  assert.ok(MODULES_CODE.includes('Confirm.show('));
  assert.ok(!/isRealAdmin/.test(MODULES_CODE),
    'the Delete control is rendered from capabilities.hard_delete, so the UI cannot offer a '
    + 'control the API refuses');
});

test('no word from the other plugin\'s vocabulary reaches the new markup or the new file', () => {
  const CLE = /\b(course|courses|material|materials|challenge|challenges|assignment|assignments|lesson|lessons)\b/i;
  assert.strictEqual(MODULES_CODE.match(CLE), null, 'instructor-modules.js');

  // Scoped to the NEW markup: the existing Sections panel legitimately carries
  // 'Import from a CLE course'.
  const panel = HTML.slice(HTML.indexOf('id="tab-modules"'), HTML.indexOf('<!-- TAB: STUDENTS'));
  assert.strictEqual(panel.match(CLE), null, 'the Modules panel');
  // Each overlay runs to the start of the next one, or to the script block.
  const END = HTML.indexOf('<!-- Load order matters.');
  assert.ok(END > 0);
  for (const id of ['moduleModal', 'moduleCloneModal', 'modulePrereqModal']) {
    const start = HTML.indexOf(`<div class="modal-overlay" id="${id}"`);
    assert.ok(start > 0, `${id} must exist in instructor.html as an overlay`);
    const next = HTML.indexOf('<div class="modal-overlay"', start + 1);
    const modal = HTML.slice(start, next > 0 && next < END ? next : END);
    assert.ok(modal.length > 200, `${id} slice must be the real modal, not an empty string`);
    assert.strictEqual(modal.match(CLE), null, id);
  }
});

test('the badge WORDS come from the payload, never from a literal in this file', () => {
  for (const word of ['Not Yet Open', 'Draft', 'Archived', 'Incomplete', 'Waived']) {
    assert.ok(!new RegExp(`['"\`]${word}`).test(MODULES_CODE),
      `${word} is a server-side label; hardcoding it lets a stale cached script disagree with the API`);
  }
  assert.ok(MODULES_CODE.includes('this.labels.release'), 'the label map is read from the payload');
  assert.ok(MODULES_CODE.includes('this.releaseStates'),
    'the release select is built from release_states, so the browser cannot offer a value the '
    + 'CHECK constraint refuses');
  // Colour only, and every colour key is a real release phase.
  for (const phase of Object.keys(S.RELEASE_LABELS)) {
    if (phase === 'scheduled') continue; // a stored state, never a derived phase
    assert.ok(new RegExp(`\\b${phase}: 'badge-`).test(MODULES_CODE), `RELEASE_BADGE needs ${phase}`);
  }
});

test('every one of the resolver\'s nine issue codes has an entry, and eight offer a fix', () => {
  const start = MODULES_CODE.indexOf('const ISSUE_ACTIONS');
  const block = MODULES_CODE.slice(start, MODULES_CODE.indexOf('\n};', start));
  for (const code of Object.values(S.ISSUE)) {
    assert.ok(block.includes(`${code}:`), `ISSUE_ACTIONS is missing ${code}`);
  }
  assert.ok(/NO_PUBLISHED_MODULES: \(\) => null/.test(block),
    'the only code with no button is the one whose sentence already names the remedy');
});

// ===========================================================================
// PART 2 — the render path, run for real
// ===========================================================================

function makeElement(id, tag) {
  const classes = new Set();
  const el = {
    id,
    tagName: (tag || 'div').toUpperCase(),
    innerHTML: '',
    textContent: '',
    value: '',
    checked: false,
    disabled: false,
    readOnly: false,
    style: {},
    dataset: {},
    onchange: null,
    classList: {
      add: (c) => classes.add(c),
      remove: (c) => classes.delete(c),
      contains: (c) => classes.has(c),
      toggle: (c, on) => (on ? classes.add(c) : classes.delete(c)),
    },
    focus() { el._focused = true; },
    querySelectorAll: () => ({ forEach: () => {} }),
    scrollIntoView() {},
  };
  return el;
}

/**
 * WHO CONTAINS WHOM, transcribed from instructor.html. A FLAT bag of elements
 * cannot see the difference between "painted" and "painted where somebody can
 * read it", and both the load skeleton and the entire load-failure card --
 * including the Retry button that is the only way out of that state -- live
 * inside #modulesMain, which the markup ships as style="display: none;".
 */
const PARENT_OF = {
  moduleIssues: 'modulesMain',
  moduleListContent: 'modulesMain',
  moduleSectionSelect: 'modulesMain',
  moduleSectionMeta: 'modulesMain',
  moduleHideArchived: 'modulesMain',
};

/** The inline styles instructor.html actually ships. */
const INITIAL_STYLE = {
  modulesMain: { display: 'none' },
  modulesNoSection: { display: 'none' },
};

const ELEMENT_IDS = [
  'moduleListContent', 'moduleIssues', 'moduleSectionSelect', 'moduleSectionMeta',
  'moduleHideArchived', 'modulesNoSection', 'modulesMain',
  'moduleModal', 'moduleModalTitle', 'moduleTitle', 'moduleClientFilter', 'moduleProfile',
  'moduleEngagement', 'moduleEngagementList', 'modulePart', 'moduleReleaseState',
  'moduleReleaseAt', 'moduleReleaseTz', 'moduleCloseAt', 'moduleBrief', 'moduleNotes', 'moduleSaveBtn',
  'moduleCloneModal', 'moduleCloneModalTitle', 'moduleCloneSource',
  'moduleCloneTitle', 'moduleCloneClientFilter', 'moduleCloneProfile', 'moduleCloneEngagement',
  'moduleCloneEngagementList', 'moduleCloneSection', 'moduleClonePrereqs',
  'moduleClonePrereqsLabel', 'moduleClonePrereqsNote', 'moduleCloneBtn',
  'modulePrereqModal', 'modulePrereqModalTitle', 'modulePrereqContent', 'modulePrereqAdd',
  'modulePrereqAddBtn',
];

/** A sandbox with the six globals instructor-core.js declares, plus the shared
 *  kit from app.js. No DOM library exists in this repo, so the element bag is
 *  hand-rolled and every helper the file touches is recorded. */
function boot({ apiHandler, confirmAnswer = true } = {}) {
  const els = new Map();
  for (const id of ELEMENT_IDS) {
    const el = makeElement(id);
    Object.assign(el.style, INITIAL_STYLE[id] || {});
    els.set(id, el);
  }
  for (const [child, parent] of Object.entries(PARENT_OF)) {
    if (els.has(child)) els.get(child).parentElement = els.get(parent) || null;
  }

  const toasts = [];
  const calls = [];
  const btnLoading = [];
  const opened = [];

  const context = {
    console,
    setTimeout,
    clearTimeout,
    Number,
    Date,
    Math,
    JSON,
    document: {
      getElementById: (id) => els.get(id) || null,
      querySelectorAll: () => ({ forEach: () => {} }),
    },
    API: {
      request: (p, options) => {
        calls.push({ path: p, options: options || {} });
        return apiHandler ? apiHandler(p, options || {}, calls.length) : Promise.resolve({});
      },
    },
    Toast: {
      success: (t, m) => toasts.push({ kind: 'success', t, m }),
      error: (t, m) => toasts.push({ kind: 'error', t, m }),
      warning: (t, m) => toasts.push({ kind: 'warning', t, m }),
      info: (t, m) => toasts.push({ kind: 'info', t, m }),
    },
    Confirm: { show: async () => confirmAnswer },
    Utils: {
      formatDateTime: (v) => `dt(${v})`,
      setBtnLoading: (btn, on, label) => btnLoading.push({ id: btn && btn.id, on, label }),
      escapeHtml: (s) => String(s),
    },
    InstructorState: { on: () => {}, profiles: [] },
    esc: (s) => String(s == null ? '' : s)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
    escapeHtml: (s) => String(s == null ? '' : s),
    escJs: (s) => String(s == null ? '' : s).replace(/\\/g, '\\\\').replace(/'/g, "\\'"),
    openModal: (id) => { opened.push(id); const el = els.get(id); if (el) el.classList.add('active'); },
    closeModal: (id) => { const el = els.get(id); if (el) el.classList.remove('active'); },
    switchTab: () => {},
    partLabel: (n) => `Part ${n} — Something`,
    profileDisplayName: (c) => c.company_name || c.client_type_name || String(c.id),
  };
  context.window = context;
  context.globalThis = context;
  vm.createContext(context);
  vm.runInContext(MODULES, context, { filename: 'instructor-modules.js' });

  return { context, els, toasts, calls, btnLoading, opened, mod: context.CiabModules };
}

const uuid = (n) => `00000000-0000-4000-8000-${String(n).padStart(12, '0')}`;

/** Would a person actually see what was painted into this element? Walks the
 *  ancestor chain, because display:none on an ancestor hides the subtree. */
function visible(harness, id) {
  let el = harness.els.get(id);
  while (el) {
    if (el.style && el.style.display === 'none') return false;
    el = el.parentElement;
  }
  return true;
}

const view = (over = {}) => ({
  section: { section_id: 'sec-1', name: 'CYBR 480', code: 'C480', term: 'SP26', status: 'active' },
  now: Date.now(),
  roster_size: 20,
  counts: { total: 3, draft: 3, pending: 0, open: 0, closed: 0, archived: 0 },
  modules: [],
  issues: [],
  clients: [{ id: uuid(11), company_name: 'Acme' }],
  parts: [{ number: 1, name: 'Scoping' }],
  labels: { release: S.RELEASE_LABELS, access: S.ACCESS_LABELS, completion: S.COMPLETION_LABELS },
  release_states: S.RELEASE_STATES,
  capabilities: { hard_delete: false },
  warnings: [],
  ...over,
});

const m = (over = {}) => ({
  module_id: uuid(1), section_id: 'sec-1', position: 1, title: 'Scoping',
  brief: null, instructor_notes: null, profile_id: null, engagement_type: 'default',
  assessment_part: null, release_state: 'draft', release_at: null, close_at: null,
  release_phase: 'draft', requires_module_ids: [], required_by_module_ids: [],
  prereq_problems: [], environment_key: null, shares_environment_with: [],
  evidence_key: null, students: null, ...over,
});

/** Drive the tab through its real load pipeline with a canned payload. */
async function loaded(payload, opts = {}) {
  const sections = [{ section_id: 'sec-1', name: 'CYBR 480', code: 'C480', term: 'SP26', status: 'active' }];
  const harness = boot({
    apiHandler: (p) => {
      if (p === '/instructor/sections') return Promise.resolve({ sections });
      return Promise.resolve(payload);
    },
    ...opts,
  });
  await harness.mod.load();
  return harness;
}

test('the tab paints a loading state before any data exists, WHERE IT CAN BE SEEN', () => {
  // instructor-core.js calls switchTab BEFORE the dashboard fetch, so a deep
  // link to #modules activates the tab while nothing at all is loaded.
  const h = boot({ apiHandler: () => new Promise(() => {}) });
  h.mod.load();
  assert.match(h.els.get('moduleListContent').innerHTML, /class="skeleton skel-row"/);
  // instructor.html ships #modulesMain as style="display: none;" and the panel
  // used to be unhidden only AFTER the sections fetch resolved, so this
  // deliberately-painted loading state was invisible on every first visit.
  assert.ok(visible(h, 'moduleListContent'),
    'a skeleton painted into a display:none subtree is not a loading state');
});

test('a failed sections fetch leaves a REACHABLE Retry, not a blank tab', async () => {
  // The failure path returned without ever unhiding #modulesMain, so the error
  // card and its Retry button -- the only way out of this state -- were written
  // into a hidden subtree. The instructor got one toast that fades, an entirely
  // empty panel, and no way back; re-entering the tab repeated it.
  const h = boot({ apiHandler: () => Promise.reject(Object.assign(new Error('boom'), { status: 500 })) });
  await h.mod.load();

  const html = h.els.get('moduleListContent').innerHTML;
  assert.match(html, /Could not load the modules/);
  assert.match(html, /CiabModules\.load\(\)/, 'the Retry button is the only affordance on this path');
  assert.ok(visible(h, 'moduleListContent'), 'an unreachable Retry is the same as no Retry');
  assert.ok(h.toasts.some((t) => t.kind === 'error'));
});

test('with no sections at all the panel is hidden and the empty state is shown', async () => {
  // The other half of the same switch: unhiding at the top of load() must not
  // break the branch that deliberately hides it again.
  const h = boot({ apiHandler: () => Promise.resolve({ sections: [] }) });
  await h.mod.load();
  assert.strictEqual(h.els.get('modulesMain').style.display, 'none');
  assert.strictEqual(h.els.get('modulesNoSection').style.display, '');
});

test('the list renders in the order the server returned, with no client-side comparator', async () => {
  const h = await loaded(view({
    modules: [
      m({ module_id: uuid(1), position: 5, title: 'Third by position' }),
      m({ module_id: uuid(2), position: 1, title: 'First by position' }),
      m({ module_id: uuid(3), position: 9, title: 'Last by position' }),
    ],
  }));
  const html = h.els.get('moduleListContent').innerHTML;
  const order = ['Third by position', 'First by position', 'Last by position'].map((t) => html.indexOf(t));
  assert.deepStrictEqual(order, [...order].sort((a, b) => a - b),
    'the server orders by (position, created_at, module_id); a browser sort on position alone '
    + 'disagrees the moment two rows tie — which is exactly what DUPLICATE_POSITION reports');
  assert.ok(!/\.sort\(/.test(stripComments(MODULES).slice(
    stripComments(MODULES).indexOf('  render() {'),
    stripComments(MODULES).indexOf('  row(m, i, total)')
  )), 'render() must not sort');
  // The row number is the render index, not the stored position.
  assert.match(html, /<span class="mod-pos">1<\/span>/);
});

test('a hostile title renders as text, and a quote cannot break out of an attribute', async () => {
  const h = await loaded(view({
    modules: [m({ title: '<img src=x onerror=alert(1)>', engagement_type: 'ex"ternal' })],
  }));
  const html = h.els.get('moduleListContent').innerHTML;
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
  assert.ok(!html.includes('<img src=x'), 'never as markup');
  assert.ok(!/title="[^"]*"[^>]*ternal/.test(html));
  assert.ok(html.includes('ex&quot;ternal'),
    'esc() escapes quotes; Utils.escapeHtml\'s textContent round-trip does not and is unsafe in '
    + 'attribute context');
});

test('the Delete control is drawn from the server flag, never inferred', async () => {
  const off = await loaded(view({ modules: [m()], capabilities: { hard_delete: false } }));
  assert.ok(!off.els.get('moduleListContent').innerHTML.includes('>Delete<'));

  const on = await loaded(view({ modules: [m()], capabilities: { hard_delete: true } }));
  assert.ok(on.els.get('moduleListContent').innerHTML.includes('>Delete<'));
});

test('a module whose students is null renders an em dash, not a zeroed rollup', async () => {
  const h = await loaded(view({
    modules: [
      m({ module_id: uuid(1), title: 'Unloaded', students: null }),
      m({ module_id: uuid(2), title: 'Empty roster', students: { enrolled: 0, completion: { complete: 0 }, blocked_by_prereq: 0 } }),
    ],
  }));
  const html = h.els.get('moduleListContent').innerHTML;
  const rows = html.split('<tr');
  const unloaded = rows.find((r) => r.includes('Unloaded'));
  const empty = rows.find((r) => r.includes('Empty roster'));
  assert.ok(unloaded.includes('<td>—</td>'),
    'the rollup is null only when no roster array was SUPPLIED');
  assert.ok(empty.includes('0/0'), 'an EMPTY roster is a real answer and gets the zeroed rollup');
});

test('the reorder arrows are disabled at the ends and never spinner-ised', async () => {
  const h = await loaded(view({
    modules: [m({ module_id: uuid(1) }), m({ module_id: uuid(2), position: 2 }), m({ module_id: uuid(3), position: 3 })],
  }));
  const rows = h.els.get('moduleListContent').innerHTML.split('<tr').filter((r) => r.includes('data-module-id'));
  assert.ok(/Move up"[^>]* disabled/.test(rows[0]), 'the first visible row cannot move up');
  assert.ok(!/Move down"[^>]* disabled/.test(rows[0]));
  assert.ok(/Move down"[^>]* disabled/.test(rows[2]), 'the last visible row cannot move down');

  const code = stripComments(MODULES);
  const rowFn = code.slice(code.indexOf('  row(m, i, total)'), code.indexOf('  highlight(ids)'));
  assert.ok(!/setBtnLoading/.test(rowFn),
    'the row is re-rendered during the await, so the finally would restore innerHTML onto a '
    + 'DETACHED node while the live button sat looking idle');
});

test('a reorder carries the FULL id list even when Hide archived is ticked', async () => {
  let body = null;
  const h = await loaded(view({
    modules: [
      m({ module_id: uuid(1) }),
      m({ module_id: uuid(2), position: 2, release_state: 'archived', release_phase: 'archived' }),
      m({ module_id: uuid(3), position: 3 }),
      m({ module_id: uuid(4), position: 4, release_state: 'archived', release_phase: 'archived' }),
    ],
  }));
  h.els.get('moduleHideArchived').checked = true;
  h.mod.render();
  assert.strictEqual((h.els.get('moduleListContent').innerHTML.match(/data-module-id=/g) || []).length, 2,
    'Hide archived filters the RENDER');

  h.context.API.request = (p, options) => {
    if (p.endsWith('/reorder')) { body = options.body; return Promise.resolve({ order: body.order, warnings: [] }); }
    return Promise.resolve({});
  };
  await h.mod.saveOrder();
  assert.strictEqual(body.order.length, 4,
    'the endpoint requires every module exactly once, so a filter applied at the PAYLOAD layer is '
    + 'a guaranteed 409 that reads like a server bug');
});

test('saveOrder is single-flight with ONE trailing re-send carrying the final order', async () => {
  const sent = [];
  let release;
  const h = await loaded(view({
    modules: [m({ module_id: uuid(1) }), m({ module_id: uuid(2), position: 2 })],
  }));
  h.context.API.request = (p, options) => {
    sent.push(options.body.order.slice());
    if (sent.length === 1) return new Promise((r) => { release = () => r({ order: options.body.order, warnings: [] }); });
    return Promise.resolve({ order: options.body.order, warnings: [] });
  };

  const first = h.mod.saveOrder();
  h.mod.saveOrder();                       // folded into the flight
  h.mod.modules.reverse();                 // the instructor keeps tapping
  h.mod.saveOrder();
  assert.strictEqual(sent.length, 1, 'never two requests racing to define the sequence');
  release();
  await first;
  assert.strictEqual(sent.length, 2, 'exactly one trailing re-send');
  assert.deepStrictEqual(sent[1], [uuid(2), uuid(1)], 'and it carries the FINAL order');
});

test('a reorder failure resyncs from the server, and ORDER_STALE is a warning', async () => {
  const paths = [];
  const h = await loaded(view({ modules: [m({ module_id: uuid(1) })] }));
  const sections = [{ section_id: 'sec-1', name: 'CYBR 480', status: 'active' }];
  h.context.API.request = (p) => {
    paths.push(p);
    if (p.endsWith('/reorder')) {
      const err = new Error('The sequence has changed. Reload the modules and try again.');
      err.data = { code: 'ORDER_STALE' };
      return Promise.reject(err);
    }
    if (p === '/instructor/sections') return Promise.resolve({ sections });
    return Promise.resolve(view({ modules: [m({ module_id: uuid(1) })] }));
  };
  h.toasts.length = 0;
  await h.mod.saveOrder();
  assert.strictEqual(h.toasts[0].kind, 'warning',
    'a lost race is a refusal, not a failure — Toast.error would tell the instructor the product broke');
  assert.strictEqual(h.toasts[0].m, 'The sequence has changed. Reload the modules and try again.',
    'the server sentence, verbatim');
  assert.ok(paths.filter((p) => !p.endsWith('/reorder')).length >= 1,
    'the server is authoritative: the tab reloads rather than keeping the optimistic order');
});

test('every issue renders the server sentence verbatim, with a Fix affordance where one exists', async () => {
  const M = uuid(1);
  const P = uuid(2);
  const issues = [
    { severity: 'error', code: 'PREREQ_CYCLE', message: 'Loop.', module_id: M, detail: null },
    { severity: 'error', code: 'PREREQ_MISSING', message: 'Gone.', module_id: M, detail: { prereq_module_id: P } },
    { severity: 'error', code: 'PREREQ_UNPUBLISHED', message: 'Draft ahead.', module_id: M, detail: { prereq_module_id: P } },
    { severity: 'error', code: 'SCHEDULED_WITHOUT_DATE', message: 'No time.', module_id: M, detail: null },
    { severity: 'error', code: 'CLOSE_BEFORE_RELEASE', message: 'Backwards.', module_id: M, detail: {} },
    { severity: 'warning', code: 'CLIENT_UNBOUND', message: 'No client.', module_id: M, detail: null },
    { severity: 'warning', code: 'DUPLICATE_POSITION', message: 'Two at 1.', module_id: null, detail: { position: 1, module_ids: [M, P] } },
    { severity: 'warning', code: 'NO_PUBLISHED_MODULES', message: 'All drafts.', module_id: null, detail: null },
    { severity: 'info', code: 'SHARED_ENVIRONMENT', message: 'Shared.', module_id: null, detail: { module_ids: [M, P] } },
  ];
  const h = await loaded(view({ modules: [m({ module_id: M })], issues }));
  const html = h.els.get('moduleIssues').innerHTML;

  assert.strictEqual((html.match(/class="action-item(?: error| warn)?"/g) || []).length, 9);
  assert.strictEqual((html.match(/<button class="btn btn-sm btn-outline"/g) || []).length, 8,
    'an issue an instructor cannot act on is a log line; NO_PUBLISHED_MODULES already names its remedy');
  for (const issue of issues) assert.ok(html.includes(issue.message), `${issue.code} sentence`);

  // Severity drives the visual weight, and errors sit above warnings.
  assert.ok(html.includes('class="action-item error"'));
  assert.ok(html.includes('class="action-item warn"'));
  assert.ok(html.includes('class="action-item"'), 'info renders neither');
  assert.ok(html.indexOf('Loop.') < html.indexOf('No client.'));
  assert.ok(html.indexOf('No client.') < html.indexOf('Shared.'));
  assert.match(html, /Needs attention \(8\)/);
});

test('an unknown issue code renders its sentence, with no button and no throw', async () => {
  const h = await loaded(view({
    modules: [m()],
    issues: [{ severity: 'error', code: 'SOMETHING_D7_ADDS', message: 'A new diagnosis.', module_id: null, detail: null }],
  }));
  const html = h.els.get('moduleIssues').innerHTML;
  assert.ok(html.includes('A new diagnosis.'));
  assert.ok(!html.includes('<button'));
  assert.ok(html.includes('This section'), 'a section-wide issue is filed against the section');
});

test('the release select offers exactly the states the CHECK constraint allows', async () => {
  const h = await loaded(view({ modules: [m()] }));
  h.mod.populateReleaseSelect('moduleReleaseState', 'draft');
  const options = [...h.els.get('moduleReleaseState').innerHTML.matchAll(/value="([^"]*)"/g)].map((x) => x[1]);
  assert.deepStrictEqual(options, [...S.RELEASE_STATES],
    'read from the payload, so a browser-side copy of a vocabulary the browser cannot require '
    + 'cannot drift into offering a value the database refuses');
});

test('the datetime helpers round-trip, which admin-crucible-events.js does not', () => {
  // A top-level const in a classic script is a LEXICAL binding, never a
  // property of the global object — which is the whole reason the file ends
  // with `window.CiabModules = CiabModules;`. Reach these two the same way the
  // engine does.
  const h = boot({});
  const toLocalInput = vm.runInContext('toLocalInput', h.context);
  const fromLocalInput = vm.runInContext('fromLocalInput', h.context);
  const iso = '2026-03-05T14:30:00.000Z';
  const local = toLocalInput(iso);
  assert.match(local, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/);
  assert.strictEqual(fromLocalInput(local), iso,
    'on release_at, which decides whether a module is open, a half-round-trip opens the module '
    + 'by the browser\'s offset with a form that redisplays exactly what the instructor typed');
  assert.strictEqual(toLocalInput(null), '');
  assert.strictEqual(toLocalInput('rubbish'), '');
  assert.strictEqual(fromLocalInput(''), null);
});

test('a mutation\'s warnings reach the instructor through the same builder as the banner', async () => {
  const h = await loaded(view({ modules: [m({ module_id: uuid(1), title: 'Scoping' })] }));
  h.toasts.length = 0;
  h.mod.applyWarnings({
    warnings: [
      { severity: 'error', code: 'SCHEDULED_WITHOUT_DATE', message: 'Scheduled with no release time, so it will never open.', module_id: uuid(1) },
      { severity: 'info', code: 'RELEASE_RESET', message: 'Saved as a draft.', module_id: uuid(1) },
    ],
  });
  assert.deepStrictEqual(h.toasts.map((t) => t.kind), ['error', 'info']);
  assert.strictEqual(h.toasts[0].t, 'Scoping', 'titled by the module the warning is about');
  assert.strictEqual(h.toasts[0].m, 'Scheduled with no release time, so it will never open.');
});

test('the empty state names the repetition the tab exists for', async () => {
  const h = await loaded(view({ modules: [], counts: { total: 0 } }));
  const html = h.els.get('moduleListContent').innerHTML;
  assert.ok(html.includes('No modules in CYBR 480 yet'));
  assert.ok(/clone it onto another client/.test(html),
    'clone-a-module is the repetition mechanism, and the empty state is where it is taught');
});

// ===========================================================================
// The defects an adjudicated review found in this phase. Each test below fails
// against the browser module as it was first written.
// ===========================================================================

test('the clone dialog does not prefill a client that guarantees a 409', async () => {
  // assessment_progress is UNIQUE (user_id, profile_id, part_number) with no
  // section column, so two modules cannot share one client AND one Deliverable.
  // A same-section clone is counted against a list that CONTAINS the source and
  // planClone inherits assessment_part unconditionally, so prefilling the
  // source's client made Clone -> change nothing -> Clone a guaranteed refusal
  // on the tab's headline feature.
  const withPart = m({ module_id: uuid(1), title: 'Scoping', profile_id: uuid(11), assessment_part: 2 });
  const h = await loaded(view({ modules: [withPart] }));
  h.mod.showCloneModal(uuid(1));
  assert.strictEqual(h.els.get('moduleCloneProfile').value, '',
    'the client is the only field that can clear the collision, so it is the one that must move');

  // A module with NO Deliverable cannot collide, so its client rides across --
  // cloning onto the same client is legitimate repetition.
  const noPart = m({ module_id: uuid(2), title: 'Debrief', profile_id: uuid(11), assessment_part: null });
  const h2 = await loaded(view({ modules: [noPart] }));
  h2.mod.showCloneModal(uuid(2));
  assert.strictEqual(h2.els.get('moduleCloneProfile').value, uuid(11));
});

test('the source title is printed ONCE in the clone dialog', () => {
  assert.ok(!HTML.includes('moduleCloneSourceTitle'),
    'the <small> and the labelled readonly input carried the same string');
  assert.ok(!MODULES_CODE.includes('moduleCloneSourceTitle'));
  assert.ok(MODULES_CODE.includes("this.setField('moduleCloneSource', m.title)"));
});

test('the release fields name the timezone they are in', async () => {
  // <input type="datetime-local"> carries no zone and fromLocalInput converts
  // through whatever zone THIS browser is set to, so a co-instructor elsewhere
  // reads a different wall-clock time out of the same field. instructor.html has
  // always shipped the <small>; nothing ever wrote to it.
  const h = await loaded(view({ modules: [m({ module_id: uuid(1) })] }));
  h.mod.showModuleModal(uuid(1));
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  assert.strictEqual(h.els.get('moduleReleaseTz').textContent, `Times are in ${tz}.`);
});

test('a create warning is titled by the module it is about, not by an id fragment', async () => {
  // applyWarnings titles each toast with moduleTitle(w.module_id), which reads
  // this.modules -- and on a create the new module is not in it yet, so the
  // warning came out titled `Module 00000000`. It must run AFTER the re-fetch.
  const created = m({ module_id: uuid(7), title: 'Later', release_state: 'scheduled' });
  let listed = [];
  const h = boot({
    apiHandler: (path, options) => {
      if (path === '/instructor/sections') {
        return Promise.resolve({ sections: [{ section_id: 'sec-1', name: 'CYBR 480' }] });
      }
      if (options.method === 'POST') {
        listed = [created];
        return Promise.resolve({
          module: created,
          warnings: [{
            severity: 'error', code: 'SCHEDULED_WITHOUT_DATE', module_id: uuid(7),
            message: 'Scheduled with no release time, so it will never open.',
          }],
        });
      }
      return Promise.resolve(view({ modules: listed }));
    },
  });
  await h.mod.load();
  h.mod.showModuleModal();
  h.els.get('moduleTitle').value = 'Later';
  h.toasts.length = 0;
  await h.mod.saveModule();

  const warning = h.toasts.find((t) => t.kind === 'error');
  assert.ok(warning, 'the warning must reach the instructor');
  assert.strictEqual(warning.t, 'Later',
    'a toast headed `Module 00000000` names nothing, and the banner names it correctly on the same repaint');
});

test('a clone warning is titled by the NEW module, not by an id fragment', async () => {
  // Every clone carries a RELEASE_RESET notice naming the NEW module's id, so
  // before this EVERY SINGLE CLONE toasted `Module 00000000`.
  const source = m({ module_id: uuid(1), title: 'Scoping' });
  const copy = m({ module_id: uuid(8), title: 'Scoping (copy)' });
  let listed = [source];
  const h = boot({
    apiHandler: (path, options) => {
      if (path === '/instructor/sections') {
        return Promise.resolve({ sections: [{ section_id: 'sec-1', name: 'CYBR 480' }] });
      }
      if (options.method === 'POST' && /\/clone$/.test(path)) {
        listed = [source, copy];
        return Promise.resolve({
          module: copy,
          warnings: [{
            severity: 'info', code: 'RELEASE_RESET', module_id: uuid(8),
            message: 'The copy was saved as a draft with no open or close time.',
          }],
        });
      }
      return Promise.resolve(view({ modules: listed }));
    },
  });
  await h.mod.load();
  h.mod.showCloneModal(uuid(1));
  h.toasts.length = 0;
  await h.mod.cloneModule();

  const info = h.toasts.find((t) => t.kind === 'info');
  assert.ok(info);
  assert.strictEqual(info.t, 'Scoping (copy)');
});

test('Renumber the sequence re-fetches, so the warning it clears actually disappears', async () => {
  // saveOrder's success path only writes m.position onto the in-memory rows and
  // repaints -- but the # cell is the render INDEX, not m.position, and
  // this.modules is already in the server's order, so the repaint was
  // byte-identical. renderIssues never re-ran, so the DUPLICATE_POSITION banner
  // and its own button stayed on screen: the database was correctly renumbered
  // and absolutely nothing changed on screen.
  const rows = [m({ module_id: uuid(1), position: 1 }), m({ module_id: uuid(2), position: 1, title: 'Twin' })];
  let issues = [{ severity: 'warning', code: 'DUPLICATE_POSITION', module_id: null, message: 'Two modules share a position.' }];
  const paths = [];
  const h = boot({
    apiHandler: (path, options) => {
      paths.push(`${(options.method || 'GET')} ${path}`);
      if (path === '/instructor/sections') {
        return Promise.resolve({ sections: [{ section_id: 'sec-1', name: 'CYBR 480' }] });
      }
      if (/\/reorder$/.test(path)) {
        issues = [];
        return Promise.resolve({ success: true, order: rows.map((r) => r.module_id), moved: 1, warnings: [] });
      }
      return Promise.resolve(view({ modules: rows, issues }));
    },
  });
  await h.mod.load();
  assert.match(h.els.get('moduleIssues').innerHTML, /Two modules share a position/);

  paths.length = 0;
  await h.mod.normalizePositions();

  assert.ok(paths.some((c) => /reorder/.test(c)), 'it still writes the renumber');
  assert.ok(paths.some((c) => c === 'GET /instructor/sections'),
    'and re-fetches, which is what every other mutation in this file does');
  assert.strictEqual(h.els.get('moduleIssues').innerHTML, '',
    'the banner that told the instructor to press the button must be the thing that goes away');
});

test('a debounced reorder is flushed to ITS OWN section when the section changes', async () => {
  // saveOrder reads this.sectionId and this.modules at FIRE time, 400ms later.
  // onSectionChange replaced both and never cleared the timer, so a move on
  // section A followed by picking section B either POSTed A's ids to B (409
  // ORDER_STALE about a section the instructor is not looking at) or POSTed B's
  // own ids to B (moved: 0, no error, and A's move silently lost).
  const a1 = m({ module_id: uuid(1), position: 1, title: 'A one' });
  const a2 = m({ module_id: uuid(2), position: 2, title: 'A two' });
  const bOnly = m({ module_id: uuid(3), position: 1, title: 'B one' });
  const sections = [
    { section_id: 'sec-a', name: 'A' },
    { section_id: 'sec-b', name: 'B' },
  ];
  const posts = [];
  const h = boot({
    apiHandler: (path, options) => {
      if (path === '/instructor/sections') return Promise.resolve({ sections });
      if (/\/reorder$/.test(path)) {
        posts.push({ path, order: options.body.order });
        return Promise.resolve({ success: true, order: options.body.order, moved: 1, warnings: [] });
      }
      const forB = path.indexOf('sec-b') !== -1;
      return Promise.resolve(view({
        section: { section_id: forB ? 'sec-b' : 'sec-a', name: forB ? 'B' : 'A' },
        modules: forB ? [bOnly] : [a1, a2],
      }));
    },
  });
  await h.mod.load();
  assert.strictEqual(h.mod.sectionId, 'sec-a');

  h.mod.move(uuid(2), -1);                       // schedules a save 400ms out
  h.els.get('moduleSectionSelect').value = 'sec-b';
  await h.mod.onSectionChange();                 // well inside the debounce

  assert.strictEqual(posts.length, 1, 'the move must reach the server exactly once');
  assert.ok(posts[0].path.indexOf('sec-a') !== -1,
    'a move made in section A belongs to section A, whatever the select now says');
  assert.deepStrictEqual(posts[0].order, [uuid(2), uuid(1)],
    'and it carries the ids of the section it was made in');
  assert.strictEqual(h.mod.sectionId, 'sec-b');
  assert.ok(h.toasts.every((t) => t.kind !== 'warning'),
    'no ORDER_STALE about a section the instructor is not looking at');
});
