/**
 * ciab-vocabulary.test.js — Track E, phase E6: the words on the Incidents tab,
 * and the wiring that puts that tab on the page.
 *
 * THE VOCABULARY RULE. Clinic-in-a-Box speaks Section / Module / Client /
 * Engagement / Environment / Incident. The neighbouring plugin's nouns —
 * course, material, cohort, challenge — and its section codes (CYBR …) name a
 * different model, and an instructor running a clinic never opens that plugin.
 * A word borrowed from it is not a cosmetic slip: it tells the reader the two
 * products are the same one, which is exactly the confusion the split exists to
 * remove.
 *
 * WHY THIS TEST IS SCOPED TO THE NEW SURFACE AND NOT TO THE WHOLE PAGE.
 * A naive scan of instructor.html fails on day one against copy that is
 * deliberate and correct: the page carries a cross-plugin roster import that
 * names the OTHER plugin's object on purpose ("Import from a CLE course",
 * "Generate Cohort Accounts"), and the section modal's placeholder is a real
 * section code. Those are right. Widening the scan would either fail
 * immediately or teach the next author to delete the assertion. So it reads
 * exactly what E6 added: instructor-incidents.js in full, and the three blocks
 * instructor.html contributes, each extracted by its own marker rather than by
 * line number so another track appending a tab cannot move them out of range.
 *
 * The scan covers COMMENTS TOO, not only rendered strings. A comment is where
 * the wrong noun gets rehearsed before it reaches a label.
 *
 * THIS FILE ALSO PINS THE FOUR-TOUCHPOINT WIRING, because a half-applied one
 * fails silently at runtime: a tab button with no panel renders an empty page,
 * a panel with no script tag renders an empty panel, a script tag with no name
 * in TAB_NAMES gives a tab switchTab() refuses to open, and the four
 * /js/blueteam/*.js tags in the wrong order give a board that throws on mount.
 *
 * Run: node --test front-end/test/ciab-vocabulary.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

const UI_FILE = path.join(CIAB, 'public', 'js', 'instructor-incidents.js');
const CORE_FILE = path.join(CIAB, 'public', 'js', 'instructor-core.js');
const HTML_FILE = path.join(CIAB, 'public', 'pages', 'instructor.html');

const UI = fs.readFileSync(UI_FILE, 'utf8');
const CORE = fs.readFileSync(CORE_FILE, 'utf8');
const HTML = fs.readFileSync(HTML_FILE, 'utf8');

// Every line-wise scan splits on a CRLF-tolerant boundary: this checkout mixes
// conventions and a '\n' split leaves a trailing '\r' on every line.
const NEWLINE = /\r?\n/;

/**
 * Deliberately NOT anchored with \b.
 *
 * 'CYBR' turns up inside a section code with no word boundary in front of it
 * ('cybr-480-7w1-student1'), and 'cohort' inside 'ciabCohortModal'. Both of
 * those are exactly the shapes that would sneak past a \b-anchored rule, and
 * neither belongs on this screen. The cost is that a substring like
 * 'materialise' would trip it — which is fine, because there is no reason to
 * write one here.
 */
const FORBIDDEN = /course|material|cohort|CYBR|challenge/i;

/** A line that is only a comment — where a rule may be EXPLAINED, not broken. */
function isCommentLine(line) {
  const t = line.trim();
  return t.startsWith('//') || t.startsWith('*') || t.startsWith('/*') || t.startsWith('<!--');
}

/** Every non-comment line of a file, joined — the code, without its prose. */
function codeOnly(text) {
  return text.split(NEWLINE).filter((l) => !isCommentLine(l)).join('\n');
}

// ── Extraction ──────────────────────────────────────────────────────────────

/** Everything from `start` up to and including `end`, or '' if absent. */
function sliceBetween(text, start, end) {
  const a = text.indexOf(start);
  if (a === -1) return '';
  const b = text.indexOf(end, a);
  return b === -1 ? text.slice(a) : text.slice(a, b + end.length);
}

/** The panel, with the comment banner that explains it. */
function incidentsPanelHtml() {
  return sliceBetween(HTML, '<!-- TAB: INCIDENTS', '<!-- /TAB: INCIDENTS -->');
}

/** The tab-strip button — two lines, because the house style wraps it. */
function incidentsButtonHtml() {
  const lines = HTML.split(NEWLINE);
  for (let i = 0; i < lines.length; i += 1) {
    if (/data-tab="incidents"/.test(lines[i])) {
      return `${lines[i]}\n${lines[i + 1] || ''}`;
    }
  }
  return '';
}

/** The script block E6 appended, comment included. */
function incidentsScriptHtml() {
  return sliceBetween(HTML, '<!-- The shared blue-team board',
    'instructor-incidents.js"></script>');
}

function scanSubjects() {
  return [
    { name: 'public/js/instructor-incidents.js', text: UI },
    { name: 'instructor.html #tab-incidents panel', text: incidentsPanelHtml() },
    { name: 'instructor.html Incidents tab button', text: incidentsButtonHtml() },
    { name: 'instructor.html incidents script block', text: incidentsScriptHtml() },
  ];
}

// ── 1. The vocabulary itself ────────────────────────────────────────────────

test('E6-V1: no out-of-vocabulary word appears anywhere in the Incidents surface', () => {
  for (const { name, text } of scanSubjects()) {
    assert.ok(text.length > 0, `${name} is empty — the extraction marker is missing`);
    const hits = [];
    text.split(NEWLINE).forEach((line, n) => {
      if (FORBIDDEN.test(line)) hits.push(`${name}:${n + 1}  ${line.trim()}`);
    });
    assert.deepStrictEqual(
      hits, [],
      'Section / Module / Client / Engagement / Environment / Incident is the '
      + `vocabulary.\n${hits.join('\n')}`
    );
  }
});

test('E6-V2: the words a reader SHOULD find are actually there', () => {
  // The negative assertion above is satisfied by an empty file, so pin the
  // positive half too: this tab really does speak the intended vocabulary.
  assert.ok(/\bSection\b/.test(UI), 'the tab names a Section');
  assert.ok(/\bClient\b/.test(UI), 'and a Client');
  assert.ok(/\bEngagement\b/.test(UI), 'and an Engagement');
  assert.ok(/\bEnvironment\b|\benvironment\b/.test(UI), 'and an Environment');
  assert.ok(/\bincident\b/i.test(UI), 'and an Incident');
});

test('E6-V3: "lane" is a payload key here and never a word on the screen', () => {
  // exclude_lane_ids and lane_id are the SHARED engine's column names —
  // renaming them would fork the payload the shared board understands — so they
  // stay. What must not happen is one of them leaking into copy.
  const hits = [];
  UI.split(NEWLINE).forEach((line, n) => {
    if (!/\blanes?\b/i.test(line)) return;
    // An identifier occurrence always carries the underscore form.
    if (/lane_id|laneId|lane_ids/.test(line)) return;
    hits.push(`${n + 1}  ${line.trim()}`);
  });
  assert.deepStrictEqual(hits, [], `the screen says "environment", never "lane":\n${hits.join('\n')}`);
});

// ── 2. The launcher offers only what the backend implements ─────────────────

test('E6-V4: the launcher offers every mode the backend implements, and no more', () => {
  // THIS TEST IS INVERTED FROM WHAT E6 SHIPPED, DELIBERATELY. Its previous form
  // asserted that the word 'scenario' appeared nowhere in this file's code,
  // because the compiler that turns a Client's threat profile into a playbook
  // did not exist: engines/synthetic.js excluded the mode and the launch route
  // refused it by name, so a picker offering it would have produced a button
  // whose only outcome was a 400.
  //
  // E4 shipped src/incident/scenario-compiler.js and E7 wired it end to end, so
  // the picker offers it and this test now guards the OTHER direction: the four
  // modes on screen must be exactly the four the engine claims to support. A
  // button the engine refuses is a 400 an instructor cannot act on; an
  // implemented mode with no button is a feature nobody can reach.
  const engine = require('../src/incident/engines').engineFor('synthetic');
  for (const mode of ['scenario', 'technique', 'tactic', 'chain']) {
    assert.strictEqual(engine.supportsMode(mode), true, `the engine dropped ${mode}`);
    assert.ok(UI.includes("setMode('" + mode + "')"), `${mode} mode is not offered`);
  }

  // And nothing beyond them. A fifth setMode() argument would be a mode the run
  // table's own CHECK constraint does not have.
  const offered = new Set();
  for (const m of UI.matchAll(/setMode\('([a-z]+)'\)/g)) offered.add(m[1]);
  assert.deepStrictEqual([...offered].sort(), ['chain', 'scenario', 'tactic', 'technique']);
});

test('E6-V4b: the scenario picker shows the count but never the answer key', () => {
  // technique_count IS shown here, and that is a deliberate asymmetry rather
  // than an oversight: this file is the INSTRUCTOR's screen. A student who
  // knows there are six techniques knows when to stop looking, which is why
  // src/incident/projection.js keeps the number off every student payload and
  // why the release gate withholds it. The instructor needs it to choose.
  assert.ok(/technique_count/.test(UI), 'the picker names the technique count');

  // What must never reach ANY browser is the per-step prose: `action` and
  // `detection_opportunity` are the answer key, and src/incident/
  // scenario-compiler.js refuses to let either onto a playbook for exactly that
  // reason. The server projects them away in summarizeScenario(); this is the
  // second gate, on the consumer.
  for (const needle of ['detection_opportunity', 'attack_path', 'answer_key']) {
    assert.ok(!new RegExp(needle).test(codeOnly(UI)),
      `instructor-incidents.js reaches for ${needle}`);
  }
});

test('E6-V5: the answer key is never named by an instructor-facing script', () => {
  // The graded truth lives on the run row and is compiled at launch time inside
  // routes/incident-launch.js. Nothing in the browser has any business naming
  // that column: src/incident/projection.js owns who may see what, and a client
  // that reached for it would be reaching past the gate.
  assert.ok(!/answer_key/.test(UI), 'instructor-incidents.js never names answer_key');
});

test('E6-V6: the board is addressed by engagement, and polled at the exempt path', () => {
  // The collection URL is the ONLY thing that differs between the two products
  // the shared board serves.
  assert.ok(
    /\/engagements\/\$\{encodeURIComponent\(id\)\}\/incidents/.test(UI),
    'the board base is /api/engagements/<id>/incidents'
  );
  // The /status suffix is what exempts the poll from the global rate limiter
  // (src/server.js matches /\/status$/). Polling any other path at 2s 429s an
  // instructor mid-exercise.
  assert.ok(/\/status`/.test(UI), 'the poll target ends in /status');
  assert.ok(/POLL_MS\s*=\s*2000/.test(UI), 'the poll runs at about 2s');
  // Terminal statuses stop it. A finished run whose tab is left open must not
  // keep asking.
  assert.ok(
    /LIVE_STATUSES\s*=\s*\['scheduling',\s*'dispatching',\s*'running'\]/.test(UI),
    'the live/terminal split is spelled once'
  );
});

test('E6-V7: a 409 is explained, not echoed', () => {
  // The dispatch mutex is a UNIQUE index on (scope_type, scope_id) while a run
  // is scheduling or dispatching, so a second Launch is a constraint violation.
  // Without a branch for it the instructor reads an index name.
  assert.ok(/409|INCIDENT_IN_FLIGHT/.test(UI), 'the 409 is recognised');
  assert.ok(
    /already dispatching for this engagement/i.test(UI),
    'and rendered as a sentence an instructor can act on'
  );
});

// ── 3. The four touchpoints ─────────────────────────────────────────────────

test('E6-W1: instructor-incidents.js exposes window.Incidents with ensureInit', () => {
  // activateTabModule() calls mod.ensureInit() and nothing else, so this pair is
  // the whole contract between the tab shell and this module.
  assert.ok(/window\.Incidents\s*=\s*\{/.test(UI), 'the module registers window.Incidents');
  assert.ok(/window\.Incidents\s*=\s*\{[\s\S]{0,200}?\bensureInit\b/.test(UI),
    'and ensureInit is one of its members');
  assert.ok(/function ensureInit\s*\(/.test(UI), 'and ensureInit is actually defined');
});

test('E6-W2: instructor-core.js lists the tab and dispatches to it', () => {
  const m = CORE.match(/const TAB_NAMES\s*=\s*\[([^\]]*)\]/);
  assert.ok(m, 'instructor-core.js still declares TAB_NAMES as an array literal');
  assert.ok(
    /'incidents'/.test(m[1]),
    `TAB_NAMES must contain 'incidents' or switchTab() falls back to overview: [${m[1].trim()}]`
  );
  assert.ok(
    /incidents:\s*window\.Incidents/.test(CORE),
    "activateTabModule must map 'incidents' to window.Incidents"
  );
});

test('E6-W3: instructor.html carries the button and the panel, and they agree', () => {
  const button = incidentsButtonHtml();
  const panel = incidentsPanelHtml();
  assert.ok(button, 'the tab strip needs a data-tab="incidents" button');
  assert.ok(panel, 'the page needs the #tab-incidents panel');

  // switchTab maintains aria-controls, aria-selected and tabindex on every
  // button; one missing them drifts out of sync the first time a tab changes.
  assert.ok(/id="tabbtn-incidents"/.test(button), 'the button has the id the panel labels itself by');
  assert.ok(/aria-controls="tab-incidents"/.test(button), 'the button controls the panel by id');
  assert.ok(/aria-selected=/.test(button), 'the button carries aria-selected');
  assert.ok(/tabindex=/.test(button), 'and tabindex');
  // This screen carries verdict overrides and the release gate. None of that
  // belongs on a projector in Student View.
  assert.ok(/data-instructor-only/.test(button), 'and data-instructor-only');

  // The id must be EXACTLY tab-incidents: switchTab matches panel.id ===
  // `tab-${name}`.
  const panelLine = panel.split(NEWLINE).find((l) => /id="tab-incidents"/.test(l)) || '';
  assert.ok(panelLine, 'the panel element itself is inside the marked block');
  assert.ok(/class="tab-content"/.test(panelLine), 'the panel is a .tab-content');
  assert.ok(/role="tabpanel"/.test(panelLine), 'the panel is a tabpanel');
  assert.ok(/aria-labelledby="tabbtn-incidents"/.test(panelLine), 'the panel names its button');
  assert.ok(/data-instructor-only/.test(panelLine), 'the panel is hidden in Student View');

  // No inline display on the PANEL: visibility is the .active class, and
  // switchTab's classList toggle would silently lose to an inline style.
  assert.ok(!/id="tab-incidents"[^>]*style="[^"]*display/.test(panelLine),
    'the panel must not carry an inline display');

  // The elements instructor-incidents.js addresses by id.
  for (const id of ['incidentNoScope', 'incidentMain', 'incidentSectionSelect',
    'incidentEngagementField', 'incidentEngagementSelect', 'incidentScopeMeta',
    'incidentLauncher', 'incidentRun', 'incidentBoard']) {
    assert.ok(panel.includes(`id="${id}"`), `the panel is missing #${id}`);
  }
});

test('E6-W4: the script tags are present and in the one order that works', () => {
  // The TAG, not the first mention. Both files are named in comments earlier in
  // the page, and comparing those positions would compare prose, not load order.
  const at = (src) => HTML.indexOf(`src="${src}"`);

  const core = at('/ciab/js/instructor-core.js');
  const api = at('/js/blueteam/blueteam-api.js');
  const timeline = at('/js/blueteam/blueteam-timeline.js');
  const score = at('/js/blueteam/blueteam-score.js');
  const board = at('/js/blueteam/blueteam-board.js');
  const mine = at('/ciab/js/instructor-incidents.js');

  assert.ok(api !== -1, 'blueteam-api.js is not loaded');
  assert.ok(timeline !== -1, 'blueteam-timeline.js is not loaded');
  assert.ok(score !== -1, 'blueteam-score.js is not loaded');
  assert.ok(board !== -1, 'blueteam-board.js is not loaded');
  assert.ok(mine !== -1, 'instructor-incidents.js is not loaded');

  // blueteam-board.js reads BlueTeamApi / BlueTeamTimeline / BlueTeamScore off
  // window when it mounts, so all three must have registered first.
  assert.ok(api < timeline, 'blueteam-api.js must come before blueteam-timeline.js');
  assert.ok(timeline < score, 'blueteam-timeline.js must come before blueteam-score.js');
  assert.ok(score < board, 'blueteam-score.js must come before blueteam-board.js');

  // esc / escJs / timeAgo are top-level consts in instructor-core.js, which
  // makes them global LEXICAL bindings and not window properties: a tag placed
  // earlier reads them inside their temporal dead zone.
  assert.ok(core !== -1 && core < mine, 'instructor-incidents.js must come AFTER instructor-core.js');
  assert.ok(board < mine, 'instructor-incidents.js must come AFTER blueteam-board.js');
});
