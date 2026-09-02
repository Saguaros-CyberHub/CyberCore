/**
 * ============================================================================
 * blueteam-student-mount.test.js — Track E, phase E5: the CiAB student board
 * ============================================================================
 * public/js/blueteam/ shipped four finished files that NOTHING LOADED. The bug
 * that produced that state is invisible — every module is correct, every test
 * over them passes, and the feature simply is not on any page. So the first
 * thing this file asserts is the dullest: that the script tags exist, in the
 * right order, pointing at files that are really there.
 *
 * WHY THE ORDER IS A TEST AND NOT A COMMENT
 * ----------------------------------------------------------------------------
 * Each of the four is an IIFE assigning exactly one global, and
 * blueteam-board.js reads BlueTeamApi, BlueTeamTimeline and BlueTeamScore off
 * `window` when mount() runs. Classic <script src> tags execute in document
 * order, so board-before-api is a TypeError at first click and nothing at load:
 * the page looks perfect until a student presses the button. A reordering by a
 * later editor tidying the block is exactly the change that would do it.
 *
 * WHY THE SOURCE-TEXT GATE
 * ----------------------------------------------------------------------------
 * Same argument as test/incident-answer-key-leak.test.js, applied to the page
 * rather than the handler. The private columns on a run are the entire answer to
 * the exercise, and the single most valuable of them is not an identifier at all
 * — it is a COUNT. "There are six" tells a student when to stop hunting, which
 * is most of the skill being taught. src/incident/projection.js withholds the
 * totals until release; this file makes sure the student page does not name them
 * either, because a page that has the number in its source is one edit away from
 * rendering it.
 *
 * The gate covers BOTH files a CiAB student's browser gets from this track —
 * the page and its mount script. The four blueteam-*.js files are already gated
 * by test/incident-answer-key-leak.test.js and are not re-scanned here.
 *
 * Run: node --test front-end/test/blueteam-student-mount.test.js   (or npm test)
 */

'use strict';

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');
const exists = (rel) => fs.existsSync(path.join(ROOT, rel));

const PAGE_REL = 'modules/crucible/plugins/ciab/public/pages/workspace.html';
const MOUNT_REL = 'modules/crucible/plugins/ciab/public/js/workspace-incident.js';

const PAGE = read(PAGE_REL);
const MOUNT = read(MOUNT_REL);

/**
 * The four, in the order they must load. api first because everything else
 * would talk to nothing; board LAST because it is the only one that reads the
 * other three.
 */
const BOARD_SCRIPTS = [
  '/js/blueteam/blueteam-api.js',
  '/js/blueteam/blueteam-timeline.js',
  '/js/blueteam/blueteam-score.js',
  '/js/blueteam/blueteam-board.js',
];

/** Where each of those actually lives, so a rename fails here and not in a browser. */
const scriptFile = (src) => 'public' + src;

// ---------------------------------------------------------------------------
// §1 The wiring
// ---------------------------------------------------------------------------

test('E5-SM1: workspace.html loads all four blue-team scripts', () => {
  for (const src of BOARD_SCRIPTS) {
    assert.ok(
      PAGE.includes(`<script src="${src}"></script>`),
      `${PAGE_REL} has no <script src="${src}">. The board is dead code without it.`
    );
    assert.ok(
      exists(scriptFile(src)),
      `${src} is referenced by the page but ${scriptFile(src)} does not exist.`
    );
  }
});

test('E5-SM2: they load in dependency order — api, timeline, score, board', () => {
  const at = BOARD_SCRIPTS.map((src) => ({ src, i: PAGE.indexOf(`<script src="${src}"></script>`) }));
  for (let n = 1; n < at.length; n += 1) {
    assert.ok(
      at[n].i > at[n - 1].i,
      `${at[n].src} is loaded before ${at[n - 1].src}. blueteam-board.js reads BlueTeamApi, `
      + 'BlueTeamTimeline and BlueTeamScore off window at mount time, so an out-of-order tag '
      + 'is a TypeError on first click and nothing at all at load.'
    );
  }
});

test('E5-SM3: the page that mounts the board loads after the board itself', () => {
  const board = PAGE.indexOf(`<script src="${BOARD_SCRIPTS[3]}"></script>`);
  const mount = PAGE.indexOf('<script src="/ciab/js/workspace-incident.js"></script>');
  assert.ok(mount !== -1, `${PAGE_REL} does not load /ciab/js/workspace-incident.js`);
  assert.ok(mount > board, 'workspace-incident.js must load after blueteam-board.js');
});

test('E5-SM4: the page carries the elements the mount script writes into', () => {
  // Named individually rather than by a smoke test, because the failure mode of
  // a missing id is a silent early return in init() -- the button never appears
  // and nothing is logged.
  for (const id of [
    'workspaceMain', 'incidentNav', 'incidentNavBtn', 'incidentCloseBtn',
    'incidentPanel', 'incidentSub', 'incidentPicker', 'incidentRunSelect',
    'incidentBanner', 'incidentNote', 'incidentMount',
  ]) {
    assert.ok(PAGE.includes(`id="${id}"`), `${PAGE_REL} is missing #${id}`);
  }
});

test('E5-SM5: the panel hides the deliverables by CLASS, never by inline style', () => {
  // workspace.js owns the inline `display` on #noProfileState and
  // #workspaceContent (loadProfile / showEmptyState write them). A second writer
  // restores a stale value the moment a student switches profile with the panel
  // open, so the panel toggles one class and lets an important author rule beat
  // the inline style.
  assert.ok(
    /\.workspace-main\.incident-open\s*>\s*#noProfileState/.test(PAGE)
    && /\.workspace-main\.incident-open\s*>\s*#workspaceContent\s*\{[^}]*display:\s*none\s*!important/.test(PAGE),
    'workspace.html must hide #noProfileState / #workspaceContent with an !important rule '
    + 'under .workspace-main.incident-open'
  );
  assert.ok(
    !/noProfileState'\)\.style|workspaceContent'\)\.style/.test(MOUNT),
    `${MOUNT_REL} writes an inline display style that workspace.js also owns.`
  );
});

// ---------------------------------------------------------------------------
// §2 The mount
// ---------------------------------------------------------------------------

/**
 * The text between a call's opening paren and its match. Nesting-aware, and it
 * SKIPS EMPTY ARGUMENT LISTS on purpose: this codebase names its functions in
 * prose, so `// BlueTeamBoard.mount() handle` sits above the real call and a
 * naive first-match returns the comment's empty parens instead.
 */
function callSlice(src, marker) {
  let from = src.indexOf(marker);
  assert.ok(from !== -1, `call not found: ${marker}`);
  while (from !== -1) {
    const open = src.indexOf('(', from);
    let depth = 0;
    let closed = false;
    for (let i = open; i < src.length; i += 1) {
      if (src[i] === '(') depth += 1;
      else if (src[i] === ')') {
        depth -= 1;
        if (depth === 0) {
          const args = src.slice(open + 1, i);
          if (args.trim()) return args;
          from = src.indexOf(marker, i);
          closed = true;
          break;
        }
      }
    }
    if (!closed) throw new Error(`unbalanced call: ${marker}`);
  }
  throw new Error(`no call to ${marker} carries arguments`);
}

test('E5-SM6: the mount passes the STUDENT role', () => {
  const args = callSlice(MOUNT, 'BlueTeamBoard.mount(');
  assert.ok(
    /role:\s*'student'/.test(args) || /role:\s*"student"/.test(args),
    'BlueTeamBoard.mount() on the CiAB workspace page must pass role: \'student\'.'
  );
  assert.ok(
    !/role:\s*['"]staff['"]/.test(MOUNT),
    `${MOUNT_REL} must never mount the staff layout.`
  );
  assert.ok(/runId:/.test(args), 'mount() requires a runId and throws without one');
});

test('E5-SM7: the board is scoped to an engagement, never to the other product', () => {
  assert.ok(
    MOUNT.includes("'/api/engagements/'"),
    `${MOUNT_REL} must build its base from /api/engagements/<id>/incidents`
  );
  assert.ok(
    MOUNT.includes('/incidents'),
    `${MOUNT_REL} must address the incidents collection`
  );
  assert.ok(
    !MOUNT.includes('/api/cle/'),
    'A CiAB student page must never call the neighbouring plugin\'s routes.'
  );
});

test('E5-SM8: the student page drives no instructor-only endpoint', () => {
  // Cosmetic on its own -- the routes carry requireRole -- but it catches the
  // real mistake, which is a block copied across from the instructor screen.
  for (const call of ['.release(', '.score(', '.overrideFinding(']) {
    assert.ok(
      !MOUNT.includes(call),
      `${MOUNT_REL} calls ${call}, which is an instructor action.`
    );
  }
});

// ---------------------------------------------------------------------------
// §3 The release gate, said out loud
// ---------------------------------------------------------------------------

test('E5-SM9: the pre-release state is named, in words, on the page', () => {
  // The gate is invisible if nobody names it: a page that quietly shows three
  // rows and no verdicts reads as broken, and a student who thinks the page is
  // broken stops trusting it.
  assert.ok(
    /not yet released by your instructor/i.test(MOUNT),
    `${MOUNT_REL} must say "not yet released by your instructor" in the pre-release banner.`
  );
  assert.ok(
    /released by your instructor/i.test(MOUNT),
    `${MOUNT_REL} must also name the released state.`
  );
  // The renderer builds the class by concatenation, so it holds the stem; the
  // stylesheet holds both endings. Both halves have to be present or the banner
  // renders unstyled — which for the locked state means an urgent message
  // wearing no colour at all.
  assert.ok(/incident-banner-/.test(MOUNT), `${MOUNT_REL} renders no banner class`);
  for (const cls of ['incident-banner-locked', 'incident-banner-released']) {
    assert.ok(PAGE.includes(cls), `${PAGE_REL} has no rule for .${cls}`);
  }
});

test('E5-SM10: the page never reconstructs a count of what is missing', () => {
  // The count is the leak the release gate exists for. Nothing on this page may
  // name a total, and nothing may derive one -- "found N of M" is the shape to
  // watch for, and it is easy to add by accident from a findings array.
  for (const needle of ['techniques_total', 'techniques_missed', 'iocs_total', 'techniques_found']) {
    assert.ok(!PAGE.includes(needle), `${PAGE_REL} names ${needle}`);
    assert.ok(!MOUNT.includes(needle), `${MOUNT_REL} names ${needle}`);
  }
  assert.ok(
    !/\bof\s*\{?\s*\$?\{?\s*(total|expected)\b/i.test(MOUNT),
    `${MOUNT_REL} looks like it renders an "N of M" line.`
  );
});

// ---------------------------------------------------------------------------
// §4 The source-text gate
// ---------------------------------------------------------------------------

/**
 * Staff-only names, and the reason each one is staff-only.
 *
 * These are not scanned for because a student page is likely to contain them.
 * They are scanned for because the page that DOES contain one will have been
 * written by somebody reasonable, copying a working block from the instructor
 * screen, with no way to see what it costs.
 */
const STAFF_ONLY = [
  ['answer_key', 'the graded truth'],
  ['playbook', 'the compiled attack, verbatim'],
  ['override_note', 'staff write it expecting the student cannot read it'],
  ['override_verdict', 'the instructor adjudication, pre-release'],
  ['override_points', 'the same, as a number'],
  ['override_by', 'who adjudicated'],
  ['auto_verdict', 'the scorer output before release'],
  ['auto_points', 'the same, as a number'],
  ['auto_matched_key', 'which entry of the graded truth matched'],
  ['catalog_version', 'names the generator build, so two runs can be diffed'],
  ['chain_key', 'the selection — literally the answer'],
  ['tactic_id', 'the same, one level up'],
  ['scenario_id', 'the same, for the client arm'],
  ['scenario_ref', 'the client threat-scenario text'],
  ['launched_by', 'staff operational detail'],
  ['event_group_id', 'staff operational detail'],
  ['duration_seconds', 'a student who knows the run is 30 minutes knows when to stop'],
  ['lead_seconds', 'the same, from the other end'],
  ['final_points', 'the student projection calls it `points`; this is the staff column'],
  ['SELECT *', 'no page has any business holding SQL, least of all a star select'],
  ['r.*', 'the same star, wearing the run table alias'],
];

test('E5-SM11: the student page names no staff-only field', () => {
  for (const [rel, src] of [[PAGE_REL, PAGE], [MOUNT_REL, MOUNT]]) {
    for (const [needle, why] of STAFF_ONLY) {
      assert.ok(
        !src.includes(needle),
        `${rel} contains ${JSON.stringify(needle)} — ${why}.\n`
        + '  Student reads go through src/incident/projection.js, which builds a new object '
        + 'from a fixed key list.'
      );
    }
  }
});

test('E5-SM12: the student page hardcodes no technique id, and no list of them', () => {
  // A technique id in the page source is a catalogue of what the exercise can
  // contain -- either an autocomplete list or, worse, the set the current run
  // was built from. The student types the id they worked out; the page never
  // offers one. (blueteam-board.js carries a single placeholder in its form and
  // is gated separately, so it is deliberately not scanned here.)
  const TECHNIQUE = /\bT\d{4}(?:\.\d{3})?\b/g;
  for (const [rel, src] of [[PAGE_REL, PAGE], [MOUNT_REL, MOUNT]]) {
    const hits = src.match(TECHNIQUE);
    assert.ok(
      !hits,
      `${rel} hardcodes technique id(s): ${hits && hits.join(', ')}. `
      + 'A list of them on the student page is a list of the answers.'
    );
  }
});

// ---------------------------------------------------------------------------
// §5 Vocabulary
//
// CiAB nouns are Client, Section, Module, Engagement, Environment, Incident. A
// student running a clinic never sees a word from the neighbouring product's
// model, and would not know what it meant if they did. Scoped to the two files
// this phase owns, for the reason ciab-engagement-vocabulary.test.js states at
// length: a repository-wide grep fails on day one against copy that is correct.
// ---------------------------------------------------------------------------

const FOREIGN = /\b(course|courses|material|materials|cohort|cohorts|challenge|challenges|lane|lanes|assignment|assignments|lesson|lessons)\b/i;

test('E5-SM13: no foreign vocabulary on the CiAB student board', () => {
  for (const [rel, src] of [[PAGE_REL, PAGE], [MOUNT_REL, MOUNT]]) {
    const lines = src.split(/\r?\n/);
    lines.forEach((line, n) => {
      const hit = line.match(FOREIGN);
      assert.ok(
        !hit,
        `${rel}:${n + 1} uses "${hit && hit[0]}" — not a Clinic-in-a-Box noun.\n`
        + `  ${line.trim()}`
      );
    });
    assert.ok(!/CYBR/.test(src), `${rel} names a catalogue number from another product.`);
  }
});
