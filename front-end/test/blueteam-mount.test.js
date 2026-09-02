/**
 * blueteam-mount.test.js — the blue-team board is actually LOADED, and it is
 * pointed at a URL that exists.
 *
 * The board (public/js/blueteam/*.js) and its two routers shipped before
 * anything on any page referenced them: four IIFEs, four globals, and zero
 * <script> tags. Every part of that is individually testable and all of it
 * passed, which is exactly why nobody noticed the feature was unreachable.
 *
 * So this is a SOURCE-TEXT GATE over the wiring itself, in the same shape as
 * test/topology-console-badge.test.js — the script-tag set on courses.html is
 * otherwise a guess that only fails in a browser. It pins three things:
 *
 *   1. ALL FOUR files load, in api → timeline → score → board order.
 *      blueteam-board.js calls BlueTeamApi.create() at mount time and
 *      BlueTeamScore/BlueTeamTimeline at render time, so a tag placed above
 *      its dependencies throws only when a student clicks the tab.
 *
 *   2. THE BASE URL MATCHES THE ROUTE. The mount builds
 *      '/api/cle/courses/{courseId}/incidents' from a literal, and
 *      routes/api.js registers the router at a path. If those two drift, every
 *      request 404s — and the board renders a 404 identically to "no incidents
 *      yet", which is the failure nobody reports as a bug.
 *
 *      There are TWO such literals now: that base, and the platform's
 *      /api/caldera-authoring/status, which the mount reads to decide whether
 *      it may offer a link to the authoring console at all. Both are checked
 *      against the path the server registers, and a third would fail.
 *
 *   3. THE MOUNT DOES NOT REACH INTO THE ATTACK CONSOLE. They are separate
 *      features with separate flags precisely so a course can run one without
 *      the other; a require-by-global from the board side would couple them
 *      back together, and attack-console.js is under a zero-diff bar.
 *
 * Run: node --test front-end/test/blueteam-mount.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CLE = path.join(ROOT, 'modules', 'crucible', 'plugins', 'cle');

const COURSES_HTML = path.join(CLE, 'public', 'pages', 'courses.html');
const MOUNT_JS = path.join(CLE, 'public', 'js', 'blue-team.js');
const API_JS = path.join(CLE, 'routes', 'api.js');
const FEATURES_JS = path.join(CLE, 'utils', 'course-features.js');

const read = (p) => fs.readFileSync(p, 'utf8');

/**
 * Source with its comments removed.
 *
 * The assertions below that say "this file must not mention X" are about CODE.
 * blue-team.js's header explains at length why it must not read
 * Auth.user.role, and a gate that cannot tell the explanation from the
 * offence would forbid documenting the rule it enforces.
 *
 * Deliberately naive — no '//' appears inside a string literal in the file
 * this runs over, and a JS parser here would be a dependency for one regex.
 */
const stripComments = (src) => src
  .replace(/\/\*[\s\S]*?\*\//g, '')
  .replace(/(^|[^:])\/\/.*$/gm, '$1');

/**
 * The load order the component graph requires, NOT alphabetical:
 * board consumes all three of the others.
 */
const BLUETEAM_SCRIPTS = [
  '/js/blueteam/blueteam-api.js',
  '/js/blueteam/blueteam-timeline.js',
  '/js/blueteam/blueteam-score.js',
  '/js/blueteam/blueteam-board.js',
];

test('every blue-team asset the page names exists on disk', () => {
  for (const src of BLUETEAM_SCRIPTS) {
    const file = path.join(ROOT, 'public', src.replace(/^\//, ''));
    assert.ok(fs.existsSync(file), `${src} is loaded by courses.html but ${file} does not exist`);
  }
  assert.ok(fs.existsSync(MOUNT_JS), 'the CLE mount module is missing');
});

test('courses.html loads all four blue-team scripts', () => {
  const html = read(COURSES_HTML);
  for (const src of BLUETEAM_SCRIPTS) {
    assert.ok(
      html.includes(`<script src="${src}"></script>`),
      `courses.html is missing the <script> tag for ${src} — the board cannot mount without it`
    );
  }
  assert.ok(
    html.includes('<script src="/cle/js/blue-team.js"></script>'),
    'courses.html is missing the CLE mount module tag'
  );
});

test('the scripts load in dependency order: api before board', () => {
  const html = read(COURSES_HTML);
  const at = (src) => html.indexOf(`<script src="${src}"></script>`);

  const positions = BLUETEAM_SCRIPTS.map(at);
  for (const [i, pos] of positions.entries()) {
    assert.ok(pos > -1, `${BLUETEAM_SCRIPTS[i]} not found`);
  }

  // Pairwise, so a failure names the two files that are out of order.
  for (let i = 1; i < BLUETEAM_SCRIPTS.length; i += 1) {
    assert.ok(
      positions[i - 1] < positions[i],
      `${BLUETEAM_SCRIPTS[i - 1]} must load before ${BLUETEAM_SCRIPTS[i]}`
    );
  }

  // The explicit form of the rule this whole test exists for.
  assert.ok(
    at('/js/blueteam/blueteam-api.js') < at('/js/blueteam/blueteam-board.js'),
    'blueteam-api.js must load before blueteam-board.js'
  );

  // And the plugin mount last: it needs BlueTeamBoard plus the inline block's
  // currentCourseId/escHtml.
  assert.ok(
    at('/js/blueteam/blueteam-board.js') < html.indexOf('<script src="/cle/js/blue-team.js"></script>'),
    'blue-team.js must load after blueteam-board.js'
  );
});

test('the base URL the mount uses is the route routes/api.js registers', () => {
  const api = read(API_JS);

  // The registered mount path, read out of the router rather than restated.
  const mount = api.match(/router\.use\(\s*'(\/api\/cle\/courses\/:courseId\/incidents)'/);
  assert.ok(mount, 'routes/api.js no longer registers the incidents router at a literal path');

  // ':courseId' is Express's placeholder; '{courseId}' is the mount module's.
  const expected = mount[1].replace(/:courseId/g, '{courseId}');
  assert.strictEqual(expected, '/api/cle/courses/{courseId}/incidents');

  const js = read(MOUNT_JS);
  assert.ok(
    js.includes(`'${expected}'`),
    `blue-team.js must build its base from '${expected}' to match the registered route`
  );

  // EVERY quoted /api/ literal in the file has to be one this test has checked
  // against a route the server actually registers. The rule used to read "one
  // literal, and only one", which was the same rule with only one endpoint to
  // apply it to; the mount now also asks the PLATFORM whether the attack
  // authoring console exists, which is not addressed by course and cannot be
  // built out of the base above.
  //
  // The second entry is pinned the same way as the first — read out of
  // src/routes/caldera-authoring.js rather than restated here — so a mount path
  // that moves fails this test instead of silently 404ing behind a panel whose
  // failure copy reads exactly like "the console is down".
  const statusPath = `${require('../src/routes/caldera-authoring').MOUNT_PATH}/status`;
  assert.strictEqual(statusPath, '/api/caldera-authoring/status');

  const literals = js.match(/'\/api\/[^']*'/g) || [];
  assert.deepStrictEqual(
    [...new Set(literals)].sort(),
    [`'${statusPath}'`, `'${expected}'`].sort(),
    'blue-team.js may contain exactly two /api/ literals: the incidents base and '
    + 'the authoring-console status endpoint. A third is an endpoint nothing has checked.'
  );
});

test('the mount does not reach into the attack console', () => {
  const js = stripComments(read(MOUNT_JS));
  assert.ok(!/attack-console/.test(js), 'blue-team.js must not reference attack-console.js');
  assert.ok(!/CleAttack/.test(js), 'blue-team.js must not use the attack console global');

  // And the console's own wiring is still on the page: this feature was added
  // beside it, not over it.
  const html = read(COURSES_HTML);
  assert.ok(html.includes('<script src="/cle/js/attack-console.js"></script>'),
    'the attack console script tag was removed');
  assert.ok(html.includes("CleAttack.onShow()"), 'the attack console show hook was removed');
});

test('the tab is gated on the blue_team feature the server knows about', () => {
  const html = read(COURSES_HTML);

  // applyCourseFeatures() hides every .detail-tab[data-feature] the course has
  // not switched on, so an un-flagged course simply has no tab.
  assert.ok(
    /<div class="detail-tab" data-feature="blue_team"/.test(html),
    'the Blue Team Board tab must carry data-feature="blue_team" or it shows on every course'
  );
  assert.ok(html.includes("switchDetailTab('blue-team', this)"), 'the tab does not open its pane');
  assert.ok(html.includes('id="blue-team-pane"'),
    'switchDetailTab looks up <tabName>-pane, so the pane id must be blue-team-pane');

  // The flag itself is defined server-side; the page only mirrors it.
  assert.ok(read(FEATURES_JS).includes("key: 'blue_team'"),
    'course-features.js no longer defines the blue_team feature');

  // The mirror the edit modal renders its checkboxes from. Missing here, the
  // key is dropped from cle_course.features on the next save, because
  // routes/courses.js writes the object whole.
  assert.ok(/{ key: 'blue_team',/.test(html),
    'courses.html COURSE_FEATURES must mirror blue_team or saving a course drops the flag');
});

test('the mount hands the board a server-decided tier, not a client role guess', () => {
  const js = stripComments(read(MOUNT_JS));

  // The tier comes off the run-list payload. An instructor is staff on their
  // own course and a student on a colleague's, which Auth.user.role cannot say.
  assert.ok(/data\.tier/.test(js), 'blue-team.js must read the tier the server returned');
  assert.ok(!/Auth\.user/.test(js), 'blue-team.js must not infer the tier from Auth.user.role');

  // The pre-release gate is the server's (projection.js). The client must not
  // rebuild a technique count from the findings it holds.
  assert.ok(!/techniques_total/.test(js),
    'blue-team.js must not touch techniques_total — the count is withheld until release');
});
