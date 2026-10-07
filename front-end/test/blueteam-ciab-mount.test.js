/**
 * blueteam-ciab-mount.test.js — the CiAB half of "the board is pointed at a URL
 * that exists".
 *
 * WHY THIS FILE EXISTS SEPARATELY FROM ITS COVERAGE
 * ----------------------------------------------------------------------------
 * The blue-team board shipped once as four IIFEs, four globals and zero <script>
 * tags: every part individually tested, all of it green, and the feature
 * unreachable in a browser. blueteam-mount.test.js closed that hole for CLE by
 * JOINING the two halves — it reads the mount path out of cle/routes/api.js and
 * compares it to the base URL blue-team.js builds.
 *
 * The CiAB side had no such join. Its two halves were each pinned, but to
 * INDEPENDENT string literals in different test files:
 *
 *   - incident-board-routes.js asserts routes/api.js registers the router at
 *     '/api/engagements/...'                          (the server half)
 *   - ciab-vocabulary.js / blueteam-student-mount.js assert the two UI modules
 *     contain the text '/api/engagements/'            (the client half)
 *
 * Two literals that happen to agree today are not a contract. This file makes
 * the agreement the assertion, and it does so by EXECUTING the URL builders
 * rather than pattern-matching them — a base assembled correctly out of pieces
 * that each look wrong (and vice versa) is exactly the case a substring check
 * cannot see.
 *
 * IT ALSO PINS THE THING THAT MAKES EVERY OTHER PATH TEST MEAN ANYTHING.
 * routes/api.js writes ABSOLUTE paths ('/api/engagements/...'), which is only
 * true because manifest.json mounts that router at '/'. Change that mountPath
 * to '/ciab' and every route test in the repo still passes while every board in
 * both products 404s — and a 404 renders identically to "no incidents yet",
 * which is the failure nobody reports as a bug. Nothing asserted it. Now this
 * does, for both plugins.
 *
 * Run: node --test front-end/test/blueteam-ciab-mount.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const PLUGINS = path.join(ROOT, 'modules', 'crucible', 'plugins');
const CIAB = path.join(PLUGINS, 'ciab');

const CIAB_API_JS = path.join(CIAB, 'routes', 'api.js');
const INSTRUCTOR_JS = path.join(CIAB, 'public', 'js', 'instructor-incidents.js');
const WORKSPACE_JS = path.join(CIAB, 'public', 'js', 'workspace-incident.js');

const read = (p) => fs.readFileSync(p, 'utf8');

/** A recognisable stand-in, so a builder that drops the id fails loudly. */
const SAMPLE_ID = 'eng-1234';

/**
 * The mount path the CiAB router ACTUALLY registers, read out of the source
 * rather than restated here. Restating it would rebuild the very coincidence
 * this file exists to replace.
 */
function registeredCiabIncidentsPath() {
  const api = read(CIAB_API_JS);
  const m = api.match(/router\.use\(\s*'(\/api\/engagements\/:[A-Za-z]+\/incidents)'/);
  assert.ok(m, 'ciab/routes/api.js no longer registers the incidents router at a literal path');
  // ':engagementId' is Express's placeholder. Substituting the sample id gives
  // the concrete URL a browser would have to request to reach this router.
  return m[1].replace(/:[A-Za-z]+/g, SAMPLE_ID);
}

test('E-VERIFY-1: both plugin routers are mounted at "/", which is what makes their paths absolute', () => {
  // Not a style point. Every path literal inside these two routers is written
  // absolute ('/api/...'); that is only correct while the loader mounts them at
  // the root. A non-'/' mountPath silently prefixes all of them.
  for (const key of ['ciab', 'cle']) {
    const manifest = JSON.parse(read(path.join(PLUGINS, key, 'manifest.json')));
    const apiRoute = (manifest.routes || []).find((r) => r.file === 'routes/api.js');
    assert.ok(apiRoute, `${key}/manifest.json no longer declares routes/api.js`);
    assert.strictEqual(
      apiRoute.mountPath, '/',
      `${key}/manifest.json must mount routes/api.js at '/': its route paths are written `
      + `absolute, so any other mountPath prefixes every one of them and the board 404s.`
    );
  }
});

test('E-VERIFY-2: the instructor board base is BUILT to the route CiAB registers', () => {
  const ui = read(INSTRUCTOR_JS);

  // Extract the two builders and RUN them. instructor-incidents.js composes the
  // base out of a pair — scopePath() is the /api-less form its own API.request
  // helper wants, boardBase() is the absolute one BlueTeamApi needs — and a
  // substring check cannot tell a correct composition from a broken one.
  const scopeSrc = ui.match(/const scopePath\s*=\s*([^;]+);/);
  const baseSrc = ui.match(/const boardBase\s*=\s*([^;]+);/);
  assert.ok(scopeSrc, 'instructor-incidents.js no longer defines scopePath');
  assert.ok(baseSrc, 'instructor-incidents.js no longer defines boardBase');

  const scopePath = new Function(`return ${scopeSrc[1]};`)();
  const boardBase = new Function('scopePath', `return ${baseSrc[1]};`)(scopePath);

  assert.strictEqual(
    boardBase(SAMPLE_ID), registeredCiabIncidentsPath(),
    'the URL instructor-incidents.js hands BlueTeamApi is not the one routes/api.js serves'
  );

  // The board is mounted with that absolute form, not the /api-less one:
  // BlueTeamApi speaks raw fetch and prepends nothing.
  assert.ok(
    /base:\s*boardBase\(/.test(ui),
    'the board must be mounted on boardBase() — scopePath() alone omits /api and every call 404s'
  );
});

test('E-VERIFY-3: the student board base is BUILT to the same registered route', () => {
  const ws = read(WORKSPACE_JS);

  // The student page assembles its base by concatenation at the mount site.
  const m = ws.match(/base:\s*('\/api\/engagements\/'[\s\S]*?'\/incidents')/);
  assert.ok(m, 'workspace-incident.js no longer builds the incidents base at its mount site');

  const built = new Function('engagementId', `return ${m[1]};`)(SAMPLE_ID);
  assert.strictEqual(
    built, registeredCiabIncidentsPath(),
    'the URL workspace-incident.js hands BlueTeamApi is not the one routes/api.js serves'
  );
});

test('E-VERIFY-4: both CiAB pages address the SAME collection', () => {
  // One board, two screens, one route. If these ever diverge, an instructor
  // grades findings a student is not submitting into — and both pages look fine
  // in isolation, which is why this is asserted rather than assumed.
  const ui = read(INSTRUCTOR_JS);
  const scopePath = new Function(`return ${ui.match(/const scopePath\s*=\s*([^;]+);/)[1]};`)();
  const boardBase = new Function('scopePath', `return ${ui.match(/const boardBase\s*=\s*([^;]+);/)[1]};`)(scopePath);

  const ws = read(WORKSPACE_JS);
  const studentBase = new Function(
    'engagementId',
    `return ${ws.match(/base:\s*('\/api\/engagements\/'[\s\S]*?'\/incidents')/)[1]};`
  )(SAMPLE_ID);

  assert.strictEqual(boardBase(SAMPLE_ID), studentBase,
    'the instructor and student screens are pointed at different incident collections');
});
