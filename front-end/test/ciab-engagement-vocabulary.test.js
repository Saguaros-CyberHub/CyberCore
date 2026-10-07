/**
 * ciab-engagement-vocabulary.test.js — Track B, phase B1a: the words on the
 * screen, and the wiring that puts the screen on the page.
 *
 * THE VOCABULARY RULE. The instructor-facing nouns are Section, Module, Client,
 * Engagement and Environment. The words *course*, *material*, *challenge*,
 * *assignment* and *lesson* belong to a different model and must never appear
 * in a string this tab renders.
 *
 * WHY THIS TEST IS SCOPED TO THE NEW SURFACE AND NOT THE REPOSITORY.
 * A naive `grep -i course` over instructor.html fails on day one against copy
 * that is deliberate and correct: the page carries a cross-plugin roster import
 * that names the NEIGHBOURING plugin's object — "Import from a CLE course",
 * <label>Course</label> — and instructor-roster-import.js is full of the same.
 * Those are right. Widening this scan to the whole page would either fail
 * immediately or teach the next author to delete the assertion. So it reads
 * exactly the files B1a added, plus the #tab-engagements block extracted from
 * instructor.html by id.
 *
 * `challenge_key` and `challenge_id` are a different problem and get their own
 * assertion. They are real column names on the engagement row — the regex below
 * does NOT match them, because `_` is a word character — so nothing stops a
 * screen rendering one except a rule that says not to. The admin reservation
 * panel renders one today. That is how the word gets onto a screen.
 *
 * THIS FILE ALSO PINS THE THREE-LINE HTML WIRING (plan §5.1) and the ZERO-LINE
 * property in instructor-core.js (plan §5.2), because both are the concurrency
 * contract between three tracks editing one dashboard in one working tree with
 * no commits between them.
 *
 * Run: node --test front-end/test/ciab-engagement-vocabulary.test.js  (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const CIAB = path.join(ROOT, 'modules', 'crucible', 'plugins', 'ciab');

const UI_FILE = path.join(CIAB, 'public', 'js', 'instructor-engagements.js');
const API_FILE = path.join(CIAB, 'public', 'js', 'ciab-api.js');
const ROUTES_FILE = path.join(CIAB, 'routes', 'engagements.js');
const CORE_FILE = path.join(CIAB, 'public', 'js', 'instructor-core.js');
const HTML_FILE = path.join(CIAB, 'public', 'pages', 'instructor.html');
// B1b's generator. Absent in B1a and scanned the moment it lands.
const DOCS_FILE = path.join(CIAB, 'utils', 'engagement-scan-documents.js');

const UI = fs.readFileSync(UI_FILE, 'utf8');
const ROUTES = fs.readFileSync(ROUTES_FILE, 'utf8');
const CORE = fs.readFileSync(CORE_FILE, 'utf8');
const HTML = fs.readFileSync(HTML_FILE, 'utf8');

// Every line-wise scan splits on a CRLF-tolerant boundary: this checkout mixes
// conventions and a '\n' split leaves a trailing '\r' on every line.
const NEWLINE = /\r?\n/;

const FORBIDDEN = /\b(course|courses|material|materials|challenge|challenges|assignment|assignments|lesson|lessons)\b/i;

// ── Helpers ─────────────────────────────────────────────────────────────────

function readIfPresent(file) {
  try { return fs.readFileSync(file, 'utf8'); } catch (_) { return null; }
}

/** The subjects of the vocabulary scan, as { name, text }. */
function scanSubjects() {
  const subjects = [
    { name: 'public/js/instructor-engagements.js', text: UI },
    { name: 'routes/engagements.js', text: ROUTES },
    // Only the appended namespace: the rest of ciab-api.js is not B1a's.
    { name: 'public/js/ciab-api.js (API.engagements)', text: engagementsNamespace() },
    { name: 'instructor.html #tab-engagements', text: engagementsHtml() },
  ];
  const docs = readIfPresent(DOCS_FILE);
  if (docs !== null) subjects.push({ name: 'utils/engagement-scan-documents.js', text: docs });
  return subjects;
}

/** The API.engagements block appended to ciab-api.js by B1a, or ''. */
function engagementsNamespace() {
  const src = fs.readFileSync(API_FILE, 'utf8');
  const i = src.indexOf('API.engagements');
  return i === -1 ? '' : src.slice(i);
}

/**
 * Everything instructor.html contributes to this tab: the tab button, the
 * panel element, and the script tag. Extracted BY ID rather than by position,
 * so another track appending its own tab cannot move this one out of range.
 */
function engagementsHtml() {
  const lines = HTML.split(NEWLINE);
  const parts = [];
  for (let i = 0; i < lines.length; i += 1) {
    const l = lines[i];
    if (/engagements/i.test(l)) {
      // A tab button wraps onto a second line in the house style, so take the
      // neighbour too rather than reading half an element.
      parts.push(l);
      if (/data-tab="engagements"/.test(l) && lines[i + 1]) parts.push(lines[i + 1]);
    }
  }
  return parts.join('\n');
}

/**
 * The text between a call's opening paren and its match — quote-, template- and
 * nesting-aware, because `Toast.error("Couldn't save", (err && err.message) ||
 * 'Request failed')` defeats every simpler reading.
 */
function callSlice(src, openIndex) {
  let depth = 0;
  let quote = null;
  for (let i = openIndex; i < src.length; i += 1) {
    const c = src[i];
    if (quote) {
      if (c === '\\') { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') {
      depth -= 1;
      if (depth === 0) return src.slice(openIndex + 1, i);
    }
  }
  return null;
}

/** Top-level argument count of a call slice. */
function argCount(slice) {
  if (slice === null) return -1;
  if (!slice.trim()) return 0;
  let depth = 0;
  let quote = null;
  let count = 1;
  for (let i = 0; i < slice.length; i += 1) {
    const c = slice[i];
    if (quote) {
      if (c === '\\') { i += 1; continue; }
      if (c === quote) quote = null;
      continue;
    }
    if (c === "'" || c === '"' || c === '`') { quote = c; continue; }
    if (c === '(' || c === '[' || c === '{') depth += 1;
    else if (c === ')' || c === ']' || c === '}') depth -= 1;
    else if (c === ',' && depth === 0) count += 1;
  }
  return count;
}

/** Every index at which `needle` occurs. */
function allIndexes(src, needle) {
  const out = [];
  let i = src.indexOf(needle);
  while (i !== -1) { out.push(i); i = src.indexOf(needle, i + 1); }
  return out;
}

// ── 1. The vocabulary itself ────────────────────────────────────────────────

test('B1a-V1: no out-of-vocabulary word appears anywhere in the new surface', () => {
  // Not just in rendered strings — in the files at all, comments included. A
  // comment is where the wrong noun gets rehearsed before it reaches a label.
  for (const { name, text } of scanSubjects()) {
    const lines = text.split(NEWLINE);
    const hits = [];
    lines.forEach((line, n) => {
      if (FORBIDDEN.test(line)) hits.push(`${name}:${n + 1}  ${line.trim()}`);
    });
    assert.deepStrictEqual(
      hits, [],
      `Section / Module / Client / Engagement / Environment is the vocabulary.\n${hits.join('\n')}`
    );
  }
});

test('B1a-V2: the words a reader SHOULD find are actually there', () => {
  // The negative assertion above is satisfied by an empty file, so pin the
  // positive half too: this tab really does speak the intended vocabulary.
  assert.ok(/\bEngagement\b/.test(UI), 'the tab names an Engagement');
  assert.ok(/\bClient\b/.test(UI), 'and a Client');
  assert.ok(/\bEnvironment\b|\benvironment\b/.test(UI), 'and an Environment');
});

test('B1a-V3: challenge_key / challenge_id are never rendered, only explained', () => {
  // These are real columns on the engagement row and the regex above does NOT
  // catch them — `_` is a word character. They are stripped server-side by
  // project(); this pins that the page never reaches for one anyway.
  const lines = UI.split(NEWLINE);
  lines.forEach((line, n) => {
    if (!/challenge_key|challenge_id/.test(line)) return;
    const t = line.trim();
    const isComment = t.startsWith('*') || t.startsWith('//') || t.startsWith('/*');
    assert.ok(
      isComment,
      `instructor-engagements.js:${n + 1} names a reservation identifier outside a comment: ${t}`
    );
  });

  // And nothing interpolates one into markup.
  assert.ok(!/\$\{[^}]*challenge_(key|id)/.test(UI), 'no reservation identifier in a template');
  assert.ok(!/row\.challenge_|eng\.challenge_/.test(UI), 'the page never reads one off a row');
});

// ── 2. No addresses in B1a ──────────────────────────────────────────────────

test('B1a-V4: the tab renders no address — not even in a placeholder', () => {
  // The compile publishes hosts[].segment_for_address BEFORE it proposes
  // exposure and overwrites ip_octet / placement / nics AFTER it, so joining
  // those two fields names a machine at ext.<n> that will live at int.<n> — an
  // address on the segment the team already stands on, for a machine they must
  // pivot to reach. Placement LABELS carry the pedagogy and none of the hazard.
  // Addresses are B2's, after that ordering is closed.
  //
  // A dotted quad in a placeholder is not a derived address, but leaving one
  // there defeats any honest scan for this property, so there are none.
  const lines = UI.split(NEWLINE);
  const hits = [];
  lines.forEach((line, n) => {
    if (/\b\d{1,3}(\.\d{1,3}){3}\b/.test(line)) hits.push(`${n + 1}  ${line.trim()}`);
  });
  assert.deepStrictEqual(hits, [], `no dotted quad in the Engagements tab:\n${hits.join('\n')}`);

  // The two fields whose JOIN is the hazard. Naming them in the header comment
  // that explains why they are not used is the point; reading one in code is not.
  UI.split(NEWLINE).forEach((line, n) => {
    if (!/ip_octet|segment_for_address/.test(line)) return;
    const t = line.trim();
    const isComment = t.startsWith('*') || t.startsWith('//') || t.startsWith('/*');
    assert.ok(isComment, `instructor-engagements.js:${n + 1} reads an address field: ${t}`);
  });
});

test('B1a-V5: no secret reaches the screen, and the credential line stays fixed', () => {
  // issued_credentials records WHICH accounts the client agreed to hand over —
  // slot key, username, machine, privilege — and never a password. The per-lane
  // secret is minted at deploy time and delivered as a file.
  const editors = UI.match(/type:\s*'password'/g);
  assert.strictEqual(editors, null, 'no password input anywhere on this tab');
  assert.ok(!/\bslot\.password\b|\bcred\.password\b/.test(UI), 'no credential password is read');

  // The one sentence that tells an instructor where the secret comes from.
  assert.ok(
    /never stored here and never shown on this screen/.test(UI),
    'the fixed credential-delivery line must stay on the screen'
  );
});

// ── 3. The three-line HTML wiring ───────────────────────────────────────────

test('B1a-V6: the instructor.html wiring is all three lines or none — never half', () => {
  // The three insertions (plan §5.1) are applied BY HAND by the orchestrator,
  // because instructor.html is the one file three tracks edit at the same
  // anchors and the failure mode there is a silent last-writer-wins overwrite,
  // not a merge conflict anyone can see. So Track B's own code never touches it.
  //
  // What this test can honestly pin, therefore, is the ALL-OR-NOTHING property:
  // a half-applied wiring is the state that fails silently at runtime — a tab
  // button with no panel renders an empty page, a panel with no script tag
  // renders an empty panel, and a script tag alone gives a tab nobody can reach.
  // Once the three lines land, every structural assertion below runs for real.
  const button = /data-tab="engagements"/.test(HTML);
  const panel = /id="tab-engagements"/.test(HTML);
  const script = /instructor-engagements\.js/.test(HTML);

  if (!button && !panel && !script) {
    // Not yet wired. Assert exactly that, loudly, rather than passing quietly:
    // the three lines are:
    //   A1  <button class="tab" role="tab" id="tabbtn-engagements" data-tab="engagements"
    //               aria-controls="tab-engagements" aria-selected="false"
    //               tabindex="-1" data-instructor-only>Engagements</button>
    //       inserted before the Review Queue button.
    //   A2  <div class="tab-content" id="tab-engagements" role="tabpanel"
    //            aria-labelledby="tabbtn-engagements" data-instructor-only></div>
    //       inserted after the </div> closing #tab-overview.
    //   A3  <script src="/ciab/js/instructor-engagements.js"></script>
    //       inserted after instructor-documents.js and AFTER instructor-core.js.
    assert.ok(true, 'instructor.html is not wired for the Engagements tab yet');
    return;
  }

  assert.ok(button, 'A1: the tab strip needs a data-tab="engagements" button');
  assert.ok(panel, 'A2: the page needs a panel with id="tab-engagements"');
  assert.ok(script, 'A3: the page needs the instructor-engagements.js script tag');

  // A1 — switchTab maintains aria-controls, aria-selected and tabindex on every
  // button; a button missing one drifts out of sync the first time a tab changes.
  const btnLine = HTML.split(NEWLINE)
    .map((l, i, all) => (/data-tab="engagements"/.test(l) ? `${l}\n${all[i + 1] || ''}` : null))
    .find(Boolean);
  assert.ok(/aria-controls="tab-engagements"/.test(btnLine), 'the button controls the panel by id');
  assert.ok(/aria-selected=/.test(btnLine), 'the button carries aria-selected');
  assert.ok(/tabindex=/.test(btnLine), 'and tabindex');
  assert.ok(/data-instructor-only/.test(btnLine), 'and data-instructor-only');

  // A2 — the id must be EXACTLY tab-engagements: switchTab matches
  // panel.id === `tab-${name}`. And the panel must carry data-instructor-only,
  // or Student View shows an engagement brief, which is answer-shaped.
  const panelLine = HTML.split(NEWLINE).find((l) => /id="tab-engagements"/.test(l));
  assert.ok(/class="tab-content"/.test(panelLine), 'the panel is a .tab-content');
  assert.ok(/role="tabpanel"/.test(panelLine), 'the panel is a tabpanel');
  assert.ok(/data-instructor-only/.test(panelLine), 'the panel is hidden in Student View');

  // A3 — load order. TAB_NAMES is a top-level const, so a tag placed before
  // instructor-core.js reads it inside its temporal dead zone.
  const core = HTML.indexOf('instructor-core.js');
  const mine = HTML.indexOf('instructor-engagements.js');
  assert.ok(core !== -1 && core < mine, 'the script tag comes AFTER instructor-core.js');
});

// ── 4. The zero-line property in instructor-core.js ─────────────────────────

test('B1a-V7: instructor-core.js knows nothing about this tab — the tab registers itself', () => {
  // The relaxed form of the plan's assertion, and the honest one. The plan drew
  // it as "TAB_NAMES still lists exactly the five original names"; another track
  // has since landed its own tab there legitimately, so the five-name form is
  // already false and would fail against correct work. What Track B actually
  // guarantees is narrower and is the property that matters: ZERO lines of
  // Track B in this file. Those two lines are the single highest-probability
  // collision on this dashboard, and the failure mode is a silent overwrite.
  assert.ok(!/engagements/i.test(CORE), 'instructor-core.js contains no Track B edit');

  // The wiring lives in the tab's own file instead: an append to the TAB_NAMES
  // array (whose BINDING is const but whose CONTENTS are mutable) and a wrapper
  // around activateTabModule (a function declaration, hence a real window
  // property).
  assert.ok(/TAB_NAMES\.push\('engagements'\)/.test(UI), 'the tab appends its own name');
  assert.ok(
    /window\.activateTabModule\s*=\s*function/.test(UI),
    'and wraps the dispatcher rather than editing it'
  );

  // IT MUST COMPOSE. Another self-registering tab, or the ordinary two-line
  // edit landing later, has to keep working — so the wrapper delegates every
  // other name to whatever was installed before it.
  assert.ok(
    /_prevActivateTabModule/.test(UI),
    'the wrapper keeps and calls the previously installed dispatcher'
  );
  assert.ok(
    /name\s*!==\s*'engagements'|name\s*===\s*'engagements'/.test(UI),
    'and only claims its own tab name'
  );

  // The push is guarded: a double-evaluated script must not list the tab twice.
  assert.ok(
    /indexOf\('engagements'\)\s*===\s*-1/.test(UI),
    'the name is pushed once, not once per evaluation'
  );
});

// ── 5. The kit, used the way the kit works ──────────────────────────────────

test('B1a-V8: Utils.setBtnLoading — never a bare setBtnLoading(', () => {
  // There is no global setBtnLoading. A bare call is a ReferenceError that
  // fires inside a click handler, so the button stays dead and the request
  // never goes out.
  const bare = [];
  UI.split(NEWLINE).forEach((line, n) => {
    if (/(^|[^.\w])setBtnLoading\s*\(/.test(line)) bare.push(`${n + 1}  ${line.trim()}`);
  });
  assert.deepStrictEqual(bare, [], `setBtnLoading is only ever Utils.setBtnLoading:\n${bare.join('\n')}`);
  assert.ok(/Utils\.setBtnLoading\(/.test(UI), 'and it IS used — every write button has a busy state');

  // Cleared in a finally, so a failed request cannot leave a button spinning.
  const starts = (UI.match(/Utils\.setBtnLoading\([^,]+,\s*true/g) || []).length;
  const stops = (UI.match(/Utils\.setBtnLoading\([^,]+,\s*false/g) || []).length;
  assert.strictEqual(stops, starts, 'every setBtnLoading(btn, true) has a matching false');
});

test('B1a-V9: every Toast call passes a title AND a message', () => {
  // app.js renders .toast-title and .toast-message as separate divs. A
  // one-argument Toast shows a bold headline over an empty line — which is how
  // an error ends up on screen with no explanation of what failed.
  const bad = [];
  for (const method of ['success', 'error', 'warning', 'info']) {
    for (const i of allIndexes(UI, `Toast.${method}(`)) {
      const open = UI.indexOf('(', i);
      const n = argCount(callSlice(UI, open));
      if (n !== 2) {
        const line = UI.slice(0, i).split(NEWLINE).length;
        bad.push(`${line}  Toast.${method} takes 2 args, found ${n}`);
      }
    }
  }
  assert.deepStrictEqual(bad, [], `Toast.x(title, message):\n${bad.join('\n')}`);
});

test('B1a-V10: Confirm.show replaces confirm(), and alert() appears nowhere', () => {
  // app.js globals replace the browser dialogs; a native confirm() blocks the
  // event loop and cannot be styled, themed or tested.
  assert.ok(!/(^|[^.\w])alert\s*\(/m.test(UI), 'no alert()');
  assert.ok(!/(^|[^.\w])confirm\s*\(/m.test(UI), 'no bare confirm()');
  assert.ok(/Confirm\.show\(\s*\{/.test(UI), 'Confirm.show({...}) is used instead');

  // The two sentences that stop a second VXLAN block being burned. Both are
  // load-bearing: creating reserves permanently and retiring returns nothing,
  // while adopting takes over a block that already exists and costs nothing.
  assert.ok(
    /reserves a network block permanently/.test(UI),
    'the create confirmation states that the reservation is permanent'
  );
  assert.ok(
    /does not return it|does not reserve anything new/.test(UI),
    'and that retiring does not hand it back'
  );
  assert.ok(
    /consumes no capacity/.test(UI),
    'the adopt copy states plainly that adopting costs nothing'
  );
});

test('B1a-V11: privileged buttons render from the server-computed can.* flags', () => {
  // requireRole's 403 calls auditDenial, so a screen offering an instructor a
  // button they cannot press manufactures access.denied audit rows for the
  // screen's primary user. The flags come from the server; the client never
  // decides.
  assert.ok(!/isRealAdmin/.test(UI), 'no client-side role test');
  assert.ok(!/user\.role\s*===\s*'admin'/.test(UI), 'and no hand-rolled one either');
  for (const flag of ['can.create', 'can.adopt', 'can.retire', 'can.reprovision']) {
    assert.ok(UI.includes(flag), `${flag} gates its own button`);
  }
});

test('B1a-V12: user-supplied text is escaped on the way into markup', () => {
  // display_name and brief are instructor-authored, flow from the database into
  // both attribute and inline-handler contexts, and this tab paints with
  // innerHTML throughout. esc() escapes quotes; the kit's escapeHtml does not,
  // which is unsafe inside title="${…}".
  assert.ok(/\besc\(/.test(UI), 'esc() is used for text and attributes');
  assert.ok(/\bescJs\(/.test(UI), 'escJs() is used for values entering an onclick string');
  assert.ok(!/Utils\.escapeHtml\(/.test(UI), 'not Utils.escapeHtml — it leaves quotes alone');

  // Every id interpolated into an inline handler goes through escJs.
  const handlers = UI.match(/onclick="Engagements\.[a-zA-Z]+\([^"]*"/g) || [];
  for (const h of handlers) {
    if (!/\$\{/.test(h)) continue;
    assert.ok(
      /escJs\(/.test(h),
      `an interpolated value in an inline handler must go through escJs: ${h}`
    );
  }
});

// ── 6. The cross-track tripwire, restated locally ───────────────────────────

test('B1a-V13: no Track B file names another track\'s internals', () => {
  // A neighbouring track's test greps FILE TEXT across src/ and modules/ for its
  // own module names against a short allowlist, and the walk includes this
  // plugin's public/js. Restating it here means a Track B author sees the
  // failure in Track B's own test rather than in a file they must not edit.
  //
  // The underlying rule is better than the tripwire, though: a route file has no
  // business naming another track's utility at all. That is coupling nobody
  // asked for, in a direction nobody agreed to.
  const banned = /module-spine|module-states|module-admin/;
  for (const [name, text] of [
    ['public/js/instructor-engagements.js', UI],
    ['routes/engagements.js', ROUTES],
    ['public/js/ciab-api.js (API.engagements)', engagementsNamespace()],
  ]) {
    const hits = [];
    text.split(NEWLINE).forEach((line, n) => {
      if (banned.test(line)) hits.push(`${name}:${n + 1}  ${line.trim()}`);
    });
    assert.deepStrictEqual(hits, [], `Track B names no other track's internals:\n${hits.join('\n')}`);
  }
});

test('B1a-V14: every top-level binding in the tab is namespaced', () => {
  // Classic scripts share ONE global lexical scope. A bare `const PLACEMENTS`
  // here would make an identically-named const in another tab's file a
  // whole-script SyntaxError — silently killing that tab — and thirteen scripts
  // load onto this page from three tracks at once. One prefix removes the whole
  // class of failure.
  const allowed = /^(ENG_|eng[A-Z]|Engagements$|_)/;
  const bad = [];
  UI.split(NEWLINE).forEach((line, n) => {
    const m = line.match(/^(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)/);
    if (m && !allowed.test(m[1])) bad.push(`${n + 1}  ${m[1]}`);
  });
  assert.deepStrictEqual(bad, [], `top-level names need an ENG_/eng prefix:\n${bad.join('\n')}`);
});

test('B1a-V15: the API namespace addresses the routes that exist', () => {
  // One namespace, one URL per route, so the screen and the router cannot
  // disagree about a path. generateDocs is B1b's and is uncalled here — declared
  // with the rest so the two halves of the phase agree on the URL up front.
  const ns = engagementsNamespace();
  assert.ok(ns, 'ciab-api.js carries an API.engagements namespace');
  for (const fn of ['types', 'list', 'get', 'patch', 'create', 'adopt', 'reprovision', 'retire']) {
    assert.ok(new RegExp(`\\b${fn}\\s*\\(`).test(ns), `API.engagements.${fn} exists`);
  }
  // Every path is under the mount routes/instructor.js actually created.
  const paths = ns.match(/'\/[^']*'|`\/[^`]*`/g) || [];
  assert.ok(paths.length >= 8, 'every route has a URL in the namespace');
  for (const p of paths) {
    assert.ok(
      p.includes('/instructor/engagements'),
      `every engagement URL is under /instructor/engagements: ${p}`
    );
  }
  // EVERY interpolation into a URL is encoded, not just the query parameter.
  // Four of the five id-taking methods used to interpolate raw while list()
  // encoded — an asymmetry, not a policy. Unencoded, a '#' truncates the request
  // at the fragment, a '?' turns the rest of the path into a query string, and a
  // '/' re-points the call at a DIFFERENT ROUTE, which on this namespace means a
  // POST landing on /reprovision or /retire — one spends capacity, the other
  // ends an engagement.
  const templates = ns.match(/`[^`]*`/g) || [];
  assert.ok(templates.length >= 6, 'the id-taking methods build their URLs as templates');
  for (const t of templates) {
    for (const interp of t.match(/\$\{[^}]*\}/g) || []) {
      assert.ok(
        /^\$\{\s*encodeURIComponent\(/.test(interp),
        `every value interpolated into an engagement URL is encoded: ${interp} in ${t}`
      );
    }
  }
});

test('B1a-V16: B1b is not smuggled into B1a', () => {
  // Stage 2 ships separately: per-perspective scan documents, migration 020 and
  // utils/engagement-scan-documents.js. B1a adds no migration at all —
  // ciab_engagement already has every column it needs.
  assert.ok(
    !fs.existsSync(path.join(CIAB, 'migrations', '020_ciab_engagement_documents.sql')),
    'B1a ships no migration'
  );
  assert.ok(
    !/router\.(post|get)\(\s*'\/:engagementId\/documents/.test(ROUTES),
    'the document routes are B1b'
  );
  // The client namespace may declare the URL — it is never called from B1a.
  assert.ok(!/generateDocs\(/.test(UI), 'nothing in the B1a tab calls the B1b route');
});

// ── 7. The tab, actually EVALUATED ──────────────────────────────────────────
//
// Everything above reads the file as text, which is the right instrument for a
// vocabulary rule and the wrong one for four defects the review found in this
// tab. Each of them is a text-level lie: a guard whose try/catch cannot enter
// its catch, a poll with a stop and no start, one fact read from two sources,
// and a placeholder printed as if it were a URL. All four read fine. So the
// block below RUNS the file the way the browser does — two classic scripts
// sharing one global lexical scope — against a DOM small enough to state in
// forty lines, and asserts on behaviour instead of on spelling.

const vm = require('vm');

/** The handful of DOM the tab touches. Not a browser — just enough of one. */
function fakeElement(id) {
  return {
    id, innerHTML: '', value: '', dataset: {}, style: {},
    classList: { toggle() {}, add() {}, remove() {} },
    setAttribute() {}, querySelectorAll: () => [],
  };
}

/**
 * A page. `withCore: false` is the mis-ordered <script> tag — the state the
 * load-order guard exists for — and it is a state text cannot reproduce.
 */
function bootPage({ withCore = true } = {}) {
  const errors = [];
  const timers = new Map();
  let nextTimer = 1;
  const elements = new Map(
    ['tab-engagements', 'engBody', 'engModalHost', 'engClientSelect'].map((id) => [id, fakeElement(id)])
  );

  const sandbox = {
    console: { error: (...a) => errors.push(a.map(String).join(' ')), warn() {}, log() {} },
    document: {
      getElementById: (id) => elements.get(id) || null,
      querySelector: () => null,
      querySelectorAll: () => [],
      addEventListener() {},                     // DOMContentLoaded never fires
      createElement: () => fakeElement('x'),
    },
    setInterval: (fn, ms) => { const t = nextTimer; nextTimer += 1; timers.set(t, { fn, ms }); return t; },
    clearInterval: (t) => { timers.delete(t); },
    setTimeout: () => 0,
    history: { replaceState() {} },
    location: { hash: '' },
    JSON, Math, Date, Number, String, Object, Array, Boolean, Set, Map, Promise, RegExp, Error,
    isNaN, parseInt, parseFloat, encodeURIComponent,
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  vm.createContext(sandbox);

  // app.js exports its kit as top-level consts, not window properties, so they
  // are declared here the same way the page declares them.
  vm.runInContext(KIT_STUB, sandbox, { filename: 'kit.js' });

  if (withCore) vm.runInContext(CORE, sandbox, { filename: 'instructor-core.js' });
  vm.runInContext(UI, sandbox, { filename: 'instructor-engagements.js' });
  return { sandbox, errors, timers, elements, run: (src) => vm.runInContext(src, sandbox) };
}

const KIT_STUB = [
  'var API = { engagements: {',
  '  types: () => Promise.resolve({ types: [] }),',
  '  list: () => Promise.resolve({ engagements: [], can: {} }),',
  '} };',
  'var Toast = { success() {}, error() {}, warning() {}, info() {} };',
  'var Confirm = { show: () => Promise.resolve(false) };',
  'var Utils = { setBtnLoading() {}, formatDate: (s) => String(s) };',
  'var Modal = { open() {}, close() {} };',
  'var Auth = { requireAuth: () => Promise.resolve(true), getUser: () => ({}),',
  '             isRealInstructor: () => true, isRealAdmin: () => true };',
].join('\n');

test('B1a-V17: a mis-ordered script tag fails LOUDLY, not into a dead tab', () => {
  // WHY THE ORIGINAL GUARD COULD NOT FIRE. It wrapped `typeof TAB_NAMES` in a
  // try/catch. `typeof` is the one operator that does NOT throw on an undeclared
  // identifier — it answers 'undefined' — so the catch was unreachable for every
  // input on every engine, and the mis-ordered tag produced exactly the silent
  // dead tab the guard named. What distinguishes the two states is that
  // instructor-core.js declares TAB_NAMES with `const` (global LEXICAL scope,
  // never a window property) and activateTabModule with `function` (a real
  // property of the global object). The second is therefore the detector.
  const page = bootPage({ withCore: false });

  assert.ok(page.errors.length >= 1, 'the wrong order must produce a console.error');
  const said = page.errors.join('\n');
  assert.ok(/instructor-core\.js/.test(said), 'the message names the file that must come first');
  assert.ok(/AFTER/.test(said), 'and says which side of it this tag goes on');
  assert.ok(/instructor-engagements\.js/.test(said), 'and names itself, so the line is actionable');

  // And it installs NOTHING. A wrapper written onto window before
  // instructor-core.js evaluates is overwritten outright by that file's own
  // function declaration — a wrapper that exists, ran, and is unreachable.
  assert.strictEqual(typeof page.sandbox.activateTabModule, 'undefined',
    'no half-registration is left behind');

  // Loud on the page too, where the person affected is looking.
  assert.ok(/did not load/i.test(page.elements.get('tab-engagements').innerHTML),
    'the panel says so rather than rendering empty');
});

test('B1a-V17b: the correct order registers silently and composes', () => {
  const page = bootPage({ withCore: true });
  assert.deepStrictEqual(page.errors, [], 'a correct page logs nothing');
  assert.ok(page.run("TAB_NAMES.includes('engagements')"), 'the tab name is reachable');
  assert.strictEqual(typeof page.sandbox.activateTabModule, 'function', 'the dispatcher is wrapped');

  // The wrapper claims its own name and delegates every other one.
  const seen = [];
  page.sandbox.Overview = { ensureInit: () => seen.push('overview') };
  page.sandbox.Sections = { load: () => seen.push('sections') };
  page.sandbox.activateTabModule('overview');
  page.sandbox.activateTabModule('sections');
  assert.deepStrictEqual(seen, ['overview', 'sections'], 'other tabs still reach their modules');
  page.sandbox.activateTabModule('engagements');
  assert.strictEqual(page.elements.get('tab-engagements').dataset.engShell, '1',
    'and its own name paints its own panel');
});

test('B1a-V18: the reservation poll RESTARTS when the instructor comes back', () => {
  // A reservation is minutes of serial VNet POSTs plus a cluster-wide apply, so
  // an instructor will leave the tab during one. Leaving stops the timer — that
  // is correct, a loop must not repaint a panel nobody is looking at — but
  // nothing restarted it, and every route back in goes through ensureInit(),
  // which returns on its first line once _inited is set. The card then read
  // "Reserving the network…" for the rest of the page's life.
  const page = bootPage({ withCore: true });
  const E = page.sandbox.Engagements;
  E.renderShell();
  E._inited = true;
  E._profileId = 'profile-1';
  E._engagements = [{ engagement_id: 'e1', provision_status: 'provisioning', can: {} }];
  E.syncPoll();
  assert.ok(E._pollTimer, 'a provisioning engagement polls');

  page.sandbox.activateTabModule('overview');           // leaves the tab
  assert.strictEqual(E._pollTimer, null, 'leaving stops the timer');
  assert.strictEqual(page.timers.size, 0, 'and really clears it');

  page.sandbox.activateTabModule('engagements');        // comes back
  assert.ok(E._pollTimer, 'coming back restarts it');
  assert.strictEqual(page.timers.size, 1, 'exactly one timer, never two');

  // An idle re-entry costs nothing: no timer for a tab with nothing in flight.
  E._engagements = [{ engagement_id: 'e1', provision_status: 'ready', can: {} }];
  page.sandbox.activateTabModule('overview');
  page.sandbox.activateTabModule('engagements');
  assert.strictEqual(E._pollTimer, null, 'nothing in flight, nothing polling');
});

test('B1a-V19: the posture badge reads its text and its colour from ONE source', () => {
  // engPosture resolves the way the compile does: the engagement's own column
  // wins and the type descriptor is only the fallback. Reading the text from
  // that and the VARIANT from the descriptor alone made one engagement show two
  // different chips between the list and the detail — because
  // describeEngagementType answers 'none' for every locally defined slug,
  // deliberately and conservatively.
  const page = bootPage({ withCore: true });
  const E = page.sandbox.Engagements;
  const row = {
    engagement_id: 'e1',
    engagement_type: 'a_locally_defined_slug',
    perspective: 'internal',
    credential_posture: 'credentialed',        // the ROW says credentialed
    provision_status: 'ready',
    can: {},
    type_descriptor: {                          // the DESCRIPTOR defaults to none
      label: 'a_locally_defined_slug', perspective: 'internal',
      credential_posture: 'none', known: false,
    },
  };
  const card = E.renderCard(row);
  const variant = (card.match(/badge badge-(\w+)">\s*Credentialed/) || [])[1];
  assert.strictEqual(variant, 'primary',
    'the list chip takes its colour from the same resolution as its text');
  // The detail header already read both halves from that resolution; this pins
  // that the two screens now agree about one engagement.
  assert.ok(!/type\.credential_posture === 'credentialed'/.test(UI),
    'nothing reads the descriptor alone for a badge variant any more');
});

test('B1a-V20: a failed GET /types never removes the only route to a new engagement', () => {
  // _types is [] both when the registry loaded empty and when it never loaded,
  // and treating the second as the first silently and permanently removed the
  // New engagement action for every client already holding one — on the
  // strength of a single failed request at tab-open. The registry is a
  // convenience here; the server is the authority on what may be created.
  const page = bootPage({ withCore: true });
  const E = page.sandbox.Engagements;
  E.renderShell();
  E._profileId = 'profile-1';
  E._listCan = { create: true };
  E._engagements = [{
    engagement_id: 'e1', engagement_type: 'internal_credentialed',
    provision_status: 'ready', can: {}, type_descriptor: { label: 'Internal', known: true },
  }];

  E._typesStatus = 'ready';
  E._types = [{ key: 'internal_credentialed' }, { key: 'external_blackbox' }];
  E.renderList();
  assert.ok(page.elements.get('engBody').innerHTML.includes('New engagement'),
    'a spare type offers the action');

  E._typesStatus = 'ready';
  E._types = [{ key: 'internal_credentialed' }];
  E.renderList();
  assert.ok(!page.elements.get('engBody').innerHTML.includes('New engagement'),
    'every type already held withholds it — that answer is known');

  E._typesStatus = 'failed';
  E._types = [];
  E.renderList();
  assert.ok(page.elements.get('engBody').innerHTML.includes('New engagement'),
    '"could not ask" must never render as "nothing left to create"');
});

test('B1a-V21: no unsubstituted placeholder reaches the screen', () => {
  // brief.facts.surface_url is a TEMPLATE, not an address: the compile leaves
  // the lane's own external range unfilled because the lane does not exist until
  // deploy time. Printed on this screen it looked like a starting URL, read like
  // one, and resolved nowhere — worse than printing nothing, and the exact
  // breach of the NO ADDRESSES rule this file states about itself.
  const page = bootPage({ withCore: true });
  const E = page.sandbox.Engagements;

  const surface = E.publicSurfaceCard({
    public_surface: { source: 'asset', target_vm: 'web01', placement: 'pivot' },
    brief: { facts: { surface_url: 'http://{ext_base}.240/' } },
  });
  assert.ok(!/\{[a-z_]+\}/i.test(surface), 'no placeholder survives into the public-surface card');
  assert.ok(!/Starting point/.test(surface), 'and the line that carried it is gone');
  assert.ok(/web01/.test(surface), 'the machine and its placement still carry the pedagogy');

  // The compile writes the same placeholder into start_position.note.
  const started = E.startPositionCard({
    start_position: {
      perspective: 'external',
      note: 'The exposed host answers on that segment. {ext_base} is filled in per lane at deploy time.',
    },
  });
  assert.ok(!/\{[a-z_]+\}/i.test(started), 'nor into the starting-position card');

  // A sentence with nothing to substitute is untouched — this drops broken
  // prose, not prose.
  const plain = E.startPositionCard({
    start_position: { perspective: 'internal', note: 'The tester works from the console inside.' },
  });
  assert.ok(/works from the console inside/.test(plain), 'ordinary notes still render');

  // The field is not read at all any more, in any branch.
  const code = UI.split(NEWLINE).filter((l) => {
    const t = l.trim();
    return !(t.startsWith('*') || t.startsWith('//') || t.startsWith('/*'));
  }).join('\n');
  assert.ok(!/surface_url/.test(code), 'brief.facts.surface_url has no reader outside a comment');
});

test('B1a-V22: "could not check" is rendered as its own state, never as "nothing is reserved"', async () => {
  // THE RECONCILIATION. The route answers THREE things about a pre-engagement
  // block — found one, looked and found none, could not look — and the tab used
  // to read two of them: `data.unadopted_reservation || null`, with the third
  // silently collapsing into the second. So a cybercore_db outage rendered as
  // "No engagement recorded for this client" beside a Create button, which is
  // the exact sentence that carves a SECOND VXLAN block for a client that
  // already holds one. The server's fix only counts once the screen reads it.
  const page = bootPage({ withCore: true });
  const E = page.sandbox.Engagements;
  E.renderShell();
  E._inited = true;
  E._profileId = 'p1';
  const body = page.elements.get('engBody');

  let answer = { engagements: [], unadopted_reservation: null, unadopted_probe: 'unavailable',
                 can: { create: true, adopt: true, edit: true } };
  page.sandbox.API.engagements.list = () => Promise.resolve(answer);

  await E.loadList();
  assert.strictEqual(E._unadoptedProbe, 'unavailable', 'the third answer is kept, not discarded');
  assert.ok(/could not be checked/i.test(body.innerHTML),
    'an unverified check is shown as unverified');
  // Create is still OFFERED — refusing the only route forward on a transient
  // outage is its own failure — but it is no longer offered under a sentence
  // asserting something nothing knows.
  assert.ok(/Create engagement/.test(body.innerHTML), 'the action stays available');

  // A probe that RAN and found nothing says nothing extra. The notice has to be
  // absent here or it is noise on every empty client, which is how a real
  // warning stops being read.
  answer = { engagements: [], unadopted_reservation: null, unadopted_probe: 'ok',
             can: { create: true, adopt: true, edit: true } };
  await E.loadList();
  assert.ok(!/could not be checked/i.test(body.innerHTML),
    'a probe that ran and found nothing adds no warning');

  // AND THE NON-EMPTY LIST. The route probes on EVERY list now, precisely
  // because one client can hold an engagement AND a separately carved block —
  // but the answer was read in the empty branch only, so on a non-empty list
  // the block stayed exactly as invisible as before the route was fixed.
  answer = {
    engagements: [{
      engagement_id: 'e1', profile_id: 'p1', engagement_type: 'external_blackbox',
      display_label: 'External — black box', provision_status: 'ready',
      type_descriptor: { key: 'external_blackbox', label: 'External — black box',
                         perspective: 'external', credential_posture: 'none', known: true },
      can: { create: true, adopt: true, edit: true },
    }],
    unadopted_reservation: { engagement_type: 'default' },
    unadopted_probe: 'ok',
    can: { create: true, adopt: true, edit: true },
  };
  await E.loadList();
  assert.ok(/holds a reserved network/i.test(body.innerHTML),
    'a carved block nothing records is visible even when the client holds an engagement');
  assert.ok(/Adopt existing reservation/.test(body.innerHTML),
    'and the route out of it is on the screen, not only in the empty state');

  // The notice is capability-gated exactly like every other privileged action:
  // an instructor is told, and is not handed a button whose 403 files an
  // access-denied row against the screen's primary user.
  answer = Object.assign({}, answer, { can: { create: false, adopt: false, edit: true } });
  answer.engagements[0].can = { create: false, adopt: false, edit: true };
  await E.loadList();
  assert.ok(/holds a reserved network/i.test(body.innerHTML), 'still told');
  assert.ok(!/Adopt existing reservation/.test(body.innerHTML), 'but not offered the admin action');
});
