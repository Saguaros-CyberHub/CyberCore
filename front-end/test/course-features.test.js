/**
 * course-features.test.js — which tabs a course shows.
 *
 * Before cle_course.features existed, the course detail page rendered all six
 * tabs for every course: CYBR 480 got an Attack Console that can only ever say
 * "No active lanes found", and every non-CYBR-400 course got the same.
 *
 * The failure mode this file exists to pin is subtler than a missing tab. The
 * defaulting rule is written TWICE — once here in JS, once in SQL in
 * migrations/007_cle_course_features.sql — and 007 re-runs on every boot. If
 * the two disagree, or if a stored value ever loses to a default, a course's
 * tabs depend on whether the backfill has reached its row yet, and an
 * instructor who switched Flags off watches them come back at the next
 * restart. Most of what follows is that one property from several angles.
 *
 * resolveFeatures()/sanitizeFeaturesInput() are pure over a plain row object,
 * so this runs with no database.
 *
 * Run: node front-end/test/course-features.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

const {
  COURSE_FEATURES,
  OPTIONAL_KEYS,
  normalizeCode,
  resolveFeatures,
  attachFeatures,
  sanitizeFeaturesInput,
  defaultFeaturesForCode,
  isFeatureEnabled,
} = require(path.join(
  __dirname, '..', 'modules', 'crucible', 'plugins', 'cle', 'utils', 'course-features.js'
));

// ---------------------------------------------------------------------------
// Defaults, for a course that has never been configured (features IS NULL)
// ---------------------------------------------------------------------------

test('CYBR 480 defaults to Flags only', () => {
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: null }),
    { flags: true, attack_console: false }
  );
});

test('CYBR 400 defaults to Attack Console only', () => {
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-400-1', features: null }),
    { flags: false, attack_console: true }
  );
});

test('an unrelated course defaults to neither', () => {
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CD101-01', features: null }),
    { flags: false, attack_console: false }
  );
});

test('a missing or absent code is not a crash and enables nothing', () => {
  for (const code of [null, undefined, '']) {
    assert.deepStrictEqual(
      resolveFeatures({ code, features: null }),
      { flags: false, attack_console: false },
      `code=${JSON.stringify(code)}`
    );
  }
  assert.deepStrictEqual(resolveFeatures({}), { flags: false, attack_console: false });
  assert.deepStrictEqual(resolveFeatures(null), { flags: false, attack_console: false });
});

test('code matching ignores punctuation and case, like the SQL backfill', () => {
  // migrations/007 strips [^a-zA-Z0-9] before its ILIKE for exactly this reason.
  for (const code of ['CYBR-480-7W1-1', 'CYBR480', 'cybr 480 section 2', 'Cybr-480']) {
    assert.strictEqual(resolveFeatures({ code, features: null }).flags, true, code);
  }
  // A prefix match, not a substring match: 480 has to start the code.
  assert.strictEqual(resolveFeatures({ code: 'ADV-CYBR-480', features: null }).flags, false);
});

test('normalizeCode strips punctuation and upcases', () => {
  assert.strictEqual(normalizeCode('CYBR-480-7W1-1'), 'CYBR4807W11');
  assert.strictEqual(normalizeCode('cybr 400'), 'CYBR400');
  assert.strictEqual(normalizeCode(null), '');
});

// ---------------------------------------------------------------------------
// Stored values beat defaults — the property that keeps 007's every-boot
// re-run from resurrecting a feature an instructor turned off.
// ---------------------------------------------------------------------------

test('an explicit false on a CYBR 480 course overrides the code default', () => {
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: { flags: false } }),
    { flags: false, attack_console: false }
  );
});

test('an explicit true on a course the code would not match is honoured', () => {
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CD101-01', features: { attack_console: true } }),
    { flags: false, attack_console: true }
  );
});

test('a partially configured row defaults only the keys it does not carry', () => {
  // Resolution is per key, so {} behaves exactly like NULL. This is what makes
  // a feature added in a later release land on existing courses with the
  // default it was designed to have instead of being forced off for everyone.
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: {} }),
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: null })
  );
  // Only attack_console is stored, so flags still falls back to the code.
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: { attack_console: true } }),
    { flags: true, attack_console: true }
  );
  // The UI never actually stores a partial row: readFeatureCheckboxes() sends
  // every key, so an unchecked box arrives as an explicit false.
  assert.deepStrictEqual(
    resolveFeatures({ code: 'CYBR-480-7W1-1', features: { flags: false, attack_console: false } }),
    { flags: false, attack_console: false }
  );
});

test('only strict true counts as enabled', () => {
  // A jsonb column can hold anything; nothing truthy-but-not-true opens a tab.
  for (const v of [1, 'true', 'yes', {}, []]) {
    assert.strictEqual(
      resolveFeatures({ code: 'CD101', features: { flags: v } }).flags,
      false,
      JSON.stringify(v)
    );
  }
});

test('resolveFeatures always returns every optional key as a boolean', () => {
  const out = resolveFeatures({ code: 'CD101', features: null });
  assert.deepStrictEqual(Object.keys(out).sort(), [...OPTIONAL_KEYS].sort());
  for (const k of OPTIONAL_KEYS) assert.strictEqual(typeof out[k], 'boolean', k);
});

// ---------------------------------------------------------------------------
// Input sanitising — what a browser is allowed to write
// ---------------------------------------------------------------------------

test('sanitize keeps known optional keys and coerces them to real booleans', () => {
  assert.deepStrictEqual(sanitizeFeaturesInput({ flags: true, attack_console: false }),
    { flags: true, attack_console: false });
  // 'yes' is not true. An unchecked box must never arrive as enabled.
  assert.deepStrictEqual(sanitizeFeaturesInput({ flags: 'yes' }), { flags: false });
});

test('sanitize drops unknown keys and non-optional tabs', () => {
  // A browser cannot invent a feature, nor switch off a mandatory tab.
  assert.deepStrictEqual(
    sanitizeFeaturesInput({ flags: true, students: false, overview: false, bogus: 1 }),
    { flags: true }
  );
});

test('sanitize returns null for anything unusable, so COALESCE means unchanged', () => {
  for (const v of [undefined, null, {}, [], 'flags', 42, true]) {
    assert.strictEqual(sanitizeFeaturesInput(v), null, JSON.stringify(v) || String(v));
  }
});

// ---------------------------------------------------------------------------
// Convenience wrappers used by the routes
// ---------------------------------------------------------------------------

test('defaultFeaturesForCode matches what the migration backfills', () => {
  assert.deepStrictEqual(defaultFeaturesForCode('CYBR-480-7W1-1'),
    { flags: true, attack_console: false });
  assert.deepStrictEqual(defaultFeaturesForCode('CYBR-400-1'),
    { flags: false, attack_console: true });
  assert.deepStrictEqual(defaultFeaturesForCode(null),
    { flags: false, attack_console: false });
});

test('isFeatureEnabled is the gate the routes use', () => {
  const cybr480 = { code: 'CYBR-480-7W1-1', features: null };
  assert.strictEqual(isFeatureEnabled(cybr480, 'flags'), true);
  assert.strictEqual(isFeatureEnabled(cybr480, 'attack_console'), false);
  // An unknown key is off, not undefined — the gate must fail closed.
  assert.strictEqual(isFeatureEnabled(cybr480, 'no_such_feature'), false);
});

test('attachFeatures replaces the raw column in place, on every row', () => {
  const rows = [
    { course_id: 'a', code: 'CYBR-480-1', features: null },
    { course_id: 'b', code: 'CYBR-400-1', features: { attack_console: false } },
  ];
  attachFeatures(rows);
  assert.deepStrictEqual(rows[0].features, { flags: true, attack_console: false });
  assert.deepStrictEqual(rows[1].features, { flags: false, attack_console: false });
  assert.doesNotThrow(() => attachFeatures(undefined));
});

// ---------------------------------------------------------------------------
// Registry shape
// ---------------------------------------------------------------------------

test('every optional feature carries a defaultFor, every mandatory one does not', () => {
  // A new optional entry with no defaultFor would silently default to off for
  // every existing course, which is a decision worth making on purpose.
  for (const f of COURSE_FEATURES) {
    assert.strictEqual(typeof f.key, 'string', 'key');
    assert.strictEqual(typeof f.label, 'string', f.key);
    if (f.optional) assert.strictEqual(typeof f.defaultFor, 'function', `${f.key} needs defaultFor`);
    else assert.strictEqual(f.defaultFor, undefined, `${f.key} is mandatory and must not default`);
  }
  assert.deepStrictEqual(OPTIONAL_KEYS, ['flags', 'attack_console']);
});

test('feature keys are unique', () => {
  const keys = COURSE_FEATURES.map(f => f.key);
  assert.strictEqual(new Set(keys).size, keys.length);
});
