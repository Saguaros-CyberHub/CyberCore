/**
 * loggen-catalog.test.js — the transcription has to stay faithful.
 *
 * cle/utils/loggen-catalog.js is hand-copied from log-generator's
 * src/utils/mitreMapper.ts and src/chains/templates/*.yaml, because upstream's
 * `mitre-list` has no --json and there is nothing to fetch. A transcription
 * rots silently: a mistyped technique id still renders in the picker, still
 * passes the anchored regex, and only fails on a student's lane at class time
 * as a run that generates nothing.
 *
 * These are the invariants that would have caught the mistakes actually made
 * while writing it — two of the three chains' technique lists were wrong on the
 * first pass, invented rather than read out of the YAML.
 *
 * Run: node front-end/test/loggen-catalog.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const path = require('path');

// E1 moved the catalog to src/incident/catalog.js and left a re-export shim at
// the old cle/utils/loggen-catalog.js path; E2 deleted the shim.
const catalog = require(path.join(__dirname, '..', 'src', 'incident', 'catalog.js'));

test('technique and tactic ids match the validators upstream applies', () => {
  for (const t of catalog.TECHNIQUES) {
    assert.ok(catalog.TECHNIQUE_RE.test(t.id), `${t.id} is not a valid technique id`);
  }
  for (const t of catalog.TACTICS) {
    assert.ok(catalog.TACTIC_RE.test(t.id), `${t.id} is not a valid tactic id`);
  }
});

test('every technique names a tactic the catalog actually declares', () => {
  const tactics = new Set(catalog.TACTICS.map((t) => t.id));
  for (const t of catalog.TECHNIQUES) {
    assert.ok(tactics.has(t.tactic), `${t.id} references unknown tactic ${t.tactic}`);
  }
});

test('ids are unique', () => {
  const tIds = catalog.TECHNIQUES.map((t) => t.id);
  assert.strictEqual(new Set(tIds).size, tIds.length, 'duplicate technique id');
  const taIds = catalog.TACTICS.map((t) => t.id);
  assert.strictEqual(new Set(taIds).size, taIds.length, 'duplicate tactic id');
  const cKeys = catalog.CHAINS.map((c) => c.key);
  assert.strictEqual(new Set(cKeys).size, cKeys.length, 'duplicate chain key');
});

test('the catalog covers exactly what mitreMapper.ts supports', () => {
  // 16 TECHNIQUE_PATTERNS entries collapse to 15 unique techniques (brute_force
  // and account_lockout both map to T1110), and there are 14 tactics. If
  // upstream is re-pinned and these counts move, this file must be re-read
  // rather than the assertion relaxed.
  assert.strictEqual(catalog.TECHNIQUES.length, 15);
  assert.strictEqual(catalog.TACTICS.length, 14);
});

test('the three shipped chains are present, by key', () => {
  assert.deepStrictEqual(
    catalog.CHAINS.map((c) => c.key).sort(),
    ['apt29-cozy-bear', 'insider-threat-data-theft', 'ransomware-ryuk']
  );
});

test('chain technique lists match src/chains/templates/*.yaml', () => {
  // Read out of the YAML mitre_mapping blocks, not from memory. The first
  // version of this catalog invented plausible-but-wrong lists for two of the
  // three, which is exactly the failure this pins down.
  const expected = {
    'apt29-cozy-bear': ['T1566.001', 'T1059.001', 'T1547.001', 'T1055', 'T1070.004',
                        'T1003.001', 'T1082', 'T1005', 'T1041', 'T1071.001'],
    'ransomware-ryuk': ['T1566.001', 'T1059.003', 'T1547.001', 'T1562.001',
                        'T1003.001', 'T1018', 'T1021.001', 'T1486'],
    'insider-threat-data-theft': ['T1005', 'T1039', 'T1213', 'T1020', 'T1070.004', 'T1083'],
  };
  for (const chain of catalog.CHAINS) {
    assert.deepStrictEqual(chain.techniques, expected[chain.key], `${chain.key} technique list drifted`);
  }
});

test('chain metadata carries the estimated duration the template declares', () => {
  const minutes = { 'apt29-cozy-bear': 45, 'ransomware-ryuk': 30, 'insider-threat-data-theft': 25 };
  for (const c of catalog.CHAINS) {
    assert.strictEqual(c.estimated_minutes, minutes[c.key], `${c.key} duration drifted`);
  }
});

test('the pinned upstream ref is a full commit sha', () => {
  assert.match(catalog.LOGGEN_REF, /^[0-9a-f]{40}$/, 'LOGGEN_REF must pin a commit, not a branch');
  assert.ok(catalog.CATALOG_VERSION && catalog.CATALOG_VERSION !== 'unknown');
});

test('formatDuration emits what upstream parseDuration accepts', () => {
  // /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/ — h then m then s, zero components
  // omitted, and a total of zero is rejected by upstream as invalid.
  const UPSTREAM = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/;
  assert.strictEqual(catalog.formatDuration(1800), '30m');
  assert.strictEqual(catalog.formatDuration(3600), '1h');
  assert.strictEqual(catalog.formatDuration(9000), '2h30m');
  assert.strictEqual(catalog.formatDuration(45), '45s');
  assert.strictEqual(catalog.formatDuration(90), '1m30s');
  for (const s of [30, 45, 90, 300, 1800, 3600, 7200, 9000, 28800]) {
    const out = catalog.formatDuration(s);
    assert.match(out, UPSTREAM, `${s}s formatted as ${out}, which upstream would reject`);
    assert.ok(out.length > 0);
  }
});

test('formatDuration refuses input that would produce a never-ending run', () => {
  // Upstream returns null for a zero total and the CLI then exits, but a
  // non-integer reaching the shell would be far worse: the wrapper would run
  // `--duration NaN` and log-generator would never stop on its own.
  for (const bad of [0, -60, 1.5, null, undefined, 'abc', NaN]) {
    assert.throws(() => catalog.formatDuration(bad), `expected ${JSON.stringify(bad)} to throw`);
  }
});

test('lookups miss cleanly rather than returning something plausible', () => {
  assert.strictEqual(catalog.findTechnique('T9999'), null);
  assert.strictEqual(catalog.findChain('not-a-chain'), null);
  assert.strictEqual(catalog.findTactic('TA9999'), null);
  assert.strictEqual(catalog.findTechnique(undefined), null);
  assert.strictEqual(catalog.findTechnique('T1110').name, 'Brute Force');
});
