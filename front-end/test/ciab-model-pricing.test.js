/**
 * ciab-model-pricing.test.js — the model catalog is duplicated six ways; keep it honest.
 *
 * WHY THIS FILE EXISTS
 * There is no shared bundler, so the Claude model list and its per-1M prices are
 * copy-pasted into six places: the server-side estimator, three CIAB pages, one
 * CIAB script, and the core admin lane modal. cost-estimator.js's own header has
 * asked readers to keep them in sync by hand since it was written, and they
 * drifted anyway — `claude-opus-4-7` sat at $15.00/$75.00 in two of the copies,
 * three times its real $5.00/$25.00, so every Opus cost preview an admin saw
 * before deploying was wrong in the expensive direction.
 *
 * Nothing about that failure is visible at runtime: the preview renders happily,
 * the deploy succeeds, and the number is simply false. A test is the only thing
 * that can notice.
 *
 * WHAT IS PINNED
 *   1. Every Claude price, against the published rate, in every copy.
 *   2. That llm-client's default model is one the estimator can price — if the
 *      default moves to a model the estimator has never heard of, the preview
 *      silently falls back and prices the wrong thing.
 *   3. That no copy carries a model id llm-client would reject or rewrite.
 *   4. That no id anywhere has a date suffix (`-20250514`); those are not valid
 *      model ids and one had made it into the reference docs.
 *
 * CiAB is Anthropic-only. Google and Ollama entries were removed because no such
 * provider was ever wired up — selecting one sent its id to the Anthropic API
 * and 404'd — and a test below keeps them from creeping back.
 *
 * Run: node --test front-end/test/ciab-model-pricing.test.js   (or npm test)
 */

const { test } = require('node:test');
const assert = require('assert');
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const read = (rel) => fs.readFileSync(path.join(ROOT, rel), 'utf8');

/**
 * Published Anthropic rates, USD per 1M tokens. This table is the authority
 * every copy below is measured against; update it here first when rates move.
 */
const PUBLISHED = {
  'claude-opus-5': { input: 5.00, output: 25.00 },
  'claude-opus-4-8': { input: 5.00, output: 25.00 },
  'claude-opus-4-7': { input: 5.00, output: 25.00 },
  'claude-sonnet-5': { input: 2.00, output: 10.00 },
  'claude-sonnet-4-6': { input: 3.00, output: 15.00 },
  'claude-haiku-4-5': { input: 1.00, output: 5.00 },
};

// Every file that carries a copy of the catalog.
const COPIES = [
  'modules/crucible/plugins/ciab/utils/cost-estimator.js',
  'modules/crucible/plugins/ciab/public/pages/generator.html',
  'modules/crucible/plugins/ciab/public/js/instructor-documents.js',
  'public/js/admin/admin-lanes.js',
];

// Selector-only surfaces: they list model ids but carry no prices.
const SELECTOR_ONLY = [
  'modules/crucible/plugins/ciab/public/pages/admin-profile-lanes.html',
  'modules/crucible/plugins/ciab/public/pages/instructor.html',
];

/**
 * Pull `'<model>': { ... input: N ... output: N ... }` out of a source file.
 *
 * Deliberately regex over source rather than importing: four of the six copies
 * are browser files (two inside <script> blocks in HTML) with no module export
 * to require. Anchored on the model id so a stray number elsewhere cannot match.
 */
function pricesIn(src) {
  const found = {};
  for (const id of Object.keys(PUBLISHED)) {
    const re = new RegExp(
      `'${id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}'\\s*:\\s*\\{([^}]*)\\}`);
    const m = src.match(re);
    if (!m) continue;
    const input = m[1].match(/input\s*:\s*([\d.]+)/);
    const output = m[1].match(/output\s*:\s*([\d.]+)/);
    if (input && output) {
      found[id] = { input: parseFloat(input[1]), output: parseFloat(output[1]) };
    }
  }
  return found;
}

for (const rel of COPIES) {
  test(`${rel} prices every Claude model at the published rate`, () => {
    const found = pricesIn(read(rel));
    assert.ok(Object.keys(found).length > 0,
      `${rel} carries no recognisable Claude price entries — did the shape change?`);
    for (const [id, price] of Object.entries(found)) {
      assert.deepStrictEqual(price, PUBLISHED[id],
        `${rel}: ${id} is priced ${JSON.stringify(price)} but the published rate is `
        + `${JSON.stringify(PUBLISHED[id])}. Six copies of this table exist; fix them all.`);
    }
  });
}

test('every Claude model id in a UI surface is one llm-client accepts', () => {
  // A <option value> that llm-client does not know is not a hard failure at
  // runtime — resolveModel passes an unknown id straight through to the API,
  // which then 404s the model. Catching it here is cheaper than catching it
  // in front of a class.
  const llm = read('src/utils/llm-client.js');
  const known = new Set(Object.keys(PUBLISHED));
  // Legacy ids are allowed to appear ONLY inside llm-client's forwarding map.
  for (const rel of [...COPIES, ...SELECTOR_ONLY]) {
    const src = read(rel);
    const ids = [...src.matchAll(/["']?(claude-[a-z0-9-]+)["']?/g)].map(m => m[1]);
    for (const id of new Set(ids)) {
      assert.ok(known.has(id),
        `${rel} references '${id}', which is not in the published-rate table. `
        + `If it is a real current model, add it to PUBLISHED; if it is superseded, `
        + `it belongs only in LEGACY_MODEL_ALIASES in src/utils/llm-client.js.`);
    }
  }
  assert.ok(/LEGACY_MODEL_ALIASES/.test(llm),
    'llm-client must keep a forwarding map for superseded ids stored in old rows');
});

test('no non-Anthropic model can creep back into a picker or price table', () => {
  // Google and Ollama entries sat in all six catalogs and four pickers while no
  // such provider was ever wired up — llm-client speaks only to @anthropic-ai/sdk,
  // so selecting one sent its id to the Anthropic API and 404'd. They were
  // priced, selectable and non-functional. Adding a provider means adding a
  // client; a row in these tables is not a provider.
  const NEWLINE = String.fromCharCode(10);
  const BANNED = /gemini|ollama|qwen|llama3|gpt-[0-9]|GEMINI_API_KEY/i;
  for (const rel of [...COPIES, ...SELECTOR_ONLY]) {
    const offenders = read(rel).split(NEWLINE)
      .map((line, i) => ({ line, n: i + 1 }))
      .filter(({ line }) => BANNED.test(line) && !line.trim().startsWith('//'));
    assert.deepStrictEqual(offenders.map(o => `${o.n}: ${o.line.trim()}`), [],
      `${rel} references a non-Anthropic model. CiAB is Anthropic-only.`);
  }
});

test('no model id carries a date suffix', () => {
  // Current Claude ids are complete as written. A recalled `-20250514` style
  // suffix is a training-data artefact and 404s; one had reached Info/.
  for (const rel of [...COPIES, ...SELECTOR_ONLY, 'src/utils/llm-client.js',
                     'Info/PROJECT_REFERENCE.md', 'Info/CIAB_SYSTEM_DOCUMENTATION.md']) {
    const hits = [...read(rel).matchAll(/claude-[a-z0-9-]*-\d{8}/g)].map(m => m[0]);
    assert.deepStrictEqual(hits, [],
      `${rel} carries date-suffixed model id(s): ${hits.join(', ')}. Model ids take no date.`);
  }
});

test('the estimator can price whatever llm-client defaults to', () => {
  // If these drift apart the cost preview quietly prices a model the run will
  // not use — the same class of silent wrongness as the $15/$75 entry.
  const llmDefault = read('src/utils/llm-client.js')
    .match(/const DEFAULT_MODEL = process\.env\.LLM_DEFAULT_MODEL \|\| '([^']+)'/);
  assert.ok(llmDefault, 'could not find DEFAULT_MODEL in llm-client.js');

  const estDefault = read('modules/crucible/plugins/ciab/utils/cost-estimator.js')
    .match(/const DEFAULT_MODEL = '([^']+)'/);
  assert.ok(estDefault, 'could not find DEFAULT_MODEL in cost-estimator.js');

  assert.strictEqual(estDefault[1], llmDefault[1],
    `cost-estimator defaults to '${estDefault[1]}' but llm-client runs '${llmDefault[1]}' — `
    + 'the preview would price a different model than the deploy uses.');
  assert.ok(PUBLISHED[llmDefault[1]],
    `the default model '${llmDefault[1]}' has no published rate in this test's table`);
});

test('models that reject sampling parameters are all listed', () => {
  // The deny-list is what stops every CIAB AI flow 400ing: each one passes a
  // temperature. A current model missing from it fails at request time, and
  // only on the flow that happens to use it.
  const llm = read('src/utils/llm-client.js');
  const block = llm.match(/MODELS_WITHOUT_SAMPLING_PARAMS = new Set\(\[([\s\S]*?)\]\)/);
  assert.ok(block, 'MODELS_WITHOUT_SAMPLING_PARAMS not found in llm-client.js');
  for (const id of ['claude-opus-5', 'claude-opus-4-8', 'claude-opus-4-7',
                    'claude-sonnet-5', 'claude-fable-5']) {
    assert.ok(block[1].includes(`'${id}'`),
      `${id} removed sampling parameters but is not in MODELS_WITHOUT_SAMPLING_PARAMS — `
      + 'every CIAB flow passes a temperature, so calls on it would 400.');
  }
  // Haiku 4.5 still accepts them, and the interview flow depends on that.
  assert.ok(!block[1].includes("'claude-haiku-4-5'"),
    'claude-haiku-4-5 still accepts temperature; listing it would silently drop the '
    + 'interview flow’s 0.7 and flatten stakeholder replies.');
});
