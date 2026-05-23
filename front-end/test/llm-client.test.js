/**
 * Standalone test runner for llm-client.
 * Run: node front-end/test/llm-client.test.js
 *
 * Uses Node's built-in assert. Mocks the Anthropic client via _setClientForTest.
 */

process.env.ANTHROPIC_API_KEY = 'sk-test-dummy';
process.env.LLM_MAX_CONCURRENT = '4';

const assert = require('assert');
const {
  generate, generateJson, generateParallel,
  cachedSystem, repairAndParseJson, resolveModel, createSemaphore,
  _setClientForTest, _internals
} = require('../src/utils/llm-client');

let passed = 0, failed = 0;

function test(name, fn) {
  const promise = (async () => fn())();
  return promise.then(() => {
    console.log(`  ✓ ${name}`);
    passed++;
  }, err => {
    console.log(`  ✗ ${name}`);
    console.log(`    ${err.stack || err.message}`);
    failed++;
  });
}

// ─── Mock client ────────────────────────────────────────────────────────────

function makeMockClient(behaviors) {
  // behaviors is either a function (params, callIndex) => response,
  // or an array of responses/errors to return in order.
  let callIndex = 0;
  const calls = [];
  return {
    messages: {
      create: async (params, opts) => {
        const idx = callIndex++;
        calls.push({ params, opts, idx });
        let b;
        if (typeof behaviors === 'function') b = behaviors(params, idx);
        else b = behaviors[idx] || behaviors[behaviors.length - 1];
        if (b instanceof Error) throw b;
        if (typeof b === 'function') return b(params, idx);
        return b;
      }
    },
    _calls: calls,
    get callCount() { return callIndex; }
  };
}

function mockResponse(text, usage = {}) {
  return {
    content: [{ type: 'text', text }],
    usage: { input_tokens: 10, output_tokens: 5, ...usage },
    stop_reason: 'end_turn'
  };
}

function mockError(status, message = 'API error') {
  const err = new Error(message);
  err.status = status;
  return err;
}

// ─── resolveModel ──────────────────────────────────────────────────────────

console.log('\nresolveModel');

(async () => {
  await test('aliases collapse to canonical ID', () => {
    assert.strictEqual(resolveModel('claude-sonnet'), 'claude-sonnet-4-5');
    assert.strictEqual(resolveModel('claude-opus'), 'claude-opus-4-1');
    assert.strictEqual(resolveModel('claude-haiku'), 'claude-haiku-4-5');
  });
  await test('unknown model passes through', () => {
    assert.strictEqual(resolveModel('claude-5000'), 'claude-5000');
  });
  await test('null defaults to claude-sonnet-4-5', () => {
    assert.strictEqual(resolveModel(null), 'claude-sonnet-4-5');
  });

  // ─── cachedSystem ─────────────────────────────────────────────────────────

  console.log('\ncachedSystem');

  await test('static portion gets cache_control', () => {
    const sys = cachedSystem('big static prompt');
    assert.strictEqual(sys.length, 1);
    assert.deepStrictEqual(sys[0].cache_control, { type: 'ephemeral' });
  });
  await test('dynamic tail is NOT cached', () => {
    const sys = cachedSystem('static', 'tail');
    assert.strictEqual(sys.length, 2);
    assert.deepStrictEqual(sys[0].cache_control, { type: 'ephemeral' });
    assert.strictEqual(sys[1].cache_control, undefined);
    assert.strictEqual(sys[1].text, 'tail');
  });

  // ─── repairAndParseJson ──────────────────────────────────────────────────

  console.log('\nrepairAndParseJson');

  await test('parses clean JSON', () => {
    assert.deepStrictEqual(repairAndParseJson('{"a":1}'), { a: 1 });
  });
  await test('strips ```json``` code fences', () => {
    assert.deepStrictEqual(repairAndParseJson('```json\n{"a":1}\n```'), { a: 1 });
  });
  await test('strips ``` code fences without lang', () => {
    assert.deepStrictEqual(repairAndParseJson('```\n{"a":1}\n```'), { a: 1 });
  });
  await test('strips leading prose before JSON', () => {
    assert.deepStrictEqual(repairAndParseJson('Sure, here you go:\n{"a":1}'), { a: 1 });
  });
  await test('repairs trailing comma', () => {
    assert.deepStrictEqual(repairAndParseJson('{"a":1,"b":[1,2,],}'), { a: 1, b: [1, 2] });
  });
  await test('repairs raw newline inside string', () => {
    const r = repairAndParseJson('{"note":"line1\nline2"}');
    assert.strictEqual(r.note, 'line1\nline2');
  });
  await test('closes truncated string + structures', () => {
    // Simulates Claude cut off mid-output
    const r = repairAndParseJson('{"a":1,"b":[1,2,3,"trunc');
    assert.strictEqual(r.a, 1);
    assert.deepStrictEqual(r.b.slice(0, 3), [1, 2, 3]);
    assert.ok(typeof r.b[3] === 'string');
  });
  await test('throws on irrecoverable garbage', () => {
    assert.throws(() => repairAndParseJson('this is not json at all xyz'), /JSON parse failed/);
  });

  // ─── _internals: escapeRawControlCharsInsideStrings ──────────────────────

  console.log('\nescapeRawControlCharsInsideStrings');

  await test('only escapes inside strings, not outside', () => {
    const input = '{"a":"x\ny",\n"b":1}';
    const out = _internals.escapeRawControlCharsInsideStrings(input);
    // Newline inside "x\ny" gets escaped; newline between fields stays raw
    assert.ok(out.includes('"x\\ny"'));
    assert.ok(out.includes('1}'));
  });

  // ─── _internals: closeUnbalancedStructures ──────────────────────────────

  console.log('\ncloseUnbalancedStructures');

  await test('closes one missing brace', () => {
    const out = _internals.closeUnbalancedStructures('{"a":1');
    assert.strictEqual(out, '{"a":1}');
  });
  await test('closes nested brackets innermost-first', () => {
    const out = _internals.closeUnbalancedStructures('{"a":[1,2');
    assert.strictEqual(out, '{"a":[1,2]}');
  });
  await test('closes unterminated string then brackets', () => {
    const out = _internals.closeUnbalancedStructures('{"a":"unfinished');
    assert.strictEqual(out, '{"a":"unfinished"}');
  });

  // ─── generate() — with mock client ───────────────────────────────────────

  console.log('\ngenerate (with mock client)');

  await test('returns text + usage + latency', async () => {
    const mock = makeMockClient([mockResponse('hello world', { input_tokens: 12, output_tokens: 3 })]);
    _setClientForTest(mock);
    const r = await generate({ messages: [{ role: 'user', content: 'hi' }] });
    assert.strictEqual(r.text, 'hello world');
    assert.strictEqual(r.usage.input_tokens, 12);
    assert.ok(r.latencyMs >= 0);
  });

  await test('passes through model + max_tokens + system', async () => {
    const mock = makeMockClient([mockResponse('ok')]);
    _setClientForTest(mock);
    await generate({
      model: 'claude-opus',
      max_tokens: 1234,
      system: 'be helpful',
      messages: [{ role: 'user', content: 'hi' }]
    });
    const c = mock._calls[0].params;
    assert.strictEqual(c.model, 'claude-opus-4-1');  // alias resolved
    assert.strictEqual(c.max_tokens, 1234);
    assert.strictEqual(c.system, 'be helpful');
  });

  await test('resolves model alias', async () => {
    const mock = makeMockClient([mockResponse('ok')]);
    _setClientForTest(mock);
    await generate({ model: 'claude-sonnet', messages: [{ role: 'user', content: 'hi' }] });
    assert.strictEqual(mock._calls[0].params.model, 'claude-sonnet-4-5');
  });

  await test('retries on 429 then succeeds', async () => {
    const mock = makeMockClient([mockError(429), mockError(429), mockResponse('finally')]);
    _setClientForTest(mock);
    const r = await generate({ messages: [{ role: 'user', content: 'hi' }], maxRetries: 3 });
    assert.strictEqual(r.text, 'finally');
    assert.strictEqual(mock.callCount, 3);
  });

  await test('retries on 500 then succeeds', async () => {
    const mock = makeMockClient([mockError(503), mockResponse('ok')]);
    _setClientForTest(mock);
    const r = await generate({ messages: [{ role: 'user', content: 'hi' }], maxRetries: 2 });
    assert.strictEqual(r.text, 'ok');
  });

  await test('does NOT retry on 400 (non-retryable)', async () => {
    const mock = makeMockClient([mockError(400, 'bad request')]);
    _setClientForTest(mock);
    await assert.rejects(
      generate({ messages: [{ role: 'user', content: 'hi' }], maxRetries: 3 }),
      /bad request/
    );
    assert.strictEqual(mock.callCount, 1);
  });

  await test('gives up after maxRetries on persistent 429', async () => {
    const mock = makeMockClient([mockError(429), mockError(429)]);
    _setClientForTest(mock);
    await assert.rejects(
      generate({ messages: [{ role: 'user', content: 'hi' }], maxRetries: 1 }),
      /API error/
    );
    assert.strictEqual(mock.callCount, 2);  // 1 initial + 1 retry
  });

  await test('throws on empty messages', async () => {
    _setClientForTest(makeMockClient([mockResponse('ok')]));
    await assert.rejects(generate({ messages: [] }), /messages array required/);
  });

  // ─── generateJson ────────────────────────────────────────────────────────

  console.log('\ngenerateJson');

  await test('parses + returns value', async () => {
    _setClientForTest(makeMockClient([mockResponse('{"answer":42}')]));
    const r = await generateJson({ messages: [{ role: 'user', content: 'x' }] });
    assert.deepStrictEqual(r.value, { answer: 42 });
  });

  await test('repairs truncated JSON before parsing', async () => {
    _setClientForTest(makeMockClient([mockResponse('{"answer":42, "b":[1,2,')]));
    const r = await generateJson({ messages: [{ role: 'user', content: 'x' }] });
    assert.strictEqual(r.value.answer, 42);
    assert.deepStrictEqual(r.value.b, [1, 2]);
  });

  await test('honors custom validate function', async () => {
    _setClientForTest(makeMockClient([mockResponse('{"answer":42}')]));
    await assert.rejects(
      generateJson({
        messages: [{ role: 'user', content: 'x' }],
        validate: (v) => { if (v.answer !== 99) throw new Error('expected 99'); }
      }),
      /expected 99/
    );
  });

  // ─── generateParallel ────────────────────────────────────────────────────

  console.log('\ngenerateParallel');

  await test('fans out N calls and returns indexed results', async () => {
    _setClientForTest(makeMockClient((p, i) => mockResponse(`result-${i}`)));
    const results = await generateParallel([
      { messages: [{ role: 'user', content: 'a' }] },
      { messages: [{ role: 'user', content: 'b' }] },
      { messages: [{ role: 'user', content: 'c' }] }
    ]);
    assert.strictEqual(results.length, 3);
    results.forEach((r, i) => {
      assert.strictEqual(r.ok, true);
      assert.strictEqual(r.index, i);
      assert.strictEqual(r.value.text, `result-${i}`);
    });
  });

  await test('collects errors without failing the whole batch', async () => {
    _setClientForTest(makeMockClient([
      mockResponse('ok1'),
      mockError(400, 'doomed'),
      mockResponse('ok3')
    ]));
    const results = await generateParallel([
      { messages: [{ role: 'user', content: 'a' }] },
      { messages: [{ role: 'user', content: 'b' }], maxRetries: 0 },
      { messages: [{ role: 'user', content: 'c' }] }
    ]);
    assert.strictEqual(results[0].ok, true);
    assert.strictEqual(results[1].ok, false);
    assert.match(results[1].error.message, /doomed/);
    assert.strictEqual(results[2].ok, true);
  });

  await test('failFast throws on first error', async () => {
    _setClientForTest(makeMockClient([mockResponse('ok'), mockError(400, 'nope'), mockResponse('ok')]));
    await assert.rejects(
      generateParallel([
        { messages: [{ role: 'user', content: 'a' }] },
        { messages: [{ role: 'user', content: 'b' }], maxRetries: 0 },
        { messages: [{ role: 'user', content: 'c' }] }
      ], { failFast: true }),
      /nope/
    );
  });

  // ─── createSemaphore — quick sanity test ─────────────────────────────────

  console.log('\ncreateSemaphore');

  await test('limits concurrent runs', async () => {
    const sem = createSemaphore(2);
    let concurrent = 0;
    let peak = 0;
    const tasks = Array.from({ length: 6 }, () => sem.run(async () => {
      concurrent++;
      peak = Math.max(peak, concurrent);
      await new Promise(r => setTimeout(r, 30));
      concurrent--;
    }));
    await Promise.all(tasks);
    assert.ok(peak <= 2, `peak concurrency was ${peak}, expected <= 2`);
  });

  console.log(`\n${passed} passed, ${failed} failed`);
  process.exit(failed === 0 ? 0 : 1);
})();
