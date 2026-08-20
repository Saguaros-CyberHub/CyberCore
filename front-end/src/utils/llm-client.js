/**
 * llm-client.js — Single Anthropic SDK wrapper used by every CyberCore AI flow.
 * ============================================================================
 * Makes direct Anthropic SDK calls. Adds:
 *   - prompt caching (cache_control: ephemeral) on system prompts and large
 *     reusable context blocks — Anthropic caches for 5 min; ~90% input cost
 *     drop on cache hits.
 *   - model selector honoring the existing UI's `llmModel` field; defaults to
 *     claude-sonnet-4-5.
 *   - concurrency limiter so 4-stage parallel profile gen doesn't exceed
 *     Anthropic's per-minute rate cap.
 *   - JSON repair (truncated strings, unbalanced braces, raw newlines inside
 *     strings) — four fallback strategies applied in order.
 *   - retry with exponential backoff: 3 attempts on 429/5xx, 1 attempt on 4xx.
 *   - usage telemetry: input/output/cached-input tokens logged per call.
 *
 * Pure-functional surface: caller provides messages, system, schema, retry
 * policy. No global state (besides the Anthropic client instance + concurrency
 * semaphore). Safe to call from multiple route handlers concurrently.
 */

const Anthropic = require('@anthropic-ai/sdk');

// ─── Configuration ─────────────────────────────────────────────────────────

const DEFAULT_MODEL = process.env.LLM_DEFAULT_MODEL || 'claude-sonnet-4-5';
const DEFAULT_MAX_TOKENS = parseInt(process.env.LLM_DEFAULT_MAX_TOKENS, 10) || 4096;
const DEFAULT_TIMEOUT_MS = parseInt(process.env.LLM_TIMEOUT_MS, 10) || 10 * 60 * 1000; // 10 min — long prompts can run
const DEFAULT_CONCURRENCY = parseInt(process.env.LLM_MAX_CONCURRENT, 10) || 6;
const DEFAULT_MAX_RETRIES = parseInt(process.env.LLM_MAX_RETRIES, 10) || 3;

// Guards for the concurrency semaphore below. Why one full call-timeout for the
// wait deadline: the SDK abandons any single call after DEFAULT_TIMEOUT_MS, so
// every in-flight slot is guaranteed to turn over inside that window. A waiter
// that has sat longer than one whole turnover of the pool is not "busy", it is
// stuck behind something that is not draining — and it is already far past the
// point where the browser that triggered the request gave up. Normal work never
// approaches this: a real call returns in seconds, not minutes.
const DEFAULT_QUEUE_WAIT_MS = parseInt(process.env.LLM_QUEUE_WAIT_MS, 10) || DEFAULT_TIMEOUT_MS;
// 128 waiters behind 6 slots is already more queued work than any single request
// path legitimately produces — past this we are looking at a runaway fan-out, and
// joining the queue only delays a failure the caller could be told about now.
const DEFAULT_MAX_QUEUE = parseInt(process.env.LLM_MAX_QUEUE, 10) || 128;

// Map UI-friendly aliases to actual model IDs. Easy to add more later.
const MODEL_ALIASES = {
  'claude-sonnet':      'claude-sonnet-4-5',
  'claude-sonnet-4':    'claude-sonnet-4-5',
  'claude-sonnet-4-5':  'claude-sonnet-4-5',
  'claude-sonnet-4-6':  'claude-sonnet-4-6',
  'claude-opus':        'claude-opus-4-1',
  'claude-opus-4':      'claude-opus-4-1',
  'claude-opus-4-1':    'claude-opus-4-1',
  'claude-haiku':       'claude-haiku-4-5',
  'claude-haiku-4-5':   'claude-haiku-4-5'
};

function resolveModel(model) {
  if (!model) return DEFAULT_MODEL;
  return MODEL_ALIASES[model] || model;
}

// ─── Client (lazy singleton — created on first call) ──────────────────────

let _client = null;
function getClient() {
  if (_client) return _client;
  const apiKey = process.env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    throw new Error('ANTHROPIC_API_KEY not set — required for LLM calls');
  }
  _client = new Anthropic.Anthropic({
    apiKey,
    timeout: DEFAULT_TIMEOUT_MS,
    maxRetries: 0   // we do our own retry so we can log + respect rate limits cooperatively
  });
  return _client;
}

// For tests: lets a test swap in a mock client.
function _setClientForTest(client) { _client = client; }

// Can this deployment talk to an LLM at all? getClient() throws without a key,
// so callers that would rather degrade than fail (the global chat widget hides
// its launcher) can ask first.
function isConfigured() {
  return !!process.env.ANTHROPIC_API_KEY;
}

// ─── Concurrency semaphore ─────────────────────────────────────────────────

// Rejection raised when a caller cannot get a slot. Carries a 503 so route
// handlers that already forward `err.status` surface "server busy" instead of a
// generic 500, and `isSemaphoreRejection` so generate() does not burn its retry
// budget re-queueing into a pool that just told us it is saturated.
function semaphoreRejection(name, code, message) {
  const err = new Error(message);
  err.name = 'LLMOverloadedError';
  err.code = code;                  // LLM_QUEUE_FULL | LLM_QUEUE_TIMEOUT
  err.status = 503;
  err.semaphore = name;
  err.isSemaphoreRejection = true;
  return err;
}

/**
 * Bounded, deadline-aware counting semaphore.
 *
 * The original version parked waiters on a bare `new Promise(r => queue.push(r))`
 * with no cap, no deadline and no abort path. One profile build takes several of
 * the 6 slots and then fires 10-20 more calls into the same queue, so every other
 * AI route (the chat widget, policy gen, an interview turn) sat behind it
 * indefinitely — no error, no log line, just a request that never answers. Two
 * bounds close that hole:
 *
 *   maxQueue      — refuse to enqueue at all once the backlog is absurd, so the
 *                   caller fails fast instead of joining a queue that cannot drain.
 *   waitTimeoutMs — refuse a waiter that has sat queued past the deadline.
 *
 * Slots are handed straight from a releasing holder to the next waiter instead of
 * decrement-then-reacquire. The old code decremented `active` in `finally` and let
 * the woken waiter increment it a microtask later, which let a brand-new caller
 * slip into that gap and push `active` past `max`.
 *
 * @param {number} max                    slots allowed in flight at once
 * @param {object} [opts]
 * @param {string} [opts.name]            appears in rejection messages and logs
 * @param {number} [opts.maxQueue]        waiters allowed before overflow rejection
 * @param {number} [opts.waitTimeoutMs]   how long a waiter may sit queued
 */
function createSemaphore(max, opts = {}) {
  const name          = opts.name || 'llm';
  const maxQueue      = opts.maxQueue      != null ? opts.maxQueue      : DEFAULT_MAX_QUEUE;
  const waitTimeoutMs = opts.waitTimeoutMs != null ? opts.waitTimeoutMs : DEFAULT_QUEUE_WAIT_MS;

  let active = 0;
  let rejectedFull = 0;
  let rejectedTimeout = 0;
  const queue = [];   // [{ resolve, reject, timer, settled }]

  // Hand this slot to the oldest live waiter. Anything already settled (rejected
  // on the deadline) is skipped: giving the slot to a dead promise would leak it
  // permanently, since nobody is left to call release() for it.
  function passSlot() {
    while (queue.length) {
      const waiter = queue.shift();
      if (waiter.settled) continue;
      waiter.settled = true;
      clearTimeout(waiter.timer);
      waiter.resolve();     // active stays put — the slot moved, it was never freed
      return true;
    }
    return false;
  }

  function acquire() {
    if (active < max) {
      active++;
      return Promise.resolve();
    }
    if (queue.length >= maxQueue) {
      rejectedFull++;
      const err = semaphoreRejection(name, 'LLM_QUEUE_FULL',
        `LLM semaphore "${name}" queue is full — ${active} in flight, ${queue.length}/${maxQueue} waiting`);
      console.warn(`[LLM] ${err.message}`);
      return Promise.reject(err);
    }
    return new Promise((resolve, reject) => {
      const waiter = { resolve, reject, settled: false, timer: null };
      waiter.timer = setTimeout(() => {
        if (waiter.settled) return;
        waiter.settled = true;
        rejectedTimeout++;
        // Drop it from the queue now so `pending` stays honest and passSlot()
        // never has to walk a pile of corpses.
        const idx = queue.indexOf(waiter);
        if (idx !== -1) queue.splice(idx, 1);
        const err = semaphoreRejection(name, 'LLM_QUEUE_TIMEOUT',
          `LLM semaphore "${name}" wait exceeded ${waitTimeoutMs}ms — ${active} in flight, ${queue.length} still waiting`);
        console.warn(`[LLM] ${err.message}`);
        reject(err);
      }, waitTimeoutMs);
      // A queued waiter must not be the reason the process refuses to exit.
      if (typeof waiter.timer.unref === 'function') waiter.timer.unref();
      queue.push(waiter);
    });
  }

  function release() {
    // passSlot() transfers the slot; only give it back to the pool if nobody took it.
    if (!passSlot()) active--;
  }

  return {
    async run(fn) {
      // Throws on overflow/deadline — nothing was acquired, so there is nothing
      // to release and no slot leaks out of the rejected path.
      await acquire();
      try {
        return await fn();
      } finally {
        release();
      }
    },
    get active() { return active; },
    get pending() { return queue.length; },
    get stats() {
      return {
        name, max, maxQueue, waitTimeoutMs,
        active,
        pending: queue.length,
        rejectedFull,
        rejectedTimeout
      };
    }
  };
}

const _globalSem = createSemaphore(DEFAULT_CONCURRENCY, { name: 'global' });

// Live view of the process-global LLM pool, for a future /health or admin panel:
// { name, max, maxQueue, waitTimeoutMs, active, pending, rejectedFull, rejectedTimeout }.
function getConcurrencyStats() {
  return _globalSem.stats;
}

// ─── Telemetry ─────────────────────────────────────────────────────────────

function logUsage(meta, usage, latencyMs) {
  if (!usage) return;
  const parts = [
    `model=${meta.model}`,
    `in=${usage.input_tokens || 0}`,
    `out=${usage.output_tokens || 0}`
  ];
  if (usage.cache_creation_input_tokens) parts.push(`cache_create=${usage.cache_creation_input_tokens}`);
  if (usage.cache_read_input_tokens)     parts.push(`cache_read=${usage.cache_read_input_tokens}`);
  parts.push(`latency=${latencyMs}ms`);
  if (meta.label) parts.unshift(`[${meta.label}]`);
  console.log(`[LLM] ${parts.join(' ')}`);
}

// ─── Core generate() ───────────────────────────────────────────────────────
/**
 * @param {object} opts
 * @param {string} [opts.model]               'claude-sonnet-4-5' (default) or alias
 * @param {Array|string} opts.system          system prompt (string or content blocks)
 * @param {Array} opts.messages               [{role, content}] — content can be string or blocks
 * @param {number} [opts.max_tokens]
 * @param {number} [opts.temperature]
 * @param {string} [opts.label]               appears in usage log
 * @param {number} [opts.maxRetries]          override DEFAULT_MAX_RETRIES
 * @param {AbortSignal} [opts.signal]
 * @returns {Promise<{ text:string, raw:object, usage:object, latencyMs:number }>}
 */
async function generate(opts = {}) {
  const model = resolveModel(opts.model);
  const max_tokens = opts.max_tokens || DEFAULT_MAX_TOKENS;
  const maxRetries = opts.maxRetries != null ? opts.maxRetries : DEFAULT_MAX_RETRIES;
  const label = opts.label || null;

  if (!opts.messages || !Array.isArray(opts.messages) || opts.messages.length === 0) {
    throw new Error('llm-client.generate: messages array required');
  }

  const params = {
    model,
    max_tokens,
    messages: opts.messages
  };
  if (opts.system != null) params.system = opts.system;
  if (opts.temperature != null) params.temperature = opts.temperature;
  if (opts.stop_sequences) params.stop_sequences = opts.stop_sequences;

  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const startedAt = Date.now();
    try {
      const response = await _globalSem.run(() =>
        getClient().messages.create(params, opts.signal ? { signal: opts.signal } : undefined)
      );
      const latencyMs = Date.now() - startedAt;
      logUsage({ model, label }, response.usage, latencyMs);

      // Extract text from content blocks (we don't use tool_use here — that's a future feature)
      const text = (response.content || [])
        .filter(b => b.type === 'text')
        .map(b => b.text)
        .join('');

      return { text, raw: response, usage: response.usage || {}, latencyMs };
    } catch (err) {
      lastErr = err;
      const status = err.status || err.response?.status;
      // A semaphore rejection also carries a 5xx, but retrying it is exactly the
      // wrong move: the pool just told us it is saturated, and three backoff
      // rounds would turn a fast, visible 503 into a multi-minute silent stall
      // while adding more pressure to the queue that rejected us.
      const isRetryable = !err.isSemaphoreRejection &&
        (status === 429 || (status >= 500 && status < 600) || err.name === 'APIConnectionError');
      const willRetry = isRetryable && attempt < maxRetries;

      const labelPrefix = label ? `[${label}] ` : '';
      if (willRetry) {
        const delayMs = Math.min(30_000, 1000 * Math.pow(2, attempt) + Math.random() * 500);
        console.warn(`[LLM] ${labelPrefix}attempt ${attempt + 1}/${maxRetries + 1} failed (${status || err.name}): ${err.message} — retrying in ${Math.round(delayMs)}ms`);
        await new Promise(r => setTimeout(r, delayMs));
      } else {
        console.error(`[LLM] ${labelPrefix}giving up (${status || err.name}): ${err.message}`);
        throw err;
      }
    }
  }
  throw lastErr;
}

// ─── JSON repair ───────────────────────────────────────────────────────────
/**
 * Repair common LLM JSON output issues using a four-stage fallback:
 *   1. Strip surrounding markdown code fences (```json ... ```).
 *   2. Try JSON.parse as-is.
 *   3. Repair: close unclosed strings, balance braces/brackets, escape raw
 *      newlines and tabs inside string values, drop trailing commas.
 *   4. Try again. If still fails, throw a descriptive error.
 */
function repairAndParseJson(rawText) {
  if (rawText == null) throw new Error('repairAndParseJson: input is null');
  let text = String(rawText).trim();

  // Strip code fences
  const fenceMatch = text.match(/^```(?:json)?\s*([\s\S]*?)```\s*$/);
  if (fenceMatch) text = fenceMatch[1].trim();

  // Strip any leading text before the first { or [
  const firstBrace = text.search(/[{\[]/);
  if (firstBrace > 0) text = text.slice(firstBrace);

  // Try as-is
  try { return JSON.parse(text); } catch (_) { /* fall through to repair */ }

  // Apply repairs
  let repaired = text;

  // Drop trailing commas before } or ]
  repaired = repaired.replace(/,(\s*[}\]])/g, '$1');

  // Escape raw newlines/tabs inside double-quoted strings (a common LLM
  // failure mode — they emit "foo\nbar" as a literal newline instead of \n).
  repaired = escapeRawControlCharsInsideStrings(repaired);

  // Balance brackets — if the JSON was truncated, close all open structures.
  repaired = closeUnbalancedStructures(repaired);

  try { return JSON.parse(repaired); } catch (err) {
    const snippet = repaired.length > 400 ? repaired.slice(0, 200) + '\n…\n' + repaired.slice(-200) : repaired;
    throw new Error(`JSON parse failed after repair: ${err.message}\nRepaired snippet:\n${snippet}`);
  }
}

function escapeRawControlCharsInsideStrings(s) {
  let out = '';
  let inString = false;
  let escape = false;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (inString) {
      if (escape) { out += ch; escape = false; continue; }
      if (ch === '\\') { out += ch; escape = true; continue; }
      if (ch === '"')  { out += ch; inString = false; continue; }
      if (ch === '\n') { out += '\\n'; continue; }
      if (ch === '\r') { out += '\\r'; continue; }
      if (ch === '\t') { out += '\\t'; continue; }
      out += ch;
    } else {
      if (ch === '"') { out += ch; inString = true; continue; }
      out += ch;
    }
  }
  return out;
}

function closeUnbalancedStructures(s) {
  const stack = [];
  let inString = false;
  let escape = false;
  let lastNonSpace = -1;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (escape) { escape = false; continue; }
    if (inString) {
      if (ch === '\\') escape = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; continue; }
    if (ch === '{' || ch === '[') stack.push(ch);
    else if (ch === '}' || ch === ']') stack.pop();
    if (ch.trim()) lastNonSpace = i;
  }

  let suffix = '';
  // If we ended inside a string, close it. The element we were emitting IS
  // that string, so any preceding comma is a real delimiter — leave it alone.
  let body = s;
  if (inString) {
    suffix += '"';
  } else if (lastNonSpace >= 0 && body[lastNonSpace] === ',') {
    // Truly trailing comma (no element started after it) — drop it.
    body = body.slice(0, lastNonSpace) + body.slice(lastNonSpace + 1);
  }
  // Close any unbalanced structures, innermost first.
  for (let i = stack.length - 1; i >= 0; i--) {
    suffix += (stack[i] === '{') ? '}' : ']';
  }
  return body + suffix;
}

// ─── generateJson — call + repair + parse ─────────────────────────────────
/**
 * Calls generate(), repairs JSON, optionally validates against a schema, returns parsed value.
 *
 * @param {object} opts                       same as generate(), plus:
 * @param {Function} [opts.validate]          (parsed) => true|throw  — caller can pass an ajv validator
 * @returns {Promise<{ value:any, raw:object, usage:object, latencyMs:number }>}
 */
async function generateJson(opts) {
  const result = await generate(opts);
  const value = repairAndParseJson(result.text);
  if (opts.validate) opts.validate(value);
  return { value, raw: result.raw, usage: result.usage, latencyMs: result.latencyMs };
}

// ─── generateParallel — fan out N calls under a concurrency cap ───────────
/**
 * @param {Array<object>} optsList      one element per call (same shape as generate())
 * @param {object} [globalOpts]
 * @param {number} [globalOpts.maxConcurrent]  override global concurrency for this fan-out
 * @param {boolean} [globalOpts.failFast]      throw on first error (default false — collect all)
 * @returns {Promise<Array<{ ok:boolean, value?:any, error?:Error, index:number }>>}
 */
async function generateParallel(optsList, globalOpts = {}) {
  // A fan-out is a *closed* set of work: every item is queued up front and the
  // tail legitimately waits ceil(N / maxConcurrent) rounds before it even starts.
  // So the local queue must clear the batch (otherwise we would reject our own
  // callers on overflow) and the local deadline is scaled by those rounds. The
  // batch still cannot hang: each holder is itself bounded by the global
  // semaphore's deadline plus the SDK's per-call timeout.
  const localSem = globalOpts.maxConcurrent
    ? createSemaphore(globalOpts.maxConcurrent, {
        name: `parallel-${globalOpts.maxConcurrent}`,
        maxQueue: Math.max(DEFAULT_MAX_QUEUE, optsList.length),
        waitTimeoutMs: DEFAULT_QUEUE_WAIT_MS *
          Math.max(1, Math.ceil(optsList.length / globalOpts.maxConcurrent))
      })
    : null;
  const failFast = !!globalOpts.failFast;
  const useJson = !!globalOpts.json;
  const callFn = useJson ? generateJson : generate;

  const runners = optsList.map((opts, index) => {
    const fn = async () => {
      try {
        const value = await callFn(opts);
        return { ok: true, value, index };
      } catch (error) {
        if (failFast) throw error;
        return { ok: false, error, index };
      }
    };
    return localSem ? localSem.run(fn) : fn();
  });

  return Promise.all(runners);
}

// ─── Helper: build a cached system prompt block ───────────────────────────
/**
 * Build a system content array that puts the large static portion under
 * cache_control. Use this for repeated system prompts (>= ~1024 tokens) so
 * Anthropic's 5-minute cache cuts input cost ~90% on hits.
 *
 * @param {string} staticPrompt   the big reusable portion (instructions, schema, examples)
 * @param {string} [dynamicTail]  per-call tail that should NOT be cached
 * @returns {Array}
 */
function cachedSystem(staticPrompt, dynamicTail) {
  const blocks = [
    { type: 'text', text: staticPrompt, cache_control: { type: 'ephemeral' } }
  ];
  if (dynamicTail) blocks.push({ type: 'text', text: dynamicTail });
  return blocks;
}

// ─── Exports ───────────────────────────────────────────────────────────────

module.exports = {
  generate,
  generateJson,
  generateParallel,
  cachedSystem,
  isConfigured,
  repairAndParseJson,
  resolveModel,
  createSemaphore,
  getConcurrencyStats,
  DEFAULT_MODEL,
  MODEL_ALIASES,
  // Test hooks
  _setClientForTest,
  _internals: {
    escapeRawControlCharsInsideStrings,
    closeUnbalancedStructures
  }
};
