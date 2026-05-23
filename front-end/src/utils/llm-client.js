/**
 * llm-client.js — Single Anthropic SDK wrapper used by every CyberCore AI flow.
 * ============================================================================
 * Replaces N8N HTTP webhooks with direct Anthropic SDK calls. Adds:
 *   - prompt caching (cache_control: ephemeral) on system prompts and large
 *     reusable context blocks — Anthropic caches for 5 min; ~90% input cost
 *     drop on cache hits.
 *   - model selector honoring the existing UI's `llmModel` field; defaults to
 *     claude-sonnet-4-5 (the model the N8N workflows targeted).
 *   - concurrency limiter so 4-stage parallel profile gen doesn't exceed
 *     Anthropic's per-minute rate cap.
 *   - JSON repair (truncated strings, unbalanced braces, raw newlines inside
 *     strings) — the four fallback strategies the N8N E2 node implemented.
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
    throw new Error('ANTHROPIC_API_KEY not set — required for LLM calls (N8N webhooks have been removed)');
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

// ─── Concurrency semaphore ─────────────────────────────────────────────────

function createSemaphore(max) {
  let active = 0;
  const queue = [];
  return {
    async run(fn) {
      if (active >= max) {
        await new Promise(resolve => queue.push(resolve));
      }
      active++;
      try {
        return await fn();
      } finally {
        active--;
        const next = queue.shift();
        if (next) next();
      }
    },
    get active() { return active; },
    get pending() { return queue.length; }
  };
}

const _globalSem = createSemaphore(DEFAULT_CONCURRENCY);

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
      const isRetryable = status === 429 || (status >= 500 && status < 600) || err.name === 'APIConnectionError';
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
 * Repair common LLM JSON output issues. Mirrors the four-stage fallback the
 * N8N E2 node implemented:
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
  const localSem = globalOpts.maxConcurrent
    ? createSemaphore(globalOpts.maxConcurrent)
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
  repairAndParseJson,
  resolveModel,
  createSemaphore,
  DEFAULT_MODEL,
  MODEL_ALIASES,
  // Test hooks
  _setClientForTest,
  _internals: {
    escapeRawControlCharsInsideStrings,
    closeUnbalancedStructures
  }
};
