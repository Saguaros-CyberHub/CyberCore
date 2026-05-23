/**
 * cost-estimator.js — Verified per-call LLM token + USD cost estimates.
 * ============================================================================
 * Token numbers below are *measured averages* from real generation runs (see
 * Anthropic console activity logs). They are intentionally rounded up slightly
 * (~10%) so the preview shows a conservative ceiling, not a best case.
 *
 * Used by:
 *   - /api/profile-deploy/preview         — pre-flight deploy cost
 *   - generator.html cost preview         — pre-gen cost shown next to model picker
 *
 * Frontend mirrors these constants in a tiny inline object (no shared bundler
 * yet). If you change values here, update generator.html and
 * admin-profile-lanes.js to match.
 */

// ─── Pricing tables (USD per 1M tokens) ────────────────────────────────────
const MODEL_PRICING = {
  // Anthropic — published rates
  'claude-opus-4-7':           { input: 15.00, output: 75.00, label: 'Claude Opus 4.7',           provider: 'anthropic' },
  'claude-sonnet-4-6':         { input:  3.00, output: 15.00, label: 'Claude Sonnet 4.6',         provider: 'anthropic' },
  'claude-sonnet-4-5':         { input:  3.00, output: 15.00, label: 'Claude Sonnet 4.5',         provider: 'anthropic' },
  'claude-haiku-4-5':          { input:  0.80, output:  4.00, label: 'Claude Haiku 4.5',          provider: 'anthropic' },
  // Google — published rates
  'gemini-2.5-flash':          { input:  0.15, output:  0.60, label: 'Gemini 2.5 Flash',          provider: 'google' },
  'gemini-2.5-pro':            { input:  1.25, output: 10.00, label: 'Gemini 2.5 Pro',            provider: 'google' },
  // Local / Ollama — no marginal cost
  'qwen3:14b':                 { input: 0, output: 0, label: 'Qwen 3.0 14B',         provider: 'ollama' },
  'qwen2.5:7b-instruct':       { input: 0, output: 0, label: 'Qwen 2.5 7B',          provider: 'ollama' },
  'llama3.2':                  { input: 0, output: 0, label: 'Llama 3.2',            provider: 'ollama' }
};

const DEFAULT_MODEL = 'claude-sonnet-4-5';

// ─── Measured token usage (rounded UP from real runs) ──────────────────────
// Source: Anthropic console req IDs req_011CbLJ* (profile-only) and
// req_011CbLJK*/req_011CbLJS*/req_011CbLJV*/req_011CbLJY*/req_011CbLJb*/req_011CbLJf*
// (profile + vuln-app, 9-page run on 2026-05-23).

const PROFILE_TOKENS = {
  // 4 branches: org, IT, network, threats. Measured ~7.9K in / ~14.5K out.
  // Padded ~10% for the future drift after we add fields.
  input:  9000,
  output: 16000,
  calls: 4
};

const VULN_APP_TOKENS = {
  // Stage 1 (concept):   ~1600 in / ~2700 out      → 1 call
  // Stage 2 (files):     ~3500 in / ~3500 out each → N calls (N = pages, 4–7, avg 6)
  // Stage 3 (install):   ~600 in  / ~900 out       → 1 call
  // With avg N=6: 1600 + 6*3500 + 600 = 23200 in; 2700 + 6*3500 + 900 = 24600 out.
  // Round up for variability.
  input:  25000,
  output: 28000,
  pages_avg: 6,
  calls: 8       // 1 concept + 6 file gens + 1 install
};

// ─── Cost calculator ───────────────────────────────────────────────────────

function resolveModel(modelId) {
  return MODEL_PRICING[modelId] || MODEL_PRICING[DEFAULT_MODEL];
}

function costFor(modelId, { input, output }) {
  const m = resolveModel(modelId);
  const usd = (input / 1_000_000) * m.input + (output / 1_000_000) * m.output;
  return {
    model_id:     modelId,
    model_label:  m.label,
    provider:     m.provider,
    input_tokens: input,
    output_tokens: output,
    input_usd:    (input / 1_000_000) * m.input,
    output_usd:   (output / 1_000_000) * m.output,
    total_usd:    usd
  };
}

/**
 * Estimate profile-only generation cost (4 LLM calls).
 */
function estimateProfileCost(modelId = DEFAULT_MODEL) {
  return {
    component:  'profile_generation',
    description: 'Org + IT + Network + Threats (4 parallel/sequential LLM calls)',
    calls: PROFILE_TOKENS.calls,
    ...costFor(modelId, PROFILE_TOKENS)
  };
}

/**
 * Estimate vuln-app generation cost (concept + ~6 file gens + install).
 */
function estimateVulnAppCost(modelId = DEFAULT_MODEL) {
  return {
    component:  'vuln_app_generation',
    description: `Concept + ~${VULN_APP_TOKENS.pages_avg} file gens + install (${VULN_APP_TOKENS.calls} LLM calls)`,
    calls: VULN_APP_TOKENS.calls,
    pages_avg: VULN_APP_TOKENS.pages_avg,
    ...costFor(modelId, VULN_APP_TOKENS)
  };
}

/**
 * Estimate full deploy cost, including any LLM work that will be triggered.
 * Caller passes flags so we know what's cached.
 *
 * @param {object} opts
 * @param {string} [opts.modelId]                  — model used for AI calls
 * @param {boolean} [opts.vulnAppEnabled=true]     — will the deploy include the vuln-app step?
 * @param {boolean} [opts.vulnAppAlreadyCached=false] — skip cost if the app is already generated
 * @param {number}  [opts.numLanes=1]              — number of lanes (Proxmox-only cost — no LLM)
 * @param {number}  [opts.vmsPerLane=0]            — VMs deployed per lane (used to estimate time)
 * @param {boolean} [opts.attackBoxes=false]       — adds 1 Kali VM per lane
 */
function estimateDeployCost(opts = {}) {
  const {
    modelId = DEFAULT_MODEL,
    vulnAppEnabled = true,
    vulnAppAlreadyCached = false,
    numLanes = 1,
    vmsPerLane = 0,
    attackBoxes = false
  } = opts;

  const items = [];
  let totalUsd = 0;

  if (vulnAppEnabled && !vulnAppAlreadyCached) {
    const vulnApp = estimateVulnAppCost(modelId);
    items.push(vulnApp);
    totalUsd += vulnApp.total_usd;
  }

  // Proxmox / infra deployment — no LLM cost, but estimate time so the UI
  // can show "~12 min" alongside the dollar figure. Numbers are conservative:
  //   ~90 s per VM clone (incl. firstboot + guest-agent wait), plus per-lane
  //   overhead (~60 s for gateway clone, VXLAN setup, Guacamole hookup).
  const totalVmsPerLane = vmsPerLane + (attackBoxes ? 1 : 0);
  const totalVms = totalVmsPerLane * numLanes;
  // Phase 1 (gateway replication) is mostly serial across nodes → ~2 min flat.
  // Phase 2 (lanes) runs N lanes in parallel-ish with a concurrency cap of ~3.
  const laneBatches = Math.ceil(numLanes / 3);
  const perBatchSec = 60 + totalVmsPerLane * 90;
  const estDeploySec = 120 + laneBatches * perBatchSec;

  return {
    components: items,
    totals: {
      llm_input_tokens:  items.reduce((s, i) => s + i.input_tokens, 0),
      llm_output_tokens: items.reduce((s, i) => s + i.output_tokens, 0),
      llm_calls:         items.reduce((s, i) => s + i.calls, 0),
      llm_total_usd:     totalUsd,
      vuln_app_already_cached: vulnAppAlreadyCached,
      vms: {
        per_lane: totalVmsPerLane,
        total: totalVms,
        breakdown: {
          challenge: vmsPerLane,
          attack_box: attackBoxes ? 1 : 0
        }
      },
      estimated_deploy_seconds: estDeploySec,
      estimated_deploy_minutes: Math.ceil(estDeploySec / 60)
    }
  };
}

module.exports = {
  MODEL_PRICING,
  DEFAULT_MODEL,
  PROFILE_TOKENS,
  VULN_APP_TOKENS,
  resolveModel,
  costFor,
  estimateProfileCost,
  estimateVulnAppCost,
  estimateDeployCost
};
