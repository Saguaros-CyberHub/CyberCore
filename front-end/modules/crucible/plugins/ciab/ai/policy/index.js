/**
 * ai/policy/index.js — Inline policy-document generator.
 * ============================================================================
 * Input:  the loaded profile JSON + difficulty + optional model
 * Output: { policies: [{name, slug, html, generation_time_ms, usage}], total_count, ... }
 *
 * Algorithm:
 *   1. Walk the student_view.raw.threats structure to extract org/it/network/governance.
 *   2. For each policy in governance.policies_present, build a prompt via prompts.js.
 *   3. Fan out all prompts in parallel via llm.generateParallel — concurrency capped by
 *      llm-client's global semaphore (no per-call sleeping).
 *   4. Clean each response (strip <think> tags, code fences, leading prose).
 *   5. Wrap in the corporate HTML template and return.
 *
 * Each prompt reuses the SAME big system prompt → Anthropic prompt cache kicks in
 * after the first call, saving ~90% on input tokens for the rest of the batch.
 */

const llm = require('../../../../../../src/utils/llm-client');
const { SYSTEM_PROMPT, buildUserPrompt } = require('./prompts');

// ─── Context extraction ────────────────────────────────────────────────────
/**
 * Walk the profile JSON and pull out the structured context the prompts need.
 *
 * @param {object} profileJson  loaded JSON (student_view.* structure)
 * @param {object} [defaults]   { difficulty? }
 * @returns {object}            normalized context object
 */
function buildContext(profileJson, defaults = {}) {
  const raw = profileJson?.student_view?.raw || {};
  const threats = raw.threats || {};
  const org = threats.organization || profileJson.organization || {};
  const gov = threats.profiles?.governance_and_policy || profileJson.governance || {};
  const it = threats.it_environment || raw.it?.it_environment || profileJson.it_environment || {};
  const net = threats.network || raw.network || {};

  const servers = (it.servers || []).slice(0, 5);
  const saas = (it.saas || []).slice(0, 5);
  const compliance = threats.profiles?.compliance_focus || [];

  return {
    company_name: org.company_name || 'Organization',
    industry: org.industry || 'General',
    employees_total: org.employees_total || 50,
    hq_city: org.hq_city || '',
    domain: org.domain_public || '',

    framework: gov.framework || 'Ad-hoc',
    policy_enforcement: gov.policy_enforcement || 'Informal',
    policies_present: gov.policies_present || [],
    policies_missing: gov.policies_missing || [],
    risk_tolerance: gov.risk_tolerance || 'Moderate',
    deliberate_weaknesses: gov.deliberate_weaknesses || [],

    endpoint_protection: it.endpoint_protection || {},
    remote_access: it.remote_access || {},
    backups: it.backups || {},
    patch_management: it.patch_management || {},
    servers,
    saas,
    delivery: it.delivery || 'Hybrid',
    physical_security: it.physical_security || {},
    vendor_risk: it.vendor_risk || {},
    vendor_dependencies: (it.vendor_dependencies || []).slice(0, 5),

    firewall: net.firewall || {},
    subnets: (net.subnets || []).slice(0, 4),

    compliance_focus: compliance,
    business_continuity: org.business_continuity || {},

    difficulty: defaults.difficulty || profileJson.difficulty || 'intermediate',

    // Derived strings used by the prompt extras
    serverList: servers.map(s => `${s.hostname} (${s.os || 'N/A'}, ${s.role || 'server'})`).join(', ') || 'standard servers',
    saasList: saas.map(s => s.name || s.app || s).join(', ') || 'standard SaaS applications',
    complianceStr: compliance.length ? compliance.join(', ') : 'industry best practices'
  };
}

// ─── Response cleanup ──────────────────────────────────────────────────────
function cleanResponse(text) {
  let s = String(text || '').trim();
  // Strip <think>...</think> blocks (legacy from Qwen days; harmless if absent)
  s = s.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
  // Strip ```html``` or ``` code fences
  s = s.replace(/^```html?\s*\n?/i, '').replace(/\n?```\s*$/i, '').trim();
  // Strip any chatter before the first <h2>
  const h2 = s.indexOf('<h2>');
  if (h2 > 0 && h2 < 400) s = s.substring(h2);
  return s;
}

// ─── HTML document wrapper ────────────────────────────────────────────────
function esc(str) {
  if (str == null) return '';
  return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;')
                    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function buildPolicyHTML(title, companyName, bodyContent, { versionMajor = 1, versionMinor = 0, effectiveDaysAgo = 0 } = {}) {
  const now = Date.now();
  const effectiveDate = new Date(now - effectiveDaysAgo * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);
  const lastReviewed = effectiveDate;
  const nextReview = new Date(now - effectiveDaysAgo * 24 * 60 * 60 * 1000 + 365 * 24 * 60 * 60 * 1000).toISOString().slice(0, 10);

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — ${esc(companyName)}</title>
<style>
  @media print { body { padding: 20px; } .no-print { display: none; } }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', 'Helvetica Neue', Arial, sans-serif; max-width: 850px; margin: 0 auto; padding: 40px 50px; color: #1a202c; line-height: 1.7; background: #fff; }
  .doc-header { border-bottom: 3px solid #1a365d; padding-bottom: 20px; margin-bottom: 30px; }
  .doc-header .org-name { color: #718096; font-size: 0.85em; text-transform: uppercase; letter-spacing: 2px; margin-bottom: 4px; }
  .doc-header h1 { color: #1a365d; font-size: 1.7em; margin-bottom: 8px; font-weight: 700; }
  .doc-meta { display: flex; gap: 12px; flex-wrap: wrap; }
  .doc-meta span { background: #f7fafc; border: 1px solid #e2e8f0; padding: 3px 12px; border-radius: 4px; font-size: 0.8em; color: #4a5568; }
  h2 { color: #2c5282; margin-top: 32px; margin-bottom: 12px; font-size: 1.2em; border-bottom: 1px solid #e2e8f0; padding-bottom: 6px; }
  h3 { color: #2d3748; margin-top: 22px; margin-bottom: 8px; font-size: 1.05em; }
  p { margin-bottom: 12px; }
  ul, ol { margin: 8px 0 12px 24px; }
  li { margin-bottom: 4px; }
  table { width: 100%; border-collapse: collapse; margin: 14px 0; font-size: 0.92em; }
  th { background: #1a365d; color: #fff; padding: 9px 12px; text-align: left; font-weight: 600; }
  td { padding: 8px 12px; border-bottom: 1px solid #e2e8f0; }
  tr:nth-child(even) td { background: #f7fafc; }
  .doc-footer { margin-top: 44px; padding-top: 20px; border-top: 2px solid #1a365d; color: #718096; font-size: 0.82em; }
  .doc-footer p { margin-bottom: 4px; }
  .sig-block { display: flex; gap: 40px; margin-top: 20px; }
  .sig-line { flex: 1; border-top: 1px solid #a0aec0; padding-top: 6px; font-size: 0.85em; color: #718096; }
</style>
</head>
<body>
<div class="doc-header">
  <div class="org-name">${esc(companyName)}</div>
  <h1>${esc(title)}</h1>
  <div class="doc-meta">
    <span>Version ${versionMajor}.${versionMinor}</span>
    <span>Effective: ${effectiveDate}</span>
    <span>Last Reviewed: ${lastReviewed}</span>
    <span>Classification: Internal Use Only</span>
    <span>Review Cycle: Annual</span>
  </div>
</div>

${bodyContent}

<div class="doc-footer">
  <p><strong>Document Owner:</strong> Information Security Department</p>
  <p><strong>Approved By:</strong> Chief Information Security Officer / Executive Leadership</p>
  <p><strong>Next Review Date:</strong> ${nextReview}</p>
  <div class="sig-block">
    <div class="sig-line">Prepared By — Information Security</div>
    <div class="sig-line">Approved By — Executive Sponsor</div>
  </div>
  <p style="margin-top: 18px; font-style: italic; color: #a0aec0;">Simulated policy document generated for Clinic-in-a-Box cybersecurity training exercise.</p>
</div>
</body>
</html>`;
}

function slugify(name) {
  return String(name).toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/-+$/, '').replace(/^-+/, '');
}

// ─── Public API ────────────────────────────────────────────────────────────
/**
 * Generate policy documents for a profile.
 *
 * @param {object} args
 * @param {object} args.profileJson         loaded profile JSON
 * @param {string} [args.difficulty]        overrides profile.difficulty
 * @param {string} [args.model]             llm-client alias or canonical model ID
 * @param {string} args.profileId           UUID — only used for log labels
 * @returns {Promise<object>}               {success, profile_id, company_name, policies:[...], total_count, total_generation_time_ms, generated_at}
 */
async function generatePolicies({ profileJson, difficulty, model, profileId } = {}) {
  if (!profileJson) {
    throw new Error('generatePolicies: profileJson required');
  }

  const ctx = buildContext(profileJson, { difficulty });

  if (!ctx.policies_present || ctx.policies_present.length === 0) {
    return {
      success: true,
      profile_id: profileId,
      company_name: ctx.company_name,
      policies: [],
      total_count: 0,
      total_generation_time_ms: 0,
      generated_at: new Date().toISOString(),
      message: 'No policies_present in profile — nothing to generate'
    };
  }

  console.log(`📋 [ai/policy] Generating ${ctx.policies_present.length} policies for ${ctx.company_name} (model=${model || llm.DEFAULT_MODEL})`);

  // Fan out: one LLM call per policy. They share the same SYSTEM_PROMPT so
  // prompt caching applies after the first call. Concurrency capped by the
  // global semaphore in llm-client.
  const optsList = ctx.policies_present.map(policyName => ({
    model,
    system: llm.cachedSystem(SYSTEM_PROMPT),
    messages: [{ role: 'user', content: buildUserPrompt(policyName, ctx) }],
    max_tokens: 4096,
    temperature: 0.7,
    label: `policy:${slugify(policyName)}:${profileId ? profileId.slice(0, 8) : 'na'}`
  }));

  const startedAt = Date.now();
  const results = await llm.generateParallel(optsList);
  const totalTime = Date.now() - startedAt;

  const policies = results.map((r, i) => {
    const name = ctx.policies_present[i];
    const slug = slugify(name);
    if (!r.ok) {
      return { name, slug, html: null, error: r.error.message, generation_time_ms: 0 };
    }
    const bodyContent = cleanResponse(r.value.text);
    // Vary version and effective date per policy so documents look like a
    // real policy library maintained at different times, not a bulk export.
    const versionMajor = i % 3 === 0 ? 2 : 1;
    const versionMinor = [0, 1, 2, 0, 1][i % 5];
    const effectiveDaysAgo = [0, 90, 180, 270, 45, 135, 365][i % 7];
    const html = buildPolicyHTML(name, ctx.company_name, bodyContent, { versionMajor, versionMinor, effectiveDaysAgo });
    return {
      name, slug, html,
      generation_time_ms: r.value.latencyMs,
      usage: r.value.usage,
      error: null
    };
  });

  const succeeded = policies.filter(p => !p.error);
  console.log(`📋 [ai/policy] ${succeeded.length}/${policies.length} succeeded in ${(totalTime / 1000).toFixed(1)}s`);

  return {
    success: true,
    profile_id: profileId,
    company_name: ctx.company_name,
    policies,
    total_count: succeeded.length,
    total_generation_time_ms: totalTime,
    generated_at: new Date().toISOString()
  };
}

module.exports = {
  generatePolicies,
  buildContext,        // exported for testing + reuse
  cleanResponse,
  buildPolicyHTML,
  slugify
};
