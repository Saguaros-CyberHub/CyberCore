/**
 * ai/examples/index.js — Inline answer-key (example) generator.
 * ============================================================================
 * For each Part 1-8 the instructor wants generated, we build a focused
 * prompt from PART_DEFINITIONS + profile context, fan out to Claude in
 * parallel, then INSERT each result directly into assessment_progress.
 *
 * Generation runs as background fire-and-forget so the instructor's HTTP
 * request returns immediately. Progress
 * tracking via the existing in-memory `activeGenerationJobs` Map in
 * instructor.js continues to work.
 */

const llm = require('../../../../../../src/utils/llm-client');
const { pool } = require('../../utils/db');

// ─── System prompt — cached across all parts of a single batch ────────────

const SYSTEM_PROMPT = `You are generating answer-key content for a Clinic-in-a-Box cybersecurity assessment course. The course has 8 numbered parts, each with several "options" (deliverable types). For one given option you must produce realistic, complete deliverable content that an instructor could share with students as a high-quality example.

Output format — STRICT JSON ONLY (no markdown, no code fences, no prose around it):

{
  "deliverables": {
    "<option_key>": {
      "title": "string (the option name)",
      "content": "string (the actual deliverable content, fully written out, ready to share)"
    }
    // ...one entry per requested option_key
  }
}

Rules:
- "content" must be substantive — multi-paragraph prose, tables (use markdown table syntax inside the string), bulleted lists where appropriate. Treat it as a sample submission an instructor would grade.
- Reference the actual company name, industry, assets, and stakeholders from the profile context. Don't write generic templates.
- Keep each deliverable's content under ~1500 words.
- Do NOT include any markdown wrapping, code fences, or commentary outside the JSON object.
`;

// ─── Per-part user prompt builder ────────────────────────────────────────

function buildContextSummary(profileContext) {
  const lines = [
    `Company: ${profileContext.company_name || 'Organization'}`,
    `Industry: ${profileContext.industry || 'General'}`,
    `Client type: ${profileContext.client_type || 'SMB'}`,
    `Difficulty: ${profileContext.difficulty || 'intermediate'}`,
    profileContext.hq_city ? `Location: ${profileContext.hq_city}` : '',
    `Employees: ${profileContext.employee_count || 'unknown'}`,
    `Endpoints: ${profileContext.endpoint_count || 'unknown'}`
  ].filter(Boolean);

  // Trim large embedded objects so we stay in budget
  if (profileContext.network) {
    const net = profileContext.network;
    lines.push(`Network: public=${net.public_ip || '?'}, subnets=${(net.subnets || []).map(s => s.name).join(',')}, assets=${(net.assets || []).length}`);
    const servers = (net.assets || []).filter(a => a.role === 'server').slice(0, 6);
    if (servers.length) lines.push(`Key servers: ${servers.map(s => `${s.hostname} (${s.os})`).join('; ')}`);
  }
  if (profileContext.it_environment) {
    const it = profileContext.it_environment;
    lines.push(`Delivery: ${it.delivery || 'Hybrid'}`);
    if (it.endpoint_protection?.product) lines.push(`EDR: ${it.endpoint_protection.product}`);
    if (it.backups?.method) lines.push(`Backups: ${it.backups.method}, ${it.backups.frequency || ''}`);
    if (Array.isArray(it.saas) && it.saas.length) {
      lines.push(`SaaS: ${it.saas.slice(0, 5).map(s => s.name || s).join(', ')}`);
    }
  }
  if (profileContext.threat_profile?.scenarios?.length) {
    lines.push(`Known scenarios: ${profileContext.threat_profile.scenarios.slice(0, 3).map(s => s.name).join('; ')}`);
  }
  if (profileContext.compliance_frameworks) {
    lines.push(`Compliance: ${JSON.stringify(profileContext.compliance_frameworks)}`);
  }
  return lines.join('\n');
}

function buildPartPrompt(partNumber, partDef, profileContext) {
  const optionsText = partDef.options.map(opt =>
    `- option_key: "${opt.key}"\n  name: "${opt.name}"\n  deliverables:\n${opt.deliverables.map(d => `    - ${d}`).join('\n')}`
  ).join('\n\n');

  return `PART ${partNumber}: ${partDef.name}

COMPANY CONTEXT:
${buildContextSummary(profileContext)}

GENERATE deliverable content for EACH of the following options:

${optionsText}

Output JSON with one entry per option_key under "deliverables". Each entry's "content" should be a complete, instructor-ready answer-key example tailored to the company context above.`;
}

// ─── Generate one part ───────────────────────────────────────────────────

async function generateOnePart({ partNumber, partDef, profileContext, model, label }) {
  const startedAt = Date.now();
  try {
    const { value, usage, latencyMs } = await llm.generateJson({
      model,
      system: llm.cachedSystem(SYSTEM_PROMPT),
      messages: [{ role: 'user', content: buildPartPrompt(partNumber, partDef, profileContext) }],
      max_tokens: 8192,
      temperature: 0.7,
      label: `${label}:p${partNumber}`
    });
    return {
      ok: true,
      partNumber,
      partName: partDef.name,
      deliverables: value.deliverables || {},
      usage,
      latencyMs,
      optionKeys: partDef.options.map(o => o.key)
    };
  } catch (err) {
    console.error(`[ai/examples] Part ${partNumber} failed: ${err.message}`);
    return { ok: false, partNumber, partName: partDef.name, error: err.message, latencyMs: Date.now() - startedAt };
  }
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Generate answer-key content for the requested parts and INSERT each into
 * assessment_progress.
 *
 * @param {object} args
 * @param {string} args.profileId
 * @param {string} args.userId
 * @param {object} args.profileContext
 * @param {Array<number>} args.parts             which part numbers to generate (1-8 subset)
 * @param {object} args.partDefinitions          full PART_DEFINITIONS map
 * @param {string} [args.model]
 * @returns {Promise<{success, parts_succeeded, parts_failed, total_time_ms}>}
 */
async function generateExamples({ profileId, userId, profileContext, parts, partDefinitions, model }) {
  const label = `examples:${profileId?.slice(0, 8) || 'na'}`;
  const startedAt = Date.now();

  const partsToRun = (parts || []).filter(n => partDefinitions[n]);
  if (partsToRun.length === 0) {
    return { success: true, parts_succeeded: 0, parts_failed: 0, total_time_ms: 0 };
  }

  console.log(`[ai/examples] Generating parts ${partsToRun.join(',')} for profile ${profileId} (model=${model || llm.DEFAULT_MODEL})`);

  // Fan out — global semaphore in llm-client caps concurrency.
  const optsList = partsToRun.map(partNumber => ({
    partNumber,
    partDef: partDefinitions[partNumber],
    profileContext,
    model,
    label
  }));

  // Run in parallel (custom — generateParallel is for generate calls; here
  // each task includes its own validation + DB write, so we Promise.all manually
  // and let llm-client's semaphore throttle the underlying messages.create calls).
  const results = await Promise.all(optsList.map(opt => generateOnePart(opt)));

  // Persist each successful result
  let succeeded = 0, failed = 0;
  for (const r of results) {
    if (!r.ok) { failed++; continue; }
    try {
      const content = JSON.stringify(r.deliverables);
      const outputOption = JSON.stringify(r.optionKeys);
      const optionNames = r.optionKeys.join(', ');
      await pool.query(`
        INSERT INTO assessment_progress
          (user_id, profile_id, part_number, part_name, content, output_option, output_option_name, status)
        VALUES ($1, $2, $3, $4, $5, $6, $7, 'reviewed')
        ON CONFLICT (user_id, profile_id, part_number) DO UPDATE SET
          content = EXCLUDED.content,
          output_option = EXCLUDED.output_option,
          output_option_name = EXCLUDED.output_option_name,
          status = 'reviewed',
          updated_at = NOW()
      `, [userId, profileId, r.partNumber, r.partName, content, outputOption, optionNames]);
      succeeded++;
    } catch (dbErr) {
      console.error(`[ai/examples] DB write failed for part ${r.partNumber}: ${dbErr.message}`);
      failed++;
    }
  }

  const totalMs = Date.now() - startedAt;
  console.log(`[ai/examples] Done: ${succeeded} ok / ${failed} failed in ${(totalMs / 1000).toFixed(1)}s`);
  return { success: failed === 0, parts_succeeded: succeeded, parts_failed: failed, total_time_ms: totalMs };
}

module.exports = {
  generateExamples,
  buildPartPrompt,           // exported for testing
  buildContextSummary,
  SYSTEM_PROMPT
};
