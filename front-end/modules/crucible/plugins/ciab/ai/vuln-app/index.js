/**
 * ai/vuln-app/index.js — Multi-stage AI vulnerable-app pipeline.
 * ============================================================================
 * Replaces the prior single-shot vuln-app generator. Produces CyberSaguaros-
 * caliber labs: 5-10 themed pages, 3-5 stage attack chain, varied vuln
 * categories (not just OWASP Top-10), tech stack matched to the company.
 *
 *   Stage 1: CONCEPT_DESIGN — one Claude call, returns the full app spec
 *   Stage 2: FILE_GENERATOR — fan-out in parallel, one Claude call per page
 *   Stage 3: INSTALL_GEN    — one Claude call, returns Dockerfile + install_script
 *
 * The final output matches the legacy shape so the downstream lane-deploy
 * orchestrator (which writes source_tree files via guest agent then runs
 * install_script) doesn't change.
 */

const llm = require('../../../../../../src/utils/llm-client');
const {
  CONCEPT_SYSTEM_PROMPT,
  FILE_GEN_SYSTEM_PROMPT,
  INSTALL_SYSTEM_PROMPT,
  buildConceptUserPrompt,
  buildFileUserPrompt,
  buildInstallUserPrompt
} = require('./prompts');

// ─── Stage 1: design the app ───────────────────────────────────────────────

async function designConcept({ profile, webServer, deliveryMode, llmModel }) {
  const { value, usage, latencyMs } = await llm.generateJson({
    model: llmModel,
    system: llm.cachedSystem(CONCEPT_SYSTEM_PROMPT),
    messages: [{ role: 'user', content: buildConceptUserPrompt({ profile, webServer, deliveryMode }) }],
    max_tokens: 8192,
    temperature: 0.8,           // higher to encourage variety across companies
    label: `vuln-app:concept:${profile.id?.slice(0,8) || 'na'}`
  });

  // Basic shape validation — caller can decide what to do if anything is missing
  if (!value || !Array.isArray(value.page_inventory) || value.page_inventory.length === 0) {
    throw new Error('Concept design returned no page_inventory');
  }
  if (!Array.isArray(value.attack_chain) || value.attack_chain.length === 0) {
    throw new Error('Concept design returned no attack_chain');
  }
  return { concept: value, usage, latencyMs };
}

// ─── Stage 2: generate every page in parallel ─────────────────────────────

async function generateAllFiles({ concept, llmModel, profileIdShort }) {
  const pages = concept.page_inventory.filter(p => p && p.path);
  if (pages.length === 0) return { files: [], totalUsage: {}, fileErrors: [] };

  const optsList = pages.map(pageSpec => ({
    model: llmModel,
    // Cache the file-gen system prompt across all N calls — big input savings
    // since each call also includes the same `concept` JSON in the user prompt.
    system: llm.cachedSystem(FILE_GEN_SYSTEM_PROMPT),
    messages: [{ role: 'user', content: buildFileUserPrompt({ concept, pageSpec }) }],
    max_tokens: 8192,
    temperature: 0.6,
    label: `vuln-app:file:${pageSpec.path.replace(/[^a-z0-9]/gi, '_').slice(0, 20)}:${profileIdShort}`
  }));

  const results = await llm.generateParallel(optsList, { json: true });
  const files = [];
  const fileErrors = [];
  let totalIn = 0, totalOut = 0, totalCacheRead = 0;

  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    const page = pages[i];
    if (!r.ok) {
      fileErrors.push({ path: page.path, error: r.error.message });
      continue;
    }
    const fileSpec = r.value.value;
    if (!fileSpec || !fileSpec.content || typeof fileSpec.content !== 'string') {
      fileErrors.push({ path: page.path, error: 'no content field in file-gen response' });
      continue;
    }
    files.push({
      path: fileSpec.path || page.path,
      content: fileSpec.content,
      vuln_notes: fileSpec.vuln_notes || null,
      vuln_role: page.vuln_role || 'none'
    });

    const u = r.value.usage || {};
    totalIn += u.input_tokens || 0;
    totalOut += u.output_tokens || 0;
    totalCacheRead += u.cache_read_input_tokens || 0;
  }

  return {
    files,
    fileErrors,
    totalUsage: { input_tokens: totalIn, output_tokens: totalOut, cache_read_input_tokens: totalCacheRead }
  };
}

// ─── Stage 3: install script + Dockerfile ─────────────────────────────────

async function generateInstall({ concept, deliveryMode, sourceTreeFileList, llmModel, profileIdShort }) {
  const { value, usage } = await llm.generateJson({
    model: llmModel,
    system: llm.cachedSystem(INSTALL_SYSTEM_PROMPT),
    messages: [{
      role: 'user',
      content: buildInstallUserPrompt({ concept, deliveryMode, sourceTreeFileList })
    }],
    max_tokens: 4096,
    temperature: 0.5,
    label: `vuln-app:install:${profileIdShort}`
  });
  if (!value || !value.install_script) {
    throw new Error('Install generator returned no install_script');
  }
  return {
    install_script: value.install_script,
    dockerfile: value.dockerfile || null,
    post_install_notes: value.post_install_notes || null,
    usage
  };
}

// ─── Public: orchestrate all three stages ─────────────────────────────────

/**
 * Generate a complete vulnerable web app via the multi-stage pipeline.
 *
 * @param {object} args
 * @param {object} args.profile        profiles row + .assets[] + .stakeholders[]
 * @param {object} [args.webServer]    web-server asset from the profile (or null → standalone_vm)
 * @param {'docker'|'apache_vhost'|'standalone_vm'} args.deliveryMode
 * @param {string} [args.llmModel]
 * @returns {Promise<{source_tree, dockerfile, install_script, generation_meta}>}
 */
async function generateVulnApp({ profile, webServer, deliveryMode, llmModel }) {
  const profileIdShort = profile.id?.slice(0, 8) || 'na';
  const startedAt = Date.now();

  console.log(`🎯 [vuln-app] Stage 1: design concept for profile ${profileIdShort} (${profile.company_name})`);
  const { concept, usage: stage1Usage } = await designConcept({ profile, webServer, deliveryMode, llmModel });
  console.log(`   → ${concept.page_inventory.length} pages, ${concept.attack_chain.length}-stage chain, stack: ${concept.tech_stack}`);

  console.log(`🎯 [vuln-app] Stage 2: generate ${concept.page_inventory.length} files in parallel`);
  const { files, fileErrors, totalUsage: stage2Usage } = await generateAllFiles({
    concept, llmModel, profileIdShort
  });
  if (files.length === 0) {
    throw new Error(`All ${concept.page_inventory.length} file generations failed: ${fileErrors.map(e => e.path).join(', ')}`);
  }
  if (fileErrors.length > 0) {
    console.warn(`   ⚠ ${fileErrors.length}/${concept.page_inventory.length} files failed to generate (continuing with rest)`);
  }

  // Build source_tree (path → content map)
  const source_tree = {};
  for (const f of files) source_tree[f.path] = f.content;

  console.log(`🎯 [vuln-app] Stage 3: generate install script + Dockerfile`);
  const { install_script, dockerfile, post_install_notes, usage: stage3Usage } = await generateInstall({
    concept, deliveryMode, sourceTreeFileList: Object.keys(source_tree), llmModel, profileIdShort
  });

  const elapsedMs = Date.now() - startedAt;
  console.log(`✅ [vuln-app] Generated app for ${profile.company_name} in ${(elapsedMs/1000).toFixed(1)}s — ${files.length} files, ${concept.attack_chain.length} attack stages`);

  return {
    source_tree,
    dockerfile,
    install_script,
    generation_meta: {
      source: 'claude_multistage',
      pipeline_version: 2,
      title: concept.title,
      theme_summary: concept.theme_summary,
      tech_stack: concept.tech_stack,
      primary_language: concept.primary_language,
      attack_chain: concept.attack_chain,
      page_count: files.length,
      page_errors: fileErrors,
      post_install_notes,
      instructor_notes: concept.instructor_notes,
      elapsed_ms: elapsedMs,
      usage: {
        stage1: stage1Usage,
        stage2: stage2Usage,
        stage3: stage3Usage
      }
    }
  };
}

module.exports = {
  generateVulnApp,
  designConcept,
  generateAllFiles,
  generateInstall
};
