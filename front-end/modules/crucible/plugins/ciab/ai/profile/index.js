/**
 * ai/profile/index.js — Inline AI profile generator (replaces N8N pipeline).
 * ============================================================================
 * Replaces the entire E0→E1→E2→E3→E4 N8N flow plus the four parallel A2/B2/C2/D3
 * Claude API nodes. Single entrypoint: generateProfile({...config}) → {profile_id}.
 *
 * Pipeline:
 *   1. Resolve client-type template + seed (analog of E0).
 *   2. Run A (organization) + B (IT) + C (network) in parallel via Claude.
 *      D (threats) is sequential after C since it references network hostnames.
 *   3. Validate + autofill each branch (workstations, dept totals, dedup).
 *   4. Combine into student_view + instructor_view (analog of S1).
 *   5. Write JSON to disk under front-end/profiles/.
 *   6. INSERT into profiles table.
 *   7. Return { id, run_id, json_file_path, company_name }.
 *
 * Prompt caching applies on all four system prompts → 2nd+ profile generated
 * within a 5-min window pays ~10% input cost on the system blocks.
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const llm = require('../../../../../../src/utils/llm-client');
const { pool } = require('../../utils/db');
const {
  pickEmployeeCount,
  buildOrgPrompt,
  buildItPrompt,
  buildNetworkPrompt,
  buildThreatPrompt,
  buildNetworkSummary,
  buildFlavorBundle
} = require('./prompts');
const { buildPrefilledIntake, buildIntakeV11Payload } = require('../../utils/profile-to-intake');
const {
  validateOrg,
  validateIt,
  validateNetwork,
  validateThreat
} = require('./validators');
const { renderProfileHtml } = require('./render');

// ─── Client-type templates (analog of N8N P0/E0 template tables) ──────────

const CLIENT_TYPE_TEMPLATES = {
  SMB: {
    clientTypeName: 'Small-Medium Business',
    industries: ['Professional Services', 'Retail', 'Manufacturing'],
    naics_hint: '541990',
    risks: ['phishing', 'ransomware', 'insider threats'],
    compliance: ['Industry Standards'],
    criticalSystems: ['CRM', 'Email', 'Accounting']
  },
  NonProfit: {
    clientTypeName: 'Non-Profit Organization',
    industries: ['Education', 'Healthcare', 'Social Services'],
    naics_hint: '813219',
    risks: ['donor data breach', 'phishing', 'budget constraints'],
    compliance: ['IRS 990', 'state regs'],
    criticalSystems: ['Donor Database', 'Email', 'Volunteer Portal']
  },
  Utility_IT_OT: {
    clientTypeName: 'Utility (IT/OT)',
    industries: ['Water', 'Power', 'Gas Distribution'],
    naics_hint: '221310',
    risks: ['SCADA compromise', 'OT lateral movement', 'ransomware'],
    compliance: ['NERC CIP', 'TSA'],
    criticalSystems: ['SCADA', 'Historian', 'Billing', 'GIS']
  },
  K12: {
    clientTypeName: 'K-12 School District',
    industries: ['Education'],
    naics_hint: '611110',
    risks: ['student data breach', 'ransomware', 'phishing'],
    compliance: ['FERPA', 'COPPA', 'CIPA'],
    criticalSystems: ['SIS', 'LMS', 'Email', 'Network Services']
  }
};

function buildConfig({
  client_type, industry, difficulty, maturity, delivery, employees,
  // Extended fields (match user-facing generator form)
  company_name, domain, hq_city,
  framework,
  stakeholder_count,
  endpoint_count, endpoint_range,
  firewall_rules_range,
  weakness_range,
  cooperation, scaffolding,
  est_hours,
  custom_seed,
  custom_config
} = {}) {
  const tmpl = CLIENT_TYPE_TEMPLATES[client_type] || CLIENT_TYPE_TEMPLATES.SMB;
  const chosenIndustry = industry || tmpl.industries[0];

  // employees can be a number, a {min,max}, or {min,max} via custom_config
  const empSource = employees ?? custom_config?.employees ?? 50;
  const empRange = (typeof empSource === 'object' && empSource !== null && 'min' in empSource)
    ? empSource
    : { min: empSource, max: empSource };

  // Stakeholder count: range or single
  const stakSource = stakeholder_count ?? custom_config?.stakeholder_count ?? 5;
  const stakRange = (typeof stakSource === 'object' && stakSource !== null && 'min' in stakSource)
    ? stakSource
    : { min: stakSource, max: stakSource };

  // Endpoint range default ~1.2x avg employees if not specified
  const avgEmp = Math.floor((empRange.min + empRange.max) / 2);
  const endpointRangeFinal = endpoint_range
    || custom_config?.endpoint_range
    || { min: Math.max(5, Math.floor(avgEmp * 0.8)), max: Math.max(20, Math.floor(avgEmp * 1.5)) };
  const endpointCountFinal = endpoint_count
    || custom_config?.endpoint_count
    || Math.floor((endpointRangeFinal.min + endpointRangeFinal.max) / 2);

  // RunId — honor custom seed if user supplied one
  const seedToken = custom_seed
    ? `RUN_${String(custom_seed).replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 24)}`
    : `RUN_${Date.now().toString(36).toUpperCase()}_${crypto.randomBytes(3).toString('hex').toUpperCase()}`;

  // Compliance list — if admin picked a specific framework, prepend it; else use industry defaults
  const complianceList = framework && framework !== 'None'
    ? [framework, ...tmpl.compliance.filter(c => c !== framework)]
    : (framework === 'None' ? [] : tmpl.compliance);

  // Public IP from RFC 5737 documentation range — never a real address
  const publicIp = `203.0.113.${10 + Math.floor(Math.random() * 240)}`;

  // Organization overrides — admin can set company name / domain / hq city explicitly
  const orgOverrides = {
    ...(custom_config?.organization_overrides || {}),
    ...(company_name ? { company_name } : {}),
    ...(domain ? { domain_public: domain } : {}),
    ...(hq_city ? { hq_city } : {})
  };

  // Difficulty-driven defaults for cooperation / weakness counts — admin can override
  const defaultCoop = difficulty === 'beginner' ? 'high' : difficulty === 'advanced' ? 'low' : 'moderate';
  const defaultWeakRange = difficulty === 'beginner' ? { min: 3, max: 5 }
                        : difficulty === 'advanced' ? { min: 6, max: 12 }
                        : { min: 3, max: 8 };

  return {
    config: {
      clientType: client_type || 'SMB',
      clientTypeName: tmpl.clientTypeName,
      organization_overrides: orgOverrides,
      challenge_network: custom_config?.challenge_network || null,
      network: { requiredSubnets: custom_config?.required_subnets || ['Management', 'Servers', 'Workstations', 'Guest'] }
    },
    seed: {
      run_id: seedToken,
      template: {
        industry: chosenIndustry,
        naics_hint: tmpl.naics_hint,
        risks: tmpl.risks,
        compliance: complianceList,
        criticalSystems: tmpl.criticalSystems
      },
      employees: empRange,
      endpoint_count: endpointCountFinal,
      endpoint_range: endpointRangeFinal,
      stakeholder_count: stakRange.max,                   // upper-bound used by prompts; range used by validators
      stakeholder_range: stakRange,
      maturity: maturity || 'Intermediate',
      delivery: delivery || 'Hybrid',
      difficulty: difficulty || 'intermediate',
      scaffolding: scaffolding || null,
      est_hours: est_hours || null,
      public_ip: publicIp,
      firewall_rules_range: firewall_rules_range || custom_config?.firewall_rules_range || { min: 8, max: 20 },
      weakness_range: weakness_range || custom_config?.weakness_range || defaultWeakRange,
      difficulty_settings: {
        stakeholder_cooperation: cooperation || defaultCoop,
        stakeholder_count: stakRange,
        deliberate_weaknesses: weakness_range || defaultWeakRange
      }
    }
  };
}

// ─── Run one branch ───────────────────────────────────────────────────────

async function runBranch({ name, systemPrompt, userPrompt, model, maxTokens, label }) {
  const startedAt = Date.now();
  try {
    const { value, usage, latencyMs } = await llm.generateJson({
      model,
      system: llm.cachedSystem(systemPrompt),
      messages: [{ role: 'user', content: userPrompt }],
      max_tokens: maxTokens,
      temperature: 0.7,
      label
    });

    // The prompt may return {error: 'cannot_comply', reason: ...} as a structured refusal
    if (value && value.error === 'cannot_comply') {
      return { branch: name, ok: false, error: `Model refused: ${value.reason || 'unknown'}`, durationMs: Date.now() - startedAt };
    }
    return { branch: name, ok: true, payload: value, usage, durationMs: Date.now() - startedAt };
  } catch (err) {
    return { branch: name, ok: false, error: err.message, durationMs: Date.now() - startedAt };
  }
}

// ─── Combine 4 branches into student_view + instructor_view ──────────────

function combineProfile({ orgPayload, itPayload, netPayload, threatPayload, config, seed, employeeCount }) {
  const org = orgPayload?.organization || {};
  const network = netPayload?.network || null;
  const tp = threatPayload?.threat_profile || null;

  // student_view — what students see; deliberate_weaknesses excluded from "quick"
  const studentView = {
    raw: {
      threats: {
        organization: org,
        network: network,
        it_environment: itPayload?.it_environment || null,
        threat_profile: tp,
        profiles: orgPayload?.profiles || null
      }
    },
    quick: {
      company_name: org.company_name,
      industry: org.industry,
      employees_total: org.employees_total || employeeCount,
      domain_public: org.domain_public,
      delivery: itPayload?.it_environment?.delivery,
      saas: itPayload?.it_environment?.saas,
      public_ip: network?.public_ip,
      subnets: network?.subnets,
      assets: network?.assets,
      top_threats: tp?.top_threats,
      scenarios: tp?.scenarios
    },
    stakeholders: (orgPayload?.stakeholders || []).map((s, i) => ({
      id: `stake_${i + 1}`,
      name: s.name,
      role: s.role,
      department: s.department || 'Executive',
      email: s.email,
      technical_fluency: s.technical_fluency || 'Medium',
      decision_power: s.decision_power || 'Advisory',
      communication_style: s.communication_style || 'Professional',
      concerns: s.concerns || [],
      likely_pushback: s.likely_pushback || [],
      persona: {
        signature_quote: s.signature_quote || '',
        information_they_can_provide: s.information_they_can_provide || [],
        information_they_lack: s.information_they_lack || []
      }
    })),
    meta: {
      profile_source: 'ai_generated',
      generated_at: new Date().toISOString(),
      run_id: seed.run_id,
      client_type: config.clientType,
      difficulty: seed.difficulty,
      cover_name: org.company_name
    }
  };

  // instructor_view — includes all the hidden stuff students need to discover
  const instructorView = {
    deliberate_weaknesses: {
      governance: orgPayload?.profiles?.governance_and_policy?.deliberate_weaknesses || [],
      it: itPayload?.it_environment?.deliberate_weaknesses || [],
      network: network?.deliberate_weaknesses || []
    },
    stakeholder_secrets: (orgPayload?.stakeholders || []).map(s => ({
      name: s.name,
      hidden_info: s.hidden_info || '',
      shadow_it_knowledge: s.shadow_it_knowledge || '',
      relationship_conflicts: s.relationship_conflicts || ''
    })),
    artifacts: threatPayload?.artifacts || []
  };

  return { student_view: studentView, instructor_view: instructorView };
}

// ─── Public API ──────────────────────────────────────────────────────────

/**
 * Generate a profile end-to-end. Writes the JSON file + profiles row, returns
 * the row (matches the shape the existing /api/profiles/generate route returns).
 *
 * @param {object} args
 * @param {string} args.user_id
 * @param {string} [args.client_type='SMB']
 * @param {string} [args.industry]
 * @param {string} [args.difficulty='intermediate']
 * @param {string} [args.maturity]
 * @param {string} [args.delivery]
 * @param {number|object} [args.employees]
 * @param {string} [args.llmModel]
 * @param {number} [args.temperature]
 * @param {object} [args.custom_config]
 * @returns {Promise<object>} profiles row { id, company_name, run_id, json_file_path, ... }
 */
async function generateProfile(args) {
  const { user_id, llmModel, temperature, onProgress, ...rest } = args;
  if (!user_id) throw new Error('generateProfile: user_id required');

  const { config, seed } = buildConfig(rest);
  const employeeCount = pickEmployeeCount(seed);
  const labelBase = `profile:${seed.run_id.slice(-6)}`;

  const reportStep = (step, percent, message) => {
    if (typeof onProgress === 'function') {
      try { onProgress({ step, percent, message, run_id: seed.run_id }); }
      catch (e) { console.warn('[ai/profile] onProgress callback threw:', e.message); }
    }
  };

  console.log(`🚀 [ai/profile] Generating ${config.clientType} profile for user ${user_id} (run ${seed.run_id})`);
  reportStep('start', 5, 'Starting generation…');

  // Stage 1: A + B + C in parallel (D needs network output).
  // Higher temperatures + per-branch flavor anchors (vendor, hostname theme,
  // EDR product, firewall, threat-actor archetype) injected into each
  // user prompt break Claude's convergence on identical-looking profiles.
  // The deterministic company name + stakeholder names handle the most
  // visible duplication; flavor anchors break the rest.
  reportStep('branches_parallel', 15, 'Generating organization, IT environment, and network in parallel…');
  const branchTemp = temperature ?? 0.9;
  const orgTemp    = Math.min(1, branchTemp + 0.05);
  const stage1 = await llm.generateParallel([
    {
      ...buildToOptionsObj(buildOrgPrompt({ config, seed, employeeCount }), { model: llmModel, maxTokens: 8192, label: `${labelBase}:org`, temperature: orgTemp }),
    },
    {
      ...buildToOptionsObj(buildItPrompt({ config, seed, employeeCount }), { model: llmModel, maxTokens: 6144, label: `${labelBase}:it`, temperature: branchTemp }),
    },
    {
      ...buildToOptionsObj(buildNetworkPrompt({ config, seed }), { model: llmModel, maxTokens: 8192, label: `${labelBase}:network`, temperature: branchTemp }),
    }
  ], { json: true });

  const [orgResult, itResult, netResult] = stage1;
  if (!orgResult.ok) throw new Error(`Organization branch failed: ${orgResult.error.message}`);
  if (!itResult.ok)  throw new Error(`IT branch failed: ${itResult.error.message}`);
  if (!netResult.ok) throw new Error(`Network branch failed: ${netResult.error.message}`);

  reportStep('branches_done', 55, 'Organization, IT, and network ready — validating…');

  const orgPayload = orgResult.value.value;
  const itPayload  = itResult.value.value;
  const netPayload = netResult.value.value;

  // Validate / autofill A, B, C
  const orgV = validateOrg(orgPayload, { employeeCount });
  const itV  = validateIt(itPayload);
  const netV = validateNetwork(netPayload, { endpointCount: seed.endpoint_count });
  for (const w of [...orgV.warnings, ...itV.warnings, ...netV.warnings]) {
    console.warn(`⚠️  [ai/profile] ${w}`);
  }

  // Stage 2: D (threats) — depends on network output
  reportStep('threats', 65, 'Generating threat scenarios + MITRE attack chains…');
  const networkSummary = buildNetworkSummary(netV.payload);
  const threatPromptObj = buildThreatPrompt({ config, seed, networkSummary });
  const threatResult = await llm.generateJson({
    model: llm.resolveModel(llmModel),
    system: llm.cachedSystem(threatPromptObj.systemPrompt),
    messages: [{ role: 'user', content: threatPromptObj.userPrompt }],
    max_tokens: 8192,
    temperature: branchTemp,
    label: `${labelBase}:threats`
  });

  let threatPayload = threatResult.value;
  if (threatPayload && threatPayload.error === 'cannot_comply') {
    console.warn(`⚠️  [ai/profile] Threat branch refused: ${threatPayload.reason}`);
    threatPayload = { threat_profile: null, artifacts: [] };
  }
  const tpV = validateThreat(threatPayload, { networkAssets: netV.payload?.network?.assets });
  for (const w of tpV.warnings) console.warn(`⚠️  [ai/profile] ${w}`);

  reportStep('combining', 80, 'Combining branches into student + instructor views…');

  // Combine
  const combined = combineProfile({
    orgPayload: orgV.payload,
    itPayload: itV.payload,
    netPayload: netV.payload,
    threatPayload: tpV.payload,
    config,
    seed,
    employeeCount
  });

  // Build pre-filled intake form (V8 schema) + v1.1 intake payload — both
  // are purely deterministic mappings from the AI profile + flavor anchors
  // + IG1 derivation. Students get a populated intake AND a populated risk
  // assessment baseline instead of starting from blank.
  reportStep('intake_prefill', 88, 'Building pre-filled intake form + IG1 baseline…');
  let intakeV11 = null;
  try {
    const flavor = buildFlavorBundle(seed.run_id, seed.stakeholder_count || 5);
    const prefillPayloads = {
      organization:    orgV.payload?.organization || {},
      it_environment:  itV.payload?.it_environment || {},
      network:         netV.payload?.network || {},
      threat_profile:  tpV.payload?.threat_profile || null,
      profiles:        orgV.payload?.profiles || {},
      stakeholders:    orgV.payload?.stakeholders || [],
      compliance_frameworks: seed.template?.compliance || [],
      vendor_flavor:   flavor.vendor_flavor,
      maturity:        seed.maturity,
      run_id:          seed.run_id
    };
    combined.prefilled_intake_form = buildPrefilledIntake(prefillPayloads);
    intakeV11 = buildIntakeV11Payload(prefillPayloads);
    console.log(`📝 [ai/profile] Pre-filled intake form: ${combined.prefilled_intake_form._meta.ig1_coverage_pct}% IG1 coverage (${combined.prefilled_intake_form._meta.ig1_totals.yes}/${combined.prefilled_intake_form._meta.ig1_totals.partial}/${combined.prefilled_intake_form._meta.ig1_totals.no} yes/partial/no)`);
  } catch (prefillErr) {
    console.warn(`⚠️  [ai/profile] Intake prefill failed (continuing without): ${prefillErr.message}`);
  }

  reportStep('writing_files', 92, 'Writing JSON + HTML deliverables…');
  // Write JSON + HTML to disk
  const profilesDir = path.join(process.cwd(), 'profiles');
  if (!fs.existsSync(profilesDir)) {
    fs.mkdirSync(profilesDir, { recursive: true });
    console.log(`📁 [ai/profile] Created profiles dir: ${profilesDir}`);
  }
  const safeName = (combined.student_view.quick.company_name || 'profile').replace(/[^a-z0-9]/gi, '_').toLowerCase();
  const baseName = `client_profile_${seed.run_id}_${safeName.slice(0, 24)}`;
  const jsonFilename = `${baseName}.json`;
  const htmlFilename = `${baseName}.html`;
  const jsonFilePath = path.join(profilesDir, jsonFilename);
  const htmlFilePath = path.join(profilesDir, htmlFilename);

  // Store paths with leading slash so <a href> resolves from the site root
  // (the profiles dir is served by Express at /profiles/* in server.js).
  // Without the leading /, links from /ciab/my-profiles resolve as
  // /ciab/profiles/... which hits a 404.
  const jsonRelPath = '/' + path.join('profiles', jsonFilename).replace(/\\/g, '/');
  const htmlRelPath = '/' + path.join('profiles', htmlFilename).replace(/\\/g, '/');

  fs.writeFileSync(jsonFilePath, JSON.stringify(combined, null, 2));
  try {
    // The ported pro generator expects `profile.meta` at top level + `config`/`seed`
    // for some cover-page fields. Adapt our shape to match.
    const profileForHtml = {
      ...combined,
      meta: combined.student_view?.meta || {},
      config,
      seed,
      learning_objectives: combined.instructor_view?.learning_objectives || {}
    };
    fs.writeFileSync(htmlFilePath, renderProfileHtml(profileForHtml));
  } catch (htmlErr) {
    console.warn(`⚠️  [ai/profile] HTML render failed (JSON saved): ${htmlErr.message}`);
  }

  // Verify both writes actually landed on disk — catches volume-mount issues
  // where process.cwd() doesn't resolve to the host-mounted profiles dir.
  const jsonStat = fs.existsSync(jsonFilePath) ? fs.statSync(jsonFilePath) : null;
  const htmlStat = fs.existsSync(htmlFilePath) ? fs.statSync(htmlFilePath) : null;
  if (!jsonStat || jsonStat.size === 0) {
    console.error(`❌ [ai/profile] JSON write reported success but file is missing or empty: ${jsonFilePath}`);
  } else {
    console.log(`💾 [ai/profile] Wrote JSON ${jsonFilePath} (${jsonStat.size} bytes) → DB path ${jsonRelPath}`);
  }
  if (htmlStat && htmlStat.size > 0) {
    console.log(`💾 [ai/profile] Wrote HTML ${htmlFilePath} (${htmlStat.size} bytes) → DB path ${htmlRelPath}`);
  }

  // Insert profiles row
  const org = combined.student_view.raw.threats.organization || {};
  const insert = await pool.query(`
    INSERT INTO profiles
      (user_id, company_name, client_type, industry, difficulty,
       hq_city, employee_count, json_file_path, html_file_path, run_id,
       generation_status, profile_type, compliance_frameworks, key_risks, critical_systems)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'complete', 'standard', $11, $12, $13)
    RETURNING id, company_name, client_type, industry, difficulty, created_at, run_id, json_file_path, html_file_path
  `, [
    user_id,
    org.company_name || 'Generated Profile',
    config.clientType,
    seed.template.industry,
    seed.difficulty,
    org.hq_city || null,
    org.employees_total || employeeCount,
    jsonRelPath,
    htmlStat && htmlStat.size > 0 ? htmlRelPath : null,
    seed.run_id,
    JSON.stringify(seed.template.compliance),
    JSON.stringify(seed.template.risks),
    JSON.stringify(seed.template.criticalSystems)
  ]);

  const profileRow = insert.rows[0];

  // Seed the unified `intakes` row so the Clinic Risk Assessment + intake
  // normalizer immediately see the pre-filled IG1 baseline. Source =
  // 'ai_simulated' (vs 'real_client' for uploaded intakes). Best-effort:
  // a failure here logs but does NOT roll back the profile.
  if (intakeV11) {
    try {
      reportStep('seeding_intake', 97, 'Seeding risk-assessment intake (IG1 baseline)…');
      await pool.query(`
        INSERT INTO intakes (
          user_id, profile_id, source, schema_version, cover_name,
          payload, completion_percentage, status, completed_at
        ) VALUES ($1, $2, 'ai_simulated', '1.1', $3, $4::jsonb, $5, 'complete', NOW())
        ON CONFLICT (profile_id) WHERE profile_id IS NOT NULL DO NOTHING
      `, [
        user_id, profileRow.id,
        intakeV11.cover_name,
        JSON.stringify(intakeV11),
        intakeV11._meta?.ig1_coverage_pct ?? 60
      ]);
      console.log(`📋 [ai/profile] Seeded intakes row for risk assessment`);
    } catch (intakeErr) {
      console.warn(`⚠️  [ai/profile] Intake seed failed (profile still created): ${intakeErr.message}`);
    }
  }

  reportStep('complete', 100, 'Profile generated successfully');
  console.log(`✅ [ai/profile] Profile ${profileRow.id} created (${org.company_name}, ${seed.run_id})`);
  return profileRow;
}

// Helper: convert {systemPrompt, userPrompt} → llm.generateJson options object
function buildToOptionsObj(promptPair, { model, maxTokens, label, temperature }) {
  return {
    model: llm.resolveModel(model),
    system: llm.cachedSystem(promptPair.systemPrompt),
    messages: [{ role: 'user', content: promptPair.userPrompt }],
    max_tokens: maxTokens,
    temperature: temperature ?? 0.7,
    label
  };
}

module.exports = {
  generateProfile,
  buildConfig,
  combineProfile,
  CLIENT_TYPE_TEMPLATES
};
