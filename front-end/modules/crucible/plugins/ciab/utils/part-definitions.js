/**
 * part-definitions.js — The 8-part assessment structure.
 * ============================================================================
 * Single source of truth for part numbers, names, options, and deliverables.
 * Mirrors PART_OPTIONS from public/js/workspace.js.
 *
 * This used to be duplicated: routes/instructor.js held the full definitions
 * while routes/progress.js carried its own getPartName() with a different set
 * of names. Since progress.js is what writes assessment_progress.part_name on
 * student save, stored names disagreed with everything the instructor UI and
 * the answer-key generator displayed. Both now read from here.
 *
 * Pure data + one lookup. No DB, no IO.
 */

const PART_DEFINITIONS = {
  1: { name: 'Clinic Orientation', options: [
    { key: 'p1_participation_agreement', name: 'Clinic Participation Agreement', deliverables: ['Signed participation agreement or code of conduct document'] },
    { key: 'p1_reflection', name: 'Short Reflection on Cybersecurity Clinics', deliverables: ['Reflection addressing: purpose of cybersecurity clinics, benefits to under-resourced organizations, workforce preparation, professional standards'] }
  ]},
  2: { name: 'Organizational Understanding', options: [
    { key: 'p2_org_brief', name: 'Initial Organizational Understanding Brief', deliverables: ['Organization mission and core services', 'High-level description of systems, data, and users', 'Summary of scoping activities performed', 'Initial cybersecurity posture observations', 'Explicit assumptions and client clarification questions'] },
    { key: 'p2_scoping_matrix', name: 'Scoping and Assumptions Matrix', deliverables: ['Table: Category, Known Information, Assumptions Made, Impact if Incorrect, Clarification Needed'] },
    { key: 'p2_asset_inventory', name: 'Preliminary Asset and Impact Inventory', deliverables: ['Key assets list (data, systems, processes)', 'Asset owner (if known)', 'Importance to mission (High/Medium/Low)', 'Potential impact of compromise'] },
    { key: 'p2_risk_hypothesis', name: 'Initial Risk Hypothesis Statement', deliverables: ['3-5 hypothesized high-risk areas', 'Rationale for each hypothesis', 'Evidence observed so far', 'Additional information needed to confirm or refute'] },
    { key: 'p2_question_log', name: 'Client Question and Information Request Log', deliverables: ['Structured question log: Topic Area, Question, Reason, Priority, Requested Evidence'] },
    { key: 'p2_scope_diagram', name: 'Visual Scope Diagram or System Context Map', deliverables: ['Systems and data flows (high-level)', 'External connections (vendors, cloud)', 'In-scope vs. out-of-scope elements', 'Unknown components highlighted'] }
  ]},
  3: { name: 'Threat Identification', options: [
    { key: 'p3_sector_brief', name: 'Sector-Based Threat Research Brief', deliverables: ['1-2 page threat research brief', 'List of top sector-specific threats', 'Rationale for relevance to the organization'] },
    { key: 'p3_actor_profiles', name: 'Threat Actor Profile Development', deliverables: ['Threat actor profile sheets', 'Actor motivation, capability, and access analysis', 'Asset-actor mapping table'] },
    { key: 'p3_case_study', name: 'Case Study-Driven Threat Mapping', deliverables: ['Case study summary', 'Threat comparison table (Case vs. Client)', 'Lessons learned and applicability analysis'] },
    { key: 'p3_threat_model', name: 'Threat Modeling Workshop', deliverables: ['Threat scenario list', 'High-level threat model diagram', 'Narrative explanation of key threat paths'] },
    { key: 'p3_emerging_threats', name: 'Emerging Threat Research Snapshot', deliverables: ['Emerging threat summary', 'Relevance assessment (High/Medium/Low)', 'Justification for inclusion or exclusion'] },
    { key: 'p3_insider_threats', name: 'Insider and Non-Technical Threat Analysis', deliverables: ['Insider threat scenarios', 'Human and process-based threat list', 'Mitigation considerations (high-level)'] }
  ]},
  4: { name: 'Vulnerability Discovery', options: [
    { key: 'p4_policy_review', name: 'Policy and Procedure Vulnerability Review', deliverables: ['Policy gap analysis document', 'List of administrative vulnerabilities', 'Assumptions and evidence references'] },
    { key: 'p4_vuln_scanning', name: 'Hands-On Vulnerability Scanning', deliverables: ['Scan configuration summary', 'Raw scan output (sanitized)', 'Identified vulnerabilities with descriptions'] },
    { key: 'p4_scan_analysis', name: 'Vulnerability Scan Results Analysis', deliverables: ['Validated vulnerability list', 'False positive justification notes', 'Severity reassessment based on context'] },
    { key: 'p4_config_assessment', name: 'Configuration-Based Assessment', deliverables: ['Configuration review checklist', 'Observational vulnerability notes', 'Interview-derived findings summary'] },
    { key: 'p4_vuln_asset_map', name: 'Vulnerability-to-Asset Mapping Table', deliverables: ['Vulnerability-asset mapping table', 'Impact notes and assumptions', 'Confidence ratings'] }
  ]},
  5: { name: 'Risk Analysis', options: [
    { key: 'p5_scoring_justification', name: 'Risk Scoring Methodology Justification', deliverables: ['Risk scoring methodology memo', 'Comparison table of alternative models', 'Justification tied to organizational context'] },
    { key: 'p5_likelihood_impact', name: 'Likelihood and Impact Research Briefs', deliverables: ['Likelihood research brief', 'Impact justification narrative', 'Annotated references'] },
    { key: 'p5_risk_narrative', name: 'Risk Narrative Development', deliverables: ['Risk narratives', 'Supporting evidence citations', 'Audience-specific language adaptation'] },
    { key: 'p5_final_package', name: 'Final Risk Prioritization Package', deliverables: ['Final prioritized risk register', 'Executive summary', 'Research appendix'] }
  ]},
  6: { name: 'Controls and Mitigations', options: [
    { key: 'p6_framework_selection', name: 'Framework Selection and Justification', deliverables: ['Framework selection memorandum', 'Comparison table of candidate frameworks', 'Justification narrative'] },
    { key: 'p6_risk_control_map', name: 'Risk-to-Control Mapping', deliverables: ['Risk-control mapping table', 'Narrative justification per control', 'Citation list linking to framework docs'] },
    { key: 'p6_feasibility', name: 'Control Feasibility and Resource Analysis', deliverables: ['Control feasibility matrix', 'Cost/benefit narrative', 'Resource assumptions and constraints'] },
    { key: 'p6_roadmap', name: 'Prioritized Mitigation Roadmap', deliverables: ['Mitigation roadmap', 'Timeline with dependencies', 'Sequencing justification'] },
    { key: 'p6_client_package', name: 'Client-Ready Mitigation Package', deliverables: ['Final mitigation recommendations', 'Executive summary', 'Reference appendix'] }
  ]},
  7: { name: 'Reporting and Communication', options: [
    { key: 'p7_full_report', name: 'Comprehensive Risk Assessment Report', deliverables: ['Formal report: executive summary, org overview, methodology, key risks, controls, limitations, next steps', 'Proper citations and references', 'Technical appendices'] },
    { key: 'p7_executive_summary', name: 'Executive Summary and Leadership Brief', deliverables: ['1-2 page executive summary', 'Top 3-5 risks with business impact', 'High-level mitigation priorities (jargon-free)'] },
    { key: 'p7_presentation', name: 'Oral Briefing or Presentation', deliverables: ['Slide deck (8-12 slides)', 'Speaker notes', 'Q&A reflection summary'] },
    { key: 'p7_handoff', name: 'Client Handoff and Next Steps Package', deliverables: ['Priority action checklist', 'Recommended timelines', 'Suggested future assessments'] }
  ]},
  8: { name: 'Reflection and Workforce Alignment', options: [
    { key: 'p8_reflection_paper', name: 'Structured Reflection Paper', deliverables: ['Reflection paper (1-3 pages): what you learned, how understanding changed, challenges, what you\'d do differently'] },
    { key: 'p8_self_assessment', name: 'Skills and Competency Self-Assessment', deliverables: ['Skills self-assessment matrix (before/after)', 'Narrative growth summary', 'Skills gap analysis'] },
    { key: 'p8_workforce_alignment', name: 'Workforce Framework Alignment Map', deliverables: ['Workforce alignment table', 'Role interest reflection', 'Evidence supporting alignment claims'] },
    { key: 'p8_career_plan', name: 'Career Pathway and Professional Development Plan', deliverables: ['Individual career roadmap', 'Short- and long-term professional goals', 'Certification or education plan'] }
  ]}
};

const TOTAL_PARTS = Object.keys(PART_DEFINITIONS).length;

/**
 * Canonical display name for a part number. Falls back to "Part N" so a
 * caller passing something out of range still gets a usable label.
 */
function getPartName(partNumber) {
  return PART_DEFINITIONS[partNumber]?.name || `Part ${partNumber}`;
}

module.exports = { PART_DEFINITIONS, TOTAL_PARTS, getPartName };
