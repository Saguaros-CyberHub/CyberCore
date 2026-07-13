// ============================================================================
// WORKSPACE.JS - PHASE 3 ENHANCED - Custom UIs for All 8 Parts
// ============================================================================

// State management
let currentProfileId = null;
let currentProfile = null;
let currentPart = 1;
let currentProgress = [];
let autoSaveTimer = null;
let intakeFormStatus = { completion: 0, status: 'not_started' };

// Part definitions with rendering info
const PARTS = [
  {
    number: 1,
    name: 'Orientation',
    title: 'Orientation and Context Setting',
    type: 'narrative', // narrative, form, structured, hybrid
    icon: '📚',
    description: 'Introduction to the clinic model and risk assessment expectations.'
  },
  {
    number: 2,
    name: 'Scoping',
    title: 'Client / Organization Scoping',
    type: 'hybrid', // Uses intake form + notes
    icon: '🎯',
    description: 'Define assessment scope and organizational context.'
  },
  {
    number: 3,
    name: 'Threats',
    title: 'Threat Identification',
    type: 'structured',
    icon: '⚠️',
    description: 'Identify and analyze relevant threats.'
  },
  {
    number: 4,
    name: 'Vulnerabilities',
    title: 'Vulnerability Identification',
    type: 'structured',
    icon: '🔍',
    description: 'Discover security weaknesses and gaps.'
  },
  {
    number: 5,
    name: 'Risk Analysis',
    title: 'Risk Analysis and Prioritization',
    type: 'structured',
    icon: '📊',
    description: 'Evaluate and prioritize risks systematically.'
  },
  {
    number: 6,
    name: 'Controls',
    title: 'Control and Mitigation',
    type: 'structured',
    icon: '🛡️',
    description: 'Recommend security controls and mitigations.'
  },
  {
    number: 7,
    name: 'Reporting',
    title: 'Reporting and Communication',
    type: 'narrative',
    icon: '📝',
    description: 'Create professional reports and presentations.'
  },
  {
    number: 8,
    name: 'Reflection',
    title: 'Reflection and Workforce Alignment',
    type: 'narrative',
    icon: '💭',
    description: 'Reflect on learning and career alignment.'
  }
];

// ============================================================================
// PART OPTIONS - From Clinic-in-a-Box Training Guidance
// Each part has selectable student output options. Selected options determine deliverables.
// ============================================================================
const PART_OPTIONS = {
  1: {
    instructions: 'Complete the selected outputs to demonstrate your understanding of the clinic model, ethics, and expectations.',
    activities: ['Introduction to the Cybersecurity Clinic Initiative and the role of student clinics', 'Overview of cybersecurity risk assessment concepts (risk, threats, vulnerabilities, impact)', 'Discussion of ethical considerations, professionalism, and client confidentiality', 'Review of toolkit materials, templates, and deliverables'],
    options: [
      { key: 'p1_participation_agreement', name: 'Clinic Participation Agreement / Code of Conduct', description: 'Sign or draft a participation agreement acknowledging ethical responsibilities, professionalism, and client confidentiality.', deliverables: ['Signed participation agreement or code of conduct document'] },
      { key: 'p1_reflection', name: 'Short Reflection on Cybersecurity Clinics', description: 'Write a reflection (200-500 words) on the purpose of cybersecurity clinics and workforce relevance.', deliverables: ['Reflection addressing: purpose of cybersecurity clinics, benefits to under-resourced organizations, workforce preparation, professional standards'] }
    ],
  },
  2: {
    instructions: 'Use the Intake Form to gather client data, interview stakeholders, then complete the selected student outputs below.',
    activities: ['Review a simulated or real under-resourced organization profile', 'Identify organizational mission, assets, and operational constraints', 'Define scope boundaries (systems included/excluded, assumptions)', 'Map stakeholders and business priorities'],
    options: [
      { key: 'p2_org_brief', name: 'Option 1: Initial Organizational Understanding Brief', description: 'Provide a narrative snapshot (1-2 pages) of the organization and preliminary understanding.', deliverables: ['Organization mission and core services', 'High-level description of systems, data, and users', 'Summary of scoping activities performed', 'Initial cybersecurity posture observations', 'Explicit assumptions and client clarification questions'] },
      { key: 'p2_scoping_matrix', name: 'Option 2: Scoping and Assumptions Matrix', description: 'Document boundaries and uncertainties in a structured, auditable format.', deliverables: ['Table: Category, Known Information, Assumptions Made, Impact if Incorrect, Clarification Needed'] },
      { key: 'p2_asset_inventory', name: 'Option 3: Preliminary Asset and Impact Inventory', description: 'Identify what matters most before deeper risk analysis begins.', deliverables: ['Key assets list (data, systems, processes)', 'Asset owner (if known)', 'Importance to mission (High/Medium/Low)', 'Potential impact of compromise'] },
      { key: 'p2_risk_hypothesis', name: 'Option 4: Initial Risk Hypothesis Statement', description: 'Encourage early analytical thinking before full risk analysis.', deliverables: ['3-5 hypothesized high-risk areas', 'Rationale for each hypothesis', 'Evidence observed so far', 'Additional information needed to confirm or refute'] },
      { key: 'p2_question_log', name: 'Option 5: Client Question and Information Request Log', description: 'Prepare for professional client engagement and follow-up.', deliverables: ['Structured question log: Topic Area, Question, Reason, Priority, Requested Evidence'] },
      { key: 'p2_scope_diagram', name: 'Option 6: Visual Scope Diagram or System Context Map', description: 'Provide a visual representation of organization and assessment boundaries.', deliverables: ['Systems and data flows (high-level)', 'External connections (vendors, cloud)', 'In-scope vs. out-of-scope elements', 'Unknown components highlighted'] }
    ],
  },
  3: {
    instructions: 'Research and identify threats relevant to the organization. Complete the selected outputs.',
    activities: ['Introduce common threat sources (cybercriminals, insiders, nation-states, accidents)', 'Use threat modeling techniques appropriate to learner level', 'Map threats to organizational assets', 'Discuss real incidents affecting similar organizations'],
    options: [
      { key: 'p3_sector_brief', name: 'Option 1: Sector-Based Threat Research Brief', description: 'Ground threat identification in real-world research relevant to the organization\'s sector.', deliverables: ['1-2 page threat research brief', 'List of top sector-specific threats', 'Rationale for relevance to the organization'] },
      { key: 'p3_actor_profiles', name: 'Option 2: Threat Actor Profile Development', description: 'Analytical thinking about who might attack and why.', deliverables: ['Threat actor profile sheets', 'Actor motivation, capability, and access analysis', 'Asset-actor mapping table'] },
      { key: 'p3_case_study', name: 'Option 3: Case Study-Driven Threat Mapping', description: 'Use real cybersecurity incidents to contextualize threats.', deliverables: ['Case study summary', 'Threat comparison table (Case vs. Client)', 'Lessons learned and applicability analysis'] },
      { key: 'p3_threat_model', name: 'Option 4: Threat Modeling Workshop', description: 'Formal or semi-formal threat modeling concepts.', deliverables: ['Threat scenario list', 'High-level threat model diagram', 'Narrative explanation of key threat paths'] },
      { key: 'p3_emerging_threats', name: 'Option 5: Emerging Threat Research Snapshot', description: 'Build awareness of evolving cybersecurity threats.', deliverables: ['Emerging threat summary', 'Relevance assessment (High/Medium/Low)', 'Justification for inclusion or exclusion'] },
      { key: 'p3_insider_threats', name: 'Option 6: Insider and Non-Technical Threat Analysis', description: 'Expand thinking beyond external technical attacks.', deliverables: ['Insider threat scenarios', 'Human and process-based threat list', 'Mitigation considerations (high-level)'] }
    ],
  },
  4: {
    instructions: 'Discover security weaknesses through review, scanning, and analysis. Complete the selected outputs.',
    activities: ['Review common technical, administrative, and physical vulnerabilities', 'Conduct guided vulnerability discovery using interviews, checklists, policy reviews', 'Emphasize non-technical vulnerabilities (training gaps, outdated policies)'],
    options: [
      { key: 'p4_policy_review', name: 'Option 1: Policy and Procedure Vulnerability Review (Baseline)', description: 'Identify non-technical weaknesses that drive real-world risk.', deliverables: ['Policy gap analysis document', 'List of administrative vulnerabilities', 'Assumptions and evidence references'] },
      { key: 'p4_simulation_lab', name: 'Option 2: Simulation-Based Vulnerability Discovery Lab', description: 'Safe, controlled exposure to vulnerability identification.', deliverables: ['Simulation vulnerability log', 'Screenshots or system observations', 'Risk relevance notes'] },
      { key: 'p4_vuln_scanning', name: 'Option 3: Hands-On Vulnerability Scanning (Authorized Scope Only)', description: 'Real-world security tooling and interpretation skills.', deliverables: ['Scan configuration summary', 'Raw scan output (sanitized)', 'Identified vulnerabilities with descriptions'] },
      { key: 'p4_scan_analysis', name: 'Option 4: Vulnerability Scan Results Analysis and Validation', description: 'Critical evaluation rather than tool dependence.', deliverables: ['Validated vulnerability list', 'False positive justification notes', 'Severity reassessment based on context'] },
      { key: 'p4_config_assessment', name: 'Option 5: Configuration and Observation-Based Assessment', description: 'Identify vulnerabilities through direct inspection and interviews.', deliverables: ['Configuration review checklist', 'Observational vulnerability notes', 'Interview-derived findings summary'] },
      { key: 'p4_case_study_vuln', name: 'Option 6: Case Study-Driven Vulnerability Mapping', description: 'Leverage real incidents to understand vulnerability impact.', deliverables: ['Case study vulnerability comparison', 'Applicability assessment', 'Preventive control discussion'] },
      { key: 'p4_vuln_asset_map', name: 'Option 7: Vulnerability-to-Asset Mapping Table', description: 'Prepare for risk analysis in Part 5.', deliverables: ['Vulnerability-asset mapping table', 'Impact notes and assumptions', 'Confidence ratings'] },
      { key: 'p4_red_blue', name: 'Option 8: Red Team / Blue Team Simulation (Non-Exploitative)', description: 'Adversarial thinking without unsafe activity.', deliverables: ['Hypothetical vulnerability scenarios', 'Defense and detection notes', 'Lessons learned summary'] },
      { key: 'p4_evidence_portfolio', name: 'Option 9: Vulnerability Evidence Portfolio', description: 'Documentation and professional rigor.', deliverables: ['Evidence portfolio', 'Evidence-to-vulnerability mapping', 'Documentation quality checklist'] }
    ],
  },
  5: {
    instructions: 'Evaluate and prioritize risks using structured methods. Complete the selected outputs.',
    activities: ['Introduce qualitative or semi-quantitative risk scoring methods', 'Estimate likelihood and impact for each threat-vulnerability pair', 'Use toolkit templates to calculate risk levels', 'Rank risks based on organizational impact'],
    options: [
      { key: 'p5_scoring_justification', name: 'Option 1: Risk Scoring Methodology Justification', description: 'Explain how and why you chose a risk analysis approach.', deliverables: ['Risk scoring methodology memo', 'Comparison table of alternative models', 'Justification tied to organizational context'] },
      { key: 'p5_traceability_matrix', name: 'Option 2: Evidence-to-Risk Traceability Matrix', description: 'Ensure each risk is supported by documented evidence.', deliverables: ['Traceability matrix', 'Evidence confidence ratings', 'Notes on inference vs. verified data'] },
      { key: 'p5_likelihood_impact', name: 'Option 3: Likelihood and Impact Research Briefs', description: 'Deepen analytical thinking behind scoring.', deliverables: ['Likelihood research brief', 'Impact justification narrative', 'Annotated references'] },
      { key: 'p5_comparative', name: 'Option 4: Comparative Risk Prioritization Exercise', description: 'Evaluate tradeoffs in constrained environments.', deliverables: ['Comparative prioritization table', 'Decision rationale memo', 'Reflection on uncertainty and bias'] },
      { key: 'p5_uncertainty', name: 'Option 5: Risk Assumptions and Uncertainty Analysis', description: 'Make uncertainty an explicit part of risk analysis.', deliverables: ['Assumptions impact analysis', 'Sensitivity summary', 'Confidence scoring table'] },
      { key: 'p5_tool_analysis', name: 'Option 6: Tool-Supported Risk Analysis with Validation', description: 'Structured tools without overreliance.', deliverables: ['Tool-generated risk register', 'Validation notes and corrections', 'Tool limitations analysis'] },
      { key: 'p5_risk_narrative', name: 'Option 7: Risk Narrative Development', description: 'Translate technical findings into coherent risk stories.', deliverables: ['Risk narratives', 'Supporting evidence citations', 'Audience-specific language adaptation'] },
      { key: 'p5_research_log', name: 'Option 8: Research Log and Analysis Journal', description: 'Professional documentation habits.', deliverables: ['Research and analysis journal', 'Source credibility assessment', 'Decision timeline'] },
      { key: 'p5_peer_review', name: 'Option 9: Peer Review and Methodology Defense', description: 'Professional review and justification.', deliverables: ['Peer review feedback forms', 'Methodology defense summary', 'Revisions log'] },
      { key: 'p5_final_package', name: 'Option 10: Final Risk Prioritization Package', description: 'Integrate analysis, research, and documentation.', deliverables: ['Final prioritized risk register', 'Executive summary', 'Research appendix'] }
    ],
  },
  6: {
    instructions: 'Recommend security controls and mitigations. Complete the selected outputs.',
    activities: ['Introduce relevant cybersecurity frameworks (NIST CSF, CIS Controls)', 'Select appropriate framework for client type', 'Map existing controls to identified risks', 'Propose feasible mitigation strategies considering resource constraints'],
    options: [
      { key: 'p6_framework_selection', name: 'Option 1: Framework Selection and Justification (Required Baseline)', description: 'Ensure controls are grounded in a recognized framework.', deliverables: ['Framework selection memorandum', 'Comparison table of candidate frameworks', 'Justification narrative (org size, sector, constraints, risk profile)'] },
      { key: 'p6_risk_control_map', name: 'Option 2: Risk-to-Control Mapping with Citations', description: 'Traceability from risks to recommended controls.', deliverables: ['Risk-control mapping table', 'Narrative justification per control', 'Citation list linking to framework docs'] },
      { key: 'p6_feasibility', name: 'Option 3: Control Feasibility and Resource Analysis', description: 'Realistic, implementable recommendations.', deliverables: ['Control feasibility matrix', 'Cost/benefit narrative', 'Resource assumptions and constraints'] },
      { key: 'p6_compensating', name: 'Option 4: Compensating and Alternative Control Research', description: 'Address constraints in under-resourced organizations.', deliverables: ['Compensating control analysis', 'Justification from authoritative sources', 'Risk acceptance considerations'] },
      { key: 'p6_roadmap', name: 'Option 5: Prioritized Mitigation Roadmap', description: 'Translate controls into an actionable plan.', deliverables: ['Mitigation roadmap', 'Timeline with dependencies', 'Sequencing justification'] },
      { key: 'p6_effectiveness', name: 'Option 6: Control Effectiveness Evaluation', description: 'Critical thinking beyond control selection.', deliverables: ['Control effectiveness analysis', 'Residual risk statements', 'Measurement recommendations'] },
      { key: 'p6_integration', name: 'Option 7: Policy, Process, and Technical Control Integration', description: 'Defense-in-depth and holistic security.', deliverables: ['Integrated control mapping', 'Defense-in-depth narrative', 'Justification with citations'] },
      { key: 'p6_research_log', name: 'Option 8: Control Recommendation Research Log', description: 'Explicit and auditable research process.', deliverables: ['Annotated research log', 'Source credibility assessment', 'Decision rationale summary'] },
      { key: 'p6_peer_review', name: 'Option 9: Peer Review and Control Defense Exercise', description: 'Professional review and stakeholder scrutiny.', deliverables: ['Peer review feedback', 'Control defense summary', 'Revisions and rationale'] },
      { key: 'p6_client_package', name: 'Option 10: Client-Ready Mitigation Package', description: 'Integrate analysis, justification, and communication.', deliverables: ['Final mitigation recommendations', 'Executive summary', 'Reference appendix'] }
    ],
  },
  7: {
    instructions: 'Create professional deliverables to communicate your findings. Complete the selected outputs.',
    activities: ['Draft a client-ready risk assessment report', 'Create an executive summary for non-technical stakeholders', 'Prepare a briefing or presentation', 'Translate technical findings into business language'],
    options: [
      { key: 'p7_full_report', name: 'Option 1: Comprehensive Risk Assessment Report (Client-Facing)', description: 'Professional, end-to-end assessment deliverable.', deliverables: ['Formal report: executive summary, org overview, methodology, key risks, controls, limitations, next steps', 'Proper citations and references', 'Technical appendices'] },
      { key: 'p7_executive_summary', name: 'Option 2: Executive Summary and Leadership Brief', description: 'Communicate risk to decision-makers.', deliverables: ['1-2 page executive summary', 'Top 3-5 risks with business impact', 'High-level mitigation priorities (jargon-free)'] },
      { key: 'p7_technical_appendix', name: 'Option 3: Technical Findings Appendix', description: 'Separate technical depth from executive messaging.', deliverables: ['Technical appendix: vulnerability scan summaries', 'Evidence references and risk scoring details', 'Control mappings'] },
      { key: 'p7_presentation', name: 'Option 4: Oral Briefing or Presentation', description: 'Verbal communication and stakeholder engagement.', deliverables: ['Slide deck (8-12 slides)', 'Speaker notes', 'Q&A reflection summary'] },
      { key: 'p7_visualizations', name: 'Option 5: Risk Visualization Artifacts', description: 'Enhance comprehension through visuals.', deliverables: ['Risk heat maps / asset-risk matrices / mitigation roadmaps', 'Explanatory captions', 'Justification for visualization choices'] },
      { key: 'p7_limitations', name: 'Option 6: Assumptions, Limitations, and Confidence Statement', description: 'Transparency and professional ethics.', deliverables: ['Key assumptions', 'Limitations affecting confidence', 'Areas requiring follow-up'] },
      { key: 'p7_evidence_portfolio', name: 'Option 7: Evidence and Reference Portfolio', description: 'Credibility and research rigor.', deliverables: ['Source list (frameworks, standards, research)', 'Evidence supporting findings', 'Citation annotations'] },
      { key: 'p7_audience_variants', name: 'Option 8: Audience-Tailored Communication Variants', description: 'Adaptability in communication.', deliverables: ['Summaries for: Executives, Technical staff, Non-technical stakeholders', 'Reflection on language and emphasis changes'] },
      { key: 'p7_peer_review', name: 'Option 9: Peer Review and Feedback Integration Report', description: 'Professional quality assurance.', deliverables: ['Peer review forms', 'Revision log with justifications', 'Final revised deliverables'] },
      { key: 'p7_handoff', name: 'Option 10: Client Handoff and Next Steps Package', description: 'Prepare organizations for action beyond assessment.', deliverables: ['Priority action checklist', 'Recommended timelines', 'Suggested future assessments'] }
    ],
  },
  8: {
    instructions: 'Reflect on your learning and connect it to workforce competencies. Complete the selected outputs.',
    activities: ['Reflect on clinic experience and professional skill development', 'Discuss how the assessment mirrors real cybersecurity roles', 'Identify career pathways connected to risk assessment skills', 'Peer and instructor feedback on performance'],
    options: [
      { key: 'p8_reflection_paper', name: 'Option 1: Structured Reflection Paper or Journal', description: 'Critical reflection on learning and professional identity.', deliverables: ['Reflection paper (1-3 pages): what you learned, how understanding changed, challenges, what you\'d do differently'] },
      { key: 'p8_self_assessment', name: 'Option 2: Skills and Competency Self-Assessment', description: 'Recognize growth and identify gaps.', deliverables: ['Skills self-assessment matrix (before/after)', 'Narrative growth summary', 'Skills gap analysis'] },
      { key: 'p8_workforce_alignment', name: 'Option 3: Workforce Framework Alignment Map', description: 'Connect activities directly to cybersecurity workforce roles.', deliverables: ['Workforce alignment table (activities to Tasks, Knowledge, Skills)', 'Role interest reflection', 'Evidence supporting alignment claims'] },
      { key: 'p8_career_plan', name: 'Option 4: Career Pathway and Professional Development Plan', description: 'Translate experience into career planning.', deliverables: ['Individual career roadmap', 'Short- and long-term professional goals', 'Certification or education plan'] },
      { key: 'p8_ethics', name: 'Option 5: Ethical and Professional Responsibility Reflection', description: 'Reinforce ethical practice and trust.', deliverables: ['Ethics reflection essay: how ethics shaped assessment, responsibilities to clients/communities, scope and authorization impact'] },
      { key: 'p8_community_impact', name: 'Option 6: Community Impact and Service-Learning Reflection', description: 'Social value of cybersecurity work.', deliverables: ['Community impact reflection', 'Service-learning summary', 'Recommendations for sustained engagement'] },
      { key: 'p8_peer_eval', name: 'Option 7: Peer and Teamwork Evaluation', description: 'Collaboration and professional conduct.', deliverables: ['Peer evaluation forms', 'Team performance reflection', 'Collaboration improvement plan'] },
      { key: 'p8_portfolio', name: 'Option 8: Portfolio Artifact and Evidence Statement', description: 'Prepare for resumes, interviews, and portfolios.', deliverables: ['Portfolio artifact list', 'Skills justification statements', 'Artifact usage guidelines'] },
      { key: 'p8_lessons_learned', name: 'Option 9: Lessons Learned and Continuous Improvement Memo', description: 'Professional after-action reporting.', deliverables: ['Lessons learned memo', 'Process improvement recommendations', 'Future clinic enhancement ideas'] },
      { key: 'p8_capstone', name: 'Option 10: Capstone Reflection Presentation', description: 'Synthesize learning through presentation.', deliverables: ['Reflection slide deck', 'Oral presentation', 'Audience feedback summary'] }
    ],
  }
};

// Track selected options per part (loaded from progress.output_option)
let selectedOptions = {};

// Track which tab is active in the deliverable tab bar, per part
let activeDeliverableTabs = {};

// ============================================================================
// INITIALIZATION
// ============================================================================
document.addEventListener('DOMContentLoaded', async () => {
  if (!await Auth.requireAuth()) return;
  
  // Get profile from URL or localStorage
  const urlParams = new URLSearchParams(window.location.search);
  const profileParam = urlParams.get('profile');
  
  const partParam = urlParams.get('part');

  if (profileParam) {
    localStorage.setItem('activeProfileId', profileParam);
    currentProfileId = profileParam;
  } else {
    currentProfileId = localStorage.getItem('activeProfileId');
  }

  await loadProfiles();

  if (currentProfileId) {
    await loadProfile(currentProfileId);
    // Navigate to specific part if requested via URL
    if (partParam) {
      const pn = parseInt(partParam);
      if (pn >= 1 && pn <= 8) switchPart(pn);
    }
  } else {
    showEmptyState();
  }
  
  setupEventListeners();
  setupSubmitModal();
  
  // Refresh intake form status when window regains focus
  window.addEventListener('focus', async () => {
    if (currentPart === 2 && currentProfileId) {
      await fetchIntakeFormStatus();
      // Re-render Part 2 to show updated status
      const part = PARTS.find(p => p.number === 2);
      const progress = currentProgress.find(p => p.part_number === 2) || {
        part_number: 2,
        status: 'not_started',
        content: null,
        evidence_files: []
      };
      renderPartContent(part, progress);
    }
  });
  
  // Listen for messages from intake form window
  window.addEventListener('message', async (event) => {
    // Verify origin
    if (event.origin !== window.location.origin) return;
    
    if (event.data && event.data.type === 'intake-form-saved') {
      console.log('[Workspace] Intake form saved, refreshing status', event.data);
      intakeFormStatus = {
        status: event.data.status || 'in_progress',
        completion: event.data.completion || 0
      };
      
      // Update badge if Part 2 is currently displayed
      if (currentPart === 2) {
        updateIntakeFormBadge();
        // Also refresh the whole part to update the progress indicator
        const part = PARTS.find(p => p.number === 2);
        const progress = currentProgress.find(p => p.part_number === 2) || {
          part_number: 2,
          status: 'not_started',
          content: null,
          evidence_files: []
        };
        renderPartContent(part, progress);
      }
      
      // Update parts list sidebar
      renderPartsList();
      
      Toast.success('Updated', 'Intake form progress synced');
    }
  });
});

// ============================================================================
// PROFILE LOADING
// ============================================================================
async function loadProfiles() {
  try {
    const response = await API.profiles.list();
    
    // Handle different response structures
    const profiles = Array.isArray(response) ? response : 
                     (response.profiles || response.data || []);
    
    const select = document.getElementById('profileSelect');
    
    const escapeHtml = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
    select.innerHTML = '<option value="">-- Select a profile --</option>' +
      profiles.map(p => `
        <option value="${p.id}" ${p.id === currentProfileId ? 'selected' : ''}>
          ${escapeHtml(p.name || p.company_name || p.companyName || 'Unnamed Organization')}
        </option>
      `).join('');
  } catch (error) {
    console.error('Failed to load profiles:', error);
    Toast.error('Error', 'Failed to load profiles');
  }
}

async function loadProfile(profileId) {
  try {
    if (!profileId) {
      showEmptyState();
      return;
    }
    
    currentProfileId = profileId;
    localStorage.setItem('activeProfileId', profileId);
    
    // Load profile data
    currentProfile = await API.profiles.get(profileId);
    
    if (!currentProfile) {
      throw new Error('Profile not found');
    }
    
    // Load progress for this profile
    const progressData = await API.progress.get(profileId);
    currentProgress = Array.isArray(progressData.progress) ? progressData.progress : [];
    
    // Show workspace
    document.getElementById('noProfileState').style.display = 'none';
    document.getElementById('workspaceContent').style.display = 'block';
    
    // Render parts list
    renderPartsList();
    
    // Update overall progress
    updateOverallProgress();
    
    // Load first incomplete part or Part 1
    const firstIncomplete = currentProgress.find(p => p.status === 'not_started' || p.status === 'in_progress');
    switchPart(firstIncomplete ? firstIncomplete.part_number : 1);
    
  } catch (error) {
    console.error('Failed to load profile:', error);
    Toast.error('Error', `Failed to load profile: ${error.message}`);
    showEmptyState();
  }
}

function showEmptyState() {
  document.getElementById('noProfileState').style.display = 'flex';
  document.getElementById('workspaceContent').style.display = 'none';
}

// ============================================================================
// PARTS LIST RENDERING
// ============================================================================
function renderPartsList() {
  const container = document.getElementById('partsList');
  
  container.innerHTML = PARTS.map(part => {
    const progress = currentProgress.find(p => p.part_number === part.number) || { status: 'not_started' };
    const statusClass = progress.status.replace('_', '-');
    
    return `
      <div class="part-item ${statusClass} ${currentPart === part.number ? 'active' : ''}" 
           data-part="${part.number}" 
           onclick="switchPart(${part.number})">
        <div class="part-icon">${part.icon || part.number}</div>
        <div class="part-info">
          <div class="part-name">${part.name}</div>
          <div class="part-status">
            <span class="part-status-badge ${statusClass}">${formatStatus(progress.status)}</span>
          </div>
        </div>
      </div>
    `;
  }).join('');
}

function formatStatus(status) {
  const map = {
    'not_started': 'Not Started',
    'in_progress': 'In Progress',
    'submitted': 'Submitted',
    'reviewed': 'Reviewed'
  };
  return map[status] || status;
}

// ============================================================================
// PART SWITCHING
// ============================================================================
async function switchPart(partNumber) {
  // Save current part content before navigating away so data isn't lost
  if (currentProfileId && currentPart && partNumber !== currentPart) {
    collectDeliverableContentFromDOM(currentPart);
    const contentToSave = collectPartContent();
    const optionsToSave = JSON.stringify(selectedOptions[currentPart] || []);
    const partToSave = currentPart;
    const statusToSave = computePartStatus(currentPart);
    API.progress.update(currentProfileId, partToSave, {
      content: contentToSave,
      output_option: optionsToSave,
      status: statusToSave
    }).then(() => {
      const existing = currentProgress.find(p => p.part_number === partToSave);
      if (existing) {
        existing.content = contentToSave;
        existing.output_option = optionsToSave;
        existing.status = statusToSave;
      }
    }).catch(err => console.warn('[switchPart] Background save failed:', err));
  }

  currentPart = partNumber;
  const part = PARTS.find(p => p.number === partNumber);
  if (!part) return;
  
  // Update sidebar highlighting
  document.querySelectorAll('.part-item').forEach(el => el.classList.remove('active'));
  document.querySelector(`.part-item[data-part="${partNumber}"]`)?.classList.add('active');
  
  // Update header
  document.getElementById('currentPartBadge').textContent = `Part ${partNumber}`;
  document.getElementById('currentPartTitle').textContent = part.title;
  
  // Load progress for this part
  const progress = currentProgress.find(p => p.part_number === partNumber) || {
    part_number: partNumber,
    status: 'not_started',
    content: null,
    evidence_files: []
  };
  
  // Load saved options from progress data
  if (progress.output_option) {
    try {
      const parsed = typeof progress.output_option === 'string'
        ? JSON.parse(progress.output_option)
        : progress.output_option;
      selectedOptions[partNumber] = Array.isArray(parsed) ? parsed : [];
    } catch (e) {
      selectedOptions[partNumber] = [];
    }
  } else if (!selectedOptions[partNumber]) {
    selectedOptions[partNumber] = [];
  }

  // Fetch intake form status if Part 2
  if (partNumber === 2) {
    await fetchIntakeFormStatus();
  }

  // Render appropriate UI based on part type
  renderPartContent(part, progress);
  
  // Update button states
  updateButtonStates(progress);
}

// ============================================================================
// OPTION SELECTION & DELIVERABLE WORK AREAS
// ============================================================================

// In-memory deliverable content: { [partNumber]: { [optionKey]: [html, html, ...], general_notes: html } }
let deliverableContent = {};

function renderOptionSelector(partNumber) {
  const partOpts = PART_OPTIONS[partNumber];
  if (!partOpts) return '';

  const selected = selectedOptions[partNumber] || [];
  const selCount = selected.length;

  return `
    <div class="part-activities">
      <h4>Learning Activities</h4>
      <ul class="activity-list">
        ${partOpts.activities.map(a => `<li>${a}</li>`).join('')}
      </ul>
    </div>

    <div class="content-section">
      <div class="section-header">
        <h3>Choose Your Outputs</h3>
        <span class="option-count-badge ${selCount === 0 ? 'empty' : ''}">${selCount} selected</span>
      </div>
      <div class="section-body">
        <p style="color:var(--text-muted, #64748b); font-size:0.88rem; margin-bottom:1rem;">${partOpts.instructions}</p>
        <div class="options-grid">
          ${partOpts.options.map(opt => {
            const isSel = selected.includes(opt.key);
            return `
              <div class="option-card ${isSel ? 'selected' : ''}"
                   onclick="toggleOption(${partNumber}, '${opt.key}')" data-option-key="${opt.key}">
                <div class="option-card-header">
                  <input type="checkbox" ${isSel ? 'checked' : ''}
                         onclick="event.stopPropagation(); toggleOption(${partNumber}, '${opt.key}')"
                         class="option-checkbox">
                  <span class="option-name">${opt.name}</span>
                </div>
                <p class="option-description">${opt.description}</p>
                <span class="option-deliverable-count">${opt.deliverables.length} deliverable${opt.deliverables.length !== 1 ? 's' : ''}</span>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    </div>
  `;
}

function renderDeliverableWorkAreas(partNumber) {
  const partOpts = PART_OPTIONS[partNumber];
  const selected = selectedOptions[partNumber] || [];
  if (!partOpts || selected.length === 0) {
    return `
      <div class="no-options-state">
        <div class="no-options-icon">&#9998;</div>
        <h4>Select an output option above to begin</h4>
        <p>Choose one or more output options and your deliverable work areas will appear here.</p>
      </div>
    `;
  }

  // Ensure the active tab is valid for this part
  if (!activeDeliverableTabs[partNumber] || !selected.includes(activeDeliverableTabs[partNumber])) {
    activeDeliverableTabs[partNumber] = selected[0];
  }
  const activeKey = activeDeliverableTabs[partNumber];
  const savedContent = deliverableContent[partNumber] || {};

  // Build tab buttons
  const tabs = selected.map(optKey => {
    const opt = partOpts.options.find(o => o.key === optKey);
    if (!opt) return '';
    const optContent = savedContent[optKey] || [];
    const filledCount = opt.deliverables.filter((_, i) =>
      (optContent[i] || '').replace(/<[^>]*>/g, '').trim().length > 0
    ).length;
    const total = opt.deliverables.length;
    const isActive = optKey === activeKey;
    const isComplete = filledCount === total && total > 0;
    const badgeClass = isComplete ? 'complete' : filledCount > 0 ? 'partial' : '';
    return `
      <button class="deliverable-tab${isActive ? ' active' : ''}"
              onclick="switchDeliverableTab(${partNumber}, '${optKey}')"
              data-option-key="${optKey}"
              title="${opt.name}">
        <span class="tab-label">${opt.name}</span>
        <span class="tab-badge ${badgeClass}">${filledCount}/${total}</span>
      </button>
    `;
  }).join('');

  // Build the active tab's deliverable panel
  const activeOpt = partOpts.options.find(o => o.key === activeKey);
  const activeContent = savedContent[activeKey] || [];
  const panel = activeOpt ? activeOpt.deliverables.map((del, i) => {
    const val = activeContent[i] || '';
    const hasContent = val.replace(/<[^>]*>/g, '').trim().length > 0;
    return `
      <div class="deliverable-item">
        <div class="deliverable-label">
          <span class="deliverable-number ${hasContent ? 'has-content' : ''}">${i + 1}</span>
          <span class="deliverable-label-text">${del}</span>
        </div>
        <div class="deliverable-editor" contenteditable="true"
             data-option="${activeKey}" data-del-index="${i}"
             data-placeholder="Write your response for this deliverable...">${val}</div>
      </div>
    `;
  }).join('') : '';

  return `
    <div class="deliverable-tabs-container" id="deliverableWorkAreas-${partNumber}">
      <div class="deliverable-tab-bar" role="tablist">
        ${tabs}
      </div>
      <div class="deliverable-tab-panel">
        ${panel}
      </div>
    </div>
  `;
}

function renderGeneralNotes(partNumber) {
  const saved = deliverableContent[partNumber] || {};
  const notes = saved.general_notes || '';
  return `
    <div class="content-section general-notes-section">
      <div class="section-header">
        <h3>Additional Notes</h3>
        <span class="word-count" id="wordCount">0 words</span>
      </div>
      <div class="section-body">
        <div class="deliverable-editor" id="generalNotesEditor" contenteditable="true"
             data-placeholder="Optional: add any additional analysis, observations, or notes..."
             style="min-height:80px;">${notes}</div>
      </div>
    </div>
  `;
}

function toggleWorkArea(headerEl) {
  headerEl.closest('.work-area').classList.toggle('collapsed');
}

function switchDeliverableTab(partNumber, optionKey) {
  collectDeliverableContentFromDOM(partNumber);
  activeDeliverableTabs[partNumber] = optionKey;
  const container = document.getElementById(`deliverableWorkAreas-${partNumber}`);
  if (container) {
    container.outerHTML = renderDeliverableWorkAreas(partNumber);
    initializeDeliverableEditors();
  }
}

function updateTabProgress(partNumber, optionKey) {
  const partOpts = PART_OPTIONS[partNumber];
  if (!partOpts) return;
  const opt = partOpts.options.find(o => o.key === optionKey);
  if (!opt) return;

  const editors = document.querySelectorAll(`.deliverable-editor[data-option="${optionKey}"]`);
  let filled = 0;
  editors.forEach(ed => { if (ed.innerText.trim().length > 0) filled++; });
  const total = opt.deliverables.length;
  const isComplete = filled === total && total > 0;
  const badgeClass = isComplete ? 'complete' : filled > 0 ? 'partial' : '';

  const tab = document.querySelector(`.deliverable-tab[data-option-key="${optionKey}"]`);
  if (tab) {
    const badge = tab.querySelector('.tab-badge');
    if (badge) {
      badge.textContent = `${filled}/${total}`;
      badge.className = `tab-badge ${badgeClass}`;
    }
  }
}

function toggleOption(partNumber, optionKey) {
  if (!selectedOptions[partNumber]) selectedOptions[partNumber] = [];

  const idx = selectedOptions[partNumber].indexOf(optionKey);
  if (idx >= 0) {
    selectedOptions[partNumber].splice(idx, 1);
  } else {
    selectedOptions[partNumber].push(optionKey);
  }

  // Collect current editor content before re-render so we don't lose it
  collectDeliverableContentFromDOM(partNumber);

  // Save options to backend
  saveSelectedOptions();

  // Re-render
  const part = PARTS.find(p => p.number === partNumber);
  const progress = currentProgress.find(p => p.part_number === partNumber) || {
    part_number: partNumber, status: 'not_started', content: null, evidence_files: []
  };
  renderPartContent(part, progress);
}

function collectDeliverableContentFromDOM(partNumber) {
  if (!deliverableContent[partNumber]) deliverableContent[partNumber] = {};

  document.querySelectorAll('.deliverable-editor[data-option]').forEach(ed => {
    const optKey = ed.getAttribute('data-option');
    const delIdx = parseInt(ed.getAttribute('data-del-index'));
    if (!isNaN(delIdx)) {
      if (!deliverableContent[partNumber][optKey]) deliverableContent[partNumber][optKey] = [];
      deliverableContent[partNumber][optKey][delIdx] = ed.innerHTML;
    }
  });

  const notesEd = document.getElementById('generalNotesEditor');
  if (notesEd) {
    deliverableContent[partNumber].general_notes = notesEd.innerHTML;
  }
}

function computePartStatus(partNumber) {
  const selected = selectedOptions[partNumber] || [];
  if (selected.length > 0) return 'in_progress';
  const content = deliverableContent[partNumber] || {};
  const hasContent = Object.entries(content).some(([key, val]) => {
    if (key === 'general_notes') return typeof val === 'string' && val.replace(/<[^>]*>/g, '').trim().length > 0;
    if (Array.isArray(val)) return val.some(html => (html || '').replace(/<[^>]*>/g, '').trim().length > 0);
    return false;
  });
  return hasContent ? 'in_progress' : 'not_started';
}

async function saveSelectedOptions() {
  try {
    const optionsData = JSON.stringify(selectedOptions[currentPart] || []);
    const status = computePartStatus(currentPart);
    await API.progress.update(currentProfileId, currentPart, {
      output_option: optionsData,
      status
    });
    const existing = currentProgress.find(p => p.part_number === currentPart);
    if (existing) {
      existing.output_option = optionsData;
      existing.status = status;
    } else {
      currentProgress.push({ part_number: currentPart, output_option: optionsData, status });
    }
    renderPartsList();
  } catch (error) {
    console.error('Failed to save options:', error);
  }
}

// ============================================================================
// PART CONTENT RENDERING
// ============================================================================
function renderPartContent(part, progress) {
  const container = document.getElementById('workspaceBody');

  // Load deliverable content from progress before rendering
  loadDeliverableContent(part.number, progress);

  switch (part.type) {
    case 'narrative':
      container.innerHTML = renderNarrativePart(part, progress);
      break;
    case 'hybrid':
      container.innerHTML = renderHybridPart(part, progress);
      break;
    case 'structured':
      container.innerHTML = renderStructuredPart(part, progress);
      break;
    default:
      container.innerHTML = renderDefaultPart(part, progress);
  }

  // Initialize all editors (deliverable editors + general notes)
  initializeDeliverableEditors();
}

// Default part renderer (fallback)
function renderDefaultPart(part, progress) {
  return `
    <div class="content-section">
      <div class="section-header">
        <h3>📋 Instructions</h3>
      </div>
      <div class="section-body">
        <p>Complete the work for Part ${part.number}: ${part.title}</p>
        <p>${part.description}</p>
      </div>
    </div>
    
    <div class="content-section">
      <div class="section-header">
        <h3>✍️ Your Work</h3>
      </div>
      <div class="section-body">
        <div id="richTextEditor" class="rich-editor" contenteditable="true" 
             data-placeholder="Start writing your response here...">
          ${progress.content || ''}
        </div>
      </div>
    </div>
    
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

// Narrative parts (Parts 1, 7, 8) - Option selector + deliverable work areas
function renderNarrativePart(part, progress) {
  return `
    ${renderOptionSelector(part.number)}
    ${renderDeliverableWorkAreas(part.number)}
    ${renderGeneralNotes(part.number)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

// Hybrid part (Part 2) - Intake form + interview + option selector + work areas
function renderHybridPart(part, progress) {
  const statusBadge = getIntakeFormStatusBadge();
  const pct = intakeFormStatus.completion || 0;

  return `
    <div class="content-section">
      <div class="section-header">
        <h3>Client Data Gathering Tools</h3>
      </div>
      <div class="section-body">
        <div style="display:grid; grid-template-columns:1fr 1fr; gap:1rem; margin-bottom:0.5rem;">
          <div style="border:1.5px solid var(--border-color, #e2e8f0); border-radius:10px; padding:1rem; background:var(--bg-card, #fafbfc);">
            <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.5rem;">
              <strong style="font-size:0.9rem; color:var(--text-primary, #334155);">Client Intake Form</strong>
              <span id="intakeFormStatusBadge" class="part-status-badge ${intakeFormStatus.status.replace('_', '-')}" style="font-size:0.75rem;">
                ${statusBadge}
              </span>
            </div>
            <p style="font-size:0.82rem; color:var(--text-muted, #64748b); margin:0 0 0.75rem;">Gather structured data about the organization, systems, and policies.</p>
            <div style="display:flex; align-items:center; gap:0.75rem;">
              <button class="btn btn-primary btn-sm" onclick="openIntakeForm()">Open Intake Form</button>
              ${pct > 0 && pct < 100 ? `<span style="font-size:0.78rem; color:#d97706;">${pct}% complete</span>` : ''}
            </div>
          </div>
          <div style="border:1.5px solid var(--border-color, #e2e8f0); border-radius:10px; padding:1rem; background:var(--bg-card, #fafbfc);">
            <strong style="font-size:0.9rem; color:var(--text-primary, #334155); display:block; margin-bottom:0.5rem;">Stakeholder Interviews</strong>
            <p style="font-size:0.82rem; color:var(--text-muted, #64748b); margin:0 0 0.75rem;">Ask questions to key personnel about their roles, concerns, and operations.</p>
            <button class="btn btn-outline btn-sm" onclick="openInterviewSimulator()">Start Interview</button>
          </div>
        </div>
      </div>
    </div>

    ${renderOptionSelector(part.number)}
    ${renderDeliverableWorkAreas(part.number)}
    ${renderGeneralNotes(part.number)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

// Structured parts (Parts 3-6) - Tables/forms
function renderStructuredPart(part, progress) {
  // Load structured data from progress
  loadStructuredData(progress);
  
  switch (part.number) {
    case 3: return renderThreatIdentification(window.currentStructuredData, progress);
    case 4: return renderVulnerabilityIdentification(window.currentStructuredData, progress);
    case 5: return renderRiskAnalysis(window.currentStructuredData, progress);
    case 6: return renderControlRecommendations(window.currentStructuredData, progress);
    default: return renderDefaultPart(part, progress);
  }
}

// Part 3: Threat Identification
function renderThreatIdentification(data, progress) {
  const threats = data.threats || [];

  return `
    ${renderOptionSelector(3)}

    <div class="content-section">
      <div class="section-header">
        <h3>Threat Register</h3>
        <button class="btn btn-sm btn-primary" onclick="addThreat()">+ Add Threat</button>
      </div>
      <div class="section-body">
        <div id="threatsList">${renderThreatsList(threats)}</div>
      </div>
    </div>

    ${renderDeliverableWorkAreas(3)}
    ${renderGeneralNotes(3)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

function renderThreatsList(threats) {
  if (!threats.length) {
    return '<p class="empty-state">No threats added yet. Click "+ Add Threat" to begin.</p>';
  }
  
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Threat Name</th>
          <th>Threat Actor</th>
          <th>Attack Vector</th>
          <th>Target Assets</th>
          <th>Likelihood</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${threats.map((t, i) => `
          <tr>
            <td>${t.name || 'Unnamed Threat'}</td>
            <td>${t.actor || 'Unknown'}</td>
            <td>${t.vector || 'N/A'}</td>
            <td>${(t.targets || []).join(', ') || 'None'}</td>
            <td><span class="badge badge-${t.likelihood?.toLowerCase() || 'medium'}">${t.likelihood || 'Medium'}</span></td>
            <td>
              <button class="btn-icon" onclick="editThreat(${i})" title="Edit">✏️</button>
              <button class="btn-icon" onclick="deleteThreat(${i})" title="Delete">🗑️</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// Part 4: Vulnerability Identification
function renderVulnerabilityIdentification(data, progress) {
  const vulns = data.vulnerabilities || [];

  return `
    ${renderOptionSelector(4)}

    <div class="content-section">
      <div class="section-header">
        <h3>Vulnerability Register</h3>
        <button class="btn btn-sm btn-primary" onclick="addVulnerability()">+ Add Vulnerability</button>
      </div>
      <div class="section-body">
        <div id="vulnerabilitiesList">${renderVulnerabilitiesList(vulns)}</div>
      </div>
    </div>

    ${renderDeliverableWorkAreas(4)}
    ${renderGeneralNotes(4)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

function renderVulnerabilitiesList(vulns) {
  if (!vulns.length) {
    return '<p class="empty-state">No vulnerabilities added yet. Click "+ Add Vulnerability" to begin.</p>';
  }
  
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Vulnerability</th>
          <th>Category</th>
          <th>Affected Asset</th>
          <th>Severity</th>
          <th>Evidence</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${vulns.map((v, i) => `
          <tr>
            <td>${v.name || 'Unnamed Vulnerability'}</td>
            <td>${v.category || 'Unknown'}</td>
            <td>${v.asset || 'N/A'}</td>
            <td><span class="badge badge-${v.severity?.toLowerCase() || 'medium'}">${v.severity || 'Medium'}</span></td>
            <td>${v.evidence || 'No evidence'}</td>
            <td>
              <button class="btn-icon" onclick="editVulnerability(${i})" title="Edit">✏️</button>
              <button class="btn-icon" onclick="deleteVulnerability(${i})" title="Delete">🗑️</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// Part 5: Risk Analysis
function renderRiskAnalysis(data, progress) {
  const risks = data.risks || [];

  return `
    ${renderOptionSelector(5)}

    <div class="content-section">
      <div class="section-header">
        <h3>Risk Register</h3>
        <button class="btn btn-sm btn-primary" onclick="addRisk()">+ Add Risk</button>
      </div>
      <div class="section-body">
        <div id="risksList">${renderRisksList(risks)}</div>
      </div>
    </div>

    ${renderDeliverableWorkAreas(5)}
    ${renderGeneralNotes(5)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

function renderRisksList(risks) {
  if (!risks.length) {
    return '<p class="empty-state">No risks added yet. Click "+ Add Risk" to begin.</p>';
  }
  
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Risk ID</th>
          <th>Risk Description</th>
          <th>Likelihood</th>
          <th>Impact</th>
          <th>Risk Level</th>
          <th>Priority</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${risks.map((r, i) => `
          <tr>
            <td><strong>R-${String(i + 1).padStart(3, '0')}</strong></td>
            <td>${r.description || 'No description'}</td>
            <td><span class="badge badge-${r.likelihood?.toLowerCase() || 'medium'}">${r.likelihood || 'Medium'}</span></td>
            <td><span class="badge badge-${r.impact?.toLowerCase() || 'medium'}">${r.impact || 'Medium'}</span></td>
            <td><span class="badge badge-${r.level?.toLowerCase() || 'medium'}">${r.level || 'Medium'}</span></td>
            <td>${r.priority || 'N/A'}</td>
            <td>
              <button class="btn-icon" onclick="editRisk(${i})" title="Edit">✏️</button>
              <button class="btn-icon" onclick="deleteRisk(${i})" title="Delete">🗑️</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// Part 6: Control Recommendations
function renderControlRecommendations(data, progress) {
  const controls = data.controls || [];

  return `
    ${renderOptionSelector(6)}

    <div class="content-section">
      <div class="section-header">
        <h3>Control Recommendations</h3>
        <button class="btn btn-sm btn-primary" onclick="addControl()">+ Add Control</button>
      </div>
      <div class="section-body">
        <div id="controlsList">${renderControlsList(controls)}</div>
      </div>
    </div>

    ${renderDeliverableWorkAreas(6)}
    ${renderGeneralNotes(6)}
    ${renderEvidenceSection(progress.evidence_files)}
    ${renderFeedbackSection(progress)}
  `;
}

function renderControlsList(controls) {
  if (!controls.length) {
    return '<p class="empty-state">No controls added yet. Click "+ Add Control" to begin.</p>';
  }
  
  return `
    <table class="data-table">
      <thead>
        <tr>
          <th>Control</th>
          <th>Framework</th>
          <th>Priority</th>
          <th>Estimated Cost</th>
          <th>Addresses Risks</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${controls.map((c, i) => `
          <tr>
            <td>${c.name || 'Unnamed Control'}</td>
            <td>${c.framework || 'N/A'}</td>
            <td><span class="badge badge-${c.priority?.toLowerCase() || 'medium'}">${c.priority || 'Medium'}</span></td>
            <td>${c.cost || 'Unknown'}</td>
            <td>${(c.risks || []).join(', ') || 'None'}</td>
            <td>
              <button class="btn-icon" onclick="editControl(${i})" title="Edit">✏️</button>
              <button class="btn-icon" onclick="deleteControl(${i})" title="Delete">🗑️</button>
            </td>
          </tr>
        `).join('')}
      </tbody>
    </table>
  `;
}

// ============================================================================
// REUSABLE SECTIONS
// ============================================================================
function renderEvidenceSection(files) {
  return `
    <div class="content-section">
      <div class="section-header">
        <h3>📎 Evidence & Attachments</h3>
        <button class="btn btn-sm btn-outline" onclick="document.getElementById('fileUpload').click()">
          📤 Upload File
        </button>
        <input type="file" id="fileUpload" style="display: none;" multiple onchange="handleFileUpload(event)">
      </div>
      <div class="section-body">
        <div id="evidenceList">
          ${renderEvidenceList(files)}
        </div>
      </div>
    </div>
  `;
}

function renderEvidenceList(files) {
  if (!files || !files.length) {
    return '<p class="empty-state">No files attached yet.</p>';
  }
  
  return `
    <ul class="file-list">
      ${files.map((f, i) => `
        <li class="file-item">
          <span class="file-icon">📄</span>
          <span class="file-name">${f.name}</span>
          <span class="file-size">${formatFileSize(f.size)}</span>
          <button class="btn-icon" onclick="removeFile(${i})">🗑️</button>
        </li>
      `).join('')}
    </ul>
  `;
}

function renderFeedbackSection(progress) {
  if (progress.status !== 'reviewed' || !progress.feedback) {
    return '';
  }
  
  return `
    <div class="content-section feedback-section">
      <div class="section-header">
        <h3>📝 Instructor Feedback</h3>
        ${progress.score ? `<span class="score-badge">${progress.score}/100</span>` : ''}
      </div>
      <div class="section-body">
        <div class="feedback-content">
          ${progress.feedback}
        </div>
        ${progress.rubric_scores ? `
          <div class="rubric-scores">
            <h4>Rubric Breakdown</h4>
            ${Object.entries(progress.rubric_scores).map(([key, val]) => `
              <div class="rubric-item">
                <span>${key}:</span>
                <span><strong>${val}</strong></span>
              </div>
            `).join('')}
          </div>
        ` : ''}
      </div>
    </div>
  `;
}


// ============================================================================
// SAVE & SUBMIT FUNCTIONS
// ============================================================================
async function saveDraft() {
  try {
    showAutoSaveStatus('saving');

    // Collect deliverable content from DOM before building payload
    collectDeliverableContentFromDOM(currentPart);

    const content = collectPartContent();
    const optionsData = JSON.stringify(selectedOptions[currentPart] || []);

    await API.progress.update(currentProfileId, currentPart, {
      content: content,
      output_option: optionsData,
      status: computePartStatus(currentPart)
    });

    showAutoSaveStatus('saved');

    // Update local state instead of re-fetching from the server
    const status = computePartStatus(currentPart);
    const existing = currentProgress.find(p => p.part_number === currentPart);
    if (existing) {
      existing.content = content;
      existing.output_option = optionsData;
      existing.status = status;
    } else {
      currentProgress.push({ part_number: currentPart, content, output_option: optionsData, status });
    }
    renderPartsList();
    updateOverallProgress();

  } catch (error) {
    console.error('Save failed:', error);
    showAutoSaveStatus('error');
    Toast.error('Save Failed', error.message);
  }
}

function collectPartContent() {
  const part = PARTS.find(p => p.number === currentPart);
  const saved = deliverableContent[currentPart] || {};

  // Build structured content envelope
  const envelope = {
    deliverables: {},
    general_notes: saved.general_notes || ''
  };

  // Collect deliverable content per option
  const selected = selectedOptions[currentPart] || [];
  for (const key of selected) {
    if (saved[key]) {
      envelope.deliverables[key] = saved[key];
    }
  }

  // For structured parts, include the table data
  if (part.type === 'structured') {
    envelope.structured_data = window.currentStructuredData || {};
  }

  return JSON.stringify(envelope);
}

async function showSubmitModal() {
  await saveDraft();

  const selected = selectedOptions[currentPart] || [];
  const partOpts = PART_OPTIONS[currentPart];
  const deliverablesDiv = document.getElementById('submitDeliverables');
  const savedContent = deliverableContent[currentPart] || {};

  if (partOpts && selected.length > 0) {
    const selectedOpts = partOpts.options.filter(o => selected.includes(o.key));
    let completedCount = 0;
    let totalCount = 0;

    const listHtml = selectedOpts.map(opt => {
      const optContent = savedContent[opt.key] || [];
      return opt.deliverables.map((del, i) => {
        totalCount++;
        const filled = (optContent[i] || '').replace(/<[^>]*>/g, '').trim().length > 0;
        if (filled) completedCount++;
        return `<li>
          <span class="${filled ? 'check-done' : 'check-empty'}">${filled ? '&#10003;' : '&#9675;'}</span>
          ${del}
        </li>`;
      }).join('');
    }).join('');

    deliverablesDiv.innerHTML = `
      <div style="margin-bottom:1rem;">
        <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:0.4rem;">
          <strong style="font-size:0.85rem; color:var(--text-primary, #334155);">Deliverable Completion</strong>
          <span style="font-size:0.82rem; color:${completedCount === totalCount ? '#10b981' : '#d97706'}; font-weight:600;">
            ${completedCount}/${totalCount} complete
          </span>
        </div>
        <ul class="submit-deliverables-list">${listHtml}</ul>
      </div>
    `;
  } else if (partOpts) {
    deliverablesDiv.innerHTML = `
      <div class="submit-options-warning">
        No output options selected. Consider selecting options above to define your deliverables before submitting.
      </div>
    `;
  } else {
    deliverablesDiv.innerHTML = '';
  }

  document.getElementById('submitModal').classList.add('active');
  document.getElementById('checkContent').checked = false;
  document.getElementById('checkEvidence').checked = false;
  document.getElementById('checkReview').checked = false;
  updateSubmitButton();
}

function setupSubmitModal() {
  // Enable submit button when all checkboxes checked
  ['checkContent', 'checkEvidence', 'checkReview'].forEach(id => {
    document.getElementById(id)?.addEventListener('change', updateSubmitButton);
  });
}

function updateSubmitButton() {
  const allChecked = 
    document.getElementById('checkContent')?.checked &&
    document.getElementById('checkEvidence')?.checked &&
    document.getElementById('checkReview')?.checked;
  
  const btn = document.getElementById('confirmSubmitBtn');
  if (btn) btn.disabled = !allChecked;
}

async function confirmSubmit() {
  try {
    await API.progress.submit(currentProfileId, currentPart);

    closeModal('submitModal');
    Toast.success('Submitted', `Part ${currentPart} submitted for review!`);
    
    // Reload progress
    const progressData = await API.progress.get(currentProfileId);
    currentProgress = progressData.progress || [];
    renderPartsList();
    updateOverallProgress();
    
    // Move to next part
    if (currentPart < 8) {
      switchPart(currentPart + 1);
    }
    
  } catch (error) {
    console.error('Submit failed:', error);
    Toast.error('Submit Failed', error.message);
  }
}

// ============================================================================
// UI HELPER FUNCTIONS
// ============================================================================
function updateOverallProgress() {
  const completed = currentProgress.filter(p => 
    p.status === 'submitted' || p.status === 'reviewed'
  ).length;
  
  const percent = Math.round((completed / 8) * 100);
  
  document.getElementById('overallProgressBar').style.width = `${percent}%`;
  document.getElementById('completedCount').textContent = `${completed} / 8 completed`;
  document.getElementById('progressPercent').textContent = `${percent}%`;
}

function updateButtonStates(progress) {
  const saveBtn = document.getElementById('saveDraftBtn');
  const submitBtn = document.getElementById('submitBtn');
  
  if (progress.status === 'reviewed' || progress.status === 'submitted') {
    if (submitBtn) submitBtn.disabled = true;
    if (submitBtn) submitBtn.textContent = progress.status === 'reviewed' ? '✓ Reviewed' : '⏳ Awaiting Review';
  } else {
    if (submitBtn) submitBtn.disabled = false;
    if (submitBtn) submitBtn.textContent = '✓ Submit for Review';
  }
}

function showAutoSaveStatus(status) {
  const indicator = document.getElementById('autosaveIndicator');
  const text = document.getElementById('autosaveText');
  
  indicator.className = 'autosave-indicator ' + status;
  
  const messages = {
    saving: 'Saving...',
    saved: 'Saved',
    error: 'Save Failed',
    ready: 'Ready'
  };
  
  text.textContent = messages[status] || 'Ready';
  
  if (status === 'saved') {
    setTimeout(() => showAutoSaveStatus('ready'), 2000);
  }
}

function closeModal(modalId) {
  const modal = document.getElementById(modalId);
  if (modal) {
    modal.classList.remove('active');
    // Remove dynamically created modals
    if (modalId !== 'submitModal') {
      setTimeout(() => modal.remove(), 200);
    }
  }
}

// ============================================================================
// PART 2 SPECIFIC FUNCTIONS
// ============================================================================

// Fetch intake form status
async function fetchIntakeFormStatus() {
  if (!currentProfileId) return;
  
  try {
    const response = await fetch(`/api/intake-form/${currentProfileId}`, {
      headers: {
        'Authorization': `Bearer ${localStorage.getItem('token')}`
      }
    });
    
    if (response.status === 401) {
      // Token expired — stop silently, don't overwrite status
      return;
    }
    if (!response.ok) {
      // Form doesn't exist yet - not started
      intakeFormStatus = { completion: 0, status: 'not_started' };
      return;
    }
    
    const data = await response.json();
    const completion = data.completion || 0;
    
    // Determine status based on completion
    let status = 'not_started';
    if (completion === 0) {
      status = 'not_started';
    } else if (completion === 100) {
      status = 'complete';
    } else {
      status = 'in_progress';
    }
    
    intakeFormStatus = { completion, status };
    
    // Update badge if Part 2 is currently displayed
    if (currentPart === 2) {
      updateIntakeFormBadge();
    }
    
  } catch (error) {
    console.error('Error fetching intake form status:', error);
    intakeFormStatus = { completion: 0, status: 'not_started' };
  }
}

// Get status badge text
function getIntakeFormStatusBadge() {
  switch (intakeFormStatus.status) {
    case 'not_started':
      return 'Not Started';
    case 'in_progress':
      return `In Progress (${intakeFormStatus.completion}%)`;
    case 'complete':
      return 'Complete ✓';
    default:
      return 'Not Started';
  }
}

// Update the badge dynamically
function updateIntakeFormBadge() {
  const badge = document.getElementById('intakeFormStatusBadge');
  if (!badge) return;
  
  badge.className = `part-status-badge ${intakeFormStatus.status.replace('_', '-')}`;
  badge.textContent = getIntakeFormStatusBadge();
}

function openIntakeForm() {
  window.open(`/ciab/intake-form?profileId=${currentProfileId}`, '_blank');
}

function openInterviewSimulator() {
  window.open(`/interview.html?profileId=${currentProfileId}`, '_blank');
}

// ============================================================================
// EDITOR INITIALIZATION (handles all deliverable editors + general notes)
// ============================================================================
function initializeDeliverableEditors() {
  // Attach auto-save to all deliverable editors
  document.querySelectorAll('.deliverable-editor').forEach(ed => {
    ed.addEventListener('input', () => {
      clearTimeout(autoSaveTimer);
      autoSaveTimer = setTimeout(saveDraft, 2000);
    });

    // Update progress indicators when content changes
    ed.addEventListener('input', () => {
      const optKey = ed.getAttribute('data-option');
      const delIdx = ed.getAttribute('data-del-index');
      if (optKey && delIdx !== null) {
        const hasContent = ed.innerText.trim().length > 0;
        const numEl = ed.closest('.deliverable-item')?.querySelector('.deliverable-number');
        if (numEl) numEl.classList.toggle('has-content', hasContent);

        // Update the tab badge progress
        updateTabProgress(currentPart, optKey);
      }
    });
  });

  // Word count on general notes
  const notesEd = document.getElementById('generalNotesEditor');
  if (notesEd) {
    const updateWordCount = () => {
      const text = notesEd.innerText || '';
      const words = text.trim().split(/\s+/).filter(w => w.length > 0).length;
      const counter = document.getElementById('wordCount');
      if (counter) counter.textContent = `${words} words`;
    };
    notesEd.addEventListener('input', updateWordCount);
    updateWordCount(); // initial count
  }
}

function updateWorkAreaProgress(workAreaEl) {
  const editors = workAreaEl.querySelectorAll('.deliverable-editor');
  const total = editors.length;
  let filled = 0;
  editors.forEach(ed => {
    if (ed.innerText.trim().length > 0) filled++;
  });
  const pct = total > 0 ? Math.round((filled / total) * 100) : 0;

  const fill = workAreaEl.querySelector('.progress-bar-mini-fill');
  const label = workAreaEl.querySelector('.deliverable-progress span');
  if (fill) {
    fill.style.width = pct + '%';
    fill.classList.toggle('complete', filled === total);
  }
  if (label) label.textContent = `${filled}/${total}`;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================
function formatFileSize(bytes) {
  if (bytes < 1024) return bytes + ' B';
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
  return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
}

function handleFileUpload(event) {
  // File upload handler - would upload to server
  console.log('Files selected:', event.target.files);
  Toast.info('File Upload', 'File upload feature coming soon');
}

function removeFile(index) {
  console.log('Remove file:', index);
  Toast.info('Remove File', 'File removal feature coming soon');
}

// ============================================================================
// CRUD FUNCTIONS FOR STRUCTURED DATA (Parts 3-6)
// ============================================================================

// Current structured data for parts 3-6
window.currentStructuredData = {
  threats: [],
  vulnerabilities: [],
  risks: [],
  controls: []
};

// Load structured data from progress (handles both old and new formats)
function loadStructuredData(progress) {
  try {
    const content = progress.content ? JSON.parse(progress.content) : {};

    // New envelope format has structured_data key
    if (content.structured_data) {
      const sd = content.structured_data;
      window.currentStructuredData = {
        threats: sd.threats || [],
        vulnerabilities: sd.vulnerabilities || [],
        risks: sd.risks || [],
        controls: sd.controls || []
      };
    } else {
      // Legacy format: content IS the structured data directly
      window.currentStructuredData = {
        threats: content.threats || [],
        vulnerabilities: content.vulnerabilities || [],
        risks: content.risks || [],
        controls: content.controls || []
      };
    }
  } catch (e) {
    console.error('Error loading structured data:', e);
    window.currentStructuredData = { threats: [], vulnerabilities: [], risks: [], controls: [] };
  }
}

// Load deliverable content from progress into memory (all part types)
function loadDeliverableContent(partNumber, progress) {
  if (!progress.content) {
    if (!deliverableContent[partNumber]) deliverableContent[partNumber] = {};
    return;
  }

  try {
    const content = typeof progress.content === 'string' ? JSON.parse(progress.content) : progress.content;

    if (content.deliverables || content.general_notes !== undefined) {
      // New envelope format
      deliverableContent[partNumber] = { ...content.deliverables };
      deliverableContent[partNumber].general_notes = content.general_notes || '';
    } else if (typeof progress.content === 'string' && !progress.content.startsWith('{')) {
      // Legacy HTML content - put it in general notes
      deliverableContent[partNumber] = { general_notes: progress.content };
    } else {
      // Legacy structured-only content or empty
      if (!deliverableContent[partNumber]) deliverableContent[partNumber] = {};
    }
  } catch (e) {
    // Non-JSON content (legacy HTML)
    deliverableContent[partNumber] = { general_notes: progress.content || '' };
  }
}

// ============================================================================
// THREAT CRUD FUNCTIONS
// ============================================================================
function addThreat() {
  showThreatModal();
}

function editThreat(index) {
  const threat = window.currentStructuredData.threats[index];
  if (threat) {
    showThreatModal(threat, index);
  }
}

async function deleteThreat(index) {
  if (await Confirm.show({ title: 'Delete this threat?', message: 'This cannot be undone.', confirmText: 'Delete', danger: true })) {
    window.currentStructuredData.threats.splice(index, 1);
    refreshThreatsList();
    saveDraft();
    Toast.success('Deleted', 'Threat removed');
  }
}

function showThreatModal(threat = null, editIndex = -1) {
  const isEdit = editIndex >= 0;
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.id = 'threatModal';
  modal.innerHTML = `
    <div class="modal-content" style="max-width: 600px;">
      <div class="modal-header">
        <h3>${isEdit ? 'Edit Threat' : 'Add New Threat'}</h3>
        <button class="modal-close" onclick="closeModal('threatModal')">&times;</button>
      </div>
      <form id="threatForm" onsubmit="saveThreat(event, ${editIndex})">
        <div class="form-group">
          <label for="threatName">Threat Name *</label>
          <input type="text" id="threatName" required placeholder="e.g., Ransomware Attack" value="${threat?.name || ''}">
        </div>
        <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
          <div class="form-group">
            <label for="threatActor">Threat Actor</label>
            <select id="threatActor">
              <option value="">Select...</option>
              <option value="Nation State" ${threat?.actor === 'Nation State' ? 'selected' : ''}>Nation State</option>
              <option value="Organized Crime" ${threat?.actor === 'Organized Crime' ? 'selected' : ''}>Organized Crime</option>
              <option value="Hacktivist" ${threat?.actor === 'Hacktivist' ? 'selected' : ''}>Hacktivist</option>
              <option value="Insider" ${threat?.actor === 'Insider' ? 'selected' : ''}>Insider (Malicious)</option>
              <option value="Insider Accidental" ${threat?.actor === 'Insider Accidental' ? 'selected' : ''}>Insider (Accidental)</option>
              <option value="Script Kiddie" ${threat?.actor === 'Script Kiddie' ? 'selected' : ''}>Script Kiddie</option>
              <option value="Competitor" ${threat?.actor === 'Competitor' ? 'selected' : ''}>Competitor</option>
            </select>
          </div>
          <div class="form-group">
            <label for="threatLikelihood">Likelihood</label>
            <select id="threatLikelihood">
              <option value="Low" ${threat?.likelihood === 'Low' ? 'selected' : ''}>Low</option>
              <option value="Medium" ${!threat || threat?.likelihood === 'Medium' ? 'selected' : ''}>Medium</option>
              <option value="High" ${threat?.likelihood === 'High' ? 'selected' : ''}>High</option>
              <option value="Critical" ${threat?.likelihood === 'Critical' ? 'selected' : ''}>Critical</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label for="threatVector">Attack Vector</label>
          <input type="text" id="threatVector" placeholder="e.g., Phishing email, Exposed service" value="${threat?.vector || ''}">
        </div>
        <div class="form-group">
          <label for="threatTargets">Target Assets (comma-separated)</label>
          <input type="text" id="threatTargets" placeholder="e.g., File servers, User workstations" value="${(threat?.targets || []).join(', ')}">
        </div>
        <div class="form-group">
          <label for="threatDescription">Description</label>
          <textarea id="threatDescription" rows="3" placeholder="Describe the threat scenario...">${threat?.description || ''}</textarea>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end;">
          <button type="button" class="btn btn-outline" onclick="closeModal('threatModal')">Cancel</button>
          <button type="submit" class="btn btn-primary">${isEdit ? 'Update' : 'Add'} Threat</button>
        </div>
      </form>
    </div>
  `;
  document.body.appendChild(modal);
}

function saveThreat(event, editIndex) {
  event.preventDefault();
  
  const threat = {
    name: document.getElementById('threatName').value,
    actor: document.getElementById('threatActor').value,
    likelihood: document.getElementById('threatLikelihood').value,
    vector: document.getElementById('threatVector').value,
    targets: document.getElementById('threatTargets').value.split(',').map(t => t.trim()).filter(t => t),
    description: document.getElementById('threatDescription').value
  };
  
  if (editIndex >= 0) {
    window.currentStructuredData.threats[editIndex] = threat;
  } else {
    window.currentStructuredData.threats.push(threat);
  }
  
  closeModal('threatModal');
  refreshThreatsList();
  saveDraft();
  Toast.success('Saved', editIndex >= 0 ? 'Threat updated' : 'Threat added');
}

function refreshThreatsList() {
  const container = document.getElementById('threatsList');
  if (container) {
    container.innerHTML = renderThreatsList(window.currentStructuredData.threats);
  }
}

// ============================================================================
// VULNERABILITY CRUD FUNCTIONS
// ============================================================================
function addVulnerability() {
  showVulnerabilityModal();
}

function editVulnerability(index) {
  const vuln = window.currentStructuredData.vulnerabilities[index];
  if (vuln) {
    showVulnerabilityModal(vuln, index);
  }
}

async function deleteVulnerability(index) {
  if (await Confirm.show({ title: 'Delete this vulnerability?', message: 'This cannot be undone.', confirmText: 'Delete', danger: true })) {
    window.currentStructuredData.vulnerabilities.splice(index, 1);
    refreshVulnerabilitiesList();
    saveDraft();
    Toast.success('Deleted', 'Vulnerability removed');
  }
}

function showVulnerabilityModal(vuln = null, editIndex = -1) {
  const isEdit = editIndex >= 0;
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.id = 'vulnModal';
  modal.innerHTML = `
    <div class="modal-content" style="max-width: 600px;">
      <div class="modal-header">
        <h3>${isEdit ? 'Edit Vulnerability' : 'Add New Vulnerability'}</h3>
        <button class="modal-close" onclick="closeModal('vulnModal')">&times;</button>
      </div>
      <form id="vulnForm" onsubmit="saveVulnerability(event, ${editIndex})">
        <div class="form-group">
          <label for="vulnName">Vulnerability Name *</label>
          <input type="text" id="vulnName" required placeholder="e.g., Outdated SSL Certificate" value="${vuln?.name || ''}">
        </div>
        <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
          <div class="form-group">
            <label for="vulnCategory">Category</label>
            <select id="vulnCategory">
              <option value="">Select...</option>
              <option value="Technical" ${vuln?.category === 'Technical' ? 'selected' : ''}>Technical</option>
              <option value="Configuration" ${vuln?.category === 'Configuration' ? 'selected' : ''}>Configuration</option>
              <option value="Policy" ${vuln?.category === 'Policy' ? 'selected' : ''}>Policy/Procedural</option>
              <option value="Physical" ${vuln?.category === 'Physical' ? 'selected' : ''}>Physical</option>
              <option value="Human" ${vuln?.category === 'Human' ? 'selected' : ''}>Human Factor</option>
              <option value="Third-Party" ${vuln?.category === 'Third-Party' ? 'selected' : ''}>Third-Party/Vendor</option>
            </select>
          </div>
          <div class="form-group">
            <label for="vulnSeverity">Severity</label>
            <select id="vulnSeverity">
              <option value="Low" ${vuln?.severity === 'Low' ? 'selected' : ''}>Low</option>
              <option value="Medium" ${!vuln || vuln?.severity === 'Medium' ? 'selected' : ''}>Medium</option>
              <option value="High" ${vuln?.severity === 'High' ? 'selected' : ''}>High</option>
              <option value="Critical" ${vuln?.severity === 'Critical' ? 'selected' : ''}>Critical</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label for="vulnAsset">Affected Asset</label>
          <input type="text" id="vulnAsset" placeholder="e.g., Web server, Database" value="${vuln?.asset || ''}">
        </div>
        <div class="form-group">
          <label for="vulnEvidence">Evidence/Source</label>
          <input type="text" id="vulnEvidence" placeholder="e.g., Nessus scan, Policy review" value="${vuln?.evidence || ''}">
        </div>
        <div class="form-group">
          <label for="vulnDescription">Description</label>
          <textarea id="vulnDescription" rows="3" placeholder="Describe the vulnerability...">${vuln?.description || ''}</textarea>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end;">
          <button type="button" class="btn btn-outline" onclick="closeModal('vulnModal')">Cancel</button>
          <button type="submit" class="btn btn-primary">${isEdit ? 'Update' : 'Add'} Vulnerability</button>
        </div>
      </form>
    </div>
  `;
  document.body.appendChild(modal);
}

function saveVulnerability(event, editIndex) {
  event.preventDefault();
  
  const vuln = {
    name: document.getElementById('vulnName').value,
    category: document.getElementById('vulnCategory').value,
    severity: document.getElementById('vulnSeverity').value,
    asset: document.getElementById('vulnAsset').value,
    evidence: document.getElementById('vulnEvidence').value,
    description: document.getElementById('vulnDescription').value
  };
  
  if (editIndex >= 0) {
    window.currentStructuredData.vulnerabilities[editIndex] = vuln;
  } else {
    window.currentStructuredData.vulnerabilities.push(vuln);
  }
  
  closeModal('vulnModal');
  refreshVulnerabilitiesList();
  saveDraft();
  Toast.success('Saved', editIndex >= 0 ? 'Vulnerability updated' : 'Vulnerability added');
}

function refreshVulnerabilitiesList() {
  const container = document.getElementById('vulnerabilitiesList');
  if (container) {
    container.innerHTML = renderVulnerabilitiesList(window.currentStructuredData.vulnerabilities);
  }
}

// ============================================================================
// RISK CRUD FUNCTIONS
// ============================================================================
function addRisk() {
  showRiskModal();
}

function editRisk(index) {
  const risk = window.currentStructuredData.risks[index];
  if (risk) {
    showRiskModal(risk, index);
  }
}

async function deleteRisk(index) {
  if (await Confirm.show({ title: 'Delete this risk?', message: 'This cannot be undone.', confirmText: 'Delete', danger: true })) {
    window.currentStructuredData.risks.splice(index, 1);
    refreshRisksList();
    saveDraft();
    Toast.success('Deleted', 'Risk removed');
  }
}

function showRiskModal(risk = null, editIndex = -1) {
  const isEdit = editIndex >= 0;
  const threats = window.currentStructuredData.threats.map(t => t.name);
  const vulns = window.currentStructuredData.vulnerabilities.map(v => v.name);
  
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.id = 'riskModal';
  modal.innerHTML = `
    <div class="modal-content" style="max-width: 650px;">
      <div class="modal-header">
        <h3>${isEdit ? 'Edit Risk' : 'Add New Risk'}</h3>
        <button class="modal-close" onclick="closeModal('riskModal')">&times;</button>
      </div>
      <form id="riskForm" onsubmit="saveRisk(event, ${editIndex})">
        <div class="form-group">
          <label for="riskDescription">Risk Description *</label>
          <textarea id="riskDescription" rows="2" required placeholder="Describe the risk scenario...">${risk?.description || ''}</textarea>
        </div>
        <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
          <div class="form-group">
            <label for="riskThreat">Related Threat</label>
            <select id="riskThreat">
              <option value="">Select...</option>
              ${threats.map(t => `<option value="${t}" ${risk?.threat === t ? 'selected' : ''}>${t}</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label for="riskVuln">Related Vulnerability</label>
            <select id="riskVuln">
              <option value="">Select...</option>
              ${vulns.map(v => `<option value="${v}" ${risk?.vulnerability === v ? 'selected' : ''}>${v}</option>`).join('')}
            </select>
          </div>
        </div>
        <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 1rem;">
          <div class="form-group">
            <label for="riskLikelihood">Likelihood</label>
            <select id="riskLikelihood" onchange="calculateRiskLevel()">
              <option value="1" ${risk?.likelihood === 'Low' ? 'selected' : ''}>1 - Low</option>
              <option value="2" ${!risk || risk?.likelihood === 'Medium' ? 'selected' : ''}>2 - Medium</option>
              <option value="3" ${risk?.likelihood === 'High' ? 'selected' : ''}>3 - High</option>
              <option value="4" ${risk?.likelihood === 'Critical' ? 'selected' : ''}>4 - Critical</option>
            </select>
          </div>
          <div class="form-group">
            <label for="riskImpact">Impact</label>
            <select id="riskImpact" onchange="calculateRiskLevel()">
              <option value="1" ${risk?.impact === 'Low' ? 'selected' : ''}>1 - Low</option>
              <option value="2" ${!risk || risk?.impact === 'Medium' ? 'selected' : ''}>2 - Medium</option>
              <option value="3" ${risk?.impact === 'High' ? 'selected' : ''}>3 - High</option>
              <option value="4" ${risk?.impact === 'Critical' ? 'selected' : ''}>4 - Critical</option>
            </select>
          </div>
          <div class="form-group">
            <label>Risk Level</label>
            <div id="riskLevelDisplay" style="padding: 0.5rem; background: #fef3c7; border-radius: 4px; text-align: center; font-weight: 600;">
              Medium
            </div>
          </div>
        </div>
        <div class="form-group">
          <label for="riskPriority">Priority</label>
          <select id="riskPriority">
            <option value="1" ${risk?.priority === '1' ? 'selected' : ''}>1 (Highest)</option>
            <option value="2" ${risk?.priority === '2' ? 'selected' : ''}>2</option>
            <option value="3" ${!risk || risk?.priority === '3' ? 'selected' : ''}>3</option>
            <option value="4" ${risk?.priority === '4' ? 'selected' : ''}>4</option>
            <option value="5" ${risk?.priority === '5' ? 'selected' : ''}>5 (Lowest)</option>
          </select>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end;">
          <button type="button" class="btn btn-outline" onclick="closeModal('riskModal')">Cancel</button>
          <button type="submit" class="btn btn-primary">${isEdit ? 'Update' : 'Add'} Risk</button>
        </div>
      </form>
    </div>
  `;
  document.body.appendChild(modal);
  calculateRiskLevel();
}

function calculateRiskLevel() {
  const likelihood = parseInt(document.getElementById('riskLikelihood')?.value || 2);
  const impact = parseInt(document.getElementById('riskImpact')?.value || 2);
  const score = likelihood * impact;
  
  let level = 'Low';
  let color = '#d1fae5';
  
  if (score >= 12) { level = 'Critical'; color = '#fee2e2'; }
  else if (score >= 8) { level = 'High'; color = '#fed7aa'; }
  else if (score >= 4) { level = 'Medium'; color = '#fef3c7'; }
  else { level = 'Low'; color = '#d1fae5'; }
  
  const display = document.getElementById('riskLevelDisplay');
  if (display) {
    display.textContent = `${level} (${score})`;
    display.style.background = color;
  }
  
  return { level, score };
}

function saveRisk(event, editIndex) {
  event.preventDefault();
  
  const likelihoodMap = { '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical' };
  const impactMap = { '1': 'Low', '2': 'Medium', '3': 'High', '4': 'Critical' };
  const { level } = calculateRiskLevel();
  
  const risk = {
    description: document.getElementById('riskDescription').value,
    threat: document.getElementById('riskThreat').value,
    vulnerability: document.getElementById('riskVuln').value,
    likelihood: likelihoodMap[document.getElementById('riskLikelihood').value],
    impact: impactMap[document.getElementById('riskImpact').value],
    level: level,
    priority: document.getElementById('riskPriority').value
  };
  
  if (editIndex >= 0) {
    window.currentStructuredData.risks[editIndex] = risk;
  } else {
    window.currentStructuredData.risks.push(risk);
  }
  
  closeModal('riskModal');
  refreshRisksList();
  saveDraft();
  Toast.success('Saved', editIndex >= 0 ? 'Risk updated' : 'Risk added');
}

function refreshRisksList() {
  const container = document.getElementById('risksList');
  if (container) {
    container.innerHTML = renderRisksList(window.currentStructuredData.risks);
  }
}

// ============================================================================
// CONTROL CRUD FUNCTIONS
// ============================================================================
function addControl() {
  showControlModal();
}

function editControl(index) {
  const control = window.currentStructuredData.controls[index];
  if (control) {
    showControlModal(control, index);
  }
}

async function deleteControl(index) {
  if (await Confirm.show({ title: 'Delete this control?', message: 'This cannot be undone.', confirmText: 'Delete', danger: true })) {
    window.currentStructuredData.controls.splice(index, 1);
    refreshControlsList();
    saveDraft();
    Toast.success('Deleted', 'Control removed');
  }
}

function showControlModal(control = null, editIndex = -1) {
  const isEdit = editIndex >= 0;
  const risks = window.currentStructuredData.risks.map((r, i) => ({ id: `R-${String(i+1).padStart(3,'0')}`, desc: r.description }));
  
  const modal = document.createElement('div');
  modal.className = 'modal-overlay active';
  modal.id = 'controlModal';
  modal.innerHTML = `
    <div class="modal-content" style="max-width: 650px;">
      <div class="modal-header">
        <h3>${isEdit ? 'Edit Control' : 'Add New Control'}</h3>
        <button class="modal-close" onclick="closeModal('controlModal')">&times;</button>
      </div>
      <form id="controlForm" onsubmit="saveControl(event, ${editIndex})">
        <div class="form-group">
          <label for="controlName">Control Name *</label>
          <input type="text" id="controlName" required placeholder="e.g., Implement MFA" value="${control?.name || ''}">
        </div>
        <div class="form-row" style="display: grid; grid-template-columns: 1fr 1fr; gap: 1rem;">
          <div class="form-group">
            <label for="controlFramework">Framework Reference</label>
            <select id="controlFramework">
              <option value="">Select...</option>
              <option value="NIST CSF" ${control?.framework === 'NIST CSF' ? 'selected' : ''}>NIST CSF</option>
              <option value="CIS Controls" ${control?.framework === 'CIS Controls' ? 'selected' : ''}>CIS Controls</option>
              <option value="ISO 27001" ${control?.framework === 'ISO 27001' ? 'selected' : ''}>ISO 27001</option>
              <option value="HIPAA" ${control?.framework === 'HIPAA' ? 'selected' : ''}>HIPAA</option>
              <option value="PCI DSS" ${control?.framework === 'PCI DSS' ? 'selected' : ''}>PCI DSS</option>
              <option value="SOC 2" ${control?.framework === 'SOC 2' ? 'selected' : ''}>SOC 2</option>
            </select>
          </div>
          <div class="form-group">
            <label for="controlPriority">Priority</label>
            <select id="controlPriority">
              <option value="High" ${control?.priority === 'High' ? 'selected' : ''}>High (Quick Win)</option>
              <option value="Medium" ${!control || control?.priority === 'Medium' ? 'selected' : ''}>Medium</option>
              <option value="Low" ${control?.priority === 'Low' ? 'selected' : ''}>Low (Long-term)</option>
            </select>
          </div>
        </div>
        <div class="form-group">
          <label for="controlCost">Estimated Cost/Effort</label>
          <select id="controlCost">
            <option value="Low ($)" ${control?.cost === 'Low ($)' ? 'selected' : ''}>Low ($)</option>
            <option value="Medium ($$)" ${!control || control?.cost === 'Medium ($$)' ? 'selected' : ''}>Medium ($$)</option>
            <option value="High ($$$)" ${control?.cost === 'High ($$$)' ? 'selected' : ''}>High ($$$)</option>
            <option value="Very High ($$$$)" ${control?.cost === 'Very High ($$$$)' ? 'selected' : ''}>Very High ($$$$)</option>
          </select>
        </div>
        <div class="form-group">
          <label>Addresses Risks</label>
          <div style="max-height: 150px; overflow-y: auto; border: 1px solid #e2e8f0; border-radius: 4px; padding: 0.5rem;">
            ${risks.length > 0 ? risks.map(r => `
              <label style="display: flex; align-items: start; gap: 0.5rem; padding: 0.5rem; cursor: pointer;">
                <input type="checkbox" name="controlRisks" value="${r.id}" 
                       ${(control?.risks || []).includes(r.id) ? 'checked' : ''}>
                <span><strong>${r.id}:</strong> ${r.desc.substring(0, 60)}${r.desc.length > 60 ? '...' : ''}</span>
              </label>
            `).join('') : '<p style="color: #a0aec0; padding: 0.5rem;">No risks defined yet. Add risks in Part 5 first.</p>'}
          </div>
        </div>
        <div class="form-group">
          <label for="controlDescription">Implementation Notes</label>
          <textarea id="controlDescription" rows="3" placeholder="Describe how to implement this control...">${control?.description || ''}</textarea>
        </div>
        <div style="display: flex; gap: 1rem; justify-content: flex-end;">
          <button type="button" class="btn btn-outline" onclick="closeModal('controlModal')">Cancel</button>
          <button type="submit" class="btn btn-primary">${isEdit ? 'Update' : 'Add'} Control</button>
        </div>
      </form>
    </div>
  `;
  document.body.appendChild(modal);
}

function saveControl(event, editIndex) {
  event.preventDefault();
  
  const selectedRisks = Array.from(document.querySelectorAll('input[name="controlRisks"]:checked')).map(cb => cb.value);
  
  const control = {
    name: document.getElementById('controlName').value,
    framework: document.getElementById('controlFramework').value,
    priority: document.getElementById('controlPriority').value,
    cost: document.getElementById('controlCost').value,
    risks: selectedRisks,
    description: document.getElementById('controlDescription').value
  };
  
  if (editIndex >= 0) {
    window.currentStructuredData.controls[editIndex] = control;
  } else {
    window.currentStructuredData.controls.push(control);
  }
  
  closeModal('controlModal');
  refreshControlsList();
  saveDraft();
  Toast.success('Saved', editIndex >= 0 ? 'Control updated' : 'Control added');
}

function refreshControlsList() {
  const container = document.getElementById('controlsList');
  if (container) {
    container.innerHTML = renderControlsList(window.currentStructuredData.controls);
  }
}

// ============================================================================
// EVENT LISTENERS
// ============================================================================
function setupEventListeners() {
  // Mobile parts toggle
  window.togglePartsSidebar = () => {
    document.getElementById('partsSidebar')?.classList.toggle('mobile-open');
  };
}

// ============================================================================
// GLOBAL EXPORTS
// ============================================================================
window.switchPart = switchPart;
window.saveDraft = saveDraft;
window.showSubmitModal = showSubmitModal;
window.confirmSubmit = confirmSubmit;
window.closeModal = closeModal;
window.openIntakeForm = openIntakeForm;
window.openInterviewSimulator = openInterviewSimulator;
window.handleFileUpload = handleFileUpload;
window.removeFile = removeFile;

// Threat CRUD
window.addThreat = addThreat;
window.editThreat = editThreat;
window.deleteThreat = deleteThreat;
window.saveThreat = saveThreat;

// Vulnerability CRUD
window.addVulnerability = addVulnerability;
window.editVulnerability = editVulnerability;
window.deleteVulnerability = deleteVulnerability;
window.saveVulnerability = saveVulnerability;

// Risk CRUD
window.addRisk = addRisk;
window.editRisk = editRisk;
window.deleteRisk = deleteRisk;
window.saveRisk = saveRisk;
window.calculateRiskLevel = calculateRiskLevel;

// Control CRUD
window.addControl = addControl;
window.editControl = editControl;
window.deleteControl = deleteControl;
window.saveControl = saveControl;

// Options & Work Areas
window.toggleOption = toggleOption;
window.toggleWorkArea = toggleWorkArea;
window.switchDeliverableTab = switchDeliverableTab;