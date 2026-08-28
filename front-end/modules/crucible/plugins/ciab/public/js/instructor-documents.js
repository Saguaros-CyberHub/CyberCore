/**
 * instructor-documents.js — Documents & Answer Keys tab.
 * ============================================================================
 * Ported generation flows: scan documents, AI answer key (background job +
 * polling), policy documents, instructor packet PDF, and the drawn-role-gated
 * vuln-app answer key. Profile list comes from InstructorState.profiles — the
 * old page died writing to a nonexistent #assignProfile before this dropdown
 * ever populated, which is why this tab was dead on arrival.
 *
 * Loaded after instructor-core.js; depends on its globals (InstructorState,
 * esc, openModal, closeModal) and the kit (API, Toast, Confirm, Utils).
 */
/* global API, Toast, Confirm, Utils, InstructorState, esc, openModal, closeModal */

// ── AI model cost estimation ────────────────────────────────────────────────
// Prices are $ per million tokens.

const AI_MODEL_INFO = {
  'claude-sonnet-4-5': { label: 'Claude Sonnet 4.5', input: 3.00, output: 15.00, provider: 'anthropic', providerLabel: 'Anthropic (Claude)' },
  'claude-haiku-4-5': { label: 'Claude Haiku 4.5', input: 0.80, output: 4.00, provider: 'anthropic', providerLabel: 'Anthropic (Claude)' },
  'gemini-2.5-flash': { label: 'Gemini 2.5 Flash', input: 0.15, output: 0.60, provider: 'google', providerLabel: 'Google (Gemini)' },
  'gemini-2.5-pro': { label: 'Gemini 2.5 Pro', input: 1.25, output: 10.00, provider: 'google', providerLabel: 'Google (Gemini)' },
  'qwen3:14b': { label: 'Qwen 3.0 14B', input: 0, output: 0, provider: 'ollama', providerLabel: 'Local (Ollama)' },
  'llama3.2': { label: 'Llama 3.2', input: 0, output: 0, provider: 'ollama', providerLabel: 'Local (Ollama)' },
};

const DOC_ICONS = { nessus: '🔍', zap: '🕷️', nmap: '🔌', policies: '📋' };
const DOC_NAMES = {
  nessus: 'NESSUS Vulnerability Scan',
  zap: 'OWASP ZAP Security Report',
  nmap: 'NMAP Network Scan',
  policies: 'Security Policy Documents',
};

function formatFileSize(bytes) {
  if (!bytes) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

const Docs = {
  _inited: false,
  _docs: [],              // last-loaded documents; download buttons index into this
  _docsProfileId: null,
  _cachedExamples: null,  // { parts: [...], profileId }
  _pollTimer: null,
  _answerKeyProfileId: null,
  _pickerProfiles: [],
  _modalProfileId: null,  // target of #generateDocsModal

  ensureInit() {
    if (this._inited) return;
    this._inited = true;
    this.populateProfileSelect();
    // The profiles fetch may land before or after the first tab visit.
    InstructorState.on('profiles', () => this.populateProfileSelect());
    const select = document.getElementById('docProfileSelect');
    if (select) select.addEventListener('change', () => this.onProfileChange());
    this.updateCostEstimate();
    this.onProfileChange(); // paint the no-profile prompt state
  },

  populateProfileSelect() {
    const select = document.getElementById('docProfileSelect');
    if (!select) return;
    const prev = select.value;
    select.innerHTML = '<option value="">-- Select a profile --</option>'
      + InstructorState.profiles.map((p) => `<option value="${esc(p.id)}">${esc(p.display_name)}</option>`).join('');
    if (prev && InstructorState.profiles.some((p) => p.id === prev)) {
      select.value = prev;
    } else if (prev) {
      // The selected profile disappeared from the list — reset the buttons.
      this.onProfileChange();
    }
  },

  async onProfileChange() {
    const select = document.getElementById('docProfileSelect');
    const profileId = select ? select.value : '';

    document.getElementById('generateDocsBtn').disabled = !profileId;
    document.getElementById('downloadPdfBtn').disabled = true; // until documents load
    document.getElementById('generateExamplesBtn').disabled = !profileId;
    document.getElementById('generatePoliciesBtn').disabled = !profileId;
    document.getElementById('printPoliciesBtn').disabled = !profileId;
    document.getElementById('viewExamplesBtn').style.display = 'none';
    const vcsBtn = document.getElementById('viewVulnCheatSheetBtn');
    if (vcsBtn) vcsBtn.disabled = !profileId;

    ['generateStatus', 'examplesStatus', 'policiesStatus', 'vulnCheatSheetStatus'].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.textContent = '';
    });

    if (profileId) {
      await this.loadProfileDocuments(profileId);
      await this.checkGenerationStatus(profileId);
      await this.checkExistingExamples(profileId);
    } else {
      this._docs = [];
      this._docsProfileId = null;
      document.getElementById('documentGrid').innerHTML = '';
      document.getElementById('generatedDocsList').innerHTML = `
        <div class="empty-state">
          <div class="icon">📄</div>
          <h3>No Profile Selected</h3>
          <p>Select a profile above to view or generate its assessment documents.</p>
        </div>`;
    }
  },

  // ── Cost estimate ─────────────────────────────────────────────────────────

  getSelectedModel() {
    return document.getElementById('instructorLlmModel')?.value || 'claude-haiku-4-5';
  },

  formatCost(modelId, inputTokens, outputTokens) {
    const info = AI_MODEL_INFO[modelId] || { input: 0, output: 0, provider: 'unknown' };
    if (info.provider === 'ollama') return { text: 'Free (local)', color: 'var(--success)' };
    const total = (inputTokens / 1_000_000) * info.input + (outputTokens / 1_000_000) * info.output;
    if (total < 0.01) return { text: '< $0.01', color: 'var(--success)' };
    return {
      text: `~$${total.toFixed(2)}`,
      color: total > 0.50 ? 'var(--danger)' : total > 0.10 ? 'var(--warning)' : 'var(--success)',
    };
  },

  updateCostEstimate() {
    const modelId = this.getSelectedModel();
    const info = AI_MODEL_INFO[modelId] || {};

    const providerEl = document.getElementById('instructorProviderLabel');
    if (providerEl) providerEl.textContent = info.providerLabel || modelId;

    // Examples: 8 parts × ~1.5K in + ~9K out each. The .cost-chip class owns
    // the pill background; only the text color signals the price band.
    const setBadge = (id, cost) => {
      const badge = document.getElementById(id);
      if (!badge) return;
      badge.textContent = cost.text;
      badge.style.color = cost.color;
      badge.hidden = false;
    };
    setBadge('examplesCostBadge', this.formatCost(modelId, 12000, 72000));
    // Policies: ~5 policies × ~1.5K in + ~2.5K out each.
    setBadge('policyCostBadge', this.formatCost(modelId, 7500, 12500));

    const costEl = document.getElementById('instructorCostEstimate');
    const contextEl = document.getElementById('instructorCostContext');
    if (info.provider === 'ollama') {
      if (costEl) { costEl.textContent = 'Free'; costEl.style.color = 'var(--success)'; }
      if (contextEl) contextEl.textContent = 'Runs locally — no API cost';
    } else {
      const totalCost = this.formatCost(modelId, 19500, 84500); // examples + policies
      if (costEl) { costEl.textContent = totalCost.text; costEl.style.color = totalCost.color; }
      if (contextEl) contextEl.textContent = 'examples + policies';
    }
  },

  // ── Scan documents ────────────────────────────────────────────────────────

  async loadProfileDocuments(profileId) {
    const list = document.getElementById('generatedDocsList');
    if (list) {
      list.innerHTML = `
        <div class="skeleton skel-row"></div>
        <div class="skeleton skel-row"></div>`;
    }
    try {
      const data = await API.request(`/instructor/documents/${encodeURIComponent(profileId)}`);
      // Stale-response guard: a slower response for a previously selected
      // profile must not overwrite the one now on screen (the Download
      // buttons would silently serve the wrong profile's files).
      const selected = document.getElementById('docProfileSelect')?.value;
      if (selected && selected !== profileId) return;
      const documents = data.documents || [];
      this._docs = documents;
      this._docsProfileId = profileId;
      this.updateDocumentGrid(documents);
      this.updateGeneratedDocsList(documents);
      document.getElementById('downloadPdfBtn').disabled = documents.length === 0;
    } catch (error) {
      console.error('Error loading documents:', error);
      if (list) {
        list.innerHTML = `
          <div class="empty-state">
            <div class="icon">⚠️</div>
            <h3>Couldn't load documents</h3>
            <p>${esc(error.message)}</p>
            <button class="btn btn-outline btn-sm" onclick="Docs.loadProfileDocuments('${esc(profileId)}')">Retry</button>
          </div>`;
      }
    }
  },

  updateDocumentGrid(documents) {
    const grid = document.getElementById('documentGrid');
    if (!grid) return;
    const docTypes = [
      { type: 'nessus', icon: '🔍', name: 'NESSUS Scan', desc: 'Vulnerability scanner XML output' },
      { type: 'zap', icon: '🕷️', name: 'ZAP Report', desc: 'Web application security scan' },
      { type: 'nmap', icon: '🔌', name: 'NMAP Scan', desc: 'Network port scanner output' },
    ];
    grid.innerHTML = docTypes.map((dt) => {
      const idx = documents.findIndex((d) => d.type === dt.type);
      const generated = idx !== -1;
      return `
        <div class="doc-card">
          <div class="doc-card-title">${dt.icon} ${dt.name}</div>
          <div class="doc-card-meta">${dt.desc}</div>
          <span class="badge ${generated ? 'badge-blue' : 'badge-gray'}">${generated ? '✓ Generated' : 'Not Generated'}</span>
          ${generated ? `
            <div style="margin-top: 0.5rem;">
              <button class="btn btn-sm btn-outline" onclick="Docs.download(${idx})">📥 Download</button>
            </div>` : ''}
        </div>`;
    }).join('');
  },

  updateGeneratedDocsList(documents) {
    const listDiv = document.getElementById('generatedDocsList');
    if (!listDiv) return;
    if (!documents || documents.length === 0) {
      listDiv.innerHTML = `
        <div class="empty-state">
          <div class="icon">📄</div>
          <h3>No Documents Generated</h3>
          <p>Click "Generate All Documents" to create assessment files for this profile.</p>
        </div>`;
      return;
    }
    listDiv.innerHTML = `
      <div style="display: flex; flex-direction: column; gap: 0.75rem;">
        ${documents.map((doc, idx) => `
          <div style="display: flex; align-items: center; justify-content: space-between; gap: 1rem; padding: 0.85rem 1rem; background: var(--bg-card); border: 1px solid var(--border-color); border-radius: 8px;">
            <div style="display: flex; align-items: center; gap: 1rem; min-width: 0;">
              <div style="font-size: 1.75rem;">${DOC_ICONS[doc.type] || '📄'}</div>
              <div style="min-width: 0;">
                <div style="font-weight: 600; color: var(--text-primary);">${esc(DOC_NAMES[doc.type] || doc.type)}</div>
                <div style="font-size: 0.85rem; color: var(--text-muted); overflow-wrap: anywhere;">${esc(doc.filename)}</div>
                <div style="font-size: 0.75rem; color: var(--text-muted); margin-top: 0.2rem;">
                  ${formatFileSize(doc.size || 0)} · Generated ${esc(Utils.formatDateTime(doc.generated_at))}
                </div>
              </div>
            </div>
            <button class="btn btn-sm btn-primary" onclick="Docs.download(${idx})">📥 Download</button>
          </div>`).join('')}
      </div>`;
  },

  // Index-based so filenames/URLs never travel through an onclick string.
  download(idx) {
    const doc = (this._docs || [])[idx];
    if (!doc) return;
    const a = document.createElement('a');
    a.href = doc.url;
    a.download = doc.filename || '';
    a.click();
  },

  async generateDocuments() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) {
      Toast.warning('Select Profile', 'Please select a profile first');
      return;
    }
    const btn = document.getElementById('generateDocsBtn');
    const status = document.getElementById('generateStatus');
    Utils.setBtnLoading(btn, true, 'Generating…');
    if (status) status.textContent = 'This may take a minute...';
    try {
      await API.instructor.generateDocuments(profileId);
      Toast.success('Documents Generated', 'All security scan files have been created!');
      if (status) status.textContent = 'Generation complete!';
      // Re-fetch instead of rendering the POST payload: its per-doc objects
      // carry no generated_at, so the list would read "Generated -" until the
      // profile was re-selected.
      await this.loadProfileDocuments(profileId);
      // The hero Documents stat is a server count now — no client-side "+3".
      InstructorState.refresh();
    } catch (error) {
      console.error('Failed to generate documents:', error);
      Toast.error('Generation Failed', error.message);
      if (status) status.textContent = 'Generation failed. Please try again.';
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // The print views are real HTML with a print button — "Print > Save as PDF"
  // produces the PDF. Cookie auth carries the session for window.open.
  printScanReports() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) {
      Toast.warning('Select Profile', 'Please select a profile first');
      return;
    }
    window.open(`/api/profiles/${encodeURIComponent(profileId)}/documents/print`, '_blank');
  },

  printPolicies() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) {
      Toast.warning('Select Profile', 'Please select a profile first');
      return;
    }
    window.open(`/api/profiles/${encodeURIComponent(profileId)}/policies/print`, '_blank');
  },

  // ── Policy documents ──────────────────────────────────────────────────────

  async generatePolicies() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) {
      Toast.warning('Select Profile', 'Please select a profile first');
      return;
    }
    const btn = document.getElementById('generatePoliciesBtn');
    const status = document.getElementById('policiesStatus');
    const selectedModel = this.getSelectedModel();
    const modelLabel = AI_MODEL_INFO[selectedModel]?.label || selectedModel;

    Utils.setBtnLoading(btn, true, 'Generating Policies…');
    if (status) status.textContent = 'Generating policy documents via AI. This may take several minutes...';
    try {
      const data = await API.profiles.generatePolicies(profileId, { model: selectedModel });
      if (!(data.success || data.policies)) throw new Error(data.error || 'Failed to generate policies');
      const count = data.total_count || data.policies?.length || 0;
      Toast.success('Policies Generated', `${count} policy document(s) generated using ${modelLabel}`);
      if (status) status.textContent = `${count} policies generated (${modelLabel}).`;
      // Old loadDocsForProfile role: the new policies doc must show up in the
      // generated-documents list without a manual profile re-select.
      await this.loadProfileDocuments(profileId);
      InstructorState.refresh();
    } catch (err) {
      console.error('Policy generation error:', err);
      if (status) status.textContent = 'Policy generation failed. Please try again.';
      Toast.error('Error', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // ── Per-student generate modal (opened from the Students tab) ─────────────

  showGenerateDocsModal(profileId, label) {
    if (!profileId) {
      Toast.error('Error', 'No profile to generate documents for');
      return;
    }
    this._modalProfileId = profileId;
    const container = document.getElementById('generateDocsModalContent');
    const row = (icon, name, desc) => `
      <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: var(--bg-card-hover); border: 1px solid var(--border-color); border-radius: 8px;">
        <span style="font-size: 1.5rem;">${icon}</span>
        <div>
          <strong>${name}</strong>
          <p style="margin: 0; font-size: 0.85rem; color: var(--text-muted);">${desc}</p>
        </div>
      </div>`;
    container.innerHTML = `
      ${label ? `
        <div style="margin-bottom: 1rem; padding-bottom: 0.75rem; border-bottom: 1px solid var(--border-color);">
          <strong>${esc(label)}</strong>
        </div>` : ''}
      <label style="display: block; margin-bottom: 0.75rem; font-weight: 500;">Documents to Generate:</label>
      <div style="display: grid; gap: 0.75rem;">
        ${row('🔍', 'NESSUS Vulnerability Scan', 'XML format - Network vulnerability assessment')}
        ${row('🕷️', 'ZAP Security Report', 'HTML format - Web application security scan')}
        ${row('🔌', 'NMAP Network Scan', 'XML format - Port and service discovery')}
      </div>
      <div style="margin-top: 1.25rem; padding-top: 1rem; border-top: 1px dashed var(--border-color);">
        <div style="display: flex; align-items: center; gap: 0.75rem; padding: 0.75rem; background: var(--bg-card-hover); border: 1px solid var(--border-color); border-radius: 8px;">
          <span style="font-size: 1.5rem;">📋</span>
          <div style="flex: 1;">
            <strong>Security Policy Documents</strong>
            <p style="margin: 0; font-size: 0.85rem; color: var(--text-muted);">Auto-generated organizational policies based on profile</p>
          </div>
          <button type="button" class="btn btn-sm btn-primary" id="generateDocsModalPoliciesBtn" onclick="Docs.generateModalPolicies()">📋 Generate Policies</button>
        </div>
      </div>
      <div id="generateDocsModalStatus" class="text-muted" style="margin-top: 1rem; font-size: 0.9rem;"></div>
      <div style="display: flex; gap: 1rem; justify-content: flex-end; margin-top: 1.5rem;">
        <button type="button" class="btn btn-outline" onclick="closeModal('generateDocsModal')">Cancel</button>
        <button type="button" class="btn btn-primary" id="generateDocsModalGoBtn" onclick="Docs.generateModalDocuments()">⚡ Generate Scan Documents</button>
      </div>`;
    openModal('generateDocsModal');
  },

  async generateModalDocuments() {
    const profileId = this._modalProfileId;
    if (!profileId) return;
    const btn = document.getElementById('generateDocsModalGoBtn');
    const status = document.getElementById('generateDocsModalStatus');
    Utils.setBtnLoading(btn, true, 'Generating…');
    if (status) status.textContent = 'Generating documents... This may take a moment.';
    try {
      const data = await API.instructor.generateDocuments(profileId);
      const count = (data.documents || []).length;
      Toast.success('Documents Generated', `${count} scan document(s) created`);
      closeModal('generateDocsModal');
      if (document.getElementById('docProfileSelect').value === profileId) {
        await this.loadProfileDocuments(profileId);
      }
      InstructorState.refresh();
    } catch (error) {
      console.error('Failed to generate documents:', error);
      if (status) status.textContent = `Generation failed: ${error.message}`;
      Toast.error('Generation Failed', error.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  async generateModalPolicies() {
    const profileId = this._modalProfileId;
    if (!profileId) return;
    const btn = document.getElementById('generateDocsModalPoliciesBtn');
    const status = document.getElementById('generateDocsModalStatus');
    Utils.setBtnLoading(btn, true, 'Generating…');
    if (status) status.textContent = 'Generating policy documents via AI. This may take several minutes...';
    try {
      const data = await API.profiles.generatePolicies(profileId, { model: this.getSelectedModel() });
      if (!(data.success || data.policies)) throw new Error(data.error || 'Failed to generate policies');
      const count = data.total_count || data.policies?.length || 0;
      Toast.success('Policies Generated', `${count} policy document(s) generated`);
      if (status) status.textContent = `${count} policies generated.`;
      if (document.getElementById('docProfileSelect').value === profileId) {
        await this.loadProfileDocuments(profileId);
      }
      InstructorState.refresh();
    } catch (err) {
      console.error('Policy generation error:', err);
      if (status) status.textContent = 'Policy generation failed. Please try again.';
      Toast.error('Error', err.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  // ── Answer key generation (background job on the server) ──────────────────

  async checkGenerationStatus(profileId) {
    try {
      const data = await API.request(`/instructor/generation-status/${encodeURIComponent(profileId)}`);
      if (data.generating) {
        const btn = document.getElementById('generateExamplesBtn');
        const status = document.getElementById('examplesStatus');
        const modelLabel = AI_MODEL_INFO[data.model]?.label || data.model || 'AI';
        // Re-selecting the same profile mid-poll must not stack loading states
        // (a second setBtnLoading(true) would capture the spinner as restoreHtml).
        if (btn && !btn.classList.contains('btn-loading')) Utils.setBtnLoading(btn, true, 'Generating…');
        if (status) {
          status.innerHTML = `<span style="color: var(--primary);">Answer key generation in progress using <strong>${esc(modelLabel)}</strong> (started ${esc(data.startedAt ? new Date(data.startedAt).toLocaleTimeString() : 'earlier')}). Results will be saved automatically.</span>`;
        }
        this.pollForExamples(profileId);
      }
    } catch (e) {
      console.error('Error checking generation status:', e);
    }
  },

  async checkExistingExamples(profileId) {
    try {
      const data = await API.request(`/instructor/examples/${encodeURIComponent(profileId)}`);
      const hasExamples = data.examples && data.examples.length > 0;
      document.getElementById('viewExamplesBtn').style.display = hasExamples ? 'inline-flex' : 'none';
      if (hasExamples) this._cachedExamples = { parts: data.examples, profileId };
    } catch (e) {
      console.error('Error checking examples:', e);
    }
  },

  async generateExamples() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) {
      Toast.warning('Select Profile', 'Please select a profile first');
      return;
    }
    this._cachedExamples = null; // stale after regeneration

    const btn = document.getElementById('generateExamplesBtn');
    const status = document.getElementById('examplesStatus');
    const selectedModel = this.getSelectedModel();
    const modelLabel = esc(AI_MODEL_INFO[selectedModel]?.label || selectedModel);

    Utils.setBtnLoading(btn, true, 'Generating Answer Key…');
    if (status) status.innerHTML = `<span style="color: var(--primary);">Generating examples for all 8 parts using <strong>${modelLabel}</strong>. This runs in the background — you can leave this page and results will be saved automatically.</span>`;

    try {
      const data = await API.request('/instructor/generate-examples', {
        method: 'POST',
        body: { profile_id: profileId, model: selectedModel },
      });
      Toast.success('Generation Started', data.message || 'Answer key generation is running in the background.');
      if (status) status.innerHTML = `<span style="color: var(--success);">Answer key generation running in background using <strong>${modelLabel}</strong>. You can leave this page — results will be saved automatically.</span>`;
      // Button stays in its loading state until the poll resolves.
      this.pollForExamples(profileId);
    } catch (error) {
      console.error('Failed to start example generation:', error);
      Toast.error('Generation Failed', error.message);
      if (status) status.textContent = 'Answer key generation failed. Please try again.';
      Utils.setBtnLoading(btn, false);
    }
  },

  // Poll every 30s for stored examples. The server's generation-status is an
  // in-memory Map lost on restart, so the DB is the source of truth here and
  // the 20-minute cap copes with a job that silently died with the process.
  pollForExamples(profileId) {
    if (this._pollTimer) clearInterval(this._pollTimer);

    let polls = 0;
    const maxPolls = 40; // 40 × 30s ≈ 20 minutes
    const status = document.getElementById('examplesStatus');

    this._pollTimer = setInterval(async () => {
      polls++;
      if (polls > maxPolls) {
        clearInterval(this._pollTimer);
        this._pollTimer = null;
        Utils.setBtnLoading(document.getElementById('generateExamplesBtn'), false);
        if (status) status.innerHTML = '<span style="color: var(--warning);">Generation may still be running. Refresh the page to check.</span>';
        return;
      }
      if (status) {
        status.innerHTML = `
          <span style="color: var(--primary);">Answer key generation in progress… results save automatically, even if you leave this page.</span>
          <div class="progress-bar" style="margin-top: 0.4rem; max-width: 320px;">
            <div class="progress-fill" style="width: ${Math.round((polls / maxPolls) * 100)}%;"></div>
          </div>`;
      }
      try {
        const data = await API.request(`/instructor/examples/${encodeURIComponent(profileId)}`);
        if (data.examples && data.examples.length > 0) {
          clearInterval(this._pollTimer);
          this._pollTimer = null;
          this._cachedExamples = { parts: data.examples, profileId };
          Utils.setBtnLoading(document.getElementById('generateExamplesBtn'), false);
          if (status) status.innerHTML = `<span style="color: var(--success);">Answer key ready! ${data.examples.length} parts generated and saved.</span>`;
          document.getElementById('viewExamplesBtn').style.display = 'inline-flex';
          Toast.success('Answer Key Ready', `${data.examples.length} parts generated and saved.`);
          InstructorState.refresh();
        }
      } catch (_) { /* transient poll failure — try again next tick */ }
    }, 30000);
  },

  // ── Answer key viewer ─────────────────────────────────────────────────────

  async viewExamples() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) return;

    // Always fetch fresh — regeneration may have updated the DB.
    try {
      const data = await API.request(`/instructor/examples/${encodeURIComponent(profileId)}`);
      this._cachedExamples = { parts: data.examples || [], profileId };
    } catch (e) {
      Toast.error('Error', e.message);
      return;
    }

    if (this._cachedExamples.parts.length === 0) {
      Toast.warning('No Examples', 'No answer key has been generated for this profile yet.');
      return;
    }

    this._answerKeyProfileId = profileId;
    const select = document.getElementById('docProfileSelect');
    const profileName = select.options[select.selectedIndex]?.text || 'Profile';
    document.getElementById('answerKeyProfileName').textContent = profileName;
    document.getElementById('downloadPacketBtn').style.display = '';
    document.getElementById('regenerateAnswerKeyBtn').style.display = '';

    this.buildAnswerKeySidebar();
    openModal('answerKeyModal');
  },

  buildAnswerKeySidebar() {
    if (!this._cachedExamples) return;
    const sidebar = document.getElementById('answerKeySidebar');
    sidebar.innerHTML = this._cachedExamples.parts.map((ex, i) => `
      <div class="ak-part-item ${i === 0 ? 'active' : ''}" onclick="Docs.selectAnswerKeyPart(${i}, this)">
        <div class="part-num">Part ${esc(ex.part_number)}</div>
        <div>${esc(ex.part_name)}</div>
      </div>`).join('');
    this.renderAnswerKeyPart(0);
  },

  selectAnswerKeyPart(index, el) {
    document.querySelectorAll('.ak-part-item').forEach((item) => item.classList.remove('active'));
    if (el) el.classList.add('active');
    this.renderAnswerKeyPart(index);
  },

  renderAnswerKeyPart(index) {
    const content = document.getElementById('answerKeyContent');
    const example = this._cachedExamples?.parts[index];
    if (!example) {
      content.innerHTML = '<p>No content available.</p>';
      return;
    }

    let parsed;
    try {
      parsed = typeof example.content === 'string' ? JSON.parse(example.content) : example.content;
    } catch {
      content.innerHTML = '<p>Error parsing content.</p>';
      return;
    }

    const deliverables = parsed.deliverables || {};
    if (Object.keys(deliverables).length === 0) {
      content.innerHTML = '<p>No deliverables found for this part.</p>';
      return;
    }

    let html = `<h3 style="margin-bottom: 1rem;">Part ${esc(example.part_number)}: ${esc(example.part_name)}</h3>`;
    if (parsed.general_notes) {
      html += `<p style="color: var(--text-muted); margin-bottom: 1.5rem; font-style: italic;">${esc(parsed.general_notes)}</p>`;
    }

    for (const [optKey, deliverablesArr] of Object.entries(deliverables)) {
      const optName = optKey.replace(/^p\d+_/, '').replace(/_/g, ' ').replace(/\b\w/g, (l) => l.toUpperCase());
      html += '<div class="ak-option-block">';
      html += `<h4>${esc(optName)}</h4>`;

      const items = deliverablesArr?.items;
      if (Array.isArray(items) && items.length > 0) {
        // New format: { title, items: [{ label, content }, ...] }
        items.forEach((item) => {
          html += `
            <div class="ak-deliverable">
              <div class="ak-deliverable-label">${esc(item.label || '')}</div>
              <div class="ak-deliverable-content">${renderMarkdown(item.content || '')}</div>
            </div>`;
        });
      } else if (Array.isArray(deliverablesArr)) {
        // Legacy: flat array
        deliverablesArr.forEach((del, i) => {
          const delContent = typeof del === 'object' ? (del.content || del.title || '') : del;
          html += `
            <div class="ak-deliverable">
              <div class="ak-deliverable-label">Deliverable ${i + 1}</div>
              <div class="ak-deliverable-content">${renderMarkdown(delContent)}</div>
            </div>`;
        });
      } else if (typeof deliverablesArr === 'string') {
        html += `<div class="ak-deliverable"><div class="ak-deliverable-content">${renderMarkdown(deliverablesArr)}</div></div>`;
      } else if (deliverablesArr && typeof deliverablesArr === 'object') {
        const delContent = deliverablesArr.content || deliverablesArr.title || '';
        if (delContent) {
          html += `<div class="ak-deliverable"><div class="ak-deliverable-content">${renderMarkdown(delContent)}</div></div>`;
        }
      }

      html += '</div>';
    }

    content.innerHTML = html;
  },

  // ── Answer key from the Students tab ──────────────────────────────────────

  // Picker for a student with several profiles. Rows call back by index so
  // company names never travel through an onclick string.
  showAnswerKeyModal(profiles, title) {
    profiles = profiles || [];
    if (!profiles.length) {
      Toast.warning('No Profiles', 'This student has no profiles yet.');
      return;
    }
    if (profiles.length === 1) {
      const p = profiles[0];
      this.openAnswerKeyForProfile(p.profile_id || p.id, `${title ? `${title} — ` : ''}${p.company_name || 'Profile'}`);
      return;
    }

    this._pickerProfiles = profiles.map((p) => ({
      id: p.profile_id || p.id,
      name: p.company_name || 'Unnamed',
      title: title || '',
    }));
    document.getElementById('answerKeyProfileName').textContent = title || 'Select a Profile';
    document.getElementById('downloadPacketBtn').style.display = 'none';
    document.getElementById('regenerateAnswerKeyBtn').style.display = 'none';
    document.getElementById('answerKeySidebar').innerHTML = this._pickerProfiles.map((p, i) => `
      <div class="ak-part-item" onclick="Docs.pickAnswerKeyProfile(${i})">
        <div class="part-num">🏢</div>
        <div>${esc(p.name)}</div>
      </div>`).join('');
    document.getElementById('answerKeyContent').innerHTML = `
      <div class="empty-state">
        <div class="icon">📝</div>
        <h3>Select a Profile</h3>
        <p>Choose a profile from the sidebar to view or generate its answer key.</p>
      </div>`;
    openModal('answerKeyModal');
  },

  pickAnswerKeyProfile(i) {
    const p = (this._pickerProfiles || [])[i];
    if (!p) return;
    this.openAnswerKeyForProfile(p.id, p.title ? `${p.title} — ${p.name}` : p.name);
  },

  async openAnswerKeyForProfile(profileId, displayName) {
    this._answerKeyProfileId = profileId;
    document.getElementById('answerKeyProfileName').textContent = displayName || 'Profile';

    try {
      const data = await API.request(`/instructor/examples/${encodeURIComponent(profileId)}`);
      if (data.examples && data.examples.length > 0) {
        this._cachedExamples = { parts: data.examples, profileId };
        this.buildAnswerKeySidebar();
        document.getElementById('downloadPacketBtn').style.display = '';
        document.getElementById('regenerateAnswerKeyBtn').style.display = '';
      } else {
        // No examples yet — offer to generate.
        document.getElementById('answerKeySidebar').innerHTML = '';
        document.getElementById('answerKeyContent').innerHTML = `
          <div style="text-align: center; padding: 3rem 1rem;">
            <div style="font-size: 3rem; margin-bottom: 1rem;">📝</div>
            <h3>No Answer Key Yet</h3>
            <p style="color: var(--text-muted); margin-bottom: 1.5rem;">Generate an answer key for this profile. This creates example content for all 8 parts plus a completed intake form.</p>
            <button class="btn btn-primary" id="generateFromModalBtn" onclick="Docs.generateAnswerKeyFromModal()">
              📝 Generate Answer Key
            </button>
            <div id="generateFromModalStatus" style="margin-top: 1rem; color: var(--text-muted);"></div>
          </div>`;
        document.getElementById('downloadPacketBtn').style.display = 'none';
        document.getElementById('regenerateAnswerKeyBtn').style.display = 'none';
      }
      openModal('answerKeyModal');
    } catch (e) {
      Toast.error('Error', e.message);
    }
  },

  async generateAnswerKeyFromModal() {
    const profileId = this._answerKeyProfileId;
    if (!profileId) return;
    const btn = document.getElementById('generateFromModalBtn');
    const status = document.getElementById('generateFromModalStatus');
    const selectedModel = this.getSelectedModel();
    const modelLabel = AI_MODEL_INFO[selectedModel]?.label || selectedModel;

    Utils.setBtnLoading(btn, true, 'Generating…');
    if (status) status.textContent = `Starting answer key generation with ${modelLabel}...`;

    try {
      await API.request('/instructor/generate-examples', {
        method: 'POST',
        body: { profile_id: profileId, model: selectedModel },
      });
      // The endpoint responds immediately and generates in the background.
      Toast.success('Generation Started', `Answer key generation running in background using ${modelLabel}. Results will be saved automatically.`);
      if (status) status.textContent = 'Generation running in the background — reopen this answer key in a few minutes.';
      this.pollForExamples(profileId);
    } catch (error) {
      Toast.error('Generation Failed', error.message);
      if (status) status.textContent = 'Generation failed. Please try again.';
      Utils.setBtnLoading(btn, false);
    }
  },

  async regenerateAnswerKey() {
    const profileId = this._answerKeyProfileId;
    if (!profileId) return;

    if (!await Confirm.show({
      title: 'Regenerate this answer key?',
      message: 'The existing answer key for this profile will be replaced by a freshly generated one. Generation runs in the background and takes several minutes.',
      confirmText: 'Regenerate',
      danger: true,
    })) return;

    const btn = document.getElementById('regenerateAnswerKeyBtn');
    Utils.setBtnLoading(btn, true, 'Regenerating…');
    try {
      const selectedModel = this.getSelectedModel();
      const modelLabel = AI_MODEL_INFO[selectedModel]?.label || selectedModel;
      await API.request('/instructor/generate-examples', {
        method: 'POST',
        body: { profile_id: profileId, model: selectedModel },
      });
      Toast.success('Regeneration Started', `Answer key regeneration running in background using ${modelLabel}. Results will be saved automatically.`);
      closeModal('answerKeyModal');
      this.pollForExamples(profileId);
    } catch (error) {
      Toast.error('Regeneration Failed', error.message);
    } finally {
      Utils.setBtnLoading(btn, false);
    }
  },

  downloadPacketPdf() {
    const profileId = this._answerKeyProfileId || document.getElementById('docProfileSelect')?.value;
    if (!profileId) {
      Toast.warning('No Profile', 'No profile selected');
      return;
    }
    // Cookie auth carries the session; the route answers with a
    // Content-Disposition attachment, so this triggers a named download.
    window.open(`/api/instructor/packet/${encodeURIComponent(profileId)}/pdf`, '_blank');
  },

  // ── Vuln-app answer key (drawn-role gated card) ───────────────────────────

  async viewVulnCheatSheet() {
    const profileId = document.getElementById('docProfileSelect').value;
    if (!profileId) return;
    const status = document.getElementById('vulnCheatSheetStatus');
    const body = document.getElementById('vulnCheatSheetBody');
    const title = document.getElementById('vulnCheatSheetTitle');
    title.textContent = 'Loading…';
    body.innerHTML = '<div class="empty-state"><div class="icon">⏳</div><h3>Loading vuln-app answer key…</h3></div>';
    openModal('vulnCheatSheetModal');
    try {
      const data = await API.request(`/instructor/vuln-cheat-sheet/${encodeURIComponent(profileId)}`);
      this.renderVulnCheatSheet(data);
      if (status) status.textContent = `Loaded answer key for ${data.title || 'vuln-app'}.`;
    } catch (err) {
      console.error('Vuln cheat sheet error:', err);
      body.innerHTML = `<div class="empty-state"><div class="icon">⚠️</div><h3>Could not load answer key</h3><p>${esc(err.message)}</p></div>`;
      if (status) status.textContent = `Error: ${err.message}`;
    }
  },

  // Everything below comes from the LLM that generated the app — it could
  // contain markup, so every field goes through esc().
  renderVulnCheatSheet(data) {
    const title = document.getElementById('vulnCheatSheetTitle');
    const body = document.getElementById('vulnCheatSheetBody');
    title.textContent = data.title || '(untitled app)';

    const parts = [];

    const diffBadge = data.difficulty
      ? `<span style="display:inline-block; padding:0.15rem 0.5rem; border-radius:1rem; font-size:0.75rem; font-weight:600; vertical-align:middle; ${
        data.difficulty === 'easy' ? 'background:rgba(16, 185, 129, 0.15); color:var(--success);'
          : data.difficulty === 'medium' ? 'background:rgba(245, 158, 11, 0.15); color:var(--warning);'
            : data.difficulty === 'hard' ? 'background:rgba(239, 68, 68, 0.15); color:var(--danger);'
              : 'background:var(--gray-200); color:var(--gray-600);'
      }">${esc(data.difficulty.toUpperCase())}</span>`
      : '';
    parts.push(`
      <div class="vcs-meta">
        <div><strong>Difficulty:</strong> ${diffBadge || '—'}</div>
        <div><strong>Tech stack:</strong> ${esc(data.tech_stack || '—')}</div>
        <div><strong>Theme:</strong> ${esc(data.theme_summary || '—')}</div>
        <div><strong>Generated:</strong> ${data.generated_at ? esc(Utils.formatDateTime(data.generated_at)) : '—'} (${esc(data.delivery_mode || 'unknown')} delivery, ${esc(data.page_count || '?')} files)</div>
      </div>`);

    if (data.post_install_notes) {
      parts.push(`
        <div class="vcs-callout">
          <strong>Access:</strong> ${esc(data.post_install_notes)}
        </div>`);
    }

    if (data.attack_chain && data.attack_chain.length) {
      parts.push('<div class="vcs-section"><h4>🗡️ Attack Chain</h4>');
      for (const s of data.attack_chain) {
        parts.push(`
          <div class="vcs-stage">
            <div class="vcs-stage-head">
              <span class="vcs-stage-num">${esc(String(s.stage || '?'))}</span>
              <span class="vcs-vuln-type">${esc(s.vuln_type || 'Unspecified vulnerability')}</span>
            </div>
            ${s.discovery_hint ? `<div class="vcs-field"><span class="vcs-field-label">Discovery</span> ${esc(s.discovery_hint)}</div>` : ''}
            ${s.exploit_summary ? `<div class="vcs-field"><span class="vcs-field-label">Exploit</span> ${esc(s.exploit_summary)}</div>` : ''}
            ${s.yields ? `<div class="vcs-field"><span class="vcs-field-label">Yields</span> ${esc(s.yields)}</div>` : ''}
            ${s.flag ? `<div class="vcs-field"><span class="vcs-field-label">Flag</span> <span class="vcs-flag">${esc(s.flag)}</span></div>` : ''}
          </div>`);
      }
      parts.push('</div>');
    }

    const users = data.seed_data && Array.isArray(data.seed_data.users) ? data.seed_data.users : [];
    if (users.length) {
      parts.push('<div class="vcs-section"><h4>🔑 Seed Credentials</h4>');
      parts.push('<table class="vcs-creds-table"><thead><tr><th>Username</th><th>Password</th><th>Role</th><th>Notes</th></tr></thead><tbody>');
      for (const u of users) {
        parts.push(`<tr>
          <td><code>${esc(u.username || '')}</code></td>
          <td><code>${esc(u.password || '')}</code></td>
          <td>${esc(u.role || '')}</td>
          <td>${esc(u.notes || '')}</td>
        </tr>`);
      }
      parts.push('</tbody></table></div>');
    }

    const fileEntries = Object.entries(data.file_annotations || {}).filter(([, v]) => v && (v.vuln_notes || v.vuln_role !== 'none'));
    if (fileEntries.length) {
      parts.push('<div class="vcs-section"><h4>📂 Per-File Notes</h4>');
      parts.push('<table class="vcs-files-table"><thead><tr><th>Path</th><th>Role</th><th>Vulnerability notes</th></tr></thead><tbody>');
      // Primary first, then pivot, noise, none — the meaty stuff on top.
      const rolePriority = { primary: 0, pivot: 1, noise: 2, none: 3 };
      fileEntries.sort(([, a], [, b]) => (rolePriority[a.vuln_role] ?? 9) - (rolePriority[b.vuln_role] ?? 9));
      for (const [path, ann] of fileEntries) {
        const role = ann.vuln_role || 'none';
        parts.push(`<tr>
          <td><code>${esc(path)}</code></td>
          <td><span class="vcs-role-badge vcs-role-${esc(role)}">${esc(role)}</span></td>
          <td>${esc(ann.vuln_notes || '—')}</td>
        </tr>`);
      }
      parts.push('</tbody></table></div>');
    }

    if (data.instructor_notes) {
      parts.push(`
        <div class="vcs-section">
          <h4>👨‍🏫 Instructor Notes</h4>
          <div style="background: var(--gray-50); padding: 1rem; border-radius: 6px; line-height: 1.6;">${esc(data.instructor_notes)}</div>
        </div>`);
    }

    if (data.page_errors && data.page_errors.length) {
      parts.push(`
        <div class="vcs-section">
          <h4>⚠️ Files That Failed to Generate</h4>
          <ul style="margin: 0; padding-left: 1.5rem; line-height: 1.6;">
            ${data.page_errors.map((e) => `<li><code>${esc(e.path || '?')}</code> — ${esc(e.error || '')}</li>`).join('')}
          </ul>
        </div>`);
    }

    body.innerHTML = parts.join('') || '<div class="empty-state"><div class="icon">📭</div><h3>No answer-key data available</h3><p>The vuln-app was generated, but contains no attack chain or annotations.</p></div>';
  },

  // instructor.css @media print isolates #vulnCheatSheetModal on the page.
  printVulnCheatSheet() {
    window.print();
  },
};

// ── Answer-key markdown renderer ────────────────────────────────────────────
// Ported verbatim from the old page. Table cells and inline text are escaped
// before the (deliberately tiny) formatting pass — same trust exposure as
// before: content is LLM-generated, never student-supplied.

function renderMarkdown(text) {
  if (!text) return '';
  const lines = text.split('\n');
  const out = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Detect markdown table: line starts and ends with |
    if (/^\|.+\|$/.test(line.trim())) {
      const tableLines = [];
      while (i < lines.length && /^\|/.test(lines[i].trim())) {
        tableLines.push(lines[i]);
        i++;
      }
      // First row = headers, second row = separator, rest = body
      const rows = tableLines.filter((l) => !/^\|[\s\-:|]+\|$/.test(l.trim()));
      const parseCells = (l) => l.trim().replace(/^\||\|$/g, '').split('|').map((c) => c.trim());
      if (rows.length > 0) {
        let tbl = '<table class="ak-md-table"><thead><tr>';
        parseCells(rows[0]).forEach((h) => { tbl += `<th>${esc(h)}</th>`; });
        tbl += '</tr></thead><tbody>';
        rows.slice(1).forEach((r) => {
          tbl += '<tr>';
          parseCells(r).forEach((c) => { tbl += `<td>${esc(c)}</td>`; });
          tbl += '</tr>';
        });
        tbl += '</tbody></table>';
        out.push(tbl);
      }
    } else {
      // Inline formatting: **bold**, *italic*, bullet lists
      let l = esc(line)
        .replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')
        .replace(/\*(.+?)\*/g, '<em>$1</em>');
      if (/^(\*|-|\d+\.) /.test(line.trim())) {
        out.push(`<li>${l.replace(/^(\*|-|\d+\.) /, '')}</li>`);
      } else if (l.trim() === '') {
        out.push('<br>');
      } else {
        out.push(`<p style="margin:0 0 0.5rem 0">${l}</p>`);
      }
      i++;
    }
  }
  // Wrap consecutive <li> in <ul>
  return out.join('\n').replace(/(<li>.*?<\/li>\n?)+/gs, (match) => `<ul style="margin:0.25rem 0 0.5rem 1.25rem;padding:0">${match}</ul>`);
}

window.Docs = Docs;
