// ============================================================================
// TOPOLOGY TAB — designer + viewer
// ============================================================================
// Two surfaces over one renderer:
//
//   DESIGNER  authors a NEW challenge on a canvas and creates it for real via
//             POST /create-lab (DB row + VXLAN reservation + SDN zone + VNets).
//             Seeds from a blank canvas, a clone of an existing challenge, a
//             GOAD lab preset, or an exported .cctopo.json.
//   VIEWER    draws either a running lane (live, read from Proxmox) or a saved
//             challenge's spec, so intended-vs-actual is one dropdown apart.
//
// ── What this file deliberately does NOT do ─────────────────────────────────
// It does not touch topology-render.js, topology-editor.js or admin-challenges.js.
// The canvas inside the Challenge Template editor modal keeps working exactly as
// it did; this tab is additive and consumes only the public APIs:
// CyberCoreTopology.create, CyberCoreTopologyEditor.{mount,segmentsForScheme,
// deriveSegments,stripInternal}, and CyberCoreTopologySeed.
//
// ── Naming ─────────────────────────────────────────────────────────────────
// Classic scripts share ONE global lexical scope, so a top-level `let` that
// collides with one in admin-challenges.js is a SyntaxError that kills this whole
// file at parse time and silently takes the tab with it. Every binding here is
// prefixed `topo`, and shared helpers (escHtml, difficultyLabel, loadGoadCatalog,
// findGoadLab, Toast) are REUSED rather than redefined — redefining a function
// would hoist and override the copy every other tab depends on.
// ============================================================================

const TopoSeed = () => window.CyberCoreTopologySeed;

/**
 * Escape for an HTML *attribute*.
 *
 * The shared escHtml() round-trips through textContent, which escapes & < > but
 * NOT quotes — fine for text nodes, wrong for `value="…"`. Machine names are
 * free text and validateTopology does not restrict the characters, so a name with
 * a double quote would otherwise break out of the attribute.
 */
function topoAttr(v) {
  return String(v == null ? '' : v).replace(/[&<>"']/g, c =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
}

let topoInited = false;      // the canvas is built on first tab activation, not at load
let topoMode = 'design';     // 'design' | 'view'
let topoVmView = 'canvas';   // 'canvas' | 'table' — two views over topoVms

// The graph. topoVms is the single source of truth for machines; the editor
// mutates these same row objects in place (adding `nics` and `layout`), which is
// what keeps the table view and the canvas in sync.
let topoVms = [];
let topoNetwork = null;      // spec.network — segments + canvas positions
let topoPhantoms = [];

let topoDesigner = null;     // CyberCoreTopologyEditor controller
let topoViewer = null;       // raw CyberCoreTopology instance (view mode)

let topoChallenges = [];     // GET /lab-templates, for the clone + spec pickers
let topoLanes = [];          // GET /lanes, for the live-lane picker
let topoViewKind = 'lane';   // 'lane' | 'spec'
let topoViewLoaded = false;
let topoViewPendingId = null;  // a selection to restore once the options exist
// Renders are async and the user can change the dropdown faster than a Proxmox
// read returns. Only the newest render is allowed to commit; without this an
// earlier fetch can resolve last and leave a diagram that does not match the
// selection — and leak the newer Cytoscape instance it overwrote.
let topoViewSeq = 0;

// ============================================================================
// ACTIVATION
// ============================================================================

/**
 * Called by the tab button AFTER switchTab has made the panel visible.
 *
 * The lazy build is mandatory, not stylistic: .tab-content is display:none, and
 * Cytoscape measures its container at init — a canvas built while the panel was
 * hidden is a 0x0 graph. Idempotent, because the button fires on every click.
 */
function topoTabActivate() {
  if (!topoInited) {
    topoInited = true;
    onTopoSchemeChange();
    renderTopoVmTable(true);
    renderTopoPhantoms();
    topoDesignMount();
    loadTopoSeedSources();
    return;
  }
  // Re-entering the tab: the graph exists but was measured before, possibly at a
  // different viewport width.
  if (topoMode === 'design') { if (topoDesigner) topoDesigner.resize(); }
  else if (topoViewer) topoViewer.resize();
}

function setTopoMode(mode) {
  topoMode = mode === 'view' ? 'view' : 'design';
  const design = topoMode === 'design';
  document.getElementById('topoDesignPane').style.display = design ? '' : 'none';
  document.getElementById('topoViewPane').style.display = design ? 'none' : '';
  document.getElementById('topoModeDesignBtn').classList.toggle('btn-primary', design);
  document.getElementById('topoModeDesignBtn').classList.toggle('btn-outline', !design);
  document.getElementById('topoModeViewBtn').classList.toggle('btn-primary', !design);
  document.getElementById('topoModeViewBtn').classList.toggle('btn-outline', design);

  if (design) {
    // Leaving the viewer tears its instance down. Each create() registers a
    // MutationObserver on <html> for theme flips, and only destroy() disconnects
    // it — keeping them alive would repaint orphaned canvases on every toggle.
    topoViewerDestroy();
    if (topoDesigner) topoDesigner.resize();
  } else if (!topoViewLoaded) {
    loadTopoViewChoices();
  } else {
    renderTopoView();
  }
}

// ============================================================================
// DESIGNER — canvas
// ============================================================================

function topoScheme() {
  return document.getElementById('topoSubnetScheme').value || 'v1';
}

/** GOAD lab host names, whose placement is fixed by the lab definition. */
function topoGoadHostNames() {
  if (!document.getElementById('topoGoadEnabled')?.checked) return null;
  const lab = findGoadLab(document.getElementById('topoGoadVersion')?.value);
  return lab ? lab.vms.map(v => v.name) : null;
}

/**
 * Mount (or remount) the designer canvas.
 *
 * Always tears the previous instance down first. Remount — not refresh() — is
 * required whenever topoVms is REPLACED rather than mutated, because the editor
 * closes over the array it was handed.
 */
function topoDesignMount() {
  if (topoDesigner) { try { topoDesigner.destroy(); } catch (e) { /* already gone */ } topoDesigner = null; }
  const canvas = document.getElementById('topoDesignCanvas');
  if (!canvas || typeof CyberCoreTopologyEditor === 'undefined') return;

  topoDesigner = CyberCoreTopologyEditor.mount({
    canvasEl: canvas,
    paletteEl: document.getElementById('topoDesignPalette'),
    panelEl: document.getElementById('topoDesignPanel'),
    findingsEl: document.getElementById('topoDesignFindings'),
    vms: topoVms,
    subnetScheme: topoScheme(),
    network: topoNetwork,
    goadHosts: topoGoadHostNames(),
    onChange: () => { renderTopoVmTable(true); }
  });
  setTopoVmView(topoVmView);
}

function setTopoVmView(view) {
  topoVmView = view === 'table' ? 'table' : 'canvas';
  const canvasOn = topoVmView === 'canvas';
  document.getElementById('topoDesignCanvasView').style.display = canvasOn ? '' : 'none';
  document.getElementById('topoDesignTableView').style.display = canvasOn ? 'none' : '';
  document.getElementById('topoViewCanvasBtn')?.classList.toggle('btn-primary', canvasOn);
  document.getElementById('topoViewTableBtn')?.classList.toggle('btn-primary', !canvasOn);
  // The canvas may have been hidden when it mounted.
  if (canvasOn && topoDesigner) topoDesigner.resize();
}

function topoDesignRelayout() { if (topoDesigner) topoDesigner.relayout(); }

function onTopoSchemeChange() {
  const scheme = topoScheme();
  const desc = document.getElementById('topoSchemeDesc');
  if (desc) {
    desc.textContent = ({
      v1: 'All lane VMs share one flat subnet. Legacy scheme — kept for in-flight classes.',
      v2: 'Each lane gets its own /24. Required for Tailscale BYOD access.',
      v3: 'Two subnets per lane — external (Kali/BYOD) and internal (corp/AD) — with the gateway ' +
          'firewall-blocking traffic between them. Give one machine the role "dmz": it becomes the ' +
          'dual-homed pivot the attacker must exploit to reach the internal network.'
    })[scheme] || '';
  }
  // setScheme drops attachments to segments the new scheme does not have, so a
  // v3→v2 switch cannot leave a machine wired to a vanished network.
  if (topoDesigner) topoDesigner.setScheme(scheme);
}

// ============================================================================
// DESIGNER — seeding
// ============================================================================

/** Populate the pickers the seed bar needs. Best-effort: a failure must not brick the tab. */
async function loadTopoSeedSources() {
  try {
    // No ?module= — GET /lab-templates/:id is hardcoded to crucible_challenge, so
    // offering another module's rows here would 404 on the follow-up fetch.
    topoChallenges = await api('GET', '/lab-templates');
  } catch (e) {
    topoChallenges = [];
    console.warn('[Topology] Could not load the challenge list:', e.message);
  }
  try { await loadGoadCatalog(); } catch (e) { /* helper already falls back */ }
  onTopoSeedSourceChange();
}

function onTopoSeedSourceChange() {
  const source = document.getElementById('topoSeedSource').value;
  const choice = document.getElementById('topoSeedChoice');
  const hint = document.getElementById('topoSeedHint');
  const loadBtn = document.getElementById('topoSeedLoadBtn');

  if (source === 'challenge') {
    choice.style.display = '';
    choice.innerHTML = topoChallenges.length
      ? topoChallenges.map(t =>
          `<option value="${topoAttr(t.id)}">${escHtml(t.name)} — ${escHtml(t.challenge_key)}</option>`).join('')
      : '<option value="">No challenges found</option>';
    hint.textContent = 'Copies its machines, layout and GOAD settings. You give the copy its own key.';
    loadBtn.textContent = 'Load';
  } else if (source === 'goad') {
    choice.style.display = '';
    const labs = (_goadCatalog && _goadCatalog.labs) || [];
    choice.innerHTML = labs.length
      ? labs.map(l => `<option value="${topoAttr(l.key)}">${escHtml(l.displayName || l.key)}</option>`).join('')
      : '<option value="">GOAD catalog unavailable</option>';
    hint.textContent = 'Stamps the lab\'s fixed host list. Kali and pre-baked mode follow the GOAD card below.';
    loadBtn.textContent = 'Load';
  } else if (source === 'file') {
    choice.style.display = 'none';
    hint.textContent = 'A .cctopo.json exported from either canvas. Its subnet scheme is adopted.';
    loadBtn.textContent = 'Choose file…';
  } else {
    choice.style.display = 'none';
    hint.textContent = 'An empty canvas with just the segments for the chosen scheme.';
    loadBtn.textContent = 'Load';
  }
}

async function applyTopoSeed() {
  const source = document.getElementById('topoSeedSource').value;
  const Seed = TopoSeed();

  if (source === 'file') {
    document.getElementById('topoSeedFile').click();
    return;
  }

  if (source === 'blank') {
    if (topoVms.length && !confirm('Clear the canvas and start from blank?')) return;
    await applyTopoSeedResult(Seed.blank(topoScheme()));
    return;
  }

  if (source === 'challenge') {
    const id = document.getElementById('topoSeedChoice').value;
    if (!id) { Toast.warning('Nothing selected', 'Pick a challenge to clone'); return; }
    try {
      // The DETAIL endpoint, not the cached list row: only SELECT * carries
      // subnet_scheme, which decides whether the canvas draws one segment or two.
      const row = await api('GET', `/lab-templates/${id}`);
      await applyTopoSeedResult(Seed.fromChallenge(row));
    } catch (e) { Toast.error('Clone failed', e.message); }
    return;
  }

  if (source === 'goad') {
    const key = document.getElementById('topoSeedChoice').value;
    const lab = findGoadLab(key);
    const prebaked = document.getElementById('topoGoadPrebaked').checked;
    await applyTopoSeedResult(Seed.fromGoadLab(lab, {
      includeKali: document.getElementById('topoGoadKali').checked,
      // The pre-baked pivot and the golden-image workflow go together: baked AD
      // carries full per-segment IPs, so it only makes sense on a segmented lane.
      addPivot: prebaked,
      blankVmids: prebaked,
      subnetScheme: topoScheme()
    }));
  }
}

async function onTopoSeedFilePicked(input) {
  const file = input.files && input.files[0];
  input.value = '';                        // so re-picking the same file re-fires
  if (!file) return;
  try {
    const payload = JSON.parse(await file.text());
    await applyTopoSeedResult(TopoSeed().fromTopologyFile(payload));
  } catch (e) { Toast.error('Import failed', e.message); }
}

/**
 * Apply a seed to the designer. The single path every source funnels through, so
 * there is exactly one place that can get "replace the graph" wrong.
 */
async function applyTopoSeedResult(seed) {
  if (!seed || !seed.ok) {
    Toast.error('Cannot load that', (seed && seed.reason) || 'Unknown problem');
    return;
  }

  topoVms = seed.vms || [];
  topoNetwork = seed.network || null;
  topoPhantoms = seed.phantoms || [];

  document.getElementById('topoName').value = seed.name || '';
  document.getElementById('topoDesc').value = seed.description || '';
  document.getElementById('topoKey').value = seed.challenge_key || '';
  document.getElementById('topoZone').value = seed.zone_abbrev || '';
  document.getElementById('topoMaxLanes').value = seed.max_lanes || 10;
  // difficulty arrives as the DB's INTEGER on a clone and as a label otherwise;
  // difficultyLabel handles both.
  document.getElementById('topoDifficulty').value = difficultyLabel(seed.difficulty);
  document.getElementById('topoModule').value = seed.module || 'crucible';
  document.getElementById('topoSubnetScheme').value = seed.subnet_scheme || 'v1';

  await applyTopoGoadFields(seed.goad);
  clearTopoFieldErrors();
  document.getElementById('topoCreateStatus').innerHTML = '';

  onTopoSchemeChange();     // helper text only; the remount below applies the scheme
  topoDesignMount();        // topoVms was REPLACED, so remount rather than refresh
  renderTopoVmTable(true);
  renderTopoPhantoms();
  onTopoKeyInput();

  const extra = (seed.notes || []).join(' ');
  Toast.success('Loaded', `${topoVms.length} machine${topoVms.length === 1 ? '' : 's'} on the canvas. ${extra}`.trim());
}

// ============================================================================
// DESIGNER — GOAD card
// ============================================================================

async function populateTopoGoadVersions() {
  const catalog = await loadGoadCatalog();
  const select = document.getElementById('topoGoadVersion');
  const previous = select.value || catalog.default_lab;
  select.innerHTML = (catalog.labs || []).map(l =>
    `<option value="${topoAttr(l.key)}">${escHtml(l.displayName || l.key)}</option>`
  ).join('') || '<option value="GOAD-Light">GOAD-Light</option>';
  select.value = (catalog.labs || []).some(l => l.key === previous)
    ? previous : (catalog.default_lab || 'GOAD-Light');
  updateTopoGoadDesc();
}

function updateTopoGoadDesc() {
  const lab = findGoadLab(document.getElementById('topoGoadVersion').value);
  const desc = document.getElementById('topoGoadVersionDesc');
  if (desc) desc.textContent = (lab && lab.description) || '';
}

/** Rebuild the machine list from the selected lab. User-intent only — never on load. */
function topoRebuildFromGoadLab() {
  const lab = findGoadLab(document.getElementById('topoGoadVersion').value);
  const prebaked = document.getElementById('topoGoadPrebaked').checked;
  const seed = TopoSeed().fromGoadLab(lab, {
    includeKali: document.getElementById('topoGoadKali').checked,
    addPivot: prebaked,
    blankVmids: prebaked,
    subnetScheme: topoScheme()
  });
  if (!seed.ok) { Toast.error('GOAD', seed.reason); return; }
  topoVms = seed.vms;
  topoNetwork = null;
  document.getElementById('topoSubnetScheme').value = seed.subnet_scheme;
  onTopoSchemeChange();
  topoDesignMount();       // new array AND a different locked-host set
  renderTopoVmTable(true);
}

async function onTopoGoadToggle() {
  const enabled = document.getElementById('topoGoadEnabled').checked;
  document.getElementById('topoGoadConfig').style.display = enabled ? 'block' : 'none';
  if (enabled) {
    await populateTopoGoadVersions();
    topoRebuildFromGoadLab();
    Toast.info('GOAD enabled', `Machine list set to the ${document.getElementById('topoGoadVersion').value} topology`);
  } else {
    document.getElementById('topoGoadPrebaked').checked = false;
    document.getElementById('topoGoadPrebakedConfig').style.display = 'none';
    // Only the locked-host set changes; the machines stay so turning GOAD off is
    // not a destructive act on work already on the canvas.
    if (topoDesigner) topoDesigner.setGoadHosts(null);
  }
}

function onTopoGoadVersionChange() {
  updateTopoGoadDesc();
  if (document.getElementById('topoGoadEnabled').checked) topoRebuildFromGoadLab();
}

function onTopoGoadKaliToggle() {
  if (!document.getElementById('topoGoadEnabled').checked) return;
  const includeKali = document.getElementById('topoGoadKali').checked;
  const hasKali = topoVms.some(v => v.name === 'Kali');
  if (includeKali && !hasKali) {
    // Mutate in place — the editor holds this array, so a push is visible to it.
    topoVms.push({
      name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, type: 'qemu',
      vm_offset: 600000 + topoVms.length * 10000, default_scripts: [], services: []
    });
    if (topoDesigner) topoDesigner.refresh(topoVms);
    renderTopoVmTable(true);
  } else if (!includeKali && hasKali) {
    // splice, not filter — replacing the array would orphan the editor's handle.
    for (let i = topoVms.length - 1; i >= 0; i--) if (topoVms[i].name === 'Kali') topoVms.splice(i, 1);
    if (topoDesigner) topoDesigner.refresh(topoVms);
    renderTopoVmTable(true);
  }
}

function onTopoGoadPrebakedToggle() {
  const on = document.getElementById('topoGoadPrebaked').checked;
  document.getElementById('topoGoadPrebakedConfig').style.display = on ? 'block' : 'none';
  if (on) {
    document.getElementById('topoSubnetScheme').value = 'v3';
    onTopoSchemeChange();
  }
  if (document.getElementById('topoGoadEnabled').checked) {
    topoRebuildFromGoadLab();
    if (on) Toast.info('Pre-baked mode', 'Enter each golden-image Template VMID — including web01, the DMZ pivot');
  }
}

function resetTopoGoadFields() {
  const cb = document.getElementById('topoGoadEnabled');
  if (cb) cb.checked = false;
  document.getElementById('topoGoadConfig').style.display = 'none';
  const pb = document.getElementById('topoGoadPrebaked');
  if (pb) pb.checked = false;
  document.getElementById('topoGoadPrebakedConfig').style.display = 'none';
  document.getElementById('topoGoadFixedInt').value = '';
  document.getElementById('topoGoadFixedExt').value = '';
  document.getElementById('topoGoadVersionDesc').textContent = '';
}

/**
 * Write a stored GOAD config into the card WITHOUT rebuilding the machine list.
 *
 * That distinction is the point: a seeded spec already carries its machines, and
 * those rows may hold golden-image template_vmids that the catalog's base
 * template would overwrite. So this calls updateTopoGoadDesc(), never
 * onTopoGoadVersionChange().
 */
async function applyTopoGoadFields(goad) {
  if (!goad || !goad.enabled) { resetTopoGoadFields(); return; }
  document.getElementById('topoGoadEnabled').checked = true;
  document.getElementById('topoGoadConfig').style.display = 'block';
  await populateTopoGoadVersions();

  const select = document.getElementById('topoGoadVersion');
  // `_goadCatalog` is admin-challenges.js's top-level `let`. A top-level `let` is
  // NOT a window property, so it must be read by bare name — window._goadCatalog
  // is always undefined. Classic scripts share one global lexical scope, which is
  // what makes the bare reference resolve across files.
  const version = goad.version || (_goadCatalog && _goadCatalog.default_lab) || 'GOAD-Light';
  if ([...select.options].some(o => o.value === version)) select.value = version;

  document.getElementById('topoGoadKali').checked = goad.include_kali !== false;
  document.getElementById('topoGoadPrebaked').checked = !!goad.prebaked;
  document.getElementById('topoGoadPrebakedConfig').style.display = goad.prebaked ? 'block' : 'none';
  document.getElementById('topoGoadFixedInt').value = (goad.fixed_subnet && goad.fixed_subnet.int) || '';
  document.getElementById('topoGoadFixedExt').value = (goad.fixed_subnet && goad.fixed_subnet.ext) || '';
  updateTopoGoadDesc();
}

function readTopoGoadFields() {
  if (!document.getElementById('topoGoadEnabled').checked) return null;
  const goad = {
    enabled: true,
    version: document.getElementById('topoGoadVersion').value ||
      (_goadCatalog && _goadCatalog.default_lab) || 'GOAD-Light',
    domain: document.getElementById('topoGoadDomain').value.trim() || 'cybersaguaros.local',
    child_subdomain: document.getElementById('topoGoadChild').value.trim() || 'tumamoc',
    admin_user: 'Administrator',
    admin_password: document.getElementById('topoGoadPassword').value || 'vagrant',
    include_kali: document.getElementById('topoGoadKali').checked
  };
  if (document.getElementById('topoGoadPrebaked').checked) {
    goad.prebaked = true;
    const int = document.getElementById('topoGoadFixedInt').value.trim();
    const ext = document.getElementById('topoGoadFixedExt').value.trim();
    goad.fixed_subnet = { int, ext: ext || int };
  }
  return goad;
}

// ============================================================================
// DESIGNER — table view + phantoms
// ============================================================================

function topoAddVM() {
  topoVms.push({
    name: '', role: '', os: 'Windows 11 25H2', template_vmid: '', type: 'qemu',
    vm_offset: 600000 + topoVms.length * 10000, default_scripts: [], services: []
  });
  renderTopoVmTable();
}

function removeTopoVM(idx) { topoVms.splice(idx, 1); renderTopoVmTable(); }

/**
 * `fromCanvas` avoids a render loop: a canvas edit calls this to refresh the
 * table, and must not push that straight back into the canvas.
 */
function renderTopoVmTable(fromCanvas) {
  if (!fromCanvas && topoDesigner) topoDesigner.refresh(topoVms);
  const host = document.getElementById('topoDesignVmList');
  if (!host) return;
  if (!topoVms.length) {
    host.innerHTML = '<p style="color: var(--text-muted); font-size: 0.8rem;">' +
      'No machines yet. Drag one in from the palette, or click "+ Add VM".</p>';
    return;
  }
  // topoAttr, not escHtml — machine names are free text and a double quote would
  // otherwise close the value attribute. Applied here so no call site can forget.
  const cell = (label, value, expr, type) =>
    `<div><label style="font-size:0.7rem; color:var(--text-secondary);">${escHtml(label)}</label>` +
    `<input type="${type || 'text'}" value="${topoAttr(value)}" onchange="${expr}" ` +
    `style="width:100%; padding:0.3rem; border-radius:4px; border:1px solid var(--border-color); ` +
    `background:var(--bg-input); color:var(--text-primary); font-size:0.8rem;"></div>`;

  host.innerHTML = topoVms.map((vm, i) => `
    <div style="background: var(--bg-card-hover); border-radius: 8px; padding: 0.75rem; margin-bottom: 0.5rem; border: 1px solid var(--border-color);">
      <div style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 0.5rem;">
        <strong style="font-size: 0.85rem;">VM ${i + 1}</strong>
        <button class="btn btn-sm" style="font-size: 0.65rem; padding: 0.1rem 0.3rem; border: 1px solid var(--danger); color: var(--danger); background: transparent;" onclick="removeTopoVM(${i})">Remove</button>
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem;">
        ${cell('Name', vm.name || '', `topoVms[${i}].name=this.value; renderTopoVmTable()`)}
        ${cell('Role', vm.role || '', `topoVms[${i}].role=this.value; renderTopoVmTable()`)}
        ${cell('OS', vm.os || '', `topoVms[${i}].os=this.value; renderTopoVmTable()`)}
      </div>
      <div style="display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 0.5rem; margin-top: 0.5rem;">
        ${cell('Template VMID', vm.template_vmid || '', `topoVms[${i}].template_vmid=parseInt(this.value)||null; renderTopoVmTable()`, 'number')}
        ${cell('VM Offset', vm.vm_offset, `topoVms[${i}].vm_offset=parseInt(this.value); renderTopoVmTable()`, 'number')}
        ${cell('Services (comma-sep)', (vm.services || []).join(', '), `topoVms[${i}].services=this.value.split(',').map(s=>s.trim()).filter(Boolean)`)}
      </div>
      <div style="margin-top: 0.5rem;">
        ${cell('Default Scripts (comma-sep slugs)', (vm.default_scripts || []).join(', '), `topoVms[${i}].default_scripts=this.value.split(',').map(s=>s.trim()).filter(Boolean)`)}
      </div>
    </div>`).join('');
}

function topoAddPhantom() {
  topoPhantoms.push({ hostname: '', ip: '', role: '', os: '', notes: '' });
  renderTopoPhantoms();
}

function removeTopoPhantom(idx) { topoPhantoms.splice(idx, 1); renderTopoPhantoms(); }

function renderTopoPhantoms() {
  const host = document.getElementById('topoPhantomList');
  if (!host) return;
  const input = (val, ph, expr, width) =>
    `<input type="text" value="${topoAttr(val)}" placeholder="${topoAttr(ph)}" onchange="${expr}" ` +
    `style="${width}; padding:0.3rem; border-radius:4px; border:1px solid var(--border-color); ` +
    `background:var(--bg-input); color:var(--text-primary); font-size:0.8rem;">`;
  host.innerHTML = topoPhantoms.map((p, i) => `
    <div style="display: flex; gap: 0.5rem; align-items: center; margin-bottom: 0.4rem;">
      ${input(p.hostname, 'Hostname', `topoPhantoms[${i}].hostname=this.value`, 'flex:1')}
      ${input(p.ip, 'IP', `topoPhantoms[${i}].ip=this.value`, 'width:120px')}
      ${input(p.role, 'Role', `topoPhantoms[${i}].role=this.value`, 'flex:1')}
      ${input(p.os, 'OS', `topoPhantoms[${i}].os=this.value`, 'width:120px')}
      <button style="font-size:0.7rem; border:1px solid var(--danger); color:var(--danger); background:transparent; border-radius:4px; padding:0.15rem 0.4rem; cursor:pointer;" onclick="removeTopoPhantom(${i})">X</button>
    </div>`).join('') ||
    '<p style="color: var(--text-muted); font-size: 0.8rem;">No phantom assets. These appear in the challenge profile only — no VM is deployed for them.</p>';
}

// ============================================================================
// DESIGNER — validate / export
// ============================================================================

/** Run the server-side validators over the current canvas and paint the results. */
async function topoDesignValidate() {
  if (!topoDesigner) return null;
  try {
    const result = await api('POST', '/lab-templates/validate', {
      subnet_scheme: topoScheme(),
      goad: readTopoGoadFields(),
      vms: CyberCoreTopologyEditor.stripInternal(topoVms)
    });
    topoDesigner.setFindings(result);
    const e = (result.errors || []).length, w = (result.warnings || []).length;
    if (!e && !w) Toast.success('Validated', 'No problems found');
    else Toast.warning('Validated', `${e} error${e === 1 ? '' : 's'}, ${w} warning${w === 1 ? '' : 's'}`);
    return result;
  } catch (err) {
    Toast.error('Validation failed', err.message);
    return null;
  }
}

/** Export the design as a reusable file. Pure client-side, same format the modal writes. */
function topoDesignExport() {
  const payload = {
    format: 'cybercore.topology',
    version: 1,
    challenge_key: document.getElementById('topoKey').value.trim() || null,
    name: document.getElementById('topoName').value.trim() || null,
    subnet_scheme: topoScheme(),
    goad: readTopoGoadFields(),
    network: topoDesigner ? topoDesigner.getNetwork() : topoNetwork,
    vms: CyberCoreTopologyEditor.stripInternal(topoVms)
  };
  const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = `${(payload.challenge_key || payload.name || 'topology')}.cctopo.json`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(a.href);
}

// ============================================================================
// DESIGNER — create
// ============================================================================

const TOPO_ERROR_FIELDS = {
  name: 'topoErrName', challenge_key: 'topoErrKey', zone_abbrev: 'topoErrZone',
  max_lanes: 'topoErrMaxLanes', goad: 'topoErrGoad'
};
const TOPO_INPUT_FIELDS = {
  name: 'topoName', challenge_key: 'topoKey', zone_abbrev: 'topoZone', max_lanes: 'topoMaxLanes'
};

function clearTopoFieldErrors() {
  Object.values(TOPO_ERROR_FIELDS).forEach(id => {
    const el = document.getElementById(id);
    if (el) { el.style.display = 'none'; el.textContent = ''; }
  });
  Object.values(TOPO_INPUT_FIELDS).forEach(id => {
    document.getElementById(id)?.classList.remove('is-invalid');
  });
}

/** Paint problems next to their field; anything unmapped falls back to the status line. */
function paintTopoProblems(problems) {
  clearTopoFieldErrors();
  const loose = [];
  let firstInput = null;
  problems.forEach(p => {
    const errId = TOPO_ERROR_FIELDS[p.field];
    if (!errId) { loose.push(p.message); return; }
    const err = document.getElementById(errId);
    err.textContent = p.message;
    err.style.display = '';
    const input = document.getElementById(TOPO_INPUT_FIELDS[p.field]);
    if (input) { input.classList.add('is-invalid'); if (!firstInput) firstInput = input; }
  });
  if (loose.length) {
    const status = document.getElementById('topoCreateStatus');
    status.innerHTML = loose.map(m => `<div style="color: var(--danger);">${escHtml(m)}</div>`).join('');
  }
  // The settings block may be collapsed; a hidden error is no error at all.
  if (firstInput) {
    document.getElementById('topoSettings').open = true;
    firstInput.focus();
  }
}

/** Everything the create path needs, gathered from the DOM and the live canvas. */
function readTopoDesignState() {
  return {
    name: document.getElementById('topoName').value,
    description: document.getElementById('topoDesc').value,
    challenge_key: document.getElementById('topoKey').value,
    zone_abbrev: document.getElementById('topoZone').value,
    max_lanes: Number(document.getElementById('topoMaxLanes').value),
    difficulty: document.getElementById('topoDifficulty').value,
    module: document.getElementById('topoModule').value,
    subnet_scheme: topoScheme(),
    // __topoId is a per-session canvas handle and must never reach the database.
    vms: CyberCoreTopologyEditor.stripInternal(topoVms),
    network: topoDesigner ? topoDesigner.getNetwork() : topoNetwork,
    phantoms: topoPhantoms,
    goad: readTopoGoadFields()
  };
}

/** Live feedback on the key: show the zone it derives to, and flag a collision early. */
function onTopoKeyInput() {
  const key = document.getElementById('topoKey').value.trim();
  const zone = document.getElementById('topoZone');
  if (zone && !zone.value) zone.placeholder = TopoSeed().deriveZone(key) || 'auto from key';
  const err = document.getElementById('topoErrKey');
  const clash = key && topoChallenges.some(t => t.challenge_key === key);
  if (clash) {
    err.textContent = `Challenge key "${key}" already exists — Create would fail`;
    err.style.display = '';
    document.getElementById('topoKey').classList.add('is-invalid');
  } else if (err.textContent.includes('already exists')) {
    err.style.display = 'none';
    err.textContent = '';
    document.getElementById('topoKey').classList.remove('is-invalid');
  }
}

async function topoCreateChallenge() {
  const Seed = TopoSeed();
  const status = document.getElementById('topoCreateStatus');
  clearTopoFieldErrors();
  status.innerHTML = '';

  // Refresh the key list first so a challenge created elsewhere is still caught.
  // Best-effort: the server's unique index is the real authority.
  try { topoChallenges = await api('GET', '/lab-templates'); } catch (e) { /* keep what we have */ }

  const state = readTopoDesignState();
  const problems = Seed.validateCreateState(state, {
    existingKeys: topoChallenges.map(t => t.challenge_key)
  });
  if (problems.length) {
    paintTopoProblems(problems);
    Toast.warning('Not ready', problems[0].message);
    return;
  }

  // The same validators the deploy path runs, so this cannot green-light a spec
  // that would fail later.
  if (!topoDesigner) {
    status.innerHTML = '<div style="color: var(--danger);">The canvas did not load, so this design cannot be validated. ' +
      'Reload the page before creating — creating unvalidated would provision real SDN infrastructure.</div>';
    return;
  }
  const result = await topoDesignValidate();
  if (!result) return;   // the validate call failed and already toasted
  if ((result.errors || []).length) {
    status.innerHTML = `<div style="color: var(--danger);">Fix the ${result.errors.length} error(s) below before creating.</div>`;
    return;
  }
  if ((result.warnings || []).length) {
    const list = result.warnings.map(w => `• ${w.message || w}`).join('\n');
    if (!confirm(`This topology validates with warnings:\n\n${list}\n\nCreate it anyway?`)) return;
  }

  const body = Seed.toCreateLabBody(state);
  status.textContent = body.goad
    ? `Creating GOAD challenge (${body.goad.version}) + SDN infrastructure…`
    : 'Creating challenge + SDN infrastructure…';

  try {
    const data = await api('POST', '/create-lab', body);
    status.innerHTML = `
      <strong style="color: var(--success);">Challenge created.</strong><br>
      Key: <code>${escHtml(data.challenge_key)}</code> ·
      Zone: <code>${escHtml(data.zone_abbrev)}</code> ·
      VXLAN: ${data.vxlan_block ? `${data.vxlan_block.start}–${data.vxlan_block.end}` : '—'} ·
      VNets: ${data.vnets_created} ·
      Machines: ${body.vms.length}
      <div style="margin-top:0.5rem; display:flex; gap:0.5rem; flex-wrap:wrap;">
        <!-- id rides on a data-* attribute rather than being interpolated into the
             handler string: topoAttr would encode a quote as &#39;, which the HTML
             parser decodes back BEFORE the JS runs, breaking the string literal.
             Same reason the CLE course page uses this pattern. -->
        <button class="btn btn-sm btn-outline" data-id="${topoAttr(data.challenge_id)}"
                onclick="editTemplate(this.dataset.id)">Open in editor</button>
        <button class="btn btn-sm btn-outline" data-id="${topoAttr(data.challenge_id)}"
                onclick="topoShowSpec(this.dataset.id)">View in Viewer</button>
      </div>
      <details style="margin-top: 0.5rem; font-size: 0.75rem;">
        <summary style="cursor: pointer; color: var(--text-muted);">Creation log</summary>
        <div style="background: var(--bg-card-hover); padding: 0.5rem; border-radius: 4px; margin-top: 0.25rem; white-space: pre-wrap;">${escHtml((data.steps || []).join('\n'))}</div>
      </details>`;
    Toast.success('Challenge created', `${body.vms.length} machine(s), ${data.vnets_created} VNets`);

    // Other tabs cache the challenge list.
    if (typeof loadChallengeTemplates === 'function') loadChallengeTemplates();
    if (typeof loadModulesAndChallenges === 'function') loadModulesAndChallenges();
    try { topoChallenges = await api('GET', '/lab-templates'); } catch (e) { /* non-fatal */ }
    onTopoSeedSourceChange();
  } catch (e) {
    const msg = String(e.message || '');
    if (/already exists/i.test(msg)) {
      // The one error with an obvious fix — put it on the field.
      paintTopoProblems([{ field: 'challenge_key', message: msg }]);
    } else if (/zone_abbrev|max_lanes|are required|template_vmid is required/i.test(msg)) {
      // A local gate has drifted from the server's; surface it verbatim.
      status.innerHTML = `<div style="color: var(--danger);">${escHtml(msg)}</div>`;
      console.warn('[Topology] Server rejected a request the local gates passed:', msg);
    } else {
      // SDN provisioning failed. reserveLabNetwork rolls the challenge row back,
      // so the key is free — say so, or the author assumes it is burned.
      status.innerHTML =
        `<div style="color: var(--danger);">${escHtml(msg)}</div>` +
        `<div style="color: var(--text-muted); font-size:0.75rem; margin-top:0.25rem;">` +
        `The challenge row is rolled back when provisioning fails, so this key is still free to retry.</div>`;
    }
    Toast.error('Create failed', msg);
  }
}

// ============================================================================
// VIEWER
// ============================================================================

function topoViewerDestroy() {
  // Invalidate any render still awaiting a fetch. Without this, switching to the
  // Designer (or to the other view kind) while a Proxmox read is in flight lets
  // that read finish and build a Cytoscape instance into a hidden pane, which
  // nothing then holds a reference to.
  topoViewSeq += 1;
  if (topoViewer) { try { topoViewer.destroy(); } catch (e) { /* already gone */ } topoViewer = null; }
  const canvas = document.getElementById('topoViewCanvas');
  if (canvas) canvas.innerHTML = '';
  const findings = document.getElementById('topoViewFindings');
  if (findings) findings.innerHTML = '';
}

function onTopoViewKindChange() {
  const picked = document.querySelector('input[name="topoViewKind"]:checked');
  topoViewKind = picked ? picked.value : 'lane';
  loadTopoViewChoices();
}

async function loadTopoViewChoices(force) {
  const sel = document.getElementById('topoViewChoice');
  const meta = document.getElementById('topoViewMeta');
  topoViewerDestroy();
  sel.innerHTML = '<option value="">Loading…</option>';

  try {
    if (topoViewKind === 'lane') {
      // GET /lanes returns every lane including deleted ones; only an active lane
      // has VMs in Proxmox to read attachments from.
      const rows = await api('GET', '/lanes');
      topoLanes = (rows || []).filter(l => l.status === 'active');
      sel.innerHTML = topoLanes.length
        ? topoLanes.map(l =>
            `<option value="${topoAttr(l.lane_id)}">${escHtml(l.name || l.lane_id)} — VXLAN ${escHtml(String(l.vxlan_id))}</option>`).join('')
        : '<option value="">No active lanes</option>';
    } else {
      if (force || !topoChallenges.length) topoChallenges = await api('GET', '/lab-templates');
      sel.innerHTML = topoChallenges.length
        ? topoChallenges.map(t =>
            `<option value="${topoAttr(t.id)}">${escHtml(t.name)} — ${escHtml(t.challenge_key)}</option>`).join('')
        : '<option value="">No challenges</option>';
    }
    // Restore a selection requested before the options existed (the post-create
    // "View in Viewer" shortcut).
    if (topoViewPendingId) {
      if ([...sel.options].some(o => o.value === topoViewPendingId)) sel.value = topoViewPendingId;
      topoViewPendingId = null;
    }
    topoViewLoaded = true;
    meta.textContent = '';
    await renderTopoView();
  } catch (e) {
    sel.innerHTML = '<option value="">Failed to load</option>';
    meta.innerHTML = `<span style="color: var(--danger);">${escHtml(e.message)}</span>`;
  }
}

/**
 * Jump straight to a challenge's spec view — the post-create shortcut.
 *
 * Hands the id off through topoViewPendingId rather than loading the list itself:
 * setTopoMode already triggers a load, and two concurrent loads would each
 * destroy and recreate the viewer.
 */
function topoShowSpec(challengeId) {
  document.querySelector('input[name="topoViewKind"][value="spec"]').checked = true;
  topoViewKind = 'spec';
  topoViewPendingId = challengeId;
  topoViewLoaded = false;
  setTopoMode('view');
}

async function renderTopoView() {
  const id = document.getElementById('topoViewChoice').value;
  const meta = document.getElementById('topoViewMeta');
  const canvas = document.getElementById('topoViewCanvas');
  // Destroy FIRST — it bumps the sequence, invalidating any older in-flight
  // render — then claim the generation this render owns. Taking `seq` before the
  // destroy would invalidate this render immediately.
  topoViewerDestroy();
  const seq = topoViewSeq;
  applyTopoViewLegend();
  if (!id) { meta.textContent = ''; return; }

  meta.textContent = topoViewKind === 'lane'
    ? 'Reading lane configuration from Proxmox…'
    : 'Reading the challenge spec…';

  try {
    // Cytoscape measures its container at init, so build the host element only
    // once the pane is visible — which it is, since the viewer is the active mode.
    const el = document.createElement('div');
    el.style.cssText = 'position:absolute; inset:0;';

    if (topoViewKind === 'lane') {
      const data = await api('GET', `/lanes/${id}/topology`);
      if (seq !== topoViewSeq) return;      // superseded while Proxmox was read
      const unattached = data.nodes.filter(n => !n.segments.length).length;
      meta.innerHTML =
        `<strong>${escHtml(data.lane.challenge_key || '—')}</strong> · ` +
        `${escHtml(data.lane.subnet_scheme)} · VXLAN ${escHtml(String(data.lane.vxlan_id))} · ` +
        `${data.nodes.length} machine${data.nodes.length === 1 ? '' : 's'}` +
        (unattached ? ` · <span style="color: var(--danger);">${unattached} on no known segment</span>` : '');

      canvas.appendChild(el);
      topoViewer = CyberCoreTopology.create(el, { mode: 'view' });
      topoViewer.setData({
        segments: data.segments,
        gateway: data.gateway,
        nodes: data.nodes.map(n => ({
          id: n.id, name: n.name, role: n.role, os: n.os, ip: n.ip, segments: n.segments,
          // A stopped machine reads as a problem worth seeing at a glance.
          severity: n.power_state && n.power_state !== 'running' ? 'warning' : ''
        }))
      }, true);
      return;
    }

    // ── challenge spec ─────────────────────────────────────────────────────
    // specToGraph derives attachments client-side rather than through a new
    // endpoint; see its comment for why. Also the code test/topology-spec-view.js
    // exercises, so this path is the tested one.
    const row = await api('GET', `/lab-templates/${id}`);
    if (seq !== topoViewSeq) return;        // superseded
    const goad = (typeof row.spec === 'string' ? JSON.parse(row.spec || '{}') : (row.spec || {})).goad;
    const built = TopoSeed().specToGraph(row, {
      goadHostNames: (goad && goad.enabled) ? (findGoadLab(goad.version)?.vms || []).map(v => v.name) : []
    });

    meta.innerHTML =
      `<strong>${escHtml(row.challenge_key || '—')}</strong> · ${escHtml(built.scheme)} · ` +
      `${built.vms.length} machine${built.vms.length === 1 ? '' : 's'} · ` +
      `<span style="color: var(--text-muted);">spec, not deployed</span>` +
      (built.isReservation
        ? ' · <span style="color: var(--warning);">reserved lab network — owns a VXLAN block and SDN zone, but declares no machines</span>'
        : '');

    canvas.appendChild(el);
    topoViewer = CyberCoreTopology.create(el, { mode: 'view' });
    topoViewer.setData(built.graph, built.runLayout);

    // Badge the spec's problems too — nearly free, and the whole point of looking
    // at a spec next to a lane is spotting what will go wrong.
    try {
      const result = await api('POST', '/lab-templates/validate', {
        subnet_scheme: built.scheme, goad: goad || null, vms: built.vms
      });
      // topoViewer may already have been destroyed and replaced by a newer render.
      if (seq !== topoViewSeq) return;
      topoViewer.setValidation(result.findings || []);
      renderTopoViewFindings(result);
    } catch (e) { /* advisory only */ }
  } catch (e) {
    if (seq !== topoViewSeq) return;
    meta.innerHTML = `<span style="color: var(--danger);">${escHtml(e.message)}</span>`;
  }
}

function renderTopoViewFindings(result) {
  const host = document.getElementById('topoViewFindings');
  const all = (result && result.findings) || [];
  if (!host) return;
  host.innerHTML = all.length
    ? '<div class="topo-findings">' + all.map(f =>
        `<div class="topo-finding is-${escHtml(f.severity)}">` +
        (f.vm ? `<span class="topo-finding-vm">${escHtml(f.vm)}</span>` : '') +
        `<span>${escHtml(f.message)}</span></div>`).join('') + '</div>'
    : '';
}

function applyTopoViewLegend() {
  const legend = document.getElementById('topoViewLegend');
  if (!legend) return;
  const shared =
    '<span><i class="topo-lg-ext"></i> External / Attacker</span>' +
    '<span><i class="topo-lg-int"></i> Internal / Corp</span>';
  legend.innerHTML = topoViewKind === 'lane'
    ? shared +
      '<span>Amber border = not running</span>' +
      '<span>Attachments read live from Proxmox, not from the challenge spec</span>'
    : shared +
      '<span>Double border = placement fixed by the GOAD lab</span>' +
      '<span>Attachments derived from the spec — this is what a lane would deploy as</span>';
}
