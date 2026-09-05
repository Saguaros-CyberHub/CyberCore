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
// It owns no CANVAS rendering. Every canvas behaviour — the context menu, the
// last-NIC refusal, the GOAD name locks — lives in
// topology-editor.js/topology-render.js and is therefore shared with the
// Challenge Template editor modal's canvas, which is the point: two surfaces,
// one set of rules. This file consumes only
// the public APIs: CyberCoreTopology.create,
// CyberCoreTopologyEditor.{mount,segmentsForScheme,deriveSegments,stripInternal,
// menuGuards}, CyberCoreTopologySeed, and goad-extensions.js's catalog pair.
//
// What it DOES own for someone else is the GOAD configuration card. See "GOAD
// CARD — ONE implementation, two surfaces" below: those `goadCard*` functions
// back both this tab's card and the Challenge Template editor modal's, and
// admin-challenges.js binds to them through tplGoadCard(). Everything else in
// this file is `topo`-prefixed and private to the tab.
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
    onChange: () => { renderTopoVmTable(true); },
    // Backs the canvas context menu's "Validate" — the same call the toolbar
    // button makes, so there is one validate path rather than two.
    onValidate: () => { topoDesignValidate(); }
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
// GOAD CARD — ONE implementation, two surfaces
// ============================================================================
// Everything from here to "DESIGNER — table view" is shared by BOTH of the GOAD
// configuration cards this page still has:
//
//   · the Topology Designer's  (#topoGoad*, this tab)
//   · the Template Editor's    (#tplGoad*,  the modal in admin-challenges.js)
//
// (There is a third, #chalGoad*, on the old "Create New Environment" form. It is
// the oldest and least capable surface and is deliberately left alone.)
//
// ── WHY THIS IS SHARED AT ALL ───────────────────────────────────────────────
// It was not, and that is the bug this section exists to end. The editor's card
// had fallen a whole feature set behind: no Extensions group, read-only forest
// and child domains, no pre-baked toggle and no fixed_subnet. So someone who
// opened an existing environment with "Edit" could not reach the pre-baked
// golden-image flow at all — and spec.goad.prebaked REQUIRES goad.fixed_subnet
// to deploy, so the one surface that edits an existing spec could not author the
// pair the deploy demands. Three copies of one card is HOW that drift happened;
// a fourth copy of the fix would guarantee it happens again.
//
// ── THE APPROACH, AND WHY IT IS NOT THE STRONGER ONE ────────────────────────
// The stronger option was to generate the card's MARKUP here too and mount it
// into both hosts, so there is literally one source for the FIELDS as well as
// the behaviour. It is not available. test/ad-domain-rules.test.js reads
// public/admin.html and asserts on `id="topoGoadDomain" …
// oninput="onTopoGoadDomainInput()"` being in that file; generating the markup
// from JS deletes the text it matches. The Designer works today and its tests
// pass, and breaking it to fix the editor is a net loss.
//
// So: every BEHAVIOUR lives here exactly once, parameterised by a card
// descriptor, and the two markup blocks are held together by a source-text
// DRIFT GATE — test/goad-card-parity.test.js strips the prefix off both blocks
// and fails on the first field, handler or readonly flag that one card grows and
// the other does not. That gate is the price of leaving two copies of the
// markup; it is what makes this arrangement honest rather than merely smaller.
//
// ── WHY IT LIVES IN admin-topology.js ───────────────────────────────────────
// Because the working implementation is already here, and three existing
// assertions name THIS FILE for it: ad-domain-rules.test.js pins
// `childEl.value = (lab && lab.childSubdomain) || '';`,
// `window.CyberCoreAdDomainRules` and `topoErrGoad` in
// public/js/admin/admin-topology.js, and goad-extensions.test.js's headless
// harness loads exactly {goad-extensions.js, admin-topology.js} and drives
// onTopoExtensionToggle through it. Moving the code to a new file — or to
// goad-extensions.js, otherwise the natural home — breaks all of them for no
// behavioural gain. admin-challenges.js therefore CALLS INTO this file. That
// direction is safe even though admin.html loads it first: classic scripts share
// one global scope and every call here happens on a user gesture, long after
// both files have evaluated.
//
// ── THE CARD DESCRIPTOR ─────────────────────────────────────────────────────
// A surface hands its differences in as a plain object, rebuilt on every call so
// it always reads the CURRENT machine array rather than a stale capture:
//
//   prefix          'topo' | 'tpl' — every element is `<prefix>Goad<Suffix>`
//   errId           the field-error element for this card
//   extToggleFn     the global name the generated checkboxes call on change
//   getVms()        the machine array the canvas is holding
//   setVms(vms)     REPLACE it — a wholesale lab rebuild only, see below
//   editor()        the CyberCoreTopologyEditor controller, or null
//   refresh()       re-render this surface's table view
//   mount()         remount the canvas; mandatory after setVms
//   getScheme()     'v1' | 'v2' | 'v3'
//   applyScheme(s)  adopt the scheme a seed chose, or say why it cannot
//   clearNetwork()  drop stored segment positions after a wholesale rebuild
//
// See topoGoadCard() at the end of this section and tplGoadCard() in
// admin-challenges.js — those two factories are the ONLY place the surfaces
// differ.
//
// ── THE TWO LOAD-BEARING BEHAVIOURS ─────────────────────────────────────────
// 1. THE KALI PATTERN, NOT THE VERSION PATTERN. goadCardRebuildFromLab replaces
//    the machine list WHOLESALE — correct when the author picks a different lab,
//    catastrophic for an extension tick, which would discard the canvas layout,
//    every hand-added machine and every template_vmid typed by hand.
//    goadCardOnKaliToggle and goadCardToggleExtension are therefore surgical:
//    push/splice on the SAME array the editor closes over, then refresh. Pinned
//    by IDENTITY in goad-extensions.test.js, not by contents.
// 2. EXTENSION MACHINE NAMES ARE NAME-LOCKED. goadCardHostNames feeds goadHosts
//    into the editor mount, which disables the name field and the Rename/Remove
//    menu items. The names are a contract with the golden images and the baked
//    agent configs, not labels.
// ============================================================================

/** The `<prefix>Goad<suffix>` element for this card, or null. */
const goadCardStored = Object.create(null);

function goadCardEl(card, suffix) {
  return document.getElementById(card.prefix + 'Goad' + suffix);
}

/** Is GOAD switched on for this card? */
function goadCardOn(card) {
  const cb = goadCardEl(card, 'Enabled');
  return !!(cb && cb.checked);
}

/**
 * The next free slot in the 600000 + n*10000 band.
 *
 * Two machines on one vm_offset clone to the same VMID and the second deploy
 * fails, so neither the Kali toggle nor an extension tick may assume the array
 * is contiguous — an author who removed a row leaves a hole that
 * `600000 + length * 10000` would land on top of.
 */
function goadCardFreeOffset(vms) {
  const used = new Set((vms || []).map(v => Number(v.vm_offset)));
  let offset = 600000;
  while (used.has(offset)) offset += 10000;
  return offset;
}

async function goadCardPopulateVersions(card) {
  const catalog = await loadGoadCatalog();
  const select = goadCardEl(card, 'Version');
  if (!select) return;
  const previous = select.value || catalog.default_lab;
  select.innerHTML = (catalog.labs || []).map(l =>
    `<option value="${topoAttr(l.key)}">${escHtml(l.displayName || l.key)}</option>`
  ).join('') || '<option value="GOAD-Light">GOAD-Light</option>';
  select.value = (catalog.labs || []).some(l => l.key === previous)
    ? previous : (catalog.default_lab || 'GOAD-Light');
  goadCardUpdateDesc(card);
}

function goadCardUpdateDesc(card) {
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const desc = goadCardEl(card, 'VersionDesc');
  if (desc) desc.textContent = (lab && lab.description) || '';
}

// ── Forest domain / child subdomain ────────────────────────────────────────
//
// These fields used to be readonly AND STALE on every card: a version change
// only refreshed the description and the machine list, so picking GOAD-Mini left
// 'cybersaguaros.local' on screen while the lab's own forestRoot is
// 'sevenkingdoms.local' — and the stale value is what got stored. Every lab but
// GOAD-Light persisted a domain it does not have. (The template editor's card
// still said "Forest Domain (read-only)" until this section became shared, which
// is the same bug wearing a label.)
//
// They are editable now, so the fix is two-part: RESET them from the lab on a
// version change (the lab's values are the defaults, which is what makes them
// correct rather than merely fresh), and VALIDATE what the author types against
// ad-domain-rules — the same rulebook the create handler runs server-side and
// Track G's compiler mints against. There is no second rulebook here.

/** Stamp the selected lab's own domain names into the two fields. */
function goadCardResetDomainsFromLab(card) {
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const domainEl = goadCardEl(card, 'Domain');
  const childEl = goadCardEl(card, 'Child');
  if (!domainEl || !childEl) return;
  // `|| ''` on the child, not a fallback to 'tumamoc': GOAD-Mini, SCCM, NHA and
  // DRACARYS have exactly one domain, and childSubdomain is null for them.
  // Inventing a child for a single-domain lab is how the old hardcoded default
  // got into every spec in the first place.
  domainEl.value = (lab && lab.forestRoot) || 'cybersaguaros.local';
  childEl.value = (lab && lab.childSubdomain) || '';
  goadCardValidateDomains(card);
}

/**
 * Paint domain problems into this card's error line. Returns the rule result so
 * the create path can refuse on an error without re-deriving anything.
 *
 * Errors block; a reserved TLD is only a WARNING, because every lab CyberCore
 * ships is named under .local and that name lives in the golden image's NTDS —
 * hard-failing it would make an unedited legacy lab unauthorable.
 */
function goadCardValidateDomains(card) {
  const err = document.getElementById(card.errId);
  const Rules = window.CyberCoreAdDomainRules;
  const domainEl = goadCardEl(card, 'Domain');
  const childEl = goadCardEl(card, 'Child');
  if (!goadCardOn(card) || !Rules || !domainEl || !childEl) {
    if (err) { err.style.display = 'none'; err.textContent = ''; err.classList.remove('is-warning'); }
    return { errors: [], warnings: [] };
  }
  const result = Rules.validateGoadDomains({
    domain: domainEl.value,
    child_subdomain: childEl.value
  });
  if (!err) return result;
  const lines = result.errors.length ? result.errors : result.warnings;
  err.textContent = lines.join(' ');
  err.style.display = lines.length ? '' : 'none';
  // A warning must not read as a blocker — it is the state EVERY shipped lab is
  // in, so painting it danger-red trains people to ignore the slot.
  err.classList.toggle('is-warning', !result.errors.length && result.warnings.length > 0);
  return result;
}

function goadCardOnDomainInput(card) {
  goadCardValidateDomains(card);
  // The rename hint carries the reserved-TLD refusal, and that is a function of
  // what is being typed RIGHT NOW. A green card that 400s on save is the exact
  // failure the hint slot exists to prevent, so it repaints on every keystroke
  // the domain takes.
  goadCardPaintRenameHint(card);
}

// ── The forest-domain RENAME opt-in ────────────────────────────────────────
//
// THE BUG THIS ANSWERS. An author typed cy400test.org into the Forest Domain
// field and the lane deployed sevenkingdoms.local with a DC that called itself
// kingslanding. spec.goad.domain is authored, validated, reset on a version
// change, round-tripped AND ALREADY READ — it drives the lane's DNS forwarder
// and Caldera's AD facts — but the AD build ignored it. So every artifact said
// one domain and NTDS said another, silently. Found live: Kibana reported
// agent.hostname: kingslanding and the console offered "Sign in to:
// SEVENKINGDOMS" on a lane whose spec said neither.
//
// WHY AN OPT-IN AND NOT `domain !== forestRoot`. The create handler defaults
// EVERY GOAD spec to cybersaguaros.local/tumamoc regardless of which lab was
// picked, so `domain !== forestRoot` is true for every stored GOAD-Mini spec in
// the database today. A derived trigger would recompile all of them into a
// forest nobody chose, on their next deploy. A key that is absent from every
// stored row cannot do that — which is why goadCardReadFields writes
// rename_forest ONLY when it is true, and why an untouched card posts the same
// body it posted before this field existed.
//
// WHY BOTH DOMAIN FIELDS STAY EDITABLE EITHER WAY. With rename off the domain is
// still the record the DNS forwarder and the Caldera facts are built from, and a
// pre-baked lane MUST be able to record whatever its golden image was baked
// with. Disabling the field would make that unauthorable. It is the CHECKBOX
// that gets disabled, and in JS rather than in markup, because the reason is
// data-driven — which lab, and whether this lane is pre-baked — and a disabled
// control the author cannot be told the reason for is the thing the readonly pin
// in goad-card-parity.test.js argues against.

/**
 * Enable or disable the rename opt-in, and say what ticking it does — or why it
 * cannot be ticked here.
 *
 * Repainted from every gesture that can change the answer (the tick, a version
 * change, the pre-baked toggle, domain input, the load path), because everything
 * the tick changes happens 40 minutes later at deploy and this hint is the only
 * place the author hears about it first.
 */
function goadCardPaintRenameHint(card) {
  const box = goadCardEl(card, 'RenameForest');
  const hint = goadCardEl(card, 'RenameHint');
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const stored = goadCardStored[card.prefix];
  const compiled = !!(stored && (stored.lab || stored.generated_lab || stored.rename_plan));
  const prebaked = goadCardEl(card, 'Prebaked');
  let blocked = '';
  if (compiled) blocked = 'This compiled environment keeps its existing forest definition. Regenerate it to change its identity.';
  else if (prebaked && prebaked.checked) blocked = 'Rename forest is unavailable on a pre-baked lane; its golden images already contain the forest.';
  else if (!lab) blocked = 'Rename forest is unavailable: this GOAD version is not in the supported catalog.';
  else if (lab.rebrandable !== true) blocked = `Rename forest is unavailable for ${lab.displayName || lab.key}: no supported vendored transform is available.`;
  if (box) box.disabled = !!blocked;
  if (!hint) return;
  if (blocked) { hint.textContent = blocked; return; }
  if (!box || !box.checked) {
    hint.textContent = `The lab builds ${lab.forestRoot || 'its stock forest'} as shipped. Enable Rename forest to build the authored domain.`;
    return;
  }
  const Rules = window.CyberCoreAdDomainRules;
  const raw = goadCardEl(card, 'Domain').value.trim();
  const domain = Rules ? Rules.publicDomainOf(raw) : raw.toLowerCase();
  if (!domain) {
    hint.textContent = 'Rename forest requires a valid public-shaped domain; reserved suffixes such as .local and malformed DNS names cannot be compiled.';
    return;
  }
  const domains = Array.isArray(lab.domains) ? lab.domains : [];
  const identities = [domain];
  if (lab.childSubdomain) {
    const child = goadCardEl(card, 'Child').value.trim() || 'corp';
    identities.push(child.endsWith('.' + domain) ? child : `${child}.${domain}`);
  }
  const trust = domains.some(d => d !== lab.forestRoot && !d.endsWith('.' + lab.forestRoot));
  if (trust) {
    const labels = domain.split('.');
    identities.push(`${labels[0]}-partner.${labels.slice(1).join('.')}`);
  }
  const names = (lab.vms || []).map(v => v.name).join(', ');
  hint.textContent = `Build domains: ${identities.join(', ')}. Hostnames use the fixed catalog roster (${names}); the domain field does not name a computer. The controller compiles the lab tree at deploy. Save validates domain and NetBIOS identities; pre-baked images cannot be renamed.`;
}

/**
 * The opt-in itself.
 *
 * A repaint and nothing else, on purpose: every consequence of the tick happens
 * at deploy, so the hint IS the behaviour on this surface. The stored key is
 * written by goadCardReadFields, and only when this box is checked.
 */
function goadCardOnRenameForestToggle(card) {
  goadCardPaintRenameHint(card);
}

/**
 * Rebuild the machine list from the selected lab. USER INTENT ONLY — never on
 * load, and never on an extension tick.
 *
 * This is the wholesale path: it throws away the canvas layout and every
 * hand-added machine, which is right when the author has just chosen a different
 * lab and wrong for anything else.
 */
function goadCardRebuildFromLab(card) {
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const prebakedEl = goadCardEl(card, 'Prebaked');
  const prebaked = !!(prebakedEl && prebakedEl.checked);
  const kaliEl = goadCardEl(card, 'Kali');
  const seed = TopoSeed().fromGoadLab(lab, {
    includeKali: !!(kaliEl && kaliEl.checked),
    addPivot: prebaked,
    blankVmids: prebaked,
    subnetScheme: card.getScheme()
  });
  if (!seed.ok) { Toast.error('GOAD', seed.reason); return; }
  card.setVms(seed.vms);
  // A lab change rebuilds the machine list wholesale, so the extension machines
  // have to be re-stamped onto the fresh list — otherwise ticking elk, then
  // switching lab, silently drops the SIEM while its checkbox stays ticked.
  // Rendered FIRST so a selection the new lab cannot take is already unticked.
  goadCardRenderExtensions(card, goadCardReadExtensions(card));
  goadCardReadExtensions(card).forEach(key => {
    const ext = findGoadExtension(key);
    if (!ext) return;
    const vms = card.getVms();
    if (vms.some(v => String(v.name).toLowerCase() === ext.machine.toLowerCase())) return;
    vms.push(buildGoadExtensionRow(ext, goadCardFreeOffset(vms)));
  });
  card.clearNetwork();
  card.applyScheme(seed.subnet_scheme);
  card.mount();            // the array was REPLACED and the locked-host set changed
  card.refresh();
}

async function goadCardOnToggle(card) {
  const enabled = goadCardOn(card);
  const cfg = goadCardEl(card, 'Config');
  if (cfg) cfg.style.display = enabled ? 'block' : 'none';
  if (enabled) {
    const stored = goadCardStored[card.prefix];
    if (stored && (stored.lab || stored.generated_lab || stored.rename_plan)) {
      return goadCardApplyFields(card, { ...stored, enabled: true });
    }
    await goadCardPopulateVersions(card);
    await loadGoadExtensionCatalog();
    goadCardRenderExtensions(card, []);
    goadCardResetDomainsFromLab(card);
    goadCardPaintRenameHint(card);
    goadCardRebuildFromLab(card);
    const select = goadCardEl(card, 'Version');
    Toast.info('GOAD enabled', `Machine list set to the ${select && select.value} topology`);
  } else {
    const pb = goadCardEl(card, 'Prebaked');
    if (pb) pb.checked = false;
    const pbc = goadCardEl(card, 'PrebakedConfig');
    if (pbc) pbc.style.display = 'none';
    // Same reasoning as the pre-baked flag: an opt-in that survives GOAD being
    // switched off is an opt-in nobody re-chose for whatever the card becomes.
    const rename = goadCardEl(card, 'RenameForest');
    if (rename) rename.checked = false;
    goadCardPaintRenameHint(card);
    goadCardValidateDomains(card);      // clears the error line with the card off
    // Only the locked-host set changes; the machines stay so turning GOAD off is
    // not a destructive act on work already on the canvas.
    const editor = card.editor();
    if (editor) editor.setGoadHosts(null);
  }
}

function goadCardOnVersionChange(card) {
  if (goadCardStored[card.prefix]?.lab || goadCardStored[card.prefix]?.generated_lab || goadCardStored[card.prefix]?.rename_plan) return;
  delete goadCardStored[card.prefix];
  goadCardUpdateDesc(card);
  if (!goadCardOn(card)) return;
  // The lab's own forest names are the defaults, so a version change RESETS
  // both fields — this is the fix for the stale-value bug that made every lab
  // but GOAD-Light persist a domain it does not have. An author who has already
  // overridden them loses that override, which is the correct trade: the fields
  // describe the lab that is now selected.
  goadCardResetDomainsFromLab(card);
  // UNTICK rather than preserve. The reset above has just put the NEW lab's own
  // stock forest root back into the field, so a rename left ticked would compile
  // a tree byte-identical to stock under a minted lab name — 40 minutes of
  // Ansible to build exactly what the vendored lab already builds. (And the new
  // lab may be multi-domain, where the tick is not offered at all; the repaint
  // is what disables it.)
  const rename = goadCardEl(card, 'RenameForest');
  if (rename) rename.checked = false;
  goadCardPaintRenameHint(card);
  goadCardRebuildFromLab(card);   // re-renders the extension list and re-stamps it
}

function goadCardOnKaliToggle(card) {
  if (!goadCardOn(card)) return;
  const includeKali = goadCardEl(card, 'Kali').checked;
  const vms = card.getVms();
  const hasKali = vms.some(v => v.name === 'Kali');
  if (includeKali && !hasKali) {
    // Mutate in place — the editor holds this array, so a push is visible to it.
    vms.push({
      name: 'Kali', role: 'attacker', os: 'Kali Linux', template_vmid: 1699, type: 'qemu',
      vm_offset: goadCardFreeOffset(vms), default_scripts: [], services: []
    });
  } else if (!includeKali && hasKali) {
    // splice, not filter — replacing the array would orphan the editor's handle.
    for (let i = vms.length - 1; i >= 0; i--) if (vms[i].name === 'Kali') vms.splice(i, 1);
  } else {
    return;
  }
  const editor = card.editor();
  if (editor) editor.refresh(vms);
  card.refresh();
}

function goadCardOnPrebakedToggle(card) {
  const on = goadCardEl(card, 'Prebaked').checked;
  const pbc = goadCardEl(card, 'PrebakedConfig');
  if (pbc) pbc.style.display = on ? 'block' : 'none';
  // A pre-baked lane runs no Ansible, so a renamed forest could not be built on
  // it. Untick unconditionally rather than only on the way in: coming back OUT
  // of pre-baked must not silently re-arm a rename the author never re-chose —
  // and the repaint is what re-enables the box once it is legal again.
  const rename = goadCardEl(card, 'RenameForest');
  if (rename) rename.checked = false;
  goadCardPaintRenameHint(card);
  // Pre-baked AD images carry full per-segment IPs, so they only make sense on a
  // segmented lane, and fromGoadLab forces the seed to v3 for exactly that
  // reason. The rebuild below already hands that choice to applyScheme, so this
  // must NOT also call it — the Designer would harmlessly set its dropdown
  // twice, but the template editor's applyScheme is a warning toast, and saying
  // the same thing twice is how a warning becomes noise. Only the (unreachable
  // through the UI) GOAD-off path needs the direct call.
  if (goadCardOn(card)) {
    goadCardRebuildFromLab(card);
    if (on) Toast.info('Pre-baked mode', 'Enter each golden-image Template VMID — including web01, the DMZ pivot');
  } else if (on) {
    card.applyScheme('v3');
  }
}

function goadCardReset(card) {
  delete goadCardStored[card.prefix];
  for (const suffix of ['Version', 'Domain', 'Child', 'Prebaked']) {
    const el = goadCardEl(card, suffix);
    if (el) el.disabled = false;
  }
  const cb = goadCardEl(card, 'Enabled');
  if (cb) cb.checked = false;
  const cfg = goadCardEl(card, 'Config');
  if (cfg) cfg.style.display = 'none';
  const pb = goadCardEl(card, 'Prebaked');
  if (pb) pb.checked = false;
  const pbc = goadCardEl(card, 'PrebakedConfig');
  if (pbc) pbc.style.display = 'none';
  const fixedInt = goadCardEl(card, 'FixedInt');
  if (fixedInt) fixedInt.value = '';
  const fixedExt = goadCardEl(card, 'FixedExt');
  if (fixedExt) fixedExt.value = '';
  const rename = goadCardEl(card, 'RenameForest');
  // Re-enabled as well as unticked: the disable is a statement about the lab and
  // the pre-baked flag that were on screen, and both have just been cleared.
  if (rename) { rename.checked = false; rename.disabled = false; }
  const renameHint = goadCardEl(card, 'RenameHint');
  if (renameHint) renameHint.textContent = '';
  const desc = goadCardEl(card, 'VersionDesc');
  if (desc) desc.textContent = '';
  const ext = goadCardEl(card, 'Extensions');
  if (ext) ext.innerHTML = '';
  const err = document.getElementById(card.errId);
  if (err) { err.style.display = 'none'; err.textContent = ''; err.classList.remove('is-warning'); }
}

/**
 * Write a stored GOAD config into the card WITHOUT rebuilding the machine list.
 *
 * That distinction is the point, and it is why both surfaces call this rather
 * than the version-change handler: a stored spec already carries its machines,
 * and those rows may hold golden-image template_vmids that the catalog's base
 * template would overwrite. The other half of the same rule is that the STORED
 * domain names win over the lab's defaults — showing what is stored is what
 * makes an edit an edit rather than a silent rewrite.
 *
 * This is the LOAD half of the round trip; goadCardReadFields is the save half.
 * The two must stay symmetric across extensions, prebaked and fixed_subnet, or a
 * field renders, saves, and comes back empty — which is worse than one that
 * never rendered.
 */
async function goadCardApplyFields(card, goad) {
  if (!goad || !goad.enabled) { goadCardReset(card); return; }
  goadCardStored[card.prefix] = JSON.parse(JSON.stringify(goad));
  goadCardEl(card, 'Enabled').checked = true;
  goadCardEl(card, 'Config').style.display = 'block';
  await goadCardPopulateVersions(card);

  const select = goadCardEl(card, 'Version');
  // `_goadCatalog` is admin-challenges.js's top-level `let`. A top-level `let` is
  // NOT a window property, so it must be read by bare name — window._goadCatalog
  // is always undefined. Classic scripts share one global lexical scope, which is
  // what makes the bare reference resolve across files.
  const version = goad.version || (_goadCatalog && _goadCatalog.default_lab) || 'GOAD-Light';
  // A STORED VERSION THE CATALOG DOES NOT LIST IS A COMPILED LAB NAME, NOT A
  // TYPO — and dropping it silently corrupts the spec. CiAB stamps
  // spec.goad.version with the minted lab name it pushed to the controller
  // (CIAB-…, and now CC-GOADMINI-… for a renamed forest), which is deliberately
  // NOT a GOAD_LABS key. This line used to leave the dropdown on whatever
  // populateVersions had defaulted it to, so opening a CiAB engagement in the
  // template editor and pressing Save wrote version:'GOAD-Light' next to a
  // generated_lab.name of 'CIAB-…' — and resolveGeneratedLab then throws on
  // every later deploy of a lane that had been working. Append it instead, so
  // the round trip is lossless and the author can SEE that this environment is
  // running a lab that was compiled for it.
  if (![...select.options].some(o => o.value === version)) {
    const label = goad.lab || goad.generated_lab || goad.rename_plan
      ? 'compiled for this environment' : 'stored version (not in catalog)';
    select.innerHTML += `<option value="${topoAttr(version)}">${escHtml(version)}`
      + ` — ${label}</option>`;
  }
  select.value = version;

  const compiled = !!(goad.lab || goad.generated_lab || goad.rename_plan);
  for (const suffix of ['Version', 'Domain', 'Child', 'Prebaked']) {
    const el = goadCardEl(card, suffix);
    if (el) el.disabled = compiled;
  }
  goadCardEl(card, 'Password').value = goad.admin_password || 'vagrant';
  goadCardEl(card, 'Kali').checked = goad.include_kali !== false;
  const pb = goadCardEl(card, 'Prebaked');
  if (pb) pb.checked = !!goad.prebaked;
  const pbc = goadCardEl(card, 'PrebakedConfig');
  if (pbc) pbc.style.display = goad.prebaked ? 'block' : 'none';
  const fixedInt = goadCardEl(card, 'FixedInt');
  if (fixedInt) fixedInt.value = (goad.fixed_subnet && goad.fixed_subnet.int) || '';
  const fixedExt = goadCardEl(card, 'FixedExt');
  if (fixedExt) fixedExt.value = (goad.fixed_subnet && goad.fixed_subnet.ext) || '';

  const lab = findGoadLab(select.value);
  goadCardEl(card, 'Domain').value =
    goad.domain || (lab && lab.forestRoot) || 'cybersaguaros.local';
  goadCardEl(card, 'Child').value =
    Object.hasOwn(goad, 'child_subdomain') ? (goad.child_subdomain || '') : ((lab && lab.childSubdomain) || '');

  // `=== true` and not truthiness: the key is written only when true, so
  // anything else in a stored row is a row that predates the opt-in.
  const rename = goadCardEl(card, 'RenameForest');
  if (rename) rename.checked = goad.rename_forest === true;

  await loadGoadExtensionCatalog();
  goadCardRenderExtensions(card, Array.isArray(goad.extensions) ? goad.extensions : []);

  goadCardUpdateDesc(card);
  // Painted AFTER the domain fields, because the ticked hint reads the domain to
  // warn about a reserved TLD. Note this can leave the box CHECKED AND DISABLED
  // on a spec that should never have been stored (rename + pre-baked): showing
  // what is stored is the same rule the domain fields follow, and re-writing it
  // here would be the silent rewrite this whole card exists to stop. The save
  // guards refuse it with a reason instead.
  goadCardPaintRenameHint(card);
  goadCardValidateDomains(card);
}

function goadCardReadFields(card) {
  if (!goadCardOn(card)) return null;
  const stored = goadCardStored[card.prefix] || {};
  const goad = {
    ...JSON.parse(JSON.stringify(stored)),
    enabled: true,
    version: goadCardEl(card, 'Version').value ||
      (_goadCatalog && _goadCatalog.default_lab) || 'GOAD-Light',
    domain: goadCardEl(card, 'Domain').value.trim() || 'cybersaguaros.local',
    // No 'tumamoc' fallback any more. An empty child means "this lab has one
    // domain", which is true of GOAD-Mini, SCCM, NHA and DRACARYS — inventing a
    // child for them is exactly the hardcoded default that put a domain nobody
    // chose into every spec.
    child_subdomain: goadCardEl(card, 'Child').value.trim() || null,
    // 'vagrant', not 'Administrator': the built-in Administrator does NOT stay enabled through
    // sysprep /generalize /oobe, and the Windows template bakes vagrant/vagrant in
    // Administrators precisely so there is an account that survives. goad-deploy.js has always
    // defaulted initialUser to 'vagrant' for this reason -- but this line wrote 'Administrator'
    // into every spec, so that default never applied and every lane authored here handed run.sh
    // an account that cannot log in.
    admin_user: stored.admin_user || 'vagrant',
    admin_password: goadCardEl(card, 'Password').value || 'vagrant',
    include_kali: goadCardEl(card, 'Kali').checked
  };
  const extensions = goadCardReadExtensions(card);
  // Written only when something is ticked, so a challenge authored without
  // extensions posts the same body it posted before this feature existed.
  if (extensions.length) goad.extensions = extensions;
  else delete goad.extensions;
  // Same rule, and here it is load-bearing rather than tidy. The create handler
  // defaults every GOAD spec to cybersaguaros.local/tumamoc whatever the lab is,
  // so `domain !== forestRoot` is true for every stored spec today — a DERIVED
  // trigger would recompile all of them into a forest nobody chose. An absent
  // key cannot: rename_forest exists only where someone ticked the box, and an
  // untouched card posts a byte-identical body.
  const renameForest = goadCardEl(card, 'RenameForest');
  if (renameForest && renameForest.checked) goad.rename_forest = true;
  else delete goad.rename_forest;
  const prebaked = goadCardEl(card, 'Prebaked');
  if (prebaked && prebaked.checked) {
    goad.prebaked = true;
    const int = goadCardEl(card, 'FixedInt').value.trim();
    const ext = goadCardEl(card, 'FixedExt').value.trim();
    // applyPrebakedFixedSubnet THROWS at deploy when `int` is empty, and that is
    // the right place for it: a pre-baked lane built on a per-lane subnet boots,
    // reports active, and is fiction. The field is authored here so it can be.
    goad.fixed_subnet = { int, ext: ext || int };
  } else {
    delete goad.prebaked;
    delete goad.fixed_subnet;
  }
  return goad;
}

// ============================================================================
// GOAD CARD — extensions
// ============================================================================
// `spec.goad.extensions` is a REQUEST TO INSTALL. On a LIVE lane the ticked keys
// are handed to the controller's run.sh as its 5th argument; it layers each
// extension's rendered inventory on top of the lab's and runs
// extensions/<key>/ansible/install.yml — upstream's `install_extension <key>`,
// verbatim. So ticking `elk` places the machine, pins its address, AND installs
// Elasticsearch + Kibana on it, with Sysmon and winlogbeat pushed to every host
// in [domain].
//
// The ONE exception is a pre-baked environment: it clones golden images and runs
// no Ansible at all, so nothing would be installed. That combination is refused
// — topology-validate reports `prebaked-extension` on the canvas, and
// goad-deploy.assertGoadExtensionsRunnable throws before any clone.

/** The ticked extension keys, in catalog order. */
function goadCardReadExtensions(card) {
  return [...document.querySelectorAll('#' + card.prefix + 'GoadExtensions input[data-ext]:checked')]
    .map(el => el.getAttribute('data-ext'));
}

/**
 * Rebuild the checkbox group for the selected lab.
 *
 * `keep` is the selection to preserve across a lab change; anything in it that
 * the new lab cannot take is dropped, which is the only honest thing to do —
 * ws01 has no inventory for NHA, and silently keeping it ticked would put a
 * machine in the AD roster that makes assertGoadRoster fail every deploy.
 *
 * Incompatible entries are rendered DISABLED WITH THE REASON rather than
 * hidden: "why can't I add a workstation to SCCM?" is a question the UI should
 * answer where it is asked. The ok/reason pair is SERVED on the lab row, so
 * compatibility, name collisions and octet collisions have one implementation.
 */
function goadCardRenderExtensions(card, keep) {
  const host = goadCardEl(card, 'Extensions');
  if (!host) return;
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const rows = goadExtensionsForLab(lab);
  const wanted = new Set(keep || []);

  if (!rows.length) {
    host.innerHTML = '<p class="topo-settings-hint" style="margin:0;">Extension catalog unavailable.</p>';
    return;
  }

  host.innerHTML = rows.map(r => {
    const ext = r.ext;
    const on = r.ok && wanted.has(r.key);
    const where = ext.in_lab
      ? `domain-joined · .${ext.ip_octet}`
      : `spec machine · .${ext.ip_octet}`;
    return `<label style="display:flex; gap:0.45rem; align-items:flex-start; margin:0 0 0.35rem 0;` +
      `cursor:${r.ok ? 'pointer' : 'not-allowed'}; opacity:${r.ok ? '1' : '0.55'};">` +
      // The key rides on data-ext and is read back from the element, never
      // interpolated into the handler string: topoAttr encodes a quote as
      // &#39;, which the HTML parser decodes BEFORE the JS runs and breaks the
      // string literal. Same rule the create-status buttons follow.
      `<input type="checkbox" data-ext="${topoAttr(r.key)}"${on ? ' checked' : ''}` +
      `${r.ok ? '' : ' disabled'} onchange="${card.extToggleFn}(this.dataset.ext)"` +
      ` style="width:15px; height:15px; margin-top:0.15rem; cursor:inherit;">` +
      `<span style="font-size:0.78rem; line-height:1.3;">` +
      `<strong>${escHtml(ext.displayName || ext.key)}</strong>` +
      `<span style="color:var(--text-muted);"> — ${escHtml(where)}</span><br>` +
      `<span style="color:var(--text-muted); font-size:0.72rem;">` +
      `${escHtml(r.ok ? (ext.description || '') : r.reason)}</span></span></label>`;
  }).join('');
}

/**
 * Tick / untick one extension. SURGICAL, and that is the whole point.
 *
 * goadCardRebuildFromLab() replaces the machine list WHOLESALE. That is correct
 * for a lab change and catastrophic for an extension tick: it would throw away
 * the canvas layout, every hand-added machine, and every template_vmid the
 * author typed. goadCardOnKaliToggle() is deliberately a push/splice on the SAME
 * array the editor is holding, and this follows it exactly — mutate in place,
 * refresh, never replace.
 */
function goadCardToggleExtension(card, key) {
  if (!goadCardOn(card)) return;
  const ext = findGoadExtension(key);
  if (!ext) return;
  const on = !!document.querySelector(`#${card.prefix}GoadExtensions input[data-ext="${key}"]:checked`);
  const vms = card.getVms();
  const idx = vms.findIndex(v => String(v.name).toLowerCase() === ext.machine.toLowerCase());

  if (on && idx === -1) {
    // Next free offset in the 600000 + n*10000 band, so a tick cannot collide
    // with a row the author already placed (two VMs on one offset clone to the
    // same VMID and the second deploy fails).
    // push, not concat — the editor closes over this array.
    vms.push(buildGoadExtensionRow(ext, goadCardFreeOffset(vms)));

    // ws01 DELIBERATELY DOES NOT CLAIM THE CONSOLE, and this used to.
    //
    // It reads like the right blue-team console — a domain-joined Windows 11
    // analyst box that browses to http://elk:5601 and, being in [domain], is
    // itself instrumented. But a ROSTER machine cannot currently BE a working
    // console, for two independent reasons in the deploy path:
    //
    //   1. Credentials. resolveConsolePlan tags it kind 'spec', and
    //      challenge-lane-deployer only ever resolves real credentials for
    //      kind 'kali' and kind 'extra'. A spec console is handed
    //      { username: null, password: null } — a Guacamole connection that
    //      exists, looks deployed, and cannot be logged into.
    //   2. Address. An in_lab machine carries no ipOctet on purpose (GOAD
    //      addresses it), so the console allocator sees NaN and hands it one
    //      from the .60-.79 console band — while cloneChallengeVm lets the GOAD
    //      MAC win and the machine actually boots at its lab octet (.31). The
    //      console DNAT and the Guac connection then both point at an address
    //      nothing answers.
    //
    // Claiming primary here ALSO silently outranked Kali: resolveConsolePlan
    // tests `specPrimaries.length === 1` BEFORE it tests attackBoxes, so a
    // ticked ws01 took the console away from a Kali box that would have worked.
    // The observed result was a lane whose every machine ran and which no
    // student could reach.
    //
    // So ws01 is what upstream means by it — a TARGET that makes an intrusion
    // cross hosts, instrumented for free by [elk_log:children] domain. Leave the
    // console to Kali or an added workstation. An author may still set
    // console_role by hand in the property panel; validateTopology reports
    // goad-host-console when they do, rather than this file deciding for them.
  } else if (!on && idx !== -1) {
    // splice, not filter — replacing the array would orphan the editor's handle.
    if (vms[idx].console_role === 'primary') {
      Toast.warning('Console cleared', `${ext.machine} was the student console — pick another machine.`);
    }
    vms.splice(idx, 1);
  } else {
    return;   // already in the wanted state; nothing to do and nothing to redraw
  }

  // The name lock set changed, so the editor needs the new list before it can
  // disable the right fields.
  const editor = card.editor();
  if (editor) {
    editor.setGoadHosts(goadCardHostNames(card));
    editor.refresh(vms);
  }
  card.refresh();
}

/**
 * Names whose placement is fixed by the environment rather than by the author.
 *
 * The lab's own hosts, plus the machines contributed by the ticked extensions.
 * Both are NAME CONTRACTS, not labels: prepareGoadMacs matches AD hosts by name,
 * and an extension machine's name is what the golden image's baked agent config
 * and (for the SIEMs) its `<name>.cybercore.lan` record are built around. A
 * rename silently converts a domain controller into an unrecognised machine, or
 * points every winlogbeat in the lane at a host that no longer answers.
 *
 * The editor turns this into `goadHosts`, which disables the name field, draws
 * the double border, and also disables Rename/Remove in the context menu.
 */
function goadCardHostNames(card) {
  if (!goadCardOn(card)) return null;
  const select = goadCardEl(card, 'Version');
  const lab = findGoadLab(select && select.value);
  const definition = goadCardStored[card.prefix]?.lab || lab;
  const names = (definition?.vms || []).map(v => v.name);
  return names.concat(goadExtensionMachineNames(goadCardReadExtensions(card)));
}

// ============================================================================
// DESIGNER — GOAD card (the topo half of the shared implementation)
// ============================================================================
// Everything below is a thin binding: the descriptor naming the Designer's half
// of the differences, plus the handlers admin.html's inline attributes call. No
// behaviour lives here — if you are about to add some, add it above, so the
// template editor gets it too.

/**
 * The Designer's card descriptor.
 *
 * Rebuilt on every call rather than cached, because `topoVms` is REPLACED (not
 * mutated) by a wholesale rebuild and a captured reference would go stale the
 * first time the author changed lab.
 */
function topoGoadCard() {
  return {
    prefix: 'topo',
    errId: 'topoErrGoad',
    extToggleFn: 'onTopoExtensionToggle',
    getVms: () => topoVms,
    setVms: (vms) => { topoVms = vms; },
    editor: () => topoDesigner,
    refresh: () => renderTopoVmTable(true),
    mount: () => topoDesignMount(),
    getScheme: () => topoScheme(),
    // The Designer authors a NEW challenge, so its scheme is still a choice.
    applyScheme: (scheme) => {
      document.getElementById('topoSubnetScheme').value = scheme;
      onTopoSchemeChange();
    },
    clearNetwork: () => { topoNetwork = null; }
  };
}

async function populateTopoGoadVersions() { return goadCardPopulateVersions(topoGoadCard()); }
function updateTopoGoadDesc() { goadCardUpdateDesc(topoGoadCard()); }
async function onTopoGoadToggle() { return goadCardOnToggle(topoGoadCard()); }

// A version change RESETS both domain fields from the lab and only then
// rebuilds the machine list. goadCardOnVersionChange() does both, in that
// order, for both cards; these three wrappers are the Designer's end of that
// one chain, kept together so the order is readable here too.
function onTopoGoadVersionChange() { goadCardOnVersionChange(topoGoadCard()); }
function resetTopoGoadDomainsFromLab() { goadCardResetDomainsFromLab(topoGoadCard()); }
function topoRebuildFromGoadLab() { goadCardRebuildFromLab(topoGoadCard()); }

function validateTopoGoadDomains() { return goadCardValidateDomains(topoGoadCard()); }
function onTopoGoadDomainInput() { goadCardOnDomainInput(topoGoadCard()); }
function onTopoGoadKaliToggle() { goadCardOnKaliToggle(topoGoadCard()); }
function onTopoGoadPrebakedToggle() { goadCardOnPrebakedToggle(topoGoadCard()); }
function onTopoGoadRenameForestToggle() { goadCardOnRenameForestToggle(topoGoadCard()); }
function resetTopoGoadFields() { goadCardReset(topoGoadCard()); }
async function applyTopoGoadFields(goad) { return goadCardApplyFields(topoGoadCard(), goad); }
function readTopoGoadFields() { return goadCardReadFields(topoGoadCard()); }
function readTopoGoadExtensions() { return goadCardReadExtensions(topoGoadCard()); }
function renderTopoGoadExtensions(keep) { goadCardRenderExtensions(topoGoadCard(), keep); }
function onTopoExtensionToggle(key) { goadCardToggleExtension(topoGoadCard(), key); }
function topoGoadHostNames() { return goadCardHostNames(topoGoadCard()); }

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
      ${topoConsoleCell(vm, i)}
    </div>`).join('');
}

/**
 * The student-console radio for one table row.
 *
 * The canvas property panel has had this picker for a while; the table has not,
 * so the only way to see which machine students open was to click every node in
 * turn. A radio COLUMN answers it at a glance — the same affordance the template
 * editor already offers (setTemplateConsolePrimary, admin-challenges.js:773) and
 * the CLE deploy modal's `STUDENT CONSOLE` chip.
 */
function topoConsoleCell(vm, i) {
  const on = vm.console_role === 'primary';
  // GOAD's ELK is headless Ubuntu Server: no desktop, no xrdp. Making it the
  // student console produces a lane that deploys clean and hands the student a
  // Guacamole session that connects to nothing. Say so HERE, where the choice is
  // made, rather than letting it be discovered after a deploy.
  const headless = String(vm.role || '').toLowerCase() === 'siem';
  const hint = on && headless
    ? '<div style="font-size:0.68rem; color:var(--warning); margin-top:0.2rem;">' +
      'A SIEM image is headless — the GOAD ELK box is Ubuntu Server with no desktop and no xrdp, so it ' +
      'cannot ' +
      'serve an RDP console as baked. ws01 (or Kali) is the machine an analyst actually works from; the ' +
      'SIEM is a web app they browse to.</div>'
    : '';
  return '<div style="margin-top:0.5rem; display:flex; align-items:center; gap:0.5rem; flex-wrap:wrap;">' +
    `<label style="display:flex; align-items:center; gap:0.4rem; font-size:0.75rem; cursor:pointer; margin:0;">` +
    `<input type="radio" name="topoConsolePrimary" ${on ? 'checked' : ''} ` +
    `onclick="setTopoConsolePrimary(${i})" style="cursor:pointer;">` +
    '<span>Student console <span style="color:var(--text-muted);">— the machine they open</span></span>' +
    `</label>${hint}</div>`;
}

/**
 * Exactly one machine is the student console.
 *
 * A radio group rendered over an array does not enforce that on the DATA — the
 * browser only clears the other INPUTS — so the previous holder is cleared here,
 * or a spec saves with two primaries and resolveConsolePlan throws at deploy
 * time. Clicking the checked radio again clears the designation, which is the
 * only way back to "no console machine". Same contract as
 * setTemplateConsolePrimary and the canvas property panel's select.
 */
function setTopoConsolePrimary(idx) {
  const wasPrimary = topoVms[idx] && topoVms[idx].console_role === 'primary';
  topoVms.forEach((vm, i) => {
    if (i === idx && !wasPrimary) vm.console_role = 'primary';
    else if (vm.console_role === 'primary') delete vm.console_role;
  });
  // The canvas paints a '▸ student console' badge off this field, so it has to
  // hear about a change made in the table.
  if (topoDesigner) topoDesigner.refresh(topoVms);
  renderTopoVmTable(true);
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
  // The AD naming rules, client-side. The create handler runs the SAME rulebook
  // (src/utils/ad-domain-rules.js) and 400s on an error, so this only moves the
  // message from a toast after the round trip into the field before it — but a
  // domain typo otherwise costs a VXLAN reservation attempt to discover.
  const domains = validateTopoGoadDomains();
  domains.errors.forEach(m => problems.push({ field: 'goad', message: m }));
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
