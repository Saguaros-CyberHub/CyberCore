// ============================================================================
// GOAD EXTENSIONS — catalog fetch, per-lab filter, canvas row builder
// ============================================================================
// Mirrors admin-challenges.js's loadGoadCatalog/findGoadLab pair exactly: one
// cached fetch, one lookup by key. Kept in its own file because the Topology
// Designer is its only consumer and admin-challenges.js is already the largest
// file on the page.
//
// ── Classic script, shared global scope ─────────────────────────────────────
// Every binding here is prefixed `goadExt`/`_goadExt` for the same reason
// admin-topology.js prefixes everything `topo`: a top-level `let` that collides
// with one in another admin-*.js is a SyntaxError that silently kills the whole
// file at parse time.
//
// ── THE SHAPE TRAP ──────────────────────────────────────────────────────────
// buildGoadExtensionRow emits `services` / `default_scripts` as ARRAYS. The
// create form's buildGoadVmRows (admin-challenges.js:166) emits them as comma
// STRINGS, and topology-seed.js:159-163 calls that mismatch out explicitly: the
// canvas property panel does `(vm.services || []).join(', ')`, so handing it a
// string turns "80/HTTP" into "8,0,/,H,T,T,P". These rows go to the canvas, so
// they take the canvas shape — the same one fromGoadLab produces.
// ============================================================================

let _goadExtCatalog = null;

/**
 * GET /goad/extensions, cached for the page's life.
 *
 * Falls back to an EMPTY catalog rather than throwing: the extensions block is
 * additive, and a Designer that cannot author extensions is far better than a
 * Designer that will not load. Same contract loadGoadCatalog() honours.
 */
async function loadGoadExtensionCatalog() {
  if (_goadExtCatalog) return _goadExtCatalog;
  try {
    _goadExtCatalog = await api('GET', '/goad/extensions');
  } catch (e) {
    console.error('Failed to load the GOAD extension catalog', e);
    _goadExtCatalog = { extensions: [], infra_ip_octets: {} };
  }
  return _goadExtCatalog;
}

/** One extension by key, or undefined. Catalog must already be loaded. */
function findGoadExtension(key) {
  return (_goadExtCatalog?.extensions || []).find(e => e.key === key);
}

/**
 * The extensions offerable for a lab, each annotated with whether it may be
 * ticked and why not.
 *
 * The `ok`/`reason` pair is SERVED on the lab row (lab-templates.js builds it
 * from goadDeploy.extensionsForLab) rather than re-derived here, so
 * compatibility, name collisions and octet collisions have exactly one
 * implementation. A lab row from an older server has no `extensions` key at
 * all; that degrades to "everything offerable", which is the pre-existing
 * behaviour and never worse than hiding a machine with no explanation.
 *
 * @param {object} lab  a row from GET /goad/labs (findGoadLab(key))
 * @returns {Array<{key, ext, ok, reason}>}
 */
function goadExtensionsForLab(lab) {
  const perLab = (lab && Array.isArray(lab.extensions)) ? lab.extensions : null;
  return (_goadExtCatalog?.extensions || []).map(ext => {
    const row = perLab ? perLab.find(e => e.key === ext.key) : null;
    return {
      key: ext.key,
      ext,
      ok: row ? !!row.ok : true,
      reason: row ? row.reason : null
    };
  });
}

/** The machine names the selected extensions contribute, lowercased for matching. */
function goadExtensionMachineNames(keys) {
  return (keys || [])
    .map(k => findGoadExtension(k))
    .filter(Boolean)
    .map(e => e.machine);
}

/**
 * A canvas row for one extension machine.
 *
 * @param {object} ext     a catalog entry from GET /goad/extensions
 * @param {number} offset  the vm_offset to claim (caller owns the 600000 band)
 */
function buildGoadExtensionRow(ext, offset) {
  const row = {
    name: ext.machine,
    role: ext.role,
    os: ext.os || '',
    // null for the SIEM images: they are registered per site, so the author
    // supplies the golden-image VMID. validateCreateState blocks Create until
    // every machine has one, which is the right place to notice.
    template_vmid: ext.template_vmid || null,
    type: 'qemu',
    vm_offset: offset,
    // ARRAYS. See the header — this is the canvas shape, not the form's.
    default_scripts: [],
    services: []
  };

  // Only the machines that are NOT in the AD roster carry an explicit octet.
  // An `in_lab` machine (ws01) is addressed by the GOAD layer from the lab
  // definition, and resolveSpecAddressing skips any machine goadMacs already
  // names — so an ipOctet here would be dead data that reads as authoritative.
  if (!ext.in_lab && ext.ip_octet) row.ipOctet = ext.ip_octet;

  // The stable in-lane name a baked agent config points at (`elk.cybercore.lan`).
  // NOTE: buildSpecVm's whitelist does not carry `dns_aliases` today, so this
  // survives PUT /lab-templates/:id (whole-object merge) but is dropped by
  // POST /create-lab. Authored here regardless, because the value is correct and
  // the alternative is authoring nothing and forgetting why.
  if (Array.isArray(ext.dns_aliases) && ext.dns_aliases.length) {
    row.dns_aliases = ext.dns_aliases.slice();
  }
  return row;
}
