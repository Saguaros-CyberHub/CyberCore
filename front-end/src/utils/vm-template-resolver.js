/**
 * VM Template Resolver
 *
 * Given a normalized VM spec ({os_family, os_version, role}), pick the best
 * template from a pre-fetched vm_template_catalog array. Pure function —
 * caller is responsible for the DB query.
 *
 * Four-rung fallback ladder:
 *   1. exact (os_family + os_version match)
 *   2. fuzzy_version (os_family match, os_version differs or missing)
 *   3. family_only (os_family match, no version info on either side)
 *   4. phantom (no family match — return null, caller renders as phantom asset)
 */

function lc(v) {
  return String(v || '').trim().toLowerCase();
}

/**
 * @param {object} input  { os_family, os_version, role }
 * @param {Array}  catalog  vm_template_catalog rows (active only)
 * @returns {object} { template_vmid, node, os_name, os_version, match_type, row } or null
 */
function resolveTemplate(input, catalog) {
  const family = lc(input.os_family);
  const version = lc(input.os_version);
  const role = lc(input.role);

  if (!family) return null;

  const candidates = catalog.filter(r => lc(r.os_family) === family && r.is_active !== false);
  if (candidates.length === 0) return null;

  // Rung 1: exact version match (when both sides have a version).
  if (version) {
    const exact = candidates.filter(r => lc(r.os_version) === version);
    if (exact.length) {
      const row = pickPreferred(exact, role);
      return formatMatch(row, 'exact');
    }
  }

  // Rung 2: fuzzy — family match but either side missing version, or version differs.
  const fuzzy = candidates.filter(r => r.os_version && version && lc(r.os_version) !== version);
  if (fuzzy.length && version) {
    const row = pickPreferred(fuzzy, role);
    return formatMatch(row, 'fuzzy_version');
  }

  // Rung 3: family only — caller didn't specify version, or catalog rows have null versions.
  const row = pickPreferred(candidates, role);
  return formatMatch(row, 'family_only');
}

/**
 * Among rows that share a family-level match, prefer:
 *   - preferred=true
 *   - role_hints intersects caller's role
 *   - most recent created_at (fallback)
 */
function pickPreferred(rows, role) {
  const withRoleMatch = role
    ? rows.filter(r => Array.isArray(r.role_hints) && r.role_hints.map(lc).includes(role))
    : [];
  const pool = withRoleMatch.length ? withRoleMatch : rows;

  const preferred = pool.filter(r => r.preferred !== false);
  const finalPool = preferred.length ? preferred : pool;

  return finalPool.slice().sort((a, b) => {
    const ta = a.created_at ? new Date(a.created_at).getTime() : 0;
    const tb = b.created_at ? new Date(b.created_at).getTime() : 0;
    return tb - ta;
  })[0];
}

function formatMatch(row, match_type) {
  if (!row) return null;
  return {
    template_vmid: row.template_vmid,
    node: row.node || 'cyberhub-node-5',
    os_name: row.os_name,
    os_version: row.os_version,
    match_type,
    row_id: row.id
  };
}

/**
 * Batch resolver — convenience wrapper for the common "resolve N VMs against
 * one fetched catalog" pattern.
 */
function resolveTemplates(inputs, catalog) {
  return inputs.map(input => ({
    input,
    match: resolveTemplate(input, catalog)
  }));
}

module.exports = {
  resolveTemplate,
  resolveTemplates
};
