/**
 * Vuln-Script Resolver (Phase 1)
 *
 * Given a wanted {service, version, os_family, role}, score each vuln_scripts
 * row and return the best match. Pure function over a pre-fetched catalog —
 * caller is responsible for the DB query.
 *
 * Phase 1 scores using only existing columns (services_exposed, os_target,
 * category). Phase 2 will add service_name/service_version/role_tags columns
 * and upgrade the ranking; the API shape here stays the same.
 */

function lc(v) {
  return String(v || '').trim().toLowerCase();
}

// OS family → os_target value stored in vuln_scripts.
function familyToOsTarget(family) {
  const f = lc(family);
  if (f === 'windows_client' || f === 'windows_server') return 'windows';
  return f || 'windows';
}

/**
 * Extract the service tokens from a row's services_exposed JSONB array.
 * Entries look like "445/SMB" or "8080/WebGoat" — we want the part after the slash.
 */
function rowServices(row) {
  const list = Array.isArray(row.services_exposed) ? row.services_exposed
             : (typeof row.services_exposed === 'string' ? safeParseArray(row.services_exposed) : []);
  return list.map(s => {
    const str = String(s || '');
    const idx = str.indexOf('/');
    return idx === -1 ? lc(str) : lc(str.slice(idx + 1));
  });
}

function safeParseArray(s) {
  try { const v = JSON.parse(s); return Array.isArray(v) ? v : []; } catch { return []; }
}

/**
 * Score a row against a {service, os_family} request.
 *   100 — Phase 2: exact service + version + os_version (not yet — requires new columns)
 *    80 — service match + os family match
 *    60 — service match, os_target='windows' (the common case — matches any Windows)
 *    40 — service match only (different OS family)
 *     0 — no service match (skip)
 *
 * Init-setup / life-artifacts / defense-evasion are returned separately — they
 * have no services_exposed but are usually added alongside service scripts.
 */
function scoreRow(row, want) {
  if (row.is_active === false) return 0;
  const wantSvc = lc(want.service);
  const wantOsTarget = familyToOsTarget(want.os_family);
  const svcs = rowServices(row);
  const osTarget = lc(row.os_target);

  if (!svcs.includes(wantSvc)) return 0;

  if (osTarget === wantOsTarget) return 80;
  if (osTarget === 'windows') return 60;
  return 40;
}

/**
 * @param {object} want      { service, version, os_family, role }
 * @param {Array}  catalog   vuln_scripts rows
 * @returns {object|null}    { slug, name, confidence, match_type, row_id } or null
 */
function findScript(want, catalog) {
  let best = null;
  let bestScore = 0;
  for (const row of catalog) {
    const s = scoreRow(row, want);
    if (s > bestScore) {
      bestScore = s;
      best = row;
    }
  }
  if (!best) return null;
  return {
    slug: best.slug,
    name: best.name,
    confidence: bestScore,
    match_type: bestScore >= 80 ? 'exact_os' : (bestScore >= 60 ? 'windows_generic' : 'weak'),
    row_id: best.id
  };
}

/**
 * For a single VM with a set of service hints, return:
 *   { required: [slug, ...], missing: [service, ...] }
 * Always seeds 'init-setup' first (common bootstrap) if present in catalog.
 */
function resolveScriptsForVm(vm, catalog) {
  const required = [];
  const missing = [];
  const seen = new Set();

  // Always include init-setup if available.
  const initSetup = catalog.find(r => r.slug === 'init-setup' && r.is_active !== false);
  if (initSetup) { required.push('init-setup'); seen.add('init-setup'); }

  const hints = Array.isArray(vm.suggested_script_services) ? vm.suggested_script_services : [];
  for (const h of hints) {
    const match = findScript({
      service: h.service,
      version: h.version,
      os_family: vm.os_family,
      role: vm.role
    }, catalog);
    if (match && !seen.has(match.slug)) {
      required.push(match.slug);
      seen.add(match.slug);
    } else if (!match) {
      missing.push({ service: h.service, version: h.version });
    }
  }

  // Seed 'life-artifacts' on endpoints by default (user simulation) if present.
  const lifeArtifacts = catalog.find(r => r.slug === 'life-artifacts' && r.is_active !== false);
  if (lifeArtifacts && !seen.has('life-artifacts') && (vm.role === 'workstation' || vm.role === 'laptop')) {
    required.push('life-artifacts');
    seen.add('life-artifacts');
  }

  return { required, missing };
}

module.exports = {
  findScript,
  resolveScriptsForVm,
  scoreRow,
  familyToOsTarget
};
