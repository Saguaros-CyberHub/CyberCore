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
 * Score a row against a {service, os_family, prefer_type} request.
 *
 *   Base scores (service + OS match):
 *     80  service match + exact OS family
 *     60  service match + os_target='windows' (the common case)
 *     40  service match only (different OS family)
 *      0  no service match (skip)
 *
 *   Type bonus (when prefer_type is set):
 *    +20  row.script_type === prefer_type
 *     -5  row.script_type !== prefer_type (light demotion, doesn't zero-out)
 *
 * Net effect: if the caller wants 'baseline', a baseline + windows-generic
 * row (60+20=80) beats a vulnerable + exact-family row (80-5=75).
 */
// Categories that should never be auto-picked by the intake synthesizer.
// "Composite Lab" scripts deploy a whole opinionated challenge lab (multiple
// services + deliberate weaknesses in one shot) — they are admin-driven
// manual picks only. Admins can still add them via the script picker modal.
const AUTO_PICK_BLOCKED_CATEGORIES = new Set(['composite lab']);

function scoreRow(row, want) {
  if (row.is_active === false) return 0;
  if (AUTO_PICK_BLOCKED_CATEGORIES.has(lc(row.category))) return 0;

  const wantSvc = lc(want.service);
  const wantOsTarget = familyToOsTarget(want.os_family);
  const svcs = rowServices(row);
  const osTarget = lc(row.os_target);

  if (!svcs.includes(wantSvc)) return 0;

  let score;
  if (osTarget === wantOsTarget) score = 80;
  else if (osTarget === 'windows') score = 60;
  else score = 40;

  if (want.prefer_type) {
    const rowType = lc(row.script_type) || 'vulnerable';
    if (rowType === lc(want.prefer_type)) score += 20;
    else                                   score -= 5;
  }

  return score;
}

/**
 * @param {object} want      { service, version, os_family, role, prefer_type? }
 *                           prefer_type defaults to 'baseline' (caller can override to 'vulnerable')
 * @param {Array}  catalog   vuln_scripts rows
 * @returns {object|null}    { slug, name, confidence, match_type, script_type, row_id } or null
 */
function findScript(want, catalog) {
  const wantWithDefault = { prefer_type: 'baseline', ...want };
  let best = null;
  let bestScore = 0;
  for (const row of catalog) {
    const s = scoreRow(row, wantWithDefault);
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
    script_type: best.script_type || 'vulnerable',
    row_id: best.id
  };
}

/**
 * For a single VM with a set of service hints, return:
 *   { required: [slug, ...], missing: [service, ...] }
 *
 * Always seeds the bootstrap ('init-setup') first and a user-simulation
 * script on endpoints. Both prefer baseline variants — the bootstrap
 * catalog may have only one option (init-setup) so prefer_type only
 * affects ties; the simulation lookup ('life-artifacts' or 'win-life-artifacts')
 * picks the first baseline-tagged match it finds.
 *
 * @param {object} opts  { prefer_type: 'baseline'|'vulnerable' }  default 'baseline'
 */
function resolveScriptsForVm(vm, catalog, opts = {}) {
  const preferType = opts.prefer_type || 'baseline';
  const required = [];
  const missing = [];
  const seen = new Set();

  // Always include a bootstrap. Prefer init-setup; fall back to any baseline-tagged bootstrap.
  const bootstrap = catalog.find(r => r.slug === 'init-setup' && r.is_active !== false)
                  || catalog.find(r => lc(r.category) === 'initial setup' && lc(r.script_type) === 'baseline' && r.is_active !== false);
  if (bootstrap) { required.push(bootstrap.slug); seen.add(bootstrap.slug); }

  const hints = Array.isArray(vm.suggested_script_services) ? vm.suggested_script_services : [];
  for (const h of hints) {
    const match = findScript({
      service: h.service,
      version: h.version,
      os_family: vm.os_family,
      role: vm.role,
      prefer_type: preferType
    }, catalog);
    if (match && !seen.has(match.slug)) {
      required.push(match.slug);
      seen.add(match.slug);
    } else if (!match) {
      missing.push({ service: h.service, version: h.version });
    }
  }

  // Seed a user-simulation script on endpoints. Accept either slug convention.
  if (vm.role === 'workstation' || vm.role === 'laptop') {
    const sim = catalog.find(r =>
      (r.slug === 'life-artifacts' || r.slug === 'win-life-artifacts')
      && r.is_active !== false
    );
    if (sim && !seen.has(sim.slug)) { required.push(sim.slug); seen.add(sim.slug); }
  }

  return { required, missing };
}

module.exports = {
  findScript,
  resolveScriptsForVm,
  scoreRow,
  familyToOsTarget
};
