/**
 * service-inference.js — Guesses a plausible services/port list for a scan
 * target when the profile itself doesn't declare one.
 *
 * Profile generation currently only produces {hostname, os, function, role}
 * per asset — no port/service list. This module fills that gap so the
 * fallback scan documents (nmap/nessus/zap) have something real to show,
 * using the same "what would this role typically run" reasoning a human
 * would apply. It intentionally favors under-inferring over inventing
 * implausible services: each asset is matched against the single strongest
 * signal in its hostname/function text, not every possible keyword hit.
 */

function isWindows(os) {
  return /windows/i.test(os || '');
}
function isLinux(os) {
  return /linux|ubuntu|debian|rhel|rocky|centos|alma/i.test(os || '');
}

// Ordered rules, most specific first. `services` is either a fixed array or
// a function of the asset's OS string (for roles that differ by platform).
const RULES = [
  {
    test: (text) => /domain controller|active directory|\bdc\b/.test(text),
    services: ['53/DNS', '88/Kerberos', '389/LDAP', '445/SMB', '3389/RDP']
  },
  {
    test: (text) => /\bsql\b|database server|\bdb\b/.test(text),
    services: (os) => isWindows(os)
      ? ['1433/MSSQL', '445/SMB', '3389/RDP']
      : ['5432/PostgreSQL', '22/SSH']
  },
  {
    test: (text) => /exchange|mail server|\bmail\b|\bsmtp\b/.test(text),
    services: ['25/SMTP', '443/HTTPS', '993/IMAPS']
  },
  {
    test: (text) => /file server|file share|file services|\bfs\b/.test(text),
    services: ['445/SMB', '3389/RDP']
  },
  {
    test: (text) => /web server|\biis\b|application server|\bapp\b|web app/.test(text),
    services: (os) => isWindows(os)
      ? ['80/HTTP', '443/HTTPS', '3389/RDP']
      : ['80/HTTP', '443/HTTPS', '22/SSH']
  },
  {
    test: (text) => /print/.test(text),
    services: (os) => isWindows(os) ? ['445/SMB', '3389/RDP'] : ['631/IPP']
  }
];

// Firewalls/switches/routers typically expose an HTTPS admin UI + SSH — not
// the same service catalog as a server, so handled separately from RULES.
function inferNetworkDeviceServices(os) {
  if (!os) return [];
  return ['443/HTTPS', '22/SSH'];
}

/**
 * @param {object} asset — profile asset: { hostname, os, function, role, ... }
 * @returns {string[]} services in "port/Service" format (parseable by
 *   vuln-knowledge.js), or [] if nothing about this asset warrants a guess.
 */
function inferServices(asset) {
  if (Array.isArray(asset.services) && asset.services.length > 0) return asset.services;

  const role = String(asset.role || '').toLowerCase();
  if (role === 'network') return inferNetworkDeviceServices(asset.os);

  const text = `${asset.hostname || ''} ${asset.function || ''}`.toLowerCase();
  for (const rule of RULES) {
    if (rule.test(text)) {
      return typeof rule.services === 'function' ? rule.services(asset.os) : rule.services;
    }
  }

  // No narrative signal — fall back to "what a bare server of this OS usually exposes."
  if (isWindows(asset.os)) return ['445/SMB', '3389/RDP'];
  if (isLinux(asset.os)) return ['22/SSH'];

  return [];
}

module.exports = { inferServices };
