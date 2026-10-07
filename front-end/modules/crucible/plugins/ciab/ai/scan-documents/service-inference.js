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

const { parseServiceEntry } = require('./vuln-knowledge');

// ─── WEB FACTS ─────────────────────────────────────────────────────────────
/**
 * The contract the vuln-app compiler fills in, and the one part of a scan
 * target that is knowledge rather than guesswork.
 *
 * Everything below this section is guesswork by construction: a profile asset
 * is {hostname, ip, subnet, role, os, function, critical} and nothing else, so
 * the only available answer to "what is listening here" is "what would a box
 * called WEB-01 usually run". That guess resolves through PORT_DEFAULTS, which
 * says every :80 and :443 is Apache httpd 2.4.52 — so every web host in every
 * profile gets the same banner, a TLS listener it never opened, and the
 * POODLE / TLS-1.0 findings that come with one.
 *
 * What actually deploys on a lane's web host is an LLM-authored container —
 * PHP, Flask or Express — bound to ONE port, with NO TLS listener at all,
 * serving the handful of routes the model invented. A student who runs `nmap`
 * against the lane is then reading about a different company than the one they
 * were handed on paper, which is the most expensive kind of defect this
 * exercise can have.
 *
 * `asset.web_facts` closes that gap. It is written by the compiler that builds
 * the vuln app — the only component that knows the base image, the bound ports
 * and the route table — and when present it OVERRIDES inference for that
 * host's web surface: banner, port set, TLS reality, and which URLs a report is
 * allowed to name.
 *
 *   asset.web_facts = {
 *     product:  'nginx',          // spelled the way nmap -sV names it
 *     version:  '1.24.0',         // '' when the image pins no version
 *     ports:    [80],             // every TCP port the web server really binds
 *     tls: {
 *       enabled:   false,         // true ONLY if a TLS listener really exists
 *       port:      443,           // which of `ports` terminates TLS
 *       protocols: ['TLSv1.2']    // versions really offered — gates POODLE/TLS 1.0
 *     },
 *     paths: ['/', '/login']      // routes that really resolve
 *   }
 *
 * SCOPE IS THE WEB SURFACE ONLY. A fact block says nothing about the host's
 * SSH or RDP — the compiler knows the container, not the VM underneath it — so
 * those keep coming from inference and are merged in around the web ports.
 *
 * `paths` is a flat route list and is deliberately the weakest field: a ZAP
 * injection alert wants to name the parameter it fired on, not just the route.
 * When that lands it should grow to {path, params: []} entries rather than a
 * parallel array, so a route and its parameters cannot drift apart.
 *
 * ABSENT MEANS ABSENT. An asset with no web_facts renders exactly as it did
 * before this contract existed — test/ciab-web-facts.test.js pins the
 * inference-only documents byte for byte.
 */

// Canonical protocol tokens: sslv2, sslv3, tlsv1.0 … tlsv1.3. Compilers spell
// these half a dozen ways ('TLS 1.0', 'tls1.0', 'TLSv1'), and the gate that
// decides whether a POODLE finding is honest cannot afford a spelling miss.
function normalizeTlsProtocol(raw) {
  const t = String(raw == null ? '' : raw).toLowerCase().replace(/[\s_-]+/g, '');
  const m = t.match(/^(ssl|tls)v?(\d+)(?:\.(\d+))?$/);
  if (!m) return t; // unrecognized token passes through verbatim; it just won't match a gate
  const [, family, major, minor] = m;
  return family === 'ssl' ? `sslv${major}` : `tlsv${major}.${minor || '0'}`;
}

function toPort(value) {
  const n = parseInt(value, 10);
  return Number.isFinite(n) && n > 0 && n < 65536 ? n : null;
}

/**
 * Read and normalize asset.web_facts. Hand-rolled, like every other validator
 * in this repo — there is no schema library here.
 *
 * @returns {null|{product:string, version:string, ports:number[],
 *                 tls:{enabled:boolean, port:number|null, protocols:string[]},
 *                 paths:string[]}}
 *   null means "no facts", and every caller must then behave exactly as it did
 *   before the contract existed.
 */
function readWebFacts(asset) {
  const raw = asset && (asset.web_facts || asset.webFacts);
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  const ports = [];
  if (Array.isArray(raw.ports)) {
    for (const entry of raw.ports) {
      const p = toPort(entry);
      if (p && !ports.includes(p)) ports.push(p);
    }
  }
  // A fact block with no usable listener describes nothing. Falling back to
  // inference is the safer failure: silently deleting the host's entire web
  // surface would bury a malformed compiler output instead of showing it.
  if (ports.length === 0) return null;

  const tlsIn = raw.tls && typeof raw.tls === 'object' ? raw.tls : {};
  // Strict === true. A compiler that left `enabled` undefined has not asserted
  // a TLS listener, and "probably TLS" is precisely what put POODLE findings on
  // hosts that never opened 443.
  const tlsEnabled = tlsIn.enabled === true;
  const protocols = Array.isArray(tlsIn.protocols)
    ? tlsIn.protocols.map(normalizeTlsProtocol).filter(Boolean)
    : [];
  let tlsPort = null;
  if (tlsEnabled) {
    tlsPort = toPort(tlsIn.port) || (ports.includes(443) ? 443 : ports[ports.length - 1]);
    // A declared TLS listener implies its port is open even if `ports` omitted it.
    if (!ports.includes(tlsPort)) ports.push(tlsPort);
  }
  ports.sort((a, b) => a - b);

  const paths = [];
  if (Array.isArray(raw.paths)) {
    for (const entry of raw.paths) {
      const p = String(entry == null ? '' : entry).trim();
      if (!p) continue;
      const abs = p.startsWith('/') ? p : `/${p}`;
      if (!paths.includes(abs)) paths.push(abs);
    }
  }
  // Every HTTP listener answers on '/', so the root is the one route a fact
  // block never has to spell out. Anything else must be declared before a
  // report is allowed to link to it.
  if (!paths.includes('/')) paths.unshift('/');

  return {
    product: String(raw.product == null ? '' : raw.product).trim(),
    version: String(raw.version == null ? '' : raw.version).trim(),
    ports,
    tls: { enabled: tlsEnabled, port: tlsPort, protocols },
    paths
  };
}

/** Does `port` really terminate TLS according to these facts? */
function isTlsPort(facts, port) {
  return !!(facts && facts.tls.enabled && facts.tls.port === port);
}

// The "port/Service" tokens the facts assert, in the format the rest of the
// pipeline parses. HTTPS is claimed ONLY for a port that really terminates TLS.
function webServiceTokens(facts) {
  return facts.ports.map(p => `${p}/${isTlsPort(facts, p) ? 'HTTPS' : 'HTTP'}`);
}

// Replace the web half of a service list with the facts, leaving everything
// else (SSH, RDP, SMB …) where inference put it — see SCOPE above.
function applyWebFacts(services, facts) {
  const kept = services.filter(s => {
    const n = parseServiceEntry(s).normalized;
    return n !== 'http' && n !== 'https';
  });
  return kept.concat(webServiceTokens(facts));
}

// ─── inference ─────────────────────────────────────────────────────────────

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

// The pre-facts derivation, unchanged. It is its own function so the facts
// branch above reads as a preference rather than as an edit to the guesswork —
// nothing here may change behaviour for an asset that carries no facts.
function inferByHeuristics(asset) {
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

/**
 * @param {object} asset — profile asset: { hostname, os, function, role, ... }
 * @returns {string[]} services in "port/Service" format (parseable by
 *   vuln-knowledge.js), or [] if nothing about this asset warrants a guess.
 *
 * web_facts beat BOTH inference and an explicitly declared `services` list:
 * a declared list is still someone's description of the host, while the facts
 * are what the compiler is about to build.
 */
function inferServices(asset) {
  const base = inferByHeuristics(asset);
  const facts = readWebFacts(asset);
  return facts ? applyWebFacts(base, facts) : base;
}

module.exports = { inferServices, readWebFacts, isTlsPort, normalizeTlsProtocol };
