/** Metadata-only GOAD identity planner. The lane controller owns all GOAD source and compilation. */
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { publicDomainOf, netbiosForDomain } = require('./ad-domain-rules');
const BASE_LABS_DIR = path.join(__dirname, '..', 'data', 'goad-base-labs');
const EXTENSIONS_DIRNAME = '_extensions';
const REBRAND_SCHEMA_VERSION = 2;
const MAX_HOSTNAME = 15;
const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;
const LAB_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const REBRAND_CODES = Object.freeze({
  "UNUSABLE_DOMAIN": "GOAD_REBRAND_UNUSABLE_DOMAIN",
  "SAME_DOMAIN": "GOAD_REBRAND_SAME_DOMAIN",
  "NO_BASE_TREE": "GOAD_REBRAND_NO_BASE_TREE",
  "NOT_REQUESTED": "GOAD_REBRAND_NOT_REQUESTED",
  "SOURCE_UNAVAILABLE": "GOAD_REBRAND_SOURCE_UNAVAILABLE",
  "SOURCE_MISMATCH": "GOAD_REBRAND_SOURCE_MISMATCH",
  "MULTI_DOMAIN": "GOAD_REBRAND_MULTI_DOMAIN",
  "FOREIGN_DOMAIN": "GOAD_REBRAND_FOREIGN_DOMAIN",
  "FOREIGN_DN": "GOAD_REBRAND_FOREIGN_DN",
  "FOREIGN_PRINCIPAL": "GOAD_REBRAND_FOREIGN_PRINCIPAL",
  "FOREIGN_LAB_NAME": "GOAD_REBRAND_FOREIGN_LAB_NAME",
  "UNMAPPED_HOST": "GOAD_REBRAND_UNMAPPED_HOST",
  "HOSTNAME_ILLEGAL": "GOAD_REBRAND_HOSTNAME_ILLEGAL",
  "HOSTNAME_TOO_LONG": "GOAD_REBRAND_HOSTNAME_TOO_LONG",
  "HOSTNAME_COLLISION": "GOAD_REBRAND_HOSTNAME_COLLISION",
  "PREBAKED": "GOAD_REBRAND_PREBAKED",
  "EXTENSION": "GOAD_REBRAND_EXTENSION",
  "RESIDUE": "GOAD_REBRAND_RESIDUE",
  "SHAPE": "GOAD_REBRAND_SHAPE",
  "ALREADY_GENERATED": "GOAD_REBRAND_ALREADY_GENERATED",
  "ALREADY_REBRANDED": "GOAD_REBRAND_ALREADY_REBRANDED",
  "LAB_NAME": "GOAD_REBRAND_LAB_NAME",
  "INVARIANT": "GOAD_REBRAND_INVARIANT"
});
class RebrandError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'RebrandError';
    this.code = code;
    Object.assign(this, details || {});
  }
}
const compiledGoadSpecs = new WeakMap();
const byteCache = new Map();
const str = value => value === null || value === undefined ? '' : String(value);
const isPlainObject = value => !!value && typeof value === 'object' && !Array.isArray(value);
function readSidecar(dir) {
  const file = path.join(dir, 'base.json');
  if (!fs.existsSync(file)) return null;
  if (!byteCache.has(file)) byteCache.set(file, fs.readFileSync(file, 'utf8'));
  return JSON.parse(byteCache.get(file));
}
function loadBaseMetadata(labName) {
  const name = canonicalGoadLabName(labName);
  if (!name || !LAB_NAME_RE.test(name) || name.includes('..')) return null;
  const dir = path.join(BASE_LABS_DIR, name), base = readSidecar(dir);
  return base ? { name, dir, base } : null;
}
function canonicalGoadLabName(value) {
  const name = str(value).trim();
  return ({ light: 'GOAD-Light', 'goad-light': 'GOAD-Light', mini: 'GOAD-Mini',
    'goad-mini': 'GOAD-Mini', full: 'GOAD', goad: 'GOAD' })[name.toLowerCase()] || name;
}

function mappingForBase(loaded, domain, childSubdomain) {
  const root = publicDomainOf(domain);
  if (!root) throw new RebrandError(REBRAND_CODES.UNUSABLE_DOMAIN,
    'Rename forest requires a valid non-reserved DNS domain. Clear Rename forest to deploy the stock identity.');
  const stock = loaded.base.stock;
  const definitions = stock.domains || { [stock.forest_root]: { netbios: stock.netbios, kind: 'root' } };
  if (!Object.values(definitions).some(d => d.kind === 'child') && str(childSubdomain).trim()) {
    throw new RebrandError(REBRAND_CODES.FOREIGN_DOMAIN, 'This base lab has no child domain. Clear the authored child domain.');
  }
  const result = [];
  const names = new Set();
  const netbiosNames = new Set();
  for (const [from, d] of Object.entries(definitions)) {
    let to = root;
    if (d.kind === 'child') {
      const raw = str(childSubdomain).trim().toLowerCase() || 'corp';
      const label = raw.includes('.') ? (raw.endsWith('.' + root) ? raw.slice(0, -root.length - 1) : '') : raw;
      if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label) || label.length > 63) {
        throw new RebrandError(REBRAND_CODES.FOREIGN_DOMAIN, 'Child domain must be one DNS label beneath the authored forest root.');
      }
      to = `${label}.${root}`;
    } else if (d.kind === 'partner') {
      const labels = root.split('.');
      labels[0] += '-partner';
      to = labels.join('.');
    }
    if (!publicDomainOf(to)) throw new RebrandError(REBRAND_CODES.FOREIGN_DOMAIN, `Derived ${d.kind} domain exceeds DNS limits: ${to}`);
    let netbios = netbiosForDomain(to);
    // A trust partner must not collide after the Windows 15-character cap.
    if (d.kind === 'partner') netbios = 'PARTNER';
    if (names.has(to.toLowerCase()) || netbiosNames.has(netbios.toLowerCase())) {
      throw new RebrandError(REBRAND_CODES.FOREIGN_DOMAIN, `Derived domain or NetBIOS name collides: ${to} (${netbios}). Choose a distinct child/root name.`);
    }
    names.add(to.toLowerCase()); netbiosNames.add(netbios.toLowerCase());
    result.push({ from, to, fromNetbios: d.netbios, netbios, kind: d.kind });
  }
  return result;
}

function assertHostname(name, hostKey) {
  const s = str(name).trim();
  if (!s) {
    throw new RebrandError(
      REBRAND_CODES.UNMAPPED_HOST,
      `No hostname for host key '${hostKey}'. Every host in the lab config has to be given the `
      + 'roster name it will actually boot as; leaving one at its stock name would build a forest '
      + 'that half agrees with the artifacts.',
      { hostKey });
  }
  if (!HOSTNAME_RE.test(s)) {
    throw new RebrandError(
      REBRAND_CODES.HOSTNAME_ILLEGAL,
      `Hostname ${JSON.stringify(s)} for host key '${hostKey}' is not a legal computer name `
      + '(letters, digits and internal hyphens only). Windows rejects it at the rename step, after '
      + 'the VM has already been cloned and booted.',
      { hostKey, hostname: s });
  }
  if (/^[0-9-]+$/.test(s)) {
    throw new RebrandError(
      REBRAND_CODES.HOSTNAME_ILLEGAL,
      `Hostname ${JSON.stringify(s)} for host key '${hostKey}' is all digits and hyphens; Windows `
      + 'refuses an all-numeric computer name.',
      { hostKey, hostname: s });
  }
  if (s.length > MAX_HOSTNAME) {
    throw new RebrandError(
      REBRAND_CODES.HOSTNAME_TOO_LONG,
      `Hostname ${JSON.stringify(s)} for host key '${hostKey}' is ${s.length} characters; Windows `
      + `caps a computer name at ${MAX_HOSTNAME}. It is REFUSED rather than truncated: the truncated `
      + 'form is what every Kerberos ticket and every Kibana document would then be stamped with, '
      + 'and nobody chose it.',
      { hostKey, hostname: s });
  }
  return s;
}

function assertNoHostnameCollision(hosts) {
  const seen = new Map();
  for (const key of Object.keys(hosts)) {
    const lower = str(hosts[key]).toLowerCase();
    if (seen.has(lower)) {
      throw new RebrandError(
        REBRAND_CODES.HOSTNAME_COLLISION,
        `Host keys '${seen.get(lower)}' and '${key}' both map to the hostname `
        + `${JSON.stringify(hosts[key])}. Computer names are case-insensitive in AD, so the second `
        + 'join would take over the first machine account and one host would drop off the domain.',
        { hostKey: key, hostname: hosts[key] });
    }
    seen.set(lower, key);
  }
  return hosts;
}

function mintLabName({ baseLab, fqdn, netbios, hostnames, goadRef, domainMapping }) {
  const digest = crypto.createHash('sha256').update(JSON.stringify({
    v: REBRAND_SCHEMA_VERSION,
    baseLab: str(baseLab),
    fqdn: str(fqdn),
    hosts: Object.keys(hostnames || {}).sort().map((k) => [k, str(hostnames[k])]),
    goadRef: str(goadRef),
    domainMapping: domainMapping || null,
  })).digest('hex').slice(0, 8);

  const seg = (s) => str(s).toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 16) || 'X';
  const name = `CC-${seg(baseLab)}-${seg(netbios)}-${digest}`;
  if (!LAB_NAME_RE.test(name)) {
    throw new RebrandError(
      REBRAND_CODES.LAB_NAME,
      `Minted lab name ${JSON.stringify(name)} does not match ${LAB_NAME_RE}. It becomes a shell `
      + 'path, a YAML mapping key and a tar member prefix on the controller.',
      { labName: name });
  }
  return name;
}

function expectedLabNameFor(baseLab, domain, childSubdomain) {
  const loaded = loadBaseMetadata(baseLab);
  const fqdn = publicDomainOf(domain);
  if (!loaded || !fqdn) return null;
  const hostnames = {};
  for (const key of Object.keys((loaded.base.stock || {}).hosts || {})) {
    hostnames[key] = str(loaded.base.stock.hosts[key].roster_name);
  }
  return mintLabName({
    baseLab: loaded.name,
    fqdn,
    netbios: netbiosForDomain(fqdn),
    hostnames,
    goadRef: REBRAND_SCHEMA_VERSION,
    domainMapping: mappingForBase(loaded, domain, childSubdomain),
  });
}

function describeRebrand(spec) {
  const goad = spec?.goad;
  if (!isPlainObject(goad) || goad.rename_forest !== true) {
    return { willRebrand: false, code: REBRAND_CODES.NOT_REQUESTED, reason: 'spec.goad.rename_forest is not true' };
  }
  const baseLab = canonicalGoadLabName(goad.version);
  const refuse = (code, reason) => ({ willRebrand: false, code, reason, baseLab });
  try {
    if (goad.extensions !== undefined && (!Array.isArray(goad.extensions)
      || goad.extensions.some(key => !['ws01', 'lx01', 'elk', 'wazuh'].includes(key))
      || new Set(goad.extensions).size !== goad.extensions.length)) {
      return refuse(REBRAND_CODES.EXTENSION,
        'Rename forest supports only distinct ws01, lx01, elk and wazuh extension selections.');
    }
    if (goad.prebaked === true) {
      return refuse(REBRAND_CODES.PREBAKED,
        'Pre-baked NTDS cannot be renamed by changing provisioning data. Clear Rename forest or use base OS templates.');
    }
    if (goad.rename_plan || goad.generated_lab) {
      const original = goad.lab?.baseLab;
      const expected = original && expectedLabNameFor(original, goad.domain, goad.child_subdomain);
      // Object provenance alone is insufficient if a caller edits its nested plan.
      if (compiledGoadSpecs.get(goad) === JSON.stringify(goad) && expected
        && expected === goad.version && goad.rename_plan?.lab_name === expected) {
        return {
          willRebrand: false, code: REBRAND_CODES.ALREADY_REBRANDED, baseLab: original, labName: expected,
          domain: goad.lab.forestRoot, childSubdomain: goad.child_subdomain,
          domainMapping: goad.lab.domainMapping, reason: 'The spec is already planned by this transform.',
        };
      }
      return refuse(REBRAND_CODES.ALREADY_GENERATED,
        'A separately generated lab or untrusted rename plan already owns this spec. Its forest identity cannot be replaced.');
    }
    if (goad.lab) {
      return refuse(REBRAND_CODES.ALREADY_GENERATED,
        'A separately compiled lab definition already owns this spec. Regenerate it to change its forest.');
    }
    if (!LAB_NAME_RE.test(baseLab) || baseLab.includes('..')) {
      return refuse(REBRAND_CODES.NO_BASE_TREE, 'Unknown GOAD lab identity.');
    }
    const loaded = loadBaseMetadata(baseLab);
    if (!loaded) {
      return refuse(REBRAND_CODES.NO_BASE_TREE,
        `No rename metadata for '${baseLab}'. Clear Rename forest to use its stock identity.`);
    }
    const domainMapping = mappingForBase(loaded, goad.domain, goad.child_subdomain);
    const root = domainMapping.find(domain => domain.kind === 'root');
    const child = domainMapping.find(domain => domain.kind === 'child');
    return {
      willRebrand: true, code: null, baseLab, domain: root.to, domainMapping,
      childSubdomain: child ? child.to.slice(0, -root.to.length - 1) : null,
    };
  } catch (error) {
    return refuse(error.code || REBRAND_CODES.SHAPE, error.message);
  }
}

function rebrandGoadSpec(spec) {
  const verdict = describeRebrand(spec);
  if (!verdict.willRebrand) {
    if ([REBRAND_CODES.NOT_REQUESTED, REBRAND_CODES.ALREADY_REBRANDED].includes(verdict.code)) return spec;
    throw new RebrandError(verdict.code, verdict.reason, { baseLab: verdict.baseLab });
  }
  const metadata = loadBaseMetadata(verdict.baseLab).base;
  const hostnames = Object.fromEntries(Object.entries(metadata.stock.hosts)
    .map(([key, host]) => [key, assertHostname(host.roster_name, key)]));
  assertNoHostnameCollision(hostnames);
  const labName = expectedLabNameFor(verdict.baseLab, verdict.domain, verdict.childSubdomain);
  const renamePlan = {
    schema: REBRAND_SCHEMA_VERSION, base_lab: verdict.baseLab, lab_name: labName,
    domain_mapping: verdict.domainMapping, hostnames,
    selected_extensions: Array.isArray(spec.goad.extensions) ? [...spec.goad.extensions] : [],
    expected_identities: Object.entries(metadata.stock.hosts).map(([key, host]) => ({
      name: host.roster_name,
      hostname: hostnames[key],
      domain: verdict.domainMapping.find(domain => domain.from === (host.domain || metadata.stock.forest_root)).to,
    })),
  };
  for (const key of renamePlan.selected_extensions) {
    const extension = readSidecar(path.join(BASE_LABS_DIR, EXTENSIONS_DIRNAME, key));
    if (!extension) continue;
    for (const host of Object.values(extension.stock.hosts)) {
      renamePlan.expected_identities.push({ name: host.roster_name, hostname: host.roster_name, domain: verdict.domain });
    }
  }
  const result = {
    ...spec,
    goad: {
      ...spec.goad, version: labName, domain: verdict.domain, child_subdomain: verdict.childSubdomain,
      lab: {
        ...metadata.lab_definition, forestRoot: verdict.domain, baseLab: verdict.baseLab,
        domains: verdict.domainMapping.map(domain => domain.to), domainMapping: verdict.domainMapping,
        childSubdomain: verdict.childSubdomain,
      },
      rename_plan: renamePlan,
    },
  };
  compiledGoadSpecs.set(result.goad, JSON.stringify(result.goad));
  return result;
}

function listExtensionBases() {
  const dir = path.join(BASE_LABS_DIR, EXTENSIONS_DIRNAME);
  return fs.existsSync(dir) ? fs.readdirSync(dir).filter(key => !!readSidecar(path.join(dir, key))).sort() : [];
}

function rootDnForDomain(fqdn) {
  return str(fqdn)
    .split('.')
    .filter(Boolean)
    .map((label) => `DC=${label}`)
    .join(',');
}

function normalizeDn(dn) {
  return str(dn)
    .split(',')
    .map((rdn) => rdn.trim().replace(/\s*=\s*/, '='))
    .join(',')
    .toLowerCase();
}

function isDnShaped(value) {
  return /(^|,)\s*(CN|OU|DC)=/i.test(str(value));
}
const preflightGoadRebrand = rebrandGoadSpec;
module.exports = {
  canonicalGoadLabName, mappingForBase, assertHostname, assertNoHostnameCollision, mintLabName,
  expectedLabNameFor, describeRebrand, rebrandGoadSpec, listExtensionBases, rootDnForDomain,
  normalizeDn, isDnShaped, preflightGoadRebrand, loadBaseMetadata, RebrandError, REBRAND_CODES,
  REBRAND_SCHEMA_VERSION, BASE_LABS_DIR, LAB_NAME_RE, MAX_HOSTNAME,
};
