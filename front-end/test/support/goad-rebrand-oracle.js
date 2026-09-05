/** Offline JS reference compiler for controller parity tests. Never imported by production. */

'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const { publicDomainOf, netbiosForDomain } = require('../../src/utils/ad-domain-rules');

// ─── Constants ──────────────────────────────────────────────────────────────

/**
 * Folded into the minted lab name's hash, so that changing the TRANSFORM
 * re-mints the name and forces a fresh push. Without it a fixed walker would
 * emit new bytes under the old lab name and pushLabTree's sha short-circuit
 * would decide the controller was already up to date.
 */
const REBRAND_SCHEMA_VERSION = 2;

/** CyberCore-owned source contracts; these directories contain no GOAD payloads. */
const BASE_LABS_DIR = path.join(__dirname, '../../src/data/goad-base-labs');

/** The subdirectory holding extension identity metadata (ws01, lx01). */
const EXTENSIONS_DIRNAME = '_extensions';

const TOP_KEY_MAIN = 'lab';
const TOP_KEY_EXT = 'lab_extension';

/**
 * Built rather than typed. This character is emitted into generated JSON (the
 * `DOMAIN\user` principals) and this repo has been broken more than once by a
 * backslash escape surviving one round of escaping too many. There is no
 * escaping question about String.fromCharCode(92).
 */
const BACKSLASH = String.fromCharCode(92);
const LF = String.fromCharCode(10);
const CR = String.fromCharCode(13);

/**
 * Windows' hard cap on a NetBIOS computer name. A name over this is not
 * truncated here — see assertHostname.
 */
const MAX_HOSTNAME = 15;

/** A legal NetBIOS computer name: letters, digits, internal hyphens. */
const HOSTNAME_RE = /^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?$/;

/**
 * Lab directory name, duplicated from goad-lab-push.js's LAB_NAME_RE. The
 * minted name becomes a shell path, a YAML key and a tar member prefix over
 * there; asserting it here means a bad mint fails at compile time rather than
 * mid-push on a live lane. The test pins the two spellings equal by reading
 * goad-lab-push.js as text.
 */
const LAB_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * Every refusal this module can raise. Codes rather than message matching,
 * because the four author-time refusal layers and the deploy-time assert all
 * have to name the same condition and they live in four different files.
 */
const REBRAND_CODES = Object.freeze({
  // NOT_REQUESTED is the only legacy opt-out; explicit invalid rename requests fail.
  UNUSABLE_DOMAIN: 'GOAD_REBRAND_UNUSABLE_DOMAIN',
  SAME_DOMAIN: 'GOAD_REBRAND_SAME_DOMAIN',
  NO_BASE_TREE: 'GOAD_REBRAND_NO_BASE_TREE',
  NOT_REQUESTED: 'GOAD_REBRAND_NOT_REQUESTED',
  SOURCE_UNAVAILABLE: 'GOAD_REBRAND_SOURCE_UNAVAILABLE',
  SOURCE_MISMATCH: 'GOAD_REBRAND_SOURCE_MISMATCH',
  // Fatal: throw, because continuing would build a forest nobody described.
  MULTI_DOMAIN: 'GOAD_REBRAND_MULTI_DOMAIN',
  FOREIGN_DOMAIN: 'GOAD_REBRAND_FOREIGN_DOMAIN',
  FOREIGN_DN: 'GOAD_REBRAND_FOREIGN_DN',
  FOREIGN_PRINCIPAL: 'GOAD_REBRAND_FOREIGN_PRINCIPAL',
  FOREIGN_LAB_NAME: 'GOAD_REBRAND_FOREIGN_LAB_NAME',
  UNMAPPED_HOST: 'GOAD_REBRAND_UNMAPPED_HOST',
  HOSTNAME_ILLEGAL: 'GOAD_REBRAND_HOSTNAME_ILLEGAL',
  HOSTNAME_TOO_LONG: 'GOAD_REBRAND_HOSTNAME_TOO_LONG',
  HOSTNAME_COLLISION: 'GOAD_REBRAND_HOSTNAME_COLLISION',
  PREBAKED: 'GOAD_REBRAND_PREBAKED',
  EXTENSION: 'GOAD_REBRAND_EXTENSION',
  RESIDUE: 'GOAD_REBRAND_RESIDUE',
  SHAPE: 'GOAD_REBRAND_SHAPE',
  ALREADY_GENERATED: 'GOAD_REBRAND_ALREADY_GENERATED',
  ALREADY_REBRANDED: 'GOAD_REBRAND_ALREADY_REBRANDED',
  LAB_NAME: 'GOAD_REBRAND_LAB_NAME',
  INVARIANT: 'GOAD_REBRAND_INVARIANT',
});

/**
 * Carries the code and the site, so a caller's finding can say WHERE. The
 * message names the mechanism and the consequence, because for the fatal codes
 * it is the only thing an operator sees.
 */
class RebrandError extends Error {
  constructor(code, message, details) {
    super(message);
    this.name = 'RebrandError';
    this.code = code;
    Object.assign(this, details || {});
  }
}

// ─── Primitives ─────────────────────────────────────────────────────────────

function str(v) {
  return v === null || v === undefined ? '' : String(v);
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** `north.sevenkingdoms.local` → `DC=north,DC=sevenkingdoms,DC=local`. */
function rootDnForDomain(fqdn) {
  return str(fqdn)
    .split('.')
    .filter(Boolean)
    .map((label) => `DC=${label}`)
    .join(',');
}

/**
 * Canonical form for DN comparison: case-folded, no whitespace around the
 * separators. AD is case-insensitive here and GOAD relies on it —
 * north.sevenkingdoms.local is declared with the path `DC=North,…` — so a
 * case-sensitive compare would refuse a tree that has shipped for years.
 */
function normalizeDn(dn) {
  return str(dn)
    .split(',')
    .map((rdn) => rdn.trim().replace(/\s*=\s*/, '='))
    .join(',')
    .toLowerCase();
}

/**
 * Is this value a DN? The predicate goad-lab-validate.js:374 already uses, kept
 * spelled identically so the two files agree about what a DN is. It has to
 * accept the bare-RDN forms the acl role takes as well as full DNs, which is
 * why it anchors on a component rather than on the whole string.
 */
function isDnShaped(value) {
  return /(^|,)\s*(CN|OU|DC)=/i.test(str(value));
}

/** Case-insensitive FQDN compare — DNS does not care and neither does AD. */
function sameDomain(a, b) {
  return str(a).toLowerCase() === str(b).toLowerCase();
}

/** Aliases are accepted on input only; generated identities always use the catalog key. */
function canonicalGoadLabName(value) {
  const name = str(value).trim();
  return ({ light: 'GOAD-Light', 'goad-light': 'GOAD-Light', mini: 'GOAD-Mini',
    'goad-mini': 'GOAD-Mini', full: 'GOAD', goad: 'GOAD' })[name.toLowerCase()] || name;
}

function domainMaps(map) { return map.domainMaps || [map]; }

function rebaseMappedDn(value, map, where) {
  const rdns = str(value).split(',');
  let i = rdns.length;
  while (i > 0 && /^\s*DC\s*=/i.test(rdns[i - 1])) i -= 1;
  const root = normalizeDn(rdns.slice(i).join(','));
  const match = domainMaps(map).find(m => normalizeDn(m.from.rootDn) === root);
  if (!match) throw new RebrandError(REBRAND_CODES.FOREIGN_DN, `Unmapped domain root in DN at ${where}`, { where });
  return rebaseDn(value, match.from.rootDn, match.to.rootDn, where);
}

function escapeRegExp(value) { return str(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

/**
 * Rewrite typed identity tokens inside SPNs, PowerShell payloads and endpoint
 * strings. Longest-first, single-pass substitution prevents a child root from
 * being consumed by its parent and never rewrites newly emitted destinations.
 * Bare domain words are deliberately excluded: they are also city/group names.
 */
function rewriteIdentityText(value, map) {
  const pairs = [];
  for (const m of domainMaps(map)) {
    pairs.push([m.from.rootDn, m.to.rootDn, 'dn']);
    pairs.push([m.from.fqdn, m.to.fqdn, 'dns']);
    for (const p of new Set([m.from.netbios, m.from.firstLabel])) pairs.push([p + BACKSLASH, m.to.netbios + BACKSLASH, 'principal']);
  }
  for (const key of Object.keys(map.from.hosts)) pairs.push([map.from.hosts[key], map.to.hosts[key], 'host']);
  const unique = new Map();
  for (const p of pairs) unique.set(p[0].toLowerCase(), p);
  const ordered = [...unique.values()].sort((a, b) => b[0].length - a[0].length);
  if (!ordered.length) return value;
  const re = new RegExp(ordered.map(p => escapeRegExp(p[0])).join('|'), 'gi');
  return str(value).replace(re, (found, offset, whole) => {
    const [, replacement, kind] = unique.get(found.toLowerCase());
    const before = whole[offset - 1] || '';
    const after = whole[offset + found.length] || '';
    // A hostname may prefix its FQDN or a machine-account '$', but may not
    // match inside an unrelated principal, identifier or device name.
    if (/[A-Za-z0-9_-]/.test(before) || (kind !== 'principal' && /[A-Za-z0-9_-]/.test(after))) return found;
    return replacement;
  });
}

/** A declared naming subtree; credentials and exercise labels are opaque. */
function rewriteReferences(value, map, where) {
  if (Array.isArray(value)) return value.map((v, i) => rewriteReferences(v, map, `${where}[${i}]`));
  if (!isPlainObject(value)) return typeof value === 'string' ? rewriteIdentityText(value, map) : value;
  const out = {};
  for (const [key, entry] of Object.entries(value)) {
    const opaque = /password|secret|^(city|description|display_name|src|dest|template_file|template_name|setup)$/i.test(key);
    const nextKey = key.includes(BACKSLASH) || key.startsWith('TERMSRV/') ? rewriteIdentityText(key, map) : key;
    out[nextKey] = opaque ? entry : rewriteReferences(entry, map, `${where}.${key}`);
  }
  return out;
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

// ─── The DN rebase — the whole trick ────────────────────────────────────────

/**
 * Move a DN from one domain root to another WITHOUT touching its prefix.
 *
 * Split into RDNs, take the MAXIMAL TRAILING RUN of `DC=` components, assert it
 * is the stock root, and re-emit [...prefix verbatim, ...new root]. Two
 * properties fall out for free, and both of them are the point:
 *
 *   · `CN=AdminSDHolder,CN=System,` and `OU=Crownlands,` survive byte for byte,
 *     including their spacing. They name objects the exercise depends on; a
 *     transform that "normalised" them would silently move an ACL.
 *   · the result has as many DC components as the NEW domain has labels, not as
 *     many as the old one had. That is what a text replace cannot do, and the
 *     failure it produces (`DC=lab.cy400test,DC=org`) is a legal DN for a
 *     domain that does not exist.
 *
 * A DN whose trailing DC run is NOT the stock root is refused rather than
 * rebased: it names a second domain, and this transform only knows how to move
 * one.
 */
function rebaseDn(dn, oldRootDn, newRootDn, where) {
  const raw = str(dn);
  const at = where ? ` at ${where}` : '';
  if (!raw.trim()) {
    throw new RebrandError(REBRAND_CODES.SHAPE, `Empty DN${at}`, { where });
  }
  const rdns = raw.split(',');
  for (const rdn of rdns) {
    // A DN with an escaped comma would mis-split above. GOAD ships none, and
    // guessing at one would silently relocate an object, so say so instead.
    if (!/^\s*[A-Za-z][A-Za-z0-9-]*\s*=\s*[^,]+$/.test(rdn)) {
      throw new RebrandError(
        REBRAND_CODES.FOREIGN_DN,
        `Cannot parse the RDN ${JSON.stringify(rdn)} in DN ${JSON.stringify(raw)}${at}. `
        + 'This transform splits DNs on unescaped commas; an escaped comma or a quoted value '
        + 'would be mis-split and the object would be created somewhere nobody named.',
        { where, dn: raw });
    }
  }

  let firstDcIndex = rdns.length;
  while (firstDcIndex > 0 && /^\s*DC\s*=/i.test(rdns[firstDcIndex - 1])) firstDcIndex -= 1;
  const prefix = rdns.slice(0, firstDcIndex);
  const trailing = rdns.slice(firstDcIndex);

  if (trailing.length === 0 || normalizeDn(trailing.join(',')) !== normalizeDn(oldRootDn)) {
    throw new RebrandError(
      REBRAND_CODES.FOREIGN_DN,
      `DN ${JSON.stringify(raw)}${at} does not end in the stock root ${JSON.stringify(oldRootDn)} `
      + `(its trailing DC run is ${JSON.stringify(trailing.join(',')) || 'empty'}). It names a domain `
      + 'this rename does not cover, so rebasing it would move an object into a forest it was never '
      + 'part of.',
      { where, dn: raw });
  }

  return [...prefix, ...str(newRootDn).split(',')].join(',');
}

// ─── The rename map ─────────────────────────────────────────────────────────

/**
 * Everything the walker needs, on both sides, so that inverting a rename is
 * swapping two halves rather than a second code path. The round-trip test in
 * test/goad-lab-rebrand.test.js runs the transform new→old and compares — which
 * is only a meaningful assertion because there is exactly one walker.
 *
 * @param {object} from  { fqdn, netbios, firstLabel, hosts:{key:name}, labName }
 * @param {object} to    same shape
 */
function buildRenameMap(from, to) {
  const side = (s, which) => {
    if (!isPlainObject(s)) {
      throw new RebrandError(REBRAND_CODES.SHAPE, `renameMap.${which} must be an object`);
    }
    const fqdn = str(s.fqdn).trim();
    if (!fqdn) {
      throw new RebrandError(REBRAND_CODES.SHAPE, `renameMap.${which}.fqdn is required`);
    }
    const firstLabel = str(s.firstLabel).trim() || fqdn.split('.')[0];
    return Object.freeze({
      fqdn,
      rootDn: rootDnForDomain(fqdn),
      netbios: str(s.netbios).trim() || netbiosForDomain(fqdn),
      firstLabel,
      hosts: Object.freeze({ ...(s.hosts || {}) }),
      labName: str(s.labName).trim(),
    });
  };
  return Object.freeze({ from: side(from, 'from'), to: side(to, 'to') });
}

/** Swap the two halves. The transform is its own inverse under this. */
function invertRenameMap(map) {
  return buildRenameMap(map.to, map.from);
}

// ─── Hostnames — refuse, never truncate ─────────────────────────────────────

/**
 * A hostname the transform is allowed to write.
 *
 * REFUSES rather than truncating or sanitising. A silently truncated computer
 * name is the name in every Kerberos ticket, every SPN, every Kibana document
 * and the Proxmox console's sign-in prompt — and nobody chose it. The roster
 * name is authored (GOAD_LABS[lab].vms[].name, which assertGoadRoster already
 * forces spec.vms[].name to equal), so a name that does not fit is a question
 * for the author, not something to guess at fifteen characters.
 */
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

/** Two hosts that boot with one name is a duplicate SPN and a broken join. */
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

// ─── Value rewriters, one per encoding ──────────────────────────────────────

/** DNS: a value that must be the stock forest root, rewritten to the new one. */
function rewriteDomainValue(value, map, where) {
  const s = str(value).trim();
  const matched = domainMaps(map).find(m => sameDomain(s, m.from.fqdn));
  if (!matched) {
    throw new RebrandError(
      REBRAND_CODES.FOREIGN_DOMAIN,
      `${where} is ${JSON.stringify(value)}, not the stock forest root `
      + `${JSON.stringify(map.from.fqdn)}. This transform renames exactly one domain; a second one `
      + 'here would be left pointing at a forest the lane no longer builds.',
      { where });
  }
  return matched.to.fqdn;
}

/**
 * NetBIOS-qualified principal: `sevenkingdoms\robert.baratheon`.
 *
 * Split on the LAST backslash (a sAMAccountName cannot contain one, a prefix
 * can be spelled either way), and match the prefix case-insensitively against
 * BOTH the stock NetBIOS name and the stock first label — GOAD-Mini spells
 * these five in lower-case first-label form while netbios_name is upper-case,
 * and both spellings resolve today only because the two strings coincide.
 *
 * The emitted prefix is always the new NETBIOS NAME, never the new first label.
 * The first-label spelling works in GOAD-Mini by coincidence; ad/SCCM
 * (`sccm.lab`, netbios_name `SCCMLAB`) is the counter-example where preserving
 * that spelling would emit a prefix Windows cannot resolve.
 *
 * A value with NO backslash is left alone — that is not a miss. lx01's
 * local_groups carry bare group names (`sudoers: ["Baratheon"]`), and refusing
 * them would make the one extension that needs no principal rewriting the one
 * extension that cannot be rewritten.
 */
function rewritePrincipal(value, map, where) {
  const s = str(value);
  const cut = s.lastIndexOf(BACKSLASH);
  if (cut === -1) return value;

  const prefix = s.slice(0, cut);
  const account = s.slice(cut + 1);
  const lower = prefix.toLowerCase();
  if (lower === 'nt authority' || lower === 'builtin' || lower === '.') return value;
  const matched = domainMaps(map).find(m => [m.from.netbios, m.from.firstLabel, m.from.fqdn].some(p => p.toLowerCase() === lower));
  if (!matched) {
    throw new RebrandError(
      REBRAND_CODES.FOREIGN_PRINCIPAL,
      `${where} is ${JSON.stringify(s)}, whose domain prefix ${JSON.stringify(prefix)} is neither `
      + `the stock NetBIOS name ${JSON.stringify(map.from.netbios)} nor the stock first label `
      + `${JSON.stringify(map.from.firstLabel)}. It names a principal in another domain, which this `
      + 'rename cannot follow.',
      { where });
  }
  return (sameDomain(prefix, matched.from.fqdn) ? matched.to.fqdn : matched.to.netbios) + BACKSLASH + account;
}

/** netbios_name itself: asserted, then replaced from the new domain. */
function rewriteNetbiosName(value, map, where) {
  const s = str(value).trim();
  if (s.toLowerCase() !== map.from.netbios.toLowerCase()) {
    throw new RebrandError(
      REBRAND_CODES.FOREIGN_DOMAIN,
      `${where} is ${JSON.stringify(value)}, not the stock NetBIOS name `
      + `${JSON.stringify(map.from.netbios)}. The vendored tree and its base.json sidecar disagree, `
      + 'so every principal prefix this transform matched was matched against the wrong name.',
      { where });
  }
  return map.to.netbios;
}

/**
 * `trust`. Empty is the single-domain case and passes through. A non-empty
 * trust names a SECOND forest by name — ad-trusts.yml wires it from this string
 * — and renaming one side of a trust leaves the other pointing at a domain that
 * no longer exists.
 */
function rewriteTrust(value, map, where) {
  const s = str(value).trim();
  if (s === '') return value;
  if (map.domainMaps) return rewriteDomainValue(value, map, where);
  throw new RebrandError(
    REBRAND_CODES.MULTI_DOMAIN,
    `${where} declares a trust with ${JSON.stringify(s)}. ad-trusts.yml wires a trust partner BY `
    + 'NAME, so renaming this forest would leave the partner pointing at a domain that no longer '
    + 'exists. Only single-domain, trust-free labs are rebrandable.',
    { where });
}

/**
 * An ACL `for` / `to`. Three shapes live in this one field and they are checked
 * most-specific first:
 *   a DN            → rebased
 *   `kingslanding$` → a COMPUTER account; the roster hostname, `$` re-added
 *   anything else   → a user or group name, which is exercise content
 * A `$`-suffixed value naming something that is not a known host falls through
 * to verbatim on purpose: it is a group whose name happens to end in `$`, and
 * if it really were a stray hostname the residue sweep refuses the whole build.
 */
function rewriteAclPrincipal(value, map, where) {
  const s = str(value);
  if (isDnShaped(s)) return rebaseMappedDn(s, map, where);
  if (s.endsWith('$')) {
    const bare = s.slice(0, -1).toLowerCase();
    for (const hostKey of Object.keys(map.from.hosts)) {
      if (str(map.from.hosts[hostKey]).toLowerCase() === bare) {
        return `${assertHostname(map.to.hosts[hostKey], hostKey)}$`;
      }
    }
  }
  if (s.includes(BACKSLASH)) return rewritePrincipal(s, map, where);
  return value;
}

// ─── The walker ─────────────────────────────────────────────────────────────

/**
 * Values the walker does not recognise are carried through by reference rather
 * than cloned. That is safe because every caller gets a freshly parsed config
 * (loadBaseLab caches BYTES, not objects) and nothing here mutates. It is also
 * deliberate: a deep clone would quietly normalise things JSON round-trips
 * differently, and the residue sweep would then be inspecting a value the
 * vendored tree does not contain.
 */
function rewriteHost(hostKey, host, map, where) {
  if (!isPlainObject(host)) {
    throw new RebrandError(REBRAND_CODES.SHAPE, `${where} must be an object`, { where });
  }
  const out = {};
  for (const key of Object.keys(host)) {
    const value = host[key];
    const at = `${where}.${key}`;
    if (key === 'hostname') {
      const stock = str(map.from.hosts[hostKey]);
      if (!stock) {
        throw new RebrandError(
          REBRAND_CODES.UNMAPPED_HOST,
          `Host key '${hostKey}' is in the config but not in the rename map's stock host list, so `
          + 'this transform does not know what it is called today and cannot tell a rename from a '
          + 'foreign name.',
          { hostKey, where: at });
      }
      if (str(value).toLowerCase() !== stock.toLowerCase()) {
        throw new RebrandError(
          REBRAND_CODES.UNMAPPED_HOST,
          `${at} is ${JSON.stringify(value)} but the sidecar records the stock hostname for `
          + `'${hostKey}' as ${JSON.stringify(stock)}. The vendored tree has drifted from its `
          + 'base.json, so the roster join this rename is built on no longer holds.',
          { hostKey, where: at });
      }
      out[key] = assertHostname(map.to.hosts[hostKey], hostKey);
    } else if (key === 'domain') {
      out[key] = rewriteDomainValue(value, map, at);
    } else if (key === 'path') {
      out[key] = rebaseMappedDn(value, map, at);
    } else if (key === 'local_groups') {
      out[key] = rewriteLocalGroups(value, map, at);
    } else if (key === 'vulns_vars' || key === 'mssql' || key === 'Remote Desktop Users') {
      out[key] = rewriteReferences(value, map, at);
    } else {
      out[key] = value;
    }
  }
  return out;
}

function rewriteLocalGroups(groups, map, where) {
  if (!isPlainObject(groups)) return groups;
  const out = {};
  for (const groupName of Object.keys(groups)) {
    const members = groups[groupName];
    out[groupName] = Array.isArray(members)
      ? members.map((m, i) => rewritePrincipal(m, map, `${where}[${JSON.stringify(groupName)}][${i}]`))
      : members;
  }
  return out;
}

/** `{ Vale: { path: 'DC=…' } }` — rewrite `path`, keep every sibling key. */
function rewritePathBearing(container, map, where) {
  if (!isPlainObject(container)) return container;
  const out = {};
  for (const name of Object.keys(container)) {
    const entry = container[name];
    const at = `${where}[${JSON.stringify(name)}]`;
    if (!isPlainObject(entry) || entry.path === undefined) {
      out[name] = entry;
      continue;
    }
    out[name] = { ...entry, path: rebaseMappedDn(entry.path, map, `${at}.path`) };
    if (Array.isArray(entry.spns)) out[name].spns = entry.spns.map(v => rewriteIdentityText(v, map));
    if (Array.isArray(entry.members)) out[name].members = entry.members.map(v => rewritePrincipal(v, map, `${at}.members`));
  }
  return out;
}

/** `groups` is scope-keyed (`universal` / `global` / `domainlocal`). */
function rewriteGroups(groups, map, where) {
  if (!isPlainObject(groups)) return groups;
  const out = {};
  for (const scope of Object.keys(groups)) {
    out[scope] = rewritePathBearing(groups[scope], map, `${where}[${JSON.stringify(scope)}]`);
  }
  return out;
}

function rewriteAcls(acls, map, where) {
  if (!isPlainObject(acls)) return acls;
  const out = {};
  for (const name of Object.keys(acls)) {
    const acl = acls[name];
    const at = `${where}[${JSON.stringify(name)}]`;
    if (!isPlainObject(acl)) {
      out[name] = acl;
      continue;
    }
    const next = {};
    for (const key of Object.keys(acl)) {
      // `right` and `inheritance` are the ACE itself — the exercise content —
      // and are never naming.
      next[key] = (key === 'for' || key === 'to')
        ? rewriteAclPrincipal(acl[key], map, `${at}.${key}`)
        : acl[key];
    }
    out[name] = next;
  }
  return out;
}

function rewriteDomain(domain, map, where) {
  if (!isPlainObject(domain)) {
    throw new RebrandError(REBRAND_CODES.SHAPE, `${where} must be an object`, { where });
  }
  const out = {};
  for (const key of Object.keys(domain)) {
    const value = domain[key];
    const at = `${where}.${key}`;
    if (key === 'netbios_name') out[key] = rewriteNetbiosName(value, map, at);
    else if (key === 'trust') out[key] = rewriteTrust(value, map, at);
    else if (key === 'laps_path') out[key] = rebaseMappedDn(value, map, at);
    else if (key === 'organisation_units') out[key] = rewritePathBearing(value, map, at);
    else if (key === 'groups') out[key] = rewriteGroups(value, map, at);
    else if (key === 'acls') out[key] = rewriteAcls(value, map, at);
    else if (key === 'users') out[key] = rewritePathBearing(value, map, at);
    else if (key === 'multi_domain_groups_member' || key === 'gmsa' || key === 'ca_server') out[key] = rewriteReferences(value, map, at);
    // `dc` is a HOST KEY, `domain_password` is the DC-promotion credential.
    // Both stay exactly as they are; see the header.
    else out[key] = value;
  }
  return out;
}

/**
 * The transform, on one parsed config object.
 *
 * @param {object} config   `{ lab: {...} }` or `{ lab_extension: {...} }`
 * @param {object} map      from buildRenameMap
 * @param {object} [opts]   { topKey } — defaults to `lab`
 */
function rewriteLabConfig(config, map, opts) {
  const topKey = (opts && opts.topKey) || TOP_KEY_MAIN;
  if (!isPlainObject(config)) {
    throw new RebrandError(REBRAND_CODES.SHAPE, 'Lab config must be a JSON object');
  }
  const keys = Object.keys(config);
  if (keys.length !== 1 || keys[0] !== topKey) {
    throw new RebrandError(
      REBRAND_CODES.SHAPE,
      `Lab config must have exactly one top-level key, '${topKey}', got [${keys.join(', ')}]. `
      + 'Ansible loads this file with vars_files, so every top-level key becomes a play-scope '
      + "variable and a stray one silently shadows the main lab's own data.",
      { topKey });
  }
  const src = config[topKey];
  if (!isPlainObject(src)) {
    throw new RebrandError(REBRAND_CODES.SHAPE, `'${topKey}' must be an object`, { topKey });
  }

  if (topKey === TOP_KEY_EXT && src.domains !== undefined) {
    throw new RebrandError(
      REBRAND_CODES.EXTENSION,
      "This extension config ships its own `domains` block. install.yml merges it over the main "
      + "lab's data, so its domains would REPLACE the renamed forest's — and the block also carries "
      + 'users, groups and OU paths that a config rewrite cannot reach (the exchange extension also '
      + 'spells the domain inside files/*.ps1). Such an extension is not rename-safe.',
      { topKey });
  }
  if (topKey === TOP_KEY_MAIN && !isPlainObject(src.domains)) {
    throw new RebrandError(
      REBRAND_CODES.SHAPE,
      "The main lab config has no `domains` block, so there is no forest root to rename.",
      { topKey });
  }

  const out = {};
  for (const key of Object.keys(src)) {
    if (key === 'hosts') {
      if (!isPlainObject(src.hosts)) {
        throw new RebrandError(REBRAND_CODES.SHAPE, `'${topKey}.hosts' must be an object`, { topKey });
      }
      const hosts = {};
      for (const hostKey of Object.keys(src.hosts)) {
        // Host KEYS are never renamed: domains[*].dc, the inventory's group
        // members, ws01's dict_key and files/<key>/ all join on them.
        hosts[hostKey] = rewriteHost(hostKey, src.hosts[hostKey], map, `${topKey}.hosts.${hostKey}`);
      }
      out[key] = hosts;
    } else if (key === 'domains') {
      const domainKeys = Object.keys(src.domains);
      if (domainKeys.length !== domainMaps(map).length) {
        throw new RebrandError(
          REBRAND_CODES.MULTI_DOMAIN,
          `This lab declares ${domainKeys.length} domains (${domainKeys.join(', ')}). A child is `
          + 'derived by dropping a label and a trust partner is wired by name, so renaming the root '
          + 'leaves both pointing at a parent that no longer exists — ad-child_domain.yml looks the '
          + 'parent up with NO default and the play dies. Only single-domain labs are rebrandable.',
          { domains: domainKeys });
      }
      const domains = {};
      for (const stockKey of domainKeys) {
      const domainMap = domainMaps(map).find(m => sameDomain(stockKey, m.from.fqdn));
      if (!domainMap) {
        throw new RebrandError(
          REBRAND_CODES.FOREIGN_DOMAIN,
          `The config's domain is ${JSON.stringify(stockKey)} but the sidecar records the stock `
          + `forest root as ${JSON.stringify(map.from.fqdn)}. The vendored tree has drifted from its `
          + 'base.json.',
          { where: `${topKey}.domains` });
      }
      domains[domainMap.to.fqdn] = rewriteDomain(src.domains[stockKey], { ...domainMap, domainMaps: map.domainMaps }, `${topKey}.domains[${JSON.stringify(stockKey)}]`);
      }
      out[key] = domains;
    } else {
      out[key] = src[key];
    }
  }
  return { [topKey]: out };
}

// ─── The other files in the tree ────────────────────────────────────────────

/**
 * data/inventory — rewrite `domain_name=` and nothing else.
 *
 * FOR CONSISTENCY ONLY. This value is INERT at deploy time: run.sh writes
 * `domain_name: "$LAB"` into extra_vars.yml and --extra-vars outranks every
 * inventory level, so the plays already resolve ../ad/<labName>/data/
 * correctly. It is rewritten so an operator reading the file on the controller
 * is not misled by a name the run is not using — do not cite it as the
 * mechanism.
 *
 * Everything else stays: the group sections and their members are HOST KEYS,
 * and `dns_domain=dc01` is an inventory host key too — not a DNS name, and the
 * most tempting mistake in the file.
 */
function rewriteInventory(text, map) {
  let found = false;
  const out = str(text).split(LF).map((line) => {
    // A CR is split off and re-attached so a CRLF checkout round-trips: `.` in
    // a JS regex does not match CR, so the match below would miss the line and
    // the domain_name would silently survive.
    const eol = line.endsWith(CR) ? CR : '';
    const body = eol ? line.slice(0, -1) : line;
    const m = /^(\s*domain_name\s*=\s*)(.*?)(\s*)$/.exec(body);
    if (!m) return line;
    if (m[2] !== map.from.labName) {
      throw new RebrandError(
        REBRAND_CODES.FOREIGN_LAB_NAME,
        `data/inventory sets domain_name=${JSON.stringify(m[2])}, but the vendored tree is `
        + `${JSON.stringify(map.from.labName)}. That value is the folder under ad/, so a tree whose `
        + 'inventory names a different one has been assembled from two different labs.');
    }
    found = true;
    return m[1] + map.to.labName + m[3] + eol;
  });
  if (!found) {
    throw new RebrandError(
      REBRAND_CODES.FOREIGN_LAB_NAME,
      'data/inventory has no domain_name= line. The vendored tree does not match what this '
      + 'transform was written against, so other assumptions about it are suspect too.');
  }
  return out.join(LF);
}

/**
 * providers/proxmox/inventory — only its banner comment names the domain. The
 * host line is `dc01 ansible_host={{ip_range}}.10 dns_domain=dc01 dict_key=dc01`:
 * every token there is a host key or a placeholder the lane substitutes, and
 * none of them is a name.
 */
function rewriteProviderInventory(text, map) {
  return str(text).split(LF).map((line) => {
    const eol = line.endsWith(CR) ? CR : '';
    const body = eol ? line.slice(0, -1) : line;
    const m = /^(\s*;\s*)(\S+)(\s*)$/.exec(body);
    if (!m || !sameDomain(m[2], map.from.fqdn)) return line;
    return m[1] + map.to.fqdn + m[3] + eol;
  }).join(LF);
}

// ─── The residue sweep ──────────────────────────────────────────────────────

/** Decode a vendored file for inspection, honouring its declared encoding. */
function decodeVendored(bytes, encoding) {
  if (typeof bytes === 'string') return bytes;
  // ESC1.json is UTF-16LE with a BOM. Reading it as utf8 would turn every
  // character into mojibake and the sweep would inspect a string that is not
  // what the file says.
  return encoding === 'utf-16le-bom' ? bytes.toString('utf16le') : bytes.toString('utf8');
}

/**
 * The backstop for the structural walk: re-read every emitted byte and refuse
 * on any surviving stock token. A key path the walker does not know about is
 * copied verbatim, so this is the only thing standing between "we added a field
 * upstream" and a forest that is half renamed — which deploys green and is
 * discovered weeks later in a Kibana document.
 *
 * The needle set is per-artifact, derived from that artifact's own sidecar.
 * Sweeping the MAIN config for lx01's stock hostname would fire on the
 * `DragonStone` GROUP, which is exercise content this transform is required to
 * preserve; the extension's own sweep covers that token where it is a hostname.
 */
function assertNoResidue(entries, needles, what) {
  const wanted = [...new Set(
    (needles || []).map((n) => str(n).toLowerCase()).filter(Boolean),
  )];
  for (const entry of entries) {
    const text = decodeVendored(entry.content, entry.encoding).toLowerCase();
    const p = str(entry.path).toLowerCase();
    for (const needle of wanted) {
      const inBody = text.includes(needle);
      if (!inBody && !p.includes(needle)) continue;
      throw new RebrandError(
        REBRAND_CODES.RESIDUE,
        `${what}: ${JSON.stringify(entry.path)} still contains ${JSON.stringify(needle)} `
        + `${inBody ? 'in its contents' : 'in its path'} after the rewrite. The structural walk `
        + 'missed a site, so this tree would build a forest that is half renamed — which deploys '
        + 'green and shows up later as one artifact naming a domain another artifact does not have.',
        { path: entry.path, needle });
    }
  }
}

// ─── Reading the external source contracts ─────────────────────────────────────────────

/**
 * Raw bytes, cached. Objects are NOT cached: every caller parses its own copy,
 * so a caller that mutated a returned config could not poison the next one.
 */
const byteCache = new Map();
// Only objects compiled in this process may re-enter the no-op path. An API
// request can reproduce a minted name, but cannot reproduce this provenance.
const compiledGoadSpecs = new WeakMap();

function readSidecar(dir) {
  const sidecar = path.join(dir, 'base.json');
  if (!fs.existsSync(sidecar)) return null;
  if (!byteCache.has(sidecar)) byteCache.set(sidecar, fs.readFileSync(sidecar));
  return JSON.parse(byteCache.get(sidecar).toString('utf8'));
}

/** Resolve only the configured external checkout, or its conventional sibling.
 * Do not probe GOAD-main or fall back to a CyberCore copy. */
function resolveGoadSourceDir() {
  const configured = str(process.env.GOAD_SOURCE_DIR).trim();
  const candidate = configured || path.resolve(__dirname, '../../../../GOAD/GOAD');
  try {
    const resolved = fs.realpathSync(candidate);
    if (fs.statSync(resolved).isDirectory()) return resolved;
  } catch (_) { /* Give the caller a stable preallocation refusal below. */ }
  throw new RebrandError(REBRAND_CODES.SOURCE_UNAVAILABLE,
    `GOAD source checkout is unavailable. Set GOAD_SOURCE_DIR to the separate checkout matching the controller pin.`,
    { sourceDir: candidate });
}

function readSourceFile(sourceDir, relativePath, digest, encoding = 'utf8') {
  const lexical = path.resolve(sourceDir, ...relativePath.split('/'));
  const within = candidate => candidate.startsWith(sourceDir + path.sep);
  if (!within(lexical)) throw new RebrandError(REBRAND_CODES.SHAPE, 'GOAD source path escapes its checkout.');
  let resolved, bytes;
  try {
    resolved = fs.realpathSync(lexical);
    if (!within(resolved)) throw new RebrandError(REBRAND_CODES.SHAPE, 'GOAD source symlink escapes its checkout.');
    bytes = fs.readFileSync(resolved);
  } catch (e) {
    if (e instanceof RebrandError) throw e;
    throw new RebrandError(REBRAND_CODES.SOURCE_UNAVAILABLE,
      `GOAD source is incomplete: ${relativePath}. Set GOAD_SOURCE_DIR to the checkout matching the controller pin.`,
      { sourcePath: relativePath });
  }
  // Git may materialize text as CRLF on Windows. Only declared UTF-8 text
  // is normalized; certificate templates and executable payloads remain bytes.
  if (encoding === 'utf8') bytes = Buffer.from(bytes.toString('utf8').replace(/\r\n/g, '\n'), 'utf8');
  if (!/^[0-9a-f]{64}$/.test(str(digest)) || crypto.createHash('sha256').update(bytes).digest('hex') !== digest) {
    throw new RebrandError(REBRAND_CODES.SOURCE_MISMATCH,
      `GOAD source differs from its pinned contract: ${relativePath}. Use a checkout matching the controller pin; do not change the running fork implicitly.`,
      { sourcePath: relativePath });
  }
  return bytes;
}

function loadBaseMetadata(labName) {
  const name = canonicalGoadLabName(labName);
  if (!name || !LAB_NAME_RE.test(name) || name.includes('..')) return null;
  const dir = path.join(BASE_LABS_DIR, name), base = readSidecar(dir);
  return base ? { name, dir, base } : null;
}

/** Fresh byte buffers are verified for every compile. A checkout edited during
 * authoring cannot silently reuse cached source from an earlier compile. */
function loadBaseLab(labName) {
  const loaded = loadBaseMetadata(labName);
  if (!loaded) return null;
  const sourceDir = resolveGoadSourceDir(), files = {};
  const base = JSON.parse(fs.readFileSync(path.join(sourceDir,'scripts','cybercore','manifests',loaded.name+'.json'),'utf8'));
  loaded.base = base;
  for (const [rel, meta] of Object.entries(base.files)) {
    files[rel] = { bytes: readSourceFile(sourceDir, `${base.derived_from}/${rel}`, meta.sha256, meta.encoding),
      encoding: meta.encoding || 'utf8' };
  }
  return { ...loaded, sourceDir, files };
}

function loadExtensionBase(key) {
  const k = str(key).trim();
  if (!k || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(k)) return null;
  const dir = path.join(BASE_LABS_DIR, EXTENSIONS_DIRNAME, k);
  if (!readSidecar(dir)) return null;
  const base = JSON.parse(fs.readFileSync(path.join(resolveGoadSourceDir(),'scripts','cybercore','manifests',k+'.json'),'utf8'));
  const rel = 'data/config.json', meta = base.files[rel];
  return { key:k, dir, base,
    config:JSON.parse(readSourceFile(resolveGoadSourceDir(), `${base.derived_from}/${rel}`, meta.sha256).toString('utf8')),
    encoding:meta.encoding || 'utf8' };
}

function listExtensionBases() {
  const dir = path.join(BASE_LABS_DIR, EXTENSIONS_DIRNAME);
  return fs.existsSync(dir) ? fs.readdirSync(dir).filter(k => !!readSidecar(path.join(dir,k))).sort() : [];
}

/** The stock-name half of a rename map, read from a sidecar — never derived. */
function stockSideOf(base, labName) {
  const stock = (base && base.stock) || {};
  const hosts = {};
  for (const key of Object.keys(stock.hosts || {})) hosts[key] = stock.hosts[key].hostname;
  return {
    fqdn: stock.forest_root,
    netbios: stock.netbios,
    firstLabel: stock.first_label,
    hosts,
    labName,
  };
}

/** The needles the sweep uses for one artifact, from that artifact's sidecar. */
function residueNeedlesFor(base, labName) {
  const stock = (base && base.stock) || {};
  const needles = [stock.forest_root, stock.first_label, stock.netbios, labName];
  for (const key of Object.keys(stock.hosts || {})) needles.push(stock.hosts[key].hostname);
  return needles.filter(Boolean);
}

// ─── The minted lab name ────────────────────────────────────────────────────

/**
 * `CC-GOADMINI-CY400TEST-1a2b3c4d`.
 *
 * The `CC-` prefix is what keeps a minted name clear of goad-lab-push.js's
 * RESERVED_LAB_NAMES — upstream ships none beginning with it, now or as that
 * list grows — and pushLabTree swaps the whole ad/<name>/ directory with no
 * undo, so a collision would replace a reference lab.
 *
 * The two middle segments are COSMETIC: they exist so an operator reading a log
 * line can tell which lab and which forest without looking anything up. They
 * are capped at 16 characters, which is safe here in a way it would never be
 * for a hostname, because identity lives entirely in the hash — two different
 * renames that truncate to the same segments still get different names.
 *
 * The hash covers the transform's schema version as well as its inputs, so a
 * change to the walker re-mints the name and forces a push instead of hitting
 * pushLabTree's tree_sha256 short-circuit with stale bytes on the controller.
 */
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

/**
 * The name THIS transform would mint for (baseLab, domain), or null when it
 * would not mint one at all. Used to recognise a spec this module has already
 * stamped, so that applying the funnel twice is a no-op rather than a refusal —
 * the deploy path has a retry and an outer catch, and a funnel that threw on
 * its own output would turn a re-entry into a failed lane.
 */
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

// ─── Invariants asserted on the OUTPUT ──────────────────────────────────────

/**
 * run.sh's header states it: hosts[parent_dc].local_admin_password must equal
 * domains[parent].domain_password, because that pair is what DC promotion
 * authenticates with. It is checked on the emitted config rather than trusted
 * from the input, so a future edit to the walker that touched either field
 * fails here instead of thirty minutes into a run as "bad credentials".
 */
function assertPromotionInvariant(labObject, where) {
  const domains = labObject.domains || {};
  for (const fqdn of Object.keys(domains)) {
    const domain = domains[fqdn] || {};
    const dcKey = domain.dc;
    const host = (labObject.hosts || {})[dcKey];
    if (!host) {
      throw new RebrandError(
        REBRAND_CODES.INVARIANT,
        `${where}: domains[${JSON.stringify(fqdn)}].dc is ${JSON.stringify(dcKey)}, which is not a `
        + 'host key in this config. That value is a JOIN KEY into hosts{}, and ad-servers.yml '
        + 'resolves the promoting DC through it.',
        { where });
    }
    if (host.local_admin_password !== domain.domain_password) {
      throw new RebrandError(
        REBRAND_CODES.INVARIANT,
        `${where}: hosts.${dcKey}.local_admin_password no longer equals `
        + `domains[${JSON.stringify(fqdn)}].domain_password. run.sh's own header states that this `
        + 'pair is what makes DC promotion authenticate; when they differ the promotion fails as '
        + 'bad credentials, which traces back to nothing.',
        { where });
    }
  }
}

// ─── Extension configs ──────────────────────────────────────────────────────

/**
 * Rewrite one extension's data/config.json against an ALREADY-RENAMED main lab.
 *
 * THE BUG THIS EXISTS FOR. extensions/ws01/ansible/install.yml imports the main
 * lab's data.yml — our renamed tree — layers this file on top as
 * `lab_extension`, and then resolves:
 *
 *     member_domain:   "{{ lab.hosts[dict_key].domain }}"
 *     domain_password: "{{ lab.domains[member_domain].domain_password }}"
 *
 * Rename the forest and leave this file alone and `lab.domains` has only the
 * new root, so the second lookup is undefined and the play dies — after the
 * workstation has already been cloned, booted and waited on. lx01 goes one hop
 * further: `lab.domains[domain].dc` → `lab.hosts[dc].hostname` → `dc_fqdn`.
 * Both joins are asserted below, on the emitted pair, because a transform that
 * rewrote both files consistently-but-wrongly would satisfy every other test in
 * this module.
 *
 * THE NETBIOS PREFIX COMES FROM THE RENAMED MAIN CONFIG, not from the new
 * FQDN's first label. In stock GOAD the two coincide; ad/SCCM (`sccm.lab`,
 * netbios_name `SCCMLAB`) is the case where they do not, and taking it from the
 * main config is what makes the two files agree by construction rather than by
 * both deriving it the same way.
 *
 * @param {object|string|Buffer} vendoredExtConfig  `{ lab_extension: {...} }`
 * @param {object} renamedMainLab   the emitted main config's `lab` object
 * @param {object} renameMap        the map used for the main config
 */
function rewriteExtensionConfig(vendoredExtConfig, renamedMainLab, renameMap) {
  let config = vendoredExtConfig;
  if (Buffer.isBuffer(config)) config = JSON.parse(config.toString('utf8'));
  else if (typeof config === 'string') config = JSON.parse(config);

  if (!isPlainObject(renamedMainLab) || !isPlainObject(renamedMainLab.domains)) {
    throw new RebrandError(
      REBRAND_CODES.EXTENSION,
      'rewriteExtensionConfig needs the RENAMED main lab object (the one carrying the new '
      + '`domains` block); without it the NetBIOS prefix would have to be re-derived and the two '
      + 'files could disagree.');
  }
  const domainKeys = Object.keys(renamedMainLab.domains);
  if (!domainKeys.includes(renameMap.to.fqdn)) {
    throw new RebrandError(
      REBRAND_CODES.MULTI_DOMAIN,
      `The renamed main lab declares ${domainKeys.length} domains; an extension host joins exactly `
      + 'one and there would be no way to tell which.');
  }
  const newFqdn = renameMap.to.fqdn;
  const newNetbios = str(renamedMainLab.domains[newFqdn].netbios_name);
  if (!newNetbios) {
    throw new RebrandError(
      REBRAND_CODES.EXTENSION,
      `The renamed main lab's domain ${JSON.stringify(newFqdn)} has no netbios_name, so there is `
      + "no prefix to write into this extension's local_groups.");
  }

  // The extension's own map: the main config's `to` side for the domain, and
  // the extension sidecar's own stock/roster hostnames for its own host.
  const map = buildRenameMap(
    renameMap.from,
    { fqdn: newFqdn, netbios: newNetbios, firstLabel: newFqdn.split('.')[0], hosts: renameMap.to.hosts },
  );

  const out = rewriteLabConfig(config, map, { topKey: TOP_KEY_EXT });
  const ext = out[TOP_KEY_EXT];

  // The cross-file join, asserted on the emitted pair — this is the ws01 bug.
  for (const hostKey of Object.keys(ext.hosts || {})) {
    const memberDomain = ext.hosts[hostKey].domain;
    const domain = renamedMainLab.domains[memberDomain];
    if (!domain || !domain.domain_password) {
      throw new RebrandError(
        REBRAND_CODES.EXTENSION,
        `The emitted extension config joins ${JSON.stringify(memberDomain)}, which the renamed main `
        + 'lab does not declare. install.yml resolves domain_password as '
        + 'lab.domains[lab.hosts[dict_key].domain].domain_password, so this pair would die on an '
        + 'undefined lookup after the machine had already been cloned and booted.',
        { hostKey, memberDomain });
    }
    // lx01's second hop: domains[d].dc → hosts[dc].hostname → dc_fqdn.
    const dcHost = (renamedMainLab.hosts || {})[domain.dc];
    if (!dcHost || !dcHost.hostname) {
      throw new RebrandError(
        REBRAND_CODES.EXTENSION,
        `The renamed main lab's domain ${JSON.stringify(memberDomain)} names dc `
        + `${JSON.stringify(domain.dc)}, which has no host entry with a hostname. lx01's install.yml `
        + 'builds dc_fqdn from exactly that chain, and it only fails after the join has already '
        + 'been attempted.',
        { hostKey, memberDomain });
    }
  }
  return out;
}

// ─── The transform ──────────────────────────────────────────────────────────

/**
 * Rebrand one vendored base lab under `domain`.
 *
 * @param {object}  opts
 * @param {string}  opts.baseLab    a directory under src/data/goad-base-labs/
 * @param {string}  opts.domain     the authored forest root
 * @param {object} [opts.hostnames] hostKey → roster name; defaults to the
 *                                  sidecar's recorded roster_name for each host
 * @returns {object} `{ rebranded: true, … }`, or `{ rebranded: false, fallback }`
 *          when the domain is unusable or the lab has no vendored tree. Those
 *          two are recorded, not fatal: the lane deploys the stock lab exactly
 *          as it does today. Everything else THROWS — a structurally impossible
 *          rename must not become a forest nobody described.
 */
function buildForestMap(loaded, mapping, hostnames, labName) {
  const allHosts = stockSideOf(loaded.base, loaded.name).hosts;
  const maps = mapping.map(d => buildRenameMap({ fqdn: d.from, netbios: d.fromNetbios,
    hosts: allHosts, labName: loaded.name }, { fqdn: d.to, netbios: d.netbios, hosts: hostnames, labName }));
  return { ...maps[mapping.findIndex(d => d.kind === 'root')], domainMaps: maps };
}

/** Mask complete destination identities before detecting stale references.
 * Opaque exercise identities/passwords are never interpreted as network names. */
function assertConfigRewritten(config, map) {
  const destinations = [...domainMaps(map).flatMap(m => [m.to.fqdn, m.to.rootDn, m.to.netbios]), ...Object.values(map.to.hosts)].sort((a,b)=>b.length-a.length);
  const sources = [...domainMaps(map).flatMap(m => [m.from.fqdn, m.from.rootDn]), ...Object.values(map.from.hosts)];
  function visit(value, where) {
    if (typeof value === 'string') {
      let masked = value.toLowerCase();
      for (const d of destinations) masked = masked.split(d.toLowerCase()).join('\u0000');
      for (const needle of sources) if (masked.includes(needle.toLowerCase())) {
        throw new RebrandError(REBRAND_CODES.RESIDUE, `Unrewritten identity at ${where}`, { where, needle });
      }
    } else if (Array.isArray(value)) value.forEach((v,i)=>visit(v,`${where}[${i}]`));
    else if (isPlainObject(value)) for (const [k,v] of Object.entries(value)) {
      if (!/password|secret|^city$|^description$|^display_name$/i.test(k)) visit(v,`${where}.${k}`);
    }
  }
  visit(config, 'config');
}

function rewritePayload(bytes, map, encoding) {
  // The pinned DLL/EXE/PDB files and UTF-16 CA templates carry no forest
  // identity. Preserve their bytes, including BOMs and embedded signatures.
  if (encoding !== 'utf8') return Buffer.from(bytes);
  return bytes.toString('utf8').split(LF).map(line => {
    if (/^\s*\$(?:password|secret|keyData)\s*=/i.test(line)) return line;
    return rewriteIdentityText(line, map);
  }).join(LF);
}

function applyExtensionPrincipalMap(config, substitutions, rootDomain) {
  const out = JSON.parse(JSON.stringify(config));
  const known = new Set(['administrator', ...Object.keys(rootDomain.users || {}).map(s=>s.toLowerCase())]);
  for (const groups of Object.values(rootDomain.groups || {})) for (const name of Object.keys(groups || {})) known.add(name.toLowerCase());
  for (const host of Object.values(out.lab_extension.hosts || {})) for (const members of Object.values(host.local_groups || {})) {
    for (let i=0;i<members.length;i++) {
      const value=members[i], at=value.lastIndexOf(BACKSLASH), account=value.slice(at+1);
      const mapped=(substitutions || {})[account] || account;
      if (!known.has(mapped.toLowerCase())) throw new RebrandError(REBRAND_CODES.EXTENSION,
        `Extension principal '${mapped}' is absent from the target root domain.`);
      members[i]=value.slice(0,at+1)+mapped;
    }
  }
  return out;
}

function rebrandLab(opts) {
  const o=opts || {}, baseLabName=canonicalGoadLabName(o.baseLab), loaded=loadBaseLab(baseLabName);
  if (!loaded) return { rebranded:false, fallback:{ code:REBRAND_CODES.NO_BASE_TREE, baseLab:baseLabName,
    reason:`No pinned base tree is available for '${baseLabName}'. Clear Rename forest to deploy its stock identity.` } };
  let mapping;
  try { mapping=mappingForBase(loaded,o.domain,o.childSubdomain); }
  catch(e) { if(e.code===REBRAND_CODES.UNUSABLE_DOMAIN) return {rebranded:false,fallback:{code:e.code,reason:e.message,baseLab:baseLabName}}; throw e; }
  const root=mapping.find(d=>d.kind==='root'), hostnames={};
  for(const[key,h]of Object.entries(loaded.base.stock.hosts)) hostnames[key]=assertHostname(o.hostnames && o.hostnames[key] !== undefined ? o.hostnames[key] : h.roster_name,key);
  assertNoHostnameCollision(hostnames);
  const labName=mintLabName({baseLab:baseLabName,fqdn:root.to,netbios:root.netbios,hostnames,
    goadRef:REBRAND_SCHEMA_VERSION,domainMapping:mapping});
  const map=buildForestMap(loaded,mapping,hostnames,labName), files={}; let config;
  for(const[rel,{bytes,encoding}]of Object.entries(loaded.files)) {
    if(rel==='data/config.json') {
      config=rewriteLabConfig(JSON.parse(bytes.toString('utf8')),map);
      assertPromotionInvariant(config.lab,'renamed lab'); assertConfigRewritten(config,map);
      files[rel]=JSON.stringify(config,null,2)+LF;
    } else if(rel==='data/inventory') files[rel]=rewriteInventory(bytes.toString('utf8'),map);
    else if(rel==='providers/proxmox/inventory') files[rel]=rewriteIdentityText(bytes.toString('utf8'),map);
    else files[rel]=rewritePayload(bytes,map,encoding);
  }
  if(!config)throw new RebrandError(REBRAND_CODES.SHAPE,'Pinned GOAD lab has no data/config.json.');
  const extensionConfigs={};
  for(const key of listExtensionBases()) {
    const ext=loadExtensionBase(key), extFrom=stockSideOf(ext.base,loaded.name);
    const extHosts=Object.fromEntries(Object.entries(ext.base.stock.hosts).map(([k,h])=>[k,assertHostname(h.roster_name,k)]));
    assertNoHostnameCollision({...hostnames,...extHosts});
    const extMap=buildRenameMap(extFrom,{fqdn:root.to,netbios:root.netbios,hosts:extHosts,labName});
    const adjusted=applyExtensionPrincipalMap(ext.config,loaded.base.extension_principals?.[key],config.lab.domains[root.to]);
    const rewritten=rewriteExtensionConfig(adjusted,config.lab,extMap);
    assertConfigRewritten(rewritten,extMap); extensionConfigs[key]=JSON.stringify(rewritten,null,2)+LF;
  }
  const child=mapping.find(d=>d.kind==='child');
  return {rebranded:true,baseLab:baseLabName,labName,forestRoot:root.to,netbios:root.netbios,
    rootDn:rootDnForDomain(root.to),hostnames,chain:loaded.base.chain,goadRef:loaded.base.goad_ref,
    files,config,extensionConfigs,renameMap:map,domainMapping:mapping,
    childSubdomain:child ? child.to.slice(0,-root.to.length-1) : null,labDefinition:loaded.base.lab_definition};
}

/** A metadata-only eligibility report. The controller validates its source
 * hashes, transformed payloads and extension joins when it compiles the plan. */
function describeRebrand(spec) {
  const goad=spec?.goad;
  if(!isPlainObject(goad)||goad.rename_forest!==true)return {willRebrand:false,code:REBRAND_CODES.NOT_REQUESTED,reason:'spec.goad.rename_forest is not true'};
  const baseLab=canonicalGoadLabName(goad.version);
  const refuse=(code,reason)=>({willRebrand:false,code,reason,baseLab});
  try {
    if (goad.extensions !== undefined && (!Array.isArray(goad.extensions) || goad.extensions.some(k => !['ws01','lx01','elk','wazuh'].includes(k)) || new Set(goad.extensions).size !== goad.extensions.length)) return refuse(REBRAND_CODES.EXTENSION,'Rename forest supports only distinct ws01, lx01, elk and wazuh extension selections.');
    if(goad.prebaked===true)return refuse(REBRAND_CODES.PREBAKED,'Pre-baked NTDS cannot be renamed by changing provisioning data. Clear Rename forest or use base OS templates.');
    if(goad.rename_plan || goad.generated_lab){
      const original=goad.lab?.baseLab;
      const expected=original && expectedLabNameFor(original,goad.domain,goad.child_subdomain);
      if(compiledGoadSpecs.get(goad) === JSON.stringify(goad) && expected && expected===goad.version && goad.rename_plan?.lab_name===expected) return {
        willRebrand:false,code:REBRAND_CODES.ALREADY_REBRANDED,baseLab:original,labName:expected,
        domain:goad.lab.forestRoot,childSubdomain:goad.child_subdomain,domainMapping:goad.lab.domainMapping,
        reason:'The spec is already planned by this transform.'};
      return refuse(REBRAND_CODES.ALREADY_GENERATED,'A separately generated lab or untrusted rename plan already owns this spec. Its forest identity cannot be replaced.');
    }
    if(goad.lab)return refuse(REBRAND_CODES.ALREADY_GENERATED,'A separately compiled lab definition already owns this spec. Regenerate it to change its forest.');
    if(!LAB_NAME_RE.test(baseLab)||baseLab.includes('..'))return refuse(REBRAND_CODES.NO_BASE_TREE,'Unknown GOAD lab identity.');
    const dir=path.join(BASE_LABS_DIR,baseLab), base=fs.existsSync(dir)?readSidecar(dir):null;
    if(!base)return refuse(REBRAND_CODES.NO_BASE_TREE,`No pinned rename input for '${baseLab}'. Clear Rename forest to use its stock identity.`);
    const domainMapping=mappingForBase({name:baseLab,base},goad.domain,goad.child_subdomain);
    const root=domainMapping.find(d=>d.kind==='root'),child=domainMapping.find(d=>d.kind==='child');
    return {willRebrand:true,code:null,baseLab,domain:root.to,domainMapping,
      childSubdomain:child?child.to.slice(0,-root.to.length-1):null};
  } catch(e){return refuse(e.code||REBRAND_CODES.SHAPE,e.message);}
}

/** Plan once, in memory. No GOAD source, DB, network or runtime/deployer imports. Explicit
 * rename requests fail closed; legacy specs retain object identity. */
function rebrandGoadSpec(spec) {
  const verdict=describeRebrand(spec);
  if(!verdict.willRebrand){
    if([REBRAND_CODES.NOT_REQUESTED,REBRAND_CODES.ALREADY_REBRANDED].includes(verdict.code))return spec;
    throw new RebrandError(verdict.code,verdict.reason,{baseLab:verdict.baseLab});
  }
  const loaded=loadBaseMetadata(verdict.baseLab), manifest=loaded.base;
  const hostnames=Object.fromEntries(Object.entries(manifest.stock.hosts).map(([key,host])=>[key,assertHostname(host.roster_name,key)]));
  assertNoHostnameCollision(hostnames);
  const labName=expectedLabNameFor(verdict.baseLab,verdict.domain,verdict.childSubdomain);
  const renamePlan={schema:REBRAND_SCHEMA_VERSION,base_lab:verdict.baseLab,lab_name:labName,
    domain_mapping:verdict.domainMapping,hostnames,
    selected_extensions:Array.isArray(spec.goad.extensions) ? [...spec.goad.extensions] : []};
  renamePlan.expected_identities=Object.entries(manifest.stock.hosts).map(([key,host])=>({
    name:host.roster_name,hostname:hostnames[key],domain:verdict.domainMapping.find(d=>d.from===(host.domain||manifest.stock.forest_root)).to}));
  for(const key of renamePlan.selected_extensions) {
    const ext=readSidecar(path.join(BASE_LABS_DIR,EXTENSIONS_DIRNAME,str(key)));
    if(ext) for(const host of Object.values(ext.stock.hosts)) renamePlan.expected_identities.push({name:host.roster_name,hostname:host.roster_name,domain:verdict.domain});
  }
  const result = {...spec,goad:{...spec.goad,version:labName,domain:verdict.domain,child_subdomain:verdict.childSubdomain,
    lab:{...manifest.lab_definition,forestRoot:verdict.domain,baseLab:verdict.baseLab,
      domains:verdict.domainMapping.map(d=>d.to),domainMapping:verdict.domainMapping,childSubdomain:verdict.childSubdomain},
    rename_plan:renamePlan}};
  compiledGoadSpecs.set(result.goad, JSON.stringify(result.goad));
  return result;
}

const preflightGoadRebrand = rebrandGoadSpec;

module.exports = {
  rebrandLab,
  rebrandGoadSpec,
  preflightGoadRebrand,
  canonicalGoadLabName,
  mappingForBase,
  rewriteIdentityText,
  assertConfigRewritten,
  rebaseDn,
  rewriteExtensionConfig,
  describeRebrand,
  buildRenameMap,
  invertRenameMap,
  rewriteLabConfig,
  rewriteInventory,
  rewriteProviderInventory,
  assertNoResidue,
  assertHostname,
  assertNoHostnameCollision,
  assertPromotionInvariant,
  mintLabName,
  expectedLabNameFor,
  loadBaseLab,
  resolveGoadSourceDir,
  readSourceFile,
  loadExtensionBase,
  listExtensionBases,
  stockSideOf,
  residueNeedlesFor,
  rootDnForDomain,
  normalizeDn,
  isDnShaped,
  decodeVendored,
  RebrandError,
  REBRAND_CODES,
  REBRAND_SCHEMA_VERSION,
  BASE_LABS_DIR,
  LAB_NAME_RE,
  MAX_HOSTNAME,
  TOP_KEY_MAIN,
  TOP_KEY_EXT,
};
