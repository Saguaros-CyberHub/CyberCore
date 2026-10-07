/**
 * ============================================================================
 * ad-domain-rules.js — what a lab forest may be called, and why
 * ============================================================================
 * ONE rulebook, read by three places:
 *
 *   1. this module            — core. The Designer's create handler validates
 *                               a hand-authored forest root / child against it.
 *   2. public/js/topology/ad-domain-rules.js
 *                             — the browser mirror, so the author sees the
 *                               problem in the field instead of in a 400.
 *   3. modules/crucible/plugins/ciab/utils/goad-lab-compile.js
 *                             — Track G's compiler, which MINTS domains for a
 *                               generated lab rather than accepting authored
 *                               ones.
 *
 * Core must never require into a plugin, so (3) cannot be the shared home even
 * though it got here first. This is the same "two shapes, two readers, one
 * rule" arrangement as resolveVmSegments / deriveSegments: the duplication is
 * deliberate and test/ad-domain-rules.test.js runs a shared corpus through
 * every copy and asserts they agree. A rule changed in one and not the others
 * fails there rather than producing a forest the compiler would refuse and the
 * Designer would accept.
 *
 * ── The rules, and the failure each one prevents ────────────────────────────
 *
 * FQDN SHAPE.  Lowercase [a-z0-9] labels with internal hyphens, each ≤63
 * characters, at least two labels. Anything else is not a DNS name; AD will
 * take some of it and fail the rest at a point far from the typo.
 *
 * TLD.  /^[a-z]{2,}$/ and NOT in RESERVED_TLDS. `.local` is the one that bites
 * twice — it is mDNS-reserved (RFC 6762) AND blackholed by this platform's own
 * mail relay, so a forest named under it is both standards-violating and
 * locally undeliverable. The rest are RFC 2606 / RFC 8375 reserved names: a
 * domain field containing one is not a domain, it is a placeholder that leaked
 * out of somebody's example config.
 *
 * CHILD SHAPE — the expensive one.  A child FQDN must be EXACTLY
 * `<label>.<parent>`. GOAD's ad-child_domain.yml:20 derives `parent_domain` by
 * dropping the first label of the child, then reads
 * `lab.domains[parent].domain_password` WITH NO DEFAULT. A child whose name is
 * not that shape therefore resolves a domain that does not exist, and the whole
 * play dies — not the child stage, the play.
 *
 * SUFFIX RELATION.  Two forest ROOTS must not be suffix-related, or the second
 * is read as living inside the first's forest and ad-trusts.yml builds a trust
 * between a domain and itself.
 *
 * NETBIOS.  Derived from the first label: uppercase [A-Z0-9-], capped at 15,
 * never empty, never all digits. Windows caps it and a truncation that collides
 * with a sibling is a name nobody chose.
 *
 * ── Warning vs error: the legacy-defaults trap ──────────────────────────────
 * Every GOAD lab CyberCore ships is named under `.local` (cybersaguaros.local,
 * sevenkingdoms.local, sccm.lab is fine, dracarys.lab is fine). Those names are
 * baked into the golden images' NTDS and cannot be changed by editing a field —
 * renaming a forest is a `rendom` operation, not something done to a clone. So
 * a reserved TLD is a WARNING here, never an error: hard-failing it would make
 * every unedited legacy lab unauthorable. Genuinely malformed input — no dot, a
 * label starting with a hyphen, a numeric TLD — is an error.
 * ============================================================================
 */

'use strict';

/** Windows' hard cap on a NetBIOS domain/computer name. */
const MAX_NETBIOS_HOSTNAME = 15;

/**
 * TLDs a lab domain must never be built on.
 * Mirrors goad-lab-compile.js RESERVED_TLDS exactly — the agreement test pins
 * the two sets equal, so adding one here without adding it there fails.
 */
const RESERVED_TLDS = Object.freeze(new Set([
  'local', 'invalid', 'test', 'example', 'localhost', 'internal', 'lan', 'home', 'arpa', 'onion',
]));

/** The compiler's `str()`: null/undefined → '', everything else trimmed. */
function str(v) {
  return v === null || v === undefined ? '' : String(v).trim();
}

/**
 * The normalising half of publicDomainOf, split out so a caller can show the
 * author what their input became before it was judged. Strips a scheme, a path,
 * a trailing dot and a leading `www.` — because this field is typed by hand and
 * pasted from a browser bar at least as often as it is typed.
 */
function normaliseFqdn(raw) {
  return str(raw)
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '')
    .replace(/^www\./, '');
}

/**
 * A usable public/forest domain, or null.
 *
 * REFUSES RATHER THAN REPAIRS, for the reason goad-lab-compile states: a
 * malformed value patched into shape becomes a forest name nobody chose.
 * Byte-for-byte the same decision the compiler's publicDomainOf() makes — that
 * equivalence is the contract this module exists to hold.
 */
function publicDomainOf(raw) {
  const name = normaliseFqdn(raw);
  if (!name || name.length > 200) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(name)) return null;
  const labels = name.split('.');
  if (labels.length < 2 || labels.some((l) => l.length > 63)) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld) || RESERVED_TLDS.has(tld)) return null;
  return name;
}

/** True when one FQDN would be read as living inside the other's forest. */
function suffixRelated(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

/** A NetBIOS-legal candidate: uppercase, [A-Z0-9-], never empty, never all digits. */
function netbiosCandidate(seed) {
  const cleaned = str(seed).toUpperCase().replace(/[^A-Z0-9-]/g, '').replace(/^-+|-+$/g, '');
  if (!cleaned || /^[0-9-]+$/.test(cleaned)) return 'CORP';
  return cleaned.slice(0, MAX_NETBIOS_HOSTNAME);
}

/** The NetBIOS name a domain would get: its first label, made legal. */
function netbiosForDomain(fqdn) {
  return netbiosCandidate(normaliseFqdn(fqdn).split('.')[0]);
}

/**
 * Everything wrong with a forest root, split into what blocks a save and what
 * only warns.
 *
 * @returns {{ value:string|null, errors:string[], warnings:string[] }}
 *          `value` is the normalised FQDN when the SHAPE is legal — a reserved
 *          TLD still yields a value, because the lane deploys fine and the
 *          author may be looking at a name baked into a golden image.
 */
function checkForestRoot(raw, opts) {
  const label = (opts && opts.label) || 'Forest domain';
  const name = normaliseFqdn(raw);
  const errors = [];
  const warnings = [];

  if (!name) {
    errors.push(`${label} is required.`);
    return { value: null, errors, warnings };
  }
  if (name.length > 200) {
    errors.push(`${label} is ${name.length} characters; a DNS name tops out well before 200.`);
    return { value: null, errors, warnings };
  }
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(name)) {
    errors.push(
      `${label} "${name}" is not a DNS name. Use at least two lowercase labels separated by dots — `
      + 'letters, digits and internal hyphens only (a label may not start or end with a hyphen).'
    );
    return { value: null, errors, warnings };
  }
  const labels = name.split('.');
  const tooLong = labels.filter((l) => l.length > 63);
  if (tooLong.length) {
    errors.push(`${label}: the label "${tooLong[0]}" is ${tooLong[0].length} characters; DNS caps a label at 63.`);
    return { value: null, errors, warnings };
  }
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld)) {
    errors.push(`${label}: "${tld}" is not a usable top-level label — it must be two or more letters, no digits.`);
    return { value: null, errors, warnings };
  }
  if (RESERVED_TLDS.has(tld)) {
    // WARNING, not an error. See the header: the shipped labs are all named
    // under .local and their names live in NTDS inside a golden image.
    warnings.push(
      `${label} "${name}" ends in .${tld}, which is a reserved TLD. `
      + (tld === 'local'
        ? '.local is mDNS-reserved (RFC 6762) and blackholed by the platform mail relay, so anything '
        : 'It is an RFC 2606 / RFC 8375 reserved name, so anything ')
      + `sent to it inside the lane goes nowhere. Track G's lab compiler refuses .${tld} outright — this `
      + 'lab will author, but a generated one with the same name would not.'
    );
  }
  return { value: name, errors, warnings };
}

/**
 * Validate a child subdomain against its parent.
 *
 * Accepts either shape the UI can produce: a bare LABEL ('tumamoc' — what the
 * field has always held) or a full FQDN ('tumamoc.cybersaguaros.local'). Both
 * resolve to the same answer, and the full form is checked to be exactly
 * `<label>.<parent>` because that is the only shape ad-child_domain.yml can
 * resolve a parent from.
 *
 * @returns {{ label:string|null, fqdn:string|null, errors:string[], warnings:string[] }}
 */
function checkChild(raw, parentFqdn, opts) {
  const fieldLabel = (opts && opts.label) || 'Child subdomain';
  const errors = [];
  const warnings = [];
  const value = normaliseFqdn(raw);
  const parent = normaliseFqdn(parentFqdn);

  // Empty is legal and common — GOAD-Mini, SCCM and DRACARYS all have exactly
  // one domain. Absence must not be an error or those labs cannot be authored.
  if (!value) return { label: null, fqdn: null, errors, warnings };

  if (!parent) {
    errors.push(`${fieldLabel} "${value}" has no parent — fix the forest domain first.`);
    return { label: null, fqdn: null, errors, warnings };
  }

  let label = value;
  if (value.includes('.')) {
    // A full FQDN was typed. It must be EXACTLY one label above the parent.
    if (!value.endsWith(`.${parent}`)) {
      errors.push(
        `${fieldLabel} "${value}" is not inside "${parent}". GOAD's ad-child_domain.yml derives the parent `
        + 'by dropping the first label and then looks that domain up with no fallback, so a child that is '
        + `not literally <label>.${parent} resolves a domain that does not exist and the play dies.`
      );
      return { label: null, fqdn: null, errors, warnings };
    }
    label = value.slice(0, -(parent.length + 1));
    if (label.includes('.')) {
      errors.push(
        `${fieldLabel} "${value}" is a grandchild of "${parent}" (${label.split('.').length} labels below it). `
        + 'ad-child_domain.yml drops exactly ONE label to find the parent, so only a direct child works. '
        + `Use "${label.split('.').pop()}.${parent}", or create the intermediate domain as its own child.`
      );
      return { label: null, fqdn: null, errors, warnings };
    }
  }

  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(label)) {
    errors.push(
      `${fieldLabel} "${label}" is not a DNS label — letters, digits and internal hyphens only `
      + '(it may not start or end with a hyphen).'
    );
    return { label: null, fqdn: null, errors, warnings };
  }
  if (label.length > 63) {
    errors.push(`${fieldLabel} "${label}" is ${label.length} characters; DNS caps a label at 63.`);
    return { label: null, fqdn: null, errors, warnings };
  }

  const fqdn = `${label}.${parent}`;
  // The NetBIOS name a child gets is its LABEL, not the parent's name with the
  // label glued on — upstream's own north.sevenkingdoms.local is NORTH. Worth
  // surfacing when the label alone would not survive the cap intact.
  if (netbiosCandidate(label) !== label.toUpperCase().replace(/[^A-Z0-9-]/g, '')) {
    warnings.push(
      `${fieldLabel} "${label}" becomes NetBIOS name ${netbiosCandidate(label)} — Windows caps that name at `
      + `${MAX_NETBIOS_HOSTNAME} characters, so the domain is known by the truncation everywhere it is typed.`
    );
  }
  return { label, fqdn, errors, warnings };
}

/**
 * The whole-card check the Designer and the create handler both run.
 *
 * Returns field-shaped problems so paintTopoProblems can drop them straight
 * into #topoErrGoad, and so the route can 400 with the same sentence the author
 * already saw client-side.
 *
 * @param {{domain?:string, child_subdomain?:string}} goad
 * @returns {{ errors:string[], warnings:string[], domain:string|null,
 *             child_label:string|null, child_fqdn:string|null }}
 */
function validateGoadDomains(goad) {
  const g = goad || {};
  const root = checkForestRoot(g.domain, { label: 'Forest domain' });
  const child = root.value
    ? checkChild(g.child_subdomain, root.value, { label: 'Child subdomain' })
    // With no usable parent there is nothing to check a child against; saying so
    // once beats two errors that both mean "fix the forest domain".
    : { label: null, fqdn: null, errors: [], warnings: [] };

  return {
    errors: [...root.errors, ...child.errors],
    warnings: [...root.warnings, ...child.warnings],
    domain: root.value,
    child_label: child.label,
    child_fqdn: child.fqdn,
  };
}

module.exports = {
  MAX_NETBIOS_HOSTNAME,
  RESERVED_TLDS,
  normaliseFqdn,
  publicDomainOf,
  suffixRelated,
  netbiosCandidate,
  netbiosForDomain,
  checkForestRoot,
  checkChild,
  validateGoadDomains,
};
