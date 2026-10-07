/**
 * goad-lab-content.js - the per-lab `files/` and `scripts/` emitter.
 * ============================================================================
 * Input:  one labIR (goad-lab-compile's `ir`, after goad-attack-chain has been
 *         applied to it) and, optionally, the compiled `lab` dict.
 * Output: { 'files/...': <bytes>, 'scripts/...': <ps1> } plus the wiring the
 *         composer needs to reference them (vulns_vars.files entries and
 *         hosts[].scripts names), ready to drop into the tree pushLabTree ships.
 *
 * WHY THIS FILE EXISTS AT ALL
 * GOAD gives a lab author exactly two escape hatches, and NEITHER of them takes
 * a parameter:
 *
 *   vulns/files   ansible.windows.win_copy src -> dest. A byte-for-byte copy.
 *                 No template, no vars, no jinja. Whatever is in the file is
 *                 what lands on the guest.
 *   roles/ps      `script: "{{script_path}}/{{item}}"`. A static .ps1 executed
 *                 with no arguments, whose return value nothing reads.
 *
 * That is the whole reason every hostname, username and GPO name in upstream's
 * scripts is a hardcoded constant: `Get-ADUser -Identity "brandon.stark"`,
 * `Set-ADComputer -Identity "castelblack$"`, `New-GPO -Name "StarkWallpaper"`,
 * `netdom trust sevenkingdoms.local /d:essos.local`. It is also why the
 * CyberSaguaros reskin had to hand-edit all seven scripts alongside the JSON:
 * there is no run-time substitution to reach for. So per-client content must be
 * EMITTED, not templated. This module is the emitter.
 *
 * THE THREE RULES THAT ARE NOT NEGOTIABLE
 *
 * 1. PURE ASCII, everywhere, including the prose.
 *    Windows PowerShell 5.1 reads a BOM-less .ps1 as the ANSI code page rather
 *    than UTF-8. An em dash (U+2014) then decodes from its three UTF-8 bytes as
 *    three cp1252 characters, the last of which is U+201D RIGHT DOUBLE QUOTATION
 *    MARK - and PowerShell accepts that as a STRING DELIMITER. The string
 *    terminates early, and the parse error surfaces fifty lines later on a line
 *    that is perfectly correct. data/probe/goad-postcondition.ps1 hit exactly
 *    this and carries the same warning in its header. Adding a BOM is not the
 *    alternative: win_copy is a byte copy and the BOM rides into the guest file
 *    as a stray leading character, which breaks .env, .rdp and CSV parsers.
 *    assertAscii() is called on every emitted member before it is returned, and
 *    it reports line, column and codepoint so the offending literal is findable.
 *
 * 2. RE-RUNNABLE. Upstream states this as the lab author's contract - "be
 *    carrefull to make script than can be played multiple times in case the
 *    provisioning crash" - and the runner's entire recovery model is "replay the
 *    failed playbook", so every script here is run again every time anything
 *    downstream of it fails. Every generated .ps1 therefore READS the state
 *    before it writes it. Note the shape of the guard: already-applied is a
 *    quiet exit 0, but a missing PRECONDITION (the target user does not exist,
 *    the trust was never built) is exit 1 with a message naming the playbook
 *    that should have made it. An idempotence guard that also swallows a broken
 *    precondition is how a lab comes up green and empty.
 *
 * 3. NO SECRET WHERE IT DOES NOT BELONG.
 *    `files/` content lands on the guest's disk by design - that IS the planted
 *    artifact. `scripts/` content does not get that dispensation: roles/ps runs
 *    through the `script` module, which stages the .ps1 into the connection
 *    user's temp directory on the guest and leaves it there long enough for any
 *    authenticated user to read. So NO generated script carries a credential,
 *    and assertContentSound() proves it by searching every script for every
 *    declared secret. This is also why the six techniques below were chosen:
 *    every one of them is an attribute or an ACL, and none of them needs a
 *    password to plant.
 *
 * WHAT COUNTS AS A DECLARED SECRET
 * Every credential this module plants must already exist in the labIR (or in
 * the compiled lab dict). Inventing one breaks the seam the whole pipeline is
 * built on: the student finds a credential on the web app, sprays it at the DC,
 * and it does not exist. So the writers below never mint a password; they only
 * ever place one that AD is already being built with, and assertContentSound()
 * checks each planted value against the declared set.
 *
 * The single most dangerous value in the lab is `lab.domains[*].domain_password`
 * - it is the password of the domain administrator account Ansible itself
 * connects as, and compileLab copies it into every host's local_admin_password.
 * Planting it in an unattend.xml would hand a student Domain Admin off a file
 * share before edge 0. DOMAIN_PASSWORDS ARE NEVER PLANTED; assertContentSound()
 * treats one appearing in any member as a hard error, not a warning.
 *
 * WHY THE UNDECLARED TECHNIQUES TARGET INERT PRINCIPALS
 * Four of the six techniques (constrained delegation, RBCD, GPO abuse,
 * sIDHistory) are never requested by the attack chain, so nothing has proved
 * they do not shortcut it. goad-attack-chain.assertNoUnintendedShortcuts() ran
 * BEFORE this module existed and cannot see what we plant. The rule that keeps
 * that sound is: a technique the chain did not ask for is applied to an INERT
 * principal - one that appears in no spine edge, no decoy edge, is not the
 * foothold and is not the objective - and never to a domain controller. An
 * inert holder makes the finding real (BloodHound draws it, the probe can see
 * it) and unreachable (nothing in the graph leads to the account that holds
 * it), which is the same trick buildDecoys() plays with ACL edges.
 *
 * Two of the guards are subtler and worth naming:
 *   - undeclared unconstrained delegation goes on a USER WITH NO SPN, never on
 *     a computer. Upstream does the same (sansa.stark), and the reason is that
 *     unconstrained delegation is only abusable if something can be coerced to
 *     authenticate TO the account, which needs a service to receive it. On a
 *     member server it is a genuine path to whatever coerces it; on an SPN-less
 *     user it is a BloodHound edge that goes nowhere.
 *   - an added SPN makes its account kerberoastable, so the account that gets
 *     constrained delegation is additionally required to hold a password that
 *     is in neither CRACKABLE_PASSWORDS nor LEAKED_PASSWORDS. Otherwise the
 *     side quest cracks open with the same wordlist the intended entry uses.
 *
 * ORDER MATTERS, AND THE ARRAY IS THE ORDER
 * vulnerabilities.yml loops `lab.hosts[k].vulns` in place, so the array IS the
 * execution order, and `files` must run before anything that consumes what it
 * copied (adcs_templates.template_file, schedule.cmd, permissions on a planted
 * path). mergeLabContent() inserts `files` and re-sorts with the same rank
 * table goad-lab-validate.validateRoleOrder() enforces. The rank table is
 * duplicated here rather than imported from goad-lab-compile on purpose: the
 * composer will eventually call THIS module, and a require in this direction
 * would close a cycle. The test asserts the two agree.
 *
 * DETERMINISM IS THE CONTRACT
 * No Math.random(), no Date.now(), no I/O. Every filename, every prose variant,
 * every AES key byte is hashed off the seed through ai/profile/hash.js, so the
 * same profile regenerates a byte-identical tree. That is what makes
 * paper-vs-lane parity assertable by regeneration rather than by inspection.
 */

const crypto = require('crypto');

const { hashStr, hashInt, hashPick, hashCoin } = require('../ai/profile/hash');
const { CRACKABLE_PASSWORDS, LEAKED_PASSWORDS } = require('./goad-attack-chain');

// --- Layout -----------------------------------------------------------------

/** Tree prefixes. win_copy resolves `src` against `../ad/<LAB>/files/`, and
 *  roles/ps resolves its item against `../ad/<LAB>/scripts/`, so these two
 *  strings are the join between a tree member and the config that names it. */
const FILES_PREFIX = 'files/';
const SCRIPTS_PREFIX = 'scripts/';

/** The six techniques GOAD expresses with no role at all - there is no
 *  config.json field for any of them, only freeform PowerShell. */
const TECHNIQUES = Object.freeze([
  'asrep',
  'unconstrained_delegation',
  'constrained_delegation',
  'rbcd',
  'gpo_abuse',
  'sidhistory',
]);

/** The planted artifacts, in the order they are emitted. Named so a caller (and
 *  the answer key) can talk about "the unattend" rather than about a path. */
const ARTIFACT_KINDS = Object.freeze([
  'web_app_config',
  'share_spreadsheet',
  'unattend',
  'rdp_shortcut',
  'backup_script',
  'sysvol_logon_script',
  'sysvol_secret',
  'sysvol_key',
  'onboarding_letter',
  'credential_vault',
  'handover_note',
  'adcs_template',
]);

/**
 * The rank table from goad-lab-validate.validateRoleOrder(), mirrored.
 *
 * Duplicated rather than imported: goad-lab-compile is the module that will
 * call this one, and importing orderVulns from it would close a require cycle.
 * ciab-goad-lab-content.test.js asserts this ranking agrees with
 * goad-lab-compile.orderVulns on every pool it can build, so a future edit to
 * either one is caught at test time rather than on a lane.
 */
const ROLE_RANK = Object.freeze({ directory: 0, files: 1, permissions: 90, schedule: 91 });

/** The magic header ConvertFrom-SecureString writes in front of a
 *  key-encrypted blob. Verbatim from GOAD's own dc02/sysvol_scripts/secret.ps1;
 *  PowerShell's ConvertTo-SecureString refuses a blob without it. */
const SECURESTRING_MAGIC = '76492d1116743f0423413b16050a5345';

// --- Errors -----------------------------------------------------------------

/**
 * Modelled on LabCompileError and ChainCompileError: 409 so the HTTP skin does
 * not translate, `code` so a caller branches, `link` naming the member.
 */
class LabContentError extends Error {
  constructor(code, message, link) {
    super(message);
    this.name = 'LabContentError';
    this.code = code;
    this.link = link === undefined ? null : link;
    this.status = 409;
  }
}

function fail(code, message, link) {
  throw new LabContentError(code, message, link);
}

// --- Small helpers ----------------------------------------------------------

function isObject(v) { return !!v && typeof v === 'object' && !Array.isArray(v); }
function asArray(v) { return Array.isArray(v) ? v : []; }
function str(v) { return v === undefined || v === null ? '' : String(v); }

/** A filename/identifier atom: everything a Windows path and an Ansible loop
 *  variable both survive. Matches goad-attack-chain's idPart so a chain-declared
 *  `item` and our filename for it cannot disagree. */
function idPart(s) {
  return str(s).replace(/[^A-Za-z0-9_.-]/g, '_');
}

/**
 * A principal reduced to the name AD indexes it by: no DOMAIN\ prefix, no
 * trailing '$'.
 *
 * Both halves matter. goad-attack-chain's own bareSam() strips only the domain
 * prefix, so a delegation edge's `from` arrives here as 'NG-SRV02$' and its
 * producer item as 'unconstrained_NG-SRV02$' - feed that to Get-ADComputer
 * -Identity and the lookup fails, because the trailing '$' is part of the
 * sAMAccountName but not of the name the cmdlet resolves by default. The
 * comparison side needs the same normalisation or a computer node is compared
 * against a hostname and never matches.
 */
function bareSam(s) {
  const t = str(s);
  const i = t.lastIndexOf('\\');
  return (i === -1 ? t : t.slice(i + 1)).replace(/\$$/, '');
}

/**
 * 'amara' + 'velez' -> 'Amara Velez'.
 *
 * Display only. sAMAccountNames are never touched by this: those are matched
 * against AD byte for byte, and a title-cased one in a config file is a
 * credential that does not work.
 */
function personName(u) {
  const first = titleCase(str((u || {}).firstname));
  const last = titleCase(str((u || {}).surname));
  return `${first} ${last}`.trim() || str((u || {}).sam);
}

function titleCase(s) {
  const t = str(s);
  return t ? t.charAt(0).toUpperCase() + t.slice(1).toLowerCase() : t;
}

/** Labels that name a forest's ROLE rather than its owner, and so must never
 *  become the company name on a planted document. */
const GENERIC_DOMAIN_LABELS = Object.freeze([
  'corp', 'ad', 'int', 'intra', 'internal', 'lan', 'local', 'hq', 'dom', 'net', 'win', 'prod',
]);

/**
 * The client's name as a document would print it.
 *
 * Prefers the NetBIOS name, which goad-lab-compile derives from the company
 * slug, and falls back to the first FQDN label that is not a role label. A
 * NetBIOS name of one or two characters (a company whose slug starts with an
 * initial, e.g. "O'Fallon and Ruiz") reads as a typo on a memo, so it loses to
 * the domain label.
 */
function orgNameFor(fqdn, netbios) {
  const labels = str(fqdn).split('.').filter(Boolean);
  const named = labels.filter((l) => GENERIC_DOMAIN_LABELS.indexOf(l.toLowerCase()) === -1);
  // The public suffix (.com/.coop/.gov) is not a name either; it is only ever
  // the last label, and there is always something before it on a minted lab.
  const fromDomain = named.length > 1 ? named[0] : (named[0] || labels[0] || 'contoso');
  const nb = str(netbios);
  return titleCase(nb.length >= 3 ? nb : fromDomain);
}

/**
 * A deterministic shuffle, stable for a seed+salt.
 *
 * The inert pools are shuffled with this before anything is handed out. Without
 * it, two labs built from rosters that happen to share a name order plant the
 * same account's credential in the same artifact, and "different client, same
 * lab" is the exact failure this whole compiler exists to prevent. Fisher-Yates
 * rather than a sort comparator, because a comparator over a hash is not a
 * permutation and V8 is free to change how it uses one.
 */
function seededShuffle(seed, salt, list) {
  const out = asArray(list).slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = hashStr(seed, `${salt}:${i}`) % (i + 1);
    const t = out[i];
    out[i] = out[j];
    out[j] = t;
  }
  return out;
}

/** Deterministic sample of n distinct items, stable for a seed+salt. */
function hashSample(seed, salt, list, n) {
  const pool = list.slice();
  const out = [];
  for (let i = 0; i < n && pool.length; i += 1) {
    out.push(pool.splice(hashStr(seed, `${salt}:${i}`) % pool.length, 1)[0]);
  }
  return out;
}

// --- ASCII -----------------------------------------------------------------

/**
 * The first non-ASCII character in `text`, with enough context to find it.
 *
 * Returns null when the text is clean. Reported as line/column/codepoint rather
 * than as an offset because the failure this guards against surfaces as a
 * PowerShell parse error on a DIFFERENT line, and the only way to connect the
 * two is to be told exactly where the bad codepoint is.
 */
function firstNonAscii(text) {
  const s = str(text);
  let line = 1;
  let column = 1;
  for (let i = 0; i < s.length; i += 1) {
    const code = s.charCodeAt(i);
    if (code > 0x7f) {
      return {
        index: i,
        line,
        column,
        char: s[i],
        codepoint: code,
        hex: `U+${code.toString(16).toUpperCase().padStart(4, '0')}`,
        line_text: s.split('\n')[line - 1] || '',
      };
    }
    if (s[i] === '\n') { line += 1; column = 1; } else { column += 1; }
  }
  return null;
}

function isAscii(text) {
  return firstNonAscii(text) === null;
}

/**
 * Refuse a non-ASCII member.
 *
 * This is a THROW and not a sanitisation on purpose. Silently transliterating an
 * em dash to a hyphen would make the bug invisible in the one place it matters
 * (a prose pool somebody pasted from a document), and the next person would add
 * another one.
 */
function assertAscii(text, where) {
  const bad = firstNonAscii(text);
  if (!bad) return str(text);
  fail('CONTENT_NOT_ASCII',
    `${where}: non-ASCII character ${bad.hex} ('${bad.char}') at line ${bad.line}, column `
    + `${bad.column}. Windows PowerShell 5.1 parses a BOM-less .ps1 as the ANSI code page, where `
    + `the UTF-8 bytes of a typographic character decode to cp1252 - and U+201D is accepted as a `
    + `STRING DELIMITER, so the string terminates early and the parse fails far from here. Use `
    + `plain ASCII punctuation. Offending line: ${JSON.stringify(bad.line_text.slice(0, 120))}`,
    where);
}

// --- Deterministic bytes ----------------------------------------------------

/**
 * n deterministic bytes for this seed and salt.
 *
 * DELIBERATELY NOT crypto.randomBytes. These bytes become an AES key and IV
 * baked into a planted artifact, and the whole pipeline's parity claim is that
 * the same profile regenerates a byte-identical lab - a random key would make
 * the tree hash different on every run and break pushLabTree's content-address
 * skip. This is lab scenery, not cryptography, and it must never be reused as
 * cryptography.
 */
function seededBytes(seed, salt, n) {
  const out = Buffer.alloc(n);
  for (let i = 0; i < n; i += 1) {
    out[i] = mix32(hashStr(seed, `${salt}:byte:${i}`)) & 0xff;
  }
  return out;
}

/**
 * An avalanche step over hashStr's output, mirroring goad-lab-compile's mix32.
 *
 * hashStr is `h = h * 31 + charCode`, so two salts differing only in their last
 * character produce hashes differing only in their low bits - and taking the low
 * byte of consecutive hashes straight out of it gives a "key" like
 * 62, 193, 192, 195, 194, 197. That is not a security problem here (see the
 * warning on seededBytes) but a key file that visibly counts reads as a
 * generator artefact rather than as something captured off a share.
 */
function mix32(x) {
  let h = x >>> 0;
  h ^= h >>> 16;
  h = Math.imul(h, 0x85ebca6b) >>> 0;
  h ^= h >>> 13;
  h = Math.imul(h, 0xc2b2ae35) >>> 0;
  h ^= h >>> 16;
  return h >>> 0;
}

// --- SecureString ----------------------------------------------------------

/**
 * Reproduce `ConvertFrom-SecureString -Key`.
 *
 * The format is undocumented but stable and trivially checkable against GOAD's
 * own shipped blob:
 *   <magic> + base64( UTF16LE( "2|" + base64(iv) + "|" + hex(ciphertext) ) )
 * with the ciphertext being AES-256-CBC/PKCS7 over the UTF-16LE bytes of the
 * plaintext. Implementing it here rather than shipping a fixed blob is what
 * makes the SYSVOL secret carry THIS lab's credential: a copied blob decrypts to
 * `powerkingftw135` on every client, which is the reskin failure in miniature.
 */
function protectSecureString(plaintext, key, iv) {
  const k = Buffer.isBuffer(key) ? key : Buffer.from(key);
  const i = Buffer.isBuffer(iv) ? iv : Buffer.from(iv);
  if (k.length !== 32) fail('SECURESTRING_BAD_KEY', `ConvertFrom-SecureString key must be 32 bytes, got ${k.length}`);
  if (i.length !== 16) fail('SECURESTRING_BAD_IV', `ConvertFrom-SecureString IV must be 16 bytes, got ${i.length}`);
  const cipher = crypto.createCipheriv('aes-256-cbc', k, i);
  const ct = Buffer.concat([cipher.update(Buffer.from(str(plaintext), 'utf16le')), cipher.final()]);
  const body = `2|${i.toString('base64')}|${ct.toString('hex')}`;
  return SECURESTRING_MAGIC + Buffer.from(body, 'utf16le').toString('base64');
}

/**
 * The inverse, exported because the only honest test of "the planted secret IS
 * the declared one" is to decrypt the blob we shipped and compare.
 */
function unprotectSecureString(blob, key) {
  const s = str(blob);
  if (s.indexOf(SECURESTRING_MAGIC) !== 0) {
    fail('SECURESTRING_NO_MAGIC', 'blob does not start with the ExportedSecureString header');
  }
  const body = Buffer.from(s.slice(SECURESTRING_MAGIC.length), 'base64').toString('utf16le');
  const parts = body.split('|');
  if (parts.length !== 3) fail('SECURESTRING_MALFORMED', `expected 3 fields, got ${parts.length}`);
  const k = Buffer.isBuffer(key) ? key : Buffer.from(key);
  const decipher = crypto.createDecipheriv('aes-256-cbc', k, Buffer.from(parts[1], 'base64'));
  const pt = Buffer.concat([decipher.update(Buffer.from(parts[2], 'hex')), decipher.final()]);
  return pt.toString('utf16le');
}

// --- labIR indexing ---------------------------------------------------------

/**
 * Everything the writers need, resolved once.
 *
 * Host selection mirrors goad-attack-chain.designAttackChain's ctx exactly - the
 * same webHost predicate, the same "fall back to the DC" for the share host -
 * because an artifact planted on a different host from the one the chain's `how`
 * names is a story that does not hold.
 */
function indexIr(ir, opts) {
  const domains = asArray(ir.domains).filter(isObject);
  if (domains.length === 0) {
    fail('CONTENT_NO_DOMAIN', 'lab content: labIR.domains is empty. There is no forest to plant '
      + 'artifacts for.', 'labIR.domains');
  }
  const domain = domains.filter((d) => d.is_forest_root)[0] || domains[0];
  const fqdn = str(domain.fqdn);
  const hosts = asArray(ir.hosts).filter(isObject);
  const dcHost = hosts.filter((h) => h.key === domain.dc_host_key)[0]
    || hosts.filter((h) => h.type === 'dc' && h.domain === fqdn)[0];
  if (!dcHost) {
    fail('CONTENT_NO_DC', `lab content: domain '${fqdn}' names no DC host. Every generated script `
      + 'runs through roles/ps on the DC, because that is the only host with RSAT.',
    'labIR.domains[].dc_host_key');
  }
  const members = hosts.filter((h) => h.type !== 'dc' && (!h.domain || h.domain === fqdn));
  // The web host predicate is goad-attack-chain's, character for character. It
  // has to be: for the web_credential and kerberoast entries the chain writes
  // `plantedAt.host_key` from ITS answer, and an app config planted on a
  // different machine is a story that does not hold.
  const webHost = hosts.filter((h) => asArray(h.roles).indexOf('web') !== -1
    || /web/i.test(str(h.key)))[0] || members[0] || dcHost;
  // goad-attack-chain's shareHost, reproduced so a caller can see which host the
  // CHAIN put its own open share on. Nothing here plants against it - litter
  // goes to litterHost below - but the two answers being visibly different is
  // the point, and a future writer that does need the chain's host should read
  // this rather than re-deriving it and drifting.
  const shareHost = members[0] || dcHost;
  // Share litter has no such constraint - win_copy resolves no directory object,
  // so a spreadsheet may sit on a member of any domain in the lab. That matters
  // because NO chassis gives the forest root a member server, and litter piled
  // onto a domain controller reads as a lab fixture rather than as a file share.
  // Preferring a machine that is not the web host also spreads the two apart.
  const anyMembers = hosts.filter((h) => h.type !== 'dc');
  const litterHost = anyMembers.filter((h) => h.key !== webHost.key)[0]
    || anyMembers[0] || dcHost;

  const users = asArray((ir.principals || {}).users).filter(isObject)
    .filter((u) => !u.domain || u.domain === fqdn);
  const groups = asArray((ir.principals || {}).groups).filter(isObject)
    .filter((g) => !g.domain || g.domain === fqdn);
  const ous = asArray((ir.principals || {}).ous).filter(isObject)
    .filter((o) => !o.domain || o.domain === fqdn);

  const rootDn = dnFor(fqdn);
  // The company name that goes on every memo, runbook header and config comment.
  //
  // NOT the first FQDN label: goad-lab-compile mints the forest root as
  // `corp.<public domain>`, so that label is the literal string 'corp' on every
  // lab it has ever produced — and every planted document across every client
  // then opened with "Corp - IT Operations". That is precisely the "same
  // document, different nouns" failure this module exists to avoid. The NetBIOS
  // name is derived from the client's own company slug, so it is the identity
  // the IR actually carries; the first non-generic FQDN label is the fallback
  // for a NetBIOS name too short to read as a name.
  const org = orgNameFor(fqdn, domain.netbios);

  const allUsers = asArray((ir.principals || {}).users).filter(isObject);
  const allOus = asArray((ir.principals || {}).ous).filter(isObject);

  // ONE VIEW PER DOMAIN, AND THE TECHNIQUES NEED THEM.
  //
  // The artifacts stay in the primary domain because they have to agree with
  // the attack chain, which designs inside exactly one domain. The TECHNIQUES
  // cannot: none of the three chassis gives the forest root a member server
  // (tier S is a lone DC, and in tiers M and L every srv* belongs to a child or
  // to the second forest), so a generator that only ever looked at the root
  // would skip RBCD and constrained delegation on every lab it ever built.
  //
  // A view is what one DC can resolve. Get-ADUser / Get-ADComputer -Identity on
  // a DC searches that DC's own domain, so a script that names a child-domain
  // computer has to RUN on the child's DC - which is exactly what a view
  // records: the DC to run on, and the principals it can see.
  const views = domains.map((d) => {
    const dFqdn = str(d.fqdn);
    const dc = hosts.filter((h) => h.key === d.dc_host_key)[0]
      || hosts.filter((h) => h.type === 'dc' && h.domain === dFqdn)[0];
    if (!dc) return null;
    return {
      domain: d,
      fqdn: dFqdn,
      netbios: str(d.netbios) || dFqdn.split('.')[0].toUpperCase(),
      rootDn: dnFor(dFqdn),
      dcHost: dc,
      members: hosts.filter((h) => h.type !== 'dc' && str(h.domain) === dFqdn),
      users: allUsers.filter((u) => !u.domain || str(u.domain) === dFqdn),
      ous: allOus.filter((o) => !o.domain || str(o.domain) === dFqdn),
      is_primary: dFqdn === fqdn,
    };
  }).filter(Boolean);
  // Primary first: a technique that any domain could carry belongs where the
  // rest of the story is.
  views.sort((a, b) => (a.is_primary === b.is_primary ? 0 : (a.is_primary ? -1 : 1)));

  return {
    ir,
    lab: isObject(opts.lab) ? opts.lab : null,
    domain,
    domains,
    fqdn,
    netbios: str(domain.netbios) || fqdn.split('.')[0].toUpperCase(),
    rootDn,
    org,
    hosts,
    dcHost,
    members,
    webHost,
    shareHost,
    litterHost,
    users,
    groups,
    ous,
    views,
    chain: isObject(ir.chain) ? ir.chain : {},
    foothold: isObject(ir.foothold_credential) ? ir.foothold_credential : {},
  };
}

/** 'north.example' -> 'DC=north,DC=example'. */
function dnFor(fqdn) {
  return str(fqdn).split('.').filter(Boolean).map((l) => `DC=${l}`).join(',');
}

/**
 * Every principal the attack graph depends on: both ends of every spine edge,
 * both ends of every decoy edge, the foothold, and the objective.
 *
 * DECOYS ARE INCLUDED ON PURPOSE. A decoy's whole claim is "nothing in the graph
 * leads to this account". Planting that account's password on a file share makes
 * the claim false and turns an intended dead end into a live route to whatever
 * the decoy holds a right over.
 */
function chainPrincipals(ctx) {
  const set = new Set();
  const add = (v) => { const s = bareSam(str(v)).toLowerCase(); if (s) set.add(s); };
  const chain = ctx.chain;
  add(ctx.foothold.sam);
  add((chain.start || {}).principal);
  add((chain.objective || {}).target);
  for (const edge of asArray(chain.edges).concat(asArray(chain.decoys))) {
    add(edge.from);
    add(edge.to);
  }
  for (const plant of asArray((chain.start || {}).plants)) add(plant.item);
  return set;
}

/**
 * Roster users that hold nothing and lead nowhere - the only accounts whose
 * credentials it is safe to litter the estate with.
 *
 * "Inert" is stricter than "not on the spine": it also excludes decoy endpoints
 * (see chainPrincipals) and anyone in a privileged group, because a planted
 * credential is a route and a route to Domain Admins is not a side quest.
 */
const PRIVILEGED_GROUP = /^(domain admins|enterprise admins|administrators|schema admins|account operators|backup operators|server operators|dnsadmins)$/i;

function filterInert(claimed, users) {
  return asArray(users)
    .filter((u) => !claimed.has(bareSam(str(u.sam)).toLowerCase()))
    .filter((u) => !asArray(u.groups).some((g) => PRIVILEGED_GROUP.test(str(g).trim())))
    .filter((u) => str(u.password).length > 0);
}

function inertUsers(ctx, users) {
  return filterInert(chainPrincipals(ctx), users === undefined ? ctx.users : users);
}

/** The set of strings that may legally appear as a planted credential. */
function declaredSecrets(ir, lab) {
  const out = new Set();
  const add = (v) => { const s = str(v); if (s.length >= 4) out.add(s); };
  add((ir.foothold_credential || {}).password);
  for (const u of asArray((ir.principals || {}).users)) add(u.password);
  const chain = isObject(ir.chain) ? ir.chain : {};
  for (const plant of asArray((chain.start || {}).plants)) {
    add((plant.item_vars || {}).password);
  }
  for (const edge of asArray(chain.edges)) {
    add(((edge.created_by || {}).item_vars || {}).password);
  }
  if (isObject(lab)) {
    for (const host of Object.values(isObject(lab.hosts) ? lab.hosts : {})) {
      for (const entry of Object.values(isObject((host.vulns_vars || {}).credentials)
        ? host.vulns_vars.credentials : {})) {
        add((entry || {}).secret);
      }
    }
  }
  return out;
}

/**
 * The values that must NEVER reach a planted file.
 *
 * `domain_password` is the credential Ansible itself authenticates with
 * (vulnerabilities.yml: `domain_password: "{{lab.domains[domain].domain_password}}"`
 * paired with `domain_username: "{{domain}}\\{{admin_user}}"`), and compileLab
 * copies it verbatim into every host's local_admin_password. A student who reads
 * it off an unattend.xml holds Domain Admin before edge 0 and the entire designed
 * graph is decoration.
 */
function forbiddenSecrets(lab) {
  const out = new Set();
  if (!isObject(lab)) return out;
  for (const d of Object.values(isObject(lab.domains) ? lab.domains : {})) {
    if (str(d.domain_password)) out.add(str(d.domain_password));
  }
  for (const h of Object.values(isObject(lab.hosts) ? lab.hosts : {})) {
    if (str(h.local_admin_password)) out.add(str(h.local_admin_password));
  }
  return out;
}

// --- chain-declared requests -----------------------------------------------

/**
 * Every `vulns/files` copy the attack chain already committed to.
 *
 * These are NOT ours to name: the chain wrote `src` and `dest` into config.json
 * before we ran (`shares/it-handover.txt` for the open_share entry,
 * `templates/CIAB-ESC1.json` for the ESC1 prerequisite). If we do not emit
 * content at exactly those srcs, win_copy fails on a missing file - or worse,
 * for the ESC1 case, New-ADCSTemplate reads an empty Get-Content and the
 * win_shell task stays green having published nothing.
 */
function chainFileRequests(ir) {
  const chain = isObject(ir.chain) ? ir.chain : {};
  const out = [];
  const seen = new Set();
  const take = (producer, origin) => {
    if (!isObject(producer) || producer.role !== 'vulns/files') return;
    const vars = isObject(producer.item_vars) ? producer.item_vars : {};
    const src = str(vars.src);
    if (!src || seen.has(src)) return;
    seen.add(src);
    out.push({
      host_key: str(producer.host),
      item: str(producer.item),
      src,
      dest: str(vars.dest),
      // A plant carries its own kind ('share_file'); an edge PREREQUISITE (the
      // ESC1 template) carries none, and defaulting a missing kind to
      // 'share_file' would route the certificate template through the handover
      // writer. Absent stays absent; the caller routes on the src instead.
      kind: str(producer.kind),
      origin,
    });
  };
  for (const plant of asArray((chain.start || {}).plants)) take(plant, 'chain.start.plants');
  for (const edge of asArray(chain.edges)) {
    take(edge.created_by, `chain.edges.${edge.id}.created_by`);
    for (const pre of asArray(edge.prerequisites)) take(pre, `chain.edges.${edge.id}.prerequisites`);
  }
  return out;
}

/**
 * Every `roles/ps` script the attack chain already committed to, by the exact
 * `item` name it used. host.scripts entries carry the extension (upstream:
 * "asrep_roasting.ps1"), so the tree member is `<item>.ps1`.
 */
function chainScriptRequests(ir) {
  const chain = isObject(ir.chain) ? ir.chain : {};
  const out = [];
  const take = (producer, kindHint, origin) => {
    if (!isObject(producer) || producer.role !== 'ps') return;
    out.push({
      host_key: str(producer.host),
      item: str(producer.item),
      kind: kindHint,
      origin,
      evidence_probe: producer.evidence_probe || null,
    });
  };
  for (const plant of asArray((chain.start || {}).plants)) {
    if (plant.role === 'ps') take(plant, plant.kind === 'asrep_flag' ? 'asrep' : 'unknown', 'chain.start.plants');
  }
  for (const edge of asArray(chain.edges)) {
    if (isObject(edge.created_by) && edge.created_by.role === 'ps') {
      take(edge.created_by,
        edge.edge_type === 'delegation' ? 'unconstrained_delegation' : 'unknown',
        `chain.edges.${edge.id}`);
    }
  }
  return out;
}

// --- files/: the writers ----------------------------------------------------
//
// One function per VARIANT, not one template with a format switch. Two clients
// that land on the same artifact kind get a different file format, a different
// filename, a different set of columns or keys, and different prose - because a
// student who has seen one CiAB lab has seen the shape of its artifacts, and
// "same document, different nouns" is the reskin failure the whole compiler
// exists to avoid.

const WEB_CONFIG_VARIANTS = ['appsettings', 'webconfig', 'dotenv', 'phpconfig', 'appini'];

function writeWebConfig(ctx, seed, cred) {
  const variant = hashPick(seed, 'web:variant', WEB_CONFIG_VARIANTS);
  const dc = ctx.dcHost.hostname;
  const ldap = `${dc}.${ctx.fqdn}`;
  const appName = hashPick(seed, 'web:app', ['Portal', 'Intranet', 'ServiceDesk', 'ClientHub', 'Workbench']);
  const sqlHost = (ctx.members[1] || ctx.members[0] || ctx.dcHost).hostname;
  const account = `${ctx.netbios}\\${cred.sam}`;

  if (variant === 'appsettings') {
    return {
      name: 'appsettings.Production.json',
      dir: 'wwwroot',
      dest: `C:\\inetpub\\wwwroot\\appsettings.Production.json`,
      content: [
        '{',
        '  "Logging": {',
        '    "LogLevel": { "Default": "Information", "Microsoft.AspNetCore": "Warning" }',
        '  },',
        '  "AllowedHosts": "*",',
        '  "ConnectionStrings": {',
        `    "${appName}": "Server=${sqlHost};Database=${appName};Trusted_Connection=True;MultipleActiveResultSets=true"`,
        '  },',
        '  "DirectoryServices": {',
        `    "Server": "ldap://${ldap}:389",`,
        `    "BaseDn": "${ctx.rootDn}",`,
        // JSON-escaped, because `account` is NETBIOS\sam and a lone backslash is
        // not a legal JSON escape: the file would look right and fail to parse
        // for the student, the app and any test that reads it back. The vault
        // exporter below already does this; this variant did not.
        `    "BindAccount": "${account.replace(/\\/g, '\\\\')}",`,
        `    "BindPassword": "${cred.password}",`,
        '    "UseStartTls": false,',
        '    "ReferralChasing": "None"',
        '  },',
        '  "StaffDirectory": { "PublishDescriptionAttribute": true, "PageSize": 200 }',
        '}',
        '',
      ].join('\n'),
    };
  }
  if (variant === 'webconfig') {
    return {
      name: 'Web.config',
      dir: 'wwwroot',
      dest: 'C:\\inetpub\\wwwroot\\Web.config',
      content: [
        '<?xml version="1.0" encoding="utf-8"?>',
        '<configuration>',
        '  <appSettings>',
        `    <add key="Ldap.Server" value="${ldap}" />`,
        `    <add key="Ldap.BaseDn" value="${ctx.rootDn}" />`,
        `    <add key="Ldap.BindUser" value="${account}" />`,
        `    <add key="Ldap.BindPassword" value="${cred.password}" />`,
        '    <add key="Ldap.RequireSsl" value="false" />',
        `    <add key="App.Name" value="${ctx.org} ${appName}" />`,
        '  </appSettings>',
        '  <connectionStrings>',
        `    <add name="${appName}" connectionString="Data Source=${sqlHost};Initial Catalog=${appName};Integrated Security=SSPI" providerName="System.Data.SqlClient" />`,
        '  </connectionStrings>',
        '  <system.web>',
        '    <compilation targetFramework="4.7.2" debug="true" />',
        '    <customErrors mode="Off" />',
        '    <authentication mode="Forms" />',
        '  </system.web>',
        '</configuration>',
        '',
      ].join('\n'),
    };
  }
  if (variant === 'dotenv') {
    return {
      name: 'portal.env',
      dir: 'config',
      dest: 'C:\\inetpub\\wwwroot\\config\\portal.env',
      content: [
        `# ${ctx.org} ${appName} - runtime environment`,
        '# Deployed by the release pipeline. Do not edit by hand.',
        `APP_NAME=${ctx.org} ${appName}`,
        'APP_ENV=production',
        'APP_DEBUG=false',
        `LDAP_HOST=${ldap}`,
        'LDAP_PORT=389',
        'LDAP_TLS=false',
        `LDAP_BASE_DN=${ctx.rootDn}`,
        `LDAP_BIND_DN=${account}`,
        `LDAP_BIND_PASSWORD=${cred.password}`,
        `DB_HOST=${sqlHost}`,
        `DB_NAME=${appName.toLowerCase()}`,
        'DB_TRUSTED=1',
        'SESSION_LIFETIME=720',
        '',
      ].join('\n'),
    };
  }
  if (variant === 'phpconfig') {
    return {
      name: 'config.inc.php',
      dir: 'wwwroot',
      dest: 'C:\\inetpub\\wwwroot\\config.inc.php',
      content: [
        '<?php',
        `/* ${ctx.org} ${appName} - directory integration. */`,
        '/* TODO: move these out of the webroot before go-live. Ticket is still open. */',
        `define('LDAP_HOST', '${ldap}');`,
        "define('LDAP_PORT', 389);",
        `define('LDAP_BASE', '${ctx.rootDn}');`,
        `define('LDAP_BIND_USER', '${account}');`,
        `define('LDAP_BIND_PASS', '${cred.password}');`,
        "define('LDAP_STARTTLS', false);",
        `define('SQL_HOST', '${sqlHost}');`,
        `define('SQL_DB', '${appName.toLowerCase()}');`,
        '',
      ].join('\n'),
    };
  }
  return {
    name: 'application.ini',
    dir: 'config',
    dest: 'C:\\inetpub\\wwwroot\\config\\application.ini',
    content: [
      `; ${ctx.org} ${appName}`,
      '; Generated from the deployment template. Environment: production.',
      '',
      '[application]',
      `name = ${ctx.org} ${appName}`,
      'debug = 0',
      '',
      '[directory]',
      `host = ${ldap}`,
      'port = 389',
      'ssl = 0',
      `base_dn = ${ctx.rootDn}`,
      `bind_user = ${account}`,
      `bind_password = ${cred.password}`,
      '',
      '[database]',
      `host = ${sqlHost}`,
      `catalog = ${appName}`,
      'integrated_security = 1',
      '',
    ].join('\n'),
  };
}

const SPREADSHEET_VARIANTS = ['asset_register', 'vendor_contacts', 'rotation_tracker', 'floor_survey'];

function writeSpreadsheet(ctx, seed, cred, pointerName) {
  const variant = hashPick(seed, 'sheet:variant', SPREADSHEET_VARIANTS);
  const people = ctx.users.slice(0, 6);
  const hostRows = ctx.hosts.slice(0, 5);
  const year = 2023 + (hashStr(seed, 'sheet:year') % 3);

  if (variant === 'asset_register') {
    const rows = hostRows.map((h, i) => [
      `${ctx.netbios.slice(0, 3)}-${String(1040 + i * 7)}`,
      h.hostname,
      (people[i % Math.max(1, people.length)] || {}).sam || 'unassigned',
      h.type === 'dc' ? 'Windows Server 2019' : 'Windows Server 2019',
      hashPick(seed, `sheet:site:${i}`, ['HQ Rack A', 'HQ Rack B', 'Comms Room 2', 'Annexe']),
      `${year}-0${1 + (i % 9)}-1${i % 9}`,
      i === 1 ? `build media and answer file are in ${pointerName}` : '',
    ]);
    return {
      name: hashPick(seed, 'sheet:name', ['asset-register.csv', 'hardware-inventory.csv', 'server-list.csv']),
      content: ['Asset Tag,Hostname,Owner,Operating System,Location,Last Patched,Notes']
        .concat(rows.map((r) => r.map(csvCell).join(','))).concat(['']).join('\n'),
      secrets: [],
    };
  }
  if (variant === 'vendor_contacts') {
    const vendors = hashSample(seed, 'sheet:vendors', [
      'Northline Managed IT', 'Beacon Print Services', 'Harborview Telecom', 'Kestrel Facilities',
      'Ardent Payroll', 'Grayfield Logistics', 'Summit Copiers',
    ], 5);
    const rows = vendors.map((v, i) => [
      v,
      personName(people[i % Math.max(1, people.length)]) || 'Sam Doyle',
      `support@${v.toLowerCase().replace(/[^a-z]/g, '')}.example`,
      `555-01${String(10 + i).slice(-2)}`,
      `https://portal.${v.toLowerCase().replace(/[^a-z]/g, '')}.example`,
      `${ctx.org.toLowerCase()}-${1000 + i}`,
      i === 2 ? `login shared with the service desk, see ${pointerName}` : 'per-user logins',
    ]);
    return {
      name: hashPick(seed, 'sheet:name', ['vendor-contacts.csv', 'suppliers.csv', 'third-party-accounts.csv']),
      content: ['Vendor,Account Manager,Support Email,Phone,Portal,Customer Ref,Notes']
        .concat(rows.map((r) => r.map(csvCell).join(','))).concat(['']).join('\n'),
      secrets: [],
    };
  }
  if (variant === 'rotation_tracker' && cred) {
    const rows = [
      [`${ctx.dcHost.hostname} - directory bind`, cred.sam, `${year}-02-14`, 'IT', cred.password, `SD-${4000 + (hashStr(seed, 'sheet:t1') % 900)}`],
      [`${(ctx.members[0] || ctx.dcHost).hostname} - file services`, (people[1] || {}).sam || 'svc_files', `${year}-01-08`, 'IT', 'PENDING - not rotated', `SD-${4000 + (hashStr(seed, 'sheet:t2') % 900)}`],
      ['Backup appliance console', (people[2] || {}).sam || 'svc_backup', `${year - 1}-11-30`, 'Operations', 'see credential vault', `SD-${4000 + (hashStr(seed, 'sheet:t3') % 900)}`],
      ['Payroll portal', (people[3] || {}).sam || 'finance', `${year}-03-02`, 'Finance', 'managed by vendor', ''],
    ];
    return {
      name: hashPick(seed, 'sheet:name', ['password-rotation.csv', 'credential-review.csv', 'account-rotation-tracker.csv']),
      content: ['System,Account,Last Rotated,Rotation Owner,Current Value,Ticket']
        .concat(rows.map((r) => r.map(csvCell).join(','))).concat(['']).join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'the rotation tracker records the value in the sheet instead of the vault' }],
    };
  }
  const rows = people.slice(0, 5).map((p, i) => [
    `${hashPick(seed, `sheet:room:${i}`, ['1.04', '1.11', '2.02', '2.18', 'G.07'])}`,
    `${ctx.netbios.slice(0, 4)}-WS${String(20 + i).slice(-2)}`,
    personName(p),
    `${ctx.netbios}\\${p.sam}`,
    i === 3 ? `imaged from the standard answer file, see ${pointerName}` : '',
  ]);
  return {
    name: hashPick(seed, 'sheet:name', ['floor-survey.csv', 'desk-allocation.csv', 'workstation-handover.csv']),
    content: ['Room,Workstation,Assigned To,Domain Account,Notes']
      .concat(rows.map((r) => r.map(csvCell).join(','))).concat(['']).join('\n'),
    secrets: [],
  };
}

/** RFC4180 quoting, ASCII only. A comma inside an unquoted cell shifts every
 *  column after it, and the artifact then reads as corrupt rather than as a
 *  finding. */
function csvCell(v) {
  const s = str(v);
  return /[",\n]/.test(s) ? `"${s.replace(/"/g, '""')}"` : s;
}

/**
 * An unattend.xml on a file share.
 *
 * ONE credential, disclosed twice. The domain-join account appears in plaintext
 * under <Credentials> and again as the obfuscated <AdministratorPassword>, which
 * is exactly what an imaging engineer does when the same string is in both
 * fields - and the second one is the teaching point: the base64 is not
 * encryption, it is UTF-16LE of the password plus the literal element name.
 *
 * The local Administrator password is deliberately NOT the lab's real one. In a
 * compiled lab every host's local_admin_password IS the domain administrator's
 * password (compileLab keeps them equal so child dcpromo authenticates), so
 * planting the real value would be a one-file path to Domain Admin.
 */
function writeUnattend(ctx, seed, cred) {
  const variant = hashPick(seed, 'unattend:variant', ['unattend', 'autounattend']);
  const tz = hashPick(seed, 'unattend:tz', ['US Mountain Standard Time', 'Central Standard Time', 'Pacific Standard Time', 'Eastern Standard Time']);
  const prefix = `${ctx.netbios.slice(0, 4)}-WS`;
  const obfuscated = Buffer.from(`${cred.password}AdministratorPassword`, 'utf16le').toString('base64');
  const joinBlock = [
    '            <Identification>',
    '                <Credentials>',
    `                    <Domain>${ctx.fqdn}</Domain>`,
    `                    <Password>${cred.password}</Password>`,
    `                    <Username>${cred.sam}</Username>`,
    '                </Credentials>',
    `                <JoinDomain>${ctx.fqdn}</JoinDomain>`,
    `                <MachineObjectOU>${ctx.ous.length ? `OU=${ctx.ous[0].name},${ctx.rootDn}` : ctx.rootDn}</MachineObjectOU>`,
    '            </Identification>',
  ];
  const body = [
    '<?xml version="1.0" encoding="utf-8"?>',
    '<unattend xmlns="urn:schemas-microsoft-com:unattend">',
    '    <settings pass="specialize">',
    '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" language="neutral" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
    `            <ComputerName>${prefix}*</ComputerName>`,
    `            <RegisteredOrganization>${ctx.org}</RegisteredOrganization>`,
    `            <TimeZone>${tz}</TimeZone>`,
    '        </component>',
    '        <component name="Microsoft-Windows-UnattendedJoin" processorArchitecture="amd64" language="neutral" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
  ].concat(joinBlock).concat([
    '        </component>',
    '    </settings>',
    '    <settings pass="oobeSystem">',
    '        <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" language="neutral" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">',
    '            <UserAccounts>',
    '                <AdministratorPassword>',
    `                    <Value>${obfuscated}</Value>`,
    '                    <PlainText>false</PlainText>',
    '                </AdministratorPassword>',
    '            </UserAccounts>',
    '            <OOBE>',
    '                <HideEULAPage>true</HideEULAPage>',
    '                <ProtectYourPC>3</ProtectYourPC>',
    '            </OOBE>',
    '        </component>',
    '    </settings>',
    '</unattend>',
    '',
  ]);
  return {
    name: variant === 'unattend' ? 'unattend.xml' : 'autounattend.xml',
    content: body.join('\n'),
    secrets: [{
      value: cred.password,
      account: cred.sam,
      why: 'the answer file joins the domain with this account and reuses the same string as the '
        + 'obfuscated AdministratorPassword',
    }],
    obfuscated,
  };
}

/**
 * A saved RDP connection.
 *
 * No password: a .rdp file stores one as a DPAPI blob bound to the user and
 * machine that saved it, so a reproducible plaintext there would be a lie about
 * how Windows works. The finding is the pairing - a saved session naming a
 * privileged-looking account on a named host, next to the cached TERMSRV
 * credential the composer plants with vulns/credentials.
 */
function writeRdp(ctx, seed, account) {
  const target = ctx.members[hashStr(seed, 'rdp:target') % Math.max(1, ctx.members.length)] || ctx.dcHost;
  const withGateway = hashCoin(seed, 'rdp:gateway', 45);
  const lines = [
    'screen mode id:i:2',
    'desktopwidth:i:1920',
    'desktopheight:i:1080',
    'session bpp:i:32',
    'compression:i:1',
    'keyboardhook:i:2',
    'audiocapturemode:i:0',
    'redirectclipboard:i:1',
    'redirectprinters:i:1',
    'drivestoredirect:s:*',
    'authentication level:i:0',
    'prompt for credentials:i:0',
    'promptcredentialonce:i:1',
    `full address:s:${target.hostname}.${ctx.fqdn}`,
    `username:s:${ctx.netbios}\\${account.sam}`,
    'alternate shell:s:',
  ];
  if (withGateway) {
    lines.push(`gatewayhostname:s:rdgw.${ctx.fqdn}`);
    lines.push('gatewayusagemethod:i:1');
    lines.push('gatewaycredentialssource:i:4');
  }
  return {
    name: hashPick(seed, 'rdp:name', [
      `${target.hostname.toLowerCase()}.rdp`,
      'admin-jump.rdp',
      'server-console.rdp',
      `${ctx.org.toLowerCase()}-mgmt.rdp`,
    ]),
    content: lines.concat(['']).join('\n'),
    secrets: [],
    target: target.hostname,
    account: account.sam,
  };
}

const BACKUP_VARIANTS = ['powershell_netuse', 'cmd_netuse', 'powershell_credential'];

function writeBackupScript(ctx, seed, cred) {
  const variant = hashPick(seed, 'backup:variant', BACKUP_VARIANTS);
  const target = ctx.members[0] || ctx.dcHost;
  const share = hashPick(seed, 'backup:share', ['Backups', 'Archive', 'NightlyDump', 'Vault']);
  const unc = `\\\\${target.hostname}\\${share}$`;
  const account = `${ctx.netbios}\\${cred.sam}`;

  if (variant === 'cmd_netuse') {
    return {
      name: hashPick(seed, 'backup:name', ['nightly-backup.cmd', 'archive-run.cmd', 'copy-shares.cmd']),
      content: [
        '@echo off',
        `REM ${ctx.org} nightly file copy. Scheduled on the file server at 23:30.`,
        'REM Runs as a service account because the task server has no interactive session.',
        `net use B: ${unc} /user:${account} ${cred.password} /persistent:no`,
        'if errorlevel 1 goto :fail',
        `robocopy C:\\Departments B:\\%DATE:~-4%%DATE:~4,2%%DATE:~7,2% /MIR /R:1 /W:2 /LOG+:C:\\logs\\backup.log`,
        'net use B: /delete /y',
        'exit /b 0',
        ':fail',
        'echo Could not map the archive share >> C:\\logs\\backup.log',
        'exit /b 1',
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'the archive share is mapped with net use, so the password is an argument on every run' }],
    };
  }
  if (variant === 'powershell_credential') {
    return {
      name: hashPick(seed, 'backup:name', ['Invoke-NightlyArchive.ps1', 'Backup-Departments.ps1', 'Run-Archive.ps1']),
      content: [
        '<#',
        `    ${ctx.org} - nightly departmental archive.`,
        '    Scheduled task "Nightly Archive" on the file server, 23:30 daily.',
        '    The service account is excluded from the password policy because the task',
        '    breaks every time it rotates. Raised as a risk in the last review.',
        '#>',
        '',
        `$ArchiveShare = '${unc}'`,
        `$User         = '${account}'`,
        `$PlainText    = '${cred.password}'`,
        '',
        '$secure = ConvertTo-SecureString $PlainText -AsPlainText -Force',
        '$cred   = New-Object System.Management.Automation.PSCredential ($User, $secure)',
        '',
        "if (-not (Get-PSDrive -Name 'Archive' -ErrorAction SilentlyContinue)) {",
        "    New-PSDrive -Name 'Archive' -PSProvider FileSystem -Root $ArchiveShare -Credential $cred | Out-Null",
        '}',
        '',
        "$stamp = Get-Date -Format 'yyyyMMdd'",
        'robocopy C:\\Departments "Archive:\\$stamp" /MIR /R:1 /W:2 /NP | Out-Null',
        "Remove-PSDrive -Name 'Archive' -Force -ErrorAction SilentlyContinue",
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'ConvertTo-SecureString -AsPlainText over a literal is not protection; the string is in the file' }],
    };
  }
  return {
    name: hashPick(seed, 'backup:name', ['backup-shares.ps1', 'Sync-Archive.ps1', 'nightly-sync.ps1']),
    content: [
      `# ${ctx.org} archive job. Owner: IT Operations.`,
      '# Kept here so the on-call engineer can run it by hand when the task fails.',
      '# TODO: move the credential into the vault. Ticket has been open for two quarters.',
      '',
      `$Target = '${unc}'`,
      `$User   = '${account}'`,
      `$Pass   = '${cred.password}'`,
      '',
      'net use $Target /user:$User $Pass /persistent:no',
      'if ($LASTEXITCODE -ne 0) {',
      '    Write-Host "archive share unavailable"',
      '    exit 1',
      '}',
      '',
      "robocopy C:\\Departments $Target /MIR /R:1 /W:2 /NP | Out-Null",
      'net use $Target /delete /y | Out-Null',
      '',
    ].join('\n'),
    secrets: [{ value: cred.password, account: cred.sam, why: 'the plaintext is assigned to a variable and handed to net use' }],
  };
}

const SYSVOL_LOGON_VARIANTS = ['drive_map', 'printer_and_drive', 'sync_launcher'];

function writeSysvolLogonScript(ctx, seed, cred) {
  const variant = hashPick(seed, 'sysvol:variant', SYSVOL_LOGON_VARIANTS);
  const fileHost = (ctx.members[0] || ctx.dcHost).hostname;
  const account = `${ctx.netbios}\\${cred.sam}`;
  const letter = hashPick(seed, 'sysvol:letter', ['S', 'H', 'P', 'M', 'K']);

  if (variant === 'printer_and_drive') {
    return {
      name: hashPick(seed, 'sysvol:name', ['logon.ps1', 'user-logon.ps1', 'startup.ps1']),
      content: [
        `# ${ctx.org} logon script. Linked from the Default Domain Policy.`,
        '# Replaced the old KIX script in the migration; never got cleaned up.',
        '',
        `$FileServer = '${fileHost}'`,
        `$SvcUser    = '${account}'`,
        `$SvcPass    = '${cred.password}'`,
        '',
        `net use ${letter}: \\\\$FileServer\\Departments /user:$SvcUser $SvcPass /persistent:yes`,
        '',
        `Add-Printer -ConnectionName "\\\\$FileServer\\Reception-MFP" -ErrorAction SilentlyContinue`,
        `Add-Printer -ConnectionName "\\\\$FileServer\\Finance-MFP" -ErrorAction SilentlyContinue`,
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'the logon script maps the departmental share with an explicit service credential' }],
    };
  }
  if (variant === 'sync_launcher') {
    return {
      name: hashPick(seed, 'sysvol:name', ['sync.ps1', 'launch-sync.ps1', 'logon-tasks.ps1']),
      content: [
        `# ${ctx.org} - launches the document sync agent at logon.`,
        '# The agent needs a domain account because it writes back to the archive.',
        '',
        `$Agent    = "\\\\${fileHost}\\Apps$\\DocSync\\docsync.exe"`,
        `$RunAs    = '${account}'`,
        `$RunAsPw  = '${cred.password}'`,
        '',
        'if (Test-Path $Agent) {',
        '    $secure = ConvertTo-SecureString $RunAsPw -AsPlainText -Force',
        '    $cred   = New-Object System.Management.Automation.PSCredential ($RunAs, $secure)',
        '    Start-Process -FilePath $Agent -Credential $cred -ErrorAction SilentlyContinue',
        '}',
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'the sync agent is started with an explicit PSCredential built from a literal' }],
    };
  }
  return {
    name: hashPick(seed, 'sysvol:name', ['script.ps1', 'mapdrives.ps1', 'netlogon.ps1']),
    content: [
      `# ${ctx.org} - drive mappings applied at logon.`,
      '# Anything in NETLOGON is world-readable to authenticated users. This one has',
      '# been here since the 2019 migration.',
      '',
      `$user     = '${account}'`,
      `$password = '${cred.password}'`,
      '',
      `net use ${letter}: \\\\${fileHost}\\Shared /user:$user $password /persistent:yes`,
      `net use ${letter === 'S' ? 'T' : 'S'}: \\\\${fileHost}\\Templates /persistent:yes`,
      '',
    ].join('\n'),
    secrets: [{ value: cred.password, account: cred.sam, why: 'a plaintext credential in NETLOGON, readable by every authenticated user' }],
  };
}

/**
 * The SYSVOL SecureString pair.
 *
 * Two shapes, both real: the key inline in the same script (which is what GOAD
 * ships, and what somebody who followed a blog post does), or the key in its own
 * file next to the blob (which is what somebody who read the cmdlet's example
 * does, since ConvertFrom-SecureString's own docs write it with Out-File). The
 * second shape emits an extra tree member; that is why the artifact count itself
 * varies between seeds.
 */
function writeSysvolSecret(ctx, seed, cred) {
  const external = hashCoin(seed, 'secret:externalkey', 50);
  const key = seededBytes(seed, 'secret:key', 32);
  const iv = seededBytes(seed, 'secret:iv', 16);
  const blob = protectSecureString(cred.password, key, iv);
  const keyBytes = Array.from(key);
  const base = hashPick(seed, 'secret:name', ['secret', 'protected', 'creds']);
  const keyName = `${base}.key`;

  const head = [
    `# ${ctx.org} - stored credential for the unattended report job.`,
    '# Encrypted so it is not "in plaintext". It is still one line of PowerShell away',
    '# from being in plaintext, because the key ships with it.',
    '#',
    '# How it was made:',
    '#   $key = New-Object Byte[] 32',
    '#   [Security.Cryptography.RNGCryptoServiceProvider]::Create().GetBytes($key)',
    external ? `#   $key | Out-File "${keyName}"` : '#   (the key was pasted into this file)',
    '#   Read-Host -AsSecureString | ConvertFrom-SecureString -Key $key | Out-File "secret.encrypted"',
    '',
  ];
  const keyLine = external
    ? [
      `$keyPath = Join-Path $PSScriptRoot '${keyName}'`,
      '$keyData = [byte[]] (Get-Content $keyPath)',
    ]
    : [`$keyData = ${keyBytes.join(', ')}`];
  const tail = [
    `$secret = "${blob}"`,
    '',
    `$account = '${ctx.netbios}\\${cred.sam}'`,
    '$secure  = ConvertTo-SecureString -String $secret -Key $keyData',
    '$cred    = New-Object System.Management.Automation.PSCredential ($account, $secure)',
    '',
  ];

  return {
    name: `${base}.ps1`,
    content: head.concat(keyLine).concat(['']).concat(tail).join('\n'),
    external_key: external,
    key_name: keyName,
    key_content: external
      ? keyBytes.map((b) => String(b)).concat(['']).join('\n')
      : null,
    key_bytes: keyBytes,
    blob,
    secrets: [{
      value: cred.password,
      account: cred.sam,
      encrypted: true,
      why: external
        ? 'ConvertFrom-SecureString -Key with the key file sitting beside the blob in NETLOGON'
        : 'ConvertFrom-SecureString -Key with the key pasted into the same script as the blob',
    }],
  };
}

const LETTER_VARIANTS = ['handover_email', 'welcome_letter', 'helpdesk_ticket', 'vendor_memo'];

/**
 * The upstream arya.txt / emma.txt slot: a document that HINTS.
 *
 * It carries no credential, on purpose. Its job is navigational - it names an
 * account and names the artifact that holds that account's password - which is
 * the step a student actually has to make and the step a wordlist cannot make
 * for them. A riddle that encodes a password would be a puzzle; this is
 * reconnaissance.
 */
function writeLetter(ctx, seed, subject, pointer) {
  const variant = hashPick(seed, 'letter:variant', LETTER_VARIANTS);
  const author = ctx.users[hashStr(seed, 'letter:author') % Math.max(1, ctx.users.length)]
    || { firstname: 'Ray', surname: 'Okonkwo', sam: 'r.okonkwo' };
  const recipient = subject;
  const day = 1 + (hashStr(seed, 'letter:day') % 27);
  const month = hashPick(seed, 'letter:month', ['January', 'March', 'May', 'July', 'September', 'November']);

  if (variant === 'handover_email') {
    return {
      name: `${idPart(recipient.firstname || recipient.sam).toLowerCase()}-handover.txt`,
      content: [
        `From: ${personName(author)} <${author.sam}@${ctx.fqdn}>`,
        `To: ${personName(recipient)} <${recipient.sam}@${ctx.fqdn}>`,
        `Sent: ${month} ${day}`,
        'Subject: Handover before I finish up',
        '',
        `${titleCase(recipient.firstname)},`,
        '',
        'Friday is my last day so here is everything I have not written down anywhere sensible.',
        '',
        `The scheduled jobs on the file server all run as ${recipient.sam === author.sam ? 'the service account' : 'a service account'} - I never got round to`,
        `moving those credentials into the vault, so they are still sitting in ${pointer}`,
        'where I left them. If a job stops running that is the first place to look.',
        '',
        'Do not change the account password without checking the jobs first. The last time',
        'someone did that we lost three nights of archives before anyone noticed.',
        '',
        'Everything else is in the runbook.',
        '',
        `${titleCase(author.firstname)}`,
        '',
      ].join('\n'),
      secrets: [],
    };
  }
  if (variant === 'welcome_letter') {
    return {
      name: `welcome-${idPart(recipient.sam).toLowerCase()}.txt`,
      content: [
        `${ctx.org}`,
        'People and Culture',
        '',
        `${month} ${day}`,
        '',
        `Dear ${titleCase(recipient.firstname)},`,
        '',
        `Welcome to ${ctx.org}. Your account has been created and your line manager will`,
        'walk you through the systems you need on your first morning.',
        '',
        `Your sign-in name is ${recipient.sam}. Your starting password was set by the service`,
        'desk using the standard onboarding value - it is the same one printed in the IT',
        'starter pack, and it is written into the imaging answer file the desktop team use,',
        `which lives on the ${pointer} share. Please change it the first time you sign in.`,
        '',
        'If you have any trouble, the service desk extension is on the back of your badge.',
        '',
        'Kind regards,',
        `${personName(author)}`,
        'People and Culture',
        '',
      ].join('\n'),
      secrets: [],
    };
  }
  if (variant === 'helpdesk_ticket') {
    const ticket = 4000 + (hashStr(seed, 'letter:ticket') % 5000);
    return {
      name: `ticket-${ticket}.txt`,
      content: [
        `Ticket SD-${ticket}`,
        `Raised by: ${personName(author)} (${author.sam})`,
        `Assigned:  Service Desk`,
        `Status:    Resolved`,
        '',
        'Summary',
        `  ${personName(recipient)} cannot sign in after the laptop rebuild.`,
        '',
        'Resolution',
        `  Rebuilt from the standard image. Account ${recipient.sam} unlocked and the password`,
        '  reset to the build default rather than a random value, because the user is on site',
        '  next week and cannot collect a new one.',
        `  The build default is the one in the answer file on ${pointer}; the desktop team`,
        '  keep it there so the imaging task does not have to prompt.',
        '',
        'Follow up',
        '  Force a change at next logon. Flagged for the next access review.',
        '',
      ].join('\n'),
      secrets: [],
    };
  }
  return {
    name: `memo-${idPart(recipient.sam).toLowerCase()}.txt`,
    content: [
      'INTERNAL MEMO',
      `${ctx.org} - IT Operations`,
      `${month} ${day}`,
      '',
      `Re: shared accounts used by the out-of-hours contractor`,
      '',
      'The contractor covers the overnight window and needs to reach the archive share',
      'without waiting on one of us. Rather than create a second account we agreed they',
      `would use ${recipient.sam}, which already has the access they need.`,
      '',
      `The credential is not being emailed. It is kept with the job scripts in ${pointer}`,
      'so that whoever is on call can find it without opening a ticket.',
      '',
      'This is a temporary arrangement and should be reviewed at the end of the quarter.',
      'It has been a temporary arrangement for some time.',
      '',
    ].join('\n'),
    secrets: [],
  };
}

const VAULT_VARIANTS = ['keepass_csv', 'psd1', 'json_secrets'];

function writeVault(ctx, seed, creds) {
  const variant = hashPick(seed, 'vault:variant', VAULT_VARIANTS);
  const rows = creds.map((c, i) => ({
    group: hashPick(seed, `vault:group:${i}`, ['Servers', 'Service Accounts', 'Applications', 'Infrastructure']),
    title: hashPick(seed, `vault:title:${i}`, ['File services', 'Reporting job', 'Backup agent', 'Monitoring probe', 'Print queue manager']),
    user: `${ctx.netbios}\\${c.sam}`,
    password: c.password,
  }));

  if (variant === 'psd1') {
    const body = ['@{'];
    rows.forEach((r, i) => {
      body.push(`    Entry${i + 1} = @{`);
      body.push(`        Title    = '${r.title}'`);
      body.push(`        Username = '${r.user}'`);
      body.push(`        Password = '${r.password}'`);
      body.push(`        Group    = '${r.group}'`);
      body.push('    }');
    });
    body.push('}');
    return {
      name: hashPick(seed, 'vault:name', ['credentials.psd1', 'accounts.psd1', 'secrets.psd1']),
      content: [
        `# ${ctx.org} - credentials consumed by the operations module.`,
        '# Exported from the password manager so the scripts do not have to prompt.',
        '',
      ].concat(body).concat(['']).join('\n'),
      secrets: rows.map((r) => ({ value: r.password, account: r.user.split('\\').pop(), why: 'a password-manager export left in a data file' })),
    };
  }
  if (variant === 'json_secrets') {
    const entries = rows.map((r) => [
      '    {',
      `      "name": "${r.title}",`,
      `      "group": "${r.group}",`,
      `      "username": "${r.user.replace(/\\/g, '\\\\')}",`,
      `      "secret": "${r.password}"`,
      '    }',
    ].join('\n'));
    return {
      name: hashPick(seed, 'vault:name', ['secrets.json', 'vault-export.json', 'ops-secrets.json']),
      content: [
        '{',
        `  "exported_from": "${ctx.org} password manager",`,
        '  "format": 1,',
        '  "entries": [',
        entries.join(',\n'),
        '  ]',
        '}',
        '',
      ].join('\n'),
      secrets: rows.map((r) => ({ value: r.password, account: r.user.split('\\').pop(), why: 'a JSON export of the password manager, kept beside the scripts that read it' })),
    };
  }
  return {
    name: hashPick(seed, 'vault:name', ['vault-export.csv', 'passwords-export.csv', 'kp-export.csv']),
    content: ['"Group","Title","Username","Password","URL","Notes"']
      .concat(rows.map((r) => [
        csvQuote(r.group), csvQuote(r.title), csvQuote(r.user), csvQuote(r.password),
        csvQuote(''), csvQuote('exported for the migration, delete after'),
      ].join(',')))
      .concat(['']).join('\n'),
    secrets: rows.map((r) => ({ value: r.password, account: r.user.split('\\').pop(), why: 'a KeePass CSV export, which is plaintext by definition' })),
  };
}

function csvQuote(v) {
  return `"${str(v).replace(/"/g, '""')}"`;
}

const HANDOVER_VARIANTS = ['shift_note', 'runbook_page', 'sticky_scan'];

/**
 * The open_share entry's artifact. The chain fixed its src and dest; only the
 * prose is ours, and the credential in it MUST be the foothold's or the lab has
 * no entrance.
 */
function writeHandoverNote(ctx, seed, cred) {
  const variant = hashPick(seed, 'handover:variant', HANDOVER_VARIANTS);
  const dc = ctx.dcHost.hostname;
  if (variant === 'runbook_page') {
    return {
      content: [
        `${ctx.org} - IT runbook, page 14`,
        'Section: after-hours access',
        '',
        'If the overnight job has stalled and nobody from IT is reachable, sign in to the',
        `management console on ${dc} and restart it from there.`,
        '',
        `  account   ${ctx.netbios}\\${cred.sam}`,
        `  password  ${cred.password}`,
        '',
        'This account is deliberately not a domain administrator. It can restart the job and',
        'read the queue and nothing else.',
        '',
        'Rotate it whenever someone leaves. (Last rotation is not recorded.)',
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'the runbook page on the open share names the account and its password' }],
    };
  }
  if (variant === 'sticky_scan') {
    return {
      content: [
        'scan_20240117_0912.txt',
        '(OCR output from the reception scanner - originals shredded)',
        '',
        'IT handover - do not lose this again',
        '',
        `svc login: ${cred.sam}`,
        `pw: ${cred.password}`,
        '',
        `box: ${dc}`,
        'restart the report job from the console, not the web page',
        '',
        'ask Dee before changing anything',
        '',
      ].join('\n'),
      secrets: [{ value: cred.password, account: cred.sam, why: 'an OCR scan of a handover note, left on the open share' }],
    };
  }
  return {
    content: [
      'SHIFT HANDOVER',
      `${ctx.org} - IT operations`,
      '',
      'Outstanding',
      '  - overnight archive failed twice this week, watch it again tonight',
      '  - the new starter in Finance still has no mailbox',
      '',
      'Access',
      `  The service account for the console is ${cred.sam} and the password is`,
      `  ${cred.password}. It is written here because the vault is behind the VPN and`,
      '  the night shift cannot reach it from the floor.',
      '',
      'Escalation',
      '  Call the on-call number before touching the domain controllers.',
      '',
    ].join('\n'),
    secrets: [{ value: cred.password, account: cred.sam, why: 'the shift handover note on the anonymous share carries the credential in full' }],
  };
}

/**
 * The certificate template the ESC1 edge imports.
 *
 * Structure is the vendor's - ADCSTemplate's New-ADCSTemplate consumes exactly
 * this schema and a missing field is a template that publishes but does not
 * behave - so only the identifiers vary. The OID is seeded because two labs
 * publishing the same msPKI-Cert-Template-OID into two forests is fine in
 * isolation and confusing the moment anyone compares two answer keys.
 *
 * The flags are the whole point and are NOT seeded:
 *   msPKI-Certificate-Name-Flag 1 = ENROLLEE_SUPPLIES_SUBJECT (this is ESC1)
 *   msPKI-Enrollment-Flag       0 = no manager approval
 *   msPKI-RA-Signature          0 = no authorised signatures required
 *   pKIExtendedKeyUsage  1.3.6.1.5.5.7.3.2 = Client Authentication
 * Change any one of them and the template is safe, the role still reports green,
 * and the edge silently does not exist.
 */
function writeAdcsTemplate(ctx, seed, templateName) {
  const oid = ['1.3.6.1.4.1.311.21.8']
    .concat([0, 1, 2, 3, 4, 5, 6].map((i) => String(10000000 + (hashStr(seed, `esc1:oid:${i}`) % 89999999))))
    .join('.');
  return {
    content: [
      '{',
      `    "name":  "${templateName}",`,
      `    "displayName":  "${templateName}",`,
      '    "objectClass":  "pKICertificateTemplate",',
      '    "flags":  131616,',
      '    "revision":  100,',
      `    "msPKI-Cert-Template-OID":  "${oid}",`,
      '    "msPKI-Certificate-Application-Policy":  [',
      '                                                 "1.3.6.1.5.5.7.3.2"',
      '                                             ],',
      '    "msPKI-Certificate-Name-Flag":  1,',
      '    "msPKI-Enrollment-Flag":  0,',
      '    "msPKI-Minimal-Key-Size":  2048,',
      '    "msPKI-Private-Key-Flag":  16842752,',
      '    "msPKI-RA-Signature":  0,',
      '    "msPKI-Template-Minor-Revision":  4,',
      '    "msPKI-Template-Schema-Version":  2,',
      '    "pKICriticalExtensions":  [',
      '                                  "2.5.29.15",',
      '                                  "2.5.29.7"',
      '                              ],',
      '    "pKIDefaultCSPs":  [',
      '                           "3,Microsoft Base DSS Cryptographic Provider",',
      '                           "2,Microsoft Base Cryptographic Provider v1.0",',
      '                           "1,Microsoft Enhanced Cryptographic Provider v1.0"',
      '                       ],',
      '    "pKIDefaultKeySpec":  2,',
      '    "pKIExpirationPeriod":  [',
      '                                0, 64, 57, 135, 46, 225, 254, 255',
      '                            ],',
      '    "pKIExtendedKeyUsage":  [',
      '                                "1.3.6.1.5.5.7.3.2"',
      '                            ],',
      '    "pKIKeyUsage":  [',
      '                        128, 0',
      '                    ],',
      '    "pKIMaxIssuingDepth":  0,',
      '    "pKIOverlapPeriod":  [',
      '                             0, 128, 166, 10, 255, 222, 255, 255',
      '                         ]',
      '}',
      '',
    ].join('\n'),
    oid,
  };
}

// --- scripts/: the six techniques ------------------------------------------
//
// Every one of these is a rewrite of an upstream script with its constants
// promoted to seeded, IR-derived values, plus the guard upstream does not have.
// The reference for each is named in its own header so the next person can diff
// the two.

/** The block comment every generated script opens with. Kept identical in shape
 *  across the six so a reader who has read one can skim the rest. */
function scriptHeader(o) {
  const rule = '='.repeat(78);
  const lines = [];
  lines.push('<#');
  lines.push(rule);
  lines.push(`${o.name} - ${o.title}`);
  lines.push(rule);
  lines.push('');
  lines.push('GENERATED. Do not hand-edit: this file is re-emitted from the lab IR on every');
  lines.push(`compile, for lab ${o.lab}. Upstream reference: ${o.reference}`);
  lines.push('');
  lines.push('WHY A SCRIPT AND NOT CONFIG');
  lines.push(...wrap(o.why_script, 78));
  lines.push('');
  lines.push('WHAT THIS PLANTS');
  lines.push(...wrap(o.what, 78));
  lines.push('');
  lines.push('RE-RUN CONTRACT');
  lines.push(...wrap(
    'The runner recovers by replaying the failed playbook, so this script runs again '
    + 'every time anything after it fails. It reads state before it writes it: an '
    + 'already-applied change is a quiet exit 0, and a missing precondition is exit 1 '
    + 'naming the play that should have created it.', 78));
  lines.push('');
  lines.push('PURE ASCII');
  lines.push(...wrap(
    'Windows PowerShell 5.1 parses a BOM-less .ps1 as the ANSI code page. The UTF-8 '
    + 'bytes of an em dash decode there as three cp1252 characters ending in a right '
    + 'double quote, which PowerShell accepts as a string delimiter - the string ends '
    + 'early and the parse fails far from the cause. Keep this file ASCII.', 78));
  lines.push(rule);
  lines.push('#>');
  lines.push('');
  return lines.join('\n');
}

/** Greedy ASCII wrap. Deterministic, and it never splits a token, so a hostname
 *  or a DN stays greppable in the emitted file. */
function wrap(text, width) {
  const words = str(text).split(/\s+/).filter(Boolean);
  const out = [];
  let line = '';
  for (const w of words) {
    if (!line) { line = w; } else if ((line.length + 1 + w.length) <= width) { line += ` ${w}`; } else { out.push(line); line = w; }
  }
  if (line) out.push(line);
  return out.length ? out : [''];
}

/** A single-quoted PowerShell literal. Single quotes are the only PowerShell
 *  string form with no escapes and no interpolation, so a password-shaped value
 *  or a backslash in a DN cannot change the parse. */
function psLit(v) {
  return `'${str(v).replace(/'/g, "''")}'`;
}

function scriptAsrep(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `AS-REP roasting: DONT_REQ_PREAUTH on ${plan.target}`,
      reference: 'ad/GOAD/scripts/asrep_roasting.ps1',
      why_script: 'config.json has no field for userAccountControl. DONT_REQ_PREAUTH is reachable '
        + 'only through roles/ps, which runs a static .ps1 with no arguments - which is why '
        + 'upstream hardcodes "brandon.stark" and why this file names its target instead.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      'Import-Module ActiveDirectory',
      '',
      "$Tag    = '[asrep]'",
      `$Target = ${psLit(plan.target)}`,
      '',
      '# 0x400000 = UF_DONT_REQUIRE_PREAUTH. Read the bit rather than calling',
      '# Set-ADAccountControl unconditionally: the cmdlet is idempotent but a replay that',
      '# writes anyway makes the ansible task report changed forever, and "changed" is one',
      '# of the two signals this pipeline has.',
      '$UF_DONT_REQUIRE_PREAUTH = 0x400000',
      '',
      '$user = Get-ADUser -Identity $Target -Properties userAccountControl -ErrorAction SilentlyContinue',
      'if ($null -eq $user) {',
      '    Write-Error "$Tag account \'$Target\' does not exist. vulnerabilities.yml runs after ad.yml, so a missing target means the roster never deployed - fix that play, not this script."',
      '    exit 1',
      '}',
      '',
      'if (($user.userAccountControl -band $UF_DONT_REQUIRE_PREAUTH) -eq $UF_DONT_REQUIRE_PREAUTH) {',
      '    Write-Host "$Tag DoesNotRequirePreAuth already set on \'$Target\'"',
      '    exit 0',
      '}',
      '',
      'Set-ADAccountControl -Identity $user -DoesNotRequirePreAuth $true',
      'Write-Host "$Tag DoesNotRequirePreAuth set on \'$Target\'"',
      '',
    ].join('\n'),
  };
}

function scriptUnconstrained(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  const isComputer = plan.target_kind === 'computer';
  const getter = isComputer ? 'Get-ADComputer' : 'Get-ADUser';
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `Unconstrained delegation on ${plan.target}`,
      reference: 'ad/GOAD/scripts/unconstrained_delegation_user.ps1',
      why_script: 'TrustedForDelegation is a userAccountControl bit, and config.json models no '
        + 'account-control fields at all. roles/ps is the only way to set it, and roles/ps takes '
        + 'no parameters - so upstream hardcodes "sansa.stark" and this file names its own target.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      'Import-Module ActiveDirectory',
      '',
      "$Tag    = '[unconstrained]'",
      `$Target = ${psLit(bareSam(plan.target))}`,
      '',
      `$obj = ${getter} -Identity $Target -Properties TrustedForDelegation -ErrorAction SilentlyContinue`,
      'if ($null -eq $obj) {',
      `    Write-Error "$Tag ${isComputer ? 'computer' : 'account'} '$Target' does not exist. ${isComputer ? 'The host has not joined the domain yet - that is a members.yml problem' : 'The roster has not deployed - that is an ad.yml problem'}, not a problem with this script."`,
      '    exit 1',
      '}',
      '',
      'if ($obj.TrustedForDelegation) {',
      '    Write-Host "$Tag TrustedForDelegation already set on \'$Target\'"',
      '    exit 0',
      '}',
      '',
      'Set-ADAccountControl -Identity $obj -TrustedForDelegation $true',
      'Write-Host "$Tag TrustedForDelegation set on \'$Target\'"',
      '',
    ].join('\n'),
  };
}

function scriptConstrained(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  const spnList = plan.delegate_to.map((s) => psLit(s)).join(', ');
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `Constrained delegation${plan.protocol_transition ? ' with protocol transition' : ' (Kerberos only)'} on ${plan.identity}`,
      reference: plan.protocol_transition
        ? 'ad/GOAD/scripts/constrained_delegation_use_any.ps1'
        : 'ad/GOAD/scripts/constrained_delegation_kerb_only.ps1',
      why_script: 'msDS-AllowedToDelegateTo and TrustedToAuthForDelegation have no representation '
        + 'in config.json. Upstream sets them with two fixed scripts naming castelblack$ and '
        + 'jon.snow; here the delegating account and every target SPN come from the lab IR.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      'Import-Module ActiveDirectory',
      '',
      "$Tag      = '[constrained]'",
      `$Identity = ${psLit(plan.identity)}`,
      `$OwnSpn   = ${psLit(plan.own_spn)}`,
      `$DelegateTo = @(${spnList})`,
      `$ProtocolTransition = $${plan.protocol_transition ? 'true' : 'false'}`,
      '',
      "$props = @('ServicePrincipalNames', 'msDS-AllowedToDelegateTo', 'TrustedToAuthForDelegation')",
      '$user = Get-ADUser -Identity $Identity -Properties $props -ErrorAction SilentlyContinue',
      'if ($null -eq $user) {',
      '    Write-Error "$Tag account \'$Identity\' does not exist. The roster is built by ad.yml, which runs before this play - fix that, not this script."',
      '    exit 1',
      '}',
      '',
      '# Constrained delegation is only meaningful on an account that is itself a service,',
      '# so the SPN goes on first. -ServicePrincipalNames @{Add=...} throws on a duplicate,',
      '# which is precisely the crash a replay would hit.',
      'if ($user.ServicePrincipalNames -contains $OwnSpn) {',
      '    Write-Host "$Tag SPN already present on \'$Identity\': $OwnSpn"',
      '} else {',
      '    Set-ADUser -Identity $Identity -ServicePrincipalNames @{Add=$OwnSpn}',
      '    Write-Host "$Tag SPN added to \'$Identity\': $OwnSpn"',
      '}',
      '',
      "$current = @($user.'msDS-AllowedToDelegateTo')",
      '$missing = @($DelegateTo | Where-Object { $current -notcontains $_ })',
      'if ($missing.Count -eq 0) {',
      '    Write-Host "$Tag msDS-AllowedToDelegateTo already covers every declared SPN"',
      '} else {',
      "    Set-ADUser -Identity $Identity -Add @{'msDS-AllowedToDelegateTo'=$missing}",
      '    Write-Host "$Tag msDS-AllowedToDelegateTo extended with: $($missing -join \', \')"',
      '}',
      '',
      'if ($ProtocolTransition) {',
      '    # TrustedToAuthForDelegation is what turns this into "use any authentication',
      '    # protocol" - S4U2Self without a real client ticket. Read it back rather than',
      '    # trusting the copy fetched before the SPN write.',
      '    $again = Get-ADUser -Identity $Identity -Properties TrustedToAuthForDelegation',
      '    if ($again.TrustedToAuthForDelegation) {',
      '        Write-Host "$Tag TrustedToAuthForDelegation already set on \'$Identity\'"',
      '    } else {',
      '        Set-ADAccountControl -Identity $Identity -TrustedToAuthForDelegation $true',
      '        Write-Host "$Tag TrustedToAuthForDelegation set on \'$Identity\'"',
      '    }',
      '}',
      '',
    ].join('\n'),
  };
}

function scriptRbcd(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  const delegateGetter = plan.delegate_kind === 'computer' ? 'Get-ADComputer' : 'Get-ADUser';
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `Resource-based constrained delegation: ${plan.delegate} -> ${plan.target}`,
      reference: 'ad/GOAD/scripts/archives/rbcd.ps1 (upstream ships this file containing only "# TODO")',
      why_script: 'msDS-AllowedToActOnBehalfOfOtherIdentity is a security descriptor on the '
        + 'RESOURCE computer, and config.json has no field for it. Upstream never implemented the '
        + 'script at all, so this one is written from scratch against the IR.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      'Import-Module ActiveDirectory',
      '',
      "$Tag      = '[rbcd]'",
      `$Resource = ${psLit(bareSam(plan.target))}`,
      `$Delegate = ${psLit(bareSam(plan.delegate))}`,
      '',
      '$target = Get-ADComputer -Identity $Resource -Properties PrincipalsAllowedToDelegateToAccount -ErrorAction SilentlyContinue',
      'if ($null -eq $target) {',
      '    Write-Error "$Tag resource computer \'$Resource\' does not exist. It joins the domain in members.yml, which runs before this play."',
      '    exit 1',
      '}',
      '',
      `$principal = ${delegateGetter} -Identity $Delegate -ErrorAction SilentlyContinue`,
      'if ($null -eq $principal) {',
      '    Write-Error "$Tag delegate \'$Delegate\' does not exist, so there is nothing to grant the resource to."',
      '    exit 1',
      '}',
      '',
      '$existing = @()',
      'foreach ($p in @($target.PrincipalsAllowedToDelegateToAccount)) {',
      '    if ($null -ne $p) { $existing += $p.DistinguishedName }',
      '}',
      '',
      'if ($existing -contains $principal.DistinguishedName) {',
      '    Write-Host "$Tag \'$Delegate\' is already allowed to act on behalf of \'$Resource\'"',
      '    exit 0',
      '}',
      '',
      '# -PrincipalsAllowedToDelegateToAccount REPLACES the whole descriptor rather than',
      '# appending to it. Passing only the new principal would silently revoke every other',
      '# RBCD relationship on this computer, which on a replay is how a planted edge',
      '# disappears without any task turning red.',
      '$merged = $existing + @($principal.DistinguishedName)',
      'Set-ADComputer -Identity $target -PrincipalsAllowedToDelegateToAccount $merged',
      'Write-Host "$Tag \'$Delegate\' can now act on behalf of any user to \'$Resource\'"',
      '',
    ].join('\n'),
  };
}

function scriptGpoAbuse(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `GPO abuse: '${plan.gpo_name}' editable by ${plan.editor}`,
      reference: 'ad/GOAD/scripts/gpo_abuse.ps1',
      why_script: 'A GPO is not a config.json object. Upstream creates "StarkWallpaper" from a '
        + 'script and grants samwell.tarly GpoEditDeleteModifySecurity on it; the GPO name, the '
        + 'link target, the payload and the editor all come from the IR here.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      // Set-GPPermissions -TargetType User resolves the principal through the AD
      // provider, and the editor is verified with Get-ADUser below.
      'Import-Module ActiveDirectory',
      '',
      "$Tag        = '[gpo]'",
      `$GpoName    = ${psLit(plan.gpo_name)}`,
      `$GpoComment = ${psLit(plan.comment)}`,
      `$LinkTarget = ${psLit(plan.link_target)}`,
      `$Editor     = ${psLit(plan.editor)}`,
      `$RegKey     = ${psLit(plan.reg_key)}`,
      `$RegName    = ${psLit(plan.reg_name)}`,
      `$RegValue   = ${psLit(plan.reg_value)}`,
      '',
      '# GPMC brings the GroupPolicy module with it. Installing it unconditionally is a',
      '# multi-minute no-op on every replay, so check for the module rather than the feature.',
      "if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {",
      "    Install-WindowsFeature -Name GPMC | Out-Null",
      '}',
      'Import-Module GroupPolicy',
      '',
      '$gpo = Get-GPO -Name $GpoName -ErrorAction SilentlyContinue',
      'if ($null -eq $gpo) {',
      '    $gpo = New-GPO -Name $GpoName -Comment $GpoComment',
      '    Write-Host "$Tag created GPO \'$GpoName\'"',
      '} else {',
      '    Write-Host "$Tag GPO \'$GpoName\' already exists"',
      '}',
      '',
      '# Upstream guards its ENTIRE body on the GPO existing, so a crash between New-GPO and',
      '# New-GPLink leaves an unlinked, unpermissioned GPO that no replay ever repairs - the',
      '# lab then has a GPO nobody can abuse and nothing reports it. Each step below is',
      '# guarded on its own state instead.',
      '$linked = $false',
      '$inheritance = Get-GPInheritance -Target $LinkTarget -ErrorAction SilentlyContinue',
      'if ($null -eq $inheritance) {',
      '    Write-Error "$Tag link target \'$LinkTarget\' does not exist. OUs are created by ad.yml before this play."',
      '    exit 1',
      '}',
      'foreach ($link in $inheritance.GpoLinks) {',
      '    if ($link.DisplayName -eq $GpoName) { $linked = $true }',
      '}',
      'if ($linked) {',
      '    Write-Host "$Tag \'$GpoName\' is already linked to \'$LinkTarget\'"',
      '} else {',
      '    New-GPLink -Name $GpoName -Target $LinkTarget | Out-Null',
      '    Write-Host "$Tag linked \'$GpoName\' to \'$LinkTarget\'"',
      '}',
      '',
      '# Set-GPRegistryValue and Set-GPPermissions both write the value they are given, so',
      '# they are already replay-safe. They are still last: a GPO with no setting and no',
      '# delegated editor is inert, and doing them after the link means a partial run leaves',
      '# the visible half missing rather than the exploitable half.',
      '$null = Set-GPRegistryValue -Name $GpoName -Key $RegKey -ValueName $RegName -Type String -Value $RegValue',
      "$null = Set-GPRegistryValue -Name $GpoName -Key 'HKEY_LOCAL_MACHINE\\Software\\Policies\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' -ValueName 'SyncForegroundPolicy' -Type DWord -Value 1",
      '',
      '$target = Get-ADUser -Identity $Editor -ErrorAction SilentlyContinue',
      'if ($null -eq $target) {',
      '    Write-Error "$Tag editor \'$Editor\' does not exist, so the delegation cannot be granted."',
      '    exit 1',
      '}',
      "$null = Set-GPPermissions -Name $GpoName -PermissionLevel GpoEditDeleteModifySecurity -TargetName $Editor -TargetType 'User'",
      'Write-Host "$Tag \'$Editor\' can now edit, delete and re-secure \'$GpoName\'"',
      '',
    ].join('\n'),
  };
}

function scriptSidHistory(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `SID history across the ${plan.trusting} <- ${plan.trusted} trust`,
      reference: 'ad/GOAD/scripts/sidhistory.ps1',
      why_script: 'SID filtering is a property of the trust object, set with netdom. There is no '
        + 'config.json field and no Ansible module for it - upstream runs one bare netdom line '
        + 'naming sevenkingdoms.local and essos.local.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      'Import-Module ActiveDirectory',
      '',
      "$Tag      = '[sidhistory]'",
      `$Trusting = ${psLit(plan.trusting)}`,
      `$Trusted  = ${psLit(plan.trusted)}`,
      '',
      '# Filter in PowerShell rather than in -Filter: the AD provider filter language',
      '# quotes differently from PowerShell and a domain name with a hyphen in it silently',
      '# matches nothing there.',
      '$trust = Get-ADTrust -Filter * | Where-Object { $_.Target -eq $Trusted } | Select-Object -First 1',
      'if ($null -eq $trust) {',
      '    Write-Error "$Tag no trust to \'$Trusted\' exists on \'$Trusting\'. ad-trusts.yml builds the trust and must run before this play; a replay cannot fix an ordering problem."',
      '    exit 1',
      '}',
      '',
      '# netdom is idempotent, but reading the flags first keeps a replay quiet and makes',
      '# the already-applied case distinguishable from the case where netdom silently',
      '# refused.',
      'if ((-not $trust.SIDFilteringQuarantined) -and (-not $trust.SIDFilteringForestAware)) {',
      '    Write-Host "$Tag SID filtering is already off for \'$Trusted\'"',
      '    exit 0',
      '}',
      '',
      'netdom trust $Trusting /d:$Trusted /enablesidhistory:yes',
      'if ($LASTEXITCODE -ne 0) {',
      '    Write-Error "$Tag netdom exited $LASTEXITCODE. Run it by hand on the forest root to see which side refused."',
      '    exit 1',
      '}',
      'Write-Host "$Tag SID history enabled for \'$Trusted\' into \'$Trusting\'"',
      '',
    ].join('\n'),
  };
}

/**
 * The coercion bot, emitted only when the chain actually carries an
 * unconstrained-delegation edge.
 *
 * UPSTREAM'S BOTS CARRY A PASSWORD AND THIS ONE MUST NOT. rdp_scheduler.ps1 and
 * ntlm_relay.ps1 both call Register-ScheduledTask -User ... -Password with a
 * literal, and roles/ps stages a script into the connection user's temp
 * directory on the guest - so a credential in one of these is a credential on
 * disk somewhere nobody chose. Running the task as SYSTEM removes the need for a
 * password entirely, and it is also the RIGHT principal: SYSTEM authenticates as
 * the machine account, so the DC's own TGT is what lands in the delegating
 * host's cache, which is what the chain's delegation edge is about.
 */
function scriptCoercionBot(ctx, seed, plan) {
  const name = `${plan.item}.ps1`;
  return {
    name,
    content: scriptHeader({
      name,
      lab: ctx.ir.lab_name || 'this lab',
      title: `Coercion bot: ${plan.run_on_hostname} reaches ${plan.unc} every ${plan.interval_minutes} minute(s)`,
      reference: 'ad/GOAD/scripts/rdp_scheduler.ps1 and ad/GOAD/scripts/responder.ps1',
      why_script: 'A scheduled task is not a config.json object. Upstream schedules its bots from '
        + 'freeform PowerShell and hardcodes the bot account, its password, the interval and the '
        + 'UNC path; all four are IR-derived here and the password is gone.',
      what: plan.why,
    }) + [
      "$ErrorActionPreference = 'Stop'",
      '',
      "$Tag      = '[coercionbot]'",
      `$TaskName = ${psLit(plan.task_name)}`,
      `$UncPath  = ${psLit(plan.unc)}`,
      `$Minutes  = ${plan.interval_minutes}`,
      '',
      '# SYSTEM, not a domain user: Register-ScheduledTask -User SYSTEM needs no password,',
      '# and the resulting network authentication comes from the machine account, which is',
      '# the ticket the delegating host is meant to capture.',
      "$action   = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument \"/c dir $UncPath\"",
      '$repeat   = New-TimeSpan -Minutes $Minutes',
      '$trigger  = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval $repeat',
      '$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd',
      '',
      '# Unregister-then-register rather than "skip if it exists": the interval and the UNC',
      '# path are regenerated on every compile, so an old task from a previous tree would',
      '# keep pointing at the previous lab and nothing would say so.',
      '$existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue',
      'if ($null -ne $existing) {',
      '    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false',
      '    Write-Host "$Tag removed the previous \'$TaskName\'"',
      '}',
      '',
      "$null = Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -User 'SYSTEM' -RunLevel Highest -Settings $settings",
      '',
      '# Read it back. A task that failed to register is the one failure mode with no',
      '# downstream signal at all: the delegation edge is still planted, the probe still',
      '# passes, and the lab simply never produces the authentication the exercise is',
      '# built around.',
      '$check = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue',
      'if ($null -eq $check) {',
      '    Write-Error "$Tag \'$TaskName\' did not register. Nothing will authenticate to $UncPath, so the delegation edge has no traffic to capture and the last hop of the chain cannot be exercised."',
      '    exit 1',
      '}',
      'Write-Host "$Tag \'$TaskName\' reaches $UncPath every $Minutes minute(s) as SYSTEM"',
      '',
    ].join('\n'),
  };
}

// --- technique planning -----------------------------------------------------

const GPO_TOPICS = Object.freeze([
  { suffix: 'Desktop Standards', key: 'HKEY_CURRENT_USER\\Control Panel\\Desktop', name: 'Wallpaper', value: '\\\\{{FILE_HOST}}\\Branding$\\desktop.jpg', about: 'desktop wallpaper' },
  { suffix: 'Screen Lock Policy', key: 'HKEY_CURRENT_USER\\Control Panel\\Desktop', name: 'ScreenSaveTimeOut', value: '900', about: 'screen saver timeout' },
  { suffix: 'Logon Banner', key: 'HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System', name: 'legalnoticecaption', value: 'Authorised users only', about: 'the interactive logon banner' },
  { suffix: 'Drive Mappings', key: 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows\\Explorer', name: 'DisableSearchBoxSuggestions', value: '1', about: 'Explorer behaviour' },
  { suffix: 'Print Defaults', key: 'HKEY_CURRENT_USER\\Software\\Policies\\Microsoft\\Windows NT\\Printers', name: 'DefaultPrinter', value: 'Reception-MFP', about: 'the default printer' },
]);

const SPN_SERVICES = Object.freeze(['HTTP', 'CIFS', 'MSSQLSvc', 'HOST', 'LDAP']);

/**
 * Decide, for each of the six techniques, what it acts on.
 *
 * Chain-declared items win outright: their `item` name is already written into
 * config.json's hosts[].scripts by whoever lowers the chain, and a filename that
 * does not match is a script Ansible looks for and never finds. Everything else
 * gets an inert principal (see the module header).
 */
function planTechniques(ctx, seed, warnings) {
  const declared = chainScriptRequests(ctx.ir);
  const byKind = {};
  for (const d of declared) byKind[d.kind] = d;

  const wordlist = new Set(
    asArray(CRACKABLE_PASSWORDS).concat(asArray(LEAKED_PASSWORDS)).map((p) => str(p)));
  const claimedPrincipals = chainPrincipals(ctx);

  // One inert pool per domain view, each with its own cursor, so two techniques
  // never land on the same account: a single principal carrying three unrelated
  // weaknesses reads as a generator artefact rather than as an estate.
  const pools = new Map();
  const poolFor = (view) => {
    if (!pools.has(view.fqdn)) {
      pools.set(view.fqdn, {
        list: seededShuffle(seed, `technique-pool:${view.fqdn}`, filterInert(claimedPrincipals, view.users)),
        cursor: 0,
      });
    }
    return pools.get(view.fqdn);
  };
  const takeFrom = (view, predicate) => {
    const pool = poolFor(view);
    for (let i = pool.cursor; i < pool.list.length; i += 1) {
      if (!predicate || predicate(pool.list[i])) { pool.cursor = i + 1; return pool.list[i]; }
    }
    return null;
  };
  // Peek without consuming: a view has to be CHOSEN before it is committed to,
  // and choosing by taking would burn an account out of a view we then reject.
  const hasFree = (view, predicate) => {
    const pool = poolFor(view);
    for (let i = pool.cursor; i < pool.list.length; i += 1) {
      if (!predicate || predicate(pool.list[i])) return true;
    }
    return false;
  };
  // Machines a technique may act ON. Domain controllers are excluded everywhere
  // (RBCD or unconstrained delegation onto a DC is one step to the whole
  // domain), and so is any machine the graph already uses: the delegation
  // pattern binds the penultimate node to a member server's COMPUTER account,
  // and a second delegation primitive on that same machine would hand a student
  // the chain's last hop from a side quest.
  const isFreeMachine = (h) => h.type !== 'dc'
    && !claimedPrincipals.has(bareSam(str(h.hostname)).toLowerCase());
  const freeMembersOf = (view) => view.members.filter(isFreeMachine);
  const anyFreeMachine = ctx.hosts.filter(isFreeMachine);
  const pickView = (need) => ctx.views.filter(need)[0] || null;
  const plans = [];

  // -- AS-REP ---------------------------------------------------------------
  if (byKind.asrep) {
    const item = byKind.asrep.item;
    const target = item.replace(/^asrep_/, '');
    plans.push({
      technique: 'asrep',
      item,
      host_key: byKind.asrep.host_key || ctx.dcHost.key,
      declared_by_chain: true,
      target,
      targets: { user: target },
      modifies: { user: target },
      why: `${target} is the chain's entry point: the AS-REP is the first hash a student can `
        + 'request without any credential at all, and the account password is in the wordlist '
        + 'the exercise assumes.',
      probe: byKind.asrep.evidence_probe || null,
    });
  } else {
    const notCrackable = (u) => !wordlist.has(str(u.password));
    const view = pickView((v) => hasFree(v, notCrackable));
    const victim = view ? takeFrom(view, notCrackable) : null;
    if (victim && view) {
      plans.push({
        technique: 'asrep',
        item: `asrep_${idPart(victim.sam)}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        target: victim.sam,
        targets: { user: victim.sam },
        modifies: { user: victim.sam },
        dead_ends_because: `${victim.sam}'s password is not in any wordlist this exercise ships, `
          + 'so the AS-REP hash is real, roastable and will not crack in the time available.',
        why: `${victim.sam} predates the current identity standard and was never migrated, so it `
          + 'still has pre-authentication disabled. The hash is genuinely obtainable; the account '
          + 'is not, which is the point.',
        probe: {
          id: `content:asrep:${idPart(victim.sam)}`,
          kind: 'asrep',
          run_on: view.dcHost.key,
          host: view.dcHost.key,
          domain: view.fqdn,
          role: 'ps',
          user: victim.sam,
          why: 'an undeclared script that silently did nothing is a finding nobody can make',
        },
      });
    } else {
      warnings.push('asrep skipped: every roster account is either on the attack graph or holds a '
        + 'wordlist password, and making one of those roastable would shortcut the chain');
    }
  }

  // -- unconstrained delegation ---------------------------------------------
  if (byKind.unconstrained_delegation) {
    // The chain's item is `unconstrained_<sam>` and a computer's sam keeps its
    // trailing '$' - so the FILENAME must stay exactly as the chain wrote it
    // (hosts[].scripts has to name a file that exists), while the identity the
    // script resolves must not.
    const item = byKind.unconstrained_delegation.item;
    const bare = bareSam(item.replace(/^unconstrained_/, ''));
    const host = ctx.hosts.filter((h) => bareSam(str(h.hostname)).toLowerCase() === bare.toLowerCase())[0];
    plans.push({
      technique: 'unconstrained_delegation',
      item,
      host_key: byKind.unconstrained_delegation.host_key || ctx.dcHost.key,
      declared_by_chain: true,
      target: bare,
      target_kind: host ? 'computer' : 'user',
      targets: host ? { computer: bare } : { user: bare },
      why: `${bare} is trusted for unconstrained delegation, so anything coerced into `
        + "authenticating to it leaves that principal's TGT in its cache. This is the chain's "
        + 'final hop and it is not optional.',
      probe: byKind.unconstrained_delegation.evidence_probe || null,
    });
  } else {
    // An SPN-less USER, never a computer. See the module header: on a member
    // server this is a live route to whatever can be coerced; on a user with no
    // service to receive the authentication it is a BloodHound edge and nothing
    // more, which is exactly what upstream plants on sansa.stark.
    const spnless = (u) => asArray(u.spns).length === 0;
    const view = pickView((v) => hasFree(v, spnless));
    const victim = view ? takeFrom(view, spnless) : null;
    if (victim && view) {
      plans.push({
        technique: 'unconstrained_delegation',
        item: `unconstrained_${idPart(victim.sam)}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        target: victim.sam,
        target_kind: 'user',
        targets: { user: victim.sam },
        modifies: { user: victim.sam },
        dead_ends_because: `${victim.sam} holds no SPN, so nothing can be coerced into `
          + 'authenticating to the account and there is no ticket cache to raid. BloodHound will '
          + 'still draw it.',
        why: `${victim.sam} was flagged for delegation during an application migration and the `
          + 'flag was never removed. It is a real misconfiguration that happens to be inert.',
        probe: {
          id: `content:delegation:unconstrained:${idPart(victim.sam)}`,
          kind: 'delegation',
          run_on: view.dcHost.key,
          host: view.dcHost.key,
          domain: view.fqdn,
          role: 'ps',
          principal: victim.sam,
          delegation: 'unconstrained',
          why: 'the flag is set by a freeform script, so nothing else can confirm it landed',
        },
      });
    } else {
      warnings.push('unconstrained_delegation skipped: no inert SPN-less account is available, and '
        + 'putting the flag on a computer or on a graph principal would create a path the chain '
        + 'designer never proved');
    }
  }

  // -- constrained delegation ----------------------------------------------
  {
    // The SPNs in msDS-AllowedToDelegateTo are cross-domain by construction -
    // a service ticket is requested by name, not by directory scope - so the
    // TARGET may live anywhere in the lab. Only the delegating account has to be
    // resolvable by the DC that runs the script.
    const notCrackable = (u) => !wordlist.has(str(u.password));
    const view = pickView((v) => hasFree(v, notCrackable));
    const identity = view ? takeFrom(view, notCrackable) : null;
    const hostPool = view && freeMembersOf(view).length ? freeMembersOf(view) : anyFreeMachine;
    const target = hostPool[hashStr(seed, 'constrained:target') % Math.max(1, hostPool.length)];
    if (identity && target && view) {
      const service = hashPick(seed, 'constrained:service', ['CIFS', 'HTTP', 'HOST']);
      const ownService = hashPick(seed, 'constrained:ownservice', SPN_SERVICES.slice());
      plans.push({
        technique: 'constrained_delegation',
        item: `constrained_delegation_${idPart(identity.sam)}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        identity: identity.sam,
        protocol_transition: hashCoin(seed, 'constrained:transition', 50),
        own_spn: `${ownService}/${identity.sam}.${view.fqdn}`,
        // The target SPN carries the TARGET host's own domain, not the
        // delegating account's: a service ticket names the service where it
        // lives, and an SPN suffixed with the wrong domain resolves to nothing.
        delegate_to: [`${service}/${target.hostname}.${str(target.domain) || view.fqdn}`, `${service}/${target.hostname}`],
        targets: { identity: identity.sam, host: target.hostname, domain: view.fqdn },
        // Only the delegating account's own AD object is written. The SPNs in
        // msDS-AllowedToDelegateTo are values ON that object; the host they name is
        // not modified and gains no new exposure that owning the inert account
        // would not already imply.
        modifies: { identity: identity.sam },
        dead_ends_because: `nothing in the graph leads to ${identity.sam}, and the delegation `
          + `points at ${target.hostname} rather than at a domain controller, so even holding the `
          + 'account buys a member server and not the domain.',
        why: `${identity.sam} runs a reporting integration that impersonates users against `
          + `${target.hostname}. The delegation is scoped, which is the good news; the account it `
          + 'is scoped to is an ordinary user with an SPN, which is not.',
        probe: {
          id: `content:delegation:constrained:${idPart(identity.sam)}`,
          kind: 'delegation',
          run_on: view.dcHost.key,
          host: view.dcHost.key,
          domain: view.fqdn,
          role: 'ps',
          principal: identity.sam,
          delegation: 'constrained',
          allowed_to_delegate_to: [`${service}/${target.hostname}.${str(target.domain) || view.fqdn}`, `${service}/${target.hostname}`],
          why: 'msDS-AllowedToDelegateTo is written by a freeform script and by nothing else',
        },
      });
    } else {
      warnings.push('constrained_delegation skipped: '
        + (target ? 'no domain in this lab has an inert account with a non-wordlist password, and '
            + 'an account with a wordlist password plus a fresh SPN would crack open with the '
            + 'same list the intended entry uses'
          : 'the lab has no member server to delegate to - a single-host lab can only delegate to '
            + 'its own domain controller, which is a domain takeover rather than a side quest'));
    }
  }

  // -- RBCD -----------------------------------------------------------------
  {
    // Both ends of RBCD are resolved on the RESOURCE's own DC: Set-ADComputer
    // finds the resource, and the delegate's DistinguishedName has to come back
    // from a Get-AD* the same DC can answer. So this needs one view holding BOTH
    // a spare account and a member server of its own - which the forest root
    // never does in any chassis, and a child or a second forest usually does.
    const view = pickView((v) => hasFree(v, null) && freeMembersOf(v).length > 0);
    const delegate = view ? takeFrom(view, null) : null;
    const members = view ? freeMembersOf(view) : [];
    const target = members[hashStr(seed, 'rbcd:target') % Math.max(1, members.length)];
    if (delegate && target && view) {
      plans.push({
        technique: 'rbcd',
        item: `rbcd_${idPart(target.hostname)}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        target: target.hostname,
        delegate: delegate.sam,
        delegate_kind: 'user',
        targets: { resource: target.hostname, delegate: delegate.sam },
        // Both ends are checked: the resource's security descriptor is rewritten,
        // and the delegate is handed impersonation over it.
        modifies: { resource: target.hostname, delegate: delegate.sam },
        dead_ends_because: `${delegate.sam} is reachable from nothing in the graph, and the `
          + `resource is ${target.hostname} rather than a domain controller.`,
        why: `${delegate.sam} was granted resource-based delegation onto ${target.hostname} `
          + 'during a service migration so the new host could impersonate callers. The grant was '
          + 'never removed, and unlike classic constrained delegation it is written on the '
          + 'resource, so the resource owner can hand it out without asking anybody.',
        probe: null,
        why_unprobed: 'goad-postcondition.ps1 implements no msDS-AllowedToActOnBehalfOfOtherIdentity '
          + 'check; the delegation kinds it knows are unconstrained, constrained and protocol '
          + 'transition. Declaring a kind it does not implement would be reported as a failure.',
      });
    } else {
      warnings.push('rbcd skipped: no domain in this lab has both a spare inert account and a '
        + 'member server of its own that the attack graph is not already using. Set-ADComputer and '
        + 'the delegate lookup both run against one DC, so the two have to be in the same domain');
    }
  }

  // -- GPO abuse ------------------------------------------------------------
  {
    const topic = hashPick(seed, 'gpo:topic', GPO_TOPICS.slice());
    // Prefer a view that HAS an OU: linking at the domain root sweeps in the
    // Domain Controllers OU, and a GPO that applies to a DC is a different
    // exercise from the one this is meant to be.
    const usableOus = (v) => v.ous.filter((o) => !/^domain controllers$/i.test(str(o.name)));
    const view = pickView((v) => hasFree(v, null) && usableOus(v).length > 0)
      || pickView((v) => hasFree(v, null));
    const editor = view ? takeFrom(view, null) : null;
    const candidates = view ? usableOus(view) : [];
    const ou = candidates[hashStr(seed, 'gpo:ou') % Math.max(1, candidates.length)];
    const linkTarget = ou ? `OU=${ou.name},${ou.path || view.rootDn}` : (view ? view.rootDn : ctx.rootDn);
    if (!ou) {
      warnings.push('gpo_abuse links at the domain root: this lab declares no organisational unit '
        + 'to link to, so the policy also applies to the Domain Controllers OU. The delegated '
        + 'editor is still an inert principal, so this does not shortcut the chain - but a lab '
        + 'with OUs makes a better exercise');
    }
    if (editor && view) {
      plans.push({
        technique: 'gpo_abuse',
        item: `gpo_abuse_${idPart(editor.sam)}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        gpo_name: `${ctx.org} ${topic.suffix}`,
        comment: `Manages ${topic.about} for ${ctx.org}.`,
        link_target: linkTarget,
        editor: editor.sam,
        reg_key: topic.key,
        reg_name: topic.name,
        // The one topic whose payload names a host substitutes the lab's own
        // file server. A GPO pointing at a stock "FILESRV" is the tell that the
        // policy was pasted in rather than written for this estate.
        reg_value: topic.value.replace('{{FILE_HOST}}',
          (anyFreeMachine[0] || ctx.members[0] || ctx.dcHost).hostname),
        targets: { gpo: `${ctx.org} ${topic.suffix}`, link: linkTarget, editor: editor.sam },
        // The GPO is new and the link target is a container, not a principal. The
        // editor is the only account this hands power to.
        modifies: { editor: editor.sam },
        dead_ends_because: `${editor.sam} is on no path in the graph, so the edit right is real `
          + 'and unreachable.',
        why: `${editor.sam} was delegated edit rights on the ${topic.about} policy so the service `
          + 'desk would stop raising tickets about it. Edit rights on a linked GPO are code '
          + 'execution on everything the GPO applies to.',
        probe: null,
        why_unprobed: 'the probe implements no Group Policy check. A GPO that failed to create is '
          + 'visible in the play output; a GPO whose delegation failed to apply is not, and that '
          + 'gap is recorded here rather than hidden.',
      });
    } else {
      warnings.push('gpo_abuse skipped: no inert principal is available to delegate edit rights to');
    }
  }

  // -- sIDHistory -----------------------------------------------------------
  {
    // netdom runs on the TRUSTING side, so the script is scheduled on that
    // domain's own DC rather than on whichever DC the artifacts landed on.
    const view = pickView((v) => str(v.domain.trust_fqdn) !== '');
    const trusting = view ? view.domain : null;
    if (trusting && view) {
      plans.push({
        technique: 'sidhistory',
        item: `sidhistory_${idPart(str(trusting.trust_fqdn).split('.')[0])}`,
        host_key: view.dcHost.key,
        declared_by_chain: false,
        trusting: str(trusting.fqdn),
        trusted: str(trusting.trust_fqdn),
        targets: { trusting: str(trusting.fqdn), trusted: str(trusting.trust_fqdn) },
        // A trust object, not a principal: nothing in the roster is touched.
        modifies: {},
        why: `The trust between ${trusting.fqdn} and ${trusting.trust_fqdn} was built during the `
          + 'acquisition with SID filtering disabled so that migrated groups would keep working. '
          + 'It has never been turned back on, so a SID injected on the far side is honoured here.',
        probe: null,
        why_unprobed: 'the probe implements no trust check. Get-ADTrust would answer it, but adding '
          + 'a check kind is a change to the .ps1 and its schema version, not to this module.',
      });
    } else {
      warnings.push('sidhistory skipped: this lab declares no trust (tier S is a single domain and '
        + "tier M's parent/child link is intra-forest), and netdom /enablesidhistory needs one. "
        + 'The technique is emitted for any lab whose IR carries a trust_fqdn');
    }
  }

  // -- coercion bot (not one of the six; only where the chain needs traffic) --
  const delegationPlan = plans.filter((p) => p.technique === 'unconstrained_delegation' && p.declared_by_chain)[0];
  if (delegationPlan) {
    const share = hashPick(seed, 'bot:share', ['C$', 'ADMIN$', 'Reports$', 'Transfer']);
    plans.push({
      technique: 'coercion_bot',
      item: `coercion_bot_${idPart(bareSam(delegationPlan.target))}`,
      host_key: ctx.dcHost.key,
      declared_by_chain: false,
      run_on_hostname: ctx.dcHost.hostname,
      task_name: hashPick(seed, 'bot:task', ['ReportSync', 'ArchiveSweep', 'HealthCheck', 'IndexRefresh']),
      unc: `\\\\${delegationPlan.target}\\${share}`,
      interval_minutes: hashInt(seed, 'bot:interval', 1, 5),
      targets: { unc_host: delegationPlan.target, run_on: ctx.dcHost.hostname },
      // Creates a scheduled task on the DC and writes nothing in the directory.
      // The UNC host it reaches for is the chain's OWN delegation target - that is
      // the point of the bot - so it deliberately declares no modified principal.
      modifies: {},
      why: `The chain's last hop needs something privileged to authenticate to `
        + `${delegationPlan.target}. This task runs on the domain controller as SYSTEM, so the `
        + "ticket the delegating host caches is the DC's own.",
      probe: null,
      why_unprobed: 'the probe implements no scheduled-task check; the task is visible in '
        + 'schtasks output on the DC.',
    });
  }

  return plans;
}

function renderScript(ctx, seed, plan) {
  switch (plan.technique) {
    case 'asrep': return scriptAsrep(ctx, seed, plan);
    case 'unconstrained_delegation': return scriptUnconstrained(ctx, seed, plan);
    case 'constrained_delegation': return scriptConstrained(ctx, seed, plan);
    case 'rbcd': return scriptRbcd(ctx, seed, plan);
    case 'gpo_abuse': return scriptGpoAbuse(ctx, seed, plan);
    case 'sidhistory': return scriptSidHistory(ctx, seed, plan);
    case 'coercion_bot': return scriptCoercionBot(ctx, seed, plan);
    default:
      return fail('TECHNIQUE_UNKNOWN',
        `lab content: technique '${plan.technique}' has no writer. TECHNIQUES is `
        + `${TECHNIQUES.join(', ')}.`, plan.item);
  }
}

// --- the generator ----------------------------------------------------------

/**
 * Entry points whose secrecy DEPENDS on the password not being on disk.
 *
 * `asrep` requires the student to request and crack an AS-REP hash; a copy of
 * the same password in a web config makes that step decorative.
 * `user_equals_password` requires them to notice that a published staff list is
 * also a spray list. The other five entries are already file- or
 * directory-readable by design, so putting the credential in the app config is
 * where it was always going to be.
 */
const ENTRIES_DEFEATED_BY_A_FILE = Object.freeze(['asrep', 'user_equals_password']);

/**
 * Generate one lab's `files/` and `scripts/`.
 *
 * @param {object} labIR   goad-lab-compile's `ir`, after applyAttackChain().
 * @param {object} [opts]
 * @param {string} [opts.runId]  the seed. Defaults to labIR.run_id, then
 *                               labIR.lab_name (itself a hash of run_id).
 * @param {object} [opts.lab]    the compiled config.json `lab` dict. Optional,
 *                               and used ONLY to widen the forbidden-secret set
 *                               (domain and local admin passwords) and to notice
 *                               a cached TERMSRV credential worth pairing the
 *                               .rdp shortcut with. Content never depends on it.
 */
function generateLabContent(labIR, opts) {
  const options = isObject(opts) ? opts : {};
  const ir = isObject(labIR) ? labIR : {};
  const seed = str(options.runId || ir.run_id || ir.lab_name);
  if (!seed) {
    fail('CONTENT_NO_SEED',
      'lab content: no seed. Every filename, prose variant and key byte is a hash of the run id, '
      + 'so without one there is nothing to be deterministic about - and content that cannot be '
      + 'regenerated cannot be checked against the paper report.', 'run_id');
  }

  const ctx = indexIr(ir, options);
  const warnings = [];
  const tree = {};
  const artifacts = [];
  const filesVars = {};
  const hostScripts = {};

  const addFile = (a) => {
    // ARTIFACT_KINDS is the vocabulary the answer key and the instructor UI both
    // read; a writer that invents a kind produces an artifact nothing downstream
    // knows how to describe. Checked here so the constant is load-bearing rather
    // than decorative.
    if (ARTIFACT_KINDS.indexOf(a.kind) === -1) {
      fail('CONTENT_ARTIFACT_KIND_UNKNOWN',
        `lab content: artifact kind '${a.kind}' is not one of ${ARTIFACT_KINDS.join(', ')}.`,
        a.src);
    }
    const treePath = FILES_PREFIX + a.src;
    if (Object.prototype.hasOwnProperty.call(tree, treePath)) {
      fail('CONTENT_DUPLICATE_MEMBER',
        `lab content: two artifacts both want '${treePath}'. pushLabTree rejects a duplicate `
        + 'member, and if it did not, one would silently win.', treePath);
    }
    tree[treePath] = assertAscii(a.content, treePath);
    artifacts.push(a);
    if (a.host_key) {
      if (!filesVars[a.host_key]) filesVars[a.host_key] = {};
      if (filesVars[a.host_key][a.item]) {
        fail('CONTENT_DUPLICATE_FILES_ITEM',
          `lab content: hosts.${a.host_key}.vulns_vars.files already has an item named `
          + `'${a.item}'. vulns_vars is a dict, so the second copy replaces the first and one `
          + 'planted artifact simply is not there.', `${a.host_key}.${a.item}`);
      }
      filesVars[a.host_key][a.item] = { src: a.src, dest: a.dest };
    }
  };

  // -- who gets to hold which credential ------------------------------------
  // Shuffled per seed: which roster account ends up in the unattend rather than
  // in the vault is itself part of what makes two labs different.
  const inert = seededShuffle(seed, 'artifact-pool', inertUsers(ctx));
  if (inert.length === 0) {
    warnings.push('no inert roster account exists: every user is on the attack graph or in a '
      + 'privileged group, so the share litter is emitted without credentials. A larger roster '
      + 'fixes this; planting a graph principal would not');
  }
  // Wraps rather than running out. A small roster then reuses an account across
  // two artifacts, which is what a real estate looks like anyway - the same
  // service account is in the backup script AND the vault - and the alternative
  // is a lab that silently ships four artifacts instead of nine because the
  // fifth writer got a null.
  let inertCursor = 0;
  const nextInert = () => {
    if (inert.length === 0) return null;
    const u = inert[inertCursor % inert.length];
    inertCursor += 1;
    return u;
  };

  const entryKind = str((ctx.chain.start || {}).kind);
  const footholdSafeInAFile = entryKind !== '' && ENTRIES_DEFEATED_BY_A_FILE.indexOf(entryKind) === -1;
  const footholdCred = str(ctx.foothold.sam) && str(ctx.foothold.password)
    ? { sam: str(ctx.foothold.sam), password: str(ctx.foothold.password) }
    : null;

  // -- 1. the web app config: the seam between the website and the forest ----
  const bindCred = (footholdSafeInAFile && footholdCred) ? footholdCred : nextInert();
  let footholdPlantedIn = null;
  if (bindCred) {
    const w = writeWebConfig(ctx, seed, bindCred);
    const carriesFoothold = !!(footholdCred && bindCred.sam === footholdCred.sam);
    addFile({
      kind: 'web_app_config',
      item: 'web_app_config',
      host_key: ctx.webHost.key,
      src: `${ctx.webHost.key}/${w.dir}/${w.name}`,
      dest: w.dest,
      content: w.content,
      secrets: [{
        value: bindCred.password,
        account: bindCred.sam,
        why: carriesFoothold
          ? "the application's directory bind credential is the chain's foothold; this file is the "
            + 'seam between the website and AD'
          : "the application's directory bind credential, which is real but leads nowhere",
      }],
      carries_foothold: carriesFoothold,
      why: carriesFoothold
        ? `${bindCred.sam} is the account the web application binds to LDAP with, stored in `
          + 'cleartext where the application itself can read it.'
        : `${bindCred.sam} is the application's read-only bind account. The chain's entry is `
          + `'${entryKind}', whose whole point is that the credential is NOT sitting in a file - `
          + 'so the foothold password is deliberately not here.',
    });
    if (carriesFoothold) footholdPlantedIn = `${FILES_PREFIX}${ctx.webHost.key}/${w.dir}/${w.name}`;
  }

  // -- share litter ---------------------------------------------------------
  // The share root the litter lands in. When the chain declared openshares on
  // this host the folder already exists at GOAD's own path; otherwise win_copy
  // creates whatever we name, and the folder should look like a department
  // share rather than like a lab fixture.
  const openshareOnLitterHost = asArray((ctx.chain.start || {}).plants)
    .some((p) => p.role === 'vulns/openshares' && p.host === ctx.litterHost.key);
  const shareRoot = openshareOnLitterHost
    ? 'C:\\shares\\all'
    : hashPick(seed, 'shareroot', ['C:\\Departments\\Shared', 'C:\\FileStore\\Common', 'C:\\Data\\Everyone', 'C:\\shares\\all']);

  // -- 2. unattend, first, because the letter and the sheet point at it ------
  const joinCred = nextInert();
  let unattendPointer = 'the imaging share';
  if (joinCred) {
    const u = writeUnattend(ctx, seed, joinCred);
    unattendPointer = `${shareRoot}\\imaging\\${u.name}`;
    addFile({
      kind: 'unattend',
      item: 'imaging_answer_file',
      host_key: ctx.litterHost.key,
      src: `${ctx.litterHost.key}/share/imaging/${u.name}`,
      dest: `${shareRoot}\\imaging\\${u.name}`,
      content: u.content,
      secrets: u.secrets,
      why: 'the desktop team keep the imaging answer file on the share so the task sequence does '
        + 'not have to prompt. It joins the domain with a real account, and the base64 '
        + 'AdministratorPassword is obfuscation rather than encryption.',
    });
  }

  // -- 3. the spreadsheet ---------------------------------------------------
  {
    const sheetCred = nextInert();
    const s = writeSpreadsheet(ctx, seed, sheetCred, unattendPointer);
    addFile({
      kind: 'share_spreadsheet',
      item: 'share_spreadsheet',
      host_key: ctx.litterHost.key,
      src: `${ctx.litterHost.key}/share/${s.name}`,
      dest: `${shareRoot}\\${s.name}`,
      content: s.content,
      secrets: s.secrets,
      why: 'the spreadsheet nobody owns. Whether it carries a credential or only a pointer, it is '
        + 'the map of the estate that a student would otherwise have to build by hand.',
    });
  }

  // -- 4. the .rdp shortcut -------------------------------------------------
  {
    const rdpAccount = nextInert() || { sam: 'administrator' };
    const r = writeRdp(ctx, seed, rdpAccount);
    addFile({
      kind: 'rdp_shortcut',
      item: 'saved_rdp_session',
      host_key: ctx.litterHost.key,
      src: `${ctx.litterHost.key}/share/${r.name}`,
      dest: `${shareRoot}\\${r.name}`,
      content: r.content,
      secrets: [],
      why: `a saved session pointing at ${r.target} as ${r.account}. It carries no password - a `
        + '.rdp stores one as a DPAPI blob bound to the machine that saved it - and the finding is '
        + 'the pairing with whatever cached TERMSRV credential the host already holds.',
    });
  }

  // -- 5. the backup script -------------------------------------------------
  {
    const backupCred = nextInert();
    if (backupCred) {
      const b = writeBackupScript(ctx, seed, backupCred);
      addFile({
        kind: 'backup_script',
        item: 'backup_job_script',
        host_key: ctx.litterHost.key,
        src: `${ctx.litterHost.key}/share/${b.name}`,
        dest: `${shareRoot}\\${b.name}`,
        content: b.content,
        secrets: b.secrets,
        why: 'the job that has to run unattended, so its credential is in the file that runs it.',
      });
    }
  }

  // -- 6/7/8. SYSVOL --------------------------------------------------------
  // NETLOGON is readable by every authenticated user in the domain, which is
  // what makes these two artifacts different in kind from the share litter: no
  // share misconfiguration is required to reach them.
  const sysvolDir = 'C:\\Windows\\SYSVOL\\domain\\scripts';
  {
    const logonCred = nextInert();
    if (logonCred) {
      const l = writeSysvolLogonScript(ctx, seed, logonCred);
      addFile({
        kind: 'sysvol_logon_script',
        item: 'sysvol_logon_script',
        host_key: ctx.dcHost.key,
        src: `${ctx.dcHost.key}/sysvol_scripts/${l.name}`,
        dest: `${sysvolDir}\\${l.name}`,
        content: l.content,
        secrets: l.secrets,
        why: 'a logon script in NETLOGON with a credential in it. Every authenticated user can '
          + 'read SYSVOL, so this needs no misconfigured share to find.',
      });
    }
    const secretCred = nextInert();
    if (secretCred) {
      const s = writeSysvolSecret(ctx, seed, secretCred);
      addFile({
        kind: 'sysvol_secret',
        item: 'sysvol_secret',
        host_key: ctx.dcHost.key,
        src: `${ctx.dcHost.key}/sysvol_scripts/${s.name}`,
        dest: `${sysvolDir}\\${s.name}`,
        content: s.content,
        secrets: s.secrets,
        securestring: { blob: s.blob, key_bytes: s.key_bytes, external_key: s.external_key },
        why: 'the credential somebody "encrypted". ConvertFrom-SecureString -Key is reversible by '
          + 'anyone holding the key, and the key ships beside the blob.',
      });
      if (s.external_key) {
        addFile({
          kind: 'sysvol_key',
          item: 'sysvol_secret_key',
          host_key: ctx.dcHost.key,
          src: `${ctx.dcHost.key}/sysvol_scripts/${s.key_name}`,
          dest: `${sysvolDir}\\${s.key_name}`,
          content: s.key_content,
          secrets: [],
          why: 'the AES key for the blob next to it. Out-File writes one byte per line, which is '
            + 'what Get-Content reads back - this is the shape the cmdlet documentation itself '
            + 'produces.',
        });
      }
    }
  }

  // -- 9. the letter --------------------------------------------------------
  {
    const subject = nextInert() || ctx.users[0];
    if (subject) {
      const letter = writeLetter(ctx, seed, subject, unattendPointer);
      addFile({
        kind: 'onboarding_letter',
        item: 'staff_letter',
        host_key: ctx.litterHost.key,
        src: `${ctx.litterHost.key}/share/${letter.name}`,
        dest: `${shareRoot}\\${letter.name}`,
        content: letter.content,
        secrets: [],
        why: 'the upstream arya.txt slot. It carries no credential on purpose: its job is to name '
          + 'an account and name where that account\'s password is kept, which is the step a '
          + 'wordlist cannot take for a student.',
      });
    }
  }

  // -- 10. the credential vault --------------------------------------------
  {
    const vaultCreds = [];
    for (let i = 0; i < 3; i += 1) {
      const c = nextInert();
      if (c && !vaultCreds.some((v) => v.sam === c.sam)) vaultCreds.push(c);
    }
    if (vaultCreds.length) {
      const v = writeVault(ctx, seed, vaultCreds);
      addFile({
        kind: 'credential_vault',
        item: 'credential_vault_export',
        host_key: ctx.litterHost.key,
        src: `${ctx.litterHost.key}/share/${v.name}`,
        dest: `${shareRoot}\\${v.name}`,
        content: v.content,
        secrets: v.secrets,
        why: 'an export from the password manager, kept next to the scripts that need it. This is '
          + 'the artifact the letter and the spreadsheet both point at.',
      });
    }
  }

  // -- 11/12. everything the chain already committed to ---------------------
  for (const req of chainFileRequests(ir)) {
    // Routed on the SRC, not on the producer's kind: an edge prerequisite
    // carries no kind at all, and the certificate template is the one member
    // whose structure is the vendor's rather than ours.
    if (/\.json$/i.test(req.src)) {
      const templateName = req.src.split('/').pop().replace(/\.json$/i, '');
      const t = writeAdcsTemplate(ctx, seed, templateName);
      addFile({
        kind: 'adcs_template',
        item: req.item,
        host_key: req.host_key,
        src: req.src,
        dest: req.dest,
        content: t.content,
        secrets: [],
        declared_by_chain: true,
        why: 'New-ADCSTemplate reads this with Get-Content -Raw and the win_shell task stays green '
          + 'on a missing file, so an unemitted template is an ESC1 edge that silently does not '
          + 'exist.',
      });
      continue;
    }
    if (req.kind === 'share_file' || /handover|note|readme|txt$/i.test(req.src)) {
      if (!footholdCred) {
        fail('CONTENT_NO_FOOTHOLD',
          `lab content: the chain declares a planted artifact at '${req.src}' but labIR carries no `
          + 'foothold_credential to put in it. That file IS the entrance; an empty one is a lab '
          + 'with no way in.', req.src);
      }
      const h = writeHandoverNote(ctx, seed, footholdCred);
      addFile({
        kind: 'handover_note',
        item: req.item,
        host_key: req.host_key,
        src: req.src,
        dest: req.dest,
        content: h.content,
        secrets: h.secrets,
        declared_by_chain: true,
        carries_foothold: true,
        why: `the chain's '${entryKind}' entry reads this file. Its src and dest were fixed by the `
          + 'attack chain before this module ran; only the prose is ours.',
      });
      footholdPlantedIn = FILES_PREFIX + req.src;
      continue;
    }
    warnings.push(`the chain declares a vulns/files copy from '${req.src}' that this module has no `
      + 'writer for, so nothing was emitted for it. win_copy will fail on the missing source');
  }

  // -- scripts --------------------------------------------------------------
  const plans = planTechniques(ctx, seed, warnings);
  const scripts = [];
  for (const plan of plans) {
    const rendered = renderScript(ctx, seed, plan);
    const treePath = SCRIPTS_PREFIX + rendered.name;
    if (Object.prototype.hasOwnProperty.call(tree, treePath)) {
      fail('CONTENT_DUPLICATE_MEMBER',
        `lab content: two techniques both want '${treePath}'.`, treePath);
    }
    tree[treePath] = assertAscii(rendered.content, treePath);
    const hostKey = plan.host_key || ctx.dcHost.key;
    if (!hostScripts[hostKey]) hostScripts[hostKey] = [];
    hostScripts[hostKey].push(rendered.name);
    scripts.push(Object.assign({}, plan, { name: rendered.name, tree_path: treePath }));
  }

  const content = {
    seed,
    lab_name: str(ir.lab_name) || null,
    domain: ctx.fqdn,
    tree,
    files: artifacts.map((a) => Object.assign({}, a, { tree_path: FILES_PREFIX + a.src })),
    scripts,
    files_vars: filesVars,
    host_scripts: hostScripts,
    share_root: shareRoot,
    foothold_planted_in: footholdPlantedIn,
    warnings,
  };
  if (!footholdPlantedIn) {
    warnings.push(entryKind
      ? `the foothold credential is not planted in any file: the chain's entry is '${entryKind}', `
        + 'which is an AD-side plant, and putting the same password in a config would make the '
        + 'intended entry technique decorative'
      : 'this labIR carries no attack chain, so there is no entry to serve. The web app config '
        + 'holds an ordinary bind account and no foothold credential was planted anywhere - run '
        + 'applyAttackChain() before this module in the real pipeline');
  }

  assertContentSound(content, ir, options.lab);
  return content;
}

// --- proofs -----------------------------------------------------------------

/**
 * Everything that must be true of a generated tree, checked on the way out.
 *
 * Runs inside generateLabContent for the same reason compileLab runs the
 * validator on its own output: a generator that can emit content these checks
 * reject is a generator whose bugs are found on a lane, ninety minutes in.
 */
function assertContentSound(content, ir, lab) {
  const declared = declaredSecrets(ir, lab);
  const forbidden = forbiddenSecrets(lab);

  // 1. ASCII, everywhere, including members a caller added by hand.
  for (const [p, body] of Object.entries(content.tree)) assertAscii(body, p);

  // 2. Every planted secret is one the IR already declares, and it is really in
  //    the file that claims it. The second half catches the writer that built a
  //    descriptor and forgot to interpolate - which would deploy, and would fail
  //    only when a student typed the credential in.
  for (const artifact of content.files) {
    for (const secret of asArray(artifact.secrets)) {
      const value = str(secret.value);
      // FORBIDDEN IS CHECKED FIRST, and the order is the whole point. A domain
      // password is not in the declared set either, so checking "undeclared"
      // first would report the most dangerous mistake in the system with the
      // mildest message this file has.
      if (forbidden.has(value)) {
        fail('CONTENT_SECRET_FORBIDDEN',
          `lab content: ${artifact.tree_path} plants the domain administrator's password. `
          + 'compileLab makes every host local_admin_password equal to its domain_password, and '
          + 'that is the credential Ansible itself connects with - reading it off a file share is '
          + 'Domain Admin before edge 0 and the designed graph becomes decoration.',
          artifact.tree_path);
      }
      if (!declared.has(value)) {
        fail('CONTENT_SECRET_UNDECLARED',
          `lab content: ${artifact.tree_path} plants a credential for '${secret.account}' that the `
          + 'labIR does not declare. AD is built from the IR, so a password this module invented '
          + 'is a credential the student finds, sprays, and discovers does not exist - the lab '
          + 'then has no second act and nothing errors.', artifact.tree_path);
      }
      const body = content.tree[artifact.tree_path];
      const present = secret.encrypted
        ? true
        : body.indexOf(value) !== -1;
      if (!present) {
        fail('CONTENT_SECRET_MISSING',
          `lab content: ${artifact.tree_path} claims to carry the credential for `
          + `'${secret.account}' but the emitted bytes do not contain it. The descriptor and the `
          + 'file have to agree, or the answer key describes an artifact that is not there.',
          artifact.tree_path);
      }
    }
  }

  // 3. No secret in a script, ever.
  //    roles/ps runs through the `script` module, which stages the .ps1 into the
  //    connection user's temp directory on the guest. A credential in one of
  //    these is a credential in a world-traversable path nobody chose.
  const everySecret = new Set([...declared, ...forbidden]);
  for (const s of content.scripts) {
    const body = content.tree[s.tree_path];
    for (const value of everySecret) {
      if (body.indexOf(value) !== -1) {
        fail('CONTENT_SECRET_IN_SCRIPT',
          `lab content: ${s.tree_path} contains a credential. roles/ps stages a script into the `
          + 'guest temp directory, so a password here is a password on disk in a path no one '
          + 'chose. Every technique this module emits is an attribute or an ACL and none of them '
          + 'needs one.', s.tree_path);
      }
    }
  }

  // 4. Every chain-declared vulns/files src has content, at exactly that src.
  for (const req of chainFileRequests(ir)) {
    const treePath = FILES_PREFIX + req.src;
    if (!Object.prototype.hasOwnProperty.call(content.tree, treePath)) {
      fail('CONTENT_CHAIN_FILE_MISSING',
        `lab content: the attack chain declares a win_copy from '${req.src}' (${req.origin}) and `
        + 'no member was emitted there. win_copy fails on a missing source, and for a certificate '
        + 'template Get-Content returns nothing while the task still reports green.', treePath);
    }
  }

  // 5. Every chain-declared roles/ps item has a script, under exactly its name.
  for (const req of chainScriptRequests(ir)) {
    const treePath = `${SCRIPTS_PREFIX}${req.item}.ps1`;
    if (!Object.prototype.hasOwnProperty.call(content.tree, treePath)) {
      fail('CONTENT_CHAIN_SCRIPT_MISSING',
        `lab content: the attack chain declares roles/ps item '${req.item}' (${req.origin}) and no `
        + `script was emitted at '${treePath}'. vulnerabilities.yml resolves the item against `
        + 'ad/<LAB>/scripts/ and a missing file fails the task with a path, not a reason.',
      treePath);
    }
  }

  // 6. Undeclared techniques never touch a graph principal.
  const ctx = indexIr(ir, { lab });
  const claimed = chainPrincipals(ctx);
  for (const s of content.scripts) {
    if (s.declared_by_chain) continue;
    // `modifies`, not `targets`. A technique may REFERENCE a graph principal
    // without empowering it - constrained delegation writes SPNs naming a host
    // onto the delegating account, and the host itself gains nothing - so the
    // check is scoped to the principals whose AD object this script rewrites or
    // whose reach it widens. Scanning every parameter instead would force the
    // planner to pick nonsense targets to satisfy a check that was too broad.
    for (const value of Object.values(s.modifies || {})) {
      const key = bareSam(str(value)).toLowerCase();
      if (claimed.has(key)) {
        fail('CONTENT_TECHNIQUE_TOUCHES_GRAPH',
          `lab content: ${s.tree_path} applies '${s.technique}' to '${value}', which is a `
          + 'principal the attack chain depends on. assertNoUnintendedShortcuts ran before this '
          + 'module and cannot see what we plant, so a technique the chain did not ask for has to '
          + 'land on an inert principal or nothing has proved the graph still holds.',
        s.tree_path);
      }
    }
  }

  return content;
}

// --- lowering into the lab dict --------------------------------------------

/**
 * The same ordering rule goad-lab-validate.validateRoleOrder() enforces.
 *
 * `vulns` is a literal execution order - vulnerabilities.yml loops it in place -
 * so `files` has to precede adcs_templates (which imports the JSON files copied),
 * schedule (which runs a script files copied) and permissions (which ACLs a path
 * files created), and `directory` has to precede permissions.
 */
function orderVulnsForContent(names) {
  return names
    .map((name, i) => ({ name, i }))
    .sort((a, b) => {
      const ra = ROLE_RANK[a.name] === undefined ? 50 : ROLE_RANK[a.name];
      const rb = ROLE_RANK[b.name] === undefined ? 50 : ROLE_RANK[b.name];
      return ra === rb ? a.i - b.i : ra - rb;
    })
    .map((e) => e.name);
}

/**
 * Put a generated content pack into a compiled `lab` dict.
 *
 * Returns a NEW lab; nothing is mutated in place, so a caller can compile, merge
 * and compare. Adding `files` to a host's vulns is not enough on its own - it
 * has to land in the right POSITION, because the array is the execution order
 * and a host that already carries adcs_templates or permissions would otherwise
 * run them against paths that do not exist yet.
 */
function mergeLabContent(lab, content) {
  if (!isObject(lab) || !isObject(lab.hosts)) {
    fail('MERGE_NO_LAB', 'mergeLabContent needs a compiled lab dict with a hosts map.', 'lab.hosts');
  }
  const out = JSON.parse(JSON.stringify(lab));

  for (const [hostKey, items] of Object.entries(content.files_vars || {})) {
    const host = out.hosts[hostKey];
    if (!host) {
      fail('MERGE_UNKNOWN_HOST',
        `mergeLabContent: content plants files on host '${hostKey}', which this lab does not `
        + `declare (hosts: ${Object.keys(out.hosts).join(', ')}). vulnerabilities.yml keys `
        + 'vulns_vars off the host dict, so an entry under an unknown host is never copied.',
      hostKey);
    }
    if (!isObject(host.vulns_vars)) host.vulns_vars = {};
    if (!isObject(host.vulns_vars.files)) host.vulns_vars.files = {};
    for (const [item, vars] of Object.entries(items)) {
      host.vulns_vars.files[item] = { src: vars.src, dest: vars.dest };
    }
    const vulns = Array.isArray(host.vulns) ? host.vulns.slice() : [];
    if (vulns.indexOf('files') === -1) vulns.push('files');
    host.vulns = orderVulnsForContent(vulns);

    // vulns_vars must be re-keyed in vulns order too. It is a dict, so the
    // ORDER does not change what Ansible does - but the emitted config.json is
    // read by an instructor next to the vulns array, and two lists in different
    // orders is how a reader concludes the file is generated slop.
    const reordered = {};
    for (const name of host.vulns) {
      if (host.vulns_vars[name] !== undefined) reordered[name] = host.vulns_vars[name];
    }
    for (const [k, v] of Object.entries(host.vulns_vars)) {
      if (reordered[k] === undefined) reordered[k] = v;
    }
    host.vulns_vars = reordered;
  }

  for (const [hostKey, names] of Object.entries(content.host_scripts || {})) {
    const host = out.hosts[hostKey];
    if (!host) {
      fail('MERGE_UNKNOWN_HOST',
        `mergeLabContent: content runs scripts on host '${hostKey}', which this lab does not `
        + 'declare.', hostKey);
    }
    const existing = Array.isArray(host.scripts) ? host.scripts.slice() : [];
    for (const n of names) if (existing.indexOf(n) === -1) existing.push(n);
    host.scripts = existing;
  }

  return out;
}

// --- the company website ----------------------------------------------------
//
// WHY THE SITE IS EMITTED HERE AND NOT TEMPLATED BY THE ROLE
// infrastructure/ansible/cc-web installs a web tier and contains no company
// name, no copy and no account, on purpose: it is variable-driven so that one
// role builds every client's site. Somebody still has to WRITE the site, and it
// is the same argument that made files/ and scripts/ emitted rather than
// templated one screen up - ansible renders a variable's value recursively, so
// the moment a page is a template the generator has to reason about two
// languages at once, and a page carrying {{ }} either explodes or, worse,
// evaluates. So: the role installs, this module authors.
//
// WHAT THE SITE IS FOR, IN ORDER
//   1. It is the surface an external engagement starts from. A student who
//      nmaps the lane and browses the company reads about the SAME company the
//      paper profile describes - the staff on the About page are the accounts
//      AD will create, the domain is the client's, the city is the client's.
//   2. It carries the weakness. One portal, and OWASP classics only: a settings
//      page served without a session check, and a service credential left in a
//      config file under the web root.
//   3. IT IS THE FOOTHOLD SEAM. The credential the site plants is the exact
//      credential Active Directory is built with. Everything else here is
//      scenery that makes the report true; this is the mechanism that turns a
//      web finding into a domain foothold, and assertSiteSound() refuses to
//      emit a site whose two halves disagree about it.
//
// `web_facts` below is asset.web_facts VERBATIM - the object documented in
// ai/scan-documents/service-inference.js and read there by readWebFacts(), and
// the same object roles/cc_web reads to decide what to build. One contract, two
// consumers, which is what turns "the paper matches the lane" from something a
// checker verifies afterwards into something that cannot be false.

/**
 * The year the site prints on its own footer and in its dates.
 *
 * A CONSTANT, because Date.now() is banned on this path for the same reason
 * Math.random() is: the same profile must regenerate a byte-identical tree, and
 * a copyright line that changes at midnight on New Year's Eve makes the bake
 * identity of every client move for a reason nobody would ever find.
 */
const SITE_YEAR = 2026;

/** Per-client route spellings. The report links to whatever is declared, so two
 *  clients differ in their URL space and not only in their copy. */
const SITE_PATH_VARIANTS = Object.freeze({
  about: ['/about', '/about-us', '/who-we-are', '/company'],
  careers: ['/careers', '/jobs', '/work-with-us', '/vacancies'],
  contact: ['/contact', '/contact-us', '/get-in-touch', '/find-us'],
  portal: ['/portal', '/intranet', '/workspace', '/staffnet', '/connect'],
});

/** The three layout engines. Not three skins of one grid: each lays a page out
 *  differently, so two clients do not read as one template with the nouns
 *  swapped - which is the reskin failure this whole compiler exists to avoid. */
const SITE_LAYOUTS = Object.freeze(['stacked', 'sidebar', 'banded']);

const SITE_PALETTES = Object.freeze([
  { ink: '#12232e', wash: '#f4f7fa', accent: '#0f6fa8', edge: '#d6e2ec', head: '#0b1a22' },
  { ink: '#1d2b1f', wash: '#f5f8f3', accent: '#2f7d4f', edge: '#d9e6d9', head: '#122015' },
  { ink: '#2b1f2e', wash: '#faf5f8', accent: '#8a3d7a', edge: '#e8d9e4', head: '#1f1522' },
  { ink: '#2e2313', wash: '#fbf8f2', accent: '#a86a12', edge: '#ece0cd', head: '#221a0d' },
  { ink: '#111827', wash: '#f6f7f9', accent: '#3b4cca', edge: '#dcdfe8', head: '#0b1120' },
  { ink: '#14282c', wash: '#f2f8f9', accent: '#0e7c86', edge: '#d2e6e8', head: '#0c1c1f' },
]);

const SITE_FONTS = Object.freeze([
  'Georgia, "Times New Roman", serif',
  '"Helvetica Neue", Helvetica, Arial, sans-serif',
  '"Segoe UI", Tahoma, Verdana, sans-serif',
  '"Trebuchet MS", "Lucida Grande", sans-serif',
]);

const SITE_TAGLINES = Object.freeze([
  'Dependable service, delivered on schedule.',
  'Practical work, done properly, the first time.',
  'Local people, national reach.',
  'The quiet partner behind busy operations.',
  'Steady hands for work that cannot stop.',
  'Small enough to care, large enough to deliver.',
  'Planning, delivery and support, under one roof.',
  'We keep the unglamorous things running.',
]);

const SITE_ABOUT_OPENERS = Object.freeze([
  'was founded in {year} by a team that had spent a decade watching the same problems go unsolved.',
  'started in {year} with two vans, one office and a list of clients who needed somebody reliable.',
  'has been trading since {year}, and still answers the phone the same way it did then.',
  'opened its doors in {year} and has grown every year since without outgrowing its first client.',
  'was set up in {year} to do one thing properly before doing anything else at all.',
]);

const SITE_ABOUT_CLOSERS = Object.freeze([
  'Today the team works out of {city} and supports clients across the region.',
  'The {city} office remains the centre of everything the company does.',
  'From {city}, the team now covers {sites} sites and a service desk that does not close.',
  'Everything is still run out of {city}, because that is where the work is.',
]);

const SITE_VALUES = Object.freeze([
  ['Do the work', 'Nobody here is paid to talk about doing the work.'],
  ['Answer the phone', 'A client who cannot reach us has already been let down.'],
  ['Say the awkward thing', 'A problem named early is a problem that stays small.'],
  ['Leave it tidy', 'A site should look better when we leave than when we arrived.'],
  ['Own the mistake', 'We fix it, we say what happened, and we change the process.'],
  ['Train the next one', 'Everybody here is teaching somebody else their job.'],
]);

const SITE_ROLE_NOUNS = Object.freeze([
  'Coordinator', 'Team Leader', 'Specialist', 'Administrator', 'Supervisor',
  'Analyst', 'Officer', 'Manager',
]);

const SITE_STREETS = Object.freeze([
  'Marlow Street', 'Bridgewater Road', 'Kestrel Way', 'Foundry Lane', 'Ashfield Park',
  'Copperworks Yard', 'Station Approach', 'Northbank Court',
]);

const SITE_BIO_SHAPES = Object.freeze([
  '{name} is {article} {title} and has been with {org} since {year}.',
  '{name} leads {dept} and joined {org} in {year}.',
  '{name} runs the {dept} side of the business as {article} {title}.',
  '{name} looks after {dept}, and has done since {year}.',
  '{name} came to {org} in {year} and now works as {article} {title}.',
]);

/**
 * Where a config file would sit, and what format it would be in.
 *
 * Every `format` here is one the cc_web role can actually render
 * (roles/cc_web/vars/main.yml, cc_web_pivot_formats). A format the role cannot
 * render is a refusal ninety minutes into a provisioning run, so the pool IS the
 * role's pool and ciab-goad-lab-content.test.js pins the two together.
 */
const SITE_CONFIG_FILES = Object.freeze([
  { dir: 'config', name: 'ldap.env', format: 'dotenv' },
  { dir: 'config', name: 'app.env', format: 'dotenv' },
  { dir: 'includes', name: 'directory.php', format: 'php' },
  { dir: 'config', name: 'settings.ini', format: 'ini' },
  { dir: 'assets/config', name: 'auth.json', format: 'json' },
  { dir: 'WEB-INF', name: 'directory.xml', format: 'xml' },
]);

/** Filename extension -> the cc_web pivot format that renders it. When the
 *  attack chain names the path ('/config/ldap.env') the format is not ours to
 *  choose: it has to be whatever that filename claims to be. */
const SITE_FORMAT_BY_EXT = Object.freeze({
  env: 'dotenv', php: 'php', json: 'json', ini: 'ini', conf: 'ini', cfg: 'ini', xml: 'xml',
});

/**
 * The TLS protocol sets a lane may declare.
 *
 * Every set carries a modern protocol so the site is reachable, and most carry a
 * deliberately weak one because the weak listener IS the finding the report
 * prints. SSLv2 and SSLv3 are absent on purpose: no OpenSSL 3 build this role
 * can install still carries them, so a report claiming an SSLv3 finding could
 * never be true - roles/cc_web says the same thing from the other side and
 * refuses SSLv2 outright.
 */
const SITE_TLS_SETS = Object.freeze([
  ['TLSv1.0', 'TLSv1.2'],
  ['TLSv1.0', 'TLSv1.1', 'TLSv1.2'],
  ['TLSv1.1', 'TLSv1.2'],
  ['TLSv1.2', 'TLSv1.3'],
]);

/** The docroot cc_web defaults to. Spelled here so the emitted pivot path can be
 *  checked against it rather than the generator guessing what the role will do. */
const SITE_DOCROOT = '/var/www/cc-web';

/**
 * The plant formats goad-attack-chain writes when the credential is meant to be
 * found ON THE WEBSITE.
 *
 * Everything else is an AD-side entry - AS-REP roasting, a password that is the
 * sAMAccountName, a note on an anonymous share - and publishing the same string
 * on a page anybody can GET would turn the technique the exercise is about into
 * decoration. Reading planted_at.format rather than guessing is the whole reason
 * this list exists.
 */
const SITE_WEB_PLANT_FORMATS = Object.freeze(['web_app_credential', 'ad_description_mirrored_on_web']);

// --- what a per-lane reseed has to rewrite ----------------------------------
//
// THE SEAM THIS CLOSES. A golden image is identical by definition, so the
// pivot password baked into it is identical for every student in the section.
// lane-reseed rotates that account per lane - and until this block existed it
// rotated ONLY the directory and an application env file it created itself with
// `mkdir -p`, which always succeeds. The website went on serving the BAKED
// password out of its own config file and off /admin/integrations, in the clear,
// and nothing anywhere reported a problem: the lane was green, the credential
// the student read was three hours old, and the pivot the whole exercise is
// built around simply did not work.
//
// A reseed cannot rewrite what it cannot find, and a reseed that GUESSES the
// path is the same bug with a longer fuse. So this module - the only one that
// knows which of six config files was picked, which of five formats it was
// rendered in and which page prints the value - emits the locations and the
// FORMATS as data, and generateSiteContent hangs them off `site.reseed` for the
// bake to carry onto the deploy spec.

/**
 * The rewrite operations lane-reseed implements, by name.
 *
 * Rewriting an ini, a PHP array, an XML element and an HTML attribute are FOUR
 * DIFFERENT OPERATIONS. A regex that happens to work on one silently corrupts
 * another - a line-wide sed substitution over the PHP include eats the closing
 * quote and the comma, and the app then serves a 500 that reads to a student as
 * "the lab is broken" rather than as a finding. Naming the operation is what
 * keeps the two ends honest; ciab-lane-reseed.test.js pins this list against
 * lane-reseed's own.
 */
const SITE_RESEED_OPS = Object.freeze(['dotenv', 'ini', 'php', 'json', 'xml', 'slot']);

/**
 * WHERE THE PASSWORD SITS INSIDE EACH RENDERED PIVOT FORMAT.
 *
 * Read straight off roles/cc_web/templates/pivot-credential.j2, which is the one
 * thing that actually writes these files. Keys are the cc_web format names
 * (cc_web_pivot_formats); values are everything the reseed needs to find the
 * value again without parsing the whole file. ciab-goad-lab-content.test.js
 * reads the template and asserts each of these really addresses the line the
 * template emits, so a change to the role's layout fails here rather than on a
 * lane.
 */
const SITE_PIVOT_FIELD = Object.freeze({
  dotenv: Object.freeze({ op: 'dotenv', key: 'AD_PASSWORD' }),
  ini:    Object.freeze({ op: 'ini', section: 'directory', key: 'password' }),
  php:    Object.freeze({ op: 'php', key: 'ad_password' }),
  json:   Object.freeze({ op: 'json', keys: Object.freeze(['ad', 'password']) }),
  xml:    Object.freeze({ op: 'xml', element: 'password' }),
});

/**
 * The exact bytes siteAdminIntegrations writes immediately in front of the
 * published password.
 *
 * A CONSTANT RATHER THAN A STRING IN TWO PLACES, because the page and the
 * descriptor that says how to find the value in the page have to be edited
 * together or not at all. assertSiteSound proves the anchor really occurs in the
 * bytes this module emitted, exactly once, with the password behind it.
 */
const SITE_ADMIN_PASSWORD_ANCHOR = '<th>Bind password</th><td><input type="text" readonly value="';

function esc(v) {
  return str(v)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** 'Title, Department' -> { title, dept }. goad-lab-compile writes exactly that
 *  shape into every user's `description`, and it is the only place the roster
 *  records what a person actually does. */
function descParts(u) {
  const parts = str((u || {}).description).split(',').map((s) => s.trim()).filter(Boolean);
  return { title: parts[0] || 'Staff', dept: parts[1] || '' };
}

function articleFor(word) {
  return /^[aeiou]/i.test(str(word)) ? 'an' : 'a';
}

/**
 * The route path -> file mapping, mirroring roles/cc_web/tasks/resolve.yml.
 *
 * The role derives this itself for a route that carries no `file`, so emitting
 * it is redundant by design: the generator states the filename it means, the
 * role would derive the same one, and the test pins the two rules against each
 * other. Deriving it in only one place would leave the generator unable to say
 * WHICH member carries the credential.
 */
function siteRouteFile(routePath) {
  const p = str(routePath) || '/';
  const rel = p.replace(/^\/+/, '');
  if (rel === '' || p.endsWith('/')) return `${rel}index.html`;
  const last = rel.split('/').pop();
  return last.indexOf('.') !== -1 ? rel : `${rel}/index.html`;
}

/** The public domain the company is known by. goad-lab-compile mints the forest
 *  root as `corp.<public domain>`, so the site's name is the FQDN with that role
 *  label taken back off - never the forest root itself, which is the INTERNAL
 *  name and would put 'corp.' on the client's letterhead. */
function sitePublicDomain(fqdn) {
  const labels = str(fqdn).split('.').filter(Boolean);
  if (labels.length > 2 && GENERIC_DOMAIN_LABELS.indexOf(labels[0].toLowerCase()) !== -1) {
    return labels.slice(1).join('.');
  }
  return labels.join('.') || 'example.com';
}

/**
 * Everything about the client the pages are written from, resolved once.
 *
 * Every field is read out of the labIR rather than invented: the staff are the
 * accounts AD will really create, the departments are the ones the roster is
 * really organised into, the city is the client's own. That is what makes the
 * site and the forest describe one company rather than two.
 */
function siteIdentity(ctx, seed, options, secrets) {
  const publicDomain = sitePublicDomain(ctx.fqdn);
  const city = str((ctx.users.find((u) => str(u.city) && str(u.city) !== '-') || {}).city) || 'head office';
  const founded = hashInt(seed, 'site:founded', 1971, 2011);

  // THE BIOS ARE THE CLIENT'S OWN STAKEHOLDERS. populatePrincipals gives every
  // synthesized filler account the title 'Staff' and gives a stakeholder the
  // role the client wrote on their intake, so a title that is not 'Staff' is
  // exactly "this person came off the paper profile". Service accounts are
  // excluded - a company does not put its application pool identity on the About
  // page - and the whole roster is the fallback, because a site with no bios
  // reads as a fixture.
  //
  // A BIO IS RENDERED FROM `description`, AND THE ATTACK CHAIN WRITES TO THAT
  // FIELD. Two of its seven entries plant a password INTO a user's description
  // (anonymous_rpc, password_in_description), so the account carrying the leak
  // reads as a stakeholder to the title rule above and its bio would publish the
  // foothold password on the public About page - handing the student an entry
  // the exercise wanted them to earn, by a door nobody was watching. Anyone
  // whose description carries a declared secret is therefore dropped here, and
  // put back only on the one page that is SUPPOSED to mirror it.
  const carriesSecret = (text) => {
    const t = str(text);
    for (const secret of secrets) if (secret && t.indexOf(secret) !== -1) return true;
    return false;
  };
  const withTitles = ctx.users.map((u) => Object.assign({}, descParts(u), { user: u }))
    .filter((e) => !carriesSecret(e.user.description));
  const stakeholders = withTitles.filter((e) => e.title.toLowerCase() !== 'staff'
    && !/^svc/i.test(str(e.user.sam)));
  const leaders = (stakeholders.length ? stakeholders : withTitles).slice(0, 5);

  const departments = [];
  for (const e of withTitles) {
    if (e.dept && departments.indexOf(e.dept) === -1) departments.push(e.dept);
  }

  const paths = {};
  for (const key of Object.keys(SITE_PATH_VARIANTS)) {
    paths[key] = hashPick(seed, `site:path:${key}`, SITE_PATH_VARIANTS[key]);
  }

  return {
    org: ctx.org,
    fqdn: ctx.fqdn,
    publicDomain,
    serverName: `www.${publicDomain}`,
    city,
    founded,
    sites: hashInt(seed, 'site:sites', 2, 9),
    phone: `+1 555 ${hashInt(seed, 'site:phone', 1000, 9999)}`,
    street: `${hashInt(seed, 'site:streetno', 2, 240)} ${hashPick(seed, 'site:street', SITE_STREETS)}`,
    tagline: hashPick(seed, 'site:tagline', SITE_TAGLINES),
    palette: hashPick(seed, 'site:palette', SITE_PALETTES),
    font: hashPick(seed, 'site:font', SITE_FONTS),
    layout: hashPick(seed, 'site:layout', SITE_LAYOUTS),
    values: hashSample(seed, 'site:values', SITE_VALUES.slice(), 3),
    leaders,
    departments: departments.length ? departments : ['Operations'],
    paths,
    portalName: hashPick(seed, 'site:portalname',
      ['Staff Portal', 'Team Hub', 'Intranet', 'Workspace', 'Connect']),
    apacheVersion: str(options.apacheVersion || ''),
  };
}

/** One stylesheet per layout, INLINED rather than served from /assets: a
 *  stylesheet is one more route to declare, and a 404 on it is a site that
 *  renders as unstyled HTML while every check in the role still passes. */
function siteCss(id) {
  const p = id.palette;
  const rules = [
    `:root { --ink: ${p.ink}; --wash: ${p.wash}; --accent: ${p.accent}; --edge: ${p.edge}; --head: ${p.head}; }`,
    '* { box-sizing: border-box; }',
    `body { margin: 0; color: var(--ink); background: var(--wash); font-family: ${id.font}; line-height: 1.55; }`,
    'a { color: var(--accent); }',
    'h1, h2, h3 { color: var(--head); line-height: 1.2; }',
    '.wrap { max-width: 1040px; margin: 0 auto; padding: 0 24px; }',
    '.muted { opacity: 0.75; font-size: 0.92em; }',
    'footer { border-top: 1px solid var(--edge); margin-top: 48px; padding: 24px 0; font-size: 0.9em; }',
    'table { border-collapse: collapse; width: 100%; }',
    'th, td { text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--edge); }',
    'input { padding: 8px; border: 1px solid var(--edge); border-radius: 3px; width: 100%; }',
    'label { display: block; margin: 12px 0 4px; font-weight: bold; }',
    '.btn { display: inline-block; margin-top: 16px; padding: 10px 18px; background: var(--accent); color: #fff; border: 0; border-radius: 3px; text-decoration: none; }',
  ];
  if (id.layout === 'stacked') {
    rules.push(
      'header { background: var(--head); color: #fff; padding: 28px 0; }',
      'header a { color: #fff; text-decoration: none; margin-right: 18px; }',
      '.hero { padding: 56px 0 40px; text-align: center; }',
      '.hero h1 { font-size: 2.6em; margin: 0 0 8px; }',
      '.cards { display: flex; flex-wrap: wrap; gap: 18px; }',
      '.card { flex: 1 1 280px; background: #fff; border: 1px solid var(--edge); border-radius: 4px; padding: 20px; }'
    );
  } else if (id.layout === 'sidebar') {
    rules.push(
      '.shell { display: flex; align-items: flex-start; gap: 32px; padding-top: 32px; }',
      'nav.side { flex: 0 0 210px; border-right: 2px solid var(--accent); padding-right: 18px; }',
      'nav.side a { display: block; padding: 7px 0; text-decoration: none; }',
      'nav.side .brand { font-size: 1.3em; font-weight: bold; color: var(--head); margin-bottom: 14px; }',
      'main { flex: 1 1 auto; }',
      '.hero { border-left: 4px solid var(--accent); padding: 6px 0 6px 18px; margin-bottom: 28px; }',
      '.card { background: #fff; border: 1px solid var(--edge); padding: 16px 18px; margin-bottom: 14px; }'
    );
  } else {
    rules.push(
      'header { border-bottom: 4px solid var(--accent); padding: 18px 0; background: #fff; }',
      'header nav a { text-decoration: none; margin-left: 16px; }',
      '.band { padding: 44px 0; }',
      '.band.alt { background: #fff; border-top: 1px solid var(--edge); border-bottom: 1px solid var(--edge); }',
      '.hero { padding: 64px 0; background: var(--head); color: #fff; }',
      '.hero h1 { color: #fff; font-size: 2.3em; margin: 0 0 10px; }',
      '.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; }',
      '.card { background: var(--wash); border: 1px solid var(--edge); padding: 18px; }'
    );
  }
  return rules.join('\n    ');
}

function siteNav(id, active) {
  return [
    { href: '/', label: 'Home' },
    { href: id.paths.about, label: 'About' },
    { href: id.paths.careers, label: 'Careers' },
    { href: id.paths.contact, label: 'Contact' },
    { href: id.paths.portal, label: id.portalName },
  ].map((l) => `<a href="${esc(l.href)}"${l.href === active ? ' class="here"' : ''}>${esc(l.label)}</a>`);
}

/**
 * The page shell, in the layout's own shape.
 *
 * Three branches rather than one shell with a body class, for the same reason
 * there is one writer per artifact VARIANT above: a single template wearing
 * three hats is still a single template, and a student who has seen one CiAB
 * client's site would recognise the next one on sight.
 */
function sitePage(id, o) {
  const nav = siteNav(id, o.route);
  const foot = `<footer><div class="wrap"><p class="muted">${esc(id.org)} &middot; `
    + `${esc(id.street)}, ${esc(id.city)} &middot; ${esc(id.phone)}<br>`
    + `Copyright ${SITE_YEAR} ${esc(id.org)}. All rights reserved.</p></div></footer>`;
  const head = [
    '<!doctype html>',
    '<html lang="en">',
    '<head>',
    '<meta charset="utf-8">',
    '<meta name="viewport" content="width=device-width, initial-scale=1">',
    `<title>${esc(o.title)} | ${esc(id.org)}</title>`,
    `<meta name="description" content="${esc(id.org)} - ${esc(id.tagline)}">`,
    `<style>\n    ${siteCss(id)}\n  </style>`,
    '</head>',
  ].join('\n');

  if (id.layout === 'sidebar') {
    return `${[
      head, '<body>', '<div class="wrap shell">',
      `<nav class="side"><div class="brand">${esc(id.org)}</div>${nav.join('')}</nav>`,
      '<main>', o.body, '</main>', '</div>', foot, '</body>', '</html>',
    ].join('\n')}\n`;
  }
  if (id.layout === 'banded') {
    return `${[
      head, '<body>',
      `<header><div class="wrap"><strong>${esc(id.org)}</strong>`
        + `<nav style="float: right">${nav.join('')}</nav></div></header>`,
      o.body, foot, '</body>', '</html>',
    ].join('\n')}\n`;
  }
  return `${[
    head, '<body>',
    `<header><div class="wrap"><strong>${esc(id.org)}</strong> &nbsp; ${nav.join('')}</div></header>`,
    o.body, foot, '</body>', '</html>',
  ].join('\n')}\n`;
}

/** A section wrapper that respects the layout's banding. */
function siteSection(id, inner, alt) {
  if (id.layout === 'banded') {
    return `<section class="band${alt ? ' alt' : ''}"><div class="wrap">${inner}</div></section>`;
  }
  if (id.layout === 'sidebar') return `<section>${inner}</section>`;
  return `<section class="wrap" style="padding: 28px 0">${inner}</section>`;
}

/** The closing paragraph of the home page. A separate pool because it is the one
 *  sentence every page shape has in common, and two clients whose home pages end
 *  identically read as one brochure with the logo changed. */
const SITE_HOME_CLOSERS = Object.freeze([
  'We have been trading since {year} and work out of {city}.',
  'Since {year} we have run everything out of {city}, and we still do.',
  '{city} has been home since {year}, and most of the team has been here nearly as long.',
  'The company started in {year}; the {city} office has been the centre of it ever since.',
]);

function siteHome(id, seed) {
  // ROTATED, NOT DRAWN INDEPENDENTLY. hashPick draws per department, so a
  // four-entry pool against three cards collides about half the time and one
  // page ends up saying the same sentence twice - which reads as generated,
  // which is the whole thing this generator exists to avoid.
  const blurbs = (dept) => [
    `The ${dept.toLowerCase()} team handles the day to day, so nothing waits on a decision nobody made.`,
    `${dept} is where most client work starts, and where the awkward questions get asked early.`,
    `Our ${dept.toLowerCase()} people are the ones clients ring first, and the ones who ring back.`,
    `${dept} keeps the schedule honest and the paperwork behind it in order.`,
  ];
  const offset = hashInt(seed, 'site:svc', 0, 3);
  const services = id.departments.slice(0, 3).map((dept, i) => {
    const pool = blurbs(dept);
    const blurb = pool[(offset + i) % pool.length];
    return `<div class="card"><h3>${esc(dept)}</h3><p>${esc(blurb)}</p></div>`;
  }).join('');

  const hero = `<div class="hero"><h1>${esc(id.org)}</h1><p>${esc(id.tagline)}</p>`
    + `<a class="btn" href="${esc(id.paths.contact)}">Talk to us</a></div>`;

  const body = [
    id.layout === 'banded' ? `<section class="hero"><div class="wrap"><h1>${esc(id.org)}</h1>`
      + `<p>${esc(id.tagline)}</p><a class="btn" href="${esc(id.paths.contact)}">Talk to us</a>`
      + '</div></section>' : `<div class="wrap">${hero}</div>`,
    siteSection(id, `<h2>What we do</h2><div class="cards">${services}</div>`, false),
    siteSection(id, `<h2>Working with ${esc(id.org)}</h2>`
      + `<p>${esc(hashPick(seed, 'site:homeclose', SITE_HOME_CLOSERS)
        .replace('{year}', String(id.founded)).replace('{city}', id.city))} `
      + `Staff can reach the ${esc(id.portalName.toLowerCase())} at `
      + `<a href="${esc(id.paths.portal)}">${esc(id.paths.portal)}</a>; everyone else is welcome to `
      + `<a href="${esc(id.paths.contact)}">get in touch</a>.</p>`, true),
  ].join('\n');

  return sitePage(id, { route: '/', title: 'Home', body });
}

function siteAbout(id, seed) {
  const opener = hashPick(seed, 'site:about:open', SITE_ABOUT_OPENERS)
    .replace('{year}', String(id.founded));
  const closer = hashPick(seed, 'site:about:close', SITE_ABOUT_CLOSERS)
    .replace('{city}', id.city).replace('{sites}', String(id.sites));

  const bios = id.leaders.map((e) => {
    const sam = str(e.user.sam);
    const joined = hashInt(seed, `site:joined:${sam}`, id.founded + 1, SITE_YEAR - 2);
    const line = hashPick(seed, `site:bio:${sam}`, SITE_BIO_SHAPES)
      .replace('{name}', personName(e.user))
      .replace('{title}', e.title)
      .replace('{article}', articleFor(e.title))
      .replace('{dept}', e.dept || 'the team')
      .replace('{org}', id.org)
      .replace('{year}', String(joined));
    return `<div class="card"><h3>${esc(personName(e.user))}</h3>`
      + `<p class="muted">${esc(e.title)}${e.dept ? ` &middot; ${esc(e.dept)}` : ''}</p>`
      + `<p>${esc(line)}</p></div>`;
  }).join('\n');

  const values = id.values
    .map(([heading, line]) => `<div class="card"><h3>${esc(heading)}</h3><p>${esc(line)}</p></div>`)
    .join('');

  const body = [
    siteSection(id, `<div class="hero"><h1>About ${esc(id.org)}</h1></div>`
      + `<p>${esc(id.org)} ${esc(opener)}</p><p>${esc(closer)}</p>`, false),
    siteSection(id, `<h2>The people who run it</h2><div class="cards">${bios}</div>`, true),
    siteSection(id, `<h2>How we work</h2><div class="cards">${values}</div>`, false),
  ].join('\n');

  return sitePage(id, { route: id.paths.about, title: 'About', body });
}

function siteCareers(id, seed) {
  const openings = id.departments.slice(0, 4).map((dept) => {
    const noun = hashPick(seed, `site:role:${dept}`, SITE_ROLE_NOUNS);
    const kind = hashPick(seed, `site:kind:${dept}`, ['Full time', 'Full time', 'Part time', 'Fixed term']);
    const line = hashPick(seed, `site:jd:${dept}`, [
      `You will be the person the ${dept.toLowerCase()} team goes to when something does not add up.`,
      `Expect to spend your first month learning how ${id.org} works before changing any of it.`,
      'This role suits somebody who would rather fix the process than work around it.',
      'You will own a small number of clients end to end, with the support to do it properly.',
    ]);
    return `<div class="card"><h3>${esc(dept)} ${esc(noun)}</h3>`
      + `<p class="muted">${esc(kind)} &middot; ${esc(id.city)}</p><p>${esc(line)}</p></div>`;
  }).join('\n');

  const body = [
    siteSection(id, '<div class="hero"><h1>Careers</h1></div>'
      + `<p>We hire people who want to stay. Most of the team joined before ${id.founded + 20} `
      + 'and are still here.</p>', false),
    siteSection(id, `<h2>Open roles</h2><div class="cards">${openings}</div>`, true),
    siteSection(id, '<h2>How to apply</h2><p>Send a CV and a paragraph about the last thing you '
      + `fixed to <a href="mailto:careers@${esc(id.publicDomain)}">careers@${esc(id.publicDomain)}</a>. `
      + 'We reply to everyone.</p>', false),
  ].join('\n');

  return sitePage(id, { route: id.paths.careers, title: 'Careers', body });
}

function siteContact(id, seed) {
  const hours = hashPick(seed, 'site:hours', [
    'Monday to Friday, 08:00 to 18:00',
    'Monday to Saturday, 07:30 to 17:30',
    'Weekdays 09:00 to 17:00, with an out-of-hours line for contract clients',
  ]);
  const body = [
    siteSection(id, `<div class="hero"><h1>Contact ${esc(id.org)}</h1></div>`
      + `<table><tr><th>Address</th><td>${esc(id.street)}, ${esc(id.city)}</td></tr>`
      + `<tr><th>Telephone</th><td>${esc(id.phone)}</td></tr>`
      + `<tr><th>Email</th><td><a href="mailto:hello@${esc(id.publicDomain)}">`
      + `hello@${esc(id.publicDomain)}</a></td></tr>`
      + `<tr><th>Opening hours</th><td>${esc(hours)}</td></tr></table>`, false),
    siteSection(id, '<h2>Send us a message</h2>'
      + `<form method="post" action="${esc(id.paths.contact)}">`
      + '<label for="cname">Your name</label><input id="cname" name="name" type="text">'
      + '<label for="cmail">Email</label><input id="cmail" name="email" type="email">'
      + '<label for="cmsg">Message</label><input id="cmsg" name="message" type="text">'
      + '<button class="btn" type="submit">Send</button></form>'
      + `<p class="muted">Messages are read by the ${esc(id.departments[0].toLowerCase())} team `
      + 'during opening hours.</p>', true),
  ].join('\n');

  return sitePage(id, { route: id.paths.contact, title: 'Contact', body });
}

/**
 * The portal, and the weakness.
 *
 * ONE FINDING, AND IT IS AN OWASP CLASSIC. The settings page is reachable
 * without a session, and the login page names it in a comment a developer left
 * behind. Broken access control plus an information leak are the two findings a
 * first-year student is expected to be able to name; this course is an
 * introduction, and a lane whose only route in is a technique nobody has been
 * taught yet is a lane nobody finishes.
 */
function sitePortal(id, seed, adminPath) {
  const notice = hashPick(seed, 'site:portal:notice', [
    'Scheduled maintenance this Sunday from 02:00. Timesheets will be read only.',
    'Reminder: expense claims for the quarter close on the 28th.',
    'The new starter checklist has moved. See the HR folder on the share.',
    'Phones are being replaced floor by floor. IT will contact you before your desk.',
  ]);
  const body = [
    siteSection(id, `<div class="hero"><h1>${esc(id.portalName)}</h1></div>`
      + `<p class="muted">${esc(notice)}</p>`
      + `<form method="post" action="${esc(id.paths.portal)}">`
      + '<label for="u">Username</label><input id="u" name="username" type="text" autocomplete="username">'
      + '<label for="p">Password</label><input id="p" name="password" type="password" autocomplete="current-password">'
      + '<button class="btn" type="submit">Sign in</button></form>'
      + `<p class="muted">Sign in with your ${esc(id.org)} network account. Lost your password? `
      + `Ring the service desk on ${esc(id.phone)}.</p>`, false),
    // THE BREADCRUMB. A comment in the markup is where a real one is found, and
    // it is the difference between "guess a URL" and "read the page".
    `<!-- TODO(${esc(id.departments[0].toLowerCase())}): the integration settings page at `
      + `${esc(adminPath)} is still served`,
    `     without a session check. Raised with the vendor in ${SITE_YEAR - 1}. -->`,
  ].join('\n');

  return sitePage(id, { route: id.paths.portal, title: id.portalName, body });
}

/**
 * The settings page that names the directory bind account.
 *
 * It always exists, and it always shows the credential the site publishes -
 * which is the FOOTHOLD only when the attack chain said the foothold is planted
 * on the website (SITE_WEB_PLANT_FORMATS). For an AD-side entry the account here
 * is an inert one that leads nowhere, so the page is a real finding without
 * being a shortcut past the technique the lab is teaching.
 */
function siteAdminIntegrations(id, seed, cred, adminPath) {
  const lastSync = `${SITE_YEAR - 1}-${String(hashInt(seed, 'site:sync:m', 1, 12)).padStart(2, '0')}`
    + `-${String(hashInt(seed, 'site:sync:d', 1, 28)).padStart(2, '0')}`;
  const body = siteSection(id, '<div class="hero"><h1>Integration settings</h1></div>'
    + `<p class="muted">${esc(id.portalName)} administration &middot; directory synchronisation</p>`
    + '<table>'
    + '<tr><th>Provider</th><td>Active Directory (LDAP)</td></tr>'
    + `<tr><th>Directory host</th><td>${esc(cred.ldapHost)}</td></tr>`
    + `<tr><th>Base DN</th><td>${esc(cred.baseDn)}</td></tr>`
    + `<tr><th>Bind account</th><td>${esc(cred.domain)}\\${esc(cred.username)}</td></tr>`
    // The anchor is a shared constant: this line and site.reseed's descriptor
    // for it are one edit or none. See SITE_ADMIN_PASSWORD_ANCHOR.
    + `<tr>${SITE_ADMIN_PASSWORD_ANCHOR}${esc(cred.password)}"></td></tr>`
    + `<tr><th>Configuration file</th><td>${esc(cred.configUrl)}</td></tr>`
    + `<tr><th>Last successful sync</th><td>${esc(lastSync)}</td></tr>`
    + '</table>'
    + '<p class="muted">Changing these values will interrupt sign in for every member of staff. '
    + `The service account is managed by ${esc(id.departments[0])}.</p>`, false);

  return sitePage(id, { route: adminPath, title: 'Integration settings', body });
}

/**
 * The staff directory, for the one entry whose leak IS a directory attribute
 * mirrored on the public site.
 *
 * It prints each person's AD `description` VERBATIM, which is exactly what the
 * chain's own `how` claims the site does. For the leaked account that attribute
 * is the onboarding password the designer planted; for everybody else it is a
 * job title and a department.
 */
function siteStaffDirectory(id, people, routePath) {
  const rows = people.map((u) => `<tr><td>${esc(personName(u))}</td>`
    + `<td>${esc(u.sam)}</td><td>${esc(u.description)}</td></tr>`).join('\n');
  const body = siteSection(id, '<div class="hero"><h1>Staff directory</h1></div>'
    + `<p class="muted">Synchronised nightly from the ${esc(id.org)} directory. `
    + `Contact ${esc(id.departments[0])} to correct an entry.</p>`
    + `<table><tr><th>Name</th><th>Account</th><th>Directory record</th></tr>${rows}</table>`, false);
  return sitePage(id, { route: routePath, title: 'Staff directory', body });
}

function siteRobots(id, disallow) {
  return `${[
    '# Generated by the site build. Do not edit by hand.',
    'User-agent: *',
    ...disallow.map((p) => `Disallow: ${p}`),
    '',
    `Sitemap: https://${id.serverName}/sitemap.xml`,
  ].join('\n')}\n`;
}

/**
 * Everything a per-lane reseed must rewrite for the website to stop advertising
 * the BAKED password, with the location and the format of each.
 *
 * WHY THIS IS EMITTED AND NOT DERIVED LATER. By the time lane-reseed runs, the
 * labIR is gone: profile-deploy replaces spec.goad.lab with a deploy-shaped lab
 * def, deliberately, because the IR is hundreds of kilobytes and a pre-baked
 * lane runs no playbook. So the ONLY moment at which "the config is an ini at
 * /var/www/cc-web/config/settings.ini, and the password is the `password` key of
 * its [directory] section" is knowable is right here, while the site is being
 * authored. Anything downstream would be guessing, and guessing a path is how
 * this defect comes back silently.
 *
 * THREE KINDS OF TARGET, and they are genuinely different files:
 *   app_config        the config cc_web templates under the docroot, in one of
 *                     five formats. The value's address is SITE_PIVOT_FIELD.
 *   published_page    an HTML page this module wrote that PRINTS the password:
 *                     always the integration-settings page, and additionally the
 *                     staff directory when the chain's entry mirrors an AD
 *                     description on the web.
 *   unrotatable       a place the same string is published that a mechanical
 *                     rewrite cannot reach. Recorded rather than dropped: an
 *                     unreported one is the whole defect again.
 *
 * @returns {{docroot:string, username:string, domain:string, plants:Array, unrotatable:Array}}
 */
function siteReseedPlan({ docroot, configUrl, configFormat, routes, adminPath,
  directoryPath, cred, leakedUser, mirrorsDescription }) {
  const plants = [];
  const unrotatable = [];
  const fileFor = (routePath) => {
    const route = routes.filter((r) => r.path === routePath)[0];
    return route ? { path: `${docroot}/${route.file}`, content: route.content } : null;
  };

  const field = SITE_PIVOT_FIELD[configFormat];
  if (!field) {
    // Unreachable through generateSiteContent (configFormat comes out of
    // SITE_FORMAT_BY_EXT or SITE_CONFIG_FILES, and the test pins both against
    // this table) - and a refusal rather than a skip, because a config file the
    // reseed cannot address is a lane that publishes the baked password.
    fail('SITE_RESEED_FORMAT_UNADDRESSABLE',
      `site content: the pivot config is rendered as '${configFormat}' and nothing records where the `
      + `password sits inside that format (SITE_PIVOT_FIELD knows `
      + `${Object.keys(SITE_PIVOT_FIELD).join(', ')}). A per-lane reseed would rotate the account in `
      + 'Active Directory and leave the website serving the baked password, which is a pivot that '
      + 'silently does not work.', 'site.pivot.format');
  }
  plants.push(Object.assign({
    kind: 'app_config',
    path: `${docroot}${configUrl}`,
    format: configFormat,
    why: `the application configuration cc_web templates under the docroot, rendered as ${configFormat}`,
  }, field));

  const admin = fileFor(adminPath);
  if (admin) {
    plants.push({
      kind: 'published_page',
      path: admin.path,
      format: 'html',
      op: 'slot',
      anchor: SITE_ADMIN_PASSWORD_ANCHOR,
      prefix: '',
      suffix: '',
      terminator: '"',
      escape: 'html',
      why: 'the integration settings page prints the bind password in the clear, and it is the page '
        + 'the portal comment points a student at',
    });
  } else {
    // Cannot happen through generateSiteContent, which always adds the page.
    // Recorded rather than assumed, because "the page was not there" and "there
    // is nothing to rewrite" must not be the same answer.
    unrotatable.push({
      where: adminPath,
      why: 'the integration settings page is declared but no route serves it, so nothing can be '
        + 'rewritten there',
    });
  }

  // The mirrored staff directory. The password sits INSIDE the person's AD
  // description, so the slot is the whole description cell and the prose either
  // side of the value travels with the descriptor - no secret, just the words
  // that surround it.
  if (directoryPath && leakedUser) {
    const page = fileFor(directoryPath);
    const desc = str(leakedUser.description);
    const parts = desc.split(str(cred.password));
    if (page && parts.length === 2) {
      plants.push({
        kind: 'published_page',
        path: page.path,
        format: 'html',
        op: 'slot',
        anchor: `<td>${esc(str(leakedUser.sam))}</td><td>`,
        prefix: esc(parts[0]),
        suffix: esc(parts[1]),
        terminator: '</td>',
        escape: 'html',
        why: "the staff directory mirrors the leaked account's AD description, and the description "
          + 'is where the chain planted the password',
      });
    } else {
      unrotatable.push({
        where: page ? page.path : directoryPath,
        why: `the leaked description for '${str(leakedUser.sam)}' does not contain the published `
          + 'password exactly once, so the reseed cannot replace it without rewriting the sentence',
      });
    }
  }

  if (mirrorsDescription) {
    // The directory attribute itself. LDAP hands it out to anyone who can read
    // the object, so a rotated account whose description still spells the old
    // password is a second copy nobody rewrote. lane-reseed cannot fix it from
    // here - it would need Set-ADUser -Description on the DC - so it is named.
    unrotatable.push({
      where: `AD description of ${str(cred.username)}`,
      why: "this lab's entry is 'ad_description_mirrored_on_web', so the password is also the "
        + "account's directory description. Rotating the account per lane leaves that attribute "
        + 'spelling the baked value, and anything that can read the object can read it',
    });
  }

  return {
    docroot,
    username: str(cred.username),
    domain: str(cred.domain),
    plants,
    unrotatable,
  };
}

/**
 * Generate one client's website: the marketing surface, the portal, the weakness
 * and the planted credential, plus the web-facts block that says what the lane
 * will really serve.
 *
 * @param {object} labIR  goad-lab-compile's `ir`, after applyAttackChain().
 * @param {object} [opts]
 * @param {string} [opts.runId]         the seed. Defaults to labIR.run_id, then
 *                                      labIR.lab_name.
 * @param {object} [opts.lab]           the compiled `lab` dict. Used only to
 *                                      widen the forbidden-secret set.
 * @param {string} [opts.apacheVersion] the version the base image really ships.
 *                                      EMPTY BY DEFAULT, DELIBERATELY: the
 *                                      version is a fact about the image, not
 *                                      about the client, and cc_web's verify.yml
 *                                      FAILS a declared version the installed
 *                                      binary does not match. An empty version
 *                                      declares none, which sets ServerTokens
 *                                      Prod and is true on every image.
 * @returns {object} the site, in the shape the cc_web role's variables want.
 */
function generateSiteContent(labIR, opts) {
  const options = isObject(opts) ? opts : {};
  const ir = isObject(labIR) ? labIR : {};
  const seed = str(options.runId || ir.run_id || ir.lab_name);
  if (!seed) {
    fail('SITE_NO_SEED',
      'site content: no seed. Every route spelling, palette, bio and config filename is a hash of '
      + 'the run id, so without one a client would get a different website every time it was '
      + 'regenerated - and a site that cannot be regenerated cannot be checked against the paper.',
      'run_id');
  }

  const ctx = indexIr(ir, options);
  const secrets = declaredSecrets(ir, options.lab);
  const id = siteIdentity(ctx, seed, options, secrets);
  const warnings = [];

  // -- what the site plants, and why ----------------------------------------
  const foothold = isObject(ctx.foothold) ? ctx.foothold : {};
  const plantedAt = isObject(foothold.planted_at) ? foothold.planted_at : {};
  const plantFormat = str(plantedAt.format);
  const websidePlant = SITE_WEB_PLANT_FORMATS.indexOf(plantFormat) !== -1;
  const mirrorsDescription = plantFormat === 'ad_description_mirrored_on_web';
  const footholdCred = str(foothold.sam) && str(foothold.password)
    ? { sam: str(foothold.sam), password: str(foothold.password), domain: str(foothold.domain) }
    : null;

  if (websidePlant && !footholdCred) {
    fail('SITE_FOOTHOLD_INCOMPLETE',
      'site content: the attack chain plants the foothold on the website (planted_at.format '
      + `'${plantFormat}') and labIR.foothold_credential carries no sam and password. The site would `
      + 'publish nothing, and the chain would start at a credential that exists nowhere.',
      'labIR.foothold_credential');
  }

  // The account whose password ends up in the app config. It is the foothold
  // whenever the chain plants on the web side; otherwise it is a real bind
  // account that leads nowhere - the same rule writeWebConfig applies to the
  // artifact it plants INSIDE the forest, for the same reason.
  const inertPool = seededShuffle(seed, 'site:bind', inertUsers(ctx));
  const bindCred = websidePlant
    ? footholdCred
    : (inertPool.length
      ? { sam: str(inertPool[0].sam), password: str(inertPool[0].password), domain: str(inertPool[0].domain) || ctx.fqdn }
      : footholdCred);
  if (!bindCred || !bindCred.password) {
    fail('SITE_NO_BIND_CREDENTIAL',
      'site content: this lab has no credential the website could plant - no foothold, and no inert '
      + 'roster account with a password. cc_web refuses to build a web host with no pivot credential, '
      + 'because a DMZ box that leads nowhere is a defaced homepage rather than a way into the domain.',
      'labIR.principals.users');
  }
  if (!websidePlant && footholdCred && bindCred.sam === footholdCred.sam) {
    fail('SITE_FOOTHOLD_LEAKED',
      `site content: the chain's entry plants the foothold as '${plantFormat}', which is not a `
      + `web-side plant, and the only credential available to the website is the foothold itself `
      + `('${bindCred.sam}'). Publishing it would hand the student the entry the exercise wanted `
      + 'them to earn, and the intended technique would be decoration.', 'labIR.foothold_credential');
  }

  const bindDomain = ctx.domains.filter((d) => str(d.fqdn) === bindCred.domain)[0] || ctx.domain;
  const bindNetbios = str(bindDomain.netbios) || str(bindDomain.fqdn).split('.')[0].toUpperCase();

  // -- where the credential lands -------------------------------------------
  // A PATH THE CHAIN NAMED WINS. planted_at.path was fixed before this module
  // ran and the answer key already prints it, so choosing our own would make the
  // key point at a URL the site does not serve.
  const namedPath = websidePlant && str(plantedAt.path).startsWith('/') ? str(plantedAt.path) : '';
  const namedIsFile = /\.[a-z0-9]{1,6}$/i.test(namedPath.split('/').pop() || '');
  let configUrl;
  let configFormat;
  if (namedPath && namedIsFile) {
    configUrl = namedPath;
    const ext = (configUrl.split('.').pop() || '').toLowerCase();
    configFormat = SITE_FORMAT_BY_EXT[ext];
    if (!configFormat) {
      // Not a guess and not a silent fallback: an unrenderable format is a
      // refusal ninety minutes into a provisioning run, so it is named here.
      fail('SITE_PIVOT_FORMAT_UNSUPPORTED',
        `site content: the attack chain plants the foothold at '${configUrl}', whose '.${ext}' `
        + `extension is not one cc_web can render (${Object.keys(SITE_FORMAT_BY_EXT).join(', ')}). `
        + 'The role would refuse the format at provision time, or write a file no parser reads.',
        'labIR.foothold_credential.planted_at.path');
    }
  } else {
    const pick = hashPick(seed, 'site:config', SITE_CONFIG_FILES);
    configUrl = `/${pick.dir}/${pick.name}`;
    configFormat = pick.format;
  }

  // The settings page. Under the portal unless the chain named a page of its
  // own, and NOT declared in web_facts.paths - the role's README is explicit
  // that a route the paper does not mention is legitimate exercise design, while
  // a declared path that serves nothing is the paper lying.
  const adminPath = (namedPath && !namedIsFile && !mirrorsDescription)
    ? namedPath
    : `${id.paths.portal}/admin/integrations`;
  const directoryPath = mirrorsDescription
    ? (namedPath || '/staff-directory')
    : null;

  const ldapHost = `${str(ctx.dcHost.hostname).toLowerCase()}.${bindDomain.fqdn}`;
  const pageCred = {
    domain: bindNetbios,
    username: bindCred.sam,
    password: bindCred.password,
    ldapHost,
    baseDn: dnFor(bindDomain.fqdn),
    configUrl,
  };

  // -- the routes -----------------------------------------------------------
  const routes = [];
  const declaredPaths = [];
  const add = (routePath, body, o) => {
    const opts2 = isObject(o) ? o : {};
    const p = str(routePath) || '/';
    routes.push({
      path: p,
      file: siteRouteFile(p),
      content: assertAscii(body, `site:${p}`),
      declared: opts2.declared !== false,
      carries_foothold: opts2.carriesFoothold === true,
      why: str(opts2.why),
    });
    if (opts2.declared !== false) declaredPaths.push(p);
  };

  add('/', siteHome(id, seed), { why: 'the front door the report links to first' });
  add(id.paths.about, siteAbout(id, seed), {
    why: "the staff the forest really creates, with the titles the client's own intake gave them",
  });
  add(id.paths.careers, siteCareers(id, seed), { why: 'a real company advertises jobs' });
  add(id.paths.contact, siteContact(id, seed), {
    why: 'the address, telephone number and hours the paper profile prints',
  });
  add(id.paths.portal, sitePortal(id, seed, adminPath), {
    why: 'the staff portal, and the comment that names the page nobody protected',
  });
  add(adminPath, siteAdminIntegrations(id, seed, pageCred, adminPath), {
    declared: false,
    carriesFoothold: websidePlant && !mirrorsDescription,
    why: 'the settings page served without a session check - the finding, and the account it names',
  });

  let leaked = null;
  if (directoryPath) {
    // The leaked user has to BE on the page that leaks them. They are a roster
    // account rather than a stakeholder more often than not, so appending them
    // is what makes the chain's `how` true instead of nearly true.
    const shown = id.leaders.map((e) => e.user);
    leaked = ctx.users.filter((u) => bareSam(str(u.sam)).toLowerCase()
      === bareSam(str(footholdCred.sam)).toLowerCase())[0] || null;
    if (leaked && shown.indexOf(leaked) === -1) shown.push(leaked);
    add(directoryPath, siteStaffDirectory(id, shown, directoryPath), {
      carriesFoothold: true,
      why: "the chain's entry mirrors an AD description attribute on the public site; this page is "
        + 'the mirror, and the record it prints is the one the designer leaked',
    });
  }

  const adminDir = adminPath.replace(/\/[^/]*$/, '/');
  add('/robots.txt', siteRobots(id, [id.paths.portal].concat(adminDir === '/' ? [] : [adminDir])), {
    declared: false,
    why: 'disallowing a path is how a real site tells a scanner the path is there',
  });

  // -- the web-facts contract -----------------------------------------------
  // Built from the routes that were actually written, so `paths` cannot name a
  // page the site does not serve. cc_web asserts the same thing from the other
  // side and refuses to build a host whose declared path has no content; both
  // ends check it because they run in different processes ninety minutes apart.
  const ports = [80, 443];
  if (hashCoin(seed, 'site:altport', 30)) ports.push(8080);
  const webFacts = {
    product: 'apache',
    version: id.apacheVersion,
    ports,
    tls: {
      enabled: true,
      port: 443,
      protocols: hashPick(seed, 'site:tls', SITE_TLS_SETS).slice(),
    },
    paths: declaredPaths.slice(),
  };

  if (!websidePlant) {
    const how = plantFormat || 'nothing this module recognises';
    warnings.push(`the chain's entry plants the foothold as '${how}', which is not a web-side plant, `
      + `so the website publishes an ordinary bind account (${bindCred.sam}) instead. That is `
      + 'deliberate: putting the foothold password on a page anybody can GET would make the designed '
      + 'entry technique decorative');
  }

  const site = {
    seed,
    lab_name: str(ir.lab_name) || null,
    domain: ctx.fqdn,
    org: id.org,
    public_domain: id.publicDomain,
    server_name: id.serverName,
    docroot: SITE_DOCROOT,
    layout: id.layout,
    portal_path: id.paths.portal,
    admin_path: adminPath,
    directory_path: directoryPath,
    web_facts: webFacts,
    routes,
    staff: id.leaders.map((e) => ({
      sam: str(e.user.sam), name: personName(e.user), title: e.title, department: e.dept,
    })),
    pivot: {
      // INSIDE THE DOCROOT, ON PURPOSE, AND DECLARED AS SUCH. cc_web refuses a
      // credential file under the docroot unless the caller says
      // allow_in_docroot, because a downloadable password and a file an attacker
      // has to earn are two different exercises. This role installs a STATIC
      // site - there is no application to exploit for a file read - so the only
      // version of this finding a student can actually reach is the config left
      // in the web root, which is also one of the commonest real findings there
      // is.
      path: `${SITE_DOCROOT}${configUrl}`,
      format: configFormat,
      domain: bindNetbios,
      username: bindCred.sam,
      password: bindCred.password,
      // QUOTED, because cc_web asserts it is a string: YAML reads an unquoted
      // 0640 as the integer 640 and applies it as a nonsense permission set.
      mode: '0640',
      dir_mode: '0750',
      allow_in_docroot: true,
      extra: {
        ldap_host: ldapHost,
        ldap_base_dn: dnFor(bindDomain.fqdn),
        app_name: id.portalName,
      },
    },
    pivot_url: configUrl,
    // WHAT A PER-LANE RESEED HAS TO REWRITE. Carried on the site so the bake can
    // put it on the deploy spec: without it lane-reseed rotates the account in
    // AD and the website keeps handing out the baked password, which is a green
    // lane whose pivot does not work. See siteReseedPlan.
    reseed: siteReseedPlan({
      docroot: SITE_DOCROOT,
      configUrl,
      configFormat,
      routes,
      adminPath,
      directoryPath,
      cred: pageCred,
      leakedUser: leaked,
      mirrorsDescription,
    }),
    carries_foothold: websidePlant,
    foothold_planted_in: websidePlant ? configUrl : null,
    warnings,
  };

  assertSiteSound(site, ir, options.lab);
  return site;
}

/**
 * Everything that must be true of a generated site, checked on the way out.
 *
 * THE FOOTHOLD SEAM IS CHECKED IN BOTH DIRECTIONS, and neither direction is
 * optional:
 *
 *   site -> AD   every credential the site plants must be one the forest is
 *                really built with. A website handing out a password AD never
 *                heard of is a lab whose second act never starts, and nothing
 *                reports it: the deploy is green, the student sprays the
 *                credential, and the domain controller says no.
 *   AD -> site   when the chain says the foothold is planted on the website, the
 *                site must plant EXACTLY that string. The same dead end,
 *                arrived at from the other side.
 *
 * The AD half is DELEGATED to goad-lab-compile.assertFootholdHonoured rather
 * than re-implemented here. That function is the compiler's own gate on this
 * invariant, and a second copy of it in this file is a second thing to keep
 * true - the first time the two disagreed, the one that was wrong would be
 * whichever one nobody ran. It is required lazily for the same reason
 * profile-deploy requires the compiler lazily: pulling the chassis library, the
 * validator and the pre-flight into the load graph of every caller of this
 * module would cost every one of them, for a function only this branch calls.
 */
function assertSiteSound(site, ir, lab) {
  const forbidden = forbiddenSecrets(lab);

  // 1. Nothing the role would mangle on the way in. ansible renders a variable's
  //    value recursively, so a page carrying {{ }} is evaluated long before the
  //    copy task sees the bytes - see the header of roles/cc_web/tasks/content.yml.
  //    The caller tags route content !unsafe as well; this refuses to depend on
  //    it, because a page that renders as "49" costs a day to diagnose.
  for (const route of site.routes) {
    assertAscii(route.content, `site:${route.path}`);
    if (/\{\{|\{%/.test(route.content)) {
      fail('SITE_ROUTE_TEMPLATED',
        `site content: the page at '${route.path}' contains a Jinja delimiter. ansible would either `
        + 'raise AnsibleUndefinedVariable on it or, worse, silently evaluate it to something else.',
        route.path);
    }
  }

  // 2. One file per route. Two routes resolving to one file is not something the
  //    role can see coming: the second copy wins and one page serves the other's
  //    content.
  const files = site.routes.map((r) => r.file);
  const dupe = files.filter((f, i) => files.indexOf(f) !== i)[0];
  if (dupe) {
    fail('SITE_DUPLICATE_MEMBER',
      `site content: two routes both resolve to '${dupe}' under the docroot.`, dupe);
  }

  // 3. Every declared path has content. web_facts.paths is exactly what the scan
  //    documents are allowed to link to.
  for (const declared of site.web_facts.paths) {
    if (!site.routes.some((r) => r.path === declared)) {
      fail('SITE_DECLARED_PATH_UNSERVED',
        `site content: web_facts.paths declares '${declared}' and no route serves it. The report `
        + 'would link to a 404, which is the paper lying about the lane.', declared);
    }
  }

  // 4. The pivot is deliverable by the role that will install it.
  const pivot = isObject(site.pivot) ? site.pivot : {};
  if (!str(pivot.path).startsWith('/') || !str(pivot.username) || !str(pivot.password)
    || !str(pivot.domain) || !str(pivot.format)) {
    fail('SITE_PIVOT_INCOMPLETE',
      'site content: the pivot credential needs an absolute path, a format, a domain, a username and '
      + 'a password. cc_web templates a missing field as an empty string, which writes a config file '
      + 'that looks planted and names no account at all.', 'site.pivot');
  }
  if (str(pivot.path).indexOf(`${site.docroot}/`) === 0 && pivot.allow_in_docroot !== true) {
    fail('SITE_PIVOT_IN_DOCROOT',
      `site content: the pivot file '${pivot.path}' is inside the docroot and does not declare `
      + 'allow_in_docroot. cc_web refuses that combination, because a password anyone can download '
      + 'and one an attacker has to earn are two different exercises.', 'site.pivot');
  }

  // 5. site -> AD.
  const users = asArray((ir.principals || {}).users);
  const sam = bareSam(str(pivot.username)).toLowerCase();
  const user = users.filter((u) => bareSam(str(u.sam)).toLowerCase() === sam)[0];
  if (!user) {
    fail('SITE_CREDENTIAL_NOT_IN_AD',
      `site content: the website plants a credential for '${pivot.username}' at '${pivot.path}', and `
      + 'labIR.principals.users creates no such account. The student would find a password, spray it '
      + 'at the domain controller and be told the account does not exist - with nothing anywhere in '
      + 'the deploy reporting a problem.', pivot.path);
  }
  if (str(user.password) !== str(pivot.password)) {
    fail('SITE_CREDENTIAL_NOT_HONOURED',
      `site content: the website plants a password for '${pivot.username}' that the forest does not `
      + 'set for that account. Two generators each doing their job correctly over two different '
      + 'strings - the login fails and both halves report success.', pivot.path);
  }
  if (forbidden.has(str(pivot.password))) {
    fail('SITE_CREDENTIAL_FORBIDDEN',
      `site content: the website would publish the domain or local administrator password at `
      + `'${pivot.path}'. A student who reads it holds Domain Admin before the first edge, and the `
      + 'entire designed chain is decoration.', pivot.path);
  }

  // 6. AD -> site.
  const foothold = isObject(ir.foothold_credential) ? ir.foothold_credential : {};
  const at = isObject(foothold.planted_at) ? foothold.planted_at : {};
  if (SITE_WEB_PLANT_FORMATS.indexOf(str(at.format)) !== -1) {
    if (str(pivot.password) !== str(foothold.password)
      || sam !== bareSam(str(foothold.sam)).toLowerCase()) {
      fail('SITE_FOOTHOLD_NOT_PLANTED',
        `site content: labIR declares the foothold '${str(foothold.sam)}' is planted on the website `
        + `(planted_at.format '${str(at.format)}') and the site plants '${str(pivot.username)}' `
        + 'instead. The chain starts at a credential nothing on the web side hands out, so there is '
        + 'no way in and step one of the answer key is fiction.', 'labIR.foothold_credential');
    }
    // eslint-disable-next-line global-require
    require('./goad-lab-compile').assertFootholdHonoured(ir);
    for (const route of site.routes.filter((r) => r.carries_foothold)) {
      if (route.content.indexOf(str(foothold.password)) === -1) {
        fail('SITE_FOOTHOLD_NOT_IN_PAGE',
          `site content: '${route.path}' is recorded as a page that carries the foothold and its `
          + 'bytes do not contain the password. The record and the file disagree, and the record is '
          + 'what the answer key prints.', route.path);
      }
    }
  }

  // 7. NOTHING ELSE LEAKS. The site publishes exactly ONE credential - the one
  //    in the app config, plus the description the chain asked to be mirrored -
  //    and every other password in the lab must be absent from every byte it
  //    serves. This is the guard that caught the real bug: two of the seven
  //    entry points plant a password into a user's `description`, the About page
  //    renders `description` because that is where a person's job title lives,
  //    and the site published the foothold on a page anybody can GET while every
  //    other check passed.
  const mirrors = str(at.format) === 'ad_description_mirrored_on_web';
  const publishable = new Set([str(pivot.password)]);
  if (mirrors) publishable.add(str(foothold.password));
  for (const secret of declaredSecrets(ir, lab)) {
    if (publishable.has(secret)) continue;
    const leaked = site.routes.filter((r) => r.content.indexOf(secret) !== -1)[0];
    if (leaked) {
      fail('SITE_SECRET_LEAKED',
        `site content: the page at '${leaked.path}' contains a credential this lab declares and the `
        + 'site is not supposed to publish. The website is allowed to hand out exactly one password, '
        + 'and a second one on a page anybody can GET is a route into the domain that nothing wrote '
        + 'down.', leaked.path);
    }
  }

  // 8. THE RESEED DESCRIPTOR ADDRESSES BYTES THAT ARE REALLY THERE.
  //
  //    A descriptor is a claim about where a value lives, and an unchecked claim
  //    is worth nothing: lane-reseed's whole failure mode is being pointed at a
  //    path or an anchor that no longer matches, rotating the account anyway and
  //    leaving the site advertising the baked password. So every page target is
  //    proved against the bytes THIS RUN emitted - the anchor occurs, exactly
  //    once, with the published password behind it - and every file target is
  //    proved to be addressable at all.
  const plan = isObject(site.reseed) ? site.reseed : null;
  if (!plan || asArray(plan.plants).length === 0) {
    fail('SITE_RESEED_NO_PLAN',
      'site content: the site publishes a pivot credential and records nowhere for a per-lane reseed '
      + 'to rewrite it. Every lane cloned from this bake would go on serving the baked password while '
      + 'the directory held a different one, and the lane would report healthy.', 'site.reseed');
  }
  const byFile = new Map(site.routes.map((r) => [`${site.docroot}/${r.file}`, r]));
  for (const plant of plan.plants) {
    if (SITE_RESEED_OPS.indexOf(str(plant.op)) === -1) {
      fail('SITE_RESEED_OP_UNKNOWN',
        `site content: the reseed target at '${plant.path}' names operation '${plant.op}', and `
        + `lane-reseed implements ${SITE_RESEED_OPS.join(', ')}. An operation nothing implements is a `
        + 'target that is silently skipped.', plant.path);
    }
    if (str(plant.op) !== 'slot') continue;
    const route = byFile.get(str(plant.path));
    if (!route) {
      fail('SITE_RESEED_TARGET_UNSERVED',
        `site content: the reseed would rewrite '${plant.path}' and this site writes no such file. `
        + 'The reseed would find nothing there, and the page that really publishes the password would '
        + 'keep publishing the baked one.', plant.path);
    }
    const needle = `${str(plant.anchor)}${str(plant.prefix)}${esc(str(pivot.password))}`
      + `${str(plant.suffix)}${str(plant.terminator)}`;
    const first = route.content.indexOf(needle);
    if (first === -1 || route.content.indexOf(needle, first + 1) !== -1) {
      fail('SITE_RESEED_ANCHOR_NOT_UNIQUE',
        `site content: the reseed descriptor for '${plant.path}' claims the published password sits `
        + `behind ${JSON.stringify(str(plant.anchor).slice(0, 60))} and that appears `
        + `${first === -1 ? 'nowhere' : 'more than once'} in the bytes this page really carries. A `
        + 'reseed pointed at an anchor that does not match rewrites nothing and reports success.',
        plant.path);
    }
  }

  return true;
}

module.exports = {
  // Layout and vocabulary a caller should not re-derive.
  FILES_PREFIX,
  SCRIPTS_PREFIX,
  TECHNIQUES,
  ARTIFACT_KINDS,
  ROLE_RANK,
  SECURESTRING_MAGIC,
  ENTRIES_DEFEATED_BY_A_FILE,
  LabContentError,
  // The generator.
  generateLabContent,
  mergeLabContent,
  assertContentSound,
  // The company website: what the DMZ host serves, and the seam it carries.
  SITE_DOCROOT,
  SITE_LAYOUTS,
  SITE_TLS_SETS,
  SITE_CONFIG_FILES,
  SITE_WEB_PLANT_FORMATS,
  // The seam a per-lane reseed rewrites: what to change, where, and in what
  // format. Exported so the bake can carry it and the tests can pin it against
  // lane-reseed's own vocabulary and against the cc_web template.
  SITE_RESEED_OPS,
  SITE_PIVOT_FIELD,
  SITE_ADMIN_PASSWORD_ANCHOR,
  siteReseedPlan,
  generateSiteContent,
  assertSiteSound,
  siteRouteFile,
  sitePublicDomain,
  // Pure primitives, exported because each encodes a rule worth testing alone.
  isAscii,
  firstNonAscii,
  assertAscii,
  seededBytes,
  seededShuffle,
  protectSecureString,
  unprotectSecureString,
  orderVulnsForContent,
  declaredSecrets,
  forbiddenSecrets,
  inertUsers,
  chainPrincipals,
  chainFileRequests,
  chainScriptRequests,
  indexIr,
};
