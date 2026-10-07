/**
 * goad-lab-validate.js — does this lab definition actually compile?
 * ============================================================================
 * A GOAD lab is two files: `ad/<LAB>/data/config.json` (hosts, domains, users,
 * groups, ACLs, per-host vuln roles) and `ad/<LAB>/data/inventory` (which host
 * is in which Ansible group). Nothing upstream checks that the two agree, and
 * nothing checks that the roles a host lists actually exist or were given the
 * variables they read.
 *
 * WHY A VALIDATOR IS WORTH WRITING AT ALL
 * Most of GOAD's failure modes are LOUD — a bad `inheritance` throws, a missing
 * `include_role` name fails the play. The ones that matter here are the QUIET
 * ones, and they all share a shape: the task runs, changes nothing, and Ansible
 * prints green.
 *
 *   - an unrecognised ACL `right` never assigns $ace, so no ACE is written and
 *     the task reports ok (see goad-role-manifest.js acl_matching_note)
 *   - a with_dict role listed with no vars entry iterates an empty dict
 *   - a `shares`/`adcs_esc7` role is structurally broken upstream
 *
 * A green deploy with nothing planted is the worst outcome available: the paper
 * scan report says the box is vulnerable, the student's nmap says it is not, and
 * the instructor has no error to search for. Everything below exists to move one
 * of those silences to generation time, where it is one line in a diff.
 *
 * SHAPE: PURE CORE, THIN THROWING BOUNDARY
 * validateLab() never throws and never touches the filesystem — it takes parsed
 * text and returns { errors, warnings } of { id, code, severity, message }.
 * assertLabCompiles() is the HTTP-facing skin that turns errors into a 409, the
 * same split as engagement-provision.js assertEngagementDeployable().
 *
 * Every message names the bad state AND the remedy, because these are read by an
 * instructor in a toast, not by the person who wrote this file.
 *
 * PARSING IS DELIBERATELY ASYMMETRIC — see parseLabConfig(). We READ like
 * Ansible (YAML, forgiving) and WRITE strict JSON (toStrictJson()).
 *
 * TWO MODES, AND THE MODE IS DECLARED RATHER THAN GUESSED — see
 * VALIDATION_MODES. Everything above is about whether a lab DEPLOYS, which is
 * the only question a hand-written reference lab raises. A lab this repo
 * composed for a client raises a second one — is there anything in it to attack
 * — and 'generated' mode is where that is asked.
 *
 * NO fs, NO path, NO require of anything but the vendored manifest: the caller
 * supplies text. That is what makes this testable against all eight shipped labs
 * without a checkout, and against hand-mutated fixtures with no temp files.
 */

const { getRole, aclRights, isAclRight, loadManifest } = require('./goad-role-manifest');

// ─── Limits ─────────────────────────────────────────────────────────────────
// Named because the numbers are AD's, not ours, and a future reader will
// otherwise assume they are arbitrary house style and "relax" them.

/** sAMAccountName ceiling. Server 2000-era, never lifted; AD silently truncates
 *  nothing — win_domain_user just fails. The dict key IS the sAMAccountName
 *  (roles/onlyusers passes `name: item.key` and win_domain_user derives sam
 *  from name), so this binds on the key, not on firstname/surname. */
const MAX_SAM_ACCOUNT_NAME = 20;

/** CN (the RDN) ceiling for any directory object. Same key again for users, and
 *  the group/OU key for groups and OUs. */
const MAX_COMMON_NAME = 64;

/** NetBIOS computer name ceiling. Over 15 the machine still joins but its
 *  NetBIOS name is a truncation of the DNS name, so two hosts sharing a
 *  15-char prefix collide on the wire and one of them stops answering. */
const MAX_NETBIOS_HOSTNAME = 15;

/** Windows' built-in "Password must meet complexity requirements" policy: at
 *  least 3 of {upper, lower, digit, non-alphanumeric}, 7 characters or more. */
const MIN_DOMAIN_PASSWORD_LEN = 7;
const REQUIRED_PASSWORD_CLASSES = 3;

/**
 * The floor for local_admin_password. Be honest about where this number comes
 * from, because half of it is Windows and half of it is ours:
 *
 *   - On a DC it IS Windows'. DC_PASSWORD_MISMATCH below requires the DC's
 *     local_admin_password to equal domain_password, which dcpromo validates
 *     against the default policy. A weak one fails the promotion.
 *   - On a member server or workstation it is a HOUSE rule. A standalone
 *     Windows box ships with complexity DISABLED and no minimum length, so
 *     Windows itself would accept 'srv_password'. We do not, because this is
 *     the credential the lane's console and WinRM login use, it is handed to
 *     students, and every lane in a cohort is built from the same definition —
 *     one weak string is a platform-wide exposure, not a per-VM one.
 *
 * 8 rather than 7 because that is the local-account floor Windows applies once
 * complexity is switched on, and nothing is gained by matching the domain's
 * looser number here.
 */
const MIN_LOCAL_ADMIN_PASSWORD_LEN = 8;

/** Groups whose host membership we cross-check against config.json. SCOPED ON
 *  PURPOSE: SCCM's inventory puts a host named `elk` in [elk_server], and `elk`
 *  has no config.json entry because it is a Linux appliance built by elk.yml,
 *  not an AD member. Checking "every inventory host is declared" against ALL
 *  groups rejects a lab that upstream deploys every day. */
const MEMBER_GROUPS = ['domain', 'linux_domain'];

/** Default local administrator account. Overridable because the inventory's
 *  [all:vars] carries `admin_user=` and at least one downstream lab renames it. */
const DEFAULT_ADMIN_USER = 'administrator';

// ─── Validation modes ───────────────────────────────────────────────────────

/**
 * WHICH RULES APPLY DEPENDS ON WHERE THE LAB CAME FROM, AND THAT IS DECLARED.
 *
 * 'reference' is a lab somebody WROTE: one of the eight the GOAD fork ships, a
 * chassis, a hand-authored fixture. Its author decided what is in it, so the
 * only question worth asking is the one every rule above asks — does it deploy?
 *
 * 'generated' is a lab this repo COMPOSED for one client, and it carries a
 * second obligation the reference labs do not: it has to be an EXERCISE. A
 * generated forest with `acls: {}` and a null chain passes every rule above. It
 * deploys perfectly — a domain, a roster, hosts that come up green — and there
 * is nothing in it to attack. Nothing upstream reports that, nothing downstream
 * reports it, and the first person to find out is a student who has run out of
 * things to enumerate. It is the same shape as every other failure in this file
 * — the task runs, changes nothing, Ansible prints green — one level up.
 *
 * WHY THE MODE IS AN ARGUMENT AND NOT A HEURISTIC. The tempting shortcut is to
 * infer it from the lab: "an empty acls block means generated-and-broken", "a
 * CIAB- lab name means generated". Every such guess is wrong in a way that is
 * SILENT IN BOTH DIRECTIONS. SCCM ships zero ACL edges and zero OUs by design
 * and DRACARYS ships exactly one edge; both are reference labs that deploy every
 * day, so a heuristic reading an empty acls block as a defect fails the
 * calibrated corpus baseline. And any heuristic loose enough to spare them is
 * loose enough to let a chainless generated lab through. One failure mode
 * rejects labs that work, the other ships a lab with nothing in it, and neither
 * announces itself. So the caller states which kind it has, and an unrecognised
 * value is a blocking error rather than a quiet fallback to 'reference' —
 * falling back would skip the chain rules in silence, which is precisely the
 * outcome the mode exists to end.
 */
const MODE_REFERENCE = 'reference';
const MODE_GENERATED = 'generated';
const VALIDATION_MODES = Object.freeze([MODE_REFERENCE, MODE_GENERATED]);

/**
 * The three chain producers that are not a per-host role choice, each with the
 * config path it actually writes.
 *
 * The vendored manifest covers ansible/roles/vulns (29) and ansible/roles/security
 * (9) — the roles a generator PICKS for a host. These three are picked by
 * nobody: every lab runs them, over data that lives in config.json itself. They
 * are therefore absent from manifest.roles and getRole() correctly returns null
 * for them, so treating that null as "unknown role" would reject every ACL edge
 * any designer ever draws, i.e. every chain.
 *
 * Spelled here rather than imported from goad-attack-chain's PRODUCERS table
 * because that module already requires THIS one (rootDnForDomain, normalizeDn)
 * and the reverse import is a cycle. What is duplicated is three role names and
 * where they write; the ACL vocabulary, the role library and the never_emit
 * verdicts are all still read from the manifest rather than re-spelled.
 */
const CORE_CHAIN_ROLES = Object.freeze({
  acl: 'lab.domains.<fqdn>.acls.<item> — ansible/roles/acl over ad_acls',
  onlyusers: 'lab.domains.<fqdn>.users.<sam> — ansible/ad-data.yml -> roles/ad',
  ps: 'lab.hosts.<host>.scripts — ansible/roles/ps, freeform PowerShell',
});

// ─── Tolerant read / strict write ───────────────────────────────────────────

/**
 * Remove commas that sit immediately before a closing `}` or `]`.
 *
 * THE ASYMMETRY, AND WHY IT IS NOT SLOPPINESS
 * `ad/DRACARYS/data/config.json` ships with a trailing comma (the last entry of
 * its `acls` dict) and upstream deploys it successfully. It can, because nothing
 * in GOAD ever feeds that file to a JSON parser: the playbooks load it with
 * `vars_files`, i.e. PyYAML, and YAML 1.1 flow collections tolerate a trailing
 * comma. The `.json` extension is a naming convention, not a contract.
 *
 * So a strict JSON.parse on the READ path would reject a working lab — a false
 * negative on the only thing that matters, "does this deploy?". We therefore
 * read with YAML's tolerance. We do NOT write with it: anything this repo emits
 * goes through toStrictJson(), so we never propagate the trap to a file some
 * other tool (jq, a linter, a future strict loader) will choke on.
 *
 * This scanner is string-aware — it tracks quotes and backslash escapes — so a
 * comma inside a value like "C:\\shares\\all," is never touched. A bare
 * /,(\s*[}\]])/g regex would corrupt exactly those Windows-path strings this
 * file is full of.
 */
function stripTrailingCommas(text) {
  const src = String(text);
  let out = '';
  let inString = false;
  let escaped = false;
  for (let i = 0; i < src.length; i++) {
    const ch = src[i];
    if (inString) {
      out += ch;
      if (escaped) escaped = false;
      else if (ch === '\\') escaped = true;
      else if (ch === '"') inString = false;
      continue;
    }
    if (ch === '"') { inString = true; out += ch; continue; }
    if (ch === ',') {
      // Look ahead past whitespace only. A comment would need handling too, but
      // JSON has none and no shipped lab uses any, so pretending otherwise would
      // be untested code.
      let j = i + 1;
      while (j < src.length && /\s/.test(src[j])) j++;
      if (src[j] === '}' || src[j] === ']') continue; // drop it
    }
    out += ch;
  }
  return out;
}

/**
 * Parse a lab config the way Ansible would.
 *
 * Returns { lab, repairs, strict } — `lab` is the inner object (the `{"lab": …}`
 * wrapper is unwrapped), `repairs` names each tolerance that was actually
 * exercised, and `strict` says whether the text was already valid JSON. Callers
 * that are about to WRITE the file back should look at `repairs`; callers that
 * only want to validate should ignore it, because a trailing comma is not a
 * defect in a file Ansible reads.
 *
 * Throws only when the text is unparseable even with the tolerance applied —
 * there is no useful degraded mode for "the lab definition is not a lab".
 */
function parseLabConfig(text, { source = 'config.json' } = {}) {
  const raw = String(text == null ? '' : text);
  const repairs = [];
  let parsed;
  let strict = true;
  try {
    parsed = JSON.parse(raw);
  } catch (strictErr) {
    strict = false;
    const cleaned = stripTrailingCommas(raw);
    if (cleaned === raw) {
      throw new Error(`${source} is not parseable as JSON or YAML-flavoured JSON: ${strictErr.message}`);
    }
    try {
      parsed = JSON.parse(cleaned);
    } catch (tolerantErr) {
      throw new Error(`${source} is not parseable even after dropping trailing commas: ${tolerantErr.message}`);
    }
    repairs.push('trailing-comma');
  }
  const lab = parsed && parsed.lab ? parsed.lab : parsed;
  return { lab, repairs, strict };
}

/**
 * The write half of the asymmetry. Round-trips through JSON.parse so a caller
 * cannot accidentally ship something only YAML would accept, and so this
 * function is a real guarantee rather than a comment.
 */
function toStrictJson(lab, { wrap = true, indent = 2 } = {}) {
  const payload = wrap ? { lab } : lab;
  const text = JSON.stringify(payload, null, indent);
  JSON.parse(text);
  return text;
}

/**
 * Parse an Ansible INI inventory into { groups, vars }.
 *
 * Only the two shapes GOAD actually uses: `[group]` host lines and
 * `[group:vars]` key=value lines. `;` and `#` both start a comment — GOAD's own
 * inventories use `;` on some lines and `#` on others, and an empty group whose
 * next non-blank line is a comment (GOAD's `[linux_domain]`) must NOT absorb
 * that comment as a hostname.
 */
function parseInventory(text) {
  const groups = {};
  const vars = {};
  let current = null;
  let currentIsVars = false;
  for (const line of String(text == null ? '' : text).split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(';') || trimmed.startsWith('#')) continue;
    const header = /^\[([^\]]+)\]$/.exec(trimmed);
    if (header) {
      const name = header[1];
      currentIsVars = name.endsWith(':vars');
      current = currentIsVars ? name.slice(0, -':vars'.length) : name;
      if (!currentIsVars && !groups[current]) groups[current] = [];
      continue;
    }
    if (!current) continue;
    if (currentIsVars) {
      const eq = trimmed.indexOf('=');
      if (eq > 0) vars[trimmed.slice(0, eq).trim()] = trimmed.slice(eq + 1).trim();
      continue;
    }
    // A host line may carry per-host vars after the name (`dc01 ansible_host=…`).
    groups[current].push(trimmed.split(/\s+/)[0]);
  }
  return { groups, vars };
}

// ─── Primitives ─────────────────────────────────────────────────────────────

const PASSWORD_CLASS_TESTS = [/[A-Z]/, /[a-z]/, /[0-9]/, /[^A-Za-z0-9]/];

/** How many of {upper, lower, digit, non-alphanumeric} the password uses. */
function passwordClasses(pw) {
  const s = String(pw == null ? '' : pw);
  return PASSWORD_CLASS_TESTS.reduce((n, re) => n + (re.test(s) ? 1 : 0), 0);
}

/**
 * The tokens Windows' complexity check pulls out of an account name.
 * It splits on , . - _ # space and tab, then rejects any password containing a
 * token longer than two characters, case-insensitively. Reproducing the split
 * matters: "administrator" is one token, but a renamed "svc.backup" is two, and
 * only the second form makes "backup2024!" illegal.
 */
function accountNameTokens(name) {
  return String(name == null ? '' : name)
    .split(/[,.\-_#\s\t]+/)
    .map((t) => t.toLowerCase())
    .filter((t) => t.length > 2);
}

function containsAccountName(pw, name) {
  const lower = String(pw == null ? '' : pw).toLowerCase();
  return accountNameTokens(name).some((t) => lower.includes(t));
}

/** `north.sevenkingdoms.local` → `DC=north,DC=sevenkingdoms,DC=local`. */
function rootDnForDomain(fqdn) {
  return String(fqdn == null ? '' : fqdn)
    .split('.')
    .filter(Boolean)
    .map((label) => `DC=${label}`)
    .join(',');
}

/**
 * Canonical form for DN comparison: case-folded, no whitespace around the
 * separators. AD itself is case-insensitive here, and GOAD relies on it —
 * `north.sevenkingdoms.local` is declared with the path `DC=North,…`, so a
 * case-sensitive compare would reject a lab that has shipped for years.
 */
function normalizeDn(dn) {
  return String(dn == null ? '' : dn)
    .split(',')
    .map((rdn) => rdn.trim().replace(/\s*=\s*/, '='))
    .join(',')
    .toLowerCase();
}

/** Case-folded, forward-slashes-as-backslashes form for Windows path compare. */
function normalizeWinPath(p) {
  return String(p == null ? '' : p).replace(/\//g, '\\').toLowerCase();
}

/**
 * Canonical identity for one node named in an attack chain.
 *
 * AD is case-insensitive for both sAMAccountNames and DNs, and GOAD relies on
 * that — north.sevenkingdoms.local declares its paths as `DC=North,…`. A chain
 * whose edges spell one object `Domain Admins` in one place and `DOMAIN ADMINS`
 * in the next is describing ONE object, and a reachability walk that treated
 * them as two would call a solvable chain unsolvable and refuse a lab that is
 * fine. The `DOMAIN\` prefix comes off for the same reason: GOAD writes
 * principals both ways in a single file, and the acl role resolves `for` with a
 * SamAccountName filter, so the bare form is the one that matches.
 */
function chainNodeKey(value) {
  const s = String(value == null ? '' : value).trim();
  // A DN, in either the `CN=x,DC=y` or the bare-RDN form the acl role accepts.
  if (/(^|,)\s*(CN|OU|DC)=/i.test(s)) return normalizeDn(s);
  const slash = s.lastIndexOf('\\');
  return (slash === -1 ? s : s.slice(slash + 1)).toLowerCase();
}

/**
 * Breadth-first: can you get from `from` to `to` over these edges?
 *
 * Deliberately takes an explicit edge list rather than a whole chain, because
 * WHICH edges count is the interesting part of the question. The objective has
 * to be reachable over the chain's own edges and NOT over its decoys — a decoy
 * that reaches the objective is a second solution, not a decoy — so the caller
 * decides what it is walking and this function stays honest about it.
 */
function chainReaches(edges, from, to) {
  const start = chainNodeKey(from);
  const goal = chainNodeKey(to);
  if (start === goal) return true;
  const adjacency = new Map();
  for (const edge of edges) {
    if (!isPlainObject(edge)) continue;
    const key = chainNodeKey(edge.from);
    if (!adjacency.has(key)) adjacency.set(key, []);
    adjacency.get(key).push(chainNodeKey(edge.to));
  }
  const seen = new Set([start]);
  const queue = [start];
  while (queue.length) {
    for (const next of adjacency.get(queue.shift()) || []) {
      if (next === goal) return true;
      if (seen.has(next)) continue;
      seen.add(next);
      queue.push(next);
    }
  }
  return false;
}

/** A human-readable locator: `hosts.dc02.vulns[8]`, `domains['essos.local'].acls['x']`. */
function ref(...parts) {
  let out = '';
  for (const part of parts) {
    if (typeof part === 'number') out += `[${part}]`;
    else if (out === '') out += String(part);
    else if (/^[A-Za-z_][A-Za-z0-9_]*$/.test(String(part))) out += `.${part}`;
    else out += `[${JSON.stringify(String(part))}]`;
  }
  return out;
}

function isPlainObject(v) {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

// ─── The core ───────────────────────────────────────────────────────────────

/**
 * Validate one lab definition.
 *
 * @param {object}        input
 * @param {object}        input.lab        parsed config (either `{lab:{…}}` or the inner object)
 * @param {string|object} [input.inventory] inventory text, or a parseInventory() result,
 *                                          or a bare { group: [host] } map
 * @param {string}        [input.labName]   used in messages only
 * @param {string}        [input.adminUser] overrides the inventory's admin_user
 * @param {string}        [input.mode]      'reference' (default) or 'generated' — see
 *                                          VALIDATION_MODES. 'generated' additionally
 *                                          requires the two arguments below.
 * @param {object}        [input.chain]     the designed attack chain (labIR.chain)
 * @param {object}        [input.foothold]  the foothold credential (labIR.foothold_credential)
 * @returns {{ errors: Array, warnings: Array, findings: Array }}
 */
function validateLab(input) {
  const opts = input || {};
  const errors = [];
  const warnings = [];
  const err = (id, code, message) => errors.push({ id, code, severity: 'error', message });
  const warn = (id, code, message) => warnings.push({ id, code, severity: 'warning', message });

  const labName = opts.labName || 'lab';

  // Resolved BEFORE the lab-shape early return below, so a caller who got the
  // mode wrong hears about it even when the lab is junk — those two mistakes
  // travel together, and reporting only the second sends the reader to the
  // wrong file.
  const mode = opts.mode === undefined || opts.mode === null ? MODE_REFERENCE : String(opts.mode);
  if (VALIDATION_MODES.indexOf(mode) === -1) {
    err('mode', 'VALIDATION_MODE_UNKNOWN',
      `${labName}: validateLab was called with mode ${JSON.stringify(opts.mode)}, which is not ` +
      `one of ${VALIDATION_MODES.join(' or ')}. Pass '${MODE_GENERATED}' for a lab this repo ` +
      `composed — it must then also carry an attack chain — or '${MODE_REFERENCE}' for one ` +
      `somebody wrote. This is a blocking error rather than a fallback on purpose: defaulting ` +
      `to '${MODE_REFERENCE}' would skip the chain rules without saying so, which is the exact ` +
      `silence the mode exists to end.`);
  }

  const raw = opts.lab && opts.lab.lab ? opts.lab.lab : opts.lab;
  if (!isPlainObject(raw)) {
    err('lab', 'LAB_NOT_AN_OBJECT',
      `${labName}: the lab definition is ${raw === undefined ? 'missing' : typeof raw}, not an object. ` +
      `Pass the parsed config.json (parseLabConfig() unwraps the {"lab": …} envelope for you).`);
    return { errors, warnings, findings: errors.concat(warnings) };
  }

  const hosts = isPlainObject(raw.hosts) ? raw.hosts : {};
  const domains = isPlainObject(raw.domains) ? raw.domains : {};
  if (!Object.keys(hosts).length) {
    err(ref('hosts'), 'NO_HOSTS',
      `${labName}: no hosts declared. A lab with no hosts builds nothing — add at least ` +
      `one host with a type of 'dc'.`);
  }
  if (!Object.keys(domains).length) {
    err(ref('domains'), 'NO_DOMAINS',
      `${labName}: no domains declared. Add a domain keyed by its FQDN with a 'dc' naming ` +
      `one of the hosts.`);
  }

  // Inventory is optional at the API level but every cross-check below depends
  // on it. Say so out loud rather than quietly returning fewer findings — a
  // caller that thinks the inventory was checked and got zero errors is worse
  // off than one that was told nothing was checked.
  let inventory = null;
  if (typeof opts.inventory === 'string') inventory = parseInventory(opts.inventory);
  else if (isPlainObject(opts.inventory) && isPlainObject(opts.inventory.groups)) inventory = opts.inventory;
  else if (isPlainObject(opts.inventory)) inventory = { groups: opts.inventory, vars: {} };
  if (!inventory) {
    warn('inventory', 'INVENTORY_NOT_CHECKED',
      `${labName}: no inventory supplied, so the config-vs-inventory cross-checks ([dc] ` +
      `membership, undeclared hosts) did NOT run. Pass the inventory text to validateLab() ` +
      `to enable them.`);
  }
  const invGroups = inventory ? inventory.groups : {};
  const adminUser = opts.adminUser || (inventory && inventory.vars && inventory.vars.admin_user) || DEFAULT_ADMIN_USER;

  // ── Hosts ─────────────────────────────────────────────────────────────────

  const hostnamesSeen = new Map();

  for (const [hostKey, host] of Object.entries(hosts)) {
    if (!isPlainObject(host)) {
      err(ref('hosts', hostKey), 'HOST_NOT_AN_OBJECT',
        `${labName}: host '${hostKey}' is not an object. Replace it with a host block ` +
        `({ hostname, type, domain, local_admin_password, … }).`);
      continue;
    }

    // NetBIOS / DNS name.
    const hostname = String(host.hostname == null ? '' : host.hostname);
    if (!hostname) {
      err(ref('hosts', hostKey, 'hostname'), 'HOSTNAME_MISSING',
        `${labName}: host '${hostKey}' has no hostname. Add one — it is the computer's ` +
        `actual Windows name, and the inventory key alone does not set it.`);
    } else {
      if (hostname.length > MAX_NETBIOS_HOSTNAME) {
        err(ref('hosts', hostKey, 'hostname'), 'HOSTNAME_TOO_LONG',
          `${labName}: hostname '${hostname}' is ${hostname.length} characters, over the ` +
          `${MAX_NETBIOS_HOSTNAME}-character NetBIOS limit. Shorten it — over the limit the ` +
          `machine joins but its NetBIOS name is a truncation, so two hosts sharing a ` +
          `${MAX_NETBIOS_HOSTNAME}-character prefix collide and one stops answering.`);
      }
      if (!/^[A-Za-z0-9-]+$/.test(hostname)) {
        err(ref('hosts', hostKey, 'hostname'), 'HOSTNAME_CHARSET',
          `${labName}: hostname '${hostname}' contains characters outside [A-Za-z0-9-]. ` +
          `Use letters, digits and hyphens only — underscores and dots are rejected by ` +
          `the domain join, not by this file.`);
      }
      const prior = hostnamesSeen.get(hostname.toLowerCase());
      if (prior) {
        err(ref('hosts', hostKey, 'hostname'), 'HOSTNAME_DUPLICATE',
          `${labName}: hosts '${prior}' and '${hostKey}' both use the hostname '${hostname}'. ` +
          `Give each host a distinct name — the second join renames the first machine out ` +
          `of the domain.`);
      } else {
        hostnamesSeen.set(hostname.toLowerCase(), hostKey);
      }
    }

    // Local Administrator password. This one is set before any domain policy
    // exists, so only the built-in local floor applies.
    const localPw = host.local_admin_password;
    if (localPw == null || localPw === '') {
      err(ref('hosts', hostKey, 'local_admin_password'), 'LOCAL_ADMIN_PASSWORD_MISSING',
        `${labName}: host '${hostKey}' has no local_admin_password. Set one — the build ` +
        `has no fallback and the host comes up unreachable.`);
    } else {
      const pw = String(localPw);
      if (pw.length < MIN_LOCAL_ADMIN_PASSWORD_LEN || passwordClasses(pw) < REQUIRED_PASSWORD_CLASSES) {
        err(ref('hosts', hostKey, 'local_admin_password'), 'WEAK_LOCAL_ADMIN_PASSWORD',
          `${labName}: host '${hostKey}' local_admin_password is ${pw.length} characters using ` +
          `${passwordClasses(pw)} of the 4 character classes; it needs ` +
          `${MIN_LOCAL_ADMIN_PASSWORD_LEN}+ characters and ${REQUIRED_PASSWORD_CLASSES} of ` +
          `{uppercase, lowercase, digit, symbol}. ` +
          (host.type === 'dc'
            ? `This host is a domain controller, so this string is also the domain and DSRM ` +
              `password and dcpromo will reject it outright. `
            : `Windows would accept it on a standalone member server, but this is the credential ` +
              `every lane's console and WinRM login uses and every student in the cohort gets the ` +
              `same one. `) +
          `Weak passwords belong in users[].password, which is set after password_policy has ` +
          `relaxed the domain.`);
      }
      if (containsAccountName(pw, adminUser)) {
        err(ref('hosts', hostKey, 'local_admin_password'), 'LOCAL_ADMIN_PASSWORD_CONTAINS_ACCOUNT',
          `${labName}: host '${hostKey}' local_admin_password contains the account name ` +
          `'${adminUser}'. Windows complexity rejects any password containing a 3+ character ` +
          `token of the account name — pick one that does not.`);
      }
    }

    validateRoleList(host, hostKey, 'vulns');
    validateRoleList(host, hostKey, 'security');
    validateHostFileDependencies(host, hostKey);
  }

  // ── Inventory cross-checks ────────────────────────────────────────────────

  if (inventory) {
    const memberHosts = new Set();
    for (const g of MEMBER_GROUPS) for (const h of invGroups[g] || []) memberHosts.add(h);
    const invDcs = new Set(invGroups.dc || []);

    for (const [hostKey, host] of Object.entries(hosts)) {
      if (!memberHosts.has(hostKey)) {
        err(ref('hosts', hostKey), 'HOST_NOT_IN_INVENTORY',
          `${labName}: host '${hostKey}' is declared in config.json but is in neither ` +
          `[${MEMBER_GROUPS.join('] nor [')}] in the inventory, so no playbook ever targets it. ` +
          `Add it to [domain] (Windows) or [linux_domain] (Linux).`);
      }
      const isDc = isPlainObject(host) && host.type === 'dc';
      if (isDc && !invDcs.has(hostKey)) {
        err(ref('hosts', hostKey, 'type'), 'DC_NOT_IN_INVENTORY_DC',
          `${labName}: host '${hostKey}' has type 'dc' but is not in the inventory's [dc] group. ` +
          `Add it — ad-acl.yml, ad-data.yml and laps.yml all run against [dc], so the domain ` +
          `is promoted and then left empty.`);
      }
      if (!isDc && invDcs.has(hostKey)) {
        err(ref('hosts', hostKey, 'type'), 'INVENTORY_DC_NOT_TYPED_DC',
          `${labName}: host '${hostKey}' is in the inventory's [dc] group but its config type is ` +
          `'${isPlainObject(host) ? host.type : 'unknown'}'. Set type to 'dc', or drop it from ` +
          `[dc] — the AD playbooks will otherwise try to write directory objects on a member server.`);
      }
    }

    // The inverse, SCOPED to [domain]/[linux_domain] only. Unscoped this rule
    // rejects SCCM's `elk`, an appliance in [elk_server] that legitimately has
    // no config.json entry.
    for (const g of MEMBER_GROUPS) {
      for (const h of invGroups[g] || []) {
        if (!Object.prototype.hasOwnProperty.call(hosts, h)) {
          err(ref('inventory', g, h), 'INVENTORY_HOST_UNDECLARED',
            `${labName}: the inventory lists '${h}' in [${g}] but config.json declares no such ` +
            `host, so every AD task against it dereferences an undefined var. Add the host block ` +
            `or remove the inventory line.`);
        }
      }
    }
  }

  // ── Domains ───────────────────────────────────────────────────────────────

  for (const [domainName, domain] of Object.entries(domains)) {
    if (!isPlainObject(domain)) {
      err(ref('domains', domainName), 'DOMAIN_NOT_AN_OBJECT',
        `${labName}: domain '${domainName}' is not an object. Replace it with a domain block ` +
        `({ dc, domain_password, netbios_name, users, groups, … }).`);
      continue;
    }
    const dcKey = domain.dc;
    const dcHost = dcKey && Object.prototype.hasOwnProperty.call(hosts, dcKey) ? hosts[dcKey] : null;

    if (!dcHost) {
      err(ref('domains', domainName, 'dc'), 'DOMAIN_DC_UNKNOWN',
        `${labName}: domain '${domainName}' names '${dcKey}' as its DC but there is no such host. ` +
        `Point 'dc' at a hosts key — it is how every domain-scoped play picks its target.`);
    } else if (dcHost.type !== 'dc') {
      err(ref('domains', domainName, 'dc'), 'DOMAIN_DC_NOT_DC',
        `${labName}: domain '${domainName}' names '${dcKey}' as its DC but that host's type is ` +
        `'${dcHost.type}'. Set the host's type to 'dc' or point the domain at a real controller.`);
    }

    // Domain password. This value is win_domain's safe_mode_password, set five
    // playbooks BEFORE password_policy relaxes anything, so the DEFAULT policy
    // applies no matter what the lab loosens later.
    const domainPw = domain.domain_password;
    if (domainPw == null || domainPw === '') {
      err(ref('domains', domainName, 'domain_password'), 'DOMAIN_PASSWORD_MISSING',
        `${labName}: domain '${domainName}' has no domain_password. Set one — it is both the ` +
        `Domain Admin password and the DSRM safe-mode password.`);
    } else {
      const pw = String(domainPw);
      if (pw.length < MIN_DOMAIN_PASSWORD_LEN || passwordClasses(pw) < REQUIRED_PASSWORD_CLASSES) {
        err(ref('domains', domainName, 'domain_password'), 'WEAK_DOMAIN_PASSWORD',
          `${labName}: domain '${domainName}' domain_password is ${pw.length} characters using ` +
          `${passwordClasses(pw)} of the 4 character classes. dcpromo rejects it: this string is ` +
          `win_domain's safe_mode_password, which runs long before password_policy relaxes the ` +
          `domain, so it must satisfy the DEFAULT policy — ${MIN_DOMAIN_PASSWORD_LEN}+ characters ` +
          `and ${REQUIRED_PASSWORD_CLASSES} of {uppercase, lowercase, digit, symbol}.`);
      }
    }

    // The DC's local password and the domain password must be the same string.
    // Holds in all 12 upstream domains and is load-bearing for child-DC dcpromo:
    // the child's promotion authenticates to the parent with the credential the
    // child host was built with.
    if (dcHost && domainPw != null && dcHost.local_admin_password !== domainPw) {
      err(ref('domains', domainName, 'domain_password'), 'DC_PASSWORD_MISMATCH',
        `${labName}: domain '${domainName}' domain_password does not equal ` +
        `hosts.${dcKey}.local_admin_password. Make them identical — the DC is promoted using its ` +
        `local credential and every child-domain dcpromo re-uses it, so a mismatch fails the ` +
        `promotion with an authentication error that names neither field.`);
    }

    const rootDn = rootDnForDomain(domainName);
    const containers = buildContainerSet(domain, rootDn);

    validateDomainNames(domain, domainName);
    validateContainerPaths(domain, domainName, containers, rootDn);
    validateDomainAcls(domain, domainName);
    validateDeadAclEdges(domain, domainName);
  }

  // ── Generated labs only ───────────────────────────────────────────────────
  // Everything above asks "does this deploy?". This asks "is there anything in
  // it to attack?", which is only a question about a lab this repo composed.
  if (mode === MODE_GENERATED) validateGeneratedChain();

  return { errors, warnings, findings: errors.concat(warnings) };

  // ── Per-host role validation ──────────────────────────────────────────────

  /**
   * One pass over `host.vulns` / `host.security` and the matching *_vars dict.
   * Both kinds are the same machinery with a different manifest namespace, and
   * splitting them into two functions would guarantee they drift.
   */
  function validateRoleList(host, hostKey, kind) {
    const varsKey = `${kind}_vars`;
    const listed = host[kind];
    const vars = host[varsKey];

    if (listed !== undefined && !Array.isArray(listed)) {
      err(ref('hosts', hostKey, kind), 'ROLE_LIST_NOT_ARRAY',
        `${labName}: hosts.${hostKey}.${kind} is ${typeof listed}, not an array. Ansible's ` +
        `loop over it silently yields nothing — make it a list of role names.`);
      return;
    }
    if (vars !== undefined && !isPlainObject(vars)) {
      err(ref('hosts', hostKey, varsKey), 'ROLE_VARS_NOT_OBJECT',
        `${labName}: hosts.${hostKey}.${varsKey} is ${Array.isArray(vars) ? 'an array' : typeof vars}, ` +
        `not a dict. Every role reads it with with_dict — make it an object keyed by role name.`);
      return;
    }

    const names = Array.isArray(listed) ? listed.map((n) => String(n)) : [];
    const varsDict = isPlainObject(vars) ? vars : {};

    names.forEach((roleName, index) => {
      const role = getRole(roleName, kind);
      if (!role) {
        err(ref('hosts', hostKey, kind, index), 'UNKNOWN_ROLE',
          `${labName}: hosts.${hostKey}.${kind}[${index}] names '${roleName}', which is not a role ` +
          `in GOAD ${loadManifest().goad_ref.slice(0, 12)}. Fix the spelling — the name is used ` +
          `verbatim as include_role, and the play dies on the lane long after generation. ` +
          `(Spelling is exact: 'enable_nbt-ns' has a hyphen, everything else uses underscores.)`);
        return;
      }
      if (role.never_emit) {
        err(ref('hosts', hostKey, kind, index), 'NEVER_EMIT_ROLE',
          `${labName}: hosts.${hostKey}.${kind}[${index}] uses '${roleName}', which is broken ` +
          `upstream and must never be emitted: ${role.never_emit_reason || 'see the vendored role manifest'} ` +
          `Remove it and use a working role instead.`);
        // Fall through: the shape checks below still apply and their findings
        // help whoever is porting the lab off the broken role.
      }

      const item = varsDict[roleName];
      if (!role.consumes_vars) {
        if (item !== undefined) {
          warn(ref('hosts', hostKey, varsKey, roleName), 'UNUSED_ROLE_VARS',
            `${labName}: hosts.${hostKey}.${varsKey}.${roleName} is set but the '${roleName}' role ` +
            `reads no variables, so it is ignored. Delete it, or you will keep editing a value ` +
            `that changes nothing.`);
        }
        return;
      }
      if (item === undefined) {
        // WARNING, not an error: two shipped labs do exactly this, so erroring
        // would reject a lab that upstream deploys. It is still a silent no-op.
        warn(ref('hosts', hostKey, kind, index), 'ROLE_VARS_MISSING',
          `${labName}: hosts.${hostKey}.${kind} lists '${roleName}' but ${varsKey}.${roleName} is ` +
          `absent. The role loops with_dict over an empty dict, plants nothing, and reports green. ` +
          `Add the ${varsKey}.${roleName} entry, or drop '${roleName}' from the list.`);
        return;
      }
      validateRoleItems(role, item, hostKey, varsKey, roleName);
    });

    // The inverse: vars for a role nobody listed. Never runs at all.
    for (const roleName of Object.keys(varsDict)) {
      if (names.includes(roleName)) continue;
      err(ref('hosts', hostKey, varsKey, roleName), 'ORPHAN_ROLE_VARS',
        `${labName}: hosts.${hostKey}.${varsKey} defines '${roleName}' but hosts.${hostKey}.${kind} ` +
        `does not list it, so the role never runs and the block is dead config. Add '${roleName}' ` +
        `to the ${kind} list, or delete the ${varsKey} entry.`);
    }

    if (kind === 'vulns') validateRoleOrder(names, hostKey);
  }

  /** Shape + required-key check for one role's vars entry. */
  function validateRoleItems(role, item, hostKey, varsKey, roleName) {
    const base = ref('hosts', hostKey, varsKey, roleName);
    if (!isPlainObject(item)) {
      err(base, 'ROLE_VARS_ENTRY_NOT_DICT',
        `${labName}: ${base} is ${Array.isArray(item) ? 'an array' : typeof item}, not a dict. ` +
        `The role iterates it with with_dict, so it must be an object of named items.`);
      return;
    }
    for (const [itemKey, value] of Object.entries(item)) {
      const at = ref('hosts', hostKey, varsKey, roleName, itemKey);

      // `directory` is the odd one out in both namespaces: its value is the bare
      // path string, not an object. Handing it an object creates a folder whose
      // name is the stringified dict.
      if (role.vars_shape === 'dict_of_scalars') {
        if (typeof value === 'object' && value !== null) {
          err(at, 'WRONG_VARS_SHAPE',
            `${labName}: ${at} is ${Array.isArray(value) ? 'an array' : 'an object'}, but the ` +
            `'${roleName}' role takes a bare path string (e.g. "c:\\\\setup"). Replace the object ` +
            `with the path itself.`);
        }
        continue;
      }

      if (!isPlainObject(value)) {
        err(at, 'WRONG_VARS_SHAPE',
          `${labName}: ${at} is ${value === null ? 'null' : typeof value}, but the '${roleName}' ` +
          `role indexes it as an object with ${role.required_item_keys.join('/')}. Wrap the value ` +
          `in an object with those keys.`);
        continue;
      }
      for (const requiredKey of role.required_item_keys) {
        if (value[requiredKey] === undefined) {
          err(ref('hosts', hostKey, varsKey, roleName, itemKey, requiredKey), 'MISSING_ROLE_ITEM_KEY',
            `${labName}: ${at} has no '${requiredKey}'. The '${roleName}' role reads it with no ` +
            `default, so the task fails on an undefined variable. Add '${requiredKey}' ` +
            `(required: ${role.required_item_keys.join(', ')}).`);
        }
      }
      // Host-level ACLs share the acls role's item shape but a DIFFERENT right
      // vocabulary from the domain-level role — see aclRights('host').
      if (roleName === 'acls' && role.kind === 'vulns') {
        checkAclValues(value, at, 'host');
      }
    }
  }

  /**
   * Ordering inside one host's `vulns` array.
   *
   * The list is a literal execution order — vulnerabilities.yml loops it in
   * place — and three pairs depend on it. Nothing upstream checks this, and
   * getting it wrong is a copy-that-fails or a permission set on a path that
   * does not exist yet, both of which surface as one red task in the middle of
   * a long play.
   */
  function validateRoleOrder(names, hostKey) {
    const pairs = [
      ['files', 'adcs_templates', 'adcs_templates imports the JSON that files copied'],
      ['files', 'schedule', 'the scheduled task runs a script that files copied'],
      ['files', 'permissions', 'permissions ACLs a path that files created'],
      ['directory', 'permissions', 'permissions ACLs a folder that directory created'],
    ];
    for (const [first, second, why] of pairs) {
      const a = names.indexOf(first);
      const b = names.indexOf(second);
      if (a === -1 || b === -1 || a < b) continue;
      err(ref('hosts', hostKey, 'vulns', b), 'ROLE_ORDER',
        `${labName}: hosts.${hostKey}.vulns runs '${second}' (index ${b}) before '${first}' ` +
        `(index ${a}), but ${why}. Move '${first}' earlier in the list — the array IS the ` +
        `execution order.`);
    }
  }

  /**
   * Same-host file dependency: a path a role consumes must be one a `files`
   * entry actually put there.
   *
   * PREFIX-AWARE ON PURPOSE. A `dest` ending in a backslash is a DIRECTORY copy
   * (win_copy semantics), so GOAD-Light plants `dc01/templates/` at `C:\setup\`
   * and then asks adcs_templates for `C:\setup\ESC1.json`. An equality-only
   * check rejects that lab.
   *
   * Sources are unioned across vulns_vars.files and security_vars.files: once
   * either has run the file is on disk, and which list planted it is not the
   * dependency's business. Ordering is validateRoleOrder()'s job.
   */
  function validateHostFileDependencies(host, hostKey) {
    const dests = [];
    for (const varsKey of ['vulns_vars', 'security_vars']) {
      const filesVar = isPlainObject(host[varsKey]) ? host[varsKey].files : null;
      if (!isPlainObject(filesVar)) continue;
      for (const entry of Object.values(filesVar)) {
        if (isPlainObject(entry) && entry.dest != null) dests.push(normalizeWinPath(entry.dest));
      }
    }
    const planted = (target) => {
      const t = normalizeWinPath(target);
      return dests.some((d) => (d.endsWith('\\') ? t.startsWith(d) : t === d));
    };
    const mentioned = (cmd) => {
      const c = normalizeWinPath(cmd);
      return dests.some((d) => c.includes(d));
    };
    const hint = dests.length
      ? `Files planted on this host: ${dests.join(', ')}.`
      : `This host has no vulns_vars.files entries at all.`;

    const vv = isPlainObject(host.vulns_vars) ? host.vulns_vars : {};

    if (isPlainObject(vv.adcs_templates)) {
      for (const [itemKey, item] of Object.entries(vv.adcs_templates)) {
        if (!isPlainObject(item) || item.template_file == null) continue;
        if (planted(item.template_file)) continue;
        err(ref('hosts', hostKey, 'vulns_vars', 'adcs_templates', itemKey, 'template_file'),
          'MISSING_FILE_DEPENDENCY',
          `${labName}: hosts.${hostKey} imports the certificate template from ` +
          `'${item.template_file}', but no files entry copies anything to that path. ${hint} ` +
          `Add a files entry whose dest is that path (or a directory dest ending in a ` +
          `backslash that contains it) — the import fails on a file that was never staged.`);
      }
    }

    if (isPlainObject(vv.schedule)) {
      for (const [itemKey, item] of Object.entries(vv.schedule)) {
        if (!isPlainObject(item) || item.cmd == null) continue;
        if (mentioned(item.cmd)) continue;
        err(ref('hosts', hostKey, 'vulns_vars', 'schedule', itemKey, 'cmd'),
          'MISSING_FILE_DEPENDENCY',
          `${labName}: hosts.${hostKey} schedules '${item.cmd}', which references no path that a ` +
          `files entry copied to this host. ${hint} Register the task's script with a files entry ` +
          `— a scheduled task pointing at a missing script is created successfully and then ` +
          `fails silently every interval.`);
      }
    }
  }

  // ── Per-domain validation ────────────────────────────────────────────────

  /** Every container a user, group or OU is allowed to be created in. */
  function buildContainerSet(domain, rootDn) {
    const set = new Set([normalizeDn(rootDn), normalizeDn(`CN=Users,${rootDn}`)]);
    const ous = isPlainObject(domain.organisation_units) ? domain.organisation_units : {};
    for (const [ouName, ou] of Object.entries(ous)) {
      const parent = isPlainObject(ou) && ou.path ? ou.path : rootDn;
      set.add(normalizeDn(`OU=${ouName},${parent}`));
    }
    return set;
  }

  function eachGroup(domain, fn) {
    const groups = isPlainObject(domain.groups) ? domain.groups : {};
    for (const [scope, byName] of Object.entries(groups)) {
      if (!isPlainObject(byName)) continue;
      for (const [groupName, group] of Object.entries(byName)) fn(groupName, group, scope);
    }
  }

  function validateDomainNames(domain, domainName) {
    const users = isPlainObject(domain.users) ? domain.users : {};
    for (const userKey of Object.keys(users)) {
      // roles/onlyusers passes `name: item.key` to win_domain_user, which derives
      // sAMAccountName from name — so the dict key alone carries both limits and
      // the tighter one binds.
      if (userKey.length > MAX_SAM_ACCOUNT_NAME) {
        err(ref('domains', domainName, 'users', userKey), 'SAM_ACCOUNT_NAME_TOO_LONG',
          `${labName}: user '${userKey}' in '${domainName}' is ${userKey.length} characters, over ` +
          `the ${MAX_SAM_ACCOUNT_NAME}-character sAMAccountName limit. Shorten the key — it is the ` +
          `logon name, not a display name, and win_domain_user fails outright rather than truncating.`);
      }
    }
    eachGroup(domain, (groupName) => {
      if (groupName.length > MAX_COMMON_NAME) {
        err(ref('domains', domainName, 'groups', groupName), 'COMMON_NAME_TOO_LONG',
          `${labName}: group '${groupName}' in '${domainName}' is ${groupName.length} characters, ` +
          `over the ${MAX_COMMON_NAME}-character CN limit. Shorten it — the key becomes the ` +
          `object's RDN.`);
      }
    });
  }

  function validateContainerPaths(domain, domainName, containers, rootDn) {
    const check = (value, id, what) => {
      if (value == null || value === '') {
        err(id, 'CONTAINER_PATH_MISSING',
          `${labName}: ${what} in '${domainName}' has no path. Set it to the domain root ` +
          `('${rootDn}'), 'CN=Users,${rootDn}', or a declared OU — win_domain_user has no default ` +
          `and the task fails on an undefined variable.`);
        return;
      }
      if (containers.has(normalizeDn(value))) return;
      err(id, 'UNRESOLVED_CONTAINER_PATH',
        `${labName}: ${what} in '${domainName}' has path '${value}', which is not the domain root, ` +
        `not CN=Users, and not an OU this config declares. Declare the OU in ` +
        `organisation_units, or point the path at an existing container — AD does not create ` +
        `intermediate OUs and the object is never made.`);
    };

    const users = isPlainObject(domain.users) ? domain.users : {};
    for (const [userKey, user] of Object.entries(users)) {
      if (!isPlainObject(user)) continue;
      check(user.path, ref('domains', domainName, 'users', userKey, 'path'), `user '${userKey}'`);
    }
    eachGroup(domain, (groupName, group, scope) => {
      if (!isPlainObject(group)) return;
      check(group.path, ref('domains', domainName, 'groups', scope, groupName, 'path'), `group '${groupName}'`);
    });
    // OU paths too: an OU nested under an OU that was never declared fails the
    // same way, and this is the only place that set is known.
    const ous = isPlainObject(domain.organisation_units) ? domain.organisation_units : {};
    for (const [ouName, ou] of Object.entries(ous)) {
      if (!isPlainObject(ou)) continue;
      check(ou.path, ref('domains', domainName, 'organisation_units', ouName, 'path'), `OU '${ouName}'`);
    }
  }

  function validateDomainAcls(domain, domainName) {
    const acls = isPlainObject(domain.acls) ? domain.acls : {};
    for (const [aclKey, acl] of Object.entries(acls)) {
      const at = ref('domains', domainName, 'acls', aclKey);
      if (!isPlainObject(acl)) {
        err(at, 'ACL_NOT_AN_OBJECT',
          `${labName}: ${at} is not an object. An ACL entry is ` +
          `{ for, to, right, inheritance } — all four, no defaults.`);
        continue;
      }
      // roles/acl indexes all four with no default, so a missing one aborts the
      // whole ad-acl.yml play, not just this entry.
      for (const key of ['for', 'to', 'right', 'inheritance']) {
        if (acl[key] === undefined) {
          err(ref('domains', domainName, 'acls', aclKey, key), 'MISSING_ACL_KEY',
            `${labName}: ${at} has no '${key}'. The acl role reads for/to/right/inheritance with ` +
            `no defaults, so one missing key fails the entire ad-acl.yml play, not just this entry. ` +
            `Add '${key}'.`);
        }
      }
      checkAclValues(acl, at, 'domain');
    }
  }

  /**
   * The right/inheritance value check, shared by both contexts.
   *
   * `right` is an ERROR, never a warning. Upstream matches it with PowerShell's
   * ordinal Array.Contains, so 'genericall' does not match 'GenericAll': the ACE
   * is never built, the task sets Changed=false, and Ansible prints GREEN. A
   * typo here is indistinguishable from a correct idempotent run, which is
   * exactly why it has to be caught before it ships.
   *
   * The two vocabularies are NEVER merged. Ext-ManageCA and Ext-Write-SPN exist
   * only in the domain role; feeding either to a host-level acls entry produces
   * no ACE and a green task.
   */
  function checkAclValues(acl, at, context) {
    const vocab = aclRights(context);
    if (acl.right !== undefined && !isAclRight(acl.right, context)) {
      const domainOnly = context === 'host' && isAclRight(acl.right, 'domain');
      err(`${at}.right`, 'UNKNOWN_ACL_RIGHT',
        `${labName}: ${at}.right is ${JSON.stringify(acl.right)}, which the ${context}-level ACL ` +
        `role does not recognise` +
        (domainOnly
          ? ` — it exists only in the DOMAIN vocabulary (roles/acl over ad_acls), not in ` +
            `roles/vulns/acls. Move the entry to the domain's acls block.`
          : `. The match is ordinal and case-sensitive, so no ACE is built and Ansible still ` +
            `reports the task green. Use one of: ${vocab.standard.concat(vocab.extended).join(', ')}.`));
    }
    if (acl.inheritance !== undefined) {
      const values = loadManifest().acl_inheritance.values;
      const ok = values.some((v) => v.toLowerCase() === String(acl.inheritance).toLowerCase());
      if (!ok) {
        err(`${at}.inheritance`, 'UNKNOWN_ACL_INHERITANCE',
          `${labName}: ${at}.inheritance is ${JSON.stringify(acl.inheritance)}. The value is cast to ` +
          `ActiveDirectorySecurityInheritance, which throws on anything outside ` +
          `${values.join(', ')} (note Microsoft's spelling of 'Descendents'). Use one of those.`);
      }
    }
  }

  /**
   * A group with no members that is the SOURCE of an ACL and the target of none.
   *
   * WARNING, not an error: the ACE is planted correctly, so the deploy is fine.
   * What is broken is the attack path — no principal can ever exercise the edge,
   * so the intended route through the lab is severed and a student following the
   * documented path hits a dead end with nothing to enumerate.
   *
   * A zero-member group is NOT by itself suspicious: GOAD deliberately empties
   * the groups you are meant to add yourself to. The discriminator is whether
   * anything grants membership — an inbound ACL naming the group as `to`, an
   * explicit members list, or a cross-domain entry in
   * multi_domain_groups_member. Only when all three are absent is the edge dead.
   */
  function validateDeadAclEdges(domain, domainName) {
    const acls = isPlainObject(domain.acls) ? domain.acls : {};
    const mdg = isPlainObject(domain.multi_domain_groups_member) ? domain.multi_domain_groups_member : {};

    const memberCount = new Map();
    const scopeOf = new Map();
    eachGroup(domain, (groupName, group, scope) => {
      const explicit = isPlainObject(group) && Array.isArray(group.members) ? group.members.length : 0;
      const cross = Array.isArray(mdg[groupName]) ? mdg[groupName].length : 0;
      memberCount.set(groupName.toLowerCase(), explicit + cross);
      scopeOf.set(groupName.toLowerCase(), scope);
    });
    const users = isPlainObject(domain.users) ? domain.users : {};
    for (const user of Object.values(users)) {
      if (!isPlainObject(user) || !Array.isArray(user.groups)) continue;
      for (const g of user.groups) {
        const key = String(g).toLowerCase();
        if (memberCount.has(key)) memberCount.set(key, memberCount.get(key) + 1);
      }
    }

    // Anything an ACL points AT can gain members later in the attack path.
    const grantsMembershipTo = new Set();
    for (const acl of Object.values(acls)) {
      if (!isPlainObject(acl) || acl.to == null) continue;
      const to = String(acl.to);
      grantsMembershipTo.add(to.toLowerCase());
      const cn = /^cn=([^,]+)/i.exec(to);
      if (cn) grantsMembershipTo.add(cn[1].toLowerCase());
    }

    for (const [aclKey, acl] of Object.entries(acls)) {
      if (!isPlainObject(acl) || acl.for == null) continue;
      const forKey = String(acl.for).toLowerCase();
      if (!memberCount.has(forKey)) continue;          // not a group this config declares
      if (memberCount.get(forKey) > 0) continue;       // somebody is in it
      if (grantsMembershipTo.has(forKey)) continue;    // reachable via another edge
      warn(ref('domains', domainName, 'acls', aclKey), 'DEAD_ACL_EDGE',
        `${labName}: ${ref('domains', domainName, 'acls', aclKey)} grants '${acl.right}' on ` +
        `'${acl.to}' to the ${scopeOf.get(forKey)} group '${acl.for}', but that group has no ` +
        `members, no explicit members list, no multi_domain_groups_member entry, and no inbound ` +
        `ACL that would let anyone join it. The ACE is planted and the deploy is green, but no ` +
        `student can ever use it. Add a member, add an edge that grants membership, or delete ` +
        `the ACL.`);
    }
  }

  // ── The generated-lab rules ──────────────────────────────────────────────

  /**
   * Is there an exercise in here?
   *
   * Five obligations, and the reason each one is separate is that each fails
   * silently on its own and each has a different remedy:
   *
   *   1. THERE IS A CHAIN. The headline defect: `acls: {}` and a null chain
   *      deploys green and has nothing to attack.
   *   2. EVERY PRODUCER IS REAL. An edge whose `created_by.role` is not a role
   *      the vendored manifest can produce — or is one of the two the manifest
   *      marks never_emit — is an edge that plants nothing while Ansible prints
   *      green. That is the same class as UNKNOWN_ROLE above, one level up: the
   *      answer key describes an ACE that does not exist.
   *   3. IT IS ROOTED AT THE FOOTHOLD. The one credential the student is given
   *      has to be where the graph starts, or step one is a dead end.
   *   4. IT REACHES THE OBJECTIVE. Over the chain's own edges, NOT its decoys —
   *      a decoy that reaches the objective is a second solution.
   *   5. THE IR AND THE EMITTED LAB AGREE. `chain` and `lab.domains[*].acls` are
   *      written by DIFFERENT code paths (the designer builds edges, the
   *      composer lowers them into config.json). Agreement between two paths is
   *      the only thing that catches a lowering bug — checking either against
   *      itself proves nothing, and a designed edge that never made it into the
   *      acls dict is an ACE nobody plants and an answer key that lies.
   *
   * Nothing here throws and nothing here reads the filesystem: the chain and the
   * foothold are arguments, exactly like the inventory.
   */
  function validateGeneratedChain() {
    const chain = isPlainObject(opts.chain) ? opts.chain : null;
    const foothold = isPlainObject(opts.foothold) ? opts.foothold : null;
    const text = (v) => String(v == null ? '' : v);
    const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

    // ── 1. a chain, with edges in it ────────────────────────────────────────
    const edges = chain && Array.isArray(chain.edges) ? chain.edges.filter(isPlainObject) : [];
    const decoys = chain && Array.isArray(chain.decoys) ? chain.decoys.filter(isPlainObject) : [];
    if (!chain) {
      err('chain', 'CHAIN_MISSING',
        `${labName}: this lab is being validated as GENERATED but no attack chain was supplied. ` +
        `A generated forest with no chain deploys perfectly — domain up, roster populated, every ` +
        `host green — and has nothing in it to attack, and neither the bake nor the deploy would ` +
        `say so. Pass the designed chain as validateLab({ chain, foothold }), or validate this ` +
        `lab in '${MODE_REFERENCE}' mode if nobody is meant to attack it.`);
    } else if (!edges.length) {
      err(ref('chain', 'edges'), 'CHAIN_EMPTY',
        `${labName}: the attack chain carries no edges, so this lab is a domain and a roster ` +
        `with no route through either. Add the designed edges — goad-attack-chain produces them ` +
        `— because an empty chain is the one failure that deploys green, reads as a finished ` +
        `lab, and teaches nothing.`);
    }

    // ── the domain the chain is drawn in ────────────────────────────────────
    const chainDomainName = chain ? text(chain.domain) : '';
    const chainDomain = chainDomainName && has(domains, chainDomainName)
      ? domains[chainDomainName] : null;
    if (chain && !chainDomain) {
      err(ref('chain', 'domain'), 'CHAIN_DOMAIN_UNKNOWN',
        `${labName}: the chain is drawn in domain '${chainDomainName || '(unset)'}', which this ` +
        `lab does not declare (declared: ${Object.keys(domains).join(', ') || 'none'}). ` +
        `ad-acl.yml resolves lab.domains[domain].acls, so every ACL this chain names would be ` +
        `written into a domain block that does not exist and the play would plant none of them. ` +
        `Point chain.domain at a declared domain, or emit the domain it names.`);
    }
    // A domain block with NO acls key is an empty acls block, not an unknown
    // one. Treating it as unknown and standing down would skip the whole
    // cross-check on the exact lab this rule exists for — a generated forest
    // that emitted no ACLs at all — and skipping in silence is the failure mode,
    // not the remedy. Only an unresolvable chain.domain (reported above) leaves
    // nothing to compare against.
    const emittedAcls = chainDomain ? (isPlainObject(chainDomain.acls) ? chainDomain.acls : {}) : null;

    // ── 2. every producer the chain names is one the manifest can produce ───
    // Plants, edges, decoys and prerequisites all go through the same sweep:
    // each of them is a real thing the composer has to write, and each of them
    // fails the same silent way when the role behind it is not real.
    const producers = [];
    if (chain) {
      const start = isPlainObject(chain.start) ? chain.start : {};
      const plants = Array.isArray(start.plants) ? start.plants : [];
      plants.forEach((plant, i) => {
        if (isPlainObject(plant)) producers.push({ p: plant, at: ref('chain', 'start', 'plants', i) });
      });
      const sweep = (list, key) => {
        list.forEach((edge, i) => {
          const at = ref('chain', key, i);
          if (isPlainObject(edge.created_by)) {
            producers.push({ p: edge.created_by, at: ref('chain', key, i, 'created_by') });
          } else {
            err(at, 'CHAIN_EDGE_PRODUCER_MISSING',
              `${labName}: ${at}${edge.id ? ` ('${text(edge.id)}')` : ''} declares no created_by, ` +
              `so nothing in the emitted lab corresponds to it: the answer key describes the hop ` +
              `and the deploy plants nothing. Add a created_by naming the role, host and item ` +
              `that produces this edge.`);
          }
          const pre = Array.isArray(edge.prerequisites) ? edge.prerequisites : [];
          pre.forEach((item, j) => {
            if (isPlainObject(item)) {
              producers.push({ p: item, at: ref('chain', key, i, 'prerequisites', j) });
            }
          });
        });
      };
      sweep(edges, 'edges');
      sweep(decoys, 'decoys');
    }

    for (const { p, at } of producers) {
      const roleName = text(p.role);
      if (!roleName) {
        err(ref(at, 'role'), 'CHAIN_EDGE_PRODUCER_MISSING',
          `${labName}: ${at} names no role, so there is nothing to run and nothing gets planted. ` +
          `Set 'role' to the role that produces it — one of ${Object.keys(CORE_CHAIN_ROLES).join(', ')} ` +
          `for config.json-driven producers, or a manifest role such as 'vulns/files'.`);
      } else if (!has(CORE_CHAIN_ROLES, roleName)) {
        const role = getRole(roleName);
        if (!role) {
          err(ref(at, 'role'), 'CHAIN_EDGE_ROLE_UNKNOWN',
            `${labName}: ${at}.role is '${roleName}', which is neither a role in GOAD ` +
            `${loadManifest().goad_ref.slice(0, 12)} nor one of the config.json producers ` +
            `(${Object.keys(CORE_CHAIN_ROLES).join(', ')}). The name is used verbatim as ` +
            `include_role, so the chain describes a hop no play can plant. Fix the spelling, or ` +
            `use a role the manifest actually carries.`);
        } else if (role.never_emit) {
          err(ref(at, 'role'), 'CHAIN_EDGE_ROLE_NEVER_EMIT',
            `${labName}: ${at}.role is '${roleName}', which is broken upstream and must never be ` +
            `emitted: ${role.never_emit_reason || 'see the vendored role manifest'} The play ` +
            `reports green having planted nothing, so this hop exists only in the answer key. ` +
            `Replace it with a working role.`);
        }
      }

      // ── 5. the IR and the emitted acls block agree ────────────────────────
      if (roleName !== 'acl' || !emittedAcls) continue;
      const item = text(p.item);
      if (!item) {
        err(ref(at, 'item'), 'CHAIN_ACL_NOT_EMITTED',
          `${labName}: ${at} produces an ACL but names no item, so it has no key in ` +
          `${ref('domains', chainDomainName, 'acls')} and the ACE is never written. Give the ` +
          `producer an item name — the acls dict is keyed by it.`);
        continue;
      }
      if (!has(emittedAcls, item)) {
        err(ref(at, 'item'), 'CHAIN_ACL_NOT_EMITTED',
          `${labName}: the chain's edge '${item}' has no entry in ` +
          `${ref('domains', chainDomainName, 'acls')}, which currently holds ` +
          `${Object.keys(emittedAcls).length ? Object.keys(emittedAcls).join(', ') : 'nothing at all'}. ` +
          `The designer drew the hop and the composer never lowered it, so BloodHound will not ` +
          `show the edge the answer key sends the student to look for. Emit the ACL entry, or ` +
          `remove the edge from the chain — these two are written by different code paths and ` +
          `agreeing is the only proof either one is right.`);
        continue;
      }
      const emitted = emittedAcls[item];
      const vars = isPlainObject(p.item_vars) ? p.item_vars : {};
      if (!isPlainObject(emitted)) continue;   // ACL_NOT_AN_OBJECT already said so
      const differs = [];
      for (const key of ['for', 'to']) {
        if (vars[key] === undefined) continue;
        // Principal comparison is AD's, not JavaScript's: case-insensitive, and
        // a `DOMAIN\` prefix on one side does not make it a different account.
        if (chainNodeKey(vars[key]) !== chainNodeKey(emitted[key])) {
          differs.push(`${key} (chain '${text(vars[key])}' vs lab '${text(emitted[key])}')`);
        }
      }
      // `right` is compared EXACTLY, because upstream matches it with an ordinal
      // Array.Contains — see checkAclValues. `inheritance` is compared case-
      // insensitively, because the [ActiveDirectorySecurityInheritance] cast is.
      if (vars.right !== undefined && text(vars.right) !== text(emitted.right)) {
        differs.push(`right (chain '${text(vars.right)}' vs lab '${text(emitted.right)}')`);
      }
      if (vars.inheritance !== undefined
        && text(vars.inheritance).toLowerCase() !== text(emitted.inheritance).toLowerCase()) {
        differs.push(`inheritance (chain '${text(vars.inheritance)}' vs lab '${text(emitted.inheritance)}')`);
      }
      if (differs.length) {
        err(ref('domains', chainDomainName, 'acls', item), 'CHAIN_ACL_MISMATCH',
          `${labName}: the ACL '${item}' the chain describes and the one the lab emits disagree ` +
          `on ${differs.join('; ')}. The ACE that gets planted is the lab's, and the one the ` +
          `answer key describes is the chain's, so the student is sent to look for an edge that ` +
          `is not the edge that exists. Make the emitted entry match the chain.`);
      }
    }

    // ── 3. rooted at the credential the student is actually given ───────────
    const start = chain && isPlainObject(chain.start) ? chain.start : null;
    const startPrincipal = start ? text(start.principal) : '';
    const footholdSam = foothold ? text(foothold.sam) : '';
    const footholdDomain = foothold ? text(foothold.domain) : '';

    if (!foothold || !footholdSam || !footholdDomain) {
      err('foothold_credential', 'FOOTHOLD_MISSING',
        `${labName}: this lab is being validated as GENERATED but ` +
        `${foothold ? 'the foothold credential names no sam and/or no domain' : 'no foothold credential was supplied'}. ` +
        `It is the single object tying the website to the forest — without it there is no way to ` +
        `check that the chain starts where the student does. Pass it as ` +
        `validateLab({ foothold }), using the compiler's foothold_credential.`);
    } else if (chain) {
      if (!startPrincipal) {
        err(ref('chain', 'start', 'principal'), 'CHAIN_NOT_ROOTED_AT_FOOTHOLD',
          `${labName}: the chain declares no start principal, so nothing says which account the ` +
          `student begins as, while the lab plants a credential for '${footholdSam}'. Set ` +
          `chain.start.principal to '${footholdSam}'.`);
      } else if (chainNodeKey(startPrincipal) !== chainNodeKey(footholdSam)) {
        err(ref('chain', 'start', 'principal'), 'CHAIN_NOT_ROOTED_AT_FOOTHOLD',
          `${labName}: the chain starts at '${startPrincipal}' but the only credential this lab ` +
          `plants is '${footholdSam}'. The student gets one account and the graph begins at ` +
          `another, so step one is a dead end that reports nothing. Make chain.start.principal ` +
          `and foothold_credential.sam the same account.`);
      } else if (edges.length
        && !edges.some((e) => chainNodeKey(e.from) === chainNodeKey(startPrincipal))) {
        err(ref('chain', 'edges'), 'CHAIN_NOT_ROOTED_AT_FOOTHOLD',
          `${labName}: no edge leaves '${startPrincipal}', so the chain names the right starting ` +
          `account and then never uses it — the graph is rooted somewhere the student cannot ` +
          `stand. Add the first hop out of '${startPrincipal}', or re-root the chain on an ` +
          `account the lab actually hands out.`);
      }
    }

    // ── the foothold's principal has to exist in the lab we emitted ─────────
    if (foothold && footholdSam && footholdDomain) {
      const homeDomain = has(domains, footholdDomain) && isPlainObject(domains[footholdDomain])
        ? domains[footholdDomain] : null;
      const users = homeDomain && isPlainObject(homeDomain.users) ? homeDomain.users : {};
      // AD is case-insensitive about sAMAccountNames and the composer's key IS
      // the sAMAccountName, so a case-only difference is the same account.
      const wanted = chainNodeKey(footholdSam);
      const found = Object.keys(users).some((sam) => chainNodeKey(sam) === wanted);
      if (!found) {
        const roster = Object.keys(users);
        err('foothold_credential.sam', 'FOOTHOLD_PRINCIPAL_MISSING',
          `${labName}: the foothold credential names '${footholdSam}' in '${footholdDomain}', but ` +
          `${homeDomain ? `that domain's roster is ${roster.length ? roster.join(', ') : 'empty'}` : 'this lab declares no such domain'}. ` +
          `The website would leak a credential the forest never honours: the student sprays it, ` +
          `gets a logon failure, and the exercise has no second act. Add the user to ` +
          `${ref('domains', footholdDomain, 'users')}, or point the credential at an account the ` +
          `lab creates.`);
      }
    }

    // ── 4. and it has to get where it says it is going ──────────────────────
    const objective = chain && isPlainObject(chain.objective) ? chain.objective : null;
    const target = objective ? text(objective.target) : '';
    if (chain && !target) {
      err(ref('chain', 'objective'), 'CHAIN_OBJECTIVE_MISSING',
        `${labName}: the chain declares no objective target, so nothing states what taking this ` +
        `lab means and nothing can check that the edges arrive anywhere. Set ` +
        `chain.objective.target to the principal or DN the last hop compromises.`);
    } else if (chain && target && startPrincipal && edges.length
      && !chainReaches(edges, startPrincipal, target)) {
      err(ref('chain', 'objective', 'target'), 'CHAIN_OBJECTIVE_UNREACHED',
        `${labName}: no route of chain edges runs from '${startPrincipal}' to the declared ` +
        `objective '${target}' — the graph stops short of the thing it says it is for, and every ` +
        `edge after the break is scenery. Decoys are deliberately excluded from this walk, ` +
        `because a decoy that reaches the objective is a second solution rather than a decoy. ` +
        `Add the missing hop, or set the objective to where the edges actually end.`);
    }
  }
}

// ─── Boundary ───────────────────────────────────────────────────────────────

/**
 * Throwing skin over validateLab(), for a route or a generator that has nowhere
 * useful to put a findings list.
 *
 * Modelled on assertEngagementDeployable(): status 409 because the request is
 * well-formed and the SERVER STATE (the lab definition) is what conflicts, and a
 * single SCREAMING_SNAKE code so a caller can branch without string-matching.
 * The full findings ride along on `.errors` / `.warnings` so a UI can render all
 * of them rather than only the first.
 *
 * Warnings never throw. That is the point of the split: a silent no-op is worth
 * telling somebody about, and it is not worth refusing to build the lab over —
 * two shipped labs would be unbuildable if it were.
 *
 * Takes the same input as validateLab, `mode`/`chain`/`foothold` included: a
 * generator asserting its own output passes MODE_GENERATED plus the chain it
 * designed, and every generated-mode finding is an error, so a chainless lab
 * throws here instead of reaching a bake.
 */
function assertLabCompiles(input) {
  const result = validateLab(input);
  if (result.errors.length) {
    const labName = (input && input.labName) || 'lab';
    const head = result.errors.slice(0, 3).map((e) => `${e.id}: ${e.message}`).join(' ');
    const more = result.errors.length > 3 ? ` (+${result.errors.length - 3} more)` : '';
    const error = new Error(
      `${labName} will not deploy: ${result.errors.length} blocking problem` +
      `${result.errors.length === 1 ? '' : 's'} in the lab definition. ${head}${more}`
    );
    error.status = 409;
    error.code = 'LAB_DEFINITION_INVALID';
    error.errors = result.errors;
    error.warnings = result.warnings;
    throw error;
  }
  return result;
}

module.exports = {
  // Parsing — tolerant in, strict out.
  stripTrailingCommas,
  parseLabConfig,
  toStrictJson,
  parseInventory,
  // Pure primitives, exported because they encode AD rules worth testing alone.
  passwordClasses,
  accountNameTokens,
  containsAccountName,
  rootDnForDomain,
  normalizeDn,
  normalizeWinPath,
  chainNodeKey,
  chainReaches,
  // The core and its boundary.
  validateLab,
  assertLabCompiles,
  // The mode vocabulary. Exported so a caller names the mode with a constant
  // rather than a string literal — a typo'd literal is the one way to get the
  // generated rules skipped, and VALIDATION_MODE_UNKNOWN only catches it at
  // runtime.
  MODE_REFERENCE,
  MODE_GENERATED,
  VALIDATION_MODES,
  CORE_CHAIN_ROLES,
  // Limits, so a caller reports the same numbers this file enforces.
  MAX_SAM_ACCOUNT_NAME,
  MAX_COMMON_NAME,
  MAX_NETBIOS_HOSTNAME,
  MIN_DOMAIN_PASSWORD_LEN,
  MIN_LOCAL_ADMIN_PASSWORD_LEN,
  REQUIRED_PASSWORD_CLASSES,
  MEMBER_GROUPS,
};
