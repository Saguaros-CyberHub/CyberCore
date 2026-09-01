/**
 * goad-lab-compile.js — the COMPOSER half of the CiAB AD compiler.
 * ============================================================================
 * Input:  one CiAB client profile.
 * Output: a labIR (the intermediate representation the ACL designer also reads
 *         and writes) plus the emitted lab tree, ready for pushLabTree().
 *
 * WHY A CHASSIS AND NOT A GENERATOR
 * Composing a GOAD topology from scratch is the riskiest thing in this pipeline:
 * the inventory groups, the config-key / dict_key / ansible_host three-way join,
 * the playbook chain, the DNS wiring and the password invariants are each easy
 * to get subtly wrong and none of them fail early — they fail 60 minutes into a
 * 90 minute bake, or worse, they do not fail at all and the lane comes up green
 * and empty. So this module NEVER composes a topology. It reads one of three
 * chassis (data/chassis/{S,M,L}), each carved out of a lab that is PROVEN to
 * deploy at the pinned GOAD ref, and puts the payload back. Everything
 * structural — group membership that drives dcpromo, the octets, the dns_domain
 * chain, [parent_dc]/[child_dc]/[trust]/[adcs_customtemplates] — is inherited,
 * not invented.
 *
 * WHY THE TIER LADDER IS DOMAINS AND NOT DCs
 * `lab.domains[d].dc` is a SCALAR: one domain, one DC. `roles/domain_controller_slave`
 * exists upstream but has zero references from any playbook, so a second DC in
 * one domain is unreachable from config.json. A profile that org-sizing says
 * needs two DCs therefore has to be spent on a second DOMAIN, and the three
 * shapes GOAD ships map cleanly onto three org stories:
 *   S  1 domain              a single-site company
 *   M  parent + child        a regional subsidiary
 *   L  2 forests + a trust   an acquired company
 * Below org-sizing's domain floor there is no AD at all, and this module
 * REFUSES rather than emitting an empty forest — a lab whose only content is a
 * bare DC teaches nothing and costs a full bake to discover.
 *
 * WHY VARIETY IS A CORRECTNESS PROPERTY HERE, NOT A GARNISH
 * The vendored ad/GOAD-Light in the fork is a reskin: it renamed every noun and
 * kept all twelve ACL edges. Two clients built that way are the same lab twice,
 * and the generated answer key then describes an attack path as if it had been
 * derived from that client's risk profile. So two profiles that land on the same
 * tier must differ STRUCTURALLY. This module varies, all seeded from run_id:
 *   - which host carries which service (iis / mssql / webdav placement)
 *   - the OU scheme (CN=Users, flat department OUs, or a tiered company OU)
 *   - the group shape (bare / suffixed / AGDLP two-tier, and its scope mix)
 *   - the number and placement of vulns
 *   - the defensive posture (defender, Protected Users, sensitive accounts,
 *     RunAsPPL, MachineAccountQuota)
 * The attack path itself is deliberately NOT varied here — chain and acls belong
 * to the ACL designer, and this file only lowers what it is handed.
 *
 * DETERMINISM IS THE CONTRACT
 * No Math.random(), no Date.now(), no I/O beyond reading the chassis. Every
 * choice is hashed off the profile's run_id through ai/profile/hash.js, so
 * regenerating a profile yields a byte-identical lab. That is what makes
 * paper-vs-lane parity assertable by regeneration rather than by inspection.
 *
 * TOLERANT IN, STRICT OUT
 * A chassis is read with parseLabConfig(), which tolerates the trailing comma
 * ad/DRACARYS ships (Ansible loads config.json through vars_files, i.e. PyYAML,
 * which accepts it). Everything this module WRITES goes through toStrictJson().
 *
 * NOTHING LEAVES HERE UNVALIDATED
 * compileLab() runs its own output through goad-lab-validate's assertLabCompiles
 * and goad-preflight's assertGoadLabPreflight before returning. A composer that
 * can emit a lab those two reject is a composer whose bugs are found on a lane.
 *
 * THE DOMAIN ADMINS CONTRACT, WHICH IS SHARED WITH THE ACL DESIGNER
 * This module mints roster Domain Admins on purpose — a real company has them,
 * and an IT director is one — but it used to mint them SILENTLY. The designer's
 * anti-shortcut gate then saw privileged principals it had no way to reason
 * about and rejected every lab that had any: 60 realistic profiles compiled and
 * 0 produced an attack chain, because the check as written could never pass.
 *
 * The contract is now explicit, and it has three parts:
 *   DECLARE   principals.declared_admins carries every principal this module
 *             puts in Domain Admins, Enterprise Admins, Schema Admins or the
 *             built-in Administrators — including membership acquired through
 *             NESTED groups, and including a DC's local Administrators list,
 *             which on a domain controller IS the built-in Administrators.
 *   SELF-CHECK assertAdminsDeclared() re-derives that set from the EMITTED lab
 *             by a different route and refuses on any difference. A Domain Admin
 *             this composer creates and does not declare is a compile error;
 *             silence is what produced the original bug.
 *   NEGOTIATE compileLabWithChain() runs composer -> designer -> composer. When
 *             the designer reports a declared 'roster_realism' admin reachable
 *             more cheaply than the intended chain, the fix is THIS module's:
 *             demote that principal and re-emit, bounded and deterministic. The
 *             designer never widens its check to make the failure go away.
 */

const fs = require('fs');
const path = require('path');

const { computeOrgSizing } = require('../ai/profile/org-sizing');
const { hashStr, hashInt, hashPick, hashCoin } = require('../ai/profile/hash');
// The domain-controller predicate, shared with ai/profile/validators.js so the
// paper and the lane can never form two opinions about which register entries
// are controllers. See ai/profile/dc-name.js.
const { isDcRecord } = require('../ai/profile/dc-name');

const {
  parseLabConfig,
  toStrictJson,
  parseInventory,
  passwordClasses,
  containsAccountName,
  rootDnForDomain,
  assertLabCompiles,
  MODE_GENERATED,
  MAX_SAM_ACCOUNT_NAME,
  MAX_COMMON_NAME,
  MAX_NETBIOS_HOSTNAME,
  MIN_DOMAIN_PASSWORD_LEN,
  MIN_LOCAL_ADMIN_PASSWORD_LEN,
  REQUIRED_PASSWORD_CLASSES,
} = require('./goad-lab-validate');

const {
  assertGoadLabPreflight,
  chainForLab,
  DEFAULT_CHAIN,
} = require('./goad-preflight');

const { getRole, isNeverEmit } = require('./goad-role-manifest');

// The designer half. Required here — and NOT the other way round, so there is no
// cycle — because the Domain Admins policy is a contract BETWEEN the two halves
// and compileLabWithChain() below is the only place that can drive it: the
// composer declares, the designer verifies, and only the composer can act on a
// verdict of "this admin is reachable too cheaply" by demoting and re-emitting.
// PRIVILEGED_GROUPS is imported rather than re-spelled: two copies of that list
// is precisely how one half starts minting admins the other half never checks.
const { designAttackChain, PRIVILEGED_GROUPS } = require('./goad-attack-chain');

// ─── Layout ─────────────────────────────────────────────────────────────────

const CHASSIS_DIR = path.join(__dirname, '..', 'data', 'chassis');

/** The three tiers, in ladder order. */
const TIERS = Object.freeze(['S', 'M', 'L']);

/**
 * The files a chassis contributes to the emitted tree.
 *
 * `playbooks.yml` is NOT here and its absence is deliberate: pushLabTree()
 * REFUSES a tree containing one (goad-lab-push.js:982) because it renders that
 * file itself from the `chain` argument, under both the lab key and `default:`.
 * So the chain travels as a return value, not as a tree member. The tier-S
 * chassis still carries a playbooks.yml — it is where the chain is READ from.
 */
const TREE_FILES = Object.freeze(['data/config.json', 'data/inventory', 'providers/proxmox/inventory']);

// ─── Errors ─────────────────────────────────────────────────────────────────

/**
 * Every refusal this module makes, with a machine-routable code.
 *
 * Modelled on assertLabCompiles' 409 and assertGoadLabPreflight's 422: the
 * request is well-formed, the thing it describes is not. A caller branches on
 * `.code`; a UI renders `.message`, which always names the reason rather than
 * just the rule.
 */
class LabCompileError extends Error {
  constructor(message, details) {
    super(message);
    this.name = 'LabCompileError';
    this.status = 422;
    Object.assign(this, details || {});
  }
}

// ─── Tiny helpers ───────────────────────────────────────────────────────────

function obj(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v) ? v : {};
}

function str(v) {
  return v === null || v === undefined ? '' : String(v).trim();
}

function arr(v) {
  return Array.isArray(v) ? v : [];
}

function clone(v) {
  return JSON.parse(JSON.stringify(v));
}

/**
 * Deterministic sample of `n` distinct items.
 *
 * Splices out of a copy rather than picking with replacement, because a vuln
 * list with the same role twice runs it twice and the second run is a silent
 * no-op that still costs a WinRM round trip.
 */
function hashSample(runId, salt, list, n) {
  const pool = list.slice();
  const out = [];
  const want = Math.max(0, Math.min(n, pool.length));
  for (let i = 0; i < want; i++) {
    out.push(pool.splice(hashStr(runId, `${salt}:${i}`) % pool.length, 1)[0]);
  }
  return out;
}

/**
 * Fold diacritics to their ASCII base letter.
 *
 * Every identifier this module mints — sAMAccountName, NetBIOS name, hostname,
 * DNS label — is restricted to ASCII by Windows or by DNS. Dropping the accented
 * character instead of folding it turns "Åkerström" into "kerstrm", which is not
 * a shortening of anybody's name; folding gives "akerstrom", which is what the
 * organisation itself would have used.
 */
function fold(v) {
  // NFD splits a precomposed letter into base + combining mark; \p{Mn} is that
  // mark. Written as a property escape rather than a literal codepoint range so
  // the rule survives being read, copied and re-encoded.
  return str(v).normalize('NFD').replace(/\p{Mn}/gu, '');
}

/** Lowercase, ASCII-only, no separators — the atom every identifier is built from. */
function atom(v) {
  return fold(v).toLowerCase().replace(/[^a-z0-9]+/g, '');
}

/**
 * Force `name` unique within `taken`, never exceeding `max` characters.
 *
 * Trims from the RIGHT to make room for the discriminator, because every
 * identifier here (sAMAccountName, NetBIOS name, hostname) is length-capped by
 * Windows and a collision that gets silently truncated back into a collision is
 * the failure this exists to prevent.
 */
function uniqueName(name, taken, max) {
  const base = String(name).slice(0, max);
  if (!taken.has(base.toLowerCase())) {
    taken.add(base.toLowerCase());
    return base;
  }
  for (let n = 2; n < 1000; n++) {
    const suffix = String(n);
    const candidate = base.slice(0, Math.max(1, max - suffix.length)) + suffix;
    if (!taken.has(candidate.toLowerCase())) {
      taken.add(candidate.toLowerCase());
      return candidate;
    }
  }
  throw new LabCompileError(`Could not make '${name}' unique within ${max} characters`, {
    code: 'CIAB_IDENTIFIER_EXHAUSTED',
  });
}

// ─── Privileged membership: the declaration half of the DA contract ─────────

/**
 * THE POLICY THIS SECTION IMPLEMENTS, STATED ONCE.
 *
 * A real company HAS domain admins — the IT director is one, and a forest whose
 * only privileged account is the one the exercise ends at is a forest no student
 * believes. So this composer mints them on purpose. But an admin the composer
 * creates and never mentions is indistinguishable, from the designer's side,
 * from an accident: the designer's anti-shortcut gate saw privileged principals
 * it had no way to reason about and rejected every lab that had any, which is
 * how 60 of 60 profiles compiled and 0 of 60 produced a chain.
 *
 * The resolution is a DECLARATION, not a relaxation:
 *
 *   the composer   emits principals.declared_admins — every principal it places
 *                  in Domain Admins, Enterprise Admins, Schema Admins or the
 *                  built-in Administrators, INCLUDING membership acquired
 *                  through nested groups — each with the reason it exists.
 *   the designer   consumes that set. It no longer objects to a declared admin
 *                  existing; it asserts the property that actually protects the
 *                  exercise, that no 'roster_realism' admin is reachable by a
 *                  path shorter than the intended chain.
 *   the composer   acts on a failed verdict by demoting that principal out of
 *                  the privileged group and re-emitting (compileLabWithChain).
 *
 * assertAdminsDeclared() below is what keeps the first half honest: it walks the
 * EMITTED lab by a different route from the one that made the declarations, so a
 * future edit that mints an admin without declaring it is a compile error here
 * rather than a silent hole a student walks through on the lane.
 */

/**
 * A principal name reduced to the key AD itself would compare on: no `DOMAIN\`
 * prefix, case-folded. Windows is case-insensitive for sAMAccountNames and group
 * names, and GOAD's own config mixes `NORTH\jon.snow` with `jon.snow` in the same
 * file, so a case- or prefix-sensitive compare here would miss exactly the
 * nesting this check exists to find.
 */
function principalKey(name) {
  const s = str(name);
  const i = s.lastIndexOf('\\');
  return (i === -1 ? s : s.slice(i + 1)).toLowerCase();
}

/** PRIVILEGED_GROUPS as comparison keys. Derived, never re-typed. */
const PRIVILEGED_GROUP_KEYS = new Set(PRIVILEGED_GROUPS.map(principalKey));

/** The demotion set, from whatever shape the negotiation handed us: a bare sam,
 *  or `DOMAIN\sam`, or `fqdn\sam`. All three reduce to the same key. */
function demotionSet(list) {
  return new Set(arr(list).map(principalKey).filter(Boolean));
}

/**
 * Every principal in the emitted lab that holds privileged group membership,
 * transitively.
 *
 * THREE ROUTES IN, and the second and third are the ones a hand-written check
 * always forgets:
 *   users[sam].groups            direct membership, the obvious one
 *   groups[scope][name].members  a GROUP inside a privileged group: every member
 *                                of the inner group is an admin and nothing
 *                                anywhere says so
 *   hosts[dc].local_groups       a DC's LOCAL Administrators group IS the
 *                                domain's built-in Administrators — the same
 *                                principal the endgame is defined by. On a
 *                                MEMBER server it is only local admin on that
 *                                box, which is a different (and much weaker)
 *                                fact, so only the DC's list counts here.
 *
 * @returns {Map<string, {sam:string, domain:string, via:string}>} keyed
 *          `<fqdn>\<principalKey>`.
 */
function privilegedPrincipalsOf(lab) {
  const found = new Map();
  const hosts = Object.values(obj(lab.hosts));

  for (const [fqdn, block] of Object.entries(obj(lab.domains))) {
    const parents = new Map();  // member key -> [parent key]
    const displayName = new Map();
    const linkUp = (member, group) => {
      const mk = principalKey(member);
      const gk = principalKey(group);
      if (!mk || !gk || mk === gk) return;
      displayName.set(mk, str(member).split('\\').pop());
      displayName.set(gk, str(group).split('\\').pop());
      if (!parents.has(mk)) parents.set(mk, []);
      if (parents.get(mk).indexOf(gk) === -1) parents.get(mk).push(gk);
    };

    for (const [sam, user] of Object.entries(obj(block.users))) {
      for (const g of arr(obj(user).groups)) linkUp(sam, g);
    }
    for (const byName of Object.values(obj(block.groups))) {
      for (const [name, group] of Object.entries(obj(byName))) {
        for (const m of arr(obj(group).members)) linkUp(m, name);
      }
    }
    for (const [name, members] of Object.entries(obj(block.multi_domain_groups_member))) {
      for (const m of arr(members)) linkUp(m, name);
    }
    for (const host of hosts) {
      if (str(obj(host).domain) !== fqdn || str(obj(host).type) !== 'dc') continue;
      for (const m of arr(obj(obj(host).local_groups).Administrators)) linkUp(m, 'Administrators');
    }

    for (const [member] of parents) {
      // A privileged group is not its own member. Reporting 'Domain Admins' as a
      // principal that must be declared would make the declaration meaningless.
      if (PRIVILEGED_GROUP_KEYS.has(member)) continue;
      const seen = new Set([member]);
      const queue = [member];
      while (queue.length > 0) {
        const node = queue.shift();
        for (const parent of (parents.get(node) || [])) {
          if (PRIVILEGED_GROUP_KEYS.has(parent) && !found.has(`${fqdn}\\${member}`)) {
            found.set(`${fqdn}\\${member}`, {
              sam: displayName.get(member) || member,
              domain: fqdn,
              via: displayName.get(parent) || parent,
            });
          }
          if (!seen.has(parent)) { seen.add(parent); queue.push(parent); }
        }
      }
    }
  }
  return found;
}

/**
 * The composer's own self-check: nothing privileged may be silent.
 *
 * Deliberately re-derived from the emitted `lab` rather than from the bookkeeping
 * that produced the declarations. Checking a registry against itself proves
 * nothing; the whole failure this exists to prevent is a code path that mints an
 * admin and forgets to say so, and that path would populate both sides of a
 * self-consistent check identically.
 */
function assertAdminsDeclared(lab, declared, labName) {
  const actual = privilegedPrincipalsOf(lab);
  const missing = [];
  for (const [key, info] of actual) {
    if (!declared.has(key)) missing.push(info);
  }
  if (missing.length > 0) {
    const named = missing.map((m) => `${m.sam} (via ${m.via} in ${m.domain})`).join(', ');
    throw new LabCompileError(
      `${labName}: ${missing.length} principal${missing.length === 1 ? '' : 's'} hold privileged `
      + `group membership that this compiler never declared — ${named}. Every principal placed in `
      + `${PRIVILEGED_GROUPS.join(', ')} — directly or through a nested group, and including a `
      + "DC's local Administrators list — must appear in principals.declared_admins with a reason. "
      + 'An undeclared admin is the exact silence that made the attack-chain designer reject every '
      + 'lab this composer produced: it cannot tell a deliberate IT director from an accident.',
      { code: 'CIAB_UNDECLARED_DOMAIN_ADMIN', missing }
    );
  }
  // The mirror-image mistake: a declaration for a principal that is not actually
  // privileged would tell the designer to skip a check it should have run.
  const stale = [];
  for (const [key, info] of declared) {
    if (!actual.has(key)) stale.push(info);
  }
  if (stale.length > 0) {
    throw new LabCompileError(
      `${labName}: principals.declared_admins claims ${stale.map((s) => s.sam).join(', ')} `
      + 'hold privileged membership, but the emitted lab does not grant it. A declaration the lab '
      + 'does not honour switches off a shortcut check for a principal that never needed one.',
      { code: 'CIAB_STALE_ADMIN_DECLARATION', stale }
    );
  }
  return actual;
}

// ─── Reading the profile ────────────────────────────────────────────────────

/**
 * The facts this compiler needs, pulled from wherever a profile happens to keep
 * them.
 *
 * THREE LAYOUTS, ONE SET OF FACTS — the same problem profile-to-spec.js's
 * resolvePublicDomain() solves for one field. An AI profile nests everything
 * under json_data.student_view.raw.threats, the quick view keeps a flattened
 * copy, and a DB row or an uploaded profile is flat. Production hands us the DB
 * row spread over `json_data`, so the nested forms are the ones that actually
 * arrive.
 */
function readProfile(profile) {
  const p = obj(profile);
  const jd = obj(p.json_data);
  const sv = obj(jd.student_view || p.student_view);
  const threats = obj(obj(sv.raw).threats);
  const org = obj(threats.organization || p.organization);
  const it = obj(threats.it_environment || p.it_environment);
  const quick = obj(sv.quick);
  const meta = obj(sv.meta);

  const runId = str(meta.run_id || p.run_id || jd.run_id || quick.run_id);
  if (!runId) {
    // No silent fallback. Every downstream choice is hashed off this string, so
    // inventing one here would produce a lab that cannot be regenerated — and
    // paper-vs-lane parity is asserted BY regeneration.
    throw new LabCompileError(
      'This profile carries no run_id, so the lab it compiles to could never be regenerated. '
      + 'Every identifier, password and structural choice below is hashed off run_id; without '
      + 'it the same profile would compile to a different forest each time. Pass a profile '
      + 'generated by ai/profile (which stamps student_view.meta.run_id), or set run_id on the row.',
      { code: 'CIAB_PROFILE_NO_RUN_ID' }
    );
  }

  const employees = Number(org.employees_total || quick.employees_total || p.employee_count || 0) || 0;

  return {
    runId,
    companyName: str(org.company_name || quick.company_name || p.company_name) || 'Client',
    domainPublic: str(org.domain_public || quick.domain_public || p.domain_public),
    employees,
    clientType: str(meta.client_type || p.client_type) || 'SMB',
    industry: str(org.industry || quick.industry || p.industry) || null,
    hqCity: str(org.hq_city || quick.hq_city || p.hq_city) || '',
    delivery: str(it.delivery || quick.delivery || p.delivery),
    maturity: str(org.security_maturity || meta.difficulty || p.difficulty),
    stakeholders: arr(sv.stakeholders || p.stakeholders || obj(jd).stakeholders),
    departments: obj(org.department_breakdown),
    // The asset register the student reads. Same three-way fallback as every
    // other fact here, and the same one profile-deploy's loadProfileForDeploy
    // walks — it spreads the normalized array onto the row as `assets`, which is
    // the shape production actually hands this compiler.
    assets: arr(obj(threats.network).assets || p.assets || jd.assets),
  };
}

// ─── Tier selection ─────────────────────────────────────────────────────────

/**
 * Derive the tier. Never asked, never configured.
 *
 * The ladder reuses org-sizing's identity block verbatim, because that module is
 * already the single authority on "does an org this size, in this sector, with
 * this delivery posture actually run AD?" and validators.js/validateSizing
 * enforces the very same numbers on the PAPER side (S-01 strips DCs below the
 * floor, S-02 trims above max_dcs). A second opinion here is how the paper and
 * the lane drift apart.
 *
 *   has_domain === false   → refuse. There is no forest to build.
 *   emp < second_dc_at     → S. One DC is plausible, so one domain.
 *   sites < 2              → M. A second DC is warranted; since `dc` is a scalar
 *                            the only way to spend it is a child domain, and a
 *                            single-site org's second domain is a subsidiary.
 *   sites >= 2             → L. Multi-site AND second-DC-sized is the acquisition
 *                            story, which is what a second FOREST plus a trust is.
 *
 * @returns {{ tier: string, reason: string, sizing: object }}
 */
function selectTier(facts) {
  const sizing = computeOrgSizing({
    clientType: facts.clientType,
    industry: facts.industry,
    employeeCount: facts.employees,
    delivery: facts.delivery,
    maturity: facts.maturity,
    runId: facts.runId,
  });

  const id = sizing.identity;
  if (!id.has_domain) {
    const floor = id.domain_floor === Infinity
      ? `never for a ${sizing.delivery_class}-first ${sizing.sector}`
      : `${id.domain_floor} employees`;
    throw new LabCompileError(
      `${facts.companyName} has no Active Directory to compile: org-sizing puts the first domain `
      + `at ${floor}, and this profile is a ${sizing.employees}-employee ${sizing.sector} with `
      + `delivery=${sizing.delivery_class}, so has_domain is false and directory is `
      + `'${id.directory}'. Emitting a forest anyway would contradict the paper profile the `
      + `student reads — validators.js/S-01 strips domain controllers off exactly this org and `
      + `flags it. Deploy this lane without a GOAD tier.`,
      {
        code: 'CIAB_NO_AD_TO_COMPILE',
        sizing,
        employees: sizing.employees,
        domain_floor: id.domain_floor,
        directory: id.directory,
      }
    );
  }

  if (sizing.employees < id.second_dc_at) {
    return {
      tier: 'S',
      sizing,
      reason: `${sizing.employees} employees is below the second-DC threshold of ${id.second_dc_at}, `
        + `so max_dcs is ${id.max_dcs} — one domain, one controller, one site.`,
    };
  }
  if (sizing.network.sites < 2) {
    return {
      tier: 'M',
      sizing,
      reason: `${sizing.employees} employees is at or above the second-DC threshold of `
        + `${id.second_dc_at} (max_dcs=${id.max_dcs}) but org-sizing puts the org on a single site. `
        + `lab.domains[d].dc is a scalar, so the second controller can only be spent as a child `
        + `domain — the regional-subsidiary shape.`,
    };
  }
  return {
    tier: 'L',
    sizing,
    reason: `${sizing.employees} employees across ${sizing.network.sites} sites, at or above the `
      + `second-DC threshold of ${id.second_dc_at}. Multi-site plus second-DC-sized is the `
      + `acquisition story: two forests and a trust.`,
  };
}

// ─── Identity minting ───────────────────────────────────────────────────────

/**
 * TLDs a lab domain must never be built on.
 *
 * `.local` is the one that bites twice: it is mDNS-reserved (RFC 6762), and this
 * platform's own mail relay blackholes it, so a forest named under it is both
 * standards-violating and locally undeliverable. The rest are RFC 2606 / RFC
 * 8375 reserved names — a public domain field containing one is not a public
 * domain, it is a placeholder that leaked out of somebody's example config.
 */
const RESERVED_TLDS = Object.freeze(new Set([
  'local', 'invalid', 'test', 'example', 'localhost', 'internal', 'lan', 'home', 'arpa', 'onion',
]));

/** Legal-form noise that should not survive into a NetBIOS name. */
const LEGAL_SUFFIX_RE = /\b(inc|llc|l\.l\.c|ltd|limited|corp|corporation|co|company|plc|gmbh|pllc|llp|pc|group|holdings)\b\.?/g;

/** A slug for the client: lowercase, hyphenated, legal form stripped. */
function companySlug(name) {
  const raw = fold(name).toLowerCase().replace(/&/g, ' and ');
  const stripped = raw
    .replace(LEGAL_SUFFIX_RE, ' ')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    // A leading article is never part of the short code an org is known by, and
    // "THE" as a NetBIOS name is the tell that nobody looked.
    .replace(/^(the|a|an)-/, '');
  if (stripped && !/^(the|a|an)$/.test(stripped)) return stripped;
  // Stripping ate the whole name ("The Group Holdings Co", "Holdings Co"). Keep
  // the noise rather than returning an article — a slug is load-bearing for the
  // domain name, and `corp.the.com` is a lab nobody will believe.
  const unstripped = raw.replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '');
  return unstripped || 'client';
}

/**
 * The short code an organization is actually known by, from its slug.
 *
 * NetBIOS names and hostname prefixes are both hard-capped and both get READ —
 * by a student mapping the estate and by whoever debugs the bake. A blind
 * truncation produces `NORTHFIEL-SRV02`, which is a name nobody chose and which
 * collides with any sibling sharing the prefix. So: use the first slug label
 * when it fits, fall back to initials when the org has enough words to have
 * them (a district really is "NUD"), and only then truncate.
 */
function shortCode(slug, max) {
  const all = str(slug).split('-').filter(Boolean);
  // An article is never the code: "The Group Holdings Co" is known as GROUP.
  const labels = all.filter((l) => !/^(the|a|an|of|and|for)$/.test(l));
  if (!labels.length) return all.length ? all[0].toUpperCase().slice(0, max) : 'CORP';
  const first = labels[0].toUpperCase();
  if (first.length <= max) return first;
  if (labels.length >= 3) {
    const initials = labels.map((l) => l[0]).join('').toUpperCase();
    if (initials.length >= 2 && initials.length <= max) return initials;
  }
  return first.slice(0, Math.min(max, 6));
}

/**
 * `organization.domain_public` as a usable public domain, or null.
 *
 * REFUSES RATHER THAN REPAIRS, for the same reason profile-to-spec's dnsName()
 * does: this field is LLM-authored and arrives as anything — 'N/A', a URL, a
 * bare word, `acme.local`. A malformed value that is patched into shape becomes
 * a forest name nobody chose; a refused one falls through to the slug, which is
 * derived from a field we do trust.
 */
function publicDomainOf(raw) {
  const name = str(raw)
    .toLowerCase()
    .replace(/^[a-z][a-z0-9+.-]*:\/\//, '')
    .replace(/\/.*$/, '')
    .replace(/\.$/, '')
    .replace(/^www\./, '');
  if (!name || name.length > 200) return null;
  if (!/^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$/.test(name)) return null;
  const labels = name.split('.');
  if (labels.length < 2 || labels.some((l) => l.length > 63)) return null;
  const tld = labels[labels.length - 1];
  if (!/^[a-z]{2,}$/.test(tld) || RESERVED_TLDS.has(tld)) return null;
  return name;
}

/** Child-domain labels: a subsidiary or a region, never a function. */
const CHILD_LABELS = Object.freeze([
  'north', 'south', 'east', 'west', 'central', 'regional', 'field', 'branch', 'metro', 'valley',
]);

/** Names for the ACQUIRED company that forest B represents. */
const ACQUISITION_NAMES = Object.freeze([
  'northgate', 'brightpath', 'cedarline', 'stonebridge', 'harborview',
  'meridian-partners', 'lakeshore', 'ironwood', 'summitpoint', 'clearwater-labs',
]);

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

/**
 * Mint the forest(s).
 *
 * The child FQDN is a STRICT suffix extension of its parent because
 * ad-child_domain.yml:20 derives parent_domain by dropping the first label and
 * then reads lab.domains[parent].domain_password with no default — a child whose
 * name is not `<label>.<parent>` resolves a domain that does not exist and kills
 * the play. The two forest roots must NOT share a suffix for the mirror-image
 * reason: the second forest would be read as a child of the first.
 */
function mintDomains(facts, tier, chassisTopology) {
  const slug = companySlug(facts.companyName);
  const publicDomain = publicDomainOf(facts.domainPublic);

  // `corp.<public>` keeps the client's real identity visible in the lab while
  // making it unmistakably the INTERNAL forest and not the public zone the
  // gateway also answers for. Already-prefixed values are left alone.
  const base = publicDomain || `${slug}.com`;
  const rootA = base.split('.')[0] === 'corp' ? base : `corp.${base}`;

  const minted = [];
  const netbiosTaken = new Set();

  minted.push({
    fqdn: rootA,
    netbios: uniqueName(netbiosCandidate(shortCode(slug, MAX_NETBIOS_HOSTNAME)), netbiosTaken, MAX_NETBIOS_HOSTNAME),
    is_forest_root: true,
    parent_fqdn: null,
    trust_fqdn: null,
  });

  if (tier === 'M' || tier === 'L') {
    const label = hashPick(facts.runId, 'child-label', CHILD_LABELS);
    minted.push({
      fqdn: `${label}.${rootA}`,
      // The child's NetBIOS name is the child LABEL, not the company name with
      // the label glued on: upstream's own north.sevenkingdoms.local is NORTH,
      // and a 15-character truncation of "ACMEHEALTHNORTH" is a name that
      // collides with its own parent's prefix and reads as a typo.
      netbios: uniqueName(netbiosCandidate(label), netbiosTaken, MAX_NETBIOS_HOSTNAME),
      is_forest_root: false,
      parent_fqdn: rootA,
      trust_fqdn: null,
    });
  }

  if (tier === 'L') {
    // Walk the pool rather than picking once: an acquired company whose name
    // happens to match the client's would produce two forests that are suffix
    // related, and ad-trusts.yml would then build a trust between a domain and
    // itself.
    const start = hashStr(facts.runId, 'acquisition') % ACQUISITION_NAMES.length;
    let rootB = null;
    for (let i = 0; i < ACQUISITION_NAMES.length; i++) {
      const candidate = `corp.${ACQUISITION_NAMES[(start + i) % ACQUISITION_NAMES.length]}.com`;
      if (!suffixRelated(candidate, rootA) && !minted.some((d) => suffixRelated(candidate, d.fqdn))) {
        rootB = candidate;
        break;
      }
    }
    if (!rootB) {
      throw new LabCompileError(
        `Could not mint a second forest that is not suffix-related to '${rootA}'`,
        { code: 'CIAB_FOREST_NAME_COLLISION' }
      );
    }
    const acqSlug = rootB.split('.')[1];
    minted.push({
      fqdn: rootB,
      netbios: uniqueName(netbiosCandidate(shortCode(acqSlug, MAX_NETBIOS_HOSTNAME)), netbiosTaken, MAX_NETBIOS_HOSTNAME),
      is_forest_root: true,
      parent_fqdn: null,
      trust_fqdn: rootA,
    });
    minted[0].trust_fqdn = rootB;
  }

  // Bind each minted domain to the chassis domain it replaces, positionally.
  // chassis.json lists its domains in the same order this function builds them
  // (root, child, second root), and ciab-chassis.test.js pins that list.
  const chassisDomains = arr(chassisTopology.domains);
  if (chassisDomains.length !== minted.length) {
    throw new LabCompileError(
      `Tier ${tier} chassis declares ${chassisDomains.length} domains but the composer minted `
      + `${minted.length}. The ladder and the chassis have drifted apart.`,
      { code: 'CIAB_CHASSIS_DOMAIN_ARITY' }
    );
  }
  minted.forEach((d, i) => {
    d.chassis_fqdn = chassisDomains[i].name;
    d.dc_host_key = chassisDomains[i].dc;
  });
  return minted;
}

// ─── Passwords ──────────────────────────────────────────────────────────────

/**
 * Word pools for machine passwords.
 *
 * Words rather than random bytes because these strings are read aloud in class,
 * typed into a console by hand, and pasted into a report. The character set is
 * deliberately narrow: no quote, backslash, backtick, `$`, `%` or brace, because
 * every one of these values is interpolated into JSON, then YAML, then a
 * PowerShell string, and only the JSON layer escapes for you.
 */
const PW_ADJECTIVES = Object.freeze([
  'Basalt', 'Copper', 'Granite', 'Amber', 'Cobalt', 'Cedar', 'Slate', 'Quartz',
  'Onyx', 'Maple', 'Indigo', 'Saffron', 'Cinder', 'Larkspur', 'Marble', 'Juniper',
]);
const PW_NOUNS = Object.freeze([
  'Harbor', 'Lantern', 'Meadow', 'Compass', 'Falcon', 'Terrace', 'Anvil', 'Orchard',
  'Beacon', 'Cavern', 'Prairie', 'Summit', 'Willow', 'Foundry', 'Ridgeline', 'Estuary',
]);
const PW_SYMBOLS = Object.freeze(['!', '#', '@', '+', '=', '?', '-', '_']);

/** The built-in whose name Windows complexity forbids inside a password. */
const DEFAULT_ADMIN_USER = 'administrator';

/**
 * The floor a machine password must clear, DERIVED from the validator's own
 * constants rather than re-spelled.
 *
 * Deliberately above both rules this file has to satisfy, because
 * domain_password is win_domain's safe_mode_password at forest creation — five
 * playbooks before password_policy relaxes anything — and a value that only just
 * clears the default policy is one word-list edit away from not clearing it. If
 * goad-lab-validate ever raises its floor, this follows without an edit.
 */
const MACHINE_PASSWORD_MIN_LEN = Math.max(12, MIN_DOMAIN_PASSWORD_LEN, MIN_LOCAL_ADMIN_PASSWORD_LEN);
const MACHINE_PASSWORD_CLASSES = Math.max(4, REQUIRED_PASSWORD_CLASSES);

/**
 * An avalanche step over hashStr's output, used ONLY where several picks are
 * drawn from one stem and have to be independent of each other.
 *
 * WHY IT IS NEEDED. hashStr is `h = h*31 + c (mod 2^32)`. Modulo 16, 31 is -1,
 * so `h % 16` is nothing more than the alternating sum of the character codes:
 * the low bits carry almost no entropy and, worse, four salts sharing a stem
 * produce four hashes that differ by a constant, so their low bits move in
 * lockstep. Measured on the password generator, that collapsed a nominal
 * 16*16*90*8 = 184,320 keyspace to 720 values, with each adjective bound to
 * exactly ONE noun (16 distinct pairs out of 256) — and this is the string used
 * for win_domain's safe_mode_password, every domain_password and every
 * local_admin_password in the forest. Reordering or re-prefixing the salts does
 * not help; only mixing the high bits down does.
 *
 * Applied HERE rather than inside ai/profile/hash.js on purpose: hashStr is the
 * shared seed for the paper profile as well, and changing it would move every
 * generated company, not just this password. The wider fix belongs upstream.
 */
function mix32(h) {
  let x = h >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  return (x ^ (x >>> 16)) >>> 0;
}

/** hashPick, over the mixed hash. Deterministic, and actually uniform. */
function mixPick(runId, salt, list) {
  return list[mix32(hashStr(runId, salt)) % list.length];
}

/**
 * A machine password: long enough, all four character classes, never containing
 * a token of the admin account name.
 *
 * The retry loop is not decoration: it is what makes a future edit to the word
 * pools fail HERE, deterministically, rather than in dcpromo an hour into a bake.
 */
function makeMachinePassword(runId, salt) {
  for (let attempt = 0; attempt < 8; attempt++) {
    const tag = attempt === 0 ? salt : `${salt}:${attempt}`;
    const pw = ''
      + mixPick(runId, `${tag}:adj`, PW_ADJECTIVES)
      + '-'
      + mixPick(runId, `${tag}:noun`, PW_NOUNS)
      + (10 + (mix32(hashStr(runId, `${tag}:num`)) % 90))
      + mixPick(runId, `${tag}:sym`, PW_SYMBOLS);
    if (pw.length >= MACHINE_PASSWORD_MIN_LEN
      && passwordClasses(pw) >= MACHINE_PASSWORD_CLASSES
      && !containsAccountName(pw, DEFAULT_ADMIN_USER)) {
      return pw;
    }
  }
  throw new LabCompileError(
    'The password word pools can no longer produce a value that satisfies the default Windows '
    + 'policy. Fix the pools — this string is win_domain safe_mode_password and dcpromo rejects it.',
    { code: 'CIAB_PASSWORD_POOL_EXHAUSTED' }
  );
}

/**
 * Passwords for domain users.
 *
 * These are set by ad-data.yml, AFTER password_policy has relaxed the domain, so
 * weak ones are legal — and a handful of genuinely weak ones is the point: they
 * are the spray-and-guess surface the exercise is built on. Upstream does the
 * same thing (`football`, `princess`).
 */
const WEAK_USER_PASSWORDS = Object.freeze([
  'Summer2024', 'Welcome1', 'Password1', 'Changeme1', 'Company123', 'Spring2025', 'Winter2024',
]);

// ─── People ─────────────────────────────────────────────────────────────────

const FIRST_NAMES = Object.freeze([
  'Alice', 'Brian', 'Carla', 'Daniel', 'Elena', 'Felix', 'Grace', 'Hector',
  'Irene', 'Jonas', 'Karen', 'Liam', 'Maria', 'Nathan', 'Olivia', 'Peter',
  'Quinn', 'Rosa', 'Samuel', 'Tina', 'Uma', 'Victor', 'Wendy', 'Xavier',
  'Yara', 'Zach', 'Amara', 'Bruno', 'Chloe', 'Devon', 'Eliza', 'Farid',
  'Gemma', 'Hugo', 'Iris', 'Jamal', 'Kira', 'Lucas', 'Mina', 'Noel',
  'Omar', 'Priya', 'Rafael', 'Sonia',
]);

const SURNAMES = Object.freeze([
  'Abbott', 'Barnes', 'Calder', 'Dawson', 'Ellis', 'Fowler', 'Grant', 'Hoffman',
  'Ibarra', 'Jennings', 'Kaur', 'Lindqvist', 'Mercer', 'Novak', 'Okafor', 'Pratt',
  'Quintana', 'Ramsey', 'Sandoval', 'Tobin', 'Urbina', 'Vance', 'Whitfield', 'Xu',
  'Yates', 'Zamora', 'Ashby', 'Blakely', 'Cortez', 'Delaney', 'Everly', 'Finnegan',
  'Gallagher', 'Hartman', 'Iversen', 'Jaworski', 'Kimura', 'Larsen', 'Moreno',
  'Nakamura', 'Ospina', 'Petrov', 'Rahimi', 'Sorensen',
]);

/** Honorifics and post-nominals that are not part of anybody's logon name. */
const TITLE_RE = /^(dr|mr|mrs|ms|miss|prof|professor|rev|fr|sr|capt|sgt|lt|hon|sir|dame)\.?$/i;
const POSTNOMINAL_RE = /^(jr|sr|ii|iii|iv|v|phd|ph\.d|md|m\.d|dds|cpa|esq|mba|rn|pe|cissp)\.?$/i;

/**
 * Split a stored "First Last" string into { firstname, surname }.
 *
 * TITLES ARE THE WHOLE REASON THIS EXISTS. profile-to-intake.js:69 builds an
 * email as `name.toLowerCase().replace(/\s+/g,'.')`, which turns "Dr. Jane
 * Smith" into `dr..jane.smith` — a title silently promoted to a name component.
 * Doing the same thing to a sAMAccountName produces a logon name with a leading
 * honorific, which is both wrong and one of the few AD mistakes a student
 * notices immediately.
 */
function splitPersonName(fullName) {
  const parts = str(fullName).split(/\s+/).filter(Boolean)
    .filter((t) => !TITLE_RE.test(t))
    .filter((t) => !POSTNOMINAL_RE.test(t.replace(/,$/, '')))
    .map((t) => t.replace(/[,]/g, ''));
  if (parts.length === 0) return { firstname: '', surname: '' };
  if (parts.length === 1) return { firstname: parts[0], surname: parts[0] };
  return { firstname: parts[0], surname: parts[parts.length - 1] };
}

/**
 * sAMAccountName for a person, capped at 20 characters and unique in-domain.
 *
 * The cap is not advisory: roles/onlyusers passes `name: item.key` to
 * win_domain_user, which derives sAMAccountName from it, and win_domain_user
 * FAILS rather than truncating.
 */
function samAccountName(firstname, surname, taken) {
  const f = atom(firstname);
  const l = atom(surname);
  let base = f && l ? `${f}.${l}` : (f || l || 'user');
  if (base.length > MAX_SAM_ACCOUNT_NAME && f && l) base = `${f.slice(0, 1)}.${l}`;
  base = base.slice(0, MAX_SAM_ACCOUNT_NAME).replace(/[.\-_]+$/, '');
  if (!base) base = 'user';
  return uniqueName(base, taken, MAX_SAM_ACCOUNT_NAME);
}

// ─── Departments, groups and OUs ────────────────────────────────────────────

/** A fallback org chart, per sector, for a profile whose breakdown never arrived. */
const DEFAULT_DEPARTMENTS = Object.freeze({
  SMB: ['Operations', 'Sales', 'Finance', 'IT', 'Administration'],
  NonProfit: ['Programs', 'Development', 'Finance', 'Administration'],
  Utility_IT_OT: ['Operations', 'Engineering', 'Customer Service', 'Finance', 'IT'],
  K12: ['Instruction', 'Student Services', 'Business Office', 'Technology', 'Facilities'],
  Library: ['Public Services', 'Technical Services', 'Youth Services', 'Administration'],
});

/**
 * A CN-safe label: no comma, plus, quote, backslash, angle bracket, semicolon or
 * equals, because every one of those is an RDN separator or escape and AD
 * rejects an unescaped occurrence outright.
 */
function cnSafe(name) {
  const cleaned = str(name)
    .replace(/[,+"\\<>;=\r\n\t]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_COMMON_NAME)
    .replace(/^[\s#]+|\s+$/g, '');
  return cleaned;
}

/** How a department becomes a group name. Pure naming, but it varies the file. */
const GROUP_NAME_SCHEMES = Object.freeze(['bare', 'suffix', 'agdlp', 'team']);

function departmentGroupName(dept, scheme) {
  const d = cnSafe(dept);
  if (scheme === 'suffix') return cnSafe(`${d}-Staff`);
  if (scheme === 'agdlp') return cnSafe(`GG-${d.replace(/\s+/g, '')}`);
  if (scheme === 'team') return cnSafe(`${d} Team`);
  return d;
}

/** Operational (non-department) group sets. Picking one varies the group shape. */
const OPS_GROUP_SETS = Object.freeze([
  ['ServerOperators', 'HelpdeskOperators', 'BackupDelegates'],
  ['IT-Admins', 'ServiceDesk', 'VendorAccess'],
  ['Infrastructure', 'AppSupport', 'RemoteWorkers'],
  ['SiteAdmins', 'PrintOperators', 'ContractStaff'],
]);

/** Domain-local resource groups, used when the AGDLP two-tier shape is chosen. */
const RESOURCE_GROUP_SETS = Object.freeze([
  ['DL-FileShare-RW', 'DL-FileShare-RO'],
  ['DL-Finance-Share', 'DL-Reporting-RO'],
  ['DL-AppData-Modify', 'DL-Archive-Read'],
]);

/** OU layouts. All three are shapes upstream actually ships. */
const OU_SCHEMES = Object.freeze(['cn_users', 'flat', 'tiered']);

// ─── Vulnerability and hardening pools ──────────────────────────────────────

/**
 * Candidate roles, by where they make sense.
 *
 * NOTHING IS HARDCODED AS SAFE. Every name below is run through the vendored
 * manifest before it is emitted: an unknown name reaches Ansible as
 * `include_role: name=vulns/<typo>` and kills the play on the lane, and a
 * never_emit name is worse because it reports GREEN having done nothing
 * (`shares` is broken upstream, `adcs_esc7`'s guard is inverted so ManageCA is
 * never granted). The domain-level Ext-ManageCA ACL is the working substitute
 * for the latter, and it belongs to the ACL designer, not here.
 *
 * Roles that need a files/ tree (files, adcs_templates, schedule) are absent on
 * purpose: this composer emits three text files and no binary payload, and
 * goad-lab-validate's MISSING_FILE_DEPENDENCY check would reject them — correctly.
 */
const VULN_POOL_DC = Object.freeze([
  'no_ldap_signing', 'no_ldap_integrity', 'no_ldap_channel_binding',
  'enable_llmnr', 'enable_nbt-ns', 'ntlmdowngrade', 'smbv1', 'administrator_folder',
]);

const VULN_POOL_MEMBER = Object.freeze([
  'openshares', 'smbv1', 'enable_llmnr', 'enable_nbt-ns',
  'administrator_folder', 'enable_credssp_server', 'ntlmdowngrade',
]);

/** Only meaningful on a host in [adcs] — the role configures a live CA. */
const VULN_POOL_ADCS = Object.freeze([
  'adcs_esc6', 'adcs_esc11', 'adcs_esc10_case1', 'adcs_esc10_case2', 'adcs_esc15',
]);

const SECURITY_POOL_DC = Object.freeze(['enable_run_as_ppl', 'maq0_server', 'powershell_restrict']);
const SECURITY_POOL_MEMBER = Object.freeze(['maq0_client', 'powershell_restrict']);

/** Defensive postures, in ascending order of how much the lab fights back. */
const POSTURES = Object.freeze(['soft', 'mixed', 'hardened']);

/**
 * Drop anything the manifest does not know, or knows is broken.
 *
 * Asks the manifest rather than carrying a copy of the never_emit list, because
 * the list is a property of the pinned GOAD ref and a second copy of it here
 * would go stale the moment the pin moves.
 */
function manifestSafe(names, kind) {
  return names.filter((name) => {
    const role = getRole(name, kind);
    if (!role) return false;
    return !isNeverEmit(name, kind);
  });
}

/**
 * `vulns` is a literal execution order — vulnerabilities.yml loops the array in
 * place — and `permissions` ACLs a folder `directory` creates. Sorting by a
 * fixed rank means a future pool edit cannot reintroduce ROLE_ORDER.
 */
const ROLE_RANK = Object.freeze({ directory: 0, files: 1, permissions: 90, schedule: 91 });

function orderVulns(names) {
  return names
    .map((name, i) => ({ name, i }))
    .sort((a, b) => {
      const ra = ROLE_RANK[a.name] === undefined ? 50 : ROLE_RANK[a.name];
      const rb = ROLE_RANK[b.name] === undefined ? 50 : ROLE_RANK[b.name];
      return ra === rb ? a.i - b.i : ra - rb;
    })
    .map((e) => e.name);
}

// ─── The machines the paper already names ───────────────────────────────────

/**
 * WHICH SIDE OWNS A FOREST HOSTNAME — AND WHY IT IS THE PROFILE, NOT THIS FILE.
 *
 * This composer used to mint every hostname off the company name (HARBOR-DC01,
 * TUC-SRV02) with nothing anywhere consulting the client's own asset register.
 * That is not a cosmetic difference, it is two estates:
 *
 *   the paper   ai/profile emits the servers deterministically from org-sizing
 *               (prompts.js roles[] -> a hostname theme), and the scan report,
 *               the asset register and the topology diagram all PRINT those
 *               names. A student nmaps DC-01 because a document told them to.
 *   the lane    profile-to-spec builds spec.vms[].name straight from
 *               asset.hostname, so the machine that boots is called DC-01 too.
 *
 * A forest whose hosts are called something else is therefore a forest that
 * corresponds to nothing a student was handed — and mechanically it is worse
 * than that: the bake's golden templates are named after the STAGING lane's
 * machines, so a bake minted as HARBOR-DC01 and a deploy synthesized as DC-01
 * can never match, and profile-deploy refuses the deploy with
 * BAKE_GOLDEN_UNMATCHED. One side has to derive from the other, and it must be
 * this one: the paper is already printed, and the names in it are the exercise.
 *
 * The mint stays as the FALLBACK, for the client whose register names fewer
 * Windows servers than the tier's forest has hosts (or none at all, which is
 * every hand-written fixture). A minted name is a machine no document mentions,
 * so it is warned about rather than silently accepted.
 */

/**
 * Is this asset the paper's domain controller?
 *
 * IMPORTED, NOT RE-DERIVED. isDcRecord is the same function S-01/S-02 use to
 * strip and trim DCs off the very same register, so a second opinion here would
 * put a machine in the forest as a DC that the paper had already demoted — or
 * leave one out that the paper had kept. It used to be mirrored into this file
 * byte for byte under a comment forbidding anyone to re-derive it, and the two
 * copies then had to be widened together to recognise the controller names a
 * real client actually types (SVO-DC01, HQDC1, ADDC01), which is the point at
 * which a comment stops being enough. ai/profile/dc-name.js carries the
 * predicate and the reasoning behind each of its boundaries; it requires
 * nothing, so it costs this module's load profile nothing and cannot cycle.
 *
 * The asset's `function` sentence is NOT consulted, even though it is where a
 * network asset spells out what validators.js reads as a server's role. It is
 * LLM-authored prose, and the two errors are not symmetrical: a false positive
 * quietly makes the file server a domain controller while the documents call it
 * a file server, and a false negative leaves the pool short, which is warned
 * about by name and refused at deploy.
 */
const isPaperDc = isDcRecord;

/**
 * A name that can be used VERBATIM as a Windows computer name.
 *
 * Verbatim is the whole point: uniqueName() truncates to fit, and a truncated
 * paper name (FRONTIER-DC-01 -> FRONTIER-DC-0) is a machine the documents do
 * not name either — so a candidate that does not already satisfy the
 * validator's own two rules is refused here and the mint is used instead.
 */
function usableAsHostname(name) {
  const s = str(name);
  return s.length > 0 && s.length <= MAX_NETBIOS_HOSTNAME && /^[A-Za-z0-9-]+$/.test(s);
}

/**
 * The client's own Windows servers, split into the two pools the chassis binds
 * against: controllers and members.
 *
 * WEB SERVERS ARE EXCLUDED, through profile-to-spec's OWN predicate rather than
 * a second copy of it. Every asset isWebServer() says yes to is forced onto
 * Linux by the synthesizer and becomes the lane's dual-homed DMZ host — so a
 * web asset adopted as a forest hostname would be a machine that is a Windows
 * domain member on one side and a Linux pivot on the other, and the two facts
 * would only meet on a lane.
 *
 * @returns {{dcs: string[], members: string[]}} in register order, deduplicated
 */
function paperForestNames(facts, warnings) {
  const assets = arr(facts.assets);
  const pools = { dcs: [], members: [] };
  if (assets.length === 0) return pools;

  // Lazily required so this module keeps its "reads the chassis and nothing
  // else" load profile — profile-to-spec pulls the template and vuln-script
  // resolvers in behind it, and every compile-only caller would pay for them.
  // eslint-disable-next-line global-require
  const { isWebServer } = require('./profile-to-spec');

  const seen = new Set();
  for (const raw of assets) {
    const asset = obj(raw);
    if (str(asset.role).toLowerCase() !== 'server') continue;
    if (!/windows/i.test(str(asset.os))) continue;
    if (isWebServer(asset)) continue;
    const hostname = str(asset.hostname);
    if (!hostname || seen.has(hostname.toLowerCase())) continue;
    if (!usableAsHostname(hostname)) {
      warnings.push({
        code: 'CIAB_PAPER_HOSTNAME_UNUSABLE',
        message: `The asset register names a Windows server '${hostname}', which cannot be a `
          + `Windows computer name (max ${MAX_NETBIOS_HOSTNAME} characters, [A-Za-z0-9-] only). `
          + 'The forest host that would have carried it gets a generated name instead, so the lab '
          + 'and the documents disagree about that one machine.',
      });
      continue;
    }
    seen.add(hostname.toLowerCase());
    (isPaperDc(asset) ? pools.dcs : pools.members).push(hostname);
  }
  return pools;
}

/**
 * host key -> the last octet the provider inventory addresses it at.
 *
 * READ, NEVER INVENTED. `providers/proxmox/inventory` is emitted verbatim from
 * the chassis (only the banner comments are rewritten), and every playbook
 * reaches a host at `{{ip_range}}.<octet>` from that file. The bake's staging
 * lane has to place each machine on exactly that octet or ansible connects to
 * an address nothing answers on — so the octet is a fact ABOUT the host, and it
 * travels on the IR beside the hostname rather than being re-derived by
 * whoever builds the spec.
 */
function parseProviderOctets(providerText) {
  const out = {};
  const re = /^\s*(\S+)\s+ansible_host=\{\{\s*ip_range\s*\}\}\.(\d{1,3})\b/;
  for (const line of String(providerText || '').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith(';') || trimmed.startsWith('#') || trimmed.startsWith('[')) continue;
    const m = re.exec(line);
    if (m) out[m[1]] = Number(m[2]);
  }
  return out;
}

// ─── The composer ───────────────────────────────────────────────────────────

/** Read one chassis off disk. Throws loudly — there is no degraded mode. */
function loadChassis(tier) {
  if (TIERS.indexOf(tier) === -1) {
    throw new LabCompileError(`Unknown tier '${tier}'; expected one of ${TIERS.join(', ')}`, {
      code: 'CIAB_UNKNOWN_TIER',
    });
  }
  const dir = path.join(CHASSIS_DIR, tier);
  const provenance = JSON.parse(fs.readFileSync(path.join(dir, 'chassis.json'), 'utf8'));
  const configText = fs.readFileSync(path.join(dir, 'data', 'config.json'), 'utf8');
  const inventoryText = fs.readFileSync(path.join(dir, 'data', 'inventory'), 'utf8');
  const providerText = fs.readFileSync(path.join(dir, 'providers', 'proxmox', 'inventory'), 'utf8');
  const playbooksPath = path.join(dir, 'playbooks.yml');
  const playbooksText = fs.existsSync(playbooksPath) ? fs.readFileSync(playbooksPath, 'utf8') : null;
  // Tolerant read: a chassis is JSON today, but the labs they are carved from
  // are YAML-flavoured and a re-sync could carry a trailing comma across.
  const { lab } = parseLabConfig(configText, { source: `chassis ${tier} data/config.json` });
  return {
    tier, dir, provenance, lab, inventoryText, providerText, playbooksText,
    octets: parseProviderOctets(providerText),
  };
}

/**
 * Rewrite an Ansible INI inventory: replace whole group memberships, leaving
 * every comment, blank line and [all:vars] block exactly where the chassis put
 * them.
 *
 * A TEXT REWRITE, not a re-render, for the same reason mergePlaybooksYaml is a
 * text splice: the chassis inventory is full of load-bearing comments (which
 * playbook consumes each group, which groups are mandatory) and a round trip
 * through parse/serialise would throw all of it away.
 */
function rewriteInventoryGroups(text, overrides) {
  const out = [];
  let current = null;
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    const header = /^\[([^\]]+)\]$/.exec(trimmed);
    if (header) {
      const name = header[1];
      const isMeta = name.endsWith(':vars') || name.endsWith(':children');
      current = isMeta ? null : name;
      out.push(line);
      if (current && Object.prototype.hasOwnProperty.call(overrides, current)) {
        for (const host of overrides[current]) out.push(host);
      }
      continue;
    }
    const overridden = current && Object.prototype.hasOwnProperty.call(overrides, current);
    // Comments and blank lines survive an override; host lines do not.
    if (overridden && trimmed !== '' && !trimmed.startsWith(';') && !trimmed.startsWith('#')) continue;
    out.push(line);
  }
  return out.join('\n');
}

/**
 * Drop the contiguous comment block that carries the CHASSIS PLACEHOLDER note.
 *
 * That block is an instruction TO this compiler ("rewrite domain_name"). Leaving
 * it in an emitted lab would tell whoever opens it that the work still has to be
 * done, and would leak the word CHASSIS into a file whose whole point is that no
 * placeholder survives.
 */
function dropPlaceholderComments(text) {
  const out = [];
  let dropping = false;
  for (const line of String(text).split(/\r?\n/)) {
    const trimmed = line.trim();
    const isComment = trimmed.startsWith(';') || trimmed.startsWith('#');
    if (isComment && /CHASSIS PLACEHOLDER/i.test(trimmed)) { dropping = true; continue; }
    if (dropping && isComment) continue;
    dropping = false;
    out.push(line);
  }
  return out.join('\n');
}

/**
 * Compile a profile into a lab.
 *
 * @param {object} profile               a CiAB profile (DB row, json_data, or flat)
 * @param {object} [opts]
 * @param {object} [opts.chain]          the ACL designer's chain, lowered into the IR as-is
 * @param {object} [opts.acls]           { '<fqdn>': { '<label>': {for,to,right,inheritance} } }
 * @param {object} [opts.footholdCredential] overrides the composer-minted foothold
 * @returns {{ ir: object, files: object, chain: string[], tier: string,
 *             reason: string, sizing: object, warnings: object[] }}
 */
function compileLab(profile, opts) {
  const options = obj(opts);
  const facts = readProfile(profile);
  const { tier, reason, sizing } = selectTier(facts);
  const runId = facts.runId;
  const chassis = loadChassis(tier);
  const warnings = [];

  const labName = `CIAB-${hashStr(runId, 'goad-lab-name').toString(16).padStart(8, '0')}`;
  const domains = mintDomains(facts, tier, chassis.provenance.topology);
  const byChassisFqdn = new Map(domains.map((d) => [d.chassis_fqdn, d]));

  // ── hosts ────────────────────────────────────────────────────────────────
  // Start from the chassis lab dict and rewrite in place. Anything the chassis
  // carries that this composer does not understand (use_laps, future keys)
  // survives untouched, which is the property that makes a re-sync a diff rather
  // than a rewrite.
  const lab = clone(chassis.lab);
  const chassisInventory = parseInventory(chassis.inventoryText);
  const invGroup = (name) => arr(chassisInventory.groups[name]);

  // The naming convention is a lab-wide choice, not a per-host one — every
  // estate names its machines one way, and mixing the schemes on one lab is the
  // tell that a generator wrote it.
  const hostnameScheme = hashPick(runId, 'hostname-scheme', ['dash', 'flat', 'site']);
  const companyCode = shortCode(companySlug(facts.companyName), 9);
  const cityAtom = atom(facts.hqCity);
  const siteCode = cityAtom ? netbiosCandidate(cityAtom.slice(0, 3)) : companyCode;
  // '-SRV02' is the longest suffix any chassis host key produces, so 9 leaves
  // the prefix exactly inside the 15-character NetBIOS cap.
  const hostPrefix = hostnameScheme === 'site' ? siteCode.slice(0, 4) : companyCode;

  const hostnamesTaken = new Set();
  const hostnameByChassisHostname = {};
  const hostKeys = Object.keys(lab.hosts);
  const irHosts = [];

  // The client's own machines, first claim. See "WHICH SIDE OWNS A FOREST
  // HOSTNAME" above: the mint below is now the fallback, not the rule.
  const paper = paperForestNames(facts, warnings);

  for (const key of hostKeys) {
    const host = lab.hosts[key];
    const domain = byChassisFqdn.get(str(host.domain));
    if (!domain) {
      throw new LabCompileError(
        `Tier ${tier} chassis host '${key}' claims domain '${host.domain}', which the composer `
        + 'never minted a replacement for. The chassis topology and its config.json disagree.',
        { code: 'CIAB_CHASSIS_DOMAIN_UNMAPPED' }
      );
    }
    // The chassis host key already encodes the role (dc01, srv02); reuse its
    // numeric tail so the emitted hostname lines up with the inventory and the
    // provider octets a reader is looking at next to it.
    const suffix = key.toUpperCase();
    const minted = hostnameScheme === 'flat' ? `${hostPrefix}${suffix}` : `${hostPrefix}-${suffix}`;
    // A controller takes a controller's name and a member takes a member's, so
    // the file server on the paper does not become a domain controller on the
    // lane. When the pool runs dry the mint is used and SAID so: a forest host
    // no document names is a machine a student cannot have been briefed on, and
    // it is also the machine a deploy will refuse over (BAKE_GOLDEN_UNMATCHED),
    // so the reason has to be visible on the bake rather than only at deploy.
    const isDcHost = str(host.type) === 'dc';
    const claimed = (isDcHost ? paper.dcs : paper.members).shift() || null;
    if (!claimed) {
      warnings.push({
        code: 'CIAB_LAB_HOST_NOT_ON_PAPER',
        message: `The forest needs a ${isDcHost ? 'domain controller' : 'member server'} for chassis `
          + `host '${key}', and ${facts.companyName}'s asset register names no `
          + `${isDcHost ? 'domain controller' : 'Windows server'} left to be it — so it is called `
          + `'${minted}', which appears in no document the student is given. A deploy of this client `
          + 'will then refuse that machine\'s golden template, because its spec has no machine of '
          + 'that name. Add the server to the profile and re-bake.',
      });
    }
    const hostname = uniqueName(claimed || minted, hostnamesTaken, MAX_NETBIOS_HOSTNAME);
    hostnameByChassisHostname[str(host.hostname)] = hostname;

    host.hostname = hostname;
    host.domain = domain.fqdn;
    host.path = rootDnForDomain(domain.fqdn);
    host.local_groups = {};
    host.scripts = [];
    host.vulns = [];
    host.vulns_vars = {};
    host.security = [];
    host.security_vars = {};

    // The octet the emitted provider inventory addresses this host at. Carried
    // on the IR because the machine has to BE there: the bake stands a staging
    // lane from this IR and then runs the chain over that same inventory, so a
    // spec built without the octet — or with a different one — is a lane whose
    // ansible connects to an address nothing answers on, ninety minutes of
    // unreachable hosts. Refused rather than defaulted: a chassis whose provider
    // file stopped naming a host is a chassis that has drifted from its own
    // config.json, and guessing an octet here would collide with a sibling.
    const ipOctet = chassis.octets[key];
    if (!Number.isInteger(ipOctet) || ipOctet < 2 || ipOctet > 254) {
      throw new LabCompileError(
        `Tier ${tier} chassis host '${key}' has no usable octet in providers/proxmox/inventory `
        + `(read ${JSON.stringify(ipOctet)}). That file is what every playbook reaches the host `
        + 'through, and it is what a bake addresses the staging machine at — the two cannot be '
        + 'allowed to disagree, so this refuses rather than inventing one.',
        { code: 'CIAB_CHASSIS_NO_OCTET', host_key: key }
      );
    }

    irHosts.push({
      key,
      hostname,
      type: str(host.type),
      domain: domain.fqdn,
      path: host.path,
      ipOctet,
      roles: [],
      // Filled by placePayload. Declared here so the shape is the same whether
      // or not a host ends up carrying either.
      local_admins: [],
      cached_credentials: [],
    });
  }

  // ── THE OTHER DIRECTION OF THE SAME MISMATCH ─────────────────────────────
  //
  // Above, the register ran SHORT and the forest minted a hostname no document
  // names — which is warned about and then refused at deploy
  // (BAKE_GOLDEN_UNMATCHED), so it cannot pass quietly.
  //
  // A register that is LONGER than the chassis has hosts fails the other way and
  // used to fail SILENTLY. The surplus servers still reach the lane: the
  // synthesizer builds a spec machine for every selected asset, and one that the
  // baked forest does not name simply clones the STOCK catalog image. Nothing
  // refuses it — deployLabDefFromBake only looks at machines the forest DOES
  // name, and prepareGoadMacs exempts the rest — so a machine the scan report,
  // the asset register and the topology diagram all call a DOMAIN CONTROLLER
  // boots as a workgroup Windows box with no account in the directory, and the
  // lane reports active. That is the same silent divergence the mint warning
  // exists to prevent, in reverse, so it is said out loud in the same place.
  //
  // A WARNING RATHER THAN A REFUSAL. A surplus MEMBER server is a defensible
  // environment — a standalone file server that was never domain-joined is a
  // thing real companies have — and the tier ladder is driven by org-sizing, not
  // by the register's length, so this is regularly the correct outcome. A
  // surplus CONTROLLER never is, and it is named separately for that reason.
  {
    const leftoverDcs = paper.dcs.slice();
    const leftoverMembers = paper.members.slice();
    if (leftoverDcs.length > 0 || leftoverMembers.length > 0) {
      const listed = leftoverDcs.map((n) => `${n} (a domain controller on paper)`)
        .concat(leftoverMembers).join(', ');
      warnings.push({
        code: 'CIAB_PAPER_SERVER_NOT_IN_FOREST',
        message: `${facts.companyName}'s asset register names ${leftoverDcs.length + leftoverMembers.length} `
          + `Windows server(s) the tier-${tier} forest has no host for: ${listed}. A deploy still `
          + 'builds them — from the STOCK catalog image, with no account in the baked directory — so '
          + 'they come up as workgroup machines while the documents describe them as domain members'
          + (leftoverDcs.length > 0
            ? ', and one of them is a machine the paper calls a domain controller, which a student '
              + 'will scan, find no LDAP on, and read as their own mistake'
            : '')
          + '. Deselect them for this engagement, or edit the register so the paper and the forest '
          + 'describe the same estate.',
      });
    }
  }

  // ── domains: rename the keys, keep the order and every key they carried ──
  const renamed = {};
  for (const [chassisFqdn, block] of Object.entries(lab.domains)) {
    const domain = byChassisFqdn.get(chassisFqdn);
    const rootDn = rootDnForDomain(domain.fqdn);
    block.netbios_name = domain.netbios;
    block.trust = domain.trust_fqdn || '';
    block.laps_path = `OU=Laps,${rootDn}`;
    block.domain_password = makeMachinePassword(runId, `domain-pw:${domain.fqdn}`);
    block.organisation_units = {};
    block.groups = { universal: {}, global: {}, domainlocal: {} };
    block.multi_domain_groups_member = {};
    block.acls = {};
    block.users = {};
    if (block.ca_server !== undefined) {
      // ca_server names a HOSTNAME, not a host key (adcs.yml:29 feeds it to
      // ca_host). Rewriting it through the hostname map keeps it pointed at the
      // same machine the chassis pointed at, whatever we renamed that machine to.
      block.ca_server = hostnameByChassisHostname[block.ca_server] || block.ca_server;
    }
    renamed[domain.fqdn] = block;
    domain.rootDn = rootDn;
  }
  lab.domains = renamed;

  // ── the password invariants ──────────────────────────────────────────────
  // A DC's local Administrator password IS its domain password: the DC is
  // promoted with its local credential and every child dcpromo re-uses it, so a
  // mismatch fails the promotion with an authentication error that names neither
  // field. A member host carries its OWN domain's password, which is what the
  // proven labs do (chassis.json records it as a kept invariant).
  for (const key of hostKeys) {
    const host = lab.hosts[key];
    host.local_admin_password = lab.domains[host.domain].domain_password;
  }

  // ── principals ───────────────────────────────────────────────────────────
  const ouScheme = hashPick(runId, 'ou-scheme', OU_SCHEMES);
  const groupScheme = hashPick(runId, 'group-scheme', GROUP_NAME_SCHEMES);
  const opsGroups = hashPick(runId, 'ops-groups', OPS_GROUP_SETS);
  const useResourceGroups = groupScheme === 'agdlp' || hashCoin(runId, 'resource-groups', 40);
  const resourceGroups = useResourceGroups ? hashPick(runId, 'resource-set', RESOURCE_GROUP_SETS) : [];

  const departments = buildDepartments(facts, sizing);

  // ── the Domain Admins declaration ────────────────────────────────────────
  // Every code path that puts a principal into a privileged group calls
  // declareAdmin() at the point of the decision, so the declaration and the
  // decision cannot drift. assertAdminsDeclared() below then re-derives the same
  // set from the emitted lab by a different route and refuses on any difference.
  const declaredAdmins = new Map();
  const demoted = demotionSet(options.demoteAdmins);
  const declareAdmin = (sam, domainFqdn, via) => {
    const key = `${domainFqdn}\\${principalKey(sam)}`;
    if (declaredAdmins.has(key)) return;
    // Reason defaults to roster_realism and is upgraded below only for the
    // principal the supplied chain actually ENDS at. The composer does not get
    // to call its own admins intentional by assertion.
    declaredAdmins.set(key, { sam: str(sam), domain: domainFqdn, reason: 'roster_realism', via });
  };
  const isDemoted = (sam) => demoted.has(principalKey(sam));

  // Services are placed BEFORE the roster, not after: which host runs SQL and
  // which runs IIS decides which service accounts exist and what their SPNs
  // point at, and an SPN naming a host that does not run the service is a
  // finding made of scenery.
  const services = placeServices({ runId, lab, invGroup });
  const principals = populatePrincipals({
    runId, facts, sizing, tier, lab, domains, departments,
    ouScheme, groupScheme, opsGroups, resourceGroups, services, warnings,
    declareAdmin, isDemoted,
  });

  // The design's decisions ABOUT principals — the foothold password, a roasted
  // account's SPN and wordlist password, a leaked description — are applied
  // BEFORE the payload is planted, because placePayload() caches user passwords
  // on hosts and attachMssql() names a sysadmin. Applying them afterwards would
  // leave a cached credential carrying the pre-design password, which is a
  // lateral-movement primitive that silently does not work.
  applyPrincipalOverrides({ lab, principals, overrides: options.principalOverrides, labName });

  const posture = hashPick(runId, 'posture', POSTURES);
  placePayload({
    runId, lab, hostKeys, services, posture, principals, irHosts, declareAdmin, isDemoted,
  });

  // ── the ACL designer's half, lowered if it was handed to us ──────────────
  const acls = obj(options.acls);
  for (const [fqdn, block] of Object.entries(acls)) {
    if (!lab.domains[fqdn]) {
      throw new LabCompileError(
        `The ACL designer supplied ACLs for domain '${fqdn}', which this lab does not declare `
        + `(declared: ${Object.keys(lab.domains).join(', ')}). ad-acl.yml resolves `
        + 'lab.domains[domain].acls, so an entry under an unknown domain is never planted.',
        { code: 'CIAB_ACL_DOMAIN_UNKNOWN' }
      );
    }
    lab.domains[fqdn].acls = clone(block);
  }

  const foothold = resolveFoothold({
    runId, lab, domains, principals, services,
    supplied: options.footholdCredential,
  });

  // ── the declaration, checked and reasoned ────────────────────────────────
  assertAdminsDeclared(lab, declaredAdmins, labName);
  // 'chain_terminus' is claimable only for the principal the supplied chain
  // actually ends at: taking that account IS the exercise, so being reachable is
  // the point rather than the problem. Everything else stays 'roster_realism'
  // and stays subject to the designer's shorter-path gate — including a member
  // of a group that is the terminus, because the group being the endgame does
  // not make its members free to take in two hops.
  const terminusKey = principalKey(str(obj(obj(options.chain).objective).target));
  const declaredAdminList = Array.from(declaredAdmins.values()).map((a) => ({
    sam: a.sam,
    domain: a.domain,
    via: a.via,
    reason: terminusKey && principalKey(a.sam) === terminusKey ? 'chain_terminus' : 'roster_realism',
  })).sort((a, b) => (a.domain.localeCompare(b.domain) || a.sam.localeCompare(b.sam)));

  const ir = {
    run_id: runId,
    tier,
    lab_name: labName,
    domains: domains.map((d) => ({
      fqdn: d.fqdn,
      netbios: d.netbios,
      dc_host_key: d.dc_host_key,
      is_forest_root: d.is_forest_root,
      parent_fqdn: d.parent_fqdn,
      trust_fqdn: d.trust_fqdn,
    })),
    hosts: irHosts,
    principals: Object.assign({}, principals.ir, { declared_admins: declaredAdminList }),
    chain: normalizeChain(options.chain),
    acls: Object.fromEntries(Object.entries(lab.domains).map(([fqdn, d]) => [fqdn, clone(d.acls)])),
    foothold_credential: foothold,
  };

  assertFootholdHonoured(ir);

  // ── emit ─────────────────────────────────────────────────────────────────
  const files = emitTree({ chassis, lab, labName, domains, services, posture, hostKeys });
  const chain = chassis.playbooksText
    ? (chainForLab(chassis.playbooksText, `CHASSIS-${tier}`) || DEFAULT_CHAIN.slice())
    : DEFAULT_CHAIN.slice();

  // Both checkers' WARNINGS travel with the result rather than being swallowed.
  // A warning here is by definition a silent no-op on the lane — an ACL edge no
  // principal can exercise, a LAPS group with no laps_path — and silence is the
  // one outcome this pipeline treats as worse than a crash.
  // GENERATED MODE IS SCOPED TO THE PASS THAT SHIPS, and the caller says so
  // explicitly rather than it being inferred from `options.chain`.
  //
  // Two things make inference wrong here. normalizeChain(undefined) returns the
  // all-null shape rather than null, so `ir.chain` is always truthy and cannot
  // distinguish the passes at all. And `options.chain` is too broad in the other
  // direction: compileLab is called directly with a PARTIAL chain — a `start`
  // and nothing else — to exercise the foothold-planting rules in isolation, and
  // holding a fragment to the whole-lab rules would refuse a lab nobody was
  // going to ship. compileLabWithChain's own first pass is the same story from
  // the other side: it compiles with no chain deliberately, because that draft
  // is what the designer reasons over.
  //
  // So the flag is set in exactly one place — compileLabWithChain's FINAL
  // compileLab, the artifact the bake route pushes — which is the boundary the
  // hole actually lived at.
  warnings.push(...assertEmitted({
    files, labName, chassis, lab, chain, ir, generated: options.assertGenerated === true,
  }));

  return {
    ir,
    files,
    chain,
    tier,
    reason,
    sizing,
    warnings,
    run_id: runId,
    declared_admins: declaredAdminList,
    demoted_admins: Array.from(demoted),
  };
}

/**
 * Apply the designer's decisions ABOUT principals back onto the roster.
 *
 * WHY THE COMPOSER HAS TO DO THIS AND NOT THE CALLER. The design picks the
 * foothold's password, the wordlist password on a roasted account and the SPN
 * that makes it roastable. Those live in `lab.domains[*].users[sam]`, which only
 * this module writes — so a caller that merged them into the IR alone would ship
 * a config.json where AD is built with one password and the website hands out
 * another. Both halves green, the login broken, nothing anywhere says so. That
 * is the exact seam assertFootholdHonoured() exists to close, and it can only
 * close if the override lands on the emitted lab as well as on the IR.
 *
 * Refuses an override naming a principal the lab does not create, for the same
 * reason: a silently ignored override is a password mismatch with extra steps.
 */
function applyPrincipalOverrides(ctx) {
  const { lab, principals, labName } = ctx;
  const overrides = obj(ctx.overrides);
  // Only the fields that are genuinely a design decision about the account. A
  // wider patch surface would let the designer rewrite `groups`, which is how
  // the two halves would start disagreeing about who is a Domain Admin.
  const PATCHABLE = ['password', 'spns', 'description'];

  for (const [fqdn, bySam] of Object.entries(overrides)) {
    const block = lab.domains[fqdn];
    if (!block) {
      throw new LabCompileError(
        `${labName}: a principal override was supplied for domain '${fqdn}', which this lab does `
        + `not declare (declared: ${Object.keys(lab.domains).join(', ')}).`,
        { code: 'CIAB_PRINCIPAL_OVERRIDE_DOMAIN_UNKNOWN' }
      );
    }
    for (const [sam, patch] of Object.entries(obj(bySam))) {
      const user = block.users[sam];
      if (!user) {
        throw new LabCompileError(
          `${labName}: a principal override names '${sam}' in '${fqdn}', which this lab does not `
          + 'create. The design decided something about an account the forest never builds, and '
          + 'silently dropping it is how the website and the directory end up with two different '
          + 'passwords.',
          { code: 'CIAB_PRINCIPAL_OVERRIDE_UNKNOWN', sam, domain: fqdn }
        );
      }
      const irUser = principals.ir.users.find((u) => u.sam === sam && u.domain === fqdn);
      const domainEntry = principals.byDomain.find((d) => d.fqdn === fqdn);
      const rosterEntry = domainEntry && domainEntry.users.find((u) => u.sam === sam);
      const serviceEntry = domainEntry && domainEntry.serviceAccounts.find((s) => s.sam === sam);
      for (const key of PATCHABLE) {
        if (obj(patch)[key] === undefined) continue;
        const value = clone(patch[key]);
        // An empty spns array is a key win_domain_user would iterate over
        // nothing; the composer's own convention is to omit it entirely.
        if (key === 'spns' && arr(value).length === 0) delete user.spns;
        else user[key] = value;
        if (irUser) irUser[key] = clone(value);
        if (rosterEntry && key === 'password') rosterEntry.password = value;
        if (serviceEntry && key === 'password') serviceEntry.password = value;
      }
    }
  }
}

// ─── The composer/designer negotiation ──────────────────────────────────────

/** How many times the composer will demote and re-emit before giving up. */
const MAX_NEGOTIATION_ROUNDS = 8;

/**
 * The principal fields the design decided, keyed the way compileLab wants them.
 *
 * Every `onlyusers` producer in the design — the entry's ad_password and
 * ad_description plants, a kerberoast edge's SPN and wordlist password, a
 * targeted-roast prerequisite — is a decision about a user OBJECT. Collecting
 * them here rather than letting each half re-derive its own copy is what stops
 * AD being built with one password while the website hands out another.
 */
function principalOverridesFromDesign(design) {
  const chain = obj(design.chain);
  const foothold = obj(design.foothold_credential);
  const fqdn = str(chain.domain) || str(foothold.domain);
  const out = {};
  if (!fqdn) return out;
  out[fqdn] = {};
  const put = (role, item, vars) => {
    if (role !== 'onlyusers') return;
    const sam = str(item);
    if (!sam) return;
    out[fqdn][sam] = Object.assign({}, out[fqdn][sam], obj(vars));
  };
  for (const plant of arr(obj(chain.start).plants)) put(plant.role, plant.item, plant.item_vars);
  for (const edge of arr(chain.edges).concat(arr(chain.decoys))) {
    const by = obj(edge.created_by);
    put(by.role, by.item, by.item_vars);
    for (const pre of arr(edge.prerequisites)) put(pre.role, pre.item, pre.item_vars);
  }
  // The foothold password last and unconditionally: it is the seam, and it wins
  // over anything else that claimed the same account.
  if (foothold.sam) {
    out[fqdn][str(foothold.sam)] = Object.assign(
      {}, out[fqdn][str(foothold.sam)], { password: str(foothold.password) });
  }
  return out;
}

/**
 * Compile a profile into a lab that carries a PROVEN attack chain.
 *
 * This is the whole composer/designer contract in one function, and it exists
 * because neither half can close it alone:
 *
 *   1. the composer emits a lab and declares every privileged principal in it;
 *   2. the designer designs a chain over that lab and verifies the declaration —
 *      no 'roster_realism' admin may be reachable more cheaply than the intended
 *      path;
 *   3. when one is, the FIX IS THE COMPOSER'S: demote that principal out of the
 *      privileged group and re-emit. The designer must not widen its own check
 *      to make the failure go away, because that check is the entire reason a
 *      three-admin company is safe to ship.
 *
 * Bounded at MAX_NEGOTIATION_ROUNDS and deterministic under a fixed run_id: the
 * demotion set only ever grows, each round is a pure function of it, and a round
 * that learns nothing new stops the loop rather than spinning. Failure names the
 * principal, the short path found and the intended chain length — the three
 * facts somebody needs to decide whether the lab or the profile is wrong.
 *
 * ON THE STATE OF THE WORLD, HONESTLY: across 1,500 realistic profiles the
 * demotion branch never fires. Once the designer stopped binding declared admins
 * to chain nodes and stopped pointing decoys at them, the composer's own data
 * leaves no roster admin within reach of the foothold — the forest root carries
 * only its DC, and that DC's local administrators are themselves declared. The
 * negotiation is therefore a GUARD rather than a routine step, which is exactly
 * why it is written, driven and tested rather than assumed: the first composer
 * change that plants a credential differently will need it to work.
 *
 * @param {object} [opts.designer] the designer to negotiate with. Defaults to
 *        goad-attack-chain.designAttackChain. Substitutable so the demotion
 *        branch can be driven against a designer that reports a cheap admin —
 *        see the note above about why realistic input does not.
 * @returns compileLab's result, plus `chain_design` (the full designed chain)
 *          and `negotiation` (what was demoted and why).
 */
function compileLabWithChain(profile, opts) {
  const options = obj(opts);
  const maxRounds = Math.max(1, Number(options.maxNegotiationRounds) || MAX_NEGOTIATION_ROUNDS);
  const demoted = demotionSet(options.demoteAdmins);
  const design = typeof options.designer === 'function' ? options.designer : designAttackChain;
  const rounds = [];

  for (let round = 0; round < maxRounds; round += 1) {
    const draft = compileLab(profile, {
      demoteAdmins: Array.from(demoted),
      footholdCredential: options.footholdCredential,
      // A caller-pinned password or SPN has to be visible to the DESIGN, not
      // just to the final emit: the designer reasons about password reuse and
      // about who can reach whom, and a pin it never saw is a pin it could not
      // account for.
      principalOverrides: options.principalOverrides,
    });
    let designed;
    try {
      designed = design(draft.ir, { runId: draft.run_id });
    } catch (err) {
      const cheap = arr(err.findings).filter((f) => f.code === 'SHORTCUT_ADMIN_TOO_CHEAP');
      const fresh = cheap.map((f) => principalKey(f.principal))
        .filter((k) => k && !demoted.has(k));
      if (fresh.length > 0 && round + 1 < maxRounds) {
        // The negotiation step. Demoting is a real change to the org chart, so
        // it is recorded rather than done quietly: an instructor reading the
        // answer key should be able to see that this client has two DAs instead
        // of three because the third could be taken in two hops.
        fresh.forEach((k) => demoted.add(k));
        rounds.push({
          round,
          demoted: fresh.slice(),
          findings: cheap.map((f) => ({
            principal: f.principal,
            hops: f.hops,
            designed_hops: f.designed_hops,
            path: f.path,
          })),
        });
        continue;
      }
      if (cheap.length > 0) {
        const f = cheap[0];
        throw new LabCompileError(
          `${draft.ir.lab_name}: after ${round + 1} negotiation round`
          + `${round === 0 ? '' : 's'} the composer could not place a roster Domain Admin that `
          + `the designed chain does not short-circuit. '${f.principal}' is reachable in `
          + `${f.hops} hop${f.hops === 1 ? '' : 's'} (${arr(f.path).join(' -> ')}) while the `
          + `intended chain is ${f.designed_hops} hops long. Demoting them and re-emitting did `
          + 'not converge, so the honest outcome is a refusal: widening the check instead would '
          + 'delete the only guarantee that a three-admin company is still a seven-hop exercise.',
          {
            code: 'CIAB_ADMIN_NEGOTIATION_FAILED',
            principal: f.principal,
            hops: f.hops,
            designed_hops: f.designed_hops,
            path: arr(f.path),
            demoted: Array.from(demoted),
            rounds,
            cause: err,
          }
        );
      }
      err.negotiation = { rounds, demoted: Array.from(demoted) };
      throw err;
    }

    // Second pass: lower the design into the lab, including the principal
    // fields it decided. compileLab re-runs assertFootholdHonoured() and both
    // external checkers over the result, so nothing here is taken on trust.
    // The design's overrides go ON TOP of the caller's: the caller pins what it
    // knows, the design decides the rest, and the foothold password is the
    // design's to set because it is the design that plants it.
    const overrides = obj(options.principalOverrides);
    const merged = principalOverridesFromDesign(designed);
    for (const [fqdn, bySam] of Object.entries(overrides)) {
      merged[fqdn] = merged[fqdn] || {};
      for (const [sam, patch] of Object.entries(obj(bySam))) {
        merged[fqdn][sam] = Object.assign({}, obj(patch), obj(merged[fqdn][sam]));
      }
    }
    const final = compileLab(profile, {
      demoteAdmins: Array.from(demoted),
      chain: designed.chain,
      acls: designed.acls,
      footholdCredential: designed.foothold_credential,
      principalOverrides: merged,
      // THE PASS THAT SHIPS. Everything downstream — the bake's identity hash,
      // the pushed tree, the golden templates — is derived from this result and
      // nothing else, so this is the one compile held to the generated-mode
      // rules: a chain that exists, is rooted at the planted foothold, reaches
      // the objective over its own edges, and whose every ACL edge was actually
      // lowered into the emitted lab. The draft pass above is deliberately not.
      assertGenerated: true,
    });
    return Object.assign({}, final, {
      chain_design: designed.chain,
      chain_acls: designed.acls,
      negotiation: { rounds, demoted: Array.from(demoted), rounds_used: round + 1 },
    });
  }

  throw new LabCompileError(
    `The composer/designer negotiation did not settle within ${maxRounds} rounds `
    + `(demoted so far: ${Array.from(demoted).join(', ') || 'nothing'}).`,
    { code: 'CIAB_ADMIN_NEGOTIATION_FAILED', demoted: Array.from(demoted), rounds }
  );
}

// ─── Departments ────────────────────────────────────────────────────────────

/**
 * The department list, from the profile's own breakdown when it has one.
 *
 * Sorted by headcount descending so the largest department is first and the
 * roster distribution below is stable regardless of the order the LLM emitted
 * the keys in — an object whose keys arrive in a different order is otherwise a
 * different lab from the same profile.
 */
function buildDepartments(facts, sizing) {
  const raw = Object.entries(facts.departments)
    .map(([name, count]) => ({ name: cnSafe(name), count: Number(count) || 0 }))
    .filter((d) => d.name && d.count >= 0);
  if (raw.length >= 2) {
    return raw.sort((a, b) => (b.count - a.count) || a.name.localeCompare(b.name));
  }
  const fallback = DEFAULT_DEPARTMENTS[sizing.sector] || DEFAULT_DEPARTMENTS.SMB;
  return fallback.map((name, i) => ({ name, count: Math.max(1, Math.round(sizing.employees / (i + 2))) }));
}

// ─── Principals ─────────────────────────────────────────────────────────────

/**
 * Users, groups and OUs for every domain.
 *
 * WHY THE ROSTER IS A SAMPLE AND NOT THE HEADCOUNT. The paper profile carries
 * 4-8 stakeholders against 25-200 employees, and the obvious move — mint one AD
 * user per employee — is wrong twice: win_domain_user is a serialised WinRM
 * round trip per user (a 200-user domain is most of an hour of bake time on its
 * own), and a directory where every object is filler teaches nothing. So the
 * roster is a REPRESENTATIVE SAMPLE: every stakeholder, plus enough synthesized
 * staff to make the department structure legible and enumeration worth doing,
 * capped per tier. The paper's headcount stays the org's; the lab's roster is
 * what a tester would actually pull out of it.
 */
const ROSTER_CAP = Object.freeze({ S: 22, M: 30, L: 38 });

/**
 * hashPick, but never returning a value already in `taken` - a deterministic
 * linear probe from the seeded index. Falls back to the seeded pick only when
 * the pool is exhausted, so the caller degrades to a collision rather than to
 * an exception.
 */
function pickUnused(runId, salt, pool, taken) {
  const start = hashStr(runId, salt) % pool.length;
  for (let i = 0; i < pool.length; i += 1) {
    const candidate = pool[(start + i) % pool.length];
    if (!taken.has(candidate)) return candidate;
  }
  return pool[start];
}

function populatePrincipals(ctx) {
  const {
    runId, facts, sizing, tier, lab, domains, departments,
    ouScheme, groupScheme, opsGroups, resourceGroups, services, warnings,
    declareAdmin, isDemoted,
  } = ctx;

  const irUsers = [];
  const irGroups = [];
  const irOus = [];

  // How the roster splits across domains. The forest root is the HQ, the child
  // is the subsidiary, the second forest is the company that was acquired.
  const weights = tier === 'S' ? [1] : tier === 'M' ? [0.6, 0.4] : [0.45, 0.3, 0.25];

  const rosterTarget = Math.max(
    facts.stakeholders.length + 6,
    Math.min(ROSTER_CAP[tier], Math.ceil(sizing.employees * 0.25))
  );

  // Stakeholders first — they are real people from the paper profile and must
  // survive any cap. Everything after them is synthesized filler.
  const people = [];
  const seenNames = new Set();
  facts.stakeholders.forEach((s, i) => {
    const { firstname, surname } = splitPersonName(s && s.name);
    if (!firstname) return;
    const dedupe = `${atom(firstname)}|${atom(surname)}`;
    if (seenNames.has(dedupe)) return;
    seenNames.add(dedupe);
    // A stakeholder's department is frequently one the breakdown never listed
    // ('Executive', 'Board'). Adopt it rather than reassigning the person: the
    // department list is what the OU and group shape is built from, so silently
    // moving a named executive into Operations shows up on the org chart the
    // student is holding.
    let department = cnSafe(str(s.department));
    if (department && !departments.some((d) => d.name === department)) {
      departments.push({ name: department, count: 1 });
    }
    if (!department) department = departments[0].name;
    people.push({
      firstname,
      surname,
      department,
      title: cnSafe(str(s.role)) || 'Staff',
      stakeholder: true,
      index: i,
    });
  });
  if (people.length === 0) {
    warnings.push({
      code: 'CIAB_NO_STAKEHOLDERS',
      message: `${facts.companyName} carries no usable stakeholder names, so the entire roster is `
        + 'synthesized. The lab still compiles, but no name in it matches the paper profile the '
        + 'student is reading.',
    });
  }

  // Synthesized staff, distributed across departments in proportion to the
  // profile's own breakdown so the OU/group shape reflects the real org chart.
  const totalWeight = departments.reduce((n, d) => n + Math.max(1, d.count), 0);
  let cursor = 0;
  for (let i = people.length; i < rosterTarget; i++) {
    const dept = departments[cursor % departments.length];
    // Larger departments get proportionally more of the sample: step the cursor
    // faster past a small department than a large one.
    const share = Math.max(1, Math.round((Math.max(1, dept.count) / totalWeight) * departments.length));
    if ((i - people.length) % Math.max(1, share) === 0) cursor++;
    let firstname = '';
    let surname = '';
    for (let attempt = 0; attempt < 12; attempt++) {
      firstname = hashPick(runId, `person:${i}:${attempt}:first`, FIRST_NAMES);
      surname = hashPick(runId, `person:${i}:${attempt}:last`, SURNAMES);
      if (!seenNames.has(`${atom(firstname)}|${atom(surname)}`)) break;
    }
    const dedupe = `${atom(firstname)}|${atom(surname)}`;
    if (seenNames.has(dedupe)) continue;
    seenNames.add(dedupe);
    people.push({ firstname, surname, department: dept.name, title: 'Staff', stakeholder: false, index: i });
  }

  // Assign each person to a domain by cumulative weight.
  const cuts = [];
  let acc = 0;
  for (const w of weights) { acc += w; cuts.push(acc); }
  const assignDomain = (i) => {
    const t = (i + 0.5) / people.length;
    for (let d = 0; d < cuts.length; d++) if (t <= cuts[d]) return d;
    return cuts.length - 1;
  };

  const perDomain = domains.map(() => []);
  people.forEach((person, i) => perDomain[assignDomain(i)].push(person));

  // Nobody may be empty: preflight treats `users: {}` and an absent key as the
  // same finding, because ad-data.yml binds ad_users straight off it and a
  // domain with no users is a green bake that built nothing.
  for (let d = 0; d < perDomain.length; d++) {
    while (perDomain[d].length < 3) {
      const donor = perDomain.findIndex((list, i) => i !== d && list.length > 4);
      if (donor === -1) break;
      perDomain[d].push(perDomain[donor].pop());
    }
  }

  const iisHosts = new Set(arr(services.iisHosts));
  const mssqlHosts = new Set(arr(services.mssqlHosts));

  domains.forEach((domain, di) => {
    const block = lab.domains[domain.fqdn];
    const rootDn = domain.rootDn;
    const domainDepartments = uniqueDepartments(perDomain[di], departments);

    // ── OUs ───────────────────────────────────────────────────────────────
    // Emitted parents-first: roles/ad/tasks/ou.yml iterates the dict in file
    // order and ADOrganizationalUnit needs the parent to exist already.
    const ous = {};
    let peoplePath = `CN=Users,${rootDn}`;
    let groupPath = `CN=Users,${rootDn}`;
    let servicePath = `CN=Users,${rootDn}`;
    const deptOuPath = {};

    if (ouScheme === 'flat') {
      for (const dept of domainDepartments) {
        const name = cnSafe(dept.name);
        ous[name] = { path: rootDn };
        deptOuPath[dept.name] = `OU=${name},${rootDn}`;
      }
      peoplePath = null; // per-department
      groupPath = rootDn;
      servicePath = rootDn;
    } else if (ouScheme === 'tiered') {
      const companyOu = cnSafe(facts.companyName) || 'Company';
      ous[companyOu] = { path: rootDn };
      const under = `OU=${companyOu},${rootDn}`;
      ous.Staff = { path: under };
      ous.Groups = { path: under };
      ous['Service Accounts'] = { path: under };
      for (const dept of domainDepartments) {
        const name = cnSafe(dept.name);
        if (ous[name]) continue;
        ous[name] = { path: `OU=Staff,${under}` };
        deptOuPath[dept.name] = `OU=${name},OU=Staff,${under}`;
      }
      peoplePath = null;
      groupPath = `OU=Groups,${under}`;
      servicePath = `OU=Service Accounts,${under}`;
    }
    block.organisation_units = ous;
    for (const [name, ou] of Object.entries(ous)) {
      irOus.push({ name, path: ou.path, domain: domain.fqdn });
    }

    const pathForDept = (dept) => (peoplePath === null
      ? (deptOuPath[dept] || `CN=Users,${rootDn}`)
      : peoplePath);

    // ── groups ────────────────────────────────────────────────────────────
    const groupNamesTaken = new Set();
    const globalGroups = {};
    const domainlocalGroups = {};
    const universalGroups = {};

    for (const dept of domainDepartments) {
      const name = uniqueName(departmentGroupName(dept.name, groupScheme), groupNamesTaken, MAX_COMMON_NAME);
      globalGroups[name] = { path: groupPath };
      dept.groupName = name;
    }
    for (const ops of opsGroups) {
      const name = uniqueName(cnSafe(ops), groupNamesTaken, MAX_COMMON_NAME);
      globalGroups[name] = { path: groupPath };
    }
    for (const res of resourceGroups) {
      const name = uniqueName(cnSafe(res), groupNamesTaken, MAX_COMMON_NAME);
      // AGDLP: accounts -> global -> domainlocal -> permission. The membership
      // is what makes the two-tier shape real rather than two flat lists.
      const members = Object.keys(globalGroups).slice(0, 2);
      domainlocalGroups[name] = { path: groupPath, members };
    }
    if (domains.length > 1 && domain.is_forest_root) {
      // A universal group only means anything in a multi-domain forest, which is
      // exactly when the chassis has one.
      const name = uniqueName('All-Staff', groupNamesTaken, MAX_COMMON_NAME);
      universalGroups[name] = { path: groupPath };
    }
    block.groups = { universal: universalGroups, global: globalGroups, domainlocal: domainlocalGroups };

    // ── users ─────────────────────────────────────────────────────────────
    const samTaken = new Set();
    const users = {};
    const domainUsers = [];
    const weakCount = hashInt(runId, `weak:${domain.fqdn}`, 1, 4);
    // Issued to NON-ADMINS only, counted rather than indexed. `pi < weakCount`
    // anchored the weak band on roster index 0 — the same index that is
    // unconditionally made a Domain Admin below — so EVERY domain of EVERY
    // compiled lab shipped a Domain Admin whose password was 'Welcome1'. A
    // password spray owned the forest before the designed chain's first edge,
    // which makes the whole graph decoration. The band still exists (crackable
    // passwords are the raw material for the user_equals_password and
    // password-spray entry points); it just cannot land on the endgame.
    let weakIssued = 0;
    // HOW MANY DOMAIN ADMINS IS REALISM, AND WHERE THE LINE IS.
    // A company has domain admins; it does not have five of them in a nine
    // account directory. The stakeholder coin below is 25% per stakeholder, and
    // a profile carrying seven stakeholders against a small domain slice really
    // did mint five — leaving two ordinary accounts for the entire attack chain
    // to be built out of, and the designer then (correctly) refused to design a
    // three hop chain over two principals. So the count is capped at a quarter
    // of the domain's own roster, with a floor of one: somebody is always a
    // Domain Admin, and it is never half the company.
    const adminCap = Math.max(1, Math.round(perDomain[di].length * 0.25));
    let adminsIssued = 0;
    // Drawn WITHOUT REPLACEMENT. hashPick draws independently per user, so with
    // 2-4 weak users against a 7-entry pool a collision is a coin flip - and two
    // users sharing 'Summer2024' is an undeclared credential-reuse shortcut
    // (goad-attack-chain SHORTCUT_SHARED_PASSWORD) that hands the student a
    // second account for free. Deliberate reuse is a legitimate lesson, but it
    // has to be DECLARED; an accidental birthday collision is just a hole.
    const weakTaken = new Set();

    perDomain[di].forEach((person, pi) => {
      const sam = samAccountName(person.firstname, person.surname, samTaken);
      const dept = domainDepartments.find((d) => d.name === person.department) || domainDepartments[0];
      const groups = [dept.groupName];
      // A privileged handful, seeded: somebody has to be a Domain Admin, and
      // which somebody is a structural fact about the lab.
      const adminCandidate = adminsIssued < adminCap
        && (pi === 0 || (person.stakeholder && hashCoin(runId, `da:${domain.fqdn}:${sam}`, 25)));
      if (adminCandidate) adminsIssued += 1;
      if (adminCandidate && !isDemoted(sam)) {
        groups.push('Domain Admins');
        declareAdmin(sam, domain.fqdn, 'Domain Admins');
      }
      const opsPick = hashInt(runId, `ops:${domain.fqdn}:${sam}`, 0, opsGroups.length * 3);
      if (opsPick < opsGroups.length) groups.push(cnSafe(opsGroups[opsPick]));

      // Anchored on the CANDIDACY, not on the resulting membership. A demoted
      // admin must keep the password it had before the demotion, or every
      // negotiation round would reshuffle the weak band and the design would be
      // chasing a moving target instead of converging.
      const weak = !adminCandidate && weakIssued < weakCount;
      if (weak) weakIssued += 1;
      const password = weak
        ? pickUnused(runId, `weakpw:${domain.fqdn}:${sam}`, WEAK_USER_PASSWORDS, weakTaken)
        : makeMachinePassword(runId, `userpw:${domain.fqdn}:${sam}`);
      if (weak) weakTaken.add(password);

      users[sam] = {
        firstname: person.firstname,
        surname: person.surname,
        password,
        city: facts.hqCity || '-',
        description: `${person.title}, ${person.department}`,
        groups: groups.filter((g, i, list) => g && list.indexOf(g) === i),
        path: pathForDept(person.department),
      };
      domainUsers.push({
        sam,
        password,
        weak,
        groups: users[sam].groups,
        department: person.department,
        // Carried so placePayload can pick DC local administrators from a set
        // that does NOT move when somebody is demoted. Keying off actual Domain
        // Admins membership would put a demoted principal back into the
        // local-admin pool, changing the sample and minting a NEW privileged
        // account every negotiation round — a treadmill, not a negotiation.
        admin_candidate: adminCandidate,
      });
    });

    // ── service accounts ──────────────────────────────────────────────────
    // SPNs are the reason these exist: a kerberoastable service account is the
    // most common real finding in an org this size, and the SPN has to name a
    // host that genuinely runs the service or the finding is scenery.
    const domainHostKeys = Object.keys(lab.hosts).filter((k) => lab.hosts[k].domain === domain.fqdn);
    const serviceAccounts = [];
    const addService = (role, sam, first, last, title, spns) => {
      const key = uniqueName(sam, samTaken, MAX_SAM_ACCOUNT_NAME);
      users[key] = {
        firstname: first,
        surname: last,
        password: makeMachinePassword(runId, `svcpw:${domain.fqdn}:${key}`),
        city: facts.hqCity || '-',
        description: title,
        groups: [Object.keys(globalGroups)[0]],
        path: servicePath,
      };
      if (spns && spns.length) users[key].spns = spns;
      // Tagged by ROLE, not looked up by name later: uniqueName may have had to
      // rename 'svc_mssql' around a collision, and a later lookup by the literal
      // string would then silently fall back to NETWORK SERVICE.
      serviceAccounts.push({ role, sam: key, password: users[key].password, spns: spns || [] });
      return key;
    };

    const sqlHost = domainHostKeys.find((k) => mssqlHosts.has(k));
    if (sqlHost) {
      const fqdnHost = `${lab.hosts[sqlHost].hostname}.${domain.fqdn}`;
      addService('mssql', 'svc_mssql', 'SQL', 'Service', 'SQL Server service account',
        [`MSSQLSvc/${fqdnHost}:1433`, `MSSQLSvc/${fqdnHost}`]);
    }
    const webHost = domainHostKeys.find((k) => iisHosts.has(k));
    if (webHost) {
      const fqdnHost = `${lab.hosts[webHost].hostname}.${domain.fqdn}`;
      addService('web', 'svc_web', 'Web', 'Service', 'Intranet application pool identity',
        [`HTTP/${fqdnHost}`]);
    }
    addService('backup', 'svc_backup', 'Backup', 'Service', 'Backup agent service account', []);

    block.users = users;

    for (const [sam, u] of Object.entries(users)) {
      irUsers.push({
        sam,
        firstname: u.firstname,
        surname: u.surname,
        password: u.password,
        description: u.description,
        city: u.city,
        path: u.path,
        domain: domain.fqdn,
        groups: u.groups.slice(),
        spns: arr(u.spns).slice(),
      });
    }
    for (const [scope, byName] of Object.entries(block.groups)) {
      for (const [name, g] of Object.entries(byName)) {
        irGroups.push({
          name,
          scope,
          path: g.path,
          domain: domain.fqdn,
          managed_by: g.managed_by || null,
          members: arr(g.members).slice(),
        });
      }
    }

    domain.users = domainUsers;
    domain.serviceAccounts = serviceAccounts;
    domain.globalGroups = Object.keys(globalGroups);
  });

  // managed_by is assigned after every user exists: roles/ad/tasks/main.yml sets
  // it in a pass that runs after users.yml, and the value has to resolve to a
  // principal in the same domain.
  domains.forEach((domain) => {
    const block = lab.domains[domain.fqdn];
    const owners = domain.users.filter((u) => u.groups.includes('Domain Admins'));
    if (!owners.length) return;
    const names = Object.keys(block.groups.global);
    names.forEach((name, i) => {
      if (!hashCoin(runId, `managedby:${domain.fqdn}:${name}`, 35)) return;
      const owner = owners[i % owners.length];
      block.groups.global[name].managed_by = owner.sam;
      const irGroup = irGroups.find((g) => g.domain === domain.fqdn && g.name === name);
      if (irGroup) irGroup.managed_by = owner.sam;
    });
  });

  return {
    ir: { users: irUsers, groups: irGroups, ous: irOus },
    byDomain: domains,
    ouScheme,
    groupScheme,
  };
}

/** The departments actually represented in one domain's slice of the roster. */
function uniqueDepartments(peopleInDomain, departments) {
  const wanted = new Set(peopleInDomain.map((p) => p.department));
  const kept = departments.filter((d) => wanted.has(d.name)).map((d) => ({ name: d.name, count: d.count }));
  if (kept.length) return kept;
  return [{ name: departments[0].name, count: departments[0].count }];
}

// ─── Service placement ──────────────────────────────────────────────────────

/**
 * Decide which host carries which service, and emit the mssql block that
 * decision implies.
 *
 * ONLY THE SERVICE GROUPS MOVE. [domain], [dc], [parent_dc], [child_dc],
 * [trust], [adcs] and [adcs_customtemplates] are inherited from the chassis
 * verbatim: they drive dcpromo, the trust build and the ca_server requirement,
 * and they are the half of the inventory that was proven to deploy. iis, mssql,
 * mssql_ssms and webdav are the half a real client's estate actually varies in.
 */
function placeServices(ctx) {
  const { runId, lab, invGroup } = ctx;
  const servers = Object.keys(lab.hosts).filter((k) => lab.hosts[k].type === 'server');

  // [adcs] and [adcs_customtemplates] are INHERITED, not chosen: adcs.yml keys
  // the ca_server requirement off them and the chassis is where that was proven.
  // Read before the tier-S early return, because tier S's only host IS its CA
  // and the ADCS vulns are most of what makes that tier worth attacking.
  const adcsHosts = invGroup('adcs').slice();

  const profileName = hashPick(runId, 'service-profile',
    ['full', 'web-and-file', 'sql-only', 'web-and-sql']);

  const placement = { iis: [], mssql: [], mssql_ssms: [], webdav: [] };

  if (servers.length === 0) {
    // Tier S has no member server at all; the chassis service groups are empty
    // and must stay that way, so there is nothing to override.
    return { profile: 'none', mssqlHosts: [], iisHosts: [], adcsHosts, servers, overrides: {} };
  }

  // With two servers the assignment itself is the structural knob: which box is
  // the web server and which is the database is the first thing a tester maps.
  const primary = servers[hashStr(runId, 'primary-server') % servers.length];
  const secondary = servers.find((s) => s !== primary) || primary;

  if (profileName === 'full') {
    placement.iis.push(primary);
    placement.mssql.push(secondary);
    placement.mssql_ssms.push(secondary);
    placement.webdav.push(primary);
  } else if (profileName === 'web-and-file') {
    placement.iis.push(primary);
    placement.webdav.push(primary, secondary === primary ? null : secondary);
  } else if (profileName === 'sql-only') {
    placement.mssql.push(primary);
    placement.mssql_ssms.push(primary);
  } else {
    placement.iis.push(primary);
    placement.mssql.push(primary);
    placement.mssql_ssms.push(primary);
    if (secondary !== primary) placement.webdav.push(secondary);
  }
  for (const key of Object.keys(placement)) {
    placement[key] = placement[key].filter(Boolean).filter((h, i, l) => l.indexOf(h) === i);
  }

  return {
    profile: profileName,
    mssqlHosts: placement.mssql.slice(),
    iisHosts: placement.iis.slice(),
    adcsHosts,
    servers,
    // The inventory group overrides emitTree applies. Only these four groups
    // move; everything else in data/inventory is the chassis'.
    overrides: placement,
  };
}

/**
 * The mssql block for every [mssql] member.
 *
 * sa_password is the ONE key servers.yml:31 reads without a `| default(...)`.
 * svcaccount is subtler and is why this runs after the roster exists:
 * servers.yml:24 resolves SQLSVCPASSWORD as
 * `lab.domains[domain].users[svcaccount].password | default('')`, so naming a
 * service account that is not a user OF THAT HOST'S OWN DOMAIN installs SQL with
 * an empty service password.
 */
function attachMssql(ctx) {
  const { runId, lab, services, principals } = ctx;
  for (const hostKey of services.mssqlHosts) {
    const host = lab.hosts[hostKey];
    const domain = principals.byDomain.find((d) => d.fqdn === host.domain);
    const svc = domain.serviceAccounts.find((s) => s.role === 'mssql');
    const sysadmin = domain.users.find((u) => u.groups.includes('Domain Admins')) || domain.users[0];
    host.mssql = {
      sa_password: makeMachinePassword(runId, `sa:${hostKey}`),
      sysadmins: sysadmin ? [`${domain.netbios}\\${sysadmin.sam}`] : [],
    };
    if (svc) host.mssql.svcaccount = svc.sam;
  }
}

// ─── Payload: vulns, hardening, local groups ────────────────────────────────

/**
 * Plant the payload.
 *
 * The COUNT is varied as well as the mix, because two labs with five different
 * vulns each are still the same lab shape. `disable_firewall` is on every host
 * unconditionally: without it the host answers nothing and every other vuln on
 * it is unreachable, which is a lab that looks planted and enumerates empty.
 */
function placePayload(ctx) {
  const {
    runId, lab, hostKeys, services, posture, principals, irHosts, declareAdmin, isDemoted,
  } = ctx;
  const adcsHosts = new Set(arr(services.adcsHosts));

  for (const hostKey of hostKeys) {
    const host = lab.hosts[hostKey];
    const isDc = host.type === 'dc';
    const domain = principals.byDomain.find((d) => d.fqdn === host.domain);
    // Recorded onto the IR host below: the two edges this file plants that no
    // reader of principals alone would ever see.
    const localAdmins = [];

    const pool = manifestSafe(isDc ? VULN_POOL_DC.slice() : VULN_POOL_MEMBER.slice(), 'vulns');
    const adcsPool = adcsHosts.has(hostKey) ? manifestSafe(VULN_POOL_ADCS.slice(), 'vulns') : [];

    // A soft lab is a noisy lab; a hardened one plants fewer holes and defends
    // the ones it has. That is the difficulty dial, expressed structurally.
    const base = posture === 'soft' ? hashInt(runId, `vulncount:${hostKey}`, 3, 5)
      : posture === 'mixed' ? hashInt(runId, `vulncount:${hostKey}`, 2, 4)
        : hashInt(runId, `vulncount:${hostKey}`, 1, 3);

    const chosen = hashSample(runId, `vulns:${hostKey}`, pool, base);
    if (adcsPool.length && hashCoin(runId, `adcsvuln:${hostKey}`, posture === 'hardened' ? 35 : 70)) {
      chosen.push(...hashSample(runId, `adcsvulns:${hostKey}`, adcsPool, hashInt(runId, `adcsn:${hostKey}`, 1, 2)));
    }

    const vulnsVars = {};

    // A world-writable staging folder: `directory` creates it, `permissions`
    // opens it, and the array order below is the execution order.
    if (hashCoin(runId, `openfolder:${hostKey}`, posture === 'hardened' ? 25 : 60)) {
      const share = hashPick(runId, `sharename:${hostKey}`, ['transfer', 'scans', 'dropbox', 'staging']);
      const root = `C:\\${share}`;
      chosen.push('directory', 'permissions');
      vulnsVars.directory = { [share]: root };
      vulnsVars.permissions = {
        [`${share}_open`]: {
          path: root,
          user: hashPick(runId, `shareuser:${hostKey}`, ['Everyone', 'Authenticated Users']),
          rights: hashPick(runId, `sharerights:${hostKey}`, ['FullControl', 'Modify']),
        },
      };
    }

    // A cached credential for somebody else's account — the lateral-movement
    // primitive, and the reason the roster's passwords have to be real values
    // rather than placeholders.
    const cachedCredentials = [];
    if (domain && domain.users.length > 1 && hashCoin(runId, `cred:${hostKey}`, posture === 'soft' ? 65 : 40)) {
      const victim = domain.users[hashStr(runId, `credvictim:${hostKey}`) % domain.users.length];
      const target = Object.keys(lab.hosts).find((k) => k !== hostKey) || hostKey;
      cachedCredentials.push(victim.sam);
      chosen.push('credentials');
      vulnsVars.credentials = {
        [`TERMSRV/${lab.hosts[target].hostname}`]: {
          username: `${domain.netbios}\\${victim.sam}`,
          secret: victim.password,
        },
      };
      if (hashCoin(runId, `autologon:${hostKey}`, 35)) {
        chosen.push('autologon');
        vulnsVars.autologon = {
          [victim.sam]: { username: `${domain.netbios}\\${victim.sam}`, password: victim.password },
        };
      }
    }

    chosen.push('disable_firewall');

    const vulns = orderVulns(chosen.filter((v, i, l) => l.indexOf(v) === i));
    host.vulns = vulns;
    host.vulns_vars = {};
    // Emit vars only for roles that are actually listed, in list order: an
    // orphaned vars entry is dead config the validator rejects outright.
    for (const name of vulns) {
      if (vulnsVars[name] !== undefined) host.vulns_vars[name] = vulnsVars[name];
    }

    // ── hardening ─────────────────────────────────────────────────────────
    const securityPool = manifestSafe(
      (isDc ? SECURITY_POOL_DC : SECURITY_POOL_MEMBER).slice(), 'security');
    const securityCount = posture === 'soft' ? 0 : posture === 'mixed' ? hashInt(runId, `sec:${hostKey}`, 0, 1) : hashInt(runId, `sec:${hostKey}`, 1, 2);
    const security = hashSample(runId, `security:${hostKey}`, securityPool, securityCount);
    const securityVars = {};

    // account_is_sensitive runs Set-ADUser, so it only belongs on a DC, and the
    // account it names has to live in that DC's own domain.
    if (isDc && posture !== 'soft' && domain && domain.users.length && !isNeverEmit('account_is_sensitive', 'security')) {
      const protectedUsers = domain.users.filter((u) => u.groups.includes('Domain Admins'));
      if (protectedUsers.length) {
        security.push('account_is_sensitive');
        securityVars.account_is_sensitive = {};
        const take = posture === 'hardened' ? Math.min(2, protectedUsers.length) : 1;
        protectedUsers.slice(0, take).forEach((u) => {
          securityVars.account_is_sensitive[u.sam] = { account: u.sam };
        });
      }
    }

    host.security = security.filter((v, i, l) => l.indexOf(v) === i);
    host.security_vars = {};
    for (const name of host.security) {
      if (securityVars[name] !== undefined) host.security_vars[name] = securityVars[name];
    }

    // ── local groups ──────────────────────────────────────────────────────
    // Only ever principals from the host's OWN domain: settings/adjust_rights
    // runs with that domain's credentials and a name it cannot resolve fails
    // the task.
    if (domain && domain.users.length) {
      // Prefer somebody who is NOT already a Domain Admin: a DA is a local admin
      // everywhere by default, so listing one here plants nothing. The
      // interesting — and far more common — finding is the ordinary account that
      // is local admin on a box it has no business owning.
      // Keyed off admin CANDIDACY rather than current membership, so the pool is
      // the same in every negotiation round and a demotion removes a name
      // instead of reshuffling the draw.
      const nonAdmins = domain.users.filter((u) => !u.admin_candidate);
      let adminPool = (nonAdmins.length ? nonAdmins : domain.users).map((u) => u.sam);
      // A DC's local Administrators list IS the domain's built-in Administrators,
      // so a name on it is a domain admin by another spelling. Honour the
      // negotiation's demotions here too — otherwise "demote this principal"
      // would move them out of Domain Admins and leave them equally privileged
      // through the DC's local group, and the negotiation would never converge.
      if (isDc) {
        const kept = adminPool.filter((sam) => !isDemoted(sam));
        if (kept.length) adminPool = kept;
      }
      const admins = hashSample(runId, `localadmin:${hostKey}`, adminPool,
        hashInt(runId, `localadminn:${hostKey}`, 1, 2));
      const rdp = domain.globalGroups.length
        ? hashSample(runId, `localrdp:${hostKey}`, domain.globalGroups, hashInt(runId, `localrdpn:${hostKey}`, 1, 2))
        : [];
      host.local_groups = {
        Administrators: admins.map((sam) => `${domain.netbios}\\${sam}`),
      };
      if (rdp.length) {
        host.local_groups['Remote Desktop Users'] = rdp.map((g) => `${domain.netbios}\\${g}`);
      }
      if (isDc) for (const sam of admins) declareAdmin(sam, domain.fqdn, 'Administrators (DC local)');
      localAdmins.push(...admins);
    }

    const irHost = irHosts.find((h) => h.key === hostKey);
    if (irHost) {
      irHost.roles = host.vulns.concat(host.security);
      // The two composer-owned facts the ACL designer cannot see from the
      // principal pool alone, and both of them are real attack edges: local
      // admin on a box, and somebody else's password cached on it. The designer
      // walks them when it asks whether a declared admin can be taken more
      // cheaply than the designed chain — reachability computed over ACLs alone
      // would call a two-hop credential-reuse takeover "unreachable".
      irHost.local_admins = localAdmins.slice();
      irHost.cached_credentials = cachedCredentials.slice();
    }
  }

  attachMssql({ runId, lab, services, principals });
}

// ─── Foothold ───────────────────────────────────────────────────────────────

/**
 * The one object neither generator owns alone.
 *
 * The AD half is minted here — this compiler is what creates the principal, so
 * it is the only thing that can guarantee the principal exists. `planted_at` is
 * the WEB half: the file, path and format the vuln-app drops it in. It stays
 * null until somebody plants it, and assertFootholdHonoured() below is what
 * turns a chain that depends on an unplanted credential into a compile error
 * rather than a lab a student cannot start.
 */
function resolveFoothold(ctx) {
  const { runId, lab, domains, principals, services, supplied } = ctx;

  if (supplied) {
    const s = obj(supplied);
    return {
      sam: str(s.sam),
      domain: str(s.domain),
      password: str(s.password),
      planted_at: s.planted_at === undefined ? null : s.planted_at,
      honoured_by: 'ad',
    };
  }

  // Prefer the domain that hosts the web application: the credential the website
  // leaks should belong where the website lives, or the story does not hold.
  const webHost = arr(services.iisHosts)[0];
  const preferred = webHost ? lab.hosts[webHost].domain : domains[0].fqdn;
  const domain = principals.byDomain.find((d) => d.fqdn === preferred) || principals.byDomain[0];

  // A service account, not a person: it is the credential most likely to sit in
  // a config file, and it is the one whose exposure a real report would flag.
  const candidate = domain.serviceAccounts.find((s) => s.role === 'web')
    || domain.serviceAccounts[hashStr(runId, 'foothold') % domain.serviceAccounts.length]
    || domain.users[0];

  return {
    sam: candidate.sam,
    domain: domain.fqdn,
    password: candidate.password,
    planted_at: null,
    honoured_by: 'ad',
  };
}

/**
 * The invariant that makes the website and the AD one system rather than two.
 *
 * Two directions, both compile errors:
 *   - foothold_credential naming a principal AD does not create. The student
 *     finds a credential on the web app, sprays it at the DC, and it does not
 *     exist. Nothing errors; the exercise just has no second act.
 *   - chain.start depending on a credential the web side does not plant. Same
 *     dead end, arrived at from the other direction.
 */
function assertFootholdHonoured(ir) {
  const cred = obj(ir.foothold_credential);
  const sam = str(cred.sam);
  const domain = str(cred.domain);
  if (!sam || !domain) {
    throw new LabCompileError(
      'foothold_credential is missing sam or domain. It is the single object that ties the '
      + 'website to the forest; without it neither half can be checked against the other.',
      { code: 'CIAB_FOOTHOLD_INCOMPLETE' }
    );
  }
  const user = ir.principals.users.find((u) => u.sam === sam && u.domain === domain);
  if (!user) {
    throw new LabCompileError(
      `foothold_credential names '${sam}' in '${domain}', but this lab creates no such user `
      + `(that domain's roster is: ${ir.principals.users.filter((u) => u.domain === domain)
        .map((u) => u.sam).join(', ') || 'empty'}). The website would leak a credential the `
      + 'forest never honours, and nothing in the deploy would report it.',
      { code: 'CIAB_FOOTHOLD_PRINCIPAL_MISSING' }
    );
  }
  if (user.password !== str(cred.password)) {
    throw new LabCompileError(
      `foothold_credential for '${sam}' carries a password the forest does not set for that `
      + 'account. The credential the website plants must be the one AD honours, byte for byte.',
      { code: 'CIAB_FOOTHOLD_PASSWORD_MISMATCH' }
    );
  }

  // ANY declared start, not just kind === 'credential'. goad-attack-chain sets
  // start.kind to one of its seven ENTRY_POINTS ids ('web_credential',
  // 'asrep', 'user_equals_password', ...) and never to the literal
  // 'credential', so this branch never fired for a designed chain and the
  // redundancy it exists to provide was silently absent. Every designed entry
  // still bottoms out in a credential the web side plants — the designer's own
  // assertFootholdContract requires planted_at unconditionally — so the two
  // halves now enforce the same rule from both sides, which is the only reason
  // to have it twice.
  const start = obj(obj(ir.chain).start);
  if (str(start.kind)) {
    const principal = str(start.principal);
    if (principal && principal !== sam) {
      throw new LabCompileError(
        `chain.start expects the student to begin with '${principal}', but the foothold credential `
        + `this lab plants is '${sam}'. One of the two is wrong, and neither the deploy nor the `
        + 'bake would say so.',
        { code: 'CIAB_CHAIN_START_UNPLANTED' }
      );
    }
    if (!cred.planted_at) {
      throw new LabCompileError(
        `chain.start declares entry '${str(start.kind)}' for '${sam}', but `
        + 'foothold_credential.planted_at is null — nothing on the web side plants it. The '
        + 'student has no way to get their first credential and the whole chain is unreachable '
        + 'from step one.',
        { code: 'CIAB_CHAIN_START_UNPLANTED' }
      );
    }
  }
  return true;
}

/**
 * The chain slot, shaped even when the ACL designer has not filled it yet.
 *
 * THE DECLARED_* FIELDS ARE NOT OPTIONAL DECORATION. An earlier version of this
 * normaliser kept only start/objective/edges/decoys, so a chain that round-
 * tripped through the composer lost `declared_admins`,
 * `declared_broad_principals` and `declared_shared_passwords` — and every one of
 * those is what tells the shortcut checker "this one is deliberate". Dropping
 * them turns a declared entry point back into an undeclared shortcut, which is
 * the same class of silence the DA policy exists to end. `domain` is kept for
 * the same reason: findUnintendedShortcuts() indexes the principal pool by it,
 * and without it the checks run over a guessed domain.
 */
function normalizeChain(chain) {
  if (!chain) {
    return {
      start: null,
      objective: null,
      edges: [],
      decoys: [],
      domain: null,
      declared_admins: [],
      declared_broad_principals: [],
      declared_shared_passwords: [],
    };
  }
  const c = obj(chain);
  return {
    start: c.start || null,
    objective: c.objective || null,
    edges: arr(c.edges).slice(),
    decoys: arr(c.decoys).slice(),
    domain: c.domain || null,
    declared_admins: arr(c.declared_admins).slice(),
    declared_broad_principals: arr(c.declared_broad_principals).slice(),
    declared_shared_passwords: arr(c.declared_shared_passwords).slice(),
  };
}

// ─── Emission ───────────────────────────────────────────────────────────────

function emitTree(ctx) {
  const { chassis, lab, labName, domains, services, posture, hostKeys } = ctx;

  // ── data/inventory ───────────────────────────────────────────────────────
  const overrides = {};
  for (const [group, hosts] of Object.entries(obj(services.overrides))) {
    overrides[group] = hosts.slice();
  }

  // Defensive posture, expressed where security.yml reads it.
  const dcs = hostKeys.filter((k) => lab.hosts[k].type === 'dc');
  const members = hostKeys.filter((k) => lab.hosts[k].type !== 'dc');
  if (posture === 'soft') {
    overrides.defender_on = [];
    overrides.defender_off = hostKeys.slice();
  } else if (posture === 'mixed') {
    overrides.defender_on = dcs.slice();
    overrides.defender_off = members.slice();
  } else {
    overrides.defender_on = hostKeys.slice();
    overrides.defender_off = [];
  }
  overrides.no_update = dcs.slice();
  overrides.update = members.slice();

  let inventory = rewriteInventoryGroups(chassis.inventoryText, overrides);
  inventory = dropPlaceholderComments(inventory);
  inventory = inventory.replace(/^domain_name=.*$/m, `domain_name=${labName}`);
  inventory = `; ${labName} — generated by CyberCore goad-lab-compile from chassis ${chassis.tier}\n`
    + `; (${chassis.provenance.derived_from} @ ${chassis.provenance.goad_ref.slice(0, 12)}).\n`
    + '; Group membership below that is NOT a service or defender group is inherited from the\n'
    + '; chassis verbatim — it is what makes dcpromo, the trust and the CA resolve.\n'
    + inventory;

  // ── providers/proxmox/inventory ──────────────────────────────────────────
  // Host lines, octets and dns_domain wiring are untouched; only the banner
  // comments that name the chassis domains are rewritten, so the file reads as
  // this client's lab rather than as a placeholder.
  let provider = chassis.providerText;
  const byLength = domains.slice().sort((a, b) => b.chassis_fqdn.length - a.chassis_fqdn.length);
  for (const d of byLength) {
    provider = provider.split(d.chassis_fqdn).join(d.fqdn);
  }

  return {
    'data/config.json': `${toStrictJson(lab, { wrap: true, indent: 2 })}\n`,
    'data/inventory': inventory,
    'providers/proxmox/inventory': provider,
  };
}

/**
 * The last gate before anything leaves this module.
 *
 * Runs the emitted tree through BOTH checkers — the validator (AD semantics:
 * password rules, name caps, container paths, role names, ACL rights) and
 * pre-flight (the no-default dereferences the chain will actually perform) —
 * because they overlap only partly and each one catches a class the other does
 * not. Then it sweeps for chassis placeholders: every one of them is
 * deliberately implausible (`chassis.invalid`, `CHASSIS-DC01`,
 * `CHASSIS-PLACEHOLDER-PW-ROOT`) precisely so a leak is unmistakable, and a leak
 * is the one failure mode that would otherwise deploy perfectly.
 *
 * Throws on any error; returns both checkers' warnings so the caller can carry
 * them rather than lose them.
 */
function assertEmitted(ctx) {
  const { files, labName, chassis, lab, chain, ir, generated } = ctx;

  // GENERATED MODE ON THE PASS THAT SHIPS. The reference rules check AD
  // semantics — password rules, name caps, container paths, ACL rights — and
  // have no opinion about whether the exercise is SOLVABLE, so a lab with
  // `acls: {}` and an all-null chain passes them cleanly and deploys green.
  // That is the hole this argument closes: generated mode additionally proves
  // the chain exists, is rooted at the planted foothold, reaches the objective
  // over its own edges, and that every ACL edge the designer drew was actually
  // lowered into the emitted lab. Without it the mode is a rule set nothing runs.
  const validated = assertLabCompiles(Object.assign({
    lab,
    inventory: files['data/inventory'],
    labName,
  }, generated ? {
    mode: MODE_GENERATED,
    chain: ir && ir.chain,
    foothold: ir && ir.foothold_credential,
  } : {}));

  const preflighted = assertGoadLabPreflight({
    labName,
    config: files['data/config.json'],
    inventory: files['data/inventory'],
    providerInventory: files['providers/proxmox/inventory'],
    playbooks: chain,
  });

  const placeholders = chassis.provenance.placeholders || {};
  const needles = []
    .concat(arr(placeholders.domains), arr(placeholders.hostnames),
      arr(placeholders.netbios_names), arr(placeholders.passwords))
    .concat([placeholders.inventory_domain_name])
    .filter(Boolean);
  for (const [name, text] of Object.entries(files)) {
    for (const needle of needles) {
      if (String(text).includes(needle)) {
        throw new LabCompileError(
          `${labName}/${name} still contains the chassis placeholder '${needle}'. `
          + 'A placeholder that survives compilation deploys a lab that looks correct and is not '
          + "this client's — which is exactly why the chassis placeholders are implausible.",
          { code: 'CIAB_PLACEHOLDER_LEAK', file: name, placeholder: needle }
        );
      }
    }
    // The families, not just the exact strings, so a re-sync that renames
    // CHASSIS-DC01 to CHASSIS-DC04 cannot slip a new placeholder past a list
    // that was written against the old one. `.invalid` is RFC 2606 reserved and
    // has no business in a lab; `CHASSIS-`/`CHASSIS_` is the placeholder prefix.
    // The word "chassis" in prose is fine — the provenance banner says it.
    const family = /\.invalid\b|CHASSIS[-_]/.exec(String(text));
    if (family) {
      throw new LabCompileError(
        `${labName}/${name} still carries a chassis placeholder of the form '${family[0]}'.`,
        { code: 'CIAB_PLACEHOLDER_LEAK', file: name }
      );
    }
  }
  return arr(validated.warnings).concat(arr(preflighted.warnings));
}

// ─── Introspection ──────────────────────────────────────────────────────────

/**
 * A comparable fingerprint of a lab's SHAPE, with every proper noun removed.
 *
 * This is the thing "variety" actually means: two labs whose signatures match
 * are the same lab with different names on it, which is the GOAD-Light reskin
 * failure this compiler exists to avoid. Exported because it is the only honest
 * way for a caller — or a test — to ask the question.
 */
function structuralSignature(ir) {
  const byDomain = {};
  for (const d of ir.domains) {
    byDomain[d.fqdn] = {
      ous: ir.principals.ous.filter((o) => o.domain === d.fqdn).map((o) => o.path.split(',')[0]).sort(),
      groupScopes: ir.principals.groups.filter((g) => g.domain === d.fqdn)
        .reduce((acc, g) => { acc[g.scope] = (acc[g.scope] || 0) + 1; return acc; }, {}),
      users: ir.principals.users.filter((u) => u.domain === d.fqdn).length,
      spns: ir.principals.users.filter((u) => u.domain === d.fqdn && u.spns.length).length,
    };
  }
  return {
    tier: ir.tier,
    domainDepths: ir.domains.map((d) => d.fqdn.split('.').length).sort(),
    hostRoles: ir.hosts.map((h) => `${h.key}:${h.roles.slice().sort().join('+')}`).sort(),
    domains: byDomain,
  };
}

module.exports = {
  // Layout and vocabulary a caller should not re-derive.
  CHASSIS_DIR,
  TIERS,
  TREE_FILES,
  ROSTER_CAP,
  OU_SCHEMES,
  GROUP_NAME_SCHEMES,
  POSTURES,
  PRIVILEGED_GROUPS,
  MAX_NEGOTIATION_ROUNDS,
  LabCompileError,
  // The compiler.
  compileLab,
  compileLabWithChain,
  selectTier,
  readProfile,
  // Pure primitives, exported because each encodes a rule worth testing alone.
  companySlug,
  publicDomainOf,
  splitPersonName,
  samAccountName,
  netbiosCandidate,
  // The paper-vs-lane naming contract's one predicate, exported so a test can
  // hold this side of it against ai/profile/validators.js over a shared corpus.
  isPaperDc,
  makeMachinePassword,
  mintDomains,
  loadChassis,
  rewriteInventoryGroups,
  orderVulns,
  manifestSafe,
  assertFootholdHonoured,
  structuralSignature,
  // The declaration half of the Domain Admins contract.
  principalKey,
  privilegedPrincipalsOf,
  assertAdminsDeclared,
  principalOverridesFromDesign,
};
