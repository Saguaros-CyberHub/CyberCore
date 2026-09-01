/**
 * goad-attack-chain.js — the ACL graph-shape designer.
 * ============================================================================
 * WHAT THIS OWNS
 * The intended attack path: `labIR.chain` (start, objective, edges, decoys) and
 * the domain-context ACL table `labIR.acls` those edges lower into. It consumes
 * `labIR.principals`, which the composer owns, and it never writes config.json —
 * the composer does that lowering.
 *
 * WHY IT EXISTS: SHAPE, NOT STRINGS
 * All three chassis descend from the same 12-edge ladder. GOAD-Mini is GOAD's
 * `sevenkingdoms.local` block with the other domains deleted; GOAD-Light is that
 * same ladder with the names changed:
 *
 *   Ext-User-Force-Change-Password -> GenericWrite -> WriteDacl ->
 *   Ext-Self-Self-Membership -> Ext-Write-Self-Membership -> WriteOwner ->
 *   GenericAll x5 -> WriteDacl        (see CHASSIS_LADDER_RIGHTS)
 *
 * Renaming `tywin.lannister` to `richard.croft` changes NOTHING a student
 * actually does. BloodHound draws the same picture, the same node degrees, the
 * same shortest path, the same six abuse primitives in the same order. A student
 * who did last cohort's lab walks this one in ten minutes from memory.
 *
 * So the axes this module varies are the ones the GRAPH has, not the ones the
 * strings have: chain LENGTH, BRANCHING, which RIGHT sits at which DEPTH, the
 * TERMINUS, the DECOYS, and the ENTRY POINT. Two seeds produce two structurally
 * different graphs, and neither is the inherited ladder — isChassisLadder() is
 * a hard guard, not a hope.
 *
 * THE ACL RIGHT VOCABULARY IS THE SHARPEST EDGE IN THIS FILE
 * There are TWO vocabularies and they are NOT interchangeable:
 *
 *   domain context  roles/acl        over `ad_acls`      19 standard + 5 extended
 *   host context    roles/vulns/acls over `vulns_vars`   19 standard + 3 extended
 *
 * The domain role accepts Ext-ManageCA and Ext-Write-SPN; the host role does
 * not. Both are read from goad-role-manifest.aclRights(context) — never
 * hardcoded here, and never unioned.
 *
 * Upstream matching is `$aclValues.contains($right)`, i.e. .NET Array.Contains
 * with the ordinal comparer. That has two consequences this file is built
 * around, and they FAIL IN OPPOSITE DIRECTIONS:
 *
 *   right        an unrecognised or miscased value matches neither list, `$ace`
 *                is never assigned, the `if ($ace)` block never runs, and the
 *                task sets Changed=$false. ANSIBLE REPORTS GREEN. 'genericall'
 *                produces no ACE and no error, and nothing downstream will ever
 *                tell you. => a bad right MUST be a compile error here. A
 *                warning would be a lie, because the deploy will look fine.
 *
 *   inheritance  goes through a [System.DirectoryServices.
 *                ActiveDirectorySecurityInheritance] cast, which is
 *                case-INSENSITIVE and THROWS on an unknown value. A bad
 *                inheritance fails the play loudly, on the lane, at deploy time.
 *                Still a compile error here — catching it in a diff is cheaper
 *                than catching it on a lane — but the failure mode is the
 *                opposite one, so the two are validated separately and a future
 *                reader should not "simplify" them into one lenient check.
 *
 * SOLVABILITY IS A PROOF, NOT A HOPE
 * proveSolvable() walks the emitted edges from the foothold credential to the
 * objective using only edges the role library can actually create. An
 * unsolvable design is rejected with the broken link named. This is what stops
 * the generator shipping a beautiful graph a student cannot enter.
 *
 * GENERATE -> PROVE -> REPAIR
 * The proof used to run once, at the end, and reject the design the generator
 * had just made: a decoy that turned out to be reachable AND productive, or an
 * ACL edge whose target was already one membership hop from the objective. Those
 * are generator bugs, not policy questions, and the answer is not to widen the
 * check — a decoy that shortens the path is not a decoy, it is a second
 * solution, and that distinction is the whole point of the check. So the design
 * is now built, proved, and REPAIRED: the offending decoy is pruned or re-sited,
 * or the binding the shortcut lands on moves, and the round runs again. Bounded
 * at MAX_REPAIR_ATTEMPTS and deterministic under a fixed seed (the repair state
 * only ever grows). If it still cannot produce a clean design it fails loudly
 * naming the axis it could not satisfy. It never emits an unproven chain.
 *
 * THE DOMAIN ADMINS POLICY, WHICH IS SHARED WITH THE COMPOSER
 * A real company has domain admins, so goad-lab-compile mints them — and now
 * DECLARES them, in `principals.declared_admins`, each with the reason it made
 * one. This module used to hardcode `declared_admins: []`, so its no-unintended-
 * shortcuts check rejected every domain admin that existed and could never pass
 * against real composer output.
 *
 * It now consumes the declaration and asserts the property that is actually
 * worth having: every 'roster_realism' admin must NOT be reachable by a path
 * SHORTER than the intended chain. Three domain admins in a company is realism;
 * one of them two hops from the foothold when the lesson is seven hops is a
 * shortcut with an org chart. Reachability is computed over the whole edge set a
 * student really has — ACL edges, group nesting (including a DC's local
 * Administrators list), local-admin grants, cached credentials and password
 * reuse — because a walk over ACLs alone calls a two-hop credential-reuse
 * takeover "unreachable".
 *
 * When an admin IS too cheap, the fix belongs to the COMPOSER: demote that
 * principal and re-emit. goad-lab-compile.compileLabWithChain() drives that as a
 * bounded negotiation. This module reports and refuses; it does not widen.
 *
 * THE FOOTHOLD IS THE SEAM
 * `labIR.foothold_credential` is the one object neither generator owns alone:
 * the website plants it, AD honours it. It is a COMPILE ERROR for chain.start to
 * reference a credential the web side does not plant, or for the foothold to
 * name a principal AD does not create. That single object is what makes the
 * website and the AD one system rather than two.
 *
 * PURE. No fs, no network, no Date.now(), no Math.random(). Everything is a
 * function of (labIR, run_id), so the same seed reproduces byte-identically —
 * which is what makes paper-vs-lane parity assertable by regeneration.
 */

const {
  getRole, aclRights, isAclRight, loadManifest,
} = require('./goad-role-manifest');
const { EXTENDED_RIGHT_ACES, CHECK_KINDS } = require('./goad-postcondition-probe');
const { rootDnForDomain, normalizeDn } = require('./goad-lab-validate');
const { hashStr, hashInt, hashPick } = require('../ai/profile/hash');

// ─── vocabularies, all derived from the vendored manifest ───────────────────

/** The inheritance enum the cast accepts. From the manifest, because
 *  'Descendents' is Microsoft's spelling and nobody remembers that. */
const INHERITANCE_VALUES = Object.freeze(
  loadManifest().acl_inheritance.values.slice());

/**
 * The four keys BOTH acl roles read out of their item dict.
 *
 * Read from the HOST role's manifest entry rather than typed out, because the
 * manifest is the vendored source of truth and the domain role's own
 * `parameters:` block passes exactly the same four (for/to/right/inheritance).
 * If a re-vendor ever changes them, this moves with it instead of drifting.
 */
const ACL_ITEM_KEYS = Object.freeze(getRole('vulns/acls').required_item_keys.slice().sort());

/**
 * The upstream ladder, in order, as a right sequence.
 *
 * Mirrored from ad/GOAD-Mini/data/config.json domains['sevenkingdoms.local']
 * .acls at the pinned ref — GOAD-Light's is the same twelve with the names
 * swapped, which is exactly the point. Emitting this sequence (or any prefix of
 * it) means the generator inherited the chassis instead of designing anything,
 * so isChassisLadder() treats a prefix match as a failure and the designer
 * perturbs itself away from it before returning.
 */
const CHASSIS_LADDER_RIGHTS = Object.freeze([
  'Ext-User-Force-Change-Password',
  'GenericWrite',
  'WriteDacl',
  'Ext-Self-Self-Membership',
  'Ext-Write-Self-Membership',
  'WriteOwner',
  'GenericAll',
  'GenericAll',
  'GenericAll',
  'GenericAll',
  'GenericAll',
  'WriteDacl',
]);

/** Node kinds an edge can target. Not AD classes exactly — these are the
 *  distinctions that decide which rights are meaningful. */
const NODE_KINDS = Object.freeze(['user', 'group', 'computer', 'container', 'ou', 'domain']);

/**
 * RIGHT -> what it is good for.
 *
 * `targets`     the node kinds where the right is a real abuse primitive. A
 *               GenericWrite on an OU is legal AD and useless to a student; a
 *               right that cannot be abused against the object it sits on is a
 *               decoy the designer did not mean to plant.
 * `domain_only` the right lives ONLY in the domain vocabulary. Asserted against
 *               the manifest at load (assertCatalogMatchesManifest) rather than
 *               trusted, so a re-vendor that moves a right cannot leave this
 *               table quietly wrong.
 * `abuse`       the sentence that ends up in the edge's `why` and, through the
 *               probe, in the instructor's report.
 */
const RIGHT_CATALOG = Object.freeze({
  GenericAll: Object.freeze({
    targets: ['user', 'group', 'computer', 'container', 'ou', 'domain'],
    domain_only: false,
    abuse: 'full control - reset the password, add a member, or write the object outright',
  }),
  GenericWrite: Object.freeze({
    targets: ['user', 'group', 'computer'],
    domain_only: false,
    abuse: 'write any non-protected attribute - plant an SPN and roast it, or set a logon script',
  }),
  WriteDacl: Object.freeze({
    targets: ['user', 'group', 'computer', 'container', 'ou', 'domain'],
    domain_only: false,
    abuse: 'rewrite the DACL and grant yourself whatever you actually wanted',
  }),
  WriteOwner: Object.freeze({
    targets: ['user', 'group', 'computer', 'container', 'ou'],
    domain_only: false,
    abuse: 'take ownership, and an owner can always rewrite the DACL',
  }),
  WriteProperty: Object.freeze({
    targets: ['user', 'group', 'computer'],
    domain_only: false,
    abuse: 'write a single attribute - msDS-KeyCredentialLink is a shadow credential',
  }),
  Self: Object.freeze({
    targets: ['group'],
    domain_only: false,
    abuse: 'the raw validated write that self-membership is built on',
  }),
  'Ext-User-Force-Change-Password': Object.freeze({
    targets: ['user'],
    domain_only: false,
    abuse: 'set the target password without knowing the old one',
  }),
  'Ext-Self-Self-Membership': Object.freeze({
    targets: ['group'],
    domain_only: false,
    abuse: 'add yourself to the group',
  }),
  'Ext-Write-Self-Membership': Object.freeze({
    targets: ['group'],
    domain_only: false,
    abuse: 'write the member attribute and add yourself to the group',
  }),
  'Ext-Write-SPN': Object.freeze({
    // USER ONLY, and not by oversight. Writing an SPN onto a COMPUTER and
    // roasting it yields the machine account hash, which is 120 random
    // characters AD rotates itself - uncrackable, so the edge would be a
    // dead end that looks live in BloodHound.
    targets: ['user'],
    domain_only: true,
    abuse: 'write a servicePrincipalName onto the target and kerberoast it (targeted roast)',
    // The only right in the catalog whose abuse REQUIRES the target's password
    // to be crackable: it grants the SPN write and nothing else, so there is no
    // shadow-credential or logon-script fallback. Edges carrying it therefore
    // plant a wordlist password on the target (see pushAcl).
    needs_crackable_target: true,
  }),
  'Ext-ManageCA': Object.freeze({
    // Meaningful ONLY on the CA's own computer object - ESC7 is "manage the
    // certification authority", and a member server that is not a CA has
    // nothing to manage. pickRight therefore never places it on a chain hop
    // (hop_candidate: false); it stays in the catalog because the domain
    // vocabulary carries it and a caller validating a hand-written edge needs
    // it recognised rather than rejected.
    targets: ['computer'],
    domain_only: true,
    hop_candidate: false,
    abuse: 'ESC7 - manage the CA and approve your own request',
  }),
});

/** Groups whose membership IS the endgame. A principal that starts inside one of
 *  these has skipped every edge the designer drew. */
const PRIVILEGED_GROUPS = Object.freeze([
  'Domain Admins', 'Enterprise Admins', 'Administrators', 'Schema Admins',
]);

/**
 * Principals so broad that an ACE naming one hands the whole cohort the endgame
 * on their first shell.
 *
 * NT AUTHORITY\ANONYMOUS LOGON is on the list even though it is not a group a
 * student is "in": an ACE for it is readable pre-authentication, so it is
 * broader than Domain Users, not narrower.
 */
const BROAD_PRINCIPALS = Object.freeze([
  'Authenticated Users', 'Domain Users', 'Everyone', 'Users',
  'NT AUTHORITY\\ANONYMOUS LOGON',
]);

/** Entry points, in the rotation. Each changes the first thirty minutes. */
const ENTRY_POINTS = Object.freeze([
  'anonymous_rpc',
  'user_equals_password',
  'password_in_description',
  'asrep',
  'kerberoast',
  'open_share',
  'web_credential',
]);

/** Where the graph ends. Four genuinely different BloodHound pictures. */
const TERMINUS_KINDS = Object.freeze([
  'dc_computer', 'domain_admins', 'adminsdholder', 'ou_control',
]);

/** How the graph branches between foothold and objective. */
const BRANCHINGS = Object.freeze(['funnel', 'parallel', 'diamond']);

/**
 * Edge types the designer can emit. Every one maps to a producer in PRODUCERS
 * and to a probe kind the post-condition probe implements — assertEdgeType()
 * and evidenceFor() both key off this list, so an entry here with no producer
 * is a load-time-visible mistake rather than a runtime surprise.
 *
 * GROUP MEMBERSHIP IS DELIBERATELY ABSENT. A member of a group inherits
 * everything the group holds, so membership behaves exactly like an edge — but
 * it is composer-owned data (principals.groups[].members and
 * principals.users[].groups), not something this module writes. Modelling it as
 * an emittable edge would give two components write access to one fact.
 * findUnintendedShortcuts() still walks it, as an implicit edge, because a
 * nested group that short-circuits the chain is one of the failure modes this
 * component exists to catch.
 */
const EDGE_TYPES = Object.freeze([
  'acl', 'kerberoast', 'delegation', 'adcs_esc1',
]);

/** Things the ENTRY plants before edge 0. Not edges: nothing in the graph
 *  points at them, they are how the student gets a first credential at all. */
const PLANT_KINDS = Object.freeze([
  'anonymous_acl', 'ad_description', 'ad_password', 'asrep_flag', 'share_file',
]);

/** The curated pattern library. Free-form random edges make graphs that are
 *  unsolvable, uninstructive, or both; these three are the shapes an instructor
 *  can actually teach against. */
const PATTERNS = Object.freeze(['acl_ladder', 'adcs_esc1', 'delegation_abuse']);

/** Chain hop counts we are willing to ship. Under 3 there is no graph to read;
 *  over 9 a beginner cohort runs out of lab time before the objective. */
const MIN_LENGTH = 3;
const MAX_LENGTH = 9;

/**
 * The domain password policy GOAD applies to EVERY lab, from
 * ansible/ad-data.yml at the pinned ref:
 *   { role: 'password_policy', pass_length: "5", complexity: false }
 *
 * This is why `user_equals_password` is shippable at all: with complexity off
 * and a five-character floor, a sAMAccountName really can be its own password.
 * It also bounds the entry — a sam shorter than five characters cannot be its
 * own password, and the play would fail on win_domain_user rather than on
 * anything we could see.
 */
const POLICY_MIN_PASSWORD_LEN = 5;

/**
 * Weak-but-policy-legal passwords for the credentials a student is MEANT to
 * crack (AS-REP and Kerberoast hashes). They have to be in a wordlist for the
 * exercise to work at all, and they have to clear the five-character floor
 * above. Deterministically chosen, never random.
 */
const CRACKABLE_PASSWORDS = Object.freeze([
  'Summer2024', 'Password123', 'Welcome2024', 'Chang3me', 'Autumn2023',
  'Letmein123', 'Spring2024', 'Qwerty12345', 'Winter2023', 'Football99',
]);

/**
 * PRODUCERS — for every edge type and plant kind, the role that actually makes
 * it and the exact item keys that role reads.
 *
 * `kind: 'manifest'` roles are validated through goad-role-manifest.getRole():
 * the role must exist, must not be never_emit, and the item_vars we hand the
 * composer must cover its required_item_keys exactly.
 *
 * `kind: 'core'` roles are the ones the vendored manifest deliberately does NOT
 * cover: the manifest vendors ansible/roles/vulns (29) and ansible/roles/security
 * (9) only, because those are the roles a GENERATOR chooses per host. The core
 * roles below are not chosen — every lab runs them, over data that lives in
 * config.json itself. They are recorded here with their config path so the
 * composer knows where to write, and each one names the vendored or upstream
 * evidence it is grounded in rather than being asserted from memory.
 */
const PRODUCERS = Object.freeze({
  // ── core (config.json data, not a per-host role choice) ────────────────────
  acl: Object.freeze({
    kind: 'core',
    role: 'acl',
    // The manifest DOES record this role: acl_rights_domain.source /
    // .vars_key are read off ansible/roles/acl/tasks/main.yml.
    evidence: 'goad-role-manifest acl_rights_domain.source',
    config_path: 'lab.domains.<fqdn>.acls.<item>',
    item_keys: ACL_ITEM_KEYS,
    probe_role: 'acl',
  }),
  onlyusers: Object.freeze({
    kind: 'core',
    role: 'onlyusers',
    evidence: 'ansible/ad-data.yml -> roles/ad, over lab.domains[*].users',
    config_path: 'lab.domains.<fqdn>.users.<sam>',
    item_keys: [],
    probe_role: 'onlyusers',
  }),
  ps: Object.freeze({
    kind: 'core',
    role: 'ps',
    // AS-REP and delegation are not expressible in config.json at all: upstream
    // plants them with freeform ad/<LAB>/scripts/*.ps1 run by roles/ps. The
    // probe module says the same thing about its `extra` option — an undeclared
    // edge is an unprobed edge, so these MUST carry an evidence_probe.
    evidence: 'ansible/roles/ps over lab.hosts[*].scripts (freeform PowerShell)',
    config_path: 'lab.hosts.<host>.scripts',
    item_keys: [],
    probe_role: 'ps',
  }),
  // ── manifest roles (a per-host choice, validated against the vendor) ───────
  'vulns/files': Object.freeze({
    kind: 'manifest',
    role: 'vulns/files',
    config_path: 'lab.hosts.<host>.vulns_vars.files.<item>',
    probe_role: 'files',
  }),
  'vulns/openshares': Object.freeze({
    kind: 'manifest',
    role: 'vulns/openshares',
    config_path: 'lab.hosts.<host>.vulns (flag role, no vars)',
    probe_role: 'openshares',
  }),
  'vulns/adcs_templates': Object.freeze({
    kind: 'manifest',
    role: 'vulns/adcs_templates',
    config_path: 'lab.hosts.<host>.vulns_vars.adcs_templates.<item>',
    probe_role: 'adcs_templates',
  }),
});

// ─── errors ────────────────────────────────────────────────────────────────

/**
 * A compile error. Modelled on goad-lab-validate.assertLabCompiles(): status
 * 409 so the HTTP skin does not have to translate, `code` so a caller can
 * branch, and `link` naming the specific broken thing — the edge id, the
 * principal, the right — because these are read by an instructor in a toast,
 * not by whoever wrote this file.
 */
class ChainCompileError extends Error {
  constructor(code, message, link) {
    super(message);
    this.name = 'ChainCompileError';
    this.code = code;
    this.link = link === undefined ? null : link;
    this.status = 409;
  }
}

function fail(code, message, link) {
  throw new ChainCompileError(code, message, link);
}

// ─── the two vocabulary guards, deliberately not merged ────────────────────

/**
 * A right must be in the vocabulary FOR ITS CONTEXT, byte for byte.
 *
 * This throws rather than warning because of the failure mode described at the
 * top of the file: upstream's ordinal Array.Contains never matches a miscased
 * or out-of-context right, no ACE is written, and Ansible prints GREEN. There
 * is no later signal. 'genericall', 'GENERICALL', and a host-context
 * Ext-ManageCA are all indistinguishable from a correct idempotent run once the
 * play has finished, so the string has to be right BEFORE it ships.
 */
function assertAclRight(right, context, link) {
  const vocab = aclRights(context); // throws on a bad context, which is our bug
  if (typeof right !== 'string' || right === '') {
    fail('ACL_RIGHT_MISSING',
      `attack chain: an ACL edge has no right. roles/${context === 'domain' ? 'acl' : 'vulns/acls'} `
      + 'writes no ACE for an empty right and the task still reports green.', link);
  }
  if (isAclRight(right, context)) return right;

  // Separate the two ways this goes wrong, because the remedies differ.
  const otherContext = context === 'domain' ? 'host' : 'domain';
  if (isAclRight(right, otherContext)) {
    fail('ACL_RIGHT_WRONG_CONTEXT',
      `attack chain: '${right}' is a ${otherContext}-context right used in a ${context}-context `
      + `ACL. roles/${context === 'domain' ? 'acl' : 'vulns/acls'} does not carry it in its own `
      + '$aclExtendValues literal, so it matches nothing, writes NO ACE, and the Ansible task '
      + `still reports green. Use a right from the ${context} vocabulary, or move the edge to a `
      + `${otherContext}-context ACL.`, link);
  }
  const lowered = vocab.standard.concat(vocab.extended)
    .filter((r) => r.toLowerCase() === String(right).toLowerCase());
  if (lowered.length > 0) {
    fail('ACL_RIGHT_MISCASED',
      `attack chain: '${right}' is miscased - the ${context} vocabulary spells it `
      + `'${lowered[0]}'. Upstream matches with .NET Array.Contains under the ordinal comparer, `
      + 'so the miscased string writes NO ACE and the task reports green. Nothing downstream '
      + 'will ever tell you.', link);
  }
  fail('ACL_RIGHT_UNKNOWN',
    `attack chain: '${right}' is not in the ${context} ACL vocabulary `
    + `(${vocab.standard.length} standard + ${vocab.extended.length} extended, from `
    + `${vocab.source}). An unrecognised right writes NO ACE and reports green.`, link);
  return right; // unreachable; keeps the signature honest for callers
}

/**
 * Inheritance must be in the enum.
 *
 * NOTE THE OPPOSITE FAILURE MODE from assertAclRight above, and do not fold the
 * two together. `$inheritance` is cast to
 * [System.DirectoryServices.ActiveDirectorySecurityInheritance]; that cast is
 * case-INSENSITIVE and THROWS on an unknown value. So a bad inheritance is a
 * LOUD deploy-time failure, not a silent no-op — but 'Descendants' still fails,
 * because Microsoft spells it 'Descendents' and the cast is not
 * spelling-forgiving. We compare case-insensitively (matching the cast) and
 * normalise to the manifest's spelling on the way out.
 */
function assertInheritance(value, link) {
  const wanted = String(value == null ? '' : value);
  const hit = INHERITANCE_VALUES.filter((v) => v.toLowerCase() === wanted.toLowerCase());
  if (hit.length === 1) return hit[0];
  fail('ACL_INHERITANCE_UNKNOWN',
    `attack chain: inheritance '${wanted}' is not a `
    + 'System.DirectoryServices.ActiveDirectorySecurityInheritance value '
    + `(${INHERITANCE_VALUES.join(', ')}). Unlike a bad right, this one THROWS on the cast and `
    + 'kills the play on the lane - catch it here instead. Note the spelling: Descendents.',
  link);
  return wanted;
}

/**
 * Load-time self-check: RIGHT_CATALOG must agree with the vendored manifest.
 *
 * The catalog carries SEMANTICS (which objects a right is worth putting on);
 * the manifest carries the VOCABULARY (which strings each role accepts). If a
 * re-vendor moves a right between the two lists, the catalog's `domain_only`
 * flag would quietly become wrong and this module would start emitting
 * host-context ACLs that write no ACE. Failing at require() time is the only
 * honest option: there is no degraded mode for a generator that cannot tell
 * which vocabulary it is writing into.
 */
function assertCatalogMatchesManifest() {
  for (const right of Object.keys(RIGHT_CATALOG)) {
    const entry = RIGHT_CATALOG[right];
    if (!isAclRight(right, 'domain')) {
      throw new Error(`goad-attack-chain: RIGHT_CATALOG lists '${right}', which the vendored `
        + 'manifest does not carry in the DOMAIN vocabulary. Re-vendor drift - fix the catalog.');
    }
    const inHost = isAclRight(right, 'host');
    if (entry.domain_only === inHost) {
      throw new Error(`goad-attack-chain: RIGHT_CATALOG says '${right}' domain_only=`
        + `${entry.domain_only}, but the manifest ${inHost ? 'does' : 'does not'} carry it in the `
        + 'HOST vocabulary. The two vocabularies moved; fix the catalog rather than the manifest.');
    }
    for (const target of entry.targets) {
      if (NODE_KINDS.indexOf(target) === -1) {
        throw new Error(`goad-attack-chain: RIGHT_CATALOG '${right}' targets unknown node kind `
          + `'${target}'.`);
      }
    }
  }
}
assertCatalogMatchesManifest();

/**
 * Load-time self-check: no producer this designer can name is a role the
 * manifest says never to emit.
 *
 * vulns/shares and vulns/adcs_esc7 are both structurally broken upstream - the
 * first iterates a dict it is never given, the second's PSPKI guard is inverted
 * - and both report green. Putting one in PRODUCERS would make every edge built
 * on it a guaranteed silent no-op, so the mistake is caught at require() time
 * rather than on a lane. This is what makes the never_emit branch of
 * assertProducer() a backstop rather than the only line of defence.
 */
function assertProducersAreEmittable() {
  for (const key of Object.keys(PRODUCERS)) {
    const spec = PRODUCERS[key];
    if (spec.kind !== 'manifest') continue;
    const role = getRole(spec.role);
    if (!role) {
      throw new Error(`goad-attack-chain: PRODUCERS['${key}'] names '${spec.role}', which the `
        + 'vendored role manifest does not carry.');
    }
    if (role.never_emit) {
      throw new Error(`goad-attack-chain: PRODUCERS['${key}'] names '${spec.role}', which the `
        + 'manifest marks never_emit. Every edge built on it would be a silent no-op that '
        + 'reports green.');
    }
  }
}
assertProducersAreEmittable();

// ─── small helpers ─────────────────────────────────────────────────────────

function isObject(v) { return v !== null && typeof v === 'object' && !Array.isArray(v); }
function asArray(v) { return Array.isArray(v) ? v : (v === null || v === undefined ? [] : [v]); }

/** Strip a `DOMAIN\` or `domain.tld\` prefix. GOAD writes principals both ways
 *  in the same file; the acl role resolves `for` with a SamAccountName filter,
 *  so the bare form is the one that matches. */
function bareSam(principal) {
  const s = String(principal == null ? '' : principal);
  const i = s.lastIndexOf('\\');
  return i === -1 ? s : s.slice(i + 1);
}

/** Ids appear in instructor output and in test assertions, so they must be
 *  stable and readable. Same normalisation the probe uses for its own ids. */
function idPart(s) {
  return String(s == null ? '' : s).trim().replace(/\s+/g, '_').replace(/:/g, '-');
}

/**
 * An avalanche step over hashStr's output.
 *
 * hashStr is `h = h*31 + c (mod 2^32)`. Modulo a small power of two, 31 is -1,
 * so the low bits are barely more than an alternating sum of the character
 * codes — and `${salt}:${i}` varies only in a trailing digit, which makes the
 * successive draws below correlated rather than independent. Measured on this
 * shuffle, that reached exactly HALF the permutations (60 of 120 for five
 * items, 12 of 24 for four — a parity invariant, the classic signature of
 * correlated low bits) and 685 of 40,320 for eight. Since shape variety is the
 * one thing this designer exists to produce, a shuffle that cannot reach half
 * the orderings is a defect in the headline feature.
 */
function mix32(h) {
  let x = h >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  x = Math.imul(x ^ (x >>> 16), 0x45d9f3b) >>> 0;
  return (x ^ (x >>> 16)) >>> 0;
}

/**
 * Deterministic Fisher-Yates. hashStr is FNV-ish and stable across processes
 * and Node versions, so the same (runId, salt, list) always yields the same
 * permutation — which is what makes the whole design reproducible.
 */
function seededShuffle(runId, salt, list) {
  const out = list.slice();
  for (let i = out.length - 1; i > 0; i -= 1) {
    const j = mix32(hashStr(runId, `${salt}:${i}`)) % (i + 1);
    const tmp = out[i];
    out[i] = out[j];
    out[j] = tmp;
  }
  return out;
}

/** True when `to` is written as a distinguished name rather than a
 *  sAMAccountName. The acl role tries get-acl on the raw string first and only
 *  falls back to a SamAccountName lookup, so both forms are legal — but which
 *  one a value is decides whether it has to exist as a principal. */
function isDn(value) {
  return /(^|,)\s*(CN|OU|DC)=/i.test(String(value == null ? '' : value));
}

// ─── principal pool ────────────────────────────────────────────────────────

/**
 * Index the composer's principals for one domain.
 *
 * Everything is sorted before it is shuffled. An unsorted Object.keys() order
 * is stable in practice but is not part of any contract, and a pool whose order
 * came from insertion would make the same seed produce a different chain
 * depending on how the composer happened to build the object.
 */
function indexPrincipals(principals, domainFqdn) {
  const p = isObject(principals) ? principals : {};
  // A null/absent domain means "every principal in the pool", NOT "none". The
  // difference matters: silently filtering everything out would leave the
  // shortcut checks passing vacuously, which is the exact failure they exist to
  // catch. Principals that carry no domain of their own always belong.
  const inDomain = (x) => !domainFqdn || !x.domain || x.domain === domainFqdn;
  const users = asArray(p.users).filter(isObject).filter(inDomain)
    .slice().sort((a, b) => String(a.sam).localeCompare(String(b.sam)));
  const groups = asArray(p.groups).filter(isObject).filter(inDomain)
    .slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const ous = asArray(p.ous).filter(isObject).filter(inDomain)
    .slice().sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const bySam = new Map();
  for (const u of users) bySam.set(String(u.sam), u);
  const byGroup = new Map();
  for (const g of groups) byGroup.set(String(g.name), g);
  return { users, groups, ous, bySam, byGroup };
}

// ─── shape planning ────────────────────────────────────────────────────────

/**
 * Which patterns this lab can actually carry.
 *
 * delegation_abuse needs a computer account that is NOT the DC: the abuse is
 * marking a member server trusted for unconstrained delegation and coercing the
 * DC to authenticate to it. On tier S there is one host and it is the DC, so the
 * pattern would degenerate into "the DC delegates to itself" — which is not a
 * lesson, it is a bug that happens to deploy.
 */
function availablePatterns(labIR, domainFqdn) {
  const hosts = asArray(labIR.hosts).filter(isObject);
  const members = hosts.filter((h) => h.type !== 'dc' && (!h.domain || h.domain === domainFqdn));
  return PATTERNS.filter((id) => id !== 'delegation_abuse' || members.length > 0);
}

/**
 * The seeded plan. This is the whole "vary shape, not strings" decision, in one
 * place, so a reader can see every axis at once.
 *
 * Each draw uses its OWN salt. Sharing a salt across two draws correlates them —
 * every lab with a long chain would also get the same terminus — and the point
 * of the exercise is that the axes move independently.
 */
function planShape(runId, ctx) {
  const patterns = (ctx && ctx.patterns && ctx.patterns.length) ? ctx.patterns : PATTERNS;
  const plan = {
    pattern: hashPick(runId, 'chain:pattern', patterns),
    entry: hashPick(runId, 'chain:entry', ENTRY_POINTS),
    terminus: hashPick(runId, 'chain:terminus', TERMINUS_KINDS),
    branching: hashPick(runId, 'chain:branching', BRANCHINGS),
    length: hashInt(runId, 'chain:length', MIN_LENGTH, MAX_LENGTH),
    decoys: hashInt(runId, 'chain:decoys', 1, 3),
    notes: [],
  };

  // delegation_abuse ends by capturing the DC's own TGT through unconstrained
  // delegation. Any other terminus would mean planting the delegation and then
  // not using it.
  if (plan.pattern === 'delegation_abuse' && plan.terminus !== 'dc_computer') {
    plan.notes.push(`terminus forced to dc_computer by pattern delegation_abuse `
      + `(was ${plan.terminus})`);
    plan.terminus = 'dc_computer';
  }

  // ESC1 AND THE HARDCODED Domain Users GRANT.
  // roles/vulns/adcs_templates publishes with -Identity "{{domain}}\Domain Users",
  // so EVERY domain user can enrol the template. That makes an ESC1 edge
  // traversable from the foothold no matter where it sits in the graph. Put it
  // at edge 0 and it is the intended first move; put it anywhere later and it is
  // a shortcut past every edge before it. So it is pinned to edge 0 — which
  // means the entry cannot also consume edge 0.
  if (plan.pattern === 'adcs_esc1' && plan.entry === 'kerberoast') {
    const others = ENTRY_POINTS.filter((e) => e !== 'kerberoast');
    const swapped = hashPick(runId, 'chain:entry:esc1', others);
    plan.notes.push('entry remapped from kerberoast: pattern adcs_esc1 owns edge 0, because '
      + 'roles/vulns/adcs_templates grants enrolment to Domain Users unconditionally and an '
      + 'ESC1 edge anywhere later is a shortcut past everything before it');
    plan.entry = swapped;
  }

  // diamond needs a spine long enough to split and re-converge inside; parallel
  // splits at the foothold and needs somewhere to converge.
  if (plan.branching === 'diamond' && plan.length < 4) {
    plan.notes.push(`branching downgraded from diamond to funnel: length ${plan.length} `
      + 'has no room to split and re-converge');
    plan.branching = 'funnel';
  } else if (plan.branching === 'parallel' && plan.length < 3) {
    plan.notes.push(`branching downgraded from parallel to funnel: length ${plan.length}`);
    plan.branching = 'funnel';
  }
  return plan;
}

/**
 * Clamp the plan to the principals the composer actually produced.
 *
 * Erroring on a small pool would be wrong — the composer sizes the org from the
 * client profile, and a 12-person company legitimately has few groups. Clamping
 * with a recorded reason keeps the chain shippable and keeps the reason visible.
 * We DO error below the floor: a 2-hop graph is not a graph.
 */
function fitShape(plan, pool) {
  const shape = Object.assign({}, plan, { notes: plan.notes.slice() });
  // Nodes needed: one foothold user, (length - 1) intermediates, one terminus
  // that comes from outside the pool, plus one more for a branch.
  const branchExtra = shape.branching === 'funnel' ? 0 : 1;
  const supply = pool.users.length + pool.groups.length;
  const needed = 1 + (shape.length - 1) + branchExtra;
  if (supply < 1 + (MIN_LENGTH - 1)) {
    fail('PRINCIPAL_POOL_TOO_SMALL',
      `attack chain: the shortest shippable chain is ${MIN_LENGTH} hops and needs `
      + `${1 + (MIN_LENGTH - 1)} principals, but labIR.principals carries ${pool.users.length} `
      + `user(s) and ${pool.groups.length} group(s) in this domain. The composer must generate `
      + 'more principals before a chain can be designed over them.', 'labIR.principals');
  }
  if (needed > supply) {
    const fitted = Math.max(MIN_LENGTH, supply - branchExtra);
    shape.notes.push(`length clamped ${shape.length} -> ${fitted}: the principal pool carries `
      + `${supply} usable principals`);
    shape.length_requested = shape.length;
    shape.length = fitted;
    if (shape.branching !== 'funnel' && shape.length < (shape.branching === 'diamond' ? 4 : 3)) {
      shape.notes.push(`branching downgraded to funnel after the length clamp`);
      shape.branching = 'funnel';
    }
  }
  return shape;
}

/**
 * The abstract graph, before any principal is bound to it.
 *
 * `s0..sL` is the spine; `length` is the number of hops on the LONGEST route.
 * Both branchings add exactly ONE alternate node that parallels one spine node,
 * so both routes are the same length. That is deliberate: an alternate route
 * one hop shorter than the spine is not a branch, it is a shortcut, and
 * findUnintendedShortcuts() would (correctly) reject it.
 *
 *   funnel    s0 -> s1 -> ... -> sL
 *   parallel  the split is at the FOOTHOLD: two genuinely different first moves
 *             that converge at s2
 *   diamond   the split is mid-chain, after the student has committed
 */
function buildSkeleton(runId, shape) {
  const nodes = [];
  for (let i = 0; i <= shape.length; i += 1) nodes.push({ id: `s${i}`, depth: i, spine: true });
  const edges = [];
  for (let i = 0; i < shape.length; i += 1) edges.push({ from: `s${i}`, to: `s${i + 1}` });

  let branchDepth = null;
  if (shape.branching === 'parallel') {
    branchDepth = 0;
    nodes.push({ id: 'alt', depth: 1, spine: false, alternate_of: 's1' });
    edges.push({ from: 's0', to: 'alt' }, { from: 'alt', to: 's2' });
  } else if (shape.branching === 'diamond') {
    // Split as near the middle as the spine allows, never at the foothold (that
    // is what `parallel` is) and never at the last hop (there would be nothing
    // to converge into).
    branchDepth = 1 + hashInt(runId, 'chain:branch_depth', 0, Math.max(0, shape.length - 4));
    nodes.push({ id: 'alt', depth: branchDepth + 1, spine: false, alternate_of: `s${branchDepth + 1}` });
    edges.push(
      { from: `s${branchDepth}`, to: 'alt' },
      { from: 'alt', to: `s${branchDepth + 2}` });
  }
  return { nodes, edges, branch_depth: branchDepth };
}

/**
 * Decide what kind of object sits at each spine position.
 *
 * s0 is always a user (a credential is a user), sL is fixed by the terminus,
 * and everything between alternates on a seeded coin with one hard rule: at
 * least one group somewhere in the middle. A chain of nothing but user->user
 * ForceChangePassword edges is a straight line in BloodHound and teaches one
 * primitive; the group hops are where students learn that owning a GROUP is
 * owning everything the group holds.
 */
function planNodeKinds(runId, shape, skeleton, terminusKind) {
  const kinds = {};
  kinds.s0 = 'user';
  kinds[`s${shape.length}`] = ({
    dc_computer: 'computer',
    domain_admins: 'group',
    adminsdholder: 'container',
    ou_control: 'ou',
  })[terminusKind];
  let groupCount = 0;
  for (let i = 1; i < shape.length; i += 1) {
    const kind = (hashStr(runId, `chain:kind:${i}`) % 100) < 45 ? 'group' : 'user';
    kinds[`s${i}`] = kind;
    if (kind === 'group') groupCount += 1;
  }
  if (groupCount === 0 && shape.length > 1) {
    // Deterministic repair rather than a re-draw: re-drawing would make the
    // whole sequence depend on the outcome of the check.
    const at = 1 + (hashStr(runId, 'chain:kind:repair') % Math.max(1, shape.length - 1));
    kinds[`s${Math.min(at, shape.length - 1)}`] = 'group';
  }
  const alt = skeleton.nodes.filter((n) => !n.spine)[0];
  if (alt) kinds.alt = kinds[alt.alternate_of];
  return kinds;
}

/**
 * Every right that is a real abuse primitive against `targetKind` in `context`.
 *
 * Three filters, and each one drops a different kind of dead edge:
 *   targets        the right has to mean something on that object class
 *   isAclRight     the right has to be in THIS context's vocabulary, or upstream
 *                  writes no ACE and reports green
 *   hop_candidate  the right has to be abusable on an ARBITRARY object of that
 *                  class, not just on one specific object (Ext-ManageCA)
 * Sorted, so the seeded pick is a function of the seed and not of key order.
 */
function hopCandidates(targetKind, context) {
  return Object.keys(RIGHT_CATALOG)
    .filter((r) => RIGHT_CATALOG[r].targets.indexOf(targetKind) !== -1)
    .filter((r) => RIGHT_CATALOG[r].hop_candidate !== false)
    .filter((r) => isAclRight(r, context))
    .sort();
}

/**
 * Pick the right for one hop.
 *
 * THIS IS THE "WHICH RIGHT AT WHICH DEPTH" AXIS. The chassis ladder always puts
 * ForceChangePassword first and GenericAll last; a student who has seen it once
 * knows what the first edge is before they run SharpHound. Here the candidate
 * set is everything the TARGET KIND can meaningfully carry, and the draw is
 * salted with the depth, so depth 0 is as likely to be a WriteOwner on a group
 * as a ForceChangePassword on a user.
 *
 * `context` is threaded through rather than assumed: the same function has to
 * be usable for a host-context edge, and the two vocabularies differ.
 */
function pickRight(runId, depth, targetKind, context, link) {
  const candidates = hopCandidates(targetKind, context);
  if (candidates.length === 0) {
    fail('EDGE_NO_RIGHT_AVAILABLE',
      `attack chain: no ${context}-context right in the catalog is a real abuse primitive `
      + `against a '${targetKind}'. Either the node kind is wrong or the catalog needs the `
      + 'right added - do not reach for one from the other vocabulary.', link);
  }
  return hashPick(runId, `chain:right:${depth}:${targetKind}`, candidates);
}

/**
 * Inheritance for one hop.
 *
 * Leaf objects (user, group, computer) take 'None': the ACE is on the object
 * itself and there is nothing under it to inherit to. Containers (OU,
 * AdminSDHolder, the domain head) take 'All', because the whole point of an OU
 * terminus is control of the objects INSIDE it - an OU ACE with 'None' grants
 * control of the OU object and nothing a student can use it for.
 *
 * This is not a variation axis on purpose. Inheritance is the field whose bad
 * values THROW on the lane rather than failing silently, so there is nothing to
 * be gained by rolling dice on it.
 */
function inheritanceFor(targetKind) {
  return (targetKind === 'ou' || targetKind === 'container' || targetKind === 'domain')
    ? 'All' : 'None';
}

/** The concrete name an edge writes into `for`/`to`. Users and groups are
 *  sAMAccountNames, computers carry the trailing $, containers and OUs are DNs. */
function nodeTarget(kind, binding) {
  if (kind === 'computer') return binding.sam;
  if (kind === 'container' || kind === 'ou' || kind === 'domain') return binding.dn;
  return binding.sam;
}

// ─── evidence probes ───────────────────────────────────────────────────────

/**
 * Every edge carries the check that proves the ACE really landed.
 *
 * The shape is exactly what goad-postcondition-probe.buildExpectationSet()
 * accepts in `opts.extra`: it Object.assigns the declaration over an id/origin
 * default and then runs makeCheck(), which throws on an unknown `kind` or a
 * missing `run_on`. Matching the acl branch field-for-field means describeCheck()
 * produces the same instructor-facing sentence for a designed edge as it does
 * for one read back out of config.json.
 *
 * `known_right` is COMPUTED, not asserted true. assertAclRight has already run,
 * so it will be true - but writing the literal would mean the probe's own
 * coverage claim depended on our claim rather than on the manifest.
 */
function aclEvidence(edge, ctx) {
  const ext = EXTENDED_RIGHT_ACES[edge.right];
  return {
    id: `chain:${edge.id}`,
    kind: 'acl',
    run_on: ctx.dcHostKey,
    host: ctx.dcHostKey,
    domain: ctx.domainFqdn,
    role: PRODUCERS.acl.probe_role,
    context: 'domain',
    principal: edge.from,
    target: edge.to,
    right: edge.right,
    ad_right: ext ? ext.ad_right : edge.right,
    object_type: ext ? ext.object_type : '',
    inheritance: edge.inheritance,
    known_right: isAclRight(edge.right, 'domain'),
    why: edge.why,
  };
}

/**
 * Build the evidence check, then check the CHECK the same way we check
 * everything else.
 *
 * buildExpectationSet() would reject an unimplemented kind too — but only when
 * a caller eventually builds the set, which may be a deploy later. The probe
 * script reports an unknown kind as a FAILURE rather than a skip, so a design
 * that shipped one would look like a broken lab instead of a broken generator.
 */
function evidenceFor(edge, ctx) {
  const check = buildEvidence(edge, ctx);
  assertProbeKind(check, edge.id);
  return check;
}

/** Fail on a check kind the staged .ps1 does not implement. */
function assertProbeKind(check, link) {
  if (CHECK_KINDS.indexOf(check.kind) === -1) {
    fail('EVIDENCE_KIND_UNIMPLEMENTED',
      `attack chain: evidence kind '${check.kind}' is not implemented by the probe script `
      + `(known: ${CHECK_KINDS.join(', ')}). The probe reports an unknown kind as a FAILURE, not `
      + 'a skip, so this would read as a broken lab rather than a broken generator.', link);
  }
  if (!check.run_on) {
    fail('EVIDENCE_NO_RUN_ON',
      `attack chain: evidence check '${check.id}' names no run_on host, so nothing would ever `
      + 'execute it.', link);
  }
  return check;
}

function buildEvidence(edge, ctx) {
  switch (edge.edge_type) {
    case 'acl':
      return aclEvidence(edge, ctx);
    case 'kerberoast':
      return {
        id: `chain:${edge.id}`,
        kind: 'kerberoast',
        run_on: ctx.dcHostKey,
        host: ctx.dcHostKey,
        domain: ctx.domainFqdn,
        role: PRODUCERS.onlyusers.probe_role,
        user: bareSam(edge.to),
        spns: asArray(edge.created_by.item_vars.spns),
        why: edge.why,
      };
    case 'delegation':
      return {
        id: `chain:${edge.id}`,
        kind: 'delegation',
        run_on: ctx.dcHostKey,
        host: ctx.dcHostKey,
        domain: ctx.domainFqdn,
        role: PRODUCERS.ps.probe_role,
        principal: edge.from,
        delegation: 'unconstrained',
        why: edge.why,
      };
    case 'adcs_esc1':
      // THE HONEST LIMITATION. The probe implements no ADCS-template check, so
      // the strongest true statement available is "the template JSON reached the
      // CA host" - which is exactly the failure that would otherwise be
      // invisible, because New-ADCSTemplate reads the file with Get-Content and
      // a missing file leaves the win_shell task green. Publication itself is
      // NOT proved, and the `why` says so rather than implying more coverage
      // than exists.
      return {
        id: `chain:${edge.id}`,
        kind: 'file',
        run_on: edge.created_by.host,
        host: edge.created_by.host,
        role: PRODUCERS['vulns/adcs_templates'].probe_role,
        path: edge.created_by.item_vars.template_file,
        is_directory: false,
        why: 'the ESC1 template JSON must be on disk: New-ADCSTemplate reads it with '
          + 'Get-Content and publishes nothing if it is missing, and the task still reports '
          + 'green. This proves delivery, NOT publication.',
      };
    default:
      return fail('EDGE_TYPE_UNKNOWN',
        `attack chain: edge type '${edge.edge_type}' is not one of ${EDGE_TYPES.join(', ')}.`,
        edge.id);
  }
}

/**
 * Validate that the producer named on an edge could actually make it.
 *
 * For a manifest role this is the real check: the role must exist, must not be
 * never_emit (vulns/shares and vulns/adcs_esc7 are structurally broken upstream
 * - emitting one is a guaranteed silent no-op), and the item_vars we hand the
 * composer must cover every key the role reads. A role listed with a vars entry
 * that is missing a key iterates and then interpolates undefined.
 */
function assertProducer(created, link) {
  const spec = PRODUCERS[created.role];
  if (!spec) {
    // Three different mistakes, three different remedies, so they are three
    // different errors rather than one shrug.
    const known = getRole(created.role);
    if (known && known.never_emit) {
      fail('EDGE_ROLE_NEVER_EMIT',
        `attack chain: '${created.role}' is a real role but the vendored manifest marks it `
        + 'never_emit - it is broken upstream and produces nothing while reporting green. There '
        + 'is no edge worth building on it.', link);
    }
    if (known) {
      fail('EDGE_ROLE_NOT_A_PRODUCER',
        `attack chain: '${created.role}' exists in the vendored manifest but is not one of this `
        + `designer's producers (${Object.keys(PRODUCERS).join(', ')}). Add it to PRODUCERS with `
        + 'its config path and probe role, or pick a producer that already carries an '
        + 'evidence_probe.', link);
    }
    fail('EDGE_ROLE_UNKNOWN',
      `attack chain: edge names producer '${created.role}', which is neither in PRODUCERS nor in `
      + 'the vendored role manifest. An invented role reaches ansible as '
      + 'include_role: name=vulns/<typo> and fails the whole play on the lane, long after '
      + 'generation.', link);
  }
  if (spec.kind === 'manifest') {
    const role = getRole(spec.role);
    if (!role) {
      fail('EDGE_ROLE_UNKNOWN',
        `attack chain: '${spec.role}' is not in the vendored role manifest.`, link);
    }
    if (role.never_emit) {
      fail('EDGE_ROLE_NEVER_EMIT',
        `attack chain: '${spec.role}' is marked never_emit in the vendored manifest - it is `
        + 'broken upstream and produces nothing while reporting green. Pick another producer.',
      link);
    }
    const have = Object.keys(created.item_vars || {});
    const missing = role.required_item_keys.filter((k) => have.indexOf(k) === -1);
    if (missing.length > 0) {
      fail('EDGE_ROLE_MISSING_KEYS',
        `attack chain: producer '${spec.role}' reads ${role.required_item_keys.join(', ')} but `
        + `the edge supplies ${have.join(', ') || '(nothing)'} - missing ${missing.join(', ')}. `
        + 'The role would iterate the item and interpolate an undefined value.', link);
    }
  } else if (spec.item_keys && spec.item_keys.length > 0) {
    const have = Object.keys(created.item_vars || {}).sort();
    const missing = spec.item_keys.filter((k) => have.indexOf(k) === -1);
    if (missing.length > 0) {
      fail('EDGE_ROLE_MISSING_KEYS',
        `attack chain: core producer '${spec.role}' reads ${spec.item_keys.join(', ')} but the `
        + `edge supplies ${have.join(', ') || '(nothing)'} - missing ${missing.join(', ')}.`, link);
    }
  }
  return spec;
}

/**
 * A targeted-Kerberoast edge is only walkable if the roasted hash cracks.
 *
 * Ext-Write-SPN grants the SPN write and nothing else - no shadow credential,
 * no logon script - so unlike GenericWrite it has no fallback, and against a
 * strong password it is a dead edge BloodHound still draws.
 *
 * This runs on DECOYS as well as on chain edges, and that is deliberate: a decoy
 * has to be WALKABLE to teach anything. A decoy the student cannot even traverse
 * dead-ends in the wrong place - at the crack, not at the destination - and the
 * lesson ("check the outbound edges before you spend an hour") never lands.
 */
function addCrackablePrerequisite(ctx, runId, edge, toBinding, taken) {
  const spec = RIGHT_CATALOG[edge.right];
  if (!spec || !spec.needs_crackable_target || toBinding.kind !== 'user') return edge;
  edge.prerequisites = asArray(edge.prerequisites).concat([{
    role: 'onlyusers',
    host: ctx.dcHostKey,
    item: toBinding.sam,
    item_vars: {
      password: pickPassword(runId, `chain:targeted:${edge.id}`, CRACKABLE_PASSWORDS, taken),
    },
  }]);
  for (const pre of edge.prerequisites) assertProducer(pre, edge.id);
  return edge;
}

/** Build one ACL edge, running both vocabulary guards on the way through. */
function makeAclEdge(ctx, opts) {
  const link = opts.id;
  const right = assertAclRight(opts.right, opts.context || 'domain', link);
  const inheritance = assertInheritance(opts.inheritance, link);
  const label = opts.label || idPart(`${opts.right}_${bareSam(opts.from)}_${bareSam(opts.to)}`);
  const edge = {
    id: opts.id,
    from: opts.from,
    to: opts.to,
    edge_type: 'acl',
    right,
    inheritance,
    depth: opts.depth,
    target_kind: opts.targetKind,
    why: `${RIGHT_CATALOG[right].abuse} (${opts.targetKind})`,
    created_by: {
      role: 'acl',
      host: ctx.dcHostKey,
      item: label,
      item_vars: { for: opts.from, to: opts.to, right, inheritance },
    },
  };
  assertProducer(edge.created_by, link);
  edge.evidence_probe = evidenceFor(edge, ctx);
  return edge;
}

// ─── graph identity and reachability ───────────────────────────────────────

/**
 * Canonical node identity.
 *
 * AD is case-insensitive for both sAMAccountNames and DNs and GOAD relies on it
 * (north.sevenkingdoms.local is declared with the path `DC=North,...`), so the
 * graph has to be too. A case-sensitive compare here would report a chain
 * unsolvable because one edge said `Domain Admins` and the next said
 * `DOMAIN ADMINS` - both of which AD resolves to the same object.
 */
function nodeKey(value) {
  const s = String(value == null ? '' : value).trim();
  return isDn(s) ? normalizeDn(s) : bareSam(s).toLowerCase();
}

/** Adjacency from a flat edge list. */
function adjacency(edges) {
  const out = new Map();
  for (const e of edges) {
    const k = nodeKey(e.from);
    if (!out.has(k)) out.set(k, []);
    out.get(k).push(nodeKey(e.to));
  }
  return out;
}

/** Hop count of the shortest route, or null when there is none. */
function shortestPath(edges, from, to) {
  const adj = adjacency(edges);
  const start = nodeKey(from);
  const goal = nodeKey(to);
  if (start === goal) return 0;
  const seen = new Set([start]);
  let frontier = [start];
  let hops = 0;
  while (frontier.length > 0) {
    hops += 1;
    const next = [];
    for (const node of frontier) {
      for (const peer of (adj.get(node) || [])) {
        if (peer === goal) return hops;
        if (!seen.has(peer)) { seen.add(peer); next.push(peer); }
      }
    }
    frontier = next;
  }
  return null;
}

/** Everything reachable from a set of roots. */
function reachableFrom(edges, roots) {
  const adj = adjacency(edges);
  const seen = new Set(asArray(roots).map(nodeKey));
  const queue = Array.from(seen);
  while (queue.length > 0) {
    const node = queue.shift();
    for (const peer of (adj.get(node) || [])) {
      if (!seen.has(peer)) { seen.add(peer); queue.push(peer); }
    }
  }
  return seen;
}

/**
 * The shortest route as a NODE SEQUENCE rather than a hop count.
 *
 * A hop count says a shortcut exists; the sequence says WHICH edges make it,
 * which is the difference between a checker that fails and a generator that can
 * repair itself. The repair loop below walks this list to decide whether the
 * culprit is a decoy it can prune or a binding it can re-site, and the failure
 * message prints it so an instructor can see the short path rather than being
 * told one exists.
 */
function shortestPathNodes(edges, from, to) {
  const adj = adjacency(edges);
  const start = nodeKey(from);
  const goal = nodeKey(to);
  if (start === goal) return [start];
  const prev = new Map([[start, null]]);
  let frontier = [start];
  while (frontier.length > 0) {
    const next = [];
    for (const node of frontier) {
      for (const peer of (adj.get(node) || [])) {
        if (prev.has(peer)) continue;
        prev.set(peer, node);
        if (peer === goal) {
          const path = [];
          for (let cur = peer; cur !== null && cur !== undefined; cur = prev.get(cur)) path.unshift(cur);
          return path;
        }
        next.push(peer);
      }
    }
    frontier = next;
  }
  return null;
}

/** Hop distance from one root to everything it can reach. */
function distancesFrom(edges, root) {
  const adj = adjacency(edges);
  const dist = new Map([[nodeKey(root), 0]]);
  let frontier = [nodeKey(root)];
  let hops = 0;
  while (frontier.length > 0) {
    hops += 1;
    const next = [];
    for (const node of frontier) {
      for (const peer of (adj.get(node) || [])) {
        if (dist.has(peer)) continue;
        dist.set(peer, hops);
        next.push(peer);
      }
    }
    frontier = next;
  }
  return dist;
}

// ─── the edge set a student actually has ───────────────────────────────────

/**
 * Group membership as edges — including the two routes that are NOT in
 * principals.groups and that a check reading only that array would miss.
 *
 *   users[].groups          direct membership
 *   groups[].members        a group inside a group: every member of the inner
 *                           one holds everything the outer one holds
 *   hosts[dc].local_admins  a DC's LOCAL Administrators group IS the domain's
 *                           built-in Administrators. Nobody writes "make this
 *                           account a domain admin"; they add it to the DC's
 *                           local administrators and it is one anyway.
 *
 * A member-server local admin is deliberately NOT here: that is control of one
 * box, not of the directory, and it is modelled as a host edge below.
 */
function membershipGraph(labIR, pool, domainFqdn) {
  const memberships = new Map();
  const link = (member, group) => {
    const k = nodeKey(member);
    const g = nodeKey(group);
    if (!k || !g || k === g) return;
    if (!memberships.has(k)) memberships.set(k, []);
    if (memberships.get(k).indexOf(g) === -1) memberships.get(k).push(g);
  };
  for (const u of pool.users) for (const g of asArray(u.groups)) link(u.sam, g);
  for (const g of pool.groups) for (const m of asArray(g.members)) link(m, g.name);
  for (const host of asArray(labIR.hosts).filter(isObject)) {
    if (String(host.type) !== 'dc') continue;
    if (domainFqdn && host.domain && host.domain !== domainFqdn) continue;
    for (const sam of asArray(host.local_admins)) link(sam, 'Administrators');
  }
  return memberships;
}

/** Membership rendered as a flat edge list, so it can be walked with the same
 *  BFS every other edge set uses. */
function membershipEdges(memberships) {
  const out = [];
  for (const [member, groups] of memberships) {
    for (const g of groups) out.push({ from: member, to: g, edge_type: 'implicit_member' });
  }
  return out;
}

/**
 * The composer-owned edges nobody draws: local admin, and cached credentials.
 *
 * WHY THEY BELONG IN THE REACHABILITY MODEL. The question the admin gate asks is
 * "can this Domain Admin be taken more cheaply than the designed chain", and the
 * cheapest real answer in most estates is not an ACL at all — it is that the
 * foothold is a local administrator on a member server, and that server has
 * somebody else's password cached on it. Two hops, no BloodHound ACL edge, and a
 * reachability check that walked only ACLs would report the account unreachable.
 *
 *   local admin on a member box   sam        -> HOSTNAME$
 *   local admin on the DC         sam        -> HOSTNAME$  (and, through
 *                                 membershipGraph, -> Administrators)
 *   a credential cached on a box  HOSTNAME$  -> victim
 */
function hostEdges(labIR, domainFqdn) {
  const out = [];
  for (const host of asArray(labIR.hosts).filter(isObject)) {
    if (domainFqdn && host.domain && host.domain !== domainFqdn) continue;
    const computer = `${host.hostname}$`;
    for (const sam of asArray(host.local_admins)) {
      out.push({ from: sam, to: computer, edge_type: 'implicit_local_admin', host: host.key });
    }
    for (const victim of asArray(host.cached_credentials)) {
      out.push({ from: computer, to: victim, edge_type: 'implicit_cached_credential', host: host.key });
    }
  }
  return out;
}

/**
 * Password reuse as edges, in both directions.
 *
 * Check 3 below reports undeclared reuse as its own finding; this is the same
 * fact expressed as reachability, because a DECLARED reuse is still a route and
 * the admin gate has to count it. Cracking one of the pair hands the student the
 * other, and BloodHound draws nothing.
 */
function sharedPasswordEdges(pool) {
  const byPassword = new Map();
  for (const u of pool.users) {
    const pw = String(u.password == null ? '' : u.password);
    if (!pw) continue;
    if (!byPassword.has(pw)) byPassword.set(pw, []);
    byPassword.get(pw).push(String(u.sam));
  }
  const out = [];
  for (const [, sams] of byPassword) {
    if (sams.length < 2) continue;
    for (const a of sams) {
      for (const b of sams) {
        if (a !== b) out.push({ from: a, to: b, edge_type: 'implicit_shared_password' });
      }
    }
  }
  return out;
}

// ─── the proofs ────────────────────────────────────────────────────────────

/**
 * The foothold is the seam between the website and the directory, so both
 * halves of it are checked here and neither is assumed.
 *
 * AD SIDE  the credential must name a principal the composer actually creates.
 *          A foothold pointing at a sam that is not in labIR.principals is a lab
 *          where the student's first login fails and there is no error anywhere
 *          - the deploy is green, the web app hands out a password, and AD has
 *          never heard of the account.
 * WEB SIDE the credential must be planted somewhere concrete. `planted_at` with
 *          no path is a promise nobody keeps.
 * BOTH     an `ad_password` plant must carry the SAME string the web side hands
 *          out. This is the one that actually bites: two generators each doing
 *          their job correctly, over two different passwords.
 */
function assertFootholdContract(chain, foothold, pool) {
  const link = 'labIR.foothold_credential';
  if (!isObject(foothold) || !foothold.sam) {
    fail('FOOTHOLD_MISSING', 'attack chain: no foothold_credential was produced. chain.start '
      + 'has nothing to reference and the student has no way into the lab.', link);
  }
  if (!pool.bySam.has(String(foothold.sam))) {
    fail('FOOTHOLD_NOT_IN_AD',
      `attack chain: foothold_credential names '${foothold.sam}', which labIR.principals.users `
      + 'does not create. AD would never have heard of the account the website hands out, and '
      + 'nothing in the deploy would report it.', link);
  }
  if (foothold.honoured_by !== 'ad') {
    fail('FOOTHOLD_NOT_HONOURED',
      `attack chain: foothold_credential.honoured_by is '${foothold.honoured_by}', must be 'ad' `
      + '- the directory is what has to accept the password the web side plants.', link);
  }
  const pw = String(foothold.password == null ? '' : foothold.password);
  if (pw.length < POLICY_MIN_PASSWORD_LEN) {
    fail('FOOTHOLD_PASSWORD_TOO_SHORT',
      `attack chain: foothold password is ${pw.length} characters. GOAD sets `
      + `MinPasswordLength=${POLICY_MIN_PASSWORD_LEN} for every lab in ansible/ad-data.yml, so `
      + 'win_domain_user rejects anything shorter and the account is never created.', link);
  }
  const at = isObject(foothold.planted_at) ? foothold.planted_at : {};
  if (!at.path || !at.format) {
    fail('FOOTHOLD_NOT_PLANTED',
      'attack chain: foothold_credential.planted_at needs both a path and a format. A credential '
      + 'the chain references but nothing plants is a lab with no entrance.', link);
  }
  if (nodeKey(chain.start.principal) !== nodeKey(foothold.sam)) {
    fail('CHAIN_START_NOT_FOOTHOLD',
      `attack chain: chain.start references '${chain.start.principal}' but the foothold `
      + `credential is for '${foothold.sam}'. Step 0 must be rooted at the credential the web `
      + 'side plants, or the two halves are two systems.', 'labIR.chain.start');
  }
  const honoured = asArray(chain.start.plants)
    .filter((p) => p.kind === 'ad_password')
    .filter((p) => String((p.item_vars || {}).password) === pw);
  if (honoured.length === 0) {
    fail('FOOTHOLD_NOT_HONOURED',
      `attack chain: no ad_password plant carries the foothold password for '${foothold.sam}'. `
      + 'The website would hand out one string and the directory would be built with another - '
      + 'both halves green, the login broken.', link);
  }
}

/**
 * Prove a route exists from the foothold to the objective over edges the role
 * library can actually create.
 *
 * A generator that emitted a plausible graph and hoped is the failure this
 * whole component exists to prevent: an unsolvable chain deploys perfectly, and
 * the only signal is a cohort of students who never finish.
 */
function proveSolvable(chain, foothold, pool) {
  assertFootholdContract(chain, foothold, pool);

  const edges = asArray(chain.edges);
  if (edges.length === 0) {
    fail('CHAIN_EMPTY', 'attack chain: the design has no edges.', 'labIR.chain.edges');
  }
  const rooted = edges.filter((e) => nodeKey(e.from) === nodeKey(foothold.sam));
  if (rooted.length === 0) {
    fail('CHAIN_START_NOT_ROOTED',
      `attack chain: no edge starts at the foothold '${foothold.sam}'. The student holds a `
      + 'credential the graph does not use.', 'labIR.chain.edges[0]');
  }

  const target = chain.objective.target;
  const hops = shortestPath(edges, foothold.sam, target);
  if (hops === null) {
    // Name the BROKEN LINK rather than saying "unsolvable": the useful fact is
    // which edge the walk could not reach, because that is the one to fix.
    const reached = reachableFrom(edges, [foothold.sam]);
    const orphan = edges.filter((e) => !reached.has(nodeKey(e.from)))[0];
    const detail = orphan
      ? `the walk stops before edge '${orphan.id}' (${orphan.from} -> ${orphan.to}): nothing `
        + `reachable from the foothold holds '${orphan.from}'`
      : `no edge leads to the objective '${target}'`;
    fail('CHAIN_UNSOLVABLE',
      `attack chain: no route from the foothold '${foothold.sam}' to the objective '${target}' `
      + `using only edges the role library can create - ${detail}.`,
      orphan ? orphan.id : 'labIR.chain.objective');
  }
  return hops;
}

/**
 * Passwords the runner must NOT hand to
 * goad-postcondition-probe.assertNoSecrets().
 *
 * THIS IS A REAL CROSS-MODULE CONFLICT, not a loophole. assertNoSecrets scans
 * the whole staged expectation set for any lab secret, because that file lands
 * in C:\Windows\Temp where any authenticated user can read it. With the
 * `user_equals_password` entry the password IS the sAMAccountName - and the
 * sAMAccountName is in every ACL check, every group check and every kerberoast
 * check, because it is the name of the object being asserted about. So the guard
 * matches, and it would refuse to run the probe for the ENTIRE lab.
 *
 * Redacting it is impossible (removing the sam removes the check) and silently
 * weakening assertNoSecrets would break the guarantee for every other lab. The
 * honest answer is that this particular string is not a secret: it is a public
 * identifier that happens to also open the door, which is the entire lesson of
 * that entry point. The runner drops it from the secrets list, and only it.
 *
 * Returns [] for every other entry, so the guard keeps its full strength.
 */
function probeSecretExemptions(foothold) {
  const at = (isObject(foothold) && isObject(foothold.planted_at)) ? foothold.planted_at : {};
  if (at.format !== 'password_equals_samaccountname') return [];
  return [String(foothold.password)];
}

/** The two reasons a principal is allowed to hold privileged membership. */
const ADMIN_REASONS = Object.freeze(['chain_terminus', 'roster_realism']);

/**
 * `principals.declared_admins` in whatever shape it arrives, as a lookup.
 *
 * The contract shape is `[{ sam, reason }]`. A bare string is accepted and read
 * as 'roster_realism' — the STRICTER of the two readings, so a caller that
 * declares carelessly gets the shorter-path gate applied rather than skipped.
 * An unknown reason is rejected outright: silently treating it as
 * 'chain_terminus' would switch off the check, and a typo must never be the
 * thing that decides whether a lab is proven.
 */
function normalizeDeclaredAdmins(value) {
  const out = new Map();
  for (const entry of asArray(value)) {
    const raw = isObject(entry) ? entry : { sam: entry, reason: 'roster_realism' };
    const sam = String(raw.sam == null ? '' : raw.sam);
    if (!sam) continue;
    const reason = String(raw.reason == null ? 'roster_realism' : raw.reason);
    if (ADMIN_REASONS.indexOf(reason) === -1) {
      fail('ADMIN_REASON_UNKNOWN',
        `attack chain: declared admin '${sam}' carries reason '${reason}', which is not one of `
        + `${ADMIN_REASONS.join(', ')}. Reading an unknown reason leniently would switch off the `
        + 'shorter-path gate for that principal, so a typo would silently ship an unproven lab.',
      'labIR.principals.declared_admins');
    }
    const key = nodeKey(sam);
    // First declaration wins, except that chain_terminus is a stronger claim and
    // is allowed to upgrade: the same principal declared twice must not end up
    // exempt by accident of ordering.
    if (!out.has(key) || reason === 'chain_terminus') {
      out.set(key, { sam, reason, domain: raw.domain || null, via: raw.via || null });
    }
  }
  return out;
}

/**
 * The cheap checks that are worth more than half of BloodHound for a pilot.
 *
 * None of these is a misconfiguration - every one of them is a lab that deploys
 * perfectly and teaches nothing, because the designed path is not the path a
 * student takes. They are all pure functions of data we already hold, which is
 * why they run on every design rather than on request.
 *
 * Returns findings; assertNoUnintendedShortcuts() is the throwing skin.
 */
function findUnintendedShortcuts(labIR, chain, options) {
  const opts = options || {};
  const findings = [];
  // chain.domain is one of this module's additive fields, and a normaliser in
  // between (goad-lab-compile.normalizeChain) can legitimately drop it. Recover
  // it from the IR rather than running the checks over an empty pool and
  // reporting all-clear.
  const domainFqdn = chain.domain
    || ((asArray(labIR.domains).filter(isObject).filter((d) => d.is_forest_root)[0]
      || asArray(labIR.domains).filter(isObject)[0] || {}).fqdn)
    || null;
  const pool = indexPrincipals(labIR.principals, domainFqdn);
  // Same recovery, same reason: a chain that has been through a normaliser may
  // have lost its declarations, and the IR is where the composer put them in the
  // first place. The chain wins when it carries any, so a caller can hand us a
  // deliberately empty declaration to test the undeclared case.
  const declaredAdmins = normalizeDeclaredAdmins(
    asArray(chain.declared_admins).length > 0
      ? chain.declared_admins
      : asArray(isObject(labIR.principals) ? labIR.principals.declared_admins : []));
  const declaredBroad = new Set(asArray(chain.declared_broad_principals).map(nodeKey));
  const declaredPairs = new Set(asArray(chain.declared_shared_passwords).map(String));

  const add = (code, message, link, extra) => findings.push(
    Object.assign({ code, message, link }, extra || {}));

  // ── 1. nobody UNDECLARED starts inside the endgame ────────────────────────
  // Transitive, because a nested group is exactly how this gets missed: nobody
  // writes `Domain Admins` next to a user's name, they put the user in Helpdesk
  // and Helpdesk in Domain Admins three lines apart.
  //
  // A DECLARED admin is not a finding here, and that is the policy change this
  // check exists to carry. A real company has domain admins; the composer mints
  // them on purpose and says so. What is fatal is an admin nobody declared,
  // because then neither half can tell a deliberate IT director from an
  // accident — and the check below (6) is what actually protects the exercise.
  const memberships = membershipGraph(labIR, pool, domainFqdn);
  const privileged = new Set(PRIVILEGED_GROUPS.map(nodeKey));
  const reportedPrivileged = new Set();
  for (const [member] of memberships) {
    if (privileged.has(member)) continue;
    if (declaredAdmins.has(member)) continue;
    const seen = new Set([member]);
    const queue = [member];
    while (queue.length > 0) {
      const node = queue.shift();
      for (const parent of (memberships.get(node) || [])) {
        if (privileged.has(parent) && !reportedPrivileged.has(member)) {
          reportedPrivileged.add(member);
          add('SHORTCUT_PRIVILEGED_MEMBERSHIP',
            `'${member}' is already a member of a privileged group (${parent}) - directly or `
            + 'through nesting - and nothing declares it. Every edge the chain draws is '
            + 'decoration: the student holds the endgame as soon as they hold that account. If '
            + 'the membership is deliberate roster realism, the composer must emit it in '
            + "principals.declared_admins with a reason, and it is then held to check 6's "
            + 'shorter-path rule instead of being waved through.',
            `labIR.principals -> ${member}`, { principal: member, via: parent });
        }
        if (!seen.has(parent)) { seen.add(parent); queue.push(parent); }
      }
    }
  }

  // ── 2. no ACE names a principal the whole cohort already is ───────────────
  const acls = isObject(opts.acls) ? opts.acls : (labIR.acls || {});
  for (const fqdn of Object.keys(acls)) {
    for (const label of Object.keys(acls[fqdn] || {})) {
      const acl = acls[fqdn][label] || {};
      const forKey = nodeKey(acl.for);
      const broad = BROAD_PRINCIPALS.filter((b) => nodeKey(b) === forKey);
      if (broad.length > 0 && !declaredBroad.has(forKey)) {
        add('SHORTCUT_BROAD_PRINCIPAL_ACL',
          `the ACL '${label}' grants ${acl.right} on '${acl.to}' to '${acl.for}'. Every student `
          + 'holds that principal from their first shell, so the ACE hands out the endgame '
          + 'before the graph starts. Declare it in chain.declared_broad_principals if it is '
          + 'the entry point, otherwise pick a narrower principal.',
          `labIR.acls.${fqdn}.${label}`);
      }
    }
  }

  // ── 3. no two accounts share a password ──────────────────────────────────
  // Password reuse silently welds two nodes together: crack one and you hold
  // both, and BloodHound draws no edge for it because there is nothing to draw.
  const byPassword = new Map();
  for (const u of pool.users) {
    const pw = String(u.password == null ? '' : u.password);
    if (!pw) continue;
    if (!byPassword.has(pw)) byPassword.set(pw, []);
    byPassword.get(pw).push(String(u.sam));
  }
  for (const [, sams] of byPassword) {
    if (sams.length < 2) continue;
    const pair = sams.slice().sort().join('+');
    if (declaredPairs.has(pair)) continue;
    add('SHORTCUT_SHARED_PASSWORD',
      `${sams.join(', ')} share a password. Cracking one hands the student all of them, and no `
      + 'edge in the graph says so. Declare the pair in chain.declared_shared_passwords if the '
      + 'reuse is the lesson.', `labIR.principals -> ${pair}`);
  }

  // ── 4. no route shorter than the designed one ────────────────────────────
  // The implicit edges are the ones nobody draws: a member of a group inherits
  // everything the group holds, a local administrator owns the box, and a
  // credential cached on that box is the next account for free. All three are
  // edges whether or not anyone wrote them down. Decoys are included because a
  // decoy that happens to be live is not a decoy.
  const implicit = membershipEdges(memberships)
    .concat(hostEdges(labIR, domainFqdn))
    .concat(sharedPasswordEdges(pool));
  const designed = asArray(chain.edges);
  const everything = designed.concat(asArray(chain.decoys)).concat(implicit);
  const designedHops = shortestPath(designed, chain.start.principal, chain.objective.target);
  const actualPath = shortestPathNodes(everything, chain.start.principal, chain.objective.target);
  const actualHops = actualPath === null ? null : actualPath.length - 1;
  if (designedHops !== null && actualHops !== null && actualHops < designedHops) {
    add('SHORTCUT_MEMBERSHIP_BYPASS',
      `the designed path is ${designedHops} hops, but group nesting, local-admin and cached-`
      + `credential grants and the decoys leave a route of ${actualHops}: `
      + `${actualPath.join(' -> ')}. The student's tooling will find the short one, and every `
      + 'edge the designer placed in between is never touched.', 'labIR.chain',
    { hops: actualHops, designed_hops: designedHops, path: actualPath });
  }

  // ── 5. every decoy actually dead-ends ────────────────────────────────────
  const reached = reachableFrom(designed.concat(implicit), [chain.start.principal]);
  for (const decoy of asArray(chain.decoys)) {
    const entered = reached.has(nodeKey(decoy.from));
    const exits = shortestPathNodes(everything, decoy.to, chain.objective.target);
    if (entered && exits !== null) {
      add('SHORTCUT_DECOY_LIVE',
        `decoy '${decoy.id}' (${decoy.from} -> ${decoy.to}) is reachable AND leads to the `
        + `objective in ${exits.length - 1} hop${exits.length === 2 ? '' : 's'} `
        + `(${exits.join(' -> ')}). That is not a decoy, it is a second solution the instructor `
        + 'does not know about.', decoy.id,
      { decoy_id: decoy.id, from: decoy.from, to: decoy.to, path: exits });
    }
  }

  // ── 6. a declared roster admin must not be CHEAP ─────────────────────────
  // The gate this whole declaration mechanism exists to enable, and the one that
  // is actually worth having. A company plausibly has three domain admins; the
  // exercise is ruined only if one of them can be taken in two hops when the
  // designed path is seven. So the question is never "does a Domain Admin
  // exist" — it is "is one of them cheaper than the lesson".
  //
  // 'chain_terminus' admins are exempt: the design ENDS by taking that account,
  // so reachability is the point rather than the problem. Everything else is
  // 'roster_realism' and is held to the rule.
  //
  // Reachability is computed over `everything` — the designed edges, the decoys,
  // group nesting, local-admin grants, cached credentials and password reuse —
  // because a walk over ACLs alone would report a two-hop credential-reuse
  // takeover as unreachable, which is precisely the shortcut that ruins a lab.
  if (designedHops !== null) {
    for (const [key, admin] of declaredAdmins) {
      if (admin.reason === 'chain_terminus') continue;
      if (nodeKey(chain.objective.target) === key) continue;
      const path = shortestPathNodes(everything, chain.start.principal, admin.sam);
      if (path === null) continue;
      const hops = path.length - 1;
      if (hops >= designedHops) continue;
      add('SHORTCUT_ADMIN_TOO_CHEAP',
        `'${admin.sam}' is a declared roster_realism Domain Admin, and the student can reach it `
        + `in ${hops} hop${hops === 1 ? '' : 's'} (${path.join(' -> ')}) while the intended chain `
        + `is ${designedHops} hops long. A company having three domain admins is realistic; one `
        + 'of them being two hops from the foothold when the lesson is seven hops is not a lab, '
        + 'it is a shortcut with an org chart. The composer must demote this principal out of the '
        + 'privileged group and re-emit - widening this check instead would delete the only '
        + 'guarantee that roster realism is safe to ship.',
        `labIR.principals.declared_admins -> ${admin.sam}`,
        { principal: admin.sam, reason: admin.reason, hops, designed_hops: designedHops, path });
    }
  }
  return findings;
}

/** Throwing skin. One error carrying every finding, the same shape
 *  goad-lab-validate.assertLabCompiles() uses for a bad lab definition. */
function assertNoUnintendedShortcuts(labIR, chain, options) {
  const findings = findUnintendedShortcuts(labIR, chain, options);
  if (findings.length === 0) return findings;
  return throwShortcuts(findings);
}

// ─── signature ─────────────────────────────────────────────────────────────

/**
 * The structural fingerprint. Deliberately carries NO names: two labs with
 * identical signatures are the same exercise no matter what the users are
 * called, which is the thing this whole module exists to prevent.
 */
function chainSignature(chain) {
  // Tolerant of a chain that has been through a normaliser: `shape` and
  // `length` are additive fields, and a signature that threw on a round-tripped
  // chain would be useless exactly where a caller most wants to compare two.
  const shape = isObject(chain.shape) ? chain.shape : {};
  const outDegree = new Map();
  for (const e of asArray(chain.edges)) {
    const k = nodeKey(e.from);
    outDegree.set(k, (outDegree.get(k) || 0) + 1);
  }
  let branchingFactor = 0;
  for (const [, n] of outDegree) branchingFactor = Math.max(branchingFactor, n);
  return {
    length: chain.length === undefined ? null : chain.length,
    edges: asArray(chain.edges).length,
    branching: shape.branching === undefined ? null : shape.branching,
    branching_factor: branchingFactor,
    branch_depth: shape.branch_depth === undefined ? null : shape.branch_depth,
    terminus: (chain.objective || {}).kind,
    entry: (chain.start || {}).kind,
    pattern: shape.pattern === undefined ? null : shape.pattern,
    edge_types: asArray(chain.edges).map((e) => e.edge_type),
    rights: asArray(chain.edges).map((e) => e.right || null),
    node_kinds: asArray(chain.edges).map((e) => e.target_kind || null),
    decoys: asArray(chain.decoys).length,
  };
}

/**
 * Did we just re-emit the chassis ladder?
 *
 * A PREFIX match counts. The three chassis all carry the same twelve rights in
 * the same order, and a generated chain is at most nine hops, so an inherited
 * ladder shows up as the first N of those twelve - which is exactly what a
 * student who memorised last cohort's lab would recognise.
 */
function isChassisLadder(chain) {
  const rights = asArray(chain.edges)
    .filter((e) => e.edge_type === 'acl' && e.spine)
    .map((e) => e.right);
  if (rights.length < MIN_LENGTH) return false;
  if (rights.length > CHASSIS_LADDER_RIGHTS.length) return false;
  return rights.every((r, i) => r === CHASSIS_LADDER_RIGHTS[i]);
}

/** Same question about a bare right sequence, used during design so the
 *  perturbation below can run before any edge object exists. */
function rightsAreLadderPrefix(rights) {
  if (rights.length < MIN_LENGTH) return false;
  if (rights.length > CHASSIS_LADDER_RIGHTS.length) return false;
  return rights.every((r, i) => r === CHASSIS_LADDER_RIGHTS[i]);
}

// ─── entry points, credentials and the terminus ─────────────────────────────

/**
 * Passwords for credentials the student is meant to FIND rather than crack.
 *
 * Deliberately NOT from CRACKABLE_PASSWORDS. If the plaintext sitting in an AD
 * description or an open share were also in rockyou, a student who sprays
 * before they enumerate lands on the same account by accident and never
 * discovers the leak - which was the entire lesson of that entry point. These
 * clear the five-character policy floor and would survive an offline crack.
 */
const LEAKED_PASSWORDS = Object.freeze([
  'Tr4nsit-Kestrel-91', 'Marlow.Quay-7723', 'Aster5-Bramble-40',
  'Ledger-Vantage-3318', 'Cobalt.Harrow-6042', 'Wilder-Pinnacle-208',
]);

/** Service classes for a planted SPN. A roastable account with an SPN nobody
 *  would put on a user is a tell; these are the ones a real estate carries. */
const SPN_SERVICES = Object.freeze(['MSSQLSvc', 'HTTP', 'CIFS', 'FTP', 'TERMSRV']);

/** Deterministic password that collides with nothing already in the lab. A
 *  collision would be a shared password, which findUnintendedShortcuts() would
 *  (rightly) reject - so it is avoided at the source rather than discovered. */
function pickPassword(runId, salt, list, taken) {
  const free = list.filter((p) => !taken.has(p));
  if (free.length === 0) {
    fail('PASSWORD_POOL_EXHAUSTED',
      `attack chain: every candidate password is already in use in this lab. Two accounts `
      + 'sharing one welds them together with an edge BloodHound cannot draw.', salt);
  }
  const chosen = hashPick(runId, salt, free);
  taken.add(chosen);
  return chosen;
}

/** The DN of an OU as the acl role would resolve it: `OU=<name>,<parent>`. */
function ouDn(ou, rootDn) {
  return `OU=${ou.name},${ou.path || rootDn}`;
}

/**
 * Bind the objective to a real object.
 *
 * ou_control means "the OU that holds most of the users", not "an OU": control
 * of an empty Marketing OU is a BloodHound edge that owns nobody. If the
 * composer produced no OUs at all the terminus is remapped rather than faked,
 * and the remap is recorded - a chain that silently pointed at a
 * non-existent DN would fail on the lane, where get-acl throws.
 */
function bindTerminus(ctx, shape, pool) {
  switch (shape.terminus) {
    case 'dc_computer':
      return { kind: 'computer', sam: `${ctx.dcHost.hostname}$`, label: 'dc_computer_object' };
    case 'domain_admins':
      return { kind: 'group', sam: 'Domain Admins', label: 'domain_admins' };
    case 'adminsdholder':
      return {
        kind: 'container',
        dn: `CN=AdminSDHolder,CN=System,${ctx.rootDn}`,
        label: 'adminsdholder',
      };
    case 'ou_control': {
      const scored = pool.ous.map((ou) => {
        const dn = ouDn(ou, ctx.rootDn);
        const key = nodeKey(dn);
        const population = pool.users
          .filter((u) => u.path && nodeKey(u.path).indexOf(key) !== -1).length;
        return { ou, dn, population };
      }).sort((a, b) => (b.population - a.population)
        || String(a.ou.name).localeCompare(String(b.ou.name)));
      const best = scored[0];
      return { kind: 'ou', dn: best.dn, label: `ou_${idPart(best.ou.name)}`, population: best.population };
    }
    default:
      return fail('TERMINUS_UNKNOWN',
        `attack chain: terminus '${shape.terminus}' is not one of ${TERMINUS_KINDS.join(', ')}.`,
        'labIR.chain.objective');
  }
}

/**
 * Everything the entry point plants, and the credential it yields.
 *
 * Every entry emits an `ad_password` plant. That is not boilerplate: it is the
 * AD half of the seam. Whatever the website hands out, the directory has to have
 * been built with the same string, and assertFootholdContract() checks exactly
 * that plant against foothold_credential.password.
 */
function planEntry(ctx, shape, pool, footholdUser, taken) {
  const runId = ctx.runId;
  const dc = ctx.dcHostKey;
  const sam = String(footholdUser.sam);
  const userDn = footholdUser.path ? `CN=${sam},${footholdUser.path}` : `CN=${sam},${ctx.rootDn}`;
  const web = ctx.webHost;
  const webKey = web ? web.key : null;
  const plants = [];
  const declaredBroad = [];
  const acls = [];
  let password;
  let plantedAt;
  let how;

  const passwordPlant = () => ({
    kind: 'ad_password',
    role: 'onlyusers',
    host: dc,
    item: sam,
    item_vars: { password },
    // No evidence_probe. The probe stages its expectation set into
    // C:\Windows\Temp, which is traversable by any authenticated user, and
    // goad-postcondition-probe.assertNoSecrets() exists precisely to stop a
    // password reaching it. A credential is verified by USING it, never by
    // asserting its plaintext.
    evidence_probe: null,
    why: 'AD must be built with the same string the web side hands out',
  });

  switch (shape.entry) {
    case 'anonymous_rpc': {
      password = pickPassword(runId, 'entry:pw', LEAKED_PASSWORDS, taken);
      // The two ACEs GOAD-Light plants on tumamoc: a null session can read the
      // domain head, so `description` is legible before authentication.
      // inheritance All on purpose - the grant is worthless on the head object
      // alone, the point is reading the objects underneath it.
      for (const [label, right] of [['anonymous_rpc', 'ReadProperty'], ['anonymous_rpc2', 'GenericExecute']]) {
        const checked = assertAclRight(right, 'domain', label);
        const inheritance = assertInheritance('All', label);
        const ext = EXTENDED_RIGHT_ACES[checked];
        acls.push({
          kind: 'anonymous_acl',
          role: 'acl',
          host: dc,
          item: label,
          item_vars: {
            for: 'NT AUTHORITY\\ANONYMOUS LOGON',
            to: ctx.rootDn,
            right: checked,
            inheritance,
          },
          // These two ACEs ARE the entry point, so they are probed like any
          // other edge. If they silently fail to land the lab has no entrance
          // and every other check still passes.
          evidence_probe: {
            id: `chain:entry:${label}`,
            kind: 'acl',
            run_on: dc,
            host: dc,
            domain: ctx.domainFqdn,
            role: 'acl',
            context: 'domain',
            principal: 'NT AUTHORITY\\ANONYMOUS LOGON',
            target: ctx.rootDn,
            right: checked,
            ad_right: ext ? ext.ad_right : checked,
            object_type: ext ? ext.object_type : '',
            inheritance,
            known_right: isAclRight(checked, 'domain'),
            why: 'without the null-session read there is no enumeration step and no way in',
          },
          why: 'a null session must be able to read the directory, or there is no enumeration '
            + 'step at all',
        });
      }
      plants.push(passwordPlant(), {
        kind: 'ad_description',
        role: 'onlyusers',
        host: dc,
        item: sam,
        item_vars: { description: `Temporary service password: ${password} - rotate before Q3` },
        evidence_probe: null,
        why: 'the plaintext a null-session enumeration walks into',
      });
      plantedAt = { host_key: dc, path: userDn, format: 'ad_description_via_anonymous' };
      declaredBroad.push('NT AUTHORITY\\ANONYMOUS LOGON');
      how = `a null RPC/LDAP session against ${ctx.dcHost.hostname} enumerates the domain and `
        + `reads ${sam}'s description, which carries the password in plaintext`;
      break;
    }
    case 'user_equals_password': {
      // Shippable only because ansible/ad-data.yml runs password_policy with
      // complexity: false and pass_length: "5" for every GOAD lab. Under the
      // default policy win_domain_user would reject this outright.
      password = sam;
      plants.push(passwordPlant());
      plantedAt = { host_key: dc, path: userDn, format: 'password_equals_samaccountname' };
      how = `${sam}'s password is their own sAMAccountName; the staff list the web app publishes `
        + 'is the spray list';
      break;
    }
    case 'password_in_description': {
      password = pickPassword(runId, 'entry:pw', LEAKED_PASSWORDS, taken);
      plants.push(passwordPlant(), {
        kind: 'ad_description',
        role: 'onlyusers',
        host: dc,
        item: sam,
        item_vars: { description: `onboarding password ${password} (HR sync)` },
        evidence_probe: null,
        why: 'the leak itself; the web directory mirrors this attribute verbatim',
      });
      plantedAt = {
        host_key: webKey,
        path: '/staff-directory',
        format: 'ad_description_mirrored_on_web',
      };
      how = 'the public staff directory mirrors the AD description attribute verbatim, and one '
        + `entry (${sam}) still carries an onboarding password`;
      break;
    }
    case 'asrep': {
      password = pickPassword(runId, 'entry:pw', CRACKABLE_PASSWORDS, taken);
      plants.push(passwordPlant(), {
        kind: 'asrep_flag',
        role: 'ps',
        host: dc,
        item: `asrep_${idPart(sam)}`,
        item_vars: {},
        evidence_probe: {
          id: `chain:entry:asrep:${idPart(sam)}`,
          kind: 'asrep',
          run_on: dc,
          host: dc,
          domain: ctx.domainFqdn,
          role: 'ps',
          user: sam,
          why: 'without DoesNotRequirePreAuth there is no AS-REP to roast and the lab has no '
            + 'entrance',
        },
        why: 'DONT_REQ_PREAUTH is set by a freeform script, not by config.json, so it MUST be '
          + 'declared to the probe or it is never checked',
      });
      plantedAt = { host_key: dc, path: userDn, format: 'asrep_roastable' };
      how = `${sam} does not require Kerberos pre-authentication; the username comes off the web `
        + 'staff directory and the AS-REP hash cracks offline';
      break;
    }
    case 'kerberoast': {
      // The foothold here is a THROWAWAY: a read-only bind account the web app
      // leaks. It holds nothing. Kerberoasting genuinely needs an authenticated
      // session to request a service ticket, so pretending it is an
      // unauthenticated entry would produce a lab nobody can start. Edge 0 is
      // the roast itself, and that is where the interesting account arrives.
      password = pickPassword(runId, 'entry:pw', LEAKED_PASSWORDS, taken);
      plants.push(passwordPlant());
      plantedAt = { host_key: webKey, path: '/config/ldap.env', format: 'web_app_credential' };
      how = `the web app's LDAP bind account (${sam}) is readable in an exposed config file; it `
        + 'holds nothing itself, but it is enough of a session to request service tickets';
      break;
    }
    case 'open_share': {
      password = pickPassword(runId, 'entry:pw', LEAKED_PASSWORDS, taken);
      const shareHost = ctx.shareHost;
      const dest = 'C:\\shares\\public\\it-handover.txt';
      plants.push(passwordPlant(), {
        kind: 'share_file',
        role: 'vulns/openshares',
        host: shareHost.key,
        item: null,
        // openshares takes no vars: it is a flag role that creates
        // C:\shares\public and C:\shares\all and sets AllowInsecureGuestAuth.
        item_vars: {},
        evidence_probe: {
          id: `chain:entry:openshare:${idPart(shareHost.key)}`,
          kind: 'registry',
          run_on: shareHost.key,
          host: shareHost.key,
          role: 'openshares',
          path: 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\LanmanWorkstation\\Parameters',
          name: 'AllowInsecureGuestAuth',
          data: 1,
          why: 'guest SMB access must be allowed or the anonymous share is not anonymous',
        },
        why: 'the share the handover note sits in',
      }, {
        kind: 'share_file',
        role: 'vulns/files',
        host: shareHost.key,
        item: 'it_handover',
        item_vars: { src: 'shares/it-handover.txt', dest },
        evidence_probe: {
          id: `chain:entry:sharefile:${idPart(shareHost.key)}`,
          kind: 'file',
          run_on: shareHost.key,
          host: shareHost.key,
          role: 'files',
          path: dest,
          is_directory: false,
          why: 'the planted artifact the entry reads; a wrong dest prefix breaks the whole lab '
            + 'invisibly',
        },
        why: 'the handover note carrying the credential',
      });
      plantedAt = { host_key: shareHost.key, path: dest, format: 'smb_share_file' };
      how = `an anonymous SMB share on ${shareHost.hostname || shareHost.key} still holds an IT `
        + `handover note naming ${sam} and their password`;
      break;
    }
    case 'web_credential': {
      password = pickPassword(runId, 'entry:pw', LEAKED_PASSWORDS, taken);
      plants.push(passwordPlant());
      plantedAt = { host_key: webKey, path: '/admin/integrations', format: 'web_app_credential' };
      how = `the vulnerable web app stores its directory-integration credential (${sam}) in `
        + 'cleartext where an authenticated low-privilege user can read it';
      break;
    }
    default:
      return fail('ENTRY_UNKNOWN',
        `attack chain: entry '${shape.entry}' is not one of ${ENTRY_POINTS.join(', ')}.`,
        'labIR.chain.start');
  }
  return { password, plants, acls, plantedAt, how, declaredBroad };
}

// ─── the designer ──────────────────────────────────────────────────────────

/**
 * Design the attack graph for one lab.
 *
 * Consumes labIR.principals (composer-owned) and returns the three pieces this
 * module owns:
 *   { chain, acls, foothold_credential }
 * The caller merges them into labIR - or calls applyAttackChain(), which does
 * the merge AND writes back the principal fields the design decided (the
 * foothold password, a roastable account's SPN), so the two halves cannot
 * disagree about them.
 *
 * Throws ChainCompileError on anything that would deploy green and teach
 * nothing. There is no warning level here on purpose: every failure mode this
 * module knows about is invisible after the play finishes.
 */
function designAttackChain(labIR, options) {
  const opts = options || {};
  const ir = isObject(labIR) ? labIR : {};
  const runId = String(opts.runId || ir.run_id || '');
  if (!runId) {
    fail('CHAIN_NO_SEED', 'attack chain: no run_id. Every dimension of the design is a hash of '
      + 'the seed - without one there is nothing to be deterministic about, and a chain that '
      + 'cannot be regenerated cannot be checked against the paper report.', 'run_id');
  }

  // ── context ───────────────────────────────────────────────────────────────
  const domains = asArray(ir.domains).filter(isObject);
  if (domains.length === 0) {
    fail('CHAIN_NO_DOMAIN', 'attack chain: labIR.domains is empty.', 'labIR.domains');
  }
  const domain = domains.filter((d) => d.is_forest_root)[0] || domains[0];
  const fqdn = String(domain.fqdn);
  const hosts = asArray(ir.hosts).filter(isObject);
  const dcHost = hosts.filter((h) => h.key === domain.dc_host_key)[0]
    || hosts.filter((h) => h.type === 'dc' && h.domain === fqdn)[0];
  if (!dcHost) {
    fail('CHAIN_NO_DC',
      `attack chain: domain '${fqdn}' names no DC host. Every domain fact - the ACLs, the SPNs, `
      + 'the memberships - is written and probed on the DC.', 'labIR.domains[].dc_host_key');
  }
  const members = hosts.filter((h) => h.type !== 'dc' && (!h.domain || h.domain === fqdn));
  const ctx = {
    runId,
    domainFqdn: fqdn,
    rootDn: rootDnForDomain(fqdn),
    dcHost,
    dcHostKey: dcHost.key,
    hosts,
    members,
    webHost: hosts.filter((h) => asArray(h.roles).indexOf('web') !== -1 || /web/i.test(String(h.key)))[0] || null,
    // The CA and the share both fall back to the DC: on tier S it is the only
    // host there is, and upstream GOAD-Mini really does plant adcs_templates
    // and files on dc01.
    caHost: hosts.filter((h) => asArray(h.roles).indexOf('adcs') !== -1)[0] || dcHost,
    shareHost: members[0] || dcHost,
  };

  const pool = indexPrincipals(ir.principals, fqdn);
  const declaredAdmins = normalizeDeclaredAdmins(
    isObject(ir.principals) ? ir.principals.declared_admins : []);

  // ── generate -> prove -> repair ──────────────────────────────────────────
  // The generator used to emit a design and then fail its own solvability proof
  // on it: a decoy that turned out to be reachable and productive, or an ACL
  // edge whose target was already one membership hop from the objective. Both
  // are generator bugs, not policy questions - a decoy that shortens the path is
  // not a decoy, it is a second solution - so the check stays and the generator
  // learns.
  //
  // Each round is a pure function of (seed, repair state), and the repair state
  // only ever grows, so the loop is deterministic under a fixed run_id and
  // cannot oscillate. If it cannot produce a clean design it fails LOUDLY naming
  // the axis it could not satisfy. It never emits an unproven chain, and it
  // never drops a guarantee to get a result.
  const repair = {
    avoidBinding: new Set(),
    avoidDecoy: new Set(),
    // The third repair axis, and the one that is a CLAMP rather than a swap.
    // fitShape() already shortens a chain that does not fit the pool's SIZE;
    // this shortens one that does not fit its SHAPE — a roster where every
    // remaining user is one membership hop from somewhere the spine goes later
    // cannot carry nine hops without a bypass, and six proven hops is a lab
    // while nine unproven ones are not.
    lengthCap: null,
    notes: [],
  };
  let lastFindings = [];
  let lastBuilt = null;
  for (let attempt = 0; attempt < MAX_REPAIR_ATTEMPTS; attempt += 1) {
    let built;
    try {
      built = buildDesign(ir, ctx, pool, declaredAdmins, repair);
    } catch (err) {
      // No user in the pool can sit at the depth the shape asked for without
      // something already bound reaching it sooner. Shorten the chain and try
      // again — the shape is a preference, the pool is a fact.
      if (err.code === 'PRINCIPAL_POOL_EXHAUSTED' && err.shape_length > MIN_LENGTH) {
        repair.lengthCap = err.shape_length - 1;
        repair.notes.push(`length capped to ${repair.lengthCap}: the roster could not carry `
          + `${err.shape_length} hops without something reaching a node sooner than the spine`);
        continue;
      }
      // The repair narrowed the pool until the design no longer fits at all.
      // That is a failure of the repair, not of the caller's lab, and saying so
      // is more useful than reporting an exhausted pool.
      if (attempt > 0 && REPAIR_EXHAUSTION_CODES.indexOf(err.code) !== -1) {
        failUnrepairable(lastFindings, repair, attempt, err);
      }
      throw err;
    }
    lastBuilt = built;
    const findings = findUnintendedShortcuts(
      Object.assign({}, ir, { acls: built.acls }), built.chain, { acls: built.acls });
    if (findings.length === 0) {
      built.chain.shape.repair_attempts = attempt;
      if (repair.notes.length) built.chain.shape.notes.push(...repair.notes);
      built.chain.signature = chainSignature(built.chain);
      return built;
    }
    lastFindings = findings;
    // SHORTCUT_ADMIN_TOO_CHEAP is NOT this module's to repair. The declaration
    // says the composer put that principal in a privileged group on purpose, so
    // the fix is the composer's: demote them and re-emit
    // (goad-lab-compile.compileLabWithChain drives exactly that negotiation).
    // Re-siting a chain node here would move the symptom without touching the
    // account that is two hops from the foothold.
    if (findings.some((f) => f.code === 'SHORTCUT_ADMIN_TOO_CHEAP')) {
      throwShortcuts(findings);
    }
    if (!planRepair(repair, findings, built)) {
      failUnrepairable(findings, repair, attempt + 1, null);
    }
  }
  failUnrepairable(lastFindings, repair, MAX_REPAIR_ATTEMPTS, null, lastBuilt);
  return null; // unreachable; failUnrepairable always throws
}

/** How many generate -> prove -> repair rounds before the designer gives up. */
const MAX_REPAIR_ATTEMPTS = 8;

/** Failures that mean the repair state has narrowed the pool past usability,
 *  rather than that the lab was unusable to begin with. */
const REPAIR_EXHAUSTION_CODES = Object.freeze([
  'PRINCIPAL_POOL_EXHAUSTED', 'PRINCIPAL_POOL_TOO_SMALL', 'FOOTHOLD_POOL_EXHAUSTED',
  'PASSWORD_POOL_EXHAUSTED',
]);

/** One error carrying every finding — the shape assertNoUnintendedShortcuts
 *  produces, extracted so the repair loop raises exactly the same thing. */
function throwShortcuts(findings) {
  const head = findings.slice(0, 3).map((f) => `${f.code}: ${f.message}`).join(' ');
  const more = findings.length > 3 ? ` (+${findings.length - 3} more)` : '';
  const error = new ChainCompileError('CHAIN_HAS_SHORTCUTS',
    `attack chain: ${findings.length} unintended shortcut`
    + `${findings.length === 1 ? '' : 's'} would let a student skip the designed path. `
    + `${head}${more}`, findings[0].link);
  error.findings = findings;
  throw error;
}

/**
 * Give up, loudly, naming the axis that could not be satisfied.
 *
 * Never a warning and never a quiet emit: an unproven chain deploys perfectly
 * and the only signal is a cohort that finishes the lab in ten minutes by a
 * route the instructor does not know exists.
 */
function failUnrepairable(findings, repair, attempts, cause, built) {
  const axes = Array.from(new Set(asArray(findings).map((f) => f.code))).sort();
  const detail = asArray(findings).slice(0, 3).map((f) => f.message).join(' ');
  const error = new ChainCompileError('CHAIN_UNREPAIRABLE',
    `attack chain: ${attempts} generate/prove/repair round${attempts === 1 ? '' : 's'} could not `
    + `produce a design that satisfies ${axes.join(', ') || 'its own solvability proof'}. `
    + `Repair had re-sited ${repair.avoidBinding.size} binding(s) and ${repair.avoidDecoy.size} `
    + `decoy endpoint(s)${cause ? ` before the pool ran out (${cause.code}: ${cause.message})` : ''}. `
    + `${detail} Emitting the chain anyway would ship a lab with a second solution nobody wrote `
    + 'down, so the honest outcome is a refusal.',
    asArray(findings)[0] ? findings[0].link : 'labIR.chain');
  error.findings = asArray(findings);
  error.axes = axes;
  error.repair = {
    attempts,
    avoid_binding: Array.from(repair.avoidBinding),
    avoid_decoy: Array.from(repair.avoidDecoy),
    notes: repair.notes.slice(),
  };
  if (cause) error.cause = cause;
  if (built) error.last_chain = built.chain;
  throw error;
}

/**
 * Turn findings into the next round's exclusions.
 *
 * PRUNE OR RE-SITE, never widen. Two culprits are actionable:
 *
 *   a decoy on the short path        its endpoints go on avoidDecoy, so the next
 *                                    round sites that decoy somewhere genuinely
 *                                    dead (or, if nothing is left, ships fewer
 *                                    decoys and says so).
 *   the LANDING node                 the first chain node the cheap prefix
 *                                    arrives at goes on avoidBinding, so the
 *                                    next round binds a different principal to
 *                                    that position. The shape is untouched; only
 *                                    the principal underneath it moves.
 *
 * ONE LANDING NODE PER FINDING, not every node on the route. The nodes AFTER the
 * landing are on the designed path and are reached legitimately — excluding them
 * too burns the principal pool in a single round and turns a repairable design
 * into an exhausted one, which is the failure this loop exists to avoid.
 *
 * Returns false when neither applies — the shortcut lives entirely in
 * composer-owned data, or lands on a computer account there is only one of, and
 * no amount of re-siting will remove it. That is a loud failure, not a shrug.
 */
function planRepair(repair, findings, built) {
  const chain = built.chain;
  const decoyByEdge = new Map();
  for (const d of asArray(chain.decoys)) {
    decoyByEdge.set(`${nodeKey(d.from)}>${nodeKey(d.to)}`, d);
  }
  const designedByEdge = new Set(asArray(chain.edges).map((e) => `${nodeKey(e.from)}>${nodeKey(e.to)}`));
  // Only principals can be re-sited. A computer node is bound to the one member
  // server the lab has, so excluding it would change nothing and would hide the
  // fact that the repair made no progress.
  const reboundable = new Set();
  for (const e of asArray(chain.edges)) {
    // The trailing `$` is what makes a name a computer account, and it is the
    // form nodeTarget() writes for one — so it is the test, not the edge's
    // target_kind, which says nothing about `from`.
    for (const value of [e.from, e.to]) {
      if (!/\$$/.test(String(value))) reboundable.add(nodeKey(value));
    }
  }
  const startKey = nodeKey(chain.start.principal);
  const objectiveKey = nodeKey(chain.objective.target);
  let progressed = false;

  const avoidDecoy = (value) => {
    const k = nodeKey(value);
    if (!k || repair.avoidDecoy.has(k)) return false;
    repair.avoidDecoy.add(k);
    progressed = true;
    return true;
  };
  // The foothold IS re-sitable — buildDesign draws it from the same `bindable`
  // filter as every other node — and sometimes it is the only thing that can
  // move: when the shortcut runs through the one member server's computer
  // account, the account cannot be swapped but the principal holding local admin
  // on it can.
  const avoidBinding = (value) => {
    const k = nodeKey(value);
    if (!k || k === objectiveKey) return false;
    if (!reboundable.has(k) || repair.avoidBinding.has(k)) return false;
    repair.avoidBinding.add(k);
    progressed = true;
    return true;
  };

  for (const finding of findings) {
    if (finding.code === 'SHORTCUT_DECOY_LIVE') {
      repair.notes.push(`decoy '${finding.decoy_id}' re-sited: it was reachable and productive`);
      avoidDecoy(finding.from);
      avoidDecoy(finding.to);
      continue;
    }
    if (finding.code !== 'SHORTCUT_MEMBERSHIP_BYPASS') continue;
    const path = asArray(finding.path);
    let landed = false;
    for (let i = 0; i + 1 < path.length && !landed; i += 1) {
      const key = `${path[i]}>${path[i + 1]}`;
      const decoy = decoyByEdge.get(key);
      if (decoy) {
        repair.notes.push(`decoy '${decoy.id}' pruned: it sat on a route shorter than the chain`);
        avoidDecoy(decoy.from);
        avoidDecoy(decoy.to);
        continue;
      }
      if (designedByEdge.has(key)) continue;
      // An edge the designer did not draw — group nesting, a local-admin grant,
      // a cached credential. Where it LANDS is the position to re-site; when the
      // landing is a computer account the lab has exactly one of, move the
      // principal that JUMPS to it instead. Either way one position moves, not
      // the whole route.
      landed = avoidBinding(path[i + 1]);
      if (landed) {
        repair.notes.push(`node '${path[i + 1]}' re-sited: a route this designer did not draw `
          + `reached it from '${path[i]}' sooner than the chain does`);
      } else {
        landed = avoidBinding(path[i]);
        if (landed) {
          repair.notes.push(`node '${path[i]}' re-sited: it jumps straight to '${path[i + 1]}', `
            + 'which the design cannot bind anywhere else');
        }
      }
    }
  }
  return progressed;
}

/**
 * One design attempt.
 *
 * Pure in (ir, ctx, pool, declaredAdmins, repair): the same inputs always
 * produce the same design, which is what lets the loop above be both
 * deterministic and self-correcting.
 */
function buildDesign(ir, ctx, pool, declaredAdmins, repair) {
  const runId = ctx.runId;
  const fqdn = ctx.domainFqdn;
  const shape = fitShape(planShape(runId, { patterns: availablePatterns(ir, fqdn) }), pool);
  if (repair.lengthCap !== null && shape.length > repair.lengthCap) {
    const capped = Math.max(MIN_LENGTH, repair.lengthCap);
    shape.notes.push(`length clamped ${shape.length} -> ${capped}: at the requested length every `
      + 'remaining principal was closer to a later node than the spine is, through group nesting, '
      + 'a local-admin grant or a cached credential');
    if (shape.length_requested === undefined) shape.length_requested = shape.length;
    shape.length = capped;
    // The branchings need room, exactly as fitShape() requires of them.
    if (shape.branching === 'diamond' && shape.length < 4) shape.branching = 'funnel';
    if (shape.branching === 'parallel' && shape.length < 3) shape.branching = 'funnel';
  }
  if (shape.terminus === 'ou_control' && pool.ous.length === 0) {
    shape.notes.push('terminus remapped ou_control -> adminsdholder: the composer produced no '
      + 'organisational units, and an OU terminus with no OU is a DN get-acl throws on');
    shape.terminus = 'adminsdholder';
  }

  // ── principals ────────────────────────────────────────────────────────────
  const taken = new Set(pool.users.map((u) => String(u.password == null ? '' : u.password)));

  /**
   * Principals this design must not put on a chain node.
   *
   * A DECLARED ADMIN is the important one and it is a NEW rule. Binding a domain
   * admin halfway along the spine means the student finishes the exercise when
   * they reach that node, and every edge after it is scenery — the same failure
   * the shortcut checker reports as a membership bypass, arrived at by the
   * designer's own hand. avoidBinding carries whatever a previous repair round
   * moved out of the way.
   */
  const bindable = (name) => !declaredAdmins.has(nodeKey(name))
    && !repair.avoidBinding.has(nodeKey(name));

  const shuffledUsers = seededShuffle(runId, 'pool:users', pool.users);
  const footholdPool = shuffledUsers.filter((u) => bindable(u.sam));
  if (footholdPool.length === 0) {
    fail('FOOTHOLD_POOL_EXHAUSTED',
      'attack chain: no user in the pool can carry the foothold. Every candidate is either a '
      + 'declared privileged principal (starting there hands the student the endgame) or has been '
      + 'excluded by a repair round. The composer must widen the roster or demote fewer accounts.',
    'labIR.principals.users');
  }
  let footholdUser = footholdPool[0];
  if (shape.entry === 'user_equals_password') {
    // The sam has to clear the policy floor to BE the password, and it must not
    // already be someone else's password or we would manufacture a shared one.
    const usable = footholdPool
      .filter((u) => String(u.sam).length >= POLICY_MIN_PASSWORD_LEN)
      .filter((u) => !taken.has(String(u.sam)));
    if (usable.length === 0) {
      const swapped = ENTRY_POINTS.filter((e) => e !== 'user_equals_password');
      shape.notes.push('entry remapped from user_equals_password: no user has a sAMAccountName '
        + `of at least ${POLICY_MIN_PASSWORD_LEN} characters that is not already in use as a `
        + 'password');
      shape.entry = hashPick(runId, 'chain:entry:fallback', swapped);
    } else {
      footholdUser = usable[0];
    }
  }
  const orderedUsers = [footholdUser]
    .concat(shuffledUsers.filter((u) => u !== footholdUser));
  const usedPrincipals = new Set([nodeKey(footholdUser.sam)]);

  const skeleton = buildSkeleton(runId, shape);
  const terminus = bindTerminus(ctx, shape, pool);
  const kinds = planNodeKinds(runId, shape, skeleton, shape.terminus);

  /**
   * THE EDGES THIS DESIGNER DOES NOT DRAW, and why binding has to know about
   * them.
   *
   * Group nesting, local-admin grants, cached credentials and password reuse are
   * all composer-owned facts, all real routes, and none of them appears in
   * BloodHound as something the designer placed. Binding a node whose cheap
   * distance from the foothold is smaller than its depth builds a shortcut
   * before the first ACL is written: the composer puts every user in a
   * department group, so a spine that ends `-> Finance -> objective` is one hop
   * from any Finance member, foothold included. Refusing that binding is
   * cheaper, more legible and far more deterministic than discovering it in the
   * proof and repairing it afterwards - the repair loop below is the backstop,
   * not the mechanism.
   */
  const memberships = membershipGraph(ir, pool, fqdn);
  const cheapEdges = membershipEdges(memberships)
    .concat(hostEdges(ir, fqdn))
    .concat(sharedPasswordEdges(pool));
  /**
   * Group candidates, EMPTIEST FIRST, seeded order breaking ties.
   *
   * A group node on the chain is a group the student has to be ADDED to, and a
   * group that already has members is a group they can reach instead by
   * compromising one of them. The composer puts every user in a department
   * group, so drawing chain groups purely by seed guaranteed that some node
   * deep in the chain was a group half the roster was already inside — a bypass
   * built by the designer's own hand, and the reason PRINCIPAL_POOL_EXHAUSTED
   * fired on perfectly ordinary rosters once the depth rule started catching it.
   * Upstream GOAD does the same thing on purpose: the groups you are meant to
   * add yourself to are the empty ones.
   */
  const groupInbound = new Map();
  for (const [, parents] of memberships) {
    for (const g of parents) groupInbound.set(g, (groupInbound.get(g) || 0) + 1);
  }
  const inboundOf = (g) => groupInbound.get(nodeKey(g.name)) || 0;
  const orderedGroups = seededShuffle(runId, 'pool:groups', pool.groups)
    .map((g, i) => ({ g, i }))
    .sort((a, b) => inboundOf(a.g) - inboundOf(b.g) || a.i - b.i)
    .map((e) => e.g);

  const distCache = new Map();
  const distFrom = (name) => {
    const key = nodeKey(name);
    if (!distCache.has(key)) distCache.set(key, distancesFrom(cheapEdges, key));
    return distCache.get(key);
  };

  /**
   * The positions already fixed, as (node key, depth) pairs, and the rule a new
   * binding has to satisfy against every one of them.
   *
   * BOTH DIRECTIONS, and the second is the one that is easy to forget. A
   * candidate at depth d is wrong if it can reach an already-bound position
   * sooner than the spine does (d + dist < that position's depth), AND it is
   * equally wrong if an already-bound position can reach IT sooner than the
   * spine does (that depth + dist < d). Checking only the first would let a user
   * bound at depth 2 hold a cached credential for the user at depth 6, which is
   * a four-edge shortcut the designer built itself.
   */
  const positions = [];
  const fitsAt = (name, depth) => {
    const key = nodeKey(name);
    const outward = distFrom(key);
    for (const p of positions) {
      if (p.key === key) return false;
      const forward = outward.get(p.key);
      if (forward !== undefined && depth + forward < p.depth) return false;
      const backward = distFrom(p.key).get(key);
      if (backward !== undefined && p.depth + backward < depth) return false;
    }
    return true;
  };
  const claimPosition = (name, depth) => positions.push({ key: nodeKey(name), depth });

  // delegation_abuse ends by capturing the DC's TGT from a server trusted for
  // unconstrained delegation, so the second-to-last node is that server's
  // COMPUTER account rather than anything from the principal pool.
  const lastId = `s${shape.length}`;
  const penultimateId = `s${shape.length - 1}`;
  if (shape.pattern === 'delegation_abuse') kinds[penultimateId] = 'computer';
  // ESC1 hands you a certificate for a named principal, so edge 0's target has
  // to be a user.
  if (shape.pattern === 'adcs_esc1') kinds.s1 = 'user';
  // The kerberoast entry requests a SERVICE TICKET for s1 and cracks it, so s1
  // has to be a user too. A group has no SPN, no password and no hash: the edge
  // would hand roles/onlyusers an item that is not an account, and win_domain_user
  // would be asked to set a password on a group.
  if (shape.entry === 'kerberoast') kinds.s1 = 'user';

  const bindings = {};
  bindings.s0 = { kind: 'user', sam: String(footholdUser.sam), principal: footholdUser };
  bindings[lastId] = terminus;

  // Node depth, from the skeleton. `alt` parallels the spine node it doubles, so
  // it is judged at that node's depth.
  const depthById = new Map(skeleton.nodes.map((n) => [n.id, n.depth]));
  const depthOf = (id) => (depthById.has(id) ? depthById.get(id) : 1);

  // The two fixed positions come first: the foothold at depth 0 and the
  // objective at the end. Everything else is checked against them.
  claimPosition(footholdUser.sam, 0);
  claimPosition(nodeTarget(terminus.kind, terminus), shape.length);

  // COMPUTERS NEXT, because they are not a choice — a lab has one member server
  // and the delegation pattern needs its computer account — so their positions
  // are facts the later choices have to live with rather than the other way
  // round.
  for (const node of skeleton.nodes) {
    if (bindings[node.id] || kinds[node.id] !== 'computer') continue;
    const host = ctx.members[0] || ctx.dcHost;
    bindings[node.id] = { kind: 'computer', sam: `${host.hostname}$`, host };
    claimPosition(bindings[node.id].sam, depthOf(node.id));
  }

  // GROUPS BEFORE USERS, and the ordering matters. A group node fixes a position
  // that every later user has to be checked against — "is this user already a
  // member of a group further down the chain than they are" — and that question
  // cannot be asked until the group positions exist. Shallowest first, so the
  // constraint each one imposes is known before the deeper ones are chosen.
  const byDepth = (a, b) => a.depth - b.depth || String(a.id).localeCompare(String(b.id));
  const groupNodes = skeleton.nodes
    .filter((n) => !bindings[n.id] && kinds[n.id] === 'group').sort(byDepth);
  const claimed = new Set([nodeKey(footholdUser.sam)]);
  for (const node of groupNodes) {
    const depth = depthOf(node.id);
    const g = orderedGroups.find((cand) => !claimed.has(nodeKey(cand.name))
      && bindable(cand.name) && fitsAt(cand.name, depth));
    if (!g) {
      // Not a failure: a small org legitimately has few groups, and every one of
      // them may be one membership hop from somewhere the chain goes later.
      // Downgrading to a user keeps the shape and says why.
      shape.notes.push(`node ${node.id} downgraded group -> user: no group in the pool can sit `
        + `at depth ${depth} without something already bound reaching it sooner through `
        + 'membership, a local-admin grant or a cached credential');
      kinds[node.id] = 'user';
      continue;
    }
    claimed.add(nodeKey(g.name));
    bindings[node.id] = { kind: 'group', sam: String(g.name), principal: g };
    usedPrincipals.add(nodeKey(g.name));
    claimPosition(g.name, depth);
  }

  const userNodes = skeleton.nodes.filter((n) => !bindings[n.id]).sort(byDepth);
  for (const node of userNodes) {
    const depth = depthOf(node.id);
    const u = orderedUsers.find((cand) => !claimed.has(nodeKey(cand.sam))
      && bindable(cand.sam) && fitsAt(cand.sam, depth));
    if (!u) {
      // Carries shape_length so the loop can shorten the chain and retry rather
      // than give up: a roster that cannot carry nine hops without a bypass can
      // usually carry six, and six proven hops beat nine unproven ones.
      try {
        fail('PRINCIPAL_POOL_EXHAUSTED',
          `attack chain: the design needs a principal for node ${node.id} (depth ${depth}) and `
          + 'every user in the pool is either already bound, a declared privileged principal, '
          + 'excluded by a repair round, or within fewer hops of something already bound than the '
          + 'chain is - through group nesting, a local-admin grant, a cached credential or a '
          + 'shared password. fitShape() clamps for size; this is the shape not fitting the pool '
          + 'it was handed.',
        'labIR.principals');
      } catch (err) {
        err.shape_length = shape.length;
        throw err;
      }
    }
    claimed.add(nodeKey(u.sam));
    bindings[node.id] = { kind: 'user', sam: String(u.sam), principal: u };
    usedPrincipals.add(nodeKey(u.sam));
    claimPosition(u.sam, depth);
  }

  // ── entry ─────────────────────────────────────────────────────────────────
  const entry = planEntry(ctx, shape, pool, footholdUser, taken);

  // ── which right sits at which depth ───────────────────────────────────────
  const hopType = (i) => {
    if (shape.pattern === 'adcs_esc1' && i === 0) return 'adcs_esc1';
    if (shape.entry === 'kerberoast' && i === 0) return 'kerberoast';
    if (shape.pattern === 'delegation_abuse' && i === shape.length - 1) return 'delegation';
    return 'acl';
  };
  const rights = [];
  for (let i = 0; i < shape.length; i += 1) {
    const type = hopType(i);
    rights.push(type === 'acl'
      ? pickRight(runId, i, bindings[`s${i + 1}`].kind, 'domain', `s${i}->s${i + 1}`)
      : null);
  }
  // THE ANTI-INHERITANCE GUARD. If the draw happened to reproduce the chassis
  // ladder's opening, re-draw the LAST ACL hop against a candidate set that
  // excludes what it picked. Perturbing the last hop rather than the first keeps
  // the earlier draws stable, so the perturbation is a small deterministic
  // correction rather than a different chain.
  const aclSequence = rights.filter((r) => r !== null);
  if (rightsAreLadderPrefix(aclSequence)) {
    let idx = -1;
    for (let i = rights.length - 1; i >= 0; i -= 1) if (rights[i] !== null) { idx = i; break; }
    const targetKind = bindings[`s${idx + 1}`].kind;
    const candidates = hopCandidates(targetKind, 'domain').filter((r) => r !== rights[idx]);
    if (candidates.length > 0) {
      shape.notes.push(`right at depth ${idx} perturbed off the chassis ladder: the draw had `
        + 'reproduced the GOAD-Mini/GOAD-Light opening, which is the one graph a repeat student '
        + 'already knows');
      rights[idx] = hashPick(runId, `chain:right:perturb:${idx}`, candidates);
    }
  }

  // ── edges ─────────────────────────────────────────────────────────────────
  const edges = [];
  const aclLabels = new Set();
  const claimLabel = (label, link) => {
    if (aclLabels.has(label)) {
      fail('ACL_LABEL_COLLISION',
        `attack chain: two ACLs both want the key '${label}'. config.json's acls is a dict, so `
        + 'the second silently replaces the first and one designed edge simply stops existing.',
      link);
    }
    aclLabels.add(label);
    return label;
  };
  for (const label of entry.acls.map((a) => a.item)) claimLabel(label, 'entry');

  const pushAcl = (fromBinding, toBinding, depth, right, id, spine) => {
    const from = nodeTarget(fromBinding.kind, fromBinding);
    const to = nodeTarget(toBinding.kind, toBinding);
    // Prefer the binding's own short label for DN-shaped targets: the config key
    // is what an instructor reads in the answer key, and
    // `GenericAll_x_CNAdminSDHolderCNSystemDCnorthgateDCexample` is not a name.
    const label = claimLabel(
      idPart(`${right}_${bareSam(from)}_${toBinding.label || bareSam(to)}`
        .replace(/[^A-Za-z0-9_.$-]/g, '')), id);
    const edge = makeAclEdge(ctx, {
      id,
      from,
      to,
      right,
      inheritance: inheritanceFor(toBinding.kind),
      depth,
      targetKind: toBinding.kind,
      label,
      context: 'domain',
    });
    edge.spine = spine;
    addCrackablePrerequisite(ctx, runId, edge, toBinding, taken);
    edges.push(edge);
    return edge;
  };

  for (let i = 0; i < shape.length; i += 1) {
    const fromB = bindings[`s${i}`];
    const toB = bindings[`s${i + 1}`];
    const id = `edge${i}`;
    const type = hopType(i);
    if (type === 'acl') {
      pushAcl(fromB, toB, i, rights[i], id, true);
    } else if (type === 'kerberoast') {
      const service = hashPick(runId, 'chain:spn:service', SPN_SERVICES.slice());
      const spn = `${service}/${toB.sam}.${fqdn}`;
      const crackable = pickPassword(runId, 'chain:roast:pw', CRACKABLE_PASSWORDS, taken);
      const edge = {
        id,
        from: fromB.sam,
        to: toB.sam,
        edge_type: 'kerberoast',
        depth: i,
        target_kind: toB.kind,
        spine: true,
        why: `${toB.sam} carries an SPN and a wordlist password, so any authenticated session `
          + 'can request its service ticket and crack it offline',
        created_by: {
          role: 'onlyusers',
          host: ctx.dcHostKey,
          item: toB.sam,
          item_vars: { spns: [spn], password: crackable },
        },
      };
      assertProducer(edge.created_by, id);
      edge.evidence_probe = evidenceFor(edge, ctx);
      edges.push(edge);
    } else if (type === 'adcs_esc1') {
      const dest = 'C:\\setup\\templates\\CIAB-ESC1.json';
      const edge = {
        id,
        from: fromB.sam,
        to: toB.sam,
        edge_type: 'adcs_esc1',
        depth: i,
        target_kind: toB.kind,
        spine: true,
        why: 'the published template lets the enrollee supply the subject, so a certificate can '
          + `be requested AS ${toB.sam} and used to authenticate as them`,
        created_by: {
          role: 'vulns/adcs_templates',
          host: ctx.caHost.key,
          item: 'ciab_esc1',
          item_vars: { template_name: 'CIAB-ESC1', template_file: dest },
        },
        // The template JSON has to be delivered before New-ADCSTemplate can read
        // it; the role does not ship one.
        prerequisites: [{
          role: 'vulns/files',
          host: ctx.caHost.key,
          item: 'ciab_esc1_template',
          item_vars: { src: 'templates/CIAB-ESC1.json', dest },
        }],
      };
      assertProducer(edge.created_by, id);
      for (const pre of edge.prerequisites) assertProducer(pre, id);
      edge.evidence_probe = evidenceFor(edge, ctx);
      edges.push(edge);
    } else if (type === 'delegation') {
      const edge = {
        id,
        from: fromB.sam,
        to: toB.sam,
        edge_type: 'delegation',
        depth: i,
        target_kind: toB.kind,
        spine: true,
        why: `${fromB.sam} is trusted for unconstrained delegation, so coercing `
          + `${toB.sam} to authenticate to it leaves the DC's own TGT in its cache`,
        created_by: {
          role: 'ps',
          host: ctx.dcHostKey,
          item: `unconstrained_${idPart(bareSam(fromB.sam))}`,
          item_vars: {},
        },
      };
      assertProducer(edge.created_by, id);
      edge.evidence_probe = evidenceFor(edge, ctx);
      edges.push(edge);
    }
  }

  // The branch. Both of its edges are ACLs whatever the pattern is: a branch is
  // an alternative ROUTE, not an alternative technique, and mixing a second
  // primitive in here would make the two halves unequal in difficulty.
  const altNode = skeleton.nodes.filter((n) => !n.spine)[0];
  if (altNode) {
    const altBinding = bindings.alt;
    const splitId = `s${altNode.depth - 1}`;
    const joinId = `s${altNode.depth + 1}`;
    pushAcl(bindings[splitId], altBinding, altNode.depth - 1,
      pickRight(runId, `alt-in`, altBinding.kind, 'domain', 'alt'), 'edgeAltIn', false);
    pushAcl(altBinding, bindings[joinId], altNode.depth,
      pickRight(runId, `alt-out`, bindings[joinId].kind, 'domain', 'alt'), 'edgeAltOut', false);
  }

  // ── decoys ────────────────────────────────────────────────────────────────
  const decoys = buildDecoys(ctx, runId, shape, {
    pool, orderedUsers, orderedGroups, usedPrincipals, terminus, bindings, claimLabel, taken,
    // Everything a decoy candidate has to be judged against: the edges just
    // designed, the composer's implicit ones, where the objective is, and
    // whatever a repair round has ruled out.
    designedEdges: edges,
    cheapEdges,
    objectiveTarget: nodeTarget(terminus.kind, terminus),
    footholdSam: bindings.s0.sam,
    avoidDecoy: repair.avoidDecoy,
    declaredAdmins,
  });

  // Plants are not edges, so they miss the per-edge guards above; check them
  // here rather than leaving PLANT_KINDS as a decorative constant.
  for (const plant of entry.plants.concat(entry.acls)) {
    if (PLANT_KINDS.indexOf(plant.kind) === -1) {
      fail('PLANT_KIND_UNKNOWN',
        `attack chain: entry '${shape.entry}' plants kind '${plant.kind}', which is not one of `
        + `${PLANT_KINDS.join(', ')}.`, 'labIR.chain.start.plants');
    }
    if (plant.evidence_probe) assertProbeKind(plant.evidence_probe, plant.kind);
  }
  if (decoys.length < shape.decoys) {
    // Silent under-delivery is how a lab ends up 100% signal without anyone
    // deciding it should be.
    shape.notes.push(`only ${decoys.length} of ${shape.decoys} decoys could be built: the pool `
      + 'has no more spare principals that are genuinely unreachable');
  }

  // ── lower to labIR.acls ──────────────────────────────────────────────────
  const acls = {};
  acls[fqdn] = {};
  for (const item of entry.acls) acls[fqdn][item.item] = item.item_vars;
  for (const edge of edges.concat(decoys)) {
    if (edge.edge_type !== 'acl') continue;
    acls[fqdn][edge.created_by.item] = edge.created_by.item_vars;
  }

  // ── assemble ──────────────────────────────────────────────────────────────
  const objectiveTarget = nodeTarget(terminus.kind, terminus);
  const chain = {
    start: {
      kind: shape.entry,
      principal: bindings.s0.sam,
      host: entry.plantedAt.host_key,
      how: entry.how,
      plants: entry.plants.concat(entry.acls),
    },
    objective: { kind: shape.terminus, target: objectiveTarget },
    edges,
    decoys,
    // ── additive, and the composer needs all of it ──
    domain: fqdn,
    lab_name: ir.lab_name || null,
    length: shape.length,
    shape: {
      pattern: shape.pattern,
      entry: shape.entry,
      terminus: shape.terminus,
      branching: shape.branching,
      branch_depth: skeleton.branch_depth,
      length: shape.length,
      length_requested: shape.length_requested === undefined ? shape.length : shape.length_requested,
      decoys: decoys.length,
      decoys_requested: shape.decoys,
      notes: shape.notes,
    },
    // The composer's declaration, carried through verbatim. This module does not
    // get to add to it or edit it: the composer is what creates the memberships,
    // so it is the only half that can honestly say which ones are deliberate.
    // What this module does with the list is CHECK it - see findUnintendedShortcuts
    // check 6, which holds every 'roster_realism' admin to the rule that it must
    // not be reachable more cheaply than the intended chain.
    declared_admins: Array.from(declaredAdmins.values())
      .map((a) => ({ sam: a.sam, reason: a.reason, domain: a.domain, via: a.via })),
    // ESC1's enrolment grant is hardcoded to Domain Users in the role itself
    // (`-Identity "{{domain}}\Domain Users"`), so a lab carrying that edge has a
    // broad principal by construction. Declaring it is honest; pretending
    // otherwise would make the shortcut check silently wrong.
    declared_broad_principals: entry.declaredBroad
      .concat(shape.pattern === 'adcs_esc1' ? ['Domain Users'] : []),
    declared_shared_passwords: [],
  };

  const foothold = {
    sam: bindings.s0.sam,
    domain: fqdn,
    password: entry.password,
    planted_at: entry.plantedAt,
    honoured_by: 'ad',
  };

  // ── the proofs ────────────────────────────────────────────────────────────
  proveSolvable(chain, foothold, pool);
  if (isChassisLadder(chain)) {
    fail('CHAIN_IS_CHASSIS_LADDER',
      'attack chain: the emitted right sequence is the chassis ladder (or its opening). Every '
      + 'same-tier client would get the same graph, which is the entire failure this designer '
      + 'exists to prevent.', 'labIR.chain.edges');
  }
  // The shortcut checks are NOT run here. They run in designAttackChain's
  // generate -> prove -> repair loop, over the design this function just
  // returned, so a finding can be repaired instead of only reported. Nothing
  // leaves designAttackChain without passing them.
  chain.signature = chainSignature(chain);
  return { chain, acls, foothold_credential: foothold };
}

/**
 * Decoy edges, so the graph is not 100% signal.
 *
 * A graph where every edge is on the intended path teaches "follow the arrows",
 * which is not what triage is. Each decoy below is a REAL ACE - it deploys, it
 * collects, BloodHound draws it - and each dead-ends for a reason the answer key
 * can state in one sentence.
 *
 * `dead_group` is GOAD's own accident made deliberate: F-07 and F-08 in
 * data/goad-corpus-findings.md are exactly this edge, a GenericAll on the root
 * DC held by a group with zero members and no route in. Upstream shipped it by
 * mistake, twice; here it is the point.
 */
function buildDecoys(ctx, runId, shape, env) {
  const {
    pool, orderedUsers, orderedGroups, usedPrincipals, terminus, bindings, claimLabel, taken,
    designedEdges, cheapEdges, objectiveTarget, footholdSam, avoidDecoy, declaredAdmins,
  } = env;
  const decoys = [];

  /**
   * THE DECOY PREMISE, CHECKED RATHER THAN ASSERTED.
   *
   * Each decoy kind below carries a sentence about why it dead-ends, and the
   * generator used to ship that sentence without testing it. `leaf_target` says
   * its target "is a member of no group" — but the composer puts EVERY user in
   * a department group, so the target routinely reached the objective through a
   * group the answer key never mentions. That is not a decoy; it is a second
   * solution, and the solvability proof was right to reject it.
   *
   * So candidates are judged against the universe of edges that will actually
   * exist: the designed spine, the composer's implicit edges (group nesting,
   * local admin, cached credentials, password reuse), and every decoy emitted so
   * far. The last of those matters — a decoy that is dead alone can be live once
   * the previous one exists.
   */
  let universe = asArray(designedEdges).concat(asArray(cheapEdges));
  const leadsToObjective = (name) => shortestPath(universe, name, objectiveTarget) !== null;
  const isReachable = (name) => reachableFrom(universe, [footholdSam]).has(nodeKey(name));
  const excluded = avoidDecoy || new Set();
  const admins = declaredAdmins || new Map();

  // A DECOY MUST NEVER TOUCH A DECLARED ADMIN. `leaf_target` draws an edge from
  // the foothold straight to a spare account; if that account happens to be one
  // of the roster's domain admins, the "decoy" is a one-hop route to the
  // endgame, and the composer would then be told to demote a perfectly
  // reasonable IT director because the designer pointed at them. Excluding them
  // here is what keeps the negotiation about the composer's data instead of
  // about this module's own decoys.
  const spare = (list, keyOf) => list.filter((x) => !usedPrincipals.has(nodeKey(keyOf(x)))
    && !excluded.has(nodeKey(keyOf(x)))
    && !admins.has(nodeKey(keyOf(x))));
  const spareUsers = spare(orderedUsers, (u) => u.sam);
  // A group is only dead if NOTHING grants membership: no members list, and no
  // user naming it in their own groups array. Those are the two routes the pool
  // can express; the third (an inbound ACL) cannot exist yet because we are the
  // only thing writing ACLs.
  const claimedGroups = new Set();
  for (const u of pool.users) for (const g of asArray(u.groups)) claimedGroups.add(nodeKey(g));
  const deadGroups = spare(orderedGroups, (g) => g.name)
    .filter((g) => asArray(g.members).length === 0)
    .filter((g) => !claimedGroups.has(nodeKey(g.name)));

  const kinds = seededShuffle(runId, 'chain:decoy:kinds',
    ['dead_group', 'unreachable_owner', 'leaf_target']);

  const emit = (kind, fromBinding, toBinding, deadBecause) => {
    const right = pickRight(runId, `decoy:${kind}`, toBinding.kind, 'domain', `decoy:${kind}`);
    const from = nodeTarget(fromBinding.kind, fromBinding);
    const to = nodeTarget(toBinding.kind, toBinding);
    const label = claimLabel(
      idPart(`decoy_${right}_${bareSam(from)}_${toBinding.label || bareSam(to)}`
        .replace(/[^A-Za-z0-9_.$-]/g, '')),
      `decoy:${kind}`);
    const edge = makeAclEdge(ctx, {
      id: `decoy_${decoys.length}_${kind}`,
      from,
      to,
      right,
      inheritance: inheritanceFor(toBinding.kind),
      depth: null,
      targetKind: toBinding.kind,
      label,
      context: 'domain',
    });
    edge.spine = false;
    edge.decoy = true;
    addCrackablePrerequisite(ctx, runId, edge, toBinding, taken);
    edge.dead_ends_because = deadBecause;
    usedPrincipals.add(nodeKey(from));
    usedPrincipals.add(nodeKey(to));
    // The emitted edge joins the universe the NEXT candidate is judged against.
    universe = universe.concat([{ from, to, edge_type: 'decoy' }]);
    decoys.push(edge);
  };

  const spentUsers = new Set();
  const spentGroups = new Set();
  /** The next candidate the premise actually holds for, not merely the next
   *  candidate. `fits` is the sentence in `dead_ends_because`, as a predicate. */
  const nextUser = (fits) => spareUsers
    .find((u) => !spentUsers.has(nodeKey(u.sam)) && !usedPrincipals.has(nodeKey(u.sam))
      && fits(u));

  for (const kind of kinds) {
    if (decoys.length >= shape.decoys) break;
    if (kind === 'dead_group') {
      // Dead by construction AND unentered in fact: a group nothing grants
      // membership to is still a live edge if some ACL we just drew targets it.
      const g = deadGroups.find((cand) => !spentGroups.has(nodeKey(cand.name))
        && !usedPrincipals.has(nodeKey(cand.name)) && !isReachable(cand.name));
      if (!g) continue;
      spentGroups.add(nodeKey(g.name));
      emit(kind, { kind: 'group', sam: String(g.name) }, terminus,
        `${g.name} has zero members, no user names it in their groups array, and no ACL grants `
        + 'membership to it - so no principal in the forest can enter the group that holds this '
        + 'right. This is GOAD-Light F-07 / GOAD-Mini F-08 made deliberate: BloodHound will '
        + 'happily route a shortest-path query through it.');
    } else if (kind === 'unreachable_owner') {
      // The premise is that the HOLDER cannot be obtained, so the candidate has
      // to be genuinely unreachable rather than merely unused.
      const u = nextUser((cand) => !isReachable(cand.sam));
      if (!u) continue;
      spentUsers.add(nodeKey(u.sam));
      const midId = `s${Math.max(1, Math.floor(shape.length / 2))}`;
      emit(kind, { kind: 'user', sam: String(u.sam) }, bindings[midId],
        `nothing in the graph leads to ${u.sam}: no ACL targets them, they hold no SPN, they are `
        + 'not AS-REP roastable and their password is not planted anywhere. The right is real '
        + 'and the holder is unobtainable.');
    } else if (kind === 'leaf_target') {
      // The premise is that the TARGET arrives nowhere. The composer puts every
      // user in a department group, so this is the check that stops the decoy
      // being a one-hop route into the objective through a group nobody named.
      const u = nextUser((cand) => !leadsToObjective(cand.sam));
      if (!u) continue;
      spentUsers.add(nodeKey(u.sam));
      emit(kind, bindings.s0, { kind: 'user', sam: String(u.sam) },
        `${u.sam} holds no rights over anything, and no group they belong to leads anywhere: `
        + 'taking the account is a genuine step that arrives nowhere - the cost of not checking '
        + 'outbound edges before spending an hour on a target.');
    }
  }
  return decoys;
}

/**
 * Design and merge, in one call.
 *
 * This exists because two fields of the design are decisions ABOUT principals -
 * the foothold's password and a roastable account's SPN - and leaving the
 * composer to copy them across by hand is exactly the seam where the website and
 * the directory end up with two different passwords. Returns a new labIR;
 * nothing is mutated in place.
 */
function applyAttackChain(labIR, options) {
  const designed = designAttackChain(labIR, options);
  const { chain, acls, foothold_credential: foothold } = designed;

  const users = asArray((labIR.principals || {}).users).map((u) => Object.assign({}, u));
  const bySam = new Map(users.map((u) => [nodeKey(u.sam), u]));

  // The seam, applied. AD is built with the string the web side plants.
  const footholdUser = bySam.get(nodeKey(foothold.sam));
  if (footholdUser) footholdUser.password = foothold.password;

  // Every edge whose producer is `onlyusers` is a decision about a user object
  // (an SPN, a description, a password), so it lands on the principal here
  // rather than being re-derived by the composer.
  const applyItemVars = (role, item, vars) => {
    if (role !== 'onlyusers') return;
    const user = bySam.get(nodeKey(item));
    if (!user) return;
    for (const key of Object.keys(vars || {})) user[key] = vars[key];
  };
  for (const plant of asArray(chain.start.plants)) {
    applyItemVars(plant.role, plant.item, plant.item_vars);
  }
  for (const edge of asArray(chain.edges)) {
    applyItemVars(edge.created_by.role, edge.created_by.item, edge.created_by.item_vars);
  }

  return Object.assign({}, labIR, {
    principals: Object.assign({}, labIR.principals, { users }),
    chain,
    acls: Object.assign({}, labIR.acls, acls),
    foothold_credential: foothold,
  });
}

module.exports = {
  // vocabularies and tables (exported so a caller reports the same values this
  // file enforces, and so the tests can assert against the manifest rather than
  // against a copy)
  INHERITANCE_VALUES,
  ACL_ITEM_KEYS,
  CHASSIS_LADDER_RIGHTS,
  RIGHT_CATALOG,
  NODE_KINDS,
  PRIVILEGED_GROUPS,
  BROAD_PRINCIPALS,
  ENTRY_POINTS,
  TERMINUS_KINDS,
  BRANCHINGS,
  EDGE_TYPES,
  PLANT_KINDS,
  PATTERNS,
  PRODUCERS,
  CRACKABLE_PASSWORDS,
  LEAKED_PASSWORDS,
  MIN_LENGTH,
  MAX_LENGTH,
  POLICY_MIN_PASSWORD_LEN,
  ADMIN_REASONS,
  MAX_REPAIR_ATTEMPTS,
  // the two guards, deliberately separate
  assertAclRight,
  assertInheritance,
  // planning primitives, exported because each encodes a rule worth testing alone
  planShape,
  fitShape,
  buildSkeleton,
  planNodeKinds,
  pickRight,
  inheritanceFor,
  indexPrincipals,
  seededShuffle,
  assertProducer,
  assertProducersAreEmittable,
  assertProbeKind,
  assertCatalogMatchesManifest,
  // graph primitives
  nodeKey,
  shortestPath,
  shortestPathNodes,
  distancesFrom,
  reachableFrom,
  membershipGraph,
  membershipEdges,
  hostEdges,
  sharedPasswordEdges,
  normalizeDeclaredAdmins,
  chainSignature,
  isChassisLadder,
  // the proofs
  proveSolvable,
  assertFootholdContract,
  probeSecretExemptions,
  findUnintendedShortcuts,
  assertNoUnintendedShortcuts,
  // the designer
  designAttackChain,
  applyAttackChain,
  ChainCompileError,
};
