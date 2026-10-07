/**
 * ============================================================================
 * CALDERA FACT SOURCE — "author an adversary for MY class's machines", as data
 * ============================================================================
 *
 * ############################################################################
 * # THIS FILE HAS NEVER TALKED TO A REAL CALDERA SERVER.                     #
 * #                                                                          #
 * # There is no Caldera anywhere in this repository and none on any cluster. #
 * # Every trait name, field name and endpoint below is taken from upstream's #
 * # documented v2 API and stockpile fact vocabulary and is UNVERIFIED. A     #
 * # trait spelled wrong does not error — the ability simply never receives   #
 * # the fact, no link is created, and the step looks exactly like one that   #
 * # ran and found nothing. That is why TRAITS is remappable per site rather  #
 * # than hardcoded at each use.                                              #
 * #                                                                          #
 * # What IS verified is everything on this side of the transport seam: what  #
 * # gets derived from a spec, what is refused, and the exact request the     #
 * # sync builds — all driven from test/caldera-fact-source.test.js over an   #
 * # injected fake client.                                                    #
 * ############################################################################
 *
 * WHAT AN INSTRUCTOR MEANS BY "CHOOSE BY CLASS WHICH MACHINES TO AUTHOR FOR"
 * ----------------------------------------------------------------------------
 * An adversary is an ordered list of abilities, and every ability declares a
 * PLATFORM (windows/linux/darwin) and consumes FACTS — named key/value pairs an
 * operation seeds itself from. "Author for my class" therefore decomposes into
 * two concrete things:
 *
 *   1. the authoring UI must be seeded with the REAL host set of that class's
 *      environment, so an adversary built against it addresses machines that
 *      exist; and
 *   2. the platform mix must be visible, so an adversary made of linux-only
 *      abilities aimed at an all-Windows class is caught while the instructor is
 *      still looking at it — not at launch, as an operation that completes in
 *      four seconds having created no links at all.
 *
 * Caldera's own mechanism for (1) is a FACT SOURCE. This file builds one from
 * the deployed spec, syncs it idempotently, and answers (2).
 *
 * WHY THE DEPLOYED SPEC AND NOT THE PROFILE'S ASSET LIST
 * ----------------------------------------------------------------------------
 * A CiAB client profile describes an estate — twelve machines with hostnames,
 * roles and free-text OS. The lane deploys a SUBSET of it (asset selection,
 * template misses, host budget). The spec is what was actually built.
 *
 * Seed the authoring UI from the profile and the instructor authors against
 * machines that exist only on paper. Every ability aimed at one of them produces
 * a link the operation can never run, and the answer key — which is compiled
 * from the abilities that WILL run — quietly stops describing the exercise. So
 * hosts come from the SPEC, `assets` is used only to ENRICH what the spec
 * already names (an OS string for a VM whose spec row carries no os_family), and
 * an asset the spec does not deploy is reported as paper-only rather than
 * silently dropped or silently included.
 *
 * WHY CYBERCORE OWNS THE SCOPING AND THE SERVER DOES NOT
 * ----------------------------------------------------------------------------
 * Caldera has NO per-user and no per-object ownership. conf/local.yml users are
 * credentials in a 'red' or 'blue' GROUP, which is a ROLE, not tenancy: every
 * instructor who can open the authoring UI can see, edit and delete every fact
 * source on it. The name below is therefore a LABEL FOR HUMANS SHARING ONE
 * STORE, not a boundary — the actual authorization is CyberCore's, upstream of
 * every call here (requireCiabAccess / sectionsManagedBy / requireCourseFeature
 * decide who may reach this code at all), exactly as it is for every other
 * cross-section surface in this codebase.
 *
 * Two consequences follow, and both are load-bearing:
 *
 *   * the name must be STABLE (the same class re-syncs the same row rather than
 *     accumulating one per launch) and COLLISION-FREE (two sections that a human
 *     called "Section A" are two scopes and must not overwrite each other), so
 *     it carries a digest of the scope KEY, not just its label; and
 *   * NOTHING SECRET MAY BECOME A FACT. `domain.user.password` is a real
 *     stockpile trait and is deliberately never emitted here: a lane credential
 *     in a fact source is a lane credential legible to every account on a shared
 *     staff server, and the bake script goes to real lengths (a 0600 file in the
 *     guest, never a script_arg) to avoid exactly that.
 *
 * NOTHING IN A LANE EVER TALKS TO THIS SERVER
 * ----------------------------------------------------------------------------
 * The authoring instance is standalone, outside every lane, with no agents and
 * no implants: it executes nothing, so there is nothing on it to steal that
 * reaches a student machine. The orchestrator READS it; dispatch into a lane
 * goes over guest-exec (agentShellExec via the Proxmox API) like everything else
 * in this codebase. This file is on the authoring side of that line and must
 * stay there — it takes a client, it never builds one, and it never learns a
 * lane address.
 *
 * PURITY, AND WHY THE CLIENT IS AN ARGUMENT
 * ----------------------------------------------------------------------------
 * Same doctrine as client.js and adversary.js: buildFactSource() and
 * summarizePlatforms() are pure functions of their arguments — no network, no
 * database, no fs, no clock, no RNG — and syncFactSource() reaches the server
 * only through a client object handed to it. There is no server to test against
 * and will not be for months; an injected client is the only thing that makes
 * the idempotence rule testable at all.
 *
 * THIS FILE IS ABOUT AUTHORING, NEVER ABOUT DISPATCH. It registers no engine and
 * cannot launch anything. src/incident/engines/index.js still refuses 'caldera'
 * and must keep refusing it until the E8 cluster gate passes.
 * ============================================================================
 */

'use strict';

const { uuidv5, normalizeAbility } = require('./adversary');

/**
 * Bumped when the SHAPE of a built fact source changes, not when a value does.
 * It travels on the object and into the launch snapshot, so a record compiled by
 * an older build is identifiable rather than merely different.
 */
const FACT_SOURCE_VERSION = 1;

/**
 * The UUIDv5 namespace every fact-source id is derived under.
 *
 * NEVER CHANGE THIS VALUE, and never make it equal ADVERSARY_NAMESPACE. It is
 * the identity of every fact source this file has ever produced: change it and
 * the same class addresses a NEW row on the next sync, leaving the old one
 * behind under the same human-readable name for an instructor to pick by
 * accident.
 */
const FACT_SOURCE_NAMESPACE = 'c1f0a5d7-9b32-4e64-8a7c-6d2f0b41e9a3';

/** Prefix on every name, so a shared server shows at a glance what CyberCore owns. */
const NAME_PREFIX = 'CyberCore: ';

/** How much of a human label survives into the name. Long enough to read, short enough to list. */
const MAX_LABEL_CHARS = 64;

/** Hex digits of scope digest appended to the name. 8 is 4 billion — plenty for a staff server. */
const DIGEST_CHARS = 8;

/**
 * Every fact is scored the same, and that is deliberate.
 *
 * Caldera's planner prefers higher-scoring facts. A score that encoded a guess
 * about which host "matters" would bias target selection invisibly — the
 * instructor sees an adversary that runs against DC01 and never learns that the
 * file server was ranked out of it by a heuristic in this file.
 */
const DEFAULT_SCORE = 1;

/**
 * The trait vocabulary, UNVERIFIED and REMAPPABLE.
 *
 * These are the names upstream's stockpile abilities are documented to consume.
 * A site whose plugin set spells one differently passes `options.traits` rather
 * than editing this file, because a wrong trait is a SILENT no-op: the fact is
 * stored, the ability never binds it, no link is created, and the step simply
 * does not happen.
 *
 * ONE HOST FACT PER HOST, and it is the FQDN. An operation creates one link per
 * (ability, matching fact), so also emitting a short name would run every
 * lateral-movement ability TWICE against the same machine — once as `dc01` and
 * once as `dc01.corp.local` — which is not a cosmetic defect: it doubles the
 * artifacts a student is asked to explain and makes the answer key's ability
 * count a lie.
 */
const TRAITS = Object.freeze({
  host: 'remote.host.fqdn',
  domain: 'domain.name',
  user: 'domain.user.name',
});

/**
 * Caldera's platform vocabulary, plus the honest fourth value.
 *
 * 'unknown' is not a platform — it is "this spec row did not say", which is a
 * different fact from "it is something exotic" and is reported rather than
 * guessed. summarizePlatforms() folds both into `other`.
 */
const PLATFORMS = Object.freeze(['windows', 'linux', 'darwin']);

/**
 * Roles that are NOT part of the exercise's target estate.
 *
 * Three groups, each excluded for its own reason:
 *
 *   gateway/router/firewall/controller  lane plumbing. The gateway is an LXC and
 *       the GOAD controller is powered off after the build — an ability aimed at
 *       either produces a link that can never run.
 *   attacker/kali/red                   the student's own box. Authoring an
 *       adversary that attacks the attack box is an exercise about nothing.
 *   siem/elk/wazuh/sensor/loggen        the EVIDENCE PLANE. This is the one that
 *       matters: an ability that lands on the SIEM corrupts the very store the
 *       student is being graded on reading, and it does it silently.
 *
 * Excluded hosts are REPORTED (`excluded[]` plus a warning), never dropped
 * quietly — the same rule adversary.js applies to unmapped steps, for the same
 * reason: an instructor who cannot see what was removed cannot tell a scoping
 * decision from a bug.
 */
const INFRASTRUCTURE_ROLES = new Set([
  'gateway', 'router', 'firewall', 'controller',
  'attacker', 'attack', 'kali', 'red',
  'siem', 'elk', 'wazuh', 'sensor', 'loggen', 'log-generator', 'log_generator', 'siem-source',
]);

/** Stable warning codes. The tests pin these strings. */
const WARNINGS = Object.freeze({
  NO_HOSTS: 'CALDERA_FACT_SOURCE_NO_HOSTS',
  UNKNOWN_PLATFORM: 'CALDERA_FACT_SOURCE_UNKNOWN_PLATFORM',
  INFRASTRUCTURE_EXCLUDED: 'CALDERA_FACT_SOURCE_INFRASTRUCTURE_EXCLUDED',
  PAPER_ONLY_ASSET: 'CALDERA_FACT_SOURCE_PAPER_ONLY_ASSET',
  DUPLICATE_HOST: 'CALDERA_FACT_SOURCE_DUPLICATE_HOST',
  DUPLICATE_SOURCE: 'CALDERA_FACT_SOURCE_DUPLICATE_NAME',
  NO_DOMAIN: 'CALDERA_FACT_SOURCE_NO_DOMAIN',
  NO_USERS: 'CALDERA_FACT_SOURCE_NO_USERS',
  PLATFORM_ABSENT: 'CALDERA_FACT_SOURCE_PLATFORM_ABSENT',
  ABILITY_UNKNOWN: 'CALDERA_FACT_SOURCE_ABILITY_NOT_IN_CATALOG',
  NOTHING_RUNNABLE: 'CALDERA_FACT_SOURCE_NOTHING_RUNNABLE',
});

/**
 * One refusal from this module.
 *
 * A named class with a `code`, on the same reasoning as CalderaError: a caller
 * has to tell "you gave me no scope" (a bug in the call) from "this client
 * cannot talk to sources" (a capability client.js has not grown yet) without
 * matching on a message.
 */
class FactSourceError extends Error {
  constructor(message, code) {
    super(message);
    this.name = 'FactSourceError';
    this.code = code || 'CALDERA_FACT_SOURCE_ERROR';
  }
}

// ---------------------------------------------------------------------------
// Normalisation
// ---------------------------------------------------------------------------

const str = (v) => (v == null ? '' : String(v)).trim();
const lower = (v) => str(v).toLowerCase();

/** A DNS-ish name, lowercased and stripped of a trailing dot. Never a URL. */
const normName = (v) => lower(v).replace(/\.+$/, '');

/**
 * What PLATFORM a machine is, from what the spec actually records.
 *
 * Read from os_family / os / os_name / platform / os_version and NOTHING ELSE.
 * Never from the hostname: a machine called `winston-01` is not Windows, and a
 * heuristic that says it is puts a Windows-only ability on a Linux box, where it
 * fails at execution time with a shell error an instructor has to open a link
 * log to see.
 *
 * Order matters. 'macos' contains 'os' and every Windows os_family this tree
 * emits ('windows_server', 'windows_client') contains 'windows', so the most
 * specific test runs first.
 *
 * @returns {'windows'|'linux'|'darwin'|'unknown'}
 */
function classifyPlatform(row) {
  const r = row || {};
  const text = [r.os_family, r.os, r.os_name, r.platform, r.os_version]
    .map(lower)
    .filter(Boolean)
    .join(' ');
  if (!text) return 'unknown';
  if (/mac ?os|darwin|osx|os x/.test(text)) return 'darwin';
  if (/windows|win_?(server|client)|win(7|8|10|11)\b/.test(text)) return 'windows';
  if (/linux|ubuntu|debian|rocky|rhel|centos|alma|fedora|suse|kali|alpine|amazon linux/.test(text)) {
    return 'linux';
  }
  return 'unknown';
}

/** Is this spec row lane plumbing, the attack box, or the evidence plane? */
function isInfrastructure(row) {
  const role = lower((row || {}).role);
  return role ? INFRASTRUCTURE_ROLES.has(role) : false;
}

/**
 * The AD domain(s) this spec knows about, primary first.
 *
 * Four places carry one, and all four are read because all four exist in the
 * wild (see src/utils/goad-deploy.js resolveGoadLab and
 * ciab/utils/profile-to-spec.js buildSpecDns):
 *
 *   an explicit `domain` argument      an instructor override, wins outright
 *   spec.dns.ad_domain                 what the lane's resolver actually answers
 *   spec.goad.domain                   what a generated engagement declared
 *   spec.goad.lab.forestRoot           the built-in lab table's forest root
 *
 * The CHILD domain is derived the one way ad-child_domain.yml can build one —
 * `<label>.<parent>` — because a child that is not a strict suffix of its parent
 * is a TRUST partner, not a child, and naming it as one produces a domain the
 * forest does not have. src/utils/ad-domain-rules.js makes this point at length
 * and GOAD_LABS records `childSubdomain: null` for exactly those labs (NHA,
 * SCCM) whose second domain is reached by a trust.
 */
function domainsFromSpec(spec, explicit) {
  const s = spec && typeof spec === 'object' ? spec : {};
  const dns = s.dns && typeof s.dns === 'object' ? s.dns : {};
  const goad = s.goad && typeof s.goad === 'object' ? s.goad : {};
  const lab = goad.lab && typeof goad.lab === 'object' ? goad.lab : {};

  const primary = normName(explicit)
    || normName(dns.ad_domain)
    || normName(goad.domain)
    || normName(lab.forestRoot)
    || null;

  const out = [];
  if (primary) out.push(primary);

  const child = normName(lab.childSubdomain || goad.child_subdomain);
  if (child && primary) {
    const fqdn = child.includes('.') ? child : `${child}.${primary}`;
    if (fqdn !== primary && fqdn.endsWith(`.${primary}`)) out.push(fqdn);
  }
  return out;
}

/**
 * Every VM row the spec declares, in one list.
 *
 * spec.vms is authoritative. spec.goad.lab.vms is folded in as a FALLBACK for a
 * spec carrying a generated lab definition whose machines have not been expanded
 * into spec.vms — goad-deploy.assertGoadRoster refuses to deploy a spec where
 * the two disagree, so on any spec that has actually deployed this adds nothing
 * and changes nothing.
 */
function specRows(spec) {
  const s = spec && typeof spec === 'object' ? spec : {};
  const rows = [];
  if (Array.isArray(s.vms)) for (const vm of s.vms) if (vm && typeof vm === 'object') rows.push(vm);
  const goad = s.goad && typeof s.goad === 'object' ? s.goad : {};
  const lab = goad.lab && typeof goad.lab === 'object' ? goad.lab : {};
  if (Array.isArray(lab.vms)) for (const vm of lab.vms) if (vm && typeof vm === 'object') rows.push(vm);
  return rows;
}

/** The short name a spec row goes by. `hostname` first — `name` is the Proxmox object name. */
const rowHostname = (row) => str((row || {}).hostname) || str((row || {}).name) || '';

// ---------------------------------------------------------------------------
// Hosts
// ---------------------------------------------------------------------------

/**
 * The class's real host set, one record per machine, in spec order.
 *
 * PURE. Every judgement it makes is recorded on the record itself rather than
 * applied silently: `excluded` says a machine was left out and `exclude_reason`
 * says why, `platform: 'unknown'` says the spec never recorded an OS.
 *
 * @param {object}   spec         the DEPLOYED spec
 * @param {object}   [opts]
 * @param {object[]} [opts.assets] profile assets, for OS enrichment only
 * @param {string}   [opts.domain] explicit AD domain override
 * @param {Function} [opts.warn]   (code, message) sink
 * @returns {Array<{name, fqdn, platform, role, domain, excluded, exclude_reason}>}
 */
function hostsFromSpec(spec, opts) {
  const o = opts || {};
  const warn = typeof o.warn === 'function' ? o.warn : () => {};
  const primary = domainsFromSpec(spec, o.domain)[0] || null;

  // Assets are ENRICHMENT ONLY, keyed on the spec's own hostnames.
  const byAsset = new Map();
  for (const a of (Array.isArray(o.assets) ? o.assets : [])) {
    if (a && typeof a === 'object' && rowHostname(a)) byAsset.set(lower(rowHostname(a)), a);
  }

  const seen = new Set();
  const out = [];

  for (const row of specRows(spec)) {
    const name = rowHostname(row);
    if (!name) continue;
    const key = lower(name);

    if (seen.has(key)) {
      // Two spec rows for one machine. Expected where goad.lab.vms overlaps
      // spec.vms; a genuine duplicate would seed the same host twice and run
      // every ability against it twice, so it is said out loud either way.
      warn(WARNINGS.DUPLICATE_HOST,
        `${name} is declared more than once in the spec; the first row wins and the rest are `
        + 'ignored — a second host fact would run every ability against that machine twice');
      continue;
    }
    seen.add(key);

    const asset = byAsset.get(key) || null;
    // The spec first, the profile's free-text `os` only as a fallback: the spec
    // is what was BUILT, the profile is what was described.
    let platform = classifyPlatform(row);
    if (platform === 'unknown' && asset) platform = classifyPlatform(asset);

    const domain = normName(row.domain) || primary;
    const record = {
      name,
      fqdn: domain ? `${key}.${domain}` : key,
      platform,
      role: lower(row.role) || null,
      domain: domain || null,
      excluded: false,
      exclude_reason: null,
    };

    if (isInfrastructure(row)) {
      record.excluded = true;
      record.exclude_reason = 'infrastructure';
    } else if (platform === 'unknown') {
      // NOT excluded. An unknown platform is a gap in the spec, not a machine
      // that should disappear from an instructor's picker — dropping it would
      // silently shrink the class's estate. It is seeded and reported.
      warn(WARNINGS.UNKNOWN_PLATFORM,
        `${name} records no OS in the spec (os_family/os/os_name are all empty), so its platform `
        + 'is unknown — an ability chosen for it may target the wrong platform and produce a link '
        + 'that fails at execution rather than one that never runs');
    }

    out.push(record);
  }

  const excluded = out.filter((h) => h.excluded);
  if (excluded.length) {
    warn(WARNINGS.INFRASTRUCTURE_EXCLUDED,
      `${excluded.map((h) => `${h.name} (${h.role})`).join(', ')} `
      + `${excluded.length === 1 ? 'is' : 'are'} lane infrastructure, the attack box or the `
      + 'evidence plane, and so not seeded as a target — an ability that lands on the SIEM '
      + 'corrupts the store the student is being graded on reading');
  }

  // Paper-only assets: described by the profile, never deployed. Reported so an
  // instructor authoring "move to FILE02" learns FILE02 is not in this lane
  // BEFORE the operation runs, rather than from an empty link list afterwards.
  const deployed = new Set(out.map((h) => lower(h.name)));
  const paper = [...byAsset.keys()].filter((k) => !deployed.has(k)).sort();
  if (paper.length) {
    warn(WARNINGS.PAPER_ONLY_ASSET,
      `${paper.join(', ')} appear in the client profile but are NOT deployed in this scope, so `
      + 'they are not seeded — an adversary aimed at one of them creates a link that can never '
      + 'run and an answer key that describes activity nothing performed');
  }

  return out;
}

/**
 * "This class has 3 Windows, 1 Linux."
 *
 * EXACTLY three keys, because that is the shape a caller renders. darwin and
 * unknown both land in `other`: they are different facts to a diagnostician and
 * the same fact to an instructor deciding whether a Windows adversary will run
 * here. hostsFromSpec() keeps the finer distinction for anyone who needs it.
 *
 * Counts TARGETABLE hosts only — infrastructure is not part of the estate an
 * adversary is authored against, so counting it would overstate the class and
 * make an all-Windows estate with an ELK box look like it has a Linux target.
 */
function summarizePlatforms(spec) {
  const out = { windows: 0, linux: 0, other: 0 };
  for (const host of hostsFromSpec(spec)) {
    if (host.excluded) continue;
    if (host.platform === 'windows') out.windows += 1;
    else if (host.platform === 'linux') out.linux += 1;
    else out.other += 1;
  }
  return out;
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

/**
 * The class's account set.
 *
 * READ THE CODE, NOT THE PLAN: NOTHING IN THIS TREE WRITES A USER SET ONTO A
 * SPEC TODAY. ciab/utils/goad-lab-compile.js builds `lab.domains[fqdn].users`
 * while compiling a generated forest, but what reaches the spec is
 * `goad.generated_lab.files` — YAML TEXT, not a structured roster — and
 * profile-to-spec.js emits no users at all. Every location below is therefore a
 * place a user set MAY appear, and the common case today is that none of them
 * do, which is REPORTED (WARNINGS.NO_USERS) rather than papered over with
 * invented accounts.
 *
 * An explicit `users` argument is how a caller that DOES know the roster (the
 * compiler that produced the forest, an instructor's own list) supplies it
 * without this module growing a dependency on either — and core must not require
 * into a plugin, so a dependency is not available to it in any case.
 *
 * A PASSWORD IS NEVER READ, whatever shape a roster arrives in. See the header.
 */
function usersFromSpec(spec, explicit) {
  const s = spec && typeof spec === 'object' ? spec : {};
  const goad = s.goad && typeof s.goad === 'object' ? s.goad : {};
  const lab = goad.lab && typeof goad.lab === 'object' ? goad.lab : {};

  const candidates = [];
  const push = (v) => {
    if (!v) return;
    if (Array.isArray(v)) { for (const u of v) candidates.push(u); return; }
    // `{sam: {...}}` — the shape goad-lab-compile builds a domain block in.
    if (typeof v === 'object') { for (const k of Object.keys(v)) candidates.push(k); return; }
    candidates.push(v);
  };
  push(explicit);
  push(s.users);
  push(goad.users);
  push(lab.users);

  const seen = new Set();
  const out = [];
  for (const raw of candidates) {
    // A bare string, or an object naming the account. Deliberately NOT `email`:
    // a UPN is not a sAMAccountName, and an ability handed one where the other
    // is wanted fails at authentication rather than at parse.
    const name = typeof raw === 'string'
      ? str(raw)
      : str(raw && (raw.sam || raw.samaccountname || raw.username || raw.name || raw.account));
    if (!name) continue;
    const key = name.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(name);
  }
  return out;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * A stable, collision-free name for one scope's fact source.
 *
 *     CyberCore: <label> [<digest>]
 *
 * The DIGEST is over the scope KEY, not the label, and that is the whole point:
 * two sections a human called "Section A" are two scopes with two keys and get
 * two rows, while the same scope re-synced next term keeps the row it had. A
 * name built from the label alone silently merges the first pair; a name
 * carrying a timestamp or a run id silently splits the second.
 *
 * Control characters and newlines are stripped because the name is rendered in a
 * list on a shared server, and a label containing a newline makes two rows out
 * of one for anyone reading it.
 */
function factSourceName(scopeLabel, scopeKey) {
  const label = str(scopeLabel)
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim()
    .slice(0, MAX_LABEL_CHARS);
  const digest = uuidv5(str(scopeKey), FACT_SOURCE_NAMESPACE)
    .replace(/-/g, '')
    .slice(0, DIGEST_CHARS);
  return `${NAME_PREFIX}${label} [${digest}]`;
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/**
 * Build one class's fact source.
 *
 * @param {object}   opts
 * @param {string}   opts.scopeLabel  what a human calls this class. REQUIRED —
 *                                    the name is the only handle an instructor
 *                                    has on a server with no tenancy.
 * @param {string}   [opts.scopeKey]  the scope's stable identity (section id,
 *                                    engagement id). Defaults to scopeLabel;
 *                                    supply it whenever two scopes could share a
 *                                    label.
 * @param {object}   opts.spec        the DEPLOYED spec
 * @param {object[]} [opts.assets]    profile assets — enrichment only
 * @param {string}   [opts.domain]    AD domain override
 * @param {*}        [opts.users]     the account set; see usersFromSpec
 * @param {object}   [opts.traits]    per-site trait remap; see TRAITS
 * @returns {{version, id, name, scope_label, facts, hosts, platforms, domains,
 *            users, excluded, warnings}}
 *   `facts` is the wire payload's array; everything else is for the CALLER and
 *   is stripped by toWire() before anything is sent. A superset is safe for the
 *   same reason it is in adversary.js's answer key: the consumer reads by name.
 * @throws {FactSourceError} when there is no scope to name the source after
 */
function buildFactSource(opts) {
  const o = opts || {};
  const scopeLabel = str(o.scopeLabel);
  if (!scopeLabel) {
    // Not defaultable. An unnamed source on a server with no tenancy is a row
    // the next class overwrites, and the symptom is one section's adversary
    // running against another section's hosts.
    throw new FactSourceError(
      'buildFactSource: scopeLabel is required — it is the only thing distinguishing one class\'s '
      + 'fact source from another on a Caldera server that has no per-object ownership',
      'CALDERA_FACT_SOURCE_NO_SCOPE'
    );
  }
  const scopeKey = str(o.scopeKey) || scopeLabel;
  const traits = { ...TRAITS, ...(o.traits && typeof o.traits === 'object' ? o.traits : {}) };

  /** @type {string[]} */
  const warnings = [];
  const warn = (code, message) => warnings.push(`${code}: ${message}`);

  const hosts = hostsFromSpec(o.spec, { assets: o.assets, domain: o.domain, warn });
  const targetable = hosts.filter((h) => !h.excluded);
  const domains = domainsFromSpec(o.spec, o.domain);
  const users = usersFromSpec(o.spec, o.users);

  if (!targetable.length) {
    warn(WARNINGS.NO_HOSTS,
      'this scope has no targetable host in its deployed spec, so the fact source seeds nothing — '
      + 'an operation against it creates no links and finishes instantly having done nothing');
  }
  if (!domains.length) {
    warn(WARNINGS.NO_DOMAIN,
      'no AD domain is recorded on this spec (dns.ad_domain, goad.domain and goad.lab.forestRoot '
      + `are all empty), so host facts are bare hostnames and no '${traits.domain}' fact is seeded`);
  }
  if (!users.length) {
    warn(WARNINGS.NO_USERS,
      `nothing on this spec records an account set, so no '${traits.user}' fact is seeded and any `
      + 'ability that consumes one will not run. Supply users explicitly when the forest compiler '
      + 'knows them');
  }

  /** @type {Array<{trait:string,value:string,score:number}>} */
  const facts = [];
  const push = (trait, value) => {
    const v = str(value);
    if (!trait || !v) return;
    facts.push({ trait: String(trait), value: v, score: DEFAULT_SCORE });
  };

  for (const d of domains) push(traits.domain, d);
  for (const h of targetable) push(traits.host, h.fqdn);
  for (const u of users) push(traits.user, u);

  // Sorted, so the same class syncs a BYTE-IDENTICAL source every time: anyone
  // diffing two syncs sees a real change or nothing, never a reordering of the
  // same facts caused by a spec whose vms array came back in another order.
  facts.sort((a, b) => a.trait.localeCompare(b.trait) || a.value.localeCompare(b.value));

  return {
    version: FACT_SOURCE_VERSION,
    id: uuidv5(scopeKey, FACT_SOURCE_NAMESPACE),
    name: factSourceName(scopeLabel, scopeKey),
    scope_label: scopeLabel,
    facts,
    hosts,
    platforms: {
      windows: targetable.filter((h) => h.platform === 'windows').length,
      linux: targetable.filter((h) => h.platform === 'linux').length,
      other: targetable.filter((h) => h.platform !== 'windows' && h.platform !== 'linux').length,
    },
    domains,
    users,
    excluded: hosts.filter((h) => h.excluded).map((h) => h.name),
    warnings,
  };
}

/**
 * The wire body, BUILT FROM A WHITELIST.
 *
 * Never a spread of the built object and never a delete of the extra keys:
 * "delete what must not be sent" fails open the first time this file grows a
 * field, and the fields it grows are exactly the ones (host roles, exclusion
 * reasons, warnings) that describe a class's estate to STAFF rather than to a
 * server every instructor shares.
 */
function toWire(factSource) {
  const f = factSource && typeof factSource === 'object' ? factSource : {};
  const id = str(f.id);
  const name = str(f.name);
  if (!id || !name) {
    throw new FactSourceError(
      'syncFactSource: the fact source must carry the id and name buildFactSource() derived — '
      + 'those two are what make a re-sync update one class\'s row instead of creating a second',
      'CALDERA_FACT_SOURCE_MALFORMED'
    );
  }
  return {
    id,
    name,
    facts: (Array.isArray(f.facts) ? f.facts : [])
      .map((fact) => ({
        trait: str(fact && fact.trait),
        value: str(fact && fact.value),
        score: Number.isFinite(Number(fact && fact.score)) ? Number(fact.score) : DEFAULT_SCORE,
      }))
      .filter((fact) => fact.trait && fact.value),
    // Upstream's Source object carries these three alongside `facts`. Sent as
    // empty arrays rather than omitted: a PATCH that omits a key is a key the
    // server may KEEP, so a source that once held a rule would go on applying it
    // to a class that no longer declares one.
    relationships: [],
    rules: [],
    adjustments: [],
  };
}

/**
 * Find this class's row in whatever the server handed back.
 *
 * Accepts a bare object (getSource) or an array (listSources), because both
 * shapes are documented for the v2 API and a 204 gives neither.
 *
 * A DUPLICATE NAME is resolved deterministically (lowest id) and reported. The
 * alternative — taking whichever the server listed first — makes the same
 * re-sync update a different row on different days, which is the exact failure
 * this function exists to prevent.
 */
function matchOneSource(payload, wire, warnings) {
  const rows = Array.isArray(payload)
    ? payload
    : (payload && typeof payload === 'object' ? [payload] : []);
  const byName = [];
  for (const row of rows) {
    if (!row || typeof row !== 'object') continue;
    const id = str(row.id || row.source_id);
    if (!id) continue;
    if (id === wire.id) return id;
    if (str(row.name) === wire.name) byName.push(id);
  }
  if (!byName.length) return null;
  byName.sort();
  if (byName.length > 1) {
    warnings.push(`${WARNINGS.DUPLICATE_SOURCE}: ${byName.length} fact sources on this server are `
      + `named ${JSON.stringify(wire.name)}; updating ${byName[0]} and leaving the rest, which an `
      + 'instructor can still pick by mistake — Caldera has no per-object ownership, so CyberCore '
      + 'can report that but not prevent it');
  }
  return byName[0];
}

/**
 * Create or update this class's fact source. IDEMPOTENT BY CONSTRUCTION.
 *
 * Re-running for the same class must UPDATE, never duplicate. A server with no
 * tenancy and thirty near-identical rows called "CyberCore: Section A" is a
 * server where an instructor picks the wrong one, and picking the wrong one is
 * unobservable: the operation runs, against another section's hosts.
 *
 * Two rungs, most authoritative first:
 *   1. the deterministic id — a uuidv5 over the scope key, so the same class
 *      always addresses the same row;
 *   2. the name — for a row created before this file existed, or by hand in the
 *      UI, whose id we did not choose.
 *
 * WHY IT TAKES A CLIENT INSTEAD OF CALLING fetch(). Same seam as the rest of the
 * adapter: this module opens no socket, so every behaviour below is a plain unit
 * test against an injected fake.
 *
 * WHY IT DUCK-TYPES THE CLIENT. src/incident/caldera/client.js has NO source
 * methods today — verified, not assumed: it exposes health, listAbilities,
 * createAdversary, listAgents, createOperation, getOperation, listLinks,
 * finishOperation, abortOperation and nothing else. Rather than reach around it
 * (which would put a second HTTP call site in this adapter and break the one
 * rule that makes it testable), this refuses with a named code naming the
 * methods the client must grow. They belong in client.js, the only file in the
 * adapter allowed to open a socket.
 *
 * @param {object} client      needs listSources() and createSource(); plus
 *                             updateSource(id, body) for the update path, and
 *                             optionally getSource(id) to skip the listing.
 * @param {object} factSource  as returned by buildFactSource()
 * @returns {Promise<{action:'created'|'updated', id:string, name:string, warnings:string[]}>}
 *   ONE discriminant rather than two booleans: {created, updated} admits a
 *   both-false and a both-true state that mean nothing, and a caller reading
 *   only `created` reads every update as a failure.
 */
async function syncFactSource(client, factSource) {
  const c = client && typeof client === 'object' ? client : null;
  const missing = ['listSources', 'createSource', 'updateSource']
    .filter((m) => !c || typeof c[m] !== 'function');
  if (missing.length) {
    throw new FactSourceError(
      'syncFactSource: this Caldera client cannot reach fact sources — it is missing '
      + `${missing.join(', ')}. src/incident/caldera/client.js does not implement them yet; they `
      + 'belong there (GET /api/v2/sources, POST /api/v2/sources, PATCH /api/v2/sources/{id}) and '
      + 'nowhere else, because it is the only file in this adapter allowed to open a socket.',
      'CALDERA_CLIENT_NO_SOURCE_API'
    );
  }

  const wire = toWire(factSource);
  /** @type {string[]} */
  const warnings = [];

  let existing = null;
  if (typeof c.getSource === 'function') {
    // Cheaper and exact where the client offers it. A miss must not be an error:
    // a source that is not there is precisely what createSource is for.
    existing = matchOneSource(await c.getSource(wire.id), wire, warnings);
  }
  if (!existing) {
    existing = matchOneSource(await c.listSources(), wire, warnings);
  }

  if (existing) {
    // Updated unconditionally, even when the facts are byte-identical. The
    // server is the authority on what it holds; a diff computed here would be a
    // diff against what we THINK it holds, and being wrong means a class runs
    // against last term's host set.
    await c.updateSource(existing, { ...wire, id: existing });
    return { action: 'updated', id: existing, name: wire.name, warnings };
  }

  const created = await c.createSource(wire);
  const id = str(created && (created.id || created.source_id)) || wire.id;
  return { action: 'created', id, name: wire.name, warnings };
}

// ---------------------------------------------------------------------------
// The platform check
// ---------------------------------------------------------------------------

/**
 * Would this adversary actually do anything in this class?
 *
 * An operation creates a link only where an ability's platform matches an
 * agent's. A linux-only adversary against an all-Windows class therefore does
 * not fail — it SUCCEEDS, instantly, having created no links, and the run row
 * says completed. The instructor's first evidence is a class that all found
 * nothing, and by then the exercise is over.
 *
 * So this is a WARNING PATH, never a silent pass and never a throw: an
 * instructor may legitimately author for a platform the class does not have yet
 * (a machine is being added next week), and refusing would make that impossible.
 *
 * @param {object}   opts
 * @param {object}   opts.adversary   needs `atomic_ordering`
 * @param {object[]} opts.abilities   the injected catalog, in any shape
 *                                    adversary.normalizeAbility accepts
 * @param {object}   [opts.spec]      the deployed spec — the platform set
 * @param {object}   [opts.platforms] a precomputed summarizePlatforms() result,
 *                                    for a caller that already has one
 * @returns {{warnings:string[], unreachable:Array<{ability_id,platforms}>,
 *            unknown:string[], reachable:number}}
 */
function checkAdversaryPlatforms(opts) {
  const o = opts || {};
  const adversary = o.adversary && typeof o.adversary === 'object' ? o.adversary : {};
  const ordering = Array.isArray(adversary.atomic_ordering) ? adversary.atomic_ordering : [];

  const summary = o.platforms && typeof o.platforms === 'object'
    ? o.platforms
    : summarizePlatforms(o.spec);
  const available = new Set();
  if (Number(summary.windows) > 0) available.add('windows');
  if (Number(summary.linux) > 0) available.add('linux');
  // `other` deliberately grants NOTHING. A darwin host and a host whose OS the
  // spec never recorded are both 'other', and treating that as "any platform is
  // fine" would turn this check into a rubber stamp on exactly the specs that
  // most need it.

  const byId = new Map();
  for (const raw of (Array.isArray(o.abilities) ? o.abilities : [])) {
    const ab = normalizeAbility(raw);
    if (ab) byId.set(ab.id, ab);
  }

  /** @type {string[]} */
  const warnings = [];
  const unreachable = [];
  const unknown = [];
  let reachable = 0;

  const have = `${summary.windows} windows, ${summary.linux} linux, ${summary.other} other`;

  for (const rawId of ordering) {
    const id = str(rawId);
    const ab = byId.get(id);
    if (!ab) {
      // Not a platform question at all: an id the catalog does not carry is a
      // 404 at operation-create time, hours after launch was pressed.
      unknown.push(id);
      warnings.push(`${WARNINGS.ABILITY_UNKNOWN}: ability ${id} is in this adversary's `
        + 'atomic_ordering but not in the injected catalog, so its platform cannot be checked and '
        + 'the server will reject or skip it at operation time');
      continue;
    }
    if (!ab.platforms.length || ab.platforms.some((p) => available.has(p))) {
      // An ability that declares no platform is not evidence of a mismatch.
      reachable += 1;
      continue;
    }
    unreachable.push({ ability_id: ab.id, platforms: ab.platforms.slice() });
    warnings.push(`${WARNINGS.PLATFORM_ABSENT}: ability ${ab.id} (${ab.name}) runs only on `
      + `${ab.platforms.join('/')} and this scope has ${have} — the operation will create NO link `
      + 'for it, so that step silently does not happen while the answer key still describes it');
  }

  if (ordering.length && reachable === 0) {
    warnings.push(`${WARNINGS.NOTHING_RUNNABLE}: not one ability in this adversary can run against `
      + `this scope (${have}). The operation would complete instantly having done nothing, and the `
      + 'run row would report success');
  }

  return { warnings, unreachable, unknown, reachable };
}

module.exports = {
  buildFactSource,
  syncFactSource,
  summarizePlatforms,
  checkAdversaryPlatforms,
  FactSourceError,
  FACT_SOURCE_VERSION,
  FACT_SOURCE_NAMESPACE,
  TRAITS,
  PLATFORMS,
  INFRASTRUCTURE_ROLES,
  WARNINGS,
  // Exported for the tests, which pin the derivation rules directly rather than
  // only through a whole build.
  hostsFromSpec,
  domainsFromSpec,
  usersFromSpec,
  classifyPlatform,
  factSourceName,
  toWire,
};
