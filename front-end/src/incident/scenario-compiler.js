// ============================================================================
// scenario-compiler.js — Track E, phase E4: a client's threat profile becomes
// an exercise.
//
// WHAT IT DOES. A CiAB profile carries threat scenarios: an ordered attack_path
// of {step, action, target, technique, detection_opportunity} over the client's
// own assets (DC01, FILE01, HMI-01). This turns one of those into what the
// baked sensor can actually run — cc-emit playbooks — plus the staff-only key
// that grades it.
//
//   compileScenario({scenario, assets, options}) -> {attack, floor, answerKey, warnings}
//
// TWO PLAYBOOKS, NOT ONE. THIS IS THE WHOLE DESIGN.
// -----------------------------------------------------------------------------
// test/loggen-playbooks.test.js (now also test/helpers/playbook-contract.js)
// proves that any source.host, any (source.type, source.name) pair, any
// closed-vocabulary metadata value and any /8 address space that appears ONLY
// during an attack is a one-terms-aggregation answer key: one click in Discover
// and the exercise is over, with nothing in review to show for it.
//
// The BAKED benign floor draws its hosts from generic pools — web-01, db-01,
// ws-042. A CiAB profile's assets are DC01, FILE01, HMI-01. Ship only an attack
// playbook into that lane and
//
//     loggen.source.host : DC01
//
// ends the exercise in one click. Every part of it would review as working: the
// run dispatches, the events land, the console reports lines>0.
//
// So the compiler emits a MATCHING floor — the client's own hostnames doing
// ordinary work — and the attack draws every host, account and address from the
// floor's own pools. The floor's STEPS are the baked ones, verbatim: they are
// the vocabulary src/incident/scenario-templates.js mirrors, and regenerating
// them would break the mirror silently. Only pool CONTENTS change, which is
// exactly the thing that needs no re-bake (cc-hostbase.service reads a fixed
// path, /opt/cybercore/host-baseline.json — see the floor swap in
// ciab/utils/blueteam-postdeploy.js).
//
// THE HARD CONSTRAINT: cc-emit.js IS BAKED INTO TEMPLATE 1007.
// -----------------------------------------------------------------------------
// A new cc-emit feature is a re-bake AND a redeploy of every existing lane. So
// everything below uses only what cc-emit already has:
//
//   entities   "literal" | {oneOf:[...]} | {ipv4Host:"10.1.2"}
//   pools      {name: [strings]}          bindings {k:{pool,by}}   skewed [name]
//   rhythm     {utc_offset, hourly[24], weekend}
//   steps      {gap, spread, count, overlap, level, source{type,name,host},
//               message | templates[{weight,message,level,metadata}],
//               metadata{}, technique, tactic, subtechnique}
//   tokens     {{key}} {{key.N}} {{rand:lo-hi}} {{port}} {{pid}} {{seq}}
//
// and the SIX-KEY envelope, with every metadata value a STRING — loggen.metadata
// is mapped `flattened`, so a number there is a mapping conflict waiting to
// reject documents. Quantities go in the message text, which is where real logs
// put them anyway.
//
// WHAT MUST NEVER REACH A MESSAGE.
// -----------------------------------------------------------------------------
// `attack_path[].action` and `attack_path[].detection_opportunity`.
// detection_opportunity is LITERALLY the answer — "unusual outbound volume from
// FILE01 to an unfamiliar host after hours" is the finding the student is being
// graded on discovering. Both go to the answer key and nowhere else, and
// assertNoScenarioProseLeaked() below re-checks the compiled JSON rather than
// trusting that the code above it stayed careful.
//
// PURITY. No DB, no network, no fs at module load. The one file read is the
// baked floor, pulled through require() on first use and memoised: it is a repo
// asset that test/bake-payloads.test.js pins byte-for-byte against the copy
// inside the bake script, so requiring it is requiring the same bytes the lane
// runs. A caller that has its own floor passes options.floorTemplate.
// ============================================================================
'use strict';

const emit = require('./cc-emit');
const { TACTIC_TEMPLATES, tacticFor, tacticIndex } = require('./scenario-templates');
const { compileAnswerKey } = require('./answer-key');

// ---------------------------------------------------------------------------
// Warning codes. Every one of these means "the exercise was still built, but a
// human should know what was guessed" — a compiler that silently invents is one
// an instructor discovers mid-class.
// ---------------------------------------------------------------------------
const WARNING_CODES = {
  UNPARSEABLE_TECHNIQUE: 'UNPARSEABLE_TECHNIQUE',
  UNMAPPED_TECHNIQUE: 'UNMAPPED_TECHNIQUE',
  UNKNOWN_TARGET: 'UNKNOWN_TARGET',
  EMPTY_BUCKET: 'EMPTY_BUCKET',
  NO_ASSETS: 'NO_ASSETS',
  NO_STAKEHOLDERS: 'NO_STAKEHOLDERS',
  NO_LANE_ADDRESSES: 'NO_LANE_ADDRESSES',
  HOST_TELEMETRY_CEDED: 'HOST_TELEMETRY_CEDED',
  TACTIC_UNREPRESENTABLE: 'TACTIC_UNREPRESENTABLE',
};

/**
 * The floor's host pools, in the order the compiler fills them.
 *
 * These names are NOT ours to choose — they are the pool names the baked
 * host-baseline.json steps already reference and that TACTIC_TEMPLATES draws
 * its `source.host` from. Renaming one here leaves the floor's own steps
 * pointing at a pool that no longer exists, every draw returns null, and
 * cc-emit ships literal "{{srvpool}}" to Kibana.
 */
const HOST_POOLS = [
  'fwpool', 'webpool', 'dbpool', 'mailpool', 'authpool', 'apppool',
  'srvpool', 'wspool', 'hosts',
];

/**
 * How an asset lands in a bucket, most specific first.
 *
 * Matched against hostname + role + function + subnet + services, because the
 * profile generator spreads the same fact across all of them: `dc-01` names it
 * in the hostname, "Primary domain controller" in the function, `389/LDAP` in
 * the services. Any one of the three is enough.
 *
 * `roles` short-circuits: role is the one field the synthesizer treats as
 * structured, so an asset marked role:'network' is firewall/switch material
 * whatever it happens to be called.
 */
const BUCKET_RULES = {
  fwpool: {
    roles: ['network'],
    re: /(^|[^a-z])(fw|firewall|edge|gw|gateway|asa|palo|fortigate|fortinet|opnsense|pfsense|sonicwall|router|switch|utm|vpn)([^a-z]|$)/,
  },
  webpool: {
    re: /(^|[^a-z])(web|www|nginx|apache|iis|http|https|portal|intranet|wordpress)([^a-z]|$)/,
  },
  dbpool: {
    re: /(^|[^a-z])(db|sql|mssql|postgres|postgresql|mysql|mariadb|oracle|database|historian)([^a-z]|$)/,
  },
  mailpool: {
    re: /(^|[^a-z])(mail|smtp|imap|exchange|mx|postfix|relay)([^a-z]|$)/,
  },
  authpool: {
    re: /(^|[^a-z])(dc|ad|adds|adfs|ldap|idp|auth|identity|radius|nps|kerberos|domain controller)([^a-z]|$)/,
  },
  apppool: {
    re: /(^|[^a-z])(app|api|erp|crm|sis|ils|scada|hmi|plc|report|reporting|sharepoint|jira|line-of-business)([^a-z]|$)/,
  },
  srvpool: { roles: ['server', 'ot'] },
  wspool: { roles: ['workstation', 'laptop', 'client', 'endpoint'] },
  hosts: { all: true },
};

/**
 * The floor's own service accounts, kept whatever the client looks like.
 *
 * A client profile names five or six stakeholders. Five accounts is not an
 * estate: `bindings.userips` maps accounts to desks, a password spray has to
 * read as many-accounts-one-source, and the answer key's "an account that only
 * ever appears during the attack is the answer" rule needs a benign population
 * to hide the actor in. These are the non-person accounts every estate has, and
 * they are lifted from the baked floor so the two vocabularies stay related.
 */
const SERVICE_ACCOUNTS = [
  'admin', 'operator', 'helpdesk', 'helpdesk2', 'backupsvc', 'monitor01',
  'sysadm', 'guest', 'svc_backup', 'svc_report', 'svc_deploy', 'svc_scan',
  'svc_sync',
];

/**
 * The /24 the external adversary is drawn from.
 *
 * TEST-NET-3, which is where the baked floor's own `extips` already live — so
 * `NOT loggen.metadata.src_ip : 10.*` returns ordinary internet traffic as well
 * as the intrusion, and "the intruder is the unfamiliar address" stays a habit
 * the exercise refuses to reward.
 *
 * The specific addresses are chosen at compile time as the ones the floor does
 * NOT enumerate (see externalAdversaryPool). That is not an oracle — the
 * metadata-vocabulary contract deliberately exempts fields with more than fifty
 * benign values, and src_ip has hundreds — but it does mean the answer key has
 * one address to grade against, which is the difference between a board that
 * scores IOCs and a board that shows an empty list.
 */
const ADVERSARY_NET = '203.0.113';

/** Windows, for the E3b cede. Matched on the profile's own free-text `os`. */
const WINDOWS_RE = /(^|[^a-z])win(dows)?([^a-z]|$)|windows/i;

/** Cheap structural clone. Playbooks are plain JSON by construction. */
const clone = (v) => JSON.parse(JSON.stringify(v));

const uniq = (list) => {
  const seen = new Set();
  const out = [];
  for (const v of list) {
    const s = String(v == null ? '' : v).trim();
    if (!s || seen.has(s)) continue;
    seen.add(s);
    out.push(s);
  }
  return out;
};

/**
 * The baked benign floor, required once.
 *
 * Lazy, so `require('./scenario-compiler')` itself does no I/O and the module
 * stays importable in any context that can load cc-emit.
 */
let _bakedFloor = null;
function bakedFloor() {
  if (!_bakedFloor) _bakedFloor = require('./playbooks/host-baseline.json');
  return _bakedFloor;
}

// ---------------------------------------------------------------------------
// Assets
// ---------------------------------------------------------------------------

/** Everything about an asset a bucket rule may match on, lowercased. */
function assetText(asset) {
  const a = asset || {};
  const services = Array.isArray(a.services) ? a.services : [];
  return [a.hostname, a.role, a.function, a.subnet, a.os, ...services]
    .map((v) => String(v == null ? '' : v))
    .join(' ')
    .toLowerCase();
}

/**
 * Is this a Windows machine.
 *
 * Read off the profile's free-text `os` ("Windows Server 2019 Standard
 * 10.0.17763", "Windows 11 23H2") and nothing else, because that is the only
 * field the generator is required to fill. An `os_family` is honoured when a
 * caller has already parsed one.
 */
function isWindowsAsset(asset) {
  const a = asset || {};
  if (a.os_family) return /^windows/i.test(String(a.os_family));
  return WINDOWS_RE.test(String(a.os || ''));
}

/** Does this asset serve HTTP, by port or by scheme? */
function servesHttp(asset) {
  const services = Array.isArray(asset && asset.services) ? asset.services : [];
  return services.some((s) => /(^|[^0-9])(80|443|8080|8443)([^0-9]|$)/.test(String(s))
    || /https?/i.test(String(s)));
}

function matchesBucket(asset, name) {
  const rule = BUCKET_RULES[name];
  if (!rule) return false;
  if (rule.all) return true;
  const role = String((asset && asset.role) || '').trim().toLowerCase();
  if (rule.roles && rule.roles.includes(role)) return true;
  if (name === 'webpool' && servesHttp(asset)) return true;
  return rule.re ? rule.re.test(assetText(asset)) : false;
}

/**
 * Bucket a profile's assets into the floor's EXISTING pool names.
 *
 * Overlapping on purpose, exactly as the baked floor overlaps: db-01 is in
 * `dbpool` AND `srvpool` AND `hosts` there, and DB01 is in all three here. A
 * host that appears in only one pool is a host the floor barely emits, and a
 * rarely-emitted host that the attack targets is most of the way back to being
 * an oracle.
 *
 * Ordering inside a bucket is not cosmetic: `srvpool`, `wspool` and `hosts` are
 * `skewed`, so cc-emit reads them roughly most-common-first with a long tail.
 * The scenario's own targets go to the FRONT — the domain controller and the
 * file server really are the busiest machines in a small estate, and a victim
 * that ordinary traffic hardly touches is a tell in its own right.
 *
 * @returns {{buckets: Object<string,string[]>, byHostname: Map<string,object>}}
 */
function bucketAssets(assets, opts) {
  const o = opts || {};
  const warn = o.warn || (() => {});
  const priority = o.priority instanceof Set ? o.priority : new Set();
  const baked = o.bakedPools || bakedFloor().pools;

  const list = Array.isArray(assets) ? assets.filter((a) => a && a.hostname) : [];
  const byHostname = new Map();
  for (const a of list) byHostname.set(String(a.hostname).trim().toLowerCase(), a);

  const rank = (a) => {
    const h = String(a.hostname).trim().toLowerCase();
    if (priority.has(h)) return 0;
    if (a.critical) return 1;
    return String(a.role || '').toLowerCase() === 'workstation' ? 3 : 2;
  };
  // Stable: rank, then the profile's own order. Never the hostname, because
  // alphabetical order would put ws-001 ahead of the domain controller.
  const ordered = list
    .map((a, i) => ({ a, i }))
    .sort((x, y) => (rank(x.a) - rank(y.a)) || (x.i - y.i))
    .map((x) => x.a);

  const allNames = uniq(ordered.map((a) => a.hostname));
  const buckets = {};

  for (const name of HOST_POOLS) {
    let members = uniq(ordered.filter((a) => matchesBucket(a, name)).map((a) => a.hostname));
    if (!members.length && allNames.length) {
      // Fall back to the whole estate. Coarse — a firewall pool containing the
      // domain controller means the DC narrates iptables lines — but an EMPTY
      // pool is not a degraded exercise, it is a broken one: samplePool returns
      // null and cc-emit ships literal "{{fwpool}}" into Kibana.
      members = allNames;
      warn(WARNING_CODES.EMPTY_BUCKET,
        `no asset matched ${name}; falling back to the whole estate (${allNames.length} host(s))`);
    }
    if (!members.length) {
      members = Array.isArray(baked[name]) ? baked[name].slice() : [];
      warn(WARNING_CODES.NO_ASSETS,
        `no assets at all; ${name} falls back to the baked generic pool`);
    }
    buckets[name] = members;
  }

  return { buckets, byHostname, ordered };
}

// ---------------------------------------------------------------------------
// Accounts and addresses
// ---------------------------------------------------------------------------

/**
 * A stakeholder becomes a login name.
 *
 * Accepts what profiles actually hold: a bare string, or an object with any of
 * username/account/login/email/name. First-initial + surname is the convention
 * the baked floor's own person accounts use (jsmith, mrodriguez), so a compiled
 * estate and the service accounts beside it read as one directory.
 */
function accountFor(stakeholder) {
  const s = stakeholder;
  const clean = (v) => String(v || '')
    .trim()
    .toLowerCase()
    .replace(/[^a-z0-9._-]/g, '');

  if (typeof s === 'string') {
    if (!/\s/.test(s.trim())) return clean(s);
    return accountFor({ name: s });
  }
  if (!s || typeof s !== 'object') return '';

  for (const key of ['username', 'account', 'login', 'sam_account_name']) {
    if (s[key]) return clean(s[key]);
  }
  if (s.email && String(s.email).includes('@')) return clean(String(s.email).split('@')[0]);

  const parts = String(s.name || s.full_name || '').trim().split(/\s+/).filter(Boolean);
  if (parts.length >= 2) return clean(parts[0][0] + parts[parts.length - 1]);
  return clean(parts[0] || '');
}

/**
 * Every address the ESTATE legitimately uses.
 *
 * The lane's real .80–.99 band first (that is where the deployed machines
 * actually are), then the profile's own asset addresses, then the baked band as
 * a last resort. Order matters for the same reason bucket order does: `lanips`
 * is skewed.
 */
function laneAddressPool(assets, opts) {
  const o = opts || {};
  const warn = o.warn || (() => {});
  const supplied = Array.isArray(o.laneIps) ? o.laneIps : [];
  const assetIps = (Array.isArray(assets) ? assets : [])
    .map((a) => (a && a.ip ? String(a.ip).trim() : ''))
    .filter((ip) => /^\d{1,3}(\.\d{1,3}){3}$/.test(ip));

  const pool = uniq([...supplied, ...assetIps]);
  if (pool.length) return pool;

  warn(WARNING_CODES.NO_LANE_ADDRESSES,
    'no lane band and no asset addresses; lanips falls back to the baked band');
  return (o.bakedPools || bakedFloor().pools).lanips.slice();
}

/**
 * Adversary addresses the floor does not enumerate.
 *
 * Derived FROM the floor rather than hardcoded, so it cannot drift out of the
 * baked pool it has to avoid. Same /24 as the floor's own external peers, which
 * is the point: the space is ordinary, only this host in it is not.
 */
function externalAdversaryPool(floorPools) {
  const taken = new Set(Array.isArray(floorPools.extips) ? floorPools.extips : []);
  const out = [];
  for (let n = 2; n <= 254 && out.length < 32; n += 1) {
    const addr = `${ADVERSARY_NET}.${n}`;
    if (!taken.has(addr)) out.push(addr);
  }
  return out;
}

// ---------------------------------------------------------------------------
// The floor
// ---------------------------------------------------------------------------

/**
 * The client's own estate doing ordinary work.
 *
 * Baked STEPS, compiled POOLS. See the header: the steps are the vocabulary
 * TACTIC_TEMPLATES mirrors — every (source.type, source.name) pair, every
 * closed metadata value, both address spaces — and rewriting them would break
 * that mirror with nothing to notice it. Pools are the half that has to become
 * the client's, and the half that needs no re-bake.
 */
function buildFloor(assets, opts) {
  const o = opts || {};
  const warn = o.warn || (() => {});
  const template = o.floorTemplate || bakedFloor();
  const bakedPools = template.pools || {};

  const floor = clone(template);
  const { buckets, byHostname, ordered } = bucketAssets(assets, {
    warn, priority: o.priority, bakedPools,
  });

  for (const name of HOST_POOLS) floor.pools[name] = buckets[name].slice();

  // ── Accounts ────────────────────────────────────────────────────────────
  const people = uniq((o.stakeholders || []).map(accountFor));
  if (!people.length) {
    warn(WARNING_CODES.NO_STAKEHOLDERS,
      'profile named no stakeholders; users falls back to the baked directory');
  }
  floor.pools.users = people.length
    ? uniq([...people, ...SERVICE_ACCOUNTS])
    : bakedPools.users.slice();

  // ── Addresses ───────────────────────────────────────────────────────────
  // lanips becomes the estate's; extips and dstips stay EXACTLY as baked. The
  // address-space contract is "whatever /8 an attack can come from, ordinary
  // traffic comes from too", and those two pools are what make 203/192/10 all
  // ordinary. Re-deriving them per client would be one client away from a floor
  // that no longer covers the adversary.
  floor.pools.lanips = laneAddressPool(assets, { warn, laneIps: o.laneIps, bakedPools });

  // ── Shares ──────────────────────────────────────────────────────────────
  // \\fileserv-01\finance in a lane whose hosts are all FILE01/DC01 is the same
  // tell as a generic source.host, one level down in the message text.
  const fileServer = ordered.find((a) => /(^|[^a-z])(file|fs|nas|share|smb)([^a-z]|$)/.test(assetText(a)))
    || ordered.find((a) => String(a.role || '').toLowerCase() === 'server');
  if (fileServer) {
    floor.pools.shares = ['finance', 'hr'].map((s) => `\\\\${fileServer.hostname}\\${s}`);
  }

  // ── Document paths belong in ORDINARY file access ────────────────────────
  // Not cosmetic, and not realism for its own sake. metadata.path is a closed
  // vocabulary once the compiled `users` pool is small (the baked floor hides
  // this behind 45 accounts x 2 per-user file templates, which puts it over the
  // contract's fifty-value exemption). The attack's collection and impact steps
  // report path = "{{docdirs}}/{{docs}}"; if ordinary traffic never touches a
  // shared document, that one metadata field separates attack from benign in a
  // single click. People read the finance share all day — so the floor does too.
  floor.pools.files = uniq([...(bakedPools.files || []), '{{docdirs}}/{{docs}}']);

  // Rhythm, bindings and skew are the baked ones and stay that way: they encode
  // how an estate BEHAVES (a working day, one account per desk, a long tail),
  // which is not a property of which client it belongs to.
  return { floor, buckets, byHostname, ordered };
}

// ---------------------------------------------------------------------------
// Host telemetry (E3b): what we must NOT narrate
// ---------------------------------------------------------------------------

/**
 * The source type Sysmon + winlogbeat already produce on a Windows machine.
 *
 * Only 'host'. When the GOAD ELK extension is in the lane, real host telemetry
 * exists for every domain machine, and a synthetic `source.type:'host'` line
 * about the same machine is the SAME EVENT narrated twice by two schemas that
 * disagree about everything. `_exists_: winlog.event_id` then separates real
 * from synthetic in one click — the exact oracle the two-playbook design exists
 * to remove, reintroduced by the fidelity upgrade that was meant to help.
 *
 * `authentication` deliberately stays. An sshd line from a Linux server is not
 * duplicated by anything winlogbeat ships, and dropping the type wholesale
 * would take the entire logon vocabulary out of the floor — including the
 * benign failures a spray has to hide inside.
 */
const CEDED_SOURCE_TYPES = new Set(['host']);

/**
 * Host sources that exist ONLY on Windows, and are therefore ceded outright.
 *
 * The rest of the ceded set — bash, auditd, systemd, sudo, sudoers, usermod,
 * dnf — are Linux tools, so pointing them at the Windows-free twin of their pool
 * is a strict improvement: the same activity, on the machines that actually run
 * it. These two are not. Redirecting `registry` to the estate's one Linux box
 * would put "SetValue HKCU\\..." on a machine with no registry, which is a
 * worse artefact than the duplication the cede exists to remove.
 */
const WINDOWS_ONLY_HOST_TOOLS = new Set(['cmd', 'registry']);

/** Pool name -> the pool of the same members with every Windows box removed. */
function nixPoolName(poolName) {
  return `nix${poolName}`;
}

/**
 * Add Windows-free twins of the host pools, and report which came out empty.
 *
 * A twin rather than a filter of the original: the original pools are still
 * needed by every non-ceded step (an `authentication/rdp` line names a Windows
 * workstation, and correctly). Only `source.host` on a ceded step is rewritten.
 */
function addNixPools(pools, buckets, byHostname) {
  const empty = new Set();
  for (const name of HOST_POOLS) {
    const members = (buckets[name] || []).filter((h) => {
      const asset = byHostname.get(String(h).trim().toLowerCase());
      return asset ? !isWindowsAsset(asset) : true;
    });
    if (members.length) pools[nixPoolName(name)] = members;
    else empty.add(name);
  }
  return empty;
}

// ---------------------------------------------------------------------------
// The attack
// ---------------------------------------------------------------------------

const TARGET_TOKEN = '{{target}}';
const POOL_TOKEN_RE = /^\{\{([a-zA-Z0-9_]+)\}\}$/;

/** Deep string rewrite over a template fragment. */
function rewrite(value, fn) {
  if (typeof value === 'string') return fn(value);
  if (Array.isArray(value)) return value.map((v) => rewrite(v, fn));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) out[k] = rewrite(v, fn);
    return out;
  }
  return value;
}

/** Weighted pick, deterministic in the seeded rng. */
function pickWeighted(rng, items) {
  let total = 0;
  for (const it of items) total += Number(it.weight) || 1;
  let r = rng() * total;
  for (const it of items) {
    r -= Number(it.weight) || 1;
    if (r <= 0) return it;
  }
  return items[items.length - 1];
}

/**
 * Can this variant be narrated honestly in this lane.
 *
 * Returns null when it can, or the reason when it cannot — the reason becomes
 * the warning, because "the Execution phase produced nothing" with no
 * explanation is indistinguishable from a bug.
 */
function cedeReason(variant, ctx) {
  if (!ctx.hostTelemetry) return null;
  if (!CEDED_SOURCE_TYPES.has(String(variant.source.type))) return null;

  if (WINDOWS_ONLY_HOST_TOOLS.has(String(variant.source.name))) {
    return `${variant.source.name} is Windows-only and Sysmon already reports it`;
  }
  const host = String(variant.source.host || '');
  if (host === TARGET_TOKEN) {
    return ctx.targetIsWindows
      ? `Sysmon already reports host activity on ${ctx.targetName}`
      : null;
  }
  const m = POOL_TOKEN_RE.exec(host);
  if (!m) return null;
  return ctx.emptyNixPools.has(m[1])
    ? `every machine in ${m[1]} is Windows and Sysmon already reports host activity on it`
    : null;
}

/** Point a ceded-but-usable step at the Windows-free twin of its pool. */
function nixHost(variant, ctx) {
  if (!ctx.hostTelemetry) return variant.source.host;
  if (!CEDED_SOURCE_TYPES.has(String(variant.source.type))) return variant.source.host;
  const m = POOL_TOKEN_RE.exec(String(variant.source.host || ''));
  return m ? `{{${nixPoolName(m[1])}}}` : variant.source.host;
}

/**
 * Which pool a step's victim should be sampled from when the scenario names a
 * host that does not exist.
 *
 * The variant's own `source.host` says what KIND of machine this phase happens
 * on, so a discovery step on `{{wspool}}` samples a workstation rather than the
 * first asset in the file. Falls through to `hosts`, which is every machine.
 */
function nearestBucketFor(hostToken, buckets, pools) {
  const m = POOL_TOKEN_RE.exec(String(hostToken || ''));
  if (m && Array.isArray(buckets[m[1]]) && buckets[m[1]].length) return buckets[m[1]];
  if (m && Array.isArray(pools[m[1]]) && pools[m[1]].length) return pools[m[1]];
  return buckets.hosts;
}

/**
 * One attack_path entry becomes one cc-emit step.
 *
 * `{{target}}` is rewritten to a per-phase entity `{{target_N}}`. cc-emit
 * resolves entities ONCE per run, which is what makes a run read as one
 * adversary — but a six-phase intrusion has six victims, not one, and collapsing
 * them into a single entity would make the whole campaign happen on one box.
 * Per-phase entities keep both properties: fixed within a phase, and the phases
 * differ.
 */
function buildStep(entry, index, ctx) {
  const tactic = TACTIC_TEMPLATES[entry.tactic];
  const usable = [];
  const ceded = [];
  for (const variant of tactic.variants) {
    const reason = cedeReason(variant, Object.assign({}, ctx, {
      targetIsWindows: entry.targetIsWindows,
      targetName: entry.targetName,
    }));
    if (reason) ceded.push(reason);
    else usable.push(variant);
  }
  // Every reason travels back, not just the fact of failure. "The phase
  // produced nothing" with no explanation is indistinguishable from a bug, and
  // this is the one path where the compiler deliberately emits less than the
  // profile asked for.
  if (!usable.length) return { step: null, ceded };

  const variant = pickWeighted(ctx.rng, usable);
  const defaults = Object.assign({}, tactic.defaults, variant.defaults || {});
  const token = `{{target_${index}}}`;
  const swap = (s) => s.split(TARGET_TOKEN).join(token);

  const step = {
    gap: defaults.gap,
    spread: defaults.spread,
    count: defaults.count,
    level: defaults.level,
    source: {
      type: variant.source.type,
      name: variant.source.name,
      host: swap(nixHost(variant, ctx)),
    },
    metadata: rewrite(variant.metadata || {}, swap),
    templates: (variant.templates || []).map((tpl) => {
      const out = { weight: tpl.weight, level: tpl.level, message: swap(tpl.message) };
      if (tpl.metadata) out.metadata = rewrite(tpl.metadata, swap);
      return out;
    }),
    technique: entry.technique,
    tactic: tactic.id,
  };
  return { step, entityKey: `target_${index}`, ceded };
}

/**
 * Order the profile's attack_path the way a campaign narrates.
 *
 * By kill-chain position, then by the profile's own step order. The generator
 * is TOLD to emit a realistic kill chain and usually does, so this is mostly a
 * no-op — but "mostly" is not a property a compiled timeline can rest on, and a
 * gigabyte leaving before the C2 channel exists tells the story backwards.
 */
function orderAttackPath(scenario, warn) {
  const raw = Array.isArray(scenario && scenario.attack_path) ? scenario.attack_path : [];
  const total = raw.length;

  const entries = [];
  raw.forEach((s, i) => {
    const resolved = tacticFor(s && s.technique, { position: i, total });
    if (!resolved.technique) {
      // No id, no mitre tag — and the sensor's drop_event processor keeps only
      // events that have one. A step like this would run, exit 0, report
      // lines>0 and put nothing in the index.
      warn(WARNING_CODES.UNPARSEABLE_TECHNIQUE,
        `attack_path step ${(s && s.step) || i + 1} has no usable MITRE id `
        + `(${JSON.stringify(s && s.technique)}); the step is dropped`);
      return;
    }
    if (!resolved.mapped) {
      warn(WARNING_CODES.UNMAPPED_TECHNIQUE,
        `${resolved.technique} is not in the tactic map; placed in `
        + `${resolved.tactic} by ${resolved.reason}`);
    }
    entries.push({
      order: i,
      step: Number((s && s.step) || i + 1),
      technique: resolved.technique,
      tactic: resolved.tactic,
      target: String((s && s.target) || '').trim(),
      action: String((s && s.action) || ''),
      detection_opportunity: String((s && s.detection_opportunity) || ''),
    });
  });

  return entries.sort((a, b) => (tacticIndex(a.tactic) - tacticIndex(b.tactic)) || (a.order - b.order));
}

// ---------------------------------------------------------------------------
// The leak guard
// ---------------------------------------------------------------------------

const norm = (s) => String(s).toLowerCase().replace(/\s+/g, ' ').trim();

/**
 * Neither playbook may contain the scenario's prose.
 *
 * `detection_opportunity` IS the finding the student is graded on discovering;
 * `action` is the narrative summary an instructor reads. A message built from
 * either turns the hunt into reading, and it would look completely fine in
 * review — the run works, the events land, the field names are right.
 *
 * Re-checked on the compiled JSON rather than trusted to the code above,
 * because the failure is silent and the check is a substring scan. Short
 * fragments are skipped: a four-word action can legitimately share a word with
 * a template ("net use"), and a guard that fires on that would be turned off.
 */
function assertNoScenarioProseLeaked(entries, playbooks) {
  const hay = norm(JSON.stringify(playbooks));
  for (const e of entries) {
    for (const field of ['action', 'detection_opportunity']) {
      const value = norm(e[field]);
      if (value.length < 16) continue;
      if (hay.includes(value)) {
        throw new Error(
          `scenario-compiler: step ${e.step}'s ${field} reached a playbook. `
          + 'detection_opportunity is the answer key; it must never be on the wire.'
        );
      }
    }
  }
}

// ---------------------------------------------------------------------------
// compileScenario
// ---------------------------------------------------------------------------

/**
 * Compile one client threat scenario into a runnable exercise.
 *
 * @param {object}   input
 * @param {object}   input.scenario   one threat_profile.scenarios[] entry
 * @param {Array}    input.assets     network.assets[] — {hostname, ip, role, os, ...}
 * @param {object}   input.options
 * @param {string}   input.options.runId            THE SEED. Required, never defaulted.
 * @param {number}  [input.options.requestedSeconds] the instructor's duration
 * @param {Array}   [input.options.laneIps]          the lane's real .80–.99 band
 * @param {Array}   [input.options.stakeholders]     profile stakeholders
 * @param {boolean} [input.options.hostTelemetry]    E3b: Sysmon is in this lane
 * @param {object}  [input.options.floorTemplate]    override the baked floor
 * @returns {{attack: object, floor: object, answerKey: object,
 *            warnings: Array<{code: string, detail: string}>}}
 */
function compileScenario(input) {
  const o = (input && input.options) || {};
  const scenario = (input && input.scenario) || {};
  const assets = Array.isArray(input && input.assets) ? input.assets : [];

  const runId = String(o.runId || '');
  if (!runId) {
    // The same refusal answer-key.js makes, for the same reason: the run id IS
    // the seed. A playbook compiled from '' describes an intrusion no lane runs,
    // and every symptom of that shows up in a student's grade rather than a log.
    throw new Error('compileScenario: options.runId is the seed and is required');
  }

  const seen = new Set();
  const warnings = [];
  const warn = (code, detail) => {
    const k = `${code}\u0000${detail}`;
    if (seen.has(k)) return;
    seen.add(k);
    warnings.push({ code, detail });
  };

  // ── The floor ───────────────────────────────────────────────────────────
  const entries = orderAttackPath(scenario, warn);
  if (!entries.length) {
    throw new Error(
      `compileScenario: scenario ${JSON.stringify(scenario.scenario_id || scenario.name || '?')} `
      + 'has no attack_path step with a usable MITRE technique, so there is nothing to run'
    );
  }

  const priority = new Set();
  for (const e of entries) if (e.target) priority.add(e.target.toLowerCase());
  for (const h of (Array.isArray(scenario.impacted_assets) ? scenario.impacted_assets : [])) {
    if (h) priority.add(String(h).trim().toLowerCase());
  }

  const { floor, buckets, byHostname } = buildFloor(assets, {
    warn,
    priority,
    laneIps: o.laneIps,
    stakeholders: o.stakeholders,
    floorTemplate: o.floorTemplate,
  });

  // ── Ceding host telemetry to Sysmon ─────────────────────────────────────
  const hostTelemetry = !!o.hostTelemetry;
  let emptyNixPools = new Set();
  if (hostTelemetry) {
    emptyNixPools = addNixPools(floor.pools, buckets, byHostname);
    const kept = [];
    for (const step of floor.steps) {
      const src = step.source || {};
      if (!CEDED_SOURCE_TYPES.has(String(src.type))) { kept.push(step); continue; }
      if (WINDOWS_ONLY_HOST_TOOLS.has(String(src.name))) {
        warn(WARNING_CODES.HOST_TELEMETRY_CEDED,
          `floor step ${src.type}/${src.name} dropped: it is Windows-only and Sysmon `
          + 'already reports it');
        continue;
      }
      const m = POOL_TOKEN_RE.exec(String(src.host || ''));
      if (m && emptyNixPools.has(m[1])) {
        warn(WARNING_CODES.HOST_TELEMETRY_CEDED,
          `floor step ${src.type}/${src.name} on ${m[1]} dropped: every machine in that `
          + 'pool is Windows and Sysmon already reports its host activity');
        continue;
      }
      kept.push(m ? Object.assign({}, step, {
        source: Object.assign({}, src, { host: `{{${nixPoolName(m[1])}}}` }),
      }) : step);
    }
    floor.steps = kept;
  }

  // ── Entities: one adversary, one account, one victim per phase ──────────
  const rng = emit.makeRng(emit.seedFrom(`${runId}|${scenario.scenario_id || scenario.name || 'scenario'}`));
  const externals = externalAdversaryPool(floor.pools);
  const people = (o.stakeholders || []).map(accountFor).filter(Boolean);
  const actorPool = people.length ? uniq(people) : floor.pools.users.slice();

  const entities = {
    // The intruder's own address, in the space ordinary internet traffic uses.
    source_ip: { oneOf: externals },
    // Filled below from the first victim that has an address: lateral movement
    // that originates outside the estate is not lateral movement.
    pivot_ip: { oneOf: floor.pools.lanips.slice() },
    // An account the directory really issued. An adversary who shows up as an
    // account nobody has ever seen is a lesson that fails on every intrusion
    // that matters.
    actor: { oneOf: actorPool },
  };

  // ── The steps ───────────────────────────────────────────────────────────
  const ctx = { rng, hostTelemetry, emptyNixPools };
  const steps = [];
  let pivotAsset = null;

  entries.forEach((entry, index) => {
    const asset = entry.target ? byHostname.get(entry.target.toLowerCase()) : null;
    let targetName;
    if (asset) {
      targetName = asset.hostname;
    } else {
      if (entry.target) {
        warn(WARNING_CODES.UNKNOWN_TARGET,
          `attack_path step ${entry.step} names ${JSON.stringify(entry.target)}, which is not `
          + 'one of this profile\'s assets; sampled from the nearest bucket instead');
      }
      // Sampled, not picked: nearestBucketFor is keyed on the variant, so the
      // draw has to happen after the variant is known. A provisional draw from
      // `hosts` keeps the rng sequence stable when the variant does not narrow it.
      targetName = null;
    }

    const built = buildStep(Object.assign({}, entry, {
      targetName: targetName || '(sampled)',
      // An UNRESOLVABLE target cannot be certified non-Windows, and under
      // hostTelemetry "we do not know what this machine is" has to mean "assume
      // Sysmon is already reporting it". Guessing the other way puts a
      // synthetic host line on a machine winlogbeat is also narrating, which is
      // the exact duplication the cede exists to prevent.
      targetIsWindows: asset ? isWindowsAsset(asset) : hostTelemetry,
    }), index, ctx);

    if (!built.step) {
      warn(WARNING_CODES.TACTIC_UNREPRESENTABLE,
        `${entry.technique} (${entry.tactic}) has no source this lane can narrate honestly `
        + `(${built.ceded.join('; ')}); the phase is left to the host agent`);
      return;
    }

    if (!targetName) {
      // Sampled only now, because the bucket to sample from is the one the
      // CHOSEN variant's own source.host names: a discovery step on {{wspool}}
      // should land on a workstation, not on whatever came first in the file.
      const bucket = nearestBucketFor(built.step.source.host, buckets, floor.pools);
      targetName = bucket[Math.floor(rng() * bucket.length)];
    }

    entities[built.entityKey] = targetName;
    steps.push(built.step);

    const resolved = byHostname.get(String(targetName).toLowerCase());
    if (!pivotAsset && resolved && resolved.ip) pivotAsset = resolved;
  });

  if (!steps.length) {
    throw new Error(
      'compileScenario: every phase of this scenario was ceded to the host agent, so the '
      + 'compiled attack would generate nothing. A run that reports completed having emitted '
      + 'nothing is the worst outcome available.'
    );
  }

  // The foothold is a real machine in the estate, not an abstract address.
  if (pivotAsset) entities.pivot_ip = String(pivotAsset.ip);

  // ── The attack playbook ─────────────────────────────────────────────────
  const attack = {
    // Opaque on purpose. The playbook is staged inside the guest; the
    // scenario's own title ("Ransomware via phished finance credentials") would
    // put the answer on the sensor's disk.
    name: `scenario ${scenario.scenario_id || 'compiled'}`,
    tactic: steps[steps.length - 1].tactic,
    nominal_seconds: 0,
    entities,
    // The SAME pools as the floor, by construction. This is what makes the
    // vocabulary contract hold by design rather than by review: every host,
    // account and address the attack can draw is one ordinary traffic also
    // draws. answer-key.js reads it the same way — a pool the floor declares
    // can never yield an attack-only indicator.
    pools: clone(floor.pools),
    bindings: clone(floor.bindings || {}),
    skewed: (floor.skewed || []).slice(),
    steps,
  };
  attack.nominal_seconds = Math.max(
    Math.ceil(emit.layout(attack.steps, 1).end),
    emit.minSecondsFor(attack)
  );

  const requested = Number(o.requestedSeconds);
  if (Number.isFinite(requested) && requested > 0) {
    const floorSeconds = emit.minSecondsFor(attack);
    if (requested < floorSeconds) {
      // cc-emit's own refusal, raised here so an instructor gets it from the
      // launcher instead of from a guest that exited 4 on thirty lanes.
      throw new Error(
        `compileScenario: this scenario needs at least ${floorSeconds}s of burst time `
        + `but was asked for ${Math.round(requested)}s. Compressing a burst into less than it `
        + 'takes does not make a shorter intrusion, it makes a different one.'
      );
    }
  }

  assertNoScenarioProseLeaked(entries, { attack, floor });

  // ── The key ─────────────────────────────────────────────────────────────
  // Compiled by re-running the emitter's own planner against the SAME seed the
  // guest will use, which is why totals.events is the count an instructor can
  // quote. The scenario half is the part only this compiler knows: the actions
  // and the detection opportunities, which exist nowhere on the wire.
  const answerKey = compileAnswerKey({
    runId,
    playbook: attack,
    floor,
    requestedSeconds: Number.isFinite(requested) && requested > 0 ? requested : null,
  });
  answerKey.scenario = {
    scenario_id: scenario.scenario_id || null,
    name: scenario.name || null,
    type: scenario.type || null,
    threat_actor: scenario.threat_actor || null,
    initial_vector: scenario.initial_vector || null,
    steps: entries.map((e, i) => ({
      step: e.step,
      technique: e.technique,
      tactic: e.tactic,
      target: entities[`target_${i}`] || e.target || null,
      action: e.action || null,
      detection_opportunity: e.detection_opportunity || null,
    })),
  };

  return { attack, floor, answerKey, warnings };
}

module.exports = {
  compileScenario,
  // Exported so the tests can hold the buckets, the cede rule and the account
  // derivation to their contracts directly, rather than inferring them from a
  // whole compiled playbook.
  bucketAssets,
  buildFloor,
  isWindowsAsset,
  accountFor,
  externalAdversaryPool,
  HOST_POOLS,
  SERVICE_ACCOUNTS,
  CEDED_SOURCE_TYPES,
  WARNING_CODES,
  WINDOWS_ONLY_HOST_TOOLS,
  ADVERSARY_NET,
};
