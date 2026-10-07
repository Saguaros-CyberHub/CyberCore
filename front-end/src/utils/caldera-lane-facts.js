'use strict';

/**
 * caldera-lane-facts.js — the DISPATCH-side fact seeder for a classroom operation.
 * ============================================================================
 * WHY THIS IS NOT src/incident/caldera/fact-source.js
 * ----------------------------------------------------------------------------
 * That module is the AUTHORING-side builder and says so in its own header:
 * "THIS FILE IS ABOUT AUTHORING, NEVER ABOUT DISPATCH." It derives ONE source
 * per SCOPE, ids it `uuidv5(scopeKey, FACT_SOURCE_NAMESPACE)`, and its toWire()
 * is a whitelist tuned to that contract. A classroom operation needs the
 * opposite shape: one source per LANE per BATCH, ided
 * `uuidv5('source:<lane>', batch)` by caldera-lane-operations.js, and built from
 * the lane's own addressing rather than a section-level scope key. Bending the
 * authoring builder to serve both would put dispatch behind a file that
 * promises, in writing, that it never dispatches.
 *
 * WHAT IT SEEDS — AND WHAT IT DELIBERATELY DOES NOT
 * ----------------------------------------------------------------------------
 * Host identity only. NO SECRET OF ANY KIND. The no-secrets rule that
 * fact-source.js states at its L73-77 applies here for the SAME reason and not
 * a weaker one: per-lane scoping buys isolation BETWEEN LANES, it buys no
 * confidentiality at all. Caldera has no per-object ownership, so
 * `GET /api/v2/sources` returns every source on the server to every account
 * holding an API key, and src/incident/caldera/snapshot.js copies every fact
 * verbatim into the CyberCore database as a second stored copy. A credential
 * seeded here would be legible in both places.
 *
 * THE TRAIT SET IS CHOSEN BY WHAT ABILITIES ACTUALLY CONSUME
 * ----------------------------------------------------------------------------
 *   remote.host.name  Start Agent (WinRM) and Copy Sandcat (WinRM / SCP)
 *   remote.host.ip    Net use
 *   remote.host.fqdn  the SMB / WMI lateral abilities
 *
 * `domain.name` is NOT emitted, and that is a correction rather than an
 * omission: it is a PARSER OUTPUT (alongside domain.ad.name and
 * network.domain.name), and no stockpile ability takes it as an input. The
 * authoring module emits it today and nothing consumes it. The domain travels
 * inside the values here instead — in the FQDN.
 *
 * NO RELATIONSHIPS ARE SEEDED, AND THIS ONE IS A LANDMINE
 * ----------------------------------------------------------------------------
 * The SMB and WMI lateral abilities do not gate on facts at all; they gate on
 * `requirements.basic` / `req_like` / `reachable`, which test RELATIONSHIPS in
 * operation.all_relationships(). The obvious fix — seeding a
 * `remote.host.fqdn -isAccessibleFrom-> remote.host.fqdn` relationship — is
 * WORSE THAN USELESS on Caldera 5.3.0: stockpile's reachable.py does
 * `links[0].host` on a list filtered from operation.chain, which is EMPTY for a
 * source-seeded relationship, and base_planning_svc._do_enforcements wraps it in
 * no try/except. That is an unhandled IndexError inside link generation, not a
 * skipped ability.
 *
 * `isAccessibleFrom` must therefore be LEARNED, by ordering Remote Host Ping
 * (921055f4) ahead of the lateral steps in the adversary's atomic_ordering.
 * Seeding hosts is what gives that ping somewhere to go.
 *
 * A WRONG VALUE IS SILENT
 * ----------------------------------------------------------------------------
 * Caldera's `skipped_abilities` report compares trait NAMES only, so a fact with
 * the right trait and a wrong hostname reports as "fact dependency fulfilled"
 * while producing links that fail at execution. Verification has to be at link
 * level; "the operation completed" proves nothing about the values.
 */

const { loadBaseMetadata, canonicalGoadLabName } = require('./goad-lab-rebrand');
const { INFRASTRUCTURE_ROLES } = require('../incident/caldera/fact-source');

/** Every fact Caldera stores carries a score; 1 is the ordinary default. */
const DEFAULT_SCORE = 1;

/**
 * Seeded hosts are capped. Facts combine COMBINATORIALLY with every other fact
 * an ability requires (itertools.product in base_planning_svc), so an unbounded
 * roster multiplied by any future credential set is how one ability becomes
 * hundreds of links.
 */
const MAX_HOSTS = 12;

/** The traits, and only these. See the header for why each earns its place. */
const TRAITS = Object.freeze({
  hostName: 'remote.host.name',
  hostIp: 'remote.host.ip',
  hostFqdn: 'remote.host.fqdn',
  user: 'domain.user.name',
});

/** Stable codes. Surfaced to the instructor, so they are pinned by test. */
const WARNINGS = Object.freeze({
  NO_LAB: 'LANE_FACTS_NO_LAB',
  NO_BASE: 'LANE_FACTS_NO_BASE',
  NO_SUBNET: 'LANE_FACTS_NO_SUBNET',
  NO_HOSTS: 'LANE_FACTS_NO_HOSTS',
  NO_USERS: 'LANE_FACTS_NO_USERS',
  EXCLUDED: 'LANE_FACTS_EXCLUDED',
  CAPPED: 'LANE_FACTS_CAPPED',
  STOCK_HOSTNAME_MISSING: 'LANE_FACTS_STOCK_HOSTNAME_MISSING',
});

const str = (value) => (value === null || value === undefined ? '' : String(value).trim());

/**
 * `10.39.17` + 22 -> `10.39.17.22`.
 *
 * Deliberately NOT imported from goad-deploy.buildIp: requiring that module
 * opens a database pool at load, which is exactly why lane-environment.js
 * requires it lazily. This is the same two-line join with the same contract, and
 * it validates rather than trusting its input because the result is handed to a
 * C2 as a target address.
 */
function buildIp(base3, octet) {
  const base = str(base3);
  const n = Number(octet);
  if (!/^\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(base)) return null;
  if (!Number.isInteger(n) || n < 1 || n > 254) return null;
  return `${base}.${n}`;
}

/**
 * The lane's GOAD subnet.
 *
 * On v3 the AD estate lives on the INTERNAL segment, so `lane_subnet_base` —
 * which is the external one — would seed every host at an address nothing in the
 * lab answers on.
 */
function goadSubnetOf(config) {
  const cfg = config && typeof config === 'object' ? config : {};
  return str(cfg.subnet_scheme) === 'v3'
    ? str(cfg.lane_subnet_internal) || null
    : str(cfg.lane_subnet_base) || null;
}

/**
 * Observed hostnames for a RENAMED forest.
 *
 * config.goad.identities is only written when spec.goad.rename_forest is true,
 * so stock and prebaked lanes have none and fall through to the sidecar.
 * Shape-tolerant on purpose: this reads a record written by a different
 * subsystem, and a shape it does not recognise must degrade to "use the stock
 * name", never throw inside a launch.
 */
function hostnameOverridesOf(config) {
  const goad = config && typeof config === 'object' ? config.goad : null;
  const out = {};
  const checks = goad && Array.isArray(goad.identities && goad.identities.checks) ? goad.identities.checks : [];
  for (const check of checks) {
    const roster = str(check && (check.roster_name || check.name));
    const observed = check && check.observed ? str(check.observed.hostname) : '';
    if (roster && observed) out[roster] = observed;
  }
  return out;
}

/**
 * Roster name -> real hostname and domain, from the vendored sidecar.
 *
 * The roster name is NOT the hostname on any stock lane: CyberCore's GOAD-Light
 * roster says DC01/DC02/SRV02 while the guests boot as
 * TUC-DC01/TUC-DC02/TUC-SRV02, and upstream GOAD boots
 * kingslanding/winterfell/castelblack. Seeding the roster name would hand every
 * ability a target that resolves to nothing.
 */
function stockHostIndex(base) {
  const index = new Map();
  const hosts = base && base.stock && base.stock.hosts;
  if (!hosts || typeof hosts !== 'object') return index;
  for (const entry of Object.values(hosts)) {
    const roster = str(entry && entry.roster_name).toLowerCase();
    if (roster) index.set(roster, { hostname: str(entry.hostname), domain: str(entry.domain) });
  }
  return index;
}

const empty = (...codes) => ({ facts: [], hosts: [], excluded: [], warnings: codes });

/**
 * Build the fact list for ONE lane.
 *
 * Pure: no clock, no randomness, no I/O beyond the vendored sidecar read, so the
 * same lane produces a byte-identical source on every launch and a diff between
 * two lanes is a real difference in their addressing.
 *
 * Degrades to zero facts and a warning rather than throwing. A lane whose lab
 * cannot be resolved must still launch exactly as it does today; seeding is a
 * realism upgrade, never a new way for a classroom launch to fail.
 */
function buildLaneFacts(opts) {
  const o = opts || {};
  const warnings = [];
  const warn = (code) => { if (!warnings.includes(code)) warnings.push(code); };

  const lab = canonicalGoadLabName(str(o.lab));
  if (!lab) return empty(WARNINGS.NO_LAB);

  const loaded = loadBaseMetadata(lab);
  if (!loaded || !loaded.base) return empty(WARNINGS.NO_BASE);

  const subnet = str(o.subnetBase) || null;
  if (!subnet) warn(WARNINGS.NO_SUBNET);

  // Overridable so the cap itself is testable: no vendored lab is large enough
  // to reach MAX_HOSTS, and an untested guard is a guard that quietly stops
  // guarding the first time someone vendors a bigger lab.
  const cap = Number.isInteger(o.maxHosts) && o.maxHosts >= 0 ? o.maxHosts : MAX_HOSTS;
  const overrides = o.hostnameOverrides && typeof o.hostnameOverrides === 'object' ? o.hostnameOverrides : {};
  const stock = stockHostIndex(loaded.base);
  const roster = Array.isArray(loaded.base.lab_definition && loaded.base.lab_definition.vms)
    ? loaded.base.lab_definition.vms
    : [];

  const hosts = [];
  const excluded = [];
  for (const vm of roster) {
    const name = str(vm && vm.name);
    if (!name) continue;
    // The evidence plane, the student's own box and lane plumbing are never
    // targets. Reported, never dropped quietly.
    if (INFRASTRUCTURE_ROLES.has(str(vm.role).toLowerCase())) { excluded.push(name); continue; }
    if (hosts.length >= cap) { warn(WARNINGS.CAPPED); break; }

    const known = stock.get(name.toLowerCase()) || null;
    const hostname = str(overrides[name] || overrides[name.toLowerCase()]) || (known && known.hostname) || '';
    if (!hostname) { warn(WARNINGS.STOCK_HOSTNAME_MISSING); continue; }
    const domain = (known && known.domain) || '';
    hosts.push({
      roster_name: name,
      hostname,
      fqdn: domain ? `${hostname}.${domain}` : '',
      ip: buildIp(subnet, vm.ipOctet),
    });
  }

  if (excluded.length) warn(WARNINGS.EXCLUDED);
  if (!hosts.length) warn(WARNINGS.NO_HOSTS);

  // No account roster is derivable server-side for a stock GOAD lane: the users
  // exist only in ad/<LAB>/data/config.json inside the GOAD fork on the lane
  // controller, and GOAD-main/ is gitignored with zero tracked files. Saying so
  // is better than a fabricated name that binds an ability to nothing.
  const users = Array.isArray(o.users) ? o.users.map(str).filter(Boolean) : [];
  if (!users.length) warn(WARNINGS.NO_USERS);

  const facts = [];
  const push = (trait, value) => { const v = str(value); if (v) facts.push({ trait, value: v, score: DEFAULT_SCORE }); };
  for (const host of hosts) {
    push(TRAITS.hostName, host.hostname);
    push(TRAITS.hostFqdn, host.fqdn);
    push(TRAITS.hostIp, host.ip);
  }
  for (const user of users) push(TRAITS.user, user);

  // Sorted, so the same lane syncs a byte-identical source every time.
  facts.sort((a, b) => a.trait.localeCompare(b.trait) || a.value.localeCompare(b.value));
  return { facts, hosts, excluded, warnings };
}

/**
 * Assemble buildLaneFacts' arguments from a lane row and the environment
 * directory's description of it.
 *
 * `described` is what createEnvironmentDirectory().describeEnvironments()
 * returns for this lane's challenge key: {label, goad, lab, labLabel, machines}.
 * A lane that is not a GOAD lane seeds nothing — there is no AD estate to name.
 */
function laneFactsFor(lane, config, described) {
  if (!described || !described.goad) return empty(WARNINGS.NO_LAB);
  return buildLaneFacts({
    lab: described.lab,
    subnetBase: goadSubnetOf(config),
    hostnameOverrides: hostnameOverridesOf(config),
  });
}

module.exports = {
  buildLaneFacts,
  laneFactsFor,
  goadSubnetOf,
  hostnameOverridesOf,
  TRAITS,
  WARNINGS,
  MAX_HOSTS,
  DEFAULT_SCORE,
};
