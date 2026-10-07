/**
 * ============================================================================
 * CALDERA AUTHORING — "prepare my class, then let me go and author for it"
 * ============================================================================
 *
 * ############################################################################
 * # THIS FILE HAS NEVER TALKED TO A REAL CALDERA SERVER.                     #
 * #                                                                          #
 * # There is no Caldera anywhere in this repository and none on any cluster. #
 * # Every endpoint it reaches is reached through caldera/client.js, whose    #
 * # own banner says the same thing. What IS verified is everything on this   #
 * # side of the transport seam — the ORDER the steps happen in, what is      #
 * # refused, and what a caller is handed when the instance is not there —    #
 * # all driven from test/caldera-authoring-ui.test.js over a fake client.    #
 * ############################################################################
 *
 * WHAT THIS IS FOR
 * ----------------------------------------------------------------------------
 * There is ONE standalone Caldera "authoring" instance, on a VM outside every
 * lane, with no agents and no implants and no agent contact configured. An
 * instructor opens its real web UI to BUILD adversaries; CyberCore reads them
 * back out and (from E9-ship onwards, not now) replicates one into each lane's
 * own lane-local Caldera at launch.
 *
 * Two consoles drive that from the CyberCore side — the CiAB Incidents tab and
 * the CLE blue-team panel — and both need the SAME four things:
 *
 *   1. the class's DEPLOYED spec, so the fact source describes real machines;
 *   2. a fact-source sync, which must happen BEFORE the instructor is handed a
 *      link (see THE ORDERING RULE below);
 *   3. the platform summary that sync produced, so "3 Windows, 1 Linux" can be
 *      said out loud before the instructor is looking at Caldera's own UI,
 *      where CyberCore can no longer help them; and
 *   4. the list of adversaries the instance holds.
 *
 * All four live here, ONCE. What does NOT live here is a single sentence of
 * copy: CiAB says Section / Client / Engagement / Environment / Incident and
 * CLE says course, the two vocabularies are not allowed to meet, and a shared
 * string is exactly how they would. This module answers in CODES and COUNTS;
 * each console writes its own sentences.
 *
 * THE ORDERING RULE, AND WHY IT IS THE WHOLE POINT
 * ----------------------------------------------------------------------------
 * A link to the authoring console offered BEFORE the fact source is synced is a
 * class authoring against the PREVIOUS environment's hosts. Nothing about that
 * fails visibly: the instructor builds a careful adversary against FILE02, the
 * source still says what it said last term, and the operation creates links for
 * machines this lane does not have. So prepareAuthoring() resolves only after
 * syncFactSource() has resolved, and a caller that could not complete the sync
 * gets `ready:false` and no link at all. `ready` is ONE field precisely so that
 * no caller can render half of it.
 *
 * NOTHING HERE DISPATCHES, AND NOTHING IN A LANE TALKS TO THIS SERVER
 * ----------------------------------------------------------------------------
 * The client this builds is pointed at the AUTHORING instance. It calls
 * listSources / getSource / createSource / updateSource / listAdversaries and
 * nothing else — no operation is created, no agent is contacted, and
 * src/incident/engines/index.js still refuses 'caldera' so no run row can even
 * name it as an engine. EXECUTION stays unreachable until the E8 cluster gate
 * passes; AUTHORING is safe to ship now precisely because it touches nothing
 * inside any lane.
 *
 * Dispatch into a lane goes over guest-exec (agentShellExec via the Proxmox
 * API) the way every other lane operation in this codebase does. There is no IP
 * route from the orchestrator into a lane and this adds none.
 *
 * WHERE THE CREDENTIAL COMES FROM
 * ----------------------------------------------------------------------------
 * src/routes/caldera-authoring.js holds NO Caldera credential and must not: it
 * is the browser-facing gate, and its own header says that if a phase ever
 * needs the app to hold a key "to READ an adversary back out over the API",
 * that key arrives as a root-owned 0600 FILE. This is that phase, and this is
 * where the key is read.
 *
 *   CALDERA_AUTHORING_API_KEY_FILE   preferred — a mounted secret, read per call
 *   CALDERA_AUTHORING_API_KEY        accepted, for a deployment with no secret
 *                                    store
 *
 * NEVER a script_arg. src/utils/script-executor.js interpolates args UNQUOTED
 * into a shell command line and password-generator.js guarantees a character
 * from !@#$%&*, where '&' backgrounds the command — the same reason
 * bake-caldera-server.sh delivers every secret it has as a file.
 *
 * The key is read AT CALL TIME and never captured at module load, so an
 * operator who rotates the mounted file gets the new value on the next click
 * rather than on the next restart — and a test drives the whole module by
 * flipping process.env with no require-cache games.
 *
 * WHY THE BASE URL IS AN ARGUMENT AND THE KEY IS NOT
 * ----------------------------------------------------------------------------
 * Deliberately asymmetric. The URL is already resolved, once, by
 * src/routes/caldera-authoring.js authoringConfig() — the same value Caddy
 * substitutes into its reverse_proxy — and a second resolver here would be a
 * second answer to "where is the authoring box", which is the class of drift
 * this codebase keeps whole test files about. So callers pass it in. The KEY
 * has no existing owner (that file deliberately holds none), so it is resolved
 * here, and nowhere else.
 *
 * PURITY
 * ----------------------------------------------------------------------------
 * Same doctrine as client.js, adversary.js and fact-source.js: everything below
 * is a pure function of its arguments except the two that are honest about it —
 * loadScopeSpec() reads the database, and the prepare/list pair reach the server
 * through a client they are HANDED. No module-scope database handle, no
 * module-scope clock, no fetch().
 *
 * Run: node --test front-end/test/caldera-authoring-ui.test.js
 * ============================================================================
 */

'use strict';

const fs = require('fs');

const { createCalderaClient, isTransportFailure } = require('./client');
const { buildFactSource, syncFactSource, FactSourceError } = require('./fact-source');

/**
 * Why a console cannot offer the link. ONE closed vocabulary, because both
 * consoles branch on it and a divergent spelling in either renders a blank card
 * rather than an error.
 *
 * Deliberately NOT sentences — see the header. What crosses this boundary is a
 * code the caller writes its own sentence for, in its own product's words.
 */
const UNAVAILABLE = Object.freeze({
  NOT_CONFIGURED: 'not_configured',   // no upstream configured anywhere
  NO_API_KEY: 'no_api_key',           // configured, but nothing to authenticate with
  UNREACHABLE: 'unreachable',         // nothing answered, or answered too late
  UNAUTHORIZED: 'unauthorized',       // it answered 401/403 — the key is wrong
  NO_SPEC: 'no_spec',                 // nothing is deployed to author against
  SYNC_FAILED: 'sync_failed',         // it answered, and refused the source
  ERROR: 'error',                     // anything else, reported rather than thrown
});

/**
 * The one reason a picked adversary cannot be launched yet.
 *
 * Exported so both consoles and the source-text gate read the SAME token.
 * EXECUTION IS SHUT: src/incident/engines/index.js does not register the caldera
 * adapter and engineFor() throws for it, so there is no code path from a picked
 * adversary to a dispatch. This constant is what a console renders in place of a
 * launch control, and it is a constant rather than a string so that "is it still
 * gated?" is one grep and not a reading exercise.
 */
const EXECUTION_GATE = Object.freeze({ enabled: false, reason: 'cluster_gate' });

/** How long one authoring call may take. Short: an instructor is waiting on it. */
const DEFAULT_TIMEOUT_MS = 8000;

const str = (v) => String(v == null ? '' : v).trim();

// ---------------------------------------------------------------------------
// The credential
// ---------------------------------------------------------------------------

/**
 * The authoring instance's API key, file first.
 *
 * NEVER LOGGED AND NEVER RETURNED TO A BROWSER. The shape below carries
 * `present` and `source` — enough for an operator to see which mechanism
 * answered — and the key itself only leaves through the client's KEY header,
 * which client.js redact()s out of every error string it builds.
 *
 * A read failure is REPORTED, not thrown: "the secret file is not mounted" is
 * exactly the condition a status surface exists to describe calmly, and throwing
 * would turn it into a 500 on the one screen that could have explained it.
 *
 * @param {object}   [env]       defaults to process.env
 * @param {Function} [readFile]  injected by the test; defaults to fs
 * @returns {{apiKey:string|null, present:boolean, source:'file'|'env'|null, detail:string|null}}
 */
function resolveApiKey(env, readFile) {
  const e = env || process.env;
  const read = typeof readFile === 'function' ? readFile : (p) => fs.readFileSync(p, 'utf8');

  const file = str(e.CALDERA_AUTHORING_API_KEY_FILE);
  if (file) {
    try {
      // trim(), because a file written with `echo` ends in a newline, and a key
      // carrying a trailing newline fails authentication with a 401 that looks
      // exactly like a wrong key.
      const key = str(read(file));
      if (key) return { apiKey: key, present: true, source: 'file', detail: null };
      return { apiKey: null, present: false, source: 'file', detail: 'empty_file' };
    } catch (err) {
      // A CODE, not the errno text. This is rendered to staff, and
      // "ENOENT: open '/run/secrets/...'" is no more actionable than the path
      // they already configured.
      return { apiKey: null, present: false, source: 'file', detail: 'unreadable_file' };
    }
  }

  const inline = str(e.CALDERA_AUTHORING_API_KEY);
  if (inline) return { apiKey: inline, present: true, source: 'env', detail: null };
  return { apiKey: null, present: false, source: null, detail: 'not_set' };
}

/**
 * A client bound to the AUTHORING instance.
 *
 * Returns null when there is nothing to bind — an unconfigured upstream or an
 * absent key — rather than throwing, because both are configuration states a
 * console must RENDER, not failures it should blow up on.
 *
 * @param {object}   opts
 * @param {string}   opts.baseUrl     from routes/caldera-authoring authoringConfig()
 * @param {string}   opts.apiKey      from resolveApiKey()
 * @param {Function} [opts.transport] injected by the test; see client.js
 */
function authoringClient(opts) {
  const o = opts || {};
  if (!str(o.baseUrl) || !str(o.apiKey)) return null;
  return createCalderaClient({
    baseUrl: o.baseUrl,
    apiKey: o.apiKey,
    transport: o.transport,
    timeoutMs: Number(o.timeoutMs) > 0 ? Number(o.timeoutMs) : DEFAULT_TIMEOUT_MS,
  });
}

/**
 * The authoring instance, or the reason there isn't one — in ONE shape, for both
 * consoles.
 *
 * The upstream ADDRESS is resolved by src/routes/caldera-authoring.js and passed
 * in; the KEY is resolved here (see the header for why that asymmetry is
 * deliberate). A null client with a reason is the NORMAL state on a deployment
 * that has not stood the instance up yet, which is what lets a console say
 * "attack authoring is not set up" and list what an admin has to do, instead of
 * rendering a link to nowhere.
 *
 * This lives in core rather than in each plugin route because it is the same six
 * lines in both, and six lines that decide whether a credential is present are
 * six lines that must not drift: a copy that forgot the NO_API_KEY rung would
 * build a client with an empty key, and createCalderaClient() throws on that —
 * turning a configuration state into a 500.
 *
 * @param {object} cfg   routes/caldera-authoring authoringConfig()'s result
 * @param {object} [opts]  {env, readFile, transport} — all injected by the test
 */
function resolveTarget(cfg, opts) {
  const c = cfg || {};
  const o = opts || {};
  if (!c.configured) {
    return {
      client: null,
      // A value that is set but unparseable is a different problem from one
      // nobody set, and an operator hunting a network fault for a typo is the
      // failure this distinction prevents.
      unavailable: c.malformed ? UNAVAILABLE.ERROR : UNAVAILABLE.NOT_CONFIGURED,
      upstream: null,
    };
  }
  const key = resolveApiKey(o.env, o.readFile);
  if (!key.present) {
    return { client: null, unavailable: UNAVAILABLE.NO_API_KEY, upstream: c.upstream || null };
  }
  return {
    client: authoringClient({ baseUrl: c.baseUrl, apiKey: key.apiKey, transport: o.transport }),
    unavailable: null,
    upstream: c.upstream || null,
  };
}

/**
 * Whatever went wrong, as one of UNAVAILABLE's codes.
 *
 * A named code, NEVER the error's own message. client.js redacts the key out of
 * its message text, but the message still carries the upstream host, the failing
 * syscall and up to 300 characters of the server's body — none of which a
 * browser needs and all of which a console would render verbatim.
 */
function classifyFailure(err) {
  if (!err) return UNAVAILABLE.ERROR;
  if (isTransportFailure(err)) return UNAVAILABLE.UNREACHABLE;
  if (err.code === 'CALDERA_UNAUTHORIZED') return UNAVAILABLE.UNAUTHORIZED;
  if (err.code === 'CALDERA_CLIENT_NO_SOURCE_API') return UNAVAILABLE.SYNC_FAILED;
  if (err instanceof FactSourceError) return UNAVAILABLE.SYNC_FAILED;
  return UNAVAILABLE.ERROR;
}

// ---------------------------------------------------------------------------
// The class's deployed spec
// ---------------------------------------------------------------------------

/**
 * The spec the lanes in this scope were actually built from.
 *
 * WHY THE SPEC AND NOT THE PROFILE. fact-source.js's header makes the argument
 * at length and it is the reason this function exists at all: a client profile
 * describes an estate on paper, the lane deploys a SUBSET of it, and an
 * adversary authored against the paper aims abilities at machines that were
 * never built. The answer key then describes activity nothing performed.
 *
 * WHY IT READS ONE LANE AND NOT ALL OF THEM. Every lane in a scope is a clone of
 * the same challenge spec — that is what makes "fan one selection out to every
 * student's lane" meaningful in the first place — so the spec is a property of
 * the SCOPE, not of a student. Reading each lane's would return N copies of one
 * document and invite a merge nobody has a rule for.
 *
 * WHY runner AND target ARE REQUIRED LAZILY. Both drag config/site.json in at
 * module scope through src/utils/site-config.js and src/utils/proxmox.js, and a
 * plain checkout has no site.json. cle/routes/incidents.js is the STUDENT board
 * and is mounted by several test suites that have never needed either; an eager
 * require here would make that file unimportable outside a deployed environment
 * and take the student board down with it. This is the same trap
 * ciab/routes/incident-launch.js documents for engagement-provision.js.
 *
 * @param {object} scope
 * @param {'course'|'engagement'} scope.scopeType
 * @param {string} scope.scopeId
 * @param {object} [deps]  injected by the test — {findScopeLanes, readSpec}
 * @returns {Promise<{spec:object|null, lanes:number, challengeKey:string|null}>}
 */
async function loadScopeSpec(scope, deps) {
  const d = deps || {};
  // eslint-disable-next-line global-require
  const runner = d.findScopeLanes ? null : require('../runner');
  const findScopeLanes = d.findScopeLanes || runner.findScopeLanes;

  const lanes = await findScopeLanes({ scopeType: scope.scopeType, scopeId: scope.scopeId });
  if (!lanes || !lanes.length) return { spec: null, lanes: 0, challengeKey: null };

  // The first lane that names a challenge. A workstation lane (CYBR 400's
  // usual shape) carries no challenge_key at all and legitimately has no spec —
  // that is reported as no_spec, not as an error.
  for (const lane of lanes) {
    const config = typeof lane.config === 'string'
      ? (() => { try { return JSON.parse(lane.config || '{}'); } catch (e) { return {}; } })()
      : (lane.config || {});
    const challengeKey = str(config.challenge_key);
    if (!challengeKey) continue;
    const spec = await readSpecFor(lane, config, d.readSpec);
    if (spec) return { spec, lanes: lanes.length, challengeKey };
  }
  return { spec: null, lanes: lanes.length, challengeKey: null };
}

/**
 * The WHOLE challenge spec for one lane, not just its vms.
 *
 * src/incident/target.js loadSpecVms() walks the same two tables and returns
 * `spec.vms`, which is all the log-generator resolver needs. A fact source needs
 * more than the machine list — `dns.ad_domain`, `goad.domain`,
 * `goad.lab.forestRoot` are what fact-source.domainsFromSpec() reads to build
 * host FQDNs — so this asks the same question and keeps the whole answer.
 *
 * The table LADDER is not re-invented: SHARED_CHALLENGE_TABLE is imported from
 * target.js so the module-specific table and the shared one are named in one
 * place. A second spelling of 'crucible_challenge' here would go stale silently,
 * and the symptom would be a fact source with no hosts in it on exactly the
 * deployments that renamed the table.
 */
async function readSpecFor(lane, config, injected) {
  if (typeof injected === 'function') return injected(lane, config);

  // eslint-disable-next-line global-require
  const { cybercoreQuery } = require('../../utils/cybercore-db');
  // eslint-disable-next-line global-require
  const { SHARED_CHALLENGE_TABLE } = require('../target');

  const moduleKey = String(lane.module_key || config.module || '').replace(/[^a-z0-9_]/gi, '');
  const tables = [];
  if (moduleKey) tables.push(`${moduleKey}_challenge`);
  if (!tables.includes(SHARED_CHALLENGE_TABLE)) tables.push(SHARED_CHALLENGE_TABLE);

  for (const table of tables) {
    try {
      const r = await cybercoreQuery(
        `SELECT spec FROM ${table} WHERE challenge_key = $1`,
        [config.challenge_key]
      );
      if (!r.rows.length) continue;
      const spec = typeof r.rows[0].spec === 'string' ? JSON.parse(r.rows[0].spec) : r.rows[0].spec;
      if (spec && typeof spec === 'object') return spec;
    } catch (err) {
      // A table that does not exist looks exactly like this from here, and it is
      // the EXPECTED shape of the first attempt on every lane whose module has
      // no table of its own. Fall through; the shared table is next.
      continue;
    }
  }
  return null;
}

// ---------------------------------------------------------------------------
// Prepare — the step that must happen BEFORE the link
// ---------------------------------------------------------------------------

/**
 * Refresh one class's fact source, and describe what it now holds.
 *
 * THE ORDER IS THE CONTRACT. Nothing in the returned object says "ready" until
 * syncFactSource() has resolved, and a caller must not offer the authoring link
 * on anything else. See the header for what a link offered early actually costs.
 *
 * Every failure comes back as `{ready:false, reason}` rather than as a throw.
 * That is not squeamishness: the two consoles' entire job on this path is to
 * render "authoring is not set up, here is what an admin does" instead of a dead
 * link, and an exception thrown through an Express handler becomes a 500 and a
 * toast that says "Internal error".
 *
 * @param {object}   opts
 * @param {object}   opts.client      as built by authoringClient(); null is a
 *                                    legal input and answers not_configured
 * @param {string}   opts.scopeLabel  what a human calls this class
 * @param {string}   opts.scopeKey    the class's stable identity
 * @param {object}   opts.spec        the DEPLOYED spec
 * @param {object[]} [opts.assets]    profile assets — OS enrichment only
 * @param {string}   [opts.domain]    AD domain override
 * @param {*}        [opts.users]     account set, when the caller knows one
 * @param {string}   [opts.unavailable] a reason the CALLER already determined
 *                                    (no upstream, no key) — passed through so
 *                                    one branch renders every not-ready state
 * @returns {Promise<object>}  {ready, reason?, fact_source?, platforms?, hosts?,
 *                              excluded?, domains?, warnings?}
 */
async function prepareAuthoring(opts) {
  const o = opts || {};
  if (o.unavailable) return { ready: false, reason: o.unavailable, warnings: [] };
  if (!o.client) return { ready: false, reason: UNAVAILABLE.NOT_CONFIGURED, warnings: [] };
  if (!o.spec || typeof o.spec !== 'object') {
    // NOT an error. A scope with nothing deployed has nothing to author
    // against, and syncing an empty source would publish a class whose every
    // ability creates no link — the exact silent failure fact-source.js warns
    // about, made permanent on a shared server.
    return { ready: false, reason: UNAVAILABLE.NO_SPEC, warnings: [] };
  }

  let built;
  try {
    built = buildFactSource({
      scopeLabel: o.scopeLabel,
      scopeKey: o.scopeKey,
      spec: o.spec,
      assets: o.assets,
      domain: o.domain,
      users: o.users,
    });
  } catch (err) {
    return { ready: false, reason: classifyFailure(err), warnings: [] };
  }

  let synced;
  try {
    // THE AWAIT THAT MAKES THE ORDERING REAL. Everything below this line is a
    // description of a source the server has already accepted.
    synced = await syncFactSource(o.client, built);
  } catch (err) {
    return { ready: false, reason: classifyFailure(err), warnings: built.warnings.slice() };
  }

  return {
    ready: true,
    reason: null,
    fact_source: {
      // The NAME is the only handle an instructor has once they are inside
      // Caldera's UI — the server has no per-user view and no ownership, so the
      // name is how they find their own class's source in a shared list.
      name: synced.name,
      id: synced.id,
      action: synced.action,          // 'created' | 'updated'
    },
    platforms: { ...built.platforms },
    // NAMES ONLY. hostsFromSpec() records roles and exclusion reasons, which
    // describe a client's estate to staff; the console needs the machine list,
    // so the projection happens here rather than being left to whichever caller
    // remembers not to spread the record.
    hosts: built.hosts.filter((h) => !h.excluded).map((h) => ({
      name: h.name,
      fqdn: h.fqdn,
      platform: h.platform,
    })),
    excluded: built.excluded.slice(),
    domains: built.domains.slice(),
    warnings: built.warnings.concat(synced.warnings || []),
  };
}

// ---------------------------------------------------------------------------
// The adversary list
// ---------------------------------------------------------------------------

/**
 * One adversary row, projected.
 *
 * Upstream spells the id `adversary_id` over HTTP and `id` in stockpile YAML,
 * and `atomic_ordering` is the ability list. Everything else the server carries
 * is dropped: an adversary object can hold per-ability command text, which is
 * the intrusion verbatim and has no business in a picker.
 */
function projectAdversary(raw) {
  if (!raw || typeof raw !== 'object') return null;
  const id = str(raw.adversary_id || raw.id);
  if (!id) return null;
  const ordering = Array.isArray(raw.atomic_ordering) ? raw.atomic_ordering : [];
  return {
    adversary_id: id,
    name: str(raw.name) || id,
    description: str(raw.description) || null,
    ability_count: ordering.length,
  };
}

/**
 * What the authoring instance holds, for a picker.
 *
 * PICKING ONE CANNOT LAUNCH ANYTHING. EXECUTION_GATE travels with the list
 * precisely so a console renders the gate from the server's answer rather than
 * from a constant of its own that could drift open — and there is no endpoint,
 * here or in either plugin, that accepts an adversary id and dispatches it.
 * engineFor('caldera') throws; that is the backstop under all of this.
 *
 * @param {object} client  as built by authoringClient(); null answers not_configured
 * @returns {Promise<{ready:boolean, reason:string|null, adversaries:object[], execution:object}>}
 */
async function listAdversaryProfiles(client, opts) {
  const o = opts || {};
  const base = { adversaries: [], execution: EXECUTION_GATE };
  if (o.unavailable) return { ready: false, reason: o.unavailable, ...base };
  if (!client) return { ready: false, reason: UNAVAILABLE.NOT_CONFIGURED, ...base };

  let rows;
  try {
    rows = await client.listAdversaries();
  } catch (err) {
    return { ready: false, reason: classifyFailure(err), ...base };
  }

  const list = (Array.isArray(rows) ? rows : [])
    .map(projectAdversary)
    .filter(Boolean)
    // By NAME, because the server's order is insertion order on a store several
    // instructors share, so "the one I just made" is not where a human looks.
    .sort((a, b) => a.name.localeCompare(b.name));

  return { ready: true, reason: null, adversaries: list, execution: EXECUTION_GATE };
}

module.exports = {
  UNAVAILABLE,
  EXECUTION_GATE,
  DEFAULT_TIMEOUT_MS,
  resolveApiKey,
  authoringClient,
  resolveTarget,
  classifyFailure,
  loadScopeSpec,
  prepareAuthoring,
  listAdversaryProfiles,
  // Exported for the tests, which pin the projections directly rather than only
  // through a whole prepare.
  projectAdversary,
  readSpecFor,
};
