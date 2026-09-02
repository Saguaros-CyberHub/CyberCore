/**
 * ============================================================================
 * INCIDENT ENGINE — 'caldera'  (Track E phase E9, DROPPABLE)
 * ============================================================================
 *
 * ############################################################################
 * # NOTHING IN THIS FILE HAS EVER RUN AGAINST A CALDERA SERVER.              #
 * #                                                                          #
 * # There is no Caldera in this repository, none on any cluster, and no lane #
 * # has ever had one. No operation has been created, no link has been polled,#
 * # no agent has beaconed. Every API shape below comes from upstream's       #
 * # DOCUMENTED v2 API and is UNVERIFIED, and the two things that cannot be   #
 * # verified without a lane are called out inline where they bite:           #
 * #                                                                          #
 * #   1. HOW THE ORCHESTRATOR REACHES A LANE-LOCAL CALDERA AT ALL. See       #
 * #      endpointFor() — this is UNSOLVED, not merely untested.              #
 * #   2. WHAT A LINK'S `status` NUMBER MEANS. See LINK_STATUS.               #
 * #                                                                          #
 * # What IS verified is every behaviour on this side of                      #
 * # src/incident/caldera/client.js's transport seam, driven by a fake in     #
 * # test/caldera-engine.test.js: the lifecycle, the engine_ref round trip,   #
 * # the failed-link path, and that readTargetState's shape is the one        #
 * # src/incident/worker.js already consumes.                                 #
 * #                                                                          #
 * # THIS ADAPTER IS NOT REGISTERED. src/incident/engines/index.js still      #
 * # refuses engineFor('caldera') and must keep refusing it until the E8      #
 * # cluster gate has passed. Nothing a user can press reaches this file.     #
 * ############################################################################
 *
 * WHAT THIS IS
 * ----------------------------------------------------------------------------
 * The second implementation of the contract in src/incident/engines/index.js,
 * written to prove that contract was worth having: adding a real C2 to the
 * incident engine touches THIS FILE, src/incident/caldera/*, and nothing else.
 * No board table, no route, no UI, no DDL — `caldera` was already legal in
 * cybercore_incident_run.engine's CHECK and `engine_ref` was already on the
 * target row, both from E0, both confirmed against src/incident/schema.js
 * rather than assumed.
 *
 * WHY THE SHAPE OF readTargetState() IS THE WHOLE POINT
 * ----------------------------------------------------------------------------
 * src/incident/worker.js polls a guest, parses a state line with
 * runner.parseGuestState(), and hands the result to applyPhase(). If a Caldera
 * run needed a branch in that file, the abstraction would have failed — the
 * worker would grow an `if (run.engine === 'caldera')`, and from there so would
 * the board, and then the routes.
 *
 * So readTargetState() returns EXACTLY parseGuestState's object, field for
 * field, and every one of those fields is consumed somewhere in worker.js:
 *
 *     phase   ''|scheduled|running|done|refused|aborted   applyPhase's switch
 *     alive   boolean          "did it die before writing anything"
 *     reason  string|null      refusal reason
 *     rc      int|null         exit code -> completed vs failed
 *     lines   int|null         written to target.event_count
 *     skew    int|null         clock skew, written to clock_skew_s
 *     src     string|null      names WHAT failed in producerFailure()
 *     raw     string           stored as guest_state, sliced to 500
 *     fellBack/split/ref/pid   carried for parity; unused by the worker today
 *
 * NOTE the field is `lines`, NOT `events`. The E9 brief says `events`; the code
 * says `lines` (runner.js:385, read by worker.js applyPhase as `p.lines`). The
 * code wins.
 *
 * TWO CONSEQUENCES OF NOT BRANCHING THE WORKER, ACCEPTED DELIBERATELY
 * ----------------------------------------------------------------------------
 *   1. `event_count` holds a LINK count for a Caldera run. A link is one ability
 *      executed against one agent; an "event" for the synthetic engine is one
 *      ND-JSON line. They are not the same unit and an instructor comparing the
 *      two numbers is comparing different things. The alternative was null,
 *      which makes a live operation look wedged for its whole duration — worse.
 *   2. A target that never got an operation reports phase '' with alive=false,
 *      and worker.js writes the synthetic-flavoured error 'wrapper exited before
 *      writing any state'. There is no wrapper. Fixing the wording means editing
 *      worker.js, which is exactly the coupling this file exists to avoid; the
 *      dispatch path already fails loudly before that state is reachable.
 *
 * WHY THE ANSWER KEY IS COMPILED IN prepare(), NOT AT LAUNCH
 * ----------------------------------------------------------------------------
 * compileAnswerKey() is called by a route in the same statement as the run
 * INSERT, and it is synchronous. A Caldera key cannot be compiled there, because
 * it depends on the ABILITY CATALOG, which is per-server state that only a
 * network call can produce (src/incident/caldera/adversary.js's header explains
 * why that catalog is injected and never fetched by the compiler).
 *
 * So compileAnswerKey() returns the honest empty-but-shaped key from
 * src/incident/answer-key.js unless the caller has already put a catalog on the
 * resolved selection, and prepare() — which is async, whole-run, and allowed to
 * touch the network — compiles the real one and RETURNS it for the caller to
 * persist. It does not write to the database itself: no dispatcher is wired to
 * this engine yet, and an engine that quietly UPDATEs a run row would be a
 * second writer to a column runner.js already owns.
 *
 * Either way the key is src/incident/answer-key.js's shape, so a Caldera run
 * scores through src/incident/scoring.js with zero changes there — which was the
 * point of compiling it from the abilities that WILL run rather than from the
 * scenario that was asked for.
 * ============================================================================
 */

'use strict';

/** The registry key. Already legal in cybercore_incident_run.engine's CHECK. */
const ENGINE_KEY = 'caldera';

/**
 * Lazily required, and not for style — the same trap engines/synthetic.js
 * documents. src/utils/site-config reads config/site.json, which is gitignored
 * and absent from a plain checkout, so requiring it at module scope would make
 * this file unimportable outside a deployed environment and take the test suite
 * with it. Deferring costs one property lookup per call.
 */
function siteConfig() {
  return require('../../utils/site-config').getConfig();
}

/** Same reasoning; answer-key.js is cheap but there is no reason to load it early. */
function answerKeyModule() {
  return require('../answer-key');
}

/** The pure compiler. No network, no db, no fs — safe at module scope. */
const { compileAdversary } = require('../caldera/adversary');

/** The only file in this adapter allowed to open a socket. */
const calderaClient = require('../caldera/client');

/**
 * A scenario id, as cybercore_incident_run.scenario_id can hold it.
 *
 * The client's own string, generated as 'TS-001' by whatever wrote the profile
 * and never validated there. It does not reach a shell on this path — it goes
 * into a JSON body and into an adversary name — but it is still REJECTED by
 * shape rather than sanitized, because the abilities this run selects DO execute
 * as real commands on a real host and "we validate the cheap fields" is how the
 * expensive one eventually gets skipped. 64 characters is the column's own
 * VARCHAR(64), not a number picked here.
 */
const SCENARIO_ID_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

/**
 * What a link's `status` integer means.
 *
 * UNVERIFIED, and the single most likely thing in this file to be wrong. Read
 * from upstream's documented link states: negative values are lifecycle states
 * (queued, paused, discarded, awaiting trust) and non-negative values are the
 * COMMAND'S OWN EXIT CODE, so 0 is success and anything positive is a failure.
 *
 * Centralised in one place precisely because it is a guess: if a real server
 * disagrees, this constant and the two predicates below are the entire fix, and
 * nothing else in the adapter reads a raw status number.
 */
const LINK_STATUS = Object.freeze({
  SUCCESS: 0,
  /** Documented lifecycle sentinels. All negative; none of them is an outcome. */
  HIGH_VIZ: -5,
  UNTRUSTED: -4,
  EXECUTE: -3,
  DISCARD: -2,
  PAUSE: -1,
});

/** Operation states that mean "this is over". UNVERIFIED, same caveat. */
const TERMINAL_OPERATION_STATES = Object.freeze(['finished', 'cleanup', 'out_of_time']);

/** Operation states that mean "not started yet". */
const PENDING_OPERATION_STATES = Object.freeze(['paused']);

/** A link that has run to completion, successfully or not. */
function linkIsFinished(link) {
  const st = Number(link && link.status);
  if (Number.isInteger(st) && st >= 0) return true;
  // Fallback for a server that reports a finish timestamp before it settles the
  // status. Cheap, and it only ever adds finished links, never removes one.
  return !!(link && typeof link.finish === 'string' && link.finish.trim());
}

/** A link that ran and failed. Discarded/queued links are neither. */
function linkIsFailed(link) {
  const st = Number(link && link.status);
  return Number.isInteger(st) && st > LINK_STATUS.SUCCESS;
}

// ---------------------------------------------------------------------------
// Configuration and endpoints
// ---------------------------------------------------------------------------

/** A named, actionable refusal rather than a TypeError three frames later. */
function calderaConfigError(message, code) {
  const err = new Error(message);
  err.name = 'CalderaConfigError';
  err.code = code || 'CALDERA_NOT_CONFIGURED';
  return err;
}

/**
 * Everything this adapter needs that is not on the run row.
 *
 * Read from site.json's `caldera` block at CALL time (see siteConfig()), or
 * injected wholesale by a test. There is no default for `api_key` and there
 * must not be: a defaulted C2 credential is a shared credential across every
 * cohort, which is the exact position bake-caldera-server.sh takes about its own
 * secrets and for the same reason.
 */
function resolveSettings(override) {
  const raw = override || (siteConfig() || {}).caldera || {};
  const apiKey = String(raw.api_key == null ? '' : raw.api_key).trim();
  if (!apiKey) {
    throw calderaConfigError(
      'caldera engine: no API key. Set config/site.json -> caldera.api_key to the RED key baked '
      + 'into the lane template (bake-caldera-server.sh writes it to '
      + '/opt/cybercore/caldera-api-key.red). There is deliberately no default: a defaulted C2 '
      + 'credential is a shared credential across every cohort.',
      'CALDERA_NOT_CONFIGURED'
    );
  }
  return {
    apiKey,
    scheme: String(raw.scheme || 'http'),
    port: Number(raw.port) > 0 ? Number(raw.port) : 8888,
    timeoutMs: Number(raw.timeout_ms) > 0 ? Number(raw.timeout_ms) : undefined,
    // Caldera's defaults. Named here rather than inlined so a site that renames
    // its planner does not need a code change.
    plannerId: String(raw.planner_id || 'atomic'),
    sourceId: String(raw.source_id || 'basic'),
    agentGroup: String(raw.agent_group || 'red'),
    // Passed to the compiler so a Windows-only estate does not silently select
    // Linux abilities that no agent in the lane can run.
    platform: raw.platform == null ? null : raw.platform,
    /** How stale an agent's last beacon may be before it does not count. */
    agentMaxAgeS: Number(raw.agent_max_age_s) > 0 ? Number(raw.agent_max_age_s) : 600,
  };
}

/**
 * jsonb comes back as an object from node-postgres and as a string from a few
 * other paths (a row round-tripped through JSON, a test fixture). Normalising in
 * one place means no caller has to care which it got.
 */
function asObject(v) {
  if (!v) return null;
  if (typeof v === 'object') return v;
  if (typeof v === 'string') {
    try {
      const parsed = JSON.parse(v);
      return parsed && typeof parsed === 'object' ? parsed : null;
    } catch (_) {
      return null;
    }
  }
  return null;
}

/**
 * WHERE THIS ADAPTER SENDS ITS REQUESTS, AND WHY THAT IS AN OPEN QUESTION
 * ----------------------------------------------------------------------------
 * bake-caldera-server.sh makes the server LANE-LOCAL on purpose and calls that
 * non-negotiable: one clone per lane, reachable only from inside that lane,
 * because an agent that can reach a controller outside its own lane turns a
 * teaching lab into a botnet with a class roster.
 *
 * The orchestrator is NOT inside the lane. It reaches lane guests over the
 * Proxmox guest agent, not over HTTP, and the one HTTP path that does exist into
 * a lane is the gateway console DNAT — which that same hand-off block forbids
 * using for this box, because a student with a session on the C2 holds the
 * entire answer key.
 *
 * So HOW the control plane talks to a lane-local Caldera is UNSOLVED. It is not
 * a detail this phase deferred by accident; it is the design question E9's next
 * phase has to answer, and the two candidates are:
 *
 *   a. a staff-only DNAT on the gateway, published to the orchestrator's address
 *      only, never in consoleTargets
 *   b. no HTTP at all from here — drive the server over the guest agent the way
 *      every other lane operation already works, and make this client's
 *      transport a QGA-backed one instead of fetch()
 *
 * Option (b) is why client.js's transport is injectable in the first place: it
 * would be a new transport function and NOTHING else in this adapter.
 *
 * Until then this resolves in the only honest order — an endpoint a previous
 * dispatch already recorded, then one a caller supplies — and REFUSES rather
 * than guessing an address.
 */
function endpointFor(target, settings) {
  const t = target || {};
  const ref = asObject(t.engine_ref);
  if (ref && ref.server) return String(ref.server);
  if (t.caldera_url) return String(t.caldera_url);
  if (t.caldera_host) {
    return `${settings.scheme}://${String(t.caldera_host)}:${settings.port}`;
  }
  throw calderaConfigError(
    `caldera engine: no server endpoint for lane ${t.lane_id || '(unknown)'}. Reaching a `
    + 'LANE-LOCAL Caldera from the control plane is an unsolved design question — see '
    + 'endpointFor() in this file. Supply target.caldera_url (or target.caldera_host) from '
    + 'whatever resolver answers it, or hand this adapter a transport that speaks over the guest '
    + 'agent instead of HTTP.',
    'CALDERA_ENDPOINT_UNKNOWN'
  );
}

// ---------------------------------------------------------------------------
// The adapter
// ---------------------------------------------------------------------------

/**
 * Build an adapter.
 *
 * A factory rather than a bare object literal so a test can inject a client
 * factory and a clock without touching a global. The exported default is
 * createCalderaEngine() with the real client, which is what a registration would
 * use — see the note at the bottom of src/incident/engines/index.js for why that
 * registration has not happened.
 *
 * @param {object}   [deps]
 * @param {Function} [deps.createClient] ({baseUrl, apiKey, timeoutMs}) -> client
 * @param {object}   [deps.settings]     bypasses site.json entirely
 * @param {Function} [deps.now]          () -> epoch ms
 */
function createCalderaEngine(deps) {
  const d = deps || {};
  const createClient = typeof d.createClient === 'function'
    ? d.createClient : calderaClient.createCalderaClient;
  const now = typeof d.now === 'function' ? d.now : () => Date.now();

  /** Settings are resolved per call, never cached: site.json may be injected. */
  function settings() {
    return resolveSettings(d.settings);
  }

  function clientFor(target, cfg) {
    return createClient({
      baseUrl: endpointFor(target, cfg),
      apiKey: cfg.apiKey,
      timeoutMs: cfg.timeoutMs,
    });
  }

  /**
   * The scenario object itself — attack_path and all.
   *
   * Core does not and must not go and fetch it: a client profile lives in a
   * PLUGIN's tables (modules/crucible/plugins/ciab), and src/incident/ requiring
   * into a plugin is the inversion test/incident-engine-locality.test.js exists
   * to fail. The caller compiles nothing here either — it just hands the
   * scenario down, exactly as the synthetic engine's scenario arm does with its
   * playbook.
   */
  function scenarioFrom(resolved, explicit) {
    const scenario = explicit || (resolved && resolved.scenario) || null;
    if (!scenario || typeof scenario !== 'object' || !Array.isArray(scenario.attack_path)) {
      throw calderaConfigError(
        'caldera engine: no threat scenario to compile. Put the profile\'s scenario object (the '
        + 'one carrying attack_path[]) on the resolved selection as `scenario`, or pass it in. '
        + 'Core cannot fetch it — client profiles live in a plugin\'s tables and src/incident/ '
        + 'must never require into modules/crucible/plugins/.',
        'CALDERA_NO_SCENARIO'
      );
    }
    return scenario;
  }

  return {
    key: ENGINE_KEY,

    /**
     * 'scenario' AND NOTHING ELSE, which is the exact complement of what the
     * synthetic engine was built for.
     *
     * technique / tactic / chain are the LOG-GENERATOR'S vocabulary: they are
     * validated against src/incident/catalog.js, which describes what cc-emit.js
     * can fabricate. Caldera has never heard of that catalog. Its unit of work
     * is an ability id out of a per-server catalog, and the only thing in this
     * system that names a coherent ordered set of them is a client profile's
     * threat scenario compiled by src/incident/caldera/adversary.js.
     *
     * Claiming 'technique' here would be plausible — one technique does map to
     * one ability — and it is still refused, because a one-ability operation is
     * not an incident and an instructor picking T1059 from the existing console
     * would get a run that fires a single command and completes, which reads as
     * a broken exercise rather than an unsupported one.
     */
    supportsMode(mode) {
      return mode === 'scenario';
    },

    /**
     * Validate a run row's scenario columns.
     *
     * THROWS on anything it cannot validate and never sanitizes — same rule as
     * runner.resolveSelection, for a reason that is if anything sharper here:
     * what this selection eventually causes is real commands executing on a real
     * Windows host, not a fabricated log line.
     */
    resolveSelection(runRow) {
      const row = runRow || {};

      if (row.mode !== 'scenario') {
        throw new Error(
          `caldera engine: unsupported mode ${JSON.stringify(row.mode)}. This engine runs `
          + "compiled threat scenarios only; technique/tactic/chain are the log generator's "
          + 'catalog and Caldera has no notion of them.'
        );
      }

      const scenarioId = String(row.scenario_id == null ? '' : row.scenario_id);
      if (!SCENARIO_ID_RE.test(scenarioId)) {
        throw new Error(`invalid scenario id: ${JSON.stringify(row.scenario_id)}`);
      }

      // NOT NULL for this mode by construction: cc_incident_run_duration_matches_mode
      // makes a NULL duration legal only for a chain. The bounds are the
      // column's own CHECK restated, so the refusal is a sentence rather than a
      // 23514 out of Postgres.
      const durationSeconds = Number(row.duration_seconds);
      if (!Number.isInteger(durationSeconds) || durationSeconds < 30 || durationSeconds > 28800) {
        throw new Error(
          `duration_seconds must be an integer in [30, 28800], got ${JSON.stringify(row.duration_seconds)}`
        );
      }

      return {
        mode: 'scenario',
        arg: scenarioId,
        scenarioId,
        scenarioRef: asObject(row.scenario_ref),
        // Carried through if the caller already attached it. scenarioFrom()
        // is what actually insists on it, at the point it is needed.
        scenario: row.scenario && typeof row.scenario === 'object' ? row.scenario : null,
        durationSeconds,
        // A CAP, not a plan, and the difference matters. cc-emit lays events out
        // to fill a requested duration; a Caldera operation runs until its links
        // are done, which may be two minutes or may be never. So this is the
        // deadline past which the operation is cut off, using the same 20%
        // headroom plus two minutes runner.resolveSelection uses.
        capSeconds: Math.ceil(durationSeconds * 1.2) + 120,
        // There is no catalog version to report. The ability catalog is
        // per-server state with no version string on it, and prepare() records
        // which server's catalog was actually used instead — which is the
        // question this field exists to answer.
        catalogVersion: 'caldera:per-server',
        label: row.scenario_label ? String(row.scenario_label) : `scenario ${scenarioId}`,
      };
    },

    /**
     * STAFF-ONLY grading key.
     *
     * Synchronous by contract (a route calls it in the same statement as the run
     * INSERT), and a real Caldera key needs the server's ability catalog — so
     * there are two paths and both are honest:
     *
     *   - a caller that already fetched a catalog puts it on the selection as
     *     `abilities`, and gets the compiled key immediately
     *   - everyone else gets answer-key.js's empty-but-shaped key, with a
     *     `reason` naming prepare() as where the real one comes from
     *
     * The empty key is not a failure mode: scoring.js reads it as "not
     * auto-graded" and marks every claim unscored, which is the honest answer.
     * A guessed key mis-grades silently, which is not.
     */
    compileAnswerKey(runRow, resolved) {
      const row = runRow || {};
      const sel = resolved || {};
      const abilities = sel.abilities;

      if (Array.isArray(abilities) && abilities.length) {
        const compiled = compileAdversary({
          scenario: scenarioFrom(sel, sel.scenario),
          abilities,
          options: {
            runId: row.run_id,
            platform: sel.platform,
            name: sel.label,
          },
        });
        // warnings ride along on the key: every one of them names a scenario
        // step that will NOT happen, and an instructor reading a board needs
        // that where the board already looks. adversary.js's header makes the
        // same point about `unmapped` — a superset is safe because scoring.js
        // and board.js read by name.
        return { ...compiled.answerKey, warnings: compiled.warnings };
      }

      const empty = answerKeyModule().answerKeyForRun({
        run_id: row.run_id,
        engine: ENGINE_KEY,
      });
      return {
        ...empty,
        reason: 'the Caldera answer key is compiled in prepare(), once the lane server\'s ability '
          + 'catalog is known: which abilities exist is per-server state, so a key compiled at '
          + 'launch would describe a scenario rather than the operation. Until prepare() runs and '
          + 'its key is persisted, this run is not auto-graded.',
      };
    },

    /**
     * Whole-run setup, before any lane is touched.
     *
     * Fetches the ability catalog ONCE and compiles the adversary ONCE. Fetching
     * once is safe for a specific reason and not merely convenient: every lane's
     * server is a clone of the SAME template (bake-caldera-server.sh pins a
     * Caldera tag precisely so the catalog cannot drift between clones), so the
     * catalogs are identical by construction. If that ever stops being true, the
     * symptom is a 404 on an ability id at dispatch — loud, and in the right
     * place.
     *
     * SAFE TO CALL TWICE, as the contract demands: it is one GET plus a pure
     * function, and the adversary id is a deterministic uuidv5 over the scenario
     * and the ordered ability list.
     *
     * Returns rather than writes. There is no dispatcher wired to this engine,
     * and an engine that UPDATEd cybercore_incident_run.answer_key itself would
     * be a second writer to a column runner.js already owns.
     */
    async prepare(args) {
      const a = args || {};
      const run = a.run || {};
      const targets = Array.isArray(a.targets) ? a.targets : [];
      const resolved = a.resolved || {};
      const cfg = settings();
      const scenario = scenarioFrom(resolved, a.scenario);

      let abilities = Array.isArray(a.abilities) ? a.abilities : null;
      let catalogFrom = abilities ? 'injected' : null;

      if (!abilities) {
        // The first target that HAS an endpoint, not simply the first target: a
        // lane whose endpoint cannot be resolved must not decide the run.
        let lastErr = null;
        for (const t of targets) {
          try {
            const client = clientFor(t, cfg);
            const list = await client.listAbilities();
            abilities = Array.isArray(list) ? list : [];
            catalogFrom = client.baseUrl;
            break;
          } catch (err) {
            lastErr = err;
          }
        }
        if (!abilities) {
          throw lastErr || calderaConfigError(
            'caldera engine: prepare() had no target with a reachable server, so there is no '
            + 'ability catalog to compile against.',
            'CALDERA_NO_CATALOG'
          );
        }
      }

      const compiled = compileAdversary({
        scenario,
        abilities,
        options: {
          runId: run.run_id,
          platform: resolved.platform == null ? cfg.platform : resolved.platform,
          name: resolved.label,
        },
      });

      // The compiler WARNS on an empty adversary and says the caller must refuse
      // to launch it. This is that caller. An operation with no abilities
      // finishes instantly having done nothing, and every lane reports
      // 'completed' — the single worst outcome available, because it looks like
      // a working exercise.
      if (!compiled.adversary.atomic_ordering.length) {
        const err = new Error(
          `caldera engine: scenario ${scenario.scenario_id || '(unnamed)'} compiled to zero `
          + 'abilities against this server\'s catalog, so the operation would run nothing and '
          + `report success. ${compiled.warnings.join(' | ')}`
        );
        err.code = 'CALDERA_ADVERSARY_EMPTY';
        err.warnings = compiled.warnings;
        err.unmapped = compiled.unmapped;
        throw err;
      }

      return {
        adversary: compiled.adversary,
        answerKey: { ...compiled.answerKey, warnings: compiled.warnings },
        warnings: compiled.warnings,
        unmapped: compiled.unmapped,
        abilityCount: abilities.length,
        catalogFrom,
      };
    },

    /**
     * Start the incident in ONE lane.
     *
     * Three calls, in an order that is not arbitrary: assert the adversary
     * exists on THIS lane's server, confirm an agent has actually beaconed, then
     * create the operation. Confirming the agent BEFORE creating the operation is
     * the whole difference between a failure an instructor can read and a lane
     * that sits at 'running' for forty-five minutes and then reports it did
     * nothing.
     *
     * Returns engineRef, which the caller writes to
     * cybercore_incident_target.engine_ref — the column E0 put on the table for
     * exactly this, so E9 does no DDL.
     */
    async dispatchTarget(args) {
      const a = args || {};
      const run = a.run || {};
      const target = a.target || {};
      const prepared = a.prepared || {};
      const cfg = settings();

      const adversary = prepared.adversary;
      if (!adversary || !adversary.adversary_id) {
        throw calderaConfigError(
          'caldera engine: dispatchTarget() needs prepare()\'s compiled adversary. Dispatching '
          + 'without one would create an operation against an adversary that may not exist on '
          + 'this lane\'s server.',
          'CALDERA_NOT_PREPARED'
        );
      }

      const client = clientFor(target, cfg);

      // Idempotent by construction: adversary_id is a uuidv5 over the scenario
      // and the ordered ability list, and the client tolerates a 409.
      await client.createAdversary(adversary);

      const agents = await client.listAgents();
      const usable = selectAgents(agents, cfg, now());
      if (!usable.length) {
        const err = new Error(
          `caldera engine: no agent has beaconed to ${client.baseUrl} in the last `
          + `${cfg.agentMaxAgeS}s (group '${cfg.agentGroup}'), so an operation here would execute `
          + 'nothing. Failing at dispatch rather than reporting a run that produced no telemetry.'
        );
        err.code = 'CALDERA_NO_AGENT';
        throw err;
      }

      const created = await client.createOperation({
        name: operationName(run, prepared),
        adversary: { adversary_id: adversary.adversary_id },
        // UNVERIFIED field names, upstream's documented v2 operation body.
        planner: { id: cfg.plannerId },
        source: { id: cfg.sourceId },
        group: cfg.agentGroup,
        state: 'running',
        autonomous: 1,
        // Staff-only server; there is no reason to obfuscate the operation from
        // itself, and a visible operation is one an instructor can debug.
        obfuscator: 'plain-text',
        auto_close: true,
      });

      const operationId = operationIdOf(created);
      if (!operationId) {
        const err = new Error(
          'caldera engine: the server accepted POST /operations but returned no operation id, so '
          + 'nothing can poll or abort this lane. Treating it as a dispatch failure rather than '
          + 'recording a target that cannot be reconciled.'
        );
        err.code = 'CALDERA_NO_OPERATION_ID';
        throw err;
      }

      return {
        dispatched: true,
        operationId,
        // WHAT GOES IN cybercore_incident_target.engine_ref. `server` is in here
        // deliberately: it is what endpointFor() reads back on the next poll, so
        // a lane keeps talking to the same box even if whatever resolved it the
        // first time is unavailable later.
        engineRef: {
          engine: ENGINE_KEY,
          server: client.baseUrl,
          adversary_id: adversary.adversary_id,
          operation_id: operationId,
          // The paw is the agent's identity. Singular for the console, plural
          // for the truth: a lane with two Windows hosts has two agents and the
          // operation runs against both.
          paw: usable[0].paw,
          paws: usable.map((x) => x.paw),
          agent_group: cfg.agentGroup,
          dispatched_at: new Date(now()).toISOString(),
        },
      };
    },

    /**
     * Poll one lane. SIDE-EFFECT FREE: two GETs and nothing else.
     *
     * Returns runner.parseGuestState()'s exact object — see this file's header
     * for the field-by-field mapping and why that shape is the whole point.
     *
     * WHAT THROWS AND WHAT DOES NOT, deliberately:
     *   - a transport failure (timeout, connection refused) PROPAGATES, because
     *     worker.js's recordCheckFailure ladder is precisely the right handling
     *     for "the network did not answer": it increments check_failures, backs
     *     off, and only gives up once the target is also overdue.
     *   - anything the server actually TOLD us is turned into a phase here. A
     *     404 on the operation is a diagnosis ('refused'), not a check failure,
     *     because retrying it for ten minutes cannot change the answer.
     */
    async readTargetState(args) {
      const a = args || {};
      const target = a.target || {};
      const ref = asObject(target.engine_ref);

      if (!ref || !ref.operation_id) {
        // Nothing was ever dispatched here. Reported as the empty state a guest
        // shows before its first write, which is what worker.js already knows
        // how to act on — see consequence (2) in this file's header.
        return guestState({ phase: '', alive: false, raw: '' });
      }

      if (ref.aborted_at) {
        return guestState({
          phase: 'aborted',
          alive: false,
          raw: `aborted op=${ref.operation_id} at=${ref.aborted_at}`,
        });
      }

      const cfg = settings();
      const client = clientFor(target, cfg);

      const opRaw = await client.getOperation(ref.operation_id);
      if (isTolerated(opRaw)) {
        // The operation is gone: the server was rebuilt, or somebody deleted it
        // in the UI. NOT 'notinstalled' — worker.js treats that one reason as a
        // signal to invalidate the LOG-GENERATOR cache, which has nothing to do
        // with this engine.
        return guestState({
          phase: 'refused',
          reason: 'nooperation',
          alive: false,
          raw: `refused nooperation op=${ref.operation_id}`,
        });
      }
      const op = firstOf(opRaw) || {};
      const state = String(op.state || '').toLowerCase();

      const linksRaw = await client.listLinks(ref.operation_id);
      const links = isTolerated(linksRaw) || !Array.isArray(linksRaw) ? [] : linksRaw;
      const finished = links.filter(linkIsFinished);
      const failed = finished.filter(linkIsFailed);

      const base = {
        lines: finished.length,
        src: ENGINE_KEY,
        ref: ref.operation_id,
      };

      if (TERMINAL_OPERATION_STATES.includes(state)) {
        // A FAILED LINK IS A FAILED TARGET, and this is the line that makes it
        // so. Without it an operation that ran six abilities and had five of
        // them blocked by Defender reports 'completed' with a link count that
        // nobody reads, and the exercise silently contains almost none of the
        // activity its answer key describes.
        const rc = failed.length ? failedRc(failed) : 0;
        return guestState({
          ...base,
          phase: 'done',
          alive: false,
          rc,
          raw: `done rc=${rc} links=${finished.length}/${links.length} `
            + `failed=${failed.length} state=${state} op=${ref.operation_id}`,
        });
      }

      if (PENDING_OPERATION_STATES.includes(state) || (!finished.length && !links.length)) {
        return guestState({
          ...base,
          phase: 'scheduled',
          alive: true,
          raw: `scheduled links=0 state=${state || 'unknown'} op=${ref.operation_id}`,
        });
      }

      return guestState({
        ...base,
        phase: 'running',
        alive: true,
        raw: `running links=${finished.length}/${links.length} failed=${failed.length} `
          + `state=${state || 'unknown'} op=${ref.operation_id}`,
      });
    },

    /**
     * Stop ONE lane. Idempotent, because abort races the sweeper by construction.
     *
     * Never throws on a server it cannot reach, and that is the same call
     * runner.abortRun makes: a guest we cannot reach is one we also cannot
     * verify, and refusing to record the abort would leave the run live forever
     * on a lane nobody can fix. The unreachability is REPORTED, not swallowed.
     */
    async abortTarget(args) {
      const a = args || {};
      const target = a.target || {};
      const ref = asObject(target.engine_ref);

      if (!ref || !ref.operation_id) {
        // Nothing to stop. Success, not an error: this is exactly the shape of
        // an abort that races a dispatch which had not yet created an operation.
        return { aborted: true, operationId: null, unreachable: false, reason: 'nothing dispatched' };
      }

      try {
        const client = clientFor(target, settings());
        await client.abortOperation(ref.operation_id);
        return { aborted: true, operationId: ref.operation_id, unreachable: false };
      } catch (err) {
        return {
          aborted: false,
          operationId: ref.operation_id,
          unreachable: calderaClient.isTransportFailure(err),
          error: err && err.message ? err.message : String(err),
        };
      }
    },

    /** Stop every live lane. Never throws: one unreachable lane is not the run. */
    async abortRun(args) {
      const a = args || {};
      const targets = Array.isArray(a.targets) ? a.targets : [];
      const results = [];
      for (const target of targets) {
        // Sequential on purpose. Abort is rare, the lanes are few, and a
        // fan-out here would need its own concurrency budget for no gain.
        results.push(await this.abortTarget({ run: a.run, target }));
      }
      return {
        aborted: results.filter((r) => r.aborted).length,
        unreachable: results.filter((r) => r.unreachable).length,
        results,
      };
    },

    /**
     * Roll per-lane outcomes into the run's terminal status.
     *
     * Deliberately NOT the same arithmetic as runner.finalizeRunStatus, and the
     * contract in engines/index.js says why: 'partial' means different things per
     * engine. The difference here is ONE rule, and it is the one that matters —
     *
     *   A LANE THAT COMPLETED WITH ZERO LINKS PRODUCED NOTHING.
     *
     * For the synthetic engine a completed target with no events is nearly
     * impossible (the emitter writes or it exits non-zero). For Caldera it is
     * the single most likely failure in the whole design: the agent never
     * beaconed, the operation ran out of links to give it, and the operation
     * closed cleanly having executed nothing at all. Counting that as
     * 'completed' would tell an instructor the class has data that does not
     * exist — the exact lie worker.js's header refuses to tell.
     */
    finalize(args) {
      const a = args || {};
      const targets = Array.isArray(a.targets) ? a.targets : [];
      const counts = {
        total: targets.length, live: 0, completed: 0, barren: 0, bad: 0, skipped: 0, aborted: 0,
      };

      for (const t of targets) {
        const st = String(t && t.status);
        if (st === 'dispatching' || st === 'scheduled' || st === 'running') counts.live += 1;
        else if (st === 'completed') {
          // NULL means "we never learned", which is NOT the same as zero and
          // must not be counted as a barren lane. Spelled out rather than
          // leaning on Number(), because Number(null) is 0 — which silently
          // turned every completed target whose event_count the sweeper had not
          // written yet into a failed run.
          const events = t == null ? null : t.event_count;
          const known = events !== null && events !== undefined && Number.isFinite(Number(events));
          if (known && Number(events) === 0) counts.barren += 1;
          else counts.completed += 1;
        } else if (st === 'failed' || st === 'unknown') counts.bad += 1;
        else if (st === 'skipped') counts.skipped += 1;
        else if (st === 'aborted') counts.aborted += 1;
      }

      if (counts.live > 0) return { status: 'running', counts };

      const bad = counts.bad + counts.barren + counts.skipped;
      let status;
      let reason = null;
      if (counts.completed > 0) {
        status = bad > 0 || counts.aborted > 0 ? 'partial' : 'completed';
      } else if (counts.aborted > 0) {
        status = 'aborted';
      } else {
        status = 'failed';
        if (counts.barren > 0 && counts.bad === 0) {
          reason = 'every lane\'s operation closed without executing a single ability — the usual '
            + 'cause is an agent that never beaconed to its lane\'s server.';
        }
      }
      return { status, counts, reason };
    },
  };
}

// ---------------------------------------------------------------------------
// Pure helpers
// ---------------------------------------------------------------------------

/**
 * runner.parseGuestState()'s object, every field present.
 *
 * Built from a defaults object rather than by spreading whatever the caller
 * happened to pass, so a missing field is null here instead of `undefined` three
 * files away in a SQL parameter — worker.js binds several of these straight into
 * an UPDATE, and node-postgres treats undefined and null differently.
 */
function guestState(partial) {
  const p = partial || {};
  return {
    phase: p.phase == null ? '' : String(p.phase),
    reason: p.reason == null ? null : String(p.reason),
    alive: !!p.alive,
    rc: Number.isInteger(p.rc) ? p.rc : null,
    lines: Number.isInteger(p.lines) ? p.lines : null,
    // No clock to compare against. The synthetic engine gets this from the guest
    // itself; a Caldera server reports its own time, not the victim host's, so
    // any number here would describe the wrong machine.
    skew: null,
    fellBack: false,
    split: null,
    ref: p.ref == null ? null : String(p.ref),
    src: p.src == null ? null : String(p.src),
    pid: null,
    raw: p.raw == null ? '' : String(p.raw),
  };
}

/**
 * The exit code to report for a set of failed links.
 *
 * The FIRST failing link's status, not a count and not a generic 1: it is the
 * command's own exit code, and worker.js renders it verbatim ('the attack
 * process exited N'). A number that came from the host is worth more to whoever
 * is debugging than a number invented here.
 */
function failedRc(failed) {
  const first = failed[0];
  const st = Number(first && first.status);
  return Number.isInteger(st) && st > 0 ? st : 1;
}

/** client.js's "this status was tolerated" marker. */
function isTolerated(v) {
  return !!v && typeof v === 'object' && v.tolerated === true;
}

/** Caldera v2 sometimes answers with a single object and sometimes a one-element array. */
function firstOf(v) {
  if (Array.isArray(v)) return v.length ? v[0] : null;
  return v && typeof v === 'object' ? v : null;
}

/** UNVERIFIED: which field carries a new operation's id. Both documented spellings. */
function operationIdOf(created) {
  const o = firstOf(created);
  if (!o) return null;
  const id = o.id || o.operation_id;
  return id ? String(id) : null;
}

/**
 * A staff-facing operation name.
 *
 * Carries the run id because that is the only string that ties a Caldera
 * operation back to a CyberCore run when somebody is looking at the server's own
 * UI at 2am. It carries NO scenario prose: the adversary compiler strips
 * `action` and `detection_opportunity` by construction and re-checks it, and
 * leaking the same text through an operation name would walk straight around
 * that.
 */
function operationName(run, prepared) {
  const runId = run && run.run_id ? String(run.run_id) : 'unknown-run';
  const adv = prepared && prepared.adversary ? prepared.adversary : {};
  const scenario = adv.adversary_id ? String(adv.adversary_id).slice(0, 8) : 'adhoc';
  return `cybercore ${runId} [${scenario}]`;
}

/**
 * Agents that count as present.
 *
 * Two filters, and the recency one is the important half: Caldera keeps an
 * agent row forever after its host is deleted, so "an agent exists" is not the
 * same claim as "an agent will execute something". A stale row passing as a
 * live agent is how a lane gets an operation that no one will ever run.
 *
 * An UNPARSEABLE last_seen is accepted rather than rejected. It is a field shape
 * nobody here has ever seen; refusing on it would fail every dispatch on the
 * first real server whose timestamp format differs, which is a far worse failure
 * than admitting one stale agent.
 */
function selectAgents(agents, cfg, nowMs) {
  const list = Array.isArray(agents) ? agents : [];
  const maxAgeMs = cfg.agentMaxAgeS * 1000;
  return list.filter((agent) => {
    if (!agent || !agent.paw) return false;
    if (cfg.agentGroup && agent.group && String(agent.group) !== cfg.agentGroup) return false;
    const seen = agent.last_seen ? Date.parse(agent.last_seen) : NaN;
    if (!Number.isFinite(seen)) return true;
    return nowMs - seen <= maxAgeMs;
  });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------
//
// The default export IS the adapter, so a future
// `registerEngine(require('./caldera'))` is one line. It is not registered
// today — see the block at the bottom of src/incident/engines/index.js.
const adapter = createCalderaEngine();

module.exports = adapter;
module.exports.createCalderaEngine = createCalderaEngine;
module.exports.ENGINE_KEY = ENGINE_KEY;
module.exports.LINK_STATUS = LINK_STATUS;
module.exports.TERMINAL_OPERATION_STATES = TERMINAL_OPERATION_STATES;
// Exported for the tests, which pin these rules directly rather than only
// through a whole lifecycle.
module.exports.__pure = {
  guestState,
  selectAgents,
  endpointFor,
  resolveSettings,
  linkIsFinished,
  linkIsFailed,
  failedRc,
  operationName,
  operationIdOf,
  asObject,
};
