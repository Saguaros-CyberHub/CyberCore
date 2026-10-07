/**
 * ============================================================================
 * INCIDENT ENGINES — the adapter contract
 * ============================================================================
 * An "engine" is whatever actually makes the incident happen inside a lane. Two
 * are planned and they have almost nothing in common at the mechanical level:
 *
 *   'synthetic'  the existing stack — a baked Rocky sensor, cc-emit.js, a
 *                staged cc-attack.sh wrapper, dispatched over the Proxmox guest
 *                agent. Fabricated ND-JSON that Filebeat ships to Elasticsearch.
 *   'caldera'    (E9, droppable) a real C2: sandcat agents execute real
 *                abilities on real Windows hosts, and the telemetry is whatever
 *                Sysmon happened to record.
 *
 * WHY THE CONTRACT EXISTS NOW, WITH ONE IMPLEMENTATION
 * ----------------------------------------------------------------------------
 * Not for pluggability as an abstract virtue. It exists so that adding Caldera
 * later touches ONE NEW FILE in this directory and nothing else — no board
 * table, no route, no UI, no DDL (the `engine` value is already in
 * cybercore_incident_run's CHECK, and `engine_ref` is already on the target
 * row). Equally important: Caldera is DROPPABLE. If E9 never ships, nothing is
 * stranded, because the only trace of it is one string in a CHECK.
 *
 * Writing the seam after the fact is what does not work. By then the worker,
 * the routes and the board have all reached directly into attack-runner, and
 * the second engine becomes a rewrite instead of a file.
 *
 * WHY engineFor() THROWS A NAMED ERROR RATHER THAN DEFAULTING
 * ----------------------------------------------------------------------------
 * The failure this guards is a row written by a NEWER version of the app and
 * read by an older one — a rolling deploy, a rollback, a stale worker process.
 * If engineFor('caldera') quietly fell back to the synthetic engine, that run
 * would be dispatched with the wrong semantics: the worker would poll a guest
 * state file that no Caldera operation ever writes, decide the target never
 * started, and mark a live intrusion 'failed' while it is still running. A
 * loud, named error leaves the row alone for a process that understands it.
 * ============================================================================
 */

'use strict';

/**
 * The methods every engine adapter must supply.
 *
 * Grouped by who calls them, because that is what makes the contract legible:
 *
 *   route      supportsMode, resolveSelection, compileAnswerKey
 *   dispatcher prepare, dispatchTarget
 *   worker     readTargetState, finalize
 *   abort path abortTarget, abortRun
 *
 * Shapes, so a second implementer does not have to read the first:
 *
 *   supportsMode(mode) -> boolean
 *       'technique' | 'tactic' | 'chain' | 'scenario'. A route rejects an
 *       unsupported (engine, mode) pair with a 400 BEFORE writing a run row —
 *       an unsupported combination must never reach 'scheduling', because the
 *       dispatch mutex would then hold the scope until something swept it.
 *
 *   resolveSelection(runRow) -> { arg, capSeconds, catalogVersion, ... }
 *       Validates the run's mode-specific columns and turns them into whatever
 *       the engine dispatches with. THROWS on anything it cannot validate;
 *       never sanitizes, because the values reach a root shell.
 *
 *   compileAnswerKey(runRow, resolved) -> object
 *       STAFF-ONLY grading key. Returns {} for an engine that cannot predict
 *       what it will produce — Caldera's real execution is exactly that case,
 *       and an empty key is honest where a guessed one silently mis-grades.
 *
 *   prepare({ run, targets }) -> void | Promise<void>
 *       Whole-run setup before any target is touched: create the Caldera
 *       adversary and operation, stage anything lane-independent. The synthetic
 *       engine needs none of it. Must be safe to call twice (a retry re-enters).
 *
 *   dispatchTarget({ run, target, resolved }) -> { dispatched, engineRef?, ... }
 *       Start the incident in ONE lane. Returns what goes into
 *       cybercore_incident_target.engine_ref (Caldera paw + operation id; NULL
 *       for synthetic).
 *
 *   readTargetState({ run, target }) -> { phase, exitCode?, eventCount?, ... }
 *       Poll. Must be side-effect free and must tolerate a guest that is off,
 *       unreachable or mid-reboot — the worker calls this on a timer and a throw
 *       here burns a check_failures increment rather than a diagnosis.
 *
 *   abortTarget({ run, target }) / abortRun({ run, targets }) -> void
 *       Stop it. MUST be idempotent: abort races the sweeper by construction.
 *
 *   finalize({ run, targets }) -> { status }
 *       Roll per-target outcomes into the run's terminal status. Lives on the
 *       engine because 'partial' means different things: a synthetic run with
 *       one dead lane is 'partial'; a Caldera operation whose agent never
 *       checked in produced nothing at all.
 */
const ENGINE_METHODS = Object.freeze([
  'supportsMode',
  'resolveSelection',
  'compileAnswerKey',
  'prepare',
  'dispatchTarget',
  'readTargetState',
  'abortTarget',
  'abortRun',
  'finalize',
]);

/**
 * Thrown by engineFor() for a key with no adapter.
 *
 * A named class, not a bare Error, so a caller can tell "this row names an
 * engine this build does not have" (leave the row alone, log, move on) apart
 * from "this engine failed" (fail the target). The two need opposite handling
 * and a string match on the message is not a contract.
 */
class UnknownIncidentEngineError extends Error {
  constructor(key) {
    super(
      `Unknown incident engine ${JSON.stringify(key)}. `
      + `Registered: ${[...REGISTRY.keys()].map((k) => JSON.stringify(k)).join(', ') || '(none)'}. `
      + `A run row naming an engine this build does not implement is left alone deliberately — `
      + `dispatching it with another engine's semantics would mis-report a live intrusion.`
    );
    this.name = 'UnknownIncidentEngineError';
    this.code = 'UNKNOWN_INCIDENT_ENGINE';
    this.engineKey = key;
  }
}

/** key -> adapter. Populated by registerEngine() at the bottom of this file. */
const REGISTRY = new Map();

/**
 * Register an adapter.
 *
 * The shape check is deliberately a hard throw at REQUIRE time rather than a
 * warning: a half-implemented adapter that registers successfully fails later,
 * mid-dispatch, in a student's lane, with a TypeError on `undefined is not a
 * function` — which is the worst possible place to learn a method is missing.
 */
function registerEngine(adapter) {
  if (!adapter || typeof adapter.key !== 'string' || !adapter.key) {
    throw new Error('incident engine adapter must declare a non-empty string `key`');
  }
  const missing = ENGINE_METHODS.filter((m) => typeof adapter[m] !== 'function');
  if (missing.length) {
    throw new Error(
      `incident engine '${adapter.key}' is missing: ${missing.join(', ')}. `
      + 'See the contract in src/incident/engines/index.js.'
    );
  }
  REGISTRY.set(adapter.key, adapter);
  return adapter;
}

/**
 * The adapter for a run row's `engine` column.
 *
 * @throws {UnknownIncidentEngineError} for any key with no adapter. See the
 *   file header for why this is not a fallback.
 */
function engineFor(key) {
  const adapter = REGISTRY.get(key);
  if (!adapter) throw new UnknownIncidentEngineError(key);
  return adapter;
}

/** Every registered key. Used by routes to render the engine picker. */
function registeredEngines() {
  return [...REGISTRY.keys()];
}

// ---------------------------------------------------------------------------
// Registration
// ---------------------------------------------------------------------------
//
// 'synthetic' ONLY. The adapter body lands in E2, when the CLE routes are
// re-pointed at the shared table and there is a caller to shape it against;
// wiring it now would mean guessing at the runner's call sites and rewriting it
// in the same session. Until then this is the contract and the registry, and
// engineFor('synthetic') resolving is what the locality test can assert.
//
// 'caldera' IS NOW IMPLEMENTED — src/incident/engines/caldera.js — AND IS STILL
// NOT REGISTERED. That is a decision, not an oversight, and it has two reasons:
//
//   1. registeredEngines() exists to feed an engine picker ("Used by routes to
//      render the engine picker", above). It has no caller yet. The moment E8's
//      console grows one, registering here would make a C2 that has never
//      spoken to a real server selectable by an instructor with no further edit
//      and no review. Leaving the key unregistered means adding Caldera to a UI
//      is a deliberate act in THIS file.
//   2. bake-caldera-server.sh's hand-off block states the same rule from the
//      other side — E8 must pass first, because standing a real C2 on top of an
//      unproven pipeline gives every failure two candidate causes.
//
// So engineFor('caldera') still throws, exactly as
// test/incident-engine-locality.test.js asserts. Wiring it at E9-ship time is
// one line:  registerEngine(require('./caldera'));
//
// The adapter is exported unregistered so tests (and a future dispatcher) can
// reach it by name without going through the registry. Requiring it is
// side-effect free: it pulls in the pure compiler and the HTTP client, neither
// of which touches the network, the database or config/site.json at load.
try {
  registerEngine(require('./synthetic'));
} catch (err) {
  // A synthetic adapter that fails to load must not take the server's boot with
  // it — same doctrine as ensureIncidentTables(). The consequence is an empty
  // registry and a loud refusal at dispatch, not a dead process.
  console.warn('⚠️  Incident engine \'synthetic\' not registered:', err.message);
}

module.exports = {
  engineFor,
  registerEngine,
  registeredEngines,
  UnknownIncidentEngineError,
  ENGINE_METHODS,
  /**
   * The Caldera adapter, DELIBERATELY OUTSIDE THE REGISTRY.
   *
   * A getter rather than a plain property so requiring this module stays as
   * cheap as it was: anything that wants to know which engines exist requires
   * index.js, and none of those callers should pay for a compiler and an HTTP
   * client they will not use.
   *
   * Reaching an engine through this export is NOT a substitute for registering
   * it — engineFor() is what a run row is dispatched through, and it still
   * refuses 'caldera'. See the registration block above.
   */
  get calderaEngineUnregistered() {
    return require('./caldera');
  },
};
