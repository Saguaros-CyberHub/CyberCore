/**
 * ============================================================================
 * INCIDENT ENGINE — 'synthetic'
 * ============================================================================
 * The engine that exists today: a baked Rocky sensor running cc-emit.js, driven
 * by a cc-attack.sh wrapper staged per dispatch over the Proxmox guest agent.
 * It fabricates ND-JSON that Filebeat ships into the lane's Elasticsearch.
 *
 * WHAT THIS FILE IS, AND WHAT IT IS NOT
 * ----------------------------------------------------------------------------
 * It is the ADAPTER — the thin surface that src/incident/engines/index.js
 * registers and that a future Caldera adapter has to match. The implementation
 * lives where it already lives: runner.js (command construction, dispatch,
 * abort, finalize) and target.js (which VM in a lane to attack). Nothing was
 * reimplemented here, and nothing should be.
 *
 * The orchestration methods are deliberately NOT wired yet, and E2 did not
 * change that on purpose. E2 re-pointed runner.js and worker.js at
 * cybercore_incident_run / _target and generalized lane discovery to a scope —
 * both behaviour-preserving, which is what let the CLE Attack Console cut over
 * with its JSON and its JS untouched. Routing the CLE routes through this
 * adapter as well would have changed the dispatch path in the same commit,
 * turning any regression into a two-suspect investigation.
 *
 * They get a caller when there is a SECOND implementation to be shaped against
 * — the CiAB scenario route, or Caldera (E9). Until then cle/routes/attacks.js
 * drives src/incident/runner.js directly, and this file is the contract plus
 * the two methods (supportsMode, resolveSelection) a route can already use.
 *
 * They throw rather than no-op, and that distinction matters: a no-op
 * dispatchTarget() returns "dispatched" for a lane where nothing was started,
 * and the worker then waits out the full run duration before reporting a
 * failure that happened instantly. A throw fails the target at dispatch, which
 * is where the operator is still looking.
 * ============================================================================
 */

'use strict';

/**
 * Lazily required, and the reason is not style.
 *
 * runner.js pulls in src/utils/site-config at module scope, which reads
 * config/site.json — gitignored, and absent in a plain checkout. Requiring it
 * from here at load time would make engines/index.js unimportable outside a
 * deployed environment, and index.js is required by anything that wants to know
 * which engines exist. Deferring costs one property lookup per call.
 */
let _runner = null;
function runner() {
  if (!_runner) _runner = require('../runner');
  return _runner;
}

/**
 * catalog.js, required at module scope and deliberately NOT deferred.
 *
 * It reaches nothing outside src/incident/ — no site config, no database, no
 * Proxmox — so the trap the lazy require above exists for does not apply, and
 * formatDuration() is needed on the scenario path below. Deferring it too would
 * imply a hazard that is not there.
 *
 * SCENARIO_ID_RE comes from there too, and that is the point of it living in
 * catalog.js at all: it is the SAME binding runner.js validates the dispatch
 * argument against, never a second spelling of the same rule. Two validators
 * that disagree by one character is how a value passes the route and is refused
 * by the dispatcher, twenty minutes into an exercise.
 */
const { formatDuration, SCENARIO_ID_RE } = require('../catalog');

/**
 * The scenario arm of resolveSelection.
 *
 * WHAT IT DOES NOT DO: compile. src/incident/scenario-compiler.js turns a
 * client's threat scenario into {attack, floor, answerKey} and it needs the
 * PROFILE — assets, stakeholders, the scenario prose — none of which a run row
 * carries and none of which core may go and fetch, because the profile lives in
 * a plugin's tables. The caller compiles and hands the result down; this
 * validates what arrived and shapes it into the argv the wrapper is dispatched
 * with. Same division as every other mode: the catalog is looked up elsewhere,
 * the selection is validated here.
 *
 * The playbook is REQUIRED, not optional-with-a-fallback. A 'scenario' run
 * dispatched without one is the exact failure the mode was withheld for: the
 * wrapper derives wrapperMode='playbook' from the presence of the file, so a
 * missing playbook does not fail — it silently runs the keyword generator
 * against an argument that means nothing to it, and every environment reports
 * 'completed' having produced no incident at all.
 */
function resolveScenarioSelection(runRow) {
  const row = runRow || {};

  // NAMING, and it is a rule rather than a habit: the fields that are real
  // columns of cybercore_incident_run keep the column's spelling
  // (scenario_id, playbook, duration_seconds), because a retry passes the
  // stored ROW here verbatim. The two that are NOT columns — the compiler's
  // key and the instructor-facing label — are camelCase, so a reader can tell
  // at a glance which half of this object came out of Postgres.

  const scenarioId = String(row.scenario_id == null ? '' : row.scenario_id);
  if (!SCENARIO_ID_RE.test(scenarioId)) {
    throw new Error(`invalid scenario id: ${JSON.stringify(row.scenario_id)}`);
  }

  // Accepts BOTH shapes on purpose. The launch path hands a compiled object
  // straight out of the compiler; a retry rebuilds the selection from the run
  // row, where Postgres may hand back jsonb as either depending on the driver's
  // parser. Normalising here means the two paths cannot diverge.
  let playbook = row.playbook;
  if (typeof playbook === 'string') {
    try {
      playbook = JSON.parse(playbook);
    } catch (err) {
      throw new Error(`scenario ${scenarioId}: stored playbook is not valid JSON (${err.message})`);
    }
  }
  if (!playbook || !Array.isArray(playbook.steps) || !playbook.steps.length) {
    throw new Error(
      `scenario ${scenarioId} has no compiled playbook with steps. A scenario run is dispatched `
      + 'from the compiler\'s output; without it the guest would fall back to the keyword '
      + 'generator and report success having produced no incident.'
    );
  }

  // NOT NULL for this mode by construction: cc_incident_run_duration_matches_mode
  // makes a NULL duration legal only for a chain. The bounds are the column's
  // own CHECK, restated rather than imported so the refusal is a 400 with a
  // sentence in it instead of a 23514 from Postgres.
  const durationSeconds = Number(row.duration_seconds);
  if (!Number.isInteger(durationSeconds) || durationSeconds < 30 || durationSeconds > 28800) {
    throw new Error(
      `duration_seconds must be an integer in [30, 28800], got ${JSON.stringify(row.duration_seconds)}`
    );
  }

  return {
    mode: 'scenario',
    arg: scenarioId,
    durationSeconds,
    duration: formatDuration(durationSeconds),
    // The same 20% headroom plus two minutes the technique arm uses. The
    // emitter self-exits at --duration; this only fires if it wedges.
    capSeconds: Math.ceil(durationSeconds * 1.2) + 120,
    speed: '1.00',
    // Staff-only copy. The compiled playbook's own `name` is deliberately
    // opaque ("scenario TS-001") because it is staged on a disk students have a
    // console on; this label never leaves an instructor-gated response.
    label: row.scenarioLabel ? String(row.scenarioLabel) : `scenario ${scenarioId}`,
    // What playbookFor() returns, instead of a lookup in the on-disk PLAYBOOKS
    // map. There is no file to find: this playbook describes ONE client's
    // estate and was compiled for THIS run.
    playbook,
    // The key the compiler already produced, carried so compileAnswerKey() can
    // return it rather than re-deriving a second, possibly different, truth.
    // Absent on a retry, which never recompiles a key — the stored one is what
    // the students were graded against.
    answerKey: row.answerKey || null,
  };
}

/** Not-yet-wired orchestration. See the header for why this throws. */
function notWiredYet(method) {
  return () => {
    throw new Error(
      `incident engine 'synthetic': ${method}() has no caller yet. `
      + 'The shared tables ARE live (E2 re-pointed runner.js and worker.js at '
      + 'cybercore_incident_run / _target); what is not wired is dispatch going '
      + 'THROUGH this adapter — cle/routes/attacks.js still drives '
      + 'src/incident/runner.js directly. See the header of this file.'
    );
  };
}

module.exports = {
  key: 'synthetic',

  /**
   * Exported so a caller can refuse a malformed scenario id with its own
   * message, and so a test pins the shape by identity rather than by respelling
   * the regex. Not part of the engine contract — engines/index.js checks for
   * the nine METHODS and ignores everything else.
   */
  SCENARIO_ID_RE,

  /**
   * Every mode the run table declares, 'scenario' now included.
   *
   * WHAT NOW SATISFIES IT. 'scenario' was withheld through E6 for one specific
   * reason: the wrapper's mechanics were already there — buildDispatchCommand
   * derives wrapperMode='playbook' from args.playbookJson — but there was no
   * COMPILER, so a route that accepted the mode would have written a run that
   * dispatched an EMPTY playbook. Every environment would report 'completed'
   * having generated nothing, which is the worst outcome available because it
   * looks exactly like a working exercise.
   *
   * E4 shipped src/incident/scenario-compiler.js, and it closes that hole at
   * both ends rather than merely filling it:
   *
   *   - compileScenario() THROWS when a scenario has no attack_path step it can
   *     represent, so "compiled but empty" is not a state that can exist;
   *   - resolveScenarioSelection() above REQUIRES a playbook with steps, so a
   *     run row that lost one is refused at dispatch rather than degrading into
   *     a keyword-generator run nobody asked for;
   *   - the compiler emits the graded key from the SAME planTimeline() the
   *     guest will run, so a scenario run is auto-gradable like a technique and
   *     unlike a tactic.
   *
   * Empty is therefore unreachable in all three directions, which is exactly
   * the claim supportsMode() makes.
   */
  supportsMode(mode) {
    return mode === 'technique' || mode === 'tactic' || mode === 'chain'
      || mode === 'scenario';
  },

  /**
   * Validates a run row's mode-specific columns and returns what the wrapper is
   * dispatched with. Throws on anything it cannot validate — these values reach
   * a root shell inside a student's VM, so it never sanitizes.
   *
   * The scenario arm is handled HERE rather than in runner.js because it is the
   * one mode whose selection is not a catalog lookup: everything it needs
   * arrives already compiled, and runner.resolveSelection's whole job is
   * turning an id into a catalog entry. See resolveScenarioSelection.
   */
  resolveSelection(runRow) {
    if (runRow && runRow.mode === 'scenario') return resolveScenarioSelection(runRow);
    return runner().resolveSelection(runRow);
  },

  /**
   * STAFF-ONLY grading key, compiled by re-running the emitter's own planner
   * server-side with the seed the guest will use — which is the run id.
   *
   * MUST BE CALLED IN THE SAME STATEMENT AS THE RUN INSERT, because the seed IS
   * the run id: there is nothing to compile before that row exists, and
   * compiling it afterwards leaves a window in which a completed run has no key
   * and the board grades every correct answer as a false positive.
   *
   * Returns {} rather than throwing when the selection has no playbook. TACTIC
   * mode is exactly that case and it is not an error: a tactic is a dozen
   * unrelated behaviours with no single honest story to script, so it stays on
   * the generator's keyword filter and there is no event list to predict.
   * src/incident/scoring.js reads an empty key as "not auto-graded" and marks
   * every claim 'unscored' — which is the honest answer, where a guessed key
   * would mis-grade silently.
   *
   * @param {object} runRow   needs run_id and duration_seconds
   * @param {object} resolved the output of resolveSelection()
   */
  compileAnswerKey(runRow, resolved) {
    // ── SCENARIO: the key is READ, never recompiled ────────────────────────
    //
    // scenario-compiler.js already produced it, in the same call that produced
    // the playbook, against the same seed and the same compiled FLOOR. That
    // last part is why recompiling here would be wrong rather than merely
    // wasteful: answer-key.js takes the floor as an argument and falls back to
    // the BAKED generic floor when it is not given one. Re-deriving the key
    // from the attack alone would compute `iocs` against web-01/db-01 instead
    // of the client's own estate, and every value the compiled floor also emits
    // would be graded as an attack-only indicator.
    //
    // {} when a caller supplied no key — honest, and read by scoring.js as "not
    // auto-graded" — rather than a guess.
    if (resolved && resolved.mode === 'scenario') {
      return resolved.answerKey || {};
    }

    const raw = runner().playbookFor(resolved);
    if (!raw) return {};
    return require('../answer-key').compileAnswerKey({
      runId: runRow.run_id,
      playbook: typeof raw === 'string' ? JSON.parse(raw) : raw,
      // A chain has no duration_seconds by construction (migration 006's
      // correlated CHECK forbids one), and cc-emit.js:640 falls back to the
      // playbook's own nominal_seconds for exactly that case. Passing null here
      // reproduces that fallback rather than second-guessing it.
      requestedSeconds: runRow.duration_seconds,
    });
  },

  prepare: notWiredYet('prepare'),
  dispatchTarget: notWiredYet('dispatchTarget'),
  readTargetState: notWiredYet('readTargetState'),
  abortTarget: notWiredYet('abortTarget'),
  abortRun: notWiredYet('abortRun'),
  finalize: notWiredYet('finalize'),
};
